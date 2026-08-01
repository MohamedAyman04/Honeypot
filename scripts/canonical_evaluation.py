#!/usr/bin/env python3
"""Canonical, reproducible Network / Process / Combined evaluation script.

Methodological Blueprint
------------------------
1. Unified Chronological Split:
   - Both datasets use an IDENTICAL split fraction (`frac=0.45` of total campaign duration).
   - Chronological order is strictly preserved:
     * Train: Initial 100% normal operating period (0 attack rows).
     * Validation: First attack phase(s) up to `frac=0.45` timeline mark (used ONLY for threshold selection).
     * Test: Remaining campaign timeline (untouched evaluation set).
   - Recovery Masking: Post-attack system stabilization periods (pressure restoring to setpoint)
     are excluded from normal-class false positive evaluation to prevent penalising physically
     accurate post-incident alerts.

2. Domain Feature Sets:
   - NETWORK_FEATURES: ["inter_arrival_time", "write_freq_10s", "is_write", "func_code", "length"]
   - PROCESS_FEATURES: ["pressure", "flow_rate", "temperature", "pressure_delta", "pressure_mean_dev"]
   - RAW_FEATURES (Combined): All 10 features above.

3. Domain ML Calibration:
   - ML_net: Isolation Forest + LSTM Autoencoder trained ONLY on NETWORK_FEATURES.
     * Captures Modbus command timing, frequency, function code, and packet size anomalies.
     * High precision on network-level attacks.
   - ML_proc: Isolation Forest + LSTM Autoencoder trained ONLY on PROCESS_FEATURES.
     * Captures physical pressure/flow dynamics, rate of change, and mean deviations.
   - ML_comb: Isolation Forest + LSTM Autoencoder trained on all 10 RAW_FEATURES.

4. Standalone & Baseline Architectures:
   - Layer 1: Network Semantic Injection detector (Modbus forced-write verification).
   - Layer 2: Physics Expert Rules (pressure threshold, delta, mean deviation - validation calibrated).
   - Layer 3: Temporal Anomaly Detector (EWMA & CUSUM on pressure dynamics).
   - Layer 4: Cross-Layer Command-Consequence Correlation & Replay Detector.
   - Layer 5: ML Ensemble (IF + LSTM Autoencoder on combined features).
   - Network-only Baseline: OR(Layer 1, ML_net)
   - Process-only Baseline: OR(Layer 2, Layer 3, ML_proc)
   - Combined (OR Fusion): OR(Layer 1, Layer 2, Layer 3, Layer 4, Layer 5)
   - Combined (Weighted Vote): 3*L1 + 1*L2 + 3*L3 + 1*L4 + 1*L5 (threshold selected on val).

5. Gated / Hierarchical Fusion Strategies:
   - Network-primary Gated Architecture: Network-only acts as the primary detector.
     Process-domain alerts are ONLY admitted where Network-only is silent (Network-only == 0).
   - Gated-Confidence (GC-strict / GC-moderate / GC-relaxed):
     Admits process-domain ML score only if process score >= gate_threshold,
     where gate_threshold is calibrated ON THE NETWORK-SILENT VALIDATION SUBSET ONLY,
     subject to strict validation-normal FPR caps (0.5%, 1.5%, 3.5%).
   - Narrow Mechanism Gate (NMG):
     Admits process alerts ONLY if physical-inconsistency signature fires:
     |pressure_mean_dev| > threshold AND write_freq_10s == 0 (large deviation with no write command).
     Threshold selected via validation F1 on network-silent subset.

6. Reproducibility & Determinism:
   - SEED = 42 set prior to model initialization and training.
   - Validation-only calibration with zero test-set peeking.
   - Automated self-check asserts 100% bitwise identity between consecutive runs.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, precision_score, recall_score

# ── Project imports ────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).parent
PROJECT_DIR = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

from architecture_validation import (
    CampaignData, detect_ewma_cusum, detect_replay,
    detect_semantic_injection, load_campaign as load_architecture_campaign,
    NETWORK_FEATURES, PROCESS_FEATURES,
)
from full_architecture_realistic import (
    metrics, recovery_mask, repair_features,
)
from precision_recalibration import RAW_FEATURES, SEED, train_scores
from full_architecture_realistic_v2 import (
    calibrate_expert, correlation_prediction,
)
from full_architecture_realistic_v4 import (
    expanded_chronological_split,
)

# ── Constants ──────────────────────────────────────────────────────────────────
CANONICAL_VAL_FRAC = 0.45
MAX_VALIDATION_NORMAL_FPR = 0.05

GATED_FPR_CAPS = {
    "GC-strict":   0.005,
    "GC-moderate": 0.015,
    "GC-relaxed":  0.035,
}
NMG_MEAN_DEV_CANDIDATES = [15.0, 25.0, 35.0, 50.0, 75.0]


def set_seed(seed: int = SEED) -> None:
    import random
    os.environ["PYTHONHASHSEED"] = str(seed)
    random.seed(seed)
    np.random.seed(seed)


def robust_select_threshold(
    y: np.ndarray,
    score: np.ndarray,
    max_fpr: float = MAX_VALIDATION_NORMAL_FPR,
) -> tuple[float, dict]:
    """Select threshold maximizing validation F1 under max_fpr normal FPR cap.

    Falls back cleanly if no threshold satisfies the FPR cap.
    """
    normal = (y == 0)
    candidates = []
    for threshold in np.unique(score):
        pred = score >= threshold
        fp = int((pred & normal).sum())
        fpr = fp / max(int(normal.sum()), 1)
        if fpr <= max_fpr:
            f1 = f1_score(y, pred, zero_division=0)
            prec = precision_score(y, pred, zero_division=0)
            rec = recall_score(y, pred, zero_division=0)
            candidates.append((f1, -fp, float(threshold), prec, rec, fpr))

    if not candidates:
        t_fallback = float(score.max()) + 1.0
        return t_fallback, {
            "validation_f1": 0.0, "validation_precision": 0.0,
            "validation_recall": 0.0, "validation_fp": 0,
            "validation_normal_fpr": 0.0, "fallback": True,
        }

    f1, neg_fp, threshold, prec, rec, fpr = max(candidates, key=lambda x: (x[0], x[1], x[2]))
    return threshold, {
        "validation_f1": float(f1),
        "validation_precision": float(prec),
        "validation_recall": float(rec),
        "validation_fp": -neg_fp,
        "validation_normal_fpr": float(fpr),
        "fallback": False,
    }


def calibrate_domain_ml(
    df: pd.DataFrame,
    val_mask: np.ndarray,
    feature_cols: list[str],
    max_fpr: float = MAX_VALIDATION_NORMAL_FPR,
) -> tuple[dict[str, np.ndarray], dict, np.ndarray]:
    """Train IF + LSTM on feature_cols and calibrate thresholds on validation set."""
    scores = train_scores(df, feature_cols)
    y_val = df.loc[val_mask, "ground_truth"].to_numpy()
    train_mask = (df.split == "train").to_numpy()

    def _norm(s: np.ndarray) -> np.ndarray:
        lo, hi = s[train_mask].min(), s[train_mask].max()
        return np.clip((s - lo) / (hi - lo + 1e-12), 0, 1)

    combined_score = np.maximum(_norm(scores["if"]), _norm(scores["lstm"]))
    preds, meta = {}, {}

    for name in ("if", "lstm"):
        val_score = scores[name][val_mask]
        threshold, detail = robust_select_threshold(y_val, val_score, max_fpr=max_fpr)
        preds[name] = (scores[name] >= threshold).astype(int)
        meta[name] = {"threshold": threshold, **detail}

    return preds, meta, combined_score


def gated_confidence(
    network_pred: np.ndarray,
    proc_score: np.ndarray,
    val_mask: np.ndarray,
    y_full: np.ndarray,
    max_fpr: float,
) -> tuple[np.ndarray, dict]:
    """Gated Confidence strategy: admit process alerts only if process score >= t on network-silent val subset."""
    net_silent = (network_pred == 0)
    val_sil_mask = val_mask & net_silent

    y_sil = y_full[val_sil_mask]
    s_sil = proc_score[val_sil_mask]
    n_sil = (y_sil == 0)

    if int(y_sil.sum()) == 0 or int(n_sil.sum()) == 0:
        return network_pred.copy(), {
            "fallback": True, "gate_threshold": float("inf"),
            "full_val_f1": float(f1_score(y_full[val_mask], network_pred[val_mask], zero_division=0)),
        }

    best = None
    for t in np.unique(s_sil):
        added = s_sil >= t
        fp = int((added & n_sil).sum())
        fpr = fp / max(int(n_sil.sum()), 1)
        if fpr <= max_fpr:
            f1 = f1_score(y_sil, added.astype(int), zero_division=0)
            prec = precision_score(y_sil, added.astype(int), zero_division=0)
            if best is None or (f1, prec) > (best[0], best[1]):
                best = (f1, prec, fp, float(t))

    if best is None:
        return network_pred.copy(), {
            "fallback": True, "gate_threshold": float("inf"),
            "full_val_f1": float(f1_score(y_full[val_mask], network_pred[val_mask], zero_division=0)),
        }

    _, _, best_fp, gate_t = best
    gated_add = (proc_score >= gate_t) & net_silent
    gated_pred = (network_pred.astype(bool) | gated_add).astype(int)
    y_val = y_full[val_mask]
    val_pred = gated_pred[val_mask]

    return gated_pred, {
        "gate_threshold": float(gate_t), "gated_fpr_cap": max_fpr,
        "full_val_f1": float(f1_score(y_val, val_pred, zero_division=0)),
        "full_val_precision": float(precision_score(y_val, val_pred, zero_division=0)),
        "full_val_recall": float(recall_score(y_val, val_pred, zero_division=0)),
        "val_gated_add_tp": int((gated_add[val_mask] & (y_val == 1)).sum()),
        "val_gated_add_fp": int((gated_add[val_mask] & (y_val == 0)).sum()),
        "fallback": False,
    }


def narrow_mechanism_gate(
    network_pred: np.ndarray,
    df: pd.DataFrame,
    val_mask: np.ndarray,
    y_full: np.ndarray,
    mean_dev_candidates: list[float],
) -> tuple[np.ndarray, dict]:
    """Narrow Mechanism Gate: admit process alert if |pressure_mean_dev| > t AND write_freq == 0 on network-silent subset."""
    net_silent = (network_pred == 0)
    val_sil_mask = val_mask & net_silent
    y_sil = y_full[val_sil_mask]
    mean_dev_s = df["pressure_mean_dev"].abs().to_numpy()
    write_freq = df["write_freq_10s"].to_numpy()

    best = None
    all_candidates = []
    for t in mean_dev_candidates:
        sig = (mean_dev_s > t) & (write_freq == 0)
        sig_sil = sig[val_sil_mask]
        if int(y_sil.sum()) > 0:
            f1 = f1_score(y_sil, sig_sil.astype(int), zero_division=0)
            prec = precision_score(y_sil, sig_sil.astype(int), zero_division=0)
        else:
            f1 = prec = 0.0
        tp = int((sig_sil & (y_sil == 1)).sum())
        fp = int((sig_sil & (y_sil == 0)).sum())
        all_candidates.append({"t": t, "f1": f1, "prec": prec, "tp": tp, "fp": fp})
        if best is None or (f1, prec, -t) > (best[0], best[1], -best[2]):
            best = (f1, prec, t)

    best_f1, best_prec, best_t = best
    # Assertion self-check: verify selected threshold achieves maximum validation F1
    max_cand_f1 = max(c["f1"] for c in all_candidates)
    assert best_f1 == max_cand_f1, f"Validation selection error: {best_f1} != max {max_cand_f1}"
    sig_best = (mean_dev_s > best_t) & (write_freq == 0)
    gated_add = sig_best & net_silent
    gated_pred = (network_pred.astype(bool) | gated_add).astype(int)
    y_val = y_full[val_mask]
    val_pred = gated_pred[val_mask]

    return gated_pred, {
        "selected_mean_dev_threshold": float(best_t),
        "mechanism": "|pressure_mean_dev| > t AND write_freq_10s == 0",
        "full_val_f1": float(f1_score(y_val, val_pred, zero_division=0)),
        "full_val_precision": float(precision_score(y_val, val_pred, zero_division=0)),
        "full_val_recall": float(recall_score(y_val, val_pred, zero_division=0)),
        "val_gated_add_tp": int((gated_add[val_mask] & (y_val == 1)).sum()),
        "val_gated_add_fp": int((gated_add[val_mask] & (y_val == 0)).sum()),
    }


def evaluate_dataset(data_dir: str, val_frac: float = CANONICAL_VAL_FRAC) -> tuple[pd.DataFrame, dict]:
    """Run full canonical evaluation on a single dataset."""
    set_seed(SEED)
    data_raw = load_architecture_campaign(data_dir)
    data = expanded_chronological_split(repair_features(data_raw), frac=val_frac)
    df = data.df

    recovery, _ = recovery_mask(df, data.phases)
    val_mask = df.split.eq("val").to_numpy() & ~recovery
    test_mask = df.split.eq("test").to_numpy() & ~recovery
    y_full = df["ground_truth"].to_numpy()
    y_test = y_full[test_mask]

    dataset_label = Path(data_dir).name

    # ── 1. Individual Layers & Domain ML Models ──────────────────────────────────
    # Layer 1: Network Semantic Injection
    csv_dir = Path(data_dir) / "csv"
    l1_pred = detect_semantic_injection(
        df, str(csv_dir / "forced_writes.csv"), data.campaign_start
    ).pred

    # Layer 2: Physics Expert Rules
    l2_pred, expert_meta = calibrate_expert(df, val_mask)

    # Layer 3: Temporal Anomaly (EWMA / CUSUM)
    l3_pred = detect_ewma_cusum(df, data.campaign_start).pred

    # Layer 4: Cross-Layer Command-Consequence Correlation
    replay = detect_replay(df, data.campaign_start).pred
    delta_t = expert_meta["new"]["pressure_delta"]
    l4_pred = correlation_prediction(df, delta_t, replay)

    # Domain ML models
    ml_net_preds, ml_net_meta, score_net = calibrate_domain_ml(df, val_mask, NETWORK_FEATURES)
    ml_proc_preds, ml_proc_meta, score_proc = calibrate_domain_ml(df, val_mask, PROCESS_FEATURES)
    ml_comb_preds, ml_comb_meta, score_comb = calibrate_domain_ml(df, val_mask, RAW_FEATURES)

    l5_pred = ml_comb_preds["if"] | ml_comb_preds["lstm"]
    ml_net_ensemble = ml_net_preds["if"] | ml_net_preds["lstm"]
    ml_proc_ensemble = ml_proc_preds["if"] | ml_proc_preds["lstm"]

    # ── 2. Domain Baselines ──────────────────────────────────────────────────────
    net_only_pred = (l1_pred.astype(bool) | ml_net_ensemble.astype(bool)).astype(int)
    proc_only_pred = (l2_pred.astype(bool) | l3_pred.astype(bool) | ml_proc_ensemble.astype(bool)).astype(int)

    # ── 3. Combined Fusion Baselines ─────────────────────────────────────────────
    or_fusion_pred = (l1_pred.astype(bool) | l2_pred.astype(bool) | l3_pred.astype(bool) |
                      l4_pred.astype(bool) | l5_pred.astype(bool)).astype(int)

    base_layers = [l1_pred, l2_pred, l3_pred, l4_pred, l5_pred]
    weights = np.array([3.0, 1.0, 3.0, 1.0, 1.0])
    weighted_score = np.dot(weights, np.stack(base_layers))
    wv_thresh, wv_meta = robust_select_threshold(y_full[val_mask], weighted_score[val_mask], max_fpr=1.0)
    weighted_vote_pred = (weighted_score >= wv_thresh).astype(int)

    # ── 4. Gated Fusion Strategies ──────────────────────────────────────────────
    gc_preds, gc_metas = {}, {}
    for g_name, fpr_cap in GATED_FPR_CAPS.items():
        gc_p, gc_m = gated_confidence(net_only_pred, score_proc, val_mask, y_full, max_fpr=fpr_cap)
        gc_preds[g_name] = gc_p
        gc_metas[g_name] = gc_m

    nmg_pred, nmg_meta = narrow_mechanism_gate(net_only_pred, df, val_mask, y_full, NMG_MEAN_DEV_CANDIDATES)

    # ── 5. Assemble Results Table ────────────────────────────────────────────────
    eval_configs = [
        ("Layer 1 — Network Semantic Injection", l1_pred),
        ("Layer 2 — Physics Expert Rules (recalibrated)", l2_pred),
        ("Layer 3 — Temporal Anomaly (EWMA/CUSUM)", l3_pred),
        ("Layer 4 — Cross-Layer Correlation", l4_pred),
        ("Layer 5 — ML Ensemble (Combined Features)", l5_pred),
        ("Network-only Baseline (L1 + ML_net)", net_only_pred),
        ("Process-only Baseline (L2 + L3 + ML_proc)", proc_only_pred),
        ("Combined Architecture (OR Fusion)", or_fusion_pred),
        ("Combined Architecture (Weighted Vote — Headline)", weighted_vote_pred),
        ("Gated-Confidence (GC-strict)", gc_preds["GC-strict"]),
        ("Gated-Confidence (GC-moderate)", gc_preds["GC-moderate"]),
        ("Gated-Confidence (GC-relaxed)", gc_preds["GC-relaxed"]),
        ("Narrow Mechanism Gate (NMG)", nmg_pred),
    ]

    rows = []
    for cfg_name, pred in eval_configs:
        m = metrics(y_test, pred[test_mask])
        m["configuration"] = cfg_name
        m["dataset"] = dataset_label
        rows.append(m)

    res_df = pd.DataFrame(rows)

    all_meta = {
        "dataset": dataset_label,
        "data_dir": data_dir,
        "val_frac": val_frac,
        "expert_l2": expert_meta,
        "ml_net": ml_net_meta,
        "ml_proc": ml_proc_meta,
        "ml_comb": ml_comb_meta,
        "weighted_vote": wv_meta,
        "gated_confidence": gc_metas,
        "narrow_mechanism_gate": nmg_meta,
    }

    return res_df, all_meta


def main() -> None:
    parser = argparse.ArgumentParser(description="Canonical evaluation script")
    parser.add_argument("--ds1", default="results/20260724_014825", help="Dataset 1 path")
    parser.add_argument("--ds2", default="results/20260725_055634", help="Dataset 2 path")
    parser.add_argument("--out", default="results/canonical_evaluation", help="Output directory")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 75)
    print("  CANONICAL REPRODUCIBLE EVALUATION RUN")
    print(f"  SEED = {SEED} | Validation fraction = {CANONICAL_VAL_FRAC}")
    print("=" * 75)

    # ── Run 1: Primary Evaluation ─────────────────────────────────────────────
    print("\n[Run 1] Evaluating Dataset 1...")
    df1_r1, meta1_r1 = evaluate_dataset(args.ds1, val_frac=CANONICAL_VAL_FRAC)

    print("\n[Run 2] Evaluating Dataset 2...")
    df2_r1, meta2_r1 = evaluate_dataset(args.ds2, val_frac=CANONICAL_VAL_FRAC)

    # ── Determinism Self-Check ────────────────────────────────────────────────
    print("\n" + "=" * 75)
    print("  DETERMINISM SELF-CHECK (Re-running with identical seed)...")
    print("=" * 75)

    df1_r2, _ = evaluate_dataset(args.ds1, val_frac=CANONICAL_VAL_FRAC)
    df2_r2, _ = evaluate_dataset(args.ds2, val_frac=CANONICAL_VAL_FRAC)

    # Assert bitwise identity
    pd.testing.assert_frame_equal(df1_r1, df1_r2, check_exact=True)
    pd.testing.assert_frame_equal(df2_r1, df2_r2, check_exact=True)
    print("\n✅ DETERMINISM VERIFIED: Both runs produced 100% bitwise identical metrics!")

    # Combine canonical results
    combined_df = pd.concat([df1_r1, df2_r1], ignore_index=True)
    combined_df.to_csv(out_dir / "canonical_comparison.csv", index=False)
    combined_df.to_csv(PROJECT_DIR / "results" / "canonical_evaluation_comparison.csv", index=False)

    print("\n" + "=" * 75)
    print("  CANONICAL EVALUATION RESULTS")
    print("=" * 75)
    print(combined_df[["dataset", "configuration", "Precision", "Recall", "F1", "TP", "FP", "FN"]].to_string(index=False))

    all_meta = {
        "seed": SEED,
        "val_frac": CANONICAL_VAL_FRAC,
        "dataset_1": meta1_r1,
        "dataset_2": meta2_r1,
        "determinism_verified": True,
    }
    (out_dir / "canonical_metadata.json").write_text(json.dumps(all_meta, indent=2))
    print(f"\nSaved canonical results to {out_dir} and results/canonical_evaluation_comparison.csv")


if __name__ == "__main__":
    main()
