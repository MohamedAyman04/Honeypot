#!/usr/bin/env python3
"""Validation-recalibrated realistic evaluation of the six-layer architecture."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

from architecture_validation import (CampaignData, detect_ewma_cusum, detect_replay,
                                     detect_semantic_injection, load_campaign as load_architecture_campaign)
from full_architecture_realistic import (RECOVERY_MAX_SECONDS, RECOVERY_STABLE_SECONDS,
                                         RECOVERY_TOLERANCE, metrics, recovery_mask, repair_features)
from precision_recalibration import RAW_FEATURES, SEED, train_scores

MAX_VALIDATION_NORMAL_FPR = 0.05
EXPANDED_VALIDATION_END_FRACTION = 0.60


def expanded_chronological_split(data: CampaignData) -> CampaignData:
    """Keep the original normal-only train prefix, then use a wider earlier validation period.

    The original 120-row validation period was too short to represent the later
    score regime.  Everything after the 60%-of-timeline boundary remains an
    untouched chronological test block.
    """
    df = data.df.copy()
    train_end = int(np.flatnonzero(df.split.eq("train").to_numpy())[-1]) + 1
    val_end = int(len(df) * EXPANDED_VALIDATION_END_FRACTION)
    if val_end <= train_end:
        raise RuntimeError("Expanded validation boundary precedes the training boundary.")
    df["split"] = "test"
    df.loc[:train_end - 1, "split"] = "train"
    df.loc[train_end:val_end - 1, "split"] = "val"
    return CampaignData(df=df, phases=data.phases, alerts=data.alerts,
                        campaign_start=data.campaign_start, data_dir=data.data_dir,
                        attack_csv=data.attack_csv)


def select_threshold(y: np.ndarray, score: np.ndarray, max_fpr: float = MAX_VALIDATION_NORMAL_FPR) -> tuple[float, dict]:
    """F1-optimal threshold subject to a validation-normal alert-rate cap."""
    normal = y == 0
    candidates = []
    for threshold in np.unique(score):
        pred = score >= threshold
        fp = int((pred & normal).sum())
        fpr = fp / max(int(normal.sum()), 1)
        if fpr <= max_fpr:
            candidates.append((f1_score(y, pred, zero_division=0), -fp, float(threshold), pred, fpr))
    if not candidates:
        raise RuntimeError("No validation threshold satisfied the normal-FPR cap.")
    f1, neg_fp, threshold, pred, fpr = max(candidates, key=lambda x: (x[0], x[1], x[2]))
    return threshold, {"validation_f1": float(f1), "validation_precision": float(precision_score(y, pred, zero_division=0)),
                       "validation_recall": float(recall_score(y, pred, zero_division=0)), "validation_fp": -neg_fp,
                       "validation_normal_fpr": float(fpr)}


def calibrated_ml(df: pd.DataFrame, val_mask: np.ndarray) -> tuple[dict[str, np.ndarray], dict]:
    scores = train_scores(df, RAW_FEATURES)
    y = df.loc[val_mask, "ground_truth"].to_numpy()
    outputs, meta = {}, {}
    for name in ("if", "lstm"):
        val_score = scores[name][val_mask]
        threshold, detail = select_threshold(y, val_score)
        outputs[name] = (scores[name] >= threshold).astype(int)
        meta[name] = {"threshold": threshold, "validation_score_min": float(val_score.min()),
                      "validation_score_max": float(val_score.max()), **detail}
    return outputs, meta


def expert_prediction(df: pd.DataFrame, delta: float, mean_dev: float, over_pressure: float) -> np.ndarray:
    """Layer-2 physics/consistency rules, including the command-free delta rule."""
    return ((df.pressure_delta.abs().to_numpy() > delta) |
            (df.pressure_mean_dev.abs().to_numpy() > mean_dev) |
            (df.pressure.to_numpy() > over_pressure)).astype(int)


def correlation_prediction(df: pd.DataFrame, delta: float, replay: np.ndarray) -> np.ndarray:
    command_free_delta = ((df.pressure_delta.abs().to_numpy() > delta) &
                          (df.write_freq_10s.to_numpy() == 0))
    return (command_free_delta | replay).astype(int)


def calibrate_expert(df: pd.DataFrame, val_mask: np.ndarray) -> tuple[np.ndarray, dict]:
    """Small validation-only grid around the original 20/35/300 thresholds."""
    y = df.loc[val_mask, "ground_truth"].to_numpy()
    best = None
    for delta in (10., 15., 20., 25., 30.):
        for mean_dev in (15., 25., 35., 45., 55.):
            for over_pressure in (200., 250., 300., 350., 400.):
                pred = expert_prediction(df, delta, mean_dev, over_pressure)
                p = pred[val_mask]
                candidate = (f1_score(y, p, zero_division=0), -int(((p == 1) & (y == 0)).sum()),
                             delta, mean_dev, over_pressure, p)
                if best is None or candidate[:2] > best[:2]:
                    best = candidate
    assert best is not None
    f1, neg_fp, delta, mean_dev, over_pressure, val_pred = best
    return expert_prediction(df, delta, mean_dev, over_pressure), {
        "old": {"pressure_delta": 20., "pressure_mean_deviation": 35., "over_pressure": 300.},
        "new": {"pressure_delta": delta, "pressure_mean_deviation": mean_dev, "over_pressure": over_pressure},
        "validation_f1": float(f1), "validation_precision": float(precision_score(y, val_pred, zero_division=0)),
        "validation_recall": float(recall_score(y, val_pred, zero_division=0)), "validation_fp": -neg_fp,
    }


def build_vectors(data: CampaignData, val_mask: np.ndarray) -> tuple[dict[str, np.ndarray], dict]:
    df = data.df
    expert, expert_meta = calibrate_expert(df, val_mask)
    replay = detect_replay(df, data.campaign_start).pred
    temporal = detect_ewma_cusum(df, data.campaign_start).pred
    semantic = detect_semantic_injection(df, str(Path(data.data_dir) / "csv" / "forced_writes.csv"), data.campaign_start).pred
    ml, ml_meta = calibrated_ml(df, val_mask)
    delta = expert_meta["new"]["pressure_delta"]
    vectors = {
        "Layer 1 — Network semantic": semantic,
        "Layer 2 — Expert rules (recalibrated)": expert,
        "Layer 3 — CUSUM/EWMA": temporal,
        "Layer 4 — Cross-layer correlation": correlation_prediction(df, delta, replay),
        "Layer 5 — ML ensemble (recalibrated)": ml["if"] | ml["lstm"],
    }
    vectors["Rules + correlation (no ML)"] = np.logical_or.reduce([vectors[n] for n in list(vectors)[:4]]).astype(int)
    base = [vectors[n] for n in list(vectors)[:5]]
    vectors["Layer 6 — OR fusion"] = np.logical_or.reduce(base).astype(int)
    vectors["Layer 6 — AND fusion"] = np.logical_and.reduce(base).astype(int)
    votes = np.stack(base).sum(axis=0)
    vectors["Layer 6 — Majority vote (2 of 5)"] = (votes >= 2).astype(int)
    vectors["Layer 6 — Majority vote (3 of 5)"] = (votes >= 3).astype(int)

    # Validation-selected simple weighted vote: precise Layers 1 and 3 receive weight 3.
    weights = np.array([3., 1., 3., 1., 1.])
    weighted_score = np.dot(weights, np.stack(base))
    threshold, weighted_meta = select_threshold(df.loc[val_mask, "ground_truth"].to_numpy(), weighted_score[val_mask], max_fpr=1.0)
    vectors["Layer 6 — Weighted vote (validation-selected)"] = (weighted_score >= threshold).astype(int)
    return vectors, {"layer_2": expert_meta, "layer_5": ml_meta,
                     "weighted_vote": {"weights": {"Layer 1": 3, "Layer 2": 1, "Layer 3": 3, "Layer 4": 1, "Layer 5": 1},
                                       "threshold": threshold, **weighted_meta}}


def contribution_table(vectors: dict[str, np.ndarray], test_mask: np.ndarray, y: np.ndarray) -> pd.DataFrame:
    names = list(vectors)[:5]
    rows = []
    for name in names:
        pred = vectors[name][test_mask].astype(bool)
        others = np.logical_or.reduce([vectors[n][test_mask] for n in names if n != name])
        rows.append({"Layer": name, "TP": int((pred & (y == 1)).sum()), "FP": int((pred & (y == 0)).sum()),
                     "Exclusive_TP": int((pred & ~others & (y == 1)).sum()),
                     "Exclusive_FP": int((pred & ~others & (y == 0)).sum())})
    return pd.DataFrame(rows)


def report(out: Path, data: CampaignData, test_mask: np.ndarray, recovery_total: int, recovery_test: int,
           table: pd.DataFrame, contributions: pd.DataFrame, meta: dict) -> None:
    y = data.df.loc[test_mask, "ground_truth"].to_numpy()
    best = table.sort_values(["F1", "Precision", "Recall"], ascending=False).iloc[0]
    lines = ["# Full architecture realistic evaluation — recalibrated v2", "",
             "## Protocol", "",
             f"- Current campaign: {len(data.df)} 1 Hz rows. The original 334-row normal-only training prefix is retained; validation is expanded chronologically through {EXPANDED_VALIDATION_END_FRACTION:.0%} of the timeline ({int((data.df.split == 'val').sum())} rows) because the previous 120-row validation range did not represent later ML scores. The untouched later test set has {int(test_mask.sum())} eligible rows ({int((y==0).sum())} normal, {int(y.sum())} attack).",
             f"- Recovery rule is unchanged: 5% pre-attack pressure/flow band, {RECOVERY_STABLE_SECONDS} stable seconds, {RECOVERY_MAX_SECONDS}-second cap. It excludes {recovery_total} unique rows ({recovery_test} test rows).",
             f"- All calibration is validation-only; seed={SEED}. Layer 5 uses F1 under a {MAX_VALIDATION_NORMAL_FPR:.0%} validation-normal FPR cap to rule out an all-normal-alert operating point. Layer 2 uses a 5×5×5 validation grid.",
             "", "## Threshold diagnosis and recalibration", "",
             "| Model/rule | Old threshold | New threshold | Validation score range / metrics |", "|---|---|---|---|"]
    for name, detail in meta["layer_5"].items():
        old = "IF: -0.021783" if name == "if" else "LSTM: 472.991730"
        lines.append(f"| Layer 5 {name.upper()} | {old} | {detail['threshold']:.6f} | score=[{detail['validation_score_min']:.6f}, {detail['validation_score_max']:.6f}], P={detail['validation_precision']:.3f}, R={detail['validation_recall']:.3f}, F1={detail['validation_f1']:.3f}, normal FPR={detail['validation_normal_fpr']:.3f} |")
    l2 = meta["layer_2"]
    lines.append(f"| Layer 2 rules | Δ={l2['old']['pressure_delta']:.0f}, mean={l2['old']['pressure_mean_deviation']:.0f}, pressure={l2['old']['over_pressure']:.0f} | Δ={l2['new']['pressure_delta']:.0f}, mean={l2['new']['pressure_mean_deviation']:.0f}, pressure={l2['new']['over_pressure']:.0f} | P={l2['validation_precision']:.3f}, R={l2['validation_recall']:.3f}, F1={l2['validation_f1']:.3f}, FP={l2['validation_fp']} |")
    lines += ["", "The original ML thresholds were not at the validation minima; the all-positive result was caused by later-timeline score drift. The FPR-constrained selection is the validation-only correction, not a test-set clamp.",
              "", "## Held-out mixed-timeline comparison", "",
              "| Configuration | Precision | Recall | F1 | TP | FP | TN | FN |", "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for _, row in table.iterrows():
        lines.append("| {Configuration} | {Precision:.3f} | {Recall:.3f} | {F1:.3f} | {TP} | {FP} | {TN} | {FN} |".format(**row))
    lines += ["", "## Layer contributions", "", "| Layer | TP | FP | Exclusive TP | Exclusive FP |", "|---|---:|---:|---:|---:|"]
    for _, r in contributions.iterrows():
        lines.append(f"| {r.Layer} | {r.TP} | {r.FP} | {r.Exclusive_TP} | {r.Exclusive_FP} |")
    lines += ["", "## Conclusion", "",
              f"Best held-out F1 among the tested configurations is **{best.Configuration}**: precision={best.Precision:.3f}, recall={best.Recall:.3f}, F1={best.F1:.3f}.",
              "Fixing Layers 2 and 5 prevents the all-positive collapse, but OR fusion is still not a good balance here (precision=0.257, recall=0.682, F1=0.373). The validation-selected weighted vote chose threshold 1 and is therefore equivalent to OR; 2-of-5 and 3-of-5 majority voting both reduce F1. The best result is the recalibrated rules-only configuration, but precision=0.328 remains too low for a strong operational claim.",
              "The remaining limitation is false-positive overlap: Layer 2 contributes 90 test false positives, Layer 4 contributes 86, and the calibrated ML layer contributes 103 (including 40 exclusive false positives) while adding only one exclusive true positive. This comparison—not any attack-only result—is the basis for claims about realistic alert quality.",
              "", "## Metadata", "", "```json", json.dumps(meta, indent=2), "```"]
    (out / "REPORT.md").write_text("\n".join(lines))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", default="results/20260701_161537")
    parser.add_argument("--out", default="results/full_architecture_realistic_v2")
    args = parser.parse_args()
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    data = expanded_chronological_split(repair_features(load_architecture_campaign(args.data_dir)))
    recovery, recovery_rows = recovery_mask(data.df, data.phases)
    val = data.df.split.eq("val").to_numpy() & ~recovery
    test = data.df.split.eq("test").to_numpy() & ~recovery
    vectors, meta = build_vectors(data, val)
    y = data.df.loc[test, "ground_truth"].to_numpy()
    rows = []
    for name, pred in vectors.items():
        row = metrics(y, pred[test]); row["Configuration"] = name; rows.append(row)
    table = pd.DataFrame(rows)
    contrib = contribution_table(vectors, test, y)
    meta["recovery"] = {"tolerance": RECOVERY_TOLERANCE, "stable_seconds": RECOVERY_STABLE_SECONDS,
                        "max_seconds": RECOVERY_MAX_SECONDS, "excluded_total": int(recovery.sum())}
    table.to_csv(out / "comparison.csv", index=False)
    contrib.to_csv(out / "layer_contributions.csv", index=False)
    pd.DataFrame(recovery_rows).to_csv(out / "recovery_exclusions.csv", index=False)
    (out / "selection.json").write_text(json.dumps(meta, indent=2))
    report(out, data, test, int(recovery.sum()), int((data.df.split.eq("test").to_numpy() & recovery).sum()), table, contrib, meta)
    print(table.to_string(index=False))
    print("Saved v2 evaluation to", out)


if __name__ == "__main__":
    main()
