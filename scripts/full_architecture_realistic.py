#!/usr/bin/env python3
"""Realistic mixed-timeline evaluation of the six-layer detector architecture.

This script deliberately evaluates the complete labelled campaign, not the
attack-only slice used by the original architecture tables.  It reuses the
offline rule/correlation implementations and the leakage-safe ML scorer.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

from architecture_validation import (
    ALERT_PHASES, CampaignData, detect_ewma_cusum, detect_expert_rules,
    detect_replay, detect_semantic_injection,
    load_campaign as load_architecture_campaign,
)
from precision_recalibration import RAW_FEATURES, SEED, threshold_from_pr, train_scores

RECOVERY_TOLERANCE = 0.05
RECOVERY_STABLE_SECONDS = 10
RECOVERY_MAX_SECONDS = 60


def repair_features(data: CampaignData) -> CampaignData:
    """Correct event/index alignment before reusing the existing detectors."""
    df = data.df.copy().sort_values("timestamp").reset_index(drop=True)
    for col in ("is_write", "func_code"):
        df[col] = df[col].fillna(0).astype(int)
    df["write_freq_10s"] = df["is_write"].rolling(10, min_periods=1).sum()
    df["pressure_delta"] = df["pressure"].diff().fillna(0.0)
    df["pressure_mean_dev"] = df["pressure"] - df["pressure"].rolling(60, min_periods=1).mean()
    if df[RAW_FEATURES].isna().any().any():
        raise RuntimeError("Campaign features contain NaNs after alignment repair.")
    return CampaignData(df=df, phases=data.phases, alerts=data.alerts,
                        campaign_start=data.campaign_start, data_dir=data.data_dir,
                        attack_csv=data.attack_csv)


def recovery_mask(df: pd.DataFrame, phases: pd.DataFrame) -> tuple[np.ndarray, list[dict]]:
    """Mask only immediately post-attack process recovery, never attack samples.

    A recovery ends at the first 10 consecutive seconds whose pressure *and*
    flow are within 5% of the 60-second pre-attack medians; it is capped at 60 s.
    """
    excluded = np.zeros(len(df), dtype=bool)
    rows: list[dict] = []
    for _, phase in phases.iterrows():
        start, end = phase["start"], phase["end"]
        before = df[(df.timestamp < start) & (df.timestamp >= start - pd.Timedelta(seconds=60))]
        p0, f0 = float(before.pressure.median()), float(before.flow_rate.median())
        after = df[(df.timestamp > end) & (df.timestamp <= end + pd.Timedelta(seconds=RECOVERY_MAX_SECONDS))]
        stable = 0
        recovery_end = None
        for idx, row in after.iterrows():
            pressure_ok = abs(float(row.pressure) - p0) <= max(abs(p0) * RECOVERY_TOLERANCE, 0.5)
            flow_ok = abs(float(row.flow_rate) - f0) <= max(abs(f0) * RECOVERY_TOLERANCE, 0.1)
            stable = stable + 1 if pressure_ok and flow_ok else 0
            if stable >= RECOVERY_STABLE_SECONDS:
                recovery_end = row.timestamp
                break
        if recovery_end is None:
            recovery_end = end + pd.Timedelta(seconds=RECOVERY_MAX_SECONDS)
            returned = False
        else:
            returned = True
        mask = ((df.timestamp > end) & (df.timestamp <= recovery_end) &
                (df.ground_truth.eq(0))).to_numpy()
        excluded |= mask
        rows.append({"phase": int(phase.phase), "attack_end": end.isoformat(),
                     "recovery_end": recovery_end.isoformat(), "duration_s": int(mask.sum()),
                     "returned_within_60s": returned})
    return excluded, rows


def metrics(y: np.ndarray, pred: np.ndarray) -> dict[str, int | float]:
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"Precision": precision_score(y, pred, zero_division=0),
            "Recall": recall_score(y, pred, zero_division=0),
            "F1": f1_score(y, pred, zero_division=0),
            "TP": int(tp), "FP": int(fp), "TN": int(tn), "FN": int(fn)}


def calibrated_ml(df: pd.DataFrame) -> tuple[dict[str, np.ndarray], dict]:
    """Use validation-only F-beta (.5) thresholds, frozen for the test timeline."""
    scores = train_scores(df, RAW_FEATURES)
    val = df.split.eq("val").to_numpy()
    y_val = df.loc[val, "ground_truth"].to_numpy()
    selected, metadata = {}, {}
    for name in ("if", "lstm"):
        threshold, curve = threshold_from_pr(y_val, scores[name][val], beta=.5)
        selected[name] = (scores[name] >= threshold).astype(int)
        metadata[name] = {"threshold": threshold, "validation_fbeta": float(curve["fbeta"][curve["index"]])}
    return selected, metadata


def layer_vectors(data: CampaignData) -> tuple[dict[str, np.ndarray], dict]:
    df = data.df
    csv_dir = Path(data.data_dir) / "csv"
    semantic = detect_semantic_injection(df, str(csv_dir / "forced_writes.csv"), data.campaign_start).pred
    expert = detect_expert_rules(df, data.campaign_start)
    temporal = detect_ewma_cusum(df, data.campaign_start).pred
    replay = detect_replay(df, data.campaign_start).pred
    ml, ml_meta = calibrated_ml(df)
    vectors = {
        "Layer 1 — Network semantic": semantic,
        "Layer 2 — Expert rules": expert["stealth_drift"].pred | expert["over_pressure"].pred,
        "Layer 3 — CUSUM/EWMA": temporal,
        "Layer 4 — Cross-layer correlation": expert["cross_layer"].pred | replay,
        "Layer 5 — ML ensemble (IF OR LSTM)": ml["if"] | ml["lstm"],
    }
    vectors["Rules + correlation (no ML)"] = (vectors["Layer 1 — Network semantic"] |
                                               vectors["Layer 2 — Expert rules"] |
                                               vectors["Layer 3 — CUSUM/EWMA"] |
                                               vectors["Layer 4 — Cross-layer correlation"])
    base = [vectors[k] for k in list(vectors)[:5]]
    vectors["Layer 6 — Full OR fusion"] = np.logical_or.reduce(base).astype(int)
    vectors["Layer 6 — Full AND fusion"] = np.logical_and.reduce(base).astype(int)
    return vectors, {"ml": ml_meta,
                     "fixed_rule_parameters": {
                         "expert_pressure_delta": 20.0, "expert_mean_deviation": 35.0,
                         "over_pressure": 300.0, "cusum_threshold": 6.0,
                         "ewma_lambda": 0.1,
                     }}


def contributions(vectors: dict[str, np.ndarray], y: np.ndarray, mask: np.ndarray) -> pd.DataFrame:
    base_names = list(vectors)[:5]
    rows = []
    for name in base_names:
        own = vectors[name][mask].astype(bool)
        others = np.logical_or.reduce([vectors[n][mask] for n in base_names if n != name])
        rows.append({"Layer": name,
                     "TP": int((own & (y == 1)).sum()), "FP": int((own & (y == 0)).sum()),
                     "Exclusive_TP": int((own & ~others & (y == 1)).sum()),
                     "Exclusive_FP": int((own & ~others & (y == 0)).sum())})
    return pd.DataFrame(rows)


def write_report(output: Path, data: CampaignData, test_mask: np.ndarray, recovery: list[dict],
                 table: pd.DataFrame, contrib: pd.DataFrame, metadata: dict,
                 recovery_total: int, recovery_test: int) -> None:
    y = data.df.loc[test_mask, "ground_truth"].to_numpy()
    lines = ["# Full architecture: realistic mixed-timeline evaluation", "",
             "## Implemented layer mapping", "",
             "| Architecture layer | Offline implementation reused | Binary output |",
             "|---|---|---|",
             "| Layer 1 — Raw ingestion / network semantics | `detect_semantic_injection` | Forced-write alert |",
             "| Layer 2 — Expert rules | `detect_expert_rules` | Mean-deviation or over-pressure alert |",
             "| Layer 3 — Statistical | `detect_ewma_cusum` | CUSUM/EWMA trend alert |",
             "| Layer 4 — Cross-layer correlation | `detect_expert_rules` + `detect_replay` | Command/consequence or replay alert |",
             "| Layer 5 — ML ensemble | `precision_recalibration.train_scores` | IF or LSTM alert |",
             "| Layer 6 — Decision fusion | this evaluator | OR / AND over Layers 1–5 |", "",
             "Layer naming follows this experiment prompt. In `main.tex`, the ML and cross-layer layers are numbered 4 and 5 respectively; the implemented detectors are unchanged.",
             "", "## Evaluation protocol", "",
             f"- Current reconstructed campaign: {len(data.df)} 1 Hz samples; held-out chronological test portion: {int(test_mask.sum())} eligible samples ({int((y == 0).sum())} normal, {int(y.sum())} attack).",
             f"- ML IF/LSTM thresholds were selected only on the existing validation split with F-beta (beta=0.5), then frozen. Seed: {SEED}.",
             "- Expert, temporal, correlation, and replay rules use their pre-existing code parameters; no threshold was hand-tuned on the test data.",
             f"- Recovery exclusion: after every logged attack termination, rows are excluded only until pressure and flow are both within 5% of the 60-second pre-attack medians for {RECOVERY_STABLE_SECONDS} consecutive seconds, capped at {RECOVERY_MAX_SECONDS} seconds. Attack-labelled rows are never excluded.",
             f"- This excludes {recovery_total} unique campaign rows in total, including {recovery_test} rows from the held-out test period.",
             "", "| Phase | Excluded recovery seconds | Returned within 60 s |", "|---:|---:|---|"]
    for r in recovery:
        lines.append(f"| {r['phase']} | {r['duration_s']} | {r['returned_within_60s']} |")
    lines += ["", "## Held-out mixed-timeline comparison", "",
              "| Configuration | Precision | Recall | F1 | TP | FP | TN | FN |",
              "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for _, r in table.iterrows():
        lines.append("| {Configuration} | {Precision:.3f} | {Recall:.3f} | {F1:.3f} | {TP} | {FP} | {TN} | {FN} |".format(**r))
    lines += ["", "## Per-layer contribution to full OR fusion", "",
              "| Layer | TP | FP | Exclusive TP | Exclusive FP |", "|---|---:|---:|---:|---:|"]
    for _, r in contrib.iterrows():
        lines.append(f"| {r.Layer} | {r.TP} | {r.FP} | {r.Exclusive_TP} | {r.Exclusive_FP} |")
    full = table[table.Configuration.eq("Layer 6 — Full OR fusion")].iloc[0]
    strongest = contrib.sort_values(["Exclusive_TP", "Exclusive_FP"], ascending=[False, True]).iloc[0]
    cleanest = contrib.sort_values(["FP", "TP"], ascending=[True, False]).iloc[0]
    noisiest = contrib.sort_values("FP", ascending=False).iloc[0]
    lines += ["", "## Interpretation", "",
              f"The largest exclusive true-positive contributor is **{strongest.Layer}** ({strongest.Exclusive_TP} exclusive TP; {strongest.Exclusive_FP} exclusive FP). ",
              f"The cleanest non-ML signal is **{cleanest.Layer}** ({cleanest.TP} TP, {cleanest.FP} FP); no layer adds true positives with literally zero false positives. The largest standalone false-positive source is **{noisiest.Layer}** ({noisiest.FP} FP).",
              f"The full OR fusion obtains precision={full.Precision:.3f} and recall={full.Recall:.3f} on the mixed test timeline. This result, including any remaining precision/recall trade-off, is the result that should replace attack-only claims.",
              "", "## Reproducibility metadata", "", "```json", json.dumps(metadata, indent=2), "```"]
    (output / "REPORT.md").write_text("\n".join(lines))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", default="results/20260701_161537")
    parser.add_argument("--out", default="results/full_architecture_realistic")
    args = parser.parse_args()
    output = Path(args.out); output.mkdir(parents=True, exist_ok=True)
    data = repair_features(load_architecture_campaign(args.data_dir))
    recovery, recovery_rows = recovery_mask(data.df, data.phases)
    test = data.df.split.eq("test").to_numpy()
    eligible_test = test & ~recovery
    vectors, metadata = layer_vectors(data)
    y = data.df.loc[eligible_test, "ground_truth"].to_numpy()
    rows = []
    for name, pred in vectors.items():
        row = metrics(y, pred[eligible_test]); row["Configuration"] = name; rows.append(row)
    table = pd.DataFrame(rows)
    contrib = contributions(vectors, y, eligible_test)
    table.to_csv(output / "comparison.csv", index=False)
    contrib.to_csv(output / "layer_contributions.csv", index=False)
    recovery_df = pd.DataFrame(recovery_rows); recovery_df.to_csv(output / "recovery_exclusions.csv", index=False)
    metadata["recovery"] = {"tolerance": RECOVERY_TOLERANCE, "stable_seconds": RECOVERY_STABLE_SECONDS,
                            "max_seconds": RECOVERY_MAX_SECONDS, "excluded_total": int(recovery.sum())}
    write_report(output, data, eligible_test, recovery_rows, table, contrib, metadata,
                 int(recovery.sum()), int((test & recovery).sum()))
    print(f"Full timeline: {len(data.df)} samples; recovery excluded: {int(recovery.sum())}; eligible test: {int(eligible_test.sum())}")
    print(table.to_string(index=False))
    print(contrib.to_string(index=False))
    print(f"Saved realistic full-architecture evaluation to {output}")


if __name__ == "__main__":
    main()
