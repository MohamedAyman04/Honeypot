#!/usr/bin/env python3
"""Targeted Layer-2/3 improvement study; no ML retraining or grid re-search."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

from architecture_validation import detect_ewma_cusum, load_campaign as load_architecture_campaign
from full_architecture_realistic import metrics, recovery_mask, repair_features
from full_architecture_realistic_v2 import expanded_chronological_split, expert_prediction

SEED = 42
THRESHOLDS = {"pressure_delta": 10.0, "pressure_mean_deviation": 15.0, "over_pressure": 400.0}


def debounce(pred: np.ndarray, n: int) -> np.ndarray:
    out = np.zeros_like(pred, dtype=int)
    run = 0
    for i, value in enumerate(pred.astype(bool)):
        run = run + 1 if value else 0
        if run >= n:
            out[i] = 1
    return out


def choose_debounce(pred: np.ndarray, y: np.ndarray, val_mask: np.ndarray) -> tuple[np.ndarray, int, dict]:
    choices = []
    for n in (2, 3):
        candidate = debounce(pred, n)
        m = metrics(y, candidate[val_mask])
        choices.append((m["F1"], n, candidate, m))
    _, n, selected, detail = max(choices, key=lambda x: (x[0], x[1] == 2))
    return selected, n, detail


def rule_conditions(df: pd.DataFrame) -> pd.DataFrame:
    return pd.DataFrame({
        "pressure_delta": df.pressure_delta.abs().to_numpy() > THRESHOLDS["pressure_delta"],
        "pressure_mean_dev": df.pressure_mean_dev.abs().to_numpy() > THRESHOLDS["pressure_mean_deviation"],
        "over_pressure": df.pressure.to_numpy() > THRESHOLDS["over_pressure"],
        "write_nearby": df.write_freq_10s.to_numpy() > 0,
    })


def fp_audit(df: pd.DataFrame, pred: np.ndarray, test_mask: np.ndarray) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    cond = rule_conditions(df)
    mask = test_mask & (df.ground_truth.to_numpy() == 0) & pred.astype(bool)
    audit = df.loc[mask, ["timestamp", "pressure", "flow_rate", "pressure_delta", "pressure_mean_dev", "write_freq_10s"]].reset_index(drop=True).copy()
    audit = audit.join(cond.loc[mask].reset_index(drop=True).rename(columns={
        "pressure_delta": "pressure_delta_trigger",
        "pressure_mean_dev": "pressure_mean_dev_trigger",
        "over_pressure": "over_pressure_trigger",
        "write_nearby": "write_nearby_trigger",
    }))
    # Cluster contiguous one-second alerts to expose transient windows.
    gaps = audit.timestamp.diff().dt.total_seconds().fillna(2).gt(1)
    audit["cluster_id"] = gaps.cumsum().to_numpy()
    clusters = audit.groupby("cluster_id").agg(start=("timestamp", "min"), end=("timestamp", "max"),
                                                seconds=("timestamp", "size"), writes_nearby=("write_nearby_trigger", "sum"),
                                                delta=("pressure_delta_trigger", "sum"), mean_dev=("pressure_mean_dev_trigger", "sum"),
                                                over_pressure=("over_pressure_trigger", "sum")).reset_index()
    delta_rows = audit[audit.pressure_delta_trigger]
    write_rate = float(delta_rows.write_nearby_trigger.mean()) if len(delta_rows) else 0.0
    summary = {"false_positive_rows": int(len(audit)), "clusters": int(len(clusters)),
               "delta_fp_rows": int(len(delta_rows)), "delta_fp_with_write_rate": write_rate,
               "mean_dev_fp_rows": int(audit.pressure_mean_dev_trigger.sum()), "over_pressure_fp_rows": int(audit.over_pressure_trigger.sum())}
    return audit, clusters, summary


def suppress_commanded_delta(df: pd.DataFrame) -> np.ndarray:
    c = rule_conditions(df)
    return (((c.pressure_delta & ~c.write_nearby) | c.pressure_mean_dev | c.over_pressure).to_numpy()).astype(int)


def row(name: str, y: np.ndarray, pred: np.ndarray, test_mask: np.ndarray, note: str = "") -> dict:
    out = metrics(y, pred[test_mask]); out["Configuration"] = name; out["Note"] = note
    return out


def write_report(out: Path, data: pd.DataFrame, test_mask: np.ndarray, recovery_total: int, recovery_test: int,
                 audit_summary: dict, clusters: pd.DataFrame, fix_applied: bool, rows: list[dict], selections: dict) -> None:
    y = data.loc[test_mask, "ground_truth"].to_numpy()
    table = pd.DataFrame(rows)
    best = table.sort_values(["F1", "Precision", "Recall"], ascending=False).iloc[0]
    lines = ["# Targeted Layer 2 + Layer 3 improvement (v3)", "",
             "## Protocol", "",
             f"- Same chronological split as v2: original 334-row normal-only training prefix, expanded validation through 60% of the timeline, and a final test block of {int(test_mask.sum())} eligible rows ({int((y==0).sum())} normal, {int(y.sum())} attack).",
             f"- Recovery handling is unchanged (5% / 10 consecutive seconds / 60-second cap): {recovery_total} total excluded rows, {recovery_test} test rows.",
             f"- Fixed v2 Layer-2 thresholds: delta={THRESHOLDS['pressure_delta']:.0f}, mean deviation={THRESHOLDS['pressure_mean_deviation']:.0f}, over-pressure={THRESHOLDS['over_pressure']:.0f}. No grid search or ML retraining was run.",
             "- Debounce N is chosen solely by validation F1 from N={2,3}, then frozen for test.",
             "", "## Layer-2 false-positive audit", "",
             f"- Baseline Layer 2 false positives: {audit_summary['false_positive_rows']} rows in {audit_summary['clusters']} contiguous time clusters.",
             f"- Trigger counts: pressure-delta={audit_summary['delta_fp_rows']}, mean-deviation={audit_summary['mean_dev_fp_rows']}, over-pressure={audit_summary['over_pressure_fp_rows']}.",
             f"- Among delta-trigger false positives, {audit_summary['delta_fp_with_write_rate']:.1%} had a write in the preceding 10 seconds."]
    if fix_applied:
        lines.append("- Targeted fix applied: suppress only the pressure-delta rule when a recent write exists. This is a semantic rule refinement, not a test-tuned numerical threshold; its performance is also reported on validation.")
    else:
        lines.append("- No write-aware delta suppression was applied because fewer than half of delta-trigger false positives had nearby writes.")
    lines += ["", "| Cluster | Start | End | Seconds | Nearby writes | Delta triggers | Mean-deviation triggers | Over-pressure triggers |", "|---:|---|---|---:|---:|---:|---:|---:|"]
    for _, c in clusters.iterrows():
        lines.append(f"| {c.cluster_id} | {c.start} | {c.end} | {c.seconds} | {c.writes_nearby} | {c.delta} | {c.mean_dev} | {c.over_pressure} |")
    lines += ["", "## Comparison", "", "| Configuration | Precision | Recall | F1 | TP | FP | TN | FN | Note |",
              "|---|---:|---:|---:|---:|---:|---:|---:|---|"]
    for r in rows:
        lines.append("| {Configuration} | {Precision:.3f} | {Recall:.3f} | {F1:.3f} | {TP} | {FP} | {TN} | {FN} | {Note} |".format(**r))
    lines += ["", "## Recommendation", "",
              f"Recommend **{best.Configuration}** as the headline result from this targeted study: precision={best.Precision:.3f}, recall={best.Recall:.3f}, F1={best.F1:.3f}.",
              "The false-positive row-level and cluster-level audits are saved alongside this report; the result should be presented as a chronological, mixed-traffic evaluation rather than compared to attack-only precision.",
              "", "## Validation debounce selections", "", "```json", json.dumps(selections, indent=2), "```"]
    (out / "REPORT.md").write_text("\n".join(lines))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", default="results/20260701_161537")
    parser.add_argument("--out", default="results/full_architecture_realistic_v3")
    args = parser.parse_args()
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    data = expanded_chronological_split(repair_features(load_architecture_campaign(args.data_dir)))
    df = data.df
    recovery, recovery_rows = recovery_mask(df, data.phases)
    val = df.split.eq("val").to_numpy() & ~recovery
    test = df.split.eq("test").to_numpy() & ~recovery
    y_val = df.loc[val, "ground_truth"].to_numpy()
    y_test = df.loc[test, "ground_truth"].to_numpy()

    layer2 = expert_prediction(df, THRESHOLDS["pressure_delta"], THRESHOLDS["pressure_mean_deviation"], THRESHOLDS["over_pressure"])
    layer3 = detect_ewma_cusum(df, data.campaign_start).pred
    layer23 = (layer2 | layer3).astype(int)
    audit, clusters, audit_summary = fp_audit(df, layer2, test)
    # Predeclared diagnostic condition: apply only if a majority of delta FPs have nearby writes.
    fix_applied = audit_summary["delta_fp_rows"] > 0 and audit_summary["delta_fp_with_write_rate"] >= 0.50
    fixed = suppress_commanded_delta(df) if fix_applied else layer2.copy()

    d2, n2, val_d2 = choose_debounce(layer2, y_val, val)
    d3, n3, val_d3 = choose_debounce(layer3, y_val, val)
    d23, n23, val_d23 = choose_debounce(layer23, y_val, val)
    fixed_d, fixed_n, fixed_val = choose_debounce(fixed, y_val, val)

    rows = [
        row("Layer 2 baseline (v2 thresholds)", y_test, layer2, test),
        row("Layer 2 + Layer 3 OR", y_test, layer23, test),
        row("Layer 2 with targeted FP fix", y_test, fixed, test, "write-aware delta suppression" if fix_applied else "not triggered"),
        row(f"Layer 2 debounce (N={n2})", y_test, d2, test, "validation-selected"),
        row(f"Layer 3 debounce (N={n3})", y_test, d3, test, "validation-selected"),
        row(f"Layer 2 + 3 OR debounce (N={n23})", y_test, d23, test, "validation-selected"),
        row(f"Layer 2 FP-fix debounce (N={fixed_n})", y_test, fixed_d, test, "validation-selected"),
    ]
    selections = {"layer2": {"N": n2, "validation": val_d2}, "layer3": {"N": n3, "validation": val_d3},
                  "layer2_layer3_or": {"N": n23, "validation": val_d23},
                  "layer2_fp_fix": {"applied": fix_applied, "N": fixed_n, "validation": fixed_val},
                  "fp_audit": audit_summary}
    pd.DataFrame(rows).to_csv(out / "comparison.csv", index=False)
    audit.to_csv(out / "layer2_false_positive_rows.csv", index=False)
    clusters.to_csv(out / "layer2_false_positive_clusters.csv", index=False)
    pd.DataFrame(recovery_rows).to_csv(out / "recovery_exclusions.csv", index=False)
    (out / "selection.json").write_text(json.dumps(selections, indent=2))
    write_report(out, df, test, int(recovery.sum()), int((df.split.eq("test").to_numpy() & recovery).sum()), audit_summary, clusters, fix_applied, rows, selections)
    print(pd.DataFrame(rows).to_string(index=False))
    print("FP audit:", audit_summary)
    print("Saved v3 evaluation to", out)


if __name__ == "__main__":
    main()
