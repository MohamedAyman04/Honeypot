#!/usr/bin/env python3
"""Leakage-safe precision recalibration for the ML anomaly detectors.

This evaluator deliberately keeps the attack-only experiment out of scope.  It
uses a chronological normal-only training period, a labelled mixed validation
period for model selection, and the later mixed test period exactly once for
reporting.  All outputs are written below ``results/precision_recalibration``.

Example:
    python3 scripts/precision_recalibration.py \
      --data-dir results/20260701_161537
"""
from __future__ import annotations

import argparse
import json
import os
import random
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, confusion_matrix, fbeta_score,
                             f1_score, precision_recall_curve, precision_score,
                             recall_score)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler

SEED = 42
RAW_FEATURES = [
    "pressure", "flow_rate", "temperature", "pressure_delta",
    "pressure_mean_dev", "inter_arrival_time", "write_freq_10s", "is_write",
    "func_code", "length",
]
ENGINEERED_FEATURES = [
    "pressure_rate_5s", "pressure_std_10s", "func_code_entropy_30s",
    "write_ratio_30s",
]
ALERT_PHASES = {4, 5, 7, 8}
SEQ_LEN = 10


def set_seed() -> None:
    os.environ["PYTHONHASHSEED"] = str(SEED)
    random.seed(SEED)
    np.random.seed(SEED)
    import tensorflow as tf
    tf.keras.utils.set_random_seed(SEED)
    try:
        tf.config.experimental.enable_op_determinism()
    except Exception:
        pass


def load_campaign(data_dir: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Reconstruct the 1 Hz mixed dataset and make chronological splits."""
    pm = pd.read_csv(data_dir / "csv" / "pipeline_metrics.csv")
    pm["timestamp"] = pd.to_datetime(pm["_time"], utc=True)
    pm = pm.sort_values("timestamp").set_index("timestamp").resample("1s").first().ffill().fillna(0)
    modbus = pd.read_csv(data_dir / "csv" / "modbus_events.csv")
    modbus["timestamp"] = pd.to_datetime(modbus["_time"], utc=True)
    modbus["is_write"] = (modbus["fc_type"].astype(str).str.lower() == "write").astype(int)
    event_1s = modbus.sort_values("timestamp").set_index("timestamp").resample("1s").max()
    # Alignment to the telemetry index can introduce NaNs outside the Modbus
    # capture range, so fill after assigning rather than only on event_1s.
    pm["is_write"] = event_1s["is_write"].reindex(pm.index).fillna(0).astype(int)
    pm["func_code"] = event_1s["func_code"].reindex(pm.index).fillna(0).astype(int)

    attacks = pd.read_csv(data_dir / "attack_results_extended.csv")
    attacks["timestamp"] = pd.to_datetime(attacks["timestamp"], utc=True)
    intervals, starts = [], {}
    for _, row in attacks.iterrows():
        phase = int(row["phase"])
        if row["status"] == "started":
            starts[phase] = row["timestamp"]
        elif row["status"] == "completed" and phase in starts:
            intervals.append((phase, starts.pop(phase), row["timestamp"]))
    phases = pd.DataFrame(intervals, columns=["phase", "start", "end"])

    start = attacks["timestamp"].min() - pd.Timedelta(minutes=5)
    end = attacks["timestamp"].max() + pd.Timedelta(minutes=2)
    df = pm.loc[start:end].reset_index().rename(columns={"index": "timestamp"})
    df["pressure_delta"] = df["pressure"].diff().fillna(0.0)
    df["pressure_mean_dev"] = df["pressure"] - df["pressure"].rolling(60, min_periods=1).mean()
    df["inter_arrival_time"] = 1.0  # telemetry has been reconstructed at 1 Hz
    df["write_freq_10s"] = df["is_write"].rolling(10, min_periods=1).sum()
    df["length"] = 0.0
    df["ground_truth"] = 0
    df["attack_phase"] = 0
    for phase, attack_start, attack_end in intervals:
        # Retain a short phase after 1 Hz resampling; no label is inferred from scores.
        if (attack_end - attack_start).total_seconds() < 3:
            pad = pd.Timedelta(seconds=(3 - (attack_end - attack_start).total_seconds()) / 2 + 1)
            attack_start, attack_end = attack_start - pad, attack_end + pad
        mask = (df["timestamp"] >= attack_start) & (df["timestamp"] <= attack_end)
        df.loc[mask, "attack_phase"] = phase
        if phase in ALERT_PHASES:
            df.loc[mask, "ground_truth"] = 1

    first = phases[phases.phase.isin(ALERT_PHASES)].sort_values("start").iloc[0]
    train_end = first.start - pd.Timedelta(seconds=60)
    val_end = first.end + pd.Timedelta(seconds=60)
    df["split"] = "train"
    df.loc[(df.timestamp >= train_end) & (df.timestamp < val_end), "split"] = "val"
    df.loc[df.timestamp >= val_end, "split"] = "test"
    return engineer_features(df), phases


def rolling_entropy(values: pd.Series, window: int) -> pd.Series:
    def entropy(x: np.ndarray) -> float:
        _, count = np.unique(x, return_counts=True)
        p = count / count.sum()
        return float(-(p * np.log2(p)).sum())
    return values.rolling(window, min_periods=1).apply(entropy, raw=True)


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """Features aimed at benign bursts and protocol mix, not attack labels."""
    df = df.copy()
    df["pressure_rate_5s"] = df["pressure"].diff(5).fillna(0.0) / 5.0
    df["pressure_std_10s"] = df["pressure"].rolling(10, min_periods=2).std().fillna(0.0)
    df["func_code_entropy_30s"] = rolling_entropy(df["func_code"], 30)
    df["write_ratio_30s"] = df["is_write"].rolling(30, min_periods=1).mean()
    return df


def make_sequences(x: np.ndarray) -> np.ndarray:
    if len(x) < SEQ_LEN:
        raise ValueError(f"Need at least {SEQ_LEN} samples for an LSTM sequence.")
    return np.asarray([x[i:i + SEQ_LEN] for i in range(len(x) - SEQ_LEN + 1)], dtype=np.float32)


def build_lstm(n_features: int):
    import tensorflow as tf
    inp = tf.keras.layers.Input(shape=(SEQ_LEN, n_features))
    x = tf.keras.layers.LSTM(16, activation="tanh")(inp)
    x = tf.keras.layers.RepeatVector(SEQ_LEN)(x)
    x = tf.keras.layers.LSTM(16, activation="tanh", return_sequences=True)(x)
    out = tf.keras.layers.TimeDistributed(tf.keras.layers.Dense(n_features))(x)
    model = tf.keras.Model(inp, out)
    model.compile(optimizer="adam", loss="mse")
    return model


def train_scores(df: pd.DataFrame, features: list[str]) -> dict[str, np.ndarray]:
    """Fit scaler/models on labelled-normal training rows only; return high=anomaly scores."""
    set_seed()
    train_mask = (df.split == "train").to_numpy()
    if int(df.loc[train_mask, "ground_truth"].sum()) != 0:
        raise RuntimeError("LEAKAGE: the normal-only training split contains attack-labelled samples.")
    scaler = MinMaxScaler().fit(df.loc[train_mask, features])
    x = scaler.transform(df[features]).astype(np.float32)
    x_train = x[train_mask]

    isolation = IsolationForest(contamination=0.01, n_estimators=200,
                                max_samples=min(128, len(x_train)), random_state=SEED).fit(x_train)
    # sklearn decision_function is low for anomalies; invert it once for a common direction.
    if_score = -isolation.decision_function(x)

    model = build_lstm(len(features))
    train_seq = make_sequences(x_train)
    model.fit(train_seq, train_seq, epochs=30, batch_size=16, verbose=0, shuffle=False)
    full_seq = make_sequences(x)
    reconstructed = model.predict(full_seq, verbose=0)
    error = np.mean((full_seq - reconstructed) ** 2, axis=(1, 2))
    lstm_score = np.concatenate([np.full(SEQ_LEN - 1, error[0]), error])
    lstm_score = pd.Series(lstm_score).rolling(3, min_periods=1).mean().to_numpy()
    return {"if": if_score, "lstm": lstm_score, "train_mask": train_mask}


def threshold_from_pr(y: np.ndarray, score: np.ndarray, beta: float) -> tuple[float, dict]:
    precision, recall, thresholds = precision_recall_curve(y, score)
    fbeta = (1 + beta ** 2) * precision * recall / (beta ** 2 * precision + recall + 1e-12)
    # final PR point has no associated threshold
    idx = int(np.nanargmax(fbeta[:-1]))
    return float(thresholds[idx]), {"precision": precision, "recall": recall, "fbeta": fbeta, "index": idx}


def normalize_train(score: np.ndarray, train_mask: np.ndarray) -> np.ndarray:
    lo, hi = score[train_mask].min(), score[train_mask].max()
    return np.clip((score - lo) / (hi - lo + 1e-12), 0, 1)


def metrics(y: np.ndarray, pred: np.ndarray, score: np.ndarray | None = None) -> dict:
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"TP": int(tp), "FP": int(fp), "TN": int(tn), "FN": int(fn),
            "Precision": precision_score(y, pred, zero_division=0),
            "Recall": recall_score(y, pred, zero_division=0),
            "F1": f1_score(y, pred, zero_division=0),
            "AUC-PR": average_precision_score(y, score) if score is not None else np.nan}


def consecutive(pred: np.ndarray, n: int) -> np.ndarray:
    out, run = np.zeros_like(pred), 0
    for i, flagged in enumerate(pred):
        run = run + 1 if flagged else 0
        if run >= n:
            out[i] = 1
    return out


def plot_distributions(df: pd.DataFrame, scores: dict, output: Path) -> None:
    test = df.split.eq("test").to_numpy()
    fig, axes = plt.subplots(1, 2, figsize=(12, 4))
    for ax, key, title in zip(axes, ("lstm", "if"), ("LSTM-AE reconstruction error", "Isolation Forest anomaly score")):
        for label, color in ((0, "#2ca02c"), (1, "#d62728")):
            values = scores[key][test & df.ground_truth.eq(label).to_numpy()]
            ax.hist(values, bins=40, density=True, alpha=.55, color=color, label="Attack" if label else "Normal")
        ax.set_title(title); ax.set_xlabel("Higher = more anomalous"); ax.set_ylabel("Density"); ax.legend()
    fig.tight_layout(); fig.savefig(output / "score_distributions_test.png", dpi=180); plt.close(fig)


def plot_pr(y: np.ndarray, score_map: dict[str, np.ndarray], chosen: dict[str, tuple[float, dict]], output: Path) -> None:
    fig, ax = plt.subplots(figsize=(7, 5))
    for name, score in score_map.items():
        p, r, _ = precision_recall_curve(y, score)
        threshold, curve = chosen[name]
        i = curve["index"]
        ax.plot(r, p, label=f"{name} (AP={average_precision_score(y, score):.3f})")
        ax.scatter(curve["recall"][i], curve["precision"][i], s=45)
    ax.set(xlabel="Recall", ylabel="Precision", title="Validation PR curves (selection only)")
    ax.legend(); ax.grid(alpha=.25); fig.tight_layout(); fig.savefig(output / "pr_curves_validation.png", dpi=180); plt.close(fig)


def select_config(df: pd.DataFrame, scores: dict, beta: float, output: Path | None = None) -> tuple[dict[str, np.ndarray], dict]:
    val = df.split.eq("val").to_numpy()
    y_val = df.loc[val, "ground_truth"].to_numpy()
    train = scores["train_mask"]
    if_norm, lstm_norm = normalize_train(scores["if"], train), normalize_train(scores["lstm"], train)
    individual = {}
    selection = {}
    for name, score in {"Isolation Forest": if_norm, "LSTM-AE": lstm_norm}.items():
        th, curve = threshold_from_pr(y_val, score[val], beta)
        individual[name] = (score >= th).astype(int)
        selection[name] = {"threshold": th, "validation": metrics(y_val, individual[name][val], score[val])}
    and_pred = individual["Isolation Forest"] & individual["LSTM-AE"]

    best = None
    for alpha in np.linspace(0, 1, 21):
        score = alpha * lstm_norm + (1 - alpha) * if_norm
        th, curve = threshold_from_pr(y_val, score[val], beta)
        pred = (score >= th).astype(int)
        candidate = (fbeta_score(y_val, pred[val], beta=beta, zero_division=0), alpha, th, score, pred)
        if best is None or candidate[0] > best[0]: best = candidate
    _, alpha, weighted_th, weighted_score, weighted_pred = best

    # The meta-model sees a small labelled subset of validation data. Its threshold
    # is selected on the other half, preventing the threshold from being fit twice.
    idx = np.flatnonzero(val)
    fit_idx, select_idx = train_test_split(idx, test_size=.5, random_state=SEED,
                                            stratify=df.loc[idx, "ground_truth"])
    x_meta = np.column_stack([lstm_norm, if_norm])
    meta = LogisticRegression(class_weight="balanced", random_state=SEED, max_iter=1000).fit(
        x_meta[fit_idx], df.loc[fit_idx, "ground_truth"])
    meta_score = meta.predict_proba(x_meta)[:, 1]
    meta_th, _ = threshold_from_pr(df.loc[select_idx, "ground_truth"].to_numpy(), meta_score[select_idx], beta)
    meta_pred = (meta_score >= meta_th).astype(int)

    pred = {"Baseline (train-percentile OR)": None, "Threshold recalibration (best individual)": None,
            "AND fusion": and_pred, "Weighted score fusion": weighted_pred,
            "Stacked logistic regression": meta_pred}
    score_map = {"AND fusion": np.minimum(lstm_norm, if_norm), "Weighted score fusion": weighted_score,
                 "Stacked logistic regression": meta_score}
    best_individual = max(selection, key=lambda k: selection[k]["validation"]["F1"])
    pred["Threshold recalibration (best individual)"] = individual[best_individual]
    score_map["Threshold recalibration (best individual)"] = lstm_norm if best_individual == "LSTM-AE" else if_norm
    selection.update({"weighted_alpha_lstm": float(alpha), "weighted_threshold": float(weighted_th),
                      "meta_threshold": float(meta_th), "best_individual": best_individual})
    if output is not None:
        plot_pr(y_val, {"IF": if_norm[val], "LSTM": lstm_norm[val], "Weighted": weighted_score[val], "Stacked": meta_score[val]},
                {"IF": threshold_from_pr(y_val, if_norm[val], beta), "LSTM": threshold_from_pr(y_val, lstm_norm[val], beta),
                 "Weighted": threshold_from_pr(y_val, weighted_score[val], beta), "Stacked": threshold_from_pr(y_val, meta_score[val], beta)}, output)
    return pred, {"scores": score_map, "selection": selection, "individual": individual}


def write_report(output: Path, df: pd.DataFrame, rows: list[dict], selection: dict, leakage_ok: bool) -> None:
    test = df.split.eq("test").to_numpy(); y = df.loc[test, "ground_truth"].to_numpy()
    n_attack, n_normal = int(y.sum()), int((y == 0).sum())
    lines = ["# Precision recalibration report", "", "## Data and leakage audit", "",
             f"- Held-out realistic test set: {n_normal} normal and {n_attack} attack windows (normal:attack = {n_normal}:{n_attack}).",
             f"- Normal-only training set: {int((df.split == 'train').sum())} windows; attack-labelled rows in it: {int(df.loc[df.split == 'train', 'ground_truth'].sum())}.",
             f"- Leakage check: **{'PASS' if leakage_ok else 'FAIL'}**. The scaler and both unsupervised models are fit only on training rows.",
             "- Existing ML fusion in `evaluate.py` is OR logic (`if_anomaly | lstm_anomaly`).", "",
             "## Test-set comparison", "", "| Configuration | Precision | Recall | F1 | AUC-PR | TP | FP | TN | FN |",
             "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for r in rows:
        lines.append("| {Configuration} | {Precision:.3f} | {Recall:.3f} | {F1:.3f} | {AUC-PR:.3f} | {TP} | {FP} | {TN} | {FN} |".format(**r))
    lines += ["", "## Selected validation hyperparameters", "", "```json", json.dumps(selection, indent=2, default=float), "```", "",
              "## Interpretation for a paper", "",
              "The original low precision is consistent with the base-rate effect in a highly imbalanced deployment stream. Precision is TP/(TP+FP): even with high recall, a detector that raises alerts on a modest fraction of the much larger benign population can accumulate many false positives. Therefore recall alone, and attack-only testing in particular, cannot characterize operational alert quality because the latter contains no true negatives and makes precision uninformative.", "",
              "Thresholds must consequently be selected on a mixed, labelled validation period and then frozen before evaluation on a separate mixed test period. The reported AUC-PR and confusion matrices retain the actual attack prevalence; they should not be compared directly with attack-only results. This experiment is limited by a single chronological campaign and correlated one-second windows, so an independent campaign and event-level evaluation are still needed before claiming deployment-level generalization."]
    (output / "REPORT.md").write_text("\n".join(lines))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", default="results/20260701_161537")
    parser.add_argument("--out", default="results/precision_recalibration")
    parser.add_argument("--beta", type=float, default=.5, help="F-beta beta < 1 prioritises precision")
    args = parser.parse_args()
    if not 0 < args.beta <= 1: raise ValueError("--beta must be in (0, 1].")
    output = Path(args.out); output.mkdir(parents=True, exist_ok=True)
    df, _ = load_campaign(Path(args.data_dir))
    leakage_ok = int(df.loc[df.split == "train", "ground_truth"].sum()) == 0
    print(f"Leakage check: {'PASS' if leakage_ok else 'FAIL'}; training attack labels={int(df.loc[df.split == 'train', 'ground_truth'].sum())}")
    print(df.groupby("split")["ground_truth"].agg(["size", "sum"]))

    raw_scores = train_scores(df, RAW_FEATURES)
    plot_distributions(df, raw_scores, output)
    pred, detail = select_config(df, raw_scores, args.beta, output)
    train = raw_scores["train_mask"]
    # Reproducible baseline: each score threshold is the 99th percentile of its normal training distribution.
    baseline = ((raw_scores["if"] >= np.quantile(raw_scores["if"][train], .99)) |
                (raw_scores["lstm"] >= np.quantile(raw_scores["lstm"][train], .99))).astype(int)
    pred["Baseline (train-percentile OR)"] = baseline
    detail["scores"]["Baseline (train-percentile OR)"] = np.maximum(normalize_train(raw_scores["if"], train), normalize_train(raw_scores["lstm"], train))

    test = df.split.eq("test").to_numpy(); y_test = df.loc[test, "ground_truth"].to_numpy()
    rows = []
    for name in ["Baseline (train-percentile OR)", "Threshold recalibration (best individual)", "AND fusion", "Weighted score fusion", "Stacked logistic regression"]:
        score = detail["scores"].get(name)
        row = metrics(y_test, pred[name][test], score[test] if score is not None else None)
        row["Configuration"] = name; rows.append(row)

    # Temporal rule is compared only after the fusion choice; choose N by validation F-beta.
    best_fusion = max(["AND fusion", "Weighted score fusion", "Stacked logistic regression"],
                      key=lambda name: fbeta_score(df.loc[df.split.eq("val"), "ground_truth"], pred[name][df.split.eq("val")], beta=args.beta, zero_division=0))
    temporal_candidates = [(n, consecutive(pred[best_fusion], n)) for n in (2, 3, 5)]
    n, smooth_pred = max(temporal_candidates, key=lambda x: fbeta_score(df.loc[df.split.eq("val"), "ground_truth"], x[1][df.split.eq("val")], beta=args.beta, zero_division=0))
    row = metrics(y_test, smooth_pred[test], detail["scores"][best_fusion][test]); row["Configuration"] = f"Temporal smoothing ({best_fusion}, N={n})"; rows.append(row)

    # Feature-engineering re-run: same chronological split and validation-only selection.
    eng_scores = train_scores(df, RAW_FEATURES + ENGINEERED_FEATURES)
    eng_pred, eng_detail = select_config(df, eng_scores, args.beta)
    eng_best = max(["AND fusion", "Weighted score fusion", "Stacked logistic regression"],
                   key=lambda name: fbeta_score(df.loc[df.split.eq("val"), "ground_truth"], eng_pred[name][df.split.eq("val")], beta=args.beta, zero_division=0))
    row = metrics(y_test, eng_pred[eng_best][test], eng_detail["scores"][eng_best][test]); row["Configuration"] = f"Feature engineering ({eng_best})"; rows.append(row)

    table = pd.DataFrame(rows); table.to_csv(output / "comparison.csv", index=False)
    selection = {"raw": detail["selection"], "temporal_base": best_fusion, "temporal_n": n,
                 "engineered": eng_detail["selection"], "seed": SEED, "beta": args.beta,
                 "raw_features": RAW_FEATURES, "engineered_features": ENGINEERED_FEATURES}
    (output / "selection.json").write_text(json.dumps(selection, indent=2, default=float))
    write_report(output, df, rows, selection, leakage_ok)
    print(table.to_string(index=False))
    print(f"Saved report and plots to {output}")


if __name__ == "__main__":
    main()
