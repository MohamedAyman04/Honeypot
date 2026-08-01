#!/usr/bin/env python3
"""Chronological supervised classification of known Modbus attack phases.

The labelled campaign is deliberately evaluated as a supervised detection task:
models learn patterns from labelled attack windows in the earlier portion of the
campaign, validation selects models and thresholds, and the later portion is
used once as a held-out test set.
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.base import clone
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, confusion_matrix, f1_score,
                             precision_recall_curve, precision_score, recall_score,
                             ConfusionMatrixDisplay)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from precision_recalibration import (ENGINEERED_FEATURES, RAW_FEATURES, SEED,
                                     load_campaign)

FEATURES = RAW_FEATURES + ENGINEERED_FEATURES
SPLIT_FRACTIONS = (0.60, 0.20, 0.20)
OLD_UNSUPERVISED = {
    "Configuration": "Old unsupervised LSTM-AE + IF (OR; legacy split)",
    "Precision": 0.037, "Recall": 1.000, "F1": 0.072, "AUC-PR": 0.037,
    "TP": 208, "FP": 5364, "TN": 0, "FN": 0,
}


def set_seed() -> None:
    random.seed(SEED)
    np.random.seed(SEED)


def chronological_split(df: pd.DataFrame) -> pd.DataFrame:
    """Assign contiguous 60/20/20 time splits and verify every split has both classes."""
    df = df.sort_values("timestamp").reset_index(drop=True).copy()
    n = len(df)
    train_end, val_end = int(n * SPLIT_FRACTIONS[0]), int(n * sum(SPLIT_FRACTIONS[:2]))
    df["supervised_split"] = "test"
    df.loc[:train_end - 1, "supervised_split"] = "train"
    df.loc[train_end:val_end - 1, "supervised_split"] = "val"
    balance = df.groupby("supervised_split", sort=False)["ground_truth"].agg(["size", "sum"])
    if (balance["sum"] == 0).any() or (balance["sum"] == balance["size"]).any():
        raise RuntimeError(f"A chronological split lacks both classes:\n{balance}")
    return df


def balance_table(df: pd.DataFrame) -> pd.DataFrame:
    grouped = df.groupby("supervised_split", sort=False)["ground_truth"].agg(["size", "sum"])
    out = pd.DataFrame({"normal": grouped["size"] - grouped["sum"], "attack": grouped["sum"]})
    out["total"] = grouped["size"]
    return out.loc[["train", "val", "test"]]


def best_threshold(y: np.ndarray, score: np.ndarray) -> float:
    """Choose an F1-optimal operating threshold on validation labels only."""
    precision, recall, thresholds = precision_recall_curve(y, score)
    f1 = 2 * precision * recall / (precision + recall + 1e-12)
    return float(thresholds[int(np.nanargmax(f1[:-1]))])


def evaluate(y: np.ndarray, score: np.ndarray, threshold: float) -> dict[str, float | int]:
    pred = (score >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"Precision": precision_score(y, pred, zero_division=0),
            "Recall": recall_score(y, pred, zero_division=0),
            "F1": f1_score(y, pred, zero_division=0),
            "AUC-PR": average_precision_score(y, score),
            "TP": int(tp), "FP": int(fp), "TN": int(tn), "FN": int(fn)}


def candidates(imbalance: float) -> dict[str, list[tuple[dict, object]]]:
    """Small, fixed searches: validation AUC-PR selects among these candidates."""
    common_xgb = dict(objective="binary:logistic", eval_metric="aucpr", n_jobs=2,
                      random_state=SEED, scale_pos_weight=imbalance, tree_method="hist")
    common_lgb = dict(objective="binary", n_jobs=2, random_state=SEED,
                      is_unbalance=True, verbosity=-1)
    return {
        "XGBoost": [
            ({"n_estimators": n, "max_depth": depth, "learning_rate": lr},
             XGBClassifier(**common_xgb, n_estimators=n, max_depth=depth, learning_rate=lr,
                           subsample=.9, colsample_bytree=.9))
            for n, depth, lr in ((150, 3, .05), (250, 3, .05), (150, 5, .05), (200, 3, .10))],
        "LightGBM": [
            ({"n_estimators": n, "max_depth": depth, "learning_rate": lr},
             LGBMClassifier(**common_lgb, n_estimators=n, max_depth=depth, learning_rate=lr,
                            num_leaves=15 if depth == 3 else 31))
            for n, depth, lr in ((150, 3, .05), (250, 3, .05), (150, 5, .05), (200, 3, .10))],
        "Random Forest": [
            ({"n_estimators": n, "max_depth": depth},
             RandomForestClassifier(n_estimators=n, max_depth=depth, min_samples_leaf=2,
                                    class_weight="balanced", n_jobs=2, random_state=SEED))
            for n, depth in ((200, None), (300, None), (200, 8), (300, 12))],
        "Logistic Regression": [
            ({"C": c}, Pipeline([("scale", StandardScaler()),
                                  ("model", LogisticRegression(C=c, class_weight="balanced",
                                                               max_iter=2000, random_state=SEED))]))
            for c in (.1, 1.0, 10.0)],
    }


def fit_select(name: str, options: list[tuple[dict, object]], x_train: pd.DataFrame,
               y_train: np.ndarray, x_val: pd.DataFrame, y_val: np.ndarray) -> tuple[object, dict, float, float]:
    best = None
    for params, model in options:
        model.fit(x_train, y_train)
        val_score = model.predict_proba(x_val)[:, 1]
        ap = average_precision_score(y_val, val_score)
        candidate = (ap, params, model, best_threshold(y_val, val_score))
        if best is None or candidate[0] > best[0]:
            best = candidate
    assert best is not None
    ap, params, model, threshold = best
    return model, params, threshold, float(ap)


def feature_importance(model: object) -> pd.Series:
    if isinstance(model, Pipeline):
        values = np.abs(model.named_steps["model"].coef_[0])
    else:
        values = model.feature_importances_
    return pd.Series(values, index=FEATURES).sort_values(ascending=False).head(10)


def plot_confusion(y: np.ndarray, score: np.ndarray, threshold: float, name: str, output: Path) -> None:
    fig, ax = plt.subplots(figsize=(5, 4))
    ConfusionMatrixDisplay.from_predictions(y, score >= threshold, display_labels=["Normal", "Attack"],
                                            cmap="Blues", colorbar=False, ax=ax)
    ax.set_title(f"Held-out test confusion matrix — {name}")
    fig.tight_layout(); fig.savefig(output / "best_model_confusion_matrix.png", dpi=180); plt.close(fig)


def plot_importance(importance: pd.Series, name: str, output: Path) -> None:
    fig, ax = plt.subplots(figsize=(8, 5))
    importance.sort_values().plot.barh(ax=ax, color="#1f77b4")
    ax.set(title=f"Top feature importances — {name}", xlabel="Importance")
    fig.tight_layout(); fig.savefig(output / "best_model_feature_importance.png", dpi=180); plt.close(fig)


def write_report(output: Path, balance: pd.DataFrame, phase_balance: pd.DataFrame, table: pd.DataFrame,
                 best_name: str, best_params: dict, best_val_ap: float, threshold: float,
                 importance: pd.Series, selected: dict) -> None:
    lines = ["# Supervised classification report", "",
             "## Framing and chronological split", "",
             "This is a supervised known-attack detector. The contiguous 60/20/20 train/validation/test split preserves time order; hyperparameters and the operating threshold are selected on validation only, then frozen for the later test set.",
             "", "| Split | Normal | Attack | Total |", "|---|---:|---:|---:|"]
    for split, row in balance.iterrows():
        lines.append(f"| {split} | {row.normal} | {row.attack} | {row.total} |")
    lines += ["", "Known attack-phase coverage (attack windows only):", "",
              "| Split | Phase 4 | Phase 5 | Phase 7 | Phase 8 |", "|---|---:|---:|---:|---:|"]
    for split in ("train", "val", "test"):
        row = phase_balance.loc[split] if split in phase_balance.index else pd.Series(dtype=int)
        lines.append(f"| {split} | {int(row.get(4, 0))} | {int(row.get(5, 0))} | {int(row.get(7, 0))} | {int(row.get(8, 0))} |")
    lines += ["", "## Held-out test comparison", "",
              "| Configuration | Precision | Recall | F1 | AUC-PR | TP | FP | TN | FN |",
              "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for _, row in table.iterrows():
        lines.append("| {Configuration} | {Precision:.3f} | {Recall:.3f} | {F1:.3f} | {AUC-PR:.3f} | {TP} | {FP} | {TN} | {FN} |".format(**row))
    lines += ["", "The legacy unsupervised row is included for paper context as requested, but it used the earlier unsupervised protocol's different test window (5,572 rows). Its confusion-matrix counts are therefore not directly comparable with this 1,206-row supervised holdout."]
    lines += ["", "## Validation-selected hyperparameters", "",
              "The small fixed candidate searches used validation AUC-PR for model selection and validation F1 for the frozen threshold.",
              "", "| Model | Hyperparameters | Validation AUC-PR | Threshold |", "|---|---|---:|---:|"]
    for name, result in selected.items():
        lines.append(f"| {name} | `{json.dumps(result['params'], sort_keys=True)}` | {result['validation_auc_pr']:.3f} | {result['threshold']:.6f} |")
    lines += ["", "## Selected best model", "",
              f"- Model: **{best_name}** (chosen by validation AUC-PR = {best_val_ap:.3f})",
              f"- Hyperparameters: `{json.dumps(best_params, sort_keys=True)}`",
              f"- Frozen validation-selected F1 threshold: `{threshold:.6f}`", "",
              "## Top-10 feature importances", "", "| Feature | Importance |", "|---|---:|"]
    for feature, value in importance.items():
        lines.append(f"| {feature} | {value:.6f} |")
    lines += ["", "## Honest limitation", "",
              "The classifier is trained to recognize labelled attack behavior from this campaign and known attack phases. It is not evidence that the model can detect entirely novel attack techniques, new phases, or independent deployments; such generalization requires leave-one-attack-type-out and multi-campaign evaluation, which is future work."]
    (output / "REPORT.md").write_text("\n".join(lines))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", default="results/20260701_161537")
    parser.add_argument("--out", default="results/supervised_comparison")
    args = parser.parse_args()
    set_seed()
    output = Path(args.out); output.mkdir(parents=True, exist_ok=True)
    df, _ = load_campaign(Path(args.data_dir))
    df = chronological_split(df)
    balance = balance_table(df)
    total_attacks = int(df.ground_truth.sum())
    print(f"Total labelled attack windows: {total_attacks}")
    print(balance.to_string())
    if total_attacks < 150:
        raise RuntimeError("Fewer than 150 attack windows: use stratified 5-fold CV rather than this holdout.")

    train, val, test = (df.supervised_split.eq(name).to_numpy() for name in ("train", "val", "test"))
    x_train, y_train = df.loc[train, FEATURES], df.loc[train, "ground_truth"].to_numpy()
    x_val, y_val = df.loc[val, FEATURES], df.loc[val, "ground_truth"].to_numpy()
    x_test, y_test = df.loc[test, FEATURES], df.loc[test, "ground_truth"].to_numpy()
    imbalance = float((y_train == 0).sum() / y_train.sum())

    rows, selected = [], {}
    for name, options in candidates(imbalance).items():
        model, params, threshold, val_ap = fit_select(name, options, x_train, y_train, x_val, y_val)
        test_score = model.predict_proba(x_test)[:, 1]
        row = evaluate(y_test, test_score, threshold)
        row["Configuration"] = name; rows.append(row)
        selected[name] = {"params": params, "threshold": threshold, "validation_auc_pr": val_ap,
                          "model": model, "test_score": test_score}
        print(f"{name}: validation AUC-PR={val_ap:.3f}, threshold={threshold:.4f}")

    best_name = max(selected, key=lambda name: selected[name]["validation_auc_pr"])
    best = selected[best_name]
    importance = feature_importance(best["model"])
    table = pd.DataFrame(rows + [OLD_UNSUPERVISED])
    table.to_csv(output / "comparison.csv", index=False)
    plot_confusion(y_test, best["test_score"], best["threshold"], best_name, output)
    plot_importance(importance, best_name, output)
    phase_balance = df[df.ground_truth.eq(1)].groupby(["supervised_split", "attack_phase"]).size().unstack(fill_value=0)
    write_report(output, balance, phase_balance, table, best_name, best["params"], best["validation_auc_pr"],
                 best["threshold"], importance, selected)
    metadata = {"seed": SEED, "split_fractions": SPLIT_FRACTIONS, "class_imbalance_train": imbalance,
                "selection_metric": "validation AUC-PR", "threshold_metric": "validation F1",
                "selected": {name: {key: value for key, value in result.items() if key not in {"model", "test_score"}}
                             for name, result in selected.items()}}
    (output / "selection.json").write_text(json.dumps(metadata, indent=2, default=float))
    print(table.to_string(index=False))
    print(f"Saved report, comparison, and plots to {output}")


if __name__ == "__main__":
    main()
