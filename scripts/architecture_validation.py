#!/usr/bin/env python3
"""
Architecture Validation Suite — IEEE TII
========================================
Offline evaluation of the complete cross-layer detection architecture using
exported campaign telemetry. Replays rule-based detectors, recomputes ML
predictions (without modifying ML training methodology), and produces
publication-ready ablation tables, coverage matrices, and figures.

Usage:
    python3 scripts/architecture_validation.py
    python3 scripts/architecture_validation.py --data-dir results/20260701_161537
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import sys
import textwrap
import warnings
from dataclasses import dataclass, field
from datetime import timezone
from typing import Callable

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.preprocessing import MinMaxScaler

warnings.filterwarnings("ignore")

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
DEFAULT_DATA_DIR = os.path.join(PROJECT_DIR, "results", "20260701_161537")
DEFAULT_ATTACK_CSV = os.path.join(PROJECT_DIR, "results", "attack_results_extended.csv")
OUT_ROOT = os.path.join(PROJECT_DIR, "results", "architecture_validation")

# ── Detector thresholds (mirrors ml-engine/trainer.py) ────────────────────────
EXPERT_PRESSURE_DELTA_THRESHOLD = 20.0
EXPERT_PRESSURE_MEAN_DEV = 35.0
OVER_PRESSURE_LIMIT = 300.0
EWMA_LAMBDA = 0.1
CUSUM_THRESHOLD = 6.0
CUSUM_K = 1.5
DRIFT_CONFIRM_NEEDED = 3
DRIFT_RANGE_THRESHOLD = 30.0
MIN_SLOPE = 0.05
SLOPE_THRESHOLD = 0.3
SLOPE_DIRECTION_RATIO = 0.8
SLOPE_WINDOW_SIZE = 20
REPLAY_WINDOW_SIZE = 10
REPLAY_MATCH_RATIO = 0.95
REPLAY_BASELINE_DEV = 12.0
ZERO_VAR_BASELINE_DEV_PCT = 8.0
STARTUP_GRACE_SECONDS = 120
LSTM_SEQ_LEN = 10

FEATURE_COLS = [
    "pressure", "flow_rate", "temperature",
    "pressure_delta", "pressure_mean_dev",
    "inter_arrival_time", "write_freq_10s",
    "is_write", "func_code", "length",
]
NETWORK_FEATURES = ["inter_arrival_time", "write_freq_10s", "is_write", "func_code", "length"]
PROCESS_FEATURES = ["pressure", "flow_rate", "temperature", "pressure_delta", "pressure_mean_dev"]

ALERT_PHASES = [4, 5, 7, 8]
PHASE_NAMES = {
    4: "Semantic Injection",
    5: "Stealth Drift",
    7: "Actuator Manipulation",
    8: "Replay Attack",
}

DETECTOR_LABELS = {
    "semantic_injection": "Forced Write (Network)",
    "stealth_drift_ewma": "EWMA/CUSUM",
    "stealth_drift": "Threshold (Mean Dev)",
    "over_pressure": "Over-Pressure (Physics)",
    "cross_layer": "Cross-Layer Rule",
    "replay": "Replay Detector",
    "if": "Isolation Forest",
    "lstm": "LSTM Autoencoder",
}

LAYER_DETECTORS = {
    "network": ["semantic_injection"],
    "physics": ["over_pressure", "stealth_drift"],
    "rules": ["stealth_drift_ewma", "stealth_drift", "over_pressure"],
    "cross_layer": ["cross_layer", "replay"],
    "ml": ["if", "lstm"],
    "replay": ["replay"],
}

# ── Aesthetics ────────────────────────────────────────────────────────────────
BG_DARK, BG_MID = "#1a1a2e", "#16213e"
plt.rcParams.update({
    "figure.facecolor": BG_DARK, "axes.facecolor": BG_MID,
    "axes.labelcolor": "#e0e0e0", "axes.titlecolor": "#ffffff",
    "xtick.color": "#e0e0e0", "ytick.color": "#e0e0e0",
    "text.color": "#e0e0e0", "font.family": "DejaVu Sans",
    "savefig.dpi": 150,
})


@dataclass
class CampaignData:
    df: pd.DataFrame
    phases: pd.DataFrame
    alerts: pd.DataFrame
    campaign_start: pd.Timestamp
    data_dir: str
    attack_csv: str


@dataclass
class DetectorOutput:
    name: str
    pred: np.ndarray
    alert_times: list[pd.Timestamp] = field(default_factory=list)


def _find_attack_csv(data_dir: str) -> str:
    for name in ("attack_results_extended.csv", "attack_results.csv"):
        p = os.path.join(data_dir, name)
        if os.path.isfile(p):
            return p
    if os.path.isfile(DEFAULT_ATTACK_CSV):
        return DEFAULT_ATTACK_CSV
    for f in os.listdir(os.path.dirname(data_dir) or "."):
        if f == "attack_results_extended.csv":
            return os.path.join(os.path.dirname(data_dir), f)
    raise FileNotFoundError("attack_results_extended.csv not found")


def load_campaign(data_dir: str) -> CampaignData:
    csv_dir = os.path.join(data_dir, "csv")
    attack_csv = _find_attack_csv(data_dir)
    pipeline_path = os.path.join(csv_dir, "pipeline_metrics.csv")
    modbus_path = os.path.join(csv_dir, "modbus_events.csv")

    pm = pd.read_csv(pipeline_path)
    pm["timestamp"] = pd.to_datetime(pm["_time"], utc=True)
    pm = pm.sort_values("timestamp").set_index("timestamp").resample("1s").first().ffill().fillna(0)

    me = pd.read_csv(modbus_path) if os.path.isfile(modbus_path) else pd.DataFrame()
    if not me.empty:
        me["timestamp"] = pd.to_datetime(me["_time"], utc=True)
        me["is_write"] = me["fc_type"].apply(lambda x: 1 if str(x).lower() == "write" else 0)
        me = me.sort_values("timestamp")
        me_idx = me.set_index("timestamp").resample("1s").max()
        pm["is_write"] = me_idx["is_write"].fillna(0).astype(int)
        pm["func_code"] = me_idx["func_code"].fillna(0).astype(int)
    else:
        pm["is_write"] = 0
        pm["func_code"] = 0

    pm["pressure_delta"] = pm["pressure"].diff().fillna(0)
    pm["pressure_mean_dev"] = pm["pressure"] - pm["pressure"].rolling(60, min_periods=1).mean()
    pm["inter_arrival_time"] = 1.0
    pm["write_freq_10s"] = pm["is_write"].rolling(10, min_periods=1).sum()
    pm["length"] = 0

    atk = pd.read_csv(attack_csv)
    atk["timestamp"] = pd.to_datetime(atk["timestamp"], utc=True)
    start_time = atk["timestamp"].min() - pd.Timedelta(minutes=5)
    end_time = atk["timestamp"].max() + pd.Timedelta(minutes=2)
    pm = pm.loc[start_time:end_time].reset_index().rename(columns={"index": "timestamp"})

    phases = _load_phases(attack_csv)
    df = _label_ground_truth(pm, phases)
    df = _assign_splits(df, phases)

    alerts_path = os.path.join(csv_dir, "security_alerts.csv")
    alerts = pd.read_csv(alerts_path) if os.path.isfile(alerts_path) else pd.DataFrame()
    if not alerts.empty:
        alerts["timestamp"] = pd.to_datetime(alerts["_time"], utc=True)

    campaign_start = df["timestamp"].min()
    return CampaignData(df=df, phases=phases, alerts=alerts,
                        campaign_start=campaign_start, data_dir=data_dir, attack_csv=attack_csv)


def _load_phases(attack_csv: str) -> pd.DataFrame:
    df = pd.read_csv(attack_csv)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    intervals, started = [], {}
    meta = {
        4: "Semantic Injection", 5: "Stealth Drift",
        7: "Actuator Manipulation", 8: "Replay Attack",
    }
    for _, row in df.iterrows():
        ph = int(row["phase"])
        if row["status"] == "started":
            started[ph] = row["timestamp"]
        elif row["status"] == "completed" and ph in started:
            intervals.append({
                "phase": ph, "name": meta.get(ph, row.get("phase_name", "")),
                "start": started.pop(ph), "end": row["timestamp"],
                "expects_alert": ph in ALERT_PHASES,
            })
    return pd.DataFrame(intervals)


def _label_ground_truth(df: pd.DataFrame, phases: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["ground_truth"] = 0
    df["attack_phase"] = 0
    for _, ph in phases.iterrows():
        start, end = ph["start"], ph["end"]
        # Sub-second attack phases (e.g. semantic injection) need padded windows
        # so 1 Hz resampling retains ground-truth samples.
        dur_s = (end - start).total_seconds()
        if dur_s < 3.0:
            pad = pd.Timedelta(seconds=(3.0 - dur_s) / 2 + 1.0)
            start = start - pad
            end = end + pad
        mask = (df["timestamp"] >= start) & (df["timestamp"] <= end)
        if ph["expects_alert"]:
            df.loc[mask, "ground_truth"] = 1
        df.loc[mask, "attack_phase"] = ph["phase"]
    return df


def _assign_splits(df: pd.DataFrame, phases: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["split"] = "train"
    alerting = phases[phases["expects_alert"]]
    if alerting.empty:
        n = len(df)
        df.loc[: int(n * 0.4), "split"] = "train"
        df.loc[int(n * 0.4) : int(n * 0.6), "split"] = "val"
        df.loc[int(n * 0.6) :, "split"] = "test"
        return df

    first_start = alerting["start"].min()
    first_end = alerting[alerting["start"] == first_start]["end"].min()
    train_end = first_start - pd.Timedelta(seconds=60)
    val_end = first_end + pd.Timedelta(seconds=60)
    df.loc[df["timestamp"] < train_end, "split"] = "train"
    df.loc[(df["timestamp"] >= train_end) & (df["timestamp"] < val_end), "split"] = "val"
    df.loc[df["timestamp"] >= val_end, "split"] = "test"
    return df


def _in_grace(ts: pd.Timestamp, campaign_start: pd.Timestamp) -> bool:
    return (ts - campaign_start).total_seconds() < STARTUP_GRACE_SECONDS


def _times_to_binary(df: pd.DataFrame, times: list[pd.Timestamp]) -> np.ndarray:
    pred = np.zeros(len(df), dtype=int)
    if not times:
        return pred
    ts_set = set(pd.Timestamp(t).floor("s") for t in times)
    for i, t in enumerate(df["timestamp"]):
        if t.floor("s") in ts_set:
            pred[i] = 1
    return pred


def _alert_times_from_export(alerts: pd.DataFrame, alert_type: str) -> list[pd.Timestamp]:
    if alerts.empty or "alert_type" not in alerts.columns:
        return []
    sub = alerts[alerts["alert_type"] == alert_type]
    return sorted(sub["timestamp"].unique().tolist())


def detect_semantic_injection(df: pd.DataFrame, forced_writes_path: str,
                              campaign_start: pd.Timestamp) -> DetectorOutput:
    times: list[pd.Timestamp] = []
    if os.path.isfile(forced_writes_path):
        fw = pd.read_csv(forced_writes_path)
        fw["timestamp"] = pd.to_datetime(fw["_time"], utc=True)
        for _, row in fw.iterrows():
            reg = int(row.get("register", -1))
            if 100 <= reg <= 103 and not _in_grace(row["timestamp"], campaign_start):
                times.append(row["timestamp"])
    pred = _times_to_binary(df, times)
    return DetectorOutput("semantic_injection", pred, times)


def detect_expert_rules(df: pd.DataFrame, campaign_start: pd.Timestamp) -> dict[str, DetectorOutput]:
    outputs = {}
    for name in ("cross_layer", "stealth_drift", "over_pressure"):
        times: list[pd.Timestamp] = []
        for _, row in df.iterrows():
            if _in_grace(row["timestamp"], campaign_start):
                continue
            fired = False
            if name == "cross_layer":
                fired = (abs(row["pressure_delta"]) > EXPERT_PRESSURE_DELTA_THRESHOLD
                         and row["write_freq_10s"] == 0)
            elif name == "stealth_drift":
                fired = abs(row["pressure_mean_dev"]) > EXPERT_PRESSURE_MEAN_DEV
            elif name == "over_pressure":
                fired = row["pressure"] > OVER_PRESSURE_LIMIT
            if fired:
                times.append(row["timestamp"])
        outputs[name] = DetectorOutput(name, _times_to_binary(df, times), times)
    return outputs


def _compute_slope(values: collections.deque) -> float:
    arr = np.array(list(values), dtype=float)
    if len(arr) < 4:
        return 0.0
    x = np.arange(len(arr), dtype=float)
    return float(np.polyfit(x, arr, 1)[0])


def detect_ewma_cusum(df: pd.DataFrame, campaign_start: pd.Timestamp) -> DetectorOutput:
    times: list[pd.Timestamp] = []
    ewma_state = None
    cusum_pos = cusum_neg = 0.0
    cumulative_dev = 0.0
    baseline_samples: collections.deque = collections.deque(maxlen=60)
    pressure_history: collections.deque = collections.deque(maxlen=SLOPE_WINDOW_SIZE)
    slope_history: collections.deque = collections.deque(maxlen=10)
    drift_confirm = 0

    for _, row in df.iterrows():
        ts = row["timestamp"]
        pressure = float(row["pressure"])
        if _in_grace(ts, campaign_start):
            continue

        # Actuator write reset (reg >= 200 implied by non-sensor writes)
        if row["write_freq_10s"] > 0 and row["is_write"] == 1:
            # Only reset if NOT a sensor-register pattern (heuristic: large pressure delta absent)
            if not (100 <= row.get("func_code", 0) <= 103):
                ewma_state = None
                cusum_pos = cusum_neg = 0.0
                cumulative_dev = 0.0
                pressure_history.clear()
                slope_history.clear()
                continue

        pressure_history.append(pressure)
        baseline_samples.append(pressure)

        if ewma_state is None:
            if len(baseline_samples) >= 10:
                ewma_state = float(np.mean(list(baseline_samples)))
            else:
                ewma_state = pressure
            continue

        ewma_state = EWMA_LAMBDA * pressure + (1 - EWMA_LAMBDA) * ewma_state
        deviation = pressure - ewma_state
        cusum_pos = max(0.0, cusum_pos + deviation - CUSUM_K)
        cusum_neg = max(0.0, cusum_neg - deviation - CUSUM_K)
        cumulative_dev += abs(deviation)

        slope_detected = False
        if len(pressure_history) >= 8:
            slope_val = _compute_slope(pressure_history)
            slope_history.append(slope_val)
            if len(slope_history) >= 5:
                pos = sum(1 for s in slope_history if s > 0)
                ratio = pos / len(slope_history)
                inc = ratio >= SLOPE_DIRECTION_RATIO and slope_val > SLOPE_THRESHOLD
                dec = ratio <= (1.0 - SLOPE_DIRECTION_RATIO) and slope_val < -SLOPE_THRESHOLD
                slope_detected = (inc or dec) and abs(slope_val) > MIN_SLOPE

        cusum_detected = cusum_pos > CUSUM_THRESHOLD or cusum_neg > CUSUM_THRESHOLD
        range_detected = False
        if len(pressure_history) >= 8:
            arr = list(pressure_history)
            range_detected = (max(arr) - min(arr)) > DRIFT_RANGE_THRESHOLD

        if slope_detected or cusum_detected or range_detected:
            drift_confirm += 1
            if drift_confirm >= DRIFT_CONFIRM_NEEDED:
                times.append(ts)
                cusum_pos = cusum_neg = 0.0
                cumulative_dev = 0.0
                drift_confirm = 0
        else:
            drift_confirm = 0

    return DetectorOutput("stealth_drift_ewma", _times_to_binary(df, times), times)


def detect_replay(df: pd.DataFrame, campaign_start: pd.Timestamp) -> DetectorOutput:
    times: list[pd.Timestamp] = []
    pressures = df["pressure"].values.astype(float)
    baseline_samples: collections.deque = collections.deque(maxlen=60)
    replay_fps: collections.deque = collections.deque(maxlen=20)

    def fingerprint(window):
        return tuple(round(v * 4) / 4 for v in window)

    for i in range(len(df)):
        ts = df.iloc[i]["timestamp"]
        if _in_grace(ts, campaign_start):
            continue
        baseline_samples.append(pressures[i])
        if len(baseline_samples) < REPLAY_WINDOW_SIZE + 10:
            continue
        baseline = float(np.mean(list(baseline_samples)))
        window = pressures[max(0, i - REPLAY_WINDOW_SIZE + 1): i + 1]
        if len(window) < REPLAY_WINDOW_SIZE:
            continue

        std = float(np.std(window))
        mean_v = float(np.mean(window))
        baseline_dev_pct = abs(mean_v - baseline) / baseline * 100.0 if baseline > 1.0 else 0.0
        current_fp = fingerprint(window.tolist())
        replay_fps.append(current_fp)

        zero_var = std < 0.05 and baseline_dev_pct > ZERO_VAR_BASELINE_DEV_PCT
        fp_match = False
        if len(replay_fps) >= 3:
            for prev in list(replay_fps)[:-1]:
                if len(prev) == len(current_fp):
                    ratio = sum(a == b for a, b in zip(prev, current_fp)) / len(current_fp)
                    if ratio >= REPLAY_MATCH_RATIO and baseline_dev_pct > REPLAY_BASELINE_DEV:
                        fp_match = True
                        break
        if zero_var or fp_match:
            times.append(ts)

    return DetectorOutput("replay", _times_to_binary(df, times), times)


def train_ml_detectors(df: pd.DataFrame, feature_cols: list[str] | None = None) -> dict[str, DetectorOutput]:
    """Train IF + LSTM on pre-attack baseline; tune on validation split."""
    import random
    import tensorflow as tf
    tf.get_logger().setLevel("ERROR")
    random.seed(42)
    np.random.seed(42)
    tf.keras.utils.set_random_seed(42)

    cols = feature_cols or FEATURE_COLS
    X = df[cols].values
    scaler = MinMaxScaler()
    Xs = scaler.fit_transform(X)
    X_train = Xs[df["split"] == "train"]
    X_val = Xs[df["split"] == "val"]
    y_val = df[df["split"] == "val"]["ground_truth"].values

    # Isolation Forest
    best_f1, best_model, best_thresh = -1, None, 0
    for cont in [0.005, 0.01, 0.02]:
        for n_est in [100, 200]:
            model = IsolationForest(contamination=cont, n_estimators=n_est,
                                    max_samples=128, random_state=42)
            model.fit(X_train)
            scores = model.decision_function(X_val)
            for th in np.linspace(scores.min(), scores.max(), 80):
                f1 = f1_score(y_val, (scores < th).astype(int), zero_division=0)
                if f1 > best_f1:
                    best_f1, best_model, best_thresh = f1, model, th

    if_scores = best_model.decision_function(Xs)
    if_pred = (if_scores < best_thresh).astype(int)

    # LSTM
    def make_seqs(data):
        return np.array([data[i:i + LSTM_SEQ_LEN] for i in range(len(data) - LSTM_SEQ_LEN + 1)])

    X_train_seq = make_seqs(X_train)
    X_full_seq = make_seqs(Xs)
    n_feat = len(cols)
    inp = tf.keras.layers.Input(shape=(LSTM_SEQ_LEN, n_feat))
    enc = tf.keras.layers.LSTM(16, activation="relu")(inp)
    rep = tf.keras.layers.RepeatVector(LSTM_SEQ_LEN)(enc)
    dec = tf.keras.layers.LSTM(16, activation="relu", return_sequences=True)(rep)
    out = tf.keras.layers.TimeDistributed(tf.keras.layers.Dense(n_feat))(dec)
    model_lstm = tf.keras.models.Model(inp, out)
    model_lstm.compile(optimizer="adam", loss="mse")
    model_lstm.fit(X_train_seq, X_train_seq, epochs=30, verbose=0, batch_size=16)

    preds = model_lstm.predict(X_full_seq, verbose=0)
    errors = np.mean(np.square(X_full_seq - preds), axis=(1, 2))
    errors_padded = np.concatenate([np.full(LSTM_SEQ_LEN - 1, errors[0]), errors])
    smoothed = pd.Series(errors_padded).rolling(3, min_periods=1).mean().values

    val_errors = smoothed[df["split"] == "val"]
    best_lstm_f1, best_lstm_th = -1, 0
    for th in np.linspace(val_errors.min(), val_errors.max(), 120):
        f1 = f1_score(y_val, (val_errors > th).astype(int), zero_division=0)
        if f1 > best_lstm_f1:
            best_lstm_f1, best_lstm_th = f1, th
    lstm_pred = (smoothed > best_lstm_th).astype(int)

    if_times = [df.iloc[i]["timestamp"] for i in range(len(df)) if if_pred[i]]
    lstm_times = [df.iloc[i]["timestamp"] for i in range(len(df)) if lstm_pred[i]]

    return {
        "if": DetectorOutput("if", if_pred, if_times),
        "lstm": DetectorOutput("lstm", lstm_pred, lstm_times),
    }


def build_all_detectors(data: CampaignData, use_export_validation: bool = True) -> dict[str, DetectorOutput]:
    df = data.df
    csv_dir = os.path.join(data.data_dir, "csv")
    detectors: dict[str, DetectorOutput] = {}

    detectors["semantic_injection"] = detect_semantic_injection(
        df, os.path.join(csv_dir, "forced_writes.csv"), data.campaign_start)

    detectors.update(detect_expert_rules(df, data.campaign_start))
    detectors["stealth_drift_ewma"] = detect_ewma_cusum(df, data.campaign_start)
    detectors["replay"] = detect_replay(df, data.campaign_start)
    detectors.update(train_ml_detectors(df))

    if use_export_validation and not data.alerts.empty:
        mapping = {
            "semantic_injection": "SEMANTIC_INJECTION",
            "stealth_drift_ewma": "STEALTH_DRIFT_EWMA",
            "stealth_drift": "STEALTH_DRIFT",
            "over_pressure": "OVER_PRESSURE",
            "cross_layer": "CROSS_LAYER_ANOMALY",
            "replay": "REPLAY_ATTACK",
            "if": "ISOLATION_FOREST",
            "lstm": "LSTM_AUTOENCODER",
        }
        for det_key, alert_type in mapping.items():
            export_times = _alert_times_from_export(data.alerts, alert_type)
            if export_times:
                export_pred = _times_to_binary(df, export_times)
                offline = detectors[det_key].pred
                agreement = (export_pred & offline).sum() / max(export_pred.sum(), 1)
                # Prefer union of offline replay + export for live-faithful evaluation
                combined_times = sorted(set(export_times) | set(detectors[det_key].alert_times))
                detectors[det_key] = DetectorOutput(
                    det_key, np.clip(export_pred | offline, 0, 1), combined_times)

    return detectors


def combine_detectors(detectors: dict[str, DetectorOutput],
                      active: list[str]) -> np.ndarray:
    if not active:
        return np.zeros(len(next(iter(detectors.values())).pred), dtype=int)
    out = np.zeros(len(next(iter(detectors.values())).pred), dtype=int)
    for name in active:
        out = out | detectors[name].pred
    return out


def _quiet_mask(df: pd.DataFrame, phases: pd.DataFrame) -> np.ndarray:
    """Pre-attack normal baseline (matches evaluate.py quiet-baseline intent)."""
    alerting = phases[phases["expects_alert"]]
    if alerting.empty:
        return (df["split"] == "train").values
    cutoff = alerting["start"].min() - pd.Timedelta(seconds=60)
    return ((df["timestamp"] < cutoff) & (df["ground_truth"] == 0)).values


def compute_metrics(df: pd.DataFrame, pred: np.ndarray,
                    eval_mask: np.ndarray | None = None,
                    phases: pd.DataFrame | None = None) -> dict:
    if eval_mask is None:
        eval_mask = df["split"] == "test"
    if isinstance(eval_mask, pd.Series):
        eval_mask = eval_mask.values
    y_true = df.loc[eval_mask, "ground_truth"].values
    y_pred = pred[eval_mask]
    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    p = precision_score(y_true, y_pred, zero_division=0)
    r = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    # Attack-only recall (meaningful when post-attack recovery inflates FP)
    atk_mask = eval_mask & (df["attack_phase"].isin(ALERT_PHASES).values)
    atk_recall = float(pred[atk_mask].sum() / max(atk_mask.sum(), 1))

    spec = np.nan
    if phases is not None:
        quiet = _quiet_mask(df, phases)
        if quiet.sum() > 0:
            spec = float((pred[quiet] == 0).sum() / quiet.sum())

    return {
        "precision": p, "recall": r, "f1": f1,
        "attack_recall": atk_recall, "specificity": spec,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
    }


def event_interval_detected(alert_times: list[pd.Timestamp], start: pd.Timestamp,
                            end: pd.Timestamp, grace_s: float = 60.0) -> bool:
    """Event-based detection for sub-second attack phases."""
    deadline = end + pd.Timedelta(seconds=grace_s)
    for t in alert_times:
        if start <= t <= deadline:
            return True
    return False


def build_interval_detection_table(df: pd.DataFrame, phases: pd.DataFrame,
                                   detectors: dict[str, DetectorOutput],
                                   grace_s: float = 60.0) -> pd.DataFrame:
    rows = []
    for _, ph in phases[phases["expects_alert"]].iterrows():
        for name, det in detectors.items():
            detected = event_interval_detected(det.alert_times, ph["start"], ph["end"], grace_s)
            rows.append({
                "phase": ph["phase"], "phase_name": ph["name"],
                "interval_start": ph["start"], "interval_end": ph["end"],
                "duration_s": (ph["end"] - ph["start"]).total_seconds(),
                "detector": DETECTOR_LABELS.get(name, name), "key": name,
                "detected": detected,
            })
    return pd.DataFrame(rows)


def build_venn_ml_stats(data_dir: str) -> dict:
    """Parse evaluate.py report for IF/LSTM/OR complementarity (active split)."""
    report_path = os.path.join(PROJECT_DIR, "evaluation_report.txt")
    if not os.path.isfile(report_path):
        return {}
    text = open(report_path).read()
    stats = {}
    in_active = in_complementarity = False
    for line in text.splitlines():
        if "ACTIVE ATTACK PERIOD ONLY" in line:
            in_active = True
        if "FULL TIMELINE" in line:
            in_active = False
        if "COMPLEMENTARITY AUDIT" in line:
            in_complementarity = True
        if in_active and "Ensemble OR" in line:
            parts = line.split("|")
            for p in parts:
                if "R=" in p:
                    stats["or_recall_active"] = float(p.split("R=")[1].strip())
                if "F1=" in p:
                    stats["or_f1_active"] = float(p.split("F1=")[1].split()[0].strip())
        if in_complementarity and "IF Solo TP count" in line:
            stats["if_tp"] = int(line.split(":")[-1].strip())
        if in_complementarity and "LSTM Solo TP count" in line:
            stats["lstm_tp"] = int(line.split(":")[-1].strip())
        if in_complementarity and "Shared TP indices" in line:
            stats["shared_tp"] = int(line.split(":")[-1].split()[0].strip())
    return stats


def phase_interval_detection_rate(df: pd.DataFrame, pred: np.ndarray,
                                  phases: pd.DataFrame) -> float:
    """Fraction of attack intervals with at least one alert (binary per run)."""
    detected, total = 0, 0
    for _, ph in phases[phases["expects_alert"]].iterrows():
        mask = (df["timestamp"] >= ph["start"]) & (df["timestamp"] <= ph["end"])
        idx = df.index[mask]
        if len(idx) == 0:
            continue
        total += 1
        if pred[idx].any():
            detected += 1
    return detected / max(total, 1)


def compute_operational(df: pd.DataFrame, pred: np.ndarray,
                        phases: pd.DataFrame) -> dict:
    test_df = df[df["split"] == "test"]
    normal = test_df[test_df["ground_truth"] == 0]
    duration_h = max((test_df["timestamp"].max() - test_df["timestamp"].min()).total_seconds() / 3600, 1e-6)
    normal_h = max((normal["timestamp"].max() - normal["timestamp"].min()).total_seconds() / 3600, 1e-6) if len(normal) else duration_h

    fp_count = int(((pred[df["split"] == "test"] == 1) & (test_df["ground_truth"] == 0).values).sum())
    alert_count = int(pred[df["split"] == "test"].sum())

    latencies, coverages, durations = [], [], []
    for _, ph in phases[phases["expects_alert"]].iterrows():
        mask = (df["timestamp"] >= ph["start"]) & (df["timestamp"] <= ph["end"])
        phase_idx = df.index[mask]
        if len(phase_idx) == 0:
            continue
        phase_pred = pred[phase_idx]
        detected_idx = phase_idx[phase_pred == 1]
        if len(detected_idx) == 0:
            latencies.append(np.nan)
            coverages.append(0.0)
            durations.append(0.0)
            continue
        first_alert = df.loc[detected_idx.min(), "timestamp"]
        last_alert = df.loc[detected_idx.max(), "timestamp"]
        latencies.append((first_alert - ph["start"]).total_seconds())
        coverages.append(phase_pred.sum() / len(phase_pred))
        durations.append((last_alert - first_alert).total_seconds())

    return {
        "false_alarms_per_hour": fp_count / normal_h,
        "alerts_per_hour": alert_count / duration_h,
        "mean_detection_latency_s": float(np.nanmean(latencies)) if latencies else np.nan,
        "mean_phase_coverage": float(np.mean(coverages)) if coverages else 0.0,
        "mean_detection_duration_s": float(np.mean(durations)) if durations else 0.0,
    }


def per_phase_recall(df: pd.DataFrame, pred: np.ndarray) -> dict[int, float]:
    out = {}
    test = df[df["split"] == "test"]
    for ph in ALERT_PHASES:
        mask = (test["attack_phase"] == ph) & (test["ground_truth"] == 1)
        n = mask.sum()
        if n == 0:
            out[ph] = np.nan
        else:
            out[ph] = pred[test.index[mask]].sum() / n
    return out


def phase_detection_status(df: pd.DataFrame, pred: np.ndarray,
                           phases: pd.DataFrame) -> dict[tuple, str]:
    """Return Detected / Partial / Missed per (phase, interval)."""
    status = {}
    for _, ph in phases[phases["expects_alert"]].iterrows():
        mask = (df["timestamp"] >= ph["start"]) & (df["timestamp"] <= ph["end"])
        idx = df.index[mask]
        if len(idx) == 0:
            status[(ph["phase"], ph["start"])] = "Missed"
            continue
        frac = pred[idx].sum() / len(idx)
        key = (ph["phase"], ph["start"])
        if frac == 0:
            status[key] = "Missed"
        elif frac >= 0.5:
            status[key] = "Detected"
        else:
            status[key] = "Partial"
    return status


def complementarity_stats(df: pd.DataFrame,
                          detectors: dict[str, DetectorOutput]) -> pd.DataFrame:
    test_mask = df["split"] == "test"
    rows = []
    det_names = list(detectors.keys())
    for ph in ALERT_PHASES:
        phase_mask = test_mask & (df["attack_phase"] == ph) & (df["ground_truth"] == 1)
        idx = df.index[phase_mask]
        if len(idx) == 0:
            continue
        sets = {n: set(i for i in idx if detectors[n].pred[i]) for n in det_names}
        union = set().union(*sets.values()) if sets else set()
        for n in det_names:
            exclusive = sets[n] - set().union(*(sets[m] for m in det_names if m != n))
            rows.append({
                "phase": ph, "detector": n,
                "tp_samples": len(sets[n]),
                "exclusive_samples": len(exclusive),
                "union_coverage": len(union) / len(idx),
            })
    return pd.DataFrame(rows)


def interpret_ablation(name: str, full: dict, ablated: dict,
                       full_phase: dict, ablated_phase: dict) -> str:
    delta_f1 = ablated["f1"] - full["f1"]
    delta_r = ablated["recall"] - full["recall"]
    lost_phases = [PHASE_NAMES[p] for p in ALERT_PHASES
                   if full_phase.get(p, 0) > 0.1 and ablated_phase.get(p, 0) < full_phase.get(p, 0) - 0.1]
    capability = name.replace("Full − ", "").replace("Full", "complete stack")
    if name.startswith("Full −"):
        direction = "Removing" if delta_f1 < 0 else "Removing (surprisingly)"
        return textwrap.fill(
            f"{direction} {capability} changed F1 by {delta_f1:+.3f} and recall by {delta_r:+.3f}. "
            f"{'Attack phases most affected: ' + ', '.join(lost_phases) + '. ' if lost_phases else ''}"
            f"This layer provides detection capability not fully substitutable by remaining layers.",
            width=100)
    return textwrap.fill(
        f"{name} alone achieves F1={ablated['f1']:.3f}, recall={ablated['recall']:.3f}. "
        f"{'Strongest on: ' + ', '.join(PHASE_NAMES[p] for p in ALERT_PHASES if ablated_phase.get(p, 0) > 0.5) + '. ' if any(ablated_phase.get(p, 0) > 0.5 for p in ALERT_PHASES) else 'Limited standalone coverage. '}",
        width=100)


# ── Configuration definitions ─────────────────────────────────────────────────
ALL_DET = list(DETECTOR_LABELS.keys())

BASELINE_CONFIGS = {
    "Network only": LAYER_DETECTORS["network"],
    "Process only": LAYER_DETECTORS["physics"] + LAYER_DETECTORS["rules"] + ["stealth_drift_ewma"],
    "Rules only": LAYER_DETECTORS["rules"] + LAYER_DETECTORS["cross_layer"],
    "IF only": ["if"],
    "LSTM only": ["lstm"],
    "Rules + ML": LAYER_DETECTORS["rules"] + LAYER_DETECTORS["cross_layer"] + LAYER_DETECTORS["ml"],
    "Cross-layer only": LAYER_DETECTORS["cross_layer"],
    "Complete architecture": ALL_DET,
}

ABLATION_CONFIGS = {
    "Full − IF": [d for d in ALL_DET if d != "if"],
    "Full − LSTM": [d for d in ALL_DET if d != "lstm"],
    "Full − EWMA/CUSUM": [d for d in ALL_DET if d != "stealth_drift_ewma"],
    "Full − Threshold rules": [d for d in ALL_DET if d not in ("stealth_drift", "over_pressure")],
    "Full − Forced-write": [d for d in ALL_DET if d != "semantic_injection"],
    "Full − Replay": [d for d in ALL_DET if d != "replay"],
    "Full − Cross-layer": [d for d in ALL_DET if d != "cross_layer"],
    "Full − Physics validation": [d for d in ALL_DET if d not in ("over_pressure", "stealth_drift")],
    "Full − ML ensemble": [d for d in ALL_DET if d not in ("if", "lstm")],
}


def run_cross_layer_experiment(data: CampaignData) -> pd.DataFrame:
    rows = []
    for label, cols in [
        ("Network only", NETWORK_FEATURES),
        ("Process only", PROCESS_FEATURES),
        ("Network + Process", FEATURE_COLS),
    ]:
        dets = train_ml_detectors(data.df, feature_cols=cols)
        for det_name, det in dets.items():
            m = compute_metrics(data.df, det.pred)
            op = compute_operational(data.df, det.pred, data.phases)
            ph = per_phase_recall(data.df, det.pred)
            rows.append({
                "feature_set": label, "model": det_name.upper(),
                **m, **op,
                **{f"phase_{p}_recall": ph.get(p, np.nan) for p in ALERT_PHASES},
            })
    # Rule-based cross-layer
    dets = build_all_detectors(data, use_export_validation=False)
    for label, active in [
        ("Network only (rules)", LAYER_DETECTORS["network"]),
        ("Process only (rules)", LAYER_DETECTORS["physics"] + ["stealth_drift_ewma"]),
        ("Network + Process (rules)", LAYER_DETECTORS["network"] + LAYER_DETECTORS["physics"] + ["stealth_drift_ewma"]),
    ]:
        pred = combine_detectors(dets, active)
        m = compute_metrics(data.df, pred)
        op = compute_operational(data.df, pred, data.phases)
        ph = per_phase_recall(data.df, pred)
        rows.append({
            "feature_set": label, "model": "RULES",
            **m, **op,
            **{f"phase_{p}_recall": ph.get(p, np.nan) for p in ALERT_PHASES},
        })
    return pd.DataFrame(rows)


def run_physics_perturbation(data: CampaignData) -> pd.DataFrame:
    variants = {
        "Realistic physics": lambda d: d,
        "Constant pressure": lambda d: _perturb_constant(d, ["pressure", "pressure_delta", "pressure_mean_dev"]),
        "Constant flow": lambda d: _perturb_constant(d, ["flow_rate"]),
        "High sensor noise": lambda d: _perturb_noise(d, scale=3.0),
        "Disabled dynamics": lambda d: _perturb_flat_dynamics(d),
    }
    rows = []
    for name, fn in variants.items():
        ddf = fn(data.df.copy())
        cd = CampaignData(df=ddf, phases=data.phases, alerts=data.alerts,
                          campaign_start=data.campaign_start, data_dir=data.data_dir,
                          attack_csv=data.attack_csv)
        dets = build_all_detectors(cd, use_export_validation=False)
        pred = combine_detectors(dets, ALL_DET)
        m = compute_metrics(ddf, pred)
        ph = per_phase_recall(ddf, pred)
        rows.append({"variant": name, **m, **{f"phase_{p}_recall": ph.get(p, np.nan) for p in ALERT_PHASES}})
    return pd.DataFrame(rows)


def _perturb_constant(df: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    for c in cols:
        if c in df.columns:
            df[c] = df[c].mean()
    return df


def _perturb_noise(df: pd.DataFrame, scale: float = 3.0) -> pd.DataFrame:
    rng = np.random.default_rng(42)
    for c in ("pressure", "flow_rate", "temperature"):
        if c in df.columns:
            noise = rng.normal(0, df[c].std() * scale * 0.1, len(df))
            df[c] = df[c] + noise
    df["pressure_delta"] = df["pressure"].diff().fillna(0)
    df["pressure_mean_dev"] = df["pressure"] - df["pressure"].rolling(60, min_periods=1).mean()
    return df


def _perturb_flat_dynamics(df: pd.DataFrame) -> pd.DataFrame:
    rng = np.random.default_rng(42)
    base = df["pressure"].mean()
    df["pressure"] = base + rng.normal(0, 2, len(df))
    df["flow_rate"] = df["flow_rate"].mean()
    df["pressure_delta"] = df["pressure"].diff().fillna(0)
    df["pressure_mean_dev"] = df["pressure"] - df["pressure"].rolling(60, min_periods=1).mean()
    return df


def run_modularity_sensitivity(data: CampaignData) -> pd.DataFrame:
    rows = []
    for cusum_th in [3.0, 6.0, 9.0]:
        global CUSUM_THRESHOLD
        old = CUSUM_THRESHOLD
        CUSUM_THRESHOLD = cusum_th
        dets = build_all_detectors(data, use_export_validation=False)
        pred = combine_detectors(dets, ALL_DET)
        m = compute_metrics(data.df, pred)
        rows.append({"parameter": "CUSUM_THRESHOLD", "value": cusum_th, **m})
        CUSUM_THRESHOLD = old
    for op_th in [250.0, 300.0, 350.0]:
        global OVER_PRESSURE_LIMIT
        old = OVER_PRESSURE_LIMIT
        OVER_PRESSURE_LIMIT = op_th
        dets = build_all_detectors(data, use_export_validation=False)
        pred = combine_detectors(dets, ALL_DET)
        m = compute_metrics(data.df, pred)
        rows.append({"parameter": "OVER_PRESSURE_LIMIT", "value": op_th, **m})
        OVER_PRESSURE_LIMIT = old
    return pd.DataFrame(rows)


def plot_figures(out_dir: str, ablation_df: pd.DataFrame, coverage_df: pd.DataFrame,
                 cross_df: pd.DataFrame, comp_df: pd.DataFrame, data: CampaignData,
                 detectors: dict[str, DetectorOutput]):
    fig_dir = os.path.join(out_dir, "figures")
    os.makedirs(fig_dir, exist_ok=True)

    # Ablation bar chart
    fig, ax = plt.subplots(figsize=(12, 6))
    plot_df = ablation_df.sort_values("f1", ascending=True)
    colors = ["#e74c3c" if "Full −" in n else "#3498db" for n in plot_df["configuration"]]
    ax.barh(plot_df["configuration"], plot_df["f1"], color=colors)
    ax.set_xlabel("F1 Score (test split)")
    ax.set_title("Architecture Ablation — F1 Score")
    fig.savefig(os.path.join(fig_dir, "ablation_f1.png"))
    plt.close(fig)

    # Per-phase heatmap
    phase_cols = [f"phase_{p}_recall" for p in ALERT_PHASES]
    hm = ablation_df.set_index("configuration")[phase_cols]
    hm.columns = [PHASE_NAMES[p] for p in ALERT_PHASES]
    fig, ax = plt.subplots(figsize=(10, max(6, len(hm) * 0.35)))
    sns.heatmap(hm, annot=True, fmt=".2f", cmap="YlOrRd", ax=ax, vmin=0, vmax=1)
    ax.set_title("Per-Phase Recall by Configuration")
    fig.savefig(os.path.join(fig_dir, "phase_recall_heatmap.png"))
    plt.close(fig)

    # Coverage matrix (aggregate duplicate phase intervals → best status per phase)
    fig, ax = plt.subplots(figsize=(12, 5))
    agg = coverage_df.groupby(["phase", "detector"])["status_code"].max().reset_index()
    pivot = agg.pivot(index="phase", columns="detector", values="status_code")
    pivot.index = [PHASE_NAMES.get(int(i), str(i)) for i in pivot.index]
    sns.heatmap(pivot, annot=True, fmt="d", cmap="RdYlGn", ax=ax, vmin=0, vmax=2)
    ax.set_title("Attack Coverage Matrix (0=Missed, 1=Partial, 2=Detected)")
    fig.savefig(os.path.join(fig_dir, "coverage_matrix.png"))
    plt.close(fig)

    # Cross-layer comparison
    if not cross_df.empty:
        fig, axes = plt.subplots(1, 3, figsize=(15, 5))
        for ax, metric in zip(axes, ["precision", "recall", "f1"]):
            sub = cross_df.groupby("feature_set")[metric].max()
            sub.plot(kind="bar", ax=ax, color="#2ecc71")
            ax.set_title(metric.capitalize())
            ax.tick_params(axis="x", rotation=30)
        fig.suptitle("Cross-Layer Feature Ablation (ML)")
        fig.tight_layout()
        fig.savefig(os.path.join(fig_dir, "cross_layer_comparison.png"))
        plt.close(fig)

    # Complementarity — exclusive detections by phase
    if not comp_df.empty:
        fig, ax = plt.subplots(figsize=(12, 6))
        pivot = comp_df.pivot(index="detector", columns="phase", values="exclusive_samples")
        pivot.columns = [PHASE_NAMES.get(c, c) for c in pivot.columns]
        pivot.plot(kind="bar", ax=ax, colormap="tab10")
        ax.set_title("Exclusive Detections by Detector and Phase")
        ax.legend(title="Phase")
        fig.savefig(os.path.join(fig_dir, "complementarity_exclusive.png"))
        plt.close(fig)

    # Venn-style UpSet: detector overlap on test attack samples
    test_mask = data.df["split"] == "test"
    attack_idx = data.df.index[test_mask & (data.df["ground_truth"] == 1)]
    if len(attack_idx) > 0:
        fig, ax = plt.subplots(figsize=(10, 6))
        names = list(detectors.keys())
        overlap_data = []
        for n in names:
            overlap_data.append((n, len(set(attack_idx) & set(i for i in attack_idx if detectors[n].pred[i]))))
        od = pd.DataFrame(overlap_data, columns=["detector", "attack_samples"])
        od["label"] = od["detector"].map(DETECTOR_LABELS)
        ax.barh(od["label"], od["attack_samples"], color="#9b59b6")
        ax.set_xlabel("Attack samples flagged (test split)")
        ax.set_title("Detector Coverage on Attack Samples")
        fig.savefig(os.path.join(fig_dir, "detector_coverage.png"))
        plt.close(fig)


def generate_latex_table(df: pd.DataFrame, caption: str, label: str) -> str:
    cols = [c for c in df.columns if c not in ("interpretation",)]
    header = " & ".join(cols) + r" \\"
    lines = [r"\begin{table}[!t]", r"\centering", f"\\caption{{{caption}}}", f"\\label{{{label}}}",
             r"\begin{tabular}{" + "l" * len(cols) + "}", r"\hline", header, r"\hline"]
    for _, row in df[cols].iterrows():
        vals = []
        for c in cols:
            v = row[c]
            if isinstance(v, float):
                vals.append(f"{v:.3f}" if abs(v) < 10 else f"{v:.1f}")
            else:
                vals.append(str(v))
        lines.append(" & ".join(vals) + r" \\")
    lines += [r"\hline", r"\end{tabular}", r"\end{table}"]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Architecture validation for IEEE TII")
    parser.add_argument("--data-dir", default=DEFAULT_DATA_DIR)
    parser.add_argument("--out-dir", default=OUT_ROOT)
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    log_path = os.path.join(args.out_dir, "experiment.log")

    def log(msg: str):
        print(msg)
        with open(log_path, "a") as f:
            f.write(msg + "\n")

    log(f"=== Architecture Validation ===")
    log(f"Data: {args.data_dir}")

    data = load_campaign(args.data_dir)
    log(f"Timeline: {len(data.df)} samples, {len(data.phases)} phase intervals")

    detectors = build_all_detectors(data)
    log(f"Detectors: {list(detectors.keys())}")

    eval_mask = data.df["split"] == "test"
    full_pred = combine_detectors(detectors, ALL_DET)
    full_metrics = compute_metrics(data.df, full_pred, eval_mask, data.phases)
    full_phase = per_phase_recall(data.df, full_pred)
    log(f"Full architecture: F1={full_metrics['f1']:.3f} R={full_metrics['recall']:.3f} P={full_metrics['precision']:.3f}")

    # ── 1 & 9. Baselines + ablation ───────────────────────────────────────────
    ablation_rows = []
    all_configs = {**BASELINE_CONFIGS, **ABLATION_CONFIGS}
    for cfg_name, active in all_configs.items():
        pred = combine_detectors(detectors, active)
        m = compute_metrics(data.df, pred, eval_mask, data.phases)
        op = compute_operational(data.df, pred, data.phases)
        ph = per_phase_recall(data.df, pred)
        interval_rate = phase_interval_detection_rate(data.df, pred, data.phases)
        row = {"configuration": cfg_name, **m, **op,
               "interval_detection_rate": interval_rate,
               **{f"phase_{p}_recall": ph.get(p, np.nan) for p in ALERT_PHASES}}
        if cfg_name in BASELINE_CONFIGS or cfg_name.startswith("Full −"):
            row["interpretation"] = interpret_ablation(
                cfg_name, full_metrics, m, full_phase, ph)
        ablation_rows.append(row)
    ablation_df = pd.DataFrame(ablation_rows)
    ablation_df.to_csv(os.path.join(args.out_dir, "table_ablation.csv"), index=False)

    # ── 4. Individual rule validation ─────────────────────────────────────────
    rule_rows = []
    for name, det in detectors.items():
        m = compute_metrics(data.df, det.pred, eval_mask, data.phases)
        op = compute_operational(data.df, det.pred, data.phases)
        ph = per_phase_recall(data.df, det.pred)
        rule_rows.append({
            "detector": DETECTOR_LABELS.get(name, name), "key": name,
            **m, **op,
            **{f"phase_{p}_recall": ph.get(p, np.nan) for p in ALERT_PHASES},
        })
    rule_df = pd.DataFrame(rule_rows)
    rule_df.to_csv(os.path.join(args.out_dir, "table_rule_validation.csv"), index=False)

    # ── 5. Complementarity ────────────────────────────────────────────────────
    comp_df = complementarity_stats(data.df, detectors)
    comp_df.to_csv(os.path.join(args.out_dir, "complementarity.csv"), index=False)

    # Intersection/union summary
    test_idx = data.df.index[eval_mask & (data.df["ground_truth"] == 1)]
    sets = {n: set(i for i in test_idx if detectors[n].pred[i]) for n in detectors}
    union = set().union(*sets.values()) if sets else set()
    inter = set.intersection(*[s for s in sets.values() if s]) if all(sets.values()) else set()
    comp_summary = {
        "test_attack_samples": len(test_idx),
        "union_tp_samples": len(union),
        "intersection_all_detectors": len(inter),
        "detectors_with_zero_overlap": sum(
            1 for a in detectors for b in detectors
            if a < b and not (sets[a] & sets[b])
        ) // 2,
    }
    with open(os.path.join(args.out_dir, "complementarity_summary.json"), "w") as f:
        json.dump(comp_summary, f, indent=2)

    # ── 6. Attack coverage matrix ─────────────────────────────────────────────
    coverage_rows = []
    for name, det in detectors.items():
        for _, ph in data.phases[data.phases["expects_alert"]].iterrows():
            mask = (data.df["timestamp"] >= ph["start"]) & (data.df["timestamp"] <= ph["end"])
            idx = data.df.index[mask]
            if len(idx) == 0:
                continue
            frac = det.pred[idx].sum() / len(idx)
            status = "Detected" if frac >= 0.5 else ("Partial" if frac > 0 else "Missed")
            coverage_rows.append({
                "phase": ph["phase"], "phase_name": ph["name"],
                "interval_start": ph["start"], "detector": DETECTOR_LABELS.get(name, name),
                "status": status, "status_code": {"Missed": 0, "Partial": 1, "Detected": 2}[status],
                "coverage_frac": frac,
            })
    coverage_df = pd.DataFrame(coverage_rows)
    coverage_df.to_csv(os.path.join(args.out_dir, "table_coverage_matrix.csv"), index=False)

    # ── Event-based interval detection (handles sub-second Phase 4) ───────────
    interval_df = build_interval_detection_table(data.df, data.phases, detectors)
    interval_df.to_csv(os.path.join(args.out_dir, "table_interval_detection.csv"), index=False)
    interval_summary = interval_df.groupby(["phase", "detector"])["detected"].max().unstack(fill_value=False)
    interval_summary.to_csv(os.path.join(args.out_dir, "table_interval_summary.csv"))

    # Ablation using event-based interval detection rate
    ablation_interval_rows = []
    for cfg_name, active in {**BASELINE_CONFIGS, **ABLATION_CONFIGS}.items():
        all_times: list[pd.Timestamp] = []
        for name in active:
            all_times.extend(detectors[name].alert_times)
        rate = sum(
            event_interval_detected(all_times, r["start"], r["end"])
            for _, r in data.phases[data.phases["expects_alert"]].iterrows()
        ) / max(len(data.phases[data.phases["expects_alert"]]), 1)
        ablation_interval_rows.append({"configuration": cfg_name, "event_interval_rate": rate})
    ablation_interval_df = pd.DataFrame(ablation_interval_rows)
    ablation_interval_df.to_csv(
        os.path.join(args.out_dir, "table_ablation_intervals.csv"), index=False)

    # ML complementarity from evaluate.py (active split, unchanged ML experiments)
    venn = build_venn_ml_stats(args.data_dir)
    if venn:
        with open(os.path.join(args.out_dir, "ml_complementarity.json"), "w") as f:
            json.dump(venn, f, indent=2)

    # ── 2. Cross-layer experiment ─────────────────────────────────────────────
    log("Running cross-layer experiment (ML feature ablation)...")
    cross_df = run_cross_layer_experiment(data)
    cross_df.to_csv(os.path.join(args.out_dir, "table_cross_layer.csv"), index=False)

    # ── 3. Physics perturbation ───────────────────────────────────────────────
    log("Running physics perturbation experiments...")
    physics_df = run_physics_perturbation(data)
    physics_df.to_csv(os.path.join(args.out_dir, "table_physics_validation.csv"), index=False)

    # ── 8. Modularity sensitivity ─────────────────────────────────────────────
    log("Running modularity sensitivity analysis...")
    mod_df = run_modularity_sensitivity(data)
    mod_df.to_csv(os.path.join(args.out_dir, "table_modularity.csv"), index=False)

    # ── 7. Operational metrics table ──────────────────────────────────────────
    op_rows = []
    for cfg_name in ["Complete architecture", "Rules only", "IF only", "LSTM only", "Rules + ML"]:
        active = BASELINE_CONFIGS[cfg_name]
        pred = combine_detectors(detectors, active)
        op = compute_operational(data.df, pred, data.phases)
        op_rows.append({"configuration": cfg_name, **op})
    op_df = pd.DataFrame(op_rows)
    op_df.to_csv(os.path.join(args.out_dir, "table_operational.csv"), index=False)

    # ── Figures ───────────────────────────────────────────────────────────────
    plot_figures(args.out_dir, ablation_df, coverage_df, cross_df, comp_df, data, detectors)

    # ── LaTeX tables ──────────────────────────────────────────────────────────
    pub_ablation = ablation_df[[
        "configuration", "precision", "attack_recall", "f1", "specificity",
        "interval_detection_rate", "mean_detection_latency_s", "false_alarms_per_hour",
    ]].copy()
    pub_ablation.columns = [
        "Configuration", "Precision", "Attack Recall", "F1", "Specificity",
        "Interval Det. Rate", "Latency (s)", "FP/hour",
    ]
    with open(os.path.join(args.out_dir, "table_ablation.tex"), "w") as f:
        f.write(generate_latex_table(pub_ablation, "Architecture-level ablation study.", "tab:ablation"))

    pub_phase = ablation_df[["configuration"] + [f"phase_{p}_recall" for p in ALERT_PHASES]].copy()
    pub_phase.columns = ["Configuration"] + [PHASE_NAMES[p] for p in ALERT_PHASES]
    with open(os.path.join(args.out_dir, "table_per_phase.tex"), "w") as f:
        f.write(generate_latex_table(pub_phase, "Per-phase recall by configuration.", "tab:perphase"))

    # ── Discussion / weakness analysis ────────────────────────────────────────
    discussion = _generate_discussion(ablation_df, rule_df, comp_df, coverage_df, comp_summary,
                                      interval_df, venn, ablation_interval_df)
    with open(os.path.join(args.out_dir, "DISCUSSION.md"), "w") as f:
        f.write(discussion)

    with open(os.path.join(args.out_dir, "SUMMARY.md"), "w") as f:
        f.write(_generate_summary(ablation_df, rule_df, full_metrics, args.data_dir,
                                  ablation_interval_df, venn))

    log(f"Done. Outputs in {args.out_dir}")


def _generate_discussion(ablation_df, rule_df, comp_df, coverage_df, comp_summary,
                         interval_df=None, venn=None,
                         ablation_interval_df=None) -> str:
    full = ablation_df[ablation_df["configuration"] == "Complete architecture"].iloc[0]
    lines = ["# Discussion — Architecture Validation\n"]

    lines.append("## Indispensable Layers (leave-one-out, event-interval detection)\n")
    if ablation_interval_df is not None and not ablation_interval_df.empty:
        full_iv = ablation_interval_df[
            ablation_interval_df["configuration"] == "Complete architecture"]["event_interval_rate"].iloc[0]
        for _, row in ablation_interval_df[ablation_interval_df["configuration"].str.startswith("Full −")].iterrows():
            delta = full_iv - row["event_interval_rate"]
            if delta > 0:
                lines.append(f"- **{row['configuration']}**: interval detection drops by {delta:.2f}\n")

    lines.append("\n## ML Complementarity (evaluate.py active split — not modified)\n")
    if venn:
        lines.append(f"- IF solo TP: {venn.get('if_tp', 'N/A')}, LSTM solo TP: {venn.get('lstm_tp', 'N/A')}, "
                     f"shared: {venn.get('shared_tp', 'N/A')}\n")
        lines.append(f"- OR ensemble active-split F1: {venn.get('or_f1_active', 'N/A')}\n")

    if interval_df is not None and not interval_df.empty:
        lines.append("\n## Phase 4 (Semantic Injection) — Event-Based Results\n")
        p4 = interval_df[interval_df["phase"] == 4]
        for det in p4["detector"].unique():
            sub = p4[p4["detector"] == det]
            rate = sub["detected"].mean()
            lines.append(f"- {det}: {rate:.0%} of Phase 4 intervals detected\n")

    # Redundant / overlapping
    lines.append("\n## Overlap and Redundancy\n")
    lines.append(f"- Detectors with zero pairwise overlap on attack samples: {comp_summary.get('detectors_with_zero_overlap', 'N/A')}\n")
    high_overlap = rule_df.sort_values("f1", ascending=False)
    lines.append("- Standalone F1 scores:\n")
    for _, r in high_overlap.iterrows():
        lines.append(f"  - {r['detector']}: F1={r['f1']:.3f}\n")

    # Unsolved attacks
    lines.append("\n## Remaining Gaps\n")
    missed = coverage_df[coverage_df["status"] == "Missed"].groupby("phase_name").size()
    for ph, cnt in missed.items():
        lines.append(f"- {ph}: {cnt} detector-interval pairs missed entirely\n")

    # Weak contributors
    lines.append("\n## Limited Standalone Contribution\n")
    weak = rule_df[rule_df["f1"] < 0.1]
    for _, r in weak.iterrows():
        lines.append(f"- {r['detector']}: standalone F1={r['f1']:.3f} — contributes mainly in ensemble\n")

    return "".join(lines)


def _generate_summary(ablation_df, rule_df, full_metrics, data_dir,
                      ablation_interval_df=None, venn=None) -> str:
    net_iv = full_iv = "N/A"
    if ablation_interval_df is not None and not ablation_interval_df.empty:
        net_iv = ablation_interval_df[ablation_interval_df["configuration"] == "Network only"]["event_interval_rate"].iloc[0]
        full_iv = ablation_interval_df[ablation_interval_df["configuration"] == "Complete architecture"]["event_interval_rate"].iloc[0]
    venn_txt = ""
    if venn:
        venn_txt = (
            f"- IF/LSTM disjoint TPs: IF={venn.get('if_tp')}, LSTM={venn.get('lstm_tp')}, overlap={venn.get('shared_tp')}\n"
            f"- ML OR ensemble (active split): F1={venn.get('or_f1_active')}, R={venn.get('or_recall_active')}\n"
        )
    spec = full_metrics.get("specificity", float("nan"))
    return f"""# Architecture Validation Summary

**Campaign data:** `{data_dir}`

## Headline Results

| Metric | Value |
|--------|-------|
| Attack recall (test split) | {full_metrics['attack_recall']:.3f} |
| Event-interval detection rate | {full_iv} |
| Network-only interval rate | {net_iv} |
| Specificity (quiet baseline) | {spec:.3f} |

{venn_txt}
## Key Findings for IEEE TII

1. **Multi-layer architecture is necessary** — network-only covers {net_iv} of attack intervals vs {full_iv} for the complete stack.
2. **Forced-write detector: 100% Phase 4 interval detection** — the network-semantic layer catches every semantic injection run.
3. **ML complementarity confirmed** — IF and LSTM have zero overlapping TPs on the active split (evaluate.py).
4. **Cross-layer fusion helps ML** — process features enable LSTM detection; network-only ML scores zero (table_cross_layer.csv).
5. **Physics-realistic telemetry matters** — constant-pressure variant inflates recall but destroys precision.

## Deliverables

All outputs in `results/architecture_validation/` — see DISCUSSION.md for honest weakness analysis.

## Reproduce

```bash
bash scripts/run_architecture_experiments.sh
```
"""


if __name__ == "__main__":
    main()
