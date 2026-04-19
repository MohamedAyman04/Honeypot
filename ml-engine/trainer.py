"""
ML Engine / Trainer  (v5 – improved FP suppression + LSTM replay detection)
===========================================================================
New in v5:
  • Semantic injection — timestamp-based deduplication: each forced_write event
    is alerted EXACTLY ONCE regardless of how many 15-s cycles it falls inside
    the -60s query window.
  • Replay attack — dedicated LSTM Autoencoder (replay_lstm) trained on
    variance-focused features  [pressure_delta, rolling_std_5, baseline_dev]
    so that frozen/repeating telemetry sequences produce anomalously high
    reconstruction errors.  LSTM signal is OR-gated with existing fingerprint
    and zero-variance checks.
  • Fingerprint gating relaxed (std < 2.0, baseline_dev ≥ 5 %) to catch noisy
    replay variants that the old std < 1.0 gate missed.

Retained from v4:
  • IsolationForest + general LSTM autoencoder ensemble for anomaly scoring
  • EWMA / CUSUM / slope stealth drift detector
  • Expert cross-layer rules
  • Model persistence (load from /data volume; retrain only if missing)
  • Startup grace period (120 s) suppressing all detections
  • TRAINING state (is_anomaly=2) permanently removed from Grafana metrics
"""

import time
import os
import uuid
import threading
import collections
import statistics
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

# ── Configuration ──────────────────────────────────────────────────────────────
INFLUX_URL    = os.environ.get("INFLUX_URL",    "http://ics_historian:8086")
INFLUX_TOKEN  = os.environ.get("INFLUX_TOKEN",  "supersecrettoken")
INFLUX_ORG    = os.environ.get("INFLUX_ORG",    "my_refinery")
INFLUX_BUCKET = os.environ.get("INFLUX_BUCKET", "sensor_logs")

IF_MODEL_FILE        = "/data/model.pkl"
LSTM_MODEL_FILE      = "/data/lstm_model.keras"
SCALER_FILE          = "/data/scaler.pkl"
REPLAY_LSTM_FILE     = "/data/replay_lstm.keras"
REPLAY_SCALER_FILE   = "/data/replay_scaler.pkl"
TRAINING_START_FILE  = "/data/training_start.txt"

WARMUP_PERIOD  = 180   # seconds of training before models are frozen
MIN_SAMPLES    = 50    # minimum rows needed before any model can train
LOOP_INTERVAL  = 15   # main loop cadence (seconds)

# ── Startup grace period ───────────────────────────────────────────────────────
STARTUP_GRACE_SECONDS = 120
_boot_time = time.time()

def in_grace_period() -> bool:
    return (time.time() - _boot_time) < STARTUP_GRACE_SECONDS

# ── IsolationForest hyper-parameters ──────────────────────────────────────────
IF_CONTAMINATION   = 0.01
IF_N_ESTIMATORS    = 200
IF_SCORE_THRESHOLD = -0.20

# ── General LSTM Autoencoder hyper-parameters ──────────────────────────────────
LSTM_SEQ_LEN        = 20
LSTM_LATENT_DIM     = 32
LSTM_EPOCHS         = 20
LSTM_BATCH_SIZE     = 32
LSTM_THRESHOLD_PCTL = 95    # p95 of train reconstruction errors → threshold

# ── Replay LSTM hyper-parameters ──────────────────────────────────────────────
REPLAY_LSTM_SEQ_LEN        = 15   # shorter window — replay patterns emerge quickly
REPLAY_LSTM_LATENT_DIM     = 16   # lightweight encoder
REPLAY_LSTM_EPOCHS         = 15
REPLAY_LSTM_BATCH_SIZE     = 32
REPLAY_LSTM_THRESHOLD_PCTL = 90   # lower p-tile → more sensitive to frozen patterns

# ── Expert-rule thresholds ─────────────────────────────────────────────────────
EXPERT_PRESSURE_DELTA_THRESHOLD = 20.0
EXPERT_PRESSURE_MEAN_DEV        = 35.0

# ── EWMA/CUSUM parameters ─────────────────────────────────────────────────────
EWMA_LAMBDA     = 0.1
CUSUM_THRESHOLD = 8.0
_cusum_k        = 1.0

_ewma_state  = None
_cusum_pos   = 0.0
_cusum_neg   = 0.0

# ── Slope-based drift parameters ──────────────────────────────────────────────
MIN_SLOPE             = 0.05
SLOPE_THRESHOLD       = 0.3
SLOPE_DIRECTION_RATIO = 0.75
SLOPE_WINDOW_SIZE     = 20
CUMULATIVE_DEV_THRESH = 100.0
DRIFT_RANGE_THRESHOLD = 30.0

_pressure_history = collections.deque(maxlen=SLOPE_WINDOW_SIZE)
_slope_history    = collections.deque(maxlen=10)
_cumulative_dev   = 0.0

# ── Rolling baseline ──────────────────────────────────────────────────────────
BASELINE_WINDOW   = 60
_baseline_samples = collections.deque(maxlen=BASELINE_WINDOW)

# ── Replay attack fingerprint matching ────────────────────────────────────────
REPLAY_WINDOW_SIZE        = 10
REPLAY_MATCH_RATIO        = 0.85
REPLAY_BASELINE_DEV       = 12.0
ZERO_VAR_BASELINE_DEV_PCT = 8.0
_replay_window_fps        = collections.deque(maxlen=20)
_frozen_fps               = collections.deque(maxlen=20)

# ── Semantic injection deduplication ──────────────────────────────────────────
# Maps  event_timestamp_key → unix_time_when_we_alerted
# Prevents the same forced_write row from firing again on each 15-s loop tick.
_seen_injection_ts: dict[str, float] = {}
_INJECTION_DEDUP_TTL = 120.0   # seconds to remember a seen event

# ── Post-attack state ─────────────────────────────────────────────────────────
_semantic_injection_seen = False
_drift_attack_seen       = False

# ── Session ID ────────────────────────────────────────────────────────────────
SESSION_ID = os.environ.get("SESSION_ID", str(uuid.uuid4())[:8])

# ── In-memory model references ─────────────────────────────────────────────────
_if_model           = None    # IsolationForest (general anomaly)
_lstm_model         = None    # LSTM autoencoder (general anomaly)
_lstm_scaler        = None
_lstm_threshold     = None
_replay_lstm_model  = None    # LSTM autoencoder (replay-specific)
_replay_lstm_scaler = None
_replay_lstm_thresh = None


# ═══════════════════════════════════════════════════════════════════════════════
# Shared LSTM building blocks
# ═══════════════════════════════════════════════════════════════════════════════

def _build_lstm_autoencoder(n_features: int, seq_len: int, latent_dim: int):
    from tensorflow.keras.models import Model
    from tensorflow.keras.layers import Input, LSTM, RepeatVector, TimeDistributed, Dense
    from tensorflow.keras.optimizers import Adam

    inp     = Input(shape=(seq_len, n_features))
    encoded = LSTM(latent_dim, activation="tanh", return_sequences=False)(inp)
    repeated = RepeatVector(seq_len)(encoded)
    decoded  = LSTM(latent_dim, activation="tanh", return_sequences=True)(repeated)
    out      = TimeDistributed(Dense(n_features))(decoded)

    model = Model(inputs=inp, outputs=out)
    model.compile(optimizer=Adam(learning_rate=1e-3), loss="mse")
    return model


def _make_sequences(scaled: np.ndarray, seq_len: int) -> np.ndarray:
    seqs = []
    for i in range(len(scaled) - seq_len + 1):
        seqs.append(scaled[i : i + seq_len])
    return np.array(seqs, dtype=np.float32)


def _reconstruction_errors(model, sequences: np.ndarray) -> np.ndarray:
    preds = model.predict(sequences, verbose=0)
    return np.mean((sequences - preds) ** 2, axis=(1, 2))


# ═══════════════════════════════════════════════════════════════════════════════
# General LSTM Autoencoder  (10-feature pipeline anomaly detection)
# ═══════════════════════════════════════════════════════════════════════════════

def _train_lstm(features: pd.DataFrame):
    """Train general LSTM autoencoder on all 10 pipeline features."""
    import tensorflow as tf
    tf.get_logger().setLevel("ERROR")

    scaler = MinMaxScaler()
    scaled = scaler.fit_transform(features.values).astype(np.float32)

    if len(scaled) < LSTM_SEQ_LEN + 1:
        print(f"[LSTM] Not enough rows ({len(scaled)} < {LSTM_SEQ_LEN+1}) — skipping.")
        return None, None, None

    sequences  = _make_sequences(scaled, LSTM_SEQ_LEN)
    n_features = scaled.shape[1]

    model = _build_lstm_autoencoder(n_features, LSTM_SEQ_LEN, LSTM_LATENT_DIM)
    model.fit(sequences, sequences,
              epochs=LSTM_EPOCHS, batch_size=LSTM_BATCH_SIZE,
              shuffle=True, verbose=0)

    train_errors = _reconstruction_errors(model, sequences)
    threshold    = float(np.percentile(train_errors, LSTM_THRESHOLD_PCTL))
    print(f"[LSTM] Trained — threshold={threshold:.6f}  (p{LSTM_THRESHOLD_PCTL})")

    try:
        model.save(LSTM_MODEL_FILE)
        joblib.dump(scaler,    SCALER_FILE)
        joblib.dump(threshold, SCALER_FILE + ".threshold")
        print(f"[LSTM] Saved → {LSTM_MODEL_FILE}")
    except Exception as e:
        print(f"[LSTM] Save failed: {e}")

    return model, scaler, threshold


def _try_load_lstm() -> bool:
    global _lstm_model, _lstm_scaler, _lstm_threshold
    if not (os.path.exists(LSTM_MODEL_FILE) and os.path.exists(SCALER_FILE)):
        print("[LSTM] No saved model — will train from scratch.")
        return False
    try:
        import tensorflow as tf
        tf.get_logger().setLevel("ERROR")
        _lstm_model     = tf.keras.models.load_model(LSTM_MODEL_FILE)
        _lstm_scaler    = joblib.load(SCALER_FILE)
        _lstm_threshold = joblib.load(SCALER_FILE + ".threshold")
        print(f"[LSTM] Loaded from disk (threshold={_lstm_threshold:.6f})")
        return True
    except Exception as e:
        print(f"[LSTM] Load failed ({e}) — will retrain.")
        return False


def _score_lstm(features: pd.DataFrame) -> tuple[bool, float]:
    """Score the most recent 20-sample window with the general LSTM autoencoder."""
    if _lstm_model is None or _lstm_scaler is None or _lstm_threshold is None:
        return False, 0.0
    if len(features) < LSTM_SEQ_LEN:
        return False, 0.0

    tail   = features.tail(LSTM_SEQ_LEN).values.astype(np.float32)
    scaled = _lstm_scaler.transform(tail)
    seq    = scaled[np.newaxis, :, :]

    error = float(_reconstruction_errors(_lstm_model, seq)[0])
    return error > _lstm_threshold, error


# ═══════════════════════════════════════════════════════════════════════════════
# Replay-specific LSTM Autoencoder
# ═══════════════════════════════════════════════════════════════════════════════
# Features: [pressure_delta, rolling_std_5, baseline_dev_norm]
# During replay these three collapse to [≈0, ≈0, constant≠0] —
# a pattern the LSTM trained on normal data cannot reconstruct cheaply.

def _build_replay_features(pressure_values: list) -> np.ndarray | None:
    """
    Compute 3-feature matrix for the replay LSTM from a raw pressure list.
    Returns ndarray shape (N, 3) or None if insufficient data.
    """
    if len(pressure_values) < REPLAY_LSTM_SEQ_LEN + 5:
        return None

    arr   = np.array(pressure_values, dtype=np.float32)
    delta = np.diff(arr, prepend=arr[0])

    # 5-sample rolling std (low during replay)
    rolling_std = (pd.Series(arr)
                   .rolling(5, min_periods=1)
                   .std()
                   .fillna(0.0)
                   .values
                   .astype(np.float32))

    # Baseline deviation normalised (non-zero during replay)
    baseline = float(np.mean(arr[:max(len(arr) // 2, 1)]))
    if abs(baseline) < 1.0:
        baseline = 1.0
    baseline_dev = np.abs(arr - baseline) / abs(baseline)

    return np.column_stack([delta, rolling_std, baseline_dev]).astype(np.float32)


def _train_replay_lstm(pressure_values: list):
    """Train the replay-specific LSTM autoencoder on normal pressure history."""
    import tensorflow as tf
    tf.get_logger().setLevel("ERROR")

    features = _build_replay_features(pressure_values)
    if features is None:
        print("[rLSTM] Not enough pressure samples — skipping replay LSTM training.")
        return None, None, None

    scaler = MinMaxScaler()
    scaled = scaler.fit_transform(features).astype(np.float32)

    sequences = _make_sequences(scaled, REPLAY_LSTM_SEQ_LEN)
    if len(sequences) < 5:
        print(f"[rLSTM] Too few sequences ({len(sequences)}) — skipping.")
        return None, None, None

    n_features = scaled.shape[1]
    model = _build_lstm_autoencoder(n_features, REPLAY_LSTM_SEQ_LEN, REPLAY_LSTM_LATENT_DIM)
    model.fit(sequences, sequences,
              epochs=REPLAY_LSTM_EPOCHS, batch_size=REPLAY_LSTM_BATCH_SIZE,
              shuffle=True, verbose=0)

    train_errors = _reconstruction_errors(model, sequences)
    threshold    = float(np.percentile(train_errors, REPLAY_LSTM_THRESHOLD_PCTL))
    print(f"[rLSTM] Trained — threshold={threshold:.6f}  (p{REPLAY_LSTM_THRESHOLD_PCTL})")

    try:
        model.save(REPLAY_LSTM_FILE)
        joblib.dump(scaler,    REPLAY_SCALER_FILE)
        joblib.dump(threshold, REPLAY_SCALER_FILE + ".threshold")
        print(f"[rLSTM] Saved → {REPLAY_LSTM_FILE}")
    except Exception as e:
        print(f"[rLSTM] Save failed: {e}")

    return model, scaler, threshold


def _try_load_replay_lstm() -> bool:
    global _replay_lstm_model, _replay_lstm_scaler, _replay_lstm_thresh
    if not (os.path.exists(REPLAY_LSTM_FILE) and os.path.exists(REPLAY_SCALER_FILE)):
        print("[rLSTM] No saved model — will train from scratch.")
        return False
    try:
        import tensorflow as tf
        tf.get_logger().setLevel("ERROR")
        _replay_lstm_model  = tf.keras.models.load_model(REPLAY_LSTM_FILE)
        _replay_lstm_scaler = joblib.load(REPLAY_SCALER_FILE)
        _replay_lstm_thresh = joblib.load(REPLAY_SCALER_FILE + ".threshold")
        print(f"[rLSTM] Loaded from disk (threshold={_replay_lstm_thresh:.6f})")
        return True
    except Exception as e:
        print(f"[rLSTM] Load failed ({e}) — will retrain.")
        return False


def _score_replay_lstm(pressure_values: list) -> tuple[bool, float]:
    """
    Score the most recent pressure window with the replay-specific LSTM.
    Returns (is_replay_anomaly, reconstruction_error).
    Low variance + non-zero baseline deviation → high reconstruction error → True.
    """
    if _replay_lstm_model is None or _replay_lstm_scaler is None or _replay_lstm_thresh is None:
        return False, 0.0

    features = _build_replay_features(pressure_values)
    if features is None:
        return False, 0.0

    # Use the most recent REPLAY_LSTM_SEQ_LEN rows
    tail   = features[-REPLAY_LSTM_SEQ_LEN:]
    if len(tail) < REPLAY_LSTM_SEQ_LEN:
        return False, 0.0

    try:
        scaled = _replay_lstm_scaler.transform(tail)
        seq    = scaled[np.newaxis, :, :]
        error  = float(_reconstruction_errors(_replay_lstm_model, seq)[0])
        return error > _replay_lstm_thresh, error
    except Exception as e:
        print(f"[rLSTM] Scoring error: {e}")
        return False, 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# IsolationForest persistence
# ═══════════════════════════════════════════════════════════════════════════════

def _try_load_if_model() -> bool:
    global _if_model
    if not os.path.exists(IF_MODEL_FILE):
        print("[IF] No saved model — will train from scratch.")
        return False
    try:
        _if_model = joblib.load(IF_MODEL_FILE)
        print(f"[IF] Model loaded from disk: {IF_MODEL_FILE}")
        return True
    except Exception as e:
        print(f"[IF] Model corrupted ({e}) — removing and retraining.")
        for f in [IF_MODEL_FILE, TRAINING_START_FILE]:
            try:
                if os.path.exists(f):
                    os.remove(f)
            except Exception:
                pass
        return False


_if_loaded_from_disk      = _try_load_if_model()
_lstm_loaded_from_disk    = _try_load_lstm()
_replay_lstm_from_disk    = _try_load_replay_lstm()

print(f"--- ML ENGINE v5 STARTING [session={SESSION_ID}] ---")
print(f"    Grace period   : {STARTUP_GRACE_SECONDS}s")
print(f"    IF on disk     : {_if_loaded_from_disk}")
print(f"    LSTM on disk   : {_lstm_loaded_from_disk}")
print(f"    Replay LSTM    : {_replay_lstm_from_disk}")

db_client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
write_api  = db_client.write_api(write_options=SYNCHRONOUS)
query_api  = db_client.query_api()

_api_state = {
    "model_ready":       _if_loaded_from_disk,
    "lstm_ready":        _lstm_loaded_from_disk,
    "replay_lstm_ready": _replay_lstm_from_disk,
    "in_warmup":         not _if_loaded_from_disk,
    "in_grace":          True,
    "sample_count":      0,
    "last_if_score":     None,
    "last_lstm_error":   None,
    "last_replay_error": None,
    "last_anomaly":      None,
    "ewma":              None,
    "cusum_pos":         0.0,
    "cusum_neg":         0.0,
    "recent_alerts":     [],
}
_api_lock = threading.Lock()


# ═══════════════════════════════════════════════════════════════════════════════
# Grafana event writer
# ═══════════════════════════════════════════════════════════════════════════════

def _write_grafana_event(metric_type: str, value: float, event_type: str,
                          severity: str, source: str, detail: str = "") -> None:
    try:
        p = (Point("grafana_events")
             .tag("metric_type", metric_type)
             .tag("event_type",  event_type)
             .tag("severity",    severity)
             .tag("source",      source)
             .tag("session_id",  SESSION_ID)
             .field("value",     float(value))
             .field("detail",    str(detail)[:256])
             .time(time.time_ns(), WritePrecision.NS))
        write_api.write(bucket=INFLUX_BUCKET, record=p)
    except Exception as e:
        print(f"[ML] grafana_events write error: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Feature extraction
# ═══════════════════════════════════════════════════════════════════════════════

def fetch_pipeline_features(lookback: str = "-1h") -> pd.DataFrame:
    """Pull pipeline telemetry and compute ML features. DNP3 intentionally excluded."""
    query = f'''
from(bucket: "{INFLUX_BUCKET}")
  |> range(start: {lookback})
  |> filter(fn: (r) => r["_measurement"] == "pipeline_metrics")
  |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
  |> sort(columns: ["_time"])
'''
    try:
        result = query_api.query_data_frame(query)
        if isinstance(result, list):
            result = pd.concat(result) if result else pd.DataFrame()
        if result.empty:
            return pd.DataFrame()
    except Exception as e:
        print(f"InfluxDB fetch error: {e}")
        return pd.DataFrame()

    for col in ["pressure", "flow_rate", "temperature", "pump_rpm"]:
        if col not in result.columns:
            result[col] = 0.0

    result["_time"] = pd.to_datetime(result["_time"]).dt.tz_localize(None)
    result = result.sort_values("_time").reset_index(drop=True)

    result["inter_arrival_time"]    = result["_time"].diff().dt.total_seconds().fillna(0)
    result["pressure_delta"]        = result["pressure"].diff().fillna(0)
    result["pressure_rolling_mean"] = result["pressure"].rolling(10, min_periods=1).mean()
    result["pressure_mean_dev"]     = result["pressure"] - result["pressure_rolling_mean"]

    result["write_freq_10s"] = 0.0
    result["is_write"]       = 0
    result["func_code"]      = 0
    result["length"]         = 0

    try:
        net_query = f'''
from(bucket: "{INFLUX_BUCKET}")
  |> range(start: {lookback})
  |> filter(fn: (r) => r["_measurement"] == "correlation_logs")
  |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
  |> sort(columns: ["_time"])
'''
        net = query_api.query_data_frame(net_query)
        if isinstance(net, list):
            net = pd.concat(net) if net else pd.DataFrame()
        if not net.empty:
            net["_time"] = pd.to_datetime(net["_time"]).dt.tz_localize(None)
            net = net.sort_values("_time").reset_index(drop=True)
            net["is_write"]  = 1
            net["func_code"] = 6
            net["length"]    = net.get("value", pd.Series([0] * len(net))).astype(int)
            net_idx = net.set_index("_time")
            net_idx["write_freq_10s"] = net_idx["is_write"].rolling("10s").sum().fillna(0)
            net["write_freq_10s"] = net_idx["write_freq_10s"].values
            result = pd.merge_asof(
                result,
                net[["_time", "is_write", "func_code", "length", "write_freq_10s"]],
                on="_time", direction="backward"
            )
            for col in ["is_write", "func_code", "length", "write_freq_10s"]:
                new_col = col + "_y"
                if new_col in result.columns:
                    result[col] = result[new_col].fillna(
                        result[col + "_x"] if col + "_x" in result.columns else 0
                    )
                    result.drop(
                        columns=[c for c in [col + "_x", col + "_y"] if c in result.columns],
                        inplace=True
                    )
    except Exception as e:
        print(f"Network feature join error (non-fatal): {e}")

    feature_cols = [
        "pressure", "flow_rate", "temperature",
        "pressure_delta", "pressure_mean_dev",
        "inter_arrival_time", "write_freq_10s",
        "is_write", "func_code", "length"
    ]
    return result[feature_cols].fillna(0.0)


# ═══════════════════════════════════════════════════════════════════════════════
# EWMA / CUSUM + slope drift detector
# ═══════════════════════════════════════════════════════════════════════════════

def _compute_slope(values: collections.deque) -> float:
    arr = np.array(list(values), dtype=float)
    if len(arr) < 4:
        return 0.0
    x = np.arange(len(arr), dtype=float)
    return float(np.polyfit(x, arr, 1)[0])


def run_ewma_cusum(current_pressure: float) -> tuple[bool, str]:
    global _ewma_state, _cusum_pos, _cusum_neg, _cumulative_dev

    if not in_grace_period():
        _pressure_history.append(current_pressure)
        if (time.time() - _boot_time) >= (STARTUP_GRACE_SECONDS + 30):
            _baseline_samples.append(current_pressure)

    if _ewma_state is None:
        if len(_baseline_samples) >= 10:
            _ewma_state = float(np.mean(list(_baseline_samples)))
        else:
            _ewma_state = current_pressure
        return False, "EWMA initialised"

    _ewma_state = EWMA_LAMBDA * current_pressure + (1 - EWMA_LAMBDA) * _ewma_state
    deviation   = current_pressure - _ewma_state

    _cusum_pos = max(0.0, _cusum_pos + deviation - _cusum_k)
    _cusum_neg = max(0.0, _cusum_neg - deviation - _cusum_k)
    _cumulative_dev += abs(deviation)

    slope_val      = 0.0
    slope_detected = False

    if len(_pressure_history) >= 8:
        slope_val = _compute_slope(_pressure_history)
        _slope_history.append(slope_val)

        if len(_slope_history) >= 5:
            positive_count  = sum(1 for s in _slope_history if s > 0)
            direction_ratio = positive_count / len(_slope_history)
            is_increasing   = direction_ratio >= SLOPE_DIRECTION_RATIO and slope_val > SLOPE_THRESHOLD
            is_decreasing   = direction_ratio <= (1.0 - SLOPE_DIRECTION_RATIO) and slope_val < -SLOPE_THRESHOLD
            slope_detected  = (is_increasing or is_decreasing) and (abs(slope_val) > MIN_SLOPE)

    cusum_detected = (_cusum_pos > CUSUM_THRESHOLD or _cusum_neg > CUSUM_THRESHOLD)

    range_detected = False
    if len(_pressure_history) >= 8:
        arr = list(_pressure_history)
        range_detected = (max(arr) - min(arr)) > DRIFT_RANGE_THRESHOLD

    drift_detected = slope_detected or cusum_detected or range_detected

    detail = (
        f"EWMA={_ewma_state:.2f} PSI  deviation={deviation:.2f}  "
        f"CUSUM+={_cusum_pos:.2f}  CUSUM-={_cusum_neg:.2f}  "
        f"slope={slope_val:.4f} PSI/sample  cumdev={_cumulative_dev:.1f}  "
        f"slope_flag={slope_detected}  cusum_flag={cusum_detected}"
    )

    with _api_lock:
        _api_state["ewma"]      = round(_ewma_state, 2)
        _api_state["cusum_pos"] = round(_cusum_pos,  2)
        _api_state["cusum_neg"] = round(_cusum_neg,  2)

    if drift_detected:
        _cusum_pos      = 0.0
        _cusum_neg      = 0.0
        _cumulative_dev = 0.0

    return drift_detected, detail


# ═══════════════════════════════════════════════════════════════════════════════
# Expert rules
# ═══════════════════════════════════════════════════════════════════════════════

def apply_expert_rules(features: pd.DataFrame) -> list[dict]:
    alerts = []
    if features.empty:
        return alerts
    row = features.iloc[-1]

    if abs(row["pressure_delta"]) > EXPERT_PRESSURE_DELTA_THRESHOLD and row["write_freq_10s"] == 0:
        alerts.append({"type": "CROSS_LAYER_ANOMALY",
                        "detail": f"pressure_delta={row['pressure_delta']:.2f} PSI with no write commands"})

    if abs(row["pressure_mean_dev"]) > EXPERT_PRESSURE_MEAN_DEV:
        alerts.append({"type": "STEALTH_DRIFT",
                        "detail": f"pressure_mean_dev={row['pressure_mean_dev']:.2f} PSI"})

    if row["pressure"] > 300.0:
        alerts.append({"type": "OVER_PRESSURE",
                        "detail": f"pressure={row['pressure']:.1f} PSI (beyond physical engine maximum)"})

    return alerts


def _record_alert(alert_type: str, detail: str, score: float) -> None:
    entry = {
        "timestamp":  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "alert_type": alert_type,
        "detail":     detail,
        "score":      round(score, 4),
        "session_id": SESSION_ID,
    }
    with _api_lock:
        _api_state["recent_alerts"].append(entry)
        if len(_api_state["recent_alerts"]) > 1000:
            _api_state["recent_alerts"] = _api_state["recent_alerts"][-1000:]
        _api_state["last_anomaly"] = entry


# ═══════════════════════════════════════════════════════════════════════════════
# Main ML cycle  (IsolationForest + LSTM ensemble)
# ═══════════════════════════════════════════════════════════════════════════════

def run_ml_cycle() -> None:
    features = fetch_pipeline_features(lookback="-2h")

    with _api_lock:
        _api_state["sample_count"] = len(features)
        _api_state["in_grace"]     = in_grace_period()

    if len(features) < MIN_SAMPLES:
        print(f"Collecting samples... ({len(features)}/{MIN_SAMPLES})")
        return

    global _if_model, _lstm_model, _lstm_scaler, _lstm_threshold
    global _replay_lstm_model, _replay_lstm_scaler, _replay_lstm_thresh

    # ── Training / warm-up phase ──────────────────────────────────────────────
    if _if_model is not None:
        with _api_lock:
            _api_state["model_ready"] = True
            _api_state["in_warmup"]   = False
    else:
        if not os.path.exists(TRAINING_START_FILE):
            with open(TRAINING_START_FILE, "w") as f:
                f.write(str(time.time()))
            print("[ML] Warm-up phase started.")

        with open(TRAINING_START_FILE) as f:
            start_time = float(f.read().strip())

        in_warmup = (time.time() - start_time) < WARMUP_PERIOD

        with _api_lock:
            _api_state["in_warmup"] = in_warmup

        if in_warmup:
            # ── Train IsolationForest ──────────────────────────────────────────
            if_model = IsolationForest(contamination=IF_CONTAMINATION,
                                       random_state=42, n_estimators=IF_N_ESTIMATORS)
            if_model.fit(features)
            _if_model = if_model
            try:
                os.makedirs(os.path.dirname(IF_MODEL_FILE), exist_ok=True)
                joblib.dump(if_model, IF_MODEL_FILE)
                print(f"[IF]   Trained and saved → {IF_MODEL_FILE}")
            except Exception as e:
                print(f"[IF]   Failed to save: {e}")

            # ── Train general LSTM ─────────────────────────────────────────────
            try:
                m, s, t = _train_lstm(features)
                if m is not None:
                    _lstm_model, _lstm_scaler, _lstm_threshold = m, s, t
                    with _api_lock:
                        _api_state["lstm_ready"] = True
            except Exception as e:
                print(f"[LSTM] Training error: {e}")

            # ── Train replay LSTM (uses pressure column from features) ──────────
            if _replay_lstm_model is None:
                try:
                    pressure_vals = features["pressure"].tolist()
                    rm, rs, rt = _train_replay_lstm(pressure_vals)
                    if rm is not None:
                        _replay_lstm_model  = rm
                        _replay_lstm_scaler = rs
                        _replay_lstm_thresh = rt
                        with _api_lock:
                            _api_state["replay_lstm_ready"] = True
                except Exception as e:
                    print(f"[rLSTM] Training error: {e}")

            remaining = WARMUP_PERIOD - (time.time() - start_time)
            print(f"[ML] Training mode: {remaining:.0f}s remaining — NO alerts.")
            return   # No alerts during warm-up

        # Warm-up finished
        if _if_model is None and os.path.exists(IF_MODEL_FILE):
            try:
                _if_model = joblib.load(IF_MODEL_FILE)
                print("[IF] Loaded post-warmup.")
            except Exception as e:
                print(f"[IF] Post-warmup load failed: {e}")
                return

        if _lstm_model is None:
            _try_load_lstm()
        if _replay_lstm_model is None:
            _try_load_replay_lstm()

        with _api_lock:
            _api_state["model_ready"] = True

    # ── Detection phase ───────────────────────────────────────────────────────
    if in_grace_period():
        remaining_grace = STARTUP_GRACE_SECONDS - (time.time() - _boot_time)
        print(f"[GRACE] {remaining_grace:.0f}s remaining — suppressing alerts.")
        return

    if _if_model is None:
        print("[ML] No IF model available — skipping detection.")
        return

    # ── IsolationForest scoring ───────────────────────────────────────────────
    recent      = features.tail(1)
    predictions = _if_model.predict(recent)
    scores      = _if_model.decision_function(recent)
    score_val   = float(scores[0])
    is_if_anom  = (predictions[0] == -1 and score_val < IF_SCORE_THRESHOLD)

    with _api_lock:
        _api_state["last_if_score"] = round(score_val, 4)

    # ── General LSTM scoring ──────────────────────────────────────────────────
    is_lstm_anom, lstm_error = _score_lstm(features)

    with _api_lock:
        _api_state["last_lstm_error"] = round(lstm_error, 6)

    # ── Ensemble decision (OR-gate) ───────────────────────────────────────────
    expert_alerts   = apply_expert_rules(features)
    is_anomaly      = int(is_if_anom or is_lstm_anom or bool(expert_alerts))
    effective_score = score_val
    if is_lstm_anom and lstm_error > 0:
        effective_score = min(score_val, -lstm_error)

    for alert in expert_alerts:
        print(f"!!! {alert['type']} !!! {alert['detail']}")
        effective_score = min(effective_score, -0.5)
        _record_alert(alert["type"], alert["detail"], effective_score)
        write_api.write(bucket=INFLUX_BUCKET, record=(
            Point("security_alerts")
            .tag("alert_type", alert["type"])
            .tag("session_id", SESSION_ID)
            .field("detail", alert["detail"])
            .field("score",  effective_score)
            .time(time.time_ns(), WritePrecision.NS)
        ))
        _write_grafana_event(
            metric_type="anomaly", value=effective_score,
            event_type=alert["type"], severity="high",
            source="ml-engine", detail=alert["detail"]
        )

    if is_if_anom and not expert_alerts:
        print(f"!!! IF ANOMALY DETECTED !!! score={score_val:.4f}")
        _record_alert("ISOLATION_FOREST", f"if_score={score_val:.4f}", score_val)
        _write_grafana_event(
            metric_type="anomaly", value=score_val,
            event_type="ISOLATION_FOREST", severity="medium",
            source="ml-engine", detail=f"if_score={score_val:.4f}"
        )

    if is_lstm_anom and not expert_alerts:
        detail = f"reconstruction_error={lstm_error:.6f}  threshold={_lstm_threshold:.6f}"
        print(f"!!! LSTM ANOMALY DETECTED !!! {detail}")
        _record_alert("LSTM_AUTOENCODER", detail, -lstm_error)
        write_api.write(bucket=INFLUX_BUCKET, record=(
            Point("security_alerts")
            .tag("alert_type", "LSTM_AUTOENCODER")
            .tag("session_id", SESSION_ID)
            .field("detail", detail)
            .field("score",  -lstm_error)
            .time(time.time_ns(), WritePrecision.NS)
        ))
        _write_grafana_event(
            metric_type="anomaly", value=-lstm_error,
            event_type="LSTM_AUTOENCODER", severity="medium",
            source="ml-engine", detail=detail
        )

    write_api.write(bucket=INFLUX_BUCKET, record=(
        Point("security_metrics")
        .tag("sensor",     "ml_engine")
        .tag("session_id", SESSION_ID)
        .field("anomaly_score", effective_score)
        .field("is_anomaly",    is_anomaly)
        .field("if_score",      score_val)
        .field("lstm_error",    lstm_error)
        .time(time.time_ns(), WritePrecision.NS)
    ))

    print(
        f"[ML] Cycle — IF_score={score_val:.4f}  IF_anom={int(is_if_anom)}  "
        f"LSTM_err={lstm_error:.6f}  LSTM_anom={int(is_lstm_anom)}  "
        f"ensemble={is_anomaly}"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Utility queries
# ═══════════════════════════════════════════════════════════════════════════════

def has_recent_writes() -> bool:
    query = f'''
from(bucket: "{INFLUX_BUCKET}")
  |> range(start: -60s)
  |> filter(fn: (r) => r["_measurement"] == "modbus_events"
                   and r["fc_type"] == "write"
                   and r["_field"] == "register")
  |> filter(fn: (r) => r["_value"] >= 200.0)
  |> count()
'''
    try:
        tables = query_api.query(query)
        for table in tables:
            for record in table.records:
                if record.get_value() > 0:
                    return True
    except Exception:
        pass
    return False


def _sensor_writes_detected() -> bool:
    query = f'''
from(bucket: "{INFLUX_BUCKET}")
  |> range(start: -60s)
  |> filter(fn: (r) => r["_measurement"] == "modbus_events"
                   and r["fc_type"] == "write"
                   and r["_field"] == "register")
  |> filter(fn: (r) => r["_value"] < 200.0 and r["_value"] >= 100.0)
  |> count()
'''
    try:
        tables = query_api.query(query)
        for table in tables:
            for record in table.records:
                if record.get_value() > 0:
                    return True
    except Exception:
        pass
    return False


def _was_injection_seen_recently() -> bool:
    for q in [
        f'from(bucket: "{INFLUX_BUCKET}") |> range(start: -10m) |> filter(fn: (r) => r["_measurement"] == "forced_writes") |> count()',
        f'from(bucket: "{INFLUX_BUCKET}") |> range(start: -10m) |> filter(fn: (r) => r["_measurement"] == "security_alerts" and r["alert_type"] == "SEMANTIC_INJECTION") |> count()',
    ]:
        try:
            for table in query_api.query(q):
                for record in table.records:
                    if record.get_value() > 0:
                        return True
        except Exception:
            pass
    return False


# ═══════════════════════════════════════════════════════════════════════════════
# EWMA / CUSUM drift cycle
# ═══════════════════════════════════════════════════════════════════════════════

def run_drift_cycle() -> None:
    global _ewma_state, _cusum_pos, _cusum_neg, _cumulative_dev, _drift_attack_seen
    if in_grace_period():
        return

    if has_recent_writes():
        _ewma_state     = None
        _cusum_pos      = 0.0
        _cusum_neg      = 0.0
        _cumulative_dev = 0.0
        _pressure_history.clear()
        _slope_history.clear()
        return

    query = f'''
from(bucket: "{INFLUX_BUCKET}")
  |> range(start: -30s)
  |> filter(fn: (r) => r["_measurement"] == "pipeline_metrics" and r["_field"] == "pressure")
  |> sort(columns: ["_time"])
'''
    try:
        tables = query_api.query(query)
        for table in tables:
            for record in table.records:
                pressure       = float(record.get_value())
                drift, detail  = run_ewma_cusum(pressure)
                if drift:
                    is_critical = _sensor_writes_detected()
                    if is_critical:
                        _drift_attack_seen = True
                    sev       = "critical" if is_critical else "high"
                    score_val = -1.0 if is_critical else -0.8
                    print(f"!!! STEALTH DRIFT DETECTED !!! {detail}")
                    _record_alert("STEALTH_DRIFT_EWMA", detail, score_val)
                    for record_obj in [
                        Point("security_alerts")
                        .tag("alert_type", "STEALTH_DRIFT_EWMA")
                        .tag("session_id", SESSION_ID)
                        .field("detail", detail)
                        .field("score",  score_val)
                        .time(time.time_ns(), WritePrecision.NS),

                        Point("security_metrics")
                        .tag("sensor",     "ml_engine")
                        .tag("session_id", SESSION_ID)
                        .field("anomaly_score", score_val)
                        .field("is_anomaly",    1)
                        .time(time.time_ns(), WritePrecision.NS),
                    ]:
                        write_api.write(bucket=INFLUX_BUCKET, record=record_obj)
                    _write_grafana_event(
                        metric_type="pressure", value=pressure,
                        event_type="STEALTH_DRIFT", severity=sev,
                        source="ml-engine", detail=detail
                    )
    except Exception as e:
        print(f"Drift cycle error: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Replay attack detector  (fingerprint + LSTM variance model)
# ═══════════════════════════════════════════════════════════════════════════════

REPLAY_COOLDOWN        = 120.0
_replay_cooldown_until = 0.0

# Tighten fingerprint resolution: round to 0.25 PSI instead of 0.5
def _fingerprint_window(values: list) -> tuple:
    return tuple(round(v * 4) / 4 for v in values)


def check_replay_attack() -> list[dict]:
    global _replay_cooldown_until
    if in_grace_period():
        return []
    current_time = time.time()
    if current_time < _replay_cooldown_until:
        return []

    query = f'''
from(bucket: "{INFLUX_BUCKET}")
  |> range(start: -60s)
  |> filter(fn: (r) => r["_measurement"] == "pipeline_metrics"
                   and r["_field"] == "pressure")
  |> sort(columns: ["_time"])
'''
    alerts = []
    try:
        tables = query_api.query(query)
        values = []
        for table in tables:
            for record in table.records:
                v = record.get_value()
                if v is not None:
                    values.append(float(v))

        if len(values) < REPLAY_WINDOW_SIZE:
            return []

        # ── Baseline guard: require a mature baseline before firing ────────────
        baseline = float(np.mean(list(_baseline_samples))) if len(_baseline_samples) > 20 else None
        if baseline is None:
            # Not enough history — store fingerprint and bail out silently
            current_fp = _fingerprint_window(values[-REPLAY_WINDOW_SIZE:])
            _replay_window_fps.append(current_fp)
            return []

        mean_v           = statistics.mean(values)
        std              = statistics.stdev(values) if len(values) > 1 else 0.0
        baseline_dev_pct = abs(mean_v - baseline) / baseline * 100.0 if baseline > 1.0 else 0.0

        current_fp     = _fingerprint_window(values[-REPLAY_WINDOW_SIZE:])
        is_post_attack = _was_injection_seen_recently() or _drift_attack_seen

        # ── Signal 1: zero-variance + strong baseline deviation ────────────────
        # Require BOTH low variance AND a meaningful deviation from known-good baseline.
        # This is what catches your 120 PSI spam: std≈0, baseline_dev high.
        # Normal stable pressure will have low baseline_dev and won't fire.
        zero_var_detected = (
            std < 0.15
            and baseline_dev_pct > 5.0   # raised back up — 2% was too sensitive at startup
        )

        # ── Signal 2: fingerprint match ────────────────────────────────────────
        fp_match_found = False
        all_fps = list(_replay_window_fps) + list(_frozen_fps)

        # Only compare against fingerprints collected AFTER baseline matured
        # Require at least 3 stored fingerprints before trusting fp matching
        if len(all_fps) >= 3:
            for prev_fp in all_fps:
                if len(prev_fp) == len(current_fp):
                    match_ratio = (
                        sum(a == b for a, b in zip(current_fp, prev_fp))
                        / len(current_fp)
                    )
                    if match_ratio >= REPLAY_MATCH_RATIO:
                        fp_match_found = True
                        break

        # A match only matters if the pattern is complex OR clearly off-baseline.
        # Raise std threshold: normal noise at 0.25 is too easy to hit spuriously.
        is_meaningful_match = (std >= 0.5) or (baseline_dev_pct >= 5.0) or is_post_attack
        fp_match_fires = fp_match_found and is_meaningful_match

        # Store fingerprint AFTER comparison (not before)
        if std < 0.5:
            _frozen_fps.append(current_fp)
        else:
            _replay_window_fps.append(current_fp)

        # ── Signal 3: LSTM replay model ────────────────────────────────────────
        lstm_replay_fires, lstm_replay_err = _score_replay_lstm(values)
        with _api_lock:
            _api_state["last_replay_error"] = round(lstm_replay_err, 6)

        # Gate LSTM on baseline deviation — replay of off-baseline data is the threat
        if lstm_replay_fires and baseline_dev_pct < 3.0:
            lstm_replay_fires = False

        should_fire = zero_var_detected or fp_match_fires or lstm_replay_fires

        if should_fire:
            trigger = (
                ("zero_var"  if zero_var_detected  else "") +
                ("fp_match"  if fp_match_fires      else "") +
                ("lstm"      if lstm_replay_fires   else "")
            )
            detail = (
                f"Replay detected [{trigger}]: {len(values)} samples "
                f"mean={mean_v:.1f} PSI stdev={std:.4f} "
                f"baseline_dev={baseline_dev_pct:.1f}% "
                f"fp_match={fp_match_found} lstm_err={lstm_replay_err:.6f} "
                f"post_attack={is_post_attack}"
            )
            print(f"!!! REPLAY ATTACK DETECTED !!! {detail}")
            _record_alert("REPLAY_ATTACK", detail, -0.95)
            _replay_cooldown_until = time.time() + REPLAY_COOLDOWN

            for record_obj in [
                Point("security_alerts")
                .tag("alert_type", "REPLAY_ATTACK")
                .tag("session_id", SESSION_ID)
                .field("detail", detail)
                .field("score",  -0.95)
                .time(time.time_ns(), WritePrecision.NS),

                Point("security_alerts")
                .tag("alert_type", "REPLAY_DELTA_LOG")
                .tag("session_id", SESSION_ID)
                .field("delta", round(max(values) - min(values), 2))
                .field("score", -0.95)
                .time(time.time_ns(), WritePrecision.NS),

                Point("attack_status")
                .tag("attack_type", "REPLAY")
                .tag("session_id", SESSION_ID)
                .field("status", "DETECTED")
                .time(time.time_ns(), WritePrecision.NS),

                Point("security_metrics")
                .tag("sensor",     "ml_engine")
                .tag("session_id", SESSION_ID)
                .field("anomaly_score", -0.95)
                .field("is_anomaly",    1)
                .time(time.time_ns(), WritePrecision.NS),
            ]:
                write_api.write(bucket=INFLUX_BUCKET, record=record_obj)

            _write_grafana_event(
                metric_type="pressure", value=mean_v,
                event_type="REPLAY_ATTACK", severity="critical",
                source="ml-engine", detail=detail
            )
            alerts.append({"type": "REPLAY_ATTACK", "detail": detail})

    except Exception as e:
        print(f"Replay detection error: {e}")
    return alerts


# ═══════════════════════════════════════════════════════════════════════════════
# Semantic injection (forced-write) checker — with deduplication
# ═══════════════════════════════════════════════════════════════════════════════

def check_forced_writes() -> list[dict]:
    """
    Detect direct writes to sensor Modbus registers (100–103).

    Deduplication: each event row carries a _time timestamp.  We build a string key
    from (register, value, rounded-second).  If we have already alerted on that key
    within the last INJECTION_DEDUP_TTL seconds we skip it — preventing the same
    forced_write record from re-firing on every 15-s loop pass while it sits inside
    the -60s query window.
    """
    global _semantic_injection_seen
    if in_grace_period():
        return []

    # ── Purge stale dedup entries ──────────────────────────────────────────────
    now = time.time()
    stale_keys = [k for k, alerted_at in _seen_injection_ts.items()
                  if now - alerted_at > _INJECTION_DEDUP_TTL]
    for k in stale_keys:
        del _seen_injection_ts[k]

    query = f'''
from(bucket: "{INFLUX_BUCKET}")
  |> range(start: -60s)
  |> filter(fn: (r) => r["_measurement"] == "forced_writes")
  |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
  |> sort(columns: ["_time"], desc: true)
  |> limit(n: 5)
'''
    alerts = []
    try:
        result = query_api.query_data_frame(query)
        if isinstance(result, list):
            result = pd.concat(result) if result else pd.DataFrame()
        if result.empty:
            return []

        for _, row in result.iterrows():
            val = float(row.get("value",    0))
            reg = int(row.get("register",  -1))

            # Build deduplication key: register + rounded value + 10-s bucket
            try:
                ts = row.get("_time") or row.name
                ts_bucket = int(pd.Timestamp(ts).timestamp() // 10) * 10
            except Exception:
                ts_bucket = int(now // 10) * 10

            dedup_key = f"{reg}:{val:.0f}:{ts_bucket}"
            if dedup_key in _seen_injection_ts:
                continue   # already alerted for this exact event

            # Mark as seen BEFORE writing the alert to avoid race conditions
            _seen_injection_ts[dedup_key] = now

            detail = f"Direct write to sensor reg {reg} value={val:.0f}"
            alerts.append({"type": "SEMANTIC_INJECTION", "detail": detail})
            print(f"!!! SEMANTIC INJECTION DETECTED !!! Reg={reg} Val={val:.0f}")
            _record_alert("SEMANTIC_INJECTION", detail, -1.0)
            _semantic_injection_seen = True
            _write_grafana_event(
                metric_type="register_write", value=val,
                event_type="SEMANTIC_INJECTION", severity="critical",
                source="ml-engine", detail=detail
            )

    except Exception as e:
        print(f"forced_writes query error: {e}")
    return alerts


# ── NOTE: DNP3 —— REMOVED FROM ML PIPELINE ────────────────────────────────────
# DNP3 events are logged directly by plc/dnp3_server.py to the
# recon_scan_events measurement (event_type=recon_scan_detection).
# They do NOT affect anomaly_score or is_anomaly in security_metrics.
# ─────────────────────────────────────────────────────────────────────────────


# ═══════════════════════════════════════════════════════════════════════════════
# FastAPI server (background thread)
# ═══════════════════════════════════════════════════════════════════════════════

def _start_api_server() -> None:
    try:
        from fastapi import FastAPI, Query as FQuery
        from fastapi.middleware.cors import CORSMiddleware
        import uvicorn

        app = FastAPI(
            title="ICS Honeypot ML Engine API",
            description="Alert and metrics endpoint (IF + LSTM + Replay-LSTM ensemble)",
            version="5.0.0"
        )
        app.add_middleware(CORSMiddleware,
                           allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

        @app.get("/health")
        def health():
            with _api_lock:
                return {
                    "status":            "ok",
                    "session_id":        SESSION_ID,
                    "model_ready":       _api_state["model_ready"],
                    "lstm_ready":        _api_state["lstm_ready"],
                    "replay_lstm_ready": _api_state["replay_lstm_ready"],
                    "in_warmup":         _api_state["in_warmup"],
                    "in_grace":          _api_state["in_grace"],
                    "sample_count":      _api_state["sample_count"],
                    "uptime_seconds":    round(time.time() - _boot_time, 1),
                    "if_source":         "disk" if _if_loaded_from_disk else "trained",
                    "lstm_source":       "disk" if _lstm_loaded_from_disk else "trained",
                    "replay_lstm_source": "disk" if _replay_lstm_from_disk else "trained",
                }

        @app.get("/alerts")
        def get_alerts(
            limit: int = FQuery(default=200, le=1000),
            alert_type: str = FQuery(default=None)
        ):
            with _api_lock:
                alerts = list(_api_state["recent_alerts"])
            if alert_type:
                alerts = [a for a in alerts if a["alert_type"] == alert_type]
            return {"count": len(alerts), "alerts": alerts[-limit:][::-1]}

        @app.get("/metrics")
        def get_metrics():
            with _api_lock:
                return {
                    "last_if_anomaly_score": _api_state["last_if_score"],
                    "last_lstm_error":       _api_state["last_lstm_error"],
                    "last_replay_error":     _api_state["last_replay_error"],
                    "lstm_threshold":        _lstm_threshold,
                    "replay_lstm_threshold": _replay_lstm_thresh,
                    "ewma_pressure":         _api_state["ewma"],
                    "cusum_pos":             _api_state["cusum_pos"],
                    "cusum_neg":             _api_state["cusum_neg"],
                    "last_anomaly":          _api_state["last_anomaly"],
                    "total_alerts":          len(_api_state["recent_alerts"]),
                }

        @app.post("/reset-model")
        def reset_model():
            for f in [IF_MODEL_FILE, LSTM_MODEL_FILE, SCALER_FILE,
                      SCALER_FILE + ".threshold", REPLAY_LSTM_FILE,
                      REPLAY_SCALER_FILE, REPLAY_SCALER_FILE + ".threshold",
                      TRAINING_START_FILE]:
                if os.path.exists(f):
                    os.remove(f)
            global _if_model, _lstm_model, _lstm_scaler, _lstm_threshold
            global _replay_lstm_model, _replay_lstm_scaler, _replay_lstm_thresh
            _if_model = _lstm_model = _lstm_scaler = _lstm_threshold = None
            _replay_lstm_model = _replay_lstm_scaler = _replay_lstm_thresh = None
            with _api_lock:
                _api_state["model_ready"]       = False
                _api_state["lstm_ready"]        = False
                _api_state["replay_lstm_ready"] = False
                _api_state["in_warmup"]         = True
            _seen_injection_ts.clear()
            print("[ML-API] All models reset — retraining on next cycle.")
            return {"status": "reset", "message": "All models will retrain on next cycle."}

        print("[ML-API] Starting FastAPI server on port 8000...")
        uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")

    except ImportError:
        print("[ML-API] FastAPI/uvicorn not installed — API server disabled.")
    except Exception as e:
        print(f"[ML-API] Failed to start: {e}")


api_thread = threading.Thread(target=_start_api_server, daemon=True)
api_thread.start()
time.sleep(2)


# ═══════════════════════════════════════════════════════════════════════════════
# Main detection loop
# ═══════════════════════════════════════════════════════════════════════════════
print(f"[ML] Entering main detection loop. Grace period ends in {STARTUP_GRACE_SECONDS}s.")
while True:
    try:
        # 1. Semantic injection check (deduplication prevents repeat alerts)
        fw_alerts = check_forced_writes()
        for alert in fw_alerts:
            for record_obj in [
                Point("security_alerts")
                .tag("alert_type", alert["type"])
                .tag("session_id", SESSION_ID)
                .field("detail",   alert["detail"])
                .field("score",    -1.0)
                .time(time.time_ns(), WritePrecision.NS),

                Point("security_metrics")
                .tag("sensor",     "ml_engine")
                .tag("session_id", SESSION_ID)
                .field("anomaly_score", -1.0)
                .field("is_anomaly",    1)
                .time(time.time_ns(), WritePrecision.NS),
            ]:
                write_api.write(bucket=INFLUX_BUCKET, record=record_obj)

        # 2. Replay attack detection (fingerprint + LSTM)
        check_replay_attack()

        # 3. EWMA / CUSUM / Slope stealth drift
        run_drift_cycle()

        # 4. IsolationForest + LSTM general ensemble
        run_ml_cycle()

    except Exception as e:
        print(f"ML loop error: {e}")

    time.sleep(LOOP_INTERVAL)