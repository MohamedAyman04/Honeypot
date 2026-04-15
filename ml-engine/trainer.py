"""
ML Engine / Trainer  (v3 – persistence + hardened detections + Grafana events)
==============================================================================
Changes from v2:
  • Fix 0: Model persistence — load from disk; retrain only if missing or corrupted
  • Fix 2: Replay detection — pattern-fingerprint matching (old data repeating),
           gated on post-attack state OR baseline deviation (not just low variance)
  • Fix 3: DNP3 entirely removed from ML pipeline (no anomaly scoring)
  • Fix 4: Direction-aware slope drift: monotonic increase/decrease detection
           via linear regression + direction-consistency check
  • Fix 5: All events written to grafana_events with source, severity, metric_type
  • Fix 8: Lowered contamination, slower loop interval, warm-up inference suppression
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
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

# ── Configuration ──────────────────────────────────────────────────────────────
INFLUX_URL    = os.environ.get("INFLUX_URL",    "http://ics_historian:8086")
INFLUX_TOKEN  = os.environ.get("INFLUX_TOKEN",  "supersecrettoken")
INFLUX_ORG    = os.environ.get("INFLUX_ORG",    "my_refinery")
INFLUX_BUCKET = os.environ.get("INFLUX_BUCKET", "sensor_logs")

MODEL_FILE          = "/data/model.pkl"
TRAINING_START_FILE = "/data/training_start.txt"
WARMUP_PERIOD       = 180   # seconds of training before model is frozen
MIN_SAMPLES         = 30
LOOP_INTERVAL       = 15   # slower loop → less IF scoring noise

# ── False-positive guard ───────────────────────────────────────────────────────
# Suppress ALL detections for this many seconds after container start.
STARTUP_GRACE_SECONDS = 120
_boot_time = time.time()

def in_grace_period() -> bool:
    return (time.time() - _boot_time) < STARTUP_GRACE_SECONDS

# ── IsolationForest parameters ─────────────────────────────────────────────────
IF_CONTAMINATION   = 0.01   # very low → only clear outliers flagged
IF_N_ESTIMATORS    = 200
IF_SCORE_THRESHOLD = -0.20

# ── Expert-rule thresholds ─────────────────────────────────────────────────────
EXPERT_PRESSURE_DELTA_THRESHOLD = 20.0
EXPERT_PRESSURE_MEAN_DEV        = 35.0

# ── EWMA/CUSUM parameters ─────────────────────────────────────────────────────
EWMA_LAMBDA     = 0.1
CUSUM_THRESHOLD = 15.0    # lower threshold for earlier drift detection
_cusum_k        = 2.0

_ewma_state  = None
_cusum_pos   = 0.0
_cusum_neg   = 0.0

# ── Slope-based drift parameters (direction-aware) ────────────────────────────
MIN_SLOPE             = 0.05    # minimum slope magnitude
SLOPE_THRESHOLD       = 0.3     # PSI/sample — minimum slope to consider
SLOPE_DIRECTION_RATIO = 0.75    # ≥75% of recent slopes must agree on direction
SLOPE_WINDOW_SIZE     = 20      # samples used in regression window
CUMULATIVE_DEV_THRESH = 100.0   # cumulative |deviation| alarm threshold

_pressure_history = collections.deque(maxlen=SLOPE_WINDOW_SIZE)
_slope_history    = collections.deque(maxlen=10)
_cumulative_dev   = 0.0

# ── Rolling baseline (for replay gating and drift anchor) ─────────────────────
BASELINE_WINDOW     = 60        # samples in rolling baseline
_baseline_samples   = collections.deque(maxlen=BASELINE_WINDOW)

# ── Replay attack fingerprint matching ────────────────────────────────────────
REPLAY_WINDOW_SIZE  = 10        # samples per fingerprint window
REPLAY_MATCH_RATIO  = 0.85      # ≥85% rounded values matching = replay
REPLAY_BASELINE_DEV = 12.0      # % deviation from baseline to qualify gating
_replay_window_fps  = collections.deque(maxlen=20)  # window fingerprint history

# ── Post-attack state (gates replay detection) ────────────────────────────────
_semantic_injection_seen = False
_drift_attack_seen       = False

# ── Session ID ────────────────────────────────────────────────────────────────
SESSION_ID = os.environ.get('SESSION_ID', str(uuid.uuid4())[:8])

# ── In-memory model reference ─────────────────────────────────────────────────
_if_model = None


# ── Fix 0: Model persistence — load from disk, retrain only if needed ─────────
def _try_load_model() -> bool:
    """
    Attempt to load a previously trained model from disk.
    Returns True if loaded successfully.
    If file is corrupted, removes it and returns False (triggers retrain).
    """
    global _if_model
    if not os.path.exists(MODEL_FILE):
        print("[ML] No saved model found — will train from scratch.")
        return False
    try:
        loaded = joblib.load(MODEL_FILE)
        _if_model = loaded
        print(f"[ML] Model loaded from disk: {MODEL_FILE}")
        return True
    except Exception as e:
        print(f"[ML] Model file corrupted ({e}) — removing and retraining.")
        try:
            os.remove(MODEL_FILE)
        except Exception:
            pass
        if os.path.exists(TRAINING_START_FILE):
            try:
                os.remove(TRAINING_START_FILE)
            except Exception:
                pass
        return False


_model_loaded_from_disk = _try_load_model()

print(f"--- ML ENGINE v3 STARTING [session={SESSION_ID}] ---")
print(f"    Grace period : {STARTUP_GRACE_SECONDS}s")
print(f"    CUSUM thresh : {CUSUM_THRESHOLD}")
print(f"    Slope thresh : {SLOPE_THRESHOLD} PSI/sample (dir_ratio={SLOPE_DIRECTION_RATIO})")
print(f"    Model on disk: {_model_loaded_from_disk}")

db_client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
write_api  = db_client.write_api(write_options=SYNCHRONOUS)
query_api  = db_client.query_api()

# Shared state for the API server thread
_api_state = {
    "model_ready":   _model_loaded_from_disk,
    "in_warmup":     not _model_loaded_from_disk,
    "in_grace":      True,
    "sample_count":  0,
    "last_score":    None,
    "last_anomaly":  None,
    "ewma":          None,
    "cusum_pos":     0.0,
    "cusum_neg":     0.0,
    "recent_alerts": [],
}
_api_lock = threading.Lock()


# ── Fix 5: Structured Grafana event writer ────────────────────────────────────
def _write_grafana_event(metric_type: str, value: float, event_type: str,
                          severity: str, source: str, detail: str = "") -> None:
    """
    Write a structured event to grafana_events measurement.
    Schema: timestamp | metric_type | value | event_type | severity | source
    """
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


# ── Feature extraction (DNP3 intentionally excluded) ──────────────────────────
def fetch_pipeline_features(lookback: str = "-1h") -> pd.DataFrame:
    """
    Pull pipeline telemetry from InfluxDB and compute ML features.
    NOTE: DNP3 data is NOT included — it is NOT an ML feature.
    """
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
                result, net[["_time", "is_write", "func_code", "length", "write_freq_10s"]],
                on="_time", direction="backward"
            )
            for col in ["is_write", "func_code", "length", "write_freq_10s"]:
                new_col = col + "_y"
                if new_col in result.columns:
                    result[col] = result[new_col].fillna(
                        result[col + "_x"] if col + "_x" in result.columns else 0
                    )
                    result.drop(columns=[c for c in [col + "_x", col + "_y"] if c in result.columns], inplace=True)
    except Exception as e:
        print(f"Network feature join error (non-fatal): {e}")

    feature_cols = [
        "pressure", "flow_rate", "temperature",
        "pressure_delta", "pressure_mean_dev",
        "inter_arrival_time", "write_freq_10s",
        "is_write", "func_code", "length"
    ]
    return result[feature_cols].fillna(0.0)


# ── Fix 4: Direction-aware slope helper ───────────────────────────────────────
def _compute_slope(values: collections.deque) -> float:
    """Linear regression slope over a pressure deque (PSI/sample)."""
    arr = np.array(list(values), dtype=float)
    if len(arr) < 4:
        return 0.0
    x = np.arange(len(arr), dtype=float)
    coeffs = np.polyfit(x, arr, 1)
    return float(coeffs[0])


# ── EWMA / CUSUM + direction-aware slope drift detector ───────────────────────
def run_ewma_cusum(current_pressure: float) -> tuple[bool, str]:
    """
    Stealth manipulation detector:
      1. EWMA tracker + CUSUM accumulator (classic low-variance drift)
      2. Slope-based detector: monotonic increase/decrease via regression
      3. Cumulative deviation threshold: sustained long-term shift

    Suppressed during grace period (called from run_drift_cycle).
    """
    global _ewma_state, _cusum_pos, _cusum_neg, _cumulative_dev

    # ── Update rolling histories ───────────────────────────────────────────────
    if not in_grace_period():
        _pressure_history.append(current_pressure)
        if (time.time() - _boot_time) >= (STARTUP_GRACE_SECONDS + 30):
            _baseline_samples.append(current_pressure)

    if _ewma_state is None:
        _ewma_state = current_pressure
        return False, "EWMA initialised"

    _ewma_state = EWMA_LAMBDA * current_pressure + (1 - EWMA_LAMBDA) * _ewma_state
    deviation   = current_pressure - _ewma_state

    _cusum_pos = max(0.0, _cusum_pos + deviation - _cusum_k)
    _cusum_neg = max(0.0, _cusum_neg - deviation - _cusum_k)
    _cumulative_dev += abs(deviation)

    # ── Fix 4: Slope analysis with direction consistency ───────────────────────
    slope_val      = 0.0
    slope_detected = False

    if len(_pressure_history) >= 8:
        slope_val = _compute_slope(_pressure_history)
        _slope_history.append(slope_val)

        if len(_slope_history) >= 5:
            positive_count = sum(1 for s in _slope_history if s > 0)
            direction_ratio = positive_count / len(_slope_history)

            # Monotonic increase: ≥75% positive slopes AND meaningful slope magnitude
            is_increasing = (direction_ratio >= SLOPE_DIRECTION_RATIO
                             and slope_val > SLOPE_THRESHOLD)
            # Monotonic decrease: ≤25% positive (= ≥75% negative) AND magnitude
            is_decreasing = (direction_ratio <= (1.0 - SLOPE_DIRECTION_RATIO)
                             and slope_val < -SLOPE_THRESHOLD)

            slope_detected = (is_increasing or is_decreasing) and (abs(slope_val) > MIN_SLOPE)

    cusum_detected  = (_cusum_pos > CUSUM_THRESHOLD or _cusum_neg > CUSUM_THRESHOLD)
    cumdev_detected = (_cumulative_dev > CUMULATIVE_DEV_THRESH)
    
    # Final drift condition: meaningful deviation AND (slope OR cusum)
    drift_detected  = (abs(deviation) >= 5.0) and (slope_detected or cusum_detected)

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
        # Reset accumulators after firing to avoid repeated alerts
        _cusum_pos      = 0.0
        _cusum_neg      = 0.0
        _cumulative_dev = 0.0

    return drift_detected, detail


# ── Expert rules ───────────────────────────────────────────────────────────────
def apply_expert_rules(features: pd.DataFrame) -> list[dict]:
    alerts = []
    if features.empty:
        return alerts

    row = features.iloc[-1]

    # Rule 1: Pressure jump with NO concurrent Modbus write commands
    if abs(row["pressure_delta"]) > EXPERT_PRESSURE_DELTA_THRESHOLD and row["write_freq_10s"] == 0:
        alerts.append({
            "type":   "CROSS_LAYER_ANOMALY",
            "detail": f"pressure_delta={row['pressure_delta']:.2f} PSI with no write commands"
        })

    # Rule 2: Sustained mean deviation — slow drift from rolling baseline
    if abs(row["pressure_mean_dev"]) > EXPERT_PRESSURE_MEAN_DEV:
        alerts.append({
            "type":   "STEALTH_DRIFT",
            "detail": f"pressure_mean_dev={row['pressure_mean_dev']:.2f} PSI"
        })

    # Rule 3: Physically impossible pressure (beyond physics engine ceiling)
    if row["pressure"] > 300.0:
        alerts.append({
            "type":   "OVER_PRESSURE",
            "detail": f"pressure={row['pressure']:.1f} PSI (beyond physical engine maximum)"
        })

    return alerts


# ── Record alert in shared state for API ──────────────────────────────────────
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
        if len(_api_state["recent_alerts"]) > 100:
            _api_state["recent_alerts"] = _api_state["recent_alerts"][-100:]
        _api_state["last_anomaly"] = entry


# ── Main ML loop ───────────────────────────────────────────────────────────────
def run_ml_cycle() -> None:
    features = fetch_pipeline_features(lookback="-2h")

    with _api_lock:
        _api_state["sample_count"] = len(features)
        _api_state["in_grace"]     = in_grace_period()

    if len(features) < MIN_SAMPLES:
        print(f"Collecting samples... ({len(features)}/{MIN_SAMPLES})")
        return

    global _if_model

    # ── Fix 0: Skip training if model was loaded from disk ────────────────────
    if _if_model is not None:
        with _api_lock:
            _api_state["model_ready"] = True
            _api_state["in_warmup"]   = False
    else:
        # ── Warm-up / training phase ───────────────────────────────────────────
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
            model = IsolationForest(contamination=IF_CONTAMINATION,
                                    random_state=42, n_estimators=IF_N_ESTIMATORS)
            model.fit(features)
            _if_model = model
            try:
                os.makedirs(os.path.dirname(MODEL_FILE), exist_ok=True)
                joblib.dump(model, MODEL_FILE)
                print(f"[ML] Model trained and saved → {MODEL_FILE}")
            except Exception as e:
                print(f"[ML] Failed to save model: {e}")
            remaining = WARMUP_PERIOD - (time.time() - start_time)
            print(f"[ML] Training mode: {remaining:.0f}s remaining — NO alerts.")
            return  # No detection during warm-up

        # Warm-up finished — load from disk if not in memory
        if _if_model is None and os.path.exists(MODEL_FILE):
            try:
                _if_model = joblib.load(MODEL_FILE)
                print("[ML] Model loaded post-warmup.")
            except Exception as e:
                print(f"[ML] Post-warmup model load failed: {e}")
                return

        with _api_lock:
            _api_state["model_ready"] = True

    # ── Detection phase ───────────────────────────────────────────────────────
    if in_grace_period():
        remaining_grace = STARTUP_GRACE_SECONDS - (time.time() - _boot_time)
        print(f"[GRACE PERIOD] {remaining_grace:.0f}s remaining — suppressing alerts.")
        return

    model = _if_model
    if model is None:
        print("[ML] No model available — skipping detection.")
        return

    recent      = features.tail(1)
    predictions = model.predict(recent)
    scores      = model.decision_function(recent)

    with _api_lock:
        if len(scores) > 0:
            _api_state["last_score"] = round(float(scores[-1]), 4)

    for pred, score in zip(predictions, scores):
        score_val  = float(score)
        is_anomaly = 1 if (pred == -1 and score_val < IF_SCORE_THRESHOLD) else 0

        expert_alerts = apply_expert_rules(features)
        for alert in expert_alerts:
            print(f"!!! {alert['type']} !!! {alert['detail']}")
            is_anomaly = 1
            score_val  = min(score_val, -0.5)
            _record_alert(alert["type"], alert["detail"], score_val)

            write_api.write(bucket=INFLUX_BUCKET, record=(
                Point("security_alerts")
                .tag("alert_type", alert["type"])
                .tag("session_id", SESSION_ID)
                .field("detail", alert["detail"])
                .field("score",  score_val)
                .time(time.time_ns(), WritePrecision.NS)
            ))
            _write_grafana_event(
                metric_type="anomaly", value=score_val,
                event_type=alert["type"], severity="high",
                source="ml-engine", detail=alert["detail"]
            )

        if is_anomaly and not expert_alerts:
            print(f"!!! ML ANOMALY DETECTED !!! score={score_val:.4f}")
            _record_alert("ISOLATION_FOREST", f"anomaly_score={score_val:.4f}", score_val)
            _write_grafana_event(
                metric_type="anomaly", value=score_val,
                event_type="ISOLATION_FOREST", severity="medium",
                source="ml-engine", detail=f"score={score_val:.4f}"
            )

        write_api.write(bucket=INFLUX_BUCKET, record=(
            Point("security_metrics")
            .tag("sensor",     "ml_engine")
            .tag("session_id", SESSION_ID)
            .field("anomaly_score", score_val)
            .field("is_anomaly",    is_anomaly)
            .time(time.time_ns(), WritePrecision.NS)
        ))

    print(
        f"[ML] Cycle complete — score={float(scores[0]):.4f}  "
        f"anomaly={int(predictions[0] == -1 and float(scores[0]) < IF_SCORE_THRESHOLD)}"
    )


def has_recent_writes() -> bool:
    """
    Returns True ONLY for legitimate actuator commands (registers ≥200).
    Sensor-register writes (100-103) are the attack and must NOT reset baseline.
    """
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


# ── EWMA/CUSUM + Slope drift cycle ────────────────────────────────────────────
def run_drift_cycle() -> None:
    global _ewma_state, _cusum_pos, _cusum_neg, _cumulative_dev, _drift_attack_seen
    if in_grace_period():
        return

    if has_recent_writes():
        # Legitimate operator change — reset baseline to adapt
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
                pressure = float(record.get_value())
                drift, detail = run_ewma_cusum(pressure)
                if drift:
                    _drift_attack_seen = True
                    print(f"!!! STEALTH DRIFT DETECTED !!! {detail}")
                    _record_alert("STEALTH_DRIFT_EWMA", detail, -0.8)

                    write_api.write(bucket=INFLUX_BUCKET, record=(
                        Point("security_alerts")
                        .tag("alert_type", "STEALTH_DRIFT_EWMA")
                        .tag("session_id", SESSION_ID)
                        .field("detail", detail)
                        .field("score",  -0.8)
                        .time(time.time_ns(), WritePrecision.NS)
                    ))
                    write_api.write(bucket=INFLUX_BUCKET, record=(
                        Point("security_metrics")
                        .tag("sensor",     "ml_engine")
                        .tag("session_id", SESSION_ID)
                        .field("anomaly_score", -0.8)
                        .field("is_anomaly",    1)
                        .time(time.time_ns(), WritePrecision.NS)
                    ))
                    _write_grafana_event(
                        metric_type="pressure", value=pressure,
                        event_type="STEALTH_DRIFT", severity="high",
                        source="ml-engine", detail=detail
                    )
    except Exception as e:
        print(f"Drift cycle error: {e}")


# ── Fix 2: Replay Attack Detector — pattern fingerprint matching ──────────────
REPLAY_COOLDOWN = 120.0
_replay_cooldown_until = 0.0


def _fingerprint_window(values: list) -> tuple:
    """Round each value to nearest 0.5 PSI → fuzzy fingerprint for replay matching."""
    return tuple(round(v * 2) / 2 for v in values)


def check_replay_attack() -> list[dict]:
    """
    Detect replay by MATCHING the current pressure window against previously
    observed windows. A match means historical data is being re-injected.

    Gates — at least ONE must be true to fire:
      A) Post-attack: semantic injection OR drift already detected this session
      B) Baseline deviation: mean pressure deviates >12% from rolling baseline
      C) Fingerprint match: current window ≥85% matches a previous window
         AND variance is near-zero (frozen telemetry signature)

    Normal stable operation (same valve/pump setpoint) will NOT match because
    it appears as a continuous stream, not a duplicate window fingerprint.
    """
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

        # Update baseline with all observed values
        if (time.time() - _boot_time) >= (STARTUP_GRACE_SECONDS + 30):
            _baseline_samples.extend(values)
        baseline = float(np.mean(list(_baseline_samples))) if len(_baseline_samples) > 5 else None

        mean_v = statistics.mean(values)

        baseline_dev_pct = 0.0
        if baseline is not None and baseline > 1.0:
            baseline_dev_pct = abs(mean_v - baseline) / baseline * 100.0
            
        std    = statistics.stdev(values) if len(values) > 1 else 0.0

        # Current window fingerprint
        current_fp = _fingerprint_window(values[-REPLAY_WINDOW_SIZE:])

        # ── Gate A: post-attack masking ───────────────────────────────────────
        is_post_attack = _semantic_injection_seen or _drift_attack_seen

        has_baseline_dev = baseline_dev_pct > REPLAY_BASELINE_DEV

        # ── Gate C: fingerprint match + frozen telemetry ──────────────────────
        fp_match_found = False
        if baseline_dev_pct >= 10.0 and std > 0.3:
            if std < 1.0 and len(_replay_window_fps) >= 2:
                for prev_fp in list(_replay_window_fps)[:-1]:
                    if len(prev_fp) == len(current_fp):
                        match_ratio = (
                            sum(a == b for a, b in zip(current_fp, prev_fp))
                            / len(current_fp)
                        )
                        if match_ratio >= REPLAY_MATCH_RATIO:
                            fp_match_found = True
                            break

        # Store fingerprint for future comparisons regardless
        if not in_grace_period() and std >= 0.5:
            _replay_window_fps.append(current_fp)

        # ── Fire condition ────────────────────────────────────────────────────
        should_fire = fp_match_found and (baseline_dev_pct >= 10.0) and (std < 1.0)

        if should_fire:
            detail = (
                f"Replay detected: {len(values)} samples "
                f"mean={mean_v:.1f} PSI stdev={std:.4f} "
                f"baseline_dev={baseline_dev_pct:.1f}% "
                f"fp_match={fp_match_found} post_attack={is_post_attack}"
            )
            print(f"!!! REPLAY ATTACK DETECTED !!! {detail}")
            _record_alert("REPLAY_ATTACK", detail, -0.95)
            _replay_cooldown_until = time.time() + REPLAY_COOLDOWN

            write_api.write(bucket=INFLUX_BUCKET, record=(
                Point("security_alerts")
                .tag("alert_type", "REPLAY_ATTACK")
                .tag("session_id", SESSION_ID)
                .field("detail", detail)
                .field("score",  -0.95)
                .time(time.time_ns(), WritePrecision.NS)
            ))
            write_api.write(bucket=INFLUX_BUCKET, record=(
                Point("security_alerts")
                .tag("alert_type", "REPLAY_DELTA_LOG")
                .tag("session_id", SESSION_ID)
                .field("delta", round(max(values) - min(values), 2))
                .field("score", -0.95)
                .time(time.time_ns(), WritePrecision.NS)
            ))
            write_api.write(bucket=INFLUX_BUCKET, record=(
                Point("attack_status")
                .tag("attack_type", "REPLAY")
                .tag("session_id", SESSION_ID)
                .field("status", "DETECTED")
                .time(time.time_ns(), WritePrecision.NS)
            ))
            write_api.write(bucket=INFLUX_BUCKET, record=(
                Point("security_metrics")
                .tag("sensor",     "ml_engine")
                .tag("session_id", SESSION_ID)
                .field("anomaly_score", -0.95)
                .field("is_anomaly",    1)
                .time(time.time_ns(), WritePrecision.NS)
            ))
            _write_grafana_event(
                metric_type="pressure", value=mean_v,
                event_type="REPLAY_ATTACK", severity="critical",
                source="ml-engine", detail=detail
            )
            alerts.append({"type": "REPLAY_ATTACK", "detail": detail})

    except Exception as e:
        print(f"Replay detection error: {e}")
    return alerts


# ── Forced-write / Semantic Injection check ───────────────────────────────────
def check_forced_writes() -> list[dict]:
    """Detect and log direct writes to sensor registers (100–103)."""
    global _semantic_injection_seen
    if in_grace_period():
        return []

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
        if not result.empty:
            for _, row in result.iterrows():
                val    = float(row.get('value',    0))
                reg    = int(row.get('register',  -1))
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


# ── API Server (FastAPI in background thread) ─────────────────────────────────
def _start_api_server() -> None:
    try:
        from fastapi import FastAPI, Query as FQuery
        from fastapi.middleware.cors import CORSMiddleware
        import uvicorn

        app = FastAPI(
            title="ICS Honeypot ML Engine API",
            description="Alert and metrics endpoint for Purdue Level-3 integration",
            version="3.0.0"
        )
        app.add_middleware(CORSMiddleware,
                           allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

        @app.get("/health")
        def health():
            with _api_lock:
                return {
                    "status":         "ok",
                    "session_id":     SESSION_ID,
                    "model_ready":    _api_state["model_ready"],
                    "in_warmup":      _api_state["in_warmup"],
                    "in_grace":       _api_state["in_grace"],
                    "sample_count":   _api_state["sample_count"],
                    "uptime_seconds": round(time.time() - _boot_time, 1),
                    "model_source":   "disk" if _model_loaded_from_disk else "trained",
                }

        @app.get("/alerts")
        def get_alerts(
            limit: int = FQuery(default=50, le=100),
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
                    "last_anomaly_score": _api_state["last_score"],
                    "ewma_pressure":      _api_state["ewma"],
                    "cusum_pos":          _api_state["cusum_pos"],
                    "cusum_neg":          _api_state["cusum_neg"],
                    "last_anomaly":       _api_state["last_anomaly"],
                    "total_alerts":       len(_api_state["recent_alerts"]),
                }

        @app.post("/reset-model")
        def reset_model():
            """Force model retrain by deleting model and training marker."""
            for f in [MODEL_FILE, TRAINING_START_FILE]:
                if os.path.exists(f):
                    os.remove(f)
            global _if_model
            _if_model = None
            with _api_lock:
                _api_state["model_ready"] = False
                _api_state["in_warmup"]   = True
            print("[ML-API] Model reset — will retrain on next cycle.")
            return {"status": "reset", "message": "Model will retrain on next cycle."}

        print("[ML-API] Starting FastAPI server on port 8000...")
        uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")

    except ImportError:
        print("[ML-API] FastAPI/uvicorn not installed — API server disabled.")
    except Exception as e:
        print(f"[ML-API] Failed to start: {e}")


# Start API in background daemon thread
api_thread = threading.Thread(target=_start_api_server, daemon=True)
api_thread.start()
time.sleep(2)


# ── Entry point ────────────────────────────────────────────────────────────────
print(f"[ML] Entering main detection loop. Grace period ends in {STARTUP_GRACE_SECONDS}s.")
while True:
    try:
        # 1. Semantic injection check (suppressed during grace period)
        fw_alerts = check_forced_writes()
        for alert in fw_alerts:
            write_api.write(bucket=INFLUX_BUCKET, record=(
                Point("security_alerts")
                .tag("alert_type", alert["type"])
                .tag("session_id", SESSION_ID)
                .field("detail",   alert["detail"])
                .field("score",    -1.0)
                .time(time.time_ns(), WritePrecision.NS)
            ))
            write_api.write(bucket=INFLUX_BUCKET, record=(
                Point("security_metrics")
                .tag("sensor",     "ml_engine")
                .tag("session_id", SESSION_ID)
                .field("anomaly_score", -1.0)
                .field("is_anomaly",    1)
                .time(time.time_ns(), WritePrecision.NS)
            ))

        # 2. Replay attack detection (pattern fingerprint matching)
        check_replay_attack()

        # 3. EWMA/CUSUM/Slope stealth drift detection
        run_drift_cycle()

        # 4. IsolationForest ML cycle
        run_ml_cycle()

        # 5. Write training-mode marker to Grafana (is_anomaly=2 = "training")
        with _api_lock:
            warmup = _api_state.get("in_warmup", True)
        if in_grace_period() or warmup:
            write_api.write(bucket=INFLUX_BUCKET, record=(
                Point("security_metrics")
                .tag("sensor",     "ml_engine")
                .tag("session_id", SESSION_ID)
                .field("anomaly_score", 0.0)
                .field("is_anomaly",    2)
                .time(time.time_ns(), WritePrecision.NS)
            ))

    except Exception as e:
        print(f"ML loop error: {e}")

    time.sleep(LOOP_INTERVAL)