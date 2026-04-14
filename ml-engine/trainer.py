"""
ML Engine / Trainer  (v2 – false-positive hardened + REST API)
==============================================================
Reads pipeline telemetry from InfluxDB, trains an IsolationForest during warm-up,
then runs anomaly detection and writes results back to InfluxDB.

Detection layers (per thesis §4.6.1):
  1. IsolationForest  – statistical anomaly score on cross-layer features
  2. Expert rules     – threshold + cross-layer heuristics
  3. EWMA/CUSUM drift – stealth manipulation detector (§4.6.1 point 3)
  4. forced_writes    – semantic injection via direct register writes
  5. Recon logging    – read-only FC events flagged but NOT anomaly-scored

False-positive mitigations added in v2:
  • STARTUP_GRACE_SECONDS (120 s) – no alerts written during startup transient
  • Stale model deleted on boot (avoids old-distribution mismatch)
  • IsolationForest contamination lowered → 0.02
  • Expert-rule thresholds raised to operational values
  • CUSUM threshold raised → 40.0 PSI × cycles
  • EWMA/CUSUM suppressed during grace period
  • Embedded FastAPI server on port 8000 for Level-3 integration
"""

import time
import os
import uuid
import threading
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
WARMUP_PERIOD       = 180   # seconds before model is locked
MIN_SAMPLES         = 30    # minimum InfluxDB rows before training begins
LOOP_INTERVAL       = 10    # seconds between ML cycles

# ── False-positive guard ───────────────────────────────────────────────────────
# Suppress ALL detections for this many seconds after container start.
# Physics engine needs ~60 s to converge from initial conditions.
STARTUP_GRACE_SECONDS = 120

_boot_time = time.time()

def in_grace_period() -> bool:
    return (time.time() - _boot_time) < STARTUP_GRACE_SECONDS

# Delete stale model from a previous Docker session so we always retrain
if os.path.exists(MODEL_FILE):
    os.remove(MODEL_FILE)
    print("[ML] Removed stale model from previous session.")
if os.path.exists(TRAINING_START_FILE):
    os.remove(TRAINING_START_FILE)
    print("[ML] Removed stale training-start marker.")

# ── EWMA/CUSUM parameters ─────────────────────────────────────────────────────
# Calibrated for the phase-5 stealth drift: 15 steps × 5 PSI each starting ~120 PSI.
# With k=2.0 and threshold=20 detection fires within 3-4 steps of sustained drift.
EWMA_LAMBDA              = 0.1    # slow tracker; large deviations build up in CUSUM
CUSUM_THRESHOLD          = 20.0   # lowered: catches 15-step drift reliably
EWMA_DEVIATION_THRESHOLD = 10.0   # PSI – sustained drift alarm
_cusum_k                 = 2.0    # allowance / slack; normal physics noise stays below this

_ewma_state  = None
_cusum_pos   = 0.0
_cusum_neg   = 0.0

# ── IsolationForest parameters ─────────────────────────────────────────────────
IF_CONTAMINATION   = 0.01   # very low → only clear outliers flagged
IF_N_ESTIMATORS    = 200    # more trees → more stable scoring
IF_SCORE_THRESHOLD = -0.20  # deeper below normal before flagging
                            # (IsolationForest scores normal data near 0..+0.1)
                            # Values between -0.20 and 0 are borderline → ignored

# In-memory model reference (avoids disk I/O race between train and load)
_if_model = None

# ── Expert-rule thresholds (raised to operational values) ─────────────────────
EXPERT_PRESSURE_DELTA_THRESHOLD = 20.0   # was 15.0 PSI – needs a real spike
EXPERT_PRESSURE_MEAN_DEV        = 35.0   # was 25.0 PSI – noise won't reach this
EXPERT_PRESSURE_MAX             = 200.0  # safety ceiling (unchanged)

SESSION_ID = os.environ.get('SESSION_ID', str(uuid.uuid4())[:8])

print(f"--- ML ENGINE v2 STARTING [session={SESSION_ID}] ---")
print(f"    Grace period: {STARTUP_GRACE_SECONDS}s, CUSUM threshold: {CUSUM_THRESHOLD}, IF threshold: {IF_SCORE_THRESHOLD}")

db_client  = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
write_api  = db_client.write_api(write_options=SYNCHRONOUS)
query_api  = db_client.query_api()

# Shared state for the API server thread
_api_state = {
    "model_ready":      False,
    "in_warmup":        True,
    "in_grace":         True,
    "sample_count":     0,
    "last_score":       None,
    "last_anomaly":     None,
    "ewma":             None,
    "cusum_pos":        0.0,
    "cusum_neg":        0.0,
    "recent_alerts":    [],   # last 100 alerts written
}
_api_lock = threading.Lock()


# ── Feature extraction ─────────────────────────────────────────────────────────
def fetch_pipeline_features(lookback: str = "-1h") -> pd.DataFrame:
    """
    Pull the last <lookback> of pipeline_metrics from InfluxDB and
    compute ML features. Returns an empty DataFrame if nothing found.
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

    result["inter_arrival_time"] = (
        result["_time"].diff().dt.total_seconds().fillna(0)
    )
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
            net["length"]    = net.get("value", pd.Series([0]*len(net))).astype(int)
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
                    result.drop(columns=[c for c in [col+"_x", col+"_y"] if c in result.columns], inplace=True)
    except Exception as e:
        print(f"Network feature join error (non-fatal): {e}")

    feature_cols = [
        "pressure", "flow_rate", "temperature",
        "pressure_delta", "pressure_mean_dev",
        "inter_arrival_time", "write_freq_10s",
        "is_write", "func_code", "length"
    ]
    return result[feature_cols].fillna(0.0)


# ── EWMA / CUSUM stealth drift detector ───────────────────────────────────────
def run_ewma_cusum(current_pressure: float) -> tuple[bool, str]:
    """
    Stealth manipulation detector using EWMA + CUSUM (false-positive hardened).
    Suppressed during grace period and warm-up.
    """
    global _ewma_state, _cusum_pos, _cusum_neg

    if _ewma_state is None:
        _ewma_state = current_pressure
        return False, "EWMA initialised"

    _ewma_state = EWMA_LAMBDA * current_pressure + (1 - EWMA_LAMBDA) * _ewma_state
    deviation   = current_pressure - _ewma_state

    _cusum_pos = max(0, _cusum_pos + deviation - _cusum_k)
    _cusum_neg = max(0, _cusum_neg - deviation - _cusum_k)

    drift_detected = (_cusum_pos > CUSUM_THRESHOLD or _cusum_neg > CUSUM_THRESHOLD)
    detail = (f"EWMA={_ewma_state:.2f} PSI  deviation={deviation:.2f}  "
              f"CUSUM+={_cusum_pos:.2f}  CUSUM-={_cusum_neg:.2f}")

    with _api_lock:
        _api_state["ewma"]      = round(_ewma_state, 2)
        _api_state["cusum_pos"] = round(_cusum_pos, 2)
        _api_state["cusum_neg"] = round(_cusum_neg, 2)

    if drift_detected:
        _cusum_pos = 0.0
        _cusum_neg = 0.0

    return drift_detected, detail


# ── Expert rules ───────────────────────────────────────────────────────────────
def apply_expert_rules(features: pd.DataFrame) -> list[dict]:
    alerts = []
    if features.empty:
        return alerts

    row = features.iloc[-1]

    # Rule 1: Pressure jump with NO concurrent Modbus write commands
    # (cross-layer inconsistency — physics changed without a PLC command)
    if abs(row["pressure_delta"]) > EXPERT_PRESSURE_DELTA_THRESHOLD and row["write_freq_10s"] == 0:
        alerts.append({
            "type":   "CROSS_LAYER_ANOMALY",
            "detail": f"pressure_delta={row['pressure_delta']:.2f} PSI with no write commands"
        })

    # Rule 2: Sustained mean deviation — slow drift from baseline
    if abs(row["pressure_mean_dev"]) > EXPERT_PRESSURE_MEAN_DEV:
        alerts.append({
            "type":   "STEALTH_DRIFT",
            "detail": f"pressure_mean_dev={row['pressure_mean_dev']:.2f} PSI"
        })

    # Rule 3: OVER_PRESSURE — only fires above 300 PSI, which is physically
    # impossible from normal pump operation (max physics output ~330 PSI at
    # 3000 RPM / valve closed, but pipeline register 100 is sensor-write only).
    # NOTE: Real semantic injection is detected by check_forced_writes() via
    # the forced_writes InfluxDB measurement — NOT by this pressure rule.
    # This rule only catches extreme out-of-range values that go beyond physics.
    if row["pressure"] > 300.0:
        alerts.append({
            "type":   "OVER_PRESSURE",
            "detail": f"pressure={row['pressure']:.1f} PSI (beyond physical engine maximum)"
        })

    return alerts


# ── Record alert in shared state for API ──────────────────────────────────────
def _record_alert(alert_type: str, detail: str, score: float):
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "alert_type": alert_type,
        "detail":     detail,
        "score":      round(score, 4),
        "session_id": SESSION_ID,
    }
    with _api_lock:
        _api_state["recent_alerts"].append(entry)
        # Keep only last 100 alerts in memory
        if len(_api_state["recent_alerts"]) > 100:
            _api_state["recent_alerts"] = _api_state["recent_alerts"][-100:]
        _api_state["last_anomaly"] = entry


# ── Main ML loop ───────────────────────────────────────────────────────────────
def run_ml_cycle():
    features = fetch_pipeline_features(lookback="-2h")

    with _api_lock:
        _api_state["sample_count"] = len(features)
        _api_state["in_grace"]     = in_grace_period()

    if len(features) < MIN_SAMPLES:
        print(f"Collecting samples... ({len(features)}/{MIN_SAMPLES})")
        return

    # ── Warm-up / training phase ──────────────────────────────────────────────
    if not os.path.exists(TRAINING_START_FILE):
        with open(TRAINING_START_FILE, "w") as f:
            f.write(str(time.time()))
        print("Warm-up phase started.")

    with open(TRAINING_START_FILE) as f:
        start_time = float(f.read().strip())

    in_warmup = (time.time() - start_time) < WARMUP_PERIOD

    with _api_lock:
        _api_state["in_warmup"] = in_warmup

    # Train / update model ONLY during warm-up
    # Once warm-up ends the model is frozen to avoid learning attack patterns
    global _if_model
    if in_warmup or _if_model is None:
        model = IsolationForest(contamination=IF_CONTAMINATION, random_state=42, n_estimators=IF_N_ESTIMATORS)
        model.fit(features)
        _if_model = model
        joblib.dump(model, MODEL_FILE)
        if in_warmup:
            remaining = WARMUP_PERIOD - (time.time() - start_time)
            print(f"Training Mode: {remaining:.0f}s remaining in warm-up — NO alerts will fire.")
            return   # No detection during warm-up

    with _api_lock:
        _api_state["model_ready"] = True

    # ── Detection phase ───────────────────────────────────────────────────────
    if in_grace_period():
        remaining_grace = STARTUP_GRACE_SECONDS - (time.time() - _boot_time)
        print(f"[GRACE PERIOD] {remaining_grace:.0f}s remaining — suppressing alerts.")
        return

    # Use in-memory model; fall back to disk model if not yet in memory
    model = _if_model
    if model is None:
        if os.path.exists(MODEL_FILE):
            model = joblib.load(MODEL_FILE)
            _if_model = model
        else:
            print("[ML] No model available yet — skipping detection.")
            return

    # Score only the MOST RECENT sample (not the last 5 which include warm-up data)
    recent      = features.tail(1)
    predictions = model.predict(recent)
    scores      = model.decision_function(recent)

    with _api_lock:
        if len(scores) > 0:
            _api_state["last_score"] = round(float(scores[-1]), 4)

    for i, (pred, score) in enumerate(zip(predictions, scores)):
        # Gate: only treat as anomaly if IF score is clearly below normal range
        score_val  = float(score)
        is_anomaly = 1 if (pred == -1 and score_val < IF_SCORE_THRESHOLD) else 0

        expert_alerts = apply_expert_rules(features)  # uses full DataFrame for context
        for alert in expert_alerts:
            print(f"!!! {alert['type']} !!! {alert['detail']}")
            is_anomaly = 1
            score_val  = min(score_val, -0.5)
            _record_alert(alert["type"], alert["detail"], score_val)

            a_point = (Point("security_alerts")
                       .tag("alert_type", alert["type"])
                       .tag("session_id", SESSION_ID)
                       .field("detail",   alert["detail"])
                       .field("score",    score_val)
                       .time(time.time_ns(), WritePrecision.NS))
            write_api.write(bucket=INFLUX_BUCKET, record=a_point)

        if is_anomaly and not expert_alerts:
            # Pure IF anomaly (no expert rule triggered it)
            print(f"!!! ML ANOMALY DETECTED !!! score={score_val:.4f}")
            _record_alert("ISOLATION_FOREST", f"anomaly_score={score_val:.4f}", score_val)

        point = (Point("security_metrics")
                 .tag("sensor",     "ml_engine")
                 .tag("session_id", SESSION_ID)
                 .field("anomaly_score", score_val)
                 .field("is_anomaly",    is_anomaly)
                 .time(time.time_ns(), WritePrecision.NS))
        write_api.write(bucket=INFLUX_BUCKET, record=point)

    print(f"ML cycle complete — 1 sample scored, "
          f"anomaly={int(predictions[0] == -1 and float(scores[0]) < IF_SCORE_THRESHOLD)}, "
          f"score={float(scores[0]):.4f}")


def has_recent_writes() -> bool:
    """
    Returns True ONLY for LEGITIMATE ACTUATOR commands (registers 200+: pump RPM,
    valve position, valve toggle). Sensor-register writes (100-103) are the ATTACK
    itself and must NOT reset the EWMA baseline — doing so would blind the detector.
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

# ── EWMA/CUSUM cycle ──────────────────────────────────────────────────────────
def run_drift_cycle():
    """Fetch latest pressure sample and run EWMA/CUSUM drift detection."""
    global _ewma_state, _cusum_pos, _cusum_neg
    if in_grace_period():
        return   # Suppressed during grace period

    if has_recent_writes():
        # Reset baseline to adapt to legitimate operator changes
        _ewma_state = None
        _cusum_pos = 0.0
        _cusum_neg = 0.0
        return

    query = f'''
from(bucket: "{INFLUX_BUCKET}")
  |> range(start: -30s)
  |> filter(fn: (r) => r["_measurement"] == "pipeline_metrics" and r["_field"] == "pressure")
  |> last()
'''
    try:
        tables = query_api.query(query)
        for table in tables:
            for record in table.records:
                pressure = float(record.get_value())
                drift, detail = run_ewma_cusum(pressure)
                if drift:
                    print(f"!!! EWMA/CUSUM DRIFT DETECTED !!! {detail}")
                    _record_alert("STEALTH_DRIFT_EWMA", detail, -0.8)
                    a_point = (Point("security_alerts")
                               .tag("alert_type", "STEALTH_DRIFT_EWMA")
                               .tag("session_id", SESSION_ID)
                               .field("detail",   detail)
                               .field("score",    -0.8)
                               .time(time.time_ns(), WritePrecision.NS))
                    write_api.write(bucket=INFLUX_BUCKET, record=a_point)
                    m_point = (Point("security_metrics")
                               .tag("sensor",     "ml_engine")
                               .tag("session_id", SESSION_ID)
                               .field("anomaly_score", -0.8)
                               .field("is_anomaly",    1)
                               .time(time.time_ns(), WritePrecision.NS))
                    write_api.write(bucket=INFLUX_BUCKET, record=m_point)
    except Exception as e:
        print(f"EWMA/CUSUM cycle error: {e}")


# ── Replay Attack Detector ────────────────────────────────────────────────────
_replay_cooldown_until = 0.0   # seconds since epoch; avoid duplicate alerts

def check_replay_attack() -> list[dict]:
    """
    Detect Phase-8 replay: attacker writes a frozen pressure value directly to
    InfluxDB. The giveaway is near-zero variance in pressure over a short window
    despite normal variance being present in earlier history.

    Logic:
      1. Query the last 60 s of pipeline_metrics pressure values.
      2. If there are ≥ 8 data points AND std_dev < 0.8 PSI → frozen telemetry.
      3. Write to security_alerts (alert_type=REPLAY_ATTACK) and
         attack_status (for the Grafana stat panel) with a 60-second cooldown.
    """
    global _replay_cooldown_until
    if in_grace_period():
        return []
    if time.time() < _replay_cooldown_until:
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
        if len(values) >= 8:
            import statistics
            std = statistics.stdev(values)
            mean = statistics.mean(values)
            if std < 0.8:
                detail = (f"Frozen telemetry detected: {len(values)} samples at "
                          f"mean={mean:.1f} PSI, stdev={std:.3f} – replay attack")
                print(f"!!! REPLAY ATTACK DETECTED !!! {detail}")
                _record_alert("REPLAY_ATTACK", detail, -0.95)
                _replay_cooldown_until = time.time() + 60.0

                # ── Write to security_alerts
                a_point = (Point("security_alerts")
                           .tag("alert_type", "REPLAY_ATTACK")
                           .tag("session_id", SESSION_ID)
                           .field("detail", detail)
                           .field("score",  -0.95)
                           .time(time.time_ns(), WritePrecision.NS))
                write_api.write(bucket=INFLUX_BUCKET, record=a_point)

                # ── Write delta to security_alerts for the time-series panel
                d_point = (Point("security_alerts")
                           .tag("alert_type", "REPLAY_DELTA_LOG")
                           .tag("session_id", SESSION_ID)
                           .field("delta",  round(max(values) - min(values), 2))
                           .field("score",  -0.95)
                           .time(time.time_ns(), WritePrecision.NS))
                write_api.write(bucket=INFLUX_BUCKET, record=d_point)

                # ── Write to attack_status for the Grafana stat panel (id=10)
                s_point = (Point("attack_status")
                           .tag("attack_type", "REPLAY")
                           .tag("session_id", SESSION_ID)
                           .field("status", "DETECTED")
                           .time(time.time_ns(), WritePrecision.NS))
                write_api.write(bucket=INFLUX_BUCKET, record=s_point)

                # ── Also mark in security_metrics
                m_point = (Point("security_metrics")
                           .tag("sensor",     "ml_engine")
                           .tag("session_id", SESSION_ID)
                           .field("anomaly_score", -0.95)
                           .field("is_anomaly",    1)
                           .time(time.time_ns(), WritePrecision.NS))
                write_api.write(bucket=INFLUX_BUCKET, record=m_point)

                alerts.append({"type": "REPLAY_ATTACK", "detail": detail})
    except Exception as e:
        print(f"Replay detection error: {e}")
    return alerts


# ── Forced-write check ────────────────────────────────────────────────────────
def check_forced_writes() -> list[dict]:
    """Return any forced sensor-register writes from the last 60 s."""
    if in_grace_period():
        return []  # Suppressed during grace period

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
                val = float(row.get('value', 0))
                reg = int(row.get('register', -1))
                detail = f"Direct write to sensor reg {reg} value={val:.0f}"
                alerts.append({"type": "SEMANTIC_INJECTION", "detail": detail})
                print(f"!!! SEMANTIC INJECTION DETECTED !!! Reg={reg} Val={val:.0f}")
                _record_alert("SEMANTIC_INJECTION", detail, -1.0)
    except Exception as e:
        print(f"forced_writes query error: {e}")
    return alerts


# ── DNP3 Probe Check ────────────────────────────────────────────────────────
def check_dnp3_probes() -> list[dict]:
    """Return any DNP3 probes logged in the last 60 s."""
    if in_grace_period():
        return []

    query = f'''
from(bucket: "{INFLUX_BUCKET}")
  |> range(start: -60s)
  |> filter(fn: (r) => r["_measurement"] == "honeypot_events" and r["protocol"] == "DNP3")
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
                ip = row.get('remote_ip', 'unknown')
                detail = f"DNP3 Probe Detected from IP={ip}"
                alerts.append({"type": "DNP3_PROBE", "detail": detail})
                print(f"!!! DNP3 PROBE DETECTED !!! IP={ip}")
                _record_alert("DNP3_PROBE", detail, -0.9)
    except Exception as e:
        print(f"DNP3 probe query error: {e}")
    return alerts


# ── API Server (FastAPI, runs in a background thread) ─────────────────────────
def _start_api_server():
    """Start the FastAPI REST server on port 8000 in a daemon thread."""
    try:
        from fastapi import FastAPI, Query
        from fastapi.middleware.cors import CORSMiddleware
        import uvicorn

        app = FastAPI(
            title="ICS Honeypot ML Engine API",
            description="Alert and metrics endpoint for Purdue Level 3 integration",
            version="2.0.0"
        )

        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_methods=["*"],
            allow_headers=["*"],
        )

        @app.get("/health")
        def health():
            with _api_lock:
                return {
                    "status":      "ok",
                    "session_id":  SESSION_ID,
                    "model_ready": _api_state["model_ready"],
                    "in_warmup":   _api_state["in_warmup"],
                    "in_grace":    _api_state["in_grace"],
                    "sample_count": _api_state["sample_count"],
                    "uptime_seconds": round(time.time() - _boot_time, 1),
                }

        @app.get("/alerts")
        def get_alerts(
            limit: int = Query(default=50, le=100, description="Max alerts to return"),
            alert_type: str = Query(default=None, description="Filter by alert_type")
        ):
            with _api_lock:
                alerts = list(_api_state["recent_alerts"])
            if alert_type:
                alerts = [a for a in alerts if a["alert_type"] == alert_type]
            alerts = alerts[-limit:][::-1]   # newest first
            return {"count": len(alerts), "alerts": alerts}

        @app.get("/metrics")
        def get_metrics():
            with _api_lock:
                return {
                    "last_anomaly_score": _api_state["last_score"],
                    "ewma_pressure":     _api_state["ewma"],
                    "cusum_pos":         _api_state["cusum_pos"],
                    "cusum_neg":         _api_state["cusum_neg"],
                    "last_anomaly":      _api_state["last_anomaly"],
                    "total_alerts":      len(_api_state["recent_alerts"]),
                }

        @app.post("/reset-model")
        def reset_model():
            """Force model retrain by deleting model and training marker."""
            for f in [MODEL_FILE, TRAINING_START_FILE]:
                if os.path.exists(f):
                    os.remove(f)
            with _api_lock:
                _api_state["model_ready"] = False
                _api_state["in_warmup"]   = True
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

# Give the API a moment to start before the main loop
time.sleep(2)


# ── Entry point ────────────────────────────────────────────────────────────────
print(f"[ML] Entering main detection loop. Grace period ends in {STARTUP_GRACE_SECONDS}s.")
while True:
    try:
        # 1. Semantic injection check (suppressed during grace period)
        fw_alerts = check_forced_writes()
        for alert in fw_alerts:
            a_point = (Point("security_alerts")
                       .tag("alert_type", alert["type"])
                       .tag("session_id", SESSION_ID)
                       .field("detail",   alert["detail"])
                       .field("score",    -1.0)
                       .time(time.time_ns(), WritePrecision.NS))
            write_api.write(bucket=INFLUX_BUCKET, record=a_point)
            m_point = (Point("security_metrics")
                       .tag("sensor",     "ml_engine")
                       .tag("session_id", SESSION_ID)
                       .field("anomaly_score", -1.0)
                       .field("is_anomaly",    1)
                       .time(time.time_ns(), WritePrecision.NS))
            write_api.write(bucket=INFLUX_BUCKET, record=m_point)

        # 1B. DNP3 probe check (suppressed during grace period)
        d_alerts = check_dnp3_probes()
        for alert in d_alerts:
            a_point = (Point("security_alerts")
                       .tag("alert_type", alert["type"])
                       .tag("session_id", SESSION_ID)
                       .field("detail",   alert["detail"])
                       .field("score",    -0.9)
                       .time(time.time_ns(), WritePrecision.NS))
            write_api.write(bucket=INFLUX_BUCKET, record=a_point)
            m_point = (Point("security_metrics")
                       .tag("sensor",     "ml_engine")
                       .tag("session_id", SESSION_ID)
                       .field("anomaly_score", -0.9)
                       .field("is_anomaly",    1)
                       .time(time.time_ns(), WritePrecision.NS))
            write_api.write(bucket=INFLUX_BUCKET, record=m_point)

        # 1C. Replay attack detection (frozen telemetry injected into InfluxDB)
        check_replay_attack()

        # 2. EWMA/CUSUM stealth drift detection (suppressed during grace period)
        run_drift_cycle()

        # 3. Isolation Forest ML cycle (suppressed during grace + warm-up)
        run_ml_cycle()

        # 4. Inform Grafana that we are in Training Mode
        with _api_lock:
            warmup = _api_state.get("in_warmup", True)
        if in_grace_period() or warmup:
            m_point = (Point("security_metrics")
                       .tag("sensor",     "ml_engine")
                       .tag("session_id", SESSION_ID)
                       .field("anomaly_score", 0.0)
                       .field("is_anomaly",    2)
                       .time(time.time_ns(), WritePrecision.NS))
            write_api.write(bucket=INFLUX_BUCKET, record=m_point)

    except Exception as e:
        print(f"ML loop error: {e}")

    time.sleep(LOOP_INTERVAL)