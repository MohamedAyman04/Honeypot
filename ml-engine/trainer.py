"""
ML Engine / Trainer
====================
Reads pipeline telemetry from InfluxDB (no log file dependency),
trains an IsolationForest during warm-up, then runs anomaly detection
and writes results back to InfluxDB.

Also queries `forced_writes` (logged by modbus_server when a client writes
directly to a sensor register) to detect semantic injection attacks.
"""

import time
import os
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

# ── Configuration ──────────────────────────────────────────────────────────────
INFLUX_URL   = os.environ.get("INFLUX_URL",   "http://ics_historian:8086")
INFLUX_TOKEN = os.environ.get("INFLUX_TOKEN", "supersecrettoken")
INFLUX_ORG   = os.environ.get("INFLUX_ORG",  "my_refinery")
INFLUX_BUCKET = os.environ.get("INFLUX_BUCKET", "sensor_logs")

MODEL_FILE           = "/data/model.pkl"
TRAINING_START_FILE  = "/data/training_start.txt"
WARMUP_PERIOD        = 180   # seconds of training before locking the model
MIN_SAMPLES          = 30    # minimum InfluxDB rows before we bother training
LOOP_INTERVAL        = 10    # seconds between ML cycles

print("--- ML ENGINE STARTING ---")

db_client  = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
write_api  = db_client.write_api(write_options=SYNCHRONOUS)
query_api  = db_client.query_api()

# ── Feature extraction ─────────────────────────────────────────────────────────
def fetch_pipeline_features(lookback: str = "-1h") -> pd.DataFrame:
    """
    Pull the last <lookback> of pipeline_metrics from InfluxDB and
    compute ML features.  Returns an empty DataFrame if nothing found.
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

    # Ensure expected columns exist
    for col in ["pressure", "flow_rate", "temperature", "pump_rpm"]:
        if col not in result.columns:
            result[col] = 0.0

    result["_time"] = pd.to_datetime(result["_time"]).dt.tz_localize(None)
    result = result.sort_values("_time").reset_index(drop=True)

    # Time-domain features
    result["inter_arrival_time"] = (
        result["_time"].diff().dt.total_seconds().fillna(0)
    )

    # Physical-layer features
    result["pressure_delta"] = result["pressure"].diff().fillna(0)
    result["pressure_rolling_mean"] = result["pressure"].rolling(10, min_periods=1).mean()
    result["pressure_mean_dev"]     = result["pressure"] - result["pressure_rolling_mean"]

    # Network-layer features (from correlator, joined best-effort)
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
            net["func_code"] = 6   # FC6 = Write Single Register
            net["length"]    = net.get("value", pd.Series([0]*len(net))).astype(int)

            # rolling write frequency (10 s window)
            net_idx = net.set_index("_time")
            net_idx["write_freq_10s"] = net_idx["is_write"].rolling("10s").sum().fillna(0)
            net["write_freq_10s"] = net_idx["write_freq_10s"].values

            result = pd.merge_asof(
                result, net[["_time", "is_write", "func_code", "length", "write_freq_10s"]],
                on="_time", direction="backward"
            )
            # merge_asof overwrites with _y columns when names clash
            for col in ["is_write", "func_code", "length", "write_freq_10s"]:
                new_col = col + "_y"
                if new_col in result.columns:
                    result[col] = result[new_col].fillna(result[col + "_x"] if col + "_x" in result.columns else 0)
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


# ── Detection rules (explicit, on top of ML) ──────────────────────────────────
def apply_expert_rules(features: pd.DataFrame) -> list[dict]:
    alerts = []
    if features.empty:
        return alerts

    row = features.iloc[-1]

    # Cross-layer: big pressure jump but no write commands
    if abs(row["pressure_delta"]) > 5.0 and row["write_freq_10s"] == 0:
        alerts.append({
            "type": "CROSS_LAYER_ANOMALY",
            "detail": f"pressure_delta={row['pressure_delta']:.2f} with no writes"
        })

    # Stealth drift: sustained deviation from rolling mean
    if abs(row["pressure_mean_dev"]) > 15.0:
        alerts.append({
            "type": "STEALTH_DRIFT",
            "detail": f"pressure_mean_dev={row['pressure_mean_dev']:.2f}"
        })

    # Pressure injected to an extreme value (semantic injection)
    if row["pressure"] > 200.0:
        alerts.append({
            "type": "SEMANTIC_INJECTION",
            "detail": f"pressure={row['pressure']:.1f} PSI (above safety threshold)"
        })

    return alerts


# ── Main ML loop ────────────────────────────────────────────────────────────────
def run_ml_cycle():
    features = fetch_pipeline_features(lookback="-2h")

    if len(features) < MIN_SAMPLES:
        print(f"Collecting samples... ({len(features)}/{MIN_SAMPLES})")
        return

    # ── Warm-up / training phase ───────────────────────────────────────────────
    if not os.path.exists(TRAINING_START_FILE):
        with open(TRAINING_START_FILE, "w") as f:
            f.write(str(time.time()))
        print("Warm-up phase started.")

    with open(TRAINING_START_FILE) as f:
        start_time = float(f.read().strip())

    in_warmup = (time.time() - start_time) < WARMUP_PERIOD

    if in_warmup:
        remaining = WARMUP_PERIOD - (time.time() - start_time)
        print(f"Training Mode: {remaining:.0f}s remaining in warm-up.")
        model = IsolationForest(contamination=0.05, random_state=42, n_estimators=100)
        model.fit(features)
        joblib.dump(model, MODEL_FILE)
        return   # Don't run detection during warm-up

    # ── Detection phase ────────────────────────────────────────────────────────
    if not os.path.exists(MODEL_FILE):
        print("Warm-up ended but model missing – training now.")
        model = IsolationForest(contamination=0.05, random_state=42, n_estimators=100)
        model.fit(features)
        joblib.dump(model, MODEL_FILE)

    model = joblib.load(MODEL_FILE)

    # Score the most recent 5 samples
    recent = features.tail(5)
    predictions = model.predict(recent)
    scores      = model.decision_function(recent)

    for i, (pred, score) in enumerate(zip(predictions, scores)):
        is_anomaly = 1 if pred == -1 else 0
        score_val  = float(score)

        # Expert rules override
        expert_alerts = apply_expert_rules(recent.iloc[[i]])
        for alert in expert_alerts:
            print(f"!!! {alert['type']} !!! {alert['detail']}")
            is_anomaly = 1
            score_val  = min(score_val, -0.5)   # push score negative

            # Write named alert to InfluxDB
            a_point = (Point("security_alerts")
                       .tag("alert_type", alert["type"])
                       .field("detail",     alert["detail"])
                       .field("score",      score_val)
                       .time(time.time_ns(), WritePrecision.NS))
            write_api.write(bucket=INFLUX_BUCKET, record=a_point)

        if is_anomaly:
            print(f"!!! ML ANOMALY DETECTED !!! score={score_val:.4f}")

        # Write ML result to InfluxDB (for Grafana + hmi_simulator alarm)
        point = (Point("security_metrics")
                 .tag("sensor", "ml_engine")
                 .field("anomaly_score", score_val)
                 .field("is_anomaly",    is_anomaly)
                 .time(time.time_ns(), WritePrecision.NS))
        write_api.write(bucket=INFLUX_BUCKET, record=point)

    print(f"ML cycle complete: {len(recent)} samples scored, "
          f"anomalies={sum(1 for p in predictions if p == -1)}")


# ── Check forced_writes (semantic injection via direct register write) ──────────
def check_forced_writes() -> list[dict]:
    """Return any forced sensor-register writes from the last 60 s."""
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
                alerts.append({
                    "type":   "SEMANTIC_INJECTION",
                    "detail": f"Direct write to sensor reg {reg} value={val:.0f}"
                })
                print(f"!!! SEMANTIC INJECTION DETECTED !!! Reg={reg} Val={val:.0f}")
    except Exception as e:
        print(f"forced_writes query error: {e}")
    return alerts


# ── Entry point ─────────────────────────────────────────────────────────────────
while True:
    try:
        # Check forced writes first (immediate detection, independent of warm-up)
        fw_alerts = check_forced_writes()
        for alert in fw_alerts:
            a_point = (Point("security_alerts")
                       .tag("alert_type", alert["type"])
                       .field("detail",   alert["detail"])
                       .field("score",    -1.0)
                       .time(time.time_ns(), WritePrecision.NS))
            write_api.write(bucket=INFLUX_BUCKET, record=a_point)
            # Also set is_anomaly=1 in security_metrics so Grafana turns red
            m_point = (Point("security_metrics")
                       .tag("sensor", "ml_engine")
                       .field("anomaly_score", -1.0)
                       .field("is_anomaly",    1)
                       .time(time.time_ns(), WritePrecision.NS))
            write_api.write(bucket=INFLUX_BUCKET, record=m_point)

        run_ml_cycle()
    except Exception as e:
        print(f"ML loop error: {e}")
    time.sleep(LOOP_INTERVAL)