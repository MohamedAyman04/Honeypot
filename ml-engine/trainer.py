import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import time
import os
import json
import numpy as np
import datetime
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

# --- CONFIGURATION ---
LOG_FILE = "/data/network_logs.json"
MODEL_FILE = "/data/model.pkl"
TRAINING_THRESHOLD = 500  # Obsolete, using time-based
WARMUP_PERIOD = 300  # seconds
TRAINING_START_FILE = "/data/training_start.txt"
PYTHONUNBUFFERED = 1

# InfluxDB Config (Matching your docker-compose)
INFLUX_URL = "http://ics_historian:8086"
INFLUX_TOKEN = "supersecrettoken"
INFLUX_ORG = "my_refinery"
INFLUX_BUCKET = "sensor_logs"

print("--- ML ENGINE STARTING UP ---")

# Initialize InfluxDB Client
db_client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
write_api = db_client.write_api(write_options=SYNCHRONOUS)

def extract_features(df):
    """Helper to turn raw hex data into ML features"""
    if "func_code" not in df.columns and "data" in df.columns:
        def get_fc(hex_str):
            # Modbus TCP: Function code is usually at byte 7 (index 14:16 in hex)
            if isinstance(hex_str, str) and len(hex_str) >= 16:
                return int(hex_str[14:16], 16)
            return 0
        df["func_code"] = df["data"].apply(get_fc)
    
    if "is_write" not in df.columns and "func_code" in df.columns:
        df["is_write"] = df["func_code"].apply(lambda x: 1 if x in [5, 6, 15, 16] else 0)
        
    if "length" not in df.columns:
        df["length"] = 0
        
    if "timestamp" in df.columns:
        df["ts_datetime"] = pd.to_datetime(df["timestamp"], unit="s")
        df = df.sort_values("ts_datetime")
        df["inter_arrival_time"] = df["ts_datetime"].diff().dt.total_seconds().fillna(0)
        
        temp_df = df.set_index("ts_datetime")
        temp_df["write_freq_10s"] = temp_df["is_write"].rolling("10s").sum().fillna(0)
        df["write_freq_10s"] = temp_df["write_freq_10s"].values
    else:
        df["inter_arrival_time"] = 0.0
        df["write_freq_10s"] = 0.0

    df["pressure"] = 0.0
    df["pressure_delta"] = 0.0
    df["pressure_mean_dev"] = 0.0

    query_api = db_client.query_api()
    query = f'''from(bucket: "{INFLUX_BUCKET}") |> range(start: -2h) |> filter(fn: (r) => r["_measurement"] == "pipeline_metrics" and r["_field"] == "pressure")'''
    
    try:
        pdf_res = query_api.query_data_frame(query)
        if isinstance(pdf_res, list):
            if len(pdf_res) == 0:
                pdf_res = None
            else:
                pdf_res = pd.concat(pdf_res)
                
        if pdf_res is not None and not pdf_res.empty:
            pdf = pdf_res[['_time', '_value']].copy()
            pdf['_time'] = pd.to_datetime(pdf['_time']).dt.tz_localize(None)
            pdf = pdf.sort_values('_time')
            pdf['pressure_delta'] = pdf['_value'].diff().fillna(0)
            pdf['pressure_rolling_mean'] = pdf['_value'].rolling(window=10, min_periods=1).mean()
            pdf['pressure_mean_dev'] = pdf['_value'] - pdf['pressure_rolling_mean']
            
            if "ts_datetime" in df.columns:
                df = pd.merge_asof(df, pdf, left_on="ts_datetime", right_on="_time", direction="backward")
                df["pressure"] = df["_value"]
    except Exception as e:
        print(f"Error querying InfluxDB: {e}")

    df = df.fillna({"pressure": 0.0, "pressure_delta": 0.0, "pressure_mean_dev": 0.0, "inter_arrival_time": 0.0, "write_freq_10s": 0.0})
    return df[["length", "func_code", "is_write", "inter_arrival_time", "write_freq_10s", "pressure", "pressure_delta", "pressure_mean_dev"]]

def run_ml_logic():
    if not os.path.exists(LOG_FILE):
        print("Waiting for log file...")
        return

    # 1. Load Data
    raw_data = []
    with open(LOG_FILE, "r") as f:
        for line in f:
            raw_data.append(json.loads(line))
    
    df = pd.DataFrame(raw_data)
    if len(df) < 50:
        print(f"Collecting initial samples... ({len(df)}/50)")
        return

    features = extract_features(df)

    # --- TRAINING HARDENING & DETECTION ---
    if not os.path.exists(TRAINING_START_FILE):
        with open(TRAINING_START_FILE, "w") as f:
            f.write(str(time.time()))
    
    with open(TRAINING_START_FILE, "r") as f:
        start_time = float(f.read().strip())
        
    is_warmup = (time.time() - start_time) < WARMUP_PERIOD
    
    if is_warmup:
        print(f"Training Mode: Warmup phase. {(WARMUP_PERIOD - (time.time() - start_time)):.0f}s remaining.")
        model = IsolationForest(contamination=0.01, random_state=42)
        model.fit(features)
        joblib.dump(model, MODEL_FILE)
    else:
        if not os.path.exists(MODEL_FILE):
            print("Error: Warmup period ended but model missing. Switching to baseline.")
            model = IsolationForest(contamination=0.01, random_state=42)
            model.fit(features)
            joblib.dump(model, MODEL_FILE)
        else:
            model = joblib.load(MODEL_FILE)

        # Predict on the most recent packets (last 5)
        latest_features = features.tail(5)
        predictions = model.predict(latest_features)
        scores = model.decision_function(latest_features)

        for i in range(len(predictions)):
            is_anomaly = 1 if predictions[i] == -1 else 0
            score_val = float(scores[i])
            
            # Cross-Layer Correlation & Stealth Attack Explicit Rules
            row = latest_features.iloc[i]
            if abs(row["pressure_delta"]) > 5.0 and row["write_freq_10s"] == 0:
                print(f"!!! CROSS-LAYER ANOMALY !!! Pressure delta {row['pressure_delta']:.2f} but no writes!")
                is_anomaly = 1
                score_val = -1.0
                
            if abs(row["pressure_mean_dev"]) > 20.0:
                print(f"!!! STEALTH ATTACK (DRIFT) DETECTED !!! Mean deviation: {row['pressure_mean_dev']:.2f}")
                is_anomaly = 1
                score_val = -1.0

            if is_anomaly:
                print(f"!!! ML ANOMALY DETECTED !!! Score: {score_val}")

            point = Point("security_metrics") \
                .tag("sensor", "network_monitor") \
                .field("anomaly_score", score_val) \
                .field("is_anomaly", is_anomaly) \
                .time(time.time_ns(), WritePrecision.NS)
            
            write_api.write(bucket=INFLUX_BUCKET, record=point)

while True:
    try:
        run_ml_logic()
    except Exception as e:
        print(f"Error in ML Loop: {e}")
    time.sleep(10) # Check for new packets every 10 seconds