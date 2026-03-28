"""
Honeypot Evaluation Engine
=========================
Calculates performance metrics as defined in thesis section 4.6.2:
- True Positive Rate (TPR)
- False Positive Rate (FPR)
- Detection Latency (Time-to-Detect)
- Attacker Dwell Time
- Cross-Layer Correlation Accuracy

Connects to InfluxDB, pulls session data, and produces a summary report.
"""
import pandas as pd
import numpy as np
from influxdb_client import InfluxDBClient
import os
import datetime

# --- Config ---
INFLUX_URL    = os.environ.get("INFLUX_URL",    "http://localhost:8086")
INFLUX_TOKEN  = os.environ.get("INFLUX_TOKEN",  "supersecrettoken")
INFLUX_ORG    = os.environ.get("INFLUX_ORG",    "my_refinery")
INFLUX_BUCKET = os.environ.get("INFLUX_BUCKET", "sensor_logs")

def get_data(query):
    client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
    query_api = client.query_api()
    try:
        df = query_api.query_data_frame(query)
        if isinstance(df, list):
            df = pd.concat(df) if df else pd.DataFrame()
        return df
    except Exception as e:
        print(f"Error querying InfluxDB: {e}")
        return pd.DataFrame()

def calculate_metrics():
    print("\n" + "="*60)
    print("ICS HONEYPOT EVALUATION REPORT")
    print("="*60)

    # 1. Load actual attacks (ground truth)
    attack_query = f'from(bucket:"{INFLUX_BUCKET}") |> range(start: -24h) |> filter(fn: (r) => r["_measurement"] == "attack_results")'
    attacks_df = get_data(attack_query)

    # 2. Load detections
    alert_query = f'from(bucket:"{INFLUX_BUCKET}") |> range(start: -24h) |> filter(fn: (r) => r["_measurement"] == "security_alerts")'
    alerts_df = get_data(alert_query)

    # 3. Load all security metrics (for FPR/stats)
    metrics_query = f'from(bucket:"{INFLUX_BUCKET}") |> range(start: -24h) |> filter(fn: (r) => r["_measurement"] == "security_metrics")'
    metrics_df = get_data(metrics_query)

    # 4. Load correlation logs (for accuracy)
    corr_query = f'from(bucket:"{INFLUX_BUCKET}") |> range(start: -24h) |> filter(fn: (r) => r["_measurement"] == "correlation_logs")'
    corr_df = get_data(corr_query)

    if attacks_df.empty:
        print("No attack simulations found in the last 24h. Run attack_simulation.py first.")
        return

    # --- Processing ---
    # Pivot for easier access
    attacks = attacks_df.pivot(index='_time', columns='attack_type', values='_value') if not attacks_df.empty else pd.DataFrame()
    
    # We'll treat every attack_type entry as a "Positive" instance
    total_attacks = len(attacks_df[attacks_df['_field'] == 'success'])
    
    # Simple TPR check: Did an alert happen within 30s of each attack success record?
    detections = 0
    latencies = []
    
    # Unique attack instances
    attack_events = attacks_df[attacks_df['_field'] == 'success'].sort_values('_time')
    
    for _, attack in attack_events.iterrows():
        a_time = attack['_time']
        a_type = attack['attack_type']
        
        # Reconnaissance Only shouldn't trigger an alert (as per §4.6.1 point 4)
        is_recon = (a_type == "reconnaissance_only")

        # Find first alert after attack start (within 60s)
        recent_alerts = alerts_df[
            (alerts_df['_time'] >= a_time) & 
            (alerts_df['_time'] <= a_time + pd.Timedelta(seconds=60))
        ]
        
        if is_recon:
            if recent_alerts.empty:
                # Correctly ignored recon
                pass
            else:
                # FPR case: flagged recon as attack
                pass
        else:
            if not recent_alerts.empty:
                detections += 1
                latency = (recent_alerts['_time'].min() - a_time).total_seconds()
                latencies.append(latency)

    # FPR: Check metrics when no attack is active
    # (Simplified: total anomalies / total samples)
    if not metrics_df.empty:
        anomalies = metrics_df[(metrics_df['_field'] == 'is_anomaly') & (metrics_df['_value'] == 1)]
        total_samples = len(metrics_df[metrics_df['_field'] == 'is_anomaly'])
        fpr = (len(anomalies) / total_samples) * 100 if total_samples > 0 else 0
    else:
        fpr = 0

    # Cross-Layer Accuracy: Check correlation logs
    # Every write should have a phys_pressure entry
    if not corr_df.empty:
        valid_corr = corr_df[corr_df['_field'] == 'phys_pressure'].dropna()
        total_corr = len(corr_df[corr_df['_field'] == 'func_code'])
        corr_acc = (len(valid_corr) / total_corr) * 100 if total_corr > 0 else 100
    else:
        corr_acc = 100

    # Dwell Time: time between first and last attack event in the log
    if not attacks_df.empty:
        dwell_time = (attacks_df['_time'].max() - attacks_df['_time'].min()).total_seconds()
    else:
        dwell_time = 0

    # Results
    tpr = (detections / (total_attacks - (1 if any(attacks_df['attack_type'] == 'reconnaissance_only') else 0))) * 100
    avg_latency = np.mean(latencies) if latencies else 0

    print(f"1. True Positive Rate (TPR):      {tpr:.1f}%")
    print(f"2. False Positive Rate (FPR):     {fpr:.2f}%")
    print(f"3. Detection Latency (Avg):       {avg_latency:.2f} s")
    print(f"4. Attacker Dwell Time:           {dwell_time:.1f} s")
    print(f"5. Cross-Layer Link Accuracy:     {corr_acc:.1f}%")
    print("-" * 60)
    
    # Save to CSV
    results_summary = pd.DataFrame([{
        "Metric": "TPR", "Value": f"{tpr:.2f}%"},
        {"Metric": "FPR", "Value": f"{fpr:.2f}%"},
        {"Metric": "Avg Latency", "Value": f"{avg_latency:.2f}s"},
        {"Metric": "Dwell Time", "Value": f"{dwell_time:.1f}s"},
        {"Metric": "Correlation Accuracy", "Value": f"{corr_acc:.2f}%"}
    ])
    results_summary.to_csv('thesis_evaluation_summary.csv', index=False)
    print("Summary saved to: thesis_evaluation_summary.csv")

if __name__ == "__main__":
    calculate_metrics()