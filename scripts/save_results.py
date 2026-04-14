#!/usr/bin/env python3
"""
Thesis Results Saver  (scripts/save_results.py)
================================================
Run this ANY TIME while the Docker stack is running to snapshot all results.

What it produces inside  results/TIMESTAMP/ :
  csv/   - one CSV per InfluxDB measurement
  logs/  - last 500 lines of each container log
  summary.txt - per-attack detection counts + Grafana PNG curl commands

NO EXTERNAL DEPS: uses only Python stdlib (urllib, csv, json, subprocess).
"""

import os, subprocess, datetime, json, urllib.request, csv, io

# ── Config ────────────────────────────────────────────────────────────────────
INFLUX_URL    = os.environ.get("INFLUX_URL",    "http://localhost:8086")
INFLUX_TOKEN  = os.environ.get("INFLUX_TOKEN",  "supersecrettoken")
INFLUX_ORG    = os.environ.get("INFLUX_ORG",    "my_refinery")
INFLUX_BUCKET = os.environ.get("INFLUX_BUCKET", "sensor_logs")
LOOKBACK      = os.environ.get("LOOKBACK",      "-6h")

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
TS          = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
OUT_DIR     = os.path.join(PROJECT_DIR, "results", TS)
CSV_DIR     = os.path.join(OUT_DIR, "csv")
LOG_DIR     = os.path.join(OUT_DIR, "logs")
for d in [CSV_DIR, LOG_DIR]:
    os.makedirs(d, exist_ok=True)

MEASUREMENTS = [
    "pipeline_metrics", "security_metrics", "security_alerts",
    "modbus_events", "honeypot_events", "auth_attempts",
    "forced_writes", "correlation_logs", "process_state", "attack_status",
]
ATTACKS = {
    "SEMANTIC_INJECTION":  "Phase 4 — Semantic Injection",
    "STEALTH_DRIFT_EWMA":  "Phase 5 — Stealth Drift (EWMA/CUSUM)",
    "STEALTH_DRIFT":       "Phase 5 — Stealth Drift (Expert Rule)",
    "CROSS_LAYER_ANOMALY": "Phase 5 — Cross-Layer Anomaly",
    "DNP3_PROBE":          "Phase 1/3 — DNP3 Protocol Probe",
    "REPLAY_ATTACK":       "Phase 8 — Replay Attack",
    "ISOLATION_FOREST":    "ML Engine — IsolationForest Anomaly",
    "OVER_PRESSURE":       "Expert Rule — Over Pressure",
}
CONTAINERS = [
    "ics_ml_engine", "plc_simulator", "ics_dnp3", "ics_sniffer",
    "ics_correlator", "attacker_node", "honeypot_historian_api",
    "ics_historian_api", "ics_scada_ssh", "fake_plc_sim",
]
PANELS = {
    "Pipeline_Pressure": 1, "ML_Anomaly_Status": 5, "ML_Anomaly_Score": 6,
    "Replay_Delta": 8, "Semantic_Injection": 9, "Replay_Status": 10,
    "DNP3_Probe": 11, "S7comm_Probe": 12, "Recon_Scan": 14, "EWMA_CUSUM_Drift": 15,
}

# ── InfluxDB HTTP helper ───────────────────────────────────────────────────────
def _influx_query(flux: str) -> str:
    """POST Flux query, return annotated CSV text. Raises on HTTP error."""
    req = urllib.request.Request(
        f"{INFLUX_URL}/api/v2/query?org={INFLUX_ORG}",
        data=json.dumps({
            "query": flux,
            "dialect": {
                "header": True,
                "annotations": [],          # NO annotation lines → clean CSV
                "delimiter": ","
            }
        }).encode(),
        headers={
            "Authorization": f"Token {INFLUX_TOKEN}",
            "Content-Type":  "application/json",
            "Accept":        "text/csv",
        }
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8")

# ── CSV export ────────────────────────────────────────────────────────────────
def export_csv() -> dict:
    print(f"\n── CSV Export (lookback={LOOKBACK}) ─────────────────────────────────")
    counts = {}
    for meas in MEASUREMENTS:
        # Simple non-pivot query: each row is one field value.
        # We use keep() to get predictable columns without pivot schema issues.
        q = (
            f'from(bucket: "{INFLUX_BUCKET}")\n'
            f'  |> range(start: {LOOKBACK})\n'
            f'  |> filter(fn: (r) => r["_measurement"] == "{meas}")\n'
            f'  |> keep(columns: ["_time","_measurement","_field","_value"])\n'
            f'  |> sort(columns: ["_time"])'
        )
        try:
            raw = _influx_query(q)
        except Exception as e:
            print(f"  [ERR]  {meas}: {e}")
            counts[meas] = -1
            continue

        # Parse: CSV lines (CRLF or LF), skip blank separator lines and header dupes
        rows = []
        seen_header = False
        header = None
        for line in raw.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
            line = line.strip()
            if not line:
                continue
            parts = line.split(",")
            # InfluxDB annotated-CSV with annotations=[] still emits a leading comma
            # Data rows: ,_result,0,<time>,<val>,...  or header: ,result,table,_time,...
            if parts[0] == "" and len(parts) > 3:
                if parts[1] in ("result", "_result"):
                    if parts[1] == "result":
                        # This is a header row
                        if not seen_header:
                            header = parts[2:]   # skip leading , result
                            seen_header = True
                        # else skip repeated header between tables
                    else:
                        # This is a data row
                        rows.append(parts[2:])   # skip leading , _result

        if not rows:
            print(f"  [EMPTY] {meas}")
            counts[meas] = 0
            continue

        out_path = os.path.join(CSV_DIR, f"{meas}.csv")
        with open(out_path, "w", newline="") as f:
            w = csv.writer(f)
            if header:
                w.writerow(header)
            w.writerows(rows)

        print(f"  [OK]  {meas:<30} {len(rows):>5} rows  →  {os.path.basename(out_path)}")
        counts[meas] = len(rows)

    return counts

# ── Docker log export ─────────────────────────────────────────────────────────
def export_logs():
    print("\n── Docker Logs ──────────────────────────────────────────────────────")
    for ctr in CONTAINERS:
        path = os.path.join(LOG_DIR, f"{ctr}.log")
        try:
            r = subprocess.run(["docker", "logs", "--tail", "500", ctr],
                               capture_output=True, text=True, timeout=12)
            content = r.stdout + r.stderr
            with open(path, "w") as f:
                f.write(content)
            print(f"  [OK]  {ctr:<30} {content.count(chr(10)):>5} lines")
        except FileNotFoundError:
            print("  [SKIP] docker not found in PATH")
            return
        except Exception as e:
            print(f"  [WARN] {ctr}: {e}")

# ── Alert counts ──────────────────────────────────────────────────────────────
def get_alert_counts() -> dict:
    counts = {}
    for at in ATTACKS:
        q = (
            f'from(bucket: "{INFLUX_BUCKET}")\n'
            f'  |> range(start: {LOOKBACK})\n'
            f'  |> filter(fn: (r) => r["_measurement"] == "security_alerts"\n'
            f'                   and r["alert_type"] == "{at}"\n'
            f'                   and r["_field"] == "score")\n'
            f'  |> count()'
        )
        try:
            raw = _influx_query(q)
            total = 0
            for line in raw.replace("\r\n", "\n").split("\n"):
                line = line.strip()
                if line and line.startswith(",_result"):
                    parts = line.split(",")
                    try:
                        total += int(parts[-1])
                    except (ValueError, IndexError):
                        pass
            counts[at] = total
        except Exception:
            counts[at] = "?"
    return counts

# ── Summary ───────────────────────────────────────────────────────────────────
def build_summary(csv_counts: dict, ac: dict) -> str:
    sep = "=" * 65
    lines = [
        sep,
        "  ICS HONEYPOT — THESIS RESULTS SNAPSHOT",
        f"  Timestamp : {TS}",
        f"  Lookback  : {LOOKBACK}",
        f"  InfluxDB  : {INFLUX_URL}",
        sep, "",
        "── Per-Attack Detection Counts ─────────────────────────────────",
    ]
    for at, label in ATTACKS.items():
        cnt = ac.get(at, "?")
        flag = cnt if isinstance(cnt, str) else ("YES" if cnt > 0 else "NO")
        lines.append(f"  {label:<45}  {str(cnt):>4} alerts  [{flag}]")

    lines += ["", "── CSV Rows Exported ───────────────────────────────────────────"]
    for meas, cnt in csv_counts.items():
        lines.append(f"  {meas:<35} {cnt:>6} rows")

    lines += ["", "── Grafana PNG Screenshots (run from project root) ─────────────",
              "  # Requires grafana_renderer container (already in docker-compose.yml)", ""]
    for name, pid in PANELS.items():
        url = (f"http://localhost:3000/render/d-solo/ics-honeypot-full/ics-honeypot"
               f"?orgId=1&panelId={pid}&from=now-4h&to=now&width=1200&height=500&theme=dark")
        lines.append(f"  # {name}")
        lines.append(f"  curl -s -u admin:admin '{url}' -o results/{TS}/{name}.png")
        lines.append("")

    lines.append(sep)
    return "\n".join(lines)

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print("\n╔══════════════════════════════════════════════════════════════╗")
    print("║   ICS Honeypot — Thesis Results Saver                       ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(f"  Output: results/{TS}/")

    csv_counts = export_csv()
    export_logs()

    print("\n── Alert Counts ─────────────────────────────────────────────────")
    ac = get_alert_counts()
    for at, cnt in ac.items():
        print(f"  {ATTACKS[at]:<45}  {cnt}")

    summary = build_summary(csv_counts, ac)
    spath = os.path.join(OUT_DIR, "summary.txt")
    with open(spath, "w") as f:
        f.write(summary)

    print("\n" + summary)
    print(f"\n[SAVED]  results/{TS}/\n")

if __name__ == "__main__":
    main()
