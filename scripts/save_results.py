#!/usr/bin/env python3
"""
Thesis Results Saver  (scripts/save_results.py)
================================================
Run this ANY TIME while the Docker stack is running to snapshot all results
that belong in the thesis Results / Evaluation chapter.

What it produces inside  results/TIMESTAMP/ :
  csv/   - one CSV per InfluxDB measurement (pipeline, alerts, events …)
  logs/  - last 500 lines of each container log
  summary.txt - per-attack detection counts + Grafana screenshot commands

Usage:
    python3 scripts/save_results.py            # uses env vars or defaults
    INFLUX_URL=http://localhost:8086 python3 scripts/save_results.py
"""

import os, sys, subprocess, datetime, json

# ── Required deps (telemetry CSV export is mandatory) ─────────────────────────
try:
    from influxdb_client import InfluxDBClient
    HAS_INFLUX = True
except ImportError:
    HAS_INFLUX = False

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False

REQUIRED_MEASUREMENTS = ["pipeline_metrics"]

# ── Config ────────────────────────────────────────────────────────────────────
INFLUX_URL    = os.environ.get("INFLUX_URL",    "http://localhost:8086")
INFLUX_TOKEN  = os.environ.get("INFLUX_TOKEN",  "supersecrettoken")
INFLUX_ORG    = os.environ.get("INFLUX_ORG",    "my_refinery")
INFLUX_BUCKET = os.environ.get("INFLUX_BUCKET", "sensor_logs")

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
TS          = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
OUT_DIR     = os.path.join(PROJECT_DIR, "results", TS)
CSV_DIR     = os.path.join(OUT_DIR, "csv")
LOG_DIR     = os.path.join(OUT_DIR, "logs")
ATTACK_CSV_DEFAULT = os.path.join(PROJECT_DIR, "results", "attack_results_extended.csv")

# Set by _resolve_export_window() before any Influx query runs.
EXPORT_START = None
EXPORT_STOP = None
for d in [CSV_DIR, LOG_DIR]:
    os.makedirs(d, exist_ok=True)

# ── Measurements to export ────────────────────────────────────────────────────
MEASUREMENTS = [
    "pipeline_metrics",
    "security_metrics",
    "security_alerts",
    "modbus_events",
    "honeypot_events",
    "auth_attempts",
    "forced_writes",
    "correlation_logs",
    "process_state",
    "attack_status",
]

# ── Alert types and their ground-truth labels ─────────────────────────────────
ATTACKS = {
    "SEMANTIC_INJECTION":  "Phase 4 — Semantic Injection",
    "STEALTH_DRIFT_EWMA":  "Phase 5 — Stealth Drift (EWMA/CUSUM)",
    "STEALTH_DRIFT":       "Phase 5 — Stealth Drift (Expert Rule)",
    "CROSS_LAYER_ANOMALY": "Phase 5 — Cross-Layer Anomaly",
    "DNP3_PROBE":          "Phase 1/3 — DNP3 Protocol Probe",
    "REPLAY_ATTACK":       "Phase 8 — Replay Attack",
    "ISOLATION_FOREST":    "ML Engine — IsolationForest Anomaly",
    "LSTM_AUTOENCODER":    "ML Engine — LSTM Autoencoder Anomaly",
    "OVER_PRESSURE":       "Expert Rule — Over Pressure",
}

# Docker container names
CONTAINERS = [
    "ics_ml_engine",
    "plc_simulator",
    "ics_dnp3",
    "ics_sniffer",
    "ics_correlator",
    "attacker_node",
    "honeypot_historian_api",
    "ics_historian_api",
    "ics_historian_bridge",
    "ics_scada_ssh",
    "fake_plc_sim",
]


# ─────────────────────────────────────────────────────────────────────────────
def _require_deps():
    missing = []
    if not HAS_INFLUX:
        missing.append("influxdb-client")
    if not HAS_PANDAS:
        missing.append("pandas")
    if missing:
        print(
            f"[FATAL] Missing required packages: {', '.join(missing)}",
            file=sys.stderr,
        )
        print(
            f"        Install in eval_env: "
            f"/home/mohamed-ayman/eval_env/bin/pip install {' '.join(missing)}",
            file=sys.stderr,
        )
        sys.exit(1)


def _validate_csv_export(counts: dict):
    if not counts:
        print("[FATAL] Telemetry export produced no measurement results.", file=sys.stderr)
        sys.exit(1)

    query_errors = [meas for meas, cnt in counts.items() if cnt == -1]
    if query_errors:
        print(
            f"[FATAL] InfluxDB query failed for: {', '.join(query_errors)}",
            file=sys.stderr,
        )
        sys.exit(1)

    for meas in REQUIRED_MEASUREMENTS:
        row_count = counts.get(meas, 0)
        if row_count <= 0:
            print(
                f"[FATAL] Required measurement '{meas}' exported {row_count} rows "
                f"(window={EXPORT_START} → {EXPORT_STOP}, bucket={INFLUX_BUCKET}).",
                file=sys.stderr,
            )
            sys.exit(1)

    csv_files = [
        name for name in os.listdir(CSV_DIR)
        if name.endswith(".csv") and os.path.getsize(os.path.join(CSV_DIR, name)) > 0
    ]
    if not csv_files:
        print("[FATAL] csv/ directory contains no non-empty CSV files.", file=sys.stderr)
        sys.exit(1)


def _flux_time(iso_ts: str) -> str:
    """Wrap an ISO-8601 UTC timestamp for use in a Flux range() call."""
    return f'time(v: "{iso_ts}")'


def _range_clause() -> str:
    if not EXPORT_START or not EXPORT_STOP:
        raise RuntimeError("Export window not resolved — call _resolve_export_window() first")
    return f"range(start: {_flux_time(EXPORT_START)}, stop: {_flux_time(EXPORT_STOP)})"


def _resolve_export_window(start: str | None, stop: str | None, attack_csv: str):
    """Bind Influx queries to an explicit UTC window (never a relative lookback)."""
    global EXPORT_START, EXPORT_STOP

    if start and stop:
        EXPORT_START, EXPORT_STOP = start, stop
        return

    if not os.path.isfile(attack_csv):
        print(
            "[FATAL] No --start/--stop provided and attack CSV not found at "
            f"{attack_csv}. Pass explicit campaign bounds.",
            file=sys.stderr,
        )
        sys.exit(1)

    atk = pd.read_csv(attack_csv)
    if atk.empty or "timestamp" not in atk.columns:
        print(
            f"[FATAL] Attack CSV {attack_csv} is empty or missing timestamps.",
            file=sys.stderr,
        )
        sys.exit(1)

    ts = pd.to_datetime(atk["timestamp"], utc=True)
    # Match evaluate.py padding: 5 min before first event, 2 min after last.
    start_dt = ts.min() - pd.Timedelta(minutes=5)
    stop_dt = ts.max() + pd.Timedelta(minutes=2)
    EXPORT_START = start_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    EXPORT_STOP = stop_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    print(
        f"  [INFO] Derived export window from attack CSV: "
        f"{EXPORT_START} → {EXPORT_STOP}"
    )


def _client():
    return InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)


def export_csv():
    _require_deps()
    print(f"\n── CSV Export ({EXPORT_START} → {EXPORT_STOP}) ─────────────────────")
    c = _client()
    counts = {}
    for meas in MEASUREMENTS:
        q = f'''
from(bucket: "{INFLUX_BUCKET}")
  |> {_range_clause()}
  |> filter(fn: (r) => r["_measurement"] == "{meas}")
  |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
  |> sort(columns: ["_time"])
'''
        try:
            df = c.query_api().query_data_frame(q)
            if isinstance(df, list):
                df = pd.concat(df) if df else pd.DataFrame()
            if df.empty:
                print(f"  [EMPTY] {meas}")
                counts[meas] = 0
                continue
            path = os.path.join(CSV_DIR, f"{meas}.csv")
            df.to_csv(path, index=False)
            print(f"  [OK]  {meas:<30} {len(df):>5} rows")
            counts[meas] = len(df)
        except Exception as e:
            print(f"  [ERR] {meas}: {e}")
            counts[meas] = -1
    c.close()
    return counts


def export_logs():
    print("\n── Docker Logs ──────────────────────────────────────────────────────")
    for ctr in CONTAINERS:
        path = os.path.join(LOG_DIR, f"{ctr}.log")
        try:
            r = subprocess.run(
                ["docker", "logs", "--tail", "500", ctr],
                capture_output=True, text=True, timeout=12
            )
            content = r.stdout + r.stderr
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"  [OK]  {ctr:<30} {content.count(chr(10)):>5} lines")
        except FileNotFoundError:
            print("  [SKIP] Docker not in PATH")
            return
        except Exception as e:
            print(f"  [WARN] {ctr}: {e}")


def alert_counts() -> dict:
    if not HAS_INFLUX:
        return {}
    c = _client()
    counts = {}
    for at in ATTACKS:
        q = f'''
from(bucket: "{INFLUX_BUCKET}")
  |> {_range_clause()}
  |> filter(fn: (r) => r["_measurement"] == "security_alerts"
                   and r["alert_type"] == "{at}"
                   and r["_field"] == "score")
  |> count()
'''
        try:
            tables = c.query_api().query(q)
            counts[at] = sum(rec.get_value() for t in tables for rec in t.records)
        except Exception:
            counts[at] = "?"
    c.close()
    return counts


def build_summary(csv_counts, ac) -> str:
    sep = "=" * 65
    lines = [
        sep,
        "  ICS HONEYPOT — THESIS RESULTS SNAPSHOT",
        f"  Timestamp : {TS}",
        f"  Export    : {EXPORT_START} → {EXPORT_STOP}",
        f"  InfluxDB  : {INFLUX_URL}",
        sep,
        "",
        "── Per-Attack Detection Counts ─────────────────────────────────",
    ]
    total_detected = 0
    for at, label in ATTACKS.items():
        cnt = ac.get(at, "?")
        detected = cnt if isinstance(cnt, str) else ("YES" if cnt > 0 else "NO")
        if isinstance(cnt, int) and cnt > 0:
            total_detected += 1
        lines.append(f"  {label:<45}  {str(cnt):>4} alerts  [{detected}]")

    lines += [
        "",
        "── CSV Rows Exported ───────────────────────────────────────────",
    ]
    for meas, cnt in csv_counts.items():
        lines.append(f"  {meas:<35} {cnt:>6} rows")

    lines += [
        "",
        "── Grafana PNG Screenshots (run from project root) ─────────────",
        "  # Install renderer first (once):  docker exec ics_grafana grafana-cli plugins install grafana-image-renderer",
        "",
    ]
    panels = {
        "Pipeline_Pressure":      1,
        "ML_Anomaly_Status":      5,
        "ML_Anomaly_Score":       6,
        "Replay_Delta":           8,
        "Semantic_Injection":     9,
        "Replay_Status":         10,
        "DNP3_Probe":            11,
        "S7comm_Probe":          12,
        "Recon_Scan":            14,
        "EWMA_CUSUM_Drift":      15,
    }
    for name, pid in panels.items():
        url = (
            f"http://localhost:3000/render/d-solo/ics-honeypot-full/"
            f"ics-honeypot?orgId=1&panelId={pid}"
            f"&from=now-4h&to=now&width=1200&height=500&theme=dark"
        )
        lines.append(f"  # {name}")
        lines.append(f"  curl -s -u admin:admin '{url}' -o results/{TS}/{name}.png")
        lines.append("")

    lines += [
        "── How to Reproduce Each Attack ────────────────────────────────",
        "  docker exec -it attacker_node bash",
        "  # Then inside the container:",
        "  python3 /tools/attack_suite.py --phase 0      # full kill chain",
        "  python3 /tools/attack_suite.py --phase 4      # semantic injection",
        "  python3 /tools/attack_suite.py --phase 5      # stealth drift",
        "  python3 /tools/attack_suite.py --phase 8      # replay attack",
        "  python3 /tools/dnp3_probe.py                  # DNP3 probe",
        "",
        "── Replay Attack Manual Trigger ────────────────────────────────",
        "  # From attacker_node (after docker exec -it attacker_node bash):",
        "  for i in $(seq 1 20); do",
        '    curl -s -XPOST "http://ics_historian:8086/api/v2/write?org=my_refinery&bucket=sensor_logs&precision=ns" \\',
        '      -H "Authorization: Token supersecrettoken" \\',
        "      --data-raw \"pipeline_metrics,location=pump_station_01,source=historian_bridge pressure=120.0 $(python3 -c 'import time; print(time.time_ns())')\"; sleep 0.2; done",
        "",
        sep,
    ]
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
def main():
    import argparse

    parser = argparse.ArgumentParser(description="Export InfluxDB telemetry for thesis results")
    parser.add_argument(
        "--start",
        help="Campaign start timestamp (ISO-8601 UTC, e.g. 2026-06-29T20:12:54.000000Z)",
    )
    parser.add_argument(
        "--stop",
        help="Campaign stop timestamp (ISO-8601 UTC)",
    )
    parser.add_argument(
        "--attack-csv",
        default=ATTACK_CSV_DEFAULT,
        help="Attack boundary CSV used to derive window if --start/--stop omitted",
    )
    args = parser.parse_args()

    print("\n╔══════════════════════════════════════════════════════════════╗")
    print("║   ICS Honeypot — Thesis Results Saver                       ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(f"  Saving to: results/{TS}/")

    _require_deps()
    _resolve_export_window(args.start, args.stop, args.attack_csv)
    csv_counts = export_csv()
    _validate_csv_export(csv_counts)
    export_logs()

    print("\n── Computing Alert Counts ───────────────────────────────────────")
    ac = alert_counts()
    for at, cnt in ac.items():
        print(f"  {ATTACKS[at]:<45}  {cnt}")

    summary = build_summary(csv_counts, ac)
    spath = os.path.join(OUT_DIR, "summary.txt")
    with open(spath, "w", encoding="utf-8") as f:
        f.write(summary)

    print("\n" + summary)
    print(f"\n[SAVED] All results in: results/{TS}/")
    print("        ├── csv/          ← import into Excel / pandas for your thesis tables")
    print("        ├── logs/         ← evidence logs for appendix")
    print("        └── summary.txt   ← copy detection counts directly into your thesis\n")


if __name__ == "__main__":
    main()
