"""
Historian API — Purdue Level 3 Integration Bridge
===================================================
Exposes a REST API for Level 3 enterprise-layer systems to:
  - Query recent security alerts from the ML engine and InfluxDB
  - Push external events into the InfluxDB historian
  - Monitor system health across all honeypot services

Runs on port 5000 and sits on both monitor-net and enterprise-net.

VULNERABILITY NOTE (intentional for honeynet):
  /api/debug  — left in by a developer; leaks all environment variables
                including SCADA SSH connection details.  This is the
                initial-access vector used in the thesis attack demo.
  /api/config — exposes internal network service topology with no auth.
"""

import os
import socket
import time
import uuid
import requests
from flask import Flask, request, jsonify
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

# ── Configuration ──────────────────────────────────────────────────────────────
INFLUX_URL    = os.environ.get("INFLUX_URL",    "http://ics_historian:8086")
INFLUX_TOKEN  = os.environ.get("INFLUX_TOKEN",  "supersecrettoken")
INFLUX_ORG    = os.environ.get("INFLUX_ORG",    "my_refinery")
INFLUX_BUCKET = os.environ.get("INFLUX_BUCKET", "sensor_logs")

ML_ENGINE_URL = os.environ.get("ML_ENGINE_URL", "http://ics_ml_engine:8000")

# SCADA SSH connection — used by the historian's data-collection cron job
# to pull archived process logs from the Level 2 SCADA workstation.
# These env vars are intentionally left exposed by a misconfigured debug endpoint.
SCADA_SSH_HOST = os.environ.get("SCADA_SSH_HOST", "ics_scada_ssh")
SCADA_SSH_PORT = os.environ.get("SCADA_SSH_PORT", "2222")
SCADA_SSH_USER = os.environ.get("SCADA_SSH_USER", "operator")
SCADA_SSH_PASS = os.environ.get("SCADA_SSH_PASS", "operator123")

SESSION_ID = str(uuid.uuid4())[:8]

db_client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
write_api  = db_client.write_api(write_options=SYNCHRONOUS)
query_api  = db_client.query_api()

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


def query_influx_alerts(lookback: str = "-1h", limit: int = 50, alert_type: str = None) -> list:
    """Returns fake security alerts for the honeypot, so the attacker thinks it's a real API."""
    import random
    alerts = []
    for _ in range(3):
        alerts.append({
            "timestamp":  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - random.randint(100, 3000))),
            "alert_type": "FAILED_LOGIN" if random.random() > 0.5 else "UNAUTHORIZED_ACCESS",
            "detail":     "Multiple failed SSH attempts" if random.random() > 0.5 else "Connection from unknown IP",
            "score":      random.uniform(0.5, 0.9),
            "session_id": "honeypot_" + str(uuid.uuid4())[:8],
        })
    return alerts


def query_influx_metrics(lookback: str = "-10m") -> dict:
    """Returns fake physical pipeline metrics for the honeypot API."""
    import random
    return {
        "timestamp":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "pressure":    round(random.uniform(118.0, 122.0), 2),
        "flow_rate":   round(random.uniform(49.0, 51.0), 2),
        "temperature": round(random.uniform(44.0, 46.0), 2),
        "pump_rpm":    round(random.uniform(1190.0, 1210.0), 2),
    }


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    """Liveness endpoint — also polls ML engine health."""
    ml_health = {}
    try:
        r = requests.get(f"{ML_ENGINE_URL}/health", timeout=3)
        ml_health = r.json()
    except Exception:
        ml_health = {"status": "unreachable"}

    return jsonify({
        "service":    "historian_api",
        "status":     "ok",
        "session_id": SESSION_ID,
        "timestamp":  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "ml_engine":  ml_health,
    })


@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    """
    GET /api/alerts
    Query params:
      - lookback  : InfluxDB range string, default '-1h'
      - limit     : max results (default 50, max 200)
      - alert_type: filter by type (e.g. SEMANTIC_INJECTION)
      - source    : 'influx' (default) or 'ml-engine' (live in-memory from ML engine)
    """
    lookback   = request.args.get("lookback",   "-1h")
    limit      = min(int(request.args.get("limit", 50)), 200)
    alert_type = request.args.get("alert_type", None)
    source     = request.args.get("source",     "influx")

    if source == "ml-engine":
        try:
            params = {"limit": limit}
            if alert_type:
                params["alert_type"] = alert_type
            r = requests.get(f"{ML_ENGINE_URL}/alerts", params=params, timeout=5)
            data = r.json()
            return jsonify({
                "source": "ml-engine",
                "count":  data.get("count", 0),
                "alerts": data.get("alerts", []),
            })
        except Exception as e:
            return jsonify({"error": f"ML engine unreachable: {e}"}), 503

    alerts = query_influx_alerts(lookback=lookback, limit=limit, alert_type=alert_type)
    return jsonify({
        "source":  "influx",
        "lookback": lookback,
        "count":   len(alerts),
        "alerts":  alerts,
    })


@app.route("/api/metrics", methods=["GET"])
def get_metrics():
    """GET /api/metrics — latest physical process telemetry + ML engine metrics."""
    physical = query_influx_metrics()
    ml_metrics = {}
    try:
        r = requests.get(f"{ML_ENGINE_URL}/metrics", timeout=3)
        ml_metrics = r.json()
    except Exception:
        ml_metrics = {"error": "ml-engine unreachable"}

    return jsonify({
        "physical_process": physical,
        "ml_engine":        ml_metrics,
        "timestamp":        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })


@app.route("/api/external-event", methods=["POST"])
def push_external_event():
    """
    POST /api/external-event
    Allows Level 3 systems to push external security events into InfluxDB.
    Body (JSON):
      {
        "event_type": "INTRUSION_DETECTED",
        "source":     "level3-ids",
        "detail":     "Unusual traffic from 10.0.0.5",
        "severity":   "HIGH"
      }
    """
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON body"}), 400

    event_type = data.get("event_type", "EXTERNAL_EVENT")
    source     = data.get("source",     "level3")
    detail     = data.get("detail",     "")
    severity   = data.get("severity",   "MEDIUM")

    try:
        point = (Point("external_events")
                 .tag("event_type", event_type)
                 .tag("source",     source)
                 .tag("severity",   severity)
                 .field("detail",   detail[:1024])
                 .time(time.time_ns(), WritePrecision.NS))
        write_api.write(bucket=INFLUX_BUCKET, record=point)
        print(f"[HIST-API] External event: {event_type} from {source}: {detail[:80]}")
        return jsonify({"status": "ok", "event_type": event_type})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/summary", methods=["GET"])
def get_summary():
    """GET /api/summary — high-level dashboard summary for Level 3 consumers."""
    lookback = request.args.get("lookback", "-1h")
    alerts   = query_influx_alerts(lookback=lookback, limit=200)

    type_counts = {}
    for a in alerts:
        t = a["alert_type"]
        type_counts[t] = type_counts.get(t, 0) + 1

    physical = query_influx_metrics()

    ml_health = {}
    try:
        r = requests.get(f"{ML_ENGINE_URL}/health", timeout=3)
        ml_health = r.json()
    except Exception:
        ml_health = {}

    return jsonify({
        "period":              lookback,
        "total_alerts":        len(alerts),
        "alert_breakdown":     type_counts,
        "latest_alert":        alerts[0] if alerts else None,
        "physical_process":    physical,
        "ml_engine_ready":     ml_health.get("model_ready", False),
        "ml_engine_session":   ml_health.get("session_id"),
        "timestamp":           time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })


# ── VULNERABILITY: Debug endpoint left in by developer ────────────────────────
# This endpoint was used during development to inspect container state.
# It was never removed before deployment — a realistic misconfiguration.
# It leaks ALL environment variables, including SCADA SSH credentials,
# the InfluxDB token, and internal service hostnames.
# Attack vector: unauthenticated GET /api/debug  (CVE-class: CWE-215)

@app.route("/api/debug", methods=["GET"])
def debug_info():
    """
    !! DEVELOPER DEBUG ENDPOINT — SHOULD NOT BE IN PRODUCTION !!
    Dumps environment configuration for troubleshooting.
    Left enabled by mistake — exposes sensitive infrastructure details.
    """
    print(f"[HIST-API][WARN] /api/debug accessed from {request.remote_addr} — credential leak!")

    # Log this access to InfluxDB as a suspicious event
    try:
        point = (Point("external_events")
                 .tag("event_type", "DEBUG_ENDPOINT_ACCESS")
                 .tag("source",     request.remote_addr or "unknown")
                 .tag("severity",   "HIGH")
                 .field("detail",   f"Unauthenticated access to /api/debug from {request.remote_addr}")
                 .time(time.time_ns(), WritePrecision.NS))
        write_api.write(bucket=INFLUX_BUCKET, record=point)
    except Exception:
        pass

    hostname = socket.gethostname()
    try:
        local_ip = socket.gethostbyname(hostname)
    except Exception:
        local_ip = "unknown"

    return jsonify({
        "_warning": "DEBUG ENDPOINT — remove before production",
        "host": {
            "hostname": hostname,
            "ip":       local_ip,
        },
        "environment": {
            # !! SCADA SSH — used by data-collection cron to pull process logs
            "SCADA_SSH_HOST":     SCADA_SSH_HOST,
            "SCADA_SSH_PORT":     SCADA_SSH_PORT,
            "SCADA_SSH_USER":     SCADA_SSH_USER,
            "SCADA_SSH_PASS":     SCADA_SSH_PASS,
            "MODBUS_HOST":        "plc_simulator",
            "MODBUS_PORT":        "502",
        },
        "note": (
            "SCADA_SSH_* vars are used by /opt/historian/collect_scada_logs.sh "
            "which runs every 5 min via cron to pull process archives from "
            "the Level-2 SCADA workstation into the historian database."
        ),
    })


# ── VULNERABILITY: Unauthenticated network topology disclosure ─────────────────
# Returns internal service map with no authentication.  (CWE-200)

@app.route("/api/config", methods=["GET"])
def config_info():
    """
    GET /api/config
    Returns internal service topology — no authentication required.
    Exposes Purdue-level network layout to any caller.
    """
    print(f"[HIST-API][WARN] /api/config accessed from {request.remote_addr} — topology leak!")

    return jsonify({
        "site":    "Pump Station 01 — ICS Refinery Control System",
        "purdue_layout": {
            "level_3_enterprise": {
                "historian_api":  f"http://ics_historian_api:5000  (this service)",
                "influxdb":       "http://ics_historian:8086",
                "grafana":        "http://ics_grafana:3000",
                "ml_engine":      "http://ics_ml_engine:8000",
            },
            "level_2_control": {
                "scada_workstation": f"ssh://{SCADA_SSH_HOST}:{SCADA_SSH_PORT}  (operator access)",
                "hmi":               "http://ics_hmi:8060",
            },
            "level_2_ot": {
                "modbus_plc":  "plc_simulator:502   (Modbus TCP — SIMATIC gateway)",
                "s7_plc":      "ics_s7_plc:102      (Siemens S7-300)",
                "dnp3_rtu":    "ics_dnp3:20000      (DNP3 outstation)",
            },
        },
        "data_flows": [
            "SCADA workstation → historian_api (SSH pull every 5 min)",
            "Modbus PLC → historian (direct write via hmi_simulator)",
            "historian_api → Grafana (InfluxDB datasource)",
        ],
    })


if __name__ == "__main__":
    print(f"--- HISTORIAN API starting on port 5000 [session={SESSION_ID}] ---")
    print(f"[WARN] /api/debug endpoint is ACTIVE — credential leak risk!")
    app.run(host="0.0.0.0", port=5000, debug=False)
