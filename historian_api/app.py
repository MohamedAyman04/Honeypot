"""
Historian API — Purdue Level 3 Integration Bridge
===================================================
Exposes a REST API for Level 3 enterprise-layer systems to:
  - Query recent security alerts from the ML engine and InfluxDB
  - Push external events into the InfluxDB historian
  - Monitor system health across all honeypot services

Runs on port 5000 and sits on both monitor-net and enterprise-net.
"""

import os
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

SESSION_ID = str(uuid.uuid4())[:8]

db_client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
write_api  = db_client.write_api(write_options=SYNCHRONOUS)
query_api  = db_client.query_api()

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


def query_influx_alerts(lookback: str = "-1h", limit: int = 50, alert_type: str = None) -> list:
    """Pull security_alerts from InfluxDB and return as list of dicts."""
    type_filter = f'  |> filter(fn: (r) => r["alert_type"] == "{alert_type}")\n' if alert_type else ""
    query = f'''
from(bucket: "{INFLUX_BUCKET}")
  |> range(start: {lookback})
  |> filter(fn: (r) => r["_measurement"] == "security_alerts")
  |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
  |> sort(columns: ["_time"], desc: true)
{type_filter}  |> limit(n: {limit})
'''
    alerts = []
    try:
        tables = query_api.query(query)
        for table in tables:
            for record in table.records:
                alerts.append({
                    "timestamp":  record.get_time().isoformat(),
                    "alert_type": record.values.get("alert_type", "UNKNOWN"),
                    "detail":     record.values.get("detail", ""),
                    "score":      record.values.get("score", None),
                    "session_id": record.values.get("session_id", ""),
                })
    except Exception as e:
        print(f"[HIST-API] InfluxDB query error: {e}")
    return alerts


def query_influx_metrics(lookback: str = "-10m") -> dict:
    """Fetch latest pipeline_metrics snapshot."""
    query = f'''
from(bucket: "{INFLUX_BUCKET}")
  |> range(start: {lookback})
  |> filter(fn: (r) => r["_measurement"] == "pipeline_metrics")
  |> last()
  |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
'''
    try:
        tables = query_api.query(query)
        for table in tables:
            for record in table.records:
                return {
                    "timestamp":   record.get_time().isoformat(),
                    "pressure":    record.values.get("pressure"),
                    "flow_rate":   record.values.get("flow_rate"),
                    "temperature": record.values.get("temperature"),
                    "pump_rpm":    record.values.get("pump_rpm"),
                }
    except Exception as e:
        print(f"[HIST-API] Metrics query error: {e}")
    return {}


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
        # Proxy request to ML engine in-memory alerts (fastest, most recent)
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

    # Default: query InfluxDB historian
    alerts = query_influx_alerts(lookback=lookback, limit=limit, alert_type=alert_type)
    return jsonify({
        "source":  "influx",
        "lookback": lookback,
        "count":   len(alerts),
        "alerts":  alerts,
    })


@app.route("/api/metrics", methods=["GET"])
def get_metrics():
    """
    GET /api/metrics
    Returns latest physical process telemetry + ML engine metrics.
    """
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
    """
    GET /api/summary
    High-level dashboard summary for Level 3 consumers – designed for thesis demos.
    """
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


if __name__ == "__main__":
    print(f"--- HISTORIAN API starting on port 5000 [session={SESSION_ID}] ---")
    app.run(host="0.0.0.0", port=5000, debug=False)
