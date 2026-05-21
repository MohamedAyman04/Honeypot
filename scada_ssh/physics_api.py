"""
physics_api.py — Purdue Level 2 SCADA Physics REST API
=======================================================
Runs inside the ics_scada_ssh container on port 5100.

Exposes the physics engine state (pressure, temperature, flow rate,
valve/pump controls) via a REST API so that:
  • Level 3 workstations / dashboards can consume live process data.
  • Attackers who pivoted via SSH can call POST /api/physics/control
    to manipulate the physical process — the realistic "payload" phase.

Intentional vulnerabilities (honeypot design):
  • No authentication on any endpoint.
  • /api/physics/control accepts arbitrary pump_rpm / valve_pos values
    without range validation (CWE-20 — Improper Input Validation).
  • /api/physics/status leaks internal host context.

All requests are logged to a structured JSON log file that feeds the
unified logging schema (see unified_logger.py).

ATT&CK coverage produced by this service:
  T0883 — Internet Accessible Device (unauthenticated API)
  T0855 — Unauthorized Command Message (/control endpoint)
  T0822 — Loss of View (replay / spoofed values possible via /control)
"""

from __future__ import annotations

import json
import os
import socket
import time
import threading
from pathlib import Path

from flask import Flask, request, jsonify

# ── Physics engine import ──────────────────────────────────────────────────────
# The container sets PYTHONPATH=/opt/physics_api, so 'physics' resolves to
# /opt/physics_api/physics/physics_engine.py (copied from Level 2/physics/).
# No sys.path manipulation needed.
from physics.physics_engine import PipelineSimulator

# ── Configuration ──────────────────────────────────────────────────────────────
PHYSICS_API_PORT  = int(os.environ.get("PHYSICS_API_PORT",  "5100"))
LOG_DIR           = Path(os.environ.get("LOG_DIR",           "/var/log/scada"))
REDIS_HOST        = os.environ.get("REDIS_HOST",             "redis")

import uuid
import sys
# Ensure logger package is accessible if running inside scada_ssh
sys.path.append("/opt") # Assuming scada_ssh might mount logger here, or we use relative paths
try:
    from logger.unified_logger import UnifiedLogger
except ImportError:
    # Fallback if path is different
    sys.path.append(str(Path(__file__).parent.parent))
    from logger.unified_logger import UnifiedLogger

# ── Logging setup ──────────────────────────────────────────────────────────────
unified_logger = UnifiedLogger(service="physics_api", layer="Level 2", log_dir=LOG_DIR)


# ── Physics engine (shared Redis state with plc/modbus_server.py) ──────────────
# use_redis=True so this API reads/writes the SAME state as the PLC simulator.
try:
    _sim = PipelineSimulator(use_redis=True)
except Exception:
    # Graceful degradation — run in-memory if Redis is unreachable.
    _sim = PipelineSimulator(use_redis=False)

# ── Background tick — keep physics evolving while API is idle ──────────────────
def _physics_tick_loop() -> None:
    """Update the physics simulation every second in a background thread."""
    while True:
        try:
            _sim.update()
        except Exception:
            pass
        time.sleep(1.0)


_tick_thread = threading.Thread(target=_physics_tick_loop, daemon=True)
_tick_thread.start()

# ── Flask application ──────────────────────────────────────────────────────────
app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


@app.before_request
def _log_request() -> None:
    """Log every incoming request for honeypot forensics."""
    session_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
    unified_logger.log(
        event_type="API_ACCESS",
        correlation_id=session_id,
        source={
            "ip": request.remote_addr,
            "user_agent": request.headers.get("User-Agent", "")
        },
        target={
            "host": "ics_scada_ssh",
            "port": PHYSICS_API_PORT,
            "endpoint": request.path,
            "service": "physics_api"
        },
        payload={
            "method": request.method,
            "path": request.path
        }
    )


# ── GET /api/physics/status ────────────────────────────────────────────────────
@app.route("/api/physics/status", methods=["GET"])
def physics_status():
    """
    Returns high-level system status.

    Example response:
      {
        "system":  "PUMP_STATION_01",
        "status":  "RUNNING",
        "valve":   "OPEN",
        "alerts":  []
      }

    ATT&CK: T0883 — Internet Accessible Device
    Kill Chain: Reconnaissance / Delivery
    """
    state = _sim.get_state()
    valve_state = "OPEN" if state["valve_pos"] > 0.01 else "CLOSED"

    alerts: list[str] = []
    if state["pressure"] > 280:
        alerts.append("HIGH_PRESSURE")
    if state["temperature"] > 75:
        alerts.append("OVER_TEMPERATURE")
    if state["pump_rpm"] > 2800:
        alerts.append("PUMP_OVERSPEED")

    resp = {
        "system":       "PUMP_STATION_01",
        "asset_id":     "SCADA-WS-01",
        "purdue_level": 2,
        "status":       "RUNNING" if state["pump_rpm"] > 0 else "IDLE",
        "valve":        valve_state,
        "alerts":       alerts,
        "timestamp":    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        # Intentional info-leak for honeypot realism
        "_host":        socket.gethostname(),
    }

    session_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
    unified_logger.log(
        event_type="API_ACCESS",
        correlation_id=session_id,
        source={
            "ip": request.remote_addr,
        },
        target={
            "host": "ics_scada_ssh",
            "service": "physics_api"
        },
        payload={
            "event": "STATUS_READ",
            "valve_state": valve_state,
            "alert_count": len(alerts)
        }
    )

    return jsonify(resp)


# ── GET /api/physics/metrics ───────────────────────────────────────────────────
@app.route("/api/physics/metrics", methods=["GET"])
def physics_metrics():
    """
    Returns detailed real-time physical process telemetry.

    Example response:
      {
        "pressure":    180.0,    (PSI)
        "temperature": 54.0,     (°C)
        "flow_rate":   0.0,      (L/s)
        "valve_pos":   0.0,      (0.0–1.0)
        "pump_rpm":    1200,
        "viscosity":   1.0
      }

    This is the endpoint consumed by the Level 3 OPC-UA server bridge
    (LEVEL2_PULL_URL in Level 3 docker-compose.yml).

    ATT&CK: T0802 — Automated Collection
    Kill Chain: Actions on Objectives
    """
    state = _sim.get_state()

    session_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
    unified_logger.log(
        event_type="API_ACCESS",
        correlation_id=session_id,
        source={
            "ip": request.remote_addr,
        },
        target={
            "host": "ics_scada_ssh",
            "service": "physics_api"
        },
        payload={
            "event": "METRICS_READ",
            "pressure_psi": state.get("pressure"),
            "flow_rate_ls": state.get("flow_rate"),
            "temperature_c": state.get("temperature"),
            "pump_rpm": state.get("pump_rpm"),
            "valve_pos": state.get("valve_pos"),
        }
    )

    return jsonify({
        # Process telemetry — realistic industrial values
        "pressure":    state.get("pressure"),     # PSI
        "temperature": state.get("temperature"),  # °C
        "flow_rate":   state.get("flow_rate"),    # L/s
        "valve_pos":   state.get("valve_pos"),    # 0.0 (closed) → 1.0 (open)
        "pump_rpm":    state.get("pump_rpm"),     # RPM
        "viscosity":   state.get("viscosity"),    # dimensionless oil viscosity
        "timestamp":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        # Also wrap in physical_process key so Level 3 OPC-UA adapter works:
        "physical_process": {
            "pressure":    state.get("pressure"),
            "flow_rate":   state.get("flow_rate"),
            "temperature": state.get("temperature"),
            "pump_rpm":    state.get("pump_rpm"),
        },
    })


# ── POST /api/physics/control ──────────────────────────────────────────────────
@app.route("/api/physics/control", methods=["POST"])
def physics_control():
    """
    Accepts arbitrary actuator commands — NO authentication required.

    Body (JSON):
      {
        "pump_rpm":  1200,   # 0–3000; values >2800 trigger over-speed alert
        "valve_pos": 0.5     # 0.0 (fully closed) to 1.0 (fully open)
      }

    !! VULNERABILITY (intentional) !!
      • No authentication / authorisation check.
      • No range validation — caller can set pump_rpm=3000 (sabotage).
      • Accepts any float for valve_pos, including negative or >1.0.
      This is an Unauthorized Command Message (CWE-20 / T0855).

    ATT&CK: T0855 — Unauthorized Command Message
    Kill Chain: Actions on Objectives
    """
    data = request.get_json(force=True, silent=True) or {}
    changes: dict = {}

    if "pump_rpm" in data:
        try:
            rpm = float(data["pump_rpm"])
            _sim.set_pump_rpm(rpm)
            changes["pump_rpm"] = rpm
        except (TypeError, ValueError):
            return jsonify({"error": "Invalid pump_rpm value"}), 400

    if "valve_pos" in data:
        try:
            pos = float(data["valve_pos"])
            _sim.set_valve_pos(pos)
            changes["valve_pos"] = pos
        except (TypeError, ValueError):
            return jsonify({"error": "Invalid valve_pos value"}), 400

    if not changes:
        return jsonify({"error": "No valid control fields provided"}), 400

    new_state = _sim.get_state()

    # ── Detect sabotage conditions ────────────────────────────────────────────
    sabotage_detected = (
        new_state["pump_rpm"] > 2800 or
        (new_state["pump_rpm"] > 100 and new_state["valve_pos"] < 0.01)
    )

    session_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
    unified_logger.log(
        event_type="PHYSICS_CONTROL_CMD",
        correlation_id=session_id,
        source={
            "ip": request.remote_addr,
        },
        target={
            "host": "ics_scada_ssh",
            "service": "physics_api",
            "asset_id": "PUMP_STATION_01"
        },
        payload={
            "changes_applied": changes,
            "new_pressure": new_state["pressure"],
            "new_flow_rate": new_state["flow_rate"],
            "new_pump_rpm": new_state["pump_rpm"],
            "new_valve_pos": new_state["valve_pos"],
            "sabotage_detected": sabotage_detected
        }
    )

    return jsonify({
        "status":            "applied",
        "changes":           changes,
        "current_state":     new_state,
        "sabotage_detected": sabotage_detected,
        "timestamp":         time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })


# ── GET /api/physics/history ───────────────────────────────────────────────────
@app.route("/api/physics/history", methods=["GET"])
def physics_history():
    """
    Returns the last N log entries from the local physics API access log.
    Intended for dashboard consumers and forensic replay.

    ATT&CK: T0802 — Automated Collection
    """
    try:
        limit = min(int(request.args.get("limit", 20)), 200)
    except ValueError:
        limit = 20

    entries: list[dict] = []
    try:
        with open(_log_path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        for line in reversed(lines[-limit:]):
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    except FileNotFoundError:
        pass

    return jsonify({
        "count":   len(entries),
        "entries": entries,
    })


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"[PHYSICS-API] Starting on 0.0.0.0:{PHYSICS_API_PORT}")
    print("[PHYSICS-API] WARNING — no authentication on /api/physics/control")
    app.run(host="0.0.0.0", port=PHYSICS_API_PORT, debug=False, threaded=True)
