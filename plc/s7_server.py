"""
S7comm Honeypot Server (Siemens S7-300 emulation)
===================================================
- Listens on TCP port 102.
- Serves real physics state in S7 DB1 (pressure, temp, flow, RPM).
- Reads physics state from Redis updated by physics_process.py.
"""
import os
import time
import uuid
import threading
import snap7.server
from snap7.util import set_real
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS
from physics.physics_engine import PipelineSimulator

# Handle both snap7 <= 0.x (snap7.types) and >= 1.x (snap7.type)
try:
    from snap7.type import SrvArea
    srv_area_db = SrvArea.DB
except (ImportError, AttributeError):
    try:
        from snap7.types import srvAreaDB
        srv_area_db = srvAreaDB
    except ImportError:
        srv_area_db = 0x04

# ── InfluxDB Config ────────────────────────────────────────────────────────────
INFLUX_URL    = os.environ.get("INFLUX_URL",    "http://ics_historian:8086")
INFLUX_TOKEN  = os.environ.get("INFLUX_TOKEN",  "supersecrettoken")
INFLUX_ORG    = os.environ.get("INFLUX_ORG",    "my_refinery")
INFLUX_BUCKET = os.environ.get("INFLUX_BUCKET", "sensor_logs")

SESSION_ID = str(uuid.uuid4())[:8]

_db_client = None
_write_api = None
_influx_lock = threading.Lock()


def get_write_api():
    global _db_client, _write_api
    with _influx_lock:
        if _write_api is None:
            try:
                _db_client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
                _write_api = _db_client.write_api(write_options=SYNCHRONOUS)
                print("[S7] InfluxDB connected")
            except Exception as e:
                print(f"[S7] InfluxDB init error: {e}")
        return _write_api


def log_s7_event(event_type: str, detail: str = "", src_ip: str = "unknown"):
    """Log S7 honeypot events to both honeypot_events and auth_attempts."""
    try:
        api = get_write_api()
        if not api: return
        ts = time.time_ns()

        p_event = (Point("honeypot_events")
                   .tag("protocol",   "S7comm")
                   .tag("session_id", SESSION_ID)
                   .tag("remote_ip",  src_ip)
                   .field("event_type", event_type)
                   .field("detail",     detail[:256])
                   .time(ts, WritePrecision.NS))
        api.write(bucket=INFLUX_BUCKET, record=p_event)

        p_auth = (Point("auth_attempts")
                  .tag("session_id", SESSION_ID)
                  .tag("src_ip",     src_ip)
                  .tag("service",    "s7comm")
                  .field("detail",   f"{event_type}: {detail}"[:256])
                  .time(ts, WritePrecision.NS))
        api.write(bucket=INFLUX_BUCKET, record=p_auth)
    except Exception as e:
        print(f"[S7] InfluxDB log error: {e}")


def run_s7_server():
    # Use Redis to read state updated by physical process simulator 
    simulator = PipelineSimulator(use_redis=True)

    server = snap7.server.Server()
    db_data = bytearray(100)
    server.register_area(srv_area_db, 1, db_data)

    server.start(102)
    print(f"[S7] S7comm Honeypot (emulated S7-300) listening on port 102 [session={SESSION_ID}]")
    log_s7_event("startup", "S7comm honeypot started", src_ip="localhost")

    try:
        while True:
            # S7 Server is passive reader of the physics state
            simulator.load_state() 
            state = simulator.get_state()
            
            # Map physical fields into DB1 as IEEE-754 REALs
            set_real(db_data, 0,  state['pressure'])         # DB1.DBD0
            set_real(db_data, 4,  state['temperature'])       # DB1.DBD4
            set_real(db_data, 8,  state['flow_rate'])         # DB1.DBD8
            set_real(db_data, 12, float(state['pump_rpm']))  # DB1.DBD12

            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()
        print("[S7] Server stopped.")


if __name__ == "__main__":
    run_s7_server()