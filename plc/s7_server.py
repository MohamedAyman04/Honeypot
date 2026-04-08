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


# ── Shared dedup registry (prevents double-logging from both detectors) ───────
_seen_conns: dict = {}          # conn_key → last-logged timestamp
_seen_lock  = threading.Lock()
DEDUP_TTL   = 60.0              # seconds before the same src IP:port can re-log


def _maybe_log(remote_ip: str, remote_port: int, source: str):
    """Log only if this (ip, port) hasn't been logged within DEDUP_TTL seconds."""
    conn_key = (remote_ip, remote_port)
    now = time.time()
    with _seen_lock:
        if now - _seen_conns.get(conn_key, 0) < DEDUP_TTL:
            return   # duplicate — skip
        _seen_conns[conn_key] = now
    print(f"[S7] {source}: new connection from {remote_ip}:{remote_port}")
    log_s7_event("probe", f"S7/COTP connection ({source})", remote_ip)


# ── PRIMARY: snap7 event callback (fires instantly on client connect) ─────────
def _setup_snap7_events(server):
    """
    Register snap7's built-in event callback.  Fires at 0 ms latency when a
    client connects (evcClientAdded = 0x00000008).  No polling needed.
    """
    try:
        import socket as _sock, struct as _struct

        def _on_event(srv, event_ptr):
            try:
                event    = event_ptr.contents if hasattr(event_ptr, "contents") else event_ptr
                evt_code = int(getattr(event, "EvtCode", 0))
                if evt_code & 0x00000008:          # evcClientAdded
                    sender = int(getattr(event, "EvtSender", 0))
                    try:
                        src_ip = _sock.inet_ntoa(_struct.pack(">I", sender))
                    except Exception:
                        src_ip = str(sender)
                    _maybe_log(src_ip, 0, "snap7-event")
            except Exception as e:
                print(f"[S7] snap7 event callback error: {e}")

        server.set_events_callback(_on_event)
        print("[S7] snap7 event callback registered (evcClientAdded=0x08)")
    except Exception as e:
        print(f"[S7] snap7 event callback unavailable: {e} — tcp-monitor is backup")


# ── BACKUP: fast /proc/net/tcp poll (catches anything events miss) ────────────
# Tracks ALL active TCP states, not just ESTABLISHED, so even a 0.2-second
# CLOSE_WAIT window is enough for us to see — and log — the connection.
_ACTIVE_STATES = {"01", "03", "04", "05", "06", "07", "08", "09"}
# 01=ESTABLISHED 03=SYN_RECV 04=FIN_WAIT1 05=FIN_WAIT2
# 06=TIME_WAIT   07=CLOSE    08=CLOSE_WAIT 09=LAST_ACK


def _hex_to_ip(hex_str: str) -> str:
    """Convert little-endian hex IP from /proc/net/tcp to dotted-decimal."""
    b = bytes.fromhex(hex_str)
    return f"{b[3]}.{b[2]}.{b[1]}.{b[0]}"


def monitor_tcp_connections():
    """
    Fast-poll /proc/net/tcp every 0.2 s for any TCP activity on port 102.
    Three polls fit in a 0.6-second probe window; also catches CLOSE_WAIT.
    """
    print("[S7] TCP connection monitor started (0.2 s poll, all active states)")
    while True:
        try:
            with open("/proc/net/tcp") as f:
                lines = f.readlines()[1:]   # skip header
            for line in lines:
                parts = line.strip().split()
                if len(parts) < 4:
                    continue
                local_addr, remote_addr, state = parts[1], parts[2], parts[3]
                if state not in _ACTIVE_STATES:
                    continue
                if int(local_addr.split(":")[1], 16) != 102:
                    continue
                remote_ip   = _hex_to_ip(remote_addr.split(":")[0])
                remote_port = int(remote_addr.split(":")[1], 16)
                _maybe_log(remote_ip, remote_port, f"tcp-monitor(state={state})")
        except Exception as e:
            print(f"[S7] TCP monitor error: {e}")
        time.sleep(0.2)


def run_s7_server():
    # Use Redis to read state updated by physical process simulator
    simulator = PipelineSimulator(use_redis=True)

    server = snap7.server.Server()
    db_data = bytearray(100)
    server.register_area(srv_area_db, 1, db_data)

    server.start(102)
    print(f"[S7] S7comm Honeypot (emulated S7-300) listening on port 102 [session={SESSION_ID}]")

    # PRIMARY: snap7 events (instant) + BACKUP: tcp-monitor (0.2 s poll)
    _setup_snap7_events(server)
    monitor_thread = threading.Thread(target=monitor_tcp_connections, daemon=True)
    monitor_thread.start()

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