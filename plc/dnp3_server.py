"""
DNP3 Honeypot Server — TCP port 20000
======================================
Parses link-layer frames, sends ACK responses, logs to InfluxDB.

Fix 3 — DNP3 out of ML pipeline:
  Events are written ONLY to:
    • honeypot_events       (raw protocol detail — existing)
    • recon_scan_events     (NEW — structured recon detection for Grafana)
    • auth_attempts         (connection tracking — existing)

  They are NOT written to security_metrics (no is_anomaly flag).
  They do NOT feed into the ML IsolationForest pipeline.

  Rate-limiting: max one recon_scan_events entry per IP per 5 seconds
  to prevent Grafana panel spam during active scans.
"""
import socket
import struct
import threading
import time
import os
import uuid
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

DNP3_PORT     = int(os.environ.get("DNP3_PORT",      20000))
INFLUX_URL    = os.environ.get("INFLUX_URL",    "http://ics_historian:8086")
INFLUX_TOKEN  = os.environ.get("INFLUX_TOKEN",  "supersecrettoken")
INFLUX_ORG    = os.environ.get("INFLUX_ORG",    "my_refinery")
INFLUX_BUCKET = os.environ.get("INFLUX_BUCKET", "sensor_logs")

# Debounce: track last log time per source IP (Fix 3 — rate-limit)
RECON_DEBOUNCE_SECONDS = 5.0
_last_recon_log: dict[str, float] = {}   # ip → epoch seconds
_debounce_lock = threading.Lock()

SESSION_ID = str(uuid.uuid4())[:8]

_db_client = None
_write_api = None


def get_write_api():
    global _db_client, _write_api
    if _write_api is None:
        try:
            _db_client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
            _write_api = _db_client.write_api(write_options=SYNCHRONOUS)
        except Exception as e:
            print(f"[DNP3] InfluxDB init error: {e}")
    return _write_api


# ── CRC-16/DNP ────────────────────────────────────────────────────────────────
def _build_crc_table() -> list:
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
        table.append(crc)
    return table


CRC_TABLE = _build_crc_table()


def dnp3_crc(data: bytes) -> int:
    crc = 0x0000
    for b in data:
        crc = CRC_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return (~crc) & 0xFFFF


def with_crc(data: bytes) -> bytes:
    return data + struct.pack('<H', dnp3_crc(data))


def build_dnp3_ack(src_addr: int = 1, dst_addr: int = 3) -> bytes:
    """Minimal DNP3 link-layer ACK frame."""
    ctrl = 0x00
    raw  = bytes([
        0x05, 0x64,
        0x05,
        ctrl,
        dst_addr & 0xFF, (dst_addr >> 8) & 0xFF,
        src_addr & 0xFF, (src_addr >> 8) & 0xFF,
    ])
    return with_crc(raw)


def parse_dnp3_frame(data: bytes) -> dict | None:
    if len(data) < 10 or data[0] != 0x05 or data[1] != 0x64:
        return None
    ctrl = data[3]
    dst  = struct.unpack('<H', data[4:6])[0]
    src  = struct.unpack('<H', data[6:8])[0]
    return {"control": ctrl, "dst": dst, "src": src}


# ── Logging helpers ───────────────────────────────────────────────────────────
def log_honeypot_event(remote_ip: str, remote_port: int, frame, raw_hex: str) -> None:
    """Write raw protocol detail to honeypot_events (existing measurement)."""
    try:
        api = get_write_api()
        if not api:
            return
        p = (Point("honeypot_events")
             .tag("protocol",   "DNP3")
             .tag("remote_ip",  remote_ip)
             .tag("session_id", SESSION_ID)
             .field("remote_port", remote_port)
             .field("raw_data",   raw_hex[:256])
             .field("src_addr",   int(frame["src"]) if frame else -1)
             .field("dst_addr",   int(frame["dst"]) if frame else -1)
             .time(time.time_ns(), WritePrecision.NS))
        api.write(bucket=INFLUX_BUCKET, record=p)
    except Exception as e:
        print(f"[DNP3] honeypot_events log error: {e}")


def log_recon_scan(remote_ip: str, detail: str) -> None:
    """
    Write to recon_scan_events (Fix 3 — new Grafana-visible measurement).
    Rate-limited: one entry per IP per RECON_DEBOUNCE_SECONDS.
    NOT written to security_metrics — NOT an ML anomaly.
    """
    now = time.time()
    with _debounce_lock:
        last = _last_recon_log.get(remote_ip, 0.0)
        if now - last < RECON_DEBOUNCE_SECONDS:
            return
        _last_recon_log[remote_ip] = now

    try:
        api = get_write_api()
        if not api:
            return
        p = (Point("recon_scan_events")
             .tag("protocol",   "DNP3")
             .tag("source",     "dnp3-server")
             .tag("event_type", "recon_scan_detection")
             .tag("severity",   "info")
             .tag("remote_ip",  remote_ip)
             .tag("session_id", SESSION_ID)
             .field("detail",   detail)
             .field("port",     DNP3_PORT)
             .time(time.time_ns(), WritePrecision.NS))
        api.write(bucket=INFLUX_BUCKET, record=p)
        print(f"[DNP3] recon_scan logged: {remote_ip} — {detail}")
    except Exception as e:
        print(f"[DNP3] recon_scan_events log error: {e}")


def log_auth_attempt(remote_ip: str, detail: str) -> None:
    """Log connection attempt to auth_attempts measurement."""
    try:
        api = get_write_api()
        if not api:
            return
        p = (Point("auth_attempts")
             .tag("session_id", SESSION_ID)
             .tag("src_ip",     remote_ip)
             .tag("service",    "dnp3")
             .field("detail",   detail)
             .time(time.time_ns(), WritePrecision.NS))
        api.write(bucket=INFLUX_BUCKET, record=p)
    except Exception as e:
        print(f"[DNP3] auth_attempts log error: {e}")


# ── Client handler ────────────────────────────────────────────────────────────
def handle_client(conn: socket.socket, addr: tuple) -> None:
    ip, port = addr
    print(f"[DNP3] Connection from {ip}:{port}")
    log_auth_attempt(ip, "TCP Connection established")
    log_recon_scan(ip, f"DNP3 probe from {ip}:{port} on port {DNP3_PORT}")

    try:
        conn.settimeout(30)
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print(f"[DNP3] RX {len(data)}b from {ip}")
            frame = parse_dnp3_frame(data)
            log_honeypot_event(ip, port, frame, data.hex())
            # Rate-limited recon log for each new packet burst
            log_recon_scan(ip, f"DNP3 frame rx {len(data)}b src={ip}")
            if frame:
                resp = build_dnp3_ack(src_addr=1, dst_addr=frame["src"])
                conn.sendall(resp)
                print(f"[DNP3] TX ACK to {ip}")
    except socket.timeout:
        pass
    except Exception as e:
        print(f"[DNP3] Handler error ({ip}): {e}")
    finally:
        conn.close()
        print(f"[DNP3] {ip} disconnected")
        log_auth_attempt(ip, "TCP Connection closed")


def run_server() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", DNP3_PORT))
    srv.listen(10)
    print(f"[DNP3] Honeypot listening on port {DNP3_PORT} [session={SESSION_ID}]")
    print(f"[DNP3] Events → recon_scan_events only (NOT in ML pipeline)")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    run_server()
