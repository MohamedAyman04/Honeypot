"""
DNP3 Probe Tool
================
Sends a DNP3 link-layer RESET_LINK_STATES frame to the DNP3 honeypot
and waits for an ACK response. Demonstrates real DNP3 communication.

Usage:
    python3 dnp3_probe.py [target_host] [target_port]
"""
import sys
import socket
import struct
import time

TARGET = sys.argv[1] if len(sys.argv) > 1 else "ics_dnp3"
PORT   = int(sys.argv[2]) if len(sys.argv) > 2 else 20000

# ── Story Logging ─────────────────────────────────────────────────────────────
def _story_log(event_type: str, message: str, details: dict = None) -> None:
    """Send an event to the story_logger to be written in general logs.jsonl."""
    import json
    import os
    import urllib.request
    import urllib.error

    logger_url = os.environ.get("STORY_LOGGER_URL")
    urls_to_try = []
    if logger_url:
        urls_to_try.append(logger_url.rstrip("/"))
    else:
        urls_to_try.extend(["http://localhost:8600", "http://story_logger:8600"])

    payload = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
        "sensor": "attacker_node",
        "event_type": event_type,
        "src_ip": "172.28.0.50",
        "stage": "S2",
        "journey_id": "probe_session",
        "outcome": "observed",
        "severity": "MEDIUM",
        "mitre_technique_id": "T0846",
        "mitre_technique_name": "Network Service Discovery",
        "mitre_tactic": "Discovery",
        "kill_chain_stage": "Stage 2 - ICS Impact",
        "purdue_level": "Level 2",
        "protocol": "DNP3",
        "meta": {
            "narrative": message,
            "target_service": "ics_dnp3",
            "target_ip": TARGET,
            **(details or {})
        }
    }

    data = json.dumps(payload).encode("utf-8")
    for base_url in urls_to_try:
        url = f"{base_url}/story/events"
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=0.5):
                return
        except Exception:
            continue

# ── DNP3 CRC-16 ───────────────────────────────────────────────────────────────
def _build_crc_table():
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
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

def build_reset_link() -> bytes:
    """DNP3 RESET_LINK_STATES frame (FC=0x40, DIR+PRM bits set)."""
    ctrl    = 0x40  # Primary, RESET_LINK_STATES
    dst     = 1     # master → outstation 1
    src     = 3     # master address
    raw = bytes([
        0x05, 0x64,                               # Start bytes
        0x05,                                     # Length (5)
        ctrl,
        dst & 0xFF, (dst >> 8) & 0xFF,
        src & 0xFF, (src >> 8) & 0xFF,
    ])
    return with_crc(raw)

# ── Main ──────────────────────────────────────────────────────────────────────
print(f"[DNP3-PROBE] Connecting to {TARGET}:{PORT}...")

try:
    sock = socket.create_connection((TARGET, PORT), timeout=5)
    print(f"[DNP3-PROBE] Connected!")

    frame = build_reset_link()
    print(f"[DNP3-PROBE] Sending RESET_LINK_STATES: {frame.hex()}")
    sock.sendall(frame)

    time.sleep(0.5)
    resp = sock.recv(1024)
    print(f"[DNP3-PROBE] Response ({len(resp)} bytes): {resp.hex()}")

    # Parse ACK
    ack_received = False
    if len(resp) >= 10 and resp[0] == 0x05 and resp[1] == 0x64:
        ctrl   = resp[3]
        dst    = struct.unpack('<H', resp[4:6])[0]
        src    = struct.unpack('<H', resp[6:8])[0]
        print(f"\n=== DNP3 ACK Received ===")
        print(f"  Control byte: 0x{ctrl:02X}")
        print(f"  From address: {src}")
        print(f"  To address:   {dst}")
        ack_received = True
    else:
        print("[DNP3-PROBE] Unexpected response format.")

    sock.close()

    if ack_received:
        _story_log(
            "DNP3_PROBE",
            f"DNP3 link-layer probe from 172.28.0.50 — connection request and handshake with outstation. Outstation address: {src}",
            {"src_address": src, "dst_address": dst, "ctrl_byte": f"0x{ctrl:02X}"}
        )

except Exception as e:
    print(f"[DNP3-PROBE] Error: {e}")
    sys.exit(1)
