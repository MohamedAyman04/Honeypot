"""
S7comm Probe Tool (port 102 — raw TCP handshake)
=================================================
Sends a COTP Connection Request + S7 Communication Setup to the
S7comm honeypot on port 102 and reads the response.

This demonstrates a real S7comm reconnaisance handshake without
needing the snap7 shared library (which is unavailable in Debian slim).

Usage:
    python3 s7comm_probe.py [target_host] [target_port]
"""
import sys
import socket
import time

TARGET = sys.argv[1] if len(sys.argv) > 1 else "ics_s7_plc"
PORT   = int(sys.argv[2]) if len(sys.argv) > 2 else 102


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
        "protocol": "S7comm",
        "meta": {
            "narrative": message,
            "target_service": "ics_s7_plc",
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


# ── S7comm packets ─────────────────────────────────────────────────────────────
# ISO-on-TCP (RFC 1006) + COTP Connection Request (CR)
COTP_CR = bytes([
    # TPKT Header (RFC 1006)
    0x03, 0x00,       # version=3, reserved=0
    0x00, 0x16,       # total length = 22
    # COTP Connection Request (CR)
    0x11,             # COTP length = 17
    0xE0,             # PDU type = CR (0xE0)
    0x00, 0x00,       # dst reference
    0x00, 0x01,       # src reference
    0x00,             # class = 0
    # src-tsap
    0xC1, 0x02, 0x01, 0x00,
    # dst-tsap (S7: 0x0102 = rack 0, slot 2)
    0xC2, 0x02, 0x01, 0x02,
    # TPDU size
    0xC0, 0x01, 0x0A,
])

# S7 Communication Setup (Negotiate PDU size)
S7_SETUP = bytes([
    # TPKT header
    0x03, 0x00, 0x00, 0x19,
    # COTP Data (DT)
    0x02, 0xF0, 0x80,
    # S7 Header
    0x32,             # protocol id
    0x01,             # ROSCTR = JOB
    0x00, 0x00,       # redundancy id
    0x00, 0x01,       # PDU reference
    0x00, 0x08,       # parameter length
    0x00, 0x00,       # data length
    # Parameter: Setup Communication
    0xF0, 0x00,
    0x00, 0x01,       # max AMQ caller
    0x00, 0x01,       # max AMQ callee
    0x03, 0xC0,       # PDU size = 960
])


def probe(host: str, port: int):
    print(f"[S7-PROBE] Connecting to {host}:{port} ...")
    sock = socket.create_connection((host, port), timeout=5)
    print(f"[S7-PROBE] TCP connected.")

    # Step 1: COTP Connection Request
    sock.sendall(COTP_CR)
    time.sleep(0.3)
    resp = sock.recv(1024)
    print(f"[S7-PROBE] COTP response ({len(resp)} bytes): {resp.hex()}")

    cotp_confirmed = False
    if len(resp) >= 5 and resp[5] == 0xD0:
        print("[S7-PROBE] ✓ COTP Connection Confirmed (CC) — this is a real S7 target!")
        cotp_confirmed = True
    elif len(resp) > 0:
        print(f"[S7-PROBE] COTP response PDU type: 0x{resp[5]:02X}")
    else:
        print("[S7-PROBE] No COTP response.")
        sock.close()
        return False, None

    # Step 2: S7 Setup Communication
    sock.sendall(S7_SETUP)
    time.sleep(0.3)
    resp2 = sock.recv(1024)
    print(f"[S7-PROBE] S7 Setup response ({len(resp2)} bytes): {resp2.hex()}")

    pdu_size = None
    s7_ack = False
    if len(resp2) >= 9 and (resp2[7] == 0x03 or resp2[8] == 0x03):
        print("[S7-PROBE] ✓ S7 ACK-DATA received — communication negotiated!")
        s7_ack = True
        # Parse PDU size from response
        if len(resp2) >= 25:
            pdu_size = (resp2[23] << 8) | resp2[24]
            print(f"[S7-PROBE] Negotiated PDU size: {pdu_size} bytes")
    else:
        print(f"[S7-PROBE] S7 response type: {resp2.hex()[:20]}...")

    sock.close()
    print("[S7-PROBE] Done.")
    return cotp_confirmed and s7_ack, pdu_size


# ── Main ──────────────────────────────────────────────────────────────────────
try:
    success, pdu_size = probe(TARGET, PORT)
    if success:
        _story_log(
            "S7COMM_PROBE",
            f"S7comm probe from 172.28.0.50 — fingerprinting Siemens PLC identity. Negotiated PDU size: {pdu_size} bytes",
            {"pdu_size": pdu_size}
        )
except Exception as e:
    print(f"[S7-PROBE] Error: {e}")
    sys.exit(1)
