#!/usr/bin/env python3
"""
Extended Campaign Orchestrator for ICS Honeypot (scripts/run_extended_campaign.py)
================================================================================
This script automates the generation of a high-volume simulation dataset by running
a 3-hour real-time campaign with repeated, randomized attacks.

Workflow:
1. Wipes any old telemetry and models for a clean start (docker compose down -v).
2. Starts the docker container stack (docker compose up -d).
3. Waits for InfluxDB and PLC services to be healthy.
4. Waits 1 hour (3600s) to build a robust, quiet normal baseline.
5. Triggers a model reset in the live ML engine to train it on the 1-hour baseline.
6. Enters the 30-minute validation split:
   - Run a standard full chain (recon + info + exploit + drift + lateral + privesc + replay)
   - Run a custom Phase 5 (stealth drift)
7. Enters the ~2-hour test split:
   - 20 randomized attacks (4× Phase 4/5/7, 8× Phase 8) with varied parameters.
8. Writes all attack boundaries to results/attack_results_extended.csv.
9. Exports the final data using scripts/save_results.py.

Usage:
    Full 3-hour run:
        nohup python3 scripts/run_extended_campaign.py > results/campaign.out 2>&1 &

    Smoke-test (compressed ~5-minute dry-run to validate the full pipeline):
        nohup python3 scripts/run_extended_campaign.py --smoke-test > results/smoke.out 2>&1 &
"""

import os
import sys
import time
import datetime
import subprocess
import random
import shlex
import urllib.request
import urllib.error
import argparse
import threading


class CampaignError(Exception):
    """Raised when a campaign step fails and the run must abort."""


def trigger_background_checkpoint():
    """Triggers save_results.py in a background thread to export a checkpoint snapshot without blocking."""
    def _checkpoint_task():
        try:
            current_stop_utc = utc_now_iso()
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            checkpoint_dir = os.path.join(RESULTS_DIR, f"checkpoint_{ts}")
            log(f"[CHECKPOINT] Starting background checkpoint export to {checkpoint_dir} ...")

            save_script = os.path.join(PROJECT_DIR, "scripts", "save_results.py")
            cmd = (
                f"{shlex.quote(EVAL_PYTHON)} {shlex.quote(save_script)} "
                f"--start {shlex.quote(CAMPAIGN_START_UTC)} "
                f"--stop {shlex.quote(current_stop_utc)} "
                f"--out-dir {shlex.quote(checkpoint_dir)}"
            )
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if res.returncode == 0:
                subprocess.run(["cp", ATTACK_CSV, checkpoint_dir + "/"], capture_output=True, text=True)
                log(f"[CHECKPOINT SUCCESS] Background checkpoint created: {checkpoint_dir}")
            else:
                log(f"[CHECKPOINT ERROR] Background checkpoint export failed (exit {res.returncode}):")
                _log_subprocess_output(res, "CHECKPOINT")
        except Exception as exc:
            log(f"[CHECKPOINT ERROR] Exception during background checkpoint: {exc}")

    t = threading.Thread(target=_checkpoint_task, daemon=True)
    t.start()


# ── Config ────────────────────────────────────────────────────────────────────
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(PROJECT_DIR, "results")
ATTACK_CSV  = os.path.join(RESULTS_DIR, "attack_results_extended.csv")
LOG_FILE    = os.path.join(RESULTS_DIR, "campaign_run.log")
# save_results.py queries host-local InfluxDB and writes CSVs for evaluate.py — use eval_env.
EVAL_PYTHON = os.environ.get(
    "EVAL_PYTHON",
    "/home/mohamed-ayman/eval_env/bin/python",
)

CAMPAIGN_START_UTC = None
CAMPAIGN_END_UTC = None

os.makedirs(RESULTS_DIR, exist_ok=True)


# ── Helpers ───────────────────────────────────────────────────────────────────
def log(msg):
    ts   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


import csv

def record_attack(phase, name, status, detail=""):
    utc_now = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )
    with open(ATTACK_CSV, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([utc_now, phase, name, status, detail])
    log(f"RECORDED: Phase {phase} ({name}) - {status} - {detail}")


def _log_subprocess_output(res, label=""):
    """Log full stdout/stderr from a failed subprocess (Python -c tracebacks land on stdout)."""
    prefix = f"  [{label}] " if label else "  "
    if res.stdout and res.stdout.strip():
        log(f"{prefix}stdout:")
        for line in res.stdout.rstrip().splitlines():
            log(f"{prefix}  {line}")
    if res.stderr and res.stderr.strip():
        log(f"{prefix}stderr:")
        for line in res.stderr.rstrip().splitlines():
            log(f"{prefix}  {line}")
    if not (res.stdout and res.stdout.strip()) and not (res.stderr and res.stderr.strip()):
        log(f"{prefix}(no output captured)")


def utc_now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )


def mark_campaign_start():
    global CAMPAIGN_START_UTC
    CAMPAIGN_START_UTC = utc_now_iso()
    log(f"Campaign telemetry window start: {CAMPAIGN_START_UTC}")


def mark_campaign_end():
    global CAMPAIGN_END_UTC
    CAMPAIGN_END_UTC = utc_now_iso()
    log(f"Campaign telemetry window end: {CAMPAIGN_END_UTC}")


def run_host_cmd(cmd, *, fatal=True):
    log(f"HOST CMD: {cmd}")
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if res.returncode != 0:
        log(f"  [ERROR] Host command exit code {res.returncode}")
        _log_subprocess_output(res, "HOST")
        if fatal:
            raise CampaignError(f"Host command failed (exit {res.returncode}): {cmd}")
    return res.stdout.strip()


def run_attacker_cmd(cmd, *, fatal=True):
    docker_cmd = f"docker exec -t attacker_node {cmd}"
    log(f"ATTACKER CMD: {docker_cmd[:200]}...")
    t0 = time.monotonic()
    res = subprocess.run(docker_cmd, shell=True, capture_output=True, text=True)
    elapsed = time.monotonic() - t0
    log(f"  Attacker command finished in {elapsed:.1f}s (exit {res.returncode})")
    if res.returncode != 0:
        log(f"  [ERROR] Attacker command exit code {res.returncode}")
        _log_subprocess_output(res, "ATTACKER")
        if fatal:
            raise CampaignError(
                f"Attacker command failed (exit {res.returncode}) after {elapsed:.1f}s"
            )
    elif res.stdout and res.stdout.strip():
        log(f"  Attacker stdout: {res.stdout.strip()[:500]}")
    return res.stdout.strip()


def check_live_services():
    log("Checking container health...")
    for i in range(10):
        res = run_host_cmd("docker ps --filter name=plc_simulator --format '{{.Status}}'")
        if "Up" in res:
            log("plc_simulator is up.")
            break
        log(f"Waiting for plc_simulator... (attempt {i+1}/10)")
        time.sleep(5)
    else:
        log("plc_simulator failed to start!")
        return False

    log("Checking Docker container health snapshot...")
    snapshot = run_host_cmd(
        "docker ps --format 'table {{.Names}}\\t{{.Status}}'"
    )
    for line in snapshot.splitlines():
        log(f"  {line}")

    log("Waiting 10 extra seconds for InfluxDB + ML Engine to boot...")
    time.sleep(10)
    return True


def reset_ml_engine():
    log("Triggering live ML Engine model reset via POST /reset-model ...")
    try:
        req = urllib.request.Request(
            "http://localhost:8001/reset-model", data=b"", method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            body = response.read().decode().strip()
            log(f"ML Engine reset response: {body}")
    except Exception as e:
        log(f"ML Engine reset failed (non-fatal): {e}")


def save_and_locate_results():
    """Run save_results.py, copy attack CSV, return path to the new run dir."""
    log("Exporting database snapshot from InfluxDB ...")
    before_dirs = {
        d for d in os.listdir(RESULTS_DIR)
        if os.path.isdir(os.path.join(RESULTS_DIR, d)) and d[:4].isdigit()
    }
    save_script = os.path.join(PROJECT_DIR, "scripts", "save_results.py")
    if not os.path.isfile(EVAL_PYTHON):
        raise CampaignError(
            f"eval_env Python not found at {EVAL_PYTHON}. "
            "Set EVAL_PYTHON to the interpreter that has influxdb-client installed."
        )
    if not CAMPAIGN_START_UTC or not CAMPAIGN_END_UTC:
        raise CampaignError(
            "Campaign window timestamps were not recorded before export."
        )
    run_host_cmd(
        f"{shlex.quote(EVAL_PYTHON)} {shlex.quote(save_script)} "
        f"--start {shlex.quote(CAMPAIGN_START_UTC)} "
        f"--stop {shlex.quote(CAMPAIGN_END_UTC)}"
    )

    after_dirs = {
        d for d in os.listdir(RESULTS_DIR)
        if os.path.isdir(os.path.join(RESULTS_DIR, d)) and d[:4].isdigit()
    }
    new_dirs = sorted(after_dirs - before_dirs)
    if not new_dirs:
        raise CampaignError(
            "save_results.py completed but no new timestamped results directory was created. "
            f"Existing dirs: {sorted(before_dirs) or '(none)'}"
        )

    latest_dir = os.path.join(RESULTS_DIR, new_dirs[-1])
    summary = os.path.join(latest_dir, "summary.txt")
    if not os.path.isfile(summary):
        raise CampaignError(
            f"Results directory {latest_dir} exists but summary.txt is missing — "
            "telemetry export likely failed."
        )

    csv_dir = os.path.join(latest_dir, "csv")
    csv_files = [
        name for name in os.listdir(csv_dir)
        if name.endswith(".csv") and os.path.getsize(os.path.join(csv_dir, name)) > 0
    ]
    if not csv_files:
        raise CampaignError(
            f"Results directory {latest_dir} has no telemetry CSV files in csv/."
        )
    pipeline_csv = os.path.join(csv_dir, "pipeline_metrics.csv")
    if not os.path.isfile(pipeline_csv):
        raise CampaignError(
            f"Required telemetry file missing: {pipeline_csv}"
        )

    cp_res = subprocess.run(
        ["cp", ATTACK_CSV, latest_dir + "/"],
        capture_output=True,
        text=True,
    )
    if cp_res.returncode != 0:
        log("[ERROR] Failed to copy attack CSV into results directory")
        _log_subprocess_output(cp_res, "CP")
        raise CampaignError("Failed to copy attack_results_extended.csv into results dir")

    log(f"Campaign artefacts saved: {latest_dir}")
    log(f"Evaluate with: python3 evaluate.py --data-dir {shlex.quote(latest_dir)}")
    return latest_dir

def run_evaluation_metrics(latest_dir):
    """Runs evaluate.py to calculate precision, recall, and F1-score."""
    log("=" * 70)
    log("EVALUATING DETECTION METRICS (Precision, Recall, F1-Score)")
    log("=" * 70)
    
    eval_script = os.path.join(PROJECT_DIR, "evaluate.py")
    if not os.path.isfile(eval_script):
        log("[WARNING] evaluate.py not found in project root. Skipping automatic evaluation metrics.")
        return

    eval_cmd = f"{shlex.quote(EVAL_PYTHON)} {shlex.quote(eval_script)} --data-dir {shlex.quote(latest_dir)}"
    res = subprocess.run(eval_cmd, shell=True, capture_output=True, text=True)
    
    if res.returncode != 0:
        log("[ERROR] Evaluation script failed.")
        _log_subprocess_output(res, "EVAL")
    else:
        log("Evaluation Results Output:")
        for line in res.stdout.splitlines():
            log(f"  {line}")
            print(line)


# ── Shared attack helpers ─────────────────────────────────────────────────────
MODBUS_HOST = "plc_simulator"
MODBUS_PORT = 502

def _pymodbus_write(register, value, label=""):
    """Build an inline python3 one-liner that writes a single Modbus register."""
    return (
        f"python3 -c \""
        f"from pymodbus.client import ModbusTcpClient; "
        f"c = ModbusTcpClient('{MODBUS_HOST}', port={MODBUS_PORT}); c.connect(); "
        f"c.write_register({register}, {value}); c.close()"
        f"\""
    )


def run_stealth_drift(step_psi, delay_s, num_steps):
    drift_loop = (
        f"for i in range({num_steps}): "
        f"c.write_register(100, base + (i+1)*{step_psi}); time.sleep({delay_s})"
    )
    cmd = (
        f"python3 -c \""
        f"from pymodbus.client import ModbusTcpClient; import time; "
        f"c = ModbusTcpClient('{MODBUS_HOST}', port={MODBUS_PORT}); c.connect(); "
        f"base = c.read_holding_registers(100, count=1).registers[0]; "
        f"exec({drift_loop!r}); c.close()"
        f"\""
    )
    run_attacker_cmd(cmd)


def run_actuator_hijack(rpm, valve, hold_s):
    cmd = (
        f"python3 -c \""
        f"from pymodbus.client import ModbusTcpClient; import time; "
        f"c = ModbusTcpClient('{MODBUS_HOST}', port={MODBUS_PORT}); c.connect(); "
        f"c.write_register(200, {rpm}); time.sleep(1); "
        f"c.write_register(201, {valve}); time.sleep({hold_s}); "
        f"c.write_register(200, 1200); "
        f"c.write_register(201, 500); c.close()"
        f"\""
    )
    run_attacker_cmd(cmd)


def run_insider_scada_attack(rpm, valve, hold_s):
    """
    Phase 9 — SCADA Insider Setpoint Attack.
    Executed 100% strictly from ics_scada_ssh (Purdue Level 2 SCADA Engineering Workstation)
    over ot-net (172.24.0.8:502).
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
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if res.returncode != 0:
        log(f"  [WARN] Phase 9 execution from ics_scada_ssh returned non-zero code {res.returncode}: {res.stderr.strip()}")



def run_replay_attack(pressure, count, frame_delay_s=0.1):
    import base64
    endpoint = (
        "http://ics_historian:8086/api/v2/write"
        "?org=my_refinery&bucket=sensor_logs&precision=ns"
    )
    script = (
        f"import time, requests\n"
        f"ep = '{endpoint}'\n"
        f"hdr = {{'Authorization': 'Token supersecrettoken', 'Content-Type': 'text/plain; charset=utf-8'}}\n"
        f"for _ in range({count}):\n"
        f"    requests.post(ep, headers=hdr, data='pipeline_metrics,location=pump_station_01,source=historian_bridge pressure={pressure} ' + str(time.time_ns()), timeout=2)\n"
        f"    time.sleep({frame_delay_s})\n"
    )
    b64_script = base64.b64encode(script.encode('utf-8')).decode('utf-8')
    cmd = f"python3 -c \"import base64; exec(base64.b64decode('{b64_script}').decode('utf-8'))\""
    run_attacker_cmd(cmd)



# ── Smoke-test timeline ───────────────────────────────────────────────────────
def run_smoke_test():
    """
    Compressed ~5-minute pipeline smoke-test:
      0:00–1:00  (60 s)  — Quiet baseline
      1:00–1:15  (15 s)  — ML model fit
      1:15–3:00  (105 s) — Validation: stealth drift (+3 PSI × 10 steps × 5 s = 50 s, then wait 55 s)
      3:00–5:10  (~130 s) — Test: semantic injection, Phase 7 actuator hijack, cooldown
    """
    log("=" * 70)
    log("SMOKE TEST — Phase 1: Baseline (60 seconds)")
    mark_campaign_start()
    log("=" * 70)
    for tick in range(6):
        time.sleep(10)
        log(f"  Baseline: {(tick+1)*10}/60 s elapsed")

    reset_ml_engine()
    log("Waiting 15 s for model fit ...")
    time.sleep(15)

    log("=" * 70)
    log("SMOKE TEST — Phase 2: Validation (stealth drift, 105 s window)")
    log("=" * 70)
    record_attack(5, "phase5_payload", "started",
                  "Smoke-test Validation — +3 PSI every 5 s, 10 steps")
    run_stealth_drift(step_psi=3, delay_s=5, num_steps=10)   # ~50 s
    record_attack(5, "phase5_payload", "completed")
    log("Stealth drift done. Waiting 55 s to fill validation window ...")
    time.sleep(55)

    log("=" * 70)
    log("SMOKE TEST — Phase 3: Test (semantic injection, 120 s window)")
    log("=" * 70)
    pressure = 350
    record_attack(4, "phase4_exploit", "started",
                  f"Smoke-test Test — Injection {pressure} PSI")
    run_attacker_cmd(_pymodbus_write(100, pressure, label="Smoke injection"))
    record_attack(4, "phase4_exploit", "completed")

    log("SMOKE TEST — Phase 7: Actuator hijack (RPM=3000, valve closed, 8 s hold)")
    record_attack(7, "phase7_privesc", "started",
                  "Smoke-test — Actuator RPM=3000 Valve=0 hold=8s")
    run_actuator_hijack(rpm=3000, valve=0, hold_s=8)
    record_attack(7, "phase7_privesc", "completed")

    log("Attacks done. Cooling down for 110 s ...")
    time.sleep(110)


# ── Full 3-hour timeline ──────────────────────────────────────────────────────
def run_full_campaign(
    skip_baseline=False,
    n_phase4=6,
    n_phase5=8,
    n_phase7=14,
    n_phase8=10,
    n_phase9=10,
    min_quiet_s=380,
    max_quiet_s=520,
    checkpoint_interval_s=3600,
):
    if skip_baseline:
        log("=" * 70)
        log("FULL CAMPAIGN — Skipping baseline (reusing existing stack + accumulated normal data)")
        log("Resetting ML Engine to retrain on accumulated baseline ...")
        log("=" * 70)
        reset_ml_engine()
        log("Waiting 5 min for model fit on accumulated baseline ...")
        time.sleep(300)
    else:
        log("=" * 70)
        log("FULL CAMPAIGN — Phase 1: Baseline (60 minutes)")
        mark_campaign_start()
        log("=" * 70)
        for tick in range(6):
            time.sleep(600)
            log(f"  Baseline: {(tick+1)*10}/60 min elapsed")

        reset_ml_engine()
        log("Waiting 5 min for model fit ...")
        time.sleep(300)

    # ── Validation: full kill chain + standalone drift ────────────────────────
    log("=" * 70)
    log("FULL CAMPAIGN — Phase 2: Validation (30 minutes)")
    log("=" * 70)

    for phase_num, phase_name in [
        (1, "phase1_recon"),
        (2, "phase2_info_gathering"),
        (3, "phase3_vuln_scan"),
        (4, "phase4_exploit"),
        (5, "phase5_payload"),
        (6, "phase6_lateral_movement"),
        (7, "phase7_privesc"),
        (8, "phase8_replay"),
    ]:
        record_attack(phase_num, phase_name, "started", "Validation chain")
        run_attacker_cmd(f"python3 attack_suite.py --phase {phase_num}")
        record_attack(phase_num, phase_name, "completed")
        time.sleep(10)

    log("Kill chain done. Running 1 Phase 9 SCADA Insider Setpoint Attack (validation boost) ...")
    record_attack(9, "phase9_insider", "started", "Validation — SCADA Insider Setpoint RPM=2800 Valve=0 hold=10s")
    run_insider_scada_attack(rpm=2800, valve=0, hold_s=10)
    record_attack(9, "phase9_insider", "completed")
    time.sleep(10)

    log("Running 2 extra validation replays (Phase 8 boost) ...")
    for replay_idx in range(2):
        pressure = random.choice([110.0, 118.0, 122.0, 128.0, 130.0])
        count = random.choice([100, 175, 225, 275, 300])
        frame_delay = random.choice([0.08, 0.1, 0.15, 0.2])
        record_attack(
            8, "phase8_replay", "started",
            f"Validation extra {replay_idx + 1}/2 — Replay {pressure} PSI × {count} "
            f"frames @ {frame_delay}s",
        )
        run_replay_attack(pressure=pressure, count=count, frame_delay_s=frame_delay)
        record_attack(8, "phase8_replay", "completed")
        time.sleep(30)

    log("Waiting 8 min before standalone drift ...")
    time.sleep(480)

    record_attack(5, "phase5_payload", "started",
                  "Validation Standalone — +3 PSI every 5 s, 10 steps")
    run_stealth_drift(step_psi=3, delay_s=5, num_steps=10)
    record_attack(5, "phase5_payload", "completed")

    log("Validation done. Waiting 8 min to fill window ...")
    time.sleep(480)

    # ── Test: Configurable attack pool (Default ~6 hours, 48 attacks) ───
    log("=" * 70)
    log(
        f"FULL CAMPAIGN — Phase 3: Test Pool "
        f"({n_phase4}x Phase 4, {n_phase5}x Phase 5, {n_phase7}x Phase 7, {n_phase8}x Phase 8, {n_phase9}x Phase 9; "
        f"Quiet interval: {min_quiet_s}-{max_quiet_s}s)"
    )
    log("=" * 70)

    attack_pool = (
        [{"phase": 4, "name": "phase4_exploit", "desc": "Semantic Injection"}] * n_phase4
        + [{"phase": 5, "name": "phase5_payload", "desc": "Stealth Drift"}] * n_phase5
        + [{"phase": 7, "name": "phase7_privesc", "desc": "Actuator Manipulation"}] * n_phase7
        + [{"phase": 8, "name": "phase8_replay", "desc": "Replay Attack"}] * n_phase8
        + [{"phase": 9, "name": "phase9_insider", "desc": "SCADA Insider Setpoint Attack"}] * n_phase9
    )
    random.shuffle(attack_pool)
    total_test_attacks = len(attack_pool)

    last_checkpoint_time = time.monotonic()

    for idx, attack in enumerate(attack_pool):
        # Check if periodic safety checkpoint is due
        if time.monotonic() - last_checkpoint_time >= checkpoint_interval_s:
            log(f"Hourly safety checkpoint due (>{checkpoint_interval_s}s since last export) — triggering background export...")
            trigger_background_checkpoint()
            last_checkpoint_time = time.monotonic()

        interval = random.randint(min_quiet_s, max_quiet_s)
        log(f"Quiet interval before attack {idx+1}/{total_test_attacks}: {interval} s ...")
        time.sleep(interval)

        log(f"--- Test Attack {idx+1}/{total_test_attacks}: {attack['desc']} ---")

        if attack["phase"] == 4:
            p = random.choice([300, 310, 330, 345, 360, 375, 400, 420])
            record_attack(4, "phase4_exploit", "started",
                          f"Test Solo — Injection {p} PSI")
            run_attacker_cmd(_pymodbus_write(100, p))
            record_attack(4, "phase4_exploit", "completed")

        elif attack["phase"] == 5:
            step  = random.choice([2, 3, 4, 5])
            delay = random.choice([3, 4, 5, 6])
            steps = random.choice([8, 10, 12, 14, 16])
            record_attack(5, "phase5_payload", "started",
                          f"Test Solo — Drift +{step} PSI every {delay}s × {steps}")
            run_stealth_drift(step_psi=step, delay_s=delay, num_steps=steps)
            record_attack(5, "phase5_payload", "completed")

        elif attack["phase"] == 7:
            rpm   = random.choice([2400, 2600, 2800, 3000, 3200])
            valve = random.choice([0, 50, 100, 200])
            hold  = random.choice([5, 6, 8, 10, 12, 15, 18])
            record_attack(7, "phase7_privesc", "started",
                          f"Test Solo — Actuator RPM={rpm} Valve={valve} hold={hold}s")
            run_actuator_hijack(rpm=rpm, valve=valve, hold_s=hold)
            record_attack(7, "phase7_privesc", "completed")

        elif attack["phase"] == 8:
            pressure = random.choice([110.0, 115.0, 118.0, 120.0, 122.0, 125.0, 128.0, 130.0])
            count    = random.choice([100, 150, 175, 200, 225, 250, 275, 300])
            frame_delay = random.choice([0.08, 0.1, 0.12, 0.15, 0.2])
            record_attack(
                8, "phase8_replay", "started",
                f"Test Solo — Replay {pressure} PSI × {count} frames @ {frame_delay}s",
            )
            run_replay_attack(pressure=pressure, count=count, frame_delay_s=frame_delay)
            record_attack(8, "phase8_replay", "completed")

        elif attack["phase"] == 9:
            rpm   = random.choice([2800, 2900, 3000, 3100, 3200])
            valve = random.choice([0, 50, 100])
            hold  = random.choice([8, 10, 12, 14, 15])
            record_attack(
                9, "phase9_insider", "started",
                f"Test Solo — SCADA Insider Setpoint RPM={rpm} Valve={valve} hold={hold}s",
            )
            run_insider_scada_attack(rpm=rpm, valve=valve, hold_s=hold)
            record_attack(9, "phase9_insider", "completed")

    log("All test attacks done. Cooling down 5 min ...")
    time.sleep(300)


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="ICS Honeypot — Extended Data Generation Campaign"
    )
    parser.add_argument(
        "--smoke-test",
        action="store_true",
        help=(
            "Run a compressed ~5-minute end-to-end smoke-test instead of "
            "the full 3-hour campaign"
        ),
    )
    parser.add_argument(
        "--skip-baseline",
        action="store_true",
        help=(
            "Skip the docker teardown/restart and the 60-min baseline wait. "
            "Assumes the stack is already running with accumulated normal data. "
            "Resets the ML model immediately, then runs validation + test attacks."
        ),
    )
    parser.add_argument(
        "--campaign-start-utc",
        type=str,
        default=None,
        help=(
            "Override the campaign telemetry window start timestamp (ISO 8601 UTC). "
            "Use this with --skip-baseline to backdate the window to when the stack "
            "first started (e.g. '2026-07-23T17:02:59Z'). "
            "If omitted with --skip-baseline, the start is queried from docker."
        ),
    )
    parser.add_argument(
        "--n-phase4",
        type=int,
        default=6,
        help="Number of Phase 4 (Semantic Injection) attacks in test pool (default: 6)",
    )
    parser.add_argument(
        "--n-phase5",
        type=int,
        default=8,
        help="Number of Phase 5 (Stealth Drift) attacks in test pool (default: 8)",
    )
    parser.add_argument(
        "--n-phase7",
        type=int,
        default=14,
        help="Number of Phase 7 (Actuator Manipulation) attacks in test pool (default: 14)",
    )
    parser.add_argument(
        "--n-phase8",
        type=int,
        default=10,
        help="Number of Phase 8 (Replay Attack) attacks in test pool (default: 10)",
    )
    parser.add_argument(
        "--n-phase9",
        type=int,
        default=10,
        help="Number of Phase 9 (SCADA Insider Setpoint) attacks in test pool (default: 10)",
    )
    parser.add_argument(
        "--min-quiet-s",
        type=int,
        default=380,
        help="Minimum quiet interval between test attacks in seconds (default: 380)",
    )
    parser.add_argument(
        "--max-quiet-s",
        type=int,
        default=520,
        help="Maximum quiet interval between test attacks in seconds (default: 520)",
    )
    parser.add_argument(
        "--checkpoint-interval-s",
        type=int,
        default=3600,
        help="Interval in seconds between background safety checkpoints (default: 3600)",
    )
    args = parser.parse_args()

    os.chdir(PROJECT_DIR)

    # Initialise log and attack CSV
    with open(LOG_FILE, "w") as f:
        f.write("=== ICS Honeypot Extended Campaign Log ===\n")
        if args.smoke_test:
            f.write("--- SMOKE TEST MODE ---\n")

    with open(ATTACK_CSV, "w") as f:
        f.write("timestamp,phase,phase_name,status,detail\n")

    mode = "SMOKE TEST" if args.smoke_test else ("FULL CAMPAIGN (SKIP-BASELINE)" if getattr(args, 'skip_baseline', False) else "FULL CAMPAIGN")
    log(f"Starting ICS Honeypot Data Generator — Mode: {mode}")
    log(f"Project directory : {PROJECT_DIR}")

    try:
        if args.skip_baseline and not args.smoke_test:
            # Stack is already running — don't wipe it
            log("--skip-baseline: keeping existing docker stack alive.")

            # Set the campaign start timestamp
            if args.campaign_start_utc:
                global CAMPAIGN_START_UTC
                CAMPAIGN_START_UTC = args.campaign_start_utc
                log(f"Campaign telemetry window start (override): {CAMPAIGN_START_UTC}")
            else:
                # Query docker for when the stack started
                log("Querying docker for stack start time ...")
                try:
                    raw = run_host_cmd(
                        "docker inspect plc_simulator "
                        "--format '{{.State.StartedAt}}'"
                    )
                    # raw is like '2026-07-23T17:02:49.123456789Z'
                    CAMPAIGN_START_UTC = raw.strip().split(".")[0] + "Z"
                    log(f"Campaign telemetry window start (from docker): {CAMPAIGN_START_UTC}")
                except Exception as e:
                    log(f"[WARN] Could not query docker start time ({e}); using now.")
                    mark_campaign_start()

            if not check_live_services():
                raise CampaignError("Stack health check failed — is the stack running?")
        else:
            # Normal path: wipe + start stack
            log("Bringing stack down and wiping volumes ...")
            run_host_cmd("docker compose down -v")

            log("Building and starting all services ...")
            run_host_cmd("docker compose up -d")

            if not check_live_services():
                raise CampaignError("Service startup failed — plc_simulator did not become healthy")

        # Execute campaign
        if args.smoke_test:
            run_smoke_test()
        else:
            run_full_campaign(
                skip_baseline=getattr(args, 'skip_baseline', False),
                n_phase4=args.n_phase4,
                n_phase5=args.n_phase5,
                n_phase7=args.n_phase7,
                n_phase8=args.n_phase8,
                n_phase9=args.n_phase9,
                min_quiet_s=args.min_quiet_s,
                max_quiet_s=args.max_quiet_s,
                checkpoint_interval_s=args.checkpoint_interval_s,
            )

        mark_campaign_end()

        # Export + locate results
        latest_dir = save_and_locate_results()

        run_evaluation_metrics(latest_dir)

        log("=" * 70)
        log(f"CAMPAIGN COMPLETE ({mode})")
        log(f"Results directory : {latest_dir}")
        log(
            f"Run evaluation   : "
            f"python3 evaluate.py --data-dir {shlex.quote(latest_dir)}"
        )
        log("=" * 70)

    except CampaignError as exc:
        log("=" * 70)
        log(f"CAMPAIGN FAILED ({mode}): {exc}")
        log("=" * 70)
        sys.exit(1)


if __name__ == "__main__":
    main()
