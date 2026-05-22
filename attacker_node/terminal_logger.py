#!/usr/bin/env python3
"""
terminal_logger.py — ICS Honeypot Terminal Command Logger
=========================================================
Wrap any terminal command to automatically log it as a security event
in general logs.jsonl (via story_logger) and Grafana (via InfluxDB).

All diagnostic/banner output goes to STDERR so pipes work correctly:
    curl -s http://localhost:5002/api/debug | python3 -m json.tool
    mbtget -r3 -a 100 localhost
    mbtget -w6 300 -a 100 localhost

Usage — source shell integration (recommended):
    source attacker_node/hplog.sh
    # Then: curl / ssh / cat / mbtget work automatically with logging

Usage — wrap a single command directly:
    python3 attacker_node/terminal_logger.py curl -s http://localhost:5002/api/debug
    python3 attacker_node/terminal_logger.py ssh engineer@localhost -p 2222
    python3 attacker_node/terminal_logger.py mbtget -w6 300 -a 100 localhost
"""

import sys
import os
import json
import socket
import datetime
import secrets
import subprocess
import urllib.request
import urllib.error

# ── Stderr-only printing (keeps stdout clean for pipes) ───────────────────────
def _err(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


# ── URL resolution helpers ─────────────────────────────────────────────────────
def _resolve(service_host: str, port: int, env_var: str) -> str:
    env = os.environ.get(env_var)
    if env:
        return env.rstrip("/")
    for host in [service_host, "localhost"]:
        try:
            s = socket.create_connection((host, port), timeout=0.4)
            s.close()
            return f"http://{host}:{port}"
        except Exception:
            continue
    return f"http://localhost:{port}"


STORY_LOGGER_URL = _resolve("story_logger",  8600, "STORY_LOGGER_URL")
INFLUX_URL       = _resolve("ics_historian", 8086, "INFLUX_URL")
INFLUX_TOKEN     = os.environ.get("INFLUX_TOKEN",  "supersecrettoken")
INFLUX_ORG       = os.environ.get("INFLUX_ORG",    "my_refinery")
INFLUX_BUCKET    = os.environ.get("INFLUX_BUCKET", "sensor_logs")
ATTACKER_IP      = os.environ.get("ATTACKER_IP",   "172.28.0.50")

# ── Journey / session ID ───────────────────────────────────────────────────────
def _new_journey_id() -> str:
    ts    = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    nonce = secrets.token_hex(2)
    return f"{ts}_{nonce}"

JOURNEY_ID = os.environ.get("STORY_RUN_ID") or _new_journey_id()

# ── ANSI colour helpers (output goes to stderr, so colours are fine) ──────────
def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m"

CYAN   = lambda t: _c("36", t)
GREEN  = lambda t: _c("32", t)
YELLOW = lambda t: _c("33", t)
RED    = lambda t: _c("31", t)
BOLD   = lambda t: _c("1",  t)
DIM    = lambda t: _c("90", t)


# ── Command → security event classifier ───────────────────────────────────────
def _flag_value(argv: list, flag_prefix: str) -> str:
    for i, a in enumerate(argv):
        if a.startswith(flag_prefix) and len(a) > len(flag_prefix):
            return a[len(flag_prefix):]
        if a == flag_prefix and i + 1 < len(argv):
            return argv[i + 1]
    return "?"


def classify(argv: list) -> dict:
    cmd  = argv[0] if argv else ""
    args = " ".join(argv)

    # curl → historian API reconnaissance
    if cmd in ("curl", "/usr/bin/curl"):
        endpoint = next((a for a in argv if a.startswith("http")), "http://localhost:5002")
        return dict(
            event_type       = "API_ACCESS",
            mitre_id         = "T0883",
            mitre_name       = "Internet Accessible Device",
            mitre_tactic     = "Reconnaissance",
            kill_chain_stage = "Stage 1 - IT Intrusion",
            purdue_level     = "Level 3",
            protocol         = "HTTP",
            severity         = "MEDIUM",
            stage            = "S1",
            target_service   = "honeypot_historian_api",
            narrative        = (
                f"Attacker curled historian API at {endpoint} \u2014 "
                "probing for credential leaks and exposed debug endpoints."
            ),
        )

    # ssh engineer → credential use / initial access
    if cmd in ("ssh", "/usr/bin/ssh") and "engineer" in args:
        port = _flag_value(argv, "-p")
        return dict(
            event_type       = "AUTH_ATTEMPT",
            mitre_id         = "T1078",
            mitre_name       = "Valid Accounts",
            mitre_tactic     = "Lateral Movement",
            kill_chain_stage = "Stage 1 - IT Intrusion",
            purdue_level     = "Level 3",
            protocol         = "SSH",
            severity         = "HIGH",
            stage            = "S1",
            target_service   = "ics_scada_ssh",
            narrative        = (
                f"SSH login as engineer to SCADA host (port {port}) \u2014 "
                "attacker using harvested credentials to enter OT network."
            ),
        )

    # ssh operator → lateral movement / privilege escalation
    if cmd in ("ssh", "/usr/bin/ssh") and "operator" in args:
        port = _flag_value(argv, "-p")
        return dict(
            event_type       = "LATERAL_MOVEMENT",
            mitre_id         = "T0885",
            mitre_name       = "Remote Services",
            mitre_tactic     = "Lateral Movement",
            kill_chain_stage = "Stage 1 - IT Intrusion",
            purdue_level     = "Level 3\u21922",
            protocol         = "SSH",
            severity         = "HIGH",
            stage            = "S3",
            target_service   = "ics_scada_ssh",
            narrative        = (
                f"Attacker pivoted into OT network as operator via SSH (port {port}) \u2014 "
                "escalating from IT tier to SCADA control tier."
            ),
        )

    # cat /var/log/* → credential discovery in maintenance logs
    if cmd in ("cat", "/bin/cat") and "/var/log" in args:
        log_path = next((a for a in argv if "/var/log" in a), "/var/log/scada_maintenance.log")
        return dict(
            event_type       = "CREDENTIAL_DISCOVERY",
            mitre_id         = "T1005",
            mitre_name       = "Data from Local System",
            mitre_tactic     = "Credential Access",
            kill_chain_stage = "Stage 1 - IT Intrusion",
            purdue_level     = "Level 3",
            protocol         = "SSH",
            severity         = "HIGH",
            stage            = "S2",
            target_service   = "ics_scada_ssh",
            narrative        = (
                f"Attacker read {log_path} \u2014 mining SCADA maintenance logs "
                "for accidentally exposed operator credentials."
            ),
        )

    # mbtget -wN → unauthorised Modbus write
    if cmd == "mbtget" and any(a.startswith("-w") for a in argv):
        val = _flag_value(argv, "-w")
        reg = _flag_value(argv, "-a")
        return dict(
            event_type       = "MODBUS_WRITE",
            mitre_id         = "T0855",
            mitre_name       = "Unauthorized Command Message",
            mitre_tactic     = "Impair Process Control",
            kill_chain_stage = "Stage 2 - ICS Impact",
            purdue_level     = "Level 2",
            protocol         = "Modbus",
            severity         = "CRITICAL",
            stage            = "S4",
            target_service   = "plc_simulator",
            narrative        = (
                f"Unauthorized Modbus FC6 WRITE from {ATTACKER_IP}: "
                f"register {reg} \u2190 value {val}. Process state manipulation attempt."
            ),
        )

    # mbtget -rN → Modbus reconnaissance read
    if cmd == "mbtget" and any(a.startswith("-r") for a in argv):
        count = _flag_value(argv, "-r")
        reg   = _flag_value(argv, "-a")
        return dict(
            event_type       = "MODBUS_READ",
            mitre_id         = "T0802",
            mitre_name       = "Automated Collection",
            mitre_tactic     = "Collection",
            kill_chain_stage = "Stage 2 - ICS Impact",
            purdue_level     = "Level 2",
            protocol         = "Modbus",
            severity         = "MEDIUM",
            stage            = "S3",
            target_service   = "plc_simulator",
            narrative        = (
                f"Modbus FC3 READ from {ATTACKER_IP}: "
                f"reading {count} register(s) at address {reg} \u2014 collecting PLC telemetry."
            ),
        )

    # generic mbtget
    if cmd == "mbtget":
        return dict(
            event_type       = "NETWORK_SCAN",
            mitre_id         = "T1595",
            mitre_name       = "Active Scanning",
            mitre_tactic     = "Reconnaissance",
            kill_chain_stage = "Stage 1 - IT Intrusion",
            purdue_level     = "Level 2",
            protocol         = "Modbus",
            severity         = "MEDIUM",
            stage            = "S2",
            target_service   = "plc_simulator",
            narrative        = (
                f"Modbus enumeration scan from {ATTACKER_IP} \u2014 "
                "probing PLC register space via mbtget."
            ),
        )

    # fallback
    return dict(
        event_type       = "TERMINAL_CMD",
        mitre_id         = "T1059",
        mitre_name       = "Command and Scripting Interpreter",
        mitre_tactic     = "Execution",
        kill_chain_stage = "Stage 1 - IT Intrusion",
        purdue_level     = "Level 2",
        protocol         = "N/A",
        severity         = "INFO",
        stage            = "S1",
        target_service   = "host",
        narrative        = f"Attacker ran terminal command: {' '.join(argv)}",
    )


# ── story_logger → general logs.jsonl ─────────────────────────────────────────
def _post_story(argv: list, ev: dict, outcome: str, exit_code: int) -> bool:
    payload = {
        "ts"                  : datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
        "sensor"              : "attacker_node",
        "event_type"          : ev["event_type"],
        "src_ip"              : ATTACKER_IP,
        "stage"               : ev["stage"],
        "journey_id"          : JOURNEY_ID,
        "outcome"             : outcome,
        "severity"            : ev["severity"],
        "mitre_technique_id"  : ev["mitre_id"],
        "mitre_technique_name": ev["mitre_name"],
        "mitre_tactic"        : ev["mitre_tactic"],
        "kill_chain_stage"    : ev["kill_chain_stage"],
        "purdue_level"        : ev["purdue_level"],
        "protocol"            : ev["protocol"],
        "meta": {
            "command"        : " ".join(argv),
            "narrative"      : ev["narrative"],
            "target_service" : ev["target_service"],
            "exit_code"      : exit_code,
            "level"          : "Level 2",
        },
    }
    data = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    req  = urllib.request.Request(
        url     = f"{STORY_LOGGER_URL}/story/events",
        data    = data,
        headers = {"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=2.0):
            pass
        return True
    except Exception as exc:
        _err(YELLOW(f"  [! story_logger] {exc}"))
        return False


# ── InfluxDB → Grafana ────────────────────────────────────────────────────────
def _etag(v: str) -> str:
    return str(v).replace(",", r"\,").replace("=", r"\=").replace(" ", r"\ ")

def _efield(v: str) -> str:
    return str(v).replace('"', '\\"')


def _post_influx(argv: list, ev: dict, outcome: str) -> bool:
    ts_ns = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1e9)

    tags = ",".join([
        f"event_type={_etag(ev['event_type'])}",
        f"protocol={_etag(ev['protocol'])}",
        f"severity={_etag(ev['severity'])}",
        f"mitre_tactic={_etag(ev['mitre_tactic'])}",
        f"mitre_technique_id={_etag(ev['mitre_id'])}",
        f"target_service={_etag(ev['target_service'])}",
        f"source=terminal",
    ])

    cmd_f = _efield(" ".join(argv))
    nar_f = _efield(ev["narrative"])

    line1 = (
        f"terminal_commands,{tags} "
        f'outcome="{_efield(outcome)}",'
        f'command="{cmd_f}",'
        f'narrative="{nar_f}",'
        f"value=1 {ts_ns}\n"
    )
    line2 = (
        f"honeypot_events,{tags} "
        f'narrative="{nar_f}",'
        f'command="{cmd_f}",'
        f"_value=1 {ts_ns}\n"
    )

    url = f"{INFLUX_URL}/api/v2/write?org={INFLUX_ORG}&bucket={INFLUX_BUCKET}&precision=ns"
    req = urllib.request.Request(
        url     = url,
        data    = (line1 + line2).encode("utf-8"),
        headers = {
            "Authorization": f"Token {INFLUX_TOKEN}",
            "Content-Type" : "text/plain; charset=utf-8",
        },
        method  = "POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=2.0):
            pass
        return True
    except Exception as exc:
        _err(YELLOW(f"  [! influx] {exc}"))
        return False


# ── Main ──────────────────────────────────────────────────────────────────────
def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        _err(__doc__)
        sys.exit(0)

    argv = sys.argv[1:]
    ev   = classify(argv)

    # Print intercept banner to STDERR (keeps stdout clean for pipes)
    # _err()
    # _err(CYAN("[honeypot-log]") + " Intercepted: " + BOLD(" ".join(argv)))
    # _err(f"  Event      : {BOLD(ev['event_type'])}")
    # _err(f"  MITRE      : {ev['mitre_id']} \u2014 {ev['mitre_name']}")
    # _err(f"  Tactic     : {ev['mitre_tactic']}")
    # sev_color = RED if ev["severity"] == "CRITICAL" else YELLOW if ev["severity"] == "HIGH" else CYAN
    # _err(f"  Severity   : {sev_color(ev['severity'])}")
    # _err(f"  Narrative  : {DIM(ev['narrative'][:90] + ('...' if len(ev['narrative']) > 90 else ''))}")
    # _err()

    # Run the actual command — stdout goes directly to caller's stdout (pipe-safe)
    # _err(DIM("\u2500" * 60))
    try:
        result = subprocess.run(argv)
        exit_code = result.returncode
    except FileNotFoundError:
        _err(RED(f"  [error] Command not found: {argv[0]}"))
        exit_code = 127
    except KeyboardInterrupt:
        _err()
        exit_code = 130
    # _err(DIM("\u2500" * 60))
    _err()

    outcome = "success" if exit_code == 0 else "failed"

    ok_story  = _post_story(argv, ev, outcome, exit_code)
    ok_influx = _post_influx(argv, ev, outcome)

    # if ok_story:
    #     _err(GREEN("  [\u2713 logged]") + f" \u2192 story_logger  ({ev['event_type']})")
    # if ok_influx:
    #     _err(GREEN("  [\u2713 logged]") + f" \u2192 InfluxDB      ({ev['event_type']})")
    # _err()

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
