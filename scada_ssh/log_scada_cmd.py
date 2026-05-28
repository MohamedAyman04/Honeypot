#!/usr/bin/env python3
import sys
import os

# Ensure shared/ is importable (Docker: /opt/shared; dev: repo root)
for _shared in (
    "/opt/shared",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "shared")),
):
    if os.path.isdir(_shared):
        _parent = os.path.dirname(_shared)
        if _parent not in sys.path:
            sys.path.insert(0, _parent)
        break

import json
import urllib.request
import datetime
import getpass
import time

from shared.mitre_mapping import lookup

def parse_mbtget(parts):
    val, reg, fc = "?", "?", "?"
    for i, p in enumerate(parts):
        if p.startswith("-w"):
            fc = p[2:] if len(p) > 2 else "6"
            if i + 1 < len(parts):
                val = parts[i+1]
        elif p.startswith("-r"):
            fc = p[2:] if len(p) > 2 else "3"
            if i + 1 < len(parts):
                val = parts[i+1]
        elif p == "-a" and i + 1 < len(parts):
            reg = parts[i+1]
    return fc, val, reg

def classify(cmd_line):
    parts = cmd_line.split()
    if not parts:
        return "TERMINAL_CMD", "INFO", "T0802", "Collection", "Automated Collection", "Unknown", "Level 2", "Stage 1 - IT Intrusion", "observed", "Terminal command executed"

    # Robust detection of command even if preceded by shell artifacts like $ or #
    cmd_idx = 0
    if parts[0] in ("$", "#") and len(parts) > 1:
        cmd_idx = 1
    
    cmd = parts[cmd_idx].split('/')[-1]
    args = parts[cmd_idx+1:]
    
    # Default values
    event_type = "TERMINAL_CMD"
    severity = "INFO"
    protocol = "Unknown"
    purdue_level = "Level 2"
    outcome = "observed"
    narrative = f"Terminal command executed: {cmd_line}"
    
    # mbtget
    if cmd == "mbtget":
        protocol = "Modbus"
        fc, val, reg = parse_mbtget(parts[cmd_idx:])
        if any(a.startswith("-w") for a in args):
            event_type = "MODBUS_WRITE"
            severity = "CRITICAL"
            narrative = f"Unauthorized Modbus FC{fc} WRITE: register {reg} \u2190 value {val}. Process state manipulation attempt."
        elif any(a.startswith("-r") for a in args):
            event_type = "MODBUS_READ"
            severity = "MEDIUM"
            narrative = f"Modbus FC{fc} READ: reading {val} register(s) at address {reg} \u2014 collecting PLC telemetry."
        else:
            event_type = "NETWORK_SCAN"
            severity = "MEDIUM"
            narrative = f"Active Modbus reconnaissance scan from terminal."
            
    # cat /var/log/scada_maintenance.log
    elif cmd in ("cat", "tail", "less", "more") and any("scada_maintenance.log" in a or "/var/log" in a for a in args):
        event_type = "CREDENTIAL_DISCOVERY"
        severity = "HIGH"
        log_file = next((a for a in args if "/var/log" in a or "scada_maintenance" in a), "scada_maintenance.log")
        narrative = f"Credential discovery: read {log_file} \u2014 mining logs for accidentally exposed operator credentials."
        
    # ssh
    elif cmd == "ssh":
        event_type = "LATERAL_MOVEMENT"
        severity = "HIGH"
        protocol = "SSH"
        target_host = parts[-1] if len(parts) > 1 else "unknown"
        narrative = f"Lateral movement: SSH connection attempt to {target_host}."
        
    # nmap / ping
    elif cmd in ("nmap", "ping"):
        event_type = "NETWORK_SCAN"
        severity = "MEDIUM"
        narrative = f"Active network scanning/reconnaissance: executed {cmd_line}."

    # Use central MITRE mapping
    meta = lookup(event_type)
    mitre_id = meta["mitre_technique_id"]
    mitre_tactic = meta["mitre_tactic"]
    mitre_name = meta["mitre_technique_name"]
    protocol = protocol if protocol != "Unknown" else meta["protocol"]
    purdue_level = "Level 2"
    kill_chain_stage = meta["kill_chain_stage"]
        
    return event_type, severity, mitre_id, mitre_tactic, mitre_name, protocol, purdue_level, kill_chain_stage, outcome, narrative

def _etag(v: str) -> str:
    return str(v).replace(",", r"\,").replace("=", r"\=").replace(" ", r"\ ")

def _efield(v: str) -> str:
    return str(v).replace('"', '\\"')

def load_env_variables():
    env = {}
    if os.path.exists("/etc/environment"):
        with open("/etc/environment", "r") as f:
            for line in f:
                if "=" in line:
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip().strip('"').strip("'")
    return env

def main():
    try:
        if len(sys.argv) < 2:
            sys.exit(0)
            
        cmd = sys.argv[1].strip()
        if not cmd:
            sys.exit(0)
            
        # Prevent logging the logging script itself or empty history commands
        if "log_scada_cmd.py" in cmd or cmd == "history 1":
            sys.exit(0)
            
        # User-specific last command file to avoid permissions errors when switching users
        uid = os.getuid()
        last_f = f'/tmp/.last_scada_cmd_{uid}'
        if os.path.exists(last_f):
            with open(last_f, 'r') as f:
                if f.read().strip() == cmd:
                    sys.exit(0)
        with open(last_f, 'w') as f:
            f.write(cmd)
            
        # Load environment variables
        env = load_env_variables()
        
        url_story = env.get("STORY_LOGGER_URL") or os.environ.get("STORY_LOGGER_URL") or "http://story_logger:8600"
        url_story = url_story.rstrip("/")
        
        user = getpass.getuser()
        role = user # operator or engineer
        
        # Get client IP from SSH connection
        conn = os.environ.get("SSH_CONNECTION", "").split()
        src_ip = conn[0] if conn else "127.0.0.1"
        
        event_type, severity, mitre_id, mitre_tactic, mitre_name, protocol, purdue_level, kill_chain_stage, outcome, narrative = classify(cmd)
        journey_id = os.environ.get("STORY_RUN_ID") or env.get("STORY_RUN_ID") or "terminal_exec"
        stage = "S2" if event_type in ("MODBUS_WRITE", "MODBUS_READ") else "S1"

        # 1. Post to story_logger (general logs.jsonl)
        payload = {
            "ts": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "sensor": "workstation",
            "event_type": event_type,
            "src_ip": src_ip,
            "stage": stage,
            "journey_id": journey_id,
            "outcome": outcome,
            "severity": severity,
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,
            "mitre_tactic": mitre_tactic,
            "kill_chain_stage": kill_chain_stage,
            "purdue_level": "Level 2",
            "protocol": protocol,
            "level": "Level 2",
            "meta": {
                "user": user,
                "role": role,
                "command": cmd,
                "message": narrative,
                "narrative": narrative,
                "component": "workstation_terminal",
                "target_service": "plc_simulator",
                "level": purdue_level,
            },
        }

        req = urllib.request.Request(
            f"{url_story}/story/events",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=2.0)
        except Exception as exc:
            try:
                with open("/var/log/scada/story_post.log", "a", encoding="utf-8") as fh:
                    fh.write(f"{payload['ts']} story_logger failed: {exc}\n")
            except OSError:
                pass

        # 2. Write to InfluxDB directly
        influx_url = env.get("INFLUX_URL") or os.environ.get("INFLUX_URL")
        influx_token = env.get("INFLUX_TOKEN") or os.environ.get("INFLUX_TOKEN")
        influx_org = env.get("INFLUX_ORG") or os.environ.get("INFLUX_ORG") or "my_refinery"
        influx_bucket = env.get("INFLUX_BUCKET") or os.environ.get("INFLUX_BUCKET") or "sensor_logs"
        
        if influx_url and influx_token:
            ts_ns = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1e9)
            
            tags = ",".join([
                f"event_type={_etag(event_type)}",
                f"protocol={_etag(protocol)}",
                f"severity={_etag(severity)}",
                f"mitre_tactic={_etag(mitre_tactic)}",
                f"mitre_technique_id={_etag(mitre_id)}",
                f"target_service=plc_simulator",
                f"source=terminal",
                f"session_id={_etag(journey_id)}",
            ])
            
            cmd_f = _efield(cmd)
            nar_f = _efield(narrative)
            
            line1 = (
                f"terminal_commands,{tags} "
                f'outcome="observed",'
                f'command="{cmd_f}",'
                f'narrative="{nar_f}",'
                f"value=1.0 {ts_ns}\n"
            )
            line2 = (
                f"honeypot_events,{tags} "
                f'narrative="{nar_f}",'
                f'command="{cmd_f}",'
                f"_value=1 {ts_ns}\n"
            )
            alert_tags = ",".join([
                f"event_type={_etag(event_type)}",
                f"protocol={_etag(protocol)}",
                f"severity={_etag(severity)}",
                f"mitre_tactic={_etag(mitre_tactic)}",
                f"mitre_technique_id={_etag(mitre_id)}",
                f"kill_chain_stage={_etag(kill_chain_stage)}",
                f"layer=Level\\ 2",
                f"service=scada_ssh",
                f"session_id={_etag(journey_id)}",
            ])
            line3 = (
                f"security_alerts,{alert_tags} "
                f'narrative="{nar_f}",'
                f"value=1.0 {ts_ns}\n"
            )
            
            write_url = f"{influx_url.rstrip('/')}/api/v2/write?org={influx_org}&bucket={influx_bucket}&precision=ns"
            
            for line in (line1, line2, line3):
                try:
                    req_db = urllib.request.Request(
                        write_url,
                        data=line.encode("utf-8"),
                        headers={
                            "Authorization": f"Token {influx_token}",
                            "Content-Type": "text/plain; charset=utf-8",
                        }
                    )
                    urllib.request.urlopen(req_db, timeout=2.0)
                except Exception as exc:
                    try:
                        with open("/var/log/scada/influx_post.log", "a", encoding="utf-8") as fh:
                            fh.write(f"{datetime.datetime.now(datetime.timezone.utc).isoformat()} influx failed: {exc}\n")
                    except OSError:
                        pass
    except Exception as exc:
        try:
            with open("/var/log/scada/log_scada_cmd.log", "a", encoding="utf-8") as fh:
                fh.write(f"{datetime.datetime.now(datetime.timezone.utc).isoformat()} error: {exc}\n")
        except OSError:
            pass

if __name__ == "__main__":
    main()
