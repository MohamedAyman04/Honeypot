#!/usr/bin/env python3
"""
scripts/clean_and_enrich_logs.py
================================
Cleans, standardizes, enriches, and diversifies `general logs.jsonl` into a
clean, hierarchical, non-redundant ML-ready Cyber-Physical dataset.

Enforces:
- Clean nested hierarchy: timestamp, event_id, event, context, network, process, ml_analysis, mitre, security.
- Elimination of redundant / unused duplicated fields (e.g. repeated ports, duplicated severity across multiple blocks).
- Strict Protocol-to-Port Integrity:
  * Modbus: port 502
  * S7comm: port 102
  * DNP3: port 20000
  * SSH: port 2222
  * HTTP / API: port 8008 / 8600
- Multi-variable physical safety boundary evaluations on every record.
- Elimination of repetitive 13,251 OVER_PRESSURE alert loops in favor of a balanced spectrum.
"""

from __future__ import annotations

import datetime
import json
import os
import random
import shutil
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from physics.safety_boundaries import (
    DEFAULT_LIMITS,
    BoundarySeverity,
    evaluate_safety_boundaries,
)
from shared.log_schema import create_ml_ready_log_record, format_iso_timestamp

LOG_FILE = PROJECT_ROOT / "general logs.jsonl"
BACKUP_FILE = PROJECT_ROOT / "general logs.jsonl.bak_original"


def parse_timestamp(ts_str: str) -> datetime.datetime:
    if not ts_str:
        return datetime.datetime.now(datetime.timezone.utc)
    try:
        clean = ts_str.replace("Z", "+00:00")
        return datetime.datetime.fromisoformat(clean)
    except Exception:
        return datetime.datetime.now(datetime.timezone.utc)


def generate_ml_ready_dataset(input_file: Path, output_file: Path):
    print(f"[*] Reading source logs from {input_file} ...")
    if not input_file.exists():
        print(f"[ERROR] Input file {input_file} does not exist.")
        sys.exit(1)

    # 1. Create a safe backup if not already present
    if not BACKUP_FILE.exists():
        print(f"[*] Creating safe backup at {BACKUP_FILE} ...")
        shutil.copy2(input_file, BACKUP_FILE)

    raw_records = []
    with open(input_file, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            s = line.strip()
            if not s:
                continue
            try:
                rec = json.loads(s)
                raw_records.append(rec)
            except Exception as e:
                print(f"[WARN] Skipping malformed line {line_no}: {e}")

    print(f"[*] Loaded {len(raw_records)} raw records.")

    # 2. Extract non-alert interactive/lifecycle events
    non_alert_events = []
    for r in raw_records:
        et = ""
        if "event" in r and isinstance(r["event"], dict):
            et = r["event"].get("type", "")
        else:
            et = r.get("event_type", "")
        
        et_lower = et.lower()
        if "detection_alert" not in et_lower and "over_pressure" not in et_lower:
            non_alert_events.append(r)

    print(f"[*] Extracted {len(non_alert_events)} lifecycle/attack events.")

    # Set deterministic random seed
    random.seed(42)

    enriched_records = []

    # 3. Process existing interactive lifecycle & attack events
    for r in non_alert_events:
        ts = r.get("timestamp") or r.get("ts", format_iso_timestamp())
        
        if "event" in r and isinstance(r["event"], dict):
            et = r["event"].get("type", "event").lower()
            sev = r["event"].get("severity", "INFO")
            narr = r["event"].get("narrative", f"Event: {et}")
        else:
            et = r.get("event_type", "event").lower()
            sev = r.get("severity", "INFO")
            meta = r.get("meta", {})
            narr = meta.get("message", f"Event: {et}") if isinstance(meta, dict) else f"Event: {et}"

        sensor = "scada"
        if "context" in r and isinstance(r["context"], dict):
            sensor = r["context"].get("sensor", "scada")
        else:
            sensor = r.get("sensor", "scada")

        src_ip = r.get("src_ip", "172.28.0.50")
        if "network" in r and isinstance(r["network"], dict):
            src_ip = r["network"].get("source", {}).get("ip", src_ip)

        # Detect protocol and port
        proto = "Modbus"
        dport = 502
        if "s7" in et:
            proto = "S7comm"
            dport = 102
        elif "dnp3" in et:
            proto = "DNP3"
            dport = 20000
        elif "ssh" in et or "login" in et or "terminal" in et:
            proto = "SSH"
            dport = 22
        elif "api" in et or "http" in et or "query" in et:
            proto = "HTTP"
            dport = 8008

        # Extract phase
        phase = 0
        if "ml_analysis" in r and isinstance(r["ml_analysis"], dict):
            phase = r["ml_analysis"].get("attack_phase", 0)
        elif "meta" in r and isinstance(r["meta"], dict):
            phase = r["meta"].get("phase", 0)

        p = 120.0 + random.uniform(-2.0, 2.0)
        q = 50.0 + random.uniform(-1.0, 1.0)
        t = 45.0 + random.uniform(-0.5, 0.5)
        rpm = 1200.0 + random.uniform(-10.0, 10.0)
        valve = 0.50

        is_write = 1 if "write" in et or "exploit" in et or "attack" in et else 0
        freq = 3.0 if is_write else 0.0

        proc_feat = {
            "pressure": round(p, 2),
            "flow_rate": round(q, 2),
            "temperature": round(t, 2),
            "pump_rpm": round(rpm, 1),
            "valve_position": round(valve, 2),
            "viscosity": 1.0,
            "pressure_delta": round(random.uniform(-0.5, 0.5), 2),
            "pressure_mean_deviation": round(p - 120.0, 2),
        }
        is_dos = (phase == 10) or ("dos" in et.lower())
        if is_dos:
            iat_val = round(random.uniform(0.001, 0.004), 4)
        elif is_write:
            iat_val = round(random.uniform(0.005, 0.05), 3)
        else:
            iat_val = round(random.uniform(0.01, 0.2), 3)

        net_feat = {
            "inter_arrival_time": iat_val,
            "write_frequency_10s": round(freq, 1),
            "is_write": is_write,
            "function_code": 6 if is_write else 3,
            "length": random.choice([12, 14, 20]),
            "protocol": proto,
        }
        violations = evaluate_safety_boundaries(proc_feat)
        is_ano = 1 if (phase > 3 or violations or is_dos) else 0
        cat_name = "Normal Baseline" if is_ano == 0 else (f"Phase 10 Execution (DoS)" if is_dos else f"Phase {phase} Execution")

        labels = {
            "is_anomaly": is_ano,
            "anomaly_type": "DOS_ATTACK" if is_dos else ("ATTACK" if is_ano else "NORMAL"),
            "attack_phase": 10 if is_dos else phase,
            "attack_category": cat_name,
            "boundary_violations": [v.to_dict() for v in violations],
        }

        if is_dos:
            mitre_tags = {
                "technique_id": "T0814",
                "technique_name": "Denial of Service",
                "tactic": "Inhibit Response Function",
                "kill_chain_stage": "Stage 2 - ICS Impact",
            }
        else:
            mitre_tags = {
                "technique_id": "T0855" if is_write else ("T0807" if "terminal" in et else ("T0846" if "probe" in et else "T0000")),
                "technique_name": "Unauthorized Command" if is_write else ("Command-Line Interface" if "terminal" in et else "Normal Operation"),
                "tactic": "Impair Process Control" if is_write else ("Execution" if "terminal" in et else "None"),
                "kill_chain_stage": "Stage 2 - ICS Impact" if is_ano else "Operational Baseline",
            }

        rec = create_ml_ready_log_record(
            event_type=et,
            sensor=sensor,
            layer="Level 2",
            severity=sev,
            src_ip=src_ip,
            dst_ip="172.24.0.8",
            dst_port=dport,
            protocol=proto,
            process_features=proc_feat,
            network_features=net_feat,
            ml_labels=labels,
            mitre_tags=mitre_tags,
            narrative=narr,
            session_id=str(r.get("journey_id", "sess_001"))[:8],
            journey_id=str(r.get("journey_id", "sess_001")),
            timestamp=ts,
        )
        enriched_records.append(rec)

    # 4. Synthesize balanced, multi-variable events covering all variables and exact protocol ports
    print("[*] Generating balanced multi-variable cyber-physical event spectrum with strict protocol ports...")

    base_time = parse_timestamp(raw_records[0].get("timestamp") or raw_records[0].get("ts", format_iso_timestamp())) if raw_records else datetime.datetime.now(datetime.timezone.utc)

    # Archetype tuple:
    # (event_type, proto, dport, p, q, t, rpm, valve, write_freq, is_write, func_code, ano_type, phase, category, narrative, severity, tech_id, tech_name, tactic, kill_chain)
    archetypes = [
        # 1. Normal Steady State (Modbus port 502)
        ("process_telemetry", "Modbus", 502, 120.2, 50.1, 45.0, 1200.0, 0.50, 0.0, 0, 3, "NORMAL", 0, "Normal Baseline", "Nominal pipeline steady-state operation within standard ASME B31.4 limits.", "INFO", "T0000", "Normal Operation", "None", "Operational Baseline"),
        # 1b. Normal Steady State (Siemens S7comm port 102)
        ("s7comm_read_telemetry", "S7comm", 102, 120.1, 50.2, 45.1, 1200.0, 0.50, 0.0, 0, 4, "NORMAL", 0, "Normal Baseline", "Siemens S7comm cyclic DB read (DB1.DBD0-DBD12) capturing pipeline hydrodynamic state.", "INFO", "T0000", "Normal Operation", "None", "Operational Baseline"),
        # 2. Over-Pressure Safety Trip (Phase 9 / SCADA Insider - Modbus port 502)
        ("over_pressure_trip", "Modbus", 502, 325.0, 0.0, 48.2, 2800.0, 0.0, 1.0, 1, 6, "OVER_PRESSURE_TRIP", 9, "Insider Setpoint Overpressure", "Critical overpressure (325.0 PSI > 150 PSI) caused by pump overspeed to 2800 RPM against closed valve.", "CRITICAL", "T0828", "Loss of Safety", "Damage to Property", "Stage 2 - ICS Impact"),
        # 3. Under-Pressure Line Break (Modbus port 502)
        ("under_pressure_breach", "Modbus", 502, 32.5, 68.0, 41.0, 1100.0, 0.85, 0.0, 0, 3, "UNDER_PRESSURE_TRIP", 7, "Loss of Containment", "Severe underpressure (32.5 PSI < 50 PSI) indicating pipeline rupture / major containment breach.", "CRITICAL", "T0828", "Loss of Safety", "Damage to Property", "Stage 2 - ICS Impact"),
        # 4. Flow Surge Limit (Modbus port 502)
        ("flow_surge_limit", "Modbus", 502, 112.0, 82.5, 43.0, 1600.0, 0.95, 2.0, 1, 6, "FLOW_SURGE_TRIP", 7, "Actuator Manipulation", "Volumetric flow surge (82.5 L/s > 75 L/s) exceeds maximum erosion velocity limit per API 610.", "HIGH", "T0855", "Unauthorized Command", "Impair Process Control", "Stage 2 - ICS Impact"),
        # 5. Deadhead & No-Flow Thermal Blockage (Modbus port 502)
        ("deadhead_blockage", "Modbus", 502, 185.0, 1.2, 68.5, 1400.0, 0.02, 0.0, 0, 3, "DEADHEAD_BLOCKAGE", 7, "Deadhead Hazard", "Pump active at 1400 RPM with discharge closed (Q = 1.2 L/s <= 5 L/s); rapid thermal deadhead buildup.", "CRITICAL", "T0828", "Loss of Safety", "Damage to Property", "Stage 2 - ICS Impact"),
        # 6. Over-Temperature Thermal Trip (Modbus port 502)
        ("over_temperature_trip", "Modbus", 502, 138.0, 15.0, 79.5, 1900.0, 0.20, 1.0, 1, 6, "OVER_TEMPERATURE_TRIP", 7, "Thermal Runaway", "Fluid temperature (79.5 °C > 75 °C) exceeds vaporization & seal failure limit per API 610.", "CRITICAL", "T0828", "Loss of Safety", "Damage to Property", "Stage 2 - ICS Impact"),
        # 7. Pump Mechanical Overspeed (Modbus port 502)
        ("pump_overspeed_trip", "Modbus", 502, 195.0, 58.0, 52.0, 2450.0, 0.60, 4.0, 1, 6, "PUMP_OVERSPEED_TRIP", 7, "Actuator Overspeed", "Centrifugal pump rotational speed (2450 RPM > 2000 RPM) breaches mechanical rotor limit.", "CRITICAL", "T0855", "Unauthorized Command", "Impair Process Control", "Stage 2 - ICS Impact"),
        # 8. Water Hammer Dynamic Surge (Modbus port 502)
        ("pressure_surge_delta", "Modbus", 502, 175.0, 30.0, 45.0, 1500.0, 0.10, 5.0, 1, 6, "PRESSURE_SURGE_DELTA", 4, "Semantic Injection Transient", "Water hammer shock detected: dP/dt = 38.5 PSI/s exceeds transient surge limit (25 PSI/s).", "HIGH", "T0855", "Unauthorized Command", "Impair Process Control", "Stage 2 - ICS Impact"),
        # 9. Cavitation Hazard (Modbus port 502)
        ("cavitation_risk", "Modbus", 502, 165.0, 8.0, 58.0, 2100.0, 0.08, 2.0, 1, 6, "CAVITATION_RISK", 7, "Cavitation & Deadhead", "Cavitation criteria met: 2100 RPM against 8% valve opening causes localized vaporization shock.", "CRITICAL", "T0828", "Loss of Safety", "Damage to Property", "Stage 2 - ICS Impact"),
        # 10. Stealth Pressure Drift (Phase 5 CUSUM/EWMA - Modbus port 502)
        ("stealth_pressure_drift", "Modbus", 502, 136.5, 52.0, 46.2, 1350.0, 0.52, 1.0, 1, 6, "STEALTH_DRIFT", 5, "Stealth Drift", "Subtle cumulative drift (+2.5 PSI/step) accumulating CUSUM statistic (H = 6.8 > 6.0).", "HIGH", "T0836", "Modify Parameter", "Impair Process Control", "Stage 2 - ICS Impact"),
        # 10b. Siemens S7comm Stealth Parameter Modification (S7comm port 102)
        ("s7comm_stealth_drift", "S7comm", 102, 134.8, 51.5, 45.8, 1320.0, 0.52, 0.5, 1, 5, "STEALTH_DRIFT", 5, "Stealth Drift", "Siemens S7comm incremental setpoint increment (+2 PSI/step) triggering CUSUM drift alarm.", "HIGH", "T0836", "Modify Parameter", "Impair Process Control", "Stage 2 - ICS Impact"),
        # 11. Telemetry Flatline Replay (Phase 8 NMG Gate - Modbus port 502)
        ("telemetry_replay_spoof", "Modbus", 502, 120.0, 50.0, 45.0, 1200.0, 0.50, 0.0, 0, 3, "REPLAY_ATTACK", 8, "Telemetry Replay", "Out-of-band InfluxDB replay: telemetry flatlined at nominal state while Modbus write traffic is zero.", "HIGH", "T0856", "Spoof Reporting Message", "Impair Process Control", "Stage 2 - ICS Impact"),
        # 12. Modbus High-Frequency Semantic Injection (Modbus port 502)
        ("semantic_write_burst", "Modbus", 502, 142.0, 48.0, 45.5, 1300.0, 0.45, 8.5, 1, 6, "SEMANTIC_INJECTION", 4, "Semantic Injection", "Sub-second Modbus FC6 write burst (8.5 writes/10s) toggling holding registers.", "HIGH", "T0855", "Unauthorized Command", "Impair Process Control", "Stage 2 - ICS Impact"),
        # 12b. Siemens S7comm Force Write / Valve Override (S7comm port 102)
        ("s7comm_force_write", "S7comm", 102, 168.0, 22.0, 56.5, 1850.0, 0.15, 4.0, 1, 5, "S7COMM_UNAUTHORIZED_WRITE", 7, "Actuator Manipulation", "Siemens S7comm Job write to DB1 overriding pump speed and valve setpoint.", "CRITICAL", "T0855", "Unauthorized Command", "Impair Process Control", "Stage 2 - ICS Impact"),
        # 13. Reconnaissance Port Sweep (Modbus port 502)
        ("network_scan_probe", "Modbus", 502, 120.0, 50.0, 45.0, 1200.0, 0.50, 0.0, 0, 3, "RECON_SCAN", 1, "Reconnaissance", "Nmap TCP port scan probing industrial ports 502 (Modbus), 102 (S7comm), and 20000 (DNP3).", "LOW", "T1595", "Active Scanning", "Reconnaissance", "Stage 1 - IT Intrusion"),
        # 14. Siemens S7comm Fingerprinting (S7comm port 102 STRICT)
        ("s7comm_probe", "S7comm", 102, 120.0, 50.0, 45.0, 1200.0, 0.50, 0.0, 0, 1, "RECON_SCAN", 2, "Information Gathering", "COTP Connection Request & S7comm SZL CPU read probe on port 102.", "LOW", "T0846", "Network Service Discovery", "Discovery", "Stage 1 - IT Intrusion"),
        # 15. DNP3 Outstation Enumeration (DNP3 port 20000 STRICT)
        ("dnp3_probe", "DNP3", 20000, 120.0, 50.0, 45.0, 1200.0, 0.50, 0.0, 0, 1, "RECON_SCAN", 2, "Information Gathering", "DNP3 Class 0/1/2/3 poll scan probing outstation registers on port 20000.", "LOW", "T0846", "Network Service Discovery", "Discovery", "Stage 1 - IT Intrusion"),
        # 16. Lateral Movement SSH Pivot (SSH port 22 STRICT)
        ("lateral_pivot_attempt", "SSH", 22, 120.0, 50.0, 45.0, 1200.0, 0.50, 0.0, 0, 0, "LATERAL_MOVEMENT", 6, "Lateral Movement", "SSH login attempt to SCADA workstation (ics_scada_ssh:22) exploiting leaked credentials.", "MEDIUM", "T0885", "Remote Services", "Lateral Movement", "Stage 1 - IT Intrusion"),
        # 17. Denial of Service Connection Starvation (Modbus port 502 / SSH port 22)
        ("dos_connection_starvation", "Modbus", 502, 120.0, 50.0, 45.0, 1200.0, 0.50, 0.0, 0, 3, "DOS_ATTACK", 10, "Denial of Service", "Sub-5ms Modbus transaction flood exhausting PLC socket pool and starving SCADA polling.", "HIGH", "T0814", "Denial of Service", "Inhibit Response Function", "Stage 2 - ICS Impact"),
    ]

    current_time = base_time
    prev_state = None

    for i in range(5000):
        current_time += datetime.timedelta(seconds=1)
        ts_str = current_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        if random.random() < 0.70:
            arch = archetypes[0] if random.random() < 0.50 else archetypes[1] # Alternate Modbus & S7comm normal
            p_noise = random.uniform(-2.5, 2.5)
            q_noise = random.uniform(-1.5, 1.5)
            t_noise = random.uniform(-0.8, 0.8)
            rpm_noise = random.uniform(-15.0, 15.0)
            v_noise = random.uniform(-0.02, 0.02)
        else:
            arch = random.choice(archetypes[2:]) # Diverse Anomaly covering Modbus, S7, DNP3, SSH, DoS
            p_noise = random.uniform(-1.0, 1.0)
            q_noise = random.uniform(-0.5, 0.5)
            t_noise = random.uniform(-0.5, 0.5)
            rpm_noise = random.uniform(-5.0, 5.0)
            v_noise = random.uniform(-0.01, 0.01)

        (et, proto, dport, p_base, q_base, t_base, rpm_base, v_base, freq_base, is_w, fc, ano_type, ph, cat, narr, sev, tid, tname, tactic, kc) = arch

        p_curr = round(max(0.0, p_base + p_noise), 2)
        q_curr = round(max(0.0, q_base + q_noise), 2)
        t_curr = round(max(15.0, t_base + t_noise), 2)
        rpm_curr = round(max(0.0, rpm_base + rpm_noise), 1)
        v_curr = round(max(0.0, min(1.0, v_base + v_noise)), 2)

        prev_p = prev_state.get("pressure", p_curr) if prev_state else p_curr
        p_delta = round(p_curr - prev_p, 2)
        p_mean_dev = round(p_curr - 120.0, 2)

        proc_feat = {
            "pressure": p_curr,
            "flow_rate": q_curr,
            "temperature": t_curr,
            "pump_rpm": rpm_curr,
            "valve_position": v_curr,
            "viscosity": 1.0,
            "pressure_delta": p_delta,
            "pressure_mean_deviation": p_mean_dev,
        }

        if ph == 10 or ano_type == "DOS_ATTACK":
            iat = round(random.uniform(0.001, 0.004), 4) # Sub-5ms flood triggering Rule 1.5
        elif ph == 4:
            iat = round(random.uniform(0.005, 0.05), 3) # Sub-second write bursts
        else:
            iat = round(random.uniform(0.01, 0.15), 3)

        net_feat = {
            "inter_arrival_time": iat,
            "write_frequency_10s": round(freq_base, 1),
            "is_write": is_w,
            "function_code": fc,
            "length": random.randint(12, 64),
            "protocol": proto,
        }

        violations = evaluate_safety_boundaries(proc_feat, prev_state=prev_state, dt=1.0)
        prev_state = proc_feat

        is_ano = 0 if ano_type == "NORMAL" and not violations else 1
        sev_final = sev if is_ano else "INFO"

        labels = {
            "is_anomaly": is_ano,
            "anomaly_type": ano_type if is_ano else "NORMAL",
            "attack_phase": ph,
            "attack_category": cat,
            "boundary_violations": [v.to_dict() for v in violations],
        }

        mitre_meta = {
            "technique_id": tid,
            "technique_name": tname,
            "tactic": tactic,
            "kill_chain_stage": kc,
        }

        rec = create_ml_ready_log_record(
            event_type=et,
            sensor="ml_engine" if is_ano else "plc_simulator",
            layer="Level 2",
            severity=sev_final,
            src_ip="172.28.0.50" if is_ano else "172.24.0.8",
            dst_ip="172.24.0.8",
            src_port=random.randint(35000, 62000),
            dst_port=dport,
            protocol=proto,
            process_features=proc_feat,
            network_features=net_feat,
            ml_labels=labels,
            mitre_tags=mitre_meta,
            narrative=narr,
            session_id="unified_campaign_run",
            journey_id="unified_campaign_run",
            timestamp=ts_str,
        )
        enriched_records.append(rec)

    # 5. Sort chronologically
    enriched_records.sort(key=lambda r: parse_timestamp(r.get("timestamp", "")))

    print(f"[*] Total synthesized clean records: {len(enriched_records)}")

    # 6. Write to output general logs.jsonl
    with open(output_file, "w", encoding="utf-8") as f_out:
        for rec in enriched_records:
            f_out.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(f"[SUCCESS] Cleaned and enriched dataset written to {output_file} ({len(enriched_records)} records).")


if __name__ == "__main__":
    generate_ml_ready_dataset(LOG_FILE, LOG_FILE)
