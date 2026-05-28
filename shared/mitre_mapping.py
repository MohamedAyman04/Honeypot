"""
shared/mitre_mapping.py
=======================
Central MITRE ATT\u0026CK for ICS technique mapping table.

Consumed by:
  - logger/correlator.py   (network-layer events)
  - ml-engine/trainer.py   (ML anomaly events)

Each entry maps an internal event_type string to:
  mitre_tactic          – ATT\u0026CK for ICS tactic name
  mitre_technique_id    – Txxxx ID
  mitre_technique_name  – Human-readable technique name
  kill_chain_stage      – ICS Kill Chain stage
  purdue_level          – Purdue/ISA-95 level string
  protocol              – Network protocol involved (for dashboard filtering)

References:
  https://attack.mitre.org/matrices/ics/
  Assante \u0026 Lee, "The Industrial Control System Cyber Kill Chain" (SANS, 2015)
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Master mapping table
# Key: internal event_type  (must match tags written by correlator / ml_engine)
# ---------------------------------------------------------------------------
TECHNIQUE_MAP: dict[str, dict[str, str]] = {

    # ── Modbus TCP (Level 1/2) ──────────────────────────────────────────────
    "write_command": {
        "mitre_tactic":         "Impair Process Control",
        "mitre_technique_id":   "T0855",
        "mitre_technique_name": "Unauthorized Command Message",
        "kill_chain_stage":     "Stage 2 - ICS Impact",
        "purdue_level":         "Level 2",
        "protocol":             "Modbus",
    },
    "modbus_write": {
        "mitre_tactic":         "Impair Process Control",
        "mitre_technique_id":   "T0855",
        "mitre_technique_name": "Unauthorized Command Message",
        "kill_chain_stage":     "Stage 2 - ICS Impact",
        "purdue_level":         "Level 2",
        "protocol":             "Modbus",
    },
    "modbus_read": {
        "mitre_tactic":         "Collection",
        "mitre_technique_id":   "T0802",
        "mitre_technique_name": "Automated Collection",
        "kill_chain_stage":     "Stage 2 - ICS Impact",
        "purdue_level":         "Level 2",
        "protocol":             "Modbus",
    },
    "credential_discovery": {
        "mitre_tactic":         "Credential Access",
        "mitre_technique_id":   "T1005",
        "mitre_technique_name": "Data from Local System",
        "kill_chain_stage":     "Stage 1 - IT Intrusion",
        "purdue_level":         "Level 2",
        "protocol":             "SSH",
    },
    "lateral_movement": {
        "mitre_tactic":         "Lateral Movement",
        "mitre_technique_id":   "T0867",
        "mitre_technique_name": "Lateral Tool Transfer",
        "kill_chain_stage":     "Stage 1 - IT Intrusion",
        "purdue_level":         "Level 2",
        "protocol":             "SSH",
    },
    "network_scan": {
        "mitre_tactic":         "Reconnaissance",
        "mitre_technique_id":   "T1595",
        "mitre_technique_name": "Active Scanning",
        "kill_chain_stage":     "Stage 1 - IT Intrusion",
        "purdue_level":         "Level 2",
        "protocol":             "Modbus",
    },
    "terminal_cmd": {
        "mitre_tactic":         "Execution",
        "mitre_technique_id":   "T0807",
        "mitre_technique_name": "Command-Line Interface",
        "kill_chain_stage":     "Stage 1 - IT Intrusion",
        "purdue_level":         "Level 2",
        "protocol":             "SSH",
    },
    "forced_write": {
        "mitre_tactic":         "Impair Process Control",
        "mitre_technique_id":   "T0855",
        "mitre_technique_name": "Unauthorized Command Message",
        "kill_chain_stage":     "Stage 2 - ICS Impact",
        "purdue_level":         "Level 2",
        "protocol":             "Modbus",
    },
    "replay_attack": {
        "mitre_tactic":         "Impair Process Control",
        "mitre_technique_id":   "T0856",
        "mitre_technique_name": "Spoof Reporting Message",
        "kill_chain_stage":     "Stage 2 - ICS Impact",
        "purdue_level":         "Level 2",
        "protocol":             "Modbus",
    },

    # ── S7comm / Siemens (Level 2) ──────────────────────────────────────────
    "s7_connect": {
        "mitre_tactic":         "Initial Access",
        "mitre_technique_id":   "T0886",
        "mitre_technique_name": "Remote Services",
        "kill_chain_stage":     "Stage 2 - ICS Impact",
        "purdue_level":         "Level 2",
        "protocol":             "S7comm",
    },
    "s7_read": {
        "mitre_tactic":         "Collection",
        "mitre_technique_id":   "T0802",
        "mitre_technique_name": "Automated Collection",
        "kill_chain_stage":     "Stage 2 - ICS Impact",
        "purdue_level":         "Level 2",
        "protocol":             "S7comm",
    },
    "s7_write": {
        "mitre_tactic":         "Impair Process Control",
        "mitre_technique_id":   "T0855",
        "mitre_technique_name": "Unauthorized Command Message",
        "kill_chain_stage":     "Stage 2 - ICS Impact",
        "purdue_level":         "Level 2",
        "protocol":             "S7comm",
    },
    "s7_stop_cpu": {
        "mitre_tactic":         "Inhibit Response Function",
        "mitre_technique_id":   "T0816",
        "mitre_technique_name": "Device Restart/Shutdown",
        "kill_chain_stage":     "Stage 2 - ICS Impact",
        "purdue_level":         "Level 2",
        "protocol":             "S7comm",
    },

    # ── DNP3 (Level 1) ──────────────────────────────────────────────────────
    "dnp3_read": {
        "mitre_tactic":         "Collection",
        "mitre_technique_id":   "T0802",
        "mitre_technique_name": "Automated Collection",
        "kill_chain_stage":     "Stage 2 - ICS Impact",
        "purdue_level":         "Level 2",
        "protocol":             "DNP3",
    },
    "dnp3_write": {
        "mitre_tactic":         "Impair Process Control",
        "mitre_technique_id":   "T0855",
        "mitre_technique_name": "Unauthorized Command Message",
        "kill_chain_stage":     "Stage 2 - ICS Impact",
        "purdue_level":         "Level 2",
        "protocol":             "DNP3",
    },
    "dnp3_direct_operate": {
        "mitre_tactic":         "Impair Process Control",
        "mitre_technique_id":   "T0855",
        "mitre_technique_name": "Unauthorized Command Message",
        "kill_chain_stage":     "Stage 2 - ICS Impact",
        "purdue_level":         "Level 2",
        "protocol":             "DNP3",
    },
    "dnp3_unsolicited": {
        "mitre_tactic":         "Collection",
        "mitre_technique_id":   "T0802",
        "mitre_technique_name": "Automated Collection",
        "kill_chain_stage":     "Stage 2 - ICS Impact",
        "purdue_level":         "Level 2",
        "protocol":             "DNP3",
    },
    "S7COMM_PROBE": {
        "mitre_tactic":         "Discovery",
        "mitre_technique_id":   "T0846",
        "mitre_technique_name": "Network Service Discovery",
        "kill_chain_stage":     "Stage 1 - IT Intrusion",
        "purdue_level":         "Level 2",
        "protocol":             "S7comm",
    },
    "DNP3_PROBE": {
        "mitre_tactic":         "Discovery",
        "mitre_technique_id":   "T0846",
        "mitre_technique_name": "Network Service Discovery",
        "kill_chain_stage":     "Stage 1 - IT Intrusion",
        "purdue_level":         "Level 2",
        "protocol":             "DNP3",
    },

    # ── SSH / SCADA Workstation (Level 3) ───────────────────────────────────
    "ssh_login": {
        "mitre_tactic":         "Lateral Movement",
        "mitre_technique_id":   "T0812",
        "mitre_technique_name": "Default Credentials",
        "kill_chain_stage":     "Stage 1 - IT Intrusion",
        "purdue_level":         "Level 2",
        "protocol":             "SSH",
    },
    "ssh_bruteforce": {
        "mitre_tactic":         "Lateral Movement",
        "mitre_technique_id":   "T0812",
        "mitre_technique_name": "Default Credentials",
        "kill_chain_stage":     "Stage 1 - IT Intrusion",
        "purdue_level":         "Level 2",
        "protocol":             "SSH",
    },
    "ssh_command": {
        "mitre_tactic":         "Execution",
        "mitre_technique_id":   "T0807",
        "mitre_technique_name": "Command-Line Interface",
        "kill_chain_stage":     "Stage 1 - IT Intrusion",
        "purdue_level":         "Level 2",
        "protocol":             "SSH",
    },
    "ssh_recon": {
        "mitre_tactic":         "Discovery",
        "mitre_technique_id":   "T0842",
        "mitre_technique_name": "Network Sniffing",
        "kill_chain_stage":     "Stage 1 - IT Intrusion",
        "purdue_level":         "Level 2",
        "protocol":             "SSH",
    },

    # ── ML-engine anomaly types ──────────────────────────────────────────────
    "ISOLATION_FOREST": {
        "mitre_tactic":         "Impair Process Control",
        "mitre_technique_id":   "T0806",
        "mitre_technique_name": "Brute Force I/O",
        "kill_chain_stage":     "Stage 2 - ICS Impact",
        "purdue_level":         "Level 2",
        "protocol":             "Modbus",
    },
    "LSTM_AUTOENCODER": {
        "mitre_tactic":         "Impair Process Control",
        "mitre_technique_id":   "T0856",
        "mitre_technique_name": "Spoof Reporting Message",
        "kill_chain_stage":     "Stage 2 - ICS Impact",
        "purdue_level":         "Level 2",
        "protocol":             "Modbus",
    },
    "REPLAY_LSTM": {
        "mitre_tactic":         "Impair Process Control",
        "mitre_technique_id":   "T0856",
        "mitre_technique_name": "Spoof Reporting Message",
        "kill_chain_stage":     "Stage 2 - ICS Impact",
        "purdue_level":         "Level 2",
        "protocol":             "Modbus",
    },
    "SEMANTIC_INJECTION": {
        "mitre_tactic":         "Impair Process Control",
        "mitre_technique_id":   "T0855",
        "mitre_technique_name": "Unauthorized Command Message",
        "kill_chain_stage":     "Stage 2 - ICS Impact",
        "purdue_level":         "Level 2",
        "protocol":             "Modbus",
    },
    "CROSS_LAYER_ANOMALY": {
        "mitre_tactic":         "Evasion",
        "mitre_technique_id":   "T0820",
        "mitre_technique_name": "Exploitation for Evasion",
        "kill_chain_stage":     "Stage 2 - ICS Impact",
        "purdue_level":         "Level 2",
        "protocol":             "Modbus",
    },
    "STEALTH_DRIFT": {
        "mitre_tactic":         "Impair Process Control",
        "mitre_technique_id":   "T0836",
        "mitre_technique_name": "Modify Parameter",
        "kill_chain_stage":     "Stage 2 - ICS Impact",
        "purdue_level":         "Level 2",
        "protocol":             "Modbus",
    },
    "OVER_PRESSURE": {
        "mitre_tactic":         "Damage to Property",
        "mitre_technique_id":   "T0828",
        "mitre_technique_name": "Loss of Safety",
        "kill_chain_stage":     "Stage 2 - ICS Impact",
        "purdue_level":         "Level 0",
        "protocol":             "Modbus",
    },
    "DRIFT_ATTACK": {
        "mitre_tactic":         "Impair Process Control",
        "mitre_technique_id":   "T0836",
        "mitre_technique_name": "Modify Parameter",
        "kill_chain_stage":     "Stage 2 - ICS Impact",
        "purdue_level":         "Level 2",
        "protocol":             "Modbus",
    },
    "ZERO_VARIANCE": {
        "mitre_tactic":         "Impair Process Control",
        "mitre_technique_id":   "T0856",
        "mitre_technique_name": "Spoof Reporting Message",
        "kill_chain_stage":     "Stage 2 - ICS Impact",
        "purdue_level":         "Level 2",
        "protocol":             "Modbus",
    },
    "REPLAY_FINGERPRINT": {
        "mitre_tactic":         "Impair Process Control",
        "mitre_technique_id":   "T0856",
        "mitre_technique_name": "Spoof Reporting Message",
        "kill_chain_stage":     "Stage 2 - ICS Impact",
        "purdue_level":         "Level 2",
        "protocol":             "Modbus",
    },
}

# Fallback for unknown event types
_UNKNOWN: dict[str, str] = {
    "mitre_tactic":         "Unknown",
    "mitre_technique_id":   "T0000",
    "mitre_technique_name": "Unknown Technique",
    "kill_chain_stage":     "Unknown",
    "purdue_level":         "Unknown",
    "protocol":             "Unknown",
}


def lookup(event_type: str) -> dict[str, str]:
    """
    Return the ATT\u0026CK metadata dict for *event_type*.
    Falls back to _UNKNOWN if the key is not in the table.
    The returned dict is a shallow copy — safe to mutate.
    All events are tagged Purdue Level 2 for this honeypot deployment.
    """
    key = event_type.lower() if isinstance(event_type, str) else event_type
    result = dict(TECHNIQUE_MAP.get(key, TECHNIQUE_MAP.get(event_type, _UNKNOWN)))
    result["purdue_level"] = "Level 2"
    return result


def enrich_point(point, event_type: str):
    """
    Add MITRE ATT\u0026CK tags to an InfluxDB-client Point object in-place.
    All five fields are added as *tags* (indexed, filterable) except none
    are omitted so that existing field queries continue to work unchanged.

    Usage:
        from shared.mitre_mapping import enrich_point
        p = Point("correlation_logs").tag(...).field(...)
        enrich_point(p, "write_command")
        write_api.write(bucket=BUCKET, record=p)
    """
    meta = lookup(event_type)
    (point
     .tag("mitre_tactic",          meta["mitre_tactic"])
     .tag("mitre_technique_id",    meta["mitre_technique_id"])
     .tag("mitre_technique_name",  meta["mitre_technique_name"])
     .tag("kill_chain_stage",      meta["kill_chain_stage"])
     .tag("purdue_level",          meta["purdue_level"])
     .tag("protocol",              meta["protocol"]))
    return point
