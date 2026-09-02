"""
shared/log_schema.py
====================
Standardized Hierarchical ML-Ready JSONL Event Schema Specification.

Adheres strictly to the clean, non-redundant nested architecture:
- timestamp, event_id
- event: {type, severity, narrative}
- context: {sensor, purdue_level, journey_id, session_id}
- network: {source: {ip, port}, destination: {ip, port}, protocol, inter_arrival_time, write_frequency_10s, is_write, function_code, length}
- process: {pressure, flow_rate, temperature, pump_rpm, valve_position, viscosity, pressure_delta, pressure_mean_deviation}
- ml_analysis: {is_anomaly, anomaly_type, attack_phase, attack_category, boundary_violations}
- mitre: {technique_id, technique_name, tactic}
- security: {kill_chain_stage}
"""

from __future__ import annotations

import datetime
import json
import uuid
from typing import Any

# Standard IANA / Industrial Protocol Port Assignments
PROTOCOL_PORT_MAP = {
    "MODBUS": 502,
    "S7COMM": 102,
    "DNP3": 20000,
    "SSH": 22,
    "HTTP": 8008,
}


def get_default_port_for_protocol(protocol: str) -> int:
    return PROTOCOL_PORT_MAP.get(protocol.upper(), 502)


def format_iso_timestamp(dt: datetime.datetime | None = None) -> str:
    if dt is None:
        dt = datetime.datetime.now(datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def create_ml_ready_log_record(
    event_type: str,
    sensor: str = "plc_simulator",
    layer: str = "Level 2",
    severity: str = "INFO",
    src_ip: str = "172.24.0.50",
    dst_ip: str = "172.24.0.8",
    src_port: int | None = None,
    dst_port: int | None = None,
    protocol: str = "Modbus",
    process_features: dict[str, Any] | None = None,
    network_features: dict[str, Any] | None = None,
    ml_labels: dict[str, Any] | None = None,
    mitre_tags: dict[str, Any] | None = None,
    narrative: str = "",
    session_id: str | None = None,
    journey_id: str | None = None,
    timestamp: str | None = None,
    extra_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Constructs a validated, hierarchical, non-redundant ML-ready event dictionary.
    """
    ts = timestamp or format_iso_timestamp()
    sess_id = session_id or str(uuid.uuid4())[:8]
    j_id = journey_id or sess_id

    # Enforce accurate protocol destination port
    proto_clean = protocol.capitalize() if protocol.lower() in {"modbus", "http", "ssh"} else protocol.upper()
    if dst_port is None or dst_port == 0:
        d_port = get_default_port_for_protocol(proto_clean)
    else:
        # Correct any mismatch if DNP3 / S7 was passed with port 502
        if proto_clean.upper() == "DNP3" and dst_port == 502:
            d_port = 20000
        elif proto_clean.upper() == "S7COMM" and dst_port == 502:
            d_port = 102
        else:
            d_port = dst_port

    s_port = src_port or 49152

    # Standardized Process Telemetry (x_proc)
    proc_dict = {
        "pressure": 120.0,
        "flow_rate": 50.0,
        "temperature": 45.0,
        "pump_rpm": 1200.0,
        "valve_position": 0.50,
        "viscosity": 1.0,
        "pressure_delta": 0.0,
        "pressure_mean_deviation": 0.0,
    }
    if process_features:
        # Handle field aliases cleanly
        if "valve_pos" in process_features and "valve_position" not in process_features:
            process_features["valve_position"] = process_features.pop("valve_pos")
        if "pressure_mean_dev" in process_features and "pressure_mean_deviation" not in process_features:
            process_features["pressure_mean_deviation"] = process_features.pop("pressure_mean_dev")
        proc_dict.update(process_features)

    # Standardized Network Telemetry (x_net)
    net_dict = {
        "source": {
            "ip": src_ip,
            "port": s_port,
        },
        "destination": {
            "ip": dst_ip,
            "port": d_port,
        },
        "protocol": proto_clean,
        "inter_arrival_time": 0.05,
        "write_frequency_10s": 0.0,
        "is_write": 0,
        "function_code": 3,
        "length": 20,
    }
    if network_features:
        if "write_freq_10s" in network_features and "write_frequency_10s" not in network_features:
            network_features["write_frequency_10s"] = network_features.pop("write_freq_10s")
        if "func_code" in network_features and "function_code" not in network_features:
            network_features["function_code"] = network_features.pop("func_code")
        
        for k in ["inter_arrival_time", "write_frequency_10s", "is_write", "function_code", "length", "protocol"]:
            if k in network_features:
                net_dict[k] = network_features[k]

    # Standardized ML Analysis & Ground Truth
    ml_dict = {
        "is_anomaly": 0,
        "anomaly_type": "NORMAL",
        "attack_phase": 0,
        "attack_category": "Normal Baseline",
        "boundary_violations": [],
    }
    if ml_labels:
        ml_dict.update(ml_labels)

    # Standardized MITRE ATT&CK Mapping
    mitre_dict = {
        "technique_id": "T0000",
        "technique_name": "Normal Operation",
        "tactic": "None",
    }
    if mitre_tags:
        for k in ["technique_id", "technique_name", "tactic"]:
            if k in mitre_tags:
                mitre_dict[k] = mitre_tags[k]

    # Standardized Security & Kill Chain Stage
    sec_dict = {
        "kill_chain_stage": (mitre_tags.get("kill_chain_stage", "Operational Baseline") if mitre_tags else "Operational Baseline"),
    }

    # Final Canonical Hierarchical Log Record
    record: dict[str, Any] = {
        "timestamp": ts,
        "event_id": str(uuid.uuid4()),
        "event": {
            "type": event_type.lower(),
            "severity": severity.upper(),
            "narrative": narrative or f"Event {event_type} observed from {src_ip}",
        },
        "context": {
            "sensor": sensor,
            "purdue_level": layer,
            "journey_id": j_id,
            "session_id": sess_id,
        },
        "network": net_dict,
        "process": proc_dict,
        "ml_analysis": ml_dict,
        "mitre": mitre_dict,
        "security": sec_dict,
    }

    return record
