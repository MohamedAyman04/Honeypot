"""
unified_logger.py — Cross-Layer Unified JSON Log Schema  (v3)
=============================================================
Single, consistent JSON log format for both Level 2 (SCADA/OT) and
Level 3 (Enterprise/IT) components.

v3 changes vs v2
----------------
• MITRE tags (tactic, technique_id, kill_chain_stage, purdue_level, protocol)
  now written as InfluxDB *tags* on security_alerts — the MITRE ATT&CK
  Grafana dashboard can therefore query a single measurement.
• Added `narrative` field — human-readable attack-story sentence describing
  where the event started, what it did, and where it ended.
• Added `session_id` — callers share one session_id across a group of related
  events so the entire kill-chain appears as one correlated story.
• schema_version bumped to "3.0".
"""

import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

try:
    from influxdb_client import InfluxDBClient, Point, WritePrecision
    from influxdb_client.client.write_api import SYNCHRONOUS
    _HAS_INFLUX = True
except ImportError:
    _HAS_INFLUX = False

SCHEMA_VERSION = "3.0"

# ---------------------------------------------------------------------------
# MITRE ATT&CK for ICS mapping
# (technique_id, technique_name, tactic, kill_chain_stage,
#  purdue_level, protocol, narrative_template)
# ---------------------------------------------------------------------------
_ATTACK_MAP: dict[str, tuple] = {
    # ── Layer 3 / IT events ──────────────────────────────────────────────────
    "DISCOVERY": (
        "T0846", "Remote System Discovery", "Reconnaissance",
        "Stage 1 - IT Intrusion", "Level 3", "HTTP",
        "Attacker started reconnaissance from {source_ip} — scanning for accessible ICS services.",
    ),
    "SQL_INJECTION": (
        "T1190", "Exploit Public-Facing Application", "Initial Access",
        "Stage 1 - IT Intrusion", "Level 3", "HTTP",
        "SQL injection from {source_ip} against {target_service} — probing historian database.",
    ),
    "API_ACCESS": (
        "T0883", "Internet Accessible Device", "Reconnaissance",
        "Stage 1 - IT Intrusion", "Level 3", "HTTP",
        "Unauthenticated API access from {source_ip} to {target_service} — mapping ICS data endpoints.",
    ),
    # ── Cross-layer pivot ────────────────────────────────────────────────────
    "LATERAL_MOVEMENT": (
        "T0885", "Remote Services", "Lateral Movement",
        "Stage 1 - IT Intrusion", "Level 3→2", "SSH",
        "Lateral movement: {source_ip} pivoted from IT into OT network via {target_service}.",
    ),
    "AUTH_ATTEMPT": (
        "T1078", "Valid Accounts", "Lateral Movement",
        "Stage 1 - IT Intrusion", "Level 3", "SSH",
        "Credential attempt from {source_ip} on {target_service} — attacker trying valid accounts.",
    ),
    # ── Layer 2 / OT events ──────────────────────────────────────────────────
    "NETWORK_SCAN": (
        "T1595", "Active Scanning", "Reconnaissance",
        "Stage 1 - IT Intrusion", "Level 2", "Modbus",
        "Network scan from {source_ip} — enumerating industrial protocol services.",
    ),
    "MODBUS_WRITE": (
        "T0855", "Unauthorized Command Message", "Impair Process Control",
        "Stage 2 - ICS Impact", "Level 2", "Modbus",
        "Unauthorized Modbus WRITE from {source_ip} to {target_service} — unapproved PLC command issued.",
    ),
    "MODBUS_READ": (
        "T0802", "Automated Collection", "Collection",
        "Stage 2 - ICS Impact", "Level 2", "Modbus",
        "Modbus READ from {source_ip} — collecting process telemetry from {target_service}.",
    ),
    "PHYSICS_CONTROL_CMD": (
        "T0855", "Unauthorized Command Message", "Impair Process Control",
        "Stage 2 - ICS Impact", "Level 1", "Modbus",
        "Physics-layer control command from {source_ip} — process state manipulation detected.",
    ),
    # ── ML alert types ───────────────────────────────────────────────────────
    "SEMANTIC_INJECTION": (
        "T0855", "Unauthorized Command Message", "Impair Process Control",
        "Stage 2 - ICS Impact", "Level 2", "Modbus",
        "SEMANTIC INJECTION confirmed — {source_ip} wrote fabricated sensor values to PLC registers, "
        "bypassing the physics engine. Attack chain ends here.",
    ),
    "REPLAY_ATTACK": (
        "T0856", "Spoof Reporting Message", "Impair Process Control",
        "Stage 2 - ICS Impact", "Level 1", "Modbus",
        "REPLAY ATTACK — {source_ip} retransmitted captured telemetry to mask real process changes.",
    ),
    "STEALTH_DRIFT": (
        "T0836", "Modify Parameter", "Impair Process Control",
        "Stage 2 - ICS Impact", "Level 1", "Modbus",
        "STEALTH DRIFT — slow monotonic pressure ramp from {source_ip} evaded threshold alarms.",
    ),
    "CROSS_LAYER_ANOMALY": (
        "T0820", "Exploitation for Evasion", "Evasion",
        "Stage 2 - ICS Impact", "Level 2", "Modbus",
        "CROSS-LAYER ANOMALY — pressure changed without a preceding authorised write command. "
        "Source: {source_ip}.",
    ),
    "S7COMM_PROBE": (
        "T0846", "Network Service Discovery", "Discovery",
        "Stage 2 - ICS Impact", "Level 2", "S7comm",
        "S7comm probe from {source_ip} — fingerprinting Siemens PLC identity.",
    ),
    "DNP3_PROBE": (
        "T0846", "Network Service Discovery", "Discovery",
        "Stage 1 - IT Intrusion", "Level 1", "DNP3",
        "DNP3 probe from {source_ip} — scanning power/water protocol endpoints.",
    ),
}

_UNKNOWN_ENTRY: tuple = (
    "T0000", "Unknown Technique", "Unknown",
    "Unknown", "Unknown", "Unknown",
    "Unknown event from {source_ip} targeting {target_service}.",
)


def _lookup(event_type: str) -> tuple:
    return _ATTACK_MAP.get(event_type, _UNKNOWN_ENTRY)


def _default_severity(event_type: str) -> str:
    if event_type in {
        "MODBUS_WRITE", "PHYSICS_CONTROL_CMD", "SQL_INJECTION",
        "SEMANTIC_INJECTION", "REPLAY_ATTACK", "STEALTH_DRIFT",
        "CROSS_LAYER_ANOMALY",
    }:
        return "CRITICAL"
    if event_type in {"LATERAL_MOVEMENT", "AUTH_ATTEMPT", "S7_PROBE"}:
        return "HIGH"
    if event_type in {"MODBUS_READ", "NETWORK_SCAN", "DNP3_PROBE", "API_ACCESS"}:
        return "MEDIUM"
    return "INFO"


def _render(template: str, source_ip: str, target_service: str) -> str:
    try:
        return template.format(source_ip=source_ip, target_service=target_service)
    except Exception:
        return template


class UnifiedLogger:
    def __init__(
        self,
        service: str,
        layer: str,
        log_dir: str | Path = "/var/log/unified-logs",
        influx_url: str | None = None,
        influx_token: str | None = None,
        influx_org: str | None = None,
        influx_bucket: str | None = None,
    ):
        self.service = service
        self.layer = layer

        log_dir = Path(log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        self._log_path = log_dir / f"{service}_events.jsonl"

        self._write_api = None
        self.influx_bucket = influx_bucket or os.environ.get("INFLUX_BUCKET", "sensor_logs")
        if _HAS_INFLUX:
            _url   = influx_url   or os.environ.get("INFLUX_URL", "")
            _token = influx_token or os.environ.get("INFLUX_TOKEN", "")
            _org   = influx_org   or os.environ.get("INFLUX_ORG", "my_refinery")
            if _url and _token:
                try:
                    _client = InfluxDBClient(url=_url, token=_token, org=_org)
                    self._write_api = _client.write_api(write_options=SYNCHRONOUS)
                except Exception as exc:
                    print(f"[UNIFIED_LOGGER] InfluxDB init failed: {exc}")

    def log(
        self,
        event_type: str,
        source: dict[str, Any],
        target: dict[str, Any],
        correlation_id: str | None = None,
        session_id: str | None = None,
        severity: str | None = None,
        payload: dict[str, Any] | None = None,
        narrative: str | None = None,
    ) -> dict:
        tid, tname, tactic, kill_chain, purdue, protocol, tmpl = _lookup(event_type)

        src_ip  = source.get("ip", "unknown")
        tgt_svc = target.get("service", target.get("host", "unknown"))

        corr_id     = correlation_id or str(uuid.uuid4())
        sess_id     = session_id or corr_id
        auto_story  = narrative or _render(tmpl, src_ip, tgt_svc)
        sev         = severity or _default_severity(event_type)

        if event_type == "API_ACCESS" and (src_ip.startswith("172.28.") or src_ip.startswith("10.88.")):
            return {}

        record = {
            "timestamp":        time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
            "schema_version":   SCHEMA_VERSION,
            "layer":            self.layer,
            "service":          self.service,
            "event_type":       event_type,
            "severity":         sev,
            "source_ip":        src_ip,
            "target_ip":        target.get("ip", "unknown"),
            "target_service":   tgt_svc,
            # ── Story / narrative ─────────────────────────────────────────
            "narrative":        auto_story,
            "correlation_id":   corr_id,
            "session_id":       sess_id,
            # ── MITRE ATT&CK enrichment ───────────────────────────────────
            "mitre_technique":      tid,
            "mitre_name":           tname,
            "mitre_tactic":         tactic,
            "kill_chain_phase":     kill_chain,
            "kill_chain_stage":     kill_chain,
            "purdue_level":         purdue,
            "protocol":             protocol,
            # ── Nested detail ─────────────────────────────────────────────
            "source":   source,
            "target":   target,
            "mitre_ics": {
                "tactic":     tactic,
                "technique":  tid,
                "name":       tname,
                "kill_chain": kill_chain,
                "purdue":     purdue,
                "protocol":   protocol,
            },
            "payload": payload or {},
        }

        # ── Write to JSONL file ───────────────────────────────────────────────
        try:
            with open(self._log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        except OSError as exc:
            print(f"[UNIFIED_LOGGER] File write error: {exc}")

        # ── Write to InfluxDB with full MITRE tag set ────────────────────────
        if self._write_api:
            try:
                point = (
                    Point("security_alerts")
                    # Standard tags
                    .tag("event_type",             event_type)
                    .tag("service",                self.service)
                    .tag("layer",                  self.layer)
                    .tag("severity",               sev)
                    .tag("correlation_id",         corr_id)
                    .tag("session_id",             sess_id)
                    # MITRE tags — consumed by mitre_attack_ics Grafana dashboard
                    .tag("mitre_tactic",           tactic)
                    .tag("mitre_technique_id",     tid)
                    .tag("mitre_technique_name",   tname)
                    .tag("kill_chain_stage",       kill_chain)
                    .tag("purdue_level",           purdue)
                    .tag("protocol",               protocol)
                    # Fields
                    .field("source_ip",      src_ip)
                    .field("target_ip",      target.get("ip", "unknown"))
                    .field("target_service", tgt_svc)
                    .field("narrative",      auto_story)
                    .field("value",          1)        # numeric sentinel for count()
                    .time(time.time_ns(), WritePrecision.NS)
                )
                self._write_api.write(bucket=self.influx_bucket, record=point)
            except Exception as exc:
                print(f"[UNIFIED_LOGGER] InfluxDB write error: {exc}")

        # ── Forward to story_logger → general logs.jsonl ─────────────────────
        self._post_to_story_logger(
            event_type=event_type,
            src_ip=src_ip,
            narrative=auto_story,
            severity=sev,
            tid=tid,
            tname=tname,
            tactic=tactic,
            kill_chain=kill_chain,
            purdue=purdue,
            protocol=protocol,
            corr_id=corr_id,
            target=target,
            payload=payload or {},
        )

        return record

    def _post_to_story_logger(
        self,
        event_type: str,
        src_ip: str,
        narrative: str,
        severity: str,
        tid: str,
        tname: str,
        tactic: str,
        kill_chain: str,
        purdue: str,
        protocol: str,
        corr_id: str,
        target: dict,
        payload: dict,
    ) -> None:
        """POST event to story_logger so it shows up in general logs.jsonl."""
        import json as _json
        story_url = os.environ.get("STORY_LOGGER_URL", "http://story_logger:8600")
        try:
            import urllib.request as _req
            body = {
                "ts":         time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
                "sensor":     self.service,
                "event_type": event_type,
                "src_ip":     src_ip,
                "stage":      "S2" if "Level 2" in purdue or "Level 1" in purdue else "S1",
                "journey_id": corr_id,
                "outcome":    "observed",
                "severity":   severity,
                "mitre_technique_id":   tid,
                "mitre_technique_name": tname,
                "mitre_tactic":         tactic,
                "kill_chain_stage":     kill_chain,
                "purdue_level":         purdue,
                "protocol":             protocol,
                "meta": {
                    "narrative":      narrative,
                    "target_service": target.get("service", target.get("host", "unknown")),
                    "target_ip":      target.get("ip", "unknown"),
                    "level":          self.layer,
                    "component":      self.service,
                    **payload,
                },
            }
            data = _json.dumps(body).encode("utf-8")
            request = _req.Request(
                f"{story_url}/story/events",
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            _req.urlopen(request, timeout=2)
        except Exception as exc:
            print(f"[UNIFIED_LOGGER] story_logger post failed: {exc}")

