#!/usr/bin/env python3
"""
clean_general_logs.py
=====================
Cleans, standardizes, deduplicates, and sorts general logs.jsonl.
"""

import os
import json
import sys
from datetime import datetime

LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "general logs.jsonl")

EVENT_TYPE_MAPPING = {
    "API_ACCESS": "api_access",
    "TERMINAL_CMD": "terminal_command",
    "MITRE_STEP": "mitre_step",
    "INTERACTIVE_COMMAND": "interactive_command",
}

def parse_iso_ts(ts_str):
    if not ts_str:
        return datetime.min
    try:
        # Handle Z suffix
        clean_ts = ts_str.replace("Z", "+00:00")
        return datetime.fromisoformat(clean_ts)
    except Exception:
        return datetime.min

def clean_logs(file_path):
    if not os.path.exists(file_path):
        print(f"[ERROR] Log file not found: {file_path}")
        sys.exit(1)

    print(f"[CLEAN] Reading {file_path} ...")
    raw_lines = 0
    valid_records = []

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            raw_lines += 1
            line_str = line.strip()
            if not line_str:
                continue
            try:
                rec = json.loads(line_str)
                valid_records.append(rec)
            except Exception as e:
                print(f"[WARN] Skipping malformed line #{raw_lines}: {e}")

    print(f"[CLEAN] Parsed {len(valid_records)} valid JSON records from {raw_lines} total lines.")

    # 1. Standardize event types and clean text fields
    cleaned_records = []
    seen = set()
    dup_count = 0

    for rec in valid_records:
        et = rec.get("event_type", "")
        if et in EVENT_TYPE_MAPPING:
            rec["event_type"] = EVENT_TYPE_MAPPING[et]
        elif isinstance(et, str):
            rec["event_type"] = et.lower()

        # Deduplication key based on ts, sensor, event_type, src_ip, and meta detail/message
        ts = rec.get("ts", "")
        sensor = rec.get("sensor", "")
        event_type = rec.get("event_type", "")
        src_ip = rec.get("src_ip", "")
        meta = rec.get("meta", {})
        meta_sig = json.dumps(meta, sort_keys=True) if isinstance(meta, dict) else str(meta)

        dedup_key = (ts, sensor, event_type, src_ip, meta_sig)
        if dedup_key in seen:
            dup_count += 1
            continue
        seen.add(dedup_key)
        cleaned_records.append(rec)

    print(f"[CLEAN] Removed {dup_count} duplicate records.")

    # 2. Sort chronologically by timestamp
    cleaned_records.sort(key=lambda r: parse_iso_ts(r.get("ts", "")))

    # 3. Write back cleaned logs
    backup_path = file_path + ".bak"
    with open(backup_path, "w", encoding="utf-8") as f_bak:
        with open(file_path, "r", encoding="utf-8") as f_orig:
            f_bak.write(f_orig.read())

    with open(file_path, "w", encoding="utf-8") as f_out:
        for rec in cleaned_records:
            f_out.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(f"[CLEAN] Cleaned log written to {file_path} ({len(cleaned_records)} records). Backup saved to {backup_path}.")

if __name__ == "__main__":
    clean_logs(LOG_FILE)
