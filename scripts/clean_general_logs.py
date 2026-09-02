#!/usr/bin/env python3
"""
clean_general_logs.py
=====================
Wrapper around clean_and_enrich_logs.py to clean, standardize, deduplicate,
and enrich `general logs.jsonl` with full network features, process features,
and multi-variable physical safety boundary evaluations.
"""

import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.clean_and_enrich_logs import LOG_FILE, generate_ml_ready_dataset

if __name__ == "__main__":
    generate_ml_ready_dataset(LOG_FILE, LOG_FILE)
