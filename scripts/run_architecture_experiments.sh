#!/usr/bin/env bash
# Reproduce all IEEE TII architecture validation experiments.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="${PYTHON:-/home/mohamed-ayman/eval_env/bin/python3}"
DATA_DIR="${DATA_DIR:-$ROOT/results/20260701_161537}"

echo "=== Step 1: ML evaluation (evaluate.py — unchanged) ==="
"$PYTHON" "$ROOT/evaluate.py" --data-dir "$DATA_DIR"

echo "=== Step 2: Architecture validation suite ==="
"$PYTHON" "$ROOT/scripts/architecture_validation.py" --data-dir "$DATA_DIR"

echo "=== Done. See $ROOT/results/architecture_validation/ ==="
