#!/usr/bin/env bash
# r10 wrapper: r1_stabilized_central
#   Centralized lr sweep {0.01, 0.03, 0.1} + early-stop on train-only CV,
#   20 seeds (configs/packguard_fl.yaml grid.seeds), all splits/blocks.
#   CPU-only.  Helper: scripts/r10/r1_stabilized_central.py
#   Real run : scripts/r10/r1_stabilized_central.sh
#   Dry run  : DRY=1 scripts/r10/r1_stabilized_central.sh
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
export HF_HOME="$ROOT/models_dir/hf"
export HF_HUB_OFFLINE=1
LOG="$ROOT/outputs/packguard/r10/r1_stabilized_central.log"
mkdir -p "$(dirname "$LOG")"
PY="$ROOT/.venv/bin/python"
if [ "${DRY:-0}" = "1" ]; then
  "$PY" scripts/r10/r1_stabilized_central.py --dry 2>&1 | tee -a "$LOG"
  exit "${PIPESTATUS[0]}"
fi
exec "$PY" scripts/r10/r1_stabilized_central.py >"$LOG" 2>&1
