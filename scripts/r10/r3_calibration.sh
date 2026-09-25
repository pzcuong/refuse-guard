#!/usr/bin/env bash
# r10 wrapper: r3_calibration
#   ECE/Brier/threshold-sweep + class-weight remedy on the r2 probability
#   dump (all-malicious degenerate-mode analysis).  CPU-only.
#   Helper: scripts/r10/r3_calibration.py
#   Real run : scripts/r10/r3_calibration.sh
#   Dry run  : DRY=1 scripts/r10/r3_calibration.sh
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
export HF_HOME="$ROOT/models_dir/hf"
export HF_HUB_OFFLINE=1
LOG="$ROOT/outputs/packguard/r10/r3_calibration.log"
mkdir -p "$(dirname "$LOG")"
PY="$ROOT/.venv/bin/python"
if [ "${DRY:-0}" = "1" ]; then
  "$PY" scripts/r10/r3_calibration.py --dry 2>&1 | tee -a "$LOG"
  exit "${PIPESTATUS[0]}"
fi
exec "$PY" scripts/r10/r3_calibration.py >"$LOG" 2>&1
