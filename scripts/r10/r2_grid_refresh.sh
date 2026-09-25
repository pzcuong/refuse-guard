#!/usr/bin/env bash
# r10 wrapper: r2_grid_refresh
#   Re-runs the registered 20-seed grid (--grid, packguard.eval) after r1
#   into outputs/packguard/r10/fl_multiseed/ + dumps per-sample centralized
#   probabilities to probs_dump.jsonl for r3.  CPU-only.
#   Helper: scripts/r10/r2_grid_refresh.py
#   Real run : scripts/r10/r2_grid_refresh.sh
#   Dry run  : DRY=1 scripts/r10/r2_grid_refresh.sh
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
export HF_HOME="$ROOT/models_dir/hf"
export HF_HUB_OFFLINE=1
LOG="$ROOT/outputs/packguard/r10/r2_grid_refresh.log"
mkdir -p "$(dirname "$LOG")"
PY="$ROOT/.venv/bin/python"
if [ "${DRY:-0}" = "1" ]; then
  "$PY" scripts/r10/r2_grid_refresh.py --dry 2>&1 | tee -a "$LOG"
  exit "${PIPESTATUS[0]}"
fi
exec "$PY" scripts/r10/r2_grid_refresh.py >"$LOG" 2>&1
