#!/usr/bin/env bash
# r10 wrapper: r8_safety_expand
#   Safety batch expansion n=60 -> n=100: 40 NEW samples x 3 arms x 2 models
#   = 240 generations (GPU ~2 h, resume-safe), merged with the 360 n60
#   records -> safety_metrics_n100.json.  Helper:
#   scripts/r10/r8_safety_expand.py
#   Real run : scripts/r10/r8_safety_expand.sh
#   Dry run  : DRY=1 scripts/r10/r8_safety_expand.sh  (stub generator,
#              0 model load, mock=true outputs)
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
export HF_HOME="$ROOT/models_dir/hf"
export HF_HUB_OFFLINE=1
LOG="$ROOT/outputs/packguard/r10/r8_safety_expand.log"
mkdir -p "$(dirname "$LOG")"
PY="$ROOT/.venv/bin/python"
if [ "${DRY:-0}" = "1" ]; then
  "$PY" scripts/r10/r8_safety_expand.py --dry 2>&1 | tee -a "$LOG"
  exit "${PIPESTATUS[0]}"
fi
exec "$PY" scripts/r10/r8_safety_expand.py >"$LOG" 2>&1
