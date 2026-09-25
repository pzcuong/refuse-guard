#!/usr/bin/env bash
# r10 wrapper: r7_mechanism_ablation
#   Safety task-text mechanism ablation: 30 malicious samples x
#   {verbatim, paraphrase, scrambled} x 2 models = 180 generations (GPU
#   ~1.5-2 h, resume-safe).  Helper: scripts/r10/r7_mechanism_ablation.py
#   Real run : scripts/r10/r7_mechanism_ablation.sh
#   Dry run  : DRY=1 scripts/r10/r7_mechanism_ablation.sh  (stub generator,
#              0 model load, mock=true outputs)
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
export HF_HOME="$ROOT/models_dir/hf"
export HF_HUB_OFFLINE=1
LOG="$ROOT/outputs/packguard/r10/r7_mechanism_ablation.log"
mkdir -p "$(dirname "$LOG")"
PY="$ROOT/.venv/bin/python"
if [ "${DRY:-0}" = "1" ]; then
  "$PY" scripts/r10/r7_mechanism_ablation.py --dry 2>&1 | tee -a "$LOG"
  exit "${PIPESTATUS[0]}"
fi
exec "$PY" scripts/r10/r7_mechanism_ablation.py >"$LOG" 2>&1
