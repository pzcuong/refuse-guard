#!/usr/bin/env bash
# r10 wrapper: r6_granite_ladder
#   granite-3.3-2b-instruct vulnerability-domain ladder A0/A5/A1 + benign
#   FP-check (60 vul + 30 ben) = 240 generations on ONE shared model, via
#   the audited round-9 runner (round9_ladder, reusing round7_7b machinery)
#   with configs/r10_granite_ladder.yaml.  GPU ~45 min, resume-safe.
#   Real run : scripts/r10/r6_granite_ladder.sh              (--stage queue)
#   Dry run  : DRY=1 scripts/r10/r6_granite_ladder.sh        (--stage dry,
#              MockLLM end-to-end, 0 GPU)
#   Metrics afterwards (not part of this wrapper):
#     .venv/bin/python -m src.experiments.round9_ladder \
#       --config configs/r10_granite_ladder.yaml --stage metrics
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
export HF_HOME="$ROOT/models_dir/hf"
export HF_HUB_OFFLINE=1
export PYTHONPATH="$ROOT"
LOG="$ROOT/outputs/packguard/r10/r6_granite_ladder.log"
mkdir -p "$(dirname "$LOG")"
PY="$ROOT/.venv/bin/python"
CFG=configs/r10_granite_ladder.yaml
if [ "${DRY:-0}" = "1" ]; then
  "$PY" -m src.experiments.round9_ladder --config "$CFG" --stage dry 2>&1 | tee -a "$LOG"
  exit "${PIPESTATUS[0]}"
fi
exec "$PY" -m src.experiments.round9_ladder --config "$CFG" --stage queue >"$LOG" 2>&1
