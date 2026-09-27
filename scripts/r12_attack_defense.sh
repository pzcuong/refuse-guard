#!/usr/bin/env bash
# r12 wrapper (W1): attack + defense matrix
#   P2 advisory-in-package attack vs D1 (AST comment/docstring strip) defense.
#   30 malicious x {P0 cache, P2 cache, P2D1 new} + 15 benign x {P0 cache,
#   P2D1 new} x 2 models (<4B) = 90 NEW generations (~30-45 min GPU,
#   resume-safe). Pre-registered: docs/packguard_prereg.md AMENDMENT-6.
#   Runner: scripts/r12_attack_defense.py
#   Real run : scripts/r12_attack_defense.sh
#   Dry run  : DRY=1 scripts/r12_attack_defense.sh  (stub generator, 0 model
#              load, mock=true outputs under dry/)
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export HF_HOME="$ROOT/models_dir/hf"
export HF_HUB_OFFLINE=1
export PYTHONPATH="$ROOT"
LOG="$ROOT/outputs/packguard/defense/r12_attack_defense.log"
mkdir -p "$(dirname "$LOG")"
PY="$ROOT/.venv/bin/python"
if [ "${DRY:-0}" = "1" ]; then
  "$PY" scripts/r12_attack_defense.py --dry 2>&1 | tee -a "$LOG"
  exit "${PIPESTATUS[0]}"
fi
exec "$PY" scripts/r12_attack_defense.py >"$LOG" 2>&1
