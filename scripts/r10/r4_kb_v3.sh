#!/usr/bin/env bash
# r10 wrapper: r4_kb_v3
#   KB-v3 features via FL/central — pure dict join over kb_v0002.jsonl
#   (142 entries, coverage 137/137), NO LLM, no generation.  CPU-only.
#   Helper: scripts/r10/r4_kb_v3_features.py
#   Real run : scripts/r10/r4_kb_v3.sh
#   Dry run  : DRY=1 scripts/r10/r4_kb_v3.sh   (join-only preview)
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
export HF_HOME="$ROOT/models_dir/hf"
export HF_HUB_OFFLINE=1
LOG="$ROOT/outputs/packguard/r10/r4_kb_v3.log"
mkdir -p "$(dirname "$LOG")"
PY="$ROOT/.venv/bin/python"
if [ "${DRY:-0}" = "1" ]; then
  "$PY" scripts/r10/r4_kb_v3_features.py --dry 2>&1 | tee -a "$LOG"
  exit "${PIPESTATUS[0]}"
fi
exec "$PY" scripts/r10/r4_kb_v3_features.py >"$LOG" 2>&1
