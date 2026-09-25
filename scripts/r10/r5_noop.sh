#!/usr/bin/env bash
# r10 wrapper: r5_noop
#   NOOP BY DESIGN — mid-round ChatGPT consultation round; no experiment
#   runs.  The only action is appending the noop marker to the round log.
#   Run: scripts/r10/r5_noop.sh  (DRY=1 behaves identically — nothing heavy)
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
export HF_HOME="$ROOT/models_dir/hf"
export HF_HUB_OFFLINE=1
LOG="$ROOT/outputs/packguard/r10/r5_noop.log"
mkdir -p "$(dirname "$LOG")"
# exactly one command: append the noop marker (exit code 0)
printf '%s [r5_noop] NOOP by design — mid-round ChatGPT consultation round; no experiment command (DRY=%s)\n' "$(date -u +%FT%TZ)" "${DRY:-0}" >>"$LOG"
exit 0
