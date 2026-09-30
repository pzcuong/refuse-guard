#!/bin/bash
# ============================================================================
# EVIDA pilot (round 17) — gated runner (prereg §5: tests BEFORE real run).
# Pre-registration: RESEARCH_STATE/PREREGISTRATIONS/prereg_EVIDA_..._.md
# (FROZEN 2026-09-30).  Stages: unit tests -> dry (MockLLM, no GPU) ->
# smoke (2 samples x 2 models, real, no stats claim) -> real pilot
# (units -> V_trusted generations -> EVIDA decisions -> analysis -> collector).
#
# Usage:  bash RESEARCH_STATE/gates/run_pilot.sh [--resume]
# Every stage is resumable (append-only LLM cache + per-stage artifacts);
# re-running skips completed generations (prompt-hash cache, prereg §1.8).
# ============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
PY=".venv/bin/python"
export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 HF_HOME="$ROOT/models_dir/hf"
export PYTHONPATH="$ROOT:$ROOT/scripts"
LOG_DIR="$ROOT/outputs/experiments/round17_evida"
mkdir -p "$LOG_DIR"
RESUME="${1:-}"

echo "== [0/4] prereg gate: filesystem freeze check =="
ls outputs/experiments/ | grep -i round17 || true

echo "== [1/4] unit tests (prereg §5: must PASS before real run) =="
$PY -m pytest tests/test_evida_pilot.py tests/test_packguard_defense.py -q || {
  echo "UNIT TESTS FAILED — real run BLOCKED (prereg §5)"; exit 1; }

echo "== [2/4] dry run (MockLLM, 0 GPU — plumbing only, no stats claim) =="
$PY - <<'EOF' || { echo "DRY FAILED"; exit 1; }
import warnings, sys, yaml, shutil
warnings.filterwarnings("ignore")
sys.path.insert(0, ".")
from pathlib import Path
from research_program.evida_runner import EvidaRunner
cfg = yaml.safe_load(open("configs/evida.yaml"))
cfg["out_dir"] = "outputs/experiments/round17_evida_dry"
cfg["dry_run"] = True
yaml.safe_dump(cfg, open("/tmp/evida_dry.yaml", "w"))
r = EvidaRunner(Path("/tmp/evida_dry.yaml"), dry=True)
r.stage_units(); r.stage_run(); r.stage_decide(); r.stage_analyze(); r.stage_collect()
print("[run_pilot] dry OK")
EOF

if [ -z "$RESUME" ] || [ "$RESUME" != "--resume" ]; then
  echo "== [3/4] smoke (2 samples x 2 models, REAL generations, no claim) =="
  $PY - <<'EOF' || { echo "SMOKE FAILED"; exit 1; }
import warnings, sys, yaml
warnings.filterwarnings("ignore")
sys.path.insert(0, ".")
from pathlib import Path
from research_program.evida_runner import EvidaRunner
cfg = yaml.safe_load(open("configs/evida.yaml"))
cfg["out_dir"] = "outputs/experiments/round17_evida_smoke"
cfg["dry_run"] = False
yaml.safe_dump(cfg, open("/tmp/evida_smoke.yaml", "w"))
r = EvidaRunner(Path("/tmp/evida_smoke.yaml"), limit=2)
r.stage_units(); r.stage_run(); r.stage_decide(); r.stage_analyze()
print("[run_pilot] smoke OK (no statistical claim)")
EOF
else
  echo "== [3/4] smoke SKIPPED (--resume: already on disk) =="
fi

echo "== [4/4] REAL pilot (fixed-n; checkpoint/resume-safe) =="
echo "   log: $LOG_DIR/pilot_run.log"
$PY -m src.experiments.run_evida --config configs/evida.yaml --stage all \
    >> "$LOG_DIR/pilot_run.log" 2>&1
rc=$?
tail -5 "$LOG_DIR/pilot_run.log"
echo "== pilot runner exit code: $rc =="
exit $rc
