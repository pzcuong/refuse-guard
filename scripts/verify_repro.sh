#!/usr/bin/env bash
# verify_repro.sh — RefuseGuard end-to-end SMOKE check (owner: A3, Round 4;
# hardened by S, Round 4: strict pytest parsing, value checks, artifact manifest).
#
# Verifies the pipeline is intact WITHOUT training or LLM generation:
#   1. full pytest suite (no model downloads; unit/regression tests only)
#      — STRICT: requires "N passed" AND zero failed tests (V2-R4 BUG-2 fix)
#   2. config-driven E2 runner in --dry-run mode (no LLM calls)
#   3. master-results check: every artifact the paper cites exists and parses
#   4. value checks on the paper's decision-critical numbers (S-R4):
#      master rows >= 340, gate verdict FAIL, E8-Llama recomputed B0 = 1/30,
#      E6 vulnerable-only stratum n.s. row present
#   5. artifact integrity: SHA256 manifest check (outputs/master/
#      ARTIFACT_MANIFEST.sha256; regenerate with scripts/make_manifest.py)
#   6. tectonic compile check of paper/main.tex -> paper/compiled/main.pdf
# Each step is bounded (~2 min); the whole script typically runs in ~3-4 min.
#
# Usage:  bash scripts/verify_repro.sh          (from repo root, or anywhere —
#                                                the script resolves the root)

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PY="$ROOT/.venv/bin/python"
export HF_HOME="$ROOT/models_dir/hf"

pass=0; fail=0
step()  { printf '\n=== [%s] %s\n' "$1" "$2"; }
ok()    { printf '    PASS: %s\n' "$1"; pass=$((pass+1)); }
bad()   { printf '    FAIL: %s\n' "$1"; fail=$((fail+1)); }

step 1 "pytest suite (strict parse: N passed and 0 failed)"
pytest_out="$("$PY" -m pytest tests/ -q 2>&1 | tail -1)"
printf '%s\n' "$pytest_out"
n_passed="$(printf '%s' "$pytest_out" | grep -Eo '\b([0-9]+) passed' | grep -Eo '[0-9]+' | head -1)"
if [ -z "$n_passed" ]; then
  bad "pytest: no 'N passed' in final line ('$pytest_out')"
elif printf '%s' "$pytest_out" | grep -Eq '\b([1-9][0-9]*) failed'; then
  bad "pytest: ${n_passed} passed but at least one test FAILED ('$pytest_out')"
else
  ok "pytest: ${n_passed} passed, 0 failed"
fi

step 2 "E2 dry-run (no LLM calls, config-driven runner)"
if "$PY" -m src.experiments.run_e2 --config configs/e2.yaml --dry-run >/tmp/rg_e2_dry.log 2>&1; then
  ok "run_e2 --dry-run: $(tail -1 /tmp/rg_e2_dry.log)"
else
  bad "run_e2 --dry-run (see /tmp/rg_e2_dry.log)"
fi

step 3 "master results exist + valid JSON/JSONL"
ARTIFACTS=(
  "outputs/master/master_results.json"
  "outputs/experiments/round3_e0/gate_verdict.json"
  "data/benchmarks/safety_contrast_v1.json"
  "data/manifests/eval_subset_round1.json"
  "data/manifests/eval_subset_v2.json"
  "data/benchmarks/e0_prompts_v1.jsonl"
  "outputs/experiments/round3_e0/qwen3b/results.json"
  "outputs/experiments/round3_e0/llama3b/results.json"
  "outputs/experiments/round3_e0/granite2b/results.json"
  "outputs/experiments/round3_e0/summary.json"
  "outputs/experiments/round3_e2e3/qwen3b/results.json"
  "outputs/experiments/round3_e2e3/llama3b/results.json"
  "outputs/experiments/round3_e5/results.json"
  "outputs/experiments/round3_e6/results.json"
  "outputs/experiments/round3_e7/e7_fusion_results.json"
  "outputs/experiments/round3_e8/results.json"
  "outputs/experiments/round3_e8/recomputed/recompute_e8_monitor.json"
  "outputs/experiments/round3_e8_llama3b/recomputed/recompute_e8_monitor.json"
  "outputs/transformer/codebert_eval_vd_s_metrics.json"
  "outputs/transformer/codebert_predictions_paired.jsonl"
  "outputs/transformer/fallback_threshold.json"
  "outputs/transformer/final_eval.json"
  "outputs/master/round5_master.json"
  "outputs/master/round6_bias.json"
  "outputs/master/round6_ablation.json"
)
for a in "${ARTIFACTS[@]}"; do
  if [ ! -f "$ROOT/$a" ]; then bad "missing: $a"; continue; fi
  if "$PY" - "$ROOT/$a" <<'EOF'
import json, sys
p = sys.argv[1]
if p.endswith(".jsonl"):
    with open(p, encoding="utf-8") as fh:
        json.loads(fh.readline())
else:
    json.load(open(p, encoding="utf-8"))
EOF
  then ok "ok: $a"; else bad "unparseable: $a"; fi
done

step 4 "value checks on decision-critical numbers (S-R4)"
if "$PY" - <<'EOF'
import json, sys

errors = []

# (a) master_results.json parses and has >= 340 verified rows
master = json.load(open("outputs/master/master_results.json", encoding="utf-8"))
rows = master["results"]
if len(rows) < 340:
    errors.append(f"master rows = {len(rows)} (< 340)")
by_metric = {r["metric"]: r for r in rows}

# (b) official 3-model E0 gate verdict == FAIL
verdict = json.load(open("outputs/experiments/round3_e0/gate_verdict.json",
                         encoding="utf-8"))
if verdict.get("verdict") != "FAIL":
    errors.append(f"gate verdict = {verdict.get('verdict')!r} (expected FAIL)")
if verdict.get("models_completed") != 3 or verdict.get("models_pass") != 0:
    errors.append(f"gate completed/pass = {verdict.get('models_completed')}/"
                  f"{verdict.get('models_pass')} (expected 3/0)")

# (c) E8-Llama recomputed B0 unsafe compliance == 1/30 (0.0333...), P2 == 0
rec = json.load(open("outputs/experiments/round3_e8_llama3b/recomputed/"
                     "recompute_e8_monitor.json", encoding="utf-8"))
b0 = rec["summary"]["B0"]["unsafe_compliance_rate"]
if abs(b0 - 1 / 30) > 1e-9:
    errors.append(f"e8 llama recomputed B0 = {b0} (expected {1/30})")
if rec["summary"]["P2"]["unsafe_compliance_rate"] != 0.0:
    errors.append("e8 llama recomputed P2 != 0.0")

# (d) master E6 row: vulnerable-only discordant stratum is n.s. (mcnemar_p=0.5)
row = by_metric.get("e6.discordant.vul_only_b01_b10_p")
if row is None:
    errors.append("master missing e6.discordant.vul_only_b01_b10_p")
elif row["value"].get("mcnemar_p") != 0.5:
    errors.append(f"e6 vul-only mcnemar_p = {row['value'].get('mcnemar_p')} (expected 0.5 n.s.)")

# (e) master gate rows corroborate the verdict file
if by_metric.get("e0.gate.verdict", {}).get("value") != "FAIL":
    errors.append("master e0.gate.verdict != FAIL")

# (f) Round-7: RQ8 verdicts + RQ9 harm-absent at 7B (S-R7)
r7 = json.load(open("outputs/master/round7_master.json", encoding="utf-8"))["results"]
by7 = {r["metric"]: r for r in r7}
if len(r7) < 130:
    errors.append(f"round7 master rows = {len(r7)} (< 130)")
g = by7.get("verdict.RQ8.granite2b.label")
if not (isinstance(g, dict) and "GENERALIZES" in str(g.get("value"))):
    errors.append(f"RQ8 granite label = {g} (expected GENERALIZES...)")
l = by7.get("verdict.RQ8.llama3b.label")
if not (isinstance(l, dict) and "GENERALIZES" in str(l.get("value"))):
    errors.append(f"RQ8 llama label = {l} (expected GENERALIZES-pooled-driven...)")
p5 = by7.get("scale.qwen7b.A5.mcnemar_p_vs_A0")
if not (isinstance(p5, dict) and abs(float(p5["value"]) - 0.7265625) < 1e-6):
    errors.append(f"RQ9 A5 vs A0 mcnemar_p = {p5} (expected 0.7265625 -> harm absent at 7B)")
a0 = by7.get("scale.qwen7b.A0.recall_vul")
if not (isinstance(a0, dict) and abs(float(a0["value"]) - 0.4746) < 1e-3):
    errors.append(f"RQ9 A0 recall = {a0} (expected ~0.4746)")

for e in errors:
    print(f"  VALUE-CHECK ERROR: {e}", file=sys.stderr)
if errors:
    sys.exit(1)
print(f"  master rows={len(rows)}; gate=FAIL (3 completed / 0 pass); "
      f"e8-llama B0={b0:.4f} (=1/30); e6 vul-only p=0.5 n.s.; "
      f"RQ8 GENERALIZES x2; RQ9 harm-absent@7B (p={float(p5['value']):.4f})")
EOF
then ok "decision-critical values match outputs"
else bad "value checks (see errors above)"
fi

step 5 "artifact integrity manifest (sha256)"
if [ ! -f "$ROOT/outputs/master/ARTIFACT_MANIFEST.sha256" ]; then
  bad "outputs/master/ARTIFACT_MANIFEST.sha256 missing (run scripts/make_manifest.py)"
elif "$PY" scripts/make_manifest.py --check; then
  ok "ARTIFACT_MANIFEST.sha256 verified"
else
  bad "manifest check failed (regenerate with scripts/make_manifest.py after re-runs)"
fi

step 6 "tectonic compile check (paper/main.tex)"
if command -v tectonic >/dev/null 2>&1; then
  if tectonic --outdir paper/compiled paper/main.tex >/tmp/rg_tectonic.log 2>&1 \
     && [ -f paper/compiled/main.pdf ]; then
    ok "paper/compiled/main.pdf written ($(du -h paper/compiled/main.pdf | cut -f1))"
  else
    bad "tectonic compile (see /tmp/rg_tectonic.log)"
  fi
else
  bad "tectonic not found in PATH"
fi

printf '\n=== SUMMARY: %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
