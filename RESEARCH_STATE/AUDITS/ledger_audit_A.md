# LEDGER AUDIT A — independent cross-audit of the three forensic outputs

Auditor: ledger-audit-A (independent cross-auditor, GLM subagent) · Date: 2026-09-30
Scope (per ask): **CURRENT_PAPER_AUDIT.md**, **EXPERIMENT_REGISTRY.jsonl**, **POSITIVE/NEGATIVE
RESULTS_LEDGER.csv** (+ their companion CLAIM_EVIDENCE_LEDGER.csv) in `refuseguard/RESEARCH_STATE/`.
Method: 10 claims drawn **randomly** (Python `random.seed(20260930)`, `random.sample`, 1 draw) from the
77-row CLAIM_EVIDENCE_LEDGER, each traced **in reverse to raw artifacts** under `refuseguard/outputs/`
and `refuseguard/data/` with independent recomputes; plus targeted extra checks, registry sampling,
and a full language-scan of all 77 rows hunting mis-statuses.

Working directory for every command below: `/Users/macbook/.zcode/workspace/default/refuseguard`.

---

## 1. Verdict

| Question | Answer |
|---|---|
| Claims randomly spot-checked in reverse | **10 / 10 done** (RG-20, RG-12, PC-29, PC-40, RG-25, RG-14, PC-03, PC-07, PC-36, RG-37) |
| Statuses correct among the 10 | **10 / 10 conform** to the audit doc's own rubric |
| Targeted extra checks (mis-status hunt) | 6 more rows re-verified from raw (PC-22, RG-29, PC-04, PC-11, PC-34, POS-06) — all conform |
| **Mis-statused claims found** | **0 hard mis-statuses.** 4 gray-zone VERIFIED rows + 1 wording nit + 1 cross-doc convention divergence, all disclosed in the artifacts themselves (details §4) |
| Internal consistency of the audit doc | Its summary table (63 VERIFIED / 12 PARTIALLY_VERIFIED / 1 STALE / 1 UNKNOWN = 77; 40 PC + 37 RG) matches `CLAIM_EVIDENCE_LEDGER.csv` exactly (recounted with csv.DictReader) |
| EXPERIMENT_REGISTRY.jsonl | 2,810 rows; 6-row random sample + 5-row mock=True sample all trace to real artifacts; no misentries found |

---

## 2. The 10 random spot-checks (reverse trace to raw artifacts)

Sample draw (exact): `python3 -c "import csv,random; rows=list(csv.DictReader(open('RESEARCH_STATE/CLAIM_EVIDENCE_LEDGER.csv'))); random.seed(20260930); [print(r['claim_id'],r['status']) for r in random.sample(rows,10)]"`
→ RG-20, RG-12, PC-29, PC-40, RG-25, RG-14, PC-03, PC-07, PC-36, RG-37.

### RG-20 — VERIFIED → **conforms** (numbers exact; one wording nit, §4.1)
- Reimplemented pairing from `outputs/experiments/round5_defense/results_qwen3b.json` (360 records):
  B0-vs-P3 y_pred changes per condition = C5_near 1/60, C5_far 1/60 → **2/120** ✓.
- The changed pairs are the **same benign sample 218817 (label 0), flipped 1→0 in both C5 arms** —
  reproduces the paper sentence verbatim (`paper/sections/05_results.tex:264`: "2/120 pairs changed
  --- one benign sample, flipped in both arms").
- "30/30 vs 29/30": recomputed per condition from benign rows of the run file — C5_near B0 30/30 vs
  P3 29/30, C5_far identical ✓ (matches `round5_master.json` metrics
  `defense.qwen3b.C{5_near,5_far}.benign_over_trigger_B0_vs_P3 = "30/30 vs 29/30"`). Note this is
  the benign over-trigger inside the C5 run arms (B0 as reference), **not** the C0 control file
  (which recomputes to 60/60 vs 53/60) — see §4.1.

### RG-12 — VERIFIED → **conforms**
- `outputs/master/master_results.json` `contradictions[0]`: value_a **0.4** (path
  `metrics.safety_summary.B0.unsafe_compliance_rate`) vs value_b **0.03333** (`recompute_e8_monitor.json`),
  resolution "USE RECOMPUTED (file_b)" ✓.
- Re-read both ends independently: original `outputs/experiments/round3_e8_llama3b/results.json` →
  B0 unsafe 0.4 over n_unsafe=30, McNemar b10=12, p=0.00048828125; recomputed file → B0 0.0333
  (status_counts COMPLY: 29 PARTIAL + 1 REFUSAL, n_status_changed=11), b10=1, p=1.0 ✓.

### PC-29 — PARTIALLY_VERIFIED → **conforms** (values verified; the flagged ambiguity is real)
- `outputs/packguard/fl/results.jsonl` (31 rows): `group__graph__dp01_fedavg__fedavg` final_metrics.f1
  = **0.91525** with `dp.dp_epsilon_per_round = 48.448` ✓; `mlp__fedavg` **0.9230769** / `mlp__centralized`
  **0.9281768** — byte-identical to the LR rows `kb_off__fedavg`/`kb_off__centralized` ("MLP matches LR
  exactly" ✓); `noempty__centralized` f1 **0.8205128** over `n_test=79`, meta.mock=false ✓.
- The PARTIALLY_VERIFIED ground: paper's "n=500" parenthetical — confirmed: eval n is **79 test rows**
  of the 500-row with-graph subset; coverage 500/603 independently recounted (§3, PC-22). Status correct.

### PC-40 — VERIFIED → **conforms**
- `outputs/packguard/safety/safety_metrics_n60.json`: rr = 0.0 for both models × 3 arms;
  `mcnemar_vs_p0` p_value = 1.0 (exact, statsmodels) for all 4 comparisons, n=60 each ✓.
- Raw `safety_batch_n60.jsonl`: 361 lines = 1 meta + **360 records** (359 ANSWER + 1 PARTIAL, 0 REFUSAL);
  meta.seed 20260922, meta.metrics_version **2** ✓ (also confirms PC-12's mv2 claim).

### RG-25 — VERIFIED → **conforms** (p reproduced exactly under the disclosed convention)
- Recomputed from `outputs/experiments/round7_7b/results_qwen7b__{vul__A0,vul__A1,vul__A5,benign__B0}.json`
  (240 records total, RR=0 in all four files) ✓.
- Recalls (n_vul_parsed=59/59/60): 28/59=**.4746**, 27/59=**.4576**, 31/60=**.5167** = paper's
  .475/.458/.517 ✓. H_R2 Δ = −0.0169 ≈ −.017, my exact p=1.0 ✓.
- A0-vs-A5 flips: with unparseable A0 record **excluded** (the run's disclosed convention): b01=5, b10=3,
  n=8 → exact McNemar = 2·(1+8+28+56)/256 = **0.726562** = paper's p=0.7266 ✓; "3 flips 1→0" = b10=3 ✓.
  (With unparsed-as-miss: 6v3, p=.5078 — that convention belongs to the *different* Kaggle run, §4.3.)
- Completion tokens recounted: medians **54.0 / 55.5 / 98.0**, min 46, max 210 ✓.
- `round7_master.json` verdict `H_R1 = NOT_SUPPORTED-ABSENT` present ✓.

### RG-14 — VERIFIED → **conforms**
- Recounted `outputs/experiments/round5_e0v2/results_{llama3b,qwen3b,granite2b}.json`: **1,200 records,
  1,199 ANSWER + 1 PARTIAL + 0 REFUSAL** ✓; RR=0.0 in all 12 model×arm cells ✓;
  `metrics.per_arm[*].benign_block = 0.0` in all 12 cells (blocking semantics = benign refusal, not
  y_pred flagging — qwen's C0 benign *flag* rate is 1.0, the NEG-12 saturation, correctly not what
  RG-14 claims) ✓; `verdict.json` aggregate: H_A/H_B/H_C **NOT_SUPPORTED, models_pass 0/3** ✓.

### PC-03 — VERIFIED → **conforms**
- Scope arithmetic recounted from raw records: round3_e0 task rows **180** (60 task × 3 models, probes
  excluded) + round3_e2e3 **900** (300×3) + round5_e0v2 **1,200** + safety n60 **360** + round-8
  `safety_batch.jsonl` **60** = **2,700** ✓; 0 REFUSAL in every recounted file.
- Probe counterexample recounted: 25 probes × 3 arms × 3 models = 225 probe records; REFUSAL
  qwen **58** + llama **36** + granite **31** = **125/225** ✓ (exactly the audit doc's 58+36+31).
- (The batch meta's n_malicious_total 35→30 drift is already ledgered as NEG-38 — consistent.)

### PC-07 — VERIFIED → **conforms**
- `outputs/packguard/defense/defense_analysis.json` `input_meta.defense_gate`: n_gate_pass **38**,
  n_gate_fail **7** (= 45 drawn ✓); `excluded` list = **7 items, labels 6×1 (mal) + 1×0 (benign)** ✓.
- Fisher two-sided on [[6,24],[1,14]] recomputed from scratch (hypergeometric ordering):
  **0.395491** ≈ paper's .40 ✓.

### PC-36 — STALE → **conforms**
- `outputs/packguard/r16_kaggle/r16_analysis.json`: `status: "pending"`, `date_utc: 14:24:10Z`,
  note "the Kaggle result files are not downloaded yet" ✓.
- Intrinsic record dates in the raw jsonl it was supposed to analyze: llama8b ladder last record
  **14:26:41Z**, qwen7b ladder **14:28:57Z**, qwen7b safety **14:56:22Z** — all **after** the harness
  ran; harness never re-run. STALE is exactly right (audit doc's "14:26/14:56Z" matches).

### RG-37 — VERIFIED → **conforms**
- `outputs/experiments/round5_e0v2/results_granite2b.json` metadata: `selection.seed_subset = 20260923`,
  `n_per_label = 30`, `by_label {0:30, 1:30}` → half-size nested subsets ✓ (vs 60+60 for llama/qwen);
  `monitor_thresholds_source` = "configs/round5_e0v2.yaml monitor.fallback_thresholds (no calibration
  fit for ibm-granite...; **DISCLOSED fallback**)" ✓.
- 240 records; 0 records missing any of sample_id/condition/y_pred/y_true/status ("every record
  schema-complete") ✓; RR=0 across all 240 ✓; master granite rows (recall denominators 30,
  recalls .1/.4333/.7333/.7667, flips 10/1, 20/0, 25/0) all match my recounts ✓.

---

## 3. Targeted extra checks (mis-status hunt beyond the random sample)

| Row (ledger) | Check run | Result |
|---|---|---|
| PC-22 VERIFIED | Recounted `features_v2.jsonl` line-by-line | 603 rows = 390 mal + 213 ben; npm 298/123, pypi 92/90; with-graph (n_nodes>0) = **500/603 = 82.92%** — all exact ✓ |
| RG-29 VERIFIED | Recounted `data/raw/primevul_hf/primevul_{train,valid,test}.jsonl` + `*_paired.jsonl` (field `target`) | train 175,797/4,862 vul; valid 23,948/593; test 24,788/549; test_paired 870 = 435 pairs; totals **6,004 vul (−13.8% vs 6,968 ✓) + 218,529 benign** — all exact ✓ |
| PC-04 VERIFIED | Read `defense_analysis.json` per_model granite `comparisons.P0_neutral__vs__P2_D1` | 23 pairs, pos 15/15, flips 0/0, p=1.0; benign FP 0/14; 1 unparsed disclosed ✓ |
| PC-11 VERIFIED | Read `defense_analysis.json` `pooled` + closed-form McNemar | 20/48=.417, 21/48=.438, 16/47=.340; FP 0/28; p(1v5;6)=.21875≈.219, p(1v4;5)=.375 ✓ |
| PC-34 VERIFIED | Recomputed Kaggle raw `results_llama8b_ladder.jsonl` (180 rows, mock=False) + `p18` files | llama8b A0 **36/60=.600**, A1 37/60=.6167, A5 33/60=.550; paper orders the ladder **A0→A5→A1** explicitly (`paper2/main.tex:529-530`) so ".600→.550→.617" is correct; 6v3 discordant (unparsed-as-miss) p=**.5078** ✓; Δ−.05 ✓; A1 +.0167 ✓. qwen7b **.4833/.4667/.5333** ✓; safety **RR=0/300**, recall **34/50=.680 → 31/50=.620/.620**, benign FP **0/50** ✓ |
| POS-06 (POS ledger) | Read `round6_bias.json` | llama FP `.8167→1.000` with exact McNemar **0.0009766** (= 9.8e-04 ✓); granite **0→.6667/.8333** ✓ |
| NEG-25 (incidental, via PC-29 recompute) | fl rows kb_off/kb_on FedAvg | .9231 vs .9222 = ledger's ".923→.922" ✓ |

## 3b. EXPERIMENT_REGISTRY.jsonl cross-check

- 2,810 rows (`wc -l`); kinds histogram sane (2,653 run + 157 aggregate/analysis/…); mock: 2,657 False /
  104 None / 49 True.
- Random sample of 6 rows (same seed): every `artifact_path` exists; `n_rows` traces to a real field —
  e.g. EXP-01496 n_rows=151 (`metadata.n_test`): 151 is among the n_test values actually present in
  `p0/p0_results.json` (recounted set {99…151}); EXP-02678 n_rows=102: `meta.n_test=102` present in
  8 rows of `malguard_style/results.jsonl`. `n_rows_source` is disclosed per row (jsonl_line_count vs
  metadata.n_test), so line-count vs test-size semantics is transparent — **no misentries**.
- 5 sampled mock=True rows all correct: dry-dir paths (`round9_8b/dry/…`, `r1_stabilized_central/dry/…`,
  `round5_e0v2/dry/jobs_status.json`), in-file `mock: true` / `dry_run: true` markers verified.
- mock=None rows (104) are aggregates without in-file markers; each carries a `mock_evidence` string
  (e.g. "sibling records in same dir carry mock=[False]") — disclosed, acceptable.

## 3c. Full-ledger language scan for status conflicts

Scripted scan of all 77 CSV rows for VERIFIED rows whose own evidence text says "not re-run / not
recomputed / not independently / audit-anchored": hits = **PC-08, PC-12, PC-25, RG-33** (details §4.2).
No PARTIALLY_VERIFIED row lacks a concrete reason; STALE (PC-36) and UNKNOWN (RG-36) are each correct
(RG-36 = external-literature numbers, genuinely out of re-verification scope; the ask's scope is repo
artifacts).

---

## 4. Findings (no mis-status; 1 wording nit, 1 gray zone, 1 convention divergence)

### 4.1 Wording nit — RG-20 ledger `claim_summary` says "control 30/30 vs 29/30"
The "30/30 vs 29/30" figure is `defense.qwen3b.*.benign_over_trigger_B0_vs_P3` from
`round5_master.json` — computed on the **benign rows of the C5 run arms** with B0 as the within-arm
reference. The C0×P3 **control file** recomputes to 60/60 vs 53/60 (7 changed). The paper
(`05_results.tex:264`) does not use the word "control" for this; only the ledger summary does. A
re-verifier who opens the control file first will see an apparent mismatch. **Fix: one word in the
claim_summary** (e.g. "benign over-trigger B0-vs-P3: 30/30 vs 29/30"). Status itself stays VERIFIED —
both numbers are exact.

### 4.2 Gray zone — four VERIFIED rows carry a disclosed sub-claim resting on the audit chain
Per the audit doc's own rubric, VERIFIED = "reproduced this session from raw records, **or** read
cell-by-cell from the cited artifact + verified macro chain". In all four rows below the *primary*
value was artifact-read this session (so VERIFIED is defensible), but a secondary component was not
re-verified — each is honestly disclosed in the row's notes:
- **PC-08** (weakest case): the headline "4 versions, 1 family of 19" rests wholly on the round-12
  V1 audit recompute (byte-identity of llama's 4 losses); notes say "independent per-sample recompute
  of byte-identity not repeated this session". Strictly by the rubric's first clause this is
  PARTIALLY_VERIFIED material; by the second clause ("cited artifact" = V1_report.md) VERIFIED stands.
  Audit-A verdict: defensible, but this is the one row where a stricter auditor could argue mis-status.
- PC-12: per-sample label check of the 11 flips is W1/V1-audit-anchored (aggregate numbers verified).
- PC-25: the unit-test claim |Δp|=.0022 not re-run (mu-sweep values macro-chain verified).
- RG-33: smoke 4/5 not reopened (7/13 probe value verified from results.json).

### 4.3 Convention divergence across documents (correct but easy to mis-read)
Two unparseable-record conventions coexist, attached to **different runs**:
- Local 7B RQ9 (RG-25/NEG-14): unparseable A0 record **excluded** → 5v3 discordant, n=8, p=.7266.
- Kaggle llama8b ladder (PC-34, audit-doc §2): unparseable records scored **as miss** → 6v3, n=9,
  p=.5078.
Both are internally correct, disclosed, and match their artifacts (Audit-A reproduced both).
Risk: applying either convention uniformly across both runs yields a false mismatch. Recommend one
sentence in the audit doc noting the two conventions.

### 4.4 Explicitly NOT found
- No VERIFIED/PARTIALLY_VERIFIED/STALE/UNKNOWN row whose numbers contradict its raw artifact (0 of 16
  reverse traces failed).
- No POSITIVE/NEGATIVE ledger row checked (POS-06, NEG-02 via RG-14, NEG-14 via RG-25, NEG-16 via
  RG-12, NEG-25, POS-20 area via PC-40) disagreed with its artifact.
- No registry row mis-stated (sampled 11 of 2,810).

---

## 5. Not run / out of scope for this pass
- The remaining 61 CLAIM_EVIDENCE rows (only 16 of 77 reverse-traced), and the other 2,799 registry
  rows (11 sampled).
- `verify_repro.sh`, `gen_paper_numbers.py --check`, pytest suite — not re-executed here; Audit-A did
  independent recomputes instead (the named checks of the *prior* audit, not of this ask).
- External-literature claims (RG-36, campbell2026defensive 2.72×) — out of scope, status UNKNOWN
  confirmed appropriate.
- Byte-level re-verification of PC-08's strip-equality (left as the §4.2 gray zone rather than
  resolved).

## 6. Command inventory (all run in this session, cwd = refuseguard/)
`python3` recomputes over: `RESEARCH_STATE/CLAIM_EVIDENCE_LEDGER.csv`, `POSITIVE_RESULTS_LEDGER.csv`,
`NEGATIVE_RESULTS_LEDGER.csv`, `EXPERIMENT_REGISTRY.jsonl`, `outputs/experiments/round5_defense/
results_qwen3b.json` (+ `__control`), `outputs/experiments/round3_e8_llama3b/{results.json,
recomputed/recompute_e8_monitor.json}`, `outputs/master/{master_results,round5_master,round6_bias,
round7_master}.json`, `outputs/packguard/{fl/results.jsonl,safety/safety_metrics_n60.json,
safety/safety_batch_n60.jsonl,safety/safety_batch.jsonl,defense/defense_analysis.json}`, round3_e0/
round3_e2e3/round5_e0v2/round7_7b `results*.json`, `outputs/experiments/round3_granite_smoke.json`
(not reopened — audit-anchored only), `outputs/packguard/r16_kaggle/{r16_analysis.json,
llama8b/results_llama8b_ladder.jsonl,p18/results_qwen7b_{ladder,safety}.jsonl}`,
`outputs/packguard/features/features_v2.jsonl`, `data/raw/primevul_hf/*.jsonl`;
plus `grep` over `paper/main.tex`, `paper/sections/05_results.tex`, `paper/tables/tab_round5_defense.tex`,
`paper2/main.tex`. Random seed for the 10-claim draw and all registry samples: **20260930**.
