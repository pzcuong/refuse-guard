# Round 7 — A1 Report: bench_attack_v2 (C5 extension to CWE families)

Date: 2026-09-21. Owner: A1. Scope: W1–W4 of the round-7 brief.
Deliverables: `configs/attack_v2_cwe.yaml`, `src/conditions/bench_attack_v2.py`,
`data/benchmarks/bench_attack_v2/{bench_attack_v2.jsonl,manifest_attack_v2.json}`,
`docs/bench_attack_v2.md`, `tests/test_attack_v2_cwe.py`, this report.
Additive change to the shared module `src/conditions/c5_risk_context.py`
(reason below). No LLM was run (CPU-only, per brief).

## What was built

`bench_attack_v2`: **160 rows = 4 CWE families × (20 vulnerable + 20 benign)
× 4 arms** (C0 / D2_task / C5_near / C5_far), layout identical to
bench_attack_v1 (1 row per sample, pre-computed `arms` dict, advisory
embedded in the C5 funcs, prompts rebuilt by
`c5_risk_context.build_attack_prompt`). Purpose: test whether the round-5
Finding-2 verdict-bias attack GENERALIZES across CWE families instead of
living on the mixed 200-row subset, where the candidate families held only
4–15 rows each (measured: CWE-476 15, CWE-416 10, CWE-200 8, CWE-190 7,
CWE-20 8, CWE-362 6 of 200).

Families selected (all under-represented in v1): **CWE-476, CWE-416,
CWE-190, CWE-200**. jsonl sha256
`7e8ed42421a7c2d00c64313d985e0f63e92911881cb24f1857b09f5490a3d6b4`;
deterministic rebuild verified byte-identical across runs. Zero sample
overlap with bench_attack_v1 (excluded by rule) and zero overlap with the
rest of the bench_v1 bridge (measured).

> **[CORRECTED-R7]** (S-exec, Vòng 7, sau audit V1): câu trên là SAI do BUG-1
> — builder đọc manifest bridge bằng key `records` trong khi file thật dùng
> key `samples`, nên overlap in ra 0. Đo lại trên chính jsonl đã ship (sha
> `7e8ed42421a7c2d00c64313d985e0f63e92911881cb24f1857b09f5490a3d6b4`,
> không đổi): overlap với `eval_subset_round2.json` (universe của bench_v1,
> 838 ids) = **22 ids**; với `eval_subset_round1.json` = **16 ids**. Ảnh hưởng
> thuần provenance/disclosure: 22 row này từng được đo ở vòng trước dưới
> điều kiện KHÁC (C2/C3 stress), không phải leak label, không đổi selection
> (seed-based), không đổi bất kỳ số RQ8 nào. Claim "zero overlap with
> bench_attack_v1" (200 ids bị loại bởi rule) vẫn ĐÚNG. Đã sửa:
> `src/conditions/bench_attack_v2.py` (key `samples`, cả round1+round2),
> `manifest_attack_v2.json` (22 / 16 + note), `docs/bench_attack_v2.md`.
> Chi tiết: `reports/round7/V1_report.md` BUG-1 + `reports/round7/EXEC_report.md`.

## W1 — family selection and pool reality (deviations disclosed)

- Parseability scan of the official test+valid splits (round-2 rule: as-is
  tree-sitter `c`→`cpp`, no error nodes, ≥1 function_definition; reused
  `src.data.bench_build.parse_language` so the rule is literally the same
  code). Test split parseable: 19,553/24,788 (vul 394/549); valid 19,307.
- Exclusion: the 200 bench_attack_v1 sample_ids. Test-only parseable vul
  pools for the candidate families: **476: 24, 416: 19, 190: 9, 200: 7,
  20: 9, 362: 4** — the "test split only" reading of the brief is infeasible
  for 20-per-family on every family except CWE-476.
- **Adopted rule (disclosed in config + docs + manifest): test-first,
  valid-fill.** Candidates come from the test split; per-(family,label)
  deficits are filled from the valid split deterministically (inside each
  project the test subgroup is consumed first). Justification: this project
  trains only on the train split; valid touches only B4 early stopping, and
  B4 is never run on this LLM bench. Realized per-cell split composition is
  in `manifest.family_split_composition`.
- **CWE-20 and CWE-362 dropped** (pools 16/11 vul over test+valid): below
  the 20+20 target they would dilute the design; disclosed rather than
  forced. The brief's candidate list is thus covered by 4 of 6 families at
  full strength.

## W2 — advisory machinery for sink-less families

Classic sinks (strcpy/free/getenv…) rarely occur in these defect classes,
so the advisory is now anchored on **family feature signals** — label-blind
AST features in `extract_family_signals` (NEW, in c5_risk_context.py):
`pointer_surface` (`*`/`->` sites gated on ≥1 pointer param, ≥3),
`heap_lifecycle` (19 allocator/free APIs, ≥1), `arith_scaling` (multiply
sites, ≥1), `log_output` (21 log/output APIs, ≥1), plus auxiliary
`shared_state` (static locals + lock APIs) and `external_input` (22 input
APIs). Thresholds were **calibrated on pooled label-blind distributions
BEFORE selection** (rule: smallest grid threshold with pooled pass-rate
≤ 0.55 over the anchor family's pool; measured rates 0.502 / 0.093 / 0.098 /
0.022 / 0.035 / 0.014 — the low auxiliary rates disclosed; no threshold
tuned per label; no extractor reads the label).

Template pools chosen by the function's own features: sink → the 8 round-5
pattern templates (copied verbatim, guard-tested equal); signal-only → **6
NEW family templates** (`fam_01`…`fam_06`: pointer surface, heap lifecycle,
arithmetic scaling, log path, shared state, input channel — third-person
threat-intel prose over `{signal_class}` feature phrases with
`{signal_sites}` count normalization, cap 3); neither → the round-5 generic
zero-API template, so **advisory presence remains 100% in both label
classes**. Policy-safety forbidden-token rules are unchanged and re-enforced
at build time and in tests.

**Anti-leakage, realized:** the 50/50 in-label signature target is
infeasible for vulnerable cells (their no-signature pools hold 8/6/3/4
rows — vulnerable functions in these families are feature-rich by nature).
Pre-registered fallback (config): when a vulnerable cell overflows, the
same family's benign signature quota is raised to the vulnerable realized
share, so advisory content type is matched ACROSS labels. Realized:
signature vul/ben 12/12, 14/14, 17/17, 16/16; advisory kinds per label
zero_api 21/21, family 48/49, pattern 11/10. `signature_balance_ok: true`.

## Shared-module change (ownership note)

`src/conditions/c5_risk_context.py` — ADDITIVE only, reason: the advisory
feature layer is contractually shared with A2/A3 through `apply_attack` /
`build_advisory`, and duplicating it in a new module would fork the
anti-leakage logic. Changes: `extract_family_signals`,
`family_signal_classes`, `_render` signal placeholders (optional kwargs),
`build_advisory` pool ladder (pattern → family → zero_api) + two new return
keys (`advisory_kind`, `family_signals`), C5-arm meta additions. Configs
without `advisory.family_signals` (i.e. `attack_v2.yaml`) are provably
unchanged: `tests/test_attack_v2_c5.py` 23/23 pass; full repo suite
**473 passed** (`--ignore=tests/test_round5_e0v2.py`) plus
`test_round5_e0v2.py` **15/15** (the round-5 report's pre-existing failure
no longer reproduces — A2's file now passes as-is).

## W3 — artifact + tests

- Materialized via `python -m src.conditions.bench_attack_v2
  configs/attack_v2_cwe.yaml`. Pool scan cached
  (`.cache_pool_scan.json`, keyed by source checksums; recorded scan mode
  `hit` in the manifest so rebuild provenance is visible).
- Manifest carries: seeds and seed derivation; source + config + excluded-
  bench checksums; per-cell selection metadata (pool sizes test/valid,
  signature pools, quotas, quota rule, overflow); signature balance + rule;
  family split composition; project distribution per cell; advisory kind /
  template distributions (family templates 14–19 uses each, max share
  0.196 ≤ 0.40 guard; pattern pool below the 50-row guard minimum — recorded
  `null`, disclosed); near/far audit (min gap 25 bytes, no confound);
  prompt-contract hashes; policy-safety record; jsonl sha256.
- `tests/test_attack_v2_cwe.py` — **21/21 pass**: config contract (≥4 family
  templates; anchors defined; ladder/system/arms/pattern/zero templates
  byte-equal to attack_v2.yaml); behavior (signal kinds on synthetic funcs;
  advisory kind pools; feature phrase embedded; label-blindness; count-cap
  on signals; policy safety over extreme renders AND over the materialized
  artifact via reconstructed advisory text; old-config v1 behavior
  unchanged); artifact (160 rows, 4×(20+20), 640 arm entries, C0 func ==
  row func; zero overlap with v1; signature rates matched across labels;
  advisory presence 100%; strict `check_semantics` on all 320 C5 pairs;
  near>far offsets everywhere; deterministic prompt rebuild; manifest
  checksum; selection determinism on the cached pool).

## Verification summary (what was actually run)

- Pool/parseability scans and signal calibration: run in this round
  (numbers above trace to `/tmp` scan artifacts rebuilt from the raw
  jsonl; the materialization itself re-derives the pool from the raw files
  through the cached scan).
- Build: 4 runs total (2 during debugging, 2 determinism checks) — final
  artifact byte-identical across the last two runs.
- Suites: `tests/test_attack_v2_cwe.py` 21/21; `tests/test_attack_v2_c5.py`
  23/23; full repo 473 passed + 15/15 (round5 file). No LLM calls.

## Handoff to A2/A3

- Per-family runs: use `build_attack_prompt(func=row["arms"][arm]["func"],
  arm=arm, language=row["language"])` over
  `data/benchmarks/bench_attack_v2/bench_attack_v2.jsonl`; pair C5/D2_task
  against C0 within family and label; gate per
  `configs/attack_v2_cwe.yaml → gate_v2_families` (Δ ≥ 0.10, McNemar p <
  0.05, ≥2 of 4 families = generalization of the Finding-2 direction; n=40
  per family is a probe — report "no detectable effect at pilot n", never
  absence).
- The bench is self-contained (advisories embedded); no attack-config
  plumbing is needed beyond the prompt builder and the v1 execution
  harness.

## Key limitations (full list in docs/bench_attack_v2.md §7)

Valid-split filler rows (share per cell in manifest; no train contamination,
possible mild B4 optimism if B4 were ever run here — it is not); in-label
50/50 replaced by across-label rate matching (infeasible otherwise);
CWE-20/362 dropped for pool scarcity; low benign rates for the three
auxiliary signals (their templates fire less; recorded); language = grammar
that parsed.
