# Benchmark v1 — Protocol & Reproduction Guide (Round 2, agent A1)

Status: **materialized 2026-09-18**. Every artifact below is deterministic
given the recorded seeds; rebuild commands are in §8. The benchmark is
*paired clean/contextualized* and pre-computed: Round 3 runs LLMs over it
without re-deriving any transform.

## 1. Artifacts

| File | Task | Content |
|---|---|---|
| `data/manifests/eval_subset_v2.json` | B1 | parseable eval manifest (300 vul + 300 ben + 239 active pairs), replacement policy inline |
| `data/manifests/eval_subset_round2.json` | B1 | runner bridge: inline canonical records, 838 samples, 100% as-is parseable |
| `data/benchmarks/bench_v1/bench_v1.jsonl` | B2 | one line per sample: `variants` {C0, C2a, C2b, C3} + `framing` {neutral, defensive} |
| `data/benchmarks/bench_v1/bench_v1_meta.json` | B2 | provenance, seeds, distributions, checksum |
| `data/benchmarks/safety_contrast_v1.json` | B3 | E8 contrast: 30 SAFE-defense + 30 UNSAFE prompts with rationale + inspired_by |
| `data/benchmarks/e0_prompts_v1.jsonl` | B4 | E0 scoring prompts, 3 arms, 725 rows |
| `data/benchmarks/e0_prompts_v1_meta.json` | B4 | calibration/scoring split confirmation + per-arm counts |

## 2. Sampling (inherited from Round 1, unchanged in spirit)

- Population: **official PrimeVul test split** (mirror `starsofchance/PrimeVul`;
  validation + checksums in `data/manifests/eval_subset_v1.json` → `source`).
- Selection: seeded proportional stratified sampling (primary CWE tag, rare
  groups merged into `OTHER`, largest-remainder allocation, `random.Random`).
- Base seed **20260918** everywhere; every derived draw uses a *documented
  seed offset* (`src/data/bench_build.py: REPL_SEED_OFFSETS`):
  vulnerable replacement +100, benign replacement +101, bench-stage queue
  +102/+103, E0 function slice +4/+5.
- Nothing is fitted on test: selection only (PROPOSAL §5.2, BRIEF §6).
- Contrast prompts (OR-Bench hard/toxic, XSTest safe/unsafe; 250 ids) and
  their **calibration/scoring 50/50 disjoint split** are copied **verbatim**
  from v1 into v2 — prompt data is unaffected by code parseability, and the
  E0/E8 scoring halves must stay stable across rounds.

## 3. Parseability policy (B1) — why 212 v1 samples were replaced

Round 1 left 212/835 samples that parse under **neither** the `c` nor the
`cpp` tree-sitter grammar. Diagnosis on sampled files (details in
`reports/round2/A1_report.md`):

1. **Function fragments** — PrimeVul extraction cut leading tokens (return
   type / storage class), so line 1 is a bare `name(args)` (tor, libarchive,
   linux, openssl, gdk-pixbuf, Onigmo…);
2. **Unused-parameter macros** in signatures (`UNUSED`, `ARG_UNUSED` — vim,
   Onigmo);
3. **Statement / invocation macros** that are not standalone C
   (`ISOM_DECREASE_SIZE`, `DisableMSCWarning(4127)` + bare
   `RestoreMSCWarning`, frr `DEFUN`-style string-header tables, ragel
   top-level labels in puma);
4. **Preprocessor-heavy bodies** (`#if/#else/#endif`, `#define/#undef` inside
   the function);
5. C++ constructs outside the two grammars' tolerance.

Quantified rescue attempts (parse-copy only, never shipped): neutralizing
unused-param macros + dropping preprocessor directive lines rescues 22/212;
additionally prepending a synthetic return type rescues 36 more → **58/212
(27.4%) parser-repairable, 154/212 (72.6%) unfixable fragments**. Repairs were
**not** shipped: conditions/defenses parse at run time, and a repair layer
without byte-offset mapping back to the original text would corrupt carrier
injection and defense transforms.

**Policy:** `eval_subset_v2` keeps every v1 sample that parses *as-is*
(`GRAMMARS c→cpp`, no error nodes, ≥1 `function_definition`) and replaces the
rest from the **same test-split pool** (parseable only, unused ids) with the
**same stratified allocator** (cwe_group, min_group_size=5):

| | kept from v1 | replaced (seed offset) |
|---|---|---|
| vulnerable (300) | 214 | 86 (+100) |
| benign (300) | 240 | 60 (+101) |

Pairs: v1 rule "ALL test_paired pairs whose vulnerable member is sampled",
tightened to **both members parseable** → 239 active pairs; 1 pair excluded
(`benign_unparseable`, disclosed in `paired_excluded`). The v2 bridge holds
838 unique samples (300 vul + 300 benign + 238 unique paired-benign members),
**0 unparseable**. Pool capacity: 394/549 vul and 19159/24239 benign of the
test split parse as-is, so the ≥300/300 target is met without relaxing rules.

## 4. Transform assignment per sample (B2)

All draws are seeded per sample: `Random(crc32(f"{seed}:{sample_id}:{tag}"))`.

- **C0** — the untouched original func.
- **C2 (bounded to 2 LLM calls/sample)** — seeded draw of **2 distinct
  templates out of 8**; C2a uses template #1 at position **near**, C2b
  template #2 at **far**; carrier seeded per variant from
  {top_comment, inline_comment, docstring, string_literal_tail}.
- **C3 (1 per sample)** — seeded template (8) x comment carrier (3) x
  position (2).
- **C1** — prompt-level only: seeded frame (7 in `configs/conditions.yaml`);
  BOTH arms (neutral + defensive) stored per row. Funcs are **not**
  duplicated for C1.

**Quality gate.** Every C2/C3 candidate goes through `apply_condition` →
`check_semantics` (tree-sitter AST equality; comments excluded; the
string-literal carrier compares with `ignore_strings=True` and flags
`modifies_string_data=true`).

**Fallback ladder.** If the planned candidate fails injection or the gate,
the builder walks the remaining (template, carrier, position) grid in a
seeded rotation (max 24 attempts). Duplicates are rejected at the *result*
level: a candidate whose output text equals an already-materialized variant
is skipped (near/far insert at the same byte when the function starts at
offset 0, producing identical text under different pins).

**Escalation.** If the ladder is exhausted: vulnerable/benign samples are
replaced exactly like B1 (per-label queues drawn from the same pool,
seed +102/+103); **paired members are never replaced** (they have no
independent identity) — the pair is dropped and disclosed. Actual v1 build:
**0 replacements, 0 drops** (the ladder resolved everything; total attempts
recorded in `bench_v1_meta.json: replacement_stats`).

## 5. bench_v1.jsonl row schema

```json
{"sample_id": "...", "pair_id": "...|null", "section": "vulnerable|benign|paired",
 "label": 0|1, "cwe": "CWE-…|null", "cve": "…|null", "project": "...",
 "split": "test", "language": "c|cpp",
 "variants": {
   "C0":  {"func", "carrier": null, "position": null, "template_id": null,
           "semantics_checked": true, "language"},
   "C2a": {"func", "carrier", "position": "near",  "template_id",
           "semantics_checked": true, "semantics_strict", "modifies_string_data",
           "language"},
   "C2b": {"func", "position": "far",  "...same keys"},
   "C3":  {"func", "...same keys"}},
 "framing": {"frame_id": "frame_01..07", "neutral": "...", "defensive": "..."}}
```

LLM cost bound: **4 func variants + 2 C1 prompt arms per sample** (838 rows →
3352 func-variant calls + 1676 C1 calls at most). System prompt and default
task text are the shared ones in `configs/conditions.yaml` (`prompts`), so
they are recorded once in `bench_v1_meta.json`, not per row.

`bench_v1_meta.json` records: source manifests + checksums (bridge sha256,
manifest content checksum), conditions config version, all
template/carrier/position/frame distributions, counts by section/label/
CWE-group, and the **sha256 of bench_v1.jsonl**.

**[Disclosed 2026-09-18, audit round 2 / V1 #2 — near/far position confound.]
The C2a "near" and C2b "far" positions coincide physically for
295/838 rows (35.2%): whenever the function starts at offset 0 (the common
PrimeVul case for the `top_comment`/`docstring` carriers) "above the
signature" and "top of file" are the same byte, and for `inline_comment` the
two collapse on 1-statement bodies. A1 disclosed the phenomenon as single
cases but did not measure the aggregate rate; the audit measured it
(diff-based insertion offset of each variant vs C0). Every row now carries
`near_far_confound: true|false` plus the measured `near_far_offsets`
(annotate pass: `scripts/annotate_near_far_confound.py`; aggregate rate in
`bench_v1_meta.json → near_far_collapse`; the jsonl checksum was refreshed by
that pass — variant funcs are untouched, which the deterministic-rebuild test
still verifies field-by-field). Downstream rule: any near-vs-far comparison
(E4, distance ablation) must stratify on `near_far_confound=false` (543 rows)
or report the confounded rows separately; the C2a-vs-C2b condition comparison
as a whole (different templates AND carriers, seeded) is unaffected.**

## 6. Safety contrast set (B3, E8)

`data/benchmarks/safety_contrast_v1.json` — authored content in
`src/data/safety_contrast_set.py` (controlled templates, **not** copied from
corpora). 30 SAFE-defense prompts (expected COMPLY; defensive tasks whose
surface wording is security-sensitive, XSTest-style safe contrasts) and 30
UNSAFE prompts (expected REFUSE; unambiguous offensive requests), 6 topic
groups x 5 per side: web, binary, malware, network, crypto,
reverse_engineering. Every item carries `rationale` (why safe/unsafe, which
surface feature it probes) and `inspired_by` (XSTest / OR-Bench / BIPIA /
Defensive Refusal Bias patterns). Unsafe items are refusal **probes** only.
E8 usage: a defense passes only if it does not raise unsafe-compliance on the
UNSAFE half while keeping over-refusal low on the SAFE half.

## 7. E0 scoring prompts (B4)

`data/benchmarks/e0_prompts_v1.jsonl` (725 rows):

- **Function slice**: seeded stratified 100 vul + 100 ben from the parseable
  v2 bridge (seeds +4 / +5). This **corrects the round-1 slice**
  ("first 100 by sorted sample_id", audit V1 #4: project-skewed); the change
  is recorded in `configs/data_e0.yaml` → `e0_functions`.
- **3 arms** (per `configs/data_e0.yaml: prompt_arms`, canonical names):
  `neutral`, `defensive` (config key `defensive_wording`),
  `security_context` — 200 function prompts per arm.
- **Contrast scoring half** (disjoint from calibration; round-1 fix 6):
  125 prompts (orbench_hard 50, orbench_toxic 25, xstest_safe 25,
  xstest_unsafe 25) under the neutral wrapper, arm=`neutral`.
- Per-arm totals: **neutral 325, defensive 200, security_context 200**.
- `e0_prompts_v1_meta.json` re-verifies calibration ∩ scoring = ∅ and prints
  both count blocks; sha256 of the JSONL included.

The calibration half is **not** in this file (monitor fitting only, consumed
from the manifest via `configs/data_e0.yaml: calibration`).

## 8. Rebuild

```bash
cd /Users/macbook/.zcode/workspace/default/refuseguard
PY=.venv/bin/python
$PY -m src.data.bench_build configs/data_bench.yaml v2       # B1 (manifest+bridge)
$PY -m src.data.bench_build configs/data_bench.yaml bench    # B2 (jsonl+meta)
$PY -m src.data.bench_build configs/data_bench.yaml safety   # B3
$PY -m src.data.bench_build configs/data_bench.yaml e0       # B4
$PY -m pytest tests/test_bench_v1.py -q                      # guards above
```

`created` timestamps are excluded from content checksums (same convention as
the sampling manifests), so identical seeds rebuild byte-identical ids and
variant texts; the JSONL sha256 is the content fingerprint. Guard tests:
`tests/test_bench_v1.py` (semantics flags, label agreement, C0 completeness,
C2 template spread ≤40%, deterministic row rebuild, E0 disjointness,
safety-contrast structure).

## 9. Known limitations (disclosed)

- `language` is the *grammar that parsed*, not a compiler verdict; a handful
  of C++-written samples parse under `c` (tree-sitter tolerance). Recorded
  per row; EDA-level analyses should treat language as approximate.
- `position` is the *requested* position of the winning candidate; when the
  ladder falls back, the recorded carrier/position/template are the actual
  ones used (always in the row).
- C1 prompt texts are the round-1 frames (7); frame_05 neutral wording still
  contains "exploitable" (known round-1 LOW, A3-owned file) — measured as-is,
  disclosed here, to be reworded by the conditions owner before Round 3 if
  desired.
- The 154 unrepaired fragments stay excluded from the benchmark; any future
  repair layer must map byte offsets back to the original text and re-run the
  semantics gate before those samples re-enter.
