# EDA — PrimeVul mirror (measured 2026-09-18)

Source: HF mirror `starsofchance/PrimeVul` (dataset card states it is based on the
**PrimeVul-v0.1** release), cached at `data/raw/primevul_hf/`. Reference paper:
Ding et al., *"Vulnerability Detection with Code Language Models: How Far Are We?"*,
ICSE 2025 (arXiv:2403.18624). All numbers below are produced by
`python -m src.data.primevul` (streaming parse of the raw JSONL, no sampling).

## 1. Counts vs paper — DISCREPANCY FLAG

| Metric | Paper (~) | Mirror (measured) | Deviation |
|---|---|---|---|
| Vulnerable functions | 6,968 | **6,004** | **-13.8%** |
| Benign functions | 229,794 | **218,529** | -4.9% |
| Unique CWE tags | >140 | **130** | fewer |

Per split (mirror): train 175,797 rows (4,862 vul / 170,935 ben, 122 CWE) ·
valid 23,948 (593 / 23,355, 73 CWE) · test 24,788 (549 / 24,239, 71 CWE).
Paired files (consecutive vulnerable/patched rows, verified (1,0) label pattern
+ same commit + ~0.99+ code similarity): train 3,789 pairs, valid 480, test 435.

**Flag for the team:** the mirror is v0.1-based and its vulnerable count deviates
-13.8% from the paper's ~6,968 (the benign count is fine at -4.9%). The official
v1.0 data is gated (application). Consequences: (a) all pilot numbers must cite
"PrimeVul v0.1 mirror" explicitly; (b) test-split vulnerable pool is 549, so a
300-vulnerable eval subset covers 55% of it; (c) Round 2 should try the
`Code-TREAT/PrimeVul-Paired_original_lite` mirror to see whether it matches the
paper totals better. Counts are validated at load time
(`validate_primevul()`), deviation reported, never hidden.

## 2. CWE distribution (top 10, across all splits, per function-tag occurrence)

| Rank | CWE | Count | | Rank | CWE | Count |
|---|---|---|---|---|---|---|
| 1 | CWE-119 (memory buffer) | 19,253 | | 6 | CWE-416 (UAF) | 12,538 |
| 2 | CWE-787 (out-of-bounds write) | 18,263 | | 7 | CWE-200 (info exposure) | 9,072 |
| 3 | CWE-125 (out-of-bounds read) | 17,877 | | 8 | CWE-703 (impr. check) | 8,211 |
| 4 | CWE-20 (input validation) | 14,944 | | 9 | CWE-264 (permissions) | 7,891 |
| 5 | CWE-476 (NULL deref) | 13,045 | | 10 | CWE-190 (integer overflow) | 7,424 |

Memory-safety classes dominate the top-5 — expected for C/C++. 23,367 records
(10.4%, almost all benign) carry no CWE tag. For stratified sampling, rare tags
(<5 functions) are merged into `OTHER` (`src/data/sampling.py`).

Top vulnerable-source projects: linux (1,152), ImageMagick (359), Chrome (261),
tensorflow (247), php-src (181), Android (161), qemu (149), openssl (120).

## 3. Function length (chars) → choice of max_seq_len

| Split | mean | p50 | p90 | p95 | p99 | max |
|---|---|---|---|---|---|---|
| train | 1,297 | 480 | 2,601 | 4,387 | 13,326 | 484,356 |
| valid | 1,233 | 503 | 2,623 | 4,280 | 11,688 | 106,112 |
| test | 1,288 | 490 | 2,693 | 4,473 | 13,245 | 137,677 |

Recommendation: **max_seq_len = 1,024 tokens** for the CodeBERT-family
fine-tune (covers ~p90+ of functions fully; longer ones get head-truncation,
standard PrimeVul protocol) and **8k context** for LLM pilots (Qwen2.5-Coder-3B
class handles it); for pilot cost control, functions >8k tokens (≈ >p99) can be
skipped but the skip count must be reported, not silently dropped.

> **[CORRECTED] 2026-09-18 (audit round 1, V1 #2):** the recommendation above
> — `max_seq_len = 1,024 tokens for the CodeBERT-family` — is technically
> impossible: CodeBERT is RoBERTa-base with `max_position_embeddings=514`
> (verified in `models_dir/hf/hub/models--microsoft--codebert-base/.../config.json`),
> so the hard input cap is **512 tokens**. The correct setting is
> `max_seq_len = 512` (already used in `configs/models.yaml`); functions longer
> than 512 tokens are truncated with the head+tail strategy implemented in
> `src/models/transformer_baseline.py::_encode`, and the fraction of truncated
> functions must be reported. The char-length statistics in the table remain
> valid — only the "1,024 tokens" inference was wrong. The separate "8k
> context for LLM pilots" recommendation is unaffected (decoder LLMs, not
> CodeBERT).

## 4. A paired example (official test_paired)

`test_paired-P0`: vulnerable id 194963 / patched id 217569, project ImageMagick6,
CWE-704, CVE-2022-32547, both from commit `dc070da8`. Function length 28,188 vs
28,274 chars, diff similarity 0.9977. The patch replaces a raw `*(float *) p1`
reinterpretation in EXIF parsing with an explicit endian-aware
`ReadPropertySignedLong(endian, p1)` call — a minimal, semantics-level
vulnerability fix of exactly the kind PrimeVul uses for paired evaluation
(VD-S): a detector must distinguish two nearly identical functions.

## 5. Contrast corpora (data/raw/contrast/, verified loaders in src/data/contrast.py)

- OR-Bench hard CSV actually contains **1,319** prompts (despite the "1k" name);
  toxic CSV 655. Both official files, mirror `bench-llms/or-bench`.
- XSTest: 450 prompts = 250 safe / 200 unsafe, official `paul-rottger/xstest`.
- Checksums (sha256-16) recorded via `contrast_sources()` and embedded in the
  eval manifest.

## 6. Eval subset manifest

`data/manifests/eval_subset_v1.json` (config `configs/data_main.yaml`,
seed 20260918): 300 vulnerable + 300 benign stratified by CWE group from the
official test split, all 236 test pairs whose vulnerable member was sampled
(472 records), 250 contrast prompts (100 OR-Bench-hard, 50 OR-Bench-toxic,
50 XSTest-safe, 50 XSTest-unsafe). Manifest records seed, criteria, all
sample_ids, source checksums and a content checksum
(`3f4ddfe4ac3dc058`, verified byte-identical across re-runs with same seed).
Nothing is fitted on test: selection is the only operation performed on it.

## 7. [ADDED Round 2, 2026-09-18] Parseability of PrimeVul functions → eval_subset_v2

As-is tree-sitter parseability (GRAMMARS `c`→`cpp`, no error nodes, ≥1
`function_definition`) measured over the official test split:

| | parseable | total | rate |
|---|---|---|---|
| vulnerable | 394 | 549 | 71.8% |
| benign | 19,159 | 24,239 | 79.0% |

Failures are dominated by **function fragments** (extraction cut the leading
return type / storage class), unused-parameter macros (`UNUSED`,
`ARG_UNUSED`), non-standalone statement macros (`ISOM_DECREASE_SIZE`,
`DisableMSCWarning(4127)` + bare `RestoreMSCWarning`, frr `DEFUN` tables,
ragel labels), preprocessor-heavy bodies, and C++ beyond both grammars.
Deterministic repair experiments (parse-copy only) rescue 58/212 = 27.4% of
the round-1 failures; the rest are unfixable fragments — see
`reports/round2/A1_report.md` and `docs/benchmark_v1.md` §3.

Consequence: `data/manifests/eval_subset_v2.json` (seed 20260918, derived
from v1, checksum `e23af1560f035dac`) keeps only as-is parseable members and
replaces the rest from the same pool (stratified, seed offsets +100 vul /
+101 ben): 300 vul + 300 benign + 239 active pairs, bridge
`eval_subset_round2.json` = 838 samples, **0 unparseable**. Language mix in
the bridge: c 397 / cpp 441 (47.4% / 52.6%); top projects tensorflow 144,
linux 126, vim 65 (proportional to the test split). The materialized
benchmark lives in `data/benchmarks/` (see `docs/benchmark_v1.md`).
