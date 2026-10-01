# RefuseGuard

**Robust LLM-Based Vulnerability Detection under Safety-Induced Blocking and Untrusted Code Context.**

RefuseGuard is a complete, reproducible research codebase that measures how
safety alignment and untrusted code context degrade LLM-based vulnerability
detection, and evaluates layered defenses (context isolation, refusal
monitoring, transformer fallback) that recover utility without sacrificing
safety. Everything in the paper (`paper/compiled/refuseguard_paper.pdf`) is
generated from real experiment outputs under `outputs/` — no number is
hand-typed; every table/figure value traces to a JSON/JSONL file listed in
`reports/round3/S_report.md` §5 (number → file mapping).

Headline findings of the current (pilot-scale, 3B open-weight models) study:

- **E0 reproduction gate: FAIL → PIVOT.** Defensive wording (C1) did *not*
  induce refusals (RR = 0.000 on all three arms, all three registered models
  incl. Granite-3.3-2B, McNemar p = 1.0, effect size 0). The pre-registered
  fallback — robustness under untrusted context as the primary lens, refusal
  as secondary — is what the paper reports.
- **C2 contextual stress and C3 injection-style context do not break output
  usability** (UAC ≈ 1.0) but C3 flips predictions (IPI-flip 0.742 → 0.484
  after P1 isolation, McNemar p = 0.0078; vulnerable-only subset n.s., p = 0.5).
- **P2 (RefuseGuard pipeline) keeps pipeline-level safety by construction**
  (intent gate blocks unsafe prompts before any LLM call) while the fixed
  monitor no longer suppresses refusals; safe-side over-refusal does not
  increase (Qwen 0.233 → 0.000, p = 0.0156).
- **CodeBERT (B4) + fusion (E7):** usable-answer coverage 0.985 → 1.000 with
  the LLM↔transformer fallback; transformer-only MCC 0.232 / VD-S 0.962 at the
  disclosed 25k-train subsample.

These are pilot-scale results (n in the hundreds, 3B models on Apple MPS), not
production-scale claims; see paper §Limitations.

---

## Repository layout

```
refuseguard/
├── PROJECT_BRIEF.md        # canonical interfaces + scientific rules (read first)
├── PROPOSAL.md             # full research proposal (design of E0–E8)
├── configs/                # YAML configs, incl. pre-registered round-3 configs
├── src/
│   ├── data/               # PrimeVul load/validate, sampling, bench_build,
│   │                       #   safety-contrast set (E8), OR-Bench/XSTest loaders
│   ├── models/             # llm_harness (cached/resumable), refusal_monitor,
│   │                       #   transformer_baseline (CodeBERT), fusion_policy
│   ├── conditions/         # C0–C3 generators + tree-sitter semantic checks
│   ├── defenses/           # B1 reframe, B2 strip, B3 aggressive, P1 SCI, P2 pipeline
│   ├── metrics/            # RR/UAC/SIUD/DRR/CUL/MCC + McNemar/bootstrap
│   └── experiments/        # run_e0..run_e8 (config-driven, --dry-run),
│                           #   pilot_round2/pilot_round3/round3_scaleup (used for paper)
├── scripts/                # train/eval CodeBERT, calibration, E7 fusion,
│                           #   recompute/audit scripts, download_data.py,
│                           #   make_manifest.py, demo_refuseguard.py,
│                           #   verify_repro.sh
├── data/                   # raw + manifests + frozen benchmarks (large files git-ignored)
├── models_dir/             # HF cache (HF_HOME) + CodeBERT checkpoint
├── outputs/                # experiment results (results.json + raw/), transformer eval
├── paper/                  # LaTeX source (acmart); compiled PDF in paper/compiled/
├── tests/                  # pytest suite (353 tests as of Round 3)
├── docs/                   # literature review, protocols, EDA, refs.bib
├── reports/                # per-round agent reports (audit trail)
├── requirements.txt        # curated, pinned top-level dependencies
└── requirements-lock.txt   # full transitive freeze of .venv (79 packages)
```

## Environment

- macOS arm64 (developed on Apple M2 Pro, 32 GB, MPS backend), Python 3.12.
- LaTeX: [tectonic](https://tectonic-typesetting.github.io) (auto-fetches
  `acmart` and all packages on first run; requires network once).
- No paid API is used anywhere: all LLM experiments run open-weight models
  locally via HF transformers (`Qwen2.5-Coder-3B-Instruct`,
  `Llama-3.2-3B-Instruct`, `granite-3.3-2b-instruct`; smoke tests use a ≤0.5B
  model).

## Step-by-step reproduction

All commands run from the repo root. Set the HF cache once:
`export HF_HOME=$PWD/models_dir/hf`.

### 0. Setup

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt        # or: uv pip install -r requirements.txt
.venv/bin/python -m pytest tests/ -q             # expect: 353 passed
```

### 1. Data download + validation (PrimeVul + contrast sets)

```bash
.venv/bin/python scripts/download_data.py        # downloads into data/raw/:
                                                 #   PrimeVul mirror (HF starsofchance/PrimeVul)
                                                 #     -> data/raw/primevul_hf/
                                                 #   OR-Bench (HF bench-llms/or-bench) +
                                                 #   XSTest (official GitHub repo)
                                                 #     -> data/raw/contrast/
                                                 # then validates counts locally
.venv/bin/python -m src.data.primevul            # validates the mirror vs the ICSE'25 paper
                                                 # and prints the manifest (status OK expected;
                                                 # the v0.1-mirror deviation -13.8% vulnerable is
                                                 # a disclosed data-provenance fact, not an error)
.venv/bin/python -m src.data.sampling configs/data_main.yaml   # seeded eval subsets
                                                 # -> data/manifests/*.json
```

### 2. Benchmark build (conditions C0–C3, E0 prompts, E8 contrast set)

```bash
.venv/bin/python -m src.data.bench_build configs/data_bench.yaml v2 bench safety e0
#   v2     -> data/manifests/eval_subset_v2.json (+ round2 bridge)
#   bench  -> data/benchmarks/bench_v1/bench_v1.jsonl (materialized variants)
#   safety -> data/benchmarks/safety_contrast_v1.json (60 prompts, E8)
#   e0     -> data/benchmarks/e0_prompts_v1.jsonl (function + scoring-probe rows)
```

### 3. Transformer baseline (B4, CodeBERT)

```bash
.venv/bin/python scripts/train_codebert.py --config configs/train_codebert.yaml
#   disclosed subsample: all vulnerable + 40k benign (train), seeded; resumable
.venv/bin/python scripts/eval_codebert.py --arm vd_s
#   -> outputs/transformer/codebert_eval_vd_s_metrics.json (recall/F1/MCC/AUC,
#      VD-S, paired metrics over the official 435 test pairs)
.venv/bin/python scripts/eval_codebert.py --paired-only   # audit: persist per-row
#   paired scores and re-verify stored metrics bit-for-bit
```

### 4. Refusal-monitor calibration (E0 first half)

```bash
.venv/bin/python scripts/calibrate_refusal_monitor.py --full     # 125 prompts x models
#   threshold fitting uses ONLY the calibration half; the scoring half is frozen
.venv/bin/python scripts/calibrate_refusal_monitor.py --refit-only
#   audit mode: NO generation, refit from cached jsonl
# per-model thresholds land in configs/models.yaml + outputs/transformer/calibration/
```

### 5. LLM experiments (all cached in `outputs/llm_cache/`, resumable)

Paper numbers come from the round-2/round-3 runners (the Round-1
config-driven runners `python -m src.experiments.run_eN --config configs/eN.yaml
[--dry-run]` remain available for dry-runs and protocol checks):

```bash
# E0 reproduction gate + E2/E3 robustness + E4 carrier/position (round 3 scale-up)
.venv/bin/python -m src.experiments.round3_scaleup --stage e0   --model Qwen/Qwen2.5-Coder-3B-Instruct
.venv/bin/python -m src.experiments.round3_scaleup --stage e0   --model unsloth/Llama-3.2-3B-Instruct
.venv/bin/python -m src.experiments.round3_scaleup --stage e0   --model ibm-granite/granite-3.3-2b-instruct
.venv/bin/python -m src.experiments.round3_scaleup --stage e2e3 --model Qwen/Qwen2.5-Coder-3B-Instruct
.venv/bin/python -m src.experiments.round3_scaleup --stage e2e3 --model unsloth/Llama-3.2-3B-Instruct
.venv/bin/python -m src.experiments.round3_scaleup --stage e4   --model <slug>
.venv/bin/python -m src.experiments.round3_scaleup --stage gate     # E0 gate verdict
.venv/bin/python -m src.experiments.round3_scaleup --stage summary  # summary.json/.md
#   add --dry for a no-generation dry-run of any stage

# E5 (text-stripping defenses), E6 (P1 isolation / IPI-flip), E8 (safety contrast)
.venv/bin/python -m src.experiments.pilot_round3 --exp e5 --model Qwen/Qwen2.5-Coder-3B-Instruct
.venv/bin/python -m src.experiments.pilot_round3 --exp e6 --model Qwen/Qwen2.5-Coder-3B-Instruct
.venv/bin/python -m src.experiments.pilot_round3 --exp e8 --model Qwen/Qwen2.5-Coder-3B-Instruct
.venv/bin/python -m src.experiments.pilot_round3 --exp e8 --model unsloth/Llama-3.2-3B-Instruct

# E7 (fusion policy: LLM <-> CodeBERT fallback; no LLM calls, reuses E3 records)
.venv/bin/python scripts/run_e7_fusion.py
```

Outputs: `outputs/experiments/round3_*/<model>/results.json` (+`raw/`),
each with full metadata (model id/revision, seed, config hash, date).

### 6. Collect master results + audit recomputes

```bash
.venv/bin/python scripts/final_eval_summary.py            # -> outputs/transformer/final_eval.{json,md}
.venv/bin/python scripts/recompute_pilot.py               # re-derive round-2 pilot metrics from records
.venv/bin/python scripts/recompute_e8_monitor_round3.py   # post-monitor-fix E8 recompute from raw
.venv/bin/python scripts/annotate_near_far_confound.py    # E4 near/far confound annotation
.venv/bin/python scripts/measure_intent_gate.py           # P2 gate recall measurement
.venv/bin/python scripts/select_fallback_threshold.py     # E7 fallback threshold selection
```

Number → file mapping for every paper table:
`reports/round3/S_report.md` §5. Corrected values (post-monitor-fix) must be
read from `outputs/experiments/round3_e8*/recomputed/`, not the original
`results.json` of E8-llama.

### 7. Figures + paper

Paper figures are generated from `outputs/**` into `paper/figures/`; tables in
`paper/tables/`. Build the PDF:

```bash
tectonic --outdir paper/compiled paper/main.tex
cp paper/compiled/main.pdf paper/compiled/refuseguard_paper.pdf
# -> paper/compiled/refuseguard_paper.pdf (ACM sigconf, review, anonymous; 10 pp)
```

## Smoke verification (no training, no generation, < ~2 min per step)

```bash
bash scripts/verify_repro.sh
```

Runs: full pytest suite (STRICT: "N passed" AND zero failed) → config-driven
E2 dry-run → existence + JSON-validity of every artifact the paper cites →
value checks on decision-critical numbers (≥340 master rows, E0 gate verdict
FAIL 3-completed/0-pass, E8-Llama recomputed B0 = 1/30, E6 vul-only n.s. row)
→ SHA256 artifact-manifest check → tectonic compile check of
`paper/main.tex`. Last full run at Round 4 (post-hardening): 27/27 checks
passed.

## Demo (single C file, offline)

```bash
.venv/bin/python scripts/demo_refuseguard.py path/to/function.c
# intent gate + P1 mediation + refusal monitor + CodeBERT prior (CPU).
# add --with-llm --model <HF id> to run the real P2 pipeline with a local LLM.
```

## Artifact integrity (sha256 manifest)

The small numeric artifacts the paper's numbers are read from are checksummed
into `outputs/master/ARTIFACT_MANIFEST.sha256`:

```bash
.venv/bin/python scripts/make_manifest.py           # regenerate after re-runs
sha256sum -c outputs/master/ARTIFACT_MANIFEST.sha256        # Linux
shasum -a 256 -c outputs/master/ARTIFACT_MANIFEST.sha256    # macOS
.venv/bin/python scripts/make_manifest.py --check   # portable check (used by verify_repro.sh)
```

Limitation: `outputs/` and `data/` contents are git-ignored, so the manifest
certifies the integrity of the released OUTPUTS BUNDLE (23 small result/metadata
files), not a fresh clone — on a clone the checks pass only after running
`scripts/download_data.py` and the pipeline, or after receiving the bundle.

## Provenance rules (enforced in this repo)

1. Every number in the paper traces to a file under `outputs/**` or
   `data/manifests/**`; sampling is seeded and stratified, never fit on test.
2. LLM cache keys are `(model_id, revision, template_hash, prompt_hash,
   gen_cfg_hash)`; re-running any experiment resumes from cache.
3. Pre-registrations live in `configs/*_round3.yaml` + `docs/e0_protocol.md`;
   deviations are disclosed in `reports/`, never silently patched.
4. Citations were verified against arXiv/DOI metadata (see
   `docs/literature_review.md`); unverified references are not used.

---

## Latest Results (Rounds 15–19, September 2026)

### Confirmatory Replication on Held-Out Data (n=200 NEW PrimeVul samples)

The directional corruption phenomenon **replicates on completely held-out data** (disjoint from all prior evaluation sets):

| Context | Granite-3.3-2B benign→vul FP | Llama-3.2-3B benign→vul FP |
|---|---:|---:|
| C0 (clean baseline) | 8% | 0% |
| CG (generic comment) | 8% | 0% |
| CB (benign framing) | 7% | 0% |
| **CR (risk advisory)** | **67%** | **3%** |

- Granite: **57/100 benign functions flip to "vulnerable"** under risk advisory (ΔFP = +.59, p < 10⁻¹⁵)
- CG/CB controls: ≤ 3 flips each — effect is **content-type-specific**
- 4 CWE families tested (787, 125, 703, 476) — replicates across families

### Alarm-Pruning Validation (EVIDA-2)

| Gate | Prereg threshold | Result | Verdict |
|---|---|---|---|
| Alarm precision | ≥ .40 | **1.000** (66/66) | ✅ PASS |
| Corruption Recovery Rate | ≥ .35 | **.803** (53/66) | ✅ PASS |
| Defense-Induced Error Rate | ≤ .05 | **0.000** (0/81) | ✅ PASS |
| Useful Answer Coverage | ≥ .95 | **1.000** | ✅ PASS |

**Caveats (disclosed):** recovery is fallback-driven (90.9% via CodeBERT, not invariant-checker logic); paired-vs-D1 shows 13–0 against EVIDA-2 (p = .000244) on the registered metric; truth-metric reverses to 5–8 against (n.s.); prune rule never engaged on v2 (0 FP to prune). Results are frame-regime-specific and descriptive (n < power threshold).

### Scale Boundary Resolution (7B/8B on Kaggle GPU)

| Model | A0 recall | A5 recall | Harm? |
|---|---|---|---|
| Llama-3.1-8B | .600 | .550 (p = .508) | **NO — fades at 8B** |
| Qwen2.5-Coder-7B | .483 | .533 (p = .727) | **NO — inert persists** |

Defense-induced corruption is a **3B phenomenon** that fades by 7–8B. The scale-versus-family confound is partially resolved.

### Rule-Based Baseline (GuardDog 3.2.0)

Full corpus (602/603 scannable): P .948 / R .792 / F1 .863 / AUC .870.
Group-test: F1 .866 — below graph features (.923) and comparable to TF-IDF (.833).
Same-origin bias disclosed (GuardDog rules + malicious corpus share DataDog provenance).

### MalGuard/Amalfi-Style Feature Baseline

41 label-blind features. MalGuard-only: ΔF1 −.0216 vs graph (raw p = .044, not Holm-surviving).
Combined graph+malguard: +.0150 (n.s.). Graph features **compare favorably** with MalGuard-style reimplementation.

