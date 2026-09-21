# W1 Report — Round 8 (PackGuard: Literature Verify + Dataset + Behavior Graphs)

Date: 2026-09-21. Owner: W1. Scope per tasking: T1 literature verify, T2 dataset,
T3 behavior graphs + features, T4 EDA + prereg data section, T5 tests.
Constraint respected: no touches to `packguard/fl.py`, `kb.py`, `safety_port.py`,
`models.py` (W2 files); `packguard/__init__.py` extended by APPEND only (W2's
docstring preserved). No git commit. No LLM runs.

## 1. What was done

- **T1 Literature verify**: all 6 user citations checked against the arXiv API
  (`export.arxiv.org`, 2026-09-21) and publisher pages:
  - MALGUARD → **MalGuard** arXiv:2506.14466, USENIX Security 2025 (venue per
    program pages; arXiv record verified) — VERIFIED.
  - DONAPI → arXiv:2403.08334, USENIX Security 2024 — VERIFIED.
  - Cerebro → arXiv:2309.02637, **TOSEM 2024, DOI 10.1145/3705304** (arXiv comment
    field confirms "accepted in TOSEM 2024") — VERIFIED.
  - VulFL → arXiv:2411.16099 (2024), no journal ref — VERIFIED as preprint; venue
    UNVERIFIED (must be cited as arXiv preprint).
  - SecurityAI → **Shifting the Lens** arXiv:2408.08924 (Zahan et al., Snyk);
    "SecurityAI" is their workflow/benchmark name, not the title — VERIFIED with
    naming caveat.
  - Ladisa → arXiv:2204.04008, journal ref **IEEE S&P 2023 pp.1509–1526** — paper
    VERIFIED but the user's venue "ACSAC 2023" is WRONG (it is S&P; corrected).
  - **Novelty verdict** (docs/packguard_literature.md §3): both claims defensible
    with "to our knowledge" hedges. Claim A (safety-layer interference in
    malicious-package detection): no duplicate found; SecurityAI measures LLM
    accuracy, not refusal interference. Claim B (FL over ecosystem-partitioned
    clients for this task): no duplicate found; FL exists for *vulnerability*
    detection (VulFL) and Cerebro is cross-ecosystem but centralized — must be
    credited explicitly.
- **T2 Dataset**: DataDog `malicious-software-packages-dataset` is 20.9 GB — full
  clone impossible. Solved with partial clone (`--filter=blob:none --no-checkout
  --depth 1`) + local `git ls-tree` + sparse-checkout of a deterministic stride
  sample. BKC Zenodo query returned unrelated records (not usable in time-box);
  MalOSS repo URL 404 — both disclosed and replaced in refs by Ohm DIMVA 2020 /
  Duan IMC 2021. Benign: npm registry popularity search (5 keywords) +
  hugovk/top-pypi-packages, tarballs capped 2.5 MB.
  - **Real counts** (`data/packguard/manifests/dataset_v1.json`): malicious
    npm 298 + pypi 86 = 384; benign npm 123 + pypi 90 = 213; total **597
    samples, 2 ecosystems** — exceeds the ≥150/≥150 target; Maven not attempted
    (disclosed). 0 duplicate archives removed. sha256 per sample stored.
- **T3 Behavior graphs**: `packguard/schema.py` (6-class semantics + per-language
  mapping tables, SCHEMA_VERSION 1.0.0, machine-readable `schema_json()`),
  `packguard/graphs.py` (tree-sitter python/javascript; node=(class,API), seq
  edges per scope, data edges via produced-var tracking; alias + destructuring +
  `require('m').f()` resolution; setup.py/postinstall entry kinds), `packguard/
  features.py` (18 graph-level features + batch CLI), `packguard/dataset.py`
  (manifest builder). Batch run: **597/597 extracted, 0 extraction errors, 468
  samples with non-empty graphs** (78.4%; empty rows kept as all-zero + disclosed).
- **T4 EDA + prereg**: `outputs/packguard/features/eda_v1.md` (coverage table,
  class-histogram means, per-ecosystem contrast, univariate AUCs) + prereg §DATA
  appended to `docs/packguard_prereg.md` (selection rule, seed 20260922, coverage
  duties, limitations L1–L5, freeze/amendment policy).
- **T5 Tests**: `tests/test_packguard_w1.py` — **35 passed** (mapping 22 cases +
  table completeness, graph determinism/classes/edges, feature schema, parse-fail
  disclosure, archive extraction incl. encrypted-zip convention).

## 2. Files (all absolute)

Code (W1-owned):
- /Users/macbook/.zcode/workspace/default/refuseguard/packguard/schema.py
- /Users/macbook/.zcode/workspace/default/refuseguard/packguard/graphs.py
- /Users/macbook/.zcode/workspace/default/refuseguard/packguard/features.py
- /Users/macbook/.zcode/workspace/default/refuseguard/packguard/dataset.py
- /Users/macbook/.zcode/workspace/default/refuseguard/packguard/__init__.py (appended only)

Data / outputs:
- /Users/macbook/.zcode/workspace/default/refuseguard/data/packguard/manifests/dataset_v1.json
- /Users/macbook/.zcode/workspace/default/refuseguard/data/packguard/raw/ddmalicious/ (partial clone, 893 MB incl. .git; samples 444 MB, 390 zips)
- /Users/macbook/.zcode/workspace/default/refuseguard/data/packguard/raw/benign/ (27 MB; npm 123 tgz, pypi 90 sdists)
- /Users/macbook/.zcode/workspace/default/refuseguard/outputs/packguard/features/features_v1.parquet (597x22, 35 KB)
- /Users/macbook/.zcode/workspace/default/refuseguard/outputs/packguard/features/features_v1.jsonl (334 KB)
- /Users/macbook/.zcode/workspace/default/refuseguard/outputs/packguard/features/graphs_v1.jsonl.gz (39 KB)
- /Users/macbook/.zcode/workspace/default/refuseguard/outputs/packguard/features/extraction_report_v1.json
- /Users/macbook/.zcode/workspace/default/refuseguard/outputs/packguard/features/eda_v1.md (+ eda_coverage_v1.json, eda_auc_v1.json)

Docs / config / tests:
- /Users/macbook/.zcode/workspace/default/refuseguard/docs/packguard_literature.md
- /Users/macbook/.zcode/workspace/default/refuseguard/docs/packguard_refs.bib (verified-only entries)
- /Users/macbook/.zcode/workspace/default/refuseguard/docs/packguard_prereg.md (§DATA appended)
- /Users/macbook/.zcode/workspace/default/refuseguard/configs/packguard_data.yaml
- /Users/macbook/.zcode/workspace/default/refuseguard/tests/test_packguard_w1.py

## 3. How to run

```
cd /Users/macbook/.zcode/workspace/default/refuseguard
.venv/bin/python -m packguard.dataset --root data/packguard/raw --out data/packguard/manifests/dataset_v1.json
.venv/bin/python -m packguard.features --manifest data/packguard/manifests/dataset_v1.json --outdir outputs/packguard/features --tag v1
.venv/bin/python -m pytest tests/test_packguard_w1.py -q
```
Notes: raw DataDog subset already on disk; re-download not needed. Feature schema:
`packguard.schema.schema_json()`.

## 4. Deviations from the spec (honest)

1. **BKC/MalOSS not used**: BKC not retrievable via Zenodo query in time-box;
   MalOSS repo 404 at probed URL. Replaced by DataDog wild-capture dataset
   (npm+PyPI native, per-sample classes). Both cited in refs via their papers.
2. **Maven absent**: target was npm+PyPI (Maven "chỉ nếu nhẹ") — not attempted;
   cross-language claim is therefore JS/Python only for the pilot.
3. **Benign labels are popularity-derived**, not audited (same practice as
   DONAPI/Cerebro); disclosed per-sample in `label_source`.
4. **Multiple versions per malicious package kept** (near-duplicate risk);
   disclosed in manifest selection policy; dedupe by sha256 only.
5. **pypi-benign graph coverage 55.6%** (40/90 empty graphs under the 12-file/
   100KB caps) vs 82–84% elsewhere — asymmetric coverage disclosed (prereg L1);
   empty rows are kept, never silently dropped.
6. **Mapping tables are hand-curated**; bare-name matching (e.g. JS bare `exec`)
   can over-trigger on benign aliased code (prereg L4).
7. DataDog zips are encrypted with the dataset's documented password `infected`
   (README); extractor implements this convention and a test pins it.
8. Ladisa venue corrected (S&P 2023, not ACSAC 2023); VulFL cited as preprint.

## 5. TODO (for next rounds)

- W2/F: FL splits must report per-cell coverage (prereg D4) and consider
  excluding or down-weighting empty-graph rows in an ablation arm.
- Expand pypi-benign pool with sdists that expose code (raise 55.6% coverage);
  optional third ecosystem (Maven) via finer-grained sparse checkout.
- KB (W2) should consume `graphs_v1.jsonl.gz` imports/classes as seed entries.
- De-duplication study across versions (exact/semantic) before paper claims of n.
- Feature schema bump policy: any mapping change ⇒ SCHEMA_VERSION 1.1.0 + re-run.

## 6. Self-test (real, run in this session)

- `pytest tests/test_packguard_w1.py` → **35 passed** (mapping, determinism,
  features schema, disclosure, encrypted zip).
- Legacy suite untouched: `pytest tests/ --ignore=tests/test_packguard_w1.py`
  → **580 passed**.
- Real batch extraction on 597 downloaded samples: 597 rows, 0 extraction errors,
  468 non-empty graphs (report: extraction_report_v1.json).
- Determinism spot-check: identical `build_graph` JSON for same source (test).
- Real-data signal check (from features_v1, with-graph n=468): best univariate
  AUCs max_repeat 0.784 / density 0.783 / n_edges 0.777 / seq_depth 0.777;
  npm install-hook rate 60% malicious vs 1% benign (has_postinstall AUC 0.730).
  These numbers are traceable to outputs/packguard/features/eda_v1.md.
