# PROJECT BRIEF — RefuseGuard (đọc bắt buộc trước khi làm việc)

## 1. Mục tiêu tổng thể
Triển khai hoàn chỉnh (A-Z) đề xuất nghiên cứu **"Robust LLM-Based Software Vulnerability Detection under Safety-Induced Blocking and Untrusted Code Context"** (framework **RefuseGuard**),产出:
1. Codebase thực nghiệm chạy được, tái lập được (dataset pipeline, baseline, conditions, defenses, metrics, stats).
2. Kết quả thực nghiệm thật (không bịa số) cho các thực nghiệm E0–E8 ở quy mô pilot khả thi trên máy này.
3. Bản thảo bài báo LaTeX chất lượng A*/Q1 (ICSE/FSE/TSE style) + tài liệu reproducibility.

Đề xuất đầy đủ: xem `PROPOSAL.md` (bản copy của user). Mọi quyết định thiết kế mặc định bám theo proposal; nếu phải đổi vì ràng buộc thực tế (compute/chi phí), ghi rõ vào report của mình.

## 2. Môi trường (đã kiểm chứng)
- macOS arm64, **Apple M2 Pro, 32GB RAM**, MPS cho GPU, disk trống ~54GB.
- **Python venv: `/Users/macbook/.zcode/workspace/default/refuseguard/.venv`** (Python 3.12, `uv` đã cài torch/transformers/datasets/scikit-learn/tree_sitter/tree_sitter_languages/statsmodels/matplotlib...). Luôn dùng `.venv/bin/python`. KHÔNG dùng python hệ thống (3.14, không có torch).
- **KHÔNG có API key LLM nào** → mọi LLM experiment dùng **open-weight models local qua HF transformers trên MPS**. Không gọi API trả phí.
- Internet OK (HF, GitHub, arXiv).
- Tốc độ thực tế: model 2-3B trên MPS ~10-20 tok/s; CodeBERT fine-tune batch nhỏ khả thi. Thiết kế mọi thứ **checkpoint + cache + resume**; quy mô pilot trước (hàng trăm sample), scale-up chỉ khi còn thời gian.

## 3. Nguồn dữ liệu / model đã xác minh
- **PrimeVul**: paper arXiv:2403.18624, ICSE 2025 (đúng là thật, ~6,968 vulnerable / ~229,794 benign C/C++ functions, >140 CWE, paired vulnerable/patched, chronological split, official test split). Data official bị gate; mirror HF khả dụng: `starsofchance/PrimeVul`, `Code-TREAT/PrimeVul-Paired_original_lite`; repo chính thức `DLVulDet/PrimeVul`. Bắt buộc validate số liệu sau khi tải; ghi nguồn + checksum vào manifest.
- **Defensive Refusal Bias**: arXiv:2603.01246 (ICLR 2026 Workshop) — tồn tại thật, đo refusal của cyber-defense tasks vs neutral.
- OR-Bench (ICML 2025), XSTest (arXiv:2308.01263), BIPIA (arXiv:2312.14197) — real.
- Các ref "2026" khác trong proposal (Beyond Refusal 2607.05842, CodeSentinel 2606.19235, TabooRAG 2603.03919): **phải tự verify**; nếu không xác minh được, coi là unverified, tìm paper thật tương đương thay thế, và ghi rõ trong literature review.
- Ứ viên LLM local gợi ý (chọn trong Round 2, tối đa 3 model, tổng <20GB): Qwen2.5-Coder-3B-Instruct, Llama-3.2-3B-Instruct, Gemma-2-2b-it (Gemma nổi tiếng over-refuse → tốt cho E0). Smoke test chỉ dùng model ≤0.5B.

## 4. Thiết kế nghiên cứu (tóm tắt bắt buộc)
- **Conditions**: C0 clean / C1 defensive wording / C2 benign contextual stress (comment,string,docstring mang security-sensitive text, KHÔNG đổi semantics) / C3 IPI-style instruction trong context / C4 = defenses áp lên C1-C3.
- **Baselines/Defenses**: B0 raw LLM; B1 prompt reframing; B2 comment stripping (Tree-sitter); B3 aggressive text removal; B4 Transformer-only (CodeBERT/GraphCodeBERT fine-tune); P1 Semantic Context Isolation (provenance + structured mediation, KHÔNG xóa mù); P2 RefuseGuard = task-intent gate + P1 + LLM + Refusal Monitor (ANSWER/PARTIAL/REFUSAL) + structured retry + Transformer fallback. Refusal KHÔNG được map thành "benign".
- **Output schema LLM**: JSON {analysis_status, vulnerable, cwe, location, root_cause, confidence}.
- **Metrics**: Vulnerability Recall/F1/MCC; PrimeVul-style paired eval (VD-S nếu làm được); Refusal Rate (RR); Partial Answer Rate; Usable Answer Coverage (UAC); Safety-Induced Utility Drop (SIUD = U_clean − U_context); Defense Recovery Rate (DRR); Clean Utility Loss (CUL); Unsafe Compliance Rate. Paired stats: McNemar + bootstrap CI, primary endpoint định trước.
- **Reproduction gate (E0)**: không giả định refusal xảy ra; nếu không tái lập được → pivot scope sang robustness under untrusted context (refusal là secondary). Đây là cơ chế bảo vệ validity — phải được tôn trọng trong mọi kết quả.
- **Safety preservation (E8)**: defense không được làm tăng unsafe compliance trên contrast set.

## 5. Cấu trúc repo & quyền sở hữu (tránh xung đột khi chạy song song)
```
refuseguard/
  src/data/          # PrimeVul load/validate/pair/sample/manifest
  src/models/        # transformer baseline + LLM harness + refusal monitor
  src/conditions/    # C0-C3 generators + semantic-preservation checks
  src/defenses/      # B1/B2/B3/P1/P2
  src/metrics/       # metrics + stats
  src/experiments/   # runners E0-E9, config-driven
  configs/           # YAML configs
  data/              # dataset cache (git-ignored nội dung lớn)
  models_dir/        # HF cache local (git-ignored)
  outputs/           # kết quả chạy (json/csv), git-ignore file lớn
  reports/roundN/    # báo cáo của từng agent mỗi vòng
  docs/              # literature review, protocol, EDA
  paper/             # LaTeX
  tests/             # pytest
```
- Mỗi agent CHỈ được sửa file trong thư mục được phân + file report của mình. Không đụng file của agent khác. Không chạy `git commit` (orchestrator lo).
- Code style: type hints, docstring ngắn, config bằng YAML, seed ghi rõ, mọi output có metadata (model id, date, config hash).

## 6. Nguyên tắc khoa học (không được vi phạm)
1. **Không bịa kết quả.** Mọi số trong report/paper phải truy vết được tới file output thật.
2. Không fit preprocessing/sampling trên test. Sampling stratified, seed công bố, manifest ghi sample IDs.
3. Verify citation trước khi trích; không khoe "first" nếu chưa audit literature.
4. Phân biệt rõ: kết quả đã chạy thật vs kết quả project (pending). Báo cáo trung thực về những gì chưa chạy được.
5. Model drift/reproducibility: ghi model ID + revision, temperature, seed, prompt template hash.

## 7. Quy trình 4 vòng (orchestrator điều phối)
- **Round 1 – Foundation**: literature + data pipeline + skeleton harness + protocols.
- **Round 2 – Core**: fine-tune transformer (subset), conditions thật, defenses thật, chạy pilot nhỏ.
- **Round 3 – Experiments**: chạy E0-E8 ở quy mô pilot, thống kê, bảng kết quả.
- **Round 4 – Paper**: bản thảo LaTeX đầy đủ + figures/tables từ outputs thật + repro package + audit.
Mỗi vòng: 3 tác nhân chính (song song, 3 góc) → 2 tác nhân kiểm lỗi (song song) → 1 tác nhân tổng hợp.

## 8. Canonical interfaces (BẮT BUỘC — mọi agent code theo đúng hợp đồng này)
Record chuẩn của 1 sample (dict):
`{"sample_id": str, "pair_id": str|None, "func": str, "label": 0|1, "cwe": str|None, "cve": str|None, "project": str, "split": str}`

- `src/data/primevul.py` → `load_primevul(split: str) -> list[dict]` (cache `data/raw/`); validate số liệu vs paper.
- `src/data/sampling.py` → `build_eval_subset(cfg) -> dict` ghi manifest JSON vào `data/manifests/` (sample_ids, seed, stratification, paired cases; không fit trên test semantics).
- `src/models/llm_harness.py` → `class LLMHarness: __init__(model_id, device="mps", dtype, cache_dir="outputs/llm_cache"); generate(prompts: list[dict(system,user)], gen_cfg) -> list[dict(text, meta)]`; cache key = (model_id, revision, template_hash, prompt_hash, gen_cfg_hash); bắt buộc resume.
- `src/models/refusal_monitor.py` → `classify(text: str, required_fields: list[str]) -> {"status": "ANSWER"|"PARTIAL"|"REFUSAL", "missing_fields": [...], "refusal_score": float}`; refusal detector có calibration mode dùng OR-Bench/XSTest-style prompts.
- `src/models/transformer_baseline.py` → `train(cfg)`, `predict(texts: list[str]) -> list[float]` (prob vulnerable), checkpoint trong `models_dir/`.
- `src/conditions/generator.py` → `apply_condition(sample: dict, condition: str, cfg) -> dict(func=str, meta=dict)` cho C0-C3; kèm `check_semantics(func_original, func_transformed) -> bool` (tree-sitter parse OK + không đổi executable AST).
- `src/defenses/mediator.py` → `mediate(sample: dict, defense: str, cfg) -> dict` cho B1/B2/B3/P1; P2 orchestrator riêng `src/defenses/refuseguard.py` → `RefuseGuardPipeline.run(sample, condition) -> dict` (gate → mediate → LLM → monitor → retry → fallback hook).
- `src/metrics/metrics.py` → `compute_metrics(records: list[dict]) -> dict` (RR, partial, UAC, recall/F1/MCC, SIUD, DRR, CUL, unsafe-compliance); `src/metrics/stats.py` → `mcnemar(...)`, `bootstrap_ci(...)`.
- Runners: `python -m src.experiments.run_eN --config configs/eN.yaml`; mọi runner ghi `outputs/<exp>/results.json` kèm metadata (model, seed, date, config).
- LLM output schema khóa: `{"analysis_status": str, "vulnerable": 0|1, "cwe": str|null, "location": str|null, "root_cause": str|null, "confidence": float|null}`.
