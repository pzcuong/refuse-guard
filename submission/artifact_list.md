# Artifact List — những gì sẽ công bố khi chấp thuận (2 bài)

Ngày: 2026-09-28 (W2, vòng 15). Nguyên tắc: mọi số trong 2 bài truy vết
về artifact; artifact bundle phải đủ để tái lập bảng/figure mà KHÔNG cần
tải lại malicious archives. Path gốc: repo
`/Users/macbook/.zcode/workspace/default/refuseguard` (đóng gói lại thành
artifact tree ẩn danh khi nộp — Paper 2 §"Data and provenance" đã mô tả
cấu trúc này).

## 1. SẼ CÔNG BỐ

### 1.1 Code
- `packguard/` — package Paper 2: schema, behavior graphs (tree-sitter),
  features, FL simulation (FedAvg/FedProx per-algo routing, unit-pinned),
  KB, safety-port, LCO/cluster (`lco.py`, `clusters.py`).
- `src/` — harness Paper 1: `llm_harness.py` (cache/resume/retry),
  `refusal_monitor.py`, `metrics/`, conditions C0–C3, defenses
  B1–B3/P1/P2, experiment runners (`run_eN`, `round3_scaleup`,
  `pilot_round3`).
- `scripts/` — `gen_paper_numbers.py` (sinh 336 macro Paper 2, có
  `--check`), `r14_guarddog_scan.py` + `r14_guarddog_metrics.py`
  (baseline GuardDog), `verify_repro.sh` (30-check smoke gate),
  `make_manifest.py`, `collect_master*.py`, train/eval CodeBERT,
  calibration, fusion E7, `demo_refuseguard.py`.
- `configs/` — toàn bộ YAML, kể cả pre-registration configs
  (`packguard_fl.yaml`, `packguard_lco.yaml`, `packguard_guarddog.yaml`
  với timestamp pre-register trước scan, `data_main.yaml`,
  `configs/*_round3.yaml`).
- `tests/` — 743 tests (pytest, chạy CPU, không cần model).

### 1.2 Dữ liệu (manifests — KHÔNG phải archives)
- `data/packguard/manifests/dataset_v2.json` — manifest 603 mẫu
  (390 malicious / 213 benign) với per-sample nguồn + sha256 + nhãn
  dataset (không gán tay).
- `data/packguard/manifests/benign_expansion_v1.json` — expansion 200
  benign npm (RANDOM draw; 17/200 hard-negative profile) — data-pack cho
  vòng sau, KHÔNG thuộc corpus đã đăng ký (disclosed trong F_report
  round-13).
- `data/manifests/*.json` — Paper 1: eval subsets + bench manifests
  (PrimeVul-based, seeded/stratified).
- Link tải nguồn chính thức: Backstabber's Knife Collection / DataDog
  malicious-software-packages-dataset (malicious); registry mirrors
  (benign). Script `scripts/download_data.py` + extract/scan pipeline
  dựng lại toàn bộ từ manifests.

### 1.3 Kết quả đo (đủ để dựng mọi bảng trong 2 bài)
- Paper 2 (`outputs/packguard/`):
  - `p0/p0_results.json` (360 rows, mock=false — corrected-baseline grid
    + TOST + μ-sweep), `trivial/trivial_results.json` (20 seeds).
  - `fl_multiseed/grid_results.json` (640 rows, grid đã đăng ký) +
    `r10/r2_grid_refresh/probs_dump.jsonl` (19,484 per-sample probs).
  - `r10/r1_stabilized_central/`, `r10/r3_calibration/`,
    `r10/r4_kb_v3/`, `r10/r7_mechanism_ablation/`,
    `r10/r8_safety_expand/` — các arm phụ đã audit.
  - `safety/safety_metrics_n60.json` + `safety_batch_n60.jsonl`
    (batch n=60 đã đăng ký), `r10/r8_safety_expand/
    safety_metrics_n100.json` + `safety_batch_n100.jsonl`.
  - `defense/defense_analysis.json` + `defense_metrics.json` +
    `defense_batch.jsonl` (attack–defense pairing, 38/45 gate-pass).
  - `lco/lco_results.json` (480 rows) + `clusters_t030.json` /
    `clusters_t050.json` + `summary.md`.
  - `kb/kb_v0002.jsonl` (142 entries: 20 seed + 122 LLM) +
    `kb_build_v2_meta.json` + `coverage_v3.json` (137/137 types).
  - `guarddog/{findings.jsonl (603), metrics.json, summary.md,
    split_membership.json, extract_status.json}`.
- Paper 1 (`outputs/master/` + `outputs/experiments/` + `outputs/transformer/`):
  - `master_results.json`, `round5_master.json`, `round6_ablation.json`,
    `round6_bias.json`, `round7_master.json`, `round6/7_token_map.json`
    — bảng số paper-facing (mapping số→file: `reports/round3/S_report.md` §5).
  - `round3_e0/`, `round3_e2e3/`, `round3_e5/e6/e8*/`, `round3_e4/`
    (results.json + raw per-record), `r10_granite_ladder/`
    (240 records, dùng làm by-domain contrast trong Paper 2 A.7).
  - `codebert_eval_vd_s_metrics.json`, `codebert_predictions_paired.jsonl`,
    `final_eval.json`, `fallback_threshold.json`, calibration outputs.

### 1.4 Provenance & audit trail
- `outputs/master/ARTIFACT_MANIFEST.sha256` — 48 file, `--check` pass
  (integrity anchor của outputs bundle).
- `docs/packguard_prereg.md` (AMENDMENT-1..7 với timestamp),
  `docs/e0_protocol.md`, `configs/*_round3.yaml` — pre-registrations.
- `reports/` — toàn bộ per-round audit trail (W/V/F reports round 1–15).
- Nguồn LaTeX 2 bài + `paper2/p0_macros/numbers.tex` (generated) +
  `paper/make_figures.py` (verify_tables).

## 2. LICENSE (ghi chú — repo CHƯA có file LICENSE, phải chọn khi release)
- **Code** (`src/`, `packguard/`, `scripts/`, `tests/`): khuyến nghị
  MIT hoặc Apache-2.0 (quyết định của author/orchestrator; Apache-2.0
  có sẵn program-patent clause — phù hợp hơn cho research code có
  dependency bên ngoài).
- **Manifests + kết quả đo (JSON/JSONL):** CC0 1.0 hoặc CC-BY 4.0
  (CC-BY nếu muốn attribution).
- **Third-party trong bundle:** GuardDog (Apache-2.0, DataDog) và
  ruleset YARA ship kèm — KHÔNG re-distribute rules; ghi version 3.2.0 +
  lệnh cài (`uv pip install guarddog`) trong README artifact.
- Datasets nguồn tuân license của chủ dataset (DataDog
  malicious-software-packages-dataset, PrimeVul/HF mirror) — bundle chỉ
  chứa con trỏ + checksum, xem §3.

## 3. KHÔNG CÔNG BỐ (và lý do)
1. **Raw malicious archives** (`data/packguard/raw/ddmalicious/`,
   `outputs/packguard/guarddog/extracted/` 1.6GB): (a) license/quy ước
   dataset DataDog — chỉ phân phối qua kênh chính thức của họ; (b) đây là
   malware thật (zips mã hóa password "infected") — re-distribution là
   rủi ro an ninh và thường bị cấm bởi policy venue. **Bundle chỉ chứa:
   per-sample source URL + sha256 + class provenance trong manifest**;
   người review tái lập bằng cách tải từ nguồn gốc.
2. **Benign tarballs/tgzs** (`data/packguard/raw/benign*/`): tái lập từ
   registry qua manifest (pin version); không thấy lợi ích khi đi kèm.
3. **Model weights**: chỉ HF id + revision (đã ghi trong metadata mỗi
   results.json); tải qua HF.
4. **`outputs/llm_cache/` và `outputs/packguard/kb/llm_cache/`**: lớn,
   tái tạo được (temperature 0, seed cố định, cache key
   model/revision/template/prompt/gen-cfg); bundle giữ outputs đã parse,
   không giữ cache thô.
5. **Địa danh tính author trong audit trail** (nếu có): ẩn danh hoá khi
   đóng gói cho bài double-blind; bản de-anonymized chỉ phát hành sau
   chấp thuận.
6. **`outputs/e0/` dry-run artifacts, `*/dry/`, `*_mock.json`, smoke
   logs**: kết quả mock/dry — theo quy ước repo không trộn với số thật,
   không đưa vào bundle (trừ khi giữ làm ví dụ schema, có cờ dry).

## 4. Việc còn mở trước khi đóng gói thật (không chặn nộp bài)
- Thêm file LICENSE (quyết định MIT vs Apache-2.0 — user/orchestrator).
- OSF upload + timestamp (P1-7) — **BLOCKED — user**.
- Human validation / annotator agreement (κ) cho KB entries + refusal
  monitor — **BLOCKED — user** (theo tasking vòng 15; chưa truy được
  artifact nguồn trong repo — ghi nhận trung thực).
- Frontier-API consult record (P1-8) — **BLOCKED — user** (ChatGPT-MCP
  not_authenticated nhiều vòng; catch-up file đã chuẩn bị).
