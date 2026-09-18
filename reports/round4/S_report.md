# S Report — Round 4 (VÒNG CUỐI): Tổng hợp, sửa lỗi V1/V2, chốt "paper sạch"

Ngày: 2026-09-19. Tác nhân: S (tổng hợp, vòng 4). Phạm vi: CHỈ các fix trong
danh sách được điều phối (FIX LIST 1→10). Không generation LLM mới; CodeBERT
inference CPU (vài giây) cho demo smoke. Mọi số dưới đây đối chiếu với
`outputs/master/master_results.json` (341 rows, đã regenerate + verify) và
các file nguồn trước khi gõ.

---

## Verdict: HOÀN THÀNH 10/10 fix. Paper compile sạch (0 error), pytest 353/353,
verify_repro **27/27 PASS**, PDF grep sạch các claim đã thu hồi.

---

## Fix 1 [HIGH-V1] — Thu hồi claim "fallback decisions 2/2 correct"

- `paper/tables/tab_defenses.tex`: dòng `E7 (fallback) & fallback decisions &
  2/2 correct` → `E7 (fallback) & fallback invocations & 2 of 133 records;
  per-case correctness not persisted`. UAC gain GIỮ NGUYÊN (0.985 vs 1.000,
  +0.015; MCC 0.0789 vs 0.0942 — không số nào khác bị đụng). Comment nguồn
  bổ sung: `n_fallback_used = 2 (C0 x1 + C3 x1); per-case correctness is NOT
  persisted (master disclosure #7)`.
- `paper/sections/05_results.tex` (RQ5): "(coverage gain $+0.015$; both
  fallback decisions correct)" → "(coverage gain $+0.015$; two fallback
  invocations on the 133-record pilot; per-case fallback correctness is not
  persisted in the released outputs)".
- Regression guard: `paper/make_figures.py::verify_tables()` giờ assert
  `"2/2" not in tab_defenses.tex` và `"2/2 correct" not in 05_results.tex`
  — claim đã thu hồi không thể tái xuất hiện mà không fail verify.
- Nguồn sự thật: `outputs/experiments/round3_e7/e7_fusion_results.json`
  chỉ có `n_fallback_used=2`, KHÔNG có per-case correctness (đúng như
  V1 HIGH-1 + disclosure #7).

## Fix 2 [MED-V1] — Cập nhật 3-model E0 (granite hoàn tất, gate FAIL 3/3)

Số đối chiếu trước khi gõ (nguồn `outputs/experiments/round3_e0/gate_verdict.json`
+ `master_results.json`): granite `completed=true, delta_rr=0.0, p_value=1.0`;
`verdict=FAIL, models_completed=3, models_pass=0, models_min=2`;
`e0.granite2b.arm.*.RR = 0.0` (n=20/arm); `e0.granite2b.probe.*`: over-refusal
0.333/0.333/0.167 (n=12 COMPLY), unsafe-compliance 0.538/0.385/0.462 (n=13
REFUSE); E2/E3 granite 300/300 (RR 0.000, UAC 1.000, recall
0.033/0.033/0.300/0.367/0.133). Metadata granite: `n_cache_calls=135,
n_cache_hits=135, gen_seconds_new_tokens_only=0.0, partial=False`.

Các chỗ sửa:
1. `00_abstract.tex`: "two open-weight 3B models" → "three open-weight
   instruct models".
2. `01_intro.tex`: "across two 3B models" → "across three open-weight
   models" (khoảng 8–75% benign probes vẫn đúng: granite 0.167–0.333 nằm
   trong khoảng).
3. `04_setup.tex` §Scale: E0 "all three registered models completed —
   Granite's Round-3 run stopped early after an infrastructure fault
   (disclosed in our artifact logs), and its Round-4 completion re-used the
   fully cached raw generations (135/135 cache hits, zero new generations)";
   E2/E3 "all three models completed".
4. `04_setup.tex` §Scale — 2 disclosure mới (đúng nội dung yêu cầu):
   (a) "Granite's refusal-monitor thresholds are fitted *in-sample* on its
   own 25 scoring probes — unlike the two main models, it has no held-out
   calibration half" (nguồn: granite results.json `monitor_fit_report.disclosure`,
   master disclosure #8); (b) "Granite complies with 0.538 of the 13
   refuse-expected probes in the neutral arm, a model-level anomaly against
   our safety sanity floor, which we report as measured rather than
   filtered" (= 7/13, `e0.granite2b.probe.neutral.unsafe_compliance_rate`).
5. `05_results.tex` fig caption: "(two completed models)" → "(all three
   registered models)"; sources thêm `granite2b`; caption nhắc anomaly được
   disclose ở setup.
6. `paper/make_figures.py::fig_e0_rr()`: figure vẽ lại với **3 model**
   (thêm Granite-3.3-2B, màu xám; title panel (a) "McNemar p = 1.0/1.0/1.0").
   Structural asserts cũ (`partial is False`, `RR==0.0`, `pass_this_model is
   False`) giờ tự cover granite. `fig_e0_rr.pdf` regenerate.
7. `05_results.tex` RQ1: "0.000 in all three arms for **all three registered
   models** (Qwen2.5-Coder-3B, Llama-3.2-3B, and Granite-3.3-2B); ΔRR=0.000
   ... for each model"; thêm câu granite probes: "over-refusal 16.7–33.3%
   across arms ... complying with 38.5–53.8% of refuse-expected probes — the
   highest unsafe-compliance rates we measure, disclosed as a model-level
   anomaly rather than filtered".
8. `paper/tables/tab_main.tex`: +2 hàng granite E0 (RR 0.000×3 + gate FAIL;
   probes 0.333/0.538, 0.333/0.385, 0.167/0.462 — từng số khớp master);
   caption middle panel ghi rõ "Granite-3.3-2B replicates the same RR 0.000 /
   UAC 1.000 pattern with recall 0.033–0.367; released artifacts"; comment
   stale "(E0 2 models...)" → "(E0 3 models; E2/E3 3 models x 300 records...)".
   `verify_tables()` thêm assert đối chiếu 3 ô probe granite với file.
9. `06_discussion.tex` (Coverage threats): "a third registered model (Granite)
   crashed post-generation and is excluded" → "E0 and E2/E3 cover all three
   registered models, with two Granite-specific disclosures: [in-sample fit]
   + [0.538 anomaly] (\S\ref{sec:setup})".
10. `07_conclusion.tex`: "two 3B models never refuse" → "all three registered
    models never refuse".
11. `scripts/collect_master.py` + master: `cross`-check list của
    `make_figures.py` thêm 3 hàng granite (RR 0.0; probe neutral 0.3333,
    unsafe 0.5385) → "[verify] **17** headline numbers" (trước 14).

## Fix 3 [LOW-V1] — Wording

- (a) `04_setup.tex`: "max 512 new tokens" → "per-experiment generation
  budget is 200–320 new tokens (round-3 configs: 200 for the E0/E8 probe
  arms, 300 for E0/E2/E3 functions, 320 for E5/E6; harness default 512)".
  Đối chiếu config thật: `configs/e0_round3.yaml:85-86` (300/200),
  `e2e3_round3.yaml:65` (300), `e5_round3.yaml:29` + `e6_round3.yaml:28`
  (320), `e8_round3.yaml:27` (200), `models.yaml:59` default 512.
- (b) E8 n: "150 records per model --- B0 60 (30 unsafe + 30 safe), P2 60
  (30 unsafe + 30 safe), P1 30 (safe prompts only; P1 has no intent gate and
  hence no unsafe arm in the round-3 output)" — hết cách hiểu 180.
- (c) `03_method.tex` §B4: `CodeBERT classifier~\cite{feng2020codebert} ...
  PrimeVul training split~\cite{ding2025primevul}`. Entry `feng2020codebert`
  (đã V1 verify metadata) copy từ `paper/refs.bib` sang `docs/refs.bib`
  (check_citations đối chiếu docs/refs.bib) → cite keys dùng 16 → **17**,
  "[cites] 17 keys used, all present".
- (d) precision "≈0.48" → "$0.48$--$0.49$" tại `05_results.tex` (RQ2) và
  `06_discussion.tex` (thật: 0.4800/0.4915/0.4828/0.4912 — V1 INFO-2).
- (e) campbell2026 "2.7×": **ĐÃ VERIFY** — arXiv:2603.01246 abstract ghi
  refuse "...at 2.72× the rate of semantically equivalent neutral requests
  (p < 0.001)" (fetch 2026-09-19) → paper GIỮ số; TODO trong
  `docs/literature_review.md:104-106` đóng kèm trích nguyên văn.
- (f) disclosure #9: wording sai nằm trong `master_results.json`
  (sinh bởi `scripts/collect_master.py`, KHÔNG phải trong
  `docs/results_master.md`): "1/50 paraphrase escape" → sửa thành
  "on the 50-prompt paraphrase scoring half the lexical gate **blocked only
  1/50 (49/50 escaped)**, per intent_gate_v2_measurement.json
  (e8_scoring_half_unsafe)" + note ghi rõ việc sửa. **Lưu ý trung thực**:
  fix-list ghi hướng "blocked 49/50, escaped 1/50", nhưng file thật
  `intent_gate_v2_measurement.json` ghi `e8_scoring_half_unsafe:
  {"blocked": 1, "n": 50}` → theo "theo file thật" tôi sửa theo chiều
  blocked=1/50, escaped=49/50 (khớp hướng diễn đạt sẵn đúng của paper:
  "blocks ... only 1/50 paraphrased OR-Bench-toxic"). Sau sửa đã chạy lại
  `collect_master.py`: `[collect] rows=341 pending=0 contradictions=2` +
  `[verify] OK — all 341 master rows match` (idempotent, chỉ disclosures đổi).

## Fix 4 [BUG-V2] — README bước 1: download thật

- Mới: `scripts/download_data.py` (~150 dòng):
  - PrimeVul: `huggingface_hub.snapshot_download(repo_id="starsofchance/PrimeVul",
    repo_type="dataset", local_dir=data/raw/primevul_hf,
    allow_patterns=["primevul_*.jsonl","README.md","file_info.json"])`
    (danh sách file mirror xác minh qua HF API — khớp layout
    `src/data/primevul.py` đọc).
  - OR-Bench: `hf_hub_download(repo_id="bench-llms/or-bench")` cho
    `or-bench-hard-1k.csv` / `or-bench-toxic.csv` (tên remote có dấu gạch —
    xác minh qua HF API) → copy sang tên underscore mà
    `src/data/contrast.py` cần (`or_bench_hard_1k.csv` / `or_bench_toxic.csv`).
  - XSTest: repo GitHub chính thức `paul-rottger/exaggerated-safety`
    (raw `xstest_prompts.csv`, HTTP 200); bản HF `paul-rottger/xstest`
    gated/không tồn tại (401/error — đã probe) → ghi nguồn GitHub.
  - Tự validate sau tải: `validate_primevul()` + 3 corpus loader.
- Chạy thật (files đã có → giữ nguyên, chỉ refresh metadata + validate):
  `[validate] PrimeVul mirror starsofchance/PrimeVul: status=OK vul=6004
  ben=218529 dev_vs_paper={'vulnerable': -0.1383, 'benign': -0.049}`;
  `[validate] contrast corpora readable: or-bench-hard=1319,
  or-bench-toxic=655, xstest=450`. EXIT=0.
- README bước 1 viết lại: gọi `scripts/download_data.py` trước, sau đó
  `-m src.data.primevul` (đúng vai trò validate). Thêm câu disclosure mirror
  v0.1 (−13.8%) vào README (leftover V2 §5).
- Sửa tham chiếu chết (V2 BUG-1 phần 2): error message
  `src/data/primevul.py` ("docs/e0_protocol.md section 'Data download'" —
  heading không tồn tại) → "Run scripts/download_data.py first (README
  step 1)"; 2 chỗ tương tự trong `src/data/contrast.py:48,74` →
  "run scripts/download_data.py first". (docs/e0_protocol.md giữ nguyên —
  chỉ mục data thật là "## 2. Data (frozen, seed 20260918)"; contrast
  corpora có nguồn ghi rõ ở README + docstring contrast.py.)

## Fix 5 [BUG-V2] — verify_repro.sh cứng hoá

- (a) pytest STRICT: parse `\b([0-9]+) passed` bắt buộc + reject
  `\b([1-9][0-9]*) failed`; không khớp "N passed" → FAIL. Regression test
  chuỗi của V2: `out="352 passed, 1 failed, 1 warning in 14.71s"` →
  **CORRECTLY-REJECTED** (script cũ PASS sai — BUG-2 đóng).
- (b) Step 4 mới "value checks on decision-critical numbers": master
  parse + rows ≥ 340 (thật: **341**); `gate_verdict.json verdict==FAIL`
  + models_completed==3 + models_pass==0; E8-Llama recomputed
  `B0.unsafe_compliance_rate == 1/30` (thật: 0.0333) + P2==0.0; master có
  row `e6.discordant.vul_only_b01_b10_p` với `mcnemar_p==0.5` (n.s.);
  master `e0.gate.verdict=="FAIL"`.
- Step 3 thêm 3 artifact thiếu theo V2: `master_results.json`,
  `gate_verdict.json`, `round3_e0/granite2b/results.json` (19 → 22 file).
- Chạy lại toàn bộ: **`=== SUMMARY: 27 passed, 0 failed`** (pytest 353
  passed, 0 failed → PASS đúng cơ chế mới).

## Fix 6 [MED-V2] — Artifact integrity manifest

- Mới: `scripts/make_manifest.py` — SHA256 của 23 file nhỏ chứa số liệu
  (master_results.{json,md}; gate_verdict + summary + results.json 3 model
  E0; results.json 3 model E2/E3; E5/E6/E7; E8 recomputed ×2;
  final_eval.json + codebert_eval_vd_s_metrics.json + fallback_threshold +
  2 calibration full_report; bench_v1_meta + e0_prompts_v1_meta +
  safety_contrast_v1) → `outputs/master/ARTIFACT_MANIFEST.sha256` (format
  `sha256sum -c`). Có `--check` (portable, dùng trong verify_repro vì macOS
  không có `sha256sum` mặc định).
- Chạy thật: `[manifest] wrote ... (23 files, 0 missing)`; `--check`:
  `[manifest] 23 ok, 0 mismatched, 0 missing`.
- README: mục mới "Artifact integrity (sha256 manifest)" + 3 lệnh verify +
  **ghi chú hạn chế** đúng yêu cầu: `outputs/` + `data/` git-ignored nên
  manifest chứng tính toàn vẹn của **outputs bundle phát hành** (23 file
  nhỏ), KHÔNG chứng "fresh clone có sẵn số" — clone phải chạy
  download_data + pipeline hoặc nhận bundle; verify_repro thêm step 5 chạy
  `make_manifest.py --check`.

## Fix 7 [MED-V2] — Demo tối thiểu

- Mới: `scripts/demo_refuseguard.py` (~150 dòng): CLI nhận path file C →
  (1) task-intent gate (lexical/structural, `_intent_gate` +
  `_payload_safety_flag` — payload parse được C thật thì `safe`);
  (2) P1 mediation qua `src.defenses.mediator.mediate(sample,"P1")`;
  (3) B4 prior `TransformerBaseline(config_path="configs/models.yaml",
  cfg={"device":"cpu"}).predict([...])` (CPU mặc định, checkpoint
  `models_dir/transformer_baseline/best`); (4) refusal monitor
  `default_monitor().classify(schema-JSON-từ-prior, prompt_safety_flag=...)`;
  cờ `--with-llm --model <HF id>` (MẶC ĐỊNH OFF) chạy full P2 với
  `LLMHarness` + `RefuseGuardPipeline.run`.
- Smoke test THẬT (offline, không LLM): hàm C thật từ
  `data/raw/primevul_hf/primevul_test.jsonl` (idx **195017**, project
  **gpac**, target=1, 455 chars) → output nguyên văn:
  ```
  --- 1. task-intent gate (request + payload) ---------------------
  request task_class : defensive_vulnerability_analysis
  payload parses as C function: True -> prompt_safety_flag=safe
  --- 2. P1 semantic-context mediation ----------------------------
  applied=True semantics_ok=True
  --- 3. B4 CodeBERT prior prob(vulnerable) -----------------------
  prob(vulnerable) = 0.0224  (checkpoint models_dir/transformer_baseline/best, device=cpu)
  --- 4. refusal monitor (schema verdict from the B4 prior) -------
  status=ANSWER refusal_score=0.000 missing_fields=[] unsafe_compliance=None
  ```
  (prior 0.0224 trên 1 hàm vulnerable thật — trung thực với chính kết luận
  paper: CodeBERT bỏ sót phần lớn vulnerable ở FPR hẹp.)

## Fix 8 — RECOMPILE + VERIFY (điều kiện "paper sạch")

| Kiểm | Lệnh | Kết quả thật |
|---|---|---|
| Compile | `tectonic --outdir paper/compiled paper/main.tex` | EXIT=0, 0 error (warning cosmetic Overfull hbox/vbox) |
| PDF | `cp main.pdf refuseguard_paper.pdf` + `pdfinfo` | **10 trang**, 278–280 KB |
| Grep PDF | `pdftotext` + grep | `"2/2 correct"`=0, `excluded`=0, `crashed`=0, `??`=0, `0.00049`=0 |
| Figure/table verify | `.venv/bin/python paper/make_figures.py` | EXIT=0; `[verify] all table numbers match`; `[verify] 17 headline numbers cross-checked`; `[cites] 17 keys`; 5/5 figures |
| Tests | `.venv/bin/python -m pytest tests/ -q` | **353 passed**, 1 warning (SyntaxWarning cũ, V2 BUG-3 — ngoài fix list) |
| Repro | `bash scripts/verify_repro.sh` | **27 passed, 0 failed** |
| Master | `.venv/bin/python scripts/collect_master.py` | rows=341 pending=0 contradictions=2; verify OK 341/341 |

Ghi chú: "comments excluded" trong định nghĩa C2 (03_method) đổi thành
"comments ignored" để grep-gate "excluded" không âm tính giả — không số nào
đụng tới. Hai "dị thú" pdftotext ("demonnomenon", "DePre-registered") đã
kiểm tra: chỉ là artifact trộn cột của pdftotext trên layout 2-cột acmart,
nguồn .tex sạch.

## Sức khỏe cuối (deliverables)

- Tests: 353 passed / 0 failed. PDF: 10 trang, compile sạch. Master: 341
  rows, verify 341/341. E0 gate: FAIL — 3/3 completed, 0/3 pass → PIVOT.
- Proposal §14: (1) code tái lập ✅; (2) manifests + bench meta ✅ (kèm
  ARTIFACT_MANIFEST.sha256 cho bundle); (3) CodeBERT checkpoint ✅ (local);
  (4) prototype P1/P2 ✅; (5) bảng + CI + stats ✅; (6) safety-preservation
  report ✅ (E8 + disclosures); (7) **demo ✅ MỚI**
  (`scripts/demo_refuseguard.py`); (8) manuscript ✅ (`paper/compiled/
  refuseguard_paper.pdf`, 10 trang) — luận văn 7 chương vẫn không có (đã
  được V2 chấp nhận theo phạm vi PROJECT_BRIEF).
- File mới: `scripts/download_data.py`, `scripts/make_manifest.py`,
  `scripts/demo_refuseguard.py`, `outputs/master/ARTIFACT_MANIFEST.sha256`,
  `reports/round4/{S_report,ROUND4_SUMMARY}.md`. File sửa: 8 file
  `paper/sections/*.tex` + `paper/tables/tab_{main,defenses}.tex` +
  `paper/make_figures.py` + `docs/refs.bib` + `docs/literature_review.md` +
  `scripts/{collect_master,verify_repro.sh}` + `README.md` +
  `src/data/{primevul,contrast}.py` (error pointers) +
  `outputs/master/master_results.{json,md}` (regenerate, disclosure #9).

*Không git commit (orchestrator lo). Không generation LLM mới.*
