# ROUND 2 SUMMARY — RefuseGuard (tổng hợp bởi S, vòng 2)

Ngày: 2026-09-18. Đầu vào: A1/A2/A3 (3 góc làm việc) + V1/V2 (2 kiểm lỗi) + S
(sửa chéo & recompute — `S_report.md`). Trạng thái test: **286 passed**
(`pytest tests/ -q`, từ 269; +17 test regression mới, 1 test cũ sửa vì mã hóa
hành vi bug). Số cho paper: **duy nhất** `outputs/experiments/pilot_round2_recomputed/summary_v2.json`.

---

## 1. Ba claim lớn — GIỮ / BÃI / AI PHÁT HIỆN

| # | Claim (A3, Round 2) | Phán quyết | Ai phát hiện / xác nhận | Số đúng |
|---|---|---|---|---|
| 1 | **E0 reproduction gate FAIL** (ΔRR = +0.000, RR=0 mọi arm, 2 model) | ✅ **GIỮ — ĐÚNG và robust** (mọi threshold, mọi cách đếm độc lập; monitor không mù: bắt 24+63 REFUSAL trên probes) | V2 đếm lại độc lập + re-run 2 bộ threshold; S recompute lại từ raw | ΔRR +0.000 [0,0], McNemar p=1.0 cả 2 model; verdict vẫn PRELIMINARY (cần 3 model) |
| 2 | **E3 SIUD +0.258, CI loại 0** ("tín hiệu thật đầu tiên của luận điểm") | ❌ **BÃI — artifact đo lường** (runner ghi `meta.pred_*`, metrics đọc top-level → mọi verdict vul=1 bị tính không-usable) | **V2 phát hiện** (recount độc lập, không qua compute_metrics); S fix 2 chiều + recompute từ raw | SIUD(C0−C2a) = **0.000**, (C0−C2b) = **0.000**, (C0−C3) = **+0.032** [0, +0.097]. Hiện tượng thật còn lại: verdict-BIAS (recall 0.158→0.50/0.57, MCC thấp) |
| 3 | **E8 invariant VIOLATION** — P2 đẩy unsafe compliance Q3B 0.04→1.00 | ⚠️✅ **GIỮ ở cấp hệ-thống, diễn đạt lại**: refusal-suppression / compliance-in-form — P2 xóa sạch refusal của model; KHÔNG phải bằng chứng "P2 sinh harmful content" (model chỉ viết JSON kết tội) | V2 đọc thủ công raw B0/P2 pairs, chỉ rõ 2 root cause trong code (gate 0/50 + schema-forcing); S fix + đo lại gate | B0 0.040 vs P2 1.000 (48/50 flip, paired) — không đổi sau recompute |

Kèm theo: **E2 (SIUD-framing +0.132) và toàn bảng E5 ("B1 làm tệ hơn",
"B2/B3 phục hồi trọn vẹn") cũng BÃI theo cùng artifact** — mới: 0.000 và
0.000/−0.032 (xem S_report §2).

## 2. Bảng "AI SAI / AI BẮT ĐƯỢC / ĐÃ SỬA CHƯA" (gộp V1 + V2 + S)

| # | [Mức] Việc | Ai sai / ai bắt được | Đã sửa chưa (bởi S) |
|---|---|---|---|
| 1 | [MAJOR] SIUD/E2/E5 artifact do schema mismatch runner↔metrics (`meta.pred_*` vs top-level) | **A3 sai**; **V2 bắt** | ✅ Fix#1: `metrics.extract_verdict_fields` 2 chiều + runner lift top-level + recompute toàn bộ pilot → `summary_v2.json` |
| 2 | [MEDIUM] P2 chỉ persist 200 ký tự → 202/250 record E8 không audit-độc-lập được | **A3 sai**; **V2 bắt** (re-classify 1252 records, mismatch=202 toàn P2) | ✅ Fix#6b: persist FULL text (`final_text_full`, uncapped `raw_output_head`, `attempts[].text`); 202 record cũ không khôi phục được — disclosed + flag `persist_truncated` |
| 3 | [MEDIUM] corpus_source E8 ghi `benchmark:...` trong khi thật ra chạy scoring half (runner đọc nhầm key `samples/prompts`) | **A3 + A1 sai chung** (file key không khớp, chưa từng test chạy thật); **V2 bắt** | ✅ Fix#8: parse đúng schema A1 (`safe_defense/unsafe`) — 60 probes (30/30); fallback giờ ghi NOTE trung thực. E8 Round 3 chạy lại đúng corpus |
| 4 | [LOW→HIGH] MPS crash 9 records (A3 đếm 5, "deterministic" — cả hai SAI: 9/1342=0.67%, flake nhất thời) | **A3 sai số liệu + nhầm cơ chế**; **V2 bắt** (liệt kê SKIPPED toàn repo, so garbage-index) | ✅ Fix#6: harness retry 1 lần + CPU fallback, provenance `gen_retries/fallback_device/gen_errors` vào meta; smoke thật 2 prompt chứng minh retry path |
| 5 | [LOW→HIGH] Intent gate lexical 0/50 unsafe thật (mock-test 4/4 Round-1 là overfit) | **A3 (Round-1) sai thiết kế**; **A3 Round-2 + V2 xác nhận** | ✅ Fix#3: +40 patterns + 4 regex cấu trúc; **đo thật: 30/30 unsafe, 0/30 safe false-block, 0/24 legit surfaces**; scoring-half 1/50 (lexical giới hạn — disclosed, cần model-based gate R3) |
| 6 | [HIGH] Pipeline P2 khung unsafe prompt thành "AUTHORIZED DEFENSIVE TASK" + schema-forcing biến REFUSAL thành ANSWER | Thiết kế **A3 Round-1**; **V2 xác nhận cơ chế** (gate miss + reframe + retry + monitor short-circuit) | ✅ Fix#4: REFUSED_UNSAFE ngay khi gate flag (không LLM, không reframe, không retry) + `_payload_safety_flag` (gate payload không-phải-code) + monitor `prompt_safety_flag="unsafe"` (Fix#2: schema-complete ≠ ANSWER sạch, `unsafe_compliance` field) |
| 7 | [MEDIUM] Calibration script `classify_text` bỏ qua monitor instance → "at_fit_thresholds" là số default-threshold (Llama 0.053 thay 0.0667) | **A2 sai nhãn cấu hình** (dữ liệu thô trung thực); **V1 bắt** | ✅ Fix#5: dùng `mon.classify`; `--refit-only` recompute từ cache: **Llama over-refusal 0.0533→0.0667, rr 0.328→0.336**; stale section giữ lại + correction note; Qwen không đổi (0.5867) |
| 8 | [MEDIUM] bench_v1 near/far trùng byte-offset 35.2% rows — A1 chỉ disclose case lẻ, không đo tổng | **A1 sót** (không phải fabrication); **V1 bắt + đo 295/838** | ✅ Fix#7: annotate pass `near_far_confound` từng row (295/838 khớp V1) + `bench_v1_meta.near_far_collapse` + disclose docs/benchmark_v1.md + checksum refresh |
| 9 | [LOW] NaN-loss isolated không reset `micro_since_step` (effective batch < 32 một step; 0 lần xảy ra thật) | **A2 (code latent)**; **V1 bắt** | ✅ Fix#9a: reset `micro_since_step` + `losses` |
| 10 | [LOW] 36 orphan raw trong `pilot_round2/e0/raw/` | **A3** (supersede giữa chừng); **V2 bắt** | ✅ Fix#9b: chuyển sang `raw_orphaned_superseded/` + MANIFEST (không xóa) |
| 11 | [LOW] Stale "+0.267 CI [+0.067,+0.500]" trong §3 A3 mâu thuẫn chính bảng §2.3; đếm crash 5→9, 3→4 | **A3**; **V2 bắt** | ✅ Fix#9c: `[CORRECTED]` header ở đầu A3_report trỏ tới summary_v2; nội dung gốc giữ nguyên |
| 12 | [LOW] 1 paired-benign id (187732) chỉ có trong test_paired mirror — quirk dữ liệu, bench ghi trung thực | **V1 bắt** | ⏳ Không cần action (không leakage); Round 3 join theo bridge |
| 13 | [INFO] frame_05 neutral còn chữ "exploitable" (A1 disclose, file của A3); E0 function-arm không yêu cầu JSON (parse_rate 0); PARTIAL=prose-compliance convention | A1/A2 disclose trước | ⏳ Cần orchestrator duyệt rebuild bench / schema-lite — để Round 3 |

**Tổng**: 13 mục — 11 đã sửa hoàn toàn trong vòng S, 2 (mục 12, 13) là
quirk/decision cần orchestrator hoặc Round 3, không có mục nào bị bỏ qua
không ghi nhận.

## 3. Sức khỏe dự án (5 dòng)

1. **Tests**: 286 passed / 0 failed (269 cũ + 17 regression mới) — mọi fix đều
   có test khóa hành vi, gồm regression chạy trên outputs thật (e3 UAC/SIUD).
2. **Dữ liệu pilot**: 1,342 records thật (0.5B: 940, 3B: 402) nguyên vẹn;
   recompute từ raw 100% truy vết được; số cũ (buggy) và số mới (correct)
   tách bạch trong 2 cây output — không xóa, không đè.
3. **Khoa học**: 3 claim lớn → 1 GIỮ (E0 FAIL, pivot clause sắp kích hoạt),
   1 BÃI (SIUD artifact), 1 GIỮ-khoan-diễn-đạt (E8 violation); mọi số paper
   quy về `summary_v2.json`; A3_report có [CORRECTED] header.
4. **An toàn P2**: policy mới REFUSED_UNSAFE + gate 30/30 unsafe (0/30
   false-block safe) + monitor unsafe-prompt override — chưa đo lại trên model
   thật (Round 3 chạy lại E8 với benchmark 60-prompt thật, lần đầu tiên).
5. **Nợ kỹ thuật còn lại** (disclosed, không chặn): 202 record E8 chỉ audit
   được ở mức runtime-fields; gate lexical miss 49/50 scoring-half paraphrase
   (cần model-based); 154 fragment ngoài pool; frame_05 + schema-lite E0.

## 4. Trạng thái train CodeBERT (đọc log — KHÔNG đụng job)

- **ĐÃ HOÀN TẤT 3/3 epochs** (process PID 49371 exit sạch ~07:38; log kết thúc
  bằng dump `history.json` sau dòng `[epoch 2] ... (no improvement)`).
- **0 skip / 0 recovery toàn run** (`nan_skips_cumulative: 0`) — MPS fp32
  batch 4×8 ổn định suốt run.
- Per-epoch (val): epoch0 MCC 0.2566 / recall 0.2901 / AUC 0.8197;
  epoch1 **MCC 0.2919 (best, `best/`)** / recall 0.5008 / F1 0.3289 / AUC
  0.8262; epoch2 MCC 0.2915 / recall 0.5228 / AUC 0.8291 (no improvement —
  hết 3 epochs nên dừng đúng kế hoạch).
- Việc tiếp theo (Round 3, A2): chạy `scripts/eval_codebert.py --arm vd_s`
  (lệnh đã dry-run kiểm chứng, VD-S dry 0.42) rồi nối B4 vào P2 prior
  (hiện `transformer_prior=None`).

## 5. File do S tạo/sửa trong vòng này

- Sửa: `src/metrics/metrics.py`, `src/models/refusal_monitor.py`,
  `src/models/llm_harness.py`, `src/defenses/refuseguard.py`,
  `src/experiments/pilot_round2.py`, `src/models/transformer_baseline.py`,
  `scripts/calibrate_refusal_monitor.py`, `configs/defenses.yaml`,
  `data/benchmarks/bench_v1/{bench_v1.jsonl,bench_v1_meta.json}` (annotate),
  `docs/benchmark_v1.md`, `reports/round2/A3_report.md` ([CORRECTED] header),
  `tests/{test_metrics_metrics,test_experiments_pilot,test_models_refusal_monitor,test_defenses,test_models_llm_harness}.py`.
- Tạo: `scripts/recompute_pilot.py`, `scripts/measure_intent_gate.py`,
  `scripts/annotate_near_far_confound.py`,
  `outputs/experiments/pilot_round2_recomputed/` (summary_v2.json,
  comparison.{json,md}, per-exp results),
  `outputs/experiments/intent_gate_v2_measurement.json`,
  `outputs/experiments/harness_recovery_smoke.json`,
  `outputs/experiments/pilot_round2/e0/raw_orphaned_superseded/` (36 file +
  MANIFEST), báo cáo này + `S_report.md`.
- Chi tiết kỹ thuật từng fix + lệnh kiểm chứng + output thật:
  **`reports/round2/S_report.md`**.
