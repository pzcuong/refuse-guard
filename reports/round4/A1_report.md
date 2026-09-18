# A1 Report — Round 4 (CHỐT DỮ LIỆU + BẢNG SỐ MASTER)

Ngày: 2026-09-19 (02:45–03:45 +07). Phạm vi: hoàn tất queue Round 3 dở, chốt
gate verdict 3 model, dựng `outputs/master/` (mọi số paper truy vết được tới
output thật), `docs/results_master.md`, kiểm chứng chéo M4. KHÔNG bịa số; mọi
giá trị mới sinh bởi lệnh ghi rõ dưới đây. Không chạy generation mới ngoài
Granite E0 re-run (0 gen mới — raw 135/135 đã cache từ Round 3).

---

## 1. Trạng thái queue cuối — TẤT CẢ ĐÃ HOÀN TẤT

Queue nền Round 3 (`run_all_round3_a1.sh`, PID 44590) tự chạy nốt đến "QUEUE
DONE" lúc **20:31:11Z (03:31 +07)**, EXIT(0) mọi stage (log:
`outputs/experiments/round3_run_a1.log`):

| Stage | Kết quả | Số liệu chính |
|---|---|---|
| E2E3 llama3b | ✅ EXIT(0) 20:06:26Z, **300/300**, partial=false | RR 0.000 mọi condition; UAC 1.000 (C2a 0.983, 1 PARTIAL); SIUD ≤ +0.017; McNemar C3 vs C0 **p=1.9e-04** (23/3 discordant, recall 0.8→0.5) |
| E2E3 granite2b | ✅ EXIT(0) 20:31:11Z, **300/300**, partial=false | RR 0.000 mọi condition; UAC 1.000; SIUD 0.000; recall C0 0.033 (model gần như luôn nói benign); McNemar C2a p=7.6e-06, C2b p=6.1e-05, C3 p=0.0215 — context ĐỔI verdict, KHÔNG đổi coverage |
| stage gate (lúc 20:31) | INCONCLUSIVE (granite E0 còn partial) | — |
| **E0 granite2b re-run (Round 4)** | ✅ **135/135**, partial=false, **0 gen mới** (toàn cache-hit) | RR 0.000 cả 3 arm; ΔRR 0.000 [0,0], McNemar p=1.0, pass=False; probe neutral over-refusal 0.333, **unsafe-compliance 0.538** (7/13) |
| **stage gate (Round 4)** | ✅ **verdict = FAIL, 3/3 model completed, 0/3 pass** | consequence = **PIVOT** per docs/e0_protocol.md §7 → `outputs/experiments/round3_e0/gate_verdict.json` |
| **stage summary (Round 4)** | ✅ `round3_e0/summary.{json,md}` + `round3_e2e3/summary.{json,md}` regenerated (generated 20:36:22Z) | — |
| stage e4 (llama + granite, Round 4, analysis-only 0 LLM call) | ✅ `e4_breakdown.json` cho cả 3 model | near vs far non-confounded; RR=0 mọi stratum |

Lệnh Round 4 đã chạy (đúng theo ROUND3_SUMMARY §4.1):
```bash
HF_HOME=$PWD/models_dir/hf PYTORCH_ENABLE_MPS_FALLBACK=1 .venv/bin/python \
  -m src.experiments.round3_scaleup --stage e0  --model ibm-granite/granite-3.3-2b-instruct
  # → --stage gate → --stage summary → --stage e4 (llama, granite)
```
Không stage nào bị dead giữa chừng; không cần resume. Generation LLM mới toàn
project: +0 (granite E0 pure cache-hit; e4/gate/summary = analysis-only).

**Quan sát mới đáng lưu ý (từ output thật, chưa có ở vòng trước):**
- Granite unsafe-compliance 0.538 (neutral arm) trên REFUSE-expected probes —
  sanity-floor FAIL ở mức model; đưa vào paper như observation (đã ghi T1
  `docs/results_master.md`).
- Granite E2E3: context thay đổi verdict có ý nghĩa thống kê (C2a/C2b p<1e-04)
  trong khi UAC/SIUD đứng yên — pattern "accuracy shift, not coverage loss".

## 2. Outputs MASTER (M2) — `outputs/master/`

Script mới: `scripts/collect_master.py` (owner A1; không đụng src/models,
src/metrics, src/data, src/conditions, src/defenses).

**Kiến trúc chống-bịa số:** không có bất kỳ con số nào được gõ tay. Mỗi row
master được sinh bằng cách navigate tới đúng vị trí (`trace` = dotted path) trong
file nguồn; sau khi ghi, script **re-read master_results.json từ đĩa + re-load
mỗi file nguồn fresh + assert từng value, từng CI, từng n**. Derived stats
(E6 stratified) được tính lại từ records và assert khớp mốc đã biết.

Kết quả chạy cuối (03:36 +07):
```
[collect] rows=341 pending=0 contradictions=2
[verify] OK — all 341 master rows match their source files (fresh re-read).
```

Files:
- `outputs/master/master_results.json` — 341 rows
  `{experiment, metric, value, ci?, n?, model, source_file, recomputed?, note?,
  trace}` + section `contradictions` (2) + `disclosures` (9 mục).
- `outputs/master/master_results.md` — bảng đầy đủ theo experiment (E0, E2E3,
  E4, E5, E6, E7, E8, CodeBERT, Calibration) + bảng contradictions.
- `outputs/master/figures_data/`:
  - `e0_rr_by_arm_model.csv` (3 model × 3 arm: RR/partial/UAC/parse + probe
    over-refusal + unsafe-compliance + CI),
  - `e3_siud_by_condition.csv` (qwen+llama+granite × 4 condition: SIUD + CI +
    RR/UAC/recall/MCC + McNemar p),
  - `e6_injection.csv` (B0/P1 flip rate + McNemar + stratified vul-only/
    benign-only),
  - `e8_compliance.csv` (2 model × B0/P1/P2: unsafe comp + safe refusal + CI +
    gate_blocked + McNemar + cờ recomputed),
  - `codebert_metrics.csv` (recall/F1/MCC/AUC/VD-S/val-MCC + paired P-C/P-V/
    P-B/P-R/rank-acc).

Phủ số theo yêu cầu đề bài: E0 (RR/arm/model + ΔRR + McNemar + probes + GATE
VERDICT) ✅; E2 framing SIUD ✅; E3 UAC/RR/recall per condition + SIUD per model
✅; E4 near-vs-far non-confounded ✅; E5 CUL/DRR/drops + carrier-stripping bias
note ✅; E6 injection-success + vul-only n.s. caveat ✅; E7 fallback/UAC-gain/
safety-scope ✅; E8 B0-vs-P2 unsafe-compliance + safe-refusal **bản RECOMPUTED
cho Llama** ✅; CodeBERT (recall/F1/MCC/AUC/VD-S/paired + val MCC) ✅;
calibration (thresholds + over-refusal per model + validity deviation) ✅.

## 3. Kiểm chứng chéo (M4) — đã xử lý

1. **341/341 số khớp nguồn** sau re-read fresh (assert value + CI + n). Bằng
   chứng: output `[verify] OK` ở trên; chạy lại bao nhiêu lần cũng idempotent.
2. **Mâu thuẫn 2 nguồn — dùng bản RECOMPUTED** (section `contradictions`):
   - `e8.llama3b.B0.unsafe_compliance_rate`: results.json gốc **0.400** vs
     recomputed **0.0333** → dùng recomputed. Lý do: V2 BUG-V3-1 (monitor thiếu
     3 pattern + không chuẩn hóa apostrophe; 11/12 PARTIAL giả được re-classify
     REFUSAL từ raw; originals giữ nguyên để audit).
   - `e8.llama3b.B0_vs_P2_unsafe.mcnemar`: gốc b10=12 p=0.000488 vs recomputed
     b10=1 p=1.0 → dùng recomputed; claim "P2 giảm unsafe compliance p=0.00049"
     đã THU HỒI từ Round 3 (S_report Fix 2).
   - Kiểm tra chéo thêm trong verify: (a) assert recomputed llama B0 đúng bằng
     1/30; (b) paired-block CodeBERT khớp IDENTICAL giữa
     `codebert_eval_vd_s_metrics.json` và `codebert_eval_paired_only_metrics.json`
     (6/6 key); (c) models.yaml corroborate over-refusal 0.5867 (Qwen) và
     0.0667 (Llama) từ calibration full_report.
3. **Derived E6 khớp độc lập với V2**: tổng discordant 8 (b01=0, b10=8,
   p=0.0078125 — khớp `flip_metrics` trong results.json từng chữ số); phân tầng
   theo y_true: **vul-only 2 discordant p=0.5 n.s. (n=14), benign-only 6
   discordant p=0.03125 (n=17)** — đúng 6+2 mà V2 đếm thủ công, giờ đã là file
   chính thức (Round-3 recommendation #4 "xuất stratified stats thành file" ✅).
4. Không có mâu thuẫn nào khác giữa results.json gốc và recomputed (E8-Qwen:
   0/150 record đổi trạng thái, số gốc = số recomputed).

## 4. Disclosure bắt buộc cho paper (đã nhúng trong master_results.json +
   docs/results_master.md)

1. Quy mô pilot mọi nơi (E0: 20 fn × 3 arm + 25 probe × 3 arm-system/model;
   E2/E3: 60 fn × 5 condition/model; E5/E6: n=40/31 per cell; E8: 30+30/arm/
   model; E7: n=133, model 0.5B).
2. PrimeVul **mirror v0.1**; CodeBERT test = 549 vul (ALL) + 20,000 benign
   subsample seed 1234; train benign 25,000.
3. **Monitor deviation Qwen**: over-refusal 0.5867 ≫ 0.10 (§7) — detector
   error; ΔRR=0 robust vì đối xứng 2 arm.
4. **E0 = FAIL, effect size đúng bằng 0; PASS-branch unattainable at n=20**
   (pre-registered config không sửa); granite threshold fit IN-SAMPLE.
5. **E8-Llama dùng RECOMPUTED** (0.400/p=0.00049 thu hồi); **H6 by-construction**
   (gate 30/30, 0 LLM call → pipeline-level safety); P2-cũ round 2 = 1.000
   (refusal-suppression, đã fix).
6. **E6 vul-only p=0.5 n.s.** + benign-keep-bias (headline p=0.0078 do stratum
   benign chi phối).
7. E7 pilot 0.5B n=133; per-case fallback correctness KHÔNG persist → không
   claim "2/2 đúng" (chỉ n_fallback_used=2, coverage +0.015, MCC +0.0153).
8. Granite: E0 in-sample fit + unsafe-compliance 0.538 (observation); E2E3
   hoàn tất đầy đủ (không cắt).
9. Hệ quả **PIVOT** chính thức: RQ2 robustness là primary, refusal là secondary.

## 5. Điểm treo / không kịp (không có số pending)

- Không còn số nào pending: 341/341 rows đã có nguồn và verify pass; granite
  E0/E2E3/E4 + gate + summary đều xong trước khi chốt report.
- `master_results.json` là nguồn duy nhất cho paper; nếu queue hay recompute
  thay đổi file nguồn, chỉ cần chạy lại `scripts/collect_master.py` — verify sẽ
  fail rõ ràng nếu có số nào lệch.
- A2 từng claim "fallback 2/2 đúng" (E7): KHÔNG tìm được per-case data trong
  outputs → master không chứa claim này (đã note trong `e7.*.n_fallback_used`).

## 6. Bảng chính tắt cho orchestrator (trích từ master, đầy đủ trong
   docs/results_master.md)

| # | Kết quả chốt | Số | Nguồn (metric key) |
|---|---|---|---|
| 1 | E0 gate | **FAIL 0/3 pass** (ΔRR=0.000, p=1.0 ×3 model) → PIVOT | `e0.gate.*` ← gate_verdict.json |
| 2 | E2/E3 | RR 0.000, UAC ≥0.983, SIUD ≤ +0.017 ở CẢ 3 model; C3 tụt recall (qwen 0.8→0.333 p=1.2e-05; llama 0.8→0.5 p=1.9e-04; granite context-shift p<1e-04) | `e23.*` ← round3_e2e3/*/results.json |
| 3 | E4 | near vs far (non-confounded): RR=0; recall near/far qwen 0.733/0.704, llama 0.862/0.741 | `e4.*` ← e4_breakdown.json |
| 4 | E5 | CUL 0.000, drops 0.000, DRR None (n=0); C3\|B2/B3 recall 1.000 = bias | `e5.*` ← round3_e5/results.json |
| 5 | E6 | flip 0.7419→0.4839, p=0.0078; **vul-only p=0.5 n.s.**; usable delta 0.000 | `e6.*` ← round3_e6/results.json (+derived) |
| 6 | E7 | UAC 0.985→1.000 (+0.015), MCC 0.0789→0.0942, fallback 2, scope-block 500/500 | `e7.*` ← e7_fusion_results.json |
| 7 | E8 | Qwen 0.000/0.000, Llama **0.033**/0.000 (recomputed), H6 met by-construction; safe-side 0.233→0.000 p=0.0156 | `e8.*` ← recomputed/recompute_e8_monitor.json |
| 8 | CodeBERT | recall 0.541, F1 0.215, MCC 0.232, AUC 0.847, VD-S 0.962, val MCC 0.292, P-C 0.0092, P-R 0.0299 | `codebert.*` ← codebert_eval_vd_s_metrics.json |
| 9 | Calibration | thresholds 0.0/0.2 ×2; over-refusal 0.5867 (Qwen, deviation) / 0.0667 (Llama) | `calib.*` ← calibration/*/full_report.json |

---
*Kiểm định: `scripts/collect_master.py` exit 0 với `[verify] OK — all 341 master
rows match their source files`. Không git commit. Không số mới ngoài output thật.*
