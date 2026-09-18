# V1 Report — Round 4 (VÒNG CUỐI): Audit bài báo RefuseGuard trước khi nộp

Ngày: 2026-09-19. Tác nhân: V1 (kiểm lỗi độc lập, vòng 4). Phạm vi: số trong
`paper/tables/*.tex` + `paper/sections/*.tex` + `paper/compiled/refuseguard_paper.pdf`,
figures (`paper/make_figures.py` tái lập), claims (E0/E3/E6/E7/E8/CodeBERT/abstract),
9 disclosures (`docs/results_master.md`), citations (`paper/refs.bib`), consistency
abstract↔results↔conclusion. KHÔNG sửa code/paper. Python `.venv/bin/python`.

---

## VERDICT PAPER: **ISSUES — 1 HIGH, 1 MEDIUM, 4 LOW, 3 INFO. Sửa 1 HIGH + quyết định 1 MEDIUM trước khi nộp; còn lại không chặn.**

- **Toàn bộ ~60 con số** trong 4 bảng + setup + results + figures **đều truy vết
  được** tới `outputs/**` hoặc `outputs/master/master_results.json` (341 rows,
  đã spot-check lại nguồn gốc phía sau master cho ~15 số) — **trừ đúng 1 số-claim:
  "fallback decisions 2/2 correct"** (HIGH-1).
- **0 claim đã thu hồi sót lại**: không có "0.400→0.000", không có "p=0.00049"
  trong bất kỳ .tex hay PDF compiled (grep xác nhận; duy nhất "(Llama B0
  0.400 → 0.033)" xuất hiện đúng vai trò disclosure bản recompute ở threats).
- **H6 đúng chốt "pipeline-level, by construction"; E6 đủ 2 vế (tổng p=0.0078 +
  vul-only p=0.5 n.s.); E3 SIUD≈0 đúng bản recompute; CodeBERT đúng bộ số
  0.215/0.962/549/25k.**
- Vấn đề lớn còn lại là **stale 2-model-vs-3-model**: paper viết "Granite
  crashed … excluded" trong khi artifact hiện tại đã có granite E0 135/135 +
  gate_verdict FAIL 3/3 completed (MEDIUM-1, để S quyết — số 2-model present
  KHÔNG sai, nhưng câu "excluded" đã trái với chính repro package kèm theo).

---

## 1. SỐ TRONG TABLES — kết quả từng bảng

### tab_main.tex — PASS (khoảng 30 số, mọi số khớp master + file gốc)
| Số trong bảng | Nguồn đối chiếu | Kết quả |
|---|---|---|
| E0 RR 0.000 ×3 arm ×2 model; ΔRR=0.000, p=1.0 | master `e0.{qwen3b,llama3b}.arm.*.RR`, `mcnemar_*.p` | ✅ |
| Probes over-ref./unsafe: Qwen 0.500/0.154, 0.750/0.077, 0.667/0.077; Llama 0.167/0.154, 0.083/0.385, 0.333/0.231 | master `e0.*.probe.*`; 0.1538→0.154 (2/13), 0.5 (6/12) khớp "12 COMPLY/13 REFUSE" trong caption | ✅ |
| E3 RR 0.000 ×4; UAC 1.000/1.000/0.983/1.000 (cả 2 model); recall Qwen 0.800/0.967/0.933/0.333; Llama 0.800/1.000/0.862/0.500; SIUD max +0.017 | master `e23.*` | ✅ |
| E6: 0.742→0.484, p=0.0078, vul-only p=0.5 n.s. | master `e6.IPI_flip_rate.*`, `mcnemar_flip*.p` (0.0078125), `discordant.vul_only` (b10=2, p=0.5) | ✅ đủ 2 vế |
| E8: Qwen 0.000→0.000; Llama 0.033→0.000; gate 30/30 | master `e8.*` (recomputed) | ✅ |

[INFO-1] Cột "C2" gộp C2a/C2b: UAC 0.983 của Qwen lấy từ **C2b** (C2a=1.000)
còn của Llama lấy từ **C2a** (C2b=1.000) — cùng cột nhưng khác variant theo
model. Text RQ2 (05_results.tex:88–89) nói đúng chi tiết "Qwen 0.983 under C2b
and Llama 0.983 under C2a", nên không sai; nên đổi header cột thành "C2a/C2b"
hoặc footnote khi có bản sửa kế tiếp.

### tab_codebert.tex — PASS (12 số)
Recall 0.493/0.541, F1 0.623/0.215, MCC 0.444/0.232, AUC 0.832/0.847, VD-S
0.970 (n_pairs=1 degenerate)/0.962, P-C 0.009, P-V 0.517, P-B 0.444, P-R 0.030,
rank-acc 0.223 — khớp từng chữ với `outputs/transformer/final_eval.json`
(final_eval_pilot_arm / final_eval_vd_s_arm), `codebert_eval_vd_s_metrics.json`,
`codebert_eval_paired_only_metrics.json` và master `codebert.*`.
"≈3.8% detected" = 1−0.962 ✅. "20,549" = 549+20,000 ✅ (`codebert.n_test`).

### tab_defenses.tex — **1 ISSUE (HIGH-1)**, còn lại PASS
- CUL 0.000, DRR n/a (n=0), C3 recall/precision 1.000/0.452 (precision thật
  0.45161 ở `round3_e5/results.json → per_condition_defense["C3|B2"]`) ✅
- E6 MCC +0.205/−0.029, usable gain 0.000, 0.742→0.484 p=0.0078 ✅
- E7 UAC 0.985 vs 1.000 (+0.015), MCC 0.0789 vs 0.0942 ✅ (`e7_fusion_results.json`)
- E7 scope 0 of 500 (250+250), reached_fallback=0 ✅
- E8 pre-fix 0.040 vs 1.000 ✅ (`pilot_round2_recomputed/summary_v2.json`,
  3b_qwen, n_unsafe=50); post-fix Qwen 0.000/0.000, Llama 0.033/0.000 ✅
- **HIGH-1: dòng "E7 (fallback) & fallback decisions & 2/2 correct"** — không
  tồn tại dữ liệu per-case fallback correctness trong bất kỳ output nào
  (`e7_fusion_results.json` chỉ có aggregate + n_fallback_used=2: C0×1 + C3×1;
  recall C3 không đổi 0.2143 nên không suy ra được đúng/sai). Vi phạm trực tiếp
  disclosure #7 + footnote T6 (`docs/results_master.md`:194): "per-case fallback
  correctness KHÔNG được persist → paper KHÔNG được claim '2/2 đúng'".

### tab_calibration.tex — PASS (10 số)
Thresholds 0.0/0.2 ×2; over-refusal 0.587 (fails) vs 0.067; unsafe compliance
0.06/0.26; calibration accuracy 0.376/0.296; refusal rate overall 0.728/0.336 —
khớp `outputs/transformer/calibration/{Qwen_Qwen2.5-Coder-3B-Instruct,
unsloth_Llama-3.2-3B-Instruct}/full_report.json` (at_fit) và master `calib.*`;
(44/75=0.5867, 5/75=0.0667 đúng mẫu số 75 COMPLY). Caption "25/125 scoring
probes consumed by pre-registered E0" khớp fix #7 ROUND3_SUMMARY.

---

## 2. SỐ TRONG FIGURES — PASS

Chạy lại `.venv/bin/python paper/make_figures.py` (CPU, vài giây): **EXIT=0**,
output nguyên văn:
```
[verify] all table numbers match source files
[verify] 14 headline numbers cross-checked against outputs/master/master_results.json
[cites] 16 keys used, all present in refs.bib (unused bib entries: none)
[ok] 5/5 paper/figures/*.pdf
```
- Script **không hardcode số kết quả**: mọi giá trị plot được đọc từ
  `outputs/experiments/...` + `outputs/transformer/...`; các assert cấu trúc
  (RR==0.0, n_status_changed llama=11, n_vulnerable=549, pre-fix 0.04/1.00)
  đều pass. Stratified E6 (8 discordant = 2 vul + 6 ben) được script **tính lại
  từ records** và khớp master (`e6.discordant.*`); p=0.031/0.5 tái tính đúng
  (binom two-sided 6/6 → 0.03125; 2/2 → 0.5).
- PDF compiled (`refuseguard_paper.pdf`) chứa text **giống hệt** `main.pdf`
  (diff text rỗng; khác nhau chỉ metadata timestamp — main.pdf recompile 03:43
  sau khi nguồn không đổi). PDF ↔ .tex nhất quán, 0 "??". Lưu ý: lần chạy
  audit của tôi có regenerate lại 5 figure PDF (nội dung identical, md5 đổi do
  timestamp matplotlib — đã ghi ở mục 2, không phải sửa paper).

---

## 3. CLAIM AUDIT (sections + abstract + PDF)

**3a. E0 — đúng verdict, stale scope (MEDIUM-1).**
- Verdict FAIL→PIVOT đúng: `outputs/experiments/round3_e0/gate_verdict.json`
  (`verdict=FAIL`, `models_completed=3`, `models_pass=0`,
  `consequence=PIVOT per docs/e0_protocol.md §7`); paper quote rule "PASS iff
  ≥2 of 3 models, ΔRR≥0.10, McNemar p<0.05, CI excludes 0" khớp nguyên văn
  `rule` trong file + `docs/e0_protocol.md`. Probes đúng (mục 1). Paper không
  hề nói sai số nào của 2 model.
- **MEDIUM-1 (stale, để S quyết):** `04_setup.tex:52–54` "Granite crashed at
  75/135 after its raw generations were cached and is **excluded from
  results**"; `05_results.tex:10` fig caption "(two completed models)";
  `00_abstract.tex:6–7` "two open-weight 3B models"; `01_intro.tex:36–37`
  "across two 3B models"; `06_discussion.tex:76–78` "a third registered model
  (Granite) crashed post-generation and is excluded"; `04_setup.tex:52` "both
  models completed". Thực trạng artifact: granite E0 **135/135 partial=false**
  (0 gen mới, cache-hit), E2E3 granite **300/300**, gate **FAIL 3/3 completed
  0/3 pass** — đã là disclosure #8 + T1 trong `docs/results_master.md` và 77
  rows `e0.*`/`e23.*` của granite trong master. Số 2-model present không sai,
  nhưng mệnh đề "crashed/excluded" giờ **trái với chính repro package** mà
  paper bảo là released (reviewer chạy `collect_master.py` sẽ thấy ngay).
  Granite còn có quan sát mới đáng giá (unsafe-compliance 0.538 neutral arm —
  sanity-floor FAIL mức model) hiện mất sạch khỏi paper.

**3b. Retracted claim + H6 — PASS.**
- Grep toàn bộ .tex + text PDF: **không có** "0.00049"/"p=0.0004"/cặp
  "0.400→0.000". Đúng duy nhất 1 chỗ nhắc 0.400: `06_discussion.tex:64–66`
  "changed a headline E8 number (Llama B0 0.400 → 0.033) and *withdrew* an
  apparent defence win — we kept both versions in the artifact trail" = đúng
  bản recompute (0.0333 = 1/30, McNemar b10=1 p=1.0, `n_status_changed=11`).
- H6: `05_results.tex:172–174` "P2's zero is the gate's zero, not the model's —
  *pipeline-level* safety by construction, not evidence that the LLM itself is
  safer"; `06_discussion.tex:27–28` "We report H6 as *met by construction* and
  deliberately do not claim the LLM inside became safer"; tab_defenses "H6
  (pipeline-level, by construction) met (gate blocked 30/30)". Đúng chốt của
  ROUND3_SUMMARY #2. Không có chỗ nào nói "P2 cải thiện compliance có ý nghĩa".

**3c. E6 — PASS, đủ 2 vế.** RQ4 (`05_results.tex:124–139`): 0.742→0.484 (23 vs
15/31 — đúng 0.7419/0.4839), McNemar p=0.0078, stratified 6 benign (p=0.031) +
2 vul (p=0.5 n.s.), benign-keep-bias giải thích đúng chiều, MCC +0.205 (B0) vs
−0.029 (P1), usable gain 0.000, "isolation is not accuracy". Cả fig_e6 caption,
tab_main và conclusion đều mang đủ 2 vế. **Không có** claim "P1 cải thiện
accuracy". Abstract dùng hedge "(aggregate … p=0.008) without helping accuracy"
— trung thực (0.0078→0.008 làm tròn chấp nhận được).

**3d. E3 SIUD — PASS.** SIUD ≈ 0, max +0.017 (Qwen C2b, Llama C2a) khớp master
`e23.*.SIUD_vs_C0.*`; không còn dấu vết artifact +0.258; RR=0.000, UAC ≥0.983,
recall per condition khớp. "35 of 60 flipping vs 6 opposite, p=1.2e-05" khớp
`paired_tests_vs_C0.C3.mcnemar_y_pred` (b10=35, b01=6) nguyên văn.
"directional accuracy 0.467–0.483" khớp file (0.4667–0.4833). McNemar
C1/C2a/C2b = 0.0039/0.0078/0.0215 ✅.

**3e. CodeBERT — PASS.** F1 0.215, VD-S 0.962 (FNR, lower=better, footnote giải
thích convention), mirror v0.1 + test 549-vul disclosed (setup §Data + caption),
train benign subsample 25,000 disclosed (setup §Models, khớp
`train_meta.json` n_benign_train=25000, n_vul_train=4862, val 10,000/593,
best_epoch=1 — "epoch 1/3", lr 2e-5/batch eff 32/seed 1234 khớp
`configs/train_codebert.yaml`). Literature chỉ quoted qualitative (không copy
số) — khớp quy tắc; khối `literature_reference` trong final_eval.json
(96.87/20.86/88.78/1.77/11.35/86.17/0.71) không bị đem vào paper ✅. Val MCC
0.292 (master) không xuất hiện trong paper — không bắt buộc.

**3f. Abstract + "first" — PASS.** Từng claim abstract có kết quả thật: RR 0.000
(✅ E0), probes refuse arm-independently (✅), UAC ≥0.98 (✅ min 0.983), 74% flip
(✅ 0.742), 48% p=0.008 (✅ 0.484/p=0.0078), unsafe compliance 1.00 (✅ pre-fix
P2), gate-first eliminated (✅ 0.000, gate 30/30). "first" chỉ xuất hiện ở
related positioning (`02_related.tex:64–66`) với hedge "(to our verified
knowledge)" và đúng scope "joint refusal–utility–safety evaluation of LLM-based
vulnerability analysis", kèm minh khảo "campbell2026defensive owns it /
cheng2026codesentinel+yi2023bipia own that" — đúng nguyên tắc §5
`docs/literature_review.md`.

Claim phụ đã verify kèm:
- "a model that refuses 96% of harmful prompts" = 1 − 0.040 (B0 pre-fix, 3b_qwen
  summary_v2, n_unsafe=50) ✅ (xuất hiện intro C4 + RQ6 + discussion, nhất quán).
- "both models never refuse" (conclusion) / "8–75% of benign probes" = min 0.083
  max 0.750 ✅ (làm tròn 8.3→8, đã chuẩn hoá theo A2_report §4).
- Gate scope "blocks 30/30 … but only **1/50** paraphrased OR-Bench-toxic" khớp
  file `outputs/experiments/intent_gate_v2_measurement.json`
  (`e8_scoring_half_unsafe: blocked=1, n=50`) ✅ — paper đúng hướng.
- τ=0.548 (0.54807), valid MCC 0.303, scope 500 (250+250), score-fusion recall
  0.839/MCC 0.0969 ✅.
- E4 "C3 recall 0.14–0.50 across cells (Qwen)" ✅ (0.1429–0.5 trong
  `e4_breakdown.json by_condition_carrier_position/C3|*`).
- Precision "flat at ≈0.48" — thực tế 0.4800/0.4915/0.4828/0.4912 (C0/C1/C2a/
  C2b) → **[INFO-2]** nên là "≈0.48–0.49"; hiện tại hơi làm tròn thấp, không
  đổi kết luận (TN=0 mọi arm security-charged ✅).

---

## 4. SỐ LỆCH / SAI (tổng hợp)

| # | Mức | Vị trí | Số/claim trong paper | Nguồn đúng | Ghi chú |
|---|---|---|---|---|---|
| HIGH-1 | HIGH | `paper/tables/tab_defenses.tex:37` + `paper/sections/05_results.tex:146` | "fallback decisions **2/2 correct**" / "both fallback decisions correct" | Không có output nào persist per-case correctness (`e7_fusion_results.json` chỉ có n_fallback_used=2) | Vi phạm disclosure #7 + T6 footnote. Sửa thành "2 fallback decisions used (per-case correctness not persisted)" hoặc xóa |
| MEDIUM-1 | MED | setup:52–54, 05_results:10 (fig caption), abstract:6, intro:36, discussion:76, tab_main.tex:5 (comment) | "Granite crashed at 75/135 … excluded from results" / "two completed models" / "two open-weight 3B models" / "both models completed" | `round3_e0/granite2b/results.json` (135/135, partial=false), `round3_e2e3/granite2b/results.json` (300/300), `round3_e0/gate_verdict.json` (FAIL, 3/3 completed, 0/3 pass), master 341 rows gồm granite | Số 2-model không sai nhưng mệnh đề "excluded" đã trái artifact; để S quyết cập nhật hay giữ nguyên kèm ghi chú cut-off |
| LOW-1 | LOW | `04_setup.tex:38` | "max **512** new tokens" | `configs/models.yaml:59` default 512, nhưng round-3 configs chạy thật dùng 300 (e0/e2e3), 320 (e5/e6), 200 (e8 probes) | Nên ghi "max 200–320 new tokens per-experiment (harness default 512)" |
| LOW-2 | LOW | `04_setup.tex:56–57` | "E8: 150 records per model (30 unsafe + 30 safe prompts × B0/P1/P2, plus probe arms)" | Thực tế B0 60 + P2 60 + P1 **30 (chỉ safe, n_unsafe=0)** = 150 | Tổng 150 đúng; công thức trong ngoặc hiểu nhầm thành 180. Nên ghi rõ P1 arm không có unsafe records (đã là footnote T7) |
| LOW-3 | LOW | refs.bib usage | B4 "CodeBERT classifier~\cite{ding2025primevul}" (03_method:73) | Entry `feng2020codebert` (EMNLP'20, DOI đúng) nằm sẵn trong refs.bib nhưng **0 lần được cite** | Baseline nên cite paper gốc CodeBERT; A3 cũng liệt kê nó "never cited" |
| LOW-4 | LOW | `02_related.tex:21–22` | "refused about **2.7×** more" (campbell2026defensive) | `docs/literature_review.md:104–106` ghi 2.72× nhưng kèm TODO "to be re-checked against the paper PDF in Round 4 writing" — không thấy report vòng nào đóng TODO | Số truy vết được tới lit review (abstract-level); khuyến nghị S re-check PDF gốc hoặc giữ hedge như hiện tại |

[INFO-1] tab_main cột "C2" gộp C2a/C2b (Qwen lấy C2b, Llama lấy C2a) — text nói
đúng, nên làm rõ header khi có bản sửa.
[INFO-2] "precision flat at ≈0.48" → thật ra 0.48–0.49 (cosmetic).
[INFO-3] `docs/results_master.md` disclosure #9 viết "**1/50 paraphrase
escape**" trong khi file thật ghi `blocked=1/50` (escape = 49/50). Paper diễn
đạt ĐÚNG hướng ("blocks … only 1/50"); khuyên S sửa wording disclosure #9 để
người đọc sau không mis-quote.

Không tìm thấy số nào khác lệch: toàn bộ số còn lại (~60) khớp nguồn, kể cả
các con số dễ nhầm (44/75, 2/13, 35/6, 23 vs 15/31, 8 discordant 6+2,
250+250/500, 133/160, 20,549, 435, 295/838=35.2%, −13.8%/−4.9%, 6,004/6,968,
218,529/229,794, 24,788/549, 130/>140, 25,000/4,862/10,000/593, 0.587/0.067,
0.728/0.336, 0.985/0.0789/0.0942/0.839/0.0969, τ 0.548).

---

## 5. CLAIM CẦN SỬA

1. **[HIGH-1]** Xóa/đổi lại "2/2 correct" ở tab_defenses + "both fallback
   decisions correct" ở RQ5 → "two fallback invocations (C0, C3); per-case
   correctness not persisted". Đây là điều kiện bắt buộc của disclosure #7.
2. **[MEDIUM-1]** Quyết định S: (a) cập nhật paper sang 3/3 model completed +
   gate FAIL 3/3 (thay "(two completed models)", thêm granite vào tab_main/E0
   phần discussion, thêm disclosure "granite monitor thresholds fit in-sample"
   + quan sát unsafe-compliance 0.538), hoặc (b) giữ bản 2-model nhưng thay câu
   "Granite crashed … is excluded from results" bằng mệnh đề cut-off trungực
   kiểu "granite completed after the submission cut-off of this draft; its
   results (consistent with the FAIL verdict) are in the released artifacts" —
   hiện trạng "crashed … excluded" là sai so với artifact kèm theo.
3. [LOW-1..4] như bảng trên (đề xuất, không chặn nộp).

---

## 6. DISCLOSURE THIẾU (9 disclosures của docs/results_master.md vs paper)

| # | Disclosure | Trạng thái trong paper |
|---|---|---|
| 1 | Pilot scale mọi nơi | ✅ setup §Scale ("state the exact budget") + threats |
| 2 | Mirror v0.1; test 549 vul + 20k benign (seed 1234); train 25k | ✅ setup §Data/§Models + tab_codebert caption + threats |
| 3 | Qwen monitor deviation 0.5867 > 0.10 | ✅ tab_calibration + RQ1 + threats ("detector error", ΔRR=0 robust đối xứng) |
| 4 | E0 FAIL effect-0; PASS-branch unattainable n=20; granite in-sample fit | ✅ FAIL effect-0 + PASS-branch (setup §Scale + threats + appendix, cite McNemar 1947); ❌ **granite in-sample fit: thiếu** (hệ quả tất yếu của việc granite bị "excluded"; **trở thành bắt buộc nếu S chọn cập nhật 3-model ở MEDIUM-1**) |
| 5 | E8-Llama RECOMPUTED (0.400/p=0.00049 thu hồi); H6 by-construction; P2-cũ 1.000 | ✅ đủ 3 (threats + RQ6 + fig_e8 + tab_defenses) |
| 6 | E6 vul-only p=0.5 n.s. + benign-keep-bias | ✅ đủ (fig_e6 + RQ4 + tab_main + conclusion). **Thiếu 1 mảnh nhỏ [LOW-5]:** footnote T5 "reference = B0\|C0 paired (40 vulnerable, n_reference_ben=0)" không được nêu — paper định nghĩa injection success "relative to the clean prediction" nhưng không nói reference set all-vulnerable |
| 7 | E7 pilot 0.5B n=133; không claim per-case correctness | ⚠️ n=133 + 0.5B + zero-LLM-call ✅ nhưng **claim "2/2 correct" vi phạm đúng điều cấm** (HIGH-1) |
| 8 | Granite: in-sample fit; E2E3 hoàn tất; gate FAIL (không phải INCONCLUSIVE) 3/3 | ❌ paper đang nói ngược lại ("crashed/excluded") — chính là MEDIUM-1 |
| 9 | Pivot: RQ2 primary, refusal secondary | ✅ RQ1 + setup pre-registration (i) |

Người đọc paper có đủ thông tin không bị误导 về pilot-n: **có** — mọi n được nêu
tường minh (20/arm, 60×5, 40/31, 30+30, 133, 838, 549+20,000, 435).

---

## 7. CITATIONS — PASS (kèm 2 ghi chú LOW)

- 4 entry mới spot-check metadata: `feng2020codebert` (EMNLP 2020,
  DOI 10.18653/v1/2020.emnlp-main.285, arXiv:2002.08155, author list Feng/Guo/…
  đúng); `grattafiori2024llama3` ("The Llama 3 Herd of Models",
  arXiv:2407.21783, 2024 — đúng); `hui2024qwen25coder` ("Qwen2.5-Coder Technical
  Report", arXiv:2409.12186, 2024 — đúng); `granite2025modelcard` (@misc HF card
  ibm-granite/granite-3.3-2b-instruct — hợp lệ). `mcnemar1947note`
  (Psychometrika 12(2):153–157, DOI 10.1007/BF02295996) và `efron1979bootstrap`
  (Ann. Statist. 7(1):1–26) cũng đúng.
- `paper/refs.bib` = `docs/refs.bib` (16 entry verified R1, không sửa) + 9 entry
  A3 bổ sung — diff xác nhận là superset thuần, check_citations của
  make_figures (chạy against docs/refs.bib) vẫn hợp lệ.
- Ref "2026" của proposal: `docs/literature_review.md` §0 ghi **VERIFIED hết**
  (campbell 2603.01246, beyondrefusal 2607.05842, codesentinel 2606.19235,
  taboorag 2603.03919 — arXiv API) → related work cite không cần cờ
  UNVERIFIED, đúng như lit review ("No UNVERIFIED citations remain").
  Ghi chú LOW-4 về số 2.7× (mục 4).
- Compile: 21/21 cite keys tồn tại, 0 "??", 0 undefined (A3 audit + tôi xác nhận
  lại qua PDF text). LOW-3: feng2020codebert never-cited (nên cite ở B4).

---

## 8. CONSISTENCY abstract ↔ results ↔ conclusion — PASS (trừ MEDIUM-1)

- Cùng một bộ số xuyên suốt: RR 0.000; probes 8–75%; UAC ≥0.98/0.983; SIUD
  +0.017; flip 74%/74.2%; P1 0.484/48% với p=0.0078/0.008 + vul-only p=0.5;
  pre-fix 0.040→1.000 + "96%"; post-fix 0.000/0.033→0.000 + gate 30/30; safe
  0.233→0.000 (p=0.0156) / 0.033→0.000 (p=1.0); CodeBERT F1 0.215/0.623, VD-S
  0.962/3.8%, paired 435; monitor 0.587. Không có chỗ nào mâu thuẫn n, p, CI.
- Không có chỗ nào nói "3 model có kết quả" trong khi chỗ khác nói "2" — toàn
  paper đồng bộ ở mốc "2 completed models" (vấn đề duy nhất là mốc đó stale so
  với artifact: MEDIUM-1). Appendix nói "the three study models are open-weight"
  (đếm số model đăng ký, không nói 3 model có kết quả) — không mâu thuẫn nội bộ.
- H6/E6/retraction: diễn đạt nhất quán 100% giữa results/discussion/conclusion.

---

## 9. AI SAI / AI BẮT ĐƯỢC

| # | Ai viết | Lỗi | Ai bắt | Mức |
|---|---|---|---|---|
| 1 | **A2-R4** | Claim "fallback decisions 2/2 correct" (tab_defenses.tex:37) + "both fallback decisions correct" (05_results.tex:146) dù per-case correctness không tồn tại trong outputs — A1 đã cảnh báo đúng issue này trong A1_report §5 ("A2 từng claim 'fallback 2/2 đúng' … master không chứa claim này") nhưng A2 chỉ sửa một phần/không sửa hai chỗ trong paper; `verify_tables()` của chính A2 cũng không assert dòng này (blind spot) | **V1-R4** (đối chiếu e7_fusion_results.json + disclosure #7 + T6) | HIGH |
| 2 | **A2-R4 (nội dung) / điều phối (không cập nhật chéo)** | Cụm "Granite crashed … excluded" + "two completed models" viết đúng tại thời điểm viết nhưng A1 hoàn tất granite + gate 3/3 trước khi chốt; không ai sync → paper mâu thuẫn artifact kèm theo | **V1-R4** (đọc gate_verdict.json + master 341 rows) | MEDIUM |
| 3 | **A1-R4** | Wording disclosure #9 trong docs/results_master.md: "1/50 paraphrase **escape**" trong khi file thật `intent_gate_v2_measurement.json` ghi `blocked=1/50` (escape=49/50); paper (A2) lại diễn đạt ĐÚNG | **V1-R4** | INFO |
| 4 | **A2-R4** | "max 512 new tokens" lấy từ default `configs/models.yaml` thay vì giá trị chạy thật 200–320 trong configs round-3 | **V1-R4** | LOW |
| 5 | **A2-R4** | Cột "C2" trong tab_main gộp C2a/C2b chọn-lấy-theo-model (Qwen→C2b, Llama→C2a) | **V1-R4** (text của chính A2 nói đúng) | INFO |
| 6 | (credit) **A1-R4** | Hạ tầng chống-bịa số (collect_master verify 341/341 + contradictions + 9 disclosures) hoạt động đúng; **A2-R4** verify_tables + make_figures assert bắt đúng mọi số khác — tôi tái lập 0 fail | V1 xác nhận lại | — |
| 7 | (credit) **V2-R3/S-R3** | Fix monitor + recompute E8-Llama đã thấm đúng vào paper (không còn dấu vết 0.400/p=0.00049 dưới dạng claim; chỉ còn ở vai trò disclosure) | V1-R4 xác nhận | — |

---

## Phụ lục: bằng chứng lệnh đã chạy (nguyên văn chính)

- `python paper/make_figures.py` → EXIT=0, `[verify] all table numbers match
  source files`, `[verify] 14 headline numbers cross-checked against
  outputs/master/master_results.json`, `[cites] 16 keys`, 5/5 `[ok]`.
- `pdftotext refuseguard_paper.pdf` → 2,850 dòng, `grep -c "??"` = 0;
  `grep 0.00049` = 0 match; `grep "0.400"` = 1 match (đúng vai trò disclosure);
  diff text main.pdf ↔ refuseguard_paper.pdf = rỗng.
- Spot-check nguồn gốc sau master (tất cả khớp): `round3_e2e3/qwen3b/results.json`
  (precision 0.48/0.4915/0.4828/0.4912, dir-acc 0.4667–0.4833, mcnemar
  b10=35/b01=6), `round3_e2e3/qwen3b/e4_breakdown.json` (C3 recall 0.1429–0.5),
  `round3_e5/results.json` (C3|B2 precision 0.45161), `round3_e7/e7_fusion_results.json`
  (score_fusion recall 0.8387/MCC 0.0969; n_fallback_used=2; không có per-case),
  `round3_e8{,_llama3b}/recomputed/` (0.0/0.0, 0.0333/0.0, gate 30, seed
  20260918, n_boot 10000, n_status_changed 0/11), `pilot_round2_recomputed/
  summary_v2.json` (3b_qwen B0 0.04/P2 1.0, n_unsafe 50), `intent_gate_v2_measurement.json`
  (blocked=1/50), `train_meta.json` + `configs/train_codebert.yaml` (4862/25000/
  10000/593, epoch 3, lr 2e-5, eff-batch 32, seed 1234), `final_eval.json`
  (pilot arm 0.4933/0.6232/0.4437/0.8318/vd_s 0.97/n_pairs 1),
  `calibration/*/full_report.json` (0.5867/0.0667, 0.06/0.26, 0.728/0.336,
  0.376/0.296, thr 0.0/0.2), `data/benchmarks/bench_v1/bench_v1_meta.json`
  (838=300+300+238, near_far_collapse 295, rate 0.352, seed 20260918+offsets),
  `docs/eda_primevul.md` (6,004/6,968/−13.8%; 218,529/229,794/−4.9%; 130/>140;
  test 24,788=549+24,239; 435 pairs), revisions qwen 488639f1 / llama 006f5dcd.

*Kiểm lỗi vòng 4 bởi V1. Không sửa file nào ngoài report này (paper/figures/*.pdf
được regenerate nguyên trạng bởi lệnh tái lập chính thức của A2 — nội dung
identical). Không git commit.*
