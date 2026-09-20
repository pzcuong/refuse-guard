# V1 Report — Round 6 (KIỂM LỖI ADVERSARIAL: A1 verdict-bias định lượng + A3 pre-reg/paper drafts)

Ngày: 2026-09-21. Phạm vi: audit A1 (`scripts/analyze_verdict_bias.py`,
`outputs/master/round6_bias.json`, `docs/verdict_bias.md`) và A3
(`docs/round6_ablation_prereg.md`, paper drafts, `paper/make_figures.py`),
soi chéo dữ liệu A2 (round6_ablation). Phương pháp: **đếm lại độc lập từ raw
records** (`outputs/experiments/round5_e0v2|round5_defense/results_*.json`,
`data/benchmarks/bench_attack_v1`, raw `*.txt`) bằng script /tmp của V1
(không dùng code của A1/A2), chạy `--verify-only`, chạy pytest, compile
tectonic ra /tmp, test fail-safe fig_round6 trong sandbox /tmp (symlink,
không đụng file thật). KHÔNG sửa src/, KHÔNG GPU.

---

## VERDICT

- **A1: PASS** — mọi số load-bearing đều tái lập độc lập 100%. 3 issue MINOR
  (không đổi kết luận).
- **A3: PASS** — pre-reg integrity xác minh được bằng chuỗi sha config; paper
  không có số bịa. 2 issue MINOR + 1 NOTE.
- **Chuyển cho A2 (ngoài scope nhưng bắt được khi soi chéo): 1 MINOR chưa
  disclose** — McNemar dùng xấp xỉ chi2 (exact=False) ở các cell nd≥25, mâu
  thuẫn prereg "Mọi p-value McNemar exact" (chiều bảo thủ, không đổi verdict).

---

## 1. A1 — ĐẾM LẠI ĐỘC LẬP (tất cả KHỚP)

### 1.1 FP-rate per model × arm (đếm trực tiếp từ results_*.json)

| Model | C0 | D2_task | C5_near | C5_far | V1 đếm | Claim A1 |
|---|---|---|---|---|---|---|
| qwen3b (60 benign) | **60/60** | 60/60 | 60/60 | 60/60 | 1.000 mọi arm | 1.000 ✓ |
| llama3b (60) | **49/60 = 0.817** | 59/60 | 60/60 | 60/60 | ✓ | 0.817/0.983/1.000/1.000 ✓ |
| granite2b (30) | **0/30** | 10/30 | **20/30 = 0.667** | **25/30 = 0.833** | ✓ | 0.000/0.333/0.667/0.833 ✓ |

- Paired flips benign 0→1 vs C0: llama 10/11/11 (D2/near/far), **C0-correct
  = 11, conditional flip 11/11 và 10/11** ✓; granite 10/20/25, headroom 30 ✓.
- **Flip ngược (flagged→cleared) = 0 ở mọi model × arm** — đếm lại đúng.
- McNemar exact tự tính: 11 discordant → 2·2⁻¹¹ = 9.766e-04 ✓; 20 → 1.907e-06
  ✓; 25 → 5.96e-08 ✓ (A1 ghi 6.0e-08 ✓); defence llama FN 19/30, 20/30 →
  3.8e-06/1.9e-06 ✓. ΔFP CI bootstrap khớp row JSON.
- Khớp `round6_bias.json`: chạy `analyze_verdict_bias.py --verify-only` →
  **"[verify] 149 round-6 bias rows re-derived from sources and matched"** ✓
  (schema row đúng, meta đủ).

### 1.2 VCI — công thức + không double-count

Đọc `analyze_verdict_bias.py::vci()`: mỗi sample chỉ được đếm đúng 1 hướng
(benign changed → fp_dir hoặc fpc_dir; vul changed → fn_dir hoặc rec_dir;
label mismatch raise) — **không thể double-count**. Tự tính lại từ records:
llama VCI 14/120 (D2), 15/120 (near/far); granite **22/39/45 per 60**
(tự đếm: D2 = 10 fp + 1 fn + 11 rec = 22 ✓); defence llama 19/30, 20/30
(vul-only, benign không chạy — record round5_defense llama lab0 = 0, đúng
như disclose); qwen P3 1/49 (FP B0 19 → P3 18, recall 1.0→1.0) ✓; nhất quán
identity: fp_direction ≡ ΔFP-rate. Ghi chú: "39/60 flips" (H-M3 context) =
19+20 trên 2 arm — hai cách trình bày đều đúng dữ liệu.

### 1.3 Stratum concrete-vs-generic (B2) — tự tính lại, KHỚP

llama (33 concrete/27 generic theo `has_risky_api`): flips C5_near = **2 vs 9**,
C5_far 2 vs 9 ✓; C0 FP theo stratum **31/33 vs 18/27** ✓; conditional trên
C0-correct: **concrete 2/2, generic 9/9** ✓. granite (15/15): **12/8 (near),
12/13 (far)** ✓, reverse 0 ✓. Qwen: cả 2 stratum 60/60 flagged sẵn ở C0 ✓.

### 1.4 Advisory echo (B4) — evidence CÓ THẬT

Re-implement echo check (word-boundary + 15-token list): llama **2/11**
(231527 `free`; 359365 `memcpy` + "sink usage"), granite **12/20 (near),
11/25 (far)**, control C0 = **0/300** cả 3 model ✓. Raw files xác nhận:
`r5_llama3b__C5_near__359365.txt` root_cause "Sink usage in the function
bgp_capability_msg_parse" trong khi C0 cùng hàm = `no_vulnerability`;
`90871` C5_near bịa CWE-522 "unsized increment of a pointer" ✓.
**[MINOR-1 — quote showcase sai tập]**: 2 câu trích "gần verbatim" nằm ở
bullet "granite flip outputs" nhưng **thuộc bản ghi label=1 và verdict KHÔNG
flip**: quote "watchlist fingerprint…" = sample **204830 (label=1, y_pred 0→0,
status HEURISTIC_POSITIVE)**; output `{"analysis_status": "authorized"…}` =
**195017/211695 (label=1, y_pred 0→0)**. Số 12/20 & 11/25 vẫn đúng, nhưng
ví dụ minh hoạ không phải từ tập 20/25 flip đó; và "1 output authorized" thực
tế là **4** (2 near + 2 far). Nên sửa chữ thành "các raw output cùng arm
(bao gồm trên hàm vul mà advisory 'gạt' luôn)" — thực ra còn mạnh hơn cho
narrative FN-direction.

### 1.5 Trần-bias (ceiling) — disclosure ĐẦY ĐỦ, đúng hướng

Qwen FP = 1.000 **ngay ở C0** (đã xác nhận 60/60) → Δ không thể dương. Được
disclose đúng ở **5 nơi**: `docs/verdict_bias.md` §3 ("ceiling artefact, not
robustness") + §8.2; `round6_bias.md` B1; JSON note row
`bias.qwen3b.C0.saturation` ("saturation, not robustness"); prereg H-M3
("artifact TRẦN bão hòa… KHÔNG phải robustness"); A1 report §2. Config A2
còn pre-reg điều kiện đọc "ceiling-bound, not as evidence of no effect".
Llama 0.817 ở C0 được xử lý đúng bằng headroom-conditional (11/11 = 100%).
**Kết luận của V1: claim FP-bias KHÔNG bị trần làm sai lệch** — hiệu ứng
mạnh nhất (granite 0 → 0.667/0.833) đo trên baseline sạch 0/30; llama được
báo cả marginal (49→60) lẫn conditional (11/11); qwen bị loại khỏi diễn giải
một cách trung thực. Không chỗ nào đọc qwen Δ=0 thành "bền vững".

### 1.6 fp_rate bug-fix + tests

`fp_rate()` lọc `y_true == 0` và raise "no benign records" ✓;
`test_empty_or_no_benign_raises` tồn tại; `pytest tests/test_round6_bias.py`
= **20 passed** ✓. Full suite: **443 passed, 0 failed** (khớp claim cuối của
A2; con số 428 của A1 là snapshot trước khi A2 merge tests — nhất quán
timeline, không phải mâu thuẫn).

### 1.7 ĐÁNH GIÁ CLAIM "global risk priming, không content-driven"

Bằng chứng 3 chân: (i) dấu Δ đảo giữa 2 model; (ii) CI granite phủ 0;
(iii) llama Δ âm giải thích được bằng headroom (31/33 đã flagged ở C0) và
conditional cả 2 stratum lật 100%. **Chân vững nhất thực ra là direct
evidence**: advisory zero-API (generic) ĐỦ MỘT MÌNH để lật 9/9 benign-correct
của llama và 8–13/15 của granite. **[MINOR-2]**: với granite, Δ(C−G) tại
C5_near = +0.267, CI [−0.067, +0.600] (n=15/stratum) — dữ liệu KHÔNG loại
trừ được một content-effect vừa phải; chữ "GLOBAL RISK PRIMING, không phải
content-driven" (A1 report) và takeaway #3 ("shift FP-rate as much as…")
nên hạ thành "no detectable content-specific trace at this power; a
zero-API advisory alone is sufficient" — trung thực hơn và vẫn giữ nguyên
hàm ý paper. Không phải false claim, nhưng là chỗ S-R6 nên làm mềm chữ khi
điền paper.

---

## 2. A3 — PRE-REG + PAPER

### 2.1 Timeline & amendment (checklist 8) — xác minh bằng sha, có 1 lệch nhỏ

Thời gian thực (mtime/filesystem):
- 00:13:28 dry-run; **00:14:40 queue_driver.py; 00:15:12 raw generation đầu
  tiên** (`r6a_llama3b__C5_near__A1__195017.txt`); **00:20:02 mtime cuối
  cùng của `docs/round6_ablation_prereg.md`** (bao gồm Amendment-1);
  results.json đầu tiên chậm nhất ~00:49 (job 1 complete); **không có
  results.json nào trước 00:26** (find 00:14–00:26: chỉ queue_driver + raw
  txt đơn-sample).
- **[MINOR-3]** Amendment-1 tự ghi dấu "2026-09-21 00:25" nhưng mtime file
  là **00:20:02** — mộc thời gian tự khai lệch so với filesystem (5 phút).
  Nội dung claim "chưa có results nào (results.json) khi amendment ghi" ĐÚNG;
  nhưng raw generations (00:15–00:20) đã tồn tại ~60 output đơn-sample trước
  khi amendment chốt — prereg đã tự disclose điều này ("run A2 bắt đầu
  generation ~00:15").
- Bản pre-reg gốc "00:03" bị **ghi đè tại chỗ** (không snapshot) → không thể
  kiểm chứng độc lập rằng "Amendment-1 không đổi ngưỡng/rule". Điều bù lại:
  **chuỗi sha config chứng minh rules của phía A2 tồn tại TRƯỚC generation** —
  `config_sha16` trong 3 results file đầu = `f09de392ec5b3b45`; V1 tái tính:
  config hiện tại (parsed, json sort_keys) = `88c07bff09f0829b` khớp 2 file
  sau (c5_far, qwen rerun); **bỏ đúng key `extension.combined_old_sources_by_slug`
  thì hash quay lại đúng `f09de392ec5b3b45`** → amendment config duy nhất
  đúng như A2 §7 disclose (metadata-only). Config đó (pre-reg_date_utc
  2026-09-20) chứa hypotheses H-A1/H-A5/H-A2A3, rule concentration "≥50%
  hoặc distributed", điều kiện ceiling-bound, subset seed 20260923, stats
  alpha 0.05 — **tất cả provably trước 00:15:12**.

### 2.2 H-M1/H-M2/H-M3 chốt trước số — kiểm với kết quả A2 (checklist 9)

Tự tính ladder từ `results_llama3b__ablation.json` (540 records; 120 record
có `meta.reused_from` ✓ khớp con số đếm trực tiếp của A2, đúng hơn counter
metadata ghi 117 mà A2 đã giải thích): recall 1.000/0.983/0.900/0.848/
0.898/0.433, fp 1.000/0.967/0.833/0.767/0.867/0.267 — **khớp bảng A2 §2.1**
(chú ý: A3/A4 dùng mẫu parse được 59 vì 1 PARTIAL mỗi bậc — quy ước này đã
được pre-reg trong `metrics_defs` của config, nhưng A2 report không chú thích
ở bảng). Flips từng bậc 1/5/3/(0, hồi phục 3)/28; cumulative A5vsA0 = **34**
✓; A5 share = 28/34 = **82%** ≥ 50% → **cả HAI framing cùng chỉ rung A5**
→ H-M1 SUPPORTED (Δ0.465 ≥ 0.20, p<0.05), H-M2 SUPPORTED (−0.017 ≥ −0.05),
guidance G1. H-M3 (dữ liệu Vòng 5): llama 10/11/11, granite 10/20/25 —
đếm lại đúng, verdict SUPPORTED theo rule non-decreasing ✓; qwen 0/0/0
ceiling ✓. Paper drafts: RQ7b (`05_results.tex`) + bảng
(`tab_round6_ablation.tex`) + `06_discussion.tex` **ghi rõ cả hai framing
(H-M1 magnitude+p và concentration ≥50%) với token verdict riêng cho từng
cái** và comment bắt S-R6 giữ đúng 1 nhánh G0–G3 → cam kết "báo cáo cả hai"
được hiện thực trong draft. **Chưa có `outputs/master/round6_ablation.json`
/ verdict json** — collector là TODO S-R6 đã disclose; do đó chưa có số nào
được điền, không có rủi ro cherry-pick ở thời điểm audit.

### 2.3 Placeholders + compile + fail-safe (checklist 10, 11)

- Placeholder: **47 token duy nhất** (đúng claim); **56 vị trí** `{{R6:*}}`
  trong .tex (A3 report ghi "63 vị trí" — **[NOTE]** sai nhẹ, có thể đếm
  trước khi chỉnh nhánh guidance); 4 cái nằm trong comment LaTeX.
- Tectonic (`--outdir /tmp/v1_audit/texout`, không đụng repo): **exit 0**,
  chỉ over/underfull warnings; PDF 341.9 KiB; **0 dangling "??"**;
  **42 `{{R6:` render nguyên văn trong PDF** — khớp chính xác claim "42 token
  render" của A3 (16 token bảng bị pdftotext ngắt dòng, không phải lỗi LaTeX).
- `make_figures.py::fig_round6` fail-safe — V1 test 4 nhánh trong sandbox
  /tmp (symlink outputs/experiments + transformer; master json tổng hợp):
  (1) file vắng → `[skip]`, không sinh figure ✓; (2) grid near-only + far
  một phần → vẽ OK (20,841 bytes), far bị bỏ qua ✓; (3) thiếu key
  `C5_near.A3` → **AssertionError "round-6 master missing C5_near recall
  grid (primary arm)"** ✓; (4) identity-guard False → AssertionError ✓.
  Repo thật không bị tạo `round6_ablation.json` (đã kiểm sau test).
- Không số bịa: mọi cell số round-6 trong paper là placeholder; các số appears
  gần RQ7/RQ7b đều là số Vòng 5 và V1 spot-check: 49/60 ✓, granite recall
  0.100→0.433/0.733/0.767 ✓ (0.433 = 13/30, gồm 11 flip 0→1 trừ 1 backflip —
  nhất quán VCI fn=1/30; p=0.006 = 12 discordant exact 0.0063 ✓), 25/30 ✓,
  1,200 E0-V2 records ✓, 473 defence records ✓, PPV 0.479 = 0.767/1.6 ✓.

### 2.4 pytest (checklist 12)

`.venv/bin/python -m pytest tests/ -q` → **443 passed, 0 failed, 2 warnings,
25.7s** — khớp claim "443" của A2; 20 test round6_bias + 15 test
round6_ablation có mặt trong con số đó.

---

## 3. CONFIRMED BUGS (đã được chính tác nhân fix, V1 xác nhận fix thật)

1. **fp_rate không lọc label=0 (A1)** — bản hiện tại lọc `y_true==0` +
   raise khi rỗng; regression test `test_empty_or_no_benign_raises` có thật,
   20/20 pass. ✓
2. **Cross-model reuse contamination qwen spot (A2)** — record A5 qwen lần
   đầu là generation llama; đã quarantine
   (`outputs/experiments/round6_ablation/quarantine/results_qwen3b__ablation__15.POLLUTED.json`
   tồn tại), guard model-mismatch + test mới; số sạch V1 đếm lại: qwen A1
   1.0/1.0, A5 1.0/0.9667, 0/60 vul flips, 1 benign flip → "qwen inert" đúng. ✓
3. **granite combined bug (old-source hard-code sang file llama, A2 §3.2)** —
   config hiện tại có `combined_old_sources_by_slug` per-model; V1 đếm lại
   combined granite benign n=70: C0 3/70, C5 50/70 (0.714), +47 flips ✓;
   `combined_with_round5.source` = file granite ✓.

## 4. FALSE CLAIMS

- **Không có false claim material.** Các phát hiện lệch nhỏ (đều đã nêu):
  quote B4 minh hoạ từ record không nằm trong tập flip được nêu [MINOR-1];
  "1 output authorized" thực tế 4 [MINOR-1]; "63 vị trí" thực tế 56
  [NOTE]; Amendment-1 tự stamp 00:25 vs mtime 00:20:02 [MINOR-3];
  A2 report benign A5vsA4 p "1.1e-05" vs file **7.629e-06** (file mạnh hơn —
  lỗi chép tay) [MINOR, bên A2].

## 5. PHÁT HIỆN CHUYỂN A2 (soi chéo ngoài scope)

**[MINOR — nên disclose trước camera-ready]** `mcnemar()` gọi mặc định
`exact=None` → statsmodels tự chuyển **chi2 khi nd≥25**, trong khi prereg
Vòng 6 ghi "Mọi p-value McNemar exact". Các cell bị ảnh hưởng: A5vsA4 vul
(3.352e-07 chi2; exact = 2·2⁻²⁸ = 7.45e-09), A5vsA0 (1.519e-08; exact
1.16e-10), granite combined benign/vul (1.95e-11/1.50e-10; exact
~1.4e-14/~8.5e-13), granite extension-only (5.6e-07). Llama combined benign
1.53e-05 là exact (nd=17<25). **Tất cả lệch theo chiều bảo thủ (chi2 p lớn
hơn exact p) → không verdict nào đổi**, nhưng bảng A2 §2.1–§3.2 in các p này
mà không ghi method; nên ghi "chi2 approx for nd≥25" hoặc ép exact=True rồi
recompute (metrics-stage chỉ, không cần generation mới).

## 6. AI SAI / AI BẮT ĐƯỢC

- **A1 sai-then-fixed**: fp_rate bug — bắt bằng self-test trước khi chạy số,
  fix + regression test; V1 xác nhận.
- **A2 sai-then-fixed (2 lần, tự audit được)**: qwen cross-model reuse
  (quarantine + guard + test) và granite combined old-source (per-model
  mapping + assert + test); V1 tái xác nhận cả 2 bằng đếm độc lập và chuỗi
  sha config.
- **V1 bắt được những gì tác nhân không tự thấy**: (1) quote B4 "verbatim/
  authorized" nằm ngoài tập flip được trình bày (thuộc hàm vul bị advisory
  gạt — thực tế evidence FN-direction còn mạnh hơn); (2) McNemar chi2-vs-exact
  lệch prereg ở các cell nd≥25; (3) p 1.1e-05 chép lệch file (7.63e-06);
  (4) Amendment-1 stamp 00:25 ≠ mtime 00:20:02; (5) "63 vị trí" ≠ 56.

## 7. KẾT LUẬN CHO S-R6

1. Số FP-bias (llama 0.817→1.000 p=9.8e-04; granite 0→0.667/0.833
   p=1.9e-06/6e-08; VCI attack=FP-dir vs defence=FN-dir) **dùng được cho
   paper** — truy vết tốt, verify-only thật, ceiling disclosed đúng.
2. Khi điền `{{R6:*}}`: giữ cả hai framing verdict như draft đã cam kết;
   làm mềm chữ "global priming" thành "no detectable content-specific trace
   (zero-API advisory alone suffices)".
3. Yêu cầu A2: ghi method McNemar (exact/chi2) vào bảng hoặc recompute exact;
   sửa p 1.1e-05 → 7.629e-06 trong bảng §2.2 (làm trong report/metrics của
   A2, V1 không đụng).
4. Sửa 2 chữ ở `docs/verdict_bias.md` §6 + `reports/round6/A1_report.md` §5:
   source của 2 quote showcase (sample 204830/195017 — hàm vul) và đếm
   "authorized" = 4.
5. Không cần chạy lại generation nào; mọi fix đều là chữ/metrics-stage.

---
*Verification của V1: script độc lập /tmp/v1_audit/{fp_count2,strata,echo,
quote_check,cfg_diff}.py; `analyze_verdict_bias.py --verify-only` PASS (149
rows); pytest 443 passed; tectonic exit 0 ra /tmp; fig_round6 fail-safe 4/4
nhánh trong sandbox; repo chỉ thay đổi `reports/round6/V1_report.md` này.*
