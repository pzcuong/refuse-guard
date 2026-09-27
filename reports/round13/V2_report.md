# ROUND 13 — V2 REPORT: AUDIT ADVERSARIAL bản W2 (rewrite paper2 theo thesis mới)

Agent: V2 (audit vòng 13). Ngày: 2026-09-27. Phạm vi: ĐỌC + COMPILE ONLY.
Chỉ tạo `reports/round13/V2_report.md` (file này) + script tạm trong /tmp.
Mọi số dưới đây đều tự verify lại từ artifacts (không tin vào report của W2).

---

## VERDICT W2: **PASS — không có lỗi chặn (0 blocking)**; 3 issue mức LOW
(tất cả nằm ở **báo cáo của W2** / **quyết định điền của F**, không nằm trong
nội dung số của paper). Mọi số trong paper2/main.tex đều truy vết được về
macro `numbers.tex` hoặc literal có `% SRC:` và KHẚP artifact thật.

---

## KIỂM THEO CHECKLIST (bằng chứng từng mục)

### 1. CẤU TRÚC P3-15/16 — ĐẠT
- **(a) Abstract ≤250 từ (đếm THẬT):** Đếm độc lập 2 cách: script trên nguồn
  (strip comment, expand 336 macro) = **231–235 từ** (tùy convention gạch nối);
  đếm trên **PDF render bằng pdftotext** (ABSTRACT → hết câu
  "…a refinement, not a replacement.") = **232 từ**. Comment trong main.tex ghi
  "237" — lệch nhẹ do convention, **vẫn ≤250 dư ≥15 từ** → PASS.
- **(b) Đúng 3 contributions:** `enumerate` có đúng 3 item: C1 Measurement
  (L107), C2 Defense (L116), C3 Background detector (L126). Không còn danh
  sách 5 contribution cũ. PASS.
- **(c) 8B + three-client ≤1 câu trong main text:** grep text đã strip comment:
  `8B` (dạng `${\ge}8$B`) **1 câu duy nhất** ở Threats L698–702;
  `three-client` **1 câu duy nhất** (chung câu compound với 8B, L699). Full
  detail nằm Appendix A.8 (8B) và A.4 (three-client). PASS.
- **(d) KB-F1 ablation 1 câu ở main; tab:kb ở appendix:** main text chỉ còn
  đúng 1 câu (L597–602, "Sensitivity and knowledge base, compressed.");
  `tab:kb` nằm Appendix A.5 (L880–900). PASS.
- **(e) audit-log/round-N trong main text = 0 hit:** grep main.tex
  comment-stripped: `AMENDMENT` = **0**; `round-N` = **0**. Trên **PDF compiled**:
  `??` = 0, NHƯNG `round-11` còn **4 hit — tất cả trong References** (note
  fields của refs.bib: L68, L76, L85, L109) — xem CONFIRMED BUGS #1 (W2 không
  được đụng refs.bib nên xuất phát từ đó; xem ra vẫn là từ vựng audit lộ trong
  phần visible của bài → để F quyết editorial).
- **(f) Threats to Validity cô đọng đủ retraction + fp_bias rename:** §7 mục
  (i) fp_bias→recall rename; (ii) retraction "text degrades under federation";
  (iii) minority-harm bug + collapse→undertraining (0/80 converged);
  (iv) FedProx μ routing. PASS.

### 2. SỐ — ĐẠT (spot-check **>20 số**, tất cả khớp artifact)
- **(a) `gen_paper_numbers.py --check`:** chạy lại thật →
  `GEN-NUMBERS CHECK: OK -- 336 macros verified against artifacts (640 grid
  rows, 20 seeds).` exit 0. PASS.
- **(b) Spot-check tab:safety (n=60) ↔ `safety_metrics_n60.json`:**
  llama P2 rec `.133→.033`, flips b→m/m→b = 1/4 ✓ (artifact 0.0333, count 1 & 4);
  granite P2 rec `.533→.800`, flips 8/0 ✓; FP 0/30 mọi arm ✓; "All 11 flips
  land on malicious" ✓ (1+2+8=11); "0/180 benign FP" ✓ (3 arms×2 models×30,
  fp rate 0.0).
- **Spot-check n=100 ↔ `r10/r8_safety_expand/safety_metrics_n100.json`**
  (mock=false): pooled rec `.350→.380→.440` ✓; FP `0/0/2-of-100` ✓ (pooled fp
  P2 = .02 trên 100 benign); flips P2 `19/8` trên `200 pairs` ✓ (llama 3+16=19,
  m→b 8+0=8); llama `.160→.060`, FP 0, cả 8 m→b là của llama ✓; granite
  `.540→.820`, FP `0→.040` (=2/50, cả 2 FP pooled là granite) ✓.
- **Spot-check tab:defense ↔ `defense_metrics.json` + `defense_analysis.json`**
  (round 12, mock=false, AMENDMENT-6 registered 18:46Z trước generation
  19:16Z): llama `.167/.042/.042`, +g/−l `1/1`, p `1.0` (b01=1,b10=1) ✓;
  granite `.667/.833/.652`, `0/4`, p `.125` (b10=4, exact) ✓; FP
  `0/50→0/14`, `2/50→0/14` ✓; granite P2D1 parsed `23/24` (1 unparseable,
  disclosed) ✓; flips_P2D1_vs_P0 = [] (23/23 khớp baseline) ✓; 4/4 revert ✓;
  `24 mal + 14 ben` ✓; gate `38/45`, excluded 6 mal + 1 ben ✓; **Fisher
  p=.40** — tự tính lại fisher_exact([[6,24],[1,14]]) = **0.3955** → ".40"
  đúng chuẩn làm tròn ✓; pooled `.417(20/48) / .438(21/48) / .340(16/47)`,
  restore `1 vs 5`, McNemar `p=.219` (tự tính .21875) ✓, `p=.375` vs neutral
  (1v4, .375) ✓, FP defended `0/28` ✓; min exact p `.125` =
  `descriptive_power.min_exact_mcnemar_p` ✓; "19 families, llama 1/19 mọi
  arm; 2500-char byte-identical; 38/38 strip(P2)==strip(original); 10/10
  prompt + 20/20 completion identical; 0/76 sha mismatch" — khớp **audit độc
  lập round-12 V1_report.md** (mục CLAIM 2/3, 45/45 stripper byte-identical) ✓.
- **(c) TOST ↔ `p0_results.json` aggregate.tost_primary:** mean_delta
  −.006494 → **−.0065** ✓; CI [−.013294, +.000306] → **[−.0133, +.0003]** ✓;
  margin ±.02, equivalent=true ✓. Trivial: `+.0227 / +.0487`, p `1.9e-5 /
  1.9e-6` ↔ `trivial_results.json` group df1_mean .022694, wilcoxon
  1.907e-5 ✓ (random kiểm qua --check). Mechanism ablation: granite
  `.6000→.6667` p=.5, `→.6333` p=1.0; llama `.1333→.2333` p=.25, `→.1667`
  p=1.0; **96/180 cache hits** (đếm lại từ mechanism_batch.jsonl: 96 True/84
  False) ✓. Granite ladder: `.7627→.0667`, `41/0`, chi2-cc 4.185e-10,
  exact 9.09e-13, `.4000` (23/2, 6.33e-5), benign `0/30→20/30` (1.907e-6)
  ↔ `r10_granite_ladder/metrics_round9.json` ✓.
- **Lưu ý (không phải lỗi):** `\pmGenDefTotal` = 2,700 là tổng
  180+900+1,200+360+60 — **không gồm** n100-expansion (600 gen) và defense
  batch (~240 gen), đều RR=0 → paper đang **kê thấp** phạm vi bằng chứng
  RR=0 (chiều an toàn).

### 3. TITLE + THESIS — ĐẠT (có 1 ghi chú editorial)
- Title *"The Advisory Inside: Measuring and Closing an In-Package Attack
  Surface on LLM Package Analyzers"* phản ánh headline reviewer (đo + đóng
  bề mặt in-package). **Không coi là overclaim** dù llama không được restore,
  vì: (i) "closing" đúng nghĩa hẹp — defense **chứng minh removing attack**
  (strip(P2)=strip(original) 38/38, byte-equality) kể cả trên llama; (ii) mọi
  claim "close" trong thân bài đều được scope: abstract "closes the channel
  **where it inflates detection**" + ngay sau đó nêu llama cost; Discussion
  "necessary and cheap, **but not uniformly sufficient**"; Conclusion "closes
  it **where it matters most**" + "residual cost—no restoration for a
  cue-based family—measured and disclosed". Llama được nâng thành first-class
  outcome (C2, tab:defense, đoạn riêng L463–473). → PASS; nếu orchestrator
  muốn an toàn tuyệt đối có thể hedge title, nhưng không bắt buộc.
- **"Family-dependent" có data chống lưng:** llama = harm (.167→.042, strip
  restores nothing), granite = neutralized sau strip (23/23, 4/4 revert, FP 0)
  — 2 family đều có đo trực tiếp trong package domain. **Không có arm safety
  cho Qwen trong paper này** (n60/n100 chỉ có llama+granite; Qwen chỉ xuất
  hiện trong KB ở vai 0.5B pilot) — paper KHÔNG hàm ý family thứ ba, wording
  nằm trong evidence. Ladder granite trên vulnerability-domain (A.7) bổ trợ
  trục domain-dependence. PASS (n=2 families — đã ghi ở Threats qua "direction
  follows model family and domain, no scale extrapolation").

### 4. PLACEHOLDER — ĐẠT (8 token, không phải 7)
- Grep `\{\{R13:[A-Z_]+\}\}` trên main.tex: **đúng 8 token**
  (LFO_GRAPH_DF, LFO_GRAPH_CI, LFO_TEXT_DF, LFO_TEXT_CI, LFO_FOLDS,
  LFO_CONTRAST, LFO_TEST, **LFO_P**). Báo cáo W2 viết "**7 token**" (bảng của
  W2 gộp LFO_TEST + LFO_P vào 1 hàng) — **đếm sai trong report**, không sai
  trong file. → CONFIRMED BUGS #2.
- Cả 8 đều bọc đúng `\detokenize{{{...}}}` (check bằng string match sau khi
  sửa lỗi đếm ngoặc của chính tôi), tất cả nằm trong `\label{sec:lco}`
  (pos 37241–37615, trước `\section{Discussion}`). PASS.
- Tectonic exit 0; PDF 8 trang; **0 "??";** 8/8 token render **searchable**
  trong PDF (`grep -oE "R13:[A-Z_]+"` bắt đủ 8) → F grep được khi điền. PASS.

### 5. THUYẾT TRÌNH TRUNG THỰC — ĐẠT
- **(a) Softening cho llama:** có — xem mục 3. Passage llama ghi rõ "the strip
  restores nothing", "the defense removes cues indiscriminately", "one-family
  observation at this draw".
- **(b) RR=0 đoạn ngắn đúng chỗ:** §5.1 gói trong 1 đoạn ngắn, scope 2,700
  ("in this domain", "at these scales and prompt families", "we do not
  generalize"). Refusal pathway còn được chứng minh sống (probe 125/225 —
  generator lấy từ E0 PROBE records).
- **(c) Superlative:** "first" xuất hiện 3 lần, đều vô hại ("first-class
  outcome", "first draw", "defender's first question") — **không có priority
  claim**; claim FL-novelty được hedge ("to our knowledge… a literature-check
  hedge"). "Provably" chỉ gắn với byte-equality (đã verify 38/38).
- **(d) Threats đủ:** pilot n ✓ (power para: CI ±.05–.08, 24+14, min p .125,
  zero-discordant uninformative, one-family); descriptive p ở safety ✓
  (§Setup + L388–390 comment + L404–407); popularity-benign ✓ (Setup "assumed
  benign, not individually audited" + Threats); expansion-pool chưa verify ✓
  (A.6 "plan-level pool figure … remains unverified; 265 scanned, 100
  gate-pass"); family-confound-scale: xử lý gián tiếp ("follows model family
  and domain, so no scale extrapolation is made") — đủ nhưng có thể thêm 1 mệnh
  đề tường minh "family và scale trùng nhau ở 2 model (2B/3B) nên không tách
  được" (khuyến nghị, không bắt buộc).

### 6. TÍNH TRUY VẾT (10+ macro soi tên↔giá trị↔nguồn) — ĐẠT
pmSafeLlamaPtwoFlipsM=4 ↔ tab:safety ↔ n60 m2b=4 ✓; pmSafeGranitePtwoFlipsB=8
↔ n60 ✓; pmSafeNLlamaRecPzero/Ptwo .160/.060 ↔ n100 ✓;
pmSafeNGraniteFpPtwo=.040 ↔ n100 fp .04 ✓; pmPzGroupGraphDelta/Ci −.0065/
−.0133/+.0003 ↔ p0 TOST ✓; pmTrivFullGroupDelta/P +.0227/1.9e-5 ↔
trivial_results ✓; pmGenDefTotal 2,700 ↔ generator decomposition ✓;
pmProbeRefusals/Recs 125/225 ↔ E0 PROBE ✓; pmKbUniverseTypes/Instances
137/2,299 ↔ coverage_v3 (đi qua --check) ✓; pmStatsGroupTfidfDf −.0521 (A.2,
số bị rút) ↔ grid cũ qua --check ✓. Không thấy macro nào dùng sai nghĩa.

### 7. COMPILE — ĐẠT
`tectonic -X compile --keep-logs main.tex` → exit 0, **main.pdf 8 trang**,
0 "??", 0 undefined/multiply-defined; Overfull chỉ **1 \vbox 1.44pt lúc
\output** (column balancing — đúng như W2 disclosed, vô hình); vài Underfull
\hbox ở A.8 (cosmetic). PackGuard_final.pdf (03:25) CŨ hơn main.pdf (04:16)
— F cần tái xuất bản final sau khi điền LFO.

---

## CONFIRMED BUGS (không có bug số liệu trong paper; các bug dưới là report/手off)
1. **[LOW — refs.bib lộ từ vựng audit trong References]** PDF compiled chứa 4
   chuỗi "round-11 audit" visible trong mục tài liệu tham khảo
   (refs.bib L68 duan2021maloss, L76 ohm2020backstabbers, L85 halder2024memptec,
   L109 refuseguard2026 — note fields). Grep "round-N" trên main.tex = 0 (W2
   không own refs.bib), nhưng trên **bản PDF render thì References là một phần
   visible của bài** → claim của W2 "`round-N` → 0 hit toàn bài" **không đúng
   với PDF**. Ảnh hưởng: thẩm mỹ/qui định venue, KHÔNG sai số. Khắc phục: F
   (owner cuối) reword note fields thành provenance trung tính, hoặc chấp nhận.
2. **[LOW — handoff sai số đếm]** W2_report §4 ghi "**7 token** {{R13:*}}";
   thực tế file có **8** ({{R13:LFO_P}} tách riêng). Rủi ro: F điền thiếu 1.
   Bảng nghĩa token trong report vẫn đúng nội dung.
3. **[COSMETIC]** Comment đếm từ abstract ghi "237"; đếm độc lập cho
   231–235 (source) / 232 (pdftotext). Vẫn ≤250 — chỉ cần sửa comment cho
   khớp convention.

## FALSE CLAIMS
- **Không tìm thấy false claim trong paper2/main.tex.** Mọi số được soi
  (>20) khớp artifact; các làm tròn đều đúng chiều (.40 ← .3955; .219 ←
  .21875; 4.2e-10 ← 4.185e-10; −.0065 ← −.006494).
- 1 hồ sơ nghi vấn tự bóc: `defense_analysis.json /pooled/arms/P2_D1/rr
  = 0.0132 (1/76)` trông như 1 refusal trong defense batch — kiểm ra là
  `n_unparsed_or_refusal = 1` = **output granite P2+D1 unparseable đã
  disclosed** trong tab:defense caption (L423–424), KHÔNG phải refusal. Paper
  nói "Refusal absent" vẫn đúng.
- Claim sai duy nhất nằm ở **W2_report.md** (không phải paper): "round-N →
  0 hit toàn bài" (bug #1) và "7 token" (bug #2).

## AI SAI / AI BẮT ĐƯỢC
- Bị W2 "gạt" 2 lần bởi tooling của chính mình: (i) check `\detokenize` lần
  đầu báo 0/8 bọc đúng — sai ở **số ngoặc của regex tôi** (token regex đã
  gồm `{}`), sửa lại = 8/8 đúng; (ii) đếm từ abstract trên PDF lần đầu ra
  6,411 từ — sai ở **mốc cắt boundary** (nonacm nên không có "CCS Concepts"),
  sửa lại = 232. Bài học: audit cũng phải tự re-verify script của mình.
- Bắt được điều W2 bỏ sót: 4 chuỗi "round-11 audit" trong refs.bib render
  thẳng vào References của PDF — grep của W2 chỉ chạy trên main.tex nên
  không thấy; đây là điểm "audit-log lộ visible" duy nhất còn lại của bài.
- Bắt được lệch protocol giữa paper và W1: §5.4 viết "leave-**families**-out
  (LFO) … {{R13:LFO_FOLDS}} held-out family **folds** … 95% CI" trong khi
  artifact W1 là leave-**cluster**-out (MinHash+package-closure), **20 seeds ×
  hold-out ngẫu nhiên ~20% cluster** (không phải k folds), báo cáo W1 chỉ có
  mean±std (**chưa có 95% CI nào được tính**). F điền theo W1 report §6 phải
  viết lại mô tả protocol hoặc tính thêm CI, nếu không sẽ mô tả sai thí
  nghiệm đã chạy.
- Nhắc lại ràng buộc trung thực khi F điền (W1 §3.3): kết luận LFO phải là
  hai chiều "both representations degrade by a small, statistically
  indistinguishable amount; **no robustness ranking supported**" (dd
  −.0033…−.0139, Wilcoxon p .37–.99) — KHÔNG được viết "graph bền hơn text".

## PAPER-READY CHECKLIST (cho F — việc còn lại trước khi chốt bản final)
1. **Điền đủ 8 (không phải 7) token** `\detokenize{{{R13:*}}}` ở §5.4
   (`\label{sec:lco}`), thay toàn cụm bằng giá trị/macro mới + `% SRC:` trỏ
   `outputs/packguard/lco/lco_results.json` (480 rows, mock=false,
   config_sha16 9bea57439fa0c473). Ánh xạ gợi ý từ W1 (threshold 0.30
   primary): GRAPH_DF = −.0383 (sc) hoặc −.0317 (fedavg); TEXT_DF = −.0289 /
   −.0179; CONTRAST dd = −.0095 (sc) / −.0139 (fedavg); TEST = exact paired
   Wilcoxon; P = .368 / .674 (t0.5: dd −.0033 p=.985 / −.0121 p=.430).
2. **Sửa mô tả protocol §5.4 cho khớp artifact:** đổi "leave-families-out …
   family folds" thành leave-cluster-out ("MinHash family clusters with
   package closure; 20 seeds × randomized ~20% cluster hold-outs; sensitivity
   threshold 0.50"); hoặc tính 95% t-CI của mean ΔF1 từ lco_results.json nếu
   giữ wording CI; cập nhật luôn chữ "queued … LFO" ở Conclusion (đã chạy xong
   rồi, không còn "queued"); cân nhắc đổi tên nhãn LFO→LCO cho nhất quán.
3. **Quyết refs.bib (bug #1):** reword 4 note fields bỏ "round-11 audit" nếu
   venue cấm từ vựng audit nội bộ; sau đó compile lại.
4. **Sửa comment đếm từ abstract** (237 → 231/232 tùy convention; vẫn ≤250).
5. Sau điền: chạy `.venv/bin/python scripts/gen_paper_numbers.py --check`
   (OK 336), `tectonic main.tex` (exit 0), kiểm `??` = 0, `R13:` còn 0 hit
   trong PDF, đếm trang, rồi **xuất lại PackGuard_final.pdf** (hiện cũ hơn
   main.pdf).
6. Tùy chọn (không chặn): 1 mệnh đề tường minh family/scale confound ở
   Threats; quyết định giữ/hedge chữ "Closing" trong title (đã đánh giá là
   defensable — xem mục 3).
