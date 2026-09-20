# V2 Report — Round 6 (AUDIT ADVERSARIAL A2: P3-ablation + C5 extension)

Ngày: 2026-09-21. Tác nhân: V2 (kiểm lỗi độc lập, vòng 6). Phạm vi: soi claim
nóng nhất của A2-R6 — "system reassertion là thủ phạm (28/34 = 82% tổng harm,
McNemar p=3.35e-07); boundary-wrap minimal vô hại; replicate C5_far; qwen miễn
nhiễm (0/60 flips)" — với tiêu chí: nếu component không được cô lập sạch thì
conclusion paper sai. KHÔNG sửa code, KHÔNG GPU; mọi số dưới đây tự đếm/tự
render bởi script /tmp của V2 và truy vết tới file output thật.

---

## VERDICT A2: **PASS** (không có issue material; 4 issue MINOR/NIT phải xử
lý trước camera-ready — xem §I)

Claim trung tâm **ĐỨNG VỮNG** sau audit adversarial. Ba trụ cột đều xác minh
được độc lập từ raw data, không qua code/metric của A2:

1. **Rung cô lập SẠCH (điểm mấu chốt của attribution)** — V2 tự render prompt
   A0→A5 cho cả 90 sample bằng chính build functions của
   `src/experiments/round6_ablation.py` và DIFF từng bước:
   - A0→A1: chỉ các comment advisory-flagged được bọc UNTRUSTED-ANNOTATION
     (0/90 sample có hunk nào khác); KHÔNG header, system == B0.
   - A1→A2: chỉ thêm 1 dòng header CONTEXT-PROVENANCE (90/90).
   - A2→A3: chỉ generic-wrap các comment còn lại (90/90).
   - A3→A4: chỉ string mediation — mọi dòng ± trong diff đều là dòng chứa
     string được chuyển sang dạng `STRING[dataflow]:...` (90/90).
   - A4→A5: **user prompt GIỐNG NHAU TỪNG BYTE ở 90/90 sample**; khác biệt
     DUY NHẤT là system prompt = B0-system + `"\n" + SYSTEM_REASSERTION`
     (90/90, so bằng equality với hằng `SYSTEM_REASSERTION` của
     `p3_boundary.py`).
   - System A1–A4 == system A0 (B0) ở 90/90.
   → Mỗi rung đúng thêm ĐÚNG 1 component; attribution theo bậc là hợp lệ.
   Ladder bậc A5 CHỈ khác A4 bởi reassertion nên flip 28/0 ở bậc này ĐÚNG là
   ảnh hưởng riêng của reassertion.
2. **A5 byte-identical với P3 Vòng 5** — V2 re-render P3 bằng pipeline GỐC
   round5 (`p3_boundary.apply` + `p3_prompt` với `configs/round5_defense.yaml`)
   cho cả 90 sample: prompt sha trùng ladder-A5 **90/90**. Pre-run audit claim
   "B0 90/90, P3 30/30" tái lập đúng (sha từng record vs file round5).
3. **Số tái lập toàn bộ** — recall ladder 1.000/0.9833/0.900/0.8475/0.8983/
   0.4333; flips từng bậc 1/5/3/(0, hồi phục 3)/28; cumulative vs A0 =
   1/6/9/6/34; p tự tính bằng scipy khớp từng ô (§2 chi tiết); C5_far A5
   recall 0.3898 (59 parsed), 36 flips 1→0 trên 59 pairs valid — khớp
   "36/59"; qwen A5-vs-A1 vul flips 0/0, benign 1→0 = 1, p=1.0 — khớp "0/60";
   extension 8/8 bảng (llama ext-only 0.825→0.975 +6/0 p=0.0312; combined
   n=100 0.820→0.990 +17/0 p=1.53e-05; vul +8/0 p=0.0078; granite ext-only
   0.075→0.750 +27/0 p=5.62e-07 và 0.025→0.625 +24/0 p=1.19e-07; combined
   n=70 0.0429→0.7143 +47/0 p=1.95e-11, vul 0.0571→0.6714 +43/0 p=1.5e-10)
   — ĐỀU khớp report A2 sau đếm độc lập.

---

## 1. Bằng chứng chi tiết theo checklist

### CHECK 1 — Rung cô lập + byte-identity (PASS, chi tiết ở Verdict)
- A5 == P3 cũ: ngoài 90/90 re-render, 30 record A5 được reuse qua sha-gate
  (30/30 match), và qwen-rerun đạt **180/180 cache-hit** — cache key trùng
  tuyệt đối chỉ xảy ra khi prompt+gen_cfg+model trùng byte, nên đây là bằng
  chứng độc lập thứ 3 cho byte-identity.
- Reuse integrity (V2 tự so từng record với file nguồn): llama ablation
  120/120 (A0=90, A5=30) khớp y_pred AND status, 0 mismatch; C5_far 30/30
  ok. `meta.reused_from` đếm trực tiếp = **120** (counter metadata ghi 117 —
  nit đã disclose đúng nguyên nhân: 3 record A5 reuse từ checkpoint lần chạy
  đầu bị cắt; queue.log line 3 "resuming 25/540" xác nhận).
- Traceability: 120/120 record reused còn trỏ tới raw file round5 TỒN TẠI
  trên disk; 0/420 record fresh thiếu raw file; 5 cặp raw A5-vs-A1 đọc trực
  tiếp từ `raw/`: nội dung == `meta.text` từng byte, flip thật (vd 195083:
  A1 `vulnerable=1` → A5 `no_vulnerability, confidence 0.0`; 195261 tương
  tự; 195233/195237/195296 giữ vulnerable — đúng tỷ lệ 26/60 còn đứng).
- Subset pairing: vul set == đúng 60-vul của round5_e0v2 (so với selection
  metadata); benign set == đúng 30-benign của round5_defense **ở cấp
  selection** (llama round5_defense chỉ chạy vul — records là 30 vul × 3
  arms × {B0,P3,P3R} = 180, không có benign record nào; claim "verified
  before pre-reg" trong config hiểu theo selection half là ĐÚNG — V2 đã thử
  bẫy bằng records và xác nhận phải đọc theo selection).

### CHECK 2 — Số ladder (PASS)
Đếm độc lập từ `results_llama3b__ablation.json` (540 records, 0 SKIPPED):

| Bậc | recall_vul (V2 đếm) | flips 1→0 / 0→1 | p McNemar (auto) | p exact thuần |
|---|---|---|---|---|
| A1 vs A0 | 0.9833 | 1/0 | 1.0 | 1.0 |
| A2 vs A1 | 0.9000 | 5/0 | 0.0625 | 0.0625 |
| A3 vs A2 | 0.8475 (59 parsed) | 3/0 | 0.25 | 0.25 |
| A4 vs A3 | 0.8983 (59 parsed) | 0/3 | 0.25 | 0.25 |
| **A5 vs A4** | **0.4333** | **28/0** | **3.35e-07** | **7.45e-09** |
| A5 vs A0 (cum.) | — | 34/0 | 1.5e-08 | 1.16e-10 |

Non-monotonic A3→A4 (+3 hồi phục, n.s.) có thật và được A2 disclose đúng ở
§2.2(4). Tổng có dấu 1+5+3−3+28 = 34 = net A5-vs-A0 — ladder tự-consistent.

### CHECK 3 — Qwen immune + quarantine (PASS)
- File sạch `results_qwen3b__ablation__15.json`: 180/180, **0 record
  reused**, 180/180 cache-hit (0 gen mới); A1 recall 1.000, A5 recall 1.000,
  vul flips A5-vs-A1 = **0/0 (p=1.0)**, benign 1→0 = 1. Baseline tương đương:
  qwen round5 B0 C5_near recall cũng = 1.000 nên so A1 là tương đương so B0.
- Cross-check với round5 qwen P3 trên 30 sample overlap: **30/30 khớp
  y_pred** (đúng như nếu reuse hợp lệ — vì generation thật của qwen round5
  được tái sử dụng qua cache).
- File polluté trong `quarantine/`: V2 soi — metadata reused=30; A5 của file
  này **19/30 lệch** so với round5 qwen P3 nhưng **30/30 TRÙNG y_pred với
  P3 LLAMA** và recall 0.6833 — nhiễm chéo llama được CHỨNG MINH, không phải
  chỉ nghi ngờ. Số polluté (0.683/19 flips) KHÔNG xuất hiện ở bất kỳ bảng nào
  của A2 report. queue.log line 1618 (`reused=30 cache_hits=19/150`) và
  qwen_rerun.log line 1 (`reuse A5: DISABLED — ... model mismatch`) xác nhận
  timeline phát hiện → fix → chạy lại.

### CHECK 4 — "82% tổng harm" (PASS, kèm yêu cầu diễn đạt)
- Định nghĩa thực tế: 28/34 = 82.35% trong đó 34 = TỔNG flips vul 1→0 của
  P3-full (A5) vs B0 (A0), 28 = flips xuất hiện ĐÚNG tại bậc reassertion
  (A5 vs A4). Theo Δrecall: 0.465/0.567 = 82.0% — hai framing cùng cho 82%.
- Tính hợp lệ: 28 (A5-vs-A4) là TẬP CON của 34 (A5-vs-A0) VÌ A0 recall =
  1.000 (60/60 parsed đều y_pred=1) → mọi sample y_pred(A4)=1 có
  y_pred(A0)=1. Subset-argument này CHỈ đúng do B0 saturated; nếu B0 < 1
  thì "share of total flips" không còn là tập con. Cần ghi caveat này khi
  viết paper.
- KHÔNG phải "sum of decrements": tổng các decrement dương = 1+5+3+28 = 37
  ≠ 34 (vì A4 hồi phục 3). "82%" là **share của net harm**, không phải tỷ
  trọng cộng-dồn các component-harm; ladder cumulative KHÔNG cho phép phân
  rã harm theo thành phần có tính cộng (prereg §6 đã khai trước giới hạn
  này). Câu chữ A2 report ("28/34 = 82% tổng số flip vul 1→0 của
  P3-full-vs-B0") là ĐÚNG; chỉ cần giữ nguyên dạng câu này trong paper, tránh
  viết kiểu "reassertion contributes 82% of the harm (rest split among
  components)" — sẽ sai vì 6 flips cumulative trước A5 ≠ 6 samples riêng biệt
  (có sample flip rồi flip lại).

### CHECK 5 — Pre-reg conformance (PASS)
- mtimes: generation bắt đầu **00:15:12** (raw file đầu tiên
  `r6a_llama3b__C5_near__A1__195017.txt`); dry-run 00:13; kết quả complete
  đầu tiên 00:51. Config mtime hiện tại 01:27 là SAU generation — nhưng:
- **Chuỗi sha chứng minh config design đã cố định trước generation**:
  (i) dry-run 00:13 (TRƯỚC generation) ghi `config_sha16 = f09de392ec5b3b45`
  — trùng sha trong cả 3 file kết quả chạy trước amendment;
  (ii) V2 reconstruct: config hiện tại **trừ đúng khóa
  `extension.combined_old_sources_by_slug`** → sha16 = f09de392ec5b3b45
  (KHỚP TỪNG BYTE). → Amendment sau 3 job chỉ thêm ĐÚNG 1 khóa metadata-only
  như disclose §7.1; toàn bộ ladder/subset/hypotheses/ngưỡng không đổi sau
  khi unblind.
- Prereg doc (mtime 00:20, trước kết quả đầu 00:51) + Amendment-1 khóa
  framing kép: H-M1 (Δ≥0.20 & p<0.05: bậc A5 Δ=0.465, p=3.35e-07 →
  SUPPORTED) và rule concentration của config (single-step flip lớn nhất =
  A5, 28 ≥ 50%×34 → KHÔNG distributed) — hai framing CÙNG verdict, không có
  cherry-pick. H-M2: 0.9833 ≥ 1.0−0.05 → SUPPORTED → guidance G1 hợp lệ.
- Lưu ý biên tập: prereg doc tự ghi "AMENDMENT-1 (00:25)" nhưng mtime file
  là 00:20:02 — lệch 5 phút, vô hại (cả hai trước kết quả đầu tiên).

### CHECK 6 — Extension (PASS)
- Selection là PHẦN BÙ: 80 sample extension có overlap = **0** với 120
  sample selection round5 (không double-count; `n_overlaps_skipped`=0);
  granite dùng đúng 80 sample đó (`granite ext ids == llama ext ids`).
- Combined: llama ghép file `results_llama3b.json` (cùng model), granite ghép
  `results_granite2b.json` (cùng model) — V2 đếm lại toàn bộ 8 ô khớp như
  Verdict(3). Granite combined chỉ 70+70 vì round5_e0v2 granite chỉ chạy đầy
  đủ cặp C0/C5_near trên 30+30 nested (30+30 còn lại thiếu arm → rơi khỏi
  paired intersection) — đúng như A2 disclose.

### CHECK 7 — 2 self-caught bugs (CẢ HAI THẬT, đã fix, có test)
- **(a) Combined mixing granite**: bug cũ hard-code file old = llama → số
  đầu tiên n=100, rate 0.52→0.90. Fix: `combined_old_sources_by_slug` +
  assert `old_mid == mid` trong `compute_extension_metrics`; test
  `test_verdict_bias_extension_metrics` assert RÕ file old của model KHÁC
  không được merge. Số bug không còn tồn tại ở bất kỳ file nào.
- **(b) Model-blind sha-gate (qwen)**: gốc rễ thật — sha-gate chỉ soi prompt.
  Fix: `resolve_reuse_specs` + `_reuse_model_id` (disable reuse khi model_id
  file nguồn ≠ model chạy) + test
  `test_reuse_specs_disabled_on_model_mismatch`. Rerun: 180/180 cache-hit,
  0 gen mới, 0 record reused; file polluté cách ly; V2 xác nhận 0 contamination
  còn sót trong llama ablation (120/120) và C5_far (30/30).

### CHECK 8 — Budget (PASS với 1 footnote bắt buộc)
- Đếm từ cache stats: llama ablation 398 calls − 73 hits = **325**; llama
  extend +160 calls − 0 hit mới = **160** (queue driver chia 1 RealLLM giữa
  2 job cùng model — giải thích counter 558 tích lũy); granite **160**
  (160−0); C5_far **58** (60−2); qwen rerun **0** (180−180). Tổng
  **703** — khớp report.
- **Nhưng**: qwen run 1 (polluté, bị loại) đã đốt **131 gen thật** (150
  calls − 19 hits). Tổng generation GPU của vòng 6 = 703 + 131 = **834**;
  703 chỉ đúng cho "gen nằm trong file cuối". Đã disclose run polluté nhưng
  headline budget cần footnote này (queue.log line 1618 là nguồn).

### CHECK 9 — pytest (PASS)
`pytest tests/ -q` = **443 passed, 0 failed** (khớp claim A2; 15 test mới
trong test_round6_ablation.py phủ: rung-isolation byte tests, subset
identity, sha-gate reuse + model-mismatch guard, metrics, complement, dry
e2e + resume).

### CHECK 10 — Raw spot (PASS)
5 cặp raw A5-vs-A1 cùng sample (195083, 195233, 195237, 195261, 195296):
raw trên disk == `meta.text` 100%; khác biệt prompt duy nhất giữa A1 và A5
đã chứng minh ở CHECK 1 là system reassertion; flips quan sát được thật
(2/5 sample sụp đúng ở A5).

---

## I. ISSUES (không material — đều phải xử lý trước camera-ready)

1. **[MINOR] Nhãn "McNemar exact" (prereg §2) ≠ phép tính cho discordant
   lớn.** `src/metrics/stats.py::mcnemar` auto: exact khi discordant < 25,
   ngược lại χ² hiệu chỉnh liên tục. Đúng các p nóng: A5vsA4 p=3.35e-07 là
   **χ²-cc** (exact thuần = 7.45e-09), A5vsA0 1.5e-08 cũng là χ²-cc (exact =
   1.16e-10). Sai lệch theo hướng BẢO THỦ (p tự DoF lớn hơn exact) nên
   không đổi verdict nào; nhưng paper phải ghi đúng phương pháp
   ("exact binomial for discordant <25, continuity-corrected χ² otherwise")
   thay vì "exact" chung.
2. **[MINOR] Budget 703 thiếu 131 gen của qwen run polluté** (tổng thật
   vòng 6 = 834) — sửa câu chữ thành "703 generations trong các file cuối;
   +131 generation của run qwen bị loại (§2.3)".
3. **[MINOR] 1 vul sample (211155) unparsed (y_pred=None) ở A3 và A4** →
   các bậc A3/A4 chạy trên 59 pairs chứ không phải 60 (A2 report không nhắn
   rõ; số trong file có `n_vul_parsed=59`). Không đổi kết luận; bảng paper
   nên ghi n parsed theo từng bậc.
4. **[NIT] Config spot_check ghi qwen A5 "reuses ... (49/60 samples
   completed in round 5)"** — thực ra 49 = tổng records qwen P3 C5_near
   (30 vul + 19 benign); chỉ 30/60 vul của subset có candidate. Guard sau đó
   DISABLE reuse hoàn toàn (chống cross-model) nên file cuối 0 reused, số
   không bị ảnh hưởng. Sửa chữ cho đúng nếu config được trích trong paper.
5. **[NIT] "82% tổng harm" phải được viết dưới dạng share-of-net-flips kèm
   điều kiện A0 saturated** (xem CHECK 4); cấm diễn đạt thành phân rã cộng
   -dồn theo thành phần.

## II. CONFIRMED BUGS (cả hai do chính A2 bắt, V2 xác nhận thật + fix có test)
1. Cross-model reuse contamination (qwen spot run 1 dùng 30 record P3 của
   llama do sha-gate model-blind) — chứng minh độc lập: file polluté 30/30
   trùng y_pred với llama-P3, 19/30 lệch với qwen-P3. Fix + test + quarantine
   + rerun sạch (0 gen mới). **ĐÃ ĐÓNG.**
2. `compute_extension_metrics` ghép nhầm file old chéo model (granite) — số
   n=100 đầu tiên vô hiệu, không còn trong file nào; fix per-model + assert
   + test regression. **ĐÃ ĐÓNG.**

## III. FALSE CLAIMS
**Không tìm thấy claim sai nào** trong phạm vi audit (số, prompt-identity,
reuse, subset, budget-headline có caveat ở Issue 2 nhưng không phải bịa).
Các claim rủi ro nhất đều SURVIVE kiểm tra độc lập:
- "A5 == P3 Vòng 5 byte-identical": ĐÚNG (90/90 re-render + 30/30 sha-gate
  + 180/180 cache-hit qwen).
- "Mỗi rung thêm đúng 1 component": ĐÚNG (diff 90/90 sample × 5 rung).
- "qwen 0/60 flips / vô hại": ĐÚNG trên file sạch (0/0 vul flips; benign 1).
- "C5_far replicate": ĐÚNG (0.390, 36/59).
- "Granite verdict-bias 0.043→0.714, p≈2e-11": ĐÚNG (n=70, không trộn model).

## IV. AI SAI / AI BẮT ĐƯỢC
- **A2 sai (tự bắt, tự sửa, disclose đúng)**: 2 bug ở §II — nhiễm chéo
  qwen/llama qua reuse và trộn model trong combined metrics; cả hai có thể
  đã cho ra conclusion giả (qwen "0/60" sẽ là giả, granite combined sẽ là
  số trộn model). Cách xử lý (quarantine + rerun cache-hit 0 gen + test
  chặn regression) là chuẩn.
- **V2 bắt được**: (1) nhãn "McNemar exact" không khớp phép tính ở các bậc
  discordant ≥25 (hướng bảo thủ, không đổi verdict); (2) budget 703 thiếu
  131 gen của run polluté; (3) bẫy "benign set == round5_defense" phải đọc
  ở cấp selection (records llama round5_defense là vul-only) — claim vẫn
  đúng nhưng cần ghi rõ; (4) sample 211155 unparsed làm vài bậc chạy 59
  pairs; (5) lệch 5 phút timestamp Amendment-1 trong prereg doc.
- **Không ai sai**: rung isolation, byte-identity A5==P3, toàn bộ số ladder
  + extension, quarantine, pre-reg timing (sha-chain).

## V. ĐÁNH GIÁ CLAIM LỚN
1. **Reassertion-attribution: VỮNG.** Đây là rung-isolation sạch nhất có thể
   ở mức prompt: 5 rung × 90 sample diff cho thấy mỗi bậc đúng 1 thay đổi,
   bậc cuối chỉ khác system reassertion (user byte-identical), và rung cuối
   byte-identical với P3 đã chạy Vòng 5. Flip 28/0 (p ≤ 3.35e-07) tại đúng
   bậc đó, replicate trên C5_far (36/59), là bằng chứng đủ để paper viết
   "the system reassertion carries the bulk of the harm on Llama-3.2-3B".
   Giới hạn phải giữ nguyên văn trong paper: cumulative ladder không tách
   tương tác; n=60/30, 1 model chính; B0 llama saturated (harm = kéo verdict
   về benign trên model over-trigger); C0×P3 control vẫn chưa chạy (không
   kết luận được "chỉ harmful khi có advisory").
2. **Minimal-provenance-safe (A1): VỮNG nhưng scope hẹp.** 1/60 flip,
   recall 0.983 ≥ 0.95 ngưỡng H-M2, qwen spot A1 cũng 1.000. Câu đúng cho
   paper: "boundary labeling alone did not reproduce the harm". KHÔNG được
   nâng thành "boundary labeling is safe" chung chung — chưa có benign-side
   utility/CUL đo với control C0×defense, và n=30 benign.
3. **"82% tổng harm": ĐÚNG SỐ, CẦN DIỄN ĐẠT LẠI.** Giữ công thức
   "28 of the 34 net verdict flips (B0→P3-full) appeared at the reassertion
   step" + caveat rằng tính chia này dựa trên B0 recall = 1.0 (saturated) và
   không phải phân rã cộng-dồn (ladder có 3 flips hồi phục ở A4). Tránh mọi
   câu kiểu "components contribute harm additively with reassertion at 82%".
4. **Qwen immune: VỮNG trên dữ liệu sạch** (0/60 vul flips; 1 benign flip)
   — nhưng phải nói là "inert at 3B scale on this bench, saturated baseline"
   (qwen FP=recall=1.0 sẵn), không phải "robust".
5. **Extension combined (llama n=100 p=1.53e-05; granite n=70 p=2e-11)**:
   ĐÚNG và không double-count (overlap 0, per-model source có assert + test).
   Granite vẫn thiếu 30+30 để full-100 — gap đã disclose, giữ nguyên khi
   trích.

---
*Verification của V2 (lệnh đã chạy thật): render/diff prompt bằng
`src.experiments.round6_ablation.prompt_for` + `difflib` trên 90 sample;
re-render P3 round5 bằng `p3_boundary.apply`+`round5_defense.p3_prompt` với
`configs/round5_defense.yaml`; đếm lại toàn bộ metrics/flips/McNemar bằng
scipy trực tiếp từ records; reconstruct config-sha; audit 120+30 reused và
file quarantine; đếm raw/980 file + 5 cặp raw so `meta.text`; pytest tests/
-q = 443 passed. KHÔNG tạo file ngoài reports/round6/V2_report.md và /tmp;
KHÔNG sửa code; KHÔNG git commit.*
