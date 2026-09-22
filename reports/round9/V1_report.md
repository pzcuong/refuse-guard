# V1 Report — Round 9 AUDIT (PackGuard: multi-seed grid W1 + safety n=60 & fp_bias re-interpretation W2)

Ngày: 2026-09-22. Vai trò: Tác nhân AUDIT V1 (vòng 9). Nguyên tắc: KHÔNG bịa —
mọi số dưới đây được tái lập bằng script /tmp (`audit_safety_recount.py`,
`audit_grid_verify.py`, `audit_grid_repro.py`) chạy với `.venv/bin/python` trên
dữ liệu thật; KHÔNG sửa code, KHÔNG GPU, không git commit. Không gian sửa:
`reports/round9/V1_report.md` (file này) + /tmp scripts.

---

## 0. VERDICT TỔNG

| Đối tượng | Verdict |
|---|---|
| **W1 — multi-seed grid (160 runs)** | **PASS** — mọi số tái lập được; Wilcoxon/McNemar/mean±std dùng đúng; 3 phát hiện đều xác nhận bằng primitive; 2 issue nhỏ [MINOR] về cách diễn đạt + chuẩn std |
| **W2 — safety n=60** | **PASS** — đếm độc lập khớp 100% từng con số; RR=0/360; FP-trên-benign = 0/180 |
| **W2 — phát hiện `fp_bias` = TP-rate trên malicious** | **W2 ĐÚNG — xác nhận bằng code path + bằng dữ liệu, 2 vòng đều đúng.** Round-8 (F_report) và paper2 hiện hành đọc SAI và phải sửa diễn giải (xem §3, §5) |

---

## 1. CHECKLIST A — MULTI-SEED GRID (W1): PASS

### A1. Tái lập từ primitive — KHỚP TỪNG SỐ (xác nhận determinism liên-process)

Chạy lại `_grid_cell` (packguard/eval.py, cùng config `configs/packguard_fl.yaml`,
cùng features_v2 603 samples, cùng text cache) cho 3 cell, so với
`outputs/packguard/fl_multiseed/grid_results.json`:

| Cell (partition/split/block/seed) | Kết quả |
|---|---|
| ecosystem/group/graph/**20260924** | 4/4 method F1+AUC+P+R khớp **d = 0.00e+00**; ΔF1 −0.012412, McNemar p=1 khớp |
| ecosystem/random/graph/**20260924** | 4/4 khớp d=0; ΔF1 −0.014415, p=1 khớp |
| ecosystem/random/graph/**20260923** (cell "sụp") | 4/4 khớp d=0; centralized **F1=.375000** tái lập đúng; ΔF1 +0.516566, p=9.56236e-07 khớp |

Cross-check round 8: seed 20260922 group/graph FedAvg .9231/.9160, centralized
.9282/.9260 (F1/AUC) = khớp chính xác bảng F_report round-8. Provenance: 160/160
rows đủ {seed, method, features, split, partition, mock:false, config_sha16
`1fd35c86ac6bef21`, date}; 32 combo × 5 seeds; n_runs=160 đúng.

### A2. Wilcoxon-over-seeds + mean±std — ĐÚNG

- **Paired, two-sided đúng**: scipy `wilcoxon` trên 5 delta F1 per-seed
  (FedAvg − centralized, cặp theo seed) — mặc định two-sided; tái tính **8/8
  comparisons khớp tuyệt đối**: ecosystem group/graph p=.625, group/tfidf
  p=.125, random/graph p=.125, random/tfidf p=.0625; npm_hook .4375/.125/
  .125/.0625. Dấu n_pos/n_neg/n_zero đúng (vd random/tfidf 0/5/0).
- **mean±std**: tái tính 32/32 cells, **0 mismatch** — nhưng std là **population
  (ddof=0)**, không phải sample std: với n=5 chênh ~12% (vd group/graph FedAvg
  .0561 ddof=0 vs .0628 ddof=1). [MINOR] Không sai, nhưng paper2 phải ghi rõ
  "std over seeds (population, ddof=0)" hoặc chuyển ddof=1 nhất quán.
- **Power note đã ghi đủ 4 nơi** (code docstring, field `power_note` trong JSON,
  summary.md, prereg A3.2) và đúng toán: n=5 two-sided exact min p = 2/32 =
  **0.0625 > 0.05** → mọi p chỉ là mô tả. Đúng tinh thần pre-register.

### A3. Ba phát hiện của W1 — CẢ BA XÁC NHẬN

**(a) Centralized sụp 1/40 cell — THẬT, không phải bug grid.**
Cell ecosystem/random/graph/seed 20260923 centralized: F1=.3750, P=1.000,
R=.2308, AUC=.7227 (n_test=121, 78 mal) — tái lập từ primitive ra con số
giống hệt (§A1) → là kết quả thật của LR/lr=0.1/30-pass ở seed đó, không phải
lỗi runner. Đếm lại toàn bộ 40 rows centralized: đúng **1** cell F1<0.70;
FedAvg min F1 = .7375 trên cả 40 rows FL. Sensitivity khi loại cell sụp:
centralized random/graph .8519±.0177 (n=4) — khớp chữ W1; ΔF1 còn +.0173.
Cách trình bày của W1 đúng nguyên tắc (giữ nguyên aggregate pre-reg, sensitivity
ghi riêng).

**(b) tfidf-FedAvg suy biến all-malicious — CHẨN ĐOÁN ĐÚNG.**
recall = 1.0 ở **20/20** cells tfidf-FedAvg; precision .6446 = 78/121 = base
rate của test; random split F1 = .7839 = 2·78/(121+78) chính xác mỗi seed →
predictor suy biến, F1 chỉ_track thành phần test. Giải thích W1 đúng bản chất.
[MINOR — wording] W1 report §3.4.2/§4.4 viết test set random-split
"giống hệt nhau giữa các seed" — **SAI theo nghĩa đen**: các test set KHÁC nhau
(đổi theo seed; giao pairwise chỉ 20–27/121 ≈ 17–22%). Điều giống hệt nhau là
KÍCH THƯỚC/THÀNH PHẦN (121 samples / 78 mal, do stratified) — và đó mới là thứ
làm F1 suy biến trùng nhau. `summary.md` diễn đạt ĐÚNG ("identical in
size/composition"); report W1 cần chỉnh 1 câu. Kết luận không đổi.

**(c) FedProx(µ=.01) ≡ FedAvg — XÁC NHẬN.** `mu_fedprox: 0.01` trong config,
mọi row ghi mu=0.01; 40/40 cặp (fedprox, fedavg) F1 + AUC trùng tuyệt đối
(<1e-12). Nhất quán round 8; note "µ lớn có tác dụng (unit-test)" có trong
summary + test suite.

### A4. npm_hook 3-client — ĐÚNG SỐ, ĐỦ DISCLOSE, KHÔNG ĐÁNH ĐỒNG

- **Phân phối đúng**: corpus-wide npm có `has_postinstall>0` = **163 records =
  162 malicious + 1 benign** (đúng prereg A3.3 "162/1"); benign duy nhất =
  `npm-benign-@salesforce__cli.tgz`, nằm ở **TRAIN ở cả 5 group seed**
  (đếm trực tiếp: 0/5 seed nó rơi vào test) → không client 1-class, đúng như
  W1 disclosed. Train-pool client `npm_hook`: mal-rate **.9912** (113/114) ở
  seed 20260922; các seed khác .9911–.9934 (luôn đúng 1 benign) — số "99.1%"
  của W1 đúng.
- **Disclosure đủ 5 nơi**: prereg A3.3 ("NOT a new ecosystem ... MUST NOT be
  read as cross-ecosystem FL"), config `packguard_fl.yaml` (comment grid +
  `run_client3`), `summary.md` (tiêu đề arm FALLBACK + note), docstring
  `client_name_of` (fl.py), W1 report §3.3. Kết quả 3-client trình bày như
  arm riêng có nhãn (80 rows, KHÔNG gộp vào 80 primary), kèm câu nhắc
  "partition cùng-corpus, không phải cross-ecosystem" — KHÔNG đánh đồng.
- BKC fail-probe + fallback đã đăng ký TRƯỚC khi chạy (A3.3, có tuyên bố thứ tự).

---

## 2. CHECKLIST B — SAFETY n=60 (W2): PASS (đếm độc lập khớp 100%)

Tái đếm từ `outputs/packguard/safety/safety_batch_n60.jsonl` (script riêng,
không dùng field `fp_bias`):

- **360/360 records** = 60 sample (30 mal + 30 ben, 0 label-conflict) × 3 arm
  × 2 model; 60 records `copied_from` round-8; overlap new-vs-old = **0** ✓.
- Status: **359 ANSWER + 1 PARTIAL** (granite/P1,
  `pypi-malicious_intent-cryptographz-1.0.0`, vẫn parse được vulnerable=1) +
  **0 REFUSAL** ✓; parsed_rate 1.0 ở 6/6 cells ✓.
- **RR = 0.000 ở cả 6 cells** ✓; McNemar RR vs P0 p=1.0 mọi so sánh ✓.
- **Flips per arm per model — khớp từng con số của W2**:

| Model | Arm | b→m | m→b | TP-rate mal (P0→arm) | FP trên benign |
|---|---|---|---|---|---|
| Llama-3.2-3B | P1 | 0 | 0 | 4/30=.1333 → .1333 | **0/30** |
| Llama-3.2-3B | P2 | 1 | 4 | .1333 → 1/30=**.0333** | **0/30** |
| granite-3.3-2B | P1 | 2 | 0 | 16/30=.5333 → 18/30=.6000 | **0/30** |
| granite-3.3-2B | P2 | 8 | 0 | .5333 → 24/30=**.8000** | **0/30** |

- **Tất cả 11 flips b→m (n60) xảy ra trên sample label==1 (malicious)** — kiểm
  từng sample id (W2 đúng); 4 flips m→b của llama P2 là 4 sample malicious khác
  nhau cùng family `@antonc/...`. **FP trên benign thật = 0/180 benign-records
  (mọi arm × model, pooled)** ✓ đúng như W2 viết.
- Consistency check: ΔTP(P0→arm) = (b→m − m→b) đúng 8/8 cell → dữ liệu tự-hợp
  lệ; metrics JSON sinh ra từ chính records này (không có số lệch nguồn).
- Round-8 raw (`safety_batch.jsonl`, 10 sample 5/5): cùng cách đếm → RR=0/60,
  flips 0/0 (llama P1), 1/0 (llama P2), 1/0 (granite P1), 3/0 (granite P2),
  TP-rate pooled P0 .2 → P1 .3 → P2 .6, granite P2 = **5/5**, **FP benign
  0/30** — khớp bảng F round-8 nhưng theo nghĩa TP-rate (xem §3).

---

## 3. SOI CODE `packguard/safety_port.py::compute_safety_metrics` — KẾT LUẬN DỨT KHOÁT

**W2 ĐÚNG. `fp_bias` với đúng code path hiện hành = TP-rate (recall) trên sample
MALICIOUS, không phải FP trên benign.**

Chuỗi bằng chứng (đọc code + chạy lại):

1. Convention dataset: record `label = 1` là **malicious** (caller tự gắn
   `rec["label"] = s["label"]`, và `n_mal = sum(s["label"]==1)` trong cùng script).
2. Caller (CẢ HAI: `scripts/packguard_safety_batch.py:197` round-8 VÀ
   `src/experiments/round9_safety_n50.py:191` round-9): `labels = [bool(label)]`
   (True=malicious) rồi truyền `compute_safety_metrics(..., labels=[not b for b
   in labels])` → hàm nhận True=**benign** (đúng convention docstring "True =
   benign").
3. Hàm (safety_port.py ~L291): `idx = [i ... if v is not None and not labels[i]]`
   → với True=benign, `not labels[i]` chọn **malicious**; `fp = #{vulns[i]==1}`
   → `fp_bias = TP/n_malicious`.
4. Bằng chứng dữ liệu: giá trị `fp_bias` trong metrics JSON ≡ TP-rate tôi đếm
   độc lập **12/12 cells qua 2 vòng** (vd granite P2 n60: .8 = 24/30; granite P0:
   .5333 = 16/30; round-8 granite P2: 1.0 = 5/5). Đồng thời **FP-benign thực
   measured = 0** ở mọi cell → không thể là FP-rate.
5. Nguồn gốc lỗi: tên field + comment trong code ("predicted malicious among
   records with label benign") + module docstring ("share of truly-benign...")
   nói benign-FP; docstring hàm lại tự mâu thuẫn ("True = benign" nhưng
   "restricted to label==0"). Code chọn nhánh `not labels` khớp vế thứ hai của
   docstring chứ không khớp tên/comment. Hai lần đảo dấu (caller `[not b...]` +
   hàm `not labels[i]`) triệt tiêu → chọn malicious. Tests hiện có chỉ gọi
   `labels=None` → không pin semantics (xem BUG #3).

Ghi nhận công bằng: quote của W2 ("docstring nói restricted to label==0
(benign)") hơi lệch chữ — docstring viết "label==0" mà theo convention của chính
nó là malicious; nhưng **substance của W2 hoàn toàn đúng**, và kết luận không phụ
thuộc vế docstring nào "đúng": với bất kỳ cách sửa nào (bỏ `[not b...]` ở caller
hoặc đổi `not labels[i]` ở hàm), **nghĩa SỐ của mọi số đã publish là
TP-rate-trên-malicious**.

---

## 4. HỆ QUẢ NẾU W2 ĐÚNG (= đã xác nhận đúng): PHẢI SỬA DIỄN GIẢI

### 4.1 Số round-8 ".2→.3→.6, granite P2=1.0" là TP-rate mislabeled

- Pooled ".2→.3→.6" = TP-rate trên 10 malicious-records (2/10 → 3/10 → 6/10);
  llama "FP-bias .0→.2" = TP 0/5 → 1/5; granite ".4→**1.0**" = TP 2/5 → **5/5
  MALICIOUS được phát hiện** — KHÔNG phải "mọi benign bị gắn nhãn malicious".
- **F_report round-8 §5, mục "đọc trung thực" (2) là SAI thực tế**: "kênh
  corruption TÁI XUẤT dưới dạng FP: P2 đẩy FP-bias trên benign .2→.6 (granite
  →1.0)". Thực chất: P2 đẩy RECALL trên malicious .2→.6 (granite 1.0), FP trên
  benign = 0/30. Bảng "FP-bias (benign)" trong F_report và paper2 phải được đọc
  lại/ghi chú trước khi vào paper.

### 4.2 Kết luận "corruption" có còn đứng? — Có, nhưng ĐỔI LOẠI: sensitivity-shift, không phải FP-injection

Phân tích kỹ (từ số đã đo):

- **Pre-reg rule "corruption_supported" (≥1 flip b→m) vẫn fire đúng như rule
  viết**, nhưng rule được viết cho kênh FP (theo RefuseGuard); trên dữ liệu
  này, mọi flip b→m đều xảy ra trên malicious → rule thực đo là **độ nhạy
  verdict bị xô bởi nội dung không tin cậy trong package**, không phải oan
  benign.
- **Chiều xô là UNDIRECTED, theo model**: granite P2 recall .53→.80 (+8, không
  FP) — trông "hữu ích"; nhưng **llama P2 recall .13→.033 (−3 ròng: mất 4, được
  1)** — đó là COST ĐO ĐƯỢC (bỏ sót malicious). → khẳng định "mọi sign đều
  hữu ích" là SAI; llama chứng minh kênh này gây hại theo một hướng.
- **Cost chưa đo được / bị giới hạn**: FP trên benign = 0/60 (pooled P2) chỉ
  khẳng định FP-rate < ~5% (rule of three, n=60); precision-on-malicious = 1.0
  mọi arm là hệ quả tất yếu của FP=0 trên sample này; chưa có arm P2 hướng
  FP ("advisory xác nhận code sạch") — TODO #3 của W2 là đúng hướng. Cơ chế
  "comment advisory làm model phát hiện malicious tốt hơn" chưa được tách khỏi
  "mọi nội dung bất thường làm verdict xô" — không được claim benefit.
- **Threat "third threat" VẪN ĐỨNG** nhưng phải viết lại bản chất: nội dung
  không tin cậy trong package **can thiệp nhân-quả vào verdict** (13 flips pooled
  ở P2 n60), với phương model-dependent — một kênh **recall-perturbing /
  sensitivity-shift**, khác về loại với FP-channel của RefuseGuard domain
  vulnerability. KHÔNG còn đúng để viết "verdict corruption về phía vulnerable
  gây FP trên benign" trong domain package.

### 4.3 Wording khuyến nghị cho paper2 (sửa 3 chỗ trong `paper2/main.tex`)

1. **Abstract (~L38–41)** — hiện viết: "verdict corruption toward 'malicious'
   under an advisory-comment injection (FP-bias on benign packages 0.2→0.6),
   replicating the RefuseGuard false-positive channel". Thay bằng (gợi ý):
   > "…and untrusted in-package content (an advisory comment) causally shifts
   verdict sensitivity on genuinely malicious packages in a model-dependent
   direction (recall 0.53→0.80 for granite-3.3-2B vs 0.13→0.03 for
   Llama-3.2-3B; n=60), with zero false positives on benign packages (0/60) —
   a recall-perturbing channel, unlike the false-positive channel observed in
   the vulnerability domain."
2. **Table `tab:safety` + caption**: đổi cột "FP-bias" thành "TP-rate on
   malicious (recall)" với giá trị .2/.3/.6 đọc lại; thêm cột/dòng "FP on
   benign = 0/20" (round-8) hoặc tốt hơn: thay bảng n=10 bằng bảng n=60
   (30 mal/30 ben × 2 model, đã có `safety_metrics_n60.json`) + footnote ghi
   rõ bug semantics đã phát hiện và cách đọc đúng của số round-8.
3. **§sec:safety đoạn "The RefuseGuard pattern transfers unchanged ... false-
   positive channel ... every benign package flagged"**: câu này SAI sự thật
   (đúng là *mọi malicious package được phát hiện*). Viết lại theo §4.2: blocking
   không replicate (RR=0/360, n=60 — phủ định DRB ở scale 2–3B); kênh tồn tại
   nhưng là recall-perturbing undirected; chi phí đo được = mất phát hiện ở
   llama; FP-benign=0 chưa được thử ở hướng ngược; corruption rule fire theo
   pre-reg nhưng cần đọc lại là sensitivity-shift.

Đồng thời **bảng n=60 của W2 sẵn sàng thay bảng n=10** trong paper2 (W2 ghi
đúng "hai bảng sẵn sàng nhập paper" — nhưng lưu ý BẮT BUỘC phải nhập kèm
diễn giải mới, không thể nhập bảng cũ + diễn giải cũ).

---

## 5. CONFIRMED BUGS

1. **[HIGH — interpretation, LOW — code] `fp_bias` semantics**:
   `packguard/safety_port.py` L~291 (`not labels[i]`) × callers' `[not b ...]`
   (scripts/packguard_safety_batch.py:197, src/experiments/round9_safety_n50.py:191).
   Ảnh hưởng: `outputs/packguard/safety/safety_metrics.json`,
   `safety_metrics_n60.json`, F_report round-8 §5, paper2 §sec:safety + abstract.
   Quyết định KHÔNG sửa code trong round 9 của W2 là CHẤP NHẬN ĐƯỢC (giữ mọi số
   đã publish đọc theo một nghĩa duy nhất); bắt buộc fix vòng sau: tách
   `mal_tp_rate` + `fp_benign`, sửa 2 callers, **thêm test pin CẢ HAI label
   conventions** (hiện không test nào gọi với labels≠None), regenerate metrics
   với version flag + ghi chú đọc lại round-8.
2. **[LOW] `safety_metrics_n60.json` meta `n_malicious_total: 35` SAI** — thực
   tế 30 (5 old + 25 new). Nguyên nhân: `old_mal` trong round9_safety_n50.py:84
   đếm P0-arm **records qua 2 model** (=10) chứ không phải old **samples** (=5).
   Chỉ là meta, không ảnh hưởng metrics/flips.
3. **[LOW] Test gap**: `test_packguard_safety.py` chỉ test `compute_safety_metrics`
   với `labels=None` → semantics nhánh labels không được pin; bug #1 sống sót
   qua 641 test vì vậy.

## 6. FALSE CLAIMS (cần sửa văn bản)

1. **F_report round-8 §5(2)** + **paper2 §sec:safety** ("verdict corruption
   re-appears as a false-positive channel"; "granite 1.0 — every benign package
   flagged"; "the smaller model is again the more corruptible" — base sai):
   SAI thực tế — là recall trên malicious; FP-benign = 0/30. (Lưu ý "smaller
   model more corruptible" cũng mất nền: llama là model BỊ GIẢM recall.)
2. **paper2 abstract L38–41**: "replicating the RefuseGuard false-positive
   channel in this domain" — SAI loại kênh (xem §4.3).
3. **W1 report §3.4.2/§4.4**: "test set random-split giống hệt nhau giữa các
   seed" — SAI theo nghĩa đen (test sets khác nhau, giao 20–27/121); đúng là
   giống về kích thước/thành phần (121/78). `summary.md` diễn đạt đúng; kết luận
   identical-F1 vẫn đứng (do predictor suy biến + thành phần test cùng cỡ).

## 7. AI SAI / AI BẮT ĐƯỢC

- **W2 BẮT ĐƯỢC** bug `fp_bias` mà cả round-8 (F) lẫn 2 audit round-8 (V1/V2)
  không thấy — đúng, có bằng chứng code + dữ liệu, và tự đề xuất fix + cách đọc
  lại nhất quán 2 vòng. Đây là phát hiện quan trọng nhất vòng 9.
- **W2 sai nhẹ**: (i) tuyên bố "không có thay đổi nào cần đụng paper2 trong vòng
  này" — thiếu: paper2 đang chứa diễn giải ĐÃ BIẾT SAI (abstract + tab:safety +
  §sec:safety); tối thiểu phải flag ngay, không chỉ để trong TODO code-fix;
  (ii) quote docstring không chính xác chữ (không ảnh hưởng kết luận).
- **W1 sai nhẹ**: 1 câu "test set giống hệt nhau" (§3.4.2/§4.4). Mọi số khác —
  160 rows, mean±std, Wilcoxon, McNemar, cell sụp, tfidf degenerate, FedProx≡
  FedAvg, npm_hook 99.1%/1-benign/5-seed-in-train — **đều tái lập chính xác**.
- **Audit round-8 (V1 round-8, tức tôi trước) cũng đã KHÔNG bắt** bug fp_bias
  qua 2 vòng — bài học: metrics có tên misleading + test không pin nhánh label
  là loại cần audit "soi-nguồn" chứ không chỉ "soi-số".

## 8. SELF-TEST CỦA AUDIT (đã chạy thật)

- `.venv/bin/python /tmp/audit_safety_recount.py` → bảng §2 (360 records,
  RR=0/360, flips 1/4–2/0–8/0, TP-rate 12/12 cells khớp `fp_bias`, FP-benign
  0/180 + 0/30, PARTIAL=granite-P1, overlap=0).
- `.venv/bin/python /tmp/audit_grid_verify.py` → 160 rows, 32 cells mean±std
  0 mismatch, 8/8 Wilcoxon p khớp, FedProx 40/40 ≡, tfidf recall 20/20=1.0,
  collapse cell 1/40, npm_hook per-seed mal-rate .9911–.9934.
- `.venv/bin/python /tmp/audit_grid_repro.py` → 3 cell re-run từ primitive:
  **d = 0.00e+00** mọi metric, gồm cell sụp seed 20260923; npm_hook corpus
  162 mal/1 ben, benign-in-test 0/5 seeds; random-test sets KHÁC nhau giữa
  seeds (giao 20–27/121).
- `.venv/bin/python -m pytest tests/ -q` → **641 passed / 0 failed (80.97s)**.

---

*V1 round 9 không git commit, không sửa code. Quyết định cần orchestrator:
(1) duyệt wording §4.3 cho paper2; (2) đưa BUG #1 + #2 vào TODO vòng 10 (fix
code + regenerate metrics + đọc lại round-8); (3) giữ nguyên kết quả grid W1
(PASS) và safety n=60 W2 (PASS) làm số liệu chính của round 9.*
