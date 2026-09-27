# V1 Report — Round 15 (AUDIT ADVERSARIAL W1: MalGuard/Amalfi-style 41-feature baseline, 320 runs)

Ngày audit: 2026-09-28. Đối tượng: `reports/round15/W1_report.md` +
`packguard/malguard_style.py` + `outputs/packguard/malguard_style/*` +
AMENDMENT-8 (`docs/packguard_prereg.md`) + `tests/test_packguard_malguard.py`.
Phạm vi sửa: chỉ file này + /tmp scripts. Không đụng code W1, không git commit.

**VERDICT W1: PASS (kèm ISSUES mức MINOR — 2 lỗi đếm trong prose + 1 timestamp
stale; KHÔNG ảnh hưởng kết luận registered, KHÔNG có confirmed bug, KHÔNG có
label leak, KHÔNG có feature trùng/collinear hoàn toàn).** 4 claim bị soi đều
CONFIRMED bởi tái lập độc lập (xem §1–§7).

## 0. TÓM TẮT 4 CLAIM TRỌNG TÂM

| # | Claim W1 | Kết quả audit | Bằng chứng độc lập của V1 |
|---|---|---|---|
| 1 | graph thắng malguard-style: ΔF1 −.0216, raw p=.044, KHÔNG sống Holm (.308) | **CONFIRMED** | Tái tính từ `aggregate.json` (20 deltas): mean −.02162, CI90 t₁₉ [−.0407, −.0025] (khớp 1e-9), Wilcoxon exact p=.04410, Holm-8 = .30841. 0/8 family sống Holm |
| 2 | combined graph+malguard +.0150 n.s. | **CONFIRMED** | mean +.01504, CI90 [+.0016, +.0285], p=.10538, Holm .48653 — n.s. đúng |
| 3 | 0/8 TOST PASS ±.02 | **CONFIRMED, logic ĐÚNG** | Rule = CI90 t(n−1) nằm trọn trong (−.02,+.02) (`packguard/eval.py:tost_equivalence`, strict inequality); 8/8 FAIL đúng thực tế; Holm step-down monotone đúng; McNemar exact<25/chi2-cc đúng rule round-8 |
| 4 | feature label-blind + không trùng 18 graph features | **CONFIRMED** | (a)签名 `extract_sample_features(graph, text, kb)` không có label; graphs_v2 rows KHÔNG mang field label (603 rows, keys kiểm tra toàn bộ); text_v2 = sample_id→text thuần; features_malguard.jsonl không chứa substring "label". (b) ma trận corr 41×18 trên 603 samples: max |r| = .8576, 0/738 pair |r|>.95, không feature nào R²>.95 khi hồi quy tuyến tính từ 18 graph features (max R²=.8511) |

## 1. CHECK-1 NO-LABEL-LEAK — PASS (test injection của W1 đủ; V1 tự chạy permutation 20 lần)

- Bề mặt leak quét toàn bộ: `graphs_v2.jsonl.gz` (603 rows) chỉ có keys
  {sample_id, ecosystem, nodes, edges, files, imports, classes, n_*, parse_*,
  schema_version, scopes} — **0 row chứa label/malicious/y/class**; node keys
  {api, cls, id}; file keys {file, entry_kind, language, n_nodes, n_edges,
  parse_ok}. `text_v2.json` = dict 603 sample_id → text thuần. Lộ trình label
  duy nhất vào trainer là `r["label"]` của features_v2 (đúng thiết kế, chỉ dùng
  làm y). `sample_id` CÓ chứa chuỗi "malicious_intent" nhưng KHÔNG bao giờ vào
  feature (extractor không nhận sample_id; features_malguard.jsonl chỉ có
  sample_id + 41 số).
- Test injection của W1 (`test_no_label_leak_label_fields_ignored`) đủ: signature
  + inject `label`/`malicious`/`label_source` → feature bất biến. V1 công nhận.
- **Kiểm chứng độc lập (V1, /tmp/v1audit/perm_test2.py): permutation label
  package-level × 20 lần** (giữ nguyên cấu trúc group — permutation mẫu-level
  bị assert chống-leak của `make_group_split` chặn đúng, tức corpus thật không
  có package trộn label). Kết quả dưới label ngẫu nhiên: F1 malguard
  .5525 [.4000, .6455], F1 graph .5806 [.4138, .7891] — **cả 2 block rơi về
  chance, không block nào còn gần .88** ⇒ không có kênh nào đưa label vào
  feature. Null ΔF1(central) = −.0281 ± .1205 [−.2584, +.1925]; ΔF1 quan sát
  −.0216 nằm sâu trong null (16/20 perms có |null|≥|obs|, perm p 2 phía = .810)
  ⇒ **không có leak, và −.0216 không phải tín hiệu ổn định bất thường**.
- Ghi chú: sd của null (.12) lớn hơn sd seed-level quan sát (.048) vì dưới
  permutation F1 ở mức chance nên nhạy noise test-set (~130 mẫu); hai checks
  đúng đắn là (i) F1 sập về chance và (ii) ΔF1 quan sát không outlier — cả hai
  đều PASS.

## 2. CHECK-2 FEATURE OVERLAP — PASS ("disjoint" đúng ở mức tên + không collinear hoàn toàn)

- Tên: 18 graph (`packguard.features.FEATURE_NAMES`) và 41 malguard rời rạc
  100% (union = 59 = input_dim combined trong mọi row — verified 80/80 row).
- Giá trị (603 samples, Pearson): **max |r(41×18)| = .8576**
  (pair_DATA_ACCESS__DYNAMIC_CODE vs hist_DATA_ACCESS); 0/738 pair |r|>.95,
  0 pair |r|>.90. Cụ thể 6 per-class ratios vs hist_* tương ứng: r = .71–.82
  (file_io .777, network .727, process .776, crypto .739, dynamic .714,
  data_access .815) — **trùng thông tin MỘT PHẦN (chúng là hist/(n_nodes+1)),
  không phải bản sao**: khác tên, khác thang, corr < .86, và 0 feature malguard
  nào tái tạo được tuyến tính từ 18 graph (max R² = .8511, count R²>.95 = 0).
  ⇒ "malguard-only" KHÔNG phải dạng trá hình của graph block; so sánh có nghĩa.
- Redundancy nội bộ malguard tối đa |r| = .784 — không có cột chết (0 feature
  hằng số). Không feature graph bị dead.

## 3. CHECK-3 THỐNG KÉ TÁI LẬP — PASS (khớp tuyệt đối)

V1 tự tính từ `delta_f1_a_minus_b` trong aggregate.json (không dùng số render
sẵn): 8/8 family có mean/std/CI90 (t₁₉=1.7291)/TOST/Wilcoxon-exact/Holm **khớp
bảng §3.2 của W1 tới 1e-9** (assert tự động trong script audit). Điểm neo:
−.0216 p=.0441 Holm .3084 và +.0150 p=.1054 Holm .4865 — đúng. TOST: PASS ⇔
(lo > −margin ∧ hi < +margin), strict — logic đúng như A5.3/A8.4; kết luận
"đọc theo hướng CI" (3 cell CI âm nguyên: group central/fedavg + lco030 fedavg;
2 cell CI dương nguyên: group central + lco030 central của combined) đúng dữ
liệu. Holm: sorted ×(m−rank), enforce monotone — tái lập .2899/.3084/.4865 từ
8 raw p [.0362,.0441,.0441,.0973,.1054,.1140,.1327,.3118] — đúng. Per-seed
McNemar (malguard vs graph, group/central): 5/20 seeds p<.05, mean b01=12.75
vs b10=9.75 — **khớp chính xác** claim §3.2.

## 4. CHECK-4 AMENDMENT-8 TIMING + FROZEN LIST — PASS (kèm 1 ISSUE MINOR về timestamp)

- Đăng ký trước run: prereg.md mtime 2026-09-27T22:48Z (local 05:48 +07);
  config sha16 `b67eb03eb9c5d4f7` mtime 22:47Z; tests 22:51Z; meta.date của
  outputs hiện tại **23:07:49Z** (re-run cuối). Mọi artifact quan sát được
  ĐỀU sau amendment 22:44:07Z ⇒ "amendment TRƯỚC run" ĐÚNG với evidence còn
  tồn tại. **NHƯNG** claim "run thật (22:52:06Z theo meta)" là SỐ STALE: meta
  trong results.jsonl/aggregate.json hiện nói 23:07:49Z (run cuối sau khi thêm
  bảng per-eco; lần chạy đầu đã bị ghi đè). Xem FALSE CLAIMS FC-1.
- Frozen list khớp 100%: tái tạo 41 tên từ A8.1+A8.2 (6 ratio + 2 KB + 10
  ind_api từ top10 A8.1 + 10 pair từ top10 A8.1 + entry×2 + n_dirs + 10 text)
  = trùng `schema.json` = trùng `MALGUARD_FEATURE_NAMES` = trùng
  `features_malguard.jsonl` (603×41, keys khớp schema). Không thêm/bớt sau.
- Selection list A8.1 tái lập được từ corpus UNSUPERVISED: 5 KB-high present
  (child_process.exec, eval, os.system, subprocess.Popen, subprocess.run) +
  2 high absent đúng là child_process.spawn, "new Function"; top-5 medium df
  đúng số đăng ký (require 333, child_process 127, exec 72, os.environ 42,
  https.request 41 — V1 đếm lại khớp từng con số); 10 pair counts khớp hết
  (216/176/158/149/149/138/117/101/89/87, tie 149 break alphabet như đăng ký);
  top10 tái tạo == `TOP10_APIS` trong code. KB = 142 entries (đếm lại đúng).

## 5. CHECK-5 DETERMINISM + MOCK — PASS

- 320/320 rows `mock:false`, config_sha16 `b67eb03eb9c5d4f7` đồng nhất;
  V1 **tính lại config_sha16 từ file config** → khớp stored (config không đổi
  sau run). 160 cells = 20 seeds × 2 splits × 4 blocks; input_dim đúng
  {graph 18, malguard 41, combined 59, hashing 262144} × 80 rows.
- Re-run thật 3 cặp (seed,split) × 2 blocks × 2 methods = **12/12 so sánh
  bit-identical** (f1, auc, C_selected) với stored: (20260933,group),
  (20260933,lco030), (20260922,group).

## 6. CHECK-6 ĐỐI CHIẾU CÔNG BẰNG — PASS (đối xứng hoàn toàn)

- graph/hashing trong round 15 dùng CÙNG `run_cell` (scaler pooled-train, CV
  chọn C, LR lbfgs, FedAvg rounds=2) như malguard/combined — đọc code xác
  nhận; và **tái lập bit-exact (diff 0.00e+00, 20/20 seeds × 4 cell
  graph/hashing × central/fedavg, cả C_selected)** so với round-11
  `outputs/packguard/p0/p0_results.json` (mock=false, config
  5ee3764c59a8e4b3). ⇒ cùng protocol, paired comparison hợp lệ, không ưu ái
  chiều nào.
- Số round-9 trích trong §3.1 đúng cell: `fl_multiseed/grid_results.json`
  ecosystem__group__graph__centralized = .8581±.0468; tfidf__centralized =
  .8419±.0383 — khớp chữ "Old round-9 (torch path)".
- C distribution group/graph central {10.0:16, 1.0:2, 0.1:2} — khớp claim.

## 7. CHECK-7 PYTEST — PASS

- `pytest tests/test_packguard_malguard.py -q` → **14 passed** (8.2s).
- `pytest tests/ -q` → **757 passed, 0 failed** (87.2s) — khớp claim W1.
- Lãng phế phạm vi: mọi file read-only (packguard/{fl,features,kb,eval,
  strong_baseline,lco}.py, outputs/packguard/{p0,fl_multiseed,features,lco})
  có mtime TRƯỚC cửa sổ round-15 (muộn nhất lco.py 21:33Z < amendment 22:44Z);
  `find outputs/packguard -newer configs/packguard_malguard.yaml` ngoài
  malguard_style/ → rỗng. W1 không đụng gì ngoài vùng sở hữu (SUBMISSION.md
  05:48 là của W2, đúng nhãn).

## CONFIRMED BUGS

**KHÔNG có.** Không tìm thấy bug nào trong `malguard_style.py` ảnh hưởng kết
quả: extractor khớp công thức A8.2, aggregator/stats đúng rule registered,
grid đủ 320 runs, không mock, không LLM, determinism bit-level.

## FALSE CLAIMS (đều MINOR — không đổi kết luận)

- **FC-1 [MINOR, stale evidence]** §M1/§7: "run thật (22:52:06Z theo meta)" —
  meta trong outputs hiện tại là **2026-09-27T23:07:49Z** (re-run cuối, sau
  khi sửa renderer; outputs lần đầu đã bị ghi đè 2 lần do W1 disclose ở §7).
  Mệnh đề cha "amendment TRƯỚC run" VẪN ĐÚNG với evidence còn lại (22:44:07Z
  < 23:07:49Z), nhưng con số 22:52:06Z không còn truy vết được tới artifact
  nào tồn tại. Sửa: thay bằng "amendment 22:44:07Z TRƯỚC mọi run quan sát
  được (meta run cuối 23:07:49Z; lần chạy đầu không còn artifact do re-run)".
- **FC-2 [MINOR, đếm sai trong prose §3.2]**: "malguard-only THẤP HƠN graph ở
  cả 8/8 so sánh (8/8 deltas âm…)" — SAI: chỉ **4/8** families là
  malguard-vs-graph (4/4 deltas âm, n_neg>n_pos 13–15/20 seeds); 4 families
  combined-vs-graph có deltas DƯƠNG. Bảng §3.2 của chính W1 đúng; chỉ câu
  prose sai. Sửa: "malguard-only thấp hơn graph ở 4/4 families (hướng nhất
  quán 13–15/20 seeds mỗi family)".
- **FC-3 [MINOR, đếm sai trong prose §3.2]**: "2 cell có raw p<.05" — thực tế
  **3 cell** (p = .0441 group/central, .0441 group/fedavg, .0362 lco030/fedavg);
  chính bảng §3.2 và câu STATUS đầu ("p≈.036–.044") của W1 đã liệt kê đủ 3.
- **FC-4 [TRIVIAL, mô tả lệch implementation]**: AMENDMENT-8 A8.2 viết
  "combined = sorted(18 graph names) + sorted(41 malguard names)" — code dùng
  **frozen registration order** (KHÔNG sort alphabetically) cho phần 41 cột
  (`design_matrix`, `_graph_names() + list(MALGUARD_FEATURE_NAMES)`). Vô hại
  với kết quả (scaler per-cột + LR bất biến với hoán vị cột) nhưng mô tả lệch
  code. Cũng lưu ý docstring code "per-class unique-API ratios" là tên gọi
  lỏng — công thức thực hiện đúng là hist/(n_nodes+1) NHƯ A8.2 đăng ký (khớp
  amendment, không phải ngược lại).

## AI SAI / AI BẮT ĐƯỢC

- **W1 sai (prose, không phải số):** "8/8 deltas âm" và "2 cell raw p<.05" —
  đúng phải là 4/8 families (chỉ malguard-vs-graph) và 3 cell p<.05; bảng của
  W1 thì đúng hết, chỉ phần tường thuật sai đếm.
- **W1 sai (stale):** timestamp "run 22:52:06Z theo meta" không còn trong bất
  kỳ artifact nào (meta hiện tại 23:07:49Z của re-run cuối); audit chỉ chứng
  minh được amendment < mọi run quan sát được.
- **V1 bắt được (mới, tăng cứng kết luận):** permutation package-level ×20 —
  dưới label xáo, F1 cả 2 block sập về chance (malguard .55, graph .58) và
  ΔF1=−.0216 nằm giữa null ±.12 (perm p=.81) ⇒ không chỉ "test injection PASS"
  mà leak vô hiệu cả ở mức pipeline; đồng thời chứng tỏ −.0216 KHÔNG tách nổi
  khỏi noise seed — củng cố việc W1 từ chối viết "malguard thua significant".
- **V1 định lượng "disjoint":** max |r| 41×18 = .858, max R² = .851 — bộ 41
  không phải graph trá hình, nhưng 6 ratio trùng thông tin một phần với hist_*
  (corr .71–.82) — paper nên diễn giải "disjoint" là name-disjoint + không
  collinear hoàn toàn, đừng viết "statistically independent".
- **W1 đúng (chống nghi vấn lớn nhất):** graph arm tái lập bit-exact 4 cell
  round-11 → không ai có thể nói baseline bị làm yếu đi để graph thắng.

## W5 ANSWER QUALITY

Câu trả lời cho reviewer W5 **đủ cứng về số và cấu trúc**: cùng corpus/cùng
protocol (chứng minh bit-exact), 2 chiều đọc công bằng (không equivalence,
không superiority sau Holm), disclose reimplementation differences (KB-v3 thay
LLM, không re-parse), và chỉ ra PyPI-weakness của lexical features. Điểm cần
siết: (i) câu "is not equivalent at ±0.02" dễ bị reviewer đọc thành "proven
meaningfully worse" trong khi CI90 [−.041, −.003] vẫn chứa hiệu ứng ≈ 0;
(ii) nên dẫn độ chắc hướng bằng sign-consistency thay vì p-value đơn lẻ.

**Wording khuyến nghị cho F (paper2, 1–2 câu):**

> "On the same corpus, splits, and training recipe, a re-implemented
> MalGuard/Amalfi-style static feature set (41 features; KB-derived risk
> priors instead of the original LLM triage; no label information accessible
> to the extractor, verified by label-permutation) scores 0.856 vs 0.878 F1
> for our behavior-graph features on the primary group split (per-seed ΔF1
> −0.022, 90% CI [−0.041, −0.003]; exact Wilcoxon p=.044, not significant
> after Holm across 8 registered comparisons), with the deficit concentrated
> on PyPI (0.72 vs 0.84); the two feature sets are not statistically
> equivalent at ±0.02 either, and their combination trends +0.015 F1 (n.s.)."

Tránh: "significantly worse" (không sống Holm), "comparable/equivalent"
(TOST FAIL), và "8/8 comparisons negative" (chỉ 4/8 families là malguard).

---
*V1 round 15: chỉ tạo reports/round15/V1_report.md + /tmp/v1audit/*; không git
commit; CPU only; mọi số mới trong report này truy vết tới aggregate.json /
results.jsonl / p0_results.json / grid_results.json / perm_results.json
(/tmp/v1audit/perm_results.json).*
