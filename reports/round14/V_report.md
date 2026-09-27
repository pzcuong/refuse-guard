# V Report — Round 14 (AUDIT ADVERSARIAL baseline GuardDog của W)

Ngày: 2026-09-28. Auditor: V (vòng 14). Đối tượng: `reports/round14/W_report.md`
+ toàn bộ artifact `outputs/packguard/guarddog/`, pre-reg
`configs/packguard_guarddog.yaml`, scripts `scripts/r14_guarddog_{scan,metrics}.py`,
tests `tests/test_packguard_guarddog.py`. Phương pháp: đếm ĐỘC LẬP từ
findings.jsonl bằng script riêng (`/tmp/v_audit_recount.py`, main venv), tái lập
split bằng primitive packguard, soi severity bằng chính guarddog 3.2.0 trong
`.venv-gd` (`/tmp/v_audit_rescan.py`), scan LẠI 5 sample, chạy lại tests.
KHÔNG sửa file nào của W; không git commit.

## VERDICT W: PASS (có 4 ISSUES, không ô số nào bị vô hiệu)

Cả 4 claim chính của tasking ĐỀU XÁC THỰC ĐƯỢC bằng đếm độc lập:
(1) pre-reg TRƯỚC mọi scan — xác thực bằng birth/mtime; (2) toàn bộ 16 ô số
metrics khớp tuyệt đối (P/R/F1 + AUC brute-force và sklearn đều trùng tới
1e-16); (3) đối chiếu group-thua / LCO-top / t0.50-đảo đúng nguyên văn số
trong grid_results.json + lco_results.json; (4) caveat same-origin DataDog
có trong pre-reg TRƯỚC khi scan. Các issue tìm được là lỗi VĂN BẢN/quy
trình, không phải lỗi số.

## EVIDENCE THEO CHECKLIST

### 1. PRE-REG TIMING — PASS
- UTC (TZ local +0700): `split_membership.json` birth 21:55:12Z →
  `configs/packguard_guarddog.yaml` birth=mtime **21:56:31Z** →
  `extract_status.json` 22:00:51Z → `scan_run.log` birth 22:02:13Z →
  `findings.jsonl` birth/mtime 22:06:26Z. Yaml (claim 21:56:03Z, file chốt
  28s sau) TRƯỚC extract lẫn scan. Claim "trước mọi scan" ĐÚNG.
- Decision rule ghi rõ verbatim trong yaml: `verdict_rule: "malicious iff
  count(distinct source YARA rules with severity in {critical,high}
  triggered) >= 1"`, `score_for_auc` = số distinct high rule, metadata
  `recorded_separately ... NEVER enter verdict or score`, timeout/error =
  status riêng loại khỏi metrics. KHÔNG có dấu đổi rule sau khi thấy kết
  quả: ruleset khai trong yaml (54 YARA/eco; high 28 / medium 14 / low 12;
  metadata npm 9 / pypi 7; không có critical) khớp 100% với bảng severity
  tôi tự inspect từ guarddog 3.2.0 trong .venv-gd; toàn bộ rule trong
  `rules_triggered` của 602 row ok đều là severity high theo bảng đó
  (0 lệch). Guarddog version xác nhận 3.2.0 (importlib.metadata).

### 2. ĐẾM ĐỘC LẬP — PASS (khớp từng số)
603 rows, id set == manifest, 0 trùng id, label/ecosystem khớp manifest 603/603.
Tự tính lại (code riêng, không dùng code W):
- full n=602 excl=1: P .9477 / R .7918 / F1 .8627 / AUC .8699,
  tp/fp/fn/tn 308/17/81/196 — khớp metrics.json + W report + tasking.
- group-test n=128 excl=1: F1 .8662 / AUC .8740 (68/2/19/39). ✓
- LCO t0.30 n=89: F1 .8571 / AUC .8758 (39/3/10/37). ✓
- LCO t0.50 n=113: F1 .8550 / AUC .8736 (56/3/16/38). ✓
- Verdict rule áp đúng trên 602/602 row ok: score==len(rules_triggered),
  verdict==1 iff score≥1, rules_triggered ⊆ rules_triggered_all, 0 rule
  metadata (không phải threat-/capability-) lọt vào trigger → metadata
  KHÔNG lẫn vào verdict. 1 row error (setnetwork) có verdict/score=None.
- Diagnostics khớp: FP=17 (npm 11, pypi 6; driver `threat-filesystem-read`
  8 + `threat-process-memory` 4 = đa số, đúng claim); top rules trên
  malicious khớp nguyên văn (preinstall-script 132, download-exec 99,
  exfiltration 90...); score dist malicious mean 1.77/median 1/max 7,
  benign mean 0.09/max 2; class recall intent .7735 vs compromised .8625
  (đúng claim .773/.863); scan time median .035s/max 18.29s (đúng .04/18.3).

### 3. SPLIT MEMBERSHIP — PASS
Tái lập bằng chính primitive packguard (seed 20260922), so SET:
- group `make_group_split(records, 0.2, seed=20260922, 'package')`:
  129 id / 88 mal — SAME_SET=True với split_membership.json; n_test=129
  khớp từng row grid_results.json.
- LCO t0.30 `draw_lco_split(records, clusters_t030.assignment, 20260922, 0.2)`:
  89 / 49 mal / 65 cluster held — SAME_SET=True; khớp row lco_results
  (n_test 89, n_test_malicious 49, n_clusters_total 326 == file clusters).
- LCO t0.50: 113 / 72 mal / 68 cluster — SAME_SET=True.
- Sample rỗng (pypi-malicious_intent-setnetwork-0.3...) nằm CHỈ trong
  group-test → group n_excluded=1, LCO n_excluded=0 — đúng như metrics;
  xử lý = error + loại khỏi mọi scope, đúng pre-reg ("statuses: [ok,
  timeout, error]", extraction failure disclosed per label: 1/390 mal,
  0/213 benign).

### 4. AUC .870 & TIES — PASS
Score là count nguyên (median 1, nhiều ties). W dùng Mann-Whitney exact
mid-rank ties — tương đương đúng cách sklearn làm. Tôi tính lại bằng (a)
brute-force pairwise U với tie=0.5 và (b) `sklearn.metrics.roc_auc_score`:
cả hai trùng metrics.json ở cả 4 scope (diff ≤ 1.1e-16). full AUC
.869872 → .870 đúng.

### 5. BIAS DISCLOSURE — PASS (có gợi ý tinh chỉnh)
- Config có mục `disclosed_risks_registered_in_advance` (TRƯỚC scan):
  same-origin "GuardDog rules AND the corpus's malicious labels both come
  from DataDog's malicious-software-packages-dataset ... optimistic for
  GuardDog; stated regardless of direction"; `rule_source` ghi rõ rules
  ship kèm 3.2.0 thuộc cùng project DataDog đó. Report nhắc lại §3.2.4 và
  §4.1, và phân tích chiều bias ĐÚNG: thua-graph ở group split là bias-
  robust (bias chỉ có thể làm GuardDog TỐT hơn), còn thắng LCO không tách
  được khỏi bias + 1-seed → chỉ "comparable". Đủ để reviewer hiểu.
- Thiếu (nhẹ, xem FALSE CLAIMS #4 + khuyến nghị cho F): (i) Caveat có thể
  nói rõ tính ASYMMETRIC — rules được viết để bắt chính các family malicious
  trong corpus nên phía recall/TP được thổi phồng; phía benign (popularity-
  ranked, KHÔNG từ DataDog) không được bias che → FP-rate ngoài thực địa có
  thể XẤU hơn số đo. (ii) Ô so sánh bị chọn: grid còn có `fedprox` (bằng
  fedavg) và `per_client_best` (tfidf per_client_best F1 .8878 > guarddog
  .8662 ở group-test), lco_results còn block `trivial` (t0.5 F1 .8846 >
  .8550) — việc chỉ lấy centralized+fedavg không lật conclusion nào (các ô
  bỏ sót phần lớn còn làm learned ĐẸP hơn, riêng trivial t0.5 cũng thắng
  guarddog) nhưng luật chọn ô cần được nêu một câu trong paper.

### 6. SCAN HONESTY (rescan 5 sample bằng .venv-gd) — PASS
- 4/4 sample ok rescan khớp TUYỆT ĐỐI: score, verdict, rules_triggered
  (high) VÀ rules_triggered_all (medium/low) giống từng rule: benign FP
  `npm-benign-@devcontainers__cli` (score 2), malicious score-0
  `npm-malicious_intent-@cloudplatform-single-spa@document-db-99.99.99-20`
  (7 rule medium/low, 0 high → verdict 0 đúng luật), malicious max
  `pypi-compromised_lib-litellm-1.82.8` (score 7/22), benign 0-rule
  `npm-benign-@a2a-js__sdk`. Scan deterministic, không hàn gắn số.
- Error sample: findings ghi status=error/verdict=None (đúng). Lưu ý:
  guarddog tự nhiên trả OK score-0 trên dir rỗng (tôi xác nhận khi gọi thẳng
  API) — check "0 files → error" của W là chặt hơn engine và ĐÚNG protocol
  (nếu không có check đó, 1 sample malicious rỗng đã bị tính như verdict
  benign). 0 timeout toàn run; không có row timeout/error nào bị tính thành
  verdict.

### 7. TESTS — PASS
- `tests/test_packguard_guarddog.py` (.venv chính): **11 passed** (khớp
  claim). File KHÔNG import guarddog (chỉ import module metrics stdlib-only
  + packguard có skip-guard) → không phụ thuộc .venv-gd khi chạy full suite.
- Full suite `.venv/bin/python -m pytest tests/ -q`: **743 passed / 0
  failed** (78.9s) — khớp claim 743/0 (732 cũ + 11 mới).
- `.venv-gd/bin/python -m pytest <file>`: 9 passed, 2 skipped — khớp claim.
- Comparator traceability test có thật: tôi tự so lại, mọi cell trong
  metrics.json == giá trị lưu trong grid_results.json / lco_results.json;
  20-seed LCO mean tự tính lại khớp (.8395±.0576 graph/sc, .8457±.0734
  hashing/sc, t0.5: .8624/.8519/.8625/.8650).

## CONFIRMED BUGS (trong số liệu/artifact)
KHÔNG CÓ. Không tìm thấy bug số liệu: mọi ô metrics, membership, verdict,
AUC, comparator đều tái lập được độc lập. 2 bug W tự báo cáo (list-vs-dict,
empty-dir) đã thực sự được fix trong bản scan cuối (bằng chứng: 602 row ok
parse đúng severity; row rỗng là error).

## FALSE CLAIMS (lỗi văn bản/quy trình — không ảnh hưởng số)
1. **[MEDIUM] "56/81 malicious score-0 không trigger rule nào kể cả
   medium/low" (W §3.3) — SAI, số bị đảo.** Đếm độc lập: chỉ **25/81**.row
   không trigger rule nào; đúng 56/81 là phần NGƯỢC LẠI (có ≥1 rule
   medium/low nhưng 0 rule high). Chỉ là câu diagnostic, không vào metrics,
   nhưng PHẢI sửa trước khi vào paper.
2. **[LOW-MEDIUM] "sau fix chạy lại từ đầu" (W §1-G4/§4.7) — không đúng
   quy trình như mô tả.** scan_nohup.log line 2: "SCAN DONE ok=0 timeout=0
   error=1 in 0s" = run RESUME chỉ quét lại đúng 1 sample rỗng, không phải
   chạy lại 602. 602 row ok đến từ run trước đó. Tính toàn vẹn dữ liệu
   VẪN GIỮ (run đó parse đúng — rescan 4/4 khớp tuyệt đối; bug còn hoạt
   động trong run đó chỉ ảnh hưởng đúng 1 row đã được thay bằng error),
   nhưng mô tả process là không chính xác.
3. **[LOW] "scan_nohup.log có trace 2 bug đã fix" (W §2) — FALSE.** File
   chỉ có 2 dòng "SCAN DONE ..."; không có trace bug nào. Nguồn duy nhất
   về 2 bug là mô tả trong report. `scan_run.log` rỗng (0 byte) — đúng
   thiết kế (chỉ ghi row non-ok của scan phase) nhưng gây hiểu nhầm nếu
   đọc nhanh.
4. **[LOW] Không disclose luật chọn ô so sánh.** Bỏ qua fedprox (trùng
   fedavg), per_client_best (tfidf .8878 > guarddog .8662 group-test) và
   block trivial (t0.5 .8846 > .8550). Không ô nào bị bỏ lật ngược
   conclusion "thua graph" (graph thắng ở mọi method), nhưng một câu
   "we compare the centralized and FedAvg cells as primary" là bắt buộc
   cho paper.

## AI SAI / AI BẮT ĐƯỢC
- W sai một câu diagnostic: 56/81 thực ra là 25/81 (đảo số với phần bù) —
  V bắt được bằng đếm lại từ findings.jsonl.
- W mô tả sai quy trình ("chạy lại từ đầu" trong khi log cho thấy resume 1
  sample; "trace bug trong log" trong khi log không có) — V bắt được qua
  scan_nohup.log + birth/mtime. May là dữ liệu cuối không bị ảnh hưởng.
- W làm ĐÚNG những chỗ khó: pre-reg trước scan (verify bằng birthtime),
  AUC ties đúng (trùng sklearn tới 1e-16), split tái lập set-chính-xác,
  rescan 5 sample cho kết quả byte-tương đương, caveat same-origin đăng
  ký TRƯỚC và dùng đúng chiều (không benefit-of-doubt cho mình).
- Không ai bịa số: mọi số trong W report đều truy vết được về artifact.

## PAPER-READY: ĐỦ — dùng được cho F
Số GuardDog đã đủ độ tin cậy để F viết 1 đoạn chính text + 1 bảng phụ lục:
metrics độc lập reproducible 100%, pre-reg timing sạch, verdict rule được
áp đúng, rescan deterministic, tests 743/0. Điều kiện sử dụng:
1. Dùng W`s CONCLUSION_SENTENCE được — nó trung thực; CHỈNH: thêm 1 câu
   chọn ô ("centralized and FedAvg cells are compared; other grid cells
   do not change the ordering") và bỏ/sửa con số 56/81 → nếu muốn giữ thì
   viết "25/81 fired no rule at all; the remaining 56 fired only
   medium/low rules".
2. Wording khuyến nghị (giữ "comparable", CẤM "superior"): GuardDog =
   "precision-first triage baseline (F1 .86–.87, P .93–.97, R .78–.80)" —
   trails graph under group split (.866 vs .928 F1; .874 vs .926 AUC);
   comparable-to-or-above learned cells on the hardest LCO seed (t0.30
   .857 vs .747–.835) nhưng single-seed và đảo dấu ở t0.50 → không claim
   robustness; same-origin DataDog caveat bắt buộc kèm mọi số GuardDog,
   nêu rõ bias làm recall GuardDog optimistic (rules cùng nguồn với
   nhãn) trong khi phía benign không được bias che.
3. Bảng phụ lục: dùng số §3.1/§3.2 của W (đã verify) + n=128 (129 trừ 1
   archive rỗng, disclosed) + ghi guarddog 3.2.0, 54 YARA rules/eco
   (high=28), verdict = ≥1 high rule, AUC = distinct-high-rule count.
4. Macro `{{R14:*}}` trong W §6: đã kiểm tra — mọi số khớp artifact, dùng
   nguyên được (chú ý {{R14:GD_FULL_F1}} ghi n=602 đúng).

Kiểm toán này chỉ tạo: `reports/round14/V_report.md` + `/tmp/v_audit_*.py`.
Không file nào của W bị sửa.
