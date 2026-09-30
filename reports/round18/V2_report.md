# V2 REPORT — ROUND 18 (ADVERSARIAL AUDIT của W2: independent re-derivation + missed-finding probes trên EVIDA-2)

Ngày: 2026-09-30. Tác nhân: V2 (Vòng 18). Đối tượng audit: `reports/round18/W2_report.md`
+ `docs/round18_design_review.md` + toàn bộ chuỗi bằng chứng W1 (`outputs/packguard/evida2/*`).
Phương pháp: KHÔNG tin bảng số của W1/W2 — tự viết lại script kiểm toán từ đầu
(`/tmp/r18_v2_audit_v2.py`, không import `packguard/`, `research_program/`, `scripts/`;
Clopper-Pearson + McNemar tự viết lại lần thứ hai, độc lập với cả code W1 lẫn code W2),
đọc raw `evida2_decisions.json` (320 records), `evida2_units.json` (320 units), 412 dòng
`gen_*.jsonl`, prompt thật trong units manifest, prereg r17 + AMENDMENT-11. V1_report.md
CHƯA tồn tại tại thời điểm audit (V1 chạy song song, chưa kịp ghi).

## 0. VERDICT W2: **PASS — với 2 ISSUE phải xử lý trước khi chữ số này vào paper2**

1. **[ISSUE-MAJOR-1] W2 bỏ sót cấu trúc lớn nhất của v2: population 66 events là
   TRỘN HƯỚNG, và trên đó "13-0 chống EVIDA-2" ĐẢO NGƯỢC trên truth-metric**
   (chi tiết §2.B1 — bằng chứng tự tính lại từ raw, tái lập bằng 1 lệnh §5).
2. **[ISSUE-MAJOR-2] Full suite KHÔNG xanh: 1 failed / 832 passed** — chính test
   "independence" của W2 fail khi chạy chung (order-dependent, §2.B6). W2 chỉ
   từng report kết quả chạy riêng (24/24).

Mọi con số headline của W2 đều TÁI LẬP ĐỘC LẬP CHÍNH XÁC (§1). W2 không bịa số,
không phát hiện false claim dạng "số sai"; các issue là BỎ SÓT diễn giải + test
hygiene, không phải gian lận.

---

## 1. CHECKLIST MANDATE — XÁC NHẬN TỪNG SỐ (tự tính lại từ raw, script riêng)

| # | Claim W2 | Tôi tự tính lại | Verdict |
|---|---|---|---|
| 1 | P1 precision-kept **66/66 = 1.000** (pre-prune cũng 1.000) | 66 alarms / 66 kept / 66 đều là events; kept-trên-events 66/66; CI [.9456, 1.0] | **CONFIRMED** |
| 2 | P2 CRR **53/66 = .803** [.6868, .8907] | 53/66 = .8030 (final == C0-raw baseline) | **CONFIRMED** (nhưng xem B1: metric trộn 2 hướng) |
| 3 | P3 DIER **0/81 = .000** | 0/81; denominator 81 = 80 benign-C0 + 1 vuln-C0; **0 alarm trên toàn arm C0** | **CONFIRMED** (vacuous — B3 định lượng thêm) |
| 4 | Fallback-driven **60/66**; checker **0 SUPPORT / 6 REFUTE** | path: 60 fallback + 6 checker_refute + 254 agree; outcomes: 60 UNDECIDABLE / 6 REFUTE / 0 SUPPORT (cả 6 REFUTE đều chọn checker CWE-416) | **CONFIRMED** |
| 5 | Paired **13–0**, McNemar **p = .000244** | b=13, c=0 → 2/2¹³ = .000244; cả 13 đều fallback-override, score .583–.787 ≥ tau .5481; 47 fallback score < tau → final := strip; 0 abstain; fallback_errors 0 | **CONFIRMED trên baseline-metric** (đảo chiều trên truth-metric — B1) |
| 6 | PRUNE-1 **0/66** engage | alarms kept 66, pruned 0; direction (1,0) 66/66; 0 alarm 0→1 xảy ra | **CONFIRMED** |
| 7 | Llama **1/66** events (granite 65) | llama events 1 (benign-side), granite 65 (36 benign + 29 vuln) | **CONFIRMED** |
| 8 | T1p **.9091** [.8126, .9659] | 60/66 = .9091 | **CONFIRMED** |
| — | Bonus: r17 baseline (D2 của W2) | Tự viết lại logic 3 dòng từ `evida_decisions.json`: 146 events / 270 alarms / TP 57 / FP 213 / FN 89 / precision .2111; CRR 12/55 (D1 18/55); DIER 25/146; inert 37 | **ALL-MATCH** |

Fallback policy đọc từ data (đúng registered "verify-or-abstain" prereg r17 dòng
350–352: UNDECIDABLE → CodeBERT tau .5481; abstain chỉ khi fallback KHÔNG đưa
verdict): score ≥ tau → final := raw (13 case), score < tau → verdict fallback
= 0 == strip → final := strip (47 case), fallback lỗi → abstain (0 case).
**Không có policy deviation.**

---

## 2. BỎ SÓT CỦA W2 (mục riêng — 10 mục, 4 đầu có hệ số tác động)

### B1. [MAJOR — diễn giải] CRR .803 và "13-0" ĐỀU là metric-relative; trên truth-metric 13-0 ĐỔI THÀNH 5–8 (p=.581, không ý nghĩa)
Tự phân loại 66 events theo nhãn + đúng/sai của baseline C0:
- **37 events benign-side** (label=0): baseline C0 = 0 = TRUTH (đúng 37/37); C5 raw=1 là FP-thật
  (advisory bình luận gây FP); recovery final=0 **phục hồi truth** (32/37; 5 fallback-override giữ
  raw=1 → SAI).
- **29 events vuln-side** (label=1): C5 raw=1 = **TRUTH** (granite phát hiện đúng nhờ cue);
  baseline C0 = 0 **SAI cả 29/29** (granite C0 chỉ phát hiện 1/40 vuln); "recovery" final=0=baseline
  **PHÁ 21 verdict ĐÚNG** thành sai; chỉ 8 fallback-override giữ raw=1 = giữ truth.
- Tổng: raw==truth 29/66 → **final==truth 40/66** (+11 net; EVIDA-2 có lợi ròng trên truth);
  D1-strip==truth 37/66. **Truth-discordants: D1-gain 5 vs EVIDA-gain 8, p = .581**.
- Hệ quả: (a) CRR .803 KHÔNG được đọc là "chất lượng recovery" — nó đếm 21 lần phá-verdict-đúng
  là thành công; (b) F-2 của W2 ("adjudication GÂY HẠI") đúng trên registered metric nhưng
  KHÔNG đúng unqualified — paper phải in cả hai metric cạnh nhau; (c) nếu "sửa fallback" theo
  khuyến nghị (i) của W2 = luôn nhận strip, final==truth trên events RỚT 40 → 37 (phá 8 đúng, sửa
  5 sai) — tức khuyến nghị đó chưa được kiểm trên truth-metric.

### B2. [MAJOR — thiết kế] P1 = 1.000 gần như degenerate-by-construction dưới regime C0-sụp
C0 raw = 0 trên 159/160 units (granite C0 phát hiện 1/40 vuln; llama 0/40). Trong regime đó,
mọi flip C5 (1→0) tự động là "event" (baseline=0), và lớp FP 0→1 mà direction-clause của
PRUNE-1 sinh ra để cắt KHÔNG XẢY RA lần nào. Kênh FP-alarm duy nhất khả dĩ là unit C0=1 duy
nhất (198559) — và nó không alarm vì strip(C5) cũng =1. **P1-PASS đo tính đơn điệu của frame,
gần như không mang thông tin về pruning rule.** W2 nói "P1-PASS ≠ bằng chứng pruning" (F-3)
đúng hướng nhưng chưa chỉ ra P1 gần-tautology.

### B3. [MAJOR — ràng buộc chữ] DIER 0/81 vacuous HAI LỚP; và im lặng trước kênh lỗi trội
Lớp 1 (W2 đã nói): 0 alarm ở clean arm. Lớp 2 (mới): 0 alarm trên TOÀN BỘ arm C0 (C0 raw==strip
160/160) → adjudication không một lần chạm denominator; ngoài ra denominator loại 79/160 unit
clean-arm baseline-SAI (granite trượt 39 vuln + llama trượt 40) → DIER không nói gì về kênh
lỗi trội của frame mới (missed-vuln). Chữ đúng: **"DIER: not-evaluable (0 cơ hội adjudication)"**,
không phải "DIER 0.0". Bằng chứng benign-protection thật nằm ở kênh khác: 37 alarm benign-C5
được phục hồi 32 (5 override giữ FP) — phải report qua đó, không phải qua P3.

### B4. [MAJOR — attribution llama] Llama-collapse KHÔNG phải prompt-hỏng (đã đọc prompt + 206 response)
- Prompt byte-IDENTICAL giữa 2 model trên cả 160/160 (raw prompt sha khớp cross-model);
  đọc prompt thật: system prompt chuẩn, JSON schema rõ; user text Diff C0↔C5 chỉ khác đúng
  comment advisory (đúng thiết kế C5_near).
- 206/206 response llama parse OK (0 lỗi), status ANSWER 100%, **vulnerable=0 205/206**;
  và **93/205 verdict-benign vẫn mô tả nội dung vulnerability trong root_cause/cwe**
  (vd gọi rõ buffer overflow / CWE-78 / CWE-611 rồi vẫn chấm 0) → head-verdict bị "kẹp" về 0,
  kênh phân tích còn sống. Kết luận: collapse là hành vi model dưới frame, không phải artifact
  format → W1/W2 gọi "model asymmetry / im tiếng" là ĐÚNG; nhưng có nguyên nhân sâu hơn mà
  chưa ai ghi (B5).

### B5. [MAJOR — hiệu lực frame] Prompt hỏi "package behaves maliciously during installation"
trên MỘT HÀM C/CPP trần (package-vs-function mismatch) — nguyên nhân hợp lý nhất của việc cả
2 model gần-mù trên code sạch (granite C0 1/40, llama 0/40) và của 50/80 vuln-C5 không-được-
phát-hiện (raw==baseline==0, alarm không thể bắn — blind-spot không đếm được bởi bất kỳ gate
nào). W1 disclose "sụp đổ recall" như một finding; W2 giữ nó ở mức mô tả (F-4). Cả hai
không suy ra hệ quả registration: **các gate v2 được đo trên một frame mà task nền bị đặt sai
câu hỏi → mọi giá trị gate chỉ có nghĩa trong-regime, không extrapolate được ra frame RQ8.**

### B6. [MINOR — test] Full suite: **832 passed / 1 failed**
`tests/test_r18_stats.py::TestIndependence::test_validator_imports_no_builder_code` fail khi
file nào đó chạy TRƯỚC đã import `packguard` (test check `sys.modules` TOÀN CỤC — order-
dependent). Chạy riêng: 24/24 PASS; `test_packguard_evida2.py`: 15/15 PASS. Thuộc tính độc
lập THẬT còn đúng (subprocess sạch: validator import 0 module bị cấm — tôi verify riêng).
Sửa: check delta sys.modules trước/sau import validator, hoặc chạy subprocess. Chưa sửa thì
KHÔNG được claim "suite xanh".

### B7. [MINOR] `w2_recompute.json` oracle_audit tự-ô-nhiễm
`fields_outside_alarm_time_safe` liệt kê `_baseline` — chính validator W2 tự inject (`c5["_baseline"]
= ...`) TRƯỚC khi audit; đồng thời safe-set không được cập nhật cho schema v2 nên flag cả các
field hợp pháp (arm, strip_y, kept…). Một reviewer sau đọc nhầm thành "pipeline rò 7 field lạ".
Sửa: audit trước khi mutate + bổ sung safe-set v2.

### B8. [MINOR — nhất quán nội bộ W2] W2 report ghi "18 passed" (§1-D4) và design review D4
ghi "18 passed", nhưng file hiện có **24 tests** (§6 của chính W2 ghi 24). Số stale trong prose.

### B9. [MINOR — coverage] Arm P1-offensive-wording KHÔNG có trong toàn bộ line EVIDA (cả r17 lẫn v2)
v2 arms = {C0, C5_near}; r17 arms = {C0, C5_near, P0_neutral, P2_advisory_in_package};
`packguard/safety_port.py` có implement P1_offensive_wording nhưng chưa từng chạy trong
EVIDA line (cả r17 và r18). KHÔNG phải deviation của A11 (không đăng ký), nhưng mandate hỏi
đúng điểm: mọi claim "threat-3 (defence-harm)" cho line này hiện CHỈ đứng trên kênh advisory
(P2-analog), chưa có kênh offensive-wording.

### B10. [MINOR — chữ] "D1-only 66/66 = 1.0" là hệ quả định nghĩa, không phải phép so độc lập
Cả 66 events đều là flip (1→0) với baseline=0 ⇒ strip_y=0=baseline trên 100% events. Phép
paired thực chất chỉ đo đúng 1 nhánh thiết kế: fallback-override (13 lần bắn). Paper không
được trình bày "D1-only = 1.0" như so sánh 2 hệ thống độc lập.

**Trả lời trực tiếp 4 câu mandate:** (a) FP thật theo registered metric: KHÔNG (0 alarm
non-event); theo truth: 26/66 kept-alarm outcomes sai (21 vuln-side phá-đúng + 5 benign override)
— precision "1.000 tuyệt đối" chỉ đúng trong nghĩa metric đã đăng ký. (b) P1-arm: KHÔNG chạy
(B9 — gap thừa kế từ r17, không phải lỗi A11). (c) 0/81 từ Conditions: 100% là C0-arm; 0 alarm
C0 → vacuous hai lớp (B3). (d) Prompt llama KHÔNG hỏng (B4) → llama-collapse là finding thật
của frame+model, không phải artifact cơ học.

---

## 3. AMENDMENT-11 — CÓ NỚI GATE SAU KHI THẤY PILOT KHÔNG?

**Có nới so với r17, TRƯỚC generation v2, có disclose; trên data đã realized, việc nới
KHÔNG quyết định verdict.**
- Bảng đối chiếu: r17 G1 CRR≥.40 → A11 P2 **.35** (thấp hơn); r17 F3 sàn precision .50 →
  A11 P1 **.40** (thấp hơn); r17 G3 (paired strict) + G5 (direction ≥2 strata) → **BỎ**;
  P3 DIER≤.05 và P4 UAC≥.95 GIỮ NGUYÊN (P3 giữ chặt dù design-basis counterfactual .0753 > .05
  — điểm tốt cho thiện chí).
- Thời gian: r17 FAIL là input thiết kế (đúng quy trình charter §10); A11 freeze 10:15,
  generation đầu 10:22; mtime code 10:11–10:14 (trước freeze); prereg lần viết cuối 11:08 =
  append execution-log sau run. KHÔNG thấy dấu hiệu gate sửa sau khi thấy số v2 (validator
  độc lập của W2 dùng gate mandate và khớp). Residual: repo không phải git → không chứng minh
  mật mã được A11.3 bất biến trong [10:15, 11:08]; mức rủi ro thấp nhưng nên ghi 1 dòng.
- Điểm nới NGHIÊM TRỌNG NHẤT theo tôi không phải .40/.35 (cả hai side-floor .50/.40 cũng
  PASS trên v2) mà là **việc G3 bị bỏ** — gate duy nhất mà nếu còn thì FIRE. W2 đã flag đúng
  (FLAG-G3) từ trước run — credit.

## 4. CONFIRMED (của W2) / FALSE CLAIMS

- **CONFIRMED (7/7 headline + 8/8 r17 baseline + design-basis prune)**: §1.
- **FALSE CLAIMS: 0**. Hai điều chỉnh diễn giải bắt buộc: (1) F-2 "adjudication gây hại" phải
  gắn nhãn metric (B1); (2) "PASS 4/4" phải đi kèm 4 định tính B2/B3/B5/B6 — W2 đã tự làm
  80% việc này (5 cấu trúc §4.4), thiếu đúng B1 và B5.

## 5. ĐÁNH GIÁ KHUYẾN NGHỊ NEXT-STEP CỦA W2

W2 đề xuất: (i) sửa fallback policy → (ii) checker bank c/cpp → (iii) paired-vs-D1 vào gate
→ (iv) stress-test prune → (v) benchmark disjoint. **Thứ tự SAI ở 2 điểm, thiếu 1 bước số 0:**
- Thiếu BƯỚC 0: **sửa endpoint + frame-decision** (B1/B5). Không bước nào trong (i)–(v) đánh
  giá được đúng khi CRR còn trộn 2 hướng và frame còn mù clean-code.
- (i) "sửa fallback" lên đầu là SAI: trên truth-metric 8/13 override là ĐÚNG; sửa theo hướng
  "luôn nhận strip" làm truth trên events rơi 40→37. Quyết định fallback CHỈ sau khi endpoint
  dual-metric chốt. (Phương án thay thế đáng cân nhắc: quay về verify-or-ABSTAIN cho nhánh
  UNDECIDABLE — khớp triết lý registered gốc, biến 13 case thành abstain có cờ.)
- (iv) stress-test prune đáng lẽ TRƯỚC (ii): checker bank hiện chỉ bắn được qua claim CWE-416
  (6/66) — giá trị biên thấp đến khi frame/endpoint xong; trong khi PRUNE-1 là chủ đề đăng ký
  của round và vẫn 0/66 engage (stress được ngay bằng replay frame RQ8 có FP thật, hoặc
  metric-level mở rộng log r17).

**Thứ tự cuối cùng đề xuất (V2):**
0. Endpoint repair (dual-metric baseline+truth; covariate baseline-correctness; DIER
   not-evaluable khi 0 cơ hội adjudication) + sửa 2 test/audit hygiene (B6, B7) — làm được
   LOCAL NGAY, 0 GPU.
1. Frame decision: mini-run 2 frame (RQ8 vs safety-port, 1 model) hoặc replay RQ8 — điều kiện
   cho mọi gate có nghĩa (khuyến nghị của W1 #2 mà W2 bỏ trong list).
2. Paired-vs-D1 gate trở lại (G3') ở dạng dual-metric (local, từ data hiện có).
3. Fallback policy decision (override / accept-strip / abstain) trên endpoint đã sửa.
4. Checker bank c/cpp (sau 1–3).
5. Stress-test PRUNE-1 trên regime FP-thật (replay r17-regime hoặc frame RQ8).
6. Disjoint benchmark + power n≥200 events → mới mở FULL.

---

## 6. EVIDA-2 VERDICT CHỐT (cho paper2)

**Gates PASS 4/4 giữ được giá trị khoa học ở framing NÀO:**
- Framing đúng duy nhất: **"frame-regime pilot, detection-only"** — dưới safety-port frame trên
  hàm c/cpp: (a) kênh alarm sạch theo registered metric (66/66, nhưng B2: near-degenerate —
  phải nói kèm); (b) strip thuần khôi phục mọi registered event; (c) adjudication thêm vào
  LÀM HẠI baseline-recovery 13–0 (p=.000244) nhưng TRÊN TRUTH là hoà hướng tốt (final==truth
  40/66 vs strip 37/66; discordants 5–8, p=.581) — in cả hai, không chọn một; (d) PRUNE-1 chưa
  engage (0/66) → chưa validated; (e) llama strata not-evaluable (frame-blind; verdict-head
  kẹp 0: 205/206, 93 dòng tự mô tả vuln vẫn chấm 0) — finding của paper, không phải số gate.
- KHÔNG được claim: "evidence-grounded recovery" (T1p .909 fired), "pruning validated",
  "DIER 0" (not-evaluable), CRR .803 như "chất lượng recovery" (trộn hướng; 21/53 là
  phá-verdict-đúng theo truth), mọi so-thẳng với r17 (.2182/.1712) — regime khác cả frame
  lẫn baseline-correctness.

**Wording khuyến nghị paper2 (3 câu chốt):**
1. "Under a package-analysis frame ported to standalone C/CPP functions, verdict-flip alarms
   were precision-clean (66/66) and pure stripping recovered all registered corruption events;
   the frozen adjudicator added no recovery and flipped 13 baseline-recoveries (exact McNemar
   p=.000244), while leaving truth-level accuracy unchanged-to-slightly-better (40/66 vs 37/66
   events correct; ns)."
2. "Because the clean-code baseline collapsed under this frame (1/40 and 0/40 vulnerabilities
   detected), alarm precision was near-degenerate, DIER was not evaluable (zero adjudication
   opportunities), and the pruning rule never engaged (0/66) — these gates are regime-bound
   and must not be read as mechanism validation."
3. "All inference is descriptive at realized n=66 events (power ≈ .45 at expected yield);
   held-out means pipeline-level (rule frozen from the round-17 log; same 160-sample bench,
   re-rendered frame)."

**AI SAI / AI BẮT ĐƯỢC (tóm 4 dòng):**
- W2 SAI nhẹ: để "13-0 gây hại" không gắn nhãn metric (đảo 5–8 trên truth) và bỏ frame-degeneracy
  ra khỏi next-step list; để test independence order-dependent khiến suite full KHÔNG xanh.
- W1 sai cấu trúc được cả W2 lẫn V2 bắt: verdict "PASS" trần che T1p; W1 đã khắc phục trong
  report cuối (verdict 2 chiều) — chấp nhận.
- V2 BẮT ĐƯỢC: population trộn hướng (B1) — phát hiện lớn nhất vòng này; P1 near-tautology (B2);
  DIER not-evaluable hai lớp (B3); llama verdict-head kẹp-0 với 93 dòng tự-mô-tả-vuln (B4/B5);
  suite 832/1 (B6); oracle_audit tự-ô-nhiễm (B7).
- Không ai bịa số: 15/15 số chính của W1+W2 tái lập độc lập lần 2 bằng code viết lại từ đầu.

## 7. FILES + SELF-TEST (thật)

- Tạo: `reports/round18/V2_report.md` (file này) + `/tmp/r18_v2_audit_v2.py` (script audit,
  ngoài workspace). KHÔNG sửa file của ai; KHÔNG git commit.
- Tái lập:
  ```
  .venv/bin/python /tmp/r18_v2_audit_v2.py                     # §1 + B1–B4, B10
  .venv/bin/python -m pytest tests/test_r18_stats.py -q        # 24 passed (riêng lẻ)
  .venv/bin/python -m pytest tests/test_packguard_evida2.py -q # 15 passed
  .venv/bin/python -m pytest tests/ -q                          # 1 failed, 832 passed (B6)
  ```
- Cross-check thêm đã chạy: subprocess sạch xác nhận validator không import code builder;
  đếm llama/granite response bất nhất (93/205, 93/138); đọc prompt C0/C5 thật từ units
  manifest; đối chiếu mtime freeze (config 10:11:44, code 10:14:05, prereg append 11:08:02).
