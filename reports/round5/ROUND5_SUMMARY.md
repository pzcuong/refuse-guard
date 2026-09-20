# ROUND 5 SUMMARY — RefuseGuard: AI SAI / AI BẮT ĐƯỢC + tổng kết 5 vòng + khung positive

Ngày chốt: 2026-09-20. Tác nhân tổng hợp: S (Vòng 5). Ngôn ngữ: tiếng Việt
(số liệu giữ nguyên gốc từ outputs, truy vết được từng số). Quy tắc xuyên
suốt: **không bịa số, không p-hack, không claim điều dữ liệu không chống
đỡ** — narrative "positive" đạt được bằng CHỌN KHUNG KỂ CHUYỆN đúng với
bằng chứng, không bằng thay đổi số.

---

## 1. Bảng "AI SAI / AI BẮT ĐƯỢC" — Vòng 5

| # | Ai viết | Lỗi | Ai bắt | Ai sửa | Mức | Trạng thái |
|---|---|---|---|---|---|---|
| 1 | A2-R5 (§1) | Claim "full suite = **405 passed**" — số stale: A2 tự thêm 3 gate-test SAU lần ghi số | **V1-R5 + V2-R5** (chạy lại `pytest tests/ -q` độc lập: 408 passed, 0 failed) | **S-R5**: khối [CORRECTED-ROUND5] đầu A2_report + inline marker; không xóa nội dung cũ | LOW | ✅ ĐÃ SỬA |
| 2 | A2-R5 (§7) | "**1.200 generation thật**" — đếm lẫn cache: 168/1,200 records là cache-hit (104 qwen + 64 llama, gồm gen B0-C5 của A3); gen mới thật = **1,032** | **V2-R5** (đếm `meta.gen.cache_hit` từ 1,200 records); V1 xác nhận lại 168 | **S-R5**: correction "1,032 new + 168 cache-hit = 1,200 records"; tổng Vòng 5 = 1,032 + 346 = **1,378** (bản "~1,546" đếm 158 gen dùng chung hai lần) | LOW | ✅ ĐÃ SỬA |
| 3 | A3-R5 (§4.1/§5.2) | "qwen: P3 inert, **1/98 pair** đổi verdict" — đếm đúng là **2/98 pair** (cùng 1 benign sample 218817 lật ở CẢ HAI arm; đếm theo sample = 1) | **V2-R5** (đếm pair-by-pair) | **S-R5**: correction + inline marker; các số xung quanh (19/19→18/19) đúng | LOW | ✅ ĐÃ SỬA |
| 4 | A3-R5 (§3/§7) | "llama run **16 phút**" — `wall_seconds` = 661.6 s ≈ **11 phút** (phần được ghi lại; có thể gồm load model, không load-bearing) | **V2-R5** (§1.6) | **S-R5**: correction + inline marker | LOW (nit) | ✅ ĐÃ SỬA |
| 5 | Tích hợp (báo cáo điều phối) | "~1,546 gen mới" — overcount: A2 1,200 records gồm 158 gen của A3 (cache-hit hai chiều qua content-addressed store) | **V2-R5** (§2.3) | **S-R5**: `scripts/collect_master_round5.py` tính `round5.unique_new_generations = 1,378` từ nguồn + assert cứng; paper dùng 1,378 kèm giải thích cache hai chiều | LOW | ✅ ĐÃ SỬA |
| 6 | A1-R5 (dry-run cũ) | `test_dry_run_end_to_end` FAIL — expectation `partial_json_broken` vs `partial_no_json` (mock sinh JSON truncation không parse được) | **A1-R5 phát hiện + A2-R5 tự sửa** (expectation khớp taxonomy trong config; mock giữ nguyên) | A2-R5 (fix trước khi chạy thật) | LOW | ✅ Sửa trước Round-5 run (15/15 test PASS) |

**Điểm danh vòng 5:**
- **A1 NÓI ĐÚNG thứ khó nhất:** V1 audit xác nhận 100% — query-relevance
  100/100 concrete advisory nêu đúng sink của chính hàm (vs C2b cũ 2/838 =
  0.2%), 0 leak label/CWE/CVE trên 400 renderings, 0 instruction, 8
  forbidden-token = 0 hit, D0 byte-equal C0, balance 50/50 per label, bench
  sha `2daa249f7543f8e0` idempotent.
- **A2 TRUNG THỰC về hướng ngược:** tự disclose granite recall 0.100→0.733/0.767
  và flip benign→vul — V1 tự đếm khớp chính xác từng con số (verdict
  NOT_SUPPORTED 0/3 đúng pre-reg, không "góp ri").
- **A3 NÓI ĐÚNG con số hot nhất của vòng:** P3 hại llama recall
  1.000→0.367/0.333, 39/60 flips, p = 3.8e-06/1.9e-06 — đứng vững 100% trước
  audit adversarial (V2: McNemar exact tự viết khớp, sha-reconstruction 20/20
  prompt, raw 10 cặp đều ANSWER JSON hợp lệ, KHÔNG parse-sai).
- **Nhất quán chéo A2↔A3:** prompt byte-identity 98/98 qwen + 60/60 llama
  tại mọi giao nhau; subset nesting 30+30 ⊂ 60+60 cùng seed 20260923;
  RR = 0.000 mọi cell hai experiment độc lập.

## 2. BẢNG TỔNG 5 VÒNG (round → ai sai → ai bắt → đã sửa)

| Round | AI SAI | AI BẮT ĐƯỢC | Đã sửa (bởi S) |
|---|---|---|---|
| **R1 — Foundation** | A1: bib lỗi + seq_len + calibration split; A2: vd_s + is_usable + monitor patterns; A3: C++/grammar crash + schema mismatch | V1/V2 (R1) bắt toàn bộ (2 CRITICAL/HIGH) | 15 mục (bib dọn, seq_len, cal-split, vd_s, is_usable, monitor patterns, parser crash, schema) |
| **R2 — Core** | A2: calibration threshold bug; A3: SIUD artifact + intent gate lexical miss 0/50; P2 refusal-suppression cơ chế (unsafe 0.040→1.000) | V1/V2 (R2) | Threshold fit lại; SIUD recompute; gate +40 patterns → 30/30; REFUSED_UNSAFE gate-first |
| **R3 — Experiments** | A3: claim E8 "P2 giảm unsafe compliance p=0.00049" — monitorlexical gap, THU HỒI (thật: B0 0.033, p=1.0); E6 diễn đạt significance thiếu decomposition 6 benign/2 vul | V2 (đọc raw 12 file); V1 (validity criterion Qwen 0.587) | Monitor +3 pattern + apostrophe normalize; recompute từ raw; claim E6 chuẩn hóa "aggregate p=0.0078, vul-only p=0.5 n.s."; protocol deviation ghi chính thức |
| **R4 — Paper** | A2-R4: "2/2 fallback correct" không có trong output nào; paper nói granite "excluded" trong khi artifact 135/135 (stale) | V1-R4 (+A1-R4 cảnh báo trước) | Thu hồi 2/2 + regression guard assert trong make_figures; 8 vị trí granite cập nhật; master_results.json + verify re-read |
| **R5 — Positive reframe** | A2: 405 stale + "1,200 gen thật"; A3: 1/98 (thực 2/98) + "16 phút"; tích hợp: "~1,546" overcount | **V1-R5 + V2-R5** (đếm độc lập, sha-reconstruct, McNemar exact tự viết) | [CORRECTED-ROUND5] + inline markers; collect_master_round5.py assert cứng 1,378/2/98/39-60/p-values; paper reframe theo khung positive |

**Xu hướng 5 vòng:** lỗi CRITICAL/HIGH giảm dần (R1: 2 → R3: 2 đo-lường →
R4: 1 → R5: 0). Vòng 5 CHỈ còn lỗi LOW (số stale, miscount nhỏ, cách đếm
ngân sách) — không lỗi nào đổi kết luận. Cơ chế hiệu quả nhất: "mọi số
phải truy vết được file nguồn + master re-read + assert kỳ vọng đã audit"
(R4-A1, tiếp qua R5 collect_master_round5.py với 139 rows re-derived).

## 3. Health cuối (trạng thái chốt Vòng 5)

| Hạng mục | Trạng thái |
|---|---|
| `pytest tests/ -q` | **408 passed, 0 failed, 2 warnings** (22.3s) |
| `scripts/collect_master_round5.py --verify-only` | **PASS** — 139 round-5 rows re-derived từ nguồn, khớp từng row |
| `paper/make_figures.py` (6 figures + verify_tables + check_citations) | **PASS** — round-5 tables khớp round5_master; 18 cite keys đều có trong refs.bib |
| `tectonic paper/main.tex` | **0 error** (chỉ font warnings chuẩn acmart); không có "??" unresolved; PDF 336KB |
| `bash scripts/verify_repro.sh` | **27/27 checks passed** (pytest strict + dry-run + artifacts + manifest sha256 23/23 + value checks + PDF build) |
| PDF stale-scan | "2/2 correct" = 0; "0.00049" = 0; "405 passed" = 0; "353 unit" = 0; "1,546" = 0; không mâu thuẫn RQ7 ở section nào |
| Jobs đang chạy | KHÔNG có (E0-V2 queue complete 480/480/240; defense runs budget-guarded disclosed) |
| Số tổng | 1,673 records vòng 5 (0 REFUSAL, 1 PARTIAL), 1,378 gen mới unique; 408 tests; master 341 rows (R4) + 139 rows (R5) |

## 4. Ánh xạ KHUNG POSITIVE ↔ BẰNG CHỨNG (mỗi finding ↔ file nguồn)

**Finding 1 — "The defence is the risk" (novel, counterintuitive, practical; hook chính của paper):**
| Số | Nguồn file |
|---|---|
| Llama recall vul 1.000 → 0.367 (C5_near) / 0.333 (C5_far) | `outputs/experiments/round5_defense/results_llama3b.json` (180 records) |
| 39/60 pair flip vul→benign (19+20; 20 unique samples) | như trên (recompute V2 + `collect_master_round5.py` assert 19/20) |
| McNemar exact p = 3.815e-06 / 1.907e-06 | như trên (V2 tự viết exact binomial, khớp master) |
| Raw audit: 20/20 prompt sha tái lập; flip đều ANSWER JSON hợp lệ `no_vulnerability, confidence 0.0` | `outputs/experiments/round5_defense/raw/r5d_llama3b__*.txt` (V2 §1.1) |
| Qwen inert 2/98; detector 400/400 + FP 0/984; side-ledger gate 30/30, probe 0/30, B0 0.033 | `results_qwen3b.json`; `side_effect_llama3b.json`; V2 §1.2/§1.5 |
| Caveat bắt buộc: P3 = bundle ≥5 thành phần → chỉ claim defense-level; C0×P3 control + ablation CHƯA chạy | V2 §1.1(c) + A3 §6 — đã ghi vào paper (RQ7 + discussion + threats) |

**Finding 2 — "Context doesn't block — it biases":**
| Số | Nguồn file |
|---|---|
| RR = 0.000, benign_block = 0.000 — 3 model × 4 arm (1,200 records; 1,199 ANSWER + 1 PARTIAL) | `outputs/experiments/round5_e0v2/results_{qwen3b,llama3b,granite2b}.json` + `summary.md` |
| Gates H_A/H_B/H_C NOT_SUPPORTED 0/3 (pre-registered) | `outputs/experiments/round5_e0v2/verdict.json` |
| Llama flip benign→vul +10 (D2) / +11 / +11; vul→benign = 0; C5 arms 60/60 benign→vulnerable (C0: 49/60) | `results_llama3b.json` (S đếm lại trực tiếp; khớp V1/V2) |
| Granite recall(vul) 0.100 → 0.433 (D2, p=0.006) → 0.733 / 0.767 (p<0.001); flips tới 25/30 | `results_granite2b.json` + `summary.md` |
| Query-relevance 100/100 vs C2b 2/838 = 0.2%; 0 leak trên 400 renderings | `data/benchmarks/bench_attack_v1/bench_attack_v1.jsonl` (sha `2daa249f7543f8e0`); V1 §1.1–1.2; master rows `c5_query_relevance.*`, `c2b_carrier_named_sink` |
| Concrete-vs-generic Δ benign_block = 0.000 (R3c) | `summary.md` stratification tables |
| Caveat bắt buộc: model-scale 2–3B — KHÔNG claim absence tổng quát (clause 0/3 đã pre-reg) | `configs/attack_v2.yaml gate_v2` + `configs/round5_e0v2.yaml hypotheses` |

**Finding 3 — P1 injection-resistance (Vòng 3, ghi đủ 2 vế):**
| Số | Nguồn file |
|---|---|
| Injection success 0.742 → 0.484, McNemar p=0.0078 (tổng); vul-only p=0.5 n.s. | `outputs/experiments/round3_e6/results.json` (verify_tables assert từng số) |
| "Isolation is not accuracy": MCC C3 B0 +0.205 vs P1 −0.029 | như trên |

**Message tổng (đã viết vào abstract + intro + RQ7 + discussion + conclusion):**
- Blocking-fear quá mức ở open-model scale: 0 refusal trên mọi record mọi
  condition xuyên 5 vòng (vòng 5: 1,673 records, 0 REFUSAL; các vòng trước:
  RR = 0.000 mọi cell E0/E2/E3, có calibration/probe chứng minh monitor bắt
  được refusal thật — smoke 0.5B 4/5 REFUSAL: `outputs/experiments/round5_e0v2/smoke_0p5b.json`).
- Rủi ro thật = verdict-corruption từ (a) untrusted context (2 hướng: IPI→benign 74.2%; advisory→vulnerable tới 25/30) và (b) chính defense layer (Finding 1).
- C5 (query-relevant + anti-leakage, pre-registered gates) = công cụ đo chuẩn cho kênh này.

**"First" claims — scope đã verify (paper §Related/Positioning):**
1. "first systematic test of query-relevant safety-blocking transfer to
   source-code vulnerability analysis at open-model scale" — literature
   check: TabooRAG (RAG/chat), Safeguard-DoS (guardrail benign-blocking),
   DRB (wording trên defense prompts) — không ai làm trên vuln-analysis
   với verifiable verdicts. HEDGE "to the best of our audited knowledge".
2. "first evidence of defence-induced verdict corruption in this setting" —
   Safeguard-DoS/TaboRAG là availability-side; CodeSentinel/P1 là anti-IPI;
   không có work nào report defense-induced flip trên vuln analysis. HEDGE cùng cách.

## 5. Việc S-R5 đã làm (tóm tắt; chi tiết lệnh + output ở S_report.md)

1. **F1** — [CORRECTED-ROUND5] + inline markers trong `A2_report.md` (405→408; 1,200 = 1,032 new + 168 cache-hit) và `A3_report.md` (1/98→2/98; 16'→~11'). Nội dung cũ giữ nguyên.
2. **F2** — verify `scripts/collect_master_round5.py` (139 rows re-derived, PASS) → `outputs/master/round5_master.json` + `docs/results_master_round5.md`.
3. **F3** — paper reframe: title (+", and the Defence Itself"); abstract mới (dẫn Finding 1+2); intro 4 contributions mới (C1 C5 benchmark, C2 blocking-transfer study + verdict-bias, C3 defence-risk, C4 P1 + CodeBERT); method thêm C5 + P3; setup thêm §bench5 + accounting 1,378; results thêm RQ7 + fig_round5 + 2 tables; related thêm Safeguard-DoS (2410.02916, verified) + 2 "first" claims hedged; discussion viết lại (defence-is-the-risk, blocking-premature/corruption-actionable, threats mở rộng model-scale + P3-confound); conclusion mới; appendix traceability + 408 tests.
4. **F4** — verify: tectonic 0 error; pytest 408; make_figures PASS; PDF stale-scan sạch; verify_repro.sh 27/27.

## 6. Khuyến nghị tiếp theo (để chốt strong-accept)

1. **P3 component ablation (ưu tiên cao nhất, chi phí thấp — mọi gen đã
   cache/resume):** tách từng thành phần (boundary wrap / header / generic
   wrap / string mediation / reassertion) trên llama C5 subset 30+30 →
   biến Finding 1 từ OBSERVATION thành MECHANISM; kèm C0×P3 control để tách
   "vô hiệu hoá advisory" vs "lật verdict bất kể advisory". Giả thuyết cần
   falsify: reassertion là thủ phạm (probe E8 cho thấy reassertion an toàn
   trên unsafe prose nhưng có thể đảo chiều trên code-vul).
2. **Frontier-model API runs** (cần API key — hiện KHÔNG có key nào, đúng
   ràng buộc PROJECT_BRIEF): chạy đúng C5 bench (prompt byte-deterministic,
   cache-ready) trên ≥1 frontier model để test blocking/bias transfer ở
   scale lớn — đóng câu "model-scale limitation" mà paper đang hedge.
3. **Mở rộng C5 sang CWE families khác:** hiện advisory inventory 26 sinks
   (bias memcpy/strcpy family); thêm CWE families (416/UAF, 190/integer,
   22/path) để test tính tổng quát của kênh verdict-bias và của P3-harm;
   tái dùng nguyên pipeline materialize + gates.
4. **(Phụ)** Hoàn tất llama benign + C0×P3 (đều cache-hit gần như toàn bộ)
   nếu cho phép thêm 1 phiên GPU; giữ nguyên pre-reg, chỉ điền cell thiếu.

---
*Verification S-R5: `pytest tests/ -q` = 408 passed; `tectonic` = 0 error;
`make_figures.py` = PASS (verify_tables + check_citations);
`collect_master_round5.py --verify-only` = PASS (139 rows);
`verify_repro.sh` = 27/27. Không git commit (orchestrator lo).*
