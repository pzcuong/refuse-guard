# ROUND 6 SUMMARY — RefuseGuard: AI SAI / AI BẮT ĐƯỢC + tổng kết 6 VÒNG + khung positive

Ngày chốt: 2026-09-21. Tác nhân tổng hợp: S (Vòng 6 — VÒNG CHỐT). Ngôn ngữ:
tiếng Việt (số giữ nguyên gốc từ outputs, truy vết được từng số). Quy tắc xuyên
suốt 6 vòng: **không bịa số, không p-hack, không claim điều dữ liệu không chống
đỡ** — narrative positive đạt được bằng CHỌN KHUNG KỂ CHUYỆN đúng bằng chứng,
không bằng thay đổi số. Vòng 6 biến finding lớn nhất của Vòng 5 ("the defence
is the risk") từ **OBSERVATION thành MECHANISM** qua ablation có pre-registration
(Amendment-1) — đúng khuyến nghị #1 của ROUND5_SUMMARY.

---

## 1. Bảng "AI SAI / AI BẮT ĐƯỢC" — Vòng 6

| # | Ai viết | Lỗi | Ai bắt | Ai sửa | Mức | Trạng thái |
|---|---|---|---|---|---|---|
| 1 | A1-R6 | `fp_rate()` không lọc `y_true==0` (đếm cả vul vào mẫu số FP) | **A1 tự bắt** bằng self-test TRƯỚC khi chạy số; fix + regression test `test_empty_or_no_benign_raises` | A1-R6 (fix trước khi chạy số); V1 xác nhận 20/20 test bias pass | MED → đã chặn sớm | ✅ ĐÃ SỬA |
| 2 | A2-R6 (qwen spot run 1) | **Cross-model reuse contamination**: sha-gate chỉ soi prompt (model-blind) → 30 record A5 "qwen" thực ra là generation của llama; nếu không bắt, kết luận "qwen inert" sẽ là GIẢ | **A2 tự bắt** (model-mismatch check); quarantine `quarantine/results_qwen3b__ablation__15.POLLUTED.json` + guard `resolve_reuse_specs` + test mới + rerun sạch 180/180 cache-hit, 0 gen mới | A2-R6; V2 chứng minh độc lập: file polluté 30/30 trùng y_pred với llama-P3, 19/30 lệch với qwen-P3 | **HIGH** (nếu lọt qua thì sai kết luận) | ✅ ĐÃ SỬA + regression test |
| 3 | A2-R6 (granite combined) | `compute_extension_metrics` hard-code file old = llama → số combined granite đầu tiên (n=100, 0.52→0.90) là **số trộn model** | **A2 tự bắt** (assert `old_mid == mid`); fix `combined_old_sources_by_slug` per-model + test regression; số đúng: n=70, benign 0.0429→0.7143 p_χ² 1.95e-11, vul 0.0571→0.6714 p_χ² 1.50e-10 | A2-R6; V1 đếm lại độc lập khớp (+47/0 benign flips, đúng file granite) | **HIGH** (nếu lọt qua thì sai kết luận) | ✅ ĐÃ SỬA + regression test |
| 4 | A2-R6 (report bảng) | p "1.1e-05" chép tay lệch file: file ghi **7.629e-06** (benign A5-vs-A4) — file mạnh hơn | **V1-R6** | Ghi nhận bên A2 (report/metrics-stage; số trong paper lấy từ master, không chịu lỗi này) | LOW | ✅ Ghi nhận |
| 5 | A2-R6 (method label) | Nhãn "McNemar exact" (prereg §2) ≠ phép tính: `mcnemar()` auto chuyển **χ²-continuity khi nd≥25** (A5-vs-A4 p=3.35e-07 là χ²-cc; exact thuần 7.45e-09). Lệch theo hướng BẢO THỦ, không verdict nào đổi | **V1-R6 (soi chéo) + V2-R6 (Issue-1)** | **S-R6**: paper ghi nhất quán method ("exact binomial; continuity-corrected χ² where discordant ≥ 25; both variants stored, χ² conservative") ở caption bảng + method + appendix; exact làm chính, χ² footnote | LOW | ✅ ĐÃ SỬA |
| 6 | A2-R6 (budget) | Headline "703 generations" thiếu **131 gen** của run qwen polluté đã loại → tổng GPU thật vòng 6 = **834** | **V2-R6** (Issue-2, nguồn queue.log line 1618) | **S-R6**: appendix ghi "total 834 — 703 in the final files (+131 discarded polluted qwen run-1)"; master row `accounting.new_generations.total_round6_gpu = 834` | LOW | ✅ ĐÃ SỬA |
| 7 | A3-R6 (prereg) | Amendment-1 tự stamp "00:25" nhưng mtime file là **00:20:02** (vẫn trước kết quả đầu 00:49–00:51 nên vô hại về chất) | **V1-R6** (MINOR-3); V2 xác nhận | **S-R6**: nhãn amendment đổi theo mtime filesystem 00:20:02 + ghi chú lệch 5 phút | NIT | ✅ ĐÃ SỬA |
| 8 | A3-R6 → A1 docs | 2 showcase quote "verbatim/authorized" nằm ở **bản ghi label=1 KHÔNG flip** (204830: y_pred 0→0; 195017/211695: mở `"analysis_status": "authorized"`) — trình bày như thuộc tập 20/25 benign-flip; và "1 output authorized" thực tế là **4** (2 near + 2 far) | **V1-R6** (MINOR-1) | **S-R6**: sửa `docs/verdict_bias.md` §6 + `A1_report.md` §5 — quote là minh hoạ echo trong cùng arm (không thuộc tập flip), đồng thời là evidence FN-direction (hàm vul bị advisory "gạt"); đếm "authorized" = 4 | LOW | ✅ ĐÃ SỬA |
| 9 | A1-R6 (wording) | "global risk priming, không content-driven" quá mạnh — granite C5_near Δ(C−G) = +0.267, CI [−0.067, +0.600], n=15/stratum: dữ liệu KHÔNG loại trừ content-effect vừa | **V1-R6** (MINOR-2) | **S-R6**: hạ thành "priming-like; no detectable content-specific trace at this power; zero-API advisory alone suffices" ở `docs/verdict_bias.md` §4/§6 + `A1_report.md`; paper không dùng chữ "priming" | LOW | ✅ ĐÃ SỬA |
| 10 | A3-R6 (report) | "63 vị trí placeholder" — đếm sai, thật ra **56** (47 token, vài token lặp) | **V1-R6** (NOTE) | **S-R6**: sửa trong A3_report §3 | NIT | ✅ ĐÃ SỬA |
| 11 | A2-R6 (bảng) | Sample 211155 unparsed (PARTIAL) ở A3/A4 → 2 bậc chạy **59/60 pairs**, bảng không chú thích | **V2-R6** (Issue-3) | **S-R6** (kế thừa trạng thái đã điền): caption bảng ghi "A3/A4 recall uses 59/60 parsed records (one unparseable PARTIAL); Δ and p computed on parsed pairs" | LOW | ✅ ĐÃ SỬA |
| 12 | S-R6 (phần điền số) | Một phiên S-R6 trước bị ngắt sau khi điền paper nhưng TRƯỚC khi viết báo cáo | — (trạng thái disk lộ rõ qua mtime) | Phiên này **không tin, kiểm lại từng số**: đối chiếu máy mọi cell round-6 trong paper ↔ `outputs/master/round6_ablation.json` (134 rows) + `round6_bias.json` (149 rows) → khớp 100%; hoàn tất các fix còn thiếu; chạy lại toàn bộ verify | — | ✅ ĐÃ KIỂM LẠI |

**Điểm danh vòng 6:**
- **A2 TỰ BẮT được 2 bug nguy hiểm nhất của vòng** (contamination chéo model
  + trộn model trong combined) — cả hai đều có thể cho ra kết luận GIẢ
  ("qwen 0/60" giả, granite combined sai) nếu lọt qua verifier; xử lý chuẩn:
  quarantine + guard + regression test + rerun sạch (0 gen mới cho qwen).
- **Rung-isolation sạch nhất có thể ở mức prompt** (V2 diff 90 sample × 5
  rung: mỗi bậc đúng 1 thay đổi; A5 chỉ khác A4 bởi system reassertion,
  user prompt byte-identical; A5 byte-identical với P3 Vòng 5 — 90/90
  re-render + 30/30 sha-gate + 180/180 cache-hit qwen).
- **Pre-reg hai tầng (A3 + A2) được reconciliation bằng Amendment-1** và
  chuỗi sha config chứng minh design cố định TRƯỚC generation đầu 00:15:12
  (config trừ đúng 1 khóa metadata-only → sha quay lại `f09de392ec5b3b45`
  khớp 3 results file đầu + dry-run 00:13).
- **V1/V2 bắt đúng những gì agent viết không tự thấy**: method-label McNemar,
  budget 834-vs-703, quote mis-attribution, timestamp amendment, "63-vs-56".
- **Không có false claim material nào** (V1 §4: "Không có false claim
  material"; V2 §III: "Không tìm thấy claim sai nào") — mọi số nóngSurvive
  đếm độc lập từ raw records.

## 2. BẢNG TỔNG 6 VÒNG (round → ai sai → ai bắt → đã sửa)

| Round | AI SAI | AI BẮT ĐƯỢC | Đã sửa (bởi S) |
|---|---|---|---|
| **R1 — Foundation** | A1: bib lỗi + seq_len + calibration split; A2: vd_s + is_usable + monitor patterns; A3: C++/grammar crash + schema mismatch | V1/V2 (R1) bắt toàn bộ (2 CRITICAL/HIGH) | 15 mục (bib dọn, seq_len, cal-split, vd_s, is_usable, monitor patterns, parser crash, schema) |
| **R2 — Core** | A2: calibration threshold bug; A3: SIUD artifact + intent gate lexical miss 0/50; P2 refusal-suppression cơ chế (unsafe 0.040→1.000) | V1/V2 (R2) | Threshold fit lại; SIUD recompute; gate +40 patterns → 30/30; REFUSED_UNSAFE gate-first |
| **R3 — Experiments** | A3: claim E8 "P2 giảm unsafe compliance p=0.00049" — THU HỒI (thật: B0 0.033, p=1.0); ngân sách "619 gen" thực 488; E6 diễn đạt significance thiếu decomposition | V2 (đọc raw 12 file); V1 (validity Qwen 0.587) | Monitor +3 pattern; recompute từ raw; claim E6 chuẩn hóa "aggregate p=0.0078, vul-only p=0.5 n.s."; protocol deviation ghi chính thức |
| **R4 — Paper** | A2-R4: "2/2 fallback correct" không có trong output nào; paper nói granite "excluded" trong khi artifact 135/135 (stale) | V1-R4 (+A1-R4 cảnh báo trước) | Thu hồi "2/2" + regression guard assert trong make_figures; 8 vị trí granite cập nhật; master_results.json + verify re-read |
| **R5 — Positive reframe** | A2: "405 passed" stale + "1,200 gen thật" (thật 1,032 mới + 168 cache); A3: "1/98" (thật 2/98) + "16 phút" (thật ~11'); tích hợp "~1,546" overcount (thật 1,378) | **V1-R5 + V2-R5** (đếm độc lập, sha-reconstruct, McNemar exact tự viết) | [CORRECTED-ROUND5] + inline markers; collect_master_round5.py assert cứng; paper reframe theo khung positive |
| **R6 — Mechanism chốt** | A2: 2 bug tự bắt (contamination qwen/llama, trộn model granite-combined) — đã sửa TRƯỚC verifier; A2 report: p chép tay 1.1e-05-vs-7.63e-06 + nhãn "exact" thiếu method note + budget 703 thiếu 131 polluté; A3: amendment stamp 00:25-vs-00:20:02 + "63 vị trí" (thật 56); quote showcase từ record không-flip; chữ "global priming" quá mạnh | **A2 tự bắt 2 bug chính; V1-R6 + V2-R6** bắt 7 mục còn lại (đều MINOR/NIT); **S-R6** sửa toàn bộ + audit truy vết lại từng số | Method McNemar nhất quán; budget 834; amendment stamp; quote/priming hedge; "49 records"; caption 59/60 parsed; master round-6 (134+149 rows) re-read; paper điền 47 token từ master |

**Xu hướng 6 vòng:** lỗi nặng giảm dần và dịch chuyển từ "sai số liệu" sang
"sai chữ/ghi nhãn" — CRITICAL/HIGH do verifier bắt: R1: 2 → R2: 1 (suppression
cơ chế) → R3: 1 (thu hồi claim) → R4: 1 → R5: 0 → R6: 0 (2 HIGH nhất của R6 do
CHÍNH A2 tự bắt trước khi verifier chạy). Vòng 6 không có false claim material.
Cơ chế giữ chất lượng đã thành chuẩn: pre-registration + sha-chain + master
JSON re-read + verifier đếm độc lập từ raw records + regression test cho mọi
bug. Vòng 6 thêm 35 test mới (20 bias + 15 ablation).

## 3. Health cuối (trạng thái chốt dự án)

| Hạng mục | Trạng thái |
|---|---|
| `.venv/bin/python -m pytest tests/ -q` | **443 passed, 0 failed, 2 warnings** (44.7s) |
| `tectonic paper/main.tex` | **exit 0** (chỉ overfull warnings); `paper/compiled/main.pdf` 376,622 bytes (368K), **18 trang** |
| PDF stale-scan | `??` = 0; `{{R6` = 0; `detokenize` = 0; "405/408/442 passed", TODO, PLACEHOLDER = 0; số nóng round-6 hiện diện đầy đủ (7.45e-09, 28/34, 36/59, 0.390, 834, 0/300) |
| `paper/make_figures.py` | **PASS** — verify_tables + 17 headline cross-check + 18 cite keys; **7 figures** (fig_round6.pdf 20,711 bytes, sinh từ master với strict assert) |
| `bash scripts/verify_repro.sh` | **30 passed, 0 failed** (nâng 27→30 khi thêm artifact round-6: round6_bias.json + round6_ablation.json + value checks; manifest sha256 23/23) |
| Master round-6 | `outputs/master/round6_ablation.json` **134 rows** + `round6_token_map.json` **47 keys**; `outputs/master/round6_bias.json` **149 rows** (verify-only PASS); `docs/results_master_round6.md` |
| Budget generation vòng 6 | **834 GPU generations** (703 trong file cuối: llama ablation 325 + llama extend 160 + granite extend 160 + C5_far 58 + qwen rerun 0; +131 run qwen polluté đã loại); 1,130 records + 150 records reused-from-round-5 qua sha-gate |
| Số tổng dự án | LLM cache toàn dự án **5,530 generations** (wc -l 4 file cache: 749 smoke-0.5B + 2,112 qwen-3B + 838 granite + 1,831 llama); riêng R5+R6 = 1,378 + 834 = **2,212 gen mới đã kiểm**; RR = 0.000 trên mọi record mọi condition xuyên 6 vòng |
| Deliverables chốt | paper 18 trang (ACM style, 7 figures, 7 tables); `docs/round6_ablation_prereg.md` (+Amendment-1, stamp mtime 00:20:02); `configs/round6_ablation.yaml`; `scripts/collect_master_round6.py`; `scripts/analyze_verdict_bias.py`; reports/round6/{A1,A2,A3,V1,V2,S}_report + SUMMARY; 6 vòng reports đầy đủ |

## 4. Ánh xạ 4 FINDINGS khung positive ↔ BẰNG CHỨNG (mỗi finding ↔ file nguồn)

**Finding 1 — "The defence is the risk" — nay CÓ CƠ CHẾ (mới Vòng 6):**
| Số | Nguồn file |
|---|---|
| Rung-isolation: mỗi bậc A0→A5 đúng 1 thay đổi prompt; A4→A5 user prompt byte-identical, chỉ thêm system reassertion | `src/experiments/round6_ablation.py` (V2 diff 90×5); `configs/round6_ablation.yaml` (sha-chain `f09de392ec5b3b45` pre-generation) |
| Ladder recall vul 1.000/0.983/0.900/0.848/0.898/**0.433**; flips 1/5/3/(−3)/**28**; cumulative 34 | `outputs/experiments/round6_ablation/results_llama3b__ablation.json` (540 records) → master rows `ablation.llama3b.C5_near.A*.recall_vul`, `flip_v2b_vs_prev` |
| Reassertion rung: 28/34 = 82% net flips (exact p=7.45e-09; χ²-cc 3.35e-07) — kèm caveat B0 saturated | master `verdict.concentration.share_of_net_flips = 28/34`, `ablation.llama3b.C5_near.A5.mcnemar_p_vs_prev(_chi2)`; caveat trong tab_round6_ablation footnote |
| Replicate C5_far: recall 0.390 (59/60 parsed), 36/59 flips vs B0 (p=2.9e-11) | `results_llama3b__ablation__c5_far__5.json` → master `ablation.llama3b.C5_far.*` |
| Qwen inert (0/60 flips, p=1.0) — model-specificity, KHÔNG "robustness" (FP=1.0 sẵn ở C0) | `results_qwen3b__ablation__15.json` (sạch sau quarantine) → master `ablation.qwen3b.*` |

**Finding 2 — "Context doesn't block — it biases" (Vòng 5, mở rộng Vòng 6):**
| Số | Nguồn file |
|---|---|
| RR = 0.000 mọi model×arm (1,200 records Vòng 5; 0 REFUSAL xuyên 6 vòng) | `outputs/experiments/round5_e0v2/results_*.json`; gates H_A/H_B/H_C NOT_SUPPORTED 0/3 (`verdict.json`) |
| FP-bias: llama 49/60→60/60 (p exact 9.8e-04, conditional 11/11); granite 0/30→20/30→25/30 (p 1.9e-06 / 6e-08); reverse flips = 0 | `outputs/master/round6_bias.json` rows `bias.{llama3b,granite2b}.*` (V1 đếm lại độc lập 100%) |
| Extension (sample mới, không double-count): llama FP 0.82→0.99 combined n=100 (p exact 1.53e-05); granite benign FP 0.043→0.714 + vul recall 0.057→0.671 combined n=70 (p χ² 1.95e-11 / 1.50e-10) | `outputs/experiments/round6_ablation/results_{llama3b,granite2b}__extend.json` → master `extension.*` (per-model source assert + test) |
| Echo evidence: granite 12/20 (near) / 11/25 (far) flip-outputs echo advisory; llama 2/11; control C0 = 0/300 | master `evidence.*`; raw `outputs/experiments/round5_e0v2/raw/` (quote-source đã sửa theo V1 MINOR-1) |
| Content-attribution hedge: granite Δ(C−G) +0.267, CI [−0.067,+0.600] — underpowered; zero-API advisory alone suffices | master `bias.granite2b.C5_near.stratum.*`; `docs/verdict_bias.md` §4 |

**Finding 3 — P1 injection-resistance + "isolation is not accuracy" (Vòng 3):**
| Số | Nguồn file |
|---|---|
| Injection success 0.742→0.484, aggregate McNemar p=0.0078; vul-only p=0.5 n.s. (decomposition bắt buộc) | `outputs/experiments/round3_e6/results.json` (verify_tables assert từng số) |
| MCC C3: B0 +0.205 vs P1 −0.029 | như trên |

**Finding 4 — Actionable guidance G1 (mới Vòng 6, pre-registered):**
| Số | Nguồn file |
|---|---|
| H-M1 SUPPORTED (rung A5 Δ=0.465 ≥ 0.20, p<0.05); H-M2 SUPPORTED (minimal A1: Δ=−0.017, 1/60 flips, p=1.0); concentration cùng chỉ A5 (28 ≥ 50%×34) → KHÔNG distributed; bundle-synergy NOT_REACHED | master `verdict.*`; `docs/round6_ablation_prereg.md` (rules chốt trước số) |
| Guidance G1: "keep the minimal provenance wrapper, drop the rest" — boundary label vô hại trên model chính, reassertion nên off-by-default cho verdict-critical, phải đo lại per-model | master `verdict.guidance = G1`; paper §RQ7b + §guidance (`05_results.tex`, `06_discussion.tex`) |
| Tính đối xứng 2 failure modes: attack thuần FP-direction (llama +0.183, FN-dir = 0.000; granite tới +0.833), defence thuần FN-direction (0.633/0.667) | `outputs/master/round6_bias.json` `VCI.*` / `defense.*.P3_vs_B0.VCI.fn_direction` |

**Message tổng (đã trong abstract + intro + RQ7/RQ7b + discussion + conclusion):**
untrusted context và defensive mediation đều KHÔNG chặn (RR = 0.000) mà đều
làm sai verdicts — theo 2 hướng đối xứng; và giờ biết ĐÍCH XÁC thành phần nào
của defence gây hại (system task-intent reassertion), đủ để ships được một
wrapper minimal-provenance an toàn hơn (G1).

## 5. Việc S-R6 đã làm (tóm tắt; chi tiết lệnh + output ở S_report.md)

1. **F1** — 47 token `{{R6:*}}` = 0 còn lại; mọi cell số round-6 đối chiếu máy
   với `outputs/master/round6_ablation.json` (134 rows) + token map 47 keys;
   số chốt của vòng (ladder, flips, 82%+caveat, 7.45e-09/3.35e-07, C5_far
   36/59, qwen 0/60, extension n=100/70, FP-bias, VCI, echo, H-M2) khớp 100%.
2. **F2** — 8 MINOR fixes wording/method (McNemar method nhất quán; priming
   hedge; caveat 82% ở mọi chỗ; showcase quote re-attribution + "authorized"=4;
   "49 records"; budget 834; amendment stamp 00:20:02; "56 vị trí").
3. **F3** — master round-6 re-read PASS (`collect_master_round6.py` exit 0).
4. **F4** — tectonic 0 error (18 trang); pytest **443**; make_figures PASS
   (7 figures); verify_repro **30/30**; PDF stale-scan sạch.
5. **F5/F6** — ROUND6_SUMMARY.md + S_report.md này.

## 6. Khuyến nghị còn lại (post-project)

1. **Frontier-model transfer (ưu tiên cao nhất — CẦN API KEY, hiện KHÔNG có
   key nào đúng ràng buộc PROJECT_BRIEF):** chạy đúng C5 bench + ladder A0/A1/A5
   (prompt byte-deterministic, cache-ready) trên ≥1 frontier model để test
   blocking/bias/reassertion-transfer ở scale lớn — đóng limitation "2–3B
   scale" mà paper đang hedge; mọi pipeline đã ready, chỉ thiếu key.
2. **Mở rộng CWE families cho C5:** advisory inventory hiện 26 sinks (nặng
   memcpy/strcpy family); thêm CWE-416/UAF, CWE-190/integer, CWE-22/path để
   test tính tổng quát của verdict-bias channel và của reassertion-harm;
   tái dùng nguyên pipeline materialize + gates + collect.
3. **P3 ablation trên model lớn hơn + C0×P3 control:** reassertion-harm đo
   được trên llama-3B; cần (a) 1–2 model lớn hơn (7B class) và (b) control
   C0×P3 (chưa chạy xuyên 6 vòng — paper giữ nguyên là limitation) để tách
   "reassertion hại chỉ khi có advisory" vs "hại bất kể context".
4. **(Phụ, chi phí ~0)** Điền cell granite extension còn thiếu 30+30 để đủ
   combined n=100 (gap đã disclose trong paper) nếu có thêm phiên GPU.
