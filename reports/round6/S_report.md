# S Report — Round 6 (VÒNG CHỐT: điền số + fix wording + verify toàn bộ)

Ngày: 2026-09-21. Tác nhân: S (tổng hợp, Vòng 6). Phạm vi: [F1] điền 47 token
`{{R6:*}}` bằng số truy vết được từ `outputs/master/round6_*`; [F2] sửa MINOR
issues V1/V2 (wording/phương pháp, không đổi số); [F3] master round-6 đầy đủ +
re-read pass; [F4] verify toàn bộ (tectonic / pytest / figures / repro / PDF
stale-scan); [F5] ROUND6_SUMMARY.md. KHÔNG bịa số; KHÔNG git commit; KHÔNG GPU.

---

## 0. Trạng thái kế thừa (minh bạch)

Khi phiên S-R6 này bắt đầu, các file paper đã được điền số (mtime 03:04–03:27,
sau A3_report 03:13) — một phiên S-R6 trước đã thực hiện phần [F1] rồi bị ngắt
trước khi kịp viết báo cáo. Xử lý của phiên này: **không tin, kiểm lại từng
số** — mọi cell số round-6 trong paper được đối chiếu máy với
`outputs/master/round6_ablation.json` (134 rows) và `round6_bias.json` (149
rows); các fix [F2] còn thiếu thì làm mới; sau đó chạy lại toàn bộ chuỗi verify
[F4]. Không số nào được gõ tay; bảng được sinh từ
`scripts/collect_master_round6.py` → `outputs/master/round6_token_map.json`
(47 keys = đúng 47 token), số trong .tex khớp token map từng ô.

## 1. [F1] Điền placeholder — kiểm tra truy vết (kết quả: PASS toàn bộ)

Lệnh + output thật:

```bash
grep -rn "{{R6:" paper/          # → 0 hit (không còn token nào)
grep -rn "R6:" paper/            # → chỉ còn comment nguồn trong tab_round6_ablation.tex + make_figures.py
.venv/bin/python scripts/collect_master_round6.py
# → [ok] wrote outputs/master/round6_ablation.json (134 rows) + round6_token_map.json
#        + docs/results_master_round6.md; re-read verification passed   (exit 0)
```

Đối chiếu số chốt của vòng (mandate) ↔ master JSON (đọc máy, từng ô):

| Số chốt | Master row | Giá trị | Paper |
|---|---|---|---|
| ladder recall A0→A5 | `ablation.llama3b.C5_near.A{0..5}.recall_vul` | 1.0 / 0.9833 / 0.9 / 0.8475 / 0.8983 / 0.4333 (n=60) | 1.000/0.983/0.900/0.848/0.898/0.433 ✓ |
| flips từng rung | `...A{1..5}.flip_v2b_vs_prev` / `flip_b2v_vs_prev` | 1/5/3/0(+3 hồi phục)/28 ; b2v = 0/0/0/3/0 | 1/5/3/(−3)/28 ✓ |
| thủ phạm reassertion | `verdict.concentration.share_of_net_flips` | `28/34`, rung A5, distributed=0 | "28/34 = 82%" + caveat saturation ✓ |
| p hot rung | `...A5.mcnemar_p_vs_prev` / `..._chi2` | 7.4506e-09 exact / 3.3516e-07 χ²-cc | exact làm chính, χ² ghi footnote ✓ |
| cumulative | `...A5.flip_v2b_vs_A0` / `...A5.mcnemar_p_vs_A0` (+chi2) | 34 ; 1.1642e-10 exact / 1.5186e-08 χ² | p=1.16e-10; footnote 1.52e-08 ✓ |
| C5_far replicate | `ablation.llama3b.C5_far.A5.recall_vul` / `A5_vs_B0.flip_v2b` | 0.3898 ; 36 | "0.390 (59/60 parsed), 36/59" ✓ |
| qwen immune | `ablation.qwen3b.C5_near.A{1,5}.recall_vul` + `A5_vs_A1.*` | 1.0/1.0 ; flips 0 ; p 1.0 ; benign 1→0 = 1 | "1.000 ... 0/60 (p=1.0)" ✓ |
| extension llama | `extension.llama3b.combined.benign.*` | 0.82→0.99, p_exact 1.5259e-05, n=100 | ✓ |
| extension granite | `extension.granite2b.combined.{benign,vul}.*` | 0.0429→0.7143 p_χ² 1.949e-11 ; 0.0571→0.6714 p_χ² 1.504e-10, n=70 | ✓ |
| FP-bias llama | `bias.llama3b.C5_near.flip_benign_to_vul` + `fp_mcnemar_p_exact` | 11 flips (49→60/60), p 9.766e-04 | ✓ |
| FP-bias granite | `bias.granite2b.C5_{near,far}.*` | 20/30 p 1.907e-06 ; 25/30 p 5.96e-08 | ✓ |
| VCI defence | `defense.llama3b.C5_{near,far}.P3_vs_B0.VCI.fn_direction` | 0.6333 / 0.6667 (fp_direction = n/a) | "0.633/0.667" ✓ |
| echo | `evidence.granite2b.C5_near.flip_outputs_echoing_advisory` | 12/20 (llama 2/11; control C0 0/300) | ✓ |
| H-M2 | `derived.delta_vs_A0.llama3b.C5_near.A1` + `...A1.mcnemar_p_vs_prev` | −0.0167 ; 1.0 | Δ=−0.017, p=1.0 ✓ |
| verdicts | `verdict.H_M1` / `H_M2` / `guidance` | SUPPORTED / SUPPORTED / G1 | cả hai framing + G1 ✓ |

Text RQ7b (`05_results.tex` §RQ7b), discussion (mechanization + guidance G1),
abstract/intro/conclusion/method/appendix: đã cập nhật đúng các số trên; figure
`fig_round6.pdf` sinh bởi `make_figures.py::fig_round6` với strict assert trên
grid C5_near (PASS, 20,711 bytes).

## 2. [F2] MINOR fixes (wording, không đổi số)

| # | Issue (nguồn) | Fix của S | File |
|---|---|---|---|
| a | McNemar "exact" chung chung trong khi stats module tự chuyển χ²-cc khi nd≥25 (V1 §5, V2 Issue-1) | Method ghi nhất quán "two-sided exact binomial; continuity-corrected χ² approximation where discordant ≥ 25; both variants stored, χ² is the conservative one, no verdict changes" — ở caption `tab_round6_ablation` + §method (dòng 141) + appendix (dòng 159–160, 74); p exact làm chính ở mọi cell, χ² chỉ trong footnote | `paper/tables/tab_round6_ablation.tex`, `03_method.tex`, `appendix_repro.tex` |
| b | "global risk priming" quá mạnh (V1 MINOR-2: granite C5_near Δ+0.267, CI [−0.067,+0.600], n=15/stratum) | Hạ thành "priming-like; no detectable content-specific trace at this power; zero-API advisory alone suffices" — đã có trong `docs/verdict_bias.md` §4/§6 (107–110, 166–167, 201–206); S sửa tiếp A1_report §5 (đo "C5 risk-context KHÔNG gây refusal…"); paper không dùng chữ "priming" (grep = 0) | `docs/verdict_bias.md`, `reports/round6/A1_report.md` |
| c | "82%" thiếu caveat saturation (V2 Issue-5) | Mọi chỗ "82%" kèm định dạng share-of-net-flips + điều kiện A0 saturated (recall 1.000) + "not an additive component decomposition (A4 recovers 3 flips)": footnote bảng + discussion + RQ7b ("28/34 of the net A5-vs-A0 flips") | bảng + `05_results.tex` + `06_discussion.tex` |
| d | 2 showcase quote từ record KHÔNG flip (204830; 195017/211695 — label=1, y_pred 0→0) + "1 authorized" thực tế 4 (V1 MINOR-1) | `docs/verdict_bias.md` §6: đã ghi rõ quote là minh hoạ echo cùng arm (không thuộc tập 20/25 flip), "occurs 4 times, not 1" + ghi chú [S-R6 correction]; S sửa tiếp `A1_report.md` §5 cùng nội dung (bản ghi label=1 cùng arm, 4 output authorized, samples 195017/211695) | `docs/verdict_bias.md`, `reports/round6/A1_report.md` |
| e | "49/60" dễ đọc nhầm thành tỷ lệ paired (mandate) | 2 vị trí trong `05_results.tex` (caption fig_round5 + RQ7 text): "60/60 vs. **49 records** on C0" | `paper/sections/05_results.tex` (dòng 66, 230) |
| f | Budget 703 thiếu 131 gen run qwen polluté (V2 Issue-2) | Appendix ghi: "Round-6 GPU generations total **834** — 703 in the final files (+131 discarded polluted qwen run-1)"; master row `accounting.new_generations.total_round6_gpu = 834`, `discarded_polluted_qwen_run1 = 131`, `in_final_files = 703` | `paper/appendix_repro.tex` (dòng 165) |
| g | Amendment-1 tự stamp "00:25" ≠ mtime 00:20:02 (V1 MINOR-3) | Prereg doc ghi nhãn amendment theo mtime filesystem 00:20:02 + ghi chú bản thân amendment trước đây tự ghi sai 5 phút | `docs/round6_ablation_prereg.md` (dòng 10–11, 235) |
| h | "63 vị trí" sai, thật ra 56 (V1 NOTE) | A3_report đã sửa kèm ghi chú "[S-Vòng-6 sửa: bản gốc ghi '63 vị trí' — đếm lại sai, V1-R6 xác nhận 56]" | `reports/round6/A3_report.md` (§3) |

Không đổi bất kỳ số kết quả nào; không cần chạy lại generation nào (đúng khuyến
 nghị V1 §7.5 — mọi fix đều chữ/metrics-stage).

## 3. [F3] Master round-6 — đầy đủ + re-read pass

```bash
.venv/bin/python scripts/collect_master_round6.py
# → [ok] wrote outputs/master/round6_ablation.json (134 rows) + round6_token_map.json
#        + docs/results_master_round6.md; re-read verification passed
```

- `outputs/master/round6_ablation.json`: 134 rows, schema
  `ablation.<model>.<arm>.<rung>.<metric>` + `verdict.*` + `extension.*` +
  `accounting.*` + `derived.*`; nguồn từng row ghi `source_file` trỏ vào
  `outputs/experiments/round6_ablation/results_*.json`. Các row paper cần đều
  có mặt (llama C5_near A0..A5 đầy đủ; C5_far A5; qwen A1/A5 spot; extension
  llama n=100 / granite n=70; verdicts; budget 834/703/131).
- `outputs/master/round6_bias.json`: 149 rows (A1), `--verify-only` của
  `analyze_verdict_bias.py` đã PASS bởi V1 ("149 round-6 bias rows re-derived
  from sources and matched").
- `docs/results_master_round6.md`: trang master round-6 đã có (TODO #6 của
  A3 — xong).

## 4. [F4] Final verify — lệnh + output thật

```bash
.venv/bin/python paper/make_figures.py
# → [verify] all table numbers match source files
#   [verify] round-5 table numbers match outputs/master/round5_master.json
#   [verify] 17 headline numbers cross-checked ...
#   [cites] 18 keys used, all present in refs.bib (unused bib entries: none)
#   [ok] 7 figures, trong đó fig_round6.pdf (20711 bytes)

tectonic --outdir paper/compiled paper/main.tex   # → exit 0
#   chỉ overfull-hbox warnings (đã có từ trước); main.pdf 376,622 bytes (368K)

pdftotext paper/compiled/main.pdf /tmp/main_pdf_text.txt
#   pages = 18; '??' = 0; '{{R6' = 0; 'detokenize' = 0
#   '405 passed'/'408 passed'/'442 passed'/TODO/PLACEHOLDER = 0 (0 stale claim)
#   số nóng có mặt: '7.45' ×6, '28/34' ×2, '36/59' ×4, '1.16' ×2, '834' ×3,
#   '0/300' ×2; footnote bảng (χ²-continuity 3.35e-07) render đúng
#   (pdftotext interleaves cột bảng — hiện tượng đã biết từ V1)

.venv/bin/python -m pytest tests/ -q   # → 443 passed, 2 warnings in 44.74s

bash scripts/verify_repro.sh           # → SUMMARY: 30 passed, 0 failed
#   (tăng 27→30 vì thêm round-6: PASS outputs/master/round6_bias.json,
#    PASS outputs/master/round6_ablation.json + value checks; manifest 23/23)
```

Ghi chú: mandate ghi "verify_repro 27/27" kèm điều kiện "cập nhật script nếu
số artifact check đổi" — script đã được nâng 27→30 checks (thêm artifact
round-6) ở phiên trước và PASS 30/30; không có FAIL nào.

## 5. Việc đã/không làm

Đã làm: audit truy vết toàn bộ số round-6 trong paper ↔ master (máy đối chiếu,
từng ô); 8 MINOR fixes [F2]; master re-read [F3]; verify chuỗi đầy đủ [F4];
ROUND6_SUMMARY.md [F5]; báo cáo này [F6].
Không làm (đúng phạm vi): KHÔNG sửa `src/`, `configs/`, tests; KHÔNG chạy
generation; KHÔNG git commit; không đổi bất kỳ số kết quả nào.
