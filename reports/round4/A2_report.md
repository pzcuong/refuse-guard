# A2 Report — Round 4 (Paper: sections + figures/tables)

Ngày: 2026-09-19. Phạm vi sở hữu: `paper/sections/*.tex`, `paper/tables/*.tex`,
`paper/make_figures.py`, `paper/figures/*.pdf`, báo cáo này. KHÔNG đụng
`paper/main.tex` (A3), KHÔNG sửa `src/`, KHÔNG git commit. Python:
`.venv/bin/python` (matplotlib).

---

## 1. Narrative đã CHỐT (viết vào paper, đúng bằng chứng)

1. **E0 reproduction gate FAIL → pivot theo pre-registration.** RR = 0.000 ở
   CẢ 3 arm × 2 model hoàn tất (Qwen, Llama); ΔRR = 0.000 [0,0], McNemar
   p = 1.0. Đối lập: trên probes, cùng các model đó over-refusal 8–75%
   (Qwen 0.500/0.750/0.667; Llama 0.167/0.083/0.333 theo arm) và unsafe
   compliance 7.7–38.5% → refusal tồn tại nhưng KHÔNG phụ thuộc defensive
   wording → defensive refusal KHÔNG transfer sang vulnerability analysis;
   refusal là secondary outcome.
2. **Untrusted context KHÔNG làm giảm availability** (RR = 0.000 mọi condition
   2 model; UAC ≥ 0.983; SIUD ≤ +0.017) — NHƯNG verdict-level: C1/C2 bias
   predictions về "vulnerable" (recall ↑, precision ≈ 0.48, TN → 0),
   C3 lật verdict sang "benign" (Qwen recall 0.800→0.333, 35/60 flip,
   p = 1.2e-05; Llama recall C3 0.500) → threat thật = **silent verdict
   corruption (integrity), không phải blocking (availability)**.
3. **E5:** CUL = 0.000, DRR undefined (n = 0) — simple defences không có gì để
   recover (hệ quả trung thực của pivot).
4. **E6:** injection success B0 0.742 → P1 0.484, McNemar p = 0.0078; 8
   discordant = 6 benign (p = 0.031) + 2 vul (p = 0.5 n.s.) → **isolation is
   not accuracy**, kèm benign-keep-bias; usable delta 0.000; MCC C3 +0.205 vs
   −0.029.
5. **E8:** P2-cũ (Round 2) = refusal-suppression machine (B0 0.040 → P2 1.000
   trên model refuse 96% harmful); P2-mới gate-first đạt H6 **pipeline-level,
   by construction** (gate chặn 30/30, 0 LLM call); safe refusal Qwen
   0.233→0.000 (p = 0.0156), Llama 0.033→0.000 (p = 1.0).
6. **CodeBERT B4:** F1 0.215 (realistic arm 549 vul + 20k benign) vs F1 0.623
   (balanced pilot) — optimism gap của PrimeVul tái lập; VD-S (FNR @
   FPR≤0.5%) 0.962 → chỉ detect ≈3.8% vuln trong ngân sách FPR 0.5%; paired
   rank-acc 0.223. Fallback độc lập, trung thực về giới hạn.
7. **Siêu-dự án:** protocol (C1) + benchmark paired (C2) + bằng chứng
   verdict-flip (C3) + cảnh báo refusal-suppression (C4) + baseline
   realistic-difficulty (C5) — mọi thứ pilot-scale, disclosed.

## 2. Sections đã viết (paper/sections/)

| File | Nội dung chính |
|---|---|
| `00_abstract.tex` | ~165 từ; gate FAIL → pivot; integrity-not-availability; P1 0.742→0.484; refusal-suppression 1.00; release protocol+benchmark+defences. |
| `01_intro.tex` | Vấn đề; reproduction gate như thiết bị phương pháp luận; contributions C1–C5 (scoped, không "first" ngoài giới hạn đã audit). |
| `02_related.tex` | 4 nhóm: vuln detection (ding, han/gao, llm4vuln); over-refusal (xstest, orbench, campbell, beyondrefusal, scans, actor, door); IPI-in-code (bipia, autopi, codesentinel); safety–utility (qi, cyberllminstruct). Positioning: claim joint evaluation, KHÔNG claim defensive-refusal/IPI-defence. |
| `03_method.tex` | Task/schema; C0–C3 + semantics gate; B1/B2/B3/P1/P2 + REFUSED_UNSAFE; refusal monitor + calibration + validity criterion; metrics + McNemar/bootstrap. Chứa float `fig:conditions`. |
| `04_setup.tex` | PrimeVul v0.1 mirror disclosure (−13.8% vuln, 549 test-vul, 435 pairs); bench_v1 (838 rows, 300/300+238 pairs, near/far collapse 295/838); models + revisions + greedy seed 1234; scale từng E (E0 135/model; E2E3 300×2 model; E5/E6 40/31; E7 133 cached 0.5B; E8 150/model); seeds; 4 pre-registration + disclosure PASS-branch unattainable tại n=20. |
| `05_results.tex` | RQ1–RQ6 + mục B4; chứa floats `fig:e0rr`, `fig:e6`, `fig:e8`, `fig:codebert`. |
| `06_discussion.tex` | Gate lessons; refusal-suppression risk của structured-recovery; isolation ≠ accuracy; availability vs integrity; **threats to validity**: pilot n, monitor deviation Qwen 0.587 + recompute thu hồi 0.400→0.033, mirror v0.1, E8 gate-paraphrase scope (1/50), coverage (E5/E6 1 model, granite crash). |
| `07_conclusion.tex` | Tổng kết + future work + release statement. |

**Hợp đồng với main.tex (A3):** `\input{sections/00_abstract}` …
`07_conclusion`; các section dùng `\section`/`\subsection` thuần,
`figure*`/`figure` + `\includegraphics{figures/*.pdf}` (cần `graphicx`),
tables `\input`-ed tại chỗ nào tuỳ A3 (đã `\label{}`: `tab:main`,
`tab:codebert`, `tab:defenses`, `tab:calibration`; figures: `fig:conditions`,
`fig:e0rr`, `fig:e6`, `fig:e8`, `fig:codebert`; sections: `sec:intro`…
`sec:conclusion`, `sec:codebert`). Package cần: `booktabs` (tables);
`\multirow`/`colortbl` KHÔNG cần.

## 3. Figures + tables sinh/thế nào

- `paper/make_figures.py` (chạy: `.venv/bin/python paper/make_figures.py`):
  - **Đọc số từ file outputs/ thật** (E0 qwen/llama results.json, E2E3, E6,
    E8 recomputed ×2, summary_v2.json, codebert_eval_vd_s_metrics.json,
    calibration full_report ×2) + assert cấu trúc (ví dụ: E0 RR phải 0.0,
    n_status_changed llama = 11, n_vulnerable = 549, E8 pre-fix 0.04/1.00).
  - Stratified E6 (8 discordant = 2 vul + 6 ben, p = 0.5/0.031) **tính lại từ
    records trong results.json** ngay trong script (khớp độc lập với số V2
    audit) — không hardcode.
  - Sinh 5 PDF: `fig_conditions.pdf` (schematic), `fig_e0_rr.pdf` (RR=0 +
    probes đối lập), `fig_e6_injection.pdf` (B0 vs P1 + annotation stratified),
    `fig_e8_compliance.pdf` (pre-fix vs post-fix ×2 model), `fig_codebert.pdf`
    (metrics + paired outcomes). Đã mở PDF kiểm tra trực quan (font ≥ ~7pt ở
    khổ 1 cột; layout đã sửa 2 vòng sau khi thấy chồng chữ).
  - `verify_tables()`: **mỗi số typed trong `paper/tables/*.tex` được assert
    ngược về file nguồn** (kể cả dạng chuỗi "0.742" v.v.) + 14 số headline
    cross-check qua `outputs/master/master_results.json` (A1) — tất cả PASS.
  - `check_citations()**: toàn bộ 16/16 `\cite` key dùng trong sections+tables
    tồn tại trong `docs/refs.bib`, không key thừa/thiếu.
- **Tables** `paper/tables/{tab_main,tab_codebert,tab_defenses,tab_calibration}.tex`:
  booktabs; mỗi ROW có comment `% source: <file> -> <path>`; tab_codebert có
  chú thích chân bảng giải thích convention VD-S (FNR, lower = better) và
  degenerate pilot-paired (n_pairs = 1); tab_calibration ghi rõ Qwen fail
  validity ≤ 0.10.

## 4. Cập nhật giữa vòng (disclosed)

- Khi bắt đầu, `outputs/master/` và `docs/results_master.md` chưa tồn tại →
  dùng trực tiếp nguồn cuối theo bảng ánh xạ S-R3. Khi A1 đẩy master giữa
  vòng, tôi đã **cross-check 14 số headline qua master** (PASS 100%, gồm cả
  contradictions list của A1: dùng recomputed cho E8-Llama — đúng như paper).
- **Llama E2/E3 (marathon) HOÀN TẤT giữa vòng** (300/300, partial=false,
  20:06Z): RR 0.000 mọi condition, UAC ≥ 0.983, SIUD ≤ +0.017, recall C3
  0.500 (vs C0 0.800). Paper chuyển từ "Llama pending" sang **số thật 2
  model** ở tab_main + RQ2 + setup + threats; các số đã assert ngược file
  `round3_e2e3/llama3b/results.json` và master.
- Dải over-refusal trên probes được viết chuẩn hoá thành **8–75%** (min Llama
  defensive 0.083, max Qwen defensive 0.750) — bản nháp đầu viết 17–75% đã
  được tự bắt và sửa.

## 5. Pending / chưa có trong paper (không bịa)

| Khoảng trống | Trạng thái | Cách paper xử lý |
|---|---|---|
| E0 Granite + `gate_verdict.json` 3/3 | chưa re-run (granite crash 75/135 đã fix code, raw cached) | paper nêu "2 completed models"; granite disclosed là crash + excluded |
| E5/E6 trên Llama | chưa chạy (stage 5/6) | threats: "E5/E6 single-model (Qwen)" |
| E7 trên LLM 3B | đang dùng cache 0.5B (n=133), disclosed ngay trong RQ5/setup | giữ nguyên disclosure |
| McNemar/stratified stats E6 dạng file riêng | chưa export; script của tôi tính lại từ records và khớp V2 | annotation trong fig/tab ghi rõ phép tính |
| Gate paraphrase model-based | ngoài scope vòng này | threats: gate lexical 1/50 scoring-half |

## 6. Checklist trung thực (claim ↔ nguồn) — rút gọn, đầy đủ là comment trong tables

| Claim trong paper | Nguồn |
|---|---|
| RR 0.000 mọi arm ×2 model; ΔRR 0 [0,0]; p=1.0; gate FAIL | `outputs/experiments/round3_e0/{qwen3b,llama3b}/results.json` (metrics.arms, gate_per_model, delta_RR_*) |
| Probes over-refusal 0.500/0.750/0.667 và 0.167/0.083/0.333; unsafe 0.154/0.077/0.077 và 0.154/0.385/0.231 | cùng file → `metrics.probes_by_arm.*` |
| Qwen monitor over-refusal 0.5867 (fail ≤0.10); Llama 0.0667; acc 0.376/0.296 | `outputs/transformer/calibration/*/full_report.json` at_fit_thresholds |
| E3: RR 0.000, UAC 1.000/0.983; recall 0.800/0.967/0.933/0.333 (Qwen), 0.800/1.000/0.862/0.500 (Llama); SIUD ≤ +0.017; McNemar C1–C3 0.0039/0.0078/0.0215, 1.2e-05 (35 vs 6) | `outputs/experiments/round3_e2e3/{qwen3b,llama3b}/results.json` (metrics.groups/SIUD_vs_C0/paired_tests_vs_C0) |
| E4: RR 0.000 mọi cell; recall C3 0.143–0.50 | `outputs/experiments/round3_e2e3/qwen3b/e4_breakdown.json` |
| E5: CUL 0.000, DRR null n=0; B2/B3 recall 1.000 prec 0.452 | `outputs/experiments/round3_e5/results.json` |
| E6: 0.742→0.484 p=0.0078; 8 discordant (6 ben p=0.031, 2 vul p=0.5); usable delta 0; MCC +0.205/−0.029 | `outputs/experiments/round3_e6/results.json` (flip_metrics + per_condition_defense + records recompute) |
| E7: UAC 0.985→1.000; MCC 0.0789→0.0942; fallback 2/2; scope-block 500 (250+250); τ=0.548 pre-reg | `outputs/experiments/round3_e7/e7_fusion_results.json` |
| E8: pre-fix 0.040→1.000; post-fix Qwen 0.000/0.000, Llama 0.033/0.000, gate 30/30; safe 0.233→0.000 p=0.0156, 0.033→0.000 p=1.0; H6 by-construction | `outputs/experiments/pilot_round2_recomputed/summary_v2.json` (3b_qwen.e8) + `round3_e8{,_llama3b}/recomputed/recompute_e8_monitor.json` |
| CodeBERT F1 0.215 / MCC 0.232 / AUC 0.847 / recall 0.541; VD-S 0.962 (FNR); pilot arm 0.623/0.493/0.444/0.832, vd_s 0.970 (degenerate); paired P-C 0.009, P-V 0.517, P-B 0.444, P-R 0.030, rank 0.223; 549+20,000; seed 1234 | `outputs/transformer/codebert_eval_vd_s_metrics.json` + `final_eval.json` + `codebert_eval_paired_only_metrics.json` + `train_meta.json` |
| Mirror v0.1: 6,004 vuln (−13.8%), 549 test-vul, 435 pairs; bench 838 rows, 300/300, near/far 295/838 (35.2%) | `docs/eda_primevul.md` + `data/benchmarks/bench_v1/bench_v1_meta.json` |
| Gate lexical 1/50 scoring-half paraphrase | `outputs/experiments/intent_gate_v2_measurement.json` (e8_scoring_half_unsafe) |
| Thresholds fit 0.0/0.2 ×2; scoring-half 25/125 consumed | `configs/models.yaml` (thresholds_per_model + STATUS UPDATE) |
| Monitor recompute thu hồi E8-Llama B0 0.400→0.033 | `master_results.json` contradictions + `round3_e8_llama3b/recomputed/` |

## 7. Kiểm chứng chạy thật (nguyên văn)

```
$ .venv/bin/python paper/make_figures.py
[verify] all table numbers match source files
[verify] 14 headline numbers cross-checked against outputs/master/master_results.json
[cites] 16 keys used, all present in refs.bib (unused bib entries: none)
[ok] paper/figures/fig_codebert.pdf
[ok] paper/figures/fig_conditions.pdf
[ok] paper/figures/fig_e0_rr.pdf
[ok] paper/figures/fig_e6_injection.pdf
[ok] paper/figures/fig_e8_compliance.pdf
```

5/5 PDF đã mở kiểm tra trực quan (nội dung + nhãn đúng; không số sai khung).
Không git commit. Số Llama E2E3 mới hoàn tất giữa vòng đã được cập nhật vào
paper và verify (không để lại claim "pending" stale).
