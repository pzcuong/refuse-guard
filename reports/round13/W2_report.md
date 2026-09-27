# ROUND 13 — W2 REPORT: REWRITE toàn bộ paper2 theo thesis mới (P3-15/16)

Agent: W2 (owner `paper2/`). Ngày: 2026-09-27. Không gian sửa:
`paper2/main.tex` (viết lại toàn bộ) + `reports/round13/W2_report.md` (file này).
KHÔNG đụng `packguard/`, `scripts/`, `outputs/`, `paper2/p0_macros/numbers.tex`
(336 macro giữ nguyên bit-for-bit), `paper2/refs.bib`, không git commit, không bịa số.

## 1. What was done (làm gì)

Rewrite hoàn chỉnh `paper2/main.tex` theo thesis mới của reviewer:
**"Untrusted in-package content is a domain-dependent, family-dependent attack
surface on LLM package analyzers — and AST-level sanitization closes it."**
FL/behavior-graph bị lùi xuống detector nền; federation-robustness chứng minh bằng
TOST; mọi số giữ nguyên qua macro `numbers.tex` hoặc literal có `% SRC:`.

### 1.1 Cấu trúc mới (đối chiếu yêu cầu P3-15/16)

| Phần mới | Nội dung |
|---|---|
| Title | Đổi thành *"The Advisory Inside: Measuring and Closing an In-Package Attack Surface on LLM Package Analyzers"* |
| Abstract | ≤250 từ (thật: **237 từ rendered**), đúng 3 contributions C1/C2/C3, RR=0 gọn 1 câu |
| §1 Intro | 3 contributions: C1 measurement, C2 defense, C3 background detector (bỏ danh sách 5 contributions cũ) |
| §2 Related | Giữ, gọt phần safety-layer line |
| §3 Threat model & design | 3.1 arms P0/P1/P2 + metrics (fp_bias saga rút còn 1 câu, trỏ Threats); 3.2 D1 + AST gate + strip-equality + two-directional hypotheses; 3.3 detector nền (graphs + FL + corrected baseline `lbfgs` + scaler + C-CV, gọn) |
| §4 Setup | Corpus/provenance + coverage inline (bảng coverage bỏ); splits; statistics (20 seeds, TOST ±.02, Holm) |
| §5.1 Attack (C1) | RR=0 ngắn (macro \pmGenDefTotal=2,700 + probe 125/225); bảng n=60 (giữ nguyên cấu trúc hàng cho `--check`); recall-perturbing 2 chiều; n=100 mở rộng (pooled + per-model divergence + FP 2/100 granite); mechanism ablation 1 câu |
| §5.2 Defense (C2) | D1 + gate + realized 24 mal/14 ben (gate loại 7 comment-only, Fisher p=.40); strip-equality **38/38**; 10 comment-free byte-identical prompt+completion; power disclaimer (min exact p=.125, 0-discordant vô thông tin); bảng per-model; granite neutralized (23/23 parsed, 4/4 flips revert, FP 0/14, H-D1+H-D2 pass) vs llama not-restored (1-family, 19 families, byte-identical snippets); pooled chỉ để "for completeness" |
| §5.3 Detector (C3) | tab:main + tab:stats (giữ, caption bỏ nhãn AMENDMENT); TOST PASS; random/graph directional win disclosed; trivial baseline (macros +.0227/+.0487, p 1.9e-5/1.9e-6, subset non-empty); graph-vs-text split-dependent; DP/MLP/KB nén còn đoạn "Sensitivity and knowledge base, compressed" |
| §5.4 **Federation-robustness under family shift** (MỚI, P2) | Subsection LFO với {{R13:*}} placeholders bọc \detokenize (xem §4 dưới) |
| §6 Discussion | Domain-dependence (granite ladder 2 câu, chi tiết số + caveats → appendix); sanitization necessary-not-sufficient; detector layer contributes |
| §7 Threats to Validity | 4 mục audit history gọn (fp_bias rename, retraction text-degradation, minority-harm bug + collapse = undertraining, FedProx routing); power; external validity + scale — **1 câu 8B** + **1 câu three-client** (đúng giới hạn cho phép) |
| §8 Conclusion | Thesis + limitations ngắn |
| Data & provenance | Giữ (sloppypar), cập nhật danh sách artifact |
| Appendix A (MỚI, sau refs) | A.1 registered-protocol history (AMENDMENT-1..-6, metrics semantics); A.2 retracted/re-attributed (số đầy đủ); A.3 grid refresh + calibration; A.4 stabilized arm + μ-sweep + three-client + sensitivity arms; A.5 KB ablation detail (tab:kb chuyển xuống đây); A.6 safety details (n100 selection, mechanism ablation); A.7 granite ladder full; A.8 8B feasibility full |

### 1.2 Abstract word count

**237 từ** (script đếm trên abstract RENDERED: strip comment, expand 336 macro,
đếm token chứa chữ/số; số trong math được đếm từng token). Ghi trong comment ngay
trên `\begin{abstract}`. Giới hạn 250 — còn dư 13 từ.

### 1.3 Ba contributions (đúng yêu cầu)

- **C1 measurement**: advisory-in-package gây recall-perturbing family-dependent
  trên malicious packages — granite `.667→.833` (+.167 hướng tăng, kèm FP benign
  xuất hiện ở scale: `0→2/50` quoted từ n100), llama `.167→.042` (−.125 hướng giảm);
  2 chiều đều có hại cho một scanner; benign FP = 0 trong paired measurement
  (0/180); RR=0 bác bỏ giả thuyết refusal (1 câu ngắn, scope 2,700).
- **C2 defense**: AST sanitization (comment/docstring strip, AST-equivalence gated)
  trung hòa hoàn toàn trên granite (P2D1 ≡ P0 trên 23/23 cặp parsed; 4/4 flips
  revert; FP 0) + chi phí đã đo trên llama (1-family); strip(P2)==strip(original)
  **38/38** chứng minh defense đúng nghĩa attack-removed.
- **C3 detector nền**: TOST equivalence PASS (ΔF1 −.0065, CI [−.0133,+.0003] ⊂
  ±.02) với strong centralized baseline (lbfgs + train-fit scaler + C-CV); graph
  beat trivial-structural (+.0227/+.0487, p ≤ 1.9e-5) — refinement not replacement.

## 2. Files (ownership)

- `paper2/main.tex` — REWRITE toàn bộ (file duy nhất bị sửa).
- `reports/round13/W2_report.md` — file này.
- KHÔNG sửa: `paper2/p0_macros/numbers.tex` (336 macro nguyên vẹn — `--check` OK),
  `paper2/refs.bib`, `packguard/`, `scripts/`, `outputs/`. Không git commit.

## 3. How to run (cách chạy / kiểm chứng)

```
cd paper2 && tectonic main.tex              # exit 0; PDF 8 trang
.venv/bin/python scripts/gen_paper_numbers.py --check
                                             # OK -- 336 macros verified
# đếm từ abstract (rendered): script trong W2 report §5
# hygiene grep (comment-stripped): round-N / "8B feasibility" / "three-client"
```

## 4. Danh sách {{R13:*}} placeholders (cho F điền)

Subsection `\subsection{Federation-robustness under family shift}`
(`\label{sec:lco}`) — số LFO của W1 chưa có; mỗi token nằm trong
`\detokenize{{{...}}}` nên compile sạch trước khi điền (đã probe: token render
thành text searchable trong PDF). **7 token, cùng một subsection:**

| Token | Nghĩa kỳ vọng |
|---|---|
| `{{R13:LFO_GRAPH_DF}}` | ΔF1 graph block dưới leave-families-out |
| `{{R13:LFO_GRAPH_CI}}` | 95% CI của ΔF1 graph |
| `{{R13:LFO_TEXT_DF}}` | ΔF1 hashing/text block dưới LFO |
| `{{R13:LFO_TEXT_CI}}` | 95% CI của ΔF1 text |
| `{{R13:LFO_FOLDS}}` | số fold/hold-out family (mô tả protocol) |
| `{{R13:LFO_CONTRAST}}` | tương phản paired graph-vs-text degradation |
| `{{R13:LFO_TEST}}` | tên test paired + `{{R13:LFO_P}}` p-value |

F điền bằng cách thay cả cụm `\detokenize{{{R13:...}}}` bằng giá trị LaTeX
(macro mới hoặc literal + `% SRC:`), rồi chạy lại `--check` + tectonic.

## 5. Self-test thật (lệnh + output)

1. `.venv/bin/python scripts/gen_paper_numbers.py --check`
   → `GEN-NUMBERS CHECK: OK -- 336 macros verified against artifacts (640 grid
   rows, 20 seeds).` (exit 0) — chạy trên main.tex MỚI; mọi needle
   (tab:main/tab:stats/tab:safety/tab:kb rows — tab:kb còn nguyên trong
   Appendix A.5, 2,700 / 603 / 137/137 / 2,299 / 500/603 / TOST CI / Holm .025 /
   trivial deltas) đều tìm thấy sau macro expansion.
2. `cd paper2 && tectonic -X compile --keep-logs main.tex`
   → `Output written on main.xdv (8 pages)`; exit 0; **0 Overfull \hbox**
   (còn đúng 1 `Overfull \vbox (1.44199pt)` lúc \output — column-balancing,
   vô hình); 0 undefined/multiply-defined references; bookmarks A.1–A.8 đủ.
   Hai bảng tab:safety/tab:defense đổi sang `\footnotesize` để hết overfull
   (layout-only, số không đổi); fix overfull đoạn Metrics bằng `{\sloppy ...}`.
3. Abstract word count (script tự viết, đếm trên rendered abstract):
   **237** (giới hạn 250).
4. Hygiene grep trên text đã strip comment:
   `round-8|round-9|round-10|round-\d` → **0 hit** toàn bài (chỉ còn path
   artifact `r10/r8_safety_expand/...` trong \path của Data-and-provenance —
   đường dẫn file, không phải nhãn vòng);
   `AMENDMENT` → **0 hit** trong visible text (chỉ trong `% SRC:` comments);
   `8B feasibility` → 0 hit; `three-client` → đúng 1 hit ở Threats (1 câu, đúng
   giới hạn "appendix/threats 1 câu"); `${\ge}8$B` → 1 câu ở Threats + full ở
   Appendix A.8.
5. Placeholder probe: compile thử `\detokenize{{{R13:LFO_GRAPH_DF}}}` trong
   document tối giản → token xuất hiện searchable trong PDF (chứng minh F grep
   được trong PDF sau khi điền).

## 6. Deviations from the task text (lệch chuẩn, all disclosed)

1. **`outputs/packguard/safety/safety_metrics_n100.json` không tồn tại ở path
   task nêu** — file thật là
   `outputs/packguard/r10/r8_safety_expand/safety_metrics_n100.json` (W1 round-12
   đã ghi lệch path này trước đó); dùng path thật (read-only).
2. **`tab:kb` không bị xóa mà chuyển xuống Appendix A.5**: `--check` của
   `gen_paper_numbers.py` bắt buộc tồn tại hàng `FedAvg &`/`centralized &`
   (check_main `expect()` raise "table row not found" nếu thiếu) — giữ bảng ở
   appendix vừa sạch check vừa đúng yêu cầu "main text bỏ KB ablation".
   Tương tự, needle `640/640` nằm trong Appendix A.3.
3. **Title đổi** — quyền sở hữu main.tex cho phép tái cấu trúc tự do; title cũ
   nêu "Cross-Language Behavior Graphs, Federated Learning, Safety Layer as
   Third Threat" không còn khớp thesis mới (FL/graph giờ là detector nền).
   Nếu orchestrator muốn giữ title cũ: đổi 1 dòng, compile lại (không ảnh hưởng
   số).
4. **Bảng coverage bỏ** (số chuyển inline macro trong §4 Setup); caption
   tab:main/tab:stats bỏ nhãn "AMENDMENT-5" (thay bằng "registered before the
   run") để đáp ứng "không audit-log trong main text" — chữ trong `% SRC:`
   comments giữ nguyên.
5. **C1 abstract dùng số r12 gate-passers** (.667→.833 / .167→.042, đúng
   +.167/−.125 yêu cầu task) — là literal có `% SRC` (không có macro); thân bài
   dùng bảng n=60 macro (.533→.800 / .133→.033) + n100 macro. Cả hai nguồn đều
   verified, không trộn lẫn trong một câu.
6. **1 Overfull \vbox 1.44pt** còn lại (column balancing cuối bài) — không sửa
   được mà không đụng flushend; vô hình ở mức sub-point.

## 7. Literals dùng trong main.tex (cho F đối chiếu — tất cả có `% SRC:` tại chỗ)

- Defense pairing (SRC: `outputs/packguard/defense/defense_analysis.json` +
  `defense_metrics.json` + audit `reports/round12/V1_report.md`): recalls
  .167/.042/.042 và .667/.833/.652; flips +1/−1 (llama), 0/−4 (granite);
  p=1.0/.125; FP 0/50→0/14, 2/50→0/14; pooled .417/.438/.340; 1 vs 5 (p=.219),
  1 vs 4 (p=.375); FP 0/28 defended; 38/45 gate-pass; 24 mal + 14 ben; Fisher
  p=.40; 19 families; 2500-char byte-identical; 23/23 parsed; 4/4 revert;
  strip-equality 38/38; 10 comment-free; 0/76 sha mismatch (comment).
- Abstract: .667→.833, .167→.042, 23/23, 38, 4 flips (SRC như trên).
- Discussion granite ladder: .7627→.0667, 41/0, p≈4e-10, 20/30, p≈1.9e-6
  (SRC: `outputs/experiments/r10_granite_ladder/metrics_round9.json`).
- Sensitivity arms: DP ε≈48.4/round, F1 0.915 (−0.8pt), 0.821 (n=500)
  (SRC: `outputs/packguard/fl/results.jsonl`).
- KB mixed-sign: +0.0103/+0.0112, −0.0009/−0.0224; pypi .875→.966 (n=36);
  113/122 confidence clip .90 (SRC: `r10/r4_kb_v3`, `fl/results.jsonl`).
- Mechanism ablation: .6000→.6667 (p=.5), →.6333 (p=1.0), .1333→.2333 (p=.25),
  →.1667 (p=1.0); 96/180 cache hits (SRC: `r10/r7_mechanism_ablation`).
- Appendix: collapse cells .375/.326, 0/80 converged, min F1 .769, n_iter 69;
  597→603; 35% leakage; ECE/Brier + oracle thresholds; 640/640; 19,484
  (12,680/6,804); npm_hook 214/114/146, 99.1%, p=1.0; 8B: 1.11 tok/s, ≈31h,
  4 MPS failures (SRC: từng dòng `% SRC:` trong file).

## 8. TODO / handoff

- **F điền 7 token {{R13:LFO_*}}** ở `\subsection{...}\label{sec:lco}` khi W1
  xong LFO; sau đó: bỏ dấu ngoặc `{R13:...}` (điền giá trị thay toàn cụm
  `\detokenize{{{...}}}`), chạy `--check` + tectonic, cập nhật PDF.
- Nếu muốn đếm trang ≤ giới hạn venue: bài hiện **8 trang** gồm appendix
  (main body ~6 trang tới hết References); cắt appendix dễ dàng (A.3/A.4/A.8
  tách được) mà không đụng main text.
- TitLe là quyết định editorial của orchestrator (deviation #3).
- Hai đề xuất đã có sẵn trong text: validation-locked threshold + FP-directed
  advisory arm ("this code is clean") vẫn queued (nêu trong A.6).
