# A3 Report — Round 4 (LẮP BÀI BÁO LaTeX + REPRODUCIBILITY PACKAGE)

Ngày: 2026-09-19 (02:49–03:30 +07). Root:
`/Users/macbook/.zcode/workspace/default/refuseguard`. Sở hữu: `paper/main.tex`,
`paper/preamble.tex`, `paper/refs.bib`, `paper/appendix_repro.tex`,
`paper/compiled/`, `README.md`, `requirements.txt`, `requirements-lock.txt`,
`scripts/verify_repro.sh`, báo cáo này. KHÔNG đụng `paper/sections/`,
`paper/tables/`, `paper/figures/`, `paper/make_figures.py` (A2-R4), KHÔNG sửa
`src/`, KHÔNG git commit.

---

## 1. Quyết định documentclass [L1]

**`acmart` DÙNG THÀNH CÔNG — không cần fallback `article`.** Tectonic 0.16.9
(`/opt/homebrew/bin/tectonic`) tải `acmart` + toàn bộ font stack (Linux
Libertine/Biolinum, Inconsolata) từ bundle lần đầu chạy (có mạng). Test tối
thiểu trước khi quyết định:

```
\documentclass[sigconf,review,anonymous]{acmart} → tectonic t.tex → t.pdf OK
```

Lựa chọn option: `sigconf` (two-column conference), `review` (line numbers +
manuscript footer — dùng cho nộp review), `anonymous` (ẩn tác giả; đi kèm
placeholder `\author{Anonymous Author(s)}` + footnote "Authors' addresses
withheld"). Trong main.tex còn đặt `\settopmatter{printacmref=false,
printfolios=true}` (chuẩn cho review submission — không in khối ACM reference
mới, giữ số trang).

**Title dùng nguyên đề bài** (đúng narrative thực tế — E0 FAIL→PIVOT nên
"Robust … under Safety-Induced Blocking and Untrusted Code Context" khớp cấu
trúc "refusal không tái lập; integrity là threat chính"):
"RefuseGuard: Robust LLM-Based Vulnerability Detection under Safety-Induced
Blocking and Untrusted Code Context".

## 2. Xử lý song song với A2 [L2]

- Viết main.tex + preamble + refs.bib **trước** với stub-check
  `\InputIfFileExists{…}{}{\missingsection{…}}` (fallback in khung
  `[DRAFT PLACEHOLDER]`), draft compile PASS ngay khi `paper/sections/` chưa
  tồn tại.
- **Bug draft mode đã sửa:** placeholder dùng `\texttt{sections/00_abstract}`
  → `_` trong text mode gây "Missing $ inserted". Fix bằng
  `\texttt{\detokenize{#1}}` trong preamble.
- Poll định kỳ; A2 thả file lần lượt (00_abstract → 07_conclusion). **Tên file
  thực tế của A2 khác dự phóng** (`01_intro`, `02_related`, `03_method`,
  `04_setup`, `05_results`, `06_discussion`, `07_conclusion`) → main.tex đã
  được cập nhật theo tên thật sau khi đủ bộ.
- Contract với abstract: file `00_abstract.tex` của A2 tự mang
  `\begin{abstract}…\end{abstract}` → main.tex `\InputIfFileExists` nó TRƯỚC
  `\maketitle` (yêu cầu của acmart), KHÔNG bọc thêm env.
- Tables: 4 file `tables/tab_*.tex` là float hoàn chỉnh (`\caption` + `\label`
  sẵn) nhưng sections chỉ `\ref` chứ không `\input` (đúng như dự kiến hợp đồng
  "tables `\input`-ed tại chỗ nào tuỳ A3" trong A2_report) → main.tex
  `\input` cả 4 ngay trước `05_results` (float `[t]`, LaTeX tự đặt trang kết
  quả).
- **Sự cố compile lúc A2 đang ghi file:** một lần compile giữa poll báo
  "Missing $ inserted @ \maketitle" rồi 3 lần chạy liên tiếp sau đó PASS 3/3 —
  khớp thời điểm A2 còn đang ghi `05_results`/`06_discussion`/`07_conclusion`.
  Không có lỗi nào tồn tại trong trạng thái file cuối; mọi compile trên bộ file
  cuối đều sạch.

## 3. Compile [L3] — trạng thái cuối

Lệnh chuẩn (từ root):

```bash
tectonic --outdir paper/compiled paper/main.tex
cp paper/compiled/main.pdf paper/compiled/refuseguard_paper.pdf
```

Log cuối (nguyên văn, các dòng chính):

```
note: Running TeX ...
note: Running BibTeX on main.aux ...
note: Running xdvipdfmx ...
note: Writing `paper/compiled/main.pdf` (274.0947265625 KiB)
```

```
$ echo exit=$?  → exit=0
$ grep -cE "^error" run_final.log → 0
$ grep -aiE "undefined|multiply defined" run_final.log → (0 dòng)
$ pdfinfo paper/compiled/refuseguard_paper.pdf
    Pages: 10
    Page size: 612 x 792 pts (letter)
    Creator: LaTeX with acmart 2022/02/19 v1.83 …
$ pdftotext … && grep -c "??" → 0
```

**PDF: `paper/compiled/refuseguard_paper.pdf` — 10 trang** (target 10–14),
280,671 bytes, SHA256 khớp từng byte với `main.pdf` cùng thư mục.

Kiểm tra chất lượng đã chạy:
- **Số trang 10** ✅ (9 trang nội dung trước khi thêm appendix — xem §5).
- **Không có `??`** trong text extract ✅; 0 undefined reference/citation ✅.
- **5/5 figure render thật** (đã render trang 5–7 bằng pdftoppm và xem ảnh:
  fig_e0rr, fig_e6_injection, fig_e8_compliance, fig_codebert là chart thật có
  số liệu; fig_conditions ở trang method) ✅.
- **4/4 bảng** (tab:main, tab:calibration, tab:defenses, tab:codebert) + 1 bảng
  traceability ở appendix ✅.
- **Bibliography: ACM-Reference-Format** (BibTeX style
  `ACM-Reference-Format-Journals`) — 21 entry được cite, mỗi entry có DOI/URL
  khi có ✅.

## 4. Reproducibility package [L4]

### 4.1 `README.md` (root, MỚI)
Mô tả dự án + headline findings (đúng narrative A2 chốt), kiến trúc repo,
environment, và **8 bước chạy lại từ đầu**: (0) venv + requirements;
(1) `src.data.primevul` download+validate; (2) `src.data.sampling`;
(3) `src.data.bench_build configs/data_bench.yaml v2 bench safety e0`;
(4) `scripts/train_codebert.py` + `scripts/eval_codebert.py` (+`--paired-only`
audit); (5) `scripts/calibrate_refusal_monitor.py --full/--refit-only`;
(6) LLM runs: `src.experiments.round3_scaleup --stage e0|e2e3|e4|gate|summary`
(E0/E2/E3/E4) + `src.experiments.pilot_round3 --exp e5|e6|e8` + Round-1
config-driven runners `run_eN --config configs/eN.yaml --dry-run` (giữ cho
dry-run); (7) collect master: `scripts/final_eval_summary.py` + các script
recompute/audit; (8) `tectonic --outdir paper/compiled paper/main.tex`.
Kèm mục provenance rules và số trang target.

### 4.2 `requirements.txt` + `requirements-lock.txt`
- `requirements.txt`: curated **level cao, pin đúng version .venv** (torch
  2.14.0, transformers 5.17.0, datasets 5.0.1, scikit-learn 1.9.1,
  statsmodels 0.15.0, tree-sitter 0.21.3 + languages 1.10.2, matplotlib,
  pyarrow, pytest 9.1.1, …) theo nhóm (LLM stack / stats / parsing / I-O /
  tests).
- `requirements-lock.txt`: freeze đầy đủ 79 packages sinh bằng
  `importlib.metadata` (venv dùng `uv`, không có `pip freeze`).

### 4.3 `scripts/verify_repro.sh` (MỚI, đã chmod +x, CHẠY THẬT)
4 bước smoke, không train/generate thật: (1) pytest full; (2)
`run_e2 --config configs/e2.yaml --dry-run`; (3) 19 artifact paper-cited
kiểm tra tồn tại + parse JSON/JSONL được; (4) tectonic compile check. Output
chạy thật (03:26 +07):

```
=== [1] pytest suite
353 passed, 1 warning in 14.71s
    PASS: pytest: 353 passed, 1 warning in 14.18s
=== [2] E2 dry-run (no LLM calls, config-driven runner)
    PASS: run_e2 --dry-run: [e2] OK -> …/outputs/e2/results.json (120 records)
=== [3] master results exist + valid JSON/JSONL
    PASS: ok: data/benchmarks/safety_contrast_v1.json
    PASS: ok: data/manifests/eval_subset_round1.json
    PASS: ok: data/manifests/eval_subset_v2.json
    PASS: ok: data/benchmarks/e0_prompts_v1.jsonl
    PASS: ok: outputs/experiments/round3_e0/qwen3b/results.json
    PASS: ok: outputs/experiments/round3_e0/llama3b/results.json
    PASS: ok: outputs/experiments/round3_e0/summary.json
    PASS: ok: outputs/experiments/round3_e2e3/qwen3b/results.json
    PASS: ok: outputs/experiments/round3_e2e3/llama3b/results.json
    PASS: ok: outputs/experiments/round3_e5/results.json
    PASS: ok: outputs/experiments/round3_e6/results.json
    PASS: ok: outputs/experiments/round3_e7/e7_fusion_results.json
    PASS: ok: outputs/experiments/round3_e8/results.json
    PASS: ok: outputs/experiments/round3_e8/recomputed/recompute_e8_monitor.json
    PASS: ok: outputs/experiments/round3_e8_llama3b/recomputed/recompute_e8_monitor.json
    PASS: ok: outputs/transformer/codebert_eval_vd_s_metrics.json
    PASS: ok: outputs/transformer/codebert_predictions_paired.jsonl
    PASS: ok: outputs/transformer/fallback_threshold.json
    PASS: ok: outputs/transformer/final_eval.json
=== [4] tectonic compile check (paper/main.tex)
    PASS: paper/compiled/main.pdf written (276K)
=== SUMMARY: 22 passed, 0 failed
```

Lưu ý: trong lúc verify chạy, E2E3-llama và E0-granite `results.json` đã xuất
hiện (queue A1 Round 4 hoàn tất sau_report_trước_đó) — script check cả hai và
PASS, tức repro package đang thấy trạng thái kết quả ĐẦY ĐỦ nhất từ đầu dự án.

## 5. Bổ sung để đạt 10 trang: Appendix A (disclosure ownership)

Bản draft đủ sections/tables/figures là **9 trang** — dưới target 10–14. Thay
vào padding vô nghĩa, A3 viết `paper/appendix_repro.tex` (file của A3):
**Appendix A "Reproducibility and Artifact Appendix"** theo chuẩn ACM artifact
evaluation — environment, 8 bước reproduce, **bảng traceability Table 5**
(paper item → file nguồn trong `outputs/`), quy tắc đọc số đã-corrected từ
`recomputed/`, và phần disclosures (PASS-branch unattainable tại n=20 với
cite McNemar 1947; Qwen monitor deviation 0.587; bootstrap 10,000 resamples
cite Efron 1979). Nội dung thuần cấu trúc/sự thật, không số mới nào được sinh.
Đặt sau `\bibliography` (đúng vị trí appendix của acmart) → PDF đạt 10 trang.

## 6. Audit cấu trúc [L5]

Script audit (đọc 15 file .tex của paper): trích mọi `\cite`/`\ref`/`\label`/
`\includegraphics`, đối chiếu `paper/refs.bib` (25 entry). Kết quả trên bộ
file cuối:

```
tex files scanned : 15
bib entries       : 25
cite keys used    : 21   → 21/21 TỒN TẠI trong refs.bib (0 missing)
refs used         : 17   → 17/17 có \label khớp (0 dangling)
labels defined    : 28
includegraphics   : 5    → 5/5 file tồn tại dưới paper/
bib entries never cited (info): feng2020codebert, guo2021graphcodebert,
                                treesitter, vaswani2017attention
\label never referenced (info, vô hại): sec:intro, sec:related, sec:models,
  sec:scale, sec:rq1..rq6, sec:conclusion, app:repro (A2 label từng section
  theo thói quen; không phải lỗi)
```

Kết luận audit: **không có lỗi hard**; chỉ còn info-level. 4 entry bib chưa
cite sẽ không xuất hiện trong REFERENCES (BibTeX chỉ in entry được cite) —
giữ lại trong refs.bib cho các vòng sau.

### Lịch sử refs.bib
Copy nguyên văn từ `docs/refs.bib` (16 entry đã verify từ Round 1, KHÔNG sửa
file gốc) + **9 entry bổ sung do A3 verify** (CodeBERT EMNLP'20,
GraphCodeBERT ICLR'21, Vaswani NeurIPS'17, McNemar 1947, Efron 1979,
Qwen2.5-Coder TR arXiv:2409.12186, Llama 3 arXiv:2407.21783, Granite model
card HF, tree-sitter) — chỉ entry standard/có DOI/arXiv id chắc chắn. Trong 9
entry, 5 được sections/appendix cite (hui2024qwen25coder,
grattafiori2024llama3, granite2025modelcard, mcnemar1947note,
efron1979bootstrap; ding2025primevul đã có sẵn và được cite); 4 còn lại là
info-only.

## 7. Còn thiếu gì do song song (tại thời điểm report 03:30 +07)

**KHÔNG còn file section/table/figure nào missing.** Đủ 8/8 sections
(00_abstract … 07_conclusion), 4/4 tables, 5/5 figures, compile sạch,
10 trang. A2_report round4 cũng đã có trên repo và khớp contract.

Còn mở (không chặn PDF, thuộc agent khác/orchestrator):
- `reports/round4/A1_report.md` + `V1/V2/S` chưa xuất hiện tại thời điểm viết
  (A1 queue E2E3-llama/E0-granite vừa hoàn tất kết quả trong lúc tôi làm việc;
  nếu audit V1/V2 yêu cầu sửa số trong sections → A2 sửa sections + A3 chạy
  lại compile 1 lệnh là PDF cập nhật).
- Header review của acmart đang in placeholder "Conference'17, July 2017,
  Washington, DC, USA" (mặc định của class khi không set `\acmConference`) —
  bình thường cho bản review; set conference thật khi nộp.
- `paper/compiled/main.log` cũ (02:57, từ lần draft lỗi) còn nằm trong
  `compiled/` — intermediate, không ảnh hưởng PDF.

## 8. Danh sách file A3-R4 tạo/sửa

| File | Hành động |
|---|---|
| `paper/main.tex` | MỚI — khung acmart + wiring sections/tables/appendix |
| `paper/preamble.tex` | MỚI — `\missingsection` (\detokenize), remark env, `\code` |
| `paper/refs.bib` | MỚI — copy `docs/refs.bib` + 9 entry bổ sung (không sửa docs/) |
| `paper/appendix_repro.tex` | MỚI — Appendix A reproducibility + Table 5 traceability |
| `paper/compiled/refuseguard_paper.pdf` | PDF cuối, 10 trang |
| `paper/compiled/main.{pdf,aux,bbl,out}` | intermediates của compile |
| `README.md` | MỚI — repro guide đầy đủ 8 bước |
| `requirements.txt` / `requirements-lock.txt` | MỚI — curated pin / freeze 79 pkg |
| `scripts/verify_repro.sh` | MỚI — smoke 22-check, đã chạy thật PASS 22/22 |
| `reports/round4/A3_report.md` | báo cáo này |

Không git commit. Mọi lệnh/output trong report này là nguyên văn từ chạy thật.
