# V2 Report — Round 11 (AUDIT ADVERSARIAL W2: gen_paper_numbers + trivial baseline + refs + de-anon)

Ngày: 2026-09-27. Auditor: V2 (vòng 11). Đối tượng audit: báo cáo
`reports/round11/W2_report.md` và toàn bộ deliverable của W2. Phương pháp:
**tính lại độc lập** từ artifact gốc bằng script riêng (`/tmp/v2_audit/`,
KHÔNG import `gen_paper_numbers.py` cho phần recompute), chạy lại thí nghiệm,
grep/compile thật, verify reference qua arXiv API + CrossRef + trang chính thức
ICSE. Không sửa bất kỳ file của W2/W1; chỉ tạo report này + `/tmp`.

## VERDICT W2: **PASS — có ISSUES**

| # | Vấn đề | Mức |
|---|---|---|
| I1 | De-anonymize **CHƯA XONG**: 4 chỗ "Round-8/9" + 14 chỗ "round-1/2/3/4/7" còn trong TEXT (render ra PDF), trong khi W2_report khẳng định đã grep sạch | **[MEDIUM]** |
| I2 | W2_report viết "trivial một mình F1 **.834–.856**" — range đó chỉ đúng 2 cell full-corpus; cả 4 cell là **.823–.856** (with-graph subset/group = .8233) | **[LOW]** |
| I3 | **70/178 macro KHÔNG được dùng** trong main.tex — các số đó trong văn bản vẫn là literal; `--check` chỉ pin 1 phần (needles 2,700 / 640/640 / 603 / 137/137 / 2,299 / 500/603). W2 có disclose trong TODO#3 nhưng chưa tính hết hệ quả bảo vệ | **[LOW]** |
| I4 | Full suite hiện là **674 passed / 1 failed** (675 collected), không phải 673/1 như W2_report — +1 test từ `tests/test_packguard_p0.py` (file của W1, mtime Sep 27 23:54, SAU khi W2 viết report). Không phải lỗi, chỉ lệch con số | [INFO] |

Toàn bộ số học macro, W3 mapping, trivial baseline, reference, compile:
**không phát hiện sai sót nào** (chi tiết bên dưới).

## 1. MACRO vs ARTIFACT — PASS (124 giá trị tự tính lại, 0 mismatch)

Không dừng ở 15 như tasking: tôi recompute độc lập **124 giá trị macro**:

- **Exhaustive tab:main (48/48)**: 6 cell × 8 số (F1/AUC/npm/pypi mean±std) cho
  Graph/Tfidf × FedAvg/Centralized/PerClientBest, tính lại trực tiếp từ 320
  rows `ecosystem` của `outputs/packguard/fl_multiseed/grid_results.json`
  (640 rows, 20 seeds 20260922–41, mock=false, config `e0cd260b014556bb`):
  khớp từng ký tự, **không có hoán đổi cell** (fedavg↔fedprox↔centralized
  đều phân biệt đúng — fedprox không xuất hiện trong tab:main là đúng).
- **tab:safety n=60 (36 giá trị rr/rec/fp)** từ `safety_metrics_n60.json`
  per_model, gồm chuỗi `.533\to.800` kiểu recall P0→arm: khớp.
- **tab:stats**: exact Wilcoxon 2 phía trên 20 ΔF1 từ `per_seed_comparisons`
  + Holm tự viết lại → `.312 / 3.8e-6 / .133 / 1.9e-6`, Holm `0.26545 → .265`,
  sign `12/8/0`, McNemar `4/20`: khớp macro.
- **KB + corpus + n100 + stabilized + npm_hook + runs** (KB 142/122/2,299;
  pooled P2 recall .440, flips 19/8 trên 200 pairs; stab epochs 12.05,
  lr 58/21/1, 4 ΔF1 early-vs-fixed; npm_hook +.024±.120; 640): khớp.
- 178 macro: unique 178/178; `gen_numbers_audit.json` ghi đúng 178;
  `main.tex` L10 có `\input{p0_macros/numbers.tex}`.
- Kết luận: **không có key sai / gán nhầm số cell khác** trong toàn bộ phần
  được kiểm (bao trùm mọi họ macro có rủi ro trộn cell).

`--check` hiện chạy: `GEN-NUMBERS CHECK: OK -- 178 macros verified against
artifacts (640 grid rows, 20 seeds)`, exit 0.

### Hành vi phát hiện stale của --check (test bằng monkeypatch trên bản copy, không đụng file thật)
1. Thay `\pmGraphFedAvgFone` bằng literal sai `.850` trong tab:main →
   **DETECTED** ("STALE table row 'graph FedAvg'…").
2. Re-inject 2 stale literal W3 `$.833{\pm}.115$` / `$.790{\pm}.105$` →
   **DETECTED** cả 2 pattern.
3. Số liệu numbers.tex lệch artifact (drift) → **DETECTED**.
→ Cả 3 lớp bảo vệ hoạt động thật (không chỉ "tự xưng" trong report).

## 2. W3 MAPPING — PASS (đúng chiều, đủ chứng cứ)

Tự lọc 5-seed subset (20260922–26) từ chính grid 640 rows và tính lại:

| Số in bài | Tự tính lại | Verdict |
|---|---|---|
| `.833±.115` | 5-seed graph/group **fedavg** pypi = 0.8331±0.1153 (n=5) | đúng nguồn stale 5-seed, superseded bởi 20-seed ✓ |
| `.790±.105` | 5-seed graph/group **centralized** pypi = 0.7900±0.1049 (n=5) | đúng nguồn stale; KHÔNG phải cùng cell với `.790±.076` ✓ |
| `.851±.080` | 20-seed graph/group fedavg pypi = 0.8507±0.0797 | đúng cell, đúng đành giữ ✓ |
| `.830±.100` | 20-seed graph/group centralized pypi = 0.8302±0.0999 | ✓ |
| `.790±.076` | 20-seed **tfidf**/group centralized pypi = 0.7898±0.0764 | đúng là cell khác ✓ |

Holm random/graph: exactWilcoxon 20 ΔF1 → Holm = **0.26545** → in `.265`
(sửa `.266→.265` là đúng, không phải "sửa sai chiều"). `w3_mapping.json`
khớp nội dung tôi tính lại từng dòng.

## 3. TRIVIAL BASELINE — PASS

- **Chạy lại 2 seed** (`--seeds 2 --out /tmp/v2_audit/triv2`): per-seed rows
  (graph/trivial F1, AUC, McNemar, Δ) **byte-equal** với 2 seed đầu trong
  `outputs/packguard/trivial/trivial_results.json` ở cả 4 scope. Determinism xác nhận.
- **Tự tính lại toàn bộ thống kê từ JSON** (scipy exact Wilcoxon, không qua script W2):
  full/group ΔF1 **+.0227±.0193** sign 19/1/0 p=**1.907e-05**, McNemar pooled **83/171**;
  full/random **+.0487±.0163** 20/0/0 p=**1.907e-06** 68/236; subset500/group
  +.0322±.0324 p=**.001209** 116/217; subset500/random +.0550±.0251 p=1.907e-06 96/255 —
  khớp 100% với bảng trong W2_report (min attainable p n=20 = 1.9e-6, đúng).
- **Không leak label**: `packguard.features.FEATURE_NAMES` = 18 feature, grep
  không có tên kiểu label/target/verdict/malicious; `features_v2.jsonl` có key
  `label`/`label_source` nhưng cả graph lẫn trivial matrix chọn feature **theo
  tên** nên label không thể lọt; `package`/`sample_id`/`ecosystem` không dùng.
  `TRIVIAL_FEATURES` = 5 metadata thuần. `n_bytes`: **0 lần xuất hiện** trong
  features_v2.jsonl → disclose "không có trong schema, không impute" là THẬT.
- **Thiết kế sạch**: graph (18) là **superset** của trivial (4/5 có mặt, còn
  `empty_graph_flag` ≡ `n_nodes==0` với `n_nodes` trong graph) → ΔF1 đo đúng
  giá trị cận biên của parsed-content so với metadata rẻ tiền.
- **Điểm trích ".834–.856" (I2)**: đúng cho full corpus (0.8341, 0.8555);
  nhưng nếu nói ở ngữ cảnh "cả 4 cell" thì range thật là **.823–.856**
  (subset/group trivial = 0.8233). W2_report viết ngay sau câu "ở cả 4 cell"
  → nên sửa thành ".823–.856" hoặc scope rõ "trên full corpus".
- **Ý nghĩa + wording đề xuất** (nếu orchestrator duyệt nhập): trivial mạnh
  (.82–.86) nghĩa là phần lớn signal là metadata; graph chỉ thắng +2–5.5pt.
  Paper KHÔNG được claim "graph essential"; phải claim "significant marginal
  gain". Wording sẵn sàng (EN):
  > *"A metadata-only baseline using five trivial features (file count, parse
  > failures, entry-point flags, empty-graph indicator) already reaches
  > F1 = .82–.86, showing that most detectable signal is cheap metadata. The
  > 18-feature behavior graph — a strict superset of these signals — adds a
  > statistically significant marginal gain (+.023 group-split / +.049
  > random-split mean ΔF1; exact Wilcoxon over 20 seeds p = 1.9e-5 / 1.9e-6;
  > the advantage persists on the 500 non-empty-graph rows, so it is not an
  > artifact of the empty-graph flag). We therefore position behavior graphs
  > as a consistent refinement of, not a replacement for, metadata signals."*

## 4. REFERENCES — PASS (4/4 spot-check độc lập + kiểm chéo thêm)

Verify bằng arXiv API (export.arxiv.org) + CrossRef + trang ICSE chính thức:

- **(a) MalOSS** `duan2021maloss`: arXiv 2002.01139 trả đúng 6 authors
  Duan / Alrawi / Pai Kasturi / Elder / Saltaformaggio / Lee, comment
  *"To appear in NDSS SYMPOSIUM 2021"* — bib khớp từng tên, venue NDSS 2021 ✓.
- **(b) `zahan2025npm`**: arXiv 2403.12196 = "Leveraging Large Language Models
  to Detect npm Malicious Packages", 5 authors Zahan / **Burckhardt** /
  **Lysenko** / **Aboukhadijeh** / **Williams** ✓; venue ICSE 2025 xác nhận qua
  proceedings chính thức DOI 10.1109/ICSE55347.2025.00146. Tác giả thứ 2 là
  **Philipp** Burckhardt (đối chiếu trang research-track ICSE 2025) — khớp bib.
  ID cũ 2408.08924 kiểm tra: đúng là bài KHÁC ("Prefix Guidance…", Zhao et al.)
  → việc đổi ID là đúng chiều.
- **(c) Cerebro `zhang2025cerebro`**: CrossRef `works/10.1145/3705304` →
  TOSEM, volume **34**, issue **4**, pages **1–28**, published **2025-04-28**,
  7 authors đúng thứ tự (…Wang Chong, Peng Xin) ✓.
- **(d) `campbell2026drb`**: arXiv 2603.01246 = "Defensive Refusal Bias: How
  Safety Alignment Fails Cyber Defenders", 8 authors Campbell / Kale / Sehwag /
  Herring / Price / Borges / Levinson / Knight ✓. Đồng thời `ti:"RefuseGuard"`
  trên arXiv = **0 kết quả** → note "no public identifier" trong
  `refuseguard2026` là trung thực, và việc tách bài 2603.01246 ra entry riêng
  là đúng chiều (không "sửa sai").
- Kiểm chéo thêm: `ohm2020backstabbers` = 2005.09535 đúng bài BKC (đúng chiều,
  2005.09561 là bài khác); `halder2024memptec` DOI 10.1145/3589334.3645543 =
  "Malicious Package Detection using Metadata Information", Proceedings of the
  ACM Web Conference 2024 (WWW '24) ✓ — venue sửa từ ASE sang WWW là ĐÚNG.
- Bib compile: tectonic 0 undefined citation. Không thấy lỗi chuỗi DOI/arXiv
  ID còn lại trong bib.

## 5. DE-ANONYMIZE — PASS có TÌM (I1)

- **PackGuard/RefuseGuard: 0 occurrence trong TEXT** (strip comment `%`).
  Chỉ còn ở comment `% SRC` (được phép) và cite keys `refuseguard2026` /
  `campbell2026drb` (vô hình với reader). ✓
- Affiliation: `\author{Anonymous (double-blind submission)}` +
  `\institution{Anonymous}` (L27–28). ✓
- Self-cite ngôi ba đúng: "findings from a prior vulnerability-domain
  measurement study~\cite{…}" (L119); "A prior vulnerability-domain
  measurement study~\cite{refuseguard2026} established…" (L165). ✓
- **Còn sót (I1)** — grep case-insensitive trên TEXT (đã strip comment):
  `Round-8` L261; `round 8` L503, L537; `Round 9` L542. Ngoài phạm vi 3 pattern
  tasking nhưng cùng họ: `round 2/round-2` L283, L405; `round-1` L285, L406,
  L412, L446; `round-3` L388, L419, L440, L653, L656, L910; `round-4` L591;
  `round-7` L731 — **tổng 18 chỗ**. Đây là số vòng nội bộ, không định danh
  hệ thống/tác giả nên không vỡ double-blind trực tiếp, nhưng (1) mâu thuẫn
  với claim "grep identifier chỉ còn cite keys + % SRC comments" trong
  W2_report, (2) nếu bất kỳ artifact/report nào lộ ra ngoài thì các nhãn
  round-N này là điểm nối. Fix cơ học ~30 phút (thay "Round 8"→"the LLM-KB
  batch", "round-2 audit"→"the refresh audit", v.v.).
- **Compile**: `tectonic main.tex` exit 0, `main.pdf` 153.8 KiB, chỉ
  underfull-hbox warnings, 0 undefined citation/reference. ✓

## 6. TESTS — PASS

- `tests/test_packguard_trivial.py`: **13/13 passed (2.1s)** — gồm 2 pin
  `test_gen_numbers_macros_reproducible` (regenerate == file) và
  `test_gen_numbers_check_passes`.
- `--check` phát hiện stale: xác nhận bằng 3 kịch bản inject (mục 1). Trả lời
  câu hỏi tasking: **CÓ, vi phạm giả tạo 1 macro/literal → đỏ (exit 1)**.
- Full suite hiện tại: **675 collected = 674 passed + 1 failed (79.2s)**.
  Con số 673 trong W2_report đã lệch +1 do `tests/test_packguard_p0.py` (file
  của W1) sửa sau report của W2 — không phải test của W2 fail thêm.
- **Root cause `test_round7_master.py::TestFigRound7::test_exists_branch`**
  (pre-existing, đúng như W2 chẩn đoán — đã reproduce lỗi thật):
  `outputs/master/round7_token_map.json` **CÓ tồn tại trên disk** (Sep 21);
  nhưng test chạy trong sandbox `tmp_path` chỉ tạo
  `outputs/master/round7_master.json`, monkeypatch ROOT→tmp_path, rồi gọi
  `fig_round7()`; bản `paper/make_figures.py` viết lại Sep 26 load
  `outputs/master/round7_token_map.json` **vô điều kiện** (L627, assert tại
  L45) → `AssertionError: missing source file: …round7_token_map.json`.
  Fix đúng chủ: hoặc `fig_round7()` early-return khi thiếu token_map trong
  sandbox, hoặc test tạo sẵn token_map. Thuộc owner make_figures (round-10),
  không phải W2/W1.

## CONFIRMED BUGS (trong deliverable round-11)

1. **[MEDIUM] De-anon sót 18 nhãn round-N trong TEXT** (danh sách L-number ở
   mục 5) + W2_report tuyên bố sai "đã grep sạch". Số/macro/refs không ảnh hưởng.
2. **[LOW] 70/178 macro unused** → các số tương ứng trong main.tex vẫn literal,
   --check không pin hết (chỉ 6 needle headline). Đã disclose một phần (TODO#3)
   nhưng cần liệt kê rõ khi F tích hợp.

## FALSE CLAIMS trong W2_report (bị V2 bắt)

1. *"Kiểm cuối: grep identifier chỉ còn cite keys + % SRC comments"* — SAI
   (18 chỗ round-N còn trong text; PackGuard/RefuseGuard thì đúng là sạch).
2. *"trivial baseline MỘT MÌNH đã đạt F1 .834–.856"* — SAI phạm vi: đây là
   range 2 cell full-corpus; cả 4 cell là .823–.856.

## AI SAI / AI BẮT ĐƯỢC (self-debrief)

- Tôi từng kết luận "--check MISS stale literal" vì inject sai anchor
  ("The refreshed grid" không tồn tại trong main.tex) — tự bắt được khi
  grep anchor = 0, làm lại với anchor đúng → checker hoạt động. Bài học:
  kết luận âm phải xác nhận injection đã xảy ra.
- Web-search summarizer trả tên "**Laurids** Burckhardt" — tôi bắt lỗi bằng
  đối chiếu trang ICSE chính thức: **Philipp** Burckhardt, khớp bib.
- Lần đầu tôi cũng đọc ".834–.856" là đúng (chỉ nhìn 2 cell full corpus);
  xuất toàn bộ 4 cell ra mới thấy range thật .823–.856.

## PAPER-READY (cho F tích hợp)

**Đủ:**
- **Macro**: 178 macro generated, 124 giá trị re-verified độc lập (gồm full
  tab:main + tab:safety), `--check` xanh và đã chứng minh phát hiện stale thật;
  F có thể thay literal bằng macro an toàn.
- **Refs**: refs.bib sạch 9/9 fix đúng chiều (4/4 spot-check độc lập PASS),
  compile 0 undefined citation.
- **W3**: 3 số mâu thuẫn đã mapping đúng artifact, stale literal được pin
  bởi STALE_PATTERNS; Holm .265 chuẩn xác.
- **Compile**: tectonic xanh (exit 0, PDF 153.8 KiB).

**Việc còn thiếu (theo thứ tự ưu tiên):**
1. Trung tính hóa 18 chỗ round-N (I1) — cơ học, ~30 phút, TRƯỚC khi submit.
2. Sửa range ".834–.856" → ".823–.856" (hoặc scope "full corpus") ở mọi nơi
   trích lại claim trivial (hiện chỉ trong W2_report, chưa vào paper).
3. Quyết định nhập trivial baseline vào paper2 (số đã verify, wording mục 3
   soạn sẵn; nên thêm qua gen_paper_numbers để --check pin).
4. Thay literal còn lại bằng 70 macro đã gen (stabilized arm, safety-n100
   text, corpus/KB text) để --check bảo vệ 100% (I3).
5. `test_exists_branch` regression — chờ owner make_figures (nguyên nhân gốc
   đã xác định, mục 6).

## Self-test của chính V2 (chạy thật)

- `/tmp/v2_audit/verify_macros.py` + 2 script recompute inline: 124 giá trị,
  0 mismatch (exit 0).
- `.venv/bin/python scripts/r11_trivial_baseline.py --seeds 2 --out
  /tmp/v2_audit/triv2` → per-seed byte-equal với artifact (so bằng ==).
- `gen_paper_numbers.py --check` → OK exit 0; 3 kịch bản inject → exit-fail
  hành vi đúng (monkeypatch, file thật không bị sửa).
- `pytest tests/test_packguard_trivial.py -q` → 13 passed;
  `pytest tests/ -q` → 674 passed, 1 failed (pre-existing, đã reproduce
  nguyên nhân gốc).
- `tectonic main.tex` (paper2) → exit 0, 0 undefined citation.
- arXiv API: 2002.01139, 2403.12196, 2603.01246, 2005.09535, 2408.08924,
  ti:"RefuseGuard"=0; CrossRef: 10.1145/3705304, 10.1145/3589334.3645543;
  WebFetch conf.researchr.org (ICSE 2025 author list).

Không git commit. Không sửa file của agent khác. Script audit nằm ở
/tmp/v2_audit/ (ngoài repo, đúng ràng buộc).
