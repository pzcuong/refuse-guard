# W2 Report — Round 11 (PackGuard P0: GEN-NUMBERS + TRIVIAL BASELINE + REFERENCES/DE-ANONYMIZE)

Ngày: 2026-09-27. Owner: W2 (vòng 11, góc P0-4/P0-5/P0-6). Song song với W1
(họ sở hữu `packguard/fl.py` — tôi KHÔNG đụng). Ràng buộc: CPU only, không
GPU/LLM, không git commit, KHÔNG bịa số — mọi số dưới đây truy vết tới
artifact thật (nguồn ghi ngay tại chỗ). Không gian sửa đúng tasking:
`scripts/gen_paper_numbers.py` (mới), `paper2/p0_macros/` (mới),
`scripts/r11_trivial_baseline.py` (mới) + `outputs/packguard/trivial/`,
`paper2/main.tex` (CHỈ de-anonymize + W3 + macro), `paper2/refs.bib`,
`tests/test_packguard_trivial.py`, report này.

## 1. LÀM GÌ

### [N1] GEN-NUMBERS SCRIPT (P0-4) — DONE, chạy thật, --check xanh
- `scripts/gen_paper_numbers.py` đọc CHỈ outputs thật:
  `fl_multiseed/grid_results.json` (640 rows, 20 seeds AMENDMENT-4,
  config `e0cd260b014556bb`), `safety/safety_metrics_n60.json`,
  `r10/r8_safety_expand/safety_metrics_n100.json`, `fl/results.jsonl`
  (KB-v2 ablation), `experiments/round9_kb/coverage_v3.json`,
  `features/features_v2.jsonl` (corpus + coverage),
  `round3_e0/*/results.json` (E0 arms 180 / probes 225-125 — đếm lại từ
  record, khớp SRC comment cũ), `round3_e2e3/summary.json` (900),
  `master/round5_master.json` (E0v2 1,200), `r10/r1_stabilized_central/
  results.jsonl` (arm ổn định). Poll W1-P0: `outputs/packguard/p0*/**`
  (hiện chỉ có `p0/run.log` của W1; loại trừ thư mục `p0_macros` của chính
  script).
- Sinh **178 macro** `paper2/p0_macros/numbers.tex` phủ: tab:main (6 hàng × 8
  số), tab:stats (4 hàng × ΔF1/std/sign/p/Holm/McNemar + npm_hook), tab:safety
  (6 hàng n=60), tab:kb, n100 pooled, corpus/coverage, 2{,}700 generations
  (decompose 180+900+1,200+360+60), 640 runs, 137/2,299 KB universe, arm ổn
  định (58/21/1 lr, epochs 12.05/2/30, 4 early-vs-fixed ΔF1).
- **--check mode**: (a) diff numbers.tex trên đĩa với regenerate (drift);
  (b) mô phỏng expansion macro (regex negative-lookahead = longest-name match
  như TeX) rồi so TỪNG hàng bảng trong main.tex với giá trị artifact;
  (c) quét stale literals. Hiện tại: **CHECK OK — 178 macros verified**
  (output: `GEN-NUMBERS CHECK: OK`), exit 1 khi stale.
- Test pin: `test_gen_numbers_macros_reproducible` (regenerate == file) và
  `test_gen_numbers_check_passes` — nếu ai sửa số trong main.tex lệch
  artifact, CI đỏ.

### [N2] TRIVIAL BASELINE (P0-5 / L4) — DONE, chạy thật 20 seeds, deterministic
- Câu hỏi reviewer (shortcut-learning): graph features có vượt baseline
  TRIVIAL metadata không? Trivial set (đúng tasking): `n_files`,
  `parse_fail_files`, `empty_graph_flag`, `has_setup`, `has_postinstall`.
  **`n_bytes` KHÔNG có trong schema features_v2/graphs_v2** (file sizes không
  được lưu) → bị loại, disclosed, KHÔNG bịa/impute (test pin T3).
- Protocol giống grid: 20 seeds 20260922–20260941 × group-split PRIMARY +
  random SECONDARY (dùng chính `packguard.fl.make_group_split /
  make_global_test_split`) × centralized **sklearn lbfgs standardized**
  (Pipeline StandardScaler + LogisticRegression(max_iter=1000,
  random_state=seed)). CẢ HAI arm (graph 18 features / trivial 5) chạy dưới
  CÙNG protocol của script này → so sánh apples-to-apples; **không** đem so
  với số torch-SGD của grid (optimizer khác) — note được ghi trong meta JSON
  và test pin.
- Thống kê: per-seed paired **exact McNemar** (statsmodels) graph-vs-trivial
  trên cùng test rows; ΔF1/ΔAUC per seed; **exact Wilcoxon** (scipy
  method='exact') trên 20 ΔF1; sign counts; bootstrap 95% CI của mean ΔF1
  (10k resamples, seed 20260922, resample ở mức seed).
- **KẾT QUẢ (truy vết `outputs/packguard/trivial/trivial_results.json`)**:

  | scope | split | graph F1 | trivial F1 | ΔF1 (g−t) | sign | Wilcoxon exact p | McNemar pooled b01/b10 |
  |---|---|---|---|---|---|---|---|
  | full 603 | group (PRIMARY) | .8782±.0440 | .8555±.0413 | **+.0227±.0193** | 19/1/0 | **1.907e-05** | 83/171 |
  | full 603 | random | .8828±.0233 | .8341±.0234 | **+.0487±.0163** | 20/0/0 | **1.907e-06** | 68/236 |
  | with-graph 500 | group | .8554±.0523 | .8233±.0533 | **+.0322±.0324** | 17/3/0 | **.001209** | 116/217 |
  | with-graph 500 | random | .9018±.0305 | .8468±.0201 | **+.0550±.0251** | 20/0/0 | **1.907e-06** | 96/255 |

  **Trả lời: CÓ — graph vượt trivial có ý nghĩa thống kê ở cả 4 cell**
  (p ≤ 1.2e-3, min attainable n=20 = 1.9e-6), kể cả khi loại 103 empty-graph
  rows (subset 500) tức không phải nhờ empty-graph flag. Bootstrap CI của mean
  ΔF1 toàn bộ dương, tách 0 (ví dụ group/full [+0.0149, +0.0317]).
  Đáng chú ý disclosed: trivial baseline MỘT MÌNH đã đạt F1 .834–.856 — phần
  lớn signal là metadata rẻ tiền; lợi thế ròng của graph là +.02–.055.
  Không thêm nội dung này vào paper2 (ngoài mandate của tôi trong vòng này) —
  sẵn sàng cho orchestrator quyết định nhập.
- Determinism: chạy 2 lần full 20 seeds → JSON **byte-identical** (diff với
  `/tmp/triv_rerun`).

### [N3] REFERENCES AUDIT (P0-6 / W8) — DONE, verify từng entry qua arXiv API/CrossRef/Web
Verify bằng: arXiv API (`export.arxiv.org`, title/id queries), CrossRef API
(`api.crossref.org/works/10.1145/3705304`), publisher/ACM DL, Web search
(USENIX program, NC State WSPR). Kết quả từng entry — **trước → sau**:

| key | trước (lỗi) | sau (đã verify) | nguồn verify |
|---|---|---|---|
| `duan2021maloss` | authors SAI ("Duan, Ruian and **Altheide, MJ** and **Joshi, Ashish** and **Gunter, Devesh**"); venue SAI **IMC 2021** | authors ĐÚNG: Duan, **Alrawi**, **Pai Kasturi**, Elder, **Saltaformaggio**, **Lee**; venue ĐÚNG: **NDSS 2021** (khớp thông tin user) | arXiv API 2002.01139: comment "To appear in NDSS Symposium 2021" + author list |
| `zahan2024securityai` → **`zahan2025npm`** | arXiv ID SAI **2408.08924** (thật ra là bài KHÁC: "Prefix Guidance: A Steering Wheel for LLMs to Defend Against Jailbreak Attacks", Zhao et al.); tên "(SecurityAI)" bịa | bài thật: arXiv:**2403.12196** "Leveraging Large Language Models to Detect npm Malicious Packages" (v1 title "Shifting the Lens: Detecting Malware in npm Ecosystem with LLMs"); authors ĐỦ: Zahan, **Burckhardt**, **Lysenko**, **Aboukhadijeh**, **Williams** (→ trả lời câu hỏi tasking: CÓ, Burckhardt/Lysenko là tác giả thật); venue **ICSE 2025** | arXiv API 2403.12196 + Web (NC State WSPR publications, ICSE proceedings) |
| `zhang2024cerebro` → **`zhang2025cerebro`** | year 2024 SAI; title thêm "(Cerebro)" không có trong title thật | **TOSEM 34(4), pp 1–28, 2025** (online 2025-04-28); title thật "Killing Two Birds with One Stone: … Single Model of Malicious Behavior Sequence"; DOI 10.1145/3705304 ĐÚNG; authors đủ 7 (thêm Wang Chong, Peng Xin) | CrossRef API works/10.1145/3705304 |
| `huang2024donapi` | first author SAI "Huang, **Chengqiang**" | "Huang, **Cheng**" (given/family đảo); đủ 10 tác giả (thêm Chen, Zhao, Han, Yang, Shi); USENIX Sec 2024 ĐÚNG (arXiv comment "accepted for publication at USENIX Security 2024") | arXiv API 2403.08334 |
| `zhou2024vulfl` | (đúng) | verified; bổ sung đủ 9 authors (thêm Yang, Liu, Wu, Chen); vẫn preprint (không journal-ref) | arXiv API 2411.16099 |
| `gao2025malguard` | (cơ bản đúng) | verified USENIX Sec **2025** + bổ sung đủ 8 authors (Liu, Lin, Xiang); arXiv 2506.14466 ĐÚNG | arXiv API + USENIX program search |
| `ladisa2023sok` | (đúng) | verified IEEE S&P 2023, pp 1509–1526 | Web (Scholar/Semantic Scholar) |
| `ohm2020backstabbers` | arXiv note SAI **2005.09561** (thật ra là bài ML "Normalized Attention Without Probability Cage") | arXiv **2005.09535** ĐÚNG (đối chiếu title/authors) | arXiv API cả 2 ID |
| `halder2024memptec` | venue SAI **ASE 2024 (39th)** | venue ĐÚNG: **WWW '24**, DOI 10.1145/3589334.3645543; title thật "Malicious Package Detection using Metadata Information" (MeMPtec = tên hệ thống); authors theo arXiv initials (10 người) | arXiv API 2402.07444 + ACM DL |
| `refuseguard2026` | **gắn arXiv:2603.01246 SAI** — ID đó là bài của TÁC GIẢ KHÁC | entry trở thành anonymous manuscript under review (KHÔNG có public identifier; title search "RefuseGuard" trên arXiv = 0 kết quả). Bài thật tại 2603.01246 được tách thành entry riêng `campbell2026drb` | arXiv API: ti:"RefuseGuard" → totalResults 0; 2603.01246 → Campbell et al. |
| **`campbell2026drb`** (MỚI) | — | Campbell, Kale, Sehwag, Herring, Price, Borges, Levinson, Knight, "Defensive Refusal Bias: How Safety Alignment Fails Cyber Defenders", arXiv:2603.01246 (v2), 2026 — được cite ở intro + related work + method (P1 "DRB vocabulary" nay có cite thật) | arXiv API ti:"Defensive Refusal Bias" |

`datadog2025mspd`: giữ nguyên (repo thật, đã dùng làm nguồn dữ liệu).

### [N4] DE-ANONYMIZE (P0-6 / W7) — DONE
- Affiliation: "PackGuard Project" → "Anonymous" (L27).
- Self-references về ngôi thứ ba + cite, không nêu tên hệ thống trong text:
  "the RefuseGuard findings" → "findings from a prior vulnerability-domain
  measurement study [refuseguard2026, campbell2026drb]" (intro);
  "Our companion study RefuseGuard" → "A prior vulnerability-domain
  measurement study [refuseguard2026]"; "PackGuard ports those conditions"
  → "The present study ports those conditions"; "The RefuseGuard machinery"
  → "The prior study's machinery" (Discussion).
- Grep "round-8/9/10", "Rounds 9" trong TEXT → thay trung tính ("initial
  pilot batch", "a follow-up audit", "post-pilot expansion", "the original
  single-seed run", "the earlier five-seed registered grid", …). Kiểm cuối:
  grep identifier chỉ còn cite keys (vô hình với reader) + comment `% SRC`
  (được phép theo tasking).
- Section "Data and provenance": path `data/packguard/`,
  `outputs/packguard/`, `docs/packguard_prereg.md`, `reports/round8/9/`
  → path trung tính tương đối artifact-root + ghi chú "paths relative to the
  anonymized artifact root" (vẫn tra cứu được nhờ `% SRC:` comments).
- AMENDMENT-1/-3/-4 được GIỮ (thực hành prereg chuẩn, không định danh).

### [N5] TESTS + REPORT — file này
- `tests/test_packguard_trivial.py`: **13 test, 13 passed (1.6s)**.
- Full suite: **673 passed / 1 failed** — failed duy nhất là
  `tests/test_round7_master.py::TestFigRound7::test_exists_branch`,
  **PRE-EXISTING từ round 10** (xem §4.4), không phải do thay đổi của tôi;
  deselect nó → 673/0.

## 2. FILES (absolute)

Mới:
- /Users/macbook/.zcode/workspace/default/refuseguard/scripts/gen_paper_numbers.py
- /Users/macbook/.zcode/workspace/default/refuseguard/paper2/p0_macros/numbers.tex (178 macro, GENERATED)
- /Users/macbook/.zcode/workspace/default/refuseguard/outputs/packguard/p0_macros/gen_numbers_audit.json (toàn bộ giá trị + nguồn)
- /Users/macbook/.zcode/workspace/default/refuseguard/outputs/packguard/p0_macros/w3_mapping.json
- /Users/macbook/.zcode/workspace/default/refuseguard/scripts/r11_trivial_baseline.py
- /Users/macbook/.zcode/workspace/default/refuseguard/outputs/packguard/trivial/{trivial_results.json,trivial_summary.md}
- /Users/macbook/.zcode/workspace/default/refuseguard/tests/test_packguard_trivial.py (13 tests)
- /Users/macbook/.zcode/workspace/default/refuseguard/reports/round11/W2_report.md (file này)

Sửa:
- /Users/macbook/.zcode/workspace/default/refuseguard/paper2/main.tex — de-anon (N4) + W3 + thay literal bằng macro trong 4 bảng/đoạn W3 + `\input{p0_macros/numbers.tex}` + cập nhật các passage "stale inference layer" (đã được giải quyết, xem §3).
- /Users/macbook/.zcode/workspace/default/refuseguard/paper2/refs.bib — viết lại toàn bộ theo verify (§1.N3, bảng trước/sau).

KHÔNG đụng: packguard/{fl,eval,models,dataset}.py, docs/packguard_prereg.md
(W1 làm amendment), data/, src/, configs/. Không git commit.

## 3. MAPPING W3 (mâu thuẫn số pypi F1) — ĐÃ GIẢI QUYẾT

| số in bài | provenance thật | verdict | số đúng theo artifact |
|---|---|---|---|
| `.833±.115` (FedAvg, đoạn "retracted finding") | grid round-9 **5-seed** (20260922–26), graph/group pypi FedAvg (.8331±.1153; W1_report §3.1) | **STALE** — superseded bởi AMENDMENT-4 20-seed | **.851±.080** (`\pmGraphFedAvgPypi/Std`) |
| `.790±.105` (centralized, cùng đoạn) | grid round-9 **5-seed**, graph/group pypi centralized (.7900±.1049) | **STALE** + rủi ro trộn cell: KHÔNG phải cùng ô với `.790±.076` của tab:main | **.830±.100** graph centralized 20-seed (`\pmGraphCentralizedPypi/Std`); `.790±.076` là tfidf centralized 20-seed (`\pmTfidfCentralizedPypi/Std`) — hai cell khác nhau |
| `.851±.080` (tab:main) | grid 20-seed, ecosystem/group/graph/fedavg, eco_pypi | ĐÚNG, nay macro-generate | .851±.080 |

Artifact thẩm quyền: `outputs/packguard/fl_multiseed/grid_results.json`
(640 rows, 20 seeds, mock=false). Đoạn Discussion nay dùng macro; --check
quét stale literal `.833{\pm}.115` / `.790{\pm}.105` → sẽ đỏ nếu ai nhập lại.

**Phát hiện phụ (cùng họ W3, đã xử lý)**: flag "stale inference layer"
(tab:stats) của audit round-2 nay **resolved** — grid 20-seed ĐÃ chứa
`per_seed_comparisons`; tính lại exact Wilcoxon 2 phía trên 20 ΔF1 reproduces
đúng bảng (.312 / 3.8e-6 / .133 / 1.9e-6; McNemar 2/14/4/16 của 20) với MỘT
sửa rounding: Holm random/graph **.266 → .265** (exact 0.26545). Lưu ý phương:
p stored trong JSON là chế độ approx; script tính lại bằng exact (đúng prereg)
— hai chế độ khớp ở mọi kết luận. Các passage "unverified pending
regeneration" trong abstract/caption/§results/conclusion đã cập nhật theo
trạng thái mới; arm ổn định vẫn aggregate-only (giữ nguyên caveat).

## 4. LỆCH CHUẨN / DISCLOSE (honest)

1. **n_bytes không tồn tại** trong schema → trivial baseline thiếu 1 feature
   theo checklist; disclosed trong meta + summary + test T3. Không impute.
2. **sklearn lbfgs ≠ torch-SGD grid**: số trivial_results KHÔNG so sánh trực
   tiếp với số bảng tab:main (khác optimizer); mọi so sánh trong script là
   nội bộ (2 arm cùng protocol). Ghi ở meta.comparability_note + test T8.
3. Wilcoxon/McNemar của tôi dùng exact; grid JSON stored p là approx — script
   gen_paper_numbers tính lại exact và khớp bảng paper; ghi rõ ở §3.
4. Holm random/graph .266→.265 là sửa rounding của số đã in (đúng hơn), đã
   ghi vào caption + w3_mapping.
5. 2,700 generations = 180+900+1,200+360+60 — đếm lại từ record (E0 arms/probe
   tách theo condition prefix PROBE@), KHÔNG gồm 240 generation mới của n100
   expansion (paper vẫn ghi 2,700 cho registered scope và n100 nói riêng).
6. refs.bib `halder2024memptec` để authors dạng initials như arXiv trả về
   (không đoán full name); venue WWW '24 đã xác nhận qua DOI.
7. **Pre-existing test failure (KHÔNG phải của tôi)**:
   `test_round7_master.py::TestFigRound7::test_exists_branch` —
   `paper/make_figures.py` rewritten Sep 26 (round-10 LAYOUT) sau ngày test
   (Sep 21); `fig_round7()` mới load token_map cả trong sandbox tmp_path nên
   assert "missing source file" fire. Ngoài không gian sửa của tôi (đúng chủ
   là round-10 agent/orchestrator); suite còn lại 673/0 khi deselect đúng
   test này.
8. Không GPU/LLM, không git commit; toàn bộ số truy vết được.

## 5. TODO (cho vòng sau / orchestrator)

1. Nhập kết quả trivial baseline vào paper2 (1 đoạn + tiny table) nếu duyệt —
   số đã sẵn sàng, chỉ cần macro hóa qua gen_paper_numbers (thêm section).
2. Sửa `test_exists_branch` (round-10 regression): `fig_round7()` nên
   early-return/decay khi thiếu token_map trong sandbox, hoặc test tạo sẵn
   token_map — quyết định thuộc chủ file.
3. Mở rộng gen_paper_numbers sang các con số còn literal trong text
   (stabilized arm đang có macro nhưng text vẫn literal ở vài chỗ —
   --check hiện chỉ pin bảng + số headline).
4. W1-P0 poll: khi W1 commit file p0 của họ, gen_paper_numbers đã sẵn sàng
   poll `outputs/packguard/p0*/**` (đang thấy `p0/run.log`).
5. Effect sizes + bootstrap CI cho tab:stats và stabilized arm (kết luận
   vẫn ghi là descriptive).

## 6. SELF-TEST THẬT (đã chạy trong phiên)

- `.venv/bin/python scripts/gen_paper_numbers.py` → 178 macros + audit + w3
  mapping; `.venv/bin/python scripts/gen_paper_numbers.py --check` →
  **GEN-NUMBERS CHECK: OK -- 178 macros verified against artifacts (640 grid
  rows, 20 seeds)**; chạy lần 2 sau khi sửa 1 số trong main.tex thử → FAIL
  đúng (đã test hành vi stale trước khi thay macro; xem log trong phiên).
- `.venv/bin/python scripts/r11_trivial_baseline.py` (20 seeds, 2.0s CPU) →
  `outputs/packguard/trivial/{trivial_results.json,trivial_summary.md}`;
  chạy lại với `--out /tmp/triv_rerun` → JSON **byte-identical** (diff = rỗng).
- `.venv/bin/python -m pytest tests/test_packguard_trivial.py -q` → **13 passed**.
- `.venv/bin/python -m pytest tests/ -q --deselect
  tests/test_round7_master.py::TestFigRound7::test_exists_branch` →
  **673 passed / 0 failed (78.9s)**; WITHOUT deselect → 1 failed (pre-existing,
  §4.7).
- `tectonic main.tex` (paper2) → build OK, **0 error / 0 undefined citation**,
  `main.pdf` ghi thành công (153.8 KiB); macro expansion trong PDF khớp số.
- Reference verify: arXiv API curl thật (ti:"Defensive Refusal Bias" → 1 kết
  quả với 8 authors; ti:"RefuseGuard" → 0; id 2005.09535 vs 2005.09561 disambiguation;
  2402.07444 MeMPtec authors), CrossRef `works/10.1145/3705304` (TOSEM 34(4)
  2025, pp 1–28), WebFetch arXiv abs pages cho 2002.01139 (NDSS 2021 comment),
  2403.12196, 2408.08924 (bài khác — bằng chứng zahan ID cũ sai), 2411.16099,
  2506.14466, 2403.08334.

Sources web chính: [arXiv 2002.01139 (MalOSS, NDSS 2021)](https://arxiv.org/abs/2002.01139),
[arXiv 2403.12196 (npm LLM, ICSE 2025)](https://arxiv.org/abs/2403.12196),
[arXiv 2408.08924 (bài KHÁC — Prefix Guidance)](https://arxiv.org/abs/2408.08924),
[CrossRef 10.1145/3705304 (Cerebro TOSEM 2025)](https://api.crossref.org/works/10.1145/3705304),
[arXiv 2603.01246 (Defensive Refusal Bias)](https://arxiv.org/abs/2603.01246),
[ACM DL 10.1145/3589334.3645543 (MeMPtec WWW'24)](https://dl.acm.org/doi/10.1145/3589334.3645543).

---

*W2 round 11 không git commit. Mọi số truy vết tới outputs/ (nguồn ghi trong
gen_numbers_audit.json và % SRC comments); paper2 compile xanh.*
