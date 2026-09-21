# V1 Report — Round 8 (AUDIT ADVERSARIAL W1: dataset + behavior graphs + literature)

Date: 2026-09-21. Owner: V1 (adversarial auditor of W1). Scope: label/source integrity,
ecosystem confound, benign selection bias, graph/feature re-extraction + leakage,
empty-graph autopsy, literature spot-check, test suite. Method: mọi kết luận dưới đây
đều được CHỨNG MINH BẰNG CHẠY CODE trên chính data thật (scripts trong /tmp, không
sửa file nào của W1; chỉ thêm báo cáo này).

## VERDICT W1: **PASS with ISSUES** — dataset integrity THẬT SỰ TỐT, nhưng có 2 lỗi
moderate (1 bug builder + 1 mis-attribution nguyên nhân empty-graph) phải được xử lý /
disclosed trước khi W2 xây trên đó.

W1 không bịa số: mọi con số tôi tái tính (counts, 18/18 AUC, coverage, empty rates,
hook rates) đều khớp chính xác với manifest + eda_v1.md. Nhưng audit tìm ra 1 bug mà
test suite không bắt được (builder bỏ lặng 5 sample pypi-malicious) và 1 nguyên nhân
empty-graph bị giải thích sai (40% empty pypi-benign là do chính policy chọn file của
W1, không phải do data "không có mapped call").

## CONFIRMED BUGS (bằng chứng chạy code)

**BUG-1 [MODERATE] `packguard/dataset.py::_dd_samples` bỏ lặng 5 sample
pypi-malicious — stride selection KHÔNG tái lập được cho pypi-mi.**
- DataDog có 2 layout: `pkg/<version>/<file>.zip` và `pkg/<file>.zip` (package
  single-version, không có thư mục version). Builder chỉ duyệt
  `for ver in os.listdir(pkg_dir): if not isdir: continue` → layout phẳng bị skip
  im lặng (dataset.py:52-58).
- Tái lập stride từ `git ls-tree` của partial clone (seed 20260922, stride=floor(N/want),
  offset=seed%stride, cắt `[:want]`): npm-mi 100/100 khớp EXACT, npm-cl 50/50 EXACT,
  pypi-cl 10/10 EXACT, **pypi-mi chỉ 55/60** — thiếu đúng 5 package có layout phẳng,
  đều CÓ zip trên đĩa (mtime 23:15:45, TRƯỚC mtime manifest 23:35:36 → không phải
  race checkout): `282828282828282828, aiiohttp, kayauthgen, libssl, spookyimagelogger`.
- Chạy `_dd_samples("data/packguard/raw")` bằng code committed trên cây hiện tại →
  384 zips, thiếu chính xác 5 zip đó. Dataset đúng theo selection policy phải là
  **602 samples** (pypi-mal 91), thực tế 597 (86).
- Impact thống kê nhỏ (−5 pypi-mal, ~5.5% pypi-mal; P(mal|pypi) 0.489→0.503 nếu fix),
  nhưng vi phạm nguyên tắc "TUYỆT ĐỐI ghi nguồn từng sample" + claim "deterministic
  stride" trong manifest/prereg là claim falsifiable — và đã bị falsify. Fix: builder
  xử lý layout phẳng, HOẶC disclose 5-sample deviation trong manifest §selection.

**BUG-2 [MODERATE] Nguyên nhân empty-graph pypi-benign bị mis-attribute; 16/40
empty là ARTIFACT của chính `select_files` (features.py:40-95), không phải "data
không có mapped call".**
- eda_v1.md §1 viết: empty pypi-benign vì "popular sdists often expose no mapped call
  in the capped file set". Autopsy 5 row (script /tmp/v1_check5_empty.py):
  - `bellows-1.0.2`: 108 file .py, nhưng 12 slot chọn = **11 `__init__.py` + setup.py**
    (vòng priority của `select_files` append TẤT CẢ file trùng tên priority, không giới
    hạn; `__init__.py` là priority → lụt slot). File thật có mapped call
    (`bellows/cli/application.py`: binascii.unhexlify) không được parse.
  - `cotyledon-2.2.0`: 12 slot = `.coveragerc, .gitignore, .mailmap, CONTRIBUTING.rst,
    ci.yaml, dependabot.yml...` (sort alphabet sau priority → file meta chiếm slot) +
    2 `__init__.py`; 3 file .py không chọn có mapped call (os.environ, socket.socket,
    subprocess.Popen).
- Simulate toàn bộ 40 empty pypi-benign (parse mọi .py trong archive, cùng cap 100KB):
  **16/40 chứa ≥1 .py có mapped call** → coverage 55.6% thấp bất thường một phần do
  self-inflicted. Coverage npm-ben/mal (82%) không bị vì ít file hơn.
- Hệ quả: row all-zero không phải "đặc tính benign sdist" mà là sản phẩm của quy ước
  chọn file → đúng dạng leak quy ước mà tasking lo ngại (xem RỦI RO #2).

## ĐÃ KIỂM VÀ ĐÚNG (không phải false claim)

1. **Counts**: tự đếm từ manifest + disk: 597 (npm 298 mal + 123 ben, pypi 86 mal +
   90 ben) — khớp declared từng cell.
2. **Checksum**: 10 sample random (seed 20260921) 10/10 khớp; sweep ĐẦY ĐỦ 597/597
   sha256 khớp file thật, 0 file missing, 0 trùng sha chéo key (dedupe không lỗ hổng).
3. **Label nguồn**: 384 malicious đều có label_source verbatim "DataDog ... (class=
   malicious_intent|compromised_lib)" và archive_path chứa đúng thư mục class tương
   ứng (0 mismatch) — không có tự suy luận. Benign label disclosed popularity-derived.
   0 sample thiếu field (eco/version/source_url/label/label_source/sha256).
4. **Re-extraction**: chạy lại `extract_sample_graphs`+`compute_features` trên 10
   sample (4 mal + 4 ben, cả 2 eco, gồm cả empty): **10/10 khớp BIT-EXACT** với
   features_v1 — pipeline deterministic thật.
5. **EDA tái lập**: 18/18 univariate AUC trong eda_auc_v1.json khớp chính xác khi tôi
   tự tính trên features_v1 (with-graph n=468); coverage 468/129/80 khớp; hook rate
   with-graph has_postinstall 0.604 vs 0.010 khớp.
6. **postinstall KHÔNG phải artifact chọn benign** (câu hỏi nghi vấn lớn nhất): mở
   package.json của TOÀN BỘ 421 sample npm — chỉ **1/123 benign npm** khai báo bất kỳ
   hook install nào (0.8%) vs **198/298 malicious (66.4%)**. Tín hiệu là THẬT, không
   phải do benign được chọn loại-trừ postinstall.
7. **Ecosystem confound DƯỚI ngưỡng**: P(mal|npm)=0.708, P(mal|pypi)=0.489;
   AUC(biến ecosystem đơn lẻ) = **0.599** toàn tập / 0.552 with-graph — **< 0.75**,
   không phải confound "gần như hoàn hảo". Nhưng inflation có thật: AUC pooled vs
   mean-within-eco: density 0.783 vs 0.753, max_repeat 0.784 vs 0.753, seq_depth
   0.777 vs 0.742; pypi yếu hơn hẳn npm (density 0.686 vs 0.820; hist_FILE_IO trong
   pypi ĐẢO DẤU 0.274). LR 5cv: eco-only 0.524, features-only 0.778, features+eco
   0.747 (thêm eco còn HẠ AUC → eco không phải đường tắt).
8. **Tests**: `pytest tests/test_packguard_w1.py` → **35 passed**; full suite →
   **615 passed** (75.9s) — khớp claim 35 + 580 legacy.
9. **Literature**: DONAPI arXiv:2403.08334 USENIX Sec 2024 — VERIFIED (web).
   MalGuard arXiv:2506.14466 — record/title VERIFIED; venue "USENIX Sec 2025" chỉ có
   nguồn thứ cấp — W1 đã hedge đúng ("venue per program pages"), giữ hedge khi cite.
   Ladisa arXiv:2204.04008 = IEEE S&P 2023 — VERIFIED (computer.org + KTH citation);
   W1 sửa ACSAC→S&P là ĐÚNG.

## FALSE CLAIMS / CLAIM KHÔNG ĐỦ (theo nghiêm giảm dần)

- **FC-1 [MODERATE]** eda_v1.md §1 + prereg L1 giải thích nguyên nhân empty
  pypi-benign là đặc tính data ("popular sdists expose few mapped calls under caps")
  — SAI MỘT PHẦN: 16/40 (40%) empty chứa mapped call mà `select_files` bỏ sót
  (BUG-2). Phần còn lại (24/40) đúng là không có mapped call.
- **FC-2 [LOW]** manifest §selection + prereg ngầm khẳng định stride selection được
  thực thi đầy đủ — thực tế pypi-mi thiếu 5/60 package do BUG-1 (không disclosed).
- **FC-3 [LOW]** W1 report §6 nêu "npm install-hook rate 60% malicious vs 1% benign"
  như một con số đặc trưng — đúng hướng nhưng che mất: (a) feature chỉ đếm hook mà
  lệnh tham chiếu file .js có trong archive → 50/198 hook malicious bị đếm 0
  (node-gyp/shell/`node -e` không được tính) — recall gap không disclosed;
  (b) "1% benign" là của POPULATION popular-packages, không phải kết quả đo cùng
  protocol với mal (capture bias DataDog, xem RỦI RO #3).

## AI SAI / AI BẮT ĐƯỢC (tự đánh giá adversarial)

- AI (W1) làm phần khó ổn: checksum/label/provenance sạch 597/597, EDA tái lập
  bit-exact, không bịa số — nhưng AI TỰ ĐỘT nguyên 2 lỗi "im lặng": builder skip
  layout phẳng (không test nào có layout này) và `select_files` lụt `__init__.py`
  (test chỉ kiểm determinism, không kiểm đại diện chọn file).
- AI (W1) giải thích hiện tượng (empty pypi-benign) bằng hypothesis thuận tiện cho
  mình ("data không có mapped call") mà không mở archive kiểm tra — audit mở 5 archive
  là thấy 11/12 slot là `__init__.py`. Bài học: mọi "coverage limitation" phải kèm
  autopsy ít nhất 5 case.
- Ngược lại nghi vấn lớn nhất của tasking (benign được chọn để không có postinstall,
  ecosystem confound AUC>0.75) đều KHÔNG có thật — AI audit phải công nhận W1 đúng
  ở 2 điểm này bằng số, không bắt bẻ ảo.
- "entry_kind trong features" của tasking: thực tế entry_kind KHÔNG vào feature
  vector trực tiếp; chỉ có 2 projection `has_setup`/`has_postinstall` — và chúng là
  marker ecosystem thuần (npm: 0/0.354; pypi: 0.608/0) → vô dụng trong FL client
  same-ecosystem, chỉ có ý nghĩa global (xem RỦI RO #4).

## RỦI RO THIẾT KẾ cho W2/F (bắt buộc xử lý / report)

1. **Per-ecosystem reporting BẮT BUỘC** (prereg D4 đã cam kết, W2 report hiện CHƯA
   thấy thực hiện): pooled AUC bị eco-inflate ~+0.03 và pypi client yếu hơn rõ
   (density 0.686 vs npm 0.820; hist_FILE_IO đảo dấu trong pypi). Mỗi bảng kết quả
   FL/centralized phải có per-cell (npm/pypi × label) + coverage, không chỉ global.
   Balanced-partition ablation (resample npm-mal ↓ hoặc pypi ↑) nên chạy 1 arm để
   chứng minh kết luận không đổi.
2. **Empty-graph leak (cao nhất cho FL)**: all-zero row mang artifact BUG-2; trong
   client pypi, is_empty là benign-predictor mạnh (P(ben|empty,pypi)=0.741;
   AUC(is_empty|pypi)=0.359 tức đảo; pooled 0.442). BẮT BUỘC: (a) arm no-empty
   (prereg D4 đã nêu — phải thực sự chạy), (b) nếu giữ empty row thì thêm flag
   `is_empty` disclosed thay vì giấu trong all-zero, (c) fix `select_files`
   (giới hạn 1 `__init__.py`, loại file meta/hidden, ưu tiên .py/.js không priority
   khi còn slot) rồi re-run features v2 — 16 row đang bị oan.
3. **postinstall/capture bias**: giữ has_postinstall (tín hiệu thật 66% vs 0.8% hook
   presence) nhưng phải disclose: (a) recall gap 50/198 hook-malicious không .js-target
   — khuyến nghị thêm feature `has_any_hook` parse trực tiếp package.json.scripts để
   đóng gap; (b) DataDog là wild-capture → over-represent install-hook attack vector,
   còn benign popular có tỷ lệ hook thấp vì ecosystem đã từ bỏ install scripts → con
   số 60%-vs-1% là của dataset này, không khái quát thành "60% malicious npm có hook"
   trong paper.
4. **has_setup/has_postinstall = ecosystem marker**: const theo eco → trong FL client
   same-ecosystem chúng hằng (0 signal), trong global model chúng là proxy eco. W2
   phải report LR kèm/không-kèm 2 feature này; nếu dùng partition "mixed" thì phải
   phân tích nhạy cảm.
5. **Size/complexity confound**: benign download cap 2.5MB (0 benign >2.5MB vs 42
   malicious); n_files median ben 4 vs mal 2 ở CẢ HAI eco (MWU p<1e-4) → "ít file"
   là proxy malicious mạnh (AUC ~0.70 sau đảo) phản ánh quy trình thu thập, không
   thuần behavior. Report metrics kèm size/n_files-stratified hoặc matched subset
   ít nhất 1 ablation. Kèm near-duplicate: 45/55 pypi-mal pkg chỉ 1 version nhưng
   npm có pkg 4+ versions — dedupe ablation trước khi claim n.
6. **Dataset freeze**: trước khi W2 train, quyết định BUG-1: fix builder + rebuild
   manifest (602 samples, re-run features) HOẶC disclose 5-sample deviation trong
   manifest. Đừng để paper claim "deterministic stride" trong khi stride không tái
   lập được cho pypi-mi.

## Cách tái lập audit (CPU, <5 phút)

```
cd /Users/macbook/.zcode/workspace/default/refuseguard
.venv/bin/python /tmp/v1_check1_counts_checksums.py   # counts + checksum 597 + label source
.venv/bin/python /tmp/v1_check2_confound.py           # eco confound + AUC pooled/within + size bias
.venv/bin/python /tmp/v1_check4_rerun.py              # re-extraction 10 samples + postinstall census
.venv/bin/python /tmp/v1_check5_empty.py              # empty autopsy + rescue sim 16/40
.venv/bin/python -m pytest tests/test_packguard_w1.py -q   # 35 passed
.venv/bin/python -m pytest tests/ -q                       # 615 passed
# stride verification (BUG-1): git ls-tree partial clone so với manifest — xem log audit
```
Scripts /tmp: v1_check1_counts_checksums.py, v1_check2_confound.py,
v1_check4_rerun.py, v1_check5_empty.py. Không file nào của W1 bị sửa.
