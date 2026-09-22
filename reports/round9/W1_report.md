# W1 Report — Round 9 (PackGuard: MULTI-SEED GRID + CLIENT-3 attempt/fallback)

Ngày: 2026-09-22. Owner: W1 (vòng 9, lộ trình Q1). Scope theo tasking: M1
multi-seed grid, M2 client thứ 3, M3 Amendment-3, M4 tests, M5 report này.
Ràng buộc: CPU only, KHÔNG đụng GPU/LLM (không chạy model nào), KHÔNG git
commit, KHÔNG bịa số — mọi số dưới đây truy vết tới
`outputs/packguard/fl_multiseed/grid_results.json` / `summary.md`. Chỉ sửa
trong không gian được cấp: `packguard/{fl,eval}.py` (dataset.py KHÔNG cần
sửa — lý do ở §4.1), `configs/packguard_fl.yaml`,
`outputs/packguard/fl_multiseed/`, `docs/packguard_prereg.md` (Amendment-3),
`tests/test_packguard_multiseed.py`, report này. `data/packguard/` KHÔNG
thêm gì (không có client-3 manifest — xem §3).

## 1. LÀM GÌ

### [M1] MULTI-SEED GRID — DONE, chạy THẬT (mock=false toàn bộ 160 rows)
- Grid ĐÚNG theo tasking: **5 seeds** {20260922..20260926} × **4 methods**
  {FedAvg, FedProx(µ=0.01 từ config), centralized, per-client-best} ×
  **2 feature sets** {graph, tfidf} × **2 splits** {group = PRIMARY,
  random = SECONDARY} = **80 runs chính** trên dataset_v2 (603 samples,
  features_v2 schema 1.1.0). Thêm arm riêng có nhãn: **partition `npm_hook`
  3-client** (fallback M2, xem §3) cùng 80 runs — arm này KHÔNG gộp vào
  count chính của grid. Tổng 160 rows, mỗi row ghi đủ
  {seed, method, features, split, partition, mock:false, config_sha16
  `1fd35c86ac6bef21`, date}. Wall-clock: **62s CPU** (LR, rounds=15, cùng
  hyperparameter round 8, KHÔNG tune lại).
- TF-IDF fit trên TRAIN của từng (seed, split) — mirror chính xác
  hyperparameter của `scripts/packguard_final_runs.py::tfidf_blocks`
  (max_features=1000, min_df=2, sublinear_tf, fixed key-set) vì `scripts/`
  ngoài không gian được phép sửa; mirror được ghi chú trong code.
- Thống kê theo AMENDMENT-3 (đăng ký TRƯỚC, §2): mỗi seed có McNemar paired
  FedAvg-vs-centralized (accuracy@0.5, method được ghi rõ) + ΔF1/ΔAUC;
  tổng hợp = Wilcoxon signed-rank 2 phía trên 5 delta F1 (+ AUC secondary)
  + dấu (n_pos/n_neg/n_zero) + mean±std per cell. Báo cáo per-ecosystem F1
  cho mọi cell (trách nhiệm D4).
- **Cross-check với round 8**: seed 20260922, group/graph — FedAvg
  .9231/.9160, centralized .9282/.9260 (F1/AUC) = KHỚP CHÍNH XÁC bảng F
  của round 8 → đường grid nhất quán với pipeline cũ.

### [M2] CLIENT THỨ 3 — BKC FAIL (đúng time-box), DÙNG FALLBACK đúng rule
- Probe BKC/Zenodo (tổng ~20 phút, dưới time-box 30'): (1) DOI Zenodo
  lưu hành của BKC `10.5281/zenodo.3367649` → record 3367650 là **file
  FITS thiên văn không liên quan** (fetch thật, title
  "goodman_comp_600Mid_GG385_HgArNe.fits"); (2) artifact Zenodo duy nhất
  liên quan BKC tìm được = record **14907786** (NSS-2024 typosquatting,
  336.8 MB — probe HEAD + central-directory qua HTTP range, không tải
  thừa): bên trong CHỈ có npm benign tgz + notebooks + CSV, và chính
  description của record nói mã nguồn BKC/MalOSS "must be retrieved by
  the corresponding owner/maintainer" → không có Maven/Ruby source; (3)
  landing page chính thức `dasfreak.github.io/Backstabber-Knife-Collection`
  → GitHub Pages 404; README repo không có link tải. Đúng rule dừng
  đã đăng ký ("fail → dừng, không chèo kéo"): **không ingest ecosystem
  thứ 3, không có manifest mới, dataset.py không đổi**.
- FALLBACK (đã đăng ký trong Amendment-3 A3.3 TRƯỚC khi chạy): partition
  3-client trên CHÍNH corpus 603 theo rule
  **client-1 `npm_hook`** = npm có install hook (feature `has_postinstall`
  của features_v2 — đáng tin sau fix BUG-2), **client-2 `npm_core`** = npm
  không hook, **client-3 `pypi`**. Kích thước (train pool, group split,
  seed 20260922): npm_core 214 (52.3% mal), npm_hook 114 (**99.1% mal**),
  pypi 146 (52.7% mal). Corpus chỉ có ĐÚNG 1 npm-benign có hook
  (`npm-benign-@salesforce__cli.tgz`) — nó nằm ở TRAIN trong cả 5 group
  split (đã verify từng seed) nên không có client 1-class.
- **DISCLOSE BẮT BUỘC (nay nằm trong config + prereg + summary.md + test)**:
  npm_hook là *"ecosystem+hook partition of the SAME corpus, NOT a new
  ecosystem"* — KHÔNG được đọc là cross-ecosystem FL.

### [M3] AMENDMENT-3 — DONE, TRƯỚC khi chạy grid
`docs/packguard_prereg.md` có mục AMENDMENT-3 với timestamp + tuyên bố
thứ tự: amendment được ghi vào file TRƯỚC khi grid runner được chạy; rule
tổng hợp đóng băng trước khi bất kỳ thống kê tổng nào được tính. Nội dung:
multi-seed grid (seeds/methods/features/splits/partitions), **primary =
group-split + F1 + FedAvg-vs-centralized**, rule Wilcoxon-over-seeds +
per-seed McNemar, định nghĩa per-client-best, fallback npm_hook + câu
disclose bắt buộc, provenance mỗi row, và **tuyên bố power trung thực**:
n=5 seeds → Wilcoxon exact 2 phía tối thiểu p = 1/16 = 0.0625 > 0.05 →
rule này KHÔNG THỂ đạt α=0.05, chỉ đóng vai trò bằng chứng mô tả; kết luận
FL-vs-central vẫn ở mức pilot.

### [M4] TESTS — 18 test mới, full suite 641/0
`tests/test_packguard_multiseed.py` (18 passed): (a) determinism của
`_grid_cell` per seed (hai lần chạy → f1/auc/history_tail/McNemar giống
nhau) và của `run_per_client_routing`; (b) partition 3-client đúng rule —
đúng 3 client tên {npm_core, npm_hook, pypi}, disjoint, union == train,
npm chia đúng theo hook flag, mỗi client đủ 2 label, không leakage với
test; scheme mặc định tái lập partition ecosystem cũ; scheme lạ raise;
(c) routing phủ 100% test sample (n_uncovered==0) và macro trùng KHỚP
baseline round-8 `run_per_client` (cùng protocol/seed); (d) helper
Wilcoxon trung thực (all-zero → p=None + note, không bịa; all-positive →
p=1/16 đúng minimum lý thuyết; power_note có mặt); (e) provenance fields
đủ trên mọi row; (f) `run_grid` TỪ CHỐI mock data (RuntimeError) và fail
loud khi thiếu features; (g) contract config grid khớp Amendment-3.
Full suite: **641 passed / 0 failed** (91.8s) — không phá test cũ.

## 2. FILES (absolute)

Code (sửa, từng lý do):
- /Users/macbook/.zcode/workspace/default/refuseguard/packguard/fl.py —
  (1) `client_name_of` + `build_clients(..., scheme=)`: rule partition
  3-client của M2; mặc định `scheme="ecosystem"` giữ nguyên hành vi
  round-8 (backward-compat do full suite chốt); (2)
  `run_per_client_routing`: method "per-client-best" cần metric
  own-partition routing mà `run_per_client` (macro-only) không sinh được.
  Không hàm cũ nào đổi ngữ nghĩa.
- /Users/macbook/.zcode/workspace/default/refuseguard/packguard/eval.py —
  `run_grid` + `_grid_cell` + `_aggregate_grid` + `_wilcoxon_over_seeds` +
  `_render_grid_summary` + CLI `--grid` (M1; đặt ở đây vì `scripts/`
  ngoài không gian sửa) + `_tfidf_blocks` (mirror round-8, cùng lý do).
  Pipeline round-8 (`run_pipeline`) KHÔNG đổi.
- /Users/macbook/.zcode/workspace/default/refuseguard/configs/packguard_fl.yaml —
  section `grid:` (seeds/splits/feature_blocks/methods/partitions/
  run_client3/text_cache) — config-driven theo tasking.
- /Users/macbook/.zcode/workspace/default/refuseguard/docs/packguard_prereg.md — AMENDMENT-3.
- /Users/macbook/.zcode/workspace/default/refuseguard/tests/test_packguard_multiseed.py — 18 test.

Outputs thật:
- /Users/macbook/.zcode/workspace/default/refuseguard/outputs/packguard/fl_multiseed/grid_results.json (160 rows + per-seed comparisons + aggregate)
- /Users/macbook/.zcode/workspace/default/refuseguard/outputs/packguard/fl_multiseed/summary.md (bảng mean±std + per-seed McNemar + Wilcoxon + client partitions + notes)

KHÔNG đổi: `packguard/dataset.py` (không có gì để sửa — fallback không cần
manifest mới), `data/packguard/`, mọi file `src/`, `scripts/`,
`packguard/{schema,graphs,features,kb,safety_port,models}.py`, pipeline
round-8 trong eval.py.

## 3. KẾT QUẢ GRID (số THẬT, truy vết grid_results.json)

### 3.1 PRIMARY: partition ecosystem (2 client), group split, F1/AUC mean±std trên 5 seeds

| features | method | F1 | AUC | npm F1 | pypi F1 |
|---|---|---|---|---|---|
| graph | FedAvg | .8530±.0561 | .8651±.0513 | .8455±.0825 | .8331±.1153 |
| graph | FedProx(µ=.01) | .8530±.0561 | .8651±.0513 | .8455±.0825 | .8331±.1153 |
| graph | centralized | .8435±.0575 | .8537±.0516 | .8466±.0743 | .7900±.1049 |
| graph | per-client-best | .8676±.0528 | .8597±.0511 | .8637±.0826 | .8319±.0955 |
| tfidf | FedAvg | .7931±.0306 | .8987±.0498 | .8256±.0618 | .6696±.0701 |
| tfidf | FedProx(µ=.01) | .7931±.0306 | .8987±.0498 | .8256±.0618 | .6696±.0701 |
| tfidf | centralized | .8332±.0328 | .8970±.0474 | .8389±.0626 | .7705±.0929 |
| tfidf | per-client-best | .8313±.0417 | .8518±.0994 | .8256±.0618 | .8079±.1591 |

### 3.2 Primary comparison FedAvg-vs-centralized per seed rồi tổng hợp

- **group/graph (PRIMARY endpoint)**: ΔF1 = +.0095±.0318, dấu 1/4/0,
  Wilcoxon p=.625 (AUC p=1.0). Per-seed McNemar: chỉ seed 20260923 có
  p=.00027 (FL tốt hơn, b01=16/b10=1); 4 seed còn lại p=1.0 → **null ổn
  định**: FL ≈ centralized trên graph/group-split, nhất quán với kết luận
  round 8 nhưng nay CÓ khoảng biến thiên giữa seed.
- **group/tfidf**: ΔF1 = −.0400±.0308, dấu 1/4/0, Wilcoxon p=.125; McNemar
  4/5 seed p<.01 (central tốt hơn) → central nhỉnh hơn ổn định.
- **random/tfidf (secondary)**: ΔF1 = −.0660±.0138, dấu **0/5/0**,
  Wilcoxon p=.0625 (= minimum khả thi của n=5, VẪN > .05 — chỉ là mô tả).
- **random/graph (secondary)**: ΔF1 = +.1171±.2005 — mean bị MỘT cell kéo:
  centralized **sụp** ở seed 20260923 (F1 .3750, P=1.0 R=.231, prob-mean
  .165 → dự đoán gần như toàn bộ là benign); loại cell này (phân tích cảm
  tính, KHÔNG thay aggregate pre-reg): .8519±.0177 (n=4) ≈ FedAvg .8737.

### 3.3 Arm fallback npm_hook (3 client) — group split

| features | method | F1 | AUC |
|---|---|---|---|
| graph | FedAvg | .8582±.0620 | .8713±.0586 |
| graph | centralized | .8663±.0578 | .8598±.0516 |
| graph | per-client-best | .8590±.0392 | .8841±.0506 |
| tfidf | FedAvg | .7923±.0309 | .8892±.0520 |
| tfidf | centralized | .8315±.0329 | .8967±.0474 |

ΔF1 FedAvg-vs-central (group/graph) = −.0081±.0535, Wilcoxon p=.4375 →
**không khác biệt** so với partition 2-client; partition mảnh hơn KHÔNG
cải thiện cũng KHÔNG làm hỏng ở scale này. LẠI NHẮC: đây là partition
cùng-corpus, không phải cross-ecosystem.

### 3.4 Ba phát hiện trung thực (cho paper, có bằng chứng trong JSON)

1. **Centralized KHỔNG ổn định theo init-seed ở hyperparameter đã đăng ký
   (LR, lr=0.1, 30 full-pass)**: 1/40 cell centralized sụp (F1 .375) trong
   khi 40/40 cell FL ổn định (min FedAvg F1 = .7375). Đây là lập luận
   mạnh nhất cho multi-seed protocol: kết luận 1 seed có thể sai theo CẢ
   HAI hướng (round 8 thấy "central ≥ FL" trên tfidf; round 9 thấy central
   có thể sụp hoàn toàn ở seed khác).
2. **tfidf-FedAvg suy biến thành all-malicious predictor**: recall=1.0 ở
   **20/20** cell tfidf-FedAvg (precision = base-rate của test; ở random
   split test stratified giống hệt giữa các seed → n_test=121, n_mal=78
   → F1 = 0.7839 giống hệt mọi seed — GIẢI THÍCH được, không phải bug).
   Khoảng cách "FL thua tfidf" là thật về hướng nhưng bản chất là FL
   non-IID chốt ở nghiệm majority-class, không phải chênh chất lượng tinh.
3. **FedProx(µ=.01) ≡ FedAvg chính xác ở mọi seed/split/block** — nhất quán
   round 8; µ này không đổi quỹ đạo (đã unit-test µ lớn có tác dụng).

## 4. LỆCH CHUẨN / DISCLOSE (honest)

1. **dataset.py KHÔNG sửa**: tasking cho phép sửa nhưng không có việc gì
   phải sửa — BKC fail probe → không có manifest client-3 mới; fallback
   npm_hook dùng chính corpus + features_v2. `data/packguard/` không thêm
   file nào.
2. **n=5 seeds không đủ power**: Wilcoxon 2 phía tối thiểu p=0.0625 > .05
   (đăng ký trước trong Amendment-3); mọi p trong report này là mô tả.
3. **per-client-best là ORACLE routing** (mỗi test sample do model của
   chính partition nó chấm) — là TRẦN của per-client deployment, không
   phải một system triển khai được; macro round-8 vẫn nằm trong row
   (`macro_metrics`).
4. **tfidf-FedAvg identical-F1 artifact**: do test set random-split giống
   hệt nhau giữa các seed (stratified, n=121/78 mal) cộng dự đoán suy
   biến — đã giải thích §3.4.2, không phải trùng số liệu bịa.
5. **Snapshot partition trong summary.md**: lần chạy đầu, snapshot bị cell
   CUỐI (random/tfidf) ghi đè — lỗi hiển thị, đã fix (chốt lấy cell
   group/graph) và CHẠY LẠI toàn bộ grid; số rows giữa 2 lần chạy GIỐNG
   NHAU ở mọi cell kiểm tra (4/4 spot-check đúng từng chữ) → determinism
   liên-process được xác nhận. Không có số nào đổi.
6. **MỘT cell "collapse" của centralized** được GIỮ NGUYÊN trong mọi
   aggregate (không loại); con số ".8519±.0177 khi loại cell sụp" chỉ là
   phân tích cảm tính được ghi rõ là sensitivity, không thay aggregate
   pre-reg.
7. npm_hook train client giữ 99%+ malicious ở MỌI seed (1 benign hooked
   duy nhất của corpus luôn rơi vào TRAIN trong 5 group split — verify
   từng seed); nếu nó rơi vào test ở seed khác, client đó sẽ 1-class —
   hiện KHÔNG xảy ra, nhưng lưu ý cho seed tương lai.
8. Không GPU, không LLM trong vòng này (đúng ràng buộc); không git commit.

## 5. TODO (cho vòng sau)

1. **N larger**: dataset pool DataDog 14k cho phép mở rộng ~10× — CI ±.05
   hiện tại là mức pilot; ưu tiên trước khi đụng GNN.
2. **Diagnose/fix central instability**: lr sweep hoặc early-stop theo
   validation nội bộ — phải là AMENDMENT-4 (không tune ngầm), kèm re-run
   grid.
3. **FedProx µ sweep 0.1/1.0 + client-weighting** (tasking F round-8 còn
   treo): grid này chỉ chạy µ=0.01 từ config.
4. **Client-3 thật**: BKC cần nguồn chính hãng (GitHub release/OSF) hoặc
   Maven Central benign crawl — ước tính >1 vòng, cần quyết định nguồn
   benign Maven trước khi hứa.
5. Kết nối grid này vào paper2 (bảng mean±std thay bảng 1-seed; thêm
   retracted-finding section cho instability).

## 6. SELF-TEST THẬT (đã chạy trong phiên)

- `.venv/bin/python -m pytest tests/test_packguard_multiseed.py -q`
  → **18 passed** (8.45s).
- `.venv/bin/python -m pytest tests/ -q` → **641 passed / 0 failed**
  (91.8s) — gồm 18 test mới của file này; số test có sẵn trong cây hiện
  tại là 623 (641 − 18; lệch +8 so với con số 615 của F round 8 — phần
  đó tồn tại trước khi tôi bắt đầu, không phải do tôi thêm).
- `.venv/bin/python -m packguard.eval --grid` → 160 rows, 62s CPU,
  `outputs/packguard/fl_multiseed/{grid_results.json,summary.md}`;
  chạy LẠI lần 2 sau fix snapshot: mọi số spot-check GIỐNG hệt
  (determinism liên-process).
- Cross-check round-8: seed 20260922 group/graph FedAvg .9231 /
  centralized .9282 = khớp bảng `reports/round8/F_report.md` chính xác.
- BKC probe: lệnh curl thật (Zenodo API records/3367650, records/14907786,
  search "backstabber"; HTTP range probe central-directory của zip
  336.8 MB; dasfreak.github.io 404) — log trong phiên; kết luận fail
  được ghi vào Amendment-3 A3.3.

Sources cho phần probe BKC (web): [BKC landing page](https://dasfreak.github.io/Backstabber-Knife-Collection/), [BKC GitHub](https://github.com/dasfreak/Backstabbers-Knife-Collection), [BKC paper arXiv:2005.09535](https://arxiv.org/abs/2005.09535).

---

*W1 round 9 không git commit. Mọi số truy vết được tới
outputs/packguard/fl_multiseed/grid_results.json (160 rows, mock=false,
config_sha16 1fd35c86ac6bef21).*
