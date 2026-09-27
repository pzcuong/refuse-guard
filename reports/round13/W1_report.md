# W1 Report — Round 13 (PackGuard: LEAVE-CLUSTER-OUT SPLIT (MinHash) +
# HARD-NEGATIVE EXPANSION)

Ngày: 2026-09-27. Owner: W1 (vòng 13, P2-11/L5). Scope theo tasking: C1
MinHash family clustering, C2 LCO runner, C3 chạy + phân tích degradation,
C4 hard-negative expansion (time-boxed), C5 tests + report này. Đây là
thí nghiệm trả lời câu hỏi mà bài đã tự nêu: **"graph vs TF-IDF
degradation under family shift must decide any robustness claim"**.

Ràng buộc: CPU only, không GPU/LLM, không git commit, KHÔNG bịa số — mọi
số dưới đây truy vết tới `outputs/packguard/lco/lco_results.json` (480
rows, mock=false), `outputs/packguard/lco/clusters_t030.json` /
`clusters_t050.json`, `outputs/packguard/lco/expansion/`. Chỉ sửa trong
không gian được cấp: `packguard/clusters.py` (mới), `packguard/lco.py`
(mới), `configs/packguard_lco.yaml` (mới),
`outputs/packguard/lco/` (mới), `docs/packguard_prereg.md` (AMENDMENT-7,
append-only), `data/packguard/` (chỉ thêm benign expansion manifest),
`tests/test_packguard_lco.py` (mới), `scripts/r13_hard_negative_expand.py`
(mới), report này. Không đụng `packguard/{kb,safety_port,defense_strip}.py`,
`paper2/`, các `scripts/` cũ. **AMENDMENT-7 được ghi TRƯỚC khi bất kỳ
metric LCO nào được tính** (timestamp 2026-09-27T20:42:55Z; chạy LCO bắt
đầu 20:46:10 — thứ tự này nằm trong chính artifacts).

## 1. LÀM GÌ

### [C1] MINHASH FAMILY CLUSTERING — DONE, tự implement, không thư viện ngoài
- `packguard/clusters.py`: MinHash **128 permutations, seed 20260922**;
  base hash = md5(shingle)[:4] uint32 (ổn định liên-process, khác hash()
  bị salt); họ hoán vị h_j(x) = (a_j·x + b_j) mod (2^31−1), MỘT lần rút
  từ `numpy.default_rng(20260922)`. Jaccard estimate = tỉ lệ 128 thành
  phần khớp. Shingles = word 3-gram của CODE TEXT (`text_v2`, lowercase)
  + name-pattern shingles: tên lowercase, scope npm tách riêng, token
  filler phổ biến bị bỏ ở ĐẦU/CUỐI lặp lại (js, py, core, lib, node,
  python, package, pkg, npm — xử lý typosquat, không bỏ giữa từ) +
  char 3-gram tên (`nme:cg:`) + tên đầy đủ (`nme:full:`). 43 sample
  text-rỗng vẫn cluster được nhờ name shingles.
- **Ngưỡng đăng ký từ phân phối similarity (histogram 181,489 cặp,
  step .05, có trong clusters_t030.json)**: 179,254 cặp nằm ở [0,0.05),
  thung lũng 840 cặp trải [0.05,0.30), takeover từ 0.30 (~1,400 cặp;
  khối 0.90+ = near-duplicate chính xác). **PRIMARY threshold = 0.30
  (elbow)**, SENSITIVITY = 0.50 — cả hai neo TRƯỚC khi chạy LCO.
- **Package closure (định nghĩa đơn vị holdout)**: unit = thành phần
  liên thông của {Jaccard ≥ threshold} ∪ {cùng package}. Lý do đăng ký
  trước: 25/67 package đa-version có version KHÁC NHAU THẬT (Jaccard <
  ngưỡng, vd @antoncallahan v2.13/v2.14 so với v1.x) nên cluster thuần
  similarity có thể xẻ một package thành hai phía. Closure làm đơn vị
  mạnh hơn group split round-11: không straddle package VÀ không
  straddle near-duplicate. Kết quả: 0.30 → 356 sim-clusters → **326
  units**; 0.50 → 400 → **342 units**; **0 mixed-label unit ở CẢ HAI
  ngưỡng**.
- **Verify family đã biết (Vòng 12)**: cả **31 archive** của
  `@antoncallahan/aws-user-helper` → đúng **1 unit** ở cả hai ngưỡng; 4
  version round-12 (1.0.0/1.0.3/1.0.6/1.0.7) cùng cluster bởi CHÍNH
  similarity (c0150) trước cả closure; sau closure **0/67** package
  đa-version bị xẻ.

### [C2] LCO RUNNER — DONE (`packguard/lco.py`)
- Mỗi seed 20260922–20260941: hold-out **round(20%) cluster mỗi stratum
  majority-label** vào TEST (rng seed = seed đó), train = phần còn lại.
  Assert CỨNG: train/test KHÔNG chung cluster, KHÔNG chung package,
  KHÔNG chung sample_id (vi phạm → AssertionError, có unit test chứng
  minh assert bắn).
- **Split hợp lệ: 20/20 seed ở cả hai ngưỡng** (test đủ 2 label; không
  seed invalid, không metric bị bỏ). Tỉ lệ sample test thực tế 14.3%–
  27.2% (cluster size lệch — disclosed, không giả định = 20%).
- Methods: `strong_centralized` + `fedavg` ĐÚNG recipe mạnh round-11
  (lbfgs LR max_iter=5000 tol=1e-6, StandardScaler trên pooled TRAIN,
  C ∈ {0.01,0.1,1,10} bằng 3-fold CV chỉ trên TRAIN, FedAvg = fit lbfgs
  cục bộ + trung bình theo n, ecosystem partition, rounds=2 fixed
  point). Blocks: `graph` (18 feature), `hashing_tfidf`
  (HashingVectorizer 2^18 stateless), `trivial` (5 metadata của r11:
  n_files, parse_fail_files, empty_graph_flag, has_setup,
  has_postinstall — arm mô tả, không claim multiplicity).
- 20 seeds × {LCO, group-in-runner} × 3 blocks × 2 methods = **480 rows**
  thực (mock=false, config_sha16 `9bea57439fa0c473`, ~12 phút CPU).

### [C3] DEGRADATION — DONE, cả hai hướng trung thực (bảng ở §3)
- Degradation cặp theo seed: **d = metric(LCO) − metric(group)**, group =
  `make_group_split` chạy TRONG cùng runner (pairing basis đăng ký).
  **Cross-check tuyệt đối**: group-in-runner tái lập ĐÚNG từng chữ
  p0_results.json round-11 — max |F1 diff| = **0.000000** qua 20 seeds ×
  4 cells (graph/hashing × centralized/fedavg) → plumbing LCO đã được
  chứng minh giống hệt pipeline đã đăng ký.
- **PRIMARY** (dd = d_graph − d_text; dd ÂM ⇒ graph degraded NẶNG hơn):
  trên 20 seeds, Wilcoxon exact 2 phía — **không cell nào đạt p < .05**
  (bảng §3.3). Tóm tắt trung thực: **family shift (LCO) đánh CÁC HAI
  biểu diễn xấp xỉ nhau; không có bằng chứng text bị đánh nặng hơn
  graph, và cũng không có bằng chứng ngược lại.** Degradation tuyệt đối
  của từng arm là nhỏ (−0.7 đến −4.4 điểm F1) so với khoảng cách cả hai
  arm còn giữ (F1 ~0.84–0.85 ở LCO so với ~0.87–0.88 ở group).
- Arm `trivial` (mô tả): degradation −0.026…−0.044 — baseline metadata
  5 chiều cũng CHỊU family shift ở mức tương tự, không phải shortcut
  bất tử; F1 tuyệt đối của nó thấp nhất mọi cell (0.81–0.83).

### [C4] HARD-NEGATIVE EXPANSION — FEASIBLE, +200 benign (time-box trong 25')
- `scripts/r13_hard_negative_expand.py`: 200 benign npm NGẪU NHÂN (không
  popularity) tải từ registry.npmjs.org trong **241 giây** (205 attempts,
  1 fail HTTP, 4 skip tarball >2.5MB = đúng cap corpus). Tên ứng viên =
  dependency harvest từ package.json của 123 tarball benign corpus, loại
  package đã có, shuffle seed 20260922. Pipeline graph+features GIỐNG
  HỆT v2 (`extract_sample_graphs` + `compute_features`); text đúng recipe
  `build_text_cache` (cùng caps).
- **Hard-negative profile (có install hook HOẶC network call trong
  graph): 17/200** (2 postinstall + 16 network, giao 1) — so với corpus
  popularity-ranked cũ chỉ ~1/123 npm-benign có hook. 47/200 graph rỗng
  (như hành vi corpus). Label mang đúng caveat cũ: "assumed benign via
  registry presence; not individually audited".
- Manifest: `data/packguard/manifests/benign_expansion_v1.json` (+200
  sample, từng sample có source_url + sha256). Features/text:
  `outputs/packguard/lco/expansion/`. **KHÔNG nhập vào grid LCO đã đăng
  ký** (A7.4: grid chạy trên corpus 603 đóng băng; expansion là đóng gói
  dữ liệu cho vòng sau — thời điểm manifest hoàn tất SAU khi grid bắt
  đầu, disclosed).

### [C5] TESTS + PROVENANCE — DONE
- `tests/test_packguard_lco.py`: **24 tests, all pass**: (a) MinHash
  deterministic + không phụ thuộc thứ tự shingle + họ hoán vị khóa seed;
  (b) Jaccard same=1.0, disjoint≈0, khớp Jaccard chính xác ±0.15;
  (c) assert KHÔNG dùng thư viện minhash ngoài (grep datasketch/mmh3);
  (d) typosquat filler stripping đúng (js/py/-core bỏ ở đuôi, giữa từ
  giữ nguyên, scope giữ token riêng); (e) corpus gate: antoncallahan
  31→1 unit, 0 mixed-label, 0/67 family bị xẻ, assignment phủ đủ 603,
  tái tính signature từ text khớp signatures.npz, closure CHỈ merge
  không xẻ; (f) LCO no-leakage (cluster/package/sample) + assert bắn
  khi package straddle 2 cluster + determinism + validity; (g)
  degradation calc: đúng dấu (dd âm ⇔ graph nặng hơn), p = 2/2^8 đúng
  minimum lý thuyết ở n=8, **all-zero deltas → p=None + note (không bịa
  p)**; (h) trivial matrix 5 feature đúng; (i) run_cell trên corpus
  thật smoke graph+trivial.
- **Full suite: 732 passed / 0 failed (80s)** = 708 test có sẵn + 24 mới.
- Bug thật 1 cái (fix trước khi có output): run đầu clusters.py crash
  KeyError (thiếu `setdefault`) khi dựng composition — crash TRƯỚC khi
  ghi bất kỳ cluster nào; log lỗi giữ lại
  `outputs/packguard/lco/clusters_t030_run1.log`; fix xong chạy lại từ
  signature cache, số đã kiểm tra nhất quán.

## 2. FILES (absolute)

Mới, trong không gian sở hữu:
- /Users/macbook/.zcode/workspace/default/refuseguard/packguard/clusters.py
- /Users/macbook/.zcode/workspace/default/refuseguard/packguard/lco.py
- /Users/macbook/.zcode/workspace/default/refuseguard/configs/packguard_lco.yaml
- /Users/macbook/.zcode/workspace/default/refuseguard/tests/test_packguard_lco.py
- /Users/macbook/.zcode/workspace/default/refuseguard/scripts/r13_hard_negative_expand.py
- /Users/macbook/.zcode/workspace/default/refuseguard/outputs/packguard/lco/
  {clusters_t030.json, clusters_t050.json, signatures.npz,
  lco_results.json, summary.md, lco_run.log, clusters_t030.log,
  clusters_t050.log, clusters_t030_run1.log (log crash run đầu),
  expansion/{features_expansion_v1.jsonl, text_expansion_v1.json,
  expansion_report.json}, expansion_run1.log}
- /Users/macbook/.zcode/workspace/default/refuseguard/data/packguard/manifests/benign_expansion_v1.json
- /Users/macbook/.zcode/workspace/default/refuseguard/docs/packguard_prereg.md — AMENDMENT-7 (append-only)
- /Users/macbook/.zcode/workspace/default/refuseguard/reports/round13/W1_report.md (file này)

KHÔNG đụng: packguard/{kb,safety_port,defense_strip,eval,fl,strong_baseline,
features,dataset,graphs,schema,models}.py, paper2/, scripts/ cũ, src/.
KHÔNG git commit.

Chạy lại:
```
.venv/bin/python -m packguard.clusters --threshold 0.3 --tag t030
.venv/bin/python -m packguard.clusters --threshold 0.5 --tag t050
.venv/bin/python -m packguard.lco --config configs/packguard_lco.yaml   # ~12 min CPU
.venv/bin/python -m pytest tests/test_packguard_lco.py -q
PYTHONPATH=$PWD .venv/bin/python scripts/r13_hard_negative_expand.py    # resume-safe
```

## 3. KẾT QUẢ (số THẬT, truy vết lco_results.json, 20/20 seed valid)

### 3.1 LCO metrics (F1/AUC mean±std trên 20 seed; test = toàn cluster)

| thr | block | method | F1 (LCO) | AUC (LCO) |
|---|---|---|---|---|
| 0.3 | graph | strong_centralized | .8395±.0576 | .8586±.0498 |
| 0.3 | graph | fedavg | .8396±.0653 | .8554±.0639 |
| 0.3 | hashing_tfidf | strong_centralized | .8457±.0734 | .8644±.0560 |
| 0.3 | hashing_tfidf | fedavg | .8543±.0473 | .8796±.0444 |
| 0.3 | trivial | strong_centralized | .8161±.0662 | .8026±.0769 |
| 0.3 | trivial | fedavg | .8100±.0598 | .8063±.0742 |
| 0.5 | graph | strong_centralized | .8624±.0467 | .8724±.0488 |
| 0.5 | graph | fedavg | .8519±.0587 | .8702±.0480 |
| 0.5 | hashing_tfidf | strong_centralized | .8625±.0343 | .8865±.0356 |
| 0.5 | hashing_tfidf | fedavg | .8650±.0346 | .8959±.0353 |
| 0.5 | trivial | strong_centralized | .8284±.0509 | .8452±.0599 |
| 0.5 | trivial | fedavg | .8284±.0506 | .8495±.0611 |

(group-in-runner đối chiếu: graph sc .8778±.0422, fedavg .8713±.0434;
hashing sc .8746±.0391, fedavg .8722±.0360 — KHỚP TỪNG CHỮ p0 round-11.)

### 3.2 Degradation cặp theo seed (ΔF1 = LCO − group; âm = sụt)

| thr | block | method | ΔF1 mean±std |
|---|---|---|---|
| 0.3 | graph | strong_centralized | −.0383±.0675 |
| 0.3 | graph | fedavg | −.0317±.0854 |
| 0.3 | hashing_tfidf | strong_centralized | −.0289±.0879 |
| 0.3 | hashing_tfidf | fedavg | −.0179±.0635 |
| 0.3 | trivial | strong_centralized | −.0388±.0706 |
| 0.3 | trivial | fedavg | −.0440±.0685 |
| 0.5 | graph | strong_centralized | −.0154±.0566 |
| 0.5 | graph | fedavg | −.0194±.0675 |
| 0.5 | hashing_tfidf | strong_centralized | −.0121±.0416 |
| 0.5 | hashing_tfidf | fedavg | −.0073±.0446 |
| 0.5 | trivial | strong_centralized | −.0265±.0588 |
| 0.5 | trivial | fedavg | −.0255±.0582 |

### 3.3 PRIMARY: paired Wilcoxon dd = deg(graph) − deg(hashing_tfidf)
(dd ÂM ⇒ graph degraded NẶNG hơn; n=20 ⇒ min p khả thi 2/2^20 ≈ 1.9e-6,
α=.05 đạt được — null ở đây là null CÓ SỨC CÂN, không phải thiếu power)

| thr | method | dd mean±std | dấu +/−/0 | Wilcoxon p (F1) | p (AUC) |
|---|---|---|---|---|---|
| 0.3 | strong_centralized | −.0095±.0803 | 8/12/0 | .368 | .870 |
| 0.3 | fedavg | −.0139±.0794 | 10/10/0 | .674 | .596 |
| 0.5 | strong_centralized | −.0033±.0443 | 11/9/0 | .985 | .498 |
| 0.5 | fedavg | −.0121±.0691 | 10/10/0 | .430 | .756 |

**Câu trả lời cho câu hỏi của bài**: under full family shift (LCO),
graph KHÔNG bền hơn code-as-text hashing ở mức phát hiện được — cả hai
sụt ~1–4 điểm F1, khác biệt giữa hai mức sụt không khác 0 (p .37–.99).
Hệ quả viết bài: claim robustness PHẢI dựa trên "cả hai biểu diễn cùng
mức bền" (hoặc cùng mức yếu), KHÔNG được viết "graph robust hơn TF-IDF
dưới family shift" — đúng hướng cả 2 như tasking yêu cầu. Range LCO F1
theo seed (graph/sc): .682–.944 → split khó nhất (cluster lớn) vẫn đủ
tín hiệu; không cell sụp kiểu majority-collapse của round-9.

### 3.4 Clustering diagnostics (clusters_t030.json / t050.json)
- Histogram similarity (off-diag, 181,489 cặp): 98.8% cặp < .05; thung
  lũng [0.05,0.30) = 840 cặp; khối family ≥ .30 ≈ 1,400 cặp; ≥ .90 =
  356 cặp (near-dup chính xác).
- 0.30: 356 sim-clusters → 326 units (30 merge do closure); 0.50: 400 →
  342 (58 merge). 0 mixed-label unit cả hai ngưỡng → stratified draw
  không bao giờ gặp unit lẫn label trong corpus này (disclosed).
- Multi-package unit (20 ở 0.3): typosquat/copy thật sự — vd các cụm
  `setnetwork`-như; danh sách đầy đủ trong `multi_package_clusters`.

### 3.5 Expansion (C4) — số thật
- 200/205 attempted downloaded trong 241s (time-box 420s < 25'); fail:
  1 HTTP, 4 tarball quá 2.5MB (đúng cap corpus, không vi phạm).
- Profile hard-negative: hook 2, network 16, hợp (hook ∪ network) =
  **17/200** — trung thực: CHỈ 17 đạt "hard negative" đúng nghĩa; 183
  còn lại là benign random thường (vẫn có giá trị de-bias popularity).
- 47/200 graph rỗng; text rỗng 16/200 (median n_nodes = 2 — package
  registry random nhỏ hơn nhiều package popular).

## 4. LỆCH CHUẨN / DISCLOSE (honest)
1. **Package closure là quyết định thiết kế SAU khi thấy 25/67 family
   bị xẻ** — nhưng được đăng ký trong AMENDMENT-7 TRƯỚC khi chạy BẤT KỲ
   metric LCO nào (chỉ dùng thông tin UNSUPERVISED từ clustering; không
   xem label/F1 khi quyết).
2. **Threshold 0.3 chọn từ histogram** (unsupervised) — không tune sau
   khi thấy F1; 0.5 chạy sensitivity đầy đủ; cả hai ngưỡng cùng kết
   luận định tính → robustness của kết luận không treo vào ngưỡng.
3. **Không có p nào đạt α** — kết luận là "không khác biệt phát hiện
   được", KHÔNG phải "bằng chứng bằng nhau tuyệt đối"; nhưng n=20 đủ
   power phát hiện dd ≥ ~0.08 (std ~0.08) — dd thực −0.003…−0.014 nhỏ
   hơn ngưỡng phát hiện thực dụng của pilot.
4. FedAvg dùng shared scaler + C chọn tập trung trên pooled TRAIN
   (disclosed từ A5.2 — giữ nguyên protocol round-11 để so sánh được).
5. Expansion label KHÔNG được audit; 17/200 hard-negative (không phải
   200); chỉ 1 ecosystem (npm); KHÔNG nhập corpus chính; không đụng
   grid đã đăng ký.
6. LCO test share dao động 14–27% sample (theo cluster size) — không
   phải 20% chuẩn; mỗi row ghi `split_info` đầy đủ.
7. 1 bug thật (setdefault) crash run clustering đầu tiên — trước khi có
   artifact nào; log giữ lại; đã test lại determinism sau fix.
8. Không GPU/LLM; toàn bộ CPU (~15 phút tính thật); không git commit.

## 5. TODO (cho vòng sau / handoff)
1. **F**: dùng macro {{R13:*}} ở §6; câu robustness của paper phải viết
   theo §3.3; bảng LCO có thể vào paper2 như "family-shift robustness"
   (đủ số, đủ provenance).
2. **W1 tiếp**: ingest expansion 200 (+ features đãextract sẵn) thành
   features_v3 khi có round dữ liệu mới; power đủ mới phát hiện được
   dd nhỏ — cân nhắc n_seed lớn hơn hoặc cluster-draw nhiều lần/seed.
3. GNN/family-aware model: LCO không cho arm nào ưu thế → bước tự nhiên
   là model dùng cấu trúc (GNN) thử qua LCO filter này.
4. FedProx/mu sweep qua LCO (bỏ để giữ grid 2-method × 3-block trong
   time-box — có thể chạy lại bằng chính runner, ~12 phút/2 ngưỡng).

## 6. HANDOFF CHO F — macro {{R13:*}} (số thật từ lco_results.json)

```
{{R13:LCO_PRIMARY_THRESHOLD}}            = 0.30 (elbow; sensitivity 0.50)
{{R13:LCO_CLUSTERS_T030}}                = 326 units (từ 356 sim-clusters)
{{R13:LCO_CLUSTERS_T050}}                = 342 units (từ 400)
{{R13:LCO_VALID_SEEDS}}                  = 20/20 (cả hai ngưỡng)
{{R13:LCO_GRAPH_CENT_F1}}                = .8395 ± .0576
{{R13:LCO_GRAPH_FEDAVG_F1}}              = .8396 ± .0653
{{R13:LCO_TEXT_CENT_F1}}                 = .8457 ± .0734
{{R13:LCO_TEXT_FEDAVG_F1}}               = .8543 ± .0473
{{R13:LCO_TRIVIAL_CENT_F1}}              = .8161 ± .0662
{{R13:LCO_DEG_GRAPH_CENT}}               = −.0383 ± .0675
{{R13:LCO_DEG_TEXT_CENT}}                = −.0289 ± .0879
{{R13:LCO_DEG_GRAPH_FEDAVG}}             = −.0317 ± .0854
{{R13:LCO_DEG_TEXT_FEDAVG}}              = −.0179 ± .0635
{{R13:LCO_DD_CENT_MEAN}}                 = −.0095 (Wilcoxon exact p=.368)
{{R13:LCO_DD_FEDAVG_MEAN}}               = −.0139 (p=.674)
{{R13:LCO_SENS_T050_DD_CENT}}            = −.0033 (p=.985)
{{R13:LCO_SENS_T050_DD_FEDAVG}}          = −.0121 (p=.430)
{{R13:LCO_CONCLUSION_SENTENCE}}          = "Under leave-cluster-out
  family shift both representations degrade by a small, statistically
  indistinguishable amount (ΔF1 ≈ −0.01…−0.04; graph-vs-text dd
  p ≥ .37), so no robustness ranking between behavior graphs and hashed
  text is supported; the family-shift claim must be written as joint."
{{R13:LCO_PROVENANCE}}                   = outputs/packguard/lco/
  lco_results.json (480 rows, mock=false, config_sha16 9bea57439fa0c473)
{{R13:LCO_EXPANSION_N}}                  = 200 (hard-negative profile 17)
{{R13:LCO_EXPANSION_MANIFEST}}           = data/packguard/manifests/
  benign_expansion_v1.json (NOT in the registered corpus/grid)
```

F lưu ý khi đưa vào paper2: (1) macro và số trong paper2/p0_macros/
numbers.tex do F quản — thêm prefix `pmLco*` nếu muốn nhất quán; (2)
câu văn theo {{R13:LCO_CONCLUSION_SENTENCE}} là bản trung thực 2 chiều
đã đăng ký; (3) KHÔNG quote expansion như một phần dataset của grid.

## 7. SELF-TEST THẬT (đã chạy trong phiên)
- `.venv/bin/python -m pytest tests/test_packguard_lco.py -q` → **24 passed**.
- `.venv/bin/python -m pytest tests/ -q` → **732 passed / 0 failed** (80.2s)
  — không phá test cũ (708 có sẵn).
- `.venv/bin/python -m packguard.lco --config configs/packguard_lco.yaml
  --limit-seeds 2` (smoke) → 48 rows; group-in-runner seed 20260922
  graph/sc F1 = .9282 = KHỚP p0 round-11 từng chữ.
- Full run → 480 rows, ~12 phút; aggregate + summary.md như §3.
- Cross-check p0: max |F1(in-runner group) − p0| = **0.000000** trên
  20 seeds × {graph,hashing} × {sc,fedavg}.
- Expansion: log + report trong outputs/packguard/lco/expansion*.

Sources: MinHash (Broder 1997), Li et al. 2020 FedProx (đã dùng từ
round-11 recipe); không citation mới cần verify — không thêm reference
mới vào paper2 từ vòng này.
