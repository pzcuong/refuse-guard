# W1 Report — Round 11 (PackGuard P0: SỬA 3 BASELINE/THUẬT TOÁN + TOST 20 seeds)

Ngày: 2026-09-27. Owner: W1 (vòng 11, P0 theo audit reviewer Q1). Scope: (A1)
AMENDMENT-5 đăng ký TRƯỚC, (A2) fix FedProx, (A3) strong centralized +
standardization, (A4) HashingVectorizer thay tfidf arm, (A5) chạy thật 20 seeds,
(A6) TOST + Wilcoxon/Holm + μ-sweep + đối chiếu cũ/mới. Ràng buộc giữ nguyên:
CPU only, không git commit, KHÔNG bịa số — mọi số truy vết tới
`outputs/packguard/p0/p0_results.json` (360 runs, mock=false) và
`outputs/packguard/fl_multiseed/grid_results.json` (640 rows cũ, GIỮ NGUYÊN).

**STATUS: `framing-change-needed` (secondary) — primary claim ĐƯỢC XÁC NHẬN.**
TOST trên cell PRIMARY (group split, graph): **PASS** — FedAvg tương đương
strong-centralized ở ±0.02 F1. Nhưng trên split random (secondary), baseline cũ
bị undertrain đã che khuất một thắng lợi có ý nghĩa của centralized (Holm
p=.0247); và claim cũ "central thắng FL trên tfidf" (p=3.8e-06) bị THÁO GỠ vì
đó là artifact của 2 baseline bug. Chi tiết §5.

## 1. LÀM GÌ

### [A1] AMENDMENT-5 — DONE, đăng ký TRƯỚC khi chạy
`docs/packguard_prereg.md` có mục **AMENDMENT-5 (A5.1–A5.8)** với timestamp
2026-09-27T16:39:29Z — TRƯỚC lúc chạy grid (16:46:30Z). Nội dung khóa trước:
(a) strong centralized = sklearn LR `lbfgs, max_iter=5000, tol=1e-6` +
StandardScaler fit TRAIN + C ∈ {0.01,0.1,1,10} chọn bằng 3-fold stratified CV
TRÊN TRAIN ONLY (tie-break AUC rồi thứ tự grid); (b) TOST margin ±0.02 F1,
paired 20 seeds, 90% CI (t, df=n−1) nằm trọn (−0.02,+0.02) → equivalence;
(c) HashingVectorizer(2^18, alternate_sign=False, norm=l2) stateless thay
TF-IDF arm, dùng chung cho cả centralized; (d) FedProx fix + μ sweep
{0.01,0.1,1.0} chỉ group split; (e) disclose: kết quả cũ 5/20-seed GIỮ ở phần
so sánh lịch sử, không xóa.

### [A2] FIX FEDPROX — bug thật trong fl.py, đã xác nhận + sửa + test
**Bug (trích dòng, file TRƯỚC khi sửa):**
- `run_federated` (fl.py dòng 648 cũ) tính `mu = 0.0 if algo == "fedavg" else
  float(cfg.mu)` nhưng **không bao giờ dùng biến này khi train** — chỉ ghi vào
  meta output.
- `FedClient.local_update` (dòng 489–494 cũ) gọi
  `local_train(..., mu=cfg.mu, ...)` — đọc **cfg.mu trực tiếp**.
- Hệ quả: với config `mu_fedprox: 0.01`, CẢ arm "fedavg" lẫn arm "fedprox"
  đều chạy FedProx(μ=0.01) → bit-identical 160/160 cells (W2 audit đúng hiện
  tượng, sai chẩn đoán: term prox CÓ vào gradient — `models.local_train`
  implement đúng Li et al. 2020; bug nằm ở ROUTING algo trong fl.py).

**Fix (fl.py hiện tại):** `FedClient.local_update(..., mu: Optional[float] =
None)` (dòng 477–508): `eff_mu = cfg.mu if mu is None else mu` (backward-compat
cho caller trực tiếp); `run_federated` truyền mu per-algo xuống (dòng 672,
683–684): fedavg → 0.0, fedprox → cfg.mu. Thêm flag
`FLConfig.legacy_mu_routing` (dòng 107, default **False**): đặt True tái lập
CHÍNH XÁC hành vi cũ (cả 2 arm dùng cfg.mu) — chỉ để tái lập artifact cũ.

### [A3] STRONG CENTRALIZED + STANDARDIZATION — module mới
`packguard/strong_baseline.py` (mới): centralized = `LogisticRegression(
solver="lbfgs", max_iter=5000, tol=1e-6)` trên StandardScaler fit TRAIN của
từng (seed, split); C chọn 3-fold CV trên TRAIN ONLY; FL clients dùng CÙNG
scaler pooled-train (**disclosed shared preprocessing, no test leak**) và CÙNG
C (hyperparameter chọn ở pooled train — disclosed, không đụng test).
**FedAvg = local fit lbfgs (hội tụ) trên standardized share của từng client +
average có trọng số n** — phương án sạch nhất, rationale: (i) hội tụ chắc chắn
(SGD lr .1 không hội tụ = gốc của L1); (ii) local-fit-then-average là mô phỏng
FedAvg hợp lệ cho mô hình lồi (full-batch local fit rồi average); vòng lặp
round vẫn chạy (rounds=2, ghi history) — **80/80 cell là fixed point từ round 2
** (bài toán lồi hội tụ nên aggregate không đổi — đã verify số, ghi trong row
`fixed_point_from_round_2: true`), disclosure nằm trong AMENDMENT-5 A5.2.
**FedProx** = đúng local objective Li et al. 2020: mean log-loss + sklearn L2
(1/(2Cn))||w||² + (μ/2)||θ−θ_g||² (θ gồm intercept), giải bằng scipy L-BFGS-B
(jac analytic — gradient đã verify finite-difference maxdiff 1.7e-10), khởi
từ θ_g mỗi round, rounds=15, 120/120 local solve hội tụ.

### [A4] HASHING VECTORIZER — DONE
`HashingTextFeaturizer`: `HashingVectorizer(n_features=2**18,
alternate_sign=False, norm="l2")` — KHÔNG fit vocab (stateless → hợp lệ FL,
mở-ft-trên-pooled-vocab của TF-IDF cũ là leakage sai thiết lập FL); ma trận
hash toàn corpus tính 1 LẦN rồi slice theo split (transform stateless nên
giống hệt mọi seed); sparse nên standardize bằng `StandardScaler(with_mean=
False)` fit pooled TRAIN (scale-only, disclosed); tfidf-centralized cũng đổi
sang hashing để so sánh công bằng.

### [A5] CHẠY THẬT 20 SEEDS — DONE: **360 runs, mock=false, ~10.5 phút CPU**
20 seeds {20260922..20260941} × {group, random} × {graph, hashing}:
strong-centralized + FedAvg + per-client-best (240 runs) + FedProx μ sweep
{0.01,0.1,1.0} trên group (120 runs). Mỗi row ghi đủ {seed, split, block,
method, mu, mock:false, C_selected, cv_table, config_sha16 `5ee3764c59a8e4b3`,
date, client_sizes}. Split TÁI ĐỊNH NGHĨA bằng cùng `make_group_split`/
`make_global_test_split` cùng seed → train/test giống hệt round 9 (đối chiếu
cũ/mới hợp lệ cùng-split).

### [A6] TỔNG HỢP — xem §3–§5.

## 2. FILES (absolute)

Code (sửa/thêm):
- /Users/macbook/.zcode/workspace/default/refuseguard/packguard/fl.py — fix
  mu-routing + `legacy_mu_routing` flag (A2). Không hàm cũ nào đổi chữ ký
  ngoài `local_update` (thêm param optional `mu=None`).
- /Users/macbook/.zcode/workspace/default/refuseguard/packguard/strong_baseline.py —
  MỚI: scaler/CV/strong-LR/FedProx solver/FedAvg-S/per-client/P0 cell (A3+A4).
- /Users/macbook/.zcode/workspace/default/refuseguard/packguard/eval.py — thêm
  `tost_equivalence`, `holm_adjust`, `run_p0_grid`, `_aggregate_p0`,
  `_render_p0_summary`, CLI `--p0`; import `copy`/`numpy` module-level.
  Round-9 grid (`run_grid`) và round-8 pipeline KHÔNG đổi logic.
- /Users/macbook/.zcode/workspace/default/refuseguard/configs/packguard_fl.yaml —
  section `p0:` (seeds/splits/blocks/mu_values/fedprox_split/rounds/tost_margin).
- /Users/macbook/.zcode/workspace/default/refuseguard/docs/packguard_prereg.md —
  AMENDMENT-5.
- /Users/macbook/.zcode/workspace/default/refuseguard/tests/test_packguard_p0.py —
  MỚI, 12 tests (xem §6).

Outputs thật:
- /Users/macbook/.zcode/workspace/default/refuseguard/outputs/packguard/p0/p0_results.json
  (360 rows + per_seed_cells + aggregate {cells, comparisons, tost_primary,
  mu_sweep})
- /Users/macbook/.zcode/workspace/default/refuseguard/outputs/packguard/p0/summary.md
- /Users/macbook/.zcode/workspace/default/refuseguard/outputs/packguard/p0/run.log

KHÔNG đụng: packguard/{schema,graphs,features,dataset,kb,safety_port}.py,
models.py (đã đúng — bug không nằm ở đây), paper2/, data/, src/, scripts/.
Kết quả cũ outputs/packguard/fl_multiseed/ GIỮ NGUYÊN 100%.

## 3. KẾT QUẢ MỚI (số THẬT, truy vết p0_results.json; F1 mean±std trên 20 seeds)

### 3.1 Grid chính (partition ecosystem 2 client)

| split | block | strong-centralized | FedAvg | FedProx μ=.01 | per-client-best |
|---|---|---|---|---|---|
| group (PRIMARY) | graph | **.8778±.0422** | .8713±.0434 | .8757±.0425 | .8607±.0412 |
| group | hashing | .8746±.0391 | .8722±.0360 | .8715±.0357 | .8840±.0314 |
| random | graph | **.8874±.0203** | .8714±.0286 | — | .8749±.0241 |
| random | hashing | .9100±.0203 | .9063±.0198 | — | .9149±.0262 |

AUC các cell .88–.95; FedProx μ=.1/μ=1 tương tự μ=.01 (bảng đầy đủ trong
summary.md). C được CV chọn: group/graph {10.0: 16, 1.0: 2, 0.1: 2}/20 seeds
(mean 8.11), random/hashing chọn 10.0 mọi seed.

### 3.2 Ba kiểm định "baseline sạch" (đối chứng trực tiếp 3 audit findings)

1. **L1 collapse ĐÃ CHẾT TRỊ**: strong-centralized 80/80 cell **converged**
   (max n_iter = 69 << 5000), min F1 = **.7692**, KHÔNG cell nào < .6. Đối chiếu:
   centralized cũ (torch SGD lr .1) có cell sụp **.3750** (random/graph seed
   20260923) + các cell .326 ở vòng trước — cùng bài toán lồi, cùng split, chỉ
   khác solver/standardization ⇒ xác nhận chẩn đoán **undertrain**, không phải
   tính chất dữ liệu. Mean random/graph centralized: .8348±.1133 → **.8874±.0203**.
2. **W2 bit-identity ĐÃ GIẢI THÍCH + FIX**: không phải "prox không vào
   gradient" mà là routing bug (§1.A2). Sau fix, trên cell thật
   (20260922/group/graph) FedAvg(μ=0) vs FedProx(μ=.01) khác nhau ở prob-level
   (max |Δp| = .0022) dù F1 trùng do lượng tử hóa (12/13); unit test chốt
   μ=1.0 → khác chắc chắn, μ=1e-9 → ≈ FedAvg.
3. **L2 degenerate all-malicious ĐÃ CHẾT TRỊ**: 0/360 row mới có recall≥.999
   (tfidf cũ: 20/20 cell FedAvg recall=1.0, F1 .7839±0 trên random). Hashing
   FedAvg giờ .8722 (group) / .9063±.0198 (random) — biến thiên thật giữa seeds.

### 3.3 TOST equivalence (FedAvg − strong-centralized, paired 20 seeds, margin ±0.02 F1)

| split | block | ΔF1 mean±std | 90% CI (t19) | TOST | Wilcoxon exact p | Holm p |
|---|---|---|---|---|---|---|
| **group (PRIMARY)** | **graph** | **−.0065±.0171** | **[−.0133, +.0003]** | **PASS** | .119 | .356 |
| group | hashing | −.0024±.0117 | [−.0070, +.0022] | **PASS** | .312 | .624 |
| random | graph | −.0160±.0228 | [−.0251, −.0070] | **FAIL (thua)** | **.0062** | **.0247** |
| random | hashing | −.0037±.0135 | [−.0091, +.0017] | **PASS** | .404 | .624 |

**Verdict TOST primary: PASS** — "FedAvg ≈ strong-centralized tại ±0.02 F1"
trên group split (cả graph lẫn hashing). Toàn bộ 20 per-seed ΔF1 của cell
primary: 6 dương / 12 âm / 2 zero, max |Δ| = .0501.

### 3.4 FedProx μ sweep (group split, ΔF1 = FedProx(μ) − FedAvg, DESCRIPTIVE)

| block | μ | ΔF1 mean±std | dấu +/−/0 | Wilcoxon p |
|---|---|---|---|---|
| graph | 0.01 | +.0044±.0140 | 15/4/1 | .084 |
| graph | 0.1 | +.0048±.0214 | 13/7/0 | .452 |
| graph | 1.0 | +.0043±.0301 | 12/8/0 | .475 |
| hashing | 0.01 | −.0008±.0129 | 9/8/3 | .981 |
| hashing | 0.1 | −.0005±.0118 | 8/11/1 | .968 |
| hashing | 1.0 | +.0032±.0113 | 10/9/1 | .212 |

**Trả lời (iii) "FedProx tách khỏi FedAvg ở đâu":** (a) Ở mức NGHIỆM: tách từ
μ=0.01 (prob-level |Δp|=.0022 trên cell thật; μ=1.0 khác mạnh — test) — khác
với torch-path 2-epoch cũ nơi μ=.01 gần như trơ. (b) Ở mức METRIC: KHÔNG μ nào
tách có ý nghĩa (mọi p > .05; gần nhất graph μ=.01 p=.084, hướng có lợi nhẹ
cho FedProx ±.005 F1). Kết luận trung thực: FedProx chỉnh sửa nghiệm nhưng
không đổi kết luận F1 ở scale/recipe này.

## 4. ĐỐI CHIẾU CŨ/MỚI (bảng trước/sau — kết quả cũ GIỮ NGUYÊN, chỉ đổi baseline)

| Cell (ecosystem) | FedAvg cũ→mới | Centralized cũ→mới | ΔF1 cũ (p cũ) | ΔF1 mới (p exact, Holm) | Đọc |
|---|---|---|---|---|---|
| group/graph (PRIMARY) | .8686→.8713 | .8581→.8778 | +.0105 (p=.30 ns) | −.0065 (p=.119, .356) | FL≈central **GIỮ VỮNG** (TOST PASS) |
| random/graph | .8751→.8714 | .8348 (1 cell sụp .375)→.8874 | +.0403 (p=.13 ns) | **−.0160 (p=.0062, Holm .0247)** | **ĐẢO DẤU**: lợi thế FL cũ là do central undertrain |
| group/tfidf→hashing | .7898 (degenerate)→.8722 | .8419→.8746 | −.0521 (p=3.8e-06) | −.0024 (p=.312, ns) | Claim "central thắng FL trên tfidf" là **ARTIFACT baseline** (FL suy biến + vocab pooled) |
| random/tfidf→hashing | .7839±0→.9063 | .8415→.9100 | −.0576 (p=8.8e-05) | −.0037 (p=.404, ns) | Như trên |

Chú thích trung thực: "FedAvg cũ" thực chất là FedProx(0.01) (bug routing) —
số cũ vẫn hợp lệ NHƯ MỘT ĐOẠN CỦA FedProx(0.01)-torch; bảng này so baseline
mạnh vs baseline cũ ở cùng split/seed-set.

## 5. FRAMING-CHANGE-NEEDED (báo ĐÚNG theo tasking A6-iv)

- **Primary claim SỐNG SÓT và LÊN CẤP ĐỘ tin cậy**: reviewer nói "FedAvg ≈
  centralized p=.312 không phải claim dương" — đúng, nhưng sau khi sửa
  baseline, claim này giờ có dạng chính thức **TOST equivalence PASS tại
  ±0.02 F1 trên group split (primary, cả 2 block)** — một claim tương đương
  âm bản (proving absence of difference) thay vì "khôngsignificant". Paper
  nên viết lại theo hướng equivalence.
- **SECONDARY framing-change-needed**: (1) random/graph ĐẢO DẤU — centralized
  mạnh thật sự thắng FedAvg có ý nghĩa sau Holm (p=.0247); paper KHÔNG được
  viết "FL không bao giờ kém centralized". (2) Claim "central thắng FL trên
  tfidf" phải THÁO (artifact). (3) Collapse .375 của centralized cũ phải được
  viết lại thành **undertrain artifact của baseline cũ** (bài học multi-seed
  vẫn đứng: 1 seed có thể sai theo cả 2 hướng).
- Không sửa paper2 (F sẽ làm theo số này).

## 6. LỆCH CHUẨN / DISCLOSE (honest)

1. **Full suite có 1 fail TIỀN TỒN** `tests/test_round7_master.py::
   test_exists_branch` — thiếu artifact dữ liệu `outputs/master/
   round7_token_map.json` (ngoài không gian sở hữu của W1, không liên quan
   thay đổi vòng 11; 616 test khác pass).
2. FedAvg-strong là "local converged fit + average" (1-round hiệu lực; fixed
   point 80/80 từ round 2) — không mô phỏng partial local work của SGD FL;
   AMENDMENT-5 A5.2 đã đăng ký lựa chọn này.
3. Shared preprocessing (scaler + C trên pooled TRAIN) là giả định FL "central
   hyperparameter coordination" — disclosed mọi row; không test leak (scaler/CV
   chưa từng thấy test).
4. Hashing ma trận tính 1 lần cho cả corpus (stateless → hợp lệ; slice theo
   split; không có thông tin nhãn/vocab nào "fit").
5. per-client-best vẫn là ORACLE routing (định nghĩa A3.2 giữ nguyên).
6. μ sweep chỉ group split (giới hạn chi phí, đăng ký trước); μ-sweep là
   DESCRIPTIVE, không correction.
7. Per-ecosystem F1 (duty D4) KHÔNG lặp lại trong P0 rows (scope P0 là
   baseline-fix; duty D4 đã nằm trong grid round-9) — disclosed.
8. Không GPU/LLM; không git commit; không số bịa.

## 7. TODO

1. F cập nhật paper2: bảng equivalence + rút claim tfidf + ghi random/graph
   central-win + retracted-finding cho undertrain.
2. Cân nhắc P0-extension: DP/secure-agg trên recipe mạnh; AUC-PR/ECE
   (roadmap AMENDMENT-4 vẫn treo).
3. FedProx μ adaptive (μ_i theo client drift) — chỉ đáng làm nếu đo được gap
   lớn hơn ±.005 hiện tại.
4. Client-3 thật (BKC nguồn chính hãng) — unchanged từ round 9.

## 8. SELF-TEST THẬT (đã chạy trong phiên)

- `.venv/bin/python -m pytest tests/test_packguard_p0.py -q` → **12 passed**
  (gồm: μ=1.0 FedProx≠FedAvg + mu đạt local_train qua monkeypatch; μ=1e-9 ≈
  FedAvg; legacy flag tái lập bit-identity cũ; regression cell thật
  20260922/group/graph: fedprox(mới) == row cũ kể cả history_tail; hashing
  stateless; scaler/CV deterministic; fixed-point; TOST/Holm known-outcomes).
- `.venv/bin/python -m pytest tests/ -q` → **616 passed, 1 failed**
  (fail TIỀN TỒN test_round7_master — thiếu artifact ngoài scope, §6.1).
- `.venv/bin/python -m packguard.eval --p0` → 360 rows, ~10.5 phút CPU,
  `outputs/packguard/p0/{p0_results.json,summary.md}`; TOST primary
  `equivalent=True Δ=−.0065 CI=[−.0133,+.0003]`.
- Gradient solver verify finite-difference: maxdiff **1.7e-10** (sau khi bắt
  được + sửa bug resid `expit(z)−s` → `expit(z)−y` trong strong_baseline —
  bug của chính tôi, bắt bằng FD check trước khi chạy thật).
- Determinism: re-run cell seed 20260933 (4 cells × mọi method) → **ALL
  MATCH** tới 1e-12.
- Cross-check regression: fedprox(μ=.01, code mới) == row cũ 20260922/group/
  graph F1 .9230769 VÀ history_tail khớp từng chữ (test tự động).

---

*W1 round 11 không git commit. Mọi số mới truy vết tới
outputs/packguard/p0/p0_results.json (360 rows, mock=false, config_sha16
5ee3764c59a8e4b3); mọi số cũ giữ nguyên tại outputs/packguard/fl_multiseed/.*
