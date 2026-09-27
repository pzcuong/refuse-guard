# V1 Report — Round 11 (AUDIT ADVERSARIAL W1: FedProx fix / strong baseline / Hashing / TOST)

Ngày: 2026-09-27. Auditor: V1 (vòng 11). Đối tượng: `reports/round11/W1_report.md`
+ code/outputs của W1. Phương pháp: KHÔNG tin báo cáo — tự tính lại mọi số từ
JSON thô, tự viết mini-implementation FedProx độc lập trong /tmp, tự chạy lại
cell thật + test. Không sửa code của ai; chỉ tạo file này + /tmp scripts.

## VERDICT W1: **PASS** (2 ISSUES [MINOR] về self-report, không đụng claim)

Cả 4 fix đều đúng bản chất và mọi số liệu chính của W1 đều tái lập được độc
lập từ `outputs/packguard/p0/p0_results.json` (360 rows, mock=false, 20 seeds
20260922–20260941) và `outputs/packguard/fl_multiseed/grid_results.json` (giữ
nguyên, mtime 09-25 06:50). Chi tiết từng mục theo checklist:

### 1. FedProx fix — ĐÚNG THUẬT TOÁN
- **Vị trí prox term đúng**: torch path `packguard/models.py::local_train`
  (không đổi, mtime 09-21) cộng `(mu/2)·Σ(p−g)²` vào loss Ở MỖI minibatch step
  (dòng 125–129) — đúng Li et al. 2020 per-step. Scipy path
  `strong_baseline.py::local_fit_fedprox` minimize đúng objective
  `mean log-loss + (1/2Cn)||w||² + (μ/2)||θ−θ_g||²` (θ gồm intercept).
  **Liêm mạnh — implementation độc lập của tôi** (/tmp/v1_indep_fedprox.py,
  viết từ đầu, không dùng solver của W1): (a) FD check gradient analytic của
  W1 → maxdiff **6.1e-10**; (b) L-BFGS-B của W1 vs vanilla gradient descent
  của tôi cùng objective, μ=1.0 → max|Δθ| **3.9e-8**, cùng giá trị objective
  0.6272028097217; (c) hướng cập nhật đúng: FedProx(μ=1) kéo θ về θ_g
  (dot(θ_prox−θ_avg, θ_avg−θ_g) = −1.73 < 0), μ=1e-9 ≡ FedAvg; torch path:
  max|μ=0 − μ=1| = 0.224, max|μ=0 − μ=1e-12| = 0.0 (bit-correct).
- **Routing đúng**: `fl.py` dòng 669–672: legacy flag False → fedavg mu=0.0,
  fedprox mu=cfg.mu; dòng 683–684 truyền `mu=mu` xuống `local_update` →
  `eff_mu` (dòng 497). Unit test spy xác nhận mu thật sự tới solver
  (fedavg leg chỉ nhận 0.0, fedprox leg nhận 1.0) — **12/12 test PASSED khi
  tôi chạy lại** (`pytest tests/test_packguard_p0.py -v`).
- **Legacy flag tái lập đúng hành vi cũ**: old grid xác minh từ JSON —
  fedavg vs fedprox **80/80 cell F1 identical + 80/80 history_tail identical**
  (= 160 rows/160, đúng như W2 audit). `legacy_mu_routing=True` cho
  bit-identity (test PASSED). **Regression cell thật 20260922/group/graph**:
  fedprox(μ=.01, code mới) == row cũ F1 **0.9230769230769231** + history_tail
  từng chữ (test `test_fixed_fedprox_mu001_reproduces_round9_grid_row`
  PASSED khi tôi chạy lại); max|Δp| fedavg-vs-fedprox = **0.00220** — khớp
  đúng con số ".0022" trong report. Chẩn đoán "old 'fedavg' rows WERE
  FedProx(0.01)" được chứng minh bằng artifact, không phải suy diễn.

### 2. TOST — ĐÚNG, TÍNH LẠI INDEPENDENT KHỚP 100%
- **(a) Tự tính lại từ per-seed F1** (script /tmp/v1_audit_stats.py, không
  import code aggregate của W1): primary group/graph: mean ΔF1 **−.00649**,
  sd 0.0176 (ddof=1), t(0.95,19)=1.729 → 90% CI **[−.0133, +.0003]** ⊂
  (−.02,+.02) → PASS. Khớp từng chữ số với W1. 3 cell còn lại cũng khớp:
  group/hashing [−.0070,+.0022] PASS; random/graph [−.0251,−.0070] FAIL;
  random/hashing [−.0091,+.0017] PASS.
- **Logic CI90-bao-margin ĐÚNG**: quy tắc "90% CI của mean nằm trọn
  (−δ,+δ)" chính là Schuirmann TOST ở α=.05 (2 one-sided tests, mỗi cái
  α=.05) — tương đương chuẩn, không phải lách. `tost_equivalence` dùng
  t.ppf(0.95, n−1), sd ddof=1 — đúng.
- **(b) Không có lỗi "chọn rồi test trên cùng data"**: margin ±0.02 KHÓA
  TRƯỚC trong AMENDMENT-5 (text có rõ "registered 2026-09-27T16:39:29Z
  BEFORE any round-11 P0 run"; mtime file prereg 09-27 23:40 giờ local =
  16:40Z, trước code mới nhất 16:54Z và trước run start **16:56:59Z** ghi
  trong meta của p0_results.json). Margin không phụ thuộc dữ liệu; seeds
  không chọn lại. LƯU Ý [MINOR]: W1 report ghi "chạy grid (16:46:30Z)" —
  artifact thật ghi 16:56:59Z; thứ tự prereg-trước-run VẪN ĐÚNG dù lấy thời
  điểm nào (16:46 và 16:56 đều > 16:39:29Z).
- **(c) Paired đúng seed**: tôi assert `sorted(fa)==sorted(sc)` theo seed
  cho cả 4 cell — 20/20 seed khớp từng cặp; per-seed delta của primary =
  6 dương/12 âm/2 zero, max|Δ|=.0501 — khớp đúng report W1.

### 3. Strong centralized — "STRONG" THẬT, KHÔNG LEAK, CÔNG BẰNG
- **(a) Scaler train-only**: grep toàn bộ `.fit(` trong
  `packguard/strong_baseline.py` + `eval.py`: chỉ `sc.fit(X_train)` (dòng
  132) và `model.fit` trong fit_lr (gọi trên train/CV-folds). Test chỉ
  được `transform`. Không đường nào fit trên test.
- **(b) C chọn train-only**: `select_c_cv(Xs_train, y_train, ...)` —
  3-fold stratified, shuffle, random_state=seed, tie-break (F1, AUC, −grid
  order) đúng như đăng ký A5.1. Phân bố C group/graph đếm lại từ JSON:
  {10.0: 16, 1.0: 2, 0.1: 2}/20 seeds, mean 8.11 — khớp report;
  random/hashing = 10.0 mọi seed — khớp.
- **(c) Hội tụ**: 80/80 cell `converged=true`, max n_iter = **69** << 5000
  (đếm lại từ method_detail của 80 row strong_centralized).
- **(d) 0/80 collapse tái lập**: min F1 strong_centralized = **.7692**,
  0 cell < .6 (đối chiếu: old torch centralized min = **.3261** (seed
  20260935, group/graph) và .3750 đúng tại random/graph seed 20260923 như
  report — cả hai tìm thấy trong old grid JSON). Mean random/graph
  centralized cũ .8348±.1133 → mới .8874±.0203 — khớp chính xác.
- **(e) So sánh CÔNG BẰNG (symmetric)**: cả 3 arm trong 1 cell DÙNG MỘT
  scaler (pooled TRAIN) và MỘT C — centralized KHÔNG được ưu đãi chuẩn hóa
  riêng; FedAvg/prox/per-client cũng chạy trên standardized share.
  Hai giả định disclosed đúng chỗ: scaler+C là "central coordination" của FL
  (không test leak), và FedAvg = converged-local-fit + average (fixed point
  80/80 từ round 2 — đếm lại đúng 80/80 `fixed_point_from_round_2=true`;
  fedprox 120/120 `all_local_converged=true`). Không flag lệch so sánh.

### 4. HashingVectorizer — ĐÚNG VÀ ĐỦ "STATELESS"
- Config thật: n_features=2^18, alternate_sign=False, norm=l2, analyzer=word
  (in spec từ object thật). Trên text cache THẬT (603 texts): transform cùng
  texts theo batch order khác nhau → 0 khác biệt; transform 1 text lẻ == row
  tương ứng trong batch (slice-invariant); 100% rows có nnz>0 (không row
  rỗng). Matrix hash tính 1 lần rồi slice theo split — hợp lệ FL (không có
  vocab fit).
- **0/360 degenerate tái lập**: đếm recall≥.999 trên 360 row mới = **0**;
  hashing FedAvg có biến thiên thật (group .8722±.0360, random
  .9063±.0198). Đối chiếu cũ: old tfidf fedavg random = .7839±**0.0000**,
  recall=1.0 ở **20/20** cell ecosystem (40/40 row nếu tính cả npm_hook) —
  degenerate cũ có thật.
- **Claim cũ p=3.8e-06 đã chết đúng nghĩa**: tìm thấy trong old grid
  aggregate `ecosystem__group__tfidf → p_value = 3.8147e-06` (số cũ không
  bị sửa); p mới hashing: group **.3118**, random **.4038** — khớp .312/.404
  của W1.

### 5. Secondary central-win (random/graph) — SỐ ĐÚNG, FRAMING ĐÚNG
Tự Wilcoxon exact lại từ per-seed deltas: ΔF1 = **−.0160** (4+/15−/1 zero),
p_exact = **.00618**, Holm (4 comparisons) = **.02472** — khớp đúng W1
(.0062/.0247). Diễn giải "FL có cost nhỏ trên random split với baseline mạnh"
CHÍNH XÁC, và cần kèm 2 ngữ cảnh khi lên paper: (i) đây là split SECONDARY
chứa near-duplicate leakage (35% test rows theo V2 — lý do group là primary),
trong khi split PRIMARY vẫn equivalence PASS; (ii) FAIL TOST cùng cell có CI
hoàn toàn dưới 0 — không phải "chưa đủ dữ kiện" mà là khác biệt âm có hướng.

### 6. Regression + determinism — ĐẠT MỨC BIT-EXACT
- Regression fedprox(μ=.01, mới) == row cũ: PASS (test chạy lại bởi tôi; F1
  khớp 16 chữ số; history_tail khớp chuỗi).
- Determinism seed 20260933 (group/graph, đủ 6 method): tôi tự chạy lại
  `run_p0_cell` → **TẤT CẢ diff = 0.00e+00** (bit-exact, mạnh hơn claim
  "1e-12" của W1).

### 7. test_round7_master — PRE-EXISTING, KHÔNG PHẢI REGRESSION VÒNG 11
File `outputs/master/round7_token_map.json` **TỒN TẠI** (mtime 09-21 14:52).
Fail KHÔNG phải vì thiếu file thật: test monkeypatch `ROOT=tmp_path` nhưng
fixture chỉ ghi `round7_master.json` vào tmp — trong khi `fig_round7` (bản
make_figures tại HEAD commit **69c6a4b, 2026-09-26**, "Fig8a redrawn from
round7_token_map") mới thêm dependency `load("outputs/master/round7_token_map.json")`
qua ROOT-relative `load()`. Test viết từ Round-7 (d5a4531) chưa biết
dependency này → fixture gap. `git status`: W1 KHÔNG đụng `paper/make_figures.py`
lẫn `tests/test_round7_master.py` → regression của commit layout 26-09
(giai đoạn giữa round 10 và 11), đúng như nghi vấn "make_figures rewrite
Sep 26". Fix 1 dòng (fixture copy token_map vào tmp_path) — để orchestrator
quyết định, tôi không sửa.

### 8. Full suite — 674 passed / 1 failed (675 collected) HIỆN TẠI
- Số của tôi (vừa chạy): `pytest tests/ -q` → **674 passed, 1 failed**
  (80.5s; fail duy nhất = test_round7_master như trên; 0 skip).
- Cấu trúc: HEAD = 650 tests + 12 (test_packguard_p0, W1) + 13
  (test_packguard_trivial, W2) = **675**. W2 report "673/1" gần đúng
  (chạy trước khi bộ test cuối ghép đủ); **W1 report "616 passed, 1 failed"
  (=617) KHÔNG TÁI LẬP ĐƯỢC** —expected tại thời điểm W1 là ~662 (650+12).
  [ISSUE MINOR] — count stale/ghi sai, nhưng phần load-bearing ("fail duy
  nhất, pre-existing test_round7_master") là ĐÚNG.

## CONFIRMED BUGS (của W1 tự report, tôi xác nhận)
1. FedProx routing bug trong fl.py (cũ): `mu` tính per-algo nhưng không được
   truyền xuống; `local_update` đọc `cfg.mu` → cả 2 arm chạy FedProx(cfg.mu).
   ĐÃ FIX đúng + legacy flag tái lập 160/160 (xem §1).
2. (Tự bắt trước khi chạy thật, W1 disclose) resid `expit(z)−s` → `expit(z)−y`
   trong strong_baseline gradient — bản hiện tại là ĐÚNG (FD của tôi 6.1e-10).

## FALSE CLAIMS (điều chỉnh, không có claim chính nào sai)
1. [MINOR] W1 §8: "616 passed, 1 failed" — không tái lập được (thực tế 674/1
   hiện tại; ~662 tại thời điểm W1). Số fail-set đúng, count sai.
2. [MINOR] W1 §1/A1: "chạy grid (16:46:30Z)" — artifact meta ghi run start
   **16:56:59Z** (mtime output 17:06Z, runtime ~9.3' ≈ claim 10.5'). Thứ tự
   prereg (16:39:29Z) → run KHÔNG đổi, nhưng con số giờ trong report sai.
3. [MINOR] W1 §6.1 diễn giải fail round7 là "thiếu artifact dữ liệu" — file
   THẬT CÓ; fail là fixture-gap của test với make_figures bản 26-09. Kết luận
   "pre-existing, ngoài scope W1" vẫn đúng.
4. [COSMETIC] ±std trong bảng §3.3 của W1 là population std (ddof=0); CI đúng
   dùng ddof=1 (sd 0.0176 vs bảng .0171). Không ảnh hưởng verdict.

## TOST + CENTRAL-WIN — VERDICT DỨT KHOÁT CHO PAPER
1. **Equivalence PASS trên primary GIỮ ĐƯỢC, lên grade chính thức**:
   group split (primary) PASS ở CẢ graph (ΔF1 −.0065, 90% CI [−.0133,+.0003])
   và hashing ([−.0070,+.0022]); random/hashing cũng PASS ([−.0091,+.0017]).
   Paper được viết: "FedAvg tương đương strong centralized tại ±0.02 F1 trên
   group split" — claim tương đương âm bản, có prereg margin, 20 seeds paired,
   TOST chuẩn (CI90-bao-margin ≡ 2 one-sided tests α=.05). Đủ bằng chứng.
2. **Central-win random/graph PHẢI VÀO PAPER, diễn đạt như sau**: "Trên split
   random (secondary, có near-duplicate leakage), strong centralized thắng
   FedAvg trung bình .0160 F1 (4+/15−/1; Wilcoxon exact p=.0062, Holm .0247;
   TOST FAIL có hướng)". CẤM viết "FL không bao giờ kém centralized"; ĐƯỢC
   viết "trên split primary (group, không leakage), tương đương; cost FL nhỏ
   chỉ xuất hiện trên split yếu về suy luận tổng quát".
3. **Rút 2 claim cũ**: (i) "central thắng FL trên tfidf (p=3.8e-06)" — artifact
   của undertrain + degenerate + pooled-vocab (đã chứng minh: p mới .312/.404
   với baseline sạch); (ii) cell collapse .375/.326 của centralized cũ —
   undertrain artifact (same convex problem, same split, chỉ đổi solver/scaler
   → min F1 .7692). Bài học multi-seed giữ nguyên: 1 seed có thể sai cả 2 hướng.
4. Không phát hiện bất kỳ đường leak test nào trong recipe mới; các giả định
   (shared scaler/C, FedAvg=local-fit-then-average fixed point, μ-sweep
   descriptive) đều đăng ký trước trong AMENDMENT-5 và ghi trong output rows.

## AI SAI / AI BẮT ĐƯỢC (tóm tắt)
- W1 sai (minor): count suite 616/617 (thực ~662 lúc đó, 675 bây giờ); giờ
  chạy grid 16:46:30Z (thực 16:56:59Z); diễn giải fail round7 thành "thiếu
  file" (file có, lỗi fixture-gap từ make_figures 26-09).
- W1 đúng: toàn bộ 25+ số liệu chính (TOST/CI, Wilcoxon/Holm, cell means,
  min F1, C-dist, fixed-point 80/80, converge 120/120, |Δp|=.0022, mọi con số
  bảng cũ→mới) tái lập independent chính xác đến chữ số thập phân cuối.
- W2 đúng về bit-identity 160/160 hiện tượng (tôi xác nhận 80/80 cell × F1 +
  history) nhưng W1 mới chẩn đoán ĐÚNG bản chất (routing, không phải prox term)
  — chính bởi chẩn đoán này mà regression fedprox(μ=.01)==old-row bit-exact
  mới pass được; đó là bằng chứng quyết định chẩn đoán đúng.
- Auditor bắt được bằng công cụ độc lập: mini-implementation FedProx riêng
  (/tmp/v1_indep_fedprox.py — FD 6.1e-10; solver-agnostic đối chiếu 3.9e-8),
  stats recompute riêng (/tmp/v1_audit_stats.py), determinism re-run bit-exact
  (diff 0.00e+00), git archaeology cho regression round7.

## CÁCH TÁI LẬP (lệnh)
```
cd /Users/macbook/.zcode/workspace/default/refuseguard
.venv/bin/python /tmp/v1_audit_stats.py          # recompute mọi số P0 + old grid
.venv/bin/python /tmp/v1_indep_fedprox.py        # FedProx độc lập + torch prox check
.venv/bin/python -m pytest tests/test_packguard_p0.py -v   # 12 passed
.venv/bin/python -m pytest tests/ -q             # 674 passed, 1 failed (pre-existing)
```
(Kèm 2 script chạy inline: determinism seed 20260933 → 6/6 method diff 0.00e+00;
real-cell 20260922 group/graph fedavg-vs-fedprox max|Δp|=.00220, cả hai F1
.9230769230769231 == old row.)
