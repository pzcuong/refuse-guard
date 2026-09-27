# V1 AUDIT REPORT — Round 13, W1 (adversarial audit: MinHash LCO + expansion)

Ngày: 2026-09-28. Auditor: V1 (vòng 13). Đối tượng: `reports/round13/W1_report.md`,
`packguard/{clusters,lco}.py`, `outputs/packguard/lco/*`, AMENDMENT-7,
`data/packguard/manifests/benign_expansion_v1.json`. Phương pháp: MỌI số
được kiểm lại độc lập bằng script /tmp (tự viết MinHash khác hàm hash,
tự đếm unit/leakage, tự enumerate 2^20 sign-vector cho Wilcoxon exact,
tự chạy lại runner, tự verify sha256 + re-extract). Toàn bộ script audit
nằm ở `/tmp/v1audit/audit{1,2,3,5,6}_*.py`, `repro2seeds.py`.

## VERDICT W1: **PASS** (2 ISSUE mức MINOR, không phải FALSE CLAIM)

Claim trung tâm "under family shift, graph và text degradation KHÔNG
khác nhau (dd = −.0095±.0803, Wilcoxon p=.368)" — **đứng được**: mọi
thành phần đã được tái lập độc lập, null có power thật (mức ≥.05 F1),
không có leakage, không có bằng chứng threshold được chọn thuận lợi.

### Bằng chứng chính (số tự kiểm, không trích lại của W1)

1. **MinHash đúng** — implement độc lập của auditor (blake2b-8B base hash
   + họ affine mod 2^61−1, 256 perm, RNG khác) trên 5 sample: khớp
   estimate của W1 và khớp EXACT Jaccard (10/10 pair trong dung sai; đa
   số exact = 0). Trên 29 pair ngẫu nhiên toàn corpus: mean|est−exact|
   = 0.0023, max 0.045 (nhỏ hơn ngưỡng elbow 0.30 hai bậc độ lớn).
   Signature tái tính từ đầu = byte-identical với `signatures.npz`
   (max diff 0 trên 3 rows kiểm). Không thư viện minhash ngoài
   (grep sạch); labels chỉ được đọc ở dòng 318 (composition, SAU khi
   clustering xong) — unsupervised xác nhận bằng đọc code.
2. **Family gate đúng** — tự đếm: @antoncallahan 31 archives → đúng 1
   unit (c0150 @0.3 / c0160 @0.5); similarity THẬT giữa 2 archive của
   nó: exact Jaccard 0.228 (v1.0.0 vs 69.420.0) và 0.536 (pair khác) —
   cluster không phải artifact tên thuần. **0/67** multi-version package
   bị xẻ sau closure (tự đếm, cả 2 ngưỡng); **0 mixed-label unit** cả 2
   ngưỡng; 326/342 unit, 356/400 pre-closure, merge 30/58 — khớp meta.
3. **Elbow 0.30 không phải tune thuận lợi** — histogram tự tính lại từ
   signatures: 179,254 cặp <0.05; thung lũng [0.05,0.30) = 840; ≥0.30 =
   1,409; ≥0.90 = 356 — KHỚP ĐÚNG từng con số claim. Lưu ý trung thực:
   **đáy thung lũng thật nằm ở bin [0.20,0.25) (94 cặp), không phải 0.30**
   (bins: .20–.25=94, .25–.30=120, .30–.35=171, .35–.40=218) — 0.30 là
   "cuối thung lũng / điểm takeoff của khối family", đọc kiểu "elbow"
   là diễn giải hợp lý nhưng nên viết chính xác hơn (xem ISSUE-2).
   Quyết định không bịa lợi thế: cả 2 ngưỡng 0.3 và 0.5 cho CÙNG kết
   luận null → không có "kết luận thuận lợi" để tune tới.
4. **Multi-package unit là near-duplicate thật** — spot 4/20 unit @0.3:
   exact cross-package Jaccard 1.000 (`@types` vs `types` — shingle set
   giống hệt), 0.871, 0.848, 0.677. Không phải merge nhầm.
5. **LCO NO-LEAKAGE (toàn bộ 40 split, không chỉ 3 seed)** — tái
   implement độc lập protocol trong A7.2 (shuffle `random.Random(seed)`
   trên pool sorted theo stratum majority-label, round(20%)): held
   clusters TRÙNG HỆT 40/40 với `draw_lco_split`; 0 overlap
   cluster/package/sample; 0 package straddle; **20/20 seed valid ở cả
   2 ngưỡng** (test đủ 2 label, tự đếm); test share thực 14.3–27.2%
   (khớp disclosed). `split_info` lưu trong rows khớp tái tính.
6. **Tái lập 2 seed bằng primitive của W1** — `run_lco` với seeds
   {20260922, 20260941} × 2 ngưỡng: **48/48 rows bit-identical**
   (max|ΔF1|,|ΔAUC|,|ΔC| = 0.00e+00 so với lco_results.json).
7. **dd + Wilcoxon exact đúng** — tự enumerate đủ 2^20 sign-vector
   (averaged ranks, không zero-diff, không tie): p = 0.368277 /
   0.674223 / 0.985435 / 0.430433 — **khớp EXACT** scipy và số lưu trữ;
   dấu +8/−12, +10/−10, +11/−9, +10/−10 khớp. dd mean±std khớp hết.
8. **Cross-check p0 = 0.000000 xác nhận** — group-in-runner vs
   `p0_results.json` round-11: max|diff| = **0.000000000** trên 160
   phép so (20 seed × 2 block × 2 method × 2 ngưỡng, mạnh hơn claim
   20×4). Nhóm group-in-runner còn lặp lại giống hệt nhau giữa 2 ngưỡng
   (0.00e+00) → pipeline deterministic thật, không đổi giữa các vòng.
9. **Expansion +200** — manifest 200 sample, 200/200 có source_url +
   sha256 và **200/200 sha256 verify khớp file tarball trên đĩa**;
   200 package distinct; recount profile: hook 2 / network 16 /
   hợp 17 (khớp claim); 47/200 graph rỗng (khớp); **0 sample nào nằm
   trong corpus 603/grid đã đăng ký**. Re-extract 7 sample độc lập
   (gồm cả 2 hook package + 3 network package) qua pipeline v2
   KHÔNG ĐỔI: 0 feature diff, text cache khớp.
10. **Tests** — `tests/test_packguard_lco.py`: **24/24 passed** (1.75s);
    full suite: **732 passed / 0 failed** (80.5s) — khớp claim.

## CONFIRMED BUGS

1. **BUG [COSMETIC] `packguard/lco.py::render_summary` (code hiện tại)
   sinh markdown lỗi nếu chạy lại**: khối `lines += ["", "## PRIMARY
   paired test..."]` nằm BÊN TRONG vòng lặp degradation rows → header
   "## PRIMARY" bị lặp 12 lần xen kẽ bảng. `summary.md` trên đĩa sạch
   (1 header) → artifact được tạo bởi bản code TRƯỚC khi sửa/hay được
   sửa tay sau render; re-render từ stored rows KHÔNG byte-reproducible
   (diff 79 dòng, chỉ formatting — `aggregate()` tính lại ra SỐ identical
   từng cell). Không ảnh hưởng bất kỳ số nào; cần fix trước khi ai đó
   re-render summary (diff tại `packguard/lco.py` ~dòng 563–568).

## FALSE CLAIMS (số bịa/sai trong W1_report.md)

- **Không có FALSE CLAIM cấp cấu trúc.** Một số liệu chép sai duy nhất:
  W1 report §C1 viết "histogram 181,489 cặp" — số cặp off-diagonal thật
  của 603 sample là **181,503** (= 603·602/2; các thành phần 179,254 +
  840 + 1,409 tự cộng ra 181,503; meta trong JSON cũng đúng 181,503).
  Lỗi gõ trong report text, các số thành phần đều đúng. [MINOR]

## ISSUE (không phải false claim, nên xử lý trước khi vào paper2)

1. **[MINOR] Tổng cặp 181,489 → 181,503** (như trên). Sửa 1 chữ trong
   report/summary khi bring-forward.
2. **[MINOR-WORDING] "Elbow 0.30"**: đáy phân phối thật ở bin
   [0.20,0.25); 0.30 là điểm cuối thung lũng/khởi đầu khối family mass.
   Kết luận KHÔNG phụ thuộc cách đọc này (0.5 cùng kết luận null, và
   cluster-count curve 346→348→356→363→385→400 tại .20/.25/.30/.35/.40/.50
   không có gãy giả tạo). Paper nên viết "the end of the low-similarity
   valley (first bin where family mass takes off)", không viết "the
   histogram minimum".
3. **[MINOR-WORDING] A7.4 "preferring packages with install scripts /
   network calls" KHÔNG được implement như cơ chế ưu tiên** — selection
   là RANDOM (seeded shuffle dependency-names), profile hard-negative
   (hook OR network) được ĐẾM SAU (17/200). W1 disclose trung thực điều
   này (report + manifest đều ghi RANDOM), nhưng paper2 KHÔNG được viết
   expansion là "selected for hard negatives" — chỉ được viết "random
   draw, of which 17/200 carry the hard-negative profile".
4. **[MINOR] render_summary bug** — xem CONFIRMED BUGS #1.

## AI SAI / AI BẮT ĐƯỢC

- AI (W1) bị bắt: chép sai tổng cặp similarity (181,489 thay vì 181,503)
  — lỗi copy, các số thành phần đều đúng.
- AI (W1) để lại: code `render_summary` hiện tại render lỗi (header lặp
  12 lần) trong khi artifact trên đĩa sạch → summary.md không tái tạo
  được từ code hiện hành; dấu hiệu sửa code sau khi ghi artifact.
- AI (W1) nghi ngờ rồi được minh oan: chọn "elbow" 0.30 khi đáy thật ở
  0.20–0.25 — kiểm độc lập cho thấy cả 0.3/0.5 cùng kết luận null và
  dd gần như bằng 0 ở cả hai → không có kết luận thuận lợi để tune.
- AI (auditor V1) tự sai và tự sửa: lần tính Wilcoxon perm đầu tiên bị
  sai công thức căn giữa (p=0.94 thay vì 0.368) — phát hiện vì lệch với
  scipy, sửa xong khớp exact 4/4. Bài học: checker cũng phải cross-check.

## NULL POWER — dd finding đứng được ở mức nào (F điền mục này)

Đo độc lập (dd_i ~ N(δ, σ=.0803), n=20, Wilcoxon exact 2 phía, α=.05,
2000 rep; kèm paired-t):

| δ (dd thật) | 0.02 | 0.03 | 0.05 | 0.08 | 0.10 |
|---|---|---|---|---|---|
| power Wilcoxon | .17 | .34 | **.75** | **.98** | 1.00 |
| power paired-t | .18 | .36 | .77 | .99 | 1.00 |

- MDE @ 80% power ≈ **0.05** F1 (≈ 0.63 σ). Claim của W1 "đủ power phát
  hiện dd ≥ ~0.08" là **bảo thủ nhưng thiếu chính xác**: 0.08 là mức
  power ~98%, còn 0.05 đã đạt ~75%. Với dd thực |0.01–0.014|, nghiên cứu
  này LOẠI BỎ được mọi khác biệt degradation ≥ 0.05 F1 giữa graph và
  text, nhưng KHÔNG loại được khác biệt ≤ 0.03.
- 95% CI của dd (thr 0.3, centralized): **[−0.047, +0.028]**; fedavg
  [−0.051, +0.023]; hai ngưỡng tương tự. Đối chiếu với chính framework
  của bài: round-11 dùng TOST margin **0.02** — ở margin 0.02 kết luận
  equivalence KHÔNG pass (CI vượt −0.02); ở margin **0.05** thì pass.
- **Kết luận đứng được**: "no detectable difference in degradation
  between graph and hashed text under family shift, with degradation
  differences bounded at |dd| ≲ 0.05 F1" — đây là phát hiện practical
  equivalence Ở MỨC 0.05, không phải equivalence tuyệt đối và không
  phải equivalence ở margin 0.02 mà round-11 từng dùng cho so sánh khác.

**Wording khuyến nghị cho paper2 (F điền, thay {{R13:LCO_CONCLUSION_SENTENCE}})**:
"Under leave-cluster-out family shift, both representations degrade by a
small paired amount (ΔF1 = −0.01…−0.04). The graph-vs-text degradation
difference is statistically indistinguishable from zero (dd = −0.010±
0.080, exact Wilcoxon p = .37; 95% CI [−0.047, +0.028]; the same holds at
the 0.50 threshold sensitivity), and the design has ≈75% power to detect
a difference of 0.05 F1. We therefore find no evidence that either
representation is more robust to family shift at practical effect sizes
(|dd| ≳ 0.05 F1); smaller differences cannot be resolved at n = 20 seeds,
and the robustness claim is written as joint across representations."

Không được viết: "graph và text tương đương đã được chứng minh
(equivalence)" hay "graph bền hơn/kém bền hơn" — cả hai hướng đều không
được dữ liệu này nâng đỡ ở mức < 0.05.

## HẠN CHẾ CỦA AUDIT

- Auditor tái lập 2/20 seed qua runner thật (48/48 rows); 18 seed còn
  lại được bảo chứng gián tiếp bởi cross-check p0 = 0.000000000 (cùng
  plumbing) và bởi việc dd/Wilcoxon tính lại từ rows khớp exact.
- Re-extract expansion: 7/200 sample (gồm cả 2 hook + 3 network) — mẫu
  nhỏ, nhưng 200/200 sha256 đã verify nên phần download là toàn vẹn;
  phần extract chỉ spot-check.
- Không audit các vòng trước (p0 chỉ dùng làm mốc đối chiếu).
