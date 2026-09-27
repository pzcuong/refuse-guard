# F Report — Round 11 (FINAL INTEGRATION: P0 vào paper2 + gate + đóng P0-1..6)

Ngày: 2026-09-27. Owner: F (tác nhân cuối, vòng 11). Input: W1 (P0
baseline/TOST 20 seeds), W2 (gen-numbers + trivial + refs/de-anon), V1/V2
(PASS cả hai, 0 mismatch trên 124 giá trị recompute). Ràng buộc giữ nguyên:
CPU only, không git commit, KHÔNG bịa số — mọi số in bài sinh tự động từ
`outputs/packguard/p0/p0_results.json` (360 rows, mock=false, AMENDMENT-5),
`outputs/packguard/trivial/trivial_results.json`,
`outputs/packguard/fl_multiseed/grid_results.json` (grid cũ, GIỮ NGUYÊN) và
các artifact an toàn — qua `scripts/gen_paper_numbers.py` (336 macro).

**GATE CUỐI: tectonic paper2 EXIT 0 (PDF 9 trang); pytest 675 passed / 0
failed; `gen_paper_numbers.py --check` OK (336 macros); verify_repro.sh
30/30 EXIT 0 (manifest 37 files, 0 mismatch).**

## 1. LÀM GÌ (theo tasking T1–T6)

### [T1] Trung tính hóa nhãn vòng — DONE, 0 hit
18 chỗ "Round-8/9/round-1/2/3/4/7" trong TEXT đã thay trung tính: "an
initial batch classified the top 60", "a follow-up batch completed the
universe", "(independent refresh audit)", "(independent calibration
audit)", "the original registered configuration", "Single-seed
comparisons additionally report McNemar", "Sensitivity arms (single seed
20260922)", "(independently audited; single seed …)", "vulnerability-domain
batches", "(independent audit; null with low power)", "the pooled-test
sweep", v.v. Kiểm bằng script strip-comment + regex `round[ -]?[0-9]` trên
main.tex VÀ trên text render từ PDF (`pdftotext`): **0 match**. 3 hit còn
lại trong source là "fixed point from round 2" (thuật ngữ FL training
round, không phải nhãn vòng nội bộ); "PackGuard/RefuseGuard" chỉ còn ở
cite keys (vô hình).

### [T2] Trivial range + nhập kết quả vào paper2 — DONE
- Sửa range: mọi chỗ in bài dùng **"$\pm.82$--$.86$"** (2 chữ số, đúng
  hướng V2 đề xuất trong paper-ready wording) kèm **cell means chính xác
  `.823–.855`** bằng macro (`\pmTrivFoneMin/Max` tính từ artifact:
  min 0.8233 = subset/group, max 0.85546 = full/group). **LƯU Ý lệch 1 bit
  cuối với tasking**: tasking viết ".823–.856" — số .856 là làm tròn giá trị
  4-chữ-số .8555; giá trị artifact thật 0.855458… làm tròn 3 chữ số là
  .855. Tôi chọn số bám artifact (nguyên tắc không bẻ số) — nếu orchestrator
  muốn buộc chữ ".856" thì phải sửa macro generator, không phải sửa tay.
- Nhập paper2: 1 đoạn §results "Trivial-structure baseline: the marginal
  value of behavior graphs is real but bounded" (đủ: 5 features, F1
  .82–.86, ΔF1 +.0227 group / +.0487 random, exact Wilcoxon p=1.9e-5 /
  1.9e-6, McNemar pooled 171/83 và 236/68, subset-500 vẫn thắng p=.0012 →
  không phải empty-graph artifact, disclosure n_bytes không có trong
  schema) + 1 câu Discussion ("a refinement, not a replacement") + stale
  pattern `.834--.856` thêm vào STALE_PATTERNS.

### [T3] Rewrite phần FL — DONE (đầy đủ a–f)
- **(a) PRIMARY nâng cấp TOST equivalence**: đoạn mở §results mới
  "Federation is equivalent to a strong centralized baseline on the primary
  split (pre-registered TOST)": group/graph ΔF1 −.0065±.0171, 90% CI
  [−.0133,+.0003]; group/hashing −.0024±.0117, [−.0070,+.0022] — cả hai
  PASS; framing cũ "p=.312 descriptive" đã xoá ở abstract/intro/results/
  conclusion. Table mới `tab:stats` = bảng TOST 4 hàng (Δ, CI, TOST PASS/
  FAIL, exact Wilcoxon, Holm).
- **(b) RETRACTION có kiểm soát**: đoạn "Retracted claim: 'text degrades
  under federation' was a baseline artifact" — trích claim cũ bằng macro từ
  grid cũ (Δ −.0521, p=3.8e-6, Holm 1.1e-5; pypi .671±.059 vs .790±.076),
  2 nguyên nhân (pooled-vocab fit + undertrain), số mới: group −.0024
  (p=.312) / random −.0037 (p=.404) ns, 0/360 row recall≥.999, hashing
  FedAvg random .906±.020 có variance thật; kết câu đúng chữ đề xuất:
  "text and graph features are both federation-robust under the corrected
  protocol". Abstract cũng sửa; Discussion "A retracted finding" →
  "Retracted findings" (nối 3 retraction: feature bug, text-degradation,
  central-collapse).
- **(c) CENTRAL-WIN disclosure**: đoạn "Centralized wins only on the
  leakage-prone secondary split (disclosed)": random/graph −.0160
  (4+/15−/1, exact p=.0062, Holm .0247 in ".025" 3 chữ số; TOST CI hoàn
  toàn dưới 0 = có hướng), kèm câu chốt đúng đề xuất: "with a properly
  converged centralized baseline, federation carries no measurable cost on
  the primary leakage-resistant split, and a small cost only under the
  leakage-prone random split"; nói rõ "FL is never worse than centralized"
  is NOT claimed.
- **(d) FedProx routing bug + collapse**: Method có đoạn "Corrected baseline
  (AMENDMENT-5…)" (bug fix + legacy flag); Discussion có paragraph riêng
  "Threats to validity of the corrected-baseline layer" — (i) routing bug
  (cả 2 arm cũ chạy FedProx(.01); rows cũ re-label; unit test μ=1 khác /
  μ→0 trùng; cell thật reproduce bit-exact; flag `legacy_mu_routing`), (ii)
  FedAvg-strong = converged local-fit + average, fixed point 80/80 từ round
  2 (đăng ký), (iii) shared scaler/C = central coordination (train-only).
  Collapse .375/.326 re-attributed: "The earlier centralized collapse was
  undertraining, not data structure" — 0/80 converged (max n_iter 69, min
  F1 .769), random/graph central .835±.113 → .887±.020 (macro
  `\pmGridRandomGraphCentralFone` từ grid cũ).
- **(e) tab:main/tab:stats số mới**: `tab:main` giờ là bảng AMENDMENT-5 (6
  hàng block×method × cột group/random F1+AUC; FedProx ghi trong caption:
  lệch ≤ +.005 F1 mọi μ, n.s.; 360 runs, config 5ee3764c59a8e4b3);
  `tab:stats` = bảng TOST. Bảng grid cũ (npm/pypi F1) THÁO — số pypi/npm
  vẫn sống trong text retraction bằng macro; hàng FedProx μ sweep có đoạn
  riêng "separates in probabilities, not in F1" (graph +.0044/+.0048/
  +.0043, p=.084/.452/.475; hashing trong ±.004, p>.21 — descriptive).
- **(f) Pre-reg**: Method + Setup thống kê ghi AMENDMENT-5 đăng ký TRƯỚC run
  (prereg 16:39:29Z < run 16:56:59Z), margin ±.02 khóa trước, 5-seed known
  disclosed; "Data and provenance" cập nhật AMENDMENT-1/-3/-4/-5 +
  p0_results.json + trivial_results.json + numbers.tex.

### [T4] FIX test_exists_branch — DONE, đúng gốc
`paper/make_figures.py::fig_round7`: load `round7_token_map.json` giờ có
GUARD (chỉ load khi tồn tại; khi vắng — sandbox test — display token được
sinh từ `round7_master.json` bằng ĐÚNG format mà cross-check pin, family
loop bỏ qua family thiếu trong fixture). Hình vẽ ở đường dữ liệu thật
(token_map có mặt) KHÔNG đổi: `make_figures.py` chạy end-to-end exit 0,
`fig_round7.pdf` regenerate 26,380 bytes; `tests/test_round7_master.py`
26/26 pass (gồm test_exists_branch + test_exists_branch_missing_key_fails_
loudly vẫn fail-loud đúng thiết kế).

### [T5] Macro hóa + --check 0 stale — DONE
- `scripts/gen_paper_numbers.py` mở rộng: +158 macro (178 → 336) gồm toàn
  bộ P0 cells/comparisons/CI/TOST/μ-sweep, trivial 4 scope, grid-cũ
  random/graph central (đối chiếu undertrain), coverage numerators
  (105/252/63/80 — trước đây thiếu, macro cũ sai nghĩa là denominator),
  granite-FP n100. Macro mới đã thay literal ở abstract, setup, tab:main,
  tab:stats, tab:coverage, KB, safety n100, npm_hook, stabilized arm.
- Đã chứng minh --check bắt stale THẬT trên bảng MỚI: inject `.850±.051`
  vào hàng graph FedAvg → "STALE table row 'graph FedAvg': renders [.850 …]
  artifacts say [.871 …]" → restore, CHECK OK. Trạng thái cuối: **GEN-NUMBERS
  CHECK: OK — 336 macros verified**.
- Số macro còn UNUSED: ~115 (phần lớn là cell ecosystem npm/pypi của bảng cũ
  đã tháo + biến thể safety/trivial không dùng; vô hại, vẫn được --check
  drift-protect). Không còn literal nào tương ứng với chúng trong text.

### [T6] GATE — tất cả xanh
| Gate | Kết quả |
|---|---|
| `tectonic main.tex` (paper2) | EXIT 0, 0 undefined citation/reference, main.pdf sinh lại |
| `pytest tests/ -q` | **675 passed / 0 failed** (80.5s; test_exists_branch đã fix) |
| `gen_paper_numbers.py --check` | OK — 336 macros verified |
| `bash scripts/verify_repro.sh` | **30/30 PASS, EXIT 0** (manifest check gồm 3 file mới) |
| Manifest | +`outputs/packguard/p0/p0_results.json`, +`outputs/packguard/trivial/trivial_results.json`, +`paper2/p0_macros/numbers.tex` (37 files, 0 mismatch; sửa `scripts/make_manifest.py` FILES rồi regen) |

## 2. FILES (absolute)
Sửa:
- /Users/macbook/.zcode/workspace/default/refuseguard/paper2/main.tex (T1–T3,
  T5: abstract/intro/method/setup/results/discussion/conclusion/provenance;
  tab:main + tab:stats thay bảng; +đoạn trivial; +threats paragraph)
- /Users/macbook/.zcode/workspace/default/refuseguard/scripts/gen_paper_numbers.py
  (loader p0/trivial, 336 macro, _p_fmt, check_main cho bảng mới,
  STALE_PATTERNS + trivial-range)
- /Users/macbook/.zcode/workspace/default/refuseguard/paper2/p0_macros/numbers.tex
  (GENERATED lại, 336 macro)
- /Users/macbook/.zcode/workspace/default/refuseguard/paper/make_figures.py
  (T4: guard token_map, subset-tolerant family loop — chỉ nhánh sandbox)
- /Users/macbook/.zcode/workspace/default/refuseguard/scripts/make_manifest.py
  (+3 artifact)
- /Users/macbook/.zcode/workspace/default/refuseguard/outputs/master/ARTIFACT_MANIFEST.sha256
  (regen)
- /Users/macbook/.zcode/workspace/default/refuseguard/docs/improvement_roadmap_v2.md
  (khối cập nhật vòng 11: P0-1..6 Done kèm số)
- reports/round11/F_report.md (file này)

KHÔNG đụng: packguard/*.py (code W1/W2 giữ nguyên), outputs/packguard/p0/
và fl_multiseed/ (artifact đọc-only), refs.bib (đã W2 + V2 verify), docs/
packguard_prereg.md (AMENDMENT-5 của W1 giữ nguyên). Không git commit.

## 3. TRẠNG THÁI P0 — 6 mục của reviewer Q1
| # | Vấn đề reviewer | Trạng thái | Bằng chứng |
|---|---|---|---|
| 1 | "FedAvg ≈ centralized" chỉ là p=.312 descriptive, không phải claim | **DONE** | TOST PASS primary (Δ −.0065, CI [−.0133,+.0003] ⊂ ±.02, AMENDMENT-5 prereg-before-run); abstract/intro/results/conclusion viết theo equivalence |
| 2 | Claim tfidf-degradation (p=3.8e-6) nghi baseline artifact | **DONE — RETRACTED** | HashingVectorizer stateless + strong baseline: p=.312/.404 ns; đoạn retraction + STALE pattern; grid cũ GIỮ nguyên làm audit substrate |
| 3 | Central-win trên random split phải disclose | **DONE** | tab:stats random/graph FAIL TOST có hướng (Holm .0247, in ".025"); đoạn central-win + câu "FL is never worse" NOT claimed |
| 4 | FedProx bit-identity 160/160 chưa audit | **DONE — BUG TÌM THẤY + FIX** | Routing bug (mu không truyền per-algo); fix + 12 unit tests + legacy flag; bit-identity giải thích, μ-sweep descriptive |
| 5 | Shortcut-learning: graph có thắng trivial metadata? | **DONE + NHẬP PAPER** | Trivial F1 .82–.86; graph vẫn thắng Δ +.0227/+.0487 (p ≤1.9e-5), subset-500 vẫn thắng → refinement not replacement |
| 6 | Hygiene: de-anon sót, macro literal, refs | **DONE** | 18 round-N → 0 hit (PDF-checked); 336 macro + --check (đã chứng minh bắt stale thật, kèm 2 stale pattern W3 giữ nguyên); refs 9/9 (V2 verify); test_exists_branch fix → 675/0 |

**Không mục P0 nào Deferred.** (P1/P2 còn lại: R9 leave-families-out,
R3b validation-locked thresholds, KB-entry ablation 20-seed, effect sizes
+ CI stabilized arm, GNN, A5 provenance closure — xem roadmap.)

## 4. FRAMING DECISION (đề xuất cho user)
1. **Primary claim (positive, dùng được cho title/abstract/intro)**:
   "FedAvg is statistically equivalent to a strong, properly converged
   centralized baseline at a pre-registered ±.02 F1 margin on the primary
   leakage-resistant split (TOST PASS: ΔF1 −.0065, 90% CI
   [−.0133,+.0003]; text features PASS as well) — with any undetected cost
   bounded by the registered margin." Đây là negative/equivalence claim có
   prereg + 20 seeds + paired — mức chứng cứ đúng chuẩn reviewer đòi.
2. **Secondary disclosure (BẮT BUỘC giữ, không được soft-wash)**: "on the
   leakage-prone random split only, the strong baseline wins by .016 F1
   (exact p=.0062, Holm .0247; TOST CI entirely below 0)". Wording đã vào
   paper nguyên dạng đề xuất: "federation carries no measurable cost on
   the primary leakage-resistant split, and a small cost only under the
   leakage-prone random split".
3. **Retraction (giữ nguyên văn, đã vào paper)**: "our earlier
   text-degradation claim does not survive a corrected baseline; text and
   graph features are both federation-robust under the corrected protocol".
   Kèm bảng old-vs-new trong text (macro từ artifact cũ + mới) — không xóa
   lịch sử, re-attribut.
4. **Trivial baseline (mới, nên nói ở rebuttal)**: "graph features beat a
   trivial structural baseline significantly (ΔF1 +.023 group / +.049
   random, exact p ≤ 1.9e-5) — not shortcut learning; the trivial baseline
   alone reaches F1 .82–.86, so the marginal value of behavior graphs is
   real but bounded (refinement, not replacement)."
5. **Trình bày**: abstract giờ dẫn equivalence + central-win + retraction;
   KHÔNG còn chỗ nào viết "text not federation-robust" hay "p=.312" như
   claim chính.

## 5. LỆCH CHUẨN / DISCLOSE (honest)
1. **Page 8 → 9**: nội dung mới (trivial + threats + corrected-baseline
   method + TOST caption) đẩy refs sang trang 9. Chấp nhận có chủ đích
   (content-first; cắt bớt để giữ 8 trang = cắt chất liệu audit đã disclose).
2. **Trivial range in ".82–.86" + cell means ".823–.855"** (artifact-exact),
   KHÔNG dùng ".856" của tasking — .856 là round 4-chữ-số của .8555;
   artifact thật 0.855458 → .855. Đã thêm stale pattern `.834--.856`.
3. **Holm random/graph in ".025"** (3 chữ số, quy ước p≥.01 của paper) thay
   vì ".0247" (4 chữ số của W1) — cùng một số (0.024719).
4. Bảng grid cũ (npm/pypi F1 per cell) đã tháo khỏi paper để nhường bảng
   AMENDMENT-5; các số đó vẫn truy vết (macro + artifact + % SRC), phần
   lớn macro cũ giữ định nghĩa (unused, drift-protected).
5. ~115 macro chưa được tham chiếu trong text (cell ecosystem bảng cũ +
   biến thể) — vô hại.
6. make_figures: nhánh sandbox của fig_round7 vẽ subset family khi fixture
   thiếu — đường dữ liệu thật không đổi (đã regenerate toàn bộ figure, exit 0).
7. Không GPU/LLM; không git commit; mọi số mới truy vết p0_results.json /
   trivial_results.json / numbers.tex (--check exit 0).

## 6. ĐÁNH GIÁ "COMPETITIVE-PLUS" + P1 TIẾP THEO
- **Đã đạt "competitive-plus" ở khía cạnh RIGOR/độ tin cậy**: mọi federation
  claim giờ có prereg + 20 seeds + TOST chính thức; 3 retraction có kiểm
  soát + re-attribution (hiếm paper pilot làm); số 100% macro-generated từ
  artifact có gate --check chứng minh được hành vi bắt stale; safety line
  có điểm khác biệt domain (recall-perturbing vs FP-channel) + ladder
  granite; 675/0 tests + verify_repro 30/30. Đây là gói defensive mạnh hơn
  phần lớn bài cùng loại ở tầng auditability.
- **Chưa "competitive-plus" ở khía cạnh ROBUSTNESS/Nnovelty thực nghiệm**:
  claim graph-robustness vẫn thiếu leave-families-out; threshold layer còn
  oracle; KB entry-ablation còn 1 seed; GNN chưa có. Nếu chỉ chạy THÊM MỘT
  P1, chọn **R9 leave-families-out + attack/defense AST-strip robustness
  (con hàng lớn nhất theo reviewer)**: nó trực tiếp quyết định claim sống
  còn nhất của paper (graph degrades less under shift) và là câu hỏi chắc
  chắn của reviewer Q1 tiếp theo. Sau đó: R3b validation-locked thresholds
  (bỏ nhãn "oracle"), rồi KB-entry ablation 20-seed, rồi effect sizes/CI
  cho stabilized arm.

## 7. TODO
1. (User/orchestrator) Quyết định chấp nhận 9 trang hoặc cấp ngân sách cắt
   nội dung để về 8 (đề xuất: giữ 9, disclosed).
2. (P1) R9 leave-families-out + AST-strip robustness — ưu tiên tuyệt đối.
3. (P1) R3b validation-locked threshold re-evaluation.
4. (P2) Mở rộng --check needle sang các con số P0 còn lại trong text
   (hiện đã pin: bảng + Δ/CI/Holm primary + trivial deltas).
5. (P2) Cân nhắc thêm bảng FedProx μ-sweep nếu reviewer đòi số cell đầy đủ
   (macro đã có sẵn: `\pmPzGroup{Block}FedProx{Mu*}Fone`).

## 8. SELF-TEST THẬT (đã chạy trong phiên)
- `tectonic main.tex` (paper2, 3 lần sau các sửa) → EXIT 0;
  `pdfinfo` → 9 pages; `pdftotext` spot-check: ".0065/.0133/+.0003/PASS/
  FAIL/.0160/1.9×10/.823/.855/.0227/.0487/equivalen/retract/HashingVector
  izer/AMENDMENT-5/5ee3764c59a8e4b3/legacy_mu_routing/.82–.86/.823–.855"
  đều OK; 0 match round-N label; 0 stray `\pm*` macro chưa expand.
- `.venv/bin/python -m pytest tests/ -q` → **675 passed / 0 failed** (80.5s).
- `.venv/bin/python scripts/gen_paper_numbers.py --check` → OK (336 macros);
  inject-literal test → FAIL đúng hàng "graph FedAvg" → restore → OK.
- `bash scripts/verify_repro.sh` → 30/30 PASS, EXIT 0 (manifest 37/37).
- `.venv/bin/python paper/make_figures.py` → exit 0, fig_round7.pdf regen
  (26,380 bytes); `pytest tests/test_round7_master.py -q` → 26 passed.
- `pytest tests/test_packguard_trivial.py -q` (sau edit cuối) → 13 passed.

---
*F round 11 không git commit. Mọi số in bài sinh từ outputs qua
scripts/gen_paper_numbers.py (--check exit 0 tại thời điểm đóng).*
