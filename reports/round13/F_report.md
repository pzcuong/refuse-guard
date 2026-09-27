# F REPORT — Round 13, FINAL (điền 8 token {{R13:*}} §5.4 + fix minor + gates + chốt)

Ngày: 2026-09-28. Agent: F (tác nhân final, vòng 13). Đầu vào:
`reports/round13/{W1,W2,V1,V2}_report.md`, `outputs/packguard/lco/
lco_results.json` (480 rows, mock=false, config_sha16 `9bea57439fa0c473`),
`outputs/packguard/lco/{summary.md,clusters_t030.json,clusters_t050.json}`.
Không bịa số: MỌI số mới trong paper §5.4 được tôi **tính lại độc lập từ
per-seed rows của lco_results.json** trước khi viết (script /tmp, scipy
`t`-CI + `wilcoxon(method='exact')`), sau đó đối chiếu với W1/V1 — khớp
hết (chi tiết §1.2). Ownership: `paper2/main.tex`, `paper2/refs.bib`,
`paper2/PackGuard_final.pdf`, `packguard/lco.py` (1 fix được tasking cấp
"vòng ngoài"), `scripts/make_manifest.py`, manifest, roadmap, report này.
KHÔNG git commit, KHÔNG GPU/LLM.

## 1. LÀM GÌ

### [X1] ĐIỀN 8 TOKEN + VIẾT LẠI §5.4 (`\label{sec:lco}`) — DONE

8/8 token `\detokenize{{{R13:*}}}` đã bị xóa, thay bằng literal có
`% SRC:` trỏ lco_results.json + AMENDMENT-7 (trong comment — hygiene
cấm "AMENDMENT" visible). Vì V2 cảnh báo protocol lệch artifact, cả câu
chuyển đã được viết lại theo đúng thiết kế đã chạy; từng token điền như
sau (kèm xác minh số):

| Token | Điền vào paper | Nguồn + xác minh độc lập của F |
|---|---|---|
| `LFO_GRAPH_DF` | ΔF1 graph block: **−.0383 ± .0675** | per-seed rows (thr 0.30, strong_centralized, n=20); khớp W1 §3.2 |
| `LFO_GRAPH_CI` | 95% CI: **[−.070, −.007]** | t-CI tự tính: [−.0699,−.0067] |
| `LFO_TEXT_DF` | ΔF1 hashing block: **−.0289 ± .0879** | per-seed rows; khớp W1 |
| `LFO_TEXT_CI` | 95% CI: **[−.070, +.012]** | t-CI tự tính: [−.0700,+.0123] |
| `LFO_FOLDS` | protocol description: **20 seeds × randomized cluster hold-outs** (~20% unit/stratum; test share 14.3–27.2% samples) | split_info 20/20 rows, min .1426 / max .2720 tự đếm |
| `LFO_CONTRAST` | **dd = −.0095 ± .0803** | dd per-seed tự tính từ rows; khớp V1 bit-exact |
| `LFO_TEST` | **exact paired Wilcoxon signed-rank on per-seed degradation differences** | Wilcoxon exact 4/4 do V1 enumerate 2^20; F chạy lại scipy exact khớp |
| `LFO_P` | **p = .368** (primary, cùng câu CONTRAST); FedAvg **p = .674** nằm ngay cạnh (−.0139 ± .0794) | scipy exact: .368277 / .674223 |

Ngoài lề token, các bổ sung trung thực 2 chiều trong cùng đoạn (đều có
số đã audit): 95% CI của dd **[−.047, +.028]** (khớp V1); kết luận
two-directional "no robustness ranking … is supported, and none is
claimed"; power **≈ .75** tại differential .05-F1, n=20; 95% CI của dd
**không nằm trọn trong margin ±.02** dùng cho TOST §5.3 (⇒ equivalence ở
margin .02 KHÔNG pass; pass ở margin .05); sensitivity ngưỡng 0.50:
dd −.0033/−.0121, p=.985/.430; baseline metadata 5 chiều sụt tương tự
(−.026…−.044) ⇒ family shift không riêng của content features.

Protocol §5.4 sửa theo đúng yêu cầu: "leave-**families**-out (LFO) …
family folds" → "leave-**cluster**-out (LCO), MinHash Jaccard ≥ .30 over
code 3-grams + package-name patterns, package closure qua union-find
(không unit nào xẻ package/near-duplicate; 0/67 multi-version family bị
xẻ), 20 seeds × randomized ~20% unit hold-outs per label stratum,
registered before any metric was computed". Hai chỗ khác cũng đổi cho
nhất quán: Discussion "The LFO evaluation" → "The leave-cluster-out
evaluation"; Conclusion "the **queued** leave-families-out evaluation"
→ "the leave-cluster-out evaluation **reported above**" (mục [X2d]).

#### 1.2 Xác minh độc lập của F (chạy lại từ raw rows, không tin report)

```
dg(sc,t.3) = −.0383±.0675  CI95 [−.0699,−.0067]   dt = −.0289±.0879  CI95 [−.0700,+.0123]
dd(sc,t.3) = −.0095±.0803  CI95 [−.0470,+.0281]   Wilcoxon exact p = .368277
dd(fed,t.3)= −.0139±.0794  CI95 [−.0510,+.0233]   p = .674223
dd(sc,t.5) = −.0033±.0443  p = .985435 | dd(fed,t.5) = −.0121±.0691  p = .430433
test share (lco, t.3): min .1426 / max .2720 (n=20)
power sim 2000 reps (RNG 20260922): δ=.02→.160, δ=.05→.736, δ=.08→.983
```
Tất cả khớp W1 §3 và V1 (V1: power .75 tại δ=.05 — lệch .014 với rerun
của tôi = MC noise, sd ước lượng ≈ .010; paper dùng "≈.75" theo số V1
đã audit).

### [X2] FIX MINOR — 4/4 DONE

- **(a) refs.bib** — 4 note fields bỏ chữ "round-11 audit", giữ nguyên
  fact bibliographic: ohm2020backstabbers → "arXiv:2005.09535; 2005.09561
  is an unrelated paper; BKC dataset"; duan2021maloss → bỏ mệnh đề
  "authors and venue corrected…"; halder2024memptec → "venue: ACM Web
  Conference (WWW)"; refuseguard2026 → "Note: arXiv:2603.01246 is a
  different paper (Campbell et al., …)" (bỏ "mistakenly attached /
  corrected in the round-11 audit"). Sau fix: grep PDF "round-N" = **0**.
- **(b) `packguard/lco.py::render_summary`** — khối header "## PRIMARY
  paired test…" đang nằm BÊN TRONG vòng `for d in agg["degradation"]`
  (lặp 12 lần). Đã dedent ra ngoài vòng. Xác minh: re-render từ stored
  rows (không chạy lại training) → **1 header "## PRIMARY"**, và **34/34
  dòng bảng/bullet số BYTE-IDENTICAL** với `summary.md` đã audit trên
  đĩa. summary.md trên đĩa KHÔNG đụng (artifact đã audit giữ nguyên).
- **(c) Comment đếm từ abstract** — đếm lại thật trên PDF mới:
  **236 từ** (pdftotext, token whitespace chứa chữ/số, ABSTRACT → hết
  "…a refinement, not a replacement."). Comment mới ghi 236 + khoảng
  audit 232–237 tùy convention math-token; ≤250 dư ≥14 từ.
- **(d) "queued" ở Conclusion** — đã đổi thành "reported above" (xem
  [X1]). Hai "queued" còn lại (A.6: validation-locked threshold;
  FP-directed advisory arm) là future-work CHƯA chạy — giữ nguyên, đúng.

### [X3] COMPILE + VERIFY — ALL GREEN

- `tectonic -X compile --keep-logs main.tex` → **exit 0**, **8 trang**;
  Overfull còn đúng 1 `\vbox (1.44199pt)` lúc `\output` (column
  balancing đã biết từ W2/V2 — vô hình).
- `{{R13:` trong main.tex = **0**; "R13:" trong **PDF** = **0** (còn 1
  chuỗi "R13:LFO_*" duy nhất nằm trong `% SRC` comment của chính §5.4 —
  vô hình, ghi nhận để truy vết).
- PDF render check: `??` = 0; `round-N` = 0; `AMENDMENT` = 0; `LFO` = 0;
  "leave-cluster-out" = 2 (§5.4 + Conclusion); mọi số mới render đúng
  (soi /tmp/pdftotext: "ΔF1 −.0383±.0675 (95% CI [−.070, −.007])",
  "dd=−.0095±.0803 … p=.368; FedAvg −.0139±.0794, p=.674; 95% CI of dd
  [−.047, +.028]", "power ≈.75", "±.02 … would pass at a margin of .05").
- `gen_paper_numbers.py --check` → `OK -- 336 macros verified` (exit 0).
- `pytest tests/ -q` → **732 passed / 0 failed** (78.8s) = 708 cũ + 24
  test LCO của W1; fix render_summary không phá test nào.

### [X4] GATE — `bash scripts/verify_repro.sh` → **exit 0 (30 passed / 0 failed)**

Trước khi chạy gate, manifest đã bổ sung theo tasking
(`scripts/make_manifest.py`, list FILES + regenerate):
`outputs/packguard/lco/lco_results.json` (414KB), `outputs/packguard/lco/
summary.md`, `outputs/packguard/lco/clusters_t030.json` (112KB) +
`clusters_t050.json`, và `data/packguard/manifests/
benign_expansion_v1.json` (**14.8MB — VƯỢT policy "<~1MB" của manifest;
add chủ đích làm integrity anchor của expansion 200-sample vì mỗi sample
mang source_url+sha256; ghi chú exception ngay trong comment của
make_manifest.py; expansion KHÔNG thuộc corpus/grid đã đăng ký**).
`expansion_report.json` (14.8MB, run-log) không add. Manifest mới:
**45 file, 0 missing**; step 5 của gate: 45 ok / 0 mismatched.
`PackGuard_final.pdf` đã **tái xuất bản** (V2 phát hiện bản cũ 03:25
stale hơn main.pdf) = bản `main.pdf` 8 trang sau khi điền.

### [X5] Roadmap — `docs/improvement_roadmap_v2.md` đã cập nhật

(i) block "Cập nhật 2026-09-28 (vòng 13, F — FINAL)" sau block vòng 11
(trạng thái đầy đủ + số LCO + gates + blockers); (ii) mục R9 đổi thành
"**P2 — DONE vòng 13 (đổi thiết kế: leave-CLUSTER-out)**" kèm lý do lệch
thiết kế so với kế hoạch gốc (fold theo family metadata → MinHash
cluster + package closure) và trỏ artifacts.

## 2. FILES (absolute)

- /Users/macbook/.zcode/workspace/default/refuseguard/paper2/main.tex — §5.4
  rewrite (8 token + protocol + power sentence), 2 chỗ LFO→LCO, Conclusion
  "queued"→"reported above", comment abstract 236 từ
- /Users/macbook/.zcode/workspace/default/refuseguard/paper2/refs.bib — 4 note fields
- /Users/macbook/.zcode/workspace/default/refuseguard/paper2/main.pdf +
  PackGuard_final.pdf — bản 8 trang sau điền (final tái xuất)
- /Users/macbook/.zcode/workspace/default/refuseguard/packguard/lco.py — fix
  render_summary (dedent header ra khỏi loop, ~dòng 563)
- /Users/macbook/.zcode/workspace/default/refuseguard/scripts/make_manifest.py — +5
  artifact round-13 vào FILES (+ comment policy exception)
- /Users/macbook/.zcode/workspace/default/refuseguard/outputs/master/ARTIFACT_MANIFEST.sha256 — regenerate (45 file)
- /Users/macbook/.zcode/workspace/default/refuseguard/docs/improvement_roadmap_v2.md — cập nhật trạng thái
- /Users/macbook/.zcode/workspace/default/refuseguard/reports/round13/F_report.md — file này

KHÔNG đụng: p0_macros/numbers.tex (336 macro nguyên vẹn — --check OK),
outputs/packguard/lco/* (artifact đã audit, không ghi đè), packguard/*
khác, scripts cũ. Không git commit.

## 3. CÁCH CHẠY / KIỂM CHỨNG

```
cd paper2 && tectonic -X compile --keep-logs main.tex     # exit 0, 8 pages
.venv/bin/python scripts/gen_paper_numbers.py --check      # OK, 336 macros
.venv/bin/python -m pytest tests/ -q                       # 732 passed
bash scripts/verify_repro.sh                               # exit 0, 30/30
.venv/bin/python scripts/make_manifest.py --check          # 45 ok, 0 mismatch
pdftotext paper2/PackGuard_final.pdf - | grep -cE "round-[0-9]|AMENDMENT|R13:"   # 0
```

## 4. LỆCH CHUẨN / QUYẾT ĐỊNH EDITORIAL (all disclosed)

1. **GRAPH_DF/TEXT_DF**: tasking ghi "−.0095±.0803" cho GRAPH_DF và
   "−.0139±.0794" cho TEXT_DF — nhưng đúng nghĩa token trong W2_report §4
   (ΔF1 từng block) thì hai số đó là **dd contrast** (đồng thời tasking
   cũng bảo "kiểm từng token nghĩa gì trong W2_report §4 trước khi điền").
   Điền theo NGHĨA: block deltas −.0383/−.0289; dd −.0095 điền 1 lần ở
   CONTRAST (không lặp). Không có số nào bị đặt sai vai.
2. **"90% CI [−.047,+.028]" trong tasking**: dãy số đó là **95%** t-CI
   (t₀.₉₇₅,₁₉=2.093; tự tính lại = [−.0470,+.0281]; V1 cũng ghi 95%;
   chính tasking ở câu power gọi nó là "the 95% CI of dd"). Ghi "90% CI"
   cho dãy đó sẽ là sai thực tế trong paper → dùng **95% CI**, đúng cả template
   ("95\% CI") lẫn nguồn. Đã tính thêm 90% t-CI của dd = **[−.041,+.022]**
   (convention TOST của bài): equivalence ±.02 FAIL dưới CẢ hai mức CI →
   kết luận không phụ thuộc mức CI (ghi trong % SRC).
3. **Power sentence**: tasking gợi ý "…95% CI of dd [−.047,+.028]
   **excludes** the round-11 margin of .02" — hướng chữ này ngược data
   (CI CHỨA ±.02; điều đúng là CI KHÔNG nằm trọn TRONG ±.02 ⇒ equivalence
   .02 không pass, per V1). Viết lại trung thực: "not contained in the
   ±.02 equivalence margin … not established (it would pass at a margin
   of .05)". Đồng thời không thể viết "round-11" trong text (gate round-N
   = 0) → tham chiếu "the ±.02 equivalence margin used above" (§5.3).
4. **LFO_FOLDS**: điền bằng mô tả protocol (20 seeds × randomized cluster
   hold-outs + test share 14.3–27.2%) thay vì một con số fold — không tồn
   tại "k folds" trong artifact.
5. **LFO_P**: đặt p=.368 (khớp CONTRAST strong-centralized trong cùng
   câu); .674 (FedAvg) nằm cạnh ngay — cả hai đều đã audit; không dùng
   .674 làm p của dd-sc (sẽ mâu thuẫn nội câu).
6. **AMENDMENT-7** không xuất hiện visible (hygiene "AMENDMENT"=0 trong
   PDF) — nằm trong `% SRC` comment cùng config_sha16.
7. Quan sát KHÔNG sửa (ngoài scope): `(pmKbUniverseTypes/\pmKbUniverseTypes`
   ở §5.3 render "137/137 types, 2,299/2,299 instances" — macro bị lặp
   tên, số tự-consistent, vô hại; nếu muốn sửa thì là 1-line nhưng đụng
   câu đã audit của W2 — để orchestrator quyết.

## 5. BẢNG TRẠNG THÁI CUỐI CÙNG — TỪNG MỤC AUDIT REVIEWER

| Mục | Nội dung (ngắn) | Trạng thái cuối |
|---|---|---|
| P0-1 | FedProx routing audit (mu per-algo) | **Done** (v11; bit-exact 160/160 + fix + test) |
| P0-2 | Strong centralized + TOST ±.02 | **Done** (v11; primary PASS −.0065 CI [−.0133,+.0003]) |
| P0-3 | Retraction claim tfidf-degradation | **Done** (v11; artifact-of-vectorizer, rút có kiểm soát) |
| P0-4 | gen_paper_numbers (336 macro) | **Done** (v11; --check OK, nay chạy lại OK trên §5.4 mới) |
| P0-5 | Trivial/shortcut baseline | **Done** (v11; graph +.0227/+.0487, p ≤1.9e-5) |
| P0-6 | Hygiene (round-N/AMENDMENT/refs) | **Done** (v11 + hoàn thiện nốt 4 note refs.bib vòng này) |
| P1-9 | Round-12 defense/safety pairing + phân tích | **Done** (v12: pairing 38/45 gate-pass, 24 mal/14 ben, Fisher .40, strip-equality 38/38, audits V1/V2 round-12) |
| P2-11 | Family-shift robustness (LCO) | **Done** (v13: 480 rows mock=false, AMENDMENT-7 trước-run, V1 audit bit-exact + Wilcoxon exact 4/4; dd −.0095 p=.368, CI95 [−.047,+.028]; joint claim vào paper §5.4) |
| P2-11b | Hard-negative expansion | **Partial — disclosed**: 200 benign npm RANDOM draw (không popularity-bias), 17/200 hard-negative profile (2 hook / 16 network), 200/200 sha256 verify (V1); KHÔNG nhập corpus/grid; manifest riêng benign_expansion_v1.json |
| P1-7 | OSF artifact upload | **BLOCKED — user** (cần OSF từ user; không thể tự làm) |
| P1-8 | API key (ChatGPT-MCP consult) | **BLOCKED — user** (not_authenticated 4 vòng liên tiếp; cần user login) |
| P1-10 | 8B/7B out-of-stack scale arm | **Deferred — resolved-by-directive** (model ≥4B đã dọn khỏi research stack theo directive <4B; paper giữ 1-câu feasibility + Appendix A.8) |
| P2-12 | Secure aggregation (pairwise mask) | **Deferred** — giữ vai simulation-disclosure; sau rewrite P3-16 đã RA KHỎI contribution chính |
| P2-13 | DP Gaussian noise ε sweep | **Deferred** — như trên (sensitivity arm ε≈48.4 disclosed trong A.4) |
| P2-14 | SecAgg/DP trong contribution chính | **Resolved-by-removal** (thesis mới đưa FL/SimTrust xuống detector nền; không còn là contribution) |
| P3-15 | Abstract ≤250 + 3 contributions | **Done** (v13 W2: C1/C2/C3; F đếm lại 236 từ) |
| P3-16 | Rewrite main theo thesis "The Advisory Inside" | **Done** (v13 W2 + F điền §5.4, compile 8 trang, mọi gate xanh) |

## 6. ĐÁNH GIÁ CUỐI — PAPER ĐẠT MỨC NÀO

**Đạt mức: competitive-plus, tiến tới strong-accept-track tại venue
Q1 phân tích an ninh/ML-systems, với 3 điều kiện kèm theo.**

Cơ sở (điểm mạnh có data chống lưng): (1) measurement sạch — paired
pre-registered, RR=0 scope 2,700, family-dependent direction 2 chiều đều
có harm cho scanner (recall loss + FP manufacture); (2) defense có tính
chứng minh cơ học — strip(P2)==strip(original) 38/38 byte-equality
("attack removal, not rephrasing"), neutralize 23/23 + 4/4 revert trên
family bị inflate, và cost trên llama được nâng thành first-class outcome
(thái độ trung thực này là điểm cộng với reviewer); (3) detector nền có
TOST equivalence PASS + refinement có ý nghĩa + **giờ đóng được câu hỏi
family-shift** mà chính bài đặt ra — kết quả null hai chiều có power
(power ≈.75 tại δ=.05; CI không cho phép claim equivalence ở ±.02) được
viết thẳng, không spin; (4) provenance/hygiene ở mức hiếm thấy: mọi số
trace được về artifact, mock=false, AMENDMENT đăng ký trước run, macro
check tự động, manifest 45 file, không còn từ vựng audit lộ trong PDF.

Điều kiện (nếu venue đòi, theo thứ tự giá trị/chi phí):
1. **User-action blocker phải được ghi rõ ngoài paper**: OSF (P1-7) +
   API-key consult (P1-8) — không ảnh hưởng nội dung nhưng ảnh hưởng
   artifact-review track.
2. **Scale ceiling 2–3B là disclaimer sống còn**: mọi claim đã scope
   "at 2–3B"; reviewer có thể hỏi family thứ 3 (chỉ granite ladder trên
   domain vulnerability là bổ trợ) — paper đã có 1 câu Threats + A.7/A.8;
   nếu rebuttal cần, chỉ có thể đáp trong giới hạn directive <4B.
3. **Expansion 200 (17 hard-negative) PHẢI được đọc như data-pack cho
   vòng sau**, không phải robustness evidence — paper không cite nó như
   corpus (đúng); nếu reviewer hỏi "corpus popularity-bias?", câu trả lời
   nằm ở manifest + W1/V1 report, không ở trong bài.

Rủi ro còn mở (không chặn submit): validation-locked threshold + FP-directed
arm vẫn queued (đã nêu trong A.6 — future work); KB confidence self-reported
(đã disclosure); pooled masking caveat (đã disclosure).

## 7. SELF-TEST THẬT (đã chạy trong phiên này)

1. Tính lại dd/CI/Wilcoxon từ raw rows (script /tmp) — khớp 4/4 cell,
   chi tiết §1.2.
2. `tectonic -X compile --keep-logs main.tex` exit 0, 8 pages (2 lần:
   sau §5.4 và sau comment abstract).
3. `gen_paper_numbers.py --check` → OK 336 (exit 0).
4. `pytest tests/ -q` → 732 passed / 0 failed (78.8s).
5. `verify_repro.sh` → exit 0, "SUMMARY: 30 passed, 0 failed"
   (pytest 732, e2 dry-run OK, 26 artifacts parse, value checks, manifest
   45/45, paper compile).
6. `make_manifest.py --check` → "45 ok, 0 mismatched, 0 missing".
7. PDF greps: R13 0, round-N 0, AMENDMENT 0, `??` 0, LFO 0; pdftotext soi
   từng số mới (list ở [X3]); render_summary re-render 1 header +
   34/34 dòng số byte-identical với artifact.
8. Abstract đếm 236 từ trên PDF (comment đã cập nhật).

Sources: W1/W2/V1/V2 reports round-13; outputs/packguard/lco/lco_results.json
(480 rows, mock=false, config_sha16 9bea57439fa0c473); AMENDMENT-7
(docs/packguard_prereg.md). Không có reference mới cần verify (W1: không
thêm citation mới).
