# S Report — Round 5 (Tổng hợp: fix false-claim + tích hợp khung positive vào paper + verify)

Ngày: 2026-09-20. Tác nhân: S. Phạm vi: reports/round5 (report của mình),
paper/, docs/, outputs/master/, reports/round5/{A2,A3}_report.md (chỉ thêm
khối correction, không xóa nội dung cũ). KHÔNG git commit. Nguyên tắc: mọi
số mới truy vết outputs; narrative mạnh lên bằng khung kể chuyện, không
bằng số mới.

---

## 0. Tiếp nhận trạng thái (phát hiện quan trọng)

Một phần sản phẩm Vòng 5 của S đã tồn tại trên disk từ phiên làm việc trước
(mtime 2026-09-20 22:48–23:17): `scripts/collect_master_round5.py`,
`outputs/master/round5_master.json`, `docs/results_master_round5.md`,
`paper/tables/tab_round5{,_defense}.tex`, hàm `fig_round5()` +
round-5 section của `verify_tables()` trong `paper/make_figures.py`, và 6
figures. XỬ LÝ: KHÔNG làm lại mù quáng — verify từng cái bằng lệnh thật
(§F2), rồi làm phần còn thiếu (paper sections chưa hề được chạm — vẫn bản
R4; refs.bib thiếu Safeguard-DoS; A2/A3 report chưa có correction).

## F1 — False claims LOW (V1/V2 bắt) → [CORRECTED-ROUND5]

| File | Sửa | Căn cứ bắt |
|---|---|---|
| `reports/round5/A2_report.md` | Khối [CORRECTED-ROUND5] đầu report: (1) "405 passed" stale → **408 passed, 0 failed**; (2) "1.200 generation thật" → **1,032 new + 168 cache-hit = 1,200 records**; tổng Vòng 5 **1,378** (không phải ~1,546) + 2 inline marker HTML comment tại §1 và §7 | V1 §4.1–4.2, V2 §2.3–2.4 |
| `reports/round5/A3_report.md` | Khối [CORRECTED-ROUND5] đầu report: (1) "1/98 pair" → **2/98 pair** (1 unique benign sample 218817 ở cả 2 arm); (2) "llama 16 phút" → **661.6 s ≈ 11 phút** + 2 inline marker tại §4.1 và §3 | V2 §4.1, §1.6 |

Nội dung gốc GIỮ NGUYÊN theo yêu cầu; marker dạng HTML comment nên không
làm hỏng render markdown.

## F2 — Master round-5 (verify lại sản phẩm dở)

```bash
.venv/bin/python scripts/collect_master_round5.py --verify-only
# → [verify] 139 round-5 rows re-derived from sources and matched against
#            outputs/master/round5_master.json
```

Script re-read: build lại mọi row từ nguồn (`results_*.json` E0-V2 +
defense, `side_effect_llama3b.json`, bench jsonl, cả 2 manifest) và assert
khớp disk từng row; kèm `check_expectations()` assert cứng các kỳ vọng đã
V1/V2 audit: llama flips 10/11/11, granite 0.100→0.733/0.767, flips 10/20/25,
P3 0.3667/0.3333, p 3.8147e-06/1.9073e-06, 39/60 (19+20), qwen "2/98",
gate 30/30, probe 0.0, query-relevance "100/100", C2b "2/838",
sha `2daa249f7543f8e0`, cache 168, new 1,032, tổng 1,378. PASS toàn bộ.
`docs/results_master_round5.md` đã chứa RR-table 3×4, flips, granite recall
curve, P3 harm + CI context, P1 injection, query-relevance, accounting.

## F3 — Paper reframe theo KHUNG POSITIVE (trung thực)

**Title** (`paper/main.tex`): giữ thân title, thêm mệnh đề phản ánh hook:
`...under Safety-Induced Blocking, Untrusted Code Context, and the Defence
Itself`. Lý do: RQ7 chứng minh cả 3 threat surface, twist cuối là finding
mạnh nhất có audit chắc nhất (20/20 sha, raw JSON hợp lệ).

**`00_abstract.tex`** — viết lại: dẫn bằng Finding 1 (P3 collapse
1.000→0.367/0.333, 39/60, p≤3.8e-06) + Finding 2 (RR=0 nhưng bias
vulnerable: llama +10/+11/+11, granite 0.100→0.733/0.767); kèm Finding 3
(P1 0.742→0.484) và refusal-suppression; kết bằng message tổng.

**`01_intro.tex`** — giữ gate narrative; thêm đoạn "Escalating the attack —
and auditing the defence" (C5 query-relevant 100/100 vs 0.2%, NOT_SUPPORTED,
verdict-bias, P3 collapse); contributions viết lại đúng 4 mục đề xuất:
C1 C5 benchmark (query-relevant + anti-leakage + pre-reg), C2 blocking-transfer
study (negative result có giá trị + verdict-bias + model-scale clause),
C3 defence-risk finding (flip-rate ledger + refusal-suppression cùng mạch
"mitigation layer is a risk surface"), C4 P1 injection-resistance + CodeBERT.
Hai "first" scoped + hedge ("To our verified knowledge...").

**`02_related.tex`** — over-refusal subsection: thêm TabooRAG mechanism câu
nối C5 + Safeguard-DoS (`zhang2024safeguarddos`); Positioning viết lại:
từ chối "first" cho quan sát có chủ; claim 2 "firsts" đúng scope đã verify
kèm hedge và scope note (frontier question open).

**`03_method.tex`** — §conditions đổi thành (C0–C3) + C5: AST sink
extraction (26 sinks, member-call excluded), 8+1 template label-blind,
count cap 3, near/far carriers, D2 wording, anti-leakage by construction,
strict semantics gate; §defences thêm P3 (a) detection (b) boundary label
verbatim (c) reassertion (d) recovery, với 2 disclosure: genre-targeted và
bundle ≥5 components (chỉ claim defense-level).

**`04_setup.tex`** — subsection mới §bench5: 200 rows × 4 arms = 800 entries,
sha, strata 50/50 per label, subsets 60+60 / 30+30 nested seed 20260923,
defence cells + budget-guard disclosure (293/360, 180/360, C0×P3 control
không chạy), pre-reg gate files, granite fallback disclosed + smoke 0.5B
4/5 REFUSAL; §models thêm "harness default 512, which the C5/defence rounds
use"; §scale thêm Round-5 accounting: 1,673 records, **1,378 unique new**
(1,032 + 168 cache-hit; defense 346), 0 REFUSAL / 1 PARTIAL.

**`05_results.tex`** — thêm `fig_round5` figure* (2 panel: flips + P3
collapse) và subsection **RQ7** (sau RQ6, trước B4): query-relevance audit,
blocking null + inert-evidence counterexample, 3 gates NOT_SUPPORTED 0/3,
verdict-bias (llama 60/60 vs 49/60 — số đếm trực tiếp từ records, xem
lệnh ở §F4), granite curve p-values, defence-is-the-risk (39/60 = 19+20,
20 unique; sha 20/20; raw JSON; qwen 2/98; detector 400/400 + 0/984;
side-ledger 30/30, 0.033, 0/30), generation accounting. Không xóa bất kỳ
RQ cũ — mọi số cũ còn khớp verify_tables.

**`06_discussion.tex`** — viết lại: giữ gate-bought-us (thêm
escalate-before-concluding), MỚI "The defence is the risk" (flip-ledger
khuyến nghị + caveats scope), MỚI "Blocking fears are premature at open
scale; corruption is the actionable channel" (0 refusal xuyên suốt + 2 kênh
corruption + C5 làm instrument + frontier open), giữ refusal-suppression
(thêm side-ledger round 5), isolation-not-accuracy, availability-vs-integrity
(thêm P3 harm vô hình với availability); Threats thêm: model-scale/transfer,
granite fallback round-5, defence attribution (bundle, control chưa chạy,
cells partial, llama benign half absent), gate scope thêm P3 genre-targeted.

**`07_conclusion.tex`** — viết lại theo message tổng; future work đặt P3
ablation + frontier API + CWE extension lên đầu.

**`appendix_repro.tex`** — artifact overview thêm c5_risk_context.py /
p3_boundary.py / round5 runners / collect_master_round5.py; repro steps
(8)–(10) thêm round-5 + master collect; traceability table thêm
tab_round5 / tab_round5_defense / fig_round5 → nguồn; "353 unit tests" →
**408** (sau khi pytest chạy thật).

**refs.bib** (`paper/refs.bib` + `docs/refs.bib`) — thêm
`zhang2024safeguarddos` (arXiv:2410.02916), VERIFIED qua trang arXiv:
"LLM Safeguard is a Double-Edged Sword: Exploiting False Positives for
Denial-of-Service Attacks", Qingzhao Zhang, Ziyang Xiong, Z. Morley Mao,
v1 2024-10-03. Đồng thời `docs/literature_review.md` §2 thêm entry verified;
check_citations (đọc docs/refs.bib) PASS 18 keys.

**`main.tex`** — wire `\InputIfFileExists` cho `tables/tab_round5` và
`tables/tab_round5_defense`.

## F4 — Verify (lệnh + output thật)

```bash
.venv/bin/python -m pytest tests/ -q
# → 408 passed, 2 warnings in 22.29s

.venv/bin/python paper/make_figures.py
# → [verify] all table numbers match source files
#   [verify] round-5 table numbers match outputs/master/round5_master.json
#   [verify] 17 headline numbers cross-checked against outputs/master/master_results.json
#   [cites] 18 keys used, all present in refs.bib (unused bib entries: none)
#   [ok] 6 figures (fig_round5.pdf 25634 bytes)

tectonic --outdir paper/compiled paper/main.tex
# → note: Writing `paper/compiled/main.pdf` (332 KiB)  — chỉ font warnings
#   chuẩn acmart/libertine; grep log: 0 error, 0 undefined citation/reference
cp paper/compiled/main.pdf paper/compiled/refuseguard_paper.pdf

pdftotext paper/compiled/refuseguard_paper.pdf /tmp/paper_r5.txt
# stale-scan: "2/2 correct"=0, "0.00049"=0, "405 passed"=0, "353 unit"=0,
#   "1,546"=0, "??"=0 (unresolved refs); "0.400" hits chỉ là substring
#   "400/400 advisories" (detector recall, có nguồn) + disclosure có chủ ý
#   trong threats (Llama B0 0.400→0.033 retraction — cố tình giữ)
# new-content scan: "RQ7 (E0-V2)" Table 5 + "RQ7 (Round 5)" Table 6 render;
#   "1,378"=2, "2/98"=1, "39/60"=10, "0.367"=10, "100/100"=4, "2/838"=2,
#   "60/60 vs. 49/60"=1; title 3 dòng render đúng

bash scripts/verify_repro.sh
# → === SUMMARY: 27 passed, 0 failed  (pytest strict 408; E2 dry-run;
#   22 artifacts; value checks master rows=341, gate FAIL 3 completed/0 pass,
#   e8-llama B0=0.0333, e6 vul-only p=0.5; manifest sha256 23/23; PDF build)
```

Số llama benign over-trigger dùng trong RQ7 ("60/60 vs. 49/60") đếm trực
tiếp từ records:

```bash
.venv/bin/python - <<'EOF'
import json
recs = json.load(open("outputs/experiments/round5_e0v2/results_llama3b.json"))["records"]
for arm in ("C0","D2_task","C5_near","C5_far"):
    ben = [r for r in recs if r["condition"]==arm and r["y_true"]==0]
    print(arm, "benign n=", len(ben), "y_pred=1:", sum(1 for r in ben if r["y_pred"]==1))
# → C0 49/60; D2 59/60; C5_near 60/60; C5_far 60/60
EOF
```

## Những gì S KHÔNG làm (giới hạn trung thực)

- Không chạy thêm LLM nào (không GPU; mọi số Vòng 5 dùng đúng runs đã có).
- Không claim cơ chế thành phần của P3 (bundle ≥5; ablation chưa chạy —
  ghi là future work #1).
- Không claim "C5 vô hại" (nó có hại theo hướng khác — verdict bias; đã
  viết đúng chiều trong paper).
- Không generalize non-transfer ra frontier models (clause model-scale
  giữ nguyên trong RQ7 + discussion + related).
- Không xóa bất kỳ nội dung cũ nào trong A2/A3 report.

---
*Verification: pytest 408 passed; tectonic 0 error; make_figures PASS;
collect_master_round5 --verify-only PASS (139 rows); verify_repro.sh 27/27.
Không git commit.*
