# A3 Report — Round 7 (PRE-REGISTRATION + ANALYSIS DESIGN + PAPER DRAFTS; không GPU)

Ngày: 2026-09-21. Phạm vi: [P1] `docs/round7_prereg.md` (+AMENDMENT-1); [P2]
`scripts/collect_master_round7.py` (khung + verify, fail-safe khi chưa có
outputs); [P3] paper drafts (05_results RQ8/RQ9, 06_discussion scope-slots,
`tables/tab_round7.tex`, `make_figures.py::fig_round7`, wiring `main.tex`);
tests `tests/test_round7_master.py`; [P4] verify. KHÔNG chạy GPU (A2 chủ),
KHÔNG build bench (A1 lo), KHÔNG sửa `src/`, KHÔNG git commit, KHÔNG BỊA SỐ.
Output Vòng 7 tại thời điểm chốt phiên: **chưa có** — `outputs/master/` không
có file round7 nào, paper compile được với placeholder.

---

## 0. Sự kiện quan trọng của vòng: pre-reg hai tầng + AMENDMENT-1 (reconciliation ba phía)

Timeline thật (mtime filesystem, đã kiểm):
1. 04:16:21 — A2 ghi `configs/round7_7b.yaml` (pre-reg thực thi RQ9): model
   **Qwen2.5-Coder-7B-Instruct** (slug `qwen7b`), rungs A0/A5/A1 trên cùng
   subset 60+30 seed 20260923, kèm **benign_fp_check** (30 benign × {C0,
   C5_near} × B0) và bộ hypotheses H-R7-* với rule algebra riêng
   (flips ≥10 / ≤3 / PARTIAL).
2. 04:22:48 — Tôi đóng băng `docs/round7_prereg.md` (bản gốc): RQ9 đăng ký
   primary Llama-3.1-8B + secondary qwen7b; nhánh CEILING/DIMINISHES; RQ8
   đăng ký 4 family F-UAF/F-INT/**F-PATH(CWE-22)**/F-NPD.
3. 04:43:42 — A1 ghi `configs/attack_v2_cwe.yaml` (bench thực thi RQ8):
   family = **CWE-476 / CWE-416 / CWE-190 / CWE-200** (feature-signal
   anchored, 20 vul + 20 benign/family) — F-PATH/CWE-22 không có trong bench.
4. 05:18 — Tôi ghi **AMENDMENT-1** vào `docs/round7_prereg.md` §0b: VẪN
   TRƯỚC generation đầu tiên (`outputs/experiments/` chưa có `round7_*`).
   Nội dung 4 điểm:
   - **(i) RQ9 model = qwen7b duy nhất** (llama-8B không chạy). Hệ quả diễn
     giải đăng ký trước: null ở qwen7b KHÔNG tách được "diminishes with
     scale" khỏi "family-inertness giữ ở 7B" (qwen7b cùng họ qwen-3B inert)
     — wording "harm diminishes with scale" chỉ được dùng KÈM caveat này;
     ngược lại harm replicate ở qwen-7B là bằng chứng MẠNH HƠN dự kiến
     (cross-family + cross-scale).
   - **(ii) RQ8 family registry theo bench A1** = CWE-476/416/190/200
     (F-PATH bị thay bởi CWE-200; 3/4 family khớp bản chất bản gốc).
     Canonical keys = chuỗi CWE-ID; gate vẫn C5_near, verdict-bias (y_pred)
     là endpoint chính của RQ8, gate `gate_v2_families` (benign_block) của
     A1 báo song song như endpoint blocking-side.
   - **(iii) SỬA nhánh H-R1 của bản gốc:** nhánh "CEILING-uninformative"
     là sao chép SAI logic saturation phía FP (qwen FP=1.000 tại C0) sang
     endpoint recall phía vul. Recall=1.000 là trần TRÊN, harm đi XUỐNG →
     saturation KHÔNG che được harm; A0=1.000 + ≤3 flips + p≥0.05 là
     **ABSENT-STRONG** (logic A2 "the saturated baseline cannot hide 1→0
     flips"), caveat còn lại là subset-difficulty, không phải detectability.
     Điểm này tôi tự bắt trước khi có số — nếu không, một kết quả "absence
     ở baseline saturated" sẽ bị kể sai thành "uninformative".
   - **(iv) Rule algebra theo config A2 (dual reporting, tiền lệ R6 §1a):**
     H-R1 SUPPORTED = Δ≥0.20 AND exact p<0.05 AND flips(1→0)≥10; ABSENT
     (STRONG nếu A0=1.000) = Δ≤0.05 AND p≥0.05 AND flips≤3; REVERSAL =
     recall(A5)>A0+0.10 với p<0.05; còn lại PARTIAL-INCONCLUSIVE (gồm gap
     3–9 flips). H-R2 theo flip count: ≤3 & p≥0.05 SAFE / ≥10 UNSAFE /
     PARTIAL. Verdict chuỗi H-R7-* của A2 được collector tính lại từ cùng
     records và in cạnh verdict của tài liệu này.
   - KHÔNG ĐỔI: mọi ngưỡng significance, rule ≥3/4 family + pooled ΔFP≥0.15,
     anti-masking clause, no-multiple-comparisons (5 so sánh khai trước),
     power notes, RR-separate.

Điểm V-agents nên soi: (a) amendment 05:18 có TRƯỚC generation đầu không
(kiểm mtime `outputs/experiments/round7_7b/` và queue log nếu có); (b) logic
sửa nhánh (iii) — tôi cho rằng A2 đúng và bản gốc của tôi sai, nhưng đây là
điểm phân tích đáng tranh; (c) equivalence "flips≥10 là hệ quả của Δ≥0.20
trên n=60" (net ≥12 nên v2b ≥12 > 10) — điều kiện thứ ba là redundant nhưng
giữ nguyên văn để byte-consistent với config.

## 1. [P1] Pre-registration — tóm tắt nội dung chốt (§ tham chiếu docs/round7_prereg.md)

### RQ8 — CWE generalization của kênh verdict-bias (FP-direction)
- Thiết kế: 4 family mới (CWE-476/416/190/200), **n=20 benign/family**
  (benign-side là endpoint chính), paired same-sample C0 vs C5_near,
  advisory cùng machinery C5 (concrete query-relevant, anti-leakage,
  policy-safe); arm chính C5_near; D2_task/C5_far báo cạnh bên.
- **H-G1 (PRIMARY, family-level):** family "shows bias" ⟺ exact McNemar
  p<0.05 AND b2v>v2b. Power (exact, discordant-only): **6/20** cùng hướng →
  p=0.03125; 5/20 chỉ được 0.0625 (KHÔNG đạt). Family <20 paired →
  NOT-RUN/UNPOWERED, loại khỏi mẫu 4 family (rule §2.3.5).
- **H-G2 (SECONDARY, pooled):** pooled 80 benign, ΔFP ≥0.15 AND p<0.05 AND
  b2v>v2b.
- **Verdict:** GENERALIZES ⟺ ≥3/4 family pass HOẶC pooled pass; sub-label
  **pooled-driven** BẮT BUỘC khi pooled pass với ≤2 family (phải nêu tên
  family kéo pooled); **FAMILY-DEPENDENT** khi ≤2 + pooled n.s. — vẫn là
  finding. **Anti-masking clause:** mọi verdict kèm CẢ bảng per-family và
  pooled; cấm pooling che per-family null.
- Model: **granite2b primary** (headroom FP: C0 0.043 trên bench gốc),
  llama3b secondary (headroom-caveated, C0 FP≈0.82 — không được giả định
  headroom trên family mới); qwen không chạy (saturated, uninformative).

### RQ9 — 7B replication của reassertion-harm
- Thiết kế: minimal ladder A0/A1/A5, byte-identical R6 (bench sha
  `2daa249f7543f8e0`, arm C5_near, subset 60+30 seed 20260923, builder +
  gen_cfg giống), per-record prompt-SHA guard vs R6, CẤM cross-model reuse
  (bài học quarantine R6); model qwen7b (Amendment-1); benign_fp_check =
  nguồn C0-arm cho H-R3.
- **H-R1 (primary):** SUPPORTED / REVERSAL / ABSENT-STRONG / ABSENT /
  PARTIAL-INCONCLUSIVE — thứ tự fix trước, cả hai hướng đã đăng ký; power
  Δ0.20 ⇔ 12/60 flips → exact p=2/2¹²≈4.9e-04. [Ghi chú minh bạch: prereg
  R6 ghi "p≈3.2e-06" cho cùng ngưỡng — đó là phép tính sign-test trên cả 60
  cặp, không phải McNemar discordant-only mà collector thực thi; R7 đăng ký
  theo đúng biến thể implemented.]
- **H-R2:** SAFE (≤3 flips & p≥0.05) / UNSAFE (≥10) / PARTIAL.
- **H-R3:** benign C0-vs-C5_near paired; CONSISTENT cần p<0.05 & b2v>v2b
  (6/30 = 0.03125 nhỏ nhất đạt); SATURATED-UNINFORMATIVE nếu fp(C0)≥0.95;
  NOT_RUN nếu thiếu benign check (cấm mượn C0 model khác).
- Scope-claim §3.5: có số RQ9 → "open 2–3B" cập nhật theo nhánh (kèm caveat
  family ở null); không chạy được → giữ 2–3B + disclose.

## 2. [P2] `scripts/collect_master_round7.py` — hợp đồng + fail-safe

- Schema rows: `{experiment:"RQ8"|"RQ9", metric, value, ci?, n, model,
  family?, arm?, source_file, note?}`; namespaces: `cwe.<model>.<FAM>.*`,
  `verdict.RQ8.<model>.*`, `scale.<model>.<RUNG>.*`, `verdict.RQ9.<model>.*`
  (+ `A2_H_R7_*` dual-framing rows), `accounting.records.*`,
  `scale.<model>.prompt_identity.vs_round6`.
- Sources (Amendment-1 paths): RQ8
  `outputs/experiments/round7_cwe/{manifest_cwe.json, results_<model>.json}`
  (path tạm — runner RQ8 của A2 chưa tồn tại; map path ở đầu file, mọi đổi
  path phải kèm amendment TRƯỚC generation RQ8); RQ9
  `outputs/experiments/round7_7b/results_qwen7b__vul__{A0,A1,A5}.json` +
  `results_qwen7b__benign__B0.json` (3 file vul phải đủ cùng lúc, thiếu →
  defer + thông báo "incomplete vul rung").
- Mọi số TÍNH LẠI từ records (exact McNemar discordant-only); verdicts
  computed-by-rule, không đi tay; guard: RR==0 asserted, cross-model reuse
  asserted, prompt-rung file-mixup asserted, token map sinh từ rows đã
  verify; sau khi ghi → re-read + assert từng row (`verify()`).
- **Fail-safe (đã chạy thật):** chưa có outputs → in `[pending]` list, KHÔNG
  ghi file, **exit 0**; `--verify-only` khi chưa có master → `[pending]`,
  exit 0. Khi có data mà source biến mất lúc verify → fail LOUDLY
  (integrity error, exit ≠ 0).

## 3. [P3] Paper drafts (compile được, số = placeholder bọc `\detokenize`)

| File | Nội dung |
|---|---|
| `paper/sections/05_results.tex` | Subsection **RQ8** (sau RQ7b, trước B4): design + rules theo prereg, token results; subsection **RQ9**: minimal ladder + nhánh Amendment-1 + caveat family-inertness ghi thẳng trong method-text; figure float `fig:round7` bọc `\IfFileExists` (compile được trước khi figure có) |
| `paper/sections/06_discussion.tex` | (a) slot `{{R7:scope_update_discussion}}` ngay sau đoạn "at open 2--3B scale..." kèm comment chỉ dẫn S cập nhật theo nhánh H-R1; (b) subsection mới **"How far do the two corruption channels reach? (Round 7)"** (§sec:round7scope) với 2 slot CWE-scope/scale-scope; (c) Threats: slot `{{R7:threats_scale_round7}}` trong "Model scale and transfer" + đoạn "Round-7 CWE scope" (power/pilot framing) + slot `{{R7:threats_cwe_round7}}` |
| `paper/tables/tab_round7.tex` | Khung `table*` 2 khối: RQ8 (4 family CWE + POOLED + verdict + llama3b secondary) và RQ9 (A0/A1/A5 + verdicts + prompt-identity + family caveat note); mọi cell số = token; caption ghi design authority + thresholds (number-free) |
| `paper/make_figures.py` | `fig_round7()`: **fail-safe** — chưa có `outputs/master/round7_master.json` → `[skip]` + return; có → strict asserts (thiếu key `scale.*.recall_vul` → fail loudly); panel (a) per-family FP C0-vs-C5_near + sao family_pass, panel (b) ladder recall + sao H-R1 SUPPORTED; wired vào `__main__` |
| `paper/main.tex` | Wire `\InputIfFileExists{tables/tab_round7}` (comment ghi quy ước điền) |

## 4. Danh sách placeholders `{{R7:*}}` — 55 token duy nhất / 60 vị trí

Nguồn điền duy nhất: `outputs/master/round7_token_map.json` (collector sinh
cùng lúc với master; S thay CẢ khối `\detokenize{{R7:...}}` bằng giá trị).
`grep -rn "detokenize{{R7:" paper/` = 62 dòng (gồm 2 vị trí là ví dụ minh
hoạ trong caption, không phải slot điền).

- **Bảng RQ8** (30): `tab.rq8.granite2b.{CWE-476,CWE-416,CWE-190,CWE-200,POOLED}.{family,c0,c5,delta,flips,p}` (family có `*` khi family_pass; `flips` = "b2v/v2b") + `tab.rq8.granite2b.verdict`.
- **Bảng RQ9** (11): `tab.rq9.qwen7b.{A0,A1,A5}.{recall,fp}` + `.{delta,p}` cho A1/A5 + `tab.rq9.qwen7b.verdicts`.
- **Prose 05_results RQ8** (4): `rq8.granite2b.family_clause` (tổng hợp 4 family), `.pooled_clause`, `.verdict_clause`, `rq8.llama3b.verdict_clause` (×2 vị trí: 05 + bảng).
- **Prose 05_results RQ9** (6): `rq9.qwen7b.model_clause`, `.hr1_clause`, `.hr2_clause`, `.hr3_clause`, `.identity_clause` (×2 vị trí), và 3 token recall ladder dùng chung với bảng (đã đếm ở bảng).
- **Discussion/Threats** (5): `scope_update_discussion`, `rq8_cwe_scope_discussion`, `rq9_scale_discussion`, `threats_scale_round7`, `threats_cwe_round7` — S TỰ VIẾT theo đúng nhánh verdict (token map KHÔNG có các token này; quy tắc wording nằm ở prereg §2.3/§3.5/§0b).

Lưu ý: nếu llama3b (RQ8 secondary) không chạy, token `rq8.llama3b.*` không
xuất hiện trong token map → S thay câu đó bằng "not run (budget)" và xóa
dòng trong bảng; nếu qwen7b chạy thêm llama8b (không có trong kế hoạch), phải
có amendment mới trước đó.

## 5. [P4] Verify — lệnh + output thật

```bash
.venv/bin/python -m pytest tests/test_round7_master.py -q
#   → 26 passed
.venv/bin/python -m pytest tests/ -q
#   → 490 passed, 2 warnings in 71.59s   (baseline 443 của Vòng 6 vẫn pass;
#     tăng vì 24 test mới của tôi + các test mới của agent khác trong phiên:
#     tests/test_attack_v2_cwe.py của A1 v.v. — KHÔNG có test nào fail)
.venv/bin/python scripts/collect_master_round7.py            # → [pending]…, exit 0, không ghi file
.venv/bin/python scripts/collect_master_round7.py --verify-only  # → [pending]…, exit 0
.venv/bin/python paper/make_figures.py
#   → [skip] fig_round7: outputs/master/round7_master.json not present …
#   → [verify] all table numbers match source files
#   → [verify] round-5 table numbers …; 17 headline numbers cross-checked
#   → [cites] 18 keys used, all present in refs.bib; 7 figures (fig_round7 cố ý không sinh)
tectonic --outdir paper/compiled paper/main.tex   # → 0 error (grep '^error' = 0)
pdftotext paper/compiled/main.pdf …   # pages 18; '??' = 0; token {{R7:*}} render nguyên văn (45 hit);
#   TODO/PLACEHOLDER = 0
```

Bài học đã áp dụng từ A3-R6: MỌI token được bọc `\detokenize{...}` ngay từ
đầu (bản nháp đầu có 8 token trần chứa `_` → "Missing $ inserted" khi
compile; đã bọc lại trước khi chốt). Test fig_round7 skip/strict được đưa
vào `tests/test_round7_master.py` (import `make_figures` có guard skip nếu
repo thiếu nguồn).

## 6. Danh sách chỗ paper cần cập nhật KHI SỐ VỀ (handoff cho S-Vòng-7)

Ngoài 60 vị trí token (§4):
1. **Scope-claim "open 2--3B"** (chỉ khi có số RQ9, đúng nhánh):
   `00_abstract.tex` ("three open-weight 2--3B models"), `01_intro.tex:97`
   ("mechanism at 2--3B scale"), `02_related.tex:82` (frontier-question),
   `05_results.tex` RQ7 ("at 2--3B open-model scale" — giữ nguyên vì nói về
   R5, chỉ thêm cross-ref nếu cần), `06_discussion.tex` (§Blocking fears
   "at open 2--3B scale" + Threats "All models are open-weight 2--3B"),
   `07_conclusion.tex` (scope sentence), `tables/tab_round5.tex` caption
   ("at open 2--3B scale"). null ở qwen7b BẮT BUỘC kèm caveat family.
2. **CWE scope**: câu "verdict-bias channel" trong abstract/intro/discussion
   thêm mệnh đề theo verdict RQ8 (GENERALIZES / pooled-driven nêu family
   kéo / FAMILY-DEPENDENT — nếu label cuối là FAMILY-DEPENDENT thì discussion
   PHẢI nói rõ channel mới được chứng minh trên bench memory-copy-heavy).
3. `03_method.tex` (S, optional): 1–2 câu mô tả RQ8/RQ9 design + pointer
   prereg.
4. `04_setup.tex` (S): thêm qwen7b + bench_attack_v2 vào model/bench
   inventory (hiện chỉ có 3 model 2–3B + 0.5B smoke).
5. `appendix_repro.tex` (S): traceability thêm `round7_master.json` +
   `tab_round7` + `fig_round7` → collector; repro steps round-7; "N unit
   tests" sẽ stale (đang 490).
6. `docs/results_master_round7.md` (S): chưa tồn tại — cần một trang master
   như R5/R6 (collector đã in đủ số trong log; S tổng hợp).
7. Conclusion future-work: mục #2 (CWE families) và #3 (7B + C0×P3 control)
   của ROUND6_SUMMARY — #2/#3a được RQ8/RQ9 trả lời; **C0×P3 control vẫn
   chưa chạy** (khoảng trống giữ nguyên, đã ghi trong threats).
8. Sau khi điền: `make_figures.py` (fig_round7 tự sinh), tectonic,
   stale-scan (0 token `{{R7:`, 0 `??`), `collect_master_round7.py
   --verify-only` phải exit 0, pytest full.

## 7. Đã / không làm

Đã làm: prereg + Amendment-1; collector + token map + verify; 26 tests;
paper drafts (2 subsections + discussion slots + bảng khung + figure
fail-safe + wiring); verify chuỗi đầy đủ; báo cáo này.
Không làm (đúng phạm vi): KHÔNG chạy generation/GPU; KHÔNG build bench;
KHÔNG sửa `src/` (mọi thay đổi `src/conditions/c5_risk_context.py` trên
working tree là của A1 trong phiên song song); KHÔNG đụng
`configs/round7_7b.yaml` / `attack_v2_cwe.yaml` (của A2/A1); KHÔNG git
commit; KHÔNG tạo `outputs/master/round7_*` (chưa có data — đúng hợp đồng).

---
*Verification: pytest full 490 passed (0 failed); collector fail-safe exit 0
cả build lẫn --verify-only; make_figures PASS với fig_round7 skip đúng;
tectonic 0 error, 18 trang, 0 '??'; 55 token duy nhất / 60 vị trí render
nguyên văn. Không git commit.*
