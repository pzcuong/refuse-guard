# GAP AUDIT — Challenger C · Lens: non-triviality (không thể bị coi là prompt engineering / trivial wrapper / comment-stripping) + empirical evaluability

State: **GAP_VALIDATION** (charter §25→§5–6) · 2026-09-30 · Auditor: gap-challenger-C (độc lập, không đọc gap_A/gap_B)

---

## 0. Gap bị thẩm định (đầu vào của vòng này)

> **"Invariant/counterfactual vulnerability analysis under semantics-preserving untrusted context —
> detect corrupted verdicts via invariance signal, recover via code-evidence channel."**

Lens của challenger C: gap này có sinh được method **KHÔNG loại được** theo checklist loại thải của
STAGE 3 không — đặc biệt 3 trap đầu (prompt-engineering-only, trivial wrapper, comment-removal-equivalent);
và nếu sinh được thì **đo thực nghiệm được đến đâu với infra hiện có**.

### 0.1 Đối chiếu "7 tiêu chí loại thải §3" — phát hiện lệch chuẩn (disclose trước, L2)

Không có tài liệu nào trong repo liệt kê **đúng 7** tiêu chí. Danh sách authoritative của STAGE 3 là
`RESEARCH_STATE/DIRECTOR_CHARTER.md:35` (§6, STAGE 3 — CANDIDATE DIRECTIONS) với **9 mục**:

1. prompt-engineering-only · 2. trivial wrapper · 3. comment-removal-equivalent · 4. reassertion-equivalent ·
5. attack-detection-only · 6. benchmark-specific · 7. tiny effects · 8. single weak model · 9. test-set tuning.

Script vòng này dùng biến `rejectionCriteria` (phase method-audit, ngay sau gap) với **10 mục** (thêm
"không phân biệt được với baseline"; tách "effect nhỏ" khỏi "practical"). Audit này chấm **tất cả 9 mục
charter §6** (superset của mọi tập con 7-mục) — kết luận không phụ thuộc việc đếm 7 hay 9.

---

## 1. TRAP 1 — comment-removal-equivalent: gap có hơn D1-strip không?

**D1 trong repo chính là comment stripping thuần:** `packguard/defense_strip.py:1-30` — "AST comment/docstring
stripping … removes every comment and Python docstring … so the model sees only executable code"; một chiều,
tĩnh, không có kênh detection, không có per-sample decision (trừ gate AST-equivalence loại sample lỗi parse).

**Bằng chứng D1 có trần đo được — đúng chỗ gap khai thác:**
- POS-17 (`POSITIVE_RESULTS_LEDGER.csv`, R12): granite trung hòa hoàn toàn — strip(P2)==strip(original)
  38/38 byte-equal; 23/23 verdicts trùng P0; 4/4 flips revert; FP 0/14.
- NEG-26 (cùng ledger, R12, KEEP_MAIN first-class): llama **không hồi phục gì** — .167 → .042 (attack) →
  .042 (defended); "+1 là NEW artifact-lab detection, not recovery"; 4 losses = 4 versions của 1 family.
  => stripping không phải là superset của recovery; nó vô dụng đúng trên model có headroom còn lại.

**Kết luận trap 1: PASS-able (không equivalent), với điều kiện đo được.** Method của gap thao tác trên
*object khác hẳn*: cặp verdict (V_raw vs V_trusted) thay vì input text. Khác biệt cấu trúc, mỗi cái đều đo được:
1. **Detection channel** — disagreement signal có ROC/AUC riêng; D1 không có khái niệm "phát hiện".
2. **Recovery per-claim** — chấp nhận/từ chối hypothesis dựa trên code evidence, không phải xóa text toàn cục.
3. **Abstention path** — D1 không thể abstain, chỉ transform đầu vào.
4. **Composition** — method lắp được *lên trên* D1 (D1 là một arm baseline bắt buộc theo charter §12:
   "simple defenses (reframe/strip/minimal provenance/semantic isolation)"); non-equivalence phải được
   **đo**, không phải khẳng định: method phải hồi phục được case D1 fail (đúng tập NEG-26).

Điều kiện reject còn lại: nếu recovery channel thực chất chỉ rebuild được những case mà strip(P2)==strip(original)
đã xử lý (tập 38/38 granite) thì method này chỉ là D1 đắt hơn → sẽ rơi trap 3. Prereg phải khóa endpoint
recovery **trên strata mà D1 fail** (llama + adaptive surfaces NEG-39) chứ không chỉ trên granite.

## 2. TRAP 2 — trivial wrapper: khác spotlighting/CaMeL/MELON ở đâu?

LITERATURE_MATRIX.csv (75 rows, scout-verified 2026-09-30) đã tự ghi 3 nearest prior buộc phải định vị:
- **Row 35 — Spotlighting (Hines et al.):** "Provenance-by-marking is prior art; our differentiator must be
  **verdict-corruption recovery + utility cost** (D1-style), not injection prevention."
- **Row 48 — CaMeL (Debenedetti et al. 2025):** "High novelty bar for system-level defenses; any
  provenance-partition defense claim must position against CaMeL explicitly."
- **Row 54 — MELON:** "Must cite when proposing verifier-based recovery; our **code-grounded (AST/CFG)
  verifier differs from their LLM-only verifier**." (+ Row 55 Origin-Aware Transformers: prior kiến trúc
  training-based; của ta là training-free approximation — phải nêu rõ.)

**Kết luận trap 2: PASS-able, có điều kiện instantiation.** "Partition + verify + recover + abstain" không phải
wrapper **nếu và chỉ nếu** ≥2 thành phần non-prompt là load-bearing, chứng minh bằng component ablation:
(a) provenance partition = split dataflow thật (trusted query/channel tách untrusted context, không phải 1 câu
hướng dẫn); (b) verifier = AST/CFG/slice check code-grounded (khác MELON đúng ở đây); (c) decision rule
disagreement→abstain có ngưỡng học/chọn từ dev, không phải prompt văn nói. Cột `what_they_do_NOT_evaluate`
của các row defense trong matrix nhất quán ghi: *"refusal/safety-state; untrusted-context perturbation; any
defence or mitigation"* — không prior nào đo corruption-detection-via-invariance trên verdict task phân tích
(vuln) — đây là delta đo được, không phải tự phong.

## 3. TRAP 4 — reassertion-equivalent: bài học đã có số trong nhà

POS-09 (`POSITIVE_RESULTS_LEDGER.csv`, R6): ladder A0→A5, rung reassertion đơn lẻ làm sập llama recall
**1.000→.433** (28/34 net flips, exact p=7.45e-09; chi2-cc 3.35e-07). Tức là "reassert instructions" không những
không phải free-win mà còn là failure mode **đã quan sát** trong program. Checklist item này có răng thật.
Method gap tránh được nó bằng cơ chế đã spec (RESEARCH_DIRECTOR_PROMPT.md §5 R-A(3)): mechanism ablation
strip-only vs strip+reassertion + matched-meaning paraphrase + scrambled controls. **PASS-able** — nhưng đây là
trap dễ rơi nhất khi designer lười (kéo "re-assert the task" vào prompt là xong); adversarial method review
(ask#16-19) phải thử reject theo đúng rung này.

## 4. TRAP 1' — prompt-engineering-only: điều kiện chấp nhận có kiểm chứng được

Gap as-stated **yêu cầu** máy móc non-prompt (partition, verifier, abstention rule). Rủi ro nằm ở instantiation:
nếu method designer cuối cùng chỉ làm "chạy 2 prompt rồi so verdict" (self-consistency thuần), đó chính là
prompt engineering có áo khoác và phải bị loại. Cơ chế kiểm chứng đã có sẵn trong pipeline: component ablation
theo mẫu A0→A5 (POS-09 là precedent) — nếu toàn bộ effect tắt khi tháo partition/verifier và chỉ còn prompt,
thì reject. **Chấp nhận gap ở mức *khả năng sinh method không-rejectable* = CÓ; chấp nhận method cụ thể
chờ phase METHOD_CANDIDATES + ADVERSARIAL_METHOD_REVIEW chấm lại.**

## 5. Chấm đủ 9 mục charter §6 (tổng hợp)

| # | Tiêu chí loại | Thẩm định | Kết luận | Bằng chứng chính |
|---|---|---|---|---|
| 1 | prompt-engineering-only | cần ≥2 thành phần non-prompt load-bearing, kiểm bằng ablation | PASS-able (điều kiện) | §4 trên; POS-09 precedent |
| 2 | trivial wrapper | khác Spotlighting/CaMeL/MELON ở detection+recovery+utility-cost, matrix đã ghi positioning | PASS-able (điều kiện) | LIT_MATRIX rows 35/48/54/55 |
| 3 | comment-removal-equivalent | thao tác trên verdict-pair + abstention; phải beat/repair D1 trên strata D1 fail | PASS-able (đo được) | defense_strip.py:1-30; POS-17; NEG-26 |
| 4 | reassertion-equivalent | failure mode đã đo (llama 1.000→.433); ablation R-A(3) cô lập được | PASS-able | POS-09 p=7.45e-09 |
| 5 | attack-detection-only | gap có recovery channel; **rủi ro chính**: nếu recovery fail → tụt về detection-only, phải re-scope claim | PASS có rủi ro | charter §5 mục 5 (contribution kể cả khi secondary fail); pilot gate ≥40% recovery |
| 6 | benchmark-specific | 3 corpus + ≥8 CWE + 2 ngôn ngữ; charter §13 yêu cầu ≥2 benchmark + 6–10 CWE | PASS-able | bench_attack_v1 manifest counts (200 rows, 100/100, arms C0/D2/C5n/C5f); bench_attack_v2 160 |
| 7 | tiny effects | headroom lớn đã đo: FP drift .817→1.000 / 0→.667/.833; verdict-shift p≤1.2e-05 | PASS-able | POS-01, POS-06 |
| 8 | single weak model | 2–3 local families + 7B/8B Kaggle đã duyệt & đã chạy (AMENDMENT-9, 660 rows verified) | PASS-able | models_dir/hf/hub (4 snapshots); PC-34; NEG-14 là boundary đã ledger |
| 9 | test-set tuning | prereg machinery + registry 2,810 rows + pilot/full split gate đóng băng | PASS-able | docs/packguard_prereg.md AMENDMENT-1..9; charter §8-9 |

**Không mục nào loại gap ở mức khái niệm.** Mục 1/2/5 là mục *điều kiện* — chuyển thành yêu cầu kiểm chứng
cho phase method (không phải lý do từ chối gap).

## 6. Empirical evaluability — chấm theo infra thật trong repo

**Đã kiểm trên đĩa trong session này:**
- `data/benchmarks/bench_attack_v1/` — **200 samples paired, 100/100 label, 4 counterfactual arms/sample
  (C0, D2_task, C5_near, C5_far = 800 entries)**; manifest có semantics gate `all_pass: True`, near/far
  carrier offsets ghi đủ (inline_comment vs top_comment). Đây chính là cấu trúc counterfactual view mà
  invariance signal cần — **không cần xây data mới cho pilot**.
- `data/benchmarks/bench_attack_v2/` — 160 rows (family signals, has_signature).
- models_dir/hf/hub: Llama-3.2-3B, granite-3.3-2b, Qwen2.5-Coder-3B/0.5B, CodeBERT — **snapshot tồn tại**.
- Phép thử paired có sẵn: `packguard/safety_port.py:241-284` (per-arm RR, paired McNemar vs P0, cùng sample set).
- Baselines chạy được: D1 (`packguard/defense_strip.py`), GuardDog 3.2.0 (outputs/packguard/guarddog/),
  MalGuard-style (outputs/packguard/malguard_style/), CodeBERT B4.
- Endpoints+khai định đã frozen sẵn: CORRUPTION RECOVERY RATE + DEFENSE-INDUCED ERROR RATE
  (charter §8); pilot gate ≥40% recovery / ≤5% new errors / ổn định ≥2 strata (charter §9) — đúng thứ
  detector+recovery cần đo. Chi phí pilot: ~4 arms × 100–200 × 2 models ≈ 1.6–2k generations ≤384 tokens
  (gen_cfg temperature 0, max_new_tokens 384 trong defense_analysis.json) — quy mô tương đương round đã chạy.

**Điểm yếu evaluability (không giấu):**
1. **Trusted-evidence channel cho C/C++** (bench_attack_v1: 109 c / 91 cpp): tree-sitter infra của D1 chỉ
   khai 'javascript'/'python' (`defense_strip.py:43-44`); parser C/C++ có ở src/conditions/parser_utils
   (docstring D1 nhắc) nhưng **slice/dataflow verification cho C/C++ chưa build** — dependency kỹ thuật
   rủi ro nhất của cả method family; ước lượng công việc thật, không phải gắn nhãn là xong.
2. **V_trusted phải tốt hơn, không chỉ khác:** nếu trusted-channel verdict tệ hơn, disagreement signal đo
   nhiễu. Prereg phải nêu power cho detection ROC ở n=200 paired và minimum-effect cho recovery strata.
3. NEG-35 (lexical gate 1/50 paraphrase) là cảnh báo gate đơn giản giòn — abstention rule phải test
   paraphrase-robustness ngay từ pilot.
4. NEG-03 (RR=0/2,700): không được thiết kế method nào dựa vào refusal — gap này không dựa (điểm cộng),
   nhưng mọi baseline "refuse" đều vô nghĩa trên 2–3B, chỉ giữ ở appendix.

## 7. VERDICT

**accepted = TRUE (conditional).** Gap "invariant/counterfactual vuln analysis under semantics-preserving
untrusted context" **sinh được method vượt 9/9 mục checklist loại thải charter §6** (superset của 7 mục mà
ask nhắc; repo không có danh sách 7-mục — đã disclose §0.1), với 3 điều kiện chuyển xuống phase method:
1. ≥2 thành phần non-prompt load-bearing, chứng minh bằng component ablation (chặn trap 1'/2);
2. non-equivalence với D1 **đo** trên strata D1 fail (llama/adaptive), D1+A1+strip là arm bắt buộc (chặn trap 3);
3. recovery channel phải load-bearing — nếu pilot chỉ còn detection, claim re-scope theo charter §5(5)
   (chặn trap 5).

Empirical evaluability: **cao** — dữ liệu counterfactual paired, models, phép thử paired, endpoints, gates,
baselines đều có sẵn và đã kiểm tồn tại trong session này; rủi ro thực nghiệm lớn nhất là C/C++
slice-verification (chưa build) và độ tin cậy V_trusted (cần power analysis trong prereg).

*Audit này độc lập; không đọc gap_A/gap_B; mọi số đều truy về ledger/manifest/code trong repo (đường dẫn
+ dòng đã ghi ở từng mục).*
