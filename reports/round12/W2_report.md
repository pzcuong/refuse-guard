# W2 Report — Round 12 (ANALYSIS TOOLING + PAPER INTEGRATION PREP)

Ngày: 2026-09-28 (UTC 2026-09-27T19:00Z). Vai trò: Tác nhân W2 vòng 12 — góc
analysis tooling + paper integration prep (CPU only, KHÔNG GPU, KHÔNG đụng
W1). Nguyên tắc: KHÔNG bịa số — file `defense_batch.jsonl` của W1 CHƯA có tại
thời điểm đóng báo cáo (đã poll đúng giới hạn 2 lần), nên output phân tích
thật là trạng thái **PENDING** (pre-reg §Eval: "pending, never fabricated");
mọi số trong phiên này là MOCK có cờ, tách biệt hoàn toàn.

Không gian sửa (đúng quyền): `scripts/r12_defense_analysis.py` (mới),
`tests/test_r12_analysis.py` (mới), `paper2/main.tex` (CHỈ §sec:safety mở
tangible + 1 subsection mới + 1 câu abstract + 1 câu conclusion, placeholder
`{{R12:*}}` bọc `\detokenize`), `reports/round12/W2_report.md` (file này).
KHÔNG git commit. Đã đọc-only `packguard/defense_strip.py` +
`scripts/r12_attack_defense.py` của W1 để đồng bộ contract (không sửa).

---

## 1. LÀM GÌ (6 mục chuẩn — mục này là tổng quan)

- **[A1] Script phân tích** `scripts/r12_defense_analysis.py`: đọc
  `outputs/packguard/defense/defense_batch.jsonl` (W1) → bảng
  recall(P0 → P2_nodef → P2+D1) per model + McNemar exact paired cho 2 cặp
  đã đăng ký (P2_nodef vs P2+D1; P0 vs P2+D1) trên 2 subset (malicious =
  recall; benign = FP) + flips HAI hướng (restore-gain 0→1, restore-loss
  1→0, không gộp chung) + FP benign per arm + RR + Wilcoxon confidence
  (secondary, DESCRIPTIVE) + scope pooled (kèm caveat). Fail-safe: input
  chưa có → ghi JSON `status: pending`, exit 0, không bịa; input có nhưng
  sai format / thiếu arm → FAIL LOUD.
- **[A2] Paper draft**: subsection mới `\subsection{Can sanitization
  neutralize the channel?}\label{sec:safety-defense}` cuối §sec:safety
  (định nghĩa D1 + AST-equivalence gate + H-D1/H-D2 hai chiều từ
  AMENDMENT-6 + bảng `tab:safety-defense` + câu kết quả placeholder), 1 câu
  abstract, 1 câu conclusion — tất cả số là placeholder `{{R12:*}}` bọc
  `\detokenize`. Tectonic XANH (exit 0), `gen_paper_numbers.py --check`
  XANH (336 macro).
- **[A3] ChatGPT consult: BỊ CHẶN** (MCP not_authenticated — cần login thủ
  công, đúng vấn đề đã ghi trong roadmap round-6). Nguyên văn lỗi + prompt
  đã soạn sẵn lưu tại §5 để chạy lại khi MCP hồi phục. KHÔNG bịa ý kiến.
- **[A4] Tests** `tests/test_r12_analysis.py`: 17 test PASS — mọi thống kê
  pin bằng tay trên fixture (recall, flips hai hướng, McNemar exact p=1.0,
  FP, restoration delta, pending/fail-loud, mock/real path hygiene, contract
  nhãn arm của W1 `P2D1_strip`).
- **[A5] Báo cáo này + handoff cho F** (§6): danh mục 37 placeholder token ↔
  đường dẫn JSON, quy trình điền số khi W1 xong.

## 2. FILES (tạo / sửa)

| File | Loại | Nội dung |
|---|---|---|
| `scripts/r12_defense_analysis.py` | MỚI (W2) | A1: analysis CLI (`--mock`, `--input`, `--out`); fail-safe pending; mock hygiene |
| `tests/test_r12_analysis.py` | MỚI (W2) | A4: 17 test, số tính tay |
| `paper2/main.tex` | SỬA (W2, phạm vi hẹp) | §4.2: subsection `sec:safety-defense` + bảng `tab:safety-defense`; abstract +1 câu; conclusion +1 câu; mọi số = `\detokenize{{{R12:*}}}` |
| `outputs/packguard/defense/defense_analysis.json` | MỚI (output) | **PENDING marker** (không số) — ghi lại lúc poll |
| `outputs/packguard/defense/defense_analysis_mock.json` | MỚI (output MOCK) | Kết quả fixture, `mock: true`, tên file `_mock` — KHÔNG bao giờ là số thật |
| `reports/round12/W2_report.md` | MỚI (W2) | file này |

Không đụng: `packguard/` (W1 đã thêm `defense_strip.py` — đọc-only),
`scripts/r12_attack_defense*` (W1), `outputs/packguard/defense/defense_batch.jsonl`
(W1, chưa tồn tại), `docs/packguard_prereg.md` (W1 đã append AMENDMENT-6 —
đọc-only, được trích dẫn trong paper).

## 3. CÁCH CHẲY

```bash
cd /Users/macbook/.zcode/workspace/default/refuseguard

# A1 — khi W1 xong (hiện tại: PENDING, không số):
.venv/bin/python scripts/r12_defense_analysis.py
#   → outputs/packguard/defense/defense_analysis.json (status ok|pending)

# A1 — self-test fixture (MOCK, có cờ, ghi ra *_mock.json):
.venv/bin/python scripts/r12_defense_analysis.py --mock

# A4 — tests:
.venv/bin/python -m pytest tests/test_r12_analysis.py -q     # 17 passed

# A2 — compile + number-pipeline check:
cd paper2 && tectonic main.tex                                # exit 0
cd .. && .venv/bin/python scripts/gen_paper_numbers.py --check
#   → "GEN-NUMBERS CHECK: OK -- 336 macros verified"
```

## 4. THIẾT KẾ + ĐỒNG BỘ CONTRACT VỚI W1 (đọc-only)

- **Arms**: chuẩn hóa mềm (`normalize_arm`) — `P0_neutral`→P0;
  `P2_advisory_in_package`/`*nodef*`→`P2_nodef`; nhãn thật của runner W1
  `DEFENDED_ARM = "P2D1_strip"`→`P2_D1` (test pin contract này). Arm lạ →
  đếm + disclose trong `unknown_arm_rows_ignored`; THIẾU arm đăng ký →
  fail-loud (không phân tích một phần).
- **Verdict**: chỉ nhận khi record parsed + status != REFUSAL (refusal
  KHÔNG BAO GIỜ map thành benign/malicious — prereg §Safety); PARTIAL tính
  parsed theo tiêu chí round-10. Pair có 1 vế unparsed → drop khỏi test,
  đếm riêng `n_pairs_dropped_unparsed_or_refusal`.
- **Nhãn**: field `label` trong record, fallback join
  `outputs/packguard/features/features_v2.jsonl` (id→label); không tìm thấy
  → fail-loud (không đoán).
- **Exclusions (gate FAIL của W1)**: sample chỉ có ở 1 arm được đếm
  `n_samples_only_in_a/b` — không nhồi lặng vào mẫu số (A6.1: "excluded and
  disclosed").
- **Hai hướng (AMENDMENT-6 A6.3)**: `flips_a0_b1` (restore-gain) và
  `flips_a1_b0` (restore-loss) đều được tính và đều được báo;
  `restoration.defense_restoration_recall` = recall(P2+D1) − recall(P2_nodef)
  kèm `attack_effect_recall` = recall(P2_nodef) − recall(P0).
- **Thống kê**: McNemar exact bắt buộc (`src/metrics/stats.mcnemar,
  exact=True`, method statsmodels.exact — khuyến nghị follow-up r6 của
  roadmap) trên detection booleans (malicious) VÀ FP booleans (benign) cho
  cả 2 cặp đăng ký. Wilcoxon signed-rank trên paired confidence =
  SECONDARY DESCRIPTIVE (gắn nhãn trong output; unavailable khi thiếu
  confidence — ghi reason, không ăn vạ).
- **Pooled**: có block `pooled` cho câu headline, kèm caveat riêng (bài học
  n=100: pooled che chuyển động ngược chiều per-model — bảng per-model là
  chính).

## 5. [A3] CHATGPT CONSULT — BỊ CHẶN (nguyên văn)

5 lần gọi `mcp__chatgpt-web__chatgpt_ask` (2 lần nội dung đầy đủ,
timeout_seconds 420) → lỗi transport `Tool execution timed out after
30000ms`; `chatgpt_session_status` và 2 lần `chatgpt_login` (120s, 300s) →
nguyên văn lỗi:

```
chatgpt-web error (not_authenticated): ChatGPT page did not show a composer. Run chatgpt_login first.
```

Đúng blocker đã ghi trong roadmap (round-6 note: "ChatGPT-MCP
not_authenticated — cần login thủ công"). Không có người ở browser để đăng
nhập trong phiên này → consult KHÔNG thực hiện được; KHÔNG tự bịa ý kiến
"ChatGPT". Ý kiến tư vấn trong báo cáo này (nếu có) = không có.

**Prompt đã soạn sẵn** (chạy lại nguyên văn khi MCP hồi phục — new_chat=true,
timeout 420s; đây là ý kiến framing, KHÔNG phải nguồn số):

> You are a harsh Q1 reviewer (top security venue). Critique this
> attack-defense design from a pilot paper on LLM-assisted
> malicious-package detection. Be harsh and specific: is the attack-defense
> pairing SUFFICIENT for the headline claim, and what is missing?
>
> CONTEXT (pilot; only 2 small open models: Llama-3.2-3B-Instruct,
> granite-3.3-2b-instruct; temperature 0; local):
> - 603 real npm/PyPI packages (390 malicious wild-capture, 213
>   popularity-derived benign); separate ML detector on behavior graphs
>   (F1 ~.85-.9). The safety arms use the LLM directly as analyzer.
> - Prior measurement (n=100 real packages, 50/50, per model): "advisory
>   attack" P2 = benign-looking security advisory comment injected into the
>   package file (comment-only change, tree-sitter AST-equivalence gated).
>   No refusals (RR=0), but malicious recall PERTURBS model-dependently:
>   granite-3.3-2B .54->.82 UP; Llama-3.2-3B .16->.06 DOWN. Benign FP ~0
>   (2/100 granite at P2).
> - Registered defense D1: strip all comments + Python docstrings before
>   analysis. Gate: stripped file must re-parse to a canonical AST
>   signature identical to the original (signature prunes exactly comment
>   nodes and docstring-positioned bare strings); gate FAIL -> sample
>   excluded, disclosed. Line-aware removal: a prepended one-line advisory
>   strips back to the BYTE-IDENTICAL original.
> - Registered round-12 pairing (pre-registered before any generation):
>   n=30 malicious + n=15 benign gate-passers of the same seeded draw.
>   Arms: P0 neutral (verified cache hit), P2 no-defense (verified cache
>   hit), P2+D1 = advisory injected then stripped then analyzed (new,
>   45x2 models = 90 generations). Where the strip is clean, the P2+D1
>   prompt is byte-identical to the P0 prompt (asserted per sample) =
>   faithful "attack removed" condition, not a rephrasing.
> - Registered hypotheses (both directions locked): H-D1 restoration =
>   recall(P2+D1) >= recall(P0)-0.05 on >=1 of 2 models; H-D2
>   neutralization = |recall(P2+D1)-recall(P0)| <= 0.10 on >=1 of 2 models;
>   per-model pass/fail reported either way; defense-cost check = does
>   stripping LOSE the extra detections the attack caused (for the model
>   whose recall went UP under attack)?
> - Metrics: recall per arm per model on the n=30 subset (recomputed there,
>   not the n=100 headline); exact paired McNemar (P2 vs P2+D1; P0 vs
>   P2+D1); restore-gain (0->1) and restore-loss (1->0) flips both
>   reported; benign FP per arm (n=15); refusal rate reported (~0 expected;
>   never mapped to verdict); secondary descriptive Wilcoxon over paired
>   confidences.
>
> HEADLINE CLAIM wanted: "an input-sanitization defense (AST-gated
> comment/docstring strip) measurably neutralizes (or fails to - whatever
> the data says) the advisory-in-package attack channel, for at least one
> of the two models."
>
> QUESTIONS: (1) Is this pairing sufficient for that headline claim at Q1
> level; if not, what exactly is missing? (2) Rank the top 3-5 weaknesses a
> harsh reviewer would raise. (3) Minimal pilot-feasible additions
> (CPU-only or small local inference) that would most raise credibility?
> (4) Is the "byte-identical prompt to P0 after strip" argument persuasive,
> or does it hide a confound? Answer concisely and concretely.

## 6. HANDOFF CHO F — ĐIỀN {{R12:*}} KHI W1 XONG

Quy trình: (1) chờ `outputs/packguard/defense/defense_batch.jsonl` của W1;
(2) chạy `.venv/bin/python scripts/r12_defense_analysis.py` →
`outputs/packguard/defense/defense_analysis.json` (`status:"ok"`); (3) thay
mỗi token `\detokenize{{{R12:TOKEN}}}` trong `paper2/main.tex` bằng giá trị
tại đường dẫn JSON tương ứng (định dạng 3 chữ số bỏ số 0 đầu, nhất quán
`tab:safety`); (4) theo AMENDMENT-6 A6.4, câu result PHẢI nêu pass/fail
H-D1/H-D2 per model và defense-cost check; (5) nếu hướng kết quả là âm
(defense KHÔNG khôi phục), chỉnh động từ framing ở câu abstract/conclusion
(skeleton đã để trung tính hướng); (6) compile lại tectonic +
`gen_paper_numbers.py --check`.

Bảng token ↔ nguồn (M = model key trong `per_model`, ví dụ
`unsloth/Llama-3.2-3B-Instruct`; `P2N__vs__P2D1` =
`comparisons.P2_nodef__vs__P2_D1`; `P0__vs__P2D1` =
`comparisons.P0_neutral__vs__P2_D1`):

| Token | Đường dẫn trong defense_analysis.json |
|---|---|
| `R12:NPAIRS` | `pooled.comparisons.P2N__vs__P2D1.malicious.n_pairs` (điên giải "X paired real packages", ví dụ "60 (30 mal + 15 ben × 2 models)") |
| `R12:STATUS` | `status` + ghi chú mock=false, thời điểm phân tích |
| `R12:POOLED_REC_P0 / _P2 / _D1` | `pooled.restoration.recall_P0 / recall_P2_nodef / recall_P2_D1` |
| `R12:POOLED_GAIN / _LOSS` | `pooled.restoration.restore_gain_flips / restore_loss_flips` |
| `R12:P_NODEF_VS_D1` | `pooled.comparisons.P2N__vs__P2D1.malicious.mcnemar_exact.p_value` |
| `R12:P_P0_VS_D1` | `pooled.comparisons.P0__vs__P2D1.malicious.mcnemar_exact.p_value` |
| `R12:FP_P2 / FP_D1` | `pooled.arms.P2_nodef.benign_fp_count` / `pooled.arms.P2_D1.benign_fp_count` (ghi "x/15" theo `benign_n_parsed`) |
| `R12:LL_*` | `per_model["unsloth/Llama-3.2-3B-Instruct"].arms...recall_*`, `.restoration.restore_gain/loss_flips`, `comparisons.P2N__vs__P2D1.malicious.mcnemar_exact.p_value`, `.arms.P2_nodef/P2_D1.benign_fp_count` |
| `R12:GR_*` | như LL_* nhưng `per_model["ibm-granite/granite-3.3-2b-instruct"]` |
| `R12:TABLE_NOTE` | tự viết: "n=30 malicious + 15 benign gate-passers (seeded draw); P0/P2 verified cache hits; gate-FAIL exclusions: <`n_samples_only_in_*`>" |
| `R12:ABS_REC_P2 / _D1`, `R12:ABS_P` | pooled recall P2 / P2+D1, pooled McNemar p (P2 vs P2+D1) |
| `R12:ABS_CLAUSE`, `R12:CONC_CLAUSE` | F tự viết MỘT mệnh đề theo hướng đo được (vd "restoring k of the m detections the attack removed" hoặc "leaving the attack's harm intact — the strip also removes the cue granite was using"); kèm pass/fail H-D1/H-D2 nếu gọn |
| `R12:CONC_REC_P2 / _D1`, `R12:CONC_P`, `R12:CONC_FP` | như ABS_*; CONC_FP = benign FP attack→defended |

Lưu ý cho F:
- Nếu `status:"pending"` còn nguyên nghĩa W1 CHƯA xong — KHÔNG điền gì, giữ
  placeholder (compile vẫn xanh).
- Bảng per-model của paper hard-code 2 hàng (llama, granite) theo A6.2;
  nếu W1 chạy khác model, F sửa hàng cho khớp.
- `paper2/sections/` KHÔNG tồn tại trong repo hiện tại — paper là
  `paper2/main.tex` đơn khối; mọi sửa của W2 nằm trong main.tex đúng vùng
  `sec:safety` (+2 câu). Đã disclose ở mục 7.

## 7. LỆCH CHUẨN / DEVIATIONS

1. **Đường dẫn quyền sở hữu**: brief giao `paper2/sections/` — thư mục này
   không tồn tại; phần safety nằm trong `paper2/main.tex`. Đã sửa thẳng
   main.tex trong phạm vi cho phép (chỉ §sec:safety + abstract + conclusion).
2. **`safety_metrics_n100.json`**: brief dẫn
   `outputs/packguard/safety/safety_metrics_n100.json` — file thật nằm ở
   `outputs/packguard/r10/r8_safety_expand/safety_metrics_n100.json`
   (đúng như `% SRC` của main.tex). Đã đọc file đúng vị trí.
3. **A3 bị chặn** (not_authenticated) — xem §5; không bịa.
4. **Poll W1**: đúng 2 lần trong phiên (recon đầu phiên ~01:47 UTC+7 và
   poll 2 ~01:50): `defense_batch.jsonl` chưa có cả 2 lần; lần 2 thấy
   `packguard/defense_strip.py` + `scripts/r12_attack_defense.py` của W1
   đã xuất hiện (W1 đang chạy) → analysis giữ PENDING. Không chạy "analysis
   thật" vì không có dữ liệu thật — đúng quy tắc không bịa.
5. **Wilcoxon**: brief ghi "McNemar/Wilcoxon" — Wilcoxon chỉ khả dụng trên
   paired confidence (trên verdict booleans nó suy biến); đã triển khai như
   secondary DESCRIPTIVE có nhãn + reason khi unavailable, không dùng làm
   claim chính (nhất quán A3.2: descriptive-only cần định lượng phụ).

## 8. TODO (cho orchestrator / vòng sau)

1. **F**: điền `{{R12:*}}` theo §6 khi `defense_batch.jsonl` + analysis
   `status:"ok"`; chỉnh framing clause theo hướng thật; compile + check.
2. **Orchestrator/W1**: khi batch xong, nhắc W1 xuất cả
   `defense_metrics.json` (A6.5) — analysis của W2 độc lập và có thể
   cross-check với nó (đặc biệt recall per arm per model trên subset n=30/15).
3. **ChatGPT consult**: chạy lại prompt §5 khi MCP đã login (framing-only,
   không phải nguồn số).
4. **Tuỳ chọn vòng sau**: thêm macro cho `{{R12:*}}` vào
   `gen_paper_numbers.py` (nguồn: `defense_analysis.json`) để vào cơ chế
   `--check` chuẩn của dự án — cần quyết định của orchestrator vì đụng file
   chung (ngoài quyền W2 vòng này).

## 9. SELF-TEST THẬT (đã chạy, nguyên văn output)

```
$ .venv/bin/python scripts/r12_defense_analysis.py --mock
[MOCK] wrote .../outputs/packguard/defense/defense_analysis_mock.json
[MOCK] recall P0=0.6667 P2_nodef=0.3333 P2_D1=0.5000
[MOCK] restore_gain=1 restore_loss=0
  (khớp tính tay: P0 4/6, P2 2/6, P2+D1 3/6; gain=m3 0→1; FP b1 1→0)

$ .venv/bin/python scripts/r12_defense_analysis.py
PENDING: .../outputs/packguard/defense/defense_batch.jsonl not found; wrote pending marker to .../defense_analysis.json   (exit 0)

$ .venv/bin/python -m pytest tests/test_r12_analysis.py -q
.................  [100%]  17 passed in 0.71s

$ .venv/bin/python -m pytest tests/ -q
704 passed, 8 warnings in 80.63s   (baseline round-11: 675/0; +17 của W2,
 +12 của W1 test_packguard_defense.py — 0 failed)

$ cd paper2 && tectonic main.tex ; echo $?
0     (main.pdf 175.07 KiB; chỉ underfull-box warnings, 0 error)

$ .venv/bin/python scripts/gen_paper_numbers.py --check
GEN-NUMBERS CHECK: OK -- 336 macros verified against artifacts (640 grid rows, 20 seeds).
```

Kiểm tra placeholder: 37 token `{{R12:*}}` (37 occurrence / 32 dòng) trong
main.tex, tất cả bọc `\detokenize` — liệt kê trong §6.

---

*W2 round 12: không git commit, không GPU, không đụng không gian W1, không
bịa số. Mọi số hiện diện trong paper ở vùng sửa là placeholder có cờ
R12 — compile xanh với placeholder là thiết kế chủ đích.*
