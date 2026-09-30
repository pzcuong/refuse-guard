# ROUND-18 DESIGN REVIEW (W2) — EVIDA-2 / PRUNE-1 — INDEPENDENT DESIGN REVIEW + STATS VALIDATION

Tác nhân: W2 (Vòng 18). Ngày review: 2026-09-30 (trước/trong khi W1 chạy).
Đối tượng: `docs/packguard_prereg.md` **AMENDMENT-11** (round 18, agent W1 —
EVIDA-2 alarm-pruning validation; ghi chú đánh số: directive gọi "AMENDMENT-10"
nhưng slot đó đã bị prereg Vòng-17 chiếm → W1 dùng AMENDMENT-11, ĐÚNG và có
nói rõ), `packguard/evida2.py`, `configs/packguard_evida2.yaml`,
`outputs/packguard/evida2/r17_alarm_log_analysis.json`.

Phương pháp: KHÔNG tin report — tự tính lại từ raw
(`outputs/experiments/round17_evida/evida_decisions.json` + `evida_units.json`)
bằng script độc lập `scripts/r18_stats_validate.py` (không import
`research_program/` hay `src/metrics/` — Clopper-Pearson tự viết từ math.comb +
beta-CF, đối chiếu khớp statsmodels đến 1e-15; exact McNemar discordant-only
đối chiếu bảng giá trị nổi tiếng). Không đụng file của W1. Không git commit.

---

## VERDICT TỔNG: **APPROVED-RUN với 4 lưu ý bắt buộc khi báo cáo** (chi tiết §D1-a…d)

Không phát hiện label leakage, không phát hiện gate-gaming đủ nặng để chặn run.
Điểm yếu lớn nhất của thiết kế là **(c) held-out chỉ còn nghĩa pipeline-level,
không sample-disjoint** — W1 đã disclose đúng và không claim sai; nhưng cách
diễn đạt "held-out" trong paper/báo cáo PHẢI theo câu chữ §D1-c dưới đây.

---

## D1-a — Pruning rule CHỈ dùng thông tin available-at-alarm-time? **PASS**

- **Quy tắc đã đăng ký (PRUNE-1, A11.1)**: giữ alarm ⟺ (1) strip đổi prompt
  (so sánh sha16) VÀ (2) hướng flip (V_raw, V_strip) = (1→0). Inputs = {raw
  verdict, strip verdict, prompt-identity} — **không có y_true, không family,
  không clean-reference** trong signature.
- **Kiểm code thật** (`packguard/evida2.py::run_pruning_rule`, dòng 189–206):
  hàm thuần nhận đúng 3 tham số `(raw_y, strip_y, strip_changed)`; **không tồn
  tại parameter nào để leak label**; `strip_changed` resolve từ cờ
  `reuse_raw_verdict` (prompt byte-identical → cưỡng chế final := raw, đúng
  registered reuse policy, không regenerate). Adjudicator gọi với
  `family_hint=None` (A11.2) — chặt HƠN r17 (nơi family bench được đưa vào):
  đây là **tightening chống oracle, đúng hướng charter §11**.
- **Kiểm fact thiết kế trên r17 log** (tự tính lại từ 764 decisions + strip_meta):
  TP r17 = 57/57 đều là flip 1→0; FP 213 = 167 flip 0→1 + 46 flip 1→0;
  56/270 alarm có strip-inert (bytes_removed=0) — toàn bộ granite — trong đó
  2 nằm ở TP và 54 ở FP. Con số này khớp nguyên `r17_alarm_log_analysis.json`
  của W1 (TP n_zero=2, FP n_zero=54). Rule dùng bytes_removed>0 = thông tin
  có TRƯỚC khi generation (strip chạy trước) — hợp lệ alarm-time.
- **Cảnh báo struct (không chặn)**: record quyết định vẫn mang theo
  `label`/`y_true` (cho analysis phase). An toàn nhờ signature thuần của rule
  + `family_hint=None`, nhưng reviewer sau này nên đọc rule TỪ signature, không
  từ record. Ghi nhận đúng như W1 khai trong `label_leakage_check`.

## D1-b — Gate mới có bị nới/hạ thuận lợi so với failure cũ? **PASS-CÓ-ĐIỀU-KIỆN (3 flag)**

Đối chiếu gate cũ (prereg r17 §1.11/§1.12, FAIL realized: precision .2111, CRR
.2182, DIER .1712) với gate mới (A11.3: P1 precision-kept ≥ .40, P2 CRR ≥ .35,
P3 DIER ≤ .05, P4 UAC ≥ .95):

1. **[FLAG-P1] P1 (.40) ĐẶT THẤP HƠN sàn falsifier cũ (F3: precision < .50)**.
   Đây là nới thật sự. Hypothesis công bằng: kept-alarm population trên v2 nhỏ
   (W1 tự khai CI ±.08 tại n≈120) nên .50 khó bảo đảm; nhưng phải nói thẳng
   trong W1 report: **"P1=.40 < F3(r17)=.50"** và kèm luôn precision ở ngưỡng
   .50 (một dòng: pass/fail tại .50). May mắn cho cơ chế: counterfactual r17
   (đã verify độc lập, xem D2) cho precision-after **.6180** — cơ chế vượt cả
   .50 trong kịch bản thiết kế; nếu v2 rớt .50 nhưng đỗ .40 thì claim phải hạ thành "pruning
   giảm noise có ý nghĩa nhưng không đạt sàn signal r17".
2. **[FLAG-P2] P2 CRR .35 < freeze criterion charter §9 (≥40% recovery)** —
   hạ .05 so với G1 cũ (.40). Khác FLAG-P1, ở đây W1 đã khai "AT RISK" TRƯỚC
   run (A11.3) và counterfactual r17 cho **.2000** — kỳ vọng đăng ký là FAIL,
   nên không phải gaming-để-pass; rủi ro thật là ngược lại (CRR rơi vào
   [.35,.40) → pass "nhờ hạ gate" — khi đó W1 report phải in song song cả hai
   ngưỡng .35 và .40, không được tính PASS nhờ .35 một cách lặng lẽ).
3. **[FLAG-G3] G3 cũ (paired gain EVIDA > D1-only, strict) BỊ BỎ, không có
   falsifier tương đương trong A11.3** → từ v2 KHÔNG ĐƯỢC claim "EVIDA-2 tốt
   hơn D1-only" kể cả khi PASS 4 gate; D1 comparator chỉ còn là side-report
   (code có `CRR_d1_only_side_report` + `DIER_d1_only_side_report` — OK).
   W1 report phải có câu chữ này.
- P3 (.05) GIỮ NGUYÊN — và chính điều này "công bằng": counterfactual DIER
  **.0753 > .05** nghĩa là ngay trên log cũ, cơ chế prune vẫn KHÔNG đủ đỗ P3
  (14/25 sai được prune; 11 sai còn lại là alarm kept). P3 không bị nới.
- Ghi nhận thiết kế đáng nhớ: prune chuyển final về V_raw trên clean-population
  mà raw đúng theo định nghĩa denominator → **P3 được thiết kế "ưu ái" về mặt
  cơ chế** (pruneFP trên clean hầu như luôn là 0→1-flip bị loại bởi direction
  clause). Không phải leak (raw là verdict runtime hợp lệ) nhưng khi diễn giải:
  cải thiện DIER = mục tiêu của chính rule, không phải bằng chứng mới độc lập.

## D1-c — Held-out v2 có thật sự virgin? **PASS cho ladder/safety; KHÔNG virgin sample-level vs r17 (đã disclose đúng)**

- **Kiểm độc lập draw**: rule đăng ký "first 10 sample_ids per (family,label)
  sorted ascending" trên `bench_attack_v2.jsonl` (sha16 7e8ed42421a7c2d0) → tôi
  tự tính draw 80 ID (40 vul + 40 ben, 4 family × 10) từ JSONL gốc — deterministic,
  tái lập được (`/tmp/r18_draw_ids.json`, quy trình trong W2 report §5).
- **Virgin check bằng script riêng** (`r18_stats_validate.py virgin`) trên toàn
  bộ universe đã-generation tồn tại trong repo:
  - r16 ladder 7B/8B (60 vul): **0/80 overlap** ✓
  - r16 safety (100): **0/80** ✓
  - r7 ladder qwen7b, r10 ladder granite, r9 8b (60+30 mỗi set): **0/80** ✓
  - r12 defense-batch (excluded list): **0/80** ✓
  - → **Câu hỏi của mandate ("chưa từng chạy ladder/safety trên nó") = ĐÚNG:
    draw này chưa từng bị ladder/safety chạm.**
  - round17_evida_units / rq8 (granite+llama): **80/80 overlap** — trùng 100%
    với sample-set r17/RQ8 (cùng corpus bench_attack_v2).
- **Đối chiếu với disclosure của W1 (A11.2)**: W1 ghi đúng sự thật này —
  "'held-out' here = pipeline-level … NOT sample-disjoint — disclosed, no
  disjoint-bench claim is made", và mọi generation v2 là MỚI (prompt frame
  safety-port, byte-different by construction). **Đánh giá: trung thực, nhưng
  đây là điểm yếu xác thực nhất của thiết kế** — rule PRUNE-1 được chọn TRÊN
  chính 80 sample này (qua log r17), rồi "xác nhận" trên chính chúng ở prompt
  frame khác. Xác nhận vẫn có giá trị (rule transfer qua frame + generation
  mới + determinism temp-0), mức độ thấp hơn disjoint replication.
  **Câu chữ bắt buộc cho paper/report**: "pipeline-level holdout (rule frozen
  from the round-17 log before these generations; same underlying 160-sample
  bench, re-rendered prompt frame)" — CẤM từ "held-out benchmark" hoặc
  "disjoint samples" đứng một mình.

## D1-d — Charter §10 compliance: **PASS**

- **CLOSED + âm preserved**: r17 verdict FAIL nằm nguyên trong prereg r17
  (execution log: G1/G2/G3/G5 false, F3 fired, MECHANISM-INVALID) +
  `evida_analysis.json` không bị sửa (so my recompute: mọi số khớp) + pass-1
  defect archived (`pass1_dtype_leak/`). Không thấy hành vi overwrite.
- **Một thay đổi hợp pháp duy nhất**: prune alarm (PRUNE-1); checker bank,
  adjudicator, D1 strip, tau .5481, refusal handling reuse verbatim — đúng
  "legitimate modification" charter §10, không đổi 5 components cùng lúc.
- **ID mới + prereg mới**: round-18 run có ID/config riêng
  (`configs/packguard_evida2.yaml` sha khác r17), AMENDMENT-11 đăng ký
  2026-09-30 10:15+07 **trước** mọi generation v2 — verify filesystem: tại
  thời điểm poll 10:07–10:15, `outputs/packguard/evida2/` chỉ chứa
  `r17_alarm_log_analysis.json` (design-basis, post-hoc w.r.t. r17 /
  pre-registered w.r.t. v2 — đúng phân loại), chưa có kết quả generation.
- **"New held-out data" của §10**: yếu nhất (xem D1-c) — đã disclose; chấp
  nhận với câu chữ bắt buộc.
- Đánh số AMENDMENT: W1 tự phát hiện xung đột tên ("AMENDMENT-10" của directive
  bị slot r17 chiếm) → dùng AMENDMENT-11 và ghi chú nguyên nhân. ĐÚNG, giữ
  tính append-only §2.

---

## D2 — STATS VALIDATION ĐỘC LẬP (baseline r17 mà rule đang nhắm)

Chạy `scripts/r18_stats_validate.py round17` (độc lập, không import code W1):

| Endpoint | Tự tính lại từ raw | Official (analysis JSON / prereg) | Trạng thái |
|---|---|---|---|
| Alarm precision | 57/270 = **.2111** (TP 57, FP 213, FN 89) | .2111 (57/213/89) | MATCH |
| CRR(EVIDA) granite pooled | 12/55 = **.2182** [CI .1181, .3501] | .2182 [.1181,.3501] | MATCH |
| CRR(D1-only) | 18/55 = **.3273** | .3273 | MATCH |
| DIER pooled clean | 25/146 = **.1712** (D1: 78/146 = .5342) | .1712 / .5342 | MATCH |
| Denominator DIER | 146 = 105 granite (75 S1-ben + 30 S2) + 41 llama (23+18) | 146 (105+41) | MATCH |
| **37 inert** | **37/55** registered granite-pooled events có V_raw == V_trusted (path `agree`; 55−18 alarms) | log chạy: "36/55" (65%) | **MISMATCH nhỏ: đúng là 37 (67.3%), log r17 lệch ±1** |
| n_units / alarms / events | 764 / 270 / 146 | 764 / 270 / 146 | MATCH |

- "37 inert" = 37 sự kiện corruption (trong 55 registered) mà stripping không
  đổi verdict → alarm không thể kêu → adjudication inert-by-construction;
  trong 37 event này KHÔNG cái nào được khôi phục (no-alarm & final==clean = 0)
  — tức D1-only cũng 0 trên nhóm này. Đây là số mà pruning rule không thể sửa
  (ngoài tầm của alarm channel) — đúng cơ cấu mà rule đang nhắm.
- **Phát hiện phụ [MINOR, mục punch-list]**: execution log của prereg r17 viết
  "36/55 events raw==trusted (65%)" — artifact cho **37/55 = 67.3%** (55−18
  alarms; 55 path-agree = 37). Sai số ±1 trong PROSE, không trong analysis JSON;
  không đổi kết luận nào. Để orchestrator quyết định sửa 1 chữ hay giữ nguyên
  (append-only).
- **Reproduce design-basis PRUNE-1 của W1 trên log r17 (độc lập, của tôi)**:
  kept alarms 89; TP kept **55/57 = .9649**; FP removed **179/213 = .8404**;
  precision-after **.6180**; CRR counterfactual **11/55 = .2000**; DIER
  counterfactual **11/146 = .0753** — khớp 100% `r17_alarm_log_analysis.json`
  của W1. Design-basis ĐÁNG TIN (không bịa, không chọn lại).

## D3 — POWER cho v2 (n=40 vul × 2 model, phát hiện CRR ≥ .35 tại α=.05)

Monte Carlo (100k reps, seed 20260922, `scripts/r18_stats_validate.py power`),
test one-sided exact binomial **H0: CRR ≤ .2182** (incumbent đo được ở r17 —
strip-only trên cùng kênh; đây là null có căn cứ data, không phải null bịa)
vs p1 = .35:

| Kịch bản events | Power |
|---|---|
| Measured flip-yield (granite .6125, llama .1875 → E[n]≈32) | **.446** |
| 32 events (≈ expected) | .448 |
| 48 events | .647 |
| 80 events (mọi unit flip — upper bound vật lý) | .794 |
| Tối thiểu để power ≥ .80 | **≈75 events** |

**Kết luận: UNDERPOWERED.** Tại expected ~32 events, power ≈ .45 — v2 gần như
coin-flip để phân giải CRR .35 khỏi .2182. Ghi khuyến nghị BẮT BUỘC vào
W1 report + paper: **"descriptive-at-realized-n; underpowered để phân giải
CRR ≥ .35 so với incumbent .2182 (power ≈ .45 tại expected n≈32 events); mọi
đọc CRR chỉ là ước điểm + CI"** (W1 đã ghi đúng tinh thần này trong A11.3
"all inference descriptive-at-realized-n" — con số power .45 của tôi định lượng
thêm). Lưu ý tương tự cho P1: CI ±.08 tại n≈120 kept alarms (W1 đã khai).
Với gate đọc theo point-estimate thì power tại biên ~.5 by construction —
vì vậy chỉ có test-vs-null mới là câu hỏi có nghĩa, đã dùng ở trên.

## D4 — TESTS

`tests/test_r18_stats.py` — **18 passed** (`.venv/bin/python -m pytest
tests/test_r18_stats.py -q`): fixture 4-unit ground-truth-by-construction
(TP/FP/CRR/DIER/inert/abstain tính tay), pin McNemar/Clopper vào giá trị exact
đã biết + cross-check statsmodels (bỏ qua nếu thiếu), oracle-audit test (field
lạ bị flag), test validator không import code builder, và live recompute r17
(57/213/89, 12/55, 25/146, 37 inert) — sẽ fail nếu ai đó sửa definition.

---

## KẾT LUẬN W2 (chốt chặn post-hoc tuning)

1. PRUNE-1 **sạch label** (signature thuần 3 inputs; family_hint=None chặt hơn r17).
2. Design-basis trên r17 log **tái lập độc lập 100%** — không có số bịa.
3. Gate mới: P3/P4 giữ nguyên; **P1 hạ dưới sàn cũ (.40 < .50), P2 hạ dưới
   charter floor (.35 < .40), G3 bị bỏ** — 3 flag này không chặn run (W1 đã
   khai AT-RISK + descriptive) nhưng **ràng buộc câu chữ report** (§D1-b).
4. Virgin: ladder/safety sạch hoàn toàn (0/80); sample-level trùng r17 —
   disclose trung thực; câu chữ "pipeline-level holdout" bắt buộc.
5. v2 **underpowered cho CRR** (power ≈ .45) — khuyến nghị "descriptive" là
   bắt buộc, không phải tùy chọn.

---

## PHỤ LỤC (post-run, 11:03–11:20) — KẾT QUẢ V2 RECOMPUTED ĐỘC LẬP

W1 xong run 11:03 (`evida2_decisions.json` + `evida2_analysis.json`, 160/160
pairs, mock=false). W2 tính lại từ raw TRƯỚC khi đối chiếu — khớp W1 đến chữ
số cuối (`outputs/packguard/evida2/w2_recompute.json`):

- **Gates: PASS 4/4** — P1 precision-kept **66/66 = 1.000** (pre-prune cũng
  1.000), P2 CRR pooled **53/66 = .803** [CI .687, .891], P3 DIER **0/81**,
  P4 UAC **320/320**. Cả hai side-threshold (.50 r17-floor, .40 charter-floor)
  cũng PASS → các FLAG-P1/P2 của W2 không biến thành thực tế (pass nhờ hiệu
  ứng thật, không nhờ gate hạ).
- **Nhưng 5 cấu trúc bắt buộc phải lộ ra cùng chữ PASS** (chi tiết
  `reports/round18/W2_report.md` §4.4):
  1. **T1p FIRED**: 60/66 = .9091 kept-alarms đi fallback (checker bank: 0
     SUPPORT / 6 REFUTE trên c/cpp) → reframe detection-only BẮT BUỘC theo
     A11.3. W1 có report T1p=true trong JSON — đúng; verdict "PASS" trần thì không.
  2. **Paired vs D1-only: 13–0 CHỐNG EVIDA-2** (D1 66/66 vs EVIDA 53/66; exact
     McNemar p=.000244) — 13 lỗi đều là fallback-override (CodeBERT score ≥ tau
     .5481 → giữ raw=1, bỏ strip-đúng). G3/F1 r17 đã bị drop (FLAG-G3 của W2) —
     nếu còn thì F1 FIRE. Adjudication hiện đang LÀM HẠI recovery.
  3. **PRUNE-1 prune 0/66** — cơ chế chủ đề của round chưa từng engage (alarm
     regime mới sạch sẵn). P1-PASS ≠ bằng chứng pruning rule hoạt động.
  4. **Llama 1/66 events** (granite 65) — near-silent trên frame mới.
  5. **Descriptive-only**: 66 events < ~75 (power .8); D1-only=1.0 trên v2 vs
     .3273 r17 → regime khác, cấm so incumbent thẳng.

**W2 chốt round 18**: gate-level PASS (independently reproduced) + reframe
detection-only + PRUNE-1 vẫn chưa được xác nhận (chưa bị stress). Việc tiếp
theo hợp lệ theo charter §25: FULL chỉ mở sau khi (i) checker bank c/cpp được
sửa/nêu rõ là không phân giải, (ii) fallback policy được thiết kế lại (nguồn
13/13 lỗi), (iii) một phép so paired-vs-D1 trở lại gate, (iv) stress-test
prune trên regime có FP thật hoặc benchmark sample-disjoint.
