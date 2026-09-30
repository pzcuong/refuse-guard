# W2 Report — Round 18 (EVIDA-2 — INDEPENDENT DESIGN REVIEW + STATS VALIDATION)

Ngày: 2026-09-30. Tác nhân: W2 (Vòng 18). Vai trò: chốt chặn chống post-hoc
tuning — review thiết kế AMENDMENT-11 TRƯỚC/trong khi W1 chạy + xác thực
thống kê độc lập từ raw. Không đụng file của W1 (`packguard/evida2.py`,
`configs/packguard_evida2.yaml`, `outputs/packguard/evida2/`), không git commit,
không số nào bịa (mọi số truy vết được đến artifact hoặc script trong report này).

## 1. LÀM GÌ (tóm tắt nhiệm vụ → kết quả)

| Nhiệm vụ | Kết quả |
|---|---|
| D1 Design review AMENDMENT-11 (4 điểm) | **APPROVED-RUN + 4 điều kiện câu chữ** — `docs/round18_design_review.md` (a PASS, b PASS-3-flag, c PASS-ladder/safety + KHÔNG sample-virgin vs r17 (disclosed đúng), d PASS) |
| D2 Xác thực số baseline r17 | **ALL-MATCH**: precision .2111 (57/270), CRR .2182 (12/55), DIER .1712 (25/146), **37 inert** (37/55) + reproduce design-basis PRUNE-1 100% (55/57 TP-kept, 179/213 FP-cut, precision-after .6180, CRR-cf .2000, DIER-cf .0753) |
| D3 Power v2 (40 vul × 2 model, CRR ≥ .35, α=.05) | **UNDERPOWERED**: power ≈ **.446** tại expected ~32 events; cần ≈75 events cho power .80 → khuyến nghị "descriptive" là BẮT BUỘC |
| D2b (sau run W1) Recompute EVIDA-2 trên v2 + PASS/FAIL từng gate | **DONE — gates PASS 4/4 reproduced** + 5 cấu trúc bắt buộc (T1p FIRED, 13–0 McNemar chống adjudication, 0/66 prune, llama 1/66, descriptive) — §4.4 |
| D4 Tests validator | `tests/test_r18_stats.py`: **18 passed** |

## 2. FILES

- **Tạo (quyền sở hữu W2)**:
  - `docs/round18_design_review.md` — verdict chi tiết D1-a…d + D2/D3.
  - `scripts/r18_stats_validate.py` — validator ĐỘC LẬP (tự viết Clopper-Pearson
    bằng beta continued-fraction + bisection, exact McNemar discordant-only,
    binomial tails; **không import** `research_program/`/`src/metrics/`/`packguard/`
    — có test khóa tính độc lập này). Subcommands: `round17` / `evida2` /
    `power` / `virgin`.
  - `tests/test_r18_stats.py` — 18 tests (fixture ground-truth-by-construction).
- **Đọc-only (không sửa)**: `PACKGUARD_BRIEF.md`, `RESEARCH_STATE/DECISION_LOG.md`,
  `RESEARCH_STATE/DIRECTOR_CHARTER.md` (§9/§10/§11/§16/§17/§18),
  `RESEARCH_STATE/PREREGISTRATIONS/prereg_EVIDA_*.md` (r17, FAIL preserved),
  `docs/packguard_prereg.md` AMENDMENT-10/11, `reports/round11/V1_report.md`
  (chuẩn TOST/CI đã audit — dùng làm mẫu phương pháp), r16 W_report,
  `outputs/experiments/round17_evida/{evida_decisions,evida_units,evida_analysis}.json`,
  `outputs/packguard/evida2/*` (W1), code W1 (`packguard/evida2.py`,
  `outputs/packguard/evida2/r18_run_evida2.py`).

## 3. CÁCH CHẠY (tái lập 100%)

```
cd /Users/macbook/.zcode/workspace/default/refuseguard
.venv/bin/python scripts/r18_stats_validate.py round17        # D2: ALL-MATCH
.venv/bin/python scripts/r18_stats_validate.py power          # D3: power .446
.venv/bin/python scripts/r18_stats_validate.py virgin --ids-file /tmp/r18_draw_ids.json
.venv/bin/python -m pytest tests/test_r18_stats.py -q         # 18 passed
# sau khi W1 xong (recompute v2 + PASS/FAIL gate):
.venv/bin/python scripts/r18_stats_validate.py evida2 --decisions outputs/packguard/evida2/evida2_decisions.json
```

Draw 80 ID của v2 được tôi tính ĐỘC LẬP từ rule đăng ký ("first 10 sample_ids
per (family,label) sorted ascending" trên `bench_attack_v2.jsonl`) và đối chiếu
với unit-list W1 emit: **khớp 80/80** (`evida2_units.json` 320 units = 80 ×
2 model × 2 arm, n_excluded=0, bench sha16 7e8ed42421a7c2d0).

## 4. KẾT QUẢ CHÍNH (D2/D3 chi tiết — số đầy đủ trong `docs/round18_design_review.md`)

### 4.1 Baseline r17 mà pruning rule nhắm — xác thực từ raw
Mọi số chính tái lập tới chữ số thập phân cuối bằng code thống kê tự viết
(Clopper-Pearson khớp statsmodels đến ~1e-15; McNemar khớp bảng giá trị exact).
**Phát hiện phụ [MINOR]**: execution-log prereg r17 viết "36/55 events
raw==trusted (65%)" nhưng artifact cho **37/55 = 67.3%** (55 − 18 alarms; đúng
số mà A11.1 và `r17_alarm_log_analysis.json` của W1 cũng dùng = 37). Sai lệch
±1 CHỈ trong prose, không nằm trong analysis JSON, không đổi kết luận — đưa
punch-list.

### 4.2 Design-basis PRUNE-1 trên log r17 (verify độc lập)
Kept 89 alarms; TP kept 55/57 (.9649); FP removed 179/213 (.8404); precision-after
.6180; CRR counterfactual 11/55 (.2000); DIER counterfactual 11/146 (.0753) —
**khớp 100%** JSON của W1. Design-basis sạch: post-hoc w.r.t. r17, pre-registered
w.r.t. v2, đúng phân loại.

### 4.3 Power (D3) — Monte Carlo 100k, seed 20260922, one-sided exact binomial
H0: CRR ≤ .2182 (incumbent r17 đo được) vs p1 = .35, α = .05:
measured-yield (~32 events) → **.446**; 48 events → .647; 80 events → .794;
min n cho power ≥ .80 ≈ **75 events**. Gate đọc theo point-estimate tại biên
luôn ~.5 by construction — test-vs-null mới có nghĩa, đã dùng.

### 4.4 EVIDA-2 trên v2 — RECOMPUTE ĐỘC LẬP (W1 xong 11:03; tôi tính lại từ `evida2_decisions.json` raw, KHÔNG đọc bảng của W1 trước)

**Reproduce: mọi số của W1 khớp độc lập đến chữ số cuối** (160/160 pairs
complete, 0 excluded; registry check `oracle_audit` trong
`outputs/packguard/evida2/w2_recompute.json`).

| Gate | Ngưỡng | Giá trị đo lại (independent) | Verdict |
|---|---|---|---|
| P1 precision kept | ≥ .40 (side: ≥ .50) | **66/66 = 1.000** [CI .946, 1.0] — pre-prune CŨNG 1.000 | **PASS** (cả hai ngưỡng) |
| P2 CRR pooled | ≥ .35 (side: ≥ .40) | **53/66 = .803** [CI .687, .891] | **PASS** (cả hai ngưỡng) |
| P3 DIER pooled | ≤ .05 | **0/81 = .000** [CI 0, .0445] | **PASS** (nhưng VACUOUS — xem F-3) |
| P4 UAC | ≥ .95 | **320/320 = 1.000** | **PASS** |
| **T1p tripwire** | UNDECIDABLE > 50% kept → reframe | **60/66 = .9091 [CI .813, .966] → FIRED** | **REFRAME BẮT BUỘC** |

**Kết luận gate: PASS 4/4 — reproduced. Nhưng W2 định lượng 5 cấu trúc mà
chữ "PASS" trần không được phép che:**

1. **[F-1] T1p FIRED (.909 > .50)**: 60/66 kept-alarm đi qua CodeBERT fallback
   (UNDECIDABLE); checker bank hầu như không phân giải gì trên c/cpp (0
   SUPPORT, 6 REFUTE). Theo đúng A11.3, claim phải reframe **detection-only**:
   EVIDA-2 trên v2 = alarm + strip-recovery, KHÔNG phải "evidence-grounded
   recovery". W1 đã report `T1p_undecidable_tripwire: true` trong JSON (đúng) —
   nhưng verdict top-line "PASS" KHÔNG ĐƯỢC đứng một mình.
2. **[F-2] Adjudication GÂY HẠI so với plain strip trên v2**: paired trên 66
   events: D1-only khôi phục **66/66 = 1.000**, EVIDA-2 **53/66 = .803**;
   discordant **13–0 chống EVIDA-2** (exact McNemar p = 2/2^13 = **.000244**).
   Cả 13 thất bại đều là fallback-override (score .58–.79 ≥ tau .5481 →
   final := raw=1, bỏ verdict strip-đúng). Đây chính là rủi ro FLAG-G3 của
   W2: G3/F1 r17 (paired gain, dropped trong A11.3) nếu còn thì **F1 FIRE**.
   CRR .803 PASS là công của D1-strip, bị EVIDA bào mòn 13 event.
3. **[F-3] PRUNE-1 prune 0/66 alarm — cơ chế được kiểm chưa từng engage**:
   toàn bộ 66 alarm đều (1→0) + strip-changed. Pre-prune precision đã là 1.000
   → không có FP-channel nào để prune (r17: 213 FP). P1-PASS KHÔNG phải bằng
   chứng cho pruning rule; nó là bằng chứng **regime đổi** dưới prompt frame
   safety-port (D1-recovery trên events = 1.0; inert events = 0 vs 37/55 r17).
   P3 DIER=0 cũng vacuous: 0 alarm trên clean arm (C0) — không gì để adjudicate.
4. **[F-4] Model asymmetry**: 65/66 events là granite; llama chỉ 1 event trên
   80 unit — llama gần như im tiếng trên frame mới. Báo per-model, không gộp che.
5. **[F-5] Power/descriptive**: realized 66 events < ~75 (ngưỡng power .8 của
   W2, D3); so sánh với incumbent r17 (.2182) KHÔNG hợp lệ vì regime khác
   (D1-only = 1.0 trên v2). Mọi số = descriptive + CI.

**W2 verdict cho round 18: GATE-PASS (reproduced) + REFRAME detection-only
(T1p) + cơ chế PRUNE-1 CHƯA được test thật (0 prune) — round này KHÔNG được
đọc là "pruning rule đã được xác nhận"; nó xác nhận (a) alarm signal sạch hơn
dưới frame mới, (b) fallback CodeBERT là điểm hỏng của recovery, (c) needed
next: stress-test prune trên frame có FP thật (r17-regime) hoặc benchmark
disjoint.**

## 5. LỆCH CHUẨN / FLAG (không chặn, nhưng ràng buộc cách viết)

1. **[FLAG-P1]** Gate precision mới (.40) **thấp hơn sàn falsifier r17** (F3: <.50).
   W1 report phải in song song pass/fail tại cả .40 và .50.
2. **[FLAG-P2]** Gate CRR mới (.35) **thấp hơn freeze criterion charter §9** (.40).
   Đã khai AT-RISK pre-run; nếu CRR rơi [.35,.40) phải in cả hai ngưỡng.
3. **[FLAG-G3]** G3 r17 (paired gain > D1-only strict) **không có Gate tương
   đương trong A11.3** → cấm claim "EVIDA-2 tốt hơn D1-only" từ v2; D1 chỉ là
   side-report.
4. **[FLAG-VIRGIN]** held-out v2 là **pipeline-level** (80/80 sample trùng
   r17/RQ8; ladder 7B/8B + safety: 0/80 — sạch). Cấm cụm "held-out benchmark /
   disjoint samples" đứng một mình; phải là "pipeline-level holdout, same
   160-sample bench re-rendered".
5. **[MINOR]** "36/55" trong execution-log r17 → đúng 37/55 (prose-only).
6. **[NOTE]** DIER cải thiện nhờ prune là by-construction-favored trên clean
   population (pruned → final := raw = baseline đúng theo định nghĩa denominator);
   counterfactual DIER .0753 vẫn > gate .05 → P3 KHÔNG được nới, vẫn at-risk.

## 6. TODO + SELF-TEST THẬT

- **Self-test đã chạy thật** (bằng `.venv/bin/python`):
  - `pytest tests/test_r18_stats.py -q` → **24 passed** (fixture ground-truth
    r17-schema + v2 arm-schema, pin McNemar/Clopper exact, cross-check
    statsmodels, oracle-audit, live-recompute r17).
  - `r18_stats_validate.py round17` → ALL-MATCH 16/16 check.
  - `r18_stats_validate.py power --reps 100000` → power .446/.448/.647/.794,
    min-n 75.
  - `r18_stats_validate.py virgin` → ladder/safety 0/80; r17/RQ8 80/80.
  - `r18_stats_validate.py evida2 --decisions outputs/packguard/evida2/
    evida2_decisions.json` → P1 1.000 / P2 .803 / P3 0.0 / P4 1.000, PASS 4/4,
    written `outputs/packguard/evida2/w2_recompute.json` (artifact ADDITIVE,
    namespaced `w2_`, không đụng file nào của W1; bản sao `/tmp/r18_w2_recompute.json`;
    schema v2-arm, oracle_audit đính kèm).
  - Unit-list W1 vs draw tự tính: khớp 80/80.
- **TODO** (không thuộc quyền W2): (i) W1 report PHẢI mang 5 cấu trúc §4.4
  (T1p-reframe; 13-0 McNemar chống adjudication; 0-prune; llama 1/66;
  descriptive/regime-shift) — verdict "PASS" trần không chấp nhận được; (ii)
  quyết định tiếp theo cho orchestrator: PRUNE-1 chưa bị stress-test (cần frame có
  FP thật — r17-regime — hoặc benchmark disjoint trước khi gọi "validated");
  (iii) punch-list: "36→37" trong prereg r17 prose (append-only); (iv) FULL
  version: cân nhắc gate paired-vs-D1 trở lại (G3) + checker bank cho c/cpp
  (hiện 0 SUPPORT) + fallback policy (score≥tau → raw là nguồn 13 lỗi).
