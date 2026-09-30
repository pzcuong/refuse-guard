# ROUND 18 — W1 REPORT: EVIDA-2 (alarm-pruning) validation trên bench_attack_v2

Ngày: 2026-09-30 (UTC+7). Prereg: `docs/packguard_prereg.md` **AMENDMENT-11**
(đăng ký TRƯỚC run; slot tên "AMENDMENT-10" trong directive đã bị r17 chiếm —
giữ đánh số tuần tự, ghi chú trong amendment).

---

## 1. Đã làm gì

1. **[E1] Phân tích alarm-log r17** (computed-by-script, không số gõ tay) từ
   `outputs/experiments/round17_evida/{evida_decisions,evida_units}.json`:
   - Tái lập đúng population registered: 764 units / 756 both-parsed /
     **146 corruption events; TP 57 / FP 213 / FN 89; precision .2111,
     recall .3904** — khớp nguyên execution log r17.
   - **Inert counterfactuals xác nhận: 37/55** granite primary events có
     `V_raw == V_trusted` (strip không đổi verdict → alarm không thể bắn →
     event không thể recover); llama 9/27.
   - Decompose 213 FP: **105 harmful** (final ≠ y_true) / **108 inert**
     (final == y_true); phân bố S1/clean 130, S1/attack 47, S2/clean 20,
     S2/attack 16.
   - Đặc trưng phân biệt TP vs FP: **(a) hướng flip** — TP 57/57 là `1→0`
     (strip gỡ verdict vul), FP 167 `0→1` + 46 `1→0`; **(b) AST-diff size** —
     TP bytes_removed median 324 (chỉ 2/57 = 0), FP median 136 (54/213 = 0 —
     pure generation-noise trên prompt byte-identical); **(c) family** — TP
     tập trung CWE-416 (22/57) nhưng family là metadata nhãn → KHÔNG dùng
     trong rule; **(d) sample size** — không phân tách.
   - **Rule đăng ký PRUNE-1** (2 mệnh đề, chỉ dùng {raw_y, strip_y,
     prompt-sha-equality} — không nhãn): giữ alarm ⟺ strip ĐỔI prompt VÀ
     (raw, strip) = (1, 0). Trên log r17: **TP giữ 55/57 (.9649 ≥ .80)**,
     **FP loại 179/213 (.8404 ≥ .60)**, precision-sau .6180; counterfactual
     DIER pooled .1712→.0753, CRR .2182→.2000 (rule KHÔNG sửa recovery —
     khai trước). Phương án thay thế R1 (chỉ hướng): TP 57/57, FP-cut .784,
     precision .5534 — bị loại vì giữ kênh noise.
2. **[E2] AMENDMENT-11** đăng ký rule + endpoints + gates trên held-out
   v2 TRƯỚC khi generate (freeze 10:07, generation đầu 10:22).
3. **[E3] Run v2**: 80 samples (10 vul + 10 ben × 4 family, draw
   deterministic first-10/sample_id per stratum) × {C0, C5_near} × 2 models
   (granite-3.3-2b, llama-3.2-3B, MPS) — **412 generations mới** (320 raw +
   92 strip; 74 units clause-1-reuse; strip(C5)==strip(C0) dedupe tiền lệ
   M4), 0 exclusion, ≤ 720 cap, fallback 64-sample KHÔNG kích hoạt.
   Pipeline: `packguard.safety_port.render_prompt` (frame P0_neutral,
   ngôn ngữ c/cpp) + `research_program.evida_strip.strip_view` (gate
   lenient-canonical) + frozen `EvidaAdjudicator` (family_hint=None — chặt
   hơn r17, chỉ dùng CWE model tự claim).
4. **[E4] Đánh giá** (mục 3 dưới). **[E5]** tests + report này.

## 2. Files (tất cả absolute dưới root `/Users/macbook/.zcode/workspace/default/refuseguard`)

| File | Vai trò | sha256_16 |
|---|---|---|
| `packguard/evida2.py` | PRUNE-1 + pipeline + endpoints (MỚI) | — |
| `configs/packguard_evida2.yaml` | registration config (MỚI) | — |
| `scripts/r18_run_evida2.py` | runner stages units/run/decide/analyze (MỚI) | — |
| `tests/test_packguard_evida2.py` | 15 tests (MỚI) | — |
| `outputs/packguard/evida2/r17_alarm_log_analysis.json` | E1 artifact | 03ccb9ec182af970 |
| `outputs/packguard/evida2/evida2_units.json` | manifest 320 units | a20b8d3ed5c41d88 |
| `outputs/packguard/evida2/gen_granite2b.jsonl` | 206 gen rows thật | 8dedb75ae3722928 |
| `outputs/packguard/evida2/gen_llama3b.jsonl` | 206 gen rows thật | e35d6674436070c8 |
| `outputs/packguard/evida2/evida2_decisions.json` | 320 decisions | c56bdfafc407a9cd |
| `outputs/packguard/evida2/evida2_analysis.json` | endpoints + gates | 2eefb3e853cfced6 |
| `docs/packguard_prereg.md` | AMENDMENT-11 + execution log (SỬA) | — |

Không đụng: `packguard/{fl,eval,dataset}.py`, `paper2/`, `RESEARCH_STATE/`,
không git commit.

## 3. Cách chạy + kết quả chính

```bash
.venv/bin/python -m pytest tests/test_packguard_evida2.py -q          # 15/15 PASS
HF_HOME=$PWD/models_dir/hf .venv/bin/python scripts/r18_run_evida2.py --stage units
HF_HOME=$PWD/models_dir/hf .venv/bin/python scripts/r18_run_evida2.py --stage run --phase raw    # 320 gens
HF_HOME=$PWD/models_dir/hf .venv/bin/python scripts/r18_run_evida2.py --stage run --phase strip  # 92 gens
HF_HOME=$PWD/models_dir/hf .venv/bin/python scripts/r18_run_evida2.py --stage decide
HF_HOME=$PWD/models_dir/hf .venv/bin/python scripts/r18_run_evida2.py --stage analyze
```

Realized (realized-n, descriptive; so sánh r17 trong ngoặc):

| Endpoint | v2 realized | Gate | r17 |
|---|---|---|---|
| **P1** alarm precision (kept) | **66/66 = 1.0** [CI .946, 1.0] | ≥ .40 **PASS** | .2111 |
| — pre-prune precision / pruned | 1.0 / **0 alarm bị prune** | — | — |
| — recall trên events | 66/66 = 1.0 | side | .3904 |
| **P2** CRR pooled | **53/66 = .803** [CI .687, .891] | ≥ .35 **PASS** | .2182 |
| — D1-only strip (side) | **66/66 = 1.0 > EVIDA-2** | side | .3273 |
| **P3** DIER pooled clean-correct | **0/81 = 0.0** [CI 0, .044] | ≤ .05 **PASS** | .1712 |
| **P4** UAC | 320/320 = 1.0 | ≥ .95 **PASS** | 1.000 |
| T1p undecidable share kept | **60/66 = .9091 → FIRES** | ≤ .50 | .152 |

Per-strata CRR (EVIDA-2): granite n=65 .80; llama n=1 1.0 (vacuous);
CWE-190 .667 / CWE-200 .733 / CWE-416 .895 / CWE-476 .882 — **D1-only = 1.0
ở MỌI stratum**. DIER strata: granite 0/41, llama 0/40.

**VERDICT (trung thực 2 chiều):**
- **Formal: PASS cả 4 gates** — precision .2111→1.0, CRR .2182→.803,
  DIER .1712→0.0 trên data v2.
- **Nhưng T1p FIRES (.9091 > .50)** → theo mệnh đề reframe đã đăng ký:
  **claim recovery bị hạ cấp — EVIDA-2 chỉ đọc ở mức detection-only**.
  Recovery .803 là do fallback CodeBERT (60/66 alarms đi fallback; checker
  bank chỉ REFUTE 6/66), và **plain strip (D1-only) recover 66/66 — hơn
  EVIDA-2**: hướng F1 của r17 (adjudication không thêm gì so với strip
  thuần) TÁI DIỄN trên v2.
- **Pruning benefit KHÔNG được stress-test trên v2**: 0 alarm 0→1 xảy ra
  dưới frame mới nên 0 alarm bị prune — lợi ích của PRUNE-1 vẫn chỉ đứng
  trên design-basis counterfactual của log r17.
- **DIER 0.0 là vacuous**: 0 alarm ở clean arm → final luôn = raw.

## 4. Lệch chuẩn so với kế hoạch (đều disclosed)

1. **Tên amendment**: directive bảo "AMENDMENT-10" — slot đã bị r17 dùng;
   đăng ký là **AMENDMENT-11** (tuần tự, ghi chú trong amendment).
2. **"Held-out" là pipeline-level, KHÔNG sample-disjoint**: r17 S1 đã dùng
   đúng 160 sample_ids của bench_attack_v2 (raw verdicts cache round-7).
   Điều mới của v2 = rule frozen trước run + generation hoàn toàn mới dưới
   prompt machinery khác (safety-port frame) — 0 kế thừa cache r17/RQ8
   (prompt byte-khác theo construction).
3. **Prompt frame domain-port** (Package-analysis wording của safety_port
   trên hàm C/CPP — theo directive "safety_port pipeline chuẩn"): hệ quả
   ĐO ĐƯỢC là **sụp đổ khả năng phân loại**: llama raw=0 ở 160/160 units
   (all-benign), granite C0 chỉ phát hiện 1/40 vul — kênh corruption chỉ
   còn granite (65/66 events). Các strata llama not-evaluable; pooled
   endpoints do granite chi phối.
4. **family_hint=None** tại adjudication (chặt hơn r17 vốn truyền family
   của bench) — đăng ký trong A11.2.
5. **run_meta.json bị ghi đè giữa 2 phase** (raw-phase meta chỉ còn trong
   `run_raw.log`); tổng gen mới 412 truy vết được từ gen_*.jsonl (412 dòng
   distinct-prompt đã dedupe: 206+206 dòng file = 160 raw + 46 strip unique
   prompts mỗi model).
6. `EXPERIMENT_REGISTRY.jsonl` không thuộc ownership — chưa emit row
   EXP mới (TODO orchestrator).

## 5. TODO / khuyến nghị

1. **Orchestrator**: append registry row cho round-18 (EXP mới) từ
   `evida2_analysis.json`.
2. **Frame của pipeline cần quyết định**: frame RQ8 (function-analysis) là
   frame duy nhất cả 2 model phân loại được; frame safety-port cho claim
   "same machinery as PG" nhưng sụp đổ recall. Khuyến nghị: round sau chạy
   song song 2 frame (nhỏ, 1 model) trước khi claim bất cứ endpoint pooled
   nào.
3. **Recovery cần cơ chế thật, không phải fallback**: T1p fire 2 vòng
   liên tiếp → checker bank cần mở (thêm family pattern + slice sâu hơn)
   hoặc chấp nhận định vị product = **alarm layer** (precision đã chứng
   minh được) + hand-off adjudication.
4. **Pruning-rule stress-test**: cần một run có FP thật (frame RQ8 hoặc
   model khác) để đo lợi ích prune ngoài counterfactual; giữ PRUNE-1
   nguyên trạng, không tune.
5. Nếu mở FULL: đăng ký sample-disjoint bench mới (không phải
   bench_attack_v2) + power n≥200 events.

## 6. Self-test (thật, không mock)

- `pytest tests/test_packguard_evida2.py` → **15 passed** (determinism,
  no-label-leak (signature không có kênh nhãn + behaviour invariant),
  clause-1/2 frozen spec, draw stratified 10/stratum deterministic,
  reuse policy = prompt-identity, synthetic endpoints hand-computed,
  gate fail paths, E1 artifact reproduces 57/213/89 + 37/55).
- `pytest tests/test_packguard_defense.py` → **13 passed** (không phá
  machinery D1 hiện có).
- Dry smoke mock end-to-end (`--dry --limit 3`) PASS, cờ `mock:true`,
  không lẫn số thật; real run records `mock:false` toàn bộ (verify: 0
  mock rows trong gen_*.jsonl).
- Cross-verify decisions ↔ gen rows: **0 mismatch** trên 320 units
  (per-model lookup đúng; phát hiện + sửa 1 bug trong script spot-check
  của chính agent — prompt_sha không chứa model_id, không phải bug
  pipeline).
- Adjudicator: fallback_calls 60, fallback_errors 0; checker synthetic
  validation kế thừa frozen r17 (16/16).
