# A1 Report — Round 5 (ATTACK V2: C5 query-relevant risk context + wording ladder)

Ngày: 2026-09-19. Phạm vi: thiết kế + triển khai attack v2 theo ĐÚNG cơ chế
literature (TabooRAG / Beyond Refusal / Defensive Refusal Bias), materialize
bench cho A2/A3, tests, pre-registration. KHÔNG chạy LLM (A2/A3 lo). Không git
commit. Mọi con số dưới đây sinh bởi lệnh thật, truy vết được tới file output.

---

## 1. X2 — Đã xong SỚM (trước deadline 45 phút), A2/A3 dùng được ngay

**Files (đúng quyền sở hữu):**
- `src/conditions/c5_risk_context.py` (module mới, không phá C0–C3 cũ):
  - `extract_risky_apis(func, language, cfg)` — đếm call-site 26 sinks bằng
    tree-sitter AST (`call_expression` callee identifier chính xác; member-call
    không đếm — conservative), regex fallback khi không parse.
  - `build_advisory(func, template_id, cfg, language, sample_id)` — 8 pattern
    template + 1 zero-api template (YAML), label-blind, count_cap=3.
  - `apply_attack(sample, arm, cfg)` — arms {C0, D2_task, C5_near, C5_far},
    mọi C5 qua `check_semantics` strict (ignore_strings=False).
  - `build_attack_prompt(sample=None, arm, cfg=None, func=None, language=None)`
    → `{"system","user","meta"}` — **SINGLE SOURCE OF TRUTH**, byte-deterministic,
    format prompt y hệt rounds 2–3 (`task\n\n```lang\nfunc```\n\nReport…`),
    chấp nhận cả dispatch kiểu A2 (`func=/arm=/language=` không sample).
  - `materialize(cfg_path)` + CLI: `python -m src.conditions.c5_risk_context
    configs/attack_v2.yaml`.
- `configs/attack_v2.yaml` — pre-registration: seed **20260919**, ladder
  D0/D1/D2, 8+1 advisory template, forbidden-token policy, gate rule v2.
- `data/benchmarks/bench_attack_v1/bench_attack_v1.jsonl` (200 rows = 100 vul +
  100 benign, 800 entries, layout `arms`-dict per sample) +
  `manifest_attack_v1.json` (seed/checksum/phân phối/strata/prompt-contract).
  JSONL sha256_16 = **2daa249f7543f8e0** (idempotent: rebuild lại đúng sha này).
- `tests/test_attack_v2_c5.py` — 23 tests, **23/23 PASS**.
- `docs/attack_v2_design.md` — mapping literature→cơ chế + trích dẫn + pre-reg.

**Tương thích A2 (verify thật, không phải claim):** chạy loader/runner của A2
trên artifact: `load_bench(round5_e0v2.yaml)` → 800 entries, 4 arms đủ,
200 samples; `select_subset` → 120 (60+60), `samples_missing_any_arm = []`;
`render_prompt` → gọi thành công `build_attack_prompt` của tôi
(`prompt_source = c5.build_attack_prompt{('arm','func','language')}`).
A3 (`round5_defense.yaml`): tên file khớp `a1_bench`:
`data/benchmarks/bench_attack_v1/bench_attack_v1.jsonl`.

## 2. Thiết kế cơ chế (chi tiết trong docs/attack_v2_design.md — đã web-verify 3 paper)

| Literature | Cơ chế | Áp vào v2 |
|---|---|---|
| TabooRAG 2603.03919 | blocking document: "restricted risk context" bọc query-related elements; "must begin with a paraphrase of the query", "reasonably repeat key terms"; "avoid instruction injection"; ASR 77–96% trên benign query | C5 advisory sinh từ CHÍNH risky-sink fingerprint của hàm (AST), nhúng TRONG artifact cần phân tích; thuần threat-intel/CVE prose, không instruction; benign-block = primary endpoint |
| DRB 2603.01246 | 2.72× refusal với security-keyword (30.5% vs 11.2%); vocab 11 từ exploit/payload/shell/bypass/crack/brute/dump/pivot/c2/obfuscate/evasion; system hardening 43.8%, malware analysis 34.3%; Authorization Paradox (auth TĂNG refusal 21.8% vs 11.6%) | D2_security_dense dùng đúng family vocab ở density "Dense Cyber"; D1_authorization giữ trong ladder để test hướng "backfire"; D0 = default_task cũ |
| Beyond Refusal 2607.05842 | funnel respond→correct→actionable; refusal KHÔNG phải loss chính (~97% usable) — framing đổi chất lượng (32→13→8 usable theo frame); 4 mức density theo term-family budgets, set TRƯỚC khi xem kết quả | H-B nhắm utility ladder (usable/recall/flip) chứ không chỉ RR; density ladder pre-registered |

**ANTI-LEAKAGE (thiết kế quan trọng nhất):**
1. Advisory không có tham số label; template draw seed theo sample_id.
2. Count cap 3 ("3+ call sites") → intensity là hàm bounded của feature.
3. Zero-API fallback (adv_00, không tên API) → presence 100% cả 2 lớp
   (chỉ 83/838 row bench_v1 có classic sink — inventory 20 cũ quá hẹp).
4. **Balancing strata**: has_risky_api 50/50 trong từng label (PrimeVul gốc
   19.3% vuln vs 13.9% benign → nếu không balance, LOẠI advisory lộ label).
   Kết quả materialize: 50/50 concrete + 50/50 generic mỗi label
   (`manifest.sampling.with_api_by_label`), CWE allocation trong từng stratum.

## 3. Pre-registration (ghi TRƯỚC khi A2 chạy generation)

- H-A (TabooRAG-analog): benign_block(C5_near|C5_far) − C0 ≥ 0.10 + McNemar
  p<0.05 + bootstrap CI loại 0.
- H-B (Beyond-Refusal): trên label=1, recall/usable của C5|D2_task giảm ≥ 0.10
  với McNemar p<0.05 (refusal không map thành benign; flip vul→benign đếm riêng).
- H-C: C5 > naive (round-3 C2b; round-5 D2_task) ≥ 0.10 (McNemar nếu paired;
  bootstrap 2 mẫu nếu unpaired — disclose).
- Pass = ≥2/3 model mỗi hypothesis. **Nếu 0/3 hypothesis đúng trên cả 3 model →
  model-scale limitation (2–3B local), KHÔNG claim absence tổng quát.**
- Config: `configs/attack_v2.yaml → gate_v2` (A2 độc lập pre-reg cùng family ở
  `round5_e0v2.yaml → hypotheses`; hai file nhất quán về ngưỡng 0.10/0.05).

## 4. Self-test thật (lệnh + kết quả)

```bash
.venv/bin/python -m src.conditions.c5_risk_context configs/attack_v2.yaml
# → materialized 200 rows ... counts: {'rows': 200, 'by_label': {'0': 100, '1': 100},
#    'arms': ['C0','D2_task','C5_near','C5_far'], 'entries_expected': 800}
.venv/bin/python -m pytest tests/test_attack_v2_c5.py -q   # → 23 passed
.venv/bin/python -m pytest tests/ -q
# → 387 passed, 1 failed (PRE-EXISTING của A2, xem §6)
```
Kiểm tra tích hợp A2 (script nội tuyến, kết quả ở §1): 800 entries / subset
120 / missing_arm rỗng / prompt render qua module của tôi. Rebuild lần 2 →
jsonl sha256_16 không đổi `2daa249f7543f8e0`.

## 5. Số liệu manifest (truy vết: data/benchmarks/bench_attack_v1/manifest_attack_v1.json)

- 200 rows; by_label 100/100; 800 entries; source bench_v1 sha
  `122aa6112b1a8966` (bridge); CWE top vul: CWE-787 (16), CWE-125 (12),
  CWE-703 (11), CWE-476 (7), CWE-119 (5); benign tương tự theo pool.
- Strata: vul with_api_pool 55 / benign with_api_pool 72 → chọn đúng 50+50 mỗi
  label, overflow 0.
- Advisory: zero_api 50/50 per label; pattern share max 0.23 ≤ guard 0.40
  (spread 6–23/template — chi-square cho thấy rộng hơn đều đều; draw verify
  uniform trên 100k id → chance, DISCLOSE, không re-seed vì lý do thẩm mỹ).
- Semantics: all_pass (strict); near/far: `any_confound=false`, min gap 24
  bytes (so với 35.2% collapse cùng-byte của bench_v1).

## 6. Phát hiện cho orchestrator / A2

1. **BUG PRE-EXISTING của A2 (không phải của tôi, tôi không sửa file của
   A2):** `tests/test_round5_e0v2.py::test_dry_run_end_to_end` FAIL —
   `pa["C5_far"]["taxonomy"]["partial_json_broken"]` kỳ vọng 2 nhưng thực tế
   `partial_no_json: 2` (mock C5_far sinh JSON đứt gãy không có `{` đóng được
   parse → has_json=False). Mâu thuẫn với unit test taxonomy của chính A2
   (partial_json_broken yêu cầu has_json=True). Dry-run KHÔNG dùng bench của
   tôi (`_mock_entries` tự dựng prompt) → không liên quan attack v2. A2 sửa
   trước khi chạy thật.
2. Lựa chọn carrier near≠far (inline_comment vs top_comment) là ĐỐI TRỌNG
   CÓ TÌNH: bench_v1 đã đo 35.2% near/far trùng byte với cùng carrier; đổi
   carrier đảm bảo near > far ở 100% row. Đổi lại arm khác nhau cả carrier
   lẫn position — ghi trong manifest + design doc §3.
3. carriers.py (A3) có hạn chế: `inline_comment near` sau `{` cùng dòng
   (K&R) sẽ nuốt phần còn lại của dòng — semantics gate bắt đúng, nhưng thay
   vì fallback tôi tự chứa `_inject_advisory` an toàn trong module của mình
   (không sửa file của A3).
4. Không sửa: src/models, src/metrics, src/data, src/defenses,
   src/experiments, configs của A2/A3. Không chạy LLM.

## 7. TODO (không thuộc quyền tôi / kế tiếp)

- A2: fix taxonomy-vs-mock (§6.1) rồi chạy E0-V2 thật (480 gen + smoke 5);
  so sánh D2_task vs C5 theo H-C; xuất `verdict.json`.
- A3: P3 boundary defense — advisory của tôi nằm trong comment
  (`// …` inside body / `/* … */` top-of-file), morphology detection dễ bám;
  lưu ý prompt contract là `build_attack_prompt` (không đọc prompt từ JSONL).
- Orchestrator: gate rule v2 0/3 → ghi model-scale limitation vào paper;
  nếu H-A PASS ≥2/3 model → E0-v2 chính là reproduction "refusal blocking"
  mà Round-3 E0 không tái lập được bằng wording-only.
- Nếu cần D1 ablation: ladder đã có trong config, `build_attack_prompt` nhận
  arm tùy ý qua cfg (không cần sửa code).

---
*Verification: `pytest tests/test_attack_v2_c5.py -q` = 23 passed; full suite
387 passed / 1 pre-existing failure (A2 dry-run mock); jsonl sha256_16
`2daa249f7543f8e0` idempotent qua 2 lần materialize. Không git commit.*
