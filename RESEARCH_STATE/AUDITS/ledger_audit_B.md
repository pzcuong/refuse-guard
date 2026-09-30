# Ledger Audit B — tính HỢP LỆ pipeline (cross-audit #2, lens: raw-path / contradiction / coverage)

- Ngày: 2026-09-30 · Audit bởi: agent "người soát ledger-B" (dynamic workflow)
- Đối tượng: `RESEARCH_STATE/CLAIM_EVIDENCE_LEDGER.csv` (78 dòng = header + **77 claim**: PC-01..PC-40, RG-01..RG-37)
- Lens: (1) mỗi status VERIFIED có raw path tồn tại không; (2) mỗi CONTRADICTED có được giải thích chưa; (3) thiếu claim quan trọng nào so với `FINAL_STATUS.md`.
- Phạm vi: chỉ hợp lệ pipeline (sự tồn tại/bám rễ của bằng chứng), KHÔNG re-check giá trị số (đã là lens của audit #1 và của các round-audit W/V).

## Kết luận tổng

| Check | Kết quả |
|---|---|
| 1. VERIFIED → raw path tồn tại | **PASS — 63/63** VERIFIED đều bám vào artifact tồn tại trên đĩa. 0 hàng trỏ tới file mất. Có 4-5 yếu điểm *schema* (không phải mất bằng chứng), xem §1.3. |
| 2. CONTRADICTED được giải thích | **PASS — 0 hàng CONTRADICTED** trong ledger. Contradiction duy nhất trong artifact tree được xử lý có resolution + reason (`master_results.json`), và được ledger hóa qua RG-12. Không có gì "contradicted mà chưa giải thích". |
| 3. Coverage so với FINAL_STATUS.md | **6 mục của FINAL_STATUS chưa có hàng ledger**, cộng 1 dòng FINAL_STATUS đã STALE (P1-10 7B/8B) so với ledger. Xem §3. |

---

## §1. Check 1 — VERIFIED phải có raw path tồn tại

### 1.1 Phương pháp (đã chạy trong session này)
Parse CSV bằng `csv.DictReader` (78 dòng, 77 claim). Với 63 hàng `status=VERIFIED`, trích path-token từ cột `raw_records` (regex cho literal path, bare basename, brace `{a,b}`, glob `*`, dir shorthand), resolve bằng: (a) tồn tại trực tiếp theo đường dẫn; (b) basename index của toàn cây (walk `.`, exclude `.git`/`.venv*`/cache); (c) brace expansion; (d) glob dưới `outputs/`, `data/`, `reports/`, `docs/`; (e) `same file(s)` kế thừa path của hàng liền trước.

### 1.2 Kết quả — 63/63 VERIFIED có bằng chứng tồn tại

| Kiểu raw_records | Số hàng | Kết quả |
|---|---|---|
| Literal path tồn tại (vd `outputs/packguard/defense/defense_batch.jsonl`) | 44 | EXISTS từng path |
| Dir-shorthand (vd `round5_e0v2 records (480+480+240)`) | 9 | Dir tồn tại: `outputs/experiments/round3_e0/`, `round3_e2e3/`, `round5_e0v2/`, `round5_defense/`, `round7_rq8/`, `round7_7b/`, `outputs/packguard/r10/r7_mechanism_ablation/`, `reports/round5/`. Brace-path RG-24/RG-25 kiểm trực tiếp: `results_{granite2b,llama3b}.json` và 4 file `results_qwen7b__*.json` đều có |
| `same file(s)` (kế thừa hàng trước) | 6 | RG-02, RG-04, RG-05, RG-07, RG-08, RG-15 — chain về RG-01 (`outputs/experiments/round3_e0/{qwen3b,llama3b,granite2b}/results.json`), RG-06, RG-07, RG-14 — đều EXISTS |
| Prose-only raw_records | 3 | RG-11 (`recompute files`), RG-19 (`control result files`), RG-33 (`granite results + smoke json`) — path thật nằm ở cột `origin_script`; kiểm bằng `ls`: `round3_e8{,_llama3b}/recomputed/recompute_e8_monitor.json`, `results_{llama3b,qwen3b}__control.json`, `round3_e0/granite2b/results.json` + `round3_granite_smoke.json` — tất cả EXISTS |
| `raw_records = '-'` | 1 | PC-37 (claim timestamp prereg) — artifact ngầm `docs/packguard_prereg.md` (55,586 bytes, Sep 28) và `outputs/packguard/defense/defense_metrics.json` EXISTS |

**Không có hàng VERIFIED nào trỏ tới artifact thiếu.** Lưu ý 2 resolver-artifact của chính audit này (không phải lỗi ledger): các lượt resolve đầu tiên report MISSING cho RG-22/RG-28/RG-29 chỉ vì glob/thư mục con (`outputs/experiments/round6_ablation/results_*`, `outputs/transformer/codebert_eval_*_metrics.json` — 4 file, `data/raw/primevul_hf/primevul_{train,valid,test}_paired.jsonl`) — đã xác nhận tồn tại bằng `ls`/`find` trực tiếp.

### 1.3 Yếu điểm schema (khuyến nghị, không chặn)
1. **PC-37 `raw_records='-'`** — hàng duy nhất không có raw path; nên điền `docs/packguard_prereg.md`.
2. **RG-11, RG-19, RG-33** — `raw_records` là lời văn, path máy-đọc được chỉ nằm ở `origin_script`.
3. **6 hàng `same file(s)`** — không tự kiểm được nếu tách lẻ từng hàng (phụ thuộc hàng trước).
4. **9 hàng dir-shorthand** — trỏ tới thư mục, không khoá file kết quả cụ thể (RG-24/RG-25 đã khoá bằng brace, nên noi gương).

## §2. Check 2 — CONTRADICTED có được giải thích không

**Ledger không dùng status CONTRADICTED** (đếm: VERIFIED 63, PARTIALLY_VERIFIED 12, STALE 1, UNKNOWN 1; `EXPERIMENT_REGISTRY.jsonl` là run-registry không có trường status/verdict).

Contradiction duy nhất trong artifact tree: `outputs/master/master_results.json` → `contradictions`, **2 entry, đều có `resolution` + `reason`**:
1. `e8.llama3b.B0.unsafe_compliance_rate` 0.4 → 0.0333 — "USE RECOMPUTED (file_b)"; reason: V2 BUG-V3-1 monitor bỏ sót 3 refusal pattern + Unicode apostrophe; 11/12 false PARTIAL re-classified.
2. `e8.llama3b.B0_vs_P2_unsafe.mcnemar` p=0.000488 → 1.0 — cùng lý do; claim "P2 reduces unsafe compliance" **RETRACTED**.

Contradiction này đã được ledger hóa: **RG-12 (VERIFIED)** — "Audit recompute changed a headline E8 number (0.400→0.033) and withdrew an apparent defence win; both versions kept", khớp threats §7 của `paper/main.tex`.

Các status biên đều có giải thích trong ledger: **PC-36 STALE** (r16_analysis.json `status='pending'`, harness chưa re-run sau khi raw Kaggle về — số paper đã verify độc lập qua PC-34); **PC-35 PARTIALLY_VERIFIED** (số '.600' trong paper2 §6.2 là transcription slip, không khớp artifact 3B nào — explained inline); **RG-36 UNKNOWN** (external citations khai báo out-of-scope).

**Kết luận: không tồn tại contradiction nào chưa được giải thích.** Caveat: nếu chuẩn của pipeline yêu cầu CONTRADICTED là một status bắt buộc dùng khi phát hiện mâu thuẫn, thì ledger đang xử lý mâu thuẫn ngầm qua `master_results.json` + report audit chứ không qua cột status — đây là quyết định schema, không phải lỗi dữ liệu.

## §3. Check 3 — Claim quan trọng thiếu so với FINAL_STATUS.md

`FINAL_STATUS.md` (đọc toàn bộ 38 dòng) liệt kê các claim verify sau đây **chưa có hàng nào trong ledger**:

| # | Claim (FINAL_STATUS.md) | Bằng chứng trên đĩa (tồn tại, chưa ledger hóa) |
|---|---|---|
| M1 | "757 tests" (dòng 12) | `reports/round15/V2_report.md:178-180` — pytest 757 passed / 0 failed (86.5s). **Lưu ý: `SUBMISSION.md:16` vẫn ghi "pytest 743/0" — stale, chính V2 audit đã flag ISSUE-2 (V2_report.md:142)** |
| M2 | "verify_repro 30/30 (manifest 48 artifacts)" (dòng 12) | `reports/round15/V2_report.md:151-155` — 30/30 passed, manifest 48/48, value checks PASS |
| M3 | "Visual-judge: PackGuard 8/8, RefuseGuard 20/20 pass" (dòng 12) | Report visual-judge tồn tại (`reports/round10/LAYOUT_report.md`, `reports/round6/V1_report.md`) nhưng không hàng ledger nào pin con số 8/8 + 20/20 |
| M4 | "tectonic 0 error cả hai" (dòng 12) | Build claim — không hàng ledger |
| M5 | "MinHash 67 units" (dòng 17, P2-11-LCO) | PC-19 chỉ pin dd p=.368 + các giá trị LCO khác; tham số 67-unit không có hàng |
| M6 | "expansion +200 random benign (17 hard-negative, disclosed)" (dòng 17) | PC-13 pin expansion pooled stats nhưng không pin con số 17 hard-negative |

**Stale-vs-ledger:** `FINAL_STATUS.md` (mtime **2026-09-28 07:01:22 +07**) viết TRƯỚC AMENDMENT-9 Kaggle (`2026-09-28T13:54:28Z`) và commit Round-16 `fb8988a` (`2026-09-28T22:26:02+07` — "Round 16 integration: Kaggle 7B/8B results into paper2"). Do đó bảng BLOCKED của nó còn dòng **"P1-10 A5-GPU (7B/8B) — chờ phê duyệt gỡ <4B + GPU runtime"**, trong khi ledger **PC-34 (VERIFIED)** ghi nhận ladder llama8b/qwen7b đã chạy trên Kaggle và đã vào paper2. FINAL_STATUS cần cập nhật dòng P1-10 (và phần "đã chuyển thành Future Work" cho 7B/8B).

## §4. Việc đã chạy / không chạy

- **Đã chạy:** parse CSV + đếm status (python, session này); walk toàn cây + basename index; resolve/glob/brace cho 63 hàng VERIFIED; `ls`/`find` trực tiếp cho 12 tham chiếu nhập nhằng (round6_ablation, codebert_eval_*, primevul_hf, recompute files, control files, smoke json, prereg, defense_metrics.json, round7_rq8, round7_7b); grep CONTRADICTED trong RESEARCH_STATE + EXPERIMENT_REGISTRY.jsonl; đọc `master_results.json` contradictions block; so FINAL_STATUS.md với ledger bằng grep từng con số (757 / verify_repro 30/30 / 48 / MinHash 67 / hard-negative / tectonic / visual-judge); `git log -1` + `stat` FINAL_STATUS.md cho timeline.
- **Không chạy (ngoài scope lens B):** re-check giá trị số bên trong artifact (lens audit #1); verify external citations RG-36; chạy lại pytest/verify_repro (chỉ xác nhận bằng chứng report tồn tại).
