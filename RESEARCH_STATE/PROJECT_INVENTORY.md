# PROJECT INVENTORY — PackGuard + RefuseGuard

State transition: **DISCOVER → AUDIT_CURRENT_WORK** (charter §25) · Synthesized: 2026-09-30
Synthesizer: ledger-synthesis agent · Inputs: `CURRENT_PAPER_AUDIT.md` + `AUDITS/ledger_audit_A.md` +
`AUDITS/ledger_audit_B.md` + 3 ledger CSV + registry (row counts re-run by this agent, §1.2).

---

## 1. Inventory của program (what exists, re-counted this session)

### 1.1 Deliverables
| Bài | File | Vai trò |
|---|---|---|
| **PackGuard** | `paper2/main.tex` (8 trang, `submission/PackGuard_FINAL.pdf`) | **Bài gộp Q1 — PAPER MẠNH NHẤT** (FINAL_STATUS.md §1). Không dùng đánh số RQ (grep "RQ" trong paper2/main.tex = 0 hit — kiểm bởi agent này). |
| **RefuseGuard** | `paper/main.tex` (20 trang, `submission/RefuseGuard_FINAL.pdf`) | Companion. RQ1–RQ9 + RQ7b (`paper/sections/05_results.tex:76,109,135,146,165,179,204,308,397,443`). |

### 1.2 Research-state assets (kết quả đếm lại bởi agent này, không copy từ audit)
| Asset | Kích thước | Kiểm |
|---|---|---|
| `CLAIM_EVIDENCE_LEDGER.csv` | 77 claim (PC-01..40 paper2, RG-01..37 paper) | `python3 csv.DictReader` → **VERIFIED 63 / PARTIALLY_VERIFIED 12 / STALE 1 (PC-36) / UNKNOWN 1 (RG-36); 0 UNSUPPORTED, 0 CONTRADICTED** — khớp bảng §1 của CURRENT_PAPER_AUDIT và cả 2 audit chéo |
| `POSITIVE_RESULTS_LEDGER.csv` | 20 (POS-01..20) | 8 CORE + 12 SUPPORTING; disposition: KEEP_MAIN 18 / APPENDIX 1 / SANITY_1LINE 1 |
| `NEGATIVE_RESULTS_LEDGER.csv` | 39 (NEG-01..39) | 14 NBSU / 10 WU / 7 PM / 4 OBSOLETE / 4 NULL-LOW; disposition: KEEP_MAIN 15 / APPENDIX 13 / RETRACTION_NOTE 5 / LEDGER_ONLY 4 / SANITY_1LINE 1 / KEEP_AS_LIMITATION 1 |
| `EXPERIMENT_REGISTRY.jsonl` | 2,810 rows | `wc -l` = 2,810 (khớp audit A §3b: 2,657 mock=False / 104 None / 49 True) |
| `MODEL_REGISTRY.json` / `DATASET_REGISTRY.json` | tồn tại (11.4KB / 13.6KB) | — |
| Gates đã chạy (session audit, CURRENT_PAPER_AUDIT §2) | `gen_paper_numbers.py --check` OK 336 macros; `verify_repro.sh` 30/30, manifest 48/48; tectonic PASS | — |
| Gates CHƯA chạy trong pass này | pytest 757 (757/0 theo `reports/round15/V2_report.md:178-180`, không re-run); external citations RG-36 | — |

### 1.3 Models & compute scope
Local 2–3B: Qwen2.5-Coder-3B (488639f1), Llama-3.2-3B (unsloth 006f5dcd), granite-3.3-2b, pilot 0.5B,
CodeBERT 125M — tất cả trong ràng buộc <4B (CURRENT_PAPER_AUDIT §6). Kaggle GPU 7B/8B đã chạy
(AMENDMENT-9 đăng ký 2026-09-28T13:54:28Z TRƯỚC push; kernels packguard-p110-p18 / packguard-p110-llama8b;
660 rows đã verify — PC-34). Không frontier API (runner stdlib sẵn sàng, chờ user key — P1-8).

## 2. Inputs của transition (đã đọc toàn bộ)
1. `RESEARCH_STATE/CURRENT_PAPER_AUDIT.md` — forensic 77 claim: 63 V / 12 PV / 1 STALE / 1 UNKNOWN; 6 finding value-level (§4 của nó), 0 conclusion-level.
2. `RESEARCH_STATE/AUDITS/ledger_audit_A.md` — cross-audit #1 (reverse-trace): 10/77 claim random (seed 20260930) + 6 targeted + language-scan 77 rows → **0 mis-status**; 1 wording nit (RG-20 "control"), 1 gray zone (PC-08), 1 convention divergence (7B excluded-vs-Kaggle as-miss).
3. `RESEARCH_STATE/AUDITS/ledger_audit_B.md` — cross-audit #2 (validity lens): **63/63 VERIFIED có raw path tồn tại**; 0 contradiction chưa giải thích; 6 mục FINAL_STATUS chưa ledger hóa + FINAL_STATUS stale dòng P1-10.
4. `RESEARCH_STATE/POSITIVE_RESULTS_LEDGER.csv` (20), `NEGATIVE_RESULTS_LEDGER.csv` (39), `CLAIM_EVIDENCE_LEDGER.csv` (77).
5. `DIRECTOR_CHARTER.md` §4 (7 lớp) + §18 (xử lý negative) + §20 (cấu trúc paper) + §25 (state machine).
6. Kiểm độc lập của agent này: recount 4 CSV/JSONL (§1.2), grep RQ trong 2 paper, xác nhận `SUBMISSION.md:16` ghi "pytest 743/0" trong khi `reports/round15/V2_report.md:178-180` xác nhận **757/0** (stale thật, đúng như audit B M1).

## 3. Phân loại TOÀN BỘ 59 kết quả theo 7 lớp §4 (charter: CORE POSITIVE / SUPPORTING POSITIVE / NEGATIVE BUT SCIENTIFICALLY USEFUL / NULL-LOW VALUE / WEAK-UNDERPOWERED / OBSOLETE / POTENTIALLY MISLEADING)

### Lớp 1 — CORE POSITIVE (8)
| ID | Nội dung | Anchor |
|---|---|---|
| POS-01 | Untrusted context shift verdicts, không mất coverage (SIUD≈0; McNemar C3 p=1.2e-05 qwen) | paper1 backbone, 3 models paired |
| POS-06 | Verdict-bias FP drift (llama FP .817→1.000 p=9.8e-04; granite 0→.667/.833) — finding 2 headline paper1 | round6_bias.json |
| POS-07 | VCI direction-symmetry: attack FP-way vs defence FN-way | cơ chế hợp nhất Finding 1+2 |
| POS-09 | Ablation ladder A0→A5: rung reassertion đơn lẻ sập llama recall 1.000→.433 (p=7.45e-09) — mechanism | round6_ablation.json |
| POS-11 | RQ8 CWE generalization: granite 4/4 families, pooled p=8.88e-16 sống Bonferroni | round7_master.json |
| POS-15 | TOST ±.02 F1: FedAvg == strong centralized (group/graph CI [-.0133,+.0003] PASS, 20 seeds) — primary claim paper2 | p0_results.json, AMENDMENT-5 |
| POS-17 | D1 AST-strip trung hòa advisory channel trên granite (38/38 byte-equal; 23/23 verdicts; FP 0/14) — defense headline paper2 | defense_analysis.json, AMENDMENT-6 |
| POS-20 | Advisory-in-package shifts verdict sensitivity theo family (n60 + n100, corrected reading) | safety_metrics_n60.json (mv2) |

### Lớp 2 — SUPPORTING POSITIVE (12)
POS-02 (P1 isolation giảm IPI-flip .742→.484, kèm bắt buộc NEG-07) · POS-03 (P2 gate 30/30 **by-construction** — wording khóa) · POS-04 (CodeBERT B4 baseline, mirror-v0.1 disclosure) · POS-05 (C5 query-relevant 100/100, anti-leakage 0/100 — validity của NEG-02) · POS-08 (advisory echo granite 12/20 vs llama 2/11) · POS-10 (extension FP n=100 p=1.53e-05 — power) · POS-12 (A1 safe ở 7B, H_R2) · POS-13 (refusal pathway functional 125/225 — sanity 1 câu) · POS-14 (KB buildable 60/60 tại 3B) · POS-16 (graph beats trivial +.0227/+.0487) · POS-18 (MalGuard-style không thắng graph; Holm n.s. — wording khóa) · POS-19 (GuardDog baseline "comparable, not superior").

### Lớp 3 — NEGATIVE BUT SCIENTIFICALLY USEFUL (14)
| ID | Nội dung | Disposition (quyết định cuối, §4) |
|---|---|---|
| NEG-01 | E0 gate FAIL (dRR=0, 3/3 models) — founding negative | **GIỮ MAIN** (framing, n=20 disclosure verbatim) |
| NEG-02 | E0-V2 C5 blocking null (1,200 records, H_A/B/C 0/3) | **GIỮ MAIN** (founding, khóa scope 2–3B) |
| NEG-03 | RR=0/2,700 defensive generations — floor boundary | **1 CÂU** trong paper2 (đã có) |
| NEG-04 | Refusal-monitor validity split (qwen over-refusal .520) | GIỮ MAIN (bảng validity) |
| NEG-05 | Granite unsafe-compliance .538 trên n=13 probes | **APPENDIX** + footnote |
| NEG-06 | E5 DRR undefined + carrier-strip bias (C3 recall 1.000 by construction) | **APPENDIX**; 1 câu bắt buộc wherever E5 cited |
| NEG-14 | RQ9 reassertion-harm absent ở 7B (p=.7266) + family confound | **GIỮ MAIN** (boundary; 3 caveats bắt buộc) |
| NEG-17 | P2-cu pushed unsafe compliance 0.040→1.000 (refusal-suppression) | **APPENDIX** (2 câu design-rationale) |
| NEG-23 | tfidf-FedAvg degenerate all-malicious predictor | **APPENDIX** (measurement-integrity) |
| NEG-24 | Random-split TOST FAIL directional (dF1 -.016, Holm .0247) | **GIỮ MAIN** verbatim cạnh POS-15 — anti-soft-washing |
| NEG-26 | D1 cost trên llama (restores nothing; 4 versions/1 family) | **GIỮ MAIN** first-class cạnh POS-17 |
| NEG-28 | LCO two-directional null (dd p=.368; equivalence ±.02 NOT established) | **GIỮ MAIN** (đoạn null trung thực §5.4) |
| NEG-30 | GuardDog recall ceiling + FN structure (25 no-rule + 56 med/low-only) | **APPENDIX** (bản corrected) |
| NEG-35 | Lexical gate 1/50 paraphrase — instrument limit | **GIỮ MAIN** footnote với POS-03/RG-31 |

### Lớp 4 — NULL-LOW VALUE (4)
NEG-25 (KB ablation neutral — APPENDIX + 1 câu) · NEG-32 (+200 benign data-pack, 17 hard-negative — APPENDIX 1 câu, không phải evidence) · NEG-38 (bookkeeping corrections batch — **SANITY 1 CÂU** provenance + ledger) · NEG-39 (planned-not-run: adaptive, repo-level, frontier, human-κ, OSF — **KEEP_AS_LIMITATION**, never results).

### Lớp 5 — WEAK-UNDERPOWERED (10)
NEG-07 (E6 vul-stratum p=.5 — **GIỮ MAIN**: bắt buộc cạnh POS-02) · NEG-08 (E7 fusion pilot 0.5B — APPENDIX, ≤1 câu) · NEG-10 (E4 near/far descriptive — APPENDIX, cấm cite hướng) · NEG-11 (B2 content-attribution CI cover 0 — GIỮ MAIN hedged sentence, sufficiency claim là phần dùng được) · NEG-12 (qwen saturation — GIỮ MAIN footnote bắt buộc) · NEG-15 (llama RQ8 2/4 anti-masking — GIỮ MAIN, charter §13) · NEG-22 (collapse cell .375 re-attributed undertraining — APPENDIX sensitivity) · NEG-27 (pooled n=47 all-p descriptive — GIỮ MAIN: per-model primary) · NEG-29 (GuardDog LCO 1-seed sign-flip — APPENDIX footnote) · NEG-31 (MalGuard 8/8 TOST FAIL + 0/8 Holm — GIỮ MAIN hedged wording).

### Lớp 6 — OBSOLETE (4)
NEG-13 ("P3 harms only with advisory" REFUTED bởi C0×P3 control — APPENDIX, 1 câu falsification-example) · NEG-19 (tfidf-degradation retracted 2 lần — RETRACTION paragraph paper2, grid giữ nguyên cho audit) · NEG-21 (FedProx bit-identical = routing bug — APPENDIX threats) · NEG-33 (R1 dry-run mock-only claim — **LEDGER_ONLY**, không paper text nào còn cite).

### Lớp 7 — POTENTIALLY MISLEADING (7) — tất cả đã RETRACTED/CORRECTED, residue = retraction note
NEG-09 ("2/2 fallback correct" không artifact — retraction note + regression guard) · NEG-16 (E8-Llama 0.400→0.033 monitor bug — retraction note, papers dùng recomputed) · NEG-18 (SIUD +0.258 schema mismatch → 0.000 — ledger-only) · NEG-20 ("FedAvg harms minority" artifact — 1 mệnh đề trong retraction paragraph) · NEG-34 (R1 instrument batch: VD-S fake, monitor blind, bib, seq-len — LEDGER_ONLY, fixed) · NEG-36 (Fig. 8(a) wrong series — LEDGER_ONLY, assert-guard fix) · NEG-37 (bench-overlap "fully fresh" sai 22/16 ids — LEDGER_ONLY, [CORRECTED-R7]).

**Tổng: 8 + 12 + 14 + 4 + 10 + 4 + 7 = 59/59 kết quả đã phân loại.** Không kết quả nào nằm ngoài 7 lớp.

## 4. TRẢ LỜI: negative nào giữ / appendix / 1 câu

**Giữ ở main text (15 — boundary/motivating/mechanism caveats, charter §18):**
NEG-01, NEG-02 (founding framing — nhưng theo charter §20 KHÔNG mở đầu bằng refusal-transfer failure; đặt ở motivation/gate section); NEG-04, NEG-07, NEG-11, NEG-12, NEG-14, NEG-15 (caveats bắt buộc biến POS-02/POS-06/POS-11/POS-12 thành defensibles); NEG-24, NEG-26, NEG-27, NEG-28, NEG-31, NEG-35 (honesty guards trong results: TOST random-split cost, llama D1 cost, per-model-primary, LCO null, Holm non-sig, lexical-gate limit). NEG-39 → limitations/future-work section (không phải results).

**Chuyển appendix (13):** NEG-05, NEG-06, NEG-08, NEG-10, NEG-13, NEG-17, NEG-21, NEG-22, NEG-23, NEG-25, NEG-29, NEG-30, NEG-32. Trong đó NEG-06 và NEG-23 mang **warning sentence bắt buộc** wherever cited (bias-by-construction / old-pipeline numbers).

**Thành 1 câu (3):** NEG-03 (boundary RR=0/2,700 trong paper2 — đã đúng 1 câu), NEG-38 (1 câu provenance gộp + ledger), và POS-13 (1 câu validity cạnh mọi claim RR=0 — sanity line, không phải negative).

**Không vào paper (9):** 5 retraction notes đã nằm sẵn trong paper (NEG-09, NEG-16, NEG-18, NEG-19, NEG-20 — residue ledger-only) + 4 LEDGER_ONLY (NEG-33, NEG-34, NEG-36, NEG-37).

## 5. TRẢ LỜI: RQ nào đang distract từ paper mạnh nhất

**Paper mạnh nhất = PackGuard (`paper2/main.tex`, bài gộp Q1, FINAL_STATUS.md §1)** — 4 core positives riêng (POS-15 TOST, POS-17 D1 defense, POS-20 safety channel, + generalization via PC-34 Kaggle), mỗi claim đều VERIFIED/độc lập recompute.

**RQ distract: RQ6 ("Joint safety–utility: naive recovery is dangerous; gate-first P2", `paper/sections/05_results.tex:179`).** Lý do, mọi mốc đều trace được:
1. Positive duy nhất còn đứng của RQ6 là POS-03 — **by-construction**, wording đã khóa "must not read as 'P2 makes the model safer'" (POS-03 rationale): không phải hiệu ứng đo đạc trên model.
2. Lịch sử đo của RQ6 chứa 1 headline bị retract (NEG-16: B0 0.400→0.033, apparent defence win withdrawn — ledgered RG-12, disclosed paper §7) và 1 system failure thật (NEG-17: 0.040→1.000 refusal-suppression).
3. RQ6 duy trì frame refusal-safety-pipeline — đúng frame mà charter §4/§20 cấm mở đầu — trong khi khoa học đo được của companion là verdict-corruption (RQ2/RQ7/RQ7b/RQ8: POS-01/06/07/09/10/11) và PackGuard không cần nó (kênh safety của paper2 đo trực tiếp bằng POS-20, defense bằng POS-17).
4. Chi phí > lợi ích: 2 retraction notes + 1 appendix item (NEG-17) + 1 mandatory caveat (NEG-35) đều treo trên RQ6.

**Không phải distract:** RQ1/RQ3 (founding negatives + consequence — giữ làm framing/motivation, RQ3 paper đã tự viết là consequence của RQ1/RQ2 tại `05_results.tex:143`); RQ9 (boundary story, giờ là load-bearing cho scale-resolution của paper2 qua PC-34 Kaggle — chính PC-35 cần nó để sửa); RQ5 (yếu — NEG-08 underpowered — nhưng chỉ là 1 subsection, hạ APPENDIX là đủ, không cần cắt RQ).

## 6. Cross-audit convergence & residual punch-list (trước camera-ready)

Convergence: cả 3 nguồn (audit doc + A + B) và recount của agent này **không có bất kỳ mâu thuẫn số nào**: 0 UNSUPPORTED / 0 CONTRADICTED; 63/63 raw-path tồn tại; 0 mis-status trong 16 reverse-traces; contradiction duy nhất (E8) đã có resolution + ledger row.

Punch-list value-level (none conclusion-level — CURRENT_PAPER_AUDIT §4):
1. PC-35: sửa ".600→.433, p=3.4e-7" trong paper2 §6.2 → 3B là **1.000→.4333** (p=1.16e-10) hoặc A4→A5 .898→.4333 (chi2-cc 3.35e-7); .600 là A0 của **8B**.
2. PC-21: GuardDog LCO lower bound ".735" → ".747" (min artifact .7473).
3. PC-29: "n=500" → nói rõ n_test=79 của with-graph subset 500.
4. PC-36 (STALE): re-run `kaggle_pkg/analysis.py` để regen `r16_analysis.json` (status vẫn "pending" dù raw đã về 14:26/14:56Z).
5. RG-32: thêm parenthetical "473 = deduplicated V2-audit count; raw run+control = 960".
6. RG-28: sửa comment-path `tab_codebert.tex` (thêm `transformer_b4.`).
7. Doc-stale: `SUBMISSION.md:16` "pytest 743/0" → **757/0** (đã xác nhận bởi agent qua V2_report.md:178-180); `FINAL_STATUS.md` bảng BLOCKED còn dòng P1-10 (7B/8B) trong khi Kaggle đã chạy (AMENDMENT-9, PC-34).
8. Schema minor: PC-37 `raw_records='-'` → điền `docs/packguard_prereg.md`; RG-11/19/33 prose-only raw_records; thêm 1 chú thích 2 convention unparseable (7B exclude vs Kaggle as-miss — audit A §4.3).
9. Gray zone PC-08 (strip byte-identity toàn gần round-12 V1 recompute, không per-sample recompute session này) — optional recompute nếu auditor tương lai phản đối.

## 7. Outputs & Next
- Outputs: file này + `RESEARCH_STATE/DECISION_LOG.md` (bản ghi transition chính thức).
- Next state: **LITERATURE_SEARCH** (charter §25→§5). Inputs cho scouts: NEG-39 (adaptive attacks, repo-level realism, frontier, human-κ, OSF chưa chạy), gap-question "adaptive robustness của D1 + open-source defense baseline hiện đại". Không chạy large new experiment trước khi punch-list xong (charter §3: không chạy large mới khi còn artifact inconsistency — hiện chỉ còn inconsistency **value-level đã ledger hóa**, không chặn decision).
