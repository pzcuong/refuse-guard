# DECISION LOG — PackGuard + RefuseGuard

Format mỗi transition: STATE / INPUTS / OUTPUTS / PASS_CRITERIA / AUDITERS / DECISION / NEXT_STATE (charter §25). Chỉ append; không overwrite (charter §2).

---

## DLOG-001 · DISCOVER → AUDIT_CURRENT_WORK · 2026-09-30

**STATE:** DISCOVER → **AUDIT_CURRENT_WORK** (chốt transition).

**INPUTS:**
- `RESEARCH_STATE/CURRENT_PAPER_AUDIT.md` — forensic audit 77 claim (63 VERIFIED / 12 PARTIALLY_VERIFIED / 1 STALE / 1 UNKNOWN; 0 UNSUPPORTED / 0 CONTRADICTED); session gates: `gen_paper_numbers.py --check` OK 336 macros, `verify_repro.sh` 30/30 + manifest 48/48 + tectonic PASS.
- `RESEARCH_STATE/AUDITS/ledger_audit_A.md` — cross-audit #1: 10 claim random (seed 20260930) reverse-trace về raw + 6 targeted + language-scan toàn bộ 77 rows + registry sample 11/2,810 → **0 mis-status**; 1 wording nit (RG-20), 1 gray zone (PC-08), 1 convention divergence (7B-excluded vs Kaggle-as-miss).
- `RESEARCH_STATE/AUDITS/ledger_audit_B.md` — cross-audit #2 (validity lens): **63/63 VERIFIED có raw artifact tồn tại trên đĩa**; contradiction duy nhất (E8-Llama 0.4→0.033) đã có resolution + reason trong `outputs/master/master_results.json` và ledger row RG-12; 6 mục FINAL_STATUS chưa ledger hóa; FINAL_STATUS stale ở P1-10.
- 3 ledger: `POSITIVE_RESULTS_LEDGER.csv` (20), `NEGATIVE_RESULTS_LEDGER.csv` (39), `CLAIM_EVIDENCE_LEDGER.csv` (77); `EXPERIMENT_REGISTRY.jsonl` (2,810).
- Kiểm độc lập của synthesizer (chạy trong session này): recount 4 file bằng `python3 csv.DictReader`/`wc -l` — 77/20/39/2,810 khớp cả 2 audit; grep "RQ" trong `paper2/main.tex` = 0 hit (PackGuard không dùng RQ numbering); xác nhận `SUBMISSION.md:16` ghi pytest **743/0** stale so với `reports/round15/V2_report.md:178-180` = **757 passed, 0 failed**.

**OUTPUTS:**
- `RESEARCH_STATE/PROJECT_INVENTORY.md` — inventory program + phân loại đủ **59/59 kết quả** theo 7 lớp §4 (CORE 8 / SUPPORTING 12 / NEG-BUT-USEFUL 14 / NULL-LOW 4 / WEAK-UNDERPOWERED 10 / OBSOLETE 4 / POTENTIALLY-MISLEADING 7) + punch-list 9 mục + định vị RQ distractor.
- File này (DLOG-001).

**PASS_CRITERIA (charter §3: "Không chạy large new experiments khi còn major artifact inconsistency"):**
- Major inconsistency: **KHÔNG CÒN** — 0 claim UNSUPPORTED/CONTRADICTED; 0 VERIFIED trỏ artifact mất; 0 mis-status; 0 contradiction chưa giải thích; registry sampling sạch. → **PASS.**
- Còn lại chỉ là inconsistency **value-level đã ledger hóa** (PC-35/PC-21/PC-29/PC-36, RG-28/RG-32 wording, doc-stale SUBMISSION 743→757 + FINAL_STATUS P1-10) — không đổi kết luận nào, đưa vào punch-list camera-ready; không chặn transition.

**AUDITERS:** Current-Paper Forensic Auditor (doc chính) · ledger-audit-A (random reverse-trace, độc lập) · ledger-audit-B (validity lens, độc lập) · synthesizer (recount + reconcile, không tự validate phát hiện mới — chỉ đối chiếu 3 nguồn đã audit chéo nhau).

**DECISION:**
1. **Chấp nhận ledger state làm nền ra quyết định** — audit pipeline qua 3 lớp độc lập, hội tụ 0 mâu thuẫn.
2. **Paper mạnh nhất = PackGuard** (`paper2/main.tex`, bài gộp Q1; 4 core positives: POS-15 TOST, POS-17 D1 defense, POS-20 safety channel, generalization PC-34 Kaggle). Companion RefuseGuard giữ vai trò protocol/mechanism.
3. **RQ distract = RQ6** (joint safety–utility / gate-first P2): positive duy nhất là by-construction (POS-03, wording khóa), 1 headline đã retract (NEG-16), 1 system failure lịch sử (NEG-17), duy trì frame refusal mà charter §20 cấm mở đầu. → hạ mức: nội dung đo được của nó (gate 30/30 + NEG-35 caveat) gộp vào phần pipeline/limitations; không đầu tư thêm round nào vào RQ6. RQ5 hạ APPENDIX (NEG-08 underpowered). RQ1/RQ3 giữ làm framing; RQ9 giữ (boundary, load-bearing cho scale-resolution paper2).
4. **Negative disposition chốt** (chi tiết PROJECT_INVENTORY §4): giữ main 15 (NEG-01/02/04/07/11/12/14/15/24/26/27/28/31/35 + NEG-39 as-limitation); appendix 13 (NEG-05/06/08/10/13/17/21/22/23/25/29/30/32); 1 câu 3 (NEG-03, NEG-38, POS-13 sanity); retraction-note 5 (NEG-09/16/18/19/20); ledger-only 4 (NEG-33/34/36/37).
5. **Punch-list 9 mục camera-ready** (PROJECT_INVENTORY §6): PC-35 (.600→.433 sai — sửa thành 1.000→.4333 hoặc A4→A5), PC-21 (.735→.747), PC-29 (n=500→n_test=79), PC-36 (regen r16_analysis.json), RG-32 (473 vs 960 parenthetical), RG-28 (comment-path), SUBMISSION.md 743→757 + FINAL_STATUS P1-10 stale, schema minor (PC-37 raw_records, 2-convention note), optional PC-08 strip recompute.

**NEXT_STATE:** **LITERATURE_SEARCH** (charter §5). Scouts nhập từ NEG-39 (adaptive red-team, repo-level realism, frontier attack, human-κ, OSF chưa chạy) + gap-question "adaptive robustness của D1-strip và baseline defense hiện đại reproduce-được". Điều kiện vào METHOD_CANDIDATES: ≥3 gap agents độc lập, novelty matrix cập nhật 2026. Chưa chạy large new experiment cho đến khi punch-list mục 1–4 (paper-facing) xong.

---

## DLOG-002 · (placeholder rỗng — append transition kế tiếp tại đây)
