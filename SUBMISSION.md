# SUBMISSION.md — Trạng thái chốt nộp bài (2 bài)

Cập nhật: 2026-09-28 (W2, vòng 15). Trạng thái competitive-plus theo
đánh giá round-13/14 (`reports/round13/F_report.md` §6,
`reports/round14/V_report.md` verdict PASS). Tài liệu con:
`submission/venue_fit.md`, `submission/cover_letter.md`,
`submission/artifact_list.md`.

## 0. Bản thảo đã compile + kiểm tra (S1, vòng này)

| Bài | PDF | Trang | Compile | Kiểm tra nội dung |
|---|---|---|---|---|
| Paper 1 — RefuseGuard | `submission/RefuseGuard_ms.pdf` (từ `paper/main.tex`) | **20** | tectonic exit 0 | `??` = 0; placeholder token = 0 (PLACEHOLDER/TODO/TBD/XXX/`{{`/`R1x:`/macro ròng) |
| Paper 2 — PackGuard | `submission/PackGuard_ms.pdf` (từ `paper2/main.tex`) | **8** | tectonic exit 0 | như trên + `round-N` = 0, `AMENDMENT-N` = 0, `R13:` = 0 |

Gates repo tại thời điểm chốt: pytest **743/0**;
`scripts/verify_repro.sh` **30/30 exit 0**;
`make_manifest.py --check` **48 ok / 0 mismatch**;
`gen_paper_numbers.py --check` OK (336 macro, xác nhận round-13).

## 1. PAPER 1 — RefuseGuard (20 trang, ACM sigconf review/anonymous)

**Venue đề xuất** (theo `docs/literature_review.md` §5 — verdict:
"first systematic joint evaluation" scoped cho LLM-based vulnerability
analysis; fallback claim = robust analysis under untrusted code context):
thứ tự khuyến nghị và lý do đầy đủ trong `submission/venue_fit.md` §2 —
1) Computers & Security (sau khi Paper 2 có quyết định), 2) EMSE,
3) TDSC, 4) TOSEM. **Không nộp cùng venue với Paper 2 trong cùng thời
điểm** (Paper 2 cite bài này như prior work — disclosed).

**Claims chính** (số truy vết `outputs/master/` +
`reports/round3/S_report.md` §5):
1. E0 reproduction gate FAIL → pivot (pre-registered): RR = 0.000 mọi arm
   × 3 model 2–3B, McNemar p = 1.0 — defensive wording không kích refusal
   trên task vulnerability; refusal pathway còn hoạt động (probe orbench:
   125/225 refused).
2. Untrusted context: C2/C3 không phá usability (UAC ≈ 1.0) nhưng
   injection-style context làm flip dự đoán; P1 isolation giảm IPI-flip
   0.742 → 0.484 (McNemar p = 0.0078); vulnerable-only subset n.s. (p=0.5).
3. P2 pipeline: safety by construction (intent gate trước LLM call);
   fixed monitor không còn che refusal; over-refusal phía safe KHÔNG tăng
   (Qwen 0.233 → 0.000, p = 0.0156).
4. CodeBERT fallback + fusion: usable-answer coverage 0.985 → 1.000;
   transformer-only MCC 0.232 / VD-S 0.962 (subsample 25k, disclosed).
5. Boundary: RQ8 corruption channels generalize trên CWE mới;
   RQ9 harm-absent tại 7B cùng family (p = 0.7266) — scale/family caveat.

**Artifact list**: `submission/artifact_list.md` §1 (code, manifests,
outputs bundle 48 file checksummed, pre-registrations, audit trail).

**Prerequisites còn lại (3 mục BLOCKED — user):**
| Mục | Nội dung | Trạng thái |
|---|---|---|
| P1-7 | OSF upload + timestamp cho artifact bundle | **Blocked-by-user** (cần OSF từ user) |
| P1-8 | Frontier-API consult record (ChatGPT-MCP) | **Blocked-by-user** (not_authenticated nhiều vòng; cần login) |
  - READY-TO-RUN: scripts/frontier_safety_runner.py (OpenAI/Anthropic/Gemini, stdlib-only) + submission/osf_registration_bundle.md (AMENDMENT-1..8, ready to paste) — chỉ chờ key/account từ user.
  - P1-10 (A5 trên GPU): DEFERRED — ràng buộc model <4B (7B/8B weights đã dọn); cần GPU runtime khác để mở lại.
| KB human-κ | Human validation / annotator agreement cho KB entries + refusal monitor | **Blocked-by-user** (theo tasking vòng 15; không có artifact nguồn trong repo — ghi nhận trung thực) |

**Readiness từng mục:** bản thảo/claims/số/provenance = **Done** (compile
+ checks xanh); venue plan = **Done** (`venue_fit.md`); cover letter =
n/a cho vòng này (ưu tiên Paper 2); artifact bundle = **Done — chờ
OSF**; 3 prerequisites trên = **Blocked-by-user**, không chặn nộp PDF
nhưng chặn artifact-review track.

## 2. PAPER 2 — PackGuard (8 trang, ACM sigconf anonymous)

**Venue đề xuất**: `submission/venue_fit.md` §2 — 1) **Computers &
Security** (venue #1, cover letter draft sẵn: `submission/cover_letter.md`),
2) TOSEM (tiền lệ Cerebro TOSEM 2024), 3) EMSE, 4) TDSC.

**Scope (pilot, disclosed trong bài):** 603 mẫu provenance-tracked
(390 malicious wild-capture + 213 benign popularity-derived; npm 421 /
PyPI 182), 2 ecosystems, model 2–3B local decoding, FL/SimTrust là
simulation disclosure. Mọi claim đã scope đúng mức này.

**Claims chính — đã qua kiểm định:**
1. **Attack (pre-registered, paired):** advisory inert làm recall trên
   malicious package đổi NGƯỢC chiều theo family — granite-3.3-2B
   .667→.833, Llama-3.2-3B .167→.042 (đo paired); n=100: granite tăng
   recall kèm FP benign 0→2/100, llama sập (8/8 flip mal→ben là llama).
   RR=0 trên ĐÚNG 2,700 defensive-task generations 2–3B — structural
   blocking-absence (floor effect: không được đọc là "blocking vô dụng").
2. **Defense (pre-registered 2 chiều, audit round-12):** AST-gated
   comment/docstring strip — strip(P2)==strip(original) byte-for-byte
   38/38; granite NEUTRALIZED (23/23 verdict = baseline, 4/4 flips
   revert, FP 0/14); llama KHÔNG restore — cost đo được, quy về 1 package
   family (1/19 mọi condition). Mọi p trong phần này descriptive
   (smallest exact McNemar p = .125).
3. **Detector nền (TOST, AMENDMENT-5 trước run, 360 runs mock=false):**
   FedAvg ≡ strong-centralized ở margin ±.02 F1 — group/graph ΔF1
   −.0065, 90% CI [−.0133,+.0003] PASS; group/hashing + random/hashing
   PASS; random/graph FAIL có hướng (centralized thắng trên split
   leakage-prone — disclosed). Graph thắng trivial 5-feature:
   +.0227 group / +.0487 random, exact Wilcoxon p 1.9e-5 / 1.9e-6
   (subtest 500 non-empty: p=.0012/1.9e-6 → không phải shortcut).
4. **Family shift (LCO, AMENDMENT-7 trước metric, 480 rows):** null hai
   chiều có power (dd = −.0095±.0803, exact Wilcoxon p = .368; power ≈.75
   tại δ=.05) — KHÔNG claim robustness ranking.
5. **GuardDog baseline (pre-registered trước scan, audit round-14 PASS):**
   F1 .866/.874 group split (thua graph .923–.928); top trên LCO t0.30
   seed khó nhất (.857/.876), đảo dấu ở t0.50 → "comparable, not
   superior" + same-origin DataDog bias (optimistic recall) disclosed.
6. Negative results đi kèm bài: tfidf-degradation retracted (baseline
   artifact); mechanism ablation null-low-power; KB neutral (mixed-sign,
   < seed-std); FedProx μ không tách ở metric level (fix routing đã test).

**Prerequisites còn lại:** cùng 3 mục BLOCKED-by-user ở §1 (dùng chung
hạ tầng artifact); ngoài ra validation-locked threshold + FP-directed
advisory arm = queued future work (đã ghi trong A.6 của bài, không chặn).

**Readiness từng mục:** bản thảo/claims/statistics/provenance = **Done**;
cover letter = **Done (draft)**; venue plan = **Done**; artifact list =
**Done**; OSF/frontier/κ = **Blocked-by-user**.

## 3. Thứ tự hành động đề xuất cho user
1. (User) Cung cấp OSF + login frontier API + quyết định human-κ plan —
   gỡ 3 blocker artifact-track.
2. Nộp Paper 2 → Computers & Security (draft cover letter sẵn; điền
   danh tính khi bỏ anonymous).
3. Paper 1 → EMSE hoặc C&S (sau khi Paper 2 có quyết định / venue khác).
4. Không git commit từ tác nhân (orchestrator lo); bundle đóng gói theo
   `submission/artifact_list.md` sau khi có LICENSE decision.
