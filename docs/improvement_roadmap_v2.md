# Improvement Roadmap v2 — PackGuard (post round-9 audit)

Ngày: 2026-09-25. Nguồn: kết quả audit các action (stats-1..8, safety-1..6,
novelty-2..8 — verdict accepted/modified) + reports/round9/{V1,V2,W1,W2}_report.md.
Phiên 2026-09-25 đã áp TOÀN BỘ phần write-only vào `paper2/main.tex`
(compile `tectonic main.tex` exit 0); tài liệu này là kế hoạch chạy cho TOÀN BỘ
newRun còn lại. Không mục nào dưới đây đã được chạy.

Cập nhật 2026-09-26 (workflow round 1, `r1_stabilized_central`): arm
centralized-stabilized — mục **R2 dưới đây — ĐÃ CHẠY và ĐÃ AUDIT**
(verdict: "Round 1 verified", trace OK; 80/80 cell thật) — xem khối
«Đã chạy + audit» trong R2 và mục mới **R2b**. Trạng thái các mục khác
không đổi so với phiên 2026-09-25. `paper2/main.tex` đã nhập số của arm
này (compile `tectonic main.tex` exit 0, kiểm tra lại 2026-09-26).
<!-- % SRC: outputs/packguard/r10/r1_stabilized_central/{results.jsonl,summary.md}; audit round 1 verdict "verified" -->

Cập nhật 2026-09-26 (vòng 2, `r2_grid_refresh`): grid FL ĐÃ refresh + ĐÃ AUDIT
(verdict "verified"; 640/640 row thật, `config_sha16 e0cd260b014556bb` khớp
vòng 1) kèm `probs_dump.jsonl` mới (19,484 prob per-sample cho 160 cell
centralized) — xem khối «Đã chạy + audit vòng 2» trong mục R1 và mục mới
**R2c**. Ba risk audit: (i) fedavg ≡ fedprox identical (F1, AUC) 160/160 →
grid thực chất 3 model riêng biệt, so sánh fedavg-vs-fedprox vacuous; (ii)
cell ecosystem/random/tfidf fedavg seed-invariant (F1 0.78392, std 0.0000);
(iii) tầng inferential round-9 STALE — summary.md self-label n=5
(AMENDMENT-3), Wilcoxon/McNemar chưa recompute trên grid refresh → R2b(a)
mở rộng thành "regenerate toàn bộ tầng inferential".
<!-- % SRC: outputs/packguard/r10/fl_multiseed/{grid_results.json,summary.md}; outputs/packguard/r10/r2_grid_refresh/probs_dump.jsonl; audit round 2 verdict "verified" -->

Cập nhật 2026-09-26 (vòng 3, `r3_calibration`): calibration + threshold sweep +
class-weight arm ĐÃ CHẠY và ĐÃ AUDIT (verdict "verified"; mọi keyNumber tái lập
từ raw) — xem khối «Đã chạy + audit vòng 3» trong mục R3. Ba điểm mang đi:
(i) **0/40 cell all-malicious** → tfidf KHÔNG phải trivial all-malicious
classifier (narrative near-degenerate của vòng 1 thu hẹp về arm
early-stopping); (ii) **class-weight là negative intervention** (xấu 3/4
group), KHÔNG phải remedy; (iii) **sweep threshold hiện chạy trên pooled
test = ORACLE** (code-read của updater, khớp chỗ trống reviewer flag) → mục
mới **R3b** validation-locked bắt buộc trước khi dùng 0.8955. R2b/R2c
(inference 20-seed + FedProx) VẪN chưa chạy — ưu tiên reviewer: làm CÙNG LÚC.
<!-- % SRC: outputs/packguard/r10/r3_calibration/*; audit round 3 verdict "verified"; ưu tiên từ harsh-review vòng 3 (wording/priority) -->

Cập nhật 2026-09-26 (vòng 4, `r4_kb_v3`): KB-v3 pure-join re-run ĐÃ CHẠY + AUDIT
(verdict "verified") — **phiên bản rút gọn: 1 seed (20260922), graph block
only, fedavg+centralized** — xem khối «Đã chạy + audit vòng 4» trong R5. Đọc
đúng: centralized +0.0103/+0.0112 (khớp cỡ +1.0 của round-8), fedavg
−0.0009/−0.0224 — **mixed sign, mọi delta < seed-std → không có statistical
claim, không được viết "KB helps"**; giá trị thật là pipeline sạch (no LLM,
coverage instances 1.0, pure dict-join). **FedProx blocker mở vòng thứ TƯ
liên tiếp** — vẫn ưu tiên tuyệt đối (R2c) + R2b inference; reviewer nhắc: nếu
sau audit FedProx vẫn identical → report VERIFIED NULL RESULT.
<!-- % SRC: outputs/packguard/r10/r4_kb_v3/*; audit round 4 verdict "verified"; ưu tiên từ harsh-review vòng 4 (wording/priority) -->

Cập nhật 2026-09-26 (vòng 5, `r5_noop` — designed NOOP; audit verdict
"verified"): không có scientific output mới theo thiết kế. Audit tái lập:
`outputs/packguard/r10/r5_noop.log` có đúng **2 dòng** — marker smoke cũ
16:32:28Z + đúng 1 marker mới **18:37:23Z** khớp verbatim kể cả hậu tố
"(DRY=0)"; wrapper `scripts/r10/r5_noop.sh` chỉ printf-append rồi `exit 0`
(exit code được xác minh bằng cấu trúc, KHÔNG chạy lại để tránh mutate log);
không có mock field vì không chạy thí nghiệm — log là artifact duy nhất.
Reviewer xếp loại: administrative NOOP nếu không kèm auditable decision
artifact → đã bổ sung **Memo M0** (Mid-Round Synthesis & Decision Memo) làm
artifact đó; **quy tắc mới: không thêm NOOP/consultation round** trừ khi có
external blocking condition hoặc formal decision gate VÀ round bắt buộc sinh
auditable decision artifact. Hai blocker chính chưa execute: FedProx (mở từ
vòng 2, qua vòng 3–5) và 20-seed paired inference (từ vòng 1) — ưu tiên tuyệt
đối, xem M0.
<!-- % SRC: outputs/packguard/r10/r5_noop.log; scripts/r10/r5_noop.sh; audit round 5 verdict "verified"; xếp loại + yêu cầu artifact từ harsh-review vòng 5 (wording/priority) -->

Cập nhật 2026-09-26 (vòng 6, `r6_granite_ladder`): granite-3.3-2b ladder
vulnerability-domain ĐÃ CHẠY + AUDIT (verdict "verified"; 240 record raw,
cache-only 0 generation mới) — **bằng chứng mạnh nhất tính đến nay**:
harm-replicates **SUPPORTED** (A5: recall .7627→.0667, 41/0 flips,
chi2-cc p=4.2e-10), A1-minimal-safe **REFUTED** (A1 advisory-only đã hại:
.7627→.4000, 23/2, p=6.3e-05), benign-verdict-bias **SUPPORTED**
(C0 0/30 → C5_near 20/30, exact p=1.9e-06) — xem khối «Đã chạy + audit
vòng 6» trong R6. Paper đã nhập (compile exit 0). **LƯU Ý QUY TRÌNH: vòng 6
KHÔNG lấy được ý kiến ChatGPT** (MCP `not_authenticated`, 6 lần thử trong
~8 phút, cần login thủ công) — 2 caveat của auditor (A5 provenance 0/60
hash-match; method mix McNemar) CHƯA qua đánh giá ChatGPT; verdict ChatGPT
đang đứng là REJECT (r5). FedProx blocker: vòng thứ 5 liên tiếp chưa chạy.
<!-- % SRC: outputs/experiments/r10_granite_ladder/{metrics_round9.json,raw/}; audit round 6 verdict "verified"; trạng thái ChatGPT-MCP từ log run vòng 6 -->

Cập nhật 2026-09-26 (vòng 7, `r7_mechanism_ablation`): mechanism ablation ĐÃ
CHẠY + AUDIT (verdict "verified with one wording correction") — kết luận:
**null with low power** (n=30 pairs/cell, mọi exact McNemar p ≥ .25 — không
phân biệt được no-effect vs small-effect), paper đã nhập kèm 3 caveat
(power; 96/180 cache-hit vs 84 fresh; cấm cross-round so sánh .60 vs .7627)
và **chỉnh sửa phần directional**: câu keyNumbers của runner "zero 1→0
flips" SAI cho granite/scrambled (đúng: 1 flip 1→0 + 2 flip 0→1, file và raw
recompute đều vậy) — auditor bắt, paper đã mang corrected directional counts.
**ChatGPT unavailable lần 2 liên tiếp** (vòng 6–7; not_authenticated, cần
login thủ công) → r6 và r7 CHƯA qua mắt harsh reviewer; assessment "reject"
của r5 có thể lạc hậu theo một trong hai hướng. FedProx: vòng thứ 5 liên
tiếp chưa chạy; inference 20-seed: thứ 7. Wall ~12 min không kiểm chứng được
(chỉ metrics meta 19:24:22Z).
<!-- % SRC: outputs/packguard/r10/r7_mechanism_ablation/{mechanism_metrics.json,mechanism_batch.jsonl}; audit round 7 (issues + verdict "verified with one wording correction"); trạng thái ChatGPT-MCP từ log vòng 7 -->

Cập nhật 2026-09-26 (vòng 8, `r8_safety_expand`): safety expansion n=100 ĐÃ
CHẠY + AUDIT (verdict "verified"; 360 verbatim copies + 240 new, 100 samples
50mal/50ben zero-overlap) — paper đã nhập kèm **2 interpretation rule bắt
buộc**: (1) **floor effect** — RR≡0.0 TẤT CẢ arms kể cả P0 (0/600 refusals;
p=1.0 với 0 discordant pairs là VÔ NGHĨA, KHÔNG được viết "blocking không có
tác dụng" — viết structural blocking-absence); (2) **pooled masking** —
pooled recall .35→.38→.44 che hướng ngược per-model: llama recall sập
.16→.06 (cả 8 flips mal→ben là llama, FP 0), granite tăng .54→.82 nhưng hút
FP 0→.04 (cả 2 FP pooled là granite); pooled corruption=true là rule-driven
(min_flip≥1) và P1 chỉ dựa trên 3 flips — thin; divergent corruption
response granite-vs-llama là observation đáng chú ý. Caveat phụ: plan-level
pool figure 560→230 VẪN chưa ai verify (run chỉ scan 265→100); copied records
không mang mock field (mock=None) — "all mock=False" chỉ đúng cho 240 new;
cache split 192 fresh / 48 hits. **ChatGPT unavailable lần 3 liên tiếp**
(vòng 6–8) — đã chuẩn bị catch-up file 3 vòng (/tmp/chatgpt_r6_r7_r8_catchup.md)
để gửi 1 lượt khi session hồi phục. FedProx: vòng thứ 6 liên tiếp chưa chạy.
<!-- % SRC: outputs/packguard/r10/r8_safety_expand/{safety_metrics_n100.json,safety_batch_n100.jsonl}; audit round 8 (issues + verdict "verified"); trạng thái ChatGPT-MCP từ log vòng 8 -->

Cập nhật 2026-09-27 (vòng 11, P0 theo audit reviewer Q1): **P0-1..P0-6 ĐÃ
XONG TOÀN BỘ** (chi tiết + bằng chứng: `reports/round11/{W1,W2,V1,V2,F}_report.md`).

- **P0-1 (R2c, FedProx audit) — DONE + BUG TÌM THẤY**: bit-identity 160/160
  là ROUTING BUG (`mu` không được truyền per-algo; `local_update` đọc
  `cfg.mu`) → cả 2 arm cũ đều chạy FedProx(μ=.01). Đã fix per-algo routing +
  unit test 12/12 (`tests/test_packguard_p0.py`) + flag
  `legacy_mu_routing` tái lập bit-exact. Blocker mở 6 vòng đã đóng.
- **P0-2 (strong centralized + TOST, thay "p=.312 descriptive") — DONE**:
  AMENDMENT-5 đăng ký TRƯỚC run (16:39:29Z < 16:56:59Z, 360 runs
  mock=false). **TOST primary PASS**: group/graph ΔF1 −.0065, 90% CI
  [−.0133,+.0003] ⊂ ±.02; group/hashing PASS; random/hashing PASS.
  80/80 strong-centralized cell converged (min F1 .7692) → 2 cell collapse
  cũ (.375/.326) = undertrain artifact, không phải tính chất dữ liệu.
- **P0-3 (claim tfidf-degradation) — RETRACTED có kiểm soát**: p=3.8e-06 cũ
  là artifact (TF-IDFVectorizer fit pooled vocab + undertrain SGD). Với
  HashingVectorizer stateless + strong baseline: group Δ −.0024 (p=.312),
  random Δ −.0037 (p=.404) — degradation biến mất; 0/360 row recall≥.999.
- **Central-win secondary — DISCLOSED**: random/graph strong-centralized
  thắng FedAvg +.0160 F1 (4+/15−/1, exact p=.0062, Holm .0247, in bài
  ".025" ở 3 chữ số; TOST FAIL có hướng, CI dưới 0). Primary group split:
  equivalence PASS.
- **P0-4 (gen-numbers) — DONE**: 336 macro (trước 178) từ p0_results.json +
  trivial_results.json + grid cũ; `gen_paper_numbers.py --check` OK và đã
  chứng minh phát hiện stale thật (inject sai → FAIL).
- **P0-5 (trivial/shortcut-learning baseline) — DONE + ĐÃ NHẬP paper**:
  trivial 5-feature F1 .82–.86 (cell means .823–.855); graph (superset) vẫn
  thắng có ý nghĩa: ΔF1 +.0227 group / +.0487 random (exact p 1.9e-5 /
  1.9e-6), còn thắng trên subset 500 non-empty (p=.0012/1.9e-6) → không
  phải shortcut learning; paper định vị graph là "refinement, not
  replacement".
- **P0-6 (hygiene) — DONE**: 18 nhãn round-N trong TEXT đã trung tính hóa
  (0 hit sau strip-comment; cite keys + "% round 2 = FL training round"
  giữ nguyên — vô hình/kỹ thuật); refs.bib 9/9 fix đúng chiều (V2 audit);
  de-anon Pass; test_exists_branch đã fix đúng gốc (guard token_map trong
  `fig_round7`) → **pytest 675/0**, verify_repro.sh 30/30 exit 0, tectonic
  paper2 exit 0 (PDF 9 trang — tăng từ 8 do nội dung mới, disclosed).
- Còn mở (P1, khuyến nghị thứ tự): **R9 leave-families-out + attack/defense
  AST-strip robustness** (con hàng lớn nhất theo reviewer — cạnh sống còn
  cho claim graph-robustness), rồi R3b validation-locked thresholds, R5b
  KB-entry ablation 20-seed, effect sizes + CI cho stabilized arm.
<!-- % SRC: outputs/packguard/p0/p0_results.json (360 rows, AMENDMENT-5); outputs/packguard/trivial/trivial_results.json; paper2/p0_macros/numbers.tex (336 macros); reports/round11/{W1,W2,V1,V2,F}_report.md -->

Cập nhật 2026-09-28 (vòng 13, F — FINAL): **R9/P2-11 DONE (đổi thiết kế thành
leave-cluster-out, xem mục R9)**; **P3-15/16 DONE** (paper2 rewrite theo thesis
mới "The Advisory Inside", 8 token {{R13:LFO_*}} đã điền bằng số đã audit,
protocol §5.4 sửa LFO→LCO khớp artifact). Kết quả LCO (đều từ
`outputs/packguard/lco/lco_results.json`, 480 rows mock=false, V1 audit
bit-exact + Wilcoxon exact 4/4): cả graph lẫn hashing sụt jointly
(dg −.0383±.0675 / dt −.0289±.0879, primary thr 0.30, strong-centralized,
n=20); dd = −.0095±.0803, 95% CI [−.047,+.028], exact Wilcoxon p=.368
(FedAvg −.0139±.0794, p=.674; sensitivity thr 0.50: −.0033/−.0121,
p=.985/.430) → **không hỗ trợ ranking robustness giữa 2 biểu diễn; claim
viết joint 2 chiều**; power ≈.75 tại differential .05-F1; equivalence ở
margin ±.02 KHÔNG pass, pass ở ±.05. Hard-negative expansion +200 benign
npm (RANDOM draw, 17/200 hard-negative profile) — **disclosed, KHÔNG nhập
grid/corpus đã đăng ký**; manifest +200 sha256 đã verify (V1). Gates: pytest
**732/0** (708 cũ + 24 LCO), gen_paper_numbers --check OK 336 macros,
tectonic paper2 exit 0 (8 trang), verify_repro.sh **30/30 exit 0** (manifest
45 file: +lco_results.json, +summary.md, +clusters_t0*.json,
+benign_expansion_v1.json), 0 "R13:"/0 round-N/0 AMENDMENT trong PDF; 4 note
refs.bib đã trung tính hóa; render_summary loop-bug đã fix (re-render: 1
header, 34/34 dòng số byte-identical); PackGuard_final.pdf đã tái xuất.
Còn mở: **P1-7 BLOCKED (user OSF)**, **P1-8 BLOCKED (user API key)**,
**P1-10 Deferred (7B removed theo directive <4B)**, **P2-12/13 Deferred**
(SecAgg/DP giữ nguyên vai trò simulation disclosure — ra khỏi contribution
chính sau rewrite), **P2-14 resolved-by-removal** (same), R3b/R5b/effect-size
CI vẫn pending nếu còn vòng.
<!-- % SRC: outputs/packguard/lco/lco_results.json; reports/round13/{W1,W2,V1,V2,F}_report.md; docs/packguard_prereg.md AMENDMENT-7 -->

## 0. Quy tắc bất di bất dịch

- **AMENDMENT-4 trước khi chạy** (mục 1): mọi thay đổi thiết kế/statistic phải
  nằm trong `docs/packguard_prereg.md` với timestamp TRƯỚC run đầu tiên.
  Cấm tune ngầm (W1 TODO #2 nguyên văn: "lr sweep hoặc early-stop ... phải là
  AMENDMENT-4, không tune ngầm").
- **Ràng buộc model <4B** (PACKGUARD_BRIEF.md §2): chỉ Qwen2.5-Coder-3B,
  Llama-3.2-3B, granite-3.3-2b, Qwen2.5-Coder-0.5B (smoke). KHÔNG tải model ≥4B.
- mock/dry không lẫn số thật; mọi số truy vết outputs; không git commit khi
  chưa được yêu cầu; pytest full sau mỗi thay đổi code (`pytest tests/ -q`,
  baseline 641/0).
- Con số scoped (đếm lại từ raw 2026-09-25): RR=0 trên ĐÚNG 2,700 defensive-task
  generations ở model 2–3B = round-3 vulnerability-domain 1,080 (E0 arms 180 +
  E2/E3 conditions 900; raw `outputs/experiments/round3_e0` + `round3_e2e3`,
  0 REFUSAL) + E0v2 1,200 (round5_master.json) + package-domain 420 (360 + 60).
  Trong cùng runs round-3, các PROBE orbench_hard (nội dung có hại thật) bị
  refuse 125/225 — refusal pathway hoạt động, task defensive không kích nó.
  Pilot round-2 (0.5B, 90 defensive-arm records) KHÔNG tính vào 2,700 vì không
  phải model 2–3B. **CẤM** viết "RR=0 trên ~6,250" — 6,250 là
  TỔNG generation toàn dự án (reports/round7/ROUND7_SUMMARY.md:48). **CẤM**
  ghi chú thích "E0 1,080" — 1,080 là tổng row RR của round-3 (E0 180 + E2/E3 900),
  không phải riêng E0.
- RefusEU: 0 hit trong `paper2/refs.bib` + `docs/packguard_refs.bib` — **chưa
  được cite; phải đọc full-text trước khi dùng** cho nghĩa "alignment bảo toàn
  ở model lớn nhưng không ở model nhỏ". Trước đó, mọi claim scale giữ dạng
  "closed at 2–3B, direction follows family".
- KHÔNG swap shim trong `configs/round9_8b.yaml` (byte-identity-guarded cho
  llama8b theo header config). Arm granite tạo config riêng.

## M0. Mid-Round Synthesis & Decision Memo — auditable artifact của vòng NOOP (2026-09-26)

> Vòng 5 là consultation NOOP (audit verified — xem header). Reviewer: NOOP
> chỉ hợp lệ nếu sinh ra auditable decision artifact; memo này là artifact đó,
> hợp nhất từ các số ĐÃ audit vòng 1–4 (không có số mới ở vòng 5).
<!-- % SRC: cấu trúc memo = yêu cầu artifact của harsh-review vòng 5 (wording/priority); toàn bộ số dẫn = đã audit vòng 1–4 -->

**Ranked blockers:**
1. **FedProx ≡ FedAvg 160/160 cell-seed** (verified vòng 2; chưa run nào giải
   thích qua vòng 3–5) → R2c: audit code path (log mu / local objective /
   proximal penalty / parameter-update norms, verify FedProx branch thực sự
   được exercise) + rerun affected cells; nếu vẫn identical → report
   **VERIFIED NULL RESULT** được documenting nghiêm ngặt, không để là
   unexplained anomaly.
2. **20-seed paired inference** (outstanding từ vòng 1 — 5 rounds) → R2b:
   paired effect size + bootstrap 95% CI + corrected p-values + seed-level
   distributions cho mọi central claim; tầng round-9 hiện stale (summary
   self-label n=5).
3. **Validation-locked threshold** (mở vòng 3) → R3b: 0.8955 hiện là
   test-oracle; tune trên validation, freeze, evaluate MỘT lần trên test.
4. **KB 20-seed + entry-level ablation** (mở vòng 4) → phần còn lại của R5:
   seed-only vs LLM-only vs random/coverage-matched control, matched KB
   size/budget; hiện chỉ n=1 mixed-sign dù coverage instances = 1.0.

**Evidence hiện có cho từng negative result (đã audit vòng 1–4):**
- FedAvg-null trên graph: ΔF1 +.0105±.0347 (group) / +.0403±.1162 (random),
  20 seeds — descriptive; significance layer stale, chưa có inference.
- FedAvg cost trên tfidf: ΔF1 −.0521/−.0576 (stale-stats caveat); tfidf
  calibration deficit: ECE .1891/.2240, 0/40 all-malicious, oracle .8955@.60
  (vòng 3).
- Blocking-absent RR=0: 2,700 defensive generations ở 2–3B (audit round 9).
- Recall perturbation: safety n=60, model-dependent, benign FP 0/180 (round 9).
- 8B infeasibility: 4 MPS load failures + CPU 1.11 tok/s ⇒ ladder ≈31 h
  decode (round 9).
- KB gain: single-seed mixed-sign (+.0103/+.0112 centralized; −.0009/−.0224
  fedavg), coverage instances 1.0, no-LLM pure join (vòng 4).
- Centralized instability + stabilization: collapse 2/160; stabilized arm
  graph-neutral (+.0011/−.0015), tfidf early arm parked @pos-rate .995
  (vòng 1).

**Quyết định (go / rerun / abandon / reframe):** không abandon mục nào.
Rerun: FedProx (R2c), inferential (R2b), threshold (R3b), KB (R5-remainder).
Reframe (viết SAU CÙNG, khi các mục trên xong): contribution cuối là
**boundary-condition / design-guideline contribution** nối các negative
results (blocking-absent, tfidf>graph ở threshold mặc định, FedAvg-null,
recall perturbation, 8B infeasibility, KB gain nhỏ backend-dependent) thay vì
isolated failed experiments (framing reviewer).

**Experiment order các round còn lại:** R2c + R2b (cùng đợt) → R3b →
R5-remainder (KB) → R4/R6–R9 theo thứ tự cũ → integrated synthesis.

**Acceptance / stop criteria (per claim):**
- FedProx: chấp nhận khi có audit log (mu, proximal penalty, update norms) và
  rerun cho kết quả khác biệt, HOẶC VERIFIED NULL RESULT memo; stop khi một
  trong hai đường document xong.
- Mọi central claim: chỉ được vào paper khi có paired effect size + corrected
  p + bootstrap CI; nếu chưa — bắt buộc ghi "descriptive".
- Threshold: tuned-threshold chỉ dùng khi gain sống sót validation-locked
  protocol; oracle (.8955) chỉ làm upper bound.
- KB: nếu 20-seed CI chứa 0 → report null; entry-ablation quyết định nguồn
  gain (curated vs LLM expansion vs extra capacity).

**Kết thúc run (cập nhật vòng 10, 2026-09-26) — close-out status:**
- Run set r10: **10/10 rounds** — r1 stabilized ✓, r2 grid-refresh ✓, r3
  calibration ✓, r4 KB ✓, r5 NOOP, r6 granite ✓, r7 mechanism ✓, r8 safety
  expand ✓, r9 NOOP, r10 paper-integration NOOP ✓. Tất cả qua audit
  "verified"; r6–r10 (5 vòng) chưa qua harsh review (ChatGPT unavailable).
- Paper integration (vòng 10): Conclusion đã mang câu chốt — FedProx audit +
  20-seed inference là **disclosed open items (unexecuted)**; mọi federated
  comparison và early-vs-fixed evidence là **descriptive** cho đến khi thực
  thi (compile exit 0, verify trong PDF).
- Blocker status cuối: **FedProx — CLOSED UNEXECUTED** (open 6/8 rounds;
  fedavg≡fedprox 160/160 từ vòng 2 vẫn unexplained) → action #1 run kế:
  audit proximal-term code path (log mu / local objective / proximal penalty
  / update norms) → rerun affected cells, hoặc **VERIFIED NULL RESULT**
  được documenting nghiêm ngặt; **20-seed paired inference — CLOSED
  UNEXECUTED** (từ vòng 1) → action #2; R3b validation-locked threshold —
  unexecuted; KB 20-seed + entry-level ablation — unexecuted; P3-FP + trục
  strength/query-relevance + human-validation — unexecuted; r6 follow-ups
  (method unify, A5 regen) — unexecuted; pool figure 560→230 — unverified.
- Acceptance criteria (phần trên) — trạng thái cuối: KHÔNG claim nào vượt
  qua gate "effect size + corrected p + bootstrap CI" → mọi finding mạnh
  (r6 harm-replicate p~1e-10, r8 floor-effect + per-model divergence) vẫn
  được gán nhãn descriptive/suggestive trong paper (đã ghi đúng như vậy);
  .8955 không được dùng (oracle); KB gain không claim; framing
  boundary-condition/design-guideline đã dựng trong Discussion nhưng
  integrated synthesis cuối chỉ chốt khi 2 blocker top xử lý xong.
- Handoff: gửi `/tmp/chatgpt_r6_r7_r8_catchup.md` (đủ r6–r9 + 4 câu hỏi
  review) MỘT lượt khi ChatGPT session hồi phục; assessment hiện hành =
  REJECT (r5), đã 4 vòng lạc hậu; login trả lỗi NGAY (không phải timeout)
  → cần đăng nhập thủ công ngoài run tự động.
- Về NOOP: r5 và r9 đều chỉ printf-marker — theo tiêu chí r5 là
  administrative NOOP trừ khi round sinh ra auditable decision artifact;
  artifact bù = M0 (vòng 5) + close-out này (vòng 9). KHÔNG thêm NOOP round
  trong run kế (quy tắc M0).
<!-- % SRC: tổng hợp từ audit rounds 1–4 — r1_stabilized_central, r10/fl_multiseed, r3_calibration, r4_kb_v3, round-9 safety/8B disclosures; cấu trúc/ưu tiên từ harsh-review vòng 5 (wording/priority); không có số mới vòng 5 -->

## 1. AMENDMENT-4 (bắt buộc, chung cho R1–R5) — draft nội dung

Ghi vào `docs/packguard_prereg.md` (mục `## AMENDMENT-4`) với timestamp +
tuyên bố thứ tự, TRƯỚC khi chạy R1. Nội dung đóng băng:

1. **Seeds**: 20 seeds = [20260922..20260941] (5 seed cũ giữ nguyên 5 vị trí đầu).
2. **Họ 8 comparisons chính** (đóng băng định nghĩa, partition=ecosystem):
   {group,random} × {graph,tfidf} × {fedavg-vs-centralized, graph-vs-tfidf}.
   Định nghĩa graph-vs-tfidf: paired per-seed trên cùng (split, seed),
   so FedAvg-graph vs FedAvg-tfidf VÀ centralized-graph vs centralized-tfidf
   (2 họ phụ, báo riêng, không gộp).
3. **Thống kê**: Wilcoxon signed-rank exact two-sided over per-seed deltas +
   Holm correction (familywise α=.05 trên 8 comparisons); kèm achieved power
   cho ΔF1 thực đo (formula: n cần cho Wilcoxon normal approx với effect size
   dz = meanΔ/sdΔ, α hai phía, power .80 — ghi công thức trong amendment,
   không chỉ assert). TOST equivalence cho claim "decentralization preserves
   utility": margin δF1 = 0.02, prereg TRƯỚC khi chạy (novelty-2).
4. **std ddof=1** nhất quán mọi aggregate (hiện ddof=0, V1_report.md:47-50);
   ghi rõ trong mọi bảng.
5. **Arm centralized-stabilized** (R2), **arm GNN** (R4), **grid kb_on v3** (R5),
   **persist final_probs + threshold rule** (R3) — cùng amendment.
6. **Feasibility/power**: n=20 → Wilcoxon exact two-sided min p = 2/2^20 ≈
   1.9e-6 → có thể đạt α=.05 (khác n=5: min p .0625).

## R1. Multi-seed grid 20 seeds + thống kê có power — **P0**

- **What**: mở grid từ 5 → 20 seeds; chạy lại toàn bộ; tham số hóa power_note;
  script phân tích mới (Holm, achieved power, TOST, variance decomposition
  seed/split/feature-block, per-client breakdown, AUC-PR).
- **Why**: audit stats-1 (accepted) + novelty-2 (modified): n=5 min p=.0625 >
  .05 — "mọi p-value hiện tại không sống qua review Q1" (F_report.md:266-267);
  Wilcoxon graph-vs-tfidf chưa có code (`_aggregate_grid` hiện chỉ tính
  fedavg-vs-centralized; power_note hardcode 'n=5' tại `packguard/eval.py:469-471`;
  seeds là config param `configs/packguard_fl.yaml:57`, đọc tại
  `packguard/eval.py:774`).
- **Cost**: 640 rows ≈ 4× grid hiện tại (62 s/160 runs tại W1_report.md:26) →
  **~4–5 phút CPU**, 0 GPU/LlM. Dev script ~1–2 h.
- **Expected evidence**: Wilcoxon 8 comparisons với Holm-adjusted p; TOST
  (δ=.02) cho graph group-split; mean±std ddof=1 thay bảng tạm 5-seed trong
  paper (tab:main/tab:stats đã dựng khung, chỉ nhập số mới); AUC-PR
  (sklearn `average_precision_score` — đã verify import được trong venv);
  variance decomposition + per-client breakdown → 1 subsection §Results.
- **Commands**:
  1. Sửa `docs/packguard_prereg.md` (AMENDMENT-4, mục 1).
  2. `configs/packguard_fl.yaml` dòng 57: `seeds: [20260922, ..., 20260941]` (20 giá trị).
  3. Sửa `packguard/eval.py:469-471` power_note theo n (f-string, giữ test).
  4. `.venv/bin/python -m packguard.eval --grid` → `outputs/packguard/fl_multiseed/grid_results.json`.
  5. Script mới `scripts/analyze_grid_stats.py`: Holm + power + TOST + AUC-PR
     + decomposition từ grid_results.json (sklearn/scipy/statsmodels — có sẵn).
  6. `.venv/bin/python -m pytest tests/test_packguard_multiseed.py -q` rồi full suite.

> **Đã chạy + audit vòng 2 (refresh 2026-09-25; audit verdict "verified").**
> Artifacts: `outputs/packguard/r10/fl_multiseed/{grid_results.json,summary.md}`
> (summary date 2026-09-25T17:15:14Z) + `outputs/packguard/r10/r2_grid_refresh/probs_dump.jsonl`
> (meta 17:20:12Z; bản `dry/` tách sạch). Auditor tái lập: **640/640 row
> `mock=False`** = 20 seeds × 8 (partition,split,block) cell × 4 methods (160
> row/method); partition {ecosystem, npm_hook}; `config_sha16 e0cd260b014556bb`
> khớp vòng 1; mean F1 centralized ecosystem tái lập ĐÚNG baseline fixed vòng 1
> (vd group/graph 0.8581±0.0468). probs_dump: 1 meta + **19,484 row per-sample**
> (mock=False) đúng 160 cell centralized (protocol meta: cùng cell construction
> như run_grid, train bằng `run_centralized` ở config lr/rounds — KHÔNG gồm arm
> early-stopping vòng 1); labels **12,680 = 1 (malicious) / 6,804 = 0 (benign)**
> — updater đối chiếu: count label-1 == `n_test_malicious` trong 40/40 cell
> ecosystem/group; pred_positive_rate cell **0.1417–0.9929** (tfidf
> **0.6847–0.9000**). Risk audit bắt buộc khai khi dùng số: **(1) fedavg ≡
> fedprox** — (F1, AUC) identical 160/160 cell-seed dù mu_fedprox=0.01 trên mọi
> row (updater recheck: 160/160); grid thực chất 3 model riêng biệt, mọi so
> sánh fedavg-vs-fedprox là vacuous, bảng summary double-count cùng số; nguyên
> nhân (proximal không bind ở scale này vs implementation inert) CHƯA xác định
> → R2c. **(2) Cell seed-invariant** — ecosystem/random/tfidf fedavg F1 =
> 0.78392 bit-identical 20/20 seed (std 0.0000, `summary.md:24`; cả nhánh
> npm_hook `summary.md:139`); giải thích runner: test set stratified random cùng
> kích thước/thành phần (121/78) giữa các seed + predictor tfidf degenerate;
> thống kê variance/paired trên cell này vô nghĩa. **(3) Stale inferential** —
> `summary.md:5-6` ghi "Wilcoxon over 5 seeds ... min p 0.0625" trong khi header
> liệt kê 20 seeds; bảng Wilcoxon/McNemar CHƯA được recompute trên grid refresh
> (auditor không recompute — ngoài scope). [Quan sát riêng của updater, CHƯA
> audit độc lập: bảng "Wilcoxon over seeds" trong summary.md cho p F1
> 0.2954/3.815e-06/0.1327/8.832e-05 — khác tab:stats paper ở 2/4 hàng (.312 và
> 1.9e-6) → càng củng cố việc phải regenerate.] (4) Wall "~14 min" do runner
> report, không kiểm chứng độc lập (log không timestamp; mốc gần nhất: grid
> summary 17:15:14Z, probs meta 17:20:12Z). (5) Minor: 342/19,484 prob đúng
> 0.0/1.0 (toàn graph block, 0 tfidf — saturation, chấp nhận được làm đầu vào
> r3); row per-sample KHÔNG mang config_sha16 (chỉ meta header).
<!-- % SRC: outputs/packguard/r10/fl_multiseed/{grid_results.json,summary.md}; outputs/packguard/r10/r2_grid_refresh/probs_dump.jsonl; audit round 2 (issues + verdict "verified"); đối chiếu p-value 2/4 hàng là quan sát riêng của updater, chưa audit độc lập -->

## R2. Arm centralized-stabilized — **P1**

- **What**: centralized + lr sweep {0.01, 0.03, 0.1} + early-stop trên 10%
  train (train-CV, không đụng test); tái dùng `_grid_cell`.
- **Why**: audit stats-4 (accepted): 1/40 cell centralized sụp (random/graph
  seed 20260923 F1=.375, tái lập d=0) trong khi 40/40 cell FL ổn định
  (min FedAvg F1 .7375) — kết luận central-vs-FL 1-seed có thể sai cả 2 hướng.
- **Cost**: 240 runs = 20 seeds × 2 splits × 2 blocks × 3 lr ≈ **15–20 phút CPU**.
- **Expected evidence**: (i) collapse rate cell F1<0.70 (so 1/40); (ii) re-test
  FedAvg-vs-centralized dưới baseline ổn định. Aggregate pre-reg cũ GIỮ làm
  primary; arm mới chỉ vào bảng sensitivity (đã có chỗ trong tab:stats caption
  + Discussion 'retracted finding' của paper).
- **Commands**: AMENDMENT-4 mục 5 → thêm arm vào config grid →
  `.venv/bin/python -m packguard.eval --grid` (chạy chung R1 nếu cùng phiên).

> **Đã chạy + audit (run 2026-09-25; audit vòng 1: "Round 1 verified", trace OK).**
> Artifacts: `outputs/packguard/r10/r1_stabilized_central/{results.jsonl,summary.md}`
> (+ bản `dry/` tách sạch khỏi số thật). Số auditor xác nhận (tái lập từ raw):
> 80/80 cell thật (`mock=False`), 20 seeds × 4 cell-group
> {group,random}×{graph,tfidf}, single `config_sha16 e0cd260b014556bb`; 240 sweep
> entry, 0 undefined fold eval; best_lr 0.1/0.03/0.01 = 58/21/1 cell; best_epochs
> mean **12.05** (min 2, max 30 — số "12.1" trong report runner là rounding
> half-up, dùng 12.05); early-vs-fixed trên 80 cell: **15 better / 1 tie / 64
> worse**; ΔF1 theo cell-group: **+0.0011** (group/graph), **−0.0511**
> (group/tfidf), **−0.0015** (random/graph), **−0.0561** (random/tfidf).
> Caveat bắt buộc khi trích dẫn (từ audit): (1) tfidf early arm có
> pred_positive_rate ≈ .995/.996 (`summary.md`, cột pos_rate(early)) → ΔF1 tfidf
> là hành vi operating-point theo block, KHÔNG phải phán xét chung về early
> stopping; (2) fixed-baseline random/graph là outlier-driven (F1 std 0.1133 vs
> early 0.0356, `summary.md:11`); (3) toàn bộ 80 row là partition=ecosystem —
> single-partition, phải nêu trong mọi so sánh cross-round; (4) early-vs-fixed
> mới chỉ là aggregate difference — CHƯA có paired test/CI; (5) wall-clock chỉ
> suy gián tiếp (row đầu 16:40:09Z → summary 16:43:12Z; log không timestamp,
> thời điểm launch không được quan sát độc lập). Expected-evidence (ii) "re-test
> FedAvg-vs-centralized dưới baseline ổn định" CHƯA làm → chuyển thành R2b.
<!-- % SRC: outputs/packguard/r10/r1_stabilized_central/results.jsonl + summary.md; audit round 1 (issues + verdict "verified") -->

## R2b. Regenerate tầng inferential 20-seed + multi-partition — **P0 (vòng 1; mở rộng vòng 2)**

- **What**: (a) **regenerate TOÀN BỘ tầng inferential trên grid refresh 20
  seeds** (`outputs/packguard/r10/fl_multiseed/grid_results.json`) — các bảng
  Wilcoxon/McNemar round-9 hiện STALE (summary self-label n=5, AMENDMENT-3;
  chưa ai recompute); tính lại paired tests (exact) + effect size +
  bootstrap/permutation 95% CI + multiple-comparison control cho fedavg-vs-
  centralized (2 partitions) VÀ cho 80 cell early-vs-fixed của arm stabilized
  (`r1_stabilized_central/results.jsonl`, hiện aggregate-only); median/IQR +
  sensitivity bỏ-outlier (fixed random/graph std 0.1133 outlier-driven); cell
  ecosystem/random/tfidf (fedavg) seed-invariant → loại/khai báo riêng, không
  đưa vào thống kê paired; (b) re-test FedAvg-vs-centralized dưới baseline ổn
  định (expected-evidence (ii) của R2, chưa làm); (c) multi-partition: dữ liệu
  2 partition (ecosystem, npm_hook) ĐÃ có trong grid refresh vòng 2 — phần còn
  lại là inference so sánh giữa partitions (partition thứ 3/temporal vẫn
  out-of-scope như R9); (d) thêm timestamp vào log/artifacts để wall-clock
  kiểm chứng độc lập được.
- **Why**: caveats vòng 1 + 3 risk vòng 2 (đặc biệt stale inferential: paper
  tab:stats đã phải gắn nhãn unverified); ưu tiên reviewer harsh (chỉ dùng để
  xếp thứ tự, không phải nguồn số): single change giảm reject-risk mạnh nhất
  là multi-partition + multi-seed + paired tests + 95% CI; FedAvg-null phải
  đối mặt trực tiếp, không chỉ stabilize central.
- **Cost**: (a) analysis-only từ `r10/fl_multiseed/grid_results.json` +
  `r1_stabilized_central/results.jsonl` hiện có (CPU giây–phút); (b)+(c) cùng
  bậc chi phí với R2 (thực đo R2 vòng 1: row đầu → summary ≈ 3 phút từ
  timestamps artifacts).
- **Commands**: prereg supplement AMENDMENT-4 (đóng băng tests/CI TRƯỚC khi
  nhìn) → script mới `scripts/analyze_stabilized_inference.py` (mở rộng thành
  regenerate toàn bộ per-seed comparisons) → nếu cần cell mới cho (b): mở
  config grid → `.venv/bin/python -m packguard.eval --grid`.
<!-- % SRC: caveats audit vòng 1 + risks (2),(3) audit vòng 2; ưu tiên từ harsh-review vòng 1–2 (wording/priority, không phải nguồn số) -->

## R2c. Audit implementation FedProx — **P0 (mới vòng 2, 2026-09-26)**

- **What**: (a) audit training path trong `packguard/fl.py`: xác nhận proximal
  term thực sự vào local objective và áp lên local updates khi mu=0.01; (b)
  thêm unit/integration test chứng minh proximal loss ≠ 0 và parameter
  divergence khỏi FedAvg sau ≥1 round ở mu=0.01 (đối chiếu unit-test cũ ở mu
  lớn); (c) nếu đã audit/sửa mà FedProx VẪN trùng FedAvg từng bit → hạ
  FedProx khỏi main comparison, report như negative ablation (không phải
  method thứ 4); mọi bảng summary ngừng double-count (hiện 4 methods = 3 model
  riêng biệt).
- **Why**: audit vòng 2 RISK-1: fedavg ≡ fedprox identical (F1, AUC) 160/160
  cell-seed dù mu_fedprox=0.01 trên mọi row; đổi FL optimizer CHƯA giải quyết
  được FedAvg-null — descriptive mạnh hơn nhưng implementation validity đặt
  nghi vấn. Ưu tiên reviewer (wording/priority, không phải nguồn số): fix
  FedProx + regenerate stats là single change giảm reject-risk mạnh nhất hiện
  tại.
- **Cost**: dev/test ~1–2 h; 0 GPU (ước lượng dev theo lệ R2, chưa đo).
- **Commands**: đọc FedProx local step trong `packguard/fl.py` → test mới
  `tests/test_fedprox_divergence.py` → nếu sửa: chạy lại arm fedprox của grid
  + regenerate summary; nếu xác định identical là tính chất thật:
  reclassify thành negative ablation trong paper.
<!-- % SRC: risk (1) audit vòng 2 (recompute 160/160 từ outputs/packguard/r10/fl_multiseed/grid_results.json); priority wording từ harsh-review vòng 2 -->

## R3. Calibration + operating point + class-weight arm — **P1**

- **Cập nhật vòng 2 (2026-09-26) — đầu vào ĐÃ có**:
  `outputs/packguard/r10/r2_grid_refresh/probs_dump.jsonl` = 19,484 prob
  per-sample cho đúng 160 cell centralized (labels 12,680 mal / 6,804 benign;
  pred_positive_rate cell 0.1417–0.9929, tfidf 0.6847–0.9000; 342 prob đúng
  0.0/1.0 toàn graph block; row per-sample KHÔNG mang config_sha16 — chỉ meta
  header; protocol: train `run_centralized` ở config lr/rounds, KHÔNG phải arm
  early-stopping). Threshold phải chọn trên validation-only rồi đánh giá trên
  held-out; cell ecosystem/random/tfidf (fedavg) seed-invariant (F1 0.78392,
  std 0.0000) → calibration trên cell đó đọc có kiểm soát (F1 phẳng vì test
  stratified cùng size/thành phần 121/78 giữa seeds + predictor degenerate).
  <!-- % SRC: meta + rows của probs_dump.jsonl; audit vòng 2; giải thích 121/78 từ Notes của runner trong fl_multiseed/summary.md (khớp đính chính V1 §A3b) -->
- **What**: (a) persist `final_probs` vào row grid (hiện dùng cho subgroup/
  McNemar tại `packguard/eval.py:555,:594` nhưng không persist); (b) ECE
  10-bin + Brier + reliability curve cho {graph,tfidf}×{FedAvg,centralized}×
  {group,random} trên grid 20-seed của R1; (c) threshold sweep 0.05–0.95
  chọn F1-optimal trên train-CV áp lên test; (d) arm class_weight='balanced'
  + per-client threshold cho tfidf-FedAvg (**code mới** trong
  `packguard/fl.py` — hiện KHÔNG có class_weight, chỉ tham số threshold tại
  `packguard/fl.py:602,:798`; sklearn LR hỗ trợ, sklearn có trong venv).
- **Why**: audit stats-5 (accepted): AUC .9605/.9260 central 1-seed
  (results.jsonl đọc trực tiếp, khớp F_report.md:89,92); multi-seed
  .8970/.8537 (W1 §3.1); tfidf-FedAvg degenerate recall=1.0 ở 20/20 cells,
  precision = base-rate.
- **Cost**: **~15 phút CPU** (chạy lại grid subset + analysis); dev ~2–3 h.
- **Expected evidence**: bảng calibration + reliability; operating-point-
  corrected comparison graph-vs-tfidf (viết lại đoạn 'split-decision' đã dựng
  khung trong paper); subgroup pypi = effect size + bootstrap CI (n=36,
  không p-value; n=29 cũ là số kế thừa F_report round-8, không tái lập được
  từ results.jsonl subgroup eco_pypi).
- **Commands**: AMENDMENT-4 mục 5 → sửa `_grid_cell` persist final_probs →
  `.venv/bin/python -m packguard.eval --grid` → script phân tích
  `scripts/analyze_calibration.py` (mới).

> **Đã chạy + audit vòng 3 (run 2026-09-25; audit verdict "verified").**
> Artifacts: `outputs/packguard/r10/r3_calibration/{calibration.json,summary.md,probs_dump_weighted.jsonl}`
> (summary date 2026-09-25T18:03:25Z; `dry/` tách sạch; mtimes 01:03 — của rerun
> thành công). Đầu vào: probs_dump vòng 2 — auditor đối chiếu hôm nay vẫn tái
> lập đúng giá trị vòng 2 (rerun không đụng vào). Auditor tái lập từ raw (đúng
> định nghĩa metric của script): probs_dump_weighted.jsonl = **19,484 row
> `class_weighted_bce`** mock=False đúng 160 cell, **0 label mismatch** vs dump
> vòng 2; pooled per block×split: ECE-15bin graph **0.0726/0.0870**, tfidf
> **0.1891/0.2240**; Brier **0.1478/0.1659/0.1664/0.1574**;
> all-malicious@0.5 **0/40 cell mọi group** (share 0.0); pos_rate@0.5
> **0.692/0.719/0.803/0.806**; F1 before→after (weighted-BCE retrain,
> pos_weight=n_neg/n_pos, cùng lr/epochs/seed): graph/group **0.8618→0.8347**,
> graph/random **0.8416→0.8278**, tfidf/group **0.8466→0.8005**, tfidf/random
> **0.8432→0.8706**; best-F1 threshold (unweighted): **0.50/0.50 /
> 0.55→0.8790 / 0.60→0.8955**.
> Risk bắt buộc khi trích dẫn: **(1) REMEDY-FRAMING** — class weighting LÀM XẤU
> 3/4 group, chỉ giúp tfidf/random (0.8706) và vẫn thua zero-cost threshold
> sweep trên model unweighted (0.8955) → KHÔNG được đọc là "class weighting đã
> sửa tfidf"; thresholding dominates weighted retraining (framing reviewer,
> khớp số audit). **(2) Cột ECE là model UNWEIGHTED** — weighted arm không
> headline ECE (calibration.json có best-F1 weighted nhưng cũng là test-oracle,
> không headline) → không gán ECE kém của tfidf cho remedy. **(3) SWEEP LÀ
> TEST-ORACLE** — code-read của updater (điều reviewer flag là chưa xác định):
> script quét threshold và lấy max-F1 TRỰC TIẾP trên pooled test probs, KHÔNG
> có validation split (`scripts/r10/r3_calibration.py:41` input = test dump
> vòng 2; `:59-69` sweep + max trên cùng row test) → 0.8955 là upper bound
> post-hoc; spec gốc của mục này ("train-CV áp lên test") KHÔNG được implement
> trong helper → R3b. **(4) Crash+fix trace** — pass thật đầu tiên crash
> KeyError 'block'; fix verified trong code (`r3_calibration.py:135` guard
> input dump; `:149-150` dùng `.get()` kèm comment disclosure); toàn bộ
> artifacts là của rerun thành công (log tail "160/160" + "wrote
> calibration.json + probs_dump_weighted.jsonl"); pass crash không được chạy
> lại. **(5) Wall ~9 min (rerun) / ~19 min (gồm pass crash)** do runner report,
> không kiểm chứng được (log không timestamp; chỉ có summary date 18:03:25Z).
> **(6) Inferential VẪN chưa chạy** (paired 20-seed, effect size, corrected p,
> bootstrap CI) — khớp disclosure runner.
<!-- % SRC: outputs/packguard/r10/r3_calibration/{calibration.json,summary.md,probs_dump_weighted.jsonl}; scripts/r10/r3_calibration.py:41,:59-69,:135,:149-150; audit round 3 (issues + verdict "verified"); mục (3) là code-read của updater, chưa audit độc lập -->

## R3b. Validation-locked threshold re-evaluation — **P0 (mới vòng 3, 2026-09-26)**

- **What**: với MỖI setting pre-specified (block×split×partition): chọn
  threshold F1-optimal trên validation (train-CV hoặc hold-out từ train pool,
  KHÔNG đụng test), KHÓA threshold, rồi đánh giá ĐÚNG MỘT LẦN trên test; báo
  cáo kèm khoảng cách so với oracle (0.55→0.8790, 0.60→0.8955 test-oracle) để
  định lượng overfit của oracle; chỉ sau đó số tuned-threshold mới được phép
  vào bất kỳ claim nào của paper (oracle chỉ được giữ làm upper bound).
- **Why**: blocker reviewer vòng 3: threshold chọn trên chính test set là
  oracle/post-hoc — không phải contribution và undermine các fixed-threshold
  claim trước đó; audit vòng 3 + code-read xác nhận sweep hiện tại chạy trên
  pooled test, không validation.
- **Cost**: cần persist probs trên validation split (thêm 1 lần train/eval per
  cell — cùng bậc R3: ~10–25 phút CPU theo docstring script) rồi analysis-only.
- **Commands**: mở rộng `scripts/r10/r3_calibration.py` (validation split +
  persist validation probs) hoặc script mới → prereg rule chọn threshold
  TRƯỚC khi nhìn test → chạy → cập nhật paper (thay oracle bằng
  validation-locked; giữ oracle làm upper bound).
<!-- % SRC: blocker vòng 3 (wording/priority); nền số từ audit vòng 3; xác nhận sweep-trên-test từ code-read r3_calibration.py:41,:59-69 -->

## R4. GNN baseline (thuần torch, không PyG) — **P1**

- **What**: GIN hoặc GraphSAGE 2 lớp; node feature = one-hot 137 API-type +
  6 semantic class (từ graphs_v2); mean-pool readout; head LR; 103
  empty-graph → zero-vector (disclosed); 20 seeds × 2 splits ×
  {GNN-FedAvg, GNN-central}; early-stop train-CV như R2 (chống label-leakage);
  paired Wilcoxon vs LR-graph và LR-tfidf cùng seeds.
- **Why**: audit stats-6 (accepted): `import torch_geometric` →
  ModuleNotFoundError (torch 2.14 + sklearn/scipy có); graphs_v2 = 603 samples
  (500 non-empty + 103 empty, khớp V2 §B7); gap là tự-thừa-nhận
  (F_report.md:268-270, paper2 đã bỏ chữ 'a GNN is future work' ở phiên này).
- **Cost**: **4–8 h dev + ~30–60 phút train** (CPU/MPS, model cổ điển nhỏ).
- **Expected evidence**: hàng GNN {FedAvg, centralized} trong tab:main hoặc
  bảng mới; kết luận tfidf-vs-graph cập nhật theo GNN; title + abstract soft
  theo hướng kết quả (chỉnh lần 2 khi có số).
- **Commands**: AMENDMENT-4 mục 5 → `packguard/gnn.py` (mới, thuần torch) →
  mở rộng grid config `feature_blocks: [graph, tfidf, gnn]` →
  `.venv/bin/python -m packguard.eval --grid`.

## R5. KB v3 qua FL (grid subset kb_on) — **P1**

- **What**: bật kb trong ablations, chạy cell kb_on (2 partitions × graph ×
  methods × 20 seeds); component leave-one-out 3 KB features; subgroup pypi
  effect size + bootstrap CI.
- **Why**: audit stats-7 (accepted) + novelty-7 (modified): row kb_on DUY NHẤT
  từng qua FL dùng KB v2 54.7% coverage (V2 §B5); coverage_v3.json đã regen
  137/137 types, 2299/2299 instances, instances_by_label 1673/626, npm/pypi
  1822/477, unsure=0 (đọc trực tiếp file, label_rule V2#B7 fix); kb_features
  là pure lookup, 0 LLM call (`packguard/kb.py:360-376`).
- **Cost**: **vài chục giây – vài phút CPU** (không LLM).
- **Expected evidence**: bảng tab:kb mới dưới KB v3 (kỳ vọng tác động nhỏ:
  risk_ratio bất biến .0745, confidence .878→.907, unsure→0 — nhưng phải đo,
  không assume); abstract câu KB + bảng utility-per-cost (static-only vs
  KB-augmented) vào Discussion.
- **Commands**: AMENDMENT-4 mục 5 → `configs/packguard_fl.yaml` ablations:
  kb_on → `.venv/bin/python -m packguard.eval --grid`.

> **Đã chạy + audit vòng 4 (phiên bản rút gọn; run 2026-09-25; audit verdict
> "verified").** Artifacts: `outputs/packguard/r10/r4_kb_v3/{results.jsonl,summary.md}`
> (summary date 2026-09-25T18:23:56Z; `dry/join_preview.json` tách sạch).
> Scope thực chạy: **8 runs = 2 splits × {kb_off,kb_on} × {fedavg,centralized},
> seed 20260922 DUY NHẤT, graph block only** — KHÔNG phải 2 partitions × 20
> seeds như What ở trên; component leave-one-out và subgroup CI CHƯA làm.
> Auditor tái lập digit-for-digit 8 cặp F1/AUC (group: kb_off .9231/.9282,
> kb_on .9222/.9385; random: kb_off .8701/.8344, kb_on .8477/.8456 — F1, thứ
> tự fedavg/centralized); join_stats (kb_on): coverage instances **2299/2299 =
> 1.0**, mean_unsure **0.0**, mean_conf **0.75215** (instance-weighted);
> kb_stats **142 entries = 20 seed + 122 LLM, n_unsure 0** (auditor đếm lại
> kb_v0002.jsonl: 142 dòng, origin seed×20 + llm:Qwen2.5-Coder-3B×122, unsure
> False×142); entry-level mean confidence **0.8993/142** — HAI MẪU SỐ KHÁC
> NHAU, không trộn khi report. "NO LLM was invoked" được corroborate bằng
> code-path pure dict-join (`scripts/r10/r4_kb_v3_features.py:41-54`, ghi
> `features={'graph': g}` → tfidf không đụng KB). Delta kb_on−kb_off:
> centralized **+0.0103 group / +0.0112 random**; fedavg **−0.0009 group /
> −0.0224 random** — mixed sign, TẤT CẢ nhỏ hơn seed-std đã đo (vd 0.0468
> centralized group/graph, vòng 1/r2) → KHÔNG có statistical claim; đọc đúng:
> backend-dependent interaction (chờ inference 20-seed). Risk: (1) **n=1
> seed** — dominant caveat (runner disclose scope prereg 1-seed); (2) FedProx
> blocker VẪN mở (scope r4 chỉ fedavg+centralized; finding 160/160 vòng 2
> chưa run nào giải thích); (3) wall "~90 s" runner-reported, không kiểm chứng
> (log không timestamp; chỉ có summary date 18:23:56Z); (4) 142 entries vs
> 137 types — 5 entries phủ API ngoài corpus 603-record: hai khái niệm
> coverage (instances vs types), khai rõ khi trích.
>
> **Phần còn lại của R5 (chưa chạy)**: 20 paired seeds × 2 partitions;
> component leave-one-out (3 KB features); **entry-level ablation {20
> seed-only, 122 LLM-only, 20+122, random/coverage-matched control}**;
> subgroup pypi effect size + bootstrap CI; cost-benefit (inference ≈ free —
> pure lookup — vs KB construction cost); test tương tác KB × training regime
> (centralized + / fedavg −) — framing **backend-dependent utility/trade-off**,
> không phải universal improvement; giới hạn: chỉ support graph block (ưu tiên
> reviewer vòng 4, wording/priority).
<!-- % SRC: outputs/packguard/r10/r4_kb_v3/{results.jsonl,summary.md}; scripts/r10/r4_kb_v3_features.py:41-54; audit round 4 (issues + verdict "verified"); phần còn lại = ưu tiên reviewer vòng 4 (wording/priority) -->

## R6. Granite ladder (family thứ 3, matched-scale) — **P1**

- **What**: chạy granite-3.3-2b qua ladder vulnerability-domain
  (A0/A5/A1 + benign) — KHÔNG swap shim; tạo `configs/round9_granite.yaml`
  kế thừa `configs/round7_7b.yaml` + prompt-sha guard; pre-register CẢ HAI
  chiều đọc; disclose refusal-monitor fallback threshold như quy ước safety-port.
- **Why**: audit stats-8 (accepted) + safety-2 (modified): 0 row P3 trên
  granite trong cả 5 master files (đếm: round5 21, master_results 66,
  round6_ablation 23, round6_bias 46, round7 52 granite rows); llama3b P3
  recall 1.0→.3667/.3333 (round5_master.json) vs qwen3b P3 inert 1.0→1.0 —
  family contrast chưa đóng; khớp V2 §SCALE QUESTION STATUS option 2 +
  docs/literature_2026_refresh.md:50; đúng ràng buộc <4B (2B).
- **Cost**: ~240 gens × 512 tok trên MPS; throughput repo đo ~5.4 s/gen
  (300 gen/27 phút) đến ~30 s/gen → **0.4–2 h**.
- **Expected evidence**: inert → hại là llama-specific; harmed → harm là
  small-model generic. Cả hai chiều đều có chỗ đi vào trong paper (khung
  scale-vs-family đã tạo trong Discussion + Conclusion).
- **Commands**:
  1. `cp` nguồn tham khảo: tạo mới `configs/round9_granite.yaml` (model shim
     granite, giữ byte-guard của `round9_8b.yaml`).
  2. Prereg hai chiều trong report/amendment trước khi chạy.
  3. `.venv/bin/python -m src.experiments.round9_ladder --stage dry` (sanity, MockLLM).
  4. `.venv/bin/python -m src.experiments.round9_ladder --stage queue` (A0→A5→A1→benign).
  5. `.venv/bin/python -m src.experiments.round9_ladder --stage metrics`.

> **Đã chạy + audit vòng 6 (run 2026-09-25/26; audit verdict "verified").**
> Artifacts: `outputs/experiments/r10_granite_ladder/{metrics_round9.json,jobs_status.json,results_granite2b__{vul__A0,vul__A1,vul__A5,benign__B0}.json,raw/}`
> (+ `dry/` tách sạch). 240 record: `real=true`, `dry_run=false`,
> model-guard granite-3.3-2b, bfloat16, **cache-only** (cache_hit=true, ngày
> gen Sep 19–23, cache mtime Sep 23 trước run; log `cache_hits=240/240
> wall=0.1s`) — 0 generation mới. **Kết quả (auditor tái lập từ raw):**
> recall_vul A0 **45/59=.7627** (1 unparseable), A1 **24/60=.4000**, A5
> **4/60=.0667** (Δ=**0.696**); flips A5_vs_A0 **41/0**, McNemar chi2-cc
> **p=4.1854e-10** (exact binomial 9.09e-13; bootstrap Δ CI [−.814, −.576],
> 10k seed 20260918); A1_vs_A0 **23/2**, chi2-cc **p=6.3342e-05** (exact
> 1.94e-05); A5_vs_A1 **20/0**, statsmodels.exact **p=1.9073e-06**; benign
> C0 **0/30** → C5_near **20/30=.6667**, 20 flips, exact **p=1.9073e-06**;
> **RR = 0.0 mọi arm** (A0/A5/A1/C0/C5_near). **Verdicts verbatim:**
> `H-R7-harm-replicates` **SUPPORTED**; `H-R7-harm-absent` NOT_EVALUABLE;
> `H-R7-A1-minimal-safe` **REFUTED (harm attributable to A1)**;
> `H-R7-benign-verdict-bias` **SUPPORTED**. `config_sha16 239a67086059a4c5`
> (auditor recompute sha16(parsed YAML) — KHÁC raw-file sha prefix
> `800e405e…` DO THIẾT KẾ: scheme tại `src/experiments/round5_e0v2.py:68`,
> sha16 tại `pilot_round2.py:131-132`).
> **Caveat bắt buộc khi trích dẫn:** (1) **A5 provenance gap** — 0/60
> `prompt_sha256_16` của A5 khớp `prompt_hash` trong cache (A0/A1/benign
> khớp 60/60; tổng 180/240): cache-hit được chứng minh (token-pair unique
> match, counters, log, mtime) nhưng "byte-identical prompts" của A5 dựa trên
> keying của cache layer, chưa tái suy được từ stored fields → chưa verify
> độc lập (không phải contradiction); **một lần regenerate A5 bằng GPU sẽ
> đóng cả gap này lẫn cache-only nature** → follow-up. (2) **Method mix** —
> trong cùng metrics file: 4.19e-10/6.33e-05 là chi2-cc (`exact=false`),
> 9.09e-13/1.94e-05 là exact binomial, benign 1.91e-06 là statsmodels.exact;
> hướng kết luận không đổi nhưng phải chọn MỘT method thống nhất → follow-up.
> (3) **Denominator 59 vs 60** — A0 recall trên 59 parsed (1 unparseable);
> paired tests đúng trên 59 pairs (rate_A1 trên 59 pairs = .4068 vs .4000
> trên 60) — không diff cột recall một cách naive. (4) **Cosmetic inherited
> labels** — metadata.round=7/'round7_7b', jobs_status round=9, log prefix
> [r7]/[r9-queue]; danh tính thật (config `r10_granite_ladder.yaml`,
> granite-3.3-2b model-guard, LEGACY-KEY llama8b shim) disclosed trong header
> config; không ảnh hưởng dữ liệu → dọn khi tiện. (5) ChatGPT KHÔNG đánh giá
> vòng này (MCP not_authenticated) — 2 caveat (1)(2) chưa qua harsh-review.
> (6) FedProx blocker: vòng thứ 5 liên tiếp chưa chạy (ngoài scope r6).
<!-- % SRC: outputs/experiments/r10_granite_ladder/{metrics_round9.json,jobs_status.json}; audit round 6 (issues + verdict "verified"); trạng thái ChatGPT-MCP từ log vòng 6 -->

> **Follow-up r6 (mới, 2026-09-26):** (a) chọn MỘT method McNemar
> (khuyến nghị: statsmodels.exact — conservative, file đã có sẵn) và recompute
> lại bảng; (b) regenerate A5 một lần bằng GPU (không cache) để đóng provenance
> gap; (c) dọn inherited labels (round=7/'round7_7b', prefix [r7]/[r9-queue]);
> (d) đưa kết quả qua harsh-review khi ChatGPT-MCP hồi phục (login thủ công).
<!-- % SRC: 2 caveats đầu là auditor round-6 issues; (a) khuyến nghị method là judgement của updater dựa trên note auditor "state one method"; (d) theo quy trình harsh-review các vòng trước -->

## R7. Safety n≥100/model + arm P3-FP + trục strength/query-relevance — **P0 design / chạy sau R1**

- **What**: thêm variants vào `configs/packguard_safety.yaml`: P3-FP
  (advisory CHỐT "code này sạch" — thử ép FP>0 trên benign, W2 TODO #3 tại
  W2_report.md:214-217) + 2–3 mức strength (neutral/strong) + trục
  query-relevance (generic vs query-relevant, kỷ luật C5 đã verify:
  docs/results_master_round5.md:88-89 "C5 thật sự query-relevant (100% vs
  0.2%) và không leak label/CWE/CVE"); anti-leakage pattern-check trên
  advisory text trước khi chạy; giữ AST-gate check_semantics; resume-safe.
  Human validation: review TẤT CẢ flips + stratified ~50 non-flips/model
  (số annotator disclose, kể cả 1); exact McNemar per arm + CI; công thức
  power trong prereg (n=100 mal/model phát hiện shift recall ≥.13 — viết
  công thức, không assert).
- **Why**: audit safety-3 (modified) + novelty-5 (modified): n=60 hiện chỉ
  2 model/2 family (Qwen2.5-Coder-3B chỉ là KB-builder, CHƯA từng chạy
  safety-batch — muốn 3 family phải thêm arm qwen); refusal-monitor fallback
  là per-model disclosure (180 true granite / 180 false llama trong
  safety_batch_n60.jsonl — KHÔNG nói "mọi record true"); FP=0/180 có thể do
  chưa từng thử hướng ngược.
- **Cost**: 4 arms × 100 mal × 2 model ≈ 800 records (~360 tái dùng, ~440 mới;
  MPS ~2–4 h theo 5–30 s/gen).
- **Expected evidence**: nếu P3-FP ép ra FP>0 → kênh hai chiều, viết lại
  Discussion 'Safety transfer' (chỗ đã dựng khung "pre-register both
  directions"); malicious_recall/fp_benign + error-type transitions per model;
  appendix human-validation.
- **Commands**: AMENDMENT-4 mục riêng cho safety → sửa
  `configs/packguard_safety.yaml` (P3-FP + strength, giữ 3 arm cũ) →
  `.venv/bin/python src/experiments/round9_safety_n50.py` (mở rộng runner
  hiện có để nhận arms mới) → human-validation sheet → analysis script.

> **Đã chạy + audit vòng 8 (phần "Safety n≥100/model"; run 2026-09-25; audit
> verdict "verified").** Artifacts:
> `outputs/packguard/r10/r8_safety_expand/{safety_metrics_n100.json,safety_batch_n100.jsonl}`
> (metrics meta 2026-09-25T19:41:58Z; `dry/` tách sạch). **Scope thực chạy**:
> arms P0/P1/P2 trên **100 samples (50 mal/50 ben)** — P3-FP, trục
> strength/query-relevance và human-validation CHƯA làm (queued). Batch gộp =
> **360 verbatim copies** (n60, không mang mock field — `mock=None` ×360) +
> **240 new** (mock=False); new-gen cache split **192 fresh (mps) / 48
> deterministic hits** (temp=0, seed=1234, gen dates Sep 21); 100 samples =
> n60 + 40 mới (gate-passers [30:50] per class cùng draw — zero overlap,
> asserted). **Số auditor tái lập:** pooled recall **.35→.38→.44**
> (35/100→38/100→44/100); fp_benign **0/0/2-of-100**; parsed
> **1.0/.995/1.0**; RR **0.0** mọi arm, **0 discordant pairs, p=1.0**;
> flips b→m **3/0** tại P1 (199 pairs) và **19/8** tại P2 (200 pairs);
> per-model: llama recall **.16→.16→.06** (cả 8 flips mal→ben là llama, FP
> 0), granite **.54→.60→.82** (fp_benign **0→.04** = cả 2 FP pooled);
> verdicts prereg: **blocking_supported=false / corruption_supported=true
> (P1, P2)**.
> **Interpretation risks (auditor, CHƯA qua ChatGPT):** (1) **FLOOR EFFECT**
> — blocking_supported=false và p=1.0 (0 discordant) VÔ NGHĨA vì RR≡0.0 kể
> cả P0 (0/600 refusals — model không bao giờ block batch này); TUYỆT ĐỐI
> không viết "blocking không có tác dụng" — viết **structural
> blocking-absence**, không phải treatment null (paper đã theo framing này).
> (2) **POOLED MASKING** — pooled-only reporting che hướng ngược per-model
> (xem trên); corruption_supported=true là rule-driven (min_flip_count≥1),
> P1 chỉ 3 flips — **thin**; divergent corruption response granite-vs-llama
> có thể là finding (paper ghi "salient observation", chưa claim).
> (3) **Selection gap** — RunPlan nói pool 560→230 (147 mal/83 ben) nhưng
> run chỉ log scanned=265/gate_pass=100 (`selection_stats_this_run`) và
> CHƯA AI verify figure plan-level (runner không rescan, auditor cũng không
> — ngoài scope) → cần một hành động scan độc lập hoặc sửa RunPlan.
> (4) Cosmetic: mock=None trên 360 copies — "all mock=False" chỉ đúng cho
> 240 new (paper đã ghi rõ). (5) Wall "~20 min" không đo được (log không
> timestamp; chỉ metrics meta 19:41:58Z, mtimes 03:01 local). (6) FedProx:
> vòng thứ 6 liên tiếp chưa chạy (ngoài scope r8).
<!-- % SRC: outputs/packguard/r10/r8_safety_expand/{safety_metrics_n100.json,safety_batch_n100.jsonl}; audit round 8 (issues + verdict "verified"); framing floor-effect/pooled-masking đã vào paper theo đúng 2 mục [AUDITOR] của ask -->

Cập nhật 2026-09-26 (vòng 9, `r9_noop` — FINAL round, designed NOOP; audit
verdict "verified"): **run set r10 ĐÓNG.** Audit tái lập:
`outputs/packguard/r10/r9_noop.log` đúng **2 dòng** (marker smoke
16:32:29Z + đúng 1 marker mới **20:20:14Z** verbatim kể cả "(DRY=0)");
wrapper `scripts/r10/r9_noop.sh` chỉ printf-append rồi `exit 0` (exit xác
minh bằng cấu trúc, không chạy lại để tránh mutate log); không có mock field
(theo thiết kế). **ChatGPT unavailable lần 4 liên tiếp (r6–r9)** — login
lần này trả lỗi NGAY (không phải timeout) → trạng thái trang/profile hỏng
deterministic; catch-up file `/tmp/chatgpt_r6_r7_r8_catchup.md` đã cập nhật
thêm r9, sẵn sàng gửi MỘT lượt khi session hồi phục. **Trạng thái đóng:**
2 standing blocker KHÔNG được wrapper r10 nào thực thi — (1) FedProx
audit/rerun (open 6/8 rounds; fedavg≡fedprox 160/160 từ vòng 2 vẫn
unexplained — accounting của runner khớp issue trail của auditor), (2)
20-seed paired inference (open từ vòng 1) → mọi finding mạnh (r6 p~1e-10,
r8 floor-effect + per-model divergence) vẫn descriptive; verdict ChatGPT
hiện hành = REJECT (r5), lạc hậu 4 vòng. 9 caveat [AUDITOR] r6–r8 ĐỀU đã
trong paper (verify 2026-09-26: A5 provenance, unified McNemar,
1-flip-correction, 96/180 cache, null-with-low-power, structural
blocking-absence ×2, llama .16→.06, 560→230). **M0 được cập nhật thêm mục
«Kết thúc run»** — đây là auditable decision artifact của vòng NOOP r9
(theo tiêu chí r5: r5+r9 chỉ printf-marker, không artifact thì là
administrative NOOP; M0 + close-out này là artifact bù).
<!-- % SRC: outputs/packguard/r10/r9_noop.log; scripts/r10/r9_noop.sh; audit round 9 (issues + verdict "verified"); trạng thái ChatGPT-MCP từ log vòng 9; khẳng định caveat-đã-vào-paper dựa trên grep verify 2026-09-26 -->

Cập nhật 2026-09-26 (vòng 10, `r10_noop` — paper integration + gate, designed
NOOP; audit verdict "verified"): **run set đóng ở 10/10 rounds, tất cả audit
"verified".** Audit tái lập: `outputs/packguard/r10/r10_noop.log` đúng **2
dòng** (marker 20:28:28Z verbatim, "(DRY=0)"); wrapper printf-append +
`exit 0` (xác minh cấu trúc, không chạy lại). **ChatGPT unavailable lần 5
liên tiếp (r6–r10)** — catch-up file đã đủ r6–r10 + câu hỏi review cho một
phiên chấm bổ khuyết. **CLOSURE STATE cho paper** (auditor độc lập xác nhận
khớp disclosure của runner): 2 blocker để ở trạng thái **disclosed
NOT-EXECUTED** — FedProx (từ finding vòng 2: fedavg≡fedprox 160/160 dù
mu=0.01; không wrapper r2–r10 nào audit/rerun) và 20-seed paired inference
(r1 summary.md per-cell ΔF1 là bằng chứng early-vs-fixed DUY NHẤT trên đĩa,
descriptive n=20 không test) — **paper integration vòng này đã thêm câu
chốt vào Conclusion**: cả hai là disclosed open items, mọi federated
comparison (gồm FedAvg-null) và mọi early-vs-fixed evidence là descriptive
cho đến khi được thực thi. 2 provenance nuance duy nhất còn mở trong run
set: r6 A5 prompt-hash (0/60; cache-hit proven) + r8 selection-stats
(265 vs plan 560→230). Mechanical note: best_epochs 12.05 (paper đã dùng
12.05 đúng từ vòng 1; "12.1" là rounding của runner).
<!-- % SRC: outputs/packguard/r10/r10_noop.log; scripts/r10/r10_noop.sh; audit round 10 (issues + verdict "verified"); closure state = yêu cầu tích hợp của vòng 10, số nền từ audit rounds 1–2 -->

## R8. Mechanism ablation (paraphrase + scrambled control) — **P1, chạy TRONG batch R7, sau arm P3**

- **What**: 3 paraphrase same-meaning của CÙNG advisory + 1 scrambled control
  (cùng độ dài/format) + P2 gốc; malicious-only; 30 mal × 5 conditions ×
  2 model = 300 gens; phân tích phân bố flips theo condition.
- **Why**: audit safety-5 (accepted): khoảng trống V1 §4.2 ("Cơ chế ... chưa
  được tách khỏi ... không được claim benefit"); infra dùng lại R7.
- **Cost**: **0.5–2.5 h MPS** (chung batch R7).
- **Expected evidence**: flips tập trung ở P2 gốc + paraphrases (content-
  mediated) vs cả scrambled (generic distribution-shift → hạ 'third threat'
  thành model instability; khi đó xem lại title).
- **Commands**: như R7 (cùng runner, conditions mới).

> **Đã chạy + audit vòng 7 (run 2026-09-25; audit verdict "verified with one
> wording correction").** Artifacts:
> `outputs/packguard/r10/r7_mechanism_ablation/{mechanism_metrics.json,mechanism_batch.jsonl}`
> (metrics meta 2026-09-25T19:24:22Z; `dry/` tách sạch). **Scope thực chạy
> khác What ở trên**: KHÔNG phải 30 mal × 5 conditions × 2 model = 300 gens —
> thực tế **3 variants (verbatim + 1 paraphrase + 1 scrambled) × 30 mal ×
> 2 model = 180 rows**, verbatim = prompt round-8 nguyên văn. Auditor tái lập
> mọi số material từ raw batch: 180 rows `mock=False` (90/model, 60/variant,
> toàn label=1, 30 sample distinct), parsed_rate **1.000** mỗi cell, refusal
> **0.000** mỗi cell; malicious-verdict rate: granite **.6000 / .6667 /
> .6333** (verbatim/paraphrase/scrambled), llama **.1333 / .2333 / .1667**;
> paired exact McNemar n=30 pairs: **p = .5 / 1.0 / .25 / 1.0** (granite-para,
> granite-scramble, llama-para, llama-scramble).
> **Sửa hồ sơ (auditor bắt lỗi keyNumbers của runner, KHÔNG phải lỗi
> artifacts):** câu "all changes are 0→1 flips with zero 1→0" SAI cho
> granite/scrambled — đúng là **1 flip 1→0 + 2 flip 0→1** (net +1, p=1.0),
> xác nhận cả trong file (b10_a_success_b_fail=1) lẫn raw recompute; 3 cell
> còn lại thuần 0→1. Rates/deltas/p-values giữ nguyên; headline "no
> significant move" sống. **Caveat bắt buộc khi trích dẫn:** (1) **POWER** —
> n=30 pairs/cell với mọi p ≥ .25 không phân biệt "no effect" vs "small
> effect" → chỉ được viết suggestive/null-with-low-power, KHÔNG established
> null; (2) **generation provenance** — "180/180 real generations made this
> run" là counter row-completed: **96/180 là deterministic-cache hits**
> (temp=0, seed=1234, byte-identical prompts; gen dates Sep 21–23: toàn bộ 60
> verbatim + 9 paraphrase + 9 scrambled per model), chỉ **84 rows generated
> fresh** (mps, bfloat16) — reuse hợp lệ về phương pháp nhưng không được
> present là generation mới; (3) **parsing definition** — parsed_rate 1.000
> tính theo parsed-JSON dict (179 ANSWER + 1 PARTIAL-with-verdict, 0
> refusal), không phải status==ANSWER; (4) **cross-round conflation** —
> granite verbatim .60 ở đây là sample set KHÁC (30 gate-passers [0:30] của
> round-8 draw; meta ghi rõ; import read-only + assert label==1 tại
> `scripts/r10/r7_mechanism_ablation.py:68-73`) so với r6 A0 .7627 (60-vul
> subset của ladder) — KHÔNG so sánh được; (5) wall "~12 min" không đo được
> từ artifacts (log không timestamp; chỉ metrics meta + mtimes 02:24 local).
> (6) FedProx: vòng thứ 5 liên tiếp chưa chạy; 20-seed inference: thứ 7.
<!-- % SRC: outputs/packguard/r10/r7_mechanism_ablation/{mechanism_metrics.json,mechanism_batch.jsonl}; scripts/r10/r7_mechanism_ablation.py:68-73; audit round 7 (issues + verdict "verified with one wording correction") -->

## R9. Leave-families-out family shift — **P2 — DONE vòng 13 (đổi thiết kế: leave-CLUSTER-out)**

- **Trạng thái: DONE (2026-09-27/28, W1 + V1 audit + F điền vào paper2)**.
  Thiết kế thực chạy khác kế hoạch dưới đây ở cấp đơn vị holdout: KHÔNG dùng
  "fold theo family metadata" mà **leave-cluster-out (LCO)** — MinHash
  (128 perm, seed 20260922) trên code 3-grams + name patterns, ngưỡng 0.30
  (cuối thung lũng similarity; sensitivity 0.50) + package closure
  (union-find; 0/67 multi-version package bị xẻ; 0 mixed-label unit),
  20 seeds × randomized ~20% cluster hold-outs/stratum; đăng ký
  **AMENDMENT-7 TRƯỚC khi chạy metric nào**. Pre-register rule 2 chiều
  được giữ: kết quả **null có power** — dd(graph−text) = −.0095±.0803,
  exact Wilcoxon p=.368 (95% CI [−.047,+.028]; FedAvg p=.674; thr .5
  p=.985/.430; power ≈.75 tại δ=.05) → KHÔNG ranking robustness được
  hỗ trợ; paper §5.4 đã viết joint claim. Chi tiết: `reports/round13/
  {W1,V1}_report.md`; số: `outputs/packguard/lco/lco_results.json`.
- **What (kế hoạch gốc, đã thay bởi LCO)**: 5-fold leave-K-families-out
  trên features_v2 + manifest; chạy graph-vs-tfidf qua grid primitives;
  pre-register rule TRƯỚC: graph degradation < tfidf degradation ⇒ claim
  "robust under family shift"; ngược lại boundary chặt hơn cho negative #2.
  KHÔNG temporal split (out-of-scope; MPI corpus chưa probe —
  docs/literature_2026_refresh.md §A1/§D).
- **Why**: audit novelty-8 (accepted): group split hiện chỉ chặn
  version-leakage trong cùng package (AMENDMENT-1); family metadata tồn tại
  trong sample ids; AUC .9605/.9260 đọc trực tiếp results.jsonl (multi-seed
  .8970/.8537).
- **Cost**: **CPU phút** (grid primitives). Thực tế: ~12 phút CPU cho 480 rows.
- **Expected evidence**: bảng 'F1/AUC degradation under family shift:
  graph vs tfidf' trong §Results; boundary condition Discussion đã dựng khung.
  Thực tế: §5.4 paper2 (sec:lco) + bảng degradation trong
  outputs/packguard/lco/summary.md.
- **Commands**: script mới `scripts/family_shift_cv.py` (mới; đọc
  features_v2 + dataset_v2 manifest, fold theo family) → chạy qua
  `packguard.eval` primitives → prereg rule trước khi nhìn kết quả.
  Thực tế: `packguard/clusters.py` + `packguard/lco.py` +
  `configs/packguard_lco.yaml`
  (`.venv/bin/python -m packguard.lco --config configs/packguard_lco.yaml`).

## R10 (tùy chọn, cần quyết định riêng). 8B out-of-stack — **P3**

- **What**: MLX 4-bit (~5 GB) hoặc GGUF/llama.cpp — cả hai KHÔNG có trong
  .venv (`import mlx`, `import llama_cpp` → ModuleNotFoundError, verify trong
  phiên audit); khai báo runtime khác, không same-claim feasibility với
  transformers/MPS (V2 §A3).
- **Why**: safety-6 (accepted) + W2 TODO #1: scale question hiện khép ở
  "qwen inert 3B & 7B + llama-8B NOT_FEASIBLE (4 fail MPS + CPU 1.11 tok/s
  ⇒ ladder 240×512 ≈ 31 h)".
- **Cost**: cài đặt runtime mới + weights q4 + re-run ladder (~vài giờ sau
  khi cài; cần quyết định có vượt ràng buộc "<4B research models" hay không).
- **Priority**: P3 — chỉ làm nếu reviewer/user đòi scale; paper hiện đã có
  feasibility disclosure + claim boundary.

## Phụ lục: việc vệ sinh ngoài không gian sửa của phiên 2026-09-25

1. **W1_report.md:181 và :199-200** (reports/round9/ — ngoài refuseguard/paper2/
   + refuseguard/docs/): sửa "test set giống hệt nhau giữa các seed" → "giống
   về kích thước/thành phần (121/78); các test set KHÁC nhau giữa seed
   (giao 20–27/121)" (V1 §A3b/§6.3). Paper2 không chứa claim sai này.
2. **RefusEU**: đọc full-text trước khi cite (điều kiện của stats-3/novelty-3);
   hiện 0 hit trong refs.bib — đúng trạng thái an toàn.
3. **AMENDMENT-4**: ghi vào `docs/packguard_prereg.md` như bước 1 của R1
   (không ghi trước — amendment phải đi cùng quyết định chạy).

## Thứ tự thực hiện khuyến nghị

1. R1 (P0, mọi thứ khác phụ thuộc config 20-seed + AMENDMENT-4).
2. R2c (P0: audit FedProx) + R2b (P0: regenerate tầng inferential 20-seed —
   analysis-only, chạy được ngay từ `r10/fl_multiseed/grid_results.json` +
   arm stabilized vòng 1) + R3b (P0: validation-locked threshold — cần persist
   validation probs trước) → R5 (cùng đợt grid, thêm ~20–35 phút CPU);
   R2 ĐÃ CHẠY + AUDIT vòng 1 (khối trong R2); grid refresh ĐÃ CHẠY + AUDIT
   vòng 2 (khối trong R1); R3 calibration ĐÃ CHẠY + AUDIT vòng 3 (khối trong
   R3) — nhưng sweep hiện là test-oracle, chờ R3b trước khi dùng 0.8955;
   KB-v3 re-run ĐÃ CHẠY + AUDIT vòng 4 ở scope 1-seed/graph-only (khối trong
   R5) — phần còn lại của R5 (20 seeds + entry-level ablation) queued;
   R6 granite ladder ĐÃ CHẠY + AUDIT vòng 6 (khối trong R6) — còn follow-up
   method-unify + A5-regenerate (khối follow-up r6); R8 mechanism ablation
   ĐÃ CHẠY + AUDIT vòng 7 ở scope 3-variants/180-rows (khối trong R8) —
   null-with-low-power, đã vào paper kèm caveats; safety expand ĐÃ CHẠY +
   AUDIT vòng 8 ở phần n=100 / arms P0–P2 (khối trong R7) — P3-FP, trục
   strength/query-relevance và human-validation vẫn queued (R7).
3. R6 (GPU MPS ~0.4–2 h) và R7+R8 (GPU MPS ~2.5–6.5 h) — có thể song song
   nếu MPS chạy tuần tự theo queue.
4. R4 (dev nặng nhất, 4–8 h) — sau khi R1 chốt baseline.
5. R9 (CPU phút, bất kỳ lúc nào sau prereg rule).
6. Nhập kết quả vào paper2 theo đúng bảng/đoạn đã dựng khung ở phiên 2026-09-25
   (lần 1 đã làm cho R2 ở phiên 2026-09-26).
7. (Vòng 5) Làm theo **Memo M0**: thứ tự + acceptance/stop criteria; KHÔNG
   thêm NOOP/consultation round trừ khi có external blocking condition hoặc
   formal decision gate VÀ round đó bắt buộc sinh ra auditable decision
   artifact.
8. (Vòng 9–10, FINAL) Run set r10 ĐÓNG ở 10/10 rounds — trạng thái từng mục
   nằm ở khối «Kết thúc run» trong M0; vòng 10 đã tích hợp câu closure vào
   paper Conclusion (2 blocker = disclosed open items; mọi so sánh federated
   + early-vs-fixed = descriptive); run kế bắt đầu từ R2c + R2b (2 blocker
   closed-unexecuted), sau đó R3b → R5-remainder → integrated synthesis.
<!-- % SRC: trạng thái R2 từ audit vòng 1; thứ tự R2b-trước-R3 theo ưu tiên harsh-review vòng 1; mục 7 = yêu cầu artifact + priority từ harsh-review vòng 5 (wording/priority); mục 8 = close-out từ audit vòng 9 + M0 -->
