# A3 Report — Round 6 (PRE-REGISTRATION + PAPER INTEGRATION cho cơ chế; không GPU)

Ngày: 2026-09-21 (phiên 2026-09-20 → 21). Phạm vi: [P1]
`docs/round6_ablation_prereg.md` + mirror `configs/round6_paper.yaml`; [P2]
paper drafts (05_results RQ7b, 06_discussion guidance + mechanization,
`paper/tables/tab_round6_ablation.tex`, `paper/make_figures.py::fig_round6`,
wiring `paper/main.tex`); [P3] check nhất quán; [P4] verify. KHÔNG sửa `src/`,
KHÔNG đụng GPU (A2 chủ), KHÔNG git commit. Mọi số ablation trong paper là
PLACEHOLDER — không bịa số nào.

---

## 0. Sự kiện quan trọng của vòng: pre-reg hai tầng + Amendment-1 (reconciliation)

Timeline thật (mtime):
1. 00:03 — Tôi đóng băng `docs/round6_ablation_prereg.md` (H-M1/H-M2/H-M3 +
   ladder 6 bậc + guidance G0–G3 + ngưỡng Δ0.20/0.05/p<0.05).
2. 00:11 — A2 ghi `configs/round6_ablation.yaml` (pre-reg thực thi của họ):
   ladder **mảnh hơn** (tách generic-wrap khỏi string-mediation; reassertion ở
   A5 = full P3; recovery KHÔNG là bậc), **arm chính chỉ C5_near** (C5_far chỉ
   confirmatory cho bậc thủ phạm), subset **60 vul + 30 benign**, kèm bộ
   hypothesis riêng theo framing concentration.
3. ~00:15 — generation bắt đầu (`raw/`, queue.log, llama cache grow).
4. Tôi ghi **AMENDMENT-1** vào prereg doc (trước khi có bất kỳ results.json
   nào): giữ nguyên toàn bộ ngưỡng/rule quyết định, chỉ điều chỉnh THUẬT TOÁN
   HOÁ theo thiết kế thực thi; §1a ghi rõ reconciliation và cam kết paper báo
   cáo CẢ HAI framing (H-M1 magnitude+significance vs rule concentration
   "largest single-step flip count / distributed if no rung ≥50%") — không
   cherry-pick framing khớp narrative.

=> Đây là điểm V-agents nên soi: hai bản pre-reg cùng thỏa "trước generation"
nhưng khác granularity; Amendment-1 hóa giải bằng cách khóa framing kép.

## 1. [P1] Pre-registration — tóm tắt nội dung đã chốt

File: `docs/round6_ablation_prereg.md` ( amendment-1 bên trong, một nguồn).

- **H-M1 (primary):** tồn tại ≥1 rung k→k+1 (k=0..4, A1vsA0…A5vsA4) với
  component-attributable **Δrecall ≥ 0.20** và **McNemar exact p<0.05** trên
  arm chính C5_near, model primary **Llama-3.2-3B**. Power: n=60 vul →
  Δ≥0.20 ⇔ 12/60 flip một chiều, p≈3.2e-06 (đã tính exact, không ước lượng).
- **H-M2:** minimal variant (A1 boundary-only) an toàn iff
  recall(A1) ≥ recall(A0) − 0.05 trên arm chính (rule điểm, không đòi p).
- **H-M3 (rule cho dữ liệu ĐÃ CÓ của Vòng 5):** FP-bias tăng theo arm C5 khi
  flips(C5_near) ≥ flips(D2) ≥, flips(C5_far) ≥ flips(C5_near), C5_near > 0,
  mỗi arm nonzero p<0.05. Verdict theo rule: **llama SUPPORTED (10/11/11),
  granite SUPPORTED (10/20/25), qwen ceiling-saturated (FP đã 1.000 ở C0 —
  uninformative, KHÔNG phải robustness; khớp phân tích A1-R6)**. A1-R6 đã
  lượng tử hóa thêm (ΔFP llama +0.183 [0.100,0.283] p=9.8e-04; granite +0.667
  p=1.9e-06; VCI) — chỉ cộng dồn evidence, không đổi rule.
- **Bundle-synergy rule (bắt buộc ghi trước):** nếu không rung nào đạt
  H-M1 nhưng A0→A5 ≥0.20 & p<0.05 → harm là compositional; vẫn là finding,
  kể khác đi. Nếu A0→A5 không đạt → failure-to-replicate (kèm prompt-sha
  audit), ghi as-is.
- **Guidance G0–G3** chốt TRƯỚC số: G1 "keep minimal provenance, drop the
  bundle" (H-M1 ✓ + H-M2 ✓); G3 "do not wrap untrusted commentary at all"
  (H-M2 ✗); G2 "avoid the bundle as a whole" (bundle-synergy); G0
  report-as-is.
- Không multiple-comparison correction; không gian test 6 rung × arm chính
  khai trước; kết quả âm giữ nguyên trạng thái.
- Hợp đồng tích hợp: `outputs/master/round6_ablation.json` schema
  `ablation.<model>.<arm>.<rung>.<metric>` (grid C5_near A0..A5 bắt buộc;
  C5_far optional) — `fig_round6` + S-R6 đọc đúng schema này.

## 2. [P2] Paper drafts đã chuẩn bị (đều compile được, số = placeholder)

| File | Nội dung |
|---|---|
| `paper/sections/05_results.tex` | Subsection **RQ7b "Which component of the defence corrupts?"** (sau RQ7, trước B4): mô tả ladder đúng thiết kế thực thi, ngưỡng H-M1/H-M2, bundle-synergy clause, framing kép; đoạn "Where the harm sits" với token từng rung; figure float `fig:round6` bọc `\IfFileExists{figures/fig_round6.pdf}` → paper compile được cả trước lẫn sau khi figure xuất hiện; comment chỉ dẫn S-R6 chọn đúng 1 guidance branch |
| `paper/sections/06_discussion.tex` | (a) "The defence is the risk": thêm câu chuyển tiếp cơ chế-hoá (verdicts H-M1/H-M2 + `{{R6:mechanism_summary}}`); (b) subsection mới **"Actionable guidance: minimal provenance vs. the full bundle"** (§sec:guidance) với 4 nhánh G0–G3 ghi trong comment, `{{R6:guidance_branch_text}}` là chỗ điền; (c) Threats "Defence attribution": cập nhật đúng trạng thái (ablation đã pre-reg/cumulative-only, C0×P3 control vẫn chưa chạy) |
| `paper/tables/tab_round6_ablation.tex` | Khung booktabs: rows A0..A5, cols = recall(vul, n=60), FP-rate(benign, n=30), Δ vs A0, p vs prev rung; note rows cho verdict kép + C5_far confirmation (optional) + qwen spot-check; caption ghi nguyên design authority (config A2 + prereg doc) |
| `paper/make_figures.py` | `fig_round6()`: **fail-safe đúng hợp đồng** — chưa có `outputs/master/round6_ablation.json` → `[skip]` + warning, KHÔNG crash; khi file có: strict assert trên grid C5_near (key thiếu → fail loudly), C5_far optional (grid đủ mới vẽ), identity-guard A5-vs-round5-P3 (nếu có trong master), marker `*` cho rung đạt ngưỡng harm. Đã wire vào `__main__` |
| `paper/main.tex` | Wire `\InputIfFileExists{tables/tab_round6_ablation}` (placeholder render được, không vỡ layout) |

## 3. [P3] Check nhất quán

- **Không claim nào trong paper hiện tại mâu thuẫn pre-reg mới.** V2-R5 cấm
  nói "reassertion gây hại" — paper chỉ nói "attribute at defence level";
  RQ7b đặt reassertion như rung A5 (hypothesis, không kết luận). Conclusion
  R5 "component ablation … là future work" giờ đã có pre-reg — S-R6 cập nhật
  khi điền số.
- **Danh sách chỗ sẽ cần cập nhật khi số R6 về** (ngoài các `{{R6:` token):
  1. `07_conclusion.tex` (S): future-work #1 "component ablation of P3" → đã
     trả lời; đổi thành kết luận cơ chế + còn lại frontier/API/CWE.
  2. `00_abstract.tex` (S): câu "the defence is the risk" — thêm mệnh đề cơ
     chế nếu H-M1/bundle-synergy có verdict.
  3. `01_intro.tex` (S): contribution defence-risk — thêm clause
     component-level nếu supported.
  4. `03_method.tex` (S, optional): mô tả 1–2 câu về ladder A0..A5 (hiện
     §method chỉ nói "bundle ≥5, defence-level only").
  5. `appendix_repro.tex` (S): traceability table thêm tab_round6_ablation +
     fig_round6 → `outputs/master/round6_ablation.json`, repro steps thêm
     round-6; "408 unit tests" sẽ stale sau khi A2 merge tests (đang 442).
  6. `docs/results_master_round6.md` (S): chưa tồn tại — cần một trang
     master như R5.
- Grep anchor: `grep -rn "R6:" paper/` → **47 token duy nhất / 56 vị trí**
  [S-Vòng-6 sửa: bản gốc ghi "63 vị trí" — đếm lại sai, V1-R6 xác nhận 56]
  (sau Amendment-1; toàn bộ nằm trong `05_results.tex`, `06_discussion.tex`,
  `tables/tab_round6_ablation.tex`, 1 comment `main.tex`). Token có `_` được
  bọc `\detokenize{...}` để LaTeX không vỡ (bài học: placeholder underscore
  gây "Missing $ inserted" — đã fix, compile 0 error).

## 4. [P4] Verify (lệnh + output thật)

```bash
.venv/bin/python paper/make_figures.py
# → [skip] fig_round6: outputs/master/round6_ablation.json not present
#   (round-6 ablation pending); paper compiles without this figure
# → [verify] all table numbers match source files
#   [verify] round-5 table numbers match outputs/master/round5_master.json
#   [verify] 17 headline numbers cross-checked ...
#   [cites] 18 keys used, all present in refs.bib (unused: none)
#   [ok] 6 figures (fig_round6.pdf cố tình KHÔNG sinh khi chưa có data)

# fig_round6 exists-branch test bằng master JSON TỔNG HỢP trong /tmp
# (monkeypatch ROOT/FIG; không bao giờ đụng path thật — A2 đang chạy):
#   near-only grid → fig_round6.pdf 20,699 bytes OK;
#   thiếu key C5_near.A3 → AssertionError "round-6 master missing ..." OK (strict);
#   C5_far grid một phần → bị bỏ qua (skip), không crash (thiết kế: optional).

tectonic --outdir paper/compiled paper/main.tex   # → 0 error
pdftotext ... ; grep -c '⁇' → 0 dangling refs; 42 token {{R6:*}} render nguyên văn

.venv/bin/python -m pytest tests/ -q --ignore=tests/test_round6_ablation.py \
  --ignore=tests/test_round6_bias.py
# → 408 passed (baseline giữ nguyên; 2 file round-6 của A1/A2 loại khỏi phép so)
.venv/bin/python -m pytest tests/ -q   # full snapshot cuối phiên
# → 442 passed (A2 đã fix xong test của họ trong lúc tôi làm; midpoint là
#   1 failed trong test_round6_ablation.py — KHÔNG phải của tôi, tôi không
#   đụng src/ hay tests/)
```

Compile status: **paper compile được với placeholder còn** (0 error, 0 dangling
ref). Token placeholder render nguyên văn trong PDF — trạng thái DRAFT được
ghi rõ ở đây; S-R6 điền số rồi compile lại.

## 5. Trạng thái + TODO cho S-Vòng-6

Đã xong: prereg (+Amendment-1), mirror config, bảng, RQ7b, discussion,
figure skeleton, wiring, verify.
Chưa/không làm (đúng phạm vi): KHÔNG chạy/generation; KHÔNG sửa `src/`,
`configs/round6_ablation.yaml` (A2), tests (A1/A2); KHÔNG git commit.

TODO S-R6 (theo thứ tự):
1. Chờ A2 xong + có `outputs/experiments/round6_ablation/results_*.json`;
   **nếu chưa có `outputs/master/round6_ablation.json`** → viết collector kiểu
   `collect_master_round5.py` (schema ở prereg §5.2) — hợp đồng này do S/A3
   giữ, config A2 không định nghĩa nó.
2. Điền 47 token `{{R6:*}}` (danh sách mục đích: bảng tự nói; các token prose:
   `delta_pair.llama.A0_A1…A4_A5`, `p.llama.*_vs_*`, `verdict.H_M1/H_M2/
   concentration_rung/guidance_branch`, `guidance_branch_text`,
   `mechanism_summary`, `spotcheck.qwen.A1_vs_A5`,
   `optional.C5_far.culprit_rung_confirmation`, `results_pointer_clause`,
   `fp_rate_direction.llama`, `fp_rate.llama.A0/A5`).
3. Giữ ĐÚNG MỘT guidance branch (G0–G3) ở cả 05 lẫn 06; xóa comment nhánh.
4. Cập nhật 6 điểm ở §3 (conclusion/abstract/intro/method/appendix/master-doc).
5. Chạy lại `make_figures.py` (fig_round6 sẽ tự sinh), verify_tables, tectonic,
   stale-scan (mục tiêu: 0 token `{{R6:` còn lại, 0 `??`).
6. Verdict phải tính từ script/records của A2, đối chiếu CẢ HAI framing
   (H-M1 ngưỡng vs concentration); nếu khác chữ → trình bày song song.

---
*Verification: make_figures PASS + fail-safe fig_round6 test 3 nhánh (skip/
strict/optional-far); tectonic 0 error, 0 dangling ref, 42 token render;
pytest baseline 408 (không tính 2 file round-6 đang phát triển), full suite
442 tại thời điểm cuối phiên; refs.bib không thêm key mới (18 keys, no unused).
Không git commit.*
