# PRE-REGISTRATION — Round 6: P3 component ablation ("Which component corrupts?")

Trạng thái: **ĐĂNG KÝ TRƯỚC** (pre-registration). Viết và đóng băng TRƯỚC khi
bất kỳ generation ablation nào của Vòng 6 được chạy (A2 là chủ GPU; S-Vòng-6
điền số vào paper). Sau khi A2 bắt đầu run, tài liệu này KHÔNG được sửa nội
dung hypothesis/decision rule — chỉ được bổ sung mục "Execution log" ở cuối
(kèm mtime) nếu cần ghi nhận sự kiện thực thi.

- Tác nhân pre-reg: A3 (Vòng 6). Ngày đóng băng: 2026-09-20.
- **AMENDMENT-1 (2026-09-21 00:20:02 — mtime của file này, kiểm chứng
  filesystem; bản thân amendment trước đây tự ghi "00:25", sai 5 phút, đã
  được S-Vòng-6 sửa theo audit V1-R6 MINOR-3. Vẫn TRƯỚC khi có results nào
  được ghi — run A2 bắt đầu generation ~00:15, chưa có results.json;
  chi tiết §1a):**
  điều chỉnh THUẬT TOÁN HOÁ (ladder granularity, arm chính, subset) cho khớp
  pre-registration thực thi của A2 (`configs/round6_ablation.yaml`, mtime
  00:11, trước generation đầu). **Không đổi:** mọi ngưỡng và rule quyết định
  H-M1/H-M2/H-M3, bảng guidance G0–G3, rule bundle-synergy, no-multiple-
  comparisons. Lý do: hai bản pre-reg (bản này 00:03, config A2 00:11) khác
  nhau ở bậc thang, không ở ngưỡng; reconciliation cần trước unblinding.
- Phạm vi giả thuyết: cơ chế phía DEFENCE (P3 bundle) — tách thủ phạm gây
  recall-collapse mà Vòng 5 phát hiện ở mức defence-level (Llama-3.2-3B,
  recall 1.000→0.367/0.333, 39/60 flip vul→benign, McNemar exact
  p=3.8e-06/1.9e-06; nguồn: `outputs/experiments/round5_defense/results_llama3b.json`,
  đã V2 audit + sha-prompt-reconstruction 20/20).
- Ràng buộc từ audit Vòng 5 (V2_report §1.1c, vẫn hiệu lực): KHÔNG được viết
  "reassertion gây hại" như kết luận đã chứng minh cho đến khi ablation chạy;
  C0×P3 control chưa chạy; n nhỏ pilot; llama B0 over-trigger (floor effect).

---

## 1. Ladder thiết kế: A0..A5 (cumulative component ladder) — [AMENDMENT-1: khớp thiết kế thực thi]

P3 như đã chạy ở Vòng 5 là bundle ≥5 thay đổi đồng thời (V2 tái dựng prompt và
so sha 20/20). Ladder bật từng lớp theo THỨ TỰ thêm dần, mỗi bậc khác bậc trước
ĐÚNG MỘT khối thay đổi prompt. Toàn bộ bậc dùng cùng: bench
`bench_attack_v1.jsonl` sha256_16 `2daa249f7543f8e0`, gen_cfg (temp 0,
max_new_tokens 512, seed 1234, batch 1), monitor required_fields
["vulnerable","cwe","location"], prompt builder A1 `build_attack_prompt`;
subset **60 vul + 30 benign llama**, seed 20260923 (vul set == nửa label-1 của
round5_e0v2; benign set == nửa label-0 của round5_defense — verified trong
config A2 trước khi pre-reg).

| Bậc | Thành phần BẬT so với bậc trước | Thực thi |
|---|---|---|
| **A0** | — (advisory trần == B0) | **cache-reuse** round5_e0v2 B0 C5_near (60 vul; per-record sha-gate 90/90 match theo audit A2) |
| **A1** | boundary wrap **duy nhất**: advisory-flagged node bọc nguyên văn UNTRUSTED-ANNOTATION; comment/string khác giữ nguyên; KHÔNG header; system == B0 | **bậc minimal của H-M2**; gen mới |
| **A2** | + CONTEXT-PROVENANCE header đầu hàm | gen mới |
| **A3** | + generic wrap các comment/docstring còn lại | gen mới |
| **A4** | + P1-style structured string mediation (lúc này func == full-P3 func) | gen mới |
| **A5** | + system reassertion (SYSTEM_REASSERTION) **== P3 đầy đủ Vòng 5**, single-shot; recovery KHÔNG là bậc (P3R ≡ P3 đã chứng minh ở Vòng 5) | 30 vul subset **cache-reuse** round5_defense P3 C5_near (sha-gate 30/30) + 30 vul còn lại + 30 benign là gen mới |

Detector (a) `detect_advisory` luôn bật ở A1–A5 (điều kiện để bọc advisory;
không tự thay đổi prompt khi không có wrapper). Mỗi BƯỚC k→k+1 thêm đúng một
khối; attribution theo BƯỚC, không theo "component đơn lẻ trong không gian đầy
đủ" (cumulative-by-design — giới hạn thiết kế, §6). Attribution = delta cặp
liền kề (A1vsA0 … A5vsA4); cumulative harm = mỗi bậc vs A0.

Model: **Llama-3.2-3B = primary** (model có hiệu ứng ở Vòng 5). Qwen KHÔNG còn
là negative-control chạy đủ ladder: chỉ **spot-check A1 vs A5** ở CUỐI queue,
có thể không kịp budget (disclosed) — kết quả qwen chỉ là narrate, không tham
gia H-M1/H-M2. Granite chỉ xuất hiện ở phần extension verdict-bias (Q3 của A2,
ngoài phạm vi H-M1/H-M2 — phục vụ H-M3, §3).

Arms: **C5_near = arm chính duy nhất** cho toàn ladder (harm Vòng 5 mạnh nhất
ở đây); **C5_far chỉ chạy lại cho bậc thủ phạm** mà H-M1 chỉ ra (nếu có), vai
trò confirmatory, có thể bị cắt vì budget — disclose khi thiếu. **Không chạy
C0×P3 control** — khoảng trống cũ giữ nguyên (không kết luận được "P3 chỉ
harmful khi có advisory"; ghi trong threats).

### 1a. Reconciliation với pre-reg thực thi của A2 (`configs/round6_ablation.yaml`)
- Ladder granularity: bản gốc của tài liệu này (00:03) gộp generic-wrap + string
  mediation thành một bậc và đặt reassertion ở A4, recovery ở A5. Config thực
  thi của A2 (00:11, cũng pre-reg trước generation) TÁCH hai khối mediation và
  đặt reassertion ở A5, không có bậc recovery. **Bản Amendment-1 theo thiết kế
  thực thi** — đây là thay đổi THUẬT TOÁN HOÁ duy nhất; ngưỡng H-M1/H-M2 áp
  dụng nguyên văn trên các bậc liền kề mới.
- Rule của runner A2 (`H-A1_boundary-alone`, `H-A5_reassertion-culprit`,
  `H-A2A3_harmless-machinery`: thủ phạm = bậc có flip đơn-bậc lớn nhất;
  "distributed" nếu không bậc nào ≥50% tổng flip A5-vs-A0) là **pre-reg song
  song, không thay thế H-M1/H-M2**: H-M1 dùng ngưỡng magnitude+significance
  (Δ≥0.20 & p<0.05), rule A2 dùng concentration (share flip). Paper báo cáo
  CẢ HAI verdict; nếu hai framing khác chữ, ghi rõ cả hai cùng điều kiện của
  chúng — không chọn cái khớp narrative.
- Endpoint FP-benign của A2 (`fp_benign`, "PRIMARY harm side-metric" theo
  metrics_defs) == FP-rate trong §2 của tài liệu này; RR vẫn báo cáo riêng,
  refusal không bao giờ map thành benign.

## 2. Endpoints (định nghĩa chốt TRƯỚC khi chạy)

Primary endpoint: **paired vulnerable recall** mỗi (bậc × arm × model), so
paired same-sample (McNemar exact, hai phía).

Secondary endpoints (ghi đầy đủ, không gate):
- FP-rate: share benign prediction=vulnerable mỗi bậc (paired vs A0).
- Flip ledger: count vul→benign và benign→vul mỗi bậc vs bậc trước và vs A0,
  stratified theo ground truth.
- UAC, RR (kỳ vọng 0 — nếu RR>0 ở bậc nào, recovery A5 kích hoạt thật: ghi
  thành sự kiện, không loại khỏi phân tích).
- FP-bias phía attack (H-M3) — đo từ dữ liệu E0-V2 Vòng 5 + (nếu A1-R6 có
  chạy thêm arm mới) dữ liệu mới, cùng công thức flip paired vs C0.

Đơn vị phân tích: (sample, arm); "39/60" của Vòng 5 = 19+20 pair trên 2 arm.
Mọi p-value McNemar exact; không chỉnh sửa đa so sánh (6 bậc × 2 arm là
không gian test đã khai trước — ngưỡng duy nhất p<0.05, mọi kết quả âm tính
giữ nguyên trạng thái, không chọn lọc sau hoc).

## 3. Hypotheses + decision rules (CHỐT, không đổi sau khi A2 chạy)

### H-M1 (primary): harm tập trung ở ≥1 bậc cụ thể
- **Phát biểu:** có ≥1 bậc k→k+1 (k=0..4, tức A1vsA0 … A5vsA4) mà khi thêm khối
  thành phần của bậc đó, recall giảm: **component-attributable Δrecall :=
  recall(A_k) − recall(A_{k+1}) ≥ 0.20** với **McNemar exact p<0.05**,
  **trên arm chính C5_near** (C5_far chỉ confirmatory cho bậc thủ phạm).
  Trên subset n=60 vul: Δ≥0.20 ⇔ ≥12/60 flip một chiều (exact McNemar
  hai phía p ≈ 3.2e-06 khi cả 12 discordant cùng hướng) → ngưỡng đủ power.
- **SUPPORTED** nếu tồn tại ≥1 bậc thỏa cả hai điều kiện (điểm effect + p)
  → paper được phép viết "component X of the bundle carries the harm", với
  X = khối của bậc thỏa; nếu nhiều bậc thỏa → liệt kê TẤT CẢ, bậc Δ lớn nhất
  là thủ phạm chính, ghi rõ cumulative-ladder không tách tương tác. Verdict
  framing thứ hai theo rule concentration của config A2 (bậc flip lớn nhất;
  "distributed" nếu không bậc nào ≥50% tổng flip) báo cáo cạnh bên (§1a).
- **NOT_SUPPORTED** nếu không bậc nào thỏa → rẽ nhánh bundle-synergy (§4).
- Spot-check qwen (A1 vs A5): chỉ narrate, không tham gia H-M1.

### H-M2: minimal variant (A1 boundary-only) KHÔNG gây harm
- **Phát biểu:** recall(A1) ≥ recall(A0) − 0.05 (Δrecall harm ≤0.05 vs B0)
  **trên arm chính (C5_near)**. (Không đòi p — đây là rule an toàn theo điểm
  ước lượng; giới hạn trên hẹp để guidance không phụ thuộc power.)
- **SUPPORTED** → mở khoá guidance "keep minimal provenance, drop the bundle"
  (§4, nhánh G1). Nếu recall(A1) ≥ recall(A0) − 0.05 nhưng đồng thời
  recall(A1) > recall(A0) + 0.10 với p<0.05 (A1 giúp hồi recall): guidance
  thành "boundary label alone recovers part of the loss" — vẫn ghi G1', không
  khoe defense-effectiveness vì floor-effect llama B0 (over-trigger) đã
  disclosed.
- **VIOLATED** (recall(A1) < recall(A0) − 0.05 trên arm chính) → minimal provenance
  cũng không an toàn; guidance chuyển G3 (§4): "do not wrap untrusted
  commentary at all on this model class".

### H-M3: FP-bias tăng theo arm C5 (rule chốt cho dữ liệu ĐÃ CÓ)
- **Phát biểu:** FP-bias(arm) := số flip paired benign→vulnerable vs C0.
  "FP-bias tăng theo arm C5" cho một model khi và chỉ khi:
  **flips(C5_near) ≥ flips(D2_task) AND flips(C5_far) ≥ flips(C5_near) AND
  flips(C5_near) > 0** (non-decreasing dọc D2→near→far, có bias thực).
  Mỗi arm nonzero phải kèm exact McNemar p<0.05 để được kể là bias đo được.
- **Trạng thái dữ liệu Vòng 5 (đã có, chỉ ghi lại verdict theo rule):**
  - Llama: 10 / 11 / 11 → **SUPPORTED** (11≥11≥10, nonzero; p≤0.00103 mỗi arm
    nonzero, exact binomial hai phía n=60).
  - Granite: 10 / 20 / 25 → **SUPPORTED** (p≤0.006 D2, p<0.001 C5).
  - Qwen: 0 / 0 / 0 → Δ=0 là artifact TRẦN bão hòa (FP-rate đã 1.000 ngay ở
    C0 — không còn headroom hai phía), KHÔNG phải robustness (phân tích
    A1-R6, docs/verdict_bias.md).
  → tổng: **2/3 models**; paper giữ cách diễn đạt hiện có ("10–11 per arm",
  "up to 25/30") — rule này chỉ khoá điều kiện được phép viết "tăng theo arm".
- Nếu A1-R6 đo thêm arm/benchmark mới: cùng công thức, không đổi ngưỡng; kết
  quả mới chỉ CỘNG DỒN evidence, không thay thế verdict Vòng 5.

### Rule bundle-synergy (bắt buộc ghi trước, theo yêu cầu pre-reg)
**Nếu H-M1 NOT_SUPPORTED** (không bậc đơn nào đạt Δ≥0.20 & p<0.05) nhưng tổng
thương A0→A4 vẫn harm: Δ_total := recall(A0) − recall(A4) ≥ 0.20 với McNemar
p<0.05 (dữ liệu Vòng 5 đã cho 0.633/0.667, p≤3.8e-06) → kết luận là
**bundle-synergy**: harm phát sinh từ SỰ KẾT HỢP, không từ một khối đơn lẻ.
Đây vẫn là finding — kể khác đi: "no single component is attributable under a
cumulative ladder; the harm is compositional". Paper viết theo hướng này,
KHÔNG được chọn thủ phạm tùy tiện. Nếu Δ_total <0.20 hoặc p≥0.05 → failure to
replicate harm của Vòng 5 (khai báo trung thực; kiểm tra prompt-identity
trước khi nghi ngờ anything else).

### Bảng quyết định guidance (trước khi có số)
| H-M1 | H-M2 | Guidance trong paper |
|---|---|---|
| SUPPORTED (bậc j là thủ phạm chính) | SUPPORTED | **G1**: "keep minimal provenance (A1 boundary label), drop the components added from step j onward" |
| SUPPORTED | VIOLATED | **G3**: "even the minimal boundary label corrupts verdicts on this model class — do not wrap untrusted commentary at all" |
| NOT_SUPPORTED (Δ_total đạt) | bất kỳ | **G2**: "the harm is bundle-synergy; no component-level fix identified — avoid the bundle as a whole" |
| NOT_SUPPORTED (Δ_total không đạt) | bất kỳ | **G0**: "harm failed to replicate under the registered ladder; report as-is" (kèm prompt-identity check) |

## 4. Power & ngưỡng (ghi rõ trước)
n=30 vul/arm/model. Δrecall ≥0.20 ⇔ ≥6 flip một chiều ròng; exact McNemar với
6/30 discordant cùng hướng: p = 2·Σ_{k≤6} C(30,k)/2^30 ≈ 1.1e-04 <0.05 →
ngưỡng Δ≥0.20 đủ power — effect điểm và p không mâu thuẫn ở quy mô này. Δ<0.20 KHÔNG được lẽo láo kể là "harm tiềm ẩn" — ghi là
not-attributable.

## 5. Hợp đồng thực thi — [AMENDMENT-1] `configs/round6_ablation.yaml` (A2) là thẩm quyền thực thi
Thực thi (prompt composition, sha-gate reuse per record, subset, jobs order,
budget guard) theo config A2 — vốn đã tôn trọng các điểm cốt lõi của hợp đồng
gốc: prompt compose từ `p3_boundary`/builder A1 read-only; reuse B0/A5 trên
per-record prompt-sha match (regenerate khi lệch, thay vì STOP — chặt hơn bản
gốc); gen_cfg/monitor/bench byte-identical Vòng 5.
Còn lại là **hợp đồng tích hợp paper** (bên S/A3):
1. `outputs/experiments/round6_ablation/results_<model>.json` kèm metadata đầy
   đủ (model id/revision, seed, config sha, prompt sha mỗi record) — như Vòng 5.
2. Bản tổng `outputs/master/round6_ablation.json` — schema `results[]` rows
   {experiment:"ABLATION", metric:"ablation.<model>.<arm>.<step>.recall_vul"
   | ".fp_rate" | ".flip_v2b" | ".flip_b2v" | ".mcnemar_p_vs_prev", value, n,
   source_file, note} — `paper/make_figures.py::fig_round6` + S-Vòng-6 đọc
   đúng schema này (arm chính C5_near bắt buộc có đủ grid A0..A5; C5_far
   optional). Nếu A2 không sinh file này ở metrics stage, một collector kiểu
   `collect_master_round5.py` phải làm trước khi S điền số (TODO orchestrator).
3. Verdict H-M1/H-M2 + bundle-synergy + rule concentration của A2 tính bằng
   script từ records, KHÔNG đi tay; verdict json kèm trong cùng thư mục, mỗi
   row ghi rule nào fire.

## 6. Giới hạn đã khai trước (đưa vào paper nguyên văn ý)
- Cumulative ladder KHÔNG tách tương tác giữa khối; chỉ attributable theo bậc.
- Không có C0×P3 control trong vòng này → không kết luận "P3 chỉ harmful khi
  có advisory" (khoảng trống cũ, giữ nguyên).
- n=60 vul + 30 benign, 1 model chính (llama); llama B0 over-trigger (recall
  1.000 là floor của all-vulnerable bias, không phải năng lực) → mọi
  recall-collapse là "kéo verdict về benign trên model over-trigger".
- Kết quả chỉ ở 2–3B open models; không generalize. Qwen chỉ spot-check;
  Granite không thuộc ladder.
- Recovery không phải bậc ladder (P3R ≡ P3 đã chứng minh Vòng 5); nếu ladder
  có non-ANSWER thì recovery được nhắc lại như giải thích, không phải rung.

## 7. Tích hợp paper (đã chừa chỗ từ trước — A3-V6)
- `paper/sections/05_results.tex`: subsection RQ7b "Which component corrupts?"
  với bảng `tab_round6_ablation` + figure `fig_round6` (guarded) — mọi số là
  placeholder `{{R6:...}}` cho đến khi S-Vòng-6 điền từ
  `outputs/master/round6_ablation.json`.
- `paper/sections/06_discussion.tex`: đoạn guidance theo bảng quyết định §3
  (4 nhánh G0–G3 đã soạn sẵn văn bản có điều kiện).
- Quy ước placeholder: token dạng `{{R6:<tên>}}` — grep được bằng
  `grep -rn "{{R6:" paper/`. KHÔNG BỊA SỐ; mỗi token có mục đích ghi ở
  reports/round6/A3_report.md.

---
*Execution log (điền sau):*

- *2026-09-21, S-Vòng-6: generation vòng 6 hoàn tất; verdicts H-M1 SUPPORTED
  (culprit rung A5: Δrecall 0.465, exact McNemar p=7.45e-09), H-M2 SUPPORTED,
  concentration framing cùng chỉ A5 (28/34 net flips) → guidance G1. Số điền
  vào paper từ `outputs/master/round6_ablation.json` (collector
  `scripts/collect_master_round6.py`, re-read verified; token map
  `outputs/master/round6_token_map.json`). Không hypothesis/rule nào bị sửa —
  chỉ sửa nhãn timestamp Amendment-1 (00:25 → mtime 00:20:02) theo V1-R6
  MINOR-3, và bổ sung log này (đúng điều khoản cho phép ở đầu tài liệu).*
- *Ghi chú phương pháp (V1-R6): "McNemar exact" ở các cell discordant ≥25 được
  module stats thực thi thành xấp xỉ χ² hiệu chỉnh liên tục (bảo thủ hơn, p
  lớn hơn exact); cả hai biến thể được lưu trong master JSON, không verdict
  nào đổi. Hot rung A5-vs-A4: exact 7.45e-09 / χ²-cc 3.35e-07; A5-vs-A0:
  exact 1.16e-10 / χ²-cc 1.52e-08.*
- *[S-R6 correction, V2-R6 issue 4] wording "49/60 samples completed in
  round 5" trong `configs/round6_ablation.yaml` (spot_check.reuse mô tả)
  thực ra là 49 = tổng records qwen P3 C5_near (30 vul + 19 benign), tức
  30/60 vul candidates. Chữ trong config KHÔNG được sửa để bảo toàn chuỗi
  sha16 parsed-config `88c07bff09f0829b` (khớp 2 file kết quả sau amendment);
  correction được ghi nhận tại đây và trong reports/round6/.*
- *Đếm vị trí placeholder: 47 token duy nhất ở 56 vị trí (bản ghi "63 vị trí"
  trong A3_report là sai — V1-R6 NOTE); tất cả đã được điền, `grep -rn
  "{{R6:" paper/` = 0.*
