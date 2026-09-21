# PRE-REGISTRATION — Round 7: CWE generalization (RQ8) + 7–8B replication (RQ9)

Trạng thái: **ĐĂNG KÝ TRƯỚC** (pre-registration). Viết và đóng băng TRƯỚC khi
bất kỳ generation Vòng 7 nào được chạy. Kiểm chứng filesystem tại thời điểm đóng
băng: `outputs/experiments/` KHÔNG có thư mục `round7_*` nào; chưa có results,
manifest hay cache Vòng 7 (A2 là chủ GPU; S-Vòng-7 điền số vào paper). Sau khi
A2 bắt đầu run, tài liệu này KHÔNG được sửa hypothesis/decision rule — chỉ được
bổ sung Execution log ở cuối (kèm mtime) và Amendment theo điều khoản §0a.

- Tác nhân pre-reg: A3 (Vòng 7 — PRE-REG + ANALYSIS DESIGN + PAPER DRAFTS).
  Ngày đóng băng: 2026-09-20 (trước mọi generation Vòng 7).
- **AMENDMENT-1 (2026-09-21 05:18 +07 — mtime kiểm chứng filesystem; vẫn
  TRƯỚC khi có bất kỳ results.json Vòng 7 nào: `outputs/experiments/` chưa có
  thư mục `round7_*` tại thời điểm amendment. Các pre-reg thực thi của A2
  `configs/round7_7b.yaml` mtime 04:16:21 và của A1 `configs/attack_v2_cwe.yaml`
  mtime 04:43:42 đều TRƯỚC generation. Chi tiết §0b):**
  (i) RQ9 model thực thi = **Qwen2.5-Coder-7B-Instruct** (slug `qwen7b`)
  theo config A2 — llama-8B KHÔNG chạy; (ii) RQ8 family registry theo bench
  thực thi của A1 = **CWE-476 / CWE-416 / CWE-190 / CWE-200** (bản gốc của
  tài liệu này đăng ký F-PATH/CWE-22 — bị thay bởi CWE-200, phần còn lại
  khớp 3/4); (iii) SỬA một nhánh diễn giải H-R1 của bản gốc (nhánh
  "CEILING-uninformative" là SAO CHÉP SAI logic saturation phía FP — saturation
  recall=1.000 KHÔNG che được harm hướng xuống; thay bằng ABSENT-STRONG của
  A2, kèm caveat còn lại là subset-difficulty chứ không phải detectability);
  (iv) H-R1/H-R2 áp dụng rule algebra của config A2 (flips ≥10 / ≤3 / PARTIAL),
  song song với framing của bản này (dual reporting, tiền lệ R6 §1a).
  KHÔNG ĐỔI: mọi ngưỡng significance (p<0.05 exact), rule ≥3/4 family +
  pooled ΔFP≥0.15, anti-masking clause, no-multiple-comparisons, power notes,
  bảng guidance, RR-separate.
- Phạm vi: hai stream Vòng 7 theo khuyến nghị ROUND6_SUMMARY #2 (mở rộng CWE
  families) và #3 (model lớp 7B):
  - **RQ8 — CWE generalization của kênh verdict-bias** (phía attack, FP-direction):
    bias benign→vulnerable dưới C5, đã đo được trên bench gốc nặng memory-copy
    (llama 49/60→60/60, p=9.8e-04; granite FP 0.043→0.714 combined n=70,
    p χ² 1.95e-11; nguồn `outputs/master/round6_bias.json` +
    `round6_ablation.json` extension rows), có tổng quát qua các HỌ CWE khác
    hay không, hay là artifact của họ memcpy/strcpy?
  - **RQ9 — 7–8B replication của reassertion-harm** (phía defence): harm đã
    định vị ở rung A5 trên Llama-3.2-3B (Δrecall 0.465, exact p=7.45e-09;
    28/34 net flips; nguồn `outputs/master/round6_ablation.json`), có tái lập
    ở lớp 7–8B hay không — và nếu không, đọc theo hướng nào cho trung thực.
- Ràng buộc kế thừa (vẫn hiệu lực): refusal KHÔNG BAO GIỜ map thành benign;
  RR báo cáo riêng ở mọi cell; không bịa số; không cherry-pick framing sau hoc;
  baseline saturation (qwen FP=1.000 tại C0) phải được disclose là
  *uninformative*, không được kể là "robustness" (phân tích A1-R6,
  `docs/verdict_bias.md`).

## 0a. Cơ chế hai tầng + Amendment (bài học Vòng 6, áp dụng nguyên văn)

Tài liệu này là **pre-reg tích hợp** (bên A3/S): chốt CỨNG mọi giả thuyết,
ngưỡng, rule quyết định, bảng nhánh diễn giải. **Pre-reg thực thi** (A2,
`configs/round7_*.yaml`, mtime phải trước generation đầu) định granularity
thực hiện: tên file results, thứ tự job, dtype/quantization, model id chính
xác. Nếu hai bản khác nhau ở BẬT KỲ điểm nào ảnh hưởng việc đọc kết quả →
**AMENDMENT-1** vào tài liệu này TRƯỚC khi có results.json đầu tiên (kèm mtime
kiểm chứng filesystem), giữ nguyên mọi ngưỡng/rule; reconciliation phải ghi rõ
cả hai framing khi chúng khác chữ (tiền lệ R6 §1a). Thay đổi SAU generation
đầu tiên = vi phạm, kết quả phải báo as-is kèm vi phạm.

## 1. RQ8 — CWE generalization (thiết kế)

### 1.1 Nguyên tắc chọn family

Bench gốc `bench_attack_v1.jsonl` (sha256_16 `2daa249f7543f8e0`) nặng memory-copy:
memcpy 49 + free 28 + strlen 19 + strcpy 10 trên 200 rows (26-sink inventory,
`configs/attack_v2.yaml`); các CWE trội là CWE-787/125/119/703 (memory-safety
copy-side). RQ8 đo trên **4 family mới, tách khỏi cụm memory-copy**.

**[AMENDMENT-1: registry theo bench thực thi của A1 — `configs/attack_v2_cwe.yaml`,
`data/benchmarks/bench_attack_v2/`; bảng gốc bên dưới GIỮ để minh bạch,
F-PATH bị thay bởi CWE-200.]**

| Family (canonical key) | Nhãn | Anchor signal (A1) | Ghi chú |
|---|---|---|---|
| **CWE-476** | NULL pointer dereference | `pointer_surface` | trùng bản chất F-NPD gốc |
| **CWE-416** | use-after-free / heap lifetime | `heap_lifecycle` | trùng bản chất F-UAF gốc |
| **CWE-190** | integer overflow / size arithmetic | `arith_scaling` | trùng bản chất F-INT gốc |
| **CWE-200** | information exposure | `log_output` | **mới so với bản gốc** (thay F-PATH/CWE-22) |

Quy mô bench v2: mỗi family 20 vul + 20 benign (n=20 benign/family = endpoint
chính — giữ nguyên); 4 arm C0/D2_task/C5_near/C5_far; advisory feature-based
từ anchor signal (không nêu tên CWE/label — anti-leakage A1); gate RQ8 vẫn
**C5_near = arm chính** (D2_task/C5_far báo cạnh bên, không gate).

*Bảng gốc (bản 04:22:48, trước amendment — giữ nguyên văn):*

| Family | Nhãn | Cơ chế đại diện | Sink kiểu (AST-visible) |
|---|---|---|---|
| **F-UAF** | CWE-416 use-after-free | dùng pointer sau free/realloc | `free` + deref tiếp theo |
| **F-INT** | CWE-190 integer overflow | số học width/truncation → length sai | `atoi`/`strtol`/cast + alloc/copy |
| **F-PATH** | CWE-22 path traversal | ghép path từ input không validate | thao tác string trên path (`getenv`+`strcat`/`sprintf`) |
| **F-NPD** | CWE-476 NULL deref | deref con trỏ không check NULL | load/deref sau call có thể trả NULL |

- Quy tắc bổ sung nguồn (nếu PrimeVul không đủ benign đạt chuẩn cho một family
  — tiêu chí tuyển theo đúng pipeline C5: có advisory concrete query-relevant
  từ AST, anti-leakage, policy-safe): **fallback order đăng ký trước**:
  F-DIV (CWE-369 divide-by-zero) → F-UPLOAD (CWE-434) → F-CMD (CWE-78). Mọi
  thay thế phải vào Amendment-1 TRƯỚC generation, kèm lý do supply-based
  (không được chọn theo kết quả chạy thử — chạy thử/PEND không được phép trước
  freeze).
- Quy mô: **n=20 benign/family × 4 = 80 benign** (tập benign là endpoint chính —
  kênh đang kiểm chứng là FP-direction). Vulnerable side (≤20 vul/family, nếu
  A2 chạy) là secondary, chỉ narrate, không gate.
- Advisory: dùng đúng generator C5 hiện có (concrete query-relevant từ AST của
  chính hàm; anti-leakage: 0 label/CWE/CVE content; policy-safe; pattern
  templates byte-giống bench gốc). Mỗi row phải có kiểm định advisory
  (advisory.risky_apis ⊆ row.risky_apis như T7) — tỉ lệ pass phải được báo
  trong manifest; nếu <100% thì disclose từng case.
- Arm: **C5_near = arm chính duy nhất** (nhất quán R5/R6; C5_far optional
  secondary, nếu chạy thì báo cạnh bên, không gate).
- Khía cạnh mẫu: paired same-sample C0 vs C5_near (mỗi benign sample chạy cả
  hai arm; McNemar paired). Sampling seed ghi trong manifest; KHÔNG fit gì trên
  test; manifest ghi sample_ids + family + advisory sha.

### 1.2 Model chính cho RQ8

- **Primary: Granite-3.3-2B** (`granite2b`) — model có headroom FP lớn nhất và
  effect đã đo mạnh nhất (C0 FP 0.043, combined n=70 +47 flips p χ² 1.95e-11).
  llama3b có C0 FP ≈ 0.82 trên bench gốc → headroom ΔFP chỉ còn ~0.18, thích
  vai trò secondary.
- **Secondary (replication, nếu budget): llama3b**, với caveat headroom được
  disclose trước (C0 FP của llama TRÊN family mới là chưa biết — không được
  giả định; chỉ báo cáo as-is).
- Qwen2.5-Coder-3B KHÔNG chạy: FP=1.000 tại C0 (saturated, uninformative —
  tiền lệ R6). Nếu A2 muốn chạy thêm thì kết quả chỉ narrate, không gate.

## 2. RQ8 — Hypotheses + decision rules (CHỐT, không đổi sau khi A2 chạy)

Đơn vị phân tích: (benign sample, arm), paired same-sample. Endpoint chính:
flip benign→vulnerable (`b2v`) vs C0; endpoint đối xứng (corrections) `v2b`
được báo cáo đầy đủ. p: **two-sided exact binomial McNemar** (recompute từ
records trong collector; biến thể χ²-cc của module stats khi discordant ≥ 25
được lưu cạnh bên, χ² là bảo thủ — quy ước R6).

### H-G1 (PRIMARY, family-level)
- **Phát biểu:** kênh verdict-bias FP-direction xuất hiện ở **≥3/4 family mới**.
  "Family f shows bias" ⟺ trên benign của family f (n=20): exact McNemar
  p<0.05 **và** b2v > v2b (điều kiện hướng).
- **Power (tính exact theo ĐÚNG thống kê implemented trong collector —
  McNemar chỉ tính cặp discordant, `p = 2·Σ_{k≤min(b,c)} C(b+c,k)/2^(b+c)`):
  với n=20/family, cấu hình discordant nhỏ nhất đạt p<0.05 là **6/20 cùng một
  hướng** (b=6,c=0 → p = 2/2⁶ = 0.03125; 5/20 chỉ được 0.0625 → KHÔNG đạt).
  Với 1 chiều ngược: b=8,c=1 → p = 2·(1+9)/2⁹ = 0.039. ⇒ ngưỡng family-level
  là chính vì per-family power thấp; pooled KHÔNG được dùng để thay thế
  per-family (§2.3).

### H-G2 (SECONDARY, pooled)
- **Phát biểu:** pooled 80 benign: **ΔFP ≥ 0.15** (ΔFP = FP(C5_near) − FP(C0),
  paired) với exact McNemar p<0.05 và b2v > v2b.
- Power: Δ0.15 trên 80 samples ⇔ ≥12 net flips một chiều; cấu hình thuần
  (12,0) cho p = 2/2¹² ≈ 4.9e-04.

### 2.3 Quy tắc verdict RQ8 (CHỐT)
1. **GENERALIZES** ⟺ family_pass_count ≥ 3 **HOẶC** (H-G2 đạt).
   - Sub-label bắt buộc khi GENERALIZES do pooled mà family_pass_count ≤ 2:
     **"pooled-driven"** — paper phải in bảng per-family đầy đủ và nêu tên
     family đang kéo pooled effect (anti-masking clause, §2.5).
2. **FAMILY-DEPENDENT** ⟺ family_pass_count ≤ 2 **VÀ** H-G2 không đạt.
   - Vẫn là finding, kể trung thực: "kênh verdict-bias cho đến nay mới được
     chứng minh trên bench gốc nặng memory-copy; chưa (hoặc chỉ từng phần)
     tổng quát qua các họ CWE khác ở quy mô này".
3. **CẤM pooling che dấu per-family null**: mọi verdict PHẢI kèm cả hai —
   bảng 4 dòng per-family (flips, p) và dòng pooled. Không được chỉ báo pooled.
4. Không hiệu chỉnh đa so sánh; không gian test đã khai trước: 4 test
   family-level + 1 test pooled = 5 so sánh, mọi kết quả âm giữ nguyên trạng
   thái (quy ước R6).
5. Family nào bị thiếu sample (manifest < 20 benign đạt chuẩn) mà không qua
   Amendment: family đó được báo "not-run/unpowered", KHÔNG được tính vào mẫu
   4 family; nếu còn ≤3 family chạy được thì verdict chỉ có thể là
   FAMILY-DEPENDENT hoặc pooled-driven — ghi rõ số family thực chạy.

### 2.4 Secondary (không gate, báo đầy đủ)
- vul-side recall mỗi family (C0→C5_near), nếu A2 chạy vul; FN-direction được
  kiểm tra để đối xứng với attack-side (kỳ vọng từ R6: FP-direction trội,
  FN ≈ 0 — nếu family mới cho FN-significant thì là finding mới, báo as-is).
- FP-rate tuyệt đối mỗi (family × arm); ΔFP mỗi family kèm CI bootstrap
  (10,000 resamples, seed ghi trong manifest — quy ước R5/R6).
- Echo-evidence mỗi family (đếm flip-output echo advisory) — narrate.
- RR mỗi cell (kỳ vọng 0; nếu >0 → sự kiện, báo as-is, refusal không map benign).

### 2.5 Anti-masking clause (bắt buộc ghi trước)
Pooling 4 family là công cụ power, KHÔNG phải công cụ kết luận. Bất kỳ câu văn
nào của paper dựa trên pooled cũng phải đứng cạnh bảng per-family. Nếu pooled
đạt nhờ 1–2 family (bất đối xứng lớn giữa các family — ví dụ 1 family +18/20,
3 family ≈ 0), paper PHẢI viết cấu trúc đó (heterogeneity), không được viết
"the bias generalizes across CWE families" khi family_pass_count ≤ 2.

## 3. RQ9 — 7–8B replication (thiết kế + hypotheses, CHỐT)

### 3.1 Thiết kế
- Bench/arm/subset **byte-identical R6**: `bench_attack_v1.jsonl`
  sha256_16 `2daa249f7543f8e0`; arm **C5_near**; subset **60 vul + 30 benign
  llama, seed 20260923** (đúng subset R6 — để so sánh scale-only cùng sample);
  prompt builder + gen_cfg (temp 0, max_new_tokens 512, seed 1234, batch 1) +
  monitor required_fields byte-giống R6. Mỗi record phải ghi prompt_sha256_16
  và PHẢI khớp prompt_sha của record R6 cùng (sample, rung) khi có — đây là
  guard "same prompt, different model" (kiểm trong collector).
- **Rungs (minimal replication ladder):** A0 (B0 raw), A1 (boundary-only =
  minimal provenance), A5 (system reassertion = full P3). Lý do bỏ A2–A4: R6
  đã định vị thủ phạm ở A5; RQ9 chỉ hỏi scale, không hỏi lại component.
  Nếu budget cho phép full A0..A5 → được phép, báo cạnh bên (không gate).
- **KHÔNG cross-model cache-reuse**: mỗi (sample, rung) ở model 7–8B là
  generation mới (bài học quarantine R6: sha-gate model-blind phải kèm
  model-match check; collector assert `reused_from` chỉ trỏ tới record
  CÙNG model).
- **Model đăng ký — [AMENDMENT-1: thực thi = qwen7b duy nhất; mục gốc giữ
  nguyên văn dưới đây để minh bạch, "primary Llama-3.1-8B" KHÔNG chạy]:**
  primary **Llama-3.1-8B-Instruct** (family-matched với
  model phát hiện harm Llama-3.2-3B → so sánh scale thuần trong cùng họ);
  secondary (nếu budget) **Qwen2.5-Coder-7B-Instruct** (family-matched với
  qwen-3B inert → test "inertness có giữ ở 7B không"). Nếu cả hai không chạy
  được (OOM/technical) → RQ9 không có số, paper giữ scope "2–3B" + disclose
  (đây là thất bại thực thi, không phải finding; không được thay bằng
  model khác không trong bảng này mà không có Amendment-1 trước generation).
  **Thực thi amendment:** model = `Qwen/Qwen2.5-Coder-7B-Instruct` (config
  A2 `configs/round7_7b.yaml`, slug `qwen7b`, ungated, sha đã verify trong
  config; dtype bfloat16, fallback float16 chỉ khi OOM at load trước jobs);
  hệ quả diễn giải family-inertness xem §0b(i). Source layout: per-variant
  files `outputs/experiments/round7_7b/results_qwen7b__vul__{A0,A1,A5}.json`
  + `results_qwen7b__benign__B0.json` (benign_fp_check = nguồn C0-arm cho
  H-R3).

## 0b. Nội dung Amendment-1 (chi tiết)

**Timeline thật (mtime filesystem):** prereg của tài liệu này 04:22:48 (bản
gốc, sau config A2 04:16:21 — hai bên chưa đọc nhau khi viết; bench config
A1 04:43:42; amendment này 05:18+07). Generation Vòng 7: CHƯA bắt đầu
(`outputs/experiments/` không có `round7_*` tại 05:18).

**(i) RQ9 — model thực thi là qwen7b.** Config A2 chọn
`Qwen/Qwen2.5-Coder-7B-Instruct` (ungated, sha ghi trong config; dtype
bfloat16, fallback float16 chỉ khi OOM at load, trước jobs — đúng điều khoản
§3.1). llama-8B không có trong queue. Hệ quả diễn giải (đăng ký trước số):
qwen7b là model cùng HỌ với qwen-3B (inert ở Vòng 6), nên một kết quả NULL
ở RQ9 KHÔNG tách được "harm diminishes with scale" khỏi "family-inertness
giữ nguyên ở 7B" — mandate cho phép đọc null là "harm diminishes with
scale", và đọc đó được GIỮ nhưng BẮT BUỘC kèm caveat family-inertness; và
nếu harm REPLICATE ở qwen-7B thì đó là bằng chứng mạnh HƠN dự kiến (cross
family + cross scale). Scope-claim "open 2–7B" áp dụng cho existence of
measurement ở model đã đo, không generalize.

**(ii) RQ8 — family registry theo bench thực thi.** Bench A1
(`configs/attack_v2_cwe.yaml` → `data/benchmarks/bench_attack_v2/`):
4 family × (20 vul + 20 benign), family key = CWE-ID:
CWE-476 (anchor signal pointer_surface), CWE-416 (heap_lifecycle),
CWE-190 (arith_scaling), CWE-200 (log_output; "information exposure").
Bản gốc đăng ký F-PATH/CWE-22 — không có trong bench thực thi, BỊ THAY BỞI
CWE-200; 3/4 family còn lại khớp bản chất. canonical family keys của
collector = chuỗi CWE-ID; alias cũ (F-UAF…) giữ để tương thích đọc. Advisory
feature-based (signal), không nêu tên CWE/label — anti-leakage của A1 giữ
nguyên. Arm: bench có 4 arm (C0/D2_task/C5_near/C5_far); gate của RQ8 vẫn
C5_near làm arm chính, D2_task/C5_far báo cạnh bên (không gate). Endpoint:
verdict-bias theo y_pred (H-G1/H-G2, bản này — CHÍNH cho RQ8 theo mandate)
+ gate của A1 (`gate_v2_families`, benign_block, Δ≥0.10, ≥2/4 family) báo
song song như một endpoint blocking-side, không thay thế.

**(iii) SỬA nhánh H-R1 của bản gốc.** Bản gốc viết nhánh (a) CEILING
"A0=1.000 → uninformative" bằng cách sao chép logic saturation phía FP của
qwen-3B (FP=1.000 tại C0 → hết headroom hai phía). Đó là SAO CHÉP SAI cho
endpoint recall phía vul: recall=1.000 là TRẦN trên, harm đi XUỐNG, nên
saturation KHÔNG che được harm — A0=1.000 + không có flip 1→0 là bằng chứng
VẮNG MẠNH trên subset này (logic H-R7-harm-absent của A2: "the saturated
baseline cannot hide 1→0 flips"). Sửa thành **ABSENT-STRONG**; caveat còn
lại (đăng ký trước số) là subset-easiness/external-validity — "strong on
this subset", không phải "the defence is safe, period". Các nhánh khác giữ.

**(iv) Rule algebra H-R1/H-R2 theo config A2 (dual reporting).**
H-R1 SUPPORTED: Δrecall(A0−A5) ≥ 0.20 AND exact McNemar p<0.05 AND
flips(1→0) ≥ 10 (điều kiện thứ ba là hệ quả của thứ nhất trên n=60 nhưng
giữ nguyên văn để byte-consistent với config). ABSENT (STRONG nếu
recall(A0)=1.000): Δ≤0.05 AND p≥0.05 AND flips≤3. REVERSAL: recall(A5) >
recall(A0)+0.10 với p<0.05. PARTIAL-INCONCLUSIVE: mọi cấu hình còn lại
(bao gồm gap 3<flips<10 của A2). Verdict chuỗi H-R7-* của A2 được in
nguyên văn cạnh verdict của tài liệu này. H-R2: SAFE iff flips(A1 vs A0) ≤3
AND p≥0.05; UNSAFE (harm attributable to A1) iff flips ≥10; PARTIAL ở giữa
(≈ tương đương rule điểm Δ≤0.05 của bản gốc khi b2v=0). H-R3 giữ nguyên
(C5 benign C0-vs-C5_near paired; SATURATED-UNINFORMATIVE nếu fp(C0)≥0.95;
6/30 power note); benign_fp_check của A2 (priority 4) chính là nguồn C0-arm.
- Dtype/quantization: quyền A2; NẾU phải đổi dtype (ví dụ 4-bit) để fit →
  Amendment-1 trước generation + mọi kết quả gắn nhãn substrate (không so
  số trực tiếp với bf16 3B như cùng substrate).

### 3.2 H-R1 (primary): reassertion-harm tái lập ở 7–8B?
- **Phát biểu:** recall(A0) − recall(A5) **≥ 0.20** với exact McNemar p<0.05
  (paired, 60 vul). Power: Δ≥0.20 ⇔ ≥12/60 flip một chiều; theo thống kê
  McNemar implemented (chỉ tính discordant, b=12,c=0): exact p = 2/2¹² ≈
  4.9e-04 < 0.05 → ngưỡng đủ power. [Ghi chú minh bạch: prereg R6 ghi
  "p≈3.2e-06" cho cùng ngưỡng — đó là phép tính sign-test trên cả 60 cặp,
  không phải McNemar discordant-only mà collector thực thi; cả hai đều <0.05
  nên ngưỡng không đổi, nhưng R7 đăng ký theo đúng biến thể implemented.]
- **SUPPORTED** → "harm persists at 7–8B (one model)" — scope-claim của paper
  được phép mở thành open 2–7B models cho *existence of the defence-risk
  channel*, vẫn single-model-per-scale, không generalize.
  **[AMENDMENT-1: rule SUPPORTED áp dụng nguyên văn config A2 — Δ≥0.20 AND
  exact p<0.05 AND flips(1→0)≥10; verdict chuỗi H-R7-* của A2 in song song.]**
- **NOT_SUPPORTED — các nhánh diễn giải (đăng ký TRƯỚC, cả hai hướng, theo
  mandate); [AMENDMENT-1: nhánh (a) CEILING của bản gốc đã BỊ SỬA thành
  ABSENT-STRONG — xem §0b(iii); (d) INCONCLUSIVE gộp vào PARTIAL]:**
  - **(a→sửa) ABSENT-STRONG:** recall(A0) = 1.000 (saturated), Δ≤0.05,
    p≥0.05, flips≤3 → vắng mặt là MẠNH trên subset này (trần trên không che
    được harm hướng xuống); caveat còn lại: subset-difficulty/external
    validity, KHÔNG được viết "the defence is safe" chung chung.
  - **(b) DIMINISHES / ABSENT:** recall(A0) < 1.0, Δ≤0.05, p≥0.05, flips≤3 →
    harm vắng mặt ở 7B trên subset; với model thực thi qwen7b (cùng họ
    qwen-3B inert) BẮT BUỘC kèm caveat family-inertness-vs-scale (§0b(i));
    wording "harm diminishes with scale" chỉ được dùng kèm caveat đó.
  - **(c) REVERSAL:** recall(A5) > recall(A0) + 0.10 với exact p<0.05 →
    "directional reversal at scale" — báo as-is, là finding độc lập.
  - **(d) PARTIAL-INCONCLUSIVE:** mọi cấu hình còn lại (gồm gap
    3<flips<10 của A2 và vùng headroom 0.90–1.0 của bản gốc) → báo
    as-is, mô tả, không kết luận hướng.
  - Thứ tự xét nhánh (fix trước): SUPPORTED → REVERSAL → ABSENT-STRONG →
    ABSENT → PARTIAL-INCONCLUSIVE. Mọi nhánh phải in cùng bảng; KHÔNG chọn
    nhánh khớp narrative.

### 3.3 H-R2: minimal A1 an toàn ở 7–8B?
- **[AMENDMENT-1: rule theo config A2] SAFE** ⟺ flips(1→0, A1 vs A0) ≤ 3
  AND exact p≥0.05 (tương đương rule điểm Δ≤0.05 của bản gốc khi b2v=0).
  **UNSAFE** (harm attributable to A1) ⟺ flips ≥ 10. **PARTIAL** ở giữa →
  báo mô tả. UNSAFE → cảnh báo G3-style ("even the minimal boundary label
  corrupts") được phép mở scope lên lớp 7–8B.
- Benign-side ΔFP(A0→A1) báo cạnh bên (không gate).

### 3.4 H-R3: FP-bias 7–8B direction-consistent?
- **Điều kiện dữ liệu:** so sánh paired C0-vs-C5_near trên benign của model
  7–8B ⇒ chạy cần thêm arm C0 (B0) cho 30 benign của model đó (30 records;
  nhẹ). Nếu source KHÔNG có benign C0-arm của model đó → **H-R3 = NOT_RUN**
  (disclose; KHÔNG được đổi thành pass bằng cách lấy C0 của model khác).
- **Phát biểu:** dưới C5_near, benign→vul flips > 0 với exact McNemar p<0.05
  trên 30 benign (power: cấu hình thuần nhỏ nhất đạt là 6/30, p = 0.03125;
  5/30 = 0.0625 không đạt) **và** không có reverse-significant (v2b không đạt
  p<0.05 theo hướng ngược).
- **SATURATED-UNINFORMATIVE** nếu FP(C0) ≥ 0.95 (không còn headroom — tiền lệ
  qwen; không được kể là consistency).
- **DIRECTION-REVERSED** nếu v2b significant và b2v không — báo as-is.
- Nếu C5_far được chạy: confirmatory, cùng rule, báo cạnh bên.

### 3.5 Tích hợp scope-claim (điều kiện rõ)
- Có số RQ9 (bất kể nhánh nào trong SUPPORTED/(a)/(b)/(c)) → mọi câu "open
  2–3B models" trong paper được cập nhật thành "open 2–7B models" kèm đúng
  định tính theo nhánh; nếu RQ9 không chạy được → giữ "2–3B" + disclose ở
  limitations (hiện trạng đã có sẵn trong 06_discussion).
- Có số RQ8 → câu scope CWE của kênh verdict-bias cập nhật theo verdict
  GENERALIZES / pooled-driven / FAMILY-DEPENDENT (từ đúng §2.3, không phóng
  đại; FAMILY-DEPENDENT phải xuất hiện trong discussion nếu nó fire).

## 4. Hợp đồng tích hợp (bên A3/S — như R6 §5.2)

1. Source files **[AMENDMENT-1 paths]**:
   - RQ9 (thực thi A2): `outputs/experiments/round7_7b/results_qwen7b__vul__A0.json`,
     `results_qwen7b__vul__A1.json`, `results_qwen7b__vul__A5.json`,
     `results_qwen7b__benign__B0.json` (records có `variant`, `condition`=arm,
     `y_pred`, `y_true`, `meta.prompt_sha256_16`; model-guard của A2 ở metrics
     stage, collector tự assert thêm).
   - RQ8: bench `data/benchmarks/bench_attack_v2/{bench_attack_v2.jsonl,
     manifest_attack_v2.json}` (A1) + results GPU theo runner của A2 khi có
     (path tạm đăng ký: `outputs/experiments/round7_cwe/results_<model>.json`
     + `manifest_cwe.json`; collector giữ map path ở đầu file — mọi thay đổi
     path khi runner A2 xuất hiện phải ghi vào amendment và KHÔNG được xảy ra
     sau khi generation RQ8 bắt đầu).
   - Định danh family = chuỗi CWE-ID (CWE-476/416/190/200; alias F-* cũ đọc
     được cho tương thích).
2. Master: `outputs/master/round7_master.json` — schema rows
   `{experiment: "RQ8"|"RQ9", metric, value, ci?, n, model, family?, arm?,
     source_file, note?}` — collector
   `scripts/collect_master_round7.py` build + re-read verify
   (`--verify-only`); **fail-safe**: thiếu nguồn → in `[pending]` list + exit 0,
   KHÔNG ghi file (chỉ tạo master khi có data thật).
3. Verdicts computed-by-rule trong collector (H-G1/H-G2/label RQ8;
   H-R1 branch/H-R2/H-R3 RQ9), KHÔNG đi tay; mỗi verdict row ghi rule nào fire.
4. Paper: `05_results.tex` subsections RQ8/RQ9 + `tables/tab_round7.tex` +
   `make_figures.py::fig_round7` (fail-safe) — toàn bộ placeholder
   `{{R7:*}}` bọc `\detokenize` cho đến khi S-Vòng-7 điền từ master.

## 5. Giới hạn đã khai trước (đưa vào paper nguyên văn ý)
- RQ8: 4 family × 20 benign là quy mô pilot; family-level rule được chọn CHÍNH
  vì per-family power thấp — không được diễn giải kết quả âm family-level như
  "bằng chứng không có bias". Chỉ benign-side được gate; vul-side secondary.
  Family là đơn vị phân nhóm hậu-học CÓ KHAI TRƯỚC (đăng ký trước dữ liệu)
  nhưng vẫn là 5 so sánh không hiệu chỉnh — ngưỡng duy nhất p<0.05.
- RQ9: một model 7–8B (hoặc hai nếu budget) — KHÔNG generalize "scale";
  ladder tối thiểu không tái tách A2–A4 (đã làm ở R6); không có C0×P3 control
  (khoảng trống cũ giữ nguyên); substrate dtype có thể khác giữa 3B và 7–8B
  (disclose khi có).
- Cả hai RQ: kết quả dương/âm đều là finding; verdict từ rule, không từ ý muốn;
  refusal luôn RR riêng.

## 6. Danh sách token `{{R7:*}}` (hợp đồng cho S-Vòng-7)

Quy ước như R6: token dạng `{{R7:<tên>}}`, grep bằng
`grep -rn "{{R7:" paper/`; KHÔNG BỊA SỐ; mọi token trong .tex được bọc
`\detokenize{...}`. Danh sách đầy đủ + mục đích từng token nằm ở
`reports/round7/A3_report.md` §placeholders (nguồn duy nhất), sinh song song
với khung bảng `paper/tables/tab_round7.tex`.

---
*Execution log (điền sau):*

---

## AMENDMENT-2 (2026-09-21 — POST-HOC, PATH-ONLY)

**Trạng thái: hậu kiểm (post-hoc).** Amendment này được ghi SAU khi generation
RQ8 đã hoàn thành (cả hai model 320/320 records), nên theo đúng chữ §0a đây là
vi phạm quy trình path-change ("KHÔNG được xảy ra sau khi generation RQ8 bắt
đầu") — được ghi nhận minh bạch, KHÔNG được dùng để hợp thức hoá bất kỳ thay
đổi rule nào. **Không có hypothesis, ngưỡng, decision rule, bảng nhánh diễn
giải, hay model registry nào bị đổi. Thay đổi duy nhất: PATH.**

- **Nội dung:** prereg §4 đăng ký path tạm cho RQ8 =
  `outputs/experiments/round7_cwe/results_<model>.json` + `manifest_cwe.json`.
  Runner thực thi (`src/experiments/round7_rq8.py`, config
  `configs/round7_rq8.yaml`) lại ghi vào **`outputs/experiments/round7_rq8/`**
  (cùng tên file: `results_granite2b.json`, `results_llama3b.json` — mỗi file
  320 records = 160 benign + 160 vul của MỘT model; `manifest_cwe.json`).
  Collector `scripts/collect_master_round7.py` đã cập nhật map `RQ8_DIR`
  trỏ sang `round7_rq8/` (comment đầu file chừa sẵn chỗ này: "edit these two
  maps then, not the logic"); tests fixture tương ứng
  (`tests/test_round7_master.py`) mirror path mới.
- **Cơ chế bước qua amendment trước generation:** step bridge-copy của runner
  (hợp đồng §4 tạm) kỳ vọng file 80 records/job trong khi driver đã đổi sang
  per-model file 320 records → bridge skipped ("partial-coverage file") và
  path divergence chỉ được phát hiện sau hết CPU/GPU bởi audit V1 (BUG-2/V2
  Issue path-map). Sửa lỗi runner bridge KHÔNG thuộc phạm vi amendment này;
  collector đọc trực tiếp layout thực thi nên bridge copy không còn cần thiết.
- **Hệ quả đọc kết quả: KHÔNG.** Cùng file, cùng records, cùng rule; chỉ đường
  dẫn nguồn đổi. Fail-safe contract (thiếu nguồn → `[pending]` + exit 0,
  không ghi file) giữ nguyên.
- File liên quan: `scripts/collect_master_round7.py` (map + comment),
  `tests/test_round7_master.py` (fixture path), `reports/round7/EXEC_report.md`
  (người sửa: S-exec Vòng 7).
