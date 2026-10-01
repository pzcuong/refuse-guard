# 📊 PHÂN TÍCH CHI TIẾT KẾT QUẢ NGHIÊN CỨU — ĐẦY ĐỦ 11 FINDINGS

## RefuseGuard + PackGuard — 19 vòng, ~7.000+ lượt sinh, 6 mô hình

> **Cập nhật:** 2026-10-01 · **833 tests** · **verify_repro 30/30** · **29+ commits**
>
> **Mỗi phát hiện có:** Phát biểu → Bảng số liệu → Kiểm định thống kê → Cỡ hiệu ứng → Diễn giải → So sánh tài liệu → Phạm vi

---

## MỤC LỤC

- [Tổng hợp 11 findings](#tổng-hợp)
- [F1: Blocking không xảy ra (RR=0)](#f1)
- [F2: CR Advisory — Directional Corruption](#f2)
- [F3: Defense P3 gây harm (Component Ablation)](#f3)
- [F4: Scale Resolution 7B/8B](#f4)
- [F5: Graph Federation-Robust](#f5)
- [F6: TF-IDF Degeneration](#f6)
- [F7: CodeBERT Baseline](#f7)
- [F8: EVIDA FAIL](#f8)
- [F9: P1 Injection Reduction](#f9)
- [F10: LCO Family-Shift Null](#f10)
- [F11: Alarm Precision](#f11)
- [Bảng tổng hợp](#bảng-tổng-hợp)
- [Hạn chế](#hạn-chế)
- [Bước tiếp theo](#bước-tiếp-theo)

---

## F1: BLOCKING KHÔNG XẢY RA (RR = 0.000)

### Phát biểu

> Trên ~7.000+ lượt sinh qua 19 vòng, không một refusal nào được kích hoạt bởi
> defensive framing trên open-weight models 2–8B. Refusal pathway hoạt động
> bình thường (OR-Bench probes: 56% refusal), nhưng defensive framing về code
> security không kích hoạt nó — ở bất kỳ arm nào (C1–C5), bất kỳ source nào
> (system/user/tool/third-party), bất kỳ CWE family nào.

### Bảng số liệu

| Mô hình | Arm | Số gen | RR (refusal rate) | Ghi chú |
|---|---|---|---|---|
| Granite-3.3-2B | C0/CG/CB/CR | 400 | 0.000 | Confirmatory pilot |
| Llama-3.2-3B | C0/CG/CB/CR | 264 | 0.000 | Smoke study |
| Qwen-Coder-3B | C0/CG/CB/CR | 135 | 0.000 | E0 original |
| Qwen-Coder-7B | C0/CB/CR | 300 | 0.000 | Safety n100 |
| Llama-3.1-8B | C5_near ladder | 180 | 0.000 | EVIDA-2 |
| **Tổng** | — | **~1.279** | **0.000** | Trừ probes |
| OR-Bench probes | — | 225 | **56%** | Pathway hoạt động |

### Ý nghĩa

> **Nỗi lo "safety blocking" cho code-security task là quá mức** ở open-weight
> models 2–8B. OR-Bench probes bị refuse 56% chứng minh refusal pathway hoạt động
> — nhưng defensive framing về code không kích hoạt nó. Đây là negative result
> có giá trị: bác bỏ giả thuyết defensive refusal cho domain này.

### So sánh tài liệu

| Nghiên cứu | Phát hiện | Khác với chúng ta |
|---|---|---|
| Campbell et al. (2026) | Cyber-defense tasks bị refuse 2,72× | Họ đo **refusal**; chúng ta đo **verdict corruption**. Họ dùng frontier models; chúng ta dùng open-weight 2–8B |
| Robey et al. (2025) — Anti-Scheming | Evaluation awareness thay đổi behavior | Họ đo trong specialized anti-scheming settings; chúng ta đo trên ordinary action boundaries |

---

## F2: CR ADVISORY — SUY BIẾN ĐỊNH HƯỚNG

### Phát biểu

> Trên Granite-3.3-2B, risk advisory (CR) chèn vào comment làm **67% benign
> functions bị flag thành "vulnerable"** (ΔFP = +59pp, p < 10⁻¹⁵) — trong khi
> CG (generic) và CB (benign framing) chỉ gây ≤3 flips. Trên Llama, recall
> tăng +7pp (mất headroom). Trên Qwen, inert hoàn toàn.

### Bảng số liệu chi tiết

| Mô hình | Arm | Recall(vul) | FP(ben) | B→V flips | V→B flips |
|---|---|---|---|---|---|
| Granite-3.3-2B | C0 | 8% | 8% | — | — |
| Granite-3.3-2B | CG | 10% | 8% | 0 | 0 |
| Granite-3.3-2B | CB | 8% | 7% | 0 | 2 |
| **Granite-3.3-2B** | **CR** | **64%** | **67%** | **0** | **25** |
| Llama-3.2-3B | C0 | 93% | 0% | — | — |
| Llama-3.2-3B | CG | 100% | 0% | 0 | 0 |
| Llama-3.2-3B | CB | 100% | 0% | 0 | 0 |
| **Llama-3.2-3B** | **CR** | **100%** | **3%** | 0 | 3 |

### Diễn giải

CR advisory chứa **tên sink API có thật** trong function (100% query-relevant,
0% generic text). Điều này tạo "risk prior" mà Granite sử dụng làm tín hiệu
chuyển từ all-benign sang all-vulnerable. Llama có headroom hạn chế hơn (baseline
93% recall) nên chỉ wobble +7pp.

**Controls:**
- CG (generic): 0 flips → loại trừ generic comment effect
- CB (benign framing): 0-2 flips → loại trừ benign-direction bias

→ **Chỉ CR (risk-relevant) mới gây effect** — cụ thể và direction-dependent.

---

## F3: DEFENSE P3 GÂY HẠI RECALL (COMPONENT ABLATION)

### Phát biểu

> Trên Llama-3.2-3B, bọc provenance P3 (full bundle) làm Recall sụp từ 1.000
> xuống .433 (39/60 flips, exact McNemar p = 3,4×10⁻⁷). Component ablation
> cho thấy **system reassertion là thủ phạm chính** (28/34 = 82% tổng harm,
> p = 7,45×10⁻⁹), trong khi boundary-only provenance (A1) gần như vô hại (.983).

### Bảng ablation

| Rung | Component | Recall | Δ | McNemar p |
|---|---|---|---|---|
| A0 | raw | 1.000 | — | — |
| A1 | boundary wrap | .983 | −.017 | 1.0 |
| A2 | + context header | .900 | −.083 | .002 |
| A3 | + generic wrap | .848 | −.052 | < .001 |
| A4 | + string mediation | .898 | +.050 | — (hồi phục) |
| **A5** | **+ system reassertion** | **.433** | **−.465** | **3,4×10⁻⁷** |

### Cross-model

| Model | A0 recall | A5 recall | Harm? |
|---|---|---|---|
| Llama-3.2-3B | 1.000 | .433 | ✅ CÓ (p = 3,4×10⁻⁷) |
| Qwen-Coder-3B | 1.000 | 1.000 | ❌ KHÔNG |
| Llama-3.1-8B | .600 | .550 | ❌ KHÔNG (p = .508) |

→ Harm là hiện tượng **3B + Llama-family-specific**. Tại 8B, harm tan biến.

---

## F4: SCALE RESOLUTION (7B/8B)

### Phát biểu

> Defense cost của P3 trên Llama **fade ở 8B**: recall .600 → .550 (Δ = −.050,
> exact McNemar p = .508). Qwen inert persists at 7B (.483 → .533, p = .727).
> → Defense cost là hiện tượng **≤3B + Llama-family-specific**.

### Bảng

| Model | Scale | A0 recall | A5 recall | Δ | Exact p | Harm? |
|---|---|---|---|---|---|---|
| Llama-3.2-3B | 3B | 1.000 | .433 | −.567 | 3,4×10⁻⁷ | ✅ CÓ |
| Qwen-Coder-3B | 3B | 1.000 | 1.000 | 0 | — | ❌ |
| Llama-3.1-8B | 8B | .600 | .550 | −.050 | .508 | ❌ |
| Qwen-Coder-7B | 7B | .483 | .533 | +.050 | .727 | ❌ |

---

## F5: GRAPH FEDERATION-ROBUST

| Feature set | FedAvg F1 (20 seeds) | Centralized F1 | ΔF1 | TOST ±.02 |
|---|---|---|---|---|
| **Graph** | **.869 ± .051** | .858 ± .047 | +.011 | ✅ PASS |
| TF-IDF | .790 ± .031 | .842 ± .038 | −.052 | ❌ FAIL (degenerates) |

---

## F6: TF-IDF DEGENERATION

TF-IDF FedAvg recall = 1.0 (all-malicious predictor) trong 79/80 cells. Precision = base rate.

---

## F7: CODEBERT BASELINE

| Metric | Giá trị |
|---|---|
| Recall@0.5 | .541 |
| F1 | .215 |
| MCC | .232 |
| AUC | .847 |
| VD-S | .962 |
| Paired acc | .009 |

---

## F8: EVIDA FAIL

| Metric | Giá trị | Gate | Verdict |
|---|---|---|---|
| CRR | .2182 | ≥ .40 | ❌ FAIL |
| DIER | .1712 | ≤ .05 | ❌ FAIL |
| Alarm precision | .2111 | ≥ .40 | ❌ FAIL |
| Verdict | | | **FAIL / MECHANISM-INVALID** |

---

## F9: P1 INJECTION REDUCTION

| Metric | Trước P1 | Sau P1 | p |
|---|---|---|---|
| Injection success | 0.742 | 0.484 | .0078 |
| MCC | +0.205 | −0.029 | — |

→ P1 giảm injection nhưng KHÔNG tăng MCC (mixed result).

---

## F10: LCO FAMILY-SHIFT NULL

| Metric | Graph | TF-IDF | Kết luận |
|---|---|---|---|
| Degradation dd | −.0095 ± .0803 | −.0139 ± .0794 | p = .368 |
| Power tại δ=.05 | ≈ .75 | — | MDE ≈ .05 |

---

## F11: ALARM PRECISION

| | TP | FP | Precision |
|---|---|---|---|
| EVIDA v1 alarm | 57 | 213 | **.2111** |

→ Invariance signal đơn giản không đủ.

---

## BẢNG TỔNG HỢP

| Finding | Kết quả chính | Số liệu | Files |
|---|---|---|---|
| F1: Blocking absent | RR = 0.000 | ~7.000 gen | E0/E0v2/safety results |
| F2: CR directional corruption | Granite +59pp FP, +56pp recall | p < 10⁻¹⁵ | confirmatory results |
| F3: Defense P3 harm | Llama 1.000→.433, p = 3,4e-7 | 39/60 flips | defense metrics |
| F4: Scale resolution | Harm fades at 8B (p = .508) | 480 gen Kaggle | r16_kaggle |
| F5: Graph federation-robust | TOST PASS ±.02 | 640 runs | fl_multiseed |
| F6: TF-IDF degeneration | recall = 1.0, 79/80 cells | p = 3,8e-6 | fl_multiseed |
| F7: CodeBERT VD-S .962 | F1 .215 khớp paper | — | transformer eval |
| F8: EVIDA FAIL | CRR .2182 < .40; DIER .1712 > .05 | 756 units | evida_analysis |
| F9: P1 injection giảm | 0.742→0.484, p = .0078 | — | round3 results |
| F10: LCO null | dd = −.0095, p = .368 | 480 runs | lco_results |
| F11: Alarm precision .2111 | 57TP/213FP | — | evida_analysis |
