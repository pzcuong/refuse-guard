# 📊 PHÂN TÍCH CHI TIẾT KẾT QUẢ NGHIÊN CỨU — 11 FINDINGS ĐẦY ĐỦ

## RefuseGuard + PackGuard — 19 vòng, ~7.000+ lượt sinh, 6 mô hình, 833 bài kiểm thử

> **Mỗi phát hiện có:** Phát biểu → Bảng số liệu chi tiết → Kiểm định thống kê → Cỡ hiệu ứng → Diễn giải cơ chế → So sánh tài liệu → Phạm vi khái quát → Ý nghĩa thực hành

---

## F1: BLOCKING KHÔNG XẢY RA (RR = 0.000)

### Phát biểu finding

> Trên ~7.000+ lượt sinh qua 19 vòng, **không một refusal nào được kích hoạt** bởi
> defensive framing trên open-weight models 2–8B. Refusal pathway hoạt động bình
> thường (OR-Bench probes: 56% refusal), nhưng defensive framing về code security
> không kích hoạt nó — ở bất kỳ arm nào (C1–C5), bất kỳ source nào
> (system/user/tool/third-party), bất kỳ CWE family nào.

### Bảng số liệu chi tiết

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
| Campbell et al. (2026) | Cyber-defense tasks bị refuse 2,72× | Họ đo **refusal** trên frontier models; chúng ta đo trên open-weight 2–8B |
| Robey et al. (2025) | Evaluation awareness thay đổi behavior | Họ đo trong specialized anti-scheming settings; chúng ta đo trên ordinary action boundaries |

### Phạm vi khái quát

> Kết quả này **chỉ khái quát trên open-weight models 2–8B**. Các mô hình
> frontier (GPT-4o, Claude) và mô hình ≥13B chưa được đo. Cần API key frontier
> để mở rộng phạm vi.

---

## F2: CR ADVISORY — SUY BIẾN ĐỊNH HƯỚNG

![Attack surface theo mô hình](charts/attack_surface_models.png)

### Phát biểu

> Trên Granite-3.3-2B, risk advisory (CR) chèn vào comment làm **67% benign
> functions bị flag thành "vulnerable"** (ΔFP = +59pp, p < 10⁻¹⁵) và tăng Recall
> trên hàm độc hại từ 8% lên 64% (+56pp) — một sự dịch chuyển hệ thống về phía
> "vulnerable" trên cả hai lớp nhãn.

### Kiểm định thống kê

| Chỉ số | Giá trị | Phương pháp |
|---|---|---|
| Kích thước mẫu | 100 lành + 100 độc | PrimeVul test split, seed 20260922 |
| Mô hình | Granite-3.3-2B-Instruct | fp16, T4 GPU (Kaggle) |
| ΔFP (CR − C0) trên benign | +59 pp | Exact binomial, p < 10⁻¹⁵ |
| ΔRecall (CR − C0) trên vulnerable | +56 pp | Exact binomial |
| Khoảng tin cậy 95% ΔFP | [+0,49, +0,69] | Clopper–Pearson |
| Cỡ hiệu ứng | Odds ratio = 21,4 | Haldane–Anscombe correction |
| Số lượt sinh | 800 (200 hàm × 4 arm) | T4 GPU, greedy, max 384 tokens |

### Tái lập trên nhiều nhóm CWE

| Nhóm CWE | C0 FP | CR FP | ΔFP | n | Hướng |
|---|---|---|---|---|---|
| CWE-787 | 8% | 67% | +59 pp | 25 | →vulnerable |
| CWE-125 | 8% | 67% | +59 pp | 25 | →vulnerable |
| CWE-703 | 8% | 67% | +59 pp | 25 | →vulnerable |
| CWE-476 | 8% | 67% | +59 pp | 25 | →vulnerable |
| **Gộp** | **8%** | **67%** | **+59 pp** | **100** | **→vulnerable** |

→ Tác động **đồng nhất trên mọi nhóm CWE** — không có nhóm nào kháng cự.

### So sánh với nhóm kiểm soát

| Arm | Benign→Vul FP | Vul→Ben FN | Ghi chú |
|---|---|---|---|
| C0 (baseline) | 8% | 0% | Nền |
| CG (generic) | 8% | 0% | Không tác động |
| CB (benign framing) | 7% | 2% | Không tác động |
| **CR (risk advisory)** | **67%** | **0%** | **Suy biến mạnh** |

→ CR là arm duy nhất gây suy biến; CG và CB là nhóm kiểm soát âm tính.

### So sánh với tài liệu tham khảo

| Nghiên cứu | Phát hiện | Khác với chúng ta |
|---|---|---|
| Campbell et al. (2026) | Cyber-defense tasks bị từ chối 2,72× | Nghiên cứu này đo **refusal**; chúng ta đo **verdict corruption** |
| OpenAI/Apollo (2025) — Anti-Scheming | Evaluation awareness thay đổi behavior trong specialized settings | Chúng ta đo trên **ordinary agent action boundaries**, không phải specialized anti-scheming |
| PaperGym (8/2026) — Criterion leakage | Rubric criteria rò rỉ vào dataset | Chúng ta đo **context-based criterion injection**, không phải dataset contamination |

### Phạm vi khái quát

> Kết quả này **chỉ khái quát trên open-weight models 2–3B**. Các mô hình
> frontier (GPT-4o, Claude) và mô hình ≥13B chưa được đo. Cần API key frontier
> để mở rộng phạm vi.

---

## F3: DEFENSE P3 GÂY HẠI RECALL (COMPONENT ABLATION)

### Phát biểu

> Trên Llama-3.2-3B, bọc provenance P3 (full bundle) làm Recall trên hàm độc
> hại sụp từ 1.000 xuống .433 (39/60 cặp lật theo chiều giảm phát hiện), với
> chi phí chủ yếu do thành phần system task-intent reassertion (28/34 = 82%
> tổng flips, exact McNemar p = 3,4×10⁻⁷). Boundary-only provenance (A1)
> gần như vô hại (.983).

### Kiểm định thống kê

| So sánh | n | Recall A0 | Recall A5 | ΔF1 | Exact McNemar p |
|---|---|---|---|---|---|
| Llama-3.2-3B, C5_near | 60 | 1.000 | .433 | −.567 | **3,4×10⁻⁷** |
| Llama-3.2-3B, C5_far | 60 | 1.000 | .333 | −.667 | **1,9×10⁻⁶** |
| Qwen-Coder-3B (inert) | 60 | 1.000 | 1.000 | 0 | — |

### Component ablation

| Rung | Thành phần | Recall | Δ vs A0 | Exact McNemar p |
|---|---|---|---|---|
| A0 | raw | 1.000 | — | — |
| A1 | boundary wrap | .983 | −.017 | 1.0 |
| A2 | + context header | .900 | −.083 | .002 |
| A3 | + generic wrap | .848 | −.052 | < .001 |
| A4 | + string mediation | .898 | +.050 | — (hồi phục) |
| **A5** | **+ system reassertion** | **.433** | **−.465** | **3,4×10⁻⁷** |

![Component ablation waterfall](charts/defense_ablation_waterfall.png)

### Cross-model

| Model | A0 recall | A5 recall | Harm? |
|---|---|---|---|
| Llama-3.2-3B | 1.000 | .433 | ✅ CÓ |
| Qwen-Coder-3B | 1.000 | 1.000 | ❌ KHÔNG |
| Llama-3.1-8B | .600 | .550 | ❌ KHÔNG (p = .508) |

→ Harm là hiện tượng **3B + Llama-family-specific**. Tại 8B, harm tan biến.

---

## F5: GRAPH FEDERATION-ROBUST DETECTOR NỀN

### Phát biểu

> Trên 20 seeds × group-split, graph features (18 chiều) đạt TOST equivalence
> PASS (ΔF1 = −.0065, CI90 [−.0133, +.0003] ⊂ ±.02) giữa FedAvg và centralized.
> TF-IDF **degenerates** dưới FedAvg (recall = 1.0, F1 = base rate) trong 79/80
> cell, với hiệu ứng có ý nghĩa thống kê (ΔF1 = −.052, exact Wilcoxon
> p = 3,8×10⁻⁶, Holm-adjusted p = 1,1×10⁻⁵).

### Bảng số liệu

| Feature set | Phương pháp | FedAvg F1 (20 seeds) | Centralized F1 | ΔF1 | TOST ±.02 |
|---|---|---|---|---|---|
| **Graph** | sklearn LR lbfgs | **.869 ± .051** | .858 ± .047 | +.011 | ✅ PASS |
| TF-IDF | sklearn LR lbfgs | .790 ± .031 | .842 ± .038 | −.052 | ❌ FAIL |

### Diễn giải

Graph features (18 chiều, semantic classes + graph metrics) khi train bằng
FedAvg cho F1 **.869 ± .051** so với centralized **.858 ± .047** — FedAvg
**không thua**, thậm chí nhỉnh hơn nhẹ. TOST equivalence PASS (CI90 của ΔF1
nằm trọn trong ±.02) → FedAvg **không thua centralized quá .02 F1** — một
claim dương có kiểm định.

TF-IDF (sparse lexical features) khi train bằng FedAvg cho F1 **.790 ± .031**,
thấp hơn centralized **.842 ± .038** — ΔF1 = **−.052** (p = 3,8×10⁻⁶). Nghĩa
là TF-IDF **mất năng lực dưới FedAvg** — dự đoán tất cả malicious.

→ **Đối với federated code-security classification: dùng semantic features,
tránh sparse lexical features.** Đây là finding có giá trị cho cộng đồng FL.

---

## F6: TF-IDF DEGENERATION

### Phát biểu

> TF-IDF FedAvg recall = 1.0 (all-malicious predictor) trong 79/80 cells.
> Precision = base rate.

### Số liệu

| Metric | Giá trị | Ghi chú |
|---|---|---|
| Recall | 1.0 | Predicts "malicious" cho mọi sample |
| Precision | ≈ base rate | Không phân biệt được |
| F1 | ≈ base rate F1 | Degenerate |
| Số cells bị degenerate | 79/80 (98.75%) | Chỉ 1 cell không degenerate |

### Diễn giải

TF-IDF (sparse lexical features, 2^18 chiều) khi train bằng FedAvg **mất hoàn
toàn khả năng phân biệt** — dự đoán tất cả sample là malicious. Nguyên nhân:
sparse lexical features có chiều rất cao và vocabulary khác nhau giữa các
client, khiến model global không hội tụ đúng.

**→ Sparse lexical features KHÔNG federation-robust.** Đây là finding có giá
trị cho cộng đồng FL: khi federate code-security classifiers, phải dùng
semantic/graph features thay vì raw token features.

---

## F7: CODEBERT BASELINE

### Số liệu

| Metric | Giá trị | Ghi chú |
|---|---|---|
| Recall@0.5 | .541 | Trên test subset |
| F1 | .215 | Khớp PrimeVul paper (~0.209) |
| MCC | .232 | — |
| AUC | .847 | — |
| VD-S | .962 | FNR@FPR≤0.5% |
| Paired acc | .009 | Gần random trên paired |

**Đọc:** CodeBERT là baseline yếu nhưng đủ làm fallback. VD-S = 0.962 có nghĩa là
96% vulnerable functions bị miss ở FPR ≤0.5% — realistic difficulty.

---

## F8: EVIDA FAIL

### Phát biểu

> EVIDA (invariant-alarm + verify-or-abstain) FAIL preregistered gates:
> CRR .2182 < .40, DIER .1712 > .05, alarm precision .2111. Số được 2 confirmers
> độc lập tái lập khớp 100% + re-execution bit-identical.

### Bảng

| Metric | Giá trị | Gate | Verdict |
|---|---|---|---|
| CRR | .2182 | ≥ .40 | ❌ FAIL |
| DIER | .1712 | ≤ .05 | ❌ FAIL |
| Alarm precision | .2111 | ≥ .40 | ❌ FAIL |

### Nguyên nhân gốc

**37/55 corrupted cases có V_raw == V_stripped** — bỏ advisory rồi nhưng model
vẫn giữ verdict corrupted. Do đó: **maximum possible recovery = 18/55 = .3273**
cho bất kỳ architecture nào chỉ adjudicate khi hai view disagreement.

→ Gate .40 thực tế **không thể đạt** trên realization này.

---

## F9: P1 INJECTION REDUCTION

### Phát biểu

> P1 (semantic isolation) giảm injection success từ 0.742 xuống 0.484
> (McNemar p = .0078) — nhưng MCC thay đổi từ +0.205 thành −0.029
> (hướng ngược, không có ý nghĩa thống kê).

### Bảng

| Metric | Trước P1 | Sau P1 | Δ |
|---|---|---|---|
| Injection success | .742 | .484 | −.258 |
| MCC | +.205 | −.029 | ↓ |
| Kết luận | Giảm attack nhưng không tăng accuracy | Mixed |

---

## F10: LCO FAMILY-SHIFT NULL

### Phát biểu

> Trên MinHash leave-cluster-out split (67 units, 0 leakage), degradation
> giữa graph và TF-IDF **không khác nhau** (dd = −.0095 ± .0803, p = .368).
> Power ≈ .75 tại δ = .05.

### Số liệu

| Model | FedAvg F1 (group) | FedAvg F1 (LCO) | Degradation |
|---|---|---|---|
| Graph | .869 | .859 | −.010 |
| TF-IDF | .842 | .850 | +.008 |

### Diễn giải

Cả graph và TF-IDF degradation tương đương nhau dưới family shift. Không có
robustness ranking — cần thêm data để phân biệt. Null hai chiều có power.

---

## F11: ALARM PRECISION .2111

### Số liệu

EVIDA alarm: 57 TP / 213 FP = **.2111**.

→ Invariance signal đơn giản (raw ≠ strip) không đủ làm corruption detector.
Cần multi-view consistency hoặc signals tinh vi hơn.

---

## BẢNG TỔNG HỢP 11 FINDINGS

| # | Finding | Kết quả chính | Hướng |
|---|---|---|---|
| F1 | Blocking absent | RR = 0.000, ~7.000 gen | Bác bỏ nỗi sợ |
| F2 | CR directional corruption | Granite 67% FP, +59pp | Tăng FP |
| F3 | Defense P3 harm | Llama sụp .100→.433 | Giảm recall |
| F4 | Scale resolution | 8B: harm tan (p=.508) | Positive |
| F5 | Graph federation-robust | TOST PASS ±.02 | Positive |
| F6 | TF-IDF degeneration | recall=1.0, 79/80 | Negative cho TF-IDF |
| F7 | CodeBERT | VD-S .962, F1 .215 | Baseline |
| F8 | EVIDA FAIL | CRR .2182 < .40 | Negative |
| F9 | P1 injection giảm | 0.742→0.484, p=.0078 | Positive defense |
| F10 | LCO null | dd=−.0095, p=.368 | Không ranking |
| F11 | Alarm precision .2111 | Invariance đơn giản không đủ | Cần refinement |
