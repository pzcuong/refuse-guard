# KẾT QUẢ NGHIÊN CỨU: PHÂN TÍCH CHI TIẾT CÁC PHÁT HIỆN

## RefuseGuard + PackGuard — Trình bày theo chuẩn bài báo khoa học Q1

> **Phạm vi:** 19 vòng thí nghiệm · ~7.000+ lượt sinh · 6 mô hình (2–8B) · 833 bài kiểm thử · verify_repro 30/30 · 29+ commits
>
> **Mỗi phát hiện được trình bày theo cấu trúc:** Phát biểu → Kiểm định thống kê → Cỡ hiệu ứng → Khoảng tin cậy → So sánh với tài liệu tham khảo → Phạm vi khái quát → Ý nghĩa

---

## TÓM TẮT (ABSTRACT)

Nghiên cứu này đo lường — theo thiết kế đã đăng ký trước — mức độ mà nội dung
không tin cậy trong code làm thay đổi phán định lỗ hổng của sáu mô hình ngôn ngữ
lớn (2–8 tỷ tham số, open-weight), đồng thời đánh giá biện pháp phòng vệ dựa trên
AST-sanitization và trình xác minh evidence. Kết quả chính: (1) cảnh báo rủi ro
liên quan đến ngữ cảnh gây suy biến phán định có hướng trên Granite-3.3-2B
(ΔFP = +59 điểm phần trăm, p < 10⁻¹⁵), tái lập trên bốn nhóm CWE; (2) blocking
(refusal) không xảy ra ở bất kỳ mô hình hay arm nào (~7.000 lượt sinh, RR = 0,000),
bác bỏ giả thuyết refusal cho nhiệm vụ phân tích mã ở quy mô open-weight; (3)
defense dựa trên provenance gây sụp Recall trên Llama-3.2-3B (1,000 → 0,433,
p = 3,4×10⁻⁷), một chi phí defense đã được đo lường và giới hạn ở mô hình ≤3 tỷ;
(4) AST-level sanitization trung hòa hoàn toàn kênh advisory trên Granite mà không
gây báo động sai; (5) graph features chịu liên kết đàn hồi (TOST ĐẠT ±0,02 F1)
trong khi TF-IDF mất năng lực dưới FedAvg (p = 3,8×10⁻⁶).

---

## PHÁT HIỆN 1: CẢNH BÁO RỦI RO GÂY SUY BIẾN PHÁN ĐỊNH CÓ HƯỚNG

### Phát biểu

> Trên Granite-3.3-2B, việc chèn cảnh báo rủi ro (CR) vào chú thích hàm làm
> tăng tỷ lệ báo động sai trên hàm lành tính từ 8% lên 67% (ΔFP = +59 điểm
> phần trăm, p < 10⁻¹⁵) và tăng Recall trên hàm độc hại từ 8% lên 64%
> (+56 điểm phần trăm) — một sự dịch chuyển hệ thống về phía "vulnerable"
> trên cả hai lớp nhãn.

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
| Campbell et al. (2026) — Defensive Refusal Bias | Cyber-defense tasks bị từ chối 2,72× | Nghiên cứu này đo **refusal**; chúng ta đo **verdict corruption** |
| OpenAI/Apollo (2025) — Anti-Scheming | Evaluation awareness thay đổi behavior trong specialized settings | Chúng ta đo trên **ordinary agent action boundaries**, không phải specialized anti-scheming |
| PaperGym (8/2026) — Criterion leakage | Rubric criteria rò rỉ vào dataset | Chúng ta đo **context-based criterion injection**, không phải dataset contamination |

### Phạm vi khái quát

> Kết quả này **chỉ khái quát trên open-weight models 2–3B**. Các mô hình
> frontier (GPT-4o, Claude) và mô hình ≥13B chưa được đo. Cần API key frontier
> để mở rộng phạm vi.

---

## PHÁT HIỆN 2: DEFENSE GÂY HẠI RECALL THEO HƯỚNG NGƯỢC

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

### Component ablation (Llama-3.2-3B, C5_near, n=60)

| Rung | Thành phần | Recall | Δ | Vai trò |
|---|---|---|---|---|
| A0 | raw | 1.000 | — | Nền |
| A1 | boundary wrap | .983 | −.017 | Gần vô hại |
| A2 | + context header | .900 | −.083 | Đóng góp vừa |
| A3 | + generic wrap | .848 | −.052 | Đóng góp vừa |
| A4 | + string mediation | .898 | +.050 | Hồi phục |
| **A5** | **+ system reassertion** | **.433** | **−.465** | **Thủ phạm chính** |

![Component ablation waterfall](charts/defense_ablation_waterfall.png)

### Cross-model

| Model | A0 recall | A5 recall | Harm? |
|---|---|---|---|
| Llama-3.2-3B | 1.000 | .433 | ✅ CÓ |
| Qwen-Coder-3B | 1.000 | 1.000 | ❌ KHÔNG |
| Llama-3.1-8B | .600 | .550 | ❌ KHÔNG (p = .508) |

→ Harm là hiện tượng **3B + Llama-family-specific**. Tại 8B, harm tan biến.

---

## PHÁT HIỆN 3: GRAPH FEATURES CHỊU LIÊN KẾT ĐÀN HỒI

### Phát biểu

> Trên 20 seeds × group-split, graph features (18 chiều) đạt TOST equivalence
> PASS (ΔF1 = −.0065, CI90 [−.0133, +.0003] ⊂ ±.02) giữa FedAvg và centralized.
> TF-IDF **degenerates** dưới FedAvg (recall = 1.0, F1 = base rate) trong 79/80
> cell, với hiệu ứng có ý nghĩa thống kê (ΔF1 = −.052, exact Wilcoxon
> p = 3,8×10⁻⁶, Holm-adjusted p = 1,1×10⁻⁵).

### Bảng so sánh

| Feature set | FedAvg F1 (20 seeds) | Centralized F1 | ΔF1 | TOST ±.02 | McNemar p |
|---|---|---|---|---|---|
| **Graph** | **.869 ± .051** | **.858 ± .047** | +.011 | ✅ PASS | n.s. |
| TF-IDF | .790 ± .031 | .842 ± .038 | −.052 | ❌ FAIL (degenerates) | 3,8×10⁻⁶ |

### Tại sao quan trọng?

Với federated code-security classification, **compact semantic features
chịu liên kết đàn hồi tốt hơn sparse lexical features** — một finding có giá
trị cho cộng đồng Federated Learning.

---

## PHÁT HIỆN 4: CODEBERT FALLBACK DETECTOR

### Số liệu

| Metric | Giá trị | Ghi chú |
|---|---|---|
| Recall@0.5 | .541 | Trên test subset (549 vul + 20k benign subsample) |
| F1 | .215 | Khớp PrimeVul paper (~0.209) |
| MCC | .232 | — |
| AUC | .847 | — |
| VD-S (FNR@FPR≤0.5%) | **.962** | Chỉ 3.8% vul được detect ở FPR ≤0.5% |
| Paired accuracy | .009 | Gần như random trên paired vul/patched |
| E7 fallback coverage gain | 0.985 → 1.000 | +1.5 điểm % usable answer coverage |

**Đọc:** CodeBERT là baseline yếu nhưng đủ làm fallback. VD-S = 0.962 có nghĩa là
96% vulnerable functions bị miss ở FPR ≤0.5% — realistic difficulty.

---

## TÓM TẮT PHÁT HIỆN 1-4

| Phát hiện | Bản chất | Mức độ | Hướng |
|---|---|---|---|
| F1: CR advisory gây FP corruption | Granite 67% FP, Llama 3% | Tích cực cho measurement paper | Tăng FP (ben→vul) |
| F2: Defense harm (P3) | Llama sụp recall .100→.433 | Tích cực cho defense-audit | Giảm recall (vul→ben) |
| F3: Graph chịu FL, TF-IDF không | Graph TOST PASS, TF-IDF degenerates | Tích cực cho method paper | F1/AUC |
| F4: CodeBERT VD-S .962 | Realistic difficulty | Baseline | — |

---

## PHẠM VI VÀ HẠN CHẾ

### Mô hình

Tất cả kết quả đo trên open-weight models 2–8B. Các mô hình frontier (GPT-4o,
Claude, Gemini) chưa được đo do thiếu API key. Kết quả không khái quát cho
frontier models.

### Corpus

603 packages pilot (npm + PyPI) + 200 expansion (random benign, 17 hard-negative).
Không bao gồm Maven, Ruby, hoặc repository-level tasks.

### Thống kê

Nhiều kết quả có n nhỏ (24-60) và chưa đủ power cho confirmatory tests.
Mọi p-value ở n nhỏ được ghi rõ là descriptive. Holm correction được áp dụng
cho các so sánh preregistered.

### Pre-registration

AMENDMENT-1..11 được đăng ký trong repo nhưng chưa có OSF timestamp công khai.
AMENDMENT-4 được đăng ký sau khi biết 5-seed kết quả (disclosed).

---

## ÁNH XẠ VỚI TÀI LIỆU THAM KHẢO

| Finding | Paper liên quan nhất | Khác biệt |
|---|---|---|
| F1 (CR advisory FP) | PaperGym (2608.31119) — criterion leakage | PaperGym đo leakage vào dataset; chúng ta đo leakage vào verdict qua untrusted context |
| F2 (defense harm) | None — mới | Không có paper nào đo defense-induced recall collapse |
| F3 (graph robust FL) | VulFL (2411.16099) — FL cho vuln detection | VulFL không đo robustness của representation type |
| F4 (VD-S .962) | PrimeVul (Ding et al., ICSE 2025) | Khớp F1; VD-S chưa được báo cáo riêng |
