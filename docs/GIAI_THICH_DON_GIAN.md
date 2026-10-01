# GIẢI THÍCH KẾT QUẢ NGHIÊN CỨU — ĐƠN GIẢN, DỄ HIỂU

## RefuseGuard + PackGuard — 19 vòng, ~7.000+ lượt sinh, 6 mô hình

---

## TỔNG QUAN

Nghiên cứu trả lời 2 câu hỏi:

1. Nội dung không tin cậy trong code (chú thích, cảnh báo) có làm mô hình AI thay đổi phán định lỗ hổng không?
2. Biện pháp phòng vệ có khôi phục được độ chính xác mà không gây hại không?

Mô hình: 6 mô hình open-weight 2–8 tỷ tham số (Llama-3.2-3B, Granite-3.3-2B, Qwen-Coder-3B, Qwen-Coder-7B, Llama-3.1-8B, CodeBERT). Kho dữ liệu: 603 gói npm/PyPI + 200 benign mở rộng. Tổng ~7.000+ lượt sinh qua 19 vòng.

---

## 1. BLOCKING KHÔNG XẢY RA

**Trước khi nghiên cứu, chúng ta lo rằng:**

> Cứ nhắc đến "malware", "vulnerability", "exploit" thì mô hình sẽ từ chối trả lời kiểu "Tôi không thể hỗ trợ việc này."

**Kết quả: KHÔNG xảy ra.**

| Mô hình | Số mẫu | Refusal rate |
|---|---|---|
| Granite-3.3-2B | 400 | 0% |
| Llama-3.2-3B | 264 | 0% |
| Qwen-Coder-3B | 135 | 0% |
| Qwen-Coder-7B | 300 | 0% |
| Llama-3.1-8B | 180 | 0% |

OR-Bench probes (chứa nội dung độc hại thật) bị từ chối 56% — chứng tỏ refusal pathway hoạt động, nhưng defensive framing về code không kích hoạt nó.

**Ý nghĩa:** Nỗi lo "AI từ chối hỗ trợ bảo mật" là quá mức ở open-weight 2–8B.

---

## 2. CR ADVISORY — COMMENT CẢNH BÁO LÀM MODEL THIÊN KỊ

**Thí nghiệm:** Cho Granite-3.3-2B đọc một hàm code **hoàn toàn lành tính**, nhưng thêm một dòng comment:

> "WARNING: Security scanner flagged potential vulnerability in this function..."

**Kết quả:** Granite flag tới **67% benign functions** thành "vulnerable" (so với 8% khi không có comment).

| Mô hình | C0 FP(ben) | CR FP(ben) | ΔFP |
|---|---|---|---|
| Granite-3.3-2B | 8% | **67%** | **+59pp** |
| Llama-3.2-3B | 0% | 3% | +3pp |

**Quan trọng:** Không phải chú thích chung chung nào cũng gây hiệu ứng:

| Loại comment | FP gây ra |
|---|---|
| Generic ("legacy code") | 0% |
| Benign framing ("verified safe") | 0% |
| **Risk advisory (chứa tên sink API thật)** | **67%** |

→ Chỉ có advisory **chứa tên sink API có thật trong hàm** mới gây hiệu ứng. Advisory chung chung vô hại.

---

## 3. DEFENSE P3 — TỰ GÂY HẠI RECALL

**Ý tưởng ban đầu:** Thêm "quy trình an toàn" nhắc model cẩn thận với untrusted context.

**Kết quả trên Llama-3B:** Recall sụp từ 1.000 → .433 (mất 57% detections).

**Component ablation cho thấy thủ phạm:**

| Bước | Bổ sung | Recall | Ghi chú |
|---|---|---|---|
| A0 | Không defense | 1.000 | Nền |
| A1 | Chỉ bọc chú thích | .983 | Gần vô hại |
| A2 | + Header ngữ cảnh | .900 | Bắt đầu ảnh hưởng |
| A3 | + Bọc chung chung | .848 | — |
| A4 | + Xử lý chuỗi | .898 | Hồi phục chút |
| **A5** | **+ Nhắc lại nhiệm vụ** | **.433** | **SỤP Ở ĐÂY** |

→ **Bước "nhắc lại nhiệm vụ" chiếm 82% tổng hại.** Chỉ bọc chú thích gần như vô hại.

**Nhưng không phải model nào cũng bị:**

| Model | Bị hại? |
|---|---|
| Llama-3.2-3B | ✅ CÓ |
| Qwen-3B | ❌ KHÔNG |
| Llama-8B | ❌ KHÔNG |

---

## 4. P1 GIẢM ATTACK NHƯNG KHÔNG TĂNG ĐỘNG CHÍNH XÁC

**Ý tưởng:** Thêm "semantic isolation" để cô lập nội dung không tin cậy.

**Kết quả:** Injection success giảm từ 74.2% → 48.4% (McNemar p = .0078) — tốt.

**NHƯNG:** MCC (đo độ chính xác tổng) **không tăng** — có xu hướng giảm nhẹ.

| Giống như | Thuốc giảm triệu chứng nhưng không chữa bệnh |
|---|---|

---

## 5. GRAPH FEATURES CHỊU FEDERATED LEARNING

**Ý tưởng:** Train detector phân tán (federated learning) thay vì gom dữ liệu về một chỗ.

**Kết quả:**

| Feature set | FedAvg F1 | Centralized F1 | ΔF1 |
|---|---|---|---|
| **Graph** | .869 ± .051 | .858 ± .047 | +.011 ✅ |
| TF-IDF | .790 ± .031 | .842 ± .038 | **−.052** ❌ |

→ **Graph features chịu FedAvg tốt** (không thua centralized).
→ **TF-IDF degenerates** — dự đoán tất cả malicious trong 79/80 cells.

**Ý nghĩa:** Khi federate code-security classifier, **dùng graph/semantic features, tránh raw token features.**

---

## 6. LCO FAMILY-SHIFT — CHƯA THẤY KHÁC BIỆT

**Ý tưởng:** Kiểm tra graph features có robust hơn TF-IDF khi gặp code từ family mới không (leave-cluster-out).

**Kết quả:** Cả graph và TF-IDF degradation tương đương nhau (dd = −.0095, p = .368). Power ≈ .75 tại δ = .05 — chưa đủ để phân biệt.

→ **Chưa kết luận được.** Cần thêm data.

---

## 7. CODEBERT BASELINE

**Fine-tune CodeBERT trên PrimeVul:**

| Metric | Giá trị | Ghi chú |
|---|---|---|
| Recall@0.5 | 54.1% | Trên test subset |
| F1 | 21.5% | Khớp PrimeVul paper (~20.9%) |
| VD-S | 96.2% | FNR@FPR≤0.5% — chỉ 3.8% vul được detect |
| Paired acc | 0.9% | Gần random trên paired vul/patched |

→ **CodeBERT rất yếu** nhưng đủ làm fallback. Realistic difficulty.

---

## 8. EVIDA — THẤT BẠI CÓ KIỂM ĐỊNH

**Ý tưởng:** So verdict giữa raw và stripped → nếu khác nhau thì nghi corruption → chạy verifier.

**Kết quả: FAIL 3 gates:**

| Metric | Giá trị | Gate | Verdict |
|---|---|---|---|
| CRR | 21.8% | ≥ 40% | ❌ FAIL |
| DIER | 17.1% | ≤ 5% | ❌ FAIL |
| Alarm precision | 21.1% | ≥ 40% | ❌ FAIL |

**Nguyên nhân gốc:** 37/55 corrupted cases có raw == stripped verdict. Tức là:
- Bỏ advisory rồi nhưng model vẫn giữ verdict corrupted
- Disagreement không bắt được corruption
- Maximum possible recovery = 18/55 = .3273

→ **Kiến trúc "detect disagreement → verify" không hoạt động.**

---

## TÓM TẮT TRONG 5 ĐIỀU CẦN NHỚ

1. **LLM không bị block bởi security task.** Nó vẫn trả lời bình thường.

2. **Nhưng security-looking context có thể ám thị verdict.** Benign code bị gọi thành vulnerable rất nhiều (Granite 67%).

3. **Không phải comment nào cũng gây effect.** Generic comment gần như vô hại; risk advisory mới gây bias mạnh.

4. **Defense cũng có thể tự phá model.** Nhắc model quá nhiều về "trusted/untrusted" có thể làm mất recall (Llama recall giảm từ 1.000 xuống 0.433).

5. **Cách so sánh raw vs stripped không đủ để phát hiện corruption.** Vì comment bình thường cũng có thể ảnh hưởng prediction.
