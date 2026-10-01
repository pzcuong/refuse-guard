# GIẢI THÍCH KẾT QUẢ NGHIÊN CỨU

## RefuseGuard + PackGuard — 19 vòng, ~7.000+ lượt sinh, 6 mô hình

---

## TỔNG QUAN

Nghiên cứu này trả lời hai câu hỏi:

1. Nội dung không tin cậy trong code (chú thích, cảnh báo) có làm mô hình LLM thay đổi phán định lỗ hổng không?
2. Biện pháp phòng vệ có khôi phục được độ chính xác mà không gây hại không?

Mô hình: 6 mô hình open-weight 2–8B (Llama-3.2-3B, Granite-3.3-2B, Qwen-Coder-3B, Qwen-Coder-7B, Llama-3.1-8B, CodeBERT). Kho dữ liệu: 603 gói npm/PyPI + PrimeVul test_paired. Tổng ~7.000+ lượt sinh qua 19 vòng.

---

## 1. BLOCKING KHÔNG XẢY RA

**Trước khi nghiên cứu, chúng ta lo rằng:**

> Cứ nhắc đến "malware", "vulnerability", "exploit" thì mô hình sẽ từ chối trả lời.

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

## 2. CR ADVISORY GÂY SUY BIẾN PHÁN ĐỊNH CÓ HƯỚNG

### Điều gì xảy ra

Granite ban đầu chỉ flag 8% hàm lành tính là vulnerable. Sau khi thêm CR advisory (chứa tên sink API thật của hàm), Granite flag tới 67%. Nghĩa là model tin lời comment quá mức.

### Số liệu

| Mô hình | C0 recall | CR recall | C0 FP | CR FP | ΔFP |
|---|---|---|---|---|---|
| Granite-3.3-2B | 8% | 64% | 8% | **67%** | **+59pp** |
| Llama-3.2-3B | 93% | 100% | 0% | 3% | +3pp |

### Tại sao CR mạnh mà CG không?

CR chứa **tên sink API có thật** trong hàm (100% query-relevant). CG chỉ là generic text. Nên CR tạo risk prior, CG không.

### Ý nghĩa

Model không từ chối làm việc, nhưng nó **tin lời comment quá mức**. Điều này quan trọng vì attacker chỉ cần viết:

> "WARNING: potential vulnerability detected..."

thay vì viết "ignore previous instructions".

---

## 3. DEFENSE P3 GÂY HẠI RECALL

### Điều gì xảy ra

Chúng ta nghĩ thêm wrapper nhắc model "cẩn thận với untrusted context" sẽ giúp. Nhưng trên Llama-3B:

```
Không defense:  recall 1.000
Thêm defense:   recall 0.433
```

Model bỏ sót nhiều hơn. Nguyên nhân: bước "nhắc lại nhiệm vụ" trong system prompt chiếm 82% tổng harm.

### Số liệu ablation

| Bậc | Thêm gì | Recall |
|---|---|---|
| A0 | raw | 1.000 |
| A1 | boundary wrap | .983 |
| A2 | + context header | .900 |
| A3 | + generic wrap | .848 |
| A4 | + string mediation | .898 |
| **A5** | **+ reassertion** | **.433** |

### Không phải model nào cũng bị

| Model | A0 recall | A5 recall | Harm? |
|---|---|---|---|
| Llama-3.2-3B | 1.000 | .433 | ✅ |
| Qwen-3B | 1.000 | 1.000 | ❌ |
| Llama-3.1-8B | .600 | .550 | ❌ (p=.508) |

---

## 4. TÓM TẮT 5 ĐIỀU CẦN NHỚ

1. **LLM không bị block bởi security task.** Nó vẫn trả lời bình thường.
2. **Nhưng security-looking context có thể ám thị verdict.** Benign code bị gọi là vulnerable rất nhiều.
3. **Không phải comment nào cũng gây effect.** Generic comment vô hại; risk advisory mới gây bias.
4. **Defense cũng có thể tự phá model.** Nhắc model quá nhiều về "trusted/untrusted" làm mất recall.
5. **Cách so sánh raw vs stripped không đủ để phát hiện corruption.** Comment bình thường cũng ảnh hưởng prediction.

---

## 5. CÒN F5/F6/F10 LÀ CÂU CHUYỆN KHÁC

Đây là nhánh federated learning:

- F5: graph features train bằng FedAvg vẫn tốt gần centralized → positive
- F6: TF-IDF train bằng FedAvg bị collapse → gần như predict tất cả là malicious
- F10: leave-cluster-out chưa thấy graph thắng TF-IDF rõ

Nếu chỉ quan tâm RefuseGuard + PackGuard, có thể tạm bỏ F5/F6/F10.

---

## CÂU CHUYỆN CHÍNH TRONG 1 CÂU

> Mô hình không từ chối phân tích bảo mật, nhưng nó dễ bị ám thị bởi comment cảnh báo trong code — và chính quy trình bảo vệ đôi khi làm nó bỏ sót bệnh nhiều hơn.
