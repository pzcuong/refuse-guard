# 📊 GIẢI THÍCH KẾT QUẢ NGHIÊN CỨU — ĐƠN GIẢN, DỄ HIỂU

## RefuseGuard + PackGuard — 19 vòng nghiên cứu

> Tài liệu này giải thích kết quả nghiên cứu bằng ngôn ngữ đơn giản, kèm ví dụ thực tế.
> Ai cũng đọc hiểu được, kể cả người không làm AI.

---

## Ý TƯỞNG CHÍNH: SO SÁNH VỚI BÁC SĨ ĐỌC HỒ SƠ

Hãy tưởng tượng:

- **LLM (mô hình AI)** = bác sĩ
- **Code** = bệnh nhân
- **Comment trong code** = lời ghi chú bên cạnh hồ sơ bệnh án
- **Defense (biện pháp bảo vệ)** = quy trình khám bệnh an toàn

Câu hỏi nghiên cứu: **Khi bác sĩ đọc hồ sơ có kèm ghi chú "bệnh nhân có thể ung thư", bác sĩ có chẩn đoán khác đi không?**

---

## PHÁT HIỆN 1: BÁC SĨ KHÔNG TỪ CHỐI KHÁM

### Trước khi nghiên cứu, chúng ta lo rằng:

> "Cứ nhắc đến từ 'virus', 'tấn công', 'exploit' là mô hình AI sẽ từ chối trả lời,
> kiểu 'Tôi không thể hỗ trợ việc này'."

### Kết quả thực tế:

**KHÔNG XẢY RA.** Qua ~7.000 lượt hỏi trên 6 mô hình khác nhau (Llama, Granite, Qwen...),
không một lần nào mô hình từ chối trả lời. Chúng vẫn phân tích code bình thường.

| Giống như | Bác sĩ không từ chối khám bệnh nhân có ghi chú "nghi nhiễm trùng" |
|---|---|
| **Lý do** | Mô hình open-weight 2–8B không có safety filter chặn nhiệm vụ security |
| **Ý nghĩa** | Nỗi lo "AI từ chối hỗ trợ bảo mật" là quá mức ở mô hình nhỏ |

---

## PHÁT HIỆN 2: NHƯNG BÁC SĨ BỊ "GHI CHÚ" ẢM HƯỞNG

### Ví dụ cụ thể:

Cho Granite đọc một hàm code **hoàn toàn lành tính** (không có lỗi bảo mật):

```
Chỉ có code, không ghi chú gì:
→ Granite nói: "Benign" (chỉ 8% chance nói vulnerable)

Thêm một dòng comment:
→ "WARNING: Security scanner flagged potential vulnerability..."
→ Granite nói: "Vulnerable!" (67% chance!)
```

**67% benign functions bị flag sai** — chỉ vì thêm một dòng comment cảnh báo!

| Giống như | Bác sĩ đọc hồ sơ có ghi chú "nghi ung thư" → dễ kết luận ung thư hơn, dù xét nghiệm không đổi |
|---|---|

**Quan trọng:** Không phải chú thích chung chung nào cũng gây hiệu ứng. Chỉ có:
- ✅ Chú thích chứa **tên API nguy hiểm có thật trong code** ("strcpy", "system"...)
- ❌ Chú thích chung chung ("legacy code") → KHÔNG gây hiệu ứng

---

## PHÁT HIỆN 3: DEFENSE TỰ GÂY HẠI

Chúng ta thử thêm "quy trình an toàn" vào trước khi mô hình đọc code:

```
Không defense:     Model đọc code → phát hiện 100% lỗi
Thêm defense:      Model đọc code → chỉ phát hiện 43% lỗi
```

**Defense làm model TỆ hơn!** Trước defense: phát hiện 60/100 lỗi. Sau defense: chỉ còn 43/100.

| Giống như | Bác sĩ được yêu cầu "thực hiện quy trình an toàn nghiêm ngặt" → lại bỏ sót bệnh |
|---|---|

**Nhưng không phải model nào cũng bị:**

| Model | Bị defense gây hại? |
|---|---|
| Llama-3.2-3B | ✅ CÓ (rõ rệt) |
| Qwen-3B | ❌ KHÔNG |
| Llama-8B | ❌ KHÔNG (chưa rõ) |

---

## PHÁT HIỆN 4: THÀNH PHẦN NÀO GÂY HẠI?

Defense có 5 bước. Mỗi bước gỡ ra thử:

| Bước | Làm gì | Recall sau bước này |
|---|---|---|
| A0 | Không defense | 100% |
| A1 | Chỉ bọc chú thích | 98% (gần như vô hại) |
| A2 | + Thêm header | 90% (bắt đầu ảnh hưởng) |
| A3 | + Bọc thêm lớp ngoài | 85% |
| A4 | + Xử lý chuỗi | 90% (hồi phục chút) |
| **A5** | **+ Nhắc lại nhiệm vụ** | **43%** ← SỤP Ở ĐÂY |

**Thủ phạm: Bước "nhắc lại nhiệm vụ" chiếm 82% tổng hại.**

| Giống như | Nhắc bác sĩ "nhớ chỉ phân tích code thực" → bác sĩ lại phân vân, bỏ sót bệnh |
|---|---|

---

## 5 THỨ CẦN NHỚ TỪ NGHIÊN CỨU NÀY

### 1. AI KHÔNG TỪ CHỐI KHÁM

Mô hình 2–8B open-weight không từ chối nhiệm vụ security. Nỗi lo "AI từ chối" là quá mức.

### 2. NHƯNG COMMENT CẢNH BÁO LÀM MODEL THIÊN KỊ

Chỉ cần thêm dòng comment "WARNING: potential vulnerability..." là 67% benign code bị gọi là vulnerable (trên Granite).

### 3. DEFENSE PHỨC TẠP CÓ THỂ TỰ GÂY HẠI

Quy trình an toàn nhiều bước khiến model bỏ sót bệnh — đặc biệt trên Llama-3B. Chỉ nên dùng bước đơn giản nhất (bọc chú thích).

### 4. KHÔNG PHẢI MODEL NÀO CŨNG BỊ

Qwen không bị ảnh hưởng bởi defense. Llama bị. → **Lựa chọn model quan trọng.**

### 5. NHẮC LẠI NHIỆM VỤ LÀ THỦ PHẠM CHÍNH

Bước "nhắc lại nhiệm vụ" chiếm 82% tổng hại. Đây là phát hiện bất ngờ nhất.

---

## SO SÁNH VỚI CÔNG TRÌNH KHÁC

| Nghiên cứu | Họ tìm thấy | Chúng ta tìm thấy |
|---|---|---|
| Campbell (2026) | Security tasks bị từ chối 2,72× | **KHÔNG thấy** ở open 2–8B |
| OpenAI/Apollo (2025) | Evaluation awareness thay đổi behavior | **XÁC NHẬN** — comment cảnh báo thay đổi verdict |
| StruQ/CaMeL | Trusted/untrusted separation | **P3 defense gây hại** — cần audit kỹ hơn |
| PrimeVul (ICSE 2025) | F1 ~0.21 cho CodeBERT | **KHỚP** — F1 0.215 của chúng ta |

---

## DỮ LIỆU THÍ NGHIỆM

| Thí nghiệm | Mô hình | Số mẫu | Kết quả chính |
|---|---|---|---|
| Smoke study | Llama-3B + Granite-2B | 66 | CR gây 25 FP trên Granite |
| Confirmatory | Granite-3.3-2B | 200 | 67% FP, +59pp, p < 10⁻¹⁵ |
| Defense ablation | Llama-3.2-3B | 60 | A5 sụp .433, reassertion = thủ phạm |
| Scale resolution | Llama-3.1-8B + Qwen-7B | 240 | Harm fades at 8B |
| Safety n100 | Llama-3B + Granite-2B | 200 | FP bằng 0 ở P0/P1 |

---

## TÓM TẮT TRONG 1 CÂU

> **Mô hình AI không từ chối phân tích bảo mật, nhưng nó dễ bị "ám thị" bởi
> comment cảnh báo trong code — và chính quy trình bảo vệ đôi khi lại làm
> nó bỏ sót bệnh nhiều hơn.**
