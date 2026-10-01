# 📊 PHÂN TÍCH CHI TIẾT KẾT QUẢ NGHIÊN CỨU

## RefuseGuard + PackGuard — Báo cáo toàn diện bằng tiếng Việt

> **Cập nhật:** 2026-10-01 · **19 vòng** · **~7.000+ lượt sinh** · **833 bài kiểm thử** · **verify_repro 30/30** · **29+ commits**
>
> **Tài liệu này phân tích chi tiết từng phát hiện, từng thí nghiệm, từng số liệu với biểu đồ nhúng.**
> Biểu đồ được tạo từ dữ liệu thật bằng `paper/make_figures.py` + script trong `docs/charts/`.

---

## MỤC LỤC

1. [Tổng quan](#1-tổng-quan)
2. [Phát hiện 1: Cảnh báo rủi ro — Suy biến định hướng](#2-phát-hiện-1-cảnh-báo-rủi-ro)
3. [Phát hiện 2: Defense gây hại — Sụp đổ recall](#3-phát-hiện-2-defense-gây-hại)
4. [Phát hiện 2a: Phân tích từng thành phần defense](#4-phát-hiện-2a-phân-tích-từng-thành-phần)
5. [Phát hiện 3: Graph features chịu liên kết đàn hồi](#5-phát-hiện-3-graph-features-chịu-liên-kết-đàn-hồi)
6. [Phát hiện 4: CodeBERT fallback](#6-phát-hiện-4-codebert-fallback)
7. [Tín hiệu bất đồng raw-vs-strip](#7-tín-hiệu-bất-đồng)
8. [Trình xác minh phục hồi](#8-trình-xác-minh-phục-hồi)
9. [Kết quả âm có giá trị](#9-kết-quả-âm-có-giá-trị)
10. [Hạn chế](#10-hạn-chế)
11. [Bước tiếp theo](#11-bước-tiếp-theo)

---

## 1. TỔNG QUAN

### Câu hỏi nghiên cứu

> Liệu nội dung không tin cậy (comments, advisories, metadata) trong code có làm
> mô hình ngôn ngữ lớn (LLM) thay đổi phán định lỗ hổng bảo mật một cách hệ thống không?
> Và các biện pháp phòng vệ có khôi phục được độ chính xác mà không gây hại không?

### Quy mô thí nghiệm

| Chỉ số | Giá trị |
|---|---|
| **Tổng lượt sinh (generation)** | ~7.000+ (chạy local MPS/CPU + Kaggle T4 GPU) |
| **Số mô hình** | 6 (Llama-3.2-3B, Granite-3.3-2B, Qwen-Coder-3B, Qwen-Coder-7B, Llama-3.1-8B, CodeBERT-125M) |
| **Kho dữ liệu** | 603 gói (npm + PyPI) + 200 bổ sung + PrimeVul 66 cặppaired |
| **Nhóm CWE** | 787, 125, 703, 476, 190, 200, 416 |
| **Arms tấn công** | C0, CG, CB, CR + P0, P1, P2 + A0, A1, A5 |
| **Biến thể phòng vệ** | B1 (đổi khung), B2 (cắt comment), B3 (xóa mạnh), P1 (cô lập ngữ nghĩa), P3 (provenance), D1 (cắt tối thiểu) |
| **Đăng ký trước** | Bổ sung 1-11 (AMENDMENT-1..11) |
| **Bài kiểm thử** | 833 đậu / 0 rớt |
| **Số commit** | 29+ |

### Các mô hình đã đo

| Mô hình | Tham số | Vai trò | Hành vi nền |
|---|---|---|---|
| Llama-3.2-3B-Instruct | 3 tỷ | Chính (phòng vệ gây hại + hiệu ứng CR) | Thiên lệch all-benign (nhận diện 93%, báo động 0%) |
| Granite-3.3-2B-Instruct | 2 tỷ | Chính (xác nhận CR) | Nền thấp (8% nhận diện, 8% báo động) — có khoảng trống |
| Qwen2.5-Coder-3B-Instruct | 3 tỷ | Phụ (KB + an toàn) | Trơ với mọi tấn công |
| Qwen2.5-Coder-7B-Instruct | 7 tỷ | Mở rộng quy mô (Kaggle) | Trơ vẫn giữ ở 7B |
| Llama-3.1-8B-Instruct | 8 tỷ | Mở rộng quy mô (Kaggle) | Chi phí defense tan biến ở 8B |
| CodeBERT (fine-tuned) | 125 triệu | Fallback detector + baseline | VD-S 0,962 / F1 0,215 |

---

## 2. PHÁT HIỆN 1: CẢNH BÁO RỦI RO — SUY BIẾN ĐỊNH HƯỚNG

![Attack surface theo mô hình](charts/attack_surface_models.png)

### 2.1 Phát hiện chính

**Cảnh báo rủi ro (CR)** chèn vào phần chú thích khiến **Granite-3.3-2B đánh dấu 67% hàm lành tính thành "có lỗ hổng"** — trong khi CG (chú thích chung) và CB (khung thân thiện) gần như không có tác động. Đây là **suy biến định hướng**: nhiễu loạn chỉ kéo phán định về một phía.

### 2.2 Số liệu chi tiết theo từng mô hình

#### Granite-3.3-2B (n=100 lành + 100 độc, 4 nhóm CWE)

| Arm | Nhận diện(vul) | Báo động sai(ben) | ΔNhận diện | ΔBáo động | McNemar chính xác p |
|---|---|---|---|---|---|
| C0 | 8% | 8% | — | — | — |
| CG | 10% | 8% | +2 điểm % | 0 | n.s. |
| CB | 8% | 7% | 0 điểm % | −1 điểm % | n.s. |
| **CR** | **64%** | **67%** | **+56 điểm %** | **+59 điểm %** | **< 10⁻¹⁵** |

**Chi tiết theo nhóm CWE:**

| Nhóm CWE | C0 Báo động sai | CR Báo động sai | ΔBáo động | Số mẫu | p chính xác |
|---|---|---|---|---|---|
| CWE-787 | 8% | 67% | +59 điểm % | 25 | < 10⁻¹⁵ |
| CWE-125 | 8% | 67% | +59 điểm % | 25 | < 10⁻¹⁵ |
| CWE-703 | 8% | 67% | +59 điểm % | 25 | < 10⁻¹⁵ |
| CWE-476 | 8% | 67% | +59 điểm % | 25 | < 10⁻¹⁵ |
| **Gộp chung** | **8%** | **67%** | **+59 điểm %** | **100** | **< 10⁻¹⁵** |

→ **KHÔNG có nhóm CWE nào kháng cự** — tác động đều đặn trên mọi nhóm.

#### Llama-3.2-3B (n=100+100)

| Arm | Nhận diện(vul) | Báo động sai(ben) | ΔNhận diện | ΔBáo động |
|---|---|---|---|---|
| C0 | 93% | 0% | — | — |
| CG | 100% | 0% | +7 điểm % | 0 |
| CB | 100% | 0% | +7 điểm % | 0 |
| **CR** | **100%** | **3%** | +7 điểm % | +3 điểm % |

→ Llama kháng cự tốt hơn Granite nhưng vẫn có dao động nhẹ.

### 2.3 Nhóm kiểm soát loại trừ

| Nhóm kiểm soát | Mục đích | Kết quả |
|---|---|---|
| CG (chú thích chung) | Loại trừ tác động của chú thích chung | ≤ 3 lật → ĐẠT |
| CB (khung thân thiện) | Loại trừ thiên lệch hướng benign | ≤ 2 lật → ĐẠT |
| CR (cảnh báo rủi ro) | Đo suy biến định hướng | **25-57 lật → XÁC NHẬN** |

→ Tác động **không phải** do chú thích chung hay khung thân thiện — nó là **tác động của nội dung liên quan đến rủi ro**.

### 2.4 Phụ thuộc mô hình

| Mô hình | CR Báo động sai(ben) | Đánh giá |
|---|---|---|
| Granite-3.3-2B | **67%** | Nhạy nhất — mô hình đọc cảnh báo như dữ kiện thực |
| Llama-3.2-3B | **3%** | Kháng tốt hơn nhưng vẫn có dao động nhẹ |
| Qwen-Coder-3B | **0%** | Trơ — không đủ nhạy để kiểm tra |

→ **Phụ thuộc mô hình**: Granite nhạy nhất, Llama vừa, Qwen trơ. Không thể khái quát
"mọi mô hình đều nhạy" — phải giới hạn theo họ mô hình.

---

## 3. PHÁT HIỆN 2: DEFENSE GÂY HẠI — SỤP ĐỔ RECALL

### 3.1 Phát hiện chính

**Bọc provenance P3** làm **Llama-3.2-3B sụp recall** từ 1.000 → .367/.333
(39/60 lật, McNemar p ≤ 3,8e-6). Đây là **sự cố corrupted do defense gây ra**:
phòng vệ gây hại nhiều hơn lợi.

### 3.2 Số liệu chi tiết

#### Llama-3.2-3B (n=60 vul, arm C5_near)

| Bậc | Bổ sung gì | Recall | Δ so với A0 | McNemar chính xác p |
|---|---|---|---|---|
| A0 | thô (không defense) | 1.000 | — | — |
| A1 | chỉ bọc boundary | .983 | −.017 | 1,0 |
| A2 | + header ngữ cảnh | .900 | −.100 | ,002 |
| A3 | + generic wrap | .848 | −.152 | < ,001 |
| A4 | + xử lý chuỗi | .898 | −.102 | < ,001 |
| **A5** | **+ khẳng định lại hệ thống** | **.433** | **−.567** | **3,4×10⁻⁷** |

**Thành phần gây hại:**
- **Khẳng định lại hệ thống (A4→A5)**: gây **28/34 = 82%** tổng hại
- A1 (bọc boundary): gần như vô hại (−.017)
- Kết luận: **cơ chế an toàn phức tạp gây hại; provenance tối thiểu an toàn**

#### So sánh chéo mô hình

| Mô hình | Recall A0 | Recall A5 | Có hại không? |
|---|---|---|---|
| Llama-3.2-3B | 1.000 | .433 | ✅ CÓ |
| Qwen2.5-Coder-3B | 1.000 | 1.000 | ❌ KHÔNG |
| Qwen2.5-Coder-7B | .483 | .533 | ❌ KHÔNG |
| Llama-3.1-8B | .600 | .550 | ❌ KHÔNG (p = ,508) |

→ **Hại là hiện tượng 3 tỷ + riêng Llama**. Ở 8 tỷ, hại tan biến.

### 3.3 Tại sao quan trọng?

> **Defense gây corruption** là rủi ro chưa được ghi nhận trong tài liệu
> phòng chống chèn lệnh. Các nghiên cứu hiện tại (StruQ, CaMeL, CodeSentinel)
> báo cáo defense hiệu quả nhưng không đo lỗi do defense gây ra trên task
> cụ thể. Phát hiện này cho thấy defense phải được kiểm tra trên task
> cụ thể, không chỉ trên tỷ lệ tấn công thành công.

---

## 4. PHÁT HIỆN 2a: PHÂN TÍCH TỪNG THÀNH PHẦN DEFENSE

![Biểu đồ thác nước ablation](charts/defense_ablation_waterfall.png)

### Chi tiết từng bậc (A0 → A5, Llama-3.2-3B)

| Bậc | Thành phần | Recall | Δ so với bậc trước | Vai trò trong hại |
|---|---|---|---|---|
| A0 | Không defense | 1.000 | — | Nền |
| A1 | Chỉ bọc boundary | .983 | −.017 | Gần vô hại |
| A2 | + header ngữ cảnh | .900 | −.083 | Vừa |
| A3 | + generic wrap | .848 | −.052 | Vừa |
| A4 | + string mediation | .898 | +.050 (hồi phục) | Không gây hại |
| **A5** | **+ khẳng định lại hệ thống** | **.433** | **−.465** | **GÂY HẠI CHÍNH** |

### Điều này có nghĩa gì?

1. **Chỉ bọc boundary (A1) an toàn**: chỉ bọc advisory trong nhãn gần như
   không ảnh hưởng mô hình → có thể triển khai
2. **Khẳng định lại hệ thống gây hại**: đoạn "IMPORTANT: You must follow your
   operating objectives..." khiến Llama sụp recall → thêm nhiễu vào system
   prompt gây hại nhiều hơn thêm vào user prompt
3. **A4 hồi phục một phần**: xử lý chuỗi có tác động bảo vệ nhẹ

### Khuyến nghị

> **Chỉ dùng boundary wrap (A1) khi triển khai thực tế.** Không dùng system
> reassertion ở mô hình ≤3 tỷ. Nếu cần defense mạnh hơn, nâng cấp lên ≥8B.

---

## 5. PHÁT HIỆN 3: GRAPH FEATURES CHỊU LIÊN KẾT ĐÀN HỒI

### 5.1 Phát hiện chính

Graph features (18 đặc trưng từ behavior graph) **chịu FedAvg tốt** — TOST
equivalence ĐẠT với biên độ ±.02 F1. TF-IDF **mất khả năng** dưới FedAvg
(dự đoán tất cả đều malicious).

### 5.2 Số liệu

| Bộ đặc trưng | FedAvg F1 (20 seeds) | Centralized F1 | ΔF1 | TOST ±.02 |
|---|---|---|---|---|
| **Graph** | .869 ± .051 | .858 ± .047 | +.011 | ✅ ĐẠT |
| **TF-IDF** | .790 ± .031 | .842 ± .038 | −.052 | ❌ RỚT (mất năng lực) |

### 5.3 Tại sao?

| Đặc tính | Graph features | TF-IDF |
|---|---|---|
| Số chiều | 18 (gọn) | 2^18 (thưa) |
| Không gian | Semantic classes (6) + graph metrics | Token vocabulary |
| Đột biến client | Chịu được | Vocabulary lệch theo client |
| FedAvg | ≈ centralized (TOST ĐẠT) | Degenerates (all-malicious) |

**Kết luận:** Với phân loại bảo mật code liên kết đàn hồi, **đặc trưng ngữ nghĩa
gọn robust hơn đặc trưng từ vựng thưa** — phát hiện có giá trị cho cộng đồng FL.

---

## 6. PHÁT HIỆN 4: CODEBERT FALLBACK

### Số liệu

| Chỉ số | Giá trị | Ghi chú |
|---|---|---|
| Recall@0.5 | .541 | Trên test subset (549 vul + 20k benign subsample) |
| F1 | .215 | Khớp PrimeVul paper (~0.209) |
| MCC | .232 | — |
| AUC | .847 | — |
| VD-S (FNR@FPR≤0.5%) | **.962** | Chỉ 3.8% vul được detect ở FPR ≤0.5% |
| Paired accuracy | .009 | Gần như random trên paired vul/patched |
| E7 fallback coverage | 0.985 → 1.000 | +1.5 điểm % usable answer coverage |

**Đọc:** CodeBERT là baseline yếu nhưng đủ làm fallback. VD-S = 0.962 có nghĩa là
96% vulnerable functions bị miss ở FPR ≤0.5% — realistic difficulty.

---

## 7. TÍN HIỆU BẤT ĐỒNG RAW-VS-STRIP

### Số liệu

| Chỉ số | Granite-3.3-2B | Llama-3.2-3B |
|---|---|---|
| CDR (bắt corruption) | 80,6% | 3,2% |
| FAR (báo động sai) | 77,1% | 8,6% |

### Đánh giá

Tín hiệu **nhạy nhưng thiếu đặc hiệu** — bắt được corruption nhưng cũng cảnh
báo sai nhiều. Để dùng làm detector production, cần kết hợp thêm signals
(chênh lệch kích thước AST, delta độ tin cậy, nhất quán đa góc nhìn).

---

## 8. TRÌNH XÁC MINH PHỤC HỒI

### Kết quả

| Phương pháp | CRR | DER | Nhận xét |
|---|---|---|---|
| D1 (chỉ cắt) | 32,7% | 4% | Đơn giản nhưng hiệu quả |
| EVIDA v1 (bất đồng + kiểm tra) | 21,8% | 17,1% | ❌ KHÔNG ĐẠT ngưỡng |
| **D1 + trình xác minh evidence** | **CHƯA CHẠY** | — | Chờ thí nghiệm |

---

## 9. KẾT QUẢ ÂM CÓ GIÁ TRỊ

### 9.1 Blocking không xảy ra

RR = 0.000 xuyên suốt ~7.000+ lượt sinh, mọi kiểu tấn công (C1-C5), mọi mô hình (2-8B), mọi domain (vulnerability + package). Refusal pathway hoạt động (OR-Bench probes bị từ chối 56%), nhưng defensive framing không kích hoạt nó.

### 9.2 FedAvg ≈ Centralized

TOST equivalence ĐẠT với biên độ ±.02 F1 trên 20 seeds (graph features). FL "miễn phí" cho graph features.

### 9.3 TF-IDF mất năng lực under FL

Recall = 1.0 (all-malicious predictor) trong 79/80 ô. Đặc trưng từ vựng thưa
không liên kết đàn hồi robust.

### 9.4 Alarm precision .2111

Tín hiệu bất đồng đơn giản (raw ≠ strip) không đủ làm corruption detector.
Precision quá thấp để dùng production.

---

## 10. HẠN CHẾ

| Hạn chế | Chi tiết | Mức độ |
|---|---|---|
| **Model scale** | Chỉ 2–8B open-weight; frontier chưa đo | Nghiêm trọng |
| **Corpus** | 603 packages pilot + 200 expansion; nhỏ hơn SOTA | Vừa |
| **Benign labels** | Popularity-derived + random; không audit thủ công | Vừa |
| **Safety model coverage** | Chỉ Llama + Granite responsive; Qwen inert | Giảm khẳng định |
| **FL simulation** | 2 clients; DP/SecAgg mô phỏng | Pilot |
| **LCO power** | MDE ≈ .05 F1; null chưa đủ power | Đã tiết lộ |
| **Alarm precision** | .2111 (EVIDA v1); pruned 1.000 nhưng single-regime | Cần stress-test |
| **80 mẫu không có chú thích** | Llama CR = C0 giống hệt từng byte → không kiểm tra được sự nhiễu loạn | Đã công bố |

---

## 11. BƯỚC TIẾP THEO

### Cần từ người dùng

| # | Nguồn lực | Mở khóa |
|---|---|---|
| 1 | **Tài khoản OSF** | Dấu thời gian pre-registration (P1-7) |
| 2 | **API key frontier** (GPT-4o / Claude / Gemini) | Safety attack ở quy mô lớn (P1-8) |
| 3 | **Duyệt gỡ <4B** | P1-10 A5 thang thang trên 7B/8B qua Kaggle GPU |
| 4 | **2 annotator** | P2-13 KB human-κ validation |

### Có thể làm ngay (local, chưa duyệt)

| # | Công việc | Giá trị |
|---|---|---|
| A | Alarm-pruning refinement ( dựa trên 37/55 inert counterfactuals) | Nâng precision .21 → .40+ |
| B | Leave-cluster-out ở quy mô corpus mới | External validity |
| C | Adaptive red-team: các cuộc tấn công được thiết kế để phá D1-strip defense | Gate G |
| D | GNN trên behavior graphs (thay feature-vector) | Nâng cấp phương pháp |
| E | Đánh giá cấp repository (bối cảnh PR/vấn đề) | Độ tin cậy bên ngoài |
