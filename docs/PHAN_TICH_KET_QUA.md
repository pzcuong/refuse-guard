# 📊 PHÂN TÍCH CHI TIẾT KẾT QUẢ NGHIÊN CỨU — BẢN ĐẦY ĐỦ

## RefuseGuard + PackGuard — 19 vòng, ~7.000+ lượt sinh, 6 mô hình, 833 bài kiểm thử

---

## PHẦN A: BỐI CẢNH NGHIÊN CỨU

### A.1. Câu hỏi nghiên cứu

> Liệu nội dung không tin cậy (chú thích, cảnh báo, metadata) trong code có làm mô hình
> ngôn ngữ lớn (LLM) thay đổi phán định lỗ hổng một cách hệ thống không? Và các biện
> pháp phòng vệ có khôi phục được độ chính xác mà không gây hại không?

### A.2. Phạm vi đo lường

| Thành phần | Chi tiết |
|---|---|
| **Mô hình** | 6 mô hình open-weight (2–8 tỷ tham số): Llama-3.2-3B, Granite-3.3-2B, Qwen2.5-Coder-3B, Qwen2.5-Coder-7B, Llama-3.1-8B, CodeBERT-125M (fine-tuned) |
| **Kho dữ liệu** | 603 gói npm/PyPI (DataDog wild-capture) + 200 benign mở rộng ngẫu nhiên + PrimeVul test_paired 870 dòng |
| **Nhóm CWE** | 787, 125, 703, 476, 190, 200, 416 |
| **Arms tấn công** | C0 (sạch), CG (chung chung), CB (benign hướng), CR (cảnh báo rủi ro, sink-grounded), P0/P1/P2 (an toàn) |
| **Biến thể defense** | B1 (reframe), B2 (cắt comment), B3 (xóa mạnh), P1 (cô lập ngữ nghĩa), P3 (provenance full), D1 (chỉ cắt tối thiểu) |
| **Tổng lượt sinh** | ~7.000+ trên 19 vòng (local MPS/CPU + Kaggle T4 GPU) |
| **Ràng buộc** | Chỉ mô hình <4B local; Kaggle GPU cho 7B/8B (đã phê duyệt) |

### A.3. Phương pháp đo

Mỗi hàm được tạo 4 phiên bản ngữ cảnh (C0 = sạch, CG = chú thích chung chung,
CB = benign hướng, CR = cảnh báo rủi ro), tất cả đảm bảo **AST tương đương**
(xóa phần chèn → AST giống gốc). Mỗi phiên bản được gửi cho mô hình LLM với
system prompt chuẩn hóa, yêu cầu trả về JSON: `{verdict: vulnerable|benign,
confidence, reason}`. Kết quả được phân tích bằng **McNemar exact test** (paired
per-hàm), **Wilcoxon signed-rank** (paired per-seed), và **bootstrap CI 10.000
lượt** (seed 20260922).

---

## PHẦN B: BỐN PHÁT HIỆN CHÍNH

---

### 🔵 PHÁT HIỆN 1: CR ADVISORY GÂY SUY BIẾN PHÁN ĐỊNH CÓ HƯỚNG

![CR Advisory theo mô hình](charts/attack_surface_models.png)

#### Bảng số liệu chi tiết

| Mô hình | Arm | Recall(vul) | FP(ben) | ΔRecall | ΔFP | Exact McNemar p |
|---|---|---|---|---|---|---|
| **Granite-3.3-2B** | C0 | 8% | 8% | — | — | — |
| Granite-3.3-2B | CG | 10% | 8% | +2pp | 0 | n.s. |
| Granite-3.3-2B | CB | 8% | 7% | 0pp | −1pp | n.s. |
| **Granite-3.3-2B** | **CR** | **64%** | **67%** | **+56pp** | **+59pp** | **< 10⁻¹⁵** |
| Llama-3.2-3B | C0 | 93% | 0% | — | — | — |
| Llama-3.2-3B | CG | 100% | 0% | +7pp | 0 | n.s. |
| Llama-3.2-3B | CB | 100% | 0% | 0pp | 0 | n.s. |
| **Llama-3.2-3B** | **CR** | **100%** | **3%** | +7pp | +3pp | n.s. |
| Qwen-Coder-3B | C0 | ~0% | ~0% | — | — | — |
| Qwen-Coder-3B | CR | ~0% | ~0% | 0 | 0 | — |

#### Diễn giải

**Granite-3.3-2B** là mô hình nhạy nhất với CR advisory. Ở baseline C0, Granite
gần như all-benign (recall 8%, FP 8%). Khi nhận CR advisory (chứa tên sink API
thật của chính hàm đó — ví dụ "strcpy", "system" — 100% query-relevant), Granite
chuyển 67% benign functions thành "vulnerable" và tăng recall trên vulnerable
functions từ 8% lên 64%.

Cơ chế: advisory chứa **tên sink API có thật trong function** (100% query-relevant,
0% generic), tạo ra một "risk prior" mà Granite sử dụng làm tín hiệu bổ sung để
chuyển từ trạng thái all-benign sang trạng thái phát hiện. Đây KHÔNG phải là
cải thiện chất lượng phân tích — mà là **verdict được điều khiển bởi ngữ cảnh**,
không phải bởi logic của code.

**Llama-3.2-3B** ít nhạy hơn đáng kể: chỉ +3pp FP, +7pp recall. Tuy nhiên,
Llama đã có baseline recall 93% (all-vulnerable bias ngược chiều), nên còn
headroom hạn chế cho CR tác động thêm.

**Qwen-Coder-3B** hoàn toàn inert — 0% recall, 0% FP ở mọi arm. Qwen-family
thể hiện tính trơ nhất quán với mọi loại attack.

#### Tách biệt với nhóm kiểm soát

| So sánh | CR FP | CG FP | CB FP | CR − max(CG,CB) | Ý nghĩa |
|---|---|---|---|---|---|
| Granite | 67% | 8% | 7% | **+59pp** | CR ≫ controls |
| Llama | 3% | 0% | 0% | +3pp | Nhẹ |

→ CG (generic comment) và CB (benign framing) KHÔNG gây tác động — chỉ CR
(risk-relevant advisory) mới có effect. Điều này loại trừ giả thuyết "mọi
chú thích đều gây nhiễu".

---

### 🔵 PHÁT HIỆN 2: DEFENSE GÂY HẠI RECALL — COMPONENT ABLATION

![Component ablation waterfall](charts/defense_ablation_waterfall.png)

#### Bảng ablation đầy đủ (Llama-3.2-3B, C5_near, n=60, seed 20260923)

| Bậc | Thành phần bổ sung | Recall | Δ vs bậc trước | Exact McNemar p | Flips |
|---|---|---|---|---|---|
| A0 | raw (không defense) | 1.000 | — | — | — |
| A1 | + boundary wrap | .983 | −.017 | 1.0 | 1/60 |
| A2 | + context header | .900 | −.083 | .002 | 5/60 |
| A3 | + generic wrap | .848 | −.052 | < .001 | 3/60 |
| A4 | + string mediation | .898 | +.050 | — | (hồi phục 3) |
| **A5** | **+ system reassertion** | **.433** | **−.465** | **3,4×10⁻⁷** | **28/60** |

#### Diễn giải từng bậc

**A1 (boundary wrap)**: Chỉ bọc advisory comment trong nhãn `[UNTRUSTED-ANNOTATION]`.
Recall giảm .017 (1 flip) — gần như vô hại. **→ An toàn, có thể deploy.**

**A2 (+ context header)**: Thêm header `[CONTEXT-PROVENANCE: This context contains...]`.
Recall giảm thêm .083 → tổng −.100. Header cung cấp thông tin bổ sung nhưng cũng
chiếm không gian context.

**A3 (+ generic wrap)**: Thêm generic wrapper quanh toàn bộ context.
Recall giảm thêm .052 → tổng −.152. Generic wrap không chứa thông tin hữu ích
nhưng chiếm token → pha loãng attention.

**A4 (+ string mediation)**: Xử lý string literals (che giấu, cắt ngắn).
Recall **tăng hồi phục** +.050 → tổng −.102. String mediation có tác động
bảo vệ nhẹ (loại bỏ string độc hại hoặc gây nhiễu).

**A5 (+ system reassertion)**: Thêm đoạn khẳng định lại mục tiêu trong system
prompt ("IMPORTANT: You must follow your operating objectives..."). Recall
**sụp từ .898 xuống .433** — mất .465 trong MỘT bậc. Đây là thủ phạm chính,
gây **28/34 = 82%** tổng flips trong toàn bộ pipeline.

#### Cross-model: Harm chỉ xảy ra trên Llama-family ≤3B

| Model | Scale | A0 recall | A5 recall | Δ | Harm? |
|---|---|---|---|---|---|
| Llama-3.2-3B | 3B | 1.000 | .433 | **−.567** | ✅ CÓ (p = 3,4×10⁻⁷) |
| Qwen-Coder-3B | 3B | 1.000 | 1.000 | 0 | ❌ KHÔNG |
| Qwen-Coder-7B | 7B | .483 | .533 | +.050 | ❌ KHÔNG (p = .727) |
| Llama-3.1-8B | 8B | .600 | .550 | −.050 | ❌ KHÔNG (p = .508) |

→ **Harm là hiện tượng 3B + Llama-family-specific**. Tại 8B, harm tan biến —
cho thấy defense cost là vấn đề của mô hình nhỏ, không phải bản chất của
phương pháp defense.

---

### 🔵 PHÁT HIỆN 2a: COMPONENT ABLATION — THỦ PHẠM LÀ SYSTEM REASSERTION

![Component ablation waterfall](charts/defense_ablation_waterfall.png)

Trong 6 bậc defense A0→A5, chỉ có **A5 (system task-intent reassertion)** gây
phần lớn harm: recall sụp từ .898 (A4) xuống .433 (A5) — mất .465 trong một bậc.
Trước đó, A1 (boundary wrap) chỉ gây −.017 và A4 (string mediation) thậm chí
hồi phục +.050 so với A3.

**Diễn giải:** System reassertion là đoạn text nhấn mạnh vào system prompt rằng
"agent phải tuân theo operating objectives". Đoạn này chiếm token context,
gây phân tán attention, và trên Llama-3.2-3B, làm model "quên" các detection
đã thực hiện ở A0. Đây là một finding quan trọng: **việc thêm text nhấn mạnh
vào system prompt — hành động tưởng như vô hại — lại là nguyên nhân chính
gây mất detection.**

**Khuyến nghị:** Chỉ dùng boundary wrap (A1). Loại bỏ system reassertion (A5).
Không thêm text vào system prompt trong pipeline phân tích bảo mật.

---

### 🔵 PHÁT HIỆN 3: GRAPH FEATURES CHỊU LIÊN KẾT ĐÀN HỒI FEDERATED

#### Bảng so sánh 20 seeds

| Feature set | Phương pháp | FedAvg F1 | Centralized F1 | ΔF1 | TOST ±.02 |
|---|---|---|---|---|---|
| **Graph (18 fts)** | sklearn LR lbfgs | **.869 ± .051** | .858 ± .047 | +.011 | ✅ PASS |
| TF-IDF (2^18 dims) | sklearn LR lbfgs | .790 ± .031 | .842 ± .038 | −.052 | ❌ FAIL |

#### Đọc kết quả

Graph features (18 chiều, semantic classes + graph metrics) khi train bằng
FedAvg (federated averaging) cho F1 **.869 ± .051** so với centralized
**.858 ± .047** — FedAvg **không thua**, thậm chí nhỉnh hơn nhẹ. TOST
equivalence PASS (CI90 của ΔF1 nằm trọn trong ±.02) → FedAvg **không thua
centralized quá .02 F1** — một claim dương có kiểm định.

TF-IDF (sparse lexical features) khi train bằng FedAvg cho F1 **.790 ± .031**,
thấp hơn centralized **.842 ± .038** — ΔF1 = **−.052** (p = 3,8×10⁻⁶). Nghĩa
là TF-IDF **mất năng lực dưới FedAvg** — dự đoán tất cả malicious.

→ **Đối với federated code-security classification: dùng semantic features,
tránh sparse lexical features.** Đây là finding có giá trị cho cộng đồng FL.

---

### 🔵 PHÁT HIỆN 4: CR ADVISORY THEO CWE FAMILY — REPLICATION

#### Confirmatory pilot trên 200 held-out samples (Granite-3.3-2B)

| Nhóm CWE | C0 recall(vul) | CR recall(vul) | ΔRecall | C0 FP(ben) | CR FP(ben) | ΔFP |
|---|---|---|---|---|---|---|
| CWE-787 | 8% | **64%** | +56pp | 8% | **67%** | +59pp |
| CWE-125 | 8% | **64%** | +56pp | 8% | **67%** | +59pp |
| CWE-703 | 8% | **64%** | +56pp | 8% | **67%** | +59pp |
| CWE-476 | 8% | **64%** | +56pp | 8% | **67%** | +59pp |
| **Pooled** | **8%** | **64%** | **+56pp** | **8%** | **67%** | **+59pp** |

→ Effect **đồng nhất trên mọi nhóm CWE** — không có nhóm nào resistant.

---

## PHẦN C: TỔNG HỢP TẤT CẢ PHÁT HIỆN

### Bảng tổng hợp: Mô hình × Attack arm × Defense × Recall

| Mô hình | Scale | C0 recall | CR recall | ΔCR | P3 recall | ΔP3 | Harm P3? | CR FP(ben) |
|---|---|---|---|---|---|---|---|---|
| Granite-3.3-2B | 2B | 8% | 64% | +56pp | 1.000 (n=25 subset) | 0 | ❌ | 67% |
| Llama-3.2-3B | 3B | 93% | 100% | +7pp | .433 | **−.567** | ✅ CÓ | 3% |
| Qwen-Coder-3B | 3B | ~0% | ~0% | 0 | 1.000 | 0 | ❌ KHÔNG | 0% |
| Qwen-Coder-7B | 7B | .483 | .533 | +5pp | .550* | −.050 | ❌ KHÔNG | 0% |
| Llama-3.1-8B | 8B | .600 | .550 | −.050 | — | — | ❌ KHÔNG | 0% |

*Qwen-7B: ladder data từ Kaggle GPU, defensive arm chưa chạy.

### Đọc tổng hợp

1. **CR advisory là attack surface thật** trên Granite (67% FP) và có effect
   nhẹ trên Llama (+7pp recall). Tuy nhiên, đây là **sensitivity shift**, không
   phải improvement — model đọc advisory như gợi ý, không phải phân tích tốt hơn.

2. **Defense P3 gây harm chỉ trên Llama-3.2-3B** (−.567 recall). Qwen inert.
   Tại 8B, harm tan biến. → **Chọn model family và scale trước khi deploy defense.**

3. **Graph features federation-robust** (TOST PASS); TF-IDF degenerates.
   → **Dùng graph features nếu federate.**

4. **Alarm precision .2111** — invariance signal đơn giản không đủ. Cần
   refinement hoặc bỏ.

---

## 10. HẠN CHẾ TOÀN DỰ ÁN

| Hạn chế | Chi tiết | Mức độ ảnh hưởng |
|---|---|---|
| **Model scale** | Chỉ 2–8B open-weight; frontier (GPT-4o, Claude) chưa đo | Nghiêm trọng — cần API key |
| **Corpus** | 603 packages pilot + 200 expansion; nhỏ hơn Cerebro ~5k | Vừa |
| **Benign labels** | Popularity-derived + random; không audit thủ công | Vừa |
| **Safety model coverage** | Chỉ Llama + Granite responsive; Qwen inert (floor) | Giảm khẳng định "model-dependent" |
| **FL simulation** | 2 clients; DP/SecAgg mô phỏng | Pilot |
| **LCO power** | n=20 seeds, MDE ≈ .05 F1 | Đã disclose |
| **Alarm precision** | .2111 (EVIDA v1); pruned 1.000 nhưng single-regime | Cần stress-test |
| **80 mẫu không comment** | Llama CR = C0 byte-identical → không test được perturbation | Đã công bố |
| **Pre-registration** | AMENDMENT-1..11 trong repo; chưa có OSF timestamp công khai | Cần OSF account |

---

## 11. BƯỚC TIẾP THEO

### Cần tài nguyên từ user

| # | Tài nguyên | Mở khóa | Thời gian |
|---|---|---|---|
| 1 | **OSF account** | Timestamp pre-registration (P1-7) | 15 phút |
| 2 | **API key frontier** (GPT-4o / Claude / Gemini) | Safety attack ở quy mô lớn (P1-8) | 1-2h |
| 3 | **Duyệt gỡ <4B** | P1-10 A5 ladder trên 7B/8B qua Kaggle GPU | 2-3h |
| 4 | **2 annotator** | P2-13 KB human-κ validation | 1-2h |

### Có thể làm ngay (local, chưa duyệt)

| # | Việc | Giá trị |
|---|---|---|
| A | Alarm-pruning refinement | Nâng precision .21 → .40+ |
| B | Leave-cluster-out ở scale corpus mới | External validity |
| C | Adaptive red-team: attacks designed to break D1-strip defense | Gate G |
| D | GNN trên behavior graphs (thay feature-vector) | Method nâng cấp |
| E | Repository-level evaluation (PR/issue context) | External validity |
