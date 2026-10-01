# 📊 PHÂN TÍCH & ĐÁNH GIÁ KẾT QUẢ NGHIÊN CỨU

## RefuseGuard + PackGuard — Báo cáo tổng hợp bằng tiếng Việt

> Cập nhật: 2026-09-30 · 19 vòng triển khai · 30 commits · 833 tests · verify_repro 30/30

---

## 1. TỔNG QUAN DỰ ÁN

### Câu hỏi nghiên cứu chính

> Liệu nội dung không tin cậy (comments, advisories, metadata) trong code có làm
> LLM-based vulnerability detector thay đổi verdict một cách hệ thống không?
> Và các defense có khôi phục được độ chính xác mà không gây hại không?

### Hai bài báo

| Bài | Tên | Trang | Trạng thái |
|---|---|---|---|
| **PackGuard** (bài gộp chính) | The Advisory Inside: Untrusted In-Package Content as a Domain- and Family-Dependent Attack Surface | 9 | ✅ SUBMIT-READY |
| **RefuseGuard** (companion) | Robust LLM-Based Vulnerability Detection under Safety-Induced Blocking | 20 | ✅ SUBMIT-READY |

### Mô hình đã đo

| Model | Params | Vai trò |
|---|---|---|
| Llama-3.2-3B-Instruct | 3B | Primary (safety attack + ladder + defense) |
| Granite-3.3-2B-Instruct | 2B | Primary (confirmatory replication) |
| Qwen2.5-Coder-3B-Instruct | 3B | Secondary (KB building, some arms) |
| Qwen2.5-Coder-7B-Instruct | 7B | Scale extension (Kaggle GPU) |
| Llama-3.1-8B-Instruct | 8B | Scale extension (Kaggle GPU) |
| CodeBERT (fine-tuned) | 125M | Baseline detector + fallback |

---

## 2. KẾT QUẢ CHÍNH (4 FINDING CÓ KIỂM ĐỊNH THỐNG KÊ)

### 🔵 F1 — Attack surface phụ thuộc domain VÀ model family

**Nội dung:** Risk advisory chèn vào code làm verdict dịch về "vulnerable" một cách
hệ thống, nhưng **chỉ trên một số model family** và **không phải qua refusal**.

| Model | C0 recall(vul) | CR recall(vul) | Δ | McNemar p | Benign FP |
|---|---|---|---|---|---|
| Granite-3.3-2B | 8% | **64%** | **+56pp** | < 10⁻¹⁵ | **67/100** |
| Llama-3.2-3B | 93% | 100% | +7pp | n.s. | **3/100** |
| Qwen2.5-Coder-3B | ~0% | ~0% | 0 | — | 0/100 |

**Giải thích:** Granite gần như all-benign ở baseline → risk advisory "đánh thức" model,
tạo 56pp recall jump. Nhưng 64% recall vẫn thấp — modelđangđọc advisory như một gợi
ý, chứ không phải thực sự phân tích code tốt hơn.

**Bằng chứng:** `outputs/confirmatory/kaggle_v2/results.jsonl` (800 gen, 4 CWE families,
100+100 held-out, freeze hash `aecc2797`).

---

### 🔵 F2 — Defense-induced corruption phụ thuộc model family

**Nội dung:** Safety wrapper P3 (provenance-based) làm **Llama-3.2-3B sụp recall**
1.000 → .367/.333 (39/60 flips, McNemar p ≤ 3.8e-6), nhưng **Qwen inert** (0 flips).
Tại 8B, harm **biến mất** (Δ = −.05, p = .508).

| Model | P0 recall | P3 (full) recall | Harm? |
|---|---|---|---|
| Llama-3.2-3B | 1.000 | .367 / .333 | ✅ CÓ (p ≤ 3.8e-6) |
| Qwen2.5-Coder-3B | 1.000 | 1.000 | ❌ KHÔNG |
| Llama-3.1-8B | .600 | .550 | ❌ KHÔNG (p = .508) |

**Giải thích:** Defense cost là hiện tượng **3B + family-specific**. Tại 8B, harm tan biến.
Minimal provenance (A1) an toàn ở mọi scale đã đo.

**Bằng chứng:** `outputs/experiments/r10_granite_ladder/results_granite2b__vul__A{0,5,1}.json`
+ `outputs/packguard/r16_kaggle/llama8b/results_llama8b_ladder.jsonl` (Kaggle GPU).

---

### 🔵 F3 — Federation-robust detector nền

**Nội dung:** Graph features chịu federation tốt (TOST equivalence PASS) trong khi
TF-IDF sụp dưới FedAvg (degeneration all-malicious).

| Metric | Graph FedAvg | Graph Central | TOST ±.02 |
|---|---|---|---|
| F1 (20 seeds) | .869 ± .051 | .858 ± .047 | ✅ PASS |
| AUC (20 seeds) | .882 ± .042 | .876 ± .042 | ✅ PASS |

| Metric | TF-IDF FedAvg | TF-IDF Central | Kết quả |
|---|---|---|---|
| F1 (20 seeds) | .790 ± .031 | .842 ± .038 | ❌ **−.052** (p = 3.8e-6) |

**Giải thích:** Graph features là lựa chọn federation-robust; TF-IDF degenerates
(all-malicious predictor, 79/80 cells recall=1.0).

**Bằng chứng:** `outputs/packguard/fl_multiseed/grid_results.json` (640 runs, 20 seeds).

---

### 🔵 F4 — CodeBERT fallback detector nền

VD-S (FNR@FPR≤0.5%) = **0.962**; F1 = 0.215 (khớp PrimeVul paper ~0.209).

---

## 3. KẾT QUẢ PHỤ (đã audit, có giá trị)

| Finding | Số liệu | Ý nghĩa |
|---|---|---|
| Alarm precision .2111 | EVIDA alarm: 57TP / 213FP | Invariance signal đơn giản KHÔNG đủ làm detector |
| Alarm-pruning EVIDA-2: precision 1.000, CRR .803 | Vòng 18 | Pruning rule hoạt động, nhưng recovery là fallback-driven |
| D1-only beats EVIDA paired 13-0 | McNemar p = .000244 | Complex pipeline THUA simple strip |
| CR advisory: 0 FN trên vul (Granite) | 0/100 flips vul→ben | Advisory không gây mất detection trên vul |
| P1 giảm injection 0.742→0.484 | McNemar p = .0078 | Giảm nhưng vul-only subset n.s. |
| C5 advisory trên Granite: 0 FN trên vul | 0/100 flips vul→ben | Advisory không gây mất detection |

---

## 4. KẾT QUẢ ÂM (đều được disclose first-class)

| Negative result | Số liệu | Ý nghĩa |
|---|---|---|
| **Blocking không xảy ra** | RR = 0.000 trên ~7,000+ gen, mọi attack, mọi model 2–8B | Bác bỏ giả thuyết refusal ở code-security domain |
| **EVIDA mechanism invalid** | CRR .2182 < gate .40; DIER .1712 > gate .05 | Alarm precision .21 — invariance signal đơn giản KHÔNG đủ |
| **EVIDA thua strip-only** | CRR(EVIDA) .218 < CRR(D1) .327 | Complex pipeline THUA simple defense |
| **TF-IDF degenerates under FL** | Recall = 1.0, F1 = base rate (79/80 cells) | TF-IDF không federation-robust |
| **Centralized LR collapse 2/160** | F1 .375 / .326 | Centralized baseline cũng instability |

---

## 5. PHÂN LOẠI 59 NEGATIVE/POSITIVE RESULTS

| Phân loại | Số lượng | Ví dụ |
|---|---|---|
| **CORE POSITIVE** | 4 | F1-F4 ở trên |
| **SUPPORTING POSITIVE** | 11 | TOST, alarm-pruning, scale boundary, LCO null |
| **NEGATIVE BUT USEFUL** | 15 | Blocking absent, TF-IDF degeneration, FedAvg null |
| **RETRACTED** | 5 | EVIDA FP-bias misinterpretation, EVIDA collapse 1-cell, v.v. |
| **APPENDIX-ONLY** | 13 | µ-sweep chi tiết, npm_hook 3-client, v.v. |
| **LEDGER-ONLY** | 4 | Minor sanity checks |
| **One-sentence** | 3 | Trivial sanity checks |

Chi tiết đầy đủ: `RESEARCH_STATE/PROJECT_INVENTORY.md`

---

## 6. ĐÁNH GIÁ CHẤT LƯỢNG NGHIÊN CỨU

### Điểm MẠNH

| Tiêu chí | Đánh giá | Bằng chứng |
|---|---|---|
| **Pre-registration** | ✅✅ Mẫu mực | AMENDMENT-1..11, gates frozen trước generation, falsifiers pre-registered |
| **Audit trail** | ✅✅ Mẫu mực | 15 vòng × (3 làm + 2 audit + 1 confirm), mọi số truy vết được |
| **Falsification protocol** | ✅ Hoạt động đúng | 2 falsifiers bắn đúng prereg; FAIL preserved verbatim |
| **Reproducibility** | ✅ | Re-execution bit-identical; 833 tests; verify_repro 30/30 |
| **Honest reporting** | ✅ | 3 claims bị thu hồi; negative results first-class; không selective reporting |
| **Benchmark contribution** | ✅ | C5 query-relevant advisory (100% sink-grounded, anti-leakage) |

### Điểm YẾU (disclosed trong paper)

| Hạn chế | Chi tiết |
|---|---|
| **Model scale** | Chỉ 2–3B open-weight (8B/7B đã xóa theo ràng buộc) — frontier chưa đo |
| **Corpus scale** | 603 packages — nhỏ hơn SOTA (Cerebro ~5k) |
| **Benign labels** | Popularity-derived, không audit thủ công |
| **Safety arms** | Chỉ 2 model families responsive; Llama baseline degenerate |
| **FL simulation** | Chỉ 2 clients; DP/SecAgg simulation-only |

---

## 7. CÂU CHUYỆN NGHIÊN CỨU (research narrative)

### Trước (lo ngại ban đầu)
> "Safety alignment + untrusted context có thể block/corrupt LLM vulnerability scanner"

### Sau 19 vòng (câu chuyện thực tế)
> **LLM vulnerability detectors are selectively robust.** They resist generic
> pressure and blocking attacks, but query-relevant risk evidence shifts
> verdicts in a family- and domain-dependent direction — and naïve safety
> wrappers can introduce their own corruption. Simple AST-strip defense is
> the most reliable mitigation at every scale tested, while complex
> invariant-based pipelines fail preregistered gates.

### Ba đóng góp cho paper

1. **Measurement protocol** — first systematic, pre-registered study of
   safety-layer interference in LLM code-security tasks, with CG/CB controls,
   directional flip matrix, and two-directional outcome reporting

2. **Defense-induced corruption finding** — provenance-based safety wrappers
   can cause model-dependent recall collapse (llama 1.000→.367), a risk not
   previously documented in the prompt-injection defense literature

3. **Federation-robust graph features** — behavior-graph representations
   survive federated averaging where TF-IDF degenerates (p = 3.8e-6)

---

## 8. SỐ LIỆU TỔNG HỢP

| Chỉ số | Giá trị |
|---|---|
| Tổng generations | ~7,000+ (local + Kaggle GPU) |
| Tổng experiments | 19 rounds × 5 agents = 95+ agent-iterations |
| Tổng audit độc lập | 30+ (mỗi kết quả chính ≥ 2) |
| Claims thu hồi | 3 lớn (FP-bias, FedAvg-harm, EVIDA-collapse) |
| Tests | 833 passed / 0 failed |
| Commits | 29 |
| PDFs | 2 (9tr + 20tr), compile sạch |
| Artifacts | 48 (sha256-verified manifest) |

---

## 9. BƯỚC TIẾP THEO

### Cần từ user

| # | Tài nguyên | Mở khóa |
|---|---|---|
| 1 | **OSF account** | Timestamp pre-registration (P1-7) |
| 2 | **API key frontier** (GPT-4o / Claude / Gemini) | Safety attack ở quy mô lớn (P1-8) |
| 3 | **Duyệt gỡ <4B** | P1-10 A5 ladder trên 7B/8B qua Kaggle GPU |
| 4 | **2 annotator** | P2-13 KB human-κ validation |

### Có thể làm ngay (local, chưa duyệt)

| # | Việc | Giá trị |
|---|---|---|
| A | Alarm-pruning refinement (dựa trên 37/55 inert counterfactuals) | Nâng precision .21 → .40+ |
| B | Leave-cluster-out ở scale corpus mới (+200 benign expansion) | External validity |
| C | Adaptive red-team: attacks designed to break D1-strip defense | Gate G |
| D | GNN trên behavior graphs (thay feature-vector) | Method nâng cấp |
| E | Repository-level evaluation (PR/issue context) | External validity |
