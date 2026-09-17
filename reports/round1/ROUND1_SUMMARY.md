# ROUND 1 — TỔNG KẾT CHO USER: AI SAI / AI BẮT ĐƯỢC / ĐÃ SỬA CHƯA

Ngày: 2026-09-18. Vòng 1: 3 tác nhân chính (A1 data+protocol, A2 models+metrics,
A3 conditions+defenses+runners) → 2 kiểm lỗi (V1 adversarial số liệu/citation,
V2 tích hợp chạy-chéo) → S (tổng hợp, sửa lỗi).

## Bảng "AI SAI / AI BẮT ĐƯỢC / ĐÃ SỬA CHƯA"

| # | AI sai | Lỗi gì | Ai bắt được | Đã sửa? |
|---|---|---|---|---|
| 1 | A3 | **[CRITICAL]** 65% sample PrimeVul là C++ nhưng toàn bộ stack hard-code grammar `c` → C2/C3/P1 fail hàng loạt, **6/9 runner crash** khi nối manifest thật; claim "e0–e8 dry-run không lỗi" chỉ đúng trên corpus giả | V2 | ✅ S (auto grammar c→cpp mọi nơi parse; runner skip-disclosed thay vì crash; 9/9 runner OK; parse coverage 34.9%→74.6%) |
| 2 | A3↔A1 | **[HIGH]** Schema results.json (`y_true/y_pred`) ≠ hợp đồng metrics (`label/vulnerable`) → `compute_metrics` trả **0 im lặng**; hook bỏ `cwe/location` → UAC undercount (e3 báo `uac 0.5` sai, đúng phải 1.0) | V2 | ✅ S (canonical = y_true/y_pred + normalize alias + raise khi thiếu trường bắt buộc; hook truyền cwe/location; e3 uac 0.5→1.0) |
| 3 | A3 | **[HIGH]** E2 "neutral vs defensive" nhưng **thiếu hẳn arm neutral** — neutral_prompt nằm chết trong meta | V2 | ✅ S (`framings: [neutral, defensive]`; records ghi `meta.framing`; e2 = 120 records, 2 arm) |
| 4 | A2 | **[CAO]** `vd_s()` KHÔNG phải VD-S của PrimeVul (thật: FNR@FPR≤0.5%); report A2 xác nhận nhầm "giữ nguyên là được" | V1 | ✅ S (implement VD-S chính thức; hàm cũ đổi tên `paired_rank_*`; test case tính tay) |
| 5 | A1 | **[CAO]** refs.bib sai tác giả 5 entry (2 entry sai TOÀN BỘ: han2023howfar, liu2024autopi) dù claim "verify toàn bộ" | V1 (query arXiv API) | ✅ S (5 entry sửa đúng + note [CORRECTED]; literature_review "Han et al."→"Gao et al.") |
| 6 | A1 | **[CAO]** Khuyến nghị max_seq_len=1024 cho CodeBERT — vô thực (cap cứng 512, max_position_embeddings=514) | V1 | ✅ S (transformer truncate head+tail @512; docs/eda thêm khối [CORRECTED], không xoá nội dung gốc) |
| 7 | A2 | **[TB]** `is_usable` bỏ qua status → REFUSAL kèm `vulnerable:0` bị đếm usable → UAC 0.8 thay vì 0.6 | V1 | ✅ S (REFUSAL không bao giờ usable + regression test đúng case V1) |
| 8 | A2 | **[TB]** Refusal monitor bỏ lỡ 3 lớp refusal thật ("I won't be able to", "should not help", tiếng Việt) → undercount RR (chính là endpoint E0) | V1 | ✅ S (thêm patterns + ràng buộc lexical_floor ≥0.2 khi fit; 3 case V1 → REFUSAL; 0 FP trên XSTest safe) |
| 9 | A1 | **[TB]** `subset_records` mất vulnerable member của pair (dict ghi đè) + runner manifest 300/300 vul có `pair_id=None` → không tính được paired eval | V1 | ✅ S (giữ cả 2 member; backfill pair_id; regenerate 2 manifest cùng seed; 236/236 pair join đủ) |
| 10 | A2 | **[TB]** LLM harness không truncation input (hàm 484k chars → crash/OOM thay vì cắt) | V1 | ✅ S (`max_input_tokens` config + head+tail truncate trước cache-key + meta disclosure; test tokenizer giả) |
| 11 | A1 | **[TB]** E0 calibration nuốt 100% contrast set (250/250) — mâu thuẫn chính nguyên tắc "calibration không trùng scoring" do A1 tự đặt | V1 | ✅ S (disjoint 50/50 split seed+3 trong manifest; data_e0.yaml calibration/scoring tách; cal ∩ scoring = ∅) |
| 12 | A3 | **[MED]** P1 im lặng bỏ defense khi comment chứa `*/` (`_sanitize_comment_text` dead code) → LLM nhận code thô không ai biết | V2 | ✅ S (gọi sanitize trong đường dẫn thật; neutralize `*/`; test pass gate) |
| 13 | A3 | **[MED]** Intent gate trượt prompt độc thật ("write ransomware" không bị chặn); e8 thật: P2 unsafe_compliance = 1.0 = B0 | V2 | ✅ S (bổ sung patterns theo họ tấn công; 4/4 prompt toxic e8 bị chặn, 0 FP trên 250 XSTest safe; e8 mock: P2 0.0 vs B0 1.0 — plumbing only) |
| 14 | A3 | **[MED]** results.json không ghi nguồn corpus → run mock/giả khó phân biệt run thật bằng metadata | V2 | ✅ S (`metadata.corpus_source` mọi runner + e8) |
| 15 | A1+A2 | **[LOW]** Bare `pytest` crash vì collect nhầm `src/models/smoke_test.py`; e8 8/16 record hứa `raw_output_path` nhưng file không tồn tại | V1+V2 | ✅ S (pytest.ini testpaths=tests; e8 luôn ghi file thật → 0/16 thiếu) |
| 16 | A3 | [LOW] C1 pin template không tồn tại → StopIteration; P1 chọn sink đầu thay vì sink nặng nhất; frame_05 "neutral" còn chữ "exploitable" | V2 | ❌ Chưa (không thuộc danh sách fix bắt buộc; ghi khuyến nghị Round 2) |
| 17 | A2 | [LOW] transformer_baseline: best_mcc lưu giá trị cũ, OOM-fallback quá rộng, predict không checkpoint dùng head random, grad_accum batch cuối, roc_auc crash 1-lớn… | V1 | ❌ Chưa (không thuộc danh sách bắt buộc; khuyến nghị Round 2) |
| 18 | A1 | [MED] E0 slice "first 100 by sorted sample_id" lệch project (tensorflow 49%) | V1 | ❌ Chưa (không thuộc danh sách bắt buộc; khuyến nghị Round 2) |
| 19 | S (tự bắt) | Lỗi phát sinh khi sửa: bản draft `load_samples` làm rơi tham số `limit` (e0 ra 3340 records thay vì 32); `raw_output_path` crash khi out-dir ngoài repo; C0 bị nhân đôi theo framing | S tự kiểm bằng dry-run | ✅ Đã sửa + re-run |

**Không ai bịa số liệu**: mọi self-test của A1/A2/A3 được V1/V2 tái lập được
từng chữ số; các vấn đề nằm ở verification citation, định nghĩa metric và
việc không chạy lại trên dữ liệu thật — không phải gian lận số.

## 5 dòng tổng kết sức khỏe dự án

1. **Pipeline hiện CHẠY ĐƯỢC trên dữ liệu thật**: 9/9 runner dry-run exit 0 với
   manifest PrimeVul thật (trước S: 6/9 crash ngay mẫu đầu); parse coverage
   34.9% → 74.6%, phần còn lại được skip-disclosed thay vì crash.
2. **Metrics giờ đáng tin**: schema khớp 2 chiều + raise khi thiếu trường
   (không còn 0 âm thầm), REFUSAL không thể đội lốt usable, UAC e3 từ 0.5 sai
   hệ thống về 1.0 đúng, VD-S đúng chuẩn PrimeVul (FNR@FPR≤0.5%).
3. **Trusty/provenance**: manifest có calibration/scoring disjoint (nguyên tắc
   E0 giờ thật sự đúng), corpus_source trong mọi results.json, pair join
   236/236, citation 5 entry đã sửa + correction notes trong docs.
4. **Safety plumbing có tín hiệu thật đầu tiên nhưng CHƯA phải kết quả**:
   gate bắt 4/4 prompt toxic e8 (mock), chưa chạy model thật nào — E0
   reproduction gate với ≥2/3 model vẫn là điều kiện bắt buộc trước mọi claim
   refusal (pivot clause vẫn còn hiệu lực nếu ΔRR < 0.10).
5. **Đã liên hoàn: 237/237 test pass** (≥216 yêu cầu), gồm 21 test mới chặn
   tái phát đúng các bug V1/V2 bắt được; các lỗi LOW/MED chưa thuộc danh sách
   bắt buộc được liệt kê minh bạch trong reports/round1/S_report.md §4 kèm
   khuyến nghị Round 2 theo 3 góc (data / models / experiments).
