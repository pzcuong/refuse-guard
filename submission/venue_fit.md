# Venue Fit — RefuseGuard (Paper 1) & PackGuard (Paper 2)

Ngày soạn: 2026-09-28 (W2, vòng 15). Nguồn: `docs/literature_review.md` §5
(novelty verdict Paper 1), `docs/packguard_literature.md` (verified related
work cho Paper 2), nội dung 2 bản thảo đã compile
(`submission/RefuseGuard_ms.pdf` 20 tr, `submission/PackGuard_ms.pdf` 8 tr).
**Không có acceptance rate nào được nêu** — không có nguồn trong repo; mọi
nhận định scope dựa trên aims-&-scope công khai của từng venue (kiểm tra
lại trên trang venue trước khi nộp).

## 1. So sánh 4 venue với 2 bài

| Venue | Scope typology (theo aims & scope công khai) | Fit Paper 1 (RefuseGuard, 20 tr) | Fit Paper 2 (PackGuard, 8 tr) |
|---|---|---|---|
| **Computers & Security** (Elsevier) | An ninh ứng dụng: measurement, attack/defense, AI/ML security, supply-chain | Cao: LLM-safety trong security analysis là đúng trục "AI security measurement"; E0-gate FAIL → pivot được bán như boundary-condition finding | Cao nhất: malicious-package detection + attack-surface measurement + defense là lõi an ninh ứng dụng; GuardDog/DONAPI/Cerebro đều là baseline cùng trục |
| **IEEE TDSC** | Dependability + security, thiên archival, đóng góp nền tảng/khung đánh giá chặt | Trung bình-cao: khung đo 3 kênh (blocking, corruption, defence-harm) có tính hệ thống; nhưng pilot 2–3B trên MPS có thể bị hỏi về scale | Trung bình: TOST + corrected baseline là điểm cộng phương pháp luận; FL là simulation (disclosed) + pilot 603 mẫu — TDSC thường đòi độ trưởng thành cao hơn |
| **TOSEM** (ACM TOSEM) | Phương pháp SE + empirical; LLM4SE đang mở rộng; tiền lệ trực tiếp: **Cerebro (baseline gần nhất của Paper 2) đăng TOSEM 2024** (verified trong `docs/packguard_literature.md`) | Trung bình: vulnerability detection là bài toán SE, nhưng headline của bài là safety/robustness measurement chứ không phải method SE mới | Cao: detector supply-chain + behavior-graph + evaluation protocol khớp dòng "SE tool + empirical evaluation"; cần reframe nhẹ "security measurement" → "SE technique + empirical study" |
| **EMSE** (Springer) | Empirical SE: measurement study, replication, **negative result được đón nhận** | Cao: E0 FAIL→pivot + retraction có kiểm soát + audit trail đúng khẩu vị empirical study; LLM4SE empirical | Cao: negative results (LCO null hai chiều, mechanism ablation null-low-power, GuardDog "comparable not superior", KB neutral) được trình bày first-class; cần reframe tương tự TOSEM |

## 2. Khuyến nghị thứ tự nộp

### Paper 2 — PackGuard (nộp TRƯỚC; bài mới hơn, cô đọng, mọi claim đã audit)
1. **Computers & Security** — fit topic cao nhất (applied security
   measurement + attack/defense), không ép khung SE; bản sigconf 8 trang
   đủ nội dung cho 1 bài journal (nên mở rộng nhẹ phần setup khi convert
   sang format single-column).
2. **TOSEM** — tiền lệ trực tiếp Cerebro TOSEM 2024; nếu chọn TOSEM phải
   đổi framing sang "SE technique + empirical evaluation" và đẩy phần
   behavior-graph/detector lên trước phần safety.
3. **EMSE** — nếu muốn giữ nguyên cách trình bày trung thực về pilot scope
   + negative results mà không reframe lớn.
4. **TDSC** — khả thi nhưng yếu nhất ở trạng thái hiện tại (simulation-only
   trust mechanisms + 2–3B ceiling); cân nhắc sau khi có thêm scale/family.

### Paper 1 — RefuseGuard (nộp SAU Paper 2, xem ràng buộc ở §3)
Theo verdict của `docs/literature_review.md` §5: claim hợp lệ là
"first systematic joint evaluation" **scoped** cho LLM-based vulnerability
analysis (không phải "first to observe defensive refusal" — 2603.01246 sở
hữu; không phải "first IPI-in-code defense" — 2606.19235/BIPIA sở hữu).
Đó là một **measurement study có pivot được pre-register** →
1. **Computers & Security** — chỉ sau khi Paper 2 được quyết định (không
   nộp 2 bài đồng dòng cùng venue cùng lúc, xem §3).
2. **EMSE** — fit tốt nhất với tính chất "empirical measurement + negative
   result + pre-registered fallback"; ít xung đột chủ đề với Paper 2.
3. **TDSC** — nếu muốn venue an ninh archival; cần chống answer cho câu
   "tại sao chỉ 2–3B" (đã có Appendix feasibility, nhưng venue có thể đòi
   thêm family thứ 4).
4. **TOSEM** — như EMSE nhưng nhấn method; một phần nội dung (defence
   ladder) có thể bị xem là ngoài phạm vi method-SE truyền thống.

## 3. Ràng buộc giữa 2 bài (disclosed)
- Paper 2 cite Paper 1 (`refuseguard2026`) như "a prior vulnerability-domain
  measurement study". Nếu cả 2 bài đang under review cùng lúc ở cùng venue,
  reviewer có thể flag dual-submission/self-plagiarism — **nộp lệch venue
  hoặc lệch thời điểm** (khuyến nghị: Paper 2 trước, Paper 1 nộp venue khác
  hoặc sau khi Paper 2 có quyết định).
- Overlap thật giữa 2 bài chỉ nằm ở 2 điểm đã disclosed trong Paper 2:
  vocabulary DRB (Campbell et al.) và granite ladder vulnerability-domain
  (Appendix A.7, dùng làm by-domain contrast) — không có bảng/số trùng.

## 4. Việc cần làm trước khi nộp (chung)
- Đọc lại aims & scope + page/format policy của venue đích trên trang chính
  thức (tài liệu này cố tình không chép số).
- Paper 2: mở rộng nhẹ khi convert journal format (hiện 8 trang sigconf;
  journal thường cho phép dài hơn — phần setup/appendix có thể nhập vào
  thân bài).
- 3 prerequisite BLOCKED-by-user chưa xong không chặn nộp bài nhưng chặn
  artifact-review track: OSF timestamp, frontier-API consult, KB human-κ —
  xem `SUBMISSION.md` §trạng thái.
