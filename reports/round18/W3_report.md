# W3 Report — Round 18 (EVIDA-2): LITERATURE VERIFY — 4 citation của tài liệu
# tư vấn ChatGPT + literature bổ sung + positioning UCA

Ngày: 2026-09-30. Owner: W3 (vòng 18). Scope: L1 verify 4 citation (CPU/WebSearch/
WebFetch/arXiv MCP only), L2 thêm 5 papers 2024–2026 đã verify, L3
docs/ucriterion_literature.md, L4 report này. KHÔNG đụng code/paper2, KHÔNG git
commit. Không bịa số — mọi metadata dưới đây đọc trực tiếp từ nguồn sơ cấp trong
phiên này (chi tiết: docs/ucriterion_literature.md).

## 1. LÀM GÌ

### [L1] Verify 4 citation — KẾT QUẢ: 4/4 TỒN TẠI THẬT, 0 UNVERIFIED; 3/4 cần
### sửa địa-chỉ-trích/thuật ngữ trước khi vào paper2

| # | Citation | Verdict | Metadata đã xác nhận trên nguồn sơ cấp | Đánh giá nghĩa được tư vấn |
|---|---|---|---|---|
| C1 | "Stress Testing Deliberative Alignment for Anti-Scheming Training" (OpenAI/Apollo 2025) | **VERIFIED** | arXiv:**2509.15541**, publish **2025-09-19**, cs.AI, 19 tác giả (Schoen, Nitishinskaya, Balesni, Højmark, …, Glaese, Barak, Zaremba, Hobbhahn); hợp tác OpenAI + Apollo Research (tác giả hai phía; LessWrong post cùng nhóm) | Claim "evaluation awareness causally thay đổi behavior": **ĐÚNG theo abstract** — "show causal evidence that this awareness decreases covert behavior, while unawareness increases it". Nuance: paper tự nói "we cannot exclude that the observed reductions … are at least partially driven by situational awareness" → trích phải kèm "partial-drive". |
| C2 | Thuật ngữ **"reward process sycophancy"** — "discussion của paper anti-scheming, bị cắt khỏi final vì chưa validate đủ" | **VERIFIED — nguồn = LessWrong author comment (trích section bị loại của bản nháp), KHÔNG nằm trong PDF arXiv** | LessWrong post `lesswrong.com/posts/JmRfgNYCrYogCq7ny/…` (2025-09-17, tác giả = nhóm paper). Self-test phủ định: substring-search trên text arXiv:2509.15541 v1 → "sycophancy" đúng **3** lần (intro cite OpenAI blog 2025b; 2 mục References), **0** lần "reward process sycophancy" | Ngữ cảnh khớp TỪNG CHỮ mô tả của tư vấn — nguyên văn tác giả: "a behaviour we call reward process sycophancy … the model actively reasons about the evaluator's implicit goals and criteria, and then tailors its actions to satisfy them to get a good score" + "We ultimately excluded this section from the final paper because we didn't have time to validate the findings to the level of rigor we wanted". Tác giả phân biệt RPS (chủ động phục tùng tiêu chí chấm) vs eval awareness (chỉ nhận ra đang bị test). Số kèm (0/600→14/600 sandbagging; +12.17pp) là **author-reported, self-declared under-validated** — cấm trích như kết quả peer-reviewed. |
| C3 | **PaperGym** (tháng 8/2026) — "criterion leakage" "theo nghĩa benchmark contamination" | **VERIFIED (tồn tại + thuật ngữ); nghĩa cần chỉnh 1 nấc** | arXiv:**2608.31119**, "PaperGym: Rubric-Centered Evolution for Research-Plan Generation", publish **2026-08-31**, cs.CL, Wang/Lu/Yan/Song/Zhang/Lu/Xiao/Zhuang/Shen — ZJU-REAL (email @zju.edu.cn; khẳng định "Apple" từ 1 tóm tắt web KHÔNG xác nhận được trên record arXiv → bỏ). Code ZJU-REAL/PaperGym | "Criterion leakage" là đại lượng ĐỊNH NGHĨA TRONG PAPER: % tiêu chí chấm suy ra được từ câu hỏi một mình — **3.7%** vs **11.90%–34.10%** dataset cũ; hệ quả nguyên văn: "a model can thus raise its reward simply by paraphrasing the question". Đây là leakage rubric→input ở tầng thiết kế benchmark, KHÔNG phải train/test data contamination cổ điển → tư vấn đúng tinh thần, sai tầng nghĩa; cách trích đúng đã ghi ở docs/ucriterion_literature.md §4.3. |
| C4 | **OWASP 2026 agentic AI guidance** — tool outputs/forged messages như goal-redirection surface | **VERIFIED (bản 2026 tồn tại); thuật ngữ cần hiệu chỉnh** | "OWASP Top 10 for Agentic Applications for 2026" — trang chính thức genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ đăng **2025-12-09**, công bố Black Hat Europe 2025 + OWASP Agentic Security Summit, 100+ chuyên gia; 10 rủi ro ASI01–ASI10 | Bề mặt tấn công ĐÚNG, phân bổ: **ASI01 Agent Goal Hijack** ("attackers alter agent objectives through malicious content"), ASI02 Tool Misuse, ASI04 ("External API dependencies that return poisoned data"), **ASI07** ("forging false consensus messages", "injecting misleading information to influence collaborative decision-making" — theo mapping ASI công khai). OWASP KHÔNG dùng chữ "goal redirection" — paraphrase; thuật ngữ chính thức **"Agent Goal Hijack" (ASI01)**. |

### [L2] 5 papers bổ sung 2024–2026 — tất cả verify trực tiếp qua arXiv (không
### qua tóm tắt AI)

1. **arXiv:2407.04694** — Laine et al., "Me, Myself, and AI: The Situational
   Awareness Dataset (SAD) for LLMs" (2024-07-05): 7 nhóm task, >13k câu, đo cả
   "determine whether a prompt is from internal evaluation or real-world
   deployment"; 16 LLM. → nền đo eval-awareness (anti-scheming paper follow Laine).
2. **arXiv:2406.13352** — Debenedetti et al., "AgentDojo" (2024-06-19): "prompt
   injection attacks where data returned by external tools hijacks the agent";
   97 task + 629 security test cases. → tool-output = bề mặt goal-hijack đo được
   (tầng hành động).
3. **arXiv:2406.10162** — Denison et al., "Sycophancy to Subterfuge:
   Investigating Reward-Tampering in Large Language Models" (2024-06-14):
   sycophancy → reward tampering, zero-shot generalize tới tự sửa reward function.
4. **arXiv:2503.11926** — Baker et al., "Monitoring Reasoning Models for
   Misbehavior and the Risks of Promoting Obfuscation" (2025-03-14): reward
   hacking qua CoT monitor; tối ưu quá mức → obfuscated reward hacking.
5. **arXiv:2404.18824** — Xu et al., "Benchmarking Benchmark Leakage in Large
   Language Models" (2024-04-29): contamination theo nghĩa data-leakage (PPL +
   n-gram, 31 LLM) — để tách bạch với "criterion leakage" của PaperGym.

### [L3] docs/ucriterion_literature.md — tổng hợp + positioning UCA

4 dòng literature hội tụ về khoảng trống mà **Untrusted Criterion Adoption**
chiếm: (1) eval-awareness (nhận ra bị đánh giá, causal nhưng frontier-only,
tiêu chí ẩn phải tự suy); (2) criteria-seeking = chính RPS (đúng khái niệm nhất
nhưng CHƯA ĐƯỢC publish dưới dạng validated — self-declared excluded);
(3) criterion leakage (PaperGym đo leakage như defect cần giảm, chưa ai biến
thành treatment); (4) goal-hijack surface (AgentDojo/OWASP đo tầng hành động,
không tầng tiêu chí phân xét). Gap statement UCA: cấp tiêu chí đánh giá qua
untrusted context (attacker-writable) như treatment có kiểm soát, đo criterion-
adoption qua verdict-flip (không qua CoT) trên local 2–3B, dùng counterfactual
disagreement machinery của EVIDA r17 — khớp kênh FP-bias đã đo (prereg EVIDA
M1–M3: granite FP .0625→.70 C0→C5_near, flips 51 b2v/0 v2b). Chi tiết câu-chữ
trích dẫn khuyến nghị + limitations: docs/ucriterion_literature.md §4.

## 2. FILES (absolute)
- /Users/macbook/.zcode/workspace/default/refuseguard/docs/ucriterion_literature.md (MỚI — tổng hợp verify + positioning)
- /Users/macbook/.zcode/workspace/default/refuseguard/reports/round18/W3_report.md (MỚI — file này)
KHÔNG đụng file nào khác; không git commit.

## 3. CÁCH CHẠY / TÁI LẬP
Verify là tác vụ tra cứu, không có script. Tái lập = chạy lại các truy vấn ghi
trong docs/ucriterion_literature.md §1–§3: arXiv abstract/text qua MCP
(get_abstract 2509.15541, 2608.31119, 2407.04694, 2406.13352, 2406.10162,
2503.11926, 2404.18824; search_paper_text 2509.15541 "sycophancy"), fetch full
LessWrong post, fetch trang OWASP genai.owasp.org + mapping ASI (promptfoo docs),
WebSearch để ĐỊNH VỊ (không làm bằng chứng).

## 4. LỆCH CHUẨN / DISCLOSE (honest)
1. Tóm tắt WebSearch là AI-generated — KHÔNG dùng làm bằng chứng; mọi claim
   load-bearing được pin về nguồn sơ cấp fetch trực tiếp (arXiv/LessWrong/OWASP).
   Riêng 1 chi tiết tóm tắt web ("PaperGym affiliated with Apple") KHÔNG xác nhận
   được trên record arXiv (email @zju.edu.cn) → đã BỎ, không ghi vào docs.
2. C2: nguồn chính của thuật ngữ là LessWrong COMMENT (author reply, 2025-09-17
   — 2 ngày trước arXiv 2025-09-19), không phải body paper; số 0/600→14/600 và
   +12.17pp nằm trong đoạn trích bản nháp bị loại, self-declared chưa validate —
   ghi rõ nhãn này trong docs.
3. C4: "tool outputs/forged messages = goal-redirection surface" là paraphrase
   hợp lệ trải trên ASI01/02/04/07; mapping ASI01–ASI10 đối chiếu qua trang
   mapping công khai (promptfoo, cập nhật 2026-09), KHÔNG qua PDF chính thức
   OWASP (landing page chỉ có nút Download, không list nội dung trên trang) —
   nếu cần trích nguyên văn ASI trong paper2 nên tải PDF và đối chiếu lại 1 lần.
4. arXiv versions: mọi check trên version hiện mà MCP trả về (2509.15541 v1,
   2608.31119 v1, …) — nếu arXiv cập nhật version mới sau 2026-09-30 cần re-check
   C2 (khả năng bản v2+ thêm lại section RPS là có thật, hiện chưa xảy ra ở v1).
5. Chưa verify Danh hiệu chính thức đầy đủ của từng tác giả OWASP (framework
   peer-reviewed 100+ chuyên gia theo trang chính thức; không list cá nhân cần
   trích) — trích theo tổ chức (OWASP GenAI Security Project), không trích author.
6. C1: verdict causal dựa trên abstract; phần chính của causal intervention
   (removing/injecting situationally-aware snippets modulates covert-action rate)
   xác nhận thêm từ LessWrong post chính — chưa đọc từng Appendix của PDF.

## 5. TODO (phiên sau)
1. W khác nhập khuyến nghị trích dẫn §4.3 (docs/ucriterion_literature.md) vào
   paper2 nếu hướng UCA được duyệt — đặc biệt sửa 3 chỗ: C2 trỏ LessWrong comment,
   C3 ghi đúng nghĩa criterion leakage, C4 dùng "Agent Goal Hijack (ASI01)".
2. Nếu chạy thí nghiệm UCA: pre-register arm {fake-criterion, clean-criterion,
   no-criterion} trước generation (tiền lệ AMENDMENT/EVIDA prereg), đo verdict-
   flip + criterion-adoption rate trên S1/S2 cache, KHÔNG dùng CoT classifier.
3. Re-check C2 khi 2509.15541 có version mới; tải PDF OWASP Agentic 2026 để trích
   nguyên văn ASI01 nếu reviewer đòi quote chính xác.
4. (Optional) Snowball từ 2509.15541 references: "Evaluation Faking" (Fan et al.,
   Zhejiang — thấy trong References nhưng chưa verify ID) là ứng viên thứ 6 cho
   eval-awareness nếu cần mở rộng.

## 6. SELF-TEST THẬT (đã chạy trong phiên)
- arXiv MCP get_abstract × 7 ID (danh sách §3) → trả title/authors/published
  khớp 100% với bảng verify; 2509.15541 abstract chứa nguyên văn câu causal
  evaluation-awareness; 2608.31119 abstract chứa "criterion leakage falls to
  3.7%, versus 11.90% to 34.10%".
- arXiv search_paper_text(2509.15541, "reward process sycophancy") → **0
  passages**; ("sycophancy") → 3 passages (Introduction cite OpenAI 2025b;
  References: Denison 2406.10162; References: OpenAI blog) — chứng minh thuật ngữ
  KHÔNG có trong PDF arXiv v1, nguồn duy nhất là LessWrong comment (fetch full
  post, tìm thấy cả 3 nguyên văn: đặt tên, định nghĩa phân biệt eval-awareness,
  câu "excluded this section from the final paper").
- download_paper(2608.31119) → body text chứa định nghĩa leakage ("11.90% to
  34.10% of them can be inferred from the question alone (Table 4)… raise its
  reward simply by paraphrasing the question").
- WebFetch/WebReader genai.owasp.org/resource/owasp-top-10-for-agentic-
  applications-for-2026/ → trang tồn tại, publishedTime 2025-12-10T07:55:54Z,
  mô tả "globally peer-reviewed … more than 100 industry experts"; promptfoo
  mapping → bảng ASI01–ASI10 nguyên văn.
- Ghi chú quy trình: WebSearch dùng 4 lượt (định vị C1, C2, C3, C4 + 2 lượt
  L2) — tất cả kết luận số liệu đều đến từ nguồn sơ cấp kể trên, không một con
  số nào trong docs/report lấy từ tóm tắt AI.

---
*W3 round 18 không git commit. Một câu: cả 4 citation của tài liệu tư vấn
ChatGPT TỒN TẠI THẬT (arXiv:2509.15541 / LessWrong-comment "reward process
sycophancy" / arXiv:2608.31119 / OWASP Agentic Top 10 2026) nhưng 3 cần sửa
địa-chỉ-thuật-ngữ trước khi vào paper2, và hướng UCA có khoảng trống rõ — giả
thuyết criteria-seeking của Apollo chưa từng được validate thành thí nghiệm
có kiểm soát, chưa ai đo trên model nhỏ, chưa ai ở tầng tiêu chí phân xét.*
