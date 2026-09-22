# Literature refresh 2026 — (demand: "tham khảo paper 2026, research trên model <4B")

Ngày: 2026-09-21. Nguồn: WebSearch (Z.ai web_search_prime); arXiv MCP lỗi HTTP 406
trong phiên này. Mọi entry cần verify kỹ trước khi vào refs.bib chính thức (một số
link là trang chủ/industry, không phải peer-reviewed).

## A. Paper / tài nguyên 2025-2026 liên quan trực tiếp

| # | Entry | Loại | Ý nghĩa cho bài |
|---|---|---|---|
| A1 | **Phoenix Security Malware Package Intelligence (MPI) corpus** — 59 supply-chain attack campaigns, 6/2024–6/2026 (phoenix.security) | Industry corpus | **Cơ hội dataset cho PackGuard**: mở rộng ngoài 603 samples DataDog, có nhãn campaign 2024-2026 (fresh attacks). Cần probe license/quy cách trước |
| A2 | **TeamPCP campaign** — LiteLLM & Telnyx PyPI malicious releases 3/2026 (Datadog Security Labs) | Incident | Motivation/fresh-attack case study; test biến thể mới của KB |
| A3 | **Axios npm compromise** 3/2026 (Zscaler/RapidFort — account takeover) | Incident | Chứng minh threat model "compromised_lib" (đúng lớp label ta đã dùng) còn nóng |
| A4 | **EMPHunter** — W. Liang, 2025, IEEE (PyPI+NPM malicious package detection) | Paper | Related work MỚI cho paper2 (bảng 2.1) — cần verify chi tiết venue |
| A5 | **Jalan et al. 2026 — Survey LLM Safety: Attacks, Defenses, Alignment, Metrics** (ACM/Springer) | Survey | Related work cho cả 2 bài (safety-alignment side); cite như survey 2026 |
| A6 | **Safety Misalignment Against LLMs** — Gong et al., NDSS | Paper | Measurement framework cho safety misalignment — so sánh measurement approach |
| A7 | **FL-LTD** — Bhaskar 2026, arXiv (robust FL against malicious clients, loss-trend detection) | Paper | Related work FL-robustness; mở hướng mở rộng: poisoned-client defense trong FL của ta |
| A8 | "A Framework for Evading LLM Safety Alignment" (11/2025, arXiv) | Paper | Related work — evasion của refusal; khác hướng của ta (ta đo interference trong defensive task, không evade) |

## B. Kết luận novelty sau refresh

1. **Không tìm thấy paper nào đo safety-layer interference (blocking/verdict-corruption/
   defence-harm) trong malicious-package detection** → gap novelty của bài gộp vẫn mở
   sau refresh 2026. Claim giữ với hedge "to our knowledge (as of 2026-09)".
2. **Dataset mới (A1)** là leverage mạnh nhất: nhãn campaign đến 6/2026 giúp trả lời
   objection "model chỉ học từ dữ liệu cũ" (đúng痛点 của proposal gốc) — khuyến nghị
   round sau: probe MPI corpus, sampling 100-200 samples campaign-fresh.
3. **FL-LTD (A7)** gợi ý ablation mới: malicious-client defense trong FL simulation
   (1 client gửi gradient độc) — tăng chiều sâu FL program nếu reviewer hỏi.

## C. Ràng buộc mới: MODEL <4B (directive user 2026-09-21)

- Toàn bộ research tiếp theo chỉ dùng model <4B: **Qwen2.5-Coder-3B, Llama-3.2-3B,
  granite-3.3-2b, Qwen2.5-Coder-0.5B (smoke)**. Không 7B/8B.
- Đã dọn 2 model lớn: Llama-3.1-8B (16.08GB — NOT_FEASIBLE MPS 32GB, chứng minh
  Vòng 9: SIGSEGV ×2 + RSS 43.7GB thrash) và Qwen2.5-Coder-7B (15.24GB — kết quả
  RQ9 đã chốt trong round7_master, không cần weights). Giải phóng ~31GB
  (disk 7GB → 37GB free). CodeBERT (1GB) + checkpoint fine-tune giữ nguyên (B4/fallback
  của paper 1, <4B).
- Hệ quả khoa học: **scale-question của RQ9 khép ở "2-3B only, qwen-family confound
  disclosed"** — không đuổi thêm 8B; nếu reviewer đòi scale → ghi future work
  (MLX 4-bit / GPU cloud).

## D. Việc pending (khi user resume)

- F-R9 (bị hủy): sửa diễn giải safety trong paper2 theo V1 (fp_bias = TP-rate trên
  malicious — "every benign package flagged" là SAI), thêm multi-seed/KB-universe/
  8B-feasibility, compile lại.
- Dataset expansion: probe MPI corpus (A1) — ưu tiên cao vì tăng fresh-attack validity.
- granite-3.3-2B ladder (family thứ 3, matched-scale, in-stack — V2 khuyến nghị, ~45').
