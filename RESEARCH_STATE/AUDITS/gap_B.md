# GAP AUDIT B — gap-challenger-B · 2026-09-30

**LENS (khác challenger A):** coi gap KHÔNG tồn tại; nhiệm vụ = tìm **paper phản ví dụ cụ thể nhất (2024-2026)** chứng minh gap đã bị lấp. Tìm thấy → verdict `accepted=false` kèm paper; không tìm thấy sau search kỹ → `accepted=true`.

---

## 1. Gap bị thách thức (nguồn trong repo)

- `RESEARCH_STATE/DECISION_LOG.md:35` (DLOG-001 NEXT_STATE): gap-question = **"adaptive robustness của D1-strip và baseline defense hiện đại reproduce-được"**, scouts nhập từ NEG-39.
- `RESEARCH_STATE/NEGATIVE_RESULTS_LEDGER.csv:40` (NEG-39): "no adaptive red-team round (C5 is static query-relevant advisory)" — planned-but-NOT-RUN.
- `RESEARCH_DIRECTOR_PROMPT.md:165,200-204`: Q1 gate **G ADAPTIVE ROBUSTNESS (defense-aware attack evaluated)** + backlog **R-B**: "red-team agent generates advisory variants that D1 does NOT strip (payload moved into identifiers/strings/docstring-shaped code comments that survive the strip)".
- Đối tượng phòng vệ: `POSITIVE_RESULTS_LEDGER.csv:18` (POS-17) — **D1 AST-strip** (comment/docstring strip, AST-equivalence gated; strip(P2)==strip(original) 38/38; granite 4/4 flips revert, FP 0).

Phát biểu ngắn của gap như challenger B hiểu nó: *"chưa ai đánh giá D1-strip (họp lớp strip/sanitize comment trong LLM vuln/package analyzer) dưới attack thích ứng (defense-aware), và thiếu baseline defense hiện đại reproduce-được trong domain này."*

## 2. Giao thức search (đã chạy thật trong session này)

Công cụ: arXiv API (MCP `arxiv`: `search_papers`, `get_abstract`, `download_paper`, `search_paper_text`), lớp thứ hai `academic-research.find_paper` (Semantic Scholar/OpenAlex), grep cục bộ trên CSV ledger/matrix.

| # | Truy vấn (đúng chuỗi đã chạy) | Biên ngày | Kết quả chính |
|---|---|---|---|
| S1 | `ti:"adaptive attacks" AND "prompt injection" AND defenses` (cat cs.CR, cs.CL) | 2024-01-01→2026-09-30 | 2503.00061; **2510.09023**; 2510.09462 |
| S2 | `"prompt injection" AND ("code comment" OR "comments" OR "package") AND defense sanitization LLM code` (cs.CR, cs.SE, cs.CL) | 2024-01-01→2026-09-30 | **2606.19235 (CodeSentinel)**; 2407.09164 (ShadowCode); 2602.10498; 2605.12233 |
| S3 | `adaptive OR "defense-aware" attacks sanitizer OR "comment stripping" OR "AST" prompt injection code LLM vulnerability detection` (cs.CR, cs.SE) | 2024-06-01→2026-09-30 | **2607.24964 (ALIBI)**; 2503.00061; 2507.05630; 2511.10720; … |

Verify chéo: `get_abstract` + `download_paper` (đọc HTML full-text từng phần) cho 2503.00061 và 2607.24964; `find_paper("arXiv:2607.24964")` resolve thành công ở lớp Semantic Scholar (title/authors khớp). Grep `LITERATURE_MATRIX.csv` (75 paper): `2503.00061` **có** (row "Adaptive Attacks Break Defenses…"); `ALIBI|24964` = **0 hit**, `CodeSentinel|19235` = **0 hit**, `2510.09023` = **0 hit** → 3 paper nguy hiểm nhất đều ngoài matrix hiện tại.

## 3. PHẢN VÍ DỤ CHÍNH (most specific counter-example)

> **ALIBI: Adaptive Agentic Attacks on LLM-Based Vulnerability Detectors via Adversarial Code Comments** — Zixuan Wu, Cristina Nita-Rotaru, **arXiv:2607.24964, published 2026-07-27** (cs.CR).

Các trích dưới đây đọc trực tiếp từ HTML full-text arXiv (download_paper v1) — không phải đoán:

1. **Domain trùng khít PackGuard**: "security-sensitive tasks such as **vulnerability detection and code review** … adversarial comments that can influence a detector's reasoning **without changing program behavior**" — đúng kênh natural-language (comment) mà D1 strip; detector yêu cầu "support interprocedural C/C++ null-pointer detection (CWE-476), **expose developer comments to the LLM**".
2. **Adaptive đúng nghĩa R-B**: "an automated **adaptive** black-box attack framework that generates and **iteratively refines** adversarial comments using **detector reasoning and feedback**" — red-team có feedback từ detector, đúng lớp attack NEG-39 liệt kê chưa chạy; có baseline **non-adaptive** để so sánh ("attacks exploit a common comment trust prior… adaptive refinement further increases attack success").
3. **Đánh giá defense DƯỚI adaptive attack**: "prompt-level defenses provide **limited robustness against adaptive attacks**, whereas architectural isolation and **pre-detector comment sanitization** substantially improve resilience". Defense set của họ (§4.5): D1 prompt trust-policy, D2 code-first reasoning, D3 architectural isolation trên "**comment-stripped code**" (đọc nguyên văn: "a prior analysis produced in a separate detector call on the comment-stripped code"), **D4 pre-detector comment sanitization** (LLM classify verifiable/unverifiable rồi remove) — D4 "consistently achieves the strongest protection across all four systems". → Họp lớp phòng vệ của D1 (comment strip/sanitize) đã được đem ra đo dưới attack thích ứng, trong chính domain vuln detection.
4. **Modern baselines reproduce-được**: 4 detector đại diện có code công khai (OpenVul Qwen3-4B fine-tuned; VulnLLM-R Qwen2.5-7B; Vul-RAG GPT-4o-mini; VulTrial GPT-4o multi-agent), attacker model Qwen3.6-27B-FP8, benchmark 125 real-world CWE-476 vulns từ vulnerability-fixing commits, generalizes to use-after-free; ASR > 90% mọi system, 100% trên một system.
5. **Thậm chí đã thảo luận blanket-strip**: "We do not consider removing all comments a viable defense, as prior work shows they improve LLM-based vulnerability detection" — tức utility-cost của full comment removal (đúng trade-off llama của POS-17/NEG-26) đã nằm trong lập luận của paper.

## 4. Phản ví dụ bổ trợ (cùng lấp 2 nửa của gap)

- **Zhan, Fang, Panchal, Kang — "Adaptive Attacks Break Defenses Against Indirect Prompt Injection Attacks on LLM Agents", arXiv:2503.00061 (2025-02-27)**. Đã có trong LITERATURE_MATRIX (row "Adaptive Attacks Break…"). Đọc full-text: 8 IPI defenses (fine-tuned detector, LLM detector, perplexity filter, instructional prevention, data-prompt isolation, sandwich prevention, **paraphrasing** = lớp input-transformation mà D1 thuộc, adversarial finetuning) — **tất cả bị bypass** bởi GCG/M-GCG/AutoDAN/two-stage GCG, white-box, ASR > 50%; code công khai (github.com/uiuc-kang-lab/AdaptiveAttackAgent). → nửa "adaptive robustness evaluation" đã có charter + tooling reproduce-được từ 02/2025.
- **Nasr, Carlini, Sitawarin, …, Tramèr — "The Attacker Moves Second", arXiv:2510.09023 (2025-10-10)**: adaptive attackers (GD/RL/random/human-guided) **bypass 12 defenses** jailbreak+prompt-injection, ASR > 90% với đa số, trong khi đa số defense gốc báo ~0 ASR. → chuẩn đánh giá gate-G đã được nền literature đặt sẵn.
- **Cheng et al. — "CodeSentinel: A Three-Layer Defense Against Indirect Prompt Injection in Code Contexts", arXiv:2606.19235 (2026-06-17)**: sanitizer inference-time dùng **Tree-sitter** trích high-risk CST nodes (comments, strings, identifiers, decoy code) rồi remove/neutralize trước Code LLM; so sánh với **CodeGarrison, DePA, KillBadCode** (0.80 node-level F1). → nửa "baseline defense hiện đại reproduce-được" cho code-context đã có cả họ baseline; Tree-sitter-strip đã bị chiếm chỗ.

## 5. Điều ALIBI (và các paper trên) KHÔNG phủ — ghi lại để tổng hợp viên dùng

1. Không đánh giá **D1 của project** (byte-provable AST-equivalence-gated strip làm standalone defense, giao thức paired P0/P2/P2D1 trên PrimeVul): không ai có thể — defense của project chưa public. ALIBI dùng strip bên trong D3 (isolation) và D4 là sanitize chọn lọc bằng LLM-judge, không phải full-strip AST-gated.
2. ALIBI đánh attack hướng **làm detector MISS vuln thật** (CWE-476/UAF, code do agent sinh mới); PackGuard đánh attack **recall-perturbing trên package thật** (granite .667→.833 up / llama .167→.042 down) — hướng result khác, chưa bị phủ định số-liệu.
3. ALIBI không đo **defense-induced error trên clean code** theo nghĩa DRR/CUL hai chiều preregistered của project (§4.5 chỉ báo hierarchy hiệu quả phòng vệ) — đây là phần khác biệt hóa còn lại *nếu* project muốn giữ R-B, nhưng không cứu được gap như một **research gap**.
4. Chưa đọc/extract số Table 5 của ALIBI, chưa truy nguồn dataset gốc 125 commit (paper không nhắc PrimeVul — 0 hit khi search trong full-text); venue/citation (cited_by=0 tại 2026-09-30) chưa xác định.

## 6. VERDICT

**accepted = false** — gap **KHÔNG tồn tại** ở mức nghiên cứu: phản ví dụ cụ thể nhất là **ALIBI (arXiv:2607.24964, 07/2026)** — adaptive agentic attack qua adversarial code comments lên LLM-based vulnerability detectors, kèm đánh giá defense lớp comment-strip/sanitization (D3 comment-stripped code, D4 pre-detector sanitization = strong nhất) và 4 modern detector baselines reproduce-được. Bổ trợ: Zhan 2503.00061 (8 IPI defenses bypass, code public), Nasr 2510.09023 (12 defenses bypass), CodeSentinel 2606.19235 (Tree-sitter CST sanitizer cho code context + họ baseline).

**Hệ quả bắt buộc (cho GAP_VALIDATION → METHOD_CANDIDATES):**
1. Không được claim "first adaptive red-team of comment/advisory defenses on LLM vulnerability/package analyzers" hay bất kỳ biến thể nào mà không định vị chống ALIBI.
2. `LITERATURE_MATRIX.csv` bắt buộc bổ sung tối thiểu: ALIBI 2607.24964 (novelty_risk **HIGH**), CodeSentinel 2606.19235 (novelty_risk **HIGH** — cùng tool Tree-sitter-strip cho code context), Nasr 2510.09023 (MEDIUM-HIGH, chuẩn gate-G). Matrix 75-row hiện stale ở đúng 2 paper nguy hiểm nhất (cả hai 2026).
3. Q1 gate **G** không thể pass bằng cách chỉ "chạy thêm adaptive round" theo R-B nguyên bản — adaptive evaluation phải **so sánh với ALIBI-style adaptive attacker** và phải nêu điểm khác cơ chế (byte-provable AST-gate, paired causal design, hai chiều defense-cost) chứ không phải điểm khác task.
4. R-B nếu giữ: định vị lại thành *differentiation/robustness extension* (adaptive attack cố sống sót qua AST-equivalence gate bằng payload trong identifier/string — phần ALIBI chưa làm trên defense full-strip có gate byte-proof), **không** thành gap độc lập.

**Auditor:** gap-challenger-B (independent lens; không dùng kết quả challenger A). Mọi truy vấn/paper trong §2-§4 đã chạy/đọc trong session này; các mục §5.4 là phần chưa chạy — ghi rõ, không bù số liệu.
