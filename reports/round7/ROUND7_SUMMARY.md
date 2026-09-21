# ROUND7_SUMMARY — Vòng 7 (CWE expansion + 7B scale-up) — VÒNG ĐÃ CHỐT

Ngày chốt: 2026-09-21. Orchestrator thực hiện vai trò S trực tiếp (phiên S subagent bị
ngắt bởi rate-limit sau khi điền số; orchestrator kiểm lại 100% số + sửa 3 lỗi LaTeX
+ hoàn thiện verify chain).

## 1. Bảng "AI SAI / AI BẮT ĐƯỢC" — Vòng 7

| # | Ai | Việc sai/thiếu | Ai bắt | Trạng thái |
|---|---|---|---|---|
| 1 | A1 | Bridge-overlap của bench_attack_v2 ghi 0 (thật: 22 ids với round2 bridge, 16 với round1) + false claim "fully fresh relative to every bench" | V1 | ✅ EXEC sửa key `records`→`samples`, manifest sửa có kiểm chứng, khối [CORRECTED-R7]; jsonl sha không đổi |
| 2 | A2 | Auto-chain 7B chết im lặng: weights tải xong 08:23 nhưng smoke/queue không fire (nghi vấn OOM do RQ8 chiếm MPS từ 08:15); report lúc đó ghi "đang tải, ETA 6-11h" — đã lỗi thời ngay khi viết | V2 | ✅ EXEC verify weights trên disk (15,231,271,864 B, rev đúng), fire queue trực tiếp, 240/240 gen xong |
| 3 | A3/A2 | Collector path map lệch (`round7_cwe` vs `round7_rq8`) → master báo [pending] dù 640/640 records thật | V1 + V2 | ✅ EXEC sửa map + Amendment-2 post-hoc path-only; collector build 104 rows, re-read verify pass |
| 4 | A3 | Pre-reg hai tầng lệch granularity (config A2 vs prereg doc) | A3 tự phát hiện, ghi Amendment-1 TRƯỚC generation | ✅ V2 xác nhận timing bằng chuỗi sha (config sha trong dry-run 00:13 khớp hiện tại trừ đúng 1 key) |
| 5 | A1 | fp_rate không lọc label=0 (bắt được bằng test tự viết) | A1 tự bắt | ✅ fixed + regression test |
| 6 | EXEC/S-later | LaTeX vỡ ở 3 chỗ do fill bị ngắt (tab_round7:98, 05_results:416/473 — underscore thô + math mode trần) | Orchestrator (compile check) | ✅ sửa: `NOT\_SUPPORTED`, `C5\_near`, bọc `$...$` cho `{\times}10^{-N}`; tectonic exit 0 |
| 7 | EXEC | Manifest list trỏ `results.json` không tồn tại (7B ghi per-job files) | Orchestrator | ✅ sửa 4 path per-job thật; manifest 34/34 ok |

Không phát hiện false claim material nào sau các fix; mọi verdict giữ nguyên.

## 2. Kết quả khoa học mới (đều pre-registered, đều thật)

**RQ8 — Verdict-bias generalize qua CWE family?** (bench_attack_v2: 4 family mới
476/416/190/200 × 20 benign + 20 vul, 640 records, llama3b + granite2b):
- **Granite-3.3-2B: GENERALIZES — 4/4 family** (flips b2v 13/15/9/14; mọi p ≤ 0.0039;
  sống sót Bonferroni ×5; pooled ΔFP +0.637 [0.062→0.700], p=8.88e-16).
- Llama-3.2-3B: GENERALIZES-pooled-driven (H_G1 NOT_SUPPORTED 2/4: 476 p=0.0625 cách
  đúng 1 flip; 190 headroom cạn — C0 FP đã 0.90) + H_G2 SUPPORTED. Anti-masking được
  tôn trọng: cả per-family và pooled đều báo, caveat headroom-limited ghi rõ.
→ **F2 upgraded: corruption channel không phải đặc sản memory-copy family.**

**RQ9 — Harm replicate ở 7B?** (Qwen2.5-Coder-7B-Instruct bf16, ladder A0/A1/A5
byte-identical Round-6, 240 records, RR=0.000):
- **H-R1 NOT_SUPPORTED-ABSENT: harm KHÔNG xuất hiện ở 7B** — recall 0.4746 (A0) →
  0.5167 (A5), Δ = −0.042 (hướng ngược harm), 3 flips 1→0, exact p=0.7266.
- **H-R2 SUPPORTED: minimal provenance an toàn ở 7B** (A1 0.4576, Δ −0.017, p=1.0).
- Prompt-identity guard: 120/120 overlapping (sample, rung) khớp Round-6 SHA.
- CAVEATS bắt buộc (đã ghi trong paper): (a) qwen7b cùng họ qwen-3B vốn inert → không
  tách được scale khỏi family-inertness; (b) A0 baseline 7B thấp (subset-difficulty);
  (c) completion ~50 tok (không 512) — đo thật từ meta.

→ **Câu chuyện guidance hoàn chỉnh: minimal provenance an toàn ở mọi scale đã đo
(2B/3B/7B); full-bundle reassertion là rủi ro của model ≤3B, biến mất ở 7B.**

## 3. Sức khỏe dự án cuối

- pytest: **531 passed, 0 failed**; tectonic exit 0 — **PDF 17 trang**, 0 `??`, 0 token
  {{R7:*}}, 0 stale path; verify_repro **30/30 PASS** (manifest 34 artifact round1-7 +
  value-check RQ7: RQ8 GENERALIZES ×2, RQ9 harm-absent p=0.7266).
- Tổng generation toàn dự án ≈ 6,250+ (Vòng 7: 640 RQ8 + 240 RQ9 + smoke).
- Master: round7_master.json 134 rows (RQ8+RQ9) + round6_bias 149 + round6_ablation
  134 + master_results 341 — tất cả re-read verified.
- 7 commits git (R1→R7).

## 4. Khuyến nghị còn lại (ngoài khả năng local)

1. **Frontier transfer test** (GPT-4o/Claude/Gemini) — cần API key; câu hỏi mở duy nhất
   của F2: bias/refusal ở model frontier-closed.
2. **Tách family-inertness khỏi scale** (RQ9 caveat): chạy ladder trên Llama-3.1-8B
   (họ llama — model có harm ở 3B) — cần ~15GB weights, khả thi MPS, ~2-3h.
3. Mở rộng RQ8 thêm families (crypto/API misuse) + user study practitioner-facing.
