# FINAL STATUS — PackGuard + RefuseGuard (chốt submission ở phạm vi 2–3B)

Ngày chốt: 2026-09-28 · Commit: xem `git log` (23 commits) · Trạng thái: **SUBMIT-READY (competitive-plus, 2–3B scope)**

## 1. Deliverable chốt

| Bài | File | Trang | Nội dung |
|---|---|---|---|
| **PackGuard** (bài gộp Q1) | `submission/PackGuard_ms.pdf` + `PackGuard_FINAL.pdf` | 8 | Thesis: untrusted in-package content là attack surface domain-/family-dependent — và AST-sanitization trung hòa nó (trên granite, có cost đo được trên llama) |
| **RefuseGuard** (companion) | `submission/RefuseGuard_ms.pdf` + `RefuseGuard_FINAL.pdf` | 20 | LLM vuln-analysis: blocking không xảy ra ở open 2–3B; verdict-corruption; defense harm; protocol + benchmark |

Visual-judge: PackGuard 8/8 pass, RefuseGuard 20/20 pass · 757 tests · verify_repro 30/30 (manifest 48 artifacts) · tectonic 0 error cả hai.

## 2. Các mục kế hoạch — trạng thái chốt

**DONE (local, đã audit độc lập):**
- P0-1..6 · P1-9 attack+defense (D1 strip: granite P2D1 ≡ P0, llama 1-family cost) · P2-11-LCO (MinHash 67 units, dd p=.368) + expansion +200 random benign (17 hard-negative, disclosed) · P2-12 cả hai nửa (GuardDog F1 .866; MalGuard-style 41 features: graph thắng raw p=.044, không sống Holm) · P3-15/16 rewrite (abstract 236 từ, 3 contributions, audit-log → Threats + Appendix).

**BLOCKED — chờ tài nguyên từ user (đã chuyển thành Future Work trong bài):**
| Mục | Chặn bởi | Unlock |
|---|---|---|
| P1-7 OSF timestamp | Tài khoản OSF | Upload `submission/osf_registration_bundle.md` (AMENDMENT-1,3–8 toàn văn, sẵn sàng paste) |
| P1-8 frontier safety attack (FN/FP-directed, attack success rate) | API key frontier | `OPENAI_API_KEY=... python scripts/frontier_safety_runner.py --model gpt-4o-mini ...` (runner sẵn sàng, stdlib-only) |
| P1-10 A5-GPU (7B/8B) | Ràng buộc <4B (weights đã dọn) | Phê duyệt gỡ <4B + GPU runtime (vLLM/MLX) |
| P2-13 KB human-κ | 2 annotator người thật | Duyệt nguồn annotator |
| P2-11 full ≥3–5k | Mạng/thời gian tải | Duyệt mở rộng tiếp |

## 3. Văn bản kèm submission
- `submission/venue_fit.md` — C&S → TOSEM/EMSE → TDSC (không bịa acceptance rate)
- `submission/cover_letter.md` — draft cho venue #1, mọi claim khớp artifact
- `submission/artifact_list.md` — công bố/bất công bố + lý do
- `SUBMISSION.md` — checklist tổng, readiness từng mục

## 4. Khi user cung cấp tài nguyên
- OSF: upload bundle → điền timestamp vào paper2 §setup + AMENDMENT mục lục (15 phút).
- API key: chạy frontier runner trên prompts P0/P2 (30–90 phút/model) → điền vòng R17, cập nhật scope-claim.
- Duyệt gỡ <4B: tải lại 7B/8B (mạng cho phép) → chạy P1-10 + A5 theo protocol Round-6/7 (đã staged).
