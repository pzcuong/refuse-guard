# V2 Audit Report — Round 9 (PackGuard): W2 verdict 8B + KB universe

Ngày: 2026-09-22. Tác nhân: V2 (vòng 9). Scope: (A) audit verdict 8B
NOT_FEASIBLE của W2; (B) audit KB universe coverage 100%. KHÔNG sửa code,
KHÔNG chạy GPU. Mọi số dưới đây tự đếm/tái tính độc lập từ raw artifacts
(scripts audit: /tmp/v2_audit_kb_recount.py, /tmp/v2_audit_labels_kb.py).
Không có mục nào bịa: số không truy vết được được ghi rõ là không truy vết
được.

---

## VERDICT W2-8B: **PASS — CÓ ISSUES (verdict đứng, 4 citation/số cần sửa)**

Kết luận NOT_FEASIBLE của W2 **ĐỨNG VỮNG**. Nếu 8B thực ra chạy được thì
kết luận phải sửa — kiểm tra độc lập cho thấy nó KHÔNG chạy được trên MPS;
CPU proof là thật. Nhưng 4 chi tiết bằng chứng trong W2_report.md không
đúng như trích dẫn (xung đột FALSE CLAIMS dưới đây) — không mục nào đổi
chiều verdict.

### A1. Bốn lần fail — kiểm từng cái

| # | Claim W2 | Kiểm của V2 | Kết |
|---|---|---|---|
| 1 | bf16 + harness `.to("mps")` smoke: stall ≥27′, RSS peak 43.7 GB, killed, 0 token | `chain.log`: supervisor start 18:43:51Z, **smoke start 18:46:32Z**, không dòng nào sau đó. `smoke_run.log`: mmap load 291/291 xong trong <1s rồi im lặng (stall đúng trong weight copy — khớp `llm_harness.py:243` `self._model.to(self.device)`, device mặc định "mps"), mtime **19:16Z** → stall 29.5′, 0 token, không có `smoke_8b.json`. **Nhưng số RSS 43.7 GB KHÔNG nằm trong artifact thô nào** — `smoke_run.log` không có RSS, supervisor không sample RSS; số chỉ tồn tại trong `jobs_status.json` + docstring probe (cả hai là tóm tắt của chính W2) | Stall/killed/0-token: **XÁC NHẬN**. RSS 43.7 GB: **KHÔNG TRUY VẾT ĐƯỢC** (plausible, không có raw) |
| 2, 3 | fp16 + `device_map={'':'mps'}` ×2 SIGSEGV (PAC), 0/291 shard | 2 file `.ips` TỒN TẠI (`~/Library/Logs/DiagnosticReports/python3.12-2026-09-22-07340{7,8}.ips`). Parse: cả hai `EXC_BAD_ACCESS / SIGSEGV / KERN_INVALID_ADDRESS … possible pointer authentication failure`, **2 PID khác nhau** (19922, 20018), cách 21s (00:34:07Z, 00:34:28Z), stack rơi vào `at::native::mps::copy_cast_kernel_mps → mps_copy_ → copy_` — đúng đường copy weight lên MPS. Giả thuyết kỹ thuật của W2 ("bug đường MPS copy") được stack trực tiếp chứng minh | **XÁC NHẬN ĐẦY ĐỦ**, mạnh hơn lập luận của W2 |
| 4 | fp16 chạy trực tiếp: HUNG 8′ ở 0/291 shard, CPU 99%, peak RSS 6.08 GB → watchdog kill | `probe_direct.log`: start **00:37:31Z**, file kết thúc ~00:45:31Z ≈ đúng deadline 480s của watchdog, dòng resource_tracker-shutdown khớp `os._exit`. **Nhưng** record `DEADLINE_EXCEEDED` + peak RSS 6.08 GB đã BỊ GHI ĐÈ: probe script ghi CẢ hai mode vào MỘT file `probe_8b_light_result.json`, CPU run 00:50:58Z ghi đè. "CPU 99%": không artifact | Sự kiện hang + watchdog: **XÁC NHẬN GIÁN TIẾP** (timing khớp). RSS 6.08 GB + "CPU 99%": **KHÔNG TRUY VẾT ĐƯỢC** |
| Control | Llama-3.2-3B load 9.4s (254 shard), "chạy được" | File **CÓ THẬT**; log: load 9.4s ✓ — nhưng ngay sau đó **`ERROR AttributeError` (message rỗng), 0 token sinh** (`probe_3b_control_result.json`: status ERROR:AttributeError). "Chạy được" là **SAI** | Load-only: **XÁC NHẬN**; "chạy được": **FALSE** |

**Độc lập của 4 fail: CÓ** — khác config (bf16/.to() vs fp16/device_map; nohup
vs direct) VÀ khác thời điểm (18:46Z 21-09 vs 00:34–00:45Z 22-09). Control
3B chứng minh đường fp16/device_map LOAD được ở size nhỏ → fail là đặc thù
8B trên đường load; lập luận độc lập **vẫn đứng dù câu chữ "chạy được" sai**.
Ghi chú: chính control AttributeError ở generation cho thấy đường MPS
generate hỏng ngay ở 3B — làm argument "MPS path dead" còn mạnh hơn, nhưng
W2 không được phép diễn giải control như một run sạch.

Điều tra phụ (đã giải thích xong, không phải bất thường): `probe_3b_control_result.json`
born/mtime 00:44:26Z trong khi content date 00:35:39Z — vì probe script ghi
result của MỌI model vào cùng `probe_8b_light_result.json` (born 00:35:50Z =
đúng lúc control lỗi); file control là bản COPY tách ra lúc 00:44:26Z trước
khi bị ghi đè. Content khớp log — genuine, nhưng phản ánh quản lý artifact
lỏng.

### A2. CPU probe + ETA ladder — TÍNH LẠI

- `probe_8b_cpu.log` + result JSON khớp từng số: load **16.4s**, peak RSS
  **14.33 GB**, **24 token thật / 21.57s = 1.11 tok/s**, template
  `vuln_analysis_standardized_v1`, 392 prompt tokens, output là JSON verdict
  parse được. Token là thật (log in full generation timeline).
- Ladder pre-reg (`configs/round9_8b.yaml`): **max_new_tokens=512** ✓
  (gen_cfg, byte-identical r5/6/7); quy mô = 60 vul × {A0,A5,A1} = 180 +
  30 benign × {C0,C5_near} = 60 → **240 generations** ✓.
- Tính lại: 240 × 512 = 122,880 token / 1.11 tok/s = **30.8 giờ** ≈ "~31h"
  của W2 ✓ — CHƯA tính prefill (prompt tới 5.587k token; trên CPU sẽ cộng
  thêm nhiều giờ). Kể cả tối ưu hóa có lợi cho 8B (decode-only ~1.5 tok/s
  → 22.8h; hoặc giả avg output chỉ 50% cap → 15.4h) vẫn **≫ 6h**.
- Rule pre-reg (tasking): CPU <2 tok/s ⇒ >6h. Đo 1.11. Lưu ý tính trung
  thực: 1.11 đo trên cửa sổ 24 token và BAO GỒM prefill 392 token → nếu gì
  thì pure-decode còn nhanh hơn chút; biên độ tới ngưỡng ~2× và tới ETA
  thực tế ~5–30× → **NOT_FEASIBLE-in-time là đúng rule, robust với mọi
  giả định hợp lý**. Verdict "weights tốt (CPU proof) / MPS dead / ladder
  NOT run, 0 record thật" khớp artifacts; dry-proof `round9_8b/dry/` là
  MockLLM, đúng cách tách mock.

### A3. Các đường bị bỏ sót?

- (a) **MLX 4-bit**: `import mlx` / `import mlx_lm` → ModuleNotFoundError —
  out-of-stack **XÁC NHẬN**. Ghi future work có disclosing rõ: **chấp nhận
  được**. Lưu ý: nếu sau này chạy MLX phải khai báo là runtime khác
  (không cùng claim feasibility với transformers/MPS).
- (b) **llama.cpp GGUF**: `import llama_cpp` → ModuleNotFoundError — cũng
  out-of-stack **XÁC NHẬN**; cần thêm weights q4 mới (~5 GB). Future work OK.
- (c) **Confound scale-vs-family**: qwen-3B/7B inert (round 7) + llama-3B
  harm (rounds 5–7) + llama-8B dead → với stack hiện tại, confound **không
  thể đóng** bằng ladder 8B. Đề xuất "Llama-3.2-3B ladder trên package-domain
  safety-port": **KHÔNG phải instrument cho scale** (vẫn là 3B — không tách
  được scale khỏi family, dù kết quả thế nào). Giá trị thật của nó là
  **domain-generality** (defense-harm đo trên package domain) — đáng làm nhưng
  phải gắn nhãn domain-extension, không được dùng làm bằng chứng scale. Đã có
  sẵn một family-contrast ~matched-scale trong dữ liệu n60 của chính W2
  (P2: llama −4 m→b vs granite +8 b→m — 2 family NHIỄU NGƯỢC chiều ở 2–3B).
  Thêm khả thi trong stack mà đánh thẳng vào "llama-specific": chạy
  **granite-3.3-2B qua cùng ladder vulnerability-domain** (family thứ 3,
  cùng cỡ nhỏ, model có sẵn) — đề xuất cho F, giá rẻ. Chi tiết ở mục
  SCALE QUESTION STATUS.

---

## VERDICT KB UNIVERSE: **PASS — CÓ ISSUES (coverage 100% ĐỨNG, 2 bug metadata)**

### B4. Đếm độc lập — KHỚP 100%

Tự đọc `outputs/packguard/features/graphs_v2.jsonl.gz` (không qua script của
W2): **137 unique api_types, 2.299 instances** — khớp `coverage_v3.json`.
Coverage tái tính: **v3 = 137/137 types (100.00%), 2299/2299 instances
(100.00%)**; v2 = 75/137 (54.74%), 2186/2299 (95.08%) — khớp từng con số.
`kb_v0002.jsonl` = **142 entries = 20 seed + 122 llm:Qwen/Qwen2.5-Coder-3B**,
unsure = 0, không entry nào có semantic_class lệch schema, không rationale
thiếu. Đối chiếu `kb_build.log`: universe 137 = 15 seed-name có trong corpus
+ 60 hit KB-cũ + 62 classify mới (llm_calls=62, refusals=0); số học khớp:
75+62=137 types, 2186+113=2299 instances. **Không phải sổ sách — số thật,
tái lập được.**

**unsure=0 có đáng ngờ không? KHÔNG nghi** — cơ chế UNSURE chỉ kích khi
refusal/unparseable sau retry (kb.py `classify_api`), không phải theo
confidence; Qwen2.5-Coder-3B với defensive framing + JSON-only prompt trả
62/62 parse-clean là hợp lý. Nhưng 2 lưu ý chất lượng (không chặn):
(1) **confidence tự báo bị chùm ở 0.90** (113/122; 5×0.8; 4×0.5) — gần như
hằng số, tín hiệu calibration yếu, phải disclose khi dùng kb_confidence
làm feature; (2) **0 entry LLM nào risk=high** (95 low / 27 medium) — giải
thích được vì sao `kb_risk_ratio` GIỐNG HỆT v2=v3 (0.0745). Sample 10/122
entries: semantic_class đều hợp lệ theo taxonomy 6+OTHER; rationale cụ thể
theo từng API (không lặp máy móc). 1-2 nit phân loại: `Buffer.from` →
DATA_ACCESS (khớp kém với định nghĩa DATA_ACCESS trong KB_SYSTEM — đáng
lẽ OTHER); `fs.rmSync` risk=low trong khi seed `fs.unlinkSync` risk=medium
(nhất quán nội tại yếu, đã disclose là pilot judgement).

### B5. KB-features impact — v3 CHƯA qua FL (TODO cho F, không phải lỗi)

Means tái tính **khớp chính xác** 6/6 số (v2: 0.0745/0.877705/0.032912;
v3: 0.0745/**0.907093**/**0.0**). Trạng thái classifier: `features_v2.jsonl`
**không có cột kb_\* nào**; run KB-augmented DUY NHẤT từng đi qua FL là
`group__graph__kb_on` của round 8 (`outputs/packguard/fl/summary.md`,
17:52Z 21-09 — TRƯỚC khi build v3 18:40Z, tức dùng KB cũ 80 entries/54.7%);
grid round-9 của W1 chỉ chạy graph/tfidf kb_off. → **KB-v3 (0.907/0 unsure)
chưa ảnh hưởng classifier nào.** TODO cho F: re-run ablation kb_on dưới KB
v3; kỳ vọng tác động nhỏ (risk_ratio không đổi; chỉ confidence +0.029 và
unsure→0) nhưng phải đo, không được assume. (W2 không hề claim ngược lại —
đúng.)

### B6. `instances_by_language = {'?': 2299}` — BUG METADATA NHỎ, XÁC NHẬN

Graph records **không có key `language`/`lang`** (keys thật: classes,
**ecosystem**, edges, files, imports, n_*, nodes, parse_*, sample_id,
schema_version, scopes) — script coverage tìm sai key → toàn '?'. Thông tin
ngôn ngữ/nguồn có sẵn dưới `ecosystem` (npm/pypi). Severity: **cosmetic**
— chỉ hỏng một breakdown; không đụng coverage/means. Fix 1 dòng cho F.

### B7 (phát hiện ngoài checklist). `instances_by_label` SAI — bug nhãn thật

Rule của script coverage `label = 1 if "-malicious" in sid else 0` **miss
80 samples `*-compromised_lib-*`** mà `features_v2.jsonl` gán label=1 →
chúng bị đếm thành benign. Đếm lại theo label CHUẨN của features_v2:
**malicious 1.673 / benign 626 instances — KHÔNG phải 1.215/1.084** như
`coverage_v3.json` và như W2_report.md §2 viết. Sai lệch 458 instances.
Severity: **minor** — breakdown thôi; claim 100% coverage và kb_feature_means
KHÔNG đụng nhãn nên vẫn đứng. Nhưng W2 đã sao số sai vào report → phải sửa
report. Lưu ý liên quan: `graphs_v2` có **603** samples, không phải 500 —
500 = số samples có ≥1 API call (103 rỗng: 64 npm + 39 pypi, zero KB signal);
field `graphs_v2.n_samples: 500` trong coverage_v3.json đặt tên dễ gây hiểu
nhầm (universe/coverage tính trên 500 non-empty là ĐÚNG).

### B7b. pytest

`.venv/bin/python -m pytest tests/ -q` chạy lại (CPU): **641 passed / 0
failed (80.83s, 6 warnings)** — khớp claim 641/0 của W2 (W2 ghi 83.98s,
V2 đo 80.83s — cùng kết luận).

---

## CONFIRMED BUGS (cho F sửa, không sửa trong vòng audit này)

1. **Label-rule bug** `src/experiments/round9_kb_coverage.py` (`"-malicious"
   in sid`): 80 compromised_lib samples (label=1) thành benign;
   `instances_by_label` sai (đúng: 1673/626, not 1215/1084). Sửa: join label
   từ features_v2/dataset manifest. Minor (breakdown), nhưng đã lan vào report.
2. **Language lookup bug** cùng file: keys `language`/`lang` không tồn tại;
   dùng `ecosystem`. Cosmetic.
3. **Probe result single-file**: `probe_8b_light.py` ghi mọi mode/mọi model
   vào cùng `probe_8b_light_result.json` → record DEADLINE_EXCEEDED (fail #4)
   bị CPU run ghi đè mất. Process/artifact bug một-lần, không phải code sản
   phẩm; bài học: một result file per (model × mode).
4. *(Đã có sẵn, W2 tự disclose, V2 KHÔNG kiểm sâu trong vòng này — time-box)*:
   fp_bias semantics trong `packguard/safety_port.py` (mal-TP-rate vs
   benign-FP). Ghi nhận disclosure của W2, giữ nguyên đề xuất fix + rename
   của nó cho vòng sau.

## FALSE CLAIMS (cần sửa trong W2_report.md; không đổi verdict)

1. §1.1 bảng, hàng Control: 3B "chạy được" — **SAI**: `ERROR AttributeError`,
   0 token (`probe_3b_control_result.json`). Chỉ mệnh đề "load 9.4s" đúng.
2. §1.1 fail #1: RSS 43.7 GB trích "smoke_run.log + jobs_status.json" —
   `smoke_run.log` KHÔNG chứa số này; số không có artifact thô (chỉ nằm
   trong tóm tắt của W2). Phải ghi "peak RSS quan sát trực tiếp lúc chạy,
   không lưu raw" hoặc bỏ số.
3. §1.1 fail #4: trích "probe_8b_light_result.json (mode mps,
   DEADLINE_EXCEEDED)" — file hiện tại KHÔNG còn nội dung đó (bị ghi đè
   00:50:58Z). Sự kiện hang vẫn chứng minh được bằng probe_direct.log
   (start 00:37:31Z → exit ~00:45Z ≈ deadline 480s); "CPU 99%" + "6.08 GB"
   không có artifact.
4. §2 bảng KB, hàng "unsure entries": v2 ">0" — **SAI**: `kb_v0001.jsonl`
   có unsure entries = 0 (tự đếm); số 3.29% là kb_unsure_ratio trung bình
   per-sample (instance thiếu KB), không phải "entries".
5. §2: "1215 mal / 1084 benign instances" — sai do bug nhãn (đúng 1673/626,
   xem B7).

## AI SAI / AI BẮT ĐƯỢC (3–5 dòng)

- W2 ĐÚNG ở chỗ quan trọng nhất: 8B thật sự không chạy được trên MPS
  (SIGSEGV ×2 là thật, stack rơi đúng mps::copy_cast; ETA 31h tính đúng;
  NOT_FEASIBLE-in-time đúng rule pre-reg) và KB coverage 100% là số thật,
  tái lập được từng con số — không phải sổ sách.
- W2 SAI ở câu chữ bằng chứng: gọi control 3B là "chạy được" trong khi nó
  lỗi ngay sau load (AttributeError, 0 token); trích 2 số RSS (43.7/6.08 GB)
  mà không có artifact thô chứa chúng (1 số còn trích sai file bị ghi đè).
- V2 BẮT ĐƯỢC thứ W2 không thấy: bug nhãn compromised_lib làm
  instances_by_label sai 458 instances (đúng 1673/626) — đã lan vào report;
  bug key language ('?' 2299); KB-v3 chưa từng đi qua FL (kb_on duy nhất là
  round-8 với KB cũ 54.7%); confidence KB chùm 0.90 + 0 entry high-risk
  (giải thích kb_risk_ratio bất biến).
- Không ai bịa số: mọi số truy vết được đều khớp; mọi số không truy vết
  được đã được định danh rõ ràng ở trên.

## SCALE QUESTION STATUS (scale-vs-family — trả lời đến đâu + lựa chọn cho F)

**Hiện trạng:** Câu hỏi mở từ round 7 — "llama-3B hại (reassertion),
qwen-3B/7B inert: scale hay family?" — đến round 9 được trả lời thêm:
llama-8B là instrument đúng (cùng family, ~2.7×) nhưng **NOT_FEASIBLE trên
stack này** (4 fail MPS + CPU 1.11 tok/s ⇒ 31h). Kết luận hiện có thể nêu:
**confound vẫn MỞ**; data đã có: qwen inert ở 3B VÀ 7B (family inert ở cả
2 mốc), llama harm ở 3B, và một family-contrast ~matched-scale trong
package-domain n60 (P2: granite +8 b→m vs llama −4 m→b — 2 family nhiễu
ngược chiều ở 2–3B, hỗ trợ "family-specific" cho channel corruption ở
nhỏ). 8B-infeasibility là một **kết quả report-able** (feasibility/expense
disclosure), không phải thất bại im lặng.

**Lựa chọn cho F (khuyến nghị V2):**
1. **Bắt buộc:** paper2 ghi confound là limitation mở + feasibility
   disclosure cho llama-8B trên MPS/transformers (bảng 4 fail + CPU proof
   1.11 tok/s — đã đủ bằng chứng sau khi sửa 4 citation ở FALSE CLAIMS).
2. **Rẻ, trong stack, đánh thẳng giả thuyết family:** chạy granite-3.3-2B
   qua cùng ladder vulnerability-domain (A0/A5/A1) — family thứ 3 ở cỡ
   ~matched (2B vs 3B). Nếu inert → chết dần giả thuyết "scale là nguyên
   nhân"; nếu hại → harm không phải llama-specific, trở thành "small-model
   generic". Một trong hai đều làm paper mạnh hơn.
3. **Đề xuất "Llama-3.2-3B ladder trên package-domain safety-port":** ĐÁNH
   GIÁ = không tách được scale-vs-family (vẫn 3B; kết quả nào cũng không
   trả lời câu hỏi scale). Giá trị thật = domain-generality của defense-harm
   (đo harm-bundle trên package domain, hiện chỉ có ở vulnerability domain).
   Nên chạy nếu còn budget, nhưng ghi nhãn domain-extension, KHÔNG dùng làm
   bằng chứng scale.
4. **8B thật sự chỉ còn đường out-of-stack** (MLX 4-bit / GGUF — xác nhận
   không có trong .venv): future work hoặc vòng riêng nếu quyết định thêm
   runtime; phải khai báo runtime khác khi so sánh.

---

*V2 round 9 không git commit, không sửa code, không GPU. Scripts audit:
/tmp/v2_audit_kb_recount.py, /tmp/v2_audit_labels_kb.py (CPU only, đọc-true
từ graphs_v2/features_v2/kb jsonl, ghi nothing vào repo). File .ips được
đọc tại ~/Library/Logs/DiagnosticReports/ (đúng 2 file như W2 nêu).*
