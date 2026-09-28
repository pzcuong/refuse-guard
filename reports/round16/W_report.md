# W Report — Round 16 (PackGuard: Kaggle GPU chạy 2 thí nghiệm GPU-bị-chặn:
# P1-10 ladder A0/A5/A1 ở 7B/8B + P1-8-partial safety P0/P1/P2 ở 7B)

Ngày: 2026-09-28. Owner: W (vòng 16). Scope: export prompt deterministic
(K1), kernel self-contained (K2), dataset + 2 kernel push qua Kaggle CLI
(K3), monitor (K4), tests + report (K5). KHÔNG git commit. KHÔNG bịa số —
**phiên này CHƯA có số generation nào** (kernel vẫn đang chạy): mọi thứ dưới
đây là trạng thái hạ tầng + verify prompt-sha, số recall/RR sẽ chỉ đến từ
results file tải về sau.

## 1. LÀM GÌ

### [K1] EXPORT PROMPT — DONE, đã verify sha chống records cũ
- `kaggle_pkg/export_prompts.py` (chạy `.venv/bin/python
  kaggle_pkg/export_prompts.py`) rebuild prompt bằng ĐÚNG machinery đã
  audit, read-only: ladder qua `src.experiments.round7_7b.build_subsets` +
  `round6_ablation.prompt_for`; safety qua
  `scripts.packguard_safety_batch.pick_samples` +
  `packguard.safety_port.render_prompt`.
- `kaggle_pkg/data/ladder_prompts_7b8b.jsonl` — **180 rows** = 60 vul
  (bench_attack_v1, arm C5_near, seed_subset **20260923**) × {A0, A5, A1}.
- `kaggle_pkg/data/safety_prompts_7b.jsonl` — **300 rows** = đúng selection
  n100 (50 mal + 50 ben, seed **20260922**, gate-passers, code_chars=2500)
  × {P0_neutral, P1_offensive_wording, P2_advisory_in_package}.
- `kaggle_pkg/prompts_verification.json` — verification meta (mọi match
  count + draw stats + file sha16). Deterministic: 2 lần build ra cùng JSON
  (test pin).

### Verify prompt-sha với records cũ (assert trong export, pass hết)
| Check | Đối chiếu | Kết quả |
|---|---|---|
| A0 (60) | round-7 qwen7b `results_qwen7b__vul__A0.json` per-record `prompt_sha256_16` | **60/60 khớp** |
| A5 (60) | round-7 qwen7b `results_qwen7b__vul__A5.json` | **60/60 khớp** |
| A1 (60) | r10 granite `results_granite2b__vul__A1.json` (sha gate model-blind → khớp sha = byte-identical rebuild) | **60/60 khớp** |
| Safety selection | 100 sample (id/label/ecosystem/language) vs `safety_batch_n100.jsonl` | **100/100 khớp**, draw stats trùng meta (scanned 265 / gate_pass 100) |
| Safety P0 | `defense_batch.jsonl` `p0_prompt_sha16` (round-12) | **38/38 khớp** |
| P2 build path | frozen advisory comment + "\n" + code (AMENDMENT-6 A6.2) | giữ nguyên (assert trong test) |

### [K2] KERNEL — DONE
`kaggle_pkg/kernel_template.py` → `kaggle_pkg/make_kernels.py` render 2
kernel self-contained: `kaggle_pkg/kernel/packguard-p110-p18.py` (Qwen
2.5-Coder-7B; ladder+safety) và `kaggle_pkg/kernel/packguard-p110-llama8b.py`
(Llama-3.1-8B; chỉ ladder — safety là câu hỏi 7B theo tasking). Kernel:
đọc `/kaggle/input/packguard-prompts-r16/*.jsonl`, load model fp16
(T4 không có bf16 — disclose) `device_map="auto"`, greedy
(do_sample=false, seed 1234), max_new_tokens 512/384, max_input_tokens
8192/4096 với head+tail truncation replica, checkpoint append+fsync TỪNG
record + progress file mỗi 20 rows, soft-stop 11h trước cap 12h, parser
JSON verdict = replica byte-compatible của `extract_json` +
`parse_verdict` (test pin equivalence), queue priority ladder A0→A5→A1 →
safety P0→P1→P2. Ghi `results_{qwen7b,llama8b}_{ladder,safety}.jsonl` +
`summary_*.json` vào `/kaggle/working`.

### [K3] DATASET + PUSH — DONE
- Dataset **pzcuong/packguard-prompts-r16** (private, CC0-1.0): 2 jsonl +
  prompts_verification.json + README. Status `ready` trước khi push.
- Kernel metadata: `enable_gpu: true` (T4×2), `enable_internet: true`,
  `kernel_type: script`, `dataset_sources: [pzcuong/packguard-prompts-r16]`,
  private. KHÔNG đụng kernel/dataset cũ của user (kiểm `kaggle datasets
  list --mine` — chỉ thêm dataset mới; 2 kernel là slug MỚI).

### [K4] MONITOR — ĐANG CHẠY
- **Sự cố v1 (disclose):** lần push đầu (13:57–13:59Z) CẢ HAI kernel ERROR
  trong ~30 s: `/kaggle/input` TRỐNG lúc worker start (dataset mount race).
  2 lần chạy hỏng này tốn <2 phút GPU quota, không sinh record nào.
- **Fix v2:** `find_input_dir` thêm wait-retry 5 phút + quét recursive +
  raise kèm listing (chẩn đoán được từ log). Push v2 ~14:01Z.
- **v2 (hiện tại): CẢ HAI kernel RUNNING** từ ~14:02Z, qua mốc 20+ phút
  (vượt điểm chết v1) → đang generate. Poller nền
  (`kaggle_pkg/poller.sh`, 5 phút/lần) tự tải output khi xong vào
  `outputs/packguard/r16_kaggle/<slug>/` và log
  `outputs/packguard/r16_kaggle/monitor.log`.
- URL: https://www.kaggle.com/code/pzcuong/packguard-p110-p18 và
  https://www.kaggle.com/code/pzcuong/packguard-p110-llama8b.

### PHÂN TÍCH SẴN SÀNG (chạy khi có results)
`kaggle_pkg/analysis.py` (AMENDMENT-9 A9.3): ladder per model — recall_vul
per rung, flip HAI CHIỀU vs A0, McNemar exact, verdict H-R7-harm-replicates
/ harm-absent / A1-minimal-safe copy VERBATIM từ configs/round7_7b.yaml;
safety — refusal phân loại post-hoc bằng RefusalMonitor ĐÃ ĐĂNG KÝ
(threshold global-default 0.5/0.35, fallback=true — disclose từng record;
Qwen 7B + Llama 8B đều KHÔNG có block calibrate), RR per arm + ΔRR +
McNemar exact vs P0, flip hai chiều, malicious_recall + fp_benign (tên gọi
đã sửa round-9F), rules blocking/corruption giữ nguyên. Output:
`outputs/packguard/r16_kaggle/r16_analysis.json`. Thiếu file →
status=pending (không bao giờ bịa).

## 2. FILES (absolute)
- /Users/macbook/.zcode/workspace/default/refuseguard/kaggle_pkg/
  {export_prompts.py, make_kernels.py, kernel_template.py, analysis.py,
  poller.sh, prompts_verification.json}
- /Users/macbook/.zcode/workspace/default/refuseguard/kaggle_pkg/data/
  {ladder_prompts_7b8b.jsonl (180), safety_prompts_7b.jsonl (300)}
- /Users/macbook/.zcode/workspace/default/refuseguard/kaggle_pkg/kernel/
  {packguard-p110-p18.py, packguard-p110-llama8b.py}
- /Users/macbook/.zcode/workspace/default/refuseguard/kaggle_pkg/push/
  {packguard-p110-p18, packguard-p110-llama8b}/{kernel-metadata.json, *.py}
- /Users/macbook/.zcode/workspace/default/refuseguard/kaggle_pkg/dataset/
  (bản upload: 2 jsonl + verification + README + dataset-metadata.json)
- /Users/macbook/.zcode/workspace/default/refuseguard/configs/packguard_kaggle.yaml (mới)
- /Users/macbook/.zcode/workspace/default/refuseguard/docs/packguard_prereg.md — **AMENDMENT-9 (2026-09-28T13:54:28Z, TRƯỚC mọi push)**
- /Users/macbook/.zcode/workspace/default/refuseguard/tests/
  {test_packguard_kaggle_pkg.py (12 tests), test_packguard_r16_analysis.py (9 tests)}
- /Users/macbook/.zcode/workspace/default/refuseguard/outputs/packguard/r16_kaggle/
  {monitor.log, packguard-p110-p18/packguard-p110-p18.log (v1 error log),
   packguard-p110-llama8b/packguard-p110-llama8b.log (v1 error log)}

KHÔNG đụng src/, packguard/ (import-only), không đụng kernel cũ của user,
không git commit.

## 3. CÁCH CHẠY / LỆNH CHO PHIÊN SAU
```
export PATH="$HOME/.local/bin:$PATH"          # kaggle CLI (uv tool install kaggle)
kaggle kernels status pzcuong/packguard-p110-p18
kaggle kernels status pzcuong/packguard-p110-llama8b
# khi COMPLETE/ERROR — poller nền đang tự tải; tải tay nếu cần:
kaggle kernels output pzcuong/packguard-p110-p18 -p outputs/packguard/r16_kaggle/packguard-p110-p18
kaggle kernels output pzcuong/packguard-p110-llama8b -p outputs/packguard/r16_kaggle/packguard-p110-llama8b
.venv/bin/python kaggle_pkg/analysis.py        # -> outputs/packguard/r16_kaggle/r16_analysis.json
```
Tái lập export (local, ~10 s): `.venv/bin/python kaggle_pkg/export_prompts.py`.

## 4. LỆCH CHUẨN / DISCLOSE (honest)
1. **Chưa có số generation nào trong phiên này** — kernel RUNNING; verdict
   H (harm A5 replicate ở 7B/8B?) CHƯA trả lời được, sẽ chỉ đến từ
   r16_analysis.json sau khi chạy xong. Không suy đoán số.
2. **Tasking ghi ladder "subset seed 20260922" và "120 rows"** — theo
   PROTOCOL ĐÃ ĐĂNG KÝ của chính ladder (configs/round7_7b.yaml /
   r10_granite_ladder.yaml mà tasking dẫn): seed_subset **20260923**, 3
   rungs → **180 rows** (20260922 là seed của safety batch). Lý do: giữ
   sample-pairing với round 6/7/10 (điều kiện so per-family/per-scale) và
   rule algebra không được dịch giữa các round. Đăng ký trong AMENDMENT-9.
3. **Kaggle = replication độc lập**: fp16 CUDA vs MPS bf16 cũ, template
   chat của model trên runtime mới → record Kaggle KHÔNG merge generation-
   level với records cũ; so sánh ở mức metric, ghi kaggle-r16 (AMENDMENT-9).
   Riêng qwen-7B: round-7 đã có A0/A5 local (A0 .4746 / A5 .5167, harm-
   absent SUPPORTED, ceiling-bound) — run Kaggle là replication + lấp A1
   (round-7 thiếu) + benign-check vẫn out-of-scope.
4. **v1 cả 2 kernel ERROR vì mount race** (<2 phút GPU, 0 record) — disclose;
   v2 fix + đang chạy; versions của kernel do tôi sở hữu, không đụng kernel cũ.
5. Refusal-monitor cho 2 model Kaggle là **fallback global 0.5/0.35**
   (không có block calibrate) — phân loại post-hoc locally bằng đúng class
   đã đăng ký, disclose trong analysis meta; nhất quán với cách granite
   được xử lý ở các batch trước.
6. Benign FP-check của ladder protocol (30 benign × {C0, C5_near}) OUT OF
   SCOPE theo tasking vòng 16 → H-R7-benign-verdict-bias = NOT_EVALUABLE.
7. Llama-8B dùng mirror unsloth/Llama-3.1-8B-Instruct (đúng tasking; family
   llama, scale 8B).
8. Kaggle CLI chưa có sẵn trong .venv (tasking nói có) → cài bằng
   `uv tool install kaggle` (CLI 2.2.4, credentials ~/.kaggle đã xác thực).

## 5. TODO (phiên sau)
1. Chờ 2 kernel xong (poller tự tải); chạy `kaggle_pkg/analysis.py`;
   trả lời H: harm A5 replicate ở 7B/8B không (per-family + per-scale) và
   safety 7B blocking/corruption — viết supplement vào report này.
2. Nếu kernel dở do 12h cap: file vẫn checkpoint từng record — tải output
   (poller làm sẵn), đánh dấu partial, không re-run nếu đã đủ câu hỏi chính
   (A0+A5 per model là core; A1/safety theo priority).
3. Nếu muốn hoàn thiện A1/benign-check còn thiếu → push version 3 (kernel
   tự resume qua done_keys nếu working dir còn — trên Kaggle commit run mới
   là working dir mới, cần dataset hiện có + dùng `kaggle kernels push`
   lại; lượt chạy mới tốn quota — quyết định của user).
4. Nhập số vào paper2 chỉ sau khi analysis JSON tồn tại.

## 6. SELF-TEST THẬT (đã chạy trong phiên)
- `.venv/bin/python -m pytest tests/test_packguard_kaggle_pkg.py
  tests/test_packguard_r16_analysis.py -q` → **21 passed** (deterministic
  export 2 lần; sha A0/A5/A1 khớp stored 60/60/60; safety selection
  100/100 + P0 38/38; parser kernel ≡ safety_port.parse_verdict trên 10
  loại text; gen params frozen; resume bỏ torn line; analysis verdict
  harm-absent/harm-replicates/incomplete/refusal-not-verdict/safety-rules
  trên mock; pending/malformed fail-safe).
- `.venv/bin/python -m pytest tests/ -q` → **778 passed / 0 failed**
  (99.5 s).
- Export chạy thật: 180 + 300 rows; verification JSON ghi đầy đủ match
  counts (bảng §1).
- Kaggle: `kaggle datasets status pzcuong/packguard-prompts-r16` → ready
  (4 files); 2 kernel push v1 + v2 thành công; v1 ERROR log đã tải về
  outputs/packguard/r16_kaggle/; v2 RUNNING (monitor.log, poll 5').
- GPU quota: chỉ 2 kernel slug mới; tổng đã dùng <5 phút (2 lần v1 fail);
  v2 dự kiến ≤ ~12h/kernel → nằm trong 30h/tuần.

---
*W round 16 không git commit. Một câu: hai thí nghiệm GPU-bị-chặn đã được
đăng ký (AMENDMENT-9 trước push), prompt export byte-verified chống records
cũ (180/180/60 ladder + 100/100 + 38/38 safety), và đang CHẠY THẬT trên 2
kernel Kaggle T4×2 riêng biệt (Qwen-7B: ladder+safety; Llama-8B: ladder) —
kết quả số chờ results file, poller tự tải về outputs/packguard/r16_kaggle/.*
