# A2 Report — Round 7 (SCALE-UP 7B / GPU: RQ9 HARM-REPLICATION trên Qwen2.5-Coder-7B-Instruct)

Ngày: 2026-09-21. Tác nhân: A2 (chủ GPU duy nhất vòng 7). Phạm vi: RQ9 —
reassertion-harm (thủ phạm A5 vòng 6 trên llama-3B) có tái lập ở 7B không, và
rung tối thiểu A1 (boundary-only) có còn vô hại ở 7B không.

**TRẠNG THÁI TRUNG THỰC TẠI THỜI ĐIỂM CHỐT REPORT (06:55 +07):**

- **Generation thật: 0/240 records. CHƯA có bất kỳ results.json thật nào.**
- Nguyên nhân: **lỗi hạ tầng mạng lần thứ 3** — weights 7B (15.23 GB) không
  tải được: path `hf_xet` (mặc định của huggingface_hub hiện tại) burst
  ~6 MB/s rồi **stall vĩnh viễn ở 371 MB**; plain CDN per-connection bị bóp
  130–750 KB/s. Hai lần phóng trước chết đúng ở bước này (`.incomplete` 0 byte
  mtime 04:41/05:42/05:51 còn trong blobs).
- Đã chuyển sang **downloader song song tự-thu-hole chạy nền** (16 connections
  ranged, resume từng byte, sha256-verify, tự install vào HF cache) kèm
  **auto-chain: weights xong → smoke → queue-driver → nohup queue**. Hệ quả:
  queue RQ9 **tự khởi động khi weights xong**, không cần can thiệp; S thu hoạch
  sau đó. Toàn bộ pipeline phía sau weights đã staged + tested 100%.

---

## 0. Kiểm kê lần phóng trước (đúng như cảnh báo giao việc)

| Hạng mục | Trạng thái kiểm kê |
|---|---|
| `configs/round7_7b.yaml` (mtime 04:16:21) | **CÓ, hợp lệ, dùng nguyên văn** — pre-registered đầy đủ (queue A0→A5→A1→benign, H-R7-*, gen_cfg byte-identical R5/6, reuse.sources=[]) |
| Records thật `outputs/experiments/round7_7b/` | **KHÔNG có** — chỉ subdir `dry/` với results của model `mock/round7-dry` (plumbing check, không phải generation) → **không có gì phải resume; không có rủi ro nhiễm chéo nào tồn tại trên disk** |
| `src/experiments/round7_7b.py` + `tests/test_round7_7b.py` | CÓ từ lần phóng trước, **13/23 tests FAIL** (4 bug — đã sửa, xem §1) |
| Dry-run mock e2e | ĐÃ chạy trước đó (05:52), config_sha16 ghi trong file dry **TRÙNG config hiện tại** (`8000706d38384ebe`) → chuỗi sha chứng minh design đóng băng trước mọi generation (tiền luật chứng minh V2-R6 CHECK 5) |
| Weights 7B trong `models_dir/hf` | **KHÔNG có** — chỉ 11 MB metadata (config/tokenizer, mtime 04:08–04:09); 4 `.incomplete` 0 byte của các lần thử trước |

Provenance model (verify lại bằng HF Hub API lúc 05:5x): `Qwen2.5-Coder-7B-Instruct`
**ungated** (gated=false), `sha = c03e6d358207e414f1eca0bb1891e29f1db0e242`
— trùng khớp sha ghi trong config và `refs/main` của cache. **Không cần
fallback granite-3.3-8b, không cần amendment model.**

## 1. Sửa 4 bug để lại từ lần phóng trước (code-only, TRƯỚC generation; config KHÔNG đổi — sha giữ nguyên `8000706d38384ebe`)

1. **`_looks_like_oom` không bao giờ khớp `kIOGPUCommandBufferCallback`** —
   key mixed-case được so với chuỗi đã lowercase → fp16-fallback tại load
   chết ngay nếu MPS đưa lỗi này. Fix: so sánh key đã lowercase. (Bug có thể
   là một phần nguyên nhân chết lần phóng trước.)
2. **`compute_round7_metrics` dùng `p.relative_to(PROJECT_ROOT)`** → ValueError
   khi out_dir nằm ngoài project (mọi đường gọi metrics với out_dir tuỳ chọn).
   Fix: helper `_display_path` (relative khi được, absolute khi không).
3./4. **Tests đọc thiếu subdir `dry/`** (runner ghi dry outputs vào
   `<out>/dry/` — convention của `dry_stage`): 3 test resume + 1 test dry-e2e
   trỏ sai path → FileNotFoundError thay vì model-guard raise. Fix test
   (file của A2) về đúng `<out>/dry/`.

**Sau fix: `pytest tests/test_round7_7b.py` = 23/23 passed; toàn suite
`pytest tests/ -q` = 513 passed, 0 failed** (không break vòng cũ).

Các test này đồng thời khoá các ràng buộc pre-reg quan trọng (đã verify pass):
queue priority `A0→A5→A1` + benign `{C0, C5_near}`; gen_cfg byte-identical
R5/6 (trừ max_input_tokens/dtype được phép); khối P3 byte-identical R6
(`system_reassertion` fallback = hằng `p3_boundary.SYSTEM_REASSERTION`);
**subset 60 vul + 30 benign seed 20260923 trùng chính xác sample-level với
selection metadata của round-6 ablation**; **prompt sha trùng records R6 cùng
(sample, rung)** (5 sample × 3 rung so với `results_llama3b__ablation.json`);
model-guard refuse foreign-model + refuse config-sha-drift trên resume và
metrics-merge; verdict machinery đủ nhánh SUPPORTED / ABSENT-STRONG /
INCONCLUSIVE / SAFE / UNSAFE / PARTIAL / INCOMPLETE + SATURATED (fp(C0)≥0.95
không được tính CONSISTENT — tiền lệ qwen-3B).

## 2. [S1] Onboarding 7B — phần làm được và phần đang chạy

### 2.1 Quyết định `max_input_tokens` BẰNG DỮ LIỆU, chốt TRƯỚC generation (điều khoản config cho phép; KHÔNG phải amendment sau-hoc)

Tokenizer 7B (đã có trong cache từ 04:09) dùng tokenize **toàn bộ 240 prompt
thật** (60 vul × 3 rungs + 30 benign × 2 arms, builder thật của runner):

```
n=240; median=814 tokens; p99=4,073; max=5,587 (sample 220924, arms C0 & C5_near)
```

- Hạ xuống 4096 sẽ **cắt 3 prompt** (gồm đúng sample nhiều advisory nhất,
  220924) → phá ràng buộc paired byte-identical với R6 ở cấp nội dung model
  nhìn thấy, và sample bị cắt là sample stress mạnh nhất → bias có hướng.
- **CHỐT: giữ `max_input_tokens: 8192`.** KV-cache 8192 tokens của 7B
  (28 layers × 4 KV-head GQA × 128 dim, bf16) ≈ 0.47 GB; weights bf16 ~15.2 GB
  → tổng ~18 GB < 32 GB MPS. Không amendment, disclose ở đây một lần duy nhất.

### 2.2 Tải weights — chẩn đoán hạ tầng + giải pháp đang chạy

Chuỗi sự kiện đã verify bằng lệnh thật (log `/tmp/r7_dl.log`, `/tmp/r7weights/fetch.log`):

1. `snapshot_download` mặc định (hf_xet): burst 287 MB/45 s (~6.4 MB/s) rồi
   **stall tuyệt đối** ở 371 MB qua 5 restart (supervisor kill/restart không
  .capture thêm byte nào) → path chunk xet (`cas-bridge`/`transfer.xethub.hf.co`)
   chết network-level.
2. Plain CDN (`resolve → us.aws.cdn.hf.co`, signed URL): sống nhưng bóp
   130–750 KB/s/connection; 4 shard song song = ~850 KB/s; 8 range cùng 1 URL
   = bị bóp về 0 (per-URL throttle).
3. Mạng nền cũng suy giảm (cloudflare 25 MB test: 119 KB/s; DNS resolver
   timeout từng lúc), route HF đi qua VPN tunnel utun6 (default route là en0
   nhưng en0 bị edge từ chối — bind en0 = 0 byte tức thì).

**Giải pháp đang chạy:** downloader riêng (`/tmp/r7_fetch.py`, stdlib + curl):
4 shard × 4 range-part = 16 connections; mỗi round lấy signed URL mới (URL
expire); mỗi part stream-append nên **resume đúng byte giữa các round**;
guard `--speed-limit 10KB/s --speed-time 45` tự cắt connection chết;
kết thúc: ghép part → **sha256 verify đúng LFS etag từng shard** → install
đúng layout HF cache (`blobs/<sha>` + symlink `snapshots/<rev>/<file>`,
rev = `c03e6d...` đúng config) → **tự chain** `--stage smoke` → `--stage
queue-driver` → **nohup queue** (log `outputs/experiments/round7_7b/queue.log`).

Tiến độ tại 06:50: **0.49/15.23 GB, trung bình 862 KB/s** → ETA weights
**~3–6 giờ** ( dao động theo network; supervisor tự sống sót qua stall bằng
round-restart). Smoke sẽ chạy ngay sau đó (~2–3 phút), queue tự lên.

### 2.3 Smoke (S1b) — sẽ có số thật, KHÔNG đoán trước

`--stage smoke` (đã có trong runner + test): load MPS bf16 (OOM tại load →
fp16 tự động bởi `RealLLM7B`; vẫn OOM → `ScaleUpBlocked` = RQ9 NOT_RUN theo
prereg §3.1, KHÔNG được thay model), 3 prompt tổng hợp (vulnerable/benign/
nhạy cảm — 0 overlap bench, không bẩn cache thí nghiệm), đo **tok/s thật**,
kiểm tra cache-replay hit, ghi `outputs/experiments/round7_7b/smoke_7b.json`
kèm ETA 240-gen theo tok/s đo được. S đọc file này để có tok/s chính thức.

## 3. [S2] Pre-reg compliance — checklist đối chiếu `docs/round7_prereg.md` (Amendment-1) ↔ `configs/round7_7b.yaml`

| Điều khoản prereg | Trạng thái |
|---|---|
| Model thực thi = qwen7b (§0b(i)) | ✅ config + runner; ungated, sha verify |
| Ladder A0/A1/A5 minimal, byte-identical R6 (§3.1) | ✅ builder reuse read-only từ round6_ablation; test khoá prompt-sha == records R6; bench sha `2daa249f7543f8e0` verify lại bằng sha256 thật |
| Subset 60+30 seed 20260923 sample-paired R6 (§3.1) | ✅ test `test_subsets_pair_with_round6_selection` |
| CẤM cross-model reuse; model-guard bắt buộc (§3.1) | ✅ `reuse.sources=[]`; `model_guard` tại resume + metrics-merge + config-sha; 0 record nào được reuse ở R7 (model mới, chưa từng chạy) |
| Per-record `prompt_sha256_16` (§3.1) | ✅ runner ghi mọi record |
| Rule algebra H-R1/H-R2/H-R3 theo Amendment-1 (§0b(iv)) | ✅ hypotheses trong config byte-consistent; verdict machinery implemented + test đủ nhánh (thứ tự xét: SUPPORTED → REVERSAL → ABSENT-STRONG → ABSENT → PARTIAL-INCONCLUSIVE) |
| Checkpoint 10 records; resume; budget-guard | ✅ `execution.checkpoint_every: 10`; `--budget-min` cắt giữa job, `partial=true` |
| Monitor required_fields [vulnerable, cwe, location]; threshold fallback 0.0/0.2 (models.yaml không có calibration cho 7B — disclose) | ✅ config `monitor.*`, ghi `monitor_thresholds_source` vào metadata job |
| RR báo riêng, refusal không map benign | ✅ taxonomy + metrics tách (`fp_benign` chỉ đếm y_pred trên PARSED records) |
| McNemar method disclosure (V2-R6 Issue 1) | ✅ metrics stage tính thêm **exact binomial thuần** cho mọi headline comparison cạnh p auto (χ²-cc khi discordant ≥25) |
| Source paths RQ9 (§4.1) | ✅ đúng `results_qwen7b__vul__{A0,A1,A5}.json` + `results_qwen7b__benign__B0.json` trong `outputs/experiments/round7_7b/` |

**Không có generation nào nên KHÔNG có số nào trong report này — trung thực
theo nguyên tắc số 1 của PROJECT_BRIEF.**

## 4. [S3] Queue vận hành + resume (toàn bộ lệnh đã verify cú pháp; queue CHƯA lên vì weights chưa xong)

Thứ tự job (variant-major, sample-major trong job — budget-cut vẫn còn paired
prefix): **A0 (60) → A5 (60, PRIMARY) → A1 (60) → benign 30×{C0, C5_near} (60)**.
Một `RealLLM7B` dùng chung (weights load 1 lần). Checkpoint 10 records/job,
`jobs_status.json` ghi pid/job/n_done/ETA/s-per-record.

```bash
cd /Users/macbook/.zcode/workspace/default/refuseguard   # ROOT, mọi lệnh dưới chạy từ đây

# (1) Nếu fetcher + chain còn sống (đang nohup): theo dõi
tail -f /tmp/r7weights/fetch.log                 # download + chain events
tail -f outputs/experiments/round7_7b/queue.log  # queue (tự xuất hiện khi chain fire)
cat outputs/experiments/round7_7b/jobs_status.json

# (2) Nếu chain bị đứt sau khi weights đã đủ: smoke rồi queue thủ công
HF_HOME=$PWD/models_dir/hf .venv/bin/python -m src.experiments.round7_7b --stage smoke
HF_HOME=$PWD/models_dir/hf .venv/bin/python -m src.experiments.round7_7b --stage queue-driver
HF_HOME=$PWD/models_dir/hf nohup .venv/bin/python \
  outputs/experiments/round7_7b/queue_driver.py \
  >> outputs/experiments/round7_7b/queue.log 2>&1 &

# (3) Resume một job bất kỳ (cache giúp phần đã chạy = miễn phí; model-guard
#     từ chối file của model/config khác):
HF_HOME=$PWD/models_dir/hf .venv/bin/python -m src.experiments.round7_7b --stage run --variant A0   # rồi A5, A1
HF_HOME=$PWD/models_dir/hf .venv/bin/python -m src.experiments.round7_7b --stage benign

# (4) Metrics + verdict khi job xong (chạy được nhiều lần, chỉ đọc):
HF_HOME=$PWD/models_dir/hf .venv/bin/python -m src.experiments.round7_7b --stage metrics
```

RQ8-extension (benign 20 từ bench_attack_v2 cho FP-bias 7B) — **ưu tiên thấp
như giao việc, CHỈ làm nếu còn budget sau RQ9; hiện chưa có runner riêng** (S
quyết định khi thu hoạch; không tự sinh việc mới khi RQ9 chính còn pending).

## 5. ETA tổng (số khai báo trước để S thu hoạch)

- Weights: còn ~14.7 GB ở 0.5–3 MB/s (burst/stall) → **ETA 3–6 h** từ 06:50.
- Smoke: ~2–3 phút (load + 3 gen + 3 cache-replay).
- Queue 240 gen: tok/s thật sẽ có ở `smoke_7b.json`; kịch bản theo brief
  (7B MPS ~8–15 tok/s, gen JSON điển hình ~120–250 completion tokens, worst
  512): **~40–70 s/gen worst-case → queue 2.7–4.7 h**; nếu prompt dài + token
  ngắn thực tế thì nhanh hơn. Tổng từ giờ report: **~6–11 h** → S thu hoạch
  phiên sau (queue + checkpoint chạy nền nohup, sống sau session).

## 6. Deviations + disclosure (trung thực)

1. **Sửa code runner/tests TRƯỚC generation** (4 bug §1) — config KHÔNG đổi
   (sha `8000706d38384ebe` trước/sau khớp dry-run của lần phóng trước → design
   frozen chain không gãy). Bug số (1) là functional (fp16-fallback), số
   (2)–(4) là plumbing/test.
2. **Cài `hf-transfer==0.1.9` vào `.venv`** (uv, PyPI) khi cố cứu download —
   cuối cùng không dùng (deprecated path), ghi để audit môi trường.
3. File hạ tầng ngoài repo: `/tmp/r7_fetch.py`, `/tmp/r7_dl.log`,
   `/tmp/r7weights/` (part files + logs). KHÔNG đụng `src/conditions`, `src/
   models`, `src/defenses`, `src/metrics`, `src/data`. KHÔNG git commit.
4. `HF_HUB_ENABLE_HF_TRANSFER`/`HF_XET_HIGH_PERFORMANCE` đã thử trong chẩn
   đoán — không thay đổi kết luận xet-stall; downloader manual không phụ thuộc
   biến môi trường nào.
5. Nếu đến phiên S weights vẫn chưa đủ (mạng chết hẳn): RQ9 = NOT_RUN,
   paper giữ scope "2–3B" + disclose (đúng prereg §3.1: thất bại thực thi,
   không phải finding) — nhưng hiện tất cả evidence cho thấy chỉ là chậm,
   không phải mất đường.

## 7. Verification (lệnh đã chạy thật)

`pytest tests/test_round7_7b.py -q` = 23 passed; `pytest tests/ -q` = 513
passed (139.97 s). sha256 bench = `2daa249f7543f8e0` (đúng R6). HF API:
gated=false, sha `c03e6d358207e414f1eca0bb1891e29f1db0e242`. Tokenize 240
prompt bằng `AutoTokenizer` 7B: max 5,587. MPS smoke: `torch.backends.mps.is_
available()=True`, matmul OK. Config-sha chain: dry-run file ==
current config. Download progress + log: `/tmp/r7weights/fetch.log`,
`/tmp/r7_dl.log`. Số liệu khác trong report này là trạng thái filesystem đọc
trực tiếp (mtime, kích thước), không có số generation vì chưa có generation.
