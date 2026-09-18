# A2 Report — Round 3 (CodeBERT eval chốt, E7 fusion/fallback, refusal-monitor calibration chốt)

Ngày: 2026-09-19. Tác nhân A2. Quyền sở hữu: `src/models/`, `src/metrics/` (không phải
sửa — lý do ở mục 6), `scripts/`, `configs/`, `outputs/transformer/`,
`outputs/experiments/round3_e7/`, tests `test_models_*`/`test_metrics_*`,
`reports/round3/A2_report.md`. Không git commit.
Mọi số dưới đây truy vết được tới file output thật nêu tên; không số nào là bịa.

**Tóm tắt: (1) CodeBERT final eval CHỐT trên official test split (mirror v0.1): 20,549
sample (TOÀN BỘ 549 vulnerable test + 20,000 benign subsample seeded), recall@0.5=0.541,
F1=0.215, MCC=0.232, AUC=0.847, VD-S (FNR@FPR≤0.5%)=0.962, paired P-C=0.0092 — đối chiếu
PrimeVul paper (Table V): F1 gần trùng (21.5 vs 20.9), accuracy/VD-S lệch có nguyên nhân
disclosed (mục 1). (2) E7 fusion PRE-REGISTERED chạy thật: fallback chỉ dùng 2/133 record
cả 2 ĐÚNG, UAC 0.985→1.0, MCC 0.0789→0.0942; safety scope chặn 500/500 record E8
(mục 2). (3) Thresholds monitor final per model đã ghi `configs/models.yaml`
(Qwen 0.0/0.2, Llama-3.2 0.0/0.2, từ cache Vòng 2, không gọi LLM mới); nửa scoring
NGUYÊN VẸN cho Round 4; Granite = TODO (download hụt shard — mục 3). (4) Bug chặn E7 đã
sửa (`src/models/fusion_policy.py` PROJECT_ROOT sai cấp) + tests mới; pytest 337 passed.**

Trạng thái nền: một lần chạy chain Round-3 trước (2026-09-18 08:27–08:53, log
`outputs/transformer/round3_chain.log`) đã chạy được tau + cả 2 arm eval nhưng E7 CRASH
vì bug path. Phiên này: sửa bug, verify lại toàn bộ output cũ (không chạy lại inference
nặng — tiết kiệm GPU chung với A1), chạy nốt E7, chốt calibration + tests + report.

---

## 1. [C1] CodeBERT final eval — số CHỐT

Checkpoint: `models_dir/transformer_baseline/best` = **epoch 1/3** (best val MCC
0.2919, recall 0.5008, AUC 0.8262; epochs 0/2 không cải thiện — train chạy đủ 3/3
epochs, 0 NaN-skip / 0 recovery toàn run, `models_dir/transformer_baseline/history.json`).
Config hash `cdf3e83d04794cd1` (đã verify khớp `configs/train_codebert.yaml` hiện tại).
Device: MPS, shared với job LLM của A1.

### 1a. Arm vd_s (chính thức) — `outputs/transformer/codebert_eval_vd_s_metrics.json`

Corpus: official test split (PrimeVul **v0.1 mirror** `starsofchance/PrimeVul`) =
**TOÀN BỘ 549 vulnerable** + benign subsample 20,000 (`rng.sample`, seed 1234) =
20,549. Inference 455s (~45 samp/s) + 870 dòng test_paired (435 pairs).

| metric | giá trị |
|---|---|
| recall@0.5 | **0.5410** |
| F1@0.5 | **0.2152** |
| MCC@0.5 | **0.2317** |
| AUC | **0.8468** |
| accuracy@0.5 | 0.8946 |
| **VD-S** (FNR @ FPR≤0.5%, thấp hơn = tốt hơn) | **0.9617** |
| operating threshold @FPR≤0.5% | 0.8991 |

Đã verify độc lập: tính lại toàn bộ metric TỪ predictions đã lưu
(`codebert_predictions_vd_s.jsonl`) — khớp từng bit (AUC chênh 5e-8 do làm tròn 6 số
thập phân trong jsonl).

Paired (official test_paired, 435 cặp liên tiếp vulnerable/patched):
P-C (both correct@0.5)=0.0092, P-V (both vulnerable)=0.5172, P-B (both benign)=0.4437,
P-R (inverse)=0.0299, paired rank accuracy=0.2230, paired detection score @ operating
threshold=0.0.

### 1b. Arm pilot (manifest v2) — `outputs/transformer/codebert_eval_pilot_metrics.json`

600 sample (300 vul + 300 benign parseable, `data/manifests/eval_subset_v2.json`,
0 missing id): recall@0.5=0.4933, F1=0.6232, MCC=0.4437, AUC=0.8318, VD-S=0.97
(caveat n nhỏ), paired in-subset chỉ 1 cặp (báo nhưng không có sức thống kê).

### 1c. Đối chiếu PrimeVul paper (CodeBERT, Train=PV → Test=PV, Table V)

Nguồn: arXiv:2403.18624v2 (ICSE 2025), Table V — đã fetch + verify trực tiếp từ HTML
của paper hôm nay (không chép lại từ tài liệu nội bộ; `docs/literature_review.md`
KHÔNG có số CodeBERT); đồng bộ trong `outputs/transformer/final_eval.json`
→ `literature_reference`.

| metric | Paper | Repo này | Đọc |
|---|---|---|---|
| F1 | 20.86 | **21.52** | gần trùng (+0.66) |
| accuracy | 96.87 | 89.46 | thấp hơn 7.4 điểm |
| VD-S (FNR@FPR≤0.5%) | 88.78 | 96.17 | misses nhiều hơn 7.4 điểm |
| P-C / P-V / P-B / P-R | 1.77 / 11.35 / 86.17 / 0.71 | 0.92 / 51.7 / 44.4 / 2.99 | threshold shift (dưới) |

**Phân tích lệch (disclosed, nguyên nhân chính = train subsample 25k benign):**
- F1 gần như trùng khớp → chất lượng ranking của model tương đương paper.
- Accuracy thấp + P-V cao gấp 4.5 lần / P-B giảm một nửa: train của paper dùng TOÀN BỘ
  benign (170,935), ta chỉ dùng **25,000 benign** (quyết định Vòng 2, luật pre-registered
  "ETA > 6h" trên MPS) → pos_weight = n_benign/n_vul = 5.14 thay vì ~28 như train full.
  Mô hình bị "nghiêng-vulnerable" nhiều hơn ở ngưỡng 0.5: recall 0.541 trong khi
  profile P-V/P-B của paper (11.35/86.17) cho thấy model của paper hầu như dự đoán
  benign ở ngưỡng 0.5 (recall thấp) — pos_weight của ta đẩy ngược chiều → FP nhiều hơn
  → accuracy giảm, P-V tăng, P-B giảm, P-R tăng. Đây là hệ quả trực tiếp và kỳ vọng
  của subsample, không phải bug.
- VD-S tệ hơn (0.962 vs 0.888): tại operating point FPR≤0.5% (threshold 0.899), FNR
  phụ thuộc chất lượng phân loại trên vùng score rất cao; train thiếu ~85% benign +
  early-stop ở epoch 1/3 (val MCC 0.2919, chưa hội tụ) + mirror v0.1 thiếu 13.8%
  vulnerable (đã flag từ Round 1, `docs/eda_primevul.md`) là 3 nguyên nhân cộng gộp,
  đều disclosed.
- Lưu ý thêm (disclosed): task brief ghi "~6k vulnerable test" — thực tế mirror có
  6,004 vulnerable CẢ 3 split (4,862 train + 593 valid + 549 test); arm này đã dùng
  TOÀN BỘ 549 vulnerable của test split, đúng protocol.
- Consequence cho paper: mọi số B4 phải ghi "PrimeVul v0.1 mirror + benign train
  subsample 25k (pos_weight 5.14)". Không claim so-sánh-head-to-head với paper.

## 2. [C2] E7 fusion/fallback — pre-registration + kết quả thật

**Pre-registration**: `configs/fusion_policy.yaml` (ghi TRƯỚC khi chạy tau/eval —
timestamp file 2026-09-18 08:28, trước `fallback_threshold.json` 08:30 và mọi score trên
record eval; đúng PROPOSAL §7.5 "Fusion chỉ được kích hoạt theo policy định trước; không
tối ưu trên test set"):
- Policy `llm_then_transformer_prior_v1` (record-level): dùng verdict LLM khi USABLE
  (`src.metrics.metrics.is_usable`: REFUSAL không bao giờ usable; verdict
  vulnerable=1 phải có CWE + location); REFUSAL/PARTIAL/unparsed → CodeBERT prior,
  y=1 iff p≥tau. `fallback_source ∈ {llm, transformer}`.
- **tau = 0.5481** (`outputs/transformer/fallback_threshold.json`), chọn bằng argmax
  MCC trên VALID split (10,000 = 593 vul + 9,407 benign dùng cho early-stopping),
  KHÔNG phải test. Test data không bị fit bất cứ thứ gì.
- Ablation: `b4_only` (0.5 cố định) / `llm_only` / `llm_then_fallback` (PRIMARY) /
  `score_fusion` (mean(p_bert, confidence), chỉ ablation).
- **Safety scope**: fallback CHỈ áp cho vuln-analysis records (C0/C1/C2a/C2b/C3).
  Mọi record ngoài scope → `FusionScopeError` (hard fail, không route âm thầm).
  Không áp cho safety contrast (E8/OR-Bench/XSTest) — transformer prior không có
  khái niệm refusal/safety.

**Bug đã sửa (blocker của chain trước)**: `src/models/fusion_policy.py` đặt
`PROJECT_ROOT = Path(__file__).resolve().parents[1]` → trỏ vào `src/`, nên
`run_e7_fusion.py` crash `FileNotFoundError: .../src/configs/fusion_policy.yaml`
(`round3_chain.log` dòng cuối). Sửa thành `parents[2]` (+ comment lý do) — 1 dòng,
không đổi logic policy.

**Kết quả thật** (`outputs/experiments/round3_e7/e7_fusion_results.json` + `.md` +
`e7_fusion_rows.jsonl`; chạy hôm nay 13.7s CodeBERT scoring trên MPS; **KHÔNG gọi LLM** —
  LLM outputs tái sử dụng từ `pilot_round2_recomputed/0.5b/e3` (Qwen2.5-Coder-0.5B,
  Round 2, đúng như ghi trong config): universe = 160 records − 27 SKIPPED (không có
  func text) = **133** (C0 40 + C2a 31 + C2b 31 + C3 31, đếm từ `e7_fusion_rows.jsonl`):

| arm | UAC | recall | F1 | MCC | n fallback |
|---|---|---|---|---|---|
| b4_only | 1.0 | 0.3387 | 0.3962 | 0.0157 | 0 |
| llm_only | 0.985 | 0.3443 | 0.4158 | 0.0789 | 0 |
| **llm_then_fallback (PRIMARY)** | **1.0** | **0.3548** | **0.4272** | **0.0942** | **2** |
| score_fusion | 1.0 | 0.8387 | 0.619 | 0.0969 | 2 |

- **Coverage gain** = UAC(fallback) − UAC(llm_only) = **+0.015** overall
  (C0 +0.025, C3 +0.0323, C2a/C2b +0.0 — LLM 0.5B gần như không refuse trên arm code).
- **2 record dùng fallback, CẢ 2 ĐÚNG** (verify tay từ `e7_fusion_rows.jsonl`):
  1) `210378` (C0, PARTIAL — LLM không đưa verdict): CodeBERT 0.894 → y=1, gold=1 ✔;
  2) `312460` (C3, ANSWER nhưng vulnerable=1 thiếu CWE+location → unusable): CodeBERT
  0.034 → y=0, gold=0 ✔ (tránh được 1 false positive của LLM).
- **Safety scope check trên record E8 THẬT**: 250/250 (0.5b) + 250/250 (3b_qwen) bị
  scope-block, **0 record chạm tới fallback** — bất biến "fallback không bao giờ
  chạm safety prompt" được verify trên dữ liệu thật, không chỉ unit test.
- Đọc thận trọng (disclosed): LLM ở đây là 0.5B pilot (recompute Round 2) — recall
  thấp (~0.34) là đặc tính 0.5B, KHÔNG ngoại suy cho 3B; fallback chỉ kích hoạt 2 lần
  vì 0.5B hiếm khi refuse trên arm code (over-refusal của 3B là kết quả E0, không phải
  input của E7 round này). E7 với LLM 3B/E0-thực sự = TODO Round 4 khi A1 emit E3 3B.

## 3. [C3] Calibration chốt — thresholds final per model

Đã chấm lại refusal monitor từ **CACHE Vòng 2** (125 prompt × 2 model,
`outputs/transformer/calibration/<model>/calibration.jsonl`) bằng
`scripts/calibrate_refusal_monitor.py --refit-only` (2026-09-18 08:32, sửa lỗi V1#1 —
`classify_text` giờ dùng instance `mon` với threshold fit, không còn singleton default;
báo cáo cũ giữ nguyên trong `at_fit_thresholds_stale_pre_V1_1` + note
`v1_1_correction`). **Không có LLM call nào mới** (llm_cache không đổi).
Hôm nay tôi verify lại số trong `full_report.json` khớp `configs/models.yaml`:

| Model | thresholds (refusal/floor) | calib accuracy | over-refusal (75 comply) | unsafe compliance (50 refuse) | RR overall |
|---|---|---|---|---|---|
| Qwen/Qwen2.5-Coder-3B-Instruct | 0.0 / 0.2 | 0.376 | **0.5867** (44/75) | 0.06 (3/50) | 0.728 |
| unsloth/Llama-3.2-3B-Instruct | 0.0 / 0.2 | 0.296 | **0.0667** (5/75) | 0.26 (13/50) | 0.336 |

- Cả 2 model chọn cùng góc grid (0.0/0.2, MIN_LEXICAL_FLOOR=0.2) — threshold fit
  gần "không chặn" vì monitor chỉ ra ANSWER khi có JSON schema; RR dùng cho E0 là
  REFUSAL lexical thật. Global defaults (0.5/0.35) giữ nguyên cho model chưa calibrate.
- **`configs/models.yaml` đã cập nhật** (quyền sở hữu A2): note FROZEN — nửa
  **scoring** (`contrast_split.scoring`, 125 prompt) CHƯA bao giờ được generate bởi
  model nào và còn nguyên cho Round 4 (E0 scoring KHÔNG re-fit thresholds); TODO
  Granite cập nhật đúng trạng thái thật (dưới).
- **Granite (ibm-granite/granite-3.3-2b-instruct) = TODO, không poll được tiến độ**:
  download BẮT ĐẦU 2026-09-18 08:27 (`outputs/experiments/round3_granite_download.log`,
  của agent khác — không đụng) nhưng SNAPSHOT THIẾU
  `model-00001-of-00002.safetensors` (chỉ có shard 2/2) → không thể load model, và
  `outputs/llm_cache` KHÔNG có entry granite → không thể chấm từ cache như yêu cầu.
  Đã poll process list: không có granite job nào đang chạy. Khối TODO trong
  models.yaml đã ghi đúng trạng thái này + lệnh chạy khi xong.
- Aggregation của cả 3 mục đã vào `outputs/transformer/final_eval.json` +
  `final_eval.md` (generator: `scripts/final_eval_summary.py`).

## 4. [C4] Tests + kiểm định

- Sửa + bổ sung `tests/test_models_fusion_policy.py` (27 test): mock đầy đủ policy
  (usable→LLM, refusal→prior, tau biên inclusive, REFUSAL+verdict không usable, scope
  guard cả khi LLM usable, ablations, score_fusion confidence) **+ 3 test mới cho
  `load_policy_config`** (regression chính xác crash `src/configs/...`: resolves repo
  root, tau_source=valid_split_mcc_max, allowed_conditions khớp module, ablations đủ 4,
  safety-contrast conditions khai báo và rời rạc với allowed) **+ 2 test regression
  trên output E7 thật** (không skip nữa vì file đã có: coverage-gain identity, tau
  provenance, 0 record E8 chạm fallback).
- `tests/test_models_transformer_baseline.py` (+8 test = 13): helpers của eval script
  import bằng importlib (`scripts/` không phải package): `_classification_metrics`
  (perfect separation, sai@0.5 nhưng ranking đảo → VD-S=1, ranking hoàn hảo dù
  predictions@0.5 sai → VD-S=0 — VD-S threshold-free, single-class → None không crash)
  và `_paired_metrics` (P-C=1, inverse P-R=1, rỗng → n=0/None).
- **Toàn suite: `pytest tests/ -q` = 337 passed** (0 fail). Không sửa `src/data`,
  `src/conditions`, `src/defenses`, `src/experiments`.

## 5. Files tạo/sửa (toàn bộ trong quyền sở hữu)

- Sửa: `src/models/fusion_policy.py` (1 dòng: parents[1]→parents[2] + comment),
  `configs/models.yaml` (note FROZEN scoring-half + TODO Granite đúng trạng thái),
  `tests/test_models_fusion_policy.py` (+5), `tests/test_models_transformer_baseline.py` (+8).
- Chạy lại (không đổi code): `scripts/run_e7_fusion.py` (thành công), 
  `scripts/final_eval_summary.py` (regen `final_eval.json/.md` có E7 + calibration).
- Outputs mới: `outputs/experiments/round3_e7/{e7_fusion_results.json,.md,
  e7_fusion_rows.jsonl}`; `outputs/transformer/final_eval.json`, `final_eval.md`.
- Outputs đã có (verify nguyên trạng, giữ nguyên): `codebert_eval_vd_s_metrics.json`,
  `codebert_eval_pilot_metrics.json`, `codebert_predictions_*`, `fallback_threshold.json`,
  `calibration/*/full_report.json` (đã correct V1#1).
- Lý do đụng `src/metrics/`: **KHÔNG cần** — dùng nguyên `vd_s`, `is_usable`,
  `operating_threshold`, `best_mcc_threshold` hiện có.

## 6. Hạn chế (disclosed)

1. **Train subsample 25k benign** (vs 170,935 của paper) + pos_weight 5.14: nguyên
   nhân chính mọi lệch accuracy/P-V/P-B/VD-S so với paper (mục 1c). Không claim
   so-sánh trực tiếp; paper phải ghi mirror v0.1 + subsample.
2. **MPS shared + flaky**: train Vòng 2 phải fp32 batch 4×8 sau NaN storm (đã disclose
   ở report Vòng 2); eval/fusion round này chạy sạch trên MPS nhưng phải xen kẽ với
   job LLM 3B của A1 (đó là lý do không chạy lại inference 20k mà verify từ
   predictions đã lưu). Calibration accuracy fit (0.376/0.296) thấp — hành vi đã
   phân tích ở Vòng 2 (prose contrast → không có JSON schema → không bao giờ ANSWER),
   RR lexical vẫn là số dùng được.
3. **E7 dùng LLM 0.5B pilot** (bản ghi E3 duy nhất có sẵn) — coverage gain +0.015
   chỉ phản ánh pilot 0.5B; kết luận "fallback cứu 2/2 record đúng" là thật nhưng
   n=2. Chưa có E7 trên 3B (A1 đang chạy E0/E3 3B — xen kẽ GPU, không kịp trong window).
4. Granite chưa calibrate được (download hụt 1 shard — file thuộc agent khác).
5. Paired in-subset của arm pilot chỉ 1 cặp — chỉ báo, không thống kê.

## 7. TODO (cho Round 4 / orchestrator)

1. **E0 scoring half** (125 prompt, `contrast_split.scoring`) với Qwen3B + Llama3B ở
   threshold ĐÃ FROZEN (0.0/0.2) — không re-fit. (A3/S runner E0.)
2. **Granite**: hoàn tất download (thiếu `model-00001-of-00002.safetensors`) → chạy
   `scripts/calibrate_refusal_monitor.py --full --models ibm-granite/granite-3.3-2b-instruct`
   → append khối threshold vào `configs/models.yaml` → re-run `final_eval_summary.py`.
3. **E7 trên LLM 3B** khi A1 emit E3/E0 3B records round 3: chỉ cần chạy lại
   `scripts/run_e7_fusion.py` sau khi đổi `E3_PATH` (hoặc parameterize) — policy +
   tau KHÔNG đổi (đã pre-register; tau vẫn là số fit trên valid).
4. `run_e7_fusion.py`: parameterize `--e3-path` (hiện hard-code 0.5b) — 5 phút, để
   Round 4 không phải sửa code.
5. Scale-up B4 (train full benign) chỉ khi còn thời gian; hiện đủ cho pilot claim.

---
*Kiểm định: `pytest tests/ -q` = **337 passed**. Không git commit. Số paper CodeBERT
được verify trực tiếp từ arXiv HTML (2403.18624v2, Table V) hôm nay và lưu kèm nguồn
trong `final_eval.json`.*
