# F Report — Round 8 (Final: bug-fix + real rerun + KB + safety + paper2)

Ngày: 2026-09-22. Vai trò: Tác nhân cuối (F). Đầu vào: audit V1/V2 (đã xác
nhận bug), W1/W2 outputs. Nguyên tắc: chỉ sửa bug được V1/V2 xác nhận +
AMENDMENT-1; KHÔNG git commit; mọi số trong report này truy vết tới file
output thật (mock=false toàn bộ kết quả FL/KB/safety; kết quả v1 cũ được
lưu hồ sơ, không xóa).

## 1. LÀM GÌ (theo thứ tự ưu tiên tasking)

### P1a — dataset.py flat-layout bug (V1#1) — FIXED, chọn phương án REGENERATE
- `packguard/dataset.py::_dd_samples` giờ xử lý CẢ 2 layout DataDog:
  `pkg/<ver>/<file>.zip` và `pkg/<file>.zip` (single-version; version =
  archive stem, sample_id hậu tố `-flat-`, disclosed trong
  `manifest["selection"]["malicious"]`).
- Manifest tạo version mới `data/packguard/manifests/dataset_v2.json`
  (v1 giữ nguyên làm artifact lỗi cho audit).
- **Kết quả: 603 samples, KHÔNG phải 602 như V1 dự đoán** — khác biệt được
  giải thích: có 6 flat zip, không phải 5. 5 package V1 liệt kê
  (282828282828282828, aiiohttp, kayauthgen, libssl, spookyimagelogger) +
  **flat zip của `xolokvhcqvifyf`** — package này ĐÃ được chọn qua
  version-dir zip của nó, và chính sách "giữ TOÀN BỘ archive của package
  được chọn" giữ thêm flat zip (sha256 khác, 0 duplicate bị dedupe).
  Counts v2: npm 298 mal + 123 ben, pypi **92** mal + 90 ben = 603
  (pypi-malicious_intent 71→77).

### P1b — select_files bug (V1#2) — FIXED + re-extract v2
- `packguard/features.py::select_files` v2: (1) package.json + setup.py
  trước; (2) **npm install-hook targets force-select** — resolve trên FULL
  file list TRƯỚC cap 12 (v1 resolve sau cap → mất target); (3) tối đa 1
  `__init__.py` (shallowest, tie alphabetical); (4) slot còn lại chỉ nhận
  code file (.py/.js/.mjs/.cjs), non-hidden, KHÔNG meta (`.coveragerc`,
  `ci.yaml`, `*.md`, LICENSE...), sort (size desc, path asc).
- SCHEMA_VERSION 1.0.0 → **1.1.0** (chỉ selection đổi, mapping table
  nguyên vẹn). Mapping tables + caps (12 file / 100 KB) KHÔNG đổi.
- Re-extract toàn bộ 603 → `features_v2|graphs_v2` (0 extraction error):
  coverage with-graph 468/597 (78.4%) → **500/603 (82.9%)**; pypi-benign
  **55.6% → 70.0%** (27/90 empty; 13/40 empty cũ được "cứu", khớp bề
  trên với dự đoán 16/40 của V1 — khác do cap-slot động; 24 empty còn lại
  đúng là không có mapped call).

### P1c — eval loader (V2 MEDIUM issue) — FIXED
- `packguard/fl.py::load_feature_records` mới: glob `features_v*.jsonl`
  (tag cao nhất) + legacy names; nhận CẢ flat schema (18 feature top-level
  → wrap thành `features.graph`) lẫn nested; **drop + đếm row có
  extraction_error** (không train silently); **api_calls derive từ
  graphs_v2.jsonl.gz** (unique node APIs/sample) vì features rows không
  có — mở đường cho KB ablation. Lệnh pre-reg
  `python -m packguard.eval --config configs/packguard_fl.yaml` giờ chạy
  được trên data thật.
- `eval.py` thêm per-ecosystem + per-coverage subgroup metrics vào mọi run
  row (nghĩa vụ prereg D4 mà V2 note là chưa thực hiện).

### P1d — GROUP-SPLIT làm PRIMARY metric — DONE
- `packguard/fl.py::make_group_split`: chia theo package-family
  (label-stratified ở mức package; assert zero overlap group); random split
  GIỮ làm secondary. Config `data.split: group`. Ghi vào **AMENDMENT-1**
  trong docs/packguard_prereg.md (kèm: dataset 603, features v2, clients=2
  thực tế, KB protocol 3B, safety protocol + quyền giảm scope).

### P1e — RERUN THẬT (mock=false) — DONE
Chạy `scripts/packguard_final_runs.py` (dùng primitives của fl.py;
TF-IDF fit trên TRAIN của từng split — không vocabulary leakage):
31 rows thật → `outputs/packguard/fl/results.jsonl` (bản v1-features của
V2 lưu `results_featuresv1_archived.jsonl`) + `final_runs_v2.json`.

**Bảng chính — PRIMARY group split (test n=129, 88 mal; LR 15 rounds):**

| run | P | R | F1 | AUC | npm F1 | pypi F1 |
|---|---|---|---|---|---|---|
| graph FedAvg | .894 | .955 | .923 | .916 | .933 | .875 |
| graph FedProx(µ=.01) | .894 | .955 | .923 | .916 | .933 | .875 |
| graph centralized | .903 | .955 | **.928** | **.926** | .940 | .875 |
| graph per-client (macro) | — | — | .917 | .909 | — | — |
| tfidf FedAvg | .682 | 1.000 | .811 | .959 | .880 | .588 |
| tfidf centralized | .763 | .989 | .861 | .960 | .885 | .757 |
| tfidf per-client (macro) | — | — | .842 | .918 | — | — |

**Secondary random split (test n=120):** graph FedAvg .870/.862 (F1/AUC),
central .834/.871; tfidf FedAvg .784/.904, central .831/.900. Per-eco +
with/empty-graph có đủ trong results.jsonl (subgroup_metrics).

**Primary comparisons (FedAvg vs centralized, accuracy@0.5):**
- group/graph: McNemar exact b01=0 b10=1 **p=1.0**; bootstrap Δ=−.008
  [−.023, .000] → KHÔNG khác biệt.
- group/tfidf: b01=1 b10=14 **p=.001**; Δ=−.101 [−.155, −.047] → FL THUA
  (minority client sụp: pypi F1 .588 vs .757).
- random/graph: p=.063; Δ=+.041 [+.008, +.083] (bootstrap loại 0, McNemar
  không đạt .05) → mixed, n pilot.
- random/tfidf: p=.007; Δ=−.107 [−.182, −.041] → FL thua.

**Ablations:** DP σ=0.1 (ε≈9.7/round, single-query): F1 .915 (−.8pt, giá
rẻ); MLP = LR (cùng metrics); no-empty arm (n=500): FedAvg .872 /
central .821 — empty rows mang tín hiệu eco, disclosed.
FedProx ≡ FedAvg chính xác (µ=.01 không đủ đổi quỹ đạo — nhất quán V2).

**Finding trung thực đáng chú ý:** "FedAvg tổn thương client thiểu số"
của V2 (pypi F1 .57) **BIẾN MẤT** sau khi fix features (pypi .875 cả FL
lẫn central, group split) → harm đó là artifact của feature bug, không
phải bản chất FL trên data này. Paper ghi rõ như một retracted finding.

### P2 — KB THẬT 3B — DONE (scope giảm 120→60, lý do wall-clock)
- `scripts/packguard_build_kb.py`: universe = unique APIs trong
  **graphs_v2** (đúng yêu cầu, không phải features) = **137 unique; 122
  chưa có trong seed**; classify top 60 theo document frequency bằng
  **Qwen/Qwen2.5-Coder-3B-Instruct** qua LLMKBBuilder (cache/refusal-gate):
  **60/60 classified, 0 refusal, 0 retry, 0 UNSURE** (0.5B cũ: 8/10
  UNSURE — chốt 3B); ~15s/call MPS; 22/60 trung gian lấy từ LLM cache khi
  restart scope (không tính lại tiền).
- KB state mới: `outputs/packguard/kb/kb_v0001.jsonl` (80 entries = 20
  seed + 60 `llm:Qwen2.5-Coder-3B`), meta `kb_build_v2_meta.json`;
  **kb_v0001 cũ (0.5B fake-api smoke) archived thành
  `fixture_smoke_kb_v0001.jsonl`** — KB production sạch fixture.
- **Ablation KB on/off** (group split, `--with-kb`): FedAvg F1 .923→.922
  (AUC .916→.911, neutral); **centralized F1 .928→.938 (AUC .926→.932),
  toàn bộ gain ở client thiểu số: pypi F1 .875→.966** (subgroup n=29 —
  chỉ ra xu hướng, không claim significant). 62 API đuôi chưa vào KB bị
  đếm unsure theo construction (disclosed).

### P3 — SAFETY BATCH THẬT — DONE (scope giảm 30→16→10, lý do wall-clock)
- `scripts/packguard_safety_batch.py`: sample THẬT từ dataset_v2
  (stratified mal/ben, seed 20260922; text = code đã chọn của package,
  2500 ký tự cắt theo dòng), **P2 inject advisory comment vào file THẬT**
  — sample không pass gate `check_semantics` bị thay từ pool TRƯỚC khi
  sinh (pool scan: 34 scanned, 16 gate-pass khiDry-run n=8/class).
- Matrix: **n=10 (5 mal + 5 ben) × 3 arm (P0/P1/P2) × 2 model
  (Llama-3.2-3B fitted-threshold, granite-3.3-2b fallback-threshold
  disclosed) = 60 gen**, resume-safe.
- Metrics RR/flip/FP-bias + rule pre-reg: `outputs/packguard/safety/
  safety_batch.jsonl` + `safety_metrics.json` (pooled + per-model) —
  số cuối cùng thấy ở §5.

### P4 — PAPER2 — DONE (compile exit 0)
- `paper2/main.tex` (acmart, tectonic) + `paper2/refs.bib` (chỉ entry đã
  verify của W1 + companion RefuseGuard). Đủ cấu trúc tasking: Abstract /
  Intro (3 threats + package domain) / Related (DONAPI USENIX24, Cerebro
  TOSEM24, MalGuard USENIX25 hedge venue, Ladisa S&P23, VulFL preprint,
  SecurityAI, RefuseGuard line) / Method / Setup (603 disclosed, group
  split primary, pilot limits) / Results (FL vs central vs per-client,
  per-eco, graph vs TF-IDF trung thực KỂ CẢ khi tfidf thắng AUC; KB
  ablation; safety arm table) / Discussion (khi nào graph thua text;
  retracted FedAvg-minority-harm; safety transfer) / Conclusion +
  Limitations. Mọi số có comment `% SRC: <file>`.
- Compile: `tectonic main.tex` → **main.pdf 104 KB, exit 0**.

## 2. FILES (absolute)
Code sửa (bug-fix được xác nhận):
- /Users/macbook/.zcode/workspace/default/refuseguard/packguard/dataset.py
- /Users/macbook/.zcode/workspace/default/refuseguard/packguard/features.py
- /Users/macbook/.zcode/workspace/default/refuseguard/packguard/fl.py
- /Users/macbook/.zcode/workspace/default/refuseguard/packguard/eval.py
- /Users/macbook/.zcode/workspace/default/refuseguard/packguard/schema.py (chỉ SCHEMA_VERSION)
Code mới:
- /Users/macbook/.zcode/workspace/default/refuseguard/scripts/packguard_final_runs.py
- /Users/macbook/.zcode/workspace/default/refuseguard/scripts/packguard_build_kb.py
- /Users/macbook/.zcode/workspace/default/refuseguard/scripts/packguard_safety_batch.py
Config/docs:
- configs/packguard_fl.yaml (split: group, dp.sigma 0.1)
- docs/packguard_prereg.md (AMENDMENT-1)
Data/outputs:
- data/packguard/manifests/dataset_v2.json (603; v1 giữ nguyên)
- outputs/packguard/features/{features_v2.jsonl,graphs_v2.jsonl.gz,text_v2.json,extraction_report_v2.json}
- outputs/packguard/fl/{results.jsonl,final_runs_v2.json,results_featuresv1_archived.jsonl}
- outputs/packguard/kb/{kb_v0001.jsonl,kb_build_v2_meta.json,fixture_smoke_kb_v0001.jsonl,llm_cache/}
- outputs/packguard/safety/{safety_batch.jsonl,safety_metrics.json}
- paper2/{main.tex,refs.bib,main.pdf}
- reports/round8/F_report.md (file này)

## 3. CÁCH CHẠY
```
cd /Users/macbook/.zcode/workspace/default/refuseguard
.venv/bin/python -m packguard.dataset --root data/packguard/raw --out data/packguard/manifests/dataset_v2.json
.venv/bin/python -m packguard.features --manifest data/packguard/manifests/dataset_v2.json --outdir outputs/packguard/features --tag v2
PYTHONPATH=$PWD .venv/bin/python scripts/packguard_final_runs.py --skip-text-cache --with-kb
HF_HOME=$PWD/models_dir/hf PYTHONPATH=$PWD .venv/bin/python scripts/packguard_build_kb.py --limit 60
HF_HOME=$PWD/models_dir/hf PYTHONPATH=$PWD .venv/bin/python scripts/packguard_safety_batch.py --n 10
cd paper2 && tectonic main.tex
```

## 4. LỆCH CHUẨN / DISCLOSE (honest)
1. **603 ≠ 602 (V1)**: giải thích đầy đủ ở §1 P1a (flat zip thứ 6 của
   xolokvhcqvifyf); policy không đổi, chỉ bug builder được fix.
2. **KB scope 120→60** (từng chạy 120 rồi dừng ở ~40 để restart 60 vì
   ~15-25s/call; 22 cache hits không tính lại). 62 API đuôi không có KB →
   kb_unsure_ratio tính chúng là unsure (by construction).
3. **Safety scope 30→16→10**: throughput đo được ~30s/gen (max_new_tokens
   384 trong config FROZEN, không giảm để giữ arms đúng pre-reg); n=10 là
   matrix HOÀN CHỈNH đầu tiên đạt được trong budget (60/60 gen, 0 missing);
   realized n ghi ở meta + metrics. Resume-safe: 5 gen trùng giữa các lần
   restart lấy từ file/cache, stale records của draw cũ bị lọc theo
   sample-set (không lẫn n).
4. **Safety snippets 2500 ký tự** (cắt theo dòng): 2 sample npm có code
   rất ngắn (63 ký tự) — thực tế package chỉ có file cực nhỏ; disclosed.
5. MLP ≡ LR và FedProx ≡ FedAvg (µ=.01): metric trùng khớp — không bịa,
   đúng bản chất (đã unit-test µ lớn có tác dụng).
6. paper2 là DRAFT pilot: single-seed, simulation-only FL/DP/secagg,
   no GNN, benign popularity-derived — Limitations liệt kê đủ.

## 5. KẾT QUẢ SAFETY CUỐI (n=10 THẬT = 5 mal + 5 ben, seed 20260922; 60 gen, 60/60 parse được verdict)

Pooled (2 model × 10 sample; nguồn `safety_metrics.json`):

| arm | RR | ΔRR | McNemar p | verdict-flip ben→mal | FP-bias (benign) | blocking? / corrupting? |
|---|---|---|---|---|---|---|
| P0 neutral | .00 | — | — | — | .2 | — / — |
| P1 offensive-wording | .00 | +0.00 | 1.0 | 1/20 | .3 | no / **yes** |
| P2 advisory-in-package | .00 | +0.00 | 1.0 | 4/20 | **.6** | no / **yes** |

Per-model: llama-3.2-3B (threshold fitted): P2 flip 1/10, FP-bias .0→.2;
granite-3.3-2b (threshold fallback, disclosed): P2 flip 3/10, FP-bias
.4→**1.0** (mọi benign bị gắn nhãn malicious dưới advisory comment).
P1 riêng granite: 1 flip.

**Đọc trung thực:** (1) RR=0 MỌI arm/model — không có refusal nào, khớp
RefuseGuard (RR≈0 open-2-7B, defensive intent) → blocking_supported=false
toàn bộ; (2) **kênh corruption TÁI XUẤT dưới dạng FP**: P2 (nội dung
không tin cậy trong package) đẩy FP-bias trên benign .2→.6 (granite →1.0)
— đúng "verdict-corruption về phía vulnerable" của RefuseGuard, chuyển
tải sang domain package; model nhỏ corruptible hơn (nhất quán RG);
(3) n=10 → chỉ là bằng chứng đo-được + hướng, KHÔNG phải effect size.

## 6. SELF-TEST THẬT
- `pytest tests/ -q` sau toàn bộ fix (chạy CUỐI, gồm cả sửa eval.py):
  **615 passed / 0 failed** (79.9s) — trong đó 3 test từng fail do fix
  của tôi (group-split assert, select_files getsize trên path giả) đã
  được sửa và pass.
- FL/KB/safety: toàn bộ row results.jsonl có `mock: false` + seed
  20260922 + config_sha16; summary v1 (V2) archived chứ không xóa.
- Re-extract v2: 603/603 rows, 0 extraction error (extraction_report_v2.json).
- Compile paper2 (final, đủ bảng): tectonic exit 0 (main.pdf 108 KB).

## 7. TODO (cho vòng sau / giai đoạn hệ thống)
1. Multi-seed + power analysis (CI hiện ±.05-.08 F1 — mọi kết quả "không
   khác biệt" chỉ là pilot-level).
2. FedProx µ sweep (0.1/1.0) + client-weighting (đối chứng FedAvg
   minority — nay là câu hỏi mở sau khi retracted finding).
3. KB: hoàn tất 62 API đuôi; confidence calibration; KB cho GNN labels.
4. Safety: n≥30, 3 model, P2 advisory biến thể đa dạng hơn 1 comment,
   composition proof cho DP R-round.
5. GNN trên behavior graphs; ecosystem thứ 3 (Maven); benign audited.

## 8. VERDICT TỔNG DỰ ÁN 2 (thẳng thắn)
- **Khoa học dữ liệu: đạt chuẩn pilot trung thực.** Dataset provenance
  603/603 sạch (audit V1 + fix), mọi số traceable, mock/real tách bạch,
  bug đều được fix CÓ CHỨNG RUN LẠI (không dán số cũ). finding FL-vs-
  central = null trên graph / có nghĩa trên tfidf; graph-vs-text
  split-decision; KB neutral-FedAvg / +gain-central-minority; safety
  pipeline đo được trên package thật. Đây là một hài lòng ở mức
  "workshop + nền tảng cho paper đầy đủ".
- **Chưa đủ Q1.** Khoảng cách cụ thể: (1) n pilot nhỏ, single seed — mọi
  p-value hiện tại không sống qua review Q1; (2) FL chỉ 2 client thực,
  simulation-only secagg/DP không có composition proof; (3) TF-IDF thắng
  AUC → cần thêm baseline text mạnh (CodeBERT) và GNN để claim
  representation; (4) safety n=10 chưa đủ kiện "third threat" như một
  contribution đứng độc lập; (5) benign labels popularity-derived —
  reviewer Q1 sẽ bắt. Đường tới Q1: multi-seed + n lớn hơn (dataset pool
  DataDog 14k cho phép), GNN + CodeBERT baseline, Maven, audited benign,
  safety n≥100. Ước lượng 2-3 vòng nữa với GPU thời gian lớn hơn.
- **Quy trình 8 vòng: mô hình audit→fix→rerun hoạt động tốt** — 2 bug
  "âm thầm" (flat layout, select_files) đều là loại mà test suite không
  bắt được, chỉ audit mở-archive mới thấy; giữ nguyên cơ chế này cho dự
  án sau.
