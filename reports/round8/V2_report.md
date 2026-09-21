# V2 Report — Round 8 (Adversarial audit W2: FL / KB / safety / eval + CHẠY THẬT lần đầu)

Ngày: 2026-09-21. Vai trò: audit adversarial W2 (PackGuard, vòng 8) + chạy thật
pipeline FL trên features thật của W1 (`features_v1`) như bằng chứng audit.
Nguyên tắc: KHÔNG sửa code người khác (không file nào của W1/W2 bị thay đổi),
KHÔNG git commit; mọi số dưới đây truy vết được tới output file thật. Mock
backup của W2 được giữ tại `/tmp/v2_backup_mock_results.jsonl` +
`/tmp/v2_backup_mock_summary.md` trước khi ghi đè bằng kết quả thật.

---

## 0. VERDICT W2: **PASS — kèm ISSUES** (không có CONFIRMED BUG về toán FL)

- **ISSUES [MEDIUM] — harness không đọc được data thật của W1 (đã chạy thử để
  chứng minh)**: lệnh pre-reg `python -m packguard.eval --config
  configs/packguard_fl.yaml` FAIL `FileNotFoundError` dù data CÓ sẵn, vì
  `packguard/fl.py:load_feature_records` chỉ nhận
  `features.jsonl|features.parquet` còn W1 ghi `features_v1.jsonl|features_v1.parquet`;
  và ngay cả khi đúng tên file, schema W1 là PHẲNG (18 feature ở top-level)
  trong khi harness đòi lồng nhau `features: {block: {name: value}}` +
  `api_calls`. Ba điểm lệch: (1) tên file, (2) flat-vs-nested, (3) thiếu
  `api_calls` → ablation KB sẽ PENDING vĩnh viễn nếu chỉ bật config. V2 đã
  chạy thật bằng adapter ở `/tmp` (không sửa code) — xem §3.
- **ISSUES [LOW] — thiết kế client trong pre-reg không khớp data thật**:
  prereg §FL nêu 3 client `npm_only/pypi_only/mixed`; data thật chỉ có 2
  ecosystem (npm/pypi) → FL thật chạy 2 client, không có client "mixed".
  Non-IID thật NHẸ hơn fixture giả định rất nhiều: malicious-rate sau split là
  **npm 0.7104 (n=335) / pypi 0.4859 (n=142)**, không phải 0.84/0.15/0.52 như
  fixture. Cần AMENDMENT hoặc disclose trong paper.
- **ISSUES [LOW] — ablation TF-IDF "pre-registered" nhưng không thể chạy từ
  data W1**: features_v1 không có block `tfidf`; harness có đường pipeline
  nhưng thiếu feature. V2 tự dựng TF-IDF post-hoc từ raw code (§3.4).
- Điểm PASS đáng chú ý: 16/16 property-test toán FL độc lập PASS (§2); pytest
  **615 passed / 0 failed** (531 cũ + 49 W2 + 35 W1); mock-hygiene đúng 100%
  (9/9 row fixture mock=true, 12/12 row thật mock=false, đủ seed + config
  sha16); KB/safety gate đúng bản chất (§5, §6).

## 1. CONFIRMED BUGS

**Không có bug toán FL.** Toàn bộ 16 property test độc lập (script V2, không
dùng test của W2) PASS — chi tiết §2. Defect duy nhất xác nhận là **lỗi tích
hợp harness↔data (ISSUE MEDIUM ở §0)**: bản chất là contract mismatch giữa 2
người viết, không phải bug thuật toán; hệ quả thực tế là lệnh pre-reg không
chạy được trên data thật cho tới khi có loader fix (vài dòng, ai sở hữu
`packguard/fl.py` — W2/F — sửa).

## 2. FL MATH — kiểm chứng độc lập (script `/tmp/v2_fl_math_test.py`, 16/16 PASS)

| Property | Kết quả |
|---|---|
| FedAvg 2 client bằng nhau = trung bình trọng số | PASS (maxdiff 6e-08, float32 ulp) |
| FedAvg trọng số theo n_samples (3:1 → (3p1+p2)/4) | PASS (exact) |
| Secure-agg mask cancel BITWISE 2 client | PASS (resid = 0.0 exactly) |
| Secure-agg ≥3 client residual ≤1e-5 (3 và 4 client) | PASS (2.4e-07 / 4.8e-07) |
| secure_aggregate == fedavg_weighted (2/3/4 client) | PASS (≤1.5e-08) |
| Chạy FL đầy đủ: đường secure-agg == đường FedAvg thuần | PASS (probs identical) |
| FedProx: mu 0→0.01→0.1→1.0 kéo update về global đơn điệu | PASS (d=0.506/0.503/0.480/0.308) |
| mu=0 + global_params == plain SGD (prox không tác động) | PASS (bitwise) |
| DP clip: norm 30 → đúng 1.0; dưới clip không đổi | PASS |
| DP noise: empirical std = 0.04994 ± ~5% với sigma=0.05 (4000 draws) | PASS |
| ε công thức khớp tính tay: 96.8961 = √(2·ln(1.25/1e-5))/0.05 | PASS |
| ε giảm khi sigma tăng; full-run determinism | PASS |

Ghi chú audit: DP sensitivity dùng C=clip=1.0 cho query-trung-bình là bound
BAO QUÁT (đúng chiều an toàn); ε=484.48/round ở sigma mặc định 0.01 ≈ không có
privacy thực dụng — W2 đã disclose trung thực trong report + prereg.

## 3. KẾT QUẢ CHẠY THẬT (bằng chứng audit — mock=false)

Chuỗi lệnh thật:
1. `.venv/bin/python -m packguard.eval --config configs/packguard_fl.yaml`
   → **FAIL `FileNotFoundError`** (chứng minh ISSUE MEDIUM) — output giữ trong
   log phiên; đúng thông báo "chờ W1" nhưng data W1 thực tế đã có.
2. Adapter V2 `/tmp/v2_build_tfidf.py`: đọc manifest
   `data/packguard/manifests/dataset_v1.json` → giải nén text code thật từ
   597 archive (zip pwd `infected` / tgz / sdist / 7 wheel — xử lý cả .whl),
   caps giống W1 (12 file/100KB); 2 sample text rỗng (disclose); TF-IDF
   sklearn (max_features=1000, min_df=2, sublinear_tf, **fit trên TRAIN
   thôi** theo split tất định của chính W2, tránh vocabulary leakage) → ghi
   `/tmp/v2_audit_features/features.jsonl` với 2 block `graph` (18 feature W1
   nguyên vẹn) + `tfidf` (1000 dim, post-hoc).
3. `.venv/bin/python -m packguard.eval --config configs/packguard_fl.yaml
   --features-dir /tmp/v2_audit_features --out-dir outputs/packguard/fl` →
   **chạy thật 3.5s, mock=False, pending=1 (KB disabled trong config)**.
   Provenance: seed 20260922, config_sha16 **196c560fcb98d8fb** (trùng sha
   run fixture của W2 — cùng config), 12/12 row có meta đầy đủ.

### 3.1 Bảng FL chính (global held-out test n=120, 77 malicious; LR, 15 rounds)

| run | P | R | F1 | AUC |
|---|---|---|---|---|
| graph — FedAvg | 0.8750 | 0.8182 | 0.8456 | 0.8780 |
| graph — FedProx (mu=0.01) | 0.8750 | 0.8182 | 0.8456 | 0.8780 |
| graph — centralized | 0.8642 | 0.9091 | **0.8861** | 0.8858 |
| graph — per-client-only (macro) | — | — | 0.8241 (npm 0.8481 / pypi 0.8000) | 0.8626 |
| tfidf — FedAvg | 0.6696 | 1.0000 | 0.8021 | 0.9659 |
| tfidf — FedProx | 0.6696 | 1.0000 | 0.8021 | 0.9659 |
| tfidf — centralized | 0.9351 | 0.9351 | **0.9351** | 0.9613 |
| tfidf — per-client-only (macro) | — | — | 0.5393 (npm 0.7897 / **pypi 0.2889**) | 0.9413 |

- FedProx == FedAvg CHÍNH XÁC cả trên data thật: đúng bản chất với mu=0.01
  (penalty không đủ đổi quỹ đạo — unit test §2 chứng minh mu lớn có tác dụng).
- Convergence: F1 FedAvg-graph đạt ~0.85 từ round 4–6, ổn định (history đủ 15
  round trong results.jsonl). secure_agg_mask_residual = **0.0** ở cả 4 row FL
  thật (2 client → cancel bitwise, khớp unit test).
- **Trung thực với scale?** Có. n=597 pilot, test 120 → CI rộng (±~0.07 F1);
  mức F1 0.85–0.94 hợp lý so với univariate AUC ~0.78 của EDA W1. Riêng
  TF-IDF 0.935 cần đọc kèm leakage (§3.3) — đây là memorize tên package,
  không phải "đồ thị kém".

### 3.2 Primary comparison pre-reg (FedAvg vs centralized, endpoint accuracy@0.5)

- McNemar **exact binomial** (discordant 9 < 25): b01=2 (central sai/FL đúng),
  b10=7, **p=0.1797** → KHÔNG có khác biệt có nghĩa ở α=0.05.
- Bootstrap paired 10k (seed 20260922): accuracy diff FL−central =
  **−0.0417 [−0.0917, +0.0083]** — điểm estimate nghiêng về centralized, CI chứa 0.
- Kết luận trung thực: trên pilot này centralized ≥ FedAvg về accuracy
  (đúng lý thuyết: FL trả chi phí non-IID), không signifcant với n=120.

### 3.3 Per-ecosystem + per-coverage (POST-HOC — yêu cầu V1/confound-check;
harness W2 chưa có, V2 tự tính từ final_probs, verify identity: re-run
tất định khớp 8/8 row đã lưu tuyệt đối)

| run | npm F1 (AUC) | pypi F1 (AUC) | with-graph F1 | empty-graph F1 (AUC) |
|---|---|---|---|---|
| graph FedAvg | 0.9091 (0.9029) | **0.5714 (0.7785)** | 0.8618 | 0.7692 (0.6726) |
| graph centralized | 0.9032 (0.8984) | 0.8235 (0.8270) | 0.9091 | 0.7692 (0.6726) |
| tfidf centralized | 0.9431 (0.9827) | 0.9032 (0.9204) | 0.9457 | 0.8800 (0.9643) |

**Finding đáng giá**: FedAvg (weighted theo n) tổn thương client thiểu số —
pypi recall rơi 0.82 (central) → **0.47** (FedAvg), F1 0.57. Đây là bằng
chứng định lượng cost non-IID của pilot, dùng được cho paper. Empty-graph
(19/120 test): graph feature all-zero → AUC 0.67 trong khi tfidf vẫn 0.95 —
nhất quán với limitation L1 của W1.

### 3.4 TF-IDF baseline post-hoc + leakage quantification

- 35% test samples (42/120; 34 là npm-malicious) **chia sẻ package với train
  ở version khác** (28 package trùng) — near-duplicate leakage W1 đã disclose
  (L2), nay được định lượng. Cả hai block đều bị inflates.
- Group-split sensitivity (post-hoc, chia theo PACKAGE, overlap=0, n_test=109):
  graph LR test F1 **0.7611** (AUC 0.8231), tfidf LR **0.8525** (AUC 0.9030);
  MLP: graph 0.7719 / tfidf 0.8850. → Thứ tự "tfidf > graph" GIỮ nguyên sau
  khi bỏ leakage, nhưng mọi số tuyệt đối phải lấy mốc group-split khi viết
  paper (đề nghị AMENDMENT).
- Overfitting check (30 epochs centralized, split pre-reg): train/test F1 gap
  tối đa **+0.009** (graph LR), MLP không overfit (thậm chí test cao hơn) →
  n=597 đủ cho LR/MLP-32 ở 18 feature; split code verified: stratified theo
  label, tách TRƯỚC partition, assert zero-overlap (đã chạy lại: True), test
  cân đúng stratification (npm 26/60, pypi 17/17 ben/mal).

## 4. FALSE CLAIMS (trong W2_report.md)

1. **"nếu W1 đặt tên block khác, chỉ sửa 2 dòng trong config"** (W2 report §5)
   — SAI: lệch là cấu trúc (flat vs nested + tên file `features_v1.*` +
   thiếu `api_calls`), KHÔNG thể fix bằng config; phải sửa loader trong
   `packguard/fl.py` (không gian W2/F). Đã chứng minh bằng lệnh fail thật (§3).
2. **"580 passed"** — đúng TẠI THỜI ĐIỂM W2, nhưng con số hiện tại (sau khi
   W1 thêm 35 test) là **615 passed / 0 failed** (verify §7); không phải claim
   sai, chỉ cần cập nhật khi trích dẫn.
3. Các disclose còn lại của W2 (secure-agg 2-client bitwise, DP ε≈484, 0.5B
   8/10 UNSURE do echo enum, McNemar method labeling) — **ĐỀU XÁC MINH ĐÚNG**
   bằng kiểm chứng độc lập (§2, §5).

## 5. KB — smoke diagnosis + parser test (`/tmp/v2_kb_parser_test.py`)

- Đọc raw cache thật `outputs/packguard/kb/llm_cache/…0.5B…__main.jsonl`: 0.5B
  emit đúng JSON nhưng `semantic_class` = **"FILE_IO|NETWORK|PROCESS|…|OTHER"**
  (copy nguyên chuỗi enum) → `_validate` từ chối → retry 1 lần → UNSURE;
  `refusals=0` → KHÔNG phải refusal, KHÔNG phải parser bug: parser đã extract
  JSON thành công và loại giá trị enum sai một cách đúng đắn. Kết luận W2
  ("limitation model 0.5B, cần 3B cho KB thật") — ĐÚNG.
- Parser test với 2 output giả ĐÚNG schema (stub generator): parse OK —
  `child_process.execSync → PROCESS/high/conf 0.9` và `https.post →
  NETWORK/medium/conf 0.8`, unsure=false, confidence giữ nguyên; refusal →
  UNSURE (không bịa class); enum sai → UNSURE; repeat classify → KB cache hit
  không gọi LLM; save/reload snapshot kb_v0001 nguyên vẹn. **7/7 PASS.**

## 6. SAFETY PORT — gate + arms test (`/tmp/v2_safety_gate_test.py`, 12/12 PASS)

- P2 gate trên fixture Python THẬT (setup.py từ config): advisory comment
  prepended → `check_semantics` **PASS** (python + javascript đều pass).
- Case "comment chứa code-break": (a) gỡ marker `#` (text thành code) → gate
  **FAIL**; (b) advisory + inject thêm `setup(...)` thật → **FAIL**; (c) sửa
  code line (version bump) → **FAIL**; (d) comment chứa ngoặc/quote KHÔNG
  đóng bên TRONG comment → vẫn **PASS** (đúng: AST bỏ qua comment node).
- Arms config khớp prereg: P0 text verbatim trong prereg; P1 mang đủ DRB
  vocabulary {steal credentials, exfiltrate, malware} với intent phòng thủ;
  rules {delta≥0.10, α=0.05, min_flip=1} khớp prereg. Smoke records:
  `monitor_fallback` đúng mapping (0.5B + granite → true; llama-3.2-3B →
  false/fitted 0.0/0.2), meta có `advisory_semantics_ok=true` + config_sha16,
  disclose "n=1, không suy luận" — hygiene ĐÚNG.

## 7. PYTEST + MOCK HYGIENE

- `pytest tests/ -q` → **615 passed / 0 failed** (78.4s) = 531 cũ + 49 W2 +
  35 W1. `--collect-only` cho 3 file test mới của W2 = **đúng 49**
  (FL 24 / KB 12 / safety 13 như claim).
- Mock hygiene: 9/9 row run fixture của W2 có `mock=true` (backup /tmp);
  12/12 row run THẬT của V2 có `mock=false` + seed + config_sha16 +
  features_source; summary thật in đậm `mock: False`. KB smoke là generation
  thật (không cần cờ mock, fixture được disclose trong meta). KHÔNG có số
  mock lẫn thật.

## 8. FILES (V2 chỉ chạm đúng không gian được phép)

- Sửa/Tạo: `reports/round8/V2_report.md` (file này);
  `outputs/packguard/fl/results.jsonl` + `summary.md` (GHI ĐÈ bằng run THẬT
  mock=false; bản mock W2 backup ở /tmp); `outputs/packguard/fl/
  v2_posthoc_analysis.json` (bằng chứng audit: provenance, identity check,
  subgroup, leakage, group-split, overfit).
- /tmp scripts (không đụng project): `v2_fl_math_test.py`,
  `v2_build_tfidf.py`, `v2_posthoc.py`, `v2_posthoc2.py`,
  `v2_kb_parser_test.py`, `v2_safety_gate_test.py`,
  `v2_audit_features/features.jsonl`, `v2_backup_mock_*`.
- KHÔNG sửa: mọi file `packguard/*`, `src/*`, `configs/*`, `data/*`,
  `outputs/packguard/features|kb|safety`. KHÔNG git commit.

## 9. AI SAI / AI BẮT ĐƯỢC

- **W2 sai (bị V2 bắt)**: harness không đọc được data thật — claim "sửa 2
  dòng config là chạy được" là sai (§4.1); giả định non-IID mạnh (0.84/0.15)
  lệch thực tế (0.71/0.49); ablation TF-IDF để pending dù đã pre-register.
- **V2 sai (tự bắt, tự sửa)**: 3 lần trong script audit của chính mình —
  init shape [5,1] vs [1,5] (broadcast error), quên chia trials khi ước lượng
  std DP noise (nhìn 3.158 vs 0.05 tưởng code sai — thực ra sqrt(4000)·σ),
  và yêu cầu "exact bitwise" nhầm đối tượng (mask cancel là bitwise; tổng
  có thứ tự cộng khác 1 ulp). Code W2 đúng cả 3 chỗ.
- **Bắt được bằng chạy thật (không có ở report nào trước)**: FedAvg tổn
  thương client thiểu số pypi (F1 0.571 vs central 0.824); leakage 35%
  test↔train theo package; tfidf > graph (cả trước lẫn sau group-split) —
  hướng này đi ngược kỳ vọng fixture của W2.

## 10. HANDOFF CHO F (việc còn lại + lệnh chính xác)

1. **Loader fix (bắt buộc trước mọi run thật tiếp theo)** — trong
   `packguard/fl.py:load_feature_records` (không gian W2/F): nhận glob
   `features*.jsonl|features*.parquet` và wrap flat row thành
   `{"features": {"graph": {18 key}}}` (hoặc `_vectorize` fallback đọc
   top-level). Sau đó lệnh pre-reg chạy thẳng:
   `.venv/bin/python -m packguard.eval --config configs/packguard_fl.yaml`.
2. **KB thật 3B** (≤ ~40 api chưa biết, cache sẵn):
   `HF_HOME=$PWD/models_dir/hf .venv/bin/python` + script: load
   `outputs/packguard/features/graphs_v1.jsonl.gz`, gom unique
   `nodes[].api` (109 unique, trừ 20 seed) → `LLMKBBuilder(kb,
   model_id="Qwen/Qwen2.5-Coder-3B-Instruct").classify_apis(...)` →
   `kb.save_version()`. LƯU Ý: `features_v1` KHÔNG có `api_calls` — phải
   derive từ graphs_v1 và nhét vào records trước khi bật
   `ablations.kb.enabled: true` rồi chạy lại eval (so sánh kb_on/kb_off).
   Không dùng 0.5B (8/10 UNSURE — đã chứng minh §5).
3. **Safety batch thật**: viết batch runner gọi
   `packguard.safety_port.run_arm` trên N package thật (benign + malicious
   từ manifest) × 3 arm (P0/P1/P2 — P2 dùng fixture python/js + gate như §6)
   × 3 model, rồi `compute_safety_metrics` + `evaluate_prereg_rules`;
   smoke 6-gen hiện có CHỈ xác nhận pipeline (đúng disclose của W2).
4. **Ablations chưa chạy**: (a) DP ablation với sigma CÓ CHỦ ĐÍCH (vd 0.1 →
   ε≈9.7/round; sigma 0.01 = ε≈484 vô nghĩa — bật `dp.enabled: true` và ghi
   disclose composition R-round chưa có proof); (b) MLP arm (config
   `model.type: mlp` — đã verify không overfit ở §3.4); (c) arm loại
   empty-graph (129 row all-zero) hoặc down-weight (W1 TODO, cần AMENDMENT).
5. **AMENDMENT đề xuất cho prereg** (F owner): (i) clients thực tế = 2
   (npm/pypi), không có "mixed"; (ii) báo cáo kèm group-split theo package
   (mốc chống leakage: graph LR F1 0.761 / tfidf LR 0.853); (iii) endpoint
   accuracy@0.5 khiến tfidf-FedAvg R=1.0/P=0.67 — cân nhắc bổ sung AUC làm
   secondary (đã pre-reg thì giữ, thêm secondary là được).

---
*Mọi số trong report này sinh từ các lệnh/file nêu tại §3, §5–§7; script
audit nằm ở /tmp để tái lập. V2 không git commit, không sửa code người khác.*
