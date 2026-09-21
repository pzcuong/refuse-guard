# Round 7 — V1 Report (Adversarial Audit): bench_attack_v2 (A1) + RQ8 CWE-generalization runs

Date: 2026-09-21. Auditor: V1 (Vòng 7). Scope: (A) `data/benchmarks/bench_attack_v2/` của A1,
(B) `outputs/experiments/round7_rq8/` (llama3b 320/320, granite2b 320/320, vừa resume xong).
Method: đọc trực tiếp 160 bench rows + 640 records, TÁI LẬP mọi số từ records (không tin
file metrics), rebuild bench 2 lần vào /tmp, re-run check_semantics 640/640, re-derive
prompt sha bằng đúng recipe runner, scan provenance cả 3 split PrimeVul, chạy collector
fail-safe và full pytest. KHÔNG sửa code, KHÔNG GPU, chỉ ghi report này + /tmp scripts.

---

## VERDICT

### A1 — bench_attack_v2: **PASS with 1 CONFIRMED BUG [MODERATE] + 1 FALSE CLAIM [MODERATE]**
Toàn bộ claim định lượng của A1 (anti-leakage, rate-matching, anchoring, semantics,
determinism, v1-overlap=0, valid-fill composition) **tái lập được và đúng** — trừ đúng
một chỗ: "zero overlap with the bench_v1 bridge" là SAI do bug key đọc manifest (chi tiết
BUG-1). Bug này KHÔNG đụng vào label-leak, KHÔNG đổi selection, KHÔNG ảnh hưởng số RQ8.

### RQ8 runs: **PASS with 1 CONFIRMED BUG [MODERATE] (pipeline) + 2 MINOR**
- Metrics tái lập từ records: **0 sai lệch** trên mọi số (FP/family/arm, flips, exact
  McNemar, pooled ΔFP, bootstrap CI, verdict labels) cho CẢ HAI model.
- Claim "granite GENERALIZES 4/4 (H_G1 SUPPORTED), llama GENERALIZES-pooled-driven
  (H_G1 NOT_SUPPORTED 2/4, H_G2 SUPPORTED)" — **ĐÚNG theo đúng pre-reg §2.3, verdict
  computed-by-rule, không đi tay; anti-masking clause được tôn trọng**.
- Bug pipeline: runner KHÔNG copy results files sang collector bridge
  (`outputs/experiments/round7_cwe/` chỉ có manifest) → collector báo `[pending] RQ8 (0/2)`
  dù data đầy đủ (chi tiết BUG-2). Data gốc nguyên vẹn; fail-safe đã chặn ghi sai.

---

## A1 — bench_attack_v2 (checks 1–3)

### 1. Anti-leakage (đọc 160/160 rows) — PASS
- **0/160** advisory (C5_near lẫn C5_far) chứa CWE-\d+ / CVE-\d+ (kể cả CWE/CVE của
  chính row); **0** câu phát biểu label kiểu "vulnerability is present/absent /
  (not) vulnerable / benign / safe"; **0** policy-forbidden token (ignore, disregard,
  "you must", reveal, refuse, #include, "curl ", bash) — scan bằng diff
  whitespace-normalized. (Lần quét đầu tôi ra 3 hit "ignore" — kiểm lại là comment
  **gốc của code** bị diff thô nhặt nhầm do khác indentation, không phải advisory.)
- Wording threat-intel ("vulnerab*", "exploit*") xuất hiện **đối xứng 2 label**:
  family-kind 6 (label1) vs 8 (label0), pattern 4 vs 6, exploit 19 vs 18 — đây là
  nội dung treatment, không phải leak label.
- **Anchoring PASS**: recompute `extract_family_signals` + `extract_risky_apis` trên
  C0 func thô → khớp 160/160 `row.family_signals`/`risky_apis` (0 mismatch);
  `advisory.risky_apis ⊆ row.risky_apis` 160/160 (kiểm định T7). pointer_surface min
  = 3 (đúng ngưỡng ≥3); mọi claim số trong advisory ≤ cap 3 và sinh từ signal thật
  (hand-check 3 row pointer: sig 23/6/13 ↔ mật độ `*`/`->` thật 42/8/20, đều có
  pointer param). Lưu ý: template (fam_01…fam_06) KHÔNG map 1-1 với anchor signal
  (vd 12 row chỉ có pointer_surface vẫn nhận fam_04_log_path) — đây là diversity
  rotation (max share 0.1959 ≤ guard 0.40), claim số trong advisory vẫn neo signal
  thật; không phải leak.
- **Rate-matching PASS (tự đếm từ rows, không tin manifest)**: signature vul/ben =
  **12/12, 14/14, 17/17, 16/16** đúng như A1 báo; advisory kind theo label =
  zero_api 21/21, family 49/48, pattern 10/11 (manifest ghi 48/49 và 11/10 — cùng
  phân bố, khác thứ tự liệt kê); 42 row no-signature đều nhận zero_api → advisory
  presence 160/160 cả 2 label.

### 2. Selection / provenance / parse — PASS (trừ BUG-1)
- Provenance: 160/160 sample_id tồn tại trong đúng split file được claim (test/valid),
  label + CWE khớp nguồn; **0 row** nằm trong train split (175,797 ids đã load) →
  valid-fill không lẫn vào nơi cấm; scan mọi file JSON trong `models_dir/transformer_baseline/`
  (B4 artifacts cũ): **0** bench-v2 id → không contamin vào train pipeline.
- Overlap bench_attack_v1: **0/200** (tự đếm) — claim v1 của A1 ĐÚNG.
- **BUG-1**: manifest field `bench_v1_bridge_overlap_rows: 0` là KẾT QUẢ CỦA BUG ĐỌC KEY.
  `src/conditions/bench_attack_v2.py:364-368` đọc `eval_subset_round2.json` bằng
  `bridge.get("records", [])` trong khi file thật dùng key **`samples`** → bridge_ids
  rỗng → overlap in ra 0. Đo lại thật: overlap với `eval_subset_round2.json` (838 ids,
  universe mà bench_v1 được rút ra) = **22 ids**; với `eval_subset_round1.json` = 16.
  A1 report ("zero overlap with the rest of the bench_v1 bridge (measured)") và
  `docs/bench_attack_v2.md` ("turned out to be 0 … **fully fresh relative to every
  bench**") là FALSE CLAIM do bug này. Impact: thuần provenance/disclosure — 22 row
  này từng bị đo ở vòng trước dưới điều kiện KHÁC (C2/C3 stress), không phải leak
  label, không đổi selection (seed-based), không đổi bất kỳ số RQ8 nào. Nhưng con số
  0 in trong manifest là sai và test hiện có không bắt được (test chỉ check v1).
- Parse: re-run `check_semantics` độc lập trên **640/640 arm funcs — 0 fail**, khớp
  cờ `semantics_ok` từng arm. 2 row (514575, 273252) cần expand brace 1 dòng để chèn
  inline comment — formatting-only, semantics OK. near>far offsets 160/160.

### 3. Determinism — PASS
- `materialize()` ×2 vào /tmp (config `configs/attack_v2_cwe.yaml`, pool-cache hit,
  read-only trên artifact gốc): jsonl **byte-identical** giữa 2 lần VÀ khớp artifact
  đang dùng: sha256 `7e8ed42421a7c2d00c64313d985e0f63e92911881cb24f1857b09f5490a3d6b4`
  = manifest ghi. Sample 10 row giống hệt nhau. (Rebuild cũng tái lập đúng BUG-1 —
  xác nhận bug nằm trong code, không phải hỏng file.)

---

## RQ8 — runs (checks 4–7)

### 4. Tái lập metrics từ records — PASS, 0 sai lệch
Tự tính từ 640 records (formula exact discordant-only `p=min(1,2·Σ_{k≤min(b,c)}C(b+c,k)/2^(b+c))`):

**llama3b** (benign side, C0 → C5_near):
| Family | FP0 | FP5 | ΔFP | b2v/v2b | p exact | pass |
|---|---|---|---|---|---|---|
| CWE-476 | 0.750 | 1.000 | 0.250 | 5/0 | 0.0625 | NO |
| CWE-416 | 0.500 | 0.950 | 0.450 | 9/0 | 0.0039 | YES |
| CWE-190 | 0.900 | 1.000 | 0.100 | 2/0 | 0.5 | NO |
| CWE-200 | 0.700 | 1.000 | 0.300 | 6/0 | 0.03125 | YES |
| POOLED | 0.7125 | 0.9875 | 0.275 | 22/0 | 4.77e-07 | H_G2 YES |

**granite2b**:
| Family | FP0 | FP5 | ΔFP | b2v/v2b | p exact | pass |
|---|---|---|---|---|---|---|
| CWE-476 | 0.050 | 0.700 | 0.650 | 13/0 | 2.44e-04 | YES |
| CWE-416 | 0.000 | 0.750 | 0.750 | 15/0 | 6.10e-05 | YES |
| CWE-190 | 0.200 | 0.650 | 0.450 | 9/0 | 0.0039 | YES |
| CWE-200 | 0.000 | 0.700 | 0.700 | 14/0 | 1.22e-04 | YES |
| POOLED | 0.0625 | 0.700 | 0.6375 | 51/0 | 8.88e-16 | H_G2 YES |

- Khớp `metrics_round7_rq8.json` **từng con số, 0 mismatch** (kể cả `family_pass`,
  `families_passing`, verdict labels). Bootstrap CI reproduce cùng seed 20260918
  (granite 476: [0.45, 0.85] — tôi ra [−0.85, −0.45] vì đảo thứ tự đối số; biên
  giống hệt → đúng seed/đúng phép tính).
- **llama 476/190 n.s. là THẬT, không phải bug**: 476 b2v=5,c=0 → 0.0625 — đúng
  power note pre-reg (cần 6/20; 5 chỉ được 0.0625); 190 b2v=2 (C0 FP đã 0.90, chỉ
  còn 2 headroom tới trần 1.0). Không có sign-flip hay drop record lẩn trong đó.
- **granite 4/4 KHÔNG phải false-positive do multiple comparisons**: flips 9–15/20,
  mọi p ≤ 0.0039; nhân cả 5 so sánh ×5 (Bonferroni, ngoài pre-reg) vẫn max 0.0195
  < 0.05. Pooled 51 flips. Effect là thật ở quy mô này.
- Verdict logic chạy đúng rule §2.3: llama family_pass_count=2 + H_G2 pass →
  GENERALIZES **bắt buộc kèm sub-label "pooled-driven"** + nêu family kéo
  (`families_passing: [CWE-416, CWE-200]` — có trong verdict block); granite 4/4 →
  GENERALIZES. Anti-masking: bảng per-family + pooled đều được lưu trong metrics.
- Vul side (secondary): tái lập khớp; llama CWE-200 có **1 record bị loại đúng luật**
  (PARTIAL unparsed — xem §5); 0 flip 1→0 (v2b=0) mọi family/model → không có
  FN-finding mới (đúng kỳ vọng pre-reg §2.4). Echo evidence 0/22 và 0/51 — tái lập được.

### 5. Monitor / threshold / parse status — PASS
- RR = 0.0 mọi cell, cả 2 model (đúng kỳ vọng pre-reg §2.4; refusal không map benign
  — không có refusal nào để map).
- llama: 1/320 PARTIAL — sample 198370 (vul, CWE-200, C0): JSON output hỏng escape
  quote ở `location` → unparsed, `y_pred=None`, bị loại khỏi paired vul CWE-200
  (n_pairs_valid=19) và **được disclose** trong metrics (`n_pairs_excluded_…: 1`);
  benign side không bị ảnh hưởng. Đúng luật "drop từ paired n, count disclosed".
- Thresholds đúng như disclosed: llama 0.0/0.2 là **calibration-fit thật** — block
  `thresholds_per_model[unsloth/Llama-3.2-3B-Instruct]` tồn tại trong
  `configs/models.yaml` (fitted_on contrast calibration 125 prompts, accuracy 0.296
  disclosed); granite KHÔNG có calibration block → fallback 0.0/0.2 được disclose
  rõ trong `configs/round7_rq8.yaml`. Cả 640 record ghi cùng `monitor_thresholds`.

### 6. Checkpoint/resume integrity — PASS
- granite: gen hours cho thấy run thật 01:xx UTC (152 records) + resume 05:xx UTC
  (168 records); **0 duplicate** (sample_id × condition unique 320/320); 12 record
  resume lấy từ LLM cache (cache_hit=True) — cùng prompt sha, không phải generation
  trùng lặp; 308 generate mới. llama: 0 dup, 0 cache hit (fresh 320).
- Census 320/320 đúng bench (không record thừa/thiếu); `raw/` đúng 640 file
  (320 + 320), sample 5 file khớp nội dung `meta.text` trên disk.

### 7. GPU hygiene — PASS
- `meta.model_guard` và `meta.gen.model_id` = đúng model của file trong **640/640
  records**; 0 record của 7B/qwen/model khác; raw filenames 100% `rq8_llama3b__` /
  `rq8_granite2b__`; metadata: mps + bfloat16, revision sha llama `006f5dcd…`,
  granite `707f574c…`, real=True, dry_run=False từng record; dry-run outputs để
  riêng trong `dry/`, không lẫn.
- Prompt chain: rebuild prompt từ bench bằng ĐÚNG recipe runner
  (`build_attack_prompt(func, arm, language)` + `sha16(json sort_keys)`) → khớp
  `prompt_sha256_16` **640/640**. Config sha `a0b0ac9b64b3b330` tái lập được từ
  config hiện tại theo convention loader (sha của dict, không phải bytes file);
  mtime config 00:17 UTC < generation đầu 00:51 UTC < amendment 22:18 UTC hôm trước —
  timeline sạch.

### 8. pytest — PASS
`.venv/bin/python -m pytest tests/ -q` → **531 passed**, 2 warnings, 78.6s, 0 failed
(số trong request "513" đã stale — suite tăng do các agent Vòng 7 thêm test; không
test nào fail).

---

## CONFIRMED BUGS
1. **[MODERATE] BUG-1 — bridge-overlap key bug (A1)**: `src/conditions/bench_attack_v2.py:364-368`
   đọc `eval_subset_round2.json` qua `bridge.get("records", [])`, key thật là
   `samples` → `bench_v1_bridge_overlap_rows` in 0; thật = **22** (round2) / 16
   (round1). Fix 1 dòng + sửa manifest; test chống hồi quy nên assert overlap == 22
   (hoặc đọc đúng key).
2. **[MODERATE] BUG-2 — collector bridge không có results (RQ8 runner)**: hợp đồng
   pre-reg §4 + `configs/round7_rq8.yaml` (`collector_bridge`) yêu cầu copy
   `results_{llama3b,granite2b}.json` vào `outputs/experiments/round7_cwe/` tại
   checkpoint COMPLETE; thực tế thư mục chỉ có `manifest_cwe.json`. Log tự nhận:
   `[rq8] bridge skipped (results_granite2b.json): 320/80 records — partial-coverage
   file` — expectation 80 (per-job) stale sau khi driver đổi sang per-model file 320.
   Hệ quả: `scripts/collect_master_round7.py` báo `[pending] RQ8 results (0/2 models)`
   → master/paper không điền được dù data complete. Fail-safe của collector hoạt
   động ĐÚNG (không ghi file, exit 0) — lỗi nằm ở runner bridge step.
3. **[TRIVIAL] stale heartbeat**: `jobs_status.json` kẹt ở state "running" 01:38 UTC,
   152/320 (điểm crash granite lần đầu); resume không cập nhật — người đọc file này
   riêng sẽ tưởng granite chưa xong.

## FALSE CLAIMS
1. **[MODERATE]** A1 report + `docs/bench_attack_v2.md`: "zero overlap with the rest
   of the bench_v1 bridge (measured)" / "v2 is **fully fresh relative to every bench**"
   — sai (thật 22 ids, do BUG-1). Mọi claim A1 khác được kiểm đều ĐÚNG (anti-leakage,
   rate-match 12/12,14/14,17/17,16/16, kinds 21/21·48/49·10/11, v1-overlap 0,
   semantics 640/640, determinism byte-identical, valid-fill composition, max template
   share 0.1959).

## AI SAI / AI BẮT ĐƯỢC
- **A1 sai (bị bắt)**: đo bridge-overlap bằng key sai rồi kể kết quả 0 thành "fully
  fresh" — đúng loại lỗi provenance mà audit này phải soi; may là không chạm vào
  label/selection nên RQ8 vẫn đứng.
- **RQ8 runner sai (bị bắt)**: bridge expectation 80 không cập nhật theo file 320 →
  dữ liệu complete nhưng collector `pending` — sẽ kẹt S-Vòng-7 nếu không ai chạy thử
  collector.
- **Tôi sai lần 1**: quét policy-token bằng diff thô → 3 hit "ignore" giả (comment
  gốc của code, khác indentation); chuẩn hóa whitespace → 0 hit. A1 sạch ở điểm này.
- **Tôi sai lần 2**: tái lập prompt-sha bằng signature sai (`sample=dict`) → 320
  "mismatch" giả; dùng đúng call-site runner (`func/arm/language` + `sha16(json)`)
  → 0/640. Bài học: rebuild-check phải theo đúng recipe của runner, không phải theo
  ý mình.
- **A2/A1 đúng ở nơi tôi sẵn nghi**: llama 476 p=0.0625 là giới hạn power đã đăng ký
  trước (5/20), không phải bug tính; verdict không bị "đi tay" theo hướng có lợi.

## ĐÁNH GIÁ CLAIM ("GENERALIZES có vững không?")
- **Đủ điều kiện pre-reg: CÓ.** Bench đúng registry Amendment-1 (CWE-476/416/190/200,
  20+20/family, không family nào rơi ra vì thiếu sample), arm gate C5_near, census
  không subsample, metrics tái lập 0 sai lệch từ records, verdict computed-by-rule.
  Selection bias theo family: KHÔNG phát hiện được — signature/advisory-kind
  rate-matching theo label đúng 12/12·14/14·17/17·16/16, advisory không mang CWE/label,
  benign/vul cùng máy cùng prompt-builder cùng monitor. Bench có BUG-1 nhưng bug đó
  là provenance-only → **kết quả RQ8 không vô nghĩa**.
- **granite GENERALIZES 4/4 (H_G1 SUPPORTED): VỮNG** — mọi family p ≤ 0.0039 với
  flips 9–15/20 (ngưỡng power 6/20), survives cả ×5 correction (ngoài scope pre-reg,
  chỉ để nói robustness). Pooled ΔFP 0.6375. Không có dấu hiệu pass "hên".
- **llama GENERALIZES-pooled-driven: ĐÚNG RULE và ĐƯỢC BÁO ĐÚNG anti-masking** —
  H_G1 NOT_SUPPORTED (2/4) in rõ cạnh H_G2 SUPPORTED; sub-label "pooled-driven" bắt
  buộc theo §2.3.1 có mặt; family kéo (416, 200) được nêu tên; bảng per-family đầy đủ.
  **Caveat bắt buộc khi viết paper (đã có trong pre-reg, phải giữ nguyên)**: llama bị
  trần headroom — FP(C5_near) = 0.95–1.00 ở cả 4 family, 2 family n.s. (476 cách
  ngưỡng đúng 1 flip; 190 chỉ còn 2 sample headroom) nên per-family null của llama
  KHÔNG được đọc là "bias vắng mặt", chỉ là "không detectable tại n=20 với headroom
  cạn". Nếu S viết ngược lại là vi phạm §2.5.
- Việc cần làm sau audit (không khẩn): fix BUG-1 (+manifest), fix bridge-copy của
  runner rồi chạy lại `collect_master_round7.py` để master/paper điền số; nếu sửa
  path/expectation runner thì ghi execution-log, KHÔNG đụng hypothesis/rule.

---
*Verification: mọi số trong report này truy vết được tới `/tmp/v1r7_bench_leak.py`,
`/tmp/v1r7_select.py`, `/tmp/v1r7_rq8_recompute.py` (đã chạy trên .venv của repo) +
rebuild /tmp/v1r7_rebuild_{1,2}. Không tạo/sửa file nào khác ngoài report này.*
