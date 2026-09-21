# Round 7 — EXEC Report (S-exec Vòng 7): 2 bug fix + bắn queue 7B (RQ9) + monitor

Ngày: 2026-09-21 (06:20–07:12 UTC ≈ 13:20–14:12 +07). Tác nhân: EXEC-FINALIZE
(S-exec). Nhiệm vụ: (A) sửa CHÍNH XÁC các bug V1/V2 xác nhận; (B) verify
weights 7B; (C) smoke MPS đo tok/s thật; (D) FIRE queue RQ9 theo thứ tự
pre-reg; (E) monitor records đầu; (F) verdict H-R1 sơ bộ (F5).

---

## VERDICT TÓM TẮT

1. **2 bug đã sửa + verify**: BUG-1 (bridge-overlap key) và path-map collector
   (BUG-2 của V1, theo đúng quyền sở hữu item 2) — chi tiết §1/§2. Suite
   pytest sau sửa: **531 passed, 0 failed** (chạy lần 2 cuối phiên; lần 1
   giữa phiên 3 test fixture path cũ đỏ — đã mirror path Amendment-2, xem §2.3).
2. **Queue RQ9 7B ĐANG CHẠY THẬT**: pid 22347, nohup, ưu tiên pre-reg đúng
   A0 → A5 → A1 → benign. **A0 xong 60/60 (wall 919.7s), A5 xong 60/60
   (wall 1042.7s), 0 cache-hit/120 (toàn bộ generation mới).** Tại giờ chốt
   report: A1 đang chạy (9/60). ETA toàn queue ≈ **07:50–07:55 UTC
   (~14:50 +07)**, tức ~40 phút sau mốc report này.
3. **H-R1 SƠ BỘ (A0 vs A5, cả hai complete; F5)**: **KHÔNG CÓ HARM ở 7B trên
   subset này** — recall(A0)=0.4746 → recall(A5)=0.5167 (Δ = **−0.0421**, A5
   HƠN CAO nhẹ), flips 1→0 = **3**, 0→1 = 5, exact p = **0.7266**. Theo rule
   A2 config: `H-R7-harm-absent = SUPPORTED` (Δ≤0.05 ∧ p≥0.05 ∧ flips≤3) kèm
   **ceiling-bound caveat bắt buộc** (A0 < 1.0); theo framing prereg H-R1:
   nhánh **NOT_SUPPORTED-ABSENT** (KHÔNG phải ABSENT-STRONG vì A0 < 0.999).
   **KHÔNG được đọc là "harm diminishes with scale" thiếu 2 caveat đăng ký
   trước**: (i) qwen7b cùng HỌ với qwen-3B inert ở Vòng 6 → null không tách
   được scale khỏi family-inertness (prereg §0b(i)); (ii) baseline A0 của 7B
   trên subset này chỉ 0.4746 → subset-difficulty/external-validity. A1 +
   benign CHƯA xong → verdict cuối tính bởi collector sau khi queue xong;
   đây là số sơ bộ đọc từ `metrics_round7.json` (stage chạy 06:59 UTC).

---

## 1. BUG-1 — bridge-overlap key (A1) — ĐÃ SỬA + VERIFY

- **Code** (`src/conditions/bench_attack_v2.py`, khối ~362–378 — lưu ý file
  thật là `src/conditions/…`, không phải `data/benchmarks/…` như tên trong
  giao việc; V1 cũng ghi đúng path này): đọc `bridge.get("records", [])` →
  sửa thành đọc key **`samples`** của manifest bridge; đồng thời mở rộng đo
  **cả hai** manifest (round2 + round1) và ghi 2 trường + note disclosure.
- **Manifest** `data/benchmarks/bench_attack_v2/manifest_attack_v2.json`:
  `bench_v1_bridge_overlap_rows: 0 → 22` (đo lại trên chính jsonl đã ship),
  thêm `bench_v1_bridge_overlap_rows_round1: 16` + note giải thích nguồn số
  0 sai (key bug) và rằng jsonl không đổi. **Chỉnh tay có kiểm chứng, KHÔNG
  re-run materialize** để giữ nguyên mọi giá trị khác (kể cả `created`);
  jsonl sha256 xác nhận không đổi sau sửa:
  `7e8ed42421a7c2d00c64313d985e0f63e92911881cb24f1857b09f5490a3d6b4`.
- **Số đo độc lập của tôi trước khi sửa** (set-intersection, ids đều str):
  round2 (838 ids) ∩ bench = **22**; round1 (835 ids) ∩ bench = **16** —
  khớp V1 từng chữ.
- **FALSE CLAIM sửa**:
  - `docs/bench_attack_v2.md` (§Exclusions): thay khối "turned out to be 0 …
    fully fresh relative to every prior function benchmark" bằng số thật
    22/16 + nhãn **[CORRECTED-R7]** + phát biểu đúng: fresh so với artifact
    `bench_attack_v1` thực thi (200 ids bị loại, vẫn ĐÚNG), KHÔNG fresh so
    với mọi bench trước; impact provenance-only (không leak label, selection
    seed-based không đổi, không số RQ8 nào đổi).
  - `reports/round7/A1_report.md`: giữ nguyên văn câu sai của A1 (lịch sử),
    thêm **khối [CORRECTED-R7]** ngay dưới nó với số 22/16, nguồn lỗi, phạm
    vi ảnh hưởng, con trỏ tới V1/EXEC report.
- **Verify**: `pytest tests/test_attack_v2_cwe.py` = 21 passed (không test
  nào pin giá trị overlap nên không đỏ). Khuyến nghị chưa làm (ngoài quyền
  sở hữu, để orchestrator quyết): V1 đề nghị thêm test hồi quy assert
  overlap == 22 (hoặc đọc đúng key).

## 2. Collector path map RQ8 + 320-record files — ĐÃ SỬA + VERIFY

- **Map** (`scripts/collect_master_round7.py`): `RQ8_DIR =
  "outputs/experiments/round7_cwe"` → **`"outputs/experiments/round7_rq8"`**
  (vị trí "edit these two maps then, not the logic" như comment đầu file dự
  liệu), kèm comment Amendment-2; thêm ghi chú rõ 2 file results là
  **per-model 320-record files** (160 benign + 160 vul × {C0, C5_near}),
  collector tiêu thụ as-is, gating theo MIN_FAMILY_N paired benign chứ không
  theo số file.
- **Xử lý 320-record files (có thật, không chỉ trên giấy)**: lần build đầu
  trên data thật CRASH tại `paired_stats` — `TypeError: int + NoneType`:
  `_rq8_family_side` không lọc `y_pred=None` (file synthetic cũ toàn binary
  nên không bao giờ fire; file thật llama3b có đúng **1** record unparsed —
  sample 198370, vul/C0, PARTIAL, đúng record V1 disclose). Fix theo đúng
  quy ước đã đăng ký của runner + `parsed()` của chính collector: unparsed/
  REFUSAL drop khỏi paired n (không map refusal thành benign), docstring ghi
  rõ. Sau fix build thành công.
- **BUILD + VERIFY THẬT**: `.venv/bin/python scripts/collect_master_round7.py`
  → `[ok] wrote outputs/master/round7_master.json (104 rows (RQ9 deferred:
  no ladder results files)) + round7_token_map.json; re-read verification
  passed`. **Cross-check 11 số headline với bảng tái lập độc lập của V1:
  khớp 11/11** (granite pooled 0.0625→0.700 Δ0.6375 flips 51/0; llama pooled
  0.7125→0.9875 Δ0.275 flips 22/0; granite H_G1 SUPPORTED 4/4; llama
  H_G1 NOT_SUPPORTED với passing=[CWE-200, CWE-416], label
  GENERALIZES-pooled-driven). RQ9 deferred đúng fail-safe (chưa có ladder
  file lúc build). LƯU Ý cho S: master/token-map hiện tại là bản
  **RQ8-only partial**; re-run collector sau khi queue 7B xong để có bản
  đủ cả 2 RQ.
- **Amendment-2** (`docs/round7_prereg.md`, cuối file): ghi rõ
  **POST-HOC, PATH-ONLY** (được ghi SAU generation RQ8 → tự nhận diện là vi
  phạm quy trình path-change theo chữ §0a, minh bạch hóa chứ không hợp thức
  hoá), KHÔNG đổi hypothesis/ngưỡng/rule/registry; ghi nguyên nhân (bridge
  expectation 80 stale vs per-model 320) và hệ quả đọc kết quả = KHÔNG.
- **2.3 (đtě ngoài danh sách nhưng bắt buộc để suite không đỏ — disclose):**
  3 test fixture tạo synthetic sources ở path cũ `round7_cwe` sẽ против map
  mới; đã mirror path trong fixture (KHÔNG đụng logic test):
  `tests/test_round7_master.py` (2 chỗ: `write_rq8`, `test_row_drift_fails_verify`)
  + `tests/test_round7_rq8.py` (1 chỗ: `_write_collector_tree`). Sau mirror:
  4 file test round7/attack_v2 = 88 passed; full suite lần 2 = 531 passed
  (xem §6).

## 3. jobs_status.json stale (round7_rq8) — ĐÃ CẬP NHẬT

Runner RQ8 không có stage nào ghi lại status sau khi chạy (write_status chỉ
được gọi bởi queue driver khi chạy), nên theo giao việc **ghi tay** trạng
thái final: `state=queue_done`, queue 640/640, kèm `hand_update_note` (nguồn
bằng chứng: results 320/320 × 2 model + metrics state=complete — không bịa
số) và `stale_values_before_hand_update` giữ giá trị kẹt cũ (running,
01:38:23Z, 152/320) để truy vết.

## 4. [F1] Weights 7B trên disk — VERIFIED

- `models_dir/hf/hub/models--Qwen--Qwen2.5-Coder-7B-Instruct/`:
  4 blob shard = 4,877,660,776 + 4,932,751,008 + 4,330,865,200 +
  1,089,994,880 = **15,231,271,864 B ≈ 15.23 GB** (khớp byte V2 báo),
  mtime 08:23; snapshot symlink dir =
  `c03e6d358207e414f1eca0bb1891e29f1db0e242`; `refs/main` cùng giá trị —
  **khớp sha trong `configs/round7_7b.yaml`**. Đủ config/tokenizer/index.
- GPU rảnh tại lúc fire (0 process python round7/rq8), RAM free 79%.

## 5. [F2] Smoke 3 prompt trên MPS — tok/s THẬT

`--stage smoke` (06:33–06:35 UTC) → `outputs/experiments/round7_7b/smoke_7b.json`:

- **dtype bfloat16, KHÔNG OOM, KHÔNG cần fp16 fallback, giữ
  `max_input_tokens=8192`** (config không đổi — sha frozen giữ nguyên).
- Load 18.3s (cache); 3 prompt trên đúng template thí nghiệm
  (`vuln_analysis_standardized_v1`): tok/s thật **5.35 / 6.34 / 6.17
  (median 6.17)**; completion 76/51/51 tokens, JSON output đúng schema;
  cache-replay hit + replay_equal = true cho cả 3.
- ETA khai trước trong smoke (worst-case 512 tok): 6.38 h — **thực tế nhanh
  hơn nhiều** vì completion thật chỉ 46–141 tok (median ~50): xem §6.
- Smoke prompt là synthetic (0 overlap bench) — không bẩn cache thí nghiệm.

## 6. [F3+F4] QUEUE ĐÃ BẮN + MONITOR 10–15 PHÚT ĐẦU

- Lệnh (đúng A2 §4, KHÔNG dùng auto-chain chết):
  `--stage queue-driver` viết `outputs/experiments/round7_7b/queue_driver.py`
  → `HF_HOME=$PWD/models_dir/hf nohup .venv/bin/python
  outputs/experiments/round7_7b/queue_driver.py >>
  outputs/experiments/round7_7b/queue.log 2>&1 &` — **pid 22347**, start
  06:36:49 UTC.
- **Thứ tự ưu tiên pre-reg đúng**: START vul/A0 → (xong) START vul/A5 →
  (xong) START vul/A1 → (kế tiếp) benign.
- **Kết quả monitor (đến 07:11 UTC)**:
  - `vul/A0` **DONE 60/60**, wall **919.7s (~15.3 phút)**, cache_hits 0/60.
  - `vul/A5` **DONE 60/60**, wall **1042.7s (~17.4 phút)**, cache_hits 0/60
    (cộng dồn 0/120 — **toàn bộ generation mới, không reuse lẫn vào**).
  - `vul/A1` running 9/60 lúc 07:11, s/record ổn định ~10.6–15.3.
  - **≥8 records thật: XÁC NHẬN** — checkpoint tại 10 records đầu: file
    `results_qwen7b__vul__A0.json` 10 records, real=true, dry_run=false,
    model+rev+dtype đúng, **10/10 ANSWER, 0 OOM, 0 crash, 0 SKIPPED**.
  - Tok/s mỗi record (A0 10 đầu): median **5.55** tok/s, completion 46–141
    tok (median 50) → **s/record wall ~15.3s**; benign dự kiến nhanh hơn.
- **ETA trung thực (cập nhật theo wall đo được, không phải kịch bản 512-tok
  của smoke)**: A1 xong ≈ 07:25–07:27 UTC; benign 60 gen ≈ 12–15 phút →
  **toàn queue ETA ≈ 07:40–07:55 UTC (~14:40–14:55 +07)**. Còn lại sau mốc
  report: ~30–45 phút. Resume/monitor cho S:
  - `tail -f outputs/experiments/round7_7b/queue.log`
  - `cat outputs/experiments/round7_7b/jobs_status.json`
  - resume job bất kỳ (cache miễn phí phần đã chạy, model-guard bật):
    `HF_HOME=$PWD/models_dir/hf .venv/bin/python -m src.experiments.round7_7b --stage run --variant A1` (tương tự `--variant A0|A5`, `--stage benign`)
  - khi queue xong: `--stage metrics` rồi `.venv/bin/python
    scripts/collect_master_round7.py` (đã fix map — sẽ build cả RQ8 + RQ9).

## 7. [F5] H-R1 SƠ BỘ (đã nêu ở VERDICT 3, chi tiết số)

Nguồn: `outputs/experiments/round7_7b/metrics_round7.json` (stage 06:59 UTC,
A0+A5 complete; A1/benign lúc đó missing → verdict machinery tự gắn
NOT_EVALUABLE/INCOMPLETE cho phần còn lại — đúng thiết kế):

- recall(A0)=0.4746 (59/60 parsed; 1 unparsed PARTIAL sample 210091 — drop
  khỏi paired n theo rule, disclose trong file), recall(A5)=0.5167 (60/60).
- A5_vs_A0_vul exact: n_pairs_valid=59, flips 1→0 = **3**, 0→1 = 5,
  **exact_p = 0.7265625**.
- Nhánh rule: SUPPORTED cần Δ≥0.20 ∧ p<0.05 ∧ flips≥10 → KHÔNG; ABSENT cần
  Δ≤0.05 ∧ p≥0.05 ∧ flips≤3 → **ĐÚNG** (A2 framing: harm-absent SUPPORTED,
  ceiling-bound caveat; prereg framing: **NOT_SUPPORTED-ABSENT** — không
  STRONG vì A0<0.999).
- Bất thường trong 120 records đầu: **KHÔNG có** gì ngoài 1 unparsed đã
  nêu (0 REFUSAL, 0 SKIPPED/GEN_ERROR, 0 OOM, model/rev/dtype đúng 100%,
  0 cache-hit — không nhiễm reuse). Điểm đáng chú ý (narrate, không phải
  bug): baseline A0 của 7B thấp (0.4746) so với llama-3B (1.000) trên cùng
  subset — ảnh hưởng trực tiếp cách đọc mọi nhánh H-R1/H-R2 (headroom khác
  hẳn), đã có caveat trong prereg §3.2.

## 8. Phạm vi + những gì KHÔNG làm

- KHÔNG đụng: hypothesis/rule bất kỳ tài liệu nào (Amendment-2 là path-only),
  `src/defenses|models|metrics|data|conditions` (chỉ sửa file bench_attack_v2
  thuộc A1 đúng phạm vi bug được giao), runner `round7_rq8.py` (BUG-2 gốc xử
  lý bằng cách cho collector đọc layout thật — bridge copy không còn cần),
  latent collector branch "GENERALIZES khi ≤3 family powered" (V2 bug #3 —
  KHÔNG fire với data hiện tại, ngoài quyền sở hữu; khuyến nghị S sửa 1 dòng
  trước khi điền paper) và "path traversal" trong `06_discussion.tex` (V2
  bug #4 — cũng ngoài quyền sở hữu).
- KHÔNG git commit. KHÔNG bịa số — mọi số trong report này truy vết được tới
  file output thật nêu tên.

---
*Verification: pytest full suite chạy 2 lần trong phiên (lần cuối: 531 passed,
xem §6); collector build + re-read verify pass + 11/11 số khớp V1; smoke_7b.json
+ metrics_round7.json + results_qwen7b__vul__{A0,A5}.json + queue.log +
jobs_status.json là artifact thật trên disk tại giờ viết.*
