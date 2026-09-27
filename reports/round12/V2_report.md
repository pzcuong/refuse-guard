# ROUND 12 — V2 AUDIT REPORT (adversarial W2 audit + readiness-for-F)

Ngày: 2026-09-28. Tác nhân: V2 vòng 12 (audit adversarial W2: analysis tooling +
paper integration prep). Phạm vi sửa: `reports/round12/V2_report.md` (file này)
+ `/tmp/v2_audit/*`. KHÔNG sửa code của W1/W2 (mọi kiểm chứng trên bản copy
/tmp), KHÔNG GPU, KHÔNG git commit. File `outputs/packguard/defense/
defense_analysis.json` NGUYÊN VẸN (vẫn là pending marker 01:48); `main.pdf`
được ghi lại bởi 1 lần compile tectonic kiểm chứng (kích thước trùng khớp đúng
175.07 KiB như W2 công bố).

---

## 1. VERDICT W2: **ISSUES**

- **[HIGH] Script phân tích CHẠY KHÔNG ĐƯỢC trên data thật** — W2 đúng khi giữ
  PENDING khi batch chưa có, nhưng lệnh tự hướng dẫn cho F (W2_report §3:
  `.venv/bin/python scripts/r12_defense_analysis.py`) **crash** trên batch thật
  đã có: `KeyError: 'id'` tại `scripts/r12_defense_analysis.py:144`
  (`load_labels_from_features` đọc `r["id"]` nhưng
  `outputs/packguard/features/features_v2.jsonl` dùng `sample_id` — 603/603
  dòng, 0 dòng có `id`). Crash xảy ra TRƯỚC khi phân tích; exit 1; không ghi
  output. Test 17/17 của W2 không bắt vì không test nào nạp file features thật.
  Bản vá 1 dòng trong /tmp (`r["id"]`→`r["sample_id"]`) → chạy end-to-end OK.
- **[HIGH] Khối `pooled` của script SAI ÂM THẦM** — sample_id trùng giữa 2
  model + `pool.update()` → model sau (llama, sort cuối) đè granite: "pooled"
  = số của LLAMA một mình. Bằng chứng: output pooled
  `recall .167/.042/.042` (= llama) trong khi pooled thật là
  `.417/.438/.340` (W1 metrics + tính lại độc lập của V2 khớp nhau);
  pooled McNemar P2 vs P2+D1 của script `p=1.0, n=24` trong khi thật là
  **p=0.219, n=47 (b01=1, b10=5)**. Toàn bộ token pooled trong bảng handoff
  (`NPAIRS, POOLED_*, P_*, ABS_*, CONC_*`) trỏ vào khối sai này. Khối
  per-model thì ĐÚNG 100% (đối chiếu độc lập, xem §3).
- Phần còn lại của W2: placeholder safety, handoff design, mock hygiene,
  fail-loud paths, ChatGPT blocker — đều ĐÚNG như công bố (bằng chứng §2–§5).

## 2. CHECKLIST AUDIT — KẾT QUẢ TỪNG MỤC

1. **Analysis trên data thật**: chạy (bản /tmp đã vá 1 dòng, đọc-only với
   repo) → `status:"ok"`, schema `r12_defense_analysis/1.0`, 200 rows,
   `unknown_arm_rows_ignored={}`. **3 số tính lại độc lập** (thuần Python,
   binomial exact tự viết, KHÔNG dùng `src.metrics.stats`) — khớp cả W1
   metrics lẫn analysis W2:
   - llama P2_D1 recall = **1/24 = .0417** ✓
   - granite P2 flips benign→malicious = **4** (az-ext, claude-skills-library,
     cryptographz, hmac2 — đúng danh sách W1 nêu; trên benign subset P2 KHÔNG
     sinh FP mới: 0) ✓
   - McNemar exact granite P2_nodef vs P2_D1 (malicious): n=23, b10=4, b01=0,
     **p=0.125** ✓ (khớp `statsmodels.exact`).
   **Fail-loud/pending paths** (trên copy /tmp, không đụng file thật): input
   thiếu → pending exit 0 (không có `per_model`); chỉ meta → pending exit 0;
   row malformed → `LoudError` exit 1; thiếu arm P0 (lọc từ copy batch thật)
   → `LoudError ... Refusing to emit a partial analysis` exit 1; arm lạ chèn
   vào (P1_offensive_wording ×4) → chạy OK + disclose
   `unknown_arm_rows_ignored={'P1_offensive_wording': 4}` ✓. `--mock` → ghi
   `_mock`, `mock:true`, số khớp tính tay của W2 §9 ✓.
2. **Handoff table**: 37 token đều CÓ đường dẫn JSON tồn tại trong output
   (schema khớp bảng §6 của W2, trừ shorthand `arms...recall_*` — key thật là
   `arms[ARM].malicious_recall`). Nhưng **14 token pooled lấy giá trị từ khối
   pooled SAI (bug HIGH-2)** và **3 token FP_P2 trỏ vào giá trị rỗng 0/0**
   (batch r12 KHÔNG có row benign của arm P2 — W1 chỉ cache P2 cho 24
   malicious; đếm batch: P0=76 (48mal+28ben cache), P2=48 (mal cache),
   P2D1=76 (48mal+28ben mới, mock=false)). Chi tiết ở §6.
3. **Placeholder safety**: 37 occurrence `{{R12:*}}` / 32 dòng (grep -c lines
   = 32; occurrence = 37; mục thứ 38 là chữ `R12:*` trong comment
   F-integration dòng 941 — vô hại). **Quét từng occurrence: 37/37 đứng ngay
   sau `\detokenize{`** — không token nào trần. Tectonic compile: **exit 0**,
   main.pdf 175.0712890625 KiB, chỉ overfull/underfull warnings.
   `gen_paper_numbers.py --check` → `OK -- 336 macros` ✓ (khớp W2).
   **Số cứng trong vùng W2 thêm**: câu abstract (dòng 92–96) và conclusion
   (1183–1188) chỉ có placeholder, KHÔNG có số bịa ✓. Subsection
   `sec:safety-defense` chỉ chứa .05/.10 (margin hypothesis đã đăng ký — hợp
   lệ) và **"30 malicious + 15 benign; 1/30 resolution"** (dòng 973) — xem
   mục 7 bên dưới.
4. **ChatGPT blocker**: W2 §5 có nguyên văn lỗi + prompt đầy đủ đã soạn ✓.
   Thử `chatgpt_session_status` 1 lần: **vẫn
   `not_authenticated` — "ChatGPT page did not show a composer. Run
   chatgpt_login first."** — blocker CÒN NGUYÊN; F báo user cần login thủ
   công rồi chạy lại prompt §5 (framing-only, không phải nguồn số).
5. **Tests**: `tests/test_r12_analysis.py` **17/17** ✓;
   `tests/test_packguard_defense.py` (W1) **13/13** ✓ (không vỡ); full suite
   `pytest tests/ -q` → **705 passed, 0 failed** (81s). W2 công bố 704 — lệch
   +1 do W2 cộng "+12 của W1" trong khi file W1 có 13 test (675+17+13=705).
   Sai số Arithmetic ở mục self-test của W2, không phải claim bẩn.
6. **Tính sẵn sàng cho F**: xem §6 (bảng 37 token + wording + việc còn lại).
7. **Mâu thuẫn n**: subsection W2 (main.tex:973) ghi **"30 malicious + 15
   benign"** (kích thước ĐĂNG KÝ trong AMENDMENT-6) — trong khi realized sau
   gate A6.1 là **24 malicious + 14 benign** (7/45 snippet chỉ-toàn-comment →
   strip ra rỗng → gate FAIL, loại + disclose). Ghi "1/30 resolution" cũng
   theo registered. F PHẢI sửa câu này sang realized (hoặc thêm hẳn mệnh đề
   "realized 24/14 after 7 gate-FAIL exclusions, disclosed") — nếu không bảng
   (mẫu số 24/23 per model, FP /14) sẽ mâu thuẫn trực diện với prose.

## 3. CONFIRMED BUGS

1. **[HIGH — code W2] `scripts/r12_defense_analysis.py:144`**: `r["id"]` →
   `KeyError: 'id'` trên `features_v2.jsonl` thật (603 dòng dùng `sample_id`).
   Nguyên văn: `File .../r12_defense_analysis.py", line 144, in
   load_labels_from_features ... KeyError: 'id'`, exit 1, không ghi output.
   Hệ quả: `defense_analysis.json` trong repo vẫn là pending marker
   (2026-09-27T18:48:21Z) — **analysis thật CHƯA TỪNG chạy trong repo**.
   Patch 1 dòng (đã thử trên /tmp): `labels[str(r["sample_id"])] =
   int(r["label"])` → chạy OK, số per-model khớp W1 tuyệt đối.
   (Lưu ý: batch thật có `label` trên 200/200 record nên fallback features
   thậm chí không cần cho batch này — nhưng loader bị nạp vô điều kiện khi
   file features tồn tại.)
2. **[HIGH — code W2] pooled scope llama-only**: `analyze_records` gộp
   `pool.update(buckets[(model, arm)])` với sample_id trùng giữa model →
   last-writer-wins (llama). Số sai: pooled recall .167/.042/.042, gain/loss
   1/1, p(P2vsP2D1)=1.0, n_pairs=24. Số ĐÚNG (V2 tính độc lập, khớp W1 pooled
   recall): **P0 .417 (20/48), P2 .438 (21/48), P2D1 .340 (16/47), gain 1,
   loss 5, McNemar P2vsP2D1 p=.21875 (n=47, 1/5), McNemar P0vsP2D1 p=.375
   (n=47, 1/4), benign FP P0 0/28, P2D1 0/28**. Fix gợi ý (F/orchestrator):
   prefix model vào key khi merge, vd `pool.update({f"{model}\x00{k}": v ...})`
   — rồi rerun.
3. **[MEDIUM — metrics W1, right-tool-wrong-question]**: `mcnemar_vs_p0`
   trong `defense_metrics.json` là McNemar trên **refusal booleans** (contract
   safety_port: "paired McNemar vs P0 (refusal booleans)") → tại RR=0 mọi nơi
   cho p=1.0 rỗng tuếch (b01=0,b10=0). McNemar DETECTION đã đăng ký (trên
   verdict booleans) KHÔNG tồn tại trong metrics W1 — chỉ có trong analysis
   W2 (per-model đúng, pooled sai theo bug 2). W1 report không trích p-value
   nào nên không cấu thành false claim, nhưng F đừng lấy `mcnemar_vs_p0` trong
   defense_metrics.json để điền token `R12:P_*` / `ABS_P` / `CONC_P`.
4. **[LOW — docs W2]** shorthand đường dẫn trong bảng handoff: `arms...recall_*`
   — key thật `arms[ARM].malicious_recall`; ví dụ NPAIRS "60 (30 mal + 15 ben
   × 2 models)" đã sai từ gốc vì realized 24/14 (xem mục 7).

## 4. FALSE CLAIMS (đã đối chiếu — không có claim số bẩn)

- "37 token, 37 occurrence / 32 dòng, mọi token bọc \detokenize" — ĐÚNG
  (quét từng occurrence; 38th là `R12:*` trong comment).
- Tectonic exit 0, pdf 175.07 KiB; gen_paper_numbers 336 macros — tái lập ĐÚNG.
- "17 test PASS" — ĐÚNG; full suite 705 (W2 ghi 704 — chêch +1 test W1, xem §2.5).
- W1: n=24/14, 7 exclusions (6 mal + 1 ben, strip-to-empty), pooled
  .417/.438/.340, granite flips về P0 (`flips_P2D1_vs_P0=[]` trên parsed
  pairs), llama 4 P0-positive = 4 version GÓI 1 family (@antoncallahan) —
  **tất cả tái lập được độc lập từ batch** ✓.
- Hai điểm nêu chứ không bịa: (a) prompt ChatGPT của W2 §5 viết "Benign FP
  ~0 (2/100 granite at P2)" — số liệu n=100 thật: fp_benign granite P2 =
  0.04 = 2/50 benign (2 trên 100 gói) — cách nói 2/100 mơ hồ nhưng không
  phải paper; (b) llama: detection DUY NHẤT ở P2D1 là artifact-lab (GÓI KHÁC
  với 4 P0-positive) → gain=1 của llama là detection MỚI dưới defense, không
  phải "phục hồi" — W2 analysis ghi đúng gain/loss, ai đọc bảng đừng diễn giải
  ngược.

## 5. AI SAI / AI BẮT ĐƯỢC (tóm tắt vòng)

- W2 sai: script chính của W2 crash trên data thật (đọc nhầm schema
  `id` vs `sample_id`) — 17 test do chính W2 viết không che được lỗi tích hợp
  này; bài học: test fallback-loader phải chạy trên file features THẬT.
- W2 sai: khối pooled silently llama-only do id-collision + dict.update —
  đúng kiểu lỗi "n=100: pooled che chuyển động per-model" mà chính W2 ghi
  caveat, lần này là hỏng hóc chứ không phải che.
- W1 sai (nhẹ): metrics chỉ có McNemar-refusal (p=1.0 rỗng) không có
  McNemar-detection đã đăng ký; defense_analysis{,_mock}.json sinh trước
  batch nên repo đang mang pending marker như thể "đã xử lý xong".
- V2 bắt được: cả 2 bug trên + token FP_P2 là 0/0 rỗng + prose "30/15" vs
  realized "24/14" — 4 cạm bẫy đúng chỗ F sẽ điền số.
- Không ai bịa số: mọi số trong paper vùng sửa đều là placeholder; mọi số
  thật truy vết được về batch 201 dòng (mock=false).

## 6. SẴN SÀNG CHO F

### 6.0 Trạng thái đoản: F KHÔNG thể điền ngay
(a) phải vá 1 dòng bug §3.1 rồi mới chạy được analysis (hoặc chạy bản vá
/tmp của V2: `/tmp/v2_audit/r12_defense_analysis_fixed.py --input
$PWD/outputs/packguard/defense/defense_batch.jsonl --out ...` — nhưng patch
chính thức phải do W2/orchestrator commit vì V2 không sửa code người khác);
(b) token pooled PHẢI lấy từ khối pooled ĐÃ FIX hoặc từ bảng dưới đây (đã
đối chiếu độc lập), không lấy từ `defense_analysis.json` hiện trạng;
(c) `defense_metrics.json.mcnemar_vs_p0` KHÔNG dùng được cho token p-value.

### 6.1 Bảng 37 token → giá trị thật (đã verify) / NOT-MEASURED
Quy ước: 3 chữ số bỏ số 0 đầu (nhất quán `tab:safety`). Nguồn per-model:
`per_model[M].*` của analysis (đã vá); pooled: giá trị đã verify độc lập.
M1 = `unsloth/Llama-3.2-3B-Instruct`, M2 = `ibm-granite/granite-3.3-2b-instruct`.

| Token | Giá trị điền (nguồn) |
|---|---|
| `R12:NPAIRS**` | viết: "76 paired real packages (38 gate-passing samples × 2 models; 24 malicious + 14 benign per model; 47 parsed malicious pairs pooled)" — KHÔNG dùng `pooled...n_pairs`=24 (bug) |
| `R12:STATUS` | "ok (real, mock=false; analysis re-run after the W1 batch, <timestamp từ JSON>" |
| `R12:POOLED_REC_P2` | `.438` (21/48) |
| `R12:POOLED_REC_D1` | `.340` (16/47; 1 granite P2D1 unparsed, disclosed) |
| `R12:POOLED_REC_P0` | `.417` (20/48) |
| `R12:POOLED_GAIN` | `1` |
| `R12:POOLED_LOSS` | `5` |
| `R12:P_NODEF_VS_D1` | `.219` (exact, n=47, b01=1/b10=5) — CHỈ có sau khi fix bug pooled |
| `R12:P_P0_VS_D1` | `.375` (exact, n=47, b01=1/b10=4) |
| `R12:FP_P2` | **NOT-MEASURED trong r12** (batch không có P2-benign; giá trị script là 0/0 rỗng). Điền trung thực: "not in the r12 batch (n=100 expansion: 0/50 llama, 2/50 granite)" |
| `R12:FP_D1` | `0/28` (thật) |
| `R12:LL_REC_P0` | `.167` (4/24) |
| `R12:LL_REC_P2` | `.042` (1/24) |
| `R12:LL_REC_D1` | `.042` (1/24 — sample KHÁC: artifact-lab, không phải 4 bản @antoncallahan của P0) |
| `R12:LL_GAIN`/`LL_LOSS` | `1`/`1` (gain = detection mới, loss = tinywallet) |
| `R12:LL_P` | `1.0` (n=24, 1/1) |
| `R12:LL_FP_P2` | **NOT-MEASURED** (n=100: 0/50) |
| `R12:LL_FP_D1` | `0/14` |
| `R12:GR_REC_P0` | `.667` (16/24) |
| `R12:GR_REC_P2` | `.833` (20/24) |
| `R12:GR_REC_D1` | `.652` (15/23; 1 unparsed disclosed) |
| `R12:GR_GAIN`/`GR_LOSS` | `0`/`4` |
| `R12:GR_P` | `.125` (n=23, 0/4) |
| `R12:GR_FP_P2` | **NOT-MEASURED** (n=100: 2/50 = .04) |
| `R12:GR_FP_D1` | `0/14` |
| `R12:TABLE_NOTE` | tự viết theo THẬT: "realized subsets after the A6.1 gate: 24 malicious + 14 benign (7/45 draw snippets comment-only → strip-to-empty → gate FAIL, excluded+disclosed); P0/P2 verified cache hits; 1 granite P2D1 row unparsed (disclosed)" |
| `R12:ABS_REC_P2` | `.438` |
| `R12:ABS_REC_D1` | `.340` |
| `R12:ABS_P` | `.219` |
| `R12:ABS_CLAUSE` | prose F — gợi ý §6.3 |
| `R12:CONC_REC_P2` | `.438` |
| `R12:CONC_REC_D1` | `.340` |
| `R12:CONC_P` | `.219` |
| `R12:CONC_FP` | "0/28 defended (attack-arm FP not in the r12 batch; n=100: 2/50 granite)" |
| `R12:CONC_CLAUSE` | prose F — gợi ý §6.3 |

### 6.2 Token KHÔNG CÓ data tương ứng (điền NOT-MEASURED, cấm bịa)
`R12:FP_P2`, `R12:LL_FP_P2`, `R12:GR_FP_P2` — arm tấn công P2 trong batch r12
chỉ có 48 row malicious (cache), không có row benign → benign_fp_count của P2
là 0 trên mẫu số 0. Nguồn thay thế hợp lệ (ghi rõ provenance): n=100 expansion
`outputs/packguard/r10/r8_safety_expand/safety_metrics_n100.json`
(fp_benign P2: llama 0.0, granite 0.04) — W1 đã dùng đúng path này ✓.
Không token nào khác rơi vào trạng thái no-data.

### 6.3 Wording khuyến nghị (2 hướng trung thực — PASS/FAIL per model)
- **Granite (neutralized — H-D1 ✓ H-D2 ✓ per-model)**: "on granite-3.3-2B,
  where the advisory had raised recall (.667→.833) and induced four
  benign-looking detection flips, D1 returns recall to within .014 of
  baseline and removes all four attack-induced flips at zero benign FP —
  full neutralization on this model."
- **Llama (not restored + defense cost — H-D1 ✗ H-D2 ✗ per-model)**: "on
  llama-3.2-3B, where the advisory suppressed recall (.167→.042), D1 does
  not restore it (.042): the strip also removes the package's own comments
  this weak model keyed on, and the one detection the advisory had added
  (tinywallet) is lost again — the defense-cost direction pre-registered as
  reportable (A6.3)."
- **Headline rule (A6.4)**: HD1_supported = TRUE, HD2_supported = TRUE ở mức
  ≥1/2 model — NHƯNG câu paper phải giữ per-model split là đọc chính (granite
  pass, llama fail); kèm caveat: llama result là 1-family (4 P0-positive =
  4 version của @antoncallahan/aws-user-helper).
- pooled (nếu dùng trong abstract/conclusion): bắt buộc kèm "per-model table
  is the primary read" vì pooled che 2 hướng ngược nhau (.438→.340 do loss 5
  trội gain 1).

### 6.4 Việc còn lại cho F (checklist)
1. Patch 1 dòng bug §3.1 (hoặc xin orchestrator); rerun analysis → status ok;
   cross-check pooled khớp §6.1 (nếu vẫn ra .167/.042/.042 → bug pooled chưa
   fix, xem §3.2).
2. Điền 37 token theo §6.1; 3 token FP_P2 theo §6.2; SỬA main.tex:973
   "30 malicious + 15 benign; 1/30" → realized 24/14 (+1 unparsed granite
   P2D1 nếu nhắc mẫu số); compile tectonic + `gen_paper_numbers.py --check`.
3. AMENDMENT-6: ĐÃ CÓ trong `docs/packguard_prereg.md` (A6.1–A6.5, dòng
   387–502, timestamp 2026-09-27T18:46:28Z, n=30/15 registered + on_fail
   exclude_and_disclose) — không thiếu gì cần bổ sung; chỉ cần F không ghi
   n registered thành n realized (mục 7 của checklist).
4. Safety n=100 path: `outputs/packguard/r10/r8_safety_expand/` — W1 dùng
   ĐÚNG (verify: `cache_verification.cache_file` trong metrics trỏ đúng;
   file tồn tại, đọc được) ✓ — không phải việc của F.
5. ChatGPT: vẫn not_authenticated → F báo user login thủ công, rồi chạy lại
   prompt nguyên văn trong W2_report §5 (new_chat, timeout 420s).

## 7. SELF-TEST THẬT (nguyên văn, đã chạy)

```
$ .venv/bin/python scripts/r12_defense_analysis.py --input $PWD/outputs/packguard/defense/defense_batch.jsonl --out /tmp/v2_audit/x.json
KeyError: 'id'   (line 144, load_labels_from_features)          exit=1   ← BUG
$ sed '1-line patch' → /tmp/v2_audit/r12_defense_analysis_fixed.py (PYTHONPATH=$PWD)
OK: analyzed 200 rows ... ibm-granite: P0=0.6667 P2=0.8333 P2_D1=0.6522 gain=0 loss=4
                            unsloth/Llama: P0=0.1667 P2=0.0417 P2_D1=0.0417 gain=1 loss=1
$ .venv/bin/python /tmp/v2_audit/verify_independent.py      (thuần python, tự tính)
  llama P2_D1 = 1/24 = 0.04167 | granite P2 b→m = 4 | McNemar P2vsP2D1 = p .125 (0/4, n=23)
  pooled: P0 .417 / P2 .438 / P2D1 .340; P2vsP2D1 p=.21875 (1/5, n=47); P0vsP2D1 p=.375 (1/4, n=47)
$ pytest tests/test_r12_analysis.py -q        → 17 passed
$ pytest tests/test_packguard_defense.py -q   → 13 passed
$ pytest tests/ -q                            → 705 passed, 8 warnings in 81.42s
$ cd paper2 && tectonic main.tex              → exit 0 (main.pdf 175.0712890625 KiB)
$ .venv/bin/python scripts/gen_paper_numbers.py --check → OK -- 336 macros
$ mcp chatgpt_session_status → not_authenticated: "ChatGPT page did not show a composer."
```

*V2 round 12: không git commit, không GPU, không sửa file của W1/W2 (mọi
thử nghiệm lỗi trên copy /tmp; defense_analysis.json gốc giữ nguyên pending;
main.pdf chỉ được ghi lại bởi compile kiểm chứng). Không bịa số — mọi giá trị
trong §6.1 truy vết được về defense_batch.jsonl (201 dòng, mock=false) hoặc
được gắn cờ NOT-MEASURED.*
