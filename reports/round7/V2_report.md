# V2 Report — Round 7 (Vòng audit 7): A2-staging 7B + A3 pre-reg/paper + quyết định RQ9

Ngày: 2026-09-21 (~13:10 +07). Tác nhân: V2. Phạm vi: (A) tính sẵn sàng + trung thực
của report staging 7B của A2 (không có generation thật); (B) pre-reg + Amendment-1 +
paper drafts của A3; (C) cách ghi quyết định RQ9. KHÔNG GPU, KHÔNG restart download,
KHÔNG sửa code. Mọi lệnh nêu dưới đã chạy thật trong phiên audit này.

---

## VERDICT

### A2-STAGING: **PASS (có 1 ISSUE [MEDIUM] về auto-chain — thất bại im lặng, và 2 [LOW])**

1. **Trung thực: SẠCH.** Report mở đầu bằng chữ to "Generation thật: 0/240 records.
   CHƯA có bất kỳ results.json thật nào" và lặp lại ở §3/§7. Kiểm filesystem:
   `outputs/experiments/round7_7b/` chỉ có `dry/` (4 file `results_mock7b__*`,
   240 file raw, `dry_run=true`, `model_id=mock/round7-dry`). Không có một chỗ nào
   trong report gợi ý đã chạy thật; mục ETA §5 ghi rõ là kịch bản khai trước, §2.3
   ghi rõ smoke "sẽ có số thật, KHÔNG đoán trước". ✅
2. **Pipeline sẵn sàng thật.** (a) Config sha16 hiện tại tôi tính lại bằng convenção
   repo (`load_config` của chính runner) = `8000706d38384ebe` — TRÙNG metadata của cả
   4 file dry (05:52) → chuỗi pre-reg→dry→config đóng băng không gãy. (b)
   `pytest tests/test_round7_7b.py tests/test_round7_master.py` = **49 passed** (đúng
   23 + 26 như A2/A3 khai); model-guard và config-sha-drift là **test thật** (ghi file,
   ép sai `model_id` / sai sha, assert raise — `tests/test_round7_7b.py:207-234,395-406`).
   (c) Hai fix bug §1 xác nhận có mặt trong code: `_looks_like_oom` so key đã
   `.lower()` (dòng 186-190), `_display_path` (dòng 568-573). (d) Bench R6 sha256_16
   tính lại = `2daa249f7543f8e0` ✅.
3. **`max_input_tokens=8192`: logic hợp lệ nhưng [LOW] không còn artifact.** Số
   tokenize (median 814 / p99 4,073 / max 5,587) chỉ tồn tại trong report — script/txt
   nằm ở /tmp đã mất (xem bug auto-chain). Rủi ro thấp: quyết định được chốt là
   **giữ nguyên mặc định frozen 8192** (không phải đổi rule; config cho phép hạ 4096
   nhưng giữ 8192 là no-op cần disclose, và đã disclose). Không Zahlen bịa — chỉ là
   claim không truy vết được artifact.
4. **Auto-chain: ISSUE [MEDIUM] — promise bị thực tế phủ nhận, thất bại IM LẶNG.**
   Bằng chứng filesystem tại giờ audit:
   - Weights **ĐÃ TẢI XONG và install đúng**: 4 blob shard =
     4,877,660,776 + 4,932,751,008 + 4,330,865,200 + 1,089,994,880 =
     **15,231,271,864 B ≈ 15.23 GB** (đúng con số report), mtime **08:23**, symlink
     `snapshots/c03e6d358207e414f1eca0bb1891e29f1db0e242/` khớp sha config. Fetcher
     hoàn thành nhiệm vụ phần tải + install. ✅
   - Nhưng **chain sau-install KHÔNG fire**: không có `smoke_7b.json`, không có
     `queue_driver.py`, không có `queue.log`, không có `jobs_status.json` trong
     `outputs/experiments/round7_7b/`; không còn process nào. Claim "queue RQ9 **tự
     khởi động** khi weights xong, không cần can thiệp" (A2 §0/tóm tắt) = SAI theo
     kết quả. Nguyên nhân gốc không chứng minh được: `/tmp/r7_fetch.py`,
     `/tmp/r7weights/fetch.log`, `/tmp/r7_dl.log` **đã mất** (máy reboot ~12:04 — mọi
     process app khởi động 12:04PM; /tmp bị dọn). Kịch bản khả dĩ nhất: RQ8 chiếm MPS
     từ ~08:15 (`round7_rq8/queue_driver.py` 08:15, `results_llama3b.json` 08:33) →
     smoke 7B load 15.2 GB lúc 08:23 OOM → `ScaleUpBlocked` raise trong `smoke_stage`
     → chain chết trước khi tới queue. Dù nguyên nhân gì: **failure không được ghi
     vào bất kỳ file nào trong repo** — watchdog như report mô tả không để lại dấu
     vết. Đây là lỗi thiết kế vận hành, không phải gian lận.
   - Phần cứu vãn: các lệnh resume thủ công A2 §4(2)-(4) đã tôi soát — đúng path
     (`ROOT=parents[3]` của `queue_driver.py` = project root; `DEFAULT_HF_HOME =
     PROJECT_ROOT/"models_dir/hf"` trùng đúng chỗ weights nằm, không cần HF_HOME
     môi trường; JOBS A0→A5→A1→benign; checkpoint 10; guard trên resume). Chạy được.
5. **[LOW] "pytest tests/ -q = 513 passed"** không tái lập nguyên phần số được — repo
   đã tiến thêm (RQ8 phase sau 06:59 thêm test). Tại giờ audit: **531 passed, 0
   failed** (79 s) → không có regression; claim thời-điểm 513 hợp lý, không phản chứng.

### A3: **PASS (1 ISSUE [MEDIUM] path map collector + 2 [LOW])**

1. **Pre-reg timing: XÁC NHẬN TRƯỚC generation.** mtime: `configs/round7_7b.yaml`
   04:16:21 → `configs/attack_v2_cwe.yaml` 04:43:42 → `docs/round7_prereg.md` bản
   Amendment-1 **05:20:56** (report ghi 05:18 — khớp trong sai số lưu file) →
   generation RQ8 đầu tiên ~08:1x–08:33. RQ9 chưa từng có generation. ✅ Timeline
   4 mốc trong A3 §0 khớp filesystem từng mốc.
2. **H-G1/H-G2 khớp implementation.** `scripts/collect_master_round7.py`:
   `family_pass = p_exact<0.05 AND flip_b2v>flip_v2b` (đúng prereg §H-G1, gồm điều
   kiện hướng); H-G1 SUPPORTED ⟺ ≥3/4; H-G2 = ΔFP≥0.15 AND p<0.05 AND b2v>v2b;
   p = **exact McNemar discordant-only** (`mcnemar_exact`, đúng biến thể đăng ký ở
   power note); label GENERALIZES / GENERALIZES-pooled-driven / FAMILY-DEPENDENT;
   `MIN_FAMILY_N=20` → "NOT-RUN/UNPOWERED" đúng §2.3.5; **anti-masking clause có
   thật trong code**: block() luôn emit cả per-family lẫn POOLED, verdict note ghi
   "Both per-family and pooled rows are ALWAYS reported". Runner metrics RQ8
   (`metrics_round7_rq8.json`, 320/320 records mỗi model) tính verdict bằng cùng rule
   text. ✅
3. **Amendment-1 trung thực, không che giấu thay đổi rule sau-hoc.** Đối chiếu
   3 phía prereg §0b ↔ `configs/round7_7b.yaml` ↔ collector/runner:
   (i) model qwen7b duy nhất (config `models.qwen7b`, `queue_order: ["qwen7b"]`;
   collector comment llama8b không chạy); (ii) registry CWE-476/416/190/200 — trùng
   bench A1; **F-PATH/CWE-22 cố ý KHÔNG map trong `FAMILY_ALIASES` → fail loudly**
   (minh bạch hóa supersede); (iii) sửa nhánh CEILING→ABSENT-STRONG khớp config
   `H-R7-harm-absent` ("STRONG if recall(A0)==1.0") và collector nhánh
   `NOT_SUPPORTED-ABSENT-STRONG` (recall≥0.999); (iv) rule algebra flips ≥10/≤3
   byte-consistent cả 3 phía; nhánh REVERSAL chỉ tồn tại ở framing prereg/collector
   (đúng thiết kế dual reporting — verdict chuỗi A2 in cạnh qua rows
   `A2_H_R7_harm_replicates/absent`). Mục "KHÔNG ĐỔI" (ngưỡng, ≥3/4, ΔFP≥0.15,
   anti-masking, no-MC, RR-separate) đối chiếu không thấy bị xê dịch. ✅
4. **[MEDIUM] Path map collector LẠC SO VỚI LAYOUT THỰC THI.** Prereg §4 đăng ký
   path tạm RQ8 = `outputs/experiments/round7_cwe/results_<model>.json` và bắt buộc
   "mọi thay đổi path khi runner A2 xuất hiện phải ghi vào amendment và KHÔNG được
   xảy ra sau khi generation RQ8 bắt đầu". Thực tế runner RQ8 ghi vào
   `outputs/experiments/round7_rq8/` (results granite2b + llama3b, 320/320 mỗi
   model, manifest 07:50) — **không có amendment nào cho path change** (prereg không
   sửa sau 05:20:56). Hệ quả tại giờ audit: `collect_master_round7.py --verify-only`
   in `[pending] RQ8 results (0/2 models): outputs/experiments/round7_cwe/...` —
   collector sẽ **defer toàn bộ RQ8** dù 640 records thật đang nằm trên disk. Không
   phải đổi rule, chỉ đổi path, nhưng đúng chữ prereg thì cần amendment; giờ phải
   bù một **amendment/execution-log ghi rõ post-hoc, path-only** + sửa map (comment
   đầu collector đã chừa chỗ "edit these two maps then, not the logic").
5. **Paper drafts: khớp claim 55/60 chính xác.** Đếm bằng chương trình trên
   `paper/**/*.tex`: **55 token `{{R7:*}}` duy nhất / 60 vị trí thật** (tab.rq8=30,
   tab.rq9=11, prose=14; 5 token dùng 2 vị trí: llama3b.verdict_clause,
   identity_clause, 3 recall ladder) + 2 vị trí ví dụ `{{R7:...}}` trong caption
   `tab_round7.tex`. Grep "detokenize{{R7:" hôm nay = **63** (A3 khai 62 — lệch 1
   dòng comment, cosmetic). **Không có số hardcode mới**: mọi số trong subsection
   RQ8/RQ9 của `05_results.tex` và trong `tab_round7.tex` là số vòng trước hoặc
   hằng prereg (memcpy 49/28/19/10; granite C0 FP 0.043; 28/34 flips R6; power
   6/20=0.03125, 2/2¹²≈4.9e-4, 6/30; sha 2daa249f7543f8e0; seed 20260923); phần
   "Results." của cả RQ8 lẫn RQ9 chỉ gồm token. Đoạn RQ9 là **registered-pending
   framing** thuần (design + branches + caveat family), không có chỗ nào gợi ý đã có
   kết quả. ✅
6. **Tectonic xanh với token `\detokenize`:** compile lại thật — 0 error, ~13 s,
   PDF 17 trang (A3 khai 18 — lệch trang do repo tiến, cosmetic), `'??' = 0`,
   **45 hit `R7:`** render nguyên văn trong pdftotext (đúng như A3 khai). ✅
7. **[LOW] `06_discussion.tex` §sec:round7scope (dòng 133-135) còn registry CŨ**:
   liệt kê "use-after-free, integer overflow, **path traversal**, NULL dereference"
   — mâu thuẫn Amendment-1 (F-PATH/path traversal đã bị thay bằng CWE-200
   information exposure). `05_results.tex` và `fig_round7` caption đã đúng CWE-200.
   S phải sửa dòng này khi điền (hoặc bây giờ), kèm chú thích rằng đây là sót
   pre-amendment.

### Kiểm kê chéo khác
- `pytest tests/ -q` = **531 passed, 0 failed** (79.21 s) — Checklist 8: số 513/490
  là giá trị thời-điểm của A2/A3; hiện tại xanh, không fail cũ sống lại.
- `outputs/master/` KHÔNG có file `round7_*` — đúng hợp đồng fail-safe của A3
  (không tự sinh master khi chưa có data). ✅
- `collect_master_round7.py --verify-only` exit 0 khi chưa có master ✅ (fail-safe
  đúng), nhưng thấy đúng ISSUE path-map nêu trên.
- A1 report ↔ bench thực thi: 4 family × (20+20) × 4 arm = 160 rows; metrics RQ8
  320 records/model (2 arm gate C0/C5_near) — nhất quán với Amendment-1 (ii).

---

## CONFIRMED BUGS

1. **Auto-chain 7B không fire sau khi install weights (A2, [MEDIUM]).** Weights xong
   08:23 nhưng không `smoke_7b.json`/`queue_driver.py`/`queue.log`/`jobs_status.json`
   nào được tạo; không process còn sống; log chain nằm ở /tmp đã mất theo reboot
   ~12:04 → nguyên nhân gốc không truy vết được (nghi vấn mạnh: OOM/`ScaleUpBlocked`
   trong smoke do MPS bị queue RQ8 chiếm từ 08:15). Thiếu hẳn dấu vết thất bại trong
   repo — watchdog như mô tả không ghi vào nơi bền.
2. **Collector path map RQ8 stale (A3/A2, [MEDIUM]).** Prereg §4 yêu cầu amendment
   trước generation khi path thực thi khác path tạm; layout thật là
   `outputs/experiments/round7_rq8/` nhưng collector + prereg vẫn trỏ
   `round7_cwe/` → hiện tại collector defer toàn bộ RQ8 bất kể 640/640 records đã có.
   Phải bù amendment post-hoc (path-only, ghi rõ hậu kiểm) + sửa `RQ8_DIR`/map.
3. **[LOW, latent] Collector có thể gán GENERALIZES khi chỉ ≤3 family powered**
   (`label` chỉ xét `len(passing)>=3`, không xét `n_powered`) trong khi prereg §2.3.5
   chốt "≤3 family chạy được → chỉ FAMILY-DEPENDENT hoặc pooled-driven". Không fire
   với data hiện tại (cả 4 family đều 20/20 benign, 4 powered) — sửa 1 dòng trước khi
   S chạy collector.
4. **[LOW] `06_discussion.tex` §sec:round7scope registry cũ "path traversal"** —
   mâu thuẫn Amendment-1 (CWE-200). Sửa trước/ khi điền slot.

## FALSE CLAIMS

Không có claim bịa số hay gian lận nào từ A2/A3. Hai mục cần cảnh báo (không phải
nói dối tại thời điểm viết, nhưng đã bị thực tế phủ nhận / sắp sai nếu dùng):

- A2: "queue RQ9 **tự khởi động** khi weights xong, không cần can thiệp" — bị phủ
  nhận bởi filesystem (weights xong 08:23, không có gì tự khởi động). S **không được
  chờ queue tự lên**; phải chạy thủ công §4(2) nếu quyết định chạy RQ9.
- (Cảnh báo cho S, xem RQ9 DECISION) Nếu ai ghi "RQ9 NOT_RUN do lỗi mạng/hạ tầng
  download" tại thời điểm NAY thì đó là claim SAI: download đã thành công 08:23.

## AI SAI / AI BẮT ĐƯỢC

- **A2 sai (dự báo vận hành):** auto-chain "tự khởi động" không fire sau khi weights
  xong 08:23 — thất bại im lặng, log /tmp mất theo reboot 12:04, không để lại dấu
  vết trong repo. Bị V2 bắt qua đối chiếu blob-size/mtime ↔ thiếu artifacts.
- **A2 đúng:** trung thực 0/240 (không có 1 chữ gợi ý chạy thật); dry-run + 23 tests
  + model-guard thật; config sha `8000706d38384ebe` và bench sha `2daa249f7543f8e0`
  khớp khi tính lại độc lập; con số 15.23 GB đúng đến từng byte.
- **A3 đúng:** pre-reg + Amendment-1 TRƯỚC generation (05:20 < 08:1x); rule algebra
  khớp 3 phía prereg↔config↔code; 55 token/60 vị trí chính xác tuyệt đối; tectonic
  xanh; không số hardcode mới; RQ9 giữ registered-pending framing.
- **A3 bị bắt:** collector path map stale (`round7_cwe` vs thực thi `round7_rq8`) —
  đúng lỗi quy trình mà chính prereg §4 dự liệu; 1 chỗ registry cũ "path traversal"
  trong 06_discussion; 1 nhánh latent GENERALIZES-vs-§2.3.5 trong collector.

## RQ9 DECISION

Trạng thái thật tại giờ audit (bằng chứng filesystem): **generation 0/240; weights
15.23 GB ĐÃ HOÀN THÀNH trên disk từ 08:23 đúng rev config; smoke chưa từng chạy
(không có tok/s, chưa khoá dtype thực thi); queue chưa từng lên; auto-chain chết im
lặng.** Không có S_report/ROUND7_SUMMARY round7 tồn tại để ghi quyết định — quyết
định đang thuộc về orchestrator, và V2 khuyến nghị chuẩn trung thực như sau:

1. **Nhãn đúng là PENDING-BOX (registered, staged), KHÔNG phải NOT_RUN, và càng
   không phải out-of-scope.** Ba lý do: (a) prereg đã đăng ký RQ9 và frozen — không
   thể "out-of-scope" mà không vi phạm chính prereg; (b) điều kiện NOT_RUN của prereg
   §3.1 là "OOM/technical không host được" — điều đó CHƯA bao giờ được kiểm định vì
   smoke chưa chạy, còn lý do mạng thì đã HẾT hiệu lực từ 08:23; (c) pipeline đã test
   và weights sẵn sàng — queue cách vài lệnh đã verify cú pháp.
2. **Nếu orchestrator quyết định KHÔNG chạy RQ9 trong vòng này** (budget/GPU đã pivot
   sang RQ8 + hết phiên): giữ mọi slot `{{R7:rq9.*}}` và `{{R7:tab.rq9.qwen7b.*}}`
   nguyên token (paper compile được — đã chứng minh), giữ wording "2–3B" theo prereg
   §3.5, và disclose ở limitations với **lý do thật**: "registered 7B replication
   staged and fully downloaded, but not executed this round: GPU time was allocated
   to RQ8 and the automated chain failed silently after download; execution remains
   one command away (smoke → queue)". Tuyệt đối KHÔNG ghi "network/infrastructure
   failure" — sai từ 08:23. Đây là điều kiện để S điền paper sạch: mức disclose phải
   khớp nguyên nhân thật, không mượn nguyên nhân cũ đã hết hạn.
3. **Nếu chạy tiếp:** theo đúng lệnh A2 §4(2) (đã audit: path/HF_HOME/JOBS đúng —
   weights nằm đúng `models_dir/hf` mà runner dùng mặc định), smoke trước để có
   tok/s + dtype thật, rồi queue nohup; nếu smoke OOM cả bf16 lẫn fp16 **khi MPS
   trống** thì đó mới là NOT_RUN hợp lệ theo §3.1. Sau đó collector sinh token map;
   không điền tay.
4. **Cản phải sửa trước khi S điền bất cứ thứ gì:** (i) amendment post-hoc path-only
   cho `round7_rq8/` + sửa map collector, nếu không RQ8 rows sẽ không build; (ii) sửa
   nhánh latent (3); (iii) sửa "path traversal" trong 06_discussion. RQ9 không thể bị
   "nhiễm số" nhầm: collector refuse build RQ9 khi chưa có 3 file vul + benign, và
   paper vẫn xanh với token.

---
*Verification của V2: 531 pytest pass; tectonic 0 error/17 trang/0 '??'/45 token hit;
sha config `8000706d38384ebe` + bench `2daa249f7543f8e0` tính lại độc lập; đếm token
bằng script; blob 4 shard = 15,231,271,864 B; `collect_master_round7.py
--verify-only` exit 0; KHÔNG sửa bất kỳ file repo nào ngoài report này; KHÔNG chạy
GPU; KHÔNG đụng download.*
