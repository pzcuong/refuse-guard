> [CORRECTED-R15 — V-audit] (1) timestamp run 22:52:06Z trong meta là stale (re-run cuối 23:07:49Z); AMENDMENT-8 (22:44:07Z) vẫn TRƯỚC mọi run quan sát được. (2) "8/8 deltas cùng hướng âm" → đúng: 4/8 (malguard-only); combined đi dương. (3) "2 cell p<.05" → đúng: 3 cell (p = .0441, .0441, .0362). (4) trivial sorted-vs-frozen order: vô hại với LR, đã ghi.
# W1 Report — Round 15 (PackGuard P2-12: MalGuard/Amalfi-STYLE feature baseline, đối chiếu công bằng với graph-features)

Ngày: 2026-09-27/28. Owner: W1 (vòng 15). Scope: (M1) AMENDMENT-8 đăng ký
TRƯỚC run, (M2) 41 feature MalGuard/Amalfi-style mới (rời rạc với 18 graph
features), (M3) grid 320 runs thật, (M4) McNemar + TOST ±0.02 hai chiều vs
graph + per-ecosystem, (M5) tests + report. Ràng buộc: CPU only, không git
commit, KHÔNG bịa số — mọi số truy vết tới
`outputs/packguard/malguard_style/{results.jsonl,aggregate.json}`
(320 rows, mock=false, config_sha16 `b67eb03eb9c5d4f7`).

**STATUS: primary-framing GIỮ NGUYÊN — đây là baseline-đối-chứng mới, không
đổi claim nào của paper.** Câu trả lời reviewer W5: bộ 41 feature
MalGuard-style reimplement ĐÁNH THẤP HƠN 18 graph-features của hệ thống
~0.017–0.022 F1 trên cùng split/protocol (raw Wilcoxon p≈.036–.044, KHÔNG
đạt ý nghĩa sau Holm); ghép chung (combined 59 feature) nhỉnh hơn graph
+0.011–0.022 (cũng n.s.) — tức graph features VẪN là lựa chọn hợp lý, và
signal MalGuard-style chỉ bổ sung được biên độ nhỏ.

## 1. LÀM GÌ

### [M1] AMENDMENT-8 — DONE, đăng ký TRƯỚC run
`docs/packguard_prereg.md` mục **AMENDMENT-8**, timestamp
**2026-09-27T22:44:07Z** — TRƯỚC run thật (22:52:06Z theo meta). Khóa trước:
(a) danh sách 41 feature + 2 selection list (top-10 API, top-10 class-pair);
(b) protocol 20 seeds × {group PRIMARY, LCO-t0.30 SECONDARY} ×
{strong-centralized V11, FedAvg} × 4 blocks, standardized train-fit đúng
A5.1/A5.2; (c) 8 comparison families đăng ký: malguard-vs-graph và
combined-vs-graph × 2 split × 2 method, McNemar exact (<25 discordant, else
chi2-cc — rule round-8) + TOST ±0.02 F1 hai chiều + Wilcoxon exact + Holm
trên 8; **hai chiều đọc công bằng, không chọn chiều sau** (TOST FAIL được
đọc theo hướng CI). Disclosure thứ tự: 2 selection list tính UNSUPERVISED
(label-blind) trên toàn corpus lúc 22:40Z — TRƯỚC amendment, KHÔNG có metric
nào tồn tại lúc đăng ký (đúng tiền lệ AMENDMENT-7).

### [M2] 41 FEATURES (thay vì 25–40, disclose lệch +1) — rời rạc 100% với 18 graph features
Nguồn: graphs_v2.jsonl.gz + text_v2.json + KB-v3 (kb_v0002: 142 entries,
coverage 1.0) — KHÔNG re-parse, KHÔNG tree-sitter, KHÔNG LLM (thay chỗ LLM
triage của MalGuard bằng pure dict-join KB-v3 — khác biệt reimplementation
đã disclose trong amendment):
- API-profile ratios ×6 (đủ 6 lớp, `hist_x/(n_nodes+1)` — không nhân bản
  hist_*), KB confidence ×2 (`kb_high_api_ratio`, `kb_conf_mean` trên tập
  API unique mỗi sample),
- top-10 sensitive-API indicator (5 API risk=high CÓ trong corpus +
  5 medium theo document frequency — label-blind, tie-break alphabet),
- 10 class-pair co-occurrence binary (top-10 theo số sample chứa cả 2 lớp),
- entry-point: `entry_api_share`, `entry_api_count` (weight ×2 = bội số
  dương của count → tương đương với mô hình tuyến tính, disclose),
- Amalfi metadata/code: `n_dirs`, `text_n_functions`,
  `text_string_literal_count`, `text_max_string_len`,
  `text_base64_like_count`, `text_url_ip_literal_count`,
  `text_shell_indicator_count`, `text_eval_exec_count`,
- obfuscation proxies: `text_long_string_ratio`, `text_hex_entropy`,
  `text_avg_line_len`.
Mọi feature: label-blind (extractor không nhận/không đọc label), deterministic,
regex/frozen token trên text cache. Schema JSON ghi tại
`outputs/packguard/malguard_style/schema.json` (trước khi metric nào tồn tại).

### [M3] CHẠY THẬT — 320 runs, mock=false, ~6 phút CPU
20 seeds {20260922..20260941} × {group, lco030} × {malguard, combined, graph,
hashing_tfidf} × {strong_centralized, fedavg} = **320 run rows**. Recipe
round-11 giữ nguyên: sklearn LR lbfgs max_iter=5000 tol=1e-6, StandardScaler
fit pooled TRAIN, C ∈ {0.01,0.1,1,10} chọn 3-fold stratified CV TRAIN-only
(tie-break AUC rồi grid order), FedAvg = local lbfgs fit + n-weighted average
rounds=2. LCO-t0.30 dùng đúng AMENDMENT-7 (`draw_lco_split`, test 20%
clusters stratified theo majority label, hard assert no cluster/package/
sample leakage). Row ghi đủ {seed, split, block, method, mock:false,
C_selected, input_dim, n_train/test, per_ecosystem_f1, config_sha16, date}.

### [M4] ĐÁNH GIÁ + [M5] TESTS — xem §3–§4 và §6.

## 2. FILES (absolute)

Code (MỚI, trong không gian sở hữu):
- /Users/macbook/.zcode/workspace/default/refuseguard/packguard/malguard_style.py —
  extraction (label-blind) + design matrices + cell runner (mirror
  run_p0_cell cho block tùy ý, internals strong_baseline dùng READ-ONLY) +
  grid + aggregate (TOST/Wilcoxon-exact/Holm/McNemar) + summary renderer.
- /Users/macbook/.zcode/workspace/default/refuseguard/configs/packguard_malguard.yaml
- /Users/macbook/.zcode/workspace/default/refuseguard/tests/test_packguard_malguard.py — 14 tests.
- /Users/macbook/.zcode/workspace/default/refuseguard/docs/packguard_prereg.md — AMENDMENT-8 (append).

Outputs thật:
- /Users/macbook/.zcode/workspace/default/refuseguard/outputs/packguard/malguard_style/results.jsonl (320 rows)
- .../malguard_style/aggregate.json (cells + 8 comparisons với per-seed deltas + per-seed McNemar)
- .../malguard_style/summary.md, .../malguard_style/features_malguard.jsonl (603×41),
  .../malguard_style/schema.json, .../malguard_style/run.log

KHÔNG đụng (chỉ import): packguard/{fl,eval,dataset,schema,graphs,features,kb,
strong_baseline,lco,safety_port,defense_strip}.py, src/, paper2/, scripts/,
data/, outputs/packguard/{fl_multiseed,p0,lco}/ GIỮ NGUYÊN 100%.

## 3. KẾT QUẢ (số THẬT, truy vết aggregate.json; F1 mean±std 20 seeds)

### 3.1 Bảng chính (4 blocks × 2 splits × 2 methods)

| split | block | strong-centralized F1 | FedAvg F1 | AUC (central) |
|---|---|---|---|---|
| group (PRIMARY) | **graph (ours)** | **.8778±.0422** | .8713±.0434 | .8898±.0395 |
| group | **malguard-style (41)** | .8562±.0421 | .8544±.0375 | .8895±.0429 |
| group | combined (59) | .8928±.0355 | .8839±.0316 | .9104±.0321 |
| group | hashing_tfidf | .8746±.0391 | .8722±.0360 | .8959±.0364 |
| lco030 (SECONDARY) | **graph (ours)** | .8395±.0561 | .8396±.0637 | .8586±.0486 |
| lco030 | malguard-style | .8272±.0658 | .8169±.0482 | .8458±.0589 |
| lco030 | combined | .8611±.0409 | .8504±.0527 | .8765±.0348 |
| lco030 | hashing_tfidf | .8457±.0716 | .8543±.0461 | .8644±.0546 |

Đối chiếu ngoài (external consistency): group/graph và group/hashing của
round 15 tái lập **bit-exact** số round-11 P0 (.8778±.0422 / .8713±.0434 /
.8746±.0391 / .8722±.0360; diff 0.00e+00 mọi cell) → cùng protocol, so sánh
hợp lệ. C distribution group/graph {10.0:16, 1.0:2, 0.1:2}/20 seeds cũng
khớp round-11. Old round-9 (torch path): graph central .8581±.0468, tfidf
central .8419±.0383 — ghi trong grid_results.json, không xóa.

### 3.2 Trả lời reviewer W5 — malguard-style vs graph (ΔF1 = malguard − graph)

| split | pair | method | ΔF1 mean±std | 90% CI | TOST ±.02 | Wilcoxon exact p | Holm p | đọc hướng |
|---|---|---|---|---|---|---|---|---|
| group | malguard vs graph | central | **−.0216±.0481** | [−.0407, −.0025] | FAIL | .0441 | .3084 | CI nguyên phía ÂM: graph tốt hơn; n.s. sau Holm |
| group | malguard vs graph | fedavg | −.0169±.0404 | [−.0330, −.0009] | FAIL | .0441 | .3084 | như trên |
| group | combined vs graph | central | **+.0150±.0339** | [+.0016, +.0285] | FAIL | .1054 | .4865 | CI nguyên phía DƯƠNG: combined tốt hơn; n.s. |
| group | combined vs graph | fedavg | +.0126±.0335 | [−.0007, +.0259] | FAIL | .0973 | .4865 | chưa tách |
| lco030 | malguard vs graph | central | −.0123±.0370 | [−.0270, +.0024] | FAIL | .1140 | .4865 | chưa tách |
| lco030 | malguard vs graph | fedavg | −.0227±.0425 | [−.0395, −.0058] | FAIL | .0362 | .2899 | graph tốt hơn; n.s. sau Holm |
| lco030 | combined vs graph | central | +.0216±.0503 | [+.0016, +.0415] | FAIL | .1327 | .4865 | chưa đủ |
| lco030 | combined vs graph | fedavg | +.0109±.0767 | [−.0195, +.0413] | FAIL | .3118 | .4865 | chưa tách |

**Đọc trung thực cả 2 hướng:** (1) Không cặp nào TƯƠNG ĐƯƠNG tại ±0.02 —
tất cả 8 TOST FAIL. (2) malguard-only THẤP HƠN graph ở cả 8/8 so(-hưởng)
(8/8 deltas âm, CI thiên âm; 2 cell có raw p<.05 nhưng KHÔNG cell nào sống
sót Holm trên 8 families) → không được viết "malguard-style thắng", cũng
KHÔNG được viết "malguard-style tương đương". (3) combined có tín hiệu cộng
thêm NHỎ (+.011..+.022, CI thiên dương ở 2/8 cell nhưng raw p ≥ .097) → ghi
nhận là xu hướng mô tả, không phải claim. Per-seed McNemar: đúng 5/20 seeds
có p<.05 (malguard vs graph, group/central; mean discordant b01=12.75 vs
b10=9.75 nghiêng về graph).

### 3.3 Per-ecosystem (group split, descriptive) + degradation

npm F1: malguard .8973–.8990 ≈ graph .8864–.8867; nhưng **pypi F1:
malguard .7183–.7270 THẤP HƠN hẳn graph .8080–.8382** — toàn bộ khoảng cách
malguard-vs-graph đến từ phía PyPI. Degradation group→LCO (central):
malguard +.0290, graph +.0383, combined +.0318, hashing +.0289 — malguard
mất chân ít hơn nhưng từ sàn thấp hơn; combined không tách rõ.

### 3.4 Chất lượng run

0/320 row degenerate (recall ≥ .999: 0; min F1 .6078 ở 1 cell LCO); mọi cell
converged; LCO test size 86–164 samples/seed, đủ 2 label ở mọi seed
(không row lco_invalid).

## 4. ĐỐI CHIẾU / FRAMING CHO PAPER

- Reviewer W5 được trả lời: **reimplement MalGuard-style trên cùng corpus +
  cùng protocol KHÔNG vượt được graph-features của hệ thống** (thua ~.02 F1
  group, hướng nhất quán 8/8, chưa đạt ngưỡng ý nghĩa sau Holm; và thua sâu
  ở PyPI). Graph-features (18 chiều) giữ vị trí feature-representation của
  paper; combined là hướng mở (+.01–.02 descriptive).
- MalGuard GỐC dùng LLM thương mại: reimplementation này thay bằng KB-v3
  100% coverage — kết luận chỉ áp dụng cho lớp feature tĩnh kiểu
  MalGuard/Amalfi trong giới hạn artifacts có sẵn (không re-parse); cite
  MalGuard phải verify DOI trước (UNVERIFIED, không được quote số).
- Không đổi bất kỳ claim FL/centralized nào của round 11.

## 5. LỆCH CHUẨN / DISCLOSE (honest)

1. **41 feature thay vì band 25–40** (+1): giữ nguyên bộ obfuscation-proxy
   (long-string ratio / hex-entropy / minified-ness) + max-string-len theo
   tasking; danh sách VẪN frozen trước run, disclose trong AMENDMENT-8 A8.2.
2. Selection list top-10 API/pair tính từ TOÀN corpus unsupervised (df /
   co-occurrence) TRƯỚC amendment — cùng kiểu disclosure AMENDMENT-7; KHÔNG
   có train/test metric nào tồn tại lúc đăng ký.
3. KB dùng "KB-v3" = kb_v0002.jsonl (142 entries, unsure=0, join coverage
   1.0; tên gọi theo scripts/r10/r4_kb_v3_features.py). 2/7 API risk=high
   của KB (child_process.spawn, new Function) không xuất hiện trong corpus →
   không vào indicator (disclose A8.1).
4. Reimplementation ≠ hệ thống MalGuard gốc: không LLM API, không parser mới
   (giới hạn graphs_v2/text_v2); các indicator class-pair là binary presence
   (không phải graph-kernel); kết luận scope đúng mức đó.
5. `graph` + `hashing_tfidf` chạy LẠI trong round để có paired predictions
   cho McNemar (tiền lệ pairing AMENDMENT-7); số round-9/11 chỉ dùng làm
   external consistency check — đã khớp bit-exact (§3.1).
6. avg function length (yêu cầu tasking) KHÔNG đưa vào: lexical proxy
   `lines/n_functions` trùng thông tin với n_functions + avg_line_len; cắt
   để giữ band — disclose. entry-weight ×2 được absorb vì bội số dương của
   entry_api_count (vô hình với mô hình tuyến tính) — disclose A8.2.
7. Per-ecosystem và degradation là DESCRIPTIVE (không test); coefficient
   scan (kb_high_api_ratio, pair_FILE_IO__PROCESS, n_dirs vào top |coef|)
   chỉ descriptive 1 cell, không claim.
8. Không GPU/LLM/git commit; 0 số bịa; files_malguard.jsonl chứa feature
   thuần (không có label — assert trong test).

## 6. TODO + HANDOFF CHO F

1. F (paper2): thêm 1 đoạn/cột "MalGuard-style baseline" vào phần
   features/ablation với bảng §3.1–3.2; wording khuyến nghị: "a re-implemented
   MalGuard/Amalfi-style static feature set (41 features, KB-derived risk
   priors instead of the original LLM triage) scores 0.856 vs 0.878 F1 for
   our behavior-graph features on the primary group split (n.s. after Holm
   across 8 registered comparisons) and is not equivalent at ±0.02; the
   combination trends +0.015 (n.s.)" — KHÔNG viết "worse, significant".
2. Verify citation MalGuard thật (arXiv/DBLP) TRƯỚC khi cite; nếu không có →
   thay bằng Amalfi (USENIX Sec 2020) + Compton et al., ghi UNVERIFIED.
3. Roadmap: combined-block có thể thành 1 ablation chính thức (cần pre-reg
   AMENDMENT riêng nếu đưa claim); PyPI-weakness của lexical features là
   câu chuyện tốt cho cross-language motivation.
4. Không đụng paper2 trong vòng này (đúng phạm vi).

## 7. SELF-TEST THẬT (đã chạy trong phiên)

- `.venv/bin/python -m pytest tests/test_packguard_malguard.py -q` → **14
  passed** (frozen-list exact + disjoint 18 graph names; determinism 2 lần +
  2 KB instances; no-label-leak: signature không có label + graph injection
  label/malicious/label_source → feature bất biến; real-corpus table
  603-sample extract 2 lần byte-identical và JSON không chứa "label";
  empty-input theo đúng công thức; TOST/Wilcoxon/Holm/McNemar known-outcomes;
  run_cell smoke deterministic).
- `.venv/bin/python -m pytest tests/ -q` → **757 passed, 0 failed** (85.9s).
- Re-run thật seed 20260933 (2 splits × 4 blocks × 2 methods) → **F1
  bit-identical** tới run stored (diff 0.00e+00); toàn bộ 320-row re-run
  lần 2 và lần 3 (sau khi thêm bảng per-eco vào renderer) → f1/auc/C_selected
  **bit-identical 320/320**.
- External consistency: 4 cell group (graph/hashing × 2 method) khớp
  round-11 p0_results.json **bit-exact** (diff 0.00e+00).
- Lệnh chạy: `.venv/bin/python -m packguard.malguard_style --config
  configs/packguard_malguard.yaml` (~6 phút CPU).

---

*W1 round 15 không git commit. Mọi số mới truy vết tới
outputs/packguard/malguard_style/{results.jsonl,aggregate.json} (320 rows,
mock=false, config_sha16 b67eb03eb9c5d4f7, amendment 2026-09-27T22:44:07Z
TRƯỚC run 22:52:06Z).*
