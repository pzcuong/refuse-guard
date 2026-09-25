# Improvement Roadmap v2 — PackGuard (post round-9 audit)

Ngày: 2026-09-25. Nguồn: kết quả audit các action (stats-1..8, safety-1..6,
novelty-2..8 — verdict accepted/modified) + reports/round9/{V1,V2,W1,W2}_report.md.
Phiên 2026-09-25 đã áp TOÀN BỘ phần write-only vào `paper2/main.tex`
(compile `tectonic main.tex` exit 0); tài liệu này là kế hoạch chạy cho TOÀN BỘ
newRun còn lại. Không mục nào dưới đây đã được chạy.

## 0. Quy tắc bất di bất dịch

- **AMENDMENT-4 trước khi chạy** (mục 1): mọi thay đổi thiết kế/statistic phải
  nằm trong `docs/packguard_prereg.md` với timestamp TRƯỚC run đầu tiên.
  Cấm tune ngầm (W1 TODO #2 nguyên văn: "lr sweep hoặc early-stop ... phải là
  AMENDMENT-4, không tune ngầm").
- **Ràng buộc model <4B** (PACKGUARD_BRIEF.md §2): chỉ Qwen2.5-Coder-3B,
  Llama-3.2-3B, granite-3.3-2b, Qwen2.5-Coder-0.5B (smoke). KHÔNG tải model ≥4B.
- mock/dry không lẫn số thật; mọi số truy vết outputs; không git commit khi
  chưa được yêu cầu; pytest full sau mỗi thay đổi code (`pytest tests/ -q`,
  baseline 641/0).
- Con số scoped (đếm lại từ raw 2026-09-25): RR=0 trên ĐÚNG 2,700 defensive-task
  generations ở model 2–3B = round-3 vulnerability-domain 1,080 (E0 arms 180 +
  E2/E3 conditions 900; raw `outputs/experiments/round3_e0` + `round3_e2e3`,
  0 REFUSAL) + E0v2 1,200 (round5_master.json) + package-domain 420 (360 + 60).
  Trong cùng runs round-3, các PROBE orbench_hard (nội dung có hại thật) bị
  refuse 125/225 — refusal pathway hoạt động, task defensive không kích nó.
  Pilot round-2 (0.5B, 90 defensive-arm records) KHÔNG tính vào 2,700 vì không
  phải model 2–3B. **CẤM** viết "RR=0 trên ~6,250" — 6,250 là
  TỔNG generation toàn dự án (reports/round7/ROUND7_SUMMARY.md:48). **CẤM**
  ghi chú thích "E0 1,080" — 1,080 là tổng row RR của round-3 (E0 180 + E2/E3 900),
  không phải riêng E0.
- RefusEU: 0 hit trong `paper2/refs.bib` + `docs/packguard_refs.bib` — **chưa
  được cite; phải đọc full-text trước khi dùng** cho nghĩa "alignment bảo toàn
  ở model lớn nhưng không ở model nhỏ". Trước đó, mọi claim scale giữ dạng
  "closed at 2–3B, direction follows family".
- KHÔNG swap shim trong `configs/round9_8b.yaml` (byte-identity-guarded cho
  llama8b theo header config). Arm granite tạo config riêng.

## 1. AMENDMENT-4 (bắt buộc, chung cho R1–R5) — draft nội dung

Ghi vào `docs/packguard_prereg.md` (mục `## AMENDMENT-4`) với timestamp +
tuyên bố thứ tự, TRƯỚC khi chạy R1. Nội dung đóng băng:

1. **Seeds**: 20 seeds = [20260922..20260941] (5 seed cũ giữ nguyên 5 vị trí đầu).
2. **Họ 8 comparisons chính** (đóng băng định nghĩa, partition=ecosystem):
   {group,random} × {graph,tfidf} × {fedavg-vs-centralized, graph-vs-tfidf}.
   Định nghĩa graph-vs-tfidf: paired per-seed trên cùng (split, seed),
   so FedAvg-graph vs FedAvg-tfidf VÀ centralized-graph vs centralized-tfidf
   (2 họ phụ, báo riêng, không gộp).
3. **Thống kê**: Wilcoxon signed-rank exact two-sided over per-seed deltas +
   Holm correction (familywise α=.05 trên 8 comparisons); kèm achieved power
   cho ΔF1 thực đo (formula: n cần cho Wilcoxon normal approx với effect size
   dz = meanΔ/sdΔ, α hai phía, power .80 — ghi công thức trong amendment,
   không chỉ assert). TOST equivalence cho claim "decentralization preserves
   utility": margin δF1 = 0.02, prereg TRƯỚC khi chạy (novelty-2).
4. **std ddof=1** nhất quán mọi aggregate (hiện ddof=0, V1_report.md:47-50);
   ghi rõ trong mọi bảng.
5. **Arm centralized-stabilized** (R2), **arm GNN** (R4), **grid kb_on v3** (R5),
   **persist final_probs + threshold rule** (R3) — cùng amendment.
6. **Feasibility/power**: n=20 → Wilcoxon exact two-sided min p = 2/2^20 ≈
   1.9e-6 → có thể đạt α=.05 (khác n=5: min p .0625).

## R1. Multi-seed grid 20 seeds + thống kê có power — **P0**

- **What**: mở grid từ 5 → 20 seeds; chạy lại toàn bộ; tham số hóa power_note;
  script phân tích mới (Holm, achieved power, TOST, variance decomposition
  seed/split/feature-block, per-client breakdown, AUC-PR).
- **Why**: audit stats-1 (accepted) + novelty-2 (modified): n=5 min p=.0625 >
  .05 — "mọi p-value hiện tại không sống qua review Q1" (F_report.md:266-267);
  Wilcoxon graph-vs-tfidf chưa có code (`_aggregate_grid` hiện chỉ tính
  fedavg-vs-centralized; power_note hardcode 'n=5' tại `packguard/eval.py:469-471`;
  seeds là config param `configs/packguard_fl.yaml:57`, đọc tại
  `packguard/eval.py:774`).
- **Cost**: 640 rows ≈ 4× grid hiện tại (62 s/160 runs tại W1_report.md:26) →
  **~4–5 phút CPU**, 0 GPU/LlM. Dev script ~1–2 h.
- **Expected evidence**: Wilcoxon 8 comparisons với Holm-adjusted p; TOST
  (δ=.02) cho graph group-split; mean±std ddof=1 thay bảng tạm 5-seed trong
  paper (tab:main/tab:stats đã dựng khung, chỉ nhập số mới); AUC-PR
  (sklearn `average_precision_score` — đã verify import được trong venv);
  variance decomposition + per-client breakdown → 1 subsection §Results.
- **Commands**:
  1. Sửa `docs/packguard_prereg.md` (AMENDMENT-4, mục 1).
  2. `configs/packguard_fl.yaml` dòng 57: `seeds: [20260922, ..., 20260941]` (20 giá trị).
  3. Sửa `packguard/eval.py:469-471` power_note theo n (f-string, giữ test).
  4. `.venv/bin/python -m packguard.eval --grid` → `outputs/packguard/fl_multiseed/grid_results.json`.
  5. Script mới `scripts/analyze_grid_stats.py`: Holm + power + TOST + AUC-PR
     + decomposition từ grid_results.json (sklearn/scipy/statsmodels — có sẵn).
  6. `.venv/bin/python -m pytest tests/test_packguard_multiseed.py -q` rồi full suite.

## R2. Arm centralized-stabilized — **P1**

- **What**: centralized + lr sweep {0.01, 0.03, 0.1} + early-stop trên 10%
  train (train-CV, không đụng test); tái dùng `_grid_cell`.
- **Why**: audit stats-4 (accepted): 1/40 cell centralized sụp (random/graph
  seed 20260923 F1=.375, tái lập d=0) trong khi 40/40 cell FL ổn định
  (min FedAvg F1 .7375) — kết luận central-vs-FL 1-seed có thể sai cả 2 hướng.
- **Cost**: 240 runs = 20 seeds × 2 splits × 2 blocks × 3 lr ≈ **15–20 phút CPU**.
- **Expected evidence**: (i) collapse rate cell F1<0.70 (so 1/40); (ii) re-test
  FedAvg-vs-centralized dưới baseline ổn định. Aggregate pre-reg cũ GIỮ làm
  primary; arm mới chỉ vào bảng sensitivity (đã có chỗ trong tab:stats caption
  + Discussion 'retracted finding' của paper).
- **Commands**: AMENDMENT-4 mục 5 → thêm arm vào config grid →
  `.venv/bin/python -m packguard.eval --grid` (chạy chung R1 nếu cùng phiên).

## R3. Calibration + operating point + class-weight arm — **P1**

- **What**: (a) persist `final_probs` vào row grid (hiện dùng cho subgroup/
  McNemar tại `packguard/eval.py:555,:594` nhưng không persist); (b) ECE
  10-bin + Brier + reliability curve cho {graph,tfidf}×{FedAvg,centralized}×
  {group,random} trên grid 20-seed của R1; (c) threshold sweep 0.05–0.95
  chọn F1-optimal trên train-CV áp lên test; (d) arm class_weight='balanced'
  + per-client threshold cho tfidf-FedAvg (**code mới** trong
  `packguard/fl.py` — hiện KHÔNG có class_weight, chỉ tham số threshold tại
  `packguard/fl.py:602,:798`; sklearn LR hỗ trợ, sklearn có trong venv).
- **Why**: audit stats-5 (accepted): AUC .9605/.9260 central 1-seed
  (results.jsonl đọc trực tiếp, khớp F_report.md:89,92); multi-seed
  .8970/.8537 (W1 §3.1); tfidf-FedAvg degenerate recall=1.0 ở 20/20 cells,
  precision = base-rate.
- **Cost**: **~15 phút CPU** (chạy lại grid subset + analysis); dev ~2–3 h.
- **Expected evidence**: bảng calibration + reliability; operating-point-
  corrected comparison graph-vs-tfidf (viết lại đoạn 'split-decision' đã dựng
  khung trong paper); subgroup pypi = effect size + bootstrap CI (n=36,
  không p-value; n=29 cũ là số kế thừa F_report round-8, không tái lập được
  từ results.jsonl subgroup eco_pypi).
- **Commands**: AMENDMENT-4 mục 5 → sửa `_grid_cell` persist final_probs →
  `.venv/bin/python -m packguard.eval --grid` → script phân tích
  `scripts/analyze_calibration.py` (mới).

## R4. GNN baseline (thuần torch, không PyG) — **P1**

- **What**: GIN hoặc GraphSAGE 2 lớp; node feature = one-hot 137 API-type +
  6 semantic class (từ graphs_v2); mean-pool readout; head LR; 103
  empty-graph → zero-vector (disclosed); 20 seeds × 2 splits ×
  {GNN-FedAvg, GNN-central}; early-stop train-CV như R2 (chống label-leakage);
  paired Wilcoxon vs LR-graph và LR-tfidf cùng seeds.
- **Why**: audit stats-6 (accepted): `import torch_geometric` →
  ModuleNotFoundError (torch 2.14 + sklearn/scipy có); graphs_v2 = 603 samples
  (500 non-empty + 103 empty, khớp V2 §B7); gap là tự-thừa-nhận
  (F_report.md:268-270, paper2 đã bỏ chữ 'a GNN is future work' ở phiên này).
- **Cost**: **4–8 h dev + ~30–60 phút train** (CPU/MPS, model cổ điển nhỏ).
- **Expected evidence**: hàng GNN {FedAvg, centralized} trong tab:main hoặc
  bảng mới; kết luận tfidf-vs-graph cập nhật theo GNN; title + abstract soft
  theo hướng kết quả (chỉnh lần 2 khi có số).
- **Commands**: AMENDMENT-4 mục 5 → `packguard/gnn.py` (mới, thuần torch) →
  mở rộng grid config `feature_blocks: [graph, tfidf, gnn]` →
  `.venv/bin/python -m packguard.eval --grid`.

## R5. KB v3 qua FL (grid subset kb_on) — **P1**

- **What**: bật kb trong ablations, chạy cell kb_on (2 partitions × graph ×
  methods × 20 seeds); component leave-one-out 3 KB features; subgroup pypi
  effect size + bootstrap CI.
- **Why**: audit stats-7 (accepted) + novelty-7 (modified): row kb_on DUY NHẤT
  từng qua FL dùng KB v2 54.7% coverage (V2 §B5); coverage_v3.json đã regen
  137/137 types, 2299/2299 instances, instances_by_label 1673/626, npm/pypi
  1822/477, unsure=0 (đọc trực tiếp file, label_rule V2#B7 fix); kb_features
  là pure lookup, 0 LLM call (`packguard/kb.py:360-376`).
- **Cost**: **vài chục giây – vài phút CPU** (không LLM).
- **Expected evidence**: bảng tab:kb mới dưới KB v3 (kỳ vọng tác động nhỏ:
  risk_ratio bất biến .0745, confidence .878→.907, unsure→0 — nhưng phải đo,
  không assume); abstract câu KB + bảng utility-per-cost (static-only vs
  KB-augmented) vào Discussion.
- **Commands**: AMENDMENT-4 mục 5 → `configs/packguard_fl.yaml` ablations:
  kb_on → `.venv/bin/python -m packguard.eval --grid`.

## R6. Granite ladder (family thứ 3, matched-scale) — **P1**

- **What**: chạy granite-3.3-2b qua ladder vulnerability-domain
  (A0/A5/A1 + benign) — KHÔNG swap shim; tạo `configs/round9_granite.yaml`
  kế thừa `configs/round7_7b.yaml` + prompt-sha guard; pre-register CẢ HAI
  chiều đọc; disclose refusal-monitor fallback threshold như quy ước safety-port.
- **Why**: audit stats-8 (accepted) + safety-2 (modified): 0 row P3 trên
  granite trong cả 5 master files (đếm: round5 21, master_results 66,
  round6_ablation 23, round6_bias 46, round7 52 granite rows); llama3b P3
  recall 1.0→.3667/.3333 (round5_master.json) vs qwen3b P3 inert 1.0→1.0 —
  family contrast chưa đóng; khớp V2 §SCALE QUESTION STATUS option 2 +
  docs/literature_2026_refresh.md:50; đúng ràng buộc <4B (2B).
- **Cost**: ~240 gens × 512 tok trên MPS; throughput repo đo ~5.4 s/gen
  (300 gen/27 phút) đến ~30 s/gen → **0.4–2 h**.
- **Expected evidence**: inert → hại là llama-specific; harmed → harm là
  small-model generic. Cả hai chiều đều có chỗ đi vào trong paper (khung
  scale-vs-family đã tạo trong Discussion + Conclusion).
- **Commands**:
  1. `cp` nguồn tham khảo: tạo mới `configs/round9_granite.yaml` (model shim
     granite, giữ byte-guard của `round9_8b.yaml`).
  2. Prereg hai chiều trong report/amendment trước khi chạy.
  3. `.venv/bin/python -m src.experiments.round9_ladder --stage dry` (sanity, MockLLM).
  4. `.venv/bin/python -m src.experiments.round9_ladder --stage queue` (A0→A5→A1→benign).
  5. `.venv/bin/python -m src.experiments.round9_ladder --stage metrics`.

## R7. Safety n≥100/model + arm P3-FP + trục strength/query-relevance — **P0 design / chạy sau R1**

- **What**: thêm variants vào `configs/packguard_safety.yaml`: P3-FP
  (advisory CHỐT "code này sạch" — thử ép FP>0 trên benign, W2 TODO #3 tại
  W2_report.md:214-217) + 2–3 mức strength (neutral/strong) + trục
  query-relevance (generic vs query-relevant, kỷ luật C5 đã verify:
  docs/results_master_round5.md:88-89 "C5 thật sự query-relevant (100% vs
  0.2%) và không leak label/CWE/CVE"); anti-leakage pattern-check trên
  advisory text trước khi chạy; giữ AST-gate check_semantics; resume-safe.
  Human validation: review TẤT CẢ flips + stratified ~50 non-flips/model
  (số annotator disclose, kể cả 1); exact McNemar per arm + CI; công thức
  power trong prereg (n=100 mal/model phát hiện shift recall ≥.13 — viết
  công thức, không assert).
- **Why**: audit safety-3 (modified) + novelty-5 (modified): n=60 hiện chỉ
  2 model/2 family (Qwen2.5-Coder-3B chỉ là KB-builder, CHƯA từng chạy
  safety-batch — muốn 3 family phải thêm arm qwen); refusal-monitor fallback
  là per-model disclosure (180 true granite / 180 false llama trong
  safety_batch_n60.jsonl — KHÔNG nói "mọi record true"); FP=0/180 có thể do
  chưa từng thử hướng ngược.
- **Cost**: 4 arms × 100 mal × 2 model ≈ 800 records (~360 tái dùng, ~440 mới;
  MPS ~2–4 h theo 5–30 s/gen).
- **Expected evidence**: nếu P3-FP ép ra FP>0 → kênh hai chiều, viết lại
  Discussion 'Safety transfer' (chỗ đã dựng khung "pre-register both
  directions"); malicious_recall/fp_benign + error-type transitions per model;
  appendix human-validation.
- **Commands**: AMENDMENT-4 mục riêng cho safety → sửa
  `configs/packguard_safety.yaml` (P3-FP + strength, giữ 3 arm cũ) →
  `.venv/bin/python src/experiments/round9_safety_n50.py` (mở rộng runner
  hiện có để nhận arms mới) → human-validation sheet → analysis script.

## R8. Mechanism ablation (paraphrase + scrambled control) — **P1, chạy TRONG batch R7, sau arm P3**

- **What**: 3 paraphrase same-meaning của CÙNG advisory + 1 scrambled control
  (cùng độ dài/format) + P2 gốc; malicious-only; 30 mal × 5 conditions ×
  2 model = 300 gens; phân tích phân bố flips theo condition.
- **Why**: audit safety-5 (accepted): khoảng trống V1 §4.2 ("Cơ chế ... chưa
  được tách khỏi ... không được claim benefit"); infra dùng lại R7.
- **Cost**: **0.5–2.5 h MPS** (chung batch R7).
- **Expected evidence**: flips tập trung ở P2 gốc + paraphrases (content-
  mediated) vs cả scrambled (generic distribution-shift → hạ 'third threat'
  thành model instability; khi đó xem lại title).
- **Commands**: như R7 (cùng runner, conditions mới).

## R9. Leave-families-out family shift — **P2**

- **What**: 5-fold leave-K-families-out trên features_v2 + manifest; chạy
  graph-vs-tfidf qua grid primitives; pre-register rule TRƯỚC: graph
  degradation < tfidf degradation ⇒ claim "robust under family shift";
  ngược lại boundary chặt hơn cho negative #2. KHÔNG temporal split
  (out-of-scope; MPI corpus chưa probe — docs/literature_2026_refresh.md §A1/§D).
- **Why**: audit novelty-8 (accepted): group split hiện chỉ chặn
  version-leakage trong cùng package (AMENDMENT-1); family metadata tồn tại
  trong sample ids; AUC .9605/.9260 đọc trực tiếp results.jsonl (multi-seed
  .8970/.8537).
- **Cost**: **CPU phút** (grid primitives).
- **Expected evidence**: bảng 'F1/AUC degradation under family shift:
  graph vs tfidf' trong §Results; boundary condition Discussion đã dựng khung.
- **Commands**: script mới `scripts/family_shift_cv.py` (mới; đọc
  features_v2 + dataset_v2 manifest, fold theo family) → chạy qua
  `packguard.eval` primitives → prereg rule trước khi nhìn kết quả.

## R10 (tùy chọn, cần quyết định riêng). 8B out-of-stack — **P3**

- **What**: MLX 4-bit (~5 GB) hoặc GGUF/llama.cpp — cả hai KHÔNG có trong
  .venv (`import mlx`, `import llama_cpp` → ModuleNotFoundError, verify trong
  phiên audit); khai báo runtime khác, không same-claim feasibility với
  transformers/MPS (V2 §A3).
- **Why**: safety-6 (accepted) + W2 TODO #1: scale question hiện khép ở
  "qwen inert 3B & 7B + llama-8B NOT_FEASIBLE (4 fail MPS + CPU 1.11 tok/s
  ⇒ ladder 240×512 ≈ 31 h)".
- **Cost**: cài đặt runtime mới + weights q4 + re-run ladder (~vài giờ sau
  khi cài; cần quyết định có vượt ràng buộc "<4B research models" hay không).
- **Priority**: P3 — chỉ làm nếu reviewer/user đòi scale; paper hiện đã có
  feasibility disclosure + claim boundary.

## Phụ lục: việc vệ sinh ngoài không gian sửa của phiên 2026-09-25

1. **W1_report.md:181 và :199-200** (reports/round9/ — ngoài refuseguard/paper2/
   + refuseguard/docs/): sửa "test set giống hệt nhau giữa các seed" → "giống
   về kích thước/thành phần (121/78); các test set KHÁC nhau giữa seed
   (giao 20–27/121)" (V1 §A3b/§6.3). Paper2 không chứa claim sai này.
2. **RefusEU**: đọc full-text trước khi cite (điều kiện của stats-3/novelty-3);
   hiện 0 hit trong refs.bib — đúng trạng thái an toàn.
3. **AMENDMENT-4**: ghi vào `docs/packguard_prereg.md` như bước 1 của R1
   (không ghi trước — amendment phải đi cùng quyết định chạy).

## Thứ tự thực hiện khuyến nghị

1. R1 (P0, mọi thứ khác phụ thuộc config 20-seed + AMENDMENT-4).
2. R2 + R3 + R5 (cùng đợt grid R1, thêm ~20–35 phút CPU).
3. R6 (GPU MPS ~0.4–2 h) và R7+R8 (GPU MPS ~2.5–6.5 h) — có thể song song
   nếu MPS chạy tuần tự theo queue.
4. R4 (dev nặng nhất, 4–8 h) — sau khi R1 chốt baseline.
5. R9 (CPU phút, bất kỳ lúc nào sau prereg rule).
6. Nhập kết quả vào paper2 theo đúng bảng/đoạn đã dựng khung ở phiên 2026-09-25.
