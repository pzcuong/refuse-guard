# PACKGUARD BRIEF — Dự án 2 (đọc bắt buộc trước khi làm)

## 1. Mục tiêu: HỢP NHẤT 2 đề tài thành 1 bài Q1
**A) Bài hiện tại (RefuseGuard, đã xong 7 vòng, paper 17tr `paper/`)**: LLM vulnerability
analysis dưới safety-blocking + untrusted context. Findings: RR=0 mọi attack (naive +
query-relevant) ở open 2-7B; verdict-corruption về phía vulnerable (FP channel);
defence full-bundle hại ≤3B (reassertion), minimal-provenance an toàn; P1 giảm IPI.
**B) Đề xuất mới**: Federated Cross-Language Malicious Package Detection qua Behavior
Graphs + LLM-Augmented KB.
**Bài gộp (đích)**: *"Trustworthy LLM-Assisted Detection of Malicious Packages:
Cross-Language Behavior Graphs, Federated Learning, and the Safety Layer as a
Third Threat"* — hệ thống đầu tiên đo 3 threat (safety-blocking, context-corruption,
defence-harm) trong domain malicious-package (nhạy cảm an ninh CAO hơn vulnerability
→ dự đoán DRB: refusal có thể mạnh hơn — phải đo, không giả định), trên biểu đồ hành vi
chuẩn hóa cross-language, huấn luyện FL qua partition ecosystem (non-IID tự nhiên),
với LLM-KB explainable gated bởi refusal monitor.

## 2. Môi trường (đã kiểm chứng) — CẬP NHẬT 2026-09-21: MODEL <4B ONLY
- Root: `/Users/macbook/.zcode/workspace/default/refuseguard` — mọi path absolute.
- **RÀNG BUỘC MỚI (directive user): research chỉ dùng model <4B.** Models khả dụng
  (đã dọn bỏ 7B/8B, giải phóng 31GB): Qwen2.5-Coder-3B, unsloth/Llama-3.2-3B,
  granite-3.3-2b, Qwen2.5-Coder-0.5B (smoke), CodeBERT-base + fine-tuned checkpoint.
  KHÔNG tải lại model ≥4B. Scale-question (RQ9) khép ở 2-3B với family-confound
  disclosed (docs/literature_2026_refresh.md mục C).
- Python `.venv/bin/python` (3.12): torch 2.14 (MPS), transformers 5.17, datasets,
  sklearn, tree_sitter + tree_sitter_languages (CÓ sẵn: javascript, python, java...),
  statsmodels, matplotlib. KHÔNG API key — LLM local: Qwen2.5-Coder-3B + Llama-3.2-3B +
  granite-3.3-2b + Qwen2.5-Coder-7B (đã cache `models_dir/hf`); harness tái dùng được:
  `src/models/llm_harness.py` (cache/resume/retry/CPU-fallback), `src/models/
  refusal_monitor.py` (đã fix patterns + Unicode + safety_flag), `src/metrics/stats.py`.
- Tái dùng self-guard lessons: model-guard mọi reuse; per-model file resolution;
  kết quả mock/dry KHÔNG lẫn số thật; mọi số truy vết outputs.

## 3. Không gian code mới (KHÔNG đụng code RefuseGuard cũ — chỉ import)
```
packguard/            # package mới: schema, graphs, features, fl, kb, safety_port
data/packguard/       # raw datasets + manifests
outputs/packguard/    # features, runs, results
paper2/               # bản thảo gộp (LaTeX, tectonic)
reports/round8/       # báo cáo 5 tác nhân
docs/packguard_*.md   # pre-reg + thiết kế
```

## 4. Thiết kế thí nghiệm (pre-register trong docs/packguard_prereg.md)
- **Data (pilot, disclosed)**: dataset công khai malicious packages — thử BKC
  (Backstabber's Knife Collection, Zenodo), MalOSS, Cerebro mirror; benign từ mirror
  top-packages. Nếu tải hết quá lớn → subset nhỏ nhất đủ power (≥150 malicious +
  ≥150 benign, 2 ecosystem: npm + PyPI ưu tiên; Maven nếu kịp) + checksum + nguồn.
  Gán nhãn: dataset labels (không tự gán tay). TUYỆT ĐỐI ghi nguồn từng sample.
- **Behavior graph (cross-language)**: tree-sitter parse → node = API call chuẩn hóa
  vào 6 lớp semantics (FILE_IO, NETWORK, PROCESS, CRYPTO, DYNAMIC_CODE, DATA_ACCESS),
  edge = sequence/dataflow trong cùng hàm/setup-script; schema thống nhất JS/Python
  (Java nếu kịp). Features: graph-level (density, node/edge count, span, class hist,
  seq features) — tên feature ghi vào schema JSON.
- **FL simulation (client = ecosystem partition)**: FedAvg + FedProx (mu cfg), 3-4
  clients non-IID tự nhiên (npm-only / pypi-only / mixed); secure-aggregation
  simulation (pairwise mask) + DP Gaussian noise (ε cfg) — công bố là SIMULATION.
  Baseline: centralized, per-client-only. Model: LR/MLP trên graph features
  (torch CPU/MPS) — đơn giản, chuẩn cho FL pilot; GNN là future work (ghi rõ).
- **Safety-transfer measurement (E-port từ RefuseGuard)**: arms trên package-analysis
  prompts: P0 neutral / P1-offensive-wording (credential-stealer phrasing theo
  DRB vocabulary) / P2 advisory-in-package (comment trong setup.py/postinstall);
  đo RR + verdict-flip + FP-bias bằng refusal monitor đã fix. Pre-register rule.
- **LLM-KB**: local LLM classify các API call chưa biết → KB entries (JSON, cache)
  → features (risk_ratio, kb_confidence); explainable verdict snippet; KB-augmented
  vs non-augmented ablation.
- **Ablations (pre-registered)**: graph-features vs code-as-text baseline (TF-IDF);
  FL vs centralized vs per-client; with/without LLM-KB. Metrics: P/R/F1/AUC +
  McNemar/bootstrap cho so sánh chính, seed cố định 20260922.

## 5. Nguyên tắc (giống PROJECT_BRIEF.md — bất di bất dịch)
1. KHÔNG bịa số; mock/synthetic phải có cờ mock, không lẫn kết quả thật.
2. Verify citation (MALGUARD/DONAPI/Cerebro/VulFL/SecurityAI/Ladisa-ACSAC trong đề
   xuấtuser: nhiều entry NGHI VẤN — check arXiv/DBLP thật, không có thì đánh dấu
   UNVERIFIED + thay bằng paper thật cùng chủ đề).
3. Số liệu dataset lệch thực tế phải disclosed; không gán nhãn tay tùy tiện.
4. Mỗi agent chỉ sửa trong không gian của mình; không git commit (orchestrator lo).
5. Báo cáo: reports/round8/<tên>_report.md — đủ 6 mục (làm gì/files/cách chạy/lệch
   chuẩn/TODO/self-test thật).
