# V2 Report — Round 4 (Vòng 4 — vòng cuối): AUDIT REPRODUCIBILITY + TÍCH HỢP CUỐI

Ngày: 2026-09-19. Root: `/Users/macbook/.zcode/workspace/default/refuseguard`.
Phạm vi: chỉ audit — KHÔNG sửa code, KHÔNG train/generate thật (dry-run/smoke,
compile CPU). Mọi lệnh/output dưới đây là nguyên văn từ chạy thật của V2.
Artefact tạo: báo cáo này + log `/tmp/rg_v2_verify_repro.log`,
`/tmp/rg_tectonic.log`, checksum trước/sau trong `/tmp/rg_{before,after}.md5`,
`/tmp/rg_fig_{before,after}.md5`.

---

## 1. Verdict REPRO: **PASS** (có ISSUES — 3 MEDIUM, 4 LOW/INFO, không có HIGH)

`bash scripts/verify_repro.sh` chạy lại từ đầu bởi V2: **22/22 PASS, EXIT=0**
(353 pytest → E2 dry-run → 19 artifact check → tectonic). Nhưng mức bảo chứng
thật của script là **"pipeline còn nguyên trên máy này"**, KHÔNG phải "fresh
clone chạy lại được từng số": step 3 chỉ kiểm tồn tại + parse được JSON, không
kiểm giá trị; còn `outputs/`, `data/`, `models_dir/` đều git-ignored nên trên
clone mới 19 check này sẽ FAIL cho tới khi ai đó chạy lại toàn bộ pipeline.

### 1.1 Từng bước — kết quả chạy thật của V2

| Bước | Kiểm | Kết quả |
|---|---|---|
| 1 | pytest `tests/ -q` | `353 passed, 1 warning in 13.44s` → PASS |
| 2 | `run_e2 --config configs/e2.yaml --dry-run` | `[e2] OK -> outputs/e2/results.json (120 records)` → PASS |
| 3 | 19 artifact paper-cited: tồn tại + parse JSON/JSONL | 19/19 PASS |
| 4 | `tectonic --outdir paper/compiled paper/main.tex` | 0 error (1 warning Overfull vbox, cosmetic), `main.pdf` 276K → PASS |
| Tổng | | `SUMMARY: 22 passed, 0 failed`, exit 0 |

### 1.2 Đánh giá mức bảo chứng thật (điều kiện lỏng)

- **[MEDIUM — BUG-CONFIRMED] Pattern pass của bước pytest là lỏng.** Đoạn
  `case "$pytest_out" in *" passed"*|*" no tests ran"*)` khớp **substring**:
  V2 thử với chuỗi `"352 passed, 1 failed, 1 warning in 14.71s"` → script
  **vẫn PASS** dù có test fail. Tức là verify_repro không phát hiện được
  regression một phần; hôm nay suite thật sự 353/353 nên kết quả hiện tại là
  xanh thật, nhưng cơ chế kiểm không sound. Nên đổi thành match
  `*" failed"*→FAIL` trước, hoặc parse `N passed` + assert `N==353`.
- **[MEDIUM] Bước 3 chỉ bảo chứng "file tồn tại + JSON parse được"** — không
  kiểm value/schema/metadata. Danh sách 19 file cũng **thiếu chính các nguồn
  canonical mà paper cite**: `outputs/master/master_results.json` (341 số —
  nguồn duy nhất của paper theo A1), `round3_e0/gate_verdict.json`,
  `round3_e2e3/*/e4_breakdown.json`, `transformer/calibration/*/full_report.json`,
  `pilot_round2_recomputed/summary_v2.json`,
  `intent_gate_v2_measurement.json`, `codebert_eval_paired_only_metrics.json`.
  Bù lại, kiểm giá trị có sẵn trong `scripts/collect_master.py` (assert ngược
  từng số) nhưng script đó KHÔNG nằm trong verify_repro.sh — nên thêm 1 bước
  chạy `collect_master.py` (chỉ đọc + re-read, idempotent — đã xác nhận bên
  dưới).
- **[MEDIUM] `outputs/` + `data/` + `models_dir/` git-ignored toàn bộ** →
  fresh clone không có BẤKỲ kết quả/checkpoint/manifest nào; mọi số paper
  không thể kiểm chứng từ repo một mình. Đây là design choice từ
  PROJECT_BRIEF ("nội dung lớn git-ignored") nên không tính là bug, nhưng với
  một "audit reproducibility package" cần ship thêm: bundle outputs (zip) hoặc
  tối thiểu một file checksum manifest (sha256 của các artifact paper-cited)
  được commit. Hiện chưa có file nào kiểu này trong git.

### 1.3 Bảo chứng mạnh hơn V2 đã tự chạy (ngoài script)

- `scripts/collect_master.py` (V2 chạy thật): `[collect] rows=341 pending=0
  contradictions=2` + `[verify] OK — all 341 master rows match their source
  files (fresh re-read)`. **Idempotent**: md5 của `master_results.{json,md}`
  trước/sau KHÔNG đổi.
- `paper/make_figures.py` (V2 chạy thật): `[verify] all table numbers match
  source files` + `14 headline numbers cross-checked` + `[cites] 16 keys … all
  present` + 5/5 figure PDF regenerate OK. Bytes figure đổi giữa 2 lần chạy
  (timestamp matplotlib nhúng trong PDF) — expected, không phải finding.
- Tất cả 13 file `scripts/*.py` + `paper/make_figures.py` compile sạch
  (`py_compile`); import-level check OK cho collect_master, recompute_pilot,
  recompute_e8_monitor_round3, make_figures.

---

## 2. Verdict TÍCH HỢP: **PASS**

- **pytest full**: 353 passed (chạy 2 lần: trong verify_repro và bởi A3) —
  khớp claim README "expect: 353 passed". KHÔNG GPU.
- **git status**: đúng dự kiến — 8 entry untracked, toàn bộ sản phẩm Round 4:
  `README.md`, `docs/results_master.md`, `paper/`, `reports/round4/`,
  `requirements.txt`, `requirements-lock.txt`, `scripts/collect_master.py`,
  `scripts/verify_repro.sh`. `.gitignore` (`.venv/ data/ models_dir/ outputs/
  __pycache__/ *.pyc .pytest_cache/ nohup.out`) **không** vô hiệu hóa
  configs/scripts/src — cả 3 thư mục đều đã track từ Round 1–3 (3 commit).
  Nhánh `main`, 3 commit, sạch ngoài các file trên.
- **PDF**: `paper/compiled/refuseguard_paper.pdf` tồn tại, **10 trang**
  (pdfinfo), 280,671 bytes. V2 compile lại bằng tectonic trên bộ file cuối:
  exit 0, **0 error**, duy nhất 1 warning `Overfull \vbox (74.01793pt too
  high)` tại main.tex:61 — cosmetic, không mới so với log A3. Lưu ý:
  `main.pdf` (do verify_repro vừa compile lại) và `refuseguard_paper.pdf`
  (artifact A3) giờ khác SHA256 dù cùng số bytes — do timestamp nhúng trong
  PDF, nội dung 10 trang như nhau; `cp` lại 1 lệnh là đồng bộ.
- **requirements**: mọi import third-party trong src/scripts/tests/paper
  (torch, transformers, sklearn, scipy, statsmodels, pandas, matplotlib,
  tree_sitter_languages, yaml, pytest) đều có trong `requirements.txt` với pin
  đúng version .venv. Không package nào bị thiếu. Các entry không được import
  trực tiếp (datasets, accelerate, tokenizers, safetensors, huggingface_hub,
  numpy, pyarrow, jsonlines, requests, tqdm) là transitive/defensive — hợp lệ
  (kiểm bằng AST toàn repo: 0 usage ẩn). `requirements-lock.txt` = 79 packages
  đúng như README mô tả, format `name==version` cài được bằng pip. Python
  version ghi rõ (3.12) ở cả README lẫn header requirements.

---

## 3. CONFIRMED BUGS (lệnh + output nguyên văn)

### BUG-1 [MEDIUM] README bước 1 sai thực tế: `src.data.primevul` KHÔNG download

README viết:
```
.venv/bin/python -m src.data.primevul            # downloads HF mirror into data/raw/,
```
Thực tế code (`src/data/primevul.py`): module chỉ đọc/validate file local;
`iter_raw()` raise khi thiếu file, và **toàn bộ repo không có bất kỳ lời gọi
download nào** (grep `snapshot_download|hf_hub_download` chỉ ra đúng 1 hit —
chuỗi trong thông báo lỗi):
```
src/data/primevul.py:123: "section 'Data download') or huggingface_hub.snapshot_download("
```
Trên clone mới, bước 1 sẽ **crash FileNotFoundError**; người reproduce phải
tự suy ra lệnh `huggingface_hub.snapshot_download(repo_id='starsofchance/PrimeVul',
repo_type='dataset')` từ message lỗi. C heavy hơn: thông báo lỗi trỏ tới
"docs/e0_protocol.md section 'Data download'" nhưng mục đó **không tồn tại**
(heading thật: `## 2. Data (frozen, seed 20260918)`; grep "download" trong
docs/*.md = 0 hit). Hệ quả: 8 bước repro trong README gãy ngay bước 1 cho
người mới; cách khắc phục 1 dòng (thêm lệnh snapshot_download vào README bước
1) — V2 không sửa (không thuộc quyền).

### BUG-2 [MEDIUM] verify_repro.sh đếm nhầm pytest fail một phần thành PASS

Lệnh test của V2 (mô phỏng đúng nhánh `case` trong script):
```
$ out="352 passed, 1 failed, 1 warning in 14.71s"
$ case "$out" in *" passed"*|*" no tests ran"*) echo PASS;; *) echo FAIL;; esac
LOOSE-PATTERN: script would PASS despite '1 failed'
```
(Chi tiết đánh giá ở §1.2.)

### BUG-3 [LOW] SyntaxWarning invalid escape sequence trong tests

```
SYNTAX-ERROR (khi -W error::SyntaxWarning): invalid escape sequence '\+'
(tests/test_models_llm_harness.py, line 252)
```
Đây cũng là "1 warning" trong `353 passed, 1 warning`. Không ảnh hưởng kết quả
hiện tại, sẽ thành SyntaxError ở Python tương lai. Fix 1 dòng (raw string).

### (không phải bug) stale pointer/TODO — xem §5.

---

## 4. ARTIFACT COMPLETENESS — đối chiếu PROPOSAL.md mục 14

| # | Sản phẩm proposal §14 | Có? | Ở đâu (path thật, đã V2 xác nhận tồn tại) |
|---|---|---|---|
| 1 | Bộ code tái lập (dataset prep, prompt/config, runner, refusal parser, metric) | **CÓ** | `src/{data,conditions,defenses,metrics,models,experiments}/`, `scripts/` (13 py), `configs/` (22 yaml) |
| 2 | Manifest benchmark clean/contextualized + metadata transformation | **CÓ** (không git-shipped) | `data/manifests/{eval_subset_round1,round2,v1,v2}.json`; `data/benchmarks/bench_v1/` + `bench_v1_meta.json`, `e0_prompts_v1.jsonl` + meta, `safety_contrast_v1.json` |
| 3 | Fine-tuned Transformer checkpoint + config | **CÓ** (local, không git — khớp điều kiện "nếu giấy phép cho phép") | `models_dir/transformer_baseline/best/{model.safetensors,config.json}` + `configs/train_codebert.yaml` |
| 4 | RefuseGuard prototype (parser/provenance, mediator, monitor, fallback) | **CÓ** | `src/conditions/parser_utils.py`, `src/defenses/{p1_sci,refuseguard,b1_reframe,b2_strip,b3_aggressive,mediator}.py`, `src/models/{refusal_monitor,fusion_policy}.py` |
| 5 | Bảng clean vs contextualized vs defense + CI + statistical tests | **CÓ** | `outputs/master/master_results.{json,md}` (341 rows, CI + McNemar/bootstrap; V2 re-verify 341/341 OK); `paper/tables/tab_{main,defenses,codebert,calibration}.tex`; `src/metrics/stats.py` |
| 6 | Safety-preservation report | **CÓ** (nhúng, không file standalone) | E8 outputs + `round3_e8{,_llama3b}/recomputed/` + section `disclosures` (9 mục) trong master_results.json + `docs/results_master.md` + paper RQ6/Threats |
| 7 | Demo (nhập code → report: LLM status, Transformer prior, recovery path) | **THIẾU** | grep "demo" trong src/scripts/README = 0 hit. Đề xuất mức tối thiểu: `scripts/demo_refuseguard.py` CLI nhận 1 snippet, chạy gate→P1→monitor→fallback (LLM 0.5B smoke hoặc chế độ cache/mock), in status + prior + recovery path — ~100 dòng, không cần train, dùng lại đúng interface có sẵn |
| 8 | Luận văn + manuscript | **MỘT PHẦN** | manuscript: `paper/compiled/refuseguard_paper.pdf` (acmart, 10 trang, compile sạch) — CÓ. Luận văn theo cấu trúc 7 chương (proposal §15): KHÔNG có — chấp nhận được vì PROJECT_BRIEF mục tiêu đã định hướng "bản thảo A*/Q1"; ghi rõ để không ai hiểu nhầm là thesis đầy đủ |

---

## 5. MẢNH VỠ (leftover scan)

- **TODO/FIXME**: 9 hit, toàn bộ trong `src/experiments/run_e0..run_e8` +
  `base.py` — là chú thích "Round 1 status … TODO Round 2/3" của các
  config-driven runner legacy. README bước 5 đã ghi rõ runner này "remain
  available for dry-runs and protocol checks" và số paper đến từ
  `round3_scaleup`/`pilot_round3` → **không chặn**, chỉ là doc stale nên dọn.
- **Scripts không chạy được**: 0. Spot-check 5/5: `collect_master.py`,
  `recompute_pilot.py`, `recompute_e8_monitor_round3.py`,
  `paper/make_figures.py` (compile + import OK, 2 script đầu chạy thật OK),
  `eval_codebert.py --help` OK. Toàn bộ `scripts/*.py` compile sạch.
- **Hardcode path**: grep `/tmp/|/Users/|/home/` trong `src/` + `configs/` =
  **0 hit** (sạch). Lưu ý duy nhất: `docs/e0_protocol.md` Runbook có dòng
  `cd /Users/macbook/...` — doc, không phải code, chấp nhận được.
- **Stale artifact**: `paper/compiled/main.log` (02:57, từ lần draft lỗi của
  A3) vẫn nằm trong `compiled/` — intermediate, vô hại (A3 đã disclose).
- **README disclosure gap [LOW]**: README nêu MPS-only (dòng "developed on
  Apple M2 Pro"), `HF_HOME=$PWD/models_dir/hf`, seeded sampling — ĐỦ 3/4 mục
  khảo sát, nhưng **không nhắc PrimeVul mirror v0.1** (−13.8% vulnerable vs
  paper) ở bất kỳ đâu; disclosure này chỉ nằm trong paper §Setup/appendix và
  `master_results.json disclosures`. README là "cửa ngõ" của artifact — nên
  thêm 1 câu.

---

## 6. KIỂM 3 CLAIM DECISION-CRITICAL (đọc trực tiếp từ outputs, không tin ai)

| # | Claim | Trả lời | Evidence (path + giá trị nguyên văn) |
|---|---|---|---|
| 1 | E0 gate verdict 3/3 FAIL | **CÓ — XÁC NHẬN** | `outputs/experiments/round3_e0/gate_verdict.json`: `verdict="FAIL"`, `models_required=3, models_completed=3, models_pass=0`; per_model cả 3 (qwen3b/llama3b/granite2b) `delta_rr=0.0, p_value=1.0`; `consequence` = PIVOT theo protocol §7 |
| 2 | E8-Llama recomputed B0 = 0.033 | **CÓ — XÁC NHẬN** | `outputs/experiments/round3_e8_llama3b/recomputed/recompute_e8_monitor.json`: `summary.B0.unsafe_compliance_rate = 0.03333333333333333` (= 1/30, n_unsafe=30); kèm `P2.unsafe_compliance_rate = 0.0` |
| 3 | master_results row E6 vul-only n.s. | **CÓ — XÁC NHẬN** | `outputs/master/master_results.json` row `e6.discordant.vul_only_b01_b10_p`: `value={"b01":0,"b10":2,"mcnemar_p":0.5}`, `n=14`, note nguyên văn "vulnerable-only stratum: n.s. — headline p=0.0078 is driven by the benign stratum" |

Phụ lục xác minh: section `contradictions` của master ghi đúng 2 mâu thuẫn
E8-Llama (results.json gốc 0.4 vs recomputed 0.0333; McNemar p=0.000488 vs
recomputed) — quyết định "dùng recomputed" được ghi rõ, khớp những gì paper
report.

---

## 7. AI SAI / AI BẮT ĐƯỢC

- **A3 sai (README bước 1)**: ghi "`-m src.data.primevul` downloads HF mirror"
  — code chỉ validate, không có dòng download nào trong repo; V2 bắt được bằng
  code-read (BUG-1). Cùng là agent viết README nên đây chính là điểm mù tự
  audit.
- **A3 (verify_repro.sh)**: pattern pytest lỏng — "352 passed, 1 failed" vẫn
  được đếm PASS; V2 bắt được bằng test chuỗi (BUG-2). Bước 3 cũng thiếu chính
  `master_results.json` — nguồn canonical của paper.
- **A1 đúng**: gate 3/3 FAIL, E8-Llama 0.033, 2 contradictions + hướng dẫn đọc
  recomputed — tất cả khớp file gốc; `collect_master.py` chạy lại idempotent,
  verify 341/341 PASS.
- **A2 đúng**: `make_figures.py` chạy lại → toàn bộ số bảng + 14 headline + 16
  cite verify PASS; figures regenerate sạch.
- **Không phát hiện số bịa hay mâu thuẫn mới** giữa paper/tables/master và
  outputs sau khi V2 tự chạy lại toàn bộ chuỗi kiểm; các issue còn lại đều là
  mức docs/packaging, không có gì chặn repro trên máy hiện có.
