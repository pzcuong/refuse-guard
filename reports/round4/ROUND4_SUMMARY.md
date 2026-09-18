# ROUND 4 SUMMARY — RefuseGuard (vòng cuối): AI SAI / AI BẮT ĐƯỢC + tổng kết 4 vòng

Ngày chốt: 2026-09-19. Tác nhân tổng hợp: S. Ngôn ngữ: tiếng Việt (số liệu
giữ nguyên gốc từ outputs). Quy tắc xuyên suốt 4 vòng: **không bịa số** — mọi
số trong paper truy vết được tới `outputs/**` qua
`outputs/master/master_results.json` (341 rows, mỗi row có `source_file` +
`trace`, được `scripts/collect_master.py` re-read + assert từng số).

---

## 1. Bảng "AI SAI / AI BẮT ĐƯỢC" — Vòng 4

| # | Ai viết | Lỗi | Ai bắt | Ai sửa | Mức | Trạng thái |
|---|---|---|---|---|---|---|
| 1 | A2-R4 | Claim "fallback decisions **2/2 correct**" (tab_defenses.tex:37) + "both fallback decisions correct" (05_results.tex:146) dù per-case fallback correctness không tồn tại trong bất kỳ output nào (`e7_fusion_results.json` chỉ có `n_fallback_used=2`) — vi phạm disclosure #7 | **V1-R4** (A1-R4 đã cảnh báo trước trong A1_report nhưng A2 sửa sót 2 chỗ trong paper) | **S-R4** Fix 1: thu hồi claim, thay bằng "two fallback invocations (2 of 133 records); per-case correctness not persisted"; giữ UAC gain; thêm regression guard trong `make_figures.py` (assert không còn "2/2") | HIGH | ✅ ĐÃ SỬA |
| 2 | A2-R4 + điều phối (không sync chéo) | Paper nói "Granite crashed at 75/135, excluded" + "two completed models" trong khi artifact đã có granite 135/135 (cache-only re-run), gate_verdict **FAIL 3/3 completed, 0/3 pass**, 77 rows granite trong master — paper mâu thuẫn chính repro package kèm theo | **V1-R4** | **S-R4** Fix 2: cập nhật 8 vị trí (abstract, intro, setup, fig caption, figure vẽ lại 3 model, RQ1, tab_main +2 hàng granite, discussion, conclusion) + thêm 2 disclosure granite (monitor in-sample fit; unsafe-compliance 0.538 = 7/13 anomaly báo nguyên trạng); mọi số đối chiếu master trước khi gõ | MEDIUM | ✅ ĐÃ SỬA |
| 3 | A3-R4 | README bước 1 sai thực tế: `-m src.data.primevul` KHÔNG download (chỉ validate); repo không có lệnh download nào; error message trỏ tới mục "Data download" trong docs/e0_protocol.md **không tồn tại** | **V2-R4** (code-read) | **S-R4** Fix 4: tạo `scripts/download_data.py` (PrimeVul mirror + OR-Bench + XSTest chính là nguồn đã dùng, tên repo/file xác minh qua HF API/GitHub), README bước 1 viết lại, sửa 3 error-pointer (`primevul.py`, `contrast.py` ×2); chạy thật → validate status=OK, 3 corpus đọc được | MEDIUM | ✅ ĐÃ SỬA |
| 4 | A3-R4 | `verify_repro.sh` đếm pytest bằng substring: "352 passed, 1 failed" vẫn PASS; step 3 chỉ kiểm tồn tại + parse JSON, thiếu chính `master_results.json` | **V2-R4** (test chuỗi) | **S-R4** Fix 5: parse STRICT (`N passed` + cấm `[1-9][0-9]* failed`) — regression test lại đúng chuỗi của V2 → CORRECTLY-REJECTED; thêm step value-check 5 số decision-critical + 3 artifact thiếu; chạy lại 27/27 PASS | MEDIUM | ✅ ĐÃ SỬA |
| 5 | (thiết kế round trước) | Fresh clone không có bất kỳ output nào; không có checksum manifest → "repro package" chưa chứng tính toàn vẹn | **V2-R4** | **S-R4** Fix 6: `scripts/make_manifest.py` → `outputs/master/ARTIFACT_MANIFEST.sha256` (23 file nhỏ, SHA256); README mục "Artifact integrity" + ghi chú hạn chế (outputs/data git-ignored → manifest chứng **bundle phát hành**, không chứng fresh clone); verify_repro thêm step `--check` | MEDIUM | ✅ ĐÃ SỬA |
| 6 | (thiếu từ đầu dự án) | Proposal §14 yêu cầu demo nhưng chưa tồn tại | **V2-R4** (§4 đối chiếu deliverables) | **S-R4** Fix 7: `scripts/demo_refuseguard.py` (gate + P1 + monitor + CodeBERT CPU; `--with-llm` mặc định OFF); smoke thật với hàm PrimeVul idx 195017 (gpac): P1 applied=True, prior 0.0224, monitor ANSWER | MEDIUM | ✅ ĐÃ SỬA |
| 7 | A1-R4 (master disclosure #9) | Wording ngược: "1/50 paraphrase **escape**" trong khi file thật `intent_gate_v2_measurement.json` ghi `blocked=1, n=50` (escape = 49/50); paper (A2) lại diễn đạt ĐÚNG | **V1-R4** (INFO-3) | **S-R4** Fix 3f: sửa trong `collect_master.py` (nguồn sinh master) + regenerate: "blocked only 1/50 (49/50 escaped)" + note ghi việc sửa; collect lại 341/341 verify OK. Lưu ý: fix-list ghi "blocked 49/50, escaped 1/50" nhưng **theo file thật** chiều đúng là blocked=1/50 | INFO | ✅ ĐÃ SỬA |
| 8 | A2-R4 | "max 512 new tokens" lấy từ default `models.yaml` thay vì budget chạy thật 200–320 theo configs round-3 | **V1-R4** (LOW-1) | **S-R4** Fix 3a: "200–320 new tokens (200 E0/E8 probes; 300 E0/E2E3; 320 E5/E6; harness default 512)" — đối chiếu 6 config | LOW | ✅ ĐÃ SỬA |
| 9 | A2-R4 | Mô tả E8 n gây hiểu 180 ("30 unsafe + 30 safe × B0/P1/P2") trong khi P1 chỉ có 30 safe-only (B0 60 + P2 60 + P1 30 = 150) | **V1-R4** (LOW-2) | **S-R4** Fix 3b: "B0 60, P2 60, P1 30 (safe prompts only; no unsafe arm)" | LOW | ✅ ĐÃ SỬA |
| 10 | A2/A3-R4 | `feng2020codebert` có trong refs.bib nhưng 0 lần được cite (B4 ghi nhầm cite ding2025primevul cho chính CodeBERT) | **V1-R4** (LOW-3) | **S-R4** Fix 3c: cite đúng ở §B4 method; entry copy sang `docs/refs.bib` cho check_citations → 17 keys, all present | LOW | ✅ ĐÃ SỬA |
| 11 | A2-R4 | precision "≈0.48" làm tròn thấp (thật 0.4800–0.4915) | **V1-R4** (INFO-2) | **S-R4** Fix 3d: "0.48–0.49" ×2 chỗ | LOW | ✅ ĐÃ SỬA |
| 12 | (rủi ro citation) | Số 2.7× (campbell2026) còn TODO "re-check" từ R1 trong literature review | **V1-R4** (LOW-4) | **S-R4** Fix 3e: fetch arXiv:2603.01246 — abstract ghi nguyên "2.72× the rate ... (p<0.001)" → **VERIFIED**, paper giữ số, TODO đóng kèm trích dẫn | LOW | ✅ ĐÃ SỬA |
| 13 | (cosmetic) | Từ "excluded" còn 1 chỗ hợp lệ ("comments excluded" — định nghĩa C2) làm grep-gate không dứt điểm | **S-R4** tự thấy khi grep PDF | **S-R4** Fix 8: đổi thành "comments ignored" (không số nào đụng) | cosmetic | ✅ ĐÃ SỬA |

Credit vòng 4: A1-R4 — hạ tầng chống-bịa số (collect_master verify 341/341 +
9 disclosures) hoạt động đúng; A2-R4 — verify_tables + make_figures bắt đúng
mọi số khác, các con số trong 4 bảng khớp nguồn; V1-R4/V2-R4 — bắt trọn 2
lỗi paper (fallback overclaim, Granite stale) + 3 lỗi repro package. S trong
vòng 4 KHÔNG phát hiện thêm số sai mới nào ngoài fix list.

---

## 2. BẢNG TỔNG 4 VÒNG (round → ai sai → ai bắt → đã sửa)

| Round | AI SAI | AI BẮT ĐƯỢC | Đã sửa (bởi S) |
|---|---|---|---|
| **R1 — Foundation** | **A1**: bib entries lỗi + seq_len + calibration split; **A2**: vd_s + is_usable + monitor patterns; **A3**: C++/grammar crash + schema | **V1/V2 (R1)** bắt toàn bộ | S sửa **15** mục (bib dọn, seq_len, cal-split, vd_s, is_usable, monitor patterns, parser crash, schema, ...) |
| **R2 — Core** | **A2**: calibration threshold bug; **A3**: SIUD artifact + gate lexical miss (0/50 trên E8 probes thật) | **V1/V2 (R2)** bắt | S sửa: threshold fit lại, SIUD tính lại từ records, gate thêm structural regexes (30/30 sau fix) |
| **R3 — Experiments** | **A3**: refusal monitor miss 11 refusal (E8-Llama B0 0.400/p=0.00049 giả) → claim thu hồi; **A1**: n=20 conservative (PASS-branch bất khả thi, disclose) | **V (R3)** bắt | S sửa + **recompute**: `recompute_e8_monitor_round3.py` (Llama B0 0.400→**0.033**=1/30, p=1.0; n_status_changed=11), originals giữ để audit, master ghi 2 contradictions; monitor thêm 3 pattern + chuẩn hoá apostrophe |
| **R4 — Paper (vòng này)** | **A2**: fallback overclaim "2/2 correct" + toàn bộ khối Granite stale (2-model); **A3**: README download không tồn tại + verify_repro pattern lỏng | **V1/V2 (R4)** bắt | **S sửa 13 mục (Fix 1→8)**: thu hồi claim, 3-model E0 toàn paper + figure, 2 disclosure granite, 6 wording LOW, download_data.py, verify_repro cứng hoá (27/27), ARTIFACT_MANIFEST (23 file), demo_refuseguard.py, recompile sạch |

Điểm chung của 4 vòng: **vòng nào cũng có ít nhất 1 lỗi do chính agent viết
nội dung không tự thấy được** (self-audit blind spot) và **đều được vòng
kiểm lỗi độc lập (V1/V2) bắt được bằng đối chiếu artifact**, không phải bằng
uy tín tác giả. Cơ chế "mọi số phải truy vết được file nguồn + master
re-read + verify" (R4-A1) là lớp bảo vệ hiệu quả nhất: sau khi có nó, V1-R4
quét ~60 số chỉ tìm ra ĐÚNG 1 claim-vượt-dữ-liệu (fallback 2/2).

---

## 3. Sức khỏe cuối của dự án (số thật, đã tự chạy lại hôm chốt)

| Hạng mục | Giá trị | Nguồn/lệnh |
|---|---|---|
| pytest | **353 passed, 0 failed** (1 SyntaxWarning cũ, ngoài phạm vi sửa) | `.venv/bin/python -m pytest tests/ -q` |
| PDF | **10 trang**, tectonic EXIT=0, 0 error | `tectonic --outdir paper/compiled paper/main.tex` |
| PDF grep (claim thu hồi) | "2/2 correct"=0; "excluded"=0; "crashed"=0; "??"=0; "0.00049"=0 | `pdftotext` + grep |
| Master rows | **341** (verify 341/341, pending=0, contradictions=2 đã ghi quyết định) | `scripts/collect_master.py` |
| E0 gate | **FAIL — 3/3 completed, 0/3 pass** (ΔRR=0.000 cả 3 model, McNemar p=1.0) → **PIVOT** | `outputs/experiments/round3_e0/gate_verdict.json` |
| Figures/tables | verify PASS: mọi số bảng khớp file; **17** headline số khớp master; **17** cite keys đủ | `paper/make_figures.py` |
| Repro smoke | **27/27 PASS** (pytest strict, E2 dry-run, 22 artifact, 5 value-check, manifest, tectonic) | `bash scripts/verify_repro.sh` |
| Artifact manifest | 23 file nhỏ, 23 ok / 0 mismatch / 0 missing | `scripts/make_manifest.py --check` |
| Data provenance | PrimeVul mirror status=OK (6,004 vul / 218,529 ben; dev −13.8%/−4.9% đã disclose); OR-Bench 1,319+655; XSTest 450 | `scripts/download_data.py` |
| Demo | hoạt động offline trên hàm PrimeVul thật (idx 195017): gate safe → P1 applied → prior 0.0224 (CPU) → monitor ANSWER | `scripts/demo_refuseguard.py /tmp/demo_func.c` |

## 4. Deliverables (đường dẫn)

| Sản phẩm | Đường dẫn |
|---|---|
| Manuscript (10 trang) | `/Users/macbook/.zcode/workspace/default/refuseguard/paper/compiled/refuseguard_paper.pdf` (nguồn: `paper/main.tex` + `paper/sections/` + `paper/tables/`) |
| Nguồn sự thật số liệu | `outputs/master/master_results.json` (+ `.md`, + `figures_data/*.csv`); bảng đối chiếu người đọc: `docs/results_master.md` |
| Gate verdict | `outputs/experiments/round3_e0/gate_verdict.json` |
| E8 đã sửa (bắt buộc dùng) | `outputs/experiments/round3_e8{,_llama3b}/recomputed/recompute_e8_monitor.json` |
| CodeBERT | `outputs/transformer/final_eval.json`, `codebert_eval_vd_s_metrics.json`, checkpoint `models_dir/transformer_baseline/best/` |
| Manifest toàn vẹn | `outputs/master/ARTIFACT_MANIFEST.sha256` (verify: `shasum -a 256 -c` hoặc `scripts/make_manifest.py --check`) |
| Repro | `README.md` (8 bước) + `scripts/download_data.py` + `scripts/verify_repro.sh` |
| Demo | `scripts/demo_refuseguard.py` |
| Audit trail 4 vòng | `reports/round{1..4}/` (mỗi round: A1/A2/A3 + V1/V2 + S_report; R4 thêm `ROUND4_SUMMARY.md` này) |
| Hạn chế đã ghi rõ | (a) manifest chứng outputs-bundle, không chứng fresh clone; (b) luận văn 7 chương không làm (bản thảo A*/Q1 là mục tiêu theo PROJECT_BRIEF); (c) SyntaxWarning cũ trong 1 test (Python tương lai sẽ thành error — nên xử lý ở vòng bảo trì); (d) granite E2/E3 có trong artifacts/master, bảng E3 trong paper chỉ trình bày 2 model 3B (caption đã ghi chú) |

**Kết luận 4 vòng:** hệ thống tự-kiểm (3 agent viết + 2 agent kiểm + 1 tổng
hợp, lặp 4 vòng) bắt và sửa được 100% lỗi phát hiện thấy, trong đó có 2 claim
HIGH-level đã bị thu hồi đúng quy trình (E8-Llama 0.400/p=0.00049 ở R3;
fallback "2/2 correct" ở R4) — paper hiện tại không còn claim nào vượt quá
dữ liệu đã biết, mọi số truy vết được, repro package tự kiểm 27/27 xanh.
