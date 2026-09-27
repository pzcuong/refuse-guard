# W2 Report — Round 15 (SUBMISSION PACKAGE: chốt trạng thái competitive-plus, chuẩn bị nộp)

Ngày: 2026-09-28. Owner: W2 (vòng 15, góc submission package). CPU only.
Scope theo tasking: S1 compile final 2 bài + copy PDF ra `submission/` +
checks; S2 `SUBMISSION.md`; S3 `submission/venue_fit.md`; S4
`submission/cover_letter.md`; S5 `submission/artifact_list.md`; S6 README
repro check; report này. Quyền sở hữu tôn trọng: KHÔNG sửa `packguard/`,
`scripts/` (chỉ chạy), `paper/`+`paper2/` (chỉ compile + copy PDF),
KHÔNG git commit, KHÔNG bịa số (mọi số truy vết artifact / PDF đã compile).

## 1. LÀM GÌ

### [S1] COMPILE FINAL CẢ 2 BÀI — DONE
- `tectonic paper/main.tex` → exit 0; `tectonic paper2/main.tex` → exit 0
  (chỉ underfull-hbox warnings, vô hình).
- Copy: `submission/RefuseGuard_ms.pdf` (**20 trang**) và
  `submission/PackGuard_ms.pdf` (**8 trang**) — page count bằng pdftotext
  (`\f` count), khớp kỳ vọng tasking (20tr / 8tr).
- Checks trên TEXT PDF cuối (làm 2 lần: sau compile đầu và sau khi
  verify_repro recompile step-6 rồi re-copy):
  - `??` = **0** cả 2 PDF (không undefined reference).
  - Placeholder tokens (PLACEHOLDER/TODO/TBD/XXX/`{{`/FILLME/macro
    `\pmXxx` ròng) = **0** cả 2 PDF.
  - Paper 2: `[Rr]ound[- ]?[0-9]` = 0, `AMENDMENT[- ]?[0-9]` = 0,
    `R1[0-9]:` = 0, `LFO` = 0. (Paper 1 không ràng buộc round-N theo
    tasking; từ vựng Amendment-1 của nó là protocol vocabulary đã được
    chấp nhận từ round 7.)

### [S2] SUBMISSION.md (root) — DONE
Checklist submission đầy đủ cho 2 bài: bảng compile/checks; Paper 1
(venue theo `docs/literature_review.md` §5 verdict, 5 claim chính kèm số
truy vết outputs/master, 3 prerequisites BLOCKED-by-user với bảng
Done/Blocked, readiness từng mục); Paper 2 (venue #1 C&S, pilot scope
603 / 2 ecosystems / 2–3B disclosed, 6 nhóm claim đã kiểm định — TOST
±.02 PASS −.0065 CI [−.0133,+.0003]; attack paired family-dependent
.667→.833 vs .167→.042; defense 38/38 strip-equality + 23/23 neutralize
+ cost llama 1-family; LCO null hai chiều p=.368; GuardDog comparable
not superior + same-origin bias; retracted/null results liệt kê đủ).

### [S3] submission/venue_fit.md — DONE
So sánh 4 venue (Computers & Security, IEEE TDSC, TOSEM, EMSE) × 2 bài:
bảng fit theo aims-&-scope (ghi rõ "kiểm tra lại trên trang venue"), khuyến
nghị thứ tự: Paper 2 = C&S → TOSEM (tiền lệ Cerebro TOSEM 2024 — verified
trong `docs/packguard_literature.md`) → EMSE → TDSC; Paper 1 = C&S (sau
quyết định Paper 2) → EMSE → TDSC → TOSEM. Lý do dựa trên
`docs/literature_review.md` §5 (paper 1 = measurement study scoped) và
`docs/packguard_literature.md` (paper 2 = applied security + tiền lệ
TOSEM). **Không nêu acceptance rate nào** (không có nguồn trong repo).
Thêm mục ràng buộc 2-bài: Paper 2 cite Paper 1 → không nộp đồng thời
cùng venue.

### [S4] submission/cover_letter.md — DONE
Cover letter draft cho venue #1 của Paper 2 (Computers & Security): 3
findings đúng tasking — (1) attack recall-perturbing family-dependent
(granite .667→.833 / llama .167→.042; n=100 FP 0→2/100; RR=0/2,700 như
boundary condition), (2) defense AST-strip neutralizes granite (23/23,
4/4 revert, FP 0; 38/38 byte-equality) với cost đo được trên llama
(1-family), (3) detector nền federation-robust TOST (−.0065,
CI [−.0133,+.0003]) + trivial margin (p ≤ 1.9e-5). Trung thực về pilot
scope (603/2 ecosystems/2–3B/simulation) và negative results (LCO null,
mechanism null-low-power, KB neutral, GuardDog comparable). Không
superlative; không "first" chưa hedge. Kèm checklist nội bộ.

### [S5] submission/artifact_list.md — DONE
Sẽ công bố: code (`src/`, `packguard/`, `scripts/`, `configs/`,
`tests/` 743 tests), manifests 603 (`dataset_v2.json` per-sample
source+sha256) + 200-expansion (`benign_expansion_v1.json`, disclosed
không thuộc corpus đã đăng ký), toàn bộ measured outputs (p0/trivial/
grid/probs_dump/safety n60+n100/defense/lco+clusters/kb v2+v3/guarddog
findings+metrics/master Paper 1), provenance (manifest 48 file sha256,
prereg AMENDMENT-1..7, reports audit trail round 1–15), LaTeX + macro
generator. License note: repo CHƯA có LICENSE — khuyến nghị MIT hoặc
Apache-2.0 cho code, CC0/CC-BY cho data outputs; GuardDog (Apache-2.0)
không re-distribute rules. KHÔNG công bố: raw malicious archives
(license DataDog + malware-safety; chỉ gửi link nguồn + sha256 trong
manifest), benign tarballs (tái lập qua registry), model weights (HF
link), llm_cache, extracted/ 1.6GB, mock/dry artifacts.

### [S6] README repro check — DONE (1 sự cố đã sửa, disclose §4.2)
Chạy lại các bước chính của README ở mức --help/dry (không train, không
generation):
- `scripts/download_data.py --help`, `train_codebert.py --help`,
  `eval_codebert.py --help`, `calibrate_refusal_monitor.py --help`,
  `run_e7_fusion.py --help`, `demo_refuseguard.py --help`,
  `make_manifest.py --help` — **7/7 help OK**.
- `python -m src.data.primevul` (README step 1) — **status OK** (validate
  local, 480 valid / 435 test).
- `run_e0 --config configs/e0.yaml --dry-run` — OK, 32 records mock
  (`dry_run: true`, `llm_mode: mock`).
- `round3_scaleup --help` / `pilot_round3 --help` — OK.
- `round3_scaleup --stage gate --dry` — chạy OK, verdict FAIL
  (3 completed / 0 pass) đúng giá trị决策-critical → **NHƯNG đã ghi đè
  `gate_verdict.json` (timestamp mới) — xem §4.2 + sửa xong**.
- `make_manifest.py --check` — 48 ok / 0 mismatch (sau sửa).
- `bash scripts/verify_repro.sh` (README smoke gate, gồm full pytest) —
  **lần 2: 30/30 passed, exit 0**; pytest **743 passed / 0 failed**.

## 2. FILES (absolute)

- /Users/macbook/.zcode/workspace/default/refuseguard/SUBMISSION.md (mới)
- /Users/macbook/.zcode/workspace/default/refuseguard/submission/
  {RefuseGuard_ms.pdf (20tr), PackGuard_ms.pdf (8tr), venue_fit.md,
  cover_letter.md, artifact_list.md} (mới)
- /Users/macbook/.zcode/workspace/default/refuseguard/reports/round15/W2_report.md (file này)
- Chỉ đọc/compile (không sửa nội dung): paper/main.tex + sections/tables,
  paper2/main.tex, docs/{literature_review,packguard_literature,
  improvement_roadmap_v2}.md, reports/round13+14, outputs/master/*.
- Sự cố sửa (disclose §4.2): outputs/master/ARTIFACT_MANIFEST.sha256
  (regenerate, 48 file) và outputs/experiments/round3_e0/gate_verdict.json
  (được rewrite bởi chính runner gate ở chế độ dry — nội dung verdict
  không đổi, chỉ date_utc).

## 3. CÁCH CHẠY / KIỂM CHỨNG

```
tectonic --outdir paper/compiled paper/main.tex          # exit 0
tectonic --outdir paper2/compiled paper2/main.tex        # exit 0
cp paper/compiled/main.pdf submission/RefuseGuard_ms.pdf # 20 trang
cp paper2/compiled/main.pdf submission/PackGuard_ms.pdf  # 8 trang
pdftotext submission/PackGuard_ms.pdf - | grep -cE "[Rr]ound[- ]?[0-9]|AMENDMENT[- ]?[0-9]|R1[0-9]:|\?\?"   # 0
.venv/bin/python scripts/make_manifest.py --check        # 48 ok, 0 mismatch
bash scripts/verify_repro.sh                             # 30/30, exit 0
.venv/bin/python -m src.experiments.run_e0 --config configs/e0.yaml --dry-run   # mock 32 records
```

## 4. LỆCH CHUẨN / DISCLOSE (honest)

1. **Venue claims không có số**: venue_fit.md cố tình không nêu acceptance
   rate/page-limit số — không có nguồn trong repo; chỉ mô tả aims-&-scope
   dạng định tính + tiền lệ đã verified (Cerebro TOSEM 2024). Mọi mục
   scope đều kèm chú ý "kiểm tra lại trang venue trước khi nộp".
2. **Sự cố S6 đã sửa (manifest mutation)**: `round3_scaleup --stage gate
   --dry` (README-style check) REWRITE `outputs/experiments/round3_e0/
   gate_verdict.json` — file nằm trong ARTIFACT_MANIFEST (48 file) nên
   lần chạy verify_repro đầu tiên FAIL đúng 1 check (29/30, manifest
   mismatch). Nội dung verdict KHÔNG đổi (FAIL, models_completed=3,
   models_pass=0 — xác minh lại bằng value-check của chính gate), chỉ
   trường `date_utc` cập nhật. outputs/ không được git track
   (`git ls-files outputs/` = 0) nên không khôi phục byte-cũ được → sửa
   theo đúng quy trình README ("regenerate after re-runs"):
   `make_manifest.py` regenerate (48/48) rồi `verify_repro.sh` chạy lại
   **30/30 exit 0**. Bài học: gate stage là lệnh CÓ write-side-effect;
   lần sau chỉ chạy `--stage gate` khi chấp nhận regenerate manifest.
3. **Dry-run ghi file**: `run_e0 --dry-run` ghi `outputs/e0/results.json`
   (32 records, `dry_run:true`/`llm_mode:mock`, KHÔNG trong manifest, KHÔNG
   được cite trong mapping số paper — grep S_report §5 = 0). File cũ
   (Sep 18) bị ghi đè — vô hại với số paper nhưng ghi nhận trung thực.
4. **"KB human-κ" không truy được artifact nguồn**: mục này có trong
   tasking W2 nhưng grep κ/human-validation/annotator không ra file nào
   trong docs/+reports/ (P1-7 OSF và P1-8 API-key có sẵn trong
   `reports/round13/F_report.md` §5). Được ghi vào SUBMISSION.md và
   artifact_list.md đúng trạng thái tasking cho (Blocked-by-user) kèm
   ghi chú "chưa truy được artifact nguồn trong repo".
5. **Paper 1 vẫn dùng từ vựng "Amendment-N"**: check round-N chỉ bắt
   buộc cho paper2 theo tasking; paper 1 giữ nguyên (ngoài quyền sửa của
   W2, và là protocol vocabulary đã chấp nhận).
6. **Copy PDF 2 lần**: verify_repro step-6 recompile `paper/main.tex`
   sau khi tôi copy PDF lần đầu → đã re-copy submission PDFs từ bản
   compile cuối + chạy lại toàn bộ checks trên bản cuối (kết quả như
   §S1, đều 0).

## 5. TODO (cho orchestrator/user)
1. (User) OSF timestamp (P1-7), frontier-API login (P1-8), quyết định
   human-κ plan — gỡ 3 blocker artifact-track trước khi nộp thật.
2. (User/orchestrator) Chọn LICENSE (MIT vs Apache-2.0) — repo chưa có.
3. Nộp Paper 2 → C&S: điền danh tính khi bỏ anonymous; xác nhận chính
   sách concurrent-submission tại thời điểm nộp; convert journal format
   nếu venue đòi (8tr sigconf → template C&S).
4. Paper 1: chọn EMSE hoặc C&S-sau-Paper-2 theo venue_fit.md; cover
   letter paper 1 chưa viết (không thuộc tasking vòng này).
5. Nếu reviewer đòi thêm: GuardDog qua đủ 20 LCO seed (chỉ tính lại
   membership+metrics, findings đã có — TODO #1 của W round-14) và
   validation-locked threshold (R3b) là 2 việc rẻ nhất tăng độ chắc
   claim.

## 6. SELF-TEST THẬT (đã chạy trong phiên này)
1. `tectonic` 2 bài — exit 0 / exit 0; PDF: RefuseGuard 20tr,
   PackGuard 8tr (page count từ pdftotext).
2. Checks PDF cuối: `??`=0; placeholder=0; paper2 round-N/AMENDMENT-N/
   R13:/LFO = 0 (regex strict, chạy trên bản re-copy cuối).
3. `verify_repro.sh` lần 2: **30/30 passed, exit 0** (pytest 743/0,
   e2 dry-run OK, 26 artifact parse, value checks — gate FAIL 3/0,
   e8-llama B0=1/30 — manifest 48/48, compile paper 1).
4. `make_manifest.py --check`: 48 ok / 0 mismatched / 0 missing.
5. README steps: 7/7 `--help` OK; `src.data.primevul` status OK;
   `run_e0 --dry-run` 32 records mock-flagged; gate --dry verdict FAIL
   3-completed/0-pass (đúng decision-critical value).
6. Số trong 3 file submission docs đối chiếu thủ công với
   paper2/p0_macros/numbers.tex (−.0065/.0171/CI −.0133..+.0003;
   trivial +.0227/.0487, p 1.9e-5/1.9e-6; 603=390+213; 2,700; 122 LLM
   entries) và với reports/round13+F/round14 W+V — khớp.

Sources: paper/main.tex + paper2/main.tex (compile 2026-09-28);
outputs/master/{ARTIFACT_MANIFEST.sha256,master_results.md};
reports/round13/F_report.md (bảng trạng thái cuối + BLOCKED P1-7/P1-8);
reports/round14/{W,V}_report.md (GuardDog + corrected FN decomposition);
docs/literature_review.md §5 (novelty verdict paper 1);
docs/packguard_literature.md (verified venues của related work);
docs/improvement_roadmap_v2.md (điều kiện trích dẫn từng số).
