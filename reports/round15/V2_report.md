# V2 Report — Round 15 (AUDIT ADVERSARIAL W2: submission package)

Ngày: 2026-09-28. Auditor: V2 (vòng 15). Đối tượng: `submission/`
{RefuseGuard_ms.pdf, PackGuard_ms.pdf, cover_letter.md, venue_fit.md,
artifact_list.md}, `SUBMISSION.md`, `reports/round15/W2_report.md`; đối chiếu
với `reports/round15/W1_report.md`, `reports/round14/{W,V}_report.md`
(GuardDog + sửa 25/81), `reports/round13/F_report.md` §5, artifacts
`outputs/packguard/**`, `outputs/master/**`, `paper2/p0_macros/numbers.tex`.
Phương pháp: compile lại cả 2 bài độc lập (tectonic), pdftotext + grep regex
riêng, đọc JSON gốc bằng script `/tmp` (main venv), chạy lại pytest +
verify_repro + make_manifest + gen_paper_numbers từ đầu. KHÔNG sửa file nào
của W2/W1/F; không git commit. Lệnh có write-side-effect đã biết
(`round3_scaleup --stage gate --dry`) CỐ Ý KHÔNG chạy lại.

## VERDICT W2: PASS — 5 ISSUES (0 chặn nộp; 1 LOW-MEDIUM, 4 LOW/cosmetic)

Mọi số trong cover letter + SUBMISSION.md mà tôi đối chiếu đều KHỚP artifact
thật (không tìm thấy false claim số liệu nào). Các issue tìm được là lỗi
TÀI LIỆU: 1 thiếu dòng mapping, 1 lệch thời điểm (stale 3 phút), 1 lệch đếm
±1, và 3 lỗi chính tả cosmetic. Gói PDF sạch hơn tiêu chuẩn audit: 0 "??",
0 placeholder, 0 round-N trong paper2, paper1 0 overfull.

## EVIDENCE THEO CHECKLIST

### 1. PDF FINAL — PASS
- Page count (đếm `\f` pdftotext, độc lập): RefuseGuard_ms.pdf = **20**,
  PackGuard_ms.pdf = **8** — khớp claim W2 và tasking.
- `??` = **0** cả 2; placeholder (PLACEHOLDER/TBD/XXX/FILLME/`{{`) = **0**
  cả 2; paper2: `[Rr]ound[- ]?[0-9]` = 0, `AMENDMENT[- ]?[0-9]` = 0, `LFO`
  = 0, `TODO` = 0. Lưu ý: grep case-insensitive ra đúng 1 hit "amendment" —
  đó là cụm tiếng Anh thường "the pre-registration amendments are in the
  anonymized artifact tree" (Data & provenance), KHÔNG phải nhãn
  AMENDMENT-N → regex của W2 chính xác, không phải lọt lưới.
- Compile lại độc lập: `tectonic paper/main.tex` exit 0, **0 overfull**
  (226 underfull — vô hình); `tectonic paper2/main.tex` exit 0, 3 overfull
  warnings giống nhau 9.88pt tại main.tex:198 (dưới 10pt — cosmetic, ghi
  nhận cho camera-ready, không vi phạm gate nào).
- Submission PDF so với compile mới: lệch 2 byte (paper2) = metadata build;
  **text extracted GIỐNG NHAU 100%** cả 2 bài → bản copy trong submission/
  là bản hiện hành.

### 2. COVER LETTER HONESTY (mục quan trọng nhất) — PASS, từng claim đối chiếu artifact gốc
- **(a) Attack finding** — ĐÚNG: `defense_metrics.json` per_model
  restoration: granite recall_P0 .6667 → recall_P2_nodef .8333; llama .1667
  → .0417 (paired, 24 malicious/model) — khớp ".667→.833 / .167→.042 in the
  paired measurement". FP benign 0→2/100: `safety_metrics_n100.json` —
  granite fp_benign 0→.04 (2/50 benign; cả 2 FP pooled là của granite), llama
  FP 0 và đúng 8/8 flip mal→ben là llama. RR=0/2,700: macro
  `\pmGenDefTotal` = 2,700 ✓. Cover letter ghi đúng nguồn từng số ("paired
  measurement" vs "at measurement scale n=100") — không trộn số.
- **(b) Defense có nói COST, không chỉ kể win** — ĐÚNG: heading finding 2
  là "closes the channel — **at a measured, family-dependent price**"; body
  nêu rõ "On Llama-3.2-3B the same strip restores nothing — the lost
  detections are byte-identical snippets of a single package family... We
  report this cost as a first-class outcome". Đối chiếu: 38/38
  strip(P2)==strip(original) ✓ (paper + V1 audit độc lập 45/45 stripper);
  granite 23/23 verdict = baseline ✓ (`defense_analysis.json`
  P0__vs__P2_D1: 23 pairs, 0 flips, p=1.0; benign 14/14 cũng 0 flips);
  4/4 flips revert ✓ (flips_a1_b0=4); FP 0/14 ✓ (và 2/50→0/14).
  Llama cost: 4 detections mất đúng toàn bộ @antoncallahan/aws-user-helper
  (byte-identical, 1/19 family-level — V1 audit + flips list trong
  defense_metrics.json). Chi tiết trung thực: flips P2D1-vs-P0 của llama là
  5 (4 mất + 1 THÊM ở family artifact-lab pypi); cover letter chỉ nói "the
  lost detections" (4) — câu đó ĐÚNG cho phần lost, phần +1/−1 có trong
  bảng defense của paper. Không phải false claim, chỉ là mức chi tiết ít
  hơn paper (chấp nhận được cho cover letter).
- **(c) TOST** — ĐÚNG: numbers.tex `\pmPzGroupGraphDelta{-.0065}`,
  `CiLow{-.0133}`, `CiHigh{+.0003}`, `Tost{PASS}` (±.02, AMENDMENT-5).
- **(d) GuardDog** — ĐÚNG: "comparable, not superior (and optimistically
  biased by shared data origin — disclosed)" — đúng ràng buộc của V round-14
  (CẤM "superior"; same-origin DataDog caveat bắt buộc) và khớp số đã audit
  (.866/.874 group; thua graph .923–.928; top LCO t0.30 1-seed).
- **(e) "closes" tuyệt đối** — KHÔNG TÌM THẤY claim tuyệt đối thiếu
  softening: mọi chỗ "closes" trong cover letter đều kèm qualifier ("at a
  measured, family-dependent price"; "where it matters most" trong paper).
  WATCH: chính TIÊU ĐỀ bài là "...and **Closing** an In-Package Attack
  Surface" — chữ mạnh nhất của gói; được chống lưng bằng bằng chứng
  byte-equality 38/38 (đóng ở tầng input, provable) + neutralization đầy đủ
  phía granite + disclosure cost llama first-class. Đáng tôn trọng nhưng
  reviewer có thể hỏi — giữ sẵn câu trả lời "input-level closure, model-level
  cost disclosed".
- **(f) Pilot scope + negative results** — ĐỦ MỨC: đoạn "Scope and honesty
  statements" nêu đủ 603 (390 wild-capture + 213 popularity-derived), 2
  ecosystems, 2–3B, FL/sim là simulation; negative results first-class: LCO
  null hai chiều (p=.368, có power), mechanism ablation null-low-power, KB
  neutral, GuardDog comparable. Không superlative; không "first" chưa hedge
  (checklist nội bộ của W2 khớp thực tế).
- **Kết luận mục 2: 0 false claim trong cover letter.** Mọi số truy vết được.

### 3. SUBMISSION.md mapping — PASS với 1 ISSUE
- Compile/checks bảng §0: đối chiếu lại toàn bộ — đúng (nhưng xem ISSUE-2
  về pytest 743→757).
- OSF P1-7 + frontier P1-8 = Blocked-by-user: khớp
  `reports/round13/F_report.md` §5 (bảng dòng 212–213 nguyên văn).
- KB human-κ = Blocked-by-user + "không có artifact nguồn trong repo": grep
  κ/human/annotator trong docs/ + reports/ chỉ thấy 1 dòng PLAN trong
  `docs/improvement_roadmap_v2.md:738` — đúng, disclosure trung thực.
- **ISSUE-1 [LOW-MEDIUM]: thiếu dòng P1-10 "8B/7B out-of-stack scale arm —
  Deferred/resolved-by-directive (<4B)"** trong bảng prerequisites; dòng này
  TỒN TẠI trong F_report §5 (dòng 214) và tasking vòng 15 yêu cầu mapping
  "7B/8B-blocked-by-<4B-constraint". SUBMISSION.md chỉ còn nhắc gián tiếp
  (RQ9 7B caveat ở Paper 1, "validation-locked + FP-directed" ở Paper 2).
  Không sai devil nào — thiếu 1 dòng mà orchestrator/user cần nhìn thấy.
- "Không mục Done nào thực ra là pending": duy nhất 1 nhãn cần siết —
  §1 "artifact bundle = **Done — chờ OSF**": content + manifest 48-file có
  thật (tôi check 48/48), nhưng VIỆC ĐÓNG GÓI (LICENSE, ẩn danh hóa artifact
  tree) là việc mở theo chính artifact_list.md §4 → nhãn chính xác hơn là
  "content-ready, packaging pending". [LOW]
- Readiness Paper 2 (bản thảo/claims/statistics/provenance Done): đúng — mọi
  claim §2 (1)–(6) tôi đối chiếu khớp artifact (xem mục 2, 4, 5).

### 4. VENUE FIT — PASS
- 4 venue đều có rationale định tính theo aims-&-scope; tài liệu TỪ CHỐI nêu
  acceptance rate ("không có nguồn trong repo") — grep xác nhận 0 hit
  acceptance-rate / impact-factor / **Q1** trong venue_fit.md + SUBMISSION.md
  → không bịa số, không gán Q1 không nguồn. Đúng yêu cầu.
- Tiền lệ "Cerebro TOSEM 2024" CÓ NGUỒN: `docs/packguard_literature.md`
  dòng 14 — VERIFIED, arXiv:2309.02637, DOI 10.1145/3705304 ✓.
- Paper 1 grounding: `docs/literature_review.md` §5 (verdict "first
  systematic joint evaluation" đã scope) — tồn tại, khớp cách lead trong
  venue_fit §2 ✓.
- Ràng buộc 2 bài (Paper 2 cite `refuseguard2026` — tôi xác nhận 2 hit trong
  paper2/main.tex + refs.bib; không nộp đồng thời cùng venue) ✓ hợp logic.
- COSMETIC (xem CONFIRMED BUGS #4): "Scope**典型**" (CJK sót) ở dòng 13;
  "**(ACM TSEM)**" là mở rộng SAI của TOSEM (đúng: ACM Transactions on
  Software Engineering and Methodology).

### 5. ARTIFACT LIST — PASS (1 ISSUE đếm)
- Spot-check 15/15 file khớp: dataset_v2.json, benign_expansion_v1.json,
  p0_results.json, trivial_results.json, grid_results.json (fl_multiseed),
  probs_dump.jsonl, safety n60 + n100, defense_metrics.json, lco_results.json,
  kb_v0002.jsonl, guarddog findings/metrics, master_results.json,
  ARTIFACT_MANIFEST.sha256 — TỒN TẠI hết.
- Mục "KHÔNG CÔNG BỐ" khớp thực tế: `guarddog/extracted/` = **1.6GB** (du);
  `outputs/llm_cache/` + `outputs/packguard/kb/llm_cache/` tồn tại;
  `data/packguard/raw/ddmalicious/` tồn tại; **repo KHÔNG có LICENSE** (ls
  trống — đúng như tài liệu ghi) → lý do không công bố raw malicious
  archives (license DataDog + malware-safety, chỉ con trỏ + sha256) và note
  "GuardDog Apache-2.0, KHÔNG re-distribute rules" đều HỢP LÝ và có mặt.
- **ISSUE-3 [LOW]: probs_dump.jsonl ghi "19,484 per-sample probs" — đếm
  thực tế 19,485 rows (100% type=sample, không có header/meta).** Lệch +1.
- **ISSUE-2 (phần này): "tests/ — 743 tests" stale → 757** (xem mục 8).

### 6. README repro check — PASS (xác nhận độc lập)
- Chạy lại của tôi: `download_data.py --help` OK, `eval_codebert.py --help`
  OK, `demo_refuseguard.py --help` OK (3/3; 7/7 của W2 nhất quán);
  `python -m src.data.primevul` → **status OK, test=435**; `run_e0 --config
  configs/e0.yaml --dry-run` → OK 32 records (ghi `outputs/e0/results.json`
  — side-effect W2 đã disclose; KHÔNG nằm trong manifest: tôi chạy
  make_manifest --check SAU khi dry-run vẫn **48 ok / 0 mismatch**);
  `gen_paper_numbers.py --check` → **OK, 336 macros** (khớp SUBMISSION.md).
- `bash scripts/verify_repro.sh` CHẠY LẠI TOÀN VẸN bởi tôi: **30/30 passed,
  exit 0; pytest 757 passed / 0 failed; manifest 48/48; value checks
  (gate=FAIL 3/0, e8-llama B0=1/30, e6 p=0.5, RQ8 x2, RQ9 p=.7266) PASS;
  compile paper 1 PASS.**
- Không chạy lại `--stage gate --dry` (write side-effect đã biết); incident
  manifest-mutation W2 tự báo (§4.2) kiểm tra chéo hợp lý: verdict hiện tại
  FAIL 3-completed/0-pass đúng giá trị, manifest 48/48 sau regenerate.

### 7. "ONE-SENTENCE EACH" trong paper2 main text — PASS (grep đếm)
- **8B feasibility**: đúng 1 câu main text — "Evaluating ≥8B models is
  infeasible on this runtime (Appendix)" (§Threats, dòng 747); chi tiết ở
  Appendix A.8 (tồn tại, trung thực kể cả phần "RSS not preserved").
  Grep main text (dòng 76–790): 0 chỗ khác nhắc 8B.
- **Three-client**: đúng 1 câu main text — "the registered three-client
  fallback partition differs negligibly... not a third ecosystem" (dòng
  748–751; chung 1 câu với 8B qua dấu chấm phẩy — mỗi chủ đề vẫn chỉ xuất
  hiện 1 câu); chi tiết Appendix (dòng 909).
- **KB ablation**: đúng 1 câu main text — "A refusal-gated LLM-built
  knowledge base ... leaves accuracy essentially neutral ...; its robust
  yield is gated per-call explanation, not F1" (dòng 620–625); tab:kb ở
  Appendix.
- Rendering "(137/137 types, 2,299/2,299 instances)" TRÒNG NHAU như vậy
  nhưng ĐÚNG SỐ: `coverage_v3.json` — v3 types 137/137 (100.0%), instances
  2299/2299 (100.0%). Không phải bug macro lặp; chỉ là tỉ lệ coverage 100%
  được render dạng ratio (cosmetic cần nhìn lại, không sai).

### 8. PYTEST — 757/0 (khớp W1, LỆCH với số trong tài liệu W2)
- Chạy lại `.venv/bin/python -m pytest tests/ -q`: **757 passed, 0 failed
  (86.5s)**. W1 report (757) đúng; W2 report/SUBMISSION.md/artifact_list
  ghi 743 — đúng TẠI THỜI ĐIỂM W2 freeze (SUBMISSION.md 05:48,
  artifact_list 05:47) nhưng `tests/test_packguard_malguard.py` của W1 sinh
  05:51:10 (+14 tests) → tài liệu stale 3 phút sau khi chốt.

## CONFIRMED BUGS (tài liệu submission — không có bug số liệu)
1. **[LOW-MEDIUM] SUBMISSION.md thiếu dòng P1-10** ("8B/7B out-of-stack
   scale arm — Deferred — resolved-by-directive <4B"; có sẵn trong
   F_report §5 dòng 214). Bảng prerequisites hiện chỉ 3 dòng; tasking đòi
   4 mapping. Sửa: thêm 1 dòng trước khi gửi orchestrator/user.
2. **[LOW] Số tests stale**: SUBMISSION.md "pytest **743/0**" +
   artifact_list.md "**743 tests**" → thực tế hiện hành **757/0** (W1 cộng
   14 tests lúc 05:51, sau mốc freeze 05:47–05:48 của W2). Cả hai tài liệu
   là tài liệu người đọc sẽ tin — phải cập nhật 757.
3. **[LOW] artifact_list.md: probs_dump "19,484" → thực tế 19,485 rows**
   (đếm độc lập, 100% type=sample).
4. **[LOW cosmetic] Lỗi văn bản trong tài liệu nộp**:
   `submission/venue_fit.md:13` chứa CJK sót "Scope**典型**";
   `venue_fit.md:17` "**(ACM TSEM)**" — mở rộng sai tên TOSEM;
   `submission/artifact_list.md:106` "**ngườireview**" (dính chữ).
5. **[LOW cosmetic] paper2: 3 overfull hbox 9.88pt** (main.tex:198, cùng
   một paragraph) — dưới ngưỡng nhìn thấy, không thuộc gate; xem lại khi
   chuyển journal template.

## FALSE CLAIMS
**KHÔNG TÌM THẤY trong cover_letter.md và SUBMISSION.md.** Mỗi số tôi thử
gỡ (granite/llama recall paired, FP 0→2/100, 2,700, 38/38, 23/23, 4/4, 0/14,
1/19, TOST −.0065 CI [−.0133,+.0003], trivial +.0227/+.0487 p 1.9e-5/1.9e-6
kèm subtest .0012/1.9e-6, LCO dd −.0095±.0803 p=.368 power .75@δ=.05,
GuardDog .866/.874 vs graph .923–.928, 125/225, 603=390+213, 336 macros,
48-file manifest, 1.6GB extracted, no LICENSE) đều khớp artifact gốc hoặc
macro generated có audit trail. 2 self-disclosure của W2 (gate --dry ghi đè
manifest file; KB-κ không truy được nguồn) đều kiểm tra chéo ĐÚNG như đã
khai. Điểm cần canh (không phải lie): chữ "Closing" trong tiêu đề — có
bằng chứng tầng input + scoping "where it matters most", nhưng là wording
mạnh nhất của gói, cần giữ câu trả lời sẵn cho reviewer.

## AI SAI / AI BẮT ĐƯỢC
- W2 làm sạch về SỐ đến mức tôi không gỡ được claim nào — nhưng sai về
  THỜI GIAN: freeze gate lúc 05:47–05:48, W1 thả 14 tests lúc 05:51 →
  hai tài liệu submission stale chỉ sau 3 phút, không ai cập nhật.
- W2 đánh rơi 1 dòng mapping (P1-10) mà F round-13 đã làm sẵn — bảng
  prerequisites hiện không phản ánh đầy đủ trạng thái roadmap.
- W2 tự báo trung thực 2 việc khó nhìn (gate --dry có write side-effect
  đè manifest; KB-κ không có artifact nguồn) — cả hai đều đúng sự thật,
  đây là chỗ làm ĐÚNG của audit nội bộ.
- Lỗi bilingual "典型" lọt vào tài liệu hướng đối tượng journal — kiểu lỗi
  chỉ bắt được khi audit đọc từng dòng.
- Paper2 dùng macro coverage "X/X" (137/137, 2,299/2,299) — đúng số nhưng
  trông như bug; một reviewer nhanh sẽ nghi macro lặp.

## SUBMISSION-READY: ĐÚNG — gói đạt chuẩn nộp sau 5 việc nhỏ
PDF sạch (0 ??/placeholder/round-N; 20tr+8tr đúng; paper1 0 overfull);
cover letter trung thực toàn bộ, cost + negative results là first-class,
không superlative; venue fit không bịa số; artifact list khớp thực tế;
repo gates xanh theo kiểm định độc lập của tôi (pytest 757/0,
verify_repro 30/30 exit 0, manifest 48/48, gen_numbers 336 OK).

Việc còn lại (theo thứ tự):
1. (5 phút, W2/orchestrator) Sửa ISSUES 1–4: thêm dòng P1-10 vào
   SUBMISSION.md; 743→757 ở SUBMISSION.md + artifact_list.md; 19,484→19,485;
   xóa "典型", sửa "(ACM TSEM)" → "(ACM TOSEM — Transactions on Software
   Engineering and Methodology)", "ngườireview" → "người review".
2. (User) 3 blocker artifact-track: OSF upload+timestamp (P1-7), login
   frontier API (P1-8), quyết định human-κ plan; chọn LICENSE (MIT vs
   Apache-2.0) — chưa chặn nộp PDF, chặn artifact-review track.
3. (User, lúc nộp) Điền danh tính khi bỏ anonymous; xác nhận chính sách
   concurrent-submission của C&S tại thời điểm nộp; convert sang journal
   template nếu venue đòi (8tr sigconf hiện tại).
4. (Tùy chọn, nếu reviewer đòi) GuardDog qua đủ 20 LCO seed + validation-
   locked threshold (R3b) — 2 việc rẻ nhất tăng độ chắc claim (đã ghi
   đúng trong TODO của W2).
5. (Camera-ready) Nhìn lại 3 overfull 9.9pt ở main.tex:198 và cách render
   coverage "X/X" trong câu KB.

Kiểm toán này chỉ tạo: `reports/round15/V2_report.md` + script/scratch trong
/tmp (compile logs `/tmp/v15_p{1,2}_compile.log`, `/tmp/v15_verify_repro.log`).
Không file nào của W1/W2/F bị sửa; không git commit.
