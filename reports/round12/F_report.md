# ROUND 12 — F REPORT (FINAL AGENT): tooling fix + real analysis + paper
# integration + gates

Agent: F (tác nhân final, vòng 12, task P1-9). Ngày: 2026-09-28. Đầu vào:
W1 batch thật (201 dòng, mock=false) + 2 bug đã xác nhận bởi V1/V2 + bảng
37 token của V2. Nguyên tắc: KHÔNG bịa số — mọi số trong paper2/main.tex
và trong báo cáo này truy vết được về
`outputs/packguard/defense/defense_analysis.json` (sinh lại từ batch trong
phiên này), `defense_metrics.json` (W1), hoặc
`outputs/packguard/r10/r8_safety_expand/safety_metrics_n100.json` (FP
provenance n=100). Không GPU, không git commit.

---

## 1. FIX + ANALYSIS THẬT

### 1.1 Hai bug đã sửa (đúng theo xác nhận của V2)

**(a) `scripts/r12_defense_analysis.py` `load_labels_from_features`:**
`r["id"]` → `r["sample_id"]` (features_v2.jsonl dùng `sample_id` ở 603/603
dòng). Sửa theo đúng triết lý fail-loud của script: hàng thiếu `sample_id`
giờ raise `LoudError` kèm keys thay vì đoán — không thêm nhánh "chấp nhận
cả `id`" vì đó là che giấu schema-drift.

**(b) Khối pooled llama-đè-granite:** merge key đổi từ bare `sample_id`
sang `f"{model}\x00{sample_id}"` cho mọi (model, arm) khi gộp pool — hết
last-writer-wins. Lý do chọn phương án "pooled THẬT + caveat" thay vì "tách
pooled theo model" hay "bỏ pooled": (1) 11 token pooled trong bảng handoff
của W2 trỏ vào khối này, và câu pooled của paper (n=47, McNemar gộp) cần
một khối gộp đúng nghĩa; (2) "pooled tách theo model" chỉ nhân bản khối
`per_model` đã có; (3) lỗi gốc là 1 dòng merge — fix nhỏ nhất là fix trong
sáng nhất. Khối pooled giờ mang thêm `per_model_pointers` (recall +
gain/loss từng model để người đọc thấy ngay chiều ngược bị pool che) và
`caveat` động (ghi loss/gain thật của batch: "loss 5 vs gain 1", per-model
là read chính, mọi số pooled DESCRIPTIVE).

**Cộng thêm (cùng đợt sửa, nguồn số tự tính — không gõ tay):** field mới
`descriptive_power` ở top-level JSON: `min_exact_mcnemar_p` (0.125,
granite P2 vs P2D1), danh sách 4 so sánh 0-discordant (p=1.0 by
construction, vô nội dung — gồm granite P0-vs-P2D1 malicious 0/23), và rule
"KHÔNG p nào trong file này là significance claim". Lý do: V1 bắt buộc
power disclosure; script phải tự sinh chứ không phải người viết tay.

### 1.2 Analysis thật [X2]

`.venv/bin/python scripts/r12_defense_analysis.py` → exit 0, 200 rows,
`unknown_arm_rows_ignored={}` → `outputs/packguard/defense/defense_analysis.json`
(status **ok**, mock=false, date 2026-09-27T20:08:02Z). Đối chiếu độc lập
với bảng verify của V2: **KHỚP 100% mọi ô**.

Per-model (malicious recall; FP = benign false positives):

| model | P0 | P2 (attack) | P2+D1 (defended) | gain/loss | McNemar P2vsP2D1 | FP P0→defended |
|---|---|---|---|---|---|---|
| llama-3.2-3B | .167 (4/24) | .042 (1/24) | .042 (1/24 — sample KHÁC: artifact-lab) | 1/1 | p=1.0 (n=24, 1/1) | 0/14 → 0/14 |
| granite-3.3-2B | .667 (16/24) | .833 (20/24) | .652 (15/23; 1 unparsed disclosed) | 0/4 | p=.125 (n=23, 0/4) | 0/14 → 0/14 |

Pooled (descriptive, n=47 parsed malicious pairs): P0 .417 (20/48), P2
.438 (21/48), P2D1 .340 (16/47); gain 1 / loss 5; McNemar P2vsP2D1
p=.219 (b01=1/b10=5), P0vsP2D1 p=.375 (b01=1/b10=4); benign FP P0 0/28,
P2D1 0/28, **P2 0/0 = NOT-MEASURED** (batch không có arm P2 benign —
đúng như V2 cảnh báo token FP_P2 rỗng). Chiều llama: gain = artifact-lab
(detection MỚI dưới defense), loss = tinywallet (advisory tự nó là cue);
4 mất của llama = 4 bản @antoncallahan/aws-user-helper. Chiều granite: 4
flip b→m do P2 (az-ext, claude-skills-library, cryptographz, hmac2) revert
hết; P2D1 ≡ P0 trên 23/23 cặp parse được (kayauthgen unparsed, vốn
P0-positive). Fisher loại trừ gate [[24,6],[14,1]] p=.3955 → "p=.40, no
label bias". H-D1/H-D2: granite PASS cả hai, llama FAIL cả hai →
"supported" theo luật ≥1/2 model, nhưng per-model split là read chính.

### 1.3 Token FP_P2 (NOT-MEASURED) → nguồn thay thế n=100

`outputs/packguard/r10/r8_safety_expand/safety_metrics_n100.json` đọc lại
trực tiếp: fp_benign P2 = **llama 0.0 (0/50), granite 0.04 (2/50)** →
paper ghi rõ "quoted from that expansion, not re-measured here" kèm % SRC.

## 2. 37 TOKEN → GIÁ TRỊ (map điền; mọi số đã verify §1.2)

| Token | Giá trị đã điền |
|---|---|
| NPAIRS | "76 paired real packages (38 gate-passing samples × two models; realized 24 malicious + 14 benign per model; 47 parsed malicious pairs pooled)" |
| STATUS | chuyển vào comment `% SRC` (status ok, mock=false, 2026-09-27T20:08:02Z) — câu "Status at resolution time" gỡ khỏi prose paper |
| POOLED_REC_P2 / _D1 / _P0 | .438 (21/48) / .340 (16/47; 1 unparsed disclosed) / .417 (20/48) |
| POOLED_GAIN / _LOSS | 1 / 5 |
| P_NODEF_VS_D1 / P_P0_VS_D1 | .219 (n=47, 1 vs 5) / .375 (1 vs 4) |
| FP_P2 | "the attack arm carries no benign rows in this batch; at the n=100 expansion the advisory caused 2/100 benign FPs, all granite" (SRC: safety_metrics_n100.json) |
| FP_D1 | 0/28 |
| LL_REC_P0 / _P2 / _D1 | .167 / .042 / .042 |
| LL_GAIN/_LOSS, LL_P | 1/1, 1.0 |
| LL_FP_P2 → _D1 | 0/50→0/14 (0/50 từ n=100) |
| GR_REC_P0 / _P2 / _D1 | .667 / .833 / .652 |
| GR_GAIN/_LOSS, GR_P | 0/4, .125 |
| GR_FP_P2 → _D1 | 2/50→0/14 (2/50 từ n=100) |
| TABLE_NOTE | caption: realized 24/14 sau gate A6.1 (7/45 comment-only → strip-to-empty, excluded+disclosed, 6 mal/1 ben, Fisher p=.40); P0/P2 cache hits; FP cột attack từ n=100; 1 granite P2D1 unparsed (baseline-positive); 0 discordant granite P0vsP2D1 (23 parsed; CP upper ≈12%) → mọi p descriptive |
| ABS_REC_P2 / _D1 / _P | .438 / .340 / .219 (abstract) |
| ABS_CLAUSE | "a descriptive shift that hides opposite per-model outcomes: on granite-3.3-2B the strip fully neutralizes the channel (all four attack-induced flips revert to the neutral baseline; benign FP 0), while on Llama-3.2-3B it restores nothing — the four detections it loses are byte-identical snippets of a single package family whose own comments the defense also strips, a defense cost we pre-registered as a possible outcome" |
| CONC_REC_P2 / _D1 / _P / _FP | .438→.340, p=.219, "0/28 defended; attack arm not re-run in this batch (n=100 expansion: 2/100, all granite)" |
| CONC_CLAUSE | "the decisive read is again per-model: full neutralization on granite-3.3-2B (verdicts identical to the neutral baseline on all 23 parseable pairs; all four attack-induced flips revert; benign FP 0) versus no restoration on Llama-3.2-3B, whose four lost detections are byte-identical snippets of one package family whose own comment the strip also removes — a defense cost we pre-registered as a possible outcome; every reported p is descriptive at this pilot scale" |

Sửa khác trong main.tex (ngoài token): (1) "30 malicious + 15 benign;
1/30 resolution" → "registered 30+15; realized 24 malicious + 14 benign
per model after 7 of the 45 drawn snippets are comment-only, strip to
empty, excluded and disclosed per the A6.1 gate; label-independent,
Fisher p=.40; coarse single-sample resolution"; (2) câu byte-identity
nâng theo V1: "on all 38 gate-passing samples the stripped attack file
equals the stripped original byte-for-byte (so P2+D1 ≡ P0+D1 at the byte
level), with byte-identical P2+D1 vs P0 prompts — and temperature-0
completions — for the 10 comment-free originals"; (3) đoạn mới
"Per-model outcome" sau bảng (wording V1: granite "fully neutralizes ...
identical on every parseable pair 23/23 ... all four flips revert"; llama
"does not restore ... byte-identical 2500-char snippets from four archive
versions of a single package family (19 distinct families) ... defense
cost pre-registered ... tinywallet lost again, single P2D1 detection is
yet another family; family granularity 1/19 every condition"). Kiểm đếm:
0 occurrence `{{R12:` / `R12:` còn lại trong main.tex (grep = 0);
`\detokenize` = 0; PDF text không còn "{{".

## 3. ATTACK+DEFENSE VERDICT (headline cho paper)

**Untrusted advisory shifts recall in a family-dependent direction
(granite +, llama −); AST sanitization neutralizes the channel on granite
and costs nothing beyond baseline on llama — with a defense-cost caveat
(llama's lost detections stem from stripping the package's own comment).**

- Granite (P2 UP-type): recall .667→.833 dưới attack +4 flip b→m; D1 đưa
  về .652 (|Δ|=0.014 so với P0, với 1 unparsed disclosed), 4/4 flip
  revert, FP 0/14 → neutralization ĐẦY ĐỦ trên model này (H-D1 ✓ H-D2 ✓
  per-model). Wording bắt buộc của V1 đã giữ: "identical on all 23
  parsed pairs; the single unparseable P2+D1 output was baseline-positive".
- Llama (P2 DOWN-type): .167→.042; D1 không khôi phục (.042); 4 detection
  mất = 4 version byte-identical của 1 family có comment riêng cũng bị
  strip → defense cost đã preregister (A6.3). Gain 1 của llama là detection
  MỚI (artifact-lab), không phải phục hồi — đã ghi đúng chiều trong paper.
- Byte-fidelity (V1 nâng cấp): strip(P2)==strip(original) ở 38/38 sample →
  P2+D1 ≡ "attack removed" đúng nghĩa ở mọi sample (paper đã ghi).
- Power: 0/23 discordant (granite P0-vs-P2D1) → p=1.0 by construction;
  CP upper cho tỷ lệ discordant ≈ 12.2% (tự tính, ghi trong caption ≈12%);
  p nhỏ nhất toàn batch .125 → MỌI p chỉ descriptive (đã ghi ở abstract,
  bảng, pooled sentence, per-model paragraph, conclusion).
- Câu HD1/HD2 "supported" mức ≥1/2 model chỉ xuất hiện trong comment SRC,
  không dùng làm claim paper — đúng yêu cầu giữ per-model split là read chính.

## 4. CHATGPT MCP

Vẫn **not_authenticated** — thử `chatgpt_session_status` trực tiếp trong
phiên F: "chatgpt-web error (not_authenticated): ChatGPT page did not show
a composer. Run chatgpt_login first." Cần USER login thủ công vào browser
profile; sau đó chạy lại nguyên văn prompt trong W2_report §5 (new_chat,
timeout 420s) — framing-only, không phải nguồn số. Không bịa ý kiến
"ChatGPT".

## 5. VIỆC CÒN LẠI

- **P1-7 / P1-8 / P1-10**: thuộc kế hoạch vòng 12 của orchestrator, KHÔNG
  có định nghĩa trong repo (grep toàn bộ reports/docs không thấy) — ngoài
  phạm vi F, orchestrator tự đối chiếu. Việc round-12 còn mở theo TODO của
  W1/W2 mà F không có quyền/đ안 định: (a) arm control P0+D1 (38×2 gen rẻ
  trên cùng harness) để tách "strip removed the advisory" khỏi "strip
  removed useful comments"; (b) mở rộng draw sang gate-passers [30:50]
  (đã cache P0/P2 ở n100) cho llama bớt 1-family; (c) nạp macro R12 vào
  `gen_paper_numbers.py` (đụng file chung — quyết định của orchestrator).
- **P2 (giai đoạn sau)**: theo bản paper, các mục Q1-grade còn queue đã
  liệt kê trong Conclusion (validation-locked threshold, KB ablation
  20-seed, GNN thật, leave-families-out, mechanism-isolated arms n≥100,
  ecosystem thứ ba, deployed-data evaluation, A5 provenance closure cho
  granite ladder) — F không thêm bớt.
- User action duy nhất: **login ChatGPT** cho MCP (mục 4) rồi chạy lại
  consult prompt.

## 6. FILES + CÁCH CHẠY + SELF-TEST

Files (F sở hữu): `scripts/r12_defense_analysis.py` (sửa: sample_id +
pooled merge + per_model_pointers + caveat động + descriptive_power),
`tests/test_r12_analysis.py` (+3 regression test: pooled no-overwrite 2
model, features join schema sample_id fail-loud, descriptive_power),
`scripts/make_manifest.py` (+3 artifact: defense_analysis.json,
defense_metrics.json, safety_metrics_n100.json — batch jsonl vẫn loại theo
policy), `outputs/master/ARTIFACT_MANIFEST.sha256` (regen: 40 files),
`outputs/packguard/defense/defense_analysis.json` (real, status ok),
`paper2/main.tex` (37 token + 30/15→24/14 + per-model paragraph + comment
RESOLVED), `reports/round12/F_report.md`. KHÔNG đụng: `packguard/`,
`scripts/r12_attack_defense*`, batch/metrics của W1, prereg.

```
$ .venv/bin/python -m pytest tests/test_r12_analysis.py -q   → 20 passed
$ .venv/bin/python scripts/r12_defense_analysis.py           → OK: 200 rows;
  llama .1667/.0417/.0417 g1/l1; granite .6667/.8333/.6522 g0/l4  (exit 0)
$ cd paper2 && tectonic main.tex ; echo $?                   → 0
  (main.pdf 176.99 KiB; chỉ underfull warnings như baseline)
$ grep -c "R12:" paper2/main.tex                             → 0
$ .venv/bin/python scripts/gen_paper_numbers.py --check      → OK -- 336 macros
$ .venv/bin/python -m pytest tests/ -q                       → 708 passed
  (705 baseline + 3 regression mới; 0 failed, ~79s)
$ bash scripts/verify_repro.sh ; echo $?                     → 0
  (SUMMARY: 30 passed, 0 failed; manifest 40 ok, 0 mismatched)
$ pdftoppm trang 1/8/9 → soi trực quan: bảng Table 6 không tràn cột;
  abstract + conclusion đọc đúng hướng per-model.
```

*Lệch chuẩn: (1) NPAIRS/STATUS không điền theo nghĩa token gốc mà viết lại
câu (STATUS hạ xuống comment) vì token gốc gợi ý "60 (30+15×2)" đã sai từ
khi realized 24/14 — đã disclose ở mục 2; (2) `defense_analysis.json`
(pending marker cũ của W2) được GHI ĐÈ bởi lần chạy thật hợp lệ, và
`defense_analysis_mock.json` được REGEN bằng script đã sửa để đồng bộ schema
mới (per_model_pointers + descriptive_power; số fixture giữ nguyên khớp tính
tay .6667/.3333/.5000, gain 1/loss 0) — đúng đích của cả hai file; (3) số
"Clopper-Pearson ≈12%" trong caption là 12.2% tự tính trên 0/23 (V1 ghi
14.8% với n giả định khác — F dùng số tự tính của mình, n nêu rõ).*
