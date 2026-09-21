# S_report — Vòng 7 (orchestrator đảm nhiệm vai trò S sau khi phiên S subagent bị
# ngắt bởi rate-limit)

Phạm vi: kiểm lại toàn bộ số đã điền bởi phiên bị ngắt, sửa 3 lỗi LaTeX vỡ, hoàn thiện
verify chain (manifest + value checks), viết ROUND7_SUMMARY. KHÔNG bịa số; mọi số đối
chiếu `outputs/master/round7_master.json` (134 rows, re-read verified).

## 1. Kiểm lại số trong paper (phiên trước đã điền)

- Script đối chiếu: 40/40 số RQ8 + 15/15 số RQ9 trong
  `paper/sections/05_results.tex`, `06_discussion.tex`, `paper/tables/tab_round7.tex`
  khớp master (format đa dạng: raw, %.3f, %.2f, %, scientific).
- Pattern audit: `GENERALIZES` ✓, `pooled-driven` ✓, `4/4` + `2/4` ✓, `headroom` ✓,
  `family confound` ✓, scope `2-7B` ✓, `0.003906` ✓.

## 2. Sửa 3 lỗi LaTeX (di sản fill bị ngắt — bắt bằng compile check)

1. `paper/tables/tab_round7.tex:98` — `H-G1 NOT_SUPPORTED` underscore thô trong text
   mode → `NOT\_SUPPORTED`; dòng 125 `NOT_SUPPORTED-ABSENT · ...` → `NOT\_SUPPORTED
   -ABSENT $\cdot$ ...`.
2. `paper/sections/05_results.tex:473` — `C5_near` thô → `C5\_near`; `p_exact` →
   `p\_exact` + bọc math.
3. `paper/sections/05_results.tex:416` — `p=1.22{\times}10^{-4}` math trần trong text
   mode → bọc `$...$` toàn paragraph Results (RQ8) + Pooled.

Sau fix: `tectonic paper/main.tex` exit 0; PDF 17 trang; pdftotext: `??`=0,
`{{R7`=0, `round7_cwe`=0.

## 3. Verify chain hoàn thiện

- `scripts/make_manifest.py`: +8 artifact Vòng 7 (round7_master, token_map, round6_bias,
  metrics_rq8, 2 results RQ8, 4 results per-job RQ7B — path per-job thật, sửa từ
  `results.json` không tồn tại) → manifest 34 files, `--check` 34/34 ok.
- `scripts/verify_repro.sh` step 4: +4 value-check RQ7 (granite/llama label
  GENERALIZES; RQ9 A5-vs-A0 exact p=0.7265625 → harm absent; A0 recall ≈0.4746).
  Chạy toàn bộ: **30 passed, 0 failed, exit 0**.
- pytest full suite: **531 passed, 0 failed**.

## 4. Những gì S KHÔNG làm (trung thực)

- Không chạy thêm generation nào; không đụng src/conditions, src/models, src/defenses,
  src/metrics, src/data.
- Không tự xử lý latent collector branch "GENERALIZES khi ≤3 family powered" (V2 #3) —
  không fire với data hiện tại, để nguyên kèm note.
- Không restart RQ9 trên model họ llama (khuyến nghị #2 trong ROUND7_SUMMARY) — chờ
  user duyệt vì mất thêm ~2-3h GPU.

## 5. Bàn giao

- Paper chốt: `paper/compiled/main.pdf` (17 trang, compile sạch).
- Báo cáo: `reports/round7/ROUND7_SUMMARY.md` (bảng 7 mục AI SAI/AI BẮT ĐƯỢC + tổng 7
  vòng + 3 khuyến nghị).
- Trạng thái objective: mọi deliverable local đã xong; "publish/strong accept" là quyết
  định reviewer bên ngoài — khuyến nghị còn lại (frontier API / llama-8B ladder / RQ8
  expansion) nằm ngoài session trừ khi user cấp tài nguyên.
