# packguard-prompts-r16

Frozen prompt files for the two PackGuard round-16 Kaggle GPU runs
(pre-registered in docs/packguard_prereg.md AMENDMENT-9, 2026-09-28T13:54:28Z,
BEFORE this dataset was created):

- `ladder_prompts_7b8b.jsonl` — 180 rows = 60 vulnerable samples of
  bench_attack_v1 (registered ladder subset, seed 20260923, arm C5_near)
  x 3 rungs {A0 baseline, A5 full-P3 reassertion defense, A1 boundary-only}.
  Rebuilt byte-identically by the round-6/7 machinery; rebuilt prompt shas
  match the stored round-7 qwen7b A0/A5 records (60/60 each) and the r10
  granite A1 records (60/60).
- `safety_prompts_7b.jsonl` — 300 rows = the exact n=100 safety-batch
  selection (50 malicious + 50 benign; round-8 draw seed 20260922,
  gate-passers, code_chars=2500) x arms {P0_neutral, P1_offensive_wording,
  P2_advisory_in_package}. Selection verified 100/100 against the recorded
  safety_batch_n100.jsonl samples; P0 prompt shas match the round-12 defense
  batch 38/38.
- `prompts_verification.json` — machine-readable verification meta (counts,
  draw stats, file sha16).

Row schema: {"sample_id", "label", ..., "rung"|"arm", "system", "user",
"prompt_sha256_16", ...}. Kernels run greedy generation (temperature 0,
max_new_tokens 512 ladder / 384 safety) on T4 x2 and append results to
/kaggle/working. No labels are used at generation time.
