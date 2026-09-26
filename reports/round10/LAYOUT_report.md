# LAYOUT_report.md — Round 10 layout-fix pass (visual-judge audit remediation)

## Lần 2 (2026-09-25) — second visual-judge pass: X1–X6

Scope again **form/layout only**; no scientific number or claim changed except
the [BLOCKING] redraw of Fig. 8(a) from its real source (X4 below).
`paper/make_figures.py` re-run in full before compiling; its verify battery
passed verbatim:
`[verify] all table numbers match source files` /
`[verify] round-5 table numbers match outputs/master/round5_master.json` /
`[verify] 41 Table-8 tokens match outputs/master/round7_token_map.json` /
`[verify] 19 headline numbers cross-checked against
outputs/master/master_results.json`. No git commit.

### Measure: compile log (tectonic, final builds)

| Paper | Overfull ≥10pt BEFORE (this pass) | AFTER | Other notes |
|---|---|---|---|
| paper1 (`paper/`) | 0 (round-1 state) | **0** (0 Overfull of any size) | the round-1 `Underfull \vbox` (badness 4266, the stretched page-6 column) is **gone** — `\raggedbottom` removed it; remaining warnings are loose-line `Underfull \hbox` badness only (round-1 `\emergencystretch` tradeoff, no overflow, no layout hole) |
| paper2 (`paper2/`) | 0 hbox (round-1 state) | **0** | unchanged; 1.17pt-class vbox noise on the balanced last page only |

Full renders self-inspected: paper1 pages 1–20 (`pdftoppm -r 110`, contact
sheets) and paper2 pages 1–8. Page count unchanged (20 pp / 8 pp).

### Per-item outcome

1. **[X1] Fig. 1 node overflow (page 4) — FIXED.** `fig_conditions()` in
   `paper/make_figures.py` rewritten: canvas 7.0→7.16 in, node fonts
   6.4/7.0 → 5.9–6.2, all eight boxes widened/re-gridded (xlim 0–12),
   longest labels re-wrapped ("B1 reframe / B2 comment strip" split,
   "REFUSED_UNSAFE if gate flags unsafe prompt" → 3 short lines,
   B4 box split to 3 lines of ≤ ~37 chars), and the task-intent-gate arrow
   re-routed down→across the inter-row band→ending **on the Recovery box's
   top edge** (previously it plunged into the box and crossed the word
   "Recovery"). Added a built-in overflow guard: after drawing, every label's
   renderer extent is measured and asserted to sit inside its own rectangle
   (`label overflows box` assert) — 6/8 overflowing nodes from the audit are
   now all inside. Verified on the page-4 render.
2. **[X2] ~5-line whitespace hole mid-left-column, page 6 — FIXED.** No
   explicit `\vspace`/`\vfill`/float exists in the source (checked
   `04_setup.tex` lines 104–146 byte-level); the hole was `\flushbottom`
   injecting the column's ~54pt of slack into the single stretchable
   `\paragraph` skip before "Power analysis." (proved by a diagnostic
   `\raggedbottom` compile: gap moved out). Fix: `\raggedbottom` in
   `paper/preamble.tex` (commented) — the column now ends naturally after
   "…Llama control C0 record)." and "Power analysis." follows the preceding
   paragraph directly. Page-6 render clean; every other page re-scanned for
   new raggedness (none: all full pages stay flush).
3. **[X3] Fig. 6 (page 8) collisions — FIXED** (`fig_round5()`): title (a)
   shortened to two lines ≤ ~41 chars ("(a) C5 attack: no blocking
   (RR = 0.000), / verdicts drift to “vulnerable”") so it can no longer reach
   panel (b)'s rotated ylabel; `fig.subplots_adjust(wspace=0.52)` added after
   `tight_layout` as a dedicated gutter for that ylabel; legend (b)
   ("B0 (raw)"/"P3 (boundary)") moved out of the bars into the free top band
   (`upper center`, `ncol=2`, `frameon=True, framealpha=1.0,
   edgecolor=#bbbbbb`, roomier `labelspacing`). Page-8 render clean.
4. **[X4, BLOCKING] Fig. 8(a) wrong data — REDRAWN from the real source.**
   `fig_round7()` rewritten: panel (a) now plots **exactly the two series of
   Table 8** (Granite-3.3-2B primary) — C0 = 0.050/0.000/0.200/0.000 and
   C5_near = 0.700/0.750/0.650/0.700 — for families in the table's
   registered order CWE-476/416/190/200. Values are read from
   `outputs/master/round7_token_map.json` (the same mapped strings typeset in
   `tables/tab_round7.tex`), and each is asserted equal to
   `outputs/master/round7_master.json` (`cwe.granite2b.<f>.fp_rate_C0 /
   fp_rate_C5_near`) before plotting — figure and table cannot drift.
   (Note: the judge's "C0 = 0.550" for CWE-476 is a misread of the typed
   0.050; the token map, the table, and the master file all say 0.050 —
   investigated before trusting the source, per instruction.) The old
   figure's unexplained 0.95–1.00 band was the Llama-3.2-3B secondary
   per-family series, which has no per-family rows in Table 8 — those bars
   are removed (Llama stays in the table as its verdict row); the
   near-invisible gray C0 series is fixed by labeling every bar value
   (0.05/0.00/0.20/0.00 now legible). Panel (a) legend framed/opaque
   ("C0 (raw)" gray / "C5_near (attack)" red), title names the model.
   Panel (b): single blue series per its legend, tick reads **"A1 / boundary
   only"**, framed opaque legend clear of the bars with increased
   line-spacing, labels use "Qwen2.5-Coder-7B-Instruct" (the "granite3b"-era
   shorthand labels are gone; panel (a) is labeled "Granite-3.3-2B"). The
   Fig. 8 caption's Sources line now cites
   `outputs/master/round7_token_map.json` alongside the master. Page-14
   render matches Table 8 cell-for-cell; make_figures verify PASS (41/41
   Table-8 tokens).
5. **[X5] paper2 page-8 orphan refs — BOTH levers tried; accepted 8 pages
   per disclosed fallback.** Attempt 1 `\renewcommand{\bibfont}{\footnotesize}`
   before `\bibliography` (acmart+natbib): probe-verified that `\bibfont` IS
   honored here (bold probe changed the list), but ACM-Reference-Format
   already sets the list at footnotesize — zero height recovered (kept in
   source, commented as a no-op attempt). Attempt 2 `\bibsep` 2.5pt → 2pt
   (natbib feeds it to the list `\itemsep`): recovered only ~5pt. Refs
   [8]–[10] need ~11 more lines than page 7 offers (page 7's two columns are
   already full; both pages visually confirmed). Per instruction the paper
   **stays 8 pages**, with `flushend` balancing the last page: refs
   [8]–[10] split evenly across the two columns. This mirrors the round-1
   disclosure (7-page fit not achievable spacing-only).
6. **[X6] Final builds + artifacts.** Both papers recompiled clean:
   paper1 20 pp / paper2 8 pp; **0 Overfull warnings** either paper (target
   "0 ≥10pt" exceeded). All 20 + 8 pages rendered and inspected. Copies:
   `paper2/PackGuard_final.pdf` and
   `/Users/macbook/.zcode/workspace/default/PackGuard_FINAL.pdf` (8 pp),
   `/Users/macbook/.zcode/workspace/default/RefuseGuard_FINAL.pdf` (20 pp).

### Files touched this pass

- `paper/make_figures.py` — `fig_conditions()` rewrite + overflow guard;
  `fig_round5()` title/wspace/legend; `fig_round7()` redraw from the token
  map + source cross-asserts; `verify_tables()` extended with the 41-token
  Table-8 ↔ token-map check.
- `paper/preamble.tex` — `\raggedbottom` (X2, commented).
- `paper/sections/05_results.tex` — Fig. 8 caption Sources line (token map).
- `paper2/main.tex` — `\renewcommand{\bibfont}{\footnotesize}` (no-op,
  documented) + `\bibsep` 2pt.
- Figures regenerated (`paper/figures/*.pdf`); PDFs recompiled; artifacts
  copied as in item 6.

---

## Lần 1 (first visual-judge pass)

Scope: **form/layout only**. No scientific number, verdict, or claim was
changed anywhere. Every plotted number was regenerated from the same
`outputs/**` files by `paper/make_figures.py`, which re-ran its full
`verify_tables()` battery (all checks passed, verbatim):
`[verify] all table numbers match source files` / `[verify] round-5 table
numbers match outputs/master/round5_master.json` / `[verify] 19 headline
numbers cross-checked against outputs/master/master_results.json`.
No git commit was made.

---

## Measure: compile log (tectonic)

| Paper | Overfull \hbox BEFORE | Overfull \hbox AFTER |
|---|---|---|
| paper1 (`paper/main.tex`) | ~122 warnings; **~90 ≥5pt, ~67 ≥10pt** (worst: `tab_round6_ablation` 579.5pt, `tab_round7` 386.5pt, `tab_defenses` 151.0pt, `05_results` 71.5pt, `06_discussion` 72.3pt) | **0** (zero warnings of any size; goal "0 ≥5pt" met, "0 ≥10pt" exceeded) |
| paper2 (`paper2/main.tex`) | 3 hbox (2.7pt, 22.1pt, 7.9pt) + 1 vbox 1.17pt | **0 hbox** (only the 1.17pt vbox remains, below every threshold) |

Visual verification: `pdftoppm -r 110` full renders of paper1 (20 pages) and
paper2 (8 pages) inspected page-by-page. All judge-flagged pages
(paper1: 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 15, 17, 18, 19) re-rendered clean.

---

## A. PAPER1 fixes (per audit item)

1. **[CRITICAL] Page 10 column overlap — FIXED.** Root cause was not a
   negative `\vspace`: `tables/tab_round6_ablation.tex` was 579.5pt too wide
   (its `\multicolumn{6}{@{}l@{}}` note rows were single non-breaking lines),
   so the table's right column ("p (vs. prev.)", `7.45×10⁻⁹` broken to
   "7146×10⁻⁹") printed across the gutter on top of §5.6 text, and the note
   rules crossed the "Figure 4 is the central safety result..." paragraph.
   Fix: `\footnotesize` + `\tabcolsep=2.5pt`, "Added component" column →
   `>{\raggedright\arraybackslash}p{0.28\columnwidth}`, and all 4 note rows →
   wrapping `\multicolumn{6}{@{}>{\raggedright...}p{\dimexpr\columnwidth-2\tabcolsep}}`.
   Evidence: rendered page 10 before (overlap) vs after (table fits its
   column; `7.45×10⁻⁹` intact; §5.4–5.6 text clean).
2. **[HIGH] Odd-page running head — FIXED.** `\title[RefuseGuard: Robust LLM
   Vulnerability Detection]{...}` (short title ~48 chars) added in
   `main.tex`. Page 3+ headers now read "RefuseGuard: Robust LLM Vulnerability
   Detection" beside "Conference'17, ..." with no collision ("Defenfself.17"
   gone).
3. **[HIGH] Tables 3/5/6 cut at page edge — FIXED.** `tab_defenses.tex`
   (151pt over): `\footnotesize`, `\tabcolsep=3pt`, Quantity/Value columns →
   raggedright `p{0.27/0.42\columnwidth}` — fits left column (page 9 render).
   `tab_round5.tex` (79.9pt) and `tab_round5_defense.tex` (84.9pt):
   `\footnotesize` + `\tabcolsep=2.5/3pt`, wide bottom note rows → wrapping
   p-multicolumns; round5_defense header split to two lines. All values
   (`3.8×10⁻⁶`, `10 / 20 / 25`, ...) fully visible, nothing clipped.
4. **[HIGH] Table 7 note block cut — FIXED.** Same wrapping p-multicolumn
   treatment (item 1); notes now wrap inside the column.
5. **[HIGH] Appendix A.1/A.2 path overflow (page 18) — FIXED.** `\code` was
   redefined from `\texttt{\small}` to a breakable `url`-`\path` form
   (breaks at `/ _ .`; `\robustify\code` via etoolbox keeps it safe inside
   `\caption`); all `\code{..._...}` args de-escaped to raw `_`; the three
   multi-word shell commands kept `\texttt` (url would print spaces as
   hyphens); A.1 + A.2 paragraphs wrapped in `sloppypar`. The long paths
   (`scripts/collect_master_round6.py`, `configs/round5_e0v2.yaml`, ...)
   now wrap at underscores; no line-number collisions (page 18–19 render).
   `\code` paths in `sections/04_setup.tex` got the same treatment.
6. **[MEDIUM] Figure 2 caption path overflow — FIXED.** The glob
   `outputs/experiments/round3_e0/{qwen3b,llama3b,granite2b}/results.json`
   (braces = unbreakable `\texttt`) replaced by the judge-suggested
   `outputs/experiments/round3_e0/<model>/results.json` in breakable
   `\code`; same for the Fig. 6 (`results_<model>.json`) and Fig. 4
   (`round3_e8*/recomputed/...`) captions. Renders show wrapped, intact paths.
7. **[MEDIUM] Table 8 (round7) note overflowing to paper edge — FIXED.**
   The 386pt "Prompt identity vs. Round-6 ... byte-for-byte ..." row and the
   two verdict rows → wrapping `\multicolumn{6}{p{\dimexpr\textwidth-2\tabcolsep}}`
   inside the `table*` (page 11 render clean).
8. **[MEDIUM] Table 9 (traceability) gutter overflow — FIXED.** Column spec →
   raggedright `p{0.28}/p{0.58}\columnwidth`; paths wrap inside cells.
   `\balance` (package `balance` **is** in the tectonic bundle): loads and
   compiles, but produces no visible change on the final page — noted, kept
   (harmless).
9. **[LOW] `paper/make_figures.py` — ALL FIXED and figures regenerated**
   (numbers re-read from the same output files; guards for round6/round7
   masters untouched):
   - (a) Fig 5(a): subtitle shortened (`FNR@FPR≤0.5%`) and set to fontsize
     7.0 — no longer overlaps the "Score" ylabel or clips right.
   - (b) Fig 6(a): TeX backticks `` ``vulnerable'' `` → unicode curly quotes
     "vulnerable".
   - (c) Fig 6 legend: `Qwen-3B` → `Qwen2.5-Coder-3B` (matches the model
     name used everywhere else).
   - (d) Fig 7 (fig_round6) and Fig 8(b) (fig_round7 panel b): legends moved
     out of the bars (upper-center 2-col band / upper-left) with `ylim`
     headroom 1.18→1.32 — the thin legends no longer sit on the A0 bar.
10. **Global text overfulls** (intro/related/method/setup/results/discussion/
    conclusion, ~80 warnings ≥5pt): eliminated by the breakable `\code`
    paths + `\emergencystretch=2.5em`, `\tolerance=2000` in
    `paper/preamble.tex` (emergency stretch only engages on otherwise
    unbreakable lines; wording untouched).

Final paper1 state: **0 Overfull warnings**, 20 pages, all pages re-rendered
and inspected (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
18, 19, 20).

---

## B. PAPER2 fix (audit: page-8 bib drift)

- `\usepackage{balance}` + `\balance` **and** `\usepackage{flushend}` were
  both tested — both exist in the tectonic bundle and compile cleanly.
- Result: the last page's two columns are balanced, but the paper stays
  **8 pages**: entries [8]–[10] genuinely need ~114pt (≈12 bib lines) more
  than page 7's right column can offer. Spacing-only levers were applied —
  `\bibsep=2.5pt` (tightens the reference list) — which recovered ~20pt and,
  together with `\emergencystretch` 1.2em→2.5em, removed **all three Overfull
  \hbox warnings**; the 1.17pt Overfull \vbox (below threshold) remains.
- Verdict per instructions: balance/flushend run successfully but a 7-page
  fit is not achievable without touching content → **accepted with this
  note**; final state: `flushend` kept (auto-balances the final page),
  8 pages, page 8 holds refs [8]–[10] in two balanced columns.

---

## Files touched (all layout-only)

- `paper/preamble.tex` — array/etoolbox/balance packages; breakable `\code`;
  `\emergencystretch`/`\tolerance`.
- `paper/main.tex` — short `\title[...]`; `\balance`.
- `paper/tables/tab_round6_ablation.tex`, `tab_round7.tex`,
  `tab_round5.tex`, `tab_round5_defense.tex`, `tab_defenses.tex`,
  `tab_calibration.tex` — font size / tabcolsep / wrapping p-columns /
  p-multicolumn note rows. No cell value edited.
- `paper/sections/04_setup.tex`, `05_results.tex`, `06_discussion.tex`,
  `appendix_repro.tex` — `\texttt` paths → breakable `\code` (raw `_`),
  brace-globs → `<model>`/`*` placeholders, `sloppypar` around the two long
  appendix paragraphs, trace-table column spec.
- `paper/make_figures.py` — figure cosmetics (a)–(d) above; figures
  regenerated (`paper/figures/*.pdf`), all verification asserts pass.
- `paper2/main.tex` — `flushend`, `\bibsep=2.5pt`, `\emergencystretch=2.5em`.

## Artifacts

- Final PDFs: `paper/compiled/main.pdf` (20 pp), `paper2/compiled/main.pdf`
  (8 pp).
- Verification renders: `/tmp/renderF/p-01..20.png` (paper1 final),
  `/tmp/rp2d/p-8.png` (paper2 final page).
