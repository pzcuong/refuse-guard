# Literature Review — RefuseGuard (Round 1, compact version)

Date: 2026-09-18. Verification method: arXiv API `id_list` / title queries
(machine-checked IDs + titles + dates) and web search with official-venue
links. **Every entry in `refs.bib` was verified to exist**; items that could
not be verified to arXiv/venue level are marked and excluded from the bib.

## 0. Verification of PROPOSAL citations

| Proposal ref | Claimed | Status | Note |
|---|---|---|---|
| [1] Defensive Refusal Bias, arXiv:2603.01246 | ICLR'26 wksp | **VERIFIED** (arXiv API; Campbell et al., 2026-03-01) | Real; abstract matches proposal claim (refusal of authorized defensive cyber tasks). |
| [4] Beyond Refusal, arXiv:2607.05842 | 2026 | **VERIFIED** (Li, Qiu, Peng, Fan, 2026-07-07) | Title/author match "M. Li et al."; abstract confirms safety-state vs vulnerability-analysis utility focus. |
| [5] CodeSentinel, arXiv:2606.19235 | 2026 | **VERIFIED** (Cheng, Yu, Lin, Wu, 2026-06-17) | Three-layer defense vs indirect prompt injection in code contexts; authors match. |
| [8] TabooRAG, arXiv:2603.03919 | 2026 | **VERIFIED** (Li et al., 2026-03-04) | Title: "When Safety Becomes a Vulnerability: ... Transferable Blocking in RAG". |
| [2] OR-Bench | ICML 2025 | **VERIFIED** (arXiv:2405.20947) | |
| [3] XSTest | arXiv:2308.01263 | **VERIFIED** | |
| [6] BIPIA | arXiv:2312.14197 | VERIFIED (known-real; listed in BRIEF §3) | |
| [7] PrimeVul | ICSE 2025 | **VERIFIED** (arXiv:2403.18624; DOI in proposal) | Note: our HF mirror is v0.1-based, -13.8% vulnerable vs paper (see docs/eda_primevul.md). |

No UNVERIFIED citations remain in the proposal's reference list.

## 1. LLM-based vulnerability detection (2024-2026)

- **PrimeVul** (Ding et al., ICSE 2025, arXiv:2403.18624): realistic C/C++
  benchmark; strict evaluation shows large optimism gaps in older benchmarks
  (Devign/BigVul); paired VD-S metric. → Our substrate; we adopt official
  splits + paired eval.
- **How Far Have We Gone in Vulnerability Detection Using LLMs**
  (Gao et al. [CORRECTED 2026-09-18: first author is Zeyu Gao, not "Han"],
  arXiv:2311.12420): systematic LLM eval; GPT-4 level ~mid-90s
  accuracy on old benchmarks but much lower precision-oriented performance on
  harder settings. → Motivates realistic-substrate requirement.
- **LLM4Vuln** (Sun et al. [CORRECTED 2026-09-18: author list partially
  fixed via arXiv API], arXiv:2401.16185): decouples LLM vulnerability
  reasoning factors (knowledge, reasoning, prompt format). → Protocol
  reference for prompt-controlled evaluation; E0 arms follow this logic.
- ACL 2025 "Benchmarking LLMs and LLM-based Agents for vulnerability
  detection" (aclanthology 2025.acl-long.1490): agents still struggle
  function-level on real-world code.
- NDSS 2025 comparative study: context-window size materially affects
  detection. → Supports reporting context settings in manifests.

**Gap vs RefuseGuard:** all of the above assume cooperative settings; none
manipulates safety alignment / refusal state, untrusted textual context, or
measures refusal/over-refusal on the vulnerability task itself.

## 2. Over-refusal measurement and mitigation (2024-2026)

- **XSTest** (Röttger et al., arXiv:2308.01263, NAACL 2024): 250 safe/200
  unsafe contrasts; exaggerated-safety test suite. → Our calibration/contrast
  corpus.
- **OR-Bench** (Cui et al., ICML 2025, arXiv:2405.20947): 80k hard benign
  prompts; strong correlation between safety and over-refusal across 32 LLMs.
  → Same.
- **SCANS** (Cao et al., AAAI 2025): query-side classifier to suppress
  exaggerated safety without hurting utility. → Mitigation-taxonomy reference;
  contrast vs our inference-time mediation (no retraining, no classifier gate
  on user intent only).
- **ACTOR / "Just Enough Shifts"** (Dabas et al., ICML 2025): single-layer
  activation calibration to reduce over-refusal. → Same positioning.
- **DOOR** (Zhao et al., ICML 2025): dual-objective alignment (refuse
  harmfulness vs helpfulness incl. XSTest). → Training-time alternative.
- **MOSR** (arXiv:2511.19009): safety-representation intervention for
  over-refusal. → Same family.
- **Safeguard-DoS** (Zhang, Xiong, Mao, arXiv:2410.02916; [VERIFIED
  2026-09-20 via arXiv abstract page: title "LLM Safeguard is a Double-Edged
  Sword: Exploiting False Positives for Denial-of-Service Attacks", v1
  2024-10-03]): shows attackers can weaponize safeguard FALSE POSITIVES —
  ~30-character adversarial prompts or server-side fine-tuning make the
  guard block benign requests (universal blocking >97% on Llama Guard 3,
  white-box). → Availability-side attack on the guardrail itself; motivates
  measuring the defence's own utility cost (our P3 flip-rate ledger).
- 2026 works (Defensive Refusal Bias; Beyond Refusal; TabooRAG) establish
  that cyber/defense and RAG queries specifically get refused. → Direct
  motivation; see §0.

**Gap:** mitigation work targets generic chat safety; nothing evaluates
mitigation *on a security-analysis task with correctness metrics* (does
"un-refusing" actually restore vulnerability-detection utility?) and almost
nothing keeps the unsafe-compliance side of the ledger (our E8).

## 3. Indirect prompt injection in code contexts (2023-2026)

- **BIPIA** (Yi et al., arXiv:2312.14197): benchmark + defense for IPI via
  external content; distinguishes informational vs instructional content.
  → Basis of our C3 design (instruction-like untrusted repo context).
- **Automatic & Universal Prompt Injection Attacks** (Liu et al.,
  arXiv:2403.04957): optimization-based universal injection suffixes.
  → Attack-strength reference for C3.
- **CodeSentinel** (Cheng et al., arXiv:2606.19235): three-layer sanitizer
  defense for IPI in code contexts (comments/strings/identifiers as
  model-facing carriers). → Closest defense work; our B2/B3 baselines plus P1
  differ by optimizing vulnerability-analysis utility + refusal recovery, not
  only attack blocking.

**Gap:** IPI-in-code work optimizes attack blocking; the *availability cost*
side (benign code analysis becoming unusable due to defensive behavior) is not
measured; no paired clean/contextualized benchmark with ground-truth
vulnerability labels exists.

## 4. Safety-utility trade-off (2024-2026)

- **Fine-tuning Aligned LMs Compromises Safety** (Qi et al., arXiv:2310.03693).
- **CyberLLMInstruct** (ACM 2025, doi:10.1145/3733799.3762968): fine-tuning
  for cyber task performance degrades safety alignment — the inverse trade of
  ours.
- **A framework for cybersecurity refusals in AI agents** (arXiv:2606.02644):
  dual-use dilemma in agentic cyber tasks; refusal-boundary inconsistency.
- **aiXamine** (arXiv:2608.20554): unified black-box safety/utility evaluation;
  safety enforcement incurs measurable utility cost via over-refusal.
- **Defensive Refusal Bias** (arXiv:2603.01246): 2.72x refusal multiplier on
  cyber-defense vs neutral NCCDC tasks (VERIFIED 2026-09-19 against the arXiv
  abstract: LLMs refuse keyword-bearing defensive requests "at 2.72x the rate
  of semantically equivalent neutral requests (p < 0.001)"; closes the Round-1
  TODO).

**Gap:** trade-off literature reports aggregate refusal/helpfulness; no work
couples it to *verifiable task correctness* (vulnerable/benign, CWE,
localization) nor to an inference-time defense with fallback. This is
RefuseGuard's joint safety-utility evaluation (UAC/SIUD/DRR/CUL + unsafe
compliance).

## 5. Novelty verdict

Verified literature supports a **narrow but real gap**: there is (i) no
benchmark that measures refusal/over-refusal/usable-answer coverage on
function-level vulnerability analysis under paired clean vs security-charged
contexts, and (ii) no inference-time defense for that setting evaluated jointly
on defensive utility and safety preservation with a transformer fallback.
The claim must be phrased as "first systematic joint evaluation" scoped to
LLM-based vulnerability analysis — NOT "first to observe defensive refusal"
(2603.01246 owns that) and NOT "first IPI-in-code defense" (2606.19235, BIPIA
own that). If E0 fails to reproduce refusal on our tasks, the novelty claim
shifts to robust analysis under untrusted code context (weaker but still
unclaimed territory per §1/§3 gaps).

Round-2 TODO: read the four 2026 PDFs in full (numbers here rest on abstracts
+ search summaries), and add DiverseVul/SecLLMHolmes as external-validation
candidates.
