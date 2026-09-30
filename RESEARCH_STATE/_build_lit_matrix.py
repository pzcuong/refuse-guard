#!/usr/bin/env python3
"""Build RESEARCH_STATE/LITERATURE_MATRIX.csv with guaranteed-valid CSV quoting.
Scout: scout-vuln-detection, 2026-09-30. Sources: arXiv MCP search + Semantic Scholar
batch_get_papers (full abstracts) + WebSearch (ACL 2025 verification). Run this script
to regenerate; do not hand-edit the CSV."""
import csv

HEADER = ["paper", "venue", "year", "task", "dataset", "model", "method",
          "attack_model", "defence", "metrics", "best_result", "limitations",
          "what_they_do_NOT_evaluate", "overlap", "novelty_risk", "opportunity"]

R = []
R.append(["PrimeVul: Vulnerability Detection with Code Language Models — How Far are We? (Ding et al., arXiv:2403.18624; DOI 10.1109/ICSE55347.2025.00038)",
"ICSE", "2025", "function-level binary vuln detection (C/C++)",
"PrimeVul (~6968 vul / ~229794 benign functions; paired vul/patched; chronological split)",
"CodeBERT/CodeLlama-7B SFT; GPT-3.5; GPT-4",
"benchmark construction + labeling pipeline + dedup + chronological split; paired VD-S evaluation",
"none (cooperative)", "none", "F1; VD-S (paired); accuracy",
"SOTA 7B: 68.26% F1 on BigVul vs 3.09% F1 on PrimeVul; GPT-4 akin to random guessing in strictest setting (abstract)",
"C/C++ only; cooperative setting; label noise reduced not eliminated",
"refusal/safety; untrusted-context perturbation; any defence or mitigation; repo-level context",
"Direct substrate of RefuseGuard (official splits + paired eval adopted per PROJECT_BRIEF.md)",
"None — enabling work",
"Primary paired-eval protocol for E0-E8; VD-S analog as primary endpoint"])

R.append(["SecLLMHolmes: LLMs Cannot Reliably Identify and Reason About Security Vulnerabilities (Ullah et al., arXiv:2312.12575; DOI 10.1109/SP54263.2024.00210)",
"IEEE S&P", "2024", "vulnerability identification + reasoning; robustness probing",
"228 code scenarios across 4 datasets (incl. DiverseVul/PrimeVul-derived)",
"8 LLMs incl. GPT-4; PaLM2; CodeLlama; Starcoder2",
"automated multi-dimensional evaluation framework (8 investigative dimensions)",
"superficial code perturbations: identifier renaming; added library function calls", "none",
"accuracy; flip rate under perturbation",
"renaming functions/variables flips GPT-4/PaLM2 answers in 26%/17% of cases (abstract)",
"pre-reasoning-model era; scenario-based; no mitigation proposed",
"refusal/safety alignment; defence design; repo context; semantics-preservation audit of perturbations",
"Closest 2024 precedent that semantics-preserving textual edits corrupt verdicts — foreshadows RefuseGuard C2 (benign contextual stress)",
"HIGH for any 'first robustness-under-perturbation' claim — must be scoped to security-charged/instructional context + refusal axis",
"Attack-strength template for C2; motivates E0 without re-claiming the phenomenon"])

R.append(["LLM4Vuln + UniVul (Sun et al., arXiv:2401.16185)",
"arXiv (v5 updated 2025)", "2024", "decoupled evaluation of LLM vuln reasoning",
"UniVul: 147 vul + 147 non-vul; Solidity/Java/C-C++; 3528 controlled scenarios",
"GPT-4.1; Phi-3; Llama-3; o4-mini; DeepSeek-R1; QwQ-32B",
"factor-decoupled eval: knowledge retrieval vs context supplementation vs prompt schemes",
"none (cooperative)", "none", "accuracy per factor; zero-day discovery",
"knowledge/context/prompt have varying impacts; 14 zero-days found; USD 3576 bounties (abstract)",
"single-function granularity; cooperative contexts only",
"refusal/over-refusal; adversarial context; defence; paired strict metric",
"Protocol reference for E0 factorial arms (already cited in docs/literature_review.md)",
"Low",
"Factorial design template; contrast 'context helps' (theirs) vs 'context corrupts' (RefuseGuard C2/C3)"])

R.append(["CORRECT: Everything You Wanted to Know About LLM-based Vulnerability Detection (Li et al., arXiv:2504.13474)",
"arXiv", "2025", "context-rich paired detection + rationale validation",
"2000 vulnerable-patched pairs; 99 CWEs", "13 LLMs across 4 families",
"context-augmented evaluation + LLM-as-judge rationale validation",
"none (benign context only)", "none", "F1; precision; rationale validity",
"0.7 F1 on key CWEs; 0.8 precision with sufficient context; most FPs are reasoning errors; overthinking bias (abstract)",
"frontier-model heavy; benign context; judge-based rationale scoring",
"adversarial/untrusted context; refusal; defences; small local models",
"Positive-control contrast: their thesis 'context helps' vs RefuseGuard 'untrusted context corrupts' — must scope claims accordingly",
"MODERATE — context-conditioning effects are taken; RefuseGuard must own the adversarial + refusal axis",
"C5 query-relevant advisory condition design; rationale-validation methodology"])

R.append(["Vul-RAG (Du et al., arXiv:2406.11147; DOI 10.1145/3797277)",
"TOSEM", "2025", "function-level paired detection + explanation",
"PairVul-style vuln/patched pairs + real-world projects", "GPT-3.5/GPT-4-class",
"knowledge-level RAG: multi-dimensional root-cause knowledge distilled from historical fixes",
"none (cooperative)", "none", "pairwise accuracy; explanation quality; zero-day yield",
"baseline LLMs only 0.06-0.14 acc distinguishing vuln vs patched; Vul-RAG +16-24%; 10 unknown Linux kernel bugs / 6 CVEs (abstract)",
"KB construction cost; proprietary models in original; cooperative prompts",
"untrusted/injected context; refusal; defence-side cost; open-weight reproducibility (latter fixed by ARES 2026 study)",
"The paired-eval predecessor RefuseGuard builds on; retrieved knowledge is trusted-by-construction — opposite of RefuseGuard untrusted context",
"LOW-MODERATE",
"Candidate trusted-knowledge defence arm; pairwise numbers define the utility ceiling"])

R.append(["Revisiting Vul-RAG: Reproducibility with Open-Weight Models (Kaniewski et al., arXiv:2606.04739)",
"ARES", "2026", "reproducibility/replicability of RAG-based VD",
"Vul-RAG pairwise benchmark; fully local open-weight setup",
"open-weight code-specialized + general + reasoning models (various sizes)",
"replication + extension of Vul-RAG", "none (cooperative)", "none", "pairwise accuracy",
"findings reproduce locally; performance plateau ~0.30 pairwise accuracy across ALL models incl. reasoning models (abstract)",
"single framework (Vul-RAG); no safety/robustness axis",
"refusal; context attacks; defences; metrics beyond pairwise",
"HIGH overlap on the open-weight/local-model constraint (<4B program): proves local models reproduce RAG-VD results and quantifies the pairwise plateau",
"MODERATE — if RefuseGuard reports pairwise gains on similar open-weight stack, the ~0.30 plateau is the bar to beat",
"Use public artifacts (github.com/hs-esslingen-it-security/revisiting-Vul-RAG) as local baseline infra; plateau motivates P2 transformer fallback"])

R.append(["VulInstruct (Zhu et al., arXiv:2511.04014; DOI 10.1145/3808132)",
"Proc. ACM Softw. Eng. (FSE)", "2025", "root-cause-reasoning detection + pairwise eval",
"PrimeVul + pairwise sets", "open-weight LLMs with specification-guided fine-tuning",
"specification KB (general + domain-specific) retrieved to steer reasoning",
"none (cooperative)", "none", "F1; recall; pairwise improvement; unique detection",
"PrimeVul 45.0% F1 (+32.7% rel); 37.7% recall; pairwise +32.3% rel; unique detection 24.3% = 2.4x baselines (abstract)",
"training-time (fine-tune + KB); cooperative; strict-metric dependence",
"refusal/safety; untrusted context; inference-time defences; cost under context perturbation",
"Strongest published PrimeVul number found in this sweep; training-time alternative to RefuseGuard inference-time mediation",
"LOW-MODERATE — distinct mechanism (specs) but adjacent goal (pairwise gains)",
"Target for fallback/fine-tune arm comparison; spec-KB idea reusable as trusted evidence channel"])

R.append(["JitVul: Benchmarking LLMs and LLM-based Agents in Practical Vulnerability Detection for Code Repositories (Yildiz et al., arXiv:2503.03586; aclanthology 2025.acl-long.1490)",
"ACL", "2025", "repo-level JIT detection (vuln-introducing + fixing commits); pairwise",
"JitVul: 879 CVEs; 91 vul types", "GPT-4o-class LLMs + ReAct agents; CoT prompting",
"benchmark + agent eval with interprocedural context retrieval", "none (cooperative)", "none",
"pairwise accuracy; detection quality",
"ReAct agents > plain LLMs at distinguishing vulnerable vs benign (abstract); inconsistencies: misidentification + over-analyzing security guards",
"agents need refinement; compute cost; no refusal quantification",
"refusal/safety-induced blocking (their 'over-analyzing security guards' is observed anecdotally not measured); defences",
"HIGH-ish: their guard-over-analysis error mode is the un-quantified cousin of RefuseGuard refusal/verdict-drift; also corrects project lit-review: ACL 2025 long.1490 IS this paper (not a separate Sun et al. paper)",
"MODERATE — repo-level benchmark space is contested; RefuseGuard is function-level paired",
"Repo-level extension substrate; quantify their guard-over-analysis anecdote as refusal/verdict-drift rate"])

R.append(["VulAgent: Hypothesis-Validation Multi-Agent VD (Wang et al., arXiv:2509.11523)",
"arXiv", "2025", "project-level detection + localization",
"two paired datasets (vuln-fixed pairs)", "multi-LLM agent ensemble",
"multi-view specialized agents + hypothesis conditions + trigger-path validation",
"none (cooperative)", "none", "accuracy; vuln-fixed pair correct-ID rate; FPR",
"+6.6% acc; vuln-fixed pair ID +246% avg (up to 450%); FPR -36% vs SOTA LLM baselines (abstract)",
"multi-agent token cost; cooperative setting; arXiv-only venue per S2",
"refusal; adversarial context; safety; cost-under-attack",
"Hypothesis-validation ~= RefuseGuard trusted-verifier stage but with NO untrusted-context threat model",
"MODERATE — verification-style pipelines are crowding; differentiator must be the corruption/recovery axis",
"Strongest agent baseline arm; design template for P2 verification stage"])

R.append(["MAVUL: Multi-Agent VD via Contextual Reasoning (Li et al., arXiv:2510.00317; DOI 10.1109/TPS-ISA67132.2025.00040)",
"TPS-ISA", "2025", "pairwise multi-agent detection with refinement",
"pairwise vulnerability dataset", "LLM agents (analyst + architect + evaluation agent)",
"contextual reasoning + iterative interactive refinement + judge agent", "none (cooperative)", "none",
"pairwise accuracy; multi-dimensional eval",
">+62% pairwise accuracy vs existing multi-agent systems; >+600% avg vs single-agent (abstract)",
"venue is mid-tier; pairwise dataset not PrimeVul; proprietary-model emphasis unclear from abstract",
"refusal; context corruption; defences; small models",
"Their evaluation-agent-as-judge relates to RefuseGuard Refusal Monitor; no safety axis", "LOW",
"Agent-arm comparison; judge-agent pattern reuse for monitor design"])

R.append(["MultiVer: Zero-Shot Multi-Agent VD (Rajan, arXiv:2602.17875)",
"arXiv", "2026", "zero-shot detection (Python)", "PyVul; SecurityEval",
"4-agent ensemble (security/correctness/performance/style); union voting",
"zero-shot ensemble voting", "none (cooperative)", "none", "recall; precision; F1",
"82.7% recall on PyVul (> fine-tuned GPT-3.5 81.3%); 48.8% precision; 61.4% F1; 91.7% detection on SecurityEval (abstract)",
"precision cost; PyVul/SecurityEval not strict paired PrimeVul; single-author arXiv",
"refusal; robustness; repo-level; paired strict metric",
"LOW — different benchmark + goal; union-voting ensemble is an alternative aggregation defence shape vs P2 monitor",
"LOW — no refusal/robustness/safety axis claimed",
"Recall-vs-precision trade framing reusable for FN-cost argument in RefuseGuard"])

R.append(["CLEAR: Causal Context-Based Agentic Reasoning (Yun et al., arXiv:2608.03134)",
"arXiv", "2026", "pairwise agentic detection (C/C++/Java)",
"C/C++ + Java pairwise benchmarks",
"4 agents (Collector/Claim/Critic/Judge) + Vulnerability Causal Knowledge Graph",
"causal-chain (entrypoint/precondition/root-cause/fix-intent) retrieval + hypothesis verification",
"none (cooperative)", "none", "Pair-Correct (P-C)",
"P-C +130.7% and +71.56% over SOTA on two benchmarks (abstract)",
"KG construction cost; cooperative; arXiv-only",
"refusal; untrusted context; safety; cost",
"NEAREST PRIOR for charter section-6 evidence-grounded direction: causal-chain verification ~ trusted evidence channel — but assumes clean trusted context",
"HIGH for the evidence-grounded/invariant direction — must differentiate via trusted/untrusted provenance partition + corruption detection",
"Differentiation template: run CLEAR-style verification on untrusted context to show evidence corruption; reuse as strong baseline"])

R.append(["R2Vul (Weyssow et al., arXiv:2504.04699)",
"arXiv (under review per S2)", "2025", "reasoning-distilled detection + explanation; 5 languages",
"18000-sample multilingual preference dataset; 5-language eval",
"1.5B code LLM student; 32B teacher; 8 LLM baselines",
"RLAIF + structured reasoning distillation; FP calibration under imbalance",
"none (cooperative)", "lightweight calibration to cut FPR",
"F1 vs static analyzers + LLM baselines; explanation ranking",
"1.5B R2Vul exceeds its 32B teacher and Claude-4-Opus (abstract)",
"arXiv-stage; training-time; cooperative",
"refusal/safety; untrusted context; corruption recovery",
"HIGH relevance to <4B constraint: small reasoning models are exactly RefuseGuard's local substrate; calibration = selective prediction cousin",
"MODERATE — claims small-model superiority; RefuseGuard differs by robustness/safety axis",
"Candidate local fine-tune arm (B4+); their calibration step comparable to abstention/fallback designs"])

R.append(["VulnLLM-R (Nie et al., arXiv:2512.07533)",
"arXiv", "2025", "specialized reasoning LLM + agent scaffold; project-level",
"Python/C-C++/Java SOTA datasets + real repos", "7B reasoning model + agent scaffold",
"reasoning-data generation/filtering/correction + testing-phase optimization + scaffold",
"none (cooperative)", "none", "comparison vs CodeQL/AFL++; zero-day count",
"outperforms SOTA static tools + open/commercial large reasoning models; zero-days found in maintained repos (abstract)",
"7B scale (>4B program constraint); arXiv-stage",
"refusal; robustness of verdicts under context manipulation; safety",
"Sets the reasoning-model bar RefuseGuard cannot chase under <4B; distinct threat model", "LOW-MODERATE",
"Reasoning-distill recipe as future work if scale constraint relaxes"])

R.append(["VulnSage: Reasoning with LLMs for Zero-Shot VD (Zibaeirad & Vieira, arXiv:2503.17885)",
"arXiv", "2025", "zero-shot multi-granularity detection (function/file/inter-function)",
"VulnSage C/C++ dataset from OSS projects", "code-specialized + general LLMs",
"4 zero-shot strategies: Baseline/CoT/Think/Think&Verify", "none (cooperative)", "none",
"accuracy; ambiguous-response rate",
"Think&Verify cuts ambiguous responses 20.3% -> 9.1% while raising accuracy; code-specialized > general (abstract)",
"arXiv-stage; noise pre-filter heuristic; no defence",
"refusal taxonomy (ambiguous != REFUSAL); adversarial context; paired strict metric",
"Their 'ambiguous response' rate is adjacent to RefuseGuard PARTIAL-answer rate / UAC but not refusal-calibrated", "LOW",
"Metric-design precedent for decomposing unusable answers; supports UAC/PARTIAL operationalization"])

R.append(["LProtector (Sheng et al., arXiv:2411.06493)",
"arXiv", "2024", "RAG-based binary detection (C/C++)", "Big-Vul", "GPT-4o + RAG",
"LLM + retrieval-augmented classification pipeline", "none (cooperative)", "none", "F1",
"outperforms two SOTA baselines on Big-Vul (abstract)",
"Big-Vul label noise (PrimeVul critique applies); no strict paired eval; proprietary model",
"paired strict metric; refusal; robustness; defence cost",
"LOW — RAG over clean knowledge base only; no untrusted-context or refusal axis", "LOW",
"RAG-arm example; cautionary Big-Vul optimism example vs PrimeVul numbers"])

R.append(["Systematic Study of Code Obfuscation Against LLM-based VD (Li et al., arXiv:2512.16538)",
"arXiv", "2025", "robustness of LLM VD + coding agents under obfuscation",
"4 languages (Solidity/C/C++/Python); 15 LLMs + Copilot/Codex",
"DeepSeek/OpenAI/Qwen/LLaMA families + 2 coding agents",
"systematization: 3 classes; 11 subcategories; 19 concrete obfuscation techniques",
"code obfuscation (layout/data-flow/control-flow) as evasion", "none (open problems only)",
"detection delta per technique; sign of impact",
"obfuscation both degrades AND improves detection depending on technique/model/vuln type (abstract)",
"no defence proposed (future work only); no refusal/safety measurement",
"refusal/safety-alignment interference; security-charged (non-obfuscation) context; mitigation",
"HIGH for C2/C3-like perturbation axis: semantics-preserving code transformation robustness — but their transforms alter code style not inject security-charged text/instructions",
"HIGH for any 'robustness under semantics-preserving transformation' phrasing — scope RefuseGuard to security-semantic context + refusal axis",
"Reuse their 19-technique taxonomy to harden C2 generator; their no-defence gap is RefuseGuard's opening"])

R.append(["EaTVul: ChatGPT-based Evasion Attack Against SVD (Liu et al., arXiv:2407.19216)",
"arXiv", "2024", "adversarial evasion of DL vulnerability detection",
"DL VD models (graph-based) on vulnerability datasets", "GPT-based perturbation generator",
"LLM-crafted adversarial code perturbations", "adversarial code perturbation (evasion)", "none",
"evasion success rate", "LLM-generated perturbations successfully evade DL detectors (per abstract)",
"targets classic DL detectors not LLM detectors; arXiv-stage",
"LLM-based detectors as victims; refusal; semantics audit",
"Attack-side prior showing LLMs as attack tools against code models — not the RefuseGuard availability failure mode", "LOW",
"Attack-generation reference for red-team arm"])

R.append(["NatGVD: Natural Adversarial Examples vs Graph-based VD (Rath et al., arXiv:2510.04987)",
"arXiv", "2025", "adversarial robustness of graph-based VD", "graph VD benchmarks",
"graph-based VD models", "natural (unoptimized) adversarial examples",
"adversarial graph perturbation", "none", "attack success / detection drop",
"per abstract: natural adversarial examples successfully degrade graph VD",
"graph models only (not LLMs); arXiv-stage", "LLM detectors; refusal; defences",
"Same as EaTVul — attack-side; complements C2 semantics-preservation argument", "LOW",
"Cite for robustness motivation; contrast with LLM-detector threat model"])

R.append(["Comparison of SAST Tools and LLMs for Repo-level VD (Zhou et al., arXiv:2407.16235)",
"arXiv", "2024", "repo-level detection: LLM vs SAST comparison",
"repo-level vulnerable-fix datasets", "ChatGPT/GPT-4-class", "SAST comparison + LLM prompting",
"none (cooperative)", "none", "accuracy; F1; cost",
"per abstract: LLMs competitive/outperform SAST tools on repo-level detection in several settings",
"arXiv-stage; dataset noise; cooperative", "refusal; robustness; paired strict metric",
"Repo-level evaluation precedent; project lit-review already tracks it", "LOW",
"Repo-level extension baseline; SAST-arm comparison"])

R.append(["ReposVul (Wang et al., arXiv:2401.13169)",
"arXiv", "2024", "repo-level benchmark construction",
"ReposVul: repo-level dataset with pipeline/commit-region structure", "n/a (benchmark)",
"dataset construction aligned to patch region + pipeline context", "none (cooperative)", "none",
"n/a (benchmark)", "n/a — benchmark paper", "benchmark; evaluation on it is separate work",
"refusal; robustness; defences",
"Substrate used by 2604.08417 interprocedural study; repo-level axis of charter section-5A", "LOW",
"Repo-level generalization dataset if E-series scales up"])

R.append(["VulnGym: Benchmarking Coding Agents for Repo-level VD (Ji et al., arXiv:2608.02001)",
"arXiv", "2026", "repo-level agentic detection end-to-end",
"184 GitHub advisories; 408 entries; 23 repos; line-level traces",
"coding agents (agentic LLMs)",
"end-to-end detection task + 3 oracle-based subtasks (localization/evidence)",
"none (cooperative)", "none", "end-to-end detection; subtask diagnostics",
"current coding agents remain limited end-to-end and at evidence/trace construction (abstract)",
"arXiv-stage; advisory-derived labels; agentic cost", "refusal; context attacks; defences",
"Frontier for repo-level agentic axis; confirms localization+evidence as bottleneck — supports P1 provenance motivation",
"MODERATE — repo-level agentic benchmarking is heating up",
"Oracle-decomposition methodology adaptable to diagnose RefuseGuard failure stages"])

R.append(["Interprocedural Context in Multiple Languages (Lira et al., arXiv:2604.08417)",
"arXiv", "2026", "interprocedural detection + cost + explanation quality",
"509 vulnerabilities from ReposVul (C/C++/Python)",
"Claude Haiku 4.5; GPT-4.1 Mini; GPT-5 Mini; Gemini 3 Flash",
"empirical: 3 context levels (function-only/+callers/+callees)", "none (cooperative)", "none",
"F1; cost; explanation correctness",
"Gemini 3 Flash F1 >= 0.978 on C at USD 0.50-0.58 per config; Haiku 4.5 93.6% correct+explained (abstract)",
"frontier proprietary models; ReposVul optimism vs PrimeVul strictness likely; arXiv-stage",
"refusal; adversarial context; small/local models; paired strict metric",
"Context-composition evidence (callers/callees) relevant to P1 provenance partition design; huge F1 vs PrimeVul 3.09% gap = dataset-difficulty cautionary tale", "LOW",
"Context-window reporting requirement for manifests (already charter-mandated); cost accounting template"])

R.append(["Think Broad Act Narrow: CWE Identification with Multi-Agent LLMs (Sayagh & Ghafari, arXiv:2508.01451)",
"arXiv", "2025", "CWE-type identification (broad->narrow)",
"CWE-labeled vulnerability datasets", "multi-agent LLM (broad scan -> narrow verification)",
"two-stage multi-agent CWE identification", "none (cooperative)", "none", "CWE-ID accuracy",
"per abstract: multi-agent pipeline improves CWE identification; abstract reiterates LLMs fail to distinguish vulnerable function from benign counterpart",
"arXiv-stage; task is CWE typing not binary detection",
"refusal; context attacks; paired binary metric; defences",
"Reiterates the paired-discrimination failure that RefuseGuard measures under corruption", "LOW",
"CWE-output schema support (cwe field in RefuseGuard JSON output); broad->narrow pattern for gate design"])

R.append(["Security Is Relative: Training-Free VD via Multi-Agent Behavioral Contract Synthesis (Wang & Huang, arXiv:2604.19012)",
"arXiv", "2026", "training-free detection via behavioral contracts",
"legacy + strictly deduplicated benchmarks", "multi-agent LLM",
"behavioral-contract synthesis between vulnerable/benign semantics", "none (cooperative)", "none",
"F1 under strict dedup",
"notes legacy F1 > 0.68 collapses to 0.031 under strict deduplication; root cause = semantic-duplication contamination (abstract)",
"arXiv-stage; single author pair; no safety axis", "refusal; untrusted context; defences; cost",
"Independently reproduces the contamination/collapse story PrimeVul told — converging evidence for strict paired eval", "MODERATE",
"Validation of strict-eval necessity; contract-synthesis idea adjacent to RefuseGuard trusted-verifier hypotheses"])

R.append(["Do Fine-Tuned LLMs Understand Vulnerabilities? The Semantic Trap (Huang et al., arXiv:2601.22655)",
"arXiv", "2026", "mechanistic analysis of SFT detectors", "SFT vulnerability-detection models",
"CodeLlama-class SFT models", "shortcut/semantic-trap analysis of fine-tuned detectors",
"none (cooperative)", "none", "shortcut-dependence metrics",
"per abstract: SFT models exploit superficial shortcuts rather than internalizing root causes",
"arXiv-stage; SFT models only", "refusal; context corruption; defences",
"Supports the mechanism story: fallback transformer (B4) may inherit shortcuts — motivates LLM+monitor P2", "LOW",
"Cite for why transformer fallback alone is insufficient; motivates hybrid P2"])

R.append(["Calibration Without Comprehension / CWE-Trace (Zibaeirad & Vieira, arXiv:2606.20502)",
"arXiv", "2026", "contamination diagnosis + kernel-specific detection",
"834 manually curated Linux kernel samples; 7 CWEs", "modern LLMs incl. fine-tuned",
"CWE-Trace framework; calibration-vs-comprehension diagnosis", "none (cooperative)", "none",
"accuracy; contamination indicators",
"per abstract: good benchmark scores do not imply security reasoning; contamination explains much performance",
"arXiv-stage; kernel domain", "refusal; untrusted context; defences",
"Third independent contamination/collapse study (with PrimeVul + 2604.19012) — strengthens RefuseGuard's strict-eval motivation", "LOW",
"Kernel CWE families as CWE-generalization strata (charter: 6-10 families)"])

R.append(["Evaluating and Enhancing the Vulnerability Reasoning Capabilities of LLMs (Lu et al., arXiv:2602.06687)",
"arXiv", "2026", "verdict-vs-rationale faithfulness + enhancement",
"vulnerability reasoning benchmarks", "modern LLMs",
"diagnose hallucinated-logic verdicts; propose reasoning enhancement", "none (cooperative)", "none",
"verdict accuracy; rationale faithfulness",
"per abstract: models frequently give correct verdicts from hallucinated logic deviating from root causes",
"arXiv-stage", "refusal; context corruption; defences",
"Directly relevant to RefuseGuard output schema (root_cause field) — rationale faithfulness under corruption unmeasured",
"MODERATE — rationale-faithfulness angle could collide with RefuseGuard claims if extended to adversarial context",
"root_cause-field validation methodology; enhancement arm candidate"])

R.append(["PromptAudit: Auditing Prompt Sensitivity in LLM-Based VD (Camarato et al., arXiv:2605.24171)",
"arXiv", "2026", "prompt-formulation sensitivity audit",
"fixed dataset + decoding controls", "LLM VD setups",
"controlled audit isolating prompt effects",
"none (prompt variation as independent variable; no adversarial intent)", "none",
"metric variance across prompt formulations",
"per abstract: reliability varies materially across prompt formulations with data/decoding fixed",
"arXiv-stage; prompt-variant space limited", "security-charged context; refusal; defences",
"Nearest 2026 robustness-audit neighbor on the prompt axis; RefuseGuard differs: semantic content of untrusted code context + refusal measurement",
"HIGH for 'prompt sensitivity of LLM VD' phrasing — RefuseGuard conditions must be framed as context/instruction corruption not prompt paraphrase",
"Template for controlled-variation methodology in E-series; cite to justify prompt-template hashing"])

R.append(["VulDetectBench (Liu et al., arXiv:2406.07595)",
"arXiv (v4)", "2024", "multi-task deep-capability benchmark",
"vulnerability benchmark suite (multi-task)", "multiple LLMs", "multi-stage capability benchmark",
"none (cooperative)", "none", "task-wise accuracy",
"per abstract: LLMs strong on code comprehension but limited deep vulnerability capability",
"arXiv-stage (later versions exist; venue unverified here)",
"refusal; robustness; paired strict metric",
"Multi-task benchmark reference for CWE/location/schema outputs", "LOW",
"Task taxonomy reference for output-schema fields"])

R.append(["Benchmarking LLMs for Multi-Language SVD (Zhang et al., arXiv:2503.01449)",
"arXiv", "2025", "multi-language detection benchmark",
"multi-language benchmark (per abstract)", "multiple LLMs",
"comprehensive multi-language LLM evaluation", "none (cooperative)", "none",
"accuracy/F1 per language",
"per abstract: systematic capability picture across languages",
"abstract-only extraction this sweep (numbers not extracted)",
"refusal; robustness; paired strict metric", "Language-coverage reference if RefuseGuard adds languages", "LOW",
"External-validation dataset candidate"])

R.append(["Dual-Granularity Multilingual Evaluation (Shu et al., arXiv:2506.07503)",
"arXiv", "2025", "dual-granularity (statement/function) multilingual detection",
"multilingual benchmarks", "LLMs", "granularity-controlled evaluation", "none (cooperative)", "none",
"per-granularity performance", "per abstract: effectiveness varies by granularity and language",
"abstract-only extraction", "refusal; robustness; paired metric",
"Granularity framing supports location-field evaluation", "LOW",
"Location-granularity metric design input"])

R.append(["Ensembling LLMs for Code VD: Empirical Evaluation (Sun et al., arXiv:2509.12629)",
"arXiv", "2025", "ensemble methods for detection", "standard VD benchmarks", "multiple LLMs",
"ensemble/voting across LLMs", "none (cooperative)", "none", "accuracy/F1 of ensembles",
"per abstract: ensembles resolve discrepancy across models and improve reliability",
"abstract-only extraction", "refusal; robustness; cost; paired metric",
"Ensemble = alternative defence arm vs P2 fallback", "LOW-MODERATE",
"Ensemble-arm comparison for B-series"])

R.append(["Can LLM Prompting Serve as a Proxy for Static Analysis? (Ceka et al., arXiv:2412.12039)",
"arXiv", "2024", "prompted static-analysis proxying", "CodeQL-annotated datasets",
"GPT-4-class", "prompt-based SA-replacement evaluation", "none (cooperative)", "none",
"agreement with SA tools",
"per abstract: LLM prompting shows limited ability as SA proxy for VD", "arXiv-stage",
"refusal; robustness; defences",
"SAST-proxy framing aligns with CodeBERT-fallback vs LLM hybrid question", "LOW",
"Justification for hybrid fallback (P2) architecture"])

R.append(["LLMxCPG: CPG-Guided Context-Aware VD (Lekssays et al., arXiv:2507.16585)",
"arXiv", "2025", "CPG-guided detection", "real-world C/C++ benchmarks",
"LLM + code property graph", "structural context via CPG + LLM reasoning",
"none (cooperative)", "none", "accuracy/F1",
"per abstract: CPG guidance improves detection vs plain LLM", "abstract-only extraction",
"refusal; robustness; cost", "Structural-evidence channel precedent (P1 trusted-code-evidence cousin)",
"MODERATE for evidence-channel framing",
"CPG as trusted structural evidence source for P1/P2 designs"])

R.append(["VulnScout-C: Lightweight Transformer for C VD (Lassoued et al., arXiv:2603.28309)",
"arXiv", "2026", "lightweight practical detection (C)", "C vulnerability benchmarks",
"compact transformer (sub-billion scale per abstract framing)", "efficiency-oriented transformer",
"none (cooperative)", "none", "accuracy; latency",
"per abstract: strong detection at practical latency vs multi-billion LLMs",
"arXiv-stage; no LLM comparison depth", "refusal; robustness; paired strict metric",
"Directly supports <4B fallback feasibility (B4 arm) and the deployment argument", "LOW",
"Latency/size evidence for fallback arm; deployment-cost framing for paper"])

R.append(["LLMs Cannot Reliably Detect Vulnerabilities in JavaScript (Fei et al., arXiv:2512.01255)",
"arXiv", "2025", "JavaScript detection benchmark + eval",
"JS benchmark (first systematic per abstract)", "multiple LLMs",
"systematic benchmark + evaluation", "none (cooperative)", "none", "accuracy/F1",
"per abstract: LLMs unreliable on JS vulnerability detection",
"abstract-only extraction; JS-only", "refusal; robustness; defences",
"Language-external validity reference", "LOW", "Language-generalization discussion for limitations section"])

R.append(["Toward Scalable Automated Repo-level Datasets (Lbath, arXiv:2603.17974)",
"arXiv", "2026", "repo-level dataset automation",
"executable interprocedural settings (per abstract)", "n/a (dataset)",
"automated dataset construction for executable interprocedural VD", "none (cooperative)", "none",
"n/a (dataset)", "per abstract: existing benchmarks function-centric; executable interprocedural settings missing",
"arXiv-stage", "refusal; robustness; defences",
"Repo-level axis of charter section-5A; executable-setting gap matches charter realism concern", "LOW",
"Future repo-level extension substrate"])

R.append(["MulVul: RAG Multi-Agent VD via Cross-Model Prompt Evolution (Wu et al., arXiv:2601.18847)",
"arXiv", "2026", "RAG + multi-agent detection", "multi-CWE real-world sets (per abstract)",
"multi-model agents", "evolutionary prompt generation per CWE + retrieval",
"none (cooperative)", "none", "accuracy/F1",
"per abstract: addresses heterogeneity of vuln patterns + manual prompt burden", "arXiv-stage",
"refusal; context attacks; cost",
"Prompt-evolution = automated prompt engineering; contrast with RefuseGuard's fixed hashed templates + mediation",
"HIGH if RefuseGuard ever claims prompt-side novelty — do not; novelty is context-robustness not prompt optimization",
"Prompt-space robustness spot-check reference"])

R.append(["Argus: Multi-Agent Ensemble for Full-Chain VD (Liang et al., arXiv:2604.06633)",
"arXiv", "2026", "full-chain SAST reorchestration (agentic RAG)",
"industrial-scale repos; zero-day cases", "multi-agent + RAG + ReAct",
"LLM-centered SAST workflow: supply-chain analysis + collaborative agents", "none (cooperative)", "none",
"true-positive volume; FP reduction; cost; zero-days",
"per abstract: more true vulns; fewer FPs; lower cost; critical zero-days with CVE assignments",
"arXiv-stage; industrial claims hard to verify", "refusal; context attacks; strict paired metric",
"Claim 'first multi-agent framework for VD' — avoid any competing 'first' phrasing; adjacent to charter competitor list E",
"HIGH for 'first agent framework' style claims",
"Industrial-deployment framing for motivation; zero-day case studies for intro"])

R.append(["Empirical Evaluation of RAG/SFT/Dual-Agent for VD (Saju et al., arXiv:2601.00254)",
"arXiv", "2026", "comparative study: RAG vs SFT vs dual-agent",
"software vulnerability datasets (per abstract)", "LLM setups under 3 approaches",
"controlled comparison", "none (cooperative)", "none", "accuracy/F1 per approach",
"per abstract: comparative effectiveness picture of three LLM-based techniques",
"abstract-only extraction; venue unclear", "refusal; robustness; paired strict metric",
"Method-family comparison covering two RefuseGuard-adjacent arms (RAG/SFT) — useful baselines map", "LOW",
"Arm-selection justification for B-series (RAG arm vs SFT arm vs agent arm)"])

R.append(["AutoTrace: Trigger Localization via Agentic Exploration (Zibaeirad et al., arXiv:2607.12058)",
"arXiv", "2026", "trigger localization (post-detection task)", "vulnerability-fixing commits",
"agentic LLM exploration", "interprocedural causal trigger localization", "none (cooperative)", "none",
"localization accuracy",
"per abstract: harder-than-detection task with interprocedural causal reasoning",
"adjacent task (not binary detection); arXiv-stage", "refusal; context attacks; defences",
"Adjacent-task reference; trigger-path idea mirrors VulAgent hypothesis paths", "LOW",
"Future-work pointer; trigger-path evidence for root_cause field"])

R.append(["Beyond Refusal: Aligned vs Abliterated LLMs for Vulnerability Analysis (Li et al., arXiv:2607.05842)",
"arXiv", "2026", "refusal impact on vulnerability-analysis utility",
"vulnerability-analysis task suite (same-lineage aligned vs abliterated models)",
"same-lineage aligned + abliterated LLMs",
"controlled same-lineage comparison of alignment state",
"none (measures safety-behavior interference; no attacker)", "abliteration as (drastic) intervention",
"refusal rate; task utility",
"per abstract: vuln-analysis terminology can resemble misuse terminology; alignment suppresses vuln analysis",
"abstract-only extraction; abliteration is training-time weight surgery",
"refusal MONITORING + retry; semantics-preserving untrusted context; fallback; paired correctness with refusal metrics; small local models",
"DIRECT nearest neighbor on the refusal axis (already verified in docs/literature_review.md section-0) — measures refusal-vs-utility but NOT untrusted-context corruption or inference-time recovery",
"HIGH — RefuseGuard novelty phrasing must not claim 'first to link refusal and vulnerability analysis'; own the corruption+recovery+fallback triple instead",
"Comparison arm; motivation citation; their utility-degradation numbers as E0 external prior"])

R.append(["Llama-based SVD: Prompt Engineering vs Fine-Tuning (Ouchebara & Dupont, arXiv:2512.09006)",
"arXiv", "2025", "prompting vs fine-tuning on Llama", "Binary classification SVD sets",
"Llama-family open weights", "controlled prompting-vs-SFT comparison", "none (cooperative)", "none",
"accuracy/F1", "per abstract: empirical comparison of the two adaptation routes",
"abstract-only extraction", "refusal; robustness; paired strict metric",
"Open-weight adaptation reference for <4B program", "LOW",
"B/T-arm design reference (prompt vs fine-tune trade)"])

R.append(["SoK: Security Issues Across AI4Code Use Cases (Wu et al., arXiv:2512.18456)",
"arXiv", "2025", "systematization of AI4Code security risks",
"AI4Code use cases incl. VD (per abstract)", "n/a (SoK)", "systematization",
"threat taxonomy incl. benchmark bias", "defence taxonomy", "mapping",
"per abstract: pervasive risks incl. insecure outputs; biased benchmarks; supply-chain; contextual",
"SoK — no new empirical numbers", "context-specific VD robustness numbers; refusal quantification",
"Frames RefuseGuard within a recognized risk taxonomy — good related-work anchor", "LOW",
"Related-work section anchor; taxonomy for threat-model section"])

OUT = "/Users/macbook/.zcode/workspace/default/refuseguard/RESEARCH_STATE/LITERATURE_MATRIX.csv"
AUDIT_ONLY = False
if AUDIT_ONLY:
    for i, r in enumerate(R):
        if len(r) != len(HEADER):
            print(f"ROW {i}: {len(r)} fields | {r[0][:70]}")
            for j in range(len(HEADER)):
                print(f"   {j:2d} {HEADER[j]:28s}: {r[j][:60] if j < len(r) else '<<MISSING>>'}")
    print(f"AUDIT: {len(R)} rows, offenders above (if any)")
else:
    with open(OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        w.writerow(HEADER)
        for r in R:
            assert len(r) == len(HEADER), f"row has {len(r)} fields: {r[0][:60]}"
            w.writerow(r)
    print(f"Wrote {len(R)} data rows x {len(HEADER)} cols to {OUT}")
