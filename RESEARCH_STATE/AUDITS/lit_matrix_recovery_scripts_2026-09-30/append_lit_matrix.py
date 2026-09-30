import csv, re, io

PATH = "/Users/macbook/.zcode/workspace/default/refuseguard/RESEARCH_STATE/LITERATURE_MATRIX.csv"

def aid(paper):
    m = re.findall(r"arXiv:(\d{4}\.\d{4,5})", paper)
    return m[0] if m else None

# --- read current state at write time ---
with open(PATH, encoding="utf-8") as f:
    rdr = csv.DictReader(f)
    FIELDS = rdr.fieldnames
    existing = list(rdr)
assert FIELDS == ["paper","venue","year","task","dataset","model","method","attack_model",
                  "defence","metrics","best_result","limitations","what_they_do_NOT_evaluate",
                  "overlap","novelty_risk","opportunity"], FIELDS
have = {aid(r["paper"]) for r in existing if aid(r["paper"])}
V = "scout-verified 2026-09-30"
NONE_COOP = "none (cooperative setting)"
GAP_STD = "refusal/safety-state; untrusted-context perturbation; any defence or mitigation"

R = []
def row(paper, venue, year, task, dataset, model, method, attack, defence, metrics,
        best, limits, not_eval, overlap, risk, opp):
    R.append([paper + ("; " + V if V not in paper else ""), venue, year, task, dataset, model,
              method, attack, defence, metrics, best, limits, not_eval, overlap, risk, opp])

row("DiverseVul: A New Vulnerable Source Code Dataset for DL-based Vulnerability Detection (Chen et al., arXiv:2304.00409; DOI 10.1145/3607199.3607242)",
    "ACSAC","2023","large-scale C/C++ vuln dataset (train+eval) — PrimeVul-line ancestor",
    "large crawled vulnerable-code dataset (OpenAlex record, cited_by 227)","",
    "dataset construction by crawling security-issue websites","none (cooperative)","none","F1/accuracy (record)","",
    "pre-PrimeVul quality controls (noisy labels/duplication critiques) predate it",GAP_STD,"LOW-MED",
    "None — lineage/enabling work","cite only as dataset lineage")

row("VulDetectBench: Evaluating the Deep Capability of Vulnerability Detection with LLMs (Liu et al., arXiv:2406.07595)",
    "arXiv","2024","multi-task LLM vuln-capability benchmark (detection + deeper capabilities)","","",
    "benchmark construction with graded task ladder",NONE_COOP,"none","task-wise accuracy (record)","",
    "cooperative; function-level",GAP_STD,"MEDIUM","None — enabling work","secondary eval ladder if reviewers want beyond paired binary")

row("Beyond Single Bugs: Benchmarking LLMs for Multi-Vulnerability Detection (Pushkar et al., arXiv:2512.22306)",
    "arXiv","2025","multi-vulnerability detection (beyond single-vuln-per-sample)","","","benchmark construction",
    NONE_COOP,"none","detection metrics (record)","","single-vuln-per-sample assumption in prior benchmarks",GAP_STD,
    "LOW-MED","None — orthogonal realism axis","none")

row("LLM-based Vulnerability Detection at Project Scale: An Empirical Study (Li et al., arXiv:2601.19239)",
    "arXiv","2026","project-scale LLM VD; failure-cause analysis","","","empirical study of LLM+static-analysis detectors",
    NONE_COOP,"none","practical effectiveness measures (record)","","project scale, cooperative",GAP_STD,"LOW-MED",
    "None","evidence pool for scale/limitations discussion")

row("Evaluating LLMs for Real-World Web Vulnerability Detection (Neef et al., arXiv:2606.21397)",
    "arXiv","2026","web-vulnerability detection benchmark (frontier + open models)","","frontier (Claude/Gemini-class) + open models",
    "benchmark evaluation",NONE_COOP,"none","detection metrics (record)","","web domain; frontier-only (outside <4B scope)",GAP_STD,
    "LOW","None","none (domain/scale out of scope)")

row("RustMizan: A Compilable, Contamination-Aware Benchmarking Framework for Rust Vulnerabilities (Elsayed et al., arXiv:2607.04729)",
    "arXiv","2026","compilable, contamination-aware vuln benchmark for LLM agents","Rust vuln corpus (record)","","benchmark + contamination controls",
    NONE_COOP,"none","task-wise metrics (record)","","critiques snippet-only binary-classification evals; Rust domain",GAP_STD,
    "MEDIUM","None","methodological ally for A1 leakage-audit framing")

row("Calibration Without Comprehension: Diagnosing Limits of Fine-Tuning LLMs for VD in Systems Software / CWE-Trace (Zibaeirad & Vieira, arXiv:2606.20502)",
    "arXiv","2026","calibration vs comprehension diagnosis of fine-tuned VD","834 manually curated Linux-kernel samples, 7 CWEs (record)","","framework + contamination/calibration analysis",
    NONE_COOP,"none","calibration + detection metrics (record)","","asks whether benchmark gains = security reasoning vs contamination",GAP_STD,
    "MEDIUM","None","supports our verdict-calibration/bias instrumentation (POS-06 vocabulary)")

row("White-Basilisk: A Hybrid Model for Code Vulnerability Detection (Lamprou et al., arXiv:2507.08540)",
    "arXiv","2025","efficient hybrid VD (anti-scale narrative)","","small hybrid model","model + evaluation",
    NONE_COOP,"none","F1/accuracy on standard benchmarks (record)","","",GAP_STD,"LOW","None",
    "small-model-efficiency context consistent with <4B constraint")

row("Evaluating LLaMA 3.2 for Software Vulnerability Detection (Goncalves et al., arXiv:2503.07770)",
    "arXiv","2025","VD evaluation of Llama-3.2 family","standard VD benchmarks (record)","Llama-3.2 (sub-4B)","evaluation study",
    NONE_COOP,"none","accuracy/F1 (record)","","",GAP_STD,"LOW","None",
    "baseline context for our llama-3.2-3B arm")

row("SVEN: Large Language Models for Code — Security Hardening and Adversarial Testing (He & Vechev, arXiv:2302.05319; DOI 10.1145/3576915.3623175; CCS 2023)",
    "ACM CCS","2023","controlled code generation (security hardening / adversarial testing) — SVEN-line origin",
    "~1.6k manually curated insecure/secure program pairs, 9 CWEs (per PrimeVul text; full text read 2026-09-30)",
    "CodeGen-2.7B (headline)","property-specific prefix vectors, no weight change; region-specialized losses (changed vs unchanged code)",
    "adversarial-testing arm degrades security deliberately","SVEN prefixes themselves","secure-code ratio; pass@k (functional correctness)",
    "secure ratio 59.1% -> 92.3% (hardening) / -> 36.8% (adversarial) on CodeGen-2.7B",
    "code-GENERATION side; not a verdict/analysis task; cooperative prompts",
    "vuln-detection verdicts; refusal/safety-state; untrusted context","HIGH (paired program-pair dataset ancestor)",
    "None — enabling work","cite as paired-dataset lineage + hardening/degradation vocabulary; PrimeVul cites SVEN as most accurate prior dataset")

row("Instruction Tuning for Secure Code Generation / SafeCoder (He et al., arXiv:2402.09497)",
    "arXiv","2024","instruction tuning to reduce vulns in generated code","SVEN-derived + benchmark data (record)","",
    "security-focused instruction tuning",NONE_COOP,"none","vulnerable-code ratio + functional (record)","","",
    "refusal/safety-state; untrusted context","MEDIUM","None","SVEN-line mitigation family citation")

row("Constrained Decoding for Secure Code Generation (Fu et al., arXiv:2405.00218)",
    "arXiv","2024","decoding-time security control for codegen","insecure-codegen benchmarks (record)","",
    "constrained/steered decoding (PrimeVul-group)",NONE_COOP,"the decoding control itself","vulnerable-code ratio (record)","","",
    "refusal/safety-state; verdict-level analysis","MEDIUM","None","decoding-side vocabulary neighbor of inference-time mediation")

row("SecCoder: Towards Generalizable and Robust Secure Code Generation (Zhang et al., arXiv:2410.01488)",
    "arXiv","2024","robust/generalizable secure codegen","","","training/eval for secure codegen robustness",
    NONE_COOP,"none","secure-code + functional metrics (record)","","robustness framing on codegen side",
    "refusal/safety-state; untrusted context","LOW-MED","None","robustness-framing citation on codegen side")

row("Rethinking the Evaluation of Secure Code Generation (Dai et al., arXiv:2503.15554)",
    "arXiv","2025","eval-validity critique of secure-codegen benchmarks","","","evaluation methodology analysis",
    NONE_COOP,"none","meta-evaluation","","argues current eval schemes leave validity concerns",
    "refusal/safety-state; untrusted context","MEDIUM","None","eval-validity ally for strict-metric stance (paired/VD-S)")

row("SafeGenBench: A Benchmark for Security Vulnerability Detection in LLM-Generated Code (Li et al., arXiv:2506.05692)",
    "arXiv","2025","benchmark of vulns in LLM-generated code incl. domain-specific data + eval method","","",
    "benchmark construction",NONE_COOP,"none","vulnerable-generation metrics (record)","","",GAP_STD,"LOW-MED","None","")

row("Does Teaming-Up LLMs Improve Secure Code Generation? Multi-LLMSecCodeEval (Sabir et al., arXiv:2603.22717)",
    "arXiv","2026","multi-LLM ensemble secure-codegen evaluation","","multi-LLM ensembles","ensemble evaluation framework",
    NONE_COOP,"none","secure-code metrics (record)","","",GAP_STD,"LOW","None","")

row("How Secure is Secure Code Generation? Adversarial Prompts Put LLM Defenses to the Test (Tessa et al., arXiv:2601.07084)",
    "arXiv","2026","robustness of secure-codegen DEFENSES under adversarial prompts","","models with vuln-aware SFT / prefix-tuning / prompt-opt defenses",
    "adversarial prompt evaluation of three defense families",
    "adversarial prompts crafted to defeat secure-codegen defenses","the codegen defenses under test",
    "defense failure rates under adversarial prompts (record)","","",
    "verdict-level vuln DETECTION/analysis; refusal or over-refusal measurement; paired vuln/patch protocol",
    "HIGH","HIGH — must cite + delta: they break codegen-side defenses under adversarial prompts; nothing on analysis-side safety-state/verdict corruption",
    "crossover framing: first to test ANALYSIS-side defences under untrusted context; keep 'to our knowledge (searched 2026-09-30)' hedge")

row("CoGate: Confidence-Gated Co-Decoding for Secure Code Generation (Hu et al., arXiv:2607.28529)",
    "arXiv","2026","small-expert gating/steering of target model for secure codegen","","target LM + small expert","confidence-gated co-decoding",
    NONE_COOP,"CoGate steering itself","secure-code metrics (record)","","",GAP_STD,"LOW-MED","None",
    "mechanism-adjacent to guard+backbone mediation vocabulary; cite in method positioning")

row("A Function-Level Vulnerability Score Measures Flag Rate More Than the Model: Protocol Effects on Paired Benchmarks (Cichon & Dmitruk, arXiv:2609.32890; 2026-09-26)",
    "arXiv","2026","meta-evaluation of PAIRED vuln/patch benchmark protocols (metric/extraction/budget effects)",
    "5 released pair benchmarks + pooled set; 68 models (61 open, 1.5B-36B)","7 frontier + 61 open models",
    "protocol-factor variation with model outputs held fixed; linear-probe analysis",
    "none (no attack arm)","none",
    "function-level F1; pair-level correctness; Spearman correlations; both-flag/both-cleared rates",
    "F1 tracks both-flag rate (Spearman +0.86), nearly unrelated to pair correctness (+0.16); extraction +/-0.001 median, budget +/-0.02 vs model/benchmark swing +/-0.16-0.18; 37/68 models' correct-vs-reversed diff within 95% CI of zero; verdicts driven by text common to both functions",
    "measurement-only: no attack condition, no defence, no safety-state/refusal axis",
    "attack/defence conditions; refusal/safety-state; mitigation design","HIGH",
    "HIGH — 4 days old; pre-empts naive 'paired protocol rigor' framing; its common-text-drives-verdicts finding rhymes with our advisory-channel mechanism (POS-06/07)",
    "adopt dual function-level + pair-level reporting + both-flag rates; cite to preempt protocol-artifact objection; use as mechanism-consistent external evidence")

row("LProtector: An LLM-driven Vulnerability Detection System (Sheng et al., arXiv:2411.06493)",
    "arXiv","2024","RAG pipeline for C/C++ vuln detection","BigVul/PrimeVul-line data (record)","GPT-4o","RAG segmentation pipeline",
    NONE_COOP,"none","detection metrics (record)","","",GAP_STD,"MEDIUM","None","strong-vuln-RAG system reference")

row("Retrieval-Augmented Few-Shot Prompting Versus Fine-Tuning for Code Vulnerability Detection (Trad & Chehab, arXiv:2512.04106)",
    "arXiv","2025","RAG few-shot vs fine-tuning comparison for VD","standard VD benchmarks (record)","","controlled comparison",
    NONE_COOP,"none","F1/accuracy comparison (record)","","effectiveness depends on in-context example quality",
    GAP_STD,"MEDIUM","None","supports caveats on KB/tfidf baselines (NEG tfidf retraction context)")

row("ParaVul: Parallel LLM and Retrieval-Augmented Framework for Smart Contract Vulnerability Detection (Huang et al., arXiv:2510.17919)",
    "arXiv","2025","parallel LLM+RAG for smart-contract VD","smart contracts","",
    "parallel LLM + RAG",NONE_COOP,"none","detection metrics (record)","","smart-contract domain",GAP_STD,"LOW","None","")

row("RESCUE: Retrieval Augmented Secure Code Generation (Shi & Zhang, arXiv:2510.18204)",
    "arXiv","2025","RAG for secure code GENERATION (defense side)","","","retrieval-augmented generation with security knowledge",
    NONE_COOP,"RESCUE itself","vulnerable-code ratio (record)","","codegen side",GAP_STD,"LOW-MED","None",
    "RAG x secure-codegen bridge citation")

row("RAVEN: Agentic RAG for Automated Vulnerability Repair (Gadey et al., arXiv:2606.22647)",
    "arXiv","2026","agentic RAG for vulnerability REPAIR","","","agentic RAG pipeline",NONE_COOP,"none","repair metrics (record)","","",
    GAP_STD,"LOW-MED","None","repair-side agentic RAG citation")

row("Argus: Reorchestrating Static Analysis via a Multi-Agent Ensemble for Full-Chain Security Vulnerability Detection (Liang et al., arXiv:2604.06633)",
    "arXiv","2026","multi-agent SAST reorchestration for full-chain detection","repo-level code","",
    "multi-agent orchestration over SAST stages",NONE_COOP,"none","detection metrics (record)","","",
    "adversarial/untrusted context; refusal/safety-state","MEDIUM","None","modern agent baseline candidate (gate E)")

row("AgenticSCR: An Autonomous Agentic Secure Code Review for Immature Vulnerabilities Detection (Charoenwet et al., arXiv:2601.19138)",
    "arXiv","2026","agentic secure code review at pre-integration","code-review diffs","",
    "agentic review workflow",NONE_COOP,"none","review metrics (record)","","",GAP_STD,"LOW-MED","None","")

row("Revelio: Cost-Efficient Agentic Memory Safety Vulnerability Detection for Repository-Scale Codebases (Hou et al., arXiv:2606.22263)",
    "arXiv","2026","agentic memory-safety detection at repo scale","repo-scale C codebases","","agentic detection with cost controls",
    NONE_COOP,"none","detection metrics (record)","","motivated by LLM unreliability/hallucination",
    "adversarial/untrusted context; refusal/safety-state","MEDIUM","None","2026 agentic line; cost-efficiency framing")

row("Multi-Agent End-to-End Vulnerability Management for Mitigating Recurring Vulnerabilities (Zheng et al., arXiv:2601.17762)",
    "arXiv","2026","multi-agent vulnerability-management lifecycle","","","multi-agent VM system",NONE_COOP,"none",
    "management metrics (record)","","ops-side",GAP_STD,"LOW","None","")

row("AgenticRepair: Multi-Faceted Program Context Engineering for Agentic Vulnerability Repair (Fu et al., arXiv:2607.29422)",
    "arXiv","2026","agentic vulnerability repair via context engineering","","","context-engineered agentic repair",
    NONE_COOP,"none","repair metrics (record)","","",GAP_STD,"LOW-MED","None","")

row("Knowledge-Enhanced Agentic Vulnerability Repair (Cao et al., arXiv:2607.00820)",
    "arXiv","2026","knowledge-enhanced agentic AVR with root-cause identification","","","knowledge-enhanced multi-step repair agents",
    NONE_COOP,"none","repair metrics (record)","","",GAP_STD,"LOW-MED","None","")

row("BASIS: Breach-Aware Selective Prompt Injection Shielding with Prefill Attention Probes (Qin et al., arXiv:2608.08027)",
    "arXiv","2026","selective prompt-injection shielding (detect-and-continue vs blanket refuse)","LLM app contexts","",
    "prefill attention probes for breach-aware selective shielding",
    "prompt-injection payloads in external data","BASIS shield itself","shielding vs over-refusal trade-off (record)","","",
    "code-analysis verdicts; paired vuln/patch protocol; vuln-task utility restoration",
    "MEDIUM","MEDIUM — same selective-vs-blanket-refusal stance as D1, different domain",
    "cite as cross-domain ally for 'do not blanket-refuse' defence stance")

row("Please refuse to answer me! Mitigating Over-Refusal in LLMs via Adaptive Contrastive Decoding (Qi et al., arXiv:2604.17132)",
    "arXiv","2026","over-refusal mitigation for chat-safety alignment","chat safety benchmarks (XSTest-style)","","adaptive contrastive decoding",
    NONE_COOP,"contrastive decoding intervention","refusal ratios (record)","","",
    "code/security-analysis tasks: no over-refusal measurement on VD found in this session's searches",
    "MEDIUM (absence evidence)","LOW","documents that over-refusal mitigation remains chat-domain (as of 2026-09-30 search) — supports hedged gap statement")

row("LLM Safeguard is a Double-Edged Sword: Exploiting False Positives for Denial-of-Service Attacks / Safeguard-DoS (Zhang et al., arXiv:2410.02916)",
    "arXiv","2024","weaponizing guard FALSE POSITIVES to DoS benign users","adversarial prompt suites","Llama Guard 3",
    "~30-char adversarial prompts / server-side fine-tuning to force guard false positives",
    "adversarial prompts targeting the GUARD","the guard under attack","universal benign-blocking rate",
    ">97% universal blocking on Llama Guard 3 (white-box; per prior-session verification docs/literature_review.md s2)",
    "chat-safety guardrails; not code-analysis verdicts; no paired vuln/patch protocol",
    "vuln-analysis verdicts; defence-induced error measurement on a real detection task","MEDIUM",
    "MEDIUM — availability-side attack ON the guardrail; motivates our P3 flip-rate / clean-utility (gate D) measurement",
    "cite in motivation: guard FP cost must be measured, exactly our defence-induced-error-rate headline")

todo = [r for r in R if aid(r[0]) not in have]
skipped = [aid(r[0]) for r in R if aid(r[0]) in have]
buf = io.StringIO()
w = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
for r in todo:
    assert len(r) == 16, (r[0][:40], len(r))
    w.writerow(r)
with open(PATH, "a", encoding="utf-8") as f:
    f.write(buf.getvalue())
print(f"existing={len(existing)} appended={len(todo)} skipped_dups={skipped}")
