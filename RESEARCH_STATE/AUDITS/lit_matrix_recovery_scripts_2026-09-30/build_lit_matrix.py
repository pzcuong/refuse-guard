import csv, os

PATH = "/Users/macbook/.zcode/workspace/default/refuseguard/RESEARCH_STATE/LITERATURE_MATRIX.csv"
HEADER = ["row_id","topic_area","title","authors","year","venue","arxiv_id","doi",
          "verified_via","what_it_shows","relation_to_program","overlap",
          "gap_remaining","novelty_risk","added_date","prior_doc_ref"]
D = "2026-09-30"
AR = "arXiv MCP search_papers (session 2026-09-30)"

rows = [
["LM-01","primevul-line|paired|fpr-constrained",
 "Vulnerability Detection with Code Language Models: How Far Are We? (PrimeVul)",
 "Ding, Fu, Ibrahim, Sitawarin, Chen, Alomair, Wagner, Ray, Chen","2024 (v2)","ICSE 2025","2403.18624","",
 "arXiv MCP get_abstract + download_paper(2403.18624v2) full text read this session; venue ICSE 2025 per docs/literature_review.md section 0 (verified prior session)",
 "6,968 vuln / 228,800 benign C functions, 140 CWEs, chronological split; 7B SOTA 68.26 F1 on BigVul vs 3.09 F1 on PrimeVul; introduces VD-S (\"measures the false negative rate, after the detector has been tuned to ensure the false positive rate is below a fixed threshold (e.g., 0.5%)\") and pair-wise eval vs benign fixed counterpart",
 "Substrate of paper 1 (official splits + paired eval adopted); defines the FPR-constrained metric vocabulary this program should report in","HIGH",
 "Cooperative setting only; no safety-state/untrusted-context manipulation; PA problem still unsolved","LOW",D,
 "docs/literature_review.md s1; docs/eda_primevul.md"],

["LM-02","primevul-line","DiverseVul: A New Vulnerable Source Code Dataset for Deep Learning Based Vulnerability Detection",
 "Chen, Ding, Alowain, +2","2023","ACSAC 2023","2304.00409","10.1145/3607199.3607242",
 "OpenAlex via academic-research search_papers (cited_by 227; arXiv:2304.00409 record)",
 "Large crawled vulnerable-code dataset; ancestor of the PrimeVul-line quality/de-dup discussion",
 "Dataset lineage only (pre-2024 window; included as PrimeVul-line ancestor)","MEDIUM",
 "Superseded by PrimeVul for our purposes","LOW",D,"none"],

["LM-03","primevul-line","VulDetectBench: Evaluating the Deep Capability of Vulnerability Detection with Large Language Models",
 "Liu, Gao, Yang, Xie, Chen, Zhang, Chen","2024","arXiv v4","2406.07595","",
 AR,"Multi-task eval ladder (detection + deeper capabilities) for LLM vuln detection",
 "Alternative eval vocabulary; cooperative only","MEDIUM","No safety-state or untrusted-context axis","LOW",D,"none"],

["LM-04","primevul-line","LLM4Vuln: A Unified Evaluation Framework for Decoupling and Enhancing LLMs' Vulnerability Reasoning",
 "Sun, Wu, Xue, Liu, Ma, Zhang, Liu, Li","2024","arXiv v4","2401.16185","",
 "arXiv search hit; authors/venue fixed in docs/literature_review.md s1 (prior session)",
 "Decouples knowledge / reasoning / prompt-format factors in LLM vuln reasoning",
 "Protocol reference for E0 prompt-controlled arm design","MEDIUM","Cooperative only","LOW",D,
 "docs/literature_review.md s1"],

["LM-05","primevul-line","SecLLMHolmes: LLMs Cannot Reliably Identify and Reason About Security Vulnerabilities (Yet?)",
 "Ullah, Han, Pujar, Pearce, Coskun, Stringhini","2023 (v3)","arXiv","2312.12575","",
 "arXiv search abs:\"SecLLMHolmes\"","Automated eval framework; LLMs unreliable at security-bug identification; dataset-purity concerns",
 "Corroborates strict/paired evaluation necessity","MEDIUM","","LOW",D,"none"],

["LM-06","primevul-line|agents","Benchmarking LLMs and LLM-based Agents in Practical Vulnerability Detection for Code Repositories (JITVul)",
 "Yildiz, Teo, Lou, Feng, Wang, Divakaran","2025","ACL 2025 Long (2025.acl-long.1490, pp.30848-30865)","2503.03586","",
 "WebFetch https://aclanthology.org/2025.acl-long.1490/ this session + arXiv search",
 "879-CVE benchmark linking vuln-introducing/fixing commits; ReAct agents with interprocedural context beat plain LLMs at distinguishing vulnerable vs benign, but both inconsistent",
 "The agents-line anchor named in prior docs; defines modern agent baseline class (gate E)","HIGH",
 "Cooperative context only; no adversarial/untrusted context, no refusal-state measurement","MEDIUM",D,
 "docs/literature_review.md s1 (listed as aclanthology 2025.acl-long.1490; identity to arXiv:2503.03586 confirmed this session)"],

["LM-07","primevul-line","Beyond Single Bugs: Benchmarking Large Language Models for Multi-Vulnerability Detection",
 "Pushkar, Kabra, Kumar, Challa","2025","arXiv","2512.22306","",AR,
 "Critiques single-vuln-per-sample benchmarks; multi-vulnerability benchmark",
 "Extends the realism axis orthogonal to our threat model","LOW-MED","","LOW",D,"none"],

["LM-08","primevul-line","Everything You Wanted to Know About LLM-based Vulnerability Detection But Were Afraid to Ask",
 "Li, Li, Wu, Xu, Zhang, Cheng, Xu, Zhong","2025","arXiv","2504.13474","",AR,
 "Meta-study: current evals leave open whether LLMs detect real-world vulnerabilities",
 "Supports strict-setting framing","MEDIUM","","LOW",D,"none"],

["LM-09","primevul-line","LLM-based Vulnerability Detection at Project Scale: An Empirical Study",
 "Li, Jiang, Chen, Xiong","2026","arXiv","2601.19239","",AR,
 "Empirical study of project-scale LLM detectors; practical effectiveness and failure causes",
 "Scaling/limitation evidence","LOW-MED","","LOW",D,"none"],

["LM-10","primevul-line","Evaluating LLMs for Real-World Web Vulnerability Detection",
 "Neef, Jungnickel, Buchholz, Spence, Birke Gonzalez","2026","arXiv","2606.21397","",AR,
 "Six frontier + open models on web-specific vulnerabilities",
 "2026 frontier snapshot; outside our <4B scope","LOW","Different domain (web), frontier-only","LOW",D,"none"],

["LM-11","primevul-line|agents","RustMizan: A Compilable, Contamination-Aware Benchmarking Framework for Rust Vulnerabilities",
 "Elsayed, Yang, Koh, +11","2026","arXiv","2607.04729","",AR,
 "Compilable, contamination-aware Rust benchmark aimed at LLM agents doing vulnerability analysis; critiques snippet-only binary classification",
 "Contamination/compilability controls align with A1 leakage-audit concerns","MEDIUM",
 "No safety-state manipulation","LOW",D,"none"],

["LM-12","primevul-line|fpr-constrained","Calibration Without Comprehension: Diagnosing the Limits of Fine-Tuning LLMs for Vulnerability Detection in Systems Software (CWE-Trace)",
 "Zibaeirad, Vieira","2026","arXiv","2606.20502","",AR,
 "834 manually curated Linux-kernel samples, 7 CWEs; asks whether benchmark gains reflect security reasoning vs contamination; calibration diagnosis",
 "Supports our verdict-calibration/bias instrumentation (POS-06 vocabulary)","MEDIUM",
 "No safety-state axis","LOW",D,"none"],

["LM-13","primevul-line","White-Basilisk: A Hybrid Model for Code Vulnerability Detection",
 "Lamprou, Shevtsov, Arapakis, Ioannidis","2025","arXiv v5","2507.08540","",AR,
 "Efficient hybrid detector; challenges the scale narrative in VD",
 "Small-model-efficiency context consistent with <4B constraint","LOW","","LOW",D,"none"],

["LM-14","primevul-line","Evaluating LLaMA 3.2 for Software Vulnerability Detection",
 "Goncalves, Silva, Cabral, Dias, Maia, Praca, Severino, Lino Ferreira","2025","arXiv","2503.07770","",AR,
 "Evaluates Llama-3.2 family for vulnerability detection",
 "Direct baseline context for our llama-3.2-3B arm","LOW","","LOW",D,"none"],

["LM-15","sven|paired","Large Language Models for Code: Security Hardening and Adversarial Testing (SVEN)",
 "He, Vechev","2023","ACM CCS 2023","2302.05319","10.1145/3576915.3623175",
 "arXiv download_paper(2302.05319v5) full text read this session (SVEN prefixes; CodeGen-2.7B secure-code ratio 59.1%->92.3% hardening / ->36.8% adversarial; ~1.6k manually curated program pairs); DOI via OpenAlex this session",
 "Origin of the SVEN line; ALSO a paired-dataset ancestor (insecure/secure program pairs; PrimeVul cites it as most accurate prior dataset, 9 CWEs / 1.6k samples)",
 "SVEN-line anchor; its program-pair (insecure/secure) dataset is the paired-protocol ancestor paper 1 builds on; hardening/degradation control vocabulary",
 "HIGH","Code-generation-side control; not an analysis task; no safety-state/over-refusal measurement","LOW",D,
 "docs/literature_review.md s1 (PrimeVul cites SVEN as most accurate prior dataset; SVEN itself not previously in project docs)"],

["LM-16","sven","Instruction Tuning for Secure Code Generation (SafeCoder)",
 "He, Vero, Krasnopolska, Vechev","2024","arXiv v2","2402.09497","",
 "arXiv search ti:\"secure code generation\"","Instruction tuning to reduce vulnerabilities in generated code while preserving functionality",
 "SVEN-line mitigation family","MEDIUM","","LOW",D,"none"],

["LM-17","sven","Constrained Decoding for Secure Code Generation",
 "Fu, Baker, Ding, Chen","2024","arXiv v3","2405.00218","",
 "arXiv search ti:\"secure code generation\"","Decoding-time security control (from the PrimeVul group)",
 "Decoding-side vocabulary neighbor of our inference-time mediation","MEDIUM","","LOW",D,"none"],

["LM-18","sven","SecCoder: Towards Generalizable and Robust Secure Code Generation",
 "Zhang, Du, Tong, Zhang, Chow, Cheng, Wang, Yin","2024","arXiv","2410.01488","",
 "arXiv search ti:\"secure code generation\"","Generalization/robustness of secure code generation",
 "Robustness framing on the codegen side","LOW-MED","","LOW",D,"none"],

["LM-19","sven|fpr-constrained","Rethinking the Evaluation of Secure Code Generation",
 "Dai, Xu, Tao","2025","arXiv v2","2503.15554","",
 "arXiv search ti:\"secure code generation\"","Argues current secure-codegen evaluation schemes leave validity concerns",
 "Eval-validity ally for our strict-metric stance","MEDIUM","","LOW",D,"none"],

["LM-20","sven","SafeGenBench: A Benchmark Framework for Security Vulnerability Detection in LLM-Generated Code",
 "Li, Ding, Peng, Zhao, Gao, Gao, Gu","2025","arXiv v3","2506.05692","",
 "arXiv search ti:\"vulnerability detection\"+LLM","Benchmark for security vulnerabilities in LLM-generated code incl. domain-specific data and evaluation",
 "SVEN-line 2025 eval extension","LOW-MED","","LOW",D,"none"],

["LM-21","sven","Does Teaming-Up LLMs Improve Secure Code Generation? A Comprehensive Evaluation with Multi-LLMSecCodeEval",
 "Sabir, Liu, Jang, Abuadbba, Gao, Moore, Kim, Kim, Nepal","2026","arXiv","2603.22717","",
 "arXiv search abs:\"DiverseVul\" OR abs:\"SecLLMHolmes\" (surfaced)","Evaluates multi-LLM ensembles/collaboration for secure code generation",
 "2026 ensemble line","LOW","","LOW",D,"none"],

["LM-22","sven|refusal-adjacent","How Secure is Secure Code Generation? Adversarial Prompts Put LLM Defenses to the Test",
 "Tessa, Olatunji, War, Klein, Bissyande","2026","arXiv","2601.07084","",
 "arXiv search abs:\"SVEN\" AND abs:\"secure code\"","Shows secure-codegen defenses (vulnerability-aware fine-tuning, prefix-tuning, prompt optimization) break under adversarial prompts",
 "CLOSEST analog to 'security defenses break under adversarial input'; generation-side, not analysis-side","HIGH",
 "Codegen not verdict analysis; no refusal/over-refusal measurement on analysis tasks","HIGH",D,"none"],

["LM-23","sven|refusal-adjacent","CoGate: Confidence-Gated Co-Decoding for Secure Code Generation",
 "Hu, Luo, Roush, Howard","2026","arXiv","2607.28529","",AR,
 "Small expert model gates/steers the target model at decode time for security",
 "Mechanism-adjacent to guard+backbone mediation vocabulary","LOW-MED",
 "Decode-time codegen, not verdict-level analysis","LOW",D,"none"],

["LM-24","paired|fpr-constrained","A Function-Level Vulnerability Score Measures Flag Rate More Than the Model: Protocol Effects on Paired Benchmarks",
 "Cichon, Dmitruk","2026","arXiv","2609.32890","",
 "arXiv MCP get_abstract(2609.32890) this session (published 2026-09-26)",
 "Function-level F1 tracks how often a model flags both functions of a pair (Spearman +0.86), nearly unrelated to pair-level correctness (+0.16); metric/verdict-extraction/budget choices swing numbers; 68 models (61 open, 1.5B-36B) on 5 released pair benchmarks; verdicts determined by text common to both functions",
 "DIRECT: constrains + validates our paired-protocol reporting (paper1 pairwise eval; R-A paired design); its 'common text drives verdicts' finding resonates with our advisory-channel/verdict-bias mechanism (POS-06/POS-07)","HIGH",
 "No safety-state/refusal/defense arm; no attack condition; measurement-only","HIGH",D,"none"],

["LM-25","vuln-rag|paired","Vul-RAG: Enhancing LLM-based Vulnerability Detection via Knowledge-level RAG",
 "Du, Zheng, Wang, Zou, Wang, Deng, Feng, Liu, Chen, Peng, Ma, Lou","2024","arXiv v3","2406.11147","",
 "arXiv search ti:\"Vul-RAG\"; abstract quotes 0.06-0.14 accuracy distinguishing vulnerable vs similar-but-benign patched code",
 "The strong-vuln-RAG anchor: KB of vulnerability root causes for LLM detection",
 "HIGH (nearest neighbor of our KB line: POS-14 KB buildable at 3B, POS-05 query-relevance/anti-leakage)","HIGH",
 "Cooperative RAG for utility; never treats KB/retrieved text as an untrusted channel; no refusal-state measurement","MEDIUM",D,"none"],

["LM-26","vuln-rag","Revisiting Vul-RAG: Reproducibility and Replicability of RAG-based Vulnerability Detection with Open-Weight Models",
 "Kaniewski, Schmidt, Heer","2026","arXiv","2606.04739","",AR,
 "Reproduces/replicates Vul-RAG with open-weight models",
 "Consolidates open-weight RAG-based VD; adjacent to our open-model KB claims","HIGH",
 "Still utility-focused; no adversarial/untrusted-KB angle","MEDIUM",D,"none"],

["LM-27","vuln-rag","LProtector: An LLM-driven Vulnerability Detection System",
 "Sheng, Wu, Zuo, Li, Qiao, Hang","2024","arXiv v2","2411.06493","",
 "arXiv search abs:retrieval+ti:vulnerability","GPT-4o + RAG pipeline for C/C++ vulnerability detection",
 "RAG-VD system reference","MEDIUM","","LOW",D,"none"],

["LM-28","vuln-rag","Retrieval-Augmented Few-Shot Prompting Versus Fine-Tuning for Code Vulnerability Detection",
 "Trad, Chehab","2025","arXiv","2512.04106","",AR,
 "Compares RAG few-shot prompting vs fine-tuning; effectiveness depends on in-context example quality",
 "Evidence supporting caveats on KB/tfidf baselines (our tfidf-degradation retraction context)","MEDIUM","","LOW",D,"none"],

["LM-29","vuln-rag","ParaVul: A Parallel Large Language Model and Retrieval-Augmented Framework for Smart Contract Vulnerability Detection",
 "Huang, Wen, Kang, +7","2025","arXiv","2510.17919","",AR,
 "Parallel LLM + RAG for smart-contract vulnerability detection",
 "RAG-VD in a different domain","LOW","","LOW",D,"none"],

["LM-30","vuln-rag|sven","RESCUE: Retrieval Augmented Secure Code Generation",
 "Shi, Zhang","2025","arXiv v2","2510.18204","",
 "arXiv search ti:\"secure code generation\"","RAG injects external security knowledge to make generated code secure",
 "RAG x secure-codegen bridge","LOW-MED","","LOW",D,"none"],

["LM-31","vuln-rag|agents","RAVEN: Agentic RAG for Automated Vulnerability Repair",
 "Gadey, Liu, Dmitrienko","2026","arXiv","2606.22647","",AR,
 "Agentic RAG for automated vulnerability repair",
 "Repair-side agentic RAG","LOW-MED","","LOW",D,"none"],

["LM-32","agents","VulAgent: Hypothesis-Validation based Multi-Agent Vulnerability Detection",
 "Wang, Li, Li, Zhu, Jin","2025","arXiv","2509.11523","",
 "arXiv search abs:false-positive+LLM-VD query","Multi-agent localization + hypothesis validation for project-level VD",
 "Modern agent baseline candidate (gate E)","MEDIUM","Cooperative context only","MEDIUM",D,"none"],

["LM-33","agents","MAVUL: Multi-Agent Vulnerability Detection via Contextual Reasoning and Interactive Refinement",
 "Li, Joshi, Wang, Wong","2025","arXiv","2510.00317","",
 "arXiv search (agentic/multi-agent + vulnerability)","Multi-agent VD with contextual reasoning and interactive refinement",
 "Modern agent baseline candidate (gate E)","MEDIUM","Cooperative context only","MEDIUM",D,"none"],

["LM-34","agents","MultiVer: Zero-Shot Multi-Agent Vulnerability Detection",
 "Rajan","2026","arXiv","2602.17875","",
 "arXiv search (agentic/multi-agent + vulnerability)","Four-agent ensemble with union voting; 82.7% recall on PyVul without fine-tuning",
 "Zero-shot agent baseline","LOW-MED","","LOW",D,"none"],

["LM-35","agents","Argus: Reorchestrating Static Analysis via a Multi-Agent Ensemble for Full-Chain Security Vulnerability Detection",
 "Liang, Xie, He, +7","2026","arXiv","2604.06633","",
 "arXiv search abs:false-positive query","Multi-agent reorchestration of SAST for full-chain vulnerability detection",
 "Strongest 2026 agent-SAST line","MEDIUM","","MEDIUM",D,"none"],

["LM-36","agents","AgenticSCR: An Autonomous Agentic Secure Code Review for Immature Vulnerabilities Detection",
 "Charoenwet, Tantithamthavorn, Thongtanunam, Lin, Jeong, Wu","2026","arXiv v2","2601.19138","",
 "arXiv search (agentic/multi-agent + vulnerability)","Agentic secure code review at pre-integration",
 "Review-workflow agent line","LOW-MED","","LOW",D,"none"],

["LM-37","agents","Revelio: Cost-Efficient Agentic Memory Safety Vulnerability Detection For Repository-Scale Codebases",
 "Hou, Wang, Lyu, Momeu, Nguyen, Yang, Sen, Song, Wagner","2026","arXiv","2606.22263","",
 "arXiv search ti:vulnerability+LLM benchmark query","Agentic memory-safety detection at repository scale; motivates by LLM unreliability/hallucination",
 "2026 agentic + cost-efficiency line; also shows agent-memory design surface","MEDIUM","","LOW",D,"none"],

["LM-38","agents","CLEAR: Causal Context-Based Agentic Reasoning for Vulnerability Detection",
 "Yun, Hwang, Lee, Kang, Park","2026","arXiv","2608.03134","",
 "arXiv search (2 independent queries)","Causal-dependency agentic reasoning for source-code VD",
 "Agent reasoning line","MEDIUM","","LOW",D,"none"],

["LM-39","agents","Multi-Agent End-to-End Vulnerability Management for Mitigating Recurring Vulnerabilities",
 "Zheng, Zhou, Hu, Gao, Pan","2026","arXiv","2601.17762","",
 "arXiv search (2 independent queries)","Multi-agent vulnerability-management lifecycle",
 "Ops-side agent line","LOW","","LOW",D,"none"],

["LM-40","agents|vuln-rag","AgenticRepair: Multi-Faceted Program Context Engineering for Agentic Vulnerability Repair",
 "Fu, Mei, Thongtanunam, Tantithamthavorn","2026","arXiv","2607.29422","",
 "arXiv search (agentic/multi-agent + vulnerability)","Agentic vulnerability repair with rich program-context engineering",
 "Repair-side context engineering","LOW-MED","","LOW",D,"none"],

["LM-41","agents|vuln-rag","Knowledge-Enhanced Agentic Vulnerability Repair",
 "Cao, Ma, Yu, Ding, Liu, Zhuo, Wang, Lin, Sun, Wang, Lo","2026","arXiv","2607.00820","",
 "arXiv search abs:retrieval+ti:vulnerability","Knowledge-enhanced agentic repair with root-cause identification",
 "Repair-side knowledge + agents","LOW-MED","","LOW",D,"none"],

["LM-42","agents|refusal-adjacent","BASIS: Breach-Aware Selective Prompt Injection Shielding with Prefill Attention Probes",
 "Qin, Zhu, Gao, Zhou","2026","arXiv","2608.08027","",
 "arXiv search abs:\"over-refusal\" AND (code OR security), 2025+","Selective shielding: detect injection and continue, instead of blanket refusing",
 "Adjacent to D1: selective-response vs blanket-refusal stance in code/injection contexts","MEDIUM",
 "Generic prompt-injection domain, not code-analysis verdicts; no safety-state measurement on VD","MEDIUM",D,"none"],

["LM-43","refusal-adjacent","Please refuse to answer me! Mitigating Over-Refusal in Large Language Models via Adaptive Contrastive Decoding",
 "Qi, Lyu, Cui, Bai, Xia","2026","arXiv","2604.17132","",
 "arXiv search abs:\"over-refusal\" AND (code OR security), 2025+","Generic-chat over-refusal mitigation balancing refuse-harmful vs refuse-benign",
 "Documents that over-refusal mitigation remains chat-domain in this session's search (supports hedged 'to our knowledge' gap statement of docs/literature_review.md s2)","MEDIUM",
 "Nothing found applying over-refusal measurement to code-security/VD tasks in this session's searches","LOW",D,"none"],

["LM-44","refusal-adjacent|fpr-constrained","LLM Safeguard is a Double-Edged Sword: Exploiting False Positives for Denial-of-Service Attacks (Safeguard-DoS)",
 "Zhang, Xiong, Mao","2024","arXiv","2410.02916","",
 "docs/literature_review.md s2 (arXiv abstract page verified 2026-09-20 prior session; not re-fetched this session)",
 "~30-char adversarial prompts or server-side fine-tuning make a guard block benign requests (universal blocking >97% on Llama Guard 3, white-box)",
 "Availability-side attack ON the guardrail; motivates measuring our defence's own utility cost (P3 flip-rate ledger; gate D clean-utility)","MEDIUM",
 "Chat-safety guardrails, not code-analysis verdicts; no paired vuln/patch protocol","MEDIUM",D,
 "docs/literature_review.md s2"],
]

exists = os.path.exists(PATH)
with open(PATH, "a" if exists else "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
    if not exists:
        w.writerow(HEADER)
    for r in rows:
        assert len(r) == len(HEADER), (r[0], len(r))
        w.writerow(r)
print("appended" if exists else "created", len(rows), "rows ->", PATH)
