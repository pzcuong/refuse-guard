# PackGuard Literature Verification (Round 8, W1)

Date: 2026-09-21. Method: every user-proposed citation checked against the arXiv API
(`export.arxiv.org`) and cross-checked with web sources (USENIX/ACM DL pages) for venue.
Verified-only references go to `docs/packguard_refs.bib`. Verdicts below are
traceable to the arXiv IDs / DOIs listed; nothing is cited from memory alone.

## 1. Verification table

| # | User cite | Verdict | Actual record | Notes |
|---|-----------|---------|---------------|-------|
| 1 | MALGUARD (2025) | VERIFIED (venue per web, arXiv confirmed) | MalGuard: Towards Real-Time, Accurate, and Actionable Detection of Malicious Packages in PyPI Ecosystem — Gao, Sun, Cao, Huang, Wu — arXiv:2506.14466 (Jun 2025); web sources report acceptance at USENIX Security 2025 | PyPI-only, non-LLM static analysis; relevant as ecosystem-specific detector baseline context |
| 2 | DONAPI (2024) | VERIFIED | DONAPI: Malicious NPM Packages Detector using Behavior Sequence Knowledge Mapping — Huang, Wang, Wang, Sun, Li (+5) — arXiv:2403.08334, accepted USENIX Security 2024 | npm-only; static+dynamic, API behavior sequences — closest methodological neighbor to our behavior graphs |
| 3 | Cerebro (TOSEM 2024) | VERIFIED | Killing Two Birds with One Stone: Malicious Package Detection in NPM and PyPI using a Single Model (Cerebro) — Zhang, Huang, Huang, Chen, Wang et al. — arXiv:2309.02637; TOSEM 2024, DOI 10.1145/3705304 | Cross-ecosystem (npm+PyPI) but CENTRALIZED single model; directly relevant to our cross-language claim |
| 4 | VulFL (2023–24) | VERIFIED (as arXiv preprint; venue unverified) | An Empirical Study of Vulnerability Detection using Federated Learning (VulFL) — Zhou, Hu, Quan, Peng, Xie et al. — arXiv:2411.16099 (Nov 2024), no journal ref on arXiv | Task = vulnerability detection (not malicious packages); use for FL-for-security framing only |
| 5 | SecurityAI (2024) | VERIFIED (name = workflow, not paper title) | Shifting the Lens: Detecting Malicious npm Packages using Large Language Models — Zahan, Burckhardt, Lysenko et al. (Snyk) — arXiv:2408.08924 (Aug 2024); "SecurityAI" is their benchmark/workflow name (5,115 npm packages) | LLM-as-detector (GPT-3.5/4) for npm; API-dependent, not local — different threat model from ours |
| 6 | Ladisa ACSAC 2023 | VERIFIED PAPER, WRONG VENUE | SoK: Taxonomy of Attacks on Open-Source Software Supply Chains — Ladisa, Plate, Martinez, Barais — arXiv:2204.04008; journal ref: **IEEE S&P 2023**, pp. 1509–1526 (not ACSAC) | ACSAC 2023 hosted a different supply-chain-attack comparison paper; if the ACSAC venue is required, cite the S&P paper instead |

## 2. Additional verified references used by the data section

- Ohm, Plate, Sykosch, Meier — *Backstabber's Knife Collection* (BKC), DIMVA 2020,
  arXiv:2005.09561. Dataset paper for OSS supply-chain attack samples; cited as the
  curated-dataset alternative we did NOT use at scale (Zenodo payload too large for the
  pilot time-box; the DataDog wild-capture dataset covers npm+PyPI natively).
- Duan et al. — *Towards Measuring Supply Chain Attacks on Package Managers for
  Interpreted Languages* (MalOSS), IMC 2021 (arXiv:2002.01139). Cited as early
  npm/PyPI malicious-package collection; original MalOSS repo was unreachable at the
  probed URL (404) — dataset role superseded by DataDog 2024+.
- MeMPtec (Halder et al.), ASE 2024 — metadata-based malicious npm/PyPI detection;
  cited as non-code-signal contrast class.
- DataDog Security Labs — *malicious-software-packages-dataset* (software/artifact,
  GitHub, accessed 2026-09-21). The actual data source of this project; license and
  checksums recorded in the dataset manifest.

## 3. Novelty verdict for the merged paper

Claim A: **"first to measure safety-layer interference (refusal/verdict corruption) in
malicious-package detection."**
- Checked the six citations above + web search for LLM-safety interactions in this
  domain. Zahan et al. (SecurityAI, 2024) measure LLM *detection accuracy* on npm
  malware, not refusal/defence interference; DONAPI/Cerebro/MalGuard are non-LLM.
- Verdict: **defensible, hedged** — phrase as "to our knowledge, the first systematic
  measurement of safety-blocking, context-corruption and defence-harm in LLM-assisted
  malicious-package analysis". No paper found that measures it; the claim's weakness is
  search exhaustiveness, not a known duplicate.

Claim B: **"first FL over ecosystem-partitioned clients for malicious-package
detection."**
- FL exists for vulnerability detection (VulFL, arXiv:2411.16099) — different task.
- Cerebro (TOSEM 2024) is cross-ecosystem but centralized; no federated variant found
  in arXiv searches ("federated learning malicious package detection npm PyPI").
- Verdict: **defensible, hedged** — phrase as "to our knowledge, the first federated
  simulation with ecosystem-partitioned clients (npm-only / PyPI-only / mixed) for
  malicious-package detection", and explicitly credit VulFL for FL-for-security
  precedent in vulnerability detection.

## 4. Sources

- arXiv API records: 2506.14466, 2403.08334, 2309.02637 (+DOI 10.1145/3705304),
  2411.16099, 2408.08924, 2204.04008 (retrieved 2026-09-21 via export.arxiv.org).
- Web: USENIX Security 2024/2025 program pages (DONAPI, MalGuard), ACM DL TOSEM entry
  for Cerebro, Snyk blog for SecurityAI authorship.
- Verified sources: https://arxiv.org/abs/2506.14466 (MalGuard),
  https://arxiv.org/abs/2403.08334 (DONAPI), https://arxiv.org/abs/2309.02637 (Cerebro),
  https://arxiv.org/abs/2411.16099 (VulFL), https://arxiv.org/abs/2408.08924 (SecurityAI),
  https://arxiv.org/abs/2204.04008 (Ladisa SoK).
