"""EVIDA — Evidence-grounded Invariant Verdict Analysis (round-17 pilot).

Implementation of the FROZEN pre-registration
`RESEARCH_STATE/PREREGISTRATIONS/prereg_EVIDA_..._.md` (freeze 2026-09-30,
git HEAD fb8988ad1ae9ef486856636c6c71129c54672e00).

Modules:
  evida_strip        D1 comment/docstring stripping extended to C/C++ bench
                     fragments (same removal + canonical-signature gate; the
                     strict clean-parse requirement is impossible on PrimeVul
                     function fragments — see module docstring).
  evida_units        Paired-unit manifest builders for S1 (RQ8) and S2
                     (PackGuard defense set), with cache asserts (fail loudly).
  evida_checkers     The 4 registered code-evidence checkers (CWE-190/200/416/
                     476) + synthetic inject-and-perturb validation.
  evida_adjudicator  Counterfactual disagreement alarm -> claim adjudication ->
                     CodeBERT fallback (tau .5481) -> verify-or-abstain.
  evida_endpoints    CRR / DIER / alarm precision / UAC + prereg §1.11 gates,
                     §1.12 falsifiers, §1.7 stats (exact McNemar, Clopper-
                     Pearson, bootstrap 10k seed 20260922, Holm x4).
  evida_runner       Orchestration: units -> V_trusted generations -> EVIDA
                     decisions -> analysis -> collector round17_master.json.
"""
