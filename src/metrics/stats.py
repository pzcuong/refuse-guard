"""Paired statistics for RefuseGuard (PROJECT_BRIEF §8; PROPOSAL §9).

- mcnemar: paired categorical comparison (statsmodels when available, exact
  binomial / chi2 fallback via scipy). Input = two aligned boolean outcome
  lists (e.g. "sample answered usable+correct" under baseline vs defense).
- bootstrap_ci: nonparametric bootstrap CI for a statistic (default mean),
  10,000 resamples, fixed seed by default (PROJECT_BRIEF: seed must be public).
- bootstrap_ci_diff: paired two-sample difference (e.g. SIUD / CUL) via
  resampling indices of the paired deltas.
- Effect sizes: odds_ratio (2x2, Haldane-Anscombe corrected) and Cohen's h.

All functions are pure and deterministic given a seed.
"""
from __future__ import annotations

import math
import random
from typing import Callable, Optional, Sequence

__all__ = [
    "mcnemar",
    "bootstrap_ci",
    "bootstrap_ci_diff",
    "odds_ratio",
    "cohens_h",
]


def mcnemar(
    success_a: Sequence[bool],
    success_b: Sequence[bool],
    exact: Optional[bool] = None,
) -> dict:
    """Two-sided McNemar test on paired binary outcomes.

    success_a / success_b: aligned per-sample outcomes (True = success) for
    system A and system B on the SAME samples. Discordant counts:
    b01 = A fail & B succeed, b10 = A succeed & B fail.

    exact=True  -> exact binomial test on the discordant pairs;
    exact=False -> chi2 approximation with continuity correction;
    exact=None  -> auto (exact when b01+b10 < 25, following statsmodels).

    Returns dict with n, n_both_success, b01, b10, statistic, p_value, exact.
    """
    if len(success_a) != len(success_b):
        raise ValueError("success_a and success_b must have the same length")
    b01 = sum(1 for a, b in zip(success_a, success_b) if not a and b)
    b10 = sum(1 for a, b in zip(success_a, success_b) if a and not b)
    n = len(success_a)
    both = sum(1 for a, b in zip(success_a, success_b) if a and b)
    nd = b01 + b10
    if exact is None:
        exact = nd < 25

    statistic = min(b01, b10)
    p_value: Optional[float] = None
    method = ""
    try:
        from statsmodels.stats.contingency_tables import mcnemar as _sm_mcnemar

        # statsmodels table: [[a, b], [c, d]] with a=both success, b=b10,
        # c=b01, d=neither.
        table = [[both, b10], [b01, n - both - b01 - b10]]
        res = _sm_mcnemar(table, exact=exact, correction=True)
        statistic, p_value, method = float(res.statistic), float(res.pvalue), (
            "statsmodels.exact" if exact else "statsmodels.chi2"
        )
    except Exception:
        # scipy fallback
        from scipy import stats as sps

        if nd == 0:
            statistic, p_value = 0.0, 1.0
        elif exact:
            statistic = min(b01, b10)
            p_value = float(sps.binomtest(min(b01, b10), nd, 0.5).pvalue)
        else:
            statistic = (abs(b01 - b10) - 1.0) ** 2 / nd if nd > 0 else 0.0
            p_value = float(sps.chi2.sf(statistic, df=1))
        method = f"scipy.{'binom' if exact else 'chi2'}"

    return {
        "n": n,
        "n_both_success": both,
        "b01_a_fail_b_success": b01,
        "b10_a_success_b_fail": b10,
        "statistic": statistic,
        "p_value": p_value,
        "exact": bool(exact),
        "method": method,
    }


def bootstrap_ci(
    values: Sequence[float],
    func: Callable[[Sequence[float]], float] = None,
    n_boot: int = 10000,
    seed: int = 1234,
    alpha: float = 0.05,
) -> dict:
    """Nonparametric percentile bootstrap CI for `func(values)` (default mean)."""
    if not values:
        raise ValueError("values must be non-empty")
    if func is None:
        func = _mean
    rng = random.Random(seed)
    xs = list(values)
    n = len(xs)
    estimate = func(xs)
    stats_ = []
    for _ in range(n_boot):
        sample = [xs[rng.randrange(n)] for _ in range(n)]
        stats_.append(func(sample))
    stats_.sort()
    lo = stats_[int((alpha / 2) * n_boot)]
    hi = stats_[min(n_boot - 1, int((1 - alpha / 2) * n_boot))]
    return {
        "estimate": estimate,
        "ci_low": lo,
        "ci_high": hi,
        "alpha": alpha,
        "n_boot": n_boot,
        "seed": seed,
    }


def bootstrap_ci_diff(
    paired_a: Sequence[float],
    paired_b: Sequence[float],
    n_boot: int = 10000,
    seed: int = 1234,
    alpha: float = 0.05,
) -> dict:
    """Bootstrap CI for mean(a_i - b_i) over paired samples (e.g. SIUD, CUL).

    Resamples PAIRS (same index) to respect the pairing, per PROPOSAL §9.
    """
    if len(paired_a) != len(paired_b):
        raise ValueError("paired lists must have the same length")
    deltas = [a - b for a, b in zip(paired_a, paired_b)]
    out = bootstrap_ci(deltas, n_boot=n_boot, seed=seed, alpha=alpha)
    out["n_pairs"] = len(deltas)
    return out


def odds_ratio(cell_2x2: Sequence[Sequence[int]], correct: bool = True) -> dict:
    """Odds ratio from a 2x2 table [[a,b],[c,d]] with Haldane-Anscombe
    0.5 correction (avoids division by zero); `correct=False` uses raw counts.
    Also returns the Woolf log-OR standard error."""
    a, b, c, d = (float(x) for x in (cell_2x2[0][0], cell_2x2[0][1], cell_2x2[1][0], cell_2x2[1][1]))
    eps = 0.5 if correct else 0.0
    num = (a + eps) * (d + eps)
    den = (b + eps) * (c + eps)
    or_ = num / den
    se = math.sqrt(1 / (a + eps) + 1 / (b + eps) + 1 / (c + eps) + 1 / (d + eps))
    return {"odds_ratio": or_, "log_or": math.log(or_), "log_or_se": se}


def cohens_h(p1: float, p2: float) -> float:
    """Cohen's h effect size for two proportions: 2*asin(sqrt(p1)) - 2*asin(sqrt(p2))."""
    for p in (p1, p2):
        if not 0.0 <= p <= 1.0:
            raise ValueError("proportions must be in [0, 1]")
    return 2.0 * math.asin(math.sqrt(p1)) - 2.0 * math.asin(math.sqrt(p2))


def _mean(xs: Sequence[float]) -> float:
    return sum(xs) / len(xs)
