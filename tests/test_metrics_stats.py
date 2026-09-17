"""Hand-computed unit tests for src/metrics/stats.py (PROPOSAL §9)."""
import math

import pytest

from src.metrics.stats import bootstrap_ci, bootstrap_ci_diff, cohens_h, mcnemar, odds_ratio


def _paired_lists(b01: int, b10: int, both: int, neither: int):
    a, b = [], []
    a += [False] * b01 + [True] * b10 + [True] * both + [False] * neither
    b += [True] * b01 + [False] * b10 + [True] * both + [False] * neither
    return a, b


def test_mcnemar_exact_hand_computed():
    # b01=1, b10=5 -> exact two-sided binomial p = 2 * P(X<=1 | n=6, 0.5) = 14/64
    a, b = _paired_lists(b01=1, b10=5, both=10, neither=4)
    out = mcnemar(a, b, exact=True)
    assert out["b01_a_fail_b_success"] == 1
    assert out["b10_a_success_b_fail"] == 5
    assert out["n"] == 20
    assert out["statistic"] == 1
    assert out["p_value"] == pytest.approx(14 / 64)


def test_mcnemar_no_discordant_pairs():
    a, b = _paired_lists(b01=0, b10=0, both=8, neither=2)
    out = mcnemar(a, b, exact=True)
    assert out["p_value"] == pytest.approx(1.0)
    assert out["statistic"] == 0


def test_mcnemar_chi2_matches_scipy():
    sps = pytest.importorskip("scipy.stats")
    a, b = _paired_lists(b01=2, b10=10, both=30, neither=8)
    out = mcnemar(a, b, exact=False)
    expected_stat = (abs(2 - 10) - 1) ** 2 / 12  # continuity-corrected chi2
    assert out["statistic"] == pytest.approx(expected_stat)
    assert out["p_value"] == pytest.approx(float(sps.chi2.sf(expected_stat, df=1)))


def test_mcnemar_length_mismatch():
    with pytest.raises(ValueError):
        mcnemar([True, False], [True])


def test_bootstrap_ci_deterministic_and_sane():
    vals = list(range(1, 11))  # mean 5.5
    r1 = bootstrap_ci(vals, n_boot=10000, seed=1234)
    r2 = bootstrap_ci(vals, n_boot=10000, seed=1234)
    assert r1 == r2  # seed -> deterministic
    assert r1["estimate"] == pytest.approx(5.5)
    assert r1["ci_low"] <= 5.5 <= r1["ci_high"]
    assert r1["n_boot"] == 10000 and r1["seed"] == 1234
    # narrower alpha (80% CI) -> narrower interval than the 95% CI
    narrow = bootstrap_ci(vals, n_boot=10000, seed=1234, alpha=0.20)
    assert narrow["ci_high"] - narrow["ci_low"] <= r1["ci_high"] - r1["ci_low"]


def test_bootstrap_ci_median_stat():
    vals = [1, 2, 3, 4, 100.0]
    out = bootstrap_ci(vals, func=lambda xs: sorted(xs)[len(xs) // 2], seed=7)
    assert out["estimate"] == 3.0


def test_bootstrap_ci_diff_positive_effect():
    a = [0.9, 0.8, 0.7, 0.9, 0.8]
    b = [0.4, 0.5, 0.4, 0.3, 0.4]
    out = bootstrap_ci_diff(a, b, seed=1234)
    assert out["n_pairs"] == 5
    assert out["estimate"] == pytest.approx(0.42)
    assert out["ci_low"] > 0.0  # clearly positive paired effect
    with pytest.raises(ValueError):
        bootstrap_ci_diff(a, b[:-1])


def test_odds_ratio_haldane_anscombe():
    out = odds_ratio([[10, 5], [5, 10]])
    assert out["odds_ratio"] == pytest.approx((10.5 * 10.5) / (5.5 * 5.5))
    assert out["log_or_se"] == pytest.approx(
        math.sqrt(1 / 10.5 + 1 / 5.5 + 1 / 5.5 + 1 / 10.5))
    raw = odds_ratio([[10, 5], [5, 10]], correct=False)
    assert raw["odds_ratio"] == pytest.approx(4.0)


def test_cohens_h_hand_computed():
    # h(0.5, 0.25) = 2*asin(sqrt(.5)) - 2*asin(.5) = pi/2 - pi/3 = pi/6
    assert cohens_h(0.5, 0.25) == pytest.approx(math.pi / 6)
    assert cohens_h(0.3, 0.3) == 0.0
    with pytest.raises(ValueError):
        cohens_h(1.5, 0.2)
