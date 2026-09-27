"""Round-11 P0 tests (AMENDMENT-5, agent W1).

A2: the FedProx mu-routing fix in packguard/fl.py —
  (i)  mu=1.0, 2 clients, same seed -> FedProx != FedAvg AND the per-algo mu
       actually reaches local_train (monkeypatched);
  (ii) mu=1e-9 -> FedProx ~= FedAvg (prox term vanishes);
  (iii) regression: cfg.legacy_mu_routing=True reproduces the OLD bit-identity
       (fedavg == fedprox), and the fixed fedprox(mu=0.01) reproduces the
       round-9 grid row for a real cell (old "fedavg" rows WERE FedProx(0.01)).

A3/A4: strong-baseline properties — train-only scaler/CV, stateless hashing,
FedAvg fixed point, deterministic C selection. TOST helper on known numbers.
"""
import copy
import json

import numpy as np
import pytest
import torch

from packguard import fl as flm
from packguard.fl import (
    FLConfig,
    FedClient,
    build_clients,
    run_federated,
    synthetic_fixture,
)
from packguard.strong_baseline import (
    C_GRID,
    HashingTextFeaturizer,
    fedavg_sklearn,
    select_c_cv,
    strong_centralized,
)

SEED = 20260922

GRID_JSON = ("outputs/packguard/fl_multiseed/grid_results.json")


# ---------------------------------------------------------------------------
# fixtures (synthetic, mock-flagged — same hygiene as test_packguard_fl_core)
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def fixture():
    records, meta = synthetic_fixture(n_per_ecosystem=60, seed=SEED)
    train, test = flm.make_global_test_split(records, 0.2, seed=SEED)
    return records, meta, train, test


def _cfg(input_dim, **kw):
    base = dict(input_dim=input_dim, rounds=5, local_epochs=2,
                lr=0.1, batch_size=32, seed=SEED)
    base.update(kw)
    return FLConfig(**base)


# ---------------------------------------------------------------------------
# A2 (i): mu routing — FedProx(mu=1.0) differs from FedAvg, mu reaches solver
# ---------------------------------------------------------------------------
def test_fedprox_mu1_differs_from_fedavg_and_mu_reaches_local_train(fixture):
    _, _, train, test = fixture
    clients = build_clients(train)
    tclient = FedClient("global_test", test)
    cfg = _cfg(tclient.input_dim, mu=1.0)

    calls = []
    import packguard.fl as fl_module

    original = fl_module.local_train

    def spy(*args, **kwargs):
        calls.append(kwargs.get("mu"))
        return original(*args, **kwargs)

    fl_module.local_train = spy
    try:
        res_avg = run_federated(clients, tclient, cfg, "fedavg", seed=SEED)
        res_prox = run_federated(clients, tclient, cfg, "fedprox", seed=SEED)
    finally:
        fl_module.local_train = original

    # mu actually reaches the local solver, per algo
    assert set(calls[: len(clients) * cfg.rounds]) == {0.0}          # fedavg leg
    assert set(calls[len(clients) * cfg.rounds:]) == {1.0}           # fedprox leg
    # and the trajectories differ
    assert res_prox["final_probs"] != res_avg["final_probs"]
    for p_avg, p_prox in zip(res_avg["final_probs"], res_prox["final_probs"]):
        assert abs(p_avg - p_prox) > 1e-6


def test_fedprox_small_mu_converges_to_fedavg(fixture):
    _, _, train, test = fixture
    clients = build_clients(train)
    tclient = FedClient("global_test", test)
    cfg = _cfg(tclient.input_dim, mu=1e-9)
    res_avg = run_federated(clients, tclient, cfg, "fedavg", seed=SEED)
    res_prox = run_federated(clients, tclient, cfg, "fedprox", seed=SEED)
    max_diff = max(abs(a - b) for a, b in
                   zip(res_avg["final_probs"], res_prox["final_probs"]))
    assert max_diff < 1e-6


# ---------------------------------------------------------------------------
# A2 (iii): regression vs the pre-fix (round-9) behavior and artifacts
# ---------------------------------------------------------------------------
def test_legacy_flag_reproduces_old_bit_identity(fixture):
    """legacy_mu_routing=True must restore the audited behavior: with
    cfg.mu>0 both algos run FedProx(cfg.mu) -> bit-identical."""
    _, _, train, test = fixture
    clients = build_clients(train)
    tclient = FedClient("global_test", test)
    cfg = _cfg(tclient.input_dim, mu=0.01, legacy_mu_routing=True)
    res_avg = run_federated(clients, tclient, cfg, "fedavg", seed=SEED)
    res_prox = run_federated(clients, tclient, cfg, "fedprox", seed=SEED)
    assert res_avg["final_probs"] == res_prox["final_probs"]


def test_fixed_fedprox_mu001_reproduces_round9_grid_row():
    """The round-9 grid's "fedavg" rows were FedProx(cfg.mu=0.01) (mu-routing
    bug). Regression contract on the real cell (seed 20260922, group, graph):
    (a) the FIXED code's fedprox(mu=0.01) reproduces the stored round-9 row
    exactly, down to the per-round history tail; (b) the two arms now DIVERGE
    at probability level, i.e. the fixed "fedavg" is no longer FedProx."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    grid = json.loads((root / GRID_JSON).read_text())
    row = next(r for r in grid["rows"]
               if r["partition"] == "ecosystem" and r["split"] == "group"
               and r["features"] == "graph" and r["method"] == "fedavg"
               and r["seed"] == SEED)
    old_f1 = float(row["f1"])
    old_tail = row["history_tail"]

    from packguard.eval import load_yaml, _grid_cell

    cfg = load_yaml(root / "configs" / "packguard_fl.yaml")
    cache_path = root / "outputs/packguard/features/text_v2.json"
    cache = json.loads(cache_path.read_text()) if cache_path.exists() else {}
    records, _ = flm.load_feature_records(root / "outputs/packguard/features")
    rows, _cell = _grid_cell(records, cache, cfg, SEED, "group", "graph",
                             "ecosystem", {"config_sha16": "test", "date": "test"})
    by_method = {r["method"]: r for r in rows}
    # (a) the arm that actually ran (FedProx 0.01) is unchanged by the fix
    assert pytest.approx(old_f1, abs=1e-9) == float(by_method["fedprox"]["f1"])
    assert old_tail == by_method["fedprox"]["history_tail"]
    # (b) arms diverge now: max prob difference > 0 between fedavg and fedprox
    from packguard.fl import FedClient, build_clients, run_federated, FLConfig

    tr, te = flm.make_group_split(flm.load_feature_records(
        root / "outputs/packguard/features")[0], 0.2, seed=SEED)
    clients = build_clients(tr, feature_block="graph")
    tclient = FedClient("global_test", te, feature_block="graph")
    flcfg = FLConfig.from_dict({"rounds": 15, "local_epochs": 2, "lr": 0.1,
                                "batch_size": 32, "mu": 0.01},
                               input_dim=tclient.input_dim)
    res_avg = run_federated(clients, tclient, flcfg, "fedavg", seed=SEED)
    res_prox = run_federated(clients, tclient, flcfg, "fedprox", seed=SEED)
    max_diff = max(abs(a - b) for a, b in
                   zip(res_avg["final_probs"], res_prox["final_probs"]))
    assert max_diff > 1e-9


# ---------------------------------------------------------------------------
# A3: strong baseline properties
# ---------------------------------------------------------------------------
def test_strong_lr_converges_and_beats_undertrained_on_synthetic(fixture):
    """Sanity on the mock fixture: the converged lbfgs baseline must not
    collapse (the L1 undertrain failure mode)."""
    _, _, train, _ = fixture
    X = np.array([[float(v) for v in sorted(
        r["features"]["graph"].values())] for r in train])
    y = np.array([int(r["label"]) for r in train])
    cent = strong_centralized(X, y, C=1.0)
    assert cent["converged"]
    probs = 1.0 / (1.0 + np.exp(-(X @ cent["theta"][:-1] + cent["theta"][-1])))
    m = flm.compute_clf_metrics(y, probs)
    assert m["f1"] >= 0.75  # separable fixture; undertrained SGD risked collapse


def test_select_c_cv_deterministic_and_grid_bounded(fixture):
    _, _, train, _ = fixture
    X = np.array([[float(v) for v in sorted(
        r["features"]["graph"].values())] for r in train])
    y = np.array([int(r["label"]) for r in train])
    a = select_c_cv(X, y, seed=SEED)
    b = select_c_cv(X, y, seed=SEED)
    assert a["C_selected"] == b["C_selected"]
    assert a["C_selected"] in C_GRID
    assert len(a["cv_table"]) == len(C_GRID)


def test_hashing_featurizer_is_stateless():
    """No vocabulary fit: the transform of a text must not change after the
    vectorizer has 'seen' other texts (FL-valid shared transform)."""
    vec = HashingTextFeaturizer(n_features=2 ** 10)
    before = vec.transform(["exec child_process require"])
    _ = vec.transform(["totally different corpus text " * 100])
    after = vec.transform(["exec child_process require"])
    assert (before != after).nnz == 0
    assert before.shape[1] == 2 ** 10


def test_fedavg_sklearn_fixed_point_after_first_round():
    """Converged convex local fits: round 2 re-aggregates to the SAME theta
    (disclosed fixed-point property, AMENDMENT-5 A5.2)."""
    rng = np.random.default_rng(SEED)
    Xa = rng.normal(size=(40, 5)); ya = (Xa[:, 0] > 0).astype(int)
    Xb = rng.normal(size=(30, 5)) + 0.5; yb = (Xb[:, 1] > 0).astype(int)
    one = fedavg_sklearn([Xa, Xb], [ya, yb], C=1.0, rounds=1)
    two = fedavg_sklearn([Xa, Xb], [ya, yb], C=1.0, rounds=2)
    assert np.allclose(one["theta"], two["theta"], atol=1e-9)


def test_fedprox_sklearn_mu1_differs_and_small_mu_close():
    rng = np.random.default_rng(SEED)
    Xa = rng.normal(size=(40, 5)); ya = (Xa[:, 0] > 0).astype(int)
    Xb = rng.normal(size=(30, 5)); yb = (Xb[:, 1] > 0).astype(int)
    from packguard.strong_baseline import fedprox_sklearn

    px1 = fedprox_sklearn([Xa, Xb], [ya, yb], C=1.0, mu=1.0, rounds=3)
    px0 = fedprox_sklearn([Xa, Xb], [ya, yb], C=1.0, mu=1e-9, rounds=3)
    avg = fedavg_sklearn([Xa, Xb], [ya, yb], C=1.0, rounds=2)
    assert not np.allclose(px1["theta"], avg["theta"], atol=1e-4)
    assert np.allclose(px0["theta"], avg["theta"], atol=1e-5)


def test_prox_solver_matches_closed_form_check():
    """The analytic gradient is finite and the solver decreases the prox-
    augmented objective from the global init (monotone sanity)."""
    from packguard.strong_baseline import local_fit_fedprox

    rng = np.random.default_rng(SEED)
    X = rng.normal(size=(50, 4)); y = (X[:, 2] > 0).astype(int)
    theta_g = np.zeros(5)
    out = local_fit_fedprox(X, y, C=1.0, theta_global=theta_g, mu=1.0)
    assert out["converged"]
    assert out["objective"] < 0.6931 + 1e-9  # improved on the init objective


# ---------------------------------------------------------------------------
# TOST helper (registered decision rule A5.3)
# ---------------------------------------------------------------------------
def test_tost_equivalence_known_outcomes():
    from packguard.eval import tost_equivalence

    # identical deltas -> CI = [0, 0] -> PASS
    ok = tost_equivalence([0.0] * 20, margin=0.02)
    assert ok["equivalent"] is True
    # large negative deltas -> FAIL below
    bad = tost_equivalence([-0.1, -0.12, -0.11, -0.09, -0.1] * 4, margin=0.02)
    assert bad["equivalent"] is False and bad["ci_high"] < -0.02
    # wide CI over the margin -> inconclusive (not equivalent)
    import random as _r
    rng = _r.Random(SEED)
    wide = tost_equivalence([rng.gauss(0, 0.2) for _ in range(8)], margin=0.02)
    assert wide["equivalent"] is False
    assert wide["n"] == 8 and wide["method"].startswith("TOST")


def test_holm_adjustment_ordering():
    from packguard.eval import holm_adjust

    ps = [0.01, 0.04, 0.03, 0.60]
    adj = holm_adjust(ps)
    assert adj[0] == pytest.approx(0.04)          # 0.01*4
    assert adj[3] == pytest.approx(0.60)          # monotone clamp
    assert all(adj[i] <= adj[i + 1] + 1e-12 for i in range(3))
