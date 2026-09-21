"""Unit tests for packguard FL framework (F1) — synthetic fixtures only.

Covers the required unit checks (round-8 W2 brief):
  FedAvg correctness (2 identical clients -> midpoint), FedProx penalty grows
  with mu, pairwise masks cancel at the server, DP noise matches sigma,
  non-IID ecosystem partition is genuinely skewed, global test split has no
  leakage, mock flag propagates into results.
"""
import json
import math

import numpy as np
import pytest
import torch

from packguard.eval import run_pipeline, load_yaml
from packguard.fl import (
    FLConfig,
    FedClient,
    add_dp_noise,
    build_clients,
    client_label_distribution,
    client_upload_mask,
    config_sha16,
    gaussian_epsilon,
    fedavg_weighted,
    make_global_test_split,
    pairwise_mask,
    run_centralized,
    run_federated,
    run_per_client,
    secure_aggregate,
    synthetic_fixture,
)
from packguard.models import local_train, build_model, LogisticModel

SEED = 20260922


@pytest.fixture(scope="module")
def fixture():
    records, meta = synthetic_fixture(n_per_ecosystem=60, seed=SEED)
    train, test = make_global_test_split(records, 0.2, seed=SEED)
    return records, meta, train, test


@pytest.fixture(scope="module")
def clients(fixture):
    _, _, train, _ = fixture
    return build_clients(train)


def _test_client(test_records):
    return FedClient("global_test", test_records)


def _cfg(clients_list, **kw):
    base = dict(input_dim=clients_list[0].input_dim, rounds=3, local_epochs=1,
                lr=0.2, batch_size=32, seed=SEED)
    base.update(kw)
    return FLConfig(**base)


# ---------------------------------------------------------------------------
# fixture + partition
# ---------------------------------------------------------------------------
def test_synthetic_fixture_carries_mock_flag(fixture):
    records, meta, _, _ = fixture
    assert meta["mock"] is True
    assert all(r["mock"] is True for r in records)
    assert all("graph" in r["features"] and "tfidf" in r["features"] for r in records)


def test_non_iid_ecosystem_partition_is_skewed(fixture, clients):
    """npm-only / pypi-only / mixed label rates must genuinely differ."""
    dist = client_label_distribution(clients)
    assert set(dist) == {"npm_only", "pypi_only", "mixed"}
    assert dist["npm_only"]["malicious_rate"] > 0.6
    assert dist["pypi_only"]["malicious_rate"] < 0.4
    rates = [dist[e]["malicious_rate"] for e in dist]
    assert max(rates) - min(rates) > 0.3  # partitions are truly non-IID


def test_global_test_split_no_leakage_and_stratified(fixture):
    records, _, _, _ = fixture
    train, test = make_global_test_split(records, 0.2, seed=SEED)
    tr_ids = {r["sample_id"] for r in train}
    te_ids = {r["sample_id"] for r in test}
    assert not (tr_ids & te_ids)
    assert len(train) + len(test) == len(records)
    tr_rate = np.mean([r["label"] for r in train])
    te_rate = np.mean([r["label"] for r in test])
    assert abs(tr_rate - te_rate) < 0.08  # stratified


# ---------------------------------------------------------------------------
# FedAvg / FedProx
# ---------------------------------------------------------------------------
def test_fedavg_two_identical_clients_midpoint():
    a = torch.tensor([1.0, 2.0, 3.0])
    b = torch.tensor([3.0, 6.0, 9.0])
    out = fedavg_weighted([[a], [b]], [1, 1])
    assert torch.allclose(out[0], torch.tensor([2.0, 4.0, 6.0]))


def test_fedavg_weighted_by_samples():
    a = torch.tensor([0.0])
    b = torch.tensor([10.0])
    out = fedavg_weighted([[a], [b]], [3, 1])  # 3/4 vs 1/4
    assert torch.allclose(out[0], torch.tensor([2.5]))


def test_fedavg_identical_clients_update_equals_each_client(clients):
    """Two clients holding the SAME data produce identical local updates; the
    secure aggregate then equals either client's update (midpoint property)."""
    recs = clients[0].records
    ca, cb = FedClient("a", recs), FedClient("b", list(recs))
    cfg = _cfg(clients, mu=0.0)
    global_params = torch.zeros(2)  # placeholder shapes fixed below
    model0 = build_model({"type": "lr"}, ca.input_dim)
    global_params = [t.detach().clone() for t in model0.parameters()]
    pa, na = ca.local_update(global_params, cfg, round_idx=0, seed=SEED)
    pb, nb = cb.local_update(global_params, cfg, round_idx=0, seed=SEED)
    for x, y in zip(pa, pb):
        assert torch.allclose(x, y)  # identical data + seed -> identical update
    agg = fedavg_weighted([pa, pb], [na, nb])
    for x, y in zip(agg, pa):
        assert torch.allclose(x, y)


def test_fedprox_penalty_pulls_toward_global_and_grows_with_mu(clients):
    client = clients[0]
    model0 = build_model({"type": "lr"}, client.input_dim)
    global_params = [t.detach().clone() for t in model0.parameters()]
    cfg = _cfg(clients, mu=0.0)

    def dist_after(mu):
        model = build_model({"type": "lr"}, client.input_dim)
        with torch.no_grad():
            for p, g in zip(model.parameters(), global_params):
                p.copy_(g)
        local_train(model, client.X, client.y, epochs=3, lr=0.2, batch_size=32,
                    global_params=global_params, mu=mu, seed=SEED)
        return float(sum(((p - g) ** 2).sum()
                         for p, g in zip(model.parameters(), global_params)).detach())

    d0 = dist_after(mu=0.0)
    d5 = dist_after(mu=5.0)
    assert d5 < d0  # proximal term keeps the update closer to w_global


# ---------------------------------------------------------------------------
# Secure aggregation SIMULATION
# ---------------------------------------------------------------------------
def test_pairwise_masks_cancel_exactly_two_clients():
    shapes = [(3,), (2, 4)]
    m0 = client_upload_mask(0, 2, shapes, base_seed=SEED)
    m1 = client_upload_mask(1, 2, shapes, base_seed=SEED)
    for s, a, b in zip(shapes, m0, m1):
        total = a + b
        assert torch.equal(total, torch.zeros(s))  # BITWISE zero: +M + (-M)


def test_pairwise_masks_are_shared_and_symmetric():
    m01 = pairwise_mask(0, 1, [(5,)], base_seed=SEED)[0]
    m10 = pairwise_mask(1, 0, [(5,)], base_seed=SEED)[0]
    assert torch.equal(m01, m10)  # same seed -> same tensor -> exact cancel


def test_pairwise_masks_sum_near_zero_many_clients():
    """n=4: elementwise sum is 0 up to float32 accumulation order (~1e-7);
    the mechanism itself is exactly cancelling (see two-client bitwise test)."""
    shapes = [(6,), (3, 3)]
    masks = [client_upload_mask(i, 4, shapes, base_seed=SEED) for i in range(4)]
    for k in range(len(shapes)):
        total = sum(m[k] for m in masks)
        assert float(total.abs().max()) < 1e-5


def test_secure_aggregate_matches_plain_fedavg():
    params = [[torch.tensor([1.0, 2.0])], [torch.tensor([3.0, 4.0])],
              [torch.tensor([5.0, 0.0])]]
    ns = [10, 20, 30]
    shapes = [(2,)]
    masks = [client_upload_mask(i, 3, shapes, base_seed=SEED) for i in range(3)]
    agg_sec, residual = secure_aggregate(params, ns, masks)
    agg_plain = fedavg_weighted(params, ns)
    assert residual < 1e-5
    assert torch.allclose(agg_sec[0], agg_plain[0], atol=1e-5)


# ---------------------------------------------------------------------------
# DP SIMULATION
# ---------------------------------------------------------------------------
def test_dp_noise_matches_sigma_and_is_seeded():
    shape = (200_000,)
    zeros = [torch.zeros(shape)]
    n1 = add_dp_noise(zeros, sigma=0.05, seed=SEED)[0]
    n2 = add_dp_noise(zeros, sigma=0.05, seed=SEED)[0]
    n3 = add_dp_noise(zeros, sigma=0.05, seed=SEED + 1)[0]
    assert torch.equal(n1, n2)          # deterministic given seed
    assert not torch.equal(n1, n3)      # different seed -> different noise
    std = float(n1.std())
    assert 0.04 < std < 0.06            # empirical std ~ sigma


def test_gaussian_epsilon_formula():
    # eps = 1.0 * sqrt(2 ln(1.25/1e-5)) / 1.0
    expected = math.sqrt(2.0 * math.log(1.25 / 1e-5))
    assert gaussian_epsilon(1.0, 1e-5, 1.0) == pytest.approx(expected, rel=1e-9)
    assert gaussian_epsilon(0.5, 1e-5, 1.0) == pytest.approx(2 * expected, rel=1e-9)


# ---------------------------------------------------------------------------
# Full runs
# ---------------------------------------------------------------------------
def test_federated_run_learns_and_records_history(fixture, clients):
    _, _, _, test = fixture
    tclient = _test_client(test)
    cfg = _cfg(clients, rounds=5)
    res = run_federated(clients, tclient, cfg, algo="fedavg", seed=SEED)
    assert len(res["history"]) == 5
    final = res["final_metrics"]
    assert final["auc"] is not None and final["auc"] > 0.85
    assert res["secure_agg_mask_residual"] < 1e-5


def test_federated_run_is_deterministic(fixture, clients):
    _, _, _, test = fixture
    tclient = _test_client(test)
    cfg = _cfg(clients)
    a = run_federated(clients, tclient, cfg, "fedprox", seed=SEED)
    b = run_federated(clients, tclient, cfg, "fedprox", seed=SEED)
    assert a["final_metrics"] == b["final_metrics"]
    assert a["final_probs"] == b["final_probs"]


def test_dp_and_non_secure_agg_variants_run(fixture, clients):
    _, _, _, test = fixture
    tclient = _test_client(test)
    cfg = _cfg(clients, dp_enabled=True, dp_sigma=0.01, secure_agg_enabled=False)
    res = run_federated(clients, tclient, cfg, "fedavg", seed=SEED)
    assert res["dp_enabled"] is True
    assert res["dp_epsilon_per_round"] == pytest.approx(
        gaussian_epsilon(0.01, cfg.dp_delta, cfg.dp_clip))


def test_baselines_central_and_per_client(fixture, clients):
    _, _, _, test = fixture
    tclient = _test_client(test)
    cfg = _cfg(clients)
    cent = run_centralized(clients, tclient, cfg, seed=SEED)
    per = run_per_client(clients, tclient, cfg, seed=SEED)
    assert 0.0 <= cent["final_metrics"]["f1"] <= 1.0
    assert cent["final_metrics"]["auc"] is not None
    assert len(per["per_client"]) == 3
    assert 0.0 <= per["final_metrics"]["f1_macro"] <= 1.0


def test_config_sha16_stable():
    assert config_sha16({"a": 1, "b": [2, 3]}) == config_sha16({"b": [2, 3], "a": 1})
    assert len(config_sha16({"x": 1})) == 16


# ---------------------------------------------------------------------------
# Eval pipeline (F4 smoke on the fixture; --synthetic contract)
# ---------------------------------------------------------------------------
def test_eval_pipeline_synthetic_end_to_end(tmp_path):
    cfg = load_yaml("configs/packguard_fl.yaml")
    summary = run_pipeline(
        cfg, synthetic=True, out_dir=tmp_path,
        overrides={"fl": {"rounds": 2, "local_epochs": 1, "lr": 0.2,
                          "mu_fedprox": 0.01}})
    assert summary["meta"]["mock"] is True
    assert summary["meta"]["seed"] == SEED
    assert len(summary["meta"]["config_sha16"]) == 16
    assert "fedavg" in summary["runs"]["graph__kb_off"]
    assert (tmp_path / "results.jsonl").exists()
    assert (tmp_path / "summary.md").exists()
    rows = [json.loads(l) for l in
            (tmp_path / "results.jsonl").read_text().splitlines() if l.strip()]
    assert rows
    assert all(r["meta"]["mock"] is True for r in rows)  # flag on EVERY row
    assert any(r["kind"] == "comparison" for r in rows)
    # summary.md discloses the mock status
    assert "mock: True" in (tmp_path / "summary.md").read_text()


def test_eval_pipeline_pending_kb_row(tmp_path):
    cfg = load_yaml("configs/packguard_fl.yaml")
    summary = run_pipeline(
        cfg, synthetic=True, out_dir=tmp_path,
        overrides={"fl": {"rounds": 1, "local_epochs": 1},
                   "ablations": {"feature_blocks": ["graph"],
                                 "fl_variants": ["fedavg", "centralized"],
                                 "kb": {"enabled": False}}})
    assert any("kb ablation disabled" in p for p in summary["pending"])


def test_eval_pipeline_fails_loudly_without_features(tmp_path):
    cfg = load_yaml("configs/packguard_fl.yaml")
    with pytest.raises(FileNotFoundError):
        run_pipeline(cfg, synthetic=False, features_dir=tmp_path,
                     out_dir=tmp_path)
