"""Unit tests for the round-9 multi-seed grid + 3-client fallback partition
(W1, AMENDMENT-3 in docs/packguard_prereg.md). Synthetic fixtures only — no
real-data runs, no writes under outputs/ (the grid runner itself is exercised
via _grid_cell on in-memory fixtures; run_grid's mock guard is tested with
monkeypatch).

Covered duties (round-9 tasking M4):
  * grid runner is deterministic per seed (same seed -> identical rows);
  * the npm_hook 3-client partition follows the registered rule
    (npm+hook / npm-core / pypi; disjoint; union == train pool) and is
    disclosed as ecosystem+hook partition of the SAME corpus, not a new
    ecosystem;
  * per-client-best routing covers every test sample and its macro matches
    the round-8 per-client baseline;
  * the Wilcoxon-over-seeds helper degrades honestly (all-zero deltas ->
    p=None, never fabricated);
  * every grid row carries full provenance {seed, method, features, split,
    partition, mock, config_sha16, date};
  * run_grid refuses mock data (AMENDMENT-3 A3.4: real runs only).
"""
import pytest
import yaml

from packguard.eval import (
    _grid_cell,
    _tfidf_blocks,
    _wilcoxon_over_seeds,
    load_yaml,
    run_grid,
)
from packguard.fl import (
    FLConfig,
    FedClient,
    build_clients,
    client_label_distribution,
    client_name_of,
    make_global_test_split,
    make_group_split,
    run_per_client,
    run_per_client_routing,
    synthetic_fixture,
)

SEED = 20260922

GRAPH_KEYS = [
    "hist_FILE_IO", "hist_NETWORK", "hist_PROCESS", "hist_CRYPTO",
    "hist_DYNAMIC_CODE", "hist_DATA_ACCESS", "n_nodes", "n_edges",
    "density", "n_scopes", "max_repeat", "distinct_classes", "seq_depth",
    "n_files", "n_import_classes", "has_setup", "has_postinstall",
    "parse_fail_files",
]


def _mk_record(sample_id, ecosystem, label, hook, package):
    feats = {k: 0.0 for k in GRAPH_KEYS}
    feats["has_postinstall"] = 1.0 if hook else 0.0
    feats["n_nodes"] = 2.0 + label  # deterministic pseudo-signal
    return {
        "sample_id": sample_id,
        "ecosystem": ecosystem,
        "label": label,
        "package": package,
        "features": {"graph": feats},
    }


@pytest.fixture(scope="module")
def hook_corpus():
    """60-sample corpus, 3 registered client groups, every group keeps BOTH
    labels (LR trainability). The single hooked-benign npm package mirrors
    the real corpus's extreme npm_hook skew."""
    recs = []
    recs.append(_mk_record("npm-ben-hook-0", "npm", 0, True, "hookedben"))  # the ONE hooked benign
    for i in range(14):   # npm hook: 1 ben + 14 mal
        recs.append(_mk_record(f"npm-mal-hook-{i}", "npm", 1, True, f"hookmal{i}"))
    for i in range(15):   # npm core: 8 ben + 7 mal
        lab = 0 if i < 8 else 1
        recs.append(_mk_record(f"npm-core-{i}", "npm", lab, False, f"corepkg{i}"))
    for i in range(15):   # pypi: 8 ben + 7 mal
        lab = 0 if i < 8 else 1
        recs.append(_mk_record(f"pypi-x-{i}", "pypi", lab, False, f"pypipkg{i}"))
    for i in range(15):   # npm benign core extra mass for the group split
        recs.append(_mk_record(f"npm-core-b-{i}", "npm", 0, False, f"coreben{i}"))
    return recs


@pytest.fixture(scope="module")
def grid_cfg(tmp_path_factory):
    cfg = {
        "seed": SEED,
        "data": {"test_fraction": 0.2, "split": "group", "feature_block": "graph"},
        "model": {"type": "lr", "hidden_dim": 32},
        "fl": {"rounds": 3, "local_epochs": 1, "lr": 0.1, "batch_size": 16,
               "mu_fedprox": 0.01},
        "secure_agg": {"enabled": True},
        "dp": {"enabled": False, "sigma": 0.1, "delta": 1.0e-5, "clip": 1.0},
        "grid": {"seeds": [SEED], "splits": ["group"], "feature_blocks": ["graph"],
                 "partitions": ["ecosystem"], "run_client3": False},
    }
    return cfg


# ---------------------------------------------------------------------------
# client_name_of + build_clients partition rules (AMENDMENT-3 A3.3)
# ---------------------------------------------------------------------------
def test_client_name_of_ecoscheme_matches_ecosystem():
    assert client_name_of({"ecosystem": "npm"}, "ecosystem") == "npm"
    assert client_name_of({"ecosystem": "pypi"}, "ecosystem") == "pypi"


def test_client_name_of_npm_hook_rule():
    hook = {"ecosystem": "npm", "features": {"graph": {"has_postinstall": 1.0}}}
    core = {"ecosystem": "npm", "features": {"graph": {"has_postinstall": 0.0}}}
    py = {"ecosystem": "pypi", "features": {"graph": {"has_postinstall": 1.0}}}
    assert client_name_of(hook, "npm_hook") == "npm_hook"
    assert client_name_of(core, "npm_hook") == "npm_core"
    # pypi keeps its ecosystem name even with a truthy hook feature
    assert client_name_of(py, "npm_hook") == "pypi"


def test_client_name_of_unknown_scheme_raises():
    with pytest.raises(ValueError):
        client_name_of({"ecosystem": "npm"}, "maven")  # never silently default


def test_npm_hook_partition_is_three_clients_and_exact(hook_corpus):
    train, test = make_group_split(hook_corpus, 0.2, seed=SEED)
    clients = build_clients(train, "graph", scheme="npm_hook")
    names = [c.name for c in clients]
    assert names == ["npm_core", "npm_hook", "pypi"]
    # disjoint + union == train pool
    n_union = sum(c.n_samples for c in clients)
    assert n_union == len(train)
    ids = [r["sample_id"] for c in clients for r in c.records]
    assert len(ids) == len(set(ids))
    # npm rows are split exactly by the hook flag
    for c in clients:
        if c.name == "npm_hook":
            assert all(float(r["features"]["graph"]["has_postinstall"]) > 0
                       for r in c.records)
        if c.name == "npm_core":
            assert all(float(r["features"]["graph"]["has_postinstall"]) == 0
                       for r in c.records)
    # every client trainable (both labels present in this fixture)
    for c in clients:
        assert set(c.y.tolist()) == {0.0, 1.0}
    # no test sample leaks into a client
    test_ids = {r["sample_id"] for r in test}
    assert not (test_ids & set(ids))


def test_default_scheme_reproduces_ecosystem_partition(hook_corpus):
    train, _ = make_group_split(hook_corpus, 0.2, seed=SEED)
    a = build_clients(train, "graph")                       # default
    b = build_clients(train, "graph", scheme="ecosystem")   # explicit
    assert [(c.name, c.n_samples) for c in a] == [(c.name, c.n_samples) for c in b]
    assert [c.name for c in a] == ["npm", "pypi"]


def test_npm_hook_client_is_extreme_skew_like_real_corpus(hook_corpus):
    """The registered disclosure: npm_hook is ~99% malicious (real corpus:
    162 mal / 1 ben). The partition rule must preserve that skew, not hide it."""
    train, _ = make_group_split(hook_corpus, 0.2, seed=SEED)
    clients = build_clients(train, "graph", scheme="npm_hook")
    dist = client_label_distribution(clients)
    assert dist["npm_hook"]["malicious_rate"] >= 0.9
    assert dist["npm_core"]["malicious_rate"] < 0.9
    assert dist["pypi"]["malicious_rate"] < 0.9


# ---------------------------------------------------------------------------
# per-client-best routing (AMENDMENT-3 A3.2 definition)
# ---------------------------------------------------------------------------
def _fl_cfg(input_dim):
    return FLConfig.from_dict(
        {"rounds": 2, "local_epochs": 1, "lr": 0.1, "batch_size": 16,
         "mu": 0.01, "type": "lr"}, input_dim=input_dim)


def test_routing_covers_every_test_sample(hook_corpus):
    train, test = make_group_split(hook_corpus, 0.2, seed=SEED)
    clients = build_clients(train, "graph", scheme="npm_hook")
    tc = FedClient("global_test", test, "graph")
    out = run_per_client_routing(clients, test, tc, _fl_cfg(tc.input_dim),
                                 SEED, scheme="npm_hook")
    assert out["n_uncovered"] == 0
    assert out["final_metrics"]["n"] == len(test)
    assert len(out["final_probs"]) == len(test)


def test_routing_macro_matches_round8_per_client_baseline(hook_corpus):
    """run_per_client_routing trains the SAME models with the SAME seed
    protocol as run_per_client — the macro-mean must be identical."""
    train, test = make_group_split(hook_corpus, 0.2, seed=SEED)
    clients = build_clients(train, "graph", scheme="npm_hook")
    tc = FedClient("global_test", test, "graph")
    cfg = _fl_cfg(tc.input_dim)
    routed = run_per_client_routing(clients, test, tc, cfg, SEED, scheme="npm_hook")
    baseline = run_per_client(clients, tc, cfg, SEED)
    assert routed["macro_metrics"]["f1_macro"] == \
        baseline["final_metrics"]["f1_macro"]
    assert routed["per_client"] == baseline["per_client"]


def test_routing_is_deterministic_per_seed(hook_corpus):
    train, test = make_group_split(hook_corpus, 0.2, seed=SEED)
    clients = build_clients(train, "graph", scheme="npm_hook")
    tc = FedClient("global_test", test, "graph")
    cfg = _fl_cfg(tc.input_dim)
    a = run_per_client_routing(clients, test, tc, cfg, SEED, scheme="npm_hook")
    b = run_per_client_routing(clients, test, tc, cfg, SEED, scheme="npm_hook")
    assert a["final_probs"] == b["final_probs"]
    assert a["final_metrics"]["f1"] == b["final_metrics"]["f1"]


# ---------------------------------------------------------------------------
# grid cell: determinism per seed + provenance + tfidf fit-on-train
# ---------------------------------------------------------------------------
def test_grid_cell_rows_deterministic_per_seed(hook_corpus, grid_cfg):
    r1, c1 = _grid_cell(hook_corpus, {}, grid_cfg, SEED, "group", "graph",
                        "ecosystem", {"config_sha16": "test", "date": "t"})
    r2, c2 = _grid_cell(hook_corpus, {}, grid_cfg, SEED, "group", "graph",
                        "ecosystem", {"config_sha16": "test", "date": "t"})
    keys = ("f1", "auc", "precision", "recall", "per_ecosystem_f1",
            "history_tail", "n_test")
    for k in keys:
        assert r1[0][k] == r2[0][k]
    assert c1["f1_delta"] == c2["f1_delta"]
    assert c1["mcnemar_fedavg_vs_centralized"]["p_value"] == \
        c2["mcnemar_fedavg_vs_centralized"]["p_value"]


def test_grid_cell_provenance_fields(hook_corpus, grid_cfg):
    rows, _ = _grid_cell(hook_corpus, {}, grid_cfg, SEED, "group", "graph",
                         "ecosystem", {"config_sha16": "deadbeef", "date": "t"})
    methods = {r["method"] for r in rows}
    assert methods == {"fedavg", "fedprox", "centralized", "per_client_best"}
    for r in rows:
        assert r["seed"] == SEED
        assert r["features"] == "graph"
        assert r["split"] == "group"
        assert r["partition"] == "ecosystem"
        assert r["mock"] is False
        assert r["config_sha16"] == "deadbeef"
        assert r["date"] == "t"
        assert set(r["per_ecosystem_f1"]) == {"eco_npm", "eco_pypi"}
    # per-client-best rows carry the macro disclosure fields
    pcb = [r for r in rows if r["method"] == "per_client_best"][0]
    assert pcb["n_uncovered"] == 0
    assert "f1_macro" in pcb["macro_metrics"]


def test_tfidf_blocks_fit_on_train_and_same_key_set(hook_corpus):
    cache = {r["sample_id"]: f"def f_{r['sample_id']}(): pass call_{r['label']}"
             for r in hook_corpus}
    train, test = make_global_test_split(hook_corpus, 0.2, seed=SEED)
    _tfidf_blocks(train, test, cache)
    names_train = {tuple(sorted(r["features"]["tfidf"])) for r in train}
    names_test = {tuple(sorted(r["features"]["tfidf"])) for r in test}
    assert len(names_train) == 1  # identical key set on every train record
    assert names_train == names_test
    assert len(next(iter(names_train))) <= 1000
    # determinism: same train -> identical vectors
    t2 = [dict(r, features=dict(r["features"])) for r in train]
    for r in t2:
        r["features"].pop("tfidf")
    _tfidf_blocks(t2, test, cache)
    for a, b in zip(train, t2):
        assert a["features"]["tfidf"] == b["features"]["tfidf"]


# ---------------------------------------------------------------------------
# Wilcoxon-over-seeds helper: honest degradation, no fabricated p
# ---------------------------------------------------------------------------
def test_wilcoxon_all_zero_deltas_is_undefined_not_fabricated():
    out = _wilcoxon_over_seeds([0.0, 0.0, 0.0, 0.0, 0.0])
    assert out["p_value"] is None
    assert "zero" in out["note"]
    assert out["n_zero"] == 5


def test_wilcoxon_signs_and_mean():
    out = _wilcoxon_over_seeds([0.1, -0.2, 0.05, -0.01, 0.0])
    assert out["n_pos"] == 2 and out["n_neg"] == 2 and out["n_zero"] == 1
    assert out["mean_delta"] == pytest.approx(-0.012)
    assert 0.0 <= out["p_value"] <= 1.0
    assert "0.0625" in out["power_note"]  # n=5 minimum two-sided exact p


def test_wilcoxon_known_direction_all_positive():
    out = _wilcoxon_over_seeds([0.1, 0.2, 0.05, 0.01, 0.3])
    assert out["n_pos"] == 5 and out["n_neg"] == 0
    assert out["p_value"] == pytest.approx(1 / 16)  # the n=5 exact minimum


# ---------------------------------------------------------------------------
# run_grid refuses mock data (AMENDMENT-3: real runs only)
# ---------------------------------------------------------------------------
def test_run_grid_refuses_mock_data(monkeypatch, tmp_path, grid_cfg):
    from packguard import eval as ev

    records, meta = synthetic_fixture(n_per_ecosystem=10, seed=SEED)
    monkeypatch.setattr(ev, "load_feature_records",
                        lambda *a, **k: (records, {"mock": True, "source": "fixture"}))
    with pytest.raises(RuntimeError, match="refuses mock"):
        ev.run_grid(grid_cfg, out_dir=tmp_path / "grid_out")


def test_run_grid_missing_features_fails_loud(monkeypatch, tmp_path, grid_cfg):
    from packguard import eval as ev

    def _raise(*a, **k):
        raise FileNotFoundError("W1 feature output not found")
    monkeypatch.setattr(ev, "load_feature_records", _raise)
    with pytest.raises(FileNotFoundError):
        ev.run_grid(grid_cfg, out_dir=tmp_path / "grid_out")


# ---------------------------------------------------------------------------
# config contract: grid section present and matches AMENDMENT-3
# ---------------------------------------------------------------------------
def test_config_grid_section_matches_amendment3():
    cfg = load_yaml("configs/packguard_fl.yaml")
    grid = cfg.get("grid") or {}
    assert grid["seeds"] == [20260922, 20260923, 20260924, 20260925, 20260926]
    assert grid["splits"] == ["group", "random"]
    assert grid["feature_blocks"] == ["graph", "tfidf"]
    assert set(grid["methods"]) == {"fedavg", "fedprox", "centralized",
                                    "per_client_best"}
    assert grid["partitions"] == ["ecosystem"]
    assert grid["run_client3"] is True
    # FedProx mu comes from the fl section (registered value)
    assert float(cfg["fl"]["mu_fedprox"]) == 0.01
