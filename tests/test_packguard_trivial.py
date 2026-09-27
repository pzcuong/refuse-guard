"""Round-11 W2 tests: gen_paper_numbers --check + trivial baseline.

Covers:
  [T1] trivial feature set is metadata-only and graph features are the
       frozen 18-name FEATURE_NAMES list;
  [T2] empty_graph_flag derivation (never imputed; consistent with n_nodes);
  [T3] n_bytes is absent from the schema and matrix() refuses it loudly
       (disclosure duty -- no silent imputation);
  [T4] run_protocol is deterministic for fixed (records, seeds);
  [T5] group split: package-group and sample-id disjointness (no leakage);
  [T6] McNemar degenerate all-agree case reports p=1.0, never a fabricated
       statistic; all-zero deltas get p=None + note;
  [T7] bootstrap CI is seeded/deterministic;
  [T8] the committed results artifact carries mock:false, the 20-seed
       AMENDMENT-4 seed list, the n_bytes disclosure, and the comparability
       note (never mixed with the torch-SGD grid numbers).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import r11_trivial_baseline as tb  # noqa: E402
import gen_paper_numbers as gpn  # noqa: E402

RESULTS = ROOT / "outputs/packguard/trivial/trivial_results.json"
NUMBERS_TEX = ROOT / "paper2/p0_macros/numbers.tex"


@pytest.fixture(scope="module")
def records():
    return tb.load_records()


# ---------------------------------------------------------------- T1
def test_trivial_features_are_metadata_only():
    assert tb.TRIVIAL_FEATURES == ["n_files", "parse_fail_files", "empty_graph_flag",
                                   "has_setup", "has_postinstall"]
    # no parsed-content leakage into the trivial set
    forbidden = {"n_nodes", "n_edges", "density", "n_scopes", "seq_depth",
                 "distinct_classes", "max_repeat", "n_import_classes"}
    assert not (set(tb.TRIVIAL_FEATURES) & forbidden)


def test_graph_features_are_frozen_18():
    from packguard.features import FEATURE_NAMES
    assert tb.GRAPH_FEATURES == list(FEATURE_NAMES)
    assert len(tb.GRAPH_FEATURES) == 18


# ---------------------------------------------------------------- T2
def test_empty_graph_flag_derivation(records):
    for r in records[:200]:
        assert r["empty_graph_flag"] == (1 if r.get("n_nodes", 0) == 0 else 0)
    assert any(r["empty_graph_flag"] == 1 for r in records), "corpus must contain empty graphs"
    assert any(r["empty_graph_flag"] == 0 for r in records)


# ---------------------------------------------------------------- T3
def test_n_bytes_absent_and_refused(records):
    assert "n_bytes" not in records[0]
    with pytest.raises(KeyError, match="n_bytes"):
        tb.matrix(records[:5], ["n_bytes"])


# ---------------------------------------------------------------- T4
def test_run_protocol_deterministic(records):
    a = tb.run_protocol(records, [20260922, 20260923])
    b = tb.run_protocol(records, [20260922, 20260923])
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    # and per-seed metrics land in a sane band (sanity, not a magic number)
    row = a["group"]["per_seed"][0]
    assert 0.0 <= row["graph"]["f1"] <= 1.0
    assert 0.0 <= row["trivial"]["f1"] <= 1.0


# ---------------------------------------------------------------- T5
def test_group_split_no_leakage(records):
    for seed in (20260922, 20260923):
        train, test = tb.make_group_split(records, tb.TEST_FRACTION, seed=seed)
        tr = {r["sample_id"] for r in train}
        te = {r["sample_id"] for r in test}
        assert not (tr & te)
        tr_pkg = {r["package"] for r in train}
        te_pkg = {r["package"] for r in test}
        assert not (tr_pkg & te_pkg), "package-family leakage"


# ---------------------------------------------------------------- T6
def test_mcnemar_degenerate_all_agree():
    y = [0, 1, 0, 1]
    p = [0.1, 0.9, 0.2, 0.8]
    res = tb.mcnemar_exact(y, p, p)
    assert res["p_value"] == 1.0
    assert res["method"] == "degenerate-all-agree"
    assert res["stat"] is None


def test_aggregate_all_zero_deltas_give_none_not_fabricated():
    per_seed = [{
        "df1_graph_minus_trivial": 0.0, "dauc_graph_minus_trivial": 0.0,
        "graph": {"f1": 0.5, "auc": 0.5}, "trivial": {"f1": 0.5, "auc": 0.5},
        "mcnemar_graph_vs_trivial": {"b01": 0, "b10": 0, "p_value": 1.0},
    }]
    agg = tb._aggregate(per_seed)
    assert agg["wilcoxon_exact_df1"]["p_value"] is None
    assert "not fabricated" in agg["wilcoxon_exact_df1"]["note"]


# ---------------------------------------------------------------- T7
def test_bootstrap_ci_seeded_deterministic():
    a = tb.bootstrap_ci_seed_level([0.01, 0.02, 0.03, 0.04])
    b = tb.bootstrap_ci_seed_level([0.01, 0.02, 0.03, 0.04])
    assert a == b
    assert a["ci_low"] <= a["mean"] <= a["ci_high"]


# ---------------------------------------------------------------- T8
@pytest.mark.skipif(not RESULTS.exists(), reason="run scripts/r11_trivial_baseline.py first")
def test_committed_results_provenance():
    res = json.loads(RESULTS.read_text())
    meta = res["meta"]
    assert meta["mock"] is False
    assert meta["seeds"] == list(range(20260922, 20260942))
    assert "n_bytes" in meta["n_bytes_disclosure"]
    assert "NOT comparable" in meta["comparability_note"]
    for scope in ("full_corpus", "with_graph_subset"):
        for split in ("group", "random"):
            agg = res[scope][split]["aggregate"]
            assert agg["n_seeds"] == 20
            assert "wilcoxon_exact_df1" in agg
            assert agg["bootstrap_mean_df1_ci95"]["n_boot"] == 10_000
    assert res["with_graph_subset"]["n_rows"] == 500
    assert res["with_graph_subset"]["n_rows_total"] == 603


# ----------------------------------------------- gen_paper_numbers --check
def test_numbers_tex_exists_and_is_generated():
    assert NUMBERS_TEX.exists()
    head = NUMBERS_TEX.read_text().splitlines()[0]
    assert "GENERATED by scripts/gen_paper_numbers.py" in head
    body = NUMBERS_TEX.read_text()
    assert "\\newcommand{\\pmGraphFedAvgFone}" in body


def test_gen_numbers_macros_reproducible():
    """Regenerating the macros in-memory must reproduce the file byte-for-byte
    (numbers.tex is never hand-edited)."""
    v = gpn.build_values()
    macros = gpn.build_macros(v)
    assert gpn.render_tex(macros) == NUMBERS_TEX.read_text()


def test_gen_numbers_check_passes():
    """The full --check pipeline (drift + rendered table rows + stale literals)."""
    v = gpn.build_values()
    macros = gpn.build_macros(v)
    problems = gpn.check_main(v, macros)
    assert problems == [], f"stale numbers detected: {problems}"
