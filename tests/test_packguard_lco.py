"""Round-13 tests: MinHash clustering determinism + LCO no-leakage +
degradation calculation (AMENDMENT-7). Corpus-dependent tests SKIP (not
fail) if the artifacts are absent, so the suite stays portable.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import numpy as np
import pytest

from packguard.clusters import (DSU, NUM_PERM, SEED, clusters_from_similarities,
                                estimate_jaccard, minhash_signature,
                                name_shingles, normalize_package_name,
                                pairwise_similarities, permutation_family,
                                sample_shingles, similarity_histogram,
                                word_shingles)
from packguard.lco import (aggregate, draw_lco_split, run_cell,
                           _trivial_matrix, TRIVIAL_NAMES, wilcoxon_exact)

ROOT = Path(__file__).resolve().parents[1]
CLUSTERS_T030 = ROOT / "outputs/packguard/lco/clusters_t030.json"
CLUSTERS_T050 = ROOT / "outputs/packguard/lco/clusters_t050.json"
SIGS = ROOT / "outputs/packguard/lco/signatures.npz"
FEATURES = ROOT / "outputs/packguard/features/features_v2.jsonl"
TEXT = ROOT / "outputs/packguard/features/text_v2.json"


# ---------------------------------------------------------------------------
# helpers: synthetic records
# ---------------------------------------------------------------------------
def _graph_feats(n_nodes: float) -> dict:
    """Real features_v2 keys (trivial block needs the metadata five)."""
    base = {k: 0.0 for k in (
        "hist_FILE_IO", "hist_NETWORK", "hist_PROCESS", "hist_CRYPTO",
        "hist_DYNAMIC_CODE", "hist_DATA_ACCESS", "n_edges", "density",
        "n_scopes", "max_repeat", "distinct_classes", "seq_depth",
        "n_import_classes")}
    base.update({"n_nodes": n_nodes, "n_files": max(1.0, n_nodes),
                 "parse_fail_files": 0.0, "has_setup": 0.0,
                 "has_postinstall": 0.0})
    return base


def make_records(n_benign=6, n_mal=6):
    recs = []
    k = 0
    for lab, n in ((0, n_benign), (1, n_mal)):
        for i in range(n):
            k += 1
            recs.append({
                "sample_id": f"s{k:03d}",
                "ecosystem": "npm" if k % 2 else "pypi",
                "label": lab,
                "package": f"pkg{lab}{i}",
                "features": {"graph": _graph_feats(float(k))},
            })
    return recs


# ---------------------------------------------------------------------------
# MinHash units
# ---------------------------------------------------------------------------
class TestMinHash:
    def test_signature_deterministic_and_order_insensitive(self):
        sh = sample_shingles("alpha beta gamma delta epsilon zeta",
                             "somepkg")
        s1 = minhash_signature(sh)
        s2 = minhash_signature(sorted(sh, reverse=True))
        assert (s1 == s2).all()
        assert s1.shape == (NUM_PERM,)

    def test_permutation_family_fixed_by_seed(self):
        a1, b1 = permutation_family(NUM_PERM, SEED)
        a2, b2 = permutation_family(NUM_PERM, SEED)
        assert (a1 == a2).all() and (b1 == b2).all()
        a3, _ = permutation_family(NUM_PERM, SEED + 1)
        assert not (a1 == a3).all()

    def test_jaccard_extremes(self):
        a = sample_shingles("one two three four five six", "pkgx")
        b = sample_shingles("one two three four five six", "pkgx")
        c = sample_shingles("entirely other words appear here now ok",
                            "pkgy")
        assert estimate_jaccard(minhash_signature(a), minhash_signature(b)) == 1.0
        assert estimate_jaccard(minhash_signature(a),
                                minhash_signature(c)) < 0.15

    def test_jaccard_close_to_exact(self):
        import itertools
        w1 = [f"w{i}" for i in range(30)]
        sh1 = word_shingles(" ".join(w1))
        sh2 = set(list(sh1)[:40]) | {"cod:extra one two"}
        inter, uni = len(sh1 & sh2), len(sh1 | sh2)
        est = estimate_jaccard(minhash_signature(sorted(sh1)),
                               minhash_signature(sorted(sh2)))
        assert abs(est - inter / uni) < 0.15

    def test_no_external_minhash_library(self):
        import packguard.clusters as C
        src = Path(C.__file__).read_text()
        for lib in ("datasketch", "mmh3", "pyminhash"):
            assert lib not in src


class TestShingling:
    def test_typosquat_filler_stripping(self):
        assert normalize_package_name("aws-user-helper-js")[1] == \
            ["aws", "user", "helper"]
        assert normalize_package_name("pyfoo-core")[1] == ["pyfoo"]
        assert normalize_package_name("jslib")[1] == ["jslib"]  # middle intact
        n, toks = normalize_package_name("@antoncallahan@aws-user-helper")
        assert toks[0] == "scope:antoncallahan"

    def test_empty_text_still_clusterable_via_name(self):
        sh = sample_shingles("", "left-pad")
        assert sh and all(s.startswith("nme:") for s in sh)

    def test_histogram_shape(self):
        ids = ["a", "b", "c", "d"]
        sims = np.eye(4)
        h = similarity_histogram(sims)
        assert len(h) == 20
        assert sum(n for _, _, n in h) == len(ids) * (len(ids) - 1) // 2


class TestClustering:
    def test_unionfind_and_threshold(self):
        ids = ["a", "b", "c"]
        sims = np.array([[1.0, 0.9, 0.0], [0.9, 1.0, 0.0], [0.0, 0.0, 1.0]])
        got = clusters_from_similarities(ids, sims, 0.5)
        assert got["a"] == got["b"] != got["c"]
        got2 = clusters_from_similarities(ids, sims, 0.95)
        assert len(set(got2.values())) == 3

    def test_dsu_deterministic(self):
        d = DSU(["x", "y", "z"])
        d.union("y", "x")
        assert d.find("x") == d.find("y")
        groups = d.groups()
        assert list(groups) == sorted(groups)

    def test_synthetic_corpus_clusters(self):
        text_a = " ".join(f"tok{i}" for i in range(200))
        text_a2 = text_a + " small addition here"
        text_b = " ".join(f"zzz{i}" for i in range(200))
        rows = [
            {"sample_id": "a1", "package": "fa", "label": 1, "ecosystem": "npm"},
            {"sample_id": "a2", "package": "fa", "label": 1, "ecosystem": "npm"},
            {"sample_id": "b1", "package": "fb", "label": 0, "ecosystem": "pypi"},
        ]
        cache = {"a1": text_a, "a2": text_a2, "b1": text_b}
        from packguard.clusters import build_corpus_clusters
        assign, aux = build_corpus_clusters(rows, cache, 0.3,
                                            signature_cache=None,
                                            verbose=False)
        assert assign["a1"] == assign["a2"]
        assert assign["b1"] != assign["a1"]
        assert aux["meta"]["known_family_check"][
            "n_multi_version_packages_split_across_clusters"] == 0


# ---------------------------------------------------------------------------
# corpus-level clustering gate (skips without artifacts)
# ---------------------------------------------------------------------------
@pytest.mark.skipif(not CLUSTERS_T030.exists(), reason="corpus clusters missing")
class TestCorpusClusters:
    def test_known_family_one_cluster(self):
        c = json.load(open(CLUSTERS_T030))
        m = c["meta"]
        anton = m["known_family_check"]["antoncallahan_aws_user_helper"]
        assert anton["n_samples"] == 31 and anton["n_clusters"] == 1
        # the 4 round-12 versions co-cluster (they are in the same unit)
        cl = [cid for sid, cid in c["assignment"].items()
             if "antoncallahan" in sid]
        assert len(set(cl)) == 1

    def test_no_split_families_no_mixed_labels(self):
        c = json.load(open(CLUSTERS_T030))
        m = c["meta"]
        assert m["known_family_check"][
            "n_multi_version_packages_split_across_clusters"] == 0
        assert m["n_mixed_label_clusters"] == 0

    def test_assignment_covers_corpus(self):
        rows = [json.loads(l) for l in FEATURES.open() if l.strip()]
        c = json.load(open(CLUSTERS_T030))
        assert set(c["assignment"]) == {r["sample_id"] for r in rows}

    def test_recompute_deterministic_from_signatures(self):
        rows = [json.loads(l) for l in FEATURES.open() if l.strip()]
        text_cache = json.load(open(TEXT))
        ids = sorted(r["sample_id"] for r in rows)
        z = np.load(SIGS)
        assert list(z["ids"]) == ids
        by_id = {r["sample_id"]: r for r in rows}
        # recompute 3 signatures from scratch -> identical to cached npz
        for sid in ids[:3]:
            sh = sample_shingles(text_cache.get(sid, "") or "",
                                 by_id[sid].get("package") or sid)
            assert (minhash_signature(sh) == z["sigs"][ids.index(sid)]).all()
        # recompute clusters at 0.3 from cached signatures -> identical
        from packguard.clusters import clusters_from_similarities
        sims = pairwise_similarities(z["sigs"])
        re = clusters_from_similarities(ids, sims, 0.3)
        # note: re is the PRE-closure similarity clustering; the stored file
        # adds package closure. Check instead that closure only merges:
        c = json.load(open(CLUSTERS_T030))
        for sid, cid in re.items():
            assert c["assignment"][sid]
        pre = {s: r for s, r in re.items()}
        pairs_pre = {frozenset(v) for v in _members(pre).values()}
        pairs_post = {frozenset(v) for v in
                      _members(c["assignment"]).values()}
        for block in pairs_pre:
            assert any(block <= b for b in pairs_post), \
                "closure must only merge, never split"

    def test_sensitivity_threshold_050_exists(self):
        assert CLUSTERS_T050.exists()
        c5 = json.load(open(CLUSTERS_T050))
        assert c5["meta"]["threshold"] == 0.5
        assert c5["meta"]["known_family_check"][
            "n_multi_version_packages_split_across_clusters"] == 0


def _members(assign):
    out = {}
    for sid, cid in assign.items():
        out.setdefault(cid, []).append(sid)
    return out


# ---------------------------------------------------------------------------
# LCO split: no-leakage + validity
# ---------------------------------------------------------------------------
class TestLCOSplit:
    def test_no_leakage_and_validity(self):
        recs = make_records()
        cluster_of = {r["sample_id"]: f"c{i%10}" for i, r in
                      enumerate(recs)}  # 2 samples/cluster, same label
        train, test, info = draw_lco_split(recs, cluster_of, seed=SEED)
        tr_c = {cluster_of[r["sample_id"]] for r in train}
        te_c = {cluster_of[r["sample_id"]] for r in test}
        assert not (tr_c & te_c)
        assert not ({r["package"] for r in train} &
                    {r["package"] for r in test})
        assert not ({r["sample_id"] for r in train} &
                    {r["sample_id"] for r in test})
        assert info["valid"] and info["n_test_clusters"] == 2  # ~20% of 10
        assert info["test_labels"]["malicious"] > 0
        assert info["test_labels"]["benign"] > 0

    def test_package_spanning_two_clusters_fires_assert(self):
        # two "versions" of one package forced into DIFFERENT clusters: a
        # cluster map that did NOT close over packages must be rejected the
        # moment the draw separates them (deterministic seed sweep).
        recs = make_records()
        recs.append({"sample_id": "s901", "ecosystem": "npm", "label": 0,
                     "package": "pkg00",
                     "features": {"graph": _graph_feats(99.0)}})
        cluster_of = {r["sample_id"]: f"c{i%10}" for i, r in
                      enumerate(recs)}
        victim = sorted(r["sample_id"] for r in recs
                        if r["package"] == "pkg00")
        assert len(victim) >= 2
        cluster_of[victim[0]] = "cX0"
        cluster_of[victim[1]] = "cX1"
        raised = False
        for seed in range(SEED, SEED + 60):
            try:
                draw_lco_split(recs, cluster_of, seed=seed)
            except AssertionError:
                raised = True
                break
        assert raised, "package straddling two clusters never caught"

    def test_deterministic_across_calls(self):
        recs = make_records()
        cluster_of = {r["sample_id"]: f"c{i%10}" for i, r in enumerate(recs)}
        _, _, i1 = draw_lco_split(recs, cluster_of, seed=123)
        _, _, i2 = draw_lco_split(recs, cluster_of, seed=123)
        assert i1["held_cluster_ids"] == i2["held_cluster_ids"]


# ---------------------------------------------------------------------------
# degradation calculation (registered endpoint)
# ---------------------------------------------------------------------------
def _fake_result(deg_graph, deg_text):
    """Rows as emitted by run_lco, with controlled degradations."""
    rows = []
    for i, (dg, dt) in enumerate(zip(deg_graph, deg_text)):
        seed = 20260922 + i
        for block, d in (("graph", dg), ("hashing_tfidf", dt)):
            rows.append({
                "kind": "run", "threshold": 0.3, "seed": seed,
                "block": block, "method": "strong_centralized",
                "split": "group_inrunner", "f1": 0.9 + d, "auc": 0.9 + d,
                "precision": 0.9, "recall": 0.9, "degradation_f1": d,
                "degradation_auc": d, "n_train": 400, "n_test": 100,
                "n_test_malicious": 50, "C_selected": 1.0, "mock": False,
                "date": "x",
            })
    return {"rows": rows, "meta": {}}


class TestDegradationCalc:
    def test_graph_degrades_more(self):
        # deg = LCO - group (negative = drop). Graph drops MORE => dd
        # = deg(graph) - deg(text) = -0.15 NEGATIVE (registered convention).
        res = _fake_result([-0.2] * 8, [-0.05] * 8)
        agg = aggregate(res)
        t = [x for x in agg["paired_tests"] if x["method"] ==
             "strong_centralized"][0]
        assert t["n_seeds"] == 8
        assert abs(t["dd_f1_mean"] - (-0.15)) < 1e-9
        assert t["wilcoxon_f1"]["n_neg"] == 8 and \
            t["wilcoxon_f1"]["n_pos"] == 0
        assert t["wilcoxon_f1"]["p"] == pytest.approx(2 / 2**8)

    def test_all_zero_deltas_honest_none(self):
        res = _fake_result([0.0] * 6, [0.0] * 6)
        agg = aggregate(res)
        t = agg["paired_tests"][0]
        assert t["wilcoxon_f1"]["p"] is None
        assert "all deltas zero" in t["wilcoxon_f1"]["note"]

    def test_text_degrades_more_negative_dd(self):
        # text drops more (-0.10 vs -0.02) => dd = +0.08 positive
        res = _fake_result([-0.02] * 10, [-0.10] * 10)
        agg = aggregate(res)
        t = agg["paired_tests"][0]
        assert t["dd_f1_mean"] == pytest.approx(0.08)
        assert t["wilcoxon_f1"]["n_pos"] == 10


class TestTrivialBlock:
    def test_trivial_matrix(self):
        recs = make_records(2, 2)
        X = _trivial_matrix(recs)
        assert X.shape == (4, len(TRIVIAL_NAMES))
        assert set(TRIVIAL_NAMES) == {"n_files", "parse_fail_files",
                                      "empty_graph_flag", "has_setup",
                                      "has_postinstall"}
        r0 = recs[0]
        assert X[0][TRIVIAL_NAMES.index("empty_graph_flag")] == \
            (1.0 if r0["features"]["graph"]["n_nodes"] == 0 else 0.0)


@pytest.mark.skipif(not CLUSTERS_T030.exists() or not FEATURES.exists(),
                    reason="corpus artifacts missing")
class TestRunCellOnRealCorpus:
    def test_run_cell_smoke_graph_and_trivial(self):
        rows = [json.loads(l) for l in FEATURES.open() if l.strip()]
        rows = [r for r in rows if not r.get("extraction_error")]
        from packguard.features import FEATURE_NAMES
        recs = []
        for r in rows:
            feats = {k: float(r[k]) for k in FEATURE_NAMES if k in r}
            rec = {k: v for k, v in r.items() if k not in set(FEATURE_NAMES)}
            rec["features"] = {"graph": feats}
            recs.append(rec)
        cluster_of = json.load(open(CLUSTERS_T030))["assignment"]
        train, test, info = draw_lco_split(recs, cluster_of, seed=SEED)
        assert info["valid"]
        for block in ("graph", "trivial"):
            out = run_cell(train, test, block, seed=SEED)
            m = out["methods"]["strong_centralized"]["final_metrics"]
            assert 0.0 <= m["f1"] <= 1.0
            assert out["methods"]["fedavg"]["final_metrics"] is not None
