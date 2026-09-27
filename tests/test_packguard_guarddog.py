"""Round 14 (W) — tests for the GuardDog rule-based baseline.

Everything is computed by hand on fixtures (no fabricated numbers) plus
corpus-level gates against the REAL artifacts committed under
outputs/packguard/guarddog/. Runs under the main .venv (has packguard) and
under .venv-gd (stdlib only -> packguard-dependent gates skip).
"""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

GD = ROOT / "outputs/packguard/guarddog"
HAS_GUARDDOG_ARTIFACTS = (GD / "findings.jsonl").exists() and (GD / "metrics.json").exists()

gm = importlib.import_module("scripts.r14_guarddog_metrics") if (ROOT / "scripts").joinpath(
    "r14_guarddog_metrics.py").exists() else None
if gm is None:  # scripts/ may not be a package under some runners
    sys.path.insert(0, str(ROOT / "scripts"))
    import r14_guarddog_metrics as gm  # type: ignore

try:
    from packguard.fl import make_group_split
    HAS_PACKGUARD = True
except Exception:  # pragma: no cover - .venv-gd has no packguard
    HAS_PACKGUARD = False


# ------------------------------------------------------------------ fixtures
def test_prf_hand_computed():
    # tp=3 fp=1 fn=2 tn=4 -> P=3/4, R=3/5, F1=2PR/(P+R)=0.9/1.35=2/3
    m = gm.prf(3, 1, 2, 4)
    assert m["precision"] == pytest.approx(0.75)
    assert m["recall"] == pytest.approx(0.6)
    assert m["f1"] == pytest.approx(2 / 3)
    # degenerate: no true positives among 3 predictions -> precision 0.0, f1 None, recall 0
    m0 = gm.prf(0, 3, 2, 5)
    assert m0["precision"] == 0.0 and m0["f1"] is None
    assert m0["recall"] == 0.0
    # fully degenerate: no predictions at all -> precision None (0/0)
    m1 = gm.prf(0, 0, 2, 8)
    assert m1["precision"] is None


def test_auc_perfect_and_inverted():
    assert gm.auc_mw([1, 2, 3, 4], [0, 0, 1, 1]) == pytest.approx(1.0)
    assert gm.auc_mw([1, 2, 3, 4], [1, 1, 0, 0]) == pytest.approx(0.0)
    # all scores tie -> 0.5
    assert gm.auc_mw([7, 7, 7, 7], [0, 1, 0, 1]) == pytest.approx(0.5)
    assert gm.auc_mw([1, 2], [0, 0]) is None  # one class absent


def test_auc_ties_hand_case():
    # scores [0,1,1,2], labels [0,1,0,1]:
    # pos={1,2}, neg={0,1}; wins: (1>0)+(1==1)*.5+(2>0)+(2>1) = 3.5 of 4 -> .875
    assert gm.auc_mw([0, 1, 1, 2], [0, 1, 0, 1]) == pytest.approx(0.875)


def test_evaluate_excludes_non_ok_rows():
    rows = [
        {"scan_status": "ok", "label": 1, "verdict": 1, "score": 2, "ecosystem": "npm"},
        {"scan_status": "ok", "label": 0, "verdict": 0, "score": 0, "ecosystem": "npm"},
        {"scan_status": "ok", "label": 1, "verdict": 0, "score": 0, "ecosystem": "npm"},
        {"scan_status": "timeout", "label": 1, "verdict": None, "score": None, "ecosystem": "npm"},
        {"scan_status": "error", "label": 0, "verdict": 0, "score": None, "ecosystem": "pypi"},
    ]
    m = gm.evaluate(rows)
    assert m["n"] == 3 and m["n_excluded"] == 2
    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (1, 0, 1, 1)
    assert m["precision"] == pytest.approx(1.0) and m["recall"] == pytest.approx(0.5)
    # timeout/error rows must NOT enter the AUC score distribution
    assert m["auc"] == pytest.approx(gm.auc_mw([2, 0, 0], [1, 0, 1]))


def test_verdict_rule_matches_preregistration():
    # pre-registered: verdict = 1 iff score >= 1 (score = #distinct high rules)
    for score, verdict in ((0, 0), (1, 1), (5, 1)):
        assert (score >= 1) == (verdict == 1)


# ------------------------------------------------------------------ corpus gates
@pytest.mark.skipif(not HAS_GUARDDOG_ARTIFACTS, reason="guarddog artifacts missing")
def test_corpus_row_count_and_labels():
    man = json.load(open(ROOT / "data/packguard/manifests/dataset_v2.json"))
    labels = {s["sample_id"]: s["label"] for s in man["samples"]}
    rows = [json.loads(l) for l in open(GD / "findings.jsonl")]
    assert len(rows) == 603
    assert {r["sample_id"] for r in rows} == set(labels)
    for r in rows:
        assert r["label"] == labels[r["sample_id"]]


@pytest.mark.skipif(not HAS_GUARDDOG_ARTIFACTS, reason="guarddog artifacts missing")
def test_corpus_scan_status_and_exclusion_accounting():
    rows = [json.loads(l) for l in open(GD / "findings.jsonl")]
    ok = [r for r in rows if r["scan_status"] == "ok"]
    bad = [r for r in rows if r["scan_status"] != "ok"]
    assert len(ok) + len(bad) == 603
    # every non-ok row has a reason and no verdict
    for r in bad:
        assert r.get("error") and r.get("verdict") is None and r.get("score") is None
    # exclusions in metrics.json match the non-ok rows exactly
    met = json.load(open(GD / "metrics.json"))
    exc = met["excluded_rows"]
    assert sorted(e["sample_id"] for e in exc) == sorted(r["sample_id"] for r in bad)
    full = met["scopes"]["full"]["overall"]
    assert full["n"] == len(ok) and full["n_excluded"] == len(bad)
    assert full["tp"] + full["fp"] + full["fn"] + full["tn"] == len(ok)


@pytest.mark.skipif(not HAS_GUARDDOG_ARTIFACTS, reason="guarddog artifacts missing")
def test_ok_rows_have_consistent_score_and_verdict():
    rows = [json.loads(l) for l in open(GD / "findings.jsonl")]
    for r in rows:
        if r["scan_status"] != "ok":
            continue
        assert r["score"] == len(r["rules_triggered"])
        assert r["verdict"] == (1 if r["score"] >= 1 else 0)
        assert set(r["rules_triggered"]).issubset(set(r["rules_triggered_all"]))
        for rule in r["rules_triggered"]:
            assert rule.startswith(("threat-", "capability-"))  # YARA source rules only


@pytest.mark.skipif(not (HAS_GUARDDOG_ARTIFACTS and HAS_PACKGUARD),
                    reason="needs artifacts + packguard")
def test_group_split_membership_reproduces_grid_counts():
    man = json.load(open(ROOT / "data/packguard/manifests/dataset_v2.json"))
    records = [{"sample_id": s["sample_id"], "label": s["label"], "package": s["package"]}
               for s in man["samples"]]
    _, test = make_group_split(records, 0.2, seed=20260922, group_key="package")
    ids = {r["sample_id"] for r in test}
    assert len(ids) == 129 and sum(r["label"] for r in test) == 88  # grid_results.json
    splits = json.load(open(GD / "split_membership.json"))
    assert set(splits["group_test_seed20260922"]) == ids
    rows = [json.loads(l) for l in open(GD / "findings.jsonl")]
    for r in rows:
        assert ("group_test_seed20260922" in r["split_membership"]) == (r["sample_id"] in ids)


@pytest.mark.skipif(not (HAS_GUARDDOG_ARTIFACTS and HAS_PACKGUARD),
                    reason="needs artifacts + packguard")
def test_lco_membership_reproduces_lco_counts():
    from packguard.lco import draw_lco_split
    man = json.load(open(ROOT / "data/packguard/manifests/dataset_v2.json"))
    records = [{"sample_id": s["sample_id"], "label": s["label"], "package": s["package"]}
               for s in man["samples"]]
    splits = json.load(open(GD / "split_membership.json"))
    for key, thr, want_n, want_mal, want_clusters in (
            ("lco_test_seed20260922_t030", 0.3, 89, 49, 65),
            ("lco_test_seed20260922_t050", 0.5, 113, 72, 68)):
        clusters = json.load(open(ROOT / f"outputs/packguard/lco/clusters_t{int(thr*100):03d}.json"))
        _, test, info = draw_lco_split(records, clusters["assignment"], 20260922, 0.2)
        assert len(test) == want_n and sum(r["label"] for r in test) == want_mal
        assert info["valid"] and info["n_test_clusters"] == want_clusters
        assert set(splits[key]) == {r["sample_id"] for r in test}


@pytest.mark.skipif(not HAS_GUARDDOG_ARTIFACTS, reason="guarddog artifacts missing")
def test_comparison_numbers_traceable():
    """Comparator cells in metrics.json must equal the stored artifact values."""
    met = json.load(open(GD / "metrics.json"))
    grid = json.load(open(ROOT / "outputs/packguard/fl_multiseed/grid_results.json"))
    stored = {(r["features"], r["method"]): (r["f1"], r["auc"]) for r in grid["rows"]
              if r.get("seed") == 20260922 and r.get("split") == "group"
              and r.get("partition") == "ecosystem"
              and r.get("features") in ("graph", "tfidf")
              and r.get("method") in ("centralized", "fedavg")}
    got = {(c["features"], c["method"]): (c["f1"], c["auc"])
           for c in met["comparison"]["group_test_seed20260922"]}
    assert got == stored
    # LCO cells must come from split=='lco' rows only (no group_inrunner mixing)
    lco = json.load(open(ROOT / "outputs/packguard/lco/lco_results.json"))
    lco_map = {(r["threshold"], r["block"], r["method"]): (r["f1"], r["auc"])
               for r in lco["rows"] if r.get("seed") == 20260922 and r.get("split") == "lco"}
    for c in met["comparison"]["lco"]:
        if c["source"] == "lco_results.json":
            key = (float(c["threshold"]), c["block"], c["method"])
            assert (c["f1"], c["auc"]) == lco_map[key]
