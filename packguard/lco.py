"""Leave-cluster-out (LCO) split + runner for PackGuard (round 13, AMENDMENT-7).

Answers the paper's open robustness question: "graph vs hashing-text
degradation under family shift must decide any robustness claim". The
round-11 group split (packguard.fl.make_group_split) holds out PACKAGE
families; LCO holds out whole MinHash SIMILARITY CLUSTERS
(packguard.clusters) — near-duplicate/typosquat families cannot straddle
the split at all.

Protocol (registered BEFORE any LCO run — AMENDMENT-7):
  * Clusters: MinHash(128, seed 20260922) over code-text word-3-gram +
    name-pattern shingles; union-find at a threshold registered from the
    pairwise-similarity histogram (primary) with sensitivity at the other
    of {0.3, 0.5}.
  * Per seed s in 20260922..20260941: draw round(20%) of clusters into
    TEST, stratified by cluster MAJORITY label (draw per stratum; mixed
    clusters go to their majority stratum; there are none in this corpus
    — disclosed). Train = every other cluster.
  * Asserts (hard): train/test share NO cluster, NO package, NO sample_id.
  * Methods: strong_centralized + FedAvg under the round-11 strong recipe
    (packguard.strong_baseline: lbfgs LR, StandardScaler on pooled TRAIN,
    C by 3-fold train-only CV). Blocks: graph, hashing_tfidf (stateless
    HashingVectorizer), trivial (5 metadata features — the r11 shortcut
    check, here under family shift).
  * PAIRED degradation per (seed, block, method): d = F1_LCO - F1_group
    where group = packguard.fl.make_group_split under the SAME plumbing
    in this same run (registered pairing basis; the stored round-11 p0
    group numbers are cited as an external consistency check only).
    Primary comparison: d(graph) vs d(hashing_tfidf) per seed, exact
    two-sided Wilcoxon over the 20 paired differences (n=20 -> min p
    2/2^20 ~ 1.9e-6, alpha reachable).
  * Validity: a seed's LCO split is VALID iff test carries both labels;
    the count of valid seeds is reported and only valid seeds enter
    aggregates (invalid seeds disclosed, never silently dropped).

Outputs: outputs/packguard/lco/lco_results.json + summary.md.
CLI: .venv/bin/python -m packguard.lco --config configs/packguard_lco.yaml
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

from packguard.fl import compute_clf_metrics, make_group_split
from packguard.strong_baseline import (
    C_GRID,
    fedavg_sklearn,
    fit_lr,
    fit_scaler,
    probs_from_theta,
    select_c_cv,
    strong_centralized,
)

SCHEMA_VERSION = "lco-v1"
SEED = 20260922
DEFAULT_SEEDS = list(range(20260922, 20260942))   # AMENDMENT-4 set
TEST_FRACTION = 0.2
METHODS = ("strong_centralized", "fedavg")
BLOCKS = ("graph", "hashing_tfidf", "trivial")

TRIVIAL_NAMES = ("n_files", "parse_fail_files", "empty_graph_flag",
                 "has_setup", "has_postinstall")


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------
def load_corpus(features_jsonl: str, text_json: str) -> Tuple[List[dict], dict]:
    """Flat features_v2 rows -> nested {"features": {"graph": {...}}} records
    (same wrapping as packguard.fl.load_feature_records, minus api_calls which
    LCO does not use) + the text cache."""
    from packguard.features import FEATURE_NAMES

    rows = [json.loads(l) for l in open(features_jsonl, encoding="utf-8")
            if l.strip()]
    records, n_dropped = [], 0
    for r in rows:
        if r.get("extraction_error"):
            n_dropped += 1
            continue
        feats = {k: float(r[k]) for k in FEATURE_NAMES if k in r}
        rec = {k: v for k, v in r.items() if k not in set(FEATURE_NAMES)}
        rec["features"] = {"graph": feats}
        records.append(rec)
    text_cache = json.load(open(text_json, encoding="utf-8"))
    meta = {"features_source": os.path.abspath(features_jsonl),
            "text_source": os.path.abspath(text_json),
            "n_rows_dropped_extraction_error": n_dropped,
            "n_records": len(records), "mock": False}
    return records, meta


def design_matrix(records: List[dict], block: str,
                  text_cache: Optional[dict[str, str]] = None):
    if block == "graph":
        return _graph_matrix(records)
    if block == "trivial":
        return _trivial_matrix(records)
    if block == "hashing_tfidf":
        if text_cache is None:
            raise ValueError("hashing_tfidf needs the text cache")
        from packguard.strong_baseline import HashingTextFeaturizer
        return HashingTextFeaturizer().transform(
            [text_cache.get(str(r["sample_id"]), "") or "" for r in records])
    raise ValueError(f"unknown block {block!r}")


def _graph_matrix(records: List[dict]) -> np.ndarray:
    names = sorted(records[0]["features"]["graph"])
    return np.array([[float(r["features"]["graph"][n]) for n in names]
                     for r in records], dtype=np.float64)


def _trivial_matrix(records: List[dict]) -> np.ndarray:
    """5 metadata features (r11 shortcut set); empty_graph_flag derived from
    n_nodes (NOT present as its own column in features_v2)."""
    out = np.empty((len(records), len(TRIVIAL_NAMES)), dtype=np.float64)
    for i, r in enumerate(records):
        g = r["features"]["graph"]
        out[i] = [float(g["n_files"]), float(g["parse_fail_files"]),
                  1.0 if float(g["n_nodes"]) == 0.0 else 0.0,
                  float(g["has_setup"]), float(g["has_postinstall"])]
    return out


# ---------------------------------------------------------------------------
# LCO split
# ---------------------------------------------------------------------------
def cluster_majority_label(member_rows: Sequence[dict]) -> int:
    """Majority label of a cluster; exact tie -> malicious (deterministic;
    disclosed: the corpus has NO mixed-label cluster at either threshold)."""
    n_mal = sum(1 for r in member_rows if int(r["label"]) == 1)
    return 1 if 2 * n_mal >= len(member_rows) else 0


def draw_lco_split(records: List[dict], cluster_of: Dict[str, str],
                   seed: int, test_fraction: float = TEST_FRACTION
                   ) -> Tuple[List[dict], List[dict], dict]:
    """Hold out ~test_fraction of CLUSTERS as test, stratified by cluster
    majority label. Hard asserts: no cluster/package/sample_id overlap."""
    members: Dict[str, List[dict]] = {}
    for r in records:
        members.setdefault(cluster_of[str(r["sample_id"])], []).append(r)
    cids = sorted(members)
    strata: Dict[int, List[str]] = {0: [], 1: []}
    for cid in cids:
        strata[cluster_majority_label(members[cid])].append(cid)

    rng = random.Random(seed)
    held: List[str] = []
    draw_info: Dict[str, Dict] = {}
    for lab in (0, 1):
        pool = sorted(strata[lab])
        rng.shuffle(pool)
        k = max(1, int(round(len(pool) * float(test_fraction))))
        held.extend(pool[:k])
        draw_info[str(lab)] = {"n_clusters_stratum": len(pool),
                               "n_held": k}
    held_set = set(held)
    test_ids = {r["sample_id"] for cid in held for r in members[cid]}
    test = [r for r in records if str(r["sample_id"]) in test_ids]
    train = [r for r in records if str(r["sample_id"]) not in test_ids]

    # --- hard no-leakage asserts (C2/C5) -----------------------------------
    tr_clusters = {cluster_of[str(r["sample_id"])] for r in train}
    te_clusters = {cluster_of[str(r["sample_id"])] for r in test}
    assert not (tr_clusters & te_clusters), "CLUSTER leakage train<->test"
    tr_pkgs = {str(r.get("package")) for r in train}
    te_pkgs = {str(r.get("package")) for r in test}
    assert not (tr_pkgs & te_pkgs), "package leakage train<->test"
    assert not (test_ids & {str(r["sample_id"]) for r in train}), "sample leakage"
    assert tr_clusters | te_clusters == set(cids) and len(held_set) == len(held)

    y_te = [int(r["label"]) for r in test]
    y_tr = [int(r["label"]) for r in train]
    info = {
        "n_clusters_total": len(cids),
        "n_test_clusters": len(held),
        "test_cluster_share": round(len(held) / len(cids), 4),
        "n_train_samples": len(train), "n_test_samples": len(test),
        "test_sample_share": round(len(test) / len(records), 4),
        "draw_by_stratum": draw_info,
        "test_labels": {"benign": y_te.count(0), "malicious": y_te.count(1)},
        "train_labels": {"benign": y_tr.count(0), "malicious": y_tr.count(1)},
        "held_cluster_ids": sorted(held_set),
        "valid": bool(y_te.count(0) > 0 and y_te.count(1) > 0
                      and y_tr.count(0) > 0 and y_tr.count(1) > 0),
    }
    return train, test, info


# ---------------------------------------------------------------------------
# One cell: strong recipe on a given train/test pair (round-11 protocol)
# ---------------------------------------------------------------------------
def _fedavg_params(client_X, client_y, C: float, rounds: int = 2):
    return fedavg_sklearn(client_X, client_y, C, rounds=rounds)


def run_cell(train_records: List[dict], test_records: List[dict], block: str,
             seed: int, text_cache: Optional[dict] = None,
             fedavg_rounds: int = 2, c_grid: Sequence[float] = C_GRID,
             ) -> dict:
    """strong_centralized + fedavg for one (train, test, block); the exact
    round-11 strong recipe (A5.1/A5.2): pooled-train scaler, train-only CV C,
    lbfgs LR; FedAvg = local lbfgs fits + n-weighted average over the
    ecosystem partition. Returns metrics + provenance (no fabricated nums)."""
    Xtr_raw = design_matrix(train_records, block, text_cache)
    Xte_raw = design_matrix(test_records, block, text_cache)
    sc = fit_scaler(Xtr_raw)
    Xs_tr, Xs_te = sc.transform(Xtr_raw), sc.transform(Xte_raw)
    y_tr = np.array([int(r["label"]) for r in train_records], dtype=int)
    y_te = [int(r["label"]) for r in test_records]

    cv = select_c_cv(Xs_tr, y_tr, seed=seed, c_grid=c_grid)
    C = cv["C_selected"]

    methods: Dict[str, Any] = {}
    cent = strong_centralized(Xs_tr, y_tr, C)
    methods["strong_centralized"] = {
        "final_metrics": compute_clf_metrics(y_te, probs_from_theta(
            cent["theta"], Xs_te)),
        "converged": cent["converged"],
    }

    part: Dict[str, List[int]] = {}
    for i, r in enumerate(train_records):
        part.setdefault(str(r["ecosystem"]), []).append(i)
    client_X = [Xs_tr[part[cn]] for cn in sorted(part)]
    client_y = [y_tr[part[cn]] for cn in sorted(part)]
    single_class = [cn for cn, yy in zip(sorted(part), client_y)
                    if len(set(yy.tolist())) < 2]
    if single_class:
        methods["fedavg"] = {
            "final_metrics": None,
            "skipped_reason": ("single-class client(s) under LCO: "
                               + ",".join(single_class)),
        }
    else:
        avg = _fedavg_params(client_X, client_y, C, rounds=fedavg_rounds)
        methods["fedavg"] = {
            "final_metrics": compute_clf_metrics(y_te, probs_from_theta(
                avg["theta"], Xs_te)),
            "client_sizes": {cn: int(len(part[cn])) for cn in sorted(part)},
        }
    return {"C_selected": float(C), "methods": methods,
            "scaler": ("StandardScaler(with_mean=False) on pooled TRAIN"
                       if hasattr(Xtr_raw, "tocsr")
                       else "StandardScaler on pooled TRAIN")}


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------
def wilcoxon_exact(diffs: Sequence[float]) -> dict:
    """Exact two-sided Wilcoxon signed-rank (+ sign counts). All-zero diffs
    -> p=None with an honest note (never a fabricated p)."""
    from scipy.stats import wilcoxon

    d = np.asarray(diffs, dtype=float)
    if len(d) < 2:
        return {"p": None, "note": "n<2", "n_pos": int((d > 0).sum()),
                "n_neg": int((d < 0).sum()), "n_zero": int((d == 0).sum())}
    if np.allclose(d, 0.0):
        return {"p": None, "note": "all deltas zero; test undefined",
                "n_pos": 0, "n_neg": 0, "n_zero": len(d)}
    res = wilcoxon(d, alternative="two-sided", mode="exact"
                   if (d != 0).sum() <= 25 else "approx")
    return {"p": float(res.pvalue),
            "method": "exact" if (d != 0).sum() <= 25 else "approx",
            "n_pos": int((d > 0).sum()), "n_neg": int((d < 0).sum()),
            "n_zero": int((d == 0).sum())}


def mean_std(xs: Sequence[Optional[float]]) -> Tuple[Optional[float], Optional[float]]:
    v = [x for x in xs if x is not None]
    if not v:
        return None, None
    return float(statistics.mean(v)), (float(statistics.stdev(v))
                                       if len(v) > 1 else 0.0)


# ---------------------------------------------------------------------------
# Full grid
# ---------------------------------------------------------------------------
def run_lco(features_jsonl: str, text_json: str,
            cluster_files: Dict[str, str],
            seeds: Sequence[int] = tuple(DEFAULT_SEEDS),
            outdir: str = "outputs/packguard/lco",
            fedavg_rounds: int = 2,
            ) -> dict:
    """cluster_files: {threshold_str: path to clusters_*.json}. The FIRST key
    is the PRIMARY threshold (registration order in the config)."""
    records, load_meta = load_corpus(features_jsonl, text_json)
    text_cache = json.load(open(text_json, encoding="utf-8"))
    date = datetime.now(timezone.utc).isoformat()

    rows: List[dict] = []
    per_threshold: Dict[str, dict] = {}
    for thr, cpath in cluster_files.items():
        clu = json.load(open(cpath, encoding="utf-8"))
        cluster_of = {sid: cid for sid, cid in clu["assignment"].items()}
        n_valid = 0
        for seed in seeds:
            train, test, info = draw_lco_split(records, cluster_of, seed)
            gtrain, gtest = make_group_split(records, TEST_FRACTION, seed)
            if not info["valid"]:
                rows.append({"kind": "lco_invalid", "threshold": float(thr),
                             "seed": seed, "split_info": info,
                             "mock": False, "date": date})
                continue
            n_valid += 1
            for block in BLOCKS:
                lco_res = run_cell(train, test, block, seed, text_cache,
                                   fedavg_rounds)
                grp_res = run_cell(gtrain, gtest, block, seed, text_cache,
                                   fedavg_rounds)
                for meth in METHODS:
                    lm = lco_res["methods"][meth]["final_metrics"]
                    gm = grp_res["methods"][meth]["final_metrics"]
                    row = {
                        "kind": "run", "threshold": float(thr),
                        "seed": seed, "block": block, "method": meth,
                        "split": "lco",
                        "f1": None if lm is None else lm["f1"],
                        "auc": None if lm is None else lm["auc"],
                        "precision": None if lm is None else lm["precision"],
                        "recall": None if lm is None else lm["recall"],
                        "n_train": info["n_train_samples"],
                        "n_test": info["n_test_samples"],
                        "n_test_malicious": info["test_labels"]["malicious"],
                        "n_test_clusters": info["n_test_clusters"],
                        "n_clusters_total": info["n_clusters_total"],
                        "C_selected": lco_res["C_selected"],
                        "fedavg_note": lco_res["methods"][meth].get(
                            "skipped_reason"),
                        "mock": False, "date": date,
                        "split_info": {k: v for k, v in info.items()
                                       if k != "held_cluster_ids"},
                        "n_held_clusters": len(info["held_cluster_ids"]),
                    }
                    rows.append(row)
                    if gm is not None:
                        dg = (None if lm is None
                              else lm["f1"] - gm["f1"])
                        da = (None if (lm is None or gm["auc"] is None
                                       or lm["auc"] is None)
                              else lm["auc"] - gm["auc"])
                    else:
                        dg = da = None
                    rows.append({
                        "kind": "run", "threshold": float(thr),
                        "seed": seed, "block": block, "method": meth,
                        "split": "group_inrunner",
                        "f1": None if gm is None else gm["f1"],
                        "auc": None if gm is None else gm["auc"],
                        "precision": None if gm is None else gm["precision"],
                        "recall": None if gm is None else gm["recall"],
                        "n_train": len(gtrain), "n_test": len(gtest),
                        "n_test_malicious": int(sum(int(r["label"])
                                                    for r in gtest)),
                        "C_selected": grp_res["C_selected"],
                        "fedavg_note": grp_res["methods"][meth].get(
                            "skipped_reason"),
                        "degradation_f1": dg, "degradation_auc": da,
                        "mock": False, "date": date,
                    })
        per_threshold[str(thr)] = {"n_valid_seeds": n_valid,
                                   "n_seeds": len(seeds),
                                   "cluster_file": os.path.abspath(cpath),
                                   "cluster_meta": clu["meta"]}

    result = {
        "schema_version": SCHEMA_VERSION,
        "meta": {
            "date": date,
            "seeds": list(seeds),
            "test_fraction_clusters": TEST_FRACTION,
            "blocks": list(BLOCKS), "methods": list(METHODS),
            "primary_threshold": float(list(cluster_files)[0]),
            "sensitivity_thresholds": [float(t) for t in cluster_files],
            "amendment": "AMENDMENT-7 (docs/packguard_prereg.md); registered "
                         "before any LCO run",
            "pipeline": "packguard.lco.run_lco",
            "mock": False,
            "load": load_meta,
            "strong_recipe": ("sklearn LR lbfgs max_iter=5000 tol=1e-6; "
                              "StandardScaler pooled-TRAIN; C in "
                              "{0.01,0.1,1,10} by 3-fold train-only CV; "
                              "FedAvg = local lbfgs + n-weighted average, "
                              "ecosystem partition, rounds=2 fixed point"),
            "pairing": ("degradation = F1(LCO split) - F1(group split "
                        "packguard.fl.make_group_split) computed in THIS run "
                        "under identical plumbing, paired by seed"),
        },
        "per_threshold": per_threshold,
        "rows": rows,
    }
    os.makedirs(outdir, exist_ok=True)
    return result


# ---------------------------------------------------------------------------
# Aggregation (frozen rule; operates on the emitted rows)
# ---------------------------------------------------------------------------
def aggregate(result: dict) -> dict:
    """Per (threshold, split, block, method): F1/AUC mean+-std over valid
    seeds; per-seed degradation table; paired Wilcoxon graph-vs-text on the
    degradation differences. Registered BEFORE the run (AMENDMENT-7)."""
    by_key: Dict[tuple, Dict[int, dict]] = {}
    for r in result["rows"]:
        if r["kind"] != "run":
            continue
        key = (r["threshold"], r["split"], r["block"], r["method"])
        by_key.setdefault(key, {})[r["seed"]] = r

    agg = {"cells": [], "degradation": [], "paired_tests": []}
    thr_list = sorted({k[0] for k in by_key})
    for thr in thr_list:
        for split in ("lco", "group_inrunner"):
            for block in BLOCKS:
                for meth in METHODS:
                    cell = by_key.get((thr, split, block, meth), {})
                    f1s = [r["f1"] for r in cell.values() if r["f1"] is not None]
                    aucs = [r["auc"] for r in cell.values()
                            if r["auc"] is not None]
                    m, s = mean_std(f1s)
                    ma, sa = mean_std(aucs)
                    agg["cells"].append({
                        "threshold": thr, "split": split, "block": block,
                        "method": meth, "n_seeds_with_metric": len(f1s),
                        "f1_mean": m, "f1_std": s,
                        "auc_mean": ma, "auc_std": sa,
                    })
        # paired degradation per (block, method)
        for block in BLOCKS:
            for meth in METHODS:
                dg = [(r["seed"], r["degradation_f1"], r["degradation_auc"])
                      for r in result["rows"]
                      if r["kind"] == "run" and r["threshold"] == thr
                      and r["split"] == "group_inrunner"
                      and r["block"] == block and r["method"] == meth
                      and r["degradation_f1"] is not None]
                if not dg:
                    continue
                d_f1 = [d for _, d, _ in dg]
                d_auc = [a for _, _, a in dg if a is not None]
                m, s = mean_std(d_f1)
                agg["degradation"].append({
                    "threshold": thr, "block": block, "method": meth,
                    "n": len(d_f1), "deg_f1_mean": m, "deg_f1_std": s,
                    "deg_auc_mean": (None if not d_auc else
                                     float(statistics.mean(d_auc))),
                    "deg_auc_std": (None if len(d_auc) < 2 else
                                    float(statistics.stdev(d_auc))),
                })
        # PRIMARY: paired graph-vs-text degradation difference per seed
        for meth in METHODS:
            def dmap(block):
                return {r["seed"]: (r["degradation_f1"], r["degradation_auc"])
                        for r in result["rows"]
                        if r["kind"] == "run" and r["threshold"] == thr
                        and r["split"] == "group_inrunner"
                        and r["block"] == block and r["method"] == meth
                        and r["degradation_f1"] is not None}
            gmap, tmap = dmap("graph"), dmap("hashing_tfidf")
            common = sorted(set(gmap) & set(tmap))
            dd_f1 = [gmap[s][0] - tmap[s][0] for s in common]
            dd_auc = [gmap[s][1] - tmap[s][1] for s in common
                      if gmap[s][1] is not None and tmap[s][1] is not None]
            m, s = mean_std(dd_f1)
            w_f1 = wilcoxon_exact(dd_f1)
            w_auc = wilcoxon_exact(dd_auc) if len(dd_auc) >= 5 else {
                "p": None, "note": "n<5"}
            agg["paired_tests"].append({
                "threshold": thr, "method": meth, "comparison":
                    "deg(graph) - deg(hashing_tfidf) where deg = "
                    "F1(LCO) - F1(group); NEGATIVE dd => graph degrades "
                    "MORE under family shift (bigger drop)",
                "n_seeds": len(dd_f1),
                "dd_f1_mean": m, "dd_f1_std": s,
                "dd_f1_per_seed": [{"seed": s0, "dd": round(v, 6)}
                                   for s0, v in zip(common, dd_f1)],
                "wilcoxon_f1": w_f1, "wilcoxon_auc": w_auc,
            })
        # trivial as third arm (descriptive; no registered multiplicity)
        for meth in METHODS:
            tdeg = [r["degradation_f1"] for r in result["rows"]
                    if r["kind"] == "run" and r["threshold"] == thr
                    and r["split"] == "group_inrunner"
                    and r["block"] == "trivial" and r["method"] == meth
                    and r["degradation_f1"] is not None]
            if tdeg:
                m, s = mean_std(tdeg)
                agg["degradation"].append({
                    "threshold": thr, "block": "trivial", "method": meth,
                    "n": len(tdeg), "deg_f1_mean": m, "deg_f1_std": s,
                    "deg_auc_mean": None, "deg_auc_std": None,
                    "note": "descriptive only (AUC undefined when the "
                            "trivial predictor ties at 0.5 on a constant "
                            "feature; reported where defined)",
                })
    return agg


# ---------------------------------------------------------------------------
# summary.md
# ---------------------------------------------------------------------------
def render_summary(result: dict, agg: dict) -> str:
    meta = result["meta"]
    lines = [
        "# PackGuard LCO — leave-cluster-out robustness (round 13, AMENDMENT-7)",
        "",
        f"- date: {meta['date']}",
        f"- seeds: {meta['seeds'][0]}..{meta['seeds'][-1]} (n={len(meta['seeds'])})",
        f"- primary threshold: {meta['primary_threshold']} (sensitivity: "
        f"{meta['sensitivity_thresholds']})",
        f"- split: hold out {int(meta['test_fraction_clusters']*100)}% of "
        "MinHash clusters per seed (majority-label stratified); train/test "
        "share NO cluster/package/sample (asserted)",
        f"- mock: **{meta['mock']}** (real features_v2, 603-sample corpus)",
        "",
        "## Split validity",
        "",
    ]
    for thr, info in result["per_threshold"].items():
        cm = info["cluster_meta"]
        lines += [
            f"- threshold {thr}: clusters={cm['n_clusters']} "
            f"(single-sample={cm['n_single_sample_clusters']}, "
            f"multi-package={cm['n_multi_package_clusters']}, "
            f"mixed-label={cm['n_mixed_label_clusters']}), "
            f"valid LCO seeds={info['n_valid_seeds']}/{info['n_seeds']}, "
            f"multi-version families split across clusters = "
            f"{cm['known_family_check']['n_multi_version_packages_split_across_clusters']}"
            f"/{cm['known_family_check']['n_multi_version_packages']}",
        ]
    lines += ["", "## Metrics (mean±std over valid seeds)", ""]
    lines.append("| thr | split | block | method | F1 | AUC | n |")
    lines.append("|---|---|---|---|---|---|---|")
    for c in agg["cells"]:
        if c["split"] != "lco":
            continue
        f1 = "n/a" if c["f1_mean"] is None else f"{c['f1_mean']:.4f}±{c['f1_std']:.4f}"
        auc = "n/a" if c["auc_mean"] is None else f"{c['auc_mean']:.4f}±{c['auc_std']:.4f}"
        lines.append(f"| {c['threshold']} | LCO | {c['block']} | "
                     f"{c['method']} | {f1} | {auc} | {c['n_seeds_with_metric']} |")
    lines += ["", "## Degradation under family shift (ΔF1 = LCO − group, paired per seed)", ""]
    lines.append("| thr | block | method | ΔF1 mean±std | n |")
    lines.append("|---|---|---|---|---|")
    for d in agg["degradation"]:
        if d.get("note"):
            continue
        lines.append(f"| {d['threshold']} | {d['block']} | {d['method']} | "
                     f"{d['deg_f1_mean']:+.4f}±{d['deg_f1_std']:.4f} | {d['n']} |")
    lines += ["", "## PRIMARY paired test: does family shift hurt one representation more?",
              "",
              "deg = F1(LCO) − F1(group); dd = deg(graph) − deg(hashing_tfidf); "
              "**negative dd ⇒ graph degrades MORE under family shift**.", ""]
    for t in agg["paired_tests"]:
        w = t["wilcoxon_f1"]
        p = "None (all-zero)" if w.get("p") is None else f"{w['p']:.6f}"
        lines += [
            f"- threshold {t['threshold']}, method {t['method']}: "
            f"Δdeg(graph−text) mean = {t['dd_f1_mean']:+.4f}±{t['dd_f1_std']:.4f} "
            f"(signs +{w.get('n_pos')}/−{w.get('n_neg')}/={w.get('n_zero')}), "
            f"Wilcoxon exact two-sided p = {p}",
        ]
    lines += ["", "Provenance: every row in lco_results.json carries "
              "{mock:false, seed, threshold, block, method, split, date}; "
              "cluster diagnostics in clusters_t*.json (histogram, known-family "
              "check).", ""]
    return "\n".join(lines)


def config_sha16(obj: Any) -> str:
    blob = json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def main() -> None:
    ap = argparse.ArgumentParser(description="PackGuard LCO runner")
    ap.add_argument("--config", default="configs/packguard_lco.yaml")
    ap.add_argument("--limit-seeds", type=int, default=None,
                    help="debug: use only the first N seeds")
    args = ap.parse_args()
    import yaml
    with open(args.config, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    seeds = cfg["seeds"][:args.limit_seeds] if args.limit_seeds else cfg["seeds"]
    cluster_files = {str(k): v for k, v in cfg["cluster_files"].items()}
    result = run_lco(cfg["features"], cfg["text_cache"], cluster_files,
                     seeds=seeds, outdir=cfg["outdir"],
                     fedavg_rounds=int(cfg.get("fedavg_rounds", 2)))
    result["meta"]["config_sha16"] = config_sha16(
        {k: v for k, v in cfg.items() if k != "seeds"})
    result["meta"]["seeds"] = list(seeds)
    agg = aggregate(result)
    result["aggregate"] = agg
    out_json = os.path.join(cfg["outdir"], "lco_results.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=1)
    with open(os.path.join(cfg["outdir"], "summary.md"), "w",
              encoding="utf-8") as f:
        f.write(render_summary(result, agg))
    print("rows:", len(result["rows"]), "->", out_json)
    for t in agg["paired_tests"]:
        w = t["wilcoxon_f1"]
        print(f"PRIMARY thr={t['threshold']} {t['method']}: "
              f"ddF1={t['dd_f1_mean']:+.4f}±{t['dd_f1_std']:.4f} "
              f"p={w.get('p')}")


if __name__ == "__main__":
    main()
