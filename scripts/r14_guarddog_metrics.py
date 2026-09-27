#!/usr/bin/env python
"""Round 14 (W) — GuardDog baseline metrics vs graph/TF-IDF on the SAME splits.

Run with the main venv or .venv-gd (stdlib + PyYAML only; AUC is an exact
Mann-Whitney statistic with mid-rank ties — no sklearn dependency).

  python scripts/r14_guarddog_metrics.py

Inputs (all real, pre-existing):
  outputs/packguard/guarddog/findings.jsonl        (G4 scan rows)
  data/packguard/manifests/dataset_v2.json         (603 labels)
  outputs/packguard/guarddog/split_membership.json (reproduced splits)
  outputs/packguard/fl_multiseed/grid_results.json (graph/tfidf, group split, seed rows)
  outputs/packguard/lco/lco_results.json           (graph/tfidf, LCO rows)
Outputs:
  outputs/packguard/guarddog/metrics.json
  outputs/packguard/guarddog/summary.md
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "outputs/packguard/guarddog"
GRID = ROOT / "outputs/packguard/fl_multiseed/grid_results.json"
LCO = ROOT / "outputs/packguard/lco/lco_results.json"


# ------------------------------------------------------------------ metrics
def prf(tp: int, fp: int, fn: int, tn: int) -> dict:
    prec = tp / (tp + fp) if (tp + fp) else None
    rec = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * prec * rec / (prec + rec)) if (prec is not None and rec is not None
                                             and (prec + rec) > 0) else None
    return {"precision": prec, "recall": rec, "f1": f1, "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def auc_mw(scores: list[float], labels: list[int]) -> float | None:
    """Exact AUC = U / (n_pos * n_neg) with mid-ranks for ties (no sklearn)."""
    pos = [s for s, y in zip(scores, labels) if y == 1]
    neg = [s for s, y in zip(scores, labels) if y == 0]
    if not pos or not neg:
        return None
    allv = sorted(zip(scores, labels))  # value asc; label irrelevant for rank
    # mid-ranks
    ranks: dict[int, float] = {}
    i = 0
    n = len(allv)
    while i < n:
        j = i
        while j + 1 < n and allv[j + 1][0] == allv[i][0]:
            j += 1
        mid = (i + j) / 2 + 1  # 1-based
        for k in range(i, j + 1):
            ranks[k] = mid
        i = j + 1
    r_pos = sum(ranks[k] for k in range(n) if allv[k][1] == 1)
    u = r_pos - len(pos) * (len(pos) + 1) / 2
    return u / (len(pos) * len(neg))


def evaluate(rows: list[dict]) -> dict:
    ok = [r for r in rows if r["scan_status"] == "ok"]
    y = [int(r["label"]) for r in ok]
    yhat = [int(r["verdict"]) for r in ok]
    s = [float(r["score"]) for r in ok]
    tp = sum(1 for a, b in zip(y, yhat) if a == 1 and b == 1)
    fp = sum(1 for a, b in zip(y, yhat) if a == 0 and b == 1)
    fn = sum(1 for a, b in zip(y, yhat) if a == 1 and b == 0)
    tn = sum(1 for a, b in zip(y, yhat) if a == 0 and b == 0)
    out = prf(tp, fp, fn, tn)
    out["n"] = len(ok)
    out["n_excluded"] = len(rows) - len(ok)
    out["auc"] = auc_mw(s, y)
    return out


def per_ecosystem(rows: list[dict]) -> dict:
    res = {}
    for eco in ("npm", "pypi"):
        sub = [r for r in rows if r["ecosystem"] == eco]
        if sub:
            res[eco] = evaluate(sub)
    return res


# ------------------------------------------------------------------ inputs
def main() -> None:
    man = json.load(open(ROOT / "data/packguard/manifests/dataset_v2.json"))
    labels = {s["sample_id"]: s["label"] for s in man["samples"]}
    rows = [json.loads(l) for l in open(OUT / "findings.jsonl")]
    # integrity: label double-check against manifest
    for r in rows:
        assert r["label"] == labels[r["sample_id"]], f"label mismatch {r['sample_id']}"
    splits = json.load(open(OUT / "split_membership.json"))
    for r in rows:  # membership double-check
        assert sorted(r["split_membership"]) == sorted(
            k for k, ids in splits.items() if r["sample_id"] in set(ids))

    scopes = {
        "full": rows,
        "group_test_seed20260922": [r for r in rows if "group_test_seed20260922" in r["split_membership"]],
        "lco_test_seed20260922_t030": [r for r in rows if "lco_test_seed20260922_t030" in r["split_membership"]],
        "lco_test_seed20260922_t050": [r for r in rows if "lco_test_seed20260922_t050" in r["split_membership"]],
    }
    metrics = {"mock": False, "detector": "guarddog-3.2.0 source-yara rules severity>=high",
               "scopes": {k: {"overall": evaluate(v), "per_ecosystem": per_ecosystem(v)}
                          for k, v in scopes.items()},
               "excluded_rows": [
                   {"sample_id": r["sample_id"], "ecosystem": r["ecosystem"],
                    "label": r["label"], "scan_status": r["scan_status"], "error": r.get("error")}
                   for r in rows if r["scan_status"] != "ok"]}

    # rule usage diagnostics (full corpus, ok rows)
    trig_mal: Counter = Counter()
    trig_ben: Counter = Counter()
    for r in rows:
        if r["scan_status"] != "ok":
            continue
        (trig_mal if r["label"] == 1 else trig_ben).update(r["rules_triggered"])
    metrics["rule_frequency_high"] = {
        "on_malicious": dict(trig_mal.most_common()),
        "on_benign": dict(trig_ben.most_common(30)),
    }

    # ---- comparators on the SAME splits (verbatim from existing artifacts)
    grid = json.load(open(GRID))
    comp_group = []
    for row in grid["rows"]:
        if (row.get("seed") == 20260922 and row.get("split") == "group"
                and row.get("partition") == "ecosystem"
                and row.get("features") in ("graph", "tfidf")
                and row.get("method") in ("centralized", "fedavg")):
            comp_group.append({"source": "grid_results.json",
                               "features": row["features"], "method": row["method"],
                               "f1": row["f1"], "auc": row["auc"],
                               "precision": row["precision"], "recall": row["recall"],
                               "n_test": row["n_test"]})

    lco = json.load(open(LCO))
    comp_lco = []
    for thr, key in (("0.3", "lco_test_seed20260922_t030"), ("0.5", "lco_test_seed20260922_t050")):
        for row in lco["rows"]:
            if (row.get("threshold") == float(thr) and row.get("seed") == 20260922
                    and row.get("split") == "lco"
                    and row.get("block") in ("graph", "hashing_tfidf")
                    and row.get("method") in ("strong_centralized", "fedavg")):
                comp_lco.append({"source": "lco_results.json", "threshold": thr,
                                 "block": row["block"], "method": row["method"],
                                 "f1": row["f1"], "auc": row["auc"],
                                 "n_test": row["n_test"]})
        # 20-seed LCO means for context
        cells = defaultdict(list)
        for row in lco["rows"]:
            if (row.get("threshold") == float(thr) and row.get("split") == "lco"
                    and row.get("block") in ("graph", "hashing_tfidf")
                    and row.get("method") in ("strong_centralized", "fedavg")):
                cells[(row["block"], row["method"])].append(row["f1"])
        import statistics
        for (blk, mth), vals in cells.items():
            comp_lco.append({"source": "lco_results.json (20-seed mean)", "threshold": thr,
                             "block": blk, "method": mth,
                             "f1": statistics.mean(vals),
                             "f1_std": statistics.stdev(vals), "n_seeds": len(vals)})
    metrics["comparison"] = {"group_test_seed20260922": comp_group, "lco": comp_lco}

    json.dump(metrics, open(OUT / "metrics.json", "w"), indent=1)

    # ---- summary.md
    L = []
    A = L.append
    A("# GuardDog baseline (round 14) — summary\n")
    A("Pre-registration: `configs/packguard_guarddog.yaml` (before any scan). "
      "guarddog 3.2.0, source-YARA rules, severity in {critical,high} -> "
      "critical absent in 3.2.0 so = high; verdict = score>=1; metadata rules recorded, never in verdict.\n")
    for name, m in metrics["scopes"].items():
        o = m["overall"]
        A(f"## {name}  (n={o['n']}, excluded={o['n_excluded']})\n")
        A(f"- P={o['precision']:.4f}  R={o['recall']:.4f}  F1={o['f1']:.4f}  AUC={o['auc']:.4f}"
          if o["precision"] is not None and o["auc"] is not None else "- undefined")
        A(f"- confusion tp/fp/fn/tn = {o['tp']}/{o['fp']}/{o['fn']}/{o['tn']}\n")
        for eco, e in m["per_ecosystem"].items():
            A(f"- {eco}: n={e['n']} P={e['precision']:.4f} R={e['recall']:.4f} "
              f"F1={e['f1']:.4f} AUC={e['auc']:.4f}")
        A("")
    A("## Excluded rows (scan_status != ok)\n")
    for r in metrics["excluded_rows"]:
        A(f"- {r['sample_id']} ({r['ecosystem']}, label={r['label']}): {r['scan_status']} — {r['error']}")
    A("\n## Comparison (same splits)\n")
    A("### group split seed 20260922 (test n=129)\n")
    A("| system | F1 | AUC |")
    A("|---|---|---|")
    g = metrics["scopes"]["group_test_seed20260922"]["overall"]
    A(f"| guarddog (this run) | {g['f1']:.4f} | {g['auc']:.4f} |")
    for c in comp_group:
        A(f"| {c['features']} {c['method']} (grid_results) | {c['f1']:.4f} | {c['auc']:.4f} |")
    A("\n### LCO seed 20260922 (primary thr 0.30; sensitivity 0.50)\n")
    A("| system | F1 | AUC |")
    A("|---|---|---|")
    for thr, key in (("0.3", "lco_test_seed20260922_t030"), ("0.5", "lco_test_seed20260922_t050")):
        g = metrics["scopes"][key]["overall"]
        A(f"| guarddog (this run, LCO t{thr}) | {g['f1']:.4f} | {g['auc']:.4f} |")
    for c in comp_lco:
        if "f1_std" in c:
            A(f"| {c['block']} {c['method']} 20-seed LCO mean t{c['threshold']} "
              f"| {c['f1']:.4f}±{c['f1_std']:.4f} | - |")
        else:
            A(f"| {c['block']} {c['method']} seed20260922 t{c['threshold']} "
              f"| {c['f1']:.4f} | {c['auc']:.4f} |")
    (OUT / "summary.md").write_text("\n".join(L) + "\n")
    print(json.dumps({k: v["overall"] for k, v in metrics["scopes"].items()}, indent=1))


if __name__ == "__main__":
    main()
