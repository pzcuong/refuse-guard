#!/usr/bin/env python
"""r11_trivial_baseline.py -- P0-5 / L4: is the behavior-graph representation
beating a TRIVIAL metadata baseline, or is the classifier riding a shortcut?

Motivation (reviewer shortcut-learning concern): the grid compares graph
features against TF-IDF text, but both encode parsed content. A detector that
only reads cheap metadata (file counts, parse failures, entry-point flags,
empty-graph flag) could explain part of the F1. This script quantifies that.

Trivial feature set (metadata only, NO parsed content):
    n_files            -- number of files selected per sample   (features_v2)
    parse_fail_files   -- files that failed tree-sitter parsing (features_v2)
    empty_graph_flag   -- 1 if the extracted graph has zero nodes (features_v2)
    has_setup          -- PyPI setup.py entry point present     (features_v2)
    has_postinstall    -- npm install hook present              (features_v2)
DISCLOSURE: n_bytes is requested by the shortcut-question checklist but is NOT
present in the features_v2 / graphs_v2 schema (file sizes are not recorded), so
it is omitted -- never imputed.

Protocol (mirrors the registered grid protocol, sklearn implementation):
    20 seeds (20260922..20260941, the AMENDMENT-4 set)
    x {group split = PRIMARY, random split = SECONDARY}   (packguard.fl split fns)
    x {graph 18 features, trivial 5 features}
    x centralized sklearn LogisticRegression(solver="lbfgs", max_iter=1000,
      random_state=seed) on StandardScaler-scaled features.
  Both arms run under THIS script's identical protocol, so the graph-vs-trivial
  comparison is internally apples-to-apples. These numbers are NOT comparable to
  the torch-SGD grid numbers in outputs/packguard/fl_multiseed/ (different
  optimizer); any such cross-comparison is forbidden by construction here.
  A with-graph-only rerun (n_nodes>0, 500 rows) drops the empty-graph rows so
  the trivial arm cannot win merely through the empty-graph flag.

Statistics (per split x feature-set-pair):
    per-seed paired exact McNemar on test predictions (statsmodels),
    per-seed dF1 / dAUC (graph - trivial), exact Wilcoxon over the 20 deltas
    (scipy, method='exact'), sign counts, and a bootstrap 95% CI of the mean
    dF1 over seeds (10,000 resamples, seed 20260922).

Outputs:
    outputs/packguard/trivial/trivial_results.json  (mock:false, full provenance)
    outputs/packguard/trivial/trivial_summary.md    (table)

Run:  .venv/bin/python scripts/r11_trivial_baseline.py [--seeds N] [--out DIR]
Deterministic: no wall-clock input; same inputs -> byte-identical JSON.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from packguard.fl import make_global_test_split, make_group_split  # noqa: E402
from packguard.features import FEATURE_NAMES  # noqa: E402

FEATURES_PATH = ROOT / "outputs/packguard/features/features_v2.jsonl"
DEFAULT_OUT = ROOT / "outputs/packguard/trivial"
SEEDS = list(range(20260922, 20260941 + 1))
TEST_FRACTION = 0.2          # configs/packguard_fl.yaml fl.test_fraction
BOOTSTRAP_RESAMPLES = 10_000
BOOTSTRAP_SEED = 20260922

TRIVIAL_FEATURES = ["n_files", "parse_fail_files", "empty_graph_flag",
                    "has_setup", "has_postinstall"]
GRAPH_FEATURES = list(FEATURE_NAMES)


def load_records(path: Path = FEATURES_PATH) -> list[dict]:
    """Load features_v2 rows + derive empty_graph_flag (never imputed)."""
    recs = []
    with path.open() as f:
        for line in f:
            r = json.loads(line)
            r["empty_graph_flag"] = 1 if r.get("n_nodes", 0) == 0 else 0
            recs.append(r)
    if not recs:
        raise SystemExit(f"no records in {path}")
    return recs


def matrix(records: list[dict], feats: list[str]) -> np.ndarray:
    missing = [f for f in feats if f not in records[0]]
    if missing:
        raise KeyError(f"features absent from schema: {missing}")
    return np.array([[float(r[f]) for f in feats] for r in records], dtype=float)


def fit_predict(Xtr, ytr, Xte, seed: int) -> np.ndarray:
    """Centralized standardized lbfgs LR -- deterministic for a given seed."""
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    pipe = Pipeline([
        ("scaler", StandardScaler()),
        ("lr", LogisticRegression(solver="lbfgs", max_iter=1000,
                                  random_state=int(seed))),
    ])
    pipe.fit(Xtr, ytr)
    return pipe.predict_proba(Xte)[:, 1]


def metrics(y, probs) -> dict:
    from sklearn import metrics as skm
    y = np.asarray(y, dtype=int)
    pred = (np.asarray(probs) >= 0.5).astype(int)
    return {
        "f1": float(skm.f1_score(y, pred, zero_division=0)),
        "auc": float(skm.roc_auc_score(y, probs)) if len(np.unique(y)) > 1 else None,
        "n_test": int(len(y)),
        "n_test_malicious": int(y.sum()),
    }


def mcnemar_exact(y, p_a, p_b) -> dict:
    """Paired exact McNemar between two arms' predictions on the SAME rows."""
    from statsmodels.stats.contingency_tables import mcnemar
    ya = (np.asarray(p_a) >= 0.5).astype(int)
    yb = (np.asarray(p_b) >= 0.5).astype(int)
    y = np.asarray(y, dtype=int)
    b01 = int(((ya != y) & (yb == y)).sum())   # A wrong, B right
    b10 = int(((ya == y) & (yb != y)).sum())   # A right, B wrong
    if b01 + b10 == 0:
        return {"b01": b01, "b10": b10, "stat": None, "p_value": 1.0, "method": "degenerate-all-agree"}
    res = mcnemar([[0, b01], [b10, 0]], exact=True, correction=False)
    return {"b01": b01, "b10": b10, "stat": float(res.statistic),
            "p_value": float(res.pvalue), "method": "statsmodels exact"}


def bootstrap_ci_seed_level(deltas: list[float], n_boot: int = BOOTSTRAP_RESAMPLES,
                            seed: int = BOOTSTRAP_SEED) -> dict:
    rng = np.random.default_rng(seed)
    d = np.asarray(deltas, dtype=float)
    idx = rng.integers(0, len(d), size=(n_boot, len(d)))
    means = d[idx].mean(axis=1)
    return {"mean": float(d.mean()),
            "ci_low": float(np.quantile(means, 0.025)),
            "ci_high": float(np.quantile(means, 0.975)),
            "n_boot": n_boot, "seed": seed, "unit": "seed-level resample"}


def run_protocol(records: list[dict], seeds: list[int],
                 splits=("group", "random"),
                 feature_sets=("graph", "trivial")) -> dict:
    """Run the full grid; deterministic given (records, seeds)."""
    out: dict = {}
    for split in splits:
        per_seed = []
        for seed in seeds:
            if split == "group":
                train, test = make_group_split(records, TEST_FRACTION, seed=int(seed))
            else:
                train, test = make_global_test_split(records, TEST_FRACTION, seed=int(seed))
            ytr = [int(r["label"]) for r in train]
            yte = [int(r["label"]) for r in test]
            row: dict = {"seed": int(seed), "split": split,
                         "n_train": len(train), "n_test": len(test)}
            preds = {}
            for fs in feature_sets:
                feats = GRAPH_FEATURES if fs == "graph" else TRIVIAL_FEATURES
                probs = fit_predict(matrix(train, feats), ytr, matrix(test, feats), seed)
                preds[fs] = probs
                row[fs] = metrics(yte, probs)
            if "graph" in preds and "trivial" in preds:
                row["df1_graph_minus_trivial"] = row["graph"]["f1"] - row["trivial"]["f1"]
                row["dauc_graph_minus_trivial"] = row["graph"]["auc"] - row["trivial"]["auc"]
                row["mcnemar_graph_vs_trivial"] = mcnemar_exact(yte, preds["graph"], preds["trivial"])
            per_seed.append(row)
        agg = _aggregate(per_seed)
        out[split] = {"per_seed": per_seed, "aggregate": agg}
    return out


def _aggregate(per_seed: list[dict]) -> dict:
    df1 = [r["df1_graph_minus_trivial"] for r in per_seed]
    dauc = [r["dauc_graph_minus_trivial"] for r in per_seed]
    from scipy.stats import wilcoxon
    b01 = sum(r["mcnemar_graph_vs_trivial"]["b01"] for r in per_seed)
    b10 = sum(r["mcnemar_graph_vs_trivial"]["b10"] for r in per_seed)
    if all(abs(d) < 1e-12 for d in df1):
        w = {"statistic": None, "p_value": None,
             "note": "all-zero deltas: exact test undefined, not fabricated"}
    else:
        stat, p = wilcoxon(df1, alternative="two-sided", method="exact")
        w = {"statistic": float(stat), "p_value": float(p)}
    sig = sum(1 for r in per_seed
              if r["mcnemar_graph_vs_trivial"]["p_value"] < 0.05
              and r["mcnemar_graph_vs_trivial"]["b01"] + r["mcnemar_graph_vs_trivial"]["b10"] > 0)
    return {
        "n_seeds": len(per_seed),
        "graph_f1_mean_std": [statistics.mean(r["graph"]["f1"] for r in per_seed),
                              statistics.pstdev([r["graph"]["f1"] for r in per_seed])],
        "trivial_f1_mean_std": [statistics.mean(r["trivial"]["f1"] for r in per_seed),
                                statistics.pstdev([r["trivial"]["f1"] for r in per_seed])],
        "graph_auc_mean_std": [statistics.mean(r["graph"]["auc"] for r in per_seed),
                               statistics.pstdev([r["graph"]["auc"] for r in per_seed])],
        "trivial_auc_mean_std": [statistics.mean(r["trivial"]["auc"] for r in per_seed),
                                 statistics.pstdev([r["trivial"]["auc"] for r in per_seed])],
        "df1_mean": statistics.mean(df1), "df1_std_pop": statistics.pstdev(df1),
        "dauc_mean": statistics.mean(dauc), "dauc_std_pop": statistics.pstdev(dauc),
        "sign_df1": {"pos": sum(1 for d in df1 if d > 1e-12),
                     "neg": sum(1 for d in df1 if d < -1e-12),
                     "zero": sum(1 for d in df1 if abs(d) <= 1e-12)},
        "wilcoxon_exact_df1": w,
        "mcnemar_pooled_discordant": {"graph_wrong_trivial_right": b01,
                                      "graph_right_trivial_wrong": b10},
        "seeds_with_significant_mcnemar_p<.05": sig,
        "bootstrap_mean_df1_ci95": bootstrap_ci_seed_level(df1),
    }


def run_subset_with_graph(records: list[dict], seeds: list[int]) -> dict:
    """Rerun on rows with a non-empty graph only (n_nodes>0)."""
    sub = [r for r in records if r.get("n_nodes", 0) > 0]
    out = {"n_rows": len(sub), "n_rows_total": len(records)}
    out.update(run_protocol(sub, seeds))
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=len(SEEDS),
                    help="number of leading AMENDMENT-4 seeds to use (default all 20)")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()

    seeds = SEEDS[:max(1, args.seeds)]
    records = load_records()
    import sklearn
    import statsmodels
    import scipy
    meta = {
        "mock": False,
        "date": "deterministic (no wall-clock input; see provenance)",
        "features_source": str(FEATURES_PATH.relative_to(ROOT)),
        "seeds": seeds,
        "test_fraction": TEST_FRACTION,
        "split_functions": "packguard.fl.make_group_split / make_global_test_split",
        "model": "sklearn Pipeline(StandardScaler, LogisticRegression(solver=lbfgs, max_iter=1000, random_state=seed))",
        "sklearn_version": sklearn.__version__,
        "scipy_version": scipy.__version__,
        "statsmodels_version": statsmodels.__version__,
        "graph_features": GRAPH_FEATURES,
        "trivial_features": TRIVIAL_FEATURES,
        "n_bytes_disclosure": "n_bytes is NOT present in the features_v2/graphs_v2 schema; "
                              "omitted (never imputed).",
        "comparability_note": "Both arms run under THIS script's identical centralized sklearn "
                              "protocol; numbers are NOT comparable to the torch-SGD FL grid "
                              "(different optimizer) and are never mixed with it.",
        "primary_question": "Does the graph feature set beat the trivial metadata baseline "
                            "under the same protocol (shortcut-learning check)?",
    }
    full = run_protocol(records, seeds)
    subset = run_subset_with_graph(records, seeds)
    result = {"meta": meta, "full_corpus": full, "with_graph_subset": subset}
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "trivial_results.json").write_text(json.dumps(result, indent=1, sort_keys=True))
    (args.out / "trivial_summary.md").write_text(render_summary(result))
    print(f"wrote {args.out / 'trivial_results.json'}")
    print(f"wrote {args.out / 'trivial_summary.md'}")
    return 0


def render_summary(res: dict) -> str:
    lines = ["# Trivial-metadata baseline vs graph features (round 11, P0-5)", ""]
    m = res["meta"]
    lines += [f"- mock: **{m['mock']}**; seeds: {m['seeds'][0]}..{m['seeds'][-1]} "
              f"({len(m['seeds'])}); test_fraction {m['test_fraction']}",
              f"- model: {m['model']}", ""]
    for scope, key in (("FULL corpus (603 rows)", "full_corpus"),
                       ("WITH-GRAPH subset (n_nodes>0)", "with_graph_subset")):
        lines.append(f"## {scope}")
        if key == "with_graph_subset":
            lines.append(f"(rows: {res[key]['n_rows']}/{res[key]['n_rows_total']})")
        lines += ["", "| split | graph F1 | trivial F1 | dF1 (g-t) | sign +-/0 | "
                  "Wilcoxon exact p | McNemar pooled (b01/b10) | boot 95% CI mean dF1 |",
                  "|---|---|---|---|---|---|---|---|"]
        for split in ("group", "random"):
            a = res[key][split]["aggregate"]
            f1g = a["graph_f1_mean_std"]
            f1t = a["trivial_f1_mean_std"]
            w = a["wilcoxon_exact_df1"]["p_value"]
            ci = a["bootstrap_mean_df1_ci95"]
            sgn = a["sign_df1"]
            lines.append(
                f"| {split} | {f1g[0]:.4f}±{f1g[1]:.4f} | {f1t[0]:.4f}±{f1t[1]:.4f} | "
                f"{a['df1_mean']:+.4f}±{a['df1_std_pop']:.4f} | {sgn['pos']}/{sgn['neg']}/{sgn['zero']} | "
                f"{'None' if w is None else f'{w:.4g}'} | "
                f"{a['mcnemar_pooled_discordant']['graph_wrong_trivial_right']}/"
                f"{a['mcnemar_pooled_discordant']['graph_right_trivial_wrong']} | "
                f"[{ci['ci_low']:+.4f}, {ci['ci_high']:+.4f}] |")
        lines.append("")
    lines += ["Interpretation duty: a POSITIVE dF1 with low Wilcoxon p means the graph "
              "features beat the trivial baseline beyond shortcut learning; a null means "
              "the trivial metadata explains the signal."]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.exit(main())
