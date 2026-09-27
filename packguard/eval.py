"""PackGuard pilot harness: features -> FL train -> eval -> ablations -> outputs
(F4, PACKGUARD_BRIEF §4).

Pipeline:
  1. features: W1 output under outputs/packguard/features/ (features.jsonl |
     parquet). Without it the run FAILS LOUDLY unless --synthetic is passed,
     in which case packguard.fl.synthetic_fixture provides a clearly
     mock-flagged fixture (never mixed with real numbers).
  2. FL training: FedAvg + FedProx + centralized + per-client-only baselines
     (packguard/fl.py), global held-out test set.
  3. Primary comparison (pre-registered): FedAvg vs centralized — per-sample
     paired correctness -> McNemar + bootstrap CI of the F1/AUC difference
     (src/metrics/stats.py).
  4. Ablations: FedAvg per feature block (graph vs tfidf code-as-text path);
     KB on/off (seed-KB features unless a real LLM-KB exists; rows carry
     kb_source). Missing inputs -> explicit PENDING_W1_DATA rows, never fakes.
  5. Outputs: results.jsonl (one row per run/comparison/ablation, every row
     with meta {mock, seed, config_sha16, date, ...}) + summary.md.

CLI: .venv/bin/python -m packguard.eval --config configs/packguard_fl.yaml
     [--synthetic] [--out-dir outputs/packguard/fl]
"""
from __future__ import annotations

import argparse
import copy
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import numpy as np
import yaml

from packguard import fl as flm
from packguard.fl import (
    FLConfig,
    FedClient,
    build_clients,
    client_label_distribution,
    config_sha16,
    load_feature_records,
    make_global_test_split,
    make_group_split,
    paired_correctness,
    run_centralized,
    run_federated,
    run_per_client,
    synthetic_fixture,
)
from src.metrics.stats import bootstrap_ci_diff, mcnemar

__all__ = ["run_pipeline", "run_grid", "main"]

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_DEFAULT = PROJECT_ROOT / "configs" / "packguard_fl.yaml"
FEATURES_DIR_DEFAULT = PROJECT_ROOT / "outputs" / "packguard" / "features"
OUT_DIR_DEFAULT = PROJECT_ROOT / "outputs" / "packguard" / "fl"
GRID_OUT_DEFAULT = PROJECT_ROOT / "outputs" / "packguard" / "fl_multiseed"
TEXT_CACHE_DEFAULT = PROJECT_ROOT / "outputs" / "packguard" / "features" / "text_v2.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_yaml(path: str | Path) -> dict:
    with Path(path).open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------
def _resolve_features(cfg: dict, synthetic: bool,
                      features_dir: Optional[Path]) -> tuple[list[dict], dict]:
    if synthetic:
        data_seed = int(cfg.get("seed", flm.DEFAULT_SEED))
        records, meta = synthetic_fixture(seed=data_seed)
        return records, meta
    fdir = Path(features_dir or (cfg.get("data", {}) or {}).get(
        "features_dir", FEATURES_DIR_DEFAULT))
    records, meta = load_feature_records(fdir)  # raises FileNotFoundError
    return records, meta


def _block_names(records: list[dict], block: str) -> list[str]:
    for r in records:
        feats = r.get("features", {})
        if block in feats:
            return sorted(feats[block])
    return []


def _subgroup_metrics(test_records: list[dict], probs: list[float]) -> dict:
    """Per-ecosystem + per-coverage metrics on the global test set
    (pre-registered reporting duty, prereg D4 / V1 audit risk #1/#2)."""
    from packguard.fl import compute_clf_metrics

    out: dict[str, Any] = {}
    for eco in ("npm", "pypi"):
        idx = [i for i, r in enumerate(test_records)
               if str(r.get("ecosystem", "")).startswith(eco)]
        if idx:
            out[f"eco_{eco}"] = compute_clf_metrics(
                [int(test_records[i]["label"]) for i in idx],
                [probs[i] for i in idx])
    for cov, pick in (("with_graph", lambda r: float(
            (r.get("features", {}).get("graph", {}) or {}).get("n_nodes", 0)) > 0),
            ("empty_graph", lambda r: float(
            (r.get("features", {}).get("graph", {}) or {}).get("n_nodes", 0)) == 0)):
        idx = [i for i, r in enumerate(test_records) if pick(r)]
        if idx:
            out[cov] = compute_clf_metrics(
                [int(test_records[i]["label"]) for i in idx],
                [probs[i] for i in idx])
    return out


def _vectorize_block(records: list[dict], block: str) -> list[dict]:
    """Project records onto one feature block (records are copied, not mutated)."""
    out = []
    for r in records:
        rr = dict(r)
        rr["features"] = {block: r["features"][block]}
        out.append(rr)
    return out


def _augment_with_kb(records: list[dict], kb_dir: Path) -> tuple[list[dict], dict]:
    """Append kb_risk_ratio / kb_confidence / kb_unsure_ratio to the graph
    block from the CURRENT KB state (seed entries + whatever LLM entries
    exist). Returns (new_records, kb_meta)."""
    from packguard.kb import KnowledgeBase, kb_features

    kb = KnowledgeBase(kb_dir)
    n_llm = kb.stats()["n_llm"]
    out = []
    for r in records:
        rr = json.loads(json.dumps(r))  # deep copy
        feats = kb_features(r.get("api_calls", []), kb)
        g = rr["features"]["graph"]
        for k, v in feats.items():
            g[k] = v
        rr["features"] = {"graph": g}
        out.append(rr)
    return out, {"kb_source": "seed+llm" if n_llm else "seed_only",
                 "kb_n_llm_entries": n_llm, "kb_version": kb.version}


def run_pipeline(cfg: dict, synthetic: bool = False,
                 features_dir: Optional[Path] = None,
                 out_dir: Path = OUT_DIR_DEFAULT,
                 overrides: Optional[dict] = None) -> dict:
    """Full pilot run; writes results.jsonl + summary.md; returns the summary
    dict. `overrides` (test hook) patches the loaded config dict before use.
    """
    if overrides:
        cfg = {**cfg, **overrides}
    seed = int(cfg.get("seed", flm.DEFAULT_SEED))
    cfg_sha = config_sha16(cfg)
    base_meta: dict[str, Any] = {
        "seed": seed,
        "config_sha16": cfg_sha,
        "date": _now(),
        "pipeline": "packguard.eval.run_pipeline",
    }

    records, feat_meta = _resolve_features(cfg, synthetic, features_dir)
    base_meta["mock"] = bool(feat_meta.get("mock", False))
    base_meta["features_source"] = feat_meta.get("source", "synthetic_fixture")
    if base_meta["mock"]:
        base_meta["mock_note"] = feat_meta.get("note", "")

    data_cfg = cfg.get("data", {}) or {}
    block_primary = str(data_cfg.get("feature_block", "graph"))
    split_mode = str(data_cfg.get("split", "random"))
    base_meta["split"] = split_mode

    def _split(recs: list[dict]) -> tuple[list[dict], list[dict]]:
        frac = float(data_cfg.get("test_fraction", 0.2))
        if split_mode == "group":
            return make_group_split(recs, frac, seed=seed)
        return make_global_test_split(recs, frac, seed=seed)

    rows: list[dict] = []

    def _add(kind: str, name: str, payload: dict) -> dict:
        row = {"kind": kind, "name": name, "meta": dict(base_meta), **payload}
        rows.append(row)
        return row

    runs: dict[str, dict] = {}
    ablation_summaries: dict[str, Any] = {}
    pending: list[str] = []

    def _run_fl_block(block: str, kb_tag: str = "off",
                      extra: Optional[dict] = None) -> Optional[dict]:
        """FedAvg/FedProx/central/per-client on one feature block."""
        recs = records if block == block_primary and kb_tag == "off" \
            else _vectorize_block(records, block)
        if kb_tag == "on":
            kb_cfg = (cfg.get("ablations", {}) or {}).get("kb", {}) or {}
            kb_dir = PROJECT_ROOT / str(kb_cfg.get("kb_dir", "outputs/packguard/kb"))
            if not any(r.get("api_calls") for r in records):
                pending.append(f"kb_on[{block}]: records have no api_calls")
                return None
            recs, kb_meta = _augment_with_kb(recs, kb_dir)
            extra = {**(extra or {}), **kb_meta}
        try:
            train, test = _split(recs)
            clients = build_clients(train, feature_block=block)
            test_client = FedClient("global_test", test, feature_block=block)
        except (KeyError, ValueError) as exc:
            pending.append(f"{block}/kb={kb_tag}: {type(exc).__name__}: {exc}")
            return None
        input_dim = test_client.input_dim
        fl_over = {**(cfg.get("fl", {}) or {}), **(cfg.get("model", {}) or {})}
        fl_over["mu"] = float(fl_over.pop("mu_fedprox", 0.01))  # config key -> FLConfig.mu
        fl_cfg = FLConfig.from_dict(fl_over, input_dim=input_dim)
        fl_cfg.test_fraction = float(data_cfg.get("test_fraction", 0.2))
        fl_cfg.seed = seed
        fl_cfg.feature_block = block
        fl_cfg.extra_meta = {"mock": base_meta["mock"]}
        if (cfg.get("dp", {}) or {}).get("enabled"):
            fl_cfg.dp_enabled = True
            fl_cfg.dp_sigma = float(cfg["dp"].get("sigma", 0.01))
            fl_cfg.dp_delta = float(cfg["dp"].get("delta", 1e-5))
            fl_cfg.dp_clip = float(cfg["dp"].get("clip", 1.0))
        mu = float((cfg.get("fl", {}) or {}).get("mu_fedprox", 0.01))

        results: dict[str, dict] = {
            "fedavg": run_federated(clients, test_client, fl_cfg, "fedavg", seed),
            "fedprox": run_federated(clients, test_client, fl_cfg, "fedprox", seed),
            "centralized": run_centralized(clients, test_client, fl_cfg, seed),
            "per_client_only": run_per_client(clients, test_client, fl_cfg, seed),
        }
        key = f"{block}__kb_{kb_tag}"
        for algo, res in results.items():
            _add("run", f"{key}__{algo}", {
                "algo": algo,
                "feature_block": block,
                "kb": kb_tag,
                "input_dim": input_dim,
                "client_distribution": client_label_distribution(clients),
                "final_metrics": res["final_metrics"],
                "subgroup_metrics": _subgroup_metrics(
                    test, res.get("final_probs", [])) if "final_probs" in res else None,
                "history": res.get("history"),
                "secure_agg_mask_residual": res.get("secure_agg_mask_residual"),
                "dp": {k: res.get(k) for k in
                       ("dp_enabled", "dp_sigma", "dp_epsilon_per_round")},
                "extra": extra or {},
            })
        runs[key] = {**results, "input_dim": input_dim,
                     "clients": client_label_distribution(clients),
                     "extra": extra or {}}
        return results

    # -- primary run + FL-variant ablation ------------------------------------
    primary = _run_fl_block(block_primary)
    if primary is None:
        raise RuntimeError("primary FL run failed; see pending rows")
    ev_cfg = cfg.get("eval", {}) or {}
    if "fedavg" not in primary or "centralized" not in primary:
        raise RuntimeError("primary comparison needs fedavg + centralized")

    # -- pre-registered primary comparison: FedAvg vs centralized --------------
    y_test = [int(r["label"]) for r in _split(records)[1]]
    corr_fl, corr_cent = paired_correctness(
        primary["fedavg"]["final_probs"], primary["centralized"]["final_probs"],
        y_test)
    mc = mcnemar(corr_cent, corr_fl,
                 exact=None)  # auto: exact <25 discordant, chi2-cc otherwise
    boot_n = int(ev_cfg.get("bootstrap_n", 10000))
    boot_seed = int(ev_cfg.get("bootstrap_seed", seed))
    boot = bootstrap_ci_diff(
        [1.0 if c else 0.0 for c in corr_fl],
        [1.0 if c else 0.0 for c in corr_cent],
        n_boot=boot_n, seed=boot_seed)
    primary_stats = {
        "comparison": "fedavg_vs_centralized",
        "endpoint": "per-sample accuracy on the global held-out test set",
        "mcnemar": mc,
        "bootstrap_accuracy_diff": boot,
        "alpha": 0.05,
        "note": ("PRE-REGISTERED primary comparison (docs/packguard_prereg.md "
                 "§eval). mcnemar exact binomial when discordant <25, "
                 "continuity-corrected chi2 otherwise (V2 lesson: label the "
                 "method, never just 'exact')."),
    }
    _add("comparison", "primary__fedavg_vs_centralized", primary_stats)
    ablation_summaries["primary_comparison"] = primary_stats

    # -- feature-block ablation (graph vs tfidf code-as-text path) -------------
    blocks = list((cfg.get("ablations", {}) or {}).get("feature_blocks",
                                                       [block_primary]))
    for block in blocks:
        if block == block_primary:
            continue
        if _block_names(records, block) == []:
            # e.g. the tfidf block is built per-split (fit on TRAIN only) by
            # scripts/packguard_final_runs.py — never fabricate it here.
            pending.append(f"feature_block={block}: not available in records")
            continue
        res = _run_fl_block(block)
        if res is None:
            pending.append(f"feature_block={block}: not available in records")
        else:
            ablation_summaries[f"block_{block}"] = {
                "fedavg_final": res["fedavg"]["final_metrics"]}

    # -- KB on/off ablation -----------------------------------------------------
    kb_cfg = (cfg.get("ablations", {}) or {}).get("kb", {}) or {}
    if kb_cfg.get("enabled"):
        res = _run_fl_block(block_primary, kb_tag="on")
        if res is None:
            ablation_summaries["kb_on"] = "PENDING (see pending rows)"
        else:
            ablation_summaries["kb_on"] = {
                "fedavg_final": res["fedavg"]["final_metrics"],
                "kb_meta": runs[f"{block_primary}__kb_on"]["extra"]}
    else:
        pending.append(
            "kb ablation disabled in config (set ablations.kb.enabled=true "
            "after a real KB run to enable)")
    ablation_summaries["fl_variants"] = {
        a: (primary[a]["final_metrics"] if a in primary else None)
        for a in (cfg.get("ablations", {}) or {}).get(
            "fl_variants", ["fedavg", "fedprox", "centralized", "per_client_only"])
    }

    # -- DP ablation (sigma from config; runs only when dp.enabled) ------------
    if (cfg.get("dp", {}) or {}).get("enabled"):
        _add("run", f"{block_primary}__dp_flag",
             {"dp": {"enabled": True,
                     "sigma": cfg["dp"].get("sigma"),
                     "epsilon_per_round": flm.gaussian_epsilon(
                         float(cfg["dp"].get("sigma", 0.01)),
                         float(cfg["dp"].get("delta", 1e-5)),
                         float(cfg["dp"].get("clip", 1.0)))}})

    # -- persist ---------------------------------------------------------------
    out_dir.mkdir(parents=True, exist_ok=True)
    results_path = out_dir / "results.jsonl"
    with results_path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")

    summary_md = _render_summary(base_meta, runs, primary_stats,
                                 ablation_summaries, pending, out_dir)
    summary = {
        "meta": base_meta,
        "runs": {k: {a: v[a]["final_metrics"] for a in
                     ("fedavg", "fedprox", "centralized", "per_client_only")}
                 for k, v in runs.items()},
        "primary_comparison": primary_stats,
        "ablations": ablation_summaries,
        "pending": pending,
        "outputs": {"results_jsonl": str(results_path),
                    "summary_md": str(out_dir / "summary.md")},
    }
    return summary


def _fmt(v: Any) -> str:
    if v is None:
        return "n/a"
    if isinstance(v, float):
        return f"{v:.4f}"
    return str(v)


def _render_summary(base_meta: dict, runs: dict, primary_stats: dict,
                    ablations: dict, pending: list[str], out_dir: Path) -> str:
    lines: list[str] = []
    lines.append("# PackGuard FL pilot — summary")
    lines.append("")
    lines.append(f"- date: {base_meta['date']}")
    lines.append(f"- seed: {base_meta['seed']} (config sha16: "
                 f"{base_meta['config_sha16']})")
    mock = base_meta.get("mock", False)
    lines.append(f"- **mock: {mock}**" + (
        " — SYNTHETIC FIXTURE; numbers are NOT real results."
        if mock else " — real W1 features"))
    lines.append(f"- features source: {base_meta.get('features_source')}")
    lines.append("")
    lines.append("## Final metrics (global held-out test set)")
    lines.append("")
    lines.append("| run | P | R | F1 | AUC |")
    lines.append("|---|---|---|---|---|")
    for key, res in sorted(runs.items()):
        for algo in ("fedavg", "fedprox", "centralized", "per_client_only"):
            m = res[algo]["final_metrics"]
            f1 = m.get("f1", m.get("f1_macro"))
            auc = m.get("auc", m.get("auc_macro"))
            lines.append(f"| {key}__{algo} | {_fmt(m.get('precision'))} | "
                         f"{_fmt(m.get('recall'))} | {_fmt(f1)} | {_fmt(auc)} |")
    lines.append("")
    lines.append("## Primary comparison (pre-registered): FedAvg vs centralized")
    lines.append("")
    mc = primary_stats["mcnemar"]
    boot = primary_stats["bootstrap_accuracy_diff"]
    method = "exact binomial" if mc["exact"] else "chi2 with continuity correction"
    lines.append(f"- McNemar ({method}): b01={mc['b01_a_fail_b_success']}, "
                 f"b10={mc['b10_a_success_b_fail']}, p={mc['p_value']:.6g}")
    lines.append(f"- bootstrap accuracy diff (FL - central): "
                 f"{boot['estimate']:.4f} "
                 f"[{boot['ci_low']:.4f}, {boot['ci_high']:.4f}] "
                 f"(n_boot={boot['n_boot']}, seed={boot['seed']})")
    lines.append("")
    lines.append("## Ablations")
    lines.append("```json")
    lines.append(json.dumps(ablations, indent=2, default=str))
    lines.append("```")
    if pending:
        lines.append("")
        lines.append("## Pending / not run")
        for p in pending:
            lines.append(f"- {p}")
    lines.append("")
    path = out_dir / "summary.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Round-9 multi-seed grid (AMENDMENT-3; W1) — 5 seeds x 4 methods x 2 feature
# sets x {group PRIMARY, random SECONDARY} splits, plus the disclosed 3-client
# fallback arm (partition npm_hook). Added HERE because scripts/ is outside
# this agent's write space; the round-8 run_pipeline above is untouched.
# ---------------------------------------------------------------------------
def _tfidf_blocks(train: list[dict], test: list[dict], cache: dict) -> None:
    """Attach a `tfidf` block, fit on the TRAIN text only (no vocabulary
    leakage). Hyperparameters (max_features=1000, min_df=2, sublinear_tf) and
    the fixed dense key set are an exact mirror of
    scripts/packguard_final_runs.py::tfidf_blocks (round-8 final runs) so the
    grid is comparable with the round-8 numbers; the mirror exists because
    scripts/ is not modifiable by this agent (round-9 tasking)."""
    from sklearn.feature_extraction.text import TfidfVectorizer

    vec = TfidfVectorizer(max_features=1000, min_df=2, sublinear_tf=True)
    Xtr = vec.fit_transform([cache.get(r["sample_id"], "") or "" for r in train])
    Xte = vec.transform([cache.get(r["sample_id"], "") or "" for r in test])
    names = [f"tfidf_{j}" for j in range(Xtr.shape[1])]
    for recs, X in ((train, Xtr), (test, Xte)):
        coo = X.tocsr()
        for i, r in enumerate(recs):
            row = coo[i]
            dense = {n: 0.0 for n in names}  # same key set for EVERY record
            for j in row.indices:
                dense[names[j]] = round(float(row[0, j]), 6)
            r["features"]["tfidf"] = dense


def _power_note(n: int) -> str:
    """Exact two-sided Wilcoxon minimum attainable p for n paired seeds."""
    if n <= 0:
        return "no seeds"
    from math import comb
    total = 2 ** n
    min_p = 2 * comb(n, 0) / total  # = 2/2^n
    reach = "CAN reach" if min_p < 0.05 else "cannot reach"
    return (f"n={n} seeds: two-sided exact Wilcoxon minimum attainable p = "
            f"{min_p:.2e} -> seed-level tests {reach} alpha=0.05 (AMENDMENT-3 A3.2 / AMENDMENT-4)")

def _wilcoxon_over_seeds(deltas: list[float]) -> dict:
    """Wilcoxon signed-rank over per-seed deltas (AMENDMENT-3 A3.2). All-zero
    deltas -> p is undefined (never fabricated). n=5 seeds cannot reach
    alpha=0.05 two-sided (minimum exact p = 1/16 = 0.0625) — the result is
    descriptive support only; this is stated in the output itself."""
    from scipy import stats as sps

    ds = [float(d) for d in deltas]
    out: dict[str, Any] = {
        "deltas": ds,
        "n": len(ds),
        "n_pos": sum(d > 0 for d in ds),
        "n_neg": sum(d < 0 for d in ds),
        "n_zero": sum(d == 0 for d in ds),
        "mean_delta": float(sum(ds) / len(ds)) if ds else None,
        "power_note": _power_note(len(ds)),
    }
    if not ds or all(d == 0.0 for d in ds):
        out["p_value"] = None
        out["note"] = "all deltas are exactly zero; Wilcoxon undefined"
        return out
    try:
        res = sps.wilcoxon(ds)
        out["statistic"] = float(res.statistic)
        out["p_value"] = float(res.pvalue)
    except Exception as exc:  # disclose, never fabricate
        out["p_value"] = None
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def _grid_fl_config(cfg: dict, input_dim: int, seed: int, block: str) -> "FLConfig":
    """FLConfig for grid cells — same hyperparameter source as run_pipeline
    (fl + model config sections; mu_fedprox -> mu; DP off unless cfg says on)."""
    fl_over: dict[str, Any] = {**(cfg.get("fl", {}) or {}), **(cfg.get("model", {}) or {})}
    fl_over["mu"] = float(fl_over.pop("mu_fedprox", 0.01))
    flc = FLConfig.from_dict(fl_over, input_dim=input_dim)
    flc.seed = seed
    flc.feature_block = block
    flc.test_fraction = float(((cfg.get("data", {}) or {}).get("test_fraction", 0.2)))
    if (cfg.get("dp", {}) or {}).get("enabled"):
        flc.dp_enabled = True
        flc.dp_sigma = float(cfg["dp"].get("sigma", 0.01))
        flc.dp_delta = float(cfg["dp"].get("delta", 1e-5))
        flc.dp_clip = float(cfg["dp"].get("clip", 1.0))
    return flc


def _grid_cell(records: list[dict], cache: dict, cfg: dict,
               seed: int, split_mode: str, block: str, scheme: str,
               base_meta: dict) -> tuple[list[dict], dict]:
    """One (seed, split, feature-set, partition) cell: run the 4 registered
    methods; return ([run rows], cell summary with per-seed comparison)."""
    import copy

    from packguard.fl import (
        FLConfig,
        FedClient,
        build_clients,
        client_label_distribution,
        make_global_test_split,
        make_group_split,
        paired_correctness,
        run_centralized,
        run_federated,
        run_per_client_routing,
    )
    from src.metrics.stats import mcnemar

    frac = float(((cfg.get("data", {}) or {}).get("test_fraction", 0.2)))
    recs = copy.deepcopy(records)
    if split_mode == "group":
        train, test = make_group_split(recs, frac, seed=seed)
    elif split_mode == "random":
        train, test = make_global_test_split(recs, frac, seed=seed)
    else:
        raise ValueError(f"unknown split mode {split_mode!r}")
    if block == "tfidf":
        _tfidf_blocks(train, test, cache)
    clients = build_clients(train, feature_block=block, scheme=scheme)
    test_client = FedClient("global_test", test, feature_block=block)
    flc = _grid_fl_config(cfg, test_client.input_dim, seed, block)
    mu = float((cfg.get("fl", {}) or {}).get("mu_fedprox", 0.01))
    dist = client_label_distribution(clients)

    methods = ("fedavg", "fedprox", "centralized", "per_client_best")
    res = {
        "fedavg": run_federated(clients, test_client, flc, "fedavg", seed),
        "fedprox": run_federated(clients, test_client, flc, "fedprox", seed),
        "centralized": run_centralized(clients, test_client, flc, seed),
        "per_client_best": run_per_client_routing(
            clients, test, test_client, flc, seed, scheme=scheme),
    }

    rows: list[dict] = []
    y_test = [int(r["label"]) for r in test]
    for method in methods:
        r = res[method]
        m = r["final_metrics"]
        sub = _subgroup_metrics(test, r["final_probs"])
        payload = {
            "kind": "run",
            "name": f"{scheme}__{split_mode}__{block}__{method}__seed{seed}",
            "meta": dict(base_meta),
            "seed": seed,
            "method": method,
            "features": block,
            "split": split_mode,
            "partition": scheme,
            "mock": False,
            "config_sha16": base_meta["config_sha16"],
            "date": base_meta["date"],
            "f1": m.get("f1", m.get("f1_macro")),
            "auc": m.get("auc", m.get("auc_macro")),
            "precision": m.get("precision"),
            "recall": m.get("recall"),
            "n_train": len(train),
            "n_test": m.get("n"),
            "n_test_malicious": m.get("n_test_malicious"),
            "input_dim": test_client.input_dim,
            "client_distribution": dist,
            "per_ecosystem_f1": {k: (v or {}).get("f1") for k, v in sub.items()
                                 if k.startswith("eco_")},
            "subgroup_metrics": sub,
            "mu_fedprox": mu,
            "secure_agg_mask_residual": r.get("secure_agg_mask_residual"),
            "dp": {k: r.get(k) for k in
                   ("dp_enabled", "dp_sigma", "dp_epsilon_per_round")},
            "history_tail": (r.get("history") or [])[-3:],
        }
        if method == "per_client_best":
            payload["macro_metrics"] = r.get("macro_metrics")
            payload["n_uncovered"] = r.get("n_uncovered")
            payload["per_client_global"] = r.get("per_client")
        rows.append(payload)

    # per-seed pre-registered comparison: FedAvg vs centralized
    corr_fl, corr_cent = paired_correctness(
        res["fedavg"]["final_probs"], res["centralized"]["final_probs"], y_test)
    mc = mcnemar(corr_cent, corr_fl, exact=None)
    f1_fl = res["fedavg"]["final_metrics"]["f1"]
    f1_c = res["centralized"]["final_metrics"]["f1"]
    auc_fl = res["fedavg"]["final_metrics"].get("auc")
    auc_c = res["centralized"]["final_metrics"].get("auc")
    cell = {
        "seed": seed, "split": split_mode, "features": block,
        "partition": scheme, "n_test": len(test),
        "n_test_malicious": int(sum(y_test)),
        "fedavg_f1": f1_fl, "centralized_f1": f1_c, "f1_delta": f1_fl - f1_c,
        "fedavg_auc": auc_fl, "centralized_auc": auc_c,
        "auc_delta": (auc_fl - auc_c) if (auc_fl is not None and auc_c is not None) else None,
        "mcnemar_fedavg_vs_centralized": mc,
    }
    return rows, cell


def _mean_std(values: list) -> dict:
    vals = [float(v) for v in values if v is not None]
    if not vals:
        return {"mean": None, "std": None, "n": 0}
    mu = sum(vals) / len(vals)
    var = sum((v - mu) ** 2 for v in vals) / len(vals)  # population std over seeds
    return {"mean": mu, "std": var ** 0.5, "n": len(vals)}


def _aggregate_grid(all_rows: list[dict], all_cells: list[dict]) -> dict:
    """Aggregate per (partition, split, features, method): mean+-std; and per
    (partition, split, features): Wilcoxon over the 5 per-seed FedAvg-vs-
    centralized deltas + per-seed McNemar table (AMENDMENT-3 A3.2)."""
    agg: dict[str, Any] = {"cells": {}, "comparisons": {}}
    groups: dict[tuple, list[dict]] = {}
    for r in all_rows:
        groups.setdefault((r["partition"], r["split"], r["features"], r["method"]),
                          []).append(r)
    for (part, split, block, method), rs in sorted(groups.items()):
        rs = sorted(rs, key=lambda r: r["seed"])
        agg["cells"][f"{part}__{split}__{block}__{method}"] = {
            "partition": part, "split": split, "features": block, "method": method,
            "seeds": [r["seed"] for r in rs],
            "f1": _mean_std([r["f1"] for r in rs]),
            "auc": _mean_std([r["auc"] for r in rs]),
            "precision": _mean_std([r["precision"] for r in rs]),
            "recall": _mean_std([r["recall"] for r in rs]),
            "eco_npm_f1": _mean_std([
                (r.get("per_ecosystem_f1") or {}).get("eco_npm") for r in rs]),
            "eco_pypi_f1": _mean_std([
                (r.get("per_ecosystem_f1") or {}).get("eco_pypi") for r in rs]),
            "mean_n_test": _mean_std([r["n_test"] for r in rs]),
        }
    comps: dict[tuple, list[dict]] = {}
    for c in all_cells:
        comps.setdefault((c["partition"], c["split"], c["features"]), []).append(c)
    for (part, split, block), cs in sorted(comps.items()):
        cs = sorted(cs, key=lambda c: c["seed"])
        f1_deltas = [c["f1_delta"] for c in cs]
        auc_deltas = [c["auc_delta"] for c in cs if c["auc_delta"] is not None]
        agg["comparisons"][f"{part}__{split}__{block}"] = {
            "partition": part, "split": split, "features": block,
            "per_seed": cs,
            "wilcoxon_f1_delta_fedavg_minus_centralized": _wilcoxon_over_seeds(f1_deltas),
            "wilcoxon_auc_delta_fedavg_minus_centralized": (
                _wilcoxon_over_seeds(auc_deltas) if len(auc_deltas) == len(cs)
                else {"note": "auc undefined in some seeds", "deltas": auc_deltas}),
            "f1_delta_mean_std": _mean_std(f1_deltas),
        }
    return agg


def _render_grid_summary(base_meta: dict, agg: dict, cfg: dict,
                         client_dist: dict, n_runs: int) -> str:
    def cell_ms(d: dict) -> str:
        f1, auc = d["f1"], d["auc"]
        fmt = lambda x: ("n/a" if x is None or x.get("mean") is None
                         else f"{x['mean']:.4f}±{x['std']:.4f}")
        return fmt(f1), fmt(auc)

    lines: list[str] = []
    lines.append("# PackGuard multi-seed grid — summary (round 9, AMENDMENT-3)")
    lines.append("")
    lines.append(f"- date: {base_meta['date']}")
    lines.append(f"- config sha16: {base_meta['config_sha16']}; seeds: "
                 f"{base_meta['seeds']}")
    lines.append(f"- runs: {n_runs} (mock=false, real features_v2, 603-sample corpus)")
    lines.append("- primary: group split, F1, FedAvg vs centralized; aggregation "
                 "= Wilcoxon over 5 seeds + per-seed McNemar (A3.2). n=5 seeds "
                 "-> two-sided Wilcoxon minimum p = 0.0625 > 0.05: DESCRIPTIVE ONLY.")
    lines.append("")
    for part, part_label in (("ecosystem", "PRIMARY partition: ecosystem (npm / pypi, 2 clients)"),
                             ("npm_hook", "FALLBACK arm: npm_hook 3-client partition "
                                          "(ecosystem+hook partition of the SAME corpus, "
                                          "NOT a new ecosystem — not cross-ecosystem FL)")):
        lines.append(f"## {part_label}")
        lines.append("")
        lines.append("| split | features | method | F1 (mean±std) | AUC (mean±std) "
                     "| npm F1 | pypi F1 |")
        lines.append("|---|---|---|---|---|---|---|")
        for split in ("group", "random"):
            for block in ("graph", "tfidf"):
                for method in ("fedavg", "fedprox", "centralized", "per_client_best"):
                    d = agg["cells"].get(f"{part}__{split}__{block}__{method}")
                    if not d:
                        continue
                    f1s, aucs = cell_ms(d)
                    eco = lambda k: ("n/a" if d[k]["mean"] is None
                                     else f"{d[k]['mean']:.4f}±{d[k]['std']:.4f}")
                    lines.append(f"| {split} | {block} | {method} | {f1s} | {aucs} "
                                 f"| {eco('eco_npm_f1')} | {eco('eco_pypi_f1')} |")
        lines.append("")
        lines.append(f"### FedAvg vs centralized — per-seed tests ({part})")
        lines.append("")
        lines.append("| split | features | seed | F1 (FL) | F1 (central) | ΔF1 | "
                     "McNemar p | method |")
        lines.append("|---|---|---|---|---|---|---|---|")
        for key, comp in sorted(agg["comparisons"].items()):
            if not key.startswith(part + "__"):
                continue
            for c in comp["per_seed"]:
                mc = c["mcnemar_fedavg_vs_centralized"]
                lines.append(
                    f"| {c['split']} | {c['features']} | {c['seed']} "
                    f"| {c['fedavg_f1']:.4f} | {c['centralized_f1']:.4f} "
                    f"| {c['f1_delta']:+.4f} | {mc['p_value']:.4g} | {mc['method']} |")
        lines.append("")
        lines.append(f"### Wilcoxon over seeds ({part})")
        lines.append("")
        lines.append("| split | features | ΔF1 mean±std | n_pos/n_neg/n_zero | "
                     "Wilcoxon p (F1) | Wilcoxon p (AUC) |")
        lines.append("|---|---|---|---|---|---|")
        for key, comp in sorted(agg["comparisons"].items()):
            if not key.startswith(part + "__"):
                continue
            w1 = comp["wilcoxon_f1_delta_fedavg_minus_centralized"]
            w2 = comp["wilcoxon_auc_delta_fedavg_minus_centralized"]
            ms = comp["f1_delta_mean_std"]
            p1 = "n/a" if w1.get("p_value") is None else f"{w1['p_value']:.4g}"
            p2 = "n/a" if w2.get("p_value") is None else f"{w2['p_value']:.4g}"
            lines.append(
                f"| {comp['split']} | {comp['features']} "
                f"| {ms['mean']:+.4f}±{ms['std']:.4f} "
                f"| {w1['n_pos']}/{w1['n_neg']}/{w1['n_zero']} | {p1} | {p2} |")
        lines.append("")
    lines.append("## Client partitions (train pool; group split, graph block, "
                 "seed 20260922)")
    lines.append("```json")
    lines.append(json.dumps(client_dist, indent=1))
    lines.append("```")
    lines.append("")
    lines.append("## Notes (honest)")
    lines.append("- FedProx(mu=0.01) can coincide exactly with FedAvg: the proximal "
                 "penalty at this mu does not change the trajectory on this data "
                 "(unit-tested that larger mu does).")
    lines.append("- per_client_best = oracle-partition routing (A3.2): each test "
                 "sample scored by its own partition's local model; macro over "
                 "clients is in the JSON rows (macro_metrics).")
    lines.append("- npm_hook partition: ecosystem+hook split of the SAME 603-sample "
                 "corpus — NOT a new ecosystem, NOT cross-ecosystem FL (A3.3). The "
                 "npm_hook client is extreme-skew (~99% malicious; the corpus has "
                 "only ONE hooked benign package, which lands in TRAIN in all 5 "
                 "group splits).")
    lines.append("- tfidf-FedAvg degenerates to an all-malicious predictor "
                 "(recall=1.0, precision = test base rate) in every cell — its F1 "
                 "variation across seeds only tracks test composition, and the "
                 "identical 0.7839 on the random split reflects the stratified "
                 "test set being identical in size/composition across seeds "
                 "(n_test=121, n_mal=78).")
    return "\n".join(lines)


def run_grid(cfg: dict, out_dir: Path = GRID_OUT_DEFAULT,
             features_dir: Optional[Path] = None) -> dict:
    """Round-9 multi-seed grid (AMENDMENT-3, registered before execution).

    Real data only (mock=false enforced); TF-IDF fit per (seed, split) on the
    train pool; every run row records {seed, method, features, split,
    partition, mock, config_sha16, date}. Outputs grid_results.json +
    summary.md under out_dir.
    """
    grid_cfg = (cfg.get("grid", {}) or {})
    seeds = [int(s) for s in grid_cfg.get("seeds", [int(cfg.get("seed", 20260922))])]
    splits = list(grid_cfg.get("splits", ["group", "random"]))
    blocks = list(grid_cfg.get("feature_blocks", ["graph", "tfidf"]))
    partitions = list(grid_cfg.get("partitions", ["ecosystem"]))
    if grid_cfg.get("run_client3") and "npm_hook" not in partitions:
        partitions.append("npm_hook")
    if "tfidf" in blocks:
        cache_path = PROJECT_ROOT / str(grid_cfg.get(
            "text_cache", "outputs/packguard/features/text_v2.json"))
        if not cache_path.exists():
            raise FileNotFoundError(
                f"tfidf grid needs the round-8 text cache {cache_path} "
                "(scripts/packguard_final_runs.py builds it); refusing to fake it")
        with cache_path.open() as f:
            cache = json.load(f)
    else:
        cache = {}

    records, feat_meta = load_feature_records(
        features_dir or ((cfg.get("data", {}) or {}).get(
            "features_dir", FEATURES_DIR_DEFAULT)))
    if feat_meta.get("mock", False):
        raise RuntimeError("run_grid refuses mock data (AMENDMENT-3: real runs only)")

    cfg_sha = config_sha16(cfg)
    base_meta = {
        "seed": "multi", "seeds": seeds,
        "config_sha16": cfg_sha,
        "date": _now(),
        "pipeline": "packguard.eval.run_grid",
        "mock": False,
        "features_source": feat_meta.get("source"),
        "amendment": "AMENDMENT-3 (docs/packguard_prereg.md): multi-seed grid + "
                     "npm_hook fallback partition; registered before execution",
    }

    all_rows: list[dict] = []
    all_cells: list[dict] = []
    client_dist_sample: dict[str, dict] = {}
    total = len(partitions) * len(seeds) * len(splits) * len(blocks)
    done = 0
    for scheme in partitions:
        for seed in seeds:
            for split_mode in splits:
                for block in blocks:
                    done += 1
                    print(f"[grid {done}/{total}] {scheme} seed={seed} "
                          f"split={split_mode} block={block}", flush=True)
                    rows, cell = _grid_cell(
                        records, cache, cfg, seed, split_mode, block, scheme,
                        base_meta)
                    all_rows.extend(rows)
                    all_cells.append(cell)
                    # one partition snapshot per scheme, taken deterministically
                    # from the PRIMARY cell (group split, graph block, seed[0])
                    if (seed == seeds[0] and split_mode == "group"
                            and block == blocks[0]):
                        client_dist_sample[scheme] = rows[0]["client_distribution"]

    agg = _aggregate_grid(all_rows, all_cells)
    out_dir.mkdir(parents=True, exist_ok=True)
    results_path = out_dir / "grid_results.json"
    with results_path.open("w", encoding="utf-8") as f:
        json.dump({
            "meta": base_meta,
            "n_runs": len(all_rows),
            "rows": all_rows,
            "per_seed_comparisons": all_cells,
            "aggregate": agg,
        }, f, indent=1, default=str)
    summary_path = out_dir / "summary.md"
    summary_path.write_text(_render_grid_summary(
        base_meta, agg, cfg, client_dist_sample, len(all_rows)), encoding="utf-8")
    return {
        "meta": base_meta,
        "n_runs": len(all_rows),
        "rows_written": str(results_path),
        "summary_written": str(summary_path),
        "aggregate_cells": len(agg["cells"]),
        "comparisons": len(agg["comparisons"]),
    }


# ---------------------------------------------------------------------------
# Round-11 P0 (AMENDMENT-5; W1) — strong baselines, FedProx fix check,
# hashing text arm, 20-seed re-run, TOST equivalence. Registered in
# docs/packguard_prereg.md AMENDMENT-5 BEFORE execution. The round-9 grid
# above is untouched (still re-runnable, with the registered mu-routing fix
# now changing its "fedavg" arm to true FedAvg — AMENDMENT-5 A5.7).
# ---------------------------------------------------------------------------
def tost_equivalence(deltas: Sequence[float], margin: float = 0.02,
                     alpha: float = 0.10) -> dict:
    """Registered equivalence rule (AMENDMENT-5 A5.3): the mean of paired
    deltas with its two-sided 100(1-alpha)% CI (t, df=n-1) must lie ENTIRELY
    inside (-margin, +margin). alpha=0.10 => 90% CI."""
    from scipy import stats as sps

    d = np.asarray([float(x) for x in deltas], dtype=float)
    n = int(len(d))
    mean = float(d.mean()) if n else float("nan")
    if n < 2:
        return {"n": n, "mean_delta": mean, "ci_low": None, "ci_high": None,
                "margin": margin, "equivalent": False,
                "method": "TOST via 90% t CI (insufficient n)", "alpha": alpha}
    sd = float(d.std(ddof=1))
    tcrit = float(sps.t.ppf(1.0 - alpha / 2.0, n - 1))
    half = tcrit * sd / np.sqrt(n)
    lo, hi = mean - half, mean + half
    return {
        "n": n, "mean_delta": mean, "sd": sd, "t_crit": tcrit,
        "ci_low": float(lo), "ci_high": float(hi), "margin": float(margin),
        "equivalent": bool(lo > -margin and hi < margin),
        "ci_within": "(-%.3f, +%.3f)" % (margin, margin),
        "method": "TOST via 90% t CI (paired over seeds)", "alpha": alpha,
    }


def holm_adjust(pvals: Sequence[float]) -> list[float]:
    """Holm step-down adjusted p-values (monotone, clipped to 1)."""
    m = len(pvals)
    order = sorted(range(m), key=lambda i: float(pvals[i]))
    adj = [0.0] * m
    prev = 0.0
    for rank, idx in enumerate(order):
        val = min(1.0, (m - rank) * float(pvals[idx]))
        val = max(val, prev)          # enforce monotonicity
        prev = val
        adj[idx] = float(val)
    return adj


P0_OUT_DEFAULT = PROJECT_ROOT / "outputs" / "packguard" / "p0"


def run_p0_grid(cfg: dict, out_dir: Path = P0_OUT_DEFAULT,
                features_dir: Optional[Path] = None) -> dict:
    """Round-11 P0 grid (AMENDMENT-5, registered before execution).

    Per (seed, split, block): strong_centralized + fedavg + per_client_best
    (+ fedprox mu sweep on the registered split) via
    packguard.strong_baseline.run_p0_cell — one shared split / scaler /
    train-only C per cell. Real features only (mock refused)."""
    p0_cfg = dict(cfg.get("p0", {}) or {})
    seeds = [int(s) for s in p0_cfg.get("seeds", [])]
    splits = list(p0_cfg.get("splits", ["group", "random"]))
    blocks = list(p0_cfg.get("blocks", ["graph", "hashing_tfidf"]))
    mu_values = [float(m) for m in p0_cfg.get("mu_values", [0.01, 0.1, 1.0])]
    fedprox_split = str(p0_cfg.get("fedprox_split", "group"))
    fedavg_rounds = int(p0_cfg.get("fedavg_rounds", 2))
    fedprox_rounds = int(p0_cfg.get("fedprox_rounds", 15))
    margin = float(p0_cfg.get("tost_margin", 0.02))
    if not seeds:
        raise ValueError("config p0.seeds is empty")

    records, feat_meta = load_feature_records(
        features_dir or ((cfg.get("data", {}) or {}).get(
            "features_dir", FEATURES_DIR_DEFAULT)))
    if feat_meta.get("mock", False):
        raise RuntimeError("run_p0_grid refuses mock data (AMENDMENT-5)")

    # stateless corpus-wide hash matrix: transform ONCE, slice per split
    precomputed = None
    text_cache: dict[str, str] = {}
    if "hashing_tfidf" in blocks:
        cache_path = PROJECT_ROOT / str(p0_cfg.get(
            "text_cache", "outputs/packguard/features/text_v2.json"))
        if not cache_path.exists():
            raise FileNotFoundError(f"hashing arm needs the text cache {cache_path}")
        with cache_path.open() as f:
            text_cache = json.load(f)
        from packguard.strong_baseline import HashingTextFeaturizer

        vec = HashingTextFeaturizer()
        H = vec.transform([text_cache.get(str(r["sample_id"]), "") or ""
                           for r in records])
        index = {str(r["sample_id"]): i for i, r in enumerate(records)}
        precomputed = (H, index)

    cfg_sha = config_sha16(cfg)
    base_meta = {
        "seed": "multi", "seeds": seeds, "config_sha16": cfg_sha,
        "date": _now(), "pipeline": "packguard.eval.run_p0_grid",
        "mock": False, "features_source": feat_meta.get("source"),
        "amendment": "AMENDMENT-5 (docs/packguard_prereg.md): strong "
                     "centralized + fixed FedProx + hashing text arm + TOST; "
                     "registered before execution",
        "mu_values": mu_values, "fedprox_split": fedprox_split,
        "tost_margin": margin,
    }

    frac = float(((cfg.get("data", {}) or {}).get("test_fraction", 0.2)))
    from packguard import strong_baseline as sb_mod

    all_rows: list[dict] = []
    cells: list[dict] = []
    total = len(seeds) * len(splits) * len(blocks)
    done = 0
    for seed in seeds:
        for split_mode in splits:
            recs = copy.deepcopy(records)
            if split_mode == "group":
                train, test = make_group_split(recs, frac, seed=seed)
            elif split_mode == "random":
                train, test = make_global_test_split(recs, frac, seed=seed)
            else:
                raise ValueError(f"unknown split mode {split_mode!r}")
            for block in blocks:
                done += 1
                mus = mu_values if split_mode == fedprox_split else ()
                print(f"[p0 {done}/{total}] seed={seed} split={split_mode} "
                      f"block={block} mus={mus}", flush=True)
                cell = sb_mod.run_p0_cell(
                    train, test, block, seed=seed, split=split_mode,
                    text_cache=text_cache, precomputed=precomputed,
                    mu_values=mus, fedavg_rounds=fedavg_rounds,
                    fedprox_rounds=fedprox_rounds)
                f1_avg = cell.methods["fedavg"]["final_metrics"]["f1"]
                f1_cent = cell.methods["strong_centralized"]["final_metrics"]["f1"]
                cell_summary = {
                    "seed": seed, "split": split_mode, "block": block,
                    "n_train": cell.n_train, "n_test": cell.n_test,
                    "C_selected": cell.C_selected,
                    "fedavg_f1": f1_avg,
                    "strong_centralized_f1": f1_cent,
                    "f1_delta_fedavg_minus_central": f1_avg - f1_cent,
                }
                cells.append(cell_summary)
                for method, res in sorted(cell.methods.items()):
                    m = res["final_metrics"]
                    mu = None
                    name = method
                    if method.startswith("fedprox_mu"):
                        mu = float(method[len("fedprox_mu"):])
                    all_rows.append({
                        "kind": "run",
                        "name": f"p0__{split_mode}__{block}__{name}__seed{seed}",
                        "meta": dict(base_meta),
                        "seed": seed, "method": name, "features": block,
                        "split": split_mode, "partition": "ecosystem",
                        "mock": False, "mu": mu,
                        "config_sha16": cfg_sha, "date": base_meta["date"],
                        "C_selected": cell.C_selected,
                        "cv_table": cell.cv_table,
                        "scaler": cell.meta["scaler"],
                        "client_sizes": cell.meta["client_sizes"],
                        "f1": m.get("f1"), "auc": m.get("auc"),
                        "precision": m.get("precision"),
                        "recall": m.get("recall"),
                        "n_train": cell.n_train, "n_test": cell.n_test,
                        "n_test_malicious": m.get("n_test_malicious"),
                        "method_detail": {k: v for k, v in res.items()
                                          if k != "final_metrics"},
                    })

    agg = _aggregate_p0(all_rows, cells, margin)
    out_dir.mkdir(parents=True, exist_ok=True)
    results_path = out_dir / "p0_results.json"
    with results_path.open("w", encoding="utf-8") as f:
        json.dump({"meta": base_meta, "n_runs": len(all_rows),
                   "rows": all_rows, "per_seed_cells": cells,
                   "aggregate": agg}, f, indent=1, default=str)
    summary_path = out_dir / "summary.md"
    summary_path.write_text(_render_p0_summary(base_meta, agg, len(all_rows)),
                            encoding="utf-8")
    return {"meta": base_meta, "n_runs": len(all_rows),
            "rows_written": str(results_path),
            "summary_written": str(summary_path),
            "tost_primary": agg["tost_primary"],
            "comparisons": agg["comparisons"]}


def _aggregate_p0(all_rows: list[dict], cells: list[dict],
                  margin: float) -> dict:
    """P0 aggregation (AMENDMENT-5 A5.6): mean+-std cells; FedAvg-vs-strong-
    centralized Wilcoxon exact + Holm over the 4 registered comparisons;
    TOST on all 4 cells (PRIMARY = group/graph); descriptive mu sweep."""
    def _ms(vals):
        v = [float(x) for x in vals if x is not None]
        if not v:
            return {"mean": None, "std": None, "n": 0}
        mu = sum(v) / len(v)
        return {"mean": mu, "std": (sum((x - mu) ** 2 for x in v) / len(v)) ** 0.5,
                "n": len(v)}

    groups: dict[tuple, list[dict]] = {}
    for r in all_rows:
        groups.setdefault((r["split"], r["features"], r["method"]), []).append(r)
    agg_cells = {}
    for (split, block, method), rs in sorted(groups.items()):
        rs = sorted(rs, key=lambda r: r["seed"])
        agg_cells[f"{split}__{block}__{method}"] = {
            "split": split, "block": block, "method": method,
            "seeds": [r["seed"] for r in rs],
            "f1": _ms([r["f1"] for r in rs]),
            "auc": _ms([r["auc"] for r in rs]),
            "precision": _ms([r["precision"] for r in rs]),
            "recall": _ms([r["recall"] for r in rs]),
            "C_selected": _ms([r.get("C_selected") for r in rs]),
        }

    # per-seed comparisons: FedAvg vs strong-centralized (4 registered cells)
    comps = {}
    raw_ps = []
    keys = []
    for (split, block) in (("group", "graph"), ("group", "hashing_tfidf"),
                           ("random", "graph"), ("random", "hashing_tfidf")):
        cs = sorted([c for c in cells if c["split"] == split
                     and c["block"] == block], key=lambda c: c["seed"])
        deltas = [c["f1_delta_fedavg_minus_central"] for c in cs]
        w = _wilcoxon_over_seeds(deltas)
        # exact method per AMENDMENT-4/5, fallback disclosed
        p_exact = None
        try:
            from scipy import stats as sps
            res = sps.wilcoxon(deltas, method="exact")
            p_exact = float(res.pvalue)
        except Exception as exc:
            w["exact_error"] = f"{type(exc).__name__}: {exc}"
        w["p_value_exact"] = p_exact
        tost = tost_equivalence(deltas, margin=margin)
        comps[f"{split}__{block}"] = {
            "split": split, "block": block, "n_seeds": len(cs),
            "per_seed": cs, "deltas": deltas,
            "delta_mean_std": _ms(deltas),
            "wilcoxon": w, "tost": tost,
        }
        raw_ps.append(w.get("p_value_exact") if p_exact is not None
                      else (w.get("p_value") or 1.0))
        keys.append(f"{split}__{block}")
    adj = holm_adjust(raw_ps)
    for k, a in zip(keys, adj):
        comps[k]["wilcoxon"]["p_holm"] = a
        comps[k]["wilcoxon"]["significant_holm_0.05"] = bool(a < 0.05)

    # TOST primary cell (registered)
    agg = {"cells": agg_cells, "comparisons": comps,
           "tost_primary": comps["group__graph"]["tost"]}

    # descriptive mu sweep (group split): fedprox(mu) - fedavg per seed
    per_seed_f1: dict[tuple, dict[int, float]] = {}
    for r in all_rows:
        per_seed_f1.setdefault((r["split"], r["features"]), {})[
            (r["seed"], r["method"])] = r["f1"]
    sweep = {}
    for block in ("graph", "hashing_tfidf"):
        for mu in (0.01, 0.1, 1.0):
            key = f"fedprox_mu{mu:g}"
            ds = []
            for (split, blk), d in per_seed_f1.items():
                if split != "group" or blk != block:
                    continue
                for (seed, method), f1 in d.items():
                    if method == key:
                        base = d.get((seed, "fedavg"))
                        if base is not None:
                            ds.append(f1 - base)
            if ds:
                w = _wilcoxon_over_seeds(ds)
                sweep[f"{block}__mu{mu:g}"] = {
                    "block": block, "mu": mu, "deltas_fedprox_minus_fedavg": ds,
                    "delta_mean_std": _ms(ds),
                    "wilcoxon_descriptive": w,
                }
    agg["mu_sweep"] = sweep
    return agg


def _render_p0_summary(base_meta: dict, agg: dict, n_runs: int) -> str:
    lines: list[str] = []
    lines.append("# PackGuard P0 — strong baselines + FedProx fix + TOST "
                 "(round 11, AMENDMENT-5)")
    lines.append("")
    lines.append(f"- date: {base_meta['date']}")
    lines.append(f"- config sha16: {base_meta['config_sha16']}; seeds: "
                 f"{base_meta['seeds']}")
    lines.append(f"- runs: {n_runs} (mock=false, features_v2, 603-sample corpus)")
    lines.append(f"- mu sweep: {base_meta['mu_values']} on split="
                 f"{base_meta['fedprox_split']}; TOST margin "
                 f"±{base_meta['tost_margin']} F1 (A5.3)")
    lines.append("")
    lines.append("## Final metrics (global held-out test; mean±std over 20 seeds)")
    lines.append("")
    lines.append("| split | block | method | F1 | AUC | C (mean) |")
    lines.append("|---|---|---|---|---|---|")
    for key, d in sorted(agg["cells"].items()):
        fmt = lambda x: ("n/a" if x.get("mean") is None
                         else f"{x['mean']:.4f}±{x['std']:.4f}")
        c = d["C_selected"]
        lines.append(f"| {d['split']} | {d['block']} | {d['method']} "
                     f"| {fmt(d['f1'])} | {fmt(d['auc'])} | {c['mean']:.3g} |")
    lines.append("")
    lines.append("## TOST + Wilcoxon (FedAvg − strong-centralized, per seed)")
    lines.append("")
    lines.append("| split | block | ΔF1 mean±std | 90% CI | TOST ±0.02 "
                 "| Wilcoxon p (exact) | p Holm |")
    lines.append("|---|---|---|---|---|---|---|")
    for key, comp in sorted(agg["comparisons"].items()):
        t = comp["tost"]
        w = comp["wilcoxon"]
        ms = comp["delta_mean_std"]
        pe = w.get("p_value_exact")
        pe_s = "n/a" if pe is None else f"{pe:.4g}"
        ph = w.get("p_holm")
        ph_s = "n/a" if ph is None else f"{ph:.4g}"
        lines.append(
            f"| {comp['split']} | {comp['block']} "
            f"| {ms['mean']:+.4f}±{ms['std']:.4f} "
            f"| [{t['ci_low']:+.4f}, {t['ci_high']:+.4f}] "
            f"| {'PASS' if t['equivalent'] else 'FAIL'} | {pe_s} | {ph_s} |")
    lines.append("")
    lines.append("## FedProx mu sweep (group split; ΔF1 = FedProx(μ) − FedAvg) "
                 "— DESCRIPTIVE")
    lines.append("")
    lines.append("| block | mu | ΔF1 mean±std | n_pos/n_neg/n_zero | "
                 "Wilcoxon p |")
    lines.append("|---|---|---|---|---|")
    for key, s in sorted(agg["mu_sweep"].items()):
        w = s["wilcoxon_descriptive"]
        ms = s["delta_mean_std"]
        p = "n/a" if w.get("p_value") is None else f"{w['p_value']:.4g}"
        lines.append(f"| {s['block']} | {s['mu']:g} "
                     f"| {ms['mean']:+.4f}±{ms['std']:.4f} "
                     f"| {w['n_pos']}/{w['n_neg']}/{w['n_zero']} | {p} |")
    lines.append("")
    lines.append("## Notes (honest)")
    lines.append("- Old round-9 arms are NOT deleted: the torch-path grid "
                 "stays in outputs/packguard/fl_multiseed/; its \"fedavg\" "
                 "arm was FedProx(0.01) by the mu-routing bug (A5.4).")
    lines.append("- Shared preprocessing disclosed: ONE StandardScaler per "
                 "(seed, split) fit on pooled TRAIN, shared by FL clients; "
                 "C selected by 3-fold CV on pooled TRAIN only.")
    lines.append("- hashing block: StandardScaler(with_mean=False) (sparse-safe, "
                 "scale-only); HashingVectorizer is stateless (FL-valid).")
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="PackGuard FL pilot harness")
    ap.add_argument("--config", default=str(CONFIG_DEFAULT))
    ap.add_argument("--synthetic", action="store_true",
                    help="use the mock fixture (results flagged mock=true)")
    ap.add_argument("--features-dir", default=None)
    ap.add_argument("--out-dir", default=None)
    ap.add_argument("--grid", action="store_true",
                    help="round-9 multi-seed grid (AMENDMENT-3); writes "
                         "outputs/packguard/fl_multiseed/{grid_results.json,summary.md}")
    ap.add_argument("--p0", action="store_true",
                    help="round-11 P0 strong-baseline grid (AMENDMENT-5); "
                         "writes outputs/packguard/p0/{p0_results.json,summary.md}")
    args = ap.parse_args(argv)
    cfg = load_yaml(args.config)
    if args.p0:
        out_dir = Path(args.out_dir) if args.out_dir else P0_OUT_DEFAULT
        summary = run_p0_grid(cfg, out_dir=out_dir,
                              features_dir=Path(args.features_dir)
                              if args.features_dir else None)
        print(f"p0 rows -> {summary['rows_written']} ({summary['n_runs']} runs)")
        print(f"p0 summary -> {summary['summary_written']}")
        t = summary["tost_primary"]
        print(f"TOST primary (group/graph, ±{t['margin']}): equivalent="
              f"{t['equivalent']} mean ΔF1={t['mean_delta']:+.4f} "
              f"90%CI=[{t['ci_low']:+.4f}, {t['ci_high']:+.4f}]")
        return 0
    if args.grid:
        out_dir = Path(args.out_dir) if args.out_dir else GRID_OUT_DEFAULT
        summary = run_grid(cfg, out_dir=out_dir,
                           features_dir=Path(args.features_dir)
                           if args.features_dir else None)
        print(f"grid rows -> {summary['rows_written']} ({summary['n_runs']} runs)")
        print(f"grid summary -> {summary['summary_written']}")
        return 0
    out_dir = Path(args.out_dir) if args.out_dir else OUT_DIR_DEFAULT
    summary = run_pipeline(cfg, synthetic=args.synthetic,
                           features_dir=Path(args.features_dir)
                           if args.features_dir else None,
                           out_dir=out_dir)
    print(f"results -> {summary['outputs']['results_jsonl']}")
    print(f"summary -> {summary['outputs']['summary_md']}")
    print(f"mock={summary['meta']['mock']} "
          f"pending={len(summary['pending'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
