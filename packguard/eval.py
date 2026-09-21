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
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

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

__all__ = ["run_pipeline", "main"]

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_DEFAULT = PROJECT_ROOT / "configs" / "packguard_fl.yaml"
FEATURES_DIR_DEFAULT = PROJECT_ROOT / "outputs" / "packguard" / "features"
OUT_DIR_DEFAULT = PROJECT_ROOT / "outputs" / "packguard" / "fl"


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


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="PackGuard FL pilot harness")
    ap.add_argument("--config", default=str(CONFIG_DEFAULT))
    ap.add_argument("--synthetic", action="store_true",
                    help="use the mock fixture (results flagged mock=true)")
    ap.add_argument("--features-dir", default=None)
    ap.add_argument("--out-dir", default=str(OUT_DIR_DEFAULT))
    args = ap.parse_args(argv)
    cfg = load_yaml(args.config)
    summary = run_pipeline(cfg, synthetic=args.synthetic,
                           features_dir=Path(args.features_dir)
                           if args.features_dir else None,
                           out_dir=Path(args.out_dir))
    print(f"results -> {summary['outputs']['results_jsonl']}")
    print(f"summary -> {summary['outputs']['summary_md']}")
    print(f"mock={summary['meta']['mock']} "
          f"pending={len(summary['pending'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
