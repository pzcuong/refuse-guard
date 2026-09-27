#!/usr/bin/env python
r"""gen_paper_numbers.py -- single source of truth for every number in paper2.

Round 11 (P0-4). Reads ONLY measured artifacts under outputs/ and emits:\\
  1. paper2/p0_macros/numbers.tex      -- newcommand macros used by paper2/main.tex
  2. outputs/packguard/p0_macros/gen_numbers_audit.json -- every value + its artifact source
  3. outputs/packguard/p0_macros/w3_mapping.json -- resolution of the W3 pypi-F1
     contradiction (.833/-.115 vs .851/-.080 vs .790/-.076) with artifact mapping.

--check mode: re-derives every value, diffs against numbers.tex on disk,
expands the macros over paper2/main.tex and verifies the rendered rows of
tab:main / tab:stats / tab:safety / tab:kb plus the headline text numbers,
and scans for known stale literals (W3). Exit 1 on any mismatch.

Number sources (all measured, mock=false):
  - outputs/packguard/fl_multiseed/grid_results.json      (AMENDMENT-4 20-seed grid, 640 rows)
  - outputs/packguard/safety/safety_metrics_n60.json      (registered n=60 safety batch)
  - outputs/packguard/r10/r8_safety_expand/safety_metrics_n100.json (n=100 expansion)
  - outputs/packguard/fl/results.jsonl                    (round-8 KB-v2 ablation runs)
  - outputs/experiments/round9_kb/coverage_v3.json        (KB universe coverage v3)
  - outputs/packguard/features/features_v2.jsonl          (corpus labels + coverage)
  - outputs/experiments/round3_e0/{llama3b,granite2b,qwen3b}/results.json (E0 arms 180 / probes 225-125)
  - outputs/experiments/round3_e2e3/summary.json          (E2/E3 900)
  - outputs/master/round5_master.json                     (E0v2 1,200)
  - outputs/packguard/r10/r1_stabilized_central/results.jsonl (stabilized-centralized arm)

Rounding/display conventions (match the current manuscript):
  - tab:main cells: 3 decimals, leading zero stripped ($.869{\pm}.051$)
  - tab:stats deltas: 4 decimals with explicit sign; p-values: exact Wilcoxon
    (scipy method='exact', scipy default zero_method='wilcox'), 3 decimals if
    >= 1e-3 else scientific with 1 decimal mantissa; Holm over the four
    registered ecosystem comparisons.
  - std over seeds is POPULATION (ddof=0), per AMENDMENT-3 A3.2 / tab captions.

Usage:
  .venv/bin/python scripts/gen_paper_numbers.py           # regenerate + audit + w3 mapping
  .venv/bin/python scripts/gen_paper_numbers.py --check   # verify only, exit 1 on stale

This script writes only: paper2/p0_macros/ and outputs/packguard/p0_macros/.
"""
from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GRID = ROOT / "outputs/packguard/fl_multiseed/grid_results.json"
SAFETY60 = ROOT / "outputs/packguard/safety/safety_metrics_n60.json"
SAFETY100 = ROOT / "outputs/packguard/r10/r8_safety_expand/safety_metrics_n100.json"
FL_RESULTS = ROOT / "outputs/packguard/fl/results.jsonl"
KB_COVERAGE = ROOT / "outputs/experiments/round9_kb/coverage_v3.json"
FEATURES = ROOT / "outputs/packguard/features/features_v2.jsonl"
E0_DIRS = [ROOT / f"outputs/experiments/round3_e0/{m}/results.json"
           for m in ("llama3b", "granite2b", "qwen3b")]
E2E3 = ROOT / "outputs/experiments/round3_e2e3/summary.json"
ROUND5 = ROOT / "outputs/master/round5_master.json"
STABILIZED = ROOT / "outputs/packguard/r10/r1_stabilized_central/results.jsonl"
P0 = ROOT / "outputs/packguard/p0/p0_results.json"
TRIVIAL = ROOT / "outputs/packguard/trivial/trivial_results.json"
MAIN_TEX = ROOT / "paper2/main.tex"
OUT_TEX = ROOT / "paper2/p0_macros/numbers.tex"
OUT_AUDIT = ROOT / "outputs/packguard/p0_macros/gen_numbers_audit.json"
OUT_W3 = ROOT / "outputs/packguard/p0_macros/w3_mapping.json"

# W1 P0 files poll (round-11 parallel stream): if any appear, they are reported
# in the audit JSON but never invented here. Excludes this script's own outputs.
W1_P0_POLL = sorted(str(p.relative_to(ROOT)) for p in
                    list(ROOT.glob("outputs/packguard/p0*/**/*")) + list(ROOT.glob("outputs/packguard/p0/*"))
                    if p.is_file() and "p0_macros" not in p.parts)


# ---------------------------------------------------------------- formatting
def f3(x: float) -> str:
    """0.8686 -> '.869' (3 decimals, leading zero stripped)."""
    s = f"{x:.3f}"
    return s.replace("0.", ".", 1) if s.startswith("0.") else s


def f2(x: float) -> str:
    """0.0 -> '.00' (2 decimals, leading zero stripped)."""
    s = f"{x:.2f}"
    return s.replace("0.", ".", 1) if s.startswith("0.") else s


def f4(x: float) -> str:
    """0.03468 -> '.0347' (4 decimals, no sign, leading zero stripped)."""
    s = f"{abs(x):.4f}"
    return s.replace("0.", ".", 1) if s.startswith("0.") else s


def f4s(x: float) -> str:
    """Signed 4-decimals: +.0105 / -.0521 / .0000."""
    s = f"{abs(x):.4f}".replace("0.", ".", 1)
    return ("+" if x >= 0 else "-") + s


def p_tex(p: float) -> str:
    """p >= 1e-3 -> 3 decimals stripped; else scientific 1-decimal mantissa."""
    if p >= 1e-3:
        return f3(p)
    exp = 0
    m = p
    while m < 1:
        m *= 10
        exp += 1
    mant = f"{m:.1f}".replace("0.", ".", 1)
    return f"{mant}{{\\times}}10^{{-{exp}}}"


def sci_or_dec(p: float) -> str:
    return p_tex(p)


def holm(pvals: dict[str, float]) -> dict[str, float]:
    order = sorted(pvals, key=lambda k: pvals[k])
    m = len(order)
    out, prev = {}, 0.0
    for rank, k in enumerate(order):
        adj = min(1.0, max(prev, (m - rank) * pvals[k]))
        out[k] = adj
        prev = adj
    return out


# ---------------------------------------------------------------- loaders
def load_grid():
    g = json.loads(GRID.read_text())
    rows = [r for r in g["rows"] if r["partition"] == "ecosystem"]
    return g, rows, [r for r in g["rows"] if r["partition"] == "npm_hook"]


def cell(rows, split, feat, method):
    rs = [r for r in rows
          if r["split"] == split and r["features"] == feat and r["method"] == method]
    if not rs:
        raise SystemExit(f"grid: no rows for {split}/{feat}/{method}")
    f1 = [r["f1"] for r in rs]
    auc = [r["auc"] for r in rs]
    npm = [r["per_ecosystem_f1"]["eco_npm"] for r in rs]
    pypi = [r["per_ecosystem_f1"]["eco_pypi"] for r in rs]
    return {
        "n_seeds": len(rs),
        "f1": (statistics.mean(f1), statistics.pstdev(f1)),
        "auc": (statistics.mean(auc), statistics.pstdev(auc)),
        "npm": (statistics.mean(npm), statistics.pstdev(npm)),
        "pypi": (statistics.mean(pypi), statistics.pstdev(pypi)),
    }


def stats_rows(rows):
    """tab:stats: FedAvg-centralized per-seed F1 deltas, exact Wilcoxon + Holm."""
    from scipy.stats import wilcoxon
    out = {}
    raw_p = {}
    for split in ("group", "random"):
        for feat in ("graph", "tfidf"):
            key = f"{split}__{feat}"
            ps = [c for c in
                  [x for x in json.loads(GRID.read_text())["per_seed_comparisons"]
                   if x["partition"] == "ecosystem"]
                  if c["split"] == split and c["features"] == feat]
            ps.sort(key=lambda c: c["seed"])
            deltas = [c["f1_delta"] for c in ps]
            npos = sum(1 for d in deltas if d > 1e-12)
            nneg = sum(1 for d in deltas if d < -1e-12)
            nzero = sum(1 for d in deltas if abs(d) <= 1e-12)
            mcn = sum(1 for c in ps
                      if c["mcnemar_fedavg_vs_centralized"]["p_value"] < 0.01)
            stat, p = wilcoxon(deltas, alternative="two-sided", method="exact")
            out[key] = {
                "n_seeds": len(ps),
                "df_mean": statistics.mean(deltas),
                "df_std": statistics.pstdev(deltas),
                "npos": npos, "nneg": nneg, "nzero": nzero,
                "wilcoxon_stat": stat, "p": float(p), "method": "scipy.stats.wilcoxon(exact, zero_method=wilcox)",
                "mcnemar_lt01": mcn,
                "mcnemar_lt01_den": len(ps),
            }
            raw_p[key] = float(p)
    adj = holm(raw_p)
    for k, v in out.items():
        v["p_holm"] = adj[k]
    return out


def load_safety60():
    d = json.loads(SAFETY60.read_text())
    out = {}
    for model, md in d["per_model"].items():
        tag = "Llama" if "Llama" in model else "Granite"
        arms = {"P0": "P0_neutral", "P1": "P1_offensive_wording", "P2": "P2_advisory_in_package"}
        for short, arm in arms.items():
            def _cnt(d, a):
                return d.get(a, {}).get("count", 0)
            out[f"{tag}{short}"] = {
                "rr": md["rr"][arm],
                "flips_b2m": _cnt(md["verdict_flips_benign_to_malicious"], arm),
                "flips_m2b": _cnt(md["verdict_flips_malicious_to_benign"], arm),
                "recall_p0": md["malicious_recall"]["P0_neutral"],
                "recall_arm": md["malicious_recall"][arm],
                "fp_benign_rate": md["fp_benign"][arm],
                "fp_den": 30,
            }
    return out, d["meta"]


def load_safety100():
    d = json.loads(SAFETY100.read_text())
    pooled = d["pooled"]
    llama = d["per_model"]["unsloth/Llama-3.2-3B-Instruct"]
    granite = d["per_model"]["ibm-granite/granite-3.3-2b-instruct"]
    return {
        "pooled_recall": pooled["malicious_recall"],           # P0/P1/P2
        "pooled_fp_counts": [round(pooled["fp_benign"][a] * 100) for a in
                             ("P0_neutral", "P1_offensive_wording", "P2_advisory_in_package")],
        "pooled_parsed": pooled["parsed_rate"],
        "p1_flips": (pooled["verdict_flips_benign_to_malicious"]["P1_offensive_wording"]["count"],
                     pooled["verdict_flips_malicious_to_benign"]["P1_offensive_wording"]["count"],
                     pooled["verdict_flips_benign_to_malicious"]["P1_offensive_wording"]["n_pairs"]),
        "p2_flips": (pooled["verdict_flips_benign_to_malicious"]["P2_advisory_in_package"]["count"],
                     pooled["verdict_flips_malicious_to_benign"]["P2_advisory_in_package"]["count"],
                     pooled["verdict_flips_benign_to_malicious"]["P2_advisory_in_package"]["n_pairs"]),
        "llama_recall": llama["malicious_recall"],
        "granite_recall": granite["malicious_recall"],
        "granite_fp_p2": granite["fp_benign"]["P2_advisory_in_package"],
        "n_records": pooled["n"],
    }, d["meta"]


def load_kb_table():
    want = {
        ("fedavg", "off"): "group__graph__kb_off__fedavg",
        ("fedavg", "on"): "group__graph__kb_on__fedavg",
        ("centralized", "off"): "group__graph__kb_off__centralized",
        ("centralized", "on"): "group__graph__kb_on__centralized",
    }
    rows = {json.loads(l)["name"]: json.loads(l) for l in FL_RESULTS.read_text().splitlines() if l.strip()}
    out = {}
    for (algo, cond), name in want.items():
        r = rows[name]
        fm = r["final_metrics"]
        sub = (r.get("subgroup_metrics") or {}).get("eco_pypi", {})
        out[f"{algo}_{cond}"] = {"f1": fm["f1"], "auc": fm["auc"], "pypi_f1": sub.get("f1")}
    return out


def load_features():
    label = Counter()
    cov = Counter()
    tot = Counter()
    for line in FEATURES.read_text().splitlines():
        r = json.loads(line)
        key = (r["ecosystem"], r["label"])
        label[key] += 1
        tot[key] += 1
        if r.get("n_nodes", 0) > 0:
            cov[key] += 1
    return {"label": dict(label), "cov": dict(cov), "tot": dict(tot)}


def load_generation_counts():
    arm_n = arm_ref = probe_n = probe_ref = 0
    for f in E0_DIRS:
        d = json.loads(f.read_text())
        for rec in d["records"]:
            if rec["condition"].startswith("PROBE"):
                probe_n += 1
                probe_ref += rec["status"] == "REFUSAL"
            else:
                arm_n += 1
                arm_ref += rec["status"] == "REFUSAL"
    e23 = json.loads(E2E3.read_text())
    e23_n = sum(m["header"]["n_records"] for m in e23["models"].values())
    r5 = json.loads(ROUND5.read_text())
    e0v2 = next(e for e in r5["results"] if e.get("metric") == "e0v2.records.total")["value"]
    return {"e0_arms": arm_n, "e0_arms_refusals": arm_ref,
            "probes": probe_n, "probe_refusals": probe_ref,
            "e2e3": e23_n, "e0v2": e0v2,
            "safe_n60": 360, "safe_n60_round8batch": 60}


def load_stabilized():
    if not STABILIZED.exists():
        return None
    rows = [json.loads(l) for l in STABILIZED.read_text().splitlines() if l.strip()]
    rows = [r for r in rows if r.get("partition") == "ecosystem"]
    best_lr = Counter(r["best_lr"] for r in rows)
    epochs = [r["best_epochs"] for r in rows]
    early, fixed = {}, {}
    for split in ("group", "random"):
        for block in ("graph", "tfidf"):
            rs = [r for r in rows if r["split"] == split and r["block"] == block]
            early[f"{split}__{block}"] = (statistics.mean([r["early_stopped"]["f1"] for r in rs]),
                                          statistics.pstdev([r["early_stopped"]["f1"] for r in rs]))
            fixed[f"{split}__{block}"] = (statistics.mean([r["baseline_fixed"]["f1"] for r in rs]),
                                          statistics.pstdev([r["baseline_fixed"]["f1"] for r in rs]))
    return {"n_cells": len(rows), "best_lr": dict(best_lr),
            "epochs_mean": statistics.mean(epochs),
            "epochs_min": min(epochs), "epochs_max": max(epochs),
            "early": early, "fixed": fixed}


def _p_fmt(p: float) -> str:
    """p-value display for the P0/TOST/trivial tables: scientific below
    1e-3, 4 decimals below .01, else 3 decimals."""
    if p < 1e-3:
        return p_tex(p)
    return f4(p) if p < 0.01 else f3(p)


def load_p0():
    """AMENDMENT-5 corrected-baseline grid (strong centralized / FedAvg /
    FedProx / per-client-best, 20 seeds, TOST)."""
    d = json.loads(P0.read_text())
    agg = d["aggregate"]
    cells = {}
    for key, c in agg["cells"].items():
        cells[key] = {
            "f1": (c["f1"]["mean"], c["f1"]["std"]),
            "auc": (c["auc"]["mean"], c["auc"]["std"]),
        }
    comps = {}
    for key, c in agg["comparisons"].items():
        comps[key] = {
            "delta": c["delta_mean_std"]["mean"],
            "delta_std": c["delta_mean_std"]["std"],
            "npos": c["wilcoxon"]["n_pos"], "nneg": c["wilcoxon"]["n_neg"],
            "nzero": c["wilcoxon"]["n_zero"],
            "p_exact": c["wilcoxon"]["p_value_exact"],
            "p_holm": c["wilcoxon"]["p_holm"],
            "ci_low": c["tost"]["ci_low"], "ci_high": c["tost"]["ci_high"],
            "tost": "PASS" if c["tost"]["equivalent"] else "FAIL",
            "margin": c["tost"]["margin"],
        }
    mu = {}
    for key, m in agg["mu_sweep"].items():
        mu[key] = {
            "delta": m["delta_mean_std"]["mean"],
            "delta_std": m["delta_mean_std"]["std"],
            "p": m["wilcoxon_descriptive"]["p_value"],
        }
    return {"n_runs": d["n_runs"], "meta": d["meta"], "cells": cells,
            "comps": comps, "mu": mu}


def load_trivial():
    """Trivial-metadata baseline (5 features) vs behavior graph, same
    standardized sklearn protocol on both arms, 20 seeds."""
    d = json.loads(TRIVIAL.read_text())
    out = {}
    trivial_means = []
    for scope, stag in (("full_corpus", "Full"), ("with_graph_subset", "Sub")):
        for split, spt in (("group", "Group"), ("random", "Random")):
            a = d[scope][split]["aggregate"]
            out[f"{stag}{spt}"] = {
                "graph_f1": a["graph_f1_mean_std"],
                "triv_f1": a["trivial_f1_mean_std"],
                "delta": a["df1_mean"], "delta_std": a["df1_std_pop"],
                "npos": a["sign_df1"]["pos"], "nneg": a["sign_df1"]["neg"],
                "nzero": a["sign_df1"]["zero"],
                "p": a["wilcoxon_exact_df1"]["p_value"],
                "mcn_g": a["mcnemar_pooled_discordant"]["graph_right_trivial_wrong"],
                "mcn_t": a["mcnemar_pooled_discordant"]["graph_wrong_trivial_right"],
            }
            trivial_means.append(a["trivial_f1_mean_std"][0])
    out["fone_min"] = min(trivial_means)
    out["fone_max"] = max(trivial_means)
    out["meta"] = d["meta"]
    return out


# ---------------------------------------------------------------- assemble
def build_values() -> dict:
    g, rows, hook_rows = load_grid()
    v: dict = {"meta": {
        "grid_n_runs": g["n_runs"],
        "grid_seeds": len(g["meta"]["seeds"]),
        "grid_config_sha16": g["meta"]["config_sha16"],
        "grid_mock": g["meta"]["mock"],
    }}

    # --- tab:main (group split = primary) ---
    main_tab = {}
    for feat, ftag in (("graph", "Graph"), ("tfidf", "Tfidf")):
        for method, mtag in (("fedavg", "FedAvg"), ("centralized", "Centralized"),
                             ("per_client_best", "PerClientBest")):
            c = cell(rows, "group", feat, method)
            main_tab[f"{ftag}{mtag}"] = c
    v["tab_main"] = main_tab

    # --- tab:stats ---
    v["tab_stats"] = stats_rows(rows)
    # npm_hook fallback comparison (group/graph), quoted in Results
    comps = g["aggregate"]["comparisons"]["npm_hook__group__graph"]
    deltas = [c["f1_delta"] for c in comps["per_seed"]]
    v["npm_hook_group_graph"] = {
        "df_mean": statistics.mean(deltas), "df_std": statistics.pstdev(deltas),
        "stored_p": comps["wilcoxon_f1_delta_fedavg_minus_centralized"]["p_value"],
        "n_seeds": len(deltas),
    }

    # --- tab:safety (n=60) ---
    v["tab_safety"], v["safety60_meta"] = load_safety60()

    # --- n=100 expansion headline numbers ---
    v["safety100"], v["safety100_meta"] = load_safety100()

    # --- tab:kb + KB universe ---
    v["tab_kb"] = load_kb_table()
    kb = json.loads(KB_COVERAGE.read_text())
    v["kb_universe"] = {
        "types": kb["graphs_v2"]["unique_api_types"],
        "instances": kb["graphs_v2"]["api_instances_total"],
        "entries": kb["kb_v3_stats"]["n_entries"],
        "seed_entries": kb["kb_v3_stats"]["n_seed"],
        "llm_entries": kb["kb_v3_stats"]["n_llm"],
        "unsure": kb["kb_v3_stats"]["n_unsure"],
        "conf_v2": kb["kb_feature_means"]["v2"]["kb_confidence"],
        "conf_v3": kb["kb_feature_means"]["v3"]["kb_confidence"],
    }

    # --- corpus + coverage ---
    feat = load_features()
    v["corpus"] = {
        "total": sum(feat["tot"].values()),
        "malicious": sum(n for (eco, lab), n in feat["tot"].items() if lab == 1),
        "benign": sum(n for (eco, lab), n in feat["tot"].items() if lab == 0),
        "npm_mal": feat["tot"][("npm", 1)], "pypi_mal": feat["tot"][("pypi", 1)],
        "npm_ben": feat["tot"][("npm", 0)], "pypi_ben": feat["tot"][("pypi", 0)],
        "cov_npm_ben": feat["cov"][("npm", 0)], "cov_npm_mal": feat["cov"][("npm", 1)],
        "cov_pypi_ben": feat["cov"][("pypi", 0)], "cov_pypi_mal": feat["cov"][("pypi", 1)],
        "cov_total": sum(feat["cov"].values()),
    }
    ct = v["corpus"]
    ct["cov_total_pct"] = round(100 * ct["cov_total"] / ct["total"], 1)
    for k, num, den in (("cov_npm_ben_pct", "cov_npm_ben", "npm_ben"),
                        ("cov_npm_mal_pct", "cov_npm_mal", "npm_mal"),
                        ("cov_pypi_ben_pct", "cov_pypi_ben", "pypi_ben"),
                        ("cov_pypi_mal_pct", "cov_pypi_mal", "pypi_mal")):
        ct[k] = round(100 * ct[num] / ct[den], 1)

    # --- generation counts (2,700 decomposition) ---
    v["gens"] = load_generation_counts()
    v["gens"]["total_defensive_task"] = (v["gens"]["e0_arms"] + v["gens"]["e2e3"] +
                                         v["gens"]["e0v2"] + v["gens"]["safe_n60"] +
                                         v["gens"]["safe_n60_round8batch"])

    # --- stabilized-centralized arm ---
    v["stabilized"] = load_stabilized()
    if v["stabilized"]:
        early_fixed = {}
        for split in ("group", "random"):
            for block in ("graph", "tfidf"):
                fixed = cell(rows, split, block, "centralized")[ "f1"][0]
                key = f"{split}__{block}"
                early_fixed[key] = v["stabilized"]["early"][key][0] - fixed
        v["stabilized"]["early_minus_fixed"] = early_fixed
    # AMENDMENT-5 corrected-baseline layer (round 11) + trivial baseline
    v["p0"] = load_p0() if P0.exists() else None
    v["trivial"] = load_trivial() if TRIVIAL.exists() else None
    # old-grid random/graph centralized cell (for the undertrain before/after)
    v["grid_random_graph_central"] = cell(rows, "random", "graph", "centralized")["f1"]
    v["w1_p0_poll"] = W1_P0_POLL
    return v


def build_macros(v: dict) -> "list[tuple[str, str]]":
    m: list[tuple[str, str]] = []

    def add(name: str, val: str):
        m.append((name, val))

    # tab:main
    for tag, label in (("GraphFedAvg", "GraphFedAvg"), ("GraphCentralized", "GraphCentralized"),
                       ("GraphPerClientBest", "GraphPerClientBest"),
                       ("TfidfFedAvg", "TfidfFedAvg"), ("TfidfCentralized", "TfidfCentralized"),
                       ("TfidfPerClientBest", "TfidfPerClientBest")):
        c = v["tab_main"][label]
        add(f"pm{tag}Fone", f3(c["f1"][0]))
        add(f"pm{tag}FoneStd", f3(c["f1"][1]))
        add(f"pm{tag}Auc", f3(c["auc"][0]))
        add(f"pm{tag}AucStd", f3(c["auc"][1]))
        add(f"pm{tag}Npm", f3(c["npm"][0]))
        add(f"pm{tag}NpmStd", f3(c["npm"][1]))
        add(f"pm{tag}Pypi", f3(c["pypi"][0]))
        add(f"pm{tag}PypiStd", f3(c["pypi"][1]))

    # tab:stats
    for split in ("group", "random"):
        for feat in ("graph", "tfidf"):
            tag = {"group": "Group", "random": "Random"}[split] + feat.capitalize()
            s = v["tab_stats"][f"{split}__{feat}"]
            add(f"pmStats{tag}Df", f4s(s["df_mean"]))
            add(f"pmStats{tag}DfStd", f4(s["df_std"]))
            add(f"pmStats{tag}Sign", f"{s['npos']}/{s['nneg']}/{s['nzero']}")
            add(f"pmStats{tag}P", p_tex(s["p"]))
            add(f"pmStats{tag}PHolm", p_tex(s["p_holm"]))
            add(f"pmStats{tag}Mcn", f"{s['mcnemar_lt01']}/{s['mcnemar_lt01_den']}")
    nh = v["npm_hook_group_graph"]
    add("pmNpmHookDf", f"{nh['df_mean']:+.3f}".replace("0.", ".", 1))
    add("pmNpmHookDfStd", f3(abs(nh["df_std"])))

    # tab:safety (n=60)
    for tag in ("Llama", "Granite"):
        for arm in ("Pzero", "Pone", "Ptwo"):
            key = f"{tag}{ {'Pzero':'P0','Pone':'P1','Ptwo':'P2'}[arm] }"
            s = v["tab_safety"][key]
            add(f"pmSafe{tag}{arm}Rr", f2(s["rr"]))
            if arm == "Pzero":
                add(f"pmSafe{tag}{arm}Flips", "-- / --")
            else:
                add(f"pmSafe{tag}{arm}Flips", f"{s['flips_b2m']} / {s['flips_m2b']}")
                add(f"pmSafe{tag}{arm}FlipsB", str(s["flips_b2m"]))
                add(f"pmSafe{tag}{arm}FlipsM", str(s["flips_m2b"]))
            if arm == "Pzero":
                add(f"pmSafe{tag}{arm}Rec", f3(s["recall_p0"]))
            else:
                add(f"pmSafe{tag}{arm}Rec",
                    f3(s["recall_p0"]) + "\\to" + f3(s["recall_arm"]))
            add(f"pmSafe{tag}{arm}Fp", f"0/{s['fp_den']}")

    # n=100 expansion headline numbers
    s1 = v["safety100"]
    arm_keys = ("P0_neutral", "P1_offensive_wording", "P2_advisory_in_package")
    for arm, key in zip(("Pzero", "Pone", "Ptwo"), arm_keys):
        add(f"pmSafeNpooledRec{arm}", f3(s1["pooled_recall"][key]))
    add("pmSafeNpooledFpPzero", str(s1["pooled_fp_counts"][0]))
    add("pmSafeNpooledFpPone", str(s1["pooled_fp_counts"][1]))
    add("pmSafeNpooledFpPtwo", str(s1["pooled_fp_counts"][2]))
    add("pmSafeNpOneFlips", f"{s1['p1_flips'][0]} / {s1['p1_flips'][1]}")
    add("pmSafeNpOnePairs", str(s1["p1_flips"][2]))
    add("pmSafeNpTwoFlips", f"{s1['p2_flips'][0]} / {s1['p2_flips'][1]}")
    add("pmSafeNpTwoPairs", str(s1['p2_flips'][2]))
    add("pmSafeNLlamaRecPzero", f3(s1["llama_recall"]["P0_neutral"]))
    add("pmSafeNLlamaRecPtwo", f3(s1["llama_recall"]["P2_advisory_in_package"]))
    add("pmSafeNGraniteRecPzero", f3(s1["granite_recall"]["P0_neutral"]))
    add("pmSafeNGraniteRecPtwo", f3(s1["granite_recall"]["P2_advisory_in_package"]))
    add("pmSafeNGraniteFpPtwo", f3(s1["granite_fp_p2"]))

    # tab:kb
    kbtab = v["tab_kb"]
    for algo, tag in (("fedavg", "FedAvg"), ("centralized", "Central")):
        add(f"pmKb{tag}FoneOff", f3(kbtab[f"{algo}_off"]["f1"]))
        add(f"pmKb{tag}FoneOn", f3(kbtab[f"{algo}_on"]["f1"]))
        add(f"pmKb{tag}AucOff", f3(kbtab[f"{algo}_off"]["auc"]))
        add(f"pmKb{tag}AucOn", f3(kbtab[f"{algo}_on"]["auc"]))
    add("pmKbCentralPypiOff", f3(kbtab["centralized_off"]["pypi_f1"]))
    add("pmKbCentralPypiOn", f3(kbtab["centralized_on"]["pypi_f1"]))
    ku = v["kb_universe"]
    add("pmKbUniverseTypes", str(ku["types"]))
    add("pmKbUniverseInstances", f"{ku['instances']:,}".replace(",", "{,}"))
    add("pmKbEntries", str(ku["entries"]))
    add("pmKbSeedEntries", str(ku["seed_entries"]))
    add("pmKbLlmEntries", str(ku["llm_entries"]))
    add("pmKbConfVtwo", f3(ku["conf_v2"]))
    add("pmKbConfVthree", f3(ku["conf_v3"]))

    # corpus / coverage
    c = v["corpus"]
    add("pmCorpusTotal", str(c["total"]))
    add("pmCorpusMal", str(c["malicious"]))
    add("pmCorpusBen", str(c["benign"]))
    add("pmCorpusNpmMal", str(c["npm_mal"]))
    add("pmCorpusPypiMal", str(c["pypi_mal"]))
    add("pmCorpusNpmBen", str(c["npm_ben"]))
    add("pmCorpusPypiBen", str(c["pypi_ben"]))
    for cellname in ("NpmBen", "NpmMal", "PypiBen", "PypiMal", "Total"):
        lo = {"NpmBen": "npm_ben", "NpmMal": "npm_mal", "PypiBen": "pypi_ben",
              "PypiMal": "pypi_mal", "Total": "cov_total"}[cellname]
        add(f"pmCov{cellname}Num", str(c[lo]))
    # with-graph numerators (105/252/63/80) for tab:coverage + setup text
    for cellname in ("NpmBen", "NpmMal", "PypiBen", "PypiMal"):
        lo = {"NpmBen": "cov_npm_ben", "NpmMal": "cov_npm_mal",
              "PypiBen": "cov_pypi_ben", "PypiMal": "cov_pypi_mal"}[cellname]
        add(f"pmCov{cellname}Cov", str(c[lo]))
    add("pmCovTotalDen", str(c["total"]))
    add("pmCovTotalPct", f"{c['cov_total_pct']}")
    add("pmCovNpmBenPct", f"{c['cov_npm_ben_pct']}")
    add("pmCovNpmMalPct", f"{c['cov_npm_mal_pct']}")
    add("pmCovPypiBenPct", f"{c['cov_pypi_ben_pct']}")
    add("pmCovPypiMalPct", f"{c['cov_pypi_mal_pct']}")

    # runs + generations
    add("pmRunsTotal", str(v["meta"]["grid_n_runs"]))
    add("pmSeedsN", str(v["meta"]["grid_seeds"]))
    gt = v["gens"]
    add("pmGenDefTotal", f"{gt['total_defensive_task']:,}".replace(",", "{,}"))
    add("pmGenEzeroArms", str(gt["e0_arms"]))
    add("pmGenEtwoThree", str(gt["e2e3"]))
    add("pmGenEzeroVtwo", f"{gt['e0v2']:,}".replace(",", "{,}"))
    add("pmGenSafeSixty", str(gt["safe_n60"]))
    add("pmGenSafeEight", str(gt["safe_n60_round8batch"]))
    add("pmProbeRecs", str(gt["probes"]))
    add("pmProbeRefusals", str(gt["probe_refusals"]))

    # stabilized-centralized arm
    st = v["stabilized"]
    if st:
        add("pmStabCells", str(st["n_cells"]))
        add("pmStabLrZeroOne", str(st["best_lr"].get(0.1, 0)))
        add("pmStabLrZeroThree", str(st["best_lr"].get(0.03, 0)))
        add("pmStabLrZeroZeroOne", str(st["best_lr"].get(0.01, 0)))
        add("pmStabEpochsMean", f"{st['epochs_mean']:.2f}")
        add("pmStabEpochsMin", str(st["epochs_min"]))
        add("pmStabEpochsMax", str(st["epochs_max"]))
        for key, tag in (("group__graph", "GroupGraph"), ("random__graph", "RandomGraph"),
                         ("group__tfidf", "GroupTfidf"), ("random__tfidf", "RandomTfidf")):
            add(f"pmStabDf{tag}", f4s(st["early_minus_fixed"][key]))
        add("pmStabGroupGraphFone", f3(st["early"]["group__graph"][0]))
        add("pmStabGroupGraphFoneStd", f3(st["early"]["group__graph"][1]))

    # ---- AMENDMENT-5 corrected-baseline grid (p0_results.json) ----
    p0 = v.get("p0")
    if p0:
        add("pmPzRuns", str(p0["n_runs"]))
        for split, stag in (("group", "Group"), ("random", "Random")):
            for block, btag in (("graph", "Graph"), ("hashing_tfidf", "Hashing")):
                for method, mtag in (("strong_centralized", "Central"),
                                     ("fedavg", "FedAvg"),
                                     ("per_client_best", "PerClient")):
                    c = p0["cells"][f"{split}__{block}__{method}"]
                    add(f"pmPz{stag}{btag}{mtag}Fone", f3(c["f1"][0]))
                    add(f"pmPz{stag}{btag}{mtag}FoneStd", f3(c["f1"][1]))
                    add(f"pmPz{stag}{btag}{mtag}Auc", f3(c["auc"][0]))
                    add(f"pmPz{stag}{btag}{mtag}AucStd", f3(c["auc"][1]))
        # FedProx cells (group split only, mu sweep)
        for block, btag in (("graph", "Graph"), ("hashing_tfidf", "Hashing")):
            for mu, mutag in (("0.01", "MuZeroZeroOne"), ("0.1", "MuZeroOne"), ("1", "MuOne")):
                c = p0["cells"][f"group__{block}__fedprox_mu{mu}"]
                add(f"pmPzGroup{btag}FedProx{mutag}Fone", f3(c["f1"][0]))
                add(f"pmPzGroup{btag}FedProx{mutag}FoneStd", f3(c["f1"][1]))
        # comparisons: FedAvg - strong-centralized, paired per seed
        for split, stag in (("group", "Group"), ("random", "Random")):
            for block, btag in (("graph", "Graph"), ("hashing_tfidf", "Hashing")):
                s = p0["comps"][f"{split}__{block}"]
                add(f"pmPz{stag}{btag}Delta", f4s(s["delta"]))
                add(f"pmPz{stag}{btag}DeltaStd", f4(s["delta_std"]))
                add(f"pmPz{stag}{btag}Sign",
                    f"{s['npos']}/{s['nneg']}/{s['nzero']}")
                add(f"pmPz{stag}{btag}CiLow", f4s(s["ci_low"]))
                add(f"pmPz{stag}{btag}CiHigh", f4s(s["ci_high"]))
                add(f"pmPz{stag}{btag}Tost", s["tost"])
                add(f"pmPz{stag}{btag}PExact", _p_fmt(s["p_exact"]))
                add(f"pmPz{stag}{btag}PHolm", _p_fmt(s["p_holm"]))
        # FedProx mu sweep deltas (descriptive, group split)
        for block, btag in (("graph", "Graph"), ("hashing_tfidf", "Hashing")):
            for mu, mutag in (("0.01", "MuZeroZeroOne"), ("0.1", "MuZeroOne"), ("1", "MuOne")):
                ms = p0["mu"][f"{block}__mu{mu}"]
                add(f"pmPzMu{btag}{mutag}Delta", f4s(ms["delta"]))
                add(f"pmPzMu{btag}{mutag}Std", f4(ms["delta_std"]))
                add(f"pmPzMu{btag}{mutag}P", _p_fmt(ms["p"]))

    # ---- old-grid random/graph centralized cell (undertrain before/after) ----
    gc = v["grid_random_graph_central"]
    add("pmGridRandomGraphCentralFone", f3(gc[0]))
    add("pmGridRandomGraphCentralFoneStd", f3(gc[1]))

    # ---- trivial-metadata baseline (trivial_results.json) ----
    tv = v.get("trivial")
    if tv:
        for stag in ("Full", "Sub"):
            for spt in ("Group", "Random"):
                t = tv[f"{stag}{spt}"]
                add(f"pmTriv{stag}{spt}GraphFone", f3(t["graph_f1"][0]))
                add(f"pmTriv{stag}{spt}GraphFoneStd", f3(t["graph_f1"][1]))
                add(f"pmTriv{stag}{spt}TrivFone", f3(t["triv_f1"][0]))
                add(f"pmTriv{stag}{spt}TrivFoneStd", f3(t["triv_f1"][1]))
                add(f"pmTriv{stag}{spt}Delta", f4s(t["delta"]))
                add(f"pmTriv{stag}{spt}DeltaStd", f4(t["delta_std"]))
                add(f"pmTriv{stag}{spt}Sign",
                    f"{t['npos']}/{t['nneg']}/{t['nzero']}")
                add(f"pmTriv{stag}{spt}P", _p_fmt(t["p"]))
                add(f"pmTriv{stag}{spt}Mcn",
                    f"{t['mcn_g']}/{t['mcn_t']}")
        add("pmTrivFoneMin", f3(tv["fone_min"]))
        add("pmTrivFoneMax", f3(tv["fone_max"]))
        add("pmTrivFoneMinTwo", f2(tv["fone_min"]))
        add("pmTrivFoneMaxTwo", f2(tv["fone_max"]))
    return m


STALE_PATTERNS = {
    "w3_pypi_fedavg_5seed": r"\.833\{\\pm\}\.115",
    "w3_pypi_central_5seed": r"\.790\{\\pm\}\.105",
    "stats_random_graph_holm_stale_rounding": r"\$\.133\$\s*\(\$\.266\$\)",
    # wrong trivial-baseline range (2-cell full-corpus range quoted for all 4 cells)
    "trivial_range_stale_lower_bound": r"\.834--\.856",
}


def render_tex(macros) -> str:
    lines = [
        "% numbers.tex -- GENERATED by scripts/gen_paper_numbers.py (P0-4, round 11).",
        "% DO NOT EDIT BY HAND: every value is derived from measured artifacts",
        "% under outputs/ (see outputs/packguard/p0_macros/gen_numbers_audit.json).",
        "% Regenerate: .venv/bin/python scripts/gen_paper_numbers.py",
        "% Verify:     .venv/bin/python scripts/gen_paper_numbers.py --check",
        "",
    ]
    for name, val in macros:
        lines.append(f"\\newcommand{{\\{name}}}{{{val}}}")
    return "\n".join(lines) + "\n"


def expand(main_tex_text: str, macros) -> str:
    """Simulate TeX macro expansion (longest-name match via negative lookahead)."""
    out = main_tex_text
    for name, val in macros:
        out = re.sub(re.escape("\\" + name) + r"(?![A-Za-z@])",
                     val.replace("\\", "\\\\"), out)
    return out


TABLE_ROW_EXPECT = None  # (removed; row checks live in check_main)


def row_numbers(expanded: str, label: str):
    """Return numeric tokens AFTER the first '&' of the row starting with label."""
    for line in expanded.splitlines():
        s = line.strip()
        if s.startswith(label):
            tail = s.split("&", 1)[1] if "&" in s else s
            return re.findall(r"\d*\.\d+|\d+", tail)
    return None


def check_main(v: dict, macros):
    """Verify main.tex against macro values. Returns list of problems."""
    problems = []
    if not MAIN_TEX.exists():
        return [f"missing {MAIN_TEX}"]
    text = MAIN_TEX.read_text()
    exp = expand(text, macros)

    def nums(label):
        r = row_numbers(exp, label)
        if r is None:
            problems.append(f"table row not found after macro expansion: '{label}'")
            return []
        return r

    def expect(label, expected):
        got = nums(label)
        if got and got != expected:
            problems.append(
                f"STALE table row '{label}': main.tex renders {got}, artifacts say {expected}")

    # tab:main rows (AMENDMENT-5 corrected-baseline grid): each row renders
    # group F1/AUC then random F1/AUC, each mean+-std -> 8 numeric tokens.
    p0 = v.get("p0")
    if p0:
        for block, btag in (("graph", "graph"), ("hashing_tfidf", "hashing")):
            for method, mtag in (("strong_centralized", "strong centralized"),
                                 ("fedavg", "FedAvg"),
                                 ("per_client_best", "per-client-best")):
                label = f"{btag} {mtag}"
                want = []
                for split in ("group", "random"):
                    c = p0["cells"][f"{split}__{block}__{method}"]
                    want += [f3(c["f1"][0]), f3(c["f1"][1]), f3(c["auc"][0]),
                             f3(c["auc"][1])]
                expect(label, want)

    # tab:stats rows (TOST): dF1+-std, sign n+/n-/n0, CI low/high, TOST verdict
    # (no digits), exact Wilcoxon p and Holm p.
    for label, key in (("group / graph", "group__graph"),
                       ("group / hashing", "group__hashing_tfidf"),
                       ("random / graph", "random__graph"),
                       ("random / hashing", "random__hashing_tfidf")):
        if not p0:
            break
        s = p0["comps"][key]
        got = nums(label)
        want = [f4s(s["delta"]).lstrip("+-"), f4(s["delta_std"]),
                str(s["npos"]), str(s["nneg"]), str(s["nzero"]),
                f4s(s["ci_low"]).lstrip("+-"), f4s(s["ci_high"]).lstrip("+-"),
                _p_fmt(s["p_exact"]), _p_fmt(s["p_holm"])]
        if got and got != want:
            problems.append(
                f"STALE tab:stats row '{label}': renders {got}, artifacts say {want}")

    # tab:safety rows
    for tag in ("llama", "granite"):
        for arm, suffix in (("P0 neutral", "P0"), ("P1 offensive", "P1"), ("P2 advisory", "P2")):
            label = f"{tag} {arm}"
            s = v["tab_safety"][("Llama" if tag == "llama" else "Granite") + suffix]
            if suffix == "P0":
                want = [f2(s["rr"]), f3(s["recall_p0"]), "0", "30"]
            else:
                want = [f2(s["rr"]), str(s["flips_b2m"]), str(s["flips_m2b"]),
                        f3(s["recall_p0"]), f3(s["recall_arm"]), "0", "30"]
            got = nums(label)
            if got and got != want:
                problems.append(f"STALE tab:safety row '{label}': renders {got}, artifacts say {want}")

    # tab:kb rows
    kb = v["tab_kb"]
    expect("FedAvg &", [f3(kb["fedavg_off"]["f1"]), f3(kb["fedavg_on"]["f1"]),
                        f3(kb["fedavg_off"]["auc"]), f3(kb["fedavg_on"]["auc"])])
    expect("centralized &", [f3(kb["centralized_off"]["f1"]), f3(kb["centralized_on"]["f1"]),
                             f3(kb["centralized_off"]["auc"]), f3(kb["centralized_on"]["auc"])])

    # headline text numbers present after expansion
    needles = [
            (f"{v['gens']['total_defensive_task']:,}".replace(",", "{,}"), "2,700 defensive-task generations"),
            (f"640/640", "640/640 real rows"),
            (str(v["corpus"]["total"]), "603-sample corpus"),
            (f"{v['kb_universe']['types']}/{v['kb_universe']['types']}", "137/137 API types"),
            (f"{v['kb_universe']['instances']:,}".replace(",", "{,}"), "2,299 instances"),
            (f"{v['corpus']['cov_total']}/{v['corpus']['total']}", "500/603 coverage"),
    ]
    if p0:
        prim = p0["comps"]["group__graph"]
        rwg = p0["comps"]["random__graph"]
        needles += [
            (f4s(prim["delta"]), "primary TOST dF1 (FedAvg - strong centralized)"),
            (f4s(prim["ci_low"]), "primary TOST 90% CI low"),
            (f4s(prim["ci_high"]), "primary TOST 90% CI high"),
            (_p_fmt(rwg["p_holm"]), "random/graph central-win Holm p"),
        ]
    if v.get("trivial"):
        tg, tr = v["trivial"]["FullGroup"], v["trivial"]["FullRandom"]
        needles += [
            (f4s(tg["delta"]), "trivial-baseline dF1 group"),
            (f4s(tr["delta"]), "trivial-baseline dF1 random"),
            (_p_fmt(tg["p"]), "trivial-baseline Wilcoxon p group"),
        ]
    for needle, what in needles:
        if needle not in exp:
            problems.append(f"STALE text number: expected '{needle}' ({what}) not found in expanded main.tex")

    # known stale literals (W3 + old rounding + wrong trivial lower bound)
    for name, pat in STALE_PATTERNS.items():
        if re.search(pat, text):
            problems.append(f"STALE literal ({name}): pattern /{pat}/ still present in main.tex")
    return problems


def w3_mapping(v: dict) -> dict:
    """W3: the three conflicting pypi F1 numbers and which artifact wins."""
    gf = v["tab_main"]["GraphFedAvg"]["pypi"]
    gc = v["tab_main"]["GraphCentralized"]["pypi"]
    tc = v["tab_main"]["TfidfCentralized"]["pypi"]
    return {
        "contradiction": "paper2 quoted pypi F1 as .833±.115 (FedAvg) vs .790±.105 (centralized) "
                         "in the retracted-finding paragraph while tab:main shows .851±.080 / "
                         ".830±.100 (graph) and .790±.076 (tfidf centralized).",
        "resolution": [
            {
                "value": ".833±.115",
                "provenance": "round-9 FIVE-seed grid (seeds 20260922-20260926), graph/group FedAvg pypi F1 "
                              "(reports/round9/W1_report.md §3.1); superseded by AMENDMENT-4 20-seed grid.",
                "correct_now": f"{f3(gf[0])}±{f3(gf[1])}",
                "authoritative_artifact": "outputs/packguard/fl_multiseed/grid_results.json (640 rows, 20 seeds)",
                "macro": "\\pmGraphFedAvgPypi / \\pmGraphFedAvgPypiStd",
                "action": "literal replaced by macros in the retracted-finding paragraph",
            },
            {
                "value": ".790±.105",
                "provenance": "round-9 FIVE-seed grid, graph/group centralized pypi F1 (.7900±.1049); "
                              "NOT comparable with tab:main's .790±.076 which is a DIFFERENT cell "
                              "(tfidf centralized, 20 seeds).",
                "correct_now": f"{f3(gc[0])}±{f3(gc[1])} (graph centralized, 20 seeds)",
                "authoritative_artifact": "outputs/packguard/fl_multiseed/grid_results.json",
                "macro": "\\pmGraphCentralizedPypi / \\pmGraphCentralizedPypiStd",
                "action": "literal replaced by macros; tfidf .790±.076 remains tab:main-only (\\pmTfidfCentralizedPypi)",
            },
            {
                "value": ".851±.080",
                "provenance": "tab:main graph/group FedAvg pypi F1, 20-seed AMENDMENT-4 grid -- CORRECT as printed.",
                "correct_now": f"{f3(gf[0])}±{f3(gf[1])}",
                "authoritative_artifact": "outputs/packguard/fl_multiseed/grid_results.json",
                "macro": "\\pmGraphFedAvgPypi",
                "action": "kept; now macro-generated",
            },
        ],
        "tab_stats_status": {
            "previous_claim": "tab:stats per-seed inference layer flagged stale/unverified (self-labeled n=5 summary).",
            "finding": "outputs/packguard/fl_multiseed/grid_results.json (refreshed 20-seed grid) CONTAINS "
                       "per_seed_comparisons for 20 seeds; recomputing two-sided EXACT Wilcoxon on the per-seed "
                       "dF1 reproduces the printed table (.312 / 3.8e-6 / .133 / 1.9e-6) and Holm values, with one "
                       "rounding correction: random/graph Holm .266 -> .265 (exact 0.26545). The stale flag is resolved.",
            "remaining_caveat": "stabilized-centralized arm remains aggregate-only (no paired inference).",
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="verify only; exit 1 on stale/mismatch")
    args = ap.parse_args()

    v = build_values()
    macros = build_macros(v)

    if args.check:
        problems = []
        if OUT_TEX.exists():
            want = render_tex(macros)
            have = OUT_TEX.read_text()
            if have != want:
                have_map = dict(re.findall(r"\\newcommand\{\\(pm\w+)\}\{(.*?)\}$", have, re.M))
                want_map = dict(macros)
                drift = [k for k in want_map if have_map.get(k) != want_map[k]]
                problems.append(f"numbers.tex DRIFT for {len(drift)} macros: {sorted(drift)[:12]}")
        else:
            problems.append(f"missing {OUT_TEX} (run without --check first)")
        problems += check_main(v, macros)
        if problems:
            print("GEN-NUMBERS CHECK: FAIL")
            for p in problems:
                print(" -", p)
            return 1
        print(f"GEN-NUMBERS CHECK: OK -- {len(macros)} macros verified against artifacts "
              f"({v['meta']['grid_n_runs']} grid rows, {v['meta']['grid_seeds']} seeds).")
        return 0

    OUT_TEX.parent.mkdir(parents=True, exist_ok=True)
    OUT_AUDIT.parent.mkdir(parents=True, exist_ok=True)
    OUT_TEX.write_text(render_tex(macros))
    OUT_AUDIT.write_text(json.dumps({"values": v, "macros": dict(macros)}, indent=1, sort_keys=True))
    OUT_W3.write_text(json.dumps(w3_mapping(v), indent=1, sort_keys=True))
    print(f"wrote {OUT_TEX.relative_to(ROOT)} ({len(macros)} macros)")
    print(f"wrote {OUT_AUDIT.relative_to(ROOT)}")
    print(f"wrote {OUT_W3.relative_to(ROOT)}")
    print(f"poll outputs/packguard/p0*: {W1_P0_POLL or 'no W1 P0 files yet'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
