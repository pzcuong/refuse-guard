"""Round-8 FINAL PackGuard FL runs on the FIXED dataset (agent F).

Executes AMENDMENT-1: dataset 603 (features v2), group-split PRIMARY +
random-split secondary, graph vs TF-IDF (fit on TRAIN only), FedAvg/FedProx/
centralized/per-client, per-ecosystem + per-coverage subgroup metrics,
McNemar + bootstrap primary comparison, DP arm (purposeful sigma), MLP arm,
no-empty-graph sensitivity arm, and (if kb_v0002+ exists) the KB on/off
ablation. Every row carries meta.mock=false and full provenance.

Run:
    .venv/bin/python scripts/packguard_final_runs.py [--with-kb] [--skip-text-cache]
Outputs (overwrite):
    outputs/packguard/fl/results.jsonl, summary.md, final_runs_v2.json
"""
from __future__ import annotations

import argparse
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from packguard import fl as flm
from packguard.fl import (
    FLConfig,
    FedClient,
    build_clients,
    client_label_distribution,
    compute_clf_metrics,
    config_sha16,
    load_feature_records,
    make_global_test_split,
    make_group_split,
    paired_correctness,
    run_centralized,
    run_federated,
    run_per_client,
)
from packguard.features import (
    MAX_FILE_BYTES,
    extract_archive,
    select_files,
    _npm_postinstall_targets,
    language_of,
)
from src.metrics.stats import bootstrap_ci_diff, mcnemar

ROOT = Path("/Users/macbook/.zcode/workspace/default/refuseguard")
FEATURES_DIR = ROOT / "outputs/packguard/features"
MANIFEST = ROOT / "data/packguard/manifests/dataset_v2.json"
OUT_DIR = ROOT / "outputs/packguard/fl"
TEXT_CACHE = FEATURES_DIR / "text_v2.json"
SEED = 20260922
TFIDF_MAX_FEATURES = 1000
ARCHIVED = OUT_DIR / "results_featuresv1_archived.jsonl"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# text cache for the TF-IDF baseline (same caps + selection as the graphs)
# ---------------------------------------------------------------------------
def build_text_cache(records: list[dict], manifest_path: Path,
                     args_skip_build: bool = False) -> dict:
    if TEXT_CACHE.exists():
        with TEXT_CACHE.open() as f:
            cache = json.load(f)
        if args_skip_build and all(r["sample_id"] in cache for r in records):
            return cache
    with manifest_path.open() as f:
        manifest = json.load(f)
    by_id = {s["sample_id"]: s for s in manifest["samples"]}
    cache = json.load(TEXT_CACHE.open()) if TEXT_CACHE.exists() else {}
    todo = [r["sample_id"] for r in records
            if r["sample_id"] not in cache and r["sample_id"] in by_id]
    for i, sid in enumerate(todo):
        s = by_id[sid]
        text = ""
        try:
            tmp = tempfile.mkdtemp(prefix="pgtext_")
            files = extract_archive(s["archive_path"], tmp)
            files = [(rel, ab) for rel, ab in files
                     if "/node_modules/" not in f"/{rel}" and "/.git/" not in f"/{rel}"]
            hooks = set(_npm_postinstall_targets(files))
            files = select_files(files, hook_targets=sorted(hooks))
            parts = []
            for rel, ab in files:
                if language_of(rel) is None:
                    continue
                try:
                    with open(ab, "rb") as f:
                        src = f.read(MAX_FILE_BYTES).decode("utf-8", "replace")
                    parts.append(src)
                except OSError:
                    continue
            text = "\n".join(parts)
        except Exception:
            text = ""
        cache[sid] = text
        if (i + 1) % 100 == 0:
            print(f"  text {i+1}/{len(todo)}", flush=True)
    with TEXT_CACHE.open("w") as f:
        json.dump(cache, f)
    return cache


def tfidf_blocks(train: list[dict], test: list[dict], cache: dict) -> None:
    """Fit TF-IDF on TRAIN text only; attach the `tfidf` block in place."""
    from sklearn.feature_extraction.text import TfidfVectorizer

    vec = TfidfVectorizer(max_features=TFIDF_MAX_FEATURES, min_df=2,
                          sublinear_tf=True)
    Xtr = vec.fit_transform([cache.get(r["sample_id"], "") or "" for r in train])
    Xte = vec.transform([cache.get(r["sample_id"], "") or "" for r in test])
    names = [f"tfidf_{j}" for j in range(Xtr.shape[1])]
    for recs, X in ((train, Xtr), (test, Xte)):
        coo = X.tocsr()
        for i, r in enumerate(recs):
            row = coo[i]
            # DENSE with a FIXED name list: every record must carry the SAME
            # key set or _vectorize (sorted names) produces ragged arrays.
            dense = {n: 0.0 for n in names}
            for j in row.indices:
                dense[names[j]] = round(float(row[0, j]), 6)
            r["features"]["tfidf"] = dense


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--with-kb", action="store_true")
    ap.add_argument("--skip-text-cache", action="store_true")
    args = ap.parse_args()

    records, feat_meta = load_feature_records(FEATURES_DIR)
    print(f"records: {len(records)} from {feat_meta['source']} "
          f"(dropped_err={feat_meta['n_rows_dropped_extraction_error']}, "
          f"api_attached={feat_meta['n_rows_with_api_calls']})")

    cache = build_text_cache(records, MANIFEST, args_skip_build=args.skip_text_cache)

    cfg_base = {
        "seed": SEED,
        "fl": {"rounds": 15, "local_epochs": 2, "lr": 0.1, "batch_size": 32,
               "mu_fedprox": 0.01},
        "model": {"type": "lr", "hidden_dim": 32},
        "secure_agg": {"enabled": True},
        "dp": {"enabled": False, "sigma": 0.1, "delta": 1.0e-5, "clip": 1.0},
        "eval": {"bootstrap_n": 10000, "bootstrap_seed": SEED},
    }
    cfg_sha = config_sha16(cfg_base)
    base_meta = {
        "seed": SEED, "config_sha16": cfg_sha, "date": _now(),
        "pipeline": "scripts/packguard_final_runs.py",
        "mock": False,
        "features_source": feat_meta["source"],
        "graphs_source": feat_meta.get("graphs_source"),
        "manifest": str(MANIFEST),
        "amendment": "AMENDMENT-1 (docs/packguard_prereg.md): 603 samples, features v2, group-split primary",
    }

    rows: list[dict] = []

    def add(kind, name, payload, split):
        rows.append({"kind": kind, "name": name,
                     "meta": {**base_meta, "split": split}, **payload})

    def subgroup(test, probs):
        out = {}
        for eco in ("npm", "pypi"):
            idx = [i for i, r in enumerate(test)
                   if str(r.get("ecosystem", "")).startswith(eco)]
            if idx:
                out[f"eco_{eco}"] = compute_clf_metrics(
                    [int(test[i]["label"]) for i in idx], [probs[i] for i in idx])
        for cov, pick in (("with_graph", lambda r: float(
                r["features"]["graph"].get("n_nodes", 0)) > 0),
                ("empty_graph", lambda r: float(
                r["features"]["graph"].get("n_nodes", 0)) == 0)):
            idx = [i for i, r in enumerate(test) if pick(r)]
            if idx:
                out[cov] = compute_clf_metrics(
                    [int(test[i]["label"]) for i in idx], [probs[i] for i in idx])
        return out

    def split_records(recs, mode):
        if mode == "group":
            return make_group_split(recs, 0.2, seed=SEED)
        return make_global_test_split(recs, 0.2, seed=SEED)

    def run_block(recs, block, split_mode, tag, cfg=None, algos=("fedavg", "fedprox", "centralized", "per_client_only")):
        c = {**cfg_base, **(cfg or {})}
        recs = json.loads(json.dumps(recs))  # deep copy
        train, test = split_records(recs, split_mode)
        if block == "tfidf":
            tfidf_blocks(train, test, cache)
        clients = build_clients(train, feature_block=block)
        test_client = FedClient("global_test", test, feature_block=block)
        flc = FLConfig.from_dict(
            {**c["fl"], **c["model"], "mu": c["fl"]["mu_fedprox"]},
            input_dim=test_client.input_dim)
        flc.seed = SEED
        flc.feature_block = block
        flc.secure_agg_enabled = True
        if c["dp"]["enabled"]:
            flc.dp_enabled = True
            flc.dp_sigma = float(c["dp"]["sigma"])
            flc.dp_delta = float(c["dp"]["delta"])
            flc.dp_clip = float(c["dp"]["clip"])
        res = {}
        dist = client_label_distribution(clients)
        for algo in algos:
            if algo == "fedavg":
                r = run_federated(clients, test_client, flc, "fedavg", SEED)
            elif algo == "fedprox":
                r = run_federated(clients, test_client, flc, "fedprox", SEED)
            elif algo == "centralized":
                r = run_centralized(clients, test_client, flc, SEED)
            else:
                r = run_per_client(clients, test_client, flc, SEED)
            res[algo] = r
            payload = {
                "algo": algo, "feature_block": block, "input_dim": test_client.input_dim,
                "n_train": len(train), "n_test": len(test),
                "test_dist": {
                    "n_mal": sum(int(t["label"]) for t in test),
                    "eco_npm": sum(1 for t in test if t["ecosystem"] == "npm"),
                    "eco_pypi": sum(1 for t in test if t["ecosystem"] == "pypi"),
                },
                "client_distribution": dist,
                "final_metrics": r["final_metrics"],
                "subgroup_metrics": subgroup(test, r.get("final_probs", []))
                if "final_probs" in r else None,
                "history": r.get("history"),
                "secure_agg_mask_residual": r.get("secure_agg_mask_residual"),
                "dp": {k: r.get(k) for k in ("dp_enabled", "dp_sigma", "dp_epsilon_per_round")},
            }
            add("run", f"{tag}__{algo}", payload, split_mode)
        # primary-style comparison inside this block
        if "fedavg" in res and "centralized" in res:
            y = [int(t["label"]) for t in test]
            ca, cb = paired_correctness(res["fedavg"]["final_probs"],
                                        res["centralized"]["final_probs"], y)
            mc = mcnemar(cb, ca, exact=None)
            boot = bootstrap_ci_diff([1.0 if x else 0.0 for x in ca],
                                     [1.0 if x else 0.0 for x in cb],
                                     n_boot=10000, seed=SEED)
            comp = {"comparison": "fedavg_vs_centralized", "block": block,
                    "split": split_mode, "mcnemar": mc,
                    "bootstrap_accuracy_diff": boot,
                    "endpoint": "per-sample accuracy@0.5"}
            add("comparison", f"primary__{tag}", comp, split_mode)
        return res

    summary = {"meta": base_meta, "splits": {}, "arms": {}}

    # ---------------- PRIMARY: group split ----------------
    print("== group split (PRIMARY) — graph block")
    res_g = run_block(records, "graph", "group", "group__graph__kb_off")
    print("== group split — tfidf block")
    run_block(records, "tfidf", "group", "group__tfidf__kb_off")

    # ---------------- secondary: random split ----------------
    print("== random split (secondary) — graph block")
    run_block(records, "graph", "random", "random__graph__kb_off")
    print("== random split — tfidf block")
    run_block(records, "tfidf", "random", "random__tfidf__kb_off")

    # ---------------- sensitivity arms (group split, graph) ----------------
    print("== DP arm (sigma=0.1) group/graph fedavg")
    run_block(records, "graph", "group", "group__graph__dp01_fedavg",
              cfg={"dp": {"enabled": True, "sigma": 0.1, "delta": 1.0e-5, "clip": 1.0}},
              algos=("fedavg",))
    print("== MLP arm group/graph fedavg+centralized")
    run_block(records, "graph", "group", "group__graph__mlp",
              cfg={"model": {"type": "mlp", "hidden_dim": 32}},
              algos=("fedavg", "centralized"))
    print("== no-empty-graph arm group/graph")
    recs_ne = [r for r in records
               if float(r["features"]["graph"].get("n_nodes", 0)) > 0]
    print(f"   n after dropping empty rows: {len(recs_ne)}")
    run_block(recs_ne, "graph", "group", "group__graph__noempty",
              algos=("fedavg", "centralized"))

    # ---------------- KB ablation ----------------
    if args.with_kb:
        from packguard.kb import KnowledgeBase, kb_features
        kb = KnowledgeBase(ROOT / "outputs/packguard/kb")
        st = kb.stats()
        print(f"== KB ablation with kb v{st['version']} "
              f"(n_entries={st['n_entries']}, n_llm={st['n_llm']})")
        recs_kb = json.loads(json.dumps(records))
        for r in recs_kb:
            feats = kb_features(r.get("api_calls", []), kb)
            r["features"]["graph"].update(feats)
        run_block(recs_kb, "graph", "group", "group__graph__kb_on",
                  algos=("fedavg", "centralized", "per_client_only"))
        summary["kb"] = {"kb_version": st["version"], "n_llm": st["n_llm"],
                         "n_entries": st["n_entries"],
                         "model_note": "kb entries: seed + llm:Qwen2.5-Coder-3B (AMENDMENT-1)"}
    else:
        add("pending", "kb_on", {"reason": "run with --with-kb after the KB build"}, "group")

    # ---------------- persist ----------------
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    results_path = OUT_DIR / "results.jsonl"
    if results_path.exists() and not ARCHIVED.exists():
        os.replace(results_path, ARCHIVED)  # keep V2's features-v1 run for traceability
    with results_path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
    with (OUT_DIR / "final_runs_v2.json").open("w") as f:
        json.dump({"rows_summary": [
            {k: row[k] for k in row if k not in ("history",)} for row in rows
        ]}, f, indent=1, default=str)
    print(f"rows -> {results_path} ({len(rows)} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
