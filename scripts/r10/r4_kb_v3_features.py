"""Round-10 [r4] KB-v3 FEATURES VIA FL/CENTRAL — PURE JOIN, NO LLM.

The round-9 KB v3 (outputs/packguard/kb/kb_v0002.jsonl: 142 entries = 20
seed + 122 LLM-classified, unsure=0, coverage 137/137 unique API types —
see reports/round9/W2_report.md §2) already covers the FULL API universe of
the corpus.  This helper therefore needs NO LLM: it

  1. loads the real feature records (api_calls derived from graphs_v2 by
     packguard.fl.load_feature_records),
  2. joins packguard.kb.kb_features (risk_ratio / kb_confidence /
     unsure_ratio) onto every record — PURE DICT LOOKUPS, no LLMKBBuilder,
     no generation,
  3. runs FL (fedavg) + centralized on the SAME cells with and without the
     KB-augmented graph block ({group PRIMARY, random} splits, config seed)
     so the v3-KB effect is measured on the stabilized protocol,
  4. writes outputs/packguard/r10/r4_kb_v3/{results.jsonl,summary.md} with
     the KB version + join-coverage stats.

Dry run (--dry): join-ONLY on the real records (coverage + unsure stats
written to a preview json, stage=join_only_dry, no training) — zero risk,
still proves the join path.  Real run cost: CPU-only, ~2-5 min.
"""
from __future__ import annotations

import argparse
import statistics as st
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _r10lib as L  # noqa: E402

from packguard.fl import (  # noqa: E402
    FedClient, build_clients, config_sha16, run_centralized, run_federated,
)
from packguard.kb import KnowledgeBase, kb_features  # noqa: E402

KB_DIR = L.ROOT / "outputs/packguard/kb"


def _join_kb(records: list[dict], kb: KnowledgeBase) -> list[dict]:
    """Append kb_risk_ratio / kb_confidence / kb_unsure_ratio (+ kb_n_calls,
    kb_n_known) into the graph block of a deep copy of every record. Pure
    dict joins; mirrors packguard.eval._augment_with_kb without the LLM path."""
    import json as _json

    out = []
    for r in records:
        rr = _json.loads(_json.dumps(r))  # deep copy
        feats = kb_features(r.get("api_calls", []), kb)
        g = rr["features"]["graph"]
        g.update(feats)
        rr["features"] = {"graph": g}
        out.append(rr)
    return out


def _join_stats(records: list[dict], kb: KnowledgeBase) -> dict:
    unsure, conf, n_calls, n_known = [], [], 0, 0
    for r in records:
        f = kb_features(r.get("api_calls", []), kb)
        unsure.append(f["kb_unsure_ratio"])
        conf.append(f["kb_confidence"])
        n_calls += f["kb_n_calls"]
        n_known += f["kb_n_known"]
    return {
        "kb_version": kb.version, "kb_stats": kb.stats(),
        "n_records": len(records),
        "mean_kb_unsure_ratio": round(st.mean(unsure), 6) if unsure else None,
        "mean_kb_confidence": round(st.mean(conf), 6) if conf else None,
        "total_api_calls": n_calls, "api_calls_known_in_kb": n_known,
        "coverage_instances": round(n_known / n_calls, 6) if n_calls else None,
    }


def run(dry: bool) -> int:
    cfg = L.load_fl_config()
    kb = KnowledgeBase(KB_DIR)  # loads latest kb_v*.jsonl (v3 = kb_v0002)
    records, _feat_meta = None, None
    from packguard.fl import load_feature_records

    records, feat_meta = load_feature_records(L.FEATURES_DIR)
    joined = _join_kb(records, kb)
    stats = _join_stats(records, kb)
    seed = int(cfg.get("seed", 20260922))
    frac = float((cfg.get("data", {}) or {}).get("test_fraction", 0.2))

    if dry:
        out = L.out_dir("r4_kb_v3", dry=True)
        payload = {"stage": "join_only_dry", "mock": False,
                   "note": ("join-only dry proof: real records, real KB v3, "
                            "pure dict lookups, NO LLM, NO training"),
                   "date": L.now_utc(), "join_stats": stats}
        L.write_json(out / "join_preview.json", payload)
        print(f"[r4 dry] KB v{kb.version}: {kb.stats()}")
        print(f"[r4 dry] join coverage: instances="
              f"{stats['coverage_instances']}, mean_unsure="
              f"{stats['mean_kb_unsure_ratio']}, mean_conf="
              f"{stats['mean_kb_confidence']}")
        print(f"[r4 dry] preview -> {out}/join_preview.json (no training)")
        return 0

    rows: list[dict] = []
    for split_mode in ("group", "random"):
        for tag, recs in (("kb_off", records), ("kb_on", joined)):
            # identical split on both record sets so cells pair sample-for-sample
            if split_mode == "group":
                from packguard.fl import make_group_split

                train, test = make_group_split(list(recs), frac, seed=seed)
            else:
                from packguard.fl import make_global_test_split

                train, test = make_global_test_split(list(recs), frac, seed=seed)
            clients = build_clients(train, feature_block="graph")
            test_client = FedClient("global_test", test, feature_block="graph")
            flc = L._grid_fl_config(cfg, test_client.input_dim, seed, "graph")
            for algo in ("fedavg", "centralized"):
                res = (run_federated(clients, test_client, flc, algo, seed)
                       if algo == "fedavg"
                       else run_centralized(clients, test_client, flc, seed))
                m = res["final_metrics"]
                rows.append({
                    "kind": "run", "name": f"graph__{tag}__{algo}__seed{seed}",
                    "mock": False, "seed": seed, "split": split_mode,
                    "block": "graph", "kb": tag, "algo": algo,
                    "config_sha16": config_sha16(cfg), "date": L.now_utc(),
                    "kb_version": kb.version,
                    "f1": m.get("f1"), "auc": m.get("auc"),
                    "precision": m.get("precision"),
                    "recall": m.get("recall"),
                    "n_test": m.get("n"),
                    "join_stats": stats if tag == "kb_on" else None,
                })
                print(f"[r4] {split_mode} {tag} {algo}: "
                      f"F1={m.get('f1'):.4f} AUC={m.get('auc'):.4f}", flush=True)

    out = L.out_dir("r4_kb_v3", dry=False)
    L.write_jsonl(out / "results.jsonl", rows)
    lines = ["# r4 KB-v3 pure join — summary", "",
             f"- date: {L.now_utc()}", f"- KB version: {kb.version} {kb.stats()}",
             f"- join coverage: {stats['coverage_instances']} instances, "
             f"mean_unsure={stats['mean_kb_unsure_ratio']}, "
             f"mean_conf={stats['mean_kb_confidence']}",
             "- NO LLM was invoked (pure dict join over kb_v0002)", "",
             "| split | kb | algo | F1 | AUC |", "|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['split']} | {r['kb']} | {r['algo']} "
                     f"| {r['f1']:.4f} | {r['auc']:.4f} |")
    (out / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[r4] wrote {out}/results.jsonl ({len(rows)} rows)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry", action="store_true",
                    help="join-only preview on real records (no training)")
    args = ap.parse_args()
    return run(dry=args.dry)


if __name__ == "__main__":
    raise SystemExit(main())
