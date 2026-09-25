"""Round-10 [r2] GRID REFRESH + PROBABILITY DUMP.

Part A — re-run the REGISTERED round-9 20-seed grid (AMENDMENT-3/4) after the
r1 stabilization, by calling packguard.eval's own CLI entry in-process:

    packguard.eval --grid --config configs/packguard_fl.yaml \
        --out-dir outputs/packguard/r10/fl_multiseed

(20 seeds x {group, random} x {graph, tfidf} x 4 methods x
{ecosystem PRIMARY, npm_hook fallback arm} — seeds/splits/blocks already in
configs/packguard_fl.yaml.)

Part B — per-sample PROBABILITY DUMP for the r3 calibration: for every grid
cell (same construction, seed-for-seed), re-run the CENTRALIZED method with
the identical protocol and dump {sample_id, label, prob} per
(partition, seed, split, block) to probs_dump.jsonl.  The grid's own rows
carry only summary metrics (no per-sample probs), so this companion pass
rebuilds each cell with the exact same split functions + TRAIN-only TF-IDF
fit (read-only reuse via scripts/r10/_r10lib.py) and trains with
packguard.fl.run_centralized.

Dry run (--dry): verifies the real inputs exist and prints the planned cell
counts; writes a TINY mock-flagged dump from the synthetic fixture to the
dry/ subdir (no grid run, no real data).  Real run cost: CPU-only, roughly
2x the round-9 20-seed grid (~1-2 h).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _r10lib as L  # noqa: E402

from packguard.fl import (  # noqa: E402
    FLConfig, FedClient, build_clients, make_global_test_split,
    run_centralized, synthetic_fixture,
)

GRID_OUT_REL = "outputs/packguard/r10/fl_multiseed"


def _dry() -> int:
    cfg = L.load_fl_config()
    grid = cfg.get("grid", {}) or {}
    seeds = grid.get("seeds") or []
    n_partitions = 2 if grid.get("run_client3") else 1  # ecosystem (+ npm_hook)
    cells = n_partitions * len(seeds) * len(grid.get("splits") or []) * \
        len(grid.get("feature_blocks") or [])
    feats = L.FEATURES_DIR / "features_v2.jsonl"
    print(f"[r2 dry] config: {L.CONFIG_PATH}")
    print(f"[r2 dry] grid.seeds: {len(seeds)} seeds "
          f"({seeds[0]}..{seeds[-1]})" if seeds else "[r2 dry] NO SEEDS")
    print(f"[r2 dry] planned grid cells: {cells} x 4 methods = {cells * 4} runs")
    print(f"[r2 dry] features input: {feats} exists={feats.exists()}")
    print(f"[r2 dry] text cache: {L.TEXT_CACHE} exists={L.TEXT_CACHE.exists()}")
    if not (feats.exists() and L.TEXT_CACHE.exists()):
        print("[r2 dry] FAIL: real inputs missing — real run would abort loudly")
        return 1
    # tiny mock dump to prove the writer path (mock=true, synthetic fixture)
    records, _ = synthetic_fixture(seed=20260922)
    flc = FLConfig(input_dim=8, model_type="lr", rounds=2, local_epochs=1,
                   lr=0.1, batch_size=16, seed=20260922)
    train, test = make_global_test_split(records, 0.2, seed=20260922)
    clients = build_clients(train, feature_block="graph")
    res = run_centralized(clients, FedClient("global_test", test, "graph"),
                          flc, 20260922)
    rows = [{"meta": {"mock": True, "note": "dry writer-path proof only",
                      "date": L.now_utc(), "method": "centralized"}}]
    sid = [r["sample_id"] for r in test]
    for s, p in zip(sid, res["final_probs"]):
        rows.append({"sample_id": s, "prob": p, "mock": True,
                     "seed": 20260922, "split": "group", "block": "graph",
                     "partition": "ecosystem", "method": "centralized"})
    out = L.out_dir("r2_grid_refresh", dry=True)
    L.write_jsonl(out / "probs_dump.jsonl", rows)
    print(f"[r2 dry] mock dump writer proof -> {out}/probs_dump.jsonl "
          f"({len(rows) - 1} rows, mock=true)")
    return 0


def _real() -> int:
    from packguard import eval as ev

    cfg = L.load_fl_config()
    out_grid = L.ROOT / GRID_OUT_REL

    # ---- Part A: the registered grid, via eval's own CLI handler ----------
    print(f"[r2] grid refresh -> {out_grid}", flush=True)
    rc = ev.main(["--grid", "--config", str(L.CONFIG_PATH),
                  "--out-dir", str(out_grid)])
    if rc != 0:
        return rc

    # ---- Part B: centralized probability dump per cell --------------------
    records, feat_meta, cache = L.load_grid_inputs(cfg)
    grid = cfg.get("grid", {}) or {}
    partitions = list(grid.get("partitions") or ["ecosystem"])
    if grid.get("run_client3"):
        partitions = partitions + ["npm_hook"]
    rows: list[dict] = [{
        "meta": {
            "mock": False, "date": L.now_utc(),
            "method": "centralized",
            "protocol": ("identical cell construction to packguard.eval."
                         "run_grid (same split fns + TRAIN-only tfidf fit); "
                         "trained with packguard.fl.run_centralized at the "
                         "config lr/rounds; probs aligned to the split's "
                         "test-record order"),
            "config_sha16": ev.config_sha16(cfg),
            "grid_summary": str(out_grid / "summary.md"),
        }}]
    n_cells = len(partitions) * len(grid["seeds"]) * len(grid["splits"]) * \
        len(grid["feature_blocks"])
    done = 0
    for scheme in partitions:
        for seed in [int(s) for s in grid["seeds"]]:
            for split_mode in grid["splits"]:
                for block in grid["feature_blocks"]:
                    done += 1
                    print(f"[r2 probs {done}/{n_cells}] {scheme} seed={seed} "
                          f"split={split_mode} block={block}", flush=True)
                    cell = L.make_cell(records, cache, cfg, seed, split_mode,
                                       block, scheme)
                    res = L.centralized_train_eval(
                        cell,
                        lr=float((cfg.get("fl", {}) or {}).get("lr", 0.1)),
                        epochs=(int((cfg.get("fl", {}) or {}).get("rounds", 15)) *
                                int((cfg.get("fl", {}) or {}).get("local_epochs", 2))),
                        seed=seed)
                    pos = sum(1 for p in res["final_probs"] if p >= 0.5)
                    for r, p in zip(cell["test"], res["final_probs"]):
                        rows.append({
                            "sample_id": r["sample_id"], "label": int(r["label"]),
                            "prob": p, "seed": seed, "split": split_mode,
                            "block": block, "partition": scheme,
                            "method": "centralized", "mock": False,
                            "pred_positive_rate_cell": round(pos / len(res["final_probs"]), 6),
                        })
    out = L.out_dir("r2_grid_refresh", dry=False)
    L.write_jsonl(out / "probs_dump.jsonl", rows)
    n_prob_rows = len(rows) - 1
    print(f"[r2] wrote {out}/probs_dump.jsonl ({n_prob_rows} prob rows)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry", action="store_true",
                    help="input checks + planned counts + mock writer proof")
    args = ap.parse_args()
    return _dry() if args.dry else _real()


if __name__ == "__main__":
    raise SystemExit(main())
