"""Round-10 [r3] CALIBRATION + ALL-MALICIOUS REMEDY on the r2 probability
dump (CPU-only, no generation).

Inputs  : outputs/packguard/r10/r2_grid_refresh/probs_dump.jsonl
          (centralized P(malicious) per grid test sample; default; override
          with --probs).
Analyses (per feature block, pooled over seeds, group PRIMARY + random):
  1. Brier score + equal-width ECE (15 bins) with reliability diagram data.
  2. Threshold sweep 0.05..0.95 (F1/precision/recall/MCC/pred-positive-rate)
     -> the best-F1 and best-MCC operating thresholds vs the default 0.5.
  3. All-malicious diagnostic: share of cells whose pred-positive-rate @0.5
     is 1.0 (the degenerate "predict everything malicious" mode the round-9
     grid summary disclosed for tfidf), and mean pred-positive-rate.
  4. CLASS-WEIGHT remedy: retrain the SAME centralized cells with weighted
     BCE (pos_weight = n_neg/n_pos on train; helper-local trainer because
     packguard.models.local_train has no class-weight hook — disclosed),
     same epochs/lr/seed protocol, then re-evaluate F1@0.5, pred-positive-
     rate, and F1@best-swept-threshold. Weighted probs are dumped alongside
     (probs_dump_weighted.jsonl) for the paper's before/after table.

Outputs outputs/packguard/r10/r3_calibration/{calibration.json,summary.md,
probs_dump_weighted.jsonl}.

Dry run (--dry): synthesizes a small deterministic mock dump and runs the
full metric code path on it (mock=true) — no real data, no training beyond
a 1-cell fixture. Real run cost: CPU-only, ~10-25 min (20 seeds x 2 splits
x 2 blocks weighted retrain + metrics).
"""
from __future__ import annotations

import argparse
import json
import statistics as st
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _r10lib as L  # noqa: E402

DEFAULT_PROBS = L.OUT_BASE / "r2_grid_refresh" / "probs_dump.jsonl"


def _load_dump(path: Path) -> tuple[dict, list[dict]]:
    meta: dict = {}
    rows: list[dict] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if "meta" in r:
                meta = r["meta"]
            elif "prob" in r:
                rows.append(r)
    if not rows:
        raise RuntimeError(f"no prob rows in {path} — run r2_grid_refresh first")
    return meta, rows


def _metrics_block(probs: list[float], ys: list[int]) -> dict:
    sweep = L.threshold_sweep(probs, ys)
    best_f1 = max(sweep, key=lambda r: r["f1"])
    best_mcc = max(sweep, key=lambda r: r["mcc"])
    return {
        "n": len(probs),
        "brier": L.brier_score(probs, ys),
        "ece_15bins": L.ece_score(probs, ys)["ece"],
        "threshold_sweep": sweep,
        "best_f1_threshold": best_f1["threshold"],
        "best_f1": best_f1["f1"],
        "best_mcc_threshold": best_mcc["threshold"],
        "best_mcc": best_mcc["mcc"],
        "f1_at_0.5": next(r["f1"] for r in sweep if r["threshold"] == 0.5)
        if any(r["threshold"] == 0.5 for r in sweep) else None,
        "pred_positive_rate@0.5": next(
            r["pred_positive_rate"] for r in sweep if r["threshold"] == 0.5)
        if any(r["threshold"] == 0.5 for r in sweep) else None,
    }


def _all_malicious_diag(rows: list[dict]) -> dict:
    """Per-cell degenerate-mode diagnostic (rows carry the cell's pooled
    pred_positive_rate at 0.5)."""
    cells: dict[tuple, float] = {}
    for r in rows:
        cells[(r["partition"], r["seed"], r["split"], r["block"])] = \
            r.get("pred_positive_rate_cell", None)
    per_block: dict[str, dict] = {}
    for block in sorted({k[3] for k in cells}):
        vals = [v for k, v in cells.items() if k[3] == block and v is not None]
        per_block[block] = {
            "n_cells": len(vals),
            "n_all_malicious_cells@0.5": sum(1 for v in vals if v >= 0.999),
            "share_all_malicious": (sum(1 for v in vals if v >= 0.999) / len(vals))
            if vals else None,
            "mean_pred_positive_rate": st.mean(vals) if vals else None,
        }
    return {"per_cell_pred_positive_rate@0.5":
            {f"{k[0]}__{k[1]}__{k[2]}__{k[3]}": v for k, v in sorted(cells.items())},
            "per_block": per_block}


def _dry() -> int:
    import numpy as np

    rng = np.random.default_rng(20260922)
    rows: list[dict] = [{"meta": {"mock": True, "date": L.now_utc(),
                                  "note": "deterministic mock dump for the "
                                          "dry code-path proof"}}]
    for seed in (20260922, 20260923):
        for split in ("group", "random"):
            for block in ("graph", "tfidf"):
                p = np.clip(rng.beta(5, 1.5, size=40), 0.0, 1.0)  # skewed high
                y = (rng.random(40) < p).astype(int)
                for i in range(40):
                    rows.append({
                        "sample_id": f"mock-{seed}-{split}-{block}-{i}",
                        "label": int(y[i]), "prob": round(float(p[i]), 6),
                        "seed": seed, "split": split, "block": block,
                        "partition": "ecosystem", "method": "centralized",
                        "mock": True,
                        "pred_positive_rate_cell": round(
                            float((p >= 0.5).mean()), 6)})
    tmp = L.out_dir("r3_calibration", dry=True) / "mock_probs_dump.jsonl"
    L.write_jsonl(tmp, rows)
    payload = _analyse(rows, weighted=None, dry=True)
    L.write_json(L.out_dir("r3_calibration", True) / "calibration.json", payload)
    print(f"[r3 dry] mock dump ({len(rows) - 1} rows) + calibration metrics "
          f"written under {L.out_dir('r3_calibration', True)} (mock=true)")
    _summary(L.out_dir("r3_calibration", True), payload, mock=True)
    return 0


def _analyse(rows: list[dict], weighted: list[dict] | None,
             dry: bool) -> dict:
    rows = [r for r in rows if "block" in r]  # drop the meta line
    by_bs: dict[tuple, list[dict]] = defaultdict(list)
    for r in rows:
        by_bs[(r["block"], r["split"])].append(r)
    out: dict = {"date": L.now_utc(), "mock": bool(dry or
                                                   rows[0].get("mock", False)),
                 "per_block_split": {}}
    for (block, split), rs in sorted(by_bs.items()):
        probs = [float(r["prob"]) for r in rs]
        ys = [int(r["label"]) for r in rs]
        m = _metrics_block(probs, ys)
        m["all_malicious_diag"] = _all_malicious_diag(rs)["per_block"].get(block)
        if weighted is not None:
            # .get(): skip the leading meta row (no block/split keys)
            w_rs = [r for r in weighted
                    if r.get("block") == block and r.get("split") == split]
            if w_rs:
                w = _metrics_block([float(r["prob"]) for r in w_rs],
                                   [int(r["label"]) for r in w_rs])
                m["class_weighted"] = {
                    "pos_weight": "n_neg/n_pos (per train pool)",
                    "f1@0.5": w["f1_at_0.5"],
                    "pred_positive_rate@0.5": w["pred_positive_rate@0.5"],
                    "best_f1": w["best_f1"],
                    "best_f1_threshold": w["best_f1_threshold"],
                    "best_mcc": w["best_mcc"],
                }
        out["per_block_split"][f"{block}__{split}"] = m
    return out


def _real(probs_path: Path) -> int:
    cfg = L.load_fl_config()
    meta, rows = _load_dump(probs_path)
    print(f"[r3] probs dump: {probs_path} ({len(rows)} rows, "
          f"dump meta date={meta.get('date')})")

    # ---- class-weight remedy: retrain the same cells, weighted BCE --------
    records, _feat_meta, cache = L.load_grid_inputs(cfg)
    grid = cfg.get("grid", {}) or {}
    weighted_rows: list[dict] = [{
        "meta": {"mock": False, "date": L.now_utc(), "method": "centralized",
                 "variant": "class_weighted_bce",
                 "note": ("helper-local weighted-BCE centralized trainer "
                          "(pos_weight=n_neg/n_pos); protocol otherwise "
                          "identical to packguard.fl.run_centralized")}}]
    partitions = list(grid.get("partitions") or ["ecosystem"])
    if grid.get("run_client3"):
        partitions = partitions + ["npm_hook"]
    n_cells = len(partitions) * len(grid["seeds"]) * len(grid["splits"]) * \
        len(grid["feature_blocks"])
    done = 0
    for scheme in partitions:
        for seed in [int(s) for s in grid["seeds"]]:
            for split_mode in grid["splits"]:
                for block in grid["feature_blocks"]:
                    done += 1
                    print(f"[r3 weighted {done}/{n_cells}] {scheme} seed={seed} "
                          f"split={split_mode} block={block}", flush=True)
                    cell = L.make_cell(records, cache, cfg, seed, split_mode,
                                       block, scheme)
                    import torch

                    ytr = torch.cat([c.y for c in cell["clients"]])
                    n_pos = float(ytr.sum())
                    n_neg = float(len(ytr) - n_pos)
                    pos_w = n_neg / n_pos if n_pos > 0 else 1.0
                    res = L.centralized_train_eval(
                        cell,
                        lr=float((cfg.get("fl", {}) or {}).get("lr", 0.1)),
                        epochs=(int((cfg.get("fl", {}) or {}).get("rounds", 15)) *
                                int((cfg.get("fl", {}) or {}).get("local_epochs", 2))),
                        seed=seed, pos_weight=pos_w)
                    pos = sum(1 for p in res["final_probs"] if p >= 0.5)
                    for r, p in zip(cell["test"], res["final_probs"]):
                        weighted_rows.append({
                            "sample_id": r["sample_id"],
                            "label": int(r["label"]), "prob": p,
                            "seed": seed, "split": split_mode, "block": block,
                            "partition": scheme, "method": "centralized",
                            "variant": "class_weighted_bce", "pos_weight": round(pos_w, 6),
                            "mock": False,
                            "pred_positive_rate_cell": round(pos / len(res["final_probs"]), 6)})
    out = L.out_dir("r3_calibration", dry=False)
    L.write_jsonl(out / "probs_dump_weighted.jsonl", weighted_rows)

    payload = _analyse(rows, weighted=weighted_rows, dry=False)
    payload["inputs"] = {"probs_dump": str(probs_path),
                         "dump_meta": meta,
                         "weighted_dump": str(out / "probs_dump_weighted.jsonl")}
    L.write_json(out / "calibration.json", payload)
    _summary(out, payload, mock=False)
    print(f"[r3] wrote {out}/calibration.json + probs_dump_weighted.jsonl")
    return 0


def _summary(out: Path, payload: dict, mock: bool) -> None:
    lines = ["# r3 calibration — summary", "",
             f"- date: {payload['date']}", f"- mock: {mock}",
             "- ECE: 15 equal-width bins; sweep 0.05..0.95; class-weight "
             "arm = weighted-BCE centralized retrain (pos_weight=n_neg/n_pos)",
             ""]
    lines.append("| block | split | Brier | ECE | F1@0.5 | pos_rate@0.5 | "
                 "best-F1 thr | F1 | F1 (weighted)@0.5 | pos_rate (weighted) |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|")
    for key, m in sorted(payload["per_block_split"].items()):
        block, split = key.split("__")
        cw = m.get("class_weighted") or {}
        lines.append(
            f"| {block} | {split} | {m['brier']:.4f} | {m['ece_15bins']:.4f} "
            f"| {m['f1_at_0.5']:.4f} | {m['pred_positive_rate@0.5']:.3f} "
            f"| {m['best_f1_threshold']:.2f} | {m['best_f1']:.4f} "
            f"| {cw.get('f1@0.5', float('nan')):.4f} "
            f"| {cw.get('pred_positive_rate@0.5', float('nan')):.3f} |")
    lines.append("")
    lines.append("## All-malicious degenerate mode (@0.5) per block")
    for key, m in sorted(payload["per_block_split"].items()):
        d = m.get("all_malicious_diag") or {}
        if d:
            lines.append(f"- {key}: {d.get('n_all_malicious_cells@0.5')}"
                         f"/{d.get('n_cells')} cells all-malicious "
                         f"(share={d.get('share_all_malicious')})")
    (out / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry", action="store_true",
                    help="deterministic mock dump through the metric code path")
    ap.add_argument("--probs", default=str(DEFAULT_PROBS),
                    help="path to the r2 probs_dump.jsonl")
    args = ap.parse_args()
    if args.dry:
        return _dry()
    return _real(Path(args.probs))


if __name__ == "__main__":
    raise SystemExit(main())
