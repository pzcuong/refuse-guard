"""Round-10 [r1] STABILIZED CENTRALIZED training: lr sweep {0.01, 0.03, 0.1}
+ early stopping on TRAIN-ONLY K-fold CV, 20 seeds (from
configs/packguard_fl.yaml grid.seeds), every split (group PRIMARY / random
secondary) and every feature block (graph / tfidf fit on TRAIN of the cell).

Protocol per cell (seed, split, block, partition=ecosystem):
  1. cell construction IDENTICAL to packguard.eval._grid_cell (read-only
     reuse via scripts/r10/_r10lib.py).
  2. For each lr: K-fold CV on the TRAIN pool only (k=3), one pass of
     local_train's exact SGD/BCE protocol per epoch, mean fold-AUC per epoch
     count, patience=3 -> best (lr, epochs) per cell.
  3. Final centralized model retrained on the FULL train pool for
     (best_lr, best_epochs); evaluated on the untouched global test set.
  4. Reference row: the UNSTABILIZED baseline (fixed max_epochs =
     rounds x local_epochs at the config lr) on the same cell, so the
     stabilization effect is measurable.

Outputs outputs/packguard/r10/r1_stabilized_central/{results.jsonl,summary.md}.
Every row carries mock + seed + split + block + config_sha16.

Dry run (--dry): synthetic fixture (mock=true), 2 seeds, group split, graph
block only, tiny epoch budget -> proves the plumbing without touching real
data. Real run cost: CPU-only, ~20-40 min.

Run (wrapper): scripts/r10/r1_stabilized_central.sh  (DRY=1 for --dry)
"""
from __future__ import annotations

import argparse
import copy
import statistics as st
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _r10lib as L  # noqa: E402

from packguard.fl import (  # noqa: E402
    FLConfig, FedClient, build_clients, config_sha16, make_global_test_split,
)

LRS = [0.01, 0.03, 0.1]
K_FOLDS = 3
PATIENCE = 3


def _fixture_cell(records, seed, split_mode, block, flc) -> dict:
    recs = copy.deepcopy(records)
    train, test = make_global_test_split(recs, 0.2, seed=seed)
    clients = build_clients(train, feature_block=block)
    test_client = FedClient("global_test", test, feature_block=block)
    return {"seed": seed, "split": split_mode, "block": block,
            "scheme": "ecosystem", "train": train, "test": test,
            "clients": clients, "test_client": test_client, "flc": flc}


def run(dry: bool) -> int:
    cfg = L.load_fl_config()
    out = L.out_dir("r1_stabilized_central", dry)
    if dry:
        from packguard.fl import synthetic_fixture

        records, _feat_meta = synthetic_fixture(seed=20260922)
        seeds, splits, blocks, partitions = ([20260922, 20260923], ["group"],
                                             ["graph"], ["ecosystem"])
        lrs = [0.1, 0.5]
        max_epochs, k_folds, patience = 4, 2, 2
        mock = True
        cfg_sha = "dry-synthetic-fixture"
        flc = FLConfig(input_dim=8, model_type="lr", rounds=2, local_epochs=1,
                       lr=0.1, batch_size=16, seed=20260922)
    else:
        records, _feat_meta, cache = L.load_grid_inputs(cfg)
        grid = cfg.get("grid", {}) or {}
        seeds = [int(s) for s in grid["seeds"]]
        splits = list(grid["splits"])
        blocks = list(grid["feature_blocks"])
        partitions = list(grid.get("partitions") or ["ecosystem"])
        lrs = LRS
        max_epochs = (int((cfg.get("fl", {}) or {}).get("rounds", 15)) *
                      int((cfg.get("fl", {}) or {}).get("local_epochs", 2)))
        k_folds, patience = K_FOLDS, PATIENCE
        mock = False
        cfg_sha = config_sha16(cfg)

    rows: list[dict] = []
    n_cells = len(seeds) * len(splits) * len(blocks) * len(partitions)
    done = 0
    for scheme in partitions:
        for seed in seeds:
            for split_mode in splits:
                for block in blocks:
                    done += 1
                    print(f"[r1 {done}/{n_cells}] seed={seed} split={split_mode} "
                          f"block={block} partition={scheme}", flush=True)
                    if dry:
                        cell = _fixture_cell(records, seed, split_mode, block, flc)
                    else:
                        cell = L.make_cell(records, cache, cfg, seed, split_mode,
                                           block, scheme)

                    # -- lr sweep with train-CV early stopping ----------------
                    sweep = []
                    best = None
                    for lr in lrs:
                        cv = L.cv_earlystop_central(
                            cell, lr=lr, k_folds=k_folds,
                            max_epochs=max_epochs, patience=patience, seed=seed)
                        sweep.append({k: cv[k] for k in
                                      ("lr", "best_epochs", "best_cv_auc",
                                       "n_undefined_fold_evals")})
                        if cv["best_cv_auc"] is not None and (
                                best is None or
                                cv["best_cv_auc"] > best["cv"]["best_cv_auc"]):
                            best = {"lr": lr, "cv": cv}
                    if best is None:
                        raise RuntimeError(
                            f"CV produced no scored epoch for cell "
                            f"{scheme}/{seed}/{split_mode}/{block}")

                    # -- final early-stopped model on the full train pool ----
                    early = L.centralized_train_eval(
                        cell, lr=best["lr"], epochs=best["cv"]["best_epochs"],
                        seed=seed)

                    # -- UNSTABILIZED reference (config protocol) ------------
                    ref = L.centralized_train_eval(
                        cell, lr=float((cfg.get("fl", {}) or {}).get("lr", 0.1)),
                        epochs=max_epochs, seed=seed)

                    def pos_rate(probs: list[float]) -> float:
                        return sum(1 for p in probs if p >= 0.5) / len(probs)

                    rows.append({
                        "kind": "run",
                        "name": (f"{scheme}__{split_mode}__{block}"
                                 f"__central_stabilized__seed{seed}"),
                        "mock": mock, "seed": seed, "split": split_mode,
                        "block": block, "partition": scheme,
                        "config_sha16": cfg_sha, "date": L.now_utc(),
                        "lr_sweep": lrs, "best_lr": best["lr"],
                        "best_epochs": best["cv"]["best_epochs"],
                        "max_epochs": max_epochs, "patience": patience,
                        "k_folds": k_folds,
                        "best_cv_auc": best["cv"]["best_cv_auc"],
                        "cv_mean_auc_curve": best["cv"]["mean_cv_auc_curve"],
                        "sweep": sweep,
                        "n_train": len(cell["train"]),
                        "n_test": len(cell["test"]),
                        "early_stopped": {
                            "f1": early["final_metrics"]["f1"],
                            "auc": early["final_metrics"]["auc"],
                            "precision": early["final_metrics"]["precision"],
                            "recall": early["final_metrics"]["recall"],
                            "pred_positive_rate": pos_rate(early["final_probs"])},
                        "baseline_fixed": {
                            "lr": float((cfg.get("fl", {}) or {}).get("lr", 0.1)),
                            "epochs": max_epochs,
                            "f1": ref["final_metrics"]["f1"],
                            "auc": ref["final_metrics"]["auc"],
                            "pred_positive_rate": pos_rate(ref["final_probs"])},
                    })

    L.write_jsonl(out / "results.jsonl", rows)
    _summary(out, rows, mock)
    print(f"[r1] wrote {out}/results.jsonl ({len(rows)} rows) mock={mock}")
    return 0


def _summary(out: Path, rows: list[dict], mock: bool) -> None:
    lines = ["# r1 stabilized centralized — summary", "",
             f"- date: {L.now_utc()}", f"- mock: {mock}",
             "- protocol: lr sweep + TRAIN-only K-fold CV early stopping "
             "(patience=3), retrain on full train, eval on global test", ""]
    lines.append("| split | block | seeds | F1 (early) mean±std | F1 (fixed) "
                 "mean±std | ΔF1 | best_epochs mean | pos_rate(early) mean |")
    lines.append("|---|---|---|---|---|---|---|---|")
    groups: dict[tuple, list[dict]] = {}
    for r in rows:
        groups.setdefault((r["split"], r["block"]), []).append(r)
    for (split, block), rs in sorted(groups.items()):
        f1e = [r["early_stopped"]["f1"] for r in rs]
        f1f = [r["baseline_fixed"]["f1"] for r in rs]
        de = [a - b for a, b in zip(f1e, f1f)]
        be = [r["best_epochs"] for r in rs]
        pe = [r["early_stopped"]["pred_positive_rate"] for r in rs]
        lines.append(
            f"| {split} | {block} | {len(rs)} | "
            f"{st.mean(f1e):.4f}±{st.pstdev(f1e):.4f} | "
            f"{st.mean(f1f):.4f}±{st.pstdev(f1f):.4f} | {st.mean(de):+.4f} | "
            f"{st.mean(be):.1f} | {st.mean(pe):.3f} |")
    (out / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry", action="store_true",
                    help="synthetic fixture, mock=true, tiny budget (0 data)")
    args = ap.parse_args()
    return run(dry=args.dry)


if __name__ == "__main__":
    raise SystemExit(main())
