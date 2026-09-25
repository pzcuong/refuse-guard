"""Shared library for the round-10 wrapper helpers (scripts/r10/).

READ-ONLY reuse of the audited round-8/9 machinery (nothing in packguard/ or
src/ is modified):
  - packguard.fl: data loading, splits, clients, centralized runner, FLConfig
  - packguard.eval: the grid's FLConfig builder + the per-(seed,split) TF-IDF
    fit (fit on TRAIN only -- the exact mirror of
    scripts/packguard_final_runs.py::tfidf_blocks used by the round-9 grid)
  - packguard.models: build_model / set_seed / predict_proba

Everything a helper writes goes under outputs/packguard/r10/<name>/ and is
mock-flagged when produced by a --dry run.
"""
from __future__ import annotations

import copy
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from packguard import fl as flm  # noqa: E402
from packguard.eval import (  # noqa: E402 (read-only reuse)
    _grid_fl_config, _tfidf_blocks, load_yaml, CONFIG_DEFAULT,
)
from packguard.fl import (  # noqa: E402
    FedClient,
    build_clients,
    load_feature_records,
    make_global_test_split,
    make_group_split,
    run_centralized,
)
from packguard.models import build_model, predict_proba, set_seed  # noqa: E402

CONFIG_PATH = ROOT / "configs/packguard_fl.yaml"
FEATURES_DIR = ROOT / "outputs/packguard/features"
TEXT_CACHE = ROOT / "outputs/packguard/features/text_v2.json"
OUT_BASE = ROOT / "outputs/packguard/r10"


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_fl_config() -> dict:
    return load_yaml(CONFIG_PATH)


def out_dir(name: str, dry: bool) -> Path:
    d = OUT_BASE / name / ("dry" if dry else "")
    d.mkdir(parents=True, exist_ok=True)
    return d


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False, default=str) + "\n")


def write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=1, default=str, ensure_ascii=False),
                    encoding="utf-8")


# ---------------------------------------------------------------------------
# Cell construction -- mirrors packguard.eval._grid_cell's data path exactly
# (deep-copy records -> (group|random) split -> tfidf fit on TRAIN only).
# ---------------------------------------------------------------------------
def load_grid_inputs(cfg: dict) -> tuple[list[dict], dict, dict]:
    grid = cfg.get("grid", {}) or {}
    records, feat_meta = load_feature_records(FEATURES_DIR)
    if feat_meta.get("mock", False):
        raise RuntimeError("run_grid refuses mock data (real runs only)")
    cache: dict = {}
    if "tfidf" in (grid.get("feature_blocks") or []):
        if not TEXT_CACHE.exists():
            raise FileNotFoundError(f"tfidf grid needs the round-8 text cache {TEXT_CACHE}")
        with TEXT_CACHE.open() as f:
            cache = json.load(f)
    return records, feat_meta, cache


def make_cell(records: list[dict], cache: dict, cfg: dict, seed: int,
              split_mode: str, block: str, scheme: str) -> dict:
    """One (seed, split, block, partition) cell: identical construction to
    packguard.eval._grid_cell (read-only mirror)."""
    import copy as _copy

    frac = float(((cfg.get("data", {}) or {}).get("test_fraction", 0.2)))
    recs = _copy.deepcopy(records)
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
    return {"seed": seed, "split": split_mode, "block": block,
            "scheme": scheme, "train": train, "test": test,
            "clients": clients, "test_client": test_client, "flc": flc}


def iter_grid_cells(records: list[dict], cache: dict, cfg: dict,
                    seeds=None, splits=None, blocks=None,
                    partitions=None) -> Iterator[dict]:
    grid = cfg.get("grid", {}) or {}
    for scheme in (partitions or grid.get("partitions") or ["ecosystem"]):
        for seed in (seeds or [int(s) for s in grid.get("seeds", [int(cfg.get("seed", 20260922))])]):
            for split_mode in (splits or grid.get("splits") or ["group", "random"]):
                for block in (blocks or grid.get("feature_blocks") or ["graph", "tfidf"]):
                    yield make_cell(records, cache, cfg, int(seed), split_mode,
                                    block, scheme)


# ---------------------------------------------------------------------------
# Centralized trainers (helper-local; disclose vs packguard.fl.run_centralized)
# ---------------------------------------------------------------------------
def _train_epochs(model, X, y, n_epochs: int, lr: float, batch_size: int,
                  seed: int) -> None:
    """One or more full passes with EXACTLY packguard.models.local_train's
    protocol (torch SGD, seeded Generator permutations, BCEWithLogits), done
    epoch-by-epoch so callers can evaluate between epochs."""
    import torch
    from torch import nn

    opt = torch.optim.SGD(model.parameters(), lr=float(lr))
    gen = torch.Generator().manual_seed(int(seed))
    n = int(X.shape[0])
    for _ in range(max(0, int(n_epochs))):
        perm = torch.randperm(n, generator=gen)
        for start in range(0, n, max(1, int(batch_size))):
            idx = perm[start:start + int(batch_size)]
            opt.zero_grad()
            logits = model(X[idx])
            loss = nn.functional.binary_cross_entropy_with_logits(
                logits, y[idx].float())
            loss.backward()
            opt.step()


def _train_epochs_weighted(model, X, y, n_epochs: int, lr: float,
                           batch_size: int, seed: int,
                           pos_weight: float) -> None:
    """Same protocol as _train_epochs but with a class-weighted BCE
    (pos_weight = n_negative/n_positive on the TRAIN pool).  Helper-local:
    packguard.models.local_train has no class-weight hook (read-only reuse)."""
    import torch
    from torch import nn

    opt = torch.optim.SGD(model.parameters(), lr=float(lr))
    gen = torch.Generator().manual_seed(int(seed))
    n = int(X.shape[0])
    pw = torch.tensor(float(pos_weight))
    for _ in range(max(0, int(n_epochs))):
        perm = torch.randperm(n, generator=gen)
        for start in range(0, n, max(1, int(batch_size))):
            idx = perm[start:start + int(batch_size)]
            opt.zero_grad()
            logits = model(X[idx])
            loss = nn.functional.binary_cross_entropy_with_logits(
                logits, y[idx].float(), pos_weight=pw)
            loss.backward()
            opt.step()


def centralized_train_eval(cell: dict, lr: float, epochs: int, seed: int,
                           pos_weight: Optional[float] = None) -> dict:
    """Train centralized on the cell's pooled train pool for a FIXED epoch
    count (protocol identical to packguard.fl.run_centralized, which uses
    rounds*local_epochs full passes), then eval on the global test set."""
    import torch

    X = torch.cat([c.X for c in cell["clients"]])
    y = torch.cat([c.y for c in cell["clients"]])
    flc = cell["flc"]
    set_seed(seed)
    model = build_model({"type": flc.model_type, "hidden_dim": flc.hidden_dim},
                        cell["test_client"].input_dim)
    if pos_weight is None:
        _train_epochs(model, X, y, epochs, lr, flc.batch_size, seed)
    else:
        _train_epochs_weighted(model, X, y, epochs, lr, flc.batch_size, seed,
                               pos_weight)
    probs = predict_proba(model, cell["test_client"].X)
    metrics = flm.compute_clf_metrics(
        cell["test_client"].y.numpy().astype(int), probs)
    return {"final_metrics": metrics,
            "final_probs": [round(float(p), 6) for p in probs]}


def cv_earlystop_central(cell: dict, lr: float, k_folds: int, max_epochs: int,
                         patience: int, seed: int,
                         min_delta: float = 1e-4) -> dict:
    """TRAIN-ONLY K-fold CV early stopping for the centralized model.

    Protocol: seeded round-robin fold assignment over the train pool
    (disclosed: plain K-fold on a seeded permutation, NOT stratified); each
    fold trains with exactly local_train's SGD/BCE protocol, evaluated on its
    held-out fold after every epoch; selection metric = mean fold AUC of
    P(malicious) (AUC-undefined folds are skipped in the mean and counted).
    best_epochs = the epoch count with the best mean CV AUC, scanning stopped
    after `patience` epochs without a min_delta improvement.
    """
    import torch

    from sklearn import metrics as skm

    X = torch.cat([c.X for c in cell["clients"]])
    y = torch.cat([c.y for c in cell["clients"]])
    flc = cell["flc"]
    n = int(X.shape[0])
    g = torch.Generator().manual_seed(int(seed))
    perm = torch.randperm(n, generator=g)
    folds = [perm[i::k_folds] for i in range(k_folds)]

    fold_curves: list[list[Optional[float]]] = []
    for f, va_idx in enumerate(folds):
        tr_idx = torch.cat([folds[j] for j in range(k_folds) if j != f])
        set_seed((seed * 1000 + f) % (2**31 - 1))
        model = build_model({"type": flc.model_type,
                             "hidden_dim": flc.hidden_dim}, int(X.shape[1]))
        curve: list[Optional[float]] = []
        for e in range(1, max_epochs + 1):
            _train_epochs(model, X[tr_idx], y[tr_idx], 1, lr, flc.batch_size,
                          (seed * 100000 + f * 1000 + e) % (2**31 - 1))
            with torch.no_grad():
                p = predict_proba(model, X[va_idx])
            yv = y[va_idx].numpy().astype(int)
            curve.append(float(skm.roc_auc_score(yv, p))
                         if len(set(yv.tolist())) > 1 else None)
        fold_curves.append(curve)

    mean_curve: list[Optional[float]] = []
    for e in range(max_epochs):
        vals = [c[e] for c in fold_curves if c[e] is not None]
        mean_curve.append(sum(vals) / len(vals) if vals else None)
    best_e, best_v = 0, -1.0
    since_best = 0
    for e, v in enumerate(mean_curve):
        if v is None:
            continue
        if v > best_v + min_delta:
            best_v, best_e, since_best = v, e + 1, 0
        else:
            since_best += 1
            if since_best >= patience:
                break
    return {"best_epochs": int(best_e),
            "best_cv_auc": (None if best_v < 0 else best_v),
            "mean_cv_auc_curve": mean_curve, "k_folds": k_folds,
            "lr": lr, "max_epochs": max_epochs, "patience": patience,
            "n_train": n,
            "n_undefined_fold_evals": sum(
                1 for c in fold_curves for v in c if v is None)}


# ---------------------------------------------------------------------------
# Calibration metrics (helper-local; sklearn otherwise untouched)
# ---------------------------------------------------------------------------
def ece_score(probs: list[float], ys: list[int], n_bins: int = 15) -> dict:
    """Equal-width ECE + reliability bins (never fabricated when empty)."""
    if not probs:
        return {"ece": None, "bins": []}
    edges = [i / n_bins for i in range(n_bins + 1)]
    bins = []
    ece = 0.0
    n = len(probs)
    for b in range(n_bins):
        lo, hi = edges[b], edges[b + 1]
        idx = [i for i, p in enumerate(probs)
               if (lo <= p < hi) or (b == n_bins - 1 and p == hi)]
        if not idx:
            bins.append({"bin": b, "lo": lo, "hi": hi, "n": 0})
            continue
        conf = sum(probs[i] for i in idx) / len(idx)
        acc = sum(ys[i] for i in idx) / len(idx)
        ece += (len(idx) / n) * abs(acc - conf)
        bins.append({"bin": b, "lo": lo, "hi": hi, "n": len(idx),
                     "mean_prob": conf, "frac_pos": acc})
    return {"ece": ece, "bins": bins}


def brier_score(probs: list[float], ys: list[int]) -> Optional[float]:
    if not probs:
        return None
    return sum((p - y) ** 2 for p, y in zip(probs, ys)) / len(probs)


def threshold_sweep(probs: list[float], ys: list[int],
                    thresholds: Optional[list[float]] = None) -> list[dict]:
    from sklearn import metrics as skm

    rows = []
    for t in (thresholds if thresholds is not None
              else [round(0.05 * i, 2) for i in range(1, 20)]):
        pred = [1 if p >= t else 0 for p in probs]
        rows.append({
            "threshold": t,
            "f1": float(skm.f1_score(ys, pred, zero_division=0)),
            "precision": float(skm.precision_score(ys, pred, zero_division=0)),
            "recall": float(skm.recall_score(ys, pred, zero_division=0)),
            "mcc": float(skm.matthews_corrcoef(ys, pred)) if len(set(pred)) > 1 else 0.0,
            "pred_positive_rate": sum(pred) / len(pred) if pred else None,
        })
    return rows


# ---------------------------------------------------------------------------
# Dry-mode stub generator for the safety helpers (0 model load, 0 GPU)
# ---------------------------------------------------------------------------
class StubHarness:
    """Minimal stand-in for LLMHarness: run_arm(harness, ..., generator=...)
    reads only harness.model_id when a stub generator is passed."""

    def __init__(self, model_id: str):
        self.model_id = model_id


def stub_generator_factory(seed: int = 1234):
    """Deterministic stub generator: emits a parseable benign/malicious JSON
    verdict keyed on the sample_id hash -- exercises run_arm's full record
    path (monitor classify + verdict parse) with ZERO generation."""
    def generate(prompt: dict) -> str:
        blob = json.dumps(prompt, sort_keys=True, ensure_ascii=False)
        h = hash(blob) % 100
        vuln = 1 if h < 45 else 0
        return json.dumps({
            "analysis_status": "analysis_complete", "vulnerable": vuln,
            "cwe": "CWE-000" if vuln else None,
            "location": "stub:dry", "confidence": 1.0,
        })
    return generate


def mcnemar_paired(a: list[bool], b: list[bool]) -> dict:
    """Paired McNemar via src.metrics.stats.mcnemar (read-only reuse)."""
    from src.metrics.stats import mcnemar

    return mcnemar(a, b)


def deep_copy_cfg(cfg: dict) -> dict:
    return copy.deepcopy(cfg)
