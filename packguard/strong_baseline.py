"""Strong centralized / FL baselines for round-11 P0 (AMENDMENT-5, A5.1-A5.5).

Fixes the three audited baseline problems:
  * L1: the old centralized torch-SGD baseline (lr=0.1, 15x2 epochs, raw
    features) UNDERTRAINED a convex problem (1/40-cell F1 collapse .375,
    .326 cells). Here centralized = sklearn LogisticRegression(solver="lbfgs",
    max_iter=5000, tol=1e-6) on StandardScaler-standardized features; the
    scaler is fit on the TRAIN pool of the (seed, split) only, and C comes
    from a 3-fold stratified CV ON THE TRAIN POOL ONLY.
  * W2-audit: FedProx under this recipe uses the exact Li et al. 2020 local
    objective (sklearn L2 objective + (mu/2)*||theta - theta_global||^2,
    intercept included) solved with scipy L-BFGS-B; fl.py's algo routing was
    fixed separately (see fl.py run_federated docstring).
  * L2: the text arm uses HashingVectorizer (STATELESS, no vocabulary fit) so
    FL clients share an identical transform without any pooled-vocab fit —
    the FL-valid replacement for the old pooled TfidfVectorizer.

FL validity notes (disclosed everywhere these are used):
  * Standardization: ONE scaler fit on the POOLED TRAIN of each (seed, split)
    and shared by all clients ("shared preprocessing"; no test rows involved).
    Sparse (hashing) blocks use with_mean=False (scale-only) to stay sparse.
  * C is selected ONCE per (seed, split, block) on the pooled TRAIN and shared
    by all clients — a centrally-chosen hyperparameter, never test-touched.
  * FedAvg-S = n-weighted parameter average of fully-converged local lbfgs
    fits ("local fit, then average"); the round loop is kept for protocol
    continuity and is a fixed point from round 2 (converged convex local
    problems are init-independent) — verified numerically in the outputs.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, Sequence

import numpy as np

from packguard.fl import client_name_of, compute_clf_metrics

__all__ = [
    "C_GRID",
    "STRONG_LR_KWARGS",
    "HashingTextFeaturizer",
    "build_design_matrix",
    "fit_scaler",
    "standardize",
    "select_c_cv",
    "fit_lr",
    "local_fit_fedprox",
    "fedavg_sklearn",
    "fedprox_sklearn",
    "per_client_best_sklearn",
    "strong_centralized",
    "probs_from_theta",
    "P0CellResult",
]

C_GRID = (0.01, 0.1, 1.0, 10.0)
STRONG_LR_KWARGS = dict(solver="lbfgs", max_iter=5000, tol=1e-6)


# ---------------------------------------------------------------------------
# Feature blocks
# ---------------------------------------------------------------------------
class HashingTextFeaturizer:
    """Stateless text -> sparse features (AMENDMENT-5 A5.5).

    HashingVectorizer(n_features=2**18, alternate_sign=False, norm="l2"):
    no vocabulary is ever fit, so every FL client applies the IDENTICAL
    transform — no pooled-vocab leakage by construction (L2 fix)."""

    def __init__(self, n_features: int = 2 ** 18):
        from sklearn.feature_extraction.text import HashingVectorizer

        self.n_features = int(n_features)
        self._vec = HashingVectorizer(
            n_features=self.n_features, alternate_sign=False, norm="l2"
        )

    def transform(self, texts: Sequence[str]):
        return self._vec.transform(list(texts))


def _graph_matrix(records: list[dict]) -> np.ndarray:
    names: Optional[list[str]] = None
    for r in records:
        block = (r.get("features", {}) or {}).get("graph", {})
        if block:
            names = sorted(block)
            break
    if names is None:
        raise ValueError("no record carries a non-empty `graph` feature block")
    return np.array(
        [[float((r.get("features", {}) or {}).get("graph", {}).get(n, 0.0))
          for n in names] for r in records], dtype=np.float64
    )


def build_design_matrix(records: list[dict], block: str,
                        text_cache: Optional[dict[str, str]] = None,
                        precomputed: Optional[tuple[Any, dict[str, int]]] = None):
    """Raw (unstandardized) design matrix for `block`.

    block="graph": dense numeric matrix from the frozen v2 feature names.
    block="hashing_tfidf": HashingVectorizer on the per-sample text cache.
    `precomputed` = (csr_matrix, sample_id -> row index) reuses the corpus-
    wide hash matrix (the transform is stateless, so the matrix is identical
    for every seed/split; only the row SLICES differ)."""
    if block == "graph":
        return _graph_matrix(records)
    if block == "hashing_tfidf":
        if precomputed is not None:
            mat, index = precomputed
            rows = [index[str(r["sample_id"])] for r in records]
            return mat[rows]
        if text_cache is None:
            raise ValueError("hashing_tfidf needs the text cache")
        featurizer = HashingTextFeaturizer()
        return featurizer.transform(
            [text_cache.get(str(r["sample_id"]), "") or "" for r in records])
    raise ValueError(f"unknown block {block!r}")


# ---------------------------------------------------------------------------
# Standardization (train-only fit; shared by FL clients — disclosed)
# ---------------------------------------------------------------------------
def fit_scaler(X_train):
    """StandardScaler fit on pooled TRAIN. Sparse input -> with_mean=False
    (scale-only; subtracting the mean would densify 2^18 columns)."""
    from sklearn.preprocessing import StandardScaler

    sparse = hasattr(X_train, "tocsr")
    sc = StandardScaler(with_mean=not sparse)
    sc.fit(X_train)
    return sc


def standardize(sc, X):
    out = sc.transform(X)
    return out


# ---------------------------------------------------------------------------
# Strong LR (lbfgs, converged) + C selection on TRAIN only
# ---------------------------------------------------------------------------
def fit_lr(X, y, C: float) -> dict:
    """Fit the registered strong LR (lbfgs, max_iter 5000, tol 1e-6)."""
    from sklearn.linear_model import LogisticRegression

    model = LogisticRegression(C=float(C), **STRONG_LR_KWARGS)
    model.fit(X, np.asarray(y, dtype=int))
    n_iter = getattr(model, "n_iter_", None)
    iters = int(np.ravel(n_iter)[0]) if n_iter is not None else -1
    return {"model": model, "n_iter": iters,
            "converged": bool(iters < STRONG_LR_KWARGS["max_iter"])}


def _probs(model, X) -> np.ndarray:
    return model.predict_proba(X)[:, 1]


def select_c_cv(X_train, y_train, seed: int, c_grid: Sequence[float] = C_GRID,
                folds: int = 3) -> dict:
    """Nested-free model selection: C by 3-fold stratified CV on the TRAIN
    pool ONLY (AMENDMENT-5 A5.1). Tie-break: mean CV AUC, then grid order
    (stronger regularization first). Deterministic via random_state=seed."""
    from sklearn.model_selection import StratifiedKFold

    y = np.asarray(y_train, dtype=int)
    skf = StratifiedKFold(n_splits=folds, shuffle=True, random_state=int(seed))
    table = []
    for c in c_grid:
        f1s, aucs, iters = [], [], []
        for tr_idx, va_idx in skf.split(np.zeros(len(y)), y):
            fit = fit_lr(X_train[tr_idx], y[tr_idx], c)
            probs = _probs(fit["model"], X_train[va_idx])
            m = compute_clf_metrics(y[va_idx], probs)
            f1s.append(m["f1"])
            if m["auc"] is not None:
                aucs.append(m["auc"])
            iters.append(fit["n_iter"])
        table.append({
            "C": float(c),
            "cv_f1_mean": float(np.mean(f1s)), "cv_f1_std": float(np.std(f1s)),
            "cv_auc_mean": (float(np.mean(aucs)) if aucs else None),
            "max_n_iter": int(max(iters)),
        })
    best_idx = max(
        range(len(table)),
        key=lambda i: (table[i]["cv_f1_mean"],
                       table[i]["cv_auc_mean"] if table[i]["cv_auc_mean"]
                       is not None else float("-inf"),
                       -i),
    )
    return {"C_selected": table[best_idx]["C"], "cv_table": table,
            "folds": int(folds), "selection": "train-only 3-fold CV "
            "(max mean F1; tie: mean AUC; tie: grid order)"}


# ---------------------------------------------------------------------------
# FedProx local solver (exact Li et al. 2020 local objective)
# ---------------------------------------------------------------------------
def _pack(coef: np.ndarray, intercept: float) -> np.ndarray:
    return np.concatenate([coef.ravel(), [float(intercept)]])


def _unpack(theta: np.ndarray) -> tuple[np.ndarray, float]:
    return theta[:-1], float(theta[-1])


def probs_from_theta(theta: np.ndarray, X) -> np.ndarray:
    from scipy.special import expit

    w, b = _unpack(theta)
    z = np.asarray(X @ w + b).ravel()
    return np.asarray(expit(z), dtype=float).ravel()


def local_fit_fedprox(X, y, C: float, theta_global: np.ndarray, mu: float
                      ) -> dict:
    """Minimize  mean log-loss + (1/(2*C*n))*||w||^2 + (mu/2)*||theta - theta_g||^2
    over theta = [w, intercept] with scipy L-BFGS-B (analytic gradient),
    starting AT the broadcast global theta (Li et al. 2020 local problem)."""
    from scipy.optimize import minimize
    from scipy.special import expit

    y = np.asarray(y, dtype=float)
    s = 2.0 * y - 1.0                      # {0,1} -> {-1,1} (for logaddexp)
    n = float(len(s))
    w_g, b_g = _unpack(theta_global)
    d = X.shape[1]

    def objective(theta: np.ndarray):
        w, b = _unpack(theta)
        z = np.asarray(X @ w + b).ravel()
        # numerically stable mean log-loss: log(1+exp(-s*z)) = logaddexp(0,-s*z)
        loss = float(np.mean(np.logaddexp(0.0, -s * z)))
        reg = float(w @ w) / (2.0 * C * n)
        prox = (float(mu) / 2.0) * (float(w @ w - 2.0 * w @ w_g + w_g @ w_g)
                                    + (b - b_g) ** 2)
        f = loss + reg + prox
        resid = expit(z) - y               # d mean-logloss / dz = sigmoid(z) - y
        gw = np.asarray(X.T @ resid).ravel() / n + w / (C * n) \
            + float(mu) * (w - w_g)
        gb = float(np.mean(resid)) + float(mu) * (b - b_g)
        return f, np.concatenate([gw, [gb]])

    res = minimize(objective, theta_global.copy(), jac=True,
                   method="L-BFGS-B",
                   options={"maxiter": 2000, "ftol": 1e-12, "gtol": 1e-8})
    return {"theta": res.x, "n_iter": int(res.nit), "converged": bool(res.success),
            "objective": float(res.fun)}


# ---------------------------------------------------------------------------
# FL methods under the strong recipe
# ---------------------------------------------------------------------------
def _theta_of_sklearn(model) -> np.ndarray:
    return _pack(model.coef_, float(model.intercept_[0]))


def _avg_thetas(thetas: list[np.ndarray], ns: list[int]) -> np.ndarray:
    total = float(sum(ns))
    out = np.zeros_like(thetas[0], dtype=float)
    for th, n in zip(thetas, ns):
        out += (float(n) / total) * th
    return out


def fedavg_sklearn(client_X: list, client_y: list, C: float,
                   rounds: int = 2) -> dict:
    """FedAvg under the strong recipe (AMENDMENT-5 A5.2): each client fits the
    registered lbfgs LR on its OWN standardized share, then the server takes
    the n-weighted parameter average. `rounds` re-runs the loop from the
    aggregate; with converged convex local fits the aggregate is a fixed
    point (the history proves it in the outputs)."""
    history = []
    theta_global: Optional[np.ndarray] = None
    fits_meta = []
    for r in range(max(1, int(rounds))):
        thetas, ns = [], []
        fits_meta = []
        for X, y in zip(client_X, client_y):
            fit = fit_lr(X, y, C)
            thetas.append(_theta_of_sklearn(fit["model"]))
            ns.append(len(y))
            fits_meta.append({"n_iter": fit["n_iter"],
                              "converged": fit["converged"]})
        theta_global = _avg_thetas(thetas, ns)
        history.append({"round": r + 1, "theta_l2": float(theta_global @ theta_global)})
    return {"theta": theta_global, "history": history, "local_fits": fits_meta,
            "C": float(C)}


def fedprox_sklearn(client_X: list, client_y: list, C: float, mu: float,
                    rounds: int = 15) -> dict:
    """FedProx (Li et al. 2020) under the strong recipe: per round, each
    client solves the prox-augmented local objective from the broadcast
    global theta (scipy L-BFGS-B), then the server n-weight-averages."""
    d = client_X[0].shape[1]
    theta_global = np.zeros(d + 1, dtype=float)
    history = []
    all_converged = True
    for r in range(max(1, int(rounds))):
        thetas, ns = [], []
        for X, y in zip(client_X, client_y):
            fit = local_fit_fedprox(X, y, C, theta_global, mu)
            thetas.append(fit["theta"])
            ns.append(len(y))
            all_converged = all_converged and fit["converged"]
        theta_global = _avg_thetas(thetas, ns)
        history.append({"round": r + 1,
                        "theta_l2": float(theta_global @ theta_global)})
    return {"theta": theta_global, "history": history, "mu": float(mu),
            "all_local_converged": bool(all_converged), "C": float(C)}


def strong_centralized(Xs_train, y_train, C: float) -> dict:
    """Registered strong centralized baseline (A5.1): converged lbfgs LR on
    the pooled standardized TRAIN."""
    fit = fit_lr(Xs_train, y_train, C)
    theta = _theta_of_sklearn(fit["model"])
    return {"theta": theta, "n_iter": fit["n_iter"], "converged": fit["converged"],
            "C": float(C)}


def per_client_best_sklearn(client_X: list, client_y: list, C: float) -> dict:
    """AMENDMENT-3 oracle-routing per-client models under the strong recipe
    (same local fits as FedAvg round 1, no aggregation)."""
    thetas = []
    fits_meta = []
    for X, y in zip(client_X, client_y):
        fit = fit_lr(X, y, C)
        thetas.append(_theta_of_sklearn(fit["model"]))
        fits_meta.append({"n_iter": fit["n_iter"], "converged": fit["converged"]})
    return {"thetas": thetas, "local_fits": fits_meta, "C": float(C)}


# ---------------------------------------------------------------------------
# P0 cell: one (seed, split, block) — everything at once, shared plumbing
# ---------------------------------------------------------------------------
@dataclass
class P0CellResult:
    seed: int
    split: str
    block: str
    n_train: int
    n_test: int
    C_selected: float
    cv_table: list
    methods: dict                 # method name -> result dict (metrics/probs)
    meta: dict


def run_p0_cell(
    train_records: list[dict],
    test_records: list[dict],
    block: str,
    seed: int,
    split: str,
    text_cache: Optional[dict[str, str]] = None,
    precomputed: Optional[tuple[Any, dict[str, int]]] = None,
    mu_values: Sequence[float] = (),
    fedavg_rounds: int = 2,
    fedprox_rounds: int = 15,
    c_grid: Sequence[float] = C_GRID,
) -> P0CellResult:
    """Run all registered P0 methods for one (seed, split, block) cell with a
    SINGLE shared plumbing: one split, one scaler (pooled TRAIN), one C
    (train-only CV), one client partition (packguard.fl.client_name_of).

    Methods always run: strong_centralized, fedavg, per_client_best.
    FedProx runs once per mu in `mu_values` (AMENDMENT-5 A5.4 sweep; pass ()
    to skip). All metrics use fl.compute_clf_metrics (threshold 0.5)."""
    # --- design matrices (raw) -------------------------------------------
    if block == "hashing_tfidf":
        Xtr_raw = build_design_matrix(train_records, block, text_cache, precomputed)
        Xte_raw = build_design_matrix(test_records, block, text_cache, precomputed)
    else:
        Xtr_raw = build_design_matrix(train_records, block)
        Xte_raw = build_design_matrix(test_records, block)

    # --- ONE scaler fit on pooled TRAIN, shared by clients (disclosed) ----
    sc = fit_scaler(Xtr_raw)
    Xs_train = standardize(sc, Xtr_raw)
    Xs_test = standardize(sc, Xte_raw)
    y_train = np.array([int(r["label"]) for r in train_records], dtype=int)
    y_test = [int(r["label"]) for r in test_records]

    # --- C on TRAIN only ---------------------------------------------------
    cv = select_c_cv(Xs_train, y_train, seed=seed, c_grid=c_grid)
    C = cv["C_selected"]

    # --- client partition (indices into train) -----------------------------
    part: dict[str, list[int]] = {}
    for i, r in enumerate(train_records):
        part.setdefault(client_name_of(r, "ecosystem"), []).append(i)
    client_names = sorted(part)
    client_X = [Xs_train[part[cn]] for cn in client_names]
    client_y = [y_train[part[cn]] for cn in client_names]
    client_sizes = {cn: int(len(part[cn])) for cn in client_names}

    methods: dict[str, Any] = {}

    # (a) strong centralized ------------------------------------------------
    cent = strong_centralized(Xs_train, y_train, C)
    methods["strong_centralized"] = {
        "final_metrics": compute_clf_metrics(y_test, probs_from_theta(
            cent["theta"], Xs_test)),
        "n_iter": cent["n_iter"], "converged": cent["converged"],
    }

    # (b) FedAvg (local fit + n-weighted average) ---------------------------
    avg = fedavg_sklearn(client_X, client_y, C, rounds=fedavg_rounds)
    methods["fedavg"] = {
        "final_metrics": compute_clf_metrics(y_test, probs_from_theta(
            avg["theta"], Xs_test)),
        "history": avg["history"], "local_fits": avg["local_fits"],
        "fixed_point_from_round_2": bool(
            fedavg_rounds >= 2
            and abs(avg["history"][-1]["theta_l2"]
                    - avg["history"][0]["theta_l2"]) < 1e-12),
    }

    # (c) FedProx mu sweep (optional) ----------------------------------------
    for mu in mu_values:
        px = fedprox_sklearn(client_X, client_y, C, float(mu),
                             rounds=fedprox_rounds)
        methods[f"fedprox_mu{mu:g}"] = {
            "final_metrics": compute_clf_metrics(y_test, probs_from_theta(
                px["theta"], Xs_test)),
            "history_tail": px["history"][-3:],
            "all_local_converged": px["all_local_converged"],
        }

    # (d) per-client-best (oracle routing, AMENDMENT-3 definition) -----------
    pcb = per_client_best_sklearn(client_X, client_y, C)
    routed = np.zeros(len(test_records), dtype=float)
    test_client_names = [client_name_of(r, "ecosystem") for r in test_records]
    covered = np.zeros(len(test_records), dtype=bool)
    per_client_metrics = {}
    for j, cn in enumerate(client_names):
        probs_cn = probs_from_theta(pcb["thetas"][j], Xs_test)
        per_client_metrics[cn] = compute_clf_metrics(y_test, probs_cn)
        for i, tcn in enumerate(test_client_names):
            if tcn == cn:
                routed[i] = probs_cn[i]
                covered[i] = True
    methods["per_client_best"] = {
        "final_metrics": compute_clf_metrics(y_test, routed),
        "n_uncovered": int((~covered).sum()),
        "per_client_global": per_client_metrics,
    }

    return P0CellResult(
        seed=int(seed), split=str(split), block=str(block),
        n_train=len(train_records), n_test=len(test_records),
        C_selected=float(C), cv_table=cv["cv_table"],
        methods=methods,
        meta={
            "client_names": client_names, "client_sizes": client_sizes,
            "scaler": ("StandardScaler(with_mean=False) on pooled TRAIN "
                       if hasattr(Xtr_raw, "tocsr")
                       else "StandardScaler on pooled TRAIN"),
            "cv_protocol": cv["selection"],
            "fedavg_rounds": int(fedavg_rounds),
            "fedprox_rounds": int(fedprox_rounds),
            "mu_values": [float(m) for m in mu_values],
        },
    )
