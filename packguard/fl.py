"""Federated-learning simulation for PackGuard (PACKGUARD_BRIEF §4).

Client = ecosystem partition (npm-only / pypi-only / mixed) => naturally
non-IID. Round-based FedAvg and FedProx (proximal mu from config) over LR /
1-hidden-layer MLP models (packguard/models.py).

Two trust mechanisms are SIMULATIONS and are labelled as such everywhere:
  * Secure aggregation: pairwise additive masking. Client i shares a seed with
    every j != i; the derived mask enters client i's upload with +sign for
    j > i and -sign for j < i, so the masks cancel EXACTLY at the server
    (unit test asserts the summed mask is 0 bitwise). Nothing cryptographic is
    claimed — this models the arithmetic of secure aggregation only.
  * Differential privacy: Gaussian noise with per-round analytic epsilon
    eps = sensitivity * sqrt(2 ln(1.25 / delta)) / sigma for the single
    aggregated query per round (single-query bound, NOT a formal composition
    proof; disclosed in every result meta as dp_epsilon_per_round).

Evaluation: per-round precision/recall/F1/AUC on a GLOBAL held-out test set
that is split off before client partitioning (no sample leakage; asserted).
Baselines: centralized (all client data pooled) and per-client-only.

Synthetic fixture mode (W1 data pending): `synthetic_fixture` produces a
mock feature dataset; EVERY result row produced from it carries
meta["mock"] = True so mock numbers can never be confused with real ones
(PROJECT_BRIEF §6.1 / V2 lesson: mock-vs-real hygiene).
"""
from __future__ import annotations

import gzip
import hashlib
import json
import math
import random
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional, Sequence

import numpy as np
import torch

from packguard.models import (
    DEFAULT_SEED,
    build_model,
    clone_params,
    local_train,
    params_to_cpu_list,
    predict_proba,
    set_seed,
)

__all__ = [
    "FLConfig",
    "FedClient",
    "synthetic_fixture",
    "make_global_test_split",
    "make_group_split",
    "build_clients",
    "pairwise_mask",
    "client_upload_mask",
    "fedavg_weighted",
    "secure_aggregate",
    "clip_update_l2",
    "add_dp_noise",
    "gaussian_epsilon",
    "compute_clf_metrics",
    "run_federated",
    "run_centralized",
    "run_per_client",
    "config_sha16",
    "load_feature_records",
]

PROJECT_ROOT = Path(__file__).resolve().parents[1]

ECOSYSTEMS = ("npm_only", "pypi_only", "mixed")


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
@dataclass
class FLConfig:
    input_dim: int
    model_type: str = "lr"           # "lr" | "mlp"
    hidden_dim: int = 32
    rounds: int = 15
    local_epochs: int = 2
    lr: float = 0.1
    batch_size: int = 32
    mu: float = 0.0                  # FedProx proximal coefficient
    test_fraction: float = 0.2       # global held-out fraction
    seed: int = DEFAULT_SEED
    secure_agg_enabled: bool = True  # pairwise-mask SIMULATION
    dp_enabled: bool = False
    dp_sigma: float = 0.01
    dp_delta: float = 1e-5
    dp_clip: float = 1.0             # per-client update L2 clip (DP-FedAvg)
    feature_block: str = "graph"     # which named feature block to vectorize
    extra_meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, cfg: dict, input_dim: int) -> "FLConfig":
        known = {k: v for k, v in (cfg or {}).items() if k in cls.__dataclass_fields__}
        known.pop("input_dim", None)
        return cls(input_dim=input_dim, **known)


def config_sha16(obj: Any) -> str:
    """Stable 16-hex sha256 of a JSON-serializable config (provenance)."""
    blob = json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Data: loading, synthetic fixture, splitting, partitioning
# ---------------------------------------------------------------------------
def _numeric_tag_key(p: Path) -> int:
    m = re.search(r"_v(\d+)\.(jsonl|parquet)$", p.name)
    return int(m.group(1)) if m else -1


def _discover_feature_files(features_dir: str | Path,
                            tag: Optional[str] = None
                            ) -> tuple[Optional[Path], Optional[Path]]:
    """Find (features_jsonl, graphs_gz) — explicit tag first, else the HIGHEST
    features_v*.jsonl tag, else legacy features.jsonl. (V2-issue fix: the old
    loader only accepted the exact names features.jsonl|features.parquet.)"""
    fdir = Path(features_dir)
    if tag:
        jl = fdir / f"features_{tag}.jsonl"
        if jl.exists():
            gz = fdir / f"graphs_{tag}.jsonl.gz"
            return jl, (gz if gz.exists() else None)
    vfiles = sorted(fdir.glob("features_v*.jsonl"), key=_numeric_tag_key)
    if vfiles:
        jl = vfiles[-1]
        m = re.search(r"features_(v\d+)\.jsonl$", jl.name)
        gz = fdir / f"graphs_{m.group(1)}.jsonl.gz" if m else None
        return jl, (gz if gz and gz.exists() else None)
    jl = fdir / "features.jsonl"
    if jl.exists():
        return jl, None
    return None, None


def _load_graph_apis(gz_path: Optional[str | Path]) -> dict[str, list[str]]:
    """sample_id -> sorted unique API names from the merged behavior graph
    (V2-issue fix: features_* rows carry no api_calls; derive them from the
    graphs_v*.jsonl.gz so the KB ablation can run on real data)."""
    if gz_path is None:
        return {}
    apis: dict[str, set] = {}
    with gzip.open(gz_path, "rt", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            g = json.loads(line)
            sid = g.get("sample_id")
            if not sid:
                continue
            names = {str(n.get("api")).strip() for n in g.get("nodes", [])
                     if n.get("api")}
            apis[sid] = names
    return {sid: sorted(a) for sid, a in apis.items()}


def load_feature_records(features_dir: str | Path,
                         tag: Optional[str] = None) -> tuple[list[dict], dict]:
    """Read PackGuard feature output (features_v*.jsonl, legacy
    features.jsonl, or features*.parquet fallback).

    Accepts BOTH schemas:
      * nested (eval contract): {sample_id, ecosystem, label, features:{block:{...}}}
      * flat (W1 features_v2): 18 numeric feature columns at the top level next
        to sample_id/ecosystem/label/label_source/package — wrapped here into
        {"features": {"graph": {name: value}}} (V2-issue fix: the old loader
        raised FileNotFoundError on features_v1/v2.* and could not read the
        flat schema at all).
    Rows carrying extraction_error are DROPPED and counted in the meta (never
    silently trained on). api_calls are attached from the matching
    graphs_v*.jsonl.gz when present.
    """
    from packguard.features import FEATURE_NAMES

    fdir = Path(features_dir)
    jl, gz = _discover_feature_files(fdir, tag)
    pq = None
    if jl is None:
        cands = sorted(fdir.glob("features*.parquet"), key=_numeric_tag_key)
        pq = cands[-1] if cands else (fdir / "features.parquet"
                                      if (fdir / "features.parquet").exists() else None)
    if jl is None and pq is None:
        raise FileNotFoundError(
            f"W1 feature output not found under {fdir} "
            "(features*.jsonl|features*.parquet). Real-data run must WAIT for "
            "W1; pass --synthetic for the clearly-flagged mock fixture."
        )

    if jl is not None:
        raw_rows: list[dict] = []
        with jl.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    raw_rows.append(json.loads(line))
        source = str(jl)
    else:
        import pandas as pd
        raw_rows = pd.read_parquet(pq).to_dict(orient="records")
        source = str(pq)

    graph_apis = _load_graph_apis(gz)
    non_feature_cols = set(FEATURE_NAMES) | {
        "sample_id", "ecosystem", "label", "label_source", "package",
        "extraction_error", "mock", "layout", "version",
    }
    records: list[dict] = []
    n_error_rows = 0
    n_api_attached = 0
    for r in raw_rows:
        if r.get("extraction_error"):
            n_error_rows += 1
            continue  # disclosed drop, never trained on
        if "features" in r and isinstance(r["features"], dict):
            rec = dict(r)  # already nested (synthetic fixture / v2 nested)
        else:
            feats = {k: float(r[k]) for k in FEATURE_NAMES if k in r}
            rec = {k: v for k, v in r.items() if k not in set(FEATURE_NAMES)}
            rec["features"] = {"graph": feats}
        if rec.get("api_calls") is None and rec.get("mock") is not True:
            apis = graph_apis.get(rec.get("sample_id"))
            if apis is not None:
                rec["api_calls"] = apis
                n_api_attached += 1
        records.append(rec)
    meta = {
        "source": source,
        "mock": False,
        "graphs_source": str(gz) if gz else None,
        "n_rows_dropped_extraction_error": n_error_rows,
        "n_rows_with_api_calls": n_api_attached,
    }
    return records, meta


def synthetic_fixture(
    n_per_ecosystem: int = 120,
    seed: int = DEFAULT_SEED,
    input_dim: int = 8,
    tfidf_dim: int = 8,
) -> tuple[list[dict], dict]:
    """Mock feature dataset with NATURALLY NON-IID ecosystem partitions.

    Label skew by ecosystem: npm_only ~85% malicious, pypi_only ~15%,
    mixed ~50%. Features: `graph` block carries a class-separable signal
    (informative dims shifted by label) plus an ecosystem offset (so the
    partitions genuinely differ in P(x)); the `tfidf` block carries a much
    weaker, noisier signal (for the graph-vs-code-as-text ablation path).
    api_calls are drawn from a mix of seed-KB APIs and unknown ones.
    Every record carries mock=True; the returned meta is prepended to all
    result rows derived from this fixture.
    """
    rng = random.Random(seed)
    rng_np = np.random.default_rng(seed)
    skew = {"npm_only": 0.85, "pypi_only": 0.15, "mixed": 0.50}
    ecos_offset = {"npm_only": 0.5, "pypi_only": -0.5, "mixed": 0.0}
    api_pool_known = [
        "child_process.exec", "fs.writeFile", "https.request", "hashlib.md5",
        "eval", "subprocess.Popen", "os.system", "socket.socket",
    ]
    api_pool_unknown = [
        "fs.readdirRecursive", "process.envDump", "wasm.instantiateRemote",
        "keytar.getPasswordBulk", "registry.autorun.persist", "curl.execAsync",
    ]
    records: list[dict] = []
    for eco in ECOSYSTEMS:
        for i in range(int(n_per_ecosystem)):
            label = 1 if rng.random() < skew[eco] else 0
            g = rng_np.normal(0.0, 1.0, size=int(input_dim))
            # informative dims: shift by label (separable) + ecosystem offset
            g[: input_dim // 2] += (1.4 * label - 0.7) + ecos_offset[eco]
            t = rng_np.normal(0.0, 1.0, size=int(tfidf_dim))
            t[0] += 0.35 * (label - 0.5)  # weak signal only
            n_api = rng.randint(2, 4)
            api_calls = [rng.choice(api_pool_known if rng.random() < 0.6
                                    else api_pool_unknown) for _ in range(n_api)]
            records.append({
                "sample_id": f"synth-{eco}-{i:04d}",
                "ecosystem": eco,
                "label": label,
                "features": {
                    "graph": {f"graph_{j}": round(float(v), 6) for j, v in enumerate(g)},
                    "tfidf": {f"tfidf_{j}": round(float(v), 6) for j, v in enumerate(t)},
                },
                "api_calls": api_calls,
                "mock": True,
            })
    meta = {
        "mock": True,
        "fixture": "packguard.fl.synthetic_fixture",
        "n_per_ecosystem": int(n_per_ecosystem),
        "label_skew_by_ecosystem": skew,
        "seed": int(seed),
        "note": (
            "SYNTHETIC fixture (W1 real features pending). All numbers derived "
            "from it are mock and must never be reported as real results."
        ),
    }
    return records, meta


def _vectorize(record: dict, block: str) -> list[float]:
    feats = record.get("features", {})
    if block not in feats:
        raise KeyError(
            f"feature block {block!r} missing in record {record.get('sample_id')!r} "
            f"(available: {sorted(feats)})"
        )
    names = sorted(feats[block])
    return [float(feats[block][n]) for n in names]


def make_global_test_split(
    records: list[dict], test_fraction: float, seed: int = DEFAULT_SEED
) -> tuple[list[dict], list[dict]]:
    """Stratified GLOBAL held-out split (drawn BEFORE client partitioning)."""
    rng = random.Random(seed)
    by_label: dict[int, list[dict]] = {0: [], 1: []}
    for r in records:
        by_label[int(r["label"])].append(r)
    test: list[dict] = []
    for label in (0, 1):
        pool = sorted(by_label[label], key=lambda r: r["sample_id"])
        rng.shuffle(pool)
        k = max(1, int(round(len(pool) * float(test_fraction))))
        test.extend(pool[:k])
    test_ids = {r["sample_id"] for r in test}
    train = [r for r in records if r["sample_id"] not in test_ids]
    assert not (test_ids & {r["sample_id"] for r in train}), "split leakage"
    return train, test


def make_group_split(
    records: list[dict], test_fraction: float, seed: int = DEFAULT_SEED,
    group_key: str = "package",
) -> tuple[list[dict], list[dict]]:
    """PRIMARY split (round-8 AMENDMENT-1): package-family group split.

    All samples of one package land in exactly one side, killing the
    version-level near-duplicate train<->test leakage that V2 quantified at
    35% of test rows under the random split. Label-STRATIFIED at the package
    level; the realized test share (group sizes differ) is reported by the
    caller, never silently assumed to equal test_fraction.
    """
    groups: dict[tuple[int, str], list[dict]] = {}
    for r in records:
        key = (int(r["label"]), str(r.get(group_key) or r["sample_id"]))
        groups.setdefault(key, []).append(r)
    rng = random.Random(seed)
    test: list[dict] = []
    for label in (0, 1):
        pkgs = sorted(pkg for lab, pkg in groups if lab == label)
        rng.shuffle(pkgs)
        k = max(1, int(round(len(pkgs) * float(test_fraction))))
        for pkg in pkgs[:k]:
            test.extend(groups[(label, pkg)])
    test_ids = {r["sample_id"] for r in test}
    train = [r for r in records if r["sample_id"] not in test_ids]
    assert not (test_ids & {r["sample_id"] for r in train}), "split leakage"
    # group-level disjointness (the actual guarantee)
    tr_pkgs = {str(r.get(group_key) or r["sample_id"]) for r in train}
    te_pkgs = {str(r.get(group_key) or r["sample_id"]) for r in test}
    assert not (tr_pkgs & te_pkgs), "package-group leakage between train and test"
    return train, test


def build_clients(train_records: list[dict], feature_block: str = "graph") -> list["FedClient"]:
    """Client = ecosystem partition (npm_only / pypi_only / mixed)."""
    groups: dict[str, list[dict]] = {}
    for r in train_records:
        groups.setdefault(str(r.get("ecosystem", "mixed")), []).append(r)
    clients = [
        FedClient(name=eco, records=recs, feature_block=feature_block)
        for eco, recs in sorted(groups.items())
    ]
    if len(clients) < 2:
        raise ValueError(
            f"need >=2 ecosystem clients for FL, got {len(clients)}: {sorted(groups)}"
        )
    return clients


def client_label_distribution(clients: Sequence["FedClient"]) -> dict[str, dict]:
    """Per-client class stats — used to ASSERT the partition is non-IID."""
    out = {}
    for c in clients:
        ys = c.y.numpy().astype(int)
        out[c.name] = {
            "n": int(len(ys)),
            "malicious_rate": float(ys.mean()) if len(ys) else float("nan"),
        }
    return out


# ---------------------------------------------------------------------------
# FedClient
# ---------------------------------------------------------------------------
class FedClient:
    """One ecosystem-partition client holding its local tensors."""

    def __init__(self, name: str, records: list[dict], feature_block: str = "graph"):
        self.name = name
        self.records = records
        self.feature_block = feature_block
        X = np.array([_vectorize(r, feature_block) for r in records], dtype=np.float32)
        y = np.array([int(r["label"]) for r in records], dtype=np.float32)
        self.X = torch.from_numpy(X)
        self.y = torch.from_numpy(y)

    @property
    def n_samples(self) -> int:
        return int(self.X.shape[0])

    @property
    def input_dim(self) -> int:
        return int(self.X.shape[1])

    def local_update(
        self,
        global_params: Sequence[torch.Tensor],
        cfg: FLConfig,
        round_idx: int,
        seed: int = DEFAULT_SEED,
    ) -> tuple[list[torch.Tensor], int]:
        """Train locally from the broadcast global weights; return (params, n)."""
        model = build_model(
            {"type": cfg.model_type, "hidden_dim": cfg.hidden_dim}, self.input_dim
        )
        with torch.no_grad():
            for p, g in zip(model.parameters(), global_params):
                p.copy_(g.to(p.dtype))
        # per-(round) stable seed, identical for every client: clients with
        # IDENTICAL data then produce IDENTICAL updates (midpoint property
        # unit-tested). zlib.crc32, NOT hash() (salted per process).
        local_seed = (int(seed) + 7919 * int(round_idx)) % (2**31)
        local_train(
            model, self.X, self.y,
            epochs=cfg.local_epochs, lr=cfg.lr, batch_size=cfg.batch_size,
            global_params=[g.to(self.X.dtype) for g in global_params],
            mu=cfg.mu, seed=local_seed,
        )
        return params_to_cpu_list(model.state_dict()), self.n_samples


# ---------------------------------------------------------------------------
# Secure-aggregation SIMULATION: pairwise additive masks
# ---------------------------------------------------------------------------
def _pair_seed(i: int, j: int, base_seed: int) -> int:
    lo, hi = min(i, j), max(i, j)
    return (int(base_seed) * 1_000_003 + lo * 8191 + hi) % (2**31)


def pairwise_mask(i: int, j: int, shapes: Sequence[Sequence[int]],
                  base_seed: int = DEFAULT_SEED) -> list[torch.Tensor]:
    """Mask shared by clients i and j — SAME tensor for both (deterministic
    from the pair seed), so +mask (client with smaller index) and -mask
    (larger index) cancel BITWISE at the server."""
    g = torch.Generator().manual_seed(_pair_seed(i, j, base_seed))
    return [torch.randn(tuple(s), generator=g) for s in shapes]


def client_upload_mask(i: int, n_clients: int, shapes: Sequence[Sequence[int]],
                       base_seed: int = DEFAULT_SEED) -> list[torch.Tensor]:
    """Mask client i adds to its upload: +M_ij for j>i, -M_ij for j<i."""
    total = [torch.zeros(tuple(s)) for s in shapes]
    for j in range(n_clients):
        if j == i:
            continue
        m = pairwise_mask(i, j, shapes, base_seed)
        sign = 1.0 if j > i else -1.0
        for t, mj in zip(total, m):
            t += sign * mj
    return total


def fedavg_weighted(param_lists: Sequence[Sequence[torch.Tensor]],
                    weights: Sequence[int]) -> list[torch.Tensor]:
    """FedAvg: parameter-wise weighted mean (weight = client n_samples)."""
    total = float(sum(weights))
    if total <= 0:
        raise ValueError("FedAvg requires positive total sample weight")
    agg = [torch.zeros(tuple(p.shape), dtype=torch.float32) for p in param_lists[0]]
    for params, w in zip(param_lists, weights):
        for a, p in zip(agg, params):
            a += float(w) * p.to(torch.float32)
    return [a / total for a in agg]


def secure_aggregate(param_lists, weights, masks) -> tuple[list[torch.Tensor], float]:
    """Server side of the SIMULATION in the weighted-sum domain: each client's
    masked upload is (w_i * p_i + m_i); the server sums uploads, subtracts the
    summed mask (which cancels: sum_i m_i == 0), then divides by the total
    weight. Returns (aggregate, max_abs_mask_residual) where the residual is
    the elementwise-max of |sum_i m_i| — 0 up to float32 accumulation order
    (bitwise 0 for two clients; unit-tested)."""
    total = float(sum(weights))
    masked_sums = [torch.zeros(tuple(p.shape), dtype=torch.float32)
                   for p in param_lists[0]]
    for (params, mask), w in zip(zip(param_lists, masks), weights):
        for s, p, m in zip(masked_sums, params, mask):
            s += float(w) * p.to(torch.float32) + m
    mask_sum = [torch.zeros_like(m) for m in masks[0]]
    for mask in masks:
        for s, m in zip(mask_sum, mask):
            s += m
    residual = max(float(s.abs().max()) for s in mask_sum) if mask_sum else 0.0
    agg = [(s - ms) / total for s, ms in zip(masked_sums, mask_sum)]
    return agg, residual


# ---------------------------------------------------------------------------
# DP SIMULATION
# ---------------------------------------------------------------------------
def clip_update_l2(update: Sequence[torch.Tensor], clip: float
                   ) -> tuple[list[torch.Tensor], float]:
    """L2-clip a client update (params - global) to norm `clip` (DP-FedAvg)."""
    sq = float(sum((u.to(torch.float32) ** 2).sum() for u in update))
    norm = math.sqrt(max(sq, 0.0))
    if norm <= clip or norm == 0.0:
        return [u.to(torch.float32) for u in update], norm
    scale = clip / norm
    return [(u.to(torch.float32) * scale) for u in update], norm


def add_dp_noise(avg_update: Sequence[torch.Tensor], sigma: float, seed: int
                 ) -> list[torch.Tensor]:
    """Gaussian noise N(0, sigma^2) on the aggregated update (seeded)."""
    g = torch.Generator().manual_seed(int(seed))
    return [u + sigma * torch.randn(u.shape, generator=g) for u in avg_update]


def gaussian_epsilon(sigma: float, delta: float = 1e-5, sensitivity: float = 1.0) -> float:
    """Analytic single-query Gaussian-mechanism bound:
    eps = sensitivity * sqrt(2 ln(1.25 / delta)) / sigma.

    DISCLOSURE: this is the per-round bound for ONE aggregated query; running
    R rounds is NOT covered by a composition proof here — the simulation
    reports eps*R as a conservative upper reference only.
    """
    if sigma <= 0:
        raise ValueError("sigma must be > 0")
    return float(sensitivity * math.sqrt(2.0 * math.log(1.25 / float(delta))) / float(sigma))


# ---------------------------------------------------------------------------
# Metrics + runners
# ---------------------------------------------------------------------------
def compute_clf_metrics(y_true: Sequence[int], probs: Sequence[float],
                        threshold: float = 0.5) -> dict:
    """P/R/F1 (malicious = positive) + AUC on the GLOBAL test set."""
    from sklearn import metrics as skm

    y = np.asarray(y_true, dtype=int)
    p = np.asarray(probs, dtype=float)
    pred = (p >= threshold).astype(int)
    auc: Optional[float]
    if len(np.unique(y)) < 2:
        auc = None  # undefined; reported as null (never fabricated)
    else:
        auc = float(skm.roc_auc_score(y, p))
    return {
        "n": int(len(y)),
        "precision": float(skm.precision_score(y, pred, zero_division=0)),
        "recall": float(skm.recall_score(y, pred, zero_division=0)),
        "f1": float(skm.f1_score(y, pred, zero_division=0)),
        "auc": auc,
        "threshold": float(threshold),
        "n_test_malicious": int(y.sum()),
    }


def _eval_state(global_params: Sequence[torch.Tensor], test_client: "FedClient",
                cfg: FLConfig) -> tuple[dict, np.ndarray]:
    model = build_model({"type": cfg.model_type, "hidden_dim": cfg.hidden_dim},
                        test_client.input_dim)
    with torch.no_grad():
        for p, g in zip(model.parameters(), global_params):
            p.copy_(g.to(p.dtype))
    probs = predict_proba(model, test_client.X)
    return compute_clf_metrics(test_client.y.numpy().astype(int), probs), probs


def _model_params(input_dim: int, cfg: FLConfig, seed: int) -> list[torch.Tensor]:
    set_seed(seed)
    model = build_model({"type": cfg.model_type, "hidden_dim": cfg.hidden_dim}, input_dim)
    return params_to_cpu_list(model.state_dict())


def run_federated(clients: Sequence[FedClient], test: FedClient, cfg: FLConfig,
                  algo: str = "fedavg", seed: int = DEFAULT_SEED) -> dict:
    """Round-based FedAvg (mu=0) or FedProx (mu>0) with the trust-mechanism
    simulations toggled by cfg. Returns history + final metrics + meta."""
    if algo not in ("fedavg", "fedprox"):
        raise ValueError(f"unknown algo {algo!r}")
    mu = 0.0 if algo == "fedavg" else float(cfg.mu)
    input_dim = test.input_dim
    global_params = _model_params(input_dim, cfg, seed)
    history: list[dict] = []
    dp_eps_per_round = (
        gaussian_epsilon(cfg.dp_sigma, cfg.dp_delta, sensitivity=float(cfg.dp_clip))
        if cfg.dp_enabled else None
    )
    shapes = [tuple(t.shape) for t in global_params]
    last_residual: Optional[float] = None
    for r in range(int(cfg.rounds)):
        updates = [c.local_update(global_params, cfg, round_idx=r, seed=seed)
                   for c in clients]
        params = [u[0] for u in updates]
        ns = [u[1] for u in updates]
        if cfg.dp_enabled:
            clipped = [clip_update_l2(
                [p - g for p, g in zip(pl, global_params)], cfg.dp_clip)[0]
                for pl in params]
            base = [p + g for p, g in zip(
                fedavg_weighted(clipped, ns),
                [g.to(torch.float32) for g in global_params])]
            noise_seed = (int(seed) + 104729 * (r + 1)) % (2**31)
            avg_update = add_dp_noise(
                [b - g for b, g in zip(base, global_params)], cfg.dp_sigma, noise_seed)
            global_params = [g + u for g, u in zip(global_params, avg_update)]
        elif cfg.secure_agg_enabled:
            masks = [client_upload_mask(i, len(clients), shapes, base_seed=seed)
                     for i in range(len(clients))]
            global_params, last_residual = secure_aggregate(params, ns, masks)
        else:
            global_params = fedavg_weighted(params, ns)
        m, _probs = _eval_state(global_params, test, cfg)
        history.append({"round": r + 1, **m})
    final, final_probs = _eval_state(global_params, test, cfg)
    return {
        "algo": algo,
        "history": history,
        "final_metrics": final,
        "final_probs": [round(float(p), 6) for p in final_probs],
        "secure_agg_mask_residual": last_residual,
        "dp_enabled": bool(cfg.dp_enabled),
        "dp_sigma": float(cfg.dp_sigma) if cfg.dp_enabled else None,
        "dp_epsilon_per_round": dp_eps_per_round,
        "mu": mu,
        "n_clients": len(clients),
        "client_names": [c.name for c in clients],
    }


def run_centralized(clients: Sequence[FedClient], test: FedClient, cfg: FLConfig,
                    seed: int = DEFAULT_SEED) -> dict:
    """Baseline: pool all client train data, train once (rounds*local_epochs
    full passes — disclosed equivalence), eval on the SAME global test set."""
    X = torch.cat([c.X for c in clients])
    y = torch.cat([c.y for c in clients])
    set_seed(seed)
    model = build_model({"type": cfg.model_type, "hidden_dim": cfg.hidden_dim},
                        test.input_dim)
    local_train(model, X, y, epochs=int(cfg.rounds) * int(cfg.local_epochs),
                lr=cfg.lr, batch_size=cfg.batch_size, seed=seed)
    probs = predict_proba(model, test.X)
    metrics = compute_clf_metrics(test.y.numpy().astype(int), probs)
    return {"algo": "centralized", "final_metrics": metrics,
            "final_probs": [round(float(p), 6) for p in probs]}


def run_per_client(clients: Sequence[FedClient], test: FedClient, cfg: FLConfig,
                   seed: int = DEFAULT_SEED) -> dict:
    """Baseline: each client trains alone; every model is evaluated on the
    SAME global test set; macro-mean over clients is reported."""
    per = []
    for c in clients:
        set_seed(seed)
        model = build_model({"type": cfg.model_type, "hidden_dim": cfg.hidden_dim},
                            c.input_dim)
        local_train(model, c.X, c.y, epochs=int(cfg.rounds) * int(cfg.local_epochs),
                    lr=cfg.lr, batch_size=cfg.batch_size, seed=seed)
        probs = predict_proba(model, test.X)
        per.append({"client": c.name,
                    **compute_clf_metrics(test.y.numpy().astype(int), probs)})
    f1s = [p["f1"] for p in per if p["f1"] is not None]
    aucs = [p["auc"] for p in per if p.get("auc") is not None]
    return {"algo": "per_client_only", "per_client": per,
            "final_metrics": {
                "f1_macro": float(np.mean(f1s)) if f1s else None,
                "auc_macro": float(np.mean(aucs)) if aucs else None,
                "n_clients": len(clients),
            }}


def paired_correctness(probs_a: Sequence[float], probs_b: Sequence[float],
                       y_true: Sequence[int], threshold: float = 0.5
                       ) -> tuple[list[bool], list[bool]]:
    """Per-sample correctness booleans for McNemar (stats.mcnemar contract)."""
    a = [(pa >= threshold) == bool(t) for pa, t in zip(probs_a, y_true)]
    b = [(pb >= threshold) == bool(t) for pb, t in zip(probs_b, y_true)]
    return a, b
