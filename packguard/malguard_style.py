"""MalGuard/Amalfi-STYLE feature baseline for PackGuard (round 15, AMENDMENT-8).

Reimplements a MalGuard/Amalfi-style static feature set on the SAME 603-sample
corpus and the SAME split protocol as the project's graph features, to answer
reviewer question W5: "where does a MalGuard-style feature set land against
our graph features on the same splits?".

Disclosed reimplementation differences (AMENDMENT-8 preamble):
  * MalGuard triages packages with a commercial LLM API; here the project's
    own KB (kb_v0002.jsonl, the "KB-v3" 100%-coverage state: 142 entries,
    unsure=0, join coverage 1.0 over the 137-API corpus universe) is a PURE
    DICT JOIN. No LLM is invoked anywhere in this module.
  * Features derive ONLY from existing artifacts: graphs_v2.jsonl.gz,
    text_v2.json and the KB. No archive is re-parsed; no tree-sitter run.

Label-blindness: `extract_sample_features(graph, text, kb)` receives NO label
input and never reads one; labels are attached only later by the run harness.
The frozen feature list (41 names, MALGUARD_FEATURE_NAMES) and the two frozen
selection lists (TOP10_APIS, TOP10_PAIRS) are registered in
docs/packguard_prereg.md AMENDMENT-8 (2026-09-27T22:44:07Z, before any run);
the selection lists were computed unsupervised (label-blind) on the whole
corpus BEFORE registration (AMENDMENT-7 precedent, disclosed there).

Training protocol: the round-11 strong recipe (packguard.strong_baseline,
A5.1/A5.2) applied to arbitrary blocks: sklearn LogisticRegression lbfgs
max_iter=5000 tol=1e-6, StandardScaler fit on pooled TRAIN only, C in
{0.01,0.1,1,10} by 3-fold stratified TRAIN-only CV, FedAvg = converged local
lbfgs fits + n-weighted average (rounds=2). Splits: make_group_split (primary)
and the AMENDMENT-7 leave-cluster-out split at threshold 0.30 (secondary).
"""
from __future__ import annotations

import gzip
import json
import math
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[1]

GRAPHS_PATH = PROJECT_ROOT / "outputs/packguard/features/graphs_v2.jsonl.gz"
TEXT_PATH = PROJECT_ROOT / "outputs/packguard/features/text_v2.json"
KB_DIR = PROJECT_ROOT / "outputs/packguard/kb"
OUT_DIR = PROJECT_ROOT / "outputs/packguard/malguard_style"
CONFIG_PATH = PROJECT_ROOT / "configs/packguard_malguard.yaml"

# ---------------------------------------------------------------------------
# Frozen selections (AMENDMENT-8 A8.1 — computed label-blind BEFORE
# registration; never re-selected)
# ---------------------------------------------------------------------------
TOP10_APIS: Tuple[str, ...] = (
    "child_process.exec", "eval", "os.system", "subprocess.Popen",
    "subprocess.run",          # all KB risk_level == "high" present in corpus
    "require", "child_process", "exec", "os.environ", "https.request",
    # top-5 medium by corpus document frequency (fill to 10)
)
TOP10_PAIRS: Tuple[Tuple[str, str], ...] = (
    ("DYNAMIC_CODE", "PROCESS"),      # 216
    ("DYNAMIC_CODE", "FILE_IO"),      # 176
    ("FILE_IO", "PROCESS"),           # 158
    ("DATA_ACCESS", "DYNAMIC_CODE"),  # 149 (tie -> alphabetical)
    ("DYNAMIC_CODE", "NETWORK"),      # 149
    ("DATA_ACCESS", "PROCESS"),       # 138
    ("DATA_ACCESS", "FILE_IO"),       # 117
    ("CRYPTO", "DYNAMIC_CODE"),       # 101
    ("NETWORK", "PROCESS"),           # 89
    ("FILE_IO", "NETWORK"),           # 87
)

SHELL_TOKENS: Tuple[str, ...] = ("curl", "wget", "powershell", "/bin/sh", "chmod")

ENTRY_KINDS = ("setup", "postinstall")

_RE_FUNCTION_PY = re.compile(r"\bdef\s+\w+")
_RE_FUNCTION_JS = re.compile(r"\bfunction\b")
_RE_STRING_LIT = re.compile(r"'[^'\n]*'|\"[^\"\n]*\"|`[^`]*`")
_RE_BASE64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_RE_URL = re.compile(r"https?://")
_RE_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_RE_EVAL_EXEC = re.compile(r"\b(eval|exec)\s*\(")
_RE_HEX = re.compile(r"\b[0-9a-fA-F]{16,}\b")

_CLASSES = ("FILE_IO", "NETWORK", "PROCESS", "CRYPTO", "DYNAMIC_CODE",
            "DATA_ACCESS")

MALGUARD_FEATURE_NAMES: Tuple[str, ...] = (
    tuple(f"ratio_{c.lower()}_of_api" for c in _CLASSES)
    + ("kb_high_api_ratio", "kb_conf_mean")
    + tuple(f"ind_api_{a.replace('.', '__')}" for a in TOP10_APIS)
    + tuple(f"pair_{a}__{b}" for a, b in TOP10_PAIRS)
    + ("entry_api_share", "entry_api_count")
    + ("n_dirs", "text_n_functions", "text_string_literal_count",
       "text_max_string_len", "text_base64_like_count",
       "text_url_ip_literal_count", "text_shell_indicator_count",
       "text_eval_exec_count", "text_long_string_ratio", "text_hex_entropy",
       "text_avg_line_len")
)
assert len(MALGUARD_FEATURE_NAMES) == 41

GRAPH_FEATURE_NAMES = 18  # frozen v2 block (packguard.features.FEATURE_NAMES)

BLOCKS = ("malguard", "combined", "graph", "hashing_tfidf")
METHODS = ("strong_centralized", "fedavg")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _shannon_entropy(chars: Sequence[str]) -> float:
    """Shannon entropy (bits) of the character distribution."""
    n = len(chars)
    if n == 0:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in chars:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _n_dirs_of(paths: Sequence[str]) -> float:
    """Distinct parent directories after the deterministic tmp-prefix strip."""
    parents = set()
    for p in paths:
        parts = [c for c in str(p).split("/") if c not in ("", ".")]
        if len(parts) >= 2 and parts[0] == "tmp":
            parts = parts[2:]
        parents.add("/".join(parts[:-1]) if len(parts) > 1 else ".")
    return float(len(parents))


# ---------------------------------------------------------------------------
# Per-sample extraction (label-blind by construction: no label argument)
# ---------------------------------------------------------------------------
def extract_sample_features(graph: dict, text: str, kb) -> Dict[str, float]:
    """41 MalGuard-style features for ONE sample (AMENDMENT-8 A8.2).

    `graph` = one merged-graph row of graphs_v2.jsonl.gz; `text` = the cached
    source text (text_v2.json, "" for empty); `kb` = packguard.kb.KnowledgeBase.
    """
    nodes = graph.get("nodes", []) or []
    files = graph.get("files", []) or []
    apis = sorted({str(n.get("api", "")).strip() for n in nodes} - {""})
    present = {n.get("cls") for n in nodes}
    n_nodes = float(graph.get("n_nodes", 0)) or float(len(nodes))

    # hist_* of the frozen graph block, recomputed from the SAME graph row
    hist = {c: 0 for c in _CLASSES}
    for n in nodes:
        if n.get("cls") in hist:
            hist[n["cls"]] += 1

    feats: Dict[str, float] = {}
    # (1-6) per-class unique-API ratios, all 6 classes (no hist_* duplicate)
    for c in _CLASSES:
        feats[f"ratio_{c.lower()}_of_api"] = round(hist[c] / (n_nodes + 1.0), 6)

    # (7-8) KB-v3 per-API confidence (pure dict join; reuse kb.kb_features on
    # the sorted unique API list — its risk_ratio/kb_confidence definitions)
    from packguard.kb import kb_features

    kbf = kb_features(apis, kb)
    feats["kb_high_api_ratio"] = float(kbf["kb_risk_ratio"])
    feats["kb_conf_mean"] = float(kbf["kb_confidence"])

    # (9-18) top-10 sensitive-API presence indicators
    aset = set(apis)
    for a in TOP10_APIS:
        feats[f"ind_api_{a.replace('.', '__')}"] = 1.0 if a in aset else 0.0

    # (19-28) class-pair co-occurrence (binary)
    for a, b in TOP10_PAIRS:
        feats[f"pair_{a}__{b}"] = 1.0 if (a in present and b in present) else 0.0

    # (29-30) entry-point weighted features
    entry_nodes = sum(float(f.get("n_nodes", 0)) for f in files
                      if f.get("entry_kind") in ENTRY_KINDS)
    total_nodes = sum(float(f.get("n_nodes", 0)) for f in files)
    feats["entry_api_share"] = round(entry_nodes / (total_nodes + 1.0), 6)
    feats["entry_api_count"] = round(entry_nodes, 6)

    # (31) Amalfi metadata: distinct parent dirs
    feats["n_dirs"] = float(_n_dirs_of([f.get("file", "") for f in files]))

    # (32-41) lexical code features on the CACHED text (no re-parse)
    t = str(text or "")
    n_chars = len(t)
    lines = t.split("\n")
    n_nonempty = sum(1 for ln in lines if ln.strip())
    fn = len(_RE_FUNCTION_PY.findall(t)) + len(_RE_FUNCTION_JS.findall(t))
    feats["text_n_functions"] = float(fn)
    lits = _RE_STRING_LIT.findall(t)
    feats["text_string_literal_count"] = float(len(lits))
    feats["text_max_string_len"] = float(max((len(x) for x in lits), default=0))
    feats["text_base64_like_count"] = float(len(_RE_BASE64.findall(t)))
    feats["text_url_ip_literal_count"] = float(
        len(_RE_URL.findall(t)) + len(_RE_IP.findall(t)))
    feats["text_shell_indicator_count"] = float(
        sum(t.count(tok) for tok in SHELL_TOKENS))
    feats["text_eval_exec_count"] = float(len(_RE_EVAL_EXEC.findall(t)))
    long_chars = sum(len(x) for x in lits if len(x) >= 32)
    feats["text_long_string_ratio"] = round(
        long_chars / n_chars, 6) if n_chars else 0.0
    hex_es = [_shannon_entropy(list(m)) for m in _RE_HEX.findall(t)]
    feats["text_hex_entropy"] = round(max(hex_es), 6) if hex_es else 0.0
    feats["text_avg_line_len"] = round(
        n_chars / max(n_nonempty, 1), 6) if n_nonempty else 0.0

    assert set(feats) == set(MALGUARD_FEATURE_NAMES)
    return {k: float(feats[k]) for k in MALGUARD_FEATURE_NAMES}


def load_graph_rows(path: Path = GRAPHS_PATH) -> List[dict]:
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def build_feature_table(graphs_path: Path = GRAPHS_PATH,
                        text_path: Path = TEXT_PATH,
                        kb_dir: Path = KB_DIR) -> Dict[str, Dict[str, float]]:
    """sample_id -> 41 features, computed over the whole corpus (deterministic;
    labels are never read — graphs_v2 rows carry none)."""
    from packguard.kb import KnowledgeBase

    kb = KnowledgeBase(kb_dir)
    with open(text_path, "r", encoding="utf-8") as f:
        cache = json.load(f)
    out: Dict[str, Dict[str, float]] = {}
    for g in load_graph_rows(graphs_path):
        sid = str(g["sample_id"])
        out[sid] = extract_sample_features(g, cache.get(sid, "") or "", kb)
    return out


# ---------------------------------------------------------------------------
# Design matrices for the 4 registered blocks
# ---------------------------------------------------------------------------
def _graph_names() -> List[str]:
    from packguard.features import FEATURE_NAMES

    return sorted(FEATURE_NAMES)


def design_matrix(records: List[dict], block: str,
                  malguard_table: Dict[str, Dict[str, float]],
                  precomputed_hash: Optional[tuple[Any, Dict[str, int]]] = None
                  ) -> np.ndarray:
    """Raw (unstandardized) matrix for block in {malguard, combined, graph,
    hashing_tfidf}. `precomputed_hash` = (csr, sample_id -> row) stateless
    corpus-wide HashingVectorizer matrix (A5.5, transform is stateless)."""
    if block == "hashing_tfidf":
        if precomputed_hash is None:
            raise ValueError("hashing_tfidf needs the precomputed hash matrix")
        mat, index = precomputed_hash
        return mat[[index[str(r["sample_id"])] for r in records]]
    if block == "graph":
        names = _graph_names()
        return np.array([[float(r["features"]["graph"][n]) for n in names]
                         for r in records], dtype=np.float64)
    if block == "malguard":
        names = list(MALGUARD_FEATURE_NAMES)
        return np.array([[float(malguard_table[str(r["sample_id"])][n])
                          for n in names] for r in records], dtype=np.float64)
    if block == "combined":
        names = _graph_names() + list(MALGUARD_FEATURE_NAMES)
        rows = []
        for r in records:
            g = r["features"]["graph"]
            m = malguard_table[str(r["sample_id"])]
            rows.append([float(g[n]) for n in _graph_names()]
                        + [float(m[n]) for n in MALGUARD_FEATURE_NAMES])
        return np.array(rows, dtype=np.float64)
    raise ValueError(f"unknown block {block!r}")


# ---------------------------------------------------------------------------
# One cell: the round-11 strong recipe on arbitrary matrices
# (mirror of packguard.strong_baseline.run_p0_cell; internals reused READ-ONLY)
# ---------------------------------------------------------------------------
def run_cell(train_records: List[dict], test_records: List[dict], block: str,
             seed: int, split: str, malguard_table: Dict[str, Dict[str, float]],
             precomputed_hash: Optional[tuple[Any, Dict[str, int]]] = None,
             c_grid: Sequence[float] = (0.01, 0.1, 1.0, 10.0),
             fedavg_rounds: int = 2) -> dict:
    from packguard.fl import client_name_of, compute_clf_metrics
    from packguard.strong_baseline import (
        fedavg_sklearn, fit_scaler, probs_from_theta, select_c_cv,
        standardize, strong_centralized,
    )

    Xtr_raw = design_matrix(train_records, block, malguard_table,
                            precomputed_hash)
    Xte_raw = design_matrix(test_records, block, malguard_table,
                            precomputed_hash)
    sc = fit_scaler(Xtr_raw)                    # pooled TRAIN only (A5.1)
    Xs_train = standardize(sc, Xtr_raw)
    Xs_test = standardize(sc, Xte_raw)
    y_train = np.array([int(r["label"]) for r in train_records], dtype=int)
    y_test = [int(r["label"]) for r in test_records]

    cv = select_c_cv(Xs_train, y_train, seed=seed, c_grid=c_grid)
    C = cv["C_selected"]

    part: Dict[str, List[int]] = {}
    for i, r in enumerate(train_records):
        part.setdefault(client_name_of(r, "ecosystem"), []).append(i)
    client_names = sorted(part)
    client_X = [Xs_train[part[cn]] for cn in client_names]
    client_y = [y_train[part[cn]] for cn in client_names]

    methods: Dict[str, Any] = {}
    cent = strong_centralized(Xs_train, y_train, C)
    methods["strong_centralized"] = {
        "final_metrics": compute_clf_metrics(y_test, probs_from_theta(
            cent["theta"], Xs_test)),
        "probs": [round(float(x), 6) for x in
                  probs_from_theta(cent["theta"], Xs_test)],
        "converged": bool(cent["converged"]),
    }
    avg = fedavg_sklearn(client_X, client_y, C, rounds=fedavg_rounds)
    methods["fedavg"] = {
        "final_metrics": compute_clf_metrics(y_test, probs_from_theta(
            avg["theta"], Xs_test)),
        "probs": [round(float(x), 6) for x in
                  probs_from_theta(avg["theta"], Xs_test)],
        "fixed_point_from_round_2": bool(fedavg_rounds >= 2 and abs(
            avg["history"][-1]["theta_l2"] - avg["history"][0]["theta_l2"])
            < 1e-12),
    }
    return {
        "seed": int(seed), "split": str(split), "block": str(block),
        "n_train": len(train_records), "n_test": len(test_records),
        "C_selected": float(C), "cv_table": cv["cv_table"],
        "client_sizes": {cn: int(len(part[cn])) for cn in client_names},
        "input_dim": int(Xtr_raw.shape[1]),
        "methods": methods,
        "y_test": [int(v) for v in y_test],
        "test_ecosystems": [str(r.get("ecosystem")) for r in test_records],
    }


# ---------------------------------------------------------------------------
# Stats helpers (registered rules of AMENDMENT-8 A8.4)
# ---------------------------------------------------------------------------
def mcnemar_exact_or_cc(corr_a: Sequence[bool], corr_b: Sequence[bool]) -> dict:
    """Per-sample paired McNemar; exact binomial when discordant < 25, else
    continuity-corrected chi2 (the round-8 rule; A8.4)."""
    from src.metrics.stats import mcnemar

    return mcnemar(list(corr_a), list(corr_b), exact=None)


def tost(deltas: Sequence[float], margin: float = 0.02) -> dict:
    from packguard.eval import tost_equivalence

    return tost_equivalence(list(deltas), margin=margin)


def wilcoxon_exact(deltas: Sequence[float]) -> dict:
    from scipy import stats as sps

    d = [float(x) for x in deltas]
    base = {"n": len(d), "n_pos": sum(x > 0 for x in d),
            "n_neg": sum(x < 0 for x in d), "n_zero": sum(x == 0 for x in d)}
    if not d or all(x == 0.0 for x in d):
        return {**base, "p_value_exact": None,
                "note": "all deltas exactly zero; Wilcoxon undefined"}
    res = sps.wilcoxon(d, method="exact")
    return {**base, "p_value_exact": float(res.pvalue)}


def holm(pvals: Sequence[float]) -> List[float]:
    from packguard.eval import holm_adjust

    return holm_adjust(list(pvals))


def per_ecosystem_f1(test_ecosystems: Sequence[str], y_test: Sequence[int],
                     probs: Sequence[float]) -> Dict[str, Optional[float]]:
    from packguard.fl import compute_clf_metrics

    out: Dict[str, Optional[float]] = {}
    for eco in ("npm", "pypi"):
        idx = [i for i, e in enumerate(test_ecosystems)
               if str(e).startswith(eco)]
        out[f"eco_{eco}"] = (
            compute_clf_metrics([y_test[i] for i in idx],
                                [probs[i] for i in idx])["f1"]
            if idx else None)
    return out


# ---------------------------------------------------------------------------
# Grid runner (AMENDMENT-8 A8.3): 20 seeds x {group, lco030} x 4 blocks x 2
# methods = 320 runs, sklearn CPU only
# ---------------------------------------------------------------------------
def _make_split(records: List[dict], split: str, seed: int,
                cluster_of: Dict[str, str],
                test_fraction: float) -> Tuple[List[dict], List[dict], dict]:
    from packguard.fl import make_group_split
    from packguard.lco import draw_lco_split

    if split == "group":
        train, test = make_group_split(records, test_fraction, seed=seed)
        return train, test, {"split_kind": "package-group (PRIMARY)"}
    if split == "lco030":
        train, test, info = draw_lco_split(records, cluster_of, seed=seed,
                                           test_fraction=test_fraction)
        return train, test, {"split_kind": "leave-cluster-out t=0.30 (SECONDARY)",
                             "n_test_clusters": info["n_test_clusters"],
                             "lco_valid": info["valid"]}
    raise ValueError(f"unknown split {split!r}")


def _load_cluster_assignment(clusters_path: Path) -> Dict[str, str]:
    with open(clusters_path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    return {str(k): str(v) for k, v in doc["assignment"].items()}


def _features_dir(path_str: str) -> Path:
    """load_feature_records expects the FEATURES DIRECTORY; accept either a
    directory or a features_v*.jsonl file path (config convenience)."""
    p = Path(path_str)
    return p.parent if p.is_file() else p


def run_grid(cfg: dict) -> dict:
    from packguard.fl import config_sha16, load_feature_records

    out_dir = PROJECT_ROOT / str(cfg.get("outdir", "outputs/packguard/malguard_style"))
    out_dir.mkdir(parents=True, exist_ok=True)
    seeds = [int(s) for s in cfg["seeds"]]
    splits = list(cfg["splits"])
    blocks = list(cfg["blocks"])
    test_fraction = float(cfg.get("test_fraction", 0.2))
    margin = float(cfg.get("tost_margin", 0.02))
    comp_pairs = [tuple(p) for p in cfg.get("compare_blocks", [["malguard", "graph"], ["combined", "graph"]])]

    records, feat_meta = load_feature_records(_features_dir(cfg["features"]))
    if feat_meta.get("mock", False):
        raise RuntimeError("run_grid refuses mock data (AMENDMENT-8)")
    cluster_of = _load_cluster_assignment(PROJECT_ROOT / cfg["clusters_t030"])

    malguard_table = build_feature_table()
    from packguard.strong_baseline import HashingTextFeaturizer

    with open(TEXT_PATH, "r", encoding="utf-8") as f:
        text_cache = json.load(f)
    vec = HashingTextFeaturizer()
    H = vec.transform([text_cache.get(str(r["sample_id"]), "") or ""
                       for r in records])
    hash_index = {str(r["sample_id"]): i for i, r in enumerate(records)}
    precomputed_hash = (H, hash_index)

    cfg_sha = config_sha16(cfg)
    base_meta = {
        "seeds": seeds, "splits": splits, "blocks": blocks,
        "config_sha16": cfg_sha, "date": _now(),
        "pipeline": "packguard.malguard_style.run_grid",
        "mock": False, "features_source": feat_meta.get("source"),
        "amendment": "AMENDMENT-8 (docs/packguard_prereg.md, "
                     "2026-09-27T22:44:07Z): MalGuard/Amalfi-style feature "
                     "baseline; registered BEFORE this run",
        "tost_margin": margin, "compare_pairs": [list(p) for p in comp_pairs],
        "n_malguard_features": len(MALGUARD_FEATURE_NAMES),
        "kb_note": "KB-v3 (kb_v0002) pure dict join; NO LLM invoked",
    }

    # features + schema provenance (written before any metric exists)
    with open(out_dir / "features_malguard.jsonl", "w", encoding="utf-8") as f:
        for sid in sorted(malguard_table):
            f.write(json.dumps({"sample_id": sid,
                                "features": malguard_table[sid]},
                               sort_keys=True) + "\n")
    with open(out_dir / "schema.json", "w", encoding="utf-8") as f:
        json.dump({
            "amendment": "AMENDMENT-8",
            "registered_at": "2026-09-27T22:44:07Z",
            "feature_names": list(MALGUARD_FEATURE_NAMES),
            "n_features": len(MALGUARD_FEATURE_NAMES),
            "top10_apis": list(TOP10_APIS),
            "top10_pairs": [list(p) for p in TOP10_PAIRS],
            "sources": {"graphs": str(GRAPHS_PATH), "text": str(TEXT_PATH),
                        "kb": str(KB_DIR)},
            "label_blind": True, "deterministic": True,
            "llm_invocations": 0,
        }, f, indent=2)

    all_rows: List[dict] = []
    cells: List[dict] = []
    total = len(seeds) * len(splits) * len(blocks)
    done = 0
    for seed in seeds:
        for split in splits:
            train, test, split_info = _make_split(
                records, split, seed, cluster_of, test_fraction)
            for block in blocks:
                done += 1
                print(f"[malguard {done}/{total}] seed={seed} split={split} "
                      f"block={block}", flush=True)
                cell = run_cell(train, test, block, seed, split,
                                malguard_table, precomputed_hash)
                cells.append(cell)
                for method in METHODS:
                    res = cell["methods"][method]
                    m = res["final_metrics"]
                    eco_f1 = per_ecosystem_f1(cell["test_ecosystems"],
                                              cell["y_test"], res["probs"])
                    cell.setdefault("eco_f1", {})[method] = eco_f1
                    all_rows.append({
                        "kind": "run",
                        "name": f"m8__{split}__{block}__{method}__seed{seed}",
                        "meta": dict(base_meta),
                        "seed": seed, "split": split, "block": block,
                        "method": method, "mock": False,
                        "config_sha16": cfg_sha, "date": base_meta["date"],
                        "C_selected": cell["C_selected"],
                        "input_dim": cell["input_dim"],
                        "n_train": cell["n_train"], "n_test": cell["n_test"],
                        "n_test_malicious": m["n_test_malicious"],
                        "f1": m["f1"], "auc": m["auc"],
                        "precision": m["precision"], "recall": m["recall"],
                        "per_ecosystem_f1": eco_f1,
                        "split_info": split_info,
                    })

    aggregate = _aggregate(cells, comp_pairs, margin)
    with open(out_dir / "results.jsonl", "w", encoding="utf-8") as f:
        for row in all_rows:
            f.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
    summary = _render_summary(base_meta, aggregate, len(all_rows))
    (out_dir / "summary.md").write_text(summary, encoding="utf-8")
    with open(out_dir / "aggregate.json", "w", encoding="utf-8") as f:
        json.dump({"meta": base_meta, "aggregate": aggregate}, f, indent=1,
                  default=str)
    return {"meta": base_meta, "n_runs": len(all_rows),
            "aggregate": aggregate, "out_dir": str(out_dir)}


def _aggregate(cells: List[dict], comp_pairs, margin: float) -> dict:
    """Cell means + the 8 registered comparisons (A8.4)."""
    def _ms(vals):
        v = [float(x) for x in vals if x is not None]
        if not v:
            return {"mean": None, "std": None, "n": 0}
        mu = sum(v) / len(v)
        return {"mean": mu, "n": len(v),
                "std": (sum((x - mu) ** 2 for x in v) / len(v)) ** 0.5}

    groups: Dict[Tuple[str, str, str], List[dict]] = {}
    for c in cells:
        for method in METHODS:
            groups.setdefault((c["split"], c["block"], method), []).append(c)
    agg_cells = {}
    for (split, block, method), cs in sorted(groups.items()):
        cs = sorted(cs, key=lambda c: c["seed"])
        # per-ecosystem F1 (descriptive, D4-style); cell["eco_f1"][method]
        eco = {"eco_npm": _ms([e["eco_npm"] for c in cs
                               for e in [c.get("eco_f1", {}).get(method)]
                               if e is not None and e.get("eco_npm") is not None]),
               "eco_pypi": _ms([e["eco_pypi"] for c in cs
                                for e in [c.get("eco_f1", {}).get(method)]
                                if e is not None and e.get("eco_pypi") is not None])}
        agg_cells[f"{split}__{block}__{method}"] = {
            "split": split, "block": block, "method": method,
            "seeds": [c["seed"] for c in cs],
            "f1": _ms([c["methods"][method]["final_metrics"]["f1"] for c in cs]),
            "auc": _ms([c["methods"][method]["final_metrics"]["auc"] for c in cs]),
            "precision": _ms([c["methods"][method]["final_metrics"]["precision"] for c in cs]),
            "recall": _ms([c["methods"][method]["final_metrics"]["recall"] for c in cs]),
            "eco_npm_f1": eco["eco_npm"], "eco_pypi_f1": eco["eco_pypi"],
        }

    comparisons: Dict[str, Any] = {}
    raw_ps: List[float] = []
    keys: List[str] = []
    from packguard.fl import paired_correctness

    for split in ("group", "lco030"):
        for block_a, block_b in comp_pairs:
            for method in METHODS:
                cs_a = sorted([c for c in cells if c["split"] == split
                               and c["block"] == block_a], key=lambda c: c["seed"])
                cs_b = sorted([c for c in cells if c["split"] == split
                               and c["block"] == block_b], key=lambda c: c["seed"])
                assert [c["seed"] for c in cs_a] == [c["seed"] for c in cs_b]
                deltas, mcns = [], []
                for ca, cb in zip(cs_a, cs_b):
                    pa = ca["methods"][method]["probs"]
                    pb = cb["methods"][method]["probs"]
                    y = ca["y_test"]
                    corr_a, corr_b = paired_correctness(pa, pb, y)
                    mc = mcnemar_exact_or_cc(corr_a, corr_b)
                    mcns.append(mc)
                    deltas.append(
                        ca["methods"][method]["final_metrics"]["f1"]
                        - cb["methods"][method]["final_metrics"]["f1"])
                w = wilcoxon_exact(deltas)
                key = f"{split}__{block_a}_vs_{block_b}__{method}"
                comparisons[key] = {
                    "split": split, "block_a": block_a, "block_b": block_b,
                    "method": method, "n_seeds": len(deltas),
                    "delta_f1_a_minus_b": deltas,
                    "delta_mean_std": _ms(deltas),
                    "tost": tost(deltas, margin=margin),
                    "wilcoxon": w,
                    "per_seed_mcnemar": [
                        {"seed": ca["seed"], "p_value": mc["p_value"],
                         "method": mc["method"],
                         "b01": mc.get("b01_a_fail_b_success"),
                         "b10": mc.get("b10_a_success_b_fail")}
                        for ca, mc in zip(cs_a, mcns)],
                    "mcnemar_n_exact": sum(
                        1 for mc in mcns if mc.get("exact")),
                }
                raw_ps.append(w["p_value_exact"] if w["p_value_exact"]
                              is not None else 1.0)
                keys.append(key)
    adj = holm(raw_ps)
    for k, a in zip(keys, adj):
        comparisons[k]["wilcoxon"]["p_holm"] = a
        comparisons[k]["wilcoxon"]["significant_holm_0.05"] = bool(a < 0.05)
    return {"cells": agg_cells, "comparisons": comparisons}


def _render_summary(base_meta: dict, agg: dict, n_runs: int) -> str:
    def fmt(d):
        if d is None or d.get("mean") is None:
            return "n/a"
        return f"{d['mean']:.4f}±{d['std']:.4f}"

    lines: List[str] = []
    lines.append("# PackGuard MalGuard-style feature baseline — summary "
                 "(round 15, AMENDMENT-8)")
    lines.append("")
    lines.append(f"- date: {base_meta['date']}")
    lines.append(f"- config sha16: {base_meta['config_sha16']}; seeds: "
                 f"{base_meta['seeds'][0]}..{base_meta['seeds'][-1]} (n="
                 f"{len(base_meta['seeds'])})")
    lines.append(f"- runs: {n_runs} (mock=false; blocks={base_meta['blocks']}; "
                 f"splits={base_meta['splits']}; methods={list(METHODS)})")
    lines.append(f"- malguard block: {base_meta['n_malguard_features']} frozen "
                 "features (A8.2); KB-v3 pure dict join, NO LLM invoked")
    lines.append("")
    lines.append("## F1 / AUC (mean±std over 20 seeds)")
    lines.append("")
    lines.append("| split | block | method | F1 | AUC |")
    lines.append("|---|---|---|---|---|")
    for key, d in sorted(agg["cells"].items()):
        lines.append(f"| {d['split']} | {d['block']} | {d['method']} "
                     f"| {fmt(d['f1'])} | {fmt(d['auc'])} |")
    lines.append("")
    lines.append("## Registered comparisons: malguard-style vs graph "
                 "(A8.4; ΔF1 = a − b, per seed paired)")
    lines.append("")
    lines.append("| split | pair | method | ΔF1 mean±std | 90% CI | TOST ±0.02 "
                 "| Wilcoxon exact p | p Holm |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for key, comp in sorted(agg["comparisons"].items()):
        t, w, ms = comp["tost"], comp["wilcoxon"], comp["delta_mean_std"]
        pe = w.get("p_value_exact")
        lines.append(
            f"| {comp['split']} | {comp['block_a']} vs {comp['block_b']} "
            f"| {comp['method']} | {ms['mean']:+.4f}±{ms['std']:.4f} "
            f"| [{t['ci_low']:+.4f}, {t['ci_high']:+.4f}] "
            f"| {'PASS' if t['equivalent'] else 'FAIL'} "
            f"| {'n/a' if pe is None else f'{pe:.4g}'} "
            f"| {w['p_holm']:.4g} |")
    lines.append("")
    lines.append("## Per-ecosystem F1 (descriptive, D4-style)")
    lines.append("")
    lines.append("| split | block | method | npm F1 | pypi F1 |")
    lines.append("|---|---|---|---|---|")
    for key, d in sorted(agg["cells"].items()):
        lines.append(f"| {d['split']} | {d['block']} | {d['method']} "
                     f"| {fmt(d.get('eco_npm_f1'))} | {fmt(d.get('eco_pypi_f1'))} |")
    lines.append("")
    lines.append("## Notes (honest)")
    lines.append("- Reimplementation, NOT the original MalGuard system: "
                 "LLM triage replaced by the project's KB-v3 (100% coverage) "
                 "pure dict join; features limited to what graphs_v2/"
                 "text_v2/KB expose (no re-parse).")
    lines.append("- The `graph` and `hashing_tfidf` numbers are re-run in "
                 "THIS round under the identical recipe so per-sample paired "
                 "predictions exist for McNemar; round-9/11 stored numbers "
                 "are external consistency checks only.")
    lines.append("- TOST FAIL directions are read and reported both ways "
                 "(A8.4): no post-hoc direction choice.")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    import yaml

    ap = argparse.ArgumentParser(
        description="PackGuard MalGuard-style baseline (AMENDMENT-8)")
    ap.add_argument("--config", default=str(CONFIG_PATH))
    args = ap.parse_args(argv)
    with open(args.config, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    res = run_grid(cfg)
    print(f"rows -> {res['out_dir']}/results.jsonl ({res['n_runs']} runs)")
    print(f"summary -> {res['out_dir']}/summary.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
