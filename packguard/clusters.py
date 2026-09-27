"""MinHash family clustering for PackGuard (round 13, AMENDMENT-7).

Question this answers (the paper's own open robustness question): the
round-11 group split holds out PACKAGE families, but near-duplicate
DIFFERENT packages (typosquat families, copies) can still straddle the
train/test boundary. A leave-CLUSTER-out split must hold out the whole
similarity cluster, so "graph vs hashing-text degradation under family
shift" can be measured with no near-duplicate leakage at all.

Method (registered BEFORE any LCO split/run, see docs/packguard_prereg.md
AMENDMENT-7; written 2026-09-27, round 13, agent W1):
  * Shingle set per SAMPLE = word 3-grams of the code text
    (outputs/packguard/features/text_v2.json, lower-cased, whitespace
    tokens) + name-pattern shingles derived from the package name
    (lower-cased, npm scope stripped, common filler tokens stripped from
    the start/end: js/py/core/lib/node/python/package/pkg/npm; remaining
    tokens as "nme:tok:" entries + character 3-grams of the de-scoped name
    as "nme:cg:" entries + the full normalized name as one "nme:full:"
    entry). Name shingles guarantee non-empty signatures for the 43
    empty-text samples and let version families merge even when code is
    tiny. Typosquat merging is therefore name-AND-code driven; name-driven
    merges only fire for small packages (disclosed limitation).
  * MinHash: 128 hash functions, seed 20260922, NO external library.
    Base hash of a shingle = first 4 bytes of md5 (little-endian uint32;
    process-stable, unlike salted built-in hash()). Permutation family:
    h_j(x) = (a_j * x + b_j) mod (2^31 - 1), a_j in [1, p), b_j in [0, p)
    drawn from numpy default_rng(20260922) ONCE (fixed family; a_j <= 2^31
    and x < 2^32 so a_j*x fits uint64 exactly).
  * Jaccard estimate = fraction of matching signature components.
  * Union-find clustering of the 603 samples at a similarity threshold.
    Threshold registered from the pairwise-similarity histogram (elbow);
    sensitivity run at BOTH 0.3 and 0.5 (AMENDMENT-7).
  * Known-family sanity gate (C1): every multi-version package family
    (e.g. the 31 archives of @antoncallahan/aws-user-helper) must land in
    ONE cluster — verified by build_corpus_clusters() and asserted in
    tests/test_packguard_lco.py.

Clustering is UNSUPERVISED (labels are never read). Determinism: same
inputs -> identical clusters, cross-process (md5 + fixed RNG; no dict
ordering dependence: shingle sets are sorted before hashing).

CLI:
    .venv/bin/python -m packguard.clusters \
        --features outputs/packguard/features/features_v2.jsonl \
        --text outputs/packguard/features/text_v2.json \
        --threshold 0.3 --outdir outputs/packguard/lco --tag t030
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections import Counter
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np

SEED = 20260922
NUM_PERM = 128
MOD_P = (1 << 31) - 1          # Mersenne prime 2^31-1
WORD_K = 3                     # word 3-gram shingles
NAME_FILLERS = {"js", "py", "core", "lib", "node", "python", "package",
                "pkg", "npm"}

SCHEMA_VERSION = "clusters-v1"


# ---------------------------------------------------------------------------
# Shingling
# ---------------------------------------------------------------------------
def normalize_package_name(package: str) -> Tuple[str, List[str]]:
    """(de-scoped lower-cased name, filler-stripped token list).

    npm scope '@scope/name' (dataset spelling '@scope@name') -> scope is
    dropped from the char-gram base but KEPT as its own token so two
    packages of one scope do not over-merge on the scope alone.
    """
    name = str(package).lower()
    scope = ""
    for sep in ("/", "@"):
        if name.startswith("@") and sep in name[1:]:
            scope, _, name = name[1:].partition(sep)
            break
    toks = [t for t in name.replace("+", " ").split() if t]
    # the dataset writes scoped names as '@antoncallahan@aws-user-helper':
    # after the scope split above the remainder keeps no separator, so also
    # split on '-' '_' '.' digits boundaries.
    toks2: List[str] = []
    for t in toks:
        buf = ""
        for ch in t:
            if ch.isalnum():
                buf += ch
            else:
                if buf:
                    toks2.append(buf)
                buf = ""
        if buf:
            toks2.append(buf)
    toks2 = [t for t in toks2 if t]
    if scope:
        toks2 = ["scope:" + scope] + toks2
    # strip common filler PREFIX/SUFFIX tokens (typosquat handling,
    # registered in AMENDMENT-7): repeated, never from the middle.
    while len(toks2) > 1 and toks2[-1] in NAME_FILLERS:
        toks2 = toks2[:-1]
    while len(toks2) > 1 and toks2[0] in NAME_FILLERS:
        toks2 = toks2[1:]
    return name, toks2


def name_shingles(package: str) -> set:
    _, toks = normalize_package_name(package)
    out = set()
    for t in toks:
        out.add("nme:tok:" + t)
    base = "".join(t for t in toks if not t.startswith("scope:")) or "x"
    padded = "#" + base + "#"
    for i in range(len(padded) - 2):
        out.add("nme:cg:" + padded[i:i + 3])
    out.add("nme:full:" + "".join(toks))
    return out


def word_shingles(text: str, k: int = WORD_K) -> set:
    toks = str(text).lower().split()
    if len(toks) < k:
        return set()
    return {"cod:" + " ".join(toks[i:i + k]) for i in range(len(toks) - k + 1)}


def sample_shingles(text: str, package: str) -> List[str]:
    """Sorted shingle list (sorted -> deterministic md5 base hashes)."""
    sh = word_shingles(text) | name_shingles(package)
    return sorted(sh)


# ---------------------------------------------------------------------------
# MinHash (no external library)
# ---------------------------------------------------------------------------
def _base_hashes(shingles: Sequence[str]) -> np.ndarray:
    """uint32 base hash per shingle: md5 first 4 bytes (process-stable)."""
    out = np.empty(len(shingles), dtype=np.uint64)
    for i, s in enumerate(shingles):
        out[i] = int.from_bytes(
            hashlib.md5(s.encode("utf-8")).digest()[:4], "little")
    return out


def permutation_family(num_perm: int = NUM_PERM, seed: int = SEED):
    """Fixed (a, b) family: ONE draw from default_rng(seed), registered."""
    rng = np.random.default_rng(seed)
    a = rng.integers(1, MOD_P, size=num_perm, dtype=np.int64).astype(np.uint64)
    b = rng.integers(0, MOD_P, size=num_perm, dtype=np.int64).astype(np.uint64)
    return a, b


def minhash_signature(shingles: Sequence[str], num_perm: int = NUM_PERM,
                      seed: int = SEED, chunk: int = 20000) -> np.ndarray:
    """128-dim uint32 signature; chunked to bound memory on large samples."""
    if not shingles:
        raise ValueError("minhash_signature: empty shingle set (name "
                         "shingles make this impossible; caller bug)")
    a, b = permutation_family(num_perm, seed)
    best = np.full(num_perm, np.iinfo(np.uint64).max, dtype=np.uint64)
    for start in range(0, len(shingles), chunk):
        h = _base_hashes(shingles[start:start + chunk])
        vals = (a[:, None] * h[None, :] + b[:, None]) % np.uint64(MOD_P)
        best = np.minimum(best, vals.min(axis=1))
    return best.astype(np.uint32)


def estimate_jaccard(sig_a: np.ndarray, sig_b: np.ndarray) -> float:
    return float(np.mean(sig_a == sig_b))


def pairwise_similarities(sigs: np.ndarray, chunk_rows: int = 64) -> np.ndarray:
    """Dense (n, n) estimated-Jaccard matrix (chunked; diagonal = 1)."""
    n = sigs.shape[0]
    out = np.zeros((n, n), dtype=np.float64)
    for i0 in range(0, n, chunk_rows):
        block = sigs[i0:i0 + chunk_rows]                     # (c, P)
        eq = (block[:, None, :] == sigs[None, :, :]).mean(axis=2)
        out[i0:i0 + chunk_rows] = eq
    np.fill_diagonal(out, 1.0)
    return out


def similarity_histogram(sims: np.ndarray, step: float = 0.05
                         ) -> List[Tuple[float, float, int]]:
    """[lo, hi) bin counts over OFF-DIAGONAL pairs (both triangles)."""
    n = sims.shape[0]
    iu = np.triu_indices(n, k=1)
    vals = sims[iu]
    edges = np.arange(0.0, 1.0 + step / 2, step)
    counts, _ = np.histogram(vals, bins=edges)
    return [(round(float(edges[i]), 2), round(float(edges[i + 1]), 2),
             int(counts[i])) for i in range(len(counts))]


# ---------------------------------------------------------------------------
# Union-find
# ---------------------------------------------------------------------------
class DSU:
    """Deterministic union-find (union by min root; no rank => stable ids)."""

    def __init__(self, items: Sequence):
        self.parent = {x: x for x in items}

    def find(self, x):
        p = self.parent
        while p[x] != x:
            p[x] = p[p[x]]
            x = p[x]
        return x

    def union(self, x, y):
        rx, ry = self.find(x), self.find(y)
        if rx != ry:
            lo, hi = sorted((rx, ry))
            self.parent[hi] = lo

    def groups(self) -> Dict:
        out: Dict = {}
        for x in self.parent:
            out.setdefault(self.find(x), []).append(x)
        return {r: sorted(m) for r, m in sorted(out.items())}


def clusters_from_similarities(ids: Sequence[str], sims: np.ndarray,
                               threshold: float) -> Dict[str, str]:
    """sample_id -> cluster_id ('c' + zero-padded rank of the cluster's
    smallest sample_id, sorted => deterministic across runs)."""
    dsu = DSU(ids)
    n = len(ids)
    for i in range(n):
        row = sims[i]
        js = np.nonzero(row >= threshold)[0]
        for j in js:
            if j > i:
                dsu.union(ids[i], ids[j])
    groups = dsu.groups()
    return {sid: "c%04d" % k for k, (root, members) in enumerate(
        sorted(groups.items())) for sid in members}


# ---------------------------------------------------------------------------
# Corpus driver
# ---------------------------------------------------------------------------
def build_corpus_clusters(features_rows: List[dict], text_cache: dict,
                          threshold: float, num_perm: int = NUM_PERM,
                          seed: int = SEED,
                          signature_cache: Optional[str] = None,
                          verbose: bool = True) -> Tuple[dict, dict]:
    """(sample_id -> cluster_id) + diagnostics meta for the 603-sample corpus.

    Labels are NEVER read here (unsupervised). Signature cache (npz) is keyed
    by (num_perm, seed, n_samples) and stores the row order; a mismatch
    rebuilds from scratch (never silently reuses).
    """
    rows = sorted(features_rows, key=lambda r: r["sample_id"])
    ids = [str(r["sample_id"]) for r in rows]
    sigs: Optional[np.ndarray] = None
    if signature_cache and os.path.exists(signature_cache):
        try:
            z = np.load(signature_cache)
            if (list(z["ids"]) == ids and int(z["num_perm"]) == num_perm
                    and int(z["seed"]) == seed):
                sigs = z["sigs"]
        except Exception:
            sigs = None
    if sigs is None:
        sig_rows = []
        for i, r in enumerate(rows):
            sh = sample_shingles(text_cache.get(ids[i], "") or "",
                                 r.get("package") or ids[i])
            sig_rows.append(minhash_signature(sh, num_perm, seed))
            if verbose and (i + 1) % 100 == 0:
                print(f"  minhash {i + 1}/{len(rows)}", flush=True)
        sigs = np.vstack(sig_rows)
        if signature_cache:
            os.makedirs(os.path.dirname(signature_cache), exist_ok=True)
            np.savez_compressed(signature_cache, sigs=sigs,
                                ids=np.array(ids), num_perm=num_perm,
                                seed=seed)
    sims = pairwise_similarities(sigs)
    sim_assign = clusters_from_similarities(ids, sims, threshold)

    # Package closure (AMENDMENT-7): the LCO holdout UNIT is the connected
    # component of {similarity edges >= threshold} U {same-package edges}.
    # Rationale: 25/67 multi-version packages contain genuinely different
    # versions (Jaccard < threshold, e.g. antoncallahan v2.13/v2.14 vs v1),
    # so a pure-similarity draw could straddle a package across train/test.
    # Closing over packages makes the unit strictly stronger than the
    # round-11 group split (no package straddle AND no near-duplicate
    # straddle). Pre-closure similarity clusters are kept in the meta.
    dsu = DSU(sorted(set(sim_assign.values())))
    pkg_units: Dict[str, set] = {}
    for r in rows:
        pkg_units.setdefault(str(r.get("package")), set()).add(
            sim_assign[str(r["sample_id"])])
    for cl in pkg_units.values():
        cl = sorted(cl)
        for c in cl[1:]:
            dsu.union(cl[0], c)
    roots = {cid: dsu.find(cid) for cid in dsu.parent}
    ordered = {root: k for k, root in enumerate(sorted(roots))}
    assign = {sid: "c%04d" % ordered[roots[sim_assign[sid]]] for sid in ids}
    n_sim_clusters = len(set(sim_assign.values()))

    # cluster-level composition (labels read ONLY for the report/split rule)
    members: Dict[str, List[dict]] = {}
    for r in rows:
        members.setdefault(assign[str(r["sample_id"])], []).append(r)
    comp = {}
    for cid, ms in members.items():
        labs = [int(m["label"]) for m in ms]
        comp[cid] = {
            "n": len(ms),
            "labels": {"benign": labs.count(0), "malicious": labs.count(1)},
            "packages": sorted({str(m.get("package")) for m in ms}),
            "ecosystems": sorted({str(m["ecosystem"]) for m in ms}),
        }
    # known-family gate: every multi-version package = ONE cluster
    pkg_clusters: Dict[str, set] = {}
    for r in rows:
        pkg_clusters.setdefault(str(r.get("package")), set()).add(
            assign[str(r["sample_id"])])
    split_fams = {p: sorted(c) for p, c in pkg_clusters.items() if len(c) > 1}
    multi = {p: c for p, c in pkg_clusters.items()
             if len({r["sample_id"] for r in rows
                     if str(r.get("package")) == p}) > 1}
    meta = {
        "schema_version": SCHEMA_VERSION,
        "num_perm": int(num_perm), "seed": int(seed),
        "threshold": float(threshold),
        "n_samples": len(ids),
        "n_similarity_clusters_preclosure": int(n_sim_clusters),
        "n_clusters": len(members),
        "package_closure": {
            "n_merges_preclosure_to_final": int(n_sim_clusters - len(members)),
            "definition": "holdout unit = connected component of "
                          "{Jaccard >= threshold} U {same package}",
        },
        "cluster_size_hist": {str(k): int(v) for k, v in sorted(
            Counter(len(ms) for ms in members.values()).items())},
        "n_single_sample_clusters": sum(
            1 for ms in members.values() if len(ms) == 1),
        "n_mixed_label_clusters": sum(
            1 for c in comp.values()
            if c["labels"]["benign"] > 0 and c["labels"]["malicious"] > 0),
        "mixed_label_cluster_ids": sorted(
            cid for cid, c in comp.items()
            if c["labels"]["benign"] > 0 and c["labels"]["malicious"] > 0),
        "n_multi_package_clusters": sum(
            1 for c in comp.values() if len(c["packages"]) > 1),
        "multi_package_clusters": {cid: c["packages"] for cid, c in
                                   sorted(comp.items())
                                   if len(c["packages"]) > 1},
        "histogram_offdiag_step05": similarity_histogram(sims),
        "similarity_stats_offdiag": {
            "n_pairs": int(len(ids) * (len(ids) - 1) / 2),
            "max": float((sims - np.eye(len(ids))).max()),
        },
        "known_family_check": {
            "n_multi_version_packages": len(multi),
            "n_multi_version_packages_split_across_clusters": len(split_fams),
            "split_families": split_fams,
            "antoncallahan_aws_user_helper": {
                "n_samples": len([r for r in rows if str(
                    r.get("package")) == "@antoncallahan@aws-user-helper"]),
                "n_clusters": len(pkg_clusters.get(
                    "@antoncallahan@aws-user-helper", set())),
            },
        },
    }
    return assign, {"meta": meta, "composition": comp, "ids": ids,
                    "sigs": sigs, "sims": sims}


def main() -> None:
    ap = argparse.ArgumentParser(description="PackGuard MinHash clustering")
    ap.add_argument("--features", default="outputs/packguard/features/features_v2.jsonl")
    ap.add_argument("--text", default="outputs/packguard/features/text_v2.json")
    ap.add_argument("--threshold", type=float, required=True)
    ap.add_argument("--num-perm", type=int, default=NUM_PERM)
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--outdir", default="outputs/packguard/lco")
    ap.add_argument("--tag", default=None, help="e.g. t030 (default thr)")
    ap.add_argument("--sig-cache", default="outputs/packguard/lco/signatures.npz")
    args = ap.parse_args()
    tag = args.tag or ("t%03d" % round(args.threshold * 100))

    rows = [json.loads(l) for l in open(args.features, encoding="utf-8")
            if l.strip()]
    text_cache = json.load(open(args.text, encoding="utf-8"))
    assign, aux = build_corpus_clusters(
        rows, text_cache, args.threshold, num_perm=args.num_perm,
        seed=args.seed, signature_cache=args.sig_cache)
    os.makedirs(args.outdir, exist_ok=True)
    out = {
        "schema_version": SCHEMA_VERSION,
        "meta": aux["meta"],
        "composition": aux["composition"],
        "assignment": assign,
    }
    path = os.path.join(args.outdir, f"clusters_{tag}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)
    m = aux["meta"]
    print(json.dumps({k: v for k, v in m.items()
                      if k not in ("multi_package_clusters",)}, indent=2))
    print("wrote", path)


if __name__ == "__main__":
    main()
