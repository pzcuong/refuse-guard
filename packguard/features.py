"""Graph-level feature extraction for PackGuard behavior graphs.

Feature vector (versioned via SCHEMA_VERSION; names in FEATURE_NAMES):
- hist_FILE_IO..hist_DATA_ACCESS : node counts per behavior class (6 dims)
- n_nodes, n_edges               : merged-sample graph size
- density                        : |E| / (|N|*(|N|-1)) for |N|>1 else 0.0
- n_scopes                       : number of function scopes that produced events
- max_repeat                     : longest run of the same class along seq edges
- distinct_classes               : number of behavior classes present
- seq_depth                      : longest path (nodes) in the seq+data DAG
- n_files                        : parsed source files
- n_import_classes               : distinct classes implied by require/import
- has_setup                      : sample included a setup.py graph (PyPI)
- has_postinstall                : sample included a postinstall-script graph (npm)
- parse_fail_files               : files whose tree-sitter parse emitted ERROR nodes

Batch CLI:
    .venv/bin/python -m packguard.features --manifest data/packguard/manifests/dataset_v1.json \
        --outdir outputs/packguard/features --tag v1
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import tarfile
import tempfile
import zipfile
from typing import Dict, List, Optional, Tuple

from packguard.graphs import build_graph, merge_graphs
from packguard.schema import BEHAVIOR_CLASSES, SCHEMA_VERSION, schema_json

# extraction caps (disclosed in prereg)
MAX_FILES_PER_SAMPLE = 12
MAX_FILE_BYTES = 100_000

_PRIORITY_FILES = [
    "index.js",
    "main.js",
    "app.js",
    "__init__.py",
    "install.js",
    "preinstall.js",
    "postinstall.js",
]

# files that can never occupy a code slot (BUG-2 fix: meta/hidden files were
# selected by the old alphabetical fill and produced spurious empty graphs)
_META_SUFFIXES = (
    ".md", ".rst", ".txt", ".cfg", ".ini", ".toml", ".yml", ".yaml", ".json",
    ".html", ".css", ".svg", ".png", ".jpg", ".gif", ".ico", ".map",
)

_LANG_BY_EXT = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
}

_CODE_EXTS = tuple(_LANG_BY_EXT.keys())

FEATURE_NAMES: Tuple[str, ...] = tuple(
    [f"hist_{c}" for c in BEHAVIOR_CLASSES]
    + [
        "n_nodes",
        "n_edges",
        "density",
        "n_scopes",
        "max_repeat",
        "distinct_classes",
        "seq_depth",
        "n_files",
        "n_import_classes",
        "has_setup",
        "has_postinstall",
        "parse_fail_files",
    ]
)


def language_of(path: str) -> Optional[str]:
    return _LANG_BY_EXT.get(os.path.splitext(path)[1].lower())


def _is_meta(rel: str) -> bool:
    """Hidden files, VCS/config metadata and non-code assets (never code slots)."""
    base = os.path.basename(rel)
    return (
        base.startswith(".")
        or base.lower().endswith(_META_SUFFIXES)
        or base.upper().startswith("LICENSE")
        or base.lower().startswith("contributing")
        or base.lower().startswith("changelog")
        or base.lower().startswith("notice")
        or base.lower().startswith("authors")
        or base.lower().startswith("code_of_conduct")
    )


def select_files(
    files: List[Tuple[str, str]],
    limit: int = MAX_FILES_PER_SAMPLE,
    hook_targets: Optional[List[str]] = None,
) -> List[Tuple[str, str]]:
    """Deterministic file selection, v2 (round-8 BUG-2 fix).

    Order:
      1. package.json first (npm install-hook detection needs it; it is never
         parsed as code), then setup.py (PyPI entry point) — by shallowest path.
      2. npm install-hook .js targets referenced by package.json scripts
         (entry_kind=postinstall; computed on the FULL file list so hooks are
         not lost to the 12-file cap).
      3. priority entry code files (index.js/main.js/app.js, install hooks by
         name); at most ONE __init__.py (the shallowest, ties alphabetical) —
         the old rule flooded slots with every package __init__.py.
      4. remaining slots: code files only (.py/.js/.mjs/.cjs), non-hidden,
         NOT metadata, sorted by (size desc, path asc) — larger files are more
         likely to carry mapped calls than meta files.

    Deterministic; caps unchanged (12 files, 100 KB each, disclosed).
    """
    by_rel = {rel: abs_ for rel, abs_ in files}
    picked: List[str] = []

    def _take(rels: List[str]) -> None:
        for rel in rels:
            if rel in by_rel and rel not in picked and len(picked) < limit:
                picked.append(rel)

    def _depth(rel: str) -> int:
        return rel.count("/")

    # 1. entry metadata / entry points
    _take(sorted((r for r in by_rel if os.path.basename(r) == "package.json"),
                 key=lambda r: (_depth(r), r)))
    _take(sorted((r for r in by_rel if os.path.basename(r) == "setup.py"),
                 key=lambda r: (_depth(r), r)))

    # 2. npm install-hook targets (parsed with entry_kind=postinstall)
    if hook_targets:
        _take(sorted(set(hook_targets), key=lambda r: (_depth(r), r)))

    # 3. priority entry code files; at most one __init__.py
    inits = sorted((r for r in by_rel if os.path.basename(r) == "__init__.py"),
                   key=lambda r: (_depth(r), r))
    _take(inits[:1])
    for p in _PRIORITY_FILES:
        if p == "__init__.py":
            continue
        _take(sorted((r for r in by_rel if os.path.basename(r) == p and r not in picked),
                     key=lambda r: (_depth(r), r)))

    # 4. fill with code files by (size desc, path asc)
    def _size(rel: str) -> int:
        try:
            return os.path.getsize(by_rel[rel])
        except OSError:
            return 0

    rest = [
        r for r in by_rel
        if r not in picked
        and r.lower().endswith(_CODE_EXTS)
        and not _is_meta(r)
    ]
    rest.sort(key=lambda r: (-_size(r), _depth(r), r))
    _take(rest)

    return [(rel, by_rel[rel]) for rel in picked[:limit]]


def extract_archive(archive: str, dest: str) -> List[Tuple[str, str]]:
    """Extract zip/tar/tgz/whl archive into dest; return [(relpath, abspath)]."""
    name = os.path.basename(archive).lower()
    os.makedirs(dest, exist_ok=True)
    if name.endswith((".zip", ".whl")):
        with zipfile.ZipFile(archive) as zf:
            encrypted = any(zinfo.flag_bits & 0x1 for zinfo in zf.infolist())
            if encrypted:
                # malware-dataset convention (DataDog malicious-software-packages-dataset):
                # sample archives are zip-encrypted with the password "infected"
                zf.extractall(dest, pwd=b"infected")
            else:
                zf.extractall(dest)
    elif name.endswith((".tgz", ".tar.gz", ".gz")):
        mode = "r:gz"
        if name.endswith(".gz") and not name.endswith((".tgz", ".tar.gz")):
            mode = "r:gz"
        with tarfile.open(archive, mode) as tf:
            tf.extractall(dest)
    elif name.endswith(".tar"):
        with tarfile.open(archive, "r:") as tf:
            tf.extractall(dest)
    else:
        raise ValueError(f"unsupported archive: {archive}")
    out: List[Tuple[str, str]] = []
    for root, _dirs, fnames in os.walk(dest):
        for fn in fnames:
            ab = os.path.join(root, fn)
            rel = os.path.relpath(ab, dest)
            out.append((rel, ab))
    return sorted(out)


def _npm_postinstall_targets(files: List[Tuple[str, str]]) -> List[str]:
    """Relative paths of js files referenced by package.json install scripts."""
    pj = None
    for rel, abs_ in files:
        if rel.endswith("package.json"):
            pj = abs_
            break
    if pj is None:
        return []
    try:
        with open(pj, "r", encoding="utf-8", errors="replace") as f:
            meta = json.load(f)
    except Exception:
        return []
    scripts = meta.get("scripts", {}) or {}
    targets: List[str] = []
    for key in ("preinstall", "install", "postinstall"):
        cmd = scripts.get(key)
        if not cmd:
            continue
        for tok in str(cmd).replace("\\", "/").split():
            if tok.endswith(".js"):
                base = os.path.basename(tok)
                for rel, _abs in files:
                    if os.path.basename(rel) == base and rel not in targets:
                        targets.append(rel)
    return targets


def extract_sample_graphs(archive: str, ecosystem: str, sample_id: str, workdir: Optional[str] = None) -> dict:
    """Extract one sample archive -> merged behavior graph dict.

    Parse-failure accounting: files that fail to parse are counted in
    parse_fail_files and disclosed; they never raise.
    """
    tmp = workdir or tempfile.mkdtemp(prefix="packguard_")
    cleanup = workdir is None
    try:
        files = extract_archive(archive, tmp)
        # skip vendored/dup trees deterministically
        files = [
            (rel, abs_)
            for rel, abs_ in files
            if ("/node_modules/" not in f"/{rel}" and "/.git/" not in f"/{rel}")
        ]
        # BUG-2 fix: resolve install-hook targets on the FULL file list BEFORE
        # the 12-file cap, so the cap can no longer drop the very files the
        # hooks reference; select_files force-includes them.
        postinstall = set(_npm_postinstall_targets(files))
        files = select_files(files, hook_targets=sorted(postinstall))
        graphs = []
        for rel, abs_ in files:
            lang = language_of(rel)
            if lang is None:
                continue
            try:
                if os.path.getsize(abs_) > MAX_FILE_BYTES:
                    with open(abs_, "rb") as f:
                        src = f.read(MAX_FILE_BYTES).decode("utf-8", "replace")
                else:
                    with open(abs_, "r", encoding="utf-8", errors="replace") as f:
                        src = f.read()
            except OSError:
                continue
            if rel in postinstall:
                kind = "postinstall"
            elif os.path.basename(rel) == "setup.py":
                kind = "setup"
            else:
                kind = "lib"
            graphs.append(build_graph(src, lang, file=rel, entry_kind=kind))
        merged = merge_graphs(graphs, sample_id)
        merged["ecosystem"] = ecosystem
        merged["n_scopes"] = len({s for g in graphs for s in g["scopes"]})
        return merged
    finally:
        if cleanup:
            import shutil

            shutil.rmtree(tmp, ignore_errors=True)


def compute_features(merged: dict) -> Dict[str, float]:
    """Graph-level features from a merged sample graph."""
    hist = {c: 0 for c in BEHAVIOR_CLASSES}
    for n in merged["nodes"]:
        hist[n["cls"]] += 1
    n_nodes, n_edges = merged["n_nodes"], merged["n_edges"]
    density = (n_edges / (n_nodes * (n_nodes - 1))) if n_nodes > 1 else 0.0

    # seq features: longest same-class run + longest path in DAG (seq+data)
    seq_edges = [e for e in merged["edges"] if e["kind"] == "seq"]
    max_repeat = 0
    if seq_edges:
        run = 1
        prev = merged["nodes"][seq_edges[0]["src"]]["cls"]
        max_repeat = 1
        for e in seq_edges + [{"src": seq_edges[-1]["dst"], "dst": None, "kind": "seq"}]:
            cur = merged["nodes"][e["src"]]["cls"] if e.get("dst") is not None else None
            if e.get("dst") is None:
                break
            if cur == prev:
                run += 1
            else:
                run = 1
            max_repeat = max(max_repeat, run)
            prev = cur

    # longest path (node count) over seq+data edges, memoized DFS (edges point forward
    # by construction; cycles are impossible for seq, guarded for data by visited set)
    adj: Dict[int, List[int]] = {}
    for e in merged["edges"]:
        adj.setdefault(e["src"], []).append(e["dst"])
    memo: Dict[int, int] = {}

    def depth(n: int, seen: set) -> int:
        if n in memo:
            return memo[n]
        if n in seen:
            return 1
        best = 1
        seen.add(n)
        for m in adj.get(n, []):
            best = max(best, 1 + depth(m, seen))
        seen.discard(n)
        memo[n] = best
        return best

    seq_depth = max((depth(i, set()) for i in range(n_nodes)), default=0) if n_nodes else 0

    import_classes = {i["cls"] for i in merged.get("imports", [])}
    feats = {}
    for c in BEHAVIOR_CLASSES:
        feats[f"hist_{c}"] = float(hist[c])
    feats.update(
        {
            "n_nodes": float(n_nodes),
            "n_edges": float(n_edges),
            "density": float(density),
            "n_scopes": float(merged.get("n_scopes", 0)),
            "max_repeat": float(max_repeat),
            "distinct_classes": float(sum(1 for c in BEHAVIOR_CLASSES if hist[c] > 0)),
            "seq_depth": float(seq_depth),
            "n_files": float(len(merged.get("files", []))),
            "n_import_classes": float(len(import_classes)),
            "has_setup": float(any(f["entry_kind"] == "setup" for f in merged.get("files", []))),
            "has_postinstall": float(any(f["entry_kind"] == "postinstall" for f in merged.get("files", []))),
            "parse_fail_files": float(merged.get("parse_fail_files", 0)),
        }
    )
    return feats


def main() -> None:
    ap = argparse.ArgumentParser(description="PackGuard feature extraction")
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--outdir", default="outputs/packguard/features")
    ap.add_argument("--tag", default="v1")
    args = ap.parse_args()

    with open(args.manifest, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    samples = manifest["samples"]
    os.makedirs(args.outdir, exist_ok=True)

    rows: List[dict] = []
    graph_path = os.path.join(args.outdir, f"graphs_{args.tag}.jsonl.gz")
    n_ok = n_empty = n_err = 0
    with gzip.open(graph_path, "wt", encoding="utf-8") as gf:
        for i, s in enumerate(samples):
            try:
                merged = extract_sample_graphs(s["archive_path"], s["ecosystem"], s["sample_id"])
            except Exception as exc:  # disclose, never silent
                rows.append(
                    {
                        "sample_id": s["sample_id"],
                        "ecosystem": s["ecosystem"],
                        "label": s["label"],
                        "extraction_error": f"{type(exc).__name__}: {exc}",
                    }
                )
                n_err += 1
                continue
            feats = compute_features(merged)
            row = {
                "sample_id": s["sample_id"],
                "ecosystem": s["ecosystem"],
                "label": s["label"],
                "label_source": s["label_source"],
                "package": s.get("package") or s["sample_id"],
            }
            row.update(feats)
            rows.append(row)
            gf.write(json.dumps(merged, sort_keys=True) + "\n")
            if feats["n_nodes"] > 0:
                n_ok += 1
            else:
                n_empty += 1
            if (i + 1) % 50 == 0:
                print(f"  {i + 1}/{len(samples)}", flush=True)

    # parquet + jsonl
    import pandas as pd

    ftag = args.tag
    pdf = pd.DataFrame(rows)
    parquet_path = os.path.join(args.outdir, f"features_{ftag}.parquet")
    pdf.to_parquet(parquet_path, index=False)
    jsonl_path = os.path.join(args.outdir, f"features_{ftag}.jsonl")
    pdf.to_json(jsonl_path, orient="records", lines=True)

    report = {
        "schema_version": SCHEMA_VERSION,
        "feature_names": list(FEATURE_NAMES),
        "n_samples": len(samples),
        "n_rows": len(rows),
        "n_with_graph": n_ok,
        "n_empty_graph": n_empty,
        "n_extraction_error": n_err,
        "extraction_caps": {
            "max_files_per_sample": MAX_FILES_PER_SAMPLE,
            "max_file_bytes": MAX_FILE_BYTES,
            "priority_files": _PRIORITY_FILES,
        },
        "manifest": os.path.abspath(args.manifest),
        "outputs": {
            "parquet": os.path.abspath(parquet_path),
            "jsonl": os.path.abspath(jsonl_path),
            "graphs": os.path.abspath(graph_path),
        },
    }
    with open(os.path.join(args.outdir, f"extraction_report_{ftag}.json"), "w") as f:
        json.dump(report, f, indent=2)
    print(json.dumps({k: v for k, v in report.items() if k != "feature_names"}, indent=2))


if __name__ == "__main__":
    main()
