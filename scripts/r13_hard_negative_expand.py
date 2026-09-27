#!/usr/bin/env python
"""r13_hard_negative_expand.py -- AMENDMENT-7 A7.4 (round 13, W1).

Hard-negative benign expansion: RANDOM (NOT popularity-ranked) npm packages
drawn from the live registry, to add benign packages WITH install hooks /
network calls (the FP-prone profile the popularity-ranked benign pool
lacks). Time-boxed (default 480 s wall per invocation, RESUME-safe).

Candidate names: dependency names parsed from package.json inside the
ALREADY-DOWNLOADED corpus tarballs (data/packguard/raw/benign/npm/*.tgz),
excluding every package already in the corpus. Seeded shuffle 20260922.
Per candidate:
  GET registry.npmjs.org/<name> -> dist-tags.latest tarball
  -> skip if content-length > 2.5 MB (corpus cap)
  -> download to data/packguard/raw/benign_random/npm/
  -> sha256; graph+features via packguard.features (UNCHANGED v2 pipeline:
     extract_sample_graphs + compute_features); text via the SAME
     selection/caps as scripts/packguard_final_runs.build_text_cache.
Labels carry the SAME disclosed caveat as the corpus benign pool:
"assumed benign via registry presence; not individually audited".
This expansion does NOT enter the registered LCO grid (A7.4); it is a
dataset contribution with its own manifest + features under
outputs/packguard/lco/expansion/.

Run: .venv/bin/python scripts/r13_hard_negative_expand.py \
        [--deadline-seconds 480] [--target 200]
Outputs:
  data/packguard/manifests/benign_expansion_v1.json
  outputs/packguard/lco/expansion/{features_expansion_v1.jsonl,
      text_expansion_v1.json, expansion_report.json}
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path("/Users/macbook/.zcode/workspace/default/refuseguard")
CORPUS_TGZ_DIR = ROOT / "data/packguard/raw/benign/npm"
OUT_RAW = ROOT / "data/packguard/raw/benign_random/npm"
OUT_EXP = ROOT / "outputs/packguard/lco/expansion"
MANIFEST_OUT = ROOT / "data/packguard/manifests/benign_expansion_v1.json"
CORPUS_FEATURES = ROOT / "outputs/packguard/features/features_v2.jsonl"
SEED = 20260922
MAX_TARBALL_BYTES = 2_500_000  # corpus cap (prereg D2)
LABEL_SOURCE = ("assumed benign: present in the live npm registry at fetch "
                "time (random dependency-derived draw, NOT popularity-"
                "ranked); not individually audited")


def log(msg: str) -> None:
    print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] {msg}",
          flush=True)


def candidate_names() -> list[str]:
    """Dependency names from corpus package.json files, minus corpus pkgs."""
    corpus_pkgs: set[str] = set()
    for line in CORPUS_FEATURES.open(encoding="utf-8"):
        if line.strip():
            corpus_pkgs.add(json.loads(line)["package"])
    names: set[str] = set()
    n_tgz = 0
    for tgz in sorted(CORPUS_TGZ_DIR.glob("*.tgz")):
        try:
            with tarfile.open(tgz, "r:gz") as tf:
                for m in tf.getmembers():
                    if not m.name.endswith("package.json"):
                        continue
                    f = tf.extractfile(m)
                    if f is None:
                        continue
                    meta = json.loads(f.read(MAX_TARBALL_BYTES).decode(
                        "utf-8", "replace"))
                    for key in ("dependencies", "optionalDependencies",
                                "devDependencies"):
                        for dep in (meta.get(key) or {}):
                            names.add(dep)
                    break
            n_tgz += 1
        except Exception:
            continue
    cands = sorted(names - corpus_pkgs)
    rng = random.Random(SEED)
    rng.shuffle(cands)
    log(f"candidates: {len(cands)} deps from {n_tgz} corpus tarballs "
        f"({len(names)} raw, {len(names & corpus_pkgs)} already in corpus); "
        f"seeded shuffle {SEED}")
    return cands


def fetch(url: str, timeout: int = 20) -> tuple[int, bytes]:
    req = urllib.request.Request(url, headers={"User-Agent": "packguard-r13"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--deadline-seconds", type=int, default=480)
    ap.add_argument("--target", type=int, default=200)
    ap.add_argument("--max-consecutive-failures", type=int, default=10)
    args = ap.parse_args()
    t0 = time.time()
    deadline = t0 + args.deadline_seconds

    from packguard.features import (MAX_FILE_BYTES, _npm_postinstall_targets,
                                    compute_features, extract_archive,
                                    extract_sample_graphs, language_of,
                                    select_files)

    OUT_RAW.mkdir(parents=True, exist_ok=True)
    OUT_EXP.mkdir(parents=True, exist_ok=True)

    # resume state
    done: dict[str, dict] = {}
    if (OUT_EXP / "expansion_report.json").exists():
        try:
            prev = json.load((OUT_EXP / "expansion_report.json").open())
            done = {s["package"]: s for s in prev.get("samples", [])}
            log(f"resume: {len(done)} already downloaded")
        except Exception:
            done = {}

    cands = candidate_names()
    stats = {"attempted": 0, "downloaded": 0, "failed": 0,
             "fail_reasons": {}, "skipped_too_big": 0,
             "consecutive_failures": 0, "stopped_reason": None}
    samples: list[dict] = list(done.values())

    def fail(pkg: str, why: str) -> None:
        stats["failed"] += 1
        stats["fail_reasons"][why] = stats["fail_reasons"].get(why, 0) + 1
        stats["consecutive_failures"] += 1
        log(f"  FAIL {pkg}: {why}")

    for pkg in cands:
        if len(done) >= args.target:
            stats["stopped_reason"] = "target reached"
            break
        if time.time() > deadline:
            stats["stopped_reason"] = "time-box expired"
            break
        if stats["consecutive_failures"] >= args.max_consecutive_failures:
            stats["stopped_reason"] = f">={args.max_consecutive_failures} consecutive failures"
            break
        if pkg in done:
            continue
        stats["attempted"] += 1
        url = "https://registry.npmjs.org/" + urllib.parse.quote(pkg, safe="")
        try:
            status, blob = fetch(url, timeout=15)
            meta = json.loads(blob)
            ver = meta["dist-tags"]["latest"]
            vmeta = meta["versions"][ver]
            tarball = vmeta["dist"]["tarball"]
            size = vmeta["dist"].get("unpackedSize")
        except Exception as exc:
            fail(pkg, f"registry:{type(exc).__name__}")
            continue
        stats["consecutive_failures"] = 0
        safe = pkg.replace("/", "__").replace("@", "")
        out_path = OUT_RAW / f"{safe}__{ver}.tgz"
        try:
            status, blob = fetch(tarball, timeout=30)
            if len(blob) > MAX_TARBALL_BYTES:
                stats["skipped_too_big"] += 1
                log(f"  SKIP {pkg}: tarball {len(blob)} > cap")
                continue
            out_path.write_bytes(blob)
        except Exception as exc:
            fail(pkg, f"download:{type(exc).__name__}")
            continue
        sha = hashlib.sha256(out_path.read_bytes()).hexdigest()
        sample_id = f"npm-benign_random-{safe}__{ver}.tgz"
        try:
            merged = extract_sample_graphs(str(out_path), "npm", sample_id)
            feats = compute_features(merged)
            # text with the EXACT v2 cache recipe
            tmp = tempfile.mkdtemp(prefix="pgr13_")
            files = extract_archive(str(out_path), tmp)
            files = [(rel, ab) for rel, ab in files
                     if "/node_modules/" not in f"/{rel}"
                     and "/.git/" not in f"/{rel}"]
            hooks = set(_npm_postinstall_targets(files))
            files = select_files(files, hook_targets=sorted(hooks))
            parts = []
            for rel, ab in files:
                if language_of(rel) is None:
                    continue
                try:
                    with open(ab, "rb") as f:
                        parts.append(f.read(MAX_FILE_BYTES).decode(
                            "utf-8", "replace"))
                except OSError:
                    continue
            text = "\n".join(parts)
        except Exception as exc:
            fail(pkg, f"pipeline:{type(exc).__name__}:{exc}")
            out_path.unlink(missing_ok=True)
            continue
        rec = {
            "sample_id": sample_id, "ecosystem": "npm", "label": 0,
            "label_source": LABEL_SOURCE, "package": pkg, "version": ver,
            "source_url": url, "archive_path": str(out_path),
            "archive_name": out_path.name, "archive_sha256": sha,
        }
        rec.update(feats)
        rec["expansion_text"] = text
        samples.append(rec)
        done[pkg] = rec
        stats["downloaded"] += 1
        if stats["downloaded"] % 10 == 0:
            log(f"  downloaded {stats['downloaded']} "
                f"(elapsed {time.time()-t0:.0f}s)")

    # write features jsonl (flat schema like features_v2) + text + manifest
    feats_path = OUT_EXP / "features_expansion_v1.jsonl"
    text_path = OUT_EXP / "text_expansion_v1.json"
    with feats_path.open("w", encoding="utf-8") as f:
        for rec in samples:
            row = {k: v for k, v in rec.items() if k != "expansion_text"}
            f.write(json.dumps(row, sort_keys=True) + "\n")
    text_path.write_text(json.dumps(
        {r["sample_id"]: r["expansion_text"] for r in samples}),
        encoding="utf-8")

    n_hook = sum(1 for r in samples if float(r.get("has_postinstall", 0)) > 0)
    n_net = sum(1 for r in samples if float(r.get("hist_NETWORK", 0)) > 0)
    n_hard = sum(1 for r in samples
                 if float(r.get("has_postinstall", 0)) > 0
                 or float(r.get("hist_NETWORK", 0)) > 0)
    manifest = {
        "schema_version": "benign-expansion-v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "seed": SEED,
        "selection": (
            "RANDOM benign npm packages: dependency names harvested from "
            "package.json of the 123 corpus benign npm tarballs, minus "
            "corpus packages, seeded shuffle 20260922, dist-tags.latest of "
            "each candidate from registry.npmjs.org; tarball cap 2.5 MB "
            "(same as corpus); NOT popularity-ranked"),
        "label_policy": LABEL_SOURCE,
        "disclosure": (
            "Hard-negative expansion per AMENDMENT-7 A7.4; does NOT enter "
            "the registered LCO grid; features extracted with the UNCHANGED "
            "v2 pipeline (extract_sample_graphs + compute_features); text "
            "with the exact v2 cache recipe"),
        "time_box_seconds": args.deadline_seconds,
        "stats": stats,
        "counts": {
            "n_samples": len(samples),
            "with_postinstall": n_hook,
            "with_network_calls": n_net,
            "hard_negative_profile (hook OR network)": n_hard,
        },
        "samples": samples,
    }
    MANIFEST_OUT.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_OUT.write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    (OUT_EXP / "expansion_report.json").write_text(json.dumps(
        {"stats": stats, "counts": manifest["counts"],
         "samples": samples}, indent=1), encoding="utf-8")
    log(f"DONE: {stats['downloaded']} downloaded / {stats['attempted']} "
        f"attempted in {time.time()-t0:.0f}s; stopped: "
        f"{stats['stopped_reason']}; hard-negative profile (hook OR net): "
        f"{n_hard}/{len(samples)}")
    log(f"manifest -> {MANIFEST_OUT}")


if __name__ == "__main__":
    main()
