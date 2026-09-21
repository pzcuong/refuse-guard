"""Dataset manifest construction for PackGuard.

Sources (all labels come from the dataset source, never self-assigned):
- Malicious: DataDog `malicious-software-packages-dataset` (github.com/DataDog/
  malicious-software-packages-dataset), classes `malicious_intent` and
  `compromised_lib`, ecosystems npm + pypi. Label = 1 with label_source recording
  the exact DataDog class. Sample subset selected by a seeded stride over the
  alphabetical package list (seed 20260922); see manifest["selection"].
- Benign: popularity-ranked package lists — npm registry search (5 generic keywords,
  popularity=1.0) and hugovk/top-pypi-packages (30-day downloads). Label = 0 with
  label_source disclosing "assumed benign via popularity ranking; not individually
  audited".

CLI:
    .venv/bin/python -m packguard.dataset --root data/packguard/raw \
        --out data/packguard/manifests/dataset_v1.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from typing import List, Optional

SEED = 20260922
DD_REPO_URL = "https://github.com/DataDog/malicious-software-packages-dataset"


def sha256_file(path: str, cap: int = 1 << 30) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read(cap))
    return h.hexdigest()


def _dd_samples(raw_root: str) -> List[dict]:
    base = os.path.join(raw_root, "ddmalicious", "samples")
    out: List[dict] = []
    if not os.path.isdir(base):
        return out
    for eco in ("npm", "pypi"):
        for cls in ("malicious_intent", "compromised_lib"):
            d = os.path.join(base, eco, cls)
            if not os.path.isdir(d):
                continue
            for pkg in sorted(os.listdir(d)):
                pkg_dir = os.path.join(d, pkg)
                if not os.path.isdir(pkg_dir):
                    continue
                entries = sorted(os.listdir(pkg_dir))
                version_dirs = [
                    e for e in entries if os.path.isdir(os.path.join(pkg_dir, e))
                ]
                flat_zips = [
                    e for e in entries
                    if os.path.isfile(os.path.join(pkg_dir, e)) and e.endswith(".zip")
                ]
                # layout A: pkg/<version>/<file>.zip
                for ver in version_dirs:
                    ver_dir = os.path.join(pkg_dir, ver)
                    for fn in sorted(os.listdir(ver_dir)):
                        if not fn.endswith(".zip"):
                            continue
                        ab = os.path.join(ver_dir, fn)
                        out.append(
                            {
                                "sample_id": f"{eco}-{cls}-{pkg}-{ver}-{fn[:-4]}",
                                "ecosystem": eco,
                                "label": 1,
                                "label_source": f"DataDog malicious-software-packages-dataset (class={cls})",
                                "package": pkg,
                                "version": ver,
                                "source_url": f"{DD_REPO_URL}/tree/main/samples/{eco}/{cls}/{pkg}",
                                "archive_path": os.path.abspath(ab),
                                "archive_name": fn,
                            }
                        )
                # layout B (BUG-1 fix, round 8): pkg/<file>.zip — single-version
                # packages have NO version directory; the zip sits directly in
                # the package dir (date-stamped filename). Version is recorded
                # as the archive stem and the layout is disclosed in
                # manifest["selection"]["malicious"].
                for fn in flat_zips:
                    ab = os.path.join(pkg_dir, fn)
                    out.append(
                        {
                            "sample_id": f"{eco}-{cls}-{pkg}-flat-{fn[:-4]}",
                            "ecosystem": eco,
                            "label": 1,
                            "label_source": f"DataDog malicious-software-packages-dataset (class={cls})",
                            "package": pkg,
                            "version": fn[:-4],
                            "layout": "flat",
                            "source_url": f"{DD_REPO_URL}/tree/main/samples/{eco}/{cls}/{pkg}",
                            "archive_path": os.path.abspath(ab),
                            "archive_name": fn,
                        }
                    )
    return out


def _benign_samples(raw_root: str, eco: str) -> List[dict]:
    d = os.path.join(raw_root, "benign", eco)
    out: List[dict] = []
    if not os.path.isdir(d):
        return out
    if eco == "npm":
        source = (
            "npm registry search, popularity-ranked, keywords utils/cli/server/web/testing "
            "(assumed benign via popularity ranking; not individually audited)"
        )
    else:
        source = (
            "hugovk/top-pypi-packages 30-day download ranking "
            "(assumed benign via popularity ranking; not individually audited)"
        )
    for fn in sorted(os.listdir(d)):
        ab = os.path.join(d, fn)
        if not os.path.isfile(ab):
            continue
        if eco == "npm" and not fn.endswith(".tgz"):
            continue
        if eco == "pypi" and not fn.endswith((".tar.gz", ".zip", ".whl", ".tar.bz2", ".tar")):
            continue
        pkg = fn.split("__", 1)[0] if "__" in fn else fn.split("-")[0]
        out.append(
            {
                "sample_id": f"{eco}-benign-{fn}",
                "ecosystem": eco,
                "label": 0,
                "label_source": source,
                "package": pkg,
                "version": None,
                "source_url": (
                    "https://registry.npmjs.org/" + pkg if eco == "npm" else "https://pypi.org/project/" + pkg + "/"
                ),
                "archive_path": ab,
                "archive_name": fn,
            }
        )
    return out


def build_manifest(raw_root: str, out_path: str) -> dict:
    samples = _dd_samples(raw_root) + _benign_samples(raw_root, "npm") + _benign_samples(raw_root, "pypi")

    # dedupe identical archives by checksum (defensive; DataDog may repeat payloads)
    seen: dict = {}
    deduped: List[dict] = []
    n_dupes = 0
    for s in samples:
        csum = sha256_file(s["archive_path"])
        s["archive_sha256"] = csum
        key = (s["ecosystem"], s["label"], csum)
        if key in seen:
            n_dupes += 1
            continue
        seen[key] = s["sample_id"]
        deduped.append(s)

    counts = {}
    for s in deduped:
        k = (s["ecosystem"], "malicious" if s["label"] == 1 else "benign")
        counts[k[0] + "/" + k[1]] = counts.get(k[0] + "/" + k[1], 0) + 1

    manifest = {
        "schema_version": "dataset-v1",
        "seed": SEED,
        "selection": {
            "malicious": (
                "DataDog malicious-software-packages-dataset; deterministic stride sample of "
                "alphabetically-sorted package list (stride = floor(N/want), offset seed%stride): "
                "npm/malicious_intent want=100, npm/compromised_lib want=50, "
                "pypi/malicious_intent want=60, pypi/compromised_lib want=10; ALL version zips "
                "of each selected package kept. Two archive layouts handled (round-8 BUG-1 fix): "
                "pkg/<version>/<file>.zip and pkg/<file>.zip (single-version packages, no version "
                "dir; version recorded as the archive stem, sample_id suffix '-flat-')."
            ),
            "benign": (
                "popularity-ranked lists, stride sample with same seed rule; npm want=130 "
                "(pool 1234 from 5 keywords), pypi want=110 (pool 15000); downloads capped at 2.5MB"
            ),
            "near_duplicate_policy": (
                "multiple versions of one malicious package are kept (power) and disclosed; "
                "identical archives deduped by sha256"
            ),
        },
        "label_policy": (
            "labels taken verbatim from source datasets (DataDog classes / popularity-ranked "
            "benign lists); no manual labeling performed"
        ),
        "counts": counts,
        "n_samples": len(deduped),
        "n_duplicate_archives_removed": n_dupes,
        "checksum_algorithm": "sha256 (archive files)",
        "samples": deduped,
    }
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=1)
    return manifest


def main() -> None:
    ap = argparse.ArgumentParser(description="Build PackGuard dataset manifest")
    ap.add_argument("--root", default="data/packguard/raw")
    ap.add_argument("--out", default="data/packguard/manifests/dataset_v1.json")
    args = ap.parse_args()
    m = build_manifest(args.root, args.out)
    print(json.dumps({k: v for k, v in m.items() if k != "samples"}, indent=2))


if __name__ == "__main__":
    main()
