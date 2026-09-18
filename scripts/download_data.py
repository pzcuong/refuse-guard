#!/usr/bin/env python
"""Download the raw datasets used by RefuseGuard into data/raw/ (S-R4).

Fixes V2-R4 BUG-1: README step 1 used to say `python -m src.data.primevul`
"downloads the HF mirror", but that module only reads/validates local files
(its error message points here). Run THIS script first on a fresh clone.

Sources — the same ones used to produce every artifact in the paper:
  - PrimeVul mirror (v0.1-based): HF dataset ``starsofchance/PrimeVul``
    -> data/raw/primevul_hf/ (layout consumed by src/data/primevul.py).
  - OR-Bench (Cui et al., ICML 2025): HF dataset ``bench-llms/or-bench``
    (official CSVs verbatim; dash-named remotely, renamed to the underscore
    layout expected by src/data/contrast.py).
  - XSTest (Roettger et al., NAACL 2024): official repository
    ``paul-rottger/exaggerated-safety`` (GitHub), file xstest_prompts.csv
    (the HF copies are gated/absent; see src/data/contrast.py docstring).

Usage:
    .venv/bin/python scripts/download_data.py                 # download + validate
    .venv/bin/python scripts/download_data.py --skip-validation

Idempotent: already-present non-empty files are kept (HF downloads are
cached/verified by huggingface_hub; the GitHub file is skipped if present).
After this script, re-run the README step 1 validation:
    .venv/bin/python -m src.data.primevul
"""
from __future__ import annotations

import argparse
import shutil
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PRIMEVUL_REPO = "starsofchance/PrimeVul"
PRIMEVUL_DIR = ROOT / "data" / "raw" / "primevul_hf"
PRIMEVUL_PATTERNS = ["primevul_*.jsonl", "README.md", "file_info.json"]

OR_BENCH_REPO = "bench-llms/or-bench"
CONTRAST_DIR = ROOT / "data" / "raw" / "contrast"
# remote filename (dashes) -> local filename (underscores, src/data/contrast.py)
OR_BENCH_FILES = {
    "or-bench-hard-1k.csv": "or_bench_hard_1k.csv",
    "or-bench-toxic.csv": "or_bench_toxic.csv",
}

XSTEST_URL = ("https://raw.githubusercontent.com/paul-rottger/exaggerated-safety/"
              "main/xstest_prompts.csv")
XSTEST_LOCAL = CONTRAST_DIR / "xstest_prompts.csv"


def sha256_16(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def download_primevul() -> list[Path]:
    from huggingface_hub import snapshot_download

    PRIMEVUL_DIR.mkdir(parents=True, exist_ok=True)
    got = snapshot_download(
        repo_id=PRIMEVUL_REPO, repo_type="dataset", local_dir=str(PRIMEVUL_DIR),
        allow_patterns=PRIMEVUL_PATTERNS,
    )
    files = sorted(p for p in Path(got).rglob("*") if p.is_file())
    print(f"[primevul] {PRIMEVUL_REPO} -> {PRIMEVUL_DIR.relative_to(ROOT)} "
          f"({len(files)} files)")
    return files


def download_orbench() -> list[Path]:
    from huggingface_hub import hf_hub_download

    CONTRAST_DIR.mkdir(parents=True, exist_ok=True)
    out = []
    for remote, local in OR_BENCH_FILES.items():
        dst = CONTRAST_DIR / local
        if dst.exists() and dst.stat().st_size > 0:
            print(f"[orbench] keep existing {dst.relative_to(ROOT)}")
            out.append(dst)
            continue
        tmp = hf_hub_download(repo_id=OR_BENCH_REPO, repo_type="dataset",
                              filename=remote)
        shutil.copyfile(tmp, dst)
        print(f"[orbench] {OR_BENCH_REPO}:{remote} -> {dst.relative_to(ROOT)}")
        out.append(dst)
    return out


def download_xstest() -> list[Path]:
    CONTRAST_DIR.mkdir(parents=True, exist_ok=True)
    if XSTEST_LOCAL.exists() and XSTEST_LOCAL.stat().st_size > 0:
        print(f"[xstest] keep existing {XSTEST_LOCAL.relative_to(ROOT)}")
        return [XSTEST_LOCAL]
    with urllib.request.urlopen(XSTEST_URL, timeout=60) as resp:
        XSTEST_LOCAL.write_bytes(resp.read())
    print(f"[xstest] paul-rottger/exaggerated-safety (GitHub) -> "
          f"{XSTEST_LOCAL.relative_to(ROOT)}")
    return [XSTEST_LOCAL]


def validate() -> int:
    """Post-download checks mirroring README step 1 (cheap, local-only)."""
    from src.data import contrast
    from src.data.primevul import DATASET_NAME, validate_primevul

    rep = validate_primevul()
    print(f"[validate] PrimeVul mirror {DATASET_NAME}: status={rep['status']} "
          f"vul={rep['mirror_totals']['vulnerable']} ben={rep['mirror_totals']['benign']} "
          f"dev_vs_paper={rep['deviation_vs_paper']} "
          f"(deviation disclosed in paper §Setup; expected for the v0.1 mirror)")
    n_hard = len(contrast.load_orbench("hard"))
    n_toxic = len(contrast.load_orbench("toxic"))
    n_xs = len(contrast.load_xstest())
    print(f"[validate] contrast corpora readable: or-bench-hard={n_hard}, "
          f"or-bench-toxic={n_toxic}, xstest={n_xs}")
    ok = rep["status"] == "OK" and n_hard > 0 and n_toxic > 0 and n_xs > 0
    if not ok:
        print("[validate] FAILED (status != OK or empty corpus)", file=sys.stderr)
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--skip-validation", action="store_true",
                    help="only download; skip the local count checks")
    args = ap.parse_args()

    files = download_primevul() + download_orbench() + download_xstest()
    print("\n[checksums] sha256_16 of downloaded/kept files")
    for f in sorted(set(files)):
        if any(part.startswith(".") for part in f.relative_to(ROOT).parts):
            continue  # huggingface_hub internal .cache/ metadata — not data
        print(f"  {sha256_16(f)}  {f.relative_to(ROOT)}")
    if args.skip_validation:
        return 0
    return validate()


if __name__ == "__main__":
    raise SystemExit(main())
