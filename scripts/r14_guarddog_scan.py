#!/usr/bin/env python
"""Round 14 (W) — GuardDog rule-based baseline on the PackGuard 603-sample corpus.

Phases (resume-safe, run with .venv-gd/bin/python):
  python scripts/r14_guarddog_scan.py extract   # G2: extract 603 archives to extracted/<sample_id>/
  python scripts/r14_guarddog_scan.py scan      # G4: YARA-source scan per extracted dir -> findings.jsonl

Pre-registration: configs/packguard_guarddog.yaml (written BEFORE any scan).
No fabricated numbers: every row is a real scan of a real extracted tree.

Env note: guarddog 3.2.0 requires Python <=3.11 -> dedicated .venv-gd (3.11.15).
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import sys
import tarfile
import time
import zipfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "data/packguard/manifests/dataset_v2.json"
OUT = ROOT / "outputs/packguard/guarddog"
EXTRACT = OUT / "extracted"
FINDINGS = OUT / "findings.jsonl"
SPLITS = OUT / "split_membership.json"
PASSWORD = b"infected"  # DataDog malicious-software-packages-dataset convention
TIMEBOX_EXTRACT_S = 30 * 60
PER_SAMPLE_TIMEOUT_S = 120
RETRIES = 1
ARCHIVE_EXTS = {".zip", ".whl", ".egg", ".tgz", ".tar.gz", ".gz"}


# --------------------------------------------------------------------------- paths
def safe_target(root: Path, member_name: str) -> Path | None:
    """Sanitize an archive member path into root; None if it escapes."""
    name = member_name.lstrip("/")
    if not name or name.endswith("/") or name.endswith("\\"):
        pass
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return None
    return root.joinpath(*parts)


def safe_extract_zip(zf: zipfile.ZipFile, dest: Path, pwd: bytes | None) -> tuple[int, list[str]]:
    n, problems = 0, []
    for info in zf.infolist():
        if info.is_dir():
            t = safe_target(dest, info.filename)
            if t is not None:
                t.mkdir(parents=True, exist_ok=True)
            continue
        t = safe_target(dest, info.filename)
        if t is None:
            problems.append(f"unsafe-path:{info.filename}")
            continue
        t.parent.mkdir(parents=True, exist_ok=True)
        try:
            data = zf.read(info, pwd=pwd)
        except RuntimeError as e:
            problems.append(f"read-fail:{info.filename}:{e}")
            continue
        t.write_bytes(data)
        n += 1
    return n, problems


def safe_extract_tar(tf: tarfile.TarFile, dest: Path) -> tuple[int, list[str]]:
    n, problems = 0, []
    for m in tf.getmembers():
        if not (m.isfile() or m.isdir() or m.issym() or m.islnk()):
            problems.append(f"special:{m.name}")
            continue
        if m.issym() or m.islnk():
            problems.append(f"link-skipped:{m.name}")
            continue
        t = safe_target(dest, m.name)
        if t is None:
            problems.append(f"unsafe-path:{m.name}")
            continue
        if m.isdir():
            t.mkdir(parents=True, exist_ok=True)
            continue
        t.parent.mkdir(parents=True, exist_ok=True)
        src = tf.extractfile(m)
        if src is None:
            problems.append(f"nofile:{m.name}")
            continue
        t.write_bytes(src.read())
        n += 1
    return n, problems


def expand_nested(dest: Path) -> int:
    """Recursively extract archives nested inside dest; delete them after."""
    rounds = 0
    expanded = 0
    while rounds < 5:
        rounds += 1
        found = False
        for p in sorted(dest.rglob("*")):
            if not p.is_file():
                continue
            exts = [sfx for sfx in p.suffixes if sfx.lower() in ARCHIVE_EXTS or
                    (p.name.lower().endswith(".tar.gz") and sfx == ".gz")]
            if not p.name.lower().endswith(tuple(ARCHIVE_EXTS)):
                continue
            found = True
            inner = p.with_name(p.name + "__inner")
            inner.mkdir(parents=True, exist_ok=True)
            try:
                if p.name.lower().endswith((".zip", ".whl", ".egg")):
                    with zipfile.ZipFile(p) as zf:
                        safe_extract_zip(zf, inner, pwd=PASSWORD)
                else:
                    try:
                        with tarfile.open(p) as tf:
                            safe_extract_tar(tf, inner)
                    except tarfile.ReadError:
                        with zipfile.ZipFile(p) as zf:
                            safe_extract_zip(zf, inner, pwd=PASSWORD)
                n_files = sum(1 for q in inner.rglob("*") if q.is_file())
                if n_files == 0:
                    shutil.rmtree(inner, ignore_errors=True)
                else:
                    expanded += n_files
                    p.unlink()
            except Exception:
                shutil.rmtree(inner, ignore_errors=True)  # leave the archive file in place
        if not found:
            break
    return expanded


def extract_one(sample: dict, dest: Path) -> dict:
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    arc = Path(sample["archive_path"])
    problems: list[str] = []
    n = 0
    if arc.name.lower().endswith(".zip"):
        with zipfile.ZipFile(arc) as zf:
            n, problems = safe_extract_zip(zf, dest, pwd=PASSWORD)
    elif arc.name.lower().endswith(".whl"):
        with zipfile.ZipFile(arc) as zf:
            n, problems = safe_extract_zip(zf, dest, pwd=None)
    else:  # .tgz / .tar.gz
        with tarfile.open(arc) as tf:
            n, problems = safe_extract_tar(tf, dest)
    nested = expand_nested(dest)
    total = sum(1 for q in dest.rglob("*") if q.is_file())
    ok = total > 0 and not any(p.startswith(("unsafe-path", "read-fail")) for p in problems)
    return {"n_files": total, "n_direct": n, "n_from_nested": nested,
            "problems": problems[:5], "ok": ok}


def phase_extract() -> None:
    t0 = time.time()
    man = json.load(open(MANIFEST))
    EXTRACT.mkdir(parents=True, exist_ok=True)
    status_path = OUT / "extract_status.json"
    status = json.load(open(status_path)) if status_path.exists() else {}
    log = open(OUT / "extract.log", "a")
    for i, s in enumerate(man["samples"], 1):
        sid = s["sample_id"]
        if status.get(sid, {}).get("ok") and (EXTRACT / sid).exists():
            continue
        dest = EXTRACT / sid
        try:
            r = extract_one(s, dest)
        except Exception as e:  # noqa: BLE001
            r = {"n_files": 0, "n_direct": 0, "n_from_nested": 0,
                 "problems": [f"exception:{type(e).__name__}:{e}"], "ok": False}
        r.update({"sample_id": sid, "ecosystem": s["ecosystem"], "label": s["label"],
                  "archive": s["archive_name"]})
        status[sid] = r
        if not r["ok"]:
            log.write(json.dumps(r) + "\n")
            log.flush()
        if i % 50 == 0:
            done_ok = sum(1 for v in status.values() if v.get("ok"))
            print(f"[{i}/{len(man['samples'])}] ok={done_ok} "
                  f"fail={sum(1 for v in status.values() if not v.get('ok'))} "
                  f"elapsed={time.time()-t0:.0f}s", flush=True)
        if time.time() - t0 > TIMEBOX_EXTRACT_S:
            print("TIMEBOX hit, stopping early (resume-safe)", flush=True)
            break
    json.dump(status, open(status_path, "w"), indent=0)
    ok = sum(1 for v in status.values() if v.get("ok"))
    print(f"EXTRACT DONE ok={ok} fail={len(status)-ok} "
          f"of {len(man['samples'])} in {time.time()-t0:.0f}s", flush=True)
    fails_by_label = Counter((v["ecosystem"], v["label"]) for v in status.values() if not v.get("ok"))
    print("failures by (eco,label):", dict(fails_by_label), flush=True)


# --------------------------------------------------------------------------- scan
def run_scan() -> None:
    from guarddog.analyzer.analyzer import Analyzer
    from guarddog.analyzer.sourcecode import get_sourcecode_rules, YaraRule
    from guarddog.ecosystems import ECOSYSTEM

    man = json.load(open(MANIFEST))
    splits = json.load(open(SPLITS))
    analyzers = {eco: Analyzer(ECOSYSTEM.NPM if eco == "npm" else ECOSYSTEM.PYPI)
                 for eco in ("npm", "pypi")}
    severities = {}
    for eco in ("npm", "pypi"):
        eco_key = ECOSYSTEM.NPM if eco == "npm" else ECOSYSTEM.PYPI
        severities[eco] = {r.id: getattr(r, "severity", None)
                           for r in get_sourcecode_rules(eco_key, YaraRule)}

    class Timeout(Exception):
        pass

    def _alarm(signum, frame):
        raise Timeout()

    signal.signal(signal.SIGALRM, _alarm)

    done: set[str] = set()
    if FINDINGS.exists():
        for line in open(FINDINGS):
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if r.get("scan_status") == "ok":
                done.add(r["sample_id"])

    splits_of = lambda sid: {k for k, ids in splits.items() if sid in set(ids)}
    n_ok = n_timeout = n_error = 0
    log = open(OUT / "scan_run.log", "a")
    t0 = time.time()
    with open(FINDINGS, "a") as out:
        for i, s in enumerate(man["samples"], 1):
            sid = s["sample_id"]
            if sid in done:
                continue
            path = EXTRACT / sid
            if not path.exists() or not any(p.is_file() for p in path.rglob("*")):
                row = {"sample_id": sid, "ecosystem": s["ecosystem"], "label": s["label"],
                       "split_membership": sorted(splits_of(sid)), "score": None,
                       "verdict": None, "rules_triggered": [], "rules_triggered_all": [],
                       "scan_status": "error",
                       "error": "missing-or-empty extraction (0 files)", "n_attempts": 0}
                out.write(json.dumps(row) + "\n")
                out.flush()
                n_error += 1
                continue
            status, error, src = "error", None, None
            for attempt in range(1, RETRIES + 2):
                try:
                    signal.alarm(PER_SAMPLE_TIMEOUT_S)
                    t1 = time.time()
                    res = analyzers[s["ecosystem"]].analyze_sourcecode(str(path))
                    meta = analyzers[s["ecosystem"]].analyze_metadata(str(path), None)
                    signal.alarm(0)
                    src = {"sourcecode": res, "metadata": meta, "seconds": round(time.time() - t1, 3)}
                    status = "ok"
                    break
                except Timeout:
                    signal.alarm(0)
                    status, error = "timeout", f"timeout>{PER_SAMPLE_TIMEOUT_S}s"
                except Exception as e:  # noqa: BLE001
                    signal.alarm(0)
                    status, error = "error", f"{type(e).__name__}: {e}"
            row = {"sample_id": sid, "ecosystem": s["ecosystem"], "label": s["label"],
                   "split_membership": sorted(splits_of(sid))}
            if status == "ok" and src is not None:
                high_rules, all_rules, findings = [], [], {}
                for rule, rres in src["sourcecode"]["results"].items():
                    matches = rres if isinstance(rres, list) else ((rres or {}).get("matches") or [])
                    if matches:
                        all_rules.append(rule)
                        if severities[s["ecosystem"]].get(rule) in ("critical", "high"):
                            high_rules.append(rule)
                        findings[rule] = len(matches)
                md_issues = src["metadata"].get("issues", 0)
                md_errors = src["metadata"].get("errors", {})
                row.update({
                    "score": len(high_rules),
                    "verdict": 1 if len(high_rules) >= 1 else 0,
                    "rules_triggered": sorted(high_rules),
                    "rules_triggered_all": sorted(all_rules),
                    "n_matches_by_rule": findings,
                    "metadata_issues": md_issues,
                    "metadata_errors": sorted(md_errors.keys()),
                    "scan_seconds": src["seconds"],
                    "scan_status": "ok", "error": None, "n_attempts": 1})
                n_ok += 1
            else:
                row.update({"score": None, "verdict": None, "rules_triggered": [],
                            "rules_triggered_all": [], "scan_status": status,
                            "error": error, "n_attempts": RETRIES + 1})
                if status == "timeout":
                    n_timeout += 1
                else:
                    n_error += 1
                log.write(json.dumps(row) + "\n")
                log.flush()
            out.write(json.dumps(row) + "\n")
            out.flush()
        if i % 25 == 0:
            print(f"[{i}] ok={n_ok} timeout={n_timeout} error={n_error} "
                  f"elapsed={time.time()-t0:.0f}s", flush=True)
    print(f"SCAN DONE ok={n_ok} timeout={n_timeout} error={n_error} "
          f"in {time.time()-t0:.0f}s", flush=True)
    log.close()


if __name__ == "__main__":
    phase = sys.argv[1] if len(sys.argv) > 1 else "extract"
    OUT.mkdir(parents=True, exist_ok=True)
    if phase == "extract":
        phase_extract()
    elif phase == "scan":
        run_scan()
    else:
        raise SystemExit(f"unknown phase {phase}")
