"""Round-7 RQ8 runner (CWE generalization of the verdict-bias channel).

Question (docs/round7_prereg.md §1 + Amendment-1 §0b(ii), CHỐT): the benign ->
vulnerable verdict bias under C5 measured on the memory-copy-heavy
bench_attack_v1 — does it GENERALIZE to 4 CWE families outside the
memory-copy cluster (CWE-476/416/190/200, bench_attack_v2), or is it an
artifact of the memcpy/strcpy family mix?

Design (pre-registered configs/round7_rq8.yaml BEFORE any generation):
  - census of bench_attack_v2: 20 benign + 20 vul per family x 4 families,
    gate arms {C0, C5_near} ONLY (D2_task/C5_far not run -> disclosed);
  - models: llama3b (secondary, headroom caveat) then granite2b (PRIMARY),
    queue order per the RQ8 execution mandate;
  - prompts: single source src.conditions.c5_risk_context.build_attack_prompt
    via round5_e0v2.render_prompt (read-only reuse);
  - monitor/thresholds: round5_e0v2.resolve_thresholds/make_monitor/
    classify_output (llama calibrated pair from configs/models.yaml; granite
    DISCLOSED fallback 0.0/0.2);
  - stats: two-sided EXACT binomial McNemar, discordant-only, formula
    p = min(1, 2*sum_{k<=min(b,c)} C(b+c,k)/2^(b+c)) — the variant implemented
    in scripts/collect_master_round7.py (prereg H-G1 power note); paired
    bootstrap CI (n_boot 10000, seed 20260918) alongside;
  - verdict computed-by-rule: H-G1 (>=3/4 families p<0.05 AND b2v>v2b),
    H-G2 (pooled dFP>=0.15 AND p<0.05 AND b2v>v2b), label in
    {GENERALIZES, GENERALIZES-pooled-driven, FAMILY-DEPENDENT};
    per-family AND pooled always reported together (anti-masking clause);
  - refusal NEVER mapped to benign: RR per cell, unpaired/unparsed counts
    disclosed.

Stages:
  python -m src.experiments.round7_rq8 --stage dry            # MockLLM, 8 gen
  python -m src.experiments.round7_rq8 --stage run --model <id> [--job all]
  python -m src.experiments.round7_rq8 --stage manifest       # manifest_cwe.json
  python -m src.experiments.round7_rq8 --stage metrics        # aggregate + verdicts
  python -m src.experiments.round7_rq8 --stage bridge         # collector copies
  python -m src.experiments.round7_rq8 --stage queue-driver   # write queue_driver.py

MODEL-GUARD (round-6 lesson): every checkpoint resume / metrics merge asserts
metadata.model_id == running model id AND config_sha16 == this config's sha.
Collector bridge: COMPLETE per-model results + manifest are byte-copied to
outputs/experiments/round7_cwe/ (the paths registered in prereg §4);
partial checkpoints are never copied.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import time
from collections import Counter
from math import comb
from pathlib import Path
from typing import Any, Callable, Optional

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.experiments.pilot_round2 import (  # noqa: E402 (read-only reuse)
    new_record, write_raw, sha16, now_utc, resolve_revision,
    DEFAULT_HF_HOME, DEFAULT_CACHE,
)
from src.experiments.round5_e0v2 import (  # noqa: E402 (read-only reuse)
    load_bench, render_prompt, resolve_thresholds, make_monitor,
    classify_output, refusal_taxonomy, MockLLM,
)
from src.metrics.stats import mcnemar, bootstrap_ci_diff  # noqa: E402

DEFAULT_CONFIG = PROJECT_ROOT / "configs/round7_rq8.yaml"
ARMS = ["C0", "C5_near"]              # gate arms (C5_near = THE gate arm)
FAMILIES = ("CWE-476", "CWE-416", "CWE-190", "CWE-200")   # Amendment-1 §0b(ii)
FALLBACK_FAMILIES = ("CWE-369", "CWE-434", "CWE-78")
CANONICAL_FAMILIES = FAMILIES + FALLBACK_FAMILIES
MIN_FAMILY_N = 20                     # prereg §2.3 item 5
FAMILIES_EXPECTED = 4
MOCK_MID = "mock/round7-rq8-dry"
MOCK_SLUG = "mockrq8"
DRY_LIMIT = 8                         # mandate: 8-generation dry before full
QUEUE_DRIVER = "queue_driver.py"      # relative to out_dir
EPS = 1e-12

__all__ = ["load_config", "ModelGuardError", "model_guard", "build_manifest",
           "build_jobs", "run_model", "mcnemar_exact_discordant",
           "compute_rq8_metrics", "aggregate_metrics", "bridge_copy", "main"]


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------
def load_config(path: Optional[Path] = None) -> dict:
    p = Path(path) if path else DEFAULT_CONFIG
    cfg = yaml.safe_load(p.read_text(encoding="utf-8"))
    cfg["_config_sha16"] = sha16({k: v for k, v in cfg.items()
                                  if k != "_config_sha16"})
    cfg["_config_path"] = str(p)
    return cfg


def model_id_of(cfg: dict, name: str) -> str:
    mid = (cfg.get("models") or {}).get(name)
    if not mid:
        raise KeyError(f"models.{name} missing from {cfg.get('_config_path')}")
    return mid


# ---------------------------------------------------------------------------
# model guard (round-6 lesson, mandatory on every disk reuse / merge)
# ---------------------------------------------------------------------------
class ModelGuardError(RuntimeError):
    """An on-disk artifact does not belong to the running model/config."""


def model_guard(expected_mid: str, found_mid: Optional[str], ctx: str) -> None:
    if found_mid != expected_mid:
        raise ModelGuardError(
            f"[rq8 model-guard] {ctx}: artifact model_id={found_mid!r} != "
            f"running model {expected_mid!r} — refusing to reuse/merge "
            f"(the prompt-sha gate alone is model-blind)")


# ---------------------------------------------------------------------------
# exact McNemar, discordant-only — the collector's formula, verbatim algebra
# ---------------------------------------------------------------------------
def mcnemar_exact_discordant(b2v: int, v2b: int) -> float:
    """Two-sided exact binomial McNemar on the discordant pairs.

    p = min(1, 2 * sum_{k<=min(b,c)} C(b+c,k) / 2^(b+c)); identical to
    scripts/collect_master_round7.py:mcnemar_exact (prereg §2/H-G1)."""
    n = b2v + v2b
    if n == 0:
        return 1.0
    tail = sum(comb(n, k) for k in range(0, min(b2v, v2b) + 1))
    return min(1.0, 2.0 * tail / 2 ** n)


# ---------------------------------------------------------------------------
# bench -> jobs / manifest
# ---------------------------------------------------------------------------
def canonical_family(value: str) -> str:
    aliases = {
        "CWE-476": "CWE-476", "F-NPD": "CWE-476", "pointer_surface": "CWE-476",
        "CWE-416": "CWE-416", "F-UAF": "CWE-416", "heap_lifecycle": "CWE-416",
        "CWE-190": "CWE-190", "F-INT": "CWE-190", "arith_scaling": "CWE-190",
        "CWE-200": "CWE-200", "F-INFO": "CWE-200", "log_output": "CWE-200",
        "CWE-369": "CWE-369", "CWE-434": "CWE-434", "CWE-78": "CWE-78",
    }
    key = str(value).strip()
    if key not in aliases:
        raise ValueError(
            f"unknown CWE family {value!r} (canonical {CANONICAL_FAMILIES}); "
            f"extensions require an Amendment in docs/round7_prereg.md")
    return aliases[key]


def _advisory_text_of(c5_func: str) -> str:
    """Recover the embedded advisory comment text from a C5-arm function."""
    for m in re.finditer(r"//[^\n]*", c5_func):
        txt = m.group(0)[2:].strip()
        if len(txt) >= 40:          # advisory comments are long by construction
            return " ".join(txt.split()).lower()
    return ""


def build_jobs(cfg: dict, dry: bool = False,
               limit: Optional[int] = None) -> tuple[list[dict], dict]:
    """(job list, bench_meta).  Job order: benign (PRIMARY) then vul;
    within a job (family, sample_id) sorted, arms [C0, C5_near] adjacent so
    every completed sample forms a paired prefix."""
    entries, bench_meta = load_bench({"bench": {"source": cfg["bench"]["source"]}})
    exp_sha = (cfg["bench"].get("sha_expected_jsonl") or "").strip()
    if exp_sha and bench_meta.get("sha256_16") != exp_sha[:16]:
        raise ValueError(
            f"bench sha mismatch: got {bench_meta.get('sha256_16')} != "
            f"expected {exp_sha[:16]} (pre-registered bench changed?)")
    by_sid: dict[str, dict] = {}
    for e in entries:
        if e["arm"] not in ARMS:
            continue                 # D2_task / C5_far are NOT run (disclosed)
        sid = e["sample_id"]
        fam = canonical_family((e.get("meta") or {}).get("family", ""))
        s = by_sid.setdefault(sid, {"sample_id": sid, "family": fam,
                                    "label": e["label"], "arms": {}})
        if s["family"] != fam or s["label"] != e["label"]:
            raise ValueError(f"sample {sid}: conflicting family/label across arms")
        s["arms"][e["arm"]] = e
    missing = [sid for sid, s in by_sid.items() if any(a not in s["arms"] for a in ARMS)]
    if missing:
        raise ValueError(f"samples missing a gate arm: {sorted(missing)[:5]}")

    samples = sorted(by_sid.values(), key=lambda s: (s["family"], s["sample_id"]))
    benign = [s for s in samples if s["label"] == 0]
    vul = [s for s in samples if s["label"] == 1]
    fam_counts = Counter((s["family"], s["label"]) for s in samples)
    for fam in FAMILIES:
        if fam_counts[(fam, 0)] != int(cfg["bench"]["n_benign_per_family"]):
            raise ValueError(f"{fam}: benign n={fam_counts[(fam, 0)]} != "
                             f"{cfg['bench']['n_benign_per_family']}")
        if fam_counts[(fam, 1)] != int(cfg["bench"]["n_vul_per_family"]):
            raise ValueError(f"{fam}: vul n={fam_counts[(fam, 1)]} != "
                             f"{cfg['bench']['n_vul_per_family']}")

    def _job(kind: str, group: list[dict]) -> dict:
        return {"job": kind, "samples": group, "n_records": len(group) * len(ARMS)}

    jobs = [_job("benign", benign), _job("vul", vul)]
    if limit is not None:            # dry cut: limit counts RECORDS (generations)
        cut, trimmed = int(limit), []
        for j in jobs:
            if cut <= 0:
                break
            take = max(0, min(len(j["samples"]), cut // len(ARMS)))
            cut -= take * len(ARMS)
            trimmed.append({**j, "samples": j["samples"][:take],
                            "n_records": take * len(ARMS)})
        jobs = [j for j in trimmed if j["samples"]]

    sel_meta = {
        "rule": cfg["pool"]["selection_rule"],
        "census": True,
        "families": list(FAMILIES),
        "n_benign": len(benign), "n_vul": len(vul),
        "n_samples": len(samples),
        "by_family": {f: {"benign": fam_counts[(f, 0)], "vul": fam_counts[(f, 1)]}
                      for f in FAMILIES},
        "sample_ids": [s["sample_id"] for s in samples],
        "arms": ARMS,
        "arms_not_run": ["D2_task", "C5_far"],
    }
    bench_meta["arms_present_all"] = bench_meta.get("arms_present")
    bench_meta["arms_used"] = ARMS
    return jobs, {"bench": bench_meta, "selection": sel_meta}


def _bench_jsonl_path(cfg: dict) -> Path:
    path = PROJECT_ROOT / cfg["bench"]["source"]
    if path.is_dir():
        jsonls = sorted(path.glob("*.jsonl"))
        if len(jsonls) != 1:
            raise FileNotFoundError(
                f"bench dir {path} must contain exactly one .jsonl, found "
                f"{[p.name for p in jsonls]}")
        path = jsonls[0]
    return path


def build_manifest(cfg: dict, out_dir: Path) -> Path:
    """manifest_cwe.json — collector-parseable (samples list of
    {sample_id, family}) + advisory checks + full provenance."""
    path = _bench_jsonl_path(cfg)
    rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()
            if l.strip()]
    samples: dict[str, dict] = {}
    families: dict[str, list[str]] = {}
    n_pass = 0
    failures: list[dict] = []
    for r in rows:
        fam = canonical_family(r["family"])
        sid = str(r["sample_id"])
        samples[sid] = {"sample_id": sid, "family": fam, "label": int(r["label"])}
        families.setdefault(fam, []).append(sid)
        adv = r.get("advisory") or {}
        ok = (set((adv.get("risky_apis") or {}).keys())
              <= set((r.get("risky_apis") or {}).keys())
              and (adv.get("family_signals") or {})
              == (r.get("family_signals") or {}))
        n_pass += int(ok)
        if not ok:
            failures.append({"sample_id": sid,
                             "advisory_risky_apis": adv.get("risky_apis"),
                             "row_risky_apis": r.get("risky_apis")})
    man = {
        "name": "round7_rq8_manifest",
        "created": now_utc(),
        "prereg": "docs/round7_prereg.md §1 + §0b(ii) Amendment-1; "
                  "configs/round7_rq8.yaml",
        "bench": {
            "source": cfg["bench"]["source"],
            "sha256_16": sha16_file(path),
            "attack_config": "configs/attack_v2_cwe.yaml (A1)",
            "seed_bench": 20260921,
        },
        "sampling": {"rule": "census of the 160-row bench (no subsampling)",
                     "arms_gate": ARMS, "arms_not_run": ["D2_task", "C5_far"]},
        "advisory_check": {
            "rule": "advisory.risky_apis ⊆ row.risky_apis AND "
                    "advisory.family_signals == row.family_signals (T7 analog)",
            "n_rows": len(rows), "n_pass": n_pass,
            "pass_rate": round(n_pass / max(1, len(rows)), 4),
            "failures": failures[:10],
        },
        "samples": [samples[k] for k in sorted(samples)],
        "families": {f: sorted(sids) for f, sids in sorted(families.items())},
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "manifest_cwe.json"
    path.write_text(json.dumps(man, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8")
    print(f"[rq8] wrote {path} ({len(samples)} samples, advisory pass "
          f"{n_pass}/{len(rows)})", flush=True)
    return path


def sha16_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# one model run (checkpoint + resume, model-guarded)
# ---------------------------------------------------------------------------
def _results_name(cfg: dict, model_id: str, dry: bool) -> str:
    slug = MOCK_SLUG if dry else (cfg["models"]["slugs"].get(model_id, model_id))
    return f"results_{slug}.json"


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False),
                    encoding="utf-8")
    print(f"[rq8] wrote {path}", flush=True)


def _load_prior(results_path: Path, cfg: dict, mid: str,
                want_keys: Optional[set] = None) -> tuple[dict, bool]:
    """(records, complete) — MODEL-GUARDED (model id + config sha).

    `want_keys` (the (sample_id, arm) pairs of the CURRENT invocation) guards
    against the partial-coverage trap hit by the first queue launch: a
    job-filtered invocation (benign only) leaves a complete-looking
    partial=False file, which the NEXT invocation (vul) must EXTEND, not
    skip.  A file counts as complete only when it already contains every
    record the current invocation needs."""
    if not (results_path.exists() and cfg["execution"].get("resume", True)):
        return {}, False
    prev = json.loads(results_path.read_text(encoding="utf-8"))
    pm = prev.get("metadata", {})
    model_guard(mid, pm.get("model_id"), f"resume {results_path.name}")
    if pm.get("config_sha16") != cfg["_config_sha16"]:
        raise ModelGuardError(
            f"[rq8 model-guard] {results_path.name}: config_sha16 mismatch "
            f"({pm.get('config_sha16')} != {cfg['_config_sha16']}) — the "
            f"pre-registered config changed; do not silently resume")
    records: dict[tuple, dict] = {}
    for rec in prev.get("records", []):
        if rec.get("status") != "SKIPPED":
            records[(rec["sample_id"], rec["condition"])] = rec
    if not pm.get("partial"):
        if want_keys is None or want_keys <= set(records):
            return {}, True
        print(f"[rq8] {results_path.name}: complete-looking file holds only "
              f"{len(records)} records — {len(want_keys - set(records))} "
              f"record(s) of this job are missing; EXTENDING it", flush=True)
        return records, False
    print(f"[rq8] resuming {results_path.name}: {len(records)} done", flush=True)
    return records, False


def _prep(cfg: dict, dry: bool, model_name: str) -> tuple[str, dict, dict, str,
                                                            int, list[str]]:
    mid = MOCK_MID if dry else model_id_of(cfg, model_name)
    thr, thr_source = resolve_thresholds(
        {"monitor": {"fallback_thresholds": cfg["monitor"]["fallback_thresholds"]}},
        mid)
    monitor = make_monitor(thr)
    max_new = int(cfg["gen_cfg"]["max_new_tokens"])
    required = list(cfg["monitor"]["required_fields"])
    return mid, dict(thr), monitor, thr_source, max_new, required


def _make_llm(cfg: dict, dry: bool, model_name: str, llm: Any) -> Any:
    if llm is not None:
        return llm
    if dry:
        return MockLLM(model_id=MOCK_MID)
    return RealLLMRQ8(cfg, model_name)


class RealLLMRQ8:
    """RealLLM with the config's max_input_tokens + call stats (per round 7)."""

    def __init__(self, cfg: dict, model_name: str):
        from src.experiments.pilot_round2 import RealLLM
        self._impl = RealLLM(
            model_id=model_id_of(cfg, model_name),
            hf_home=Path(DEFAULT_HF_HOME), cache_dir=DEFAULT_CACHE,
            max_input_tokens=int(cfg["gen_cfg"]["max_input_tokens"]),
            seed=int(cfg["gen_cfg"]["seed"]))
        self.model_id = self._impl.model_id
        self.rev = self._impl.rev
        self.seed = self._impl.seed
        self.n_calls = self._impl.n_calls
        self.n_cache_hits = self._impl.n_cache_hits
        self.gen_seconds = self._impl.gen_seconds

    def generate(self, system: str, user: str, max_new_tokens: int):
        text, meta = self._impl.generate(system, user, max_new_tokens)
        self.n_calls = self._impl.n_calls
        self.n_cache_hits = self._impl.n_cache_hits
        self.gen_seconds = self._impl.gen_seconds
        return text, meta


def run_model(cfg: dict, model_name: str, dry: bool = False,
              job_filter: Optional[str] = None, limit: Optional[int] = None,
              budget_min: Optional[float] = None, llm: Any = None,
              status_cb: Optional[Callable[[dict], None]] = None) -> dict:
    """Run (or resume) one model's benign+vul jobs.  Writes
    results_<slug>.json in out_dir (+ collector bridge copy when complete)."""
    t_start = time.perf_counter()
    out_dir = PROJECT_ROOT / cfg["out_dir"] / ("dry" if dry else "")
    out_dir.mkdir(parents=True, exist_ok=True)
    mid, thr, monitor, thr_source, max_new, required = _prep(cfg, dry, model_name)
    llm = _make_llm(cfg, dry, model_name, llm)
    jobs, meta = build_jobs(cfg, dry=dry, limit=limit)
    if job_filter:
        jobs = [j for j in jobs if j["job"] == job_filter]
        if not jobs:
            raise SystemExit(f"--job {job_filter!r} matched nothing")
    job_pairs = {(s["sample_id"], arm) for j in jobs for s in j["samples"]
                 for arm in ARMS}
    results_path = out_dir / _results_name(cfg, mid, dry)
    records, complete = _load_prior(results_path, cfg, mid, want_keys=job_pairs)
    if complete:
        print(f"[rq8] {results_path.name}: already complete — nothing to do")
        return json.loads(results_path.read_text(encoding="utf-8"))
    # expected coverage of the FILE = prior records union this invocation
    # (a job-filtered resume on a partial-coverage file must write
    # n_records_expected = full-file size, not just this job's size)
    expected = len(set(records) | job_pairs)

    new_since_ckpt = 0
    budget_hit = False

    def base_meta(partial: bool) -> dict:
        return {
            "round": 7, "agent": "RQ8-executor", "experiment": "round7_rq8",
            "real": not dry, "dry_run": dry,
            "model_id": getattr(llm, "model_id", mid),
            **(getattr(llm, "rev", {}) or {}),
            "device": "mock" if dry else "mps",
            "dtype": str(cfg["gen_cfg"].get("dtype", "bfloat16")),
            "seed_generation": getattr(llm, "seed", int(cfg["gen_cfg"]["seed"])),
            "gen_cfg": {k: v for k, v in cfg["gen_cfg"].items()},
            "config": cfg.get("_config_path"),
            "config_sha16": cfg.get("_config_sha16"),
            "date_utc": now_utc(), "cache_dir": str(DEFAULT_CACHE),
            "n_cache_calls": getattr(llm, "n_calls", 0),
            "n_cache_hits": getattr(llm, "n_cache_hits", 0),
            "gen_seconds_new_tokens_only":
                round(getattr(llm, "gen_seconds", 0.0), 1),
            "partial": bool(partial),
            "n_records": len(records), "n_records_expected": expected,
            "wall_seconds": round(time.perf_counter() - t_start, 1),
            "bench": meta["bench"], "selection": meta["selection"],
            "jobs": [j["job"] for j in jobs],
            "monitor_thresholds": dict(thr),
            "monitor_thresholds_source": thr_source,
            "prompt_builder": "src.conditions.c5_risk_context.build_attack_prompt",
        }

    def checkpoint(partial: bool) -> dict:
        results = {"metadata": base_meta(partial),
                   "records": [records[k] for k in sorted(records)],
                   "metrics": (compute_rq8_metrics(
                       [records[k] for k in sorted(records)], cfg)
                       if not partial else {"partial": True})}
        _write_json(results_path, results)
        if not partial:
            bridge_copy(cfg, results_path)
        return results

    for j in jobs:
        for s in j["samples"]:
            sid, fam, label = s["sample_id"], s["family"], s["label"]
            for arm in ARMS:
                if (sid, arm) in records:
                    continue
                if budget_min is not None and \
                        (time.perf_counter() - t_start) / 60.0 >= budget_min:
                    budget_hit = True
                    print("[rq8] budget reached — checkpointing", flush=True)
                    break
                entry = s["arms"][arm]
                try:
                    prompt, psrc = render_prompt(entry)
                    if dry:  # marker so MockLLM keys behaviour deterministically
                        prompt = dict(prompt)
                        prompt["user"] = (f"[[MOCK_ARM={arm}]]"
                                          f"[[MOCK_LABEL={label}]] "
                                          + prompt["user"])
                    t0 = time.perf_counter()
                    text, gen = llm.generate(prompt["system"], prompt["user"],
                                             max_new)
                    status, y_pred, extras = classify_output(monitor, text,
                                                             required)
                    m = {
                        "real": not dry, "dry_run": dry, "arm": arm,
                        "family": fam, "label": label,
                        "language": entry["language"],
                        "prompt_source": psrc,
                        "prompt_sha256_16": sha16(prompt),
                        "date_utc": now_utc(), "model_guard": mid,
                        "monitor_thresholds": dict(thr),
                        "gen": gen,
                        "gen_seconds": round(time.perf_counter() - t0, 2),
                        "advisory_text_norm": _advisory_text_of(
                            s["arms"]["C5_near"]["func"]) if arm == "C5_near" else "",
                        "bench_row": {
                            k: (entry.get("meta") or {}).get(k)
                            for k in ("has_risky_api", "has_signature",
                                      "family_signals") if k in (entry.get("meta") or {})
                        },
                        **extras,
                    }
                    if arm == "C5_near":
                        bm = entry.get("meta") or {}
                        adv = bm.get("advisory") or {}
                        m["bench_row"].update({
                            "advisory_kind": adv.get("advisory_kind"),
                            "advisory_template_id": adv.get("template_id"),
                            "zero_api": adv.get("zero_api"),
                            "risky_apis": adv.get("risky_apis"),
                        })
                    raw_rel = write_raw(
                        out_dir, f"rq8_{_results_name(cfg, mid, dry)[8:-5]}"
                                f"__{arm}__{sid}.txt", text)
                    m["text"] = text
                    rec = new_record(sid, arm, "B0", label, y_pred, status,
                                     status, raw_rel, m)
                    rec["family"] = fam
                    rec["taxonomy"] = refusal_taxonomy({**rec, "meta": m})
                except Exception as exc:  # noqa: BLE001 — disclosed skip
                    rec = new_record(sid, arm, "B0", label, None, "SKIPPED",
                                     f"GEN_ERROR: {type(exc).__name__}", None,
                                     {"real": not dry, "dry_run": dry,
                                      "family": fam, "arm": arm,
                                      "error": str(exc)[:300]})
                records[(sid, arm)] = rec
                new_since_ckpt += 1
                done = sum(1 for r in records.values()
                           if r.get("status") != "SKIPPED")
                print(f"[rq8] {results_path.name} {done}/{expected} "
                      f"last=({sid},{arm}) status={rec.get('status')}",
                      flush=True)
                if new_since_ckpt % int(cfg["execution"]["checkpoint_every"]) == 0:
                    checkpoint(partial=True)
                if status_cb is not None:
                    status_cb({"job": j["job"], "done": done,
                               "expected": expected, "state": "running"})
            if budget_hit:
                break
        if budget_hit:
            break

    return checkpoint(partial=budget_hit)


# ---------------------------------------------------------------------------
# metrics — computed-by-rule (prereg §2; collector-compatible algebra)
# ---------------------------------------------------------------------------
def _verdict_table(records: list[dict], arm: str, label: int,
                   fam: Optional[str] = None) -> dict[str, Optional[int]]:
    out: dict[str, Optional[int]] = {}
    for r in records:
        if r.get("condition") != arm or r.get("y_true") != label \
                or r.get("status") == "SKIPPED":
            continue
        if fam is not None and r.get("family") != fam:
            continue
        v = r.get("y_pred")
        out[str(r["sample_id"])] = int(v == 1) if v in (0, 1) else None
    return out


def _paired_block(records: list[dict], label: int, fam: Optional[str],
                  cfg: dict) -> dict:
    """Paired C0 vs C5_near block (benign: FP side; vul: recall side)."""
    t0 = _verdict_table(records, "C0", label, fam)
    t5 = _verdict_table(records, "C5_near", label, fam)
    ids = sorted(set(t0) & set(t5))
    valid = [i for i in ids if t0[i] is not None and t5[i] is not None]
    n_excluded = len(ids) - len(valid)
    n_per_arm = {"C0": len(t0), "C5_near": len(t5)}
    blk: dict = {"n_pairs": len(ids), "n_pairs_valid": len(valid),
                 "n_pairs_excluded_unparsed_or_refusal": n_excluded,
                 "n_per_arm": n_per_arm}
    if not valid:
        return {**blk, "fp_or_recall_C0": None, "fp_or_recall_C5_near": None,
                "delta_fp": None, "flip_b2v_0to1": None, "flip_v2b_1to0": None,
                "p_exact": None, "delta_ci": None, "powered": False}
    c0 = [t0[i] for i in valid]
    c5 = [t5[i] for i in valid]
    b2v = sum(1 for a, b in zip(c0, c5) if a == 0 and b == 1)
    v2b = sum(1 for a, b in zip(c0, c5) if a == 1 and b == 0)
    rate0 = sum(c0) / len(valid)
    rate5 = sum(c5) / len(valid)
    blk.update({
        "fp_or_recall_C0": round(rate0, 4),
        "fp_or_recall_C5_near": round(rate5, 4),
        "delta_fp": round(rate5 - rate0, 4),
        "flip_b2v_0to1": b2v,
        "flip_v2b_1to0": v2b,
        # PRIMARY p: exact discordant-only (collector algebra)
        "p_exact": mcnemar_exact_discordant(b2v, v2b),
        # side-report: src/metrics/stats.py exact variant (statsmodels when
        # available); chi2 is conservative — round-6 convention
        "p_side_mcnemar_module": mcnemar([bool(x) for x in c0],
                                         [bool(x) for x in c5], exact=True)
        if b2v + v2b else {"p_value": 1.0, "method": "no-discordant-pairs"},
        # power gate follows the collector's semantics: BOTH-ARMS-PRESENT
        # pairs (a refused/unparsed verdict drops stats but not power;
        # refusal event is disclosed in n_pairs_excluded_* and RR_by_cell)
        "powered": len(ids) >= MIN_FAMILY_N,
    })
    if label == 0:  # bootstrap CI on delta FP (paired resampling, R5/R6 conv.)
        blk["delta_ci"] = bootstrap_ci_diff(
            c5, c0, n_boot=int(cfg["stats"]["n_boot"]),
            seed=int(cfg["stats"]["seed"]))
    return blk


def compute_rq8_metrics(records: list[dict], cfg: dict) -> dict:
    alpha = float(cfg["stats"]["alpha"])
    recs = [r for r in records if r.get("status") != "SKIPPED"]
    n_skipped = len(records) - len(recs)
    rr_by_cell: dict[str, float] = {}
    for arm in ARMS:
        for label in (0, 1):
            cell = [r for r in recs if r["condition"] == arm
                    and r.get("y_true") == label]
            rr_by_cell[f"{'vul' if label else 'benign'}|{arm}"] = round(
                sum(1 for r in cell if r["status"] == "REFUSAL") / len(cell), 4
            ) if cell else None
    rr_overall = (sum(1 for r in recs if r["status"] == "REFUSAL") / len(recs)
                  if recs else None)

    # ---- PRIMARY: benign side, per family + pooled -----------------------
    fam_blocks: dict[str, dict] = {}
    passing: list[str] = []
    powered_fams: list[str] = []
    for fam in FAMILIES:
        blk = _paired_block(recs, 0, fam, cfg)
        present = blk["n_pairs"] > 0
        if present and blk.get("powered"):
            blk["family_pass"] = bool(blk["p_exact"] < alpha
                                      and blk["flip_b2v_0to1"]
                                      > blk["flip_v2b_1to0"])
            if blk["family_pass"]:
                passing.append(fam)
            powered_fams.append(fam)
        else:
            blk["family_pass"] = False
            blk["note"] = (f"NOT-RUN/UNPOWERED: paired n={blk['n_pairs']} < "
                           f"{MIN_FAMILY_N} (prereg §2.3 item 5)")
        fam_blocks[fam] = blk
    # pooled over POWERED families when any exist (collector algebra: pooling
    # is a power tool over participating families); interim/partial reads with
    # no powered family yet fall back to all present families, labelled.
    pool_scope = powered_fams if powered_fams else list(FAMILIES)
    pooled = _paired_block(
        [r for r in recs if r.get("family") in pool_scope], 0, None, cfg)
    if not powered_fams:
        pooled["note"] = ("interim: no family has reached n_pairs >= "
                          f"{MIN_FAMILY_N}; pooled row is INTERIM over "
                          f"{pool_scope}")
    pooled_pass = bool(pooled.get("p_exact") is not None
                       and pooled["p_exact"] < alpha
                       and pooled["delta_fp"] is not None
                       and pooled["delta_fp"] >= 0.15
                       and pooled["flip_b2v_0to1"] > pooled["flip_v2b_1to0"])

    # ---- verdicts (computed-by-rule; per-family AND pooled always both) --
    family_pass_count = len(passing)
    h_g1 = "SUPPORTED" if family_pass_count >= 3 else "NOT_SUPPORTED"
    h_g2 = "SUPPORTED" if pooled_pass else "NOT_SUPPORTED"
    if family_pass_count >= 3:
        label_verdict = "GENERALIZES"
    elif pooled_pass:
        label_verdict = "GENERALIZES-pooled-driven"
    else:
        label_verdict = "FAMILY-DEPENDENT"
    verdict = {
        "H_G1_family_level": h_g1,
        "H_G1_rule": ">=3/4 powered families with exact p<0.05 AND b2v>v2b",
        "H_G2_pooled": h_g2,
        "H_G2_rule": "pooled delta_fp>=0.15 AND exact p<0.05 AND b2v>v2b",
        "family_pass_count": family_pass_count,
        "families_passing": passing,
        "families_powered": powered_fams,
        "families_not_run_or_unpowered":
            [f for f in FAMILIES if f not in powered_fams],
        "label": label_verdict,
        "anti_masking_note": "both per-family and pooled rows reported "
                             "(prereg §2.5); pooling is power, not conclusion",
        "pooled_scope": pool_scope,
        "pooled": pooled,
        "complete_data": all(fam_blocks[f].get("powered") for f in FAMILIES),
    }

    # ---- SECONDARY: vul-side recall per family (narrate only) ------------
    vul_blocks = {fam: _paired_block(recs, 1, fam, cfg) for fam in FAMILIES}
    for fam, blk in vul_blocks.items():
        blk["note"] = "secondary, narrate only (prereg §2.4); " \
                      "fp_or_recall_* fields are RECALLS on this side"

    # ---- echo evidence (narrate-only) ------------------------------------
    c0_table = _verdict_table(recs, "C0", 0)
    echo = {"n_b2v_flips": 0, "n_echo_advisory": 0, "examples": []}
    for r in recs:
        if r.get("y_true") != 0 or r.get("condition") != "C5_near":
            continue
        if c0_table.get(str(r["sample_id"])) != 0 or r.get("y_pred") != 1:
            continue
        echo["n_b2v_flips"] += 1
        adv = ((r.get("meta") or {}).get("advisory_text_norm") or "")
        txt = " ".join(str((r.get("meta") or {}).get("text", "")).split()).lower()
        if adv and adv in txt:
            echo["n_echo_advisory"] += 1
            if len(echo["examples"]) < 3:
                echo["examples"].append({"sample_id": r["sample_id"],
                                         "family": r.get("family")})

    return {
        "n_records": len(records), "n_skipped": n_skipped,
        "RR_by_cell": rr_by_cell, "RR_overall": round(rr_overall, 4)
        if rr_overall is not None else None,
        "refusal_note": "refusal is never mapped to benign (prereg); "
                        "unparsed/REFUSAL records drop from paired n "
                        "(counts disclosed per block)",
        "families": fam_blocks,
        "pooled": pooled,
        "verdict": verdict,
        "vul_secondary": vul_blocks,
        "echo_evidence": echo,
        "stats_methods": {
            "mcnemar_primary": "exact binomial discordant-only: "
                               "p=min(1, 2*sum_{k<=min(b,c)} C(b+c,k)/2^(b+c)) "
                               "(== scripts/collect_master_round7.py)",
            "mcnemar_side": "src/metrics/stats.py:mcnemar(exact=True) "
                            "(statsmodels) stored as p_side_mcnemar_module",
            "delta_ci": f"bootstrap_ci_diff paired n_boot="
                        f"{cfg['stats']['n_boot']} seed={cfg['stats']['seed']}",
            "no_multiple_comparisons": "5 pre-registered comparisons, "
                                       "threshold p<0.05, no correction",
        },
    }


def aggregate_metrics(cfg: dict, out_dir: Optional[Path] = None) -> dict:
    """Read every complete per-model results file (MODEL-GUARDED) + verdicts."""
    out_root = Path(out_dir) if out_dir else PROJECT_ROOT / cfg["out_dir"]
    out: dict = {"date_utc": now_utc(), "config_sha16": cfg["_config_sha16"],
                 "models": {}, "notes": []}
    for name in cfg["models"]["queue_order"]:
        mid = model_id_of(cfg, name)
        p = out_root / _results_name(cfg, mid, False)
        if not p.exists():
            out["models"][name] = {"model_id": mid, "state": "not_started"}
            continue
        d = json.loads(p.read_text(encoding="utf-8"))
        md = d.get("metadata", {})
        model_guard(mid, md.get("model_id"), f"metrics {p.name}")
        n_done = sum(1 for r in d.get("records", [])
                     if r.get("status") != "SKIPPED")
        entry: dict = {
            "model_id": mid, "file": str(p.relative_to(PROJECT_ROOT)),
            "n_records": n_done,
            "n_expected": md.get("n_records_expected"),
            "partial": bool(md.get("partial")),
        }
        if md.get("partial"):
            entry["state"] = "partial"
            out["notes"].append(f"{name}: PARTIAL checkpoint "
                                f"({n_done}/{md.get('n_records_expected')}) — "
                                f"metrics below are INTERIM, not verdicts")
            # interim computed-by-rule read of what exists (labelled partial)
            m = compute_rq8_metrics(d.get("records", []), cfg)
            m["interim"] = True
            entry["metrics_interim"] = m
        else:
            entry["state"] = "complete"
            entry["metrics"] = d.get("metrics") or \
                compute_rq8_metrics(d.get("records", []), cfg)
        out["models"][name] = entry
    return out


# ---------------------------------------------------------------------------
# collector bridge (prereg §4 registered paths)
# ---------------------------------------------------------------------------
def bridge_copy(cfg: dict, results_path: Path) -> Optional[str]:
    """Byte-copy COMPLETE per-model results + manifest into
    outputs/experiments/round7_cwe/ so scripts/collect_master_round7.py finds
    its registered sources.  Partial files are NEVER copied; dry/MockLLM
    artifacts are NEVER copied."""
    p = Path(results_path)
    if not p.exists():
        return None
    d = json.loads(p.read_text(encoding="utf-8"))
    md = d.get("metadata", {})
    if md.get("partial") or md.get("dry_run"):
        print(f"[rq8] bridge skipped ({'partial' if md.get('partial') else 'dry'}):"
              f" {p.name}", flush=True)
        return None
    # full-bench coverage guard: a complete-looking file from a job-filtered
    # invocation must NEVER reach the collector (round-7 lesson)
    n_rec = len([r for r in d.get("records", []) if r.get("status") != "SKIPPED"])
    n_full = 2 * int(cfg["bench"]["n_benign_per_family"]) + \
        2 * int(cfg["bench"]["n_vul_per_family"])
    if n_rec != n_full:
        print(f"[rq8] bridge skipped ({p.name}): {n_rec}/{n_full} records — "
              f"partial-coverage file, not the full bench census", flush=True)
        return None
    bridge = PROJECT_ROOT / cfg["collector_bridge"]
    bridge.mkdir(parents=True, exist_ok=True)
    dest = bridge / p.name
    shutil.copyfile(p, dest)
    man_src = Path(p).parent / "manifest_cwe.json"
    if man_src.exists():
        shutil.copyfile(man_src, bridge / man_src.name)
    print(f"[rq8] bridge: {p.name} -> {dest}", flush=True)
    return str(dest)


# ---------------------------------------------------------------------------
# queue driver (nohup; llama3b -> granite2b; benign -> vul per model)
# ---------------------------------------------------------------------------
_STATUS_PATH = "jobs_status.json"


def write_status(out_dir: Path, cfg: dict, mid: str, slug: str, state: str,
                 job: str, done: int, expected: int, elapsed_s: float,
                 queue_done: int, queue_expected: int,
                 next_jobs: list[str]) -> None:
    rate = (elapsed_s / done) if done else None
    _write_json(out_dir / _STATUS_PATH, {
        "pid": os.getpid(),
        "model_id": mid, "running_model_slug": slug,
        "running_job": job, "state": state, "date_utc": now_utc(),
        "records_done_this_job": done, "records_expected_this_job": expected,
        "elapsed_s_this_job": round(elapsed_s, 1),
        "s_per_record": round(rate, 2) if rate else None,
        "eta_minutes_this_job": round(max(0, expected - done) * rate / 60, 1)
        if rate else None,
        "queue": {"order": list(cfg["models"]["queue_order"]),
                  "records_done": queue_done, "records_expected": queue_expected,
                  "next_jobs": next_jobs},
        "resume_command": (
            f"cd {PROJECT_ROOT} && HF_HOME={PROJECT_ROOT}/models_dir/hf "
            f"HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 nohup "
            f".venv/bin/python {PROJECT_ROOT / cfg['out_dir'] / QUEUE_DRIVER} "
            f"> {PROJECT_ROOT / cfg['out_dir'] / 'queue.log'} 2>&1 &"),
        "log": str(PROJECT_ROOT / cfg["out_dir"] / "queue.log"),
    })


_QUEUE_DRIVER_TEMPLATE = '''"""Round-7 RQ8 sequential queue driver (mandate: llama3b -> granite2b).

Pre-registered job order (configs/round7_rq8.yaml), executed as ONE run_model
per model so file-completeness == model-completeness (round-7 fix: a
per-job-filtered driver left benign-only "complete" files and silently
skipped the vul job):
  per model in queue order [llama3b, granite2b]:
    1. benign job  (80 benign x {{C0, C5_near}} — PRIMARY endpoint)
    2. vul job     (80 vul x {{C0, C5_near}} — secondary recall)
One shared LLM instance per model (weights load once).  Checkpoint every
{ckpt} records; re-running the same command RESUMES (model-guard refuses
other models / other config shas); the LLM JSONL cache makes repeated
generations free.
Launch:
  cd <root> && HF_HOME=<root>/models_dir/hf HF_HUB_OFFLINE=1 \\
  TRANSFORMERS_OFFLINE=1 nohup .venv/bin/python \\
      <root>/outputs/experiments/round7_rq8/queue_driver.py \\
      > <root>/outputs/experiments/round7_rq8/queue.log 2>&1 &
"""
import json
import os
import sys
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from src.experiments.round7_rq8 import (  # noqa: E402
    ARMS, FAMILIES, load_config, model_id_of, run_model, write_status,
    RealLLMRQ8, _results_name,
)


def main() -> None:
    cfg = load_config(ROOT / "configs/round7_rq8.yaml")
    out = ROOT / cfg["out_dir"]
    out.mkdir(parents=True, exist_ok=True)
    plan = []
    for name in cfg["models"]["queue_order"]:
        mid = model_id_of(cfg, name)
        plan.append((name, mid, out / _results_name(cfg, mid, False)))
    queue_expected = len(cfg["models"]["queue_order"]) * len(FAMILIES) \\
        * (int(cfg["bench"]["n_benign_per_family"])
           + int(cfg["bench"]["n_vul_per_family"])) * len(ARMS)
    for idx, (name, mid, rp) in enumerate(plan):
        slug = cfg["models"]["slugs"].get(mid, mid)
        llm = RealLLMRQ8(cfg, name)
        print(f"[rq8-queue] model {{mid}} loaded ({{slug}})", flush=True)
        done_before = 0
        if rp.exists():
            try:
                d = json.loads(rp.read_text(encoding="utf-8"))
                done_before = sum(1 for r in d.get("records", [])
                                  if r.get("status") != "SKIPPED")
            except Exception:
                done_before = 0
        label = f"{{slug}}/benign+vul"
        print(f"[rq8-queue] === START {{label}} ({{done_before}} records on "
              f"disk) ===", flush=True)
        t0 = time.perf_counter()

        def cb(info: dict, _slug: str = slug, _t0: float = t0) -> None:
            write_status(out, cfg, mid, _slug, info.get("state", "running"),
                         f"{{_slug}}/{{info.get('job', 'run')}}",
                         info.get("done", 0), info.get("expected", 0),
                         time.perf_counter() - _t0,
                         queue_done=done_before + info.get("done", 0),
                         queue_expected=queue_expected,
                         next_jobs=[f"{{cfg['models']['slugs'].get(m, m)}}"
                                    for n2, m, _p2 in plan[idx + 1:]])

        write_status(out, cfg, mid, slug, "starting", label, 0, 0, 0.0,
                     queue_done=done_before, queue_expected=queue_expected,
                     next_jobs=[f"{{cfg['models']['slugs'].get(m, m)}}"
                                for n2, m, _p2 in plan[idx + 1:]])
        try:
            res = run_model(cfg, name, llm=llm, status_cb=cb)
            md = res.get("metadata", {{}})
            print(f"[rq8-queue] === DONE {{label}}: "
                  f"n_records={{md.get('n_records')}}/"
                  f"{{md.get('n_records_expected')}} "
                  f"partial={{md.get('partial')}} "
                  f"cache={{md.get('n_cache_hits')}}/{{md.get('n_cache_calls')}} "
                  f"wall={{md.get('wall_seconds')}}s ===", flush=True)
            write_status(out, cfg, mid, slug, "job_complete", label,
                         md.get("n_records", 0),
                         md.get("n_records_expected", 0),
                         time.perf_counter() - t0,
                         queue_done=queue_expected,
                         queue_expected=queue_expected, next_jobs=[])
        except Exception:  # noqa: BLE001 — log, continue with next model
            print(f"[rq8-queue] === FAILED {{label}} ===\\n"
                  f"{{traceback.format_exc()}}", flush=True)
            write_status(out, cfg, mid, slug, "failed", label, 0, 0,
                         time.perf_counter() - t0, queue_done=done_before,
                         queue_expected=queue_expected, next_jobs=[])
    write_status(out, cfg, "all", "queue", "queue_done", "all-jobs", 0, 0,
                 0.0, queue_done=queue_expected,
                 queue_expected=queue_expected, next_jobs=[])
    print("[rq8-queue] all jobs attempted", flush=True)


if __name__ == "__main__":
    main()
'''


def write_queue_driver(cfg: dict) -> Path:
    out_dir = PROJECT_ROOT / cfg["out_dir"]
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / QUEUE_DRIVER
    path.write_text(_QUEUE_DRIVER_TEMPLATE.format(
        ckpt=int(cfg["execution"]["checkpoint_every"])), encoding="utf-8")
    print(f"[rq8] wrote {path}")
    return path


# ---------------------------------------------------------------------------
def dry_stage(cfg: dict, limit: int = DRY_LIMIT) -> dict:
    """MockLLM end-to-end on REAL bench entries (0 GPU) — plumbing +
    computed-by-rule metrics, written under out_dir/dry (never the real dir)."""
    outs = {}
    for name in cfg["models"]["queue_order"][:1]:
        outs[name] = run_model(cfg, name, dry=True, limit=limit)
    m = compute_rq8_metrics(outs[cfg["models"]["queue_order"][0]]["records"], cfg)
    _write_json(PROJECT_ROOT / cfg["out_dir"] / "dry" / "dry_metrics.json", m)
    print("[rq8] dry OK — verdict:",
          json.dumps(m.get("verdict", {}))[:300], flush=True)
    return {"ok": True, "n_records": outs[cfg["models"]["queue_order"][0]]
            ["metadata"]["n_records"]}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default=str(DEFAULT_CONFIG))
    ap.add_argument("--stage", required=True,
                    choices=["dry", "run", "manifest", "metrics", "bridge",
                             "queue-driver"])
    ap.add_argument("--model", default=None,
                    help="model registry name (llama3b|granite2b) for --stage run")
    ap.add_argument("--job", default=None, choices=[None, "benign", "vul"])
    ap.add_argument("--budget-min", type=float, default=None)
    args = ap.parse_args()
    cfg = load_config(Path(args.config))
    out_dir = PROJECT_ROOT / cfg["out_dir"]
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.stage == "dry":
        dry_stage(cfg)
    elif args.stage == "run":
        if not args.model:
            raise SystemExit("--stage run requires --model <llama3b|granite2b>")
        run_model(cfg, args.model, job_filter=args.job,
                  budget_min=args.budget_min)
    elif args.stage == "manifest":
        build_manifest(cfg, out_dir)
    elif args.stage == "metrics":
        m = aggregate_metrics(cfg)
        _write_json(out_dir / "metrics_round7_rq8.json", m)
        for name, e in m["models"].items():
            met = e.get("metrics") or e.get("metrics_interim") or {}
            v = met.get("verdict", {})
            print(f"[rq8] {name}: state={e.get('state')} "
                  f"label={v.get('label')} H_G1={v.get('H_G1_family_level')} "
                  f"H_G2={v.get('H_G2_pooled')} "
                  f"pass={v.get('families_passing')}")
    elif args.stage == "bridge":
        for name in cfg["models"]["queue_order"]:
            p = out_dir / _results_name(cfg, model_id_of(cfg, name), False)
            if p.exists():
                bridge_copy(cfg, p)
    elif args.stage == "queue-driver":
        write_queue_driver(cfg)


if __name__ == "__main__":
    main()
