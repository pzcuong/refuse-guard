"""Round-9 F: regenerate PackGuard safety metrics with the CORRECTED
metric semantics (metrics_version 2).

Background (audit round-9 V1 #1/#2, confirmed by W2):
- ``compute_safety_metrics`` used to emit a field named ``fp_bias`` whose
  value was, via two cancelling sign invocations (callers passed
  ``[not label ...]`` and the function selected ``not labels[i]``), the
  TP rate on MALICIOUS packages. Renamed ``malicious_recall``; the true
  benign FP rate is now computed as ``fp_benign``.
- ``safety_metrics_n60.json`` meta ``n_malicious_total`` was 35 (counted
  P0-arm records across 2 models) instead of 30 (unique malicious
  samples: 5 old + 25 new).

This script recomputes BOTH metrics files from the UNCHANGED raw record
files (no generation, CPU-only, deterministic) and writes them back with
``metrics_version: 2`` plus a correction note. Raw records are never
modified.

Run: PYTHONPATH=$PWD .venv/bin/python scripts/packguard_safety_metrics_regen.py
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path("/Users/macbook/.zcode/workspace/default/refuseguard")
sys.path.insert(0, str(ROOT))

from packguard.safety_port import (  # noqa: E402
    compute_safety_metrics, evaluate_prereg_rules, load_safety_config)

ARMS = ["P0_neutral", "P1_offensive_wording", "P2_advisory_in_package"]
MODELS = ["unsloth/Llama-3.2-3B-Instruct",
          "ibm-granite/granite-3.3-2b-instruct"]
SAFETY_DIR = ROOT / "outputs/packguard/safety"
CONFIG = ROOT / "configs/packguard_safety.yaml"

REGEN_NOTE = (
    "metrics_version 2 (round-9 F): recomputed from the unchanged raw "
    "records with corrected metric semantics. The previously published "
    "field 'fp_bias' was, under the old code path, the TP rate on "
    "MALICIOUS packages (audit V1 round-9); it is renamed "
    "'malicious_recall' with identical values, and the true benign FP "
    "rate is now reported as 'fp_benign'. Raw records untouched.")


def _load(path: Path) -> tuple[dict, list[dict]]:
    meta: dict = {}
    records: list[dict] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if "meta" in r:
                meta = r["meta"]
            elif "sample_id" in r:
                records.append(r)
    return meta, records


def _metrics_for(recs: list[dict]) -> dict:
    arms_recs: dict = {}
    labels = None
    for arm in ARMS:
        arm_recs = sorted((r for r in recs if r["arm"] == arm),
                          key=lambda r: r["sample_id"])
        arms_recs[arm] = arm_recs
        if labels is None:
            labels = [bool(r.get("label")) for r in arm_recs]  # True=mal
    return compute_safety_metrics(arms_recs, labels=labels)


def regen_one(batch_file: Path, metrics_file: Path) -> dict:
    cfg = load_safety_config(CONFIG)
    old_meta, records = _load(batch_file)
    sample_ids = {r["sample_id"] for r in records}
    mal_ids = {r["sample_id"] for r in records if r.get("label") == 1}
    ben_ids = sample_ids - mal_ids

    results: dict = {"meta": {}, "per_model": {}, "pooled": None, "rules": {}}
    for model_id in MODELS:
        m = _metrics_for([r for r in records if r["model_id"] == model_id])
        results["per_model"][model_id] = m
        results["rules"][model_id] = evaluate_prereg_rules(
            m, cfg.get("rules", {}))
    pooled = _metrics_for(records)
    results["pooled"] = pooled
    results["rules"]["pooled"] = evaluate_prereg_rules(
        pooled, cfg.get("rules", {}))

    meta = dict(old_meta)
    meta["metrics_version"] = 2
    meta["regen_date"] = datetime.now(timezone.utc).isoformat()
    meta["regen_note"] = REGEN_NOTE
    meta["n_samples_total"] = len(sample_ids)
    # honest sample counts by unique id (not records)
    meta["n_malicious_total"] = len(mal_ids)
    meta["n_benign_total"] = len(ben_ids)
    meta.pop("n_malicious", None)
    meta.pop("n_samples", None)
    meta["legacy_counts_note"] = (
        "n_samples/n_malicious of the original run meta (v1) are kept in "
        "legacy_meta_v1; n_malicious there could double-count records "
        "across models (round-9 audit V1#2).")
    meta["legacy_meta_v1"] = {
        k: old_meta[k] for k in ("n_samples", "n_malicious",
                                 "n_samples_total", "n_samples_new",
                                 "n_malicious_total") if k in old_meta}
    results["meta"] = meta
    metrics_file.write_text(json.dumps(results, indent=1, default=str),
                            encoding="utf-8")
    return results


def main() -> int:
    for batch, metrics in (
            (SAFETY_DIR / "safety_batch.jsonl",
             SAFETY_DIR / "safety_metrics.json"),
            (SAFETY_DIR / "safety_batch_n60.jsonl",
             SAFETY_DIR / "safety_metrics_n60.json")):
        res = regen_one(batch, metrics)
        m = res["meta"]
        pooled = res["pooled"]
        print(f"== {metrics.name}: n_samples={m['n_samples_total']} "
              f"(mal={m['n_malicious_total']}, ben={m['n_benign_total']}) "
              f"metrics_version={m['metrics_version']}")
        print("   pooled malicious_recall:",
              {a: pooled["malicious_recall"][a] for a in ARMS})
        print("   pooled fp_benign:",
              {a: pooled["fp_benign"][a] for a in ARMS})
        print("   pooled rr:", pooled["rr"])
        for model_id, mres in res["per_model"].items():
            print(f"   {model_id}: mal_recall="
                  f"{mres['malicious_recall']} fp_benign="
                  f"{mres['fp_benign']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
