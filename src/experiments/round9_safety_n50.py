"""Round-9 W2 [Q3]: safety batch extension to n=60 samples (GPU, sequenced
AFTER the 8B ladder queue by the round-9 supervisor).

Design (extends round-8 AMENDMENT-1 §6, same arms/gen_cfg/monitor frozen in
configs/packguard_safety.yaml):
- The round-8 batch drew 5 mal + 5 ben (seed 20260922, first gate-passers).
- This run draws the FIRST 30 gate-passers per class with the SAME
  seed/rule (scripts.packguard_safety_batch.pick_samples, called read-only),
  then takes indices [5:30] per class -> 25 NEW mal + 25 NEW ben with ZERO
  overlap with the old 10 (asserted against the old file before any
  generation).  Total with the old 10: n=60 (30 mal + 30 ben).
- 3 arms x 2 models (unsloth/Llama-3.2-3B-Instruct,
  ibm-granite/granite-3.3-2b-instruct) -> 300 NEW generations; the old 60
  records are COPIED into the merged file (provenance: copied_from field).
- Metrics per model + pooled with packguard.safety_port functions
  (RR per arm, delta + paired McNemar vs P0, verdict flips, FP-bias) and
  the pre-registered rules; written to safety_metrics_n60.json.

Resume-safe: existing (sample_id, arm, model) in the merged file are skipped.

Run: HF_HOME=$PWD/models_dir/hf PYTHONPATH=$PWD .venv/bin/python \
        -m src.experiments.round9_safety_n50
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

ARMS = ["P0_neutral", "P1_offensive_wording", "P2_advisory_in_package"]
MODELS = ["unsloth/Llama-3.2-3B-Instruct", "ibm-granite/granite-3.3-2b-instruct"]
OLD_FILE = ROOT / "outputs/packguard/safety/safety_batch.jsonl"
NEW_FILE = ROOT / "outputs/packguard/safety/safety_batch_n60.jsonl"
METRICS_FILE = ROOT / "outputs/packguard/safety/safety_metrics_n60.json"
OLD_N_PER_CLASS = 5      # round-8 realized draw
NEW_PER_CLASS = 25       # -> 30 per class incl. the old 5
DRAW_PER_CLASS = OLD_N_PER_CLASS + NEW_PER_CLASS  # 30
CHARS = 2500


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def select_new_samples() -> tuple[list[dict], dict]:
    """25 NEW mal + 25 NEW ben = gate-passers [5:30] of the same seeded draw
    the round-8 script uses (imported read-only; sample payloads identical).
    pick_samples takes the PER-CLASS count (round-8 main() passes n//2)."""
    from scripts.packguard_safety_batch import pick_samples
    samples, stats = pick_samples(DRAW_PER_CLASS, CHARS)  # 30 per class
    n_per = DRAW_PER_CLASS
    mal = samples[:n_per]
    ben = samples[n_per:]
    assert len(mal) == n_per and len(ben) == n_per, \
        f"draw short: mal={len(mal)} ben={len(ben)}"
    new = mal[OLD_N_PER_CLASS:] + ben[OLD_N_PER_CLASS:]
    return new, stats


def main() -> int:
    from packguard.safety_port import (
        advisory_semantics_ok, compute_safety_metrics, evaluate_prereg_rules,
        load_safety_config, run_arm,
    )
    from src.models.llm_harness import LLMHarness

    cfg = load_safety_config(ROOT / "configs/packguard_safety.yaml")

    # ---- old records + ids ----
    old_records: list[dict] = []
    old_meta: dict = {}
    with OLD_FILE.open() as f:
        for line in f:
            r = json.loads(line)
            if "sample_id" in r:
                old_records.append(r)
            elif "meta" in r:
                old_meta = r
    old_ids = {r["sample_id"] for r in old_records}
    # FIX (round-9 F, audit V1#2): count old MALICIOUS *samples* (unique
    # sample ids), not P0-arm records — the old expression counted records
    # of one arm across BOTH models (10) instead of samples (5), which made
    # meta n_malicious_total 35 instead of 30.
    old_mal_ids = {r["sample_id"] for r in old_records if r.get("label") == 1}
    old_mal = len(old_mal_ids)
    print(f"old batch: {len(old_ids)} samples ({old_mal} malicious), "
          f"{len(old_records)} records")

    # ---- new samples, zero-overlap gate ----
    new_samples, sel_stats = select_new_samples()
    new_ids = {s["sample_id"] for s in new_samples}
    overlap = old_ids & new_ids
    assert not overlap, f"overlap with the round-8 batch: {sorted(overlap)[:3]}"
    n_mal = sum(1 for s in new_samples if s["label"] == 1)
    assert n_mal == NEW_PER_CLASS and len(new_samples) == 2 * NEW_PER_CLASS
    # P2 semantics gate re-asserted per new sample
    for s in new_samples:
        comment = cfg["package_fixture"][
            "advisory_comment_" + ("python" if s["language"] == "python"
                                   else "javascript")].strip("\n")
        assert advisory_semantics_ok(s["code"], comment + "\n" + s["code"],
                                     s["language"]), \
            f"P2 gate failed for {s['sample_id']}"
    print(f"new samples: {len(new_samples)} (mal={n_mal}); "
          f"selection stats: {sel_stats}; overlap=0 VERIFIED")

    # ---- merged record set + resume ----
    records: list[dict] = []
    done: set = set()
    NEW_FILE.parent.mkdir(parents=True, exist_ok=True)
    if NEW_FILE.exists():
        with NEW_FILE.open() as f:
            for line in f:
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if "sample_id" in r:
                    records.append(r)
                    done.add((r["sample_id"], r["arm"], r["model_id"]))
    if not records:
        for r in old_records:
            c = dict(r)
            c["copied_from"] = "outputs/packguard/safety/safety_batch.jsonl (round 8)"
            records.append(c)
            done.add((c["sample_id"], c["arm"], c["model_id"]))

    meta = {
        "date": _now(),
        "round": 9,
        "n_samples_total": len(old_ids) + len(new_ids),
        "n_samples_new": len(new_ids),
        "n_malicious_total": old_mal + n_mal,
        "seed": 20260922,
        "selection_rule": ("round-8 draw (seed 20260922, first gate-passers) "
                           "kept; NEW = gate-passers [5:30] per class of the "
                           "SAME draw -> zero overlap (asserted); real "
                           "package source text (text_v2 cache, first 2500 "
                           "chars at a line boundary)"),
        "selection_stats_this_run": sel_stats,
        "arms": ARMS,
        "models": MODELS,
        "code_chars": CHARS,
        "gen_cfg": cfg.get("gen_cfg"),
        "old_meta": old_meta.get("date") and
                    {"date": old_meta.get("date"),
                     "n_samples": old_meta.get("n_samples")} or None,
        "note": ("REAL local generations on REAL packages; round-8 records "
                 "copied verbatim into the merged file (copied_from flag)."),
    }
    with NEW_FILE.open("w") as f:
        f.write(json.dumps({"meta": meta}) + "\n")
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # ---- generation: model-sequential (1 model on GPU at a time) ----
    for model_id in MODELS:
        harness = LLMHarness(model_id, hf_home=str(ROOT / "models_dir/hf"))
        for arm in ARMS:
            for s in sorted(new_samples, key=lambda x: x["sample_id"]):
                if (s["sample_id"], arm, model_id) in done:
                    continue
                code = s["code"]
                if arm == "P2_advisory_in_package":
                    comment = cfg["package_fixture"][
                        "advisory_comment_" + (
                            "python" if s["language"] == "python"
                            else "javascript")].strip("\n")
                    code = comment + "\n" + code
                rec = run_arm(harness, arm, code, cfg,
                              sample_id=s["sample_id"],
                              language=s["language"])
                rec["label"] = s["label"]
                rec["ecosystem"] = s["ecosystem"]
                records.append(rec)
                with NEW_FILE.open("a") as f:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                print(f"[{model_id.split('/')[-1][:16]:16s}] {arm:22s} "
                      f"{s['sample_id'][:40]:40s} status={rec['status']:7s} "
                      f"vuln={rec['vulnerable']}", flush=True)

    # ---- metrics per model + pooled (n=60 samples per model-arm) ----
    def _metrics_for(recs: list[dict]) -> dict:
        arms_recs, labels = {}, None
        for arm in ARMS:
            arm_recs = sorted((r for r in recs if r["arm"] == arm),
                              key=lambda r: r["sample_id"])
            arms_recs[arm] = arm_recs
            if labels is None:
                # DATASET convention: True = malicious (label==1). No
                # inversion — round-9 F fix (the old ``[not b for b ...]``
                # double-inversion made the TP-rate read as ``fp_bias``).
                labels = [bool(r.get("label")) for r in arm_recs]
        return compute_safety_metrics(arms_recs, labels=labels)

    results: dict = {"meta": meta, "per_model": {}, "pooled": None,
                     "rules": {}}
    for model_id in MODELS:
        m = _metrics_for([r for r in records if r["model_id"] == model_id])
        results["per_model"][model_id] = m
        results["rules"][model_id] = evaluate_prereg_rules(
            m, cfg.get("rules", {}))
    pooled = _metrics_for(records)
    results["pooled"] = pooled
    results["rules"]["pooled"] = evaluate_prereg_rules(pooled,
                                                       cfg.get("rules", {}))
    METRICS_FILE.write_text(json.dumps(results, indent=1, default=str),
                            encoding="utf-8")
    print("wrote", METRICS_FILE)
    print("pooled RR:", pooled["rr"])
    print("rules:", json.dumps(results["rules"], indent=1, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
