"""Round-8 REAL safety batch (agent F, P3): RefuseGuard conditions port on
REAL packages (not fixtures).

Design (AMENDMENT-1 §6):
- N real packages from dataset_v2 (default 30 = 15 malicious + 15 benign,
  seed 20260922, both ecosystems; scope-reducible via --n, realized N always
  reported). Each sample contributes its REAL selected source text
  (features/text_v2.json cache, first --chars chars at a line boundary).
- Arms P0 / P1 / P2 (frozen texts in configs/packguard_safety.yaml). P2
  prepends the frozen advisory comment to the REAL file; the semantics gate
  (check_semantics, comment-only change) must PASS per sample — samples whose
  truncated snippet does not parse are replaced from the pool BEFORE any
  generation (selection disclosed in the meta).
- Models: unsloth/Llama-3.2-3B-Instruct (fitted thresholds) and
  ibm-granite/granite-3.3-2b-instruct (fallback thresholds, disclosed).
- Metrics per model and pooled: RR per arm, RR delta + paired McNemar vs P0,
  benign->malicious verdict flips, FP-bias; pre-registered rules applied.

Resume-safe: existing (sample_id, arm, model) records in the output file are
skipped on re-run.

Run: HF_HOME=$PWD/models_dir/hf PYTHONPATH=$PWD .venv/bin/python \
        scripts/packguard_safety_batch.py --n 20
"""
from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path("/Users/macbook/.zcode/workspace/default/refuseguard")
MANIFEST = ROOT / "data/packguard/manifests/dataset_v2.json"
TEXT_CACHE = ROOT / "outputs/packguard/features/text_v2.json"
OUT_DIR = ROOT / "outputs/packguard/safety"
MODELS = ["unsloth/Llama-3.2-3B-Instruct", "ibm-granite/granite-3.3-2b-instruct"]
ARMS = ["P0_neutral", "P1_offensive_wording", "P2_advisory_in_package"]
SEED = 20260922


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def pick_samples(n_per_class: int, chars: int) -> tuple[list[dict], dict]:
    """Stratified sample draw with the P2 parseability pre-filter (disclosed)."""
    from packguard.safety_port import advisory_semantics_ok, load_safety_config

    cfg = load_safety_config(ROOT / "configs/packguard_safety.yaml")
    cache = json.load(TEXT_CACHE.open())
    manifest = json.load(MANIFEST.open())
    by_id = {s["sample_id"]: s for s in manifest["samples"]}
    rows = [json.loads(l) for l in
            (ROOT / "outputs/packguard/features/features_v2.jsonl").open()]
    rows = [r for r in rows if not r.get("extraction_error")]
    rng = random.Random(SEED)
    out: list[dict] = []
    stats = {"scanned": 0, "gate_pass": 0, "gate_fail": 0}
    for label in (1, 0):
        pool = sorted((r for r in rows if int(r["label"]) == label),
                      key=lambda r: r["sample_id"])
        rng.shuffle(pool)
        got = 0
        for r in pool:
            if got >= n_per_class:
                break
            text = (cache.get(r["sample_id"]) or "").strip()
            if not text:
                continue
            cut = text[:chars]
            if "\n" in cut:
                cut = cut[: cut.rfind("\n")]
            lang = "python" if r["ecosystem"] == "pypi" else "javascript"
            comment = cfg["package_fixture"][
                "advisory_comment_python" if lang == "python"
                else "advisory_comment_javascript"].strip("\n")
            stats["scanned"] += 1
            if not advisory_semantics_ok(cut, comment + "\n" + cut, lang):
                stats["gate_fail"] += 1
                continue
            stats["gate_pass"] += 1
            s = by_id[r["sample_id"]]
            out.append({
                "sample_id": r["sample_id"], "label": int(r["label"]),
                "ecosystem": r["ecosystem"], "package": r.get("package"),
                "language": lang, "code": cut,
                "archive_name": s["archive_name"],
                "label_source": s["label_source"],
            })
            got += 1
    return out, stats


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=30,
                    help="total samples (half malicious, half benign)")
    ap.add_argument("--chars", type=int, default=2500)
    ap.add_argument("--models", nargs="*", default=MODELS)
    args = ap.parse_args()
    n_per_class = args.n // 2

    from packguard.safety_port import (
        advisory_semantics_ok,
        compute_safety_metrics,
        evaluate_prereg_rules,
        load_safety_config,
        run_arm,
    )
    from src.models.llm_harness import LLMHarness

    cfg = load_safety_config(ROOT / "configs/packguard_safety.yaml")
    samples, sel_stats = pick_samples(n_per_class, args.chars)
    n_mal = sum(1 for s in samples if s["label"] == 1)
    print(f"samples: {len(samples)} (mal={n_mal}, ben={len(samples)-n_mal}); "
          f"selection stats: {sel_stats}")
    assert all(advisory_semantics_ok(
        s["code"],
        cfg["package_fixture"]["advisory_comment_" + (
            "python" if s["language"] == "python"
            else "javascript")].strip("\n") + "\n" + s["code"],
        s["language"]) for s in samples), "P2 gate must pass for all samples"

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "safety_batch.jsonl"
    keep_ids = {s["sample_id"] for s in samples}
    done: set = set()
    records: list[dict] = []
    if out_path.exists():
        with out_path.open() as f:
            for line in f:
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if "sample_id" in r:
                    if r["sample_id"] not in keep_ids:
                        continue  # stale records from a larger earlier draw
                    records.append(r)
                    done.add((r["sample_id"], r["arm"], r["model_id"]))

    meta = {
        "date": _now(),
        "n_samples": len(samples),
        "n_malicious": n_mal,
        "seed": SEED,
        "arms": ARMS,
        "models": args.models,
        "code_chars": args.chars,
        "sample_selection": ("stratified mal/ben from dataset_v2, seed 20260922; "
                             "real package source text (text_v2 cache); samples "
                             "whose truncated snippet fails the P2 semantics gate "
                             "are replaced from the pool before any generation"),
        "selection_stats": sel_stats,
        "gen_cfg": cfg.get("gen_cfg"),
        "note": "REAL local generations on REAL packages (no fixture codes).",
    }
    with out_path.open("w") as f:
        f.write(json.dumps({"meta": meta}) + "\n")
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    for model_id in args.models:
        harness = LLMHarness(model_id, hf_home=str(ROOT / "models_dir/hf"))
        for arm in ARMS:
            for s in samples:
                if (s["sample_id"], arm, model_id) in done:
                    continue
                code = s["code"]
                if arm == "P2_advisory_in_package":
                    comment = cfg["package_fixture"][
                        "advisory_comment_" + ("python" if s["language"] == "python"
                                               else "javascript")].strip("\n")
                    code = comment + "\n" + code
                rec = run_arm(harness, arm, code, cfg,
                              sample_id=s["sample_id"], language=s["language"])
                rec["label"] = s["label"]
                rec["ecosystem"] = s["ecosystem"]
                records.append(rec)
                with out_path.open("a") as f:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                print(f"[{model_id.split('/')[-1][:18]:18s}] {arm:22s} "
                      f"{s['sample_id'][:44]:44s} status={rec['status']:7s} "
                      f"vuln={rec['vulnerable']}", flush=True)

    # ---- metrics per model + pooled ----
    def _metrics_for(recs: list[dict]) -> dict:
        arms_recs = {}
        labels = None
        for arm in ARMS:
            arm_recs = sorted((r for r in recs if r["arm"] == arm),
                              key=lambda r: r["sample_id"])
            arms_recs[arm] = arm_recs
            if labels is None:
                labels = [bool(r.get("label")) for r in arm_recs]
        return compute_safety_metrics(arms_recs, labels=[not b for b in labels])

    results = {"meta": meta, "per_model": {}, "pooled": None, "rules": {}}
    for model_id in args.models:
        m = _metrics_for([r for r in records if r["model_id"] == model_id])
        results["per_model"][model_id] = m
        results["rules"][model_id] = evaluate_prereg_rules(m, cfg.get("rules", {}))
    pooled = _metrics_for(records)
    results["pooled"] = pooled
    results["rules"]["pooled"] = evaluate_prereg_rules(pooled, cfg.get("rules", {}))

    with (OUT_DIR / "safety_metrics.json").open("w") as f:
        json.dump(results, f, indent=1, default=str)
    print("pooled RR:", results["pooled"]["rr"])
    print("rules:", json.dumps(results["rules"], indent=1, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
