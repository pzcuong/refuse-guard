"""Round-10 [r8] SAFETY EXPANSION n=60 -> n=100 (extends the round-9
round9_safety_n50.py pattern with the SAME arms/gen_cfg/monitor frozen in
configs/packguard_safety.yaml).

- Old state: outputs/packguard/safety/safety_batch_n60.jsonl (60 samples =
  30 mal + 30 ben, 360 records).
- This run draws gate-passers [30:50] PER CLASS of the SAME round-8 seeded
  draw (scripts.packguard_safety_batch.pick_samples, read-only) -> 20 NEW
  mal + 20 NEW ben = 40 NEW samples with ZERO overlap vs the old 60
  (asserted BEFORE any generation; pool verified to hold >=50 gate-passers
  per class: scan 560 -> 230 pass = 147 mal / 83 ben).
- 40 NEW x 3 arms (P0/P1/P2) x 2 models (unsloth/Llama-3.2-3B-Instruct,
  ibm-granite/granite-3.3-2b-instruct) = 240 NEW generations; old 360
  records COPIED verbatim (copied_from) -> merged n=100 (>= 100 target).
- P2 semantics gate re-asserted per NEW sample before any generation.
- Metrics per model + pooled (packguard.safety_port, dataset label
  convention True=malicious) + pre-registered rules -> safety_metrics_n100.

Resume-safe: existing (sample_id, arm, model) in the merged file are skipped.
Dry run (--dry): identical draw/gates/merge with a deterministic STUB
generator (0 model load, 0 GPU), mock=true records under dry/.
Real run cost: ~240 gen x ~30 s ≈ 2 h GPU.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _r10lib as L  # noqa: E402

OLD_FILE = L.ROOT / "outputs/packguard/safety/safety_batch_n60.jsonl"
ARMS = ["P0_neutral", "P1_offensive_wording", "P2_advisory_in_package"]
MODELS = ["unsloth/Llama-3.2-3B-Instruct", "ibm-granite/granite-3.3-2b-instruct"]
OLD_PER_CLASS = 30   # realized round-9 draw per class
NEW_PER_CLASS = 20   # -> 50 per class incl. the old 30
DRAW_PER_CLASS = OLD_PER_CLASS + NEW_PER_CLASS  # 50
CHARS = 2500


def _now() -> str:
    return L.now_utc()


def _select_new_samples() -> tuple[list[dict], dict]:
    from scripts.packguard_safety_batch import pick_samples

    samples, stats = pick_samples(DRAW_PER_CLASS, CHARS)  # per class
    mal, ben = samples[:DRAW_PER_CLASS], samples[DRAW_PER_CLASS:]
    assert len(mal) == DRAW_PER_CLASS and len(ben) == DRAW_PER_CLASS, \
        f"draw short: mal={len(mal)} ben={len(ben)} (pool gate-passers < " \
        f"{DRAW_PER_CLASS}/class — n=100 NOT reachable, failing loudly)"
    new = mal[OLD_PER_CLASS:] + ben[OLD_PER_CLASS:]
    return new, stats


def run(dry: bool) -> int:
    from packguard.safety_port import (
        advisory_semantics_ok, compute_safety_metrics, evaluate_prereg_rules,
        load_safety_config, run_arm,
    )

    cfg = load_safety_config(L.ROOT / "configs/packguard_safety.yaml")
    out = L.out_dir("r8_safety_expand", dry)
    new_file = out / "safety_batch_n100.jsonl"
    metrics_file = out / "safety_metrics_n100.json"

    # ---- old records + ids -------------------------------------------------
    old_records: list[dict] = []
    old_meta: dict = {}
    with OLD_FILE.open(encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if "sample_id" in r:
                old_records.append(r)
            elif "meta" in r:
                old_meta = r
    old_ids = {r["sample_id"] for r in old_records}
    old_mal_ids = {r["sample_id"] for r in old_records if r.get("label") == 1}
    print(f"[r8] old batch: {len(old_ids)} samples "
          f"({len(old_mal_ids)} malicious), {len(old_records)} records")

    # ---- new samples, zero-overlap + P2 gate (BEFORE any generation) -------
    new_samples, sel_stats = _select_new_samples()
    new_ids = {s["sample_id"] for s in new_samples}
    overlap = old_ids & new_ids
    assert not overlap, f"overlap with the n60 batch: {sorted(overlap)[:3]}"
    n_mal = sum(1 for s in new_samples if s["label"] == 1)
    assert n_mal == NEW_PER_CLASS and len(new_samples) == 2 * NEW_PER_CLASS
    for s in new_samples:
        comment = cfg["package_fixture"][
            "advisory_comment_" + ("python" if s["language"] == "python"
                                   else "javascript")].strip("\n")
        assert advisory_semantics_ok(s["code"], comment + "\n" + s["code"],
                                     s["language"]), \
            f"P2 gate failed for {s['sample_id']}"
    print(f"[r8] new samples: {len(new_samples)} (mal={n_mal}); overlap=0 "
          f"VERIFIED; P2 gate PASS all; selection stats: {sel_stats}")

    # ---- merged record set + resume ----------------------------------------
    records: list[dict] = []
    done: set = set()
    if new_file.exists():
        with new_file.open(encoding="utf-8") as f:
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
            c["copied_from"] = str(OLD_FILE)
            records.append(c)
            done.add((c["sample_id"], c["arm"], c["model_id"]))

    meta = {
        "date": _now(), "round": 10, "mock": bool(dry),
        "n_samples_total": len(old_ids) + len(new_ids),
        "n_samples_new": len(new_ids),
        "n_malicious_total": len(old_mal_ids) + n_mal,
        "seed": 20260922,
        "selection_rule": ("round-8 draw (seed 20260922, gate-passers per "
                           "class); NEW = gate-passers [30:50] per class of "
                           "the SAME draw -> zero overlap (asserted)"),
        "selection_stats_this_run": sel_stats,
        "arms": ARMS, "models": MODELS, "code_chars": CHARS,
        "gen_cfg": cfg.get("gen_cfg"),
        "dry_note": None if not dry else
                    ("STUB generator, 0 GPU — old records copied, new records "
                     "are stub verdicts flagged mock=true"),
    }
    with new_file.open("w", encoding="utf-8") as f:
        f.write(json.dumps({"meta": meta}, ensure_ascii=False) + "\n")
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False, default=str) + "\n")

    # ---- generation: model-sequential --------------------------------------
    n_made = 0
    for model_id in MODELS:
        if dry:
            harness = L.StubHarness(model_id)
            gen = L.stub_generator_factory()
        else:
            from src.models.llm_harness import LLMHarness

            harness = LLMHarness(model_id, hf_home=str(L.ROOT / "models_dir/hf"))
            gen = None
        for arm in ARMS:
            for s in sorted(new_samples, key=lambda x: x["sample_id"]):
                if (s["sample_id"], arm, model_id) in done:
                    continue
                code = s["code"]
                if arm == "P2_advisory_in_package":
                    comment = cfg["package_fixture"][
                        "advisory_comment_" + ("python" if s["language"] == "python"
                                               else "javascript")].strip("\n")
                    code = comment + "\n" + code
                rec = run_arm(harness, arm, code, cfg,
                              sample_id=s["sample_id"], language=s["language"],
                              generator=gen)
                rec["label"] = s["label"]
                rec["ecosystem"] = s["ecosystem"]
                rec["mock"] = bool(dry)
                records.append(rec)
                with new_file.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
                n_made += 1
                print(f"[r8] [{model_id.split('/')[-1][:16]:16s}] {arm:22s} "
                      f"{s['sample_id'][:40]:40s} status={rec['status']:7s} "
                      f"vuln={rec['vulnerable']}", flush=True)
    print(f"[r8] generations made this run: {n_made} "
          f"(expected NEW: {len(new_samples) * len(ARMS) * len(MODELS)})")

    # ---- metrics per model + pooled ----------------------------------------
    def _metrics_for(recs: list[dict]) -> dict:
        arms_recs, labels = {}, None
        for arm in ARMS:
            arm_recs = sorted((r for r in recs if r["arm"] == arm),
                              key=lambda r: r["sample_id"])
            arms_recs[arm] = arm_recs
            if labels is None:
                # DATASET convention: True = malicious (label==1); no inversion
                labels = [bool(r.get("label")) for r in arm_recs]
        return compute_safety_metrics(arms_recs, labels=labels)

    results: dict = {"meta": meta, "per_model": {}, "pooled": None, "rules": {}}
    for model_id in MODELS:
        m = _metrics_for([r for r in records if r["model_id"] == model_id])
        results["per_model"][model_id] = m
        results["rules"][model_id] = evaluate_prereg_rules(m, cfg.get("rules", {}))
    pooled = _metrics_for(records)
    results["pooled"] = pooled
    results["rules"]["pooled"] = evaluate_prereg_rules(pooled, cfg.get("rules", {}))
    metrics_file.write_text(json.dumps(results, indent=1, default=str),
                            encoding="utf-8")
    print(f"[r8] wrote {new_file} ({len(records)} records, "
          f"n_samples={meta['n_samples_total']})")
    print(f"[r8] wrote {metrics_file}")
    print("[r8] pooled RR:", pooled["rr"])
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry", action="store_true",
                    help="stub generator, 0 model load, mock=true outputs")
    args = ap.parse_args()
    return run(dry=args.dry)


if __name__ == "__main__":
    raise SystemExit(main())
