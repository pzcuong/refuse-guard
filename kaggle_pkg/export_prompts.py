"""Round-16 W: deterministic Kaggle prompt export (GPU-blocked experiments).

Exports TWO prompt files for the two previously GPU-blocked experiments, so
they can run on Kaggle (T4 x2) without shipping the repo:

  P1-10  ladder A0/A5/A1 on the 60-vulnerable subset of bench_attack_v1
         (registered round-6/7/9/10 ladder protocol: seed_subset 20260923,
         arm C5_near, n_vul 60) -> data/ladder_prompts_7b8b.jsonl
         (60 samples x 3 rungs = 180 rows; the SAME file feeds BOTH kernels,
         Qwen2.5-Coder-7B-Instruct and unsloth/Llama-3.1-8B-Instruct).
         NOTE: the round-16 tasking text said "subset seed 20260922" and
         "120 rows"; the registered ladder protocol (configs/round7_7b.yaml,
         configs/r10_granite_ladder.yaml -- the "round-9 granite ladder
         protocol" the tasking cites) fixes seed_subset 20260923 and 3 rungs,
         so the export follows the REGISTERED protocol (seed 20260923, 180
         rows) to stay sample-paired with rounds 6/7/10.  Disclosed in
         AMENDMENT-9 and reports/round16/W_report.md.
         20260922 is the SEPARATE safety-batch selection seed (below).

  P1-8-partial  safety arms P0/P1/P2 on the n=100 safety batch (50 mal + 50
         ben; round-8 draw seed 20260922, gate-passers, code_chars=2500,
         EXACTLY the selection already recorded in
         outputs/packguard/r10/r8_safety_expand/safety_batch_n100.jsonl)
         -> data/safety_prompts_7b.jsonl (100 x 3 = 300 rows; Qwen 7B kernel
         only, per tasking).

Prompts are rebuilt by the AUDITED machinery, read-only:
  ladder : src.experiments.round7_7b.load_config + build_subsets and
           src.experiments.round6_ablation.prompt_for (A0 == b0_prompt,
           A5 == p3_prompt reassertion, A1 == boundary-only ladder mediation)
  safety : scripts.packguard_safety_batch.pick_samples (seed 20260922 draw)
           + packguard.safety_port.render_prompt (frozen arm texts).

Row schema (both files, one JSON object per line):
  {sample_id, label, rung|arm, system, user, prompt_sha256_16, ...}
with prompt_sha256_16 = sha256(json.dumps({system,user}, sort_keys=True)
                               .encode()).hexdigest()[:16]
-- the SAME convention as pilot_round2.sha16 used by every prior round
  (verified against stored per-record prompt_sha256_16 values below).

Verification baked into the export (asserted, reported in the meta file):
  V1 ladder A0 + A5: per-sample prompt shas == round-7 qwen7b records
     (outputs/experiments/round7_7b/results_qwen7b__vul__{A0,A5}.json) 60/60.
  V2 ladder A1: per-sample prompt shas == r10 granite records
     (outputs/experiments/r10_granite_ladder/results_granite2b__vul__A1.json)
     60/60 (the sha gate is model-blind; a cross-model sha match is exactly a
     byte-identity proof of the rebuild).
  V3 safety: the 100 drawn (sample_id, label, ecosystem, language) ==
     the n100 batch records' unique samples; draw stats scanned/gate_pass
     equal the recorded meta (265 / 100).
  V4 safety P0: prompt shas == p0_prompt_sha16 stored in the round-12
     defense batch for every overlapping sample.

Run:  .venv/bin/python kaggle_pkg/export_prompts.py
Writes only inside kaggle_pkg/ (+ this file's verification JSON).  No GPU,
no generation, no network.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DATA_DIR = Path(__file__).resolve().parent / "data"
LADDER_OUT = DATA_DIR / "ladder_prompts_7b8b.jsonl"
SAFETY_OUT = DATA_DIR / "safety_prompts_7b.jsonl"
VERIFY_OUT = Path(__file__).resolve().parent / "prompts_verification.json"

LADDER_RUNGS = ["A0", "A5", "A1"]          # queue priority order (r7 protocol)
SAFETY_ARMS = ["P0_neutral", "P1_offensive_wording", "P2_advisory_in_package"]
SAFETY_N_PER_CLASS = 50                     # n=100 batch (50 mal + 50 ben)
SAFETY_CHARS = 2500                         # code_chars of the round-8 draw

R7_QWEN = ROOT / "outputs/experiments/round7_7b"
R10_GRANITE = ROOT / "outputs/experiments/r10_granite_ladder"
SAFETY_N100 = ROOT / "outputs/packguard/r10/r8_safety_expand/safety_batch_n100.jsonl"
DEFENSE_BATCH = ROOT / "outputs/packguard/defense/defense_batch.jsonl"


def sha16(obj) -> str:
    """pilot_round2.sha16 convention (the prompt-sha of every prior round)."""
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# P1-10 ladder export (registered round-6/7/9/10 protocol, seed 20260923)
# ---------------------------------------------------------------------------
def build_ladder_rows() -> tuple[list[dict], dict]:
    from src.experiments.round7_7b import load_config, build_subsets
    from src.experiments.round6_ablation import prompt_for

    cfg = load_config()                       # configs/round7_7b.yaml (frozen)
    vul, _ben, sel_meta, _bench_meta = build_subsets(cfg)
    assert len(vul) == 60, f"expected 60 vul, got {len(vul)}"
    rows: list[dict] = []
    for rung in LADDER_RUNGS:                 # rung-major, sample-major within
        for sid in sorted(vul):
            entry = vul[sid]
            prompt, psrc = prompt_for(entry, rung, cfg)
            assert prompt.get("system") and prompt.get("user")
            rows.append({
                "sample_id": sid,
                "label": int(entry["label"]),
                "arm": entry["arm"],
                "rung": rung,
                "language": entry["language"],
                "system": prompt["system"],
                "user": prompt["user"],
                "prompt_sha256_16": sha16({"system": prompt["system"],
                                           "user": prompt["user"]}),
                "prompt_source": psrc,
            })
    meta = {
        "task": "P1-10 provenance-closure ladder (A0/A5/A1)",
        "protocol": "configs/round7_7b.yaml (byte-identical to r10/r9 ladder)",
        "seed_subset": int(cfg["pool"]["seed_subset"]),
        "arm": cfg["ablation"]["arm"],
        "n_vul": len(vul),
        "n_rows": len(rows),
        "vul_ids": sorted(vul),
        "gen_cfg_locked": dict(cfg["gen_cfg"]),
        "selection_rule": cfg["pool"]["selection_rule"],
    }
    return rows, meta


def _stored_shas(path: Path) -> dict[str, str]:
    d = json.loads(path.read_text(encoding="utf-8"))
    out = {}
    for r in d.get("records", []):
        if r.get("status") == "SKIPPED":
            continue
        sha = (r.get("meta") or {}).get("prompt_sha256_16")
        if sha:
            out[r["sample_id"]] = sha
    return out


def verify_ladder(rows: list[dict]) -> dict:
    shas = {(r["rung"], r["sample_id"]): r["prompt_sha256_16"] for r in rows}
    checks = {}
    for name, path, rung in (
        ("A0_vs_round7_qwen7b", R7_QWEN / "results_qwen7b__vul__A0.json", "A0"),
        ("A5_vs_round7_qwen7b", R7_QWEN / "results_qwen7b__vul__A5.json", "A5"),
        ("A1_vs_r10_granite2b", R10_GRANITE / "results_granite2b__vul__A1.json", "A1"),
    ):
        stored = _stored_shas(path)
        match = sum(1 for sid, s in stored.items()
                    if shas.get((rung, sid)) == s)
        checks[name] = {"file": str(path.relative_to(ROOT)), "rung": rung,
                        "n_stored": len(stored), "n_match": match}
    return checks


# ---------------------------------------------------------------------------
# P1-8-partial safety export (round-8 draw, seed 20260922, n=100 selection)
# ---------------------------------------------------------------------------
def build_safety_rows() -> tuple[list[dict], dict]:
    sys.path.insert(0, str(ROOT / "scripts"))
    from packguard_safety_batch import pick_samples          # read-only reuse
    from packguard.safety_port import load_safety_config, render_prompt

    cfg = load_safety_config(ROOT / "configs/packguard_safety.yaml")
    samples, stats = pick_samples(SAFETY_N_PER_CLASS, SAFETY_CHARS)
    assert len(samples) == 2 * SAFETY_N_PER_CLASS, \
        f"draw returned {len(samples)} samples"
    by_label = {1: 0, 0: 0}
    for s in samples:
        by_label[int(s["label"])] += 1
    assert by_label == {1: SAFETY_N_PER_CLASS, 0: SAFETY_N_PER_CLASS}, by_label

    rows: list[dict] = []
    for arm in SAFETY_ARMS:                   # arm-major, sample-major within
        for s in sorted(samples, key=lambda x: x["sample_id"]):
            code = s["code"]
            if arm == "P2_advisory_in_package":
                key = ("advisory_comment_python" if s["language"] == "python"
                       else "advisory_comment_javascript")
                code = cfg["package_fixture"][key].strip("\n") + "\n" + s["code"]
            prompt = render_prompt(arm, code, cfg, s["language"])
            assert prompt.get("system") and prompt.get("user")
            rows.append({
                "sample_id": s["sample_id"],
                "label": int(s["label"]),
                "ecosystem": s["ecosystem"],
                "package": s.get("package"),
                "arm": arm,
                "language": s["language"],
                "system": prompt["system"],
                "user": prompt["user"],
                "prompt_sha256_16": sha16({"system": prompt["system"],
                                           "user": prompt["user"]}),
            })
    meta = {
        "task": "P1-8-partial safety arms P0/P1/P2 on the n=100 batch (7B)",
        "seed": 20260922,
        "selection_rule": ("round-8 draw (scripts.packguard_safety_batch."
                           "pick_samples), gate-passers, first 50 per class"),
        "code_chars": SAFETY_CHARS,
        "n_samples": len(samples),
        "n_rows": len(rows),
        "draw_stats": stats,
        "gen_cfg_locked": dict(cfg["gen_cfg"]),
        "models_planned": ["Qwen/Qwen2.5-Coder-7B-Instruct"],
    }
    return rows, meta


def _n100_truth() -> tuple[dict[str, dict], dict]:
    samples: dict[str, dict] = {}
    meta = None
    with SAFETY_N100.open("r", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if "meta" in r and len(r) <= 2:
                meta = r["meta"]
                continue
            cur = samples.setdefault(r["sample_id"], {
                "label": int(r["label"]), "ecosystem": r["ecosystem"],
                "language": r["language"]})
            assert cur == {"label": int(r["label"]),
                           "ecosystem": r["ecosystem"],
                           "language": r["language"]}, r["sample_id"]
    return samples, meta


def verify_safety(rows: list[dict]) -> dict:
    truth, n100_meta = _n100_truth()
    drawn = {r["sample_id"]: {"label": r["label"], "ecosystem": r["ecosystem"],
                              "language": r["language"]} for r in rows}
    match = sum(1 for sid, t in truth.items() if drawn.get(sid) == t)
    extra = sorted(set(drawn) - set(truth))
    # V4: P0 prompt shas vs the round-12 defense batch (stored p0_prompt_sha16)
    stored_p0: dict[str, str] = {}
    if DEFENSE_BATCH.exists():
        with DEFENSE_BATCH.open("r", encoding="utf-8") as f:
            for line in f:
                r = json.loads(line)
                if r.get("p0_prompt_sha16"):
                    stored_p0[r["sample_id"]] = r["p0_prompt_sha16"]
    p0 = {r["sample_id"]: r["prompt_sha256_16"] for r in rows
          if r["arm"] == "P0_neutral"}
    p0_match = sum(1 for sid, s in stored_p0.items() if p0.get(sid) == s)
    return {
        "n100_truth_file": str(SAFETY_N100.relative_to(ROOT)),
        "n100_unique_samples": len(truth),
        "n_match_id_label_eco_lang": match,
        "extra_ids": extra[:5],
        "draw_stats": None if n100_meta is None else {
            "scanned": n100_meta.get("selection_stats_this_run", {}).get("scanned"),
            "gate_pass": n100_meta.get("selection_stats_this_run", {}).get("gate_pass"),
        },
        "P0_vs_round12_defense_batch": {
            "file": str(DEFENSE_BATCH.relative_to(ROOT)),
            "n_stored_p0_shas": len(stored_p0), "n_match": p0_match,
        },
    }


# ---------------------------------------------------------------------------
def main() -> int:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    ladder, ladder_meta = build_ladder_rows()
    safety, safety_meta = build_safety_rows()

    with LADDER_OUT.open("w", encoding="utf-8") as f:
        for r in ladder:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with SAFETY_OUT.open("w", encoding="utf-8") as f:
        for r in safety:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    v_lad = verify_ladder(ladder)
    v_saf = verify_safety(safety)
    for name, c in v_lad.items():
        assert c["n_match"] == c["n_stored"] == 60, \
            f"ladder verification FAILED: {name}: {c}"
    vs = v_saf
    assert vs["n_match_id_label_eco_lang"] == vs["n100_unique_samples"] == 100, \
        f"safety selection mismatch: {vs}"
    # the recorded n100 meta lacks the gate_fail key (added later); compare
    # on the keys it records
    assert vs["draw_stats"] == {k: safety_meta["draw_stats"][k]
                                for k in vs["draw_stats"]}, \
        (vs["draw_stats"], safety_meta["draw_stats"])
    p0v = vs["P0_vs_round12_defense_batch"]
    assert p0v["n_match"] == p0v["n_stored_p0_shas"], \
        f"P0 sha mismatch vs round-12 defense batch: {p0v}"

    verify = {
        "date_utc": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc).isoformat(),
        "ladder_file": str(LADDER_OUT.relative_to(ROOT)),
        "ladder_rows": len(ladder), "ladder_meta": ladder_meta,
        "safety_file": str(SAFETY_OUT.relative_to(ROOT)),
        "safety_rows": len(safety), "safety_meta": safety_meta,
        "verification": {"ladder": v_lad, "safety": v_saf},
        "file_sha256_16": {
            "ladder": hashlib.sha256(LADDER_OUT.read_bytes()).hexdigest()[:16],
            "safety": hashlib.sha256(SAFETY_OUT.read_bytes()).hexdigest()[:16],
        },
    }
    VERIFY_OUT.write_text(json.dumps(verify, indent=2, ensure_ascii=False),
                          encoding="utf-8")
    print(f"[export] ladder  {len(ladder):4d} rows -> {LADDER_OUT}")
    print(f"[export] safety  {len(safety):4d} rows -> {SAFETY_OUT}")
    print(f"[export] verification: ladder "
          f"{ {k: c['n_match'] for k, c in v_lad.items()} } | "
          f"safety n100 {vs['n_match_id_label_eco_lang']}/100, P0-vs-r12 "
          f"{p0v['n_match']}/{p0v['n_stored_p0_shas']}")
    print(f"[export] meta -> {VERIFY_OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
