"""EVIDA paired-unit manifest (prereg §1.1: NO resampling, NO re-selection —
every unit is derived from an already-hashed, already-cached artifact).

S1 — RQ8 near-injection (bench_attack_v2, sha256_16 7e8ed42421a7c2d0):
     160 samples x {C0 clean unit, C5_near attack unit} x {granite, llama}.
     Raw records: outputs/experiments/round7_rq8/results_{granite2b,llama3b}.json
     (cache assert: exactly 320 records each, per (sample_id, condition)).
S2 — PackGuard defense set (seed_draw 20260922, gate-pass 38 x 2 models):
     per sample a P0 clean unit and — for the 24 malicious — a P2 attack unit.
     Raw records: outputs/packguard/defense/defense_batch.jsonl (P0_neutral +
     P2_advisory_in_package rows, defense_gate_pass rows only).
     V_trusted view = stripped P0 source; the runner asserts strip(P0) ==
     strip(P2) byte-identity per sample (M4) — the registered new generation
     is therefore the P2D1-view generation already in the LLM cache (76/76
     verified at pilot prep), emitted with cache:true + copied_from.
S3 — E6 IPI pairs: NOT REALIZED AT PILOT (disclosed).  Rebuilding the frozen
     C3 carrier prompt machinery post-freeze risks a prompt-machinery drift
     the prereg forbids; the E6 stratum is reported not-evaluable (prereg
     §1.10 soft-stop semantics), qwen is outside the pilot model roster
     (prereg §1.1: replication only).  No gated comparison touches S3.
S4 — safety contrast: cache-only recompute (no unit; safety preservation is
     reported from outputs/experiments/round3_e8*/recomputed + an invariant
     check over EVIDA's own records).

Unit record fields (emitted to evida_units.json):
  unit_id, source (S1|S2), model, sample_id, family, label, language,
  unit_kind (clean|attack), raw_view {arm, func, verdict(y_pred), status,
  prompt_sha16, record_path}, clean_ref {verdict...} (attack units),
  trusted_view {func_stripped, strip_meta, prompt_builder}
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research_program.evida_strip import strip_view  # noqa: E402

__all__ = ["build_units", "unit_list_hash"]

RQ8_DIR = PROJECT_ROOT / "outputs/experiments/round7_rq8"
RQ8_RESULTS = {
    "ibm-granite/granite-3.3-2b-instruct": RQ8_DIR / "results_granite2b.json",
    "unsloth/Llama-3.2-3B-Instruct": RQ8_DIR / "results_llama3b.json",
}
RQ8_BENCH = PROJECT_ROOT / "data/benchmarks/bench_attack_v2/bench_attack_v2.jsonl"
RQ8_BENCH_SHA16 = "7e8ed42421a7c2d0"
DEFENSE_BATCH = PROJECT_ROOT / "outputs/packguard/defense/defense_batch.jsonl"
DEFENSE_BATCH_SHA16 = "5bc02c99a026246b"
PG_MODELS = ("ibm-granite/granite-3.3-2b-instruct",
             "unsloth/Llama-3.2-3B-Instruct")

_EXPECTED_BENCH_SHA16 = "7e8ed42421a7c2d0"


def _sha16_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def _sha16_prompt(prompt: dict) -> str:
    return hashlib.sha256(
        json.dumps(prompt, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()[:16]


def _load_rq8_entries() -> dict:
    """(sample_id, arm) -> bench entry (the arm dict carries func/language)."""
    import warnings

    sys.path.insert(0, str(PROJECT_ROOT))
    from src.experiments.round5_e0v2 import load_bench  # read-only reuse

    rows = [json.loads(l) for l in
            RQ8_BENCH.read_text(encoding="utf-8").splitlines() if l.strip()]
    sha = _sha16_file(RQ8_BENCH)
    if sha != _EXPECTED_BENCH_SHA16:
        raise AssertionError(
            f"bench_attack_v2 sha mismatch: {sha} != {_EXPECTED_BENCH_SHA16} "
            "(the registered bench changed — ABORT per prereg §1.9.3)")
    out = {}
    for r in rows:
        for arm in ("C0", "C5_near"):
            e = r["arms"][arm]
            out[(str(r["sample_id"]), arm)] = {
                "sample_id": str(r["sample_id"]), "arm": arm,
                "func": e["func"], "language": r["language"],
                "label": int(r["label"]), "family": r["family"],
            }
    return out


def _verdict_of(rec: dict) -> int | None:
    """Parsed verdict from any cached-record layout (RQ8: y_pred; safety
    port: vulnerable / parsed.vulnerable).  A REFUSAL view is NEVER parsed
    into a verdict (repo invariant; prereg §1.9.2) — returns None instead."""
    status = str(rec.get("status", "") or "").upper()
    if status == "REFUSAL":
        return None
    for key_chain in (("y_pred",), ("vulnerable",), ("parsed", "vulnerable")):
        v = rec
        ok = True
        for k in key_chain:
            if not isinstance(v, dict) or k not in v:
                ok = False
                break
            v = v[k]
        if ok and v in (0, 1, "0", "1", True, False):
            return int(v)
    return None


def _rq8_records(model_id: str) -> dict:
    path = RQ8_RESULTS[model_id]
    d = json.loads(path.read_text(encoding="utf-8"))
    md = d.get("metadata", {})
    if md.get("model_id") != model_id:
        raise AssertionError(
            f"[evida model-guard] {path.name}: model_id={md.get('model_id')!r} "
            f"!= {model_id!r}")
    out = {}
    for rec in d.get("records", []):
        if rec.get("status") == "SKIPPED":
            continue
        out[(str(rec["sample_id"]), rec["condition"])] = rec
    return out


def build_units(models: list[str]) -> tuple[list[dict], dict]:
    """Build + cache-assert the full S1/S2 unit manifest.  ABORTS (fail
    loudly, prereg §1.9.3) when any registered cached record is missing."""
    entries = _load_rq8_entries()
    units: list[dict] = []
    meta = {"S1": {"n_samples": 0, "n_units": 0, "cache_asserts": []},
            "S2": {"n_samples": 0, "n_units": 0, "cache_asserts": [],
                   "strip_p0_eq_p2": 0, "strip_p0_neq_p2": 0},
            "sources": ["S1", "S2"], "S3": "NOT_REALIZED_AT_PILOT (disclosed)"}

    # ---------------- S1 (RQ8) ----------------
    for model_id in models:
        recs = _rq8_records(model_id)
        sids = sorted({sid for (sid, _arm) in entries})
        n_units_model = 0
        for sid in sids:
            e0 = entries[(sid, "C0")]
            rec_c0 = recs.get((sid, "C0"))
            rec_c5 = recs.get((sid, "C5_near"))
            if rec_c0 is None or rec_c5 is None:
                raise AssertionError(
                    f"[evida cache-assert] RQ8 {model_id} missing cached "
                    f"record for ({sid}, C0/C5_near) — ABORT (prereg §1.9.3)")
            lang = "cpp" if e0["language"] == "cpp" else "c"
            common = {"source": "S1", "model": model_id, "sample_id": sid,
                      "family": e0["family"], "label": e0["label"],
                      "language": lang}
            for kind, arm, rec in (("clean", "C0", rec_c0),
                                   ("attack", "C5_near", rec_c5)):
                func = entries[(sid, arm)]["func"]
                units.append({
                    **common, "unit_id": f"S1|{model_id}|{sid}|{arm}",
                    "unit_kind": kind, "raw_arm": arm,
                    "raw_view": {"arm": arm, "func": func,
                                 "y_pred": _verdict_of(rec),
                                 "status": rec.get("status"),
                                 "cwe": (rec.get("meta") or {}).get("pred_cwe"),
                                 "location": (rec.get("meta") or {}).get(
                                     "pred_location"),
                                 "prompt_sha16": (rec.get("meta") or {}).get(
                                     "prompt_sha256_16"),
                                 "record_path": str(
                                     RQ8_RESULTS[model_id].relative_to(
                                         PROJECT_ROOT))},
                    "clean_ref": (None if kind == "clean" else {
                        "y_pred": _verdict_of(rec_c0),
                        "status": rec_c0.get("status")}),
                })
                n_units_model += 1
        meta["S1"]["cache_asserts"].append(
            {"model": model_id, "records": len(recs), "expected": 320,
             "ok": len(recs) == 320})
        if len(recs) != 320:
            raise AssertionError(
                f"[evida cache-assert] {model_id}: {len(recs)} RQ8 records "
                "!= 320 — ABORT (prereg §1.9.3)")
        meta["S1"]["n_samples"] += len(sids)
        meta["S1"]["n_units"] += n_units_model

    # ---------------- S2 (PackGuard defense set) ----------------
    sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
    from scripts.packguard_safety_batch import pick_samples  # read-only redraw

    from packguard.safety_port import load_safety_config, render_prompt

    scfg = load_safety_config(PROJECT_ROOT / "configs/packguard_safety.yaml")
    samples, _stats = pick_samples(50, 2500)
    by_id = {s["sample_id"]: s for s in samples}
    cmt = {"python": scfg["package_fixture"]["advisory_comment_python"].strip(),
           "javascript": scfg["package_fixture"][
               "advisory_comment_javascript"].strip()}
    batch: dict = {}
    for line in DEFENSE_BATCH.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        if "sample_id" not in r:
            continue
        batch[(r["sample_id"], r["arm"], r["model_id"])] = r
    gate_ids = sorted({sid for (sid, arm, _m) in batch
                       if arm == "P0_neutral"})
    for model_id in PG_MODELS:
        if model_id not in models:
            continue
        n_units_model = 0
        for sid in gate_ids:
            s = by_id.get(sid)
            if s is None:
                raise AssertionError(
                    f"[evida cache-assert] S2 sample {sid} not in the redraw "
                    "— ABORT (prereg §1.9.3)")
            lang = s["language"]
            rec_p0 = batch.get((sid, "P0_neutral", model_id))
            rec_p2 = batch.get((sid, "P2_advisory_in_package", model_id))
            if rec_p0 is None:
                raise AssertionError(
                    f"[evida cache-assert] S2 {model_id} missing P0_neutral "
                    f"row for {sid} — ABORT (prereg §1.9.3)")
            stripped_p0, m0 = strip_view(s["code"], lang)
            common = {"source": "S2", "model": model_id, "sample_id": sid,
                      "family": None, "label": int(s["label"]),
                      "language": lang}
            # trusted view built ONCE per sample: the stripped P0 source; the
            # prompt (P2D1 task text == P0 task text, asserted in round 12)
            # is byte-identical for the clean and the attack unit.
            trusted = {"func_stripped": stripped_p0, "strip_meta": m0,
                       "prompt_builder": "packguard.safety_port.render_prompt"
                                         "('P2D1_strip', stripped_P0, "
                                         "safety_config e3e37d636a92a998)",
                       "task_text_arm": "P2D1_strip"}
            if s["label"] == 1:
                p2_code = cmt[lang] + "\n" + s["code"]
                stripped_p2, m2 = strip_view(p2_code, lang)
                if m0.get("gate_pass") and m2.get("gate_pass"):
                    if stripped_p0 == stripped_p2:
                        meta["S2"]["strip_p0_eq_p2"] += 1
                    else:
                        meta["S2"]["strip_p0_neq_p2"] += 1
                if rec_p2 is None:
                    raise AssertionError(
                        f"[evida cache-assert] S2 {model_id} missing "
                        f"P2_advisory_in_package row for {sid} — ABORT")
                units.append({
                    **common, "unit_id": f"S2|{model_id}|{sid}|P2",
                    "unit_kind": "attack", "raw_arm": "P2_advisory_in_package",
                    "raw_view": {"arm": "P2_advisory_in_package",
                                 "func": p2_code,
                                 "y_pred": _verdict_of(rec_p2),
                                 "status": rec_p2.get("status"),
                                 "cwe": ((rec_p2.get("parsed") or {}) or {}).get(
                                     "cwe"),
                                 "location": ((rec_p2.get("parsed") or {})
                                              or {}).get("location"),
                                 "prompt_sha16": rec_p2.get("p2d1_prompt_sha16"),
                                 "record_path": str(
                                     DEFENSE_BATCH.relative_to(PROJECT_ROOT))},
                    "clean_ref": {"y_pred": _verdict_of(rec_p0),
                                  "status": rec_p0.get("status")},
                    "trusted_view": trusted,
                })
                n_units_model += 1
            units.append({
                **common, "unit_id": f"S2|{model_id}|{sid}|P0",
                "unit_kind": "clean", "raw_arm": "P0_neutral",
                "raw_view": {"arm": "P0_neutral", "func": s["code"],
                             "y_pred": _verdict_of(rec_p0),
                             "status": rec_p0.get("status"),
                             "cwe": ((rec_p0.get("parsed") or {}) or {}).get(
                                 "cwe"),
                             "location": ((rec_p0.get("parsed") or {})
                                          or {}).get("location"),
                             "prompt_sha16": rec_p0.get("p0_prompt_sha16"),
                             "record_path": str(
                                 DEFENSE_BATCH.relative_to(PROJECT_ROOT))},
                "clean_ref": None,
                "trusted_view": trusted,
            })
            n_units_model += 1
        meta["S2"]["n_units"] += n_units_model
    meta["S2"]["n_samples"] = len(gate_ids)

    # S1 attack units carry their trusted view (stripped per-arm func)
    for u in units:
        if u["source"] == "S1":
            lang = u["language"]
            stripped, m = strip_view(u["raw_view"]["func"], lang)
            u["trusted_view"] = {"func_stripped": stripped, "strip_meta": m,
                                 "prompt_builder": "src.conditions."
                                 "c5_risk_context.build_attack_prompt via "
                                 "round5_e0v2.render_prompt (stripped func)",
                                 "task_text_arm": u["raw_arm"]}
    return units, meta


def unit_list_hash(units: list[dict]) -> str:
    ids = sorted(u["unit_id"] for u in units)
    blob = json.dumps(ids, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]
