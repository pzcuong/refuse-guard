"""EVIDA-2 (round 18): the round-17 EVIDA pipeline plus the FROZEN alarm
PRUNING rule PRUNE-1 (docs/packguard_prereg.md AMENDMENT-11).

Round-17 failure (frozen provenance): alarm precision .2111 (57 TP / 213 FP,
F3 fired), CRR .2182 < .40, DIER pooled .1712 > .05.  Failure analysis
(outputs/packguard/evida2/r17_alarm_log_analysis.json, computed-by-script):
167/213 FPs are 0->1 disagreements (stripping makes the code look MORE
vulnerable - comment-cue loss / generation noise, never a corruption
signal), and 37/55 granite primary corruption events are INERT
counterfactuals (V_raw == V_trusted: the alarm channel cannot fire).

PRUNE-1 (the ONLY mechanism change; everything else is the frozen r17
machinery): keep an alarm for adjudication iff
  (1) strip-change clause: the stripped prompt differs from the raw prompt
      (byte-identical prompts resolve to the raw verdict - registered reuse
      policy, never re-generated); and
  (2) direction clause: (V_raw, V_strip) == (1, 0)  (stripping REMOVED a
      vulnerability verdict - the signature of a de-inflated corruption).
Pruned alarms: final := V_raw, no adjudication, no fallback.

Rule inputs = {raw verdict, strip verdict, prompt-sha equality} ONLY: no
ground-truth label, no CWE family, no clean-reference verdict enters the
alarm decision (anti-oracle, charter section 11).  Labels are read ONLY in
the analysis phase (event / CRR / DIER definitions).

Design basis on the r17 log (POST-HOC w.r.t. r17, PRE-REGISTERED w.r.t. the
round-18 run): TP kept 55/57 (.9649 >= .80), FP removed 179/213 (.8404 >=
.60), precision-after .6180; counterfactual DIER pooled .1712 -> .0753;
CRR .2182 -> .2000 (pruning does NOT repair recovery - declared AT RISK in
AMENDMENT-11).
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research_program.evida_adjudicator import EvidaAdjudicator  # noqa: E402
from research_program.evida_strip import strip_view  # noqa: E402

__all__ = [
    "PRUNE_SPEC", "BENCH_PATH", "BENCH_SHA16", "MODELS",
    "sha16", "load_bench_rows", "draw_samples", "build_units",
    "run_pruning_rule", "decide_unit", "compute_endpoints_v2",
    "evaluate_gates_v2",
]

# --- frozen registration constants (AMENDMENT-11) -------------------------
PRUNE_SPEC = {
    "name": "PRUNE-1",
    "clause_1_strip_change": "prompt_sha_strip != prompt_sha_raw "
                             "(byte-identical -> reuse raw verdict, no alarm)",
    "clause_2_direction": "(V_raw, V_strip) == (1, 0)",
    "pruned_action": "final := V_raw (no adjudication, no fallback)",
    "inputs": ["raw_y", "strip_y", "prompt_sha_equality"],
    "labels_used": "NONE at runtime",
    "design_basis": "outputs/packguard/evida2/r17_alarm_log_analysis.json",
}
BENCH_PATH = PROJECT_ROOT / "data/benchmarks/bench_attack_v2/bench_attack_v2.jsonl"
BENCH_SHA16 = "7e8ed42421a7c2d0"
MODELS = ("ibm-granite/granite-3.3-2b-instruct",
          "unsloth/Llama-3.2-3B-Instruct")
ARMS = ("C0", "C5_near")

# frozen r17 comparator numbers (quoted provenance: r17 prereg execution log
# + outputs/experiments/round17_evida/evida_analysis.json - never recomputed
# silently; the r17 log analysis artifact re-derives them by script)
R17_COMPARATORS = {
    "alarm_precision_unpruned": {"num": 57, "den": 270, "rate": 0.2111},
    "CRR_granite_pooled": {"num": 12, "den": 55, "rate": 0.2182},
    "DIER_pooled_clean": {"num": 25, "den": 146, "rate": 0.1712},
}

GATES = {"precision_min": 0.40, "crr_min": 0.35, "dier_max": 0.05,
         "uac_min": 0.95}


def sha16(obj: Any) -> str:
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str)
        .encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# bench + registered draw
# ---------------------------------------------------------------------------
def load_bench_rows(path: Path = BENCH_PATH) -> list[dict]:
    """Read bench_attack_v2 with the frozen sha assert (fail loudly)."""
    blob = path.read_bytes()
    sha = hashlib.sha256(blob).hexdigest()[:16]
    if sha != BENCH_SHA16:
        raise AssertionError(
            f"bench_attack_v2 sha mismatch: {sha} != {BENCH_SHA16} - ABORT "
            "(the registered bench changed; AMENDMENT-11 A11.2)")
    rows = [json.loads(l) for l in blob.decode("utf-8").splitlines() if l.strip()]
    if len(rows) != 160:
        raise AssertionError(f"bench_attack_v2: {len(rows)} rows != 160")
    return rows


def draw_samples(rows: list[dict], per_stratum: int = 10) -> list[dict]:
    """Registered draw (A11.2): first `per_stratum` sample_ids per
    (family, label), ascending sort. Deterministic; label is used ONLY for
    the stratified draw (benchmark design metadata), never at runtime."""
    strata: dict[tuple[str, str], list[dict]] = {}
    for r in rows:
        strata.setdefault((str(r["family"]), str(int(r["label"]))), []).append(r)
    out = []
    for key in sorted(strata):
        members = sorted(strata[key], key=lambda r: str(r["sample_id"]))
        if len(members) < per_stratum:
            raise AssertionError(
                f"stratum {key}: {len(members)} < {per_stratum} - ABORT")
        out.extend(members[:per_stratum])
    return sorted(out, key=lambda r: str(r["sample_id"]))


# ---------------------------------------------------------------------------
# units
# ---------------------------------------------------------------------------
def build_units(samples: list[dict], models: list[str],
                safety_cfg: dict) -> tuple[list[dict], dict]:
    """Per (sample, model, arm): raw prompt (safety-port P0_neutral frame,
    language c/cpp), D1 strip view (lenient-canonical c/cpp gate), strip
    prompt + clause-1 reuse flag.  Gate FAIL -> excluded + disclosed."""
    from packguard.safety_port import render_prompt

    units: list[dict] = []
    excluded: list[dict] = []
    n_reuse = 0
    for model_id in models:
        for s in samples:
            lang = "cpp" if s["language"] == "cpp" else "c"
            common = {
                "source": "V2", "model": model_id,
                "sample_id": str(s["sample_id"]), "family": s["family"],
                "label": int(s["label"]), "language": lang,
                "cve": s.get("cve"), "project": s.get("project"),
            }
            per_arm: dict[str, dict] = {}
            for arm in ARMS:
                func = s["arms"][arm]["func"]
                prompt_raw = render_prompt("P0_neutral", func, safety_cfg, lang)
                stripped, meta = strip_view(func, lang)
                if not meta.get("gate_pass"):
                    excluded.append({
                        "unit_id": f"V2|{model_id}|{s['sample_id']}|{arm}",
                        "reason": "defense_gate_fail",
                        "gate_error": meta.get("gate_error"),
                        "gate_mode": meta.get("gate_mode")})
                    continue
                prompt_strip = render_prompt("P0_neutral", stripped,
                                             safety_cfg, lang)
                sha_raw, sha_strip = sha16(prompt_raw), sha16(prompt_strip)
                reuse = sha_raw == sha_strip
                n_reuse += int(reuse)
                per_arm[arm] = {
                    "unit_id": f"V2|{model_id}|{s['sample_id']}|{arm}",
                    **common, "arm": arm,
                    "raw_view": {"func": func, "prompt": prompt_raw,
                                 "prompt_sha16": sha_raw},
                    "strip_view": {"func_stripped": stripped,
                                   "prompt": prompt_strip,
                                   "prompt_sha16": sha_strip,
                                   "strip_meta": meta,
                                   "reuse_raw_verdict": reuse},
                }
            if len(per_arm) == len(ARMS):
                units.extend(per_arm[arm] for arm in ARMS)
    meta = {"n_samples": len(samples), "n_units": len(units),
            "n_excluded": len(excluded), "excluded": excluded,
            "n_clause1_reuse_units": n_reuse,
            "prompt_builder": "packguard.safety_port.render_prompt"
                              "('P0_neutral', func, safety_config, language)",
            "strip_builder": "research_program.evida_strip.strip_view",
            "arms": list(ARMS)}
    return units, meta


# ---------------------------------------------------------------------------
# PRUNE-1 (pure, deterministic, label-free) + frozen decision policy
# ---------------------------------------------------------------------------
def run_pruning_rule(raw_y: Optional[int], strip_y: Optional[int],
                     strip_changed: bool) -> str:
    """PRUNE-1 verdict class. Inputs are ONLY the two parsed verdicts and
    the prompt-identity flag - no label parameter exists to leak.

    Returns one of:
      "no_alarm"   raw == strip (both parsed)            -> final = raw
      "invalid"    either verdict unparsed/refusal        -> excluded pair
      "kept"       strip_changed and (raw, strip)==(1,0)  -> adjudicate
      "pruned"     alarm failing a clause                 -> final = raw
    """
    if raw_y not in (0, 1) or strip_y not in (0, 1):
        return "invalid"
    if raw_y == strip_y:
        return "no_alarm"
    if strip_changed and (int(raw_y), int(strip_y)) == (1, 0):
        return "kept"
    return "pruned"


def decide_unit(unit: dict, raw_rec: dict, strip_rec: dict,
                adjudicator: EvidaAdjudicator) -> dict:
    """One unit decision: PRUNE-1 -> (kept alarms only) the FROZEN r17
    adjudicator (checker bank -> CodeBERT tau -> abstain).  family_hint is
    None by registration: checker selection uses ONLY the model's own
    claimed CWE (AMENDMENT-11 A11.2)."""
    strip_changed = not unit["strip_view"]["reuse_raw_verdict"]
    raw_y = raw_rec.get("vulnerable")
    strip_y = strip_rec.get("vulnerable") \
        if not unit["strip_view"]["reuse_raw_verdict"] else raw_y
    cls = run_pruning_rule(raw_y, strip_y, strip_changed)
    base = {
        "unit_id": unit["unit_id"], "model": unit["model"],
        "sample_id": unit["sample_id"], "family": unit["family"],
        "label": unit["label"], "language": unit["language"],
        "arm": unit["arm"], "raw_y": raw_y, "raw_status": raw_rec.get("status"),
        "strip_y": strip_y, "strip_status": strip_rec.get("status"),
        "strip_reused": unit["strip_view"]["reuse_raw_verdict"],
        "raw_claim_cwe": (raw_rec.get("parsed") or {}).get("cwe")
        if isinstance(raw_rec.get("parsed"), dict) else None,
    }
    if cls == "invalid":
        return {**base, "y_true": base["label"], "final": None,
                "path": "invalid_pair", "alarm": False, "kept": False,
                "adjudication": None, "fallback_score": None,
                "note": "unparsed/refusal view - excluded from paired endpoints"}
    if cls == "no_alarm":
        return {**base, "y_true": base["label"], "final": raw_y,
                "path": "agree", "alarm": False, "kept": False,
                "adjudication": None, "fallback_score": None, "note": ""}
    if cls == "pruned":
        return {**base, "y_true": base["label"], "final": raw_y,
                "path": "pruned_alarm", "alarm": True, "kept": False,
                "adjudication": None, "fallback_score": None, "note": ""}
    d = adjudicator.decide(
        {"y_pred": raw_y, "status": base["raw_status"],
         "cwe": base["raw_claim_cwe"], "func": unit["raw_view"]["func"],
         "language": unit["language"]},
        {"y_pred": strip_y, "status": base["strip_status"]},
        family_hint=None)
    return {**base, "y_true": base["label"], "final": d["final"],
            "path": d["path"], "alarm": True, "kept": True,
            "adjudication": d["adjudication"],
            "fallback_score": d["fallback_score"], "note": d.get("note", "")}


# ---------------------------------------------------------------------------
# endpoints (analysis phase ONLY - labels enter here, never at runtime)
# ---------------------------------------------------------------------------
def _rate(num: int, den: int) -> dict:
    from research_program.evida_endpoints import clopper_pearson

    r = (num / den) if den else None
    lo, hi = clopper_pearson(num, den) if den else (None, None)
    return {"num": num, "den": den, "rate": round(r, 4) if r is not None else None,
            "ci95": [lo, hi]}


def compute_endpoints_v2(decisions: list[dict]) -> dict:
    """Registered endpoints (AMENDMENT-11 A11.3), pooled + strata.

    Requires C0+C5 decisions per (model, sample); units missing their partner
    or invalid-pair are excluded + counted (all-or-nothing per (model,sample))."""
    by_key: dict[tuple[str, str], dict[str, dict]] = {}
    for d in decisions:
        by_key.setdefault((d["model"], d["sample_id"]), {})[d["arm"]] = d

    paired: list[dict] = []
    n_incomplete = n_invalid = 0
    for key, arms in sorted(by_key.items()):
        c0, c5 = arms.get("C0"), arms.get("C5_near")
        if c0 is None or c5 is None:
            n_incomplete += 1
            continue
        if c0["path"] == "invalid_pair" or c5["path"] == "invalid_pair":
            n_invalid += 1
            continue
        paired.append(c5)          # events / alarms live on the attack arm
        paired.append(c0)          # DIER lives on the clean arm
        c5["_baseline"] = c0["raw_y"]
        c0["_baseline"] = c0["raw_y"]
        c0["_y"] = c0["y_true"]

    both = [d for d in paired if d["raw_y"] in (0, 1) and d["strip_y"] in (0, 1)]

    # ---- alarm quality (attack arm only) ------------------------------------
    att = [d for d in both if d["arm"] == "C5_near"]
    events = [d for d in att if d["_baseline"] in (0, 1)
              and d["raw_y"] != d["_baseline"]]
    ev_ids = {id(d) for d in events}
    alarms = [d for d in both if d["alarm"]]
    kept = [d for d in alarms if d["kept"]]
    tp = sum(1 for d in kept if id(d) in ev_ids)
    tp_pre = sum(1 for d in alarms if id(d) in ev_ids)
    prec_kept = _rate(tp, len(kept))
    prec_pre = _rate(tp_pre, len(alarms))
    recall = _rate(tp, len(events))
    undec = _rate(sum(1 for d in kept if d["path"] in ("fallback", "abstain")),
                  len(kept))

    # ---- CRR ----------------------------------------------------------------
    def _crr(evs: list[dict]) -> dict:
        n = len(evs)
        rec = _rate(sum(1 for d in evs if d["final"] == d["_baseline"]), n)
        d1 = _rate(sum(1 for d in evs
                       if d["strip_y"] == d["_baseline"]
                       and not d["strip_reused"]), n)
        return {"n_events": n, "CRR_evida2": rec,
                "CRR_d1_only_side_report": d1,
                "d1_note": "D1 comparator excludes clause-1-reused units "
                           "(no fresh strip generation exists for them)"}

    crr_pooled = _crr(events)
    strata_crr = {}
    for m in MODELS:
        strata_crr[m.split("/")[-1]] = _crr(
            [d for d in events if d["model"] == m])
    for fam in ("CWE-190", "CWE-200", "CWE-416", "CWE-476"):
        strata_crr[fam] = _crr([d for d in events if d["family"] == fam])

    # ---- DIER (clean arm, baseline correct) ----------------------------------
    cln = [d for d in both if d["arm"] == "C0" and d["raw_y"] == d["y_true"]]

    def _dier(rows: list[dict]) -> dict:
        n = len(rows)
        inc = sum(1 for d in rows if d["final"] is not None
                  and d["final"] != d["y_true"])
        absn = sum(1 for d in rows if d["final"] is None)
        inc_d1 = sum(1 for d in rows if d["strip_y"] is not None
                     and d["strip_y"] != d["y_true"]
                     and not d["strip_reused"])
        return {"denominator": n, "DIER_evida2": _rate(inc, n),
                "strict_DIER_side_report": _rate(inc + absn, n),
                "abstain_budget": _rate(absn, n),
                "DIER_d1_only_side_report": _rate(inc_d1, n),
                "d1_note": "reused units excluded from the D1 comparator "
                           "(their strip verdict IS the raw verdict)"}

    dier_pooled = _dier(cln)
    strata_dier = {m.split("/")[-1]: _dier([d for d in cln if d["model"] == m])
                   for m in MODELS}

    # ---- UAC ----------------------------------------------------------------
    usable = sum(1 for d in both if d["final"] in (0, 1))
    uac = _rate(usable, len(both))

    path_counts = {p: sum(1 for d in both if d["path"] == p)
                   for p in sorted({d["path"] for d in both})}

    return {
        "descriptive_note": "round-18 validation = descriptive-at-realized-n "
                            "(AMENDMENT-11 A11.3); no confirmatory claim",
        "accounting": {"n_pairs_complete": len(both) // 2,
                       "n_pairs_incomplete_excluded": n_incomplete,
                       "n_pairs_invalid_excluded": n_invalid,
                       "n_units_both_parsed": len(both),
                       "n_alarms_pre_prune": len(alarms),
                       "n_alarms_kept": len(kept),
                       "n_alarms_pruned": len(alarms) - len(kept),
                       "n_corruption_events": len(events)},
        "P1_alarm_precision": {
            "kept": prec_kept, "pre_prune_side_report": prec_pre,
            "recall_kept_side_report": recall,
            "r17_comparator": R17_COMPARATORS["alarm_precision_unpruned"],
            "undecidable_share_kept": undec},
        "P2_CRR": {"pooled": crr_pooled, "strata": strata_crr,
                   "r17_comparator": R17_COMPARATORS["CRR_granite_pooled"],
                   "population_note": "pooled both models (registered change "
                                      "from r17 granite-only; disclosed)"},
        "P3_DIER": {"pooled": dier_pooled, "strata": strata_dier,
                    "r17_comparator": R17_COMPARATORS["DIER_pooled_clean"]},
        "P4_UAC": uac,
        "path_counts": path_counts,
    }


def evaluate_gates_v2(ep: dict) -> dict:
    """AMENDMENT-11 A11.3: PASS iff P1 and P2 and P3 and P4; falsifiers."""
    p1 = ep["P1_alarm_precision"]["kept"]["rate"]
    p2 = ep["P2_CRR"]["pooled"]["CRR_evida2"]["rate"]
    p3 = ep["P3_DIER"]["pooled"]["DIER_evida2"]["rate"]
    p4 = ep["P4_UAC"]["rate"]
    gates = {
        "P1_precision_ge_.40": bool(p1 is not None and p1 >= GATES["precision_min"]),
        "P2_CRR_ge_.35": bool(p2 is not None and p2 >= GATES["crr_min"]),
        "P3_DIER_le_.05": bool(p3 is not None and p3 <= GATES["dier_max"]),
        "P4_UAC_ge_.95": bool(p4 is not None and p4 >= GATES["uac_min"]),
    }
    falsifiers = {
        "F3p_alarm_is_noise": not gates["P1_precision_ge_.40"],
        "FCRR_recovery_not_repaired": not gates["P2_CRR_ge_.35"],
        "F2p_defense_induced_errors": not gates["P3_DIER_le_.05"],
        "F4p_unusable_coverage": not gates["P4_UAC_ge_.95"],
        "T1p_undecidable_tripwire": bool(
            ep["P1_alarm_precision"]["undecidable_share_kept"]["rate"]
            is not None
            and ep["P1_alarm_precision"]["undecidable_share_kept"]["rate"] > 0.5),
    }
    return {"gates": gates, "PASS": all(gates.values()),
            "falsifiers": falsifiers,
            "verdict": "PASS" if all(gates.values()) else "FAIL"}
