#!/usr/bin/env python
"""Collect MASTER results for the RefuseGuard paper (Round 4, agent A1).

Every number written to outputs/master/master_results.json is READ from a real
output file under outputs/ (no hand-typed values). After writing, the script
RE-READS master_results.json from disk, re-loads every source file fresh, and
ASSERTS that each stored value still matches its declared source location
(M4 cross-validation). Contradictions between two sources (e.g. original
results.json vs recomputed/) are resolved in favour of the recomputed file and
documented in the "contradictions" section.

Usage:
    .venv/bin/python scripts/collect_master.py            # build + verify
    .venv/bin/python scripts/collect_master.py --verify-only

Outputs:
    outputs/master/master_results.json
    outputs/master/master_results.md
    outputs/master/figures_data/{e0_rr_by_arm_model,e3_siud_by_condition,
        e6_injection,e8_compliance,codebert_metrics}.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]

# --------------------------------------------------------------------------
# source-file access (cached for build; NEVER cached for verify)
# --------------------------------------------------------------------------
_CACHE: dict[str, dict] = {}


def load_src(rel: str, fresh: bool = False) -> dict:
    if fresh:
        return json.loads((PROJECT / rel).read_text(encoding="utf-8"))
    if rel not in _CACHE:
        _CACHE[rel] = json.loads((PROJECT / rel).read_text(encoding="utf-8"))
    return _CACHE[rel]


def jget(obj, dotted: str):
    """Navigate nested json by 'a.b.0.c' dotted path (ints = list index).

    A segment wrapped in [..] is taken literally (for keys that contain '.',
    e.g. file paths used as dict keys in e7 safety_scope_check).
    """
    cur = obj
    for part in _split_path(dotted):
        if isinstance(cur, list):
            cur = cur[int(part)]
        else:
            cur = cur[part]
    return cur


def _split_path(dotted: str) -> list[str]:
    parts, buf, in_br, just_closed = [], "", False, False
    for ch in dotted:
        if ch == "[":
            in_br = True
        elif ch == "]":
            parts.append(buf)
            buf, in_br, just_closed = "", False, True
        elif ch == "." and not in_br:
            if just_closed:
                just_closed = False
                continue
            parts.append(buf)
            buf = ""
        else:
            buf += ch
            just_closed = False
    if buf:
        parts.append(buf)
    return [p for p in parts if p != ""]


ROWS: list[dict] = []
PEND: list[str] = []


def add(exp: str, metric: str, src: str, path: str, *, model: str | None = None,
        n: int | None = None, n_path: str | None = None, ci_path: str | None = None,
        note: str | None = None, recomputed: bool = False) -> None:
    """Register one master row sourced from src at dotted path."""
    try:
        doc = load_src(src)
        value = jget(doc, path)
    except (FileNotFoundError, KeyError, IndexError, TypeError):
        PEND.append(f"{metric}  <- {src}#{path}")
        return
    ci = None
    if ci_path:
        node = jget(doc, ci_path)
        ci = {"low": node["ci_low"], "high": node["ci_high"]}
    row = {
        "experiment": exp,
        "metric": metric,
        "value": value,
        "ci": ci,
        "n": n if n is not None else (jget(doc, n_path) if n_path else None),
        "model": model,
        "source_file": src,
        "recomputed": recomputed,
        "note": note,
        "trace": path,
    }
    if ci is None:
        row.pop("ci")
    else:
        row["trace_ci"] = ci_path
    got = {r["metric"] for r in ROWS}
    assert metric not in got, f"duplicate metric key: {metric}"
    ROWS.append(row)


def add_derived(exp: str, metric: str, fn, *, model: str | None = None,
                n: int | None = None, note: str | None = None,
                recomputed: bool = False) -> None:
    """Row whose value is computed from records by a registered function."""
    try:
        value, n_eff, extra = fn()
    except Exception as exc:  # missing/partial source -> pending
        PEND.append(f"{metric}  (derived: {exc})")
        return
    n = n_eff if n is None else n
    row = {
        "experiment": exp,
        "metric": metric,
        "value": value,
        "n": n,
        "model": model,
        "source_file": extra.get("source_file", ""),
        "recomputed": recomputed,
        "note": note,
        "derive": fn.__name__,
    }
    if extra.get("ci"):
        row["ci"] = extra["ci"]
    got = {r["metric"] for r in ROWS}
    assert metric not in got, f"duplicate metric key: {metric}"
    ROWS.append(row)


# --------------------------------------------------------------------------
# derived stats (recomputed from records; no new LLM calls)
# --------------------------------------------------------------------------
def _e6_records():
    return load_src("outputs/experiments/round3_e6/results.json")["records"]


def _mcnemar_exact(b01: int, b10: int) -> float:
    from math import comb

    nn = b01 + b10
    if nn == 0:
        return 1.0
    p = sum(comb(nn, k) for k in range(0, min(b01, b10) + 1)) / (2 ** (nn - 1))
    return min(1.0, p)


def _e6_flip_pairs():
    """Yield (y_true, b0_flip, p1_flip) for C3 pairs vs the B0|C0 reference."""
    recs = _e6_records()
    ref, b0c3, p1c3 = {}, {}, {}
    for r in recs:
        if r["status"] == "SKIPPED" or r.get("y_pred") is None:
            continue
        key = r["sample_id"]
        if r["condition"] == "C0" and r["defense"] == "B0":
            ref[key] = r
        elif r["condition"] == "C3" and r["defense"] == "B0":
            b0c3[key] = r
        elif r["condition"] == "C3" and r["defense"] == "P1":
            p1c3[key] = r
    pairs = []
    for key, rr in ref.items():
        if key in b0c3 and key in p1c3:
            b0_flip = 1 if (rr["y_pred"] == 1 and b0c3[key]["y_pred"] == 0) else 0
            p1_flip = 1 if (rr["y_pred"] == 1 and p1c3[key]["y_pred"] == 0) else 0
            pairs.append((rr.get("y_true"), b0_flip, p1_flip))
    return pairs


def derive_e6_discordant_total():
    pairs = _e6_flip_pairs()
    b01 = sum(1 for _, a, b in pairs if a == 0 and b == 1)
    b10 = sum(1 for _, a, b in pairs if a == 1 and b == 0)
    assert (b01, b10) == (0, 8), f"e6 discordant changed: b01={b01} b10={b10}"
    return {"b01": b01, "b10": b10, "mcnemar_p": _mcnemar_exact(b01, b10)}, len(pairs), {
        "source_file": "outputs/experiments/round3_e6/results.json#records"}


def _e6_stratum(stratum: int):
    pairs = [p for p in _e6_flip_pairs() if p[0] == stratum]
    b01 = sum(1 for _, a, b in pairs if a == 0 and b == 1)
    b10 = sum(1 for _, a, b in pairs if a == 1 and b == 0)
    return b01, b10, _mcnemar_exact(b01, b10), len(pairs)


def derive_e6_discordant_vul_only():
    b01, b10, p, n = _e6_stratum(1)
    assert (b01, b10) == (0, 2), f"vul-only discordant changed: {b01}/{b10}"
    return {"b01": b01, "b10": b10, "mcnemar_p": p}, n, {
        "source_file": "outputs/experiments/round3_e6/results.json#records"}


def derive_e6_discordant_benign_only():
    b01, b10, p, n = _e6_stratum(0)
    assert (b01, b10) == (0, 6), f"benign-only discordant changed: {b01}/{b10}"
    return {"b01": b01, "b10": b10, "mcnemar_p": p}, n, {
        "source_file": "outputs/experiments/round3_e6/results.json#records"}


DERIVED = {fn.__name__: fn for fn in [
    derive_e6_discordant_total,
    derive_e6_discordant_vul_only,
    derive_e6_discordant_benign_only,
]}


# --------------------------------------------------------------------------
# model slug helper
# --------------------------------------------------------------------------
SLUGS = {
    "Qwen/Qwen2.5-Coder-3B-Instruct": "qwen3b",
    "unsloth/Llama-3.2-3B-Instruct": "llama3b",
    "ibm-granite/granite-3.3-2b-instruct": "granite2b",
}
E0_MODELS = ["Qwen/Qwen2.5-Coder-3B-Instruct", "unsloth/Llama-3.2-3B-Instruct",
             "ibm-granite/granite-3.3-2b-instruct"]
E23_MODELS = E0_MODELS
ARMS = ["neutral", "defensive_wording", "security_context"]
CONDS = ["C1_defensive", "C2a", "C2b", "C3"]


# --------------------------------------------------------------------------
# build
# --------------------------------------------------------------------------
def build() -> None:
    # ---------------- E0 ----------------
    for mid in E0_MODELS:
        slug = SLUGS[mid]
        src = f"outputs/experiments/round3_e0/{slug}/results.json"
        for arm in ARMS:
            add("E0", f"e0.{slug}.arm.{arm}.RR", src,
                f"metrics.arms.{arm}.RR", model=mid, n_path=f"metrics.arms.{arm}.n",
                ci_path=None)
            add("E0", f"e0.{slug}.arm.{arm}.partial_rate", src,
                f"metrics.arms.{arm}.partial_rate", model=mid)
            add("E0", f"e0.{slug}.arm.{arm}.uac", src,
                f"metrics.arms.{arm}.uac", model=mid)
            add("E0", f"e0.{slug}.arm.{arm}.parse_rate", src,
                f"metrics.arms.{arm}.parse_rate", model=mid)
            add("E0", f"e0.{slug}.probe.{arm}.over_refusal_rate", src,
                f"metrics.probes_by_arm.{arm}.over_refusal_rate", model=mid,
                n_path=f"metrics.probes_by_arm.{arm}.COMPLY.n",
                ci_path=f"metrics.probes_by_arm.{arm}.over_refusal_rate_ci")
            add("E0", f"e0.{slug}.probe.{arm}.unsafe_compliance_rate", src,
                f"metrics.probes_by_arm.{arm}.unsafe_compliance_rate", model=mid,
                n_path=f"metrics.probes_by_arm.{arm}.REFUSE.n",
                ci_path=f"metrics.probes_by_arm.{arm}.unsafe_compliance_rate_ci")
        add("E0", f"e0.{slug}.deltaRR_defensive_vs_neutral", src,
            "metrics.delta_RR_defensive_vs_neutral.delta_ci.estimate", model=mid,
            n_path="metrics.delta_RR_defensive_vs_neutral.n_pairs",
            ci_path="metrics.delta_RR_defensive_vs_neutral.delta_ci")
        add("E0", f"e0.{slug}.mcnemar_defensive_vs_neutral.p", src,
            "metrics.delta_RR_defensive_vs_neutral.mcnemar.p_value", model=mid,
            n_path="metrics.delta_RR_defensive_vs_neutral.mcnemar.n")
        add("E0", f"e0.{slug}.deltaRR_security_context_vs_neutral", src,
            "metrics.delta_RR_security_context_vs_neutral.delta_ci.estimate",
            model=mid, n_path="metrics.delta_RR_security_context_vs_neutral.n_pairs",
            ci_path="metrics.delta_RR_security_context_vs_neutral.delta_ci")
        add("E0", f"e0.{slug}.gate.pass_this_model", src,
            "metrics.gate_per_model.pass_this_model", model=mid,
            note="delta_rr/p/ci of this model in gate_per_model; rule = docs/e0_protocol.md §7")
        add("E0", f"e0.{slug}.gate.delta_rr", src,
            "metrics.gate_per_model.delta_rr", model=mid)
        add("E0", f"e0.{slug}.gate.p_value", src,
            "metrics.gate_per_model.p_value", model=mid)
    # official 3-model gate verdict (written by --stage gate)
    add("E0", "e0.gate.verdict", "outputs/experiments/round3_e0/gate_verdict.json",
        "verdict", note="official 3-model reproduction-gate verdict (docs/e0_protocol.md §7)")
    add("E0", "e0.gate.consequence", "outputs/experiments/round3_e0/gate_verdict.json",
        "consequence")
    add("E0", "e0.gate.models_min", "outputs/experiments/round3_e0/gate_verdict.json",
        "models_min")
    add("E0", "e0.gate.models_completed", "outputs/experiments/round3_e0/gate_verdict.json",
        "models_completed")
    add("E0", "e0.gate.models_pass", "outputs/experiments/round3_e0/gate_verdict.json",
        "models_pass")

    # ---------------- E2/E3 (round3_e2e3) ----------------
    for mid in E23_MODELS:
        slug = SLUGS[mid]
        src = f"outputs/experiments/round3_e2e3/{slug}/results.json"
        for cond in ["C0_neutral"] + CONDS:
            add("E2E3", f"e23.{slug}.{cond}.RR", src,
                f"metrics.groups.{cond}.RR", model=mid, n_path=f"metrics.groups.{cond}.n")
            add("E2E3", f"e23.{slug}.{cond}.uac", src,
                f"metrics.groups.{cond}.uac", model=mid)
            add("E2E3", f"e23.{slug}.{cond}.recall", src,
                f"metrics.groups.{cond}.classification.recall", model=mid,
                n_path=f"metrics.groups.{cond}.classification.n_eval")
            add("E2E3", f"e23.{slug}.{cond}.mcc", src,
                f"metrics.groups.{cond}.classification.mcc", model=mid)
        for cond in CONDS:
            add("E2E3", f"e23.{slug}.SIUD_vs_C0.{cond}", src,
                f"metrics.SIUD_vs_C0.{cond}.usable_delta_ci.estimate", model=mid,
                n_path=f"metrics.SIUD_vs_C0.{cond}.n_pairs",
                ci_path=f"metrics.SIUD_vs_C0.{cond}.usable_delta_ci")
            add("E2E3", f"e23.{slug}.mcnemar_vs_C0.{cond}.y_pred_p", src,
                f"metrics.paired_tests_vs_C0.{cond}.mcnemar_y_pred.p_value", model=mid,
                n_path=f"metrics.paired_tests_vs_C0.{cond}.mcnemar_y_pred.n")
            add("E2E3", f"e23.{slug}.mcnemar_vs_C0.{cond}.refusal_p", src,
                f"metrics.paired_tests_vs_C0.{cond}.mcnemar_refusal.p_value", model=mid)

        e4src = f"outputs/experiments/round3_e2e3/{slug}/e4_breakdown.json"
        for side in ["near", "far"]:
            add("E4", f"e4.{slug}.nonconfounded.{side}.n", e4src,
                f"near_vs_far.non_confounded.{side}.n", model=mid,
                note="near-vs-far stratified on near_far_confound == false only")
            add("E4", f"e4.{slug}.nonconfounded.{side}.RR", e4src,
                f"near_vs_far.non_confounded.{side}.RR", model=mid)
            add("E4", f"e4.{slug}.nonconfounded.{side}.uac", e4src,
                f"near_vs_far.non_confounded.{side}.uac", model=mid)
            add("E4", f"e4.{slug}.nonconfounded.{side}.recall", e4src,
                f"near_vs_far.non_confounded.{side}.recall", model=mid)
            add("E4", f"e4.{slug}.nonconfounded.{side}.mcc", e4src,
                f"near_vs_far.non_confounded.{side}.mcc", model=mid)

    # ---------------- E5 ----------------
    e5src = "outputs/experiments/round3_e5/results.json"
    e5m = "Qwen/Qwen2.5-Coder-3B-Instruct"
    for cell in ["C0|B2", "C0|B3", "C2b|B2", "C2b|B3", "C3|B2", "C3|B3", "C3|B1"]:
        key = cell.replace("|", ".")
        add("E5", f"e5.{key}.n", e5src, f"metrics.per_condition_defense.{cell}.metrics.n",
            model=e5m)
        add("E5", f"e5.{key}.uac", e5src, f"metrics.per_condition_defense.{cell}.metrics.uac",
            model=e5m)
        add("E5", f"e5.{key}.recall", e5src,
            f"metrics.per_condition_defense.{cell}.metrics.classification.recall", model=e5m,
            note=("stripping removes the injected C3 carrier (bias; not a real recovery)"
                  if cell.startswith("C3|B") and cell != "C3|B1" else None))
        add("E5", f"e5.{key}.utility_drop_vs_B0", e5src,
            f"metrics.per_condition_defense.{cell}.utility_drop_vs_B0_same_condition",
            model=e5m, note="CUL when cell is C0|B*")
        add("E5", f"e5.{key}.DRR", e5src,
            f"metrics.per_condition_defense.{cell}.DRR_vs_B0_same_condition.DRR",
            model=e5m, n_path=f"metrics.per_condition_defense.{cell}.DRR_vs_B0_same_condition.n_candidates",
            note="DRR null because n_candidates=0 (B0 never refused in this cell)")

    # ---------------- E6 ----------------
    e6src = "outputs/experiments/round3_e6/results.json"
    for cell in ["C0|B0", "C2b|B0", "C3|B0", "C0|P1", "C2b|P1", "C3|P1"]:
        key = cell.replace("|", ".")
        add("E6", f"e6.{key}.n", e6src, f"metrics.per_condition_defense.{cell}.n", model=e5m)
        add("E6", f"e6.{key}.recall", e6src,
            f"metrics.per_condition_defense.{cell}.classification.recall", model=e5m)
        add("E6", f"e6.{key}.mcc", e6src,
            f"metrics.per_condition_defense.{cell}.classification.mcc", model=e5m)
        add("E6", f"e6.{key}.uac", e6src, f"metrics.per_condition_defense.{cell}.uac",
            model=e5m)
    add("E6", "e6.IPI_flip_rate.B0_C3", e6src, "metrics.flip_metrics.IPI_flip_rate_B0.ipi_flip_rate",
        model=e5m,
        note="reference = B0|C0 y_pred paired; flip = vulnerable->benign")
    add("E6", "e6.IPI_flip_rate.P1_C3", e6src, "metrics.flip_metrics.IPI_flip_rate_P1.ipi_flip_rate",
        model=e5m)
    add("E6", "e6.mcnemar_flip_C3_B0_vs_P1.p", e6src,
        "metrics.flip_metrics.mcnemar_flip_C3_B0_vs_P1.p_value", model=e5m,
        n_path="metrics.flip_metrics.mcnemar_flip_C3_B0_vs_P1.n")
    for cond in ["C0", "C2b", "C3"]:
        add("E6", f"e6.usable_delta_P1_minus_B0.{cond}", e6src,
            f"metrics.paired_usable_delta_P1_minus_B0.{cond}.usable_delta_ci_P1_minus_B0.estimate",
            model=e5m, n_path=f"metrics.paired_usable_delta_P1_minus_B0.{cond}.n_pairs",
            ci_path=f"metrics.paired_usable_delta_P1_minus_B0.{cond}.usable_delta_ci_P1_minus_B0",
            note="P1 isolation must not cost usable answers")
    add_derived("E6", "e6.discordant.total_b01_b10_p", derive_e6_discordant_total,
                model=e5m, note="b10=8 pairs where B0 flipped and P1 did not")
    add_derived("E6", "e6.discordant.vul_only_b01_b10_p", derive_e6_discordant_vul_only,
                model=e5m,
                note="vulnerable-only stratum: n.s. — headline p=0.0078 is driven by the benign stratum (benign-keep-bias caveat)")
    add_derived("E6", "e6.discordant.benign_only_b01_b10_p", derive_e6_discordant_benign_only,
                model=e5m)

    # ---------------- E7 ----------------
    e7src = "outputs/experiments/round3_e7/e7_fusion_results.json"
    add("E7", "e7.llm_only.uac", e7src, "ablations.llm_only.overall.uac", n=133,
        note="pilot on Qwen2.5-Coder-0.5B E3 records (n_in_universe=133); no new LLM calls")
    add("E7", "e7.llm_only.mcc", e7src, "ablations.llm_only.overall.mcc")
    add("E7", "e7.llm_only.recall", e7src, "ablations.llm_only.overall.recall")
    add("E7", "e7.llm_then_fallback.uac", e7src, "ablations.llm_then_fallback.overall.uac")
    add("E7", "e7.llm_then_fallback.mcc", e7src, "ablations.llm_then_fallback.overall.mcc")
    add("E7", "e7.llm_then_fallback.recall", e7src, "ablations.llm_then_fallback.overall.recall")
    add("E7", "e7.llm_then_fallback.n_fallback_used", e7src,
        "ablations.llm_then_fallback.overall.n_fallback_used",
        note="per-case fallback correctness is NOT persisted in outputs — do not claim 'k/N correct' in the paper")
    add("E7", "e7.coverage_gain.overall", e7src, "coverage_gain.overall",
        note="UAC(llm_then_fallback) - UAC(llm_only)")
    add("E7", "e7.coverage_gain.C3", e7src, "coverage_gain.per_condition.C3")
    add("E7", "e7.safety_scope.qwen05b_e8.blocked", e7src,
        "safety_scope_check.[outputs/experiments/pilot_round2_recomputed/0.5b/e8/results.json].scope_blocked",
        n=250, note="scope guard: out-of-scope (safety-contrast) prompts can never reach the transformer fallback")
    add("E7", "e7.safety_scope.qwen3b_e8.blocked", e7src,
        "safety_scope_check.[outputs/experiments/pilot_round2_recomputed/3b_qwen/e8/results.json].scope_blocked",
        n=250)
    add("E7", "e7.tau", e7src, "policy.tau",
        note="pre-registered argmax-MCC threshold; outputs/transformer/fallback_threshold.json; tau_valid_mcc=0.3030097")
    add("E7", "e7.tau_valid_mcc", e7src, "policy.tau_valid_mcc")

    # ---------------- E8 (RECOMPUTED source — mandatory for llama) ----------------
    for slug, mid in [("qwen3b", "Qwen/Qwen2.5-Coder-3B-Instruct"),
                      ("llama3b", "unsloth/Llama-3.2-3B-Instruct")]:
        src = f"outputs/experiments/round3_e8{'' if slug == 'qwen3b' else '_llama3b'}/recomputed/recompute_e8_monitor.json"
        for arm in ["B0", "P1", "P2"]:
            add("E8", f"e8.{slug}.{arm}.unsafe_compliance_rate", src,
                f"summary.{arm}.unsafe_compliance_rate", model=mid, recomputed=True,
                n_path=f"summary.{arm}.n_unsafe")
            add("E8", f"e8.{slug}.{arm}.safe_refusal_rate", src,
                f"summary.{arm}.safe_refusal_rate", model=mid, recomputed=True,
                ci_path=f"summary.{arm}.safe_refusal_rate_ci")
        add("E8", f"e8.{slug}.P2.gate_blocked_n", src, "summary.P2.gate_blocked_n",
            model=mid, recomputed=True,
            note="P2 blocks 30/30 unsafe prompts at the intent gate (by construction, 0 LLM calls)")
        add("E8", f"e8.{slug}.B0_vs_P2_unsafe.mcnemar_p", src,
            "paired.B0_vs_P2_unsafe_compliance.mcnemar.p_value", model=mid,
            recomputed=True, n_path="paired.B0_vs_P2_unsafe_compliance.mcnemar.n")
        add("E8", f"e8.{slug}.B0_vs_P1_safe.mcnemar_p", src,
            "paired.B0_vs_P1_safe_refusal.mcnemar.p_value", model=mid,
            recomputed=True, n_path="paired.B0_vs_P1_safe_refusal.mcnemar.n")
        add("E8", f"e8.{slug}.h6.p2_minus_b0", src, "h6.p2_minus_b0", model=mid,
            recomputed=True,
            note="H6 = pipeline-level safety; P2 unsafe 0.000 is by-construction (gate-blocked), not model persuasion")
        add("E8", f"e8.{slug}.h6.met", src, "h6.met", model=mid, recomputed=True)
        add("E8", f"e8.{slug}.n_status_changed", src, "metadata.n_status_changed",
            model=mid, recomputed=True)
    # round-2 pre-fix P2 (before/after table) — scoring-half corpus, disclosed
    r2src = "outputs/experiments/pilot_round2_recomputed/summary_v2.json"
    add("E8", "e8.round2_prefix.qwen.B0.unsafe_compliance_rate", r2src,
        "trees.3b_qwen.experiments.e8.metrics.safety_summary.B0.unsafe_compliance_rate",
        model="Qwen/Qwen2.5-Coder-3B-Instruct",
        note="Round-2 corpus: 50 unsafe + 75 safe (scoring half); P2-cũ ép trả lời (refusal-suppression bug, fixed in round 3)")
    add("E8", "e8.round2_prefix.qwen.P2.unsafe_compliance_rate", r2src,
        "trees.3b_qwen.experiments.e8.metrics.safety_summary.P2.unsafe_compliance_rate",
        model="Qwen/Qwen2.5-Coder-3B-Instruct")

    # ---------------- CodeBERT (B4) ----------------
    cbsrc = "outputs/transformer/codebert_eval_vd_s_metrics.json"
    for mkey, jpath in [
        ("recall@0.5", "metrics.[recall@0.5]"),
        ("f1@0.5", "metrics.[f1@0.5]"),
        ("mcc@0.5", "metrics.[mcc@0.5]"),
        ("auc", "metrics.auc"),
        ("vd_s", "metrics.vd_s"),
        ("accuracy@0.5", "metrics.[accuracy@0.5]"),
    ]:
        add("CodeBERT", f"codebert.{mkey}", cbsrc, jpath,
            note="mirror PrimeVul v0.1 official test split: 549 vul + 20,000 seeded benign subsample (seed 1234)")
    add("CodeBERT", "codebert.n_test", cbsrc, "metrics.n")
    add("CodeBERT", "codebert.n_vulnerable", cbsrc, "metrics.n_vulnerable")
    add("CodeBERT", "codebert.n_benign", cbsrc, "metrics.n_benign")
    add("CodeBERT", "codebert.val_mcc", cbsrc, "meta.checkpoint_metrics.val_mcc",
        note="validation MCC at the saved checkpoint (epoch 1)")
    add("CodeBERT", "codebert.operating_threshold_fpr0.005", cbsrc,
        "meta.[operating_threshold_fpr0.005]")
    for mkey, jpath in [
        ("paired_p_c_both_correct@0.5", "metrics.paired.[p_c_both_correct@0.5]"),
        ("paired_p_v_both_vulnerable@0.5", "metrics.paired.[p_v_both_vulnerable@0.5]"),
        ("paired_p_b_both_benign@0.5", "metrics.paired.[p_b_both_benign@0.5]"),
        ("paired_p_r_inverse@0.5", "metrics.paired.[p_r_inverse@0.5]"),
        ("paired_rank_accuracy", "metrics.paired.paired_rank_accuracy"),
    ]:
        add("CodeBERT", f"codebert.{mkey}", cbsrc, jpath, n_path="metrics.paired.n_pairs",
            note="paired block cross-checked IDENTICAL against codebert_eval_paired_only_metrics.json (persisted scores)")
    add("CodeBERT", "codebert.paired.n_pairs", cbsrc, "metrics.paired.n_pairs")

    # ---------------- Calibration / refusal monitor ----------------
    for slug, mid in [("Qwen_Qwen2.5-Coder-3B-Instruct", "Qwen/Qwen2.5-Coder-3B-Instruct"),
                      ("unsloth_Llama-3.2-3B-Instruct", "unsloth/Llama-3.2-3B-Instruct")]:
        src = f"outputs/transformer/calibration/{slug}/full_report.json"
        add("Calibration", f"calib.{slug}.n_prompts", src, "n_prompts", model=mid,
            note="frozen calibration half (50 orbench-hard + 25 xstest-safe + 25 orbench-toxic + 25 xstest-unsafe), disjoint from scoring")
        add("Calibration", f"calib.{slug}.fit.refusal_threshold", src,
            "fit_thresholds.refusal_threshold", model=mid)
        add("Calibration", f"calib.{slug}.fit.lexical_floor", src,
            "fit_thresholds.lexical_floor", model=mid)
        add("Calibration", f"calib.{slug}.at_fit.over_refusal_rate", src,
            "at_fit_thresholds.over_refusal_rate", model=mid,
            note=("round-10: legacy over_refusal_rate = model strong over-refusal at fitted "
                  "thresholds (free-text protocol); validity uses monitor_false_refusal_rate"))
        add("Calibration", f"calib.{slug}.at_fit.monitor_false_refusal_rate", src,
            "at_fit_thresholds.monitor_false_refusal_rate", model=mid,
            note="validity criterion <=0.10 on silver gold non-refusals (PASSES)")
        add("Calibration", f"calib.{slug}.at_fit.model_strong_refusal_rate", src,
            "at_fit_thresholds.model_strong_refusal_rate", model=mid,
            note="true model over-refusal (strong opener on COMPLY-expected)")
        add("Calibration", f"calib.{slug}.at_default.over_refusal_rate", src,
            "at_default_thresholds.over_refusal_rate", model=mid)
        add("Calibration", f"calib.{slug}.at_default.unsafe_compliance_rate", src,
            "at_default_thresholds.unsafe_compliance_rate", model=mid)
        add("Calibration", f"calib.{slug}.at_fit.calibration_accuracy", src,
            "at_fit_thresholds.calibration_accuracy", model=mid)

    # ---------------- contradictions registry ----------------
    contradictions = build_contradictions()

    return contradictions


CONTRADICTIONS: list[dict] = []


def build_contradictions() -> list[dict]:
    out = []
    # 1) E8-Llama B0 unsafe_compliance: original results.json vs recomputed
    orig = "outputs/experiments/round3_e8_llama3b/results.json"
    recomp = "outputs/experiments/round3_e8_llama3b/recomputed/recompute_e8_monitor.json"
    try:
        v_orig = jget(load_src(orig), "metrics.safety_summary.B0.unsafe_compliance_rate")
        v_rec = jget(load_src(recomp), "summary.B0.unsafe_compliance_rate")
        out.append({
            "metric": "e8.llama3b.B0.unsafe_compliance_rate",
            "file_a": orig, "path_a": "metrics.safety_summary.B0.unsafe_compliance_rate",
            "value_a": v_orig,
            "file_b": recomp, "path_b": "summary.B0.unsafe_compliance_rate",
            "value_b": v_rec,
            "resolution": "USE RECOMPUTED (file_b)",
            "reason": ("V2 BUG-V3-1: monitor missed 3 refusal patterns + Unicode apostrophes; "
                       "11/12 false PARTIALs re-classified REFUSAL from raw outputs "
                       "(round3_e8_llama3b/raw). Original results.json kept untouched for audit."),
        })
    except (FileNotFoundError, KeyError):
        pass
    # 2) E8-Llama McNemar B0vsP2: original 12/0 p=0.00049 vs recomputed 1/0 p=1.0
    try:
        m_orig = jget(load_src(orig), "metrics.paired.B0_vs_P2_unsafe_compliance.mcnemar")
        m_rec = jget(load_src(recomp), "paired.B0_vs_P2_unsafe_compliance.mcnemar")
        out.append({
            "metric": "e8.llama3b.B0_vs_P2_unsafe.mcnemar",
            "file_a": orig, "path_a": "metrics.paired.B0_vs_P2_unsafe_compliance.mcnemar",
            "value_a": {"b01": m_orig.get("b01_a_fail_b_success"),
                        "b10": m_orig.get("b10_a_success_b_fail"),
                        "p": m_orig.get("p_value")},
            "file_b": recomp, "path_b": "paired.B0_vs_P2_unsafe_compliance.mcnemar",
            "value_b": {"b01": m_rec.get("b01_a_fail_b_success"),
                        "b10": m_rec.get("b10_a_success_b_fail"),
                        "p": m_rec.get("p_value")},
            "resolution": "USE RECOMPUTED (file_b)",
            "reason": "same monitor fix as above; claim 'P2 reduces unsafe compliance p=0.00049' RETRACTED (see ROUND3_SUMMARY #1).",
        })
    except (FileNotFoundError, KeyError):
        pass
    return out


# --------------------------------------------------------------------------
# markdown + csv emitters
# --------------------------------------------------------------------------
def fmt(v) -> str:
    if v is None:
        return "—"
    if isinstance(v, bool):
        return str(v)
    if isinstance(v, float):
        if v != 0 and abs(v) < 1e-3:
            return f"{v:.2e}"
        s = f"{v:.4f}".rstrip("0").rstrip(".")
        return s if s else "0"
    return str(v)


def write_md(path: Path) -> None:
    by_exp: dict[str, list[dict]] = {}
    for r in ROWS:
        by_exp.setdefault(r["experiment"], []).append(r)
    lines = ["# Master results (paper-facing) — generated by scripts/collect_master.py", "",
             "Every value below is read programmatically from the cited `source_file`",
             "(no hand-typed numbers) and re-verified by re-reading each file (M4).", ""]
    titles = {
        "E0": "E0 — Reproduction gate (defensive refusal / over-refusal)",
        "E2E3": "E2/E3 — Robustness under untrusted context (framing C1; contextual stress C2a/C2b; IPI-style C3)",
        "E4": "E4 — Carrier/position breakdown (near vs far, non-confounded only)",
        "E5": "E5 — Stripping defenses B1/B2/B3 (CUL / DRR / carrier-stripping bias)",
        "E6": "E6 — Semantic Context Isolation P1 (injection-success / IPI-flip)",
        "E7": "E7 — Refusal-recovery fusion (LLM → CodeBERT fallback)",
        "E8": "E8 — Safety preservation (H6): B0 vs P1/P2 unsafe compliance + safe refusal",
        "CodeBERT": "B4 — CodeBERT fine-tune (PrimeVul mirror v0.1)",
        "Calibration": "Refusal-monitor calibration (thresholds + over-refusal validity)",
    }
    for exp in ["E0", "E2E3", "E4", "E5", "E6", "E7", "E8", "CodeBERT", "Calibration"]:
        rows = by_exp.get(exp, [])
        if not rows:
            continue
        lines += [f"## {titles.get(exp, exp)}", "",
                  "| metric | value | 95% CI | n | model | source_file | recomputed |",
                  "|---|---|---|---|---|---|---|"]
        for r in rows:
            ci = r.get("ci")
            ci_s = f"[{fmt(ci['low'])}, {fmt(ci['high'])}]" if ci else "—"
            lines.append(
                f"| `{r['metric']}` | {fmt(r['value'])} | {ci_s} | {fmt(r.get('n'))} | "
                f"{r.get('model') or '—'} | `{r['source_file']}` | {'yes' if r.get('recomputed') else 'no'} |")
        notes = [r.get("note") for r in rows if r.get("note")]
        if notes:
            lines += ["", "Notes:"]
            lines += [f"- {n}" for n in dict.fromkeys(notes)]
        lines.append("")
    if CONTRADICTIONS:
        lines += ["## Contradictions found and resolved (M4)", "",
                  "| metric | original (file_a) | recomputed (file_b) | resolution |", "|---|---|---|---|"]
        for c in CONTRADICTIONS:
            lines.append(f"| `{c['metric']}` | {fmt(c['value_a'])} (`{c['file_a']}`) | "
                         f"{fmt(c['value_b'])} (`{c['file_b']}`) | {c['resolution']} |")
        lines += ["", "Reasons:"]
        lines += [f"- **{c['metric']}**: {c['reason']}" for c in CONTRADICTIONS]
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def write_csvs(outdir: Path) -> None:
    outdir.mkdir(parents=True, exist_ok=True)

    # 1) e0_rr_by_arm_model.csv
    with (outdir / "e0_rr_by_arm_model.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["model_slug", "arm", "n", "RR", "partial_rate", "uac", "parse_rate",
                    "probe_over_refusal_rate", "probe_over_refusal_ci_low",
                    "probe_over_refusal_ci_high", "probe_unsafe_compliance_rate",
                    "probe_unsafe_ci_low", "probe_unsafe_ci_high", "source_file"])
        for slug in ["qwen3b", "llama3b", "granite2b"]:
            for arm in ARMS:
                g = lambda m: next((r for r in ROWS if r["metric"] == m), None)
                rr = g(f"e0.{slug}.arm.{arm}.RR")
                if rr is None:
                    continue
                src = rr["source_file"]
                pr = g(f"e0.{slug}.arm.{arm}.partial_rate")
                uac = g(f"e0.{slug}.arm.{arm}.uac")
                par = g(f"e0.{slug}.arm.{arm}.parse_rate")
                orr = g(f"e0.{slug}.probe.{arm}.over_refusal_rate")
                ucr = g(f"e0.{slug}.probe.{arm}.unsafe_compliance_rate")
                w.writerow([slug, arm, rr.get("n"), rr["value"],
                            pr["value"] if pr else "", uac["value"] if uac else "",
                            par["value"] if par else "",
                            orr["value"] if orr else "",
                            orr.get("ci", {}).get("low", "") if orr else "",
                            orr.get("ci", {}).get("high", "") if orr else "",
                            ucr["value"] if ucr else "",
                            ucr.get("ci", {}).get("low", "") if ucr else "",
                            ucr.get("ci", {}).get("high", "") if ucr else "",
                            src])

    # 2) e3_siud_by_condition.csv
    with (outdir / "e3_siud_by_condition.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["model_slug", "condition", "n_pairs", "SIUD_usable_delta",
                    "ci_low", "ci_high", "cond_RR", "cond_uac", "cond_recall", "cond_mcc",
                    "mcnemar_vs_C0_y_pred_p", "source_file"])
        for slug in ["qwen3b", "llama3b", "granite2b"]:
            for cond in CONDS:
                s = next((r for r in ROWS if r["metric"] == f"e23.{slug}.SIUD_vs_C0.{cond}"), None)
                if s is None:
                    continue
                src = s["source_file"]
                g = lambda m: next((r for r in ROWS if r["metric"] == m), None)
                rr = g(f"e23.{slug}.{cond}.RR")
                uac = g(f"e23.{slug}.{cond}.uac")
                rec = g(f"e23.{slug}.{cond}.recall")
                mcc = g(f"e23.{slug}.{cond}.mcc")
                mp = g(f"e23.{slug}.mcnemar_vs_C0.{cond}.y_pred_p")
                ci = s.get("ci") or {}
                w.writerow([slug, cond, s.get("n"), s["value"], ci.get("low", ""),
                            ci.get("high", ""), rr["value"] if rr else "",
                            uac["value"] if uac else "", rec["value"] if rec else "",
                            mcc["value"] if mcc else "", mp["value"] if mp else "", src])

    # 3) e6_injection.csv
    with (outdir / "e6_injection.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["comparison", "ipi_flip_rate", "n_pairs", "b01", "b10", "mcnemar_p",
                    "stratum", "source_file"])
        fb0 = next(r for r in ROWS if r["metric"] == "e6.IPI_flip_rate.B0_C3")
        fp1 = next(r for r in ROWS if r["metric"] == "e6.IPI_flip_rate.P1_C3")
        mtot = next(r for r in ROWS if r["metric"] == "e6.discordant.total_b01_b10_p")
        mvul = next((r for r in ROWS if r["metric"] == "e6.discordant.vul_only_b01_b10_p"), None)
        mben = next((r for r in ROWS if r["metric"] == "e6.discordant.benign_only_b01_b10_p"), None)
        w.writerow(["B0|C3_vs_ref", fb0["value"], "", "", "", "", "all", fb0["source_file"]])
        w.writerow(["P1|C3_vs_ref", fp1["value"], mtot.get("n"), mtot["value"]["b01"],
                    mtot["value"]["b10"], mtot["value"]["mcnemar_p"], "all",
                    fp1["source_file"]])
        if mvul:
            w.writerow(["P1_vs_B0_discordant", "", mvul.get("n"), mvul["value"]["b01"],
                        mvul["value"]["b10"], mvul["value"]["mcnemar_p"], "vul_only",
                        mvul["source_file"]])
        if mben:
            w.writerow(["P1_vs_B0_discordant", "", mben.get("n"), mben["value"]["b01"],
                        mben["value"]["b10"], mben["value"]["mcnemar_p"], "benign_only",
                        mben["source_file"]])

    # 4) e8_compliance.csv
    with (outdir / "e8_compliance.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["model_slug", "arm", "n_unsafe", "unsafe_compliance_rate",
                    "n_safe", "safe_refusal_rate", "safe_ci_low", "safe_ci_high",
                    "gate_blocked_n", "mcnemar_p_vs_B0", "source_file", "recomputed"])
        for slug in ["qwen3b", "llama3b"]:
            for arm in ["B0", "P1", "P2"]:
                u = next((r for r in ROWS if r["metric"] == f"e8.{slug}.{arm}.unsafe_compliance_rate"), None)
                s = next((r for r in ROWS if r["metric"] == f"e8.{slug}.{arm}.safe_refusal_rate"), None)
                if u is None or s is None:
                    continue
                gb = next((r for r in ROWS if r["metric"] == f"e8.{slug}.P2.gate_blocked_n"), None)
                mp = next((r for r in ROWS if r["metric"] == (
                    f"e8.{slug}.B0_vs_P2_unsafe.mcnemar_p" if arm == "P2"
                    else f"e8.{slug}.B0_vs_P1_safe.mcnemar_p")), None) if arm in ("P1", "P2") else None
                ci = s.get("ci") or {}
                w.writerow([slug, arm, u.get("n", ""), u["value"],
                            s.get("n", ""), s["value"], ci.get("low", ""), ci.get("high", ""),
                            gb["value"] if (gb and arm == "P2") else "",
                            mp["value"] if mp else "", s["source_file"], s.get("recomputed", False)])

    # 5) codebert_metrics.csv
    with (outdir / "codebert_metrics.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["metric", "value", "n", "source_file"])
        for r in ROWS:
            if r["experiment"] == "CodeBERT":
                w.writerow([r["metric"], r["value"], r.get("n", ""), r["source_file"]])


# --------------------------------------------------------------------------
# verification (M4): re-read master + sources fresh, assert every value
# --------------------------------------------------------------------------
def verify() -> int:
    master = json.loads((PROJECT / "outputs/master/master_results.json").read_text())
    rows = master["results"]
    errors = []
    for r in rows:
        try:
            if "derive" in r:
                val, _, _ = DERIVED[r["derive"]]()
                got = val
            else:
                assert r.get("source_file"), r["metric"]
                doc = load_src(r["source_file"], fresh=True)
                got = jget(doc, r["trace"])
            want = r["value"]
            ok = got == want
            if not ok:
                errors.append(f"MISMATCH {r['metric']}: master={want!r} source={got!r}")
        except (FileNotFoundError, KeyError, IndexError, AssertionError) as e:
            errors.append(f"ERROR {r['metric']}: {e}")
    # CI verification: re-read the stored trace_ci node fresh
    for r in rows:
        if not r.get("ci") or "derive" in r:
            continue
        try:
            doc = load_src(r["source_file"], fresh=True)
            node = jget(doc, r["trace_ci"])
            for side in ("low", "high"):
                if r["ci"][side] != node[f"ci_{side}"]:
                    errors.append(f"CI MISMATCH {r['metric']}.{side}")
        except (FileNotFoundError, KeyError, IndexError):
            errors.append(f"CI ERROR {r['metric']}")
    # contradiction cross-checks
    try:
        v_orig = jget(load_src("outputs/experiments/round3_e8_llama3b/results.json", fresh=True),
                      "metrics.safety_summary.B0.unsafe_compliance_rate")
        v_rec = next(r["value"] for r in rows
                     if r["metric"] == "e8.llama3b.B0.unsafe_compliance_rate")
        assert v_orig != v_rec and abs(v_rec - 0.03333333333333333) < 1e-12, \
            "recomputed llama B0 must be 1/30"
    except (FileNotFoundError, KeyError, AssertionError) as e:
        errors.append(f"CONTRADICTION CHECK ERROR: {e}")
    # codebert paired agreement between the two persisted sources
    try:
        a = jget(load_src("outputs/transformer/codebert_eval_vd_s_metrics.json", fresh=True),
                 "metrics.paired")
        b = jget(load_src("outputs/transformer/codebert_eval_paired_only_metrics.json", fresh=True),
                 "metrics.paired")
        for k in ("p_c_both_correct@0.5", "p_v_both_vulnerable@0.5", "p_b_both_benign@0.5",
                  "p_r_inverse@0.5", "paired_rank_accuracy", "n_pairs"):
            assert a[k] == b[k], f"paired block drift at {k}"
    except (FileNotFoundError, KeyError, AssertionError) as e:
        errors.append(f"CODEBERT PAIRED CHECK ERROR: {e}")
    # models.yaml corroboration of calibration over-refusal (second source)
    try:
        my = (PROJECT / "configs/models.yaml").read_text()
        assert "monitor_false_refusal_rate: 0.0" in my, "models.yaml monitor false-refusal 0.0"
        assert "lexical_floor: 0.7" in my, "models.yaml Qwen lexical_floor 0.7 (round-10 fit)"
        assert "lexical_floor: 0.3" in my, "models.yaml Llama lexical_floor 0.3 (round-10 fit)"
    except AssertionError as e:
        errors.append(f"MODEL-YAML CORROBORATION ERROR: {e}")
    return errors


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify-only", action="store_true")
    args = ap.parse_args()
    if not args.verify_only:
        global CONTRADICTIONS
        CONTRADICTIONS = build()
        master = {
            "generated_by": "scripts/collect_master.py (Round 4 A1)",
            "schema": {"row": ["experiment", "metric", "value", "ci?", "n?", "model?",
                                "source_file", "recomputed?", "note?", "trace"]},
            "results": ROWS,
            "contradictions": CONTRADICTIONS,
            "disclosures": [
                "Pilot scale: E0 20 functions x 3 arms + 25 probes x 3 arm-systems per model; "
                "E2/E3 60 functions x 5 conditions per model; E5/E6 40 cells (C0) / 31 (C2b, C3 usable of 40); "
                "E8 30 unsafe + 30 safe per arm per model; E7 pilot on Qwen2.5-Coder-0.5B records (n=133).",
                "PrimeVul mirror v0.1 (community HF mirror, not the gated official release); "
                "CodeBERT test corpus = official test split ALL 549 vulnerable + seeded benign subsample n=20,000 (seed 1234); "
                "training used vul all + benign subsample 25,000.",
                "Refusal-monitor validity (docs/e0_protocol.md §7, round-10 re-fit): "
                "monitor false-refusal on silver gold non-refusals = 0.0 for both models "
                "(criterion <=0.10 PASSES); Qwen model strong over-refusal = 0.52 "
                "(true model behaviour, not detector error); "
                "E0 delta_RR = 0 is robust because error is symmetric across the two arms.",
                "E8-Llama numbers use the RECOMPUTED monitor output "
                "(outputs/experiments/round3_e8_llama3b/recomputed/), not the original results.json "
                "(kept for audit) — see contradictions.",
                "E6 headline p=0.0078 for injection-success reduction is driven by benign-stratum "
                "discordant pairs; vulnerable-only stratum is n.s. (p=0.5) — benign-keep-bias caveat is mandatory.",
                "H6 (P2 does not increase unsafe compliance) is met by construction: the intent gate blocks "
                "30/30 unsafe prompts before any LLM call, so evidence is pipeline-level only.",
                "E0 PASS-branch is statistically unattainable at n=20 paired functions (needs delta_RR >= ~0.30 "
                "for McNemar p<0.05); verdict is FAIL with effect size exactly 0, config was pre-registered.",
                "E0 granite monitor thresholds are fitted IN-SAMPLE on its own scoring probes "
                "(disclosed deviation, configs/e0_round3.yaml); no granite calibration-half run.",
                "P2 gate on safety-contrast prompts: 30/30 blocked on the round-3 unsafe slice; "
                "on the 50-prompt paraphrase scoring half the lexical gate blocked only 1/50 "
                "(49/50 escaped), per intent_gate_v2_measurement.json (e8_scoring_half_unsafe). "
                "Wording corrected in Round 4 (S): previously said '1/50 escape', which inverted "
                "the blocked/escaped counts.",
            ],
        }
        outdir = PROJECT / "outputs/master"
        outdir.mkdir(parents=True, exist_ok=True)
        (outdir / "master_results.json").write_text(
            json.dumps(master, indent=1, ensure_ascii=False), encoding="utf-8")
        write_md(outdir / "master_results.md")
        write_csvs(outdir / "figures_data")
        print(f"[collect] rows={len(ROWS)} pending={len(PEND)} "
              f"contradictions={len(CONTRADICTIONS)}")
        for p in PEND:
            print("  PENDING:", p)
    errors = verify()
    n = len(json.loads((PROJECT / "outputs/master/master_results.json").read_text())["results"])
    if errors:
        print(f"[verify] FAILED ({len(errors)} errors):")
        for e in errors:
            print("  ", e)
        sys.exit(1)
    print(f"[verify] OK — all {n} master rows match their source files (fresh re-read).")


if __name__ == "__main__":
    main()
