#!/usr/bin/env python
"""Collect ROUND-7 MASTER results for the RefuseGuard paper (agent A3/S, Round 7).

Two pre-registered experiments (docs/round7_prereg.md, frozen BEFORE any
round-7 generation):
  RQ8  CWE generalization of the verdict-bias channel (benign->vulnerable
       under C5) on 4 NEW CWE families x 20 benign (Granite-3.3-2B primary,
       Llama-3.2-3B secondary; hypotheses H-G1 family-level, H-G2 pooled).
  RQ9  7-8B replication of the reassertion harm (minimal ladder A0/A1/A5 on
       the byte-identical Round-6 C5_near subset; hypotheses H-R1/H-R2/H-R3).

Every written number is COMPUTED from a real source file under outputs/ (no
hand-typed values). After writing, the script RE-READS the JSON from disk,
rebuilds every row from freshly re-loaded sources, and asserts row-by-row
equality (same M4-style cross-validation as collect_master_round5/6).

FAIL-SAFE contract (mandate): with no round-7 outputs on disk the script
prints a [pending] list, writes NOTHING, and exits 0. outputs/master/
round7_master.json is only created when at least one source part exists.

Row schema (contract: docs/round7_prereg.md §4):
  {experiment: "RQ8"|"RQ9", metric, value, ci?, n, model, family?, arm?,
   source_file, note?}

Stats disclosure: two-sided EXACT binomial McNemar recomputed here from
records (discriminating pairs only), identical to collect_master_round6.py;
the runner's chi2-continuity variant (discordant >= 25) is stored alongside
when present in the runner metrics.

Usage:
    .venv/bin/python scripts/collect_master_round7.py            # build + verify
    .venv/bin/python scripts/collect_master_round7.py --verify-only
"""
from __future__ import annotations

import argparse
import json
import sys
from math import comb
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------------------
# expected sources (defaults; the executed layout is recorded via Amendment-2
# in docs/round7_prereg.md -- edit these two maps then, not the logic)
# ---------------------------------------------------------------------------
# [Amendment-2, POST-HOC PATH-ONLY (recorded after RQ8 generation; no rule
# changed)]: the RQ8 runner executed into outputs/experiments/round7_rq8/
# (per-model 320-record files results_<model>.json + manifest_cwe.json),
# not the provisional outputs/experiments/round7_cwe/ path registered in
# prereg §4. See docs/round7_prereg.md Amendment-2 for the full disclosure.
RQ8_DIR = "outputs/experiments/round7_rq8"
# RQ9 executed layout (Amendment-1; configs/round7_7b.yaml, slug qwen7b):
# one file per ladder variant + one benign B0 file (the C0-arm source for H-R3).
RQ9_DIR = "outputs/experiments/round7_7b"
RQ8_MANIFEST = f"{RQ8_DIR}/manifest_cwe.json"
RQ8_RESULTS = {
    "granite2b": f"{RQ8_DIR}/results_granite2b.json",   # primary model (prereg §1.2)
    "llama3b": f"{RQ8_DIR}/results_llama3b.json",       # secondary replication
}
# Both executed files hold ONE model's full RQ8 run (320 records = 160 benign
# + 160 vul across {C0, C5_near}) — the collector consumes them as-is; the
# per-family/pooled blocks gate on MIN_FAMILY_N paired benign, not on file
# counts.
RQ9_RUNGS = ("A0", "A1", "A5")
RQ9_RUNG_COMPONENT = {
    "A0": "none (B0 raw)",
    "A1": "boundary label only (minimal provenance)",
    "A5": "system task-intent reassertion (= full P3)",
}
RQ9_MODELS = {
    "qwen7b": {
        "vul": {r: f"{RQ9_DIR}/results_qwen7b__vul__{r}.json"
                for r in RQ9_RUNGS},
        "benign": f"{RQ9_DIR}/results_qwen7b__benign__B0.json",
    },
    # llama8b was registered primary in the original prereg but is NOT
    # executed (Amendment-1 §0b(i)); add its file map here only together
    # with a new amendment BEFORE any generation.
}
RQ9_RUNG_COMPONENT_LABEL = RQ9_RUNG_COMPONENT

# ---------------------------------------------------------------------------
# RQ8 families — canonical keys = the executed bench_attack_v2 registry
# (Amendment-1 §0b(ii): configs/attack_v2_cwe.yaml, CWE-476/416/190/200).
# ---------------------------------------------------------------------------
FAMILIES = ("CWE-476", "CWE-416", "CWE-190", "CWE-200")
FALLBACK_FAMILIES = ("CWE-369", "CWE-434", "CWE-78")
CANONICAL_FAMILIES = FAMILIES + FALLBACK_FAMILIES
FAMILY_ALIASES = {
    "CWE-476": "CWE-476", "F-NPD": "CWE-476", "null_deref": "CWE-476",
    "pointer_surface": "CWE-476",
    "CWE-416": "CWE-416", "F-UAF": "CWE-416", "use_after_free": "CWE-416",
    "uaf": "CWE-416", "heap_lifecycle": "CWE-416",
    "CWE-190": "CWE-190", "F-INT": "CWE-190", "integer_overflow": "CWE-190",
    "int": "CWE-190", "arith_scaling": "CWE-190",
    "CWE-200": "CWE-200", "F-INFO": "CWE-200", "info_exposure": "CWE-200",
    "log_output": "CWE-200",
    "CWE-369": "CWE-369", "F-DIV": "CWE-369", "divide_by_zero": "CWE-369",
    "CWE-434": "CWE-434", "F-UPLOAD": "CWE-434",
    "CWE-78": "CWE-78", "F-CMD": "CWE-78",
    # F-PATH / CWE-22 was registered in the original prereg but superseded
    # by Amendment-1 (not in the executed bench): intentionally NOT mapped —
    # a record carrying it fails loudly instead of being silently bucketed.
}
# round-6 sources used ONLY by the optional prompt-identity guard (RQ9)
RQ6_LADDER = {
    "qwen7b": "outputs/experiments/round6_ablation/results_qwen3b__ablation__15.json",
}
MIN_FAMILY_N = 20  # prereg §2.3 item 5: below this a family is not-run/unpowered
FAMILIES_EXPECTED = 4

RQ8_LABELS = ("GENERALIZES", "GENERALIZES-pooled-driven", "FAMILY-DEPENDENT")
# Amendment-1 §0b(iv): branch set follows configs/round7_7b.yaml rule algebra
RQ9_HR1 = ("SUPPORTED", "NOT_SUPPORTED-REVERSAL", "NOT_SUPPORTED-ABSENT-STRONG",
           "NOT_SUPPORTED-ABSENT", "PARTIAL-INCONCLUSIVE")
RQ9_HR2 = ("SAFE", "UNSAFE", "PARTIAL")
RQ9_HR3 = ("CONSISTENT", "SATURATED-UNINFORMATIVE", "DIRECTION-REVERSED",
           "NOT_SUPPORTED", "NOT_RUN")

EPS = 1e-9


class PendingError(RuntimeError):
    """Raised when a part's sources exist but are insufficient to build it."""


# ---------------------------------------------------------------------------
# source access (cached for build; NEVER cached for verify)
# ---------------------------------------------------------------------------
_CACHE: dict[str, object] = {}


def src(rel: str) -> Path:
    return PROJECT / rel


def exists(rel: str) -> bool:
    return src(rel).exists()


def load_json(rel: str, fresh: bool = False):
    p = src(rel)
    if not p.exists():
        raise FileNotFoundError(f"missing source file: {rel}")
    if fresh:
        return json.loads(p.read_text(encoding="utf-8"))
    if rel not in _CACHE:
        _CACHE[rel] = json.loads(p.read_text(encoding="utf-8"))
    return _CACHE[rel]


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact McNemar (binomial) p; b/c = discordant counts.

    Note (prereg §3.2 transparency note): this is the discordant-only variant
    actually implemented across the project's collectors (b+c is the
    Bernoulli population)."""
    n = b + c
    if n == 0:
        return 1.0
    tail = sum(comb(n, k) for k in range(0, min(b, c) + 1))
    return min(1.0, tail * 2 / 2 ** n)


def row(experiment: str, metric: str, value, *, ci=None, n=None, model=None,
        family=None, arm=None, source_file: str, note: str = "") -> dict:
    r: dict = {"experiment": experiment, "metric": metric, "value": value}
    if ci is not None:
        r["ci95"] = ci
    if n is not None:
        r["n"] = n
    if model is not None:
        r["model"] = model
    if family is not None:
        r["family"] = family
    if arm is not None:
        r["arm"] = arm
    r["source_file"] = source_file
    if note:
        r["note"] = note
    return r


def parsed(recs: list[dict]) -> dict[str, int]:
    """sample_id -> y_pred for records with a binary verdict."""
    return {r["sample_id"]: r["y_pred"] for r in recs
            if r.get("y_pred") in (0, 1)}


def paired_stats(prev: dict[str, int], cur: dict[str, int]) -> dict:
    common = sorted(set(prev) & set(cur))
    v2b = sum(1 for s in common if prev[s] == 1 and cur[s] == 0)
    b2v = sum(1 for s in common if prev[s] == 0 and cur[s] == 1)
    n = len(common)
    return {"n_pairs": n, "flip_1to0": v2b, "flip_0to1": b2v,
            "p_exact": mcnemar_exact(v2b, b2v),
            "rate_prev": sum(prev[s] for s in common) / n if n else 0.0,
            "rate_cur": sum(cur[s] for s in common) / n if n else 0.0}


def _rung_of(rec: dict) -> str | None:
    """Ladder rung of a record; None for non-ladder records (e.g. the
    same-model benign C0 arm, which is B0 and belongs to no rung)."""
    v = rec.get("variant", rec.get("rung"))
    if v is None:
        return None
    if v not in RQ9_RUNGS:
        raise PendingError(f"record {rec.get('sample_id')!r} has unknown "
                           f"rung/variant {v!r} (expected {RQ9_RUNGS})")
    return v  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# RQ8: manifest parsing (accepts three declared shapes, strict validation)
# ---------------------------------------------------------------------------
def canonical_family(value: str) -> str:
    key = str(value).strip()
    if key in FAMILY_ALIASES:
        return FAMILY_ALIASES[key]
    raise PendingError(f"unknown CWE family {value!r} (canonical: "
                       f"{CANONICAL_FAMILIES}); extend FAMILY_ALIASES only via "
                       f"Amendment-1 in docs/round7_prereg.md")


def parse_manifest(man: dict) -> dict[str, str]:
    """sample_id -> canonical family, from any of the three declared shapes."""
    out: dict[str, str] = {}
    if isinstance(man.get("samples"), list):
        for s in man["samples"]:
            out[str(s["sample_id"])] = canonical_family(s["family"])
    elif isinstance(man.get("samples"), dict):
        for sid, fam in man["samples"].items():
            out[str(sid)] = canonical_family(fam)
    elif isinstance(man.get("families"), dict):
        for fam, sids in man["families"].items():
            for sid in sids:
                out[str(sid)] = canonical_family(fam)
    else:
        raise PendingError("manifest_cwe.json: none of samples[list]/"
                           "samples[dict]/families[dict] found")
    if not out:
        raise PendingError("manifest_cwe.json: zero samples parsed")
    return out


def _rq8_family_side(recs: list[dict], fam_map: dict[str, str],
                     label: int, condition: str) -> dict[str, dict[str, int]]:
    """family -> {sid: y_pred} for one (label, condition) side.

    Parsed-binary records only (y_pred in {0,1}): an unparsed PARTIAL or a
    REFUSAL drops from the paired n (runner rule, disclosed as
    n_pairs_excluded_unparsed_or_refusal) — refusal is never mapped to
    benign.  Mirrors the `parsed()` convention used by the RQ9 blocks; the
    executed per-model 320-record files contain exactly one such record
    (llama3b, sample 198370, vul/C0)."""
    side: dict[str, dict[str, int]] = {}
    for r in recs:
        if r.get("y_true") != label or r.get("condition") != condition \
                or r.get("y_pred") not in (0, 1):
            continue
        sid = str(r["sample_id"])
        fam = canonical_family(r["family"]) if "family" in r else fam_map[sid]
        side.setdefault(fam, {})[sid] = r["y_pred"]
    return side


def build_rq8_rows() -> tuple[list[dict], dict]:
    """RQ8 rows + summary struct for the token map."""
    man = load_json(RQ8_MANIFEST)
    fam_map = parse_manifest(man)
    rows: list[dict] = []
    summaries: dict[str, dict] = {}
    for model, rel in RQ8_RESULTS.items():
        if not exists(rel):
            continue
        data = load_json(rel)
        recs = data["records"]
        assert recs, f"{rel}: zero records"
        rr = sum(1 for r in recs if r.get("status") == "REFUSAL") / len(recs)
        assert rr == 0.0, f"{rel}: unexpected REFUSAL records (RR={rr}) — " \
                          "refusal is never mapped to benign; report as event"
        unknown = {str(r["sample_id"]) for r in recs
                   if "family" not in r and str(r["sample_id"]) not in fam_map}
        assert not unknown, f"{rel}: sample_ids missing from manifest: {sorted(unknown)[:5]}"
        c0 = _rq8_family_side(recs, fam_map, 0, "C0")
        c5 = _rq8_family_side(recs, fam_map, 0, "C5_near")
        v0 = _rq8_family_side(recs, fam_map, 1, "C0")
        v5 = _rq8_family_side(recs, fam_map, 1, "C5_near")
        ms = summaries.setdefault(model, {"families": {}, "pooled": {}})

        def emit(metric: str, value, *, n=None, family=None, arm=None,
                 note: str = "", ci=None) -> None:
            rows.append(row("RQ8", metric, value, ci=ci, n=n, model=model,
                            family=family, arm=arm, source_file=rel, note=note))

        def block(fam: str, prev: dict[str, int], cur: dict[str, int],
                  arm: str) -> dict:
            st = paired_stats(prev, cur)
            delta = st["rate_cur"] - st["rate_prev"]
            base = f"cwe.{model}.{fam}"
            emit(f"{base}.fp_rate_C0", round(st["rate_prev"], 4), n=st["n_pairs"],
                 family=fam, arm="C0")
            emit(f"{base}.fp_rate_C5_near", round(st["rate_cur"], 4), n=st["n_pairs"],
                 family=fam, arm="C5_near")
            emit(f"{base}.delta_fp", round(delta, 4), n=st["n_pairs"],
                 family=fam, arm="C5_near",
                 note="point estimate from paired records; a bootstrap CI is "
                      "added by S only from a runner bootstrap block, never "
                      "synthesized here")
            emit(f"{base}.flip_b2v", st["flip_0to1"], n=st["n_pairs"],
                 family=fam, arm="C5_near", note="paired benign 0->1 (FP direction)")
            emit(f"{base}.flip_v2b", st["flip_1to0"], n=st["n_pairs"],
                 family=fam, arm="C5_near", note="paired corrections 1->0")
            emit(f"{base}.mcnemar_p_exact", st["p_exact"], n=st["n_pairs"],
                 family=fam, arm="C5_near", note="two-sided EXACT binomial, "
                                                 "recomputed from records")
            return st

        # per-family (gated: only families with >= MIN_FAMILY_N paired benign)
        passing: list[str] = []
        for fam in sorted(set(c0) | set(c5)):
            prev, cur = c0.get(fam, {}), c5.get(fam, {})
            st = paired_stats(prev, cur)
            powered = st["n_pairs"] >= MIN_FAMILY_N
            if powered:
                block(fam, prev, cur, "C5_near")
                fam_pass = bool(st["p_exact"] < 0.05
                                and st["flip_0to1"] > st["flip_1to0"])
                note = "rule: exact p<0.05 AND flip_b2v>flip_v2b"
                ms["families"][fam] = st
                if fam_pass:
                    passing.append(fam)
            else:
                fam_pass = False
                note = (f"NOT-RUN/UNPOWERED: paired n={st['n_pairs']} < "
                        f"{MIN_FAMILY_N} (prereg §2.3 item 5)")
                ms["families"][fam] = {**st, "unpowered": True}
            emit(f"cwe.{model}.{fam}.family_pass", int(fam_pass),
                 n=st["n_pairs"], family=fam, arm="C5_near", note=note)
        # pooled over participating families
        powered_fams = {f for f, s in ms["families"].items()
                        if not s.get("unpowered")}
        p0 = {s: v for fam, d in c0.items() if fam in powered_fams
              for s, v in d.items()}
        p5 = {s: v for fam, d in c5.items() if fam in powered_fams
              for s, v in d.items()}
        if not p0 or not p5:
            raise PendingError(f"{rel}: no powered-family benign pairs")
        stp = block("POOLED", p0, p5, "C5_near")
        pooled_pass = bool(stp["p_exact"] < 0.05
                           and (stp["rate_cur"] - stp["rate_prev"]) >= 0.15
                           and stp["flip_0to1"] > stp["flip_1to0"])
        emit(f"cwe.{model}.POOLED.pooled_pass", int(pooled_pass),
             n=stp["n_pairs"], family="POOLED", arm="C5_near",
             note="rule (H-G2): delta_fp>=0.15 AND exact p<0.05 AND "
                  "flip_b2v>flip_v2b")
        ms["pooled"] = stp
        # vul-side secondary (narrate only)
        for fam in sorted(set(v0) | set(v5)):
            stv = paired_stats(v0.get(fam, {}), v5.get(fam, {}))
            if stv["n_pairs"]:
                emit(f"cwe.{model}.{fam}.recall_vul_C0",
                     round(stv["rate_prev"], 4), n=stv["n_pairs"], family=fam,
                     arm="C0", note="secondary, narrate only (prereg §2.4)")
                emit(f"cwe.{model}.{fam}.recall_vul_C5_near",
                     round(stv["rate_cur"], 4), n=stv["n_pairs"], family=fam,
                     arm="C5_near", note="secondary, narrate only")
                emit(f"cwe.{model}.{fam}.mcnemar_p_vul", stv["p_exact"],
                     n=stv["n_pairs"], family=fam, arm="C5_near",
                     note="secondary, narrate only")
        # verdicts (computed by rule; both per-family and pooled reported)
        # V2-bug-#3 guard (S-Vòng-7): prereg §2.3.5 -- with fewer than the 4
        # registered families powered, H-G1 cannot fire ("GENERALIZES" via
        # >=3 passing requires ALL registered families powered); a verdict on
        # a partially-powered design can only be FAMILY-DEPENDENT or
        # pooled-driven.
        n_powered = len(powered_fams)
        g1_supported = (n_powered == FAMILIES_EXPECTED
                        and len(passing) >= 3)
        rows.append(row("RQ8", f"verdict.RQ8.{model}.families_powered",
                        n_powered, model=model, source_file=rel,
                        note=f"of {FAMILIES_EXPECTED} registered; unpowered "
                             f"families are excluded by rule (prereg §2.3.5)"))
        rows.append(row("RQ8", f"verdict.RQ8.{model}.family_pass_count",
                        len(passing), model=model, source_file=rel,
                        note=f"passing: {passing or 'none'} (H-G1: >=3/4)"))
        rows.append(row("RQ8", f"verdict.RQ8.{model}.H_G1",
                        "SUPPORTED" if g1_supported else "NOT_SUPPORTED",
                        model=model, source_file=rel,
                        note="rule: all 4 registered families powered AND "
                             ">=3 of them with exact p<0.05 AND b2v>v2b on "
                             "benign (prereg §2.3 + §2.3.5 guard: <=3 powered "
                             "-> H-G1 NOT_SUPPORTED)"))
        rows.append(row("RQ8", f"verdict.RQ8.{model}.H_G2",
                        "SUPPORTED" if pooled_pass else "NOT_SUPPORTED",
                        model=model, source_file=rel,
                        note=f"rule: pooled delta_fp>=0.15 AND p<0.05 AND "
                             f"b2v>v2b; observed delta="
                             f"{stp['rate_cur'] - stp['rate_prev']:+.4f}"))
        if g1_supported or pooled_pass:
            label = "GENERALIZES" if g1_supported \
                else "GENERALIZES-pooled-driven"
        else:
            label = "FAMILY-DEPENDENT"
        assert label in RQ8_LABELS
        rows.append(row("RQ8", f"verdict.RQ8.{model}.label", label,
                        model=model, source_file=rel,
                        note="rule (prereg §2.3 + §2.3.5): GENERALIZES iff "
                             "all 4 families powered AND family_pass_count>=3, "
                             "OR pooled_pass; pooled-driven sub-label when "
                             "family_pass_count<=2 (or <=3 families powered) "
                             "and pooled fires; else FAMILY-DEPENDENT. Both "
                             "per-family and pooled rows are ALWAYS reported "
                             "(anti-masking clause)."))
    if not summaries:
        raise PendingError("RQ8: manifest exists but no model results files")
    return rows, summaries


# ---------------------------------------------------------------------------
# RQ9: minimal replication ladder A0/A1/A5 (+ optional C0 arm for H-R3)
# ---------------------------------------------------------------------------
def _load_model_records(model: str) -> tuple[list[dict], dict, str]:
    """Load the executed per-variant layout (Amendment-1): three vul rung
    files (all required together) + the optional benign B0 file. Returns
    (records, benign_records, source_descriptor)."""
    files = RQ9_MODELS[model]
    recs: list[dict] = []
    rels: list[str] = []
    have_any = any(exists(rel) for rel in files["vul"].values())
    if not have_any:
        return [], {}, ""
    missing = [rel for rel in files["vul"].values() if not exists(rel)]
    if missing:
        raise PendingError(f"{model}: incomplete vul rung files (missing "
                           f"{missing}); all of A0/A1/A5 are required together")
    for rung in RQ9_RUNGS:
        rel = files["vul"][rung]
        d = load_json(rel)
        rr = [r for r in d["records"] if r.get("status") != "SKIPPED"]
        rungs_seen = {_rung_of(r) for r in rr}
        assert rungs_seen <= {rung}, \
            f"{rel}: records carry rungs {rungs_seen - {rung}} (file mixup)"
        recs.extend(rr)
        rels.append(rel)
    ben_recs: list[dict] = []
    if exists(files["benign"]):
        d = load_json(files["benign"])
        ben_recs = [r for r in d["records"] if r.get("status") != "SKIPPED"]
        recs.extend(ben_recs)
        rels.append(files["benign"])
        ben_conds = {r.get("condition") for r in ben_recs}
        assert ben_conds <= {"C0", "C5_near"}, \
            f"{files['benign']}: unexpected conditions {ben_conds}"
    assert recs, f"{model}: zero records in round-7 files"
    return recs, ben_recs, " + ".join(rels)


def build_rq9_rows() -> tuple[list[dict], dict]:
    rows: list[dict] = []
    summaries: dict[str, dict] = {}
    for model in RQ9_MODELS:
        recs, ben_recs, rel = _load_model_records(model)
        if not recs:
            continue
        # quarantine lesson (R6): reuse must never cross models
        cross = [r for r in recs
                 if r.get("meta", {}).get("reused_from")
                 and r["meta"]["reused_from"].get("model") not in (None, model)]
        assert not cross, f"{model}: cross-model reuse detected on " \
                          f"{len(cross)} records (quarantine rule)"
        rr = sum(1 for r in recs if r.get("status") == "REFUSAL") / len(recs)
        assert rr == 0.0, f"{model}: unexpected REFUSAL records (RR={rr})"

        def vul_pred(rung: str) -> dict[str, int]:
            return {str(r["sample_id"]): r["y_pred"] for r in recs
                    if _rung_of(r) == rung and r.get("condition") == "C5_near"
                    and r.get("y_true") == 1 and r.get("y_pred") in (0, 1)}

        def ben_pred(rung: str) -> dict[str, int]:
            return {str(r["sample_id"]): r["y_pred"] for r in recs
                    if _rung_of(r) == rung and r.get("condition") == "C5_near"
                    and r.get("y_true") == 0 and r.get("y_pred") in (0, 1)}

        vp = {s: vul_pred(s) for s in RQ9_RUNGS}
        bp = {s: ben_pred(s) for s in RQ9_RUNGS}
        recall = {s: (sum(vp[s].values()) / len(vp[s])) if vp[s] else 0.0
                  for s in RQ9_RUNGS}
        fp = {s: (sum(bp[s].values()) / len(bp[s])) if bp[s] else 0.0
              for s in RQ9_RUNGS}
        ms = summaries.setdefault(model, {"recall": recall, "fp": fp,
                                          "stats": {}, "records": recs})

        def emit(metric: str, value, *, n=None, arm="C5_near",
                 note: str = "", family=None) -> None:
            rows.append(row("RQ9", metric, value, n=n, model=model, arm=arm,
                            family=family, source_file=rel, note=note))

        for rung in RQ9_RUNGS:
            n_vul = len(vp[rung]) + sum(
                1 for r in recs if _rung_of(r) == rung
                and r.get("condition") == "C5_near"
                and r.get("y_true") == 1 and r.get("y_pred") not in (0, 1))
            n_ben = len(bp[rung])
            assert 0 <= recall[rung] <= 1.0 and 0 <= fp[rung] <= 1.0
            emit(f"scale.{model}.{rung}.recall_vul", round(recall[rung], 4),
                 n=n_vul, note="y_pred==1 among parsed vul records")
            emit(f"scale.{model}.{rung}.fp_rate", round(fp[rung], 4), n=n_ben,
                 note="y_pred==1 among parsed benign records; RR reported "
                      "separately, refusal never mapped to benign")
            emit(f"scale.{model}.{rung}.RR", 0.0, n=n_vul + n_ben,
                 note="RR asserted 0.0 across all round-7 records (assert "
                      "would have failed otherwise); refusal is never mapped "
                      "to benign")
            if rung != "A0":
                st = paired_stats(vp["A0"], vp[rung])
                sb = paired_stats(bp["A0"], bp[rung])
                ms["stats"][rung] = {"vul": st, "ben": sb}
                emit(f"scale.{model}.{rung}.delta_recall_vs_A0",
                     round(recall[rung] - recall["A0"], 4), n=st["n_pairs"],
                     note="recall(rung)-recall(A0) on parsed paired vul")
                emit(f"scale.{model}.{rung}.flip_v2b_vs_A0", st["flip_1to0"],
                     n=st["n_pairs"], note="paired vul 1->0 vs A0 (harm direction)")
                emit(f"scale.{model}.{rung}.flip_b2v_vs_A0", st["flip_0to1"],
                     n=st["n_pairs"], note="paired vul 0->1 vs A0 (recovery)")
                emit(f"scale.{model}.{rung}.mcnemar_p_vs_A0", st["p_exact"],
                     n=st["n_pairs"], note="two-sided EXACT binomial, recomputed")
                emit(f"scale.{model}.{rung}.benign_flip_1to0_vs_A0",
                     sb["flip_1to0"], n=sb["n_pairs"],
                     note="benign corrections 1->0 vs A0")
        # ---- H-R1 (primary; Amendment-1 branch order = A2 rule algebra) ----
        st5 = paired_stats(vp["A0"], vp["A5"])
        d_harm = recall["A0"] - recall["A5"]
        v2b5 = st5["flip_1to0"]
        if d_harm >= 0.20 and st5["p_exact"] < 0.05 and v2b5 >= 10:
            hr1 = "SUPPORTED"
        elif recall["A5"] > recall["A0"] + 0.10 and st5["p_exact"] < 0.05:
            hr1 = "NOT_SUPPORTED-REVERSAL"
        elif (d_harm <= 0.05 and st5["p_exact"] >= 0.05 and v2b5 <= 3
                and recall["A0"] >= 0.999):
            hr1 = "NOT_SUPPORTED-ABSENT-STRONG"
        elif d_harm <= 0.05 and st5["p_exact"] >= 0.05 and v2b5 <= 3:
            hr1 = "NOT_SUPPORTED-ABSENT"
        else:
            hr1 = "PARTIAL-INCONCLUSIVE"
        assert hr1 in RQ9_HR1
        rows.append(row("RQ9", f"verdict.RQ9.{model}.H_R1", hr1, model=model,
                        source_file=rel,
                        note=f"branch order: SUPPORTED -> REVERSAL -> "
                             f"ABSENT-STRONG -> ABSENT -> PARTIAL-INCONCLUSIVE "
                             f"(Amendment-1 §0b(iii)/(iv), configs/"
                             f"round7_7b.yaml rule algebra); recall "
                             f"A0={recall['A0']:.4f} A5={recall['A5']:.4f}, "
                             f"delta_harm={d_harm:+.4f}, flips_1to0={v2b5}, "
                             f"p_exact={st5['p_exact']:.3g}"))
        # dual framing: A2 config verdict strings, recomputed from records
        a2_rep = "SUPPORTED" if hr1 == "SUPPORTED" else "NOT_SUPPORTED"
        a2_absent = ("SUPPORTED" if hr1 in ("NOT_SUPPORTED-ABSENT-STRONG",
                                            "NOT_SUPPORTED-ABSENT")
                     else "NOT_SUPPORTED")
        rows.append(row("RQ9", f"verdict.RQ9.{model}.A2_H_R7_harm_replicates",
                        a2_rep, model=model, source_file=rel,
                        note="dual framing (Amendment-1 §0b(iv)): configs/"
                             "round7_7b.yaml H-R7-harm-replicates, recomputed "
                             "from the same records"))
        rows.append(row("RQ9", f"verdict.RQ9.{model}.A2_H_R7_harm_absent",
                        a2_absent, model=model, source_file=rel,
                        note="dual framing: H-R7-harm-absent; STRONG variant "
                             "when recall(A0)==1.0 is carried by the "
                             "ABSENT-STRONG branch of H_R1"))
        # ---- H-R2 (Amendment-1: A2 flip-count rule) -------------------------
        st1 = paired_stats(vp["A0"], vp["A1"])
        f10_a1 = st1["flip_1to0"]
        if f10_a1 <= 3 and st1["p_exact"] >= 0.05:
            hr2 = "SAFE"
        elif f10_a1 >= 10:
            hr2 = "UNSAFE"
        else:
            hr2 = "PARTIAL"
        assert hr2 in RQ9_HR2
        rows.append(row("RQ9", f"verdict.RQ9.{model}.H_R2", hr2, model=model,
                        source_file=rel,
                        note=f"rule: flips(1->0, A1 vs A0) <=3 AND p>=0.05 -> "
                             f"SAFE; >=10 -> UNSAFE; else PARTIAL "
                             f"(Amendment-1 §0b(iv)); flips={f10_a1}, "
                             f"p_exact={st1['p_exact']:.3g}"))
        # ---- H-R3 (benign_fp_check file = same-model C0 arm) ----------------
        c0b = {str(r["sample_id"]): r["y_pred"] for r in ben_recs
               if r.get("condition") == "C0" and r.get("y_true") == 0
               and r.get("y_pred") in (0, 1)} if ben_recs else {}
        c5b = {str(r["sample_id"]): r["y_pred"] for r in ben_recs
               if r.get("condition") == "C5_near" and r.get("y_true") == 0
               and r.get("y_pred") in (0, 1)} if ben_recs else {}
        if not c0b or not c5b:
            hr3 = "NOT_RUN"
            hr3_note = ("benign_fp_check (same-model B0 benign C0-vs-C5_near) "
                        "missing from sources; prereg §3.4 forbids borrowing "
                        "C0 from another model")
        else:
            stf = paired_stats(c0b, c5b)
            fp_c0 = stf["rate_prev"]
            if fp_c0 >= 0.95:
                hr3 = "SATURATED-UNINFORMATIVE"
            elif stf["p_exact"] < 0.05 and stf["flip_0to1"] > stf["flip_1to0"]:
                hr3 = "CONSISTENT"
            elif stf["p_exact"] < 0.05 and stf["flip_1to0"] > stf["flip_0to1"]:
                hr3 = "DIRECTION-REVERSED"
            else:
                hr3 = "NOT_SUPPORTED"
            hr3_note = (f"benign C0 FP={fp_c0:.4f}, C5_near flips "
                        f"b2v={stf['flip_0to1']} v2b={stf['flip_1to0']}, "
                        f"n={stf['n_pairs']}, p_exact={stf['p_exact']:.3g}")
            emit(f"scale.{model}.C0.fp_rate", round(fp_c0, 4), n=len(c0b),
                 arm="C0", note="same-model B0 benign arm (H-R3 reference)")
            emit(f"scale.{model}.C5_near.fp_vs_C0.flip_b2v", stf["flip_0to1"],
                 n=stf["n_pairs"], note="paired benign 0->1 vs C0 (FP direction)")
            emit(f"scale.{model}.C5_near.fp_vs_C0.flip_v2b", stf["flip_1to0"],
                 n=stf["n_pairs"], note="paired benign corrections 1->0 vs C0")
            emit(f"scale.{model}.C5_near.fp_vs_C0.mcnemar_p_exact",
                 stf["p_exact"], n=stf["n_pairs"],
                 note="two-sided EXACT binomial, recomputed")
        assert hr3 in RQ9_HR3
        rows.append(row("RQ9", f"verdict.RQ9.{model}.H_R3", hr3, model=model,
                        source_file=rel, note=hr3_note))
        ms["hr3_stats"] = hr3_note
        # accounting
        reused = sum(1 for r in recs if r.get("meta", {}).get("reused_from"))
        rows.append(row("RQ9", f"accounting.records.{model}", len(recs),
                        model=model, source_file=rel,
                        note=f"reused-from (same-model only) recount: {reused}; "
                             "cross-model reuse is asserted against"))
    if not summaries:
        raise PendingError("RQ9: no ladder results files")
    return rows, summaries


# ---------------------------------------------------------------------------
# optional prompt-identity guard (RQ9 vs round-6 same-sample prompts)
# ---------------------------------------------------------------------------
def build_rq9_identity_rows(rq9_summaries: dict) -> list[dict]:
    """Same (sample, rung, arm) prompt-SHA match vs the round-6 qwen spot
    records — the 'same prompt, different model' guard (Amendment-1)."""
    rows: list[dict] = []
    for model, rel6 in RQ6_LADDER.items():
        if model not in rq9_summaries or not exists(rel6):
            continue
        r7 = rq9_summaries[model]["records"]
        r6 = load_json(rel6)["records"]
        r6_map = {(str(r["sample_id"]), r.get("variant"), r.get("condition")):
                  r.get("meta", {}).get("prompt_sha256_16")
                  for r in r6 if r.get("y_true") == 1}
        ok = tot = 0
        for r in r7:
            if r.get("y_true") != 1 or r.get("condition") != "C5_near":
                continue
            key = (str(r["sample_id"]), _rung_of(r), "C5_near")
            if key not in r6_map or r6_map[key] is None:
                continue
            tot += 1
            if r.get("meta", {}).get("prompt_sha256_16") == r6_map[key]:
                ok += 1
        if tot == 0:
            continue
        rows.append(row("RQ9", f"scale.{model}.prompt_identity.vs_round6",
                        f"{ok}/{tot}", model=model,
                        source_file=f"{RQ9_DIR}/ + {rel6}",
                        note="same (sample, rung, arm) prompt_sha256_16 match "
                             "against the round-6 ladder records — "
                             "'same prompt, different model' guard; y_pred is "
                             "NOT expected to match across models"))
    return rows


# ---------------------------------------------------------------------------
# token map (LaTeX strings for every {{R7:*}} slot in the paper)
# ---------------------------------------------------------------------------
def build_token_map(rows: list[dict], rq8: dict, rq9: dict) -> dict[str, str]:
    val = {r["metric"]: r["value"] for r in rows}
    tm: dict[str, str] = {}

    def f3(x) -> str:
        return f"{x:.3f}"

    def pstr(p: float) -> str:
        if p == 1.0:
            return "$1.0$"
        if p >= 0.001:
            return f"${p:.4g}$"
        exp = 0
        m = p
        while m < 1:
            m *= 10
            exp += 1
        mant = f"{m:.2f}".rstrip("0").rstrip(".")
        return f"${mant}" + r"{\times}10^{" + f"-{exp}}}$"

    def signed(x: float) -> str:
        s = f"{abs(x):.3f}"
        return f"$-{s}$" if x < 0 else (f"$+{s}$" if x > 0 else "$0.000$")

    for model, ms in rq8.items():
        for fam, st in ms["families"].items():
            p = f"cwe.{model}.{fam}"
            tm[f"tab.rq8.{model}.{fam}.c0"] = f3(val[f"{p}.fp_rate_C0"])
            tm[f"tab.rq8.{model}.{fam}.c5"] = f3(val[f"{p}.fp_rate_C5_near"])
            tm[f"tab.rq8.{model}.{fam}.delta"] = signed(val[f"{p}.delta_fp"])
            tm[f"tab.rq8.{model}.{fam}.flips"] = \
                f"{val[f'{p}.flip_b2v']}/{val[f'{p}.flip_v2b']}"
            tm[f"tab.rq8.{model}.{fam}.p"] = pstr(val[f"{p}.mcnemar_p_exact"])
            star = "*" if val[f"{p}.family_pass"] else ""
            # LaTeX text mode renders "F-UAF" with a plain hyphen: keep as-is
            tm[f"tab.rq8.{model}.{fam}.family"] = f"{fam}{star}"
            tm[f"rq8.{model}.{fam}.family_clause"] = (
                f"{fam}: {val[f'{p}.flip_b2v']}/"
                f"{val[f'{p}.flip_v2b']} paired benign flips (n="
                f"{st['n_pairs']}, p="
                f"{pstr(val[f'{p}.mcnemar_p_exact'])[1:-1]})")
        p = f"cwe.{model}.POOLED"
        tm[f"tab.rq8.{model}.POOLED.c0"] = f3(val[f"{p}.fp_rate_C0"])
        tm[f"tab.rq8.{model}.POOLED.c5"] = f3(val[f"{p}.fp_rate_C5_near"])
        tm[f"tab.rq8.{model}.POOLED.delta"] = signed(val[f"{p}.delta_fp"])
        tm[f"tab.rq8.{model}.POOLED.flips"] = \
            f"{val[f'{p}.flip_b2v']}/{val[f'{p}.flip_v2b']}"
        tm[f"tab.rq8.{model}.POOLED.p"] = pstr(val[f"{p}.mcnemar_p_exact"])
        lab = val[f"verdict.RQ8.{model}.label"]
        fc = val[f"verdict.RQ8.{model}.family_pass_count"]
        npow = val[f"verdict.RQ8.{model}.families_powered"]
        tm[f"tab.rq8.{model}.verdict"] = (
            f"{lab} (family\\_pass\\_count {fc}/{npow} of "
            f"{FAMILIES_EXPECTED}; H-G1 "
            f"{val[f'verdict.RQ8.{model}.H_G1']}, H-G2 "
            f"{val[f'verdict.RQ8.{model}.H_G2']})")
        tm[f"rq8.{model}.verdict_clause"] = tm[f"tab.rq8.{model}.verdict"]
        tm[f"rq8.{model}.family_clause"] = "; ".join(
            tm[f"rq8.{model}.{fam}.family_clause"] for fam in ms["families"])
        tm[f"rq8.{model}.pooled_clause"] = (
            f"pooled FP {val[f'cwe.{model}.POOLED.fp_rate_C0']:.3f}"
            f"$\\rightarrow${val[f'cwe.{model}.POOLED.fp_rate_C5_near']:.3f} "
            f"($\\Delta$FP={val[f'cwe.{model}.POOLED.delta_fp']:+.3f}, "
            f"{val[f'cwe.{model}.POOLED.flip_b2v']} benign$\\to$vulnerable vs "
            f"{val[f'cwe.{model}.POOLED.flip_v2b']} corrections, n="
            f"{ms['pooled']['n_pairs']}, "
            f"p={pstr(val[f'cwe.{model}.POOLED.mcnemar_p_exact'])[1:-1]})")
    for model, ms in rq9.items():
        for rung in RQ9_RUNGS:
            p = f"scale.{model}.{rung}"
            tm[f"tab.rq9.{model}.{rung}.recall"] = f3(val[f"{p}.recall_vul"])
            tm[f"tab.rq9.{model}.{rung}.fp"] = f3(val[f"{p}.fp_rate"])
            if rung != "A0":
                tm[f"tab.rq9.{model}.{rung}.delta"] = \
                    signed(val[f"{p}.delta_recall_vs_A0"])
                tm[f"tab.rq9.{model}.{rung}.p"] = \
                    pstr(val[f"{p}.mcnemar_p_vs_A0"])
        tm[f"rq9.{model}.model_clause"] = str(model)
        tm[f"rq9.{model}.hr1_clause"] = (
            f"H-R1 {val[f'verdict.RQ9.{model}.H_R1']}: recall "
            f"{val[f'scale.{model}.A0.recall_vul']:.3f}"
            f"$\\rightarrow${val[f'scale.{model}.A5.recall_vul']:.3f} "
            f"(A0$\\to$A5 flips "
            f"{val[f'scale.{model}.A5.flip_v2b_vs_A0']}/"
            f"{val[f'scale.{model}.A5.flip_b2v_vs_A0']}, "
            f"p={pstr(val[f'scale.{model}.A5.mcnemar_p_vs_A0'])[1:-1]})")
        tm[f"rq9.{model}.hr2_clause"] = (
            f"H-R2 {val[f'verdict.RQ9.{model}.H_R2']}: "
            f"$\\Delta$recall(A0$\\to$A1) = "
            f"{val[f'scale.{model}.A1.delta_recall_vs_A0']:+.3f}")
        hr3 = val[f"verdict.RQ9.{model}.H_R3"]
        tm[f"rq9.{model}.hr3_clause"] = (
            f"H-R3 {hr3}" + (f": {ms['hr3_stats']}" if ms.get("hr3_stats")
                             and hr3 != "NOT_RUN" else ""))
        ident_key = f"scale.{model}.prompt_identity.vs_round6"
        tm[f"rq9.{model}.identity_clause"] = (
            f"{val[ident_key]} of the overlapping (sample, rung) prompts "
            "match the Round-6 prompt SHAs byte-for-byte (same prompt, "
            "different model)" if ident_key in val else
            "prompt-identity guard not computed (no round-6 overlap)")
        tm[f"tab.rq9.{model}.verdicts"] = (
            f"{val[f'verdict.RQ9.{model}.H_R1']} \\cdot "
            f"H-R2 {val[f'verdict.RQ9.{model}.H_R2']} \\cdot "
            f"H-R3 {hr3}")
    return tm


# ---------------------------------------------------------------------------
# structural checks + verify
# ---------------------------------------------------------------------------
def check_structure(rows: list[dict]) -> None:
    for r in rows:
        assert r["experiment"] in ("RQ8", "RQ9"), r
        assert isinstance(r["metric"], str) and r["metric"], r
        assert "source_file" in r, r
        v = r["value"]
        if isinstance(v, float):
            if "delta" in r["metric"]:
                assert -1.0 - EPS <= v <= 1.0 + EPS, (r["metric"], v)
            else:
                assert 0.0 <= v <= 1.0 + EPS, (r["metric"], v)
        if r["experiment"] == "RQ8" and not r["metric"].startswith("verdict."):
            assert "model" in r and "family" in r and "arm" in r, r
        if r["experiment"] == "RQ8" and r["metric"].startswith("verdict."):
            assert "model" in r, r
        if r.get("metric", "").startswith("verdict.RQ9.") \
                and r["metric"].endswith("H_R1"):
            assert v in RQ9_HR1, v


def build_available() -> tuple[list[dict], dict, dict, list[str]]:
    """Build whichever round-7 parts have sources; defer the rest with a
    reason (never raise for a missing part)."""
    rows: list[dict] = []
    rq8: dict = {}
    rq9: dict = {}
    deferred: list[str] = []
    try:
        rq8_rows, rq8 = build_rq8_rows()
        rows += rq8_rows
    except (PendingError, AssertionError, FileNotFoundError) as exc:
        deferred.append(f"RQ8 deferred: {exc}")
    try:
        rq9_rows, rq9 = build_rq9_rows()
        rows += rq9_rows
        rows += build_rq9_identity_rows(rq9)
    except (PendingError, AssertionError, FileNotFoundError) as exc:
        deferred.append(f"RQ9 deferred: {exc}")
    check_structure(rows)
    return rows, rq8, rq9, deferred


def verify(master: dict) -> None:
    """Rebuild every part PRESENT on disk from freshly loaded sources and
    compare row-by-row. A source file that existed when the master was
    written but is gone now is an integrity error (fail loudly)."""
    global _CACHE
    _CACHE = {}
    exps = {r["experiment"] for r in master["results"]}
    fresh: list[dict] = []
    if "RQ8" in exps:
        rows8, _ = build_rq8_rows()          # missing source -> raises
        fresh += rows8
    if "RQ9" in exps:
        rows9, rq9s = build_rq9_rows()
        fresh += rows9
        fresh += build_rq9_identity_rows(rq9s)
    assert len(fresh) == len(master["results"]), \
        (f"row count drift: disk {len(master['results'])} vs fresh {len(fresh)}")
    for on_disk, rebuilt in zip(master["results"], fresh):
        assert on_disk == rebuilt, \
            f"mismatch\n disk : {json.dumps(on_disk)}\n fresh: {json.dumps(rebuilt)}"


def pending_parts() -> list[str]:
    pend = []
    if not exists(RQ8_MANIFEST):
        pend.append(f"[pending] RQ8 manifest: {RQ8_MANIFEST}")
    n_models = sum(1 for rel in RQ8_RESULTS.values() if exists(rel))
    if n_models == 0:
        pend.append(f"[pending] RQ8 results (0/{len(RQ8_RESULTS)} models): "
                    + ", ".join(RQ8_RESULTS.values()))
    n_ladders = sum(
        1 for m in RQ9_MODELS.values()
        if any(exists(rel) for rel in list(m["vul"].values()) + [m["benign"]]))
    if n_ladders == 0:
        pend.append(f"[pending] RQ9 ladders (0/{len(RQ9_MODELS)} models): "
                    f"{RQ9_DIR}/results_<model>__vul__{{A0,A1,A5}}.json + "
                    f"results_<model>__benign__B0.json for "
                    f"{sorted(RQ9_MODELS)}")
    return pend


def main(argv: list[str] | None = None) -> int:
    global PROJECT
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify-only", action="store_true")
    args = ap.parse_args(argv)

    out_json = PROJECT / "outputs/master/round7_master.json"
    token_json = PROJECT / "outputs/master/round7_token_map.json"

    if args.verify_only:
        if not out_json.exists():
            for line in pending_parts() or ["[pending] no round-7 sources"]:
                print(line)
            print("[pending] outputs/master/round7_master.json not present; "
                  "nothing to verify (fail-safe exit 0)")
            return 0
        master = json.loads(out_json.read_text(encoding="utf-8"))
        verify(master)
        print(f"[verify] {len(master['results'])} round-7 rows re-derived from "
              f"sources and matched against {out_json.relative_to(PROJECT)}")
        return 0

    have_rq8 = exists(RQ8_MANIFEST) and any(
        exists(rel) for rel in RQ8_RESULTS.values())
    have_rq9 = any(
        exists(rel) for m in RQ9_MODELS.values() for rel in m["vul"].values())
    if not (have_rq8 or have_rq9):
        for line in pending_parts():
            print(line)
        print("[pending] round-7 outputs not present; nothing written "
              "(fail-safe exit 0). Paper stays on {{R7:*}} placeholders.")
        return 0

    rows, rq8, rq9, partial = build_available()
    if not rows:
        for line in pending_parts():
            print(line)
        print("[pending] no buildable round-7 rows; nothing written")
        return 0
    tm = build_token_map(rows, rq8, rq9)
    master = {
        "meta": {
            "round": 7,
            "generated_by": "scripts/collect_master_round7.py",
            "prereg": "docs/round7_prereg.md",
            "partial": partial or "complete",
            "note": "every value computed from source files; re-read "
                    "verification after write; McNemar p is two-sided exact "
                    "binomial (discordant-only); verdicts computed by the "
                    "pre-registered rules, never by hand. Schema: "
                    "{experiment: RQ8|RQ9, metric, value, ci?, n, model, "
                    "family?, arm?, source_file, note?}.",
            "token_map": "outputs/master/round7_token_map.json",
        },
        "results": rows,
    }
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(master, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8")
    token_json.write_text(json.dumps(tm, indent=2, ensure_ascii=False) + "\n",
                          encoding="utf-8")
    verify(master)
    status = f"{len(rows)} rows"
    if partial:
        status += " (" + "; ".join(partial) + ")"
    print(f"[ok] wrote {out_json.relative_to(PROJECT)} ({status}) + "
          f"round7_token_map.json; re-read verification passed")
    for line in pending_parts():
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
