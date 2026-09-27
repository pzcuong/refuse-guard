#!/usr/bin/env python
"""r12_defense_analysis.py -- round-12 W2 analysis of the attack-defense pairing.

Reads W1's defense batch ``outputs/packguard/defense/defense_batch.jsonl``
(real, mock=false rows) and emits the registered round-12 statistics:

  1. recall(restoration) table per model: malicious recall under
     P0_neutral -> P2_nodef (attack, no defense) -> P2+D1 (advisory attack
     after the AST comment/docstring strip defense),
  2. exact paired McNemar for (P2_nodef vs P2+D1) and (P0 vs P2+D1) on the
     paired detection booleans (malicious subset) AND on the benign-FP
     booleans (benign subset),
  3. TWO-DIRECTIONAL flip reporting (AMENDMENT-6 rule): restore-gain
     (0->1 under the defense) and restore-loss (1->0 under the defense)
     are both counted and both reported -- neither direction is silently
     dropped into an "other" bucket,
  4. benign false positives per arm (FP never conflated with malicious
     recall; refusal is never mapped to a verdict),
  5. secondary Wilcoxon signed-rank over paired per-sample confidence
     deltas, DESCRIPTIVE ONLY (labelled as such), skipped with an explicit
     reason when a comparison carries no usable confidence values.

FAIL-SAFE (pre-reg SS Eval rule: "pending, never fabricated"): if the
input file does not exist or contains only a meta header, the script
writes an analysis JSON with ``status: pending`` and exits 0.  If the
input file EXISTS but is malformed (missing keys, unknown arms), the
script FAILS LOUDLY -- silent partial analyses are worse than crashes.

MOCK HYGIENE (PACKGUARD_BRIEF principle 1): ``--mock`` runs the analysis
on a small built-in fixture with ``mock: true`` in every row and writes
ONLY to ``outputs/packguard/defense/defense_analysis_mock.json`` (the
mock path is rejected for real runs and vice versa).  Mock numbers can
never be mistaken for real ones: the output carries mock=true, a
fixture id, and a distinct filename.

Usage:
  .venv/bin/python scripts/r12_defense_analysis.py            # real, or pending
  .venv/bin/python scripts/r12_defense_analysis.py --mock     # fixture self-test
  .venv/bin/python scripts/r12_defense_analysis.py --input P --out P2

Writes only: outputs/packguard/defense/defense_analysis[_mock].json
(or the --out override).  No GPU, no model loads -- pure CPU bookkeeping.
"""
from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.metrics.stats import mcnemar  # project-registered paired test

DEFAULT_INPUT = ROOT / "outputs/packguard/defense/defense_batch.jsonl"
DEFAULT_OUT = ROOT / "outputs/packguard/defense/defense_analysis.json"
MOCK_OUT = ROOT / "outputs/packguard/defense/defense_analysis_mock.json"
FEATURES = ROOT / "outputs/packguard/features/features_v2.jsonl"

# Canonical arms of the round-12 pairing.
P0 = "P0_neutral"
P2_NODEF = "P2_nodef"          # attack arm, no defense
P2_D1 = "P2_D1"                # attack arm under the D1 strip defense
EXPECTED_ARMS = (P0, P2_NODEF, P2_D1)

# The two registered paired comparisons (task A1).
COMPARISONS = ((P2_NODEF, P2_D1), (P0, P2_D1))


# ------------------------------------------------------------------ helpers
def normalize_arm(raw: str) -> Optional[str]:
    """Map W1's condition label onto the canonical round-12 arms.

    Tolerant to spelling variants ("P2_defended", "P2_D1_stripped",
    "P2_nodefense", ...) so the reader does not silently drop rows whose
    condition was named slightly differently.  Returns None for arms that
    are not part of this pairing (caller counts them as ignored, with the
    raw names disclosed in the output meta).
    """
    s = (raw or "").strip().lower()
    if not s:
        return None
    if "p0" in s:
        return P0
    if "p2" in s or "advisory" in s:
        has_def = ("d1" in s or "defend" in s or "def_" in s
                   or "strip" in s or "sanitize" in s)
        no_def = ("nodef" in s or "no_def" in s or "undefend" in s
                  or "no-defense" in s)
        if has_def and not no_def:
            return P2_D1
        if no_def or not has_def:
            return P2_NODEF
    return None


def verdict_of(rec: dict) -> Optional[int]:
    """Parsed verdict (0 benign / 1 malicious) or None.

    A verdict exists iff the model returned a parsed JSON carrying a
    ``vulnerable`` field and the record status is not a refusal --
    refusal is NEVER mapped onto benign or malicious (prereg SS Safety).
    PARTIAL rows count as parsed when their JSON parsed (the round-10
    criterion used for the 1 PARTIAL record of the n=60 batch).
    """
    if str(rec.get("status", "")).upper() == "REFUSAL":
        return None
    parsed = rec.get("parsed")
    vuln = rec.get("vulnerable", None)
    if vuln is None and isinstance(parsed, dict):
        vuln = parsed.get("vulnerable", None)
    if vuln is None:
        return None
    try:
        return int(vuln)
    except (TypeError, ValueError):
        return None


def confidence_of(rec: dict) -> Optional[float]:
    """Parsed confidence in [0,1] or None (secondary Wilcoxon input)."""
    parsed = rec.get("parsed")
    conf = rec.get("confidence", None)
    if conf is None and isinstance(parsed, dict):
        conf = parsed.get("confidence", None)
    if conf is None:
        return None
    try:
        c = float(conf)
    except (TypeError, ValueError):
        return None
    return c if 0.0 <= c <= 1.0 else None


def load_labels_from_features(path: Path) -> dict[str, int]:
    """sample_id -> label map from the frozen features file (label-join fallback).

    ``outputs/packguard/features/features_v2.jsonl`` keys its rows with
    ``sample_id`` (603/603 rows; no ``id`` field exists) -- matching that
    schema exactly and failing loud on anything else (no silent guessing).
    """
    labels: dict[str, int] = {}
    with path.open() as f:
        for line in f:
            r = json.loads(line)
            if "sample_id" not in r:
                raise LoudError(
                    f"{path}: features row lacks 'sample_id' "
                    f"(keys={sorted(r)[:8]}) -- label join would be a guess")
            labels[str(r["sample_id"])] = int(r["label"])
    return labels


def read_batch(path: Path) -> tuple[Optional[dict], list[dict]]:
    """Read the W1 defense batch (jsonl; first line may be a meta header).

    Returns (meta_or_None, records).  Raises LoudError on a malformed
    RECORD row (the file exists -> no silent degradation).
    """
    meta: Optional[dict] = None
    records: list[dict] = []
    with path.open() as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if "sample_id" not in row:
                if lineno == 1 and "meta" in row:
                    meta = row["meta"]
                    continue
                raise LoudError(f"{path}:{lineno}: row has no sample_id "
                                f"and is not the meta header: keys={sorted(row)[:8]}")
            records.append(row)
    return meta, records


class LoudError(RuntimeError):
    pass


# ----------------------------------------------------------------- analysis
def paired_block(pairs: list[tuple[Optional[int], Optional[int]]],
                 which_label: str) -> dict:
    """Statistics over paired verdicts restricted to one true-label subset.

    ``pairs`` = [(verdict_arm_a, verdict_arm_b), ...] on the same samples;
    None = unparsed/refused -> the PAIR IS DROPPED from verdict statistics
    and counted in n_dropped so denominators stay honest.
    """
    usable = [(a, b) for a, b in pairs if a is not None and b is not None]
    dropped = len(pairs) - len(usable)
    a_pos = sum(1 for a, _ in usable if a == 1)
    b_pos = sum(1 for _, b in usable if b == 1)
    loss = sum(1 for a, b in usable if a == 1 and b == 0)   # restore-loss
    gain = sum(1 for a, b in usable if a == 0 and b == 1)   # restore-gain
    n = len(usable)
    block: dict[str, Any] = {
        "subset": which_label,
        "n_pairs": n,
        "n_pairs_dropped_unparsed_or_refusal": dropped,
        "pos_a": a_pos,
        "pos_b": b_pos,
        "rate_a": (a_pos / n) if n else None,
        "rate_b": (b_pos / n) if n else None,
        "delta_b_minus_a": ((b_pos - a_pos) / n) if n else None,
        "flips_a1_b0": loss,
        "flips_a0_b1": gain,
    }
    if n:
        mc = mcnemar([bool(a) for a, _ in usable], [bool(b) for _, b in usable],
                     exact=True)
        block["mcnemar_exact"] = {
            "n": mc["n"],
            "b01_a0_b1": mc["b01_a_fail_b_success"],
            "b10_a1_b0": mc["b10_a_success_b_fail"],
            "p_value": mc["p_value"],
            "method": mc.get("method", "exact-binomial"),
        }
    else:
        block["mcnemar_exact"] = None
    return block


def wilcoxon_block(conf_pairs: list[tuple[Optional[float], Optional[float]]]) -> dict:
    """Secondary DESCRIPTIVE Wilcoxon over paired confidence deltas."""
    usable = [(a, b) for a, b in conf_pairs if a is not None and b is not None]
    if not usable:
        return {"available": False,
                "reason": "no paired parsed confidence values in this comparison"}
    try:
        from scipy.stats import wilcoxon as _wilcoxon
    except ImportError:  # pragma: no cover - scipy is in the lockfile
        return {"available": False, "reason": "scipy unavailable"}
    xs = [a for a, _ in usable]
    ys = [b for _, b in usable]
    nonidentical = any(a != b for a, b in usable)
    if not nonidentical:
        return {"available": True, "n_pairs": len(usable), "statistic": 0.0,
                "p_value": 1.0, "note": "all paired confidences identical"}
    method = "exact" if len(usable) <= 25 else "approx"
    stat, p = _wilcoxon(xs, ys, zero_method="wilcox", alternative="two-sided",
                        method=method)
    return {"available": True, "n_pairs": len(usable), "statistic": float(stat),
            "p_value": float(p), "method": method,
            "role": "secondary descriptive -- NOT a headline claim"}


def analyze_records(records: list[dict], meta: Optional[dict],
                    labels_fallback: Optional[dict[str, int]] = None,
                    mock: bool = False) -> dict:
    """Full round-12 analysis over normalized records."""
    unknown_arms: dict[str, int] = {}
    # buckets[(model, arm)][sample_id] = rec
    buckets: dict[tuple[str, str], dict[str, dict]] = {}
    for rec in records:
        arm = normalize_arm(str(rec.get("arm", rec.get("condition", ""))))
        if arm is None:
            key = str(rec.get("arm", rec.get("condition", "<missing>")))
            unknown_arms[key] = unknown_arms.get(key, 0) + 1
            continue
        model = str(rec.get("model_id", "unknown"))
        buckets.setdefault((model, arm), {})[str(rec["sample_id"])] = rec

    present = {arm for (_, arm) in buckets}
    missing_arms = [a for a in EXPECTED_ARMS if a not in present]
    if missing_arms:
        raise LoudError(
            f"defense batch lacks expected arms {missing_arms}; "
            f"present={sorted(present)} unknown_arm_rows={unknown_arms}. "
            "Refusing to emit a partial analysis (fail-loud rule).")

    # label resolution: per-record label, else frozen-features join, else error
    def label_of(rec: dict, sid: str) -> int:
        lab = rec.get("label", None)
        if lab is None and labels_fallback is not None:
            lab = labels_fallback.get(sid)
            if lab is None and "\x00" in sid:
                # pooled keys are "model\x00sample_id"; retry the bare id
                lab = labels_fallback.get(sid.split("\x00", 1)[1])
        if lab is None:
            raise LoudError(f"no label for sample {sid!r} (record and "
                            "features-join both empty) -- cannot split "
                            "recall from FP; fix the batch or pass labels")
        return int(lab)

    def scope_block(arms: dict[str, dict[str, dict]]) -> dict:
        """All round-12 statistics for one scope (one model, or pooled)."""
        ids = sorted(set().union(*(set(a) for a in arms.values())))
        # ---- per-arm marginal table (recall / FP / refusal)
        arm_table: dict[str, dict] = {}
        for arm, recs in arms.items():
            n_total = len(ids)
            mal_det = mal_pairs = 0
            ben_fp = ben_pairs = 0
            refused = 0
            for sid in ids:
                rec = recs.get(sid)
                if rec is None:
                    continue
                v = verdict_of(rec)
                if v is None:
                    refused += 1
                    continue
                if label_of(rec, sid) == 1:
                    mal_pairs += 1
                    mal_det += int(v == 1)
                else:
                    ben_pairs += 1
                    ben_fp += int(v == 1)
            arm_table[arm] = {
                "n_samples": n_total,
                "n_records": len(recs),
                "malicious_n_parsed": mal_pairs,
                "malicious_recall": (mal_det / mal_pairs) if mal_pairs else None,
                "malicious_detected": mal_det,
                "benign_n_parsed": ben_pairs,
                "benign_fp_count": ben_fp,
                "benign_fp_rate": (ben_fp / ben_pairs) if ben_pairs else None,
                "n_unparsed_or_refusal": refused,
                "rr": (refused / len(recs)) if recs else None,
            }

        # ---- registered paired comparisons (both directions reported)
        comparisons: dict[str, dict] = {}
        for arm_a, arm_b in COMPARISONS:
            mal_pairs: list[tuple[Optional[int], Optional[int]]] = []
            ben_pairs2: list[tuple[Optional[int], Optional[int]]] = []
            conf_pairs: list[tuple[Optional[float], Optional[float]]] = []
            missing_a = missing_b = 0  # sample present in one arm only
            for sid in ids:
                ra, rb = arms[arm_a].get(sid), arms[arm_b].get(sid)
                if ra is None or rb is None:
                    # AMENDMENT-6 gate-FAIL/draw exclusions must never be
                    # silently folded into the denominators
                    if ra is None:
                        missing_a += 1
                    if rb is None:
                        missing_b += 1
                    continue
                va, vb = verdict_of(ra), verdict_of(rb)
                if label_of(ra, sid) == 1:
                    mal_pairs.append((va, vb))
                else:
                    ben_pairs2.append((va, vb))
                conf_pairs.append((confidence_of(ra), confidence_of(rb)))
            key = f"{arm_a}__vs__{arm_b}"
            comparisons[key] = {
                "n_samples_only_in_a": missing_a,
                "n_samples_only_in_b": missing_b,
                "malicious": paired_block(mal_pairs, "label=1 (recall)"),
                "benign": paired_block(ben_pairs2, "label=0 (FP)"),
                "wilcoxon_confidence_secondary":
                    wilcoxon_block(conf_pairs),
            }

        # ---- restoration summary (the headline read of the table)
        rec_p0 = arm_table[P0]["malicious_recall"]
        rec_att = arm_table[P2_NODEF]["malicious_recall"]
        rec_def = arm_table[P2_D1]["malicious_recall"]
        mal_cmp = comparisons[f"{P2_NODEF}__vs__{P2_D1}"]["malicious"]
        restoration = {
            "recall_P0": rec_p0,
            "recall_P2_nodef": rec_att,
            "recall_P2_D1": rec_def,
            "attack_effect_recall": (None if rec_att is None or rec_p0 is None
                                     else rec_att - rec_p0),
            "defense_restoration_recall": (None if rec_def is None or rec_att is None
                                           else rec_def - rec_att),
            "restore_gain_flips": mal_cmp["flips_a0_b1"],
            "restore_loss_flips": mal_cmp["flips_a1_b0"],
            "both_directions_reported": True,
        }
        return {
            "n_samples_union": len(ids),
            "arms": arm_table,
            "comparisons": comparisons,
            "restoration": restoration,
        }

    per_model: dict[str, dict] = {}
    models = sorted({m for (m, _) in buckets})
    for model in models:
        per_model[model] = scope_block(
            {arm: buckets.get((model, arm), {}) for arm in EXPECTED_ARMS})

    # pooled-across-models scope: provided for the inline headline sentence,
    # with the project's own caveat attached (the n=100 expansion showed
    # pooled numbers mask OPPOSITE per-model movement -- per-model table
    # remains the primary read).
    # Merge keys are (model, sample_id): sample_ids repeat across models, so
    # a bare sample_id key would let the last model silently overwrite the
    # earlier ones (the round-12 audit caught exactly this: "pooled" was
    # llama alone).  The prefix keeps every model's rows in the pool.
    merged: dict[str, dict[str, dict]] = {}
    for arm in EXPECTED_ARMS:
        pool: dict[str, dict] = {}
        for model in models:
            for sid, rec in buckets.get((model, arm), {}).items():
                pool[f"{model}\x00{sid}"] = rec
        merged[arm] = pool
    pooled = scope_block(merged)
    pooled["per_model_pointers"] = {
        model: {"recall_P0": per_model[model]["restoration"]["recall_P0"],
                "recall_P2_nodef": per_model[model]["restoration"]["recall_P2_nodef"],
                "recall_P2_D1": per_model[model]["restoration"]["recall_P2_D1"],
                "restore_gain_flips": per_model[model]["restoration"]["restore_gain_flips"],
                "restore_loss_flips": per_model[model]["restoration"]["restore_loss_flips"]}
        for model in models}
    pooled["caveat"] = (
        "pooled across models (merge keyed model+sample_id, no model "
        "overwrite); masks OPPOSITE per-model movement (here: loss "
        f"{pooled['restoration']['restore_loss_flips']} vs gain "
        f"{pooled['restoration']['restore_gain_flips']}) -- the per-model "
        "table is the primary read; at this pilot n every pooled statistic "
        "is DESCRIPTIVE, not an inference")

    # Descriptive-power disclosure, computed from THIS batch (never typed by
    # hand): exact McNemar over tiny discordant counts carries little
    # information, and a 0-discordant comparison has p=1.0 by construction.
    min_p = None
    zero_discordant: list[str] = []
    for scope_name, scope in ([("pooled", pooled)]
                              + [(m, per_model[m]) for m in models]):
        for cmp_name, cmpb in scope["comparisons"].items():
            for subset in ("malicious", "benign"):
                mc = cmpb[subset].get("mcnemar_exact")
                if not mc:
                    continue
                p = mc["p_value"]
                if min_p is None or p < min_p:
                    min_p = p
                if mc["b01_a0_b1"] + mc["b10_a1_b0"] == 0:
                    zero_discordant.append(f"{scope_name}/{cmp_name}/{subset}")
    descriptive_power = {
        "min_exact_mcnemar_p": min_p,
        "n_zero_discordant_comparisons": len(zero_discordant),
        "zero_discordant_comparisons": zero_discordant,
        "rule": ("pilot scale: NO p in this file is a significance claim; "
                 "every comparison with 0 discordant pairs yields p=1.0 by "
                 "construction and carries no information (Clopper-Pearson "
                 "upper bounds on the discordant rate remain wide); all "
                 "effects are reported as flip counts alongside rates "
                 "(AMENDMENT-6 A6.4 coarse-resolution rule)"),
    }

    return {
        "schema": "r12_defense_analysis/1.0",
        "status": "ok",
        "mock": mock,
        "date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "input_meta": meta,
        "unknown_arm_rows_ignored": unknown_arms,
        "registered_comparisons": [f"{a}__vs__{b}" for a, b in COMPARISONS],
        "two_directional_rule": ("restore-gain (0->1) and restore-loss (1->0) "
                                 "are both counted and both reported "
                                 "(AMENDMENT-6 both-directions rule)"),
        "descriptive_power": descriptive_power,
        "per_model": per_model,
        "pooled": pooled,
    }


# --------------------------------------------------------------------- CLI
def build_mock_records() -> list[dict]:
    """Hand-checked fixture: 1 model, 6 malicious + 4 benign, 3 arms.

    Ground truth (used by tests/test_r12_analysis.py, hand-computed):
      P0      detections {m1,m2,m3,m4}  recall 4/6; benign FP 0/4
      P2_nodef detections {m1,m2}       recall 2/6; benign FP 1/4 (b1)
      P2_D1   detections {m1,m2,m3}     recall 3/6; benign FP 0/4 (b1 repaired)
    """
    det = {
        P0:      {"m1": 1, "m2": 1, "m3": 1, "m4": 1, "m5": 0, "m6": 0,
                  "b1": 0, "b2": 0, "b3": 0, "b4": 0},
        P2_NODEF: {"m1": 1, "m2": 1, "m3": 0, "m4": 0, "m5": 0, "m6": 0,
                   "b1": 1, "b2": 0, "b3": 0, "b4": 0},
        P2_D1:   {"m1": 1, "m2": 1, "m3": 1, "m4": 0, "m5": 0, "m6": 0,
                  "b1": 0, "b2": 0, "b3": 0, "b4": 0},
    }
    conf = {1: 0.9, 0: 0.2}
    rows: list[dict] = [{
        "meta": {"fixture": "r12_defense_mock_v1", "mock": True,
                 "note": "built-in hand-checked fixture -- NEVER a real result"},
    }]
    for arm, truth in det.items():
        for sid, v in truth.items():
            rows.append({
                "sample_id": sid,
                "label": 1 if sid.startswith("m") else 0,
                "arm": arm if arm != P2_D1 else "P2_D1_stripped",  # exercise matcher
                "model_id": "mock-model",
                "status": "ANSWER",
                "parsed": {"vulnerable": v, "confidence": conf[v]},
                "vulnerable": v,
                "mock": True,
            })
    return rows


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--mock", action="store_true",
                    help="run the built-in hand-checked fixture (mock hygiene)")
    args = ap.parse_args(argv)

    if args.mock:
        records = build_mock_records()
        meta = records[0].get("meta")
        result = analyze_records(records[1:], meta, mock=True)
        out = args.out if args.out else MOCK_OUT
        if out.resolve() == DEFAULT_OUT.resolve() and args.out:
            raise SystemExit("refusing: mock output must not overwrite the "
                             "real analysis path (mock hygiene)")
        write_json(out, result)
        r = result["per_model"]["mock-model"]["restoration"]
        print(f"[MOCK] wrote {out}")
        print(f"[MOCK] recall P0={r['recall_P0']:.4f} "
              f"P2_nodef={r['recall_P2_nodef']:.4f} P2_D1={r['recall_P2_D1']:.4f}")
        print(f"[MOCK] restore_gain={r['restore_gain_flips']} "
              f"restore_loss={r['restore_loss_flips']}")
        return 0

    out = args.out if args.out else DEFAULT_OUT
    if not args.input.exists():
        payload = {
            "schema": "r12_defense_analysis/1.0",
            "status": "pending",
            "mock": False,
            "date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "input": str(args.input),
            "note": ("W1 defense batch not present yet -- NO numbers emitted "
                     "(pre-reg rule: pending, never fabricated). Re-run this "
                     "script after outputs/packguard/defense/defense_batch.jsonl "
                     "lands."),
        }
        write_json(out, payload)
        print(f"PENDING: {args.input} not found; wrote pending marker to {out}")
        return 0

    meta, records = read_batch(args.input)
    if not records:
        payload = {
            "schema": "r12_defense_analysis/1.0",
            "status": "pending",
            "mock": False,
            "date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "input": str(args.input),
            "note": "input exists but carries only a meta header -- no numbers "
                    "emitted (never fabricated)",
        }
        write_json(out, payload)
        print(f"PENDING: {args.input} has no record rows; wrote pending marker")
        return 0

    labels_fb: Optional[dict[str, int]] = None
    if FEATURES.exists():
        labels_fb = load_labels_from_features(FEATURES)
    result = analyze_records(records, meta, labels_fallback=labels_fb, mock=False)
    result["input"] = str(args.input)
    write_json(out, result)
    print(f"OK: analyzed {len(records)} rows from {args.input} -> {out}")
    for model, blk in result["per_model"].items():
        r = blk["restoration"]
        print(f"  {model}: recall P0={r['recall_P0']} "
              f"P2_nodef={r['recall_P2_nodef']} P2_D1={r['recall_P2_D1']} "
              f"gain={r['restore_gain_flips']} loss={r['restore_loss_flips']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
