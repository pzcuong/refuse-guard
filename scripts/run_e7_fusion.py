#!/usr/bin/env python
"""E7 refusal-recovery pilot: LLM -> transformer-prior fallback (owner: A2 R3).

Evaluates the PRE-REGISTERED fusion policy (configs/fusion_policy.yaml) on the
Round-2 pilot E3 records (outputs/experiments/pilot_round2_recomputed/0.5b/e3),
REUSING the recorded LLM outputs — no LLM is called. CodeBERT scores are
computed locally (MPS/CPU) on the exact func text each record's pipeline used:
the original function for C0, the reconstructed conditioned variant for
C2a/C2b/C3 (same apply_condition calls as the Round-2 runner).

Ablations: b4_only | llm_only | llm_then_fallback (PRIMARY) | score_fusion.
Coverage gain = UAC(llm_then_fallback) - UAC(llm_only).
Safety scope check: every E8 CONTRAST record must be REFUSED by the policy
scope guard (FusionScopeError) — the fallback can never touch safety prompts.

Usage:
  HF_HOME=$PWD/models_dir/hf .venv/bin/python scripts/run_e7_fusion.py [--device mps]

Outputs -> outputs/experiments/round3_e7/e7_fusion_results.json + .md
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import copy  # noqa: E402

from src.conditions.generator import (  # noqa: E402
    apply_condition,
    load_config as load_conditions_config,
)
from src.conditions.parser_utils import resolve_language  # noqa: E402
from src.data.primevul import load_primevul  # noqa: E402
from src.metrics.metrics import extract_verdict_fields, is_usable  # noqa: E402
from src.models.fusion_policy import (  # noqa: E402
    FusionPolicy,
    FusionScopeError,
    load_policy_config,
)
from src.models.llm_harness import extract_json  # noqa: E402
from src.models.transformer_baseline import TransformerBaseline  # noqa: E402

E3_PATH = PROJECT_ROOT / "outputs/experiments/pilot_round2_recomputed/0.5b/e3/results.json"
E8_PATHS = [PROJECT_ROOT / "outputs/experiments/pilot_round2_recomputed/0.5b/e8/results.json",
            PROJECT_ROOT / "outputs/experiments/pilot_round2_recomputed/3b_qwen/e8/results.json"]
TAU_PATH = PROJECT_ROOT / "outputs/transformer/fallback_threshold.json"
OUT_DIR = PROJECT_ROOT / "outputs/experiments/round3_e7"
CONDITIONS_YAML = "configs/conditions.yaml"


def _pinned(ccfg: dict, condition: str, pin: dict) -> dict:
    out = copy.deepcopy(ccfg)
    out.setdefault(condition, {})["pin"] = pin
    return out


def reconstruct_func(record: dict, by_id: dict, ccfg: dict) -> str | None:
    """Rebuild the exact func text the record's pipeline analyzed."""
    s = by_id.get(record["sample_id"])
    if s is None:
        return None
    cname = record["condition"]
    base = "C2" if cname.startswith("C2") else ("C0" if cname == "C0" else "C3")
    cfg = ccfg
    if cname == "C2a":
        cfg = _pinned(ccfg, "C2", {"carrier": "top_comment", "position": "near"})
    elif cname == "C2b":
        cfg = _pinned(ccfg, "C2", {"carrier": "string_literal_tail", "position": "near"})
    try:
        cond = apply_condition(s, base, cfg)
        return cond.get("func")
    except ValueError:
        return None


def llm_confidence(record: dict) -> float | None:
    """Recover the LLM's self-reported confidence from the persisted raw text."""
    p = record.get("raw_output_path")
    if not p:
        return None
    f = PROJECT_ROOT / p
    if not f.exists():
        return None
    try:
        obj, _err = extract_json(f.read_text(encoding="utf-8"))
        conf = (obj or {}).get("confidence")
        return float(conf) if isinstance(conf, (int, float)) else None
    except Exception:
        return None


def classify_metrics(rows: list[dict]) -> dict:
    """UAC / recall / F1 / MCC over policy-decided rows (y_pred may be None
    for llm_only unusable records — excluded from recall denominators)."""
    from sklearn.metrics import f1_score, matthews_corrcoef, recall_score

    n = len(rows)
    usable = [r for r in rows if r.get("usable_out")]
    decided = [r for r in usable if r.get("y_out") is not None]
    yt = [r["y_true"] for r in decided]
    yp = [r["y_out"] for r in decided]
    both = len(yt) > 0 and len(set(yt)) > 1 and len(set(yp)) > 1
    return {
        "n": n,
        "uac": round(len(usable) / n, 4) if n else None,
        "n_decided": len(decided),
        "recall": round(float(recall_score(yt, yp, zero_division=0)), 4) if both else None,
        "f1": round(float(f1_score(yt, yp, zero_division=0)), 4) if both else None,
        "mcc": round(float(matthews_corrcoef(yt, yp)), 4) if both else None,
        "n_fallback_used": sum(1 for r in rows if r.get("fallback_source") == "transformer"),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--device", default=None, help="override CodeBERT device")
    ap.add_argument("--max-new-tokens-dummy", type=int, default=None, help=argparse.SUPPRESS)
    args = ap.parse_args()

    pol_cfg = load_policy_config()
    tau_rec = json.loads(TAU_PATH.read_text(encoding="utf-8"))
    tau = float(tau_rec["tau"])
    policy = FusionPolicy(tau=tau)
    print(f"[e7] pre-registered policy={pol_cfg['policy']['name']} tau={tau} "
          f"(fitted on valid, MCC={tau_rec['tau_mcc_on_valid']})", flush=True)

    e3 = json.loads(E3_PATH.read_text(encoding="utf-8"))
    records = [r for r in e3["records"] if r["status"] != "SKIPPED"]
    n_skipped = len(e3["records"]) - len(records)
    by_id = {r["sample_id"]: r for r in load_primevul("test")}
    ccfg = load_conditions_config(CONDITIONS_YAML)

    # -- CodeBERT scores on the exact analyzed texts ------------------------
    texts, keys = [], []
    for r in records:
        func = reconstruct_func(r, by_id, ccfg)
        if func is None:
            r["_bert"] = None
            continue
        texts.append(func)
        keys.append(r)
    import yaml
    with (PROJECT_ROOT / "configs/train_codebert.yaml").open("r", encoding="utf-8") as f:
        tcfg = yaml.safe_load(f)
    if args.device:
        tcfg["transformer_baseline"]["device"] = args.device
    tb = TransformerBaseline(cfg=dict(tcfg["transformer_baseline"]))
    t0 = time.perf_counter()
    scores = tb.predict(texts)
    bert_seconds = round(time.perf_counter() - t0, 1)
    for r, sc in zip(keys, scores):
        r["_bert"] = float(sc)
    n_no_func = sum(1 for r in records if r["_bert"] is None)
    print(f"[e7] CodeBERT scored {len(keys)}/{len(records)} records in {bert_seconds}s", flush=True)

    # -- attach LLM-side info ----------------------------------------------
    for r in records:
        r["_llm_usable"] = bool(is_usable(r) and r.get("y_pred") is not None)
        r["_confidence"] = llm_confidence(r)

    # -- ablations ----------------------------------------------------------
    def run_ablation(mode: str) -> dict:
        rows = []
        for r in records:
            if r["_bert"] is None:
                continue  # excluded universe (no func text) — disclosed
            if mode == "b4_only":
                d = policy.b4_only(r["_bert"])
                usable_out = True
            elif mode == "llm_only":
                usable_out = r["_llm_usable"]
                d = {"y_pred": int(r["y_pred"]) if r.get("y_pred") is not None else None,
                     "fallback_source": "llm" if usable_out else None, "fused": False}
            elif mode == "llm_then_fallback":
                d = policy.decide(r, r["_bert"])
                usable_out = True  # a prior verdict always exists post-policy
            elif mode == "score_fusion":
                r2 = dict(r)
                r2["confidence"] = r["_confidence"]
                d = policy.score_fusion(r2, r["_bert"])
                usable_out = True
            else:
                raise ValueError(mode)
            rows.append({"sample_id": r["sample_id"], "condition": r["condition"],
                         "y_true": int(r["y_true"]), "y_out": d["y_pred"],
                         "usable_out": usable_out,
                         "fallback_source": d["fallback_source"]})
        overall = classify_metrics(rows)
        per_cond = {c: classify_metrics([x for x in rows if x["condition"] == c])
                    for c in sorted({x["condition"] for x in rows})}
        return {"overall": overall, "per_condition": per_cond, "rows": rows}

    ablations = {m: run_ablation(m) for m in
                 ("b4_only", "llm_only", "llm_then_fallback", "score_fusion")}
    gain = round(ablations["llm_then_fallback"]["overall"]["uac"]
                 - ablations["llm_only"]["overall"]["uac"], 4)
    gain_per_cond = {c: round(ablations["llm_then_fallback"]["per_condition"][c]["uac"]
                              - ablations["llm_only"]["per_condition"][c]["uac"], 4)
                     for c in ablations["llm_then_fallback"]["per_condition"]}

    # -- safety scope check on REAL E8 records ------------------------------
    scope_check = {}
    for p in E8_PATHS:
        if not p.exists():
            scope_check[p.name] = "missing"
            continue
        e8 = json.loads(p.read_text(encoding="utf-8"))
        blocked = attempted = 0
        for r in e8["records"]:
            try:
                policy.decide(r, 0.9)  # would-be fallback score
                attempted += 1  # policy accepted -> violation
            except FusionScopeError:
                blocked += 1
            except ValueError:
                pass  # in-scope but no score — not a scope failure
            except Exception:
                attempted += 1
        scope_check[str(p.relative_to(PROJECT_ROOT))] = {
            "n_records": len(e8["records"]), "scope_blocked": blocked,
            "reached_fallback": attempted}

    # -- persist -------------------------------------------------------------
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    result = {
        "date": datetime.now(timezone.utc).isoformat(),
        "policy": {
            "name": pol_cfg["policy"]["name"],
            "pre_registered_config": "configs/fusion_policy.yaml",
            "tau": tau, "tau_source": tau_rec["tau_rule"],
            "tau_valid_mcc": tau_rec["tau_mcc_on_valid"],
            "scope_allowed_conditions": list(policy.allowed_conditions),
        },
        "inputs": {
            "e3_records": str(E3_PATH.relative_to(PROJECT_ROOT)),
            "n_records_total": len(e3["records"]),
            "n_skipped_excluded": n_skipped,
            "n_in_universe": sum(1 for r in records if r["_bert"] is not None),
            "n_excluded_no_func": n_no_func,
            "llm_model": e3["metadata"].get("model_id", e3["metadata"]),
            "no_llm_called": True,
        },
        "codebert": {"predict_seconds": bert_seconds,
                     "checkpoint": "models_dir/transformer_baseline/best"},
        "ablations": {m: {"overall": v["overall"], "per_condition": v["per_condition"]}
                      for m, v in ablations.items()},
        "coverage_gain": {"overall": gain, "per_condition": gain_per_cond,
                          "definition": "UAC(llm_then_fallback) - UAC(llm_only)"},
        "safety_scope_check": scope_check,
    }
    (OUT_DIR / "e7_fusion_results.json").write_text(json.dumps(result, indent=2),
                                                    encoding="utf-8")
    (OUT_DIR / "e7_fusion_rows.jsonl").write_text(
        "\n".join(json.dumps({**r, "_bert_score": r.get("_bert")}, ensure_ascii=False)
                  for r in records) + "\n", encoding="utf-8")

    # -- markdown table ------------------------------------------------------
    lines = ["# E7 fusion/fallback pilot (Round 3, A2)", "",
             f"Policy: `{pol_cfg['policy']['name']}`, tau={tau:.4f} "
             f"(valid-split argmax MCC={tau_rec['tau_mcc_on_valid']:.4f}); "
             f"LLM outputs reused from Round-2 recompute (no LLM called).", "",
             "| arm | UAC | recall | F1 | MCC | n fallback |", "|---|---|---|---|---|---|"]
    for m, v in ablations.items():
        o = v["overall"]
        lines.append(f"| {m} | {o['uac']} | {o['recall']} | {o['f1']} | {o['mcc']} "
                     f"| {o['n_fallback_used']} |")
    lines += ["", f"Coverage gain (UAC fallback - UAC llm_only): overall **{gain}**, "
              f"per condition {json.dumps(gain_per_cond)}.", "",
              "Safety scope: " + json.dumps(
                  {k: (v if isinstance(v, str) else
                       f"{v['scope_blocked']}/{v['n_records']} blocked, "
                       f"{v['reached_fallback']} reached fallback")
                   for k, v in scope_check.items()}, ensure_ascii=False)]
    (OUT_DIR / "e7_fusion_results.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({m: v["overall"] for m, v in ablations.items()}, indent=1), flush=True)
    print(f"[e7] wrote {OUT_DIR / 'e7_fusion_results.json'}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
