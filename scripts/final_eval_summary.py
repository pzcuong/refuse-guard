#!/usr/bin/env python
"""Aggregate the Round-3 A2 final numbers into one file (owner: A2).

Reads ONLY real outputs (no recomputation of model results):
  outputs/transformer/codebert_eval_{vd_s,pilot}_metrics.json
  models_dir/transformer_baseline/history.json + best/val_metrics.json
  outputs/transformer/fallback_threshold.json
  outputs/experiments/round3_e7/e7_fusion_results.json
  outputs/transformer/calibration/<model>/full_report.json

Writes: outputs/transformer/final_eval.json + final_eval.md
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUT = PROJECT_ROOT / "outputs/transformer"


def _load(path: Path) -> dict | None:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def main() -> int:
    vd = _load(OUT / "codebert_eval_vd_s_metrics.json")
    pilot = _load(OUT / "codebert_eval_pilot_metrics.json")
    history = _load(PROJECT_ROOT / "models_dir/transformer_baseline/history.json") or []
    val = _load(PROJECT_ROOT / "models_dir/transformer_baseline/best/val_metrics.json")
    tau = _load(OUT / "fallback_threshold.json")
    e7 = _load(PROJECT_ROOT / "outputs/experiments/round3_e7/e7_fusion_results.json")
    calib = {}
    for d in sorted((OUT / "calibration").glob("*/full_report.json")):
        r = _load(d)
        af = r.get("at_fit_thresholds", {})
        calib[r["model_id"]] = {
            "fit_thresholds": {k: r["fit_thresholds"][k] for k in
                               ("refusal_threshold", "lexical_floor")},
            "n": af.get("n"),
            "over_refusal_rate": af.get("over_refusal_rate"),
            "monitor_false_refusal_rate": af.get("monitor_false_refusal_rate"),
            "model_strong_refusal_rate": af.get("model_strong_refusal_rate"),
            "unsafe_compliance_rate": af.get("unsafe_compliance_rate"),
            "refusal_rate_overall": af.get("refusal_rate_overall"),
            "calibration_accuracy": af.get("calibration_accuracy"),
            "constraint_met": r.get("fit_thresholds", {}).get("constraint_met"),
            "source": str(d.relative_to(PROJECT_ROOT)),
        }

    final = {
        "date": datetime.now(timezone.utc).isoformat(),
        "generator": "scripts/final_eval_summary.py",
        "transformer_b4": {
            "checkpoint": "models_dir/transformer_baseline/best",
            "best_epoch": (val or {}).get("epoch"),
            "history": history,
            "final_eval_vd_s_arm": vd,
            "final_eval_pilot_arm": pilot,
        },
        "fallback_threshold": tau,
        "e7_fusion": e7,
        "refusal_monitor_calibration": calib,
        "literature_reference": {
            "source": "Ding et al., arXiv:2403.18624v2 (ICSE 2025), Table V, CodeBERT Train=PV Test=PV",
            "accuracy": 96.87, "f1": 20.86, "vd_s_fnr_at_fpr_le_0.5pct": 88.78,
            "p_c": 1.77, "p_v": 11.35, "p_b": 86.17, "p_r": 0.71,
            "note": "VD-S in the paper IS the FNR at FPR<=0.5% (lower is better); "
                    "our repo metric vd_s follows the same definition.",
        },
    }
    (OUT / "final_eval.json").write_text(json.dumps(final, indent=2), encoding="utf-8")

    md = ["# RefuseGuard — B4 CodeBERT final eval + E7 fusion + calibration (Round 3, A2)", ""]
    if vd:
        m = vd["metrics"]
        md += ["## 1. B4 CodeBERT — official test split (v0.1 mirror)", "",
               f"Corpus: {vd['meta']['corpus']}. Device: {vd['meta']['device']}. "
               f"Operating threshold @FPR<=0.5%: {vd['meta']['operating_threshold_fpr0.005']}.", "",
               "| metric | value |", "|---|---|",
               f"| recall@0.5 | {m['recall@0.5']:.4f} |",
               f"| f1@0.5 | {m['f1@0.5']:.4f} |",
               f"| mcc@0.5 | {m['mcc@0.5']:.4f} |",
               f"| auc | {m['auc']:.4f} |",
               f"| accuracy@0.5 | {m['accuracy@0.5']:.4f} |",
               f"| VD-S (FNR@FPR<=0.5%, lower=better) | {m['vd_s']:.4f} |"]
        p = m.get("paired", {})
        if p:
            md += ["", f"Paired (official test_paired, n={p.get('n_pairs')} pairs): "
                   f"P-C={p.get('p_c_both_correct@0.5')}, P-V={p.get('p_v_both_vulnerable@0.5')}, "
                   f"P-B={p.get('p_b_both_benign@0.5')}, P-R={p.get('p_r_inverse@0.5')}."]
    if pilot:
        m = pilot["metrics"]
        md += ["", "## 2. B4 CodeBERT — pilot manifest v2 subset", "",
               f"Corpus: {pilot['meta']['corpus']}", "",
               f"recall@0.5={m['recall@0.5']}, f1@0.5={m['f1@0.5']}, mcc@0.5={m['mcc@0.5']}, "
               f"auc={m['auc']}, vd_s(small-n caveat)={m['vd_s']}, "
               f"paired in-subset n={m.get('paired', {}).get('n_pairs')}.",
               "", "## 3. Comparison vs PrimeVul paper (CodeBERT PV/PV, Table V)", "",
               "paper: Acc 96.87 / F1 20.86 / VD-S(FNR@FPR<=0.5%) 88.78 / P-C 1.77 — "
               "see final_eval.json literature_reference."]
    if tau:
        md += ["", f"## 4. Fallback threshold tau (VALID split) = {tau['tau']} "
               f"(MCC {tau['tau_mcc_on_valid']})"]
    if e7:
        md += ["", "## 5. E7 fusion/fallback", "",
               json.dumps({m: v["overall"] for m, v in e7["ablations"].items()}, indent=1),
               "", f"Coverage gain: {json.dumps(e7['coverage_gain'])}"]
    if calib:
        md += ["", "## 6. Refusal-monitor calibration finals", "",
               json.dumps(calib, indent=1, ensure_ascii=False)]
    (OUT / "final_eval.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"[final_eval] wrote {OUT / 'final_eval.json'} + .md", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
