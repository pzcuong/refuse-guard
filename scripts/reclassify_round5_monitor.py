#!/usr/bin/env python
"""Round-10: reclassify round5_defense records under models.yaml thresholds.

Defense runs mixed thresholds mid-flight (old 0.0/0.2 fit vs round-10 free-text
fit 0.0/0.7 and 0.0/0.3). This re-reads every non-SKIPPED raw output, applies
the CURRENT per-model thresholds from configs/models.yaml, updates status /
y_pred / taxonomy / meta scores, and recomputes metrics for non-partial files.

0 LLM calls. Safe to re-run (idempotent under fixed thresholds).

Usage:
  .venv/bin/python scripts/reclassify_round5_monitor.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.experiments.round5_defense import (  # noqa: E402
    compute_metrics_r5d,
    load_config,
    resolve_thresholds,
)
from src.models.refusal_monitor import RefusalMonitor  # noqa: E402
from src.experiments.round5_e0v2 import classify_output, refusal_taxonomy  # noqa: E402

MODEL_SLUGS = {
    "Qwen/Qwen2.5-Coder-3B-Instruct": "qwen3b",
    "unsloth/Llama-3.2-3B-Instruct": "llama3b",
}


def _monitor_for(model_id: str) -> RefusalMonitor:
    thr, _src = resolve_thresholds(
        {"monitor": {"fallback_thresholds": {  # unused when models.yaml has entry
            "refusal_threshold": 0.0, "lexical_floor": 0.2}}},
        model_id,
    )
    return RefusalMonitor(
        refusal_threshold=thr["refusal_threshold"],
        lexical_floor=thr["lexical_floor"],
    )


def _classify_output(mon: RefusalMonitor, text: str, required: list[str]):
    return classify_output(mon, text, required)


def reclassify_file(path: Path, cfg: dict, required: list[str]) -> dict:
    d = json.loads(path.read_text(encoding="utf-8"))
    md = d.get("metadata", {})
    model_id = md.get("model_id")
    if not model_id:
        raise RuntimeError(f"{path.name}: missing model_id")
    mon = _monitor_for(model_id)
    thr = {"refusal_threshold": mon.refusal_threshold,
           "lexical_floor": mon.lexical_floor}
    n_changed = 0
    for rec in d.get("records", []):
        if rec.get("status") == "SKIPPED":
            continue
        raw = ROOT / rec["raw_output_path"]
        if not raw.exists():
            raise FileNotFoundError(raw)
        text = raw.read_text(encoding="utf-8")
        status, y_pred, extras = _classify_output(mon, text, required)
        meta = rec.setdefault("meta", {})
        # P3R / transformer fallback: keep pipeline analysis_status if set
        if meta.get("fallback_source") == "transformer_prior":
            analysis = "TRANSFORMER_FALLBACK"
            y_pred = rec.get("y_pred", y_pred)
        else:
            analysis = status
        if status != rec.get("status") or y_pred != rec.get("y_pred"):
            n_changed += 1
        rec["status"] = status
        rec["y_pred"] = y_pred
        rec["analysis_status"] = analysis
        rec["cwe"] = extras.get("pred_cwe")
        rec["location"] = extras.get("pred_location")
        meta["monitor_thresholds"] = dict(thr)
        meta["final_refusal_score"] = extras.get("refusal_score")
        for k in ("refusal_score", "lexical_score", "has_json", "missing_fields"):
            if k in extras:
                meta[k] = extras[k]
        rec["taxonomy"] = refusal_taxonomy(
            {**rec, "meta": {**meta, "text": text}}
        )
    md["monitor_thresholds"] = thr
    md["reclassified_round10"] = True
    partial = bool(md.get("partial"))
    if not partial:
        d["metrics"] = compute_metrics_r5d(d["records"], cfg)
    path.write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "file": path.name,
        "model_id": model_id,
        "n": len(d.get("records", [])),
        "n_changed": n_changed,
        "partial": partial,
        "thresholds": thr,
        "metrics_recomputed": not partial,
    }


def main() -> int:
    cfg = load_config(ROOT / "configs/round5_defense.yaml")
    required = list((cfg.get("monitor") or {}).get(
        "required_fields", ["vulnerable", "cwe", "location"]))
    out_dir = ROOT / cfg["out_dir"]
    reports = []
    for path in sorted(out_dir.glob("results_*.json")):
        rep = reclassify_file(path, cfg, required)
        reports.append(rep)
        print(
            f"[reclass] {rep['file']}: changed={rep['n_changed']}/{rep['n']} "
            f"thr={rep['thresholds']} metrics={rep['metrics_recomputed']}",
            flush=True,
        )
    summary = ROOT / out_dir / "reclassify_round10.json"
    summary.write_text(json.dumps(
        {"reports": reports}, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[reclass] wrote {summary.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
