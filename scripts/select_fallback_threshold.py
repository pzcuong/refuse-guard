#!/usr/bin/env python
"""Fit the transformer-fallback threshold tau on the VALID split (owner: A2 R3).

Pre-registered rule (configs/fusion_policy.yaml): tau = argmax MCC over the
score grid on outputs/transformer/valid_vul_all_total_10000.jsonl — the same
official valid-split subsample used for early stopping in training (593 vul +
9,407 benign, seed 1234). NEVER fitted on test.

Usage:
  HF_HOME=$PWD/models_dir/hf .venv/bin/python scripts/select_fallback_threshold.py

Output: outputs/transformer/fallback_threshold.json (tau + full audit metadata).
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.metrics.metrics import best_mcc_threshold  # noqa: E402
from src.models.transformer_baseline import TransformerBaseline  # noqa: E402

VALID_PATH = PROJECT_ROOT / "outputs/transformer/valid_vul_all_total_10000.jsonl"
OUT_PATH = PROJECT_ROOT / "outputs/transformer/fallback_threshold.json"


def main() -> int:
    rows = [json.loads(l) for l in VALID_PATH.read_text(encoding="utf-8").splitlines() if l.strip()]
    n_vul = sum(1 for r in rows if int(r["label"]) == 1)
    print(f"[tau] valid subsample: n={len(rows)} (vul={n_vul}, benign={len(rows) - n_vul})", flush=True)

    import yaml
    with (PROJECT_ROOT / "configs/train_codebert.yaml").open("r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    tb = TransformerBaseline(cfg=dict(cfg["transformer_baseline"]))
    t0 = time.perf_counter()
    scores = tb.predict([r["func"] for r in rows])
    dt = time.perf_counter() - t0
    y = [int(r["label"]) for r in rows]
    fit = best_mcc_threshold(y, scores)

    out = {
        "date": datetime.now(timezone.utc).isoformat(),
        "tau": fit["threshold"],
        "tau_rule": "argmax MCC over score grid (src.metrics.metrics.best_mcc_threshold)",
        "tau_mcc_on_valid": fit["mcc"],
        "valid_set": {"path": str(VALID_PATH.relative_to(PROJECT_ROOT)),
                      "n": len(rows), "n_vulnerable": n_vul, "n_benign": len(rows) - n_vul},
        "checkpoint": "models_dir/transformer_baseline/best",
        "device": cfg["transformer_baseline"]["device"],
        "predict_seconds": round(dt, 1),
        "sha16_valid_path": hashlib.sha256(str(VALID_PATH).encode()).hexdigest()[:16],
        "note": "PRE-REGISTERED in configs/fusion_policy.yaml before this run; test data untouched.",
    }
    OUT_PATH.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
