#!/usr/bin/env python
"""Evaluate the fine-tuned CodeBERT vulnerability classifier (owner: A2, Round 2).

Arms
  vd_s   (default): official PrimeVul-style eval — ALL vulnerable of the test
         split + a seeded benign subsample (default 20000) -> VD-S
         (= FNR @ FPR<=0.5%, official definition), plus recall/F1/MCC/AUC @0.5.
  pilot: eval-pilot manifest subset (eval_subset_v2.json when present, else
         eval_subset_v1.json), funcs joined from the raw test split by
         sample_id; same metrics (VD-S caveat: benign n small).

Outputs -> outputs/transformer/ : predictions JSONL + parquet, metrics JSON,
all with full metadata (checkpoint path, config hash, seed, date).

Dry-run (pipeline check only, while training still runs):
  .venv/bin/python scripts/eval_codebert.py --arm vd_s --limit 200 --device cpu

Full run AFTER training completes:
  HF_HOME=$PWD/models_dir/hf .venv/bin/python scripts/eval_codebert.py --arm vd_s
  HF_HOME=$PWD/models_dir/hf .venv/bin/python scripts/eval_codebert.py --arm pilot
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.data.primevul import load_primevul  # noqa: E402
from src.metrics.metrics import vd_s  # noqa: E402
from src.models.transformer_baseline import TransformerBaseline  # noqa: E402

MANIFEST_PRIORITY = ["eval_subset_v2", "eval_subset_v1"]  # v2 when A1 emits it


def _sha16(obj) -> str:
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str).encode()
    ).hexdigest()[:16]


def _classification_metrics(y_true: list[int], scores: list[float]) -> dict:
    from sklearn.metrics import f1_score, matthews_corrcoef, recall_score, roc_auc_score

    preds = [int(s >= 0.5) for s in scores]
    out = {
        "n": len(y_true), "n_vulnerable": int(sum(y_true)),
        "n_benign": int(len(y_true) - sum(y_true)),
        "recall@0.5": float(recall_score(y_true, preds, zero_division=0)),
        "f1@0.5": float(f1_score(y_true, preds, zero_division=0)),
        "mcc@0.5": float(matthews_corrcoef(y_true, preds)) if len(set(y_true)) > 1 else None,
        "auc": float(roc_auc_score(y_true, scores)) if len(set(y_true)) > 1 else None,
        "accuracy@0.5": float(sum(int(p == t) for p, t in zip(preds, y_true)) / len(y_true)),
    }
    out["vd_s"] = float(vd_s(y_true, scores)) if len(set(y_true)) > 1 else None
    return out


def load_pilot_samples(limit: int | None) -> tuple[list[dict], str]:
    """Pilot manifest records (funcs joined from the raw test split)."""
    man_name = None
    man = None
    for name in MANIFEST_PRIORITY:
        p = PROJECT_ROOT / "data" / "manifests" / f"{name}.json"
        if p.exists():
            man = json.loads(p.read_text(encoding="utf-8"))
            man_name = name
            break
    if man is None:
        raise FileNotFoundError("no eval_subset_v2/v1 manifest under data/manifests/")
    ids = man.get("sample_ids", {})
    wanted: list[str] = []
    for key in ("vulnerable", "benign"):
        wanted.extend(str(s) for s in ids.get(key, []))
    if not wanted:  # runner-style manifest: flat list
        wanted = [str(s) for s in (man.get("samples") or man.get("records") or [])]
    by_id = {r["sample_id"]: r for r in load_primevul("test")}
    samples = [by_id[i] for i in wanted if i in by_id]
    missing = len(wanted) - len(samples)
    if limit:
        samples = samples[:limit]
    return samples, f"manifest:{man_name} (joined from raw test split; missing_ids={missing})"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default="configs/train_codebert.yaml")
    ap.add_argument("--arm", choices=["vd_s", "pilot"], default="vd_s")
    ap.add_argument("--limit", type=int, default=None,
                    help="cap total samples (dry-run; NOT for reported results)")
    ap.add_argument("--device", default=None, help="override device (e.g. cpu for dry-run)")
    ap.add_argument("--benign-test-n", type=int, default=None,
                    help="override eval.benign_test_subsample")
    args = ap.parse_args()

    with (PROJECT_ROOT / args.config).open("r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    ecfg = dict(cfg.get("eval", {}))
    if args.benign_test_n is not None:
        ecfg["benign_test_subsample"] = args.benign_test_n
    seed = int(ecfg.get("seed", 1234))
    out_dir = PROJECT_ROOT / ecfg.get("out_dir", "outputs/transformer")
    out_dir.mkdir(parents=True, exist_ok=True)

    # --- checkpoint must be a fine-tuned one ------------------------------
    ckpt_dir = PROJECT_ROOT / cfg["transformer_baseline"]["output_dir"] / "best"
    if not ckpt_dir.exists():
        print(f"[abort] no fine-tuned checkpoint at {ckpt_dir}; train first "
              "(scripts/train_codebert.py). Refusing to eval a random head.", flush=True)
        return 2

    # --- build the eval sample list ---------------------------------------
    t0 = time.perf_counter()
    if args.arm == "pilot":
        samples, corpus = load_pilot_samples(args.limit)
        n_benign_used = None
    else:
        test = load_primevul("test")
        vul = [r for r in test if r["label"] == 1]
        ben_all = [r for r in test if r["label"] == 0]
        n_benign = int(args.benign_test_n or ecfg.get("benign_test_subsample", 20000))
        n_benign = min(n_benign, len(ben_all))
        idx = sorted(random.Random(seed).sample(range(len(ben_all)), n_benign))
        ben = [ben_all[i] for i in idx]
        samples = vul + ben
        if args.limit:
            half = min(args.limit // 2, len(vul))
            samples = vul[:half] + ben[: args.limit - half]
        corpus = (f"official test split: ALL vulnerable (n={len(vul)}) + seeded benign "
                  f"subsample n={len(ben)} (rng.sample, seed={seed})")
    print(f"[eval] arm={args.arm} n={len(samples)} corpus={corpus} "
          f"(loaded in {time.perf_counter() - t0:.1f}s)", flush=True)

    # --- predict -----------------------------------------------------------
    tb_cfg = dict(cfg["transformer_baseline"])
    if args.device:
        tb_cfg["device"] = args.device
    tb = TransformerBaseline(cfg=tb_cfg)
    t1 = time.perf_counter()
    scores = tb.predict([s["func"] for s in samples])
    y = [int(s["label"]) for s in samples]
    print(f"[eval] predicted {len(samples)} in {time.perf_counter() - t1:.1f}s "
          f"({len(samples) / max(1e-9, time.perf_counter() - t1):.1f} samp/s)", flush=True)

    metrics = _classification_metrics(y, scores)
    metrics["vd_s_definition"] = "FNR at the operating point with largest FPR <= 0.005"
    meta = {
        "date": datetime.now(timezone.utc).isoformat(),
        "arm": args.arm,
        "limit": args.limit,
        "checkpoint": str(ckpt_dir.relative_to(PROJECT_ROOT)),
        "checkpoint_metrics": json.loads(
            (ckpt_dir / "val_metrics.json").read_text(encoding="utf-8")
        ) if (ckpt_dir / "val_metrics.json").exists() else None,
        "corpus": corpus,
        "seed": seed,
        "device": tb_cfg["device"],
        "model_name": tb_cfg["model_name"],
        "config_sha16": _sha16(cfg),
        "is_dry_run": bool(args.limit),
    }
    result = {"metrics": metrics, "meta": meta}
    suffix = f"_dry{args.limit}" if args.limit else ""
    (out_dir / f"codebert_eval_{args.arm}{suffix}_metrics.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8")

    pred_path = out_dir / f"codebert_predictions_{args.arm}{suffix}.jsonl"
    with pred_path.open("w", encoding="utf-8") as f:
        for s, sc in zip(samples, scores):
            f.write(json.dumps({
                "sample_id": s["sample_id"], "label": int(s["label"]),
                "score_vulnerable": round(float(sc), 6), "cwe": s.get("cwe"),
                "project": s.get("project"),
            }, ensure_ascii=False) + "\n")
    try:
        pd.read_json(pred_path, lines=True).to_parquet(
            out_dir / f"codebert_predictions_{args.arm}{suffix}.parquet", index=False)
        pq = f" + .parquet"
    except Exception as e:  # parquet optional, jsonl is canonical
        pq = f" (parquet skipped: {e})"
    print(json.dumps(result, indent=2), flush=True)
    print(f"[eval] wrote {pred_path.name}{pq}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
