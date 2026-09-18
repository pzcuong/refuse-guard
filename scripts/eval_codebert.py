#!/usr/bin/env python
"""Evaluate the fine-tuned CodeBERT vulnerability classifier (owner: A2, Round 2).

Arms
  vd_s   (default): official PrimeVul-style eval — ALL vulnerable of the test
         split + a seeded benign subsample (default 20000) -> VD-S
         (= FNR @ FPR<=0.5%, official definition), plus recall/F1/MCC/AUC @0.5.
         Additionally predicts ALL of the official test_paired split (435
         consecutive vulnerable/patched pairs) -> paired detection metrics
         (both-members-correct rate, the paper's "paired accuracy/VD-S" family).
  pilot: eval-pilot manifest subset (eval_subset_v2.json when present, else
         eval_subset_v1.json), funcs joined from the raw test split by
         sample_id; same metrics (VD-S caveat: benign n small). Paired metrics
         restricted to the manifest's in-subset pairs (both members present).

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
from src.metrics.metrics import (  # noqa: E402
    operating_threshold,
    paired_detection_score,
    paired_rank_accuracy,
    vd_s,
)
from src.models.transformer_baseline import TransformerBaseline  # noqa: E402

MANIFEST_PRIORITY = ["eval_subset_v2", "eval_subset_v1"]  # v2 when A1 emits it


def _paired_metrics(vul_scores: list[float], patched_scores: list[float],
                    threshold: float) -> dict:
    """Paired detection metrics over aligned (vulnerable, patched) scores.

    p_c/p_v/p_b/p_r follow the PrimeVul pair-wise outcome definitions
    (arXiv:2403.18624 Table V): P-C both members correct, P-V both predicted
    vulnerable, P-B both predicted benign, P-R inverse-predicted."""
    n = len(vul_scores)
    pc = sum(1 for v, p in zip(vul_scores, patched_scores)
             if v >= 0.5 and p < 0.5)
    pv = sum(1 for v, p in zip(vul_scores, patched_scores)
             if v >= 0.5 and p >= 0.5)
    pb = sum(1 for v, p in zip(vul_scores, patched_scores)
             if v < 0.5 and p < 0.5)
    pr = sum(1 for v, p in zip(vul_scores, patched_scores)
             if v < 0.5 and p >= 0.5)
    r = lambda k: round(k / n, 6) if n else None  # noqa: E731
    return {
        "n_pairs": n,
        "p_c_both_correct@0.5": r(pc),
        "p_v_both_vulnerable@0.5": r(pv),
        "p_b_both_benign@0.5": r(pb),
        "p_r_inverse@0.5": r(pr),
        "paired_rank_accuracy": round(paired_rank_accuracy(vul_scores, patched_scores), 6) if n else None,
        "paired_detection_score@thr": (round(paired_detection_score(vul_scores, patched_scores, threshold), 6)
                                       if n else None),
        "paired_threshold": round(threshold, 6),
        "definition": ("pair-wise outcomes per PrimeVul (arXiv:2403.18624): P-C both correct; "
                       "paired_detection_score = both-correct at the FPR-constrained operating "
                       "threshold from the main eval set (VD-S family)"),
    }


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


def load_pilot_samples(limit: int | None) -> tuple[list[dict], str, list[tuple[str, str]]]:
    """Pilot manifest records (funcs joined from the raw test split).

    Returns (samples, corpus_desc, manifest_pairs) where manifest_pairs are
    (vulnerable_id, benign_id) restricted to pairs whose BOTH members are in
    the returned sample list (paired metrics are computed on those only)."""
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
    kept = {s["sample_id"] for s in samples}
    pairs = [(str(p["vulnerable"]), str(p["benign"]))
             for p in man.get("paired", [])
             if str(p["vulnerable"]) in kept and str(p["benign"]) in kept]
    return samples, f"manifest:{man_name} (joined from raw test split; missing_ids={missing})", pairs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default="configs/train_codebert.yaml")
    ap.add_argument("--arm", choices=["vd_s", "pilot"], default="vd_s")
    ap.add_argument("--limit", type=int, default=None,
                    help="cap total samples (dry-run; NOT for reported results)")
    ap.add_argument("--device", default=None, help="override device (e.g. cpu for dry-run)")
    ap.add_argument("--benign-test-n", type=int, default=None,
                    help="override eval.benign_test_subsample")
    ap.add_argument("--paired-only", action="store_true",
                    help="S round-3 (V1 bug 4): only re-predict the 870 "
                         "test_paired rows, PERSIST per-row scores to "
                         "codebert_predictions_paired.jsonl, and re-verify the "
                         "paired metrics against the stored vd_s metrics. "
                         "Light (~1 min); used because the original paired "
                         "inference was not persisted.")
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
    manifest_pairs: list[tuple[str, str]] = []
    if args.arm == "pilot":
        samples, corpus, manifest_pairs = load_pilot_samples(args.limit)
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

    # --- S round-3 --paired-only branch (persist what V1 said was missing) --
    if args.paired_only:
        if args.arm != "vd_s":
            print("[abort] --paired-only only implemented for --arm vd_s", flush=True)
            return 2
        tb_cfg = dict(cfg["transformer_baseline"])
        if args.device:
            tb_cfg["device"] = args.device
        tb = TransformerBaseline(cfg=tb_cfg)
        paired_rows = load_primevul("test_paired")
        t1 = time.perf_counter()
        p_scores = tb.predict([r["func"] for r in paired_rows])
        print(f"[eval] predicted {len(paired_rows)} paired rows in "
              f"{time.perf_counter() - t1:.1f}s", flush=True)
        pred_path = out_dir / "codebert_predictions_paired.jsonl"
        with pred_path.open("w", encoding="utf-8") as f:
            for r, sc in zip(paired_rows, p_scores):
                f.write(json.dumps({
                    "sample_id": r["sample_id"], "label": int(r["label"]),
                    "score_vulnerable": round(float(sc), 6),
                }, ensure_ascii=False) + "\n")
        vs = [p_scores[i] for i in range(0, len(paired_rows), 2)
              if paired_rows[i]["label"] == 1]
        ps = [p_scores[i] for i in range(1, len(paired_rows), 2)
              if paired_rows[i - 1]["label"] == 1]
        stored_path = out_dir / "codebert_eval_vd_s_metrics.json"
        stored = json.loads(stored_path.read_text(encoding="utf-8")) \
            if stored_path.exists() else None
        op_thr = (stored["meta"]["operating_threshold_fpr0.005"]
                  if stored else 0.5)
        paired = _paired_metrics(vs, ps, op_thr)
        result = {
            "metrics": {"paired": paired},
            "meta": {
                "date": datetime.now(timezone.utc).isoformat(),
                "arm": "vd_s_paired_only",
                "checkpoint": str(ckpt_dir.relative_to(PROJECT_ROOT)),
                "n_rows": len(paired_rows),
                "predictions_file": str(pred_path.relative_to(PROJECT_ROOT)),
                "op_threshold_source": ("stored codebert_eval_vd_s_metrics.json"
                                        if stored else "default 0.5"),
                "note": ("S round-3: per-pair scores persisted after V1 audit "
                         "found the original paired inference was not saved; "
                         "metrics recomputed from these scores must match the "
                         "stored vd_s paired block"),
            },
        }
        (out_dir / "codebert_eval_paired_only_metrics.json").write_text(
            json.dumps(result, indent=2), encoding="utf-8")
        if stored:
            old = stored["metrics"].get("paired", {})
            diffs = {k: (old.get(k), paired.get(k)) for k in old
                     if isinstance(old.get(k), float)
                     and abs((old.get(k) or 0) - (paired.get(k) or 0)) > 1e-6}
            print(f"[eval] paired recompute vs stored: "
                  f"{'IDENTICAL' if not diffs else diffs}", flush=True)
        print(f"[eval] wrote {pred_path}", flush=True)
        return 0

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

    # --- paired (vulnerable vs patched) section ---------------------------
    # Operating threshold from THIS eval set (FPR<=0.5% rule, same sweep as
    # vd_s); test-only data, nothing is fitted for the model itself.
    op_thr = operating_threshold(y, scores)
    if args.arm == "pilot":
        score_by_id = {s["sample_id"]: sc for s, sc in zip(samples, scores)}
        vs = [score_by_id[v] for v, b in manifest_pairs if v in score_by_id and b in score_by_id]
        ps = [score_by_id[b] for v, b in manifest_pairs if v in score_by_id and b in score_by_id]
        metrics["paired"] = _paired_metrics(vs, ps, op_thr) if vs else {"n_pairs": 0}
    else:
        paired_rows = load_primevul("test_paired")
        print(f"[eval] paired arm: predicting {len(paired_rows)} test_paired rows "
              f"(official consecutive vulnerable/patched pairs)", flush=True)
        p_scores = tb.predict([r["func"] for r in paired_rows])
        vs = [p_scores[i] for i in range(0, len(paired_rows), 2) if paired_rows[i]["label"] == 1]
        ps = [p_scores[i] for i in range(1, len(paired_rows), 2) if paired_rows[i - 1]["label"] == 1]
        metrics["paired"] = _paired_metrics(vs, ps, op_thr)

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
        "operating_threshold_fpr0.005": round(float(op_thr), 6),
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
