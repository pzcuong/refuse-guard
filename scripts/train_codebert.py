#!/usr/bin/env python
"""Train the CodeBERT vulnerability classifier on the PrimeVul OFFICIAL train split.

Owner: agent A2 (Round 2). Wraps src/models/transformer_baseline.py.

What it does
  1. Builds (idempotently, seeded) the disclosed subsample:
       - train: ALL vulnerable + n_benign_train benign (default 40000)
       - val:   ALL vulnerable of the official valid split + benign fill to n_val_total
     Files + provenance meta are written under outputs/transformer/.
  2. Runs the fine-tune with weighted CE (pos_weight), cosine schedule,
     bf16 autocast on MPS, step-level checkpoints + resume.

Modes
  default          : prepare data (if missing) + full train (resumable)
  --speed-test N   : prepare + N optimizer steps -> sec/step + ETA, writes NOTHING
  --prepare-only   : just build the jsonl subsets + meta, then exit

Launch (nohup background; log + follow):
  HF_HOME=$PWD/models_dir/hf nohup .venv/bin/python scripts/train_codebert.py \
      --config configs/train_codebert.yaml > outputs/transformer/train.log 2>&1 &
  tail -f outputs/transformer/train.log
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

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.data.primevul import load_primevul  # noqa: E402
from src.models.transformer_baseline import TransformerBaseline  # noqa: E402


def _sha16(obj) -> str:
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str).encode()
    ).hexdigest()[:16]


def _write_jsonl(path: Path, records: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps({"sample_id": r["sample_id"], "func": r["func"],
                                "label": r["label"], "cwe": r.get("cwe"),
                                "project": r.get("project")}, ensure_ascii=False) + "\n")


def prepare_subsets(cfg: dict, out_dir: Path, benign_override: int | None = None) -> dict:
    """Build the seeded train/val jsonl subsets (idempotent) + provenance meta."""
    import yaml

    with (PROJECT_ROOT / cfg["_config_path"]).open("r", encoding="utf-8") as f:
        raw_yaml = yaml.safe_load(f) or {}
    cfg_hash = _sha16(raw_yaml)

    dcfg = cfg["data"]
    seed = int(dcfg["seed"])
    n_benign = int(benign_override or dcfg["n_benign_train"])
    n_val = int(dcfg["n_val_total"])

    train_file = out_dir / f"train_vul_all_benign_{n_benign}.jsonl"
    val_file = out_dir / f"valid_vul_all_total_{n_val}.jsonl"
    meta_file = out_dir / "train_meta.json"

    if train_file.exists() and val_file.exists() and meta_file.exists():
        meta = json.loads(meta_file.read_text(encoding="utf-8"))
        if meta.get("cfg_hash") == cfg_hash and meta.get("n_benign_train") == n_benign:
            print(f"[prepare] reusing existing subsets "
                  f"(train={train_file.name}, val={val_file.name})", flush=True)
            return {"train_path": str(train_file), "val_path": str(val_file), "meta": meta}

    t0 = time.perf_counter()
    train = load_primevul(dcfg["train_split"])
    valid = load_primevul(dcfg["valid_split"])
    print(f"[prepare] loaded splits in {time.perf_counter() - t0:.1f}s "
          f"(train={len(train)}, valid={len(valid)})", flush=True)

    rng = random.Random(seed)
    tr_vul = [r for r in train if r["label"] == 1]
    tr_ben = [r for r in train if r["label"] == 0]
    if n_benign > len(tr_ben):
        raise ValueError(f"requested {n_benign} benign > available {len(tr_ben)}")
    benign_pick = sorted(rng.sample(range(len(tr_ben)), n_benign))
    train_sub = [tr_ben[i] for i in benign_pick] + tr_vul
    rng2 = random.Random(seed)
    rng2.shuffle(train_sub)

    va_vul = [r for r in valid if r["label"] == 1]
    va_ben = [r for r in valid if r["label"] == 0]
    need_ben = max(0, n_val - len(va_vul))
    if need_ben > len(va_ben):
        need_ben = len(va_ben)  # disclose in meta
    ben_idx = sorted(random.Random(seed + 1).sample(range(len(va_ben)), need_ben))
    val_sub = va_vul + [va_ben[i] for i in ben_idx]
    random.Random(seed + 1).shuffle(val_sub)

    _write_jsonl(train_file, train_sub)
    _write_jsonl(val_file, val_sub)
    meta = {
        "date": datetime.now(timezone.utc).isoformat(),
        "cfg_hash": cfg_hash,
        "seed": seed,
        "source": "starsofchance/PrimeVul mirror (data/raw/primevul_hf), official splits",
        "train_split": dcfg["train_split"], "valid_split": dcfg["valid_split"],
        "n_benign_train": n_benign, "n_vul_train": len(tr_vul),
        "n_train_total": len(train_sub),
        "n_vul_valid": len(va_vul), "n_benign_valid": len(ben_idx),
        "n_val_total": len(val_sub),
        "sampling": "rng.sample(seed) over stable split order; shuffle with same seed",
        "train_path": train_file.name, "val_path": val_file.name,
        "imbalance_choice": "weighted CE pos_weight=n_benign/n_vul (not oversampling)",
    }
    meta_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"[prepare] train={len(train_sub)} (vul {len(tr_vul)} + ben {n_benign}), "
          f"val={len(val_sub)} (vul {len(va_vul)} + ben {len(ben_idx)})", flush=True)
    return {"train_path": str(train_file), "val_path": str(val_file), "meta": meta}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default="configs/train_codebert.yaml")
    ap.add_argument("--speed-test", type=int, default=None, metavar="N",
                    help="run N optimizer steps, report sec/step + ETA, write nothing")
    ap.add_argument("--prepare-only", action="store_true")
    ap.add_argument("--benign", type=int, default=None,
                    help="override data.n_benign_train (downgrade rule disclosure)")
    ap.add_argument("--no-resume", action="store_true")
    args = ap.parse_args()

    import yaml

    cfg_path = PROJECT_ROOT / args.config
    with cfg_path.open("r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    cfg["_config_path"] = str(cfg_path)
    out_dir = PROJECT_ROOT / cfg["data"]["out_dir"]
    out_dir.mkdir(parents=True, exist_ok=True)

    prep = prepare_subsets(cfg, out_dir, benign_override=args.benign)
    if args.prepare_only:
        print(json.dumps(prep["meta"], indent=2))
        return 0

    tb_cfg = dict(cfg["transformer_baseline"])
    if args.no_resume:
        tb_cfg["resume"] = False
    if args.speed_test:
        tb_cfg["speed_test_steps"] = int(args.speed_test)
    tb = TransformerBaseline(cfg=tb_cfg)
    result = tb.train(train_path=prep["train_path"], val_path=prep["val_path"])
    print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
