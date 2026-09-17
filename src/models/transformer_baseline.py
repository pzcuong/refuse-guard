"""Transformer baseline B4: CodeBERT binary vulnerability classifier.

Contract (PROJECT_BRIEF §8):
    train(cfg) / TransformerBaseline().train(cfg)  -> fine-tune on PrimeVul-style records
    predict(texts: list[str]) -> list[float]        (prob vulnerable)

Design for M2 Pro / MPS (32GB):
- microsoft/codebert-base (roberta architecture, ungated), num_labels=2.
- max_seq_len from cfg (512, fallback 256 on MPS OOM), small batch + grad accum.
- Hand-rolled training loop (no transformers Trainer): explicit seed, MPS-friendly,
  full checkpoint/resume (model + optimizer + scheduler + epoch + best val MCC).
- Early stopping on validation MCC with patience cfg.epoch — logs recall/F1/MCC/AUC.
- `dry_run=True` runs 2 synthetic batches through forward+backward on MPS to
  prove the pipeline without real data (used in Round 1).

Record contract input (canonical BRIEF §8 record):
    {"sample_id": str, "func": str, "label": 0|1, ...}

Round 2 train command (real data, after src/data is done):
    HF_HOME=<root>/models_dir/hf .venv/bin/python -m src.models.transformer_baseline \
        --config configs/models.yaml --train data/manifests/train.jsonl \
        --val data/manifests/val.jsonl
"""
from __future__ import annotations

import importlib
import json
import math
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_CFG = {
    "model_name": "microsoft/codebert-base",
    "num_labels": 2,
    "max_seq_len": 512,
    "fallback_seq_len": 256,     # used automatically on MPS OOM
    "batch_size": 8,
    "grad_accum_steps": 4,       # effective batch 32
    "lr": 2.0e-5,
    "weight_decay": 0.01,
    "warmup_ratio": 0.06,
    "epochs": 3,
    "seed": 1234,
    "early_stopping_patience": 2,  # on val MCC
    "output_dir": "models_dir/transformer_baseline",
    "resume": True,
    "device": "mps",
    "dry_run": False,
    "max_train_samples": None,   # pilot scale knob
}


def _load_cfg(cfg: Optional[dict], config_path: Optional[str]) -> dict:
    merged = dict(DEFAULT_CFG)
    if config_path:
        import yaml

        with open(PROJECT_ROOT / config_path, "r", encoding="utf-8") as f:
            yaml_cfg = yaml.safe_load(f) or {}
        merged.update(yaml_cfg.get("transformer_baseline", {}) or {})
    merged.update(cfg or {})
    return merged


class TransformerBaseline:
    """CodeBERT-style binary vulnerability classifier (MPS-first)."""

    def __init__(self, cfg: Optional[dict] = None, config_path: Optional[str] = None):
        self.cfg = _load_cfg(cfg, config_path)
        self.output_dir = PROJECT_ROOT / self.cfg["output_dir"]
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.device = self.cfg["device"]
        self.model = None
        self.tokenizer = None

    # ------------------------------------------------------------------ setup
    def _lazy_load(self, seq_len: Optional[int] = None) -> None:
        if self.model is not None:
            return
        import torch
        import transformers as tf

        torch.manual_seed(self.cfg["seed"])
        name = self.cfg["model_name"]
        sl = seq_len or self.cfg["max_seq_len"]
        self.tokenizer = tf.AutoTokenizer.from_pretrained(name, model_max_length=sl)
        self.model = tf.AutoModelForSequenceClassification.from_pretrained(
            name, num_labels=int(self.cfg["num_labels"])
        ).to(self.device)
        self.model.eval()

    def _set_seed(self) -> None:
        import torch

        seed = int(self.cfg["seed"])
        random.seed(seed)
        torch.manual_seed(seed)
        if torch.backends.mps.is_available():
            torch.mps.manual_seed(seed)

    # ------------------------------------------------------------- data utils
    @staticmethod
    def _read_jsonl(path: str | Path) -> list[dict]:
        records = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records

    def _encode(self, texts: list[str]):
        """Tokenize a batch with head+tail truncation for over-long inputs.

        Strategy (audit round 1): CodeBERT is RoBERTa-base
        (max_position_embeddings=514 -> hard input cap of 512 tokens, i.e. the
        configured max_seq_len). Plain HF truncation keeps only the head, which
        silently discards the end of long functions (where vulnerable code
        often sits). Over-long inputs therefore keep the FIRST half and the
        LAST half of the budget with an explicit [SEP] between the halves;
        fitting inputs go through the standard tokenizer path untouched.
        """
        seq_len = int(self.cfg["max_seq_len"])
        tok = self.tokenizer
        rows_ids, any_long = [], False
        for t in texts:
            ids = tok(t, add_special_tokens=False)["input_ids"]
            if len(ids) > seq_len:
                any_long = True
                keep = seq_len - 3  # room for [CLS] + mid-[SEP] + [SEP]
                head = ids[: keep // 2]
                tail = ids[len(ids) - (keep - keep // 2):]
                ids = head + [tok.sep_token_id] + tail
            rows_ids.append(ids)
        if not any_long:
            return tok(
                texts,
                truncation=True,
                padding=True,
                max_length=seq_len,
                return_tensors="pt",
            )
        torch = importlib.import_module("torch")
        cls_id, sep_id = tok.cls_token_id, tok.sep_token_id
        pad_id = tok.pad_token_id or 0
        batch_max = min(seq_len, max(len(r) + 2 for r in rows_ids))
        input_ids, attention = [], []
        for r in rows_ids:
            row = [cls_id] + r[: seq_len - 2] + [sep_id]
            pad = batch_max - len(row)
            input_ids.append(row + [pad_id] * pad)
            attention.append([1] * len(row) + [0] * pad)
        return {
            "input_ids": torch.tensor(input_ids, dtype=torch.long),
            "attention_mask": torch.tensor(attention, dtype=torch.long),
        }

    # ---------------------------------------------------------------- train
    def train(self, train_path: Optional[str] = None, val_path: Optional[str] = None,
              cfg: Optional[dict] = None) -> dict:
        """Fine-tune. cfg override at call time. With cfg["dry_run"]=True no data
        is needed: 2 synthetic batches prove forward/backward/optimizer on MPS."""
        if cfg:
            self.cfg.update(cfg)
        self._set_seed()
        if self.cfg.get("dry_run"):
            return self._dry_run()

        import torch
        from sklearn.metrics import f1_score, matthews_corrcoef, recall_score, roc_auc_score

        train_recs = self._read_jsonl(train_path)
        val_recs = self._read_jsonl(val_path)
        if self.cfg.get("max_train_samples"):
            train_recs = train_recs[: int(self.cfg["max_train_samples"])]
        rng = random.Random(self.cfg["seed"])
        rng.shuffle(train_recs)

        self._lazy_load()
        model = self.model
        optimizer = torch.optim.AdamW(
            model.parameters(), lr=float(self.cfg["lr"]),
            weight_decay=float(self.cfg["weight_decay"]),
        )
        steps_per_epoch = math.ceil(len(train_recs) / (self.cfg["batch_size"] * self.cfg["grad_accum_steps"]))
        total_steps = max(1, steps_per_epoch * int(self.cfg["epochs"]))
        warmup = max(1, int(float(self.cfg["warmup_ratio"]) * total_steps))

        def lr_lambda(step: int) -> float:
            if step < warmup:
                return step / warmup
            return max(0.0, (total_steps - step) / max(1, total_steps - warmup))

        scheduler = torch.optim.lr_scheduler.LambdaLR(optimizer, lr_lambda)

        start_epoch, best_mcc, history = 0, -1.0, []
        state_path = self.output_dir / "checkpoint.pt"
        if self.cfg.get("resume") and state_path.exists():
            ck = torch.load(state_path, map_location=self.device, weights_only=False)
            model.load_state_dict(ck["model"])
            optimizer.load_state_dict(ck["optimizer"])
            scheduler.load_state_dict(ck["scheduler"])
            start_epoch, best_mcc, history = ck["epoch"] + 1, ck["best_mcc"], ck["history"]
            print(f"[resume] from epoch {start_epoch}, best_val_mcc={best_mcc:.4f}", flush=True)

        patience_left = int(self.cfg["early_stopping_patience"])
        for epoch in range(start_epoch, int(self.cfg["epochs"])):
            model.train()
            t0 = time.perf_counter()
            optimizer.zero_grad()
            step = 0
            losses = []
            for bstart in range(0, len(train_recs), int(self.cfg["batch_size"])):
                batch = train_recs[bstart : bstart + int(self.cfg["batch_size"])]
                enc = self._encode([b["func"] for b in batch]).to(self.device)
                labels = torch.tensor([int(b["label"]) for b in batch], device=self.device)
                try:
                    out = model(**enc, labels=labels)
                except RuntimeError as e:  # MPS OOM -> shrink sequence length
                    if "out of memory" in str(e).lower() or "MPS" in str(e):
                        self.cfg["max_seq_len"] = int(self.cfg["fallback_seq_len"])
                        print(f"[warn] OOM, falling back seq_len={self.cfg['max_seq_len']}", flush=True)
                        torch.mps.empty_cache() if torch.backends.mps.is_available() else None
                        enc = self._encode([b["func"] for b in batch]).to(self.device)
                        out = model(**enc, labels=labels)
                    else:
                        raise
                (out.loss / self.cfg["grad_accum_steps"]).backward()
                losses.append(float(out.loss.detach()))
                if (bstart // self.cfg["batch_size"] + 1) % self.cfg["grad_accum_steps"] == 0:
                    torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                    optimizer.step()
                    scheduler.step()
                    optimizer.zero_grad()
                step += 1
            train_loss = sum(losses) / max(1, len(losses))

            val_probs = self.predict([r["func"] for r in val_recs])
            val_labels = [int(r["label"]) for r in val_recs]
            val_preds = [int(p >= 0.5) for p in val_probs]
            mcc = float(matthews_corrcoef(val_labels, val_preds))
            rec = float(recall_score(val_labels, val_preds, zero_division=0))
            f1 = float(f1_score(val_labels, val_preds, zero_division=0))
            auc = float(roc_auc_score(val_labels, val_probs))
            history.append({"epoch": epoch, "train_loss": train_loss, "val_mcc": mcc,
                            "val_recall": rec, "val_f1": f1, "val_auc": auc,
                            "seconds": time.perf_counter() - t0})
            print(f"[epoch {epoch}] loss={train_loss:.4f} mcc={mcc:.4f} "
                  f"recall={rec:.4f} f1={f1:.4f} auc={auc:.4f}", flush=True)

            torch.save({"model": model.state_dict(), "optimizer": optimizer.state_dict(),
                        "scheduler": scheduler.state_dict(), "epoch": epoch,
                        "best_mcc": best_mcc, "history": history,
                        "cfg": self.cfg,
                        "meta": {"model": self.cfg["model_name"], "seed": self.cfg["seed"],
                                 "date": datetime.now(timezone.utc).isoformat()}},
                       state_path)
            with (self.output_dir / "history.json").open("w", encoding="utf-8") as f:
                json.dump(history, f, indent=2)
            if mcc > best_mcc:
                best_mcc = mcc
                model.save_pretrained(self.output_dir / "best")
                self.tokenizer.save_pretrained(self.output_dir / "best")
                patience_left = int(self.cfg["early_stopping_patience"])
            else:
                patience_left -= 1
                if patience_left <= 0:
                    print(f"[early stop] no val MCC improvement for "
                          f"{self.cfg['early_stopping_patience']} epochs", flush=True)
                    break
        return {"best_val_mcc": best_mcc, "history": history,
                "output_dir": str(self.output_dir)}

    # ----------------------------------------------------------------- dry run
    def _dry_run(self) -> dict:
        """2 synthetic batches, forward + backward + optimizer step on MPS."""
        import torch

        self._lazy_load()
        model = self.model
        model.train()
        device_name = "mps" if torch.backends.mps.is_available() else "cpu"
        batch_shapes = []
        losses = []
        optimizer = torch.optim.AdamW(model.parameters(), lr=1e-5)
        for b in range(2):
            texts = [f"int f{x}() {{ char buf[64]; strcpy(buf, s); return 0; }}" for x in range(4)]
            labels = torch.tensor([1, 0, 1, 0], device=device_name)
            enc = self.tokenizer(texts, truncation=True, padding=True,
                                 max_length=256, return_tensors="pt").to(device_name)
            out = model(**enc, labels=labels)
            out.loss.backward()
            optimizer.step()
            optimizer.zero_grad()
            batch_shapes.append(tuple(enc["input_ids"].shape))
            losses.append(float(out.loss.detach()))
        return {"dry_run": True, "device": device_name,
                "model": self.cfg["model_name"], "batches": 2,
                "batch_shapes": [list(s) for s in batch_shapes],
                "losses": losses}

    # ---------------------------------------------------------------- predict
    def predict(self, texts: list[str], batch_size: int = 16) -> list[float]:
        """Prob(vulnerable) per text; loads best checkpoint if model is fresh."""
        import torch

        if self.model is None:
            best_dir = self.output_dir / "best"
            import transformers as tf

            if best_dir.exists():
                name = str(best_dir)
                sl = int(self.cfg.get("max_seq_len", 512))
            else:
                name, sl = self.cfg["model_name"], int(self.cfg["max_seq_len"])
            self.tokenizer = tf.AutoTokenizer.from_pretrained(name, model_max_length=sl)
            self.model = tf.AutoModelForSequenceClassification.from_pretrained(name).to(self.cfg["device"])
        self.model.eval()
        probs: list[float] = []
        with torch.no_grad():
            for bstart in range(0, len(texts), batch_size):
                batch = texts[bstart : bstart + batch_size]
                enc = self.tokenizer(batch, truncation=True, padding=True,
                                     max_length=int(self.cfg["max_seq_len"]),
                                     return_tensors="pt").to(self.cfg["device"])
                logits = self.model(**enc).logits
                probs.extend(torch.softmax(logits, dim=-1)[:, 1].tolist())
        return probs


def train(cfg: Optional[dict] = None, config_path: str = "configs/models.yaml",
          train_path: Optional[str] = None, val_path: Optional[str] = None) -> dict:
    """Module-level convenience matching the BRIEF §8 contract name."""
    return TransformerBaseline(cfg=cfg, config_path=config_path).train(train_path, val_path)


if __name__ == "__main__":  # pragma: no cover
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/models.yaml")
    ap.add_argument("--train", default=None, help="jsonl with {func,label} records")
    ap.add_argument("--val", default=None, help="jsonl with {func,label} records")
    ap.add_argument("--dry-run", action="store_true", help="2 synthetic batches on MPS")
    args = ap.parse_args()
    cfg = {"dry_run": True} if args.dry_run else {}
    if args.dry_run:
        result = TransformerBaseline(cfg=cfg, config_path=args.config).train()
    else:
        if not (args.train and args.val):
            ap.error("--train and --val required without --dry-run")
        result = TransformerBaseline(config_path=args.config).train(args.train, args.val)
    print(json.dumps(result, indent=2))
    sys.exit(0)
