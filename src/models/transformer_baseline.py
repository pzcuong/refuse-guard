"""Transformer baseline B4: CodeBERT binary vulnerability classifier.

Contract (PROJECT_BRIEF §8):
    train(cfg) / TransformerBaseline().train(cfg)  -> fine-tune on PrimeVul-style records
    predict(texts: list[str]) -> list[float]        (prob vulnerable)

Design for M2 Pro / MPS (32GB):
- microsoft/codebert-base (roberta architecture, ungated), num_labels=2.
- max_seq_len from cfg (512, fallback 256 on MPS OOM), small batch + grad accum.
- Hand-rolled training loop (no transformers Trainer): explicit seed, MPS-friendly,
  full step-level checkpoint/resume (model + optimizer + scheduler + epoch +
  batches-done-in-epoch + best val MCC + patience).
- Class imbalance handled with weighted cross-entropy (pos_weight = n_benign /
  n_vulnerable of the actual train subsample, computed at run time and logged)
  instead of oversampling: keeps the real class prior in the majority gradients,
  adds no duplicate samples, one disclosed hyperparameter.
- LR schedule: warmup + cosine decay (cfg["scheduler"] = "cosine") or the
  round-1 linear decay ("linear").
- bf16 autocast on MPS when cfg["dtype"] = "bfloat16" (M2 Pro supports it);
  "float32" / "float16" also accepted (fp16 has no GradScaler on MPS -> bf16 is
  the recommended low-precision choice).
- Early stopping on validation MCC with patience cfg.early_stopping_patience —
  logs recall/F1/MCC/AUC (AUC = None when the val set has a single class).
- `dry_run=True` runs 2 synthetic batches through forward+backward on MPS to
  prove the pipeline without real data (used in Round 1).
- `speed_test_steps=N` runs N optimizer steps on the real data and reports
  sec/step + full-train ETA without writing any checkpoint (Round 2 planning).

Record contract input (canonical BRIEF §8 record):
    {"sample_id": str, "func": str, "label": 0|1, ...}

Round 2 train command (real data, see scripts/train_codebert.py):
    HF_HOME=<root>/models_dir/hf nohup .venv/bin/python scripts/train_codebert.py \
        --config configs/train_codebert.yaml > outputs/transformer/train.log 2>&1 &
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
    "scheduler": "cosine",       # cosine | linear
    "dtype": "bfloat16",         # bfloat16 | float16 | float32 (autocast on mps)
    "pos_weight": "auto",        # "auto" -> n_benign/n_vul of train subsample, or float
    "seed": 1234,
    "early_stopping_patience": 2,  # on val MCC
    "ckpt_every_steps": 200,     # optimizer steps between mid-epoch checkpoints
    "output_dir": "models_dir/transformer_baseline",
    "resume": True,
    "device": "mps",
    "dry_run": False,
    "max_train_samples": None,   # pilot scale knob
    "speed_test_steps": None,    # N optimizer steps -> report sec/step + ETA, no ckpt
    "allow_random_head": False,  # predict() on a base model without a fine-tuned head
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

    def _encode_ids(self, text: str) -> list[int]:
        """Final token-id row for ONE text (incl. [CLS]/[SEP]), matching the
        audited head+tail truncation semantics of `_encode`:
          - fits in budget:  [CLS] + ids[:seq_len-2] + [SEP]
          - over-long:       [CLS] + first-half + [SEP] + last-half + [SEP]
            (keep = seq_len-3 split 50/50 between head and tail)
        """
        tok = self.tokenizer
        seq_len = int(self.cfg["max_seq_len"])
        ids = tok(text, add_special_tokens=False)["input_ids"]
        if len(ids) > seq_len:
            keep = seq_len - 3  # room for [CLS] + mid-[SEP] + [SEP]
            head = ids[: keep // 2]
            tail = ids[len(ids) - (keep - keep // 2):]
            ids = head + [tok.sep_token_id] + tail
        return [tok.cls_token_id] + ids[: seq_len - 2] + [tok.sep_token_id]

    def _pad_batch(self, rows_ids: list[list[int]]):
        """Right-pad a list of id rows to the batch max (<= max_seq_len).
        Returns a transformers BatchEncoding so callers keep the `.to(device)`
        API (round-1 code path crashed here on real data: plain dict has no
        `.to` — latent bug surfaced by the first real-data run)."""
        torch = importlib.import_module("torch")
        tf = importlib.import_module("transformers")
        tok = self.tokenizer
        pad_id = tok.pad_token_id or 0
        batch_max = min(int(self.cfg["max_seq_len"]), max(len(r) for r in rows_ids))
        input_ids, attention = [], []
        for r in rows_ids:
            pad = batch_max - len(r)
            input_ids.append(r + [pad_id] * pad)
            attention.append([1] * len(r) + [0] * pad)
        return tf.BatchEncoding({
            "input_ids": torch.tensor(input_ids, dtype=torch.long),
            "attention_mask": torch.tensor(attention, dtype=torch.long),
        })

    def _encode(self, texts: list[str]):
        """Tokenize a batch with head+tail truncation for over-long inputs.

        Strategy (audit round 1): CodeBERT is RoBERTa-base
        (max_position_embeddings=514 -> hard input cap of 512 tokens, i.e. the
        configured max_seq_len). Plain HF truncation keeps only the head, which
        silently discards the end of long functions (where vulnerable code
        often sits). Over-long inputs therefore keep the FIRST half and the
        LAST half of the budget with an explicit [SEP] between the halves;
        fitting inputs go through the standard tokenizer path untouched.

        Round 2: delegates to `_encode_ids` + `_pad_batch` so training (which
        pre-tokenizes once and reuses id rows) and one-shot `_encode` are
        guaranteed to produce identical tensors.
        """
        return self._pad_batch([self._encode_ids(t) for t in texts])

    def _predict_from_ids(self, rows_ids: list[list[int]], batch_size: int = 16) -> list[float]:
        """Prob(vulnerable) for pre-tokenized rows (no re-tokenization)."""
        import torch

        probs: list[float] = []
        self.model.eval()
        with torch.no_grad():
            for bstart in range(0, len(rows_ids), batch_size):
                enc = self._pad_batch(rows_ids[bstart : bstart + batch_size]).to(self.device)
                logits = self.model(**enc).logits
                probs.extend(torch.softmax(logits, dim=-1)[:, 1].tolist())
        return probs

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
        import torch.nn.functional as F
        from sklearn.metrics import f1_score, matthews_corrcoef, recall_score, roc_auc_score

        train_recs = self._read_jsonl(train_path)
        val_recs = self._read_jsonl(val_path)
        if self.cfg.get("max_train_samples"):
            train_recs = train_recs[: int(self.cfg["max_train_samples"])]
        rng = random.Random(self.cfg["seed"])
        rng.shuffle(train_recs)

        # Pre-tokenize once (Round 2 wall-clock: avoids re-tokenizing the whole
        # train set every epoch; identical ids to _encode by construction).
        t_tok = time.perf_counter()
        train_ids = [self._lazy_load_ids_and_encode(r["func"]) for r in train_recs]
        val_ids = [self._lazy_load_ids_and_encode(r["func"]) for r in val_recs]
        train_labels = [int(r["label"]) for r in train_recs]
        val_labels = [int(r["label"]) for r in val_recs]
        print(f"[data] train={len(train_recs)} val={len(val_recs)} "
              f"tokenized in {time.perf_counter() - t_tok:.1f}s", flush=True)

        # --- class imbalance: weighted CE (pos_weight disclosed) ------------
        n_pos = sum(train_labels)
        n_neg = len(train_labels) - n_pos
        if self.cfg["pos_weight"] == "auto":
            pos_w = n_neg / n_pos if n_pos else 1.0
        else:
            pos_w = float(self.cfg["pos_weight"])
        class_weights = torch.tensor([1.0, pos_w], device=self.device)
        print(f"[data] n_benign={n_neg} n_vul={n_pos} pos_weight={pos_w:.4f} "
              f"(weighted CE, choice disclosed: pos_weight over oversampling)", flush=True)

        self._lazy_load()
        model = self.model
        optimizer = torch.optim.AdamW(
            model.parameters(), lr=float(self.cfg["lr"]),
            weight_decay=float(self.cfg["weight_decay"]),
        )
        batch_size = int(self.cfg["batch_size"])
        accum = int(self.cfg["grad_accum_steps"])
        n_batches = math.ceil(len(train_recs) / batch_size)
        steps_per_epoch = math.ceil(n_batches / accum)
        total_steps = max(1, steps_per_epoch * int(self.cfg["epochs"]))
        warmup = max(1, int(float(self.cfg["warmup_ratio"]) * total_steps))

        def lr_lambda(step: int) -> float:
            if step < warmup:
                return step / warmup
            progress = (step - warmup) / max(1, total_steps - warmup)
            if str(self.cfg.get("scheduler", "cosine")) == "cosine":
                return max(0.0, 0.5 * (1.0 + math.cos(math.pi * min(1.0, progress))))
            return max(0.0, (total_steps - step) / max(1, total_steps - warmup))

        scheduler = torch.optim.lr_scheduler.LambdaLR(optimizer, lr_lambda)

        # ---- resume (step-level; Round 2) ----------------------------------
        start_epoch, batches_done = 0, 0
        global_step, best_mcc, history, patience_left = 0, -1.0, [], \
            int(self.cfg["early_stopping_patience"])
        state_path = self.output_dir / "checkpoint.pt"
        if self.cfg.get("resume") and state_path.exists():
            ck = torch.load(state_path, map_location=self.device, weights_only=False)
            model.load_state_dict(ck["model"])
            optimizer.load_state_dict(ck["optimizer"])
            scheduler.load_state_dict(ck["scheduler"])
            start_epoch = int(ck["epoch"])
            batches_done = int(ck.get("batches_done", 0))
            global_step = int(ck.get("global_step", 0))
            best_mcc = float(ck.get("best_mcc", -1.0))
            history = list(ck.get("history", []))
            patience_left = int(ck.get("patience_left", self.cfg["early_stopping_patience"]))
            if batches_done == 0 and ck.get("epoch_completed"):
                start_epoch += 1
            print(f"[resume] epoch={start_epoch} batches_done={batches_done} "
                  f"global_step={global_step} best_val_mcc={best_mcc:.4f}", flush=True)

        # bf16/fp16 autocast (bf16 recommended on MPS; no GradScaler on MPS fp16)
        amp_dtype = None
        dt = str(self.cfg.get("dtype", "float32")).lower()
        if dt in ("bfloat16", "bf16"):
            amp_dtype = torch.bfloat16
        elif dt == "float16":
            amp_dtype = torch.float16
        amp_ctx = (
            (lambda: torch.autocast(device_type="mps", dtype=amp_dtype))
            if (amp_dtype is not None and self.device == "mps") else None
        )
        if amp_dtype is not None:
            print(f"[amp] autocast dtype={amp_dtype} device={self.device}", flush=True)

        def weighted_loss(logits, labels_t):
            return F.cross_entropy(logits, labels_t, weight=class_weights)

        # ---- speed test mode (Round 2 planning): N steps, no writes --------
        speed_test = self.cfg.get("speed_test_steps")
        speed_t0, speed_step_times = None, []

        # NaN skip policy (Round 2, disclosed): this machine's MPS GPU is
        # SHARED (other agent jobs + browser automation observed running
        # concurrently). Transient non-finite events appeared in 2/2 bf16
        # attempts and once in fp32, at random steps, while other standalone
        # runs of the same code were clean — i.e. environment flake, not
        # LR divergence. A non-finite batch/step is SKIPPED (grads zeroed
        # before any optimizer step touches the params) and counted.
        # Observed failure mode on this machine: once poison enters, EVERY
        # following batch is NaN (params corrupted) — so after 3 consecutive
        # NaN batches the trainer RELOADS the last-known-good checkpoint and
        # replays from there (self-healing recovery, counted + disclosed).
        nan_skips = 0
        max_nan_skips = max(20, int(0.10 * total_steps))
        consecutive_nan = 0
        recover_every = 10          # optimizer steps between recovery checkpoints
        recoveries = 0
        max_recoveries = 50
        last_good = {"epoch": start_epoch, "batches_done": batches_done,
                     "global_step": global_step}

        def _save_recovery() -> None:
            self._save_ckpt(state_path, model, optimizer, scheduler,
                            last_good["epoch"], last_good["batches_done"],
                            last_good["global_step"], best_mcc, history,
                            patience_left, epoch_completed=False, pos_weight=pos_w)

        def _grads_finite() -> bool:
            return all(
                bool(torch.isfinite(p.grad).all())
                for p in model.parameters() if p.grad is not None
            )

        if not speed_test:
            _save_recovery()  # recovery anchor at t=0 (pretrained/resumed state)

        for epoch in range(start_epoch, int(self.cfg["epochs"])):
            model.train()
            t0 = time.perf_counter()
            optimizer.zero_grad()
            losses = []
            micro_since_step = 0
            bidx = batches_done
            while bidx < n_batches:
                sl = slice(bidx * batch_size, min((bidx + 1) * batch_size, len(train_recs)))
                batch_ids = train_ids[sl]
                labels = torch.tensor(train_labels[sl], device=self.device)
                enc = self._pad_batch(batch_ids).to(self.device)
                try:
                    if amp_ctx is not None:
                        with amp_ctx():
                            logits = model(**enc).logits
                        # loss in fp32 OUTSIDE the autocast block: bf16 CE was
                        # observed to go NaN on MPS within ~30 steps (run
                        # 2026-09-18), standard mixed-precision practice is to
                        # keep the objective in fp32.
                        loss = weighted_loss(logits.float(), labels)
                    else:
                        logits = model(**enc).logits
                        loss = weighted_loss(logits, labels)
                except RuntimeError as e:  # MPS OOM -> shrink sequence length
                    if "out of memory" in str(e).lower():
                        self.cfg["max_seq_len"] = int(self.cfg["fallback_seq_len"])
                        print(f"[warn] OOM, falling back seq_len={self.cfg['max_seq_len']}",
                              flush=True)
                        if torch.backends.mps.is_available():
                            torch.mps.empty_cache()
                        enc = self._pad_batch(batch_ids).to(self.device)
                        logits = model(**enc).logits
                        loss = weighted_loss(logits, labels)
                    else:
                        raise
                (loss / accum).backward()
                loss_f = float(loss.detach())
                if loss_f != loss_f:  # NaN loss: params may be poisoned
                    nan_skips += 1
                    consecutive_nan += 1
                    optimizer.zero_grad()
                    # audit round 2 (V1 #3): the isolated NaN skip zeroed grads
                    # but left micro_since_step at its partial count, so the
                    # next flush would average fewer micro-batches (effective
                    # batch < 32 for one step). Reset both accumulators.
                    micro_since_step = 0
                    losses = []
                    print(f"[warn] NaN loss epoch={epoch} batch={bidx} "
                          f"(skip {nan_skips}/{max_nan_skips}, consecutive={consecutive_nan})",
                          flush=True)
                    if speed_test:
                        raise RuntimeError("NaN during speed test — MPS unstable right now")
                    if consecutive_nan >= 3 and state_path.exists():
                        # poison storm -> reload last-known-good and replay
                        if recoveries >= max_recoveries or nan_skips > max_nan_skips:
                            raise RuntimeError(
                                f"Giving up after {recoveries} recoveries / "
                                f"{nan_skips} skips (GPU contention?).")
                        ck = torch.load(state_path, map_location=self.device,
                                        weights_only=False)
                        model.load_state_dict(ck["model"])
                        optimizer.load_state_dict(ck["optimizer"])
                        scheduler.load_state_dict(ck["scheduler"])
                        bidx = int(ck["batches_done"])
                        global_step = int(ck["global_step"])
                        consecutive_nan, micro_since_step, recoveries = 0, 0, recoveries + 1
                        losses = []
                        print(f"[recover #{recoveries}] reloaded last-good checkpoint "
                              f"(epoch={epoch}, batch={bidx}, step={global_step})", flush=True)
                        continue
                    if nan_skips > max_nan_skips:
                        raise RuntimeError(
                            f"Too many non-finite steps ({nan_skips} > {max_nan_skips}); "
                            "aborting. Check GPU contention or dtype.")
                    bidx += 1  # isolated NaN: skip this batch
                    continue
                consecutive_nan = 0
                losses.append(loss_f)
                micro_since_step += 1
                if micro_since_step == accum or bidx == n_batches - 1:  # flush incl. last partial group (fix: round-1 LOW)
                    if not _grads_finite():  # poisoned grads: drop step, params untouched
                        nan_skips += 1
                        optimizer.zero_grad()
                        print(f"[warn] non-finite grads epoch={epoch} batch={bidx} -> "
                              f"optimizer step skipped ({nan_skips}/{max_nan_skips})",
                              flush=True)
                        if nan_skips > max_nan_skips:
                            raise RuntimeError(
                                f"Too many non-finite steps ({nan_skips} > {max_nan_skips}); "
                                "aborting. Check GPU contention or dtype.")
                        micro_since_step = 0
                        bidx += 1
                        continue
                    torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                    optimizer.step()
                    scheduler.step()
                    optimizer.zero_grad()
                    micro_since_step = 0
                    global_step += 1
                    last_good = {"epoch": epoch, "batches_done": bidx + 1,
                                 "global_step": global_step}
                    if global_step % recover_every == 0:
                        _save_recovery()  # self-healing reload point
                    if speed_test:
                        if speed_t0 is None:
                            speed_t0 = time.perf_counter()  # skip warmup step below
                        else:
                            now = time.perf_counter()
                            speed_step_times.append(now - speed_t0)
                            speed_t0 = now
                        if global_step >= int(speed_test):
                            per_step = sum(speed_step_times) / len(speed_step_times)
                            eta_s = per_step * total_steps
                            return {
                                "speed_test": True, "steps_timed": len(speed_step_times),
                                "sec_per_optimizer_step": round(per_step, 3),
                                "total_optimizer_steps": total_steps,
                                "eta_hours_full_train": round(eta_s / 3600, 2),
                                "note": "excludes tokenization + per-epoch validation",
                            }
                    if global_step % 25 == 0:
                        recent = losses[-accum * 25:] if len(losses) >= accum * 25 else losses
                        print(f"[step {global_step}/{total_steps}] "
                              f"loss~{sum(recent) / len(recent):.4f} "
                              f"lr={scheduler.get_last_lr()[0]:.2e} "
                              f"skips={nan_skips} recoveries={recoveries}", flush=True)
                    if global_step % int(self.cfg["ckpt_every_steps"]) == 0:
                        _save_recovery()
                        print(f"[ckpt] epoch={epoch} batch={bidx + 1}/{n_batches} "
                              f"step={global_step} loss~{sum(losses[-accum:]) / accum:.4f}",
                              flush=True)
                bidx += 1
            batches_done = 0
            train_loss = sum(losses) / max(1, len(losses))

            val_probs = self._predict_from_ids(val_ids)
            val_preds = [int(p >= 0.5) for p in val_probs]
            mcc = float(matthews_corrcoef(val_labels, val_preds))
            rec = float(recall_score(val_labels, val_preds, zero_division=0))
            f1 = float(f1_score(val_labels, val_preds, zero_division=0))
            auc = (float(roc_auc_score(val_labels, val_probs))
                   if len(set(val_labels)) > 1 else None)  # fix: round-1 LOW (1-class crash)
            history.append({"epoch": epoch, "train_loss": train_loss, "val_mcc": mcc,
                            "val_recall": rec, "val_f1": f1, "val_auc": auc,
                            "nan_skips_cumulative": nan_skips,
                            "seconds": time.perf_counter() - t0})
            improved = mcc > best_mcc
            if improved:  # fix: round-1 LOW (checkpoint stored stale best_mcc)
                best_mcc = mcc
            print(f"[epoch {epoch}] loss={train_loss:.4f} mcc={mcc:.4f} "
                  f"recall={rec:.4f} f1={f1:.4f} auc={auc} "
                  f"({'improved' if improved else 'no improvement'})", flush=True)

            self._save_ckpt(state_path, model, optimizer, scheduler, epoch, 0,
                            global_step, best_mcc, history, patience_left,
                            epoch_completed=True, pos_weight=pos_w)
            with (self.output_dir / "history.json").open("w", encoding="utf-8") as f:
                json.dump(history, f, indent=2)
            if improved:
                model.save_pretrained(self.output_dir / "best")
                self.tokenizer.save_pretrained(self.output_dir / "best")
                with (self.output_dir / "best" / "val_metrics.json").open(
                        "w", encoding="utf-8") as f:
                    json.dump(history[-1], f, indent=2)
                patience_left = int(self.cfg["early_stopping_patience"])
            else:
                patience_left -= 1
                if patience_left <= 0:
                    print(f"[early stop] no val MCC improvement for "
                          f"{self.cfg['early_stopping_patience']} epochs", flush=True)
                    break
        return {"best_val_mcc": best_mcc, "history": history,
                "nan_skips_cumulative": nan_skips, "max_nan_skips": max_nan_skips,
                "output_dir": str(self.output_dir)}

    def _lazy_load_ids_and_encode(self, text: str) -> list[int]:
        """Tokenize helper that also triggers lazy model/tokenizer load once."""
        if self.tokenizer is None:
            import transformers as tf

            self.tokenizer = tf.AutoTokenizer.from_pretrained(
                self.cfg["model_name"], model_max_length=int(self.cfg["max_seq_len"]))
        return self._encode_ids(text)

    def _save_ckpt(self, state_path: Path, model, optimizer, scheduler, epoch: int,
                   batches_done: int, global_step: int, best_mcc: float, history: list,
                   patience_left: int, epoch_completed: bool, pos_weight: float) -> None:
        import torch

        torch.save({
            "model": model.state_dict(), "optimizer": optimizer.state_dict(),
            "scheduler": scheduler.state_dict(), "epoch": epoch,
            "batches_done": batches_done, "global_step": global_step,
            "best_mcc": best_mcc, "history": history,
            "patience_left": patience_left, "epoch_completed": epoch_completed,
            "pos_weight": pos_weight,
            "cfg": self.cfg,
            "meta": {"model": self.cfg["model_name"], "seed": self.cfg["seed"],
                     "date": datetime.now(timezone.utc).isoformat()},
        }, state_path)

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
        """Prob(vulnerable) per text; requires a fine-tuned checkpoint unless
        cfg['allow_random_head'] is set explicitly (fix: round-1 LOW — a fresh
        classification head used to be loaded silently)."""
        import torch

        if self.model is None:
            best_dir = self.output_dir / "best"
            if best_dir.exists():
                name = str(best_dir)
                sl = int(self.cfg.get("max_seq_len", 512))
            elif self.cfg.get("allow_random_head"):
                print("[warn] no fine-tuned checkpoint at "
                      f"{best_dir}; using base model with a RANDOM head",
                      flush=True)
                name, sl = self.cfg["model_name"], int(self.cfg["max_seq_len"])
            else:
                raise FileNotFoundError(
                    f"No fine-tuned checkpoint at {best_dir}. Train first or pass "
                    "cfg['allow_random_head']=True to use the untuned base head.")
            import transformers as tf

            self.tokenizer = tf.AutoTokenizer.from_pretrained(name, model_max_length=sl)
            self.model = tf.AutoModelForSequenceClassification.from_pretrained(name).to(self.cfg["device"])
        self.model.eval()
        rows = [self._encode_ids(t) for t in texts]
        return self._predict_from_ids(rows, batch_size=batch_size)


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
