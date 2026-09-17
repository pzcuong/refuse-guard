"""B1 — Prompt reframing (PROPOSAL §8.1): assert defensive intent/authorization
at the prompt layer; the code context itself is left untouched."""
from __future__ import annotations

import zlib
from pathlib import Path
from typing import Optional

import yaml

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[2] / "configs" / "defenses.yaml"


def load_defenses_config(path=None) -> dict:
    p = Path(path) if path else DEFAULT_CONFIG_PATH
    with open(p, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    if not isinstance(cfg, dict):
        raise ValueError(f"defenses config must be a mapping: {p}")
    return cfg


def apply(sample: dict, cfg: dict) -> dict:
    """Return {"func": unchanged, "meta": {defense, reframe_id, reframe_prefix}}."""
    prefixes = (cfg.get("B1") or {}).get("reframe_prefixes", [])
    if not prefixes:
        raise ValueError("B1.reframe_prefixes missing from defenses config")
    pin = (cfg.get("B1") or {}).get("pin") or {}
    if pin.get("reframe_id"):
        chosen = next(p for p in prefixes if p["id"] == pin["reframe_id"])
    else:
        idx = zlib.crc32(str(sample.get("sample_id", "")).encode("utf-8")) % len(prefixes)
        chosen = prefixes[idx]
    text = " ".join(chosen["text"].split())
    return {
        "func": sample["func"],
        "meta": {
            "defense": "B1",
            "reframe_id": chosen["id"],
            "reframe_prefix": text,
        },
    }
