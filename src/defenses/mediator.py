"""Mediator dispatch (PROJECT_BRIEF §8): mediate(sample, defense, cfg) -> dict.

Defense contract — every defense module exposes:
    apply(sample: dict, cfg: dict) -> {"func": str, "meta": dict}
Known defenses: B1 (prompt reframe), B2 (comment strip), B3 (aggressive text
removal), P1 (semantic context isolation). B0 (raw) is handled by runners as
"no mediation"; P2 (RefuseGuard) is the separate orchestrator in refuseguard.py.
"""
from __future__ import annotations

from typing import Optional

from . import b1_reframe, b2_strip, b3_aggressive, p1_sci
from .b1_reframe import load_defenses_config

__all__ = ["mediate", "DEFENSES", "load_defenses_config"]

DEFENSES = ("B1", "B2", "B3", "P1")


def mediate(sample: dict, defense: str, cfg: Optional[dict] = None) -> dict:
    """Apply one non-LLM defense to a sample; returns {"func", "meta"} with
    meta["defense"] set. Raises ValueError for unknown defenses."""
    if cfg is None:
        cfg = load_defenses_config()
    defense = str(defense).upper()
    if defense == "B1":
        out = b1_reframe.apply(sample, cfg)
    elif defense == "B2":
        out = b2_strip.apply(sample, cfg)
    elif defense == "B3":
        out = b3_aggressive.apply(sample, cfg)
    elif defense == "P1":
        out = p1_sci.apply(sample, cfg)
    else:
        raise ValueError(f"unknown defense {defense!r}; expected one of {DEFENSES}")
    out["meta"]["defense"] = defense
    return out
