"""EVIDA verify-or-abstain decision policy (prereg §2.3-§2.5, frozen).

Per paired unit, both verdicts parsed:
  alarm        = (V_raw != V_trusted)          — verdict-level disagreement.
                 The alarm NEVER rewrites a verdict by itself; it only
                 triggers adjudication (registered mitigation).
  agree        -> final = V_raw                                  [path=agree]
  alarm:
    checker SUPPORT -> final = V_raw (claim is backed by code evidence)
                                                           [checker_support]
    checker REFUTE  -> final = V_trusted (pattern absent from the slice)
                                                            [checker_refute]
    UNDECIDABLE     -> E7 fallback: frozen CodeBERT 125M, tau=.5481
                       (outputs/transformer/fallback_threshold.json, argmax-
                       MCC, pre-registered — NOT retuned at pilot) on the
                       RAW view's func -> final = (p >= tau)     [fallback]
                       CodeBERT unavailable/error -> final = None [abstain]

Scope guard (E7/M6): the transformer prior only ever sees vulnerability-
analysis records; every EVIDA record is one by construction and the guard is
asserted per call.  Refusal is NEVER mapped to a verdict anywhere.
"""
from __future__ import annotations

import json
from pathlib import Path

from research_program.evida_checkers import (REFUTE, SUPPORT, UNDECIDABLE,
                                             adjudicate_claim)

__all__ = ["FALLBACK_THRESHOLD_PATH", "EvidaAdjudicator", "decode_final"]

FALLBACK_THRESHOLD_PATH = \
    Path(__file__).resolve().parents[1] / \
    "outputs/transformer/fallback_threshold.json"


class EvidaAdjudicator:
    """Frozen decision policy.  `codebert` is lazy: the 125M model loads on
    the first UNDECIDABLE unit only (pilot budget; it is frozen regardless)."""

    def __init__(self, tau: float | None = None,
                 threshold_path: Path = FALLBACK_THRESHOLD_PATH,
                 checker_enabled: bool = True):
        if tau is None:
            d = json.loads(threshold_path.read_text(encoding="utf-8"))
            tau = float(d["tau"])
            self.tau_source = str(d.get("tau_rule", "fallback_threshold.json"))
        else:
            self.tau_source = "config override"
        self.tau = float(tau)
        self.checker_enabled = checker_enabled
        self._codebert = None
        self.fallback_calls = 0
        self.fallback_errors = 0

    # -- frozen CodeBERT prior (E7 machinery, read-only reuse) ---------------
    def _p_vulnerable(self, func: str) -> float | None:
        try:
            if self._codebert is None:
                from src.models.transformer_baseline import TransformerBaseline

                self._codebert = TransformerBaseline(
                    config_path="configs/train_codebert.yaml")
            return float(self._codebert.predict([func])[0])
        except Exception:  # noqa: BLE001 — fallback failure => ABSTAIN, disclosed
            self.fallback_errors += 1
            return None

    # -- the registered decision --------------------------------------------
    def decide(self, raw: dict, trusted: dict, family_hint: str | None,
               safety_record: bool = False) -> dict:
        """raw/trusted: {y_pred (int|None), status, cwe}; returns the decision
        {final, path, alarm, adjudication, fallback_score}.

        Any unparsed/refusal verdict on either view returns final=None with
        path='invalid_pair' — the caller excludes the unit from paired
        endpoints and discloses it (prereg §1.9.2; refusal is never mapped to
        benign/malicious).
        """
        ry, ty = raw.get("y_pred"), trusted.get("y_pred")
        if ry not in (0, 1) or ty not in (0, 1):
            return {"final": None, "path": "invalid_pair", "alarm": False,
                    "adjudication": None, "fallback_score": None,
                    "note": f"unparsed/refusal view (raw={ry!r}, "
                            f"trusted={ty!r}) — excluded from paired endpoints"}
        alarm = int(ry) != int(ty)
        if not alarm:
            return {"final": int(ry), "path": "agree", "alarm": False,
                    "adjudication": None, "fallback_score": None, "note": ""}
        if safety_record:
            raise AssertionError(
                "E7 scope guard: safety-contrast records must never reach "
                "adjudication/fallback (M6); EVIDA has none by construction")
        adj = adjudicate_claim(
            claim_vulnerable=int(ry), claim_cwe=raw.get("cwe"),
            family_hint=family_hint,
            source=raw["func"], language=raw["language"]) \
            if self.checker_enabled else \
            {"checker": None, "outcome": UNDECIDABLE, "pattern_state": None,
             "note": "checker disabled (config)"}
        if adj["outcome"] == SUPPORT:
            return {"final": int(ry), "path": "checker_support", "alarm": True,
                    "adjudication": adj, "fallback_score": None, "note": ""}
        if adj["outcome"] == REFUTE:
            return {"final": int(ty), "path": "checker_refute", "alarm": True,
                    "adjudication": adj, "fallback_score": None, "note": ""}
        # UNDECIDABLE -> frozen fallback, then abstain if unusable
        p = self._p_vulnerable(raw["func"])
        self.fallback_calls += 1
        if p is None:
            return {"final": None, "path": "abstain", "alarm": True,
                    "adjudication": adj, "fallback_score": None,
                    "note": "fallback unavailable -> ABSTAIN (fail loudly)"}
        return {"final": int(float(p) >= self.tau), "path": "fallback",
                "alarm": True, "adjudication": adj, "fallback_score": round(p, 6),
                "note": ""}


def decode_final(final) -> str:
    """3-state outcome for DIER-style tables: correct/incorrect decided by the
    caller against y_true; abstain == final None."""
    return "abstain" if final is None else f"verdict:{final}"
