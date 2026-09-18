"""E7 fusion/fallback policy — LLM verdict when usable, else CodeBERT prior.

Owner: agent A2 (Round 3). Implements the PRE-REGISTERED policy in
configs/fusion_policy.yaml (written before any score was computed on the
evaluation records):

  record-level: use the LLM verdict when the output is USABLE
  (src.metrics.metrics.is_usable); otherwise substitute the CodeBERT prior
  (y = 1 iff p_vulnerable >= tau, tau fitted on the VALID split only).
  meta.fallback_source in {"llm", "transformer"} records the origin.

Safety scope (pre-registered): the fallback fires ONLY on vulnerability-
analysis records (conditions C0/C1/C2a/C2b/C3). It raises on any
safety-contrast record — the defense must never increase unsafe compliance,
and a transformer prior has no notion of safety refusal, so routing unsafe
prompts to it is forbidden by construction.
"""
from __future__ import annotations

import yaml
from pathlib import Path

from src.metrics.metrics import is_usable

# parents[2] = repo root (src/models/fusion_policy.py); parents[1] is src/ —
# the wrong level made run_e7_fusion.py crash with
# FileNotFoundError: .../src/configs/fusion_policy.yaml (round-3 chain log).
PROJECT_ROOT = Path(__file__).resolve().parents[2]

ALLOWED_CONDITIONS = ("C0", "C1", "C2a", "C2b", "C3")
FALLBACK_SOURCE_LLM = "llm"
FALLBACK_SOURCE_TRANSFORMER = "transformer"


class FusionScopeError(ValueError):
    """Raised when a fusion decision is requested outside the pre-registered
    scope (e.g. a safety-contrast record). Fail loudly, never silently route
    safety prompts to the transformer prior."""


def load_policy_config(path: str | Path = "configs/fusion_policy.yaml") -> dict:
    with (PROJECT_ROOT / path).open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


class FusionPolicy:
    """Pre-registered record-level LLM -> transformer-prior fallback."""

    def __init__(self, tau: float,
                 allowed_conditions: tuple[str, ...] = ALLOWED_CONDITIONS):
        if not 0.0 <= tau <= 1.1:
            raise ValueError(f"tau out of range: {tau}")
        self.tau = float(tau)
        self.allowed_conditions = tuple(allowed_conditions)

    # -- scope guard --------------------------------------------------------
    def _check_scope(self, record: dict) -> None:
        cond = str(record.get("condition", "")).strip().lower()
        allowed = {c.lower() for c in self.allowed_conditions}
        if cond not in allowed:
            raise FusionScopeError(
                f"fallback requested outside pre-registered scope "
                f"(condition={record.get('condition')!r}); safety-contrast "
                f"records must never reach the transformer prior")

    # -- core decision ------------------------------------------------------
    def decide(self, record: dict, transformer_score: float | None) -> dict:
        """Return {y_pred, fallback_source, fused} for ONE record.

        transformer_score may be None only when the record stays on the LLM
        arm (usable); an unusable record without a score is an input error.
        """
        self._check_scope(record)
        if is_usable(record) and record.get("y_pred") is not None:
            return {"y_pred": int(record["y_pred"]),
                    "fallback_source": FALLBACK_SOURCE_LLM,
                    "fused": False}
        if transformer_score is None:
            raise ValueError(
                f"unusable record {record.get('sample_id')!r} has no "
                "transformer score; cannot apply the pre-registered fallback")
        return {"y_pred": int(float(transformer_score) >= self.tau),
                "fallback_source": FALLBACK_SOURCE_TRANSFORMER,
                "fused": True}

    # -- ablations ----------------------------------------------------------
    def b4_only(self, transformer_score: float) -> dict:
        """Pure transformer baseline at the fixed 0.5 threshold (no LLM)."""
        return {"y_pred": int(float(transformer_score) >= 0.5),
                "fallback_source": None, "fused": False}

    def score_fusion(self, record: dict, transformer_score: float) -> dict:
        """Optional simple average fusion (ablation only, not the primary
        policy): usable LLM + float confidence -> p = mean(p_bert, conf);
        otherwise the raw transformer score. Threshold fixed at 0.5."""
        self._check_scope(record)
        if is_usable(record) and record.get("y_pred") is not None \
                and isinstance(record.get("confidence"), (int, float)):
            p = (float(transformer_score) + float(record["confidence"])) / 2.0
            return {"y_pred": int(p >= 0.5),
                    "fallback_source": FALLBACK_SOURCE_LLM,
                    "fused": True}
        return {"y_pred": int(float(transformer_score) >= 0.5),
                "fallback_source": FALLBACK_SOURCE_TRANSFORMER,
                "fused": True}
