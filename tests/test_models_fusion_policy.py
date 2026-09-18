"""Tests for the E7 fusion/fallback policy (owner: A2, Round 3).

All unit tests are MOCK-based (no GPU, no LLM): policy decisions are pure
record-level logic. The optional real-outputs regression reads the E7 result
file when present and verifies the pre-registered invariants.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.models.fusion_policy import (
    FALLBACK_SOURCE_LLM,
    FALLBACK_SOURCE_TRANSFORMER,
    FusionPolicy,
    FusionScopeError,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def vul_record(y_pred: int = 1, status: str = "ANSWER", condition: str = "C0",
               cwe: str | None = "CWE-120", location: str | None = "line 4") -> dict:
    return {"sample_id": "s1", "condition": condition, "status": status,
            "y_pred": y_pred, "cwe": cwe, "location": location, "y_true": 1}


def refusal_record(condition: str = "C0") -> dict:
    return {"sample_id": "s2", "condition": condition, "status": "REFUSAL",
            "y_pred": 0, "cwe": None, "location": None, "y_true": 1}


@pytest.fixture
def policy() -> FusionPolicy:
    return FusionPolicy(tau=0.42)


class TestDecidePrimaryPolicy:
    def test_usable_llm_record_stays_on_llm(self, policy):
        d = policy.decide(vul_record(y_pred=1), transformer_score=0.01)
        assert d == {"y_pred": 1, "fallback_source": FALLBACK_SOURCE_LLM, "fused": False}

    def test_refusal_record_falls_back_to_transformer(self, policy):
        d = policy.decide(refusal_record(), transformer_score=0.9)
        assert d == {"y_pred": 1, "fallback_source": FALLBACK_SOURCE_TRANSFORMER, "fused": True}

    def test_tau_boundary_is_inclusive(self, policy):
        assert policy.decide(refusal_record(), 0.42)["y_pred"] == 1
        assert policy.decide(refusal_record(), 0.4199)["y_pred"] == 0

    def test_refusal_with_parsed_verdict_is_never_usable(self, policy):
        """Audit-round-1 semantics: REFUSAL + vulnerable=0 must not count as a
        usable LLM answer — the prior must take over."""
        d = policy.decide(refusal_record(), transformer_score=0.99)
        assert d["fallback_source"] == FALLBACK_SOURCE_TRANSFORMER
        assert d["y_pred"] == 1

    def test_benign_llm_verdict_kept_without_cwe(self, policy):
        rec = {"sample_id": "s3", "condition": "C2a", "status": "ANSWER",
               "y_pred": 0, "cwe": None, "location": None}
        d = policy.decide(rec, transformer_score=0.9)
        assert d["y_pred"] == 0 and d["fallback_source"] == FALLBACK_SOURCE_LLM

    def test_unusable_record_without_score_raises(self, policy):
        with pytest.raises(ValueError, match="no transformer score"):
            policy.decide(refusal_record(), None)

    def test_invalid_tau_rejected(self):
        with pytest.raises(ValueError):
            FusionPolicy(tau=1.5)


class TestSafetyScope:
    @pytest.mark.parametrize("cond", ["CONTRAST", "E8_SAFE", "E8_UNSAFE",
                                      "SAFETY_CONTRAST", "orbench", "xstest"])
    def test_safety_records_never_reach_the_prior(self, policy, cond):
        rec = refusal_record(condition=cond)
        with pytest.raises(FusionScopeError):
            policy.decide(rec, transformer_score=0.99)

    def test_scope_error_even_when_llm_usable(self, policy):
        """The scope guard fires before any decision, usable or not."""
        rec = vul_record(condition="CONTRAST")
        with pytest.raises(FusionScopeError):
            policy.decide(rec, transformer_score=0.0)

    def test_allowed_conditions_accept_fallback(self, policy):
        for cond in ("C0", "C1", "C2a", "C2b", "C3"):
            d = policy.decide(refusal_record(condition=cond), 0.9)
            assert d["fallback_source"] == FALLBACK_SOURCE_TRANSFORMER


class TestAblations:
    def test_b4_only_fixed_threshold_05(self, policy):
        assert policy.b4_only(0.5)["y_pred"] == 1
        assert policy.b4_only(0.4999)["y_pred"] == 0
        assert policy.b4_only(0.9)["fallback_source"] is None

    def test_score_fusion_uses_confidence_mean(self, policy):
        rec = vul_record(y_pred=1)
        rec["confidence"] = 0.0
        d = policy.score_fusion(rec, transformer_score=0.9)
        assert d["y_pred"] == 0 and d["fused"] is True  # (0.9+0.0)/2 < 0.5
        rec["confidence"] = 0.4
        assert policy.score_fusion(rec, 0.9)["y_pred"] == 1  # (0.9+0.4)/2 >= 0.5

    def test_score_fusion_without_confidence_uses_prior(self, policy):
        rec = vul_record(y_pred=1)
        rec["confidence"] = None
        d = policy.score_fusion(rec, transformer_score=0.6)
        assert d == {"y_pred": 1, "fallback_source": FALLBACK_SOURCE_TRANSFORMER,
                     "fused": True}

    def test_score_fusion_respects_scope(self, policy):
        with pytest.raises(FusionScopeError):
            policy.score_fusion(vul_record(condition="CONTRAST"), 0.5)


class TestPolicyConfigLoading:
    """Regression for the round-3 chain crash: PROJECT_ROOT pointed at src/
    (parents[1]) so load_policy_config raised FileNotFoundError for
    src/configs/fusion_policy.yaml and run_e7_fusion.py exited 1."""

    def test_load_policy_config_resolves_repo_root(self):
        from src.models.fusion_policy import ALLOWED_CONDITIONS, load_policy_config

        cfg = load_policy_config()  # default path, resolved from the repo root
        assert cfg["policy"]["name"] == "llm_then_transformer_prior_v1"
        assert cfg["policy"]["tau_source"] == "valid_split_mcc_max"
        assert set(cfg["policy"]["scope"]["allowed_conditions"]) == set(ALLOWED_CONDITIONS)

    def test_pre_registered_ablations_present(self):
        from src.models.fusion_policy import load_policy_config

        ids = {a["id"] for a in load_policy_config()["ablations"]}
        assert {"b4_only", "llm_only", "llm_then_fallback", "score_fusion"} <= ids

    def test_safety_contrast_conditions_declared(self):
        from src.models.fusion_policy import load_policy_config

        scope = load_policy_config()["policy"]["scope"]
        assert "SAFETY_CONTRAST" in scope["safety_contrast_conditions"]
        # disjointness: no condition may be both fusable and safety-contrast
        assert not (set(scope["allowed_conditions"])
                    & set(scope["safety_contrast_conditions"]))


class TestMetricsHelpers:
    def test_operating_threshold_picks_lowest_thr_meeting_fpr(self):
        from src.metrics.metrics import operating_threshold
        # 4 neg, 4 pos; FPR<=0.25 allows 1 FP.
        y = [0, 0, 0, 0, 1, 1, 1, 1]
        s = [0.1, 0.2, 0.3, 0.9, 0.4, 0.5, 0.6, 0.7]
        thr = operating_threshold(y, s, fpr_target=0.25)
        preds = [x >= thr for x in s]
        fp = sum(1 for p, t in zip(preds, y) if p and t == 0)
        assert fp <= 1
        # 0.4 admits 1 FP (0.9); any lower threshold admits >= 2.
        assert thr == pytest.approx(0.4)

    def test_best_mcc_threshold_separable_scores(self):
        from src.metrics.metrics import best_mcc_threshold
        fit = best_mcc_threshold([0, 0, 1, 1], [0.1, 0.2, 0.8, 0.9])
        assert fit["mcc"] == 1.0
        assert fit["threshold"] == pytest.approx(0.8)

    def test_paired_detection_score(self):
        from src.metrics.metrics import paired_detection_score
        assert paired_detection_score([0.9, 0.2], [0.1, 0.6], 0.5) == pytest.approx(0.5)
        with pytest.raises(ValueError):
            paired_detection_score([0.1], [0.2, 0.3], 0.5)


class TestRealOutputsRegression:
    """Guards the committed E7 output against policy regressions (skipped
    when the round-3 output has not been produced yet)."""

    E7 = PROJECT_ROOT / "outputs/experiments/round3_e7/e7_fusion_results.json"

    @pytest.mark.skipif(not E7.exists(), reason="E7 round-3 output not produced yet")
    def test_e7_invariants(self):
        res = json.loads(self.E7.read_text(encoding="utf-8"))
        abl = res["ablations"]
        # coverage gain identity
        gain = abl["llm_then_fallback"]["overall"]["uac"] - abl["llm_only"]["overall"]["uac"]
        assert res["coverage_gain"]["overall"] == pytest.approx(gain, abs=1e-6)
        # fallback usage is a strict subset, never larger than the unusable mass
        assert abl["llm_then_fallback"]["overall"]["n_fallback_used"] <= \
            abl["llm_then_fallback"]["overall"]["n"]
        # pre-registered tau provenance
        assert res["policy"]["tau_source"].startswith("argmax MCC")
        assert 0.0 <= res["policy"]["tau"] <= 1.0
        # safety scope: every E8 record must have been scope-blocked
        for path, chk in res["safety_scope_check"].items():
            if isinstance(chk, dict):
                assert chk["reached_fallback"] == 0, path
                assert chk["scope_blocked"] == chk["n_records"], path

    @pytest.mark.skipif(not E7.exists(), reason="E7 round-3 output not produced yet")
    def test_e8_real_records_are_scope_blocked_by_policy(self):
        """Direct check with the CURRENT policy on real E8 records."""
        policy = FusionPolicy(tau=0.5)
        blocked = total = 0
        for rel in ("outputs/experiments/pilot_round2_recomputed/0.5b/e8/results.json",
                    "outputs/experiments/pilot_round2_recomputed/3b_qwen/e8/results.json"):
            p = PROJECT_ROOT / rel
            if not p.exists():
                continue
            for r in json.loads(p.read_text(encoding="utf-8"))["records"]:
                total += 1
                with pytest.raises(FusionScopeError):
                    policy.decide(r, 0.9)
                blocked += 1
        assert blocked == total and blocked > 0
