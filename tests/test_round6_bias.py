"""Tests for Round-6 verdict-bias analysis (agent A1, Round 6).

Covers the pure helpers of scripts/analyze_verdict_bias.py: fp_rate,
paired_fp_bias, vci, advisory_echo_rate, unpaired_diff_ci. All fixtures are
SMALL and hand-computed (no data files, no GPU, no statsmodels dependence in
asserts beyond the shared mcnemar helper). The script is imported by path
(scripts/ is not a package), following the eval_codebert pattern.
"""
from __future__ import annotations

import importlib.util as _ilu
from pathlib import Path

import pytest

AVB_PATH = Path(__file__).resolve().parents[1] / "scripts" / "analyze_verdict_bias.py"
_spec = _ilu.spec_from_file_location("analyze_verdict_bias_mod", AVB_PATH)
avb = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(avb)


def _rec(sid, label, y_pred, condition="C0", text=None):
    return {"sample_id": str(sid), "y_true": label, "y_pred": y_pred,
            "condition": condition, "status": "ANSWER", "meta": {"text": text}}


# ---------------------------------------------------------------------------
# verdict / fp_rate
# ---------------------------------------------------------------------------
class TestFpRate:
    def test_hand_computed(self):
        # benign records: preds 1,0,1,0 -> FP-rate 0.5; the vul record is ignored
        recs = [_rec(1, 0, 1), _rec(2, 0, 0), _rec(3, 0, 1), _rec(4, 0, 0),
                _rec(5, 1, 1)]
        assert avb.fp_rate(recs) == 0.5

    def test_all_flagged_and_none_flagged(self):
        assert avb.fp_rate([_rec(1, 0, 1), _rec(2, 0, 1)]) == 1.0
        assert avb.fp_rate([_rec(1, 0, 0), _rec(2, 0, 0)]) == 0.0

    def test_empty_or_no_benign_raises(self):
        with pytest.raises(ValueError):
            avb.fp_rate([])
        with pytest.raises(ValueError):
            avb.fp_rate([_rec(1, 1, 1), _rec(2, 1, 0)])  # no benign records

    def test_nonbinary_pred_raises(self):
        with pytest.raises(ValueError):
            avb.verdict({"y_pred": 2})


# ---------------------------------------------------------------------------
# paired_fp_bias
# ---------------------------------------------------------------------------
class TestPairedFpBias:
    def test_hand_computed(self):
        # 4 benign samples, C0 flags = [0,0,1,0], arm flags = [1,0,1,1]
        c0 = [_rec(1, 0, 0), _rec(2, 0, 0), _rec(3, 0, 1), _rec(4, 0, 0)]
        arm = [_rec(1, 0, 1, "C5_near"), _rec(2, 0, 0, "C5_near"),
               _rec(3, 0, 1, "C5_near"), _rec(4, 0, 1, "C5_near")]
        pb = avb.paired_fp_bias(c0, arm, n_boot=200, seed=7)
        assert pb["n"] == 4
        assert pb["fp_rate_c0"] == pytest.approx(0.25)
        assert pb["fp_rate_arm"] == pytest.approx(0.75)
        assert pb["delta"] == pytest.approx(0.5)
        assert pb["flip_benign_to_vul"] == 2   # samples 1 and 4: 0 -> 1
        assert pb["flip_vul_to_benign"] == 0
        assert pb["headroom"] == 3             # benign correct at C0
        # exact McNemar with b01=2, b10=0 -> two-sided p = 2 * (1/2)^2 = 0.5
        assert pb["mcnemar_p"] == pytest.approx(0.5)
        # bootstrap CI of the paired delta: with deltas [1,0,0,1] resampled,
        # the CI must contain the point estimate 0.5 and lie within [0, 1]
        assert pb["ci_low"] <= 0.5 <= pb["ci_high"]
        assert 0.0 <= pb["ci_low"] and pb["ci_high"] <= 1.0

    def test_no_change_gives_p_one(self):
        c0 = [_rec(1, 0, 1), _rec(2, 0, 0)]
        arm = [_rec(1, 0, 1, "D2_task"), _rec(2, 0, 0, "D2_task")]
        pb = avb.paired_fp_bias(c0, arm, n_boot=100, seed=7)
        assert pb["delta"] == 0.0
        assert pb["mcnemar_p"] == pytest.approx(1.0)

    def test_misaligned_samples_raise(self):
        c0 = [_rec(1, 0, 0), _rec(2, 0, 0)]
        arm = [_rec(1, 0, 1, "C5_near"), _rec(3, 0, 1, "C5_near")]
        with pytest.raises(ValueError):
            avb.paired_fp_bias(c0, arm)


# ---------------------------------------------------------------------------
# vci (Verdict Corruption Index)
# ---------------------------------------------------------------------------
class TestVci:
    def test_hand_computed_all_directions(self):
        # benign: 0->1 (fp), vul: 1->0 (fn), vul: 0->1 (rec) -> 3 of 6 changed
        base = [_rec(1, 0, 0), _rec(2, 1, 1), _rec(3, 1, 0),
                _rec(4, 0, 1), _rec(5, 1, 1), _rec(6, 0, 0)]
        treat = [_rec(1, 0, 1, "C5_near"), _rec(2, 1, 0, "C5_near"),
                 _rec(3, 1, 1, "C5_near"), _rec(4, 0, 1, "C5_near"),
                 _rec(5, 1, 1, "C5_near"), _rec(6, 0, 0, "C5_near")]
        v = avb.vci({r["sample_id"]: r for r in base},
                    {r["sample_id"]: r for r in treat})
        assert v["n_paired"] == 6 and v["n_benign"] == 3 and v["n_vul"] == 3
        assert v["n_changed"] == 3
        assert v["vci"] == pytest.approx(0.5)
        assert v["n_fp_direction"] == 1
        assert v["vci_fp_direction"] == pytest.approx(1 / 3)
        assert v["n_fn_direction"] == 1
        assert v["vci_fn_direction"] == pytest.approx(1 / 3)
        assert v["n_rec_direction"] == 1
        assert v["vci_rec_direction"] == pytest.approx(1 / 3)
        assert v["n_fpc_direction"] == 0
        assert v["vci_fpc_direction"] == 0.0

    def test_no_change(self):
        base = [_rec(1, 0, 0), _rec(2, 1, 1)]
        treat = [_rec(1, 0, 0, "C5_far"), _rec(2, 1, 1, "C5_far")]
        v = avb.vci({r["sample_id"]: r for r in base},
                    {r["sample_id"]: r for r in treat})
        assert v["vci"] == 0.0
        assert v["vci_fp_direction"] == 0.0 and v["vci_fn_direction"] == 0.0

    def test_direction_semantics_match_rate_deltas(self):
        """fp_direction rate must equal the FP-rate delta; fn_direction rate
        must equal the FN-rate delta (recall delta negated)."""
        base = [_rec(1, 0, 0), _rec(2, 0, 1), _rec(3, 1, 1), _rec(4, 1, 0)]
        treat = [_rec(1, 0, 1, "A"), _rec(2, 0, 1, "A"),
                 _rec(3, 1, 0, "A"), _rec(4, 1, 0, "A")]
        m = {r["sample_id"]: r for r in base}
        t = {r["sample_id"]: r for r in treat}
        v = avb.vci(m, t)
        fp_c0 = avb.fp_rate([m["1"], m["2"]])
        fp_a = avb.fp_rate([t["1"], t["2"]])
        assert v["vci_fp_direction"] == pytest.approx(fp_a - fp_c0)
        rec_c0 = sum(1 for r in (m["3"], m["4"]) if avb.verdict(r) == 1) / 2
        rec_a = sum(1 for r in (t["3"], t["4"]) if avb.verdict(r) == 1) / 2
        assert v["vci_fn_direction"] == pytest.approx(rec_c0 - rec_a)

    def test_label_mismatch_raises(self):
        base = [_rec(1, 0, 0)]
        treat = [_rec(1, 1, 0, "A")]
        with pytest.raises(ValueError):
            avb.vci({r["sample_id"]: r for r in base},
                    {r["sample_id"]: r for r in treat})

    def test_disjoint_raise(self):
        with pytest.raises(ValueError):
            avb.vci({"1": _rec(1, 0, 0)}, {"2": _rec(2, 0, 1, "A")})


# ---------------------------------------------------------------------------
# advisory_echo_rate
# ---------------------------------------------------------------------------
class TestAdvisoryEcho:
    def test_api_word_boundary_and_token(self):
        texts = ['{"root_cause": "Sink usage in the function f"}',
                 '{"root_cause": "memcpy overflow"}',
                 '{"root_cause": "unrelated"}']
        apis = [["memcpy"], ["memcpy"], ["memcpy"]]
        r = avb.advisory_echo_rate(texts, apis)
        assert r["n"] == 3
        assert r["n_token_echo"] == 1          # only text 0 has "sink usage"
        assert r["n_api_mention"] == 1         # only text 1 mentions memcpy
        assert r["rate_api_mention"] == pytest.approx(1 / 3)

    def test_substring_is_not_a_word_match(self):
        # "userfree" must NOT count as a mention of "free"
        r = avb.advisory_echo_rate(["calls userfree and memcpyz"], [["free", "memcpy"]])
        assert r["n_api_mention"] == 0

    def test_control_zero(self):
        r = avb.advisory_echo_rate(["plain analysis, no risk language here"], [["free"]])
        assert r["n_api_mention"] == 0 and r["n_token_echo"] == 0

    def test_length_mismatch_raises(self):
        with pytest.raises(ValueError):
            avb.advisory_echo_rate(["a"], [["x"], ["y"]])


# ---------------------------------------------------------------------------
# unpaired_diff_ci
# ---------------------------------------------------------------------------
class TestUnpairedDiffCi:
    def test_hand_computed_point_estimate(self):
        d = avb.unpaired_diff_ci([1.0, 1.0, 0.0], [0.0, 0.0, 0.0],
                                 n_boot=500, seed=11)
        assert d["estimate"] == pytest.approx(2 / 3)  # mean([1,1,0]) - 0
        assert 0.0 <= d["ci_low"] <= d["ci_high"] <= 1.0

    def test_identical_groups_bracket_zero(self):
        d = avb.unpaired_diff_ci([0.0, 1.0, 0.0, 1.0], [1.0, 0.0, 1.0, 0.0],
                                 n_boot=500, seed=11)
        assert d["estimate"] == pytest.approx(0.0)
        assert d["ci_low"] <= 0.0 <= d["ci_high"]

    def test_empty_group_raises(self):
        with pytest.raises(ValueError):
            avb.unpaired_diff_ci([], [0.0])


# ---------------------------------------------------------------------------
# ADVISORY_TOKENS sanity: none of the tokens may appear in the plain task
# prompt vocabulary (guards the C0 must-be-0 control from false positives).
# ---------------------------------------------------------------------------
class TestAdvisoryTokenList:
    def test_tokens_are_lowercase_and_distinctive(self):
        for tok in avb.ADVISORY_TOKENS:
            assert tok == tok.lower()
            assert "vulnerab" not in tok  # task-prompt word, not advisory-only
