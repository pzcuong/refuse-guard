"""Round-12 W2 analysis tests (CPU only): every statistic of
scripts/r12_defense_analysis.py is pinned against HAND-COMPUTED values on a
small fixture -- recall, both flip directions, exact McNemar p, benign FP,
restoration deltas, fail-safe pending behaviour, and mock/real path hygiene.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.r12_defense_analysis import (  # noqa: E402
    DEFAULT_OUT, MOCK_OUT, P0, P2_D1, P2_NODEF,
    analyze_records, build_mock_records, main, normalize_arm, verdict_of,
)


@pytest.fixture(scope="module")
def mock_result() -> dict:
    records = build_mock_records()
    return analyze_records(records[1:], records[0]["meta"], mock=True)


# ------------------------------------------------------------- arm matching
def test_normalize_arm_variants():
    assert normalize_arm("P0_neutral") == P0
    assert normalize_arm("p0") == P0
    assert normalize_arm("P2_advisory_in_package") == P2_NODEF
    assert normalize_arm("P2_nodefense") == P2_NODEF
    assert normalize_arm("P2_D1_stripped") == P2_D1
    assert normalize_arm("P2_defended") == P2_D1
    # W1 runner's actual label (scripts/r12_attack_defense.py DEFENDED_ARM)
    assert normalize_arm("P2D1_strip") == P2_D1
    assert normalize_arm("P1_offensive_wording") is None
    assert normalize_arm("") is None


def test_verdict_of_refusal_never_mapped():
    assert verdict_of({"status": "REFUSAL", "vulnerable": 1}) is None
    assert verdict_of({"status": "ANSWER", "parsed": {"vulnerable": 1}}) == 1
    assert verdict_of({"status": "PARTIAL", "parsed": {"vulnerable": 0}}) == 0
    assert verdict_of({"status": "ANSWER", "parsed": {}}) is None


# -------------------------------------------- hand-computed fixture numbers
# Ground truth of build_mock_records() (see the fixture docstring):
#   P0      recall 4/6 = .6667, FP 0/4
#   P2_nodef recall 2/6 = .3333, FP 1/4 (b1 flips to malicious: ATTACK FP)
#   P2_D1   recall 3/6 = .5,    FP 0/4 (b1 repaired)
#   P2_nodef vs P2_D1 (malicious): gain m3 (0->1), loss none,
#       McNemar exact nd=1 -> p = 2*(1/2)^1 = 1.0
#   P0 vs P2_D1 (malicious): loss m4 (1->0), gain none,
#       McNemar exact nd=1 -> p = 1.0
#   P2_nodef vs P2_D1 (benign): FP removed b1 (1->0), nd=1 -> p = 1.0
#   P0 vs P2_D1 (benign): no discordance, nd=0 -> p = 1.0
def test_restoration_table_matches_hand_computation(mock_result):
    r = mock_result["per_model"]["mock-model"]["restoration"]
    assert r["recall_P0"] == pytest.approx(4 / 6)
    assert r["recall_P2_nodef"] == pytest.approx(2 / 6)
    assert r["recall_P2_D1"] == pytest.approx(3 / 6)
    assert r["attack_effect_recall"] == pytest.approx(2 / 6 - 4 / 6)
    assert r["defense_restoration_recall"] == pytest.approx(1 / 6)
    # two-directional bookkeeping, both directions present
    assert r["restore_gain_flips"] == 1      # m3 0->1 under D1
    assert r["restore_loss_flips"] == 0
    assert r["both_directions_reported"] is True


def test_mcnemar_exact_matches_hand_computation(mock_result):
    cmp_blocks = mock_result["per_model"]["mock-model"]["comparisons"]
    d1 = cmp_blocks[f"{P2_NODEF}__vs__{P2_D1}"]
    p0 = cmp_blocks[f"{P0}__vs__{P2_D1}"]

    mal = d1["malicious"]
    assert mal["n_pairs"] == 6
    assert mal["pos_a"] == 2 and mal["pos_b"] == 3
    assert mal["rate_a"] == pytest.approx(2 / 6)
    assert mal["rate_b"] == pytest.approx(3 / 6)
    assert mal["flips_a0_b1"] == 1 and mal["flips_a1_b0"] == 0
    assert mal["mcnemar_exact"]["b01_a0_b1"] == 1
    assert mal["mcnemar_exact"]["b10_a1_b0"] == 0
    assert mal["mcnemar_exact"]["p_value"] == pytest.approx(1.0)

    mal0 = p0["malicious"]
    assert mal0["pos_a"] == 4 and mal0["pos_b"] == 3
    assert mal0["flips_a1_b0"] == 1 and mal0["flips_a0_b1"] == 0
    assert mal0["mcnemar_exact"]["p_value"] == pytest.approx(1.0)

    # benign-FP pairing: the attack FP is repaired by the defense
    ben = d1["benign"]
    assert ben["n_pairs"] == 4
    assert ben["pos_a"] == 1 and ben["pos_b"] == 0
    assert ben["flips_a1_b0"] == 1 and ben["flips_a0_b1"] == 0
    assert ben["mcnemar_exact"]["p_value"] == pytest.approx(1.0)
    ben0 = p0["benign"]
    assert ben0["pos_a"] == 0 and ben0["pos_b"] == 0
    assert ben0["mcnemar_exact"]["p_value"] == pytest.approx(1.0)


def test_fp_benign_marginals(mock_result):
    arms = mock_result["per_model"]["mock-model"]["arms"]
    assert arms[P0]["benign_fp_count"] == 0
    assert arms[P2_NODEF]["benign_fp_count"] == 1
    assert arms[P2_D1]["benign_fp_count"] == 0
    assert arms[P2_NODEF]["malicious_detected"] == 2


def test_wilcoxon_secondary_on_confidence(mock_result):
    # paired confidences: only m3 changes (0.2 -> 0.9) -> n=1 discordant,
    # exact two-sided p = 1.0; explicitly labelled secondary/descriptive
    w = (mock_result["per_model"]["mock-model"]["comparisons"]
         [f"{P2_NODEF}__vs__{P2_D1}"]["wilcoxon_confidence_secondary"])
    assert w["available"] is True
    assert w["n_pairs"] == 10
    assert w["p_value"] == pytest.approx(1.0)
    assert "secondary" in w.get("role", "")


def test_unparsed_pairs_dropped_and_counted():
    # m3 refused under the defense -> pair dropped from verdict stats,
    # counted honestly in n_pairs_dropped (refusal never mapped to a verdict)
    from scripts.r12_defense_analysis import paired_block

    pairs = [(1, 1), (0, 0), (1, None)]  # m3 refusal under arm b
    blk = paired_block(pairs, "label=1 (recall)")
    assert blk["n_pairs"] == 2
    assert blk["n_pairs_dropped_unparsed_or_refusal"] == 1
    assert blk["pos_a"] == 1 and blk["pos_b"] == 1
    assert blk["flips_a0_b1"] == 0 and blk["flips_a1_b0"] == 0
    assert blk["mcnemar_exact"]["p_value"] == pytest.approx(1.0)


def test_unknown_sample_label_fails_loud():
    # all three arms present, but a sample carries no label anywhere
    records = [{"sample_id": "x1", "arm": arm, "model_id": "mm",
                "status": "ANSWER", "parsed": {"vulnerable": 1},
                "vulnerable": 1}
               for arm in (P0, P2_NODEF, P2_D1)]
    with pytest.raises(Exception, match="no label"):
        analyze_records(records, None)  # no label field, no fallback map


# ---------------------------------------------------------------- fail-safe
def test_missing_input_is_pending_not_fabricated(tmp_path, capsys):
    out = tmp_path / "defense_analysis.json"
    rc = main(["--input", str(tmp_path / "nope.jsonl"), "--out", str(out)])
    assert rc == 0
    payload = json.loads(out.read_text())
    assert payload["status"] == "pending"
    assert "per_model" not in payload
    assert "NO numbers emitted" in payload["note"]


def test_meta_only_input_is_pending(tmp_path):
    inp = tmp_path / "defense_batch.jsonl"
    inp.write_text(json.dumps({"meta": {"mock": False}}) + "\n")
    out = tmp_path / "out.json"
    rc = main(["--input", str(inp), "--out", str(out)])
    assert rc == 0
    assert json.loads(out.read_text())["status"] == "pending"


def test_existing_but_malformed_input_fails_loud(tmp_path):
    inp = tmp_path / "defense_batch.jsonl"
    inp.write_text(json.dumps({"meta": {}}) + "\n"
                   + json.dumps({"arm": "P0_neutral"}) + "\n")  # no sample_id
    with pytest.raises(Exception):
        main(["--input", str(inp), "--out", str(tmp_path / "out.json")])


def test_missing_expected_arm_fails_loud():
    records = [r for r in build_mock_records()[1:] if r["arm"] != P0]
    with pytest.raises(Exception, match="lacks expected arms"):
        analyze_records(records, None)


def test_pair_completeness_exclusions_counted():
    # a gate-FAIL exclusion (sample absent from the defended arm only) must
    # be disclosed, never silently folded into the paired denominators
    records = [r for r in build_mock_records()[1:]
               if not (r["arm"].lower().find("d1") >= 0 and r["sample_id"] == "m6")]
    res = analyze_records(records, None)
    cmp_d1 = res["per_model"]["mock-model"]["comparisons"][
        f"{P2_NODEF}__vs__{P2_D1}"]
    assert cmp_d1["n_samples_only_in_b"] == 1
    assert cmp_d1["n_samples_only_in_a"] == 0
    assert cmp_d1["malicious"]["n_pairs"] == 5
    # the marginal defended-arm recall is unaffected in the union table
    assert res["per_model"]["mock-model"]["arms"][P2_D1]["n_samples"] == 10


def test_rr_disclosed_per_arm(mock_result):
    arms = mock_result["per_model"]["mock-model"]["arms"]
    for arm in (P0, P2_NODEF, P2_D1):
        assert arms[arm]["rr"] == 0.0


def test_pooled_scope_matches_single_model_fixture(mock_result):
    # with one fixture model, pooled == per-model; caveat attached
    pooled = mock_result["pooled"]
    single = mock_result["per_model"]["mock-model"]
    assert pooled["restoration"] == single["restoration"]
    assert "per-model" in pooled["caveat"]


# ------------------------------------------------------------ mock hygiene
def test_mock_cli_writes_mock_flagged_output(tmp_path):
    out = tmp_path / "defense_analysis_mock.json"
    rc = main(["--mock", "--out", str(out)])
    assert rc == 0
    payload = json.loads(out.read_text())
    assert payload["mock"] is True
    assert payload["status"] == "ok"
    assert payload["input_meta"]["mock"] is True
    # fixture arms all recognized -> nothing silently dropped
    assert payload["unknown_arm_rows_ignored"] == {}
    assert out != DEFAULT_OUT  # never the real path


def test_mock_and_real_paths_differ_by_default():
    assert MOCK_OUT != DEFAULT_OUT
    assert str(MOCK_OUT).endswith("_mock.json")


# ------------------------------------- round-12 F regression tests (audit)
def test_pooled_does_not_let_one_model_overwrite_another():
    # Regression (round-12 audit HIGH bug): sample_ids repeat across models,
    # so the pooled merge keyed on bare sample_id let the LAST model
    # silently replace the earlier ones ("pooled" == one model alone).
    # Two models, same 2 malicious samples, opposite verdicts: pooled recall
    # must be the union (2/4 detections per arm below), not either model.
    recs = []
    for model, p0v, p2v, d1v in (("ma", 1, 0, 0), ("mb", 0, 0, 1)):
        for arm, v in ((P0, p0v), (P2_NODEF, p2v), (P2_D1, d1v)):
            recs.append({"sample_id": "s1", "label": 1, "arm": arm,
                         "model_id": model, "status": "ANSWER",
                         "parsed": {"vulnerable": v}, "vulnerable": v})
        # a second malicious sample detected by nobody, for a non-trivial n
        for arm in (P0, P2_NODEF, P2_D1):
            recs.append({"sample_id": "s2", "label": 1, "arm": arm,
                         "model_id": model, "status": "ANSWER",
                         "parsed": {"vulnerable": 0}, "vulnerable": 0})
    res = analyze_records(recs, None)
    pooled = res["pooled"]
    assert pooled["n_samples_union"] == 4  # 2 samples x 2 models, all kept
    arms = pooled["arms"]
    assert arms[P0]["malicious_detected"] == 1        # ma s1 only
    assert arms[P2_NODEF]["malicious_detected"] == 0
    assert arms[P2_D1]["malicious_detected"] == 1     # mb s1 only
    # flips: P2_nodef->P2_D1 gains mb/s1 (0->1); ma/s1 is 0->0 here.
    # P0->P2_D1 is fully two-directional: ma/s1 lost (1->0), mb/s1 gained (0->1)
    mal = pooled["comparisons"][f"{P2_NODEF}__vs__{P2_D1}"]["malicious"]
    assert mal["n_pairs"] == 4
    assert mal["flips_a1_b0"] == 0 and mal["flips_a0_b1"] == 1
    mal0 = pooled["comparisons"][f"{P0}__vs__{P2_D1}"]["malicious"]
    assert mal0["flips_a1_b0"] == 1 and mal0["flips_a0_b1"] == 1
    # per-model pointers expose the opposite movement the pool masks
    assert pooled["per_model_pointers"]["ma"]["recall_P0"] == 0.5
    assert pooled["per_model_pointers"]["mb"]["recall_P0"] == 0.0
    assert "per-model" in pooled["caveat"]


def test_features_label_join_uses_sample_id_schema(tmp_path):
    # Regression (round-12 audit HIGH bug): features_v2.jsonl keys rows with
    # `sample_id`; the old loader read `r["id"]` and crashed on the real file.
    from scripts.r12_defense_analysis import load_labels_from_features

    f = tmp_path / "features_v2.jsonl"
    f.write_text('{"sample_id": "s1", "label": 1}\n{"sample_id": "s2", "label": 0}\n')
    assert load_labels_from_features(f) == {"s1": 1, "s2": 0}

    # a row without sample_id fails LOUD instead of guessing
    bad = tmp_path / "legacy.jsonl"
    bad.write_text('{"id": "s1", "label": 1}\n')
    with pytest.raises(Exception, match="sample_id"):
        load_labels_from_features(bad)


def test_descriptive_power_disclosure_present(mock_result):
    # every real run must carry the computed (never hand-typed) power note
    dp = mock_result["descriptive_power"]
    assert dp["min_exact_mcnemar_p"] == pytest.approx(1.0)  # tiny fixture
    assert dp["n_zero_discordant_comparisons"] >= 1
    assert "significance" in dp["rule"]
