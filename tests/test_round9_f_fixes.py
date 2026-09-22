"""Round-9 F fix pins: the regenerated metrics (metrics_version 2) and the
fixed KB-coverage breakdown must match the audit-confirmed values, and the
metrics must be reproducible from the unchanged raw records. CPU-only,
read-only over outputs/."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from packguard.safety_port import compute_safety_metrics
from src.experiments.round9_safety_n50 import ARMS

ROOT = Path(__file__).resolve().parents[1]
SAFETY = ROOT / "outputs/packguard/safety"

LLAMA = "unsloth/Llama-3.2-3B-Instruct"
GRANITE = "ibm-granite/granite-3.3-2b-instruct"


def _records(path: Path) -> list[dict]:
    out = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if "sample_id" in r:
                out.append(r)
    return out


def _recompute(recs: list[dict]) -> dict:
    arms_recs, labels = {}, None
    for arm in ARMS:
        arm_recs = sorted((r for r in recs if r["arm"] == arm),
                          key=lambda r: r["sample_id"])
        arms_recs[arm] = arm_recs
        if labels is None:
            labels = [bool(r.get("label")) for r in arm_recs]
    return compute_safety_metrics(arms_recs, labels=labels)


# ---------------------------------------------------------------------------
# n60 metrics file (regenerated, metrics_version 2)
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def n60():
    return json.loads((SAFETY / "safety_metrics_n60.json").read_text())


def test_n60_meta_counts_fixed(n60):
    meta = n60["meta"]
    assert meta["metrics_version"] == 2
    assert meta["n_samples_total"] == 60
    assert meta["n_malicious_total"] == 30   # was 35 (records vs samples bug)
    assert meta["n_benign_total"] == 30


def test_n60_recall_and_fp_match_audit(n60):
    """Audit V1 round-9 recount, now under the corrected names."""
    expect_recall = {
        LLAMA: {"P0_neutral": 4 / 30, "P1_offensive_wording": 4 / 30,
                "P2_advisory_in_package": 1 / 30},
        GRANITE: {"P0_neutral": 16 / 30, "P1_offensive_wording": 18 / 30,
                  "P2_advisory_in_package": 24 / 30},
    }
    for model, arms in expect_recall.items():
        for arm, val in arms.items():
            got = n60["per_model"][model]["malicious_recall"][arm]
            assert got == pytest.approx(val), f"{model} {arm}"
    # benign FP measured 0 in every (model x arm) cell
    for model in (LLAMA, GRANITE):
        for arm in ARMS:
            assert n60["per_model"][model]["fp_benign"][arm] == 0.0
    # refusals still zero everywhere
    for model in (LLAMA, GRANITE):
        for arm in ARMS:
            assert n60["per_model"][model]["rr"][arm] == 0.0
    pooled = n60["pooled"]
    assert "fp_bias" not in pooled  # the mislabelled key is gone
    assert pooled["malicious_recall"]["P2_advisory_in_package"] == \
        pytest.approx(25 / 60)
    assert pooled["malicious_recall"]["P0_neutral"] == pytest.approx(20 / 60)


def test_n60_metrics_reproducible_from_raw(n60):
    recs = _records(SAFETY / "safety_batch_n60.jsonl")
    assert len(recs) == 360
    for model in (LLAMA, GRANITE):
        m = _recompute([r for r in recs if r["model_id"] == model])
        assert m["malicious_recall"] == n60["per_model"][model][
            "malicious_recall"]
        assert m["fp_benign"] == n60["per_model"][model]["fp_benign"]
    pooled = _recompute(recs)
    assert pooled["malicious_recall"] == n60["pooled"]["malicious_recall"]


# ---------------------------------------------------------------------------
# round-8 metrics file (regenerated, metrics_version 2)
# ---------------------------------------------------------------------------
def test_round8_metrics_reread_under_corrected_names():
    m = json.loads((SAFETY / "safety_metrics.json").read_text())
    assert m["meta"]["metrics_version"] == 2
    pooled = m["pooled"]
    # the published ".2 -> .3 -> .6" sequence was a malicious TP-rate
    assert pooled["malicious_recall"]["P0_neutral"] == pytest.approx(0.2)
    assert pooled["malicious_recall"]["P1_offensive_wording"] == \
        pytest.approx(0.3)
    assert pooled["malicious_recall"]["P2_advisory_in_package"] == \
        pytest.approx(0.6)
    # granite P2 "1.0" was 5/5 MALICIOUS detected — not every benign flagged
    assert m["per_model"][GRANITE]["malicious_recall"][
        "P2_advisory_in_package"] == pytest.approx(1.0)
    # the TRUE benign FP rate is 0 everywhere
    for model in (LLAMA, GRANITE):
        for arm in ARMS:
            assert m["per_model"][model]["fp_benign"][arm] == 0.0
    assert "fp_bias" not in pooled


# ---------------------------------------------------------------------------
# KB coverage_v3 (regenerated after the label-rule fix)
# ---------------------------------------------------------------------------
def test_coverage_v3_label_breakdown_fixed():
    cov = json.loads(
        (ROOT / "outputs/experiments/round9_kb/coverage_v3.json")
        .read_text())
    # was 1215/1084 under the substring rule that missed 80
    # compromised_lib samples (audit V2#B7)
    assert cov["instances_by_label"]["malicious"] == 1673
    assert cov["instances_by_label"]["benign"] == 626
    # language breakdown no longer all-'?' (audit V2#B6): ecosystem domain
    langs = cov["instances_by_language"]
    assert set(langs) == {"npm", "pypi"}
    assert sum(langs.values()) == 2299
    # the actual coverage claims must be untouched by the fix
    assert cov["graphs_v2"]["unique_api_types"] == 137
    assert cov["graphs_v2"]["api_instances_total"] == 2299
    assert cov["coverage"]["v3_round9"]["types"] == 137
    assert cov["coverage"]["v3_round9"]["instances"] == 2299
    assert cov["kb_v3_stats"]["n_entries"] == 142
    assert cov["kb_v3_stats"]["n_unsure"] == 0
