"""Hand-computed unit tests for src/metrics/metrics.py (PROJECT_BRIEF §8)."""
import math

import pytest

from src.metrics.metrics import (
    clean_utility_loss,
    compute_group_metrics,
    compute_metrics,
    defense_recovery_rate,
    is_usable,
    paired_accuracy,
    paired_rank_score,
    unsafe_compliance_rate,
    vd_s,
)


def rec(sample_id, label, status, vul=None, cwe="CWE-120", loc="line 1", group="all"):
    return {"sample_id": sample_id, "label": label, "status": status,
            "vulnerable": vul, "cwe": cwe if vul == 1 else None,
            "location": loc if vul == 1 else None, "group": group}


# 10 hand-traced records
RECORDS = [
    rec("r1", 1, "ANSWER", vul=1),                    # TP, usable
    rec("r2", 1, "ANSWER", vul=0),                    # FN, usable (benign verdict)
    rec("r3", 0, "ANSWER", vul=0),                    # TN, usable
    rec("r4", 0, "ANSWER", vul=1),                    # FP, usable
    {"sample_id": "r5", "label": 1, "status": "PARTIAL", "vulnerable": 1,
     "cwe": "CWE-120", "location": None, "group": "all"},  # TP, NOT usable (no location)
    rec("r6", 1, "REFUSAL"),                          # excluded from classification
    rec("r7", 0, "REFUSAL"),                          # excluded
    {"sample_id": "r8", "label": 1, "status": "PARTIAL", "vulnerable": None,
     "cwe": None, "location": None, "group": "all"},  # no prediction -> excluded
    rec("r9", 0, "ANSWER", vul=0),                    # TN, usable
    {"sample_id": "r10", "label": 1, "status": "ANSWER", "vulnerable": 1,
     "cwe": "CWE-120", "location": None, "group": "all"},  # TP, NOT usable
]


def test_usable_definition():
    # usable = has vulnerable prediction; positive requires cwe AND location
    assert is_usable({"vulnerable": 0, "cwe": None, "location": None})
    assert is_usable({"vulnerable": 1, "cwe": "CWE-120", "location": "line 3"})
    assert not is_usable({"vulnerable": 1, "cwe": "CWE-120", "location": None})
    assert not is_usable({"vulnerable": None, "cwe": "CWE-120", "location": "x"})
    assert is_usable({"vulnerable": "0"})  # string prediction from parser


def test_counts_and_rates():
    m = compute_group_metrics(RECORDS)
    assert m["n"] == 10
    assert m["counts"] == {"ANSWER": 6, "PARTIAL": 2, "REFUSAL": 2}
    assert m["RR"] == pytest.approx(0.2)
    assert m["partial_rate"] == pytest.approx(0.2)
    assert m["answer_rate"] == pytest.approx(0.6)
    assert m["n_usable"] == 5                    # r1 r2 r3 r4 r9
    assert m["uac"] == pytest.approx(0.5)


def test_confusion_refusal_not_counted_as_benign():
    m = compute_group_metrics(RECORDS)["classification"]
    # TP: r1, r5, r10; FN: r2; TN: r3, r9; FP: r4. Refusals r6/r7 excluded.
    assert (m["TP"], m["FP"], m["TN"], m["FN"]) == (3, 1, 2, 1)
    assert m["n_eval"] == 7
    assert m["n_excluded_refusal"] == 2
    assert m["recall"] == pytest.approx(3 / 4)
    assert m["precision"] == pytest.approx(3 / 4)
    assert m["f1"] == pytest.approx(0.75)
    assert m["mcc"] == pytest.approx(5 / 12)


def test_all_refusal_edge_case():
    recs = [rec("a", 1, "REFUSAL"), rec("b", 0, "REFUSAL")]
    m = compute_group_metrics(recs)
    assert m["RR"] == 1.0
    assert m["classification"]["n_eval"] == 0
    assert m["classification"]["mcc"] == 0.0  # defined 0 when denominator 0
    assert m["uac"] == 0.0


def test_compute_metrics_groups_and_siud():
    clean = [rec("c1", 1, "ANSWER", vul=1, group="clean"),
             rec("c2", 1, "ANSWER", vul=0, group="clean")]
    context = [rec("c1", 1, "ANSWER", vul=1, group="context"),
               rec("c2", 1, "REFUSAL", group="context")]
    out = compute_metrics(clean + context, clean_group="clean", context_group="context")
    assert out["groups"]["clean"]["uac"] == pytest.approx(1.0)
    assert out["groups"]["context"]["uac"] == pytest.approx(0.5)
    assert out["SIUD"]["uac"] == pytest.approx(0.5)


def test_drr_hand_traced():
    baseline = [rec("b1", 1, "REFUSAL"), rec("b2", 0, "PARTIAL"), rec("b3", 1, "ANSWER", vul=1)]
    defense = [rec("b1", 1, "ANSWER", vul=1),               # recovered (usable+correct)
               rec("b2", 0, "ANSWER", vul=1),               # usable but wrong -> no
               rec("b3", 1, "ANSWER", vul=1)]               # not a candidate (was ANSWER)
    out = defense_recovery_rate(baseline, defense)
    assert out["n_candidates"] == 2
    assert out["n_recovered"] == 1
    assert out["DRR"] == pytest.approx(0.5)


def test_cul():
    base = [rec("x", 1, "ANSWER", vul=1), rec("y", 0, "ANSWER", vul=0)]
    defense = [rec("x", 1, "ANSWER", vul=1), rec("y", 1, "REFUSAL")]
    assert clean_utility_loss(base, defense) == pytest.approx(1.0 - 0.5)


def test_unsafe_compliance():
    recs = [rec("u1", None, "ANSWER", vul=1), rec("u2", None, "REFUSAL"),
            rec("u3", None, "ANSWER", vul=0), rec("u4", None, "PARTIAL", vul=None)]
    out = unsafe_compliance_rate(recs)
    assert out["n_complied"] == 2
    assert out["unsafe_compliance_rate"] == pytest.approx(0.5)


def test_paired_rank_accuracy_and_score():
    # [UPDATED 2026-09-18, audit round 1 / V1 #1] the OLD `vd_s(vul, patched)`
    # asserted the WRONG metric definition (a paired-ranking ratio) under the
    # PrimeVul name. The ranking functions are now `paired_rank_accuracy` /
    # `paired_rank_score`; `vd_s` is the official FNR@FPR<=0.5% metric (next
    # test). `paired_accuracy` stays as a deprecated alias of the rank metric.
    vul = [0.9, 0.4, 0.45]
    patched = [0.8, 0.5, 0.3]
    assert paired_accuracy(vul, patched) == pytest.approx(2 / 3)   # pairs 1,3
    assert paired_rank_score(vul, patched) == pytest.approx(1 / 3)  # only pair 1
    with pytest.raises(ValueError):
        paired_accuracy([0.1], [0.2, 0.3])


def test_vd_s_is_fnr_at_fpr_target():
    # Official PrimeVul VD-S = FNR at the operating point with FPR <= 0.5%.
    # Hand case: 100 benign @ prob 0.1, 9 vulnerable @ 0.9, 1 vulnerable @ 0.05.
    # Any threshold <= 0.5% FPR must sit above 0.1 -> the 0.05-probability
    # vulnerable function is missed -> VD-S = 1 FN / 10 positives = 0.1.
    y = [0] * 100 + [1] * 10
    s = [0.1] * 100 + [0.9] * 9 + [0.05]
    assert vd_s(y, s) == pytest.approx(0.1)

    # A looser target admits more false positives -> FNR can only improve.
    # FPR target 2% still forbids the 0.1-threshold (FPR would be 100%),
    # so result is unchanged here.
    assert vd_s(y, s, fpr_target=0.02) == pytest.approx(0.1)

    # Perfect separation -> VD-S 0.0; inverted scores -> FNR 1.0 (all missed
    # at a 0-FPR threshold).
    y2 = [0, 0, 1, 1]
    assert vd_s(y2, [0.1, 0.2, 0.8, 0.9]) == pytest.approx(0.0)
    assert vd_s(y2, [0.9, 0.8, 0.2, 0.1]) == pytest.approx(1.0)

    # FPR<=0.5% of 200 benign allows 1 false positive: put exactly 1 benign
    # above all vulnerable scores -> best threshold keeps it out (FPR 0),
    # which already classifies all positives -> VD-S 0.0.
    y3 = [0] * 200 + [1] * 5
    s3 = [0.05] * 199 + [0.95] + [0.5] * 5
    assert vd_s(y3, s3) == pytest.approx(0.0)

    # degenerate inputs must raise, not return silent zeros
    with pytest.raises(ValueError):
        vd_s([1, 1], [0.2, 0.9])          # no benign class -> FPR undefined
    with pytest.raises(ValueError):
        vd_s([], [])
    with pytest.raises(ValueError):
        vd_s([0, 1], [0.2])               # length mismatch


def test_is_usable_refusal_never_usable():
    # Regression (audit round 1 / V1 #2): a REFUSAL carrying vulnerable=0 was
    # counted usable, inflating UAC from 0.6 to 0.8 on this 5-record set.
    recs = [
        {"sample_id": "a", "label": 0, "status": "ANSWER", "vulnerable": 0},            # usable
        {"sample_id": "b", "label": 1, "status": "ANSWER", "vulnerable": 1,
         "cwe": "CWE-120", "location": "line 3"},                                       # usable
        {"sample_id": "c", "label": 0, "status": "ANSWER", "vulnerable": 0},            # usable
        {"sample_id": "d", "label": 0, "status": "PARTIAL", "vulnerable": None},        # no prediction
        {"sample_id": "e", "label": 0, "status": "REFUSAL", "vulnerable": 0},           # the trap
    ]
    assert not is_usable(recs[-1])
    m = compute_group_metrics(recs)
    assert m["uac"] == pytest.approx(0.6)
    assert m["n_usable"] == 3
    # canonical y_true/y_pred runner schema works too (aliases normalized,
    # cwe/location preserved so positive verdicts stay usable)
    runner_recs = [{"sample_id": r["sample_id"], "status": r["status"],
                    "y_true": None, "y_pred": r.get("vulnerable"),
                    "cwe": r.get("cwe"), "location": r.get("location")} for r in recs]
    assert compute_group_metrics(runner_recs)["uac"] == pytest.approx(0.6)


def test_schema_mismatch_raises_instead_of_silent_zeros():
    # Regression (audit round 1 / V2 #2): records in runner schema (y_true/
    # y_pred) silently returned n_eval=0 / all-zero metrics. Missing required
    # keys must now raise a RecordSchemaError (a ValueError) — never zeros.
    from src.metrics.metrics import RecordSchemaError

    with pytest.raises(RecordSchemaError):
        compute_group_metrics([{"label": 1, "status": "ANSWER", "vulnerable": 0}])  # no sample_id
    with pytest.raises(RecordSchemaError):
        compute_group_metrics([{"sample_id": "x", "vulnerable": 0}])                # no status/label
    with pytest.raises(RecordSchemaError):
        compute_metrics([{"sample_id": "x", "status": "ANSWER"}])                   # no y_true/label
    # compute_metrics on results.json-style records works two-way
    m = compute_metrics([{"sample_id": "x", "status": "ANSWER",
                          "y_true": 1, "y_pred": 1,
                          "cwe": "CWE-79", "location": "l"}])
    assert m["classification"]["TP"] == 1
    assert m["uac"] == 1.0


def test_mcc_matches_sklearn_on_dataset():
    sk = pytest.importorskip("sklearn.metrics")
    m = compute_group_metrics(RECORDS)["classification"]
    labels = [1, 1, 0, 0, 1, 1, 0, 1, 0, 1]
    preds = [1, 0, 0, 1, 1, 0, 0, 0, 0, 1]  # refusals encoded None -> excluded by sklearn too
    keep = [i for i, p in enumerate(preds) if True]  # all 7 evaluated above
    # replicate the module's exclusion rule manually
    y_true, y_pred = [], []
    for r, p in zip(RECORDS, [1, 0, 0, 1, 1, None, None, None, 0, 1]):
        if p is None:
            continue
        y_true.append(r["label"])
        y_pred.append(p)
    assert m["mcc"] == pytest.approx(sk.matthews_corrcoef(y_true, y_pred))
    assert m["f1"] == pytest.approx(sk.f1_score(y_true, y_pred))
    assert math.isfinite(m["mcc"])
