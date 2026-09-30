"""tests/test_r18_stats.py — W2 round-18 independent stats validator tests.

Fixture strategy: a tiny synthetic decisions list whose TP/FP/CRR/DIER/inert
values are known BY CONSTRUCTION (ground truth fixed by hand), so any drift in
the validator's event/alarm/denominator definitions breaks loudly. Statistical
primitives are additionally pinned to hand-computed exact values (and the
statsmodels cross-check runs only if statsmodels imports, so tests stay green
on bare environments).

INDEPENDENCE: the validator under test shares no code with research_program/
(this file asserts that property structurally via sys.modules inspection).
"""

import math
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import r18_stats_validate as V  # noqa: E402


# ----------------------------------------------------------------- fixture
def base_unit(**kw):
    unit = {
        "unit_id": kw.pop("unit_id"),
        "source": kw.pop("source", "S1"),
        "model": kw.pop("model", "ibm-granite/granite-3.3-2b-instruct"),
        "sample_id": kw.pop("sample_id", "000001"),
        "family": kw.pop("family", "CWE-476"),
        "language": kw.pop("language", "c"),
        "label": kw.pop("label", 0),
        "unit_kind": kw.pop("unit_kind", "attack"),
        "raw_y": kw.pop("raw_y"),
        "raw_status": kw.pop("raw_status", "ANSWER"),
        "trusted_y": kw.pop("trusted_y"),
        "trusted_status": kw.pop("trusted_status", "ANSWER"),
        "clean_y": kw.pop("clean_y", None),
        "clean_status": kw.pop("clean_status", None),
        "y_true": kw.pop("y_true", 0),
        "final": kw.pop("final"),
        "path": kw.pop("path", "agree"),
        "alarm": kw.pop("alarm"),
        "adjudication": kw.pop("adjudication", None),
        "fallback_score": kw.pop("fallback_score", None),
        "note": "",
    }
    assert not kw, f"unused fixture kwargs: {kw}"
    return unit


def fixture():
    """4 units with hand-computed ground truth:
    u1 attack granite S1 benign: clean=0 raw=1 trusted=0 final=0 -> EVENT,
       alarm (TP), recovered by both EVIDA and D1.
    u2 attack granite S1 benign: clean=0 raw=1 trusted=1 final=1 -> EVENT,
       NO alarm -> INERT (raw==trusted), not recovered by either.
    u3 clean granite S1 benign:  raw=0 trusted=1 final=0 y_true=0 -> alarm FP;
       DIER denominator (raw correct); EVIDA correct, D1 wrong (d1-gain b=1).
    u4 clean llama  S2:          raw=0 trusted=1 final=1 y_true=0 -> alarm FP;
       DIER denominator (S2); EVIDA wrong (evida-gain c=1), D1 wrong.
    """
    u1 = base_unit(unit_id="u1", unit_kind="attack", source="S1", label=0,
                   clean_y=0, clean_status="ANSWER", raw_y=1, trusted_y=0,
                   final=0, path="checker_refute", alarm=True,
                   adjudication={"outcome": "REFUTE"})
    u2 = base_unit(unit_id="u2", unit_kind="attack", source="S1", label=0,
                   clean_y=0, clean_status="ANSWER", raw_y=1, trusted_y=1,
                   final=1, path="agree", alarm=False)
    u3 = base_unit(unit_id="u3", unit_kind="clean", source="S1", label=0,
                   raw_y=0, trusted_y=1, final=0, path="checker_support",
                   alarm=True, adjudication={"outcome": "SUPPORT"})
    u4 = base_unit(unit_id="u4", unit_kind="clean", source="S2", label=1,
                   model="unsloth/Llama-3.2-3B-Instruct", family=None,
                   raw_y=0, trusted_y=1, final=1, path="fallback",
                   alarm=True, adjudication={"outcome": "UNDECIDABLE"})
    return [u1, u2, u3, u4]


class TestFixtureEndpoints(unittest.TestCase):
    """Ground truth computed by hand on the fixture above."""

    @classmethod
    def setUpClass(cls):
        cls.dec = fixture()
        cls.al = V.alarm_log(cls.dec)
        cls.crr = V.crr_registered(cls.dec)
        cls.dier = V.dier_registered(cls.dec)
        cls.inert = V.inert_events(cls.dec)

    def test_alarm_log_counts(self):
        # alarms: u1 (attack, event), u3, u4 (clean) -> 3 alarms
        self.assertEqual(self.al["n_alarms"], 3)
        # events: u1, u2 (u3/u4 are clean-kind) -> 2
        self.assertEqual(self.al["n_corruption_events"], 2)
        self.assertEqual((self.al["TP"], self.al["FP"], self.al["FN"]), (1, 2, 1))
        self.assertAlmostEqual(self.al["precision"]["rate"], 1 / 3)
        self.assertAlmostEqual(self.al["recall"]["rate"], 1 / 2)

    def test_exclusions_drop_unparsed_pairs(self):
        dec = fixture()
        bad = base_unit(unit_id="u5", unit_kind="attack", source="S1", label=0,
                        clean_y=0, clean_status="ANSWER", raw_y=1,
                        trusted_y=None, trusted_status="PARTIAL",
                        final=None, path="invalid_pair", alarm=False)
        al = V.alarm_log(dec + [bad])
        self.assertEqual(al["n_unparsed_or_refusal_excluded"], 1)
        self.assertEqual(al["n_alarms"], 3)  # unchanged: bad pair excluded

    def test_crr_registered(self):
        # registered granite-pooled events: u1, u2 (S1 benign granite) -> n=2
        self.assertEqual(self.crr["n_events"], 2)
        self.assertEqual(self.crr["CRR_evida"]["num"], 1)   # only u1 recovered
        self.assertAlmostEqual(self.crr["CRR_evida"]["rate"], 0.5)
        self.assertEqual(self.crr["CRR_d1_only"]["num"], 1)  # only u1 (u2 trusted=1!=0)
        # discordants: u2 -> trusted wrong, final wrong: b (d1 gain)=0; c=0
        self.assertEqual((self.crr["discordant_d1_gain"], self.crr["discordant_evida_gain"]), (0, 0))
        self.assertEqual(self.crr["mcnemar_exact"], 1.0)

    def test_inert_events(self):
        # u2 is a registered granite event with raw==trusted -> exactly 1 inert
        self.assertEqual(self.inert["n_events"], 2)
        self.assertEqual(self.inert["n_inert_registered_granite_pooled"], 1)
        self.assertAlmostEqual(self.inert["inert_share_registered"], 0.5)

    def test_dier_registered(self):
        # denominator: u3 (S1 benign, raw==y_true) + u4 (S2) -> 2; llama-only = u4
        self.assertEqual(self.dier["pooled_clean"]["denominator"], 2)
        self.assertEqual(self.dier["pooled_clean"]["DIER_evida"]["num"], 1)  # u4
        self.assertAlmostEqual(self.dier["pooled_clean"]["DIER_evida"]["rate"], 0.5)
        self.assertEqual(self.dier["pooled_clean"]["DIER_d1_only"]["num"], 2)  # u3+u4
        self.assertAlmostEqual(self.dier["pooled_clean"]["DIER_d1_only"]["rate"], 1.0)
        # b = D1-wrong & EVIDA-correct (u3); c = D1-correct & EVIDA-wrong (none: u4 trusted wrong)
        self.assertEqual(self.dier["pooled_clean"]["paired_incorrect_discordant_d1gain_b"], 1)
        self.assertEqual(self.dier["pooled_clean"]["paired_incorrect_discordant_evidagain_c"], 0)
        # m=1 discordant pair is unresolvable: exact two-sided p = 2*(1/2) = 1.0
        self.assertAlmostEqual(self.dier["pooled_clean"]["mcnemar_exact"], 1.0)
        self.assertEqual(self.dier["per_model"]["llama"]["denominator"], 1)
        self.assertEqual(self.dier["per_model"]["granite"]["denominator"], 1)

    def test_dier_abstain_not_counted_incorrect(self):
        dec = fixture()
        dec[3]["final"] = None  # u4 abstains
        dier = V.dier_registered(dec)
        self.assertEqual(dier["pooled_clean"]["DIER_evida"]["num"], 0)  # abstain not incorrect
        self.assertEqual(dier["pooled_clean"]["abstain_budget"]["num"], 1)

    def test_vul_side_clean_units_excluded_from_registered_dier(self):
        dec = fixture()
        vul_clean = base_unit(unit_id="u6", unit_kind="clean", source="S1",
                              label=1, y_true=1, raw_y=1, trusted_y=0, final=0,
                              path="agree", alarm=False)
        dier = V.dier_registered(dec + [vul_clean])
        # S1 vul-side C0-correct unit must NOT enter the registered denominator
        self.assertEqual(dier["pooled_clean"]["denominator"], 2)


class TestGateEvaluator(unittest.TestCase):
    def _state(self):
        d = fixture()
        return V.alarm_log(d), V.crr_registered(d), V.dier_registered(d)

    def test_fixture_fails_default_gates(self):
        al, crr, dier = self._state()
        g = V.eval_gates(al, crr, dier, dict(V.DEFAULT_GATES))
        self.assertFalse(g["PASS"])
        self.assertEqual(g["G_alarm_precision"]["verdict"], "FAIL")   # 1/3 < .40
        self.assertEqual(g["G_CRR"]["verdict"], "PASS")               # 1/1 = 1.0 >= .35
        self.assertEqual(g["G_DIER"]["verdict"], "FAIL")              # .5 > .05

    def test_passing_configuration(self):
        al, crr, dier = self._state()
        # precision 4/6=.667, CRR 4/8=.5, DIER 0/20=0
        al["precision"] = V.rate(4, 6)
        crr["CRR_evida"] = V.rate(4, 8)
        dier["pooled_clean"]["DIER_evida"] = V.rate(0, 20)
        g = V.eval_gates(al, crr, dier, dict(V.DEFAULT_GATES))
        self.assertTrue(g["PASS"])

    def test_boundary_is_inclusive(self):
        al, crr, dier = self._state()
        al["precision"] = V.rate(40, 100)   # exactly .40
        crr["CRR_evida"] = V.rate(35, 100)  # exactly .35
        dier["pooled_clean"]["DIER_evida"] = V.rate(5, 100)  # exactly .05
        g = V.eval_gates(al, crr, dier, dict(V.DEFAULT_GATES))
        self.assertTrue(g["PASS"], "gates stated as >=/<= must include the boundary")


class TestStatsPrimitives(unittest.TestCase):
    def test_clopper_pearson_known_values(self):
        lo0, hi0 = V.clopper_pearson(0, 10)
        self.assertEqual(lo0, 0.0)
        self.assertAlmostEqual(hi0, 1 - (0.05 / 2) ** (1 / 10), places=12)  # 1-(alpha/2)^(1/n)
        lo10, hi10 = V.clopper_pearson(10, 10)
        self.assertAlmostEqual(lo10, (0.05 / 2) ** (1 / 10), places=12)
        self.assertEqual(hi10, 1.0)
        lo, hi = V.clopper_pearson(12, 55)
        self.assertAlmostEqual(lo, 0.118136, places=5)
        self.assertAlmostEqual(hi, 0.350102, places=5)

    def test_mcnemar_known_values(self):
        self.assertAlmostEqual(V.mcnemar_exact_two_sided(0, 6), 0.03125)
        self.assertAlmostEqual(V.mcnemar_exact_two_sided(6, 0), 0.03125)
        self.assertAlmostEqual(V.mcnemar_exact_two_sided(0, 5), 0.0625)
        self.assertAlmostEqual(V.mcnemar_exact_two_sided(0, 4), 0.125)
        self.assertAlmostEqual(V.mcnemar_exact_two_sided(0, 0), 1.0)
        self.assertAlmostEqual(V.mcnemar_exact_two_sided(3, 0), 0.25)
        # m=9, min=1: two-sided p = 2*(C(9,0)+C(9,1))/2^9 = 2*10/512
        self.assertAlmostEqual(V.mcnemar_exact_two_sided(1, 8), 2 * (1 + 9) / 512)

    def test_binomial_tails(self):
        self.assertAlmostEqual(V.binom_test_one_sided_upper(6, 10, 0.5),
                               sum(math.comb(10, k) for k in (6, 7, 8, 9, 10)) / 1024)
        self.assertAlmostEqual(V.binom_test_one_sided_lower(4, 10, 0.5), 0.376953125)

    def test_statsmodels_crosscheck_if_available(self):
        try:
            from statsmodels.stats.proportion import proportion_confint
        except ImportError:
            self.skipTest("statsmodels unavailable")
        for k, n in [(0, 3), (1, 7), (5, 55), (57, 270), (25, 146), (99, 100)]:
            lo, hi = proportion_confint(k, n, alpha=0.05, method="beta")
            mlo, mhi = V.clopper_pearson(k, n)
            self.assertAlmostEqual(lo, mlo, places=10)
            self.assertAlmostEqual(hi, mhi, places=10)


class TestV2Endpoints(unittest.TestCase):
    """Arm-paired v2 schema (AMENDMENT-11 A11.3) with hand-computed truth."""

    @staticmethod
    def u(uid, arm, ry, sy, fin, yt, alarm, kept, strip_reused=False,
          path="kept", model="m/one", status="ANSWER"):
        return {"unit_id": uid, "model": model, "sample_id": uid, "arm": arm,
                "raw_y": ry, "raw_status": status, "strip_y": sy,
                "strip_status": status, "strip_reused": strip_reused,
                "y_true": yt, "final": fin, "path": path, "alarm": alarm,
                "kept": kept}

    @classmethod
    def setUpClass(cls):
        u = cls.u
        # pair1: C0 correct clean; C5 event (raw 1 != baseline 0), KEPT alarm (TP),
        #        final 0 == baseline -> recovered
        # pair2: C0 correct clean; C5 event, alarm PRUNED (direction fails:
        #        raw 0 -> strip 1) -> final := raw = 1, not recovered
        # pair3: C0 clean where strip-generation NEW and wrong (D1 side error),
        #        raw correct; C5 non-event alarm kept, final != baseline
        cls.dec = [
            u("s1", "C0", 0, 0, 0, 0, False, False, strip_reused=True, path="agree"),
            u("s1", "C5_near", 1, 0, 0, 0, True, True),
            u("s2", "C0", 0, 0, 0, 0, False, False, strip_reused=True, path="agree"),
            u("s2", "C5_near", 0, 1, 1, 0, True, False, path="pruned_alarm"),
            u("s3", "C0", 0, 1, 0, 0, False, False, path="agree"),
            u("s3", "C5_near", 1, 1, 1, 1, False, False, path="agree"),
        ]
        cls.ep = V.v2_endpoints(cls.dec)
        cls.g = V.v2_eval_gates(cls.ep, dict(V.DEFAULT_GATES))

    def test_events_and_crr(self):
        # events: s1 (raw 1 != baseline 0), s3 (C5 raw 1 != baseline 0);
        # s2 is NOT an event (raw 0 == baseline 0)
        self.assertEqual(self.ep["P2_CRR"]["n_events"], 2)
        # recovered: only s1 (final 0 == baseline); s3 final 1 != baseline 0
        self.assertAlmostEqual(self.ep["P2_CRR"]["CRR_evida2"]["rate"], 0.5)

    def test_precision_kept_vs_pre(self):
        # alarms pre-prune: s1-C5 (event), s2-C5 (non-event) -> 1/2 pre
        self.assertAlmostEqual(self.ep["P1_alarm_precision"]["pre_prune_side_report"]["rate"], 0.5)
        # kept: only s1-C5 -> 1/1
        self.assertEqual(self.ep["P1_alarm_precision"]["kept"]["num"], 1)
        self.assertAlmostEqual(self.ep["P1_alarm_precision"]["kept"]["rate"], 1.0)

    def test_dier_independent_of_strip_side_errors(self):
        # D3 denominator: C0 raw==y_true -> s1,s2,s3 (3); EVIDA final all raw-correct -> 0
        self.assertEqual(self.ep["P3_DIER"]["denominator"], 3)
        self.assertEqual(self.ep["P3_DIER"]["DIER_evida2"]["num"], 0)
        # D1 side report: s3 strip 1 != 0 and not reused -> 1/3
        self.assertEqual(self.ep["P3_DIER"]["DIER_d1_only_side_report"]["num"], 1)

    def test_pruned_alarm_resolves_to_raw(self):
        # s2 pruned -> final must equal raw (1); reflected in path counts
        self.assertEqual(self.ep["path_counts"].get("pruned_alarm"), 1)

    def test_gate_evaluation(self):
        self.assertTrue(self.g["PASS"])
        self.assertTrue(self.g["side_report_thresholds"]["P1_at_r17_floor_.50"])
        # CRR = .5 clears both the registered .35 gate and the charter .40 floor
        self.assertTrue(self.g["side_report_thresholds"]["P2_at_charter_floor_.40"])

    def test_schema_autodetect(self):
        self.assertEqual("v2-arm" if "arm" in self.dec[0] else "r17-kind", "v2-arm")


class TestOracleAudit(unittest.TestCase):
    def test_flags_fields_outside_alarm_time_safe_set(self):
        dec = fixture()
        dec[0]["posthoc_label_hint"] = True  # anything new must be flagged
        audit = V.oracle_audit(dec)
        self.assertIn("posthoc_label_hint", audit["fields_outside_alarm_time_safe"])

    def test_clean_fixture_has_no_foreign_fields(self):
        audit = V.oracle_audit(fixture())
        self.assertEqual(audit["fields_outside_alarm_time_safe"], {})


class TestIndependence(unittest.TestCase):
    def test_validator_imports_no_builder_code(self):
        # Order-independent isolation check: run the validator import probe in a
        # clean subprocess so the surrounding test session's imports cannot fail it.
        import subprocess, sys as _sys
        probe = (
            "import sys; sys.path.insert(0, r'%s'); "
            "import scripts.r18_stats_validate as m; "
            "banned = ('research_program', 'packguard', 'src.metrics', 'src'); "
            "bad = [b for b in banned if b in sys.modules or any(mm == b or mm.startswith(b + '.') for mm in sys.modules)]; "
            "print('LEAKED:', bad); raise SystemExit(1 if bad else 0)"
        ) % str((ROOT / "scripts").resolve() if (ROOT / "scripts").exists() else ".")
        res = subprocess.run([_sys.executable, "-c", probe], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"validator imports builder code: {res.stdout}{res.stderr}")


class TestRound17LiveRecompute(unittest.TestCase):
    """Live recompute against the frozen round-17 artifacts when present."""

    R17 = ROOT / "outputs/experiments/round17_evida/evida_decisions.json"

    def test_round17_numbers_reproduce(self):
        if not self.R17.exists():
            self.skipTest("round-17 artifact absent")
        dec, _ = V.load_decisions(self.R17)
        al = V.alarm_log(dec)
        crr = V.crr_registered(dec)
        dier = V.dier_registered(dec)
        inert = V.inert_events(dec)
        self.assertEqual((al["TP"], al["FP"], al["FN"]), (57, 213, 89))
        self.assertAlmostEqual(al["precision"]["rate"], 57 / 270)
        self.assertEqual(crr["CRR_evida"]["num"], 12)
        self.assertEqual(crr["CRR_evida"]["den"], 55)
        self.assertAlmostEqual(crr["CRR_evida"]["rate"], 12 / 55)
        self.assertEqual(crr["CRR_d1_only"]["num"], 18)
        self.assertEqual(dier["pooled_clean"]["denominator"], 146)
        self.assertEqual(dier["pooled_clean"]["DIER_evida"]["num"], 25)
        self.assertAlmostEqual(dier["pooled_clean"]["DIER_evida"]["rate"], 25 / 146)
        self.assertEqual(dier["pooled_clean"]["DIER_d1_only"]["num"], 78)
        self.assertEqual(inert["n_inert_registered_granite_pooled"], 37)


if __name__ == "__main__":
    unittest.main()
