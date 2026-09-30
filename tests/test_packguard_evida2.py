"""Round-18 EVIDA-2 tests (AMENDMENT-11): PRUNE-1 determinism, no-label-leak,
reuse policy, synthetic endpoints.  MUST PASS before the real run (A6.5).
"""
from __future__ import annotations

import importlib
import inspect
import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

evida2 = importlib.import_module("packguard.evida2")


# ---------------------------------------------------------------------------
# PRUNE-1: the pure rule
# ---------------------------------------------------------------------------
class TestPruneRule:
    def test_determinism(self):
        """Same inputs -> same class, across repeated calls."""
        grid = [(y, s, chg) for y in (0, 1, None) for s in (0, 1, None)
                for chg in (True, False)]
        for inp in grid:
            outs = {evida2.run_pruning_rule(*inp) for _ in range(5)}
            assert len(outs) == 1, f"nondeterministic on {inp}: {outs}"

    def test_no_label_parameter_exists(self):
        """The rule's signature exposes NO label channel to leak."""
        sig = inspect.signature(evida2.run_pruning_rule)
        params = set(sig.parameters)
        assert params == {"raw_y", "strip_y", "strip_changed"}
        for banned in ("y_true", "label", "family", "cwe", "baseline",
                       "clean_y", "event"):
            assert banned not in params

    def test_no_label_influence(self):
        """Class is invariant to anything outside the three inputs: feeding
        arbitrary 'label-like' kwargs is impossible by signature; instead
        verify behaviour depends only on the verdict pair + flag."""
        assert evida2.run_pruning_rule(1, 0, True) == "kept"
        assert evida2.run_pruning_rule(1, 0, False) == "pruned"
        assert evida2.run_pruning_rule(0, 1, True) == "pruned"
        assert evida2.run_pruning_rule(0, 1, False) == "pruned"
        assert evida2.run_pruning_rule(0, 0, True) == "no_alarm"
        assert evida2.run_pruning_rule(1, 1, False) == "no_alarm"
        assert evida2.run_pruning_rule(None, 0, True) == "invalid"
        assert evida2.run_pruning_rule(1, None, True) == "invalid"

    def test_frozen_spec_clause1(self):
        """Clause 1: byte-identical views can never keep an alarm."""
        assert evida2.run_pruning_rule(1, 0, strip_changed=False) == "pruned"

    def test_frozen_spec_clause2(self):
        """Clause 2: only the 1->0 direction is kept."""
        assert evida2.run_pruning_rule(1, 0, strip_changed=True) == "kept"
        assert evida2.run_pruning_rule(0, 1, strip_changed=True) == "pruned"

    def test_spec_constants_match_amendment(self):
        assert evida2.PRUNE_SPEC["name"] == "PRUNE-1"
        assert evida2.PRUNE_SPEC["labels_used"] == "NONE at runtime"
        assert evida2.MODELS == ("ibm-granite/granite-3.3-2b-instruct",
                                 "unsloth/Llama-3.2-3B-Instruct")
        assert evida2.BENCH_SHA16 == "7e8ed42421a7c2d0"


# ---------------------------------------------------------------------------
# registered draw + reuse policy
# ---------------------------------------------------------------------------
class TestDrawAndUnits:
    @staticmethod
    @pytest.fixture(scope="class")
    def bench():
        return evida2.load_bench_rows()

    def test_bench_load(self, bench):
        assert len(bench) == 160
        assert sum(int(r["label"]) for r in bench) == 80

    def test_draw_deterministic_and_stratified(self, bench):
        d1 = evida2.draw_samples(bench, 10)
        d2 = evida2.draw_samples(bench, 10)
        assert [r["sample_id"] for r in d1] == [r["sample_id"] for r in d2]
        assert len(d1) == 80
        from collections import Counter
        c = Counter((r["family"], int(r["label"])) for r in d1)
        assert set(c.values()) == {10}
        assert set(f for f, _ in c) == {"CWE-190", "CWE-200",
                                        "CWE-416", "CWE-476"}

    def test_draw_fallback_counts(self, bench):
        d = evida2.draw_samples(bench, 8)
        assert len(d) == 64

    def test_build_units_reuse_policy(self, bench):
        """Clause 1: byte-identical prompt <=> reuse flag; a comment-free
        func must reuse, a comment-bearing func must not."""
        from packguard.safety_port import load_safety_config

        scfg = load_safety_config(PROJECT_ROOT / "configs/packguard_safety.yaml")
        samples = evida2.draw_samples(bench, 10)[:4]
        units, meta = evida2.build_units(samples, list(evida2.MODELS)[:1],
                                         scfg)
        assert len(units) == 8  # 4 samples x 2 arms x 1 model
        n_reuse = 0
        for u in units:
            reuse = u["strip_view"]["reuse_raw_verdict"]
            same = (u["raw_view"]["prompt_sha16"]
                    == u["strip_view"]["prompt_sha16"])
            assert reuse == same
            n_reuse += int(reuse)
        assert meta["n_clause1_reuse_units"] == n_reuse
        assert meta["n_excluded"] == 0

    def test_units_all_or_nothing_per_sample(self, bench):
        from packguard.safety_port import load_safety_config

        scfg = load_safety_config(PROJECT_ROOT / "configs/packguard_safety.yaml")
        samples = evida2.draw_samples(bench, 10)[:3]
        units, _m = evida2.build_units(samples, list(evida2.MODELS), scfg)
        from collections import Counter
        c = Counter((u["model"], u["sample_id"]) for u in units)
        assert set(c.values()) == {2}  # C0 + C5_near always paired


# ---------------------------------------------------------------------------
# synthetic endpoints (hand-computable)
# ---------------------------------------------------------------------------
def _mk_dec(model, sid, arm, raw_y, strip_y, kept, final, y_true,
            family="CWE-190", strip_reused=False):
    alarm = (raw_y in (0, 1) and strip_y in (0, 1) and raw_y != strip_y)
    path = ("invalid_pair" if raw_y not in (0, 1) or strip_y not in (0, 1)
            else "agree" if not alarm else
            ("kept_path" if kept else "pruned_alarm"))
    return {"unit_id": f"V2|{model}|{sid}|{arm}", "model": model,
            "sample_id": sid, "family": family, "label": y_true,
            "language": "c", "arm": arm, "raw_y": raw_y,
            "raw_status": "ANSWER", "strip_y": strip_y,
            "strip_status": "ANSWER", "strip_reused": strip_reused,
            "raw_claim_cwe": None, "y_true": y_true, "final": final,
            "path": path, "alarm": alarm, "kept": kept,
            "adjudication": None, "fallback_score": None, "note": ""}


class TestEndpointsSynthetic:
    def build(self):
        # two samples x two models; granite gets a corruption event recovered,
        # llama gets a pruned 0->1 FP on a clean unit and an unparsed pair.
        M1, M2 = evida2.MODELS
        decs = [
            # granite: benign sample s1, C0 raw=0 correct; C5 corrupted raw=1,
            # strip=0 kept, adjudication REFUTE -> final=0 == baseline: RECOVERED
            _mk_dec(M1, "s1", "C0", 0, 0, False, 0, 0),
            _mk_dec(M1, "s1", "C5_near", 1, 0, True, 0, 0),
            # granite: benign s2, no corruption (raw=0==baseline), kept 1->0
            # alarm on the CLEAN-side noise is impossible here; make C5 alarm
            # on a non-event: raw=1 but baseline=1 (no flip), kept, final=1
            _mk_dec(M1, "s2", "C0", 1, 0, True, 1, 1),
            _mk_dec(M1, "s2", "C5_near", 1, 0, True, 1, 1),
            # llama: vul s3 correct at C0 (raw=1==y_true); C5 not corrupted,
            # 0->1 alarm pruned -> final=raw=1 correct
            _mk_dec(M2, "s3", "C0", 1, 1, False, 1, 1),
            _mk_dec(M2, "s3", "C5_near", 1, 1, False, 1, 1),
            # llama: vul s4 baseline correct, C0 0->1 alarm PRUNED -> final=raw=0?
            # raw=0 would be wrong baseline; instead: raw=1 correct, 0->1 impossible
            # (raw=1). Use an invalid pair on C5 -> pair excluded.
            _mk_dec(M2, "s4", "C0", 1, 0, True, 1, 1),
            _mk_dec(M2, "s4", "C5_near", None, None, False, None, 1),
        ]
        return decs

    def test_counts(self):
        ep = evida2.compute_endpoints_v2(self.build())
        acc = ep["accounting"]
        # s4 llama is invalid -> excluded; complete pairs = 3
        assert acc["n_pairs_complete"] == 3
        assert acc["n_pairs_invalid_excluded"] == 1
        # events: granite s1 (raw 1 != baseline 0). s2 baseline 1 == raw -> no.
        # llama s3 no flip. s4 excluded.
        assert acc["n_corruption_events"] == 1
        # kept alarms within complete pairs: s1-C5 (TP on the event),
        # s2-C5 (FP non-event), s2-C0 (FP clean unit) -> precision 1/3
        # (s4-C0 is dropped with its invalid-pair partner: all-or-nothing)
        assert acc["n_alarms_kept"] == 3
        assert ep["P1_alarm_precision"]["kept"]["num"] == 1
        assert ep["P1_alarm_precision"]["kept"]["den"] == 3
        assert ep["P1_alarm_precision"]["kept"]["rate"] == 0.3333
        # CRR: 1 recovered / 1 event
        assert ep["P2_CRR"]["pooled"]["CRR_evida2"]["rate"] == 1.0
        # DIER: clean baseline-correct units: s1(0==0), s2(1==1), s3(1==1)
        # finals all correct -> DIER 0
        assert ep["P3_DIER"]["pooled"]["DIER_evida2"]["rate"] == 0.0
        # UAC: both_parsed units 6 of 6 usable
        assert ep["P4_UAC"]["rate"] == 1.0

    def test_gates(self):
        ep = evida2.compute_endpoints_v2(self.build())
        g = evida2.evaluate_gates_v2(ep)
        # precision 1/3 = .3333 < .40 -> P1 fails, F3' fires; recovery/coverage OK
        assert g["gates"]["P1_precision_ge_.40"] is False
        assert g["falsifiers"]["F3p_alarm_is_noise"] is True
        assert g["gates"]["P2_CRR_ge_.35"] is True
        assert g["gates"]["P3_DIER_le_.05"] is True
        assert g["gates"]["P4_UAC_ge_.95"] is True
        assert g["PASS"] is False

    def test_gate_fail_paths(self):
        ep = evida2.compute_endpoints_v2(self.build())
        ep["P1_alarm_precision"]["kept"]["rate"] = 0.5
        ep["P1_alarm_precision"]["kept"]["num"] = 2
        g = evida2.evaluate_gates_v2(ep)
        assert g["gates"]["P1_precision_ge_.40"] is True
        assert g["gates"]["P2_CRR_ge_.35"] is True
        assert g["gates"]["P3_DIER_le_.05"] is True
        assert g["gates"]["P4_UAC_ge_.95"] is True
        assert g["PASS"] is True


# ---------------------------------------------------------------------------
# r17 alarm-log analysis artifact (E1 provenance)
# ---------------------------------------------------------------------------
class TestR17AnalysisArtifact:
    def test_artifact_reproduces_registered_numbers(self):
        p = PROJECT_ROOT / ("outputs/packguard/evida2/"
                            "r17_alarm_log_analysis.json")
        assert p.exists(), "E1 artifact missing"
        d = json.loads(p.read_text(encoding="utf-8"))
        rap = d["registered_alarm_population"]
        assert (rap["TP"], rap["FP"], rap["FN"]) == (57, 213, 89)
        assert rap["precision"] == 0.2111
        inert = d["inert_counterfactuals"]
        assert inert["granite_raw_eq_trusted_inert"] == 37
        assert inert["granite_primary_events"] == 55
        p1 = [c for c in d["pruning_rule_candidates"]
              if c["rule"].startswith("P1")][0]
        assert p1["TP_retention"] >= 0.80
        assert p1["FP_removed_share"] >= 0.60
        assert p1["meets_gate_80tp_60fp"] is True
