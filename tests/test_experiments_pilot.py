"""Round-2 pilot validation (agent A3, round 2).

Two layers:
  1. Offline unit tests with a FAKE LLM (no model, no GPU): the pilot module's
     records must satisfy the canonical schema, SKIPPED must be disclosed,
     metrics must be traceable, and a synthetic results tree must pass the
     validators used for the real outputs.
  2. Integration validation of the REAL pilot outputs if present
     (outputs/experiments/pilot_round2/): every record with meta.real
     (i.e. not a dry-run) must have an existing raw_output_path and a valid
     status; summary.json must have the agreed schema. Skipped (not failed)
     when the real outputs do not exist yet.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUT_ROOT = PROJECT_ROOT / "outputs" / "experiments" / "pilot_round2"

VALID_STATUSES = {"ANSWER", "PARTIAL", "REFUSAL", "SKIPPED"}
VALID_CONDITIONS = {"C0", "C1", "C2", "C3", "C2a", "C2b", "PROBE", "CONTRAST"}
VALID_CONDITIONS |= {f"E0ARM:{a}" for a in
                     ("neutral", "defensive_wording", "security_context")}


# ---------------------------------------------------------------------------
# helpers (shared with the module under test)
# ---------------------------------------------------------------------------
class FakeLLM:
    """Deterministic stand-in for RealLLM: same generate() signature."""

    def __init__(self, refuse_on: str = "exploit"):
        self.model_id = "fake/fake-0.5b"
        self.rev = {"revision": "main", "revision_sha": "deadbeef"}
        self.n_calls = 0
        self.n_cache_hits = 0
        self.gen_seconds = 0.0
        self.refuse_on = refuse_on
        self.max_input_tokens = 8192

    def gen_cfg(self, max_new_tokens: int) -> dict:
        return {"max_new_tokens": max_new_tokens, "seed": 1234}

    def generate(self, system: str, user: str, max_new_tokens: int):
        self.n_calls += 1
        if self.refuse_on and self.refuse_on in user.lower():
            text = "I'm sorry, but I can't help with that request."
        else:
            text = json.dumps({
                "analysis_status": "analysis_complete", "vulnerable": 1,
                "cwe": "CWE-120", "location": "line 3", "root_cause": "x",
                "confidence": 0.5})
        meta = {"model_id": self.model_id, "revision": "main", "gen_cfg": {},
                "cache_hit": False, "prompt_tokens": 10, "completion_tokens": 20,
                "latency_s": 0.001, "date": "2026-09-18T00:00:00+00:00"}
        return text, meta


@pytest.fixture(scope="module")
def fake_tree(tmp_path_factory):
    """Build a complete pilot results tree with the FAKE LLM (fast, offline)."""
    from src.experiments.pilot_round2 import (
        run_e0, run_e2, run_e3, run_e5, run_e8, select_samples, RealLLM)

    out_root = tmp_path_factory.mktemp("pilot_fake")
    llm = FakeLLM(refuse_on="exploit")  # defensive_wording arm contains 'exploit'
    run_e0(llm, n_per_label=2, max_new_tokens_fn=32, max_new_tokens_probe=16,
           out_dir=out_root / "e0")
    samples, sel_meta = select_samples(3)
    run_e2(llm, samples, sel_meta, 32, out_root / "e2")
    run_e3(llm, samples, sel_meta, 32, out_root / "e3")
    run_e5(llm, samples, sel_meta, 32, out_root / "e5",
           e3_results_path=out_root / "e3" / "results.json")
    run_e8(llm, 16, out_root / "e8")

    from src.experiments.pilot_round2 import build_summary
    build_summary(out_root)
    return out_root


# ---------------------------------------------------------------------------
# 1. unit behaviour with the fake LLM
# ---------------------------------------------------------------------------
def _records(out_root: Path, exp: str) -> list[dict]:
    res = json.loads((out_root / exp / "results.json").read_text(encoding="utf-8"))
    return res["records"]


def test_fake_e0_writes_gate_metrics(fake_tree):
    res = json.loads((fake_tree / "e0" / "results.json").read_text(encoding="utf-8"))
    m = res["metrics"]
    assert set(m["arms"]) == {"neutral", "defensive_wording", "security_context"}
    for arm, am in m["arms"].items():
        assert {"RR", "uac", "n"} <= set(am), arm
    d = m["delta_RR_defensive_vs_neutral"]
    assert {"n_pairs", "mcnemar", "delta_ci"} <= set(d)
    assert d["mcnemar"]["p_value"] is not None
    gate = m["gate_per_model"]
    assert set(gate) >= {"delta_rr", "p_value", "ci_low", "ci_high",
                         "pass_this_model", "rule"}
    # fake LLM refuses the defensive arm -> delta RR must be detected > 0
    assert gate["delta_rr"] > 0.0


def test_fake_records_follow_canonical_schema(fake_tree):
    for exp in ("e0", "e2", "e3", "e5", "e8"):
        for r in _records(fake_tree, exp):
            assert {"sample_id", "condition", "defense", "y_true", "y_pred",
                    "status", "analysis_status", "raw_output_path",
                    "meta"} <= set(r), (exp, r)
            assert r["status"] in VALID_STATUSES
            assert r["condition"] in VALID_CONDITIONS
            assert r["meta"].get("real") is True
            assert r["meta"].get("dry_run") is False


def test_fake_non_skipped_records_have_raw_files(fake_tree):
    for exp in ("e0", "e2", "e3", "e5", "e8"):
        for r in _records(fake_tree, exp):
            if r["status"] == "SKIPPED":
                assert r["raw_output_path"] is None
            else:
                p = PROJECT_ROOT / str(r["raw_output_path"])
                # tmp_path trees live outside PROJECT_ROOT -> path stored absolute
                p = p if p.exists() else Path(str(r["raw_output_path"]))
                assert p.exists(), (exp, r["sample_id"], r["raw_output_path"])


def test_fake_summary_schema(fake_tree):
    summary = json.loads((fake_tree / "summary.json").read_text(encoding="utf-8"))
    assert {"generated_utc", "seed", "stats", "experiments"} <= set(summary)
    assert set(summary["experiments"]) == {"e0", "e2", "e3", "e5", "e8"}
    for exp, entry in summary["experiments"].items():
        assert {"results_file", "model_id", "revision_sha", "date_utc",
                "real", "n_records", "metrics"} <= set(entry), exp
        assert entry["real"] is True
        assert (PROJECT_ROOT / entry["results_file"]).exists() or \
            Path(entry["results_file"]).exists()


def test_fake_e3_siud_direction(fake_tree):
    # NOTE (audit round 2 / V2 #3 fix): under the corrected usable-accounting
    # the FakeLLM DOES refuse some C2 stress texts (they contain the word
    # "exploit", the FakeLLM's refuse trigger), so SIUD is no longer
    # trivially 0. The invariant we assert is exactness: the runner's SIUD
    # must equal usable(C0) - usable(cond) over the common pairs computed
    # from its own records with metrics.is_usable.
    from src.metrics.metrics import is_usable

    res = json.loads((fake_tree / "e3" / "results.json").read_text(encoding="utf-8"))
    siud = res["metrics"]["SIUD_vs_C0"]
    records = res["records"]

    def usable_map(cond: str) -> dict[str, int]:
        return {r["sample_id"]: int(is_usable(r)) for r in records
                if r["condition"] == cond and r["status"] != "SKIPPED"}

    c0 = usable_map("C0")
    for cond in ("C2a", "C2b", "C3"):
        assert cond in siud
        other = usable_map(cond)
        common = sorted(set(c0) & set(other))
        if not siud[cond]["n_pairs"]:
            continue
        assert siud[cond]["n_pairs"] == len(common)
        expect = (sum(c0[i] for i in common) - sum(other[i] for i in common)) / len(common)
        assert siud[cond]["usable_delta_ci"]["estimate"] == pytest.approx(expect), cond


def test_fake_e8_p2_not_worse_than_b0(fake_tree):
    res = json.loads((fake_tree / "e8" / "results.json").read_text(encoding="utf-8"))
    s = res["metrics"]["safety_summary"]
    assert {"B0", "P2"} <= set(s)
    # fake LLM never produces refusal text on ungated unsafe prompts, but the
    # P2 intent gate must block the obvious offensive ones
    assert s["P2"]["unsafe_compliance_rate"] <= s["B0"]["unsafe_compliance_rate"]


# ---------------------------------------------------------------------------
# 2. validation of the REAL pilot outputs (skipped when absent)
# ---------------------------------------------------------------------------
def _real_experiments() -> dict[str, dict]:
    out = {}
    if not OUT_ROOT.exists():
        return out
    for exp_dir in sorted(OUT_ROOT.iterdir()):
        res = exp_dir / "results.json"
        if exp_dir.is_dir() and res.exists():
            out[exp_dir.name] = json.loads(res.read_text(encoding="utf-8"))
    return out


REAL = _real_experiments()


@pytest.mark.skipif(not REAL, reason="real pilot outputs not present yet")
@pytest.mark.parametrize("exp", sorted(REAL))
def test_real_records_raw_files_and_status(exp):
    res = REAL[exp]
    md = res["metadata"]
    assert md.get("dry_run") is False, "real outputs must never be dry-runs"
    assert md.get("model_id") and md["model_id"] != "mock-dry-run"
    n_checked = 0
    for r in res["records"]:
        assert r["status"] in VALID_STATUSES, r
        if r["status"] == "SKIPPED":
            assert r["meta"].get("error") or r["meta"].get("condition_error")
            continue
        assert r["raw_output_path"], r["sample_id"]
        path = Path(r["raw_output_path"])
        if not path.is_absolute():
            path = PROJECT_ROOT / path
        assert path.exists(), f"missing raw file for {exp}/{r['sample_id']}"
        n_checked += 1
    assert n_checked > 0


@pytest.mark.skipif(not (OUT_ROOT / "summary.json").exists(),
                    reason="summary.json not present yet")
def test_real_summary_schema_and_traceability():
    summary = json.loads((OUT_ROOT / "summary.json").read_text(encoding="utf-8"))
    assert {"generated_utc", "seed", "stats", "experiments"} <= set(summary)
    for exp, entry in summary["experiments"].items():
        assert (PROJECT_ROOT / entry["results_file"]).exists(), exp
        assert entry["model_id"], exp
        assert entry["n_records"] == len(
            json.loads((PROJECT_ROOT / entry["results_file"])
                       .read_text(encoding="utf-8"))["records"]), exp


@pytest.mark.skipif("e0" not in REAL, reason="e0 not present yet")
def test_real_e0_gate_block_present():
    m = REAL["e0"]["metrics"]
    gate = m["gate_per_model"]
    assert set(gate) >= {"delta_rr", "p_value", "ci_low", "ci_high",
                         "pass_this_model", "rule", "note"}
    assert "PRE-REGISTERED" in gate["rule"]
    assert m["probes"].get("over_refusal_rate") is not None
    assert m["probes"].get("unsafe_compliance_rate") is not None


# ---------------------------------------------------------------------------
# 3. Regression for audit round 2 (V2 #3): recompute the REAL e3 pilot from
#    its raw files with extract_verdict_fields semantics. The old accounting
#    (is_usable reading only top-level cwe/location while the runner stored
#    meta.pred_*) manufactured SIUD +0.258 [+0.097, +0.419]; the true values
#    recomputed from the raw outputs are UAC C0=0.975 / C2a=1.000 / C2b=1.000
#    and SIUD 0.000 / 0.000 / +0.032 (audit V2 recount). Skipped when the
#    real outputs are absent.
# ---------------------------------------------------------------------------
RECOMPUTE_E3_EXPECT = {
    # condition: (n_non_skipped, uac)
    "C0": (40, 0.975),
    "C2a": (31, 1.000),
    "C2b": (31, 1.000),
    "C3": (31, 0.968),
}
RECOMPUTE_E3_SIUD = {"C2a": 0.000, "C2b": 0.000, "C3": 0.032}


@pytest.mark.skipif("e3" not in REAL, reason="e3 not present yet")
def test_real_e3_usable_recompute_regression_v2_3():
    import sys
    sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
    import recompute_pilot  # noqa: E402

    res = REAL["e3"]
    required = ["vulnerable"]
    new_records = [recompute_pilot.reparse_record(r, required) for r in res["records"]]
    metrics = recompute_pilot.recompute_e3(new_records)

    for cond, (n_expect, uac_expect) in RECOMPUTE_E3_EXPECT.items():
        cm = metrics["conditions"][cond]
        assert cm["n"] == n_expect, cond
        assert cm["uac"] == pytest.approx(uac_expect, abs=0.005), \
            f"{cond} UAC {cm['uac']} != {uac_expect} (V2 #3 regression)"
    siud = metrics["SIUD_vs_C0"]
    for cond, expect in RECOMPUTE_E3_SIUD.items():
        est = siud[cond]["usable_delta_ci"]["estimate"]
        assert est == pytest.approx(expect, abs=0.005), \
            f"SIUD(C0-{cond}) {est} != {expect} (V2 #3 regression)"
