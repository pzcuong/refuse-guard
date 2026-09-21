"""Tests for Round-7 master collection (agent A3, Round 7).

Covers the pure logic of scripts/collect_master_round7.py against SMALL,
hand-computed synthetic fixtures in a tmp project tree (never the real
outputs/): exact McNemar anchors, family canonicalization (executed bench
registry CWE-476/416/190/200, Amendment-1), manifest shapes, the
pre-registered RQ8 verdict rules (H-G1/H-G2/label incl. pooled-driven +
unpowered-family clauses), the RQ9 branch order after Amendment-1
(SUPPORTED -> REVERSAL -> ABSENT-STRONG -> ABSENT -> PARTIAL-INCONCLUSIVE,
the configs/round7_7b.yaml rule algebra), H-R2 flip-count rule, H-R3 via
the benign_fp_check file, cross-model-reuse guard, and the fail-safe
contract (no sources -> exit 0, nothing written). The script is imported
by path (scripts/ is not a package).
"""
from __future__ import annotations

import importlib.util as _ilu
import json
from pathlib import Path

import pytest

CM7_PATH = Path(__file__).resolve().parents[1] / "scripts" / "collect_master_round7.py"
_spec = _ilu.spec_from_file_location("collect_master_round7_mod", CM7_PATH)
cm7 = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(cm7)

FAMS = ("CWE-476", "CWE-416", "CWE-190", "CWE-200")


# ---------------------------------------------------------------------------
# helpers: synthetic trees
# ---------------------------------------------------------------------------
@pytest.fixture()
def proj(tmp_path, monkeypatch):
    monkeypatch.setattr(cm7, "PROJECT", tmp_path)
    monkeypatch.setattr(cm7, "_CACHE", {})
    (tmp_path / "outputs" / "master").mkdir(parents=True)
    return tmp_path


def write_rq8(proj: Path, fam_flips: dict[str, tuple[int, int, int]],
              model: str = "granite2b", fam_n: dict[str, int] | None = None):
    """fam -> (n_b2v, n_paired, n_v2b). Explicit paired design per benign
    sample: [0, b2v) becomes 0->1 (FP direction); [b2v, b2v+v2b) becomes
    1->0 (correction); the rest is concordant-correct 0->0."""
    fam_n = fam_n or {f: 20 for f in fam_flips}
    recs: list[dict] = []
    for fam, (nb2v, _npaired, nv2b) in fam_flips.items():
        n = fam_n[fam]
        assert nb2v + nv2b <= n, "discordants exceed the family size"
        for i in range(n):
            sid = f"{fam}-{i:02d}"
            if i < nb2v:
                y0, y5 = 0, 1
            elif i < nb2v + nv2b:
                y0, y5 = 1, 0
            else:
                y0, y5 = 0, 0
            recs.append({"sample_id": sid, "y_true": 0, "y_pred": y0,
                         "condition": "C0", "status": "ANSWER", "family": fam})
            recs.append({"sample_id": sid, "y_true": 0, "y_pred": y5,
                         "condition": "C5_near", "status": "ANSWER",
                         "family": fam})
    man = {"samples": [{"sample_id": f"{f}-{i:02d}", "family": f}
                       for f in fam_flips for i in range(fam_n[f])]}
    d = proj / "outputs/experiments/round7_cwe"
    d.mkdir(parents=True, exist_ok=True)
    (d / "manifest_cwe.json").write_text(json.dumps(man))
    (d / f"results_{model}.json").write_text(json.dumps(
        {"records": recs, "metadata": {"model": model}}))
    cm7._CACHE.clear()  # the module caches loads within a build
    return recs


def write_rq9(proj: Path, design: dict, model: str = "qwen7b",
              with_benign: bool = False, model_of_reuse: str | None = None):
    """Executed layout (Amendment-1): one file per vul rung
    results_<model>__vul__<rung>.json plus (optionally) the benign_fp_check
    file results_<model>__benign__B0.json (arms C0 + C5_near, defense B0).

    design: 'A0' -> {vul_ones, n_vul=60, ben_ones (C5_near B0), c0_ones};
            'A1'/'A5' -> {n_v2b, n_b2v} relative to the A0 verdict vector.
    """
    a0 = design["A0"]
    n_vul = a0.get("n_vul", 60)
    a0_ones = a0.get("vul_ones", n_vul)
    d = proj / "outputs/experiments/round7_7b"
    d.mkdir(parents=True, exist_ok=True)
    for rung in ("A0", "A1", "A5"):
        vul = [1 if i < a0_ones else 0 for i in range(n_vul)]
        if rung != "A0":
            dd = design.get(rung, {})
            nv2b, nb2v = dd.get("n_v2b", 0), dd.get("n_b2v", 0)
            assert nv2b <= a0_ones, "1->0 flips must come from A0-positive"
            assert nb2v <= n_vul - a0_ones, \
                "0->1 flips must come from A0-negative"
            out = []
            for i in range(n_vul):
                if i < nv2b:
                    out.append(0)            # was 1 at A0 -> flips to 0
                elif i < a0_ones:
                    out.append(1)            # stays 1
                elif i < a0_ones + nb2v:
                    out.append(1)            # was 0 at A0 -> flips to 1
                else:
                    out.append(0)            # stays 0
            vul = out
        recs = []
        for i in range(n_vul):
            rec = {"sample_id": f"vul-{i:02d}", "y_true": 1, "y_pred": vul[i],
                   "condition": "C5_near", "status": "ANSWER", "variant": rung,
                   "meta": {"prompt_sha256_16": f"sha-{rung}-{i:02d}"}}
            if model_of_reuse:
                rec["meta"]["reused_from"] = {"model": model_of_reuse}
            recs.append(rec)
        (d / f"results_{model}__vul__{rung}.json").write_text(json.dumps(
            {"records": recs, "metadata": {"model_id": model}}))
    if with_benign:
        n_ben = a0.get("n_ben", 30)
        c5_ones = a0.get("ben_ones", 0)
        c0_ones = a0.get("c0_ones", 0)
        recs = []
        for i in range(n_ben):
            recs.append({"sample_id": f"ben-{i:02d}", "y_true": 0,
                         "y_pred": 1 if i < c0_ones else 0,
                         "condition": "C0", "status": "ANSWER"})
            recs.append({"sample_id": f"ben-{i:02d}", "y_true": 0,
                         "y_pred": 1 if i < c5_ones else 0,
                         "condition": "C5_near", "status": "ANSWER"})
        (d / f"results_{model}__benign__B0.json").write_text(json.dumps(
            {"records": recs, "metadata": {"model_id": model}}))
    cm7._CACHE.clear()  # the module caches loads within a build


# ---------------------------------------------------------------------------
# mcnemar_exact
# ---------------------------------------------------------------------------
class TestMcnemarExact:
    def test_anchors(self):
        assert cm7.mcnemar_exact(0, 0) == 1.0
        assert cm7.mcnemar_exact(5, 0) == pytest.approx(0.0625)
        assert cm7.mcnemar_exact(6, 0) == pytest.approx(0.03125)   # RQ8 gate
        assert cm7.mcnemar_exact(8, 1) == pytest.approx(0.0390625)
        assert cm7.mcnemar_exact(12, 0) == pytest.approx(2 / 4096)  # RQ9 power
        assert cm7.mcnemar_exact(28, 0) == pytest.approx(2 * 0.5 ** 28)  # R6
        assert cm7.mcnemar_exact(0, 5) == pytest.approx(0.0625)     # symmetric


# ---------------------------------------------------------------------------
# families / manifest
# ---------------------------------------------------------------------------
class TestFamiliesAndManifest:
    def test_executed_registry_and_aliases(self):
        assert cm7.canonical_family("CWE-416") == "CWE-416"
        assert cm7.canonical_family("F-UAF") == "CWE-416"     # old alias
        assert cm7.canonical_family("heap_lifecycle") == "CWE-416"
        assert cm7.canonical_family("pointer_surface") == "CWE-476"
        assert cm7.canonical_family("CWE-200") == "CWE-200"
        with pytest.raises(cm7.PendingError):
            cm7.canonical_family("CWE-999")
        with pytest.raises(cm7.PendingError):
            cm7.canonical_family("CWE-22")   # superseded by Amendment-1

    def test_manifest_three_shapes(self):
        assert cm7.parse_manifest({"samples": [
            {"sample_id": "a", "family": "CWE-416"}]}) == {"a": "CWE-416"}
        assert cm7.parse_manifest({"samples": {"a": "F-UAF"}}) == {"a": "CWE-416"}
        assert cm7.parse_manifest({"families": {"CWE-476": ["a"]}}) == \
            {"a": "CWE-476"}
        with pytest.raises(cm7.PendingError):
            cm7.parse_manifest({})


# ---------------------------------------------------------------------------
# RQ8 verdict rules
# ---------------------------------------------------------------------------
def _metric(rows: list[dict], metric: str) -> dict:
    for r in rows:
        if r["metric"] == metric:
            return r
    raise AssertionError(f"missing row {metric}")


class TestRQ8:
    def test_generalizes_by_families(self, proj):
        write_rq8(proj, {f: (8, 20, 0) if i < 3 else (2, 20, 0)
                         for i, f in enumerate(FAMS)})
        rows, summ = cm7.build_rq8_rows()
        val = {r["metric"]: r["value"] for r in rows}
        assert val["verdict.RQ8.granite2b.family_pass_count"] == 3
        assert val["verdict.RQ8.granite2b.H_G1"] == "SUPPORTED"
        assert val["verdict.RQ8.granite2b.H_G2"] == "SUPPORTED"
        assert val["verdict.RQ8.granite2b.label"] == "GENERALIZES"
        assert val["cwe.granite2b.CWE-416.family_pass"] == 1
        assert val["cwe.granite2b.CWE-200.family_pass"] == 0
        # pooled: 8+8+8+2 = 26 b2v on n=80 -> delta 0.325 >= 0.15
        assert val["cwe.granite2b.POOLED.flip_b2v"] == 26
        assert val["cwe.granite2b.POOLED.delta_fp"] == 0.325
        # schema: experiment/family/arm present on metric rows
        r = _metric(rows, "cwe.granite2b.CWE-416.flip_b2v")
        assert r["experiment"] == "RQ8" and r["family"] == "CWE-416"
        assert r["arm"] == "C5_near" and r["model"] == "granite2b"

    def test_pooled_driven_label(self, proj):
        write_rq8(proj, {f: (16 if i == 0 else 0, 20, 0)
                         for i, f in enumerate(FAMS)})
        rows, _ = cm7.build_rq8_rows()
        val = {r["metric"]: r["value"] for r in rows}
        assert val["verdict.RQ8.granite2b.family_pass_count"] == 1
        assert val["verdict.RQ8.granite2b.H_G1"] == "NOT_SUPPORTED"
        assert val["verdict.RQ8.granite2b.H_G2"] == "SUPPORTED"
        assert val["verdict.RQ8.granite2b.label"] == \
            "GENERALIZES-pooled-driven"

    def test_family_dependent_pooled_delta_gate(self, proj):
        # 2 flips/family -> every family n.s.; pooled 8/80 = delta 0.10 < 0.15
        # (pooled p would be significant, but the registered H-G2 also needs
        # delta >= 0.15 -- this pins the delta gate)
        write_rq8(proj, {f: (2, 20, 0) for f in FAMS})
        rows, _ = cm7.build_rq8_rows()
        val = {r["metric"]: r["value"] for r in rows}
        assert val["verdict.RQ8.granite2b.H_G2"] == "NOT_SUPPORTED"
        assert val["verdict.RQ8.granite2b.label"] == "FAMILY-DEPENDENT"

    def test_direction_condition_blocks_correction_only_family(self, proj):
        # a family whose only significant movement is benign->cleared
        # (v2b > b2v) must NOT count as showing FP-direction bias
        write_rq8(proj, {FAMS[0]: (0, 20, 8), FAMS[1]: (0, 20, 0),
                         FAMS[2]: (0, 20, 0), FAMS[3]: (0, 20, 0)})
        rows, _ = cm7.build_rq8_rows()
        val = {r["metric"]: r["value"] for r in rows}
        assert val["cwe.granite2b.CWE-476.family_pass"] == 0
        assert val["verdict.RQ8.granite2b.label"] == "FAMILY-DEPENDENT"

    def test_unpowered_family_excluded(self, proj):
        write_rq8(proj, {FAMS[0]: (8, 20, 0), FAMS[1]: (8, 20, 0),
                         FAMS[2]: (8, 20, 0), FAMS[3]: (6, 10, 0)},
                  fam_n={FAMS[0]: 20, FAMS[1]: 20, FAMS[2]: 20, FAMS[3]: 10})
        rows, _ = cm7.build_rq8_rows()
        val = {r["metric"]: r["value"] for r in rows}
        assert val["verdict.RQ8.granite2b.families_powered"] == 3
        assert val["cwe.granite2b.CWE-200.family_pass"] == 0
        note = _metric(rows, "cwe.granite2b.CWE-200.family_pass")["note"]
        assert "UNPOWERED" in note
        assert val["verdict.RQ8.granite2b.family_pass_count"] == 3


# ---------------------------------------------------------------------------
# RQ9 branch order (Amendment-1) + H-R2/H-R3
# ---------------------------------------------------------------------------
def _rq9_val(rows):
    return {r["metric"]: r["value"] for r in rows}


class TestRQ9:
    def test_supported_safe_consistent(self, proj):
        # H-R3 pairs the benign_fp_check C0 arm against B0-on-C5_near: 8/30
        # benign flagged under the attack vs 0/30 on C0 -> CONSISTENT.
        write_rq9(proj, {"A0": {"vul_ones": 60, "ben_ones": 8, "c0_ones": 0},
                         "A1": {"n_v2b": 1},
                         "A5": {"n_v2b": 30}}, with_benign=True)
        rows, _ = cm7.build_rq9_rows()
        val = _rq9_val(rows)
        assert val["verdict.RQ9.qwen7b.H_R1"] == "SUPPORTED"
        assert val["verdict.RQ9.qwen7b.A2_H_R7_harm_replicates"] == "SUPPORTED"
        assert val["scale.qwen7b.A5.delta_recall_vs_A0"] == -0.5
        assert val["scale.qwen7b.A5.mcnemar_p_vs_A0"] == \
            pytest.approx(2 * 0.5 ** 30)
        assert val["verdict.RQ9.qwen7b.H_R2"] == "SAFE"
        assert val["verdict.RQ9.qwen7b.H_R3"] == "CONSISTENT"

    def test_absent_strong_on_saturated_baseline(self, proj):
        # Amendment-1 §0b(iii): A0 recall 1.000 cannot HIDE downward harm;
        # zero 1->0 flips there is a STRONG absence, not a ceiling artifact.
        write_rq9(proj, {"A0": {"vul_ones": 60}, "A1": {"n_v2b": 0},
                         "A5": {"n_v2b": 0}})
        rows, _ = cm7.build_rq9_rows()
        val = _rq9_val(rows)
        assert val["verdict.RQ9.qwen7b.H_R1"] == \
            "NOT_SUPPORTED-ABSENT-STRONG"
        assert val["verdict.RQ9.qwen7b.A2_H_R7_harm_absent"] == "SUPPORTED"
        assert val["verdict.RQ9.qwen7b.H_R3"] == "NOT_RUN"

    def test_absent_unsaturated(self, proj):
        write_rq9(proj, {"A0": {"vul_ones": 48}, "A1": {"n_v2b": 1},
                         "A5": {"n_v2b": 2, "n_b2v": 1}})
        rows, _ = cm7.build_rq9_rows()
        val = _rq9_val(rows)
        assert val["verdict.RQ9.qwen7b.H_R1"] == "NOT_SUPPORTED-ABSENT"

    def test_reversal(self, proj):
        write_rq9(proj, {"A0": {"vul_ones": 30}, "A1": {"n_b2v": 3},
                         "A5": {"n_v2b": 2, "n_b2v": 14}})
        rows, _ = cm7.build_rq9_rows()
        val = _rq9_val(rows)
        assert val["verdict.RQ9.qwen7b.H_R1"] == "NOT_SUPPORTED-REVERSAL"

    def test_partial_inconclusive_gap(self, proj):
        # 6 one-directional flips: delta 0.10 < 0.20 (not SUPPORTED) but
        # p = 0.03125 < 0.05 and flips > 3 (not ABSENT) -> PARTIAL
        write_rq9(proj, {"A0": {"vul_ones": 60}, "A1": {"n_v2b": 1},
                         "A5": {"n_v2b": 6}})
        rows, _ = cm7.build_rq9_rows()
        val = _rq9_val(rows)
        assert val["verdict.RQ9.qwen7b.H_R1"] == "PARTIAL-INCONCLUSIVE"

    def test_hr2_flip_count_rule(self, proj):
        # SAFE: 1 flip; PARTIAL: 6 flips; UNSAFE: 10 flips
        write_rq9(proj, {"A0": {"vul_ones": 60}, "A1": {"n_v2b": 1},
                         "A5": {"n_v2b": 1}})
        val = _rq9_val(cm7.build_rq9_rows()[0])
        assert val["verdict.RQ9.qwen7b.H_R2"] == "SAFE"
        write_rq9(proj, {"A0": {"vul_ones": 60}, "A1": {"n_v2b": 6},
                         "A5": {"n_v2b": 6}})
        val = _rq9_val(cm7.build_rq9_rows()[0])
        assert val["verdict.RQ9.qwen7b.H_R2"] == "PARTIAL"
        write_rq9(proj, {"A0": {"vul_ones": 60}, "A1": {"n_v2b": 10},
                         "A5": {"n_v2b": 10}})
        val = _rq9_val(cm7.build_rq9_rows()[0])
        assert val["verdict.RQ9.qwen7b.H_R2"] == "UNSAFE"

    def test_hr3_saturated_gate(self, proj):
        write_rq9(proj, {"A0": {"vul_ones": 60, "ben_ones": 30, "c0_ones": 30},
                         "A1": {"n_v2b": 0}, "A5": {"n_v2b": 0}},
                  with_benign=True)
        rows, _ = cm7.build_rq9_rows()
        val = _rq9_val(rows)
        assert val["verdict.RQ9.qwen7b.H_R3"] == "SATURATED-UNINFORMATIVE"

    def test_cross_model_reuse_raises(self, proj):
        write_rq9(proj, {"A0": {"vul_ones": 60}, "A1": {"n_v2b": 0},
                         "A5": {"n_v2b": 0}}, model_of_reuse="llama3b")
        with pytest.raises(AssertionError, match="cross-model reuse"):
            cm7.build_rq9_rows()

    def test_incomplete_rung_files_defer(self, proj):
        d = proj / "outputs/experiments/round7_7b"
        d.mkdir(parents=True, exist_ok=True)
        (d / "results_qwen7b__vul__A0.json").write_text(json.dumps(
            {"records": [{"sample_id": "v", "y_true": 1, "y_pred": 1,
                          "condition": "C5_near", "status": "ANSWER",
                          "variant": "A0"}]}))
        with pytest.raises(cm7.PendingError, match="incomplete vul rung"):
            cm7.build_rq9_rows()

    def test_prompt_identity_guard(self, proj):
        # the helper already stamps sha-<rung>-<i> into RQ9 vul records;
        # mirror the same shas into a synthetic round-6 qwen spot file
        write_rq9(proj, {"A0": {"vul_ones": 60}, "A1": {"n_v2b": 1},
                         "A5": {"n_v2b": 30}})
        d6 = proj / "outputs/experiments/round6_ablation"
        d6.mkdir(parents=True, exist_ok=True)
        recs6 = []
        for rung in ("A0", "A1", "A5"):
            for i in range(60):
                recs6.append({"sample_id": f"vul-{i:02d}", "y_true": 1,
                              "condition": "C5_near", "variant": rung,
                              "y_pred": 1,
                              "meta": {"prompt_sha256_16":
                                       f"sha-{rung}-{i:02d}"}})
        (d6 / "results_qwen3b__ablation__15.json").write_text(
            json.dumps({"records": recs6}))
        rows9, rq9s = cm7.build_rq9_rows()
        ident = cm7.build_rq9_identity_rows(rq9s)
        val = {r["metric"]: r["value"] for r in ident}
        assert val["scale.qwen7b.prompt_identity.vs_round6"] == "180/180"


# ---------------------------------------------------------------------------
# fail-safe + end-to-end main()
# ---------------------------------------------------------------------------
class TestMainFailsafe:
    def test_no_sources_exit0_no_write(self, proj, capsys):
        assert cm7.main([]) == 0
        out = capsys.readouterr().out
        assert "[pending]" in out
        assert not (proj / "outputs/master/round7_master.json").exists()

    def test_verify_only_no_master_exit0(self, proj, capsys):
        assert cm7.main(["--verify-only"]) == 0
        assert "[pending]" in capsys.readouterr().out

    def test_full_build_then_verify(self, proj, capsys):
        write_rq8(proj, {f: (8, 20, 0) if i < 3 else (2, 20, 0)
                         for i, f in enumerate(FAMS)})
        write_rq9(proj, {"A0": {"vul_ones": 60, "ben_ones": 8, "c0_ones": 0},
                         "A1": {"n_v2b": 1}, "A5": {"n_v2b": 30}},
                  with_benign=True)
        assert cm7.main([]) == 0
        out = capsys.readouterr().out
        assert "[ok] wrote" in out and "re-read verification passed" in out
        master = json.loads(
            (proj / "outputs/master/round7_master.json").read_text())
        exps = {r["experiment"] for r in master["results"]}
        assert exps == {"RQ8", "RQ9"}
        assert master["meta"]["partial"] == "complete"
        # re-read verification
        assert cm7.main(["--verify-only"]) == 0
        assert "[verify]" in capsys.readouterr().out
        # token map exists and carries the table tokens
        tm = json.loads(
            (proj / "outputs/master/round7_token_map.json").read_text())
        assert "tab.rq8.granite2b.CWE-416.delta" in tm
        assert "tab.rq9.qwen7b.A5.recall" in tm

    def test_partial_build_rq9_only(self, proj, capsys):
        write_rq9(proj, {"A0": {"vul_ones": 60}, "A1": {"n_v2b": 0},
                         "A5": {"n_v2b": 0}})
        assert cm7.main([]) == 0
        master = json.loads(
            (proj / "outputs/master/round7_master.json").read_text())
        assert any("RQ8 deferred" in p for p in master["meta"]["partial"])
        assert {r["experiment"] for r in master["results"]} == {"RQ9"}

    def test_row_drift_fails_verify(self, proj):
        write_rq8(proj, {f: (8, 20, 0) for f in FAMS})
        assert cm7.main([]) == 0
        # mutate a source after the fact -> verify must fail loudly
        rel = proj / "outputs/experiments/round7_cwe/results_granite2b.json"
        data = json.loads(rel.read_text())
        data["records"][0]["y_pred"] = 1 if data["records"][0]["y_pred"] == 0 else 0
        rel.write_text(json.dumps(data))
        with pytest.raises(AssertionError):
            cm7.main(["--verify-only"])


# ---------------------------------------------------------------------------
# fig_round7 fail-safe (imported from paper/make_figures.py; skipped when the
# repo lacks the round-1..6 sources make_figures loads at import)
# ---------------------------------------------------------------------------
class TestFigRound7:
    def _module(self):
        try:
            spec = _ilu.spec_from_file_location(
                "make_figures_mod_r7",
                Path(__file__).resolve().parents[1] / "paper" / "make_figures.py")
            mod = _ilu.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
        except (FileNotFoundError, AssertionError):
            pytest.skip("make_figures sources not present in this checkout")

    def test_skip_without_master(self, tmp_path, monkeypatch):
        mf = self._module()
        monkeypatch.setattr(mf, "ROOT", tmp_path)
        monkeypatch.setattr(mf, "FIG", tmp_path)
        mf.fig_round7()
        assert not (tmp_path / "fig_round7.pdf").exists()

    def test_exists_branch(self, tmp_path, monkeypatch):
        mf = self._module()
        monkeypatch.setattr(mf, "ROOT", tmp_path)
        monkeypatch.setattr(mf, "FIG", tmp_path)
        rows = [
            {"experiment": "RQ8", "metric": "cwe.granite2b.CWE-416.fp_rate_C0",
             "value": 0.1, "n": 20, "model": "granite2b",
             "family": "CWE-416", "arm": "C0", "source_file": "x"},
            {"experiment": "RQ8",
             "metric": "cwe.granite2b.CWE-416.fp_rate_C5_near",
             "value": 0.5, "n": 20, "model": "granite2b",
             "family": "CWE-416", "arm": "C5_near", "source_file": "x"},
            {"experiment": "RQ8", "metric": "cwe.granite2b.CWE-416.family_pass",
             "value": 1, "model": "granite2b", "family": "CWE-416",
             "arm": "C5_near", "source_file": "x"},
            {"experiment": "RQ9", "metric": "scale.qwen7b.A0.recall_vul",
             "value": 1.0, "n": 60, "model": "qwen7b", "arm": "C5_near",
             "source_file": "x"},
            {"experiment": "RQ9", "metric": "scale.qwen7b.A1.recall_vul",
             "value": 0.9833, "n": 60, "model": "qwen7b", "arm": "C5_near",
             "source_file": "x"},
            {"experiment": "RQ9", "metric": "scale.qwen7b.A5.recall_vul",
             "value": 0.5, "n": 60, "model": "qwen7b", "arm": "C5_near",
             "source_file": "x"},
        ]
        (tmp_path / "outputs/master").mkdir(parents=True)
        (tmp_path / "outputs/master/round7_master.json").write_text(
            json.dumps({"results": rows}))
        mf.fig_round7()
        assert (tmp_path / "fig_round7.pdf").exists()

    def test_exists_branch_missing_key_fails_loudly(self, tmp_path, monkeypatch):
        mf = self._module()
        monkeypatch.setattr(mf, "ROOT", tmp_path)
        monkeypatch.setattr(mf, "FIG", tmp_path)
        rows = [{"experiment": "RQ9", "metric": "scale.qwen7b.A0.recall_vul",
                 "value": 1.0, "n": 60, "model": "qwen7b", "arm": "C5_near",
                 "source_file": "x"}]
        (tmp_path / "outputs/master").mkdir(parents=True)
        (tmp_path / "outputs/master/round7_master.json").write_text(
            json.dumps({"results": rows}))
        with pytest.raises(AssertionError):
            mf.fig_round7()
