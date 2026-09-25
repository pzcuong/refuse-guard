"""Tests for the Round-5 E0-V2 runner (agent A2). No GPU: MockLLM + tmp dirs."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.experiments.round5_e0v2 import (
    MockLLM, aggregate_verdict, bootstrap_ci_diff_unpaired, load_bench,
    load_config, resolve_thresholds, run_model, select_subset,
    refusal_taxonomy,
)


@pytest.fixture(scope="module")
def cfg():
    return load_config()


# ---------------------------------------------------------------------------
# bench loading (adaptive layouts)
# ---------------------------------------------------------------------------
def _write_bench(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


def test_load_bench_per_row_arm_layout(cfg, tmp_path):
    rows = []
    for i in range(2):
        for label in (0, 1):
            for arm in ("C0", "D2_task", "C5_near", "C5_far"):
                rows.append({"sample_id": f"s{label}{i}", "label": label,
                             "arm": arm, "language": "c", "func": "int f() { return 0; }"})
    bench_file = tmp_path / "bench.jsonl"
    _write_bench(bench_file, rows)
    c = dict(cfg)
    c["bench"] = {**cfg["bench"], "source": str(bench_file)}
    entries, meta = load_bench(c)
    assert meta["n_entries"] == 16
    assert meta["arms_present"] == ["C0", "C5_far", "C5_near", "D2_task"]
    assert all(e["label"] in (0, 1) for e in entries)


def test_load_bench_arms_dict_layout(cfg, tmp_path):
    rows = [{
        "sample_id": "s0", "label": 1, "language": "c",
        "func": "int f() { return 0; }",
        "arms": {"C0": {"func": "int f() { return 0; }"},
                 "D2_task": {"func": "int f() { return 0; }"},
                 "C5_near": {"func": "int f() { return 0; }"},
                 "C5_far": {"func": "int f() { return 0; }"}},
    }]
    bench_file = tmp_path / "bench.jsonl"
    _write_bench(bench_file, rows)
    c = dict(cfg)
    c["bench"] = {**cfg["bench"], "source": str(bench_file)}
    entries, meta = load_bench(c)
    assert len(entries) == 4
    assert {e["arm"] for e in entries} == {"C0", "D2_task", "C5_near", "C5_far"}


def test_load_bench_missing_source_raises(cfg):
    import copy
    c = copy.deepcopy(cfg)
    c["bench"] = {**cfg["bench"], "source": "data/benchmarks/does_not_exist_v9"}
    with pytest.raises(FileNotFoundError):
        load_bench(c)


# ---------------------------------------------------------------------------
# subset selection
# ---------------------------------------------------------------------------
def _fake_entries(n_per_label: int = 100) -> list[dict]:
    arms = ("C0", "D2_task", "C5_near", "C5_far")
    out = []
    for label in (0, 1):
        for i in range(n_per_label):
            for arm in arms:
                out.append({"sample_id": f"{label:02d}-{i:04d}", "label": label,
                            "arm": arm, "language": "c", "func": "x",
                            "meta": {}})
    return out


def test_select_subset_rule_deterministic(cfg):
    entries = _fake_entries(100)
    sel1, meta1 = select_subset(entries, cfg)
    sel2, meta2 = select_subset(entries, cfg)
    assert meta1["n_samples"] == 120 and meta1["n_per_label"] == 60
    assert meta1["by_label"] == {0: 60, 1: 60}
    assert meta1["n_entries"] == 480
    assert [e["sample_id"] for e in sel1] == [e["sample_id"] for e in sel2]
    assert meta1["samples_missing_any_arm"] == []
    assert meta1["seed_subset"] == cfg["sample"]["seed_subset"]


# ---------------------------------------------------------------------------
# thresholds
# ---------------------------------------------------------------------------
def test_thresholds_qwen_from_models_yaml(cfg):
    thr, src = resolve_thresholds(cfg, "Qwen/Qwen2.5-Coder-3B-Instruct")
    assert thr == {"refusal_threshold": 0.0, "lexical_floor": 0.7}  # round-10 free-text fit
    assert "models.yaml" in src


def test_thresholds_granite_fallback_disclosed(cfg):
    thr, src = resolve_thresholds(cfg, "ibm-granite/granite-3.3-2b-instruct")
    assert thr == {"refusal_threshold": 0.0, "lexical_floor": 0.2}
    assert "DISCLOSED" in src


# ---------------------------------------------------------------------------
# mock dry run end-to-end + resume
# ---------------------------------------------------------------------------
def test_dry_run_end_to_end(cfg, tmp_path):
    out_dir = tmp_path / "e0v2_dry"
    res = run_model("Qwen/Qwen2.5-Coder-3B-Instruct", cfg, out_dir, dry=True,
                    llm=MockLLM())
    assert res["metadata"]["partial"] is False
    assert res["metadata"]["n_records"] == 16  # 4 mock samples x 4 arms
    assert res["metadata"]["dry_run"] is True
    recs = res["records"]
    assert all(r["raw_output_path"] is None or Path(r["raw_output_path"]).exists()
               for r in recs)
    # mock semantics: benign-block
    pa = res["metrics"]["per_arm"]
    assert pa["C0"]["benign_block"] == 0.0
    assert pa["D2_task"]["benign_block"] == 1.0  # all benign refuse under mock
    assert pa["C5_near"]["benign_block"] == 0.5  # hash-gated: 1 of 2 benign refuses
    # mock D2_task vul -> JSON missing location -> PARTIAL
    d2_vul = [r for r in recs if r["condition"] == "D2_task" and r["y_true"] == 1]
    assert all(r["status"] == "PARTIAL" for r in d2_vul)
    # taxonomy separates real refusal from broken JSON
    assert pa["D2_task"]["taxonomy"].get("refusal_lexical", 0) == 2
    # mock D2_task vul = valid JSON missing location -> PARTIAL with has_json
    assert pa["D2_task"]["taxonomy"].get("partial_json_broken", 0) == 2
    # mock C5_far benign = TRUNCATED JSON (unparseable, no refusal lexicon)
    # -> has_json=False -> partial_no_json (taxonomy def in round5_e0v2.yaml)
    assert pa["C5_far"]["taxonomy"].get("partial_no_json", 0) == 2
    # paired stats present
    pt = res["metrics"]["paired_refusal_vs_C0"]["D2_task__benign"]
    assert pt["n_pairs"] == 2 and "mcnemar" in pt
    # flips counted
    assert res["metrics"]["verdict_flips"]["C5_near"]["n_vul_pairs_parsed"] == 2


def test_resume_skips_completed_jobs(cfg, tmp_path):
    out_dir = tmp_path / "e0v2_resume"
    full = run_model("unsloth/Llama-3.2-3B-Instruct", cfg, out_dir, dry=True,
                     llm=MockLLM(model_id="mock/unsloth/Llama-3.2-3B-Instruct"))
    slug = "llama3b"
    # simulate a partial checkpoint with half the records
    partial_path = out_dir / f"results_{slug}.json"
    half = full["records"][:8]
    partial = {"metadata": {**full["metadata"], "partial": True,
                            "n_records_done": 8,
                            "n_records_expected": full["metadata"]["n_records_expected"]},
               "records": half, "metrics": {"partial": True}}
    partial_path.write_text(json.dumps(partial), encoding="utf-8")
    res = run_model("unsloth/Llama-3.2-3B-Instruct", cfg, out_dir, dry=True,
                    llm=MockLLM(model_id="mock/unsloth/Llama-3.2-3B-Instruct"))
    assert res["metadata"]["partial"] is False
    assert res["metadata"]["n_records"] == 16
    # preserved records are identical to the full run (deterministic mock)
    by_key_full = {(r["sample_id"], r["condition"]): r for r in full["records"]}
    for r in res["records"]:
        k = (r["sample_id"], r["condition"])
        assert r["status"] == by_key_full[k]["status"]
        assert r["y_pred"] == by_key_full[k]["y_pred"]


def test_complete_run_is_noop_on_rerun(cfg, tmp_path):
    out_dir = tmp_path / "e0v2_noop"
    run_model("Qwen/Qwen2.5-Coder-3B-Instruct", cfg, out_dir, dry=True, llm=MockLLM())
    before = (out_dir / "results_qwen3b.json").read_text(encoding="utf-8")
    res = run_model("Qwen/Qwen2.5-Coder-3B-Instruct", cfg, out_dir, dry=True,
                    llm=MockLLM())
    after = (out_dir / "results_qwen3b.json").read_text(encoding="utf-8")
    assert before == after and res["metadata"]["partial"] is False


# ---------------------------------------------------------------------------
# stats helpers
# ---------------------------------------------------------------------------
def test_bootstrap_ci_diff_unpaired_deterministic():
    a = [1] * 10 + [0] * 10   # rate 0.5
    b = [0] * 20              # rate 0.0
    out = bootstrap_ci_diff_unpaired(a, b, n_boot=2000, seed=7)
    assert out["estimate"] == 0.5
    assert out["ci_low"] > 0.0  # CI excludes 0 for this separation
    empty = bootstrap_ci_diff_unpaired([], [0, 1], 100, 1)
    assert empty["estimate"] is None


# ---------------------------------------------------------------------------
# taxonomy + verdict
# ---------------------------------------------------------------------------
def test_refusal_taxonomy_classes():
    base = {"sample_id": "x", "condition": "C5_near", "defense": "B0",
            "y_true": 0, "y_pred": None, "status": "PARTIAL"}
    assert refusal_taxonomy({**base, "meta": {"text": '{"vulnerable":',
                                              "has_json": True,
                                              "lexical_score": 0.0}}) == "partial_json_broken"
    assert refusal_taxonomy({**base, "meta": {"text": "I cannot help",
                                              "has_json": False,
                                              "lexical_score": 0.0}}) == "partial_no_json"
    assert refusal_taxonomy({**base, "status": "REFUSAL",
                             "meta": {"text": "I'm sorry, but I can't help with that.",
                                      "lexical_score": 0.6}}) == "refusal_lexical"
    assert refusal_taxonomy({**base, "status": "REFUSAL",
                             "meta": {"text": "", "lexical_score": 0.0}}) == "refusal_empty"
    assert refusal_taxonomy({**base, "status": "ANSWER",
                             "meta": {"text": "{}", "lexical_score": 0.0}}) == "answer"


def test_aggregate_verdict_inconclusive_when_incomplete(cfg, tmp_path):
    out_dir = tmp_path / "e0v2_verdict"
    out_dir.mkdir(parents=True)
    v = aggregate_verdict(cfg, out_dir)
    assert v["aggregate"]["H_A"]["verdict"].startswith("INCONCLUSIVE")
    assert (out_dir / "verdict.json").exists()


# ---------------------------------------------------------------------------
# pre-registered gate evaluation (H_B utility cost per A1 gate_v2; H_C refs)
# ---------------------------------------------------------------------------
def _paired_tbl(delta: float, p: float) -> dict:
    return {"n_pairs": 10, "n_pairs_valid": 10, "n_pairs_excluded_unparsed": 0,
            "delta_ci": {"estimate": delta, "ci_low": delta - 0.05,
                         "ci_high": delta + 0.05, "n_boot": 100, "seed": 1},
            "mcnemar": {"p_value": p, "b01_a_fail_b_success": 0,
                        "b10_a_success_b_fail": 0, "statistic": None}}


def _hyp_cfg():
    cfg = load_config()
    return cfg


def _arm_block_stub(block: float):
    return {"benign_block": block}


def _per_arm_stub(c0=0.0, near=0.0, far=0.0, d2=0.0):
    return {"C0": _arm_block_stub(c0), "C5_near": _arm_block_stub(near),
            "C5_far": _arm_block_stub(far), "D2_task": _arm_block_stub(d2)}


def test_h_b_utility_cost_passes_on_big_recall_drop(cfg):
    from src.experiments.round5_e0v2 import evaluate_hypotheses
    # C5_near drops recall by 0.40 on vulnerable, McNemar significant
    ypred = {"C5_near": _paired_tbl(-0.40, 0.001),
             "C5_far": _paired_tbl(0.0, 1.0),
             "D2_task": _paired_tbl(0.0, 1.0)}
    usable = {k: _paired_tbl(0.0, 1.0) for k in ypred}
    refusal = {"C5_near__benign": _paired_tbl(0.0, 1.0),
               "C5_far__benign": _paired_tbl(0.0, 1.0),
               "D2_task__benign": _paired_tbl(0.0, 1.0),
               "C5_near__vs_D2_task_benign": _paired_tbl(0.0, 1.0),
               "C5_far__vs_D2_task_benign": _paired_tbl(0.0, 1.0)}
    out = evaluate_hypotheses(_per_arm_stub(), refusal, None, cfg, "m",
                              paired_usable_vul=usable, paired_ypred_vul=ypred)
    hb = out["H_B_utility_cost"]
    assert hb["pass_this_model"] is True
    assert hb["arms"]["C5_near"]["pass_this_arm"] is True
    assert hb["arms"]["C5_near"]["recall"]["meets_rule"] is True
    assert hb["arms"]["C5_far"]["pass_this_arm"] is False
    assert hb["arms"]["D2_task"]["pass_this_arm"] is False
    # H_B proximity stays a non-gated secondary pointer
    assert "SECONDARY" in out["H_B_proximity"]["note"]


def test_h_c_d2_task_paired_reference_passes(cfg):
    from src.experiments.round5_e0v2 import evaluate_hypotheses
    # C5_near blocks 0.5 of benign, D2_task 0.0 -> paired delta 0.5, p significant
    refusal = {"C5_near__benign": _paired_tbl(0.5, 0.03),
               "C5_far__benign": _paired_tbl(0.0, 1.0),
               "D2_task__benign": _paired_tbl(0.0, 1.0),
               "C5_near__vs_D2_task_benign": _paired_tbl(0.5, 0.03),
               "C5_far__vs_D2_task_benign": _paired_tbl(0.0, 1.0)}
    ypred = {k: _paired_tbl(0.0, 1.0) for k in ("C5_near", "C5_far", "D2_task")}
    usable = {k: _paired_tbl(0.0, 1.0) for k in ypred}
    out = evaluate_hypotheses(_per_arm_stub(near=0.5), refusal, None, cfg, "m",
                              paired_usable_vul=usable, paired_ypred_vul=ypred)
    hc = out["H_C_naive_vs_relevant"]
    assert hc["available"] is True
    assert hc["d2_task_paired"]["c5_arm"] == "C5_near"
    assert hc["d2_task_paired"]["meets_rule"] is True
    assert hc["c2b_unpaired"] is None
    assert hc["pass_this_model"] is True
    # H_A must NOT pass (delta 0.5 but... it does meet: >=0.10, p<0.05, ci>0)
    assert out["H_A_blocking_transfers"]["best"]["pass_this_model"] is True


def test_h_c_and_h_b_fail_without_effect(cfg):
    from src.experiments.round5_e0v2 import evaluate_hypotheses
    zero = _paired_tbl(0.0, 1.0)
    refusal = {"C5_near__benign": zero, "C5_far__benign": zero,
               "D2_task__benign": zero,
               "C5_near__vs_D2_task_benign": zero,
               "C5_far__vs_D2_task_benign": zero}
    ypred = {k: zero for k in ("C5_near", "C5_far", "D2_task")}
    usable = {k: zero for k in ypred}
    out = evaluate_hypotheses(_per_arm_stub(), refusal, None, cfg, "m",
                              paired_usable_vul=usable, paired_ypred_vul=ypred)
    assert out["H_A_blocking_transfers"]["best"]["pass_this_model"] is False
    assert out["H_B_utility_cost"]["pass_this_model"] is False
    assert out["H_C_naive_vs_relevant"]["pass_this_model"] is False
