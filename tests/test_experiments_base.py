"""Regression tests for the shared runner loop (audit round 1 fixes).

Covers the crash-proofing added by S (round 1): a sample whose code parses
under neither the C nor the C++ grammar must yield a disclosed SKIPPED record,
never crash the run; results.json must carry corpus_source; the metrics hook
must speak the canonical y_true/y_pred schema in both directions.
"""
import json

import pytest

from src.experiments.base import run_experiment


GOOD_FUNC = (
    "/* module header */\n"
    "int f(char *user) {\n"
    "    char buf[64];\n"
    "    strcpy(buf, user);\n"
    "    return 0;\n"
    "}\n"
)
BAD_FUNC = "this is neither C nor C++ %%% {{{"


@pytest.fixture()
def manifest_cfg(tmp_path, monkeypatch):
    monkeypatch.chdir(".")  # runners resolve configs relative to repo root
    man = tmp_path / "mini_manifest.json"
    man.write_text(json.dumps({"samples": [
        {"sample_id": 1, "pair_id": None, "func": GOOD_FUNC, "label": 1,
         "cwe": "CWE-120", "cve": None, "project": "t", "split": "test"},
        {"sample_id": 2, "pair_id": None, "func": BAD_FUNC, "label": 0,
         "cwe": None, "cve": None, "project": "t", "split": "test"},
    ]}), encoding="utf-8")
    return {
        "experiment": {"id": "tst", "conditions": ["C0", "C2"], "defenses": ["B0"],
                       "framing": "defensive"},
        "seed": 1,
        "data": {"manifest": str(man)},
        "llm": {"mode": "mock"},
        "transformer": {"mode": "mock"},
        "output": {"dir": str(tmp_path / "out")},
    }


def test_unparseable_sample_skips_disclosed_not_crash(manifest_cfg):
    results_path = run_experiment(manifest_cfg, dry_run=True)  # must NOT raise
    data = json.loads(open(results_path, encoding="utf-8").read())
    by_sample = {}
    for r in data["records"]:
        by_sample.setdefault(r["sample_id"], []).append(r)
    # good sample produced normal records
    assert any(r["status"] != "SKIPPED" for r in by_sample[1])
    # bad sample: C0 (identity, no parsing) still runs; C2 must be SKIPPED
    bad_c2 = [r for r in by_sample[2] if r["condition"] == "C2"]
    assert bad_c2 and all(r["status"] == "SKIPPED" for r in bad_c2)
    assert all(r["y_pred"] is None for r in bad_c2)
    assert "semantics" in bad_c2[0]["meta"]["condition_error"].lower() or \
        "parse" in bad_c2[0]["meta"]["condition_error"].lower()
    assert any(r["status"] != "SKIPPED" for r in by_sample[2] if r["condition"] == "C0")
    # skipped rows are excluded from metrics groups but counted
    assert data["metrics"]["n_skipped_records"] == 1  # 1 unit (C2) x 1 defense


def test_results_metadata_has_corpus_source(manifest_cfg):
    results_path = run_experiment(manifest_cfg, dry_run=True)
    data = json.loads(open(results_path, encoding="utf-8").read())
    assert data["metadata"]["corpus_source"].startswith("manifest:")
    assert data["metadata"]["dry_run"] is True


def test_metrics_hook_canonical_schema(manifest_cfg):
    results_path = run_experiment(manifest_cfg, dry_run=True)
    data = json.loads(open(results_path, encoding="utf-8").read())
    groups = data["metrics"]["groups"]
    assert groups, "expected at least one metrics group"
    for g, m in groups.items():
        assert "error" not in m, (g, m)  # schema mismatch would surface here
        assert m["n"] > 0
