"""Round-9 ladder tests (agent W2): config integrity, byte-identical-prompt
guard against round-6 records, subset pairing with rounds 6/7, model-guard,
and a MockLLM dry e2e.  No GPU, no generation."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from src.experiments.round7_7b import ModelGuardError, build_subsets as \
    build_subsets_r7, load_config as load_config_r7, model_guard
from src.experiments.round9_ladder import (build_subsets, dry_stage,
                                           load_config, model_id_of)
from src.experiments.pilot_round2 import sha16
from src.experiments.round6_ablation import prompt_for

ROOT = Path(__file__).resolve().parents[1]
R6_ABLATION = ROOT / "outputs/experiments/round6_ablation/results_llama3b__ablation.json"


def test_config_shim_and_model_id():
    cfg = load_config()
    mid = model_id_of(cfg)
    assert mid == "unsloth/Llama-3.1-8B-Instruct"
    # legacy-key shim: value is the TRUE round-9 model id (key-only shim)
    assert cfg["models"]["qwen7b"] == mid
    assert cfg["models"]["llama8b"] == mid
    assert len(cfg["_config_sha16"]) == 16
    assert cfg["out_dir"] == "outputs/experiments/round9_8b"


def test_inherited_blocks_equal_round7_config():
    """Everything except models/out_dir/version (and the whitelisted prose
    slots that name the round's model) must be IDENTICAL to the audited
    round-7 config — the pre-registered design may not move."""
    c9 = yaml.safe_load((ROOT / "configs/round9_8b.yaml").read_text())
    c7 = yaml.safe_load((ROOT / "configs/round7_7b.yaml").read_text())
    # (block, key) slots whose text MAY differ because the prose names the
    # round's own model; every OTHER value must be byte-equal
    PROSE_OK = {
        ("pool", "selection_rule"),
        ("ablation", "rungs"),          # compared structurally below
        ("benign_fp_check", "description"),
        ("monitor", "thresholds_source"),
        ("reuse", "rule"),
        ("stats", "mcnemar_method_disclosure"),
        ("metrics_defs", "fp_benign"),
        ("hypotheses", "H-R7-harm-replicates"),      # statements say 7B vs
        ("hypotheses", "H-R7-harm-absent"),          # 8B; RULES compared
        ("hypotheses", "H-R7-A1-minimal-safe"),      # byte-for-byte below
        ("hypotheses", "H-R7-benign-verdict-bias"),
    }
    diffs = []
    for block in ("gen_cfg", "pool", "ablation", "benign_fp_check", "reuse",
                  "monitor", "stats", "metrics_defs", "execution", "P3",
                  "seed", "hypotheses"):
        a, b = c9[block], c7[block]
        if block == "seed":
            if a != b:
                diffs.append((block, "<scalar>"))
            continue
        if block == "ablation":
            assert a["arm"] == b["arm"] and \
                [r["variant"] for r in a["rungs"]] == \
                [r["variant"] for r in b["rungs"]], "rung structure drifted"
        for k in set(a) | set(b):
            if a.get(k) == b.get(k):
                continue
            if (block, k) in PROSE_OK:
                continue
            diffs.append((block, k))
    assert not diffs, f"pre-registered design drifted from round 7: {diffs}"
    # rule algebra byte-for-byte (hypotheses WITHOUT a separate rule key --
    # A1-safe in round 7 -- keep the rule embedded in the statement, so
    # presence/absence of the key must match too)
    for h in ("H-R7-harm-replicates", "H-R7-harm-absent",
              "H-R7-A1-minimal-safe", "H-R7-benign-verdict-bias"):
        assert ("rule" in c9["hypotheses"][h]) == \
            ("rule" in c7["hypotheses"][h]), f"rule-key presence changed: {h}"
        if "rule" in c7["hypotheses"][h]:
            assert c9["hypotheses"][h]["rule"] == \
                c7["hypotheses"][h]["rule"], \
                f"decision RULE text changed for {h}"


def test_subsets_pair_with_round6_and_round7():
    cfg9 = load_config()
    vul9, ben9, _, _ = build_subsets(cfg9)
    cfg7 = load_config_r7(ROOT / "configs/round7_7b.yaml")
    vul7, ben7, _, _ = build_subsets_r7(cfg7)
    assert set(vul9) == set(vul7) and len(vul9) == 60
    assert set(ben9) == set(ben7) and len(ben9) == 30


def test_prompt_sha_matches_round6_records():
    """THE byte-identical guard: for 5 vul samples x 3 rungs the round-9
    prompt sha16 must equal the sha recorded in the round-6 llama-3B
    ablation records for the same (sample, rung)."""
    cfg = load_config()
    vul, _ben, _, _ = build_subsets(cfg)
    r6 = json.loads(R6_ABLATION.read_text(encoding="utf-8"))
    r6_sha = {(r["sample_id"], r["variant"]):
              r.get("meta", {}).get("prompt_sha256_16")
              for r in r6["records"]}
    checked = 0
    for sid in sorted(vul)[:5]:
        for variant in ("A0", "A5", "A1"):
            prompt, _src = prompt_for(vul[sid], variant, cfg)
            assert sha16(prompt) == r6_sha[(sid, variant)], \
                f"prompt drift for ({sid}, {variant})"
            checked += 1
    assert checked == 15


def test_model_guard_refuses_foreign_model():
    model_guard("m/a", "m/a", "ok")
    with pytest.raises(ModelGuardError):
        model_guard("m/a", "m/b", "foreign artifact")
    with pytest.raises(ModelGuardError):
        model_guard("unsloth/Llama-3.1-8B-Instruct",
                    "Qwen/Qwen2.5-Coder-7B-Instruct", "r7 file into r9")


def test_dry_e2e_mock(tmp_path):
    cfg = load_config()
    cfg["out_dir"] = str(tmp_path / "r9dry")
    res = dry_stage(cfg)
    assert res["ok"] is True
    assert res["n_vul_A0"] == 60
    v = res["verdict"]
    for key in ("H-R7-harm-replicates", "H-R7-harm-absent",
                "H-R7-A1-minimal-safe", "H-R7-benign-verdict-bias"):
        assert key in v
    files = sorted(p.name for p in (tmp_path / "r9dry" / "dry").glob("*.json"))
    assert any("vul__A0" in f for f in files)
    assert any("benign__B0" in f for f in files)
