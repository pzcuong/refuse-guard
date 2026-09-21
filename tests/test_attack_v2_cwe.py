"""Tests for bench_attack_v2 (CWE-family extension of the C5 attack) — A1, round 7.

Covers:
  * config contract: >=4 family templates, signals defined, ladder/system/
    arms/pattern templates byte-equal to configs/attack_v2.yaml;
  * advisory behavior: sink -> pattern template, family feature signal ->
    family template, neither -> zero-API fallback (presence 100% both labels);
  * anti-leakage: label-blind advisory text, signature-rate matched across
    labels per family, policy-safety token scan;
  * artifact: layout identical to bench_attack_v1 (1 row per sample, arms
    dict, advisory embedded in C5 funcs), strict AST preservation, near/far
    ordering, deterministic prompts, no overlap with bench_attack_v1.
Artifact tests are skipped (loudly) only if the bench has not been materialized.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from src.conditions.bench_attack_v2 import DEFAULT_OUTPUT_DIR, select_cells, scan_pool
from src.conditions.c5_risk_context import (
    ARM_ORDER,
    apply_attack,
    build_advisory,
    build_attack_prompt,
    check_policy_safety,
    extract_family_signals,
    extract_risky_apis,
    load_attack_config,
)
from src.conditions.parser_utils import check_semantics

PROJECT_ROOT = Path(__file__).resolve().parents[1]
V2_JSONL = DEFAULT_OUTPUT_DIR / "bench_attack_v2.jsonl"
V2_MANIFEST = DEFAULT_OUTPUT_DIR / "manifest_attack_v2.json"
V1_CFG = "configs/attack_v2.yaml"
V2_CFG = "configs/attack_v2_cwe.yaml"

PTR_FUNC = (
    "int f(struct s *p, int n)\n{\n    int x = 0;\n    if (!p) return -1;\n"
    "    x += p->a;\n    x += p->b->c;\n    x += p->d;\n    return x;\n}\n"
)
HEAP_FUNC = (
    "int g(int n)\n{\n    char *b = malloc(n);\n    if (!b) return -1;\n"
    "    b[0] = 1;\n    free(b);\n    return 0;\n}\n"
)
MUL_FUNC = "int h(int a, int b)\n{\n    return a * b + 1;\n}\n"
PLAIN_FUNC = "int k(int x)\n{\n    return x + 1;\n}\n"
STATIC_FUNC = (
    "int c(void)\n{\n    static int hits = 0;\n    hits++;\n    return hits;\n}\n"
)


@pytest.fixture(scope="module")
def cfg():
    return load_attack_config(V2_CFG, refresh=True)


@pytest.fixture(scope="module")
def cfg_v1():
    return load_attack_config(V1_CFG)


@pytest.fixture(scope="module")
def bench():
    if not V2_JSONL.exists():
        pytest.skip(f"bench_attack_v2 not materialized at {V2_JSONL}")
    rows = [json.loads(l) for l in V2_JSONL.read_text(encoding="utf-8").splitlines()
            if l.strip()]
    return rows, json.loads(V2_MANIFEST.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# config contract
# ---------------------------------------------------------------------------
def test_family_templates_exist_and_anchored(cfg):
    tpls = cfg["advisory"]["family_templates"]
    assert len(tpls) >= 4
    ids = [t["id"] for t in tpls]
    assert len(ids) == len(set(ids))
    for t in tpls:
        assert "{signal_class}" in t["text"]  # anchored on a FEATURE phrase


def test_family_signals_defined_with_thresholds(cfg):
    sigs = cfg["advisory"]["family_signals"]
    for fam, fcfg in cfg["families"].items():
        assert fcfg["anchor_signal"] in sigs, fam  # every family has its signal
    for name, sig in sigs.items():
        assert sig.get("kind") in ("api", "pointer_surface", "static_shared",
                                   "mul_sites"), name
        assert int(sig.get("min_count", 1)) >= 1
        assert sig.get("description")


def test_ladder_system_arms_equal_v1_for_comparability(cfg, cfg_v1):
    assert cfg["ladder"] == cfg_v1["ladder"]
    assert " ".join(cfg["system_prompt"].split()) == \
        " ".join(cfg_v1["system_prompt"].split())
    assert cfg["arms"] == cfg_v1["arms"]
    assert list(cfg["arm_order"]) == list(cfg_v1["arm_order"]) == list(ARM_ORDER)


def test_pattern_and_zero_api_templates_verbatim_from_v1(cfg, cfg_v1):
    assert cfg["advisory"]["pattern_templates"] == cfg_v1["advisory"]["pattern_templates"]
    assert cfg["advisory"]["zero_api_templates"] == cfg_v1["advisory"]["zero_api_templates"]
    assert cfg["advisory"]["apis"] == cfg_v1["advisory"]["apis"]
    assert cfg["advisory"]["forbidden_tokens"] == cfg_v1["advisory"]["forbidden_tokens"]


# ---------------------------------------------------------------------------
# advisory behavior (W2)
# ---------------------------------------------------------------------------
def test_signal_kind_selection_synthetic(cfg):
    assert "pointer_surface" in extract_family_signals(PTR_FUNC, cfg=cfg)
    assert "heap_lifecycle" in extract_family_signals(HEAP_FUNC, cfg=cfg)
    assert "arith_scaling" in extract_family_signals(MUL_FUNC, cfg=cfg)
    assert "shared_state" in extract_family_signals(STATIC_FUNC, cfg=cfg)
    assert extract_family_signals(PLAIN_FUNC, cfg=cfg) == {}


def test_advisory_kind_pools(cfg):
    assert build_advisory(HEAP_FUNC, cfg=cfg, sample_id="a")["advisory_kind"] == "pattern"
    assert build_advisory(MUL_FUNC, cfg=cfg, sample_id="b")["advisory_kind"] == "family"
    assert build_advisory(PLAIN_FUNC, cfg=cfg, sample_id="c")["advisory_kind"] == "zero_api"


def test_family_advisory_names_feature_not_label(cfg):
    adv = build_advisory(MUL_FUNC, cfg=cfg, sample_id="b")
    desc = cfg["advisory"]["family_signals"]["arith_scaling"]["description"]
    assert desc in adv["text"]
    assert adv["family_signals"] == {"arith_scaling": 1}


def test_label_blindness_family_and_pattern_paths(cfg):
    for func in (PTR_FUNC, MUL_FUNC, PLAIN_FUNC, HEAP_FUNC):
        a = build_advisory(func, cfg=cfg, sample_id="S1")
        b = build_advisory(func, cfg=cfg, sample_id="S1")  # same id, "flipped label"
        assert a["text"] == b["text"]
        assert a["template_id"] == b["template_id"]


def test_policy_safety_all_templates_extreme_render(cfg):
    acfg = cfg["advisory"]
    cap = int(acfg["count_cap"])
    extreme = {"apis": {k: 99 for k in acfg["apis"]},
               "signals": {k: 99 for k in acfg["family_signals"]}}
    texts = []
    for pool, kw in ((acfg["pattern_templates"], {"apis": extreme["apis"]}),
                     (acfg["family_templates"], {"signals": extreme["signals"]}),
                     (acfg["zero_api_templates"], {})):
        for t in pool:
            from src.conditions.c5_risk_context import _render, family_signal_classes
            texts.append(_render(t["text"], next(iter(kw.get("apis", {})), ""),
                                 acfg["apis"], kw.get("apis", {}), cap,
                                 signals=kw.get("signals"),
                                 signal_classes=family_signal_classes(cfg)))
    assert texts and all(check_policy_safety(t, cfg) == [] for t in texts)


def test_old_config_keeps_v1_behavior(cfg_v1):
    # attack_v2.yaml has no family_signals key: kind never "family", no signals
    for func in (PTR_FUNC, MUL_FUNC, HEAP_FUNC, PLAIN_FUNC):
        adv = build_advisory(func, cfg=cfg_v1, sample_id="z")
        assert adv["advisory_kind"] in ("pattern", "zero_api")
        assert adv["family_signals"] == {}


def test_count_cap_normalization_signals(cfg):
    many = ("int f(struct s *p)\n{\n    int x = 0;\n"
            + "".join(f"    x += p->f{i};\n" for i in range(7))
            + "    return x;\n}\n")
    adv = build_advisory(many, cfg=cfg, sample_id="cap")
    assert "3+ matched sites" in adv["text"]  # capped like the v1 {sites} rule


# ---------------------------------------------------------------------------
# artifact: shape + distributions
# ---------------------------------------------------------------------------
def test_artifact_shape_and_family_cells(bench, cfg):
    rows, mf = bench
    fams = list(cfg["family_order"])
    assert len(rows) == 160
    assert mf["counts"]["by_label"] == {"0": 80, "1": 80}
    assert mf["counts"]["entries_expected"] == 640
    for fam in fams:
        cell = [r for r in rows if r["family"] == fam]
        assert len(cell) == 40
        assert sum(1 for r in cell if r["label"] == 1) == 20
        assert sum(1 for r in cell if r["label"] == 0) == 20
    for r in rows:
        assert list(r["arms"]) == list(ARM_ORDER)
        assert r["arms"]["C0"]["func"] == r["func"]


def test_no_overlap_with_bench_attack_v1(bench):
    rows, _ = bench
    v1_ids = {json.loads(l)["sample_id"] for l in
              (PROJECT_ROOT / "data/benchmarks/bench_attack_v1/bench_attack_v1.jsonl")
              .read_text(encoding="utf-8").splitlines() if l.strip()}
    assert not v1_ids & {r["sample_id"] for r in rows}


def test_signature_rate_matched_across_labels(bench):
    rows, mf = bench
    assert mf["signature_balance_ok"] is True
    for fam in mf["counts"]["families"]:
        sig = {l: sum(1 for r in rows if r["family"] == fam and r["label"] == l
                      and r["has_signature"]) for l in (0, 1)}
        assert sig[0] == sig[1], (fam, sig)
    # advisory content-type distribution (kind level) matched across labels
    kinds = {l: {} for l in (0, 1)}
    for r in rows:
        k = r["advisory"]["advisory_kind"]
        kinds[r["label"]][k] = kinds[r["label"]].get(k, 0) + 1
    assert kinds[0].get("zero_api", 0) == kinds[1].get("zero_api", 0)


def test_advisory_presence_and_family_appropriateness(bench, cfg):
    rows, _ = bench
    descs = {k: v["description"] for k, v in cfg["advisory"]["family_signals"].items()}
    for r in rows:
        adv = r["advisory"]
        assert adv is not None  # presence 100% both labels
        kind = adv["advisory_kind"]
        if kind == "family":
            assert adv["family_signals"]
            marker = any(descs[s] in " ".join(
                r["arms"][a]["func"] for a in ("C5_near",)) for s in adv["family_signals"])
            assert marker  # the feature phrase is embedded in the C5 func
        if kind == "zero_api":
            assert adv["template_id"] == "adv_00_heuristic_flag"
            assert not adv["risky_apis"] and not adv["family_signals"]


def test_policy_safety_on_materialized_advisories(bench, cfg):
    # Reconstruct the exact advisory text (same seeded draw as the build) and
    # re-run the forbidden-token scan on THAT text; do not scan arbitrary
    # comment lines — PrimeVul functions carry their own pre-existing comments.
    rows, _ = bench
    for r in rows[:40]:
        adv = build_advisory(r["func"], cfg=cfg, sample_id=r["sample_id"])
        assert check_policy_safety(adv["text"], cfg) == []
        assert adv["template_id"] == r["advisory"]["template_id"]
        # the reconstructed advisory is verbatim what was embedded (near arm)
        assert adv["text"] in r["arms"]["C5_near"]["func"]


# ---------------------------------------------------------------------------
# artifact: semantics + geometry + determinism
# ---------------------------------------------------------------------------
def test_semantics_all_arms_strict(bench):
    rows, _ = bench
    for r in rows:
        for arm in ARM_ORDER:
            payload = r["arms"][arm]
            assert payload["semantics_checked"] and payload["semantics_ok"]
        assert check_semantics(r["func"], r["arms"]["C5_near"]["func"],
                               language=r["language"], ignore_strings=False)
        assert check_semantics(r["func"], r["arms"]["C5_far"]["func"],
                               language=r["language"], ignore_strings=False)


def test_near_far_ordering_all_rows(bench):
    rows, mf = bench
    for r in rows:
        off = r["near_far_offsets"]
        assert off["C5_near"] > off["C5_far"]
        assert r["near_far_confound"] is False
    assert mf["near_far"]["any_confound"] is False


def test_prompt_builder_deterministic_and_v1_compatible(bench):
    rows, _ = bench
    sample_rows = rows[::20]
    for r in sample_rows:
        for arm in ARM_ORDER:
            p1 = build_attack_prompt(func=r["arms"][arm]["func"], arm=arm,
                                     language=r["language"])
            p2 = build_attack_prompt(func=r["arms"][arm]["func"], arm=arm,
                                     language=r["language"])
            assert p1["user"] == p2["user"] and p1["system"] == p2["system"]
    assert build_attack_prompt(func=rows[0]["func"], arm="C0")["system"] == \
        build_attack_prompt(func=rows[0]["func"], arm="C0",
                            cfg=load_attack_config(V1_CFG))["system"]


def test_manifest_checksum_and_jsonl_shape(bench):
    rows, mf = bench
    body = V2_JSONL.read_bytes()
    assert hashlib.sha256(body).hexdigest() == mf["jsonl_sha256"]
    assert mf["semantics"]["all_pass"] is True
    assert mf["sources"]["pool_scan"] == "hit"  # deterministic cached pool


def test_selection_deterministic_cached_pool(cfg):
    rows_a, _ = scan_pool(cfg, cache_path=DEFAULT_OUTPUT_DIR / ".cache_pool_scan.json")
    sel_a, meta_a = select_cells(rows_a, cfg)
    sel_b, meta_b = select_cells(rows_a, cfg)
    assert [r["sample_id"] for r in sel_a] == [r["sample_id"] for r in sel_b]
    assert meta_a["cells"] == meta_b["cells"]
