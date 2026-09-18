"""Benchmark v1 materialization tests (Round 2, agent A1 / task B2-B4).

These tests guard the materialized artifacts under data/benchmarks/ plus the
parseable manifest v2. They validate the FILES as built (not the builder's
good intentions): semantics gate flags, label agreement with the manifest,
C0 completeness, C2 template spread, deterministic rebuild of a row subset,
E0 split disjointness, and safety-contrast structure.
"""
import json
import os

import pytest

from src.data.bench_build import (BENCH_DIR, MANIFEST_DIR, V2_BRIDGE,
                                  V2_MANIFEST, materialize_row,
                                  parse_language, plan_variants)
from src.conditions.generator import load_config as load_conditions_config

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BENCH_JSONL = os.path.join(BENCH_DIR, "bench_v1", "bench_v1.jsonl")
BENCH_META = os.path.join(BENCH_DIR, "bench_v1", "bench_v1_meta.json")
SAFETY_JSON = os.path.join(BENCH_DIR, "safety_contrast_v1.json")
E0_JSONL = os.path.join(BENCH_DIR, "e0_prompts_v1.jsonl")
E0_META = os.path.join(BENCH_DIR, "e0_prompts_v1_meta.json")


def _load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def bench_rows():
    with open(BENCH_JSONL, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


@pytest.fixture(scope="module")
def manifest_v2():
    return _load(os.path.join(MANIFEST_DIR, f"{V2_MANIFEST}.json"))


@pytest.fixture(scope="module")
def bridge():
    return _load(os.path.join(MANIFEST_DIR, f"{V2_BRIDGE}.json"))


@pytest.fixture(scope="module")
def bench_meta():
    return _load(BENCH_META)


# ---------------------------------------------------------------------------
# core invariants required by the Round-2 task B2
# ---------------------------------------------------------------------------
def test_every_variant_semantics_checked(bench_rows):
    assert len(bench_rows) >= 600
    for row in bench_rows:
        for slot in ("C0", "C2a", "C2b", "C3"):
            v = row["variants"].get(slot)
            assert v is not None, f"{row['sample_id']}: missing variant {slot}"
            assert v["semantics_checked"] is True, \
                f"{row['sample_id']}/{slot}: semantics_checked is not True"
            assert isinstance(v["func"], str) and v["func"].strip()
        # the two C2 slots must be distinct transforms
        assert row["variants"]["C2a"]["func"] != row["variants"]["C2b"]["func"], \
            f"{row['sample_id']}: C2a and C2b collapsed to the same text"


def test_no_sample_missing_c0(bench_rows):
    for row in bench_rows:
        c0 = row["variants"]["C0"]
        assert c0["carrier"] is None and c0["template_id"] is None
        # C0 must be the untouched original func (bridge / manifest source)


def test_c0_matches_source_func(bench_rows, bridge):
    by_id = {s["sample_id"]: s["func"] for s in bridge["samples"]}
    meta = _load(BENCH_META)
    for repl in meta["replacement_stats"]["bench_stage_replacements"]:
        from src.data import primevul
        rec = {r["sample_id"]: r for r in primevul.load_primevul("test")}
        by_id[repl["replacement"]] = rec[repl["replacement"]]["func"]
    n_src = 0
    for row in bench_rows:
        if row["sample_id"] in by_id:
            assert row["variants"]["C0"]["func"] == by_id[row["sample_id"]], \
                f"{row['sample_id']}: C0 is not the original func"
            n_src += 1
    assert n_src >= len(bench_rows) - len(
        meta["replacement_stats"]["bench_stage_replacements"])


def test_labels_match_manifest_v2(bench_rows, manifest_v2, bridge):
    label_of = {s["sample_id"]: s["label"] for s in bridge["samples"]}
    meta = _load(BENCH_META)
    # bench rows include paired benign members from the PAIRED split (their ids
    # do not exist in the test split) and bench-stage replacements (in neither
    # manifest): fall back to the underlying PrimeVul records, same pool.
    import src.data.primevul as pv
    test_label = {r["sample_id"]: r["label"] for r in pv.load_primevul("test")}
    test_label.update({r["sample_id"]: r["label"]
                       for r in pv.load_primevul("test_paired")})
    for row in bench_rows:
        expected = label_of.get(row["sample_id"], test_label[row["sample_id"]])
        assert row["label"] == expected, \
            f"{row['sample_id']}: bench label {row['label']} != {expected}"
    # aggregate balance: >= 300 rows per label (task B1 target)
    n1 = sum(1 for r in bench_rows if r["label"] == 1)
    n0 = sum(1 for r in bench_rows if r["label"] == 0)
    assert n1 >= 300 and n0 >= 300, f"label balance broken: {n1} vul / {n0} ben"


def test_c2_templates_not_concentrated(bench_rows):
    """No single C2 template may exceed 40% of the C2a+C2b assignments."""
    from collections import Counter
    counts = Counter()
    for row in bench_rows:
        counts[row["variants"]["C2a"]["template_id"]] += 1
        counts[row["variants"]["C2b"]["template_id"]] += 1
    total = sum(counts.values())
    for tpl, n in counts.items():
        assert n / total <= 0.40, \
            f"template {tpl} over-concentrated: {n}/{total} = {n/total:.2%}"
    assert len(counts) >= 6, f"C2 should spread over most of 8 templates, got {sorted(counts)}"


def test_meta_checksum_matches_jsonl(bench_meta):
    import hashlib
    h = hashlib.sha256(open(BENCH_JSONL, "rb").read()).hexdigest()
    assert bench_meta["checksum"]["value"] == h
    assert bench_meta["checksum"]["algo"] == "sha256"


# ---------------------------------------------------------------------------
# deterministic rebuild (task: rebuild must reproduce the materialized rows)
# ---------------------------------------------------------------------------
def test_deterministic_rebuild_subset(bench_rows):
    conditions_cfg = load_conditions_config(
        os.path.join(ROOT, "configs", "conditions.yaml"))
    meta = _load(BENCH_META)
    seed = int(meta["seed"])
    import src.data.primevul as pv
    test_by_id = {r["sample_id"]: r for r in pv.load_primevul("test")}
    test_by_id.update({r["sample_id"]: r for r in pv.load_primevul("test_paired")})
    manifest_v2 = _load(os.path.join(MANIFEST_DIR, f"{V2_MANIFEST}.json"))
    vul_pair = {p["vulnerable"]: p for p in manifest_v2["paired"]}
    for row in bench_rows[:10] + bench_rows[-10:]:
        s = dict(test_by_id[row["sample_id"]])
        if s["sample_id"] in vul_pair:
            s["pair_id"] = vul_pair[s["sample_id"]]["pair_id"]
        built = materialize_row(s, conditions_cfg, seed)
        assert built is not None, f"{s['sample_id']} no longer materializes"
        parts, frame = built
        for slot in ("C2a", "C2b", "C3"):
            for key in ("func", "carrier", "position", "template_id",
                        "semantics_checked"):
                assert parts[slot][key] == row["variants"][slot][key], \
                    f"{s['sample_id']}/{slot}.{key} rebuild mismatch"
        assert frame["id"] == row["framing"]["frame_id"]
        assert " ".join(frame["neutral"].split()) == row["framing"]["neutral"]
        assert " ".join(frame["defensive"].split()) == row["framing"]["defensive"]


def test_plan_variants_is_pure_and_seeded():
    conditions_cfg = load_conditions_config(
        os.path.join(ROOT, "configs", "conditions.yaml"))
    for sid in ("194989", "x", "999999"):
        a = plan_variants(sid, conditions_cfg, 20260918)
        b = plan_variants(sid, conditions_cfg, 20260918)
        assert a == b
        assert a["C2a"]["template_id"] != a["C2b"]["template_id"]
        assert a["C2a"]["position"] == "near" and a["C2b"]["position"] == "far"


# ---------------------------------------------------------------------------
# manifest v2 (B1)
# ---------------------------------------------------------------------------
def test_manifest_v2_parseable_300_300(manifest_v2, bridge):
    c = manifest_v2["counts"]
    assert c["vulnerable_sampled"] >= 300 and c["benign_sampled"] >= 300
    for s in bridge["samples"]:
        assert parse_language(s["func"]) is not None, \
            f"{s['sample_id']} in v2 bridge is not parseable"
    assert manifest_v2["replacement_policy"]["seed_offsets"]


def test_manifest_v2_contrast_split_copied_verbatim(manifest_v2):
    v1 = _load(os.path.join(MANIFEST_DIR, "eval_subset_v1.json"))
    assert manifest_v2["contrast_prompt_ids"] == v1["contrast_prompt_ids"]
    assert manifest_v2["contrast_split"] == v1["contrast_split"]


# ---------------------------------------------------------------------------
# E0 prompts (B4)
# ---------------------------------------------------------------------------
def test_e0_prompts_counts_and_arms():
    with open(E0_JSONL, encoding="utf-8") as fh:
        rows = [json.loads(line) for line in fh if line.strip()]
    meta = _load(E0_META)
    assert {r["arm"] for r in rows} <= {"neutral", "defensive", "security_context"}
    per_arm = meta["counts"]["per_arm"]
    for arm in ("neutral", "defensive", "security_context"):
        n = sum(1 for r in rows if r["arm"] == arm)
        assert n == per_arm[arm] and n >= 200, f"arm {arm}: {n}"
    fns = [r for r in rows if r["meta"]["kind"] == "function"]
    assert len({r["meta"]["sample_id"] for r in fns}) == 200  # 100 + 100
    import hashlib
    h = hashlib.sha256(open(E0_JSONL, "rb").read()).hexdigest()
    assert meta["checksum"]["value"] == h


def test_e0_calibration_scoring_disjoint():
    meta = _load(E0_META)
    sc = meta["split_confirmation"]
    assert sc["disjoint"] is True and sc["intersection"] == {}
    assert sc["calibration_counts"] == {"orbench_hard": 50, "orbench_toxic": 25,
                                        "xstest_safe": 25, "xstest_unsafe": 25}
    assert sc["scoring_counts"] == sc["calibration_counts"]


# ---------------------------------------------------------------------------
# safety contrast (B3)
# ---------------------------------------------------------------------------
def test_safety_contrast_structure():
    doc = _load(SAFETY_JSON)
    assert doc["name"] == "safety_contrast_v1"
    assert doc["counts"]["safe_defense"] == 30
    assert doc["counts"]["unsafe"] == 30
    for side in ("safe_defense", "unsafe"):
        pids = [p["pid"] for p in doc[side]]
        assert len(set(pids)) == 30
        for p in doc[side]:
            assert p["prompt"] and p["rationale"] and p["inspired_by"]
            assert p["group"] in doc["counts"]["groups"]
            assert p["expected"] == ("COMPLY" if side == "safe_defense"
                                     else "REFUSE")
    groups_safe = {p["group"] for p in doc["safe_defense"]}
    groups_unsafe = {p["group"] for p in doc["unsafe"]}
    assert len(groups_safe) >= 6 and groups_safe == groups_unsafe
    # no overlap between the two splits
    safe_prompts = {p["prompt"] for p in doc["safe_defense"]}
    unsafe_prompts = {p["prompt"] for p in doc["unsafe"]}
    assert not (safe_prompts & unsafe_prompts)
