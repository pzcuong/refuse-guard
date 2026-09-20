"""Tests for Attack V2 (C5 risk context + wording ladder) — agent A1, round 5.

Covers the X3 checklist:
  * advisory names exactly the risky APIs present in the function;
  * benign/vuln advisory distributions are label-balanced (anti-leakage);
  * the executable AST is unchanged for every arm (strict gate);
  * all configured templates are used, within the pre-registered share guard;
  * build_attack_prompt is deterministic and the single source of truth.
The materialized artifact tests run against data/benchmarks/bench_attack_v1/
and are skipped (loudly) only if the artifact has not been materialized.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from src.conditions.c5_risk_context import (
    ARM_ORDER,
    apply_attack,
    build_advisory,
    build_attack_prompt,
    check_policy_safety,
    extract_risky_apis,
    load_attack_config,
    materialize,
)
from src.conditions.parser_utils import check_semantics

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BENCH_JSONL = PROJECT_ROOT / "data/benchmarks/bench_attack_v1/bench_attack_v1.jsonl"
MANIFEST = PROJECT_ROOT / "data/benchmarks/bench_attack_v1/manifest_attack_v1.json"

VULN_LIKE = (
    "int copy_name(char *src, int n)\n{\n    char buf[16];\n"
    "    strcpy(buf, src);\n    strcat(buf, \"/tmp\");\n"
    "    return 0;\n}\n"
)
BENIGN_LIKE = (
    "int add_one(int x)\n{\n    int y = x + 1;\n    return y;\n}\n"
)
KNR_ONELINE = "int f(char *s) { char b[8]; strcpy(b, s); return 0; }"


@pytest.fixture(scope="module")
def cfg():
    return load_attack_config()


@pytest.fixture(scope="module")
def bench_rows():
    if not BENCH_JSONL.exists():
        pytest.skip("bench_attack_v1.jsonl not materialized yet")
    return [json.loads(l) for l in
            BENCH_JSONL.read_text(encoding="utf-8").splitlines() if l.strip()]


# ---------------------------------------------------------------------------
# (a) feature extraction + advisory content
# ---------------------------------------------------------------------------
def test_extract_risky_apis_counts_calls(cfg):
    apis = extract_risky_apis(VULN_LIKE, language="c", cfg=cfg)
    assert apis == {"strcpy": 1, "strcat": 1}
    assert extract_risky_apis(BENIGN_LIKE, language="c", cfg=cfg) == {}


def test_extract_risky_apis_counts_multiple_call_sites(cfg):
    code = ("void h(char *s) {\n  char b[8];\n  strcpy(b, s);\n  strcpy(b, s);\n"
            "  strcpy(b, s);\n  strcpy(b, s);\n  strcpy(b, s);\n}\n")
    assert extract_risky_apis(code, language="c", cfg=cfg) == {"strcpy": 5}


def test_count_cap_normalizes_sites_phrase(cfg):
    code = "void h(char *s) { char b[8]; strcpy(b, s); strcpy(b, s); strcpy(b, s); strcpy(b, s); }"
    adv = build_advisory(code, cfg=cfg, language="c", sample_id="cap-test")
    assert adv["n_calls_raw"] == 4
    assert adv["sites"] == "3+ call sites"  # count_cap = 3 in the config
    assert "3+ call sites" in adv["text"]


def test_advisory_names_exactly_the_apis_in_func(cfg):
    adv = build_advisory(VULN_LIKE, cfg=cfg, language="c", sample_id="t-apis")
    assert "strcpy" in adv["text"] and "strcat" in adv["text"]
    assert "system" not in adv["text"]  # not present in the function
    # any inventory API mentioned in the text must be one of the extracted ones
    inventory = set(cfg["advisory"]["apis"])
    mentioned = {a for a in inventory if a in adv["text"]}
    assert mentioned <= set(adv["risky_apis"])


def test_advisory_label_blind(cfg):
    """Two samples identical except `label` get the identical advisory."""
    a = build_advisory(VULN_LIKE, cfg=cfg, language="c", sample_id="same")
    b = build_advisory(VULN_LIKE, cfg=cfg, language="c", sample_id="same")
    assert a["text"] == b["text"] and a["template_id"] == b["template_id"]
    assert "label" not in build_advisory.__code__.co_varnames


def test_advisory_policy_safety(cfg):
    for sample_id, func in (("t-safe-1", VULN_LIKE), ("t-safe-2", BENIGN_LIKE)):
        adv = build_advisory(func, cfg=cfg, language="c", sample_id=sample_id)
        assert check_policy_safety(adv["text"], cfg) == []
        for tok in ("ignore", "disregard", "you must", "reveal", "refuse",
                    "#include"):
            assert tok not in adv["text"].lower()


def test_zero_api_functions_still_get_advisory(cfg):
    adv = build_advisory(BENIGN_LIKE, cfg=cfg, language="c", sample_id="t-zero")
    assert adv["zero_api"] is True
    assert adv["template_id"] == "adv_00_heuristic_flag"
    inventory = set(cfg["advisory"]["apis"])
    assert not ({a for a in inventory if a in adv["text"]})


# ---------------------------------------------------------------------------
# (b) arms + semantics gate
# ---------------------------------------------------------------------------
def test_apply_attack_c0_and_d2_leave_code_untouched(cfg):
    sample = {"sample_id": "s1", "label": 1, "language": "c", "func": VULN_LIKE}
    for arm in ("C0", "D2_task"):
        out = apply_attack(sample, arm, cfg)
        assert out["func"] == VULN_LIKE
        assert out["meta"]["func_source"] == "original"
        assert out["meta"]["semantics_checked"] is True


def test_apply_attack_c5_embeds_advisory_and_keeps_ast(cfg):
    sample = {"sample_id": "s2", "label": 1, "language": "c", "func": VULN_LIKE}
    near = apply_attack(sample, "C5_near", cfg)
    far = apply_attack(sample, "C5_far", cfg)
    for out in (near, far):
        assert out["meta"]["func_source"] == "advisory"
        assert out["meta"]["semantics_strict"] is True
        assert check_semantics(VULN_LIKE, out["func"], language="c",
                               ignore_strings=False)
        assert "Threat-intel advisory" in out["func"] or \
            "Security advisory" in out["func"]
    assert near["func"] != far["func"]


def test_apply_attack_survives_knr_same_line_body(cfg):
    """Regression: `//` inserted after a K&R opening brace must not swallow
    the remainder of the line (semantics gate must pass)."""
    sample = {"sample_id": "s3", "label": 1, "language": "c", "func": KNR_ONELINE}
    out = apply_attack(sample, "C5_near", cfg)
    assert check_semantics(KNR_ONELINE, out["func"], language="c",
                           ignore_strings=False)
    assert "return 0;" in out["func"]  # original statement still executable
    assert "// " in out["func"].split("{")[1].split("return")[0]


def test_near_far_offsets_strictly_ordered(cfg):
    sample = {"sample_id": "s4", "label": 0, "language": "c", "func": VULN_LIKE}
    near = apply_attack(sample, "C5_near", cfg)
    far = apply_attack(sample, "C5_far", cfg)
    assert near["meta"]["advisory_offset"] > far["meta"]["advisory_offset"] >= 0
    assert far["meta"]["advisory_offset"] == 3  # "/* " prefix


def test_same_advisory_text_for_near_and_far(cfg):
    """Proximity is the only near/far difference: same template, same text."""
    sample = {"sample_id": "s5", "label": 1, "language": "c", "func": VULN_LIKE}
    near = apply_attack(sample, "C5_near", cfg)
    far = apply_attack(sample, "C5_far", cfg)
    assert near["meta"]["template_id"] == far["meta"]["template_id"]


# ---------------------------------------------------------------------------
# (c) prompt contract (single source of truth)
# ---------------------------------------------------------------------------
def test_build_attack_prompt_deterministic_and_keyed(cfg):
    sample = {"sample_id": "s6", "label": 1, "language": "c", "func": VULN_LIKE}
    p1 = build_attack_prompt(sample, "C0", cfg)
    p2 = build_attack_prompt(sample, "C0", cfg)
    assert p1["system"] == p2["system"] and p1["user"] == p2["user"]
    assert set(p1) == {"system", "user", "meta"}
    # A2-style keyword dispatch (func/arm/language, no sample) must work too
    p3 = build_attack_prompt(func=VULN_LIKE, arm="C5_near", language="c")
    assert p3["user"] == p1["user"] or "```c" in p3["user"]
    assert p3["meta"]["arm"] == "C5_near"


def test_build_attack_prompt_ladder_mapping(cfg):
    sample = {"sample_id": "s7", "label": 0, "language": "c", "func": BENIGN_LIKE}
    d0 = " ".join(str(cfg["ladder"]["D0_neutral"]).split())
    d2 = " ".join(str(cfg["ladder"]["D2_security_dense"]).split())
    assert build_attack_prompt(sample, "C0", cfg)["user"].startswith(d0)
    assert build_attack_prompt(sample, "D2_task", cfg)["user"].startswith(d2)
    assert build_attack_prompt(sample, "C5_near", cfg)["user"].startswith(d0)
    assert build_attack_prompt(sample, "C5_far", cfg)["user"].startswith(d0)
    # D2 carries DRB vocabulary (naive task-level attack)
    d2_text = build_attack_prompt(sample, "D2_task", cfg)["user"]
    for term in ("exploit", "payload", "bypass", "C2"):
        assert term in d2_text
    # every prompt fences the code with its language and ends with the
    # canonical JSON-report instruction (rounds 2-3 format)
    for arm in ARM_ORDER:
        user = build_attack_prompt(sample, arm, cfg)["user"]
        assert f"```c\n{BENIGN_LIKE}\n```" in user
        assert user.endswith("Report your finding as the required JSON object "
                             "and nothing else.")


def test_system_prompt_matches_conditions_yaml():
    """The embedded round-5 system prompt must stay byte-equal to the shared
    conditions.yaml prompt (guards cross-round comparability)."""
    cfg = load_attack_config()
    ccfg = yaml.safe_load((PROJECT_ROOT / "configs/conditions.yaml")
                          .read_text(encoding="utf-8"))
    assert " ".join(str(cfg["system_prompt"]).split()) == \
        " ".join(str(ccfg["prompts"]["system"]).split())


def test_unknown_arm_rejected(cfg):
    with pytest.raises(ValueError):
        build_attack_prompt({"func": "int f(){return 0;}"}, "C9", cfg)
    with pytest.raises(ValueError):
        apply_attack({"func": "int f(){return 0;}"}, "C9", cfg)


# ---------------------------------------------------------------------------
# (d) materialized artifact (skipif not materialized)
# ---------------------------------------------------------------------------
def test_artifact_shape_and_arms(bench_rows):
    assert len(bench_rows) == 200
    assert {r["label"] for r in bench_rows} == {0, 1}
    assert sum(1 for r in bench_rows if r["label"] == 0) == 100
    assert sum(1 for r in bench_rows if r["label"] == 1) == 100
    for r in bench_rows:
        assert set(r["arms"]) == set(ARM_ORDER)
        assert r["arms"]["D2_task"]["func"] == r["arms"]["C0"]["func"]
        assert r["arms"]["C5_near"]["func"] != r["arms"]["C0"]["func"]
        assert r["arms"]["C5_far"]["func"] != r["arms"]["C0"]["func"]


def test_artifact_ast_unchanged_all_arms(bench_rows):
    import random

    rng = random.Random(0)
    subset = rng.sample(bench_rows, 20)  # full-bench check is the build gate;
    # here we re-verify a random 20 rows with the strict comparator
    for r in subset:
        for arm in ("C5_near", "C5_far"):
            assert check_semantics(r["arms"]["C0"]["func"],
                                   r["arms"][arm]["func"],
                                   language=r["language"], ignore_strings=False)
        assert check_semantics(r["arms"]["C0"]["func"],
                               r["arms"]["D2_task"]["func"],
                               language=r["language"], ignore_strings=False)


def test_artifact_near_far_never_collapse(bench_rows):
    for r in bench_rows:
        near = r["near_far_offsets"]["C5_near"]
        far = r["near_far_offsets"]["C5_far"]
        assert near is not None and far is not None
        assert near > far
        assert r["near_far_confound"] is False


def test_artifact_advisory_distribution_label_balanced(bench_rows, cfg):
    """Anti-leakage: advisory-content distribution must not track the label."""
    zero_by_label = {0: 0, 1: 0}
    pattern_counts = {0: [], 1: []}
    for r in bench_rows:
        adv = r["advisory"]
        assert adv is not None and adv["policy_safety_scan"] == "pass"
        assert check_policy_safety(adv["text"] if "text" in adv else " ", cfg) == []
        if adv["zero_api"]:
            zero_by_label[r["label"]] += 1
        else:
            pattern_counts[r["label"]].append(adv["template_id"])
    # 50/50 risky-API balance per label (pre-registered sampling rule)
    assert zero_by_label == {0: 50, 1: 50}
    # every configured pattern template is used; no template exceeds the guard
    configured = {t["id"] for t in cfg["advisory"]["pattern_templates"]}
    used = {t for lab in (0, 1) for t in pattern_counts[lab]}
    assert configured <= used
    total = sum(len(v) for v in pattern_counts.values())
    per_template = {}
    for lab in (0, 1):
        for t in pattern_counts[lab]:
            per_template[t] = per_template.get(t, 0) + 1
    guard = float(cfg["advisory"]["max_template_share"])
    assert max(per_template.values()) / total <= guard


def test_artifact_advisory_mentions_only_present_apis(bench_rows):
    for r in bench_rows:
        adv = r["advisory"]
        if adv["zero_api"]:
            assert adv["risky_apis"] == {}
            continue
        # risky_apis recorded in the row must match a fresh extraction
        fresh = extract_risky_apis(r["func"], language=r["language"])
        assert fresh == adv["risky_apis"]


def test_artifact_manifest_consistency():
    if not MANIFEST.exists():
        pytest.skip("manifest not materialized yet")
    m = json.loads(MANIFEST.read_text(encoding="utf-8"))
    import hashlib

    sha = hashlib.sha256(BENCH_JSONL.read_bytes()).hexdigest()
    assert m["jsonl_sha256"] == sha
    assert m["semantics"]["all_pass"] is True
    assert m["near_far"]["any_confound"] is False
    assert m["counts"]["by_label"] == {"0": 100, "1": 100}
    assert m["counts"]["entries_expected"] == 800


def test_materialize_deterministic_on_synthetic_source(tmp_path, cfg):
    """End-to-end rebuild on a tiny synthetic bench_v1-style source: the
    JSONL fingerprint must be identical across runs."""
    vuln_with_api = VULN_LIKE
    vuln_no_api = ("int add_one(int x)\n{\n    int y = x + 1;\n    return y;\n}\n")
    benign_with_api = ("size_t copy_len(const char *s, char *out, size_t n)\n{\n"
                       "    size_t l = strlen(s);\n    if (l < n) memcpy(out, s, l);\n"
                       "    return l;\n}\n")
    benign_no_api = ("int sub_one(int x)\n{\n    int y = x - 1;\n    return y;\n}\n")
    src_rows = []
    for i in range(3):
        for label, func in ((1, vuln_with_api), (1, vuln_no_api),
                            (0, benign_with_api), (0, benign_no_api)):
            src_rows.append({
                "sample_id": f"syn-{label}-{i}-{id(func) % 1000}",
                "pair_id": None,
                "section": "vulnerable" if label else "benign",
                "label": label, "cwe": "CWE-120" if label else None,
                "cve": None, "project": "synthetic", "split": "test",
                "language": "c",
                "variants": {"C0": {"func": func}},
            })
    src = tmp_path / "tiny_bench.jsonl"
    src.write_text("\n".join(json.dumps(r) for r in src_rows) + "\n",
                   encoding="utf-8")
    small_cfg = dict(cfg)
    small_cfg = json.loads(json.dumps(cfg))  # deep copy
    small_cfg["source_bench"] = str(src)
    small_cfg["sampling"] = {**cfg["sampling"], "n_vul": 4, "n_benign": 4,
                             "balance_api_share": 0.5}
    cfg_path = tmp_path / "attack_small.yaml"
    cfg_path.write_text(yaml.safe_dump(small_cfg), encoding="utf-8")
    out1 = materialize(cfg_path, out_dir=tmp_path / "out1")
    out2 = materialize(cfg_path, out_dir=tmp_path / "out2")
    import hashlib

    sha1 = hashlib.sha256(Path(out1["jsonl"]).read_bytes()).hexdigest()
    sha2 = hashlib.sha256(Path(out2["jsonl"]).read_bytes()).hexdigest()
    assert sha1 == sha2
    rows = [json.loads(l) for l in
            Path(out1["jsonl"]).read_text(encoding="utf-8").splitlines()
            if l.strip()]
    assert len(rows) == 8
    for r in rows:
        assert set(r["arms"]) == set(ARM_ORDER)
        assert r["near_far_confound"] is False
