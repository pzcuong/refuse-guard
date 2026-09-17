"""Tests for src/conditions (C0-C3 generator + semantic-preservation gate).

Owner: agent A3. Runs against the real venv tree-sitter ('c' language).
"""
import copy
import re
import warnings

import pytest

from src.conditions.generator import (
    apply_condition,
    check_semantics,
    condition_combos,
    load_config,
)
from src.conditions.parser_utils import iter_nodes, parse

warnings.filterwarnings("ignore", category=FutureWarning)

# Function with: preproc, existing comments, string/char literals, a call sink.
FUNC = '''#include <string.h>
/* module header comment */
int run_cmd(char *user) {
    // inline note
    char cmd[128] = "logger -t run";
    char local[64];
    char tag = 'a';
    strcpy(local, user);            /* trailing risk note */
    return system(cmd);
}
'''


def make_sample(func: str = FUNC, label: int = 1, sample_id: str = "t_sample"):
    return {"sample_id": sample_id, "pair_id": None, "func": func, "label": label,
            "cwe": "CWE-120", "cve": None, "project": "test", "split": "test"}


@pytest.fixture(scope="module")
def cfg():
    return load_config()


# ---------------------------------------------------------------- C0 / C1
def test_c0_identity(cfg):
    out = apply_condition(make_sample(), "C0", cfg)
    assert out["func"] == FUNC
    assert out["meta"]["carrier"] is None
    assert out["meta"]["semantics_ok"] is True
    assert out["meta"]["condition"] == "C0"


def test_c1_func_unchanged_and_meta(cfg):
    out = apply_condition(make_sample(), "C1", cfg)
    assert out["func"] == FUNC  # prompt-level only
    m = out["meta"]
    assert m["prompt_variant_key"] in {v["id"] for v in cfg["C1"]["prompt_variants"]}
    assert m["neutral_prompt"] and m["defensive_prompt"]


def test_c1_has_at_least_6_variants_neutral_vs_defensive(cfg):
    variants = cfg["C1"]["prompt_variants"]
    assert len(variants) >= 6  # anti single-trigger principle
    trigger_re = re.compile(
        r"\b(exploits?|payloads?|bypass(es)?|malware|weaponi[sz]ed?|attackers?|"
        r"backdoor|trojan|injection|penetration-test)\b", re.I)
    for v in variants:
        assert v["id"] and v["neutral"] and v["defensive"]
        assert trigger_re.search(v["defensive"]), v["id"]
        assert not trigger_re.search(v["neutral"]), v["id"]


def test_c1_label_preserved(cfg):
    for label in (0, 1):
        s = make_sample(label=label)
        for cond in ("C0", "C1", "C2", "C3"):
            out = apply_condition(s, cond, cfg)
            assert out["meta"]["label"] == label


# ---------------------------------------------------------------- C2 / C3
CFG = load_config()
ALL_C2 = [(t["id"], c, p)
          for t in CFG["C2"]["templates"]
          for c in CFG["C2"]["carriers"]
          for p in CFG["C2"]["positions"]]
ALL_C3 = [(t["id"], c, p)
          for t in CFG["C3"]["templates"]
          for c in CFG["C3"]["carriers"]
          for p in CFG["C3"]["positions"]]


@pytest.mark.parametrize("tpl,carrier,position", ALL_C2)
def test_c2_every_combo_passes_semantics_gate(cfg, tpl, carrier, position):
    c = copy.deepcopy(cfg)
    c["C2"]["pin"] = {"template_id": tpl, "carrier": carrier, "position": position}
    out = apply_condition(make_sample(), "C2", c)
    assert out["meta"]["semantics_ok"] is True
    assert out["meta"]["template_id"] == tpl
    assert out["meta"]["carrier"] == carrier
    assert out["meta"]["position"] == position
    if carrier == "string_literal_tail":
        assert out["meta"]["modifies_string_data"] is True
        assert check_semantics(FUNC, out["func"], ignore_strings=True)
    else:
        assert out["meta"]["modifies_string_data"] is False
        assert check_semantics(FUNC, out["func"], ignore_strings=False)  # strict


@pytest.mark.parametrize("tpl,carrier,position", ALL_C3)
def test_c3_every_combo_passes_semantics_gate_and_family(cfg, tpl, carrier, position):
    c = copy.deepcopy(cfg)
    c["C3"]["pin"] = {"template_id": tpl, "carrier": carrier, "position": position}
    out = apply_condition(make_sample(), "C3", c)
    assert out["meta"]["semantics_ok"] is True
    families = {t["id"]: t["attack_family"] for t in cfg["C3"]["templates"]}
    assert out["meta"]["attack_family"] == families[tpl]
    assert check_semantics(FUNC, out["func"], ignore_strings=False)  # comments only


def test_c2_c3_at_least_6_templates(cfg):
    assert len(cfg["C2"]["templates"]) >= 6
    assert len(cfg["C3"]["templates"]) >= 6


def test_c2_label_and_semantics_untouched_by_carrier(cfg):
    """Label survives every carrier; no comment carrier may add executable nodes."""
    for carrier in ("top_comment", "inline_comment", "docstring"):
        c = copy.deepcopy(cfg)
        c["C2"]["pin"] = {"carrier": carrier, "position": "near"}
        out = apply_condition(make_sample(label=0), "C2", c)
        assert out["meta"]["label"] == 0
        tree_before = _count_exec_nodes(FUNC)
        tree_after = _count_exec_nodes(out["func"])
        assert tree_before == tree_after


def _count_exec_nodes(code: str) -> int:
    tree = parse(code, "c")
    return sum(1 for n in iter_nodes(tree.root_node)
               if n.type not in ("comment",))


def test_determinism_same_input_same_transform(cfg):
    s = make_sample()
    a = apply_condition(s, "C2", cfg)
    b = apply_condition(copy.deepcopy(s), "C2", cfg)
    assert a == b


def test_unknown_condition_raises(cfg):
    with pytest.raises(ValueError):
        apply_condition(make_sample(), "C9", cfg)


def test_unparseable_input_raises_or_skips():
    bad = make_sample(func="this is not C code %%% {{{")
    with pytest.raises(ValueError):
        apply_condition(bad, "C2", load_config())
    c = load_config()
    c["C2"]["on_semantics_fail"] = "skip"
    out = apply_condition(bad, "C2", c)
    assert out["meta"]["applied"] is False and out["meta"]["semantics_ok"] is False


def test_condition_combos_grid(cfg):
    combos = condition_combos(cfg, "C2")
    assert len(combos) == len(cfg["C2"]["templates"]) * len(cfg["C2"]["carriers"]) * len(cfg["C2"]["positions"])
    assert all(set(x) >= {"template_id", "carrier", "position"} for x in combos)


# --- regression: audit round 1 / V2 #1 — PrimeVul contains ~65% C++ ---------
CPP_FUNC = '''namespace util {

class Adder {
public:
    /// trivial arithmetic helper used by the fuzz target
    int add_checked(int a, int b) {
        if (a > 0 && b > 0 && a + b < 0) {
            return -1;
        }
        return a + b;
    }
};

}
'''


def test_cpp_code_auto_language_detection():
    from src.conditions.parser_utils import resolve_language
    assert resolve_language(CPP_FUNC, "c") == "cpp"
    # parse() with auto=True falls back to the cpp grammar transparently
    tree = parse(CPP_FUNC, "c")
    assert tree is not None and not tree.root_node.has_error
    # pure C stays 'c'
    assert resolve_language(FUNC, "c") == "c"


def test_cpp_sample_c2_c3_p1_all_apply(cfg):
    """C++ samples (no 'language' field) must pass C2/C3 and P1 via the
    auto-selected cpp grammar — before the fix this raised ValueError."""
    from src.defenses.b1_reframe import load_defenses_config
    from src.defenses.mediator import mediate
    sample = make_sample(func=CPP_FUNC)
    for cond in ("C2", "C3"):
        out = apply_condition(sample, cond, cfg)
        assert out["meta"]["semantics_ok"] is True, out["meta"]
        assert out["meta"]["language"] == "cpp"
        assert check_semantics(CPP_FUNC, out["func"], ignore_strings=True)
    med = mediate({"func": CPP_FUNC}, "P1", load_defenses_config())
    assert med["meta"]["applied"] is True, med["meta"]
    assert "UNTRUSTED-ANNOTATION" in med["func"]
