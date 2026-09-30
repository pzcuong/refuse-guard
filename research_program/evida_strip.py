"""EVIDA V_trusted view construction: D1 comment/docstring stripping, extended
to the C/C++ bench fragments of S1 (RQ8 / bench_attack_v2).

What is reused VERBATIM from the audited round-12 machinery
(`packguard/defense_strip.py`): the removal-span discovery (`_removal_spans`:
comment nodes + python docstrings, pre-order), the line-aware span expansion
(`_line_aware_spans`) and the canonical-signature gate (`_canonical`: prunes
comment nodes + python bare-string statements on BOTH sides, keeps every other
named node and leaf token).  String literals are never removed.

Why an extension is needed at all: `defense_strip` pins LANGUAGES =
(javascript, python) because its round-12 use case was whole npm/pypi files.
The S1 population (bench_attack_v2) is 97 C + 63 C++ *function fragments*;
measured at pilot prep: 0/160 of the C0 views parse CLEANLY under the c/cpp
grammars (PrimeVul fragments start at the declarator, e.g. `mrb_ary_shift_m(
mrb_state *mrb, ...)` with no return type — tree-sitter marks the root ERROR).
A strict clean-parse gate (defense_strip semantics) would exclude 100% of the
registered PRIMARY population, so for c/cpp ONLY this module relaxes the
parse requirement to tree-sitter's error-tolerant mode while KEEPING the
canonical-signature equality gate.  The gate stays sound for comment-only
removal: the signature includes every non-comment leaf token, so any
executable-content difference changes it; comment nodes are pruned on both
sides.  Gate FAIL still means EXCLUDE + DISCLOSE (never silently emitted).
Disclosed in run meta as gate_mode="lenient_canonical_c_cpp".

JS/Python sources are delegated UNCHANGED to `defense_strip.strip_with_gate`
(the audited path, strict parse) — no behavioural difference there.
"""
from __future__ import annotations

import warnings
from typing import Optional

from packguard import defense_strip as ds

__all__ = ["strip_view", "C_CPP_LANGUAGES", "LANGUAGES_D1"]

LANGUAGES_D1 = ds.LANGUAGES                 # javascript, python (audited D1)
C_CPP_LANGUAGES = ("c", "cpp")


def _parse_lenient(source: str, language: str):
    """Error-tolerant parse for C/C++ fragments (None on empty input)."""
    if not source or not source.strip():
        return None
    from tree_sitter_languages import get_parser

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            return get_parser(language).parse(source.encode("utf-8"))
        except Exception:
            return None


def _strip_c_cpp(source: str, language: str) -> tuple[str, dict]:
    """Comment-node-only removal on a C/C++ fragment + canonical-signature
    gate (lenient parse).  Mirrors `defense_strip.strip_with_gate` semantics:
    NEVER raises; gate_fail / parse_fail => source returned unchanged with
    gate_pass=False (caller excludes + discloses)."""
    tree = _parse_lenient(source, language)
    if tree is None:
        return source, {
            "language": language, "n_nodes_removed": 0, "n_comments_removed": 0,
            "n_docstrings_removed": 0, "bytes_removed": 0, "parse_ok": False,
            "gate_pass": False, "gate_mode": "lenient_canonical_c_cpp",
            "gate_error": "empty source or parser failure",
        }
    spans = ds._removal_spans(tree.root_node, language)
    n_comments = sum(1 for _s, _e, k in spans if k == "comment")
    data = source.encode("utf-8")
    line_spans = ds._line_aware_spans(data, spans)
    out_parts, prev = [], 0
    for s, e in line_spans:
        out_parts.append(data[prev:s])
        prev = e
    out_parts.append(data[prev:])
    stripped = b"".join(out_parts).decode("utf-8")
    tree2 = _parse_lenient(stripped, language)
    gate_pass = tree2 is not None and (
        ds._canonical(tree.root_node, language)
        == ds._canonical(tree2.root_node, language))
    return stripped, {
        "language": language,
        "n_nodes_removed": len(spans),
        "n_comments_removed": n_comments,
        "n_docstrings_removed": len(spans) - n_comments,
        "bytes_removed": len(data) - len(stripped.encode("utf-8")),
        "parse_ok": True,
        "gate_pass": bool(gate_pass),
        "gate_mode": "lenient_canonical_c_cpp",
    }


def strip_view(source: str, language: str) -> tuple[str, dict]:
    """V_trusted source view for `source` under D1 semantics.

    javascript/python -> the audited `defense_strip.strip_with_gate` path.
    c/cpp             -> the lenient-canonical extension above (S1 fragments).
    Anything else     -> ValueError (fail loudly; no silent pass-through).
    """
    if language in LANGUAGES_D1:
        stripped, meta = ds.strip_with_gate(source, language)
        return stripped, {**meta, "gate_mode": "d1_strict_audited"}
    if language in C_CPP_LANGUAGES:
        return _strip_c_cpp(source, language)
    raise ValueError(
        f"strip_view: unsupported language {language!r} "
        f"(supported: {sorted(set(LANGUAGES_D1) | set(C_CPP_LANGUAGES))})")


def gate_pass_of(meta: dict) -> bool:
    return bool(meta.get("gate_pass"))
