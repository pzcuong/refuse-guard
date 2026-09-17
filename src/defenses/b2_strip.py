"""B2 — Comment stripping via tree-sitter (PROPOSAL §8.1).

Removes comment nodes only (comments and Doxygen-style docstrings, which ARE
comment nodes in C); string/char literal data is never touched. The result must
pass the strict semantics gate: executable AST incl. string literals identical
to the original (ignore_strings=False).
"""
from __future__ import annotations

from ..conditions.carriers import expand_comment_lines
from ..conditions.parser_utils import check_semantics, resolve_language
from .b1_reframe import load_defenses_config  # re-exported for convenience


def apply(sample: dict, cfg: dict, language: str = "c") -> dict:
    """Return {"func": stripped, "meta": {...}}; falls back to the original
    (applied=False) if the strict gate fails, so B2 never corrupts a sample."""
    func = sample["func"]
    language = sample.get("language") or resolve_language(func, language)
    try:
        stripped, n_removed = expand_comment_lines(func, language)
    except ValueError as exc:
        return {"func": func, "meta": {"defense": "B2", "applied": False,
                                       "semantics_ok": False, "reason": str(exc)}}
    strict = (cfg.get("B2") or {}).get("verify_semantics_strict", True)
    ok = check_semantics(func, stripped, language=language, ignore_strings=not strict)
    if not ok:
        # never hand the LLM corrupted code; disclose instead
        return {"func": func, "meta": {"defense": "B2", "applied": False,
                                       "semantics_ok": False,
                                       "reason": "strict semantics gate failed"}}
    return {
        "func": stripped,
        "meta": {
            "defense": "B2",
            "applied": True,
            "n_comments_removed": n_removed,
            "semantics_ok": True,
            "semantics_strict": strict,
        },
    }
