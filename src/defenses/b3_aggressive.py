"""B3 — Aggressive text removal (PROPOSAL §8.1).

Masks comments AND string/char literal contents (replaced by placeholders) to
measure clean-utility loss of the strongest non-semantic-preserving baseline.
Gate: executable AST minus string subtrees identical to the original
(check_semantics with ignore_strings=True).
"""
from __future__ import annotations

from ..conditions.carriers import expand_comment_lines
from ..conditions.parser_utils import check_semantics, parse, iter_nodes, resolve_language


def _mask_strings(func: str, str_placeholder: str, char_placeholder: str,
                  language: str) -> tuple[str, int]:
    """Replace the contents of every string/char literal with a placeholder."""
    tree = parse(func, language)
    if tree is None or tree.root_node.has_error:
        raise ValueError("cannot parse function for aggressive masking")
    spans = []  # (start, end, replacement) over content between the quotes
    for node in iter_nodes(tree.root_node):
        if node.type == "string_literal" and node.end_byte - node.start_byte >= 2:
            spans.append((node.start_byte + 1, node.end_byte - 1, str_placeholder))
        elif node.type == "char_literal" and node.end_byte - node.start_byte >= 2:
            spans.append((node.start_byte + 1, node.end_byte - 1, char_placeholder))
    out, last = [], 0
    for start, end, repl in spans:
        out.append(func[last:start])
        out.append(repl)
        last = end
    out.append(func[last:])
    return "".join(out), len(spans)


def apply(sample: dict, cfg: dict, language: str = "c") -> dict:
    """Return {"func": masked, "meta": {...}}; original + applied=False on gate
    failure (B3 must never return unparseable code)."""
    func = sample["func"]
    language = sample.get("language") or resolve_language(func, language)
    b3 = cfg.get("B3") or {}
    str_ph = b3.get("string_placeholder", "__STR__")
    char_ph = b3.get("char_placeholder", "#")
    try:
        no_comments, n_comments = expand_comment_lines(func, language)
        masked, n_strings = _mask_strings(no_comments, str_ph, char_ph, language)
    except ValueError as exc:
        return {"func": func, "meta": {"defense": "B3", "applied": False,
                                       "semantics_ok": False, "reason": str(exc)}}
    # string subtrees changed by design -> compare AST with ignore_strings=True
    ok = check_semantics(func, masked, language=language, ignore_strings=True)
    if not ok:
        return {"func": func, "meta": {"defense": "B3", "applied": False,
                                       "semantics_ok": False,
                                       "reason": "AST-minus-strings gate failed"}}
    return {
        "func": masked,
        "meta": {
            "defense": "B3",
            "applied": True,
            "n_comments_removed": n_comments,
            "n_literals_masked": n_strings,
            "semantics_ok": True,
        },
    }
