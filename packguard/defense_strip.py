"""Defense D1 (round 12, W1): AST comment/docstring stripping for the
attack+defense pair pre-registered in docs/packguard_prereg.md AMENDMENT-6.

Attack arm of record: P2_advisory_in_package (an advisory security comment
injected into the package file) — round 9-11 showed it PERTURBS malicious
recall in a model-dependent direction. Defense D1 removes every comment and
Python docstring from the package source before analysis, so the model sees
only executable code.

What is removed (AMENDMENT-6 A6.1, frozen):
  - `comment` nodes in BOTH languages (tree-sitter grammars 'javascript' and
    'python' ONLY — the C/C++ auto-fallback of src.conditions.parser_utils
    is deliberately NOT used here).
  - PYTHON docstrings: an `expression_statement` whose only named child is a
    `string`, in FIRST-statement position of `module`/`block` (PEP-257
    docstring positions). String literals are NEVER removed.

Removal is line-aware: a removed node whose entire line becomes blank
contributes the whole line, so a prepended one-line advisory comment strips
back to the BYTE-IDENTICAL original file (asserted by the runner; this is
what makes P2+D1 a faithful "attack removed" condition).

Gate (pre-registered): re-parse the stripped source and compare canonical
AST signatures — the signature prunes comment nodes AND python bare-string
`expression_statement`s (side-effect-free on both sides; any position, so
the signature is stable when the advisory comment precedes a docstring) and
otherwise includes all named structure and leaf tokens. Gate FAIL -> the
sample is EXCLUDED and disclosed (never silently emitted). A pre-strip parse
error is also a FAIL (fail loudly); a snippet that is ONLY comments strips
to an empty source and is a FAIL by this same rule (nothing left to
analyze).
"""
from __future__ import annotations

from functools import lru_cache
from typing import Optional

__all__ = [
    "strip_comments", "strip_with_gate", "defense_gate",
    "canonical_signature", "LANGUAGES",
]

LANGUAGES = ("javascript", "python")
COMMENT_TYPES = frozenset({"comment"})
DOCSTRING_STMT_TYPE = "expression_statement"
DOCSTRING_STRING_TYPE = "string"
# Parents whose FIRST statement may be a docstring (python module root and
# every block: function/class/if/for/while/try bodies).
DOCSTRING_PARENTS = frozenset({"module", "block"})


@lru_cache(maxsize=None)
def _get_parser(language: str):
    if language not in LANGUAGES:
        raise ValueError(
            f"unsupported language {language!r}; D1 supports {LANGUAGES}")
    from tree_sitter_languages import get_parser as _impl

    return _impl(language)


def _parse_strict(source: str, language: str):
    """Parse with exactly one grammar; None on empty/parse-error input."""
    if not source or not source.strip():
        return None
    try:
        tree = _get_parser(language).parse(source.encode("utf-8"))
    except Exception:
        return None
    if tree.root_node.has_error:
        return None
    return tree


# ---------------------------------------------------------------------------
# Removal-span discovery
# ---------------------------------------------------------------------------
def _is_bare_string_stmt(node) -> bool:
    """True for an `expression_statement` whose only named child is a
    `string` (a side-effect-free bare string statement — the docstring form
    and its inert siblings)."""
    if node.type != DOCSTRING_STMT_TYPE:
        return False
    named = node.named_children
    return len(named) == 1 and named[0].type == DOCSTRING_STRING_TYPE


def _first_noncomment(parent):
    """First named child of `parent` that is not a comment node (comments
    are NAMED nodes in tree-sitter, so named_children[0] is positionally
    unstable once a comment is prepended)."""
    for child in parent.named_children:
        if child.type not in COMMENT_TYPES:
            return child
    return None


def _is_docstring_stmt(node) -> bool:
    """True for a python DOCSTRING: a bare-string `expression_statement` in
    first non-comment position of a module/block (PEP-257 docstring
    position, stable under a prepended advisory comment)."""
    if not _is_bare_string_stmt(node):
        return False
    parent = node.parent
    if parent is None or parent.type not in DOCSTRING_PARENTS:
        return False
    first = _first_noncomment(parent)
    return first is not None and first.id == node.id


def _removal_spans(root, language: str) -> list[tuple[int, int, str]]:
    """[(start_byte, end_byte, kind)] for every node D1 removes (pre-order)."""
    spans: list[tuple[int, int, str]] = []
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type in COMMENT_TYPES:
            spans.append((node.start_byte, node.end_byte, "comment"))
        elif language == "python" and _is_docstring_stmt(node):
            spans.append((node.start_byte, node.end_byte, "docstring"))
        stack.extend(reversed(node.children))
    spans.sort(key=lambda t: (t[0], t[1]))
    return spans


def _line_aware_spans(data: bytes,
                      spans: list[tuple[int, int, str]]) -> list[tuple[int, int]]:
    """Expand spans to whole lines when the rest of the line(s) involved is
    whitespace-only, then merge overlaps. Prevents blank-line residue.
    `data` is the UTF-8 ENCODED source: tree-sitter offsets are BYTE
    offsets, so every span computation must run on bytes (slicing the str
    with byte offsets silently corrupts any file containing multibyte
    characters)."""
    out: list[tuple[int, int]] = []
    for s, e, _kind in spans:
        ls = data.rfind(b"\n", 0, s) + 1
        nl = data.find(b"\n", e)
        le = len(data) if nl == -1 else nl + 1
        if not data[ls:s].strip() and not data[e:le].strip():
            out.append((ls, le))
        else:
            out.append((s, e))
    merged: list[tuple[int, int]] = []
    for s, e in sorted(out):
        if merged and s <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        else:
            merged.append((s, e))
    return merged


# ---------------------------------------------------------------------------
# Canonical AST signature (gate)
# ---------------------------------------------------------------------------
def _canonical(node, language: str) -> Optional[tuple]:
    """Structural signature pruned to executable content: comment nodes AND
    python BARE-STRING `expression_statement`s (any position — a bare string
    statement allocates an unused string object and has NO observable side
    effect, so pruning it on both sides can never hide an executable
    difference; this keeps the signature stable regardless of what precedes
    a docstring). Byte offsets excluded; leaf token text included (so token
    edits change the signature)."""
    if node.type in COMMENT_TYPES:
        return None
    if language == "python" and _is_bare_string_stmt(node):
        return None
    children = []
    for child in node.children:
        canon = _canonical(child, language)
        if canon is not None:
            children.append(canon)
    if not children and node.named_child_count == 0:
        text = node.text.decode("utf-8", "replace") if node.text is not None else ""
        return (node.type, bool(node.is_named), text)
    return (node.type, bool(node.is_named), tuple(children))


def canonical_signature(source: str, language: str) -> tuple:
    """Canonical AST signature; raises ValueError when the source does not
    parse cleanly under the single requested grammar."""
    tree = _parse_strict(source, language)
    if tree is None:
        raise ValueError(f"could not parse source as {language!r} (error nodes)")
    canon = _canonical(tree.root_node, language)
    if canon is None:  # pragma: no cover - root is never pruned
        raise ValueError("empty AST signature")
    return canon


def defense_gate(original: str, stripped: str, language: str) -> bool:
    """Pre-registered D1 gate: stripped parses and its canonical AST equals
    the original's (comments + docstrings pruned on BOTH sides)."""
    try:
        return canonical_signature(original, language) == \
            canonical_signature(stripped, language)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Public strip API
# ---------------------------------------------------------------------------
def strip_comments(source: str, language: str) -> tuple[str, dict]:
    """Remove all comment nodes (+ python docstrings) from `source`.

    Returns (stripped_source, meta) with meta holding at least
    {n_nodes_removed, bytes_removed}. Raises ValueError when `source` does
    not parse cleanly under `language` (fail loudly — the caller excludes
    and discloses the sample; broken code is never emitted).
    """
    tree = _parse_strict(source, language)
    if tree is None:
        raise ValueError(
            f"strip_comments: source does not parse cleanly as {language!r}")
    spans = _removal_spans(tree.root_node, language)
    n_comments = sum(1 for k in (k for _s, _e, k in spans) if k == "comment")
    n_docstrings = len(spans) - n_comments
    data = source.encode("utf-8")
    line_spans = _line_aware_spans(data, spans)
    out_parts, prev = [], 0
    for s, e in line_spans:
        out_parts.append(data[prev:s])
        prev = e
    out_parts.append(data[prev:])
    stripped_bytes = b"".join(out_parts)
    try:
        stripped = stripped_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:  # pragma: no cover - spans preserve
        raise ValueError(               # UTF-8 boundaries by construction
            f"strip_comments: stripped output is not valid UTF-8 ({exc})") \
        from exc
    meta = {
        "language": language,
        "n_nodes_removed": len(spans),
        "n_comments_removed": n_comments,
        "n_docstrings_removed": n_docstrings,
        "bytes_removed": len(data) - len(stripped_bytes),
    }
    return stripped, meta


def strip_with_gate(source: str, language: str) -> tuple[str, dict]:
    """strip_comments + the pre-registered gate. NEVER raises: on a
    pre-strip parse failure the source is returned unchanged with
    gate_pass=False / parse_ok=False (the runner excludes such samples and
    discloses them)."""
    try:
        stripped, meta = strip_comments(source, language)
        parse_ok = True
    except ValueError as exc:
        return source, {
            "language": language, "n_nodes_removed": 0,
            "n_comments_removed": 0, "n_docstrings_removed": 0,
            "bytes_removed": 0, "parse_ok": False, "gate_pass": False,
            "gate_error": str(exc),
        }
    gate_pass = defense_gate(source, stripped, language)
    meta.update({"parse_ok": True, "gate_pass": bool(gate_pass)})
    return stripped, meta
