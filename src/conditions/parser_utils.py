"""Tree-sitter utilities shared by conditions and defenses (agent A3).

Uses `tree_sitter_languages` with languages 'c' and 'cpp' (per PROJECT_BRIEF).
Note: requires tree_sitter <0.22 for tree_sitter_languages 1.10.2 compatibility;
the venv is pinned to tree_sitter==0.21.3 (see reports/round1/A3_report.md).
"""
from __future__ import annotations

from functools import lru_cache
from typing import Iterator, Optional

COMMENT_TYPES = frozenset({"comment"})
STRING_TYPES = frozenset({"string_literal", "char_literal"})
PREPROC_PREFIX = "preproc"

# PrimeVul contains BOTH C and C++ functions (audit round 1: ~65% of the eval
# manifest is C++ and fails to parse under the bare 'c' grammar). GRAMMARS is
# the ordered fallback chain used by parse(auto=True) and resolve_language.
GRAMMARS = ("c", "cpp")
# Heuristic C++ content markers (used only when no grammar parses cleanly).
_CPP_HINTS = ("::", "namespace ", "template<", "template <", "class ",
              "public:", "private:", "protected:", "virtual ", "nullptr",
              "std::", "throw(", "catch (")


@lru_cache(maxsize=None)
def _get_parser(language: str):
    from tree_sitter_languages import get_parser as _get_parser_impl

    return _get_parser_impl(language)


def _parse_strict(code: str, language: str):
    """Parse with exactly one grammar; return Tree, or None on failure."""
    if not code or not code.strip():
        return None
    try:
        parser = _get_parser(language)
        return parser.parse(code.encode("utf-8"))
    except Exception:
        return None


def parse(code: str, language: str = "c", auto: bool = True):
    """Parse source text; return tree-sitter Tree or None on failure.

    auto=True (default): if the code fails to parse (error nodes) under
    `language`, retry the remaining grammars in GRAMMARS and return the first
    clean tree. This keeps every call site (conditions C2/C3, defenses
    B2/B3/P1, check_semantics) working on both C and C++ functions without
    each caller having to know the language.
    """
    tree = _parse_strict(code, language)
    if auto and (tree is None or tree.root_node.has_error):
        for alt in GRAMMARS:
            if alt == language:
                continue
            alt_tree = _parse_strict(code, alt)
            if alt_tree is not None and not alt_tree.root_node.has_error:
                return alt_tree
    return tree


def resolve_language(code: str, requested: str = "c") -> str:
    """Return the grammar under which `code` parses without errors AND yields
    a function_definition. Falls back to the C++ heuristic when no grammar
    parses cleanly, and to `requested` as the last resort (the caller then
    raises its own clear error). Deterministic."""
    if not code or not code.strip():
        return requested
    for lang in [requested] + [g for g in GRAMMARS if g != requested]:
        tree = _parse_strict(code, lang)
        if tree is not None and not tree.root_node.has_error \
                and find_function(tree) is not None:
            return lang
    if "cpp" in GRAMMARS and requested != "cpp" and any(h in code for h in _CPP_HINTS):
        return "cpp"
    return requested


def iter_nodes(root) -> Iterator:
    """Yield every node in the tree (pre-order)."""
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


def find_function(tree):
    """Return the first `function_definition` node, or None."""
    for node in iter_nodes(tree.root_node):
        if node.type == "function_definition":
            return node
    return None


def function_name(fn_node) -> Optional[str]:
    """Best-effort function name extraction (handles pointer declarators)."""
    declarator = fn_node.child_by_field_name("declarator")
    if declarator is None:
        return None
    for node in iter_nodes(declarator):
        if node.type == "identifier":
            return node.text.decode("utf-8", "replace")
    return None


def node_line_span(node, src: str) -> tuple[int, int]:
    """[line_start, line_end) byte offsets of the lines covered by node."""
    start = src.rfind("\n", 0, node.start_byte) + 1
    end = src.find("\n", node.end_byte)
    if end == -1:
        end = len(src)
    return start, end


def indent_of(src: str, byte_offset: int) -> str:
    """Leading whitespace of the line containing byte_offset."""
    start = src.rfind("\n", 0, byte_offset) + 1
    line = src[start:src.find("\n", start) if src.find("\n", start) != -1 else len(src)]
    return line[: len(line) - len(line.lstrip())]


def body_node(fn_node):
    """compound_statement of a function_definition (may be None)."""
    body = fn_node.child_by_field_name("body")
    return body


def _canonical(node, ignore_strings: bool) -> Optional[tuple]:
    """Structural signature of a subtree, omitting comments (and optionally
    string/char literal subtrees). Byte offsets are intentionally excluded so
    inserting comments does not change the signature. Leaf token text IS
    included (childless nodes), so renaming identifiers or editing string
    contents changes the signature — the gate checks tokens, not just shape."""
    skip_strings = ignore_strings and node.type in STRING_TYPES
    if node.type in COMMENT_TYPES or skip_strings:
        return None
    children = []
    for child in node.children:
        canon = _canonical(child, ignore_strings)
        if canon is not None:
            children.append(canon)
    if not children and node.named_child_count == 0:
        text = node.text.decode("utf-8", "replace") if node.text is not None else ""
        return (node.type, bool(node.is_named), text)
    return (node.type, bool(node.is_named), tuple(children))


def semantic_signature(code: str, language: str = "c", ignore_strings: bool = True):
    """Canonical AST signature; raises ValueError if the code does not parse.

    `language` is a *preference*: parse(auto=True) retries the other grammar
    in GRAMMARS for C++ sources, so a C++ function is signed under 'cpp'.
    """
    tree = parse(code, language)
    if tree is None:
        raise ValueError(f"could not parse code as '{language}'")
    if tree.root_node.has_error:
        raise ValueError(f"parse error in code (language={language})")
    canon = _canonical(tree.root_node, ignore_strings)
    if canon is None:  # pragma: no cover - root node is never skipped
        raise ValueError("empty AST signature")
    return canon


def check_semantics(
    func_original: str,
    func_transformed: str,
    language: str = "c",
    ignore_strings: bool = True,
) -> bool:
    """Quality gate: transformed code parses and its executable AST (comments
    removed; string/char literal subtrees removed when `ignore_strings`) is
    identical to the original. Both sides are compared under the same grammar
    (auto-selected per parse()): a C++ pair is compared as 'cpp', a C pair as
    'c' — so the gate never fails merely because of the grammar choice."""
    try:
        return semantic_signature(func_original, language, ignore_strings) == (
            semantic_signature(func_transformed, language, ignore_strings)
        )
    except ValueError:
        return False


def provenance_label(node) -> Optional[str]:
    """Classify a model-facing node: comment | docstring | string | config_like.

    `docstring` = Doxygen-style block comment (/** ... */) or /// line comments;
    everything else comment-like is `comment`. Preprocessor nodes are
    `config_like`; everything else returns None (treated as executable code).
    """
    if node.type in COMMENT_TYPES:
        text = node.text.decode("utf-8", "replace").lstrip()
        if text.startswith(("/**", "/*!", "///")):
            return "docstring"
        return "comment"
    if node.type in STRING_TYPES:
        return "string"
    if node.type.startswith(PREPROC_PREFIX):
        return "config_like"
    return None
