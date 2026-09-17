"""Carrier injection for context conditions C2/C3 (agent A3).

A "carrier" is the surface slot where untrusted context text is inserted:
top_comment | inline_comment | docstring | string_literal_tail.
"position" controls distance relative to the (potential) vulnerability site:
near = start of the function body / directly above the signature;
far  = end of the function body / top of the file.

Comment/docstring carriers never touch executable tokens; the string carrier
only appends characters inside an existing string literal (flagged in meta as
`modifies_string_data=True` because runtime data does change even though the
executable AST does not).
"""
from __future__ import annotations

from typing import Optional, Tuple

from .parser_utils import (
    body_node,
    find_function,
    indent_of,
    iter_nodes,
    node_line_span,
    parse,
)

CARRIER_ORDER = ["top_comment", "inline_comment", "docstring", "string_literal_tail"]
C3_CARRIERS = ["top_comment", "inline_comment", "docstring"]


def _sanitize(text: str, style: str) -> str:
    """Make template text safe for a given comment style."""
    text = text.replace("\r", " ").replace("\x00", "")
    if style == "//":
        return " ".join(text.split())
    # block comment styles: neutralize terminator, keep newlines for realism
    return text.replace("*/", "* /")


def _comment_wrap(text: str, style: str) -> str:
    if style == "//":
        return f"// {text}"
    if style == "doc":
        return f"/** {text} */"
    return f"/* {text} */"


def _escape_into_string(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def inject_carrier(
    func: str,
    text: str,
    carrier: str,
    position: str,
    language: str = "c",
) -> Tuple[str, str, bool]:
    """Insert `text` into `func` using `carrier` at `position`.

    Returns (new_code, actual_carrier, modifies_string_data).
    Raises ValueError when the code does not parse or the carrier is unknown.
    """
    tree = parse(func, language)
    if tree is None or tree.root_node.has_error:
        raise ValueError("cannot parse function for carrier injection")
    fn = find_function(tree)
    if fn is None:
        raise ValueError("no function_definition found")
    body = body_node(fn)

    if carrier == "top_comment":
        block = _comment_wrap(_sanitize(text, "/*"), "/*")
        if position == "near":
            at = func.rfind("\n", 0, fn.start_byte) + 1
            indent = indent_of(func, fn.start_byte)
        else:
            at, indent = 0, ""
        return func[:at] + f"{indent}{block}\n" + func[at:], carrier, False

    if carrier == "docstring":
        block = _comment_wrap(_sanitize(text, "doc"), "doc")
        if position == "near":
            at = func.rfind("\n", 0, fn.start_byte) + 1
            indent = indent_of(func, fn.start_byte)
        else:
            at, indent = 0, ""
        return func[:at] + f"{indent}{block}\n" + func[at:], carrier, False

    if carrier == "inline_comment":
        block = _comment_wrap(_sanitize(text, "//"), "//")
        if position == "near":
            if body is None:
                raise ValueError("function has no body")
            open_brace = body.children[0] if body.children else None
            if open_brace is None or open_brace.type != "{":
                raise ValueError("cannot locate opening brace")
            at = open_brace.end_byte
            inner_indent = indent_of(func, body.start_byte) + "    "
            return func[:at] + f"\n{inner_indent}{block}" + func[at:], carrier, False
        # far: last line inside the body, above the closing brace
        if body is None:
            raise ValueError("function has no body")
        close = body.children[-1] if body.children else None
        if close is None or close.type != "}":
            raise ValueError("cannot locate closing brace")
        at, _ = node_line_span(close, func)
        indent = indent_of(func, close.start_byte)
        return func[:at] + f"{indent}{block}\n" + func[at:], carrier, False

    if carrier == "string_literal_tail":
        if body is None:
            raise ValueError("function has no body")
        literals = [n for n in iter_nodes(body) if n.type == "string_literal"]
        if not literals:
            # graceful fallback: comment carrier inside the body (near)
            return inject_carrier(func, text, "inline_comment", "near", language)
        target = literals[-1]
        closing_quote = target.children[-1] if target.children else None
        if closing_quote is None:
            raise ValueError("malformed string_literal node")
        at = closing_quote.start_byte
        return func[:at] + f" {_escape_into_string(text)}" + func[at:], carrier, True

    raise ValueError(f"unknown carrier: {carrier}")


def expand_comment_lines(func: str, language: str = "c") -> Tuple[str, int]:
    """Remove every comment, erasing whole lines that contain only comments and
    replacing intra-line comments with a single space (token-safe).

    Returns (stripped_code, n_comments_removed). Comments inside string
    literals are left untouched because spans come from AST comment nodes.
    """
    tree = parse(func, language)
    if tree is None:
        raise ValueError("cannot parse function for comment removal")
    spans = []
    for node in iter_nodes(tree.root_node):
        if node.type == "comment":
            line_start, line_end = node_line_span(node, func)
            prefix = func[line_start:node.start_byte]
            suffix = func[node.end_byte:line_end]
            if prefix.strip() == "" and suffix.strip() == "":
                spans.append((line_start, line_end))  # whole line -> erase
            else:
                spans.append((node.start_byte, node.end_byte))  # keep tokens apart
    out, last = [], 0
    for start, end in spans:
        out.append(func[last:start])
        out.append(" ")
        last = end
    out.append(func[last:])
    return "".join(out), len(spans)
