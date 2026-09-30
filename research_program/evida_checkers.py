"""EVIDA code-evidence checker bank (prereg §2.4: exactly 4 registered
checkers — CWE-190, CWE-200, CWE-416, CWE-476 — tree-sitter AST validation on
the function slice).  The bank NEVER sees y_true (charter §11 no-oracle).

Claim-relative outcomes (registered decision semantics):

  claim.vulnerable == 1  SUPPORT iff the family's *unvalidated* pattern is
                         present;  REFUTE iff the pattern is absent OR every
                         instance is guarded (the *unchecked* pattern is
                         absent — the guard IS part of the family definition
                         for CWE-190 "arithmetic-on-unvalidated-size" and
                         CWE-476 "null-deref path");  UNDECIDABLE when
                         instances are mixed guarded/unguarded.
  claim.vulnerable == 0  mirror image (SUPPORT iff unvalidated pattern absent,
                         REFUTE iff an unguarded instance exists).

CWE-200 / CWE-416 have no guard concept: pattern present vs absent only.

Language scope (disclosed): full checkers on c/cpp (the S1 registry — the 4
families ARE the bench_attack_v2 registry).  On javascript (S2 PackGuard
packages) only CWE-190/CWE-200 are defined; a 416/476 claim on JS returns
UNDECIDABLE (never a vacuous REFUTE from an undefined checker).  Python:
same two-checker subset, ABSENT semantics for 190/200 implemented on the
tree-sitter python grammar.

Prereg §2.1 requires synthetic inject-and-perturb validation BEFORE reading
real adjudications: `synthetic_validation` builds labelled cases by inserting
the pattern into clean code (SUPPORT-known for claim=1) and deleting the
pattern from vulnerable code (REFUTE-known); precision/recall are reported in
run meta.  No gate — disclosure only.
"""
from __future__ import annotations

import re
import warnings
from functools import lru_cache

__all__ = [
    "SUPPORT", "REFUTE", "UNDECIDABLE", "PATTERN_UNGUARDED", "PATTERN_GUARDED",
    "PATTERN_ABSENT", "FAMILY_REGISTRY", "run_checker", "adjudicate_claim",
    "normalize_cwe", "synthetic_validation",
]

SUPPORT = "SUPPORT"
REFUTE = "REFUTE"
UNDECIDABLE = "UNDECIDABLE"

PATTERN_UNGUARDED = "pattern_unguarded"
PATTERN_GUARDED = "pattern_guarded"
PATTERN_ABSENT = "pattern_absent"

FAMILY_REGISTRY = ("CWE-190", "CWE-200", "CWE-416", "CWE-476")

_CWE_RE = re.compile(r"CWE-(\d{2,5})")
_CWE_NAME = {190: "CWE-190", 200: "CWE-200", 416: "CWE-416", 476: "CWE-476"}


def normalize_cwe(cwe) -> str | None:
    """'CWE-476' / 'cwe 476' / '476' -> registry name; None otherwise."""
    if cwe is None:
        return None
    m = _CWE_RE.search(str(cwe))
    if not m:
        m2 = re.fullmatch(r"\s*(\d{2,5})\s*", str(cwe))
        if not m2:
            return None
        num = int(m2.group(1))
    else:
        num = int(m.group(1))
    return _CWE_NAME.get(num)


# ---------------------------------------------------------------------------
# tree-sitter helpers (grammar = tree_sitter_languages bundle, same as D1)
# ---------------------------------------------------------------------------
@lru_cache(maxsize=8)
def _parser(language: str):
    from tree_sitter_languages import get_parser

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return get_parser(language)


def parse_ok(source: str, language: str) -> bool:
    """Lenient parse (fragments allowed); False only on empty/crash."""
    if not source or not source.strip():
        return False
    try:
        _parser(language).parse(source.encode("utf-8"))
        return True
    except Exception:
        return False


def _walk(root):
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


def _text(node) -> str:
    return node.text.decode("utf-8", "replace") if node.text is not None else ""


def _call_name(node):
    """Callee identifier of a call_expression node, else None."""
    if node.type != "call_expression":
        return None
    fn = node.child_by_field_name("function")
    if fn is None:
        return None
    return _text(fn).strip()


def _calls(root):
    for n in _walk(root):
        if n.type == "call_expression":
            name = _call_name(n)
            if name:
                yield name, n


def _idents(root):
    for n in _walk(root):
        if n.type == "identifier":
            yield n


def _args(node):
    args = node.child_by_field_name("arguments")
    return args if args is not None else node


def _inside(inner, outer) -> bool:
    return outer.start_byte <= inner.start_byte and inner.end_byte <= outer.end_byte


# ---------------------------------------------------------------------------
# CWE-190: arithmetic-on-unvalidated-size
# ---------------------------------------------------------------------------
_ALLOC_SINKS_C = {
    "malloc", "calloc", "realloc", "alloca", "kmalloc", "vmalloc",
    "kzalloc", "PyMem_Malloc", "PyMem_Realloc", "g_malloc", "g_new",
}
_MEM_SINKS_C = {"memcpy", "memmove", "memset", "strncpy", "bcopy", "strncat"}
_GUARD_FNS = {"min", "MIN", "clamp", "MIN_T", "max_size", "std::min"}

_SINKS_190 = {
    "c": _ALLOC_SINKS_C | _MEM_SINKS_C,
    "cpp": _ALLOC_SINKS_C | _MEM_SINKS_C,
    "javascript": {"Buffer.alloc", "Buffer.allocUnsafe", "alloc", "Array"},
    "python": {"range", "bytearray", "array"},
}


def _scaling_idents(node):
    """Identifiers inside a `*` scaling expression (non-literal operands)."""
    return [t for t in _text(node).split() if re.fullmatch(r"[A-Za-z_]\w*", t)]


def _has_guard_c(source: str, root, size_ids, sink_node) -> bool:
    """A comparison on a scaling identifier before the sink, a min()/clamp()
    wrapper around the scaling, or a truthiness/relational guard on it."""
    for name, call in _calls(root):
        base = name.split("::")[-1].split(".")[-1]
        if base in _GUARD_FNS and _inside(sink_node, call):
            return True
    span = source[: sink_node.start_byte]
    for sid in size_ids:
        if re.search(rf"\b{re.escape(sid)}\s*(<|<=|>|>=|==|!=)", span) or \
                re.search(rf"(<|<=|>|>=|==|!=)\s*{re.escape(sid)}\b", span) or \
                re.search(rf"!\s*{re.escape(sid)}\b", span):
            return True
    return False


def _op_of(node) -> str:
    """Operator token text of a binary_expression (works whether or not the
    grammar exposes an `operator` field)."""
    op = node.child_by_field_name("operator")
    if op is not None:
        return _text(op)
    for c in node.children:
        if c.type not in ("identifier", "number_literal", "string_literal",
                          "call_expression", "binary_expression",
                          "parenthesized_expression", "update_expression",
                          "cast_expression", "pointer_expression",
                          "subscript_expression", "field_expression") \
                and not c.is_named:
            return _text(c)
    return ""


def _scaling_assignments(root) -> dict:
    """var -> scaling identifiers for `T var = a * b;` / `var = a * b;` — the
    one-hop data-flow that lets a size variable carry a scaling into a sink."""
    out: dict[str, list] = {}
    for n in _walk(root):
        if n.type == "assignment_expression" or n.type == "init_declarator":
            left = n.child_by_field_name("left")
            if left is None and n.type == "init_declarator":
                left = n.child_by_field_name("declarator")
            right = n.child_by_field_name("right") if \
                n.type == "assignment_expression" else n.child_by_field_name("value")
            if left is None or right is None:
                continue
            for sc in _walk(right):
                if sc.type == "binary_expression" and _op_of(sc) == "*":
                    ids = _scaling_idents(sc)
                    if ids:
                        name = _text(left).strip()
                        out.setdefault(name, []).extend(ids)
    return out


def _pattern_190(source: str, language: str, root, sites=None) -> str:
    sinks = _SINKS_190.get(language)
    if not sinks:
        return PATTERN_ABSENT
    flow = _scaling_assignments(root)
    found_guarded = found_unguarded = False

    def _check(call, scalings):
        nonlocal found_guarded, found_unguarded
        for sc in scalings:
            ids = _scaling_idents(sc.child_by_field_name("left") or sc) + \
                _scaling_idents(sc.child_by_field_name("right") or sc)
            if not ids:
                continue
            if language in ("c", "cpp"):
                if _has_guard_c(source, root, ids, call):
                    found_guarded = True
                else:
                    found_unguarded = True
            else:
                found_unguarded = True  # non-C: no guard model (disclosed)

    for name, call in _calls(root):
        base = name.split("::")[-1].split(".")[-1]
        if base not in sinks and not name.startswith("Buffer.alloc"):
            continue
        args = _args(call)
        arg_txt = _text(args)
        scalings = [n for n in _walk(args)
                    if n.type == "binary_expression" and _op_of(n) == "*"]
        if scalings and sites is not None:
            sites.append({"kind": "sink_call_with_scaling",
                          "ref": f"{base} at byte {call.start_byte}"})
        _check(call, scalings)
        # one-hop flow: a sink argument carrying a scaling-assigned variable
        for var, ids in flow.items():
            if var and re.search(rf"\b{re.escape(var)}\b", arg_txt):
                if sites is not None:
                    sites.append({"kind": "sink_call_with_scaled_size_var",
                                  "ref": f"{base}({var}...) at byte "
                                         f"{call.start_byte}"})
                if language in ("c", "cpp"):
                    if _has_guard_c(source, root, list(set(ids)) + [var], call):
                        found_guarded = True
                    else:
                        found_unguarded = True
                else:
                    found_unguarded = True
    if found_unguarded:
        return PATTERN_UNGUARDED
    if found_guarded:
        return PATTERN_GUARDED
    return PATTERN_ABSENT


# ---------------------------------------------------------------------------
# CWE-200: info-flow-to-sink (direct single-hop name match — disclosed)
# ---------------------------------------------------------------------------
_LOG_SINKS_C = {"printf", "fprintf", "dprintf", "vprintf", "puts", "fputs",
                "syslog", "write", "send", "sendto", "sendmsg"}
_SINKS_200 = {
    "c": _LOG_SINKS_C,
    "cpp": _LOG_SINKS_C | {"std::cout", "cout"},
    "javascript": {"console.log", "console.error", "console.info",
                   "fetch", "axios", "post", "get",
                   "XMLHttpRequest", "write", "send"},
    "python": {"print", "sys.stdout.write", "logging.info", "logging.debug",
               "logger.info", "logger.debug", "requests.post", "requests.get"},
}
_SOURCE_FNS = {"getenv", "recv", "read", "fgets", "getline", "scanf",
               "fread", "req", "request", "input"}


def _param_names(root) -> set:
    """Parameter names of the FIRST function definition in the slice."""
    fn = next((n for n in _walk(root)
               if n.type in ("function_definition", "function_declaration",
                             "function_item", "method_definition",
                             "function", "arrow_function")), None)
    if fn is None:
        return set()
    params = fn.child_by_field_name("parameters") or \
        fn.child_by_field_name("declarator")
    if params is None:
        return set()
    txt = _text(params)
    return set(re.findall(r"[A-Za-z_]\w*", txt)) - {
        "void", "int", "char", "size_t", "const", "struct", "unsigned",
        "long", "self", "mrb_state", "jmp_buf", "var", "let", "function",
        "async", "export", "default", "require", "module", "exports",
        "True", "False", "None", "null", "undefined", "true", "false"}


def _flow_sources(source: str, language: str, root) -> set:
    src = _param_names(root)
    for name, call in _calls(root):
        base = name.split("::")[-1].split(".")[-1]
        if base in _SOURCE_FNS:
            src |= set(re.findall(r"[A-Za-z_]\w*", _text(_args(call))))
    # explicit sensitive-name vocabulary (bounded, disclosed)
    for m in re.finditer(r"\b(password|passwd|secret|token|api[_-]?key|"
                         r"private[_-]?key|credential|argv|environ)\w*\b",
                         source, re.IGNORECASE):
        src.add(m.group(0))
    return src


def _pattern_200(source: str, language: str, root, sites=None) -> str:
    sinks = _SINKS_200.get(language)
    if not sinks:
        return PATTERN_ABSENT
    src = _flow_sources(source, language, root)
    for name, call in _calls(root):
        if name not in sinks and name.split(".")[-1] not in {s.split(".")[-1] for s in sinks}:
            continue
        arg_txt = _text(_args(call))
        for sid in src:
            if re.search(rf"\b{re.escape(sid)}\b", arg_txt):
                if sites is not None:
                    sites.append({"kind": "flow_to_sink",
                                  "ref": f"{name}({sid}...) at byte "
                                         f"{call.start_byte}"})
                return PATTERN_UNGUARDED  # present (no guard concept)
    return PATTERN_ABSENT


# ---------------------------------------------------------------------------
# CWE-416: free-then-use order (source order as the CFG approximation)
# ---------------------------------------------------------------------------
def _pattern_416(source: str, language: str, root, sites=None) -> str:
    if language not in ("c", "cpp"):
        return PATTERN_ABSENT  # JS/Python: no free() semantics -> not defined
    frees = []  # (ident, byte_pos)
    for name, call in _calls(root):
        base = name.split("::")[-1]
        if base != "free":
            continue
        args = _args(call)
        first = next((n for n in _walk(args) if n.type == "identifier"), None)
        if first is not None:
            frees.append((_text(first), first.start_byte))
    for n in _walk(root):
        if n.type in ("delete_expression",):  # C++ delete / delete[]
            inner = next((c for c in n.children if c.type == "identifier"), None)
            if inner is not None:
                frees.append((_text(inner), inner.start_byte))
    if not frees:
        return PATTERN_ABSENT
    for ident, pos in frees:
        if sites is not None:
            sites.append({"kind": "free_site",
                          "ref": f"free({ident}) at byte {pos}"})
        for n in _idents(root):
            if _text(n) != ident or n.start_byte <= pos:
                continue
            if sites is not None:
                sites.append({"kind": "use_after_free",
                              "ref": f"{ident} used at byte {n.start_byte}"})
            # a nulling assignment (`p = NULL/0/nullptr`) is NOT a use
            parent = n.parent
            if parent is not None and parent.type == "assignment_expression" \
                    and parent.child_by_field_name("left") is not None and \
                    parent.child_by_field_name("left").id == n.id:
                rhs = parent.child_by_field_name("right")
                if rhs is not None and _text(rhs).strip() in \
                        ("0", "NULL", "nullptr", "nil", "(void*)0", "(0)"):
                    continue
            # any other later occurrence of the freed name counts as a use
            # (including a second free(x) = double-free — disclosed)
            return PATTERN_UNGUARDED  # use-after-free (order)
    return PATTERN_ABSENT  # free(s) exist but nothing used afterwards


# ---------------------------------------------------------------------------
# CWE-476: null-deref path
# ---------------------------------------------------------------------------
def _deref_sites(root):
    """(ident, node) for `x->f`, `*x`, `x[i]` deref sites."""
    out = []
    for n in _walk(root):
        if n.type == "field_expression":
            op = n.child_by_field_name("operator")
            base = n.child_by_field_name("argument")
            if op is not None and _text(op) == "->" and \
                    base is not None and base.type == "identifier":
                out.append((_text(base), n))
        elif n.type == "pointer_expression":
            inner = n.child_by_field_name("argument")
            if inner is not None and inner.type == "identifier" and \
                    "*" in [(_text(c) if c.type not in ("identifier",) else "")
                            for c in n.children]:
                out.append((_text(inner), n))
        elif n.type == "subscript_expression":
            obj = n.child_by_field_name("argument")
            if obj is not None and obj.type == "identifier":
                out.append((_text(obj), n))
    return out


def _null_guarded(source: str, ident: str, deref_node) -> bool:
    span = source[: deref_node.start_byte]
    if re.search(rf"!\s*{re.escape(ident)}\b", span) or \
            re.search(rf"\b{re.escape(ident)}\s*(==|!=)\s*(NULL|nullptr|0|nil)\b", span) or \
            re.search(rf"(==|!=)\s*(NULL|nullptr|0)\s*[)&|]*\s*{re.escape(ident)}\b", span) or \
            re.search(rf"\bassert\s*\(\s*{re.escape(ident)}\b", span):
        return True
    # deref inside an `if (ident)` truthiness body: the deref byte-range sits
    # inside an if_statement whose condition is exactly the identifier
    node = deref_node.parent
    while node is not None:
        if node.type == "if_statement":
            cond = node.child_by_field_name("condition")
            if cond is not None and _text(cond).strip() in (ident, f"({ident})"):
                return True
        node = node.parent
    return False


def _pattern_476(source: str, language: str, root, sites=None) -> str:
    if language not in ("c", "cpp"):
        return PATTERN_ABSENT  # not defined outside C/C++ (disclosed)
    derefs = _deref_sites(root)
    if not derefs:
        return PATTERN_ABSENT
    unguarded = guarded = False
    for ident, node in derefs:
        if _null_guarded(source, ident, node):
            guarded = True
        else:
            unguarded = True
            if sites is not None:
                sites.append({"kind": "unguarded_deref",
                              "ref": f"{ident} at byte {node.start_byte}"})
    if unguarded:
        return PATTERN_UNGUARDED
    return PATTERN_GUARDED


# ---------------------------------------------------------------------------
# claim-relative adjudication
# ---------------------------------------------------------------------------
_PATTERN_FN = {
    "CWE-190": _pattern_190,
    "CWE-200": _pattern_200,
    "CWE-416": _pattern_416,
    "CWE-476": _pattern_476,
}
_GUARDED_REFUTES_VULN = {"CWE-190", "CWE-476"}  # guard is part of the definition


def run_checker(family: str, claim_vulnerable: int, source: str,
                language: str) -> dict:
    """One checker -> {checker, outcome, pattern_state, evidence, note}."""
    fam = normalize_cwe(family)
    if fam not in FAMILY_REGISTRY:
        return {"checker": family, "outcome": UNDECIDABLE,
                "pattern_state": None, "evidence": None,
                "note": f"family {family!r} outside the 4-checker registry"}
    fn = _PATTERN_FN[fam]
    if language not in ("c", "cpp") and fam in ("CWE-416", "CWE-476"):
        return {"checker": fam, "outcome": UNDECIDABLE, "pattern_state": None,
                "evidence": None,
                "note": f"{fam} checker not defined for {language} (no "
                        f"vacuous REFUTE from an undefined checker)"}
    try:
        tree = _parser(language).parse(source.encode("utf-8"))
    except Exception as exc:  # noqa: BLE001 — checker must never crash the run
        return {"checker": fam, "outcome": UNDECIDABLE, "pattern_state": None,
                "evidence": None, "note": f"parse error: {type(exc).__name__}"}
    root = tree.root_node
    evidence: list = []
    state = fn(source, language, root, evidence)
    if claim_vulnerable == 1:
        if state == PATTERN_UNGUARDED:
            outcome = SUPPORT
        elif state in (PATTERN_ABSENT, PATTERN_GUARDED) and (
                state == PATTERN_ABSENT or fam in _GUARDED_REFUTES_VULN):
            outcome = REFUTE
        else:  # GUARDED on a family without a guard concept -> cannot refute
            outcome = UNDECIDABLE
    else:
        if state == PATTERN_UNGUARDED:
            outcome = REFUTE
        else:  # ABSENT or GUARDED both support the benign claim
            outcome = SUPPORT
    return {"checker": fam, "outcome": outcome, "pattern_state": state,
            "evidence": evidence[:3], "note": ""}


def adjudicate_claim(claim_vulnerable, claim_cwe, family_hint, source: str,
                     language: str) -> dict:
    """Checker-bank adjudication of ONE parsed verdict claim.

    Checker selection (registered rule, disclosed in run meta): the claim's
    own CWE when it is in the 4-family bank, else the sample's registered
    family hint (S1 only), else no checker (UNDECIDABLE -> caller falls back).
    """
    fam = normalize_cwe(claim_cwe) or (
        family_hint if family_hint in FAMILY_REGISTRY else None)
    if claim_vulnerable not in (0, 1):
        return {"checker": None, "outcome": UNDECIDABLE, "pattern_state": None,
                "note": "raw verdict not parsed to 0/1"}
    if fam is None:
        return {"checker": None, "outcome": UNDECIDABLE, "pattern_state": None,
                "note": "no banked CWE in claim and no family hint (S2 "
                        "packages carry no registered family)"}
    return run_checker(fam, int(claim_vulnerable), source, language)


# ---------------------------------------------------------------------------
# prereg §2.1: synthetic inject-and-perturb validation (disclosure only)
# ---------------------------------------------------------------------------
_CLEAN_190 = """static size_t f(const char *in) {
  size_t n = strlen(in);
  if (n > 100) n = 100;
  char *buf = malloc(n + 1);
  memcpy(buf, in, n);
  buf[n] = 0;
  return n;
}
"""
_VULN_190 = """static size_t f(const char *in, size_t k) {
  size_t n = strlen(in) * k;
  char *buf = malloc(n + 1);
  memcpy(buf, in, n);
  buf[n] = 0;
  return n;
}
"""
_CLEAN_200 = """void report(int code) {
  log_line("exit code recorded");
}
"""
_VULN_200 = """void report(char *token) {
  printf("token = %s\\n", token);
}
"""
_CLEAN_416 = """void g(char *p) {
  free(p);
  p = NULL;
}
"""
_VULN_416 = """void g(char *p) {
  free(p);
  p[0] = 0;
}
"""
_CLEAN_476 = """int h(char *p) {
  if (!p) return -1;
  return p[0];
}
"""
_VULN_476 = """int h(char *p) {
  return p[0];
}
"""


def synthetic_validation() -> dict:
    """Inject-and-perturb bank validation.  Labels are correct BY
    CONSTRUCTION: vulnerable code -> claim=1 must SUPPORT; clean code ->
    claim=1 must REFUTE (claim=0 mirror).  Precision / recall are computed on
    the SUPPORT outcome (precision = correct SUPPORTs / all SUPPORTs emitted,
    recall = correct SUPPORTs / all SUPPORT-wanted cases) and reported in run
    meta.  Disclosure only — no gate."""
    cases = {
        "CWE-190": [("c", _VULN_190, 1, SUPPORT), ("c", _CLEAN_190, 1, REFUTE),
                    ("c", _VULN_190, 0, REFUTE), ("c", _CLEAN_190, 0, SUPPORT)],
        "CWE-200": [("c", _VULN_200, 1, SUPPORT), ("c", _CLEAN_200, 1, REFUTE),
                    ("c", _VULN_200, 0, REFUTE), ("c", _CLEAN_200, 0, SUPPORT)],
        "CWE-416": [("c", _VULN_416, 1, SUPPORT), ("c", _CLEAN_416, 1, REFUTE),
                    ("c", _VULN_416, 0, REFUTE), ("c", _CLEAN_416, 0, SUPPORT)],
        "CWE-476": [("c", _VULN_476, 1, SUPPORT), ("c", _CLEAN_476, 1, REFUTE),
                    ("c", _VULN_476, 0, REFUTE), ("c", _CLEAN_476, 0, SUPPORT)],
    }
    per, tp, n_support_wanted, n_support_emitted, total, n_correct = {}, 0, 0, 0, 0, 0
    for fam, rows in cases.items():
        ok = 0
        for lang, src, claim, want in rows:
            got = run_checker(fam, claim, src, lang)["outcome"]
            ok += int(got == want)
            n_correct += int(got == want)
            total += 1
            if want == SUPPORT:
                n_support_wanted += 1
                tp += int(got == SUPPORT)
            n_support_emitted += int(got == SUPPORT)
        per[fam] = {"n": len(rows), "n_correct": ok,
                    "accuracy": round(ok / len(rows), 4)}
    return {
        "rule": "prereg §2.1 inject-and-perturb; labels by construction",
        "n_cases": total, "n_correct": n_correct,
        "accuracy": round(n_correct / total, 4) if total else None,
        "synthetic_precision": round(tp / n_support_emitted, 4)
        if n_support_emitted else None,
        "synthetic_recall": round(tp / n_support_wanted, 4)
        if n_support_wanted else None,
        "per_checker": per,
    }
