"""Tree-sitter based behavior-graph extraction (javascript + python).

Graph model (schema_version 1.0.0, see packguard/schema.py):
- node  : unique (cls, api) pair; `cls` one of BEHAVIOR_CLASSES, `api` the matched
          pattern string (e.g. "os.system" or bare "eval").
- edge  : ("seq") consecutive classified calls/attribute-reads within the same scope
          (module body or function body, document order); ("data") a call whose
          result is bound to a variable that later flows into another classified
          call's arguments (same scope).
- imports: require('x') / import x / from x import y records mapped through
          import_module_class; `from X import name` and JS destructured
          `const {exec} = require('child_process')` also register local aliases so
          aliased calls still classify (a common malicious style).

Determinism: fixed pre-order traversal + first-occurrence node ids; no randomness.
Parse failures never raise: build_graph returns parse_ok=False; callers disclose.
"""

from __future__ import annotations

import warnings
from typing import Dict, List, Optional, Tuple

from packguard.schema import (
    BEHAVIOR_CLASSES,
    SCHEMA_VERSION,
    import_module_class,
    mapping_for,
)

warnings.filterwarnings("ignore", category=FutureWarning)

_PARSERS: Dict[str, object] = {}


def _parser(language: str):
    if language not in _PARSERS:
        import tree_sitter_languages

        _PARSERS[language] = tree_sitter_languages.get_parser(language)
    return _PARSERS[language]


def _text(node) -> str:
    return node.text.decode("utf-8", "replace")


_CALL_TYPES = {"python": "call", "javascript": "call_expression"}
_ARGS_FIELD = {"python": "arguments", "javascript": "arguments"}
_FUNC_TYPES = {
    "python": {"function_definition"},
    "javascript": {"function_declaration", "function", "method_definition", "arrow_function", "generator_function"},
}
_IMPORT_TYPES = {"python": {"import_statement", "import_from_statement"}}


def classify_callee(text: str, language: str, local: Dict[str, Tuple[str, str]]) -> Optional[Tuple[str, str]]:
    """Classify a callee/attribute text. Returns (cls, api) or None.

    `local` maps locally-bound names (import aliases, destructures) to (cls, api).
    """
    dotted, bare, _attr = mapping_for(language)
    if text in local:
        return local[text]
    if text in dotted:
        return dotted[text], text
    if text in bare:
        return bare[text], text
    last = text.rsplit(".", 1)[-1]
    if last in bare:
        return bare[last], last
    return None


def _scope_label(node, language: str) -> str:
    if language == "python":
        if node.type == "function_definition":
            nm = node.child_by_field_name("name")
            return "func:" + (_text(nm) if nm is not None else "<anon>")
        return "module"
    if node.type in ("function_declaration", "function", "generator_function"):
        nm = node.child_by_field_name("name")
        return "func:" + (_text(nm) if nm is not None else "<anon>")
    if node.type == "method_definition":
        nm = node.child_by_field_name("name")
        return "method:" + (_text(nm) if nm is not None else "<anon>")
    return "module"


def _arg_identifiers(args_node) -> List[str]:
    """Identifier names anywhere inside a call's argument subtree (document order,
    deduplicated). Deliberately deep: catches `get("http://x/" + out)` flows."""
    ids: List[str] = []
    seen: set = set()
    for n in _walk(args_node):
        if n is args_node:
            continue
        if n.type == "identifier":
            t = _text(n)
            if t not in seen:
                seen.add(t)
                ids.append(t)
    return ids


def _has_error(node) -> bool:
    if node.type in ("ERROR", "MISSING"):
        return True
    return any(_has_error(ch) for ch in node.children)


def _classify_require_chain(text: str, language: str):
    """Classify require('mod').method(...) callee chains, e.g.
    require('https').get(...) -> ("NETWORK", "https.get")."""
    import re as _re

    m = _re.match(r"^require\(\s*['\"]([^'\"]+)['\"]\s*\)\.([A-Za-z_$][\w$]*)$", text)
    if not m:
        return None
    mod, meth = m.group(1), m.group(2)
    dotted, bare, _attr = mapping_for(language)
    qual = f"{mod}.{meth}"
    if qual in dotted:
        return dotted[qual], qual
    return None


def _walk(root):
    """Deterministic pre-order walk over the tree."""
    stack = [root]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def build_graph(source: str, language: str, file: str = "<source>", entry_kind: str = "lib") -> dict:
    """Parse `source` and return the behavior-graph dict for one file."""
    if language not in ("python", "javascript"):
        raise ValueError(f"unsupported language: {language!r}")
    parser = _parser(language)
    tree = parser.parse(source.encode("utf-8", "replace"))

    nodes: List[dict] = []
    node_ids: Dict[Tuple[str, str], int] = {}
    edges: List[dict] = []
    imports: List[dict] = []
    scope_labels: List[str] = []
    # per-scope ordered events; event = {node:int} after resolution
    scope_events: List[List[dict]] = []
    call_scope: Dict[int, int] = {}  # id(call_node) -> scope index
    func_scope: Dict[int, int] = {}  # id(func_node) -> scope index

    def node_id(cls: str, api: str) -> int:
        key = (cls, api)
        if key not in node_ids:
            node_ids[key] = len(nodes)
            nodes.append({"id": node_ids[key], "cls": cls, "api": api})
        return node_ids[key]

    def ensure_scope(label: str) -> int:
        scope_labels.append(label)
        scope_events.append([])
        return len(scope_labels) - 1

    module_scope = ensure_scope("module")

    # ---------- python import aliases ----------
    local: Dict[str, Tuple[str, str]] = {}
    root_alias: Dict[str, str] = {}
    if language == "python":
        for imp in _walk(tree.root_node):
            if imp.type not in _IMPORT_TYPES[language]:
                continue
            if imp.type == "import_statement":
                for clause in imp.children_by_field_name("name"):
                    if clause is None:
                        continue
                    if clause.type == "dotted_name":
                        mod = _text(clause)
                        cls = import_module_class(language, mod) or import_module_class(language, mod.split(".")[0])
                        if cls:
                            local[mod.split(".")[0]] = (cls, mod)
                    elif clause.type == "aliased_import":
                        nm = clause.child_by_field_name("name")
                        al = clause.child_by_field_name("alias")
                        if nm is not None and al is not None:
                            mod, alias = _text(nm), _text(al)
                            root_alias[alias] = mod
                            cls = import_module_class(language, mod) or import_module_class(language, mod.split(".")[0])
                            if cls:
                                local[alias] = (cls, mod)
            else:  # import_from_statement
                mod_node = imp.child_by_field_name("module_name")
                if mod_node is None:
                    continue
                mod = _text(mod_node)
                for nm in imp.children_by_field_name("name"):
                    if nm is None or nm.type in ("wildcard_import",):
                        continue
                    if nm.type == "aliased_import":
                        base = nm.child_by_field_name("name")
                        alias = nm.child_by_field_name("alias")
                        if base is None or alias is None:
                            continue
                        orig, bound = _text(base), _text(alias)
                    else:
                        orig, bound = _text(nm), _text(nm)
                    qual = f"{mod}.{orig}"
                    cls = import_module_class(language, qual) or import_module_class(language, mod)
                    if cls:
                        local[bound] = (cls, qual)

    # ---------- JS require imports + destructuring aliases ----------
    if language == "javascript":
        for call in _walk(tree.root_node):
            if call.type != _CALL_TYPES[language]:
                continue
            fn = call.child_by_field_name("function")
            args = call.child_by_field_name("arguments")
            if fn is None or args is None or _text(fn) != "require":
                continue
            named = args.named_children
            if not named or named[0].type != "string":
                continue
            mod = named[0].text.decode("utf-8", "replace").strip("'\"")
            cls = import_module_class(language, mod)
            if cls is None:
                continue
            k = (mod, cls)
            if k not in {(i["module"], i["cls"]) for i in imports}:
                imports.append({"module": mod, "cls": cls})
            parent = call.parent
            if parent is not None and parent.type == "variable_declarator":
                pat = parent.child_by_field_name("name")
                if pat is None:
                    continue
                if pat.type == "identifier":
                    local.setdefault(_text(pat), (cls, mod))
                elif pat.type == "object_pattern":
                    for sh in pat.named_children:
                        if sh.type == "shorthand_property_identifier_pattern":
                            key = _text(sh)
                        elif sh.type == "pair_pattern":
                            nm2 = sh.child_by_field_name("key")
                            key = _text(nm2) if nm2 is not None else None
                        else:
                            key = None
                        if key:
                            qual = f"{mod}.{key}"
                            c2 = import_module_class(language, qual)
                            local[key] = (c2 or cls, qual if c2 else mod)

    # ---------- main traversal: collect ordered classified events per scope ----------
    _dotted, _bare, attr_table = mapping_for(language)

    def visit(node, scope: int) -> None:
        ntype = node.type
        if ntype in _FUNC_TYPES[language]:
            child = ensure_scope(_scope_label(node, language))
            func_scope[id(node)] = child
            for ch in node.children:
                visit(ch, child)
            return
        if ntype == _CALL_TYPES[language]:
            fn = node.child_by_field_name("function")
            if fn is not None:
                text = _text(fn)
                hit = classify_callee(text, language, local)
                if hit is None and "." in text:
                    root, rest = text.split(".", 1)
                    if root in root_alias:
                        hit = classify_callee(f"{root_alias[root]}.{rest}", language, local)
                if hit is None and "require(" in text:
                    hit = _classify_require_chain(text, language)
                if hit is not None:
                    args = node.child_by_field_name("arguments")
                    arg_ids = _arg_identifiers(args) if args is not None else []
                    ev = {"call_key": None, "cls": hit[0], "api": hit[1], "args": arg_ids}
                    scope_events[scope].append(ev)
                    # dataflow: consume vars produced earlier in this scope
                    for v in arg_ids:
                        pk = (scope, v)
                        if pk in var_prod and var_prod[pk][1] is not ev:
                            flow_pairs.append((var_prod[pk][1], ev))
                    # producer: climb chained calls to the owning assignment
                    p2 = node.parent
                    lhs = None
                    while p2 is not None:
                        if p2.type in ("assignment", "assignment_expression", "named_expression"):
                            lhs = p2.child_by_field_name("left") or p2.child_by_field_name("name")
                            break
                        if p2.type == "variable_declarator":
                            lhs = p2.child_by_field_name("name")
                            break
                        if p2.type in ("attribute", "member_expression", "subscript", "call", "call_expression"):
                            p2 = p2.parent
                        else:
                            break
                    if lhs is not None and lhs.type == "identifier":
                        var_prod[(scope, _text(lhs))] = (len(scope_events[scope]) - 1, ev)
            for ch in node.children:
                visit(ch, scope)
            return
        if ntype in ("attribute", "member_expression"):
            otext = _text(node)
            if otext in attr_table:
                scope_events[scope].append({"call_key": None, "node": node_id(attr_table[otext], otext), "args": []})
        for ch in node.children:
            visit(ch, scope)

    # dataflow state (scoped): (scope, var) -> (event_index, producer_event)
    var_prod: Dict[Tuple[int, str], Tuple[int, dict]] = {}
    flow_pairs: List[Tuple[dict, dict]] = []

    visit(tree.root_node, module_scope)

    # ---------- resolve node ids in document order + seq edges ----------
    for si, events in enumerate(scope_events):
        last: Optional[int] = None
        for ev in events:
            if "node" not in ev:
                ev["node"] = node_id(ev["cls"], ev["api"])
            nid = ev["node"]
            if last is not None and last != nid:
                edges.append({"src": last, "dst": nid, "kind": "seq"})
            last = nid

    # ---------- dataflow edges: producer event -> consumer event ----------
    for prod_ev, cons_ev in flow_pairs:
        if prod_ev["node"] != cons_ev["node"]:
            edges.append({"src": prod_ev["node"], "dst": cons_ev["node"], "kind": "data"})

    # dedupe edges deterministically (keep first occurrence = document order)
    seen = set()
    uniq_edges = []
    for e in edges:
        k = (e["src"], e["dst"], e["kind"])
        if k not in seen:
            seen.add(k)
            uniq_edges.append(e)

    return {
        "schema_version": SCHEMA_VERSION,
        "language": language,
        "file": file,
        "entry_kind": entry_kind,
        "nodes": nodes,
        "edges": uniq_edges,
        "scopes": [lbl for si, lbl in enumerate(scope_labels) if scope_events[si]],
        "imports": imports,
        "parse_ok": not _has_error(tree.root_node),
        "n_nodes": len(nodes),
        "n_edges": len(uniq_edges),
    }


def merge_graphs(graphs: List[dict], sample_id: str) -> dict:
    """Merge per-file graphs of one sample into a single graph (id-offset remap)."""
    nodes: List[dict] = []
    ids: Dict[Tuple[str, str], int] = {}
    edges: List[dict] = []
    imports: List[dict] = []
    files: List[dict] = []
    scopes: List[str] = []
    for g in graphs:
        remap: Dict[int, int] = {}
        for n in g["nodes"]:
            key = (n["cls"], n["api"])
            if key not in ids:
                ids[key] = len(nodes)
                nodes.append({"id": ids[key], "cls": n["cls"], "api": n["api"]})
            remap[n["id"]] = ids[key]
        for e in g["edges"]:
            edges.append({"src": remap[e["src"]], "dst": remap[e["dst"]], "kind": e["kind"]})
        for imp in g.get("imports", []):
            if (imp["module"], imp["cls"]) not in {(i["module"], i["cls"]) for i in imports}:
                imports.append(imp)
        for sc in g.get("scopes", []):
            if sc not in scopes:
                scopes.append(sc)
        files.append(
            {
                "file": g["file"],
                "language": g["language"],
                "entry_kind": g["entry_kind"],
                "parse_ok": g["parse_ok"],
                "n_nodes": g["n_nodes"],
                "n_edges": g["n_edges"],
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "sample_id": sample_id,
        "classes": list(BEHAVIOR_CLASSES),
        "nodes": nodes,
        "edges": edges,
        "imports": imports,
        "files": files,
        "scopes": scopes,
        "n_nodes": len(nodes),
        "n_edges": len(edges),
        "parse_ok_files": sum(1 for f in files if f["parse_ok"]),
        "parse_fail_files": sum(1 for f in files if not f["parse_ok"]),
    }
