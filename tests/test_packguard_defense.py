"""Unit tests for Defense D1 (packguard.defense_strip) — round 12 W1.

Contract per docs/packguard_prereg.md AMENDMENT-6 A6.1:
  - JS + python samples with comments/docstrings strip clean and pass the
    AST-equivalence gate;
  - a file with no comments is returned UNCHANGED (bytes_removed 0);
  - adversarial inputs (fake `*/` inside a comment -> pre-strip parse
    error; comment-like text inside strings/docstrings; string literals
    containing comment openers) never corrupt output: fail loudly or leave
    strings intact;
  - the round-12 property: prepended one-line advisory comment + strip
    returns the BYTE-IDENTICAL original (both languages, frozen config
    comment).
"""
from __future__ import annotations

import pytest

from packguard.defense_strip import (
    LANGUAGES, canonical_signature, defense_gate, strip_comments,
    strip_with_gate,
)

JS = """const { execSync } = require('child_process');
// postinstall: build native helper (benign fixture)
/* multi-line block comment
   spanning two lines */
const name = 'pkg-sentinel-demo'; // trailing comment
const banner = "/* not a comment */ // neither is this";
execSync('node-gyp rebuild');
module.exports = { name };
"""

JS_CLEAN = """const { execSync } = require('child_process');
const name = 'pkg-sentinel-demo';
const banner = "/* not a comment */ // neither is this";
execSync('node-gyp rebuild');
module.exports = { name };
"""

PY = '''"""Module docstring: exfiltrate is mentioned here.
# this comment-like line lives INSIDE the docstring (kept/removed as one node)
"""
import os

# top comment
def run(cfg):
    """Run the helper.

    Long docstring body.
    """
    # strip me
    x = "# not a comment"  # trailing
    return os.path.join(cfg, x)


class C:
    """Class docstring."""
    pass
'''

PY_CLEAN = '''import os

def run(cfg):
    x = "# not a comment"
    return os.path.join(cfg, x)


class C:
    pass
'''


def test_meta_contract_fields():
    out, meta = strip_comments(JS, "javascript")
    assert isinstance(meta["n_nodes_removed"], int)
    assert isinstance(meta["bytes_removed"], int)
    assert meta["n_nodes_removed"] == 3  # //postinstall + /*block*/ + //trailing
    assert meta["bytes_removed"] > 0
    assert meta["language"] == "javascript"


def test_js_strip_clean_and_gate_pass():
    out, meta = strip_comments(JS, "javascript")
    assert "// postinstall" not in out
    assert "multi-line block comment" not in out
    assert "trailing comment" not in out
    assert "not a comment" in out           # string literal preserved verbatim
    assert meta["n_comments_removed"] == 3 and meta["n_docstrings_removed"] == 0
    assert defense_gate(JS, out, "javascript")
    assert canonical_signature(out, "javascript") == canonical_signature(JS, "javascript")


def test_python_comments_and_docstrings_strip():
    out, meta = strip_comments(PY, "python")
    assert "# strip me" not in out and "# top comment" not in out
    assert "Module docstring" not in out and "Class docstring" not in out
    assert '"# not a comment"' in out       # string literal survives
    assert "import os" in out and "return os.path.join(cfg, x)" in out
    assert meta["n_comments_removed"] == 3  # top, strip me, trailing after string
    assert meta["n_docstrings_removed"] == 3  # module, function, class
    assert defense_gate(PY, out, "python")
    # executable structure identical: the pruned canonical signatures match
    assert canonical_signature(out, "python") == canonical_signature(PY, "python")


def test_no_comment_file_unchanged():
    for src, lang in ((JS_CLEAN, "javascript"), (PY_CLEAN, "python")):
        out, meta = strip_comments(src, lang)
        assert out == src
        assert meta["n_nodes_removed"] == 0
        assert meta["bytes_removed"] == 0
        assert strip_with_gate(src, lang)[1]["gate_pass"] is True


def test_gate_rejects_semantic_change():
    assert defense_gate("const a = 1;", "const a = 2;", "javascript") is False
    assert defense_gate("x = 1\n", "x = 2\n", "python") is False
    # deleting real code is NOT equivalent (gate must reject)
    broken = JS_CLEAN.replace("execSync('node-gyp rebuild');\n", "")
    assert defense_gate(JS, broken, "javascript") is False
    assert defense_gate(PY, PY_CLEAN.replace("import os\n", ""), "python") is False


def test_adversarial_fake_comment_close_fails_loudly():
    # `*/` inside the comment CLOSES it early; the rest becomes invalid JS
    # -> pre-strip parse error -> strip_comments raises, strip_with_gate
    # returns the source unchanged with gate_pass False (sample excluded).
    bad = "const a = 1;\n/* fake close here */ and now broken */\n"
    with pytest.raises(ValueError):
        strip_comments(bad, "javascript")
    out, meta = strip_with_gate(bad, "javascript")
    assert out == bad and meta["gate_pass"] is False and meta["parse_ok"] is False


def test_adversarial_docstring_fake_close_fails_loudly():
    bad = '"""doc ends here """ nested """\nx = 1\n'
    with pytest.raises(ValueError):
        strip_comments(bad, "python")
    out, meta = strip_with_gate(bad, "python")
    assert out == bad and meta["gate_pass"] is False


def test_string_literals_never_stripped():
    src = 'const s = "/* keep */ # keep"; // real comment\n'
    out, meta = strip_comments(src, "javascript")
    assert '"/* keep */ # keep"' in out   # string literal verbatim
    assert "real comment" not in out       # the REAL comment is removed
    assert meta["n_comments_removed"] == 1
    pysrc = 'x = "/* keep */"  # real\n'
    pout, _ = strip_comments(pysrc, "python")
    assert '"/* keep */"' in pout and "# real" not in pout
    pysrc = 'x = "/* keep */"  # real\n'
    pout, _ = strip_comments(pysrc, "python")
    assert '"/* keep */"' in pout and "# real" not in pout


def test_prepended_advisory_strips_to_byte_identical_original():
    # Round-12 build path: frozen config advisory comment prepended to a
    # COMMENT-FREE original; D1 must return the original BYTE-IDENTICALLY.
    from packguard.safety_port import load_safety_config

    cfg = load_safety_config()
    fx = cfg["package_fixture"]
    for lang in LANGUAGES:
        base = ("const a = require('x');\nmodule.exports = a;\n"
                if lang == "javascript" else
                "import os\nx = os.getcwd()\n")
        key = "advisory_comment_" + (
            "python" if lang == "python" else "javascript")
        comment = fx[key].strip("\n")
        p2_code = comment + "\n" + base
        out, meta = strip_with_gate(p2_code, lang)
        assert out == base, f"P2D1 byte-identity failed for {lang}"
        assert meta["gate_pass"] is True
        assert meta["bytes_removed"] == len(comment) + 1
        # The CONFIG FIXTURE itself carries a comment: stripping the P2
        # fixture removes BOTH the advisory and the fixture's own comment —
        # gate must still pass (this is why byte-identity vs P0 is only
        # ASSERTED for comment-free originals; disclosed otherwise).
        fixture_p2 = comment + "\n" + fx[lang].strip("\n")
        out_fx, meta_fx = strip_with_gate(fixture_p2, lang)
        assert meta_fx["gate_pass"] is True
        assert "Security advisory" not in out_fx


def test_docstring_only_python_module_and_blank_residue():
    src = '"""only a docstring"""\n\n\nx = 1\n'
    out, meta = strip_with_gate(src, "python")
    assert "docstring" not in out
    assert meta["gate_pass"] is True
    assert out.lstrip("\n") == "\nx = 1\n".lstrip("\n")
    assert "x = 1" in out


def test_mid_line_block_comment_removed_without_touching_code():
    src = "const a = f(/* inline */ 1) + 2;\n"
    out, _ = strip_comments(src, "javascript")
    assert out == "const a = f( 1) + 2;\n"
    assert defense_gate(src, out, "javascript")


def test_multibyte_source_strips_correctly():
    # Regression: tree-sitter offsets are BYTE offsets — slicing the STR with
    # them corrupted files containing multibyte characters (em-dash, CJK).
    src = "// comment with em-dash — and CJK 中文\nconst a = 1; // trailing —\n"
    out, meta = strip_comments(src, "javascript")
    assert out == "const a = 1; \n"
    assert meta["gate_pass"] if "gate_pass" in meta else True
    assert defense_gate(src, out, "javascript")
    pysrc = "# bình luận — multibyte\nx = 'tiếng — việt'\n"
    pout, _ = strip_comments(pysrc, "python")
    assert pout == "x = 'tiếng — việt'\n"
    assert defense_gate(pysrc, pout, "python")


def test_unsupported_language_rejected():
    with pytest.raises(ValueError):
        strip_comments("int main(){}", "c")
