"""Round-16 W tests: Kaggle prompt export + kernel plumbing.

Covers (tasking K1/K5):
  - the exported ladder/safety prompt files are deterministic (2 runs
    byte-identical) and carry the registered row counts (180 / 300);
  - ladder prompt shas equal the STORED per-record prompt_sha256_16 of the
    round-7 qwen7b A0/A5 runs and the r10 granite A1 run (rebuild is
    byte-identical to the audited machinery);
  - the safety selection equals the recorded n=100 batch samples
    (id/label/ecosystem/language) and P0 prompt shas equal the round-12
    defense-batch p0_prompt_sha16 for every overlapping sample;
  - the kernel's embedded JSON-verdict parser is byte-equivalent to
    packguard.safety_port.parse_verdict on a battery of response texts;
  - the two rendered kernels parse, carry the right model/tasks, and leave
    no template placeholders; gen params equal the frozen configs.
"""
from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "kaggle_pkg"
if str(PKG) not in sys.path:
    sys.path.insert(0, str(PKG))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import export_prompts  # noqa: E402

LADDER = PKG / "data" / "ladder_prompts_7b8b.jsonl"
SAFETY = PKG / "data" / "safety_prompts_7b.jsonl"


def _rows(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()
            if l.strip()]


# ---------------------------------------------------------------------------
# export: determinism + schema
# ---------------------------------------------------------------------------
def test_export_deterministic_two_runs(tmp_path):
    rows1_l, _ = export_prompts.build_ladder_rows()
    rows1_s, _ = export_prompts.build_safety_rows()
    rows2_l, _ = export_prompts.build_ladder_rows()
    rows2_s, _ = export_prompts.build_safety_rows()
    assert json.dumps(rows1_l) == json.dumps(rows2_l)
    assert json.dumps(rows1_s) == json.dumps(rows2_s)
    # and the on-disk files match the in-memory rebuild (same machinery)
    assert json.dumps(rows1_l) == json.dumps(_rows(LADDER))
    assert json.dumps(rows1_s) == json.dumps(_rows(SAFETY))


def test_ladder_rows_schema_and_counts():
    rows = _rows(LADDER)
    assert len(rows) == 180, "registered ladder protocol: 60 vul x 3 rungs"
    for rung in ("A0", "A5", "A1"):
        rs = [r for r in rows if r["rung"] == rung]
        assert len(rs) == 60
        assert all(r["label"] == 1 for r in rs)
        assert len({r["sample_id"] for r in rs}) == 60
    assert len({r["sample_id"] for r in rows}) == 60
    for r in rows:
        assert r["arm"] == "C5_near"
        assert r["system"] and r["user"]
        recomputed = export_prompts.sha16({"system": r["system"],
                                           "user": r["user"]})
        assert r["prompt_sha256_16"] == recomputed


def test_ladder_shas_match_stored_round_records():
    rows = _rows(LADDER)
    shas = {(r["rung"], r["sample_id"]): r["prompt_sha256_16"] for r in rows}
    for name, rel, rung in (
        ("qwen7b A0", "outputs/experiments/round7_7b/results_qwen7b__vul__A0.json", "A0"),
        ("qwen7b A5", "outputs/experiments/round7_7b/results_qwen7b__vul__A5.json", "A5"),
        ("granite2b A1", "outputs/experiments/r10_granite_ladder/results_granite2b__vul__A1.json", "A1"),
    ):
        d = json.loads((ROOT / rel).read_text(encoding="utf-8"))
        stored = {r["sample_id"]: r["meta"]["prompt_sha256_16"]
                  for r in d["records"] if r.get("status") != "SKIPPED"}
        assert len(stored) == 60, name
        bad = [sid for sid, s in stored.items()
               if shas[(rung, sid)] != s]
        assert not bad, f"{name}: {len(bad)} prompt-sha mismatches: {bad[:3]}"


def test_ladder_subset_is_registered_seed_20260923():
    """The vul ids must equal the registered ladder subset (seed 20260923,
    sample-paired with rounds 6/7/10) — NOT the 20260922 safety draw."""
    rows = _rows(LADDER)
    ids = sorted({r["sample_id"] for r in rows})
    r7 = json.loads((ROOT / "outputs/experiments/round7_7b/"
                     "results_qwen7b__vul__A0.json").read_text(encoding="utf-8"))
    stored_ids = sorted({r["sample_id"] for r in r7["records"]
                         if r.get("status") != "SKIPPED"})
    assert ids == stored_ids


def test_safety_rows_schema_counts_and_n100_truth():
    rows = _rows(SAFETY)
    assert len(rows) == 300
    for arm in ("P0_neutral", "P1_offensive_wording", "P2_advisory_in_package"):
        rs = [r for r in rows if r["arm"] == arm]
        assert len(rs) == 100
        assert sum(r["label"] for r in rs) == 50  # 50 malicious + 50 benign
    truth, _ = export_prompts._n100_truth()
    p0 = {r["sample_id"]: r for r in rows if r["arm"] == "P0_neutral"}
    assert set(p0) == set(truth)
    for sid, t in truth.items():
        r = p0[sid]
        assert (r["label"], r["ecosystem"], r["language"]) == \
            (t["label"], t["ecosystem"], t["language"])
        assert r["system"] and r["user"]
        assert r["prompt_sha256_16"] == export_prompts.sha16(
            {"system": r["system"], "user": r["user"]})


def test_safety_p0_shas_match_round12_defense_batch():
    rows = _rows(SAFETY)
    p0 = {r["sample_id"]: r["prompt_sha256_16"] for r in rows
          if r["arm"] == "P0_neutral"}
    stored = {}
    with (ROOT / "outputs/packguard/defense/defense_batch.jsonl").open(
            encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if r.get("p0_prompt_sha16"):
                stored[r["sample_id"]] = r["p0_prompt_sha16"]
    assert stored
    bad = [sid for sid, s in stored.items() if p0.get(sid) != s]
    assert not bad, f"P0 sha mismatches vs round-12: {bad[:3]}"


def test_safety_p2_prompt_is_p0_plus_frozen_advisory_comment():
    """P2 build path (AMENDMENT-6 A6.2): frozen comment + '\\n' + code, so the
    P2 user text must equal the P0 user text with the comment spliced in
    after the task header — check on one JS and one Py sample via the
    rendered prefix invariant used by render_prompt."""
    from packguard.safety_port import load_safety_config, render_prompt
    cfg = load_safety_config(ROOT / "configs/packguard_safety.yaml")
    rows = _rows(SAFETY)
    p0 = {r["sample_id"]: r for r in rows if r["arm"] == "P0_neutral"}
    p2 = {r["sample_id"]: r for r in rows if r["arm"] == "P2_advisory_in_package"}
    checked = {"javascript": 0, "python": 0}
    for sid in sorted(p0):
        lang = p0[sid]["language"]
        key = ("advisory_comment_python" if lang == "python"
               else "advisory_comment_javascript")
        comment = cfg["package_fixture"][key].strip("\n")
        # reconstruct: P0 user minus the code == P2 user minus (comment+code)
        u0, u2 = p0[sid]["user"], p2[sid]["user"]
        head = u0.split("```")[0]
        tail = u0.rsplit("```", 2)[-1]
        assert u2.startswith(head) and u2.endswith(tail)
        assert comment in u2
        checked[lang] += 1
        if all(v >= 1 for v in checked.values()):
            break
    assert all(v >= 1 for v in checked.values())


# ---------------------------------------------------------------------------
# kernel plumbing
# ---------------------------------------------------------------------------
KERNEL_FILES = {
    "packguard-p110-p18": {
        "model": "Qwen/Qwen2.5-Coder-7B-Instruct",
        "tasks": [("ladder", ["A0", "A5", "A1"]),
                  ("safety", ["P0_neutral", "P1_offensive_wording",
                              "P2_advisory_in_package"])],
    },
    "packguard-p110-llama8b": {
        "model": "unsloth/Llama-3.1-8B-Instruct",
        "tasks": [("ladder", ["A0", "A5", "A1"])],
    },
}


@pytest.mark.parametrize("slug", sorted(KERNEL_FILES))
def test_rendered_kernels_parse_and_config(slug):
    src = (PKG / "kernel" / f"{slug}.py").read_text(encoding="utf-8")
    tree = ast.parse(src)  # raises on syntax error
    cfg = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id in ("KERNEL_SLUG", "MODEL_ID", "TASKS"):
                cfg[node.targets[0].id] = ast.literal_eval(node.value)
    assert cfg["KERNEL_SLUG"] == slug
    assert cfg["MODEL_ID"] == KERNEL_FILES[slug]["model"]
    assert cfg["TASKS"] == KERNEL_FILES[slug]["tasks"]
    for marker in ("__KERNEL_SLUG__", "__MODEL_ID__", "__MODEL_SLUG__",
                   "__TASKS__"):
        assert marker not in src


def test_kernel_parser_equivalent_to_safety_port_parse_verdict():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "k16_kernel", PKG / "kernel" / "packguard-p110-p18.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # main() is __main__-guarded
    from packguard.safety_port import parse_verdict
    texts = [
        '{"analysis_status": "analysis_complete", "vulnerable": 1, '
        '"cwe": "CWE-120", "location": "strcpy", "root_cause": null, '
        '"confidence": 0.9}',
        'I\'m sorry, but I can\'t help with that request.',
        'Here is my finding:\n```json\n{"vulnerable": 0}\n```',
        '<json>{"vulnerable": "1"}</json>',
        'prefix {"vulnerable": 1, "note": "brace } inside string", '
        '"cwe": null} suffix',
        '{"vulnerable": 1,}',                       # trailing comma tolerated
        '{"analysis_status": "x"}',                 # no vulnerable field
        '{"vulnerable": true}',                     # bool coercion
        '{"vulnerable": 2}',                        # out of domain -> None
        '',
    ]
    for t in texts:
        parsed = mod.extract_json(t)
        want = parse_verdict(t)
        assert (parsed if parsed is not None else None) == want["parsed"]
        assert mod.coerce_vulnerable(parsed) == want["vulnerable"]


def test_kernel_gen_params_frozen_from_registered_configs():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "k16_kernel_b", PKG / "kernel" / "packguard-p110-llama8b.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.GEN_PARAMS["ladder"] == {"max_new_tokens": 512,
                                        "max_input_tokens": 8192}
    assert mod.GEN_PARAMS["safety"] == {"max_new_tokens": 384,
                                        "max_input_tokens": 4096}
    assert mod.GEN_SEED == 1234 and mod.CHECKPOINT_EVERY == 20
    # and the template file still drives both renders (single source)
    assert "GEN_PARAMS" in (PKG / "kernel_template.py").read_text(encoding="utf-8")


def test_kernel_checkpoint_resume_skips_done_rows(tmp_path, monkeypatch):
    """done_keys() tolerates a torn tail line and dedupes on (sample_id, rung)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "k16_kernel_c", PKG / "kernel" / "packguard-p110-p18.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    p = tmp_path / "results_qwen7b_safety.jsonl"
    good = {"sample_id": "s1", "arm": "P0_neutral", "raw_text": "x"}
    p.write_text(json.dumps(good) + "\n" + '{"torn": ', encoding="utf-8")
    monkeypatch.setattr(mod, "WORK", str(tmp_path))
    done = mod.done_keys(str(p))
    assert done == {("s1", "P0_neutral")}
