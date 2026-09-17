"""Tests for src/data/sampling.py — stratified sampling + manifest building.

Runs entirely on tiny synthetic mirror fixtures (monkeypatched RAW_DIR /
CONTRAST_DIR); determinism and correctness properties are checked, not the
real 470MB dataset.
"""

from __future__ import annotations

import json

import pytest

from src.data import contrast as ct
from src.data import primevul as pv
from src.data import sampling as sp


def _row(idx, target, cwe, project="p1", commit="c"):
    return {"idx": idx, "project": project, "commit_id": commit,
            "project_url": "u", "commit_url": "u", "commit_message": "m",
            "target": target, "func": f"int f{idx}(void){{return {idx};}}",
            "func_hash": None, "file_name": "None", "file_hash": None,
            "cwe": cwe, "cve": "CVE-2024-0001", "cve_desc": "d",
            "nvd_url": "u"}


@pytest.fixture()
def fake_world(monkeypatch, tmp_path):
    """5 vulnerable (3x CWE-A, 1x CWE-B, 1x rare) + 4 benign test rows,
    2 paired rows (vul idx 0 / ben idx 9), tiny contrast CSVs."""
    d = tmp_path / "primevul_hf"
    d.mkdir()
    test_rows = [
        _row(0, 1, ["CWE-A"]), _row(1, 1, ["CWE-A"]), _row(2, 1, ["CWE-A"]),
        _row(3, 1, ["CWE-B"]), _row(4, 1, ["CWE-RARE"]),
        _row(5, 0, []), _row(6, 0, []), _row(7, 0, []), _row(8, 0, []),
    ]
    (d / "primevul_test.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in test_rows))
    (d / "primevul_test_paired.jsonl").write_text(
        json.dumps(_row(0, 1, ["CWE-A"], commit="px")) + "\n" +
        json.dumps(_row(9, 0, ["CWE-A"], commit="px")) + "\n")
    # loader needs every entry of SPLIT_FILES to exist only if touched;
    # sampling only touches test + test_paired.
    c = tmp_path / "contrast"
    c.mkdir()
    (c / "or_bench_hard_1k.csv").write_text(
        "prompt,category\n" + "".join(f"q{i},c\n" for i in range(6)))
    (c / "or_bench_toxic.csv").write_text(
        "prompt,category\n" + "".join(f"t{i},c\n" for i in range(4)))
    (c / "xstest_prompts.csv").write_text(
        "id,prompt,type,label,focus,note\n" +
        "".join(f"{i},s{i},t,safe,x,y\n" for i in range(4)) +
        "".join(f"{10+i},u{i},t,unsafe,x,y\n" for i in range(4)))
    monkeypatch.setattr(pv, "RAW_DIR", str(d))
    monkeypatch.setattr(pv, "_MEM_CACHE", {})
    monkeypatch.setattr(ct, "CONTRAST_DIR", str(c))
    monkeypatch.setattr(sp, "MANIFEST_DIR", str(tmp_path / "manifests"))
    cfg = {
        "manifest_name": "test_subset", "seed": 1234,
        "eval": {"split": "test", "n_vulnerable": 3, "n_benign": 3,
                 "stratify_key": "cwe_group", "min_group_size": 2},
        "paired": {"split": "test_paired", "mode": "intersect"},
        "contrast": {"orbench_hard": 2, "orbench_toxic": 1,
                     "xstest_safe": 2, "xstest_unsafe": 1},
    }
    return cfg, tmp_path


def _core(manifest):
    return {k: v for k, v in manifest.items() if k not in ("created", "integrity")}


def test_build_eval_subset_counts(fake_world):
    cfg, tmp = fake_world
    m = sp.build_eval_subset(cfg)
    assert m["counts"]["vulnerable_sampled"] == 3
    assert m["counts"]["benign_sampled"] == 3
    # pair (vul idx 0 in sample? depends on rng) — at minimum structure holds
    for p in m["paired"]:
        assert p["vulnerable"] in m["sample_ids"]["vulnerable"]
    assert m["counts"]["contrast_prompts"] == 6


def test_stratification_respects_groups(fake_world):
    cfg, _ = fake_world
    m = sp.build_eval_subset(cfg)
    vul_ids = m["sample_ids"]["vulnerable"]
    assert len(vul_ids) == 3 and len(set(vul_ids)) == 3
    # rare group (size 1 < min_group_size=2) merged into OTHER — the sampler
    # must still return exactly n items drawn from the 5 vulnerable rows.
    assert set(vul_ids) <= {"0", "1", "2", "3", "4"}


def test_manifest_checksum_deterministic(fake_world):
    cfg, _ = fake_world
    m1 = sp.build_eval_subset(cfg)
    m2 = sp.build_eval_subset(cfg)
    assert (m1["integrity"]["content_sha256_16"]
            == m2["integrity"]["content_sha256_16"])
    assert _core(m1) == _core(m2)
    # different seed -> different draw (overwhelmingly likely, n=3 of 5)
    cfg2 = json.loads(json.dumps(cfg))
    cfg2["seed"] = 5678
    m3 = sp.build_eval_subset(cfg2)
    assert m1["sample_ids"]["vulnerable"] != m3["sample_ids"]["vulnerable"] or \
        m1["sample_ids"]["benign"] != m3["sample_ids"]["benign"]


def test_manifest_written_and_loadable(fake_world):
    cfg, tmp = fake_world
    sp.build_eval_subset(cfg)
    path = tmp / "manifests" / "test_subset.json"
    assert path.exists()
    m = sp.load_manifest("test_subset")
    assert m["seed"] == 1234 and "criteria" in m and "source" in m
    with pytest.raises(FileNotFoundError):
        sp.load_manifest("missing_manifest")


def test_subset_records_roundtrip(fake_world):
    cfg, _ = fake_world
    m = sp.build_eval_subset(cfg)
    sub = sp.subset_records(m)
    assert {r["sample_id"] for r in sub["vulnerable"]} == \
        set(m["sample_ids"]["vulnerable"])
    assert all(r["pair_id"] for r in sub["paired"])
    n_con = sum(len(v) for v in sub["contrast"].values())
    assert n_con == m["counts"]["contrast_prompts"]
    for key, recs in sub["contrast"].items():
        expected = {"orbench_hard": "COMPLY", "orbench_toxic": "REFUSE",
                    "xstest_safe": "COMPLY", "xstest_unsafe": "REFUSE"}
        assert all(r["expected"] == expected[key] for r in recs)


def test_paired_resolves_both_members(fake_world):
    # Regression (audit round 1 / V1 #5): subset_records keyed pairs by pair_id
    # in a plain dict, silently keeping only the LAST member (always benign) —
    # 236 vulnerable members vanished from eval_subset_round1.json.
    cfg, _ = fake_world
    m = sp.build_eval_subset(cfg)
    sub = sp.subset_records(m)
    for p in m["paired"]:
        members = [r for r in sub["paired"] if r["pair_id"] == p["pair_id"]]
        assert len(members) == 2, p
        assert {r["sample_id"] for r in members} == {p["vulnerable"], p["benign"]}, p
    labels = {r["label"] for r in sub["paired"]}
    assert labels == {0, 1}


def test_contrast_calibration_scoring_disjoint(fake_world):
    # Audit round 1 / V1 #3: calibration must never overlap scoring/E8.
    cfg, _ = fake_world
    m = sp.build_eval_subset(cfg)
    cal = {i for ids in m["contrast_split"]["calibration"].values() for i in ids}
    sco = {i for ids in m["contrast_split"]["scoring"].values() for i in ids}
    assert cal and sco
    assert not (cal & sco)
    assert cal | sco == {i for ids in m["contrast_prompt_ids"].values() for i in ids}


def test_emit_runner_manifest_backfills_pair_id(fake_world):
    # Audit round 1 / V1 #5: runner manifest had pair_id=None for all
    # vulnerable members, breaking paired evaluation joins.
    cfg, _ = fake_world
    m = sp.build_eval_subset(cfg)
    path = sp.emit_runner_manifest(m["manifest_name"], "runner_subset_pairs")
    d = json.load(open(path))
    vul_pair = {p["vulnerable"]: p["pair_id"] for p in m["paired"]}
    by_id = {s["sample_id"]: s for s in d["samples"]}
    for vid, pid in vul_pair.items():
        assert by_id[vid]["pair_id"] == pid, vid


def test_no_vul_benign_overlap(fake_world):
    cfg, _ = fake_world
    m = sp.build_eval_subset(cfg)
    vul = set(m["sample_ids"]["vulnerable"])
    ben = set(m["sample_ids"]["benign"])
    assert not (vul & ben)
    for p in m["paired"]:  # paired benign members excluded from benign sample
        assert p["benign"] not in ben


def test_paired_label_convention_enforced(fake_world, monkeypatch, tmp_path):
    cfg, tmp = fake_world
    # corrupt pairing convention: two vulnerable rows in a pair
    bad = tmp / "primevul_hf2"
    bad.mkdir()
    rows = [_row(0, 1, ["CWE-A"]), _row(1, 1, ["CWE-A"]), _row(2, 1, ["CWE-A"]),
            _row(3, 0, []), _row(4, 0, []), _row(5, 0, [])]
    (bad / "primevul_test.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in rows))
    (bad / "primevul_test_paired.jsonl").write_text(
        json.dumps(rows[0]) + "\n" + json.dumps(rows[1]) + "\n")
    monkeypatch.setattr(pv, "RAW_DIR", str(bad))
    monkeypatch.setattr(pv, "_MEM_CACHE", {})
    with pytest.raises(AssertionError, match="pairing convention"):
        sp.build_eval_subset(cfg)


def test_emit_runner_manifest(fake_world):
    cfg, tmp = fake_world
    m = sp.build_eval_subset(cfg)
    path = sp.emit_runner_manifest(m["manifest_name"], "runner_subset")
    d = json.load(open(path))
    assert d["n_samples"] == len(d["samples"]) > 0
    s0 = d["samples"][0]
    assert set(s0) == {"sample_id", "pair_id", "func", "label", "cwe",
                       "cve", "project", "split"}
    ids = [s["sample_id"] for s in d["samples"]]
    assert len(ids) == len(set(ids))  # no duplicates across sections


def test_stratified_sample_rejects_oversized_n():
    recs = [{"sample_id": str(i)} for i in range(3)]
    with pytest.raises(ValueError, match="pool has only"):
        sp._stratified_sample(recs, lambda r: "g", 5, seed=1)
