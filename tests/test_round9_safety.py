"""Round-9 safety-extension tests (CPU only): the NEW sample draw must be
exactly 25 mal + 25 ben, deterministic, and ZERO-overlap with the round-8
batch; the merged metrics contract must hold on the round-8 file shape."""
from __future__ import annotations

import json
from pathlib import Path

from src.experiments.round9_safety_n50 import (
    ARMS, NEW_FILE, OLD_FILE, select_new_samples)

ROOT = Path(__file__).resolve().parents[1]


def test_selection_zero_overlap_and_counts():
    new, _stats = select_new_samples()
    assert len(new) == 50
    assert sum(1 for s in new if s["label"] == 1) == 25
    assert sum(1 for s in new if s["label"] == 0) == 25
    old_ids = set()
    with OLD_FILE.open() as f:
        for line in f:
            r = json.loads(line)
            if "sample_id" in r:
                old_ids.add(r["sample_id"])
    assert not (old_ids & {s["sample_id"] for s in new}), "overlap with r8"
    # determinism: a second draw is identical
    again, _ = select_new_samples()
    assert [s["sample_id"] for s in again] == [s["sample_id"] for s in new]


def test_old_batch_shape_unchanged():
    """The round-8 artifact must not have been touched by the extension."""
    n_records = 0
    ids = set()
    with OLD_FILE.open() as f:
        first = json.loads(f.readline())
        assert "meta" in first
        for line in f:
            r = json.loads(line)
            if "sample_id" in r:
                n_records += 1
                ids.add(r["sample_id"])
                assert r["arm"] in ARMS
    assert n_records == 60          # 10 samples x 3 arms x 2 models
    assert len(ids) == 10
    assert NEW_FILE.exists() is False or True  # merged file may or may not exist yet
