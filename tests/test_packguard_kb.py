"""Unit tests for the PackGuard LLM-KB (F2). All LLM paths use INJECTED
stub generators — no model is loaded here (the real 0.5B smoke is run
separately and its output pasted into reports/round8/W2_report.md)."""
import json

import pytest

from packguard.kb import (
    FAKE_API_SMOKE,
    KB_REQUIRED_FIELDS,
    RISK_LEVELS,
    SEED_KB,
    SEMANTIC_CLASSES,
    KnowledgeBase,
    LLMKBBuilder,
    kb_features,
)
from src.models.refusal_monitor import ANSWER, REFUSAL, RefusalMonitor

REFUSAL_TEXT = "I'm sorry, but I can't help with that request."
FENCED = 'Here you go:\n```json\n{"api": "%s", "semantic_class": "NETWORK", ' \
         '"risk_level": "high", "confidence": 0.7, "rationale": "socket use"}\n```'


@pytest.fixture()
def kb(tmp_path):
    return KnowledgeBase(tmp_path / "kb")


def _builder(kb, texts):
    """Stub generator popping canned texts (records call count)."""
    state = {"calls": list(texts), "n": 0}

    def gen(prompt):
        assert KB_REQUIRED_FIELDS  # prompt contract sane
        state["n"] += 1
        return state["calls"].pop(0) if state["calls"] else REFUSAL_TEXT

    builder = LLMKBBuilder(kb, generator=gen)
    return builder, state


# ---------------------------------------------------------------------------
# Seed KB
# ---------------------------------------------------------------------------
def test_seed_kb_has_20_entries_all_six_classes():
    assert len(SEED_KB) == 20
    classes = {e["semantic_class"] for e in SEED_KB}
    assert classes <= set(SEMANTIC_CLASSES)
    for c in ["FILE_IO", "NETWORK", "PROCESS", "CRYPTO", "DYNAMIC_CODE",
              "DATA_ACCESS"]:
        assert c in classes, f"canonical class {c} missing from seed KB"
    assert all(e["risk_level"] in RISK_LEVELS for e in SEED_KB)


def test_kb_lookup_seed_and_versioning_roundtrip(tmp_path):
    kb = KnowledgeBase(tmp_path / "kb")
    assert kb.lookup("child_process.exec") is not None
    kb.add({"api": "new.api", "semantic_class": "NETWORK",
            "risk_level": "medium", "rationale": "x", "confidence": 0.9,
            "source": "llm:stub"})
    p1 = kb.save_version()
    assert p1.name == "kb_v0001.jsonl"
    kb2 = KnowledgeBase(tmp_path / "kb")
    assert kb2.lookup("new.api")["semantic_class"] == "NETWORK"
    p2 = kb2.save_version()
    assert p2.name == "kb_v0002.jsonl"  # versioned snapshots, never in-place
    lines = [json.loads(l) for l in p2.read_text().splitlines() if l.strip()]
    assert any(e["api"] == "new.api" for e in lines)


# ---------------------------------------------------------------------------
# Builder: parse, cache, refusal gate
# ---------------------------------------------------------------------------
def test_builder_parses_fenced_json_and_caches_by_api(kb):
    builder, state = _builder(kb, [FENCED % "fs.readdirRecursive"])
    e1 = builder.classify_api("fs.readdirRecursive")
    assert e1["semantic_class"] == "NETWORK"
    assert e1["risk_level"] == "high"
    assert e1["source"].startswith("llm:")
    assert e1["unsure"] is False
    assert e1["confidence"] == pytest.approx(0.7)
    e2 = builder.classify_api("fs.readdirRecursive")  # KB cache hit, no LLM call
    assert e2 is e1
    assert state["n"] == 1


def test_builder_refusal_retry_once_then_unsure(kb):
    builder, state = _builder(kb, [REFUSAL_TEXT, REFUSAL_TEXT])
    e = builder.classify_api("process.envDump")
    assert e["semantic_class"] == "UNSURE"       # never a fabricated class
    assert e["risk_level"] is None
    assert e["unsure"] is True
    assert e["confidence"] == 0.0
    assert state["n"] == 2                        # initial + exactly 1 retry
    assert builder.counters["retries_used"] == 1
    assert builder.counters["refusals"] == 2
    assert builder.counters["unsure"] == 1


def test_builder_refusal_retry_succeeds(kb):
    builder, state = _builder(kb, [REFUSAL_TEXT, FENCED % "process.envDump"])
    e = builder.classify_api("process.envDump")
    assert e["semantic_class"] == "NETWORK" and e["unsure"] is False
    assert builder.counters["retries_used"] == 1


def test_builder_invalid_class_lands_unsure_not_invented(kb):
    bad = ('{"api": "wasm.instantiateRemote", "semantic_class": "HACKING", '
           '"risk_level": "high", "rationale": "nope"}')
    builder, state = _builder(kb, [bad, bad])
    e = builder.classify_api("wasm.instantiateRemote")
    assert e["semantic_class"] == "UNSURE"
    assert e["semantic_class"] not in SEMANTIC_CLASSES or \
        e["semantic_class"] == "UNSURE"


def test_builder_seed_entries_never_call_llm(kb):
    builder, state = _builder(kb, [])
    e = builder.classify_api("subprocess.Popen")
    assert e["source"] == "seed" and e["confidence"] == 1.0
    assert state["n"] == 0


def test_monitor_gate_answer_on_valid_payload():
    mon = RefusalMonitor()
    text = FENCED % "dns.tunnelQuery"
    cls = mon.classify(text, required_fields=KB_REQUIRED_FIELDS)
    assert cls["status"] == ANSWER


def test_monitor_gate_refusal_on_refusal_text():
    mon = RefusalMonitor()
    cls = mon.classify(REFUSAL_TEXT, required_fields=KB_REQUIRED_FIELDS)
    assert cls["status"] == REFUSAL


# ---------------------------------------------------------------------------
# KB-augmented features
# ---------------------------------------------------------------------------
def test_kb_features_seed_mixture(tmp_path):
    kb = KnowledgeBase(tmp_path / "kb")  # seed entries only, no files yet
    feats = kb_features(["child_process.exec", "fs.readFile", "never.seen.api"],
                        kb)
    assert feats["kb_n_calls"] == 3
    assert feats["kb_risk_ratio"] == pytest.approx(1 / 3)  # exec is high
    assert feats["kb_unsure_ratio"] == pytest.approx(1 / 3)  # unknown api
    assert feats["kb_confidence"] == pytest.approx((1.0 + 1.0 + 0.0) / 3)


def test_kb_features_empty_and_unsure(tmp_path):
    kb = KnowledgeBase(tmp_path / "kb")
    assert kb_features([], kb)["kb_n_calls"] == 0
    kb.add({"api": "x.y", "semantic_class": "UNSURE", "risk_level": None,
            "rationale": "r", "confidence": 0.0, "source": "llm:stub",
            "unsure": True})
    f = kb_features(["x.y"], kb)
    assert f["kb_unsure_ratio"] == 1.0 and f["kb_confidence"] == 0.0


def test_fake_api_smoke_fixture_has_10_names():
    assert len(FAKE_API_SMOKE) == 10
    assert all(a not in {e["api"] for e in SEED_KB} for a in FAKE_API_SMOKE)
