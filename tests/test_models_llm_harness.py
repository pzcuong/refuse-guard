"""Offline unit tests for src/models/llm_harness.py (no model download)."""
import json

import pytest

from src.models.llm_harness import DEFAULT_TEMPLATE, LLMHarness, build_prompt, extract_json


# --------------------------------------------------------------- extract_json
@pytest.mark.parametrize(
    "text,expected",
    [
        # plain JSON with leading/trailing text
        ('Sure! {"vulnerable": 1, "cwe": "CWE-120", "location": "line 3"} hope it helps',
         {"vulnerable": 1, "cwe": "CWE-120", "location": "line 3"}),
        # markdown fence
        ('Analysis:\n```json\n{"vulnerable": 0}\n```\nDone.', {"vulnerable": 0}),
        # fence without language tag
        ('```\n{"vulnerable": 0}\n```', {"vulnerable": 0}),
        # <json> tags
        ('<json>{"vulnerable": 1}</json>', {"vulnerable": 1}),
        # nested braces inside string values
        ('{"vulnerable": 1, "location": "buf[64] {loop}", "cwe": "CWE-120"}',
         {"vulnerable": 1, "location": "buf[64] {loop}", "cwe": "CWE-120"}),
        # trailing comma tolerated
        ('{"vulnerable": 1, "cwe": "CWE-79",}', {"vulnerable": 1, "cwe": "CWE-79"}),
        # two objects -> first one wins
        ('{"vulnerable": 1} {"vulnerable": 0}', {"vulnerable": 1}),
        # no JSON at all
        ("I'm sorry, but I cannot help with that.", None),
    ],
)
def test_extract_json(text, expected):
    obj, block = extract_json(text)
    assert obj == expected


def test_extract_json_empty_and_none():
    assert extract_json("") == (None, None)
    assert extract_json(None) == (None, None)


# ------------------------------------------------------------------ prompt
def test_build_prompt_standardized_template():
    p = build_prompt("int f() { return 0; }", language="c")
    assert set(p) == {"system", "user"}
    assert "```c\nint f() { return 0; }\n```" in p["user"]
    for field in ("analysis_status", "vulnerable", "cwe", "location", "root_cause", "confidence"):
        assert field in p["system"]  # locked schema is in the system prompt
    assert p == build_prompt("int f() { return 0; }")  # deterministic
    assert DEFAULT_TEMPLATE["name"] == "vuln_analysis_standardized_v1"


# ------------------------------------------------------------------- caching
class FakeTok:
    chat_template = "fake-template-v1"


class FakeHarness(LLMHarness):
    """Never touches HF: canned generations + fake tokenizer."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._tokenizer = FakeTok()  # bypass HF tokenizer load
        self.calls = 0

    def _generate_batch(self, prompts, cfg):
        self.calls += 1
        return {
            "texts": [f'{{"vulnerable": 0, "cwe": null, "location": null, "for": "{p["user"][:10]}"}}'
                      for p in prompts],
            "metas": [{"prompt_tokens": 10, "completion_tokens": 5, "latency_s": 0.01}
                      for _ in prompts],
        }


@pytest.fixture()
def harness(tmp_path):
    return FakeHarness("fake/model-x", device="cpu", cache_dir=str(tmp_path / "cache"))


def test_cache_key_sensitivity(harness):
    p = {"system": "s", "user": "u"}
    base = harness.cache_key(p, {"max_new_tokens": 512})
    assert harness.cache_key(p, {"max_new_tokens": 256}) != base          # gen_cfg
    assert harness.cache_key({"system": "s", "user": "u2"}, {"max_new_tokens": 512}) != base  # prompt
    other = FakeHarness("fake/model-y", device="cpu", cache_dir=harness.cache_dir)
    assert other.cache_key(p, {"max_new_tokens": 512}) != base            # model_id
    other.revision = "v2"
    assert other.cache_key(p, {"max_new_tokens": 512}) != base            # revision
    # stable across instances with identical inputs
    twin = FakeHarness("fake/model-x", device="cpu", cache_dir=harness.cache_dir)
    assert twin.cache_key(p, {"max_new_tokens": 512}) == base


def test_generate_and_resume_from_cache(harness, tmp_path):
    prompts = [build_prompt("int a(){}"), build_prompt("int b(){}")]
    gen_cfg = {"max_new_tokens": 512, "seed": 1234, "batch_size": 2}

    r1 = harness.generate(prompts, gen_cfg)
    assert harness.calls == 1  # one batch call
    assert all(not r["meta"]["cache_hit"] for r in r1)
    assert all(r["meta"]["model_id"] == "fake/model-x" for r in r1)
    assert {"template_hash", "prompt_hash", "gen_cfg_hash", "date", "device", "dtype"} <= set(r1[0]["meta"])

    # second pass: all cache hits, identical texts, no model calls
    r2 = harness.generate(prompts, gen_cfg)
    assert harness.calls == 1
    assert all(r["meta"]["cache_hit"] for r in r2)
    assert [r["text"] for r in r1] == [r["text"] for r in r2]

    # resume: a NEW harness instance over the same cache_dir sees the entries
    fresh = FakeHarness("fake/model-x", device="cpu", cache_dir=str(tmp_path / "cache"))
    r3 = fresh.generate(prompts, gen_cfg)
    assert fresh.calls == 0
    assert all(r["meta"]["cache_hit"] for r in r3)

    # changed gen_cfg -> cache miss
    r4 = harness.generate(prompts, {"max_new_tokens": 64, "seed": 1234, "batch_size": 2})
    assert harness.calls == 2
    assert all(not r["meta"]["cache_hit"] for r in r4)

    # jsonl file: one line per unique key
    lines = [json.loads(l) for l in open(next(harness.cache_dir.glob("*.jsonl")))]
    assert len(lines) == len(prompts) + len(prompts)  # 2 keys x 2 gen_cfgs


def test_coerce_prompt_accepts_sample_dict(harness):
    p = harness._coerce_prompt({"func": "int f(){}", "language": "c"}, None)
    assert "int f(){}" in p["user"]
    with pytest.raises(ValueError):
        harness._coerce_prompt({"foo": "bar"}, None)


# ---------------------------------------------------------------- truncation
class _WordTok:
    """Fake tokenizer: 1 token == 1 whitespace-separated word (audit round 1,
    V1 #4: the harness had NO input truncation; this tests the head+tail guard
    offline, without downloading any model)."""

    chat_template = "fake-template-v1"

    def encode(self, text):
        return text.split()

    def decode(self, ids, skip_special_tokens=True):
        return " ".join(ids)


def test_truncate_input_head_tail(monkeypatch, tmp_path):
    h = FakeHarness("fake/model-x", device="cpu", cache_dir=str(tmp_path / "c"))
    h._tokenizer = _WordTok()
    prompt = {"system": "sys", "user": " ".join(f"w{i}" for i in range(100))}

    # short input passes through untouched
    out, meta = h.truncate_input(prompt, max_input_tokens=200)
    assert meta == {} and out is prompt

    # long input: head+tail kept, middle elided, meta discloses the cut
    out, meta = h.truncate_input(prompt, max_input_tokens=30)
    assert meta["input_truncated"] is True
    assert meta["input_tokens_before"] == 100
    assert meta["input_tokens_omitted"] > 0
    assert meta["truncation_strategy"] == "head+tail"
    head_word = out["user"].split()[0]
    tail_word = out["user"].split()[-1]
    assert head_word == "w0" and tail_word == "w99"          # head AND tail kept
    assert "TRUNCATED" in out["user"]
    assert "w50" not in out["user"].split()                  # middle elided
    assert out["system"] == "sys"                            # system untouched


def test_generate_applies_truncation_before_cache(tmp_path):
    h = FakeHarness("fake/model-x", device="cpu", cache_dir=str(tmp_path / "c"))
    h._tokenizer = _WordTok()
    long_user = " ".join(f"w{i}" for i in range(200))
    prompts = [{"system": "s", "user": long_user}]
    r = h.generate(prompts, {"max_new_tokens": 8, "max_input_tokens": 40})
    assert r[0]["meta"]["input_truncated"] is True
    assert r[0]["meta"]["input_tokens_before"] == 200
    # truncated prompt is what gets hashed: re-run hits the same cache entry
    r2 = h.generate(prompts, {"max_new_tokens": 8, "max_input_tokens": 40})
    assert r2[0]["meta"]["cache_hit"] is True
    lines = [json.loads(l) for l in open(next(h.cache_dir.glob("*.jsonl")))]
    assert len(lines) == 1


# ---------------------------------------------------------------------------
# Audit round 2 (V2 #5)
# ---------------------------------------------------------------------------
# Audit round 2 (V2 #5): accelerator-recovery path — retry once, then CPU
# fallback, recovery provenance surfaced in meta (no more silent SKIPPED).
# ---------------------------------------------------------------------------
def _fake_ok(prompts, cfg):
    return {"texts": ['{"vulnerable": 0}'] * len(prompts),
            "metas": [{"prompt_tokens": 1, "completion_tokens": 1, "latency_s": 0.01}
                      for _ in prompts]}


def test_generate_retries_transient_accelerator_error(tmp_path, monkeypatch):
    harness = FakeHarness("fake/model-x", device="cpu", cache_dir=str(tmp_path / "c"))
    state = {"n": 0}

    def flaky(prompts, cfg):
        state["n"] += 1
        if state["n"] == 1:
            raise RuntimeError("Index out of bounds for dimension with size 151936")
        return _fake_ok(prompts, cfg)

    monkeypatch.setattr(harness, "_generate_batch", flaky)
    monkeypatch.setattr("src.models.llm_harness.time.sleep", lambda _s: None)
    out = harness.generate([build_prompt("int a(){}")], {"max_new_tokens": 8})
    assert state["n"] == 2  # one failure, one successful retry
    assert out[0]["meta"]["gen_retries"] == 1
    assert out[0]["meta"]["fallback_device"] is None
    assert "Index out of bounds" in out[0]["meta"]["gen_errors"][0]
    # recovered generation is cached like any other
    out2 = harness.generate([build_prompt("int a(){}")], {"max_new_tokens": 8})
    assert out2[0]["meta"]["cache_hit"] is True
    assert out2[0]["meta"]["gen_retries"] == 1  # provenance survives the cache


def test_generate_cpu_fallback_when_device_error_persists(tmp_path, monkeypatch):
    harness = FakeHarness("fake/model-x", device="cpu", cache_dir=str(tmp_path / "c"))
    state = {"n": 0}

    def fails_on_device_then_cpu_succeeds(prompts, cfg):
        # attempt + same-device retry fail (accelerator flake), the CPU-fallback
        # call succeeds — mirrors the round-2 MPS profile.
        state["n"] += 1
        if state["n"] <= 2:
            raise RuntimeError("Metal kIOGPUCommandBufferCallbackErrorInnocentVictim")
        return _fake_ok(prompts, cfg)

    monkeypatch.setattr(harness, "_generate_batch", fails_on_device_then_cpu_succeeds)
    monkeypatch.setattr("src.models.llm_harness.time.sleep", lambda _s: None)
    out = harness.generate([build_prompt("int b(){}")], {"max_new_tokens": 8})
    assert state["n"] == 3  # attempt, retry, cpu-fallback
    assert out[0]["meta"]["fallback_device"] == "cpu"
    assert out[0]["meta"]["gen_retries"] == 1
    assert len(out[0]["meta"]["gen_errors"]) == 2  # attempt1 + retry both failed


def test_generate_raises_only_after_retry_and_cpu_both_fail(tmp_path, monkeypatch):
    harness = FakeHarness("fake/model-x", device="cpu", cache_dir=str(tmp_path / "c"))

    def always_fails(prompts, cfg):
        raise RuntimeError("hard failure")

    monkeypatch.setattr(harness, "_generate_batch", always_fails)
    monkeypatch.setattr("src.models.llm_harness.time.sleep", lambda _s: None)
    with pytest.raises(RuntimeError, match="retry \+ CPU fallback"):
        harness.generate([build_prompt("int c(){}")], {"max_new_tokens": 8})
