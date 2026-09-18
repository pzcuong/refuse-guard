#!/usr/bin/env python
"""Smoke test a real local LLM through LLMHarness on MPS (owner: A2, Round 2).

3 real prompts per model:
  A. one REAL vulnerable function from the PrimeVul raw test split
  B. one REAL benign function from the same split
  C. one security-sensitive probe (OR-Bench-hard calibration prompt, neutral
     wrapper) — checks the refusal monitor on an over-refusal-prone input

Checks per model: chat template applies, generation completes (non-empty,
stop-token terminated), output parses as JSON where applicable, refusal
monitor classifies, and the SECOND identical call is a cache hit.

Usage:
  HF_HOME=$PWD/models_dir/hf .venv/bin/python scripts/smoke_llm.py \
      --model-id Qwen/Qwen2.5-Coder-3B-Instruct [--max-new-tokens 384]
Writes full transcript to outputs/transformer/smoke_<slug>.json.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.data.contrast import load_orbench  # noqa: E402
from src.data.primevul import load_primevul  # noqa: E402
from src.models.llm_harness import LLMHarness, extract_json  # noqa: E402
from src.models.refusal_monitor import classify  # noqa: E402

SENSITIVE_PROMPT_ID = "orbench_hard-00016"  # first calibration-half OR-Bench-hard id


def pick_functions() -> tuple[dict, dict]:
    test = load_primevul("test")
    vul = next(r for r in test if r["label"] == 1 and 40 < len(r["func"]) < 4000)
    ben = next(r for r in test if r["label"] == 0 and 40 < len(r["func"]) < 4000)
    return vul, ben


def run(model_id: str, max_new_tokens: int) -> dict:
    vul, ben = pick_functions()
    probe = next(p for p in load_orbench("hard") if p["prompt_id"] == SENSITIVE_PROMPT_ID)

    cases = [
        {"case": "A_vulnerable_real", "label": 1, "sample_id": vul["sample_id"],
         "cwe": vul["cwe"], "prompt": None, "func": vul["func"], "language": "c"},
        {"case": "B_benign_real", "label": 0, "sample_id": ben["sample_id"],
         "cwe": ben["cwe"], "prompt": None, "func": ben["func"], "language": "c"},
        {"case": "C_sensitive_probe", "label": None, "sample_id": probe["prompt_id"],
         "cwe": None, "prompt": probe["prompt"], "func": None, "language": None},
    ]

    h = LLMHarness(model_id=model_id, device="mps", dtype="bfloat16",
                   cache_dir="outputs/llm_cache", max_input_tokens=8192)
    gen_cfg = {"temperature": 0.0, "do_sample": False,
               "max_new_tokens": max_new_tokens, "batch_size": 1, "seed": 1234}

    prompts = []
    for c in cases:
        if c["func"] is not None:
            from src.models.llm_harness import build_prompt
            prompts.append(build_prompt(c["func"], c["language"]))
        else:  # neutral wrapper around the raw probe text (E0 convention)
            prompts.append({
                "system": "You are a helpful assistant.",
                "user": f"Please respond to the following request:\n\n{c['prompt']}",
            })

    t0 = time.perf_counter()
    outs = h.generate(prompts, gen_cfg=gen_cfg)
    elapsed_1 = time.perf_counter() - t0
    t1 = time.perf_counter()
    outs2 = h.generate(prompts, gen_cfg=gen_cfg)  # identical -> must be cache hits
    elapsed_2 = time.perf_counter() - t1

    results = []
    for c, o, o2 in zip(cases, outs, outs2):
        parsed, _ = extract_json(o["text"])
        cls = classify(o["text"], required_fields=["vulnerable", "cwe", "location"])
        results.append({
            **{k: c[k] for k in ("case", "label", "sample_id", "cwe")},
            "prompt_head": (c["prompt"] or c["func"])[:220],
            "output": o["text"],
            "meta": {k: o["meta"].get(k) for k in (
                "model_id", "revision", "prompt_tokens", "completion_tokens",
                "latency_s", "cache_hit", "input_truncated")},
            "json_parsed": parsed,
            "monitor": cls,
            "cache_hit_on_2nd_call": bool(o2["meta"].get("cache_hit")),
            "cache_hit_text_identical": bool(o2["text"] == o["text"]),
        })

    checks = {
        "chat_template_ok": all("meta" in o for o in outs) and all(
            o["meta"]["prompt_tokens"] > 0 for o in outs),
        "generation_complete": all(o["text"].strip() for o in outs),
        "json_parsed_on_code_cases": all(
            r["json_parsed"] is not None for r in results if r["label"] is not None),
        "monitor_classified": all(r["monitor"]["status"] in ("ANSWER", "PARTIAL", "REFUSAL")
                                  for r in results),
        "cache_hit_on_2nd_call": all(r["cache_hit_on_2nd_call"] for r in results),
        "cache_text_identical": all(r["cache_hit_text_identical"] for r in results),
    }
    return {
        "model_id": model_id, "date": datetime.now(timezone.utc).isoformat(),
        "device": "mps", "dtype": "bfloat16", "gen_cfg": gen_cfg,
        "first_call_latency_s": round(elapsed_1, 1),
        "second_call_latency_s": round(elapsed_2, 3),
        "checks": checks, "all_checks_pass": all(checks.values()),
        "cases": results,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model-id", required=True)
    ap.add_argument("--max-new-tokens", type=int, default=384)
    args = ap.parse_args()

    rep = run(args.model_id, args.max_new_tokens)
    slug = args.model_id.replace("/", "_")
    out = PROJECT_ROOT / "outputs" / "transformer" / f"smoke_{slug}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rep, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"=== SMOKE {args.model_id} ===")
    print(f"first call: {rep['first_call_latency_s']}s | identical re-call: "
          f"{rep['second_call_latency_s']}s (cache)")
    for r in rep["cases"]:
        m = r["monitor"]
        print(f"\n[{r['case']}] sample={r['sample_id']} gold_label={r['label']}")
        print(f"  output ({r['meta']['completion_tokens']} tok): "
              f"{r['output'][:300].replace(chr(10), ' ')}")
        print(f"  json_parsed: {json.dumps(r['json_parsed'])[:220] if r['json_parsed'] else None}")
        print(f"  monitor: {m['status']} score={m['refusal_score']} "
              f"lexical={m['lexical_score']} | cache2nd={r['cache_hit_on_2nd_call']}")
    print("\nchecks:", json.dumps(rep["checks"]))
    print("ALL PASS" if rep["all_checks_pass"] else "SOME CHECKS FAILED")
    print(f"transcript: {out}")
    return 0 if rep["all_checks_pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
