#!/usr/bin/env python
"""Minimal RefuseGuard demo: analyze ONE C file through the pipeline (S-R4).

Closes proposal §14 deliverable #7 (V2-R4: demo was missing). Default mode is
FULLY OFFLINE: task-intent gate + P1 semantic-context mediation + refusal
monitor + CodeBERT (B4) prior on CPU. No LLM is downloaded or called unless
you pass --with-llm (requires a locally cached HF model and enough RAM).

Usage:
    .venv/bin/python scripts/demo_refuseguard.py path/to/function.c
    .venv/bin/python scripts/demo_refuseguard.py func.c --with-llm \
        --model Qwen/Qwen2.5-Coder-3B-Instruct [--device mps]

Report sections: (1) intent gate on the request/payload, (2) P1 mediation
summary, (3) B4 CodeBERT prior prob(vulnerable) on CPU, (4) refusal-monitor
status on a schema-complete verdict built from the B4 prior (and on the real
LLM answer when --with-llm is set). Numbers printed are computed live; the B4
checkpoint must exist (scripts/train_codebert.py) or section 3 is skipped.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def section(title: str) -> None:
    print(f"\n--- {title} " + "-" * max(0, 60 - len(title)))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("path", help="path to a C/C++ function file to analyze")
    ap.add_argument("--with-llm", action="store_true",
                    help="also run the local LLM via RefuseGuardPipeline (P2); "
                          "default OFF = offline demo")
    ap.add_argument("--model", default="Qwen/Qwen2.5-Coder-3B-Instruct",
                    help="HF model id used with --with-llm")
    ap.add_argument("--device", default="cpu",
                    help="device for the CodeBERT prior (default cpu)")
    args = ap.parse_args()

    src = Path(args.path)
    code = src.read_text(encoding="utf-8")
    sample = {"sample_id": f"demo-{src.stem}", "pair_id": None, "func": code,
              "label": -1, "cwe": None, "cve": None, "project": "demo",
              "split": "demo"}
    print(f"RefuseGuard demo — input: {src} ({len(code)} chars, "
          f"{len(code.splitlines())} lines)")

    # -- (1) task-intent gate (lexical/structural, no model) -----------------
    from src.defenses.refuseguard import RefuseGuardPipeline
    from src.conditions.parser_utils import parse, find_function, resolve_language

    pipeline = RefuseGuardPipeline()  # llm_callable None: gate/mediation only
    gate = pipeline._intent_gate(
        "Analyze whether this function contains a vulnerability "
        "(JSON verdict: analysis_status, vulnerable, cwe, location, confidence).")
    tree = parse(code, resolve_language(code, "c"), auto=True)
    is_code = tree is not None and find_function(tree) is not None
    payload_flag = pipeline._payload_safety_flag(code)
    section("1. task-intent gate (request + payload)")
    print(f"request task_class : {gate['task_class']}"
          + (f" (matched {gate.get('matched_rule')}: {gate.get('matched_pattern')})"
             if gate.get("matched_rule") else ""))
    print(f"payload parses as C function: {is_code} -> prompt_safety_flag="
          f"{payload_flag}")
    if gate["task_class"] == "out_of_scope" or payload_flag == "unsafe":
        print("P2 would return REFUSED_UNSAFE here (no LLM call, no retry).")

    # -- (2) P1 semantic context isolation -----------------------------------
    from src.defenses.mediator import mediate

    med = mediate(sample, "P1")
    meta = med.get("meta", {})
    section("2. P1 semantic-context mediation")
    print(f"applied={meta.get('applied')} semantics_ok={meta.get('semantics_ok')}")
    for k in ("counts", "n_edits", "n_structured", "n_verbatim"):
        if meta.get(k) is not None:
            print(f"{k}: {meta[k]}")
    if meta.get("reason"):
        print(f"reason: {meta['reason']}")

    # -- (3) B4 CodeBERT prior (CPU by default) ------------------------------
    prior = None
    ckpt = ROOT / "models_dir/transformer_baseline/best"
    section("3. B4 CodeBERT prior prob(vulnerable)")
    if not ckpt.exists():
        print(f"checkpoint {ckpt.relative_to(ROOT)} missing — run "
              "scripts/train_codebert.py; skipping prior.")
    else:
        from src.models.transformer_baseline import TransformerBaseline
        baseline = TransformerBaseline(config_path="configs/models.yaml",
                                       cfg={"device": args.device})
        (prior,) = baseline.predict([code])
        print(f"prob(vulnerable) = {prior:.4f}  "
              f"(checkpoint {ckpt.relative_to(ROOT)}, device={args.device})")

    # -- (4) refusal monitor on a schema-complete verdict --------------------
    from src.models.refusal_monitor import default_monitor

    monitor = default_monitor()
    verdict = {
        "analysis_status": "completed",
        "vulnerable": int(prior >= 0.5) if prior is not None else 0,
        "cwe": None, "location": None, "root_cause": None,
        "confidence": round(float(prior), 4) if prior is not None else None,
    }
    answer = json.dumps(verdict)
    res = monitor.classify(answer, prompt_safety_flag=payload_flag)
    section("4. refusal monitor (schema verdict from the B4 prior)")
    print(f"status={res['status']} refusal_score={res['refusal_score']:.3f} "
          f"missing_fields={res['missing_fields']} "
          f"unsafe_compliance={res['unsafe_compliance']}")
    print("(the monitor certifies schema-complete JSON as ANSWER only when the "
          "prompt is NOT flagged unsafe — the round-2 refusal-suppression fix)")

    # -- (5) optional: full P2 pipeline with a real local LLM ----------------
    if args.with_llm:
        from src.models.llm_harness import LLMHarness

        section(f"5. full P2 pipeline with {args.model}")
        harness = LLMHarness(args.model, device="mps", cache_dir="outputs/llm_cache")
        gen_cfg = {"temperature": 0.0, "max_new_tokens": 300}
        pipeline = RefuseGuardPipeline(
            llm_callable=lambda prompt: harness.generate([prompt], gen_cfg)[0]["text"])
        out = pipeline.run(sample, "C0")
        print(f"analysis_status={out.get('analysis_status')} "
              f"status={out.get('status')} y_pred={out.get('y_pred')} "
              f"gate={out.get('meta', {}).get('gate', {}).get('task_class')}")
        print(f"llm_answer={str(out.get('func'))[:400]!r}")
    else:
        print("\n(no LLM run — pass --with-llm --model <HF id> to use the real "
              "P2 pipeline; offline demo stops here)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
