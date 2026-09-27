#!/usr/bin/env python3
"""Frontier-model safety-attack runner (P1-8) — READY-TO-RUN once an API key is provided.

Reads a prompt JSONL (same schema as outputs/packguard/guarddog/defense_batch.jsonl rows:
{"sample_id", "label", "arm"/"condition", "prompt": {"system", "user"}} or a flat
{"prompt"} field), calls a frontier chat API with temperature 0, and writes rows
compatible with packguard safety analysis:
    {"sample_id", "arm", "model", "label", "raw_text", "mock": false, "date"}

Providers (auto-picked by env var, first found wins):
    OPENAI_API_KEY     -> https://api.openai.com/v1/chat/completions
    ANTHROPIC_API_KEY  -> https://api.anthropic.com/v1/messages
    GEMINI_API_KEY     -> https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent

Usage:
    OPENAI_API_KEY=sk-... .venv/bin/python scripts/frontier_safety_runner.py \
        --in outputs/packguard/safety/prompts_frontier.jsonl \
        --model gpt-4o-mini --out outputs/packguard/r16/frontier_results.jsonl --limit 300

NO KEY = NO RUN. This script is staged so P1-8 is one command once the key exists.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

PROMPT_JSONL_DEFAULT = "outputs/packguard/safety/prompts_frontier.jsonl"
OUT_DEFAULT = "outputs/packguard/r16/frontier_results.jsonl"
TIMEOUT_S = 120


def _post_json(url: str, headers: dict, payload: dict) -> tuple[int, dict]:
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json", **headers},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8") or "{}")


def call_openai(model: str, system: str, user: str) -> str:
    status, body = _post_json(
        "https://api.openai.com/v1/chat/completions",
        {"Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}"},
        {"model": model, "temperature": 0,
         "messages": [{"role": "system", "content": system},
                      {"role": "user", "content": user}]})
    if status != 200:
        raise RuntimeError(f"openai {status}: {json.dumps(body)[:300]}")
    return body["choices"][0]["message"]["content"]


def call_anthropic(model: str, system: str, user: str) -> str:
    status, body = _post_json(
        "https://api.anthropic.com/v1/messages",
        {"x-api-key": os.environ["ANTHROPIC_API_KEY"],
         "anthropic-version": "2023-06-01"},
        {"model": model, "max_tokens": 768, "temperature": 0,
         "system": system, "messages": [{"role": "user", "content": user}]})
    if status != 200:
        raise RuntimeError(f"anthropic {status}: {json.dumps(body)[:300]}")
    return "".join(b.get("text", "") for b in body.get("content", []))


def call_gemini(model: str, system: str, user: str) -> str:
    url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
           f"{model}:generateContent?key={os.environ['GEMINI_API_KEY']}")
    status, body = _post_json(
        url, {},
        {"systemInstruction": {"parts": [{"text": system}]},
         "contents": [{"parts": [{"text": user}]}],
         "generationConfig": {"temperature": 0, "maxOutputTokens": 768}})
    if status != 200:
        raise RuntimeError(f"gemini {status}: {json.dumps(body)[:300]}")
    cands = body.get("candidates", [])
    parts = (cands[0].get("content", {}).get("parts", []) if cands else [])
    return "".join(p.get("text", "") for p in parts)


PROVIDERS = {
    "openai": (os.environ.get("OPENAI_API_KEY"), call_openai,
               "https://api.openai.com/v1/chat/completions"),
    "anthropic": (os.environ.get("ANTHROPIC_API_KEY"), call_anthropic,
                  "https://api.anthropic.com/v1/messages"),
    "gemini": (os.environ.get("GEMINI_API_KEY"), call_gemini,
               "https://generativelanguage.googleapis.com/v1beta/models"),
}


def pick_provider(model: str) -> str:
    m = model.lower()
    if "gpt" in m or m.startswith("o") and "mini" in m:
        return "openai"
    if "claude" in m:
        return "anthropic"
    if "gemini" in m:
        return "gemini"
    for name, (key, _, _) in PROVIDERS.items():
        if key:
            return name
    raise SystemExit("No frontier API key found in env (OPENAI_API_KEY / "
                     "ANTHROPIC_API_KEY / GEMINI_API_KEY). Provide one and re-run.")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default=PROMPT_JSONL_DEFAULT)
    ap.add_argument("--out", default=OUT_DEFAULT)
    ap.add_argument("--model", required=True,
                    help="e.g. gpt-4o-mini | claude-3-5-haiku-latest | gemini-1.5-flash")
    ap.add_argument("--limit", type=int, default=0, help="0 = all rows")
    args = ap.parse_args()

    provider = pick_provider(args.model)
    key_present = PROVIDERS[provider][0]
    if not key_present:
        raise SystemExit(f"env {provider.upper()}_API_KEY missing")
    caller = {"openai": call_openai, "anthropic": call_anthropic,
              "gemini": call_gemini}[provider]

    rows = [json.loads(l) for l in open(args.inp, encoding="utf-8") if l.strip()]
    if args.limit:
        rows = rows[: args.limit]
    done = 0
    with open(args.out, "a", encoding="utf-8") as fh:
        for r in rows:
            prompt = r.get("prompt") or {}
            system = prompt.get("system", "")
            user = prompt.get("user", "") or r.get("prompt_text", "")
            try:
                text = caller(args.model, system, user)
                status = "ok"
            except Exception as exc:  # noqa: BLE001 — per-row resilience, logged
                text = ""
                status = f"error: {exc}"
            rec = {"sample_id": r.get("sample_id"), "arm": r.get("arm") or r.get("condition"),
                   "model": args.model, "provider": provider, "label": r.get("label"),
                   "raw_text": text, "status": status, "mock": False,
                   "date": datetime.now(timezone.utc).isoformat()}
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            fh.flush()
            done += 1
            if done % 10 == 0:
                print(f"[frontier] {done}/{len(rows)} last_status={status}", flush=True)
            if status != "ok":
                time.sleep(2)  # backoff on provider errors
    print(f"[frontier] wrote {done} rows -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
