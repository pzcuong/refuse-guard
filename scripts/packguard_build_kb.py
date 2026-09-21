"""Round-8 REAL KB build (agent F, P2): classify unknown APIs from graphs_v2
with LOCAL Qwen2.5-Coder-3B-Instruct via the refusal-gated LLMKBBuilder.

- API universe: unique node APIs in outputs/packguard/features/graphs_v2.jsonl.gz
  (NOT features rows), minus the 20 seed-KB names, ranked by document frequency.
- Top --limit APIs (default 120; scope-reducible) classified one by one;
  cache/retry/UNSURE semantics are kb.py's (refusal -> 1 retry -> UNSURE,
  never a fabricated class).
- The old kb_v0001.jsonl (0.5B fake-api smoke state: 20 seed + 10 fixture
  entries) is archived as fixture_smoke_kb_v0001.jsonl so the production KB
  starts from seeds only; the new complete snapshot is kb_v0001.jsonl
  (seed + 3B LLM entries).

Run: HF_HOME=$PWD/models_dir/hf PYTHONPATH=$PWD .venv/bin/python \
        scripts/packguard_build_kb.py --limit 120
"""
from __future__ import annotations

import argparse
import gzip
import json
import re
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path("/Users/macbook/.zcode/workspace/default/refuseguard")
GRAPHS = ROOT / "outputs/packguard/features/graphs_v2.jsonl.gz"
KB_DIR = ROOT / "outputs/packguard/kb"

PY_HINTS = ("os.", "sys.", "subprocess.", "hashlib.", "socket.", "urllib.",
            "requests.", "base64.", "shutil.", "ctypes.", "pickle.",
            "binascii.", "ftplib.", "http.client", "ssl.", "zipfile.",
            "tarfile.", "gzip.", "tempfile.", "pathlib.", "io.")
JS_HINTS = ("fs.", "child_process.", "https.", "http.", "net.", "crypto.",
            "process.", "electron.", "dns.", "dgram.", "os.", "zlib.",
            "require", "eval", "Function", "exec", "spawn")


def guess_language(api: str):
    if any(api.startswith(h) or h in api for h in PY_HINTS) and "." in api:
        return "python"
    if any(h in api for h in JS_HINTS):
        return "javascript"
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=120)
    ap.add_argument("--model", default="Qwen/Qwen2.5-Coder-3B-Instruct")
    args = ap.parse_args()

    # 1. archive the 0.5B smoke KB state (fake-api fixture entries)
    old = KB_DIR / "kb_v0001.jsonl"
    if old.exists():
        arch = KB_DIR / "fixture_smoke_kb_v0001.jsonl"
        if not arch.exists():
            old.rename(arch)
            print(f"archived {old.name} -> {arch.name} (0.5B fake-api smoke state)")

    # 2. API universe from graphs_v2
    df: Counter = Counter()
    df_mal: Counter = Counter()
    with gzip.open(GRAPHS, "rt", encoding="utf-8") as f:
        for line in f:
            g = json.loads(line)
            apis = {str(n.get("api")).strip() for n in g.get("nodes", []) if n.get("api")}
            mal = 1 if "-malicious" in str(g.get("sample_id", "")) else 0
            for a in apis:
                df[a] += 1
                if mal:
                    df_mal[a] += 1
    print(f"unique APIs in graphs_v2: {len(df)}")

    from packguard.kb import SEED_KB, KnowledgeBase, LLMKBBuilder

    seed_names = {e["api"] for e in SEED_KB}
    unknown = [(a, c) for a, c in df.most_common() if a not in seed_names]
    sel = unknown[: args.limit]
    print(f"unknown APIs: {len(unknown)}; classifying top {len(sel)} by doc frequency")

    kb = KnowledgeBase(KB_DIR)
    builder = LLMKBBuilder(kb, model_id=args.model, device="mps")
    t0 = time.time()
    for i, (api, _c) in enumerate(sel):
        t1 = time.time()
        e = builder.classify_api(api, language=guess_language(api))
        if (i + 1) % 10 == 0 or i == 0:
            rate = (time.time() - t0) / (i + 1)
            print(f"  {i+1}/{len(sel)} last={time.time()-t1:.1f}s "
                  f"avg={rate:.1f}s/call eta={rate*(len(sel)-i-1)/60:.1f}min "
                  f"unsure_so_far={builder.counters['unsure']}", flush=True)
    kb.save_version()

    st = kb.stats()
    meta = {
        "model_id": args.model,
        "api_universe": len(df),
        "n_unknown": len(unknown),
        "n_classified": len(sel),
        "counters": builder.counters,
        "kb_stats_after": st,
        "wall_seconds": round(time.time() - t0, 1),
        "selection": "top-N by document frequency over graphs_v2 samples, seed-KB names excluded",
        "date": datetime.now(timezone.utc).isoformat(),
        "docfreq_head": [
            {"api": a, "df": c, "df_mal": df_mal.get(a, 0)} for a, c in sel[:40]
        ],
    }
    with (KB_DIR / "kb_build_v2_meta.json").open("w") as f:
        json.dump(meta, f, indent=1, default=str)
    print(json.dumps({k: v for k, v in meta.items() if k != "docfreq_head"}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
