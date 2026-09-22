"""Round-9 scale ladder runner (agent W2, sole GPU owner): LLAMA-3.1-8B.

Question Q-SCALE-FAMILY (the registered round-7 caveat): llama-3.2-3B is
HARMED by the full P3 reassertion defence (vul recall 1.000 -> 0.433) while
qwen-2.5-3B/7B are inert, so the round-7 null could not separate SCALE from
FAMILY-INERTNESS. This runner executes the SAME pre-registered ladder
(A0 = B0-C5_near baseline, A5 = full P3, A1 = boundary-only) on
unsloth/Llama-3.1-8B-Instruct -- SAME FAMILY as the 3B that harms, larger
scale -- on the SAME 60-vul subset (seed 20260923, sample-paired with rounds
6/7) with BYTE-IDENTICAL prompts (prompt-sha guard tested against round-6
records).

Implementation REUSES the audited round-7 machinery READ-ONLY
(src/experiments/round7_7b.py: RealLLM7B, model_guard, job runners, combined
metrics + verdict machinery). The one deliberate shim: round7_7b internals
look the model id up under the legacy key models.qwen7b; load_config() below
sets that key to the ROUND-9 model id read from models.llama8b, so every
metadata write, model-guard check and file slug sees the TRUE running model
(unsloth/Llama-3.1-8B-Instruct). The shim never changes any value -- only the
lookup key -- and the config sha16 is computed over the raw file.

Stages
    python -m src.experiments.round9_ladder --stage smoke          # onboarding, 3 prompts
    python -m src.experiments.round9_ladder --stage dry            # MockLLM, 0 GPU
    python -m src.experiments.round9_ladder --stage run  --variant A0   # B0-C5_near, 60 vul
    python -m src.experiments.round9_ladder --stage run  --variant A5   # full P3
    python -m src.experiments.round9_ladder --stage run  --variant A1   # boundary-only
    python -m src.experiments.round9_ladder --stage benign         # 30 x {C0, C5_near} B0
    python -m src.experiments.round9_ladder --stage metrics        # tables + verdict
    python -m src.experiments.round9_ladder --stage queue          # A0->A5->A1->benign, 1 shared model

Hypotheses/decision rules: copied VERBATIM from configs/round7_7b.yaml into
configs/round9_8b.yaml (H-R7-harm-replicates / H-R7-harm-absent /
H-R7-A1-minimal-safe / H-R7-benign-verdict-bias) -- the rule algebra may not
move between rounds.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.experiments.round6_ablation import load_config as _load_config_raw  # noqa: E402
from src.experiments.round7_7b import (  # noqa: E402 (read-only reuse)
    MOCK_MID, RealLLM7B, RUNGS, BENIGN_ARMS, ScaleUpBlocked, ModelGuardError,
    model_guard, build_subsets, run_vul_job, run_benign_job,
    compute_round7_metrics, prompt_for, smoke_stage as _smoke_stage_r7,
)
from src.models.llm_harness import DEFAULT_TEMPLATE  # noqa: E402 (read-only)
from src.experiments.pilot_round2 import (  # noqa: E402 (read-only reuse)
    DEFAULT_HF_HOME, DEFAULT_CACHE, now_utc,
)

DEFAULT_CONFIG = PROJECT_ROOT / "configs/round9_8b.yaml"

__all__ = ["load_config", "model_id_of", "ModelGuardError", "ScaleUpBlocked",
           "build_subsets", "run_vul_job", "run_benign_job", "run_queue",
           "smoke_stage", "dry_stage", "write_status_r9", "main"]


# ---------------------------------------------------------------------------
# config: raw load -> sha -> LEGACY-KEY SHIM (key only, never values)
# ---------------------------------------------------------------------------
def load_config(path: Optional[Path] = None) -> dict:
    """Load configs/round9_8b.yaml with the round-6 sha convention, then make
    it consumable by the round-7 machinery: cfg['models']['qwen7b'] is set to
    the round-9 model id from models.llama8b.  SHIM IS KEY-ONLY: the value is
    the true running model id, so metadata.model_id, model-guard comparisons
    and slugs all carry the real model.  Disclosed here and in the report."""
    cfg = _load_config_raw(Path(path) if path else DEFAULT_CONFIG)
    cfg["_config_path"] = str(Path(path) if path else DEFAULT_CONFIG)
    mid = (cfg.get("models") or {}).get("llama8b")
    if not mid:
        raise KeyError("models.llama8b missing from configs/round9_8b.yaml")
    cfg["models"]["qwen7b"] = mid  # LEGACY-KEY SHIM (see module docstring)
    return cfg


def model_id_of(cfg: dict) -> str:
    return (cfg.get("models") or {}).get("llama8b")


# ---------------------------------------------------------------------------
# jobs status (round-7 convention, round-9 paths)
# ---------------------------------------------------------------------------
def write_status_r9(out_dir: Path, pid: int, model_id: str, slug: str,
                    state: str, done: int, expected: int, elapsed_s: float,
                    job: str) -> None:
    rate = (elapsed_s / done) if done else None
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "jobs_status.json").write_text(json.dumps({
        "round": 9, "pid": pid, "model_id": model_id,
        "running_model_slug": slug, "running_job": job,
        "date_utc": now_utc(), "state": state,
        "records_done_this_job": done,
        "records_expected_this_job": expected,
        "elapsed_s_this_job": round(elapsed_s, 1),
        "s_per_record": round(rate, 2) if rate else None,
        "eta_minutes_this_job": round(max(0, expected - done) * rate / 60, 1)
        if rate else None,
        "log": "outputs/experiments/round9_8b/queue.log",
    }, indent=1), encoding="utf-8")


# ---------------------------------------------------------------------------
# smoke: reuse the r7 smoke machinery but write round-9-branded output
# ---------------------------------------------------------------------------
def smoke_stage(cfg: dict) -> dict:
    """Onboarding: bf16 load (fp16 fallback on OOM), 3 synthetic prompts on
    the REAL experiment template (0 bench overlap), REAL tok/s + ETA for the
    queue.  Delegates to the audited r7 smoke, renames the artifact."""
    res = _smoke_stage_r7(cfg)
    out_dir = PROJECT_ROOT / cfg["out_dir"]
    res["runner"] = "src/experiments/round9_ladder.py (r7 smoke machinery)"
    (out_dir / "smoke_8b.json").write_text(
        json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
    return res


# ---------------------------------------------------------------------------
# queue: sequential in-process, ONE shared RealLLM7B, r7 priority order
# ---------------------------------------------------------------------------
def run_queue(cfg: dict, budget_min: Optional[float] = None) -> None:
    out = PROJECT_ROOT / cfg["out_dir"]
    out.mkdir(parents=True, exist_ok=True)
    mid = model_id_of(cfg)
    slug = cfg["models"]["slugs"].get(mid, mid)
    llm = RealLLM7B(
        model_id=mid, hf_home=Path(DEFAULT_HF_HOME), cache_dir=DEFAULT_CACHE,
        max_input_tokens=int(cfg["gen_cfg"]["max_input_tokens"]),
        seed=int(cfg["gen_cfg"]["seed"]),
        dtype=str(cfg["gen_cfg"].get("dtype", "bfloat16")))
    print(f"[r9-queue] model {mid} dtype={llm.dtype} loaded", flush=True)
    subsets = build_subsets(cfg)
    jobs = [("vul", "A0"), ("vul", "A5"), ("vul", "A1"), ("benign", None)]
    for kind, variant in jobs:
        job = f"{slug}/{kind}/{variant or 'B0'}"
        print(f"[r9-queue] === START {job} ===", flush=True)
        t0 = time.perf_counter()

        def cb(done: int, expected: int, state: str, _job: str = job,
               _t0: float = t0) -> None:
            write_status_r9(out, os.getpid(), mid, slug, state, done,
                            expected, time.perf_counter() - _t0, _job)

        write_status_r9(out, os.getpid(), mid, slug, "starting", 0, 0, 0.0, job)
        try:
            if kind == "vul":
                res = run_vul_job(cfg, variant, budget_min=budget_min,
                                  llm=llm, status_cb=cb, subsets=subsets)
            else:
                res = run_benign_job(cfg, budget_min=budget_min, llm=llm,
                                     status_cb=cb, subsets=subsets)
            md = res.get("metadata", {})
            print(f"[r9-queue] === DONE {job}: n={md.get('n_records')}/"
                  f"{md.get('n_records_expected')} partial={md.get('partial')} "
                  f"cache_hits={md.get('n_cache_hits')}/{md.get('n_cache_calls')} "
                  f"wall={md.get('wall_seconds')}s ===", flush=True)
            write_status_r9(out, os.getpid(), mid, slug, "job_complete",
                            md.get("n_records", 0),
                            md.get("n_records_expected", 0),
                            time.perf_counter() - t0, job)
        except Exception:  # noqa: BLE001 — log, continue next job
            import traceback
            print(f"[r9-queue] === FAILED {job} ===\n{traceback.format_exc()}",
                  flush=True)
            write_status_r9(out, os.getpid(), mid, slug, "failed", 0, 0,
                            time.perf_counter() - t0, job)
    write_status_r9(out, os.getpid(), mid, slug, "queue_done", 0, 0, 0.0,
                    "all-jobs")
    print("[r9-queue] all jobs attempted", flush=True)


# ---------------------------------------------------------------------------
# dry (MockLLM e2e, 0 GPU) — used by tests and pre-flight plumbing checks
# ---------------------------------------------------------------------------
def dry_stage(cfg: dict) -> dict:
    from src.experiments.round5_e0v2 import MockLLM  # read-only reuse
    subsets = build_subsets(cfg)
    outs = {}
    for v in RUNGS:
        outs[v] = run_vul_job(cfg, v, dry=True, llm=MockLLM(model_id=MOCK_MID),
                              subsets=subsets)
    outs["benign"] = run_benign_job(cfg, dry=True,
                                    llm=MockLLM(model_id=MOCK_MID),
                                    subsets=subsets)
    m = compute_round7_metrics(cfg, out_dir=PROJECT_ROOT / cfg["out_dir"] / "dry",
                               dry=True)
    print("[r9] dry OK — verdict:", json.dumps(m.get("verdict", {}))[:400])
    return {"ok": True, "n_vul_A0": outs["A0"]["metadata"]["n_records"],
            "verdict": m.get("verdict", {})}


# ---------------------------------------------------------------------------
def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False),
                    encoding="utf-8")
    print(f"[r9] wrote {path}", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default=str(DEFAULT_CONFIG))
    ap.add_argument("--stage", required=True,
                    choices=["smoke", "dry", "run", "benign", "metrics",
                             "queue"])
    ap.add_argument("--variant", default=None,
                    help="vul job variant (A0|A5|A1) for --stage run")
    ap.add_argument("--budget-min", type=float, default=None)
    args = ap.parse_args()
    cfg = load_config(Path(args.config))

    if args.stage == "smoke":
        smoke_stage(cfg)
    elif args.stage == "dry":
        dry_stage(cfg)
    elif args.stage == "run":
        if args.variant not in RUNGS:
            raise SystemExit(f"--variant must be one of {RUNGS}")
        run_vul_job(cfg, args.variant, budget_min=args.budget_min)
    elif args.stage == "benign":
        run_benign_job(cfg, budget_min=args.budget_min)
    elif args.stage == "metrics":
        m = compute_round7_metrics(cfg)
        _write_json(PROJECT_ROOT / cfg["out_dir"] / "metrics_round9.json", m)
        print(json.dumps(m.get("verdict", {}), indent=1))
    elif args.stage == "queue":
        run_queue(cfg, budget_min=args.budget_min)


if __name__ == "__main__":
    main()
