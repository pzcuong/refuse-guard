#!/usr/bin/env python
"""Round-18 EVIDA-2 runner (AMENDMENT-11, docs/packguard_prereg.md).

Stages (resumable; every stage recomputes from disk):
  units    registered draw (first-N per family x label, sha-asserted bench)
           -> outputs/packguard/evida2/evida2_units.json
  run      V_raw + V_strip generations per model via the PackGuard
           safety-port prompt frame + D1 strip views; append-only JSONL,
           resume by prompt_sha16; clause-1 byte-identical reuse (never
           regenerated)
  decide   PRUNE-1 + frozen adjudicator -> evida2_decisions.json
  analyze  registered endpoints + gates -> evida2_analysis.json
           (refuses to gate on mock rows)

Contract: .venv/bin/python scripts/r18_run_evida2.py --stage all
           [--per-stratum 10] [--phase raw|strip|all] [--dry] [--limit N]
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import yaml  # noqa: E402

from packguard import evida2  # noqa: E402
from packguard.safety_port import (  # noqa: E402
    load_safety_config, make_monitor, parse_verdict, render_prompt)

CFG_PATH = PROJECT_ROOT / "configs/packguard_evida2.yaml"


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def slug(model_id: str) -> str:
    return "granite2b" if model_id.startswith("ibm-granite") else \
        ("llama3b" if "lama" in model_id else model_id.replace("/", "_"))


class Runner:
    def __init__(self, per_stratum: int | None, dry: bool, limit: int | None):
        self.cfg = yaml.safe_load(CFG_PATH.read_text(encoding="utf-8"))
        self.out = PROJECT_ROOT / self.cfg["out_dir"]
        self.out.mkdir(parents=True, exist_ok=True)
        self.per_stratum = per_stratum or int(self.cfg["bench"]["per_stratum"])
        self.dry = dry or bool(self.cfg.get("mock"))
        self.limit = limit
        self.models = [self.cfg["models"][k]
                       for k in self.cfg["models"]["order"]]
        self.safety_cfg = load_safety_config(
            PROJECT_ROOT / self.cfg["safety_config"])
        self.gen_cfg = {k: v for k, v in self.safety_cfg["gen_cfg"].items()
                        if k != "dtype"}
        self.required = list(self.safety_cfg["monitor"]["required_fields"])
        self._status_data: dict = {}

    # ------------------------------------------------------------------ util
    def _status(self, stage: str, **extra) -> None:
        self._status_data.update({"stage": stage, "updated": now_utc(),
                                  "mock": self.dry, **extra})
        (self.out / "jobs_status.json").write_text(
            json.dumps(self._status_data, indent=1, ensure_ascii=False),
            encoding="utf-8")

    def _write_json(self, name: str, obj: dict) -> Path:
        p = self.out / name
        p.write_text(json.dumps(obj, indent=1, ensure_ascii=False) + "\n",
                     encoding="utf-8")
        print(f"[evida2] wrote {p}", flush=True)
        return p

    # ---------------------------------------------------------------- stages
    def stage_units(self) -> dict:
        rows = evida2.load_bench_rows()
        per = self.per_stratum
        samples = evida2.draw_samples(rows, per_stratum=per)
        if self.limit:
            samples = samples[: self.limit]
        units, meta = evida2.build_units(samples, self.models, self.safety_cfg)
        man = {
            "name": "evida2_r18_units",
            "created": now_utc(), "mock": self.dry,
            "prereg": self.cfg["prereg"], "rule": self.cfg["rule"],
            "bench_sha16": self.cfg["bench"]["sha256_16"],
            "per_stratum": per,
            "models": self.models,
            "n_samples": len(samples),
            "sample_ids": sorted(s["sample_id"] for s in samples),
            "n_units": len(units),
            "unit_meta": meta,
            "units": units,
        }
        self._write_json("evida2_units.json", man)
        self._status("units", n_units=len(units), n_samples=len(samples),
                     n_excluded=meta["n_excluded"])
        return man

    # ------------------------------------------------------------------- run
    def _gen_rows_path(self, model_id: str) -> Path:
        return self.out / f"gen_{slug(model_id)}.jsonl"

    def _load_gen_rows(self, model_id: str) -> dict:
        rows: dict[str, dict] = {}
        p = self._gen_rows_path(model_id)
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    r = json.loads(line)
                    rows[r["prompt_sha16"]] = r
        return rows

    def _gen_one(self, model_id: str, prompt: dict) -> dict:
        """One generation (or mock); classify with the safety-port monitor."""
        from src.models.llm_harness import LLMHarness

        harness = getattr(self, "_harness", None)
        if harness is None or harness.model_id != model_id:
            harness = LLMHarness(
                model_id, device=self.cfg["models"]["device"],
                dtype=self.cfg["models"]["dtype"],
                hf_home=str(PROJECT_ROOT / self.cfg["models"]["hf_home"]))
            self._harness = harness
        t0 = time.perf_counter()
        out = harness.generate([prompt], self.gen_cfg)[0]
        text, meta = out["text"], dict(out.get("meta") or {})
        monitor, thr = make_monitor(model_id)
        cls = monitor.classify(text, required_fields=self.required)
        verdict = parse_verdict(text)
        return {
            "prompt_sha16": evida2.sha16(prompt),
            "model": model_id, "text": text,
            "status": cls["status"],
            "refusal_score": cls["refusal_score"],
            "lexical_score": cls["lexical_score"],
            "vulnerable": verdict["vulnerable"],
            "parsed": verdict["parsed"],
            "monitor_fallback": thr["fallback"],
            "latency_s": round(time.perf_counter() - t0, 2),
            "gen_meta": {k: meta.get(k) for k in
                         ("prompt_tokens", "completion_tokens", "total_tokens",
                          "elapsed_s", "cached")},
            "mock": self.dry, "date": now_utc(),
        }

    def _mock_one(self, model_id: str, prompt: dict, tag: str) -> dict:
        """Deterministic MOCK generation (smoke only; never gated)."""
        blob = int(evida2.sha16({"p": prompt, "tag": tag})[:8], 16)
        vuln = 1 if (blob % 100) < 45 else 0
        text = json.dumps({"analysis_status": "analysis_complete",
                           "vulnerable": vuln,
                           "cwe": f"CWE-{190 + 10 * (blob % 4)}" if vuln else None,
                           "location": "mock", "root_cause": "mock",
                           "confidence": 0.5})
        return {
            "prompt_sha16": evida2.sha16(prompt), "model": model_id,
            "text": text, "status": "ANSWER", "refusal_score": 0.0,
            "lexical_score": 0.0, "vulnerable": vuln,
            "parsed": {"analysis_status": "analysis_complete",
                       "vulnerable": vuln, "cwe": text and json.loads(text)["cwe"],
                       "location": "mock"},
            "monitor_fallback": True, "latency_s": 0.0, "gen_meta": {},
            "mock": True, "date": now_utc(),
        }

    def stage_run(self, phase: str = "all") -> dict:
        """phase: raw (V_raw only) | strip (V_strip only) | all."""
        man = json.loads((self.out / "evida2_units.json")
                         .read_text(encoding="utf-8"))
        units = man["units"]
        run_meta = {"started": man.get("run_started", now_utc()),
                    "mock": self.dry, "phase": phase,
                    "n_new_generations": 0, "n_reused_clause1": 0,
                    "n_prompt_rows": 0, "per_model": {}}
        man["run_started"] = run_meta["started"]
        for model_id in self.models:
            units_m = [u for u in units if u["model"] == model_id]
            rows = self._load_gen_rows(model_id)
            jobs: list[tuple[str, dict, dict]] = []
            n_reuse = 0
            for u in units_m:
                if phase in ("all", "raw"):
                    ps = u["raw_view"]["prompt_sha16"]
                    if ps not in rows:
                        jobs.append((ps, u["raw_view"]["prompt"],
                                     {"unit": u["unit_id"], "view": "raw"}))
                if phase in ("all", "strip"):
                    if u["strip_view"]["reuse_raw_verdict"]:
                        n_reuse += 1
                        continue
                    ps = u["strip_view"]["prompt_sha16"]
                    if ps not in rows:
                        jobs.append((ps, u["strip_view"]["prompt"],
                                     {"unit": u["unit_id"], "view": "strip"}))
            t0 = time.perf_counter()
            path = self._gen_rows_path(model_id)
            n_new = 0
            seen: set[str] = set()
            with path.open("a", encoding="utf-8") as f:
                for i, (ps, prompt, tag) in enumerate(jobs):
                    if ps in seen:
                        continue  # same prompt shared across units (M4
                        # precedent: strip(C5)==strip(C0) -> one generation)
                    seen.add(ps)
                    rec = (self._mock_one(model_id, prompt, tag["view"])
                           if self.dry else self._gen_one(model_id, prompt))
                    assert rec["prompt_sha16"] == ps, "prompt sha drift"
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    f.flush()
                    rows[ps] = rec
                    n_new += 1
                    if n_new % 10 == 0:
                        rate = n_new / max(1e-9, time.perf_counter() - t0)
                        self._status("run", model=model_id, phase=phase,
                                     n_new=n_new, n_jobs=len(jobs),
                                     gens_per_s=round(rate, 3),
                                     eta_min=round((len(jobs) - n_new)
                                                   / max(rate, 1e-9) / 60, 1))
                        print(f"[evida2] {slug(model_id)} {phase}: "
                              f"{n_new}/{len(jobs)} "
                              f"({rate:.2f} gen/s, eta "
                              f"{(len(jobs) - n_new) / max(rate, 1e-9) / 60:.0f}"
                              " min)", flush=True)
            self._harness = None  # free MPS memory between models
            elapsed = round(time.perf_counter() - t0, 1)
            run_meta["per_model"][slug(model_id)] = {
                "phase": phase, "n_new": n_new, "n_jobs": len(jobs),
                "n_clause1_reuse": n_reuse, "elapsed_s": elapsed,
                "gens_per_s": round(n_new / max(elapsed, 1e-9), 3)}
            run_meta["n_new_generations"] += n_new
            run_meta["n_reused_clause1"] += n_reuse
            print(f"[evida2] {slug(model_id)} {phase} done: {n_new} new, "
                  f"{n_reuse} clause-1 reuse, {elapsed:.0f}s", flush=True)
        self._write_json("run_meta.json", run_meta)
        self._status("run_done", phase=phase,
                     n_new=run_meta["n_new_generations"])
        return run_meta

    # ---------------------------------------------------------------- decide
    def stage_decide(self) -> dict:
        from research_program.evida_adjudicator import EvidaAdjudicator

        man = json.loads((self.out / "evida2_units.json")
                         .read_text(encoding="utf-8"))
        units = man["units"]
        adj = EvidaAdjudicator(
            threshold_path=PROJECT_ROOT / self.cfg["adjudicator"]
            ["fallback_threshold"])
        rows_cache: dict[str, dict] = {}
        decisions = []
        for u in units:
            if u["model"] not in rows_cache:
                rows_cache[u["model"]] = self._load_gen_rows(u["model"])
            rows = rows_cache[u["model"]]
            raw = rows.get(u["raw_view"]["prompt_sha16"])
            if raw is None:
                raise AssertionError(
                    f"missing raw generation for {u['unit_id']} - ABORT")
            if u["strip_view"]["reuse_raw_verdict"]:
                strip = raw
            else:
                strip = rows.get(u["strip_view"]["prompt_sha16"])
                if strip is None:
                    raise AssertionError(
                        f"missing strip generation for {u['unit_id']} - ABORT")
            decisions.append(evida2.decide_unit(u, raw, strip, adj))
        out = {
            "created": now_utc(), "mock": self.dry,
            "rule": evida2.PRUNE_SPEC, "config": self.cfg_path_sha(),
            "n_units": len(decisions),
            "fallback_calls": adj.fallback_calls,
            "fallback_errors": adj.fallback_errors,
            "decisions": decisions,
        }
        self._write_json("evida2_decisions.json", out)
        self._status("decide", n_units=len(decisions))
        return out

    def cfg_path_sha(self) -> str:
        return evida2.sha16(yaml.safe_load(
            CFG_PATH.read_text(encoding="utf-8")))

    # --------------------------------------------------------------- analyze
    def stage_analyze(self) -> dict:
        dec = json.loads((self.out / "evida2_decisions.json")
                         .read_text(encoding="utf-8"))
        if dec.get("mock"):
            print("[evida2] MOCK decisions - endpoints computed for smoke "
                  "only, flagged mock:true; gates NOT evaluable", flush=True)
        ep = evida2.compute_endpoints_v2(dec["decisions"])
        gates = evida2.evaluate_gates_v2(ep)
        analysis = {
            "created": now_utc(), "mock": dec.get("mock", False),
            "rule": evida2.PRUNE_SPEC,
            "prereg": "docs/packguard_prereg.md#AMENDMENT-11",
            "endpoints": ep, "gates": gates,
            "r17_comparators": evida2.R17_COMPARATORS,
            "honesty_note": (
                "Rule designed on the r17 alarm log (post-hoc w.r.t. r17, "
                "pre-registered w.r.t. this run, AMENDMENT-11); pruning does "
                "NOT mechanically repair CRR - declared AT RISK before the "
                "run; verdict computed-by-rule, both directions reported."),
        }
        self._write_json("evida2_analysis.json", analysis)
        self._status("analyze", PASS=gates["PASS"])
        print(json.dumps(gates, indent=1), flush=True)
        return analysis


def main() -> int:
    ap = argparse.ArgumentParser(description="EVIDA-2 round-18 runner")
    ap.add_argument("--stage", default="all",
                    choices=["units", "run", "decide", "analyze", "all"])
    ap.add_argument("--phase", default="all", choices=["raw", "strip", "all"])
    ap.add_argument("--per-stratum", type=int, default=None)
    ap.add_argument("--limit", type=int, default=None,
                    help="smoke: first N samples of the draw")
    ap.add_argument("--dry", action="store_true",
                    help="deterministic MOCK generations (smoke only)")
    args = ap.parse_args()

    r = Runner(per_stratum=args.per_stratum, dry=args.dry, limit=args.limit)
    stages = (["units", "run", "decide", "analyze"]
              if args.stage == "all" else [args.stage])
    for st in stages:
        print(f"[evida2] === stage {st} (phase={args.phase}) ===", flush=True)
        if st == "units":
            r.stage_units()
        elif st == "run":
            r.stage_run(args.phase)
        elif st == "decide":
            r.stage_decide()
        elif st == "analyze":
            r.stage_analyze()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
