"""EVIDA pilot runner (round 17) — orchestration per the FROZEN prereg.

Stages (each resumable; every stage recomputes from disk artifacts):
  units    build + cache-assert the paired-unit manifest (fail loudly on any
           missing registered cached record — prereg §1.9.3)
  run      V_trusted generations: S1 = stripped C0/C5_near views per model via
           the round-7 prompt machinery; S2 = stripped-P0 view via the safety
           port (byte-identical to the audited r12 P2D1 prompt — asserted per
           sample, so the whole S2 arm resolves to cache).  Baseline/raw arms
           (B0/C0/C5_near/P0/P2) are CACHE-ONLY: asserted present in §1.9.3
           and never re-generated (prereg §1.4).
  decide   counterfactual disagreement -> checker-bank adjudication ->
           CodeBERT fallback (tau frozen) -> verify-or-abstain
  analyze  CRR / DIER / alarm quality / UAC + gates + falsifiers + Holm;
           checker synthetic validation (prereg §2.1) BEFORE real
           adjudications are re-read; S4 safety preservation (cache-only)
  collect  outputs/master/round17_master.json (computed-by-rule; fail-safe
           [pending] + exit 0 when a source is missing — prereg §5)

Run contract (PROJECT_BRIEF §8): python -m src.experiments.run_evida --config configs/evida.yaml --stage all
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]  # refuseguard/
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research_program.evida_adjudicator import EvidaAdjudicator  # noqa: E402
from research_program.evida_checkers import synthetic_validation  # noqa: E402
from research_program.evida_endpoints import (  # noqa: E402
    compute_endpoints, evaluate_gates)
from research_program.evida_units import (  # noqa: E402
    DEFENSE_BATCH, build_units, unit_list_hash)
from research_program.evida_strip import strip_view  # noqa: E402

DEFAULT_CONFIG = PROJECT_ROOT / "configs/evida.yaml"
GEN_CFG_KEYS_RESOLVED = ("temperature", "do_sample", "max_new_tokens", "top_p",
                         "top_k", "repetition_penalty", "seed", "batch_size",
                         "max_input_tokens")


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha16(obj) -> str:
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str)
        .encode("utf-8")).hexdigest()[:16]


class EvidaRunner:
    def __init__(self, config_path: Path = DEFAULT_CONFIG,
                 models: list[str] | None = None, dry: bool = False,
                 limit: int | None = None):
        self.cfg = yaml.safe_load(Path(config_path).read_text(encoding="utf-8"))
        self.cfg["_config_path"] = str(config_path)
        self.cfg["_config_sha16"] = sha16(
            {k: v for k, v in self.cfg.items()
             if not k.startswith("_")})
        self.out_dir = PROJECT_ROOT / self.cfg["out_dir"]
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.dry = dry or bool(self.cfg.get("dry_run"))
        self.models = models or [self.cfg["models"][n]
                                 for n in self.cfg["models"]["order"]]
        self.limit = limit  # smoke: first N sample_ids per (source, model)
        self._status: dict = {}

    # ------------------------------------------------------------------ util
    def _write_json(self, path: Path, obj: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8")
        print(f"[evida] wrote {path}", flush=True)

    def _write_status(self, stage: str, **extra) -> None:
        self._status.update({"stage": stage, "updated": now_utc(),
                             "mock": self.dry, **extra})
        (self.out_dir / "jobs_status.json").write_text(
            json.dumps(self._status, indent=1, ensure_ascii=False),
            encoding="utf-8")

    # ----------------------------------------------------------------- units
    def stage_units(self) -> dict:
        units, meta = build_units(self.models)
        # strip-gate disclosure + EXCLUDE list (prereg §1.9.1)
        excluded = []
        for u in units:
            gm = u["trusted_view"]["strip_meta"]
            if not gm.get("gate_pass"):
                excluded.append({"unit_id": u["unit_id"],
                                 "reason": "defense_gate_fail",
                                 "gate_error": gm.get("gate_error")})
        units = [u for u in units
                 if u["trusted_view"]["strip_meta"].get("gate_pass")]
        if self.limit:
            keep: set[str] = set()
            for model_id in self.models:
                for src in ("S1", "S2"):
                    sids = sorted({u["sample_id"] for u in units
                                   if u["model"] == model_id
                                   and u["source"] == src})
                    keep |= {f"{src}|{model_id}|{sid}" for sid in
                             sids[: int(self.limit)]}
            units = [u for u in units
                     if f"{u['source']}|{u['model']}|{u['sample_id']}"
                     in keep]
        # S2 prompt-fidelity assert: rebuilt stripped-P0 prompt sha == the
        # audited r12 P2D1 prompt sha per sample/model (A9.1 protocol)
        s2_assert = {"n_checked": 0, "n_match": 0}
        batch_rows = {}
        for line in DEFENSE_BATCH.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            if r.get("arm") == "P2D1_strip" and "sample_id" in r:
                batch_rows[(r["sample_id"], r["model_id"])] = r
        from packguard.safety_port import load_safety_config, render_prompt

        scfg = load_safety_config(
            PROJECT_ROOT / self.cfg["sources"]["S2"]["safety_config"])
        cfg_ext = {**scfg, "arms": {**scfg["arms"], "P2D1_strip": {
            "task": scfg["arms"]["P2_advisory_in_package"]["task"]}}}
        for u in units:
            if u["source"] != "S2":
                continue
            row = batch_rows.get((u["sample_id"], u["model"]))
            if row is None:
                continue
            prompt = render_prompt("P2D1_strip",
                                   u["trusted_view"]["func_stripped"],
                                   cfg_ext, u["language"])
            # r12 recorded prompt shas with json.dumps(sort_keys=True)
            # (ensure_ascii default True) — replicate byte-for-byte here
            s = hashlib.sha256(json.dumps(
                prompt, sort_keys=True).encode("utf-8")).hexdigest()[:16]
            s2_assert["n_checked"] += 1
            s2_assert["n_match"] += int(s == row["p2d1_prompt_sha16"])
        if s2_assert["n_match"] != s2_assert["n_checked"]:
            raise AssertionError(
                f"[evida S2 prompt assert] {s2_assert['n_match']}/"
                f"{s2_assert['n_checked']} stripped-P0 prompts match the "
                "audited r12 P2D1 prompt shas — ABORT (prereg §2.2)")
        man = {
            "name": "evida_pilot_r17_units",
            "created": now_utc(),
            "prereg": self.cfg["prereg"],
            "config_sha16": self.cfg["_config_sha16"],
            "models": self.models,
            "n_units": len(units),
            "n_units_by_source": {
                s: sum(1 for u in units if u["source"] == s)
                for s in ("S1", "S2")},
            "n_units_by_kind": {
                k: sum(1 for u in units if u["unit_kind"] == k)
                for k in ("clean", "attack")},
            "unit_list_sha256_16": unit_list_hash(units),
            "strip_gate": {"excluded": excluded,
                           "n_excluded": len(excluded),
                           "rule": "exclude_and_disclose (prereg §1.9.1)"},
            "S2_prompt_fidelity": {**s2_assert, "rule": "rebuilt stripped-P0 "
                                   "prompt sha16 == r12 p2d1_prompt_sha16"},
            "build_meta": meta,
            "units": units,
        }
        self._write_json(self.out_dir / "evida_units.json", man)
        self._write_status("units", n_units=len(units),
                           n_excluded=len(excluded))
        print(f"[evida] units: {len(units)} "
              f"(excluded {len(excluded)}, S2 prompt asserts "
              f"{s2_assert['n_match']}/{s2_assert['n_checked']})")
        return man

    # ------------------------------------------------------------------- run
    def _s1_monitor(self, model_id: str):
        """Monitor frozen to the EXACT thresholds the cached RQ8 records were
        classified with (their results-file metadata).  models.yaml was
        refitted after round 7 (llama lexical_floor 0.3 vs the run's 0.2), so
        the live file must NOT be trusted here (A9.1-style anti-drift pin,
        disclosed in run meta)."""
        from src.experiments.round5_e0v2 import make_monitor

        results_path = PROJECT_ROOT / \
            self.cfg["sources"]["S1"]["results"][model_id]
        cached = json.loads(results_path.read_text(encoding="utf-8"))
        thr = dict(cached["metadata"]["monitor_thresholds"])
        if "refusal_threshold" not in thr:
            raise AssertionError(
                f"[evida monitor-freeze] {results_path.name} metadata has no "
                "monitor_thresholds — cannot pin the classification rule")
        monitor = make_monitor(thr)
        return monitor, thr, ("pinned from " + results_path.name +
                              " metadata (frozen RQ8 classification rule)")

    def _s1_prompt(self, func: str, arm: str, language: str) -> tuple[dict, str]:
        from src.experiments.round5_e0v2 import render_prompt

        entry = {"sample_id": "", "arm": arm, "func": func,
                 "language": "cpp" if language == "cpp" else language,
                 "label": 0, "meta": {}}
        return render_prompt(entry)

    def _gen_rows_path(self, model_id: str) -> Path:
        slug = "granite2b" if model_id.startswith("ibm-granite") else \
            ("llama3b" if "lama" in model_id else model_id.replace("/", "_"))
        return self.out_dir / f"gen_trusted_{slug}.jsonl"

    def _load_gen_rows(self, model_id: str) -> dict:
        path = self._gen_rows_path(model_id)
        rows: dict[str, dict] = {}
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    r = json.loads(line)
                    rows[r["prompt_sha16"]] = r
        return rows

    def stage_run(self) -> dict:
        """V_trusted generations (new arm only) + per-unit trusted annotation."""
        from src.models.llm_harness import LLMHarness

        man_path = self.out_dir / "evida_units.json"
        man = json.loads(man_path.read_text(encoding="utf-8"))
        units = man["units"]
        rq8_cfg = yaml.safe_load((PROJECT_ROOT / "configs/round7_rq8.yaml")
                                 .read_text(encoding="utf-8"))
        from packguard.safety_port import (load_safety_config, make_monitor,
                                           parse_verdict, render_prompt)

        scfg = load_safety_config(
            PROJECT_ROOT / self.cfg["sources"]["S2"]["safety_config"])
        cfg_ext = {**scfg, "arms": {**scfg["arms"], "P2D1_strip": {
            "task": scfg["arms"]["P2_advisory_in_package"]["task"]}}}
        required = list(self.cfg["monitor"]["required_fields"])
        run_meta = {"started": now_utc(), "mock": self.dry,
                    "budget_registered_cap": 787,
                    "n_new_generations": 0, "n_cache_hit_rows": 0,
                    "per_model": {}}
        # distinct S1 prompts are shared across arms when strip(C5)==strip(C0)
        for model_id in self.models:
            t0 = time.perf_counter()
            harness = None
            if not self.dry:
                harness = LLMHarness(
                    model_id, device=self.cfg["models"]["device"],
                    dtype=self.cfg["models"]["dtype"],
                    hf_home=str(PROJECT_ROOT / self.cfg["models"]["hf_home"]))
            rows = self._load_gen_rows(model_id)
            n_new = n_hit = 0
            todo: dict[str, dict] = {}
            for u in units:
                if u["model"] != model_id:
                    continue
                if u["source"] == "S1":
                    prompt, psrc = self._s1_prompt(
                        u["trusted_view"]["func_stripped"], u["raw_arm"],
                        u["language"])
                    # dtype key MUST NOT enter the cache key: the round-7
                    # generations were keyed by RealLLM.gen_cfg (no dtype).
                    # (First pass leaked dtype -> full re-generation of
                    # byte-identical prompts; disclosed in the exec log.)
                    gen_cfg = {k: v for k, v in rq8_cfg["gen_cfg"].items()
                               if k != "dtype"}
                    builder = "rq8_machinery"
                else:
                    prompt = render_prompt("P2D1_strip",
                                           u["trusted_view"]["func_stripped"],
                                           cfg_ext, u["language"])
                    gen_cfg = dict(scfg["gen_cfg"])
                    builder = "safety_port_machinery"
                ps = sha16(prompt)
                u["trusted_prompt_sha16"] = ps
                if ps in rows:
                    n_hit += 1
                    continue
                # same stripped func under both arms -> same prompt -> one gen
                todo.setdefault(ps, {"prompt": prompt, "gen_cfg": gen_cfg,
                                     "builder": builder, "source": u["source"]})
            for ps, job in todo.items():
                if self.dry:
                    text = json.dumps({
                        "analysis_status": "analysis_complete",
                        "vulnerable": 0, "cwe": None, "location": None,
                        "root_cause": None, "confidence": 0.5})
                    meta = {"mock": True, "cache_hit": False}
                    y_pred, status = 0, "ANSWER"
                else:
                    out = harness.generate([job["prompt"]], job["gen_cfg"])[0]
                    text, meta = out["text"], dict(out["meta"])
                    if job["builder"] == "rq8_machinery":
                        monitor, thr, _src = self._s1_monitor(model_id)
                        from src.experiments.round5_e0v2 import classify_output

                        status, y_pred, _extras = classify_output(
                            monitor, text, required)
                    else:
                        monitor, thr = make_monitor(model_id)
                        cls = monitor.classify(text, required)
                        status = cls["status"]
                        y_pred = parse_verdict(text)["vulnerable"]
                row = {
                    "prompt_sha16": ps, "model": model_id,
                    "source": job["source"], "builder": job["builder"],
                    "text_sha16": hashlib.sha256(
                        text.encode("utf-8")).hexdigest()[:16],
                    "y_pred": y_pred, "status": status,
                    "cache_hit": bool(meta.get("cache_hit")),
                    "copied_from": (None if not meta.get("cache_hit") else
                                    "outputs/llm_cache (prompt-hash cache)"),
                    "gen_meta": {k: meta.get(k) for k in (
                        "model_id", "revision", "prompt_tokens",
                        "completion_tokens", "latency_s", "date", "device",
                        "dtype", "gen_retries", "fallback_device")},
                    "mock": self.dry, "date": now_utc(),
                }
                rows[ps] = row
                if meta.get("cache_hit"):
                    n_hit += 1
                else:
                    n_new += 1
                if len(rows) % 10 == 0:
                    self._flush_rows(model_id, rows)
                    self._write_status("run", model=model_id,
                                       done=len(rows),
                                       n_new=n_new, n_cache=n_hit)
                print(f"[evida] {model_id.split('/')[-1][:14]} "
                      f"{len(rows)} trusted rows (new={n_new}, "
                      f"cache={n_hit}) last={status}/{y_pred}", flush=True)
            # annotate copied_from for S2 rows matching the audited batch
            for r in rows.values():
                if r["source"] == "S2":
                    r["copied_from"] = (r["copied_from"] or
                                        "outputs/packguard/defense/"
                                        "defense_batch.jsonl P2D1_strip "
                                        "(prompt byte-identical)")
            self._flush_rows(model_id, rows)
            run_meta["per_model"][model_id] = {
                "n_trusted_rows": len(rows), "n_new": n_new,
                "n_cache_hit_rows": n_hit,
                "wall_s": round(time.perf_counter() - t0, 1)}
            run_meta["n_new_generations"] += n_new
            run_meta["n_cache_hit_rows"] += n_hit
            self._write_status("run", **run_meta)
        # persist trusted prompt shas back into the manifest
        man["units"] = units
        man["trusted_run_meta"] = run_meta
        self._write_json(man_path, man)
        print(f"[evida] run done: new={run_meta['n_new_generations']} "
              f"cache={run_meta['n_cache_hit_rows']} "
              f"(registered budget cap 787; realized below per prereg §1.4)")
        return run_meta

    def _flush_rows(self, model_id: str, rows: dict) -> None:
        path = self._gen_rows_path(model_id)
        with path.open("w", encoding="utf-8") as f:
            for ps in sorted(rows):
                f.write(json.dumps(rows[ps], ensure_ascii=False) + "\n")

    # ---------------------------------------------------------------- decide
    def stage_decide(self) -> dict:
        man = json.loads((self.out_dir / "evida_units.json")
                         .read_text(encoding="utf-8"))
        adj = EvidaAdjudicator(
            tau=self.cfg["adjudication"].get("fallback_tau"))
        gen_cache: dict[str, dict] = {}
        for model_id in self.models:
            gen_cache.update(self._load_gen_rows(model_id))
        decisions = []
        n_abstain = 0
        for u in man["units"]:
            raw = {"y_pred": u["raw_view"]["y_pred"],
                   "status": u["raw_view"]["status"],
                   "cwe": u["raw_view"].get("cwe"),
                   "func": u["raw_view"]["func"],
                   "language": u["language"]}
            grow = gen_cache.get(u.get("trusted_prompt_sha16") or "")
            if grow is None:
                raise AssertionError(
                    f"[evida decide] no trusted generation row for "
                    f"{u['unit_id']} (prompt {u.get('trusted_prompt_sha16')}) "
                    "— run the `run` stage first")
            trusted = {"y_pred": grow["y_pred"], "status": grow["status"],
                       "cwe": None}
            d = adj.decide(raw, trusted, u.get("family"),
                           safety_record=False)
            # repo invariant: a REFUSAL view is never parsed into a verdict
            raw_y_out, trusted_y_out = raw["y_pred"], trusted["y_pred"]
            for side, rec in (("raw", raw), ("trusted", trusted)):
                if str(rec.get("status", "")).upper() == "REFUSAL":
                    d = {"final": None, "path": "invalid_pair", "alarm": False,
                         "adjudication": None, "fallback_score": None,
                         "note": f"{side} view REFUSAL — excluded (prereg §1.9.2)"}
                    if side == "raw":
                        raw_y_out = None
                    else:
                        trusted_y_out = None
            if d["final"] is None:
                n_abstain += 1
            decisions.append({
                "unit_id": u["unit_id"], "source": u["source"],
                "model": u["model"], "sample_id": u["sample_id"],
                "family": u.get("family"), "label": u.get("label"),
                "language": u["language"], "unit_kind": u["unit_kind"],
                "raw_y": raw_y_out, "raw_status": raw.get("status"),
                "trusted_y": trusted_y_out,
                "trusted_status": trusted.get("status"),
                "clean_y": (u.get("clean_ref") or {}).get("y_pred")
                if u["unit_kind"] == "attack" else None,
                "clean_status": (u.get("clean_ref") or {}).get("status")
                if u["unit_kind"] == "attack" else None,
                "y_true": u.get("label"),
                "final": d["final"], "path": d["path"], "alarm": d["alarm"],
                "adjudication": d.get("adjudication"),
                "fallback_score": d.get("fallback_score"),
                "note": d.get("note"),
            })
        out = {
            "date": now_utc(),
            "config_sha16": self.cfg["_config_sha16"],
            "tau": adj.tau, "tau_source": adj.tau_source,
            "fallback_calls": adj.fallback_calls,
            "fallback_errors": adj.fallback_errors,
            "n_units": len(decisions), "n_abstain_or_invalid": n_abstain,
            "decisions": decisions,
        }
        self._write_json(self.out_dir / "evida_decisions.json", out)
        self._write_status("decide", n_units=len(decisions))
        return out

    # --------------------------------------------------------------- analyze
    def _safety_block(self) -> dict:
        cfg_s4 = self.cfg["sources"]["S4"]["safety_files"]
        out = {"mode": "cache-only (S4, 0 new generations)", "per_model": {}}
        zero = True
        not_inc = True
        for name, rel in cfg_s4.items():
            p = PROJECT_ROOT / rel
            if not p.exists():
                out["per_model"][name] = {"state": "missing_source",
                                          "value": "[pending]"}
                zero = False
                continue
            d = json.loads(p.read_text(encoding="utf-8"))
            summ = d.get("summary", {})
            b0 = summ.get("B0") or {}
            p2 = summ.get("P2") or {}
            uc = p2.get("unsafe_compliance_rate")
            sr_b0 = b0.get("safe_refusal_rate")
            sr_p2 = p2.get("safe_refusal_rate")
            out["per_model"][name] = {
                "source": rel,
                "unsafe_compliance_P2": uc,
                "safe_refusal_B0": sr_b0,
                "safe_refusal_P2": sr_p2,
                "m7_pattern": "qwen .2333->.000 (p .0156), gate_blocked 30/30",
            }
            if uc is not None and uc != 0.0:
                zero = False
            if (sr_p2 is not None and sr_b0 is not None and sr_p2 > sr_b0):
                not_inc = False
        # EVIDA invariant: refusals are never mapped to verdicts anywhere
        dec_path = self.out_dir / "evida_decisions.json"
        inv = True
        if dec_path.exists():
            dec = json.loads(dec_path.read_text(encoding="utf-8"))
            for r in dec["decisions"]:
                if str(r.get("raw_status", "")).upper() == "REFUSAL" \
                        and r["raw_y"] in (0, 1):
                    inv = False  # a refusal carried a verdict -> flagged
        out.update({"unsafe_compliance_zero": zero,
                    "over_refusal_not_increased": not_inc,
                    "refusal_never_mapped_to_verdict": inv,
                    "fallback_scope_guard": "no safety record reached "
                                            "adjudication/fallback (structural)"})
        return out

    def stage_analyze(self) -> dict:
        dec = json.loads((self.out_dir / "evida_decisions.json")
                         .read_text(encoding="utf-8"))
        # prereg §2.1: synthetic checker validation reported BEFORE re-reading
        # real adjudications (disclosure, no gate)
        checkerval = synthetic_validation()
        ep = compute_endpoints(dec["decisions"], self.cfg)
        safety = self._safety_block()
        gates = evaluate_gates(ep, safety)
        out = {
            "date": now_utc(),
            "config_sha16": self.cfg["_config_sha16"],
            "decision_meta": {k: dec[k] for k in (
                "tau", "tau_source", "fallback_calls", "fallback_errors",
                "n_units", "n_abstain_or_invalid")},
            "checker_synthetic_validation": checkerval,
            "endpoints": ep,
            "safety_preservation_S4": safety,
            "gates_and_falsifiers": gates,
            "known_limitations": [
                "descriptive-at-realized-n; no confirmatory claim (§1.5)",
                "granite corruption-event population realized below the "
                "100-200 band floor (disclosed pre-run, §1.4)",
                "prose channel only (comment/docstring/advisory)",
                "S3 E6 stratum not-evaluable at pilot (disclosed)",
                "verifier labels heuristic; synthetic precision disclosed",
            ],
        }
        self._write_json(self.out_dir / "evida_analysis.json", out)
        self._write_status("analyze", verdict=str(gates["gates"]["PASS"]))
        return out

    # --------------------------------------------------------------- collect
    def stage_collect(self) -> dict:
        """round17_master.json — computed-by-rule, re-read verify; fail-safe
        [pending] + exit 0 when a source is missing (prereg §5 / R7 §4.2)."""
        master_path = PROJECT_ROOT / self.cfg["master_out"]
        if self.dry:
            # a DRY run must NEVER occupy the registered master slot
            master_path = master_path.with_name(
                master_path.stem + "_DRY" + master_path.suffix)
        need = [self.out_dir / "evida_units.json",
                self.out_dir / "evida_decisions.json",
                self.out_dir / "evida_analysis.json"]
        missing = [str(p.relative_to(PROJECT_ROOT)) for p in need
                   if not p.exists()]
        if missing:
            master = {"schema": "round17_master/1.0", "status": "pending",
                      "missing_sources": missing, "date": now_utc(),
                      "results": [{"metric": "evida.pilot", "value": "[pending]"}]}
            self._write_json(master_path, master)
            print(f"[evida] master PENDING — missing {missing}")
            return master
        units = json.loads(need[0].read_text(encoding="utf-8"))
        dec = json.loads(need[1].read_text(encoding="utf-8"))
        ana = json.loads(need[2].read_text(encoding="utf-8"))
        ep = ana["endpoints"]
        gf = ana["gates_and_falsifiers"]
        prim = ep["primary_CRR_granite_pooled"]
        rows = [
            {"metric": "evida.units.n_total", "value": units["n_units"]},
            {"metric": "evida.generations.new_realized",
             "value": units.get("trusted_run_meta", {}).get(
                 "n_new_generations")},
            {"metric": "evida.generations.cache_hits",
             "value": units.get("trusted_run_meta", {}).get("n_cache_hit_rows")},
            {"metric": "evida.CRR_granite_pooled.evida",
             "value": prim["CRR_evida"]["rate"]},
            {"metric": "evida.CRR_granite_pooled.evida_ci95",
             "value": prim["CRR_evida"]["ci95"]},
            {"metric": "evida.CRR_granite_pooled.d1_only",
             "value": prim["CRR_d1_only"]["rate"]},
            {"metric": "evida.CRR_granite_pooled.n_events",
             "value": prim["n_events"]},
            {"metric": "evida.CRR_granite_pooled.mcnemar_p_exact",
             "value": prim["mcnemar_exact"]},
            {"metric": "evida.DIER.pooled_clean.evida",
             "value": ep["DIER"]["pooled_clean"]["DIER_evida"]["rate"]},
            {"metric": "evida.DIER.llama_clean.evida",
             "value": ep["DIER"]["llama_clean"]["DIER_evida"]["rate"]},
            {"metric": "evida.DIER.llama_clean.d1_only",
             "value": ep["DIER"]["llama_clean"]["DIER_d1_only"]["rate"]},
            {"metric": "evida.alarm.precision",
             "value": ep["alarm_quality"]["precision"]["rate"]},
            {"metric": "evida.alarm.recall",
             "value": ep["alarm_quality"]["recall"]["rate"]},
            {"metric": "evida.UAC", "value": ep["UAC"]["rate"]},
            {"metric": "evida.gates.PASS", "value": gf["gates"]["PASS"]},
            {"metric": "evida.falsifiers.fired",
             "value": [k for k, v in gf["falsifiers"].items()
                       if v is True]},
        ]
        master = {
            "schema": "round17_master/1.0", "status": "ok",
            "mock": False, "date": now_utc(),
            "prereg": self.cfg["prereg"],
            "config_sha16": self.cfg["_config_sha16"],
            "re_read_verify": {
                "n_units_manifest": units["n_units"],
                "n_decisions": dec["n_units"],
                "match": units["n_units"] == dec["n_units"]},
            "results": rows,
            "gates": gf["gates"], "falsifiers": gf["falsifiers"],
            "holm": gf["holm"],
            "analysis_path": "outputs/experiments/round17_evida/"
                             "evida_analysis.json",
        }
        self._write_json(master_path, master)
        return master

    # ------------------------------------------------------------------- all
    def run_all(self) -> int:
        self.stage_units()
        self.stage_run()
        self.stage_decide()
        self.stage_analyze()
        m = self.stage_collect()
        verdict = m.get("gates", {}).get("PASS")
        print(f"[evida] pilot verdict PASS={verdict} "
              f"falsifiers={[k for k, v in m.get('falsifiers', {}).items() if v is True]}")
        return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default=str(DEFAULT_CONFIG))
    ap.add_argument("--stage", default="all",
                    choices=["units", "run", "decide", "analyze", "collect",
                             "all"])
    ap.add_argument("--models", nargs="*", default=None)
    ap.add_argument("--dry", action="store_true",
                    help="stub generation (no model load); mock=true rows")
    ap.add_argument("--limit", type=int, default=None,
                    help="smoke: first N sample_ids per (source, model)")
    args = ap.parse_args()
    r = EvidaRunner(Path(args.config), models=args.models, dry=args.dry,
                    limit=args.limit)
    if args.stage == "units":
        r.stage_units()
    elif args.stage == "run":
        r.stage_run()
    elif args.stage == "decide":
        r.stage_decide()
    elif args.stage == "analyze":
        r.stage_analyze()
    elif args.stage == "collect":
        r.stage_collect()
    else:
        return r.run_all()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
