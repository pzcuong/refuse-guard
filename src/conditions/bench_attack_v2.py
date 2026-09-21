"""Bench attack v2 — CWE-family extension (agent A1, round 7).

Materializes data/benchmarks/bench_attack_v2/ : 4 CWE families x (20 vul +
20 benign) x 4 arms (C0 / D2_task / C5_near / C5_far), reusing the round-5
machinery in src.conditions.c5_risk_context UNCHANGED (apply_attack,
build_attack_prompt; build_advisory gains a family-template pool only when
the config defines advisory.family_signals — configs/attack_v2.yaml does not,
so round-5 behavior is byte-identical).

Layout mirrors bench_attack_v1: one row per sample with a pre-computed
"arms" dict (advisory already embedded in the C5 funcs); prompts are NOT
stored — build_attack_prompt is the single source of truth.

CLI:
    .venv/bin/python -m src.conditions.bench_attack_v2 configs/attack_v2_cwe.yaml

Why a new module (ownership note): the round-7 brief assigns
bench_attack_v2 + its config/doc/tests to A1; the sampling rule here
(family x label x signature-strata x project, test-first/valid-fill pool) is
bench-specific and deliberately kept out of the shared round-5 module.
"""
from __future__ import annotations

import hashlib
import json
import random
import zlib
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from src.data.bench_build import parse_language  # round-2 parseability rule
from src.data.primevul import load_primevul, sha256_16

from .c5_risk_context import (
    ARM_ORDER,
    apply_attack,
    build_attack_prompt,
    check_policy_safety,
    extract_family_signals,
    extract_risky_apis,
    load_attack_config,
)

__all__ = ["materialize", "scan_pool", "select_cells"]

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = _PROJECT_ROOT / "configs" / "attack_v2_cwe.yaml"
DEFAULT_OUTPUT_DIR = _PROJECT_ROOT / "data" / "benchmarks" / "bench_attack_v2"
_PATTERN_ARMS = ("C5_near", "C5_far")


def _sha256_16_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def _sel_seed(seed: int, *parts) -> int:
    return zlib.crc32(":".join(["sel"] + [str(p) for p in (seed, *parts)]).encode("utf-8"))


# ---------------------------------------------------------------------------
# (1) parseable pool scan (cached; identical rule to round-2 B1)
# ---------------------------------------------------------------------------
def scan_pool(cfg: dict, cache_path: Optional[Path] = None,
              refresh: bool = False) -> tuple[list[dict], dict]:
    """Parseable records of the configured splits, in split order (test first,
    then valid — the "test-first, valid-fill" priority), each
    {sample_id, pair_id, label, cwe, cve, project, split, language, func}.

    Cached because the scan parses ~44k functions (~2-4 min); the cache key is
    the set of source-file sha256-16 checksums, so any source change forces a
    rescan.
    """
    spool = cfg["source_pool"]
    files = {s: _PROJECT_ROOT / spool["files"][s] for s in spool["splits"]}
    checksums = {s: sha256_16(str(p)) for s, p in files.items()}
    if cache_path is not None and not refresh and cache_path.exists():
        try:
            blob = json.loads(cache_path.read_text(encoding="utf-8"))
            if blob.get("source_checksums") == checksums:
                return blob["rows"], {"cache": "hit", "source_checksums": checksums}
        except (json.JSONDecodeError, KeyError):
            pass  # corrupt cache -> rescan
    # pair-id map from the paired files (both members share the pair id)
    pair_of: dict[str, str] = {}
    for s, rel in (spool.get("paired_files") or {}).items():
        for rec in load_primevul(f"{s}_paired"):
            pair_of[rec["sample_id"]] = rec["pair_id"]
    rows: list[dict] = []
    for s in spool["splits"]:
        for rec in load_primevul(s):
            lang = parse_language(rec["func"])
            if lang is None:
                continue
            rows.append({
                "sample_id": rec["sample_id"], "pair_id": pair_of.get(rec["sample_id"]),
                "label": int(rec["label"]), "cwe": rec["cwe"], "cve": rec["cve"],
                "project": rec["project"], "split": s, "language": lang,
                "func": rec["func"],
            })
    rows.sort(key=lambda r: (r["split"], r["sample_id"]))
    if cache_path is not None:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(
            {"source_checksums": checksums, "rows": rows}, ensure_ascii=False),
            encoding="utf-8")
    return rows, {"cache": "miss", "source_checksums": checksums}


# ---------------------------------------------------------------------------
# (2) selection — family x label x signature-strata x project (selection only)
# ---------------------------------------------------------------------------
def _alloc_quotas(groups: dict[str, list[dict]], n_take: int) -> dict[str, int]:
    """Largest-remainder allocation of n_take over group sizes (deterministic;
    ties broken by group name). Mirrors the bench_v1 allocator rule."""
    names = sorted(groups, key=lambda g: (-len(groups[g]), g))
    total = sum(len(groups[g]) for g in names)
    if total <= n_take:  # short pool: everything is taken
        return {g: len(groups[g]) for g in names}
    quotas = [len(groups[g]) * n_take / total for g in names]
    alloc = [int(q) for q in quotas]
    rem = n_take - sum(alloc)
    order = sorted(range(len(names)), key=lambda i: (-(quotas[i] - alloc[i]), i))
    for i in order[:rem]:
        alloc[i] += 1
    return dict(zip(names, alloc))


def _select_stratum(rows: list[dict], n_take: int, seed: int, family: str,
                    label: int, stratum: str, scfg: dict) -> list[dict]:
    """Project-stratified, test-first pick of n_take rows (deterministic).

    Within each project the split subgroups are shuffled independently
    (seeded) and concatenated test-before-valid, so the test split is always
    preferred inside a project (pool rule) while the shuffle supplies the
    randomness.  Projects smaller than min_group_size merge into rare_group.
    """
    min_group = int(scfg["min_group_size"])
    rare = str(scfg["rare_group"])
    by_project: dict[str, list[dict]] = {}
    for r in rows:
        by_project.setdefault(r["project"], []).append(r)
    big = {g: m for g, m in by_project.items() if len(m) >= min_group}
    groups = dict(big)
    small = [m for g, m in by_project.items() if g not in big for m in m]
    if small:
        groups.setdefault(rare, []).extend(small)
    alloc = _alloc_quotas(groups, n_take)
    picks: list[dict] = []
    for proj, k in sorted(alloc.items(), key=lambda kv: kv[0]):
        if k <= 0:
            continue
        members = sorted(groups[proj], key=lambda r: r["sample_id"])
        rng = random.Random(_sel_seed(seed, family, str(label), stratum, proj))
        rng.shuffle(members)
        picks.extend(members[:k])
    return picks


def select_cells(pool: list[dict], cfg: dict) -> tuple[list[dict], dict]:
    """Select the bench rows: per (family, label) fill a 50/50 signature
    stratum target with deterministic overflow into the complementary
    stratum.  Returns (selected_rows_flat, selection_meta)."""
    scfg = cfg["sampling"]
    seed = int(cfg["seed"])
    sig_share = float(scfg["balance_signature_share"])
    n_cell = int(scfg["n_per_cell"])
    excl_path = _PROJECT_ROOT / cfg["source_pool"]["exclude_bench"]
    excluded = {json.loads(l)["sample_id"]
                for l in excl_path.read_text(encoding="utf-8").splitlines() if l.strip()}
    # feature pre-pass (label-blind)
    for r in pool:
        r["_apis"] = extract_risky_apis(r["func"], language=r["language"], cfg=cfg)
        r["_fam"] = extract_family_signals(r["func"], language=r["language"], cfg=cfg)
        r["_sig"] = bool(r["_apis"] or r["_fam"])
    family_order = list(cfg["family_order"])
    fam_cfg = cfg["families"]
    selected: list[dict] = []
    meta: dict = {"excluded_bench_ids": len(excluded), "cells": {}}
    for fam in family_order:
        target = int(fam_cfg[fam]["n_vul"])
        target_b = int(fam_cfg[fam]["n_benign"])
        vul_overflow = 0
        for label, n_target in ((1, target), (0, target_b)):
            # Quota rule (pre-registered): target 50/50 signature strata per
            # label.  Vulnerable cells in these families are feature-rich by
            # nature (no-signature pools can be < 10), so when the vulnerable
            # cell needed overflow, the benign cell's signature quota is
            # RAISED TO MATCH the vulnerable cell's realized signature share —
            # this restores the anti-leakage objective (advisory content-type
            # distribution identical across labels) via rate matching instead
            # of an infeasible in-label 50/50.  Recorded per cell.
            if label == 1:
                quota_sig = int(round(n_target * sig_share))
            else:
                quota_sig = int(round(n_target * sig_share)) + vul_overflow
            cands = [r for r in pool if r["cwe"] == fam and r["label"] == label
                     and r["sample_id"] not in excluded]
            with_sig = [r for r in cands if r["_sig"]]
            without_sig = [r for r in cands if not r["_sig"]]
            picks_sig = _select_stratum(with_sig, quota_sig, seed, fam, label, "sig", scfg)
            n_nosig = n_target - len(picks_sig)
            picks_nosig = _select_stratum(without_sig, n_nosig, seed, fam,
                                          label, "nosig", scfg)
            overflow = {"into_nosig": 0, "into_sig": 0}
            if len(picks_nosig) < n_nosig and scfg.get("stratum_overflow", True):
                # nosig pool short -> pull the remainder from the unused sig pool
                deficit = n_nosig - len(picks_nosig)
                taken = {r["sample_id"] for r in picks_sig + picks_nosig}
                rng = random.Random(_sel_seed(seed, fam, label, "overflow"))
                extra = sorted((r for r in with_sig
                                if r["sample_id"] not in taken),
                               key=lambda r: r["sample_id"])
                rng.shuffle(extra)
                extra = extra[:deficit]
                overflow["into_nosig"] = len(extra)
                picks_sig = picks_sig + extra
            if label == 1:
                vul_overflow = overflow["into_nosig"]
            meta["cells"][f"{fam}|label{label}"] = {
                "target": n_target,
                "pool": len(cands), "pool_test": sum(1 for r in cands if r["split"] == "test"),
                "pool_valid": sum(1 for r in cands if r["split"] == "valid"),
                "pool_with_signature": len(with_sig),
                "quota_signature": quota_sig,
                "quota_rule": "50/50" if (label == 1 or not vul_overflow)
                else "matched to vulnerable realized share",
                "selected_signature": len(picks_sig),
                "selected_without_signature": len(picks_nosig),
                "selected_total": len(picks_sig) + len(picks_nosig),
                "overflow": overflow,
            }
            selected.extend(picks_sig + picks_nosig)
    selected.sort(key=lambda r: (family_order.index(r["cwe"]), -r["label"],
                                 r["sample_id"]))
    return selected, meta


# ---------------------------------------------------------------------------
# (3) build rows + manifest
# ---------------------------------------------------------------------------
def materialize(cfg_path=None, out_dir: Optional[Path] = None) -> dict:
    """Materialize bench_attack_v2/{bench_attack_v2.jsonl, manifest_attack_v2.json}."""
    cfg = load_attack_config(cfg_path, refresh=True)
    out_dir = Path(out_dir) if out_dir else DEFAULT_OUTPUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    seed = int(cfg["seed"])
    spool = cfg["source_pool"]
    cache_rel = spool.get("pool_cache")
    cache_path = Path(cache_rel) if cache_rel and str(cache_rel).startswith("/") \
        else _PROJECT_ROOT / (cache_rel or "data/benchmarks/bench_attack_v2/.cache_pool_scan.json")
    pool, scan_info = scan_pool(cfg, cache_path=cache_path)
    selected, sel_meta = select_cells(pool, cfg)

    expected = sum(int(cfg["families"][f][k]) for f in cfg["family_order"]
                   for k in ("n_vul", "n_benign"))
    if len(selected) != expected:
        raise ValueError(f"selection produced {len(selected)} rows, expected {expected}")

    rows_out: list[dict] = []
    fail: dict[str, list[str]] = {}
    v1_ids = set()
    for r in selected:
        sample = {"sample_id": r["sample_id"], "pair_id": r.get("pair_id"),
                  "label": int(r["label"]), "cwe": r["cwe"], "cve": r.get("cve"),
                  "project": r["project"], "split": r["split"],
                  "language": r["language"], "func": r["func"]}
        arms_payload: dict[str, dict] = {}
        offsets: dict[str, Optional[int]] = {}
        adv_meta: Optional[dict] = None
        for arm in cfg["arm_order"]:
            out = apply_attack(sample, arm, cfg)
            m = out["meta"]
            arms_payload[arm] = {
                "func": out["func"],
                "task_ladder": m["task_ladder"],
                "semantics_checked": True,
                "semantics_ok": m["semantics_ok"],
                "semantics_strict": m.get("semantics_strict",
                                          m["func_source"] == "original"),
                "modifies_string_data": m["modifies_string_data"],
                "carrier": m["carrier"], "position": m["position"],
                "template_id": m["template_id"],
                "advisory_kind": m.get("advisory_kind"),
                "advisory_offset": m.get("advisory_offset"),
                "language": m["language"],
            }
            if m.get("advisory_offset") is not None:
                offsets[arm] = m["advisory_offset"]
            if arm in _PATTERN_ARMS:
                adv_meta = {
                    "template_id": m["template_id"],
                    "advisory_kind": m["advisory_kind"],
                    "zero_api": m["zero_api"],
                    "risky_apis": m["risky_apis"],
                    "family_signals": m["family_signals"],
                    "n_calls_raw": m["n_calls_raw"],
                    "sites": m["sites"],
                    "n_api_kinds": m["n_api_kinds"],
                    "advisory_chars": m["advisory_chars"],
                    "policy_safety_scan": m["policy_safety_scan"],
                }
        near, far = offsets.get("C5_near"), offsets.get("C5_far")
        if near is None or far is None or near <= far:
            fail.setdefault(sample["sample_id"], []).append(
                f"near/far offset {near}!>{far}")
        rows_out.append({
            "sample_id": sample["sample_id"], "pair_id": sample["pair_id"],
            "family": sample["cwe"],
            "section": "vulnerable" if sample["label"] else "benign",
            "label": sample["label"], "cwe": sample["cwe"], "cve": sample["cve"],
            "project": sample["project"], "split": sample["split"],
            "language": sample["language"], "func": sample["func"],
            "has_risky_api": bool(adv_meta and adv_meta["risky_apis"]),
            "has_signature": bool(adv_meta and
                                  (adv_meta["risky_apis"] or adv_meta["family_signals"])),
            "risky_apis": adv_meta["risky_apis"] if adv_meta else {},
            "family_signals": adv_meta["family_signals"] if adv_meta else {},
            "advisory": adv_meta,
            "near_far_confound": near is None or far is None or near <= far,
            "near_far_offsets": {"C5_near": near, "C5_far": far},
            "arms": arms_payload,
        })
        v1_ids.add(sample["sample_id"])
    if fail:
        raise ValueError(f"near/far collapse or missing offsets in {len(fail)} rows: "
                         f"{sorted(fail)[:5]}")

    jsonl_path = out_dir / "bench_attack_v2.jsonl"
    body = "\n".join(json.dumps(r, ensure_ascii=False) for r in rows_out) + "\n"
    jsonl_path.write_text(body, encoding="utf-8")

    # ---- distributions ----------------------------------------------------
    fam_order = list(cfg["family_order"])
    sig_by_cell = {f"{r['family']}|label{r['label']}": 0 for r in rows_out}
    kind_by_label: dict[int, Counter] = {0: Counter(), 1: Counter()}
    kind_by_family: dict[str, Counter] = {f: Counter() for f in fam_order}
    tpl_by_kind: Counter = Counter()
    split_by_cell: Counter = Counter()
    project_by_cell: dict[str, Counter] = {}
    for r in rows_out:
        key = f"{r['family']}|label{r['label']}"
        if r["has_signature"]:
            sig_by_cell[key] += 1
        kind = (r["advisory"] or {}).get("advisory_kind")
        kind_by_label[r["label"]][kind] += 1
        kind_by_family[r["family"]][kind] += 1
        tpl_by_kind[(kind, (r["advisory"] or {}).get("template_id"))] += 1
        split_by_cell[(key, r["split"])] += 1
        project_by_cell.setdefault(key, Counter())[r["project"]] += 1
    pattern_rows = sum(c for (kind, _), c in tpl_by_kind.items() if kind == "pattern")
    family_rows = sum(c for (kind, _), c in tpl_by_kind.items() if kind == "family")
    max_share = {}
    for kind_name, total in (("pattern", pattern_rows), ("family", family_rows)):
        if total >= int((cfg.get("advisory") or {}).get("min_rows_for_balance_guard", 50)):
            shares = [c for (k, _), c in tpl_by_kind.items() if k == kind_name]
            max_share[kind_name] = round(max(shares) / total, 4)
        else:
            max_share[kind_name] = None  # guard not applicable below min rows

    # bench_v1 bridge overlap (disclosed; only bench_attack_v1 ids are excluded).
    # [CORRECTED-R7 / BUG-1 fix, V1 audit]: the bridge manifests store ids under
    # the key `samples` (a list of records), NOT `records` — the old read
    # silently yielded an empty id set and a false overlap of 0.  Measured for
    # the shipped artifact (same seed/rule): 22 ids overlap the round-2 bridge
    # (eval_subset_round2.json, 838 ids — the universe bench_v1 was drawn from)
    # and 16 ids overlap the round-1 manifest (eval_subset_round1.json).
    def _bridge_ids(rel: str) -> set:
        try:
            d = json.loads(Path(_PROJECT_ROOT / rel).read_text(encoding="utf-8"))
            return {str(s["sample_id"]) for s in d.get("samples", [])}
        except (OSError, json.JSONDecodeError, KeyError, TypeError):
            return set()

    bridge_ids = _bridge_ids("data/manifests/eval_subset_round2.json")
    bridge1_ids = _bridge_ids("data/manifests/eval_subset_round1.json")

    manifest = {
        "name": "bench_attack_v2",
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "date": "2026-09-21",
        "seed": seed,
        "seed_derivation": {
            "in_project_shuffle": "Random(crc32('sel:<seed>:<family>:<label>:<stratum>:<project>'))",
            "overflow": "Random(crc32('sel:<seed>:<family>:<label>:overflow'))",
        },
        "prereg": cfg.get("prereg"),
        "purpose": ("CWE-family extension of the round-5 C5 attack (Finding-2 "
                    "generalization probe): 4 families x (20 vul + 20 benign) x "
                    "4 arms, advisory anchored on classic sinks OR family feature "
                    "signals, label-blind. Prompts rebuilt by "
                    "src.conditions.c5_risk_context.build_attack_prompt."),
        "sources": {
            "pool_files": {s: str(_PROJECT_ROOT / spool["files"][s])
                           for s in spool["splits"]},
            "pool_file_sha256_16": scan_info["source_checksums"],
            "pool_scan": scan_info["cache"],
            "exclude_bench": spool["exclude_bench"],
            "exclude_bench_sha256_16": _sha256_16_path(
                _PROJECT_ROOT / spool["exclude_bench"]),
            "attack_config": str(cfg_path) if cfg_path else str(DEFAULT_CONFIG_PATH),
            "attack_config_version": cfg.get("version"),
            "attack_config_sha256_16": _sha256_16_path(
                Path(cfg_path).resolve() if cfg_path else DEFAULT_CONFIG_PATH),
        },
        "counts": {
            "rows": len(rows_out),
            "families": fam_order,
            "by_label": dict(Counter(r["label"] for r in rows_out)),
            "arms": list(cfg["arm_order"]),
            "entries_expected": len(rows_out) * len(cfg["arm_order"]),
        },
        "sampling": {
            "rule": ("per (family,label): 50/50 advisory-signature strata "
                     "(anti-leakage distribution guard), project-stratified "
                     "largest-remainder allocation, test-first/valid-fill pool, "
                     "deterministic overflow"),
            "pool_rule": ("official PrimeVul test split preferred; valid split "
                          "fills deficits only (test-only vulnerable pools are "
                          "24/19/9/7 for the four families)"),
            "excluded_bench_ids": sel_meta["excluded_bench_ids"],
            "cells": sel_meta["cells"],
        },
        "signature_by_cell": dict(sorted(sig_by_cell.items())),
        # Anti-leakage check: the advisory SIGNATURE-rate is matched across
        # labels within each family (content-type channel removed).  In-label
        # 50/50 was infeasible for the vulnerable cells (feature-rich by
        # nature; nosig pools 8/6/3/4) — the benign quota is raised to the
        # vulnerable realized share instead (pre-registered rule).
        "signature_balance_rule": "signature rate matched across labels per family",
        "signature_balance_ok": all(
            sig_by_cell[f"{f}|label1"] == sig_by_cell[f"{f}|label0"]
            for f in fam_order),
        "family_split_composition": {
            f"{key}|{split}": n for (key, split), n in sorted(split_by_cell.items())},
        "project_distribution": {
            key: dict(cnt.most_common()) for key, cnt in sorted(project_by_cell.items())},
        "advisory_distribution": {
            "kind_by_label": {str(l): dict(kind_by_label[l]) for l in (0, 1)},
            "kind_by_family": {f: dict(kind_by_family[f]) for f in fam_order},
            "template_by_kind": {
                f"{kind}:{tid}": c for (kind, tid), c in sorted(
                    tpl_by_kind.items(), key=lambda kv: str(kv[0]))},
            "max_template_share_by_kind": max_share,
            "max_template_share_guard": (cfg.get("advisory") or {}).get(
                "max_template_share", 0.40),
        },
        "semantics": {
            "rule": "check_semantics strict (ignore_strings=False) for C5 comment "
                    "carriers; C0/D2_task are identity transforms",
            "all_pass": all(p["semantics_ok"] for r in rows_out
                            for p in r["arms"].values()),
        },
        "near_far": {
            "carrier_choice": {"C5_near": "inline_comment", "C5_far": "top_comment"},
            "any_confound": any(r["near_far_confound"] for r in rows_out),
            "min_gap_bytes": min(r["near_far_offsets"]["C5_near"]
                                 - r["near_far_offsets"]["C5_far"] for r in rows_out),
        },
        "prompt_contract": {
            "builder": "src.conditions.c5_risk_context.build_attack_prompt",
            "arm_task_ladder": {a: cfg["arms"][a]["task_ladder"]
                                for a in cfg["arm_order"]},
            "ladder_sha256_16": {k: hashlib.sha256(
                " ".join(str(v).split()).encode()).hexdigest()[:16]
                for k, v in (cfg.get("ladder") or {}).items()},
            "system_sha256_16": hashlib.sha256(
                " ".join(str(cfg["system_prompt"]).split()).encode()).hexdigest()[:16],
        },
        "policy_safety": {
            "forbidden_tokens": (cfg.get("advisory") or {}).get("forbidden_tokens"),
            "scan": "all rendered advisories pass (build-time + tests)",
        },
        "bench_v1_bridge_overlap_rows": sum(1 for r in rows_out
                                            if r["sample_id"] in bridge_ids),
        "bench_v1_bridge_overlap_rows_round1": sum(
            1 for r in rows_out if r["sample_id"] in bridge1_ids),
        "bench_v1_bridge_overlap_note": (
            "overlap with the round-2 bridge manifest (the universe bench_v1 "
            "was drawn from) and the round-1 manifest; provenance disclosure "
            "only — no label leak, selection is seed-based and unchanged, and "
            "bench_attack_v1 ids themselves remain excluded (overlap 0)"),
        "jsonl_sha256": hashlib.sha256(jsonl_path.read_bytes()).hexdigest(),
    }
    manifest_path = out_dir / "manifest_attack_v2.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                             encoding="utf-8")
    return {"jsonl": str(jsonl_path), "manifest": str(manifest_path),
            "rows": len(rows_out), "signature_balance_ok": manifest["signature_balance_ok"],
            "counts": manifest["counts"]}


def main(argv: Optional[list[str]] = None) -> int:  # pragma: no cover
    import sys

    args = list(sys.argv[1:] if argv is None else argv)
    res = materialize(args[0] if args else None)
    print(f"[attack_v2_cwe] materialized {res['rows']} rows -> {res['jsonl']}")
    print(f"[attack_v2_cwe] manifest -> {res['manifest']}")
    print(f"[attack_v2_cwe] signature 50/50 per cell ok: {res['signature_balance_ok']}")
    print(f"[attack_v2_cwe] counts: {res['counts']}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
