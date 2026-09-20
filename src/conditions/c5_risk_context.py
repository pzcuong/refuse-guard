"""Attack V2 — C5 query-relevant risk context + wording ladder (agent A1, round 5).

Mechanism-faithful implementation of the "blocking" attack family:
  * C5 risk context (TabooRAG-analog, arXiv:2603.03919): an advisory text is
    generated FROM THE FUNCTION'S OWN OBSERVABLE FEATURES (risky-sink call
    sites extracted by AST) and embedded as a comment near/far from the code.
    The advisory is pure threat-intel/CVE-style prose (risk-descriptive,
    instruction-free) — never derived from the ground-truth label, so benign
    and vulnerable functions receive the same KIND of context (anti-leakage).
  * C1-v2 wording ladder (Defensive Refusal Bias, arXiv:2603.01246; Beyond
    Refusal, arXiv:2607.05842): D0 neutral / D1 authorization / D2
    security-dense, applied at the TASK-PROMPT layer only.

Canonical interfaces (owner: A1; used by A2's round5_e0v2 runner and A3's P3):
    build_attack_prompt(sample=None, arm="C0", cfg=None, func=None,
                        language=None) -> {"system", "user", "meta"}
        SINGLE SOURCE OF TRUTH for round-5 prompts — same (func, arm) always
        yields byte-identical prompts so LLM-cache keys stay deduplicated.
    apply_attack(sample, arm, cfg) -> {"func", "meta"}
    check_semantics(func_original, func_transformed)  (re-exported, unchanged)

CLI (materialize bench_attack_v1):
    .venv/bin/python -m src.conditions.c5_risk_context configs/attack_v2.yaml
"""
from __future__ import annotations

import hashlib
import json
import random
import re
import zlib
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

from .parser_utils import (  # noqa: F401 (canonical re-export)
    body_node,
    check_semantics,
    find_function,
    indent_of,
    iter_nodes,
    parse,
    resolve_language,
)

__all__ = [
    "apply_attack",
    "build_advisory",
    "build_attack_prompt",
    "extract_risky_apis",
    "load_attack_config",
    "materialize",
    "check_semantics",
    "ARM_ORDER",
]

ARM_ORDER = ("C0", "D2_task", "C5_near", "C5_far")
_PATTERN_ARMS = ("C5_near", "C5_far")
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = _PROJECT_ROOT / "configs" / "attack_v2.yaml"
DEFAULT_OUTPUT_DIR = _PROJECT_ROOT / "data" / "benchmarks" / "bench_attack_v1"
_PROMPT_TAIL = "Report your finding as the required JSON object and nothing else."

_CONFIG_CACHE: dict[str, dict] = {}


def load_attack_config(path=None, refresh: bool = False) -> dict:
    """Load (and memoize) the attack-v2 YAML. Deterministic content."""
    p = Path(path) if path else DEFAULT_CONFIG_PATH
    key = str(p.resolve())
    if refresh or key not in _CONFIG_CACHE:
        with open(p, "r", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        if not isinstance(cfg, dict):
            raise ValueError(f"attack_v2 config must be a mapping: {p}")
        missing = [a for a in ARM_ORDER if a not in (cfg.get("arms") or {})]
        if missing:
            raise ValueError(f"attack_v2 config missing arms: {missing}")
        _CONFIG_CACHE[key] = cfg
    return _CONFIG_CACHE[key]


def _rng(seed: int, *parts: str) -> random.Random:
    return random.Random(zlib.crc32(":".join([str(seed), *parts]).encode("utf-8")))


# ---------------------------------------------------------------------------
# (a) feature extraction — the ONLY input to advisory construction
# ---------------------------------------------------------------------------
def extract_risky_apis(func: str, language: str = "c", cfg: Optional[dict] = None,
                       auto: bool = True) -> dict[str, int]:
    """Count risky-sink call sites in `func` via the tree-sitter AST.

    Returns {api_name: raw_count} sorted by (-count, name).  A call is counted
    when the call_expression's callee is exactly the sink identifier (member
    calls like `x->strcpy` are NOT counted — conservative by design).

    Falls back to a word-boundary regex on `name(` if the code does not parse
    (bench_attack_v1 sources are all parseable; the fallback only exists so the
    function is total).  Label-blind by construction: the signature has no
    label parameter.
    """
    cfg = cfg or load_attack_config()
    apis = list((cfg.get("advisory") or {}).get("apis") or {})
    if not apis:
        return {}
    counts: Counter = Counter()
    from .parser_utils import parse

    tree = parse(func, language, auto=auto) if auto else None
    if tree is not None and not tree.root_node.has_error:
        for node in iter_nodes(tree.root_node):
            if node.type != "call_expression":
                continue
            callee = node.child_by_field_name("function")
            if callee is None or callee.type != "identifier":
                continue
            name = callee.text.decode("utf-8", "replace")
            if name in apis:
                counts[name] += 1
    else:  # regex fallback (documented; not used for bench_attack_v1 rows)
        for api in apis:
            counts[api] = len(re.findall(rf"\b{re.escape(api)}\s*\(", func))
    return {k: counts[k] for k in sorted(counts, key=lambda a: (-counts[a], a)) if counts[k]}


def _sites_phrase(raw: int, cap: int) -> str:
    """Normalized (label-blind) call-site phrase — '3+ call sites' for any raw >= cap."""
    if raw >= cap:
        return f"{cap}+ call sites"
    return f"{raw} call site" + ("" if raw == 1 else "s")


def _render(template_text: str, primary: str, classes: dict[str, str],
            apis: dict[str, int], cap: int) -> str:
    n_kinds = len(apis)
    api_list = ", ".join(list(apis)[:3])
    return template_text.format(
        api_primary=primary,
        class_primary=classes.get(primary, "unsafe sink usage"),
        api_list=api_list,
        n_api_kinds=n_kinds,
        sites=_sites_phrase(apis[primary], cap) if primary in apis else "0 call sites",
    )


# ---------------------------------------------------------------------------
# (b) advisory construction (query-relevant, instruction-free, label-blind)
# ---------------------------------------------------------------------------
def build_advisory(func: str, template_id: Optional[str] = None,
                   cfg: Optional[dict] = None, language: str = "c",
                   sample_id: str = "") -> dict:
    """Build the C5 advisory for one function.

    The template is selected by a seeded draw on (config.seed, sample_id) —
    NEVER by the label.  Content is anchored on the function's own risky-sink
    profile; counts are capped (advisory.count_cap) so advisory intensity is a
    bounded function of observable features.

    Returns {"text", "template_id", "zero_api", "risky_apis", "n_calls_raw",
             "sites", "n_api_kinds"}.
    """
    cfg = cfg or load_attack_config()
    acfg = cfg.get("advisory") or {}
    cap = int(acfg.get("count_cap", 3))
    apis = extract_risky_apis(func, language=language, cfg=cfg)
    seed = int(cfg.get("seed", 0))
    if apis:
        pool = acfg.get("pattern_templates") or []
        fallback_kind = "pattern"
    else:
        pool = acfg.get("zero_api_templates") or []
        fallback_kind = "zero_api"
    if not pool:
        raise ValueError("attack_v2 config: advisory templates missing")
    if template_id is None:
        rng = _rng(seed, str(sample_id), "C5-advisory")
        template_id = pool[rng.randrange(len(pool))]["id"]
    tpl = next((t for t in pool if t["id"] == template_id), None)
    if tpl is None:  # cross-pool pin (e.g. caller forces a specific id)
        all_t = (acfg.get("pattern_templates") or []) + (acfg.get("zero_api_templates") or [])
        tpl = next((t for t in all_t if t["id"] == template_id), None)
    if tpl is None:
        raise ValueError(f"unknown advisory template_id: {template_id!r}")
    primary = next(iter(apis), "")
    text = " ".join(_render(tpl["text"], primary, acfg.get("apis") or {},
                            apis, cap).split())
    return {
        "text": text,
        "template_id": tpl["id"],
        "zero_api": fallback_kind == "zero_api",
        "risky_apis": apis,
        "n_calls_raw": int(apis[primary]) if apis else 0,
        "sites": _sites_phrase(apis[primary], cap) if apis else "0 call sites",
        "n_api_kinds": len(apis),
    }


def check_policy_safety(advisory_text: str, cfg: Optional[dict] = None) -> list[str]:
    """Scan rendered advisory text for forbidden tokens (policy-safety +
    anti-instruction).  Returns the list of violations (empty == pass)."""
    cfg = cfg or load_attack_config()
    forbidden = list((cfg.get("advisory") or {}).get("forbidden_tokens") or [])
    low = advisory_text.lower()
    return [tok for tok in forbidden if tok.lower() in low]


# ---------------------------------------------------------------------------
# advisory comment injection (self-contained; deliberately NOT reusing
# carriers.inject_carrier: that implementation assumes the opening brace ends
# its line, so a `//` comment inserted after `{` would swallow the remainder
# of a K&R-style line like `{ x; y; }` — the semantics gate correctly rejects
# such transforms.  Here the comment always lands on its own line.)
# ---------------------------------------------------------------------------
def _inject_advisory(func: str, text: str, position: str,
                     language: str) -> tuple[str, str]:
    """Insert the advisory as a comment; returns (new_func, actual_carrier).

    position="near": comment line directly after the opening brace of the
    first function body (closest to the executable code).
    position="far":  block comment at the very top of the file (offset 0).
    Raises ValueError when the code does not parse or no function body exists.
    """
    text = " ".join(text.split())
    if position == "far":
        block = f"/* {text.replace('*/', '* /')} */\n"
        return func[:0] + block + func[0:], "top_comment"

    tree = parse(func, language)
    if tree is None or tree.root_node.has_error:
        raise ValueError("cannot parse function for advisory injection")
    fn = find_function(tree)
    body = body_node(fn) if fn else None
    if body is None or not body.children or body.children[0].type != "{":
        raise ValueError("cannot locate opening brace for near advisory")
    open_brace = body.children[0]
    at = open_brace.end_byte
    indent = indent_of(func, body.start_byte) + "    "
    line_end = func.find("\n", at)
    rest = func[at:(line_end if line_end != -1 else len(func))]
    block = f"// {text}"
    if rest.strip():
        # same-line body (K&R): give the comment its own line, then restore
        # the original line content on the next line at the same indent.
        new = func[:at] + f"\n{indent}{block}\n{indent}" + func[at:]
    else:
        new = func[:at] + f"\n{indent}{block}" + func[at:]
    return new, "inline_comment"


# ---------------------------------------------------------------------------
# (c) arm application (every transform passes the semantics gate)
# ---------------------------------------------------------------------------
def apply_attack(sample: dict, arm: str, cfg: Optional[dict] = None) -> dict:
    """Apply attack arm {C0, D2_task, C5_near, C5_far} to a PrimeVul-style sample.

    Returns {"func": str, "meta": dict}.  Never mutates `sample`.  C0 and
    D2_task leave the code untouched (their manipulation is prompt-level);
    C5_near/C5_far embed the advisory as a comment (strict check_semantics).
    """
    cfg = cfg or load_attack_config()
    arm = str(arm)
    if arm not in ARM_ORDER:
        raise ValueError(f"unknown arm {arm!r}; expected one of {ARM_ORDER}")
    func = sample["func"]
    language = sample.get("language") or resolve_language(func, "c")
    arm_cfg = cfg["arms"][arm]
    common = {
        "arm": arm,
        "task_ladder": arm_cfg["task_ladder"],
        "language": language,
        "sample_id": sample.get("sample_id"),
        "label": sample.get("label"),
        "config_version": cfg.get("version"),
        "seed": int(cfg.get("seed", 0)),
    }
    if arm in ("C0", "D2_task"):
        meta = dict(common)
        meta.update({"func_source": "original", "carrier": None, "position": None,
                     "template_id": None, "advisory_offset": None,
                     "semantics_ok": True, "semantics_checked": True,
                     "modifies_string_data": False})
        return {"func": func, "meta": meta}

    # C5 arms: advisory as comment carrier (query-relevant risk context)
    adv = build_advisory(func, cfg=cfg, language=language,
                         sample_id=str(sample.get("sample_id", "")))
    violations = check_policy_safety(adv["text"], cfg)
    if violations:
        raise ValueError(f"advisory failed policy-safety scan: {violations}")
    carrier = arm_cfg["carrier"]
    position = arm_cfg["position"]
    new_func, actual = _inject_advisory(func, adv["text"], position, language)
    if not check_semantics(func, new_func, language=language, ignore_strings=False):
        raise ValueError(
            f"semantics gate failed for arm={arm} sample_id={sample.get('sample_id', '?')}")
    marker = adv["text"][:24]
    offset = new_func.find(marker)
    if offset < 0:
        raise ValueError("advisory text not found after injection")
    meta = dict(common)
    meta.update({
        "func_source": "advisory", "carrier": actual, "requested_carrier": carrier,
        "position": position, "template_id": adv["template_id"],
        "zero_api": adv["zero_api"], "risky_apis": adv["risky_apis"],
        "n_calls_raw": adv["n_calls_raw"], "sites": adv["sites"],
        "n_api_kinds": adv["n_api_kinds"], "advisory_chars": len(adv["text"]),
        "advisory_offset": offset, "policy_safety_scan": "pass",
        "semantics_ok": True, "semantics_checked": True, "semantics_strict": True,
        "modifies_string_data": False,
    })
    return {"func": new_func, "meta": meta}


# ---------------------------------------------------------------------------
# (d) SINGLE SOURCE OF TRUTH for round-5 prompts
# ---------------------------------------------------------------------------
def build_attack_prompt(sample: Optional[dict] = None, arm: str = "C0",
                        cfg: Optional[dict] = None, func: Optional[str] = None,
                        language: Optional[str] = None, **_) -> dict:
    """Build {"system", "user", "meta"} for one (function, arm) pair.

    Deterministic and pure: the SAME (func, arm) always yields byte-identical
    prompts (A2/A3 rely on this for LLM-cache deduplication).  The advisory is
    NOT injected here — it is already materialized inside `func` for C5 arms
    (see apply_attack / the bench_attack_v1 artifact); this function only pairs
    the arm's task-ladder wording with the given code.
    """
    cfg = cfg or load_attack_config()
    arm = str(arm)
    if arm not in ARM_ORDER:
        raise ValueError(f"unknown arm {arm!r}; expected one of {ARM_ORDER}")
    if func is None:
        if sample is None or not sample.get("func"):
            raise ValueError("build_attack_prompt needs func (or a sample with 'func')")
        func = sample["func"]
    if language is None:
        language = (sample or {}).get("language") or resolve_language(func, "c")
    arm_cfg = cfg["arms"][arm]
    system = " ".join(str(cfg["system_prompt"]).split())
    task = " ".join(str(cfg["ladder"][arm_cfg["task_ladder"]]).split())
    user = (f"{task}\n\n```{language}\n{func}\n```\n\n{_PROMPT_TAIL}")
    return {
        "system": system,
        "user": user,
        "meta": {"arm": arm, "task_ladder": arm_cfg["task_ladder"],
                 "language": language},
    }


# ---------------------------------------------------------------------------
# (e) materialize bench_attack_v1 (JSONL + manifest)
# ---------------------------------------------------------------------------
def _cwe_key(row: dict, rare_group: str) -> str:
    return row.get("cwe") or "NONE"


def _stratified_select(rows: list[dict], label: int, n_take: int, seed: int,
                       min_group_size: int, rare_group: str) -> list[dict]:
    """Seeded proportional stratified selection within one label class.

    Mirrors the bench_v1 allocator rule: group by the stratify key, merge
    groups smaller than min_group_size into `rare_group`, largest-remainder
    allocation over group proportions, then a seeded shuffle inside each group
    supplies the picks.  Selection only — nothing is fitted on test semantics.
    """
    pool = [r for r in rows if r.get("label") == label]
    by_group: dict[str, list[dict]] = {}
    for r in pool:
        by_group.setdefault(_cwe_key(r, rare_group), []).append(r)
    big = {g: members for g, members in by_group.items() if len(members) >= min_group_size}
    small_total = sum(len(m) for g, m in by_group.items() if g not in big)
    groups: dict[str, list[dict]] = dict(big)
    if small_total:
        groups.setdefault(rare_group, []).extend(
            m for g, m in by_group.items() if g not in big for m in m)
    names = sorted(groups, key=lambda g: (-len(groups[g]), g))
    total = len(pool)
    quotas = [len(groups[g]) * n_take / total for g in names]
    alloc = [int(q) for q in quotas]
    rem = n_take - sum(alloc)
    order = sorted(range(len(names)), key=lambda i: (-(quotas[i] - alloc[i]), i))
    for i in order[:rem]:
        alloc[i] += 1
    rng = random.Random(seed)
    picks: list[dict] = []
    for g, k in zip(names, alloc):
        members = sorted(groups[g], key=lambda r: r["sample_id"])
        rng.shuffle(members)
        picks.extend(members[:k])
    return picks


def _sha256_16(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def _select_label(rows: list[dict], label: int, n_take: int, seed: int, scfg: dict,
                  seed_offsets: dict) -> tuple[list[dict], dict]:
    """Two-level stratified selection for one label class.

    Level 1 balances risky-API presence (balance_api_share, default 50/50) so
    the advisory-content distribution matches across label classes (anti-
    leakage at the distribution level); level 2 allocates within each stratum
    proportionally over CWE groups.  Quota overflow into the complementary
    stratum is deterministic and disclosed.
    """
    min_group = int(scfg["min_group_size"])
    rare = scfg["rare_group"]
    balance = float(scfg.get("balance_api_share", 0.5))
    n_with = int(round(n_take * balance))
    n_without = n_take - n_with
    with_api = [r for r in rows if r.get("label") == label and r["_has_risky_api"]]
    without_api = [r for r in rows if r.get("label") == label and not r["_has_risky_api"]]
    picks = (
        _stratified_select(with_api, label, n_with,
                           seed + int(seed_offsets[f"{'vul' if label else 'benign'}_with_api"]),
                           min_group, rare)
        + _stratified_select(without_api, label, n_without,
                             seed + int(seed_offsets[f"{'vul' if label else 'benign'}_without_api"]),
                             min_group, rare)
    )
    overflow = {"from_with": 0, "from_without": 0}
    picked_ids = {r["sample_id"] for r in picks}
    if len(picks) < n_take and scfg.get("stratum_overflow", True):
        deficit = n_take - len(picks)
        donor, donor_key = (with_api, "from_with") if n_without > n_with else (without_api, "from_without")
        rng = random.Random(seed + 99)
        cands = sorted((r for r in donor if r["sample_id"] not in picked_ids),
                       key=lambda r: r["sample_id"])
        rng.shuffle(cands)
        extra = cands[:deficit]
        overflow[donor_key] = len(extra)
        picks.extend(extra)
        picked_ids |= {r["sample_id"] for r in extra}
    picks.sort(key=lambda r: r["sample_id"])
    meta = {"n_taken": len(picks), "with_api_pool": len(with_api),
            "without_api_pool": len(without_api), "overflow": overflow,
            "with_api_selected": sum(1 for r in picks if r["_has_risky_api"])}
    return picks, meta


def materialize(cfg_path=None, out_dir: Optional[Path] = None) -> dict:
    """Materialize data/benchmarks/bench_attack_v1/{bench_attack_v1.jsonl,manifest}.

    Deterministic given the config seed; re-running overwrites byte-identical
    artifacts (except the `created` timestamp, which is excluded from the
    content checksum convention used across the project).
    """
    cfg = load_attack_config(cfg_path, refresh=True)
    out_dir = Path(out_dir) if out_dir else DEFAULT_OUTPUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    seed = int(cfg["seed"])
    scfg = cfg["sampling"]
    seed_offsets = dict(scfg.get("api_balance_seed_offsets") or {})
    src = _PROJECT_ROOT / cfg["source_bench"]
    rows = [json.loads(l) for l in src.read_text(encoding="utf-8").splitlines() if l.strip()]
    # bench_v1 stores the clean function under variants.C0.func (no top-level
    # 'func'); normalize once so the rest of the builder is representation-
    # agnostic (also tolerates a flat {sample_id, func} source).
    pool = []
    for r in rows:
        if r.get("label") not in (0, 1):
            continue
        func = r.get("func") or (r.get("variants") or {}).get("C0", {}).get("func")
        if not func:
            continue
        pool.append({**r, "func": func})
    for r in pool:  # feature pre-pass: label-blind (no label argument involved)
        r["_has_risky_api"] = bool(extract_risky_apis(
            r["func"], language=r.get("language") or "c", cfg=cfg))

    sel_vul, meta_v = _select_label(pool, 1, int(scfg["n_vul"]), seed, scfg, seed_offsets)
    sel_ben, meta_b = _select_label(pool, 0, int(scfg["n_benign"]), seed + 1, scfg,
                                    seed_offsets)
    selected = sel_vul + sel_ben
    selected.sort(key=lambda r: r["sample_id"])

    out_rows: list[dict] = []
    fail: dict[str, list[str]] = {}
    for r in selected:
        sample = {"sample_id": r["sample_id"], "pair_id": r.get("pair_id"),
                  "label": int(r["label"]), "cwe": r.get("cwe"), "cve": r.get("cve"),
                  "project": r.get("project"), "split": r.get("split", "test"),
                  "language": r.get("language") or "c", "func": r["func"]}
        arms_payload: dict[str, dict] = {}
        offsets: dict[str, Optional[int]] = {}
        adv_meta: Optional[dict] = None
        for arm in cfg["arm_order"]:
            out = apply_attack(sample, arm, cfg)
            meta = out["meta"]
            arms_payload[arm] = {
                "func": out["func"],
                "task_ladder": meta["task_ladder"],
                "semantics_checked": True,
                "semantics_ok": meta["semantics_ok"],
                "semantics_strict": meta.get("semantics_strict",
                                             meta["func_source"] == "original"),
                "modifies_string_data": meta["modifies_string_data"],
                "carrier": meta["carrier"], "position": meta["position"],
                "template_id": meta["template_id"],
                "advisory_offset": meta.get("advisory_offset"),
                "language": meta["language"],
            }
            if meta.get("advisory_offset") is not None:
                offsets[arm] = meta["advisory_offset"]
            if arm in _PATTERN_ARMS:
                adv_meta = {
                    "template_id": meta["template_id"],
                    "zero_api": meta["zero_api"],
                    "risky_apis": meta["risky_apis"],
                    "n_calls_raw": meta["n_calls_raw"],
                    "sites": meta["sites"],
                    "n_api_kinds": meta["n_api_kinds"],
                    "advisory_chars": meta["advisory_chars"],
                    "policy_safety_scan": meta["policy_safety_scan"],
                }
        near, far = offsets.get("C5_near"), offsets.get("C5_far")
        confound = (near is None or far is None or near <= far)
        if confound:
            fail.setdefault(r["sample_id"], []).append(f"near/far offset {near}!>{far}")
        out_rows.append({
            "sample_id": sample["sample_id"], "pair_id": sample["pair_id"],
            "section": r.get("section", "vulnerable" if sample["label"] else "benign"),
            "label": sample["label"], "cwe": sample["cwe"], "cve": sample["cve"],
            "project": sample["project"], "split": sample["split"],
            "language": sample["language"],
            "func": sample["func"],
            "has_risky_api": not (adv_meta["zero_api"] if adv_meta else True),
            "risky_apis": adv_meta["risky_apis"] if adv_meta else {},
            "advisory": adv_meta,
            "near_far_confound": confound,
            "near_far_offsets": {"C5_near": near, "C5_far": far},
            "arms": arms_payload,
        })

    if fail:
        raise ValueError(f"near/far collapse or missing offsets in {len(fail)} rows: "
                         f"{sorted(fail)[:5]}")

    jsonl_path = out_dir / "bench_attack_v1.jsonl"
    body = "\n".join(json.dumps(row, ensure_ascii=False) for row in out_rows) + "\n"
    jsonl_path.write_text(body, encoding="utf-8")

    # ---- manifest + distribution checks ---------------------------------
    tpl_by_label: dict[int, Counter] = {0: Counter(), 1: Counter()}
    zero_api_by_label: dict[int, int] = {0: 0, 1: 0}
    bucket_by_label: dict[int, Counter] = {0: Counter(), 1: Counter()}
    for row in out_rows:
        adv = row["advisory"] or {}
        tpl_by_label[row["label"]][adv.get("template_id")] += 1
        if adv.get("zero_api"):
            zero_api_by_label[row["label"]] += 1
        raw = adv.get("n_calls_raw", 0)
        bucket = "0" if raw == 0 else ("1" if raw == 1 else ("2" if raw == 2 else "3+"))
        bucket_by_label[row["label"]][bucket] += 1
    pattern_counts = Counter(
        row["advisory"]["template_id"] for row in out_rows
        if row["advisory"] and not row["advisory"]["zero_api"])
    max_share = max(pattern_counts.values()) / max(1, sum(pattern_counts.values()))

    manifest = {
        "name": "bench_attack_v1",
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "date": "2026-09-19",
        "seed": seed,
        "seed_offsets": {"benign_label": 1, **{f"api_balance_{k}": v
                                               for k, v in seed_offsets.items()}},
        "prereg": cfg.get("prereg"),
        "purpose": ("Mechanism-faithful attack-v2 benchmark: C5 query-relevant "
                    "risk context (code-anchored advisory, label-blind) + D0/D2 "
                    "wording ladder. Pre-computed, semantics-checked; prompts are "
                    "rebuilt by src.conditions.c5_risk_context.build_attack_prompt "
                    "(single source of truth) — this file stores func variants, "
                    "not prompts."),
        "sources": {
            "bench_v1": cfg["source_bench"],
            "bench_v1_sha256_16": _sha256_16(src),
            "attack_config": "configs/attack_v2.yaml",
            "attack_config_version": cfg.get("version"),
            "attack_config_sha256_16": _sha256_16(Path(cfg_path).resolve())
            if cfg_path else _sha256_16(DEFAULT_CONFIG_PATH),
        },
        "counts": {
            "rows": len(out_rows),
            "by_label": dict(Counter(r["label"] for r in out_rows)),
            "arms": list(cfg["arm_order"]),
            "entries_expected": len(out_rows) * len(cfg["arm_order"]),
        },
        "sampling": {
            "rule": "two-level stratification: risky-API presence balanced "
                    "50/50 within each label (anti-leakage distribution "
                    "guard), CWE-group proportional allocation within strata",
            "balance_api_share": scfg.get("balance_api_share", 0.5),
            "strata": {"vul": meta_v, "benign": meta_b},
            "with_api_by_label": {
                str(l): sum(1 for r in out_rows if r["label"] == l and r["has_risky_api"])
                for l in (0, 1)},
        },
        "cwe_distribution": {
            str(l): dict(sorted(Counter(r["cwe"] or "NONE" for r in out_rows
                                        if r["label"] == l).items(),
                                key=lambda kv: (-kv[1], kv[0])))
            for l in (0, 1)
        },
        "advisory_distribution": {
            "template_by_label": {str(l): dict(tpl_by_label[l]) for l in (0, 1)},
            "zero_api_by_label": zero_api_by_label,
            "n_calls_raw_bucket_by_label": {str(l): dict(bucket_by_label[l])
                                            for l in (0, 1)},
            "max_pattern_template_share": round(max_share, 4),
            "max_template_share_guard": (cfg.get("advisory") or {}).get(
                "max_template_share", 0.40),
        },
        "semantics": {
            "rule": "check_semantics strict (ignore_strings=False) for C5 comment "
                    "carriers; C0/D2_task are identity transforms",
            "all_pass": all(
                payload["semantics_ok"] for row in out_rows
                for payload in row["arms"].values()),
        },
        "near_far": {
            "carrier_choice": {"C5_near": "inline_comment", "C5_far": "top_comment"},
            "rationale": "different carriers guarantee near_offset > far_offset "
                         "for every row (bench_v1 audit measured 35.2% same-byte "
                         "collapse for same-carrier near/far pairs)",
            "any_confound": any(r["near_far_confound"] for r in out_rows),
            "min_gap_bytes": min(r["near_far_offsets"]["C5_near"]
                                 - r["near_far_offsets"]["C5_far"] for r in out_rows),
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
        "jsonl_sha256": hashlib.sha256(
            jsonl_path.read_bytes()).hexdigest(),
    }
    guard_min = int((cfg.get("advisory") or {}).get("min_rows_for_balance_guard", 50))
    if sum(pattern_counts.values()) >= guard_min and \
            manifest["advisory_distribution"]["max_pattern_template_share"] > \
            manifest["advisory_distribution"]["max_template_share_guard"]:
        raise ValueError("advisory template-usage balance guard failed "
                         f"(max share {max_share:.3f})")
    manifest_path = out_dir / "manifest_attack_v1.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                             encoding="utf-8")
    return {"jsonl": str(jsonl_path), "manifest": str(manifest_path),
            "rows": len(out_rows), "manifest_summary": manifest["counts"]}


def main(argv: Optional[list[str]] = None) -> int:  # pragma: no cover
    import sys

    args = list(sys.argv[1:] if argv is None else argv)
    cfg_path = args[0] if args else None
    res = materialize(cfg_path)
    print(f"[attack_v2] materialized {res['rows']} rows -> {res['jsonl']}")
    print(f"[attack_v2] manifest -> {res['manifest']}")
    print(f"[attack_v2] counts: {res['manifest_summary']}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
