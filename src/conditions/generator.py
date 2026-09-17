"""Context-condition generator C0-C3 (PROJECT_BRIEF §8; PROPOSAL §6).

Canonical interface:
    apply_condition(sample: dict, condition: str, cfg) -> {"func": str, "meta": dict}
    check_semantics(func_original, func_transformed) -> bool   (re-exported)

Conditions (PROPOSAL §6):
    C0 clean                    -> identity; standardized defensive prompt.
    C1 defensive wording        -> prompt-level only; `func` unchanged, meta
                                   carries `prompt_variant_key` (neutral vs
                                   security-defensive wording, YAML variants,
                                   Defensive-Refusal-Bias inspired).
    C2 benign contextual stress -> security-sensitive, instruction-free text
                                   injected into comment/docstring/string
                                   carriers; program semantics preserved
                                   (enforced by the check_semantics gate).
    C3 IPI-style                -> instruction-like text in comments
                                   (BIPIA-style families); meta records
                                   `attack_family`.

Determinism: template/carrier/position selection is seeded by
crc32(config.seed : sample_id : condition), so the same (sample, condition,
cfg) always yields the same transform without global RNG state.

Quality gate: every C2/C3 transform must pass check_semantics before it is
returned. Comment carriers are verified strictly (string literals included in
the AST comparison); the string-literal carrier only appends data inside an
existing string, so for that carrier the comparison skips string subtrees
(ignore_strings=True) — the executable AST is still unchanged, and
meta["modifies_string_data"]=True discloses the runtime-data change.
If no candidate passes the gate, the call raises ValueError by default
(configurable: C2.on_semantics_fail / C3.on_semantics_fail = "skip").
"""
from __future__ import annotations

import random
import zlib
from pathlib import Path
from typing import Optional

import yaml

from .carriers import C3_CARRIERS, CARRIER_ORDER, inject_carrier
from .parser_utils import check_semantics, resolve_language  # noqa: F401 (canonical re-export)

__all__ = [
    "apply_condition",
    "check_semantics",
    "load_config",
    "condition_combos",
    "CONDITIONS",
]

CONDITIONS = ("C0", "C1", "C2", "C3")
DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[2] / "configs" / "conditions.yaml"


def load_config(path=None) -> dict:
    """Load the conditions YAML (default: configs/conditions.yaml)."""
    p = Path(path) if path else DEFAULT_CONFIG_PATH
    with open(p, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    if not isinstance(cfg, dict):
        raise ValueError(f"conditions config must be a mapping: {p}")
    return cfg


def _rng(seed: int, sample_id: str, condition: str) -> random.Random:
    key = f"{seed}:{sample_id}:{condition}"
    return random.Random(zlib.crc32(key.encode("utf-8")))


def _pin(cfg: dict, condition: str) -> dict:
    """Optional per-call pinning for ablations (E4): cfg[<C>]['pin'] may fix
    template_id / carrier / position."""
    sec = cfg.get(condition) or {}
    pin = sec.get("pin") or {}
    return {k: pin[k] for k in ("template_id", "carrier", "position") if pin.get(k)}


def _pick(seq, rng: random.Random):
    seq = list(seq)
    if not seq:
        raise ValueError("no candidates configured for condition")
    i = rng.randrange(len(seq))
    return seq[i:] + seq[:i]  # rotate; deterministic and keeps full coverage


def _condition_cfg(cfg: dict, condition: str) -> dict:
    return cfg.get(condition) or {}


def _sample_language(sample: dict, cfg: dict) -> str:
    """Grammar for this sample: explicit sample['language'] wins; otherwise the
    grammar is auto-resolved from the code (c first, then cpp — PrimeVul is
    ~65% C++; see parser_utils.GRAMMARS)."""
    default = cfg.get("parser", {}).get("default_language", "c")
    return sample.get("language") or resolve_language(sample.get("func", ""), default)


def _apply_contextual(
    sample: dict,
    condition: str,
    cfg: dict,
    templates: list,
    carriers: list,
    positions: list,
) -> dict:
    func = sample["func"]
    language = _sample_language(sample, cfg)
    rng = _rng(int(cfg.get("seed", 0)), str(sample.get("sample_id", "")), condition)
    ccfg = _condition_cfg(cfg, condition)
    pin = _pin(cfg, condition)
    cve_pool = ccfg.get("placeholders", {}).get("cve_pool", [])
    cve_id = rng.choice(cve_pool) if cve_pool else ""

    cands = []
    for tpl in _pick(templates, rng):
        if pin.get("template_id") and tpl["id"] != pin["template_id"]:
            continue
        for carrier in _pick(carriers, rng):
            if pin.get("carrier") and carrier != pin["carrier"]:
                continue
            for position in _pick(positions, rng):
                if pin.get("position") and position != pin["position"]:
                    continue
                cands.append((tpl, carrier, position))

    fill = dict(ccfg.get("placeholders", {}).get("fill", {}))
    if condition == "C3":
        # payload texts are format *values*, never re-formatted (braces safe)
        fill.setdefault("answer", " ".join(str(ccfg.get("payload_benign_json", "")).split()))
        fill.setdefault("answer_brief", str(ccfg.get("payload_benign_brief", "")))

    failures = []
    for tpl, carrier, position in cands:
        text = tpl["text"].format(cve_id=cve_id, **fill)
        try:
            new_func, actual, modifies_string = inject_carrier(func, text, carrier, position, language)
        except ValueError as exc:
            failures.append(f"{tpl['id']}/{carrier}/{position}: {exc}")
            continue
        # Gate: strict (strings included) for comment carriers; string-subtree-
        # skipping comparison for the string-literal carrier (documented above).
        strict = not modifies_string
        if check_semantics(func, new_func, language=language, ignore_strings=not strict):
            meta = {
                "condition": condition,
                "language": language,
                "template_id": tpl["id"],
                "carrier": actual,
                "requested_carrier": carrier if actual != carrier else None,
                "position": position,
                "semantics_ok": True,
                "semantics_strict": strict,
                "modifies_string_data": modifies_string,
                "seed": int(cfg.get("seed", 0)),
            }
            if condition == "C3":
                meta["attack_family"] = tpl.get("attack_family", "unspecified")
                meta["ipi_text"] = " ".join(text.split())
            else:
                meta["stress_template_id"] = tpl["id"]
                meta["cve_id"] = cve_id if "{cve_id}" in tpl["text"] else None
            return {"func": new_func, "meta": meta}
        failures.append(f"{tpl['id']}/{carrier}/{position}: semantics gate failed")

    on_fail = ccfg.get("on_semantics_fail", "raise")
    if on_fail == "skip":
        return {
            "func": func,
            "meta": {
                "condition": condition,
                "language": language,
                "applied": False,
                "semantics_ok": False,
                "failures": failures[:5],
            },
        }
    raise ValueError(
        f"{condition}: no candidate passed the semantics gate for "
        f"sample_id={sample.get('sample_id', '?')}; attempts={failures[:5]}"
    )


def apply_condition(sample: dict, condition: str, cfg: Optional[dict] = None) -> dict:
    """Apply condition C0|C1|C2|C3 to a PrimeVul-style sample dict.

    Returns {"func": str, "meta": dict}. Never mutates `sample`.
    """
    if cfg is None:
        cfg = load_config()
    if isinstance(cfg, (str, Path)):
        cfg = load_config(cfg)
    condition = str(condition).upper()
    if condition not in CONDITIONS:
        raise ValueError(f"unknown condition {condition!r}; expected one of {CONDITIONS}")
    func = sample["func"]
    language = _sample_language(sample, cfg)
    common = {
        "condition": condition,
        "language": language,
        "sample_id": sample.get("sample_id"),
        "label": sample.get("label"),
        "config_version": cfg.get("version"),
        "seed": int(cfg.get("seed", 0)),
    }

    if condition == "C0":
        meta = dict(common)
        meta.update({"carrier": None, "position": None, "template_id": None,
                     "semantics_ok": True, "modifies_string_data": False})
        return {"func": func, "meta": meta}

    if condition == "C1":
        rng = _rng(int(cfg.get("seed", 0)), str(sample.get("sample_id", "")), "C1")
        variants = _condition_cfg(cfg, "C1").get("prompt_variants", [])
        pin = _pin(cfg, "C1")  # E2 variant grid: pin.template_id selects one framing
        if pin.get("template_id"):
            variant = next(v for v in variants if v["id"] == pin["template_id"])
        else:
            variant = _pick(variants, rng)[0]  # single deterministic draw
        meta = dict(common)
        meta.update({
            "carrier": None,
            "position": None,
            "prompt_variant_key": variant["id"],
            "neutral_prompt": " ".join(variant["neutral"].split()),
            "defensive_prompt": " ".join(variant["defensive"].split()),
            "semantics_ok": True,
            "modifies_string_data": False,
        })
        return {"func": func, "meta": meta}

    if condition == "C2":
        ccfg = _condition_cfg(cfg, "C2")
        out = _apply_contextual(sample, "C2", cfg, ccfg.get("templates", []),
                                ccfg.get("carriers", CARRIER_ORDER),
                                ccfg.get("positions", ["near", "far"]))
        out["meta"].update({"label": sample.get("label"), "sample_id": sample.get("sample_id"),
                            "config_version": cfg.get("version")})
        return out

    # C3
    ccfg = _condition_cfg(cfg, "C3")
    out = _apply_contextual(sample, "C3", cfg, ccfg.get("templates", []),
                            ccfg.get("carriers", C3_CARRIERS),
                            ccfg.get("positions", ["near", "far"]))
    out["meta"].update({"label": sample.get("label"), "sample_id": sample.get("sample_id"),
                        "config_version": cfg.get("version")})
    return out


def condition_combos(cfg: dict, condition: str) -> list:
    """Enumerate (template_id, carrier, position) combos configured for a
    contextual condition — used by runners for full-coverage ablations (E3/E4).
    """
    ccfg = _condition_cfg(cfg, condition)
    combos = []
    for tpl in ccfg.get("templates", []):
        for carrier in ccfg.get("carriers", []):
            for position in ccfg.get("positions", []):
                combos.append({"template_id": tpl["id"], "carrier": carrier,
                               "position": position,
                               "attack_family": tpl.get("attack_family")})
    return combos
