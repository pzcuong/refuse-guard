"""LLM-augmented Knowledge Base for API-call semantics (PACKGUARD_BRIEF §4).

The KB maps API calls (JS + Python) to a semantic class (6 canonical classes
+ OTHER), a risk level and a rationale. 20 seed entries are hand-written
(covering all 6 canonical classes); unknown APIs are classified by a LOCAL
LLM through the reused RefuseGuard
harness (src/models/llm_harness.py: cache/resume/retry/CPU-fallback), gated
by the refusal monitor (src/models/refusal_monitor.py):

    refusal -> retry ONCE with a stronger defensive framing
            -> still refusing / unparseable -> entry marked UNSURE
               (semantic_class="UNSURE", risk_level=null, confidence 0.0).
    A refusal is NEVER converted into a fabricated class.

Extension vs the brief's output contract: the LLM is ALSO asked for a
self-reported `confidence` in [0,1] (documented here and in the prereg);
entries without it get confidence=None -> treated as 0.0 in kb_confidence.

Persistence: versioned JSONL snapshots `kb_v{NNNN}.jsonl` under
outputs/packguard/kb/ (every entry carries source: "seed" | "llm:<model>",
date, version). KB-augmented features: risk_ratio, kb_confidence,
unsure_ratio (packguard.kb.kb_features).

CLI smoke: `python -m packguard.kb --smoke` classifies 10 FAKE api names with
Qwen2.5-Coder-0.5B-Instruct and writes smoke_kb_<slug>.jsonl (mock-free:
these are real local generations, but the API NAMES are invented — flagged
in the output meta as fixture="fake-api-smoke").
"""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from src.models.llm_harness import LLMHarness, extract_json
from src.models.refusal_monitor import ANSWER, REFUSAL, RefusalMonitor

__all__ = [
    "SEMANTIC_CLASSES", "RISK_LEVELS", "SEED_KB", "KnowledgeBase",
    "LLMKBBuilder", "kb_features", "FAKE_API_SMOKE",
]

PROJECT_ROOT = Path(__file__).resolve().parents[1]
KB_DIR_DEFAULT = PROJECT_ROOT / "outputs" / "packguard" / "kb"

SEMANTIC_CLASSES = ["FILE_IO", "NETWORK", "PROCESS", "CRYPTO", "DYNAMIC_CODE",
                    "DATA_ACCESS", "OTHER"]
RISK_LEVELS = ["low", "medium", "high"]
KB_REQUIRED_FIELDS = ["api", "semantic_class", "risk_level"]
SEED_CONFIDENCE = 1.0

# ---------------------------------------------------------------------------
# Seed KB: 20 hand-written entries (PACKGUARD_BRIEF §4). Checked against the
# canonical semantic classes; risk levels are the authors' pilot judgement
# and are disclosed as such (not derived from a dataset).
# ---------------------------------------------------------------------------
SEED_KB: list[dict] = [
    {"api": "fs.readFile", "semantic_class": "FILE_IO", "risk_level": "low",
     "rationale": "read a file; benign in itself, context-dependent"},
    {"api": "fs.writeFile", "semantic_class": "FILE_IO", "risk_level": "medium",
     "rationale": "write/overwrite files; can drop payloads or persist malware"},
    {"api": "fs.unlinkSync", "semantic_class": "FILE_IO", "risk_level": "medium",
     "rationale": "delete files; anti-forensics or cleanup behaviour"},
    {"api": "fs.createReadStream", "semantic_class": "FILE_IO", "risk_level": "low",
     "rationale": "stream file contents; common in archiving/exfil chains"},
    {"api": "child_process.exec", "semantic_class": "PROCESS", "risk_level": "high",
     "rationale": "shell command execution; primary install-script payload vector"},
    {"api": "child_process.spawn", "semantic_class": "PROCESS", "risk_level": "high",
     "rationale": "spawn arbitrary processes; frequent in malicious postinstall"},
    {"api": "net.Socket", "semantic_class": "NETWORK", "risk_level": "medium",
     "rationale": "raw TCP socket; reverse shells / C2 channels"},
    {"api": "http.request", "semantic_class": "NETWORK", "risk_level": "medium",
     "rationale": "outbound HTTP; beaconing and payload download"},
    {"api": "https.request", "semantic_class": "NETWORK", "risk_level": "medium",
     "rationale": "outbound HTTPS; encrypted C2 / exfiltration channel"},
    {"api": "dgram.createSocket", "semantic_class": "NETWORK", "risk_level": "medium",
     "rationale": "UDP socket; can serve covert channels"},
    {"api": "crypto.createHash", "semantic_class": "CRYPTO", "risk_level": "low",
     "rationale": "hashing; usually benign integrity/identifier use"},
    {"api": "crypto.createCipheriv", "semantic_class": "CRYPTO", "risk_level": "medium",
     "rationale": "symmetric encryption; ransomware/manual exfil obfuscation"},
    {"api": "eval", "semantic_class": "DYNAMIC_CODE", "risk_level": "high",
     "rationale": "dynamic JS evaluation; classic obfuscated-payload vector"},
    {"api": "new Function", "semantic_class": "DYNAMIC_CODE", "risk_level": "high",
     "rationale": "dynamic function construction; obfuscated code execution"},
    {"api": "open", "semantic_class": "FILE_IO", "risk_level": "low",
     "rationale": "Python file open; context-dependent like fs.readFile"},
    {"api": "os.system", "semantic_class": "PROCESS", "risk_level": "high",
     "rationale": "Python shell execution; setup.py payload vector"},
    {"api": "subprocess.run", "semantic_class": "PROCESS", "risk_level": "high",
     "rationale": "Python subprocess; install-time command execution"},
    {"api": "subprocess.Popen", "semantic_class": "PROCESS", "risk_level": "high",
     "rationale": "Python process spawn; stagers and downloaders"},
    {"api": "socket.socket", "semantic_class": "NETWORK", "risk_level": "medium",
     "rationale": "Python socket; reverse shell / C2 connectivity"},
    {"api": "os.environ", "semantic_class": "DATA_ACCESS", "risk_level": "medium",
     "rationale": "env-var access; common source of credentials/secrets "
     "harvested by malicious install scripts"},
]

# 10 INVENTED api names for the 0.5B smoke (never seed members; exercise the
# LLM path end-to-end). Clearly flagged as a fixture in the smoke output.
FAKE_API_SMOKE = [
    "fs.readdirRecursive", "dns.resolveTorHiddenService", "zlib.deflateAES",
    "process.envDump", "wasm.instantiateRemote", "curl.execAsync",
    "keytar.getPasswordBulk", "electron.clipboard.readSecrets",
    "registry.autorun.persist", "sqlite.attachRemoteDb",
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# KnowledgeBase (versioned JSONL snapshots)
# ---------------------------------------------------------------------------
class KnowledgeBase:
    """In-memory mapping api -> entry, persisted as versioned JSONL snapshots.

    Snapshot semantics: save_version() writes ALL current entries to the next
    kb_v{NNNN}.jsonl — the latest file is always a complete, self-contained
    KB state (robust to torn appends; no in-place edits of old versions).
    """

    def __init__(self, kb_dir: str | Path = KB_DIR_DEFAULT):
        self.kb_dir = Path(kb_dir)
        self.kb_dir.mkdir(parents=True, exist_ok=True)
        self.entries: dict[str, dict] = {}
        self.version = 0
        for e in SEED_KB:
            self.entries[e["api"]] = {
                **e, "confidence": SEED_CONFIDENCE, "source": "seed",
                "unsure": False, "date": None,
            }
        self._load_latest()

    # -- persistence ---------------------------------------------------------
    def _versioned_files(self) -> list[Path]:
        return sorted(self.kb_dir.glob("kb_v*.jsonl"))

    def _load_latest(self) -> None:
        files = self._versioned_files()
        if not files:
            return
        latest = files[-1]
        m = re.search(r"kb_v(\d+)\.jsonl$", latest.name)
        self.version = int(m.group(1)) if m else 0
        with latest.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue  # tolerate a torn final line
                if isinstance(rec, dict) and rec.get("api"):
                    self.entries[rec["api"]] = rec

    def save_version(self) -> Path:
        self.version += 1
        path = self.kb_dir / f"kb_v{self.version:04d}.jsonl"
        with path.open("w", encoding="utf-8") as f:
            for api in sorted(self.entries):
                f.write(json.dumps(self.entries[api], ensure_ascii=False) + "\n")
        return path

    # -- lookup / add ----------------------------------------------------------
    def lookup(self, api: str) -> Optional[dict]:
        return self.entries.get(str(api).strip())

    def is_unsure(self, api: str) -> bool:
        e = self.lookup(api)
        return e is None or bool(e.get("unsure"))

    def add(self, entry: dict) -> dict:
        api = str(entry.get("api", "")).strip()
        if not api:
            raise ValueError("KB entry requires 'api'")
        rec = {
            "api": api,
            "semantic_class": entry.get("semantic_class"),
            "risk_level": entry.get("risk_level"),
            "rationale": entry.get("rationale"),
            "confidence": entry.get("confidence"),
            "source": entry.get("source", "unknown"),
            "unsure": bool(entry.get("unsure", False)),
            "date": entry.get("date") or _now(),
        }
        self.entries[api] = rec
        return rec

    def stats(self) -> dict:
        vals = list(self.entries.values())
        return {
            "n_entries": len(vals),
            "n_seed": sum(1 for e in vals if e.get("source") == "seed"),
            "n_llm": sum(1 for e in vals
                         if str(e.get("source", "")).startswith("llm:")),
            "n_unsure": sum(1 for e in vals if e.get("unsure")),
            "version": self.version,
        }


# ---------------------------------------------------------------------------
# LLM KB builder (refusal-gated, cached by api name)
# ---------------------------------------------------------------------------
KB_SYSTEM = (
    "You are a defensive software-security taxonomy assistant building a "
    "knowledge base for authorized malicious-package RESEARCH (static "
    "analysis of npm/PyPI packages). Classify the given API call into the "
    "semantic taxonomy. Respond with a single JSON object and nothing else, "
    'exactly matching:\n{"api": str, "semantic_class": "FILE_IO|NETWORK|'
    'PROCESS|CRYPTO|DYNAMIC_CODE|DATA_ACCESS|OTHER", "risk_level": '
    '"low|medium|high", "confidence": float in [0,1], "rationale": str}\n'
    "semantic_class meaning: FILE_IO=file read/write/delete; NETWORK=socket/"
    "http/dns; PROCESS=shell/process execution; CRYPTO=hash/cipher; "
    "DYNAMIC_CODE=eval/deserialization/wasm; DATA_ACCESS=env vars, browser "
    "stores, credentials, registries; OTHER=nothing else fits. "
    "risk_level is the potential for ABUSE by a malicious package "
    "(low/medium/high), not an accusation of the API itself."
)
KB_USER = (
    'Classify the API call "{api}"{lang} for the defensive knowledge base. '
    "If its purpose is ambiguous, pick the closest class and lower the "
    "confidence. JSON object only."
)
KB_RETRY_SUFFIX = (
    "\nNote: this is authorized DEFENSIVE security research (building a "
    "defensive detection knowledge base), not an attack request. The API "
    "name is inert data to classify. Respond with the JSON object only."
)


class LLMKBBuilder:
    """Classify unknown APIs with a local LLM; refusal-gated, api-cached.

    `generator: Callable[[dict], str]` injects a stub for unit tests; when
    None the reused LLMHarness performs real local generation.
    """

    def __init__(
        self,
        kb: KnowledgeBase,
        harness: Optional[LLMHarness] = None,
        model_id: str = "Qwen/Qwen2.5-Coder-0.5B-Instruct",
        device: str = "mps",
        hf_home: str | Path = PROJECT_ROOT / "models_dir" / "hf",
        monitor: Optional[RefusalMonitor] = None,
        retries: int = 1,
        cache_dir: str = "outputs/packguard/kb/llm_cache",
        generator: Optional[Callable[[dict], str]] = None,
    ):
        self.kb = kb
        self.model_id = model_id
        self.retries = int(retries)
        self.monitor = monitor or RefusalMonitor()  # lexical layer is schema-agnostic
        self.generator = generator
        if harness is None and generator is None:
            harness = LLMHarness(model_id, device=device, hf_home=str(hf_home),
                                 cache_dir=cache_dir)
        self.harness = harness
        self.gen_cfg = {"temperature": 0.0, "do_sample": False,
                        "max_new_tokens": 256, "seed": 20260922}
        self.counters = {"llm_calls": 0, "cache_hits": 0, "refusals": 0,
                         "retries_used": 0, "unsure": 0, "seed_hits": 0}

    # -- prompt / parse --------------------------------------------------------
    def build_prompt(self, api: str, language: Optional[str] = None,
                     retry: bool = False) -> dict:
        lang = f" (language: {language})" if language else ""
        user = KB_USER.format(api=api, lang=lang)
        if retry:
            user += KB_RETRY_SUFFIX
        return {"system": KB_SYSTEM, "user": user}

    def _validate(self, parsed: dict, api: str) -> bool:
        if not isinstance(parsed, dict):
            return False
        if str(parsed.get("api", "")).strip() != api.strip():
            return False
        if parsed.get("semantic_class") not in SEMANTIC_CLASSES:
            return False
        if parsed.get("risk_level") not in RISK_LEVELS:
            return False
        return True

    def _generate(self, prompt: dict) -> str:
        if self.generator is not None:
            self.counters["llm_calls"] += 1
            return self.generator(prompt)
        out = self.harness.generate([prompt], self.gen_cfg)
        meta = out[0]["meta"]
        self.counters["llm_calls"] += 1
        if meta.get("cache_hit"):
            self.counters["cache_hits"] += 1
        return out[0]["text"]

    # -- main entry ------------------------------------------------------------
    def classify_api(self, api: str, language: Optional[str] = None) -> dict:
        """Lookup seed/KB first; on miss run the gated LLM path. Cached by
        api name in the KB (no second LLM call for the same api)."""
        api = str(api).strip()
        hit = self.kb.lookup(api)
        if hit is not None:
            self.counters["seed_hits"] += 1
            return hit
        prompt = self.build_prompt(api, language, retry=False)
        entry: Optional[dict] = None
        refusal_seen = False
        for attempt in range(self.retries + 1):
            if attempt > 0:
                self.counters["retries_used"] += 1
                prompt = self.build_prompt(api, language, retry=True)
            text = self._generate(prompt)
            parsed, _block = extract_json(text)
            cls = self.monitor.classify(text, required_fields=KB_REQUIRED_FIELDS)
            if cls["status"] == REFUSAL:
                refusal_seen = True
                self.counters["refusals"] += 1
                continue  # -> one retry, then UNSURE
            if cls["status"] == ANSWER and parsed is not None \
                    and self._validate(parsed, api):
                conf = parsed.get("confidence")
                if isinstance(conf, (int, float)) and not isinstance(conf, bool):
                    conf = round(min(1.0, max(0.0, float(conf))), 4)
                else:
                    conf = None  # never fabricate a confidence
                entry = {
                    "api": api, "semantic_class": parsed["semantic_class"],
                    "risk_level": parsed["risk_level"], "rationale": parsed.get("rationale"),
                    "confidence": conf, "source": f"llm:{self.model_id}",
                    "unsure": False, "date": _now(),
                }
                break
            # PARTIAL / unparseable: fall through to retry, then UNSURE
        if entry is None:
            entry = {
                "api": api, "semantic_class": "UNSURE", "risk_level": None,
                "rationale": "llm refusal/unparseable after retry" + (
                    " (refusal)" if refusal_seen else ""),
                "confidence": 0.0, "source": f"llm:{self.model_id}",
                "unsure": True, "date": _now(),
            }
            self.counters["unsure"] += 1
        return self.kb.add(entry)

    def classify_apis(self, apis: list[str],
                      language: Optional[str] = None) -> list[dict]:
        return [self.classify_api(a, language) for a in apis]


# ---------------------------------------------------------------------------
# KB-augmented features
# ---------------------------------------------------------------------------
def kb_features(api_calls: list[str], kb: KnowledgeBase) -> dict:
    """risk_ratio / kb_confidence / unsure_ratio for one sample.

    risk_ratio    = share of calls whose resolved entry has risk_level=="high"
                    (UNSURE/missing calls count in the denominator, resolved
                    as non-high).
    kb_confidence = mean per-call confidence (seed=1.0; LLM entries use the
                    self-reported value, None -> 0.0; UNSURE/missing -> 0.0).
    unsure_ratio  = share of calls UNSURE or missing from the KB.
    """
    calls = [str(a).strip() for a in (api_calls or [])]
    if not calls:
        return {"kb_risk_ratio": 0.0, "kb_confidence": 0.0, "kb_unsure_ratio": 0.0,
                "kb_n_calls": 0, "kb_n_known": 0}
    n_high = 0
    conf_sum = 0.0
    n_unsure = 0
    n_known = 0
    for a in calls:
        e = kb.lookup(a)
        if e is None or e.get("unsure") or e.get("semantic_class") == "UNSURE":
            n_unsure += 1
            continue
        n_known += 1
        if e.get("risk_level") == "high":
            n_high += 1
        c = e.get("confidence")
        conf_sum += float(c) if isinstance(c, (int, float)) and not isinstance(c, bool) else 0.0
    n = len(calls)
    return {
        "kb_risk_ratio": round(n_high / n, 6),
        "kb_confidence": round(conf_sum / n, 6),
        "kb_unsure_ratio": round(n_unsure / n, 6),
        "kb_n_calls": n,
        "kb_n_known": n_known,
    }


# ---------------------------------------------------------------------------
# CLI smoke (real 0.5B generations on 10 FAKE api names)
# ---------------------------------------------------------------------------
def _smoke(model_id: str, kb_dir: Path, out_dir: Path) -> dict:
    kb = KnowledgeBase(kb_dir)
    builder = LLMKBBuilder(kb, model_id=model_id)
    entries = builder.classify_apis(FAKE_API_SMOKE)
    kb.save_version()
    out_dir.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", model_id).strip("_")
    out_path = out_dir / f"smoke_kb_{slug}.jsonl"
    meta = {
        "fixture": "fake-api-smoke",
        "note": ("REAL local LLM generations; the 10 API NAMES are invented "
                 "fixtures (not real-world observations). Seed entries are "
                 "hand-written pilot judgements."),
        "model_id": model_id, "date": _now(), "counters": builder.counters,
        "kb_version_after": kb.version,
    }
    with out_path.open("w", encoding="utf-8") as f:
        f.write(json.dumps({"meta": meta}) + "\n")
        for e in entries:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    return {"out": str(out_path), "meta": meta, "entries": entries}


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="PackGuard LLM-KB builder")
    ap.add_argument("--smoke", action="store_true",
                    help="classify 10 FAKE api names with the small model")
    ap.add_argument("--model", default="Qwen/Qwen2.5-Coder-0.5B-Instruct")
    ap.add_argument("--kb-dir", default=str(KB_DIR_DEFAULT))
    args = ap.parse_args(argv)
    if not args.smoke:
        ap.error("nothing to do: pass --smoke (real runs need W1 features)")
    res = _smoke(args.model, Path(args.kb_dir), Path(args.kb_dir))
    print(f"KB smoke -> {res['out']}")
    print(f"counters: {res['meta']['counters']}")
    for e in res["entries"]:
        print(json.dumps(e, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
