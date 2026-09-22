"""Round-9 W2 [Q2]: KB-v3 coverage analysis over graphs_v2 (CPU-only).

Computes, from the REAL graphs (not features rows, same source as the build
script): type-level coverage (unique APIs in KB), instance-level coverage
(api_call occurrences covered), split by label and language; UNSURE rate;
and the KB-augmented feature deltas (packguard.kb.kb_features) for every
sample under KB v2 (round-8 state) vs KB v3 (full universe).  Writes
outputs/experiments/round9_kb/coverage_v3.json.  No generation, no GPU.
"""
from __future__ import annotations

import gzip
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path("/Users/macbook/.zcode/workspace/default/refuseguard")
sys.path.insert(0, str(ROOT))

from packguard.kb import KnowledgeBase, kb_features  # noqa: E402

GRAPHS = ROOT / "outputs/packguard/features/graphs_v2.jsonl.gz"
FEATURES = ROOT / "outputs/packguard/features/features_v2.jsonl"
KB_DIR = ROOT / "outputs/packguard/kb"
OUT_DIR = ROOT / "outputs/experiments/round9_kb"


def load_label_map() -> dict[str, dict]:
    """sample_id -> {label, ecosystem} from the DATASET feature rows.

    FIX (round-9 F, audit V2#B7/#B6): the old per-sid substring rule
    (``"-malicious" in sid``) missed the 80 ``*-compromised_lib-*``
    samples (label 1) and the ``language``/``lang`` keys do not exist on
    graph records. Labels now come from features_v2 (the same labels the
    classifier trains on); language comes from the dataset ``ecosystem``
    field (npm/pypi — a source domain, not a natural language).
    """
    mapping: dict[str, dict] = {}
    with FEATURES.open(encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            mapping[str(r["sample_id"])] = {
                "label": int(r["label"]),
                "ecosystem": str(r.get("ecosystem", "?")),
            }
    return mapping


def load_kb_state(version_file: Path) -> dict[str, dict]:
    entries: dict[str, dict] = {}
    with version_file.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rec = json.loads(line)
                if rec.get("api"):
                    entries[rec["api"]] = rec
    return entries


def main() -> int:
    kb_v3 = KnowledgeBase(KB_DIR)          # loads latest (v3 == kb_v0002)
    v3_state = dict(kb_v3.entries)
    v2_state = load_kb_state(KB_DIR / "kb_v0001.jsonl")  # round-8 snapshot
    label_map = load_label_map()

    n_types = 0
    type_df: Counter = Counter()
    inst_total = 0
    per_label = {1: Counter(), 0: Counter()}          # instance counts
    per_lang = Counter()
    unsure_instances = 0
    feat_rows = []
    with gzip.open(GRAPHS, "rt", encoding="utf-8") as f:
        for line in f:
            g = json.loads(line)
            sid = str(g.get("sample_id", ""))
            meta = label_map.get(sid)
            if meta is None:
                raise KeyError(
                    f"sample {sid!r} missing from features_v2 label map")
            label = meta["label"]
            lang = meta["ecosystem"]
            calls = [str(n.get("api")).strip() for n in g.get("nodes", [])
                     if n.get("api")]
            if not calls:
                continue
            n_types += len({c for c in calls})
            for c in set(calls):
                type_df[c] += 1
            inst_total += len(calls)
            per_label[label].update(calls)
            per_lang[lang] += len(calls)
            for c in calls:
                e = v3_state.get(c)
                if e is None or e.get("unsure") or \
                        e.get("semantic_class") == "UNSURE":
                    unsure_instances += 1
            f3 = kb_features(calls, kb_v3)
            # KB-v2 features: wrap the round-8 state in a stub KB
            class _Stub:
                def lookup(self, api):
                    return v2_state.get(str(api).strip())
            f2 = kb_features(calls, _Stub())  # type: ignore[arg-type]
            feat_rows.append({"sample_id": sid, "label": label,
                              "kb2": f2, "kb3": f3})

    uniq_types = len(type_df)
    covered_types_v2 = sum(1 for a in type_df if a in v2_state and
                           not v2_state[a].get("unsure"))
    covered_types_v3 = sum(1 for a in type_df if a in v3_state and
                           not v3_state[a].get("unsure"))
    inst_cov_v2 = sum(c for a, c in type_df.items() if a in v2_state and
                      not v2_state[a].get("unsure"))
    inst_cov_v3 = inst_total - unsure_instances

    def _mean(rows, which, key):
        vals = [r[which][key] for r in rows]
        return round(sum(vals) / len(vals), 6) if vals else None

    out = {
        "date": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc).isoformat(),
        "kb_files": {"v2_round8": "outputs/packguard/kb/kb_v0001.jsonl",
                     "v3_round9": "outputs/packguard/kb/kb_v0002.jsonl"},
        "kb_v3_stats": kb_v3.stats(),
        "graphs_v2": {"n_samples": len(feat_rows),
                      "unique_api_types": uniq_types,
                      "api_instances_total": inst_total},
        "coverage": {
            "v2_round8": {"types": covered_types_v2,
                          "type_pct": round(100 * covered_types_v2 / uniq_types, 2),
                          "instances": inst_cov_v2,
                          "instance_pct": round(100 * inst_cov_v2 / inst_total, 2)},
            "v3_round9": {"types": covered_types_v3,
                          "type_pct": round(100 * covered_types_v3 / uniq_types, 2),
                          "instances": inst_cov_v3,
                          "instance_pct": round(100 * inst_cov_v3 / inst_total, 2)},
            "unsure_entries": sum(1 for e in v3_state.values() if e.get("unsure")),
            "unsure_instances_v3": unsure_instances,
        },
        "instances_by_label": {
            "malicious": sum(per_label[1].values()),
            "benign": sum(per_label[0].values())},
        "instances_by_language": dict(per_lang),
        "label_rule": ("label joined per sample_id from features_v2.jsonl "
                       "(dataset label; includes compromised_lib samples); "
                       "language = dataset ecosystem (npm/pypi). "
                       "Round-9 F fix of audit V2#B7/#B6."),
        "kb_feature_means": {
            "v2": {k: _mean(feat_rows, "kb2", k) for k in
                   ("kb_risk_ratio", "kb_confidence", "kb_unsure_ratio")},
            "v3": {k: _mean(feat_rows, "kb3", k) for k in
                   ("kb_risk_ratio", "kb_confidence", "kb_unsure_ratio")},
            "note": "means over graphs_v2 samples (n=%d); kb_features() is "
                    "packguard.kb's read-only function" % len(feat_rows)},
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "coverage_v3.json").write_text(
        json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({k: out[k] for k in
                      ("kb_v3_stats", "graphs_v2", "coverage",
                       "kb_feature_means")}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
