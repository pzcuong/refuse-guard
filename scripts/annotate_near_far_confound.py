#!/usr/bin/env python
"""Annotate bench_v1 rows with the near/far position-confound flag (audit V1 #2).

Finding being made traceable (reports/round2/V1_report.md §3 bug 2): C2a
("near", above the signature) and C2b ("far", top of file) are inserted at the
SAME byte offset for ~35% of rows — whenever the function starts at offset 0
(top_comment/docstring carriers) or the body is a single statement
(inline_comment carrier). Those rows carry a position LABEL without a position
SIGNAL, which would dilute any near-vs-far comparison (E4 / distance
ablation). This pass adds, per row:

    "near_far_confound": true|false
    "near_far_offsets":  {"c2a": int, "c2b": int}   (insertion offsets in C0)

and records the aggregate rate + method in bench_v1_meta.json. The jsonl is
modified in place (checksum refreshed); variant content is untouched, so the
deterministic-rebuild guard still passes field-by-field.

Run: .venv/bin/python scripts/annotate_near_far_confound.py
"""
from __future__ import annotations

import difflib
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
JSONL = PROJECT_ROOT / "data/benchmarks/bench_v1/bench_v1.jsonl"
META = PROJECT_ROOT / "data/benchmarks/bench_v1/bench_v1_meta.json"


def insertion_offset(orig: str, variant: str) -> int:
    """Offset in `orig` where the pure insertion starts (diff-based; the
    builder guarantees C2 variants are pure insertions into C0)."""
    for tag, i1, _i2, _j1, _j2 in difflib.SequenceMatcher(None, orig, variant, autojunk=False)\
            .get_opcodes():
        if tag in ("insert", "replace"):
            return i1
    return 0  # identical text


def main() -> int:
    rows = [json.loads(line) for line in
            JSONL.read_text(encoding="utf-8").splitlines() if line.strip()]
    n_confound = 0
    for row in rows:
        c0 = row["variants"]["C0"]["func"]
        off_a = insertion_offset(c0, row["variants"]["C2a"]["func"])
        off_b = insertion_offset(c0, row["variants"]["C2b"]["func"])
        row["near_far_confound"] = bool(off_a == off_b)
        row["near_far_offsets"] = {"c2a": off_a, "c2b": off_b}
        n_confound += int(row["near_far_confound"])

    payload = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)
    JSONL.write_text(payload, encoding="utf-8")
    sha = hashlib.sha256(JSONL.read_bytes()).hexdigest()

    meta = json.loads(META.read_text(encoding="utf-8"))
    meta["near_far_collapse"] = {
        "n_rows": len(rows),
        "n_confound": n_confound,
        "rate": round(n_confound / len(rows), 4),
        "definition": ("C2a (near) and C2b (far) carrier inserted at the same "
                       "byte offset in C0 -> the position label carries no "
                       "position signal for the row"),
        "method": ("difflib.SequenceMatcher first insert/replace opcode offset "
                   "of variant vs C0 (pure insertions, audit V1 #2); filter or "
                   "stratify on near_far_confound=false for near-vs-far analyses"),
        "measured_by": "scripts/annotate_near_far_confound.py",
        "date_utc": datetime.now(timezone.utc).isoformat(),
        "audit_ref": "reports/round2/V1_report.md §3 bug 2",
    }
    meta["checksum"] = {"algo": "sha256", "of": "bench_v1.jsonl", "value": sha,
                        "note": ("refreshed after the near_far_confound annotate pass "
                                 "(audit S / V1 #2); variant funcs untouched")}
    META.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"annotated {len(rows)} rows: near_far_confound={n_confound} "
          f"({n_confound / len(rows):.3f}); new sha256={sha[:16]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
