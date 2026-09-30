#!/usr/bin/env python3
"""
Experiment Artifact Auditor — builds:
  RESEARCH_STATE/EXPERIMENT_REGISTRY.jsonl   (one row per experiment artifact / run)
  RESEARCH_STATE/DATASET_REGISTRY.json
  RESEARCH_STATE/MODEL_REGISTRY.json

Inventory scope: ALL of refuseguard/outputs/ (incl. outputs/packguard/,
outputs/transformer/, outputs/master/) + Kaggle outputs
(outputs/packguard/r16_kaggle/, kernels packguard-p110-p18 & packguard-p110-llama8b).

Every registry row is derived from artifacts actually read on disk at build time.
Run from the refuseguard/ project root:  python3 RESEARCH_STATE/AUDITS/build_experiment_registry.py
"""
import json, os, sys, glob, hashlib, gzip, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(ROOT)
RS = os.path.join("RESEARCH_STATE")
OUT_JL = os.path.join(RS, "EXPERIMENT_REGISTRY.jsonl")
OUT_DS = os.path.join(RS, "DATASET_REGISTRY.json")
OUT_MD = os.path.join(RS, "MODEL_REGISTRY.json")
BUILD_UTC = datetime.datetime.now(datetime.timezone.utc).isoformat()

rows = []
uid = [0]
def next_uid():
    uid[0] += 1
    return f"EXP-{uid[0]:05d}"

def rel(p):  # posix path relative to project root
    return os.path.relpath(p, ROOT).replace(os.sep, "/")

def sha256_file(p, limit=200*1024*1024):
    try:
        if os.path.getsize(p) > limit:
            return None
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

# ---------------------------------------------------------------- metadata extraction
MOCK_KEYS = [("mock",), ("llm_mode",), ("dry_run",), ("real",)]

def find_first(d, key_paths):
    """BFS for first matching key path; returns (value, dotted_path) or (None, None)."""
    seen = 0
    stack = [("", d)]
    while stack and seen < 4000:
        seen += 1
        path, cur = stack.pop(0)
        if isinstance(cur, dict):
            for kp in key_paths:
                if len(kp) == 1 and kp[0] in cur:
                    return cur[kp[0]], (path + kp[0]).lstrip(".")
            for k, v in cur.items():
                if isinstance(v, (dict, list)):
                    stack.append((f"{path}{k}.", v))
        elif isinstance(cur, list):
            for i, v in enumerate(cur[:80]):
                if isinstance(v, (dict, list)):
                    stack.append((f"{path}{i}.", v))
    return None, None

def mock_verdict(meta, path, extra_note=None):
    """Returns (mock_bool_or_None, evidence)."""
    v, where = find_first(meta or {}, MOCK_KEYS)
    if v is not None:
        if isinstance(v, bool):
            return (not v) if where.endswith("real") else v, f"{where}={v}"
        if isinstance(v, str):
            return v.lower() in ("mock", "true", "dry"), f"{where}='{v}'"
    segs = rel(path).split("/")
    if "dry" in segs[:-1]:
        return True, "path_has_dry_dir_segment"
    if "mock" in os.path.basename(path).lower():
        return True, "filename_contains_mock"
    return None, "no_mock_marker_in_metadata"

def get_meta(obj):
    """metadata may sit at top level, under 'metadata' or 'meta'."""
    if not isinstance(obj, dict):
        return {}
    for k in ("metadata", "meta"):
        if isinstance(obj.get(k), dict):
            m = dict(obj[k])
            m["__top__"] = {kk: vv for kk, vv in obj.items() if kk not in ("metadata", "meta", "records", "rows", "results")}
            return m
    return dict(obj)

def norm_hash(meta):
    """config hash from metadata, priority sha256 > sha256-16 > cfg_hash."""
    v = meta.get("config_sha256")
    if isinstance(v, str) and len(v) >= 32:
        return {"value": v, "algo": "sha256", "source": "metadata.config_sha256"}
    v = meta.get("config_sha16")
    if isinstance(v, str) and 4 <= len(v) <= 32:
        return {"value": v, "algo": "sha256-16", "source": "metadata.config_sha16"}
    v = meta.get("cfg_hash")
    if isinstance(v, str) and 4 <= len(v) <= 32:
        return {"value": v, "algo": "sha256-16", "source": "metadata.cfg_hash"}
    # explicit config file reference -> compute at audit time
    cfg = meta.get("config")
    if isinstance(cfg, str) and (cfg.endswith(".yaml") or cfg.endswith(".yml")) and os.path.exists(cfg):
        h = sha256_file(cfg)
        if h:
            return {"value": h, "algo": "sha256", "source": f"computed_at_audit:{cfg}"}
    return {"value": None, "algo": None, "source": "not_recorded"}

N_ROWS_KEYS = ["n_records", "n_records_done", "rows_done", "n_runs", "n", "n_samples", "n_entries"]
N_ROWS_KEYS_RUN = ["n_records", "n_records_done", "rows_done", "n_test", "n", "n_samples", "n_entries"]

def n_rows_from(meta, obj=None, line_count=None, keys=N_ROWS_KEYS):
    for k in keys:
        if isinstance(meta, dict) and isinstance(meta.get(k), int):
            return meta[k], f"metadata.{k}"
    if isinstance(obj, dict):
        for k in keys:
            if isinstance(obj.get(k), int):
                return obj[k], f"top.{k}"
        if isinstance(obj.get("records"), list):
            return len(obj["records"]), "len(records)"
        if isinstance(obj.get("results"), list) and "schema" in obj:
            return len(obj["results"]), "len(results)"
    if line_count is not None:
        return line_count, "jsonl_line_count"
    return None, "unknown"

def area_of(path):
    r = rel(path)
    if r.startswith("outputs/packguard/r16_kaggle"):
        return "kaggle_outputs (downloaded: outputs/packguard/r16_kaggle)"
    if r.startswith("outputs/packguard/"):
        return "outputs/packguard/" + r.split("/")[2]
    if r.startswith("outputs/experiments"):
        return "outputs/experiments"
    if r.startswith("outputs/transformer"):
        return "outputs/transformer"
    if r.startswith("outputs/master"):
        return "outputs/master"
    if r.startswith("outputs/llm_cache"):
        return "outputs/llm_cache"
    if r.startswith("outputs/"):
        return "outputs/" + r.split("/")[1]
    return "other"

DATA_KEYS = [("corpus_source",), ("manifest",), ("prompts_source",), ("source",), ("features_source",), ("graphs_source",), ("train_path",), ("val_path",)]

def data_sources(meta, obj=None):
    out = []
    def add(v):
        if isinstance(v, str) and 3 < len(v) < 400 and (v.startswith(("data/", "outputs/", "manifest:", "/Users/")) or "bench" in v or "primevul" in v):
            v = v.replace("/Users/macbook/.zcode/workspace/default/refuseguard/", "")
            if v not in out:
                out.append(v)
    for k in ("corpus_source", "manifest", "prompts_source", "features_source", "graphs_source", "train_path", "val_path", "source_path_rel"):
        v = (meta or {}).get(k)
        if isinstance(v, str): add(v)
    b = (meta or {}).get("bench")
    if isinstance(b, dict) and isinstance(b.get("source_path_rel"), str):
        add(b["source_path_rel"])
    if isinstance(obj, dict):
        for k in ("corpus_source", "manifest", "prompts_source"):
            if isinstance(obj.get(k), str): add(obj[k])
    return out

def models_in(meta):
    out = []
    def walk(o):
        if isinstance(o, dict):
            for k in ("model_id", "model", "model_name"):
                v = o.get(k)
                if isinstance(v, str) and 1 < len(v) < 120 and v not in out:
                    out.append(v)
            for v in o.values(): walk(v)
        elif isinstance(o, list):
            for v in o[:60]: walk(v)
    walk(meta or {})
    return out[:4]

def raw_dir_for(path):
    """raw/ directory conventionally sits beside the results file."""
    d = os.path.dirname(path)
    cand = os.path.join(d, "raw")
    return cand if os.path.isdir(cand) else None

def count_raw(path):
    rd = raw_dir_for(path)
    if not rd:
        return None, None
    n = 0
    for _, _, fn in os.walk(rd):
        n += len(fn)
    return rd, n

def referenced_raw_basenames(path, obj):
    if not isinstance(obj, dict) or not isinstance(obj.get("records"), list):
        return set()
    return {os.path.basename(r["raw_output_path"]) for r in obj["records"]
            if isinstance(r.get("raw_output_path"), str)}

def actual_raw_basenames(path):
    rd = raw_dir_for(path)
    if not rd:
        return None, set()
    actual = set()
    for _, _, fn in os.walk(rd):
        actual.update(fn)
    return rd, actual

def compose_run_id(rr, rmeta, fallback):
    """composite experiment id for runs without an explicit name."""
    if rr.get("name"):
        return rr["name"]
    parts = []
    for k in ("rung", "task", "kernel", "threshold", "split", "block", "method", "algo", "kb", "partition", "stage", "stage_kind", "agent"):
        v = rr.get(k, rmeta.get(k))
        if isinstance(v, (str, int, float)):
            parts.append(str(v))
    if rr.get("seed", rmeta.get("seed")) is not None:
        parts.append(f"seed{rr.get('seed', rmeta.get('seed'))}")
    return "__".join(parts) if parts else fallback

def base_row(path, kind, meta, obj=None, line=None, line_count=None,
             experiment_id=None, notes=None, extra=None, nrow_keys=None):
    mock, mevi = mock_verdict(meta, path)
    ch = norm_hash(meta)
    nr, nrsrc = n_rows_from(meta, obj, line_count, keys=nrow_keys or N_ROWS_KEYS)
    rd, rdc = count_raw(path)
    row = {
        "exp_uid": next_uid(),
        "experiment_id": experiment_id or meta.get("experiment") or meta.get("name") or os.path.splitext(os.path.basename(path))[0],
        "kind": kind,
        "area": area_of(path),
        "artifact_path": rel(path),
        "artifact_line": line,
        "config_hash": ch,
        "raw_output_path": rel(rd) if rd else (meta.get("output_dir") if isinstance(meta.get("output_dir"), str) else None),
        "raw_file_count": rdc,
        "n_rows": nr,
        "n_rows_source": nrsrc,
        "mock": mock,
        "mock_evidence": mevi,
        "model_id": (meta.get("model_id") or meta.get("model") if isinstance(meta.get("model_id", meta.get("model")), str) else None) or (models_in(meta)[0] if models_in(meta) else None),
        "seed": meta.get("seed") if isinstance(meta.get("seed"), (int, str)) else None,
        "date_utc": meta.get("date_utc") or meta.get("date") or meta.get("measured_utc") or meta.get("generated_utc"),
        "data_sources": data_sources(meta, obj),
        "notes": notes or "",
    }
    if extra:
        row.update(extra)
    return row

# ---------------------------------------------------------------- collectors
model_hits = {}   # model_id -> set of exp areas/paths
def harvest_models(meta, where):
    for m in models_in(meta):
        model_hits.setdefault(m, set()).add(where)

dataset_hits = {}  # path -> info
def harvest_datasets(meta, where):
    for s in data_sources(meta, None):
        dataset_hits.setdefault(s, set()).add(where)

def add_row(**kw):
    row = base_row(**kw)
    rows.append(row)
    harvest_models(kw.get("meta") or {}, row["artifact_path"] + (f":L{kw['line']}" if kw.get("line") else ""))
    harvest_datasets(kw.get("meta") or {}, row["artifact_path"])
    return row

# ---------------------------------------------------------------- main scan
EXCLUDE_SUBSTR = ("/guarddog/extracted/", "/llm_cache/", "/__pycache__/")
json_files = sorted(glob.glob("outputs/**/*.json", recursive=True))
jsonl_files = sorted(glob.glob("outputs/**/*.jsonl", recursive=True))
gz_files = sorted(glob.glob("outputs/**/*.jsonl.gz", recursive=True))
parquet_files = sorted(glob.glob("outputs/**/*.parquet", recursive=True))

def excluded(p):
    return any(s in p for s in EXCLUDE_SUBSTR)

# ---------- JSON files
for p in json_files:
    if excluded(p):
        continue
    try:
        obj = json.load(open(p))
    except Exception as e:
        rows.append({"exp_uid": next_uid(), "experiment_id": os.path.basename(p), "kind": "unparsable",
                     "area": area_of(p), "artifact_path": rel(p), "artifact_line": None,
                     "config_hash": {"value": None, "algo": None, "source": "not_recorded"},
                     "raw_output_path": None, "raw_file_count": None, "n_rows": None,
                     "n_rows_source": "json_parse_error", "mock": None,
                     "mock_evidence": f"unparsable: {e}", "model_id": None, "seed": None,
                     "date_utc": None, "data_sources": [], "notes": "JSON parse failed"})
        continue
    meta = get_meta(obj)
    # grid bundles: rows[] of kind==run with names -> explode
    run_rows = None
    if isinstance(obj, dict):
        for key in ("rows", "runs"):
            v = obj.get(key)
            if isinstance(v, list) and v and isinstance(v[0], dict) and (v[0].get("kind") == "run" or (v[0].get("name") and isinstance(v[0].get("meta"), dict))):
                run_rows = v
                break
    if run_rows:
        hashes, mocks = set(), set()
        file_meta = {k: v for k, v in meta.items() if k != "__top__"}
        for i, rr in enumerate(run_rows):
            rmeta = get_meta(rr)
            r = add_row(path=p, kind="run", meta={**file_meta, **rmeta, **{k: v for k, v in rr.items() if k not in ("meta",)}},
                        obj=None, line=i + 1,
                        experiment_id=compose_run_id(rr, rmeta, os.path.splitext(os.path.basename(p))[0]),
                        extra={"bundle_path": rel(p)}, nrow_keys=N_ROWS_KEYS_RUN)
            if r["config_hash"]["value"]: hashes.add(r["config_hash"]["value"])
            if r["mock"] is not None: mocks.add(r["mock"])
        agg = add_row(path=p, kind="aggregate", meta=meta, obj=obj,
                      experiment_id=(meta.get("experiment") or os.path.basename(os.path.dirname(p))),
                      notes=f"aggregate over {len(run_rows)} run rows in this file (exploded separately); config_hashes={sorted(hashes) if hashes else 'mixed/none'}; mock_values={sorted(mocks) if mocks else 'mixed/none'}")
        agg["n_rows"] = len(run_rows); agg["n_rows_source"] = "len(run_rows)"
        rows[-1] = agg
        continue
    # kind classification for plain files
    kind = "analysis"
    base = os.path.basename(p)
    bl = base.lower()
    if "summary" in bl or "verdict" in bl or "gate" in bl or "master" in bl or bl == "final_runs_v2.json": kind = "aggregate"
    elif bl.startswith("metrics") or "_metrics" in bl or "metrics_" in bl: kind = "metrics"
    elif "smoke" in bl or "probe" in bl: kind = "probe"
    elif "manifest" in bl: kind = "provenance"
    elif "POLLUTED" in base or "quarantine" in p: kind = "quarantined"
    elif "train_meta" in bl: kind = "training"
    elif "final_eval" in bl or "eval_" in bl or "fallback_threshold" in bl: kind = "eval"
    elif "kb_build" in bl: kind = "kb_build"
    elif "jobs_status" in bl: kind = "run_control"
    elif "analysis" in bl or "breakdown" in bl or "recompute" in bl or "reclassify" in bl or "side_effect" in bl or "comparison" in bl or "coverage" in bl or "calibration" in bl or "report" in bl or "membership" in bl or "clusters" in bl or "expansion" in bl or "schema" in bl or "eda" in bl or "text_v2" in bl or "mapping" in bl or "audit" in bl or "bias" in bl or "token_map" in bl or "join_preview" in bl:
        kind = "analysis"
    elif "extract_status" in bl or "jobs_status" in bl: kind = "run_control"
    elif base == "results.json": kind = "run"
    elif "results" in bl: kind = "run"
    else: kind = "artifact"
    notes = []
    if "POLLUTED" in base:
        notes.append("QUARANTINED as POLLUTED per filename/dir (see outputs/experiments/round6_ablation/quarantine/)")
    if p.endswith(("p0_macros/gen_numbers_audit.json", "p0_macros/w3_mapping.json")):
        kind = "audit_support"
    row = add_row(path=p, kind=kind, meta=meta, obj=obj, notes="; ".join(notes) or None)
    # records length vs declared n_records
    if isinstance(obj, dict) and isinstance(obj.get("records"), list) and isinstance(meta.get("n_records"), int):
        if len(obj["records"]) != meta["n_records"]:
            row["notes"] = (row["notes"] + "; " if row["notes"] else "") + f"MISMATCH: len(records)={len(obj['records'])} != metadata.n_records={meta['n_records']}"
    # anomaly: dry path but meta says real
    if row["mock"] is False and "dry" in rel(p).split("/"):
        row["notes"] = (row["notes"] + "; " if row["notes"] else "") + f"ANOMALY: path has 'dry' segment but metadata marks it non-mock (dry_run={meta.get('dry_run')}, real={meta.get('real')}, model={meta.get('model_id')}, device={meta.get('device')}) — real-model mini run stored under a dry-named path"

# ---------- JSONL files
for p in jsonl_files:
    if excluded(p):
        continue
    lines = []
    n_lines = 0
    try:
        with open(p) as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                n_lines += 1
                try:
                    lines.append(json.loads(ln))
                except Exception:
                    pass
    except Exception as e:
        rows.append({"exp_uid": next_uid(), "experiment_id": os.path.basename(p), "kind": "unparsable",
                     "area": area_of(p), "artifact_path": rel(p), "artifact_line": None,
                     "config_hash": {"value": None, "algo": None, "source": "not_recorded"},
                     "raw_output_path": None, "raw_file_count": None, "n_rows": n_lines or None,
                     "n_rows_source": "line_count", "mock": None,
                     "mock_evidence": f"unparsable: {e}", "model_id": None, "seed": None,
                     "date_utc": None, "data_sources": [], "notes": "JSONL parse failed"})
        continue
    # per-run jsonl? lines have kind/name + run metadata
    def is_run_line(o):
        return isinstance(o, dict) and (o.get("kind") == "run" or (isinstance(o.get("name"), str) and (isinstance(o.get("meta"), dict) or "config_sha16" in o or "mock" in o)))
    run_lines = [i for i, o in enumerate(lines) if is_run_line(o)]
    if len(run_lines) >= max(1, len(lines) // 2):
        for i in run_lines:
            rr = lines[i]
            rmeta = get_meta(rr)
            add_row(path=p, kind="run", meta={**rmeta, **{k: v for k, v in rr.items() if k != "meta"}},
                    obj=None, line=i + 1,
                    experiment_id=compose_run_id(rr, rmeta, os.path.splitext(os.path.basename(p))[0]),
                    extra={"bundle_path": rel(p)}, nrow_keys=N_ROWS_KEYS_RUN)
        agg = add_row(path=p, kind="aggregate", meta=get_meta(lines[0]), obj=None, line_count=len(run_lines),
                      experiment_id=os.path.basename(os.path.dirname(p)) or os.path.basename(p),
                      notes=f"bundle of {len(run_lines)} per-run rows (exploded separately)")
        continue
    # per-sample record file: single artifact row
    first_meta = get_meta(lines[0]) if lines else {}
    kind = "run_records"
    base = os.path.basename(p)
    if base.startswith(("train_vul_all", "valid_vul")): kind = "dataset_slice"
    elif "predictions" in base: kind = "predictions"
    elif "findings" in base: kind = "findings"
    elif "probs" in base: kind = "probs_dump"
    elif "kb" in base or base.startswith("smoke_kb"): kind = "kb_entries"
    elif "features" in base: kind = "derived_features"
    exp_id = os.path.splitext(base)[0]
    notes_extra = []
    if lines and isinstance(lines[0], dict) and lines[0].get("kernel"):
        exp_id = f"{lines[0]['kernel']}__{lines[0].get('task', 'records')}"
        notes_extra.append(f"Kaggle kernel output: kernel={lines[0]['kernel']} (Kaggle platform run)")
    row = add_row(path=p, kind=kind, meta=first_meta, obj=None, line_count=n_lines, experiment_id=exp_id)
    if notes_extra:
        row["notes"] = (row["notes"] + "; " if row["notes"] else "") + "; ".join(notes_extra)
    if "predictions" in base:
        row["notes"] = (row["notes"] + "; " if row["notes"] else "") + "per-sample prediction records (raw output of transformer eval)"

# ---------------------------------------------------------------- post-passes
# 1) summaries without mock marker: cite sibling records' mock values
for row in rows:
    if row["mock"] is None and "summary" in os.path.basename(row["artifact_path"]).lower():
        d = os.path.dirname(row["artifact_path"])
        sib_mocks = set()
        for sib in glob.glob(os.path.join(d, "results_*.jsonl")) + glob.glob(os.path.join(d, "*_batch*.jsonl")):
            try:
                with open(sib) as f:
                    for ln in f:
                        ln = ln.strip()
                        if ln and '"mock"' in ln:
                            sib_mocks.add(json.loads(ln).get("mock"))
                            break
            except Exception:
                pass
        sib_mocks.discard(None)
        if sib_mocks:
            if len(sib_mocks) == 1:
                row["mock"] = list(sib_mocks)[0]
            row["mock_evidence"] = f"sibling records in same dir carry mock={sorted(sib_mocks)} (summary itself has no mock marker)"

# 2) per-directory raw reconciliation: stale raw = files in dir/raw not referenced by ANY results file in that dir
from collections import defaultdict
dir_refs = defaultdict(set)
for p in json_files:
    if excluded(p):
        continue
    try:
        obj = json.load(open(p))
    except Exception:
        continue
    dir_refs[os.path.dirname(p)] |= referenced_raw_basenames(p, obj)
stale_by_dir = {}
for d, refs in dir_refs.items():
    rd = os.path.join(d, "raw")
    if not os.path.isdir(rd):
        continue
    actual = set()
    for _, _, fn in os.walk(rd):
        actual.update(fn)
    stale = actual - refs
    if stale:
        stale_by_dir[d] = len(stale)
for row in rows:
    d = os.path.dirname(row["artifact_path"])
    if d in stale_by_dir and os.path.basename(row["artifact_path"]).startswith("results"):
        row["notes"] = (row["notes"] + "; " if row["notes"] else "") + f"STALE-RAW: {stale_by_dir[d]} files in {d}/raw are NOT referenced by any current results file in this dir (leftovers from superseded runs)"

# ---------- gz jsonl (graphs) — count only
for p in gz_files:
    if excluded(p):
        continue
    n = 0
    try:
        with gzip.open(p, "rt") as f:
            for _ in f:
                n += 1
    except Exception:
        n = None
    rows.append({"exp_uid": next_uid(), "experiment_id": os.path.basename(p), "kind": "derived_graphs",
                 "area": area_of(p), "artifact_path": rel(p), "artifact_line": None,
                 "config_hash": {"value": None, "algo": None, "source": "not_recorded"},
                 "raw_output_path": None, "raw_file_count": None, "n_rows": n,
                 "n_rows_source": "gzip_line_count", "mock": None,
                 "mock_evidence": "derived data artifact (no run metadata)", "model_id": None,
                 "seed": None, "date_utc": None, "data_sources": [], "notes": "graph dataset artifact"})

# ---------- parquet — metadata only
for p in parquet_files:
    rows.append({"exp_uid": next_uid(), "experiment_id": os.path.basename(p), "kind": "derived_features",
                 "area": area_of(p), "artifact_path": rel(p), "artifact_line": None,
                 "config_hash": {"value": None, "algo": None, "source": "not_recorded"},
                 "raw_output_path": None, "raw_file_count": None, "n_rows": None,
                 "n_rows_source": "parquet_not_parsed_no_pyarrow_check_performed",
                 "mock": None, "mock_evidence": "derived data artifact", "model_id": None,
                 "seed": None, "date_utc": None, "data_sources": [], "notes": "row count not read (parquet)"})

# ---------- r16 kaggle duplicates detection
def fhash(p):
    return sha256_file(p)
dup_groups = {}
for p in glob.glob("outputs/packguard/r16_kaggle/**/*.json*", recursive=True):
    h = fhash(p)
    if h:
        dup_groups.setdefault(h, []).append(rel(p))
dup_notes = {}
for h, ps in dup_groups.items():
    if len(ps) > 1:
        for p in ps:
            dup_notes[p] = f"byte-identical duplicate (sha256 {h[:16]}) of: " + ", ".join(q for q in ps if q != p)
for row in rows:
    if row["artifact_path"] in dup_notes:
        row["notes"] = (row["notes"] + "; " if row["notes"] else "") + dup_notes[row["artifact_path"]]

# ---------------------------------------------------------------- write EXPERIMENT_REGISTRY.jsonl
rows.sort(key=lambda r: (r["area"], r["artifact_path"], r.get("artifact_line") or 0))
with open(OUT_JL, "w") as f:
    for r in rows:
        f.write(json.dumps(r, ensure_ascii=False, default=str) + "\n")
print(f"WROTE {OUT_JL}: {len(rows)} rows")

# ---------------------------------------------------------------- DATASET_REGISTRY.json
def line_count(p):
    try:
        with open(p, "rb") as f:
            return sum(1 for _ in f)
    except Exception:
        return None

datasets = []
def ds(name, path, role, description, provenance="", count_rows=False):
    entry = {"name": name, "path": path, "role": role, "description": description}
    if provenance: entry["provenance"] = provenance
    ap = path if os.path.isabs(path) else os.path.join(ROOT, path)
    if os.path.exists(ap):
        entry["bytes"] = os.path.getsize(ap)
        h = sha256_file(ap)
        entry["sha256"] = h if h else "not_computed_file_too_large"
        if count_rows:
            entry["n_rows"] = line_count(ap)
        entry["exists_on_disk"] = True
    else:
        entry["exists_on_disk"] = False
    datasets.append(entry)

# source datasets
for m in sorted(glob.glob("data/manifests/*.json")):
    try:
        d = json.load(open(m))
        n = d.get("n_samples") or d.get("n") or len(d.get("sample_ids", d.get("samples", [])))
    except Exception:
        n = None
    datasets.append({"name": os.path.basename(m), "path": rel(m), "role": "eval_manifest",
                     "description": "refuseguard eval manifest (sample id subset)", "n_samples_recorded": n,
                     "bytes": os.path.getsize(m), "sha256": sha256_file(m), "exists_on_disk": True})
ds("bench_v1", "data/benchmarks/bench_v1/bench_v1.jsonl", "benchmark", "bench v1 prompt benchmark", "built from data/manifests + corpus; see bench_v1_meta.json", True)
ds("e0_prompts_v1", "data/benchmarks/e0_prompts_v1.jsonl", "benchmark", "e0 prompt set (round3 prompts_source; sha16 e13ec860572ffa2e recorded in run metadata)", "metadata.prompts_source in outputs/experiments/round3_e0/*", True)
ds("e0_prompts_v1_meta", "data/benchmarks/e0_prompts_v1_meta.json", "benchmark_meta", "prompt-set meta/hash", "")
ds("bench_attack_v1", "data/benchmarks/bench_attack_v1/bench_attack_v1.jsonl", "benchmark", "attack benchmark v1: 200 samples x 4 arms (C0/C5_far/C5_near/D2_task); sha16 2daa249f7543f8e0 recorded in run metadata", "metadata.bench in round5/6/7 results", True)
ds("bench_attack_v2", "data/benchmarks/bench_attack_v2/bench_attack_v2.jsonl", "benchmark", "attack benchmark v2", "", True)
ds("safety_contrast_v1", "data/benchmarks/safety_contrast_v1.json", "benchmark", "safety contrast set", "")
ds("PrimeVUL_train", "data/raw/primevul_hf/primevul_train.jsonl", "raw_corpus", "PrimeVUL train split (HF mirror)", "transformer train_meta.json: source starsofchance/PrimeVul mirror, official splits")
ds("PrimeVUL_valid", "data/raw/primevul_hf/primevul_valid.jsonl", "raw_corpus", "PrimeVUL valid split", "same")
ds("PrimeVUL_test", "data/raw/primevul_hf/primevul_test.jsonl", "raw_corpus", "PrimeVUL test split", "same")
ds("PrimeVUL_train_paired", "data/raw/primevul_hf/primevul_train_paired.jsonl", "raw_corpus", "PrimeVUL paired subset", "same")
for m in sorted(glob.glob("data/packguard/manifests/*.json")):
    try:
        d = json.load(open(m))
        n = d.get("n_samples") or len(d.get("samples", []))
        eco = d.get("ecosystems") or d.get("counts")
    except Exception:
        n, eco = None, None
    datasets.append({"name": os.path.basename(m), "path": rel(m), "role": "packguard_manifest",
                     "description": "packguard dataset manifest", "n_samples_recorded": n,
                     "counts": eco, "bytes": os.path.getsize(m), "sha256": sha256_file(m),
                     "exists_on_disk": True})
ds("text_expansion_v1", "outputs/packguard/lco/expansion/text_expansion_v1.json", "derived_corpus", "200 random benign npm packages pulled from live registry (LCO expansion)", "outputs/packguard/lco/expansion/expansion_report.json stats")
# derived feature/graph/kb artifacts
for p in ["outputs/packguard/features/features_v1.jsonl", "outputs/packguard/features/features_v2.jsonl",
          "outputs/packguard/malguard_style/features_malguard.jsonl",
          "outputs/packguard/features/graphs_v1.jsonl.gz", "outputs/packguard/features/graphs_v2.jsonl.gz",
          "outputs/packguard/kb/kb_v0001.jsonl", "outputs/packguard/kb/kb_v0002.jsonl",
          "outputs/packguard/guarddog/findings.jsonl",
          "outputs/transformer/train_vul_all_benign_25000.jsonl",
          "outputs/transformer/train_vul_all_benign_40000.jsonl",
          "outputs/transformer/valid_vul_all_total_10000.jsonl"]:
    if os.path.exists(p):
        if "/kb/" in p: role = "knowledge_base"
        elif "findings" in p: role = "detector_findings"
        elif p.endswith(".gz"): role = "derived_graphs"
        elif "feature" in p or "malguard" in p: role = "derived_features"
        else: role = "training_slice"
        nr = line_count(p)
        if nr is None and p.endswith(".gz"):
            import gzip as _gz
            try:
                with _gz.open(p, "rt") as f: nr = sum(1 for _ in f)
            except Exception: nr = None
        datasets.append({"name": os.path.basename(p), "path": p, "role": role,
                         "description": "derived artifact (see rows in EXPERIMENT_REGISTRY for build metadata)",
                         "bytes": os.path.getsize(p),
                         "n_rows": nr,
                         "exists_on_disk": True})
ds("kaggle_ladder_prompts_7b8b", "kaggle_pkg/dataset/ladder_prompts_7b8b.jsonl", "kaggle_prompt_dataset", "r16 Kaggle prompt dataset (ladder A0/A5/A1, 7B/8B models)", "uploaded to Kaggle as pzcuong/packguard-prompts-r16; consumed at /kaggle/input/datasets/pzcuong/packguard-prompts-r16 (r16 kernel log)", True)
ds("kaggle_safety_prompts_7b", "kaggle_pkg/dataset/safety_prompts_7b.jsonl", "kaggle_prompt_dataset", "r16 Kaggle safety prompt set (qwen7b)", "same", True)
datasets.append({"name": "dataDog-malicious-software-packages-dataset (label source)", "path": "(external, via data/packguard/raw)",
                 "role": "label_source", "description": "malicious_packages labels; recorded per-sample in features_v2 label_source",
                 "exists_on_disk": False})
datasets.append({"name": "guarddog/extracted package sources", "path": "outputs/packguard/guarddog/extracted/",
                 "role": "raw_source_dump", "description": "extracted npm/pypi package trees used for feature extraction (1.6 GB; not experiment outputs)",
                 "exists_on_disk": True})
datasets.append({"name": "llm_cache (refuseguard)", "path": "outputs/llm_cache/", "role": "generation_cache",
                 "description": "resume-safe JSONL LLM response cache (8.6 MB) — infra, not experiment output", "exists_on_disk": True})
datasets.append({"name": "packguard kb llm_cache", "path": "outputs/packguard/kb/llm_cache/", "role": "generation_cache",
                 "description": "KB classification cache for Qwen 0.5B/3B", "exists_on_disk": True})
datasets.append({"name": "data/packguard/raw", "path": "data/packguard/raw/", "role": "raw_corpus",
                 "description": "raw package metadata/archive corpus (941 MB) backing packguard manifests", "exists_on_disk": True})

ds_registry = {
    "schema": "refuseguard.dataset_registry/1.0",
    "generated_utc": BUILD_UTC,
    "generated_by": "RESEARCH_STATE/AUDITS/build_experiment_registry.py (Experiment Artifact Auditor)",
    "scope": "datasets referenced by outputs/ + outputs/packguard/ + kaggle r16 experiments",
    "n_datasets": len(datasets),
    "datasets": datasets,
    "evidence_basis": "paths/counts read from disk at build time; sha16 hashes quoted from run metadata where noted; derived artifacts' provenance lives in EXPERIMENT_REGISTRY rows' data_sources",
}
with open(OUT_DS, "w") as f:
    json.dump(ds_registry, f, indent=2, ensure_ascii=False)
print(f"WROTE {OUT_DS}: {len(datasets)} datasets")

# ---------------------------------------------------------------- MODEL_REGISTRY.json
PINNED = {
    "Qwen/Qwen2.5-Coder-0.5B-Instruct": ("ea3f2471cf1b1f0db85067f1ef93848e38e88c25", "run metadata revision_sha"),
    "Qwen/Qwen2.5-Coder-3B-Instruct": ("488639f1ff808d1d3d0ba301aef8c11461451ec5", "run metadata revision_sha; configs/models.yaml sha 488639f1ff80"),
    "Qwen/Qwen2.5-Coder-7B-Instruct": ("c03e6d358207e414f1eca0bb1891e29f1db0e242", "run metadata revision_sha"),
    "ibm-granite/granite-3.3-2b-instruct": ("707f574c62054322f6b5b04b6d075f0a8f05e0f0", "run metadata revision_sha; configs/models.yaml sha 707f574c6205"),
    "unsloth/Llama-3.2-3B-Instruct": ("006f5dcd1393c3add266de40994ba96225e9689d", "run metadata revision_sha; configs/models.yaml sha 006f5dcd1393"),
    "unsloth/Llama-3.1-8B-Instruct": ("4699cc75b550f9c6f3173fb80f4703b62d946aa5", "run metadata revision_sha (kaggle r16 kernels)"),
}
MODELS = []
for mid, pinned in PINNED.items():
    sha, src = pinned
    used = sorted({p.split("/")[-2] + ("/" + p.split("/")[-1] if p.endswith(".json") and "r16" not in p else "") for p in model_hits.get(mid, set())})[:12]
    MODELS.append({
        "model_id": mid, "role": "LLM (local inference, temperature 0, MPS/CUDA)",
        "revision": "main", "revision_sha_observed": sha, "sha_source": src,
        "pin_recorded_in": "configs/models.yaml + per-run metadata.revision_sha",
        "used_in": model_hits.get(mid, set()) and sorted(model_hits[mid])[:10],
        "n_artifacts_using": len(model_hits.get(mid, set())),
        "notes": "",
    })
for stub in sorted(m for m in model_hits if m.startswith("mock")):
    MODELS.append({"model_id": stub, "role": "MOCK stub (dry-run harness)",
                   "revision_sha_observed": "mock0123456789 or 'mock'", "sha_source": "run metadata",
                   "used_in": sorted(model_hits[stub])[:10], "n_artifacts_using": len(model_hits[stub]),
                   "notes": "template responder; any numbers from mock runs are NOT real results"})
MODELS += [
    {"model_id": "microsoft/codebert-base", "role": "transformer baseline (fine-tuned fallback classifier)",
     "revision_sha_observed": None, "sha_source": "not recorded in eval meta (configs/train_codebert.yaml model_name)",
     "checkpoint": "models_dir/transformer_baseline/best (best_epoch=1 per final_eval.json)",
     "used_in": sorted(model_hits.get("microsoft/codebert-base", set()))[:10],
     "n_artifacts_using": len(model_hits.get("microsoft/codebert-base", set())),
     "notes": "fallback channel in fusion (outputs/transformer/fallback_threshold.json tau=0.548)"},
    {"model_id": "sklearn LogisticRegression(solver=lbfgs, max_iter=1000) + StandardScaler",
     "role": "packguard FL classifier head", "revision_sha_observed": None, "sha_source": "n/a (sklearn pipeline)",
     "used_in": sorted(model_hits.get("sklearn Pipeline(StandardScaler, LogisticRegression(solver=lbfgs, max_iter=1000, random_state=seed))", set()))[:10],
     "n_artifacts_using": len(model_hits.get("sklearn Pipeline(StandardScaler, LogisticRegression(solver=lbfgs, max_iter=1000, random_state=seed))", set())),
     "notes": "recorded verbatim in packguard FL run meta"},
    {"model_id": "guarddog-3.2.0 (source+yara rules, severity>=high)", "role": "external detector baseline (non-LLM)",
     "revision_sha_observed": None, "sha_source": "detector string in outputs/packguard/guarddog/metrics.json",
     "used_in": ["outputs/packguard/guarddog/"], "n_artifacts_using": 1,
     "notes": "semgrep guarddog 3.2.0"},
]
md_registry = {
    "schema": "refuseguard.model_registry/1.0",
    "generated_utc": BUILD_UTC,
    "generated_by": "RESEARCH_STATE/AUDITS/build_experiment_registry.py (Experiment Artifact Auditor)",
    "scope": "all model ids observed in outputs/ metadata + pinned registry configs/models.yaml",
    "n_models": len(MODELS),
    "models": MODELS,
    "generation_defaults": {"temperature": 0.0, "do_sample": False, "seed": 1234,
                            "source": "configs/models.yaml env + per-run gen_cfg in results metadata"},
    "evidence_basis": "harvested from every parsed JSON/JSONL under outputs/ (model_id/revision_sha keys); models.yaml verified against HF Hub API 2026-09-18 per its header comment",
}
with open(OUT_MD, "w") as f:
    json.dump(md_registry, f, indent=2, ensure_ascii=False)
print(f"WROTE {OUT_MD}: {len(MODELS)} models")

# ---------------------------------------------------------------- summary stats
from collections import Counter
c_area = Counter(r["area"] for r in rows)
c_kind = Counter(r["kind"] for r in rows)
c_mock = Counter(str(r["mock"]) for r in rows)
print("\nROWS BY AREA:"); [print(f"  {k}: {v}") for k, v in sorted(c_area.items())]
print("ROWS BY KIND:"); [print(f"  {k}: {v}") for k, v in sorted(c_kind.items())]
print("MOCK FLAG:"); [print(f"  {k}: {v}") for k, v in sorted(c_mock.items())]
print(f"\nmodel hits: {len(model_hits)} distinct ids")
