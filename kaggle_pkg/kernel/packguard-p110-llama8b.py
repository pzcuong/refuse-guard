#!/usr/bin/env python
# PackGuard round-16 Kaggle GPU kernel — template. Do not run directly;
# kaggle_pkg/make_kernels.py renders the two concrete kernels from this file.
#
# Self-contained: reads ONLY the mounted prompt dataset, runs greedy
# generation, appends checkpoints to /kaggle/working. No repo code, no
# network needs beyond the HF model download (internet enabled).
import json
import os
import re
import subprocess
import sys
import time
import hashlib
from datetime import datetime, timezone

# --- rendered config --------------------------------------------------------
KERNEL_SLUG = "packguard-p110-llama8b"
MODEL_ID = "unsloth/Llama-3.1-8B-Instruct"
MODEL_SLUG = "llama8b"
# task priority order: ladder rungs first (A0/A5/A1 harm question), then the
# safety arms (Qwen kernel only, per AMENDMENT-9)
TASKS = [("ladder", ["A0", "A5", "A1"])]
# ----------------------------------------------------------------------------

LADDER_FILE = "ladder_prompts_7b8b.jsonl"
SAFETY_FILE = "safety_prompts_7b.jsonl"
GEN_PARAMS = {  # frozen from the registered configs (r7 ladder / safety cfg)
    "ladder": {"max_new_tokens": 512, "max_input_tokens": 8192},
    "safety": {"max_new_tokens": 384, "max_input_tokens": 4096},
}
GEN_SEED = 1234
CHECKPOINT_EVERY = 20
MAX_WALL_S = 11.0 * 3600          # soft stop before the 12h commit-run cap
WORK = "/kaggle/working"
DTYPE_STR = "float16"             # T4/P100 have no bf16 -> fp16, disclosed

T0 = time.perf_counter()
_LOG = []


def log(msg):
    line = f"[{time.perf_counter() - T0:8.1f}s] {msg}"
    print(line, flush=True)
    _LOG.append(line)


def now_iso():
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# verdict parsing: byte-compatible replica of src.models.llm_harness.extract_json
# (order: <json> tags -> ```json fence -> first balanced block; tolerates a
# single trailing comma) + packguard.safety_port.parse_verdict coercion.
# ---------------------------------------------------------------------------
_FENCE_RE = re.compile(r"```(?:json|JSON)?\s*\n?(\{.*?\})\s*```", re.DOTALL)
_JSON_TAG_RE = re.compile(r"<json>\s*(\{.*?\})\s*</json>", re.DOTALL | re.IGNORECASE)


def _balanced_json_candidates(text):
    for start in (m.start() for m in re.finditer(r"\{", text)):
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            c = text[i]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
                continue
            if c == '"':
                in_str = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    yield text[start:i + 1]
                    break


def extract_json(text):
    if not isinstance(text, str):
        return None
    candidates = []
    m = _JSON_TAG_RE.search(text)
    if m:
        candidates.append(m.group(1))
    candidates.extend(_FENCE_RE.findall(text))
    candidates.extend(_balanced_json_candidates(text))
    for block in candidates:
        block = block.strip()
        try:
            obj = json.loads(block)
        except json.JSONDecodeError:
            try:
                obj = json.loads(re.sub(r",\s*([}\]])", r"\1", block))
            except json.JSONDecodeError:
                continue
        if isinstance(obj, dict):
            return obj
    return None


def coerce_vulnerable(parsed):
    if not isinstance(parsed, dict) or "vulnerable" not in parsed:
        return None
    v = parsed.get("vulnerable")
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, (int, float)) and v in (0, 1):
        return int(v)
    if isinstance(v, str) and v.strip() in ("0", "1"):
        return int(v.strip())
    return None


def sha16_prompt(system, user):
    return hashlib.sha256(
        json.dumps({"system": system, "user": user},
                   sort_keys=True).encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# input truncation: head+tail replica of llm_harness.truncate_input
# ---------------------------------------------------------------------------
def truncate_user(tok, user, max_input_tokens):
    ids = tok.encode(user)
    if len(ids) <= int(max_input_tokens):
        return user, {}
    budget = max(2, int(max_input_tokens) - 32)
    head_ids = ids[: budget // 2]
    tail_ids = ids[len(ids) - (budget - budget // 2):]
    omitted = len(ids) - len(head_ids) - len(tail_ids)
    marker = (f"\n\n[TRUNCATED {omitted} TOKENS from the middle of the input: "
              "head+tail kept to fit the model context; content in the middle "
              "was elided.]\n\n")
    new_user = (tok.decode(head_ids, skip_special_tokens=True) + marker +
                tok.decode(tail_ids, skip_special_tokens=True))
    return new_user, {"input_truncated": True,
                      "input_tokens_before": len(ids),
                      "input_tokens_omitted": omitted,
                      "max_input_tokens": int(max_input_tokens),
                      "truncation_strategy": "head+tail"}


# ---------------------------------------------------------------------------
def find_input_dir():
    """Locate the prompt dataset mount; tolerate slow input sync at session
    start (retry up to ~5 min) and search recursively. Raises with the
    observed listing so a genuinely empty mount is diagnosable from the log."""
    direct = "/kaggle/input/packguard-prompts-r16"
    deadline = time.perf_counter() + 300
    attempt = 0
    while time.perf_counter() < deadline:
        attempt += 1
        if os.path.exists(os.path.join(direct, LADDER_FILE)):
            return direct
        base = "/kaggle/input"
        if os.path.isdir(base):
            try:
                entries = os.listdir(base)
            except OSError:
                entries = []
            if attempt % 6 == 1:
                log(f"input scan #{attempt}: {entries}")
            for d in entries:
                root = os.path.join(base, d)
                if os.path.exists(os.path.join(root, LADDER_FILE)):
                    return root
                for dirpath, _dirnames, filenames in os.walk(root):
                    if LADDER_FILE in filenames:
                        return dirpath
        time.sleep(5)
    listing = None
    if os.path.isdir("/kaggle/input"):
        listing = []
        for dirpath, _d, files in os.walk("/kaggle/input"):
            listing.append(f"{dirpath}: {sorted(files)[:8]}")
    raise FileNotFoundError(
        f"prompt dataset not found under /kaggle/input after {attempt} "
        f"attempts; observed: {listing}")


def load_rows(path, rungs):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if r.get("rung") in rungs or r.get("arm") in rungs:
                rows.append(r)
    return rows


def out_path(task):
    return os.path.join(WORK, f"results_{MODEL_SLUG}_{task}.jsonl")


def done_keys(path):
    done = set()
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue  # torn tail line: keep earlier checkpoints
                done.add((r["sample_id"], r.get("rung") or r.get("arm")))
    return done


def main():
    os.makedirs(WORK, exist_ok=True)
    log(f"kernel {KERNEL_SLUG} model {MODEL_ID} tasks {TASKS}")
    import torch
    import transformers
    log(f"torch {torch.__version__} transformers {transformers.__version__} "
        f"cuda={torch.cuda.is_available()} n_gpu={torch.cuda.device_count()}")

    in_dir = find_input_dir()
    log(f"input dir {in_dir}")

    # transformers+accelerate are preinstalled on Kaggle; keep them satisfied
    # (fast no-op when already present) without force-upgrading torch.
    try:
        import accelerate  # noqa: F401
    except ImportError:
        subprocess.run([sys.executable, "-m", "pip", "install", "-q",
                        "transformers", "accelerate"], check=True)

    from transformers import AutoModelForCausalLM, AutoTokenizer

    queue = []
    for task, rungs in TASKS:
        fname = LADDER_FILE if task == "ladder" else SAFETY_FILE
        rows = load_rows(os.path.join(in_dir, fname), rungs)
        op = out_path(task)
        done = done_keys(op)
        pending = [r for r in rows if (r["sample_id"],
                                       r.get("rung") or r.get("arm")) not in done]
        log(f"task {task} rungs {rungs}: {len(rows)} rows, "
            f"{len(done)} already done, {len(pending)} pending")
        for r in pending:
            queue.append((task, r))
    n_total = len(queue)
    log(f"queue total pending {n_total}")
    summary_path = os.path.join(WORK, f"summary_{MODEL_SLUG}.json")
    if n_total == 0:
        with open(summary_path, "w") as f:
            json.dump({"kernel": KERNEL_SLUG, "model": MODEL_ID,
                       "queue_pending": 0, "all_done": True,
                       "date": now_iso()}, f, indent=1)
        log("nothing to do")
        return 0

    tok = AutoTokenizer.from_pretrained(MODEL_ID)
    log("tokenizer loaded; loading model fp16 device_map=auto ...")
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_ID, torch_dtype=torch.float16, attn_implementation="sdpa",
        device_map="auto", low_cpu_mem_usage=True)
    model.eval()
    rev = getattr(getattr(model, "config", None), "_commit_hash", None)
    log(f"model loaded revision={rev}")

    torch.manual_seed(GEN_SEED)
    n_done = n_err = 0
    err_by_task = {}
    for task, row in queue:
        if (time.perf_counter() - T0) > MAX_WALL_S:
            log("soft wall-clock budget reached — flushing and exiting")
            break
        rung = row.get("rung") or row.get("arm")
        gp = GEN_PARAMS[task]
        rec = {
            "sample_id": row["sample_id"],
            "rung": rung if task == "ladder" else None,
            "arm": rung if task == "safety" else None,
            "task": task,
            "model": MODEL_ID,
            "kernel": KERNEL_SLUG,
            "label": row.get("label"),
            "prompt_sha256_16": row.get("prompt_sha256_16"),
            "mock": False,
            "date": now_iso(),
            "revision_sha": rev,
            "dtype": DTYPE_STR,
            "gen": {"temperature": 0.0, "do_sample": False,
                    "max_new_tokens": gp["max_new_tokens"],
                    "max_input_tokens": gp["max_input_tokens"],
                    "seed": GEN_SEED},
        }
        try:
            user, tmeta = truncate_user(tok, row["user"], gp["max_input_tokens"])
            rec.update(tmeta)
            text_chat = tok.apply_chat_template(
                [{"role": "system", "content": row["system"]},
                 {"role": "user", "content": user}],
                tokenize=False, add_generation_prompt=True)
            enc = tok(text_chat, return_tensors="pt").to(model.device)
            t0 = time.perf_counter()
            with torch.no_grad():
                out = model.generate(
                    **enc, do_sample=False,
                    max_new_tokens=gp["max_new_tokens"],
                    repetition_penalty=1.0,
                    pad_token_id=tok.pad_token_id or tok.eos_token_id)
            lat = time.perf_counter() - t0
            gen_only = out[:, enc["input_ids"].shape[1]:]
            raw = tok.batch_decode(gen_only, skip_special_tokens=True)[0]
            parsed = extract_json(raw)
            rec.update({
                "raw_text": raw,
                "parsed": parsed,
                "vulnerable": coerce_vulnerable(parsed),
                "has_json": parsed is not None,
                "prompt_tokens": int(enc["input_ids"].shape[1]),
                "completion_tokens": int(gen_only.shape[1]),
                "latency_s": round(lat, 2),
            })
        except Exception as exc:  # disclosed skip; the run continues
            rec["status"] = "GEN_ERROR"
            rec["error"] = f"{type(exc).__name__}: {str(exc)[:300]}"
            n_err += 1
            err_by_task[task] = err_by_task.get(task, 0) + 1
            try:
                import torch as _t
                _t.cuda.empty_cache()
            except Exception:
                pass
        with open(out_path(task), "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
        n_done += 1
        if n_done % 10 == 0 or n_done == n_total:
            rate = n_done / (time.perf_counter() - T0) * 60.0
            eta = (n_total - n_done) / max(rate, 1e-9) * 60.0 if rate else None
            log(f"{n_done}/{n_total} done errors={n_err} "
                f"({rate:.1f} rows/min eta={eta and round(eta / 60, 1)}h)")
        if n_done % CHECKPOINT_EVERY == 0:
            with open(summary_path, "w") as f:
                json.dump({"kernel": KERNEL_SLUG, "model": MODEL_ID,
                           "rows_done": n_done, "rows_expected": n_total,
                           "errors": n_err, "all_done": False,
                           "date": now_iso()}, f, indent=1)

    with open(summary_path, "w") as f:
        json.dump({"kernel": KERNEL_SLUG, "model": MODEL_ID,
                   "rows_done": n_done, "rows_expected": n_total,
                   "errors": n_err, "errors_by_task": err_by_task,
                   "all_done": n_done == n_total,
                   "date": now_iso(), "log_tail": _LOG[-40:]}, f, indent=1)
    log(f"DONE {n_done}/{n_total} errors={n_err}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
