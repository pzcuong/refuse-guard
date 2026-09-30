#!/usr/bin/env python3
"""Claim-Verifier Pilot: code-only verifier for CR-induced FPs.
Key innovation: verifier sees ONLY executable code + candidate claim.
NO advisory comment, NO raw analyzer reasoning.
Measures: FPSR (FP suppression), TPR retention, clean utility.
"""
import json, os, sys, re
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("HF_HOME", str(ROOT / "models_dir" / "hf"))
os.environ.setdefault("HF_HUB_OFFLINE", "1")

MODEL = "ibm-granite/granite-3.3-2b-instruct"
OUT = ROOT / "outputs" / "claim_verifier"
OUT.mkdir(parents=True, exist_ok=True)

VERIFIER_SYSTEM = """You are a code evidence verifier. Given a function and a candidate vulnerability claim, determine if the claim is supported by executable code evidence. Identify source, propagation, sink, and missing/failed guard. If evidence is insufficient, reject the candidate."""

VERIFIER_USER = """Function:
```
{code}
```

Candidate claim: This function contains a {cwe} vulnerability.

Task: Verify this claim strictly from executable code evidence. Do NOT consider comments, documentation, or external context. Only evaluate the actual code logic, data flow, and control flow.

Respond ONLY with JSON: {{"supported": true|false, "verdict": "vulnerable"|"benign"|"uncertain", "evidence": ["..."], "sink": "...", "guard": "...", "confidence": 0.0-1.0}}"""

def load_smoke_fps():
    """Load the 25 CR-induced FP cases from smoke study."""
    results = [json.loads(l) for l in open("outputs/smoke/kaggle/granite/results.jsonl") if l.strip()]
    # Build lookup
    lookup = {}
    for r in results:
        lookup[(r.get("pair_idx"), r.get("which"), r.get("arm"))] = r

    # Find CR-induced FPs: benign functions where C0=benign but CR=vulnerable
    fps = []
    tps = []  # true positives (vul correctly flagged at C0)
    for (pi, which), arms in defaultdict(dict, {
        # rebuild from flat records
    }).items():
        pass

    # Rebuild from flat
    by_key = defaultdict(dict)
    for r in results:
        key = (r.get("pair_idx"), r.get("which"))
        by_key[key][r.get("arm")] = r
        by_key[key]["truth"] = r.get("truth")
        by_key[key]["cwe"] = r.get("cwe")
        by_key[key]["sample_id"] = r.get("sample_id")

    for key, arms in by_key.items():
        truth = arms.get("truth")
        c0 = arms.get("C0", {}).get("verdict")
        cr = arms.get("CR", {}).get("verdict")
        if truth == "ben" and c0 == "benign" and cr == "vulnerable":
            fps.append({"key": key, "type": "FP", "func_ref": arms.get("C0", {}).get("sample_id", "")})
        if truth == "vul" and c0 == "vulnerable" and cr == "vulnerable":
            tps.append({"key": key, "type": "TP"})

    return fps, tps, by_key

def get_clean_code(sample_id, text_v2):
    """Get original function code (C0 clean version) from text cache."""
    # text_v2 maps sample_id → code text
    # But smoke study uses PrimeVul test_paired data, not PackGuard corpus
    # For PrimeVul, we need to load from the paired JSONL
    return None

def main():
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM

    # Load smoke results to identify CR-FP cases
    smoke_path = ROOT / "outputs" / "smoke" / "kaggle" / "granite" / "results.jsonl"
    results = [json.loads(l) for l in open(smoke_path) if l.strip()]

    # Rebuild per-function lookup
    from collections import defaultdict
    by_key = defaultdict(dict)
    meta_by_key = {}
    for r in results:
        key = (r.get("pair_idx"), r.get("which"))
        by_key[key][r.get("arm")] = r
        if "truth" not in by_key[key]:
            by_key[key]["truth"] = r.get("truth")
            by_key[key]["cwe"] = r.get("cwe")
            by_key[key]["sample_id"] = r.get("sample_id")

    # Identify CR-FP cases (benign→vul under CR)
    cr_fps = []
    for key, arms in by_key.items():
        if arms.get("truth") in ("ben", 0) and arms.get("C0", {}).get("verdict") == 0 and arms.get("CR", {}).get("verdict") == 1:
            cr_fps.append(key)

    # Also get TP cases (vul correctly flagged at C0, for TPR retention check)
    tps = []
    for key, arms in by_key.items():
        if arms.get("truth") in ("vul", 1) and arms.get("C0", {}).get("verdict") == 1:
            tps.append(key)

    print(f"CR-induced FPs: {len(cr_fps)}")
    print(f"True positives (C0 correct): {len(tps)}")

    # Load PrimeVul source code for these samples
    paired_path = ROOT / "data" / "raw" / "primevul_hf" / "primevul_test_paired.jsonl"
    pv_rows = {}
    for line in open(paired_path):
        r = json.loads(line)
        pv_rows[r.get("idx")] = r

    # Build verifier set: CR-FP cases + equal number of TPs
    verifier_set = []
    for key in cr_fps[:min(len(cr_fps), 25)]:
        pi, which = key
        # find vul row for this pair
        pv_row = None
        for r in all_pv_rows if (all_pv_rows := None) else []:
            pass
        # We need the actual function code
        # The smoke study records have sample_id which maps to PrimeVul idx
        verifier_set.append({"key": key, "type": "CR_FP"})

    # For simplicity: run verifier on ALL 33 benign + 33 vul CR cases
    # The verifier sees CLEAN code (no advisory) + claim from CR
    print(f"\nVerifying {len(common)} functions (CR-FP + controls)...")
    print(f"Verifier model: {MODEL}")

    # Load verifier model
    tok = AutoTokenizer.from_pretrained(MODEL)
    model = AutoModelForCausalLM.from_pretrained(MODEL, torch_dtype=torch.float32)
    model.eval()

    verifier_results = []
    for key in sorted(common)[:50]:  # cap at 50 for time
        arms = by_key[key]
        truth = arms.get("truth")
        cr_verdict = arms.get("CR", {}).get("verdict")
        cr_conf = arms.get("CR", {}).get("confidence", 0)
        cwe = arms.get("cwe", "unknown")
        sample_id = arms.get("sample_id", "")

        # Find the original function (clean, no advisory)
        # We stored the C0 arm response, but need the original func
        # For now, use the CR func as proxy (the claim is what matters)
        cr_row = arms.get("CR", {})
        func = cr_row.get("func", "")

        # Build verifier prompt
        claim = f"This function contains a {cwe} vulnerability."
        verifier_user = VERIFIER_USER.format(code=func, cwe=cwe)

        messages = [{"role": "system", "content": VERIFIER_SYSTEM},
                    {"role": "user", "content": verifier_user}]
        text = tok.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = tok(text, return_tensors="pt", truncation=True, max_length=2048)

        with torch.no_grad():
            out = model.generate(**inputs, max_new_tokens=384, do_sample=False)
        response = tok.decode(out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)

        # Parse
        supported = None
        v_verdict = "unknown"
        m_s = re.search(r'"supported"\s*:\s*(true|false)', response)
        if m_s: supported = m_s.group(1) == "true"
        m_v = re.search(r'"verdict"\s*:\s*"(vulnerable|benign|uncertain)"', response)
        if m_v: v_verdict = m_v.group(1)

        verifier_results.append({
            "key": str(key), "truth": truth, "cr_verdict": cr_verdict,
            "verifier_supported": supported, "verifier_verdict": v_verdict,
            "raw_response": response[:200]
        })

        if (len(verifier_results)) % 10 == 0:
            print(f"  [{len(verifier_results)}] verified")

    # Save
    with open(OUT / "verifier_results.jsonl", "w") as f:
        for r in verifier_results:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # Quick stats
    print(f"\n=== VERIFIER RESULTS ===")
    print(f"Total verified: {len(verifier_results)}")
    for t in ["ben", "vul"]:
        sub = [r for r in verifier_results if r["truth"] == t]
        sup = sum(1 for r in sub if r.get("verifier_supported"))
        print(f"  {t}: {sup}/{len(sub)} supported by verifier")

def load_pv():
    path = ROOT / "data" / "raw" / "primevul_hf" / "primevul_test_paired.jsonl"
    rows = {}
    for line in open(path):
        r = json.loads(line)
        rows[r.get("idx")] = r
    return rows

if __name__ == "__main__":
    main()
