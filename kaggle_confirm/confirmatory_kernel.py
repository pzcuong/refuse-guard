import json, os, glob
from pathlib import Path
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

MODEL = "ibm-granite/granite-3.3-2b-instruct"
print("Loading", MODEL)
tok = AutoTokenizer.from_pretrained(MODEL)
model = AutoModelForCausalLM.from_pretrained(MODEL, torch_dtype=torch.float16, device_map="auto")
model.eval()
print("Model loaded, generating...")

# Find prompts
data_dir = None
for root, dirs, files in os.walk("/kaggle/input"):
    for f in files:
        if f == "prompts.jsonl":
            data_dir = root
            break
if not data_dir:
    data_dir = str(Path(__file__).parent)
prompts_file = None
for root, dirs, files in os.walk("/kaggle/input"):
    for f in files:
        if f.endswith(".jsonl") and "prompt" in f.lower():
            prompts_file = os.path.join(root, f)
            break

rows = [json.loads(l) for l in open(prompts_file) if l.strip()]
print(f"Loaded {len(rows)} prompts")

results = []
for i, r in enumerate(rows):
    messages = [
        {"role": "system", "content": r["system"]},
        {"role": "user", "content": r["user"]}
    ]
    text = tok.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = tok(text, return_tensors="pt", truncation=True, max_length=2048).to(model.device)
    with torch.no_grad():
        out = model.generate(**inputs, max_new_tokens=384, do_sample=False)
    response = tok.decode(out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)
    
    import re
    verdict = "unknown"
    m = re.search(r'"verdict"\s*:\s*"(vulnerable|benign)"', response)
    if m: verdict = m.group(1)
    elif "vulnerable" in response.lower(): verdict = "vulnerable"
    elif "benign" in response.lower(): verdict = "benign"
    
    results.append({
        "sample_key": r.get("sample_key",""), "arm": r.get("arm",""),
        "truth": r.get("truth",""), "verdict": verdict,
        "raw_response": response[:300], "mock": False
    })
    
    if (i+1) % 50 == 0:
        print(f"  [{i+1}/{len(rows)}]")
        with open("/kaggle/working/results_partial.jsonl","w") as f:
            for rr in results: f.write(json.dumps(rr, ensure_ascii=False)+"\n")

with open("/kaggle/working/results.jsonl","w") as f:
    for rr in results: f.write(json.dumps(rr, ensure_ascii=False)+"\n")
print(f"DONE: {len(results)} results")
