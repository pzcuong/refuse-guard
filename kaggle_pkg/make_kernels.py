#!/usr/bin/env python
"""Render the two round-16 Kaggle kernels from kernel_template.py.

Kernel A (primary):   pzcuong/packguard-p110-p18      Qwen2.5-Coder-7B-Instruct
                      ladder A0/A5/A1 (180) + safety P0/P1/P2 (300) = 480 gens
Kernel B (secondary): pzcuong/packguard-p110-llama8b  unsloth/Llama-3.1-8B-Instruct
                      ladder A0/A5/A1 (180 gens) — safety is 7B-only
                      (AMENDMENT-9; the n=100 safety batch question is a 7B
                      question per the round-16 tasking).
"""
from pathlib import Path

HERE = Path(__file__).resolve().parent
TEMPLATE = (HERE / "kernel_template.py").read_text(encoding="utf-8")

KERNELS = [
    {
        "slug": "packguard-p110-p18",
        "model_id": "Qwen/Qwen2.5-Coder-7B-Instruct",
        "model_slug": "qwen7b",
        "tasks": ('[("ladder", ["A0", "A5", "A1"]), '
                  '("safety", ["P0_neutral", "P1_offensive_wording", '
                  '"P2_advisory_in_package"])]'),
    },
    {
        "slug": "packguard-p110-llama8b",
        "model_id": "unsloth/Llama-3.1-8B-Instruct",
        "model_slug": "llama8b",
        "tasks": '[("ladder", ["A0", "A5", "A1"])]',
    },
]


def render(k: dict) -> Path:
    out = (TEMPLATE
           .replace("__KERNEL_SLUG__", k["slug"])
           .replace("__MODEL_ID__", k["model_id"])
           .replace("__MODEL_SLUG__", k["model_slug"])
           .replace("__TASKS__", k["tasks"]))
    path = HERE / "kernel" / f"{k['slug']}.py"
    path.write_text(out, encoding="utf-8")
    print(f"[kernels] wrote {path}")
    return path


if __name__ == "__main__":
    for k in KERNELS:
        render(k)
