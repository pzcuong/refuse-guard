"""Reproduction gate: refusal/utility shift across conditions (>=3 models TODO Round 2/3) (PROPOSAL section 8.2).

Round 1 status: Round 1: plumbing only (mock LLM); real model matrix is the Round 2/3 gate.

Usage:
    python -m src.experiments.run_e0 --config configs/e0.yaml [--dry-run] [--limit N]
"""
from pathlib import Path

from .base import main

DEFAULT_CONFIG = str(Path(__file__).resolve().parents[2] / "configs" / "e0.yaml")

if __name__ == "__main__":
    main(default_config=DEFAULT_CONFIG, description="Reproduction gate: refusal/utility shift across conditions (>=3 models TODO Round 2/3)")
