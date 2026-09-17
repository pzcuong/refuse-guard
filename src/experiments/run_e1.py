"""Clean baseline: raw LLM (B0) and transformer-only (B4) on clean code (PROPOSAL section 8.2).

Round 1 status: Round 1: B0 mock + B4 mock prior; real models/checkpoints Round 2 (TODO A2/A3).

Usage:
    python -m src.experiments.run_e1 --config configs/e1.yaml [--dry-run] [--limit N]
"""
from pathlib import Path

from .base import main

DEFAULT_CONFIG = str(Path(__file__).resolve().parents[2] / "configs" / "e1.yaml")

if __name__ == "__main__":
    main(default_config=DEFAULT_CONFIG, description="Clean baseline: raw LLM (B0) and transformer-only (B4) on clean code")
