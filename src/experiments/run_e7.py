"""Refusal recovery: P2 RefuseGuard (retry + transformer fallback) vs B0 (PROPOSAL section 8.2).

Round 1 status: Round 1: structure + dry-run (exercises retry+fallback); TODO Round 3 ablations.

Usage:
    python -m src.experiments.run_e7 --config configs/e7.yaml [--dry-run] [--limit N]
"""
from pathlib import Path

from .base import main

DEFAULT_CONFIG = str(Path(__file__).resolve().parents[2] / "configs" / "e7.yaml")

if __name__ == "__main__":
    main(default_config=DEFAULT_CONFIG, description="Refusal recovery: P2 RefuseGuard (retry + transformer fallback) vs B0")
