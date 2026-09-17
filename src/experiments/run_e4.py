"""Carrier/position ablation: comment vs docstring vs string, near vs far (PROPOSAL section 8.2).

Round 1 status: Round 1: grid plumbing (grid: sampled|full in config); TODO Round 2 scale-up.

Usage:
    python -m src.experiments.run_e4 --config configs/e4.yaml [--dry-run] [--limit N]
"""
from pathlib import Path

from .base import main

DEFAULT_CONFIG = str(Path(__file__).resolve().parents[2] / "configs" / "e4.yaml")

if __name__ == "__main__":
    main(default_config=DEFAULT_CONFIG, description="Carrier/position ablation: comment vs docstring vs string, near vs far")
