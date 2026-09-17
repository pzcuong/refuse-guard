"""Semantic isolation: P1 vs B3 aggressive-removal control (PROPOSAL section 8.2).

Round 1 status: Round 1: structure + dry-run; TODO Round 3 pilot per RQ4.

Usage:
    python -m src.experiments.run_e6 --config configs/e6.yaml [--dry-run] [--limit N]
"""
from pathlib import Path

from .base import main

DEFAULT_CONFIG = str(Path(__file__).resolve().parents[2] / "configs" / "e6.yaml")

if __name__ == "__main__":
    main(default_config=DEFAULT_CONFIG, description="Semantic isolation: P1 vs B3 aggressive-removal control")
