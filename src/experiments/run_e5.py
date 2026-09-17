"""Simple defenses: B1 reframe / B2 comment strip / B3 aggressive removal (PROPOSAL section 8.2).

Round 1 status: Round 1: structure + dry-run; TODO Round 2 pilot with real LLM.

Usage:
    python -m src.experiments.run_e5 --config configs/e5.yaml [--dry-run] [--limit N]
"""
from pathlib import Path

from .base import main

DEFAULT_CONFIG = str(Path(__file__).resolve().parents[2] / "configs" / "e5.yaml")

if __name__ == "__main__":
    main(default_config=DEFAULT_CONFIG, description="Simple defenses: B1 reframe / B2 comment strip / B3 aggressive removal")
