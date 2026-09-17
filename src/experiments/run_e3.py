"""Contextual stress: clean vs semantics-preserving contextual variants (C2/C3) (PROPOSAL section 8.2).

Round 1 status: Round 1: full dry-run proven end-to-end (--dry-run); real models Round 2.

Usage:
    python -m src.experiments.run_e3 --config configs/e3.yaml [--dry-run] [--limit N]
"""
from pathlib import Path

from .base import main

DEFAULT_CONFIG = str(Path(__file__).resolve().parents[2] / "configs" / "e3.yaml")

if __name__ == "__main__":
    main(default_config=DEFAULT_CONFIG, description="Contextual stress: clean vs semantics-preserving contextual variants (C2/C3)")
