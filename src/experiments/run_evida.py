"""Registered runner contract (PROJECT_BRIEF §8 + EVIDA prereg §2.6):

    python -m src.experiments.run_evida --config configs/evida.yaml [--stage ...]

Thin CLI: all logic lives in research_program/evida_runner.py (src/models,
src/conditions, src/metrics, src/defenses, src/data are NOT modified).
"""
from pathlib import Path

from research_program.evida_runner import DEFAULT_CONFIG, main

if __name__ == "__main__":
    raise SystemExit(main())
