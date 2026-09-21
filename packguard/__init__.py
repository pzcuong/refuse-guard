"""PackGuard: cross-language malicious-package detection (PACKGUARD_BRIEF §3).

W2 scope (round 8): FL framework (fl.py, models.py), LLM-KB (kb.py),
safety port (safety_port.py), eval harness (eval.py). schema/graphs/features/
dataset are owned by W1 — imported, never modified here.
"""

# W1 scope (round 8): schema/graphs/features/dataset
from packguard.schema import BEHAVIOR_CLASSES, SCHEMA_VERSION  # noqa: E402,F401
from packguard.features import FEATURE_NAMES  # noqa: E402,F401
