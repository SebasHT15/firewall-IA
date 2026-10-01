"""
firewall-IA — data contracts of the proposed Hybrid Architecture (Phase 1, Issue #49).

    Request -> RequestFeatures -> AnalyzerOutput -> DecisionInput -> DecisionOutput

"Hybrid Architecture" is the multi-stage design (feature extraction ->
lightweight request analyzer -> small decision model -> V4 as fallback). It is
not the "V5" model revision of D37/D40 (terminology: D45).

CONTRACTS ONLY. `RequestFeatures` is implemented in `request_features.py`. The
other three are defined here so later stages agree on their boundaries, but
nothing produces or consumes them yet: there is no Lightweight Request Analyzer
and no Small Decision Model, and no traffic decision is taken from them. V4,
through `/classify`, is the only decision (D43).

The analyzer's signal vocabulary is deliberately NOT fixed: no signal category
has been defined by the project, so `AnalyzerOutput.signals` accepts any name.
"""

import math
from dataclasses import dataclass
from typing import Mapping

from request_features import RequestFeatures

DECISIONS = ("ALLOW", "BLOCK", "UNCERTAIN")


def _check_confidence(value: float) -> None:
    # bool is an int subclass, but True is not a confidence.
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or not 0.0 <= value <= 1.0):
        raise ValueError(f"confidence must be a number in [0, 1], got {value!r}")


@dataclass(frozen=True)
class AnalyzerOutput:
    """What a future Lightweight Request Analyzer reports about one request.

    signals           signal name -> value; the names are open until the
                      project defines them
    confidence        the analyzer's confidence in its own output, [0, 1]
    analyzer_version  identity of the analyzer that produced it
    """

    signals: Mapping[str, float]
    confidence: float
    analyzer_version: str

    def __post_init__(self) -> None:
        _check_confidence(self.confidence)


@dataclass(frozen=True)
class DecisionInput:
    """Everything a future decision stage may read about one request."""

    features: RequestFeatures
    analysis: AnalyzerOutput


@dataclass(frozen=True)
class DecisionOutput:
    """A future decision stage's answer. UNCERTAIN means "defer to V4"; how it
    is routed is not designed yet. Like `/classify` (D25), a value outside the
    vocabulary is rejected, never coerced."""

    decision: str       # one of DECISIONS
    confidence: float   # [0, 1]
    reason: str

    def __post_init__(self) -> None:
        if self.decision not in DECISIONS:
            raise ValueError(f"decision must be one of {DECISIONS}, got {self.decision!r}")
        _check_confidence(self.confidence)
