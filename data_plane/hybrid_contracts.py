"""
firewall-IA — data contracts of the proposed Hybrid Architecture (Phase 1, Issue #49;
Analyzer output frozen in Phase 2A, Issue #51).

    Request -> RequestFeatures -> AnalyzerOutput -> DecisionInput -> DecisionOutput

"Hybrid Architecture" is the multi-stage design (feature extraction ->
lightweight request analyzer -> small decision model -> V4 as fallback). It is
not the "V5" model revision of D37/D40 (terminology: D45).

CONTRACTS ONLY. `RequestFeatures` is implemented in `request_features.py`. The
other three are defined here so later stages agree on their boundaries, but
nothing produces or consumes them yet: there is no Lightweight Request Analyzer
and no Small Decision Model, and no traffic decision is taken from them. V4,
through `/classify`, is the only decision (D43).

The Analyzer's signals are fixed by D46, D47 and D50: one `attack` probability
and an optional distribution over ANALYZER_CATEGORIES given attack. There is no
global confidence score.
"""

import math
from dataclasses import dataclass
from typing import Mapping

from request_features import RequestFeatures

DECISIONS = ("ALLOW", "BLOCK", "UNCERTAIN")

# D47 / D49: the Analyzer's category vocabulary. "other_attack" is a residual bucket
# for every other modelled BLOCK reason, not a semantic category.
ANALYZER_CATEGORIES = ("sql_injection", "xss", "path_file_access", "command_injection",
                       "ssti", "open_redirect", "ssrf", "other_attack")
ATTACK = "attack"
CATEGORY_PREFIX = "category:"
CATEGORY_SIGNALS = tuple(CATEGORY_PREFIX + c for c in ANALYZER_CATEGORIES)
_SUM_TOLERANCE = 1e-6


def _check_probability(name: str, value: float) -> None:
    # bool is an int subclass, but True is not a probability.
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or not 0.0 <= value <= 1.0):
        raise ValueError(f"{name} must be a number in [0, 1], got {value!r}")


@dataclass(frozen=True)
class AnalyzerOutput:
    """What a future Lightweight Request Analyzer reports about one request (D50).

    signals
        "attack"           P̂(BLOCK | RequestFeatures), a calibrated probability
                           learned on V4-clean, which is 50/50 ALLOW/BLOCK by
                           construction: not an operational attack prevalence.
        "category:<id>"    P̂(category = id | attack, RequestFeatures) for every id
                           in ANALYZER_CATEGORIES. Either all present, summing to 1,
                           or all absent. Auxiliary context only (D46).
    analyzer_version       identity of the analyzer that produced it

    No confidence score: uncertainty is derived from the probabilities themselves
    (closeness of `attack` to 0.5, top-1 probability, top-1/top-2 margin, entropy).
    """

    signals: Mapping[str, float]
    analyzer_version: str

    def __post_init__(self) -> None:
        unknown = set(self.signals) - {ATTACK, *CATEGORY_SIGNALS}
        if unknown:
            raise ValueError(f"unknown signals: {sorted(unknown)}")
        if ATTACK not in self.signals:
            raise ValueError(f"the {ATTACK!r} signal is required")
        for name, value in self.signals.items():
            _check_probability(name, value)
        categories = [s for s in CATEGORY_SIGNALS if s in self.signals]
        if categories:
            if len(categories) != len(CATEGORY_SIGNALS):
                raise ValueError("category signals must be all present or all absent; "
                                 f"missing {sorted(set(CATEGORY_SIGNALS) - set(categories))}")
            total = math.fsum(self.signals[s] for s in CATEGORY_SIGNALS)
            if abs(total - 1.0) > _SUM_TOLERANCE:
                raise ValueError(f"category signals must sum to 1, got {total!r}")


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
        _check_probability("confidence", self.confidence)
