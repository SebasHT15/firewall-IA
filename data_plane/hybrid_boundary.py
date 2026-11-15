"""
firewall-IA — Hybrid Architecture: the boundary for Model 2 and the semantic fallback.

DEFINED, NOT IMPLEMENTED. Nothing in the gateway imports this module, and
`tests/test_hybrid_shadow.py` checks that it stays that way. It exists so the next stages
have one place that says where they would attach, and what is NOT yet approved.

    ... -> Analyzer (shadow, hybrid_shadow.py) -> [Model 2] -> ALLOW | BLOCK | UNCERTAIN
                                                                              |
                                                                  UNCERTAIN -> [semantic fallback]

What the repository APPROVES today, and this module reuses by name:
  hybrid_contracts.DecisionInput     features + AnalyzerOutput: "everything a future decision
                                     stage may read" (D43, D50)
  hybrid_contracts.DecisionOutput    decision in DECISIONS, confidence in [0, 1], reason
                                     (D43; unchanged by D50)
  `/classify` (V4)                   the only active decision; the only approved semantic path

What is NOT approved, so NOT defined here (no thresholds, no model, no routing):
  * Model 2 itself. D55: "the operating policy (ALLOW / BLOCK / UNCERTAIN) is decided later
    with the Small Decision Model." There is no approved Model 2 training data, calibration,
    decision policy or operating point. `DecisionOutput.confidence` has no approved meaning
    (D50 removed the Analyzer's global confidence and defined none for Model 2).
  * How UNCERTAIN is routed: the `DecisionOutput` docstring says "defer to V4" and that
    routing "is not designed yet".
  * Whether any stage may BLOCK or ALLOW without V4: D43 leaves it open; D29 excludes a
    heuristic fast path. There is no approved fast path, so none exists.
  * The V5 fallback: `control_plane/v5_output_contract.py` defines V5's OUTPUT contract, but
    V5 is not integrated into the gateway, and its integration policy is undecided.
  * The latency allocation: D36 sets an end-to-end P95 <= 200 ms objective that is NOT met
    today (V4 alone measured 269.58 ms), so no stage may be assumed to fit a budget.

So the only thing implemented below is a stage that refuses to answer.
"""

from typing import Protocol

from hybrid_contracts import DecisionInput, DecisionOutput

MODEL2_STATUS = "UNIMPLEMENTED"
SEMANTIC_FALLBACK_STATUS = "UNIMPLEMENTED"


class DecisionStage(Protocol):
    """Model 2's attachment point: read a DecisionInput, return a DecisionOutput.

    A conforming implementation does not exist. Whoever writes one must first get its
    decision contract approved (see the module docstring)."""

    def decide(self, decision_input: DecisionInput) -> DecisionOutput:
        ...


class SemanticFallback(Protocol):
    """Where UNCERTAIN would go. Today the only semantic path is V4 via `/classify`, which
    is already consulted for EVERY request; no routing from UNCERTAIN is designed."""

    def resolve(self, decision_input: DecisionInput) -> DecisionOutput:
        ...


class Model2Unimplemented(NotImplementedError):
    """Model 2's decision contract is not approved; there is nothing to call."""


class UnimplementedDecisionStage:
    """The only DecisionStage that exists. It never returns a decision: there is no
    fabricated model, no threshold and no default that could turn into an ALLOW."""

    def decide(self, decision_input: DecisionInput) -> DecisionOutput:
        raise Model2Unimplemented(
            "Model 2 is not implemented: its decision contract is not approved "
            "(D55: the ALLOW / BLOCK / UNCERTAIN policy is decided later with the Small "
            "Decision Model). V4 remains the only decision.")
