"""
firewall-IA — Model 2 decider: the runtime BLOCK/DEFER stage of the cascade.

Reuses the ratified scorer with no reimplementation:
    scripts/model2/training.load_artifact   hash + contract (+ FINAL evidence) verified
    scripts/model2/training.score            the fitted posterior p_block, pure stdlib
and the separate, model-bound policy (`model2_policy`) to map that posterior to an
action. Model 2 produces BLOCK or DEFER only, never ALLOW (PDF §3; D55).

FAIL-TO-DEFER is the rule: a missing/invalid/unbound policy, a non-ACCEPT canonical
result, missing text, or any scoring failure yields DEFER, so the request still
reaches V5. Only a confident, policy-authorized early block short-circuits V5.

The path-neutralized ablation is handled entirely by the artifact's `feature_view`
(`training.score` neutralizes the path when the view requires it); the C1 extension
fields stay metadata and are never fed to the trained model.

`load_artifact` runs the FINAL evidence check, which imports numpy/sklearn, so the
decider is constructed in an environment that has them (`.venv-analyzer`). The
scorer itself (`training.score`) is stdlib. The artifact bytes are hash-verified
against `expected_sha256` before anything is parsed.
"""

import os
import sys
from dataclasses import dataclass
from typing import Optional

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
if HERE not in sys.path:
    sys.path.insert(0, HERE)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from scripts.model2 import training as M2  # noqa: E402
import model2_policy as mp  # noqa: E402

BLOCK = "BLOCK"
DEFER = "DEFER"

# status codes; everything but OK forces DEFER.
OK = "OK"
POLICY_UNAVAILABLE = "POLICY_UNAVAILABLE"
POLICY_MISMATCH = "POLICY_MISMATCH"
CANONICAL_NOT_ACCEPTED = "CANONICAL_NOT_ACCEPTED"
EVIDENCE_MISSING = "EVIDENCE_MISSING"
SCORING_FAILED = "SCORING_FAILED"


@dataclass(frozen=True)
class Model2Outcome:
    decision: str                       # BLOCK | DEFER
    status: str
    p_block: Optional[float]
    threshold: Optional[float]
    feature_view: str
    model_artifact_sha256: str
    policy_id: Optional[str]
    policy_sha256: Optional[str]
    policy_status: Optional[str]

    @property
    def defers(self) -> bool:
        return self.decision == DEFER


class Model2Decider:
    """Holds one verified Model 2 artifact and an optional bound policy."""

    def __init__(self, artifact_path: str, *, expected_sha256: str,
                 policy: Optional[mp.Model2Policy] = None):
        self.artifact_path = artifact_path
        self.artifact = M2.load_artifact(artifact_path, expected_sha256=expected_sha256)
        self.artifact_sha256 = expected_sha256
        self.feature_view = self.artifact["feature_view"]
        self.policy = policy

    @classmethod
    def from_policy_file(cls, artifact_path, *, expected_sha256, policy_path):
        policy = None
        try:
            if policy_path:
                policy = mp.load_policy(policy_path)
        except (mp.PolicyError, OSError):
            policy = None  # treated as no policy -> DEFER
        return cls(artifact_path, expected_sha256=expected_sha256, policy=policy)

    def _defer(self, status, p_block=None):
        pol = self.policy
        return Model2Outcome(
            decision=DEFER, status=status, p_block=p_block,
            threshold=(pol.threshold if pol else None),
            feature_view=self.feature_view, model_artifact_sha256=self.artifact_sha256,
            policy_id=(pol.policy_id if pol else None),
            policy_sha256=(pol.sha256 if pol else None),
            policy_status=(pol.status if pol else None))

    def decide(self, *, canonical_outcome: str, canonical_text: Optional[str]) -> Model2Outcome:
        """Decide BLOCK/DEFER for one canonical request result.

        `canonical_outcome` is the CanonicalResult.outcome (ACCEPT/REJECT/UNSUPPORTED);
        `canonical_text` is CanonicalResult.text (None unless ACCEPT)."""
        pol = self.policy
        if pol is None:
            return self._defer(POLICY_UNAVAILABLE)
        if not pol.binds(feature_view=self.feature_view, artifact_sha256=self.artifact_sha256):
            return self._defer(POLICY_MISMATCH)
        if canonical_outcome != "ACCEPT":
            return self._defer(CANONICAL_NOT_ACCEPTED)
        if not canonical_text:
            return self._defer(EVIDENCE_MISSING)
        try:
            p = M2.score(self.artifact, canonical_text)
        except Exception:
            return self._defer(SCORING_FAILED)
        decision = BLOCK if p >= pol.threshold else DEFER
        return Model2Outcome(
            decision=decision, status=OK, p_block=float(p), threshold=pol.threshold,
            feature_view=self.feature_view, model_artifact_sha256=self.artifact_sha256,
            policy_id=pol.policy_id, policy_sha256=pol.sha256, policy_status=pol.status)
