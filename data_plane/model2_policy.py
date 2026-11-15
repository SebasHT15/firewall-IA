"""
firewall-IA — Model 2 decision policy (BLOCK / DEFER), separate from the model.

The trained Model 2 artifact is a scorer only: it carries no operating threshold
(`operating_threshold: null`) and no approved policy (`operational_policy_approved:
false`), by construction (`scripts/model2/training.check_artifact`). Turning a
score into an action is a SEPARATE, versioned, model-bound decision — this module.

A policy maps the fitted posterior p_block to exactly one of:
    BLOCK   p_block >= threshold   (early block, no V5 call)
    DEFER   p_block <  threshold   (hand the canonical request to V5)
An explicit LAB_EXPERIMENTAL `decision_mode: DEFER_ONLY` keeps scoring for
analysis while always handing the request to V5. The threshold is then a
counterfactual marker only; it never authorizes a block.
`GUARDED_ENFORCE` is a separate LAB_EXPERIMENTAL selective candidate bound to
the original baseline34 artifact and a fixed guard identifier. It can block
inside the guard's eligibility region; known-DEV results do not approve it.
Model 2 NEVER produces ALLOW (PDF §3; D55). There is no implicit 0.5: the
threshold is explicit and required. A policy is bound to ONE model artifact by its
sha256 and feature_view; applied to any other artifact it does not match and the
decider defers (fail-to-defer).

STATUS is `LAB_EXPERIMENTAL` or `APPROVED`. LAB_EXPERIMENTAL exercises the
mechanism and the routes; it is NOT a calibrated/selected operating point and must
not be reported as one. `APPROVED` additionally requires an approval record
(approved_by/date/decision_ref) and is still subject to the project's evaluation
protocol — nothing here ratifies an operating point.

Standard library only: importable in every environment.
"""

import hashlib
import json
from dataclasses import dataclass

POLICY_SCHEMA = "model2-decision-policy/v1"
STATUSES = ("LAB_EXPERIMENTAL", "APPROVED")
FEATURE_VIEWS = ("baseline_34", "target-path-neutralized/v1")
DECISION_MODES = ("ENFORCE", "DEFER_ONLY", "GUARDED_ENFORCE")
SELECTIVE_GUARD = "c1-selective-abstention/v1"
SELECTIVE_GUARD_ARTIFACT_SHA256 = "da6f6eb85c5a687bd038c6298baf59abdbe0489a80c8993b74a34dae7c60aa38"


class PolicyError(ValueError):
    """The policy is not acceptable. Never partially applied (the decider defers)."""


@dataclass(frozen=True)
class Model2Policy:
    policy_id: str
    status: str                 # LAB_EXPERIMENTAL | APPROVED
    feature_view: str
    model_artifact_sha256: str  # the exact Model 2 artifact this policy is bound to
    threshold: float            # p_block >= threshold -> BLOCK, else DEFER
    sha256: str                 # digest of the policy document
    note: str = ""
    decision_mode: str = "ENFORCE"
    guard_id: str | None = None

    def binds(self, *, feature_view: str, artifact_sha256: str) -> bool:
        """True iff this policy is the one authored for this exact model artifact."""
        return (self.feature_view == feature_view
                and self.model_artifact_sha256 == artifact_sha256)


def parse_policy(doc) -> Model2Policy:
    if not isinstance(doc, dict):
        raise PolicyError("policy must be an object")
    allowed = {"schema", "policy_id", "status", "approval", "feature_view", "decision_mode", "guard_id",
               "model_artifact_sha256", "threshold", "note"}
    unknown = set(doc) - allowed
    if unknown:
        raise PolicyError(f"unknown policy keys: {sorted(unknown)}")
    if doc.get("schema") != POLICY_SCHEMA:
        raise PolicyError(f"schema must be {POLICY_SCHEMA!r}")
    policy_id = doc.get("policy_id")
    if not isinstance(policy_id, str) or not policy_id.strip():
        raise PolicyError("policy_id must be a non-empty string")
    status = doc.get("status")
    if status not in STATUSES:
        raise PolicyError(f"status must be one of {STATUSES}")
    if status == "APPROVED":
        appr = doc.get("approval")
        if (not isinstance(appr, dict)
                or any(not isinstance(appr.get(k), str) or not appr[k].strip()
                       for k in ("approved_by", "date", "decision_ref"))):
            raise PolicyError("an APPROVED policy needs approval.approved_by/date/decision_ref")
    decision_mode = doc.get("decision_mode", "ENFORCE")
    if decision_mode not in DECISION_MODES:
        raise PolicyError(f"decision_mode must be one of {DECISION_MODES}")
    if status == "APPROVED" and decision_mode != "ENFORCE":
        raise PolicyError("selective and defer-only modes are analysis-only LAB_EXPERIMENTAL")
    guard_id = doc.get("guard_id")
    if (decision_mode == "GUARDED_ENFORCE" and guard_id != SELECTIVE_GUARD) or (
            decision_mode != "GUARDED_ENFORCE" and guard_id is not None):
        raise PolicyError("guard_id must name the supported guard only for GUARDED_ENFORCE")
    fv = doc.get("feature_view")
    if fv not in FEATURE_VIEWS:
        raise PolicyError(f"feature_view must be one of {FEATURE_VIEWS}")
    sha = doc.get("model_artifact_sha256")
    if not isinstance(sha, str) or len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
        raise PolicyError("model_artifact_sha256 must be a 64-hex string")
    if decision_mode == "GUARDED_ENFORCE" and (fv != "baseline_34" or sha != SELECTIVE_GUARD_ARTIFACT_SHA256):
        raise PolicyError("selective guard is bound to the original baseline34 artifact")
    threshold = doc.get("threshold")
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
        raise PolicyError("threshold must be a number")
    threshold = float(threshold)
    if not 0.0 <= threshold <= 1.0:
        raise PolicyError("threshold must be in [0, 1]")
    note = doc.get("note", "")
    if not isinstance(note, str):
        raise PolicyError("note must be a string")
    digest = hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":"),
                                       ensure_ascii=True).encode("ascii")).hexdigest()
    return Model2Policy(policy_id, status, fv, sha, threshold, digest, note, decision_mode, guard_id)


def load_policy(path: str) -> Model2Policy:
    """Read and validate a policy file. Raises PolicyError/OSError; the decider
    treats any failure as 'no usable policy' and defers (never a crash)."""
    with open(path, encoding="utf-8") as fh:
        try:
            doc = json.load(fh)
        except ValueError as exc:
            raise PolicyError(f"not valid JSON: {exc.__class__.__name__}") from None
    return parse_policy(doc)
