"""PROPOSED C1-only boundary for offline integration tests.

No fitting, weights, operating threshold or enforcement. NoModelDecider always
defers. Successful results are synthetic fixtures only. This does not replace
hybrid_contracts or ratify the complete model2-contract/v2 proposal.
"""
import math
import sys
from dataclasses import dataclass, fields
from enum import Enum
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "data_plane"))
import request_features as rf

CONTRACT_ID = "model2-c1-boundary/proposal-v1"
REPRESENTATION = "canonical-request/v1"


class Decision(str, Enum):
    BLOCK = "BLOCK"
    DEFER = "DEFER"


class Status(str, Enum):
    OK = "OK"
    EVIDENCE_MISSING = "EVIDENCE_MISSING"
    EVIDENCE_INVALID = "EVIDENCE_INVALID"
    MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"


class Reason(str, Enum):
    MODEL_NOT_TRAINED = "MODEL_NOT_TRAINED"
    C1_MISSING = "C1_MISSING"
    C1_INVALID = "C1_INVALID"
    CANONICAL_NOT_ACCEPTED = "CANONICAL_NOT_ACCEPTED"
    REPRESENTATION_MISMATCH = "REPRESENTATION_MISMATCH"
    SYNTHETIC_RESULT = "SYNTHETIC_RESULT"


@dataclass(frozen=True)
class C1Evidence:
    """Candidate interface, not an attestation of wire/size/training eligibility.

    No C2, V4/V5 decision, raw text, labels or Fast Path reasons are model inputs.
    """
    features: rf.RequestFeatures | None
    representation: str
    canonical_outcome: str


def invalid_features(value):
    if not isinstance(value, rf.RequestFeatures) or value.schema_version != rf.FEATURE_SCHEMA_VERSION:
        return True
    for item in fields(rf.RequestFeatures):
        v = getattr(value, item.name)
        if item.type is bool:
            if type(v) is not bool:
                return True
        elif item.type is int:
            if type(v) is not int or v < 0:
                return True
        elif item.type is float:
            if type(v) not in (float, int) or v < 0:
                return True
            try:
                if not math.isfinite(v):
                    return True
            except OverflowError:
                return True
            if item.name.endswith("ratio") and v > 1:
                return True
        elif item.type is str:
            if type(v) is not str:
                return True
        else:
            return True  # Review schema additions explicitly.
    return value.body_format not in ("none", "form", "json", "json_invalid", "other")


@dataclass(frozen=True)
class Model2Result:
    status: Status
    reason: Reason
    decision: Decision | None = None
    p_block: float | None = None

    def __post_init__(self):
        if type(self.status) is not Status or type(self.reason) is not Reason:
            raise ValueError("unknown status or reason")
        if self.status is Status.OK:
            if type(self.decision) is not Decision:
                raise ValueError("OK requires BLOCK or DEFER")
            p = self.p_block
            if type(p) not in (float, int) or not 0 <= p <= 1 or not math.isfinite(p):
                raise ValueError("OK requires a finite posterior in [0, 1]")
            if self.reason is not Reason.SYNTHETIC_RESULT:
                raise ValueError("only synthetic OK results are supported in this preparation")
        else:
            if self.decision is not None or self.p_block is not None:
                raise ValueError("non-OK must not carry a decision or posterior")
            allowed = {
                Status.EVIDENCE_MISSING: {Reason.C1_MISSING},
                Status.EVIDENCE_INVALID: {Reason.C1_INVALID, Reason.CANONICAL_NOT_ACCEPTED,
                                          Reason.REPRESENTATION_MISMATCH},
                Status.MODEL_UNAVAILABLE: {Reason.MODEL_NOT_TRAINED},
            }
            if self.reason not in allowed[self.status]:
                raise ValueError("reason does not match status")

    @property
    def next_action(self):
        return self.decision if self.status is Status.OK else Decision.DEFER


class NoModelDecider:
    """Offline placeholder: never trains, loads a model or produces BLOCK."""
    def decide(self, evidence):
        if evidence is None:
            return Model2Result(Status.EVIDENCE_MISSING, Reason.C1_MISSING)
        if type(evidence) is not C1Evidence:
            return Model2Result(Status.EVIDENCE_INVALID, Reason.C1_INVALID)
        if evidence.representation != REPRESENTATION:
            return Model2Result(Status.EVIDENCE_INVALID, Reason.REPRESENTATION_MISMATCH)
        if evidence.canonical_outcome != "ACCEPT":
            return Model2Result(Status.EVIDENCE_INVALID, Reason.CANONICAL_NOT_ACCEPTED)
        if evidence.features is None:
            return Model2Result(Status.EVIDENCE_MISSING, Reason.C1_MISSING)
        if invalid_features(evidence.features):
            return Model2Result(Status.EVIDENCE_INVALID, Reason.C1_INVALID)
        return Model2Result(Status.MODEL_UNAVAILABLE, Reason.MODEL_NOT_TRAINED)
