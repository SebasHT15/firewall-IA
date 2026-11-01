"""
firewall-IA — hybrid cascade router (PDF architecture), transport-independent.

Implements the decision path of the target architecture:

    WIRE HTTP -> parser/framing/canonicalization -> Fast Path -> C1 -> Model 2 -> V5

as a PURE function over a per-request snapshot plus three injected stage
callables (Fast Path evaluate, Model 2 decide, V5 classify). It owns no sockets,
no model and no HTTP client, so every branch is testable with doubles and the
same object drives the real lab. The one canonical snapshot is produced once by
the caller and handed to every stage; the router never re-canonicalizes and never
mixes evidence across requests.

Routing (ACTIVE cascade):
  canonical REJECT / UNSUPPORTED -> DENY (protocol reject; NOT a model decision,
                                   NOT delegated to V5)
  Fast Path FAST_ALLOW           -> FORWARD, no model call
  Fast Path CONTINUE             -> Model 2
  Model 2 BLOCK *and* status OK  -> DENY, no V5 call
  Model 2 DEFER / non-OK status  -> V5 (with the canonical text; Model 2's score
  / raised exception                is NEVER put in the V5 prompt). A BLOCK with a
                                   non-OK status is an inconsistent reply and is
                                   NEVER trusted to deny early — it fails to DEFER.
  V5 ok ALLOW                    -> FORWARD
  V5 ok BLOCK                    -> DENY
  V5 invalid / error / timeout   -> DENY (fail-closed; never ALLOW by exception)

Every request ends in exactly one applied action (FORWARD or DENY) and records
which stage decided it. Modes:
  V4_ONLY         the existing V4 path decides (delegated to `v4_classify`)
  V5_ONLY         canonical -> V5 directly (no Fast Path, no Model 2)
  CASCADE_OBSERVE the cascade is computed and recorded, but the APPLIED action is
                  V4's (V4 unchanged); use to compare without changing traffic
  CASCADE_ACTIVE  the cascade decides and is applied

Standard library only.
"""

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

# Modes
V4_ONLY = "V4_ONLY"
V5_ONLY = "V5_ONLY"
CASCADE_OBSERVE = "CASCADE_OBSERVE"
CASCADE_ACTIVE = "CASCADE_ACTIVE"
MODES = (V4_ONLY, V5_ONLY, CASCADE_OBSERVE, CASCADE_ACTIVE)

# Applied actions
FORWARD = "FORWARD"
DENY = "DENY"

# Deciding stages
STAGE_PROTOCOL = "protocol"       # canonical REJECT/UNSUPPORTED
STAGE_FAST_PATH = "fast_path"
STAGE_MODEL2 = "model2"
STAGE_V5 = "v5"
STAGE_V4 = "v4"

# Model 2 boundary contract (mirrors model2_decider: BLOCK/DEFER, status OK else
# DEFER-forcing). Kept as local constants so this router stays transport- and
# model-independent; an early BLOCK is honored only with an OK status.
MODEL2_OK = "OK"
MODEL2_BLOCK = "BLOCK"


@dataclass(frozen=True)
class Snapshot:
    """One request as the data plane saw it, canonicalized exactly once.

    `raw_*` are the received parts (bytes/str) the Fast Path needs for header and
    target inspection. `canonical` is the canonical-request/v1 result object
    (duck-typed: .outcome/.text/.signals/.audit/.size). `framing` is the Fast
    Path framing evidence for this same request."""
    method: bytes
    target: bytes
    http_version: str
    headers: tuple
    body: bytes
    canonical: Any                       # CanonicalResult
    framing: Any                         # fast_path.FramingEvidence
    raw_request_text: Optional[str] = None  # for V4 delegation only (its D1 render input)
    correlation_id: Optional[str] = None


@dataclass
class V5Reply:
    """Normalized V5 answer, from an in-process call or the HTTP service."""
    status: str                 # "ok" | "invalid" | "error"
    decision: Optional[str] = None     # "ALLOW" | "BLOCK"
    invalid_reason: Optional[str] = None
    detail: Optional[str] = None
    generate_ms: Optional[float] = None


@dataclass
class V4Reply:
    status: str                 # "ok" | "invalid" | "error"
    decision: Optional[str] = None     # "ALLOW" | "BLOCK"
    detail: Optional[str] = None


@dataclass
class CascadeResult:
    applied: str                       # FORWARD | DENY
    deciding_stage: str
    mode: str
    correlation_id: Optional[str]
    canonical_outcome: Optional[str]
    canonical_reject: Optional[str] = None
    fast_path: Optional[dict] = None
    model2: Optional[dict] = None
    v5: Optional[dict] = None
    v4: Optional[dict] = None
    # What the cascade *would* apply, recorded even in OBSERVE mode where `applied`
    # follows V4 instead.
    cascade_applied: Optional[str] = None
    cascade_stage: Optional[str] = None
    timings_ms: dict = field(default_factory=dict)
    reason: Optional[str] = None


@dataclass(frozen=True)
class CascadeConfig:
    mode: str = CASCADE_ACTIVE
    fast_path_policy: Any = None        # fast_path.Policy or None
    v5_fail_closed: bool = True         # invalid/error/timeout -> DENY (always True here)

    def __post_init__(self):
        if self.mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        if not self.v5_fail_closed:
            raise ValueError("v5_fail_closed must stay True: V5 failure never ALLOWs")


class CascadeRouter:
    """Holds the injected stage callables and the config; `route(snapshot)` decides.

    fast_path_evaluate(fp_input, policy) -> FastPathDecision
    model2_decide(canonical_outcome, canonical_text) -> object with .decision and
                 (.status, .p_block, .threshold, .policy_id, .policy_sha256,
                  .policy_status, .feature_view, .model_artifact_sha256)
    v5_classify(canonical_text) -> V5Reply   (may raise; caught -> DENY)
    v4_classify(raw_request_text) -> V4Reply (only used in V4 modes; may raise)
    make_fast_path_input(snapshot) -> fast_path.FastPathInput
    """

    def __init__(self, config: CascadeConfig, *, fast_path_evaluate=None,
                 model2_decide=None, v5_classify=None, v4_classify=None,
                 make_fast_path_input=None):
        self.config = config
        self._fp_eval = fast_path_evaluate
        self._m2 = model2_decide
        self._v5 = v5_classify
        self._v4 = v4_classify
        self._mk_fp = make_fast_path_input

    # ── stage helpers ────────────────────────────────────────────────────
    def _call_v5(self, canonical_text: str, out: CascadeResult, t: dict):
        t0 = time.perf_counter()
        try:
            reply = self._v5(canonical_text)
        except Exception as exc:  # timeout, connection, protocol — fail-closed
            t["v5_ms"] = (time.perf_counter() - t0) * 1000
            out.v5 = {"status": "error", "detail": f"{type(exc).__name__}"}
            return DENY, STAGE_V5, "v5_unavailable"
        t["v5_ms"] = (time.perf_counter() - t0) * 1000
        out.v5 = {"status": reply.status, "decision": reply.decision,
                  "invalid_reason": reply.invalid_reason, "generate_ms": reply.generate_ms}
        if reply.status == "ok" and reply.decision == "ALLOW":
            return FORWARD, STAGE_V5, None
        if reply.status == "ok" and reply.decision == "BLOCK":
            return DENY, STAGE_V5, "v5_block"
        # invalid / error / unexpected -> fail-closed
        return DENY, STAGE_V5, f"v5_{reply.status}"

    def _call_model2(self, outcome, canonical_text, out: CascadeResult, t: dict) -> bool:
        """Call Model 2 at its boundary and record its reply. Returns True ONLY when
        Model 2 authoritatively early-BLOCKs: status OK *and* decision BLOCK. Any
        raised exception, any non-OK status, or any non-BLOCK decision is a
        fail-to-DEFER — it is recorded and False is returned so the caller delegates
        to V5. This is where the router's declared "non-OK -> V5" is enforced: the
        decision string is never trusted on its own."""
        t0 = time.perf_counter()
        try:
            m2 = self._m2(canonical_outcome=outcome, canonical_text=canonical_text)
        except Exception as exc:   # timeout, scoring crash, anything — fail-to-DEFER
            t["model2_ms"] = (time.perf_counter() - t0) * 1000
            out.model2 = {"decision": None, "status": "error",
                          "detail": type(exc).__name__}
            return False
        t["model2_ms"] = (time.perf_counter() - t0) * 1000
        status = getattr(m2, "status", None)
        decision = getattr(m2, "decision", None)
        out.model2 = {"decision": decision, "status": status,
                      "p_block": getattr(m2, "p_block", None),
                      "threshold": getattr(m2, "threshold", None),
                      "feature_view": getattr(m2, "feature_view", None),
                      "model_artifact_sha256": getattr(m2, "model_artifact_sha256", None),
                      "policy_id": getattr(m2, "policy_id", None),
                      "policy_sha256": getattr(m2, "policy_sha256", None),
                      "policy_status": getattr(m2, "policy_status", None)}
        return status == MODEL2_OK and decision == MODEL2_BLOCK

    def _run_cascade(self, snapshot: Snapshot, out: CascadeResult, t: dict):
        """Compute the cascade's own (action, stage) for this snapshot."""
        canon = snapshot.canonical
        outcome = getattr(canon, "outcome", None)
        out.canonical_outcome = outcome
        if outcome != "ACCEPT":
            out.canonical_reject = getattr(canon, "reject", None)
            return DENY, STAGE_PROTOCOL, f"canonical_{outcome}"

        canonical_text = getattr(canon, "text", None)

        # Fast Path
        t0 = time.perf_counter()
        fp_input = self._mk_fp(snapshot)
        decision = self._fp_eval(fp_input, self.config.fast_path_policy)
        t["fast_path_ms"] = (time.perf_counter() - t0) * 1000
        out.fast_path = {"decision": decision.decision, "reasons": list(decision.reasons),
                         "rule_id": decision.rule_id, "policy_id": decision.policy_id,
                         "policy_sha256": decision.policy_sha256,
                         "policy_status": decision.policy_status}
        if decision.decision == "FAST_ALLOW":
            return FORWARD, STAGE_FAST_PATH, None

        # Model 2 — early BLOCK only on an OK status; every other outcome
        # (DEFER, non-OK status, or a raised exception) fails to DEFER -> V5.
        if self._call_model2(outcome, canonical_text, out, t):
            return DENY, STAGE_MODEL2, "model2_block"

        # DEFER / non-OK / Model 2 failure -> V5
        return self._call_v5(canonical_text, out, t)

    def _run_v5_only(self, snapshot: Snapshot, out: CascadeResult, t: dict):
        canon = snapshot.canonical
        outcome = getattr(canon, "outcome", None)
        out.canonical_outcome = outcome
        if outcome != "ACCEPT":
            out.canonical_reject = getattr(canon, "reject", None)
            return DENY, STAGE_PROTOCOL, f"canonical_{outcome}"
        return self._call_v5(getattr(canon, "text", None), out, t)

    def _call_v4(self, snapshot: Snapshot, out: CascadeResult, t: dict):
        t0 = time.perf_counter()
        try:
            reply = self._v4(snapshot.raw_request_text)
        except Exception as exc:
            t["v4_ms"] = (time.perf_counter() - t0) * 1000
            out.v4 = {"status": "error", "detail": type(exc).__name__}
            return DENY, STAGE_V4, "v4_unavailable"
        t["v4_ms"] = (time.perf_counter() - t0) * 1000
        out.v4 = {"status": reply.status, "decision": reply.decision}
        if reply.status == "ok" and reply.decision == "ALLOW":
            return FORWARD, STAGE_V4, None
        return DENY, STAGE_V4, ("v4_block" if reply.status == "ok" else f"v4_{reply.status}")

    # ── public ───────────────────────────────────────────────────────────
    def route(self, snapshot: Snapshot) -> CascadeResult:
        out = CascadeResult(applied=DENY, deciding_stage=STAGE_PROTOCOL,
                            mode=self.config.mode, correlation_id=snapshot.correlation_id,
                            canonical_outcome=None)
        t: dict = {}
        mode = self.config.mode

        if mode == V4_ONLY:
            action, stage, reason = self._call_v4(snapshot, out, t)
            out.applied, out.deciding_stage, out.reason = action, stage, reason
            out.timings_ms = t
            return out

        if mode == V5_ONLY:
            action, stage, reason = self._run_v5_only(snapshot, out, t)
            out.applied, out.deciding_stage, out.reason = action, stage, reason
            out.cascade_applied, out.cascade_stage = action, stage
            out.timings_ms = t
            return out

        # CASCADE_OBSERVE / CASCADE_ACTIVE: always compute the cascade decision.
        # The stage boundaries already fail-closed, but the observed computation is
        # additionally isolated so an unexpected error in it can never strip V4 of
        # authority in OBSERVE mode (D-note: V4 unchanged while observing).
        try:
            c_action, c_stage, c_reason = self._run_cascade(snapshot, out, t)
        except Exception as exc:   # defensive: cascade computation must not leak out
            c_action, c_stage = DENY, STAGE_V5
            c_reason = f"cascade_error_{type(exc).__name__}"
            if out.v5 is None:
                out.v5 = {"status": "error", "detail": type(exc).__name__}
        out.cascade_applied, out.cascade_stage = c_action, c_stage

        if mode == CASCADE_ACTIVE:
            out.applied, out.deciding_stage, out.reason = c_action, c_stage, c_reason
            out.timings_ms = t
            return out

        # CASCADE_OBSERVE: V4 is applied regardless of the cascade computation; the
        # cascade is recorded only.
        action, stage, reason = self._call_v4(snapshot, out, t)
        out.applied, out.deciding_stage, out.reason = action, stage, reason
        out.timings_ms = t
        return out
