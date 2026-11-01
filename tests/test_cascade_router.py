"""Deterministic branch tests for the cascade router (`data_plane/cascade.py`).

Doubles only — no model, no HTTP, no canonicalization. Verifies the routing
contract of every branch: protocol reject, Fast Path FAST_ALLOW (no model call),
Model 2 BLOCK (no V5 call), DEFER -> V5, V5 ALLOW/BLOCK/invalid/error fail-closed,
V5_ONLY, CASCADE_OBSERVE (V4 applied, cascade recorded), V4_ONLY, and that a V5
exception never yields FORWARD.
"""
import os
import sys
import unittest
from dataclasses import dataclass
from typing import Optional

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "data_plane"))

import cascade as C  # noqa: E402


# ── doubles ──────────────────────────────────────────────────────────────
@dataclass
class FakeCanonical:
    outcome: str
    text: Optional[str] = None
    reject: Optional[str] = None


@dataclass
class FakeFP:
    decision: str
    reasons: tuple = ()
    rule_id: Optional[str] = None
    policy_id: Optional[str] = None
    policy_sha256: Optional[str] = None
    policy_status: Optional[str] = None


@dataclass
class FakeM2:
    decision: str
    status: str = "OK"
    p_block: Optional[float] = None
    threshold: Optional[float] = None
    feature_view: str = "baseline_34"
    model_artifact_sha256: str = "0" * 64
    policy_id: Optional[str] = "p"
    policy_sha256: Optional[str] = "s"
    policy_status: Optional[str] = "LAB_EXPERIMENTAL"


def snap(outcome="ACCEPT", text="GET / HTTP/1.1\n", reject=None):
    return C.Snapshot(method=b"GET", target=b"/", http_version="HTTP/1.1",
                      headers=(), body=b"", canonical=FakeCanonical(outcome, text, reject),
                      framing=None, raw_request_text="GET / HTTP/1.1\r\n\r\n",
                      correlation_id="cid-1")


def router(mode, *, fp="CONTINUE", fp_reasons=("NO_RULE_MATCHED",), m2="DEFER",
           m2_status="OK", m2_exc=None, v5_reply=None, v5_exc=None, v4_reply=None):
    calls = {"m2": 0, "v5": 0, "v4": 0}

    def fp_eval(inp, policy):
        return FakeFP(fp, () if fp == "FAST_ALLOW" else fp_reasons,
                      rule_id=("r1" if fp == "FAST_ALLOW" else None))

    def m2_decide(canonical_outcome, canonical_text):
        calls["m2"] += 1
        if m2_exc:
            raise m2_exc
        return FakeM2(m2, status=m2_status)

    def v5_classify(text):
        calls["v5"] += 1
        if v5_exc:
            raise v5_exc
        return v5_reply

    def v4_classify(raw):
        calls["v4"] += 1
        return v4_reply

    r = C.CascadeRouter(C.CascadeConfig(mode=mode),
                        fast_path_evaluate=fp_eval, model2_decide=m2_decide,
                        v5_classify=v5_classify, v4_classify=v4_classify,
                        make_fast_path_input=lambda s: s)
    return r, calls


class CascadeRouterTests(unittest.TestCase):
    def test_protocol_reject_denies_without_models(self):
        r, calls = router(C.CASCADE_ACTIVE)
        out = r.route(snap(outcome="REJECT", text=None, reject="R8"))
        self.assertEqual(out.applied, C.DENY)
        self.assertEqual(out.deciding_stage, C.STAGE_PROTOCOL)
        self.assertEqual(out.reason, "canonical_REJECT")
        self.assertEqual(out.canonical_reject, "R8")
        self.assertEqual((calls["m2"], calls["v5"]), (0, 0))

    def test_protocol_unsupported_denies(self):
        r, calls = router(C.CASCADE_ACTIVE)
        out = r.route(snap(outcome="UNSUPPORTED", text=None))
        self.assertEqual(out.applied, C.DENY)
        self.assertEqual(out.deciding_stage, C.STAGE_PROTOCOL)
        self.assertEqual((calls["m2"], calls["v5"]), (0, 0))

    def test_fast_allow_forwards_without_models(self):
        r, calls = router(C.CASCADE_ACTIVE, fp="FAST_ALLOW")
        out = r.route(snap())
        self.assertEqual(out.applied, C.FORWARD)
        self.assertEqual(out.deciding_stage, C.STAGE_FAST_PATH)
        self.assertEqual((calls["m2"], calls["v5"]), (0, 0))
        self.assertEqual(out.fast_path["rule_id"], "r1")

    def test_model2_block_denies_without_v5(self):
        r, calls = router(C.CASCADE_ACTIVE, m2="BLOCK")
        out = r.route(snap())
        self.assertEqual(out.applied, C.DENY)
        self.assertEqual(out.deciding_stage, C.STAGE_MODEL2)
        self.assertEqual(out.reason, "model2_block")
        self.assertEqual((calls["m2"], calls["v5"]), (1, 0))

    def test_defer_calls_v5_once_allow_forwards(self):
        r, calls = router(C.CASCADE_ACTIVE, m2="DEFER",
                          v5_reply=C.V5Reply(status="ok", decision="ALLOW"))
        out = r.route(snap())
        self.assertEqual(out.applied, C.FORWARD)
        self.assertEqual(out.deciding_stage, C.STAGE_V5)
        self.assertEqual((calls["m2"], calls["v5"]), (1, 1))

    def test_defer_v5_block_denies(self):
        r, calls = router(C.CASCADE_ACTIVE, m2="DEFER",
                          v5_reply=C.V5Reply(status="ok", decision="BLOCK"))
        out = r.route(snap())
        self.assertEqual(out.applied, C.DENY)
        self.assertEqual(out.deciding_stage, C.STAGE_V5)
        self.assertEqual(out.reason, "v5_block")

    def test_v5_invalid_denies_fail_closed(self):
        r, _ = router(C.CASCADE_ACTIVE, m2="DEFER",
                      v5_reply=C.V5Reply(status="invalid", invalid_reason="no_eos"))
        out = r.route(snap())
        self.assertEqual(out.applied, C.DENY)
        self.assertEqual(out.deciding_stage, C.STAGE_V5)
        self.assertEqual(out.reason, "v5_invalid")

    def test_v5_exception_denies_never_forward(self):
        r, _ = router(C.CASCADE_ACTIVE, m2="DEFER", v5_exc=TimeoutError("boom"))
        out = r.route(snap())
        self.assertEqual(out.applied, C.DENY)
        self.assertEqual(out.deciding_stage, C.STAGE_V5)
        self.assertEqual(out.reason, "v5_unavailable")
        self.assertEqual(out.v5["status"], "error")

    def test_model2_non_ok_status_still_defers_to_v5(self):
        # A decider that returns DEFER with a non-OK status (fail-to-defer).
        r, calls = router(C.CASCADE_ACTIVE, m2="DEFER",
                          v5_reply=C.V5Reply(status="ok", decision="ALLOW"))
        out = r.route(snap())
        self.assertEqual(out.model2["decision"], "DEFER")
        self.assertEqual(calls["v5"], 1)

    def test_model2_exception_defers_to_v5_not_propagated(self):
        # A synthetic Model 2 timeout must NOT propagate out of route(); the router
        # declares fail-to-DEFER, so V5 is consulted and decides the request.
        r, calls = router(C.CASCADE_ACTIVE, m2_exc=TimeoutError("m2 timeout"),
                          v5_reply=C.V5Reply(status="ok", decision="ALLOW"))
        out = r.route(snap())
        self.assertEqual(calls["m2"], 1)
        self.assertEqual(calls["v5"], 1)                 # V5 WAS called
        self.assertEqual(out.applied, C.FORWARD)          # V5's ALLOW applied
        self.assertEqual(out.deciding_stage, C.STAGE_V5)
        self.assertEqual(out.model2["status"], "error")   # failure recorded
        self.assertEqual(out.model2["detail"], "TimeoutError")
        self.assertIsNone(out.model2["decision"])

    def test_model2_inconsistent_block_with_non_ok_status_defers_to_v5(self):
        # SCORING_FAILED + decision=BLOCK is an inconsistent reply: the BLOCK string
        # must NOT be trusted to deny early. It fails to DEFER and V5 decides.
        r, calls = router(C.CASCADE_ACTIVE, m2="BLOCK", m2_status="SCORING_FAILED",
                          v5_reply=C.V5Reply(status="ok", decision="BLOCK"))
        out = r.route(snap())
        self.assertEqual(calls["v5"], 1)                  # V5 consulted despite BLOCK
        self.assertEqual(out.deciding_stage, C.STAGE_V5)  # not model2
        self.assertEqual(out.applied, C.DENY)             # V5's BLOCK, with V5 reason
        self.assertEqual(out.reason, "v5_block")
        self.assertEqual(out.model2["status"], "SCORING_FAILED")

    def test_model2_block_with_ok_status_still_early_blocks(self):
        # The honest path is unchanged: OK + BLOCK short-circuits without V5.
        r, calls = router(C.CASCADE_ACTIVE, m2="BLOCK", m2_status="OK")
        out = r.route(snap())
        self.assertEqual(out.applied, C.DENY)
        self.assertEqual(out.deciding_stage, C.STAGE_MODEL2)
        self.assertEqual((calls["m2"], calls["v5"]), (1, 0))

    def test_observe_keeps_v4_authority_when_model2_raises(self):
        # In OBSERVE a Model 2 failure must not strip V4 of authority: V4 is still
        # applied, and the recorded cascade fails-to-DEFER into V5 (recorded only).
        r, calls = router(C.CASCADE_OBSERVE, m2_exc=TimeoutError("m2 timeout"),
                          v5_reply=C.V5Reply(status="ok", decision="BLOCK"),
                          v4_reply=C.V4Reply(status="ok", decision="ALLOW"))
        out = r.route(snap())
        self.assertEqual(out.applied, C.FORWARD)          # V4 ALLOW applied
        self.assertEqual(out.deciding_stage, C.STAGE_V4)
        self.assertEqual(calls["v4"], 1)
        self.assertEqual(out.model2["status"], "error")   # cascade recorded the failure
        self.assertEqual(out.cascade_applied, C.DENY)     # recorded cascade -> V5 BLOCK
        self.assertEqual(out.cascade_stage, C.STAGE_V5)

    def test_v5_only_skips_fast_path_and_model2(self):
        r, calls = router(C.V5_ONLY, v5_reply=C.V5Reply(status="ok", decision="ALLOW"))
        out = r.route(snap())
        self.assertEqual(out.applied, C.FORWARD)
        self.assertEqual(out.deciding_stage, C.STAGE_V5)
        self.assertIsNone(out.fast_path)
        self.assertEqual((calls["m2"], calls["v5"]), (0, 1))

    def test_v5_only_protocol_reject_denies(self):
        r, calls = router(C.V5_ONLY)
        out = r.route(snap(outcome="REJECT", text=None, reject="R4"))
        self.assertEqual(out.applied, C.DENY)
        self.assertEqual(out.deciding_stage, C.STAGE_PROTOCOL)
        self.assertEqual(calls["v5"], 0)

    def test_observe_applies_v4_but_records_cascade(self):
        r, calls = router(C.CASCADE_OBSERVE, m2="BLOCK",
                          v4_reply=C.V4Reply(status="ok", decision="ALLOW"))
        out = r.route(snap())
        # V4 applied (ALLOW -> FORWARD); cascade recorded a Model 2 BLOCK.
        self.assertEqual(out.applied, C.FORWARD)
        self.assertEqual(out.deciding_stage, C.STAGE_V4)
        self.assertEqual(out.cascade_applied, C.DENY)
        self.assertEqual(out.cascade_stage, C.STAGE_MODEL2)
        self.assertEqual(calls["v4"], 1)

    def test_v4_only_delegates(self):
        r, calls = router(C.V4_ONLY, v4_reply=C.V4Reply(status="ok", decision="BLOCK"))
        out = r.route(snap())
        self.assertEqual(out.applied, C.DENY)
        self.assertEqual(out.deciding_stage, C.STAGE_V4)
        self.assertEqual((calls["m2"], calls["v5"]), (0, 0))

    def test_v4_error_fail_closed(self):
        def boom(raw):
            raise ConnectionError("down")
        r = C.CascadeRouter(C.CascadeConfig(mode=C.V4_ONLY), v4_classify=boom)
        out = r.route(snap())
        self.assertEqual(out.applied, C.DENY)
        self.assertEqual(out.reason, "v4_unavailable")

    def test_config_rejects_unknown_mode(self):
        with self.assertRaises(ValueError):
            C.CascadeConfig(mode="NOPE")

    def test_config_forbids_v5_open_on_failure(self):
        with self.assertRaises(ValueError):
            C.CascadeConfig(v5_fail_closed=False)


if __name__ == "__main__":
    unittest.main()
