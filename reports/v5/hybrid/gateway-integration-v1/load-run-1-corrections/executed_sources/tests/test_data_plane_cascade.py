"""The cascade inside the mitmproxy addon: V4_ONLY, V5_ONLY, CASCADE_OBSERVE, CASCADE_ACTIVE and the
return to V4, on real mitmproxy flow objects with the real router.

    .venv-dataplane/bin/python -m unittest discover -s tests -p 'test_data_plane_cascade.py' -v

Doubles for the stages, the canonical pool and V4 (httpx.MockTransport). Real sockets, the real
mitmdump and the real workers are in `scripts/gateway_ops/live_check.py`.
"""
import asyncio
import http.server as stdlib_http_server
import json
import os
import sys
import tempfile
import threading
import types
import unittest
import urllib.request
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(REPO, "data_plane"), os.path.join(REPO, "scripts", "gateway_ops")]

try:
    import httpx
    from mitmproxy import http
    from mitmproxy.test import tflow, tutils
except ImportError as exc:
    raise unittest.SkipTest(f"needs the data plane environment (.venv-dataplane): {exc}")

import canonical_observer as obs    # noqa: E402
import canonical_request as cr      # noqa: E402
import cascade as C                 # noqa: E402
import cascade_addon as addon       # noqa: E402
import cascade_canonical as CC      # noqa: E402
import cascade_gateway as CG        # noqa: E402
import cascade_manifest as CM       # noqa: E402
import cascade_ops as ops           # noqa: E402
import cascade_runtime as RT        # noqa: E402
import data_plane as dp             # noqa: E402
import fast_path as fp              # noqa: E402
import fast_path_audit as FA        # noqa: E402
import gateway_framing as GF        # noqa: E402
import live_stack as L              # noqa: E402

LIMITS = cr.Limits(max_decoded_body=4800, token_budget=100, max_bytes_per_token=48)
URL = "http://classifier.test/classify"
MARKER = "Zq7Marker"


def make_flow(path=b"/catalog", method=b"GET", headers=((b"Host", b"shop.local"),), content=b"",
              http_version=b"HTTP/1.1"):
    req = tutils.treq(method=method, path=path, host="shop.local", port=80,
                      headers=http.Headers(list(headers)), content=content,
                      http_version=http_version, authority=b"")
    flow = tflow.tflow(req=req)
    flow.client_conn.timestamp_tls_setup = None
    return flow


class FakePool:
    """Canonicalizes in-process, so these tests need no worker."""

    def __init__(self):
        self.failure = None
        self.calls = 0
        self.ready = 1

    def status(self):
        return {"workers": 1, "ready": self.ready, "free": 1, "disabled": 0}

    def prewarm(self):
        pass

    def heal(self):
        pass

    def close(self):
        pass

    def _result(self, req):
        self.calls += 1
        if self.failure is not None:
            return CC.CanonicalOutcome(None, "injected", self.failure)
        result = cr.canonicalize(
            cr.RequestParts(method=bytes(req.data.method), target=bytes(req.data.path),
                            http_version=req.http_version,
                            headers=tuple((bytes(n), bytes(v)) for n, v in req.headers.fields),
                            body=req.raw_content), LIMITS)
        return CC.CanonicalOutcome(result, None, obs.OK)

    async def canonicalize(self, req, wait_seconds):
        return self._result(req)

    def try_capture(self, req):
        return self._result(req)

    async def finish(self, handle):
        return handle


class FakeModel2:
    state = "READY"
    incompatible = False
    ever_ready = True

    def __init__(self, decision="DEFER", status="OK", raises=None):
        self.decision, self.status_code, self.raises = decision, status, raises
        self.calls = 0

    def status(self):
        return {"state": self.state}

    def start(self):
        pass

    def heal(self):
        pass

    def close(self):
        pass

    def decide(self, *, canonical_outcome, canonical_text):
        self.calls += 1
        if self.raises:
            raise self.raises
        return types.SimpleNamespace(decision=self.decision, status=self.status_code, p_block=0.5,
                                     threshold=0.9)


class FakeV5:
    def __init__(self, reply=None, raises=None):
        self.reply = reply or C.V5Reply(status="ok", decision="ALLOW")
        self.raises = raises
        self.calls = 0

    def __call__(self, text):
        self.calls += 1
        if self.raises:
            raise self.raises
        return self.reply


class Base(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.records = []
        self.v4_seen = []

    def v4_transport(self, decision="ALLOW", status_code=200):
        def handler(request):
            self.v4_seen.append(json.loads(request.content)["request"])
            return httpx.Response(status_code, json={"status": "ok", "decision": decision,
                                                     "reason": "x", "model_latency_ms": 1.0})
        return httpx.MockTransport(handler)

    def runtime(self, mode, *, pool=None, model2=None, v5=None, policy=None, auditor=None,
                ready=True, **overrides):
        kwargs = dict(mode=mode, manifest="m.json", listen_port=8080, guard_port=8081, sink_port=8082,
                      admin_port=8083, v4_url="http://127.0.0.1:1", v5_url="http://127.0.0.1:2",
                      workdir=self.tmp.name)
        kwargs.update(overrides)
        cfg = CM.parse_gateway_config(L.gateway_config(**kwargs)["cascade_gateway"])
        manifest = types.SimpleNamespace(
            manifest_id="m-1", sha256="a" * 64, status="EXPERIMENTAL", model2=None,
            canonical=types.SimpleNamespace(token_budget_B=100), v5=None)
        self.pool = pool or FakePool()
        self.model2 = model2 or FakeModel2()
        self.v5 = v5 or FakeV5()
        sink = types.SimpleNamespace(write=self.records.append, close=lambda *a: None)
        runtime = CG.CascadeRuntime(cfg, manifest, v4_health_url="http://127.0.0.1:1/health",
                                    policy=policy, canonical_pool=self.pool, model2=self.model2,
                                    v5_client=self.v5, sink=sink, auditor=auditor,
                                    metrics=ops.Metrics())
        self.addCleanup(runtime._executor.shutdown, False)
        if ready:
            runtime._profile_problems = ()
            runtime._v5_problems = ()
            runtime._v4_ok = True
            if runtime.guard is not None:
                runtime.guard = types.SimpleNamespace(listening=True)
        return runtime

    def gateway(self, runtime=None, decision="ALLOW", status_code=200):
        return addon.CascadeFirewallGateway(URL, 1.0, transport=self.v4_transport(decision, status_code),
                                            cascade=runtime)

    async def settle(self, runtime):
        for _ in range(100):
            if not runtime._tasks:
                return
            await asyncio.sleep(0.005)
        self.fail("observation did not finish")

    def decisions(self):
        return [r for r in self.records if r.get("kind") == "decision"]


class V4OnlyTests(Base):
    async def test_no_runtime_is_exactly_the_v4_gateway(self):
        for decision, expected in (("ALLOW", None), ("BLOCK", 403)):
            flow = make_flow()
            await self.gateway(None, decision).request(flow)
            self.assertEqual(flow.response.status_code if flow.response else None, expected)

    async def test_same_v4_input_and_action_as_the_base_gateway(self):
        base_flow, sub_flow = make_flow(), make_flow()
        base = dp.FirewallGateway(URL, 1.0, transport=self.v4_transport())
        await base.request(base_flow)
        await self.gateway(None).request(sub_flow)
        self.assertEqual(self.v4_seen[0], self.v4_seen[1])
        self.assertIsNone(base_flow.response)
        self.assertIsNone(sub_flow.response)

    async def test_v4_failure_stays_fail_closed(self):
        flow = make_flow()
        await self.gateway(None, status_code=503).request(flow)
        self.assertEqual(flow.response.status_code, 503)


class ActiveTests(Base):
    async def decide(self, runtime, flow=None):
        flow = flow or make_flow()
        await self.gateway(runtime).request(flow)
        self.assertEqual(self.v4_seen, [], "V4 must not be asked in an authoritative mode")
        return flow

    async def test_v5_allow_forwards_and_issues_the_ticket(self):
        runtime = self.runtime(C.CASCADE_ACTIVE)
        flow = await self.decide(runtime)
        self.assertIsNone(flow.response)
        self.assertEqual(len(runtime.book), 1)
        self.assertEqual(self.v5.calls, 1)
        record = self.decisions()[0]
        self.assertEqual((record["applied"], record["deciding_stage"], record["framing_status"]),
                         (C.FORWARD, C.STAGE_V5, GF.EGRESS_BOUND))
        self.assertEqual(runtime.metrics.value("firewall_requests_total", mode=C.CASCADE_ACTIVE,
                                               applied=C.FORWARD, stage=C.STAGE_V5), 1)

    async def test_v5_block_denies_without_a_ticket(self):
        runtime = self.runtime(C.CASCADE_ACTIVE, v5=FakeV5(C.V5Reply(status="ok", decision="BLOCK")))
        flow = await self.decide(runtime)
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(len(runtime.book), 0)

    async def test_model2_block_needs_no_v5_call(self):
        runtime = self.runtime(C.CASCADE_ACTIVE, model2=FakeModel2("BLOCK"))
        flow = await self.decide(runtime)
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(self.v5.calls, 0)

    async def test_model2_exception_defers_to_v5(self):
        runtime = self.runtime(C.CASCADE_ACTIVE, model2=FakeModel2(raises=RuntimeError("x")))
        flow = await self.decide(runtime)
        self.assertIsNone(flow.response)
        self.assertEqual(self.v5.calls, 1)
        self.assertEqual(self.decisions()[0]["model2"]["status"], "error")

    async def test_model2_non_ok_block_defers_to_v5(self):
        runtime = self.runtime(C.CASCADE_ACTIVE, model2=FakeModel2("BLOCK", "SCORING_FAILED"))
        flow = await self.decide(runtime)
        self.assertIsNone(flow.response)
        self.assertEqual(self.v5.calls, 1)

    async def test_v5_invalid_error_and_timeout_deny(self):
        cases = (FakeV5(C.V5Reply(status="invalid", invalid_reason="no_eos")),
                 FakeV5(C.V5Reply(status="error", detail="http_503")),
                 FakeV5(raises=TimeoutError()),
                 FakeV5(C.V5Reply(status="ok", decision="MAYBE")))
        for v5 in cases:
            runtime = self.runtime(C.CASCADE_ACTIVE, v5=v5)
            flow = await self.decide(runtime)
            self.assertEqual(flow.response.status_code, 503)
            self.assertEqual(len(runtime.book), 0)

    async def test_canonical_reject_is_a_protocol_answer_without_models(self):
        runtime = self.runtime(C.CASCADE_ACTIVE)
        flow = make_flow(headers=[(b"Host", b"h"), (b"Content-Type", b"a/b"), (b"Content-Type", b"c/d")])
        await self.decide(runtime, flow)
        self.assertEqual(flow.response.status_code, 400)
        self.assertEqual((self.model2.calls, self.v5.calls), (0, 0))

    async def test_no_canonical_result_denies(self):
        pool = FakePool()
        pool.failure = obs.TIMEOUT
        runtime = self.runtime(C.CASCADE_ACTIVE, pool=pool)
        flow = await self.decide(runtime)
        self.assertEqual(flow.response.status_code, 503)
        self.assertEqual(self.decisions()[0]["deciding_stage"], "canonical")

    async def test_oversize_snapshot_is_413(self):
        pool = FakePool()
        pool.failure = obs.DROP
        flow = await self.decide(self.runtime(C.CASCADE_ACTIVE, pool=pool))
        self.assertEqual(flow.response.status_code, 413)

    async def test_out_of_scope_is_rejected_before_any_stage(self):
        runtime = self.runtime(C.CASCADE_ACTIVE)
        flow = make_flow(http_version=b"HTTP/1.0")
        await self.decide(runtime, flow)
        self.assertEqual(flow.response.status_code, 505)
        self.assertEqual(self.pool.calls, 0)

    async def test_ambiguous_message_is_rejected_before_any_stage(self):
        runtime = self.runtime(C.CASCADE_ACTIVE)
        flow = make_flow(method=b"POST", headers=[(b"Host", b"h"), (b"Content-Length", b"0"),
                                                  (b"Transfer-Encoding", b"chunked")])
        await self.decide(runtime, flow)
        self.assertEqual(flow.response.status_code, 400)
        self.assertEqual(self.pool.calls, 0)

    async def test_not_ready_denies_without_stages(self):
        for problem in ("_profile_problems", "_v5_problems"):
            runtime = self.runtime(C.CASCADE_ACTIVE)
            setattr(runtime, problem, ("injected",))
            flow = await self.decide(runtime)
            self.assertEqual(flow.response.status_code, 503)
            self.assertEqual(self.pool.calls, 0)

    async def test_model2_that_never_proved_its_identity_is_not_ready(self):
        model2 = FakeModel2()
        model2.ever_ready = False
        runtime = self.runtime(C.CASCADE_ACTIVE, model2=model2)
        self.assertIn("model2_not_started", runtime.problems())
        model2.ever_ready, model2.incompatible = True, True
        self.assertIn("model2_incompatible", runtime.problems())

    async def test_observation_waits_for_model2_too(self):
        model2 = FakeModel2()
        model2.ever_ready = False
        runtime = self.runtime(C.CASCADE_OBSERVE, model2=model2)
        self.assertIn("model2_not_started", runtime.problems())

    async def test_model2_crash_after_start_is_degraded_not_unready(self):
        model2 = FakeModel2()
        model2.state = "BACKOFF"
        runtime = self.runtime(C.CASCADE_ACTIVE, model2=model2)
        ready, detail = runtime.readiness()
        self.assertTrue(ready)
        self.assertEqual(detail["degraded"], ["model2_BACKOFF"])

    async def test_guard_down_is_not_ready(self):
        runtime = self.runtime(C.CASCADE_ACTIVE)
        runtime.guard = types.SimpleNamespace(listening=False)
        self.assertIn("egress_guard_down", runtime.problems())

    async def test_probe_restarts_a_stopped_guard(self):
        runtime = self.runtime(C.CASCADE_ACTIVE)
        started = []

        class Guard:
            listening = False

            async def start(self):
                started.append(True)
                self.listening = True

        runtime.guard = Guard()
        with mock.patch.object(CG, "_http_json", lambda url, timeout: None):
            await runtime.probe_once()
            await runtime.probe_once()
        self.assertEqual(started, [True])
        self.assertEqual(runtime.metrics.value("firewall_guard_restarts_total", result="ok"), 1)

    async def test_a_failed_guard_restart_stays_not_ready(self):
        runtime = self.runtime(C.CASCADE_ACTIVE)

        class Guard:
            listening = False

            async def start(self):
                raise OSError("address in use")

        runtime.guard = Guard()
        with mock.patch.object(CG, "_http_json", lambda url, timeout: None):
            await runtime.probe_once()
        self.assertIn("egress_guard_down", runtime.problems())
        self.assertEqual(runtime.metrics.value("firewall_guard_restarts_total", result="failed"), 1)

    async def test_waiting_for_admission_is_recorded(self):
        runtime = self.runtime(C.CASCADE_ACTIVE)
        await self.gateway(runtime).request(make_flow())
        stages = self.decisions()[0]["stage_ms"]
        self.assertIn("admission", stages)
        self.assertIn("canonical_with_wait", stages)

    async def test_ticket_book_full_denies(self):
        runtime = self.runtime(C.CASCADE_ACTIVE)
        runtime.book.max_tickets = 0
        flow = await self.decide(runtime)
        self.assertEqual(flow.response.status_code, 503)

    async def test_saturation_is_bounded_and_fail_closed(self):
        gate = threading.Event()
        self.addCleanup(gate.set)

        class SlowV5(FakeV5):
            def __call__(self, text):
                gate.wait(5)
                return super().__call__(text)

        runtime = self.runtime(C.CASCADE_ACTIVE, v5=SlowV5(), max_inflight=1, max_waiting=0)
        first = asyncio.ensure_future(self.decide(runtime))
        await asyncio.sleep(0.05)
        flow = await self.decide(runtime)
        self.assertEqual(flow.response.status_code, 503)
        self.assertEqual(self.decisions()[0]["deciding_stage"], "admission")
        gate.set()
        served = await first
        self.assertIsNone(served.response)

    async def test_decision_deadline_denies_and_keeps_the_slot_until_the_thread_ends(self):
        gate = threading.Event()
        self.addCleanup(gate.set)

        class SlowV5(FakeV5):
            def __call__(self, text):
                gate.wait(5)
                return super().__call__(text)

        runtime = self.runtime(C.CASCADE_ACTIVE, v5=SlowV5(), max_inflight=1, max_waiting=0)
        runtime.cfg = types.SimpleNamespace(**{**vars(runtime.cfg), "decision_deadline_seconds": 0.05})
        flow = await self.decide(runtime)
        self.assertEqual(flow.response.status_code, 503)
        self.assertEqual(self.decisions()[0]["reason"], "decision_deadline")
        self.assertTrue(runtime._slots.locked())
        gate.set()
        await asyncio.sleep(0.05)
        self.assertFalse(runtime._slots.locked())

    async def test_unexpected_error_is_fail_closed_at_the_hook(self):
        runtime = self.runtime(C.CASCADE_ACTIVE)
        with mock.patch.object(GF, "bind_delivery", side_effect=RuntimeError("boom")), \
                self.assertLogs("firewall.data_plane", level="ERROR"):
            flow = await self.decide(runtime)
        self.assertEqual(flow.response.status_code, 503)
        self.assertEqual(len(runtime.book), 0)

    async def test_records_carry_no_request_content(self):
        runtime = self.runtime(C.CASCADE_ACTIVE)
        flow = make_flow(path=f"/search?q={MARKER}".encode(), method=b"POST",
                         headers=[(b"Host", MARKER.encode()), (b"Content-Length", b"9"),
                                  (b"Content-Type", b"text/plain")], content=MARKER.encode())
        await self.decide(runtime, flow)
        self.assertNotIn(MARKER, json.dumps(ops.safe_record(self.decisions()[0])))
        self.assertNotIn(MARKER, runtime.metrics.render())
        self.assertNotIn("wire_sha256", {} if runtime.cfg.observability.log_wire_sha256
                         else self.decisions()[0])


POLICY = fp.parse_policy({
    "schema": fp.POLICY_SCHEMA, "policy_id": "EXPERIMENTAL-fixture", "status": "PROPOSED",
    "canonical_contract": "canonical-request/v1",
    "rules": [{"id": "health", "methods": ["GET"], "path": ["healthz"], "query": {},
               "required_query": [], "headers": {"host": {"type": "enum", "values": ["shop.local"]}}}]})


class FastPathTests(Base):
    def setUp(self):
        super().setUp()
        self.audited = []
        self.auditor = types.SimpleNamespace(
            submit=lambda **k: self.audited.append(k), close=lambda: None)

    def fast_runtime(self, **kwargs):
        kwargs.setdefault("auditor", self.auditor)
        policy_path = os.path.join(self.tmp.name, "unused.json")
        runtime = self.runtime(kwargs.pop("mode", C.CASCADE_ACTIVE), policy=POLICY,
                               fast_path_policy=policy_path, fast_path_sha256="a" * 64, **kwargs)
        return runtime

    async def test_permit_skips_the_models_and_is_audited_after_the_ticket(self):
        runtime = self.fast_runtime()
        flow = make_flow(path=b"/healthz")
        await self.gateway(runtime).request(flow)
        self.assertIsNone(flow.response)
        self.assertEqual((self.model2.calls, self.v5.calls), (0, 0))
        self.assertEqual(len(runtime.book), 1)
        self.assertTrue(self.audited[0]["applied"])
        self.assertEqual(self.decisions()[0]["deciding_stage"], C.STAGE_FAST_PATH)

    async def test_no_match_continues_to_the_models(self):
        runtime = self.fast_runtime()
        await self.gateway(runtime).request(make_flow(path=b"/catalog"))
        self.assertEqual((self.model2.calls, self.v5.calls), (1, 1))
        self.assertEqual(self.audited, [])

    async def test_without_framing_evidence_a_matching_rule_does_not_apply(self):
        runtime = self.fast_runtime()
        runtime.verified_evidence = False
        await self.gateway(runtime).request(make_flow(path=b"/healthz"))
        self.assertEqual(self.v5.calls, 1)
        self.assertIn("FRAMING_UNVERIFIED", self.decisions()[0]["fast_path"]["reasons"])

    async def test_disabled_activation_never_permits(self):
        runtime = self.runtime(C.CASCADE_ACTIVE)
        await self.gateway(runtime).request(make_flow(path=b"/healthz"))
        self.assertIsNone(runtime.policy)
        self.assertIn("POLICY_UNAVAILABLE", self.decisions()[0]["fast_path"]["reasons"])
        self.assertEqual(self.v5.calls, 1)

    async def test_auditor_failure_cannot_touch_an_applied_permit(self):
        real = FA.FastPathAuditor(
            types.SimpleNamespace(sample_rate=1.0, sample_salt="s", queue_size=1, max_queue_bytes=10,
                                  workers=1, timeout_seconds=0.1, max_abandoned=1,
                                  shutdown_drain_seconds=0.0),
            mock.Mock(side_effect=RuntimeError("audit")), self.records.append)
        self.addCleanup(real.close)
        runtime = self.fast_runtime(auditor=real)
        flow = make_flow(path=b"/healthz")
        await self.gateway(runtime).request(flow)
        self.assertIsNone(flow.response)
        self.assertEqual(len(runtime.book), 1)


class ObserveTests(Base):
    async def observe(self, runtime, flow=None, decision="ALLOW", status_code=200):
        flow = flow or make_flow()
        await self.gateway(runtime, decision, status_code).request(flow)
        await self.settle(runtime)
        return flow

    async def test_v4_applies_and_the_cascade_is_recorded(self):
        runtime = self.runtime(C.CASCADE_OBSERVE, model2=FakeModel2("BLOCK"))
        flow = await self.observe(runtime)
        self.assertIsNone(flow.response)
        self.assertEqual(len(self.v4_seen), 1)
        record = self.decisions()[0]
        self.assertEqual((record["applied"], record["deciding_stage"]), (C.FORWARD, C.STAGE_V4))
        self.assertEqual((record["cascade_applied"], record["cascade_stage"]), (C.DENY, C.STAGE_MODEL2))
        self.assertEqual(runtime.metrics.value("firewall_observe_agreement_total",
                                               agreement="different"), 1)

    async def test_v4_block_is_kept_when_the_cascade_would_allow(self):
        runtime = self.runtime(C.CASCADE_OBSERVE)
        flow = await self.observe(runtime, decision="BLOCK")
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(self.decisions()[0]["cascade_applied"], C.FORWARD)

    async def test_v4_failure_is_recorded_as_such(self):
        runtime = self.runtime(C.CASCADE_OBSERVE)
        flow = await self.observe(runtime, status_code=503)
        self.assertEqual(flow.response.status_code, 503)
        self.assertEqual(self.decisions()[0]["v4"]["status"], "error")

    async def test_no_ticket_and_no_guard_in_observe(self):
        runtime = self.runtime(C.CASCADE_OBSERVE)
        await self.observe(runtime)
        self.assertIsNone(runtime.guard)
        self.assertEqual(len(runtime.book), 0)
        self.assertEqual(runtime.expected_target, ("127.0.0.1", 8082))

    async def test_every_cascade_failure_leaves_v4_unchanged(self):
        def bomb(*a, **k):
            raise RuntimeError("cascade failure")

        injections = [
            ("bind", mock.patch.object(GF, "bind_delivery", bomb)),
            ("scope", mock.patch.object(GF, "check_scope", bomb)),
            ("router", mock.patch.object(C.CascadeRouter, "route", bomb)),
            ("problems", mock.patch.object(CG.CascadeRuntime, "problems", bomb)),
            ("v5", mock.patch.object(FakeV5, "__call__", bomb)),
            ("model2", mock.patch.object(FakeModel2, "decide", bomb)),
            ("capture", mock.patch.object(FakePool, "try_capture", bomb)),
            ("finish", mock.patch.object(FakePool, "finish", bomb)),
        ]
        reference = make_flow()
        await self.gateway(None).request(reference)
        v4_input = self.v4_seen[-1]
        for name, patch in injections:
            with self.subTest(injected=name), patch:
                runtime = self.runtime(C.CASCADE_OBSERVE)
                flow = await self.observe(runtime)
                self.assertIsNone(flow.response)
                self.assertEqual(self.v4_seen[-1], v4_input)

    async def test_no_canonical_result_loses_only_the_observation(self):
        pool = FakePool()
        pool.failure = obs.TIMEOUT
        runtime = self.runtime(C.CASCADE_OBSERVE, pool=pool)
        flow = await self.observe(runtime)
        self.assertIsNone(flow.response)
        self.assertEqual(runtime.metrics.value("firewall_observe_total",
                                               status="canonical_unavailable"), 1)

    async def test_not_ready_skips_the_observation(self):
        runtime = self.runtime(C.CASCADE_OBSERVE, ready=False)
        flow = await self.observe(runtime)
        self.assertIsNone(flow.response)
        self.assertEqual(self.pool.calls, 0)
        self.assertEqual(runtime.metrics.value("firewall_observe_total", status="not_ready"), 1)

    async def test_out_of_scope_is_observed_without_a_verdict(self):
        runtime = self.runtime(C.CASCADE_OBSERVE)
        flow = await self.observe(runtime, make_flow(http_version=b"HTTP/1.0"))
        self.assertIsNone(flow.response)
        self.assertEqual(runtime.metrics.value("firewall_observe_total", status="out_of_scope"), 1)

    async def test_pending_observations_are_bounded(self):
        runtime = self.runtime(C.CASCADE_OBSERVE)
        runtime._pending_observe = runtime.cfg.observe_max_pending
        flow = make_flow()
        await self.gateway(runtime).request(flow)
        self.assertIsNone(flow.response)
        self.assertEqual(runtime.metrics.value("firewall_observe_total", status="saturated"), 1)

    async def test_manifest_unusable_disables_the_observation_only(self):
        runtime = self.runtime(C.CASCADE_OBSERVE)
        runtime.manifest, runtime.enabled = None, False
        runtime.manifest_problems = ("manifest_unusable",)
        flow = await self.observe(runtime)
        self.assertIsNone(flow.response)
        ready, detail = runtime.readiness()
        self.assertTrue(ready)
        self.assertEqual(detail["cascade_problems"], ["manifest_unusable"])


class ReturnToV4Tests(Base):
    async def test_sentinel_hands_authority_to_v4_and_back(self):
        runtime = self.runtime(C.CASCADE_ACTIVE, model2=FakeModel2("BLOCK"))
        gateway = self.gateway(runtime)
        runtime_flow = make_flow()
        await gateway.request(runtime_flow)
        self.assertEqual(runtime_flow.response.status_code, 403)
        self.assertEqual(self.v4_seen, [])

        open(runtime.cfg.rollback_file, "w").close()
        self.assertFalse(runtime.authoritative())
        self.assertEqual(runtime.effective_mode(), C.V4_ONLY)
        flow = make_flow()
        await gateway.request(flow)
        self.assertIsNone(flow.response)
        self.assertEqual(len(self.v4_seen), 1)
        self.assertEqual(self.model2.calls, 1)
        ready, detail = runtime.readiness()
        self.assertEqual(detail["effective_mode"], C.V4_ONLY)

        os.unlink(runtime.cfg.rollback_file)
        self.assertTrue(runtime.authoritative())
        flow = make_flow()
        await gateway.request(flow)
        self.assertEqual(flow.response.status_code, 403)

    async def test_observation_stops_during_the_return(self):
        runtime = self.runtime(C.CASCADE_OBSERVE)
        open(runtime.cfg.rollback_file, "w").close()
        await self.gateway(runtime).request(make_flow())
        self.assertEqual(self.pool.calls, 0)


class V5OnlyTests(Base):
    async def test_no_model2_and_no_fast_path(self):
        runtime = self.runtime(C.V5_ONLY, model2=FakeModel2("BLOCK"), policy=POLICY)
        flow = make_flow(path=b"/healthz")
        await self.gateway(runtime).request(flow)
        self.assertIsNone(flow.response)
        self.assertEqual((self.model2.calls, self.v5.calls), (0, 1))
        self.assertEqual(len(runtime.book), 1)

    async def test_failure_denies(self):
        runtime = self.runtime(C.V5_ONLY, v5=FakeV5(raises=OSError()))
        flow = make_flow()
        await self.gateway(runtime).request(flow)
        self.assertEqual(flow.response.status_code, 503)


class V5ServiceClientTests(unittest.TestCase):
    """It must answer exactly like `V5HttpClient`, the client the 30 October evidence measured."""

    def setUp(self):
        replies = self.replies = {}

        class Handler(stdlib_http_server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                status, body = replies["current"]
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = stdlib_http_server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.metrics = ops.Metrics()

    def both(self, url=None):
        url = url or self.url
        base, ours = RT.V5HttpClient(url, 1.0), CG.V5ServiceClient(url, 1.0, self.metrics)
        return base("t"), ours("t"), ours

    def test_answers_like_the_base_client(self):
        cases = ((200, b'{"status":"ok","decision":"ALLOW","invalid_reason":null,"generate_ms":9.5}'),
                 (200, b'{"status":"ok","decision":"BLOCK"}'),
                 (200, b'{"status":"invalid","invalid_reason":"not_in_vocabulary"}'),
                 (200, b'{"decision":"ALLOW"}'),
                 (200, b'{not json'),
                 (500, b'{}'), (503, b'{}'))
        for status, body in cases:
            with self.subTest(status=status, body=body):
                self.replies["current"] = (status, body)
                base, ours, _ = self.both()
                self.assertEqual(ours, base)

    def test_unreachable_service_answers_like_the_base_client(self):
        import socket
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        base, ours, _ = self.both(f"http://127.0.0.1:{port}")
        self.assertEqual(ours, base)

    def test_a_reply_that_is_not_an_object_fails_like_the_base_client(self):
        self.replies["current"] = (200, b"[1]")
        for client in (RT.V5HttpClient(self.url, 1.0), CG.V5ServiceClient(self.url, 1.0, self.metrics)):
            with self.assertRaises(AttributeError):
                client("t")

    def test_service_fields_are_kept_once(self):
        self.replies["current"] = (200, json.dumps({
            "status": "ok", "decision": "ALLOW", "queue_wait_ms": 7.0, "pipeline_ms": 90.0,
            "service_ms": 97.0, "generated_tokens": 13, "decoder_verified": True,
            "decoder_fallback": False}).encode())
        _, _, client = self.both()
        fields = client.take_fields()
        self.assertEqual((fields["queue_wait_ms"], fields["decoder_fallback"]), (7.0, False))
        self.assertIsNone(client.take_fields())

    def test_failure_detail_is_counted_and_keeps_no_fields(self):
        self.replies["current"] = (503, b"{}")
        _, reply, client = self.both()
        self.assertEqual(reply.detail, "http_503")
        self.assertEqual(self.metrics.value("firewall_v5_client_errors_total", detail="http_503"), 1)
        self.assertIsNone(client.take_fields())

    def test_a_valid_answer_counts_nothing(self):
        self.replies["current"] = (200, b'{"status":"ok","decision":"BLOCK"}')
        self.both()
        self.assertEqual(self.metrics.total("firewall_v5_client_errors_total"), 0)


class ProbeTests(Base):
    async def test_probe_binds_readiness_to_the_v5_contract(self):
        runtime = self.runtime(C.CASCADE_ACTIVE, ready=False)
        runtime._profile_problems = ()
        runtime.guard = types.SimpleNamespace(listening=True)
        v5 = CM.V5Identity("a" * 64, "b" * 64, "c" * 64, ("ALLOW",), 100)
        runtime.manifest.v5 = v5
        health = {"status": "ok", "model_loaded": True, "adapter_sha256": v5.adapter_sha256,
                  "template_fingerprint": v5.template_fingerprint}
        contract = {"template_fingerprint": v5.template_fingerprint, "recipe_sha256": v5.recipe_sha256,
                    "token_budget_B": 100, "vocabulary": ["ALLOW"]}
        replies = {"/health": health, "/contract": contract}

        def fake(url, timeout):
            return replies.get("/" + url.rsplit("/", 1)[1])

        with mock.patch.object(CG, "_http_json", fake):
            await runtime.probe_once()
            self.assertEqual(runtime.problems(), ())
            self.assertTrue(runtime.readiness()[0])
            replies["/contract"] = {**contract, "token_budget_B": 200}
            await runtime.probe_once()
            self.assertIn("v5_token_budget_B_mismatch", runtime.problems())
            self.assertFalse(runtime.readiness()[0])
            replies.clear()
            await runtime.probe_once()
            self.assertEqual(runtime._v5_problems, ("v5_unreachable",))
        self.assertEqual(runtime.metrics.render().count("firewall_ready 0"), 1)

    async def test_the_service_client_ignores_proxy_variables(self):
        class Handler(stdlib_http_server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                body = b'{"status":"ok","decision":"ALLOW"}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = stdlib_http_server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.addCleanup(urllib.request.install_opener, urllib.request.build_opener())
        CG.install_direct_opener()
        with mock.patch.dict(os.environ, {"http_proxy": "http://127.0.0.1:1",
                                          "HTTP_PROXY": "http://127.0.0.1:1"}):
            reply = RT.V5HttpClient(f"http://127.0.0.1:{server.server_address[1]}")("GET / HTTP/1.1\n")
        self.assertEqual((reply.status, reply.decision), ("ok", "ALLOW"))


if __name__ == "__main__":
    unittest.main()
