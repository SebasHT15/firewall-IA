"""Gateway tests for the canonical-request/v1 shadow OBSERVER wired into the data plane
(data_plane.py + canonical_observer.py + canonical_adapter.py + canonical_worker.py), issue #68 / D69.

The contract under test, AGAINST THE INTEGRATED GATEWAY: V4 via /classify stays the ONLY enforcement
decision. Whatever the canonical observer does (answer OK, DROP, be BUSY, time out, crash, reply
malformed, be unavailable, hang, or fail to schedule) the client gets exactly what it would get with
the observer off, V4 is sent byte-identical D1 text through the unchanged /classify contract, the
observer runs ONLY after the verdict in a background task the request never awaits, and the outcome
appears only as a `CANONICAL OBS` log line of closed codes and numbers. The Fast Path stays
ineligible (GatewayEvidence.canonical is still None), by design (D69).

This suite is complementary to tests/test_canonical_observer.py (the observer in isolation) and
tests/test_canonical_adapter.py (the snapshot adapter): here the observer is driven THROUGH
`FirewallGateway` with an httpx.MockTransport classifier, so what is proven is the integration.

Needs the data plane environment (mitmproxy):
    .venv-dataplane/bin/python -m unittest tests.test_data_plane_canonical_observer -v

Under `python3.12 -m unittest discover -s tests` this module is reported as skipped.

NOTE: uses synthetic requests only; it never reads any dataset (no datasets/v4_clean/eval.jsonl).
"""

import asyncio
import hashlib
import os
import re
import socket
import sys
import time
import unittest
from unittest.mock import patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "data_plane"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import httpx
    from mitmproxy import http
    from mitmproxy.addons import blocklist
    from mitmproxy.test import taddons, tflow, tutils
except ImportError as exc:
    raise unittest.SkipTest(f"needs the data plane environment (.venv-dataplane): {exc}")

import data_plane
import canonical_observer as obs_mod
import canonical_adapter as adapter
# Reusing the data-plane test helpers (classifier doubles). Importing the module does not run its
# tests; in particular it never selects TestRenderRequest.test_reproduces_the_v4_dataset_representation
# (the protected dataset reader).
from test_data_plane import (CLASSIFIER_BEHAVIOURS, INVALID, OK_ALLOW, OK_BLOCK, URL,  # noqa: E402
                             classifier, make_request, recording_classifier)

CANONICAL_LOGGER = "firewall.data_plane.canonical"


# ── observer doubles ─────────────────────────────────────────────────────────
class StubObserver:
    """A canonical observer that follows the gateway's observer protocol (observe / startup_summary /
    prewarm / close) but answers deterministically, without a worker process. `behaviour(req)` returns
    a CanonicalObservation or raises. `calls` counts how often observe ran."""

    def __init__(self, behaviour=None):
        import logging
        self._logging = logging
        self.behaviour = behaviour or (
            lambda req: obs_mod.CanonicalObservation(obs_mod.OK, outcome="ACCEPT", size="UNCHECKED",
                                                     target_form=adapter.FORM_ORIGIN))
        self.calls = 0
        self.closed = False
        self.prewarmed = False

    async def observe(self, req):
        self.calls += 1
        return self.behaviour(req)

    def startup_summary(self):
        return self._logging.INFO, "canonical observer: stub (test)"

    def prewarm(self):
        self.prewarmed = True

    def close(self):
        self.closed = True


class HangingObserver(StubObserver):
    """observe() blocks on an asyncio.Event, so the background task is still pending when the request
    has already been forwarded."""

    def __init__(self):
        super().__init__()
        self.release = asyncio.Event()
        self.entered = asyncio.Event()

    async def observe(self, req):
        self.calls += 1
        self.entered.set()
        await self.release.wait()
        return obs_mod.CanonicalObservation(obs_mod.OK, outcome="ACCEPT", size="UNCHECKED")


def obs(status, **kw):
    return obs_mod.CanonicalObservation(status, **kw)


# Observation statuses the observer can report, each as a stub behaviour. Covers success and every
# failure/edge the observer can surface; all must be invisible to the client.
OBSERVER_BEHAVIOURS = {
    "OK ACCEPT": lambda req: obs(obs_mod.OK, outcome="ACCEPT", size="UNCHECKED",
                                 target_form=adapter.FORM_ORIGIN),
    "OK REJECT": lambda req: obs(obs_mod.OK, outcome="REJECT", reject="R3",
                                 reason="double_decode", target_form=adapter.FORM_ORIGIN),
    "BODY_UNAVAILABLE": lambda req: obs(obs_mod.BODY_UNAVAILABLE, detail="raw_content_none"),
    "OUT_OF_SCOPE": lambda req: obs(obs_mod.OUT_OF_SCOPE, detail=adapter.SCOPE_ABSOLUTE),
    "DROP": lambda req: obs(obs_mod.DROP, detail="body_too_large"),
    "BUSY": lambda req: obs(obs_mod.BUSY, detail="in_flight"),
    "TIMEOUT": lambda req: obs(obs_mod.TIMEOUT, detail="worker_killed"),
    "UNAVAILABLE": lambda req: obs(obs_mod.UNAVAILABLE, detail="worker_starting"),
    "EXCEPTION": lambda req: obs(obs_mod.EXCEPTION, detail="ipc_malformed_reply"),
    "raises": None,   # special-cased: StubObserver with a raising behaviour
}


def raising_behaviour(req):
    raise RuntimeError("boom token=secret-token-123")


class GatewayObserverTestCase(unittest.IsolatedAsyncioTestCase):
    def flow(self):
        return tflow.tflow(req=make_request(
            "POST", "/search?q=laptop&q=tv",
            headers=[("Host", "shop.example"), ("User-Agent", "curl/8.18.0"),
                     ("Content-Type", "application/x-www-form-urlencoded")],
            content=b"page=2&sort=price"))

    async def run_flow(self, transport, observer=None, flow=None, **kw):
        gateway = data_plane.FirewallGateway(URL, 1.0, transport=transport,
                                             canonical_observer=observer, **kw)
        flow = flow or self.flow()
        await gateway.request(flow)
        return gateway, flow

    @staticmethod
    async def drain(gateway):
        if gateway._shadow_tasks:
            await asyncio.gather(*list(gateway._shadow_tasks))

    @staticmethod
    def outcome(flow, seen):
        """What the client gets and the exact bytes V4 was sent."""
        response = None if flow.response is None else (flow.response.status_code, flow.response.text)
        return response, [r.content for r in seen]

    def make_observer(self, name):
        if name == "raises":
            return StubObserver(raising_behaviour)
        return StubObserver(OBSERVER_BEHAVIOURS[name])


# ── 1. V4 preservation: off vs on ─────────────────────────────────────────────
class TestV4PreservationOffVsOn(GatewayObserverTestCase):
    async def test_client_outcome_and_v4_input_identical_off_vs_on(self):
        """The decisive test: for every V4 behaviour and every observer behaviour, the client's
        response AND the bytes V4 received equal those of a gateway with no observer."""
        for v4_name, answer in CLASSIFIER_BEHAVIOURS.items():
            seen = []
            with self.assertLogs("firewall.data_plane", level="INFO"):
                _, flow = await self.run_flow(recording_classifier(seen, answer))
            baseline = self.outcome(flow, seen)
            for obs_name in OBSERVER_BEHAVIOURS:
                with self.subTest(v4=v4_name, observer=obs_name):
                    seen = []
                    with self.assertLogs("firewall.data_plane", level="INFO"):
                        gateway, flow = await self.run_flow(
                            recording_classifier(seen, answer), self.make_observer(obs_name))
                        await self.drain(gateway)
                    self.assertEqual(self.outcome(flow, seen), baseline)

    async def test_classify_request_body_is_byte_identical_and_uses_the_contract(self):
        """/classify is still POST <url> with body {"request": "<D1 text>"}; the bytes are identical
        with the observer on and off."""
        seen_off = []
        with self.assertLogs("firewall.data_plane", level="INFO"):
            await self.run_flow(recording_classifier(seen_off, CLASSIFIER_BEHAVIOURS["ALLOW"]))
        seen_on = []
        with self.assertLogs("firewall.data_plane", level="INFO"):
            gateway, _ = await self.run_flow(
                recording_classifier(seen_on, CLASSIFIER_BEHAVIOURS["ALLOW"]), StubObserver())
            await self.drain(gateway)
        self.assertEqual(len(seen_off), 1)
        self.assertEqual(len(seen_on), 1)
        self.assertEqual(seen_on[0].method, "POST")
        self.assertEqual(str(seen_on[0].url), URL)
        self.assertEqual(seen_on[0].content, seen_off[0].content)   # byte-identical
        import json
        self.assertEqual(set(json.loads(seen_on[0].content)), {"request"})   # schema unchanged

    async def test_exactly_one_classifier_call_for_a_classified_request(self):
        seen = []
        with self.assertLogs("firewall.data_plane", level="INFO"):
            gateway, _ = await self.run_flow(
                recording_classifier(seen, CLASSIFIER_BEHAVIOURS["ALLOW"]), StubObserver())
            await self.drain(gateway)
        self.assertEqual(len(seen), 1)

    async def test_zero_classifier_calls_and_no_observation_for_a_preanswered_flow(self):
        """A flow mitmproxy already answered (e.g. block_list) is neither classified nor observed."""
        seen = []
        observer = StubObserver()
        flow = tflow.tflow(req=make_request(), resp=True)
        original = flow.response
        gateway, flow = await self.run_flow(
            recording_classifier(seen, CLASSIFIER_BEHAVIOURS["ALLOW"]), observer, flow=flow)
        await self.drain(gateway)
        self.assertEqual(seen, [])
        self.assertEqual(observer.calls, 0)
        self.assertIs(flow.response, original)

    async def test_observer_cannot_turn_a_v4_block_into_an_allow(self):
        """Even an OK ACCEPT observation cannot unblock what V4 blocked or fail-closed."""
        for name in ("BLOCK", "invalid", "HTTP 500", "timeout"):
            with self.subTest(v4=name):
                observer = StubObserver(OBSERVER_BEHAVIOURS["OK ACCEPT"])
                with self.assertLogs("firewall.data_plane", level="INFO"):
                    gateway, flow = await self.run_flow(
                        recording_classifier([], CLASSIFIER_BEHAVIOURS[name]), observer)
                    await self.drain(gateway)
                self.assertIsNotNone(flow.response, "a request V4 blocked was let through")
                self.assertEqual(flow.response.status_code, 403 if name == "BLOCK" else 503)

    async def test_observer_cannot_turn_a_v4_allow_into_a_block(self):
        """An OK REJECT observation cannot block what V4 allowed."""
        observer = StubObserver(OBSERVER_BEHAVIOURS["OK REJECT"])
        with self.assertLogs("firewall.data_plane", level="INFO"):
            gateway, flow = await self.run_flow(
                recording_classifier([], CLASSIFIER_BEHAVIOURS["ALLOW"]), observer)
            await self.drain(gateway)
        self.assertIsNone(flow.response, "the observation changed V4's ALLOW")

    async def test_v4_is_asked_once_before_and_regardless_of_the_observer(self):
        seen = []
        observer = StubObserver(raising_behaviour)
        with self.assertLogs("firewall.data_plane", level="INFO"):
            gateway, flow = await self.run_flow(
                recording_classifier(seen, CLASSIFIER_BEHAVIOURS["ALLOW"]), observer)
            await self.drain(gateway)
        self.assertEqual(len(seen), 1)
        self.assertEqual(observer.calls, 1)
        self.assertIsNone(flow.response)

    async def test_connection_failure_is_503_with_the_observer_on(self):
        """No MockTransport: the classifier call really fails (closed port) -> fail-closed 503, which
        the observer never touches."""
        with socket.socket() as s:            # grab a free port, then leave it closed
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        gateway = data_plane.FirewallGateway(f"http://127.0.0.1:{port}/classify", 1.0,
                                             canonical_observer=StubObserver())
        with self.assertLogs("firewall.data_plane", level="ERROR") as logs:
            flow = self.flow()
            await gateway.request(flow)
            await self.drain(gateway)
        self.assertEqual(flow.response.status_code, 503)
        self.assertEqual(flow.response.text, data_plane.UNAVAILABLE_BODY)
        self.assertIn("BLOCK (fail-closed)", "\n".join(logs.output))


# ── 2. Isolation: no observer state can block or alter the request ─────────────
class TestIsolation(GatewayObserverTestCase):
    async def test_every_observer_failure_leaves_the_request_untouched(self):
        """startup-unavailable, BUSY, DROP(oversize), TIMEOUT, crash, malformed reply: none changes
        the V4 decision or the client response, and V4 is always asked exactly once."""
        failures = ["UNAVAILABLE", "BUSY", "DROP", "TIMEOUT", "EXCEPTION", "raises"]
        for v4_name, expected in (("ALLOW", None), ("BLOCK", 403), ("invalid", 503)):
            for obs_name in failures:
                with self.subTest(v4=v4_name, observer=obs_name):
                    seen = []
                    with self.assertLogs("firewall.data_plane", level="INFO"):
                        gateway, flow = await self.run_flow(
                            recording_classifier(seen, CLASSIFIER_BEHAVIOURS[v4_name]),
                            self.make_observer(obs_name))
                        await self.drain(gateway)
                    status = None if flow.response is None else flow.response.status_code
                    self.assertEqual(status, expected)
                    self.assertEqual(len(seen), 1, "V4 must still be asked exactly once")

    async def test_a_hung_observer_never_delays_the_response(self):
        observer = HangingObserver()
        gateway = data_plane.FirewallGateway(
            URL, 1.0, transport=classifier(json_body=OK_BLOCK), canonical_observer=observer)
        started = time.perf_counter()
        with self.assertLogs("firewall.data_plane", level="INFO"):
            flow = self.flow()
            await gateway.request(flow)
        returned_after = time.perf_counter() - started
        # The decision is out while the observation is still pending (never awaited).
        self.assertEqual(flow.response.status_code, 403)
        self.assertTrue(gateway._shadow_tasks, "the observation should still be running")
        self.assertLess(returned_after, 1.0)
        observer.release.set()
        await self.drain(gateway)

    async def test_classifier_timing_field_excludes_observer_time(self):
        """`(classifier N ms)` keeps its definition (render + /classify). A slow observation, which
        runs after the verdict in a background task, must not appear in it."""
        class SlowObserver(StubObserver):
            async def observe(self, req):
                self.calls += 1
                await asyncio.sleep(0.3)
                return obs(obs_mod.OK, outcome="ACCEPT", size="UNCHECKED")

        observer = SlowObserver()
        gateway = data_plane.FirewallGateway(
            URL, 1.0, transport=classifier(json_body=OK_ALLOW), canonical_observer=observer)
        started = time.perf_counter()
        with self.assertLogs("firewall.data_plane", level="INFO") as logs:
            await gateway.request(self.flow())
        returned_after = time.perf_counter() - started
        self.assertLess(returned_after, 0.2, "request waited on the observation")
        decision = next(m for m in (r.getMessage() for r in logs.records) if "(classifier " in m)
        classifier_ms = float(re.search(r"\(classifier ([\d.]+) ms\)", decision).group(1))
        self.assertLess(classifier_ms, 100)   # the 300 ms observation is not inside it
        await self.drain(gateway)              # let the background observation finish

    async def test_a_scheduling_failure_cannot_block_the_request(self):
        observer = StubObserver()
        with patch.object(data_plane.asyncio, "get_running_loop",
                          side_effect=RuntimeError("no loop")), \
                self.assertLogs("firewall.data_plane", level="INFO") as logs:
            _, flow = await self.run_flow(classifier(json_body=OK_ALLOW), observer)
        self.assertIsNone(flow.response)
        output = "\n".join(logs.output)
        self.assertIn("CANONICAL OBS not started: RuntimeError", output)
        self.assertNotIn("fail-closed", output)
        self.assertEqual(observer.calls, 0)

    async def test_combined_with_the_other_shadow_observers_on(self):
        """Feature extraction + Fast Path + canonical observer all on: the client outcome and the
        bytes V4 received still equal a gateway with everything off."""
        policy = os.path.join(REPO_ROOT, "tests", "fixtures", "fast_path_policy_example.json")
        for v4_name, answer in CLASSIFIER_BEHAVIOURS.items():
            with self.subTest(v4=v4_name):
                seen = []
                with self.assertLogs("firewall.data_plane", level="INFO"):
                    _, flow = await self.run_flow(recording_classifier(seen, answer))
                baseline = self.outcome(flow, seen)
                seen = []
                gateway = data_plane.FirewallGateway(
                    URL, 1.0, transport=recording_classifier(seen, answer),
                    shadow_features=True, shadow_fast_path=True, fast_path_policy_file=policy,
                    canonical_observer=StubObserver())
                with self.assertLogs("firewall.data_plane", level="INFO"):
                    flow = self.flow()
                    await gateway.request(flow)
                    await self.drain(gateway)
                self.assertEqual(self.outcome(flow, seen), baseline)

    def test_unloading_the_addon_still_installs_the_503_block_and_closes_the_observer(self):
        observer = StubObserver()
        blocker = blocklist.BlockList()
        gateway = data_plane.FirewallGateway(URL, 1.0, canonical_observer=observer)
        with taddons.context(blocker, gateway) as tctx:
            with self.assertLogs("firewall.data_plane", level="ERROR"):
                tctx.master.addons.remove(gateway)   # what a failed script reload does
            self.assertEqual(tctx.options.block_list, ["/~all/503"])
            self.assertTrue(observer.closed, "the observer worker was not shut down")
            flow = tflow.tflow(req=make_request())
            blocker.request(flow)
            self.assertEqual(flow.response.status_code, 503)


# ── 3. Privacy: the canonical log line never carries request content ───────────
class TestPrivacy(GatewayObserverTestCase):
    MARKERS = ("SENTINEL_Q", "SENTINEL_CRED", "SENTINEL_COOKIE", "SENTINEL_HOST",
               "SENTINEL_UA", "SENTINEL_BODY")

    def secret_flow(self):
        return tflow.tflow(req=make_request(
            "POST", "/a?token=SENTINEL_Q",
            headers=[("Host", "SENTINEL_HOST"), ("User-Agent", "SENTINEL_UA"),
                     ("Authorization", "Bearer SENTINEL_CRED"), ("Cookie", "s=SENTINEL_COOKIE"),
                     ("Content-Type", "application/x-www-form-urlencoded")],
            content=b"password=SENTINEL_BODY"))

    def assert_no_leak(self, text):
        for marker in self.MARKERS:
            self.assertNotIn(marker, text, f"marker {marker} leaked")
            digest = hashlib.sha256(marker.encode()).hexdigest()
            self.assertNotIn(digest, text, f"sha256 of {marker} leaked")

    async def start_real(self, observer):
        observer.prewarm()
        if observer._start_task is not None:
            await observer._start_task
        return observer

    async def test_ok_observation_through_the_real_worker_leaks_nothing(self):
        """The real ProcessCanonicalObserver + worker: proves the process path, and that the OK line
        carries only closed codes/numbers — no target, query, header value or body."""
        observer = obs_mod.build_process_observer(
            sys.executable, 5.0, 10.0, 0.0, 3, max_decoded_body=obs_mod.LAB_MAX_DECODED_BODY)
        self.addAsyncCleanup(observer.aclose)
        await self.start_real(observer)
        self.assertIsNotNone(observer.worker_pid, "the worker did not start")
        gateway = data_plane.FirewallGateway(
            URL, 1.0, transport=classifier(json_body=OK_ALLOW), canonical_observer=observer)
        with self.assertLogs(CANONICAL_LOGGER, level="INFO") as logs:
            await gateway.request(self.secret_flow())
            await self.drain(gateway)
        text = "\n".join(logs.output)
        self.assert_no_leak(text)
        line = next(m for m in (r.getMessage() for r in logs.records) if "CANONICAL OBS" in m)
        self.assertRegex(line, r"^\[[0-9a-f]{8}\] CANONICAL OBS OK ")   # tag + status
        self.assertIn("outcome=ACCEPT", line)                           # a closed enum
        self.assertIn("target_form=origin", line)

    async def test_a_failing_observation_logs_a_type_not_a_message_and_no_content(self):
        """The failure path (observer raises): the gateway logs `detail=internal:<ExcType>` and never
        the exception message, which could quote the request."""
        def raise_with_secret(req):
            raise RuntimeError("boom Authorization=Bearer SENTINEL_CRED body=SENTINEL_BODY")

        observer = StubObserver(raise_with_secret)
        gateway = data_plane.FirewallGateway(
            URL, 1.0, transport=classifier(json_body=OK_ALLOW), canonical_observer=observer)
        with self.assertLogs(CANONICAL_LOGGER, level="INFO") as logs:
            await gateway.request(self.secret_flow())
            await self.drain(gateway)
        text = "\n".join(logs.output)
        self.assert_no_leak(text)
        self.assertNotIn("boom", text)                     # the exception message is not logged
        self.assertIn("CANONICAL OBS failed detail=internal:RuntimeError", text)

    async def test_status_lines_carry_only_a_closed_detail_token(self):
        """A worker-supplied DROP/TIMEOUT detail is a closed token; no request-derived value appears,
        even when the request is full of markers."""
        for obs_name in ("DROP", "TIMEOUT", "UNAVAILABLE", "OUT_OF_SCOPE"):
            with self.subTest(observer=obs_name):
                observer = self.make_observer(obs_name)
                gateway = data_plane.FirewallGateway(
                    URL, 1.0, transport=classifier(json_body=OK_ALLOW), canonical_observer=observer)
                with self.assertLogs(CANONICAL_LOGGER, level="INFO") as logs:
                    await gateway.request(self.secret_flow())
                    await self.drain(gateway)
                text = "\n".join(logs.output)
                self.assert_no_leak(text)
                self.assertIn(f"CANONICAL OBS {obs_name}", text)


# ── 4. Fast Path stays ineligible with the observer on ─────────────────────────
class TestFastPathUnchanged(GatewayObserverTestCase):
    def test_gateway_evidence_canonical_is_still_none(self):
        """The observer result is NOT fed back into GatewayEvidence: canonical stays None, so the
        Fast Path prerequisite is still unavailable (no observer->Fast Path link; D69)."""
        evidence = data_plane.GatewayEvidence()
        self.assertIsNone(evidence.canonical(make_request()))

    async def test_fast_path_still_logs_continue_canonical_unavailable_with_observer_on(self):
        policy = os.path.join(REPO_ROOT, "tests", "fixtures", "fast_path_policy_example.json")
        gateway = data_plane.FirewallGateway(
            URL, 1.0, transport=classifier(json_body=OK_ALLOW),
            shadow_fast_path=True, fast_path_policy_file=policy, canonical_observer=StubObserver())
        with self.assertLogs("firewall.data_plane.fastpath", level="INFO") as logs:
            await gateway.request(self.flow())
            await self.drain(gateway)
        text = "\n".join(logs.output)
        self.assertIn("FAST PATH (shadow) CONTINUE", text)
        self.assertIn("CANONICAL_UNAVAILABLE", text)
        self.assertNotIn("FAST_ALLOW", text)


# ── 4b. Repaired lifecycle (repairs 1/3) through the gateway, with a REAL worker ──
class TestRepairedLifecycleThroughGateway(GatewayObserverTestCase):
    """Owner-review repairs 1 and 3 exercised at the gateway level with a REAL worker process (not a
    status-returning double): a real observation runs through the gateway, then the shutdown path
    (`close()` = what the sync mitmproxy `done` hook calls, then `aclose()`) reaps the worker exactly
    once with no orphan, while V4's decision/forwarding is untouched."""

    async def _start_real(self, observer):
        observer.prewarm()
        if observer._start_task is not None:
            await observer._start_task
        return observer

    async def test_real_observation_then_close_aclose_reaps_without_orphan_or_touching_v4(self):
        observer = obs_mod.build_process_observer(
            sys.executable, 5.0, 10.0, 0.0, 3, max_decoded_body=obs_mod.LAB_MAX_DECODED_BODY)
        reaped = False
        try:
            await self._start_real(observer)
            self.assertIsNotNone(observer.worker_pid, "the worker did not start")
            pid = observer.worker_pid
            gateway = data_plane.FirewallGateway(
                URL, 1.0, transport=classifier(json_body=OK_ALLOW), canonical_observer=observer)
            flow = self.flow()
            with self.assertLogs(CANONICAL_LOGGER, level="INFO") as logs:
                await gateway.request(flow)
                await self.drain(gateway)
            # V4 ALLOW preserved: the proxy sets no response, so the request is forwarded.
            self.assertIsNone(flow.response)
            self.assertTrue(any("CANONICAL OBS" in line for line in logs.output))
            # Repair 3: close() (the sync done-hook path) SIGKILLs but RETAINS the handle so a later
            # aclose() can reap exactly once; it is not nulled before reaping.
            observer.close()
            self.assertEqual(observer.worker_pid, pid, "close() must not drop the handle before reaping")
            await observer.aclose()
            reaped = True
            self.assertIsNone(observer.worker_pid, "aclose() should have reaped and cleared the worker")
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)   # the child is gone (reaped), not a lingering zombie
            # Idempotent: a second close()/aclose() must not raise.
            observer.close()
            await observer.aclose()
        finally:
            if not reaped:
                await observer.aclose()


# ── 5. Default-off config (read-only) ──────────────────────────────────────────
class TestDefaultOff(unittest.TestCase):
    def test_repository_config_leaves_the_canonical_observer_off(self):
        # The shadow_canonical_observer block is commented out in config.yaml, so loading returns None
        # and the gateway builds no observer: default-off, as approved (D69).
        self.assertIsNone(data_plane.load_canonical_observer())
        self.assertIsNone(data_plane.build_canonical_observer(None))


if __name__ == "__main__":
    unittest.main()
