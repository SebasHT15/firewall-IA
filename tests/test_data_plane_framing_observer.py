"""Gateway tests for the HTTP/1.1 framing OBSERVATION slice wired into the data plane
(data_plane.py + framing_evidence.py riding on canonical_observer.py), issue #68 / D70 (APPROVED).

TRACK C — PRESERVATION / PRIVACY REVIEW. This suite verifies the acceptance gates of the bounded,
observe-only framing slice AGAINST THE INTEGRATED GATEWAY: V4 via /classify stays the ONLY enforced
authority, framing observation never changes the client response / the bytes V4 receives / the
/classify schema, it runs only after the verdict in a background task the request never awaits, it
never sets fast_path.FRAMING_VERIFIED or touches GatewayEvidence (canonical stays None, framing stays
UNAVAILABLE), and it emits only a `FRAMING OBS` line of closed codes, approved identifiers and
numbers — no request content, no destination/port.

It also pins the three defects that Track A fixed and the coordinator re-wired in the correction pass:
  * Defect A — version exclusion: an in-scope HTTP/1.0 request that canonicalizes OK+ACCEPT must NOT
    reach PROFILE_MATCHED; it is UNATTESTABLE / HTTP_VERSION_NOT_11. The original received version is
    carried on the immutable snapshot (`Capture.http_version`), not inferred from normalized text.
  * Defect B — mode / drift: `is_tested_profile()` uses a port/destination-free PUBLIC class marker
    (so dynamic ports share the tested class) but rejects https/http3/DNS-lookalike destinations; the
    INTERNAL `mode_fingerprint` (never logged) makes a transport/destination/port change bump the
    monotonic generation (A->B->A = two bumps), so capture-vs-reply drift is detectable.
  * Defect C — reservation: the old boolean `_busy` is replaced by a single-use token reservation; a
    release is token-scoped and idempotent, `run_captured` is single-use (a consumed capture returns
    `EXCEPTION capture_consumed`), and a completion task cancelled before it runs frees the slot via
    the gateway's done-callback backstop.

Complementary to:
  * tests/test_canonical_observer.py             — the observer in isolation (incl. the
                                                   `ipc_id_mismatch -> EXCEPTION` cross/late-reply
                                                   guard CITED here for no-misattribution).
  * tests/test_data_plane_canonical_observer.py  — the canonical observer through the gateway.
  * Track A's framing_evidence unit tests        — the pure evaluator / profile sampling / generation.
Here the FRAMING slice is driven THROUGH `FirewallGateway` with an httpx.MockTransport classifier.

Needs the data plane environment (mitmproxy):
    .venv-dataplane/bin/python -m unittest tests.test_data_plane_framing_observer -v

Run this module ON ITS OWN. Running several mitmproxy-based async test modules in one process can
emit a pre-existing, unrelated "Event loop is closed" teardown artifact from mitmproxy's logging; it
is NOT attributable to this slice. Under `python3.12 -m unittest discover -s tests` this module is
reported as skipped. Synthetic requests only; no dataset is ever read.
"""

import asyncio
import contextlib
import hashlib
import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "data_plane"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import httpx
    from mitmproxy import http
    from mitmproxy.test import tflow, tutils
except ImportError as exc:
    raise unittest.SkipTest(f"needs the data plane environment (.venv-dataplane): {exc}")

import data_plane
import fast_path
import framing_evidence as fe
import canonical_observer as obs_mod
import canonical_adapter as adapter
# Classifier doubles + V4 behaviour table. Importing the module never selects its protected
# dataset test (TestRenderRequest.test_reproduces_the_v4_dataset_representation).
from test_data_plane import (CLASSIFIER_BEHAVIOURS, OK_ALLOW, OK_BLOCK, URL,  # noqa: E402
                             classifier, make_request, recording_classifier)

FRAMING_LOGGER = "firewall.data_plane.framing"
CANONICAL_LOGGER = "firewall.data_plane.canonical"
DATA_PLANE_LOGGER = "firewall.data_plane"


def obs(status, **kw):
    return obs_mod.CanonicalObservation(status, **kw)


def ok_accept(req):
    return obs(obs_mod.OK, outcome="ACCEPT", size="UNCHECKED", target_form=adapter.FORM_ORIGIN,
               elapsed_ms=1.0)


def ok_reject_r1(req):
    return obs(obs_mod.OK, outcome="REJECT", reject="R1", reason="bare_lf",
               target_form=adapter.FORM_ORIGIN, elapsed_ms=1.0)


def raising_behaviour_with_secret(req):
    raise RuntimeError("boom Authorization=Bearer SENTINEL_CRED body=SENTINEL_BODY")


# ── the tested lab runtime, as a fake mitmproxy options object ─────────────────
def fake_options(**overrides):
    """A duck-typed mitmproxy options object whose EFFECTIVE values are the documented tested lab
    profile, overridable per field. `sample_profile` reads it via getattr; nothing here is a request
    byte. `mode` is a reverse proxy to an http loopback literal (the tested CLASS; dynamic port)."""
    base = dict(validate_inbound_headers=True, http2=False, stream_large_bodies=None,
                body_size_limit=None, mode=["reverse:http://127.0.0.1:0"],
                connection_strategy="lazy")
    base.update(overrides)
    return SimpleNamespace(**base)


@contextlib.contextmanager
def tested_runtime(**overrides):
    """Patch the gateway's `ctx.options` and the sampled mitmproxy version so a request driven
    through the gateway samples a controlled runtime profile (the tested one by default)."""
    with patch.object(data_plane, "ctx", SimpleNamespace(options=fake_options(**overrides))), \
            patch.object(data_plane, "MITMPROXY_VERSION", "12.2.3"):
        yield


# ── framing-aware observer doubles (carry http_version, consumed, reservation) ──
class _FramingCapture:
    """A stand-in for canonical_observer.Capture that carries everything the gateway reads back on
    the framing path, including the ORIGINAL received `http_version` and the new single-use fields
    (`consumed`, `reservation`). The doubles never model a real worker reservation."""
    __slots__ = ("is_early", "form", "http_version", "profile", "profile_generation", "req",
                 "consumed", "reservation", "observation")

    def __init__(self, req, profile, profile_generation, form, http_version):
        self.is_early = True
        self.form = form
        self.http_version = http_version
        self.profile = profile
        self.profile_generation = profile_generation
        self.req = req
        self.consumed = False
        self.reservation = None
        self.observation = None


class FramingStubObserver:
    """A canonical observer following the gateway protocol (capture / run_captured /
    release_captured / observe / startup_summary / prewarm / close) that answers deterministically
    without a worker. `capture()` binds an in-scope form and the request's ORIGINAL http_version, so
    the gateway's framing evaluation sees a scoped, version-correct request."""

    def __init__(self, behaviour=None, form=adapter.FORM_ORIGIN):
        import logging
        self._logging = logging
        self.behaviour = behaviour or ok_accept
        self.form = form
        self.calls = 0
        self.closed = False
        self.prewarmed = False

    @staticmethod
    def _version(req):
        try:
            v = req.http_version
            return bytes(v).decode("ascii", "replace") if isinstance(v, (bytes, bytearray)) else v
        except Exception:  # noqa: BLE001
            return None

    def capture(self, req, *, profile=None, profile_generation=None):
        return _FramingCapture(req, profile, profile_generation, self.form, self._version(req))

    async def run_captured(self, capture):
        self.calls += 1
        return self.behaviour(capture.req)

    def release_captured(self, capture):
        pass

    async def observe(self, req):
        return await self.run_captured(self.capture(req))

    def startup_summary(self):
        return self._logging.INFO, "canonical observer: framing stub (test)"

    def prewarm(self):
        self.prewarmed = True

    def close(self):
        self.closed = True


class HangingFramingObserver(FramingStubObserver):
    """run_captured() blocks on an event so the test can change the relevant-profile generation
    mid-observation (between capture and reply), exercising GENERATION_DRIFT end to end."""

    def __init__(self):
        super().__init__(ok_accept)
        self.release = asyncio.Event()
        self.entered = asyncio.Event()

    async def run_captured(self, capture):
        self.calls += 1
        self.entered.set()
        await self.release.wait()
        return ok_accept(capture.req)


async def start_real_observer(testcase):
    """A started real ProcessCanonicalObserver (worker up), auto-closed at test teardown."""
    observer = obs_mod.build_process_observer(
        sys.executable, 5.0, 10.0, 0.0, 3, max_decoded_body=obs_mod.LAB_MAX_DECODED_BODY)
    testcase.addAsyncCleanup(observer.aclose)
    observer.prewarm()
    if observer._start_task is not None:
        await observer._start_task
    testcase.assertIsNotNone(observer.worker_pid, "the worker did not start")
    return observer


class FramingGatewayTestCase(unittest.IsolatedAsyncioTestCase):
    def flow(self, version=b"HTTP/1.1"):
        return tflow.tflow(req=make_request(
            "POST", "/search?q=laptop&q=tv",
            headers=[("Host", "shop.example"), ("User-Agent", "curl/8.18.0"),
                     ("Content-Type", "application/x-www-form-urlencoded")],
            content=b"page=2&sort=price"))

    def simple_flow(self, version=b"HTTP/1.1", body=b""):
        return tflow.tflow(req=tutils.treq(
            method=b"GET", path=b"/a", http_version=version,
            headers=http.Headers([(b"Host", b"h.example")]), content=body))

    async def run_flow(self, transport, observer=None, framing_observer=False, flow=None, **kw):
        gateway = data_plane.FirewallGateway(URL, 1.0, transport=transport,
                                             canonical_observer=observer,
                                             framing_observer=framing_observer, **kw)
        flow = flow or self.flow()
        await gateway.request(flow)
        return gateway, flow

    @staticmethod
    async def drain(gateway):
        if gateway._shadow_tasks:
            await asyncio.gather(*list(gateway._shadow_tasks), return_exceptions=True)

    @staticmethod
    def outcome(flow, seen):
        """What the client gets and the exact bytes V4 was sent."""
        response = None if flow.response is None else (flow.response.status_code, flow.response.text)
        return response, [r.content for r in seen]


# ── GATE 1. Default-off ────────────────────────────────────────────────────────
class TestDefaultOff(FramingGatewayTestCase):
    def test_repository_config_leaves_framing_observation_off(self):
        self.assertIs(data_plane.load_shadow_framing_observer(), False)

    async def test_no_framing_line_and_byte_identical_behaviour_when_off(self):
        for v4_name, answer in CLASSIFIER_BEHAVIOURS.items():
            with self.subTest(v4=v4_name):
                seen_base = []
                with self.assertLogs(DATA_PLANE_LOGGER, level="INFO"):
                    _, base_flow = await self.run_flow(recording_classifier(seen_base, answer))
                baseline = self.outcome(base_flow, seen_base)

                seen = []
                framing_records = []
                with _collect(FRAMING_LOGGER, framing_records), \
                        self.assertLogs(DATA_PLANE_LOGGER, level="INFO"):
                    gateway, flow = await self.run_flow(recording_classifier(seen, answer),
                                                        framing_observer=False)
                    await self.drain(gateway)
                self.assertEqual(self.outcome(flow, seen), baseline)
                self.assertEqual(framing_records, [], "a FRAMING OBS line was logged while off")

    async def test_configure_is_a_noop_while_off(self):
        gateway = data_plane.FirewallGateway(URL, 1.0, framing_observer=False)
        gen0 = gateway._relevant_profile_generation.generation
        with tested_runtime():
            gateway.configure(object())
            gateway.configure(object())
        self.assertEqual(gateway._relevant_profile_generation.generation, gen0)


# ── GATE 2. On/off equivalence ─────────────────────────────────────────────────
class TestOnOffEquivalence(FramingGatewayTestCase):
    async def test_client_outcome_and_v4_input_identical_framing_off_vs_on(self):
        behaviours = {
            "OK ACCEPT (PROFILE_MATCHED)": ok_accept,
            "OK REJECT R1": ok_reject_r1,
            "TIMEOUT": lambda r: obs(obs_mod.TIMEOUT, detail="worker_killed"),
            "UNAVAILABLE": lambda r: obs(obs_mod.UNAVAILABLE, detail="worker_starting"),
            "observer raises": "raises",
        }
        for v4_name, answer in CLASSIFIER_BEHAVIOURS.items():
            seen_base = []
            with self.assertLogs(DATA_PLANE_LOGGER, level="INFO"):
                _, base_flow = await self.run_flow(recording_classifier(seen_base, answer))
            baseline = self.outcome(base_flow, seen_base)
            for obs_name, behaviour in behaviours.items():
                with self.subTest(v4=v4_name, observer=obs_name):
                    observer = FramingStubObserver(
                        raising_behaviour_with_secret if behaviour == "raises" else behaviour)
                    seen = []
                    with tested_runtime(), self.assertLogs(DATA_PLANE_LOGGER, level="INFO"):
                        gateway, flow = await self.run_flow(
                            recording_classifier(seen, answer), observer, framing_observer=True)
                        await self.drain(gateway)
                    self.assertEqual(self.outcome(flow, seen), baseline)

    async def test_classify_bytes_and_schema_unchanged_with_framing_on(self):
        import json
        seen_off = []
        with self.assertLogs(DATA_PLANE_LOGGER, level="INFO"):
            await self.run_flow(recording_classifier(seen_off, CLASSIFIER_BEHAVIOURS["ALLOW"]))
        seen_on = []
        with tested_runtime(), self.assertLogs(DATA_PLANE_LOGGER, level="INFO"):
            gateway, _ = await self.run_flow(
                recording_classifier(seen_on, CLASSIFIER_BEHAVIOURS["ALLOW"]),
                FramingStubObserver(ok_accept), framing_observer=True)
            await self.drain(gateway)
        self.assertEqual(len(seen_off), 1)
        self.assertEqual(len(seen_on), 1)
        self.assertEqual(seen_on[0].method, "POST")
        self.assertEqual(str(seen_on[0].url), URL)
        self.assertEqual(seen_on[0].content, seen_off[0].content)      # byte-identical
        self.assertEqual(set(json.loads(seen_on[0].content)), {"request"})   # schema unchanged

    async def test_exactly_one_classifier_call_when_the_classification_path_is_reached(self):
        for v4_name in ("ALLOW", "BLOCK", "invalid"):
            with self.subTest(v4=v4_name):
                seen = []
                with tested_runtime(), self.assertLogs(DATA_PLANE_LOGGER, level="INFO"):
                    gateway, _ = await self.run_flow(
                        recording_classifier(seen, CLASSIFIER_BEHAVIOURS[v4_name]),
                        FramingStubObserver(ok_accept), framing_observer=True)
                    await self.drain(gateway)
                self.assertEqual(len(seen), 1)

    async def test_zero_classifier_calls_and_no_framing_line_for_a_preanswered_flow(self):
        seen = []
        observer = FramingStubObserver(ok_accept)
        flow = tflow.tflow(req=make_request(), resp=True)
        original = flow.response
        records = []
        with _collect(FRAMING_LOGGER, records), tested_runtime():
            gateway, flow = await self.run_flow(
                recording_classifier(seen, CLASSIFIER_BEHAVIOURS["ALLOW"]), observer,
                framing_observer=True, flow=flow)
            await self.drain(gateway)
        self.assertEqual(seen, [])
        self.assertEqual(observer.calls, 0)
        self.assertEqual(records, [])
        self.assertIs(flow.response, original)

    async def test_a_framing_or_observer_failure_never_changes_the_response(self):
        # (a) observer raises (canonical fails; framing not reached).
        seen = []
        with tested_runtime(), self.assertLogs(DATA_PLANE_LOGGER, level="INFO"):
            gateway, flow = await self.run_flow(
                recording_classifier(seen, CLASSIFIER_BEHAVIOURS["ALLOW"]),
                FramingStubObserver(raising_behaviour_with_secret), framing_observer=True)
            await self.drain(gateway)
        self.assertIsNone(flow.response)
        self.assertEqual(len(seen), 1)

        # (b) profile sampling raises -> the gateway still emits an explicit profile and a line; the
        #     response is untouched (C1 resolution: never a silent skip, never a changed response).
        seen = []
        with patch.object(data_plane.framing_evidence, "sample_profile",
                          side_effect=RuntimeError("sample boom")), \
                tested_runtime(), self.assertLogs(FRAMING_LOGGER, level="INFO") as fr:
            gateway, flow = await self.run_flow(
                recording_classifier(seen, CLASSIFIER_BEHAVIOURS["BLOCK"]),
                FramingStubObserver(ok_accept), framing_observer=True)
            await self.drain(gateway)
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(len(seen), 1)
        self.assertIn("FRAMING OBS", "\n".join(fr.output))   # an explicit line, not a silent skip

        # (c) framing evaluate raises -> logged + dropped on the FRAMING line, response untouched.
        seen = []
        with tested_runtime(), \
                patch.object(data_plane.framing_evidence, "evaluate",
                             side_effect=RuntimeError("eval boom token=SENTINEL")), \
                self.assertLogs(FRAMING_LOGGER, level="INFO") as logs:
            gateway, flow = await self.run_flow(
                recording_classifier(seen, CLASSIFIER_BEHAVIOURS["ALLOW"]),
                FramingStubObserver(ok_accept), framing_observer=True)
            await self.drain(gateway)
        self.assertIsNone(flow.response)
        text = "\n".join(logs.output)
        self.assertIn("FRAMING OBS failed detail=internal:RuntimeError", text)
        self.assertNotIn("SENTINEL", text)
        self.assertNotIn("eval boom", text)


# ── GATE 3. GatewayEvidence unchanged / Fast Path stays ineligible ─────────────
class TestGatewayEvidenceUnchanged(FramingGatewayTestCase):
    def test_canonical_none_and_framing_unavailable_regardless_of_framing_observation(self):
        evidence = data_plane.GatewayEvidence()
        req = make_request()
        self.assertIsNone(evidence.canonical(req))
        framing = evidence.framing(req)
        self.assertEqual(framing.status, fast_path.FRAMING_UNAVAILABLE)
        self.assertNotEqual(framing.status, fast_path.FRAMING_VERIFIED)

    async def test_fast_path_still_continue_canonical_unavailable_with_framing_on(self):
        policy = os.path.join(REPO_ROOT, "tests", "fixtures", "fast_path_policy_example.json")
        gateway = data_plane.FirewallGateway(
            URL, 1.0, transport=classifier(json_body=OK_ALLOW),
            shadow_fast_path=True, fast_path_policy_file=policy,
            canonical_observer=FramingStubObserver(ok_accept), framing_observer=True)
        with tested_runtime(), self.assertLogs("firewall.data_plane.fastpath", level="INFO") as fp, \
                self.assertLogs(FRAMING_LOGGER, level="INFO") as fr:
            await gateway.request(self.flow())
            await self.drain(gateway)
        fp_text = "\n".join(fp.output)
        self.assertIn("FAST PATH (shadow) CONTINUE", fp_text)
        self.assertIn("CANONICAL_UNAVAILABLE", fp_text)
        self.assertNotIn("FAST_ALLOW", fp_text)
        self.assertNotIn("VERIFIED", fp_text)
        self.assertIn("FRAMING OBS PROFILE_MATCHED", "\n".join(fr.output))  # not vacuous


# ── GATE 4. Privacy: the FRAMING OBS / CANONICAL OBS lines never carry content ──
class TestPrivacy(FramingGatewayTestCase):
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
            self.assertNotIn(hashlib.sha256(marker.encode()).hexdigest(), text,
                             f"sha256 of {marker} leaked")

    async def test_framing_and_canonical_lines_carry_only_closed_codes(self):
        for name, behaviour in (("PROFILE_MATCHED", ok_accept), ("CANONICAL_REJECT", ok_reject_r1)):
            with self.subTest(outcome=name):
                observer = FramingStubObserver(behaviour)
                gateway = data_plane.FirewallGateway(
                    URL, 1.0, transport=classifier(json_body=OK_ALLOW),
                    canonical_observer=observer, framing_observer=True)
                with tested_runtime(), self.assertLogs(FRAMING_LOGGER, level="INFO") as logs:
                    await gateway.request(self.secret_flow())
                    await self.drain(gateway)
                text = "\n".join(logs.output)
                self.assert_no_leak(text)
                line = next(m for m in (r.getMessage() for r in logs.records) if "FRAMING OBS" in m)
                self.assertRegex(line, r"^\[[0-9a-f]{8}\] FRAMING OBS ")

    async def test_framing_evaluate_failure_logs_type_not_message_and_no_content(self):
        with tested_runtime(), \
                patch.object(data_plane.framing_evidence, "evaluate",
                             side_effect=RuntimeError("boom Cookie=s=SENTINEL_COOKIE")), \
                self.assertLogs(FRAMING_LOGGER, level="INFO") as logs:
            gateway = data_plane.FirewallGateway(
                URL, 1.0, transport=classifier(json_body=OK_ALLOW),
                canonical_observer=FramingStubObserver(ok_accept), framing_observer=True)
            await gateway.request(self.secret_flow())
            await self.drain(gateway)
        text = "\n".join(logs.output)
        self.assert_no_leak(text)
        self.assertNotIn("boom", text)
        self.assertIn("FRAMING OBS failed detail=internal:RuntimeError", text)

    async def test_destination_and_port_never_appear_in_the_framing_line(self):
        """Defect B privacy: the configured upstream destination/port (the internal mode fingerprint)
        is NEVER logged; the FRAMING line carries only the public, port/destination-free class."""
        observer = FramingStubObserver(ok_accept)
        gateway = data_plane.FirewallGateway(
            URL, 1.0, transport=classifier(json_body=OK_ALLOW),
            canonical_observer=observer, framing_observer=True)
        with tested_runtime(mode=["reverse:http://127.0.0.1:65432"]), \
                self.assertLogs(FRAMING_LOGGER, level="INFO") as logs:
            await gateway.request(self.flow())
            await self.drain(gateway)
        text = "\n".join(logs.output)
        self.assertIn("FRAMING OBS PROFILE_MATCHED", text)       # tested class still matches
        self.assertNotIn("65432", text)                          # the port never leaks
        self.assertNotIn("127.0.0.1", text)                      # nor the destination host

    async def test_real_worker_framing_line_leaks_nothing(self):
        observer = await start_real_observer(self)
        gateway = data_plane.FirewallGateway(
            URL, 1.0, transport=classifier(json_body=OK_ALLOW),
            canonical_observer=observer, framing_observer=True)
        with tested_runtime(), self.assertLogs(FRAMING_LOGGER, level="INFO") as logs:
            await gateway.request(self.secret_flow())
            await self.drain(gateway)
        text = "\n".join(logs.output)
        self.assert_no_leak(text)
        self.assertIn("FRAMING OBS", text)


# ── GATE 5 / Defect B. Snapshot identity, generation drift, no misattribution ──
class TestSnapshotIdentity(FramingGatewayTestCase):
    async def test_mutating_the_flow_after_capture_cannot_change_the_observation(self):
        """The one immutable snapshot is built synchronously in capture(); mutating the request after
        capture cannot change what is observed. Proven with the REAL worker: decoded_body_bytes
        reflects the body AT CAPTURE, not the later mutation."""
        observer = await start_real_observer(self)
        gateway = data_plane.FirewallGateway(
            URL, 1.0, transport=classifier(json_body=OK_ALLOW),
            canonical_observer=observer, framing_observer=True)
        flow = tflow.tflow(req=make_request(
            "POST", "/a", headers=[("Host", "h.example"), ("Content-Type", "text/plain")],
            content=b"ORIGINAL_14BYTE"))     # 15 bytes
        with tested_runtime(), self.assertLogs(CANONICAL_LOGGER, level="INFO") as logs:
            await gateway.request(flow)
            flow.request.content = b"MUTATED_BODY_FAR_LONGER_THAN_THE_ORIGINAL_SNAPSHOT"
            flow.request.path = "/totally-different-target?x=1"
            await self.drain(gateway)
        line = next(m for m in (r.getMessage() for r in logs.records) if "CANONICAL OBS" in m)
        self.assertIn("decoded_body_bytes=15", line)
        self.assertIn("target_form=origin", line)
        self.assertIsNone(flow.response)

    def test_generation_drift_between_capture_and_reply_is_unattestable(self):
        tested = _tested_profile()
        result = fe.evaluate(profile=tested, gen_at_capture=0, gen_at_reply=1,
                             canonical_obs=ok_accept(None), form=adapter.FORM_ORIGIN,
                             http_version="HTTP/1.1", canonical_available=True)
        self.assertEqual(result.status, fe.UNATTESTABLE)
        self.assertIn(fe.GENERATION_DRIFT, result.reasons)

    async def test_generation_change_mid_observation_is_drift_through_the_gateway(self):
        """Defect B end to end: the relevant-profile generation changes BETWEEN a request's capture
        and its worker reply (a transport change observed by configure() while the observation hangs);
        the framing line is UNATTESTABLE / GENERATION_DRIFT, never PROFILE_MATCHED."""
        observer = HangingFramingObserver()
        gateway = data_plane.FirewallGateway(
            URL, 1.0, transport=classifier(json_body=OK_ALLOW),
            canonical_observer=observer, framing_observer=True)
        fake_ctx = SimpleNamespace(options=fake_options())
        with patch.object(data_plane, "ctx", fake_ctx), \
                patch.object(data_plane, "MITMPROXY_VERSION", "12.2.3"), \
                self.assertLogs(FRAMING_LOGGER, level="INFO") as logs:
            gateway.configure(object())                         # establish the generation baseline (0)
            await gateway.request(self.flow())                  # capture at gen 0; completion hangs
            await observer.entered.wait()
            fake_ctx.options = fake_options(mode=["reverse:https://127.0.0.1:0"])   # transport change
            gateway.configure(object())                         # generation bumps to 1 mid-observation
            observer.release.set()
            await self.drain(gateway)
        text = "\n".join(logs.output)
        self.assertIn("FRAMING OBS UNATTESTABLE", text)
        self.assertIn("GENERATION_DRIFT", text)
        self.assertNotIn("PROFILE_MATCHED", text)

    def test_cross_or_late_worker_reply_is_rejected_at_the_observer_level(self):
        """The no-misattribution mechanism for a swapped/late worker reply is the observer's
        `id != snapshot_id -> EXCEPTION ipc_id_mismatch` guard in canonical_observer._exchange,
        exercised at the observer level in tests/test_canonical_observer.py (CITED). Here we assert
        such an EXCEPTION can never become a positive framing observation."""
        self.assertIn(obs_mod.EXCEPTION, obs_mod.STATUSES)
        exc = obs(obs_mod.EXCEPTION, detail="ipc_id_mismatch")
        result = fe.evaluate(profile=_tested_profile(), gen_at_capture=0, gen_at_reply=0,
                             canonical_obs=exc, form=adapter.FORM_ORIGIN, http_version="HTTP/1.1",
                             canonical_available=True)
        self.assertEqual(result.status, fe.UNAVAILABLE)
        self.assertNotEqual(result.status, fe.PROFILE_MATCHED)


# ── Defect B — mode class vs fingerprint, generation bumps ──────────────────────
class TestModeClassAndGeneration(FramingGatewayTestCase):
    def test_is_tested_profile_rejects_non_http_and_dns_lookalike_destinations(self):
        for mode in ("reverse:https://127.0.0.1:0", "reverse:http3://127.0.0.1:0",
                     "reverse:http://127.synthetic.invalid:0", "reverse:http://example.com:0"):
            with self.subTest(mode=mode):
                profile = fe.sample_profile(fake_options(mode=[mode]), "12.2.3")
                self.assertFalse(profile.is_tested_profile(), f"{mode} wrongly accepted as tested")
        tested = fe.sample_profile(fake_options(mode=["reverse:http://127.0.0.1:0"]), "12.2.3")
        self.assertTrue(tested.is_tested_profile())
        # The PUBLIC marker is port/destination-free (safe to log); the two share the tested class.
        other_port = fe.sample_profile(fake_options(mode=["reverse:http://127.0.0.1:65432"]), "12.2.3")
        self.assertEqual(tested.mode, other_port.mode)
        self.assertTrue(other_port.is_tested_profile())

    def test_transport_change_bumps_the_generation_a_b_a_is_two_bumps(self):
        """A transport change HTTP->HTTPS->HTTP observed through the REAL FirewallGateway.configure()
        yields generations [0, 1, 2] (not [0, 0, 0]): the internal fingerprint carries the scheme, so
        A->B->A is TWO bumps that value-equality against a single 'current' profile would miss."""
        gateway = data_plane.FirewallGateway(URL, 1.0, framing_observer=True)
        fake_ctx = SimpleNamespace(options=None)
        seq = []
        with patch.object(data_plane, "ctx", fake_ctx), \
                patch.object(data_plane, "MITMPROXY_VERSION", "12.2.3"):
            for mode in ("reverse:http://127.0.0.1:8080", "reverse:https://127.0.0.1:8080",
                         "reverse:http://127.0.0.1:8080"):
                fake_ctx.options = fake_options(mode=[mode])
                gateway.configure(object())
                seq.append(gateway._relevant_profile_generation.generation)
        self.assertEqual(seq, [0, 1, 2])

    def test_dynamic_port_change_within_the_tested_class_still_bumps_the_generation(self):
        """Even within the tested CLASS (same public marker), a port change bumps the generation,
        because the internal fingerprint carries the concrete port."""
        gateway = data_plane.FirewallGateway(URL, 1.0, framing_observer=True)
        fake_ctx = SimpleNamespace(options=None)
        seq = []
        with patch.object(data_plane, "ctx", fake_ctx), \
                patch.object(data_plane, "MITMPROXY_VERSION", "12.2.3"):
            for port in (1111, 2222):
                fake_ctx.options = fake_options(mode=[f"reverse:http://127.0.0.1:{port}"])
                gateway.configure(object())
                seq.append(gateway._relevant_profile_generation.generation)
        self.assertEqual(seq, [0, 1])


# ── Defect A — HTTP version exclusion (through the real gateway) ────────────────
class TestHttpVersionExclusion(FramingGatewayTestCase):
    async def test_http_1_1_reaches_profile_matched_http_1_0_is_unattestable(self):
        """An in-scope HTTP/1.0 request that canonicalizes OK+ACCEPT yields UNATTESTABLE /
        HTTP_VERSION_NOT_11 (NOT PROFILE_MATCHED); its HTTP/1.1 counterpart reaches PROFILE_MATCHED.
        Driven through the REAL worker so the canonical ACCEPT is genuine."""
        observer = await start_real_observer(self)
        gateway = data_plane.FirewallGateway(
            URL, 1.0, transport=classifier(json_body=OK_ALLOW),
            canonical_observer=observer, framing_observer=True)
        results = {}
        for label, version in (("1.1", b"HTTP/1.1"), ("1.0", b"HTTP/1.0")):
            with tested_runtime(), self.assertLogs(FRAMING_LOGGER, level="INFO") as logs:
                await gateway.request(self.simple_flow(version=version))
                await self.drain(gateway)
            results[label] = next(m for m in (r.getMessage() for r in logs.records)
                                  if "FRAMING OBS" in m)
        self.assertIn("FRAMING OBS PROFILE_MATCHED", results["1.1"])
        self.assertIn("FRAMING OBS UNATTESTABLE", results["1.0"])
        self.assertIn("HTTP_VERSION_NOT_11", results["1.0"])
        self.assertIn("canonical_outcome=ACCEPT", results["1.0"])   # canonical still ACCEPTed it
        self.assertNotIn("PROFILE_MATCHED", results["1.0"])

    def test_missing_or_odd_version_prevents_a_positive(self):
        tested = _tested_profile()
        for version in (None, "HTTP/1.0", "HTTP/2.0", "", "http/1.1"):
            with self.subTest(version=version):
                result = fe.evaluate(profile=tested, gen_at_capture=0, gen_at_reply=0,
                                     canonical_obs=ok_accept(None), form=adapter.FORM_ORIGIN,
                                     http_version=version, canonical_available=True)
                self.assertNotEqual(result.status, fe.PROFILE_MATCHED)
                self.assertIn(fe.HTTP_VERSION_NOT_11, result.reasons)


# ── Defect C — reservation (through the real gateway / observer) ────────────────
class TestReservation(FramingGatewayTestCase):
    async def test_pre_start_cancellation_frees_the_reservation_for_the_next_request(self):
        """A completion task cancelled BEFORE its coroutine runs never reaches run_captured's finally;
        the gateway's done-callback backstop releases the token, so the NEXT capture is admitted (not
        BUSY). Driven through the real gateway + real observer."""
        observer = await start_real_observer(self)
        gateway = data_plane.FirewallGateway(
            URL, 1.0, transport=classifier(json_body=OK_ALLOW),
            canonical_observer=observer, framing_observer=False)
        with self.assertLogs(DATA_PLANE_LOGGER, level="INFO"):
            await gateway.request(self.simple_flow())
        pending = list(gateway._shadow_tasks)
        self.assertTrue(pending, "the completion task should be pending (not yet run)")
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)   # cancellation + done-callback run
        cap = observer.capture(self.simple_flow().request)
        self.assertFalse(cap.is_early, "the reservation was not freed: next capture is not admitted")
        observer.release_captured(cap)

    async def test_stale_release_cannot_free_a_newer_reservation(self):
        observer = await start_real_observer(self)
        cap1 = observer.capture(self.simple_flow().request)
        self.assertFalse(cap1.is_early)
        observer.release_captured(cap1)                 # frees token1, marks cap1 consumed
        cap2 = observer.capture(self.simple_flow().request)
        self.assertFalse(cap2.is_early)                 # admitted: token2
        observer.release_captured(cap1)                 # stale repeat -> no-op
        cap3 = observer.capture(self.simple_flow().request)
        self.assertTrue(cap3.is_early)                  # BUSY: token2 still held
        self.assertEqual(cap3.observation.status, obs_mod.BUSY)
        observer.release_captured(cap2)

    async def test_repeated_run_captured_returns_capture_consumed(self):
        observer = await start_real_observer(self)
        cap = observer.capture(self.simple_flow().request)
        self.assertFalse(cap.is_early)
        first = await observer.run_captured(cap)
        second = await observer.run_captured(cap)
        self.assertEqual(first.status, obs_mod.OK)
        self.assertEqual(second.status, obs_mod.EXCEPTION)
        self.assertEqual(second.detail, "capture_consumed")

    async def test_scheduler_failure_releases_the_reservation_and_leaves_the_request_untouched(self):
        """A failure to schedule the completion task releases the reservation (so the observer is not
        wedged at BUSY) and never changes the response; the coroutine is closed (no leak)."""
        observer = await start_real_observer(self)
        gateway = data_plane.FirewallGateway(
            URL, 1.0, transport=classifier(json_body=OK_ALLOW),
            canonical_observer=observer, framing_observer=False)
        with patch.object(data_plane.asyncio, "get_running_loop",
                          side_effect=RuntimeError("no loop")), \
                self.assertLogs(CANONICAL_LOGGER, level="INFO") as logs:
            await gateway.request(self.simple_flow())
        output = "\n".join(logs.output)
        self.assertIn("CANONICAL OBS not started: RuntimeError", output)
        self.assertNotIn("fail-closed", output)
        # The reservation was released: a fresh capture is admitted, not BUSY.
        cap = observer.capture(self.simple_flow().request)
        self.assertFalse(cap.is_early, "scheduler failure left the reservation wedged at BUSY")
        observer.release_captured(cap)


# ── GATE 6. No unbounded state ─────────────────────────────────────────────────
class TestNoUnboundedState(FramingGatewayTestCase):
    async def test_shadow_tasks_drains_to_empty_and_nothing_accumulates_per_request(self):
        gateway = data_plane.FirewallGateway(
            URL, 1.0, transport=classifier(json_body=OK_ALLOW),
            canonical_observer=FramingStubObserver(ok_accept), framing_observer=True)
        attrs_before = set(vars(gateway))
        with tested_runtime(), self.assertLogs(DATA_PLANE_LOGGER, level="INFO"):
            for _ in range(25):
                await gateway.request(self.flow())
            await self.drain(gateway)
        self.assertEqual(len(gateway._shadow_tasks), 0, "completion tasks were retained")
        self.assertEqual(set(vars(gateway)), attrs_before, "a per-request attribute was added")
        self.assertIsInstance(gateway._relevant_profile_generation.generation, int)

    async def test_no_snapshot_retained_after_completion(self):
        observed = {}

        class RecordingObserver(FramingStubObserver):
            def capture(self, req, *, profile=None, profile_generation=None):
                cap = super().capture(req, profile=profile, profile_generation=profile_generation)
                observed["cap_id"] = id(cap)
                return cap

        gateway = data_plane.FirewallGateway(
            URL, 1.0, transport=classifier(json_body=OK_ALLOW),
            canonical_observer=RecordingObserver(ok_accept), framing_observer=True)
        with tested_runtime(), self.assertLogs(DATA_PLANE_LOGGER, level="INFO"):
            await gateway.request(self.flow())
            await self.drain(gateway)
        self.assertFalse(any(id(v) == observed["cap_id"] for v in vars(gateway).values()))
        self.assertEqual(len(gateway._shadow_tasks), 0)


# ── GATE 7. Known V4 UnicodeEncodeError (valid obs-text) PRESERVED + DISCLOSED ──
class TestKnownUnicodeDefectPreserved(FramingGatewayTestCase):
    def obs_text_flow(self):
        return tflow.tflow(req=tutils.treq(
            method=b"GET", path=b"/a", http_version=b"HTTP/1.1",
            headers=http.Headers([(b"Host", b"h.example"), (b"X-Bin", b"\xff\xfe")]),
            content=b""))

    async def test_valid_obs_text_yields_503_and_zero_classifier_calls_with_framing_on(self):
        """PRESERVED + DISCLOSED, NOT fixed here (D1). The UnicodeEncodeError is raised inside
        httpx.build_request BEFORE the transport is contacted, so the classifier is never called; it
        propagates to request()'s broad guard -> fail-closed 503. Framing observation (on) neither
        masks, changes, nor repairs it, and is never reached."""
        seen = []
        with tested_runtime(), self.assertLogs(DATA_PLANE_LOGGER, level="ERROR") as logs:
            gateway, flow = await self.run_flow(
                recording_classifier(seen, CLASSIFIER_BEHAVIOURS["ALLOW"]),
                FramingStubObserver(ok_accept), framing_observer=True, flow=self.obs_text_flow())
            await self.drain(gateway)
        self.assertEqual(len(seen), 0, "the classifier was contacted despite the encode error")
        self.assertEqual(flow.response.status_code, 503)
        self.assertEqual(flow.response.text, data_plane.UNAVAILABLE_BODY)
        self.assertIn("BLOCK (fail-closed) unexpected data plane error", "\n".join(logs.output))


# ── GATE 8. Framing-on-without-canonical-observer ──────────────────────────────
class TestFramingOnWithoutCanonicalObserver(FramingGatewayTestCase):
    """GATE 8 — PASS (a regression was found and resolved here during review). The correction pass
    added a REQUIRED `http_version` kwarg to `framing_evidence.evaluate(...)` but initially left this
    `enforce()` branch calling it without the kwarg, which raised `TypeError` and fail-closed every
    such request to 503 (violating gate 8 and the observe-only invariant). Track B flagged it and the
    COORDINATOR repaired data_plane.py (now passes `http_version=None` there); these tests pass
    against the repaired file and guard the invariant going forward."""

    async def test_logs_unavailable_no_canonical_observer_and_leaves_response_unchanged(self):
        """framing_observer=True, canonical_observer=None: every request that reaches the hook logs
        FRAMING OBS UNAVAILABLE / NO_CANONICAL_OBSERVER, no worker exists or is started, the response
        is V4's unchanged (observe-only: never a 503 from the missing observer), and V4 is asked once.
        Holds for ALLOW and BLOCK."""
        for v4_name, expected in (("ALLOW", None), ("BLOCK", 403)):
            with self.subTest(v4=v4_name):
                seen = []
                with tested_runtime(), self.assertLogs(FRAMING_LOGGER, level="INFO") as fr:
                    gateway, flow = await self.run_flow(
                        recording_classifier(seen, CLASSIFIER_BEHAVIOURS[v4_name]),
                        observer=None, framing_observer=True)
                    await self.drain(gateway)
                text = "\n".join(fr.output)
                self.assertIn("FRAMING OBS UNAVAILABLE", text)
                self.assertIn("NO_CANONICAL_OBSERVER", text)
                self.assertEqual(len(seen), 1)
                status = None if flow.response is None else flow.response.status_code
                self.assertEqual(status, expected, "the missing observer changed V4's response")
                self.assertIsNone(gateway.canonical_observer)
                self.assertEqual(len(gateway._shadow_tasks), 0)

    async def test_no_framing_line_for_a_preanswered_flow_without_observer(self):
        seen = []
        records = []
        flow = tflow.tflow(req=make_request(), resp=True)
        with _collect(FRAMING_LOGGER, records), tested_runtime():
            gateway, flow = await self.run_flow(
                recording_classifier(seen, CLASSIFIER_BEHAVIOURS["ALLOW"]),
                observer=None, framing_observer=True, flow=flow)
            await self.drain(gateway)
        self.assertEqual(seen, [])
        self.assertEqual(records, [])


# ── pure evaluator coverage (the ONLY producer of PROFILE_MATCHED) ─────────────
def _tested_profile():
    return fe.FramingProfile("12.2.3", True, False, None, None, fe.MODE_REVERSE_LOOPBACK, "lazy",
                             mode_fingerprint=("reverse", "http", "127.0.0.1", 0))


class TestEvaluateDimensions(unittest.TestCase):
    def ev(self, canonical_obs, form=adapter.FORM_ORIGIN, profile=None,
           gen_c=0, gen_r=0, available=True, http_version="HTTP/1.1"):
        return fe.evaluate(profile=_tested_profile() if profile is None else profile,
                           gen_at_capture=gen_c, gen_at_reply=gen_r, canonical_obs=canonical_obs,
                           form=form, http_version=http_version, canonical_available=available)

    def test_profile_matched_only_when_every_condition_holds(self):
        r = self.ev(ok_accept(None))
        self.assertEqual(r.status, fe.PROFILE_MATCHED)
        self.assertEqual(r.reasons, ())
        self.assertEqual(r.canonical_outcome, "ACCEPT")

    def test_no_canonical_observer_is_unavailable(self):
        r = self.ev(None, form=None, available=False)
        self.assertEqual(r.status, fe.UNAVAILABLE)
        self.assertEqual(r.reasons, (fe.NO_CANONICAL_OBSERVER,))

    def test_canonical_reject_is_unattestable_not_a_worker_failure(self):
        r = self.ev(ok_reject_r1(None))
        self.assertEqual(r.status, fe.UNATTESTABLE)
        self.assertIn(fe.CANONICAL_REJECT_REASON, r.reasons)
        self.assertEqual(r.canonical_status, obs_mod.OK)
        self.assertEqual(r.canonical_outcome, "REJECT")

    def test_worker_states_are_unavailable(self):
        for status, reason in ((obs_mod.TIMEOUT, fe.WORKER_TIMEOUT),
                               (obs_mod.BUSY, fe.WORKER_BUSY),
                               (obs_mod.UNAVAILABLE, fe.WORKER_UNAVAILABLE),
                               (obs_mod.DROP, fe.SNAPSHOT_DROPPED),
                               (obs_mod.BODY_UNAVAILABLE, fe.BODY_UNAVAILABLE)):
            with self.subTest(status=status):
                r = self.ev(obs(status, detail="x"))
                self.assertEqual(r.status, fe.UNAVAILABLE)
                self.assertIn(reason, r.reasons)
                self.assertNotEqual(r.status, fe.PROFILE_MATCHED)

    def test_untested_profile_and_disabled_header_validation_are_unattestable(self):
        not_tested = fe.FramingProfile("12.2.3", True, True, None, None,
                                       fe.MODE_REVERSE_LOOPBACK, "lazy")
        r = self.ev(ok_accept(None), profile=not_tested)
        self.assertEqual(r.status, fe.UNATTESTABLE)
        self.assertIn(fe.PROFILE_NOT_TESTED, r.reasons)

        vih_off = fe.FramingProfile("12.2.3", False, False, None, None,
                                    fe.MODE_REVERSE_LOOPBACK, "lazy")
        r2 = self.ev(ok_accept(None), profile=vih_off)
        self.assertEqual(r2.status, fe.UNATTESTABLE)
        self.assertIn(fe.VALIDATE_INBOUND_HEADERS_OFF, r2.reasons)

    def test_http_version_not_11_blocks_a_positive(self):
        r = self.ev(ok_accept(None), http_version="HTTP/1.0")
        self.assertEqual(r.status, fe.UNATTESTABLE)
        self.assertIn(fe.HTTP_VERSION_NOT_11, r.reasons)

    def test_out_of_scope_form_is_unavailable(self):
        r = self.ev(ok_accept(None), form=adapter.FORM_ABSOLUTE)
        self.assertEqual(r.status, fe.UNAVAILABLE)
        self.assertIn(fe.TARGET_FORM_OUT_OF_SCOPE, r.reasons)

    def test_format_record_is_closed_codes_and_numbers_only(self):
        line = fe.format_record("deadbeef", self.ev(ok_accept(None)))
        self.assertEqual(line,
                         "[deadbeef] FRAMING OBS PROFILE_MATCHED canonical_status=OK "
                         "canonical_outcome=ACCEPT target_form=origin gen=0 elapsed=1.000ms")


# ── a tiny log-capture helper (records without asserting a non-empty log) ──────
@contextlib.contextmanager
def _collect(logger_name, records):
    """Capture messages on `logger_name` into `records` without requiring any to be emitted
    (unlike assertLogs, which fails when nothing is logged). Used to assert the ABSENCE of a line."""
    import logging
    logger = logging.getLogger(logger_name)
    handler = logging.Handler()
    handler.emit = lambda record: records.append(record.getMessage())
    previous_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        yield
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)


if __name__ == "__main__":
    unittest.main()
