"""Unit tests for the canonical observation runtime (data_plane/canonical_observer.py +
data_plane/canonical_worker.py).

The observer runs canonicalize in a SEPARATE worker process (the data-plane interpreter) and
reports an explicit status for every request. These tests spawn the real worker under
`sys.executable` (the test runner is the data-plane venv) and, for protocol-violation paths, a
runtime-generated stand-in worker written to a temp dir (never a repo file). V4 is never involved;
nothing here forwards or enforces.

All timing assertions use generous scheduler tolerance; no exact duration is asserted.

LAB VALUES used below (LAB-ONLY, NOT production defaults; the coordinator chooses real values):
  * timeout_seconds for the OK/REJECT paths: 5.0 s — comfortably above the OBSERVED canonicalize
    durations below (not a proven bound).
  * timeout_seconds for the TIMEOUT / blocked-drain tests: a few ms, against a ~1 MiB body of empty
    gzip members that canonicalize took 28.3-29.7 ms on when measured (2026-10-21, .venv-dataplane,
    Python 3.12; identity 1 MiB ~9.5 ms, tiny ~0.01 ms — OBSERVED synthetic durations, not a
    worst-case bound). A few ms is well below those observed durations, so the deadline reliably
    fires while the work (or a blocked write) is still outstanding, proving the worker is killed,
    not merely abandoned. No production timeout value is implied by this sample; the coordinator
    chooses the real setting from measurement.
  * admission caps for the DROP tests: a deliberately tiny cap so a small request is oversize
    without allocating a megabyte.

Needs the data plane environment (mitmproxy):
    .venv-dataplane/bin/python -m unittest tests.test_canonical_observer -v
"""
import asyncio
import gzip
import os
import signal
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PLANE = os.path.join(REPO_ROOT, "data_plane")
sys.path.insert(0, DATA_PLANE)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from mitmproxy import http
    from mitmproxy.test import tutils
except ImportError as exc:  # pragma: no cover
    raise unittest.SkipTest(f"needs the data plane environment (.venv-dataplane): {exc}")

import canonical_adapter as adapter
import canonical_observer as obs_mod


def req(method=b"GET", path=b"/search?q=laptop", authority=b"", http_version=b"HTTP/1.1",
        headers=None, content=b""):
    if headers is None:
        headers = [(b"Host", b"shop.example")]
    return tutils.treq(method=method, path=path, authority=authority, http_version=http_version,
                       headers=http.Headers(headers), content=content)


STUB_PRELUDE = f"""\
import os, sys, struct
sys.path.insert(0, {DATA_PLANE!r})
import canonical_observer as ipc
import canonical_request as cr
out = os.fdopen(os.dup(1), "wb", buffering=0)
sys.stdout = sys.stderr
stdin = sys.stdin.buffer
out.write(ipc.encode_reply({{"ready": True, "protocol": ipc.PROTOCOL,
                             "contract": cr.CONTRACT_ID, "version": "stub"}}))
out.flush()
"""

STUB_BAD_ID = STUB_PRELUDE + """\
while True:
    payload = ipc.read_frame_sync(stdin, ipc.DEFAULT_CAPS.max_frame_bytes)
    if payload is None:
        break
    sid = struct.unpack(">Q", payload[:8])[0]
    out.write(ipc.encode_reply({"id": sid + 1, "ok": True, "outcome": "ACCEPT",
                                "size": "UNCHECKED", "signals": []}))
    out.flush()
"""

STUB_MALFORMED = STUB_PRELUDE + """\
while True:
    payload = ipc.read_frame_sync(stdin, ipc.DEFAULT_CAPS.max_frame_bytes)
    if payload is None:
        break
    out.write(ipc.encode_frame(b"not-json{", ipc.MAX_REPLY_BYTES))
    out.flush()
"""

# Reads the snapshot frame, then blocks for a long time before replying: used to hold an exchange
# in flight so a cancellation or a shutdown can be injected while it is outstanding.
STUB_SLOW = STUB_PRELUDE + """\
import time as _t
while True:
    payload = ipc.read_frame_sync(stdin, ipc.DEFAULT_CAPS.max_frame_bytes)
    if payload is None:
        break
    sid = struct.unpack(">Q", payload[:8])[0]
    _t.sleep(30)
    out.write(ipc.encode_reply({"id": sid, "ok": True, "outcome": "ACCEPT",
                                "size": "UNCHECKED", "signals": []}))
    out.flush()
"""


class ObserverTestCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._observers = []

    async def asyncTearDown(self):
        for o in self._observers:
            await o.aclose()
        self._tmp.cleanup()

    def real(self, *, timeout=5.0, startup=10.0, backoff=0.0, max_fail=3, caps=obs_mod.DEFAULT_CAPS,
             max_decoded_body=obs_mod.LAB_MAX_DECODED_BODY):
        o = obs_mod.build_process_observer(sys.executable, timeout, startup, backoff, max_fail,
                                           max_decoded_body=max_decoded_body, caps=caps)
        self._observers.append(o)
        return o

    def stub(self, source, *, timeout=5.0, startup=10.0, backoff=0.0, max_fail=3):
        path = os.path.join(self._tmp.name, f"stub_{len(self._observers)}.py")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(source)
        argv = [sys.executable, "-I", path, "--unused", "0"]  # args ignored by the stub
        o = obs_mod.ProcessCanonicalObserver(
            argv, timeout, startup, backoff, max_fail, obs_mod.LAB_MAX_DECODED_BODY)
        self._observers.append(o)
        return o

    async def start(self, o):
        o.prewarm()
        if o._start_task is not None:
            await o._start_task
        return o


class TestDefaultOff(ObserverTestCase):
    async def test_nothing_runs_until_an_observer_is_built_and_started(self):
        # The module creates no observer of its own: the gateway wiring (coordinator's) decides.
        self.assertFalse(hasattr(obs_mod, "observer"))
        o = self.real()
        self.assertIsNone(o.worker_pid)       # built, but no worker spawned yet
        self.assertEqual(o.spawn_count, 0)


class TestLocalStatuses(ObserverTestCase):
    """Statuses decided before any worker is needed."""

    async def test_none_body_is_body_unavailable_not_empty(self):
        o = self.real()
        result = await o.observe(req(content=None))
        self.assertEqual(result.status, obs_mod.BODY_UNAVAILABLE)
        self.assertEqual(o.spawn_count, 0)    # never reached the worker

    async def test_absolute_form_is_out_of_scope(self):
        o = self.real()
        result = await o.observe(req(authority=b"example.com:80"))
        self.assertEqual(result.status, obs_mod.OUT_OF_SCOPE)
        self.assertEqual(result.detail, adapter.SCOPE_ABSOLUTE)

    async def test_http2_is_out_of_scope_unsupported_version(self):
        o = self.real()
        result = await o.observe(req(http_version=b"HTTP/2.0"))
        self.assertEqual(result.status, obs_mod.OUT_OF_SCOPE)
        self.assertEqual(result.detail, adapter.SCOPE_UNSUPPORTED_VERSION)

    async def test_oversize_snapshot_is_dropped_not_rejected(self):
        tiny = obs_mod.AdmissionCaps(max_body_bytes=16)
        o = self.real(caps=tiny)
        result = await o.observe(req(method=b"POST", path=b"/x", content=b"x" * 64))
        self.assertEqual(result.status, obs_mod.DROP)
        self.assertEqual(result.detail, "body_too_large")

    async def test_busy_when_one_is_in_flight(self):
        o = self.real()
        o._busy = True                        # simulate an observation already running
        result = await o.observe(req())
        self.assertEqual(result.status, obs_mod.BUSY)

    async def test_adapter_error_never_raises(self):
        o = self.real()
        result = await o.observe(object())    # not a mitmproxy request
        self.assertEqual(result.status, obs_mod.ADAPTER_ERROR)


class TestWorkerPaths(ObserverTestCase):
    async def test_accept_is_ok_with_size_unchecked_when_budget_is_none(self):
        o = await self.start(self.real())
        self.assertIsNotNone(o.worker_pid)
        result = await o.observe(req(method=b"POST", path=b"/x",
                                     headers=[(b"Content-Type", b"application/json")],
                                     content=b"{\"a\":1}"))
        self.assertEqual(result.status, obs_mod.OK)       # B=None is NOT MALFORMED_CONFIG
        self.assertEqual(result.outcome, "ACCEPT")
        self.assertEqual(result.size, "UNCHECKED")
        self.assertEqual(result.target_form, adapter.FORM_ORIGIN)
        self.assertIsNotNone(result.canonicalize_ms)

    async def test_canonical_reject_is_status_ok_with_outcome_reject(self):
        # Two Content-Type fields -> canonical-request R7; a SUCCESSFUL observation of a reject.
        o = await self.start(self.real())
        result = await o.observe(req(method=b"POST", path=b"/x",
                                     headers=[(b"Content-Type", b"text/plain"),
                                              (b"Content-Type", b"application/json")],
                                     content=b"hi"))
        self.assertEqual(result.status, obs_mod.OK)
        self.assertEqual(result.outcome, "REJECT")
        self.assertEqual(result.reject, "R7")

    async def test_timeout_kills_and_reaps_the_worker(self):
        body = gzip.compress(b"") * (((1 << 20) // len(gzip.compress(b""))) - 1)  # ~1 MiB, 0 decoded
        o = await self.start(self.real(timeout=0.002))
        pid = o.worker_pid
        self.assertIsNotNone(pid)
        result = await o.observe(req(method=b"POST", path=b"/x",
                                     headers=[(b"Content-Encoding", b"gzip")], content=body))
        self.assertEqual(result.status, obs_mod.TIMEOUT)
        self.assertEqual(result.detail, "worker_killed")
        self.assertIsNone(o.worker_pid)       # killed and reaped
        self.assertGreaterEqual(o.kill_count, 1)
        self.assertFalse(_pid_alive(pid))

    async def test_worker_death_while_idle_is_unavailable_and_restarts(self):
        o = await self.start(self.real(backoff=0.0))
        pid = o.worker_pid
        os.kill(pid, 9)                       # kill the worker out from under the observer
        # The observation that meets the dead worker is UNAVAILABLE (no cross-request evidence);
        # like the Analyzer, a fresh worker is started by the NEXT request (after backoff).
        first = await o.observe(req())
        self.assertEqual(first.status, obs_mod.UNAVAILABLE)
        await o.observe(req())                # triggers the background restart
        if o._start_task is not None:
            await o._start_task
        self.assertGreaterEqual(o.spawn_count, 2)

    async def test_mismatched_reply_id_is_refused_and_worker_killed(self):
        o = await self.start(self.stub(STUB_BAD_ID))
        self.assertIsNotNone(o.worker_pid)
        result = await o.observe(req(method=b"POST", path=b"/x", content=b"hi"))
        self.assertEqual(result.status, obs_mod.EXCEPTION)
        self.assertEqual(result.detail, "ipc_id_mismatch")
        self.assertIsNone(o.worker_pid)       # a desynchronised worker is never reused

    async def test_malformed_reply_is_refused_and_worker_killed(self):
        o = await self.start(self.stub(STUB_MALFORMED))
        result = await o.observe(req(method=b"POST", path=b"/x", content=b"hi"))
        self.assertEqual(result.status, obs_mod.EXCEPTION)
        self.assertEqual(result.detail, "ipc_malformed_reply")
        self.assertIsNone(o.worker_pid)


class TestExchangeDeadline(ObserverTestCase):
    """REPAIR 1: the single deadline covers write+drain+read, so a worker that stops reading its
    stdin (blocking drain) cannot evade the timeout."""

    async def test_blocked_drain_still_times_out_and_kills(self):
        o = await self.start(self.real(timeout=0.05))
        pid = o.worker_pid
        self.assertIsNotNone(pid)
        # Larger than a pipe buffer so drain() blocks once the stopped worker stops draining.
        big = b"x" * (256 * 1024)
        try:
            os.kill(pid, signal.SIGSTOP)      # LOCAL test child only
            result = await o.observe(req(method=b"POST", path=b"/x",
                                         headers=[(b"Content-Type", b"text/plain")], content=big))
            self.assertEqual(result.status, obs_mod.TIMEOUT)
            self.assertEqual(result.detail, "worker_killed")
            self.assertFalse(o._busy)         # released even though drain was blocked
            self.assertIsNone(o.worker_pid)   # killed and reaped
            self.assertFalse(_pid_alive(pid))
        finally:
            try:
                os.kill(pid, signal.SIGKILL)  # cleanup if anything above failed before the reap
            except ProcessLookupError:
                pass

    async def test_cancellation_mid_exchange_kills_and_propagates(self):
        o = await self.start(self.stub(STUB_SLOW))
        pid = o.worker_pid
        task = asyncio.ensure_future(o.observe(req(method=b"POST", path=b"/x", content=b"hi")))
        try:
            await asyncio.sleep(0.1)          # let the exchange get outstanding
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertFalse(o._busy)         # released on cancellation
            self.assertIsNone(o._proc)        # invalidated, never reused
            self.assertFalse(_pid_alive(pid))
        finally:
            if not task.done():
                task.cancel()
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


class TestCheapAdmission(ObserverTestCase):
    """REPAIR 2: cheap gates run before any snapshot is materialized."""

    async def test_cheap_paths_build_no_snapshot(self):
        calls = []
        real_build = adapter.build_snapshot

        def counting(r, sid):
            calls.append(sid)
            return real_build(r, sid)

        with patch.object(adapter, "build_snapshot", counting):
            o = self.real(caps=obs_mod.AdmissionCaps(max_body_bytes=8))
            o._busy = True
            self.assertEqual((await o.observe(req())).status, obs_mod.BUSY)
            o._busy = False
            self.assertEqual((await o.observe(req(authority=b"h.example:80"))).status,
                             obs_mod.OUT_OF_SCOPE)
            self.assertEqual((await o.observe(req(content=None))).status, obs_mod.BODY_UNAVAILABLE)
            self.assertEqual((await o.observe(req(method=b"POST", path=b"/x",
                                                  content=b"x" * 64))).status, obs_mod.DROP)
        self.assertEqual(calls, [])           # no snapshot was materialized on any cheap path

    async def test_boundary_request_at_the_caps_still_admits(self):
        # A request exactly at the caps is admitted and observed OK (not dropped).
        caps = obs_mod.AdmissionCaps(max_header_count=4, max_header_bytes=256, max_body_bytes=16)
        o = await self.start(self.real(caps=caps))
        result = await o.observe(req(method=b"POST", path=b"/x",
                                     headers=[(b"Content-Type", b"text/plain")], content=b"hello"))
        self.assertEqual(result.status, obs_mod.OK)
        self.assertEqual(result.outcome, "ACCEPT")


class TestLifecycleCleanup(ObserverTestCase):
    """REPAIR 3: idempotent close/aclose that reap exactly once and orphan nothing."""

    async def test_close_then_aclose_reaps_exactly_once(self):
        o = await self.start(self.real())
        pid = o.worker_pid
        o.close()
        self.assertIsNotNone(o._proc)         # handle retained for aclose() to reap
        # close() closed the subprocess transport (prevents the __del__ "Event loop is closed").
        self.assertTrue(o._proc._transport.is_closing())
        await o.aclose()
        self.assertIsNone(o._proc)            # reaped and dropped
        self.assertEqual(o.kill_count, 1)     # exactly one reap path (aclose's _kill), no double
        self.assertFalse(_pid_alive(pid))

    async def test_double_close_is_idempotent(self):
        o = await self.start(self.real())
        pid = o.worker_pid
        o.close()
        o.close()                             # must not raise
        await o.aclose()
        await o.aclose()                      # must not raise
        self.assertFalse(_pid_alive(pid))

    async def test_shutdown_during_startup(self):
        o = self.real(startup=10.0)
        o.prewarm()                           # schedules the start task
        o.close()                             # cancel mid-start
        await o.aclose()
        self.assertIsNone(o._proc)

    async def test_shutdown_during_exchange(self):
        o = await self.start(self.stub(STUB_SLOW))
        pid = o.worker_pid
        task = asyncio.ensure_future(o.observe(req(method=b"POST", path=b"/x", content=b"hi")))
        try:
            await asyncio.sleep(0.1)          # reach the exchange
            await o.aclose()                  # shut down while an observation is in flight
            result = await task               # the in-flight observe must not raise out
            self.assertIn(result.status,
                          (obs_mod.UNAVAILABLE, obs_mod.TIMEOUT, obs_mod.EXCEPTION))
            self.assertFalse(_pid_alive(pid))
        finally:
            if not task.done():
                task.cancel()
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


class TestLogLineSecrecy(ObserverTestCase):
    MARKERS = ("SECRETPATH", "SECRETQUERY", "SECRETHDRVAL", "SECRETBODY")

    def _assert_clean(self, line):
        for m in self.MARKERS:
            self.assertNotIn(m, line)

    async def test_ok_log_line_carries_no_request_bytes(self):
        o = await self.start(self.real())
        r = req(method=b"POST", path=b"/SECRETPATH?x=SECRETQUERY",
                headers=[(b"X-Secret", b"SECRETHDRVAL"), (b"Content-Type", b"text/plain")],
                content=b"SECRETBODY")
        result = await o.observe(r)
        self.assertEqual(result.status, obs_mod.OK)
        self._assert_clean(obs_mod.format_record("abc12345", result))

    async def test_failure_log_lines_carry_no_request_bytes(self):
        o = self.real()
        for r in (req(path=b"/SECRETPATH?x=SECRETQUERY", authority=b"h.example:80"),  # OUT_OF_SCOPE
                  req(path=b"/SECRETPATH", content=None)):                             # BODY_UNAVAILABLE
            result = await o.observe(r)
            self._assert_clean(obs_mod.format_record("tag00001", result))


def _pid_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


if __name__ == "__main__":
    unittest.main()
