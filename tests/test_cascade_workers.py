"""The two worker clients of the cascade, with real processes.

    .venv-dataplane/bin/python -m unittest discover -s tests -p 'test_cascade_workers.py' -v

`InlineCanonicalClient` runs the real worker. `Model2WorkerClient` runs a scripted fake worker for the
failure modes, and the real worker with the real artifact (CPU) when `.venv-analyzer` is present.
"""
import asyncio
import hashlib
import json
import os
import signal
import sys
import tempfile
import textwrap
import time
import types
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "data_plane"))

try:
    from mitmproxy import http
    from mitmproxy.test import tutils
except ImportError as exc:
    raise unittest.SkipTest(f"needs the data plane environment (.venv-dataplane): {exc}")

import canonical_observer as obs     # noqa: E402
import canonical_request as cr       # noqa: E402
import cascade_canonical as CC       # noqa: E402
import cascade_manifest as CM        # noqa: E402
import model2_client as M2           # noqa: E402

PYTHON = sys.executable
ANALYZER = os.path.join(REPO, ".venv-analyzer", "bin", "python")
LIMITS = CM.CanonicalLimits("canonical-request/v1", 4800, 100, 48)
BOUNDS = CM.WorkerBounds(PYTHON, 2.0, 10.0, 0.05, 3)


def make_request(method=b"GET", path=b"/catalog", content=b"", headers=((b"Host", b"h"),)):
    return tutils.treq(method=method, path=path, host="h", port=80,
                       headers=http.Headers(list(headers)), content=content, authority=b"")


class CanonicalTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.pool = CC.CanonicalPool(lambda: CC.build_client(BOUNDS, LIMITS, 4800, 1 << 16), 2)
        self.pool.prewarm()
        deadline = time.monotonic() + 10
        while self.pool.status()["ready"] < 2 and time.monotonic() < deadline:
            await asyncio.sleep(0.01)
        self.assertEqual(self.pool.status()["ready"], 2)

    async def asyncTearDown(self):
        await self.pool.aclose()

    async def test_text_is_the_one_canonicalize_result(self):
        req = make_request(path=b"/search?q=1", content=b"a=1", method=b"POST",
                           headers=[(b"Host", b"h"), (b"Content-Type", b"application/x-www-form-urlencoded"),
                                    (b"Content-Length", b"3")])
        outcome = await self.pool.canonicalize(req, 1.0)
        expected = cr.canonicalize(
            cr.RequestParts(method=b"POST", target=b"/search?q=1", http_version="HTTP/1.1",
                            headers=tuple((bytes(n), bytes(v)) for n, v in req.headers.fields),
                            body=b"a=1"),
            cr.Limits(max_decoded_body=4800, token_budget=100, max_bytes_per_token=48))
        view = outcome.view
        self.assertEqual((view.outcome, view.text, view.size, tuple(view.signals)),
                         (expected.outcome, expected.text, expected.size, expected.signals))
        self.assertEqual(view.audit["target_form"], "origin")
        self.assertEqual(view.audit["text_sha256"], hashlib.sha256(view.text.encode()).hexdigest())

    async def test_reject_is_a_result_not_a_failure(self):
        req = make_request(headers=[(b"Host", b"h"), (b"Content-Type", b"a/b"),
                                    (b"Content-Type", b"c/d")])
        outcome = await self.pool.canonicalize(req, 1.0)
        self.assertEqual((outcome.view.outcome, outcome.view.reject, outcome.view.text),
                         ("REJECT", "R7", None))

    async def test_oversize_is_dropped_before_any_work(self):
        outcome = await self.pool.canonicalize(make_request(content=b"a" * 5000), 1.0)
        self.assertIsNone(outcome.view)
        self.assertEqual(outcome.status, obs.DROP)

    async def test_requests_beyond_the_workers_wait_their_turn(self):
        outcomes = await asyncio.gather(*(self.pool.canonicalize(make_request(), 2.0)
                                          for _ in range(8)))
        self.assertTrue(all(o.view and o.view.outcome == "ACCEPT" for o in outcomes))
        self.assertEqual(self.pool.status()["free"], 2)

    async def test_wait_is_bounded(self):
        handles = [self.pool.try_capture(make_request()) for _ in range(2)]
        self.assertIsNone(self.pool.try_capture(make_request()))
        started = time.monotonic()
        outcome = await self.pool.canonicalize(make_request(), 0.05)
        self.assertEqual(outcome.failure, "pool_wait_timeout")
        self.assertLess(time.monotonic() - started, 1.0)
        for handle in handles:
            await self.pool.finish(handle)
        self.assertEqual(self.pool.status()["free"], 2)

    async def test_a_dead_worker_does_not_deny_what_another_can_serve(self):
        os.kill(self.pool._free[0].worker_pid, signal.SIGKILL)
        await asyncio.sleep(0.05)
        outcome = await self.pool.canonicalize(make_request(), 1.0)
        self.assertEqual(outcome.view.outcome, "ACCEPT")

    async def test_all_workers_dead_is_a_failure_token_then_recovers(self):
        for client in self.pool._clients:
            os.kill(client.worker_pid, signal.SIGKILL)
        await asyncio.sleep(0.05)
        outcome = await self.pool.canonicalize(make_request(), 1.0)
        self.assertIsNone(outcome.view)
        self.assertEqual(outcome.status, obs.UNAVAILABLE)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            outcome = await self.pool.canonicalize(make_request(), 1.0)
            if outcome.view is not None:
                break
            await asyncio.sleep(0.02)
        self.assertEqual(outcome.view.outcome, "ACCEPT")

    async def test_dead_workers_come_back_without_any_request(self):
        """A gateway that is not ready never reaches the pool, so this cannot depend on traffic."""
        for client in self.pool._clients:
            os.kill(client.worker_pid, signal.SIGKILL)
        deadline = time.monotonic() + 5
        while self.pool.status()["ready"] and time.monotonic() < deadline:
            await asyncio.sleep(0.01)
        self.assertEqual(self.pool.status()["ready"], 0)
        deadline = time.monotonic() + 10
        while self.pool.status()["ready"] < 2 and time.monotonic() < deadline:
            self.pool.heal()
            await asyncio.sleep(0.02)
        self.assertEqual(self.pool.status()["ready"], 2)

    async def test_a_worker_stuck_past_the_deadline_is_killed(self):
        bounds = CM.WorkerBounds(PYTHON, 0.05, 10.0, 0.05, 3)
        hang = textwrap.dedent("""\
            import os, sys, time
            sys.path.insert(0, %r)
            import canonical_observer as ipc
            import canonical_request as cr
            out = os.fdopen(os.dup(1), "wb", buffering=0)
            out.write(ipc.encode_reply({"ready": True, "protocol": ipc.PROTOCOL, "contract": cr.CONTRACT_ID}))
            time.sleep(60)
            """) % os.path.join(REPO, "data_plane")
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as fh:
            fh.write(hang)
        self.addCleanup(os.unlink, fh.name)
        client = CC.InlineCanonicalClient([PYTHON, fh.name], bounds.timeout_seconds,
                                          bounds.startup_timeout_seconds, 0.05, 3, 4800,
                                          CC.admission_caps(4800), max_text_bytes=1024, env={})
        client.prewarm()
        deadline = time.monotonic() + 10
        while client.worker_pid is None and time.monotonic() < deadline:
            await asyncio.sleep(0.01)
        pid = client.worker_pid
        outcome = await client.complete(client.capture(make_request()))
        self.assertEqual(outcome.status, obs.TIMEOUT)
        self.assertRaises(ProcessLookupError, os.kill, pid, 0)
        await client.aclose()

    async def test_text_that_does_not_match_its_hash_is_unusable(self):
        observation = obs.CanonicalObservation(obs.OK, outcome="ACCEPT", size="WITHIN_BUDGET",
                                               text_sha256="0" * 64)
        outcome = CC.InlineCanonicalClient._outcome(observation, b"GET / HTTP/1.1\n")
        self.assertEqual((outcome.view, outcome.failure), (None, "text_unavailable"))

    async def test_disabled_client_is_replaced(self):
        client = self.pool._clients[0]
        client._permanent = "worker_disabled"
        self.assertEqual(self.pool.status()["disabled"], 1)
        self.pool.heal()
        self.assertIsNot(self.pool._clients[0], client)
        self.assertEqual(self.pool.status()["disabled"], 0)


FAKE_WORKER = """
import json, os, sys, time
sys.path.insert(0, {data_plane!r})
import canonical_observer as ipc
behavior = {behavior!r}
out = os.fdopen(os.dup(1), "wb", buffering=0)
identity = {identity}
if behavior == "wrong_artifact":
    identity = dict(identity, model_artifact_sha256="f" * 64)
if behavior == "no_hello":
    time.sleep(60)
out.write(ipc.encode_reply(dict(identity, ready=behavior != "not_ready", protocol="model2-worker-ipc/v1")))
stdin = sys.stdin.buffer
while True:
    payload = ipc.read_frame_sync(stdin, 1 << 20)
    if payload is None:
        sys.exit(0)
    message = json.loads(payload)
    reply = dict(id=message["id"], ok=True, decision="DEFER", status="OK", p_block=0.2, threshold=0.9,
                 feature_view="baseline_34", policy_id="p", **{{k: identity[k] for k in
                 ("model_artifact_sha256", "policy_sha256", "policy_status")}})
    if behavior == "hang_on_request":
        time.sleep(60)
    if behavior == "exit_on_request":
        sys.exit(7)
    if behavior == "allow":
        reply["decision"] = "ALLOW"
    if behavior == "other_id":
        reply["id"] += 1
    if behavior == "not_a_probability":
        reply["p_block"] = 2.0
    if behavior == "other_identity":
        reply["policy_sha256"] = "f" * 64
    if behavior == "non_ok":
        reply.update(decision="BLOCK", status="SCORING_FAILED")
    out.write(ipc.encode_reply(reply))
"""

IDENTITY = types.SimpleNamespace(artifact_sha256="a" * 64, feature_view="baseline_34",
                                 policy_sha256="b" * 64, policy_status="LAB_EXPERIMENTAL",
                                 artifact_path="x", policy_path="y")
HELLO = {"model_artifact_sha256": "a" * 64, "feature_view": "baseline_34", "policy_sha256": "b" * 64,
         "policy_status": "LAB_EXPERIMENTAL"}


class Model2ClientTests(unittest.TestCase):
    def client(self, behavior="normal", timeout=0.2, failures=3, startup=5.0):
        fh = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False)
        self.addCleanup(os.unlink, fh.name)
        fh.write(FAKE_WORKER.format(data_plane=os.path.join(REPO, "data_plane"), behavior=behavior,
                                    identity=repr(HELLO)))
        fh.close()
        bounds = CM.WorkerBounds(PYTHON, timeout, startup, 0.01, failures)
        client = M2.Model2WorkerClient([PYTHON, fh.name], IDENTITY, bounds, 1 << 20, env={})
        self.addCleanup(client.close)
        client.start()
        return client

    def wait(self, client, state, timeout=5.0):
        deadline = time.monotonic() + timeout
        while client.state != state and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertEqual(client.state, state)

    def decide(self, client):
        return client.decide(canonical_outcome="ACCEPT", canonical_text="GET / HTTP/1.1\n")

    def test_normal_reply(self):
        client = self.client()
        self.wait(client, M2.READY)
        reply = self.decide(client)
        self.assertEqual((reply.decision, reply.status, reply.p_block), ("DEFER", "OK", 0.2))

    def test_while_starting_it_raises_so_the_router_defers(self):
        client = self.client("no_hello", startup=5.0)
        with self.assertRaises(M2.Model2Unavailable):
            self.decide(client)
        self.assertFalse(client.ever_ready)

    def test_non_ok_reply_is_passed_on_for_the_router_to_refuse(self):
        client = self.client("non_ok")
        self.wait(client, M2.READY)
        reply = self.decide(client)
        self.assertEqual((reply.decision, reply.status), ("BLOCK", "SCORING_FAILED"))

    def test_allow_does_not_exist_at_this_boundary(self):
        client = self.client("allow")
        self.wait(client, M2.READY)
        with self.assertRaises(M2.Model2Unavailable):
            self.decide(client)

    def test_protocol_violations_raise_and_kill_the_worker(self):
        for behavior in ("other_id", "not_a_probability", "other_identity"):
            with self.subTest(behavior=behavior):
                client = self.client(behavior)
                self.wait(client, M2.READY)
                with self.assertRaises(M2.Model2Unavailable):
                    self.decide(client)
                self.assertEqual(client.kill_count, 1)

    def test_timeout_ends_the_worker_and_it_comes_back(self):
        client = self.client("hang_on_request", timeout=0.05)
        self.wait(client, M2.READY)
        started = time.monotonic()
        with self.assertRaises(M2.Model2Unavailable):
            self.decide(client)
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertEqual(client.kill_count, 1)
        time.sleep(0.05)
        client.start()
        self.wait(client, M2.READY)
        self.assertEqual(client.spawn_count, 2)

    def test_exit_gives_up_after_the_bound_and_heal_retries(self):
        client = self.client("exit_on_request", failures=2)
        self.wait(client, M2.READY)
        with self.assertRaises(M2.Model2Unavailable):
            self.decide(client)
        time.sleep(0.05)
        client.start()
        self.wait(client, M2.READY)
        with self.assertRaises(M2.Model2Unavailable):
            self.decide(client)
        self.wait(client, M2.DISABLED)
        client.heal()
        self.wait(client, M2.READY)

    def test_a_dead_worker_is_noticed_without_any_request(self):
        client = self.client()
        self.wait(client, M2.READY)
        client._proc.kill()
        client._proc.wait()
        time.sleep(0.05)
        client.heal()
        deadline = time.monotonic() + 5
        while client.spawn_count < 2 and time.monotonic() < deadline:
            client.heal()
            time.sleep(0.01)
        self.wait(client, M2.READY)
        self.assertEqual(client.spawn_count, 2)

    def test_start_and_heal_never_wait_for_an_exchange(self):
        client = self.client()
        self.wait(client, M2.READY)
        with client._lock:
            started = time.monotonic()
            client.start()
            client.heal()
            self.assertLess(time.monotonic() - started, 0.05)

    def test_identity_mismatch_is_incompatible_and_never_retried(self):
        client = self.client("wrong_artifact")
        self.wait(client, M2.INCOMPATIBLE)
        self.assertEqual(client.status()["detail"], "model_artifact_sha256_mismatch")
        client.heal()
        time.sleep(0.05)
        self.assertEqual(client.spawn_count, 1)
        self.assertFalse(client.ever_ready)

    def test_worker_that_is_not_ready_is_incompatible(self):
        client = self.client("not_ready")
        self.wait(client, M2.INCOMPATIBLE)

    def test_startup_timeout_backs_off(self):
        client = self.client("no_hello", startup=0.05)
        self.wait(client, M2.BACKOFF)
        self.assertEqual(client.status()["detail"], "worker_startup_timeout")

    def test_close_ends_the_worker(self):
        client = self.client()
        self.wait(client, M2.READY)
        proc = client._proc
        client.close()
        self.assertIsNotNone(proc.poll())
        with self.assertRaises(M2.Model2Unavailable):
            self.decide(client)


@unittest.skipUnless(os.path.exists(ANALYZER), "needs .venv-analyzer")
class Model2RealArtifactTests(unittest.TestCase):
    """The real FINAL artifact and lab policy on CPU, as development fixtures. The threshold in that
    policy is LAB_EXPERIMENTAL."""

    def test_real_worker_identity_and_decisions(self):
        with open(os.path.join(REPO, "reports/v5/hybrid/cascade-lab/policies/model2_lab_baseline34.json")) as fh:
            policy_doc = json.load(fh)
        import model2_policy as mp
        policy = mp.parse_policy(policy_doc)
        identity = CM.Model2Identity(
            os.path.join(REPO, "model-output-model2/final/v4-d82-20261027T052308Z/baseline34.json"),
            policy.model_artifact_sha256, policy.feature_view,
            os.path.join(REPO, "reports/v5/hybrid/cascade-lab/policies/model2_lab_baseline34.json"),
            policy.sha256, policy.policy_id, policy.status)
        bounds = CM.WorkerBounds(ANALYZER, 1.0, 30.0, 0.1, 3)
        client = M2.Model2WorkerClient(M2.worker_argv(ANALYZER, identity, 1 << 20), identity, bounds,
                                       1 << 20)
        self.addCleanup(client.close)
        client.start()
        deadline = time.monotonic() + 30
        while client.state == M2.STARTING and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(client.state, M2.READY, client.status())
        benign = client.decide(canonical_outcome="ACCEPT",
                               canonical_text="GET /catalog/widgets HTTP/1.1\n")
        self.assertEqual((benign.decision, benign.status), ("DEFER", "OK"))
        attack = client.decide(canonical_outcome="ACCEPT",
                               canonical_text="GET /download?file=..%2f..%2f..%2fetc%2fpasswd HTTP/1.1\n")
        self.assertEqual((attack.decision, attack.status), ("BLOCK", "OK"))
        self.assertEqual(attack.policy_status, "LAB_EXPERIMENTAL")


if __name__ == "__main__":
    unittest.main()
