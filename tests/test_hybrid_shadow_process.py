"""Separate-process shadow runtime tests (data_plane/hybrid_shadow_process.py + _worker.py).

Two layers:
  * the process handling (bounds, kill, recovery, protocol violations), against a scriptable
    stand-in worker (tests/fake_shadow_worker.py) — stdlib only, runs in either environment;
  * the REAL worker with the REAL frozen artifact, which needs the analyzer interpreter and the
    gitignored artifact (D55). Point at them when they are not in this tree:
        FIREWALL_ANALYZER_PYTHON=/path/.venv-analyzer/bin/python \\
        FIREWALL_ANALYZER_ARTIFACT=/path/model-output-hybrid-analyzer-v2/recommended.pkl \\
        .venv-dataplane/bin/python -m unittest tests.test_hybrid_shadow_process -v
    The runner itself runs in the data plane interpreter, the worker under the analyzer one:
    the deployment shape.
"""

import asyncio
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "data_plane"))
HERE = os.path.dirname(os.path.abspath(__file__))
FAKE_WORKER = os.path.join(HERE, "fake_shadow_worker.py")

import hybrid_contracts as contracts  # noqa: E402
import hybrid_shadow as shadow  # noqa: E402
import hybrid_shadow_process as ipc  # noqa: E402
import request_features as rf  # noqa: E402

RAW = ("POST /account?token=secret-token-123 HTTP/1.1\nContent-Type: "
       "application/x-www-form-urlencoded\n\nuser=ana&password=hunter2' OR 1=1--")


def pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def make_runner(mode="ok", once_flag=None, timeout=1.0, startup=5.0, backoff=0.0, failures=3,
                **kw):
    argv = [sys.executable, "-I", FAKE_WORKER, "--mode", mode]
    if once_flag:
        argv += ["--once-flag", once_flag]
    return ipc.ProcessShadowRunner(argv, timeout, startup, backoff, failures, **kw)


class ProcessTestCase(unittest.IsolatedAsyncioTestCase):
    async def start(self, runner):
        """Start the worker and wait until it is ready (or has failed to be)."""
        self.addAsyncCleanup(runner.aclose)
        runner.prewarm()
        if runner._start_task is not None:
            await runner._start_task
        return runner

    async def ready(self, mode="ok", **kw):
        runner = make_runner(mode, **kw)
        await self.start(runner)
        self.assertIsNotNone(runner.worker_pid, "the worker should be ready")
        return runner

    async def settle(self, runner):
        if runner._start_task is not None:
            await runner._start_task


class TestProtocolHelpers(unittest.TestCase):
    def test_nan_and_infinity_cannot_be_encoded_or_decoded(self):
        with self.assertRaises(ValueError):
            ipc.encode_line({"attack": float("nan")})
        with self.assertRaises(ValueError):
            ipc.encode_line({"attack": float("inf")})
        for token in (b"NaN", b"Infinity", b"-Infinity"):
            with self.assertRaises(ValueError):
                ipc.decode_line(b'{"attack":' + token + b'}\n')

    def test_lines_are_bounded_and_must_be_objects(self):
        with self.assertRaises(ValueError):
            ipc.encode_line({"x": "y" * ipc.MAX_LINE_BYTES})
        with self.assertRaises(ValueError):
            ipc.decode_line(b"x" * (ipc.MAX_LINE_BYTES + 1) + b"\n")
        for bad in (b"[1]\n", b'"text"\n', b"{}", b"not json\n"):
            with self.assertRaises(ValueError):
                ipc.decode_line(bad)

    def test_worker_detail_is_data_and_only_a_safe_token_is_kept(self):
        self.assertEqual(ipc.safe_detail("analyze:RuntimeError@x.py:12"), "analyze:RuntimeError@x.py:12")
        for hostile in ("password=hunter2 /account?token=abc", "a" * 200, "", None, 7, "x\ny"):
            self.assertEqual(ipc.safe_detail(hostile), "malformed_detail")

    def test_the_worker_gets_a_minimal_environment_and_isolated_interpreter(self):
        os.environ["HTTP_PROXY"] = "http://leak.example"
        os.environ["FIREWALL_SECRET_FOR_TEST"] = "x"
        try:
            env = ipc.worker_environment()
        finally:
            del os.environ["HTTP_PROXY"], os.environ["FIREWALL_SECRET_FOR_TEST"]
        self.assertLessEqual(set(env), {"PATH", "OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS",
                                        "MKL_NUM_THREADS", "PYTHONDONTWRITEBYTECODE"})
        self.assertEqual(env["OMP_NUM_THREADS"], "1")
        argv = ipc.worker_argv("/py", "/a.pkl")
        self.assertEqual(argv[:2], ["/py", "-I"])

    def test_constructor_rejects_unbounded_or_meaningless_settings(self):
        ok = dict(argv=["x"], timeout_seconds=1, startup_timeout_seconds=1,
                  restart_backoff_seconds=0, max_consecutive_failures=1)
        ipc.ProcessShadowRunner(**ok)
        for key, bad in (("timeout_seconds", 0), ("timeout_seconds", float("inf")),
                         ("timeout_seconds", True), ("startup_timeout_seconds", -1),
                         ("restart_backoff_seconds", -1), ("max_consecutive_failures", 0),
                         ("max_consecutive_failures", 1.5), ("max_consecutive_failures", True)):
            with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                ipc.ProcessShadowRunner(**{**ok, key: bad})


class TestNormalOperation(ProcessTestCase):
    async def test_a_valid_analysis_through_the_worker(self):
        runner = await self.ready()
        result = await runner.run(RAW)
        self.assertEqual(result.status, shadow.OK)
        self.assertEqual(result.attack, 0.25)
        self.assertEqual((result.category, result.category_probability), ("sql_injection", 1.0))
        self.assertEqual(result.analyzer_version, "fake-analyzer/test")
        # Overhead is reported apart from the Analyzer's own time, which the worker measured.
        self.assertEqual(result.analyze_ms, 0.01)
        self.assertAlmostEqual(result.overhead_ms, result.elapsed_ms - 0.01, places=6)

    async def test_the_worker_receives_features_never_the_request_text(self):
        runner = await self.ready()
        seen = []
        real = rf.extract_features
        runner._extract = lambda text: seen.append(text) or real(text)
        line_bytes = []
        original = ipc.encode_line

        def spy(message):
            line_bytes.append(original(message))
            return line_bytes[-1]

        ipc.encode_line = spy
        try:
            await runner.run(RAW)
        finally:
            ipc.encode_line = original
        self.assertEqual(seen, [RAW])
        wire = b"".join(line_bytes).decode()
        for leaked in ("secret-token-123", "hunter2", "password", "/account", "OR 1=1"):
            self.assertNotIn(leaked, wire)
        self.assertEqual(json.loads(wire)["features"]["schema_version"], rf.FEATURE_SCHEMA_VERSION)

    async def test_the_worker_starts_in_the_background_and_requests_never_wait_for_it(self):
        runner = make_runner("slow:0")   # healthy, but start-up takes some interpreter time
        self.addAsyncCleanup(runner.aclose)
        started = time.perf_counter()
        first = await runner.run(RAW)
        self.assertEqual((first.status, first.detail), (shadow.UNAVAILABLE, "worker_starting"))
        self.assertLess(time.perf_counter() - started, 0.1)
        await self.settle(runner)
        self.assertEqual((await runner.run(RAW)).status, shadow.OK)

    async def test_a_worker_failure_is_not_a_score(self):
        for mode, status in (("worker_failed:analyze:ValueError@x.py:1", shadow.FAILED),
                             ("worker_invalid:non_finite_output", shadow.INVALID_OUTPUT)):
            with self.subTest(mode=mode):
                runner = await self.ready(mode)
                result = await runner.run(RAW)
                self.assertEqual(result.status, status)
                self.assertIsNone(result.attack)
                self.assertTrue(result.detail.startswith(mode.split(":", 1)[1]), result.detail)
                self.assertIsNotNone(runner.worker_pid, "a reported failure does not need a kill")

    async def test_hostile_detail_from_a_worker_is_not_logged(self):
        runner = await self.ready("worker_failed:token=secret-token-123 password=hunter2")
        result = await runner.run(RAW)
        self.assertEqual((result.status, result.detail), (shadow.FAILED, "malformed_detail"))


class TestInvalidOutput(ProcessTestCase):
    async def test_invalid_answers_are_invalid_output_and_never_a_score(self):
        cases = {"garbage": "ipc_malformed_or_non_finite",
                 "nan": "ipc_malformed_or_non_finite",       # a raw NaN token is refused at the wire
                 "inf": "ipc_malformed_or_non_finite",
                 "wrong_id": "ipc_id_mismatch",
                 "oversize": "ipc_line_too_long",
                 "out_of_range": "contract_violation",
                 "bad_version": "version_mismatch"}
        for mode, detail in cases.items():
            with self.subTest(mode=mode):
                runner = await self.ready(mode)
                pid = runner.worker_pid
                result = await runner.run(RAW)
                self.assertEqual((result.status, result.detail), (shadow.INVALID_OUTPUT, detail))
                self.assertIsNone(result.attack, "an invalid answer must not leave a score behind")
                if detail.startswith("ipc_"):   # a desynchronised worker is not kept
                    self.assertFalse(pid_alive(pid))
                    self.assertIsNone(runner.worker_pid)

    async def test_a_worker_with_a_different_feature_contract_is_never_used(self):
        runner = make_runner("bad_schema_hello")
        await self.start(runner)
        result = await runner.run(RAW)
        self.assertEqual((result.status, result.detail), (shadow.UNAVAILABLE, "feature_contract_mismatch"))
        self.assertEqual(runner.spawn_count, 1, "a deterministic mismatch must not be retried")


class TestUnavailable(ProcessTestCase):
    async def test_every_deterministic_startup_failure_is_unavailable_and_not_retried(self):
        for detail in ("artifact_missing", "artifact_hash_mismatch", "dependencies_missing",
                       "load_failed", "evidence_unreadable", "feature_contract_mismatch",
                       "artifact_not_configured"):
            with self.subTest(detail=detail):
                runner = make_runner(f"ready_false:{detail}")
                await self.start(runner)
                for _ in range(3):
                    result = await runner.run(RAW)
                    self.assertEqual((result.status, result.detail), (shadow.UNAVAILABLE, detail))
                    self.assertIsNone(result.attack)
                self.assertEqual(runner.spawn_count, 1)
                self.assertIsNone(runner.worker_pid)

    async def test_an_unknown_startup_detail_is_load_failed_not_echoed(self):
        runner = make_runner("ready_false:hunter2")
        await self.start(runner)
        self.assertEqual((await runner.run(RAW)).detail, "load_failed")

    async def test_a_missing_interpreter_is_a_status_not_a_crash(self):
        now = [0.0]
        runner = ipc.ProcessShadowRunner(["/nonexistent/python", "-I", "x"], 1.0, 1.0, 5.0, 2,
                                         clock=lambda: now[0])
        self.addAsyncCleanup(runner.aclose)
        first = await runner.run(RAW)           # triggers the start, which fails at once
        self.assertEqual((first.status, first.detail), (shadow.UNAVAILABLE, "worker_starting"))
        await self.settle(runner)
        again = await runner.run(RAW)
        self.assertEqual((again.status, again.detail), (shadow.UNAVAILABLE, "worker_spawn_failed"))
        # Bounded: two failures, then it gives up.
        now[0] += 6.0
        await runner.run(RAW)
        await self.settle(runner)
        final = await runner.run(RAW)
        self.assertEqual((final.status, final.detail), (shadow.UNAVAILABLE, "worker_disabled"))
        self.assertEqual(runner.spawn_count, 2)

    async def test_startup_timeout_kills_the_starting_worker(self):
        runner = make_runner("never_ready", startup=0.3, backoff=60.0)
        started = time.perf_counter()
        await self.start(runner)
        self.assertLess(time.perf_counter() - started, 3.0)
        self.assertIsNone(runner.worker_pid)
        self.assertEqual(runner.kill_count, 1)
        result = await runner.run(RAW)   # inside the backoff: reports why, starts nothing
        self.assertEqual((result.status, result.detail), (shadow.UNAVAILABLE, "worker_startup_timeout"))
        self.assertEqual(runner.spawn_count, 1)

    async def test_a_worker_that_exits_or_babbles_at_start_is_a_failed_start(self):
        for mode in ("exit_at_start", "bad_hello"):
            with self.subTest(mode=mode):
                runner = make_runner(mode, failures=1)
                await self.start(runner)
                result = await runner.run(RAW)
                self.assertEqual((result.status, result.detail), (shadow.UNAVAILABLE, "worker_disabled"))


class TestBoundedSubmission(ProcessTestCase):
    async def test_concurrent_requests_get_busy_and_nothing_queues(self):
        runner = await self.ready("slow:0.3", timeout=3.0)
        results = await asyncio.gather(*(runner.run(RAW) for _ in range(10)))
        statuses = sorted(r.status for r in results)
        self.assertEqual(statuses, [shadow.BUSY] * 9 + [shadow.OK])
        busy = [r for r in results if r.status == shadow.BUSY]
        self.assertTrue(all(r.elapsed_ms < 50 for r in busy), "BUSY must be immediate")
        self.assertEqual(runner.spawn_count, 1)
        # Once the analysis ends the slot is free again.
        self.assertEqual((await runner.run(RAW)).status, shadow.OK)

    async def test_busy_does_not_reach_the_worker(self):
        runner = await self.ready("slow:0.3", timeout=3.0)
        first = asyncio.create_task(runner.run(RAW))
        await asyncio.sleep(0.05)
        for _ in range(5):
            self.assertEqual((await runner.run(RAW)).status, shadow.BUSY)
        self.assertEqual((await first).status, shadow.OK)
        self.assertEqual(runner._next_id, 1, "only one request was ever sent to the worker")


class TestHungWorker(ProcessTestCase):
    async def test_timeout_kills_the_worker_and_the_pid_is_gone(self):
        runner = await self.ready("hang", timeout=0.2)
        pid = runner.worker_pid
        started = time.perf_counter()
        result = await runner.run(RAW)
        took = time.perf_counter() - started
        self.assertEqual((result.status, result.detail), (shadow.TIMEOUT, "worker_killed"))
        self.assertIsNone(result.attack)
        self.assertLess(took, 2.0)
        self.assertFalse(pid_alive(pid), "TIMEOUT is only reported after the worker is killed and reaped")
        self.assertIsNone(runner.worker_pid)
        self.assertEqual(runner.kill_count, 1)

    async def test_the_killed_worker_is_replaced_and_the_next_analysis_succeeds(self):
        with tempfile.TemporaryDirectory() as d:
            runner = await self.ready("hang", once_flag=os.path.join(d, "flag"), timeout=0.2)
            first_pid = runner.worker_pid
            self.assertEqual((await runner.run(RAW)).status, shadow.TIMEOUT)
            during = await runner.run(RAW)     # the replacement is starting in the background
            self.assertEqual((during.status, during.detail), (shadow.UNAVAILABLE, "worker_starting"))
            await self.settle(runner)
            second_pid = runner.worker_pid
            self.assertIsNotNone(second_pid)
            self.assertNotEqual(first_pid, second_pid)
            self.assertFalse(pid_alive(first_pid))
            result = await runner.run(RAW)
            self.assertEqual(result.status, shadow.OK)
            self.assertEqual(runner.spawn_count, 2)

    async def test_recovery_waits_for_the_backoff(self):
        now = [100.0]
        runner = make_runner("hang", timeout=0.2, backoff=5.0, clock=lambda: now[0])
        await self.start(runner)
        self.assertEqual((await runner.run(RAW)).status, shadow.TIMEOUT)
        for _ in range(3):
            result = await runner.run(RAW)
            self.assertEqual((result.status, result.detail), (shadow.UNAVAILABLE, "worker_restarting"))
        self.assertEqual(runner.spawn_count, 1, "no respawn inside the backoff window")
        now[0] += 6.0
        result = await runner.run(RAW)
        self.assertEqual((result.status, result.detail), (shadow.UNAVAILABLE, "worker_starting"))
        await self.settle(runner)
        self.assertEqual(runner.spawn_count, 2)

    async def test_a_worker_that_keeps_hanging_is_given_up_on(self):
        runner = await self.ready("hang", timeout=0.1, failures=2)
        pids = [runner.worker_pid]
        self.assertEqual((await runner.run(RAW)).status, shadow.TIMEOUT)
        await runner.run(RAW)
        await self.settle(runner)
        pids.append(runner.worker_pid)
        self.assertEqual((await runner.run(RAW)).status, shadow.TIMEOUT)
        for _ in range(3):
            result = await runner.run(RAW)
            self.assertEqual((result.status, result.detail), (shadow.UNAVAILABLE, "worker_disabled"))
        self.assertEqual(runner.spawn_count, 2, "bounded: it stopped spawning")
        self.assertTrue(all(not pid_alive(p) for p in pids if p), "no worker left behind")

    async def test_a_success_resets_the_failure_streak(self):
        with tempfile.TemporaryDirectory() as d:
            runner = await self.ready("hang", once_flag=os.path.join(d, "flag"), timeout=0.2,
                                      failures=2)
            self.assertEqual((await runner.run(RAW)).status, shadow.TIMEOUT)
            await runner.run(RAW)
            await self.settle(runner)
            self.assertEqual((await runner.run(RAW)).status, shadow.OK)
            self.assertEqual(runner._failures, 0)


class TestProcessFailure(ProcessTestCase):
    async def test_a_worker_that_dies_mid_request_is_failed_and_replaced(self):
        with tempfile.TemporaryDirectory() as d:
            runner = await self.ready("crash", once_flag=os.path.join(d, "flag"))
            pid = runner.worker_pid
            result = await runner.run(RAW)
            self.assertEqual((result.status, result.detail), (shadow.FAILED, "worker_exited:rc=7"))
            self.assertFalse(pid_alive(pid))
            await runner.run(RAW)
            await self.settle(runner)
            self.assertEqual((await runner.run(RAW)).status, shadow.OK)

    async def test_a_worker_killed_while_idle_is_noticed_and_replaced(self):
        runner = await self.ready("ok")
        pid = runner.worker_pid
        os.kill(pid, signal.SIGKILL)
        await asyncio.sleep(0.2)
        result = await runner.run(RAW)
        self.assertEqual(result.status, shadow.UNAVAILABLE)
        await self.settle(runner)
        self.assertNotEqual(runner.worker_pid, pid)
        self.assertEqual((await runner.run(RAW)).status, shadow.OK)

    async def test_a_crashing_worker_is_bounded(self):
        runner = await self.ready("crash", failures=2)
        first = await runner.run(RAW)
        self.assertEqual(first.status, shadow.FAILED)
        await runner.run(RAW)
        await self.settle(runner)
        self.assertEqual((await runner.run(RAW)).status, shadow.FAILED)
        final = await runner.run(RAW)
        self.assertEqual((final.status, final.detail), (shadow.UNAVAILABLE, "worker_disabled"))
        self.assertEqual(runner.spawn_count, 2)


class TestShutdown(ProcessTestCase):
    # (the EOF test below is synchronous on purpose: it blocks on a real child and must not
    # stall an event loop)
    async def test_close_kills_the_worker(self):
        runner = await self.ready("ok")
        pid = runner.worker_pid
        runner.close()
        deadline = time.time() + 5
        while pid_alive(pid) and time.time() < deadline:
            await asyncio.sleep(0.02)
        self.assertFalse(pid_alive(pid))
        result = await runner.run(RAW)
        self.assertEqual(result.status, shadow.UNAVAILABLE)
        self.assertEqual(runner.spawn_count, 1, "a closed runner never starts a worker again")

    async def test_aclose_reaps_the_worker_and_a_pending_start(self):
        runner = make_runner("never_ready", startup=30.0)
        runner.prewarm()
        await asyncio.sleep(0.1)
        await runner.aclose()
        self.assertTrue(runner._start_task.done())

    def test_the_worker_exits_by_itself_when_the_gateway_goes_away(self):
        proc = subprocess.Popen([sys.executable, "-I", FAKE_WORKER, "--mode", "ok"],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertTrue(json.loads(proc.stdout.readline())["ready"])
        proc.stdin.close()               # what the OS does to a dead gateway's pipe
        self.assertEqual(proc.wait(timeout=5), 0)
        proc.stdout.close()


# ── the REAL worker with the REAL frozen artifact ──────────────────────────
def _real_python():
    for candidate in (os.environ.get("FIREWALL_ANALYZER_PYTHON"),
                      os.path.join(REPO_ROOT, ".venv-analyzer", "bin", "python")):
        if candidate and os.path.isfile(candidate):
            return candidate


def _real_artifact():
    candidate = os.environ.get("FIREWALL_ANALYZER_ARTIFACT", shadow.DEFAULT_ARTIFACT)
    return candidate if os.path.isfile(candidate) else None


@unittest.skipUnless(_real_python() and _real_artifact(),
                     "needs the analyzer interpreter and the frozen artifact (gitignored, D55)")
class TestRealWorker(ProcessTestCase):
    # Golden values of the frozen artifact (hybrid-analyzer-v2, SHA 79eb7265...), computed with
    # AnalyzerModel.analyze on 2026-10-20. A change here means the artifact or the inference changed.
    GOLDEN = {
        "GET /search?q=laptop HTTP/1.1\nHost: shop.example": 0.028853260186412096,
        "GET /a?q=1' OR 1=1-- HTTP/1.1\nHost: x": 0.9871705666187857,
        'POST /login HTTP/1.1\nContent-Type: application/json\n\n{"user":"ana"}': 0.9938719853574278,
    }

    def real(self, **kw):
        defaults = dict(timeout_seconds=5.0, startup_timeout_seconds=60.0,
                        restart_backoff_seconds=0.0, max_consecutive_failures=3)
        return ipc.build_process_runner(_real_python(), _real_artifact(),
                                        **{**defaults, **kw})

    async def test_normal_operation_matches_the_frozen_analyzer(self):
        runner = self.real()
        await self.start(runner)
        self.assertEqual(runner.analyzer_version, "hybrid-analyzer-v2/attack=hist_gb,category=hist_gb")
        for raw, attack in self.GOLDEN.items():
            with self.subTest(raw=raw[:25]):
                result = await runner.run(raw)
                self.assertEqual(result.status, shadow.OK, result)
                self.assertAlmostEqual(result.attack, attack, places=12)
                self.assertIn(result.category, contracts.ANALYZER_CATEGORIES)
                self.assertGreater(result.analyze_ms, 0)
                self.assertGreaterEqual(result.overhead_ms, 0)

    async def test_missing_artifact(self):
        runner = ipc.build_process_runner(_real_python(), "/nonexistent/recommended.pkl",
                                          5.0, 60.0, 0.0, 3)
        await self.start(runner)
        result = await runner.run(RAW)
        self.assertEqual((result.status, result.detail), (shadow.UNAVAILABLE, "artifact_missing"))
        self.assertEqual(runner.spawn_count, 1)

    async def test_altered_artifact_is_refused_before_it_is_unpickled(self):
        with tempfile.TemporaryDirectory() as d:
            marker = os.path.join(d, "executed")
            evil = os.path.join(d, "recommended.pkl")
            with open(evil, "wb") as f:
                f.write(b"cos\nsystem\n(S'touch " + marker.encode() + b"'\ntR.")
            runner = ipc.build_process_runner(_real_python(), evil, 5.0, 60.0, 0.0, 3)
            await self.start(runner)
            result = await runner.run(RAW)
            self.assertEqual((result.status, result.detail), (shadow.UNAVAILABLE, "artifact_hash_mismatch"))
            self.assertFalse(os.path.exists(marker), "an unverified pickle was executed")

    async def test_dependencies_missing_in_the_wrong_environment(self):
        runner = ipc.build_process_runner(sys.executable, _real_artifact(), 5.0, 60.0, 0.0, 3)
        try:
            import numpy  # noqa: F401
            self.skipTest("the running interpreter has numpy; this case needs one without")
        except ImportError:
            pass
        await self.start(runner)
        result = await runner.run(RAW)
        self.assertEqual((result.status, result.detail), (shadow.UNAVAILABLE, "dependencies_missing"))

    async def test_process_failure_external_kill_then_recovery(self):
        runner = self.real()
        await self.start(runner)
        self.assertEqual((await runner.run(RAW)).status, shadow.OK)
        pid = runner.worker_pid
        os.kill(pid, signal.SIGKILL)
        await asyncio.sleep(0.2)
        during = await runner.run(RAW)
        self.assertEqual(during.status, shadow.UNAVAILABLE)
        await self.settle(runner)
        self.assertNotEqual(runner.worker_pid, pid)
        again = await runner.run(RAW)
        self.assertEqual(again.status, shadow.OK)

    async def test_timeout_kills_the_real_worker_and_it_recovers(self):
        runner = self.real(timeout_seconds=0.0005)   # far below the ~9 ms analysis
        await self.start(runner)
        pid = runner.worker_pid
        result = await runner.run(RAW)
        self.assertEqual((result.status, result.detail), (shadow.TIMEOUT, "worker_killed"))
        self.assertFalse(pid_alive(pid), "the real worker must really be gone")
        during = await runner.run(RAW)      # starts the replacement in the background
        self.assertEqual((during.status, during.detail), (shadow.UNAVAILABLE, "worker_starting"))
        await self.settle(runner)           # replacement loads the artifact again
        self.assertNotEqual(runner.worker_pid, pid)
        runner.timeout_seconds = 5.0        # the recovered worker works
        self.assertEqual((await runner.run(RAW)).status, shadow.OK)

    def test_the_real_worker_exits_on_eof(self):
        proc = subprocess.Popen(ipc.worker_argv(_real_python(), _real_artifact()),
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, env=ipc.worker_environment())
        self.assertTrue(json.loads(proc.stdout.readline())["ready"])
        proc.stdin.close()
        self.assertEqual(proc.wait(timeout=10), 0)
        proc.stdout.close()


if __name__ == "__main__":
    unittest.main()
