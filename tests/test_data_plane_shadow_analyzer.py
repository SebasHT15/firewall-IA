"""Gateway tests for the Hybrid shadow Analyzer (data_plane.py + hybrid_shadow.py).

The contract under test: V4 stays the ONLY enforcement decision. Whatever the Analyzer does
(answer, answer garbage, raise, hang, be absent) the client gets exactly what it would get
with the Analyzer off, V4 is sent exactly the same text, fail-closed is untouched, and the
Analyzer's outcome appears only as a "HYBRID SHADOW" log line correlated by the request's tag.

Needs the data plane environment (mitmproxy):
    .venv-dataplane/bin/python -m unittest tests.test_data_plane_shadow_analyzer -v
"""

import asyncio
import os
import re
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "data_plane"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import httpx  # noqa: F401
    from mitmproxy.addons import blocklist
    from mitmproxy.test import taddons, tflow
except ImportError as exc:
    raise unittest.SkipTest(f"needs the data plane environment (.venv-dataplane): {exc}")

import data_plane
import hybrid_contracts as contracts
import hybrid_shadow as shadow
import request_features as rf
from test_data_plane import (CLASSIFIER_BEHAVIOURS, URL, make_request,  # noqa: E402
                             recording_classifier)

SHADOW_LOGGER = "firewall.data_plane.shadow"


def good_signals(attack=0.02):
    out = {contracts.ATTACK: attack}
    out.update({s: (1.0 if s == "category:other_attack" else 0.0)
                for s in contracts.CATEGORY_SIGNALS})
    return out


class Provider:
    version = "fake-analyzer/test"
    feature_schema = rf.FEATURE_SCHEMA_VERSION

    def __init__(self, behaviour=None):
        self.behaviour = behaviour or (
            lambda f: contracts.AnalyzerOutput(good_signals(), self.version))
        self.calls = 0

    def analyze(self, features):
        self.calls += 1
        return self.behaviour(features)


def hung(release):
    def analyze(features):
        release.wait(30)
        return contracts.AnalyzerOutput(good_signals(), "fake")
    return analyze


def raising(features):
    raise RuntimeError("boom token=secret-token-123")


def invalid(features):
    return contracts.AnalyzerOutput(good_signals(attack=1.7), "fake")


ANALYZERS = {
    "absent": lambda release: shadow.ShadowRunner(None, 1.0, "artifact_missing"),
    "answers attack=0.00": lambda release: shadow.ShadowRunner(
        Provider(lambda f: contracts.AnalyzerOutput(good_signals(0.0), "fake-analyzer/test")), 1.0),
    "answers attack=1.00": lambda release: shadow.ShadowRunner(
        Provider(lambda f: contracts.AnalyzerOutput(good_signals(1.0), "fake")), 1.0),
    "raises": lambda release: shadow.ShadowRunner(Provider(raising), 1.0),
    "invalid output": lambda release: shadow.ShadowRunner(Provider(invalid), 1.0),
    "hangs": lambda release: shadow.ShadowRunner(Provider(hung(release)), 0.05),
}


class ShadowAnalyzerTestCase(unittest.IsolatedAsyncioTestCase):
    def flow(self):
        return tflow.tflow(req=make_request(
            "POST", "/search?q=laptop&q=tv",
            headers=[("Host", "shop.example"), ("User-Agent", "curl/8.18.0"),
                     ("Content-Type", "application/x-www-form-urlencoded")],
            content=b"page=2&sort=price"))

    async def run_flow(self, transport, runner=None, flow=None):
        gateway = data_plane.FirewallGateway(URL, 1.0, transport=transport, shadow_analyzer=runner)
        flow = flow or self.flow()
        await gateway.request(flow)
        return gateway, flow

    @staticmethod
    async def drain(gateway):
        if gateway._shadow_tasks:
            await asyncio.gather(*list(gateway._shadow_tasks))

    @staticmethod
    def outcome(flow, seen):
        response = None if flow.response is None else (flow.response.status_code,
                                                         flow.response.text)
        return response, [r.content for r in seen]


class TestEnforcementIsUntouched(ShadowAnalyzerTestCase):
    async def test_outcome_is_identical_with_every_analyzer_behaviour(self):
        """The decisive test: for every V4 behaviour and every Analyzer behaviour, the
        client's response and the text V4 received equal those of a gateway with no Analyzer."""
        for v4_name, answer in CLASSIFIER_BEHAVIOURS.items():
            seen = []
            with self.assertLogs("firewall.data_plane", level="INFO"):
                _, flow = await self.run_flow(recording_classifier(seen, answer))
            baseline = self.outcome(flow, seen)
            for analyzer_name, make_runner in ANALYZERS.items():
                with self.subTest(v4=v4_name, analyzer=analyzer_name):
                    release = threading.Event()
                    self.addCleanup(release.set)
                    runner = make_runner(release)
                    seen = []
                    with self.assertLogs("firewall.data_plane", level="INFO"):
                        gateway, flow = await self.run_flow(
                            recording_classifier(seen, answer), runner)
                        await self.drain(gateway)
                    release.set()
                    runner.close()
                    self.assertEqual(self.outcome(flow, seen), baseline)

    async def test_the_analyzer_cannot_turn_a_v4_block_into_an_allow(self):
        for name in ("BLOCK", "invalid", "HTTP 500", "timeout"):
            with self.subTest(v4=name):
                runner = ANALYZERS["answers attack=0.00"](None)
                with self.assertLogs("firewall.data_plane", level="INFO"):
                    gateway, flow = await self.run_flow(
                        recording_classifier([], CLASSIFIER_BEHAVIOURS[name]), runner)
                    await self.drain(gateway)
                runner.close()
                self.assertIsNotNone(flow.response, "a request V4 blocked was let through")
                self.assertEqual(flow.response.status_code, 403 if name == "BLOCK" else 503)

    async def test_the_analyzer_cannot_turn_a_v4_allow_into_a_block(self):
        runner = ANALYZERS["answers attack=1.00"](None)
        with self.assertLogs("firewall.data_plane", level="INFO"):
            gateway, flow = await self.run_flow(
                recording_classifier([], CLASSIFIER_BEHAVIOURS["ALLOW"]), runner)
            await self.drain(gateway)
        runner.close()
        self.assertIsNone(flow.response, "the Analyzer's score changed V4's ALLOW")

    async def test_v4_is_asked_before_and_regardless_of_the_analyzer(self):
        seen, provider = [], Provider(raising)
        runner = shadow.ShadowRunner(provider, 1.0)
        with self.assertLogs("firewall.data_plane", level="INFO"):
            gateway, flow = await self.run_flow(
                recording_classifier(seen, CLASSIFIER_BEHAVIOURS["ALLOW"]), runner)
            await self.drain(gateway)
        runner.close()
        self.assertEqual(len(seen), 1)
        self.assertEqual(provider.calls, 1)

    async def test_a_scheduling_failure_cannot_block_the_request(self):
        runner = ANALYZERS["answers attack=0.00"](None)
        with patch.object(data_plane.asyncio, "get_running_loop",
                          side_effect=RuntimeError("no loop")), \
                self.assertLogs("firewall.data_plane", level="INFO") as logs:
            _, flow = await self.run_flow(
                recording_classifier([], CLASSIFIER_BEHAVIOURS["ALLOW"]), runner)
        runner.close()
        self.assertIsNone(flow.response)
        output = "\n".join(logs.output)
        self.assertIn("HYBRID SHADOW not started: RuntimeError", output)
        self.assertNotIn("data plane error", output)
        self.assertNotIn("fail-closed", output)

    async def test_an_unexpected_error_in_the_shadow_task_is_logged_and_ignored(self):
        runner = ANALYZERS["answers attack=0.00"](None)

        async def broken(raw):
            raise KeyError("secret-token-123")

        with patch.object(runner, "run", broken), \
                self.assertLogs("firewall.data_plane", level="INFO") as logs:
            gateway, flow = await self.run_flow(
                recording_classifier([], CLASSIFIER_BEHAVIOURS["ALLOW"]), runner)
            await self.drain(gateway)
        runner.close()
        self.assertIsNone(flow.response)
        output = "\n".join(logs.output)
        self.assertIn("HYBRID SHADOW FAILED v4=ALLOW detail=internal:KeyError", output)
        self.assertNotIn("secret-token-123", output)


class TestBoundedOnTheRequestPath(ShadowAnalyzerTestCase):
    async def test_a_hung_analyzer_never_delays_the_response(self):
        release = threading.Event()
        self.addCleanup(release.set)
        runner = shadow.ShadowRunner(Provider(hung(release)), timeout_seconds=5.0)
        started = time.perf_counter()
        with self.assertLogs("firewall.data_plane", level="INFO"):
            gateway, flow = await self.run_flow(
                recording_classifier([], CLASSIFIER_BEHAVIOURS["BLOCK"]), runner)
        returned_after = time.perf_counter() - started
        # The decision is out while the analysis (timeout 5 s, actually hung) is still pending.
        self.assertEqual(flow.response.status_code, 403)
        self.assertTrue(gateway._shadow_tasks, "the analysis should still be running")
        self.assertLess(returned_after, 1.0)
        release.set()
        with self.assertLogs(SHADOW_LOGGER, level="INFO"):
            await self.drain(gateway)
        runner.close()

    async def test_the_analyzer_is_cut_off_at_its_timeout_and_recorded(self):
        release = threading.Event()
        self.addCleanup(release.set)
        runner = shadow.ShadowRunner(Provider(hung(release)), timeout_seconds=0.1)
        with self.assertLogs("firewall.data_plane", level="INFO") as logs:
            gateway, flow = await self.run_flow(
                recording_classifier([], CLASSIFIER_BEHAVIOURS["ALLOW"]), runner)
            await self.drain(gateway)
        release.set()
        runner.close()
        self.assertIsNone(flow.response)
        line = next(r.getMessage() for r in logs.records if "HYBRID SHADOW" in r.getMessage())
        self.assertIn("HYBRID SHADOW TIMEOUT v4=ALLOW", line)
        self.assertNotIn("attack=", line)

    async def test_requests_during_a_stuck_analysis_are_recorded_busy_and_unqueued(self):
        release = threading.Event()
        self.addCleanup(release.set)
        provider = Provider(hung(release))
        runner = shadow.ShadowRunner(provider, timeout_seconds=0.05)
        with self.assertLogs("firewall.data_plane", level="INFO") as logs:
            gateway = data_plane.FirewallGateway(
                URL, 1.0, transport=recording_classifier([], CLASSIFIER_BEHAVIOURS["ALLOW"]),
                shadow_analyzer=runner)
            for _ in range(4):
                await gateway.request(self.flow())
                await self.drain(gateway)
        release.set()
        runner.close()
        statuses = [re.search(r"HYBRID SHADOW (\w+)", r.getMessage()).group(1)
                    for r in logs.records if "HYBRID SHADOW" in r.getMessage()]
        self.assertEqual(statuses, ["TIMEOUT", "BUSY", "BUSY", "BUSY"])
        self.assertEqual(provider.calls, 1)


class TestCorrelationAndLogging(ShadowAnalyzerTestCase):
    async def lines(self, v4_name, runner):
        with self.assertLogs("firewall.data_plane", level="INFO") as logs:
            flow = self.flow()
            gateway, _ = await self.run_flow(
                recording_classifier([], CLASSIFIER_BEHAVIOURS[v4_name]), runner, flow)
            await self.drain(gateway)
        runner.close()
        return flow, [r.getMessage() for r in logs.records]

    async def test_the_shadow_line_carries_the_flows_tag_and_the_v4_outcome(self):
        expected = {"ALLOW": "v4=ALLOW", "BLOCK": "v4=BLOCK", "invalid": "v4=FAIL_CLOSED",
                    "HTTP 500": "v4=FAIL_CLOSED", "timeout": "v4=FAIL_CLOSED"}
        for v4_name, v4_word in expected.items():
            with self.subTest(v4=v4_name):
                runner = shadow.ShadowRunner(Provider(), 1.0)
                flow, messages = await self.lines(v4_name, runner)
                tag = flow.id[:8]
                shadow_line = next(m for m in messages if "HYBRID SHADOW" in m)
                # The same [tag] every other line of this request has (received / decision).
                self.assertTrue(shadow_line.startswith(f"[{tag}] HYBRID SHADOW OK "), shadow_line)
                self.assertIn(v4_word, shadow_line)
                self.assertTrue(any(m.startswith(f"[{tag}] received ") for m in messages))
                self.assertIn("category=other_attack(1.000)", shadow_line)
                self.assertIn("attack=0.0200", shadow_line)
                self.assertRegex(shadow_line, r"analyze=[\d.]+ms elapsed=[\d.]+ms")

    async def test_each_failure_is_a_distinct_status_in_the_line(self):
        cases = {"absent": ("UNAVAILABLE", "detail=artifact_missing"),
                 "raises": ("FAILED", "detail=analyze:RuntimeError@"),
                 "invalid output": ("INVALID_OUTPUT", "detail=contract_violation")}
        for name, (status, detail) in cases.items():
            with self.subTest(analyzer=name):
                _, messages = await self.lines("ALLOW", ANALYZERS[name](None))
                line = next(m for m in messages if "HYBRID SHADOW" in m)
                self.assertIn(f"HYBRID SHADOW {status} ", line)
                self.assertIn(detail, line)
                self.assertNotIn("attack=", line)   # a failure never looks like a score

    async def test_the_shadow_line_carries_no_request_content(self):
        flow = tflow.tflow(req=make_request(
            "POST", "/account?token=secret-token-123",
            headers=[("Host", "shop.example"), ("User-Agent", "agent-x"),
                     ("Content-Type", "application/x-www-form-urlencoded")],
            content=b"user=ana&password=hunter2"))
        for runner in (shadow.ShadowRunner(Provider(), 1.0), shadow.ShadowRunner(Provider(raising), 1.0)):
            with self.assertLogs(SHADOW_LOGGER, level="INFO") as logs:
                gateway, _ = await self.run_flow(
                    recording_classifier([], CLASSIFIER_BEHAVIOURS["ALLOW"]), runner, flow)
                await self.drain(gateway)
            runner.close()
            text = "\n".join(logs.output)
            for secret in ("secret-token-123", "token", "hunter2", "password", "/account",
                           "shop.example", "agent-x", "boom"):
                self.assertNotIn(secret, text)

    async def test_shadow_lines_are_not_decision_lines(self):
        sys.path.insert(0, os.path.join(REPO_ROOT, "scripts", "external"))
        import external_v1_run
        import summarize_latency_observations
        parsers = [external_v1_run._ALLOW_RE, external_v1_run._BLOCK_RE,
                   external_v1_run._FAILCLOSED_RE, summarize_latency_observations.DECISION_LINE,
                   re.compile(r"\] (ALLOW|BLOCK) ")]
        for name in ("ALLOW", "BLOCK", "HTTP 500"):
            with self.subTest(v4=name):
                runner = shadow.ShadowRunner(Provider(), 1.0)
                with self.assertLogs("firewall.data_plane", level="INFO") as logs:
                    gateway = data_plane.FirewallGateway(
                        URL, 1.0, transport=recording_classifier([], CLASSIFIER_BEHAVIOURS[name]),
                        shadow_analyzer=runner)
                    gateway.running()
                    await gateway.request(self.flow())
                    await self.drain(gateway)
                runner.close()
                lines = [f"[12:00:00.000] {r.getMessage()}" for r in logs.records]
                shadow_lines = [ln for ln in lines if "hybrid shadow" in ln.lower()]
                decisions = [ln for ln in lines if any(p.search(ln) for p in parsers)]
                self.assertEqual(len(shadow_lines), 2)   # startup mode + one request
                self.assertEqual(len(decisions), 1)      # exactly the decision, as before
                for ln in shadow_lines:
                    self.assertFalse(any(p.search(ln) for p in parsers), ln)

    async def test_nothing_is_logged_or_run_when_the_analyzer_is_off(self):
        provider = Provider()
        gateway = data_plane.FirewallGateway(
            URL, 1.0, transport=recording_classifier([], CLASSIFIER_BEHAVIOURS["ALLOW"]))
        with self.assertLogs("firewall.data_plane", level="INFO") as logs:
            gateway.running()
            await gateway.request(self.flow())
        self.assertFalse(gateway._shadow_tasks)
        self.assertEqual(provider.calls, 0)
        output = "\n".join(logs.output)
        self.assertNotIn("HYBRID SHADOW", output)
        self.assertIn("hybrid shadow analyzer: off", output)

    async def test_startup_says_what_will_happen(self):
        cases = {"absent": "UNAVAILABLE (artifact_missing)",
                 "answers attack=0.00": "shadow (logged only, never used for decisions) "
                                        "analyzer=fake-analyzer/test"}
        for name, expected in cases.items():
            runner = ANALYZERS[name](None)
            gateway = data_plane.FirewallGateway(URL, 1.0, shadow_analyzer=runner)
            with self.assertLogs(SHADOW_LOGGER, level="INFO") as logs:
                gateway.running()
            runner.close()
            self.assertIn(expected, "\n".join(logs.output))


class TestConfiguration(unittest.TestCase):
    def write(self, text):
        handle = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
        self.addCleanup(os.unlink, handle.name)
        with handle:
            handle.write(text)
        return handle.name

    BASE = "data_plane: {classifier_url: http://127.0.0.1:8000/classify, classifier_timeout_seconds: 3%s}"

    def test_the_repository_config_leaves_the_analyzer_off(self):
        self.assertIsNone(data_plane.load_shadow_analyzer())

    def test_absent_or_disabled_is_off(self):
        self.assertIsNone(data_plane.load_shadow_analyzer(self.write(self.BASE % "")))
        self.assertIsNone(data_plane.load_shadow_analyzer(self.write(
            self.BASE % ", shadow_analyzer: {enabled: false}")))
        self.assertIsNone(data_plane.build_shadow_analyzer(None))

    FULL = ("shadow_analyzer: {enabled: true, runtime: process, python: .venv-analyzer/bin/python, "
            "artifact_path: model-output-hybrid-analyzer-v2/recommended.pkl, timeout_seconds: 0.25, "
            "startup_timeout_seconds: 10, restart_backoff_seconds: 2, max_consecutive_failures: 3}")

    def test_enabled_needs_every_key_and_resolves_paths_against_the_repository(self):
        config = data_plane.load_shadow_analyzer(self.write(self.BASE % (", " + self.FULL)))
        self.assertEqual(config, data_plane.ShadowAnalyzerConfig(
            os.path.join(REPO_ROOT, ".venv-analyzer/bin/python"),
            os.path.join(REPO_ROOT, "model-output-hybrid-analyzer-v2/recommended.pkl"),
            0.25, 10.0, 2.0, 3))
        keys = ("runtime", "python", "artifact_path", "timeout_seconds",
                "startup_timeout_seconds", "restart_backoff_seconds", "max_consecutive_failures")
        for key in keys:   # no key has a default: the bounds and the interpreter are explicit
            fields = [f for f in self.FULL[len("shadow_analyzer: {"):-1].split(", ")
                      if not f.startswith(key + ":")]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                data_plane.load_shadow_analyzer(self.write(
                    self.BASE % (", shadow_analyzer: {" + ", ".join(fields) + "}")))

    def test_invalid_settings_stop_the_gateway_at_startup(self):
        def replace(old, new):
            return self.FULL.replace(old, new)

        for fragment in ("shadow_analyzer: true", "shadow_analyzer: {}",
                         "shadow_analyzer: {enabled: yes-please}",
                         "shadow_analyzer: {enabled: true}",
                         replace("runtime: process", "runtime: thread"),
                         replace("timeout_seconds: 0.25", "timeout_seconds: 0"),
                         replace("timeout_seconds: 0.25", "timeout_seconds: fast"),
                         replace("timeout_seconds: 0.25", "timeout_seconds: true"),
                         replace("startup_timeout_seconds: 10", "startup_timeout_seconds: -1"),
                         replace("restart_backoff_seconds: 2", "restart_backoff_seconds: -1"),
                         replace("max_consecutive_failures: 3", "max_consecutive_failures: 0"),
                         replace("max_consecutive_failures: 3", "max_consecutive_failures: 1.5"),
                         replace("python: .venv-analyzer/bin/python", "python: 3"),
                         replace("enabled: true,", "enabled: true, extra: 1,")):
            with self.subTest(fragment=fragment[:70]), self.assertRaises(ValueError):
                data_plane.load_shadow_analyzer(self.write(self.BASE % (", " + fragment)))

    def test_zero_backoff_is_allowed_but_zero_timeouts_are_not(self):
        config = data_plane.load_shadow_analyzer(self.write(self.BASE % (
            ", " + self.FULL.replace("restart_backoff_seconds: 2", "restart_backoff_seconds: 0"))))
        self.assertEqual(config.restart_backoff_seconds, 0.0)

    def test_building_a_runner_starts_nothing(self):
        """Gateway start-up must not wait for, or fail on, the Analyzer: the worker is started
        in the background after the gateway runs, and a missing artifact is a status."""
        runner = data_plane.build_shadow_analyzer(data_plane.ShadowAnalyzerConfig(
            "/nonexistent/python", "/nonexistent/recommended.pkl", 1.0, 1.0, 0.0, 3))
        self.assertIsNone(runner.worker_pid)
        self.assertEqual(runner.spawn_count, 0)
        self.assertIsNone(runner.provider)


class TestProcessRuntimeBehindTheGateway(ShadowAnalyzerTestCase):
    """The same gateway guarantees with the separate-process runtime (stand-in worker)."""

    def runner(self, mode="ok", **kw):
        import hybrid_shadow_process as ipc
        argv = [sys.executable, "-I", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                    "fake_shadow_worker.py"), "--mode", mode]
        defaults = dict(timeout_seconds=1.0, startup_timeout_seconds=10.0,
                        restart_backoff_seconds=0.0, max_consecutive_failures=3)
        return ipc.ProcessShadowRunner(argv, **{**defaults, **kw})

    async def ready(self, mode="ok", **kw):
        runner = self.runner(mode, **kw)
        self.addAsyncCleanup(runner.aclose)
        runner.prewarm()
        await runner._start_task
        return runner

    async def test_outcome_is_identical_whatever_the_worker_does(self):
        for v4_name, answer in CLASSIFIER_BEHAVIOURS.items():
            seen = []
            with self.assertLogs("firewall.data_plane", level="INFO"):
                _, flow = await self.run_flow(recording_classifier(seen, answer))
            baseline = self.outcome(flow, seen)
            for mode in ("ok", "hang", "crash", "garbage", "nan", "oversize", "out_of_range",
                         "worker_failed:analyze:E@f.py:1", "ready_false:artifact_missing"):
                with self.subTest(v4=v4_name, worker=mode):
                    runner = await self.ready(mode, timeout_seconds=0.2)
                    seen = []
                    with self.assertLogs("firewall.data_plane", level="INFO"):
                        gateway, flow = await self.run_flow(
                            recording_classifier(seen, answer), runner)
                        await self.drain(gateway)
                    self.assertEqual(self.outcome(flow, seen), baseline)
                    await runner.aclose()

    async def test_a_hung_worker_never_delays_the_response_and_is_killed(self):
        runner = await self.ready("hang", timeout_seconds=0.3)
        pid = runner.worker_pid
        started = time.perf_counter()
        with self.assertLogs("firewall.data_plane", level="INFO") as logs:
            gateway, flow = await self.run_flow(
                recording_classifier([], CLASSIFIER_BEHAVIOURS["BLOCK"]), runner)
            returned_after = time.perf_counter() - started
            self.assertEqual(flow.response.status_code, 403)
            self.assertTrue(gateway._shadow_tasks, "the analysis is still pending")
            self.assertLess(returned_after, 0.25, "the response waited for the worker")
            await self.drain(gateway)
        line = next(r.getMessage() for r in logs.records if "HYBRID SHADOW" in r.getMessage())
        self.assertIn("HYBRID SHADOW TIMEOUT v4=BLOCK", line)
        self.assertIn("detail=worker_killed", line)
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    async def test_the_shadow_line_has_status_score_category_and_separate_overhead(self):
        runner = await self.ready("ok")
        with self.assertLogs("firewall.data_plane", level="INFO") as logs:
            flow = self.flow()
            gateway, _ = await self.run_flow(
                recording_classifier([], CLASSIFIER_BEHAVIOURS["ALLOW"]), runner, flow)
            await self.drain(gateway)
        line = next(r.getMessage() for r in logs.records if "HYBRID SHADOW" in r.getMessage())
        self.assertTrue(line.startswith(f"[{flow.id[:8]}] HYBRID SHADOW OK v4=ALLOW "), line)
        self.assertRegex(line, r"attack=0\.2500 category=sql_injection\(1\.000\) "
                               r"analyze=0\.010ms overhead=[\d.]+ms elapsed=[\d.]+ms")

    async def test_startup_line_and_prewarm(self):
        runner = self.runner("ok")
        self.addAsyncCleanup(runner.aclose)
        gateway = data_plane.FirewallGateway(URL, 1.0, shadow_analyzer=runner)
        with self.assertLogs(SHADOW_LOGGER, level="INFO") as logs:
            gateway.running()
        self.assertIn("shadow, separate process (logged only, never used for decisions)",
                      "\n".join(logs.output))
        await runner._start_task   # the worker was started by running(), in the background
        self.assertIsNotNone(runner.worker_pid)

    async def test_done_kills_the_worker(self):
        runner = await self.ready("ok")
        pid = runner.worker_pid
        gateway = data_plane.FirewallGateway(URL, 1.0, shadow_analyzer=runner)
        with taddons.context(blocklist.BlockList(), gateway) as tctx:
            tctx.master.should_exit.set()          # a normal shutdown
            tctx.master.addons.remove(gateway)     # calls the addon's done()
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            await asyncio.sleep(0.02)
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)


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
class TestRealWorkerBehindTheGateway(ShadowAnalyzerTestCase):
    """The ACTUAL path: this (data plane) interpreter runs the gateway; the real frozen
    Analyzer runs in a worker under the analyzer interpreter."""

    def real(self, artifact=None, **kw):
        import hybrid_shadow_process as ipc
        defaults = dict(timeout_seconds=5.0, startup_timeout_seconds=60.0,
                        restart_backoff_seconds=0.0, max_consecutive_failures=3)
        return ipc.build_process_runner(_real_python(), artifact or _real_artifact(),
                                        **{**defaults, **kw})

    async def ready(self, **kw):
        runner = self.real(**kw)
        self.addAsyncCleanup(runner.aclose)
        runner.prewarm()
        await runner._start_task
        return runner

    def attack_flow(self):
        return tflow.tflow(req=make_request(
            "GET", "/a?q=1'%20OR%201=1--", headers=[("Host", "shop.example")]))

    async def test_real_analyzer_scores_beside_every_v4_outcome(self):
        runner = await self.ready()
        for v4_name, v4_word in (("ALLOW", "v4=ALLOW"), ("BLOCK", "v4=BLOCK"),
                                 ("invalid", "v4=FAIL_CLOSED"), ("timeout", "v4=FAIL_CLOSED")):
            with self.subTest(v4=v4_name):
                seen = []
                with self.assertLogs("firewall.data_plane", level="INFO"):
                    _, baseline_flow = await self.run_flow(recording_classifier(
                        seen, CLASSIFIER_BEHAVIOURS[v4_name]), None, self.attack_flow())
                baseline = self.outcome(baseline_flow, seen)
                seen = []
                flow = self.attack_flow()
                with self.assertLogs("firewall.data_plane", level="INFO") as logs:
                    gateway, flow = await self.run_flow(
                        recording_classifier(seen, CLASSIFIER_BEHAVIOURS[v4_name]), runner, flow)
                    await self.drain(gateway)
                self.assertEqual(self.outcome(flow, seen), baseline, "enforcement changed")
                line = next(r.getMessage() for r in logs.records if "HYBRID SHADOW" in r.getMessage())
                self.assertTrue(line.startswith(f"[{flow.id[:8]}] HYBRID SHADOW OK {v4_word} "), line)
                self.assertIn("analyzer=hybrid-analyzer-v2/attack=hist_gb,category=hist_gb", line)
                attack = float(re.search(r"attack=([\d.]+)", line).group(1))
                self.assertGreater(attack, 0.9)   # the Analyzer's view; V4's decision is what was enforced
                self.assertRegex(line, r"analyze=[\d.]+ms overhead=[\d.]+ms elapsed=[\d.]+ms")

    async def test_the_analyzer_saying_attack_never_blocks_a_v4_allow(self):
        runner = await self.ready()
        with self.assertLogs("firewall.data_plane", level="INFO"):
            gateway, flow = await self.run_flow(
                recording_classifier([], CLASSIFIER_BEHAVIOURS["ALLOW"]), runner, self.attack_flow())
            await self.drain(gateway)
        self.assertIsNone(flow.response)

    async def test_missing_artifact_is_unavailable_and_v4_is_unaffected(self):
        runner = self.real(artifact="/nonexistent/recommended.pkl")
        self.addAsyncCleanup(runner.aclose)
        runner.prewarm()
        await runner._start_task
        seen = []
        with self.assertLogs("firewall.data_plane", level="INFO") as logs:
            gateway, flow = await self.run_flow(
                recording_classifier(seen, CLASSIFIER_BEHAVIOURS["BLOCK"]), runner)
            await self.drain(gateway)
        self.assertEqual(flow.response.status_code, 403)
        line = next(r.getMessage() for r in logs.records if "HYBRID SHADOW" in r.getMessage())
        self.assertIn("HYBRID SHADOW UNAVAILABLE v4=BLOCK detail=artifact_missing", line)

    async def test_timeout_then_recovery_with_v4_unchanged_throughout(self):
        runner = await self.ready(timeout_seconds=0.0005)
        pid = runner.worker_pid
        statuses = []
        with self.assertLogs("firewall.data_plane", level="INFO") as logs:
            gateway = data_plane.FirewallGateway(
                URL, 1.0, transport=recording_classifier([], CLASSIFIER_BEHAVIOURS["ALLOW"]),
                shadow_analyzer=runner)
            flows = []
            for step in range(3):
                flow = self.attack_flow()
                await gateway.request(flow)
                await self.drain(gateway)
                flows.append(flow)
                if step == 0:
                    await runner._start_task if runner._start_task else None
                    runner.timeout_seconds = 5.0   # from here on the recovered worker has time
                if step == 1 and runner._start_task is not None:
                    await runner._start_task
        self.assertTrue(all(f.response is None for f in flows), "V4 allowed all three")
        statuses = [re.search(r"HYBRID SHADOW (\w+)", r.getMessage()).group(1)
                    for r in logs.records if "HYBRID SHADOW" in r.getMessage()]
        self.assertEqual(statuses[0], "TIMEOUT")
        self.assertEqual(statuses[-1], "OK", statuses)
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)


if __name__ == "__main__":
    unittest.main()
