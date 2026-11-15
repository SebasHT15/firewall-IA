"""Data plane tests (data_plane.py).

No model, no control plane and no mitmproxy process. Flows are built with
mitmproxy's own test helpers and handed straight to the addon's `request` hook.
The classifier is replaced by `httpx.MockTransport`, except for the
connection-refused, timeout and proxy-environment cases, which use real local
sockets.

mitmproxy lives in the data plane environment, not in the ML one:
    .venv-dataplane/bin/python -m unittest discover -s tests -p 'test_data_plane.py' -v

Under `python3.12 -m unittest discover -s tests` this module is reported as skipped.
"""

import json
import os
import re
import socket
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "data_plane"))

try:
    import httpx
    from mitmproxy import http
    from mitmproxy.addons import blocklist
    from mitmproxy.test import taddons, tflow, tutils
except ImportError as exc:
    raise unittest.SkipTest(f"needs the data plane environment (.venv-dataplane): {exc}")

import data_plane

URL = "http://classifier.test/classify"

OK_ALLOW = {"status": "ok", "decision": "ALLOW",
            "reason": "Normal HTTP request with no attack patterns detected", "model_latency_ms": 201.5}
OK_BLOCK = {"status": "ok", "decision": "BLOCK",
            "reason": "SQL injection payload detected", "model_latency_ms": 223.2}
INVALID = {"status": "invalid", "decision": None, "reason": None, "model_latency_ms": 12.5}


def make_request(method="GET", path="/search?q=laptop", headers=None, content=b""):
    """A request with exactly these headers (http.Request.make would add content-length)."""
    headers = headers or [("Host", "shop.example"), ("User-Agent", "curl/8.18.0")]
    return tutils.treq(
        method=method.encode(), path=path.encode(), host="shop.example", port=80,
        headers=http.Headers([(k.encode(), v.encode()) for k, v in headers]),
        content=content,
    )


def classifier(status_code=200, json_body=None, content=None, seen=None):
    """A fake /classify that always answers the same way. `seen` collects its requests."""
    def handler(request):
        if seen is not None:
            seen.append(request)
        if content is not None:
            return httpx.Response(status_code, content=content)
        return httpx.Response(status_code, json=json_body)
    return httpx.MockTransport(handler)


class AddonTestCase(unittest.IsolatedAsyncioTestCase):
    async def run_request(self, transport=None, url=URL, timeout=1.0, flow=None):
        """Pass one flow through the addon's request hook and return the flow."""
        flow = flow or tflow.tflow(req=make_request())
        gateway = data_plane.FirewallGateway(url, timeout, transport=transport)
        await gateway.request(flow)
        return flow

    async def assert_fail_closed(self, **kwargs):
        with self.assertLogs("firewall.data_plane", level="ERROR") as logs:
            flow = await self.run_request(**kwargs)
        self.assertIsNotNone(flow.response, "request was not blocked")
        self.assertEqual(flow.response.status_code, 503)
        self.assertEqual(flow.response.text, data_plane.UNAVAILABLE_BODY)
        self.assertIn("BLOCK (fail-closed)", "\n".join(logs.output))
        return flow


class TestDecisions(AddonTestCase):
    async def test_allow_lets_the_request_through(self):
        flow = await self.run_request(classifier(json_body=OK_ALLOW))
        # No response set: mitmproxy forwards the request to the destination.
        self.assertIsNone(flow.response)

    async def test_block_answers_403_and_does_not_forward(self):
        with self.assertLogs("firewall.data_plane", level="WARNING") as logs:
            flow = await self.run_request(classifier(json_body=OK_BLOCK))
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(flow.response.text, data_plane.BLOCKED_BODY)
        self.assertNotIn("SQL", flow.response.text)  # the reason is logged, never returned
        self.assertIn("SQL injection payload detected", "\n".join(logs.output))

    async def test_sends_the_raw_request_using_the_classify_contract(self):
        seen = []
        flow = tflow.tflow(req=make_request())
        await self.run_request(classifier(json_body=OK_ALLOW, seen=seen), flow=flow)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].method, "POST")
        self.assertEqual(str(seen[0].url), URL)
        self.assertEqual(json.loads(seen[0].content),
                         {"request": "GET /search?q=laptop HTTP/1.1\n"
                                     "Host: shop.example\nUser-Agent: curl/8.18.0"})

    async def test_flow_already_answered_is_not_classified(self):
        seen = []
        flow = tflow.tflow(req=make_request(), resp=True)
        original = flow.response
        await self.run_request(classifier(json_body=OK_ALLOW, seen=seen), flow=flow)
        self.assertEqual(seen, [])
        self.assertIs(flow.response, original)


class TestFailClosed(AddonTestCase):
    async def test_invalid_model_output_blocks(self):
        await self.assert_fail_closed(transport=classifier(json_body=INVALID))

    async def test_error_status_codes_block(self):
        for code in (503, 500, 422, 404, 201):
            with self.subTest(code=code):
                await self.assert_fail_closed(transport=classifier(code, json_body=OK_ALLOW))

    async def test_invalid_json_blocks(self):
        await self.assert_fail_closed(transport=classifier(content=b"<html>not json</html>"))

    async def test_answer_without_a_valid_decision_blocks(self):
        bodies = [
            {},
            [],
            "ALLOW",
            {"decision": "ALLOW"},                      # no status
            {"status": "ok"},                           # no decision
            {"status": "ok", "decision": None},
            {"status": "ok", "decision": "allow"},      # the contract is uppercase
            {"status": "ok", "decision": "MAYBE"},
            {"status": "invalid", "decision": "ALLOW"},
        ]
        for body in bodies:
            with self.subTest(body=body):
                await self.assert_fail_closed(transport=classifier(json_body=body))

    async def test_mocked_timeout_blocks(self):
        def handler(request):
            raise httpx.ReadTimeout("simulated", request=request)
        await self.assert_fail_closed(transport=httpx.MockTransport(handler))

    async def test_unexpected_error_blocks_instead_of_escaping_the_hook(self):
        # mitmproxy forwards a request whose hook raised, so this must not raise.
        def handler(request):
            raise RuntimeError("bug")
        await self.assert_fail_closed(transport=httpx.MockTransport(handler))


class TestFailClosedRealSockets(AddonTestCase):
    """No mocks: the classifier call really goes over TCP."""

    async def test_classifier_not_running_blocks(self):
        with socket.socket() as s:          # grab a free port, then leave it closed
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        await self.assert_fail_closed(url=f"http://127.0.0.1:{port}/classify")

    async def test_classifier_timeout_blocks(self):
        # Accepts TCP connections (kernel backlog) but never answers.
        with socket.socket() as silent:
            silent.bind(("127.0.0.1", 0))
            silent.listen(8)
            port = silent.getsockname()[1]
            await self.assert_fail_closed(url=f"http://127.0.0.1:{port}/classify", timeout=0.3)

    async def test_proxy_environment_variables_are_ignored(self):
        """A shell configured to use the gateway must not make the classifier
        call go through a proxy (it would loop back into the gateway)."""

        class AllowAll(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                body = json.dumps(OK_ALLOW).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), AllowAll)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        dead_proxy = "http://127.0.0.1:9"
        env = {"HTTP_PROXY": dead_proxy, "http_proxy": dead_proxy,
               "ALL_PROXY": dead_proxy, "all_proxy": dead_proxy, "NO_PROXY": "", "no_proxy": ""}
        with patch.dict(os.environ, env):
            flow = await self.run_request(url=f"http://127.0.0.1:{server.server_port}/classify")
        self.assertIsNone(flow.response)


def recording_classifier(seen, answer):
    """A fake /classify that records each request, then answers via `answer(request)`."""
    def handler(request):
        seen.append(request)
        return answer(request)
    return httpx.MockTransport(handler)


def raise_timeout(request):
    raise httpx.ReadTimeout("simulated", request=request)


CLASSIFIER_BEHAVIOURS = {
    "ALLOW": lambda r: httpx.Response(200, json=OK_ALLOW),
    "BLOCK": lambda r: httpx.Response(200, json=OK_BLOCK),
    "invalid": lambda r: httpx.Response(200, json=INVALID),
    "HTTP 500": lambda r: httpx.Response(500, json={"detail": "Inference failed"}),
    "timeout": raise_timeout,
}


class TestShadowFeatureExtraction(AddonTestCase):
    """Hybrid Architecture Phase 1 (D43): request features are extracted beside
    the V4 pipeline and change nothing about it — not the text V4 receives, not
    the decision, not enforcement, not fail-closed, not the classifier timing."""

    def shadow_flow(self):
        return tflow.tflow(req=make_request(
            "POST", "/search?q=laptop&q=tv",
            headers=[("Host", "shop.example"), ("User-Agent", "curl/8.18.0"),
                     ("Content-Type", "application/x-www-form-urlencoded")],
            content=b"page=2&sort=price"))

    async def run_shadow(self, transport, shadow):
        gateway = data_plane.FirewallGateway(URL, 1.0, transport=transport, shadow_features=shadow)
        flow = self.shadow_flow()
        await gateway.request(flow)
        return flow

    @staticmethod
    def outcome(flow, seen):
        """What the client gets and what V4 was sent."""
        response = None if flow.response is None else (flow.response.status_code,
                                                         flow.response.text)
        return response, [r.content for r in seen]

    async def test_features_are_extracted_and_v4_still_makes_the_decision(self):
        seen, extracted = [], []
        real = data_plane.request_features.extract_features

        def spy(text):
            extracted.append((text, real(text)))
            return extracted[-1][1]

        with patch.object(data_plane.request_features, "extract_features", side_effect=spy), \
                self.assertLogs("firewall.data_plane", level="INFO") as logs:
            flow = await self.run_shadow(
                recording_classifier(seen, CLASSIFIER_BEHAVIOURS["BLOCK"]), shadow=True)

        # The extractor ran once, on exactly the text V4 was sent.
        self.assertEqual(len(extracted), 1)
        text, features = extracted[0]
        self.assertEqual(len(seen), 1)
        self.assertEqual(json.loads(seen[0].content), {"request": text})
        # It produced the expected description.
        self.assertEqual(
            (features.method, features.body_format, features.query_param_count,
             features.body_param_count, features.repeated_param_name_count),
            ("POST", "form", 2, 2, 1))
        # V4's BLOCK is what was enforced.
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(flow.response.text, data_plane.BLOCKED_BODY)
        output = "\n".join(logs.output)
        self.assertIn("FEATURE EXTRACTION (shadow)", output)
        self.assertIn("method=POST", output)
        self.assertIn("BLOCK", output)

    async def test_outcome_is_identical_with_shadow_on_and_off(self):
        for name, answer in CLASSIFIER_BEHAVIOURS.items():
            with self.subTest(classifier=name):
                outcomes = {}
                for shadow in (False, True):
                    seen = []
                    with self.assertLogs("firewall.data_plane", level="INFO"):
                        flow = await self.run_shadow(recording_classifier(seen, answer), shadow)
                    outcomes[shadow] = self.outcome(flow, seen)
                self.assertEqual(outcomes[True], outcomes[False])

    async def test_extractor_failure_changes_nothing(self):
        for name, expected_status in (("ALLOW", None), ("BLOCK", 403), ("invalid", 503)):
            with self.subTest(classifier=name):
                seen = []
                with patch.object(data_plane.request_features, "extract_features",
                                  side_effect=RuntimeError("boom q=laptop")), \
                        self.assertLogs("firewall.data_plane", level="INFO") as logs:
                    flow = await self.run_shadow(
                        recording_classifier(seen, CLASSIFIER_BEHAVIOURS[name]), shadow=True)
                status = None if flow.response is None else flow.response.status_code
                self.assertEqual(status, expected_status)
                self.assertEqual(len(seen), 1, "V4 must still be asked")
                output = "\n".join(logs.output)
                self.assertIn("FEATURE EXTRACTION (shadow) failed", output)
                self.assertIn("RuntimeError", output)
                # The exception message may quote the request; it is not logged.
                self.assertNotIn("boom", output)
                if name != "invalid":
                    self.assertNotIn("fail-closed", output)

    async def test_request_is_rendered_once(self):
        with patch.object(data_plane, "render_request",
                          wraps=data_plane.render_request) as render, \
                self.assertLogs("firewall.data_plane", level="INFO"):
            await self.run_shadow(recording_classifier([], CLASSIFIER_BEHAVIOURS["ALLOW"]),
                                  shadow=True)
        self.assertEqual(render.call_count, 1)

    async def test_classifier_time_keeps_its_definition(self):
        """`(classifier N ms)` keeps its pre-Phase-1 definition: render_request
        plus the /classify call. A slow render must show up in it; a slow
        extractor must not."""
        real_render = data_plane.render_request
        real_extract = data_plane.request_features.extract_features

        # 30 + 60 ms: each well above the mocked classifier call, together below
        # asyncio's 100 ms slow-callback warning in debug mode.
        def slow_render(request):
            time.sleep(0.03)
            return real_render(request)

        def slow_extract(text):
            time.sleep(0.06)
            return real_extract(text)

        with patch.object(data_plane, "render_request", side_effect=slow_render), \
                patch.object(data_plane.request_features, "extract_features",
                             side_effect=slow_extract), \
                self.assertLogs("firewall.data_plane", level="INFO") as logs:
            await self.run_shadow(recording_classifier([], CLASSIFIER_BEHAVIOURS["BLOCK"]),
                                  shadow=True)
        messages = [r.getMessage() for r in logs.records]
        decision = next(m for m in messages if "(classifier " in m)
        classifier_ms = float(re.search(r"\(classifier ([\d.]+) ms\)", decision).group(1))
        self.assertGreaterEqual(classifier_ms, 29)  # the render is inside (%.0f rounding)
        self.assertLess(classifier_ms, 85)           # the 60 ms extraction is not
        feature = next(m for m in messages if "FEATURE EXTRACTION (shadow)" in m)
        self.assertGreaterEqual(float(re.search(r"\(shadow\) ([\d.]+) ms", feature).group(1)), 60)
        # Logged after the verdict, before the decision line.
        self.assertLess(messages.index(feature), messages.index(decision))

    async def test_shadow_is_off_unless_enabled(self):
        with patch.object(data_plane.request_features, "extract_features") as extractor:
            flow = await self.run_request(classifier(json_body=OK_ALLOW))
        extractor.assert_not_called()
        self.assertIsNone(flow.response)

    async def test_feature_line_carries_no_payload(self):
        flow = tflow.tflow(req=make_request(
            "POST", "/account?token=secret-token-123",
            headers=[("Host", "shop.example"), ("User-Agent", "agent-x"),
                     ("Content-Type", "application/x-www-form-urlencoded")],
            content=b"user=ana&password=hunter2"))
        gateway = data_plane.FirewallGateway(URL, 1.0, transport=classifier(json_body=OK_ALLOW),
                                             shadow_features=True)
        with self.assertLogs("firewall.data_plane.features", level="INFO") as logs:
            await gateway.request(flow)
        line = "\n".join(logs.output)
        for secret in ("secret-token-123", "token", "hunter2", "password", "/account",
                       "shop.example", "agent-x"):
            self.assertNotIn(secret, line)

    async def test_feature_lines_are_not_read_as_decision_lines(self):
        """The External v1 runner, the latency summarizer and docker/demo.sh
        find decisions in the data-plane log with regexes. Feature lines must
        not match them, and decision lines must still match."""
        sys.path.insert(0, os.path.join(REPO_ROOT, "scripts", "external"))
        import external_v1_run
        import summarize_latency_observations
        decision_parsers = [external_v1_run._ALLOW_RE, external_v1_run._BLOCK_RE,
                            external_v1_run._FAILCLOSED_RE,
                            summarize_latency_observations.DECISION_LINE,
                            re.compile(r"\] (ALLOW|BLOCK) ")]  # docker/demo.sh

        for name in ("ALLOW", "BLOCK", "HTTP 500"):
            gateway = data_plane.FirewallGateway(
                URL, 1.0, transport=recording_classifier([], CLASSIFIER_BEHAVIOURS[name]),
                shadow_features=True)
            with self.assertLogs("firewall.data_plane", level="INFO") as logs:
                gateway.running()
                await gateway.request(self.shadow_flow())
            # mitmdump prints "[HH:MM:SS.mmm] <message>".
            lines = [f"[12:00:00.000] {r.getMessage()}" for r in logs.records]
            feature_lines = [ln for ln in lines if "feature extraction" in ln.lower()]
            decision_lines = [ln for ln in lines if any(p.search(ln) for p in decision_parsers)]
            with self.subTest(classifier=name):
                self.assertEqual(len(feature_lines), 2)    # startup mode + one request
                self.assertEqual(len(decision_lines), 1)   # exactly the decision, as before
                for ln in feature_lines:
                    self.assertFalse(any(p.search(ln) for p in decision_parsers), ln)


class TestRenderRequest(unittest.TestCase):
    def test_request_without_body(self):
        self.assertEqual(
            data_plane.render_request(make_request()),
            "GET /search?q=laptop HTTP/1.1\nHost: shop.example\nUser-Agent: curl/8.18.0",
        )

    def test_body_follows_a_blank_line(self):
        req = make_request("POST", "/login", content=b"user=ana&pass=x",
                           headers=[("Host", "shop.example"),
                                    ("Content-Type", "application/x-www-form-urlencoded")])
        self.assertEqual(
            data_plane.render_request(req),
            "POST /login HTTP/1.1\nHost: shop.example\n"
            "Content-Type: application/x-www-form-urlencoded\n\nuser=ana&pass=x",
        )

    def test_headers_are_kept_as_received(self):
        headers = [("Host", "shop.example"), ("Proxy-Connection", "Keep-Alive"),
                   ("Cookie", "a=1"), ("Cookie", "b=2"), ("x-lower", "v")]
        rendered = data_plane.render_request(make_request(headers=headers))
        self.assertEqual(rendered.split("\n")[1:],
                         ["Host: shop.example", "Proxy-Connection: Keep-Alive",
                          "Cookie: a=1", "Cookie: b=2", "x-lower: v"])

    def test_reproduces_the_v4_dataset_representation(self):
        """D1 parity: rebuilding each held-out row as a mitmproxy request and
        rendering it must give back the exact text the model was evaluated on."""
        path = os.path.join(REPO_ROOT, "datasets", "v4_clean", "eval.jsonl")
        if not os.path.exists(path):
            self.skipTest(f"{path} not present (the V4 splits are not tracked in git)")
        with open(path, encoding="utf-8") as f:
            texts = [json.loads(line)["input"] for line in f]
        for text in texts:
            head, _, body = text.partition("\n\n")
            request_line, *header_lines = head.split("\n")
            method, rest = request_line.split(" ", 1)
            target, version = rest.rsplit(" ", 1)
            req = tutils.treq(
                method=method.encode(), path=target.encode(), http_version=version.encode(),
                headers=http.Headers([tuple(p.encode() for p in line.split(": ", 1))
                                      for line in header_lines]),
                content=body.encode(),
            )
            self.assertEqual(data_plane.render_request(req), text)
        self.assertEqual(len(texts), 6206)


class TestConfig(unittest.TestCase):
    def write_config(self, text):
        f = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
        self.addCleanup(os.unlink, f.name)
        with f:
            f.write(text)
        return f.name

    def test_repository_config_loads(self):
        self.assertEqual(data_plane.load_config(),
                         ("http://127.0.0.1:8000/classify", 3.0))

    def test_invalid_config_is_rejected(self):
        bad = [
            "",
            "data_plane: {}",
            "data_plane: {classifier_url: http://127.0.0.1:8000/classify}",
            "data_plane: {classifier_url: 127.0.0.1:8000, classifier_timeout_seconds: 3}",
            "data_plane: {classifier_url: http://127.0.0.1:8000/classify, classifier_timeout_seconds: 0}",
            "data_plane: {classifier_url: http://127.0.0.1:8000/classify, classifier_timeout_seconds: fast}",
        ]
        for text in bad:
            with self.subTest(config=text), self.assertRaises(Exception):
                data_plane.load_config(self.write_config(text))

    def test_repository_config_enables_shadow_feature_extraction(self):
        self.assertIs(data_plane.load_shadow_feature_extraction(), True)

    def test_shadow_feature_extraction_is_optional_and_off_when_absent(self):
        path = self.write_config(
            "data_plane: {classifier_url: http://127.0.0.1:8000/classify, "
            "classifier_timeout_seconds: 3}")
        self.assertIs(data_plane.load_shadow_feature_extraction(path), False)

    def test_shadow_feature_extraction_accepts_booleans_only(self):
        base = ("data_plane: {classifier_url: http://127.0.0.1:8000/classify, "
                "classifier_timeout_seconds: 3, shadow_feature_extraction: %s}")
        self.assertIs(data_plane.load_shadow_feature_extraction(
            self.write_config(base % "false")), False)
        for value in ('"true"', "1", "shadow", "null"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                data_plane.load_shadow_feature_extraction(self.write_config(base % value))


class TestUnloadGuard(unittest.TestCase):
    """mitmdump forwards traffic unfiltered if a hot reload leaves the script
    unloaded; the addon's done() hook closes that gap."""

    def test_unloading_the_addon_while_running_blocks_all_traffic(self):
        blocker = blocklist.BlockList()
        gateway = data_plane.FirewallGateway(URL, 1.0)
        with taddons.context(blocker, gateway) as tctx:
            with self.assertLogs("firewall.data_plane", level="ERROR"):
                tctx.master.addons.remove(gateway)   # what a script reload does
            self.assertEqual(tctx.options.block_list, ["/~all/503"])
            flow = tflow.tflow(req=make_request())
            blocker.request(flow)
            self.assertEqual(flow.response.status_code, 503)

    def test_normal_shutdown_leaves_block_list_alone(self):
        gateway = data_plane.FirewallGateway(URL, 1.0)
        with taddons.context(blocklist.BlockList(), gateway) as tctx:
            tctx.master.should_exit.set()
            tctx.master.addons.remove(gateway)
            self.assertEqual(tctx.options.block_list, [])


class TestDockerLabConfig(unittest.TestCase):
    """docker/config.docker.yaml is bind-mounted over config.yaml inside the
    data-plane container, so the same loader must accept it.

    The Docker Lab deliberately duplicates two keys instead of adding an
    environment override to this validated component. Duplication invites drift,
    so the one key that is allowed to differ is pinned here and the one that is
    not is asserted equal.
    """

    DOCKER_CONFIG = os.path.join(REPO_ROOT, "docker", "config.docker.yaml")
    ROOT_CONFIG = os.path.join(REPO_ROOT, "config.yaml")

    def test_docker_config_loads_and_points_at_the_control_plane_service(self):
        url, timeout = data_plane.load_config(self.DOCKER_CONFIG)
        # A Docker service name, not 127.0.0.1: inside a container, loopback is
        # that container.
        self.assertEqual(url, "http://control-plane:8000/classify")
        self.assertGreater(timeout, 0)

    def test_docker_timeout_does_not_drift_from_the_root_config(self):
        _, docker_timeout = data_plane.load_config(self.DOCKER_CONFIG)
        _, root_timeout = data_plane.load_config(self.ROOT_CONFIG)
        self.assertEqual(
            docker_timeout, root_timeout,
            "docker/config.docker.yaml and config.yaml must keep the same "
            "classifier timeout; if they diverge on purpose, say why in both files",
        )

    def test_docker_config_leaves_shadow_feature_extraction_off(self):
        # Deliberate difference from the root config (Hybrid Architecture
        # Phase 1, D43): the key
        # is absent, so the Docker Lab, the demo and the External v1 capture
        # proxy (which imports data_plane with this file) behave exactly as
        # before. Enabling it in the lab is a separate, explicit change.
        self.assertIs(data_plane.load_shadow_feature_extraction(self.DOCKER_CONFIG), False)

    def test_root_config_still_targets_localhost(self):
        # The local, non-Docker workflow must keep working: the Docker Lab is an
        # addition, not a migration.
        url, _ = data_plane.load_config(self.ROOT_CONFIG)
        self.assertEqual(url, "http://127.0.0.1:8000/classify")


if __name__ == "__main__":
    unittest.main()
