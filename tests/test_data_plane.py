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
import socket
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

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


if __name__ == "__main__":
    unittest.main()
