"""Shadow Fast Path inside the data plane (data_plane.py + fast_path.py).

Needs the data plane environment (mitmproxy), like tests/test_data_plane.py:
    .venv-dataplane/bin/python -m unittest discover -s tests -p 'test_data_plane_fast_path.py' -v

What is proven here: the Fast Path only OBSERVES. With it on, V4 is still asked for every request,
receives byte-identical input, and its decision, the response, the fail-closed behaviour and the
number of classifier calls are exactly those with it off, even when the Fast Path hypothetically
says FAST_ALLOW, and even when it fails.
"""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "data_plane"))

try:
    import httpx
    from mitmproxy import http
    from mitmproxy.test import tflow, tutils
except ImportError as exc:
    raise unittest.SkipTest(f"needs the data plane environment (.venv-dataplane): {exc}")

import canonical_request as cr
import data_plane
import fast_path as fp

URL = "http://classifier.test/classify"
POLICY_REL = os.path.join("tests", "fixtures", "fast_path_policy_example.json")
TEST_LIMITS = cr.Limits(max_decoded_body=1_000_000, token_budget=10_000, max_bytes_per_token=48)

OK_ALLOW = {"status": "ok", "decision": "ALLOW", "reason": "Normal HTTP request",
            "model_latency_ms": 1.0}
OK_BLOCK = {"status": "ok", "decision": "BLOCK", "reason": "SQL injection payload detected",
            "model_latency_ms": 1.0}
INVALID = {"status": "invalid", "decision": None, "reason": None, "model_latency_ms": 1.0}


def make_request(method="GET", path="/api/items/42", headers=None, content=b""):
    headers = headers if headers is not None else [("Host", "shop.example")]
    return tutils.treq(method=method.encode(), path=path.encode(), host="shop.example", port=80,
                       headers=http.Headers([(k.encode(), v.encode()) for k, v in headers]),
                       content=content)


def classifier(status_code=200, json_body=None, seen=None):
    def handler(request):
        if seen is not None:
            seen.append(request)
        return httpx.Response(status_code, json=json_body)
    return httpx.MockTransport(handler)


class EligibleEvidence(data_plane.GatewayEvidence):
    """TEST DOUBLE for the two dependencies the real gateway does not have: a real canonical-request
    ACCEPT built from the flow's own parts, and framing evidence marked VERIFIED."""

    def canonical(self, req):
        return cr.canonicalize(cr.RequestParts(
            method=req.data.method, target=req.data.path, http_version=req.http_version,
            headers=tuple((bytes(n), bytes(v)) for n, v in req.headers.fields),
            body=req.raw_content or b""), TEST_LIMITS)

    def framing(self, req):
        return fp.FramingEvidence(fp.FRAMING_VERIFIED, "test double")


class Base(unittest.IsolatedAsyncioTestCase):
    async def run_flow(self, transport, *, shadow=False, policy_file=None, evidence=None,
                       request=None):
        flow = tflow.tflow(req=request or make_request())
        gateway = data_plane.FirewallGateway(
            URL, 1.0, transport=transport, shadow_fast_path=shadow,
            fast_path_policy_file=policy_file, fast_path_evidence=evidence)
        await gateway.request(flow)
        return flow


class TestDefaultGatewayIsIneligible(Base):
    async def test_default_evidence_logs_continue_with_every_unmet_prerequisite(self):
        seen = []
        with self.assertLogs("firewall.data_plane.fastpath", level="INFO") as logs:
            flow = await self.run_flow(classifier(json_body=OK_ALLOW, seen=seen), shadow=True,
                                       policy_file=POLICY_REL)
        line = "\n".join(logs.output)
        self.assertIn("CONTINUE", line)
        for reason in ("FRAMING_UNAVAILABLE", "CANONICAL_UNAVAILABLE"):
            self.assertIn(reason, line)
        self.assertNotIn("FAST_ALLOW", line)
        self.assertNotIn("NO_RULE_MATCHED", line)        # rules are not even consulted
        self.assertIn("v4=ALLOW", line)
        self.assertIsNone(flow.response)                 # V4 allowed: forwarded as before
        self.assertEqual(len(seen), 1)

    async def test_no_policy_file_is_policy_unavailable(self):
        with self.assertLogs("firewall.data_plane.fastpath", level="INFO") as logs:
            await self.run_flow(classifier(json_body=OK_ALLOW), shadow=True)
        self.assertIn("POLICY_UNAVAILABLE", "\n".join(logs.output))

    async def test_invalid_or_missing_policy_never_stops_the_gateway(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = os.path.join(tmp, "bad.json")
            with open(bad, "w") as fh:
                fh.write('{"schema": "fast-path-policy/v1"}')
            for path in (bad, os.path.join(tmp, "missing.json")):
                with self.assertLogs("firewall.data_plane.fastpath", level="INFO") as logs:
                    flow = await self.run_flow(classifier(json_body=OK_ALLOW), shadow=True,
                                               policy_file=path, evidence=EligibleEvidence())
                text = "\n".join(logs.output)
                self.assertIn("POLICY_INVALID", text)
                self.assertNotIn("FAST_ALLOW", text)
                self.assertIsNone(flow.response)

    async def test_off_by_default_and_when_switched_off_no_fast_path_output(self):
        with self.assertNoLogs("firewall.data_plane.fastpath", level="DEBUG"):
            flow = await self.run_flow(classifier(json_body=OK_ALLOW))
        self.assertIsNone(flow.response)


class TestHypotheticalFastAllowDoesNotChangeV4(Base):
    async def hypothetical(self, body, status=200, shadow=True):
        seen = []
        with self.assertLogs("firewall.data_plane.fastpath", level="INFO") as logs:
            flow = await self.run_flow(classifier(status, body, seen), shadow=shadow,
                                       policy_file=POLICY_REL, evidence=EligibleEvidence())
        return flow, seen, "\n".join(logs.output)

    async def test_eligible_request_is_recorded_as_hypothetical(self):
        flow, seen, text = await self.hypothetical(OK_ALLOW)
        self.assertIn("FAST_ALLOW (hypothetical; V4 decision unchanged) rule=item-by-id", text)
        self.assertIn("v4=ALLOW", text)
        self.assertEqual(len(seen), 1)        # V4 was still asked
        self.assertIsNone(flow.response)

    async def test_v4_block_still_blocks_when_fast_path_would_allow(self):
        with self.assertLogs("firewall.data_plane", level="WARNING"):
            flow, seen, text = await self.hypothetical(OK_BLOCK)
        self.assertIn("FAST_ALLOW", text)
        self.assertIn("v4=BLOCK", text)
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(flow.response.text, data_plane.BLOCKED_BODY)
        self.assertEqual(len(seen), 1)

    async def test_classifier_failures_stay_fail_closed(self):
        cases = [(200, INVALID), (503, {"detail": "model not loaded"}), (500, {"x": 1}),
                 (200, ["not", "a", "dict"])]
        for status, body in cases:
            with self.assertLogs("firewall.data_plane", level="ERROR"):
                flow, seen, text = await self.hypothetical(body, status=status)
            self.assertIn("FAST_ALLOW", text, (status, body))
            self.assertEqual(flow.response.status_code, 503, (status, body))
            self.assertEqual(flow.response.text, data_plane.UNAVAILABLE_BODY)
            self.assertEqual(len(seen), 1)

    async def test_classifier_unreachable_stays_fail_closed(self):
        def boom(request):
            raise httpx.ConnectError("refused")
        with self.assertLogs("firewall.data_plane", level="ERROR"):
            with self.assertLogs("firewall.data_plane.fastpath", level="INFO") as logs:
                flow = await self.run_flow(httpx.MockTransport(boom), shadow=True,
                                           policy_file=POLICY_REL, evidence=EligibleEvidence())
        self.assertIn("FAST_ALLOW", "\n".join(logs.output))
        self.assertEqual(flow.response.status_code, 503)

    async def test_ineligible_request_with_policy_still_continues(self):
        # Not covered by any rule: CONTINUE although every prerequisite holds.
        seen = []
        with self.assertLogs("firewall.data_plane.fastpath", level="INFO") as logs:
            flow = await self.run_flow(
                classifier(json_body=OK_ALLOW, seen=seen), shadow=True, policy_file=POLICY_REL,
                evidence=EligibleEvidence(), request=make_request(path="/search?q=laptop"))
        self.assertIn("CONTINUE reasons=NO_RULE_MATCHED", "\n".join(logs.output))
        self.assertIsNone(flow.response)


class TestEquivalenceWithAndWithoutShadow(Base):
    async def test_same_requests_same_classifier_input_same_outcome(self):
        requests = [
            make_request(),
            make_request(path="/healthz"),
            make_request(path="/api/items/7?lang=es"),
            make_request(path="/search?q=laptop"),
            make_request(path="/api/items/1' OR '1'='1"),
            make_request(method="POST", path="/api/items", content=b"a=b",
                         headers=[("Host", "shop.example"),
                                  ("Content-Type", "application/x-www-form-urlencoded")]),
            make_request(path="/api/items/42", headers=[("Host", "shop.example"),
                                                        ("Cookie", "sid=secret-cookie")]),
        ]
        with self.assertLogs("firewall.data_plane", level="DEBUG"):   # keeps the run quiet
            for body, status in ((OK_ALLOW, 200), (OK_BLOCK, 200), (INVALID, 200), (None, 503)):
                for index, req in enumerate(requests):
                    results = {}
                    for shadow in (False, True):
                        seen = []
                        kwargs = dict(shadow=shadow, policy_file=POLICY_REL,
                                      evidence=EligibleEvidence()) if shadow else {}
                        flow = await self.run_flow(classifier(status, body, seen),
                                                   request=req.copy(), **kwargs)
                        results[shadow] = (
                            None if flow.response is None else
                            (flow.response.status_code, flow.response.text,
                             tuple(flow.response.headers.items())),
                            [json.loads(r.content) for r in seen])
                    self.assertEqual(results[False], results[True], (index, body, status))
                    self.assertEqual(len(results[True][1]), 1)

    async def test_fast_path_failure_is_ignored(self):
        for target in ("safe_evaluate", "fast_path_input"):
            seen = []
            with patch.object(fp if target == "safe_evaluate" else data_plane, target,
                              side_effect=RuntimeError("boom")):
                with self.assertLogs("firewall.data_plane.fastpath", level="WARNING") as logs:
                    flow = await self.run_flow(classifier(json_body=OK_ALLOW, seen=seen),
                                               shadow=True, policy_file=POLICY_REL,
                                               evidence=EligibleEvidence())
            self.assertIn("failed", "\n".join(logs.output))
            self.assertIn("ignored, the request continues unchanged", "\n".join(logs.output))
            self.assertIsNone(flow.response)
            self.assertEqual(len(seen), 1)

    async def test_evidence_provider_failure_is_ignored(self):
        class Broken(data_plane.GatewayEvidence):
            def canonical(self, req):
                raise RuntimeError("canonicalizer exploded")
        with self.assertLogs("firewall.data_plane.fastpath", level="WARNING"):
            flow = await self.run_flow(classifier(json_body=OK_BLOCK), shadow=True,
                                       policy_file=POLICY_REL, evidence=Broken())
        self.assertEqual(flow.response.status_code, 403)

    async def test_fast_path_runs_after_the_verdict(self):
        order = []
        real = data_plane.shadow_fast_path

        def spy(*args, **kwargs):
            order.append("fast_path")
            return real(*args, **kwargs)

        def handler(request):
            order.append("classifier")
            return httpx.Response(200, json=OK_ALLOW)
        with patch.object(data_plane, "shadow_fast_path", spy):
            await self.run_flow(httpx.MockTransport(handler), shadow=True,
                                policy_file=POLICY_REL, evidence=EligibleEvidence())
        self.assertEqual(order, ["classifier", "fast_path"])


class TestLogsHoldNoRequestContent(Base):
    async def test_no_path_query_header_value_or_body_in_fast_path_lines(self):
        req = make_request(path="/api/items/42?lang=en", headers=[
            ("Host", "shop.example"), ("Cookie", "sid=SECRET-COOKIE"),
            ("Authorization", "Bearer SECRET-TOKEN")])
        for evidence in (None, EligibleEvidence()):
            with self.assertLogs("firewall.data_plane.fastpath", level="INFO") as logs:
                await self.run_flow(classifier(json_body=OK_ALLOW), shadow=True,
                                    policy_file=POLICY_REL, evidence=evidence,
                                    request=req.copy())
            text = "\n".join(logs.output)
            for secret in ("SECRET-COOKIE", "SECRET-TOKEN", "/api/items", "lang=en", "sid="):
                self.assertNotIn(secret, text)


class TestConfig(unittest.TestCase):
    def write(self, text):
        fh = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
        self.addCleanup(os.unlink, fh.name)
        fh.write(text)
        fh.close()
        return fh.name

    def test_absent_means_off(self):
        path = self.write("data_plane:\n  classifier_url: http://x\n  classifier_timeout_seconds: 1\n")
        self.assertEqual(data_plane.load_shadow_fast_path(path), (False, None))

    def test_valid_and_invalid_values(self):
        ok = self.write("data_plane:\n  shadow_fast_path: true\n  fast_path_policy_file: p.json\n")
        self.assertEqual(data_plane.load_shadow_fast_path(ok), (True, "p.json"))
        for text in ("data_plane:\n  shadow_fast_path: yes please\n",
                     "data_plane:\n  shadow_fast_path: 1\n",
                     "data_plane:\n  fast_path_policy_file: 7\n"):
            with self.assertRaises(ValueError):
                data_plane.load_shadow_fast_path(self.write(text))

    def test_repository_config_ships_it_off(self):
        self.assertEqual(data_plane.load_shadow_fast_path(data_plane.CONFIG_PATH), (False, None))


if __name__ == "__main__":
    unittest.main()
