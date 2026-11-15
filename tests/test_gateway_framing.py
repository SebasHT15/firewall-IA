"""`gateway-framing/v1`: scope, effective profile, delivery binding, tickets and the egress guard.

Needs the data plane environment (mitmproxy's serializer is part of what is tested):
    .venv-dataplane/bin/python -m unittest discover -s tests -p 'test_gateway_framing.py' -v

The guard tests use real sockets on loopback with an in-process recording upstream.
"""
import asyncio
import hashlib
import os
import sys
import types
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(REPO, "data_plane"), os.path.join(REPO, "scripts", "cascade_lab")]

try:
    from mitmproxy import http
    from mitmproxy.test import tflow, tutils
except ImportError as exc:
    raise unittest.SkipTest(f"needs the data plane environment (.venv-dataplane): {exc}")

import fast_path as fp           # noqa: E402
import framing_evidence as fe    # noqa: E402
import gateway_framing as GF     # noqa: E402
import http1_wire as W           # noqa: E402


def make_request(method=b"GET", path=b"/a", headers=((b"Host", b"shop.local"),), content=b"",
                 http_version=b"HTTP/1.1"):
    req = tutils.treq(method=method, path=path, host="shop.local", port=80,
                      headers=http.Headers(list(headers)), content=content,
                      http_version=http_version, authority=b"")
    req.timestamp_end = 1.0
    return req


def make_flow(**kwargs):
    flow = tflow.tflow(req=make_request(**kwargs))
    flow.client_conn.timestamp_tls_setup = None
    return flow


class DriftGuard(unittest.TestCase):
    def test_incomplete_reasons_match_the_lab_reader(self):
        import lab_server
        self.assertEqual(GF.WIRE_INCOMPLETE, lab_server._WIRE_INCOMPLETE)

    def test_profile_match_is_never_the_binding_status(self):
        self.assertNotEqual(GF.EGRESS_BOUND, fe.PROFILE_MATCHED)
        self.assertNotEqual(GF.EGRESS_BOUND, fp.FRAMING_VERIFIED)


class ScopeTests(unittest.TestCase):
    def test_supported_request(self):
        self.assertIsNone(GF.check_scope(make_flow()))

    def test_rejections(self):
        cases = (
            (dict(http_version=b"HTTP/1.0"), GF.SCOPE_HTTP_VERSION),
            (dict(http_version=b"HTTP/2.0"), GF.SCOPE_HTTP_VERSION),
            (dict(path=b"*"), GF.SCOPE_TARGET_FORM),
            (dict(headers=[(b"Host", b"h"), (b"Upgrade", b"websocket"),
                           (b"Connection", b"Upgrade")]), GF.SCOPE_UPGRADE),
            (dict(headers=[(b"Host", b"h"), (b"Connection", b"keep-alive, upgrade")]), GF.SCOPE_UPGRADE),
            (dict(headers=[(b"Host", b"a"), (b"Host", b"b")]), GF.SCOPE_HOST_COUNT),
            (dict(headers=[(b"Accept", b"*/*")]), GF.SCOPE_HOST_COUNT),
        )
        for kwargs, expected in cases:
            with self.subTest(kwargs=kwargs):
                self.assertEqual(GF.check_scope(make_flow(**kwargs)), expected)

    def test_tls_inbound_rejected(self):
        flow = make_flow()
        flow.client_conn.timestamp_tls_setup = 1.0
        self.assertEqual(GF.check_scope(flow), GF.SCOPE_TLS_INBOUND)

    def test_absolute_form_rejected(self):
        flow = make_flow()
        flow.request.authority = "shop.local"
        self.assertEqual(GF.check_scope(flow), GF.SCOPE_TARGET_FORM)

    def test_streamed_body_rejected(self):
        flow = make_flow()
        flow.request.stream = True
        self.assertEqual(GF.check_scope(flow), GF.SCOPE_STREAMED_BODY)
        flow = make_flow()
        flow.request.data.content = None
        self.assertEqual(GF.check_scope(flow), GF.SCOPE_STREAMED_BODY)

    def test_trailers_rejected(self):
        flow = make_flow()
        flow.request.trailers = http.Headers([(b"X", b"1")])
        self.assertEqual(GF.check_scope(flow), GF.SCOPE_TRAILERS)


class BindingTests(unittest.TestCase):
    def test_binding_is_the_serialized_message(self):
        from mitmproxy.net.http import http1
        req = make_request(method=b"POST", headers=[(b"Host", b"h"), (b"Content-Length", b"3")],
                           content=b"abc")
        binding = GF.bind_delivery(req, 7)
        self.assertEqual(binding.wire, http1.assemble_request(req))
        self.assertEqual(binding.wire_sha256, hashlib.sha256(binding.wire).hexdigest())
        self.assertEqual(binding.parts.body, b"abc")
        self.assertEqual(binding.generation, 7)
        self.assertEqual(binding.body_framing, "content-length")

    def test_chunked_is_bound_as_it_will_be_rechunked(self):
        req = make_request(method=b"POST", headers=[(b"Host", b"h"),
                                                    (b"Transfer-Encoding", b"chunked")], content=b"abc")
        binding = GF.bind_delivery(req, 0)
        self.assertTrue(binding.wire.endswith(b"3\r\nabc\r\n0\r\n\r\n"))
        self.assertEqual(binding.parts.body, b"abc")
        self.assertEqual(binding.body_framing, "chunked")

    def test_missing_body_has_no_binding(self):
        req = make_request()
        req.data.content = None
        with self.assertRaises(GF.BindingError) as caught:
            GF.bind_delivery(req, 0)
        self.assertEqual(caught.exception.reason, GF.BINDING_ASSEMBLE_FAILED)

    def test_body_shorter_than_declared_is_refused(self):
        req = make_request(method=b"POST", headers=[(b"Host", b"h"), (b"Content-Length", b"9")],
                           content=b"abc")
        with self.assertRaises(GF.BindingError) as caught:
            GF.bind_delivery(req, 0)
        self.assertEqual(caught.exception.reason, GF.BINDING_INCOMPLETE)

    def test_body_longer_than_declared_is_refused(self):
        req = make_request(method=b"POST", headers=[(b"Host", b"h"), (b"Content-Length", b"1")],
                           content=b"abc")
        with self.assertRaises(GF.BindingError) as caught:
            GF.bind_delivery(req, 0)
        self.assertEqual(caught.exception.reason, GF.BINDING_TRAILING_BYTES)

    def test_conflicting_framing_is_refused_by_the_strict_parser(self):
        req = make_request(method=b"POST", headers=[(b"Host", b"h"), (b"Content-Length", b"0"),
                                                    (b"Transfer-Encoding", b"chunked")])
        with self.assertRaises(W.WireError):
            GF.bind_delivery(req, 0)

    def test_folded_value_tolerated_by_the_object_is_refused(self):
        req = make_request(headers=[(b"Host", b"h"), (b"X", b"a\r\n b")])
        with self.assertRaises(W.WireError) as caught:
            GF.bind_delivery(req, 0)
        self.assertEqual(caught.exception.reason, "obsolete-line-folding")

    def test_value_that_would_inject_a_header_is_not_equal_to_the_object(self):
        req = make_request(headers=[(b"Host", b"h"), (b"X", b"a\r\nTransfer-Encoding: chunked")])
        with self.assertRaises((GF.BindingError, W.WireError)):
            GF.bind_delivery(req, 0)

    def test_evidence_needs_the_deployment_flag(self):
        binding = GF.bind_delivery(make_request(), 3)
        self.assertEqual(binding.framing_evidence(False).status, fp.FRAMING_UNVERIFIED)
        evidence = binding.framing_evidence(True)
        self.assertEqual(evidence.status, fp.FRAMING_VERIFIED)
        self.assertIn(GF.CONTRACT_ID, evidence.detail)
        self.assertIn("generation=3", evidence.detail)


def good_options(**changes):
    values = dict(GF.REQUIRED_OPTIONS)
    values.update(mode=["reverse:http://127.0.0.1:9000"], body_size_limit="1m")
    values.update(changes)
    return types.SimpleNamespace(**values)


class ProfileTests(unittest.TestCase):
    def problems(self, options, version=fe.TESTED_MITMPROXY_VERSION):
        return GF.profile_problems(GF.sample_profile(options, version), body_size_limit="1m",
                                   expected_target=("127.0.0.1", 9000))

    def test_required_profile(self):
        self.assertEqual(self.problems(good_options()), ())

    def test_each_option_matters(self):
        for name, value in GF.REQUIRED_OPTIONS.items():
            changed = (["x"] if isinstance(value, list) else "x" if value is None
                       else "eager" if value == "lazy" else 1 if name == "flow_detail" else not value)
            with self.subTest(option=name):
                self.assertIn(f"option:{name}", self.problems(good_options(**{name: changed})))

    def test_missing_option_never_matches(self):
        options = good_options()
        del options.http2
        self.assertIn("option:http2", self.problems(options))

    def test_other_version(self):
        self.assertEqual(self.problems(good_options(), "12.2.4"), ("mitmproxy_version",))

    def test_other_destination_or_scheme(self):
        self.assertIn("option:mode", self.problems(good_options(mode=["reverse:http://127.0.0.1:9001"])))
        self.assertIn("option:mode", self.problems(good_options(mode=["reverse:https://127.0.0.1:9000"])))
        self.assertIn("option:mode", self.problems(good_options(mode=["regular"])))

    def test_other_body_limit(self):
        self.assertEqual(self.problems(good_options(body_size_limit="2m")),
                         ("option:body_size_limit",))

    def test_change_and_change_back_is_two_generations(self):
        generation = fe.RelevantProfileGeneration()
        a = GF.sample_profile(good_options(), "v")
        b = GF.sample_profile(good_options(http2=True), "v")
        self.assertEqual([generation.observe(p) for p in (a, b, a)], [0, 1, 2])

    def test_launch_options_cover_the_scalars(self):
        options = GF.launch_options(body_size_limit="1m")
        self.assertEqual(options["connection_strategy"], "lazy")
        self.assertEqual(options["http2"], "false")
        self.assertEqual(options["validate_inbound_headers"], "true")
        self.assertEqual(options["body_size_limit"], "1m")
        self.assertEqual(options["flow_detail"], "0")


class TicketBookTests(unittest.TestCase):
    def setUp(self):
        self.now = 0.0
        self.book = GF.TicketBook(2, 10.0, clock=lambda: self.now)

    def test_single_use(self):
        self.assertTrue(self.book.issue("h", "c1", 0))
        self.assertEqual(self.book.redeem("h").correlation_id, "c1")
        self.assertIsNone(self.book.redeem("h"))

    def test_identical_messages_are_separate_tickets_in_order(self):
        self.book.issue("h", "c1", 0)
        self.book.issue("h", "c2", 0)
        self.assertEqual([self.book.redeem("h").correlation_id for _ in range(2)], ["c1", "c2"])

    def test_bounded(self):
        self.book.issue("a", "c1", 0)
        self.book.issue("b", "c2", 0)
        self.assertFalse(self.book.issue("c", "c3", 0))

    def test_expiry(self):
        self.book.issue("h", "c1", 0)
        self.now = 11.0
        self.assertIsNone(self.book.redeem("h"))
        self.assertEqual(len(self.book), 0)
        self.assertEqual(self.book.expired, 1)
        self.assertTrue(self.book.issue("h", "c2", 0))


REQUEST = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n"
RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"


class Upstream:
    """Records the bytes it receives and answers one response per read."""

    def __init__(self):
        self.received = bytearray()
        self.connections = 0

    async def serve(self, reader, writer):
        self.connections += 1
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    return
                self.received += data
                writer.write(RESPONSE)
                await writer.drain()
        finally:
            writer.close()


class GuardTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.upstream = Upstream()
        self.server = await asyncio.start_server(self.upstream.serve, "127.0.0.1", 0)
        port = self.server.sockets[0].getsockname()[1]
        self.book = GF.TicketBook(8, 30.0)
        self.events = []
        self.enforcing = True
        self.generation = 0
        self.guard = GF.EgressGuard(
            listen_port=0, upstream=("127.0.0.1", port), book=self.book,
            enforcing=lambda: self.enforcing, generation=lambda: self.generation,
            on_event=self.events.append, max_message_bytes=4096, idle_timeout_seconds=5.0)
        await self.guard.start()

    async def asyncTearDown(self):
        await self.guard.aclose()
        self.server.close()
        await self.server.wait_closed()

    def ticket(self, message=REQUEST, generation=0):
        self.assertTrue(self.book.issue(hashlib.sha256(message).hexdigest(), "cid", generation))

    async def exchange(self, *segments, close=True):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.guard.listen_port)
        for segment in segments:
            writer.write(segment)
            await writer.drain()
            await asyncio.sleep(0.01)
        if close:
            answer = await asyncio.wait_for(self._read_some(reader), 2.0)
            writer.close()
            return answer
        return reader, writer

    @staticmethod
    async def _read_some(reader):
        out = bytearray()
        try:
            while b"\r\n\r\n" not in out:
                data = await reader.read(4096)
                if not data:
                    break
                out += data
        except ConnectionError:
            pass
        return bytes(out)

    def events_of(self, kind):
        return [e for e in self.events if e["event"] == kind]

    async def test_ticketed_message_is_forwarded_exactly(self):
        self.ticket()
        answer = await self.exchange(REQUEST)
        self.assertTrue(answer.startswith(b"HTTP/1.1 200"))
        self.assertEqual(bytes(self.upstream.received), REQUEST)
        self.assertEqual(self.events_of(GF.EVENT_DELIVERED)[0]["correlation_id"], "cid")

    async def test_segmented_message_is_framed_before_forwarding(self):
        self.ticket()
        answer = await self.exchange(REQUEST[:3], REQUEST[3:10], REQUEST[10:])
        self.assertTrue(answer.startswith(b"HTTP/1.1 200"))
        self.assertEqual(bytes(self.upstream.received), REQUEST)

    async def test_no_ticket_nothing_delivered(self):
        answer = await self.exchange(REQUEST)
        self.assertTrue(answer.startswith(b"HTTP/1.1 502"))
        self.assertEqual(bytes(self.upstream.received), b"")
        self.assertEqual(self.events_of(GF.EVENT_REJECTED)[0]["reason"], GF.REJECT_UNTICKETED)

    async def test_one_byte_of_difference_is_not_delivered(self):
        self.ticket()
        answer = await self.exchange(REQUEST.replace(b"/a", b"/b"))
        self.assertTrue(answer.startswith(b"HTTP/1.1 502"))
        self.assertEqual(bytes(self.upstream.received), b"")

    async def test_ticket_is_single_use(self):
        self.ticket()
        await self.exchange(REQUEST)
        answer = await self.exchange(REQUEST)
        self.assertTrue(answer.startswith(b"HTTP/1.1 502"))
        self.assertEqual(bytes(self.upstream.received), REQUEST)

    async def test_smuggled_second_message_is_not_delivered(self):
        smuggled = b"GET /admin HTTP/1.1\r\nHost: h\r\n\r\n"
        self.ticket()
        reader, writer = await self.exchange(REQUEST + smuggled, close=False)
        await asyncio.sleep(0.05)
        writer.close()
        self.assertEqual(bytes(self.upstream.received), REQUEST)
        self.assertEqual(self.events_of(GF.EVENT_REJECTED)[0]["reason"], GF.REJECT_UNTICKETED)

    async def test_two_ticketed_messages_on_one_connection(self):
        second = b"GET /b HTTP/1.1\r\nHost: h\r\n\r\n"
        self.ticket()
        self.ticket(second)
        reader, writer = await self.exchange(REQUEST, close=False)
        await asyncio.sleep(0.02)
        writer.write(second)
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.close()
        self.assertEqual(bytes(self.upstream.received), REQUEST + second)
        self.assertEqual(self.upstream.connections, 1)

    async def test_ambiguous_framing_is_refused(self):
        bad = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab"
        self.ticket(bad)
        answer = await self.exchange(bad)
        self.assertTrue(answer.startswith(b"HTTP/1.1 502"))
        self.assertEqual(bytes(self.upstream.received), b"")
        self.assertTrue(self.events_of(GF.EVENT_REJECTED)[0]["reason"].startswith(GF.REJECT_WIRE))

    async def test_oversize_is_refused(self):
        big = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 9999\r\n\r\n" + b"a" * 5000
        answer = await self.exchange(big)
        self.assertTrue(answer.startswith(b"HTTP/1.1 502"))
        self.assertEqual(self.events_of(GF.EVENT_REJECTED)[0]["reason"], GF.REJECT_TOO_LARGE)

    async def test_truncated_message_is_not_delivered(self):
        reader, writer = await self.exchange(REQUEST[:10], close=False)
        writer.close()
        await asyncio.sleep(0.05)
        self.assertEqual(bytes(self.upstream.received), b"")
        self.assertEqual(self.events_of(GF.EVENT_REJECTED)[0]["reason"], GF.REJECT_TRUNCATED)

    async def test_profile_change_after_the_decision_voids_the_ticket(self):
        self.ticket(generation=0)
        self.generation = 1
        answer = await self.exchange(REQUEST)
        self.assertTrue(answer.startswith(b"HTTP/1.1 502"))
        self.assertEqual(bytes(self.upstream.received), b"")
        self.assertEqual(self.events_of(GF.EVENT_REJECTED)[0]["reason"], GF.REJECT_STALE_PROFILE)

    async def test_upstream_unreachable_is_recorded_and_nothing_is_claimed(self):
        self.guard.upstream = ("127.0.0.1", 1)
        self.ticket()
        await self.exchange(REQUEST)
        self.assertEqual(self.events_of(GF.EVENT_REJECTED)[-1]["reason"], "upstream_unreachable")
        self.assertEqual(self.events_of(GF.EVENT_DELIVERED), [])

    async def test_v4_authority_forwards_everything_and_records(self):
        self.enforcing = False
        answer = await self.exchange(REQUEST)
        self.assertTrue(answer.startswith(b"HTTP/1.1 200"))
        self.assertEqual(bytes(self.upstream.received), REQUEST)
        self.assertEqual(self.events_of(GF.EVENT_PASSTHROUGH)[0]["reason"], GF.REJECT_UNTICKETED)

    async def test_v4_authority_does_not_stop_on_what_the_parser_refuses(self):
        self.enforcing = False
        bad = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab"
        answer = await self.exchange(bad)
        self.assertTrue(answer.startswith(b"HTTP/1.1 200"))
        self.assertEqual(bytes(self.upstream.received), bad)

    async def test_a_broken_event_sink_does_not_decide_delivery(self):
        def broken(event):
            raise RuntimeError("sink")

        self.guard._on_event = broken
        self.ticket()
        with self.assertLogs("firewall.data_plane.framing", level="ERROR"):
            answer = await self.exchange(REQUEST)
        self.assertTrue(answer.startswith(b"HTTP/1.1 200"))


if __name__ == "__main__":
    unittest.main()
