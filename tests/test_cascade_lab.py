"""Real-socket enforcement tests for the cascade lab (`scripts/cascade_lab/lab_server.py`).

Doubles for Model 2 and V5, but REAL TCP transport, real wire parsing, real
canonicalization and a real controlled upstream. Verifies L2 enforcement: a
FORWARD actually reaches the upstream and a DENY/ malformed request does not.
"""
import os
import socket
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "data_plane"))
sys.path.insert(0, os.path.join(REPO, "scripts", "cascade_lab"))

import cascade as C          # noqa: E402
import cascade_runtime as RT  # noqa: E402
import fast_path as fp        # noqa: E402
import lab_server as L        # noqa: E402


class FakeM2:
    def __init__(self, decision):
        self.decision = decision
        self.status = "OK"
        self.p_block = 0.5
        self.threshold = 0.9
        self.feature_view = "baseline_34"
        self.model_artifact_sha256 = "0" * 64
        self.policy_id = self.policy_sha256 = self.policy_status = None


def make_router(m2_decision="DEFER", v5_decision="ALLOW"):
    def m2(canonical_outcome, canonical_text):
        # block when the path contains "attack"
        if canonical_text and "attack" in canonical_text:
            return FakeM2("BLOCK")
        return FakeM2(m2_decision)

    def v5(canonical_text):
        dec = "BLOCK" if (canonical_text and "evil" in canonical_text) else v5_decision
        return C.V5Reply(status="ok", decision=dec)

    return C.CascadeRouter(C.CascadeConfig(mode=C.CASCADE_ACTIVE),
                           fast_path_evaluate=fp.safe_evaluate, model2_decide=m2,
                           v5_classify=v5, make_fast_path_input=RT.make_fast_path_input)


import time  # noqa: E402


def send(host, port, raw: bytes) -> bytes:
    with socket.create_connection((host, port), timeout=5) as s:
        s.sendall(raw)
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        return resp


def send_segmented(host, port, parts, gap=0.05) -> bytes:
    """Send `parts` with a small gap between each so the server reads them in
    separate recv() calls, then read the full response."""
    with socket.create_connection((host, port), timeout=5) as s:
        for i, p in enumerate(parts):
            if i:
                time.sleep(gap)
            s.sendall(p)
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        return resp


def read_length_respecting(host, port, raw: bytes):
    """A client that reads the response head, then EXACTLY Content-Length body
    bytes. Returns (declared_cl, body, leftover_after_body)."""
    with socket.create_connection((host, port), timeout=5) as s:
        s.sendall(raw)
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        cl = None
        for line in head.split(b"\r\n")[1:]:
            if line.lower().startswith(b"content-length:"):
                cl = int(line.partition(b":")[2].strip())
        body = rest
        while cl is not None and len(body) < cl:
            chunk = s.recv(4096)
            if not chunk:
                break
            body += chunk
        leftover = body[cl:] if cl is not None else b""
        return cl, body[:cl] if cl is not None else body, leftover


class LabEnforcementTests(unittest.TestCase):
    def setUp(self):
        self.logs = []
        self.sink = L.UpstreamSink()
        self.sink.start()
        self.gw = L.CascadeGateway(
            make_router(), L.GatewayConfig(upstream_addr=(self.sink.host, self.sink.port),
                                           log_sink=self.logs.append))
        self.gw.start()

    def tearDown(self):
        self.gw.stop()
        self.sink.stop()

    def test_benign_forwarded_to_upstream(self):
        resp = send(self.gw.host, self.gw.port,
                    b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertIn(b"200 OK", resp)
        self.assertEqual(len(self.sink.received()), 1)
        self.assertEqual(self.logs[-1]["applied"], "FORWARD")
        self.assertEqual(self.logs[-1]["deciding_stage"], "v5")
        self.assertTrue(self.logs[-1]["upstream_received"])

    def test_model2_block_not_forwarded(self):
        resp = send(self.gw.host, self.gw.port,
                    b"GET /attack?x=1 HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertIn(b"403", resp)
        self.assertEqual(len(self.sink.received()), 0)
        self.assertEqual(self.logs[-1]["deciding_stage"], "model2")
        self.assertFalse(self.logs[-1]["upstream_received"])

    def test_v5_block_not_forwarded(self):
        resp = send(self.gw.host, self.gw.port,
                    b"GET /evil?x=1 HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertIn(b"403", resp)
        self.assertEqual(len(self.sink.received()), 0)
        self.assertEqual(self.logs[-1]["deciding_stage"], "v5")
        self.assertEqual(self.logs[-1]["v5"]["decision"], "BLOCK")

    def test_malformed_framing_denied_as_protocol(self):
        raw = (b"POST /u HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
               b"Content-Length: 5\r\n\r\n0\r\n\r\n")
        resp = send(self.gw.host, self.gw.port, raw)
        self.assertIn(b"400", resp)
        self.assertEqual(len(self.sink.received()), 0)
        self.assertEqual(self.logs[-1]["deciding_stage"], "wire")
        self.assertEqual(self.logs[-1]["reason"], "wire_framing-te-and-cl")

    def test_post_body_forwarded_intact(self):
        body = b'{"ok":1}'
        raw = (b"POST /api HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
               b"Content-Length: %d\r\n\r\n" % len(body)) + body
        resp = send(self.gw.host, self.gw.port, raw)
        self.assertIn(b"200 OK", resp)
        recs = self.sink.received()
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].body_len, len(body))

    def test_segmented_chunk_body_containing_terminator_read_whole(self):
        # The chunk DATA contains the chunked terminator bytes (\r\n0\r\n\r\n). A
        # substring-search reader stops early; the parser-driven reader must read
        # the whole message by chunk size even when it arrives in segments.
        data = b"AAAA\r\n0\r\n\r\nBBBB"          # 15 bytes, embeds the terminator
        self.assertEqual(len(data), 15)
        head = (b"POST /api HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
        p1 = head + b"f\r\n" + b"AAAA\r\n0\r\n\r\n"    # 0xf chunk; ends after embedded terminator
        p2 = b"BBBB\r\n0\r\n\r\n"                        # rest of chunk + real terminator
        resp = send_segmented(self.gw.host, self.gw.port, [p1, p2])
        self.assertIn(b"200 OK", resp)
        recs = self.sink.received()
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].body_len, len(data))   # full 15-byte body, not 4
        self.assertTrue(self.logs[-1]["upstream_received"])

    def test_deny_response_is_length_respecting(self):
        # A DENY reaches a length-respecting client with a Content-Length that
        # matches the body exactly (no truncation, no trailing bytes).
        cl, body, leftover = read_length_respecting(
            self.gw.host, self.gw.port, b"GET /evil?x=1 HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertEqual(cl, len(body))
        self.assertEqual(body, b"Request blocked by firewall-IA lab.")
        self.assertEqual(leftover, b"")


class ResponseFramingTests(unittest.TestCase):
    """The lab's canned responses declare a Content-Length equal to their body."""

    def _check(self, resp: bytes):
        head, _, body = resp.partition(b"\r\n\r\n")
        cl = next(int(l.partition(b":")[2].strip())
                  for l in head.split(b"\r\n") if l.lower().startswith(b"content-length:"))
        self.assertEqual(cl, len(body), resp)

    def test_deny_response_length(self):
        self._check(L.DENY_RESPONSE)

    def test_protocol_response_length(self):
        self._check(L.PROTOCOL_RESPONSE)

    def test_ok_response_length(self):
        self._check(L.OK_RESPONSE)


class NetworkSegmentationTests(unittest.TestCase):
    def test_valid_chunked_request_at_every_two_segment_boundary(self):
        wire = (b"POST / HTTP/1.1\r\nHost: lab.local\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n0\r\n\r\n")
        class Segments:
            def __init__(self, chunks):
                self.chunks = iter(chunks)
            def recv(self, _):
                return next(self.chunks, b"")
        for cut in range(1, len(wire)):
            with self.subTest(cut=cut):
                actual = L._read_one_request(Segments([wire[:cut], wire[cut:]]))
                self.assertEqual(actual, wire)
                self.assertEqual(L.W.parse_request(actual).parts.body, b"Wiki")

    def test_incomplete_terminator_differs_from_bad_terminator(self):
        head = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki"
        for tail in (b"", b"\r"):
            with self.assertRaisesRegex(L.W.WireError, "chunk-data-terminator-incomplete"):
                L.W.parse_request(head + tail)
        for tail in (b"x", b"\nx", b"\rx"):
            with self.assertRaisesRegex(L.W.WireError, "chunk-data-not-crlf-terminated"):
                L.W.parse_request(head + tail)


if __name__ == "__main__":
    unittest.main()
