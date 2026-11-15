"""Tests for the strict HTTP/1.1 wire parser (`data_plane/http1_wire.py`)."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "data_plane"))

import http1_wire as W  # noqa: E402
import fast_path as fp  # noqa: E402
import cascade_runtime as RT  # noqa: E402


class WireParseTests(unittest.TestCase):
    def test_simple_get_framing_verified(self):
        buf = b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n"
        w = W.parse_request(buf)
        self.assertEqual(w.parts.method, b"GET")
        self.assertEqual(w.parts.target, b"/index.html")
        self.assertEqual(w.body_framing, "none")
        self.assertEqual(w.framing.status, fp.FRAMING_VERIFIED)
        self.assertEqual(w.consumed, len(buf))
        self.assertEqual(w.leftover, b"")

    def test_get_with_query(self):
        buf = b"GET /p?id=5&q=a HTTP/1.1\r\nHost: x\r\n\r\n"
        w = W.parse_request(buf)
        self.assertEqual(w.parts.target, b"/p?id=5&q=a")

    def test_post_content_length(self):
        body = b'{"a":1}'
        buf = (b"POST /api HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
               b"Content-Length: %d\r\n\r\n" % len(body)) + body
        w = W.parse_request(buf)
        self.assertEqual(w.body_framing, "content-length")
        self.assertEqual(w.parts.body, body)
        self.assertEqual(w.framing.status, fp.FRAMING_VERIFIED)

    def test_chunked_dechunked(self):
        buf = (b"POST /u HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
               b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n")
        w = W.parse_request(buf)
        self.assertEqual(w.body_framing, "chunked")
        self.assertEqual(w.parts.body, b"Wikipedia")
        self.assertEqual(w.framing.status, fp.FRAMING_VERIFIED)

    def test_te_and_cl_rejected(self):
        buf = (b"POST /u HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
               b"Content-Length: 5\r\n\r\n0\r\n\r\n")
        with self.assertRaises(W.WireError) as cm:
            W.parse_request(buf)
        self.assertEqual(cm.exception.reason, "framing-te-and-cl")

    def test_duplicate_cl_rejected(self):
        buf = b"POST /u HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nxx"
        with self.assertRaises(W.WireError) as cm:
            W.parse_request(buf)
        self.assertEqual(cm.exception.reason, "framing-duplicate-cl")

    def test_non_chunked_te_rejected(self):
        buf = b"POST /u HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n"
        with self.assertRaises(W.WireError):
            W.parse_request(buf)

    def test_obsolete_folding_rejected(self):
        buf = b"GET / HTTP/1.1\r\nHost: x\r\nX-Y: a\r\n b\r\n\r\n"
        with self.assertRaises(W.WireError) as cm:
            W.parse_request(buf)
        self.assertEqual(cm.exception.reason, "obsolete-line-folding")

    def test_body_short_rejected(self):
        buf = b"POST /u HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nshort"
        with self.assertRaises(W.WireError) as cm:
            W.parse_request(buf)
        self.assertEqual(cm.exception.reason, "body-short")

    def test_bad_method_token(self):
        buf = b"GE T / HTTP/1.1\r\nHost: x\r\n\r\n"
        with self.assertRaises(W.WireError):
            W.parse_request(buf)

    def test_chunked_with_valid_trailer_accepted(self):
        buf = (b"POST /u HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
               b"4\r\nWiki\r\n0\r\nX-Checksum: abc123\r\n\r\n")
        w = W.parse_request(buf)
        self.assertEqual(w.parts.body, b"Wiki")
        self.assertEqual(w.body_framing, "chunked")
        self.assertEqual(w.consumed, len(buf))

    def test_chunked_malformed_trailer_rejected(self):
        # A trailer line that is not a valid field ("not-a-header") is a framing
        # FAILURE, not an accepted VERIFIED parse.
        buf = (b"POST /u HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
               b"4\r\nWiki\r\n0\r\nnot-a-header\r\n\r\n")
        with self.assertRaises(W.WireError) as cm:
            W.parse_request(buf)
        self.assertEqual(cm.exception.reason, "header-without-colon")

    def test_chunked_trailer_bad_name_rejected(self):
        buf = (b"POST /u HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
               b"0\r\nbad name: v\r\n\r\n")
        with self.assertRaises(W.WireError) as cm:
            W.parse_request(buf)
        self.assertEqual(cm.exception.reason, "bad-header-name")

    def test_http10_evidence_declares_actual_version(self):
        # HTTP/1.0 is admitted but the VERIFIED evidence must NOT claim it is 1.1.
        buf = b"GET / HTTP/1.0\r\nHost: x\r\n\r\n"
        w = W.parse_request(buf)
        self.assertEqual(w.parts.http_version, "HTTP/1.0")
        self.assertEqual(w.framing.status, fp.FRAMING_VERIFIED)
        self.assertIn("HTTP/1.0", w.framing.detail)
        self.assertNotIn("HTTP/1.1", w.framing.detail)

    def test_http11_evidence_declares_11(self):
        buf = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        w = W.parse_request(buf)
        self.assertIn("HTTP/1.1", w.framing.detail)

    def test_unsupported_version_rejected(self):
        buf = b"GET / HTTP/2.0\r\nHost: x\r\n\r\n"
        with self.assertRaises(W.WireError) as cm:
            W.parse_request(buf)
        self.assertEqual(cm.exception.reason, "unsupported-http-version")

    def test_pipelined_leftover_preserved(self):
        buf = b"GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n"
        w = W.parse_request(buf)
        self.assertEqual(w.parts.target, b"/a")
        self.assertTrue(w.leftover.startswith(b"GET /b"))

    def test_snapshot_canonicalizes_accept(self):
        buf = b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n"
        w = W.parse_request(buf)
        limits = RT.v5_limits(415)
        snap = RT.build_snapshot(w.parts, w.framing, limits, correlation_id="c1")
        self.assertEqual(snap.canonical.outcome, "ACCEPT")
        self.assertTrue(snap.canonical.text.startswith("GET /index.html HTTP/1.1"))
        self.assertEqual(snap.framing.status, fp.FRAMING_VERIFIED)

    def test_fast_path_input_built_from_snapshot(self):
        buf = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        w = W.parse_request(buf)
        snap = RT.build_snapshot(w.parts, w.framing, RT.v5_limits(415))
        fpi = RT.make_fast_path_input(snap)
        self.assertEqual(fpi.method, b"GET")
        self.assertEqual(fpi.framing.status, fp.FRAMING_VERIFIED)


if __name__ == "__main__":
    unittest.main()
