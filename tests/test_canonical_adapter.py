"""Unit tests for the canonical observation adapter (data_plane/canonical_adapter.py).

The adapter copies the RAW received parts of a mitmproxy request into an immutable snapshot and,
for an admitted snapshot, hands them to the ONE canonical_request.canonicalize. These tests pin the
mapping fidelity and the scope markers; they do NOT run the gateway or a worker.

Needs the data plane environment (mitmproxy):
    .venv-dataplane/bin/python -m unittest tests.test_canonical_adapter -v
"""
import gzip
import os
import sys
import unittest
from types import SimpleNamespace

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "data_plane"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from mitmproxy import http
    from mitmproxy.test import tutils
except ImportError as exc:  # pragma: no cover
    raise unittest.SkipTest(f"needs the data plane environment (.venv-dataplane): {exc}")

import canonical_adapter as adapter
import canonical_request as cr
import request_features as rf


def req(method=b"GET", path=b"/search?q=laptop", authority=b"", http_version=b"HTTP/1.1",
        headers=None, content=b""):
    """A mitmproxy request with EXACTLY these header fields (treq would otherwise add some)."""
    if headers is None:
        headers = [(b"Host", b"shop.example")]
    return tutils.treq(method=method, path=path, authority=authority, http_version=http_version,
                       headers=http.Headers(headers), content=content)


class TestTargetFormMapping(unittest.TestCase):
    def test_origin_form_target_is_copied_byte_for_byte(self):
        r = req(method=b"GET", path=b"/a/b?x=%2F&y=1", authority=b"")
        snap = adapter.build_snapshot(r, 7)
        self.assertEqual(snap.form, adapter.FORM_ORIGIN)
        self.assertTrue(snap.in_scope)
        self.assertIsNone(snap.scope_reason)
        self.assertEqual(snap.target, b"/a/b?x=%2F&y=1")   # exact bytes, no decoding/normalization
        self.assertEqual(snap.method, b"GET")
        self.assertEqual(snap.snapshot_id, 7)

    def test_asterisk_form_is_in_scope_and_exact(self):
        r = req(method=b"OPTIONS", path=b"*", authority=b"")
        snap = adapter.build_snapshot(r, 1)
        self.assertEqual(snap.form, adapter.FORM_ASTERISK)
        self.assertTrue(snap.in_scope)
        self.assertEqual(snap.target, b"*")

    def test_absolute_form_is_out_of_scope_and_not_reconstructed(self):
        # mitmproxy splits the authority out of data.path and lowercases the scheme; the adapter
        # refuses to reconstruct wire facts, so it is out of scope with target = None.
        r = req(method=b"GET", path=b"/a", authority=b"example.com:80")
        self.assertEqual(r.first_line_format, "absolute")
        snap = adapter.build_snapshot(r, 1)
        self.assertEqual(snap.form, adapter.FORM_ABSOLUTE)
        self.assertFalse(snap.in_scope)
        self.assertEqual(snap.scope_reason, adapter.SCOPE_ABSOLUTE)
        self.assertIsNone(snap.target)

    def test_authority_form_connect_is_marked(self):
        r = req(method=b"CONNECT", path=b"", authority=b"example.com:443")
        self.assertEqual(r.first_line_format, "authority")
        snap = adapter.build_snapshot(r, 1)
        self.assertEqual(snap.form, adapter.FORM_AUTHORITY)
        self.assertFalse(snap.in_scope)
        self.assertEqual(snap.scope_reason, adapter.SCOPE_CONNECT)
        self.assertIsNone(snap.target)


class TestHttpVersionScope(unittest.TestCase):
    def test_http_1_0_is_in_scope(self):
        snap = adapter.build_snapshot(req(http_version=b"HTTP/1.0"), 1)
        self.assertTrue(snap.version_supported)
        self.assertTrue(snap.in_scope)
        self.assertEqual(snap.http_version, "HTTP/1.0")

    def test_http_2_0_is_unsupported_marker(self):
        snap = adapter.build_snapshot(req(http_version=b"HTTP/2.0"), 1)
        self.assertFalse(snap.version_supported)
        self.assertFalse(snap.in_scope)
        self.assertEqual(snap.scope_reason, adapter.SCOPE_UNSUPPORTED_VERSION)


class TestBodyAvailability(unittest.TestCase):
    def test_none_body_and_empty_body_are_distinct(self):
        none_body = adapter.build_snapshot(req(content=None), 1)
        self.assertIsNone(none_body.body)
        self.assertFalse(none_body.body_available)   # missing/streamed

        empty_body = adapter.build_snapshot(req(content=b""), 2)
        self.assertEqual(empty_body.body, b"")        # present but empty
        self.assertTrue(empty_body.body_available)

    def test_raw_content_is_passed_still_content_coded_not_decoded(self):
        coded = gzip.compress(b"hello=world")
        r = req(method=b"POST", path=b"/x",
                headers=[(b"Content-Encoding", b"gzip"), (b"Content-Type", b"text/plain")],
                content=coded)
        snap = adapter.build_snapshot(r, 1)
        # The adapter passes the STILL-CODED bytes, not what get_content() would decode them to.
        self.assertEqual(snap.body, coded)
        self.assertEqual(r.get_content(strict=False), b"hello=world")
        self.assertNotEqual(snap.body, b"hello=world")


class TestHeaderFidelity(unittest.TestCase):
    def test_order_case_and_repeats_are_preserved(self):
        fields = [(b"Host", b"h"), (b"X-A", b"1"), (b"x-a", b"2"), (b"USER-AGENT", b"curl/8")]
        snap = adapter.build_snapshot(req(headers=fields), 1)
        self.assertEqual(snap.headers, tuple((bytes(n), bytes(v)) for n, v in fields))


class TestConversionAndLimits(unittest.TestCase):
    def test_admitted_snapshot_converts_to_requestparts(self):
        r = req(method=b"POST", path=b"/x",
                headers=[(b"Content-Type", b"application/json")], content=b"{}")
        snap = adapter.build_snapshot(r, 1)
        parts = adapter.snapshot_to_parts(snap)
        self.assertIsInstance(parts, cr.RequestParts)
        self.assertEqual(parts.method, b"POST")
        self.assertEqual(parts.target, b"/x")
        self.assertEqual(parts.body, b"{}")
        self.assertEqual(parts.headers, ((b"Content-Type", b"application/json"),))

    def test_conversion_refuses_out_of_scope_and_missing_body(self):
        oos = adapter.build_snapshot(req(authority=b"example.com:80"), 1)
        with self.assertRaises(ValueError):
            adapter.snapshot_to_parts(oos)
        missing = adapter.build_snapshot(req(content=None), 2)
        with self.assertRaises(ValueError):
            adapter.snapshot_to_parts(missing)

    def test_make_limits_supplies_no_token_budget(self):
        lim = adapter.make_limits(1000)
        self.assertEqual(lim.max_decoded_body, 1000)
        self.assertIsNone(lim.token_budget)        # size UNCHECKED: a valid lab setting
        self.assertIsNone(lim.max_bytes_per_token)
        self.assertIsNone(lim.count_tokens)

    def test_requestparts_type_contract_is_guarded(self):
        # The adapter always passes bytes; the contract itself rejects anything else, so a wrong
        # type can never pass silently.
        with self.assertRaises(TypeError):
            cr.RequestParts(method="GET", target=b"/")        # str method
        with self.assertRaises(TypeError):
            cr.RequestParts(method=b"GET", target="/")        # str target


class TestAdmitRawEarlyExit(unittest.TestCase):
    """admit_raw scans req.headers.fields with early exit and never materializes the header tuple."""

    def test_header_scan_stops_as_soon_as_the_count_cap_is_exceeded(self):
        consumed = [0]

        class Hdr:
            @property
            def fields(self):
                for i in range(1000):      # a generator, so we can see how many were consumed
                    consumed[0] += 1
                    yield (b"h%d" % i, b"v")

        fake = SimpleNamespace(
            data=SimpleNamespace(method=b"GET", path=b"/x"),
            http_version="HTTP/1.1", first_line_format="relative", raw_content=b"",
            headers=Hdr())
        caps = SimpleNamespace(max_method_bytes=32, max_target_bytes=1024, max_body_bytes=1024,
                               max_header_count=3, max_header_bytes=10 ** 9)
        info = adapter.classify_raw(fake)
        self.assertTrue(info.in_scope)
        token = adapter.admit_raw(fake, caps, info)
        self.assertEqual(token, "too_many_headers")
        self.assertLessEqual(consumed[0], 4)   # stopped right after exceeding the cap, not all 1000

    def test_header_bytes_cap_also_early_exits(self):
        consumed = [0]

        class Hdr:
            @property
            def fields(self):
                for i in range(1000):
                    consumed[0] += 1
                    yield (b"name", b"x" * 100)

        fake = SimpleNamespace(
            data=SimpleNamespace(method=b"GET", path=b"/x"),
            http_version="HTTP/1.1", first_line_format="relative", raw_content=b"",
            headers=Hdr())
        caps = SimpleNamespace(max_method_bytes=32, max_target_bytes=1024, max_body_bytes=1024,
                               max_header_count=10 ** 9, max_header_bytes=250)
        info = adapter.classify_raw(fake)
        self.assertEqual(adapter.admit_raw(fake, caps, info), "header_bytes_exceeded")
        self.assertLessEqual(consumed[0], 4)


class TestRepresentationRegression(unittest.TestCase):
    def test_feature_schema_does_not_distinguish_d1_from_canonical_text(self):
        # The frozen Analyzer was fitted on request-features/v2 extracted from V4 D1 text. The
        # feature extractor stamps the SAME schema id for a canonical-request/v1 text, so the
        # schema id is NOT a guard against mixing the two representations. Therefore the observer
        # path MUST NEVER feed canonical text to the frozen Analyzer; keeping the canonical
        # observation on its own worker (which never touches the Analyzer) is the real safeguard,
        # not any schema check. This assertion documents that the schema cannot be relied on.
        d1_text = "GET /search?q=laptop HTTP/1.1\nHost: shop.example\nUser-Agent: curl/8"
        canonical_text = ("POST /x HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n"
                          "\npage=2&sort=price")
        self.assertEqual(rf.FEATURE_SCHEMA_VERSION, "request-features/v2")
        self.assertEqual(rf.extract_features(d1_text).schema_version, "request-features/v2")
        self.assertEqual(rf.extract_features(canonical_text).schema_version, "request-features/v2")


if __name__ == "__main__":
    unittest.main()
