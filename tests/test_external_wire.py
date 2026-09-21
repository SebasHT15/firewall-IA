"""External Test v1 — wire-format conversion tests (scripts/external/wire.py).

Pure standard library: no mitmproxy, no model, no services. Runs in the ML environment.

What matters here is that turning a frozen classifier representation into wire bytes
changes NOTHING except the request target. If any header were added, dropped, reordered or
rewritten, V4 would be scored on text other than the text that was labelled.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "scripts", "external"))

import wire  # noqa: E402

GET = ("GET /products?category=office&page=2 HTTP/1.1\n"
       "Host: shop.fwlab.test:9100\n"
       "User-Agent: Mozilla/5.0 (X11; Linux x86_64)\n"
       "Accept: text/html")

POST = ("POST /api/orders HTTP/1.1\n"
        "Host: api.fwlab.test:9100\n"
        "Content-Type: application/json\n"
        "Content-Length: 27\n"
        "\n"
        '{"product_id": 1, "qty": 2}')


class TestParseRendered(unittest.TestCase):
    def test_parses_request_line_and_headers_in_order(self):
        method, target, version, headers, body = wire.parse_rendered(GET)
        self.assertEqual((method, target, version), ("GET", "/products?category=office&page=2", "HTTP/1.1"))
        self.assertEqual([h[0] for h in headers], ["Host", "User-Agent", "Accept"])
        self.assertIsNone(body)

    def test_body_is_split_on_the_first_blank_line(self):
        *_, body = wire.parse_rendered(POST)
        self.assertEqual(body, '{"product_id": 1, "qty": 2}')

    def test_body_may_contain_blank_lines(self):
        text = "POST /x HTTP/1.1\nHost: h\nContent-Length: 6\n\na\n\nb\n"
        *_, body = wire.parse_rendered(text)
        self.assertEqual(body, "a\n\nb\n")

    def test_repeated_headers_are_preserved(self):
        text = "GET /x HTTP/1.1\nHost: h\nCookie: a=1\nCookie: b=2\n"
        *_, headers, _ = wire.parse_rendered(text)
        self.assertEqual(headers.count(("Cookie", "a=1")), 1)
        self.assertEqual(headers.count(("Cookie", "b=2")), 1)

    def test_empty_header_value_is_kept(self):
        text = "GET /x HTTP/1.1\nHost: h\nX-Empty: \n"
        *_, headers, _ = wire.parse_rendered(text)
        self.assertIn(("X-Empty", ""), headers)

    def test_rejects_malformed_request_line(self):
        with self.assertRaises(wire.WireError):
            wire.parse_rendered("NONSENSE\nHost: h\n")


class TestToWire(unittest.TestCase):
    def test_target_becomes_absolute_form(self):
        first = wire.to_wire(GET).split(b"\r\n", 1)[0]
        self.assertEqual(
            first,
            b"GET http://shop.fwlab.test:9100/products?category=office&page=2 HTTP/1.1")

    def test_line_endings_are_crlf_and_headers_are_untouched(self):
        out = wire.to_wire(GET)
        self.assertIn(b"\r\nHost: shop.fwlab.test:9100\r\n", out)
        self.assertIn(b"\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\n", out)
        self.assertTrue(out.endswith(b"\r\n\r\n"))
        self.assertNotIn(b"\n\n", out.replace(b"\r\n", b"\n")[:-2])

    def test_no_header_is_added_removed_or_reordered(self):
        out = wire.to_wire(GET).decode()
        names = [l.split(":")[0] for l in out.split("\r\n")[1:] if l]
        self.assertEqual(names, ["Host", "User-Agent", "Accept"])

    def test_body_is_appended_verbatim_after_a_blank_line(self):
        out = wire.to_wire(POST)
        self.assertTrue(out.endswith(b'\r\n\r\n{"product_id": 1, "qty": 2}'))

    def test_absolute_form_target_is_left_alone(self):
        text = "GET http://shop.fwlab.test:9100/x HTTP/1.1\nHost: shop.fwlab.test:9100\n"
        self.assertTrue(wire.to_wire(text).startswith(b"GET http://shop.fwlab.test:9100/x "))

    def test_origin_form_without_host_is_an_error(self):
        with self.assertRaises(wire.WireError):
            wire.to_wire("GET /x HTTP/1.1\nAccept: */*\n")


class TestStrictFraming(unittest.TestCase):
    """A frozen case whose framing is inconsistent must fail loudly, before freeze.

    Rewriting Content-Length at replay time would desynchronise the frozen text from the
    bytes sent, and V4 would be scored on something other than what was labelled.
    """

    def test_content_length_mismatch_is_rejected(self):
        bad = POST.replace("Content-Length: 27", "Content-Length: 99")
        with self.assertRaises(wire.WireError) as ctx:
            wire.to_wire(bad)
        self.assertIn("Content-Length", str(ctx.exception))

    def test_matching_content_length_is_accepted(self):
        self.assertIn(b"Content-Length: 27", wire.to_wire(POST))

    def test_transfer_encoding_is_out_of_scope(self):
        text = "POST /x HTTP/1.1\nHost: h\nTransfer-Encoding: chunked\n\nx"
        with self.assertRaises(wire.WireError):
            wire.to_wire(text)

    def test_non_strict_skips_the_framing_checks(self):
        bad = POST.replace("Content-Length: 27", "Content-Length: 99")
        self.assertIn(b"Content-Length: 99", wire.to_wire(bad, strict=False))


class TestCanonicalForm(unittest.TestCase):
    """A frozen case must be stored exactly as render_request() would produce it.

    Otherwise its SHA-256 describes text the classifier will never be handed, and every
    such case fails the fidelity comparison after it is too late to change anything.
    """

    def test_canonical_bodyless_request_is_accepted(self):
        wire.assert_canonical("GET /x HTTP/1.1\nHost: h\nAccept: */*")

    def test_canonical_request_with_body_is_accepted(self):
        wire.assert_canonical("POST /x HTTP/1.1\nHost: h\nContent-Length: 1\n\nz")

    def test_trailing_newline_on_a_bodyless_request_is_rejected(self):
        with self.assertRaises(wire.WireError):
            wire.assert_canonical("GET /x HTTP/1.1\nHost: h\nAccept: */*\n")

    def test_crlf_endings_are_rejected(self):
        with self.assertRaises(wire.WireError):
            wire.assert_canonical("GET /x HTTP/1.1\r\nHost: h")

    def test_blank_line_with_no_body_is_rejected(self):
        with self.assertRaises(wire.WireError):
            wire.assert_canonical("GET /x HTTP/1.1\nHost: h\n\n")


class TestSha256(unittest.TestCase):
    def test_hash_is_over_the_classifier_representation(self):
        import hashlib
        self.assertEqual(wire.sha256_text(GET),
                         hashlib.sha256(GET.encode("utf-8")).hexdigest())

    def test_hash_changes_when_a_single_header_changes(self):
        other = GET.replace("Accept: text/html", "Accept: */*")
        self.assertNotEqual(wire.sha256_text(GET), wire.sha256_text(other))


if __name__ == "__main__":
    unittest.main()
