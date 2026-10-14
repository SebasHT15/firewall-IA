"""Independent conformance review + adversarial tests for data_plane/canonical_request.py
(`canonical-request/v1`, V5-DATA-SPEC-r3 §2.2, §5.1-§5.6, FROZEN D62).

Written by a reviewer who did not write the module. Tests assert the SPEC, not the
implementation. The four findings of the review (R8 cap on coded bodies ×2, unknown coding
names in the audit record, media-type ReDoS) were fixed on 2026-10-13 (D63); their tests now
run as ordinary regression tests. Standard library only; br/zstd tests skip when `brotli` / `zstandard`
are missing:

    .venv-dataplane/bin/python -m unittest tests.test_canonical_request_review -v
    python3.12 -m unittest tests.test_canonical_request_review -v
"""

import gzip
import json
import os
import random
import subprocess
import sys
import unittest
import unittest.mock
import zlib

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PLANE_DIR = os.path.join(REPO_ROOT, "data_plane")
sys.path.insert(0, DATA_PLANE_DIR)

import canonical_request as cr  # noqa: E402
from canonical_request import (  # noqa: E402
    ACCEPT, REJECT, UNSUPPORTED, Limits, RequestParts, canonicalize, parse_canonical,
)

try:
    import brotli  # noqa: E402
except ImportError:  # pragma: no cover
    brotli = None
try:
    import zstandard  # noqa: E402
except ImportError:  # pragma: no cover
    zstandard = None

CAP = 1 << 20


def P(method=b"GET", target=b"/", headers=(), body=b"", ver="HTTP/1.1"):
    return RequestParts(method=method, target=target, http_version=ver,
                        headers=tuple(headers), body=body)


def L(cap=CAP, **kw):
    return Limits(max_decoded_body=cap, **kw)


def run(method=b"GET", target=b"/", headers=(), body=b"", ver="HTTP/1.1", limits=None):
    return canonicalize(P(method, target, headers, body, ver), limits or L())


def CT(v=b"text/plain"):
    return (b"Content-Type", v)


def gz(b):
    return gzip.compress(b, mtime=0)


def raw_deflate(b):
    c = zlib.compressobj(wbits=-15)
    return c.compress(b) + c.flush()


def need_br(test):
    return unittest.skipIf(brotli is None, "brotli not installed")(test)


def need_zstd(test):
    return unittest.skipIf(zstandard is None, "zstandard not installed")(test)


class Base(unittest.TestCase):
    def assertAccept(self, r, msg=None):
        self.assertEqual(r.outcome, ACCEPT, msg or repr((r.reject, r.reason)))
        self.assertIsNotNone(r.text)
        self.assertIsNone(r.reject)

    def assertReject(self, r, rid, reason_prefix=None, msg=None):
        self.assertEqual(r.outcome, REJECT, msg or repr((r.outcome, r.text)))
        self.assertEqual(r.reject, rid, msg or repr(r.reason))
        self.assertIsNone(r.text)
        self.assertEqual(r.audit.get("reject"), rid)
        if reason_prefix is not None:
            self.assertTrue(r.reason.startswith(reason_prefix), r.reason)


# ───────────────────────────── R6 ─────────────────────────────
class TestR6Method(Base):
    def test_invalid_methods_rejected(self):
        for m in (b"", b"GE T", b"GET ", b" GET", b"GET(", b"GE)T", b"G\xc3\xa9T", b"\xff",
                  b"GET\n", b"GET\r", b"GET\x00", b"GE\tT", b'GE"T', b"GE/T", b"GE:T",
                  b"GE@T", b"GE,T", b"GE;T", b"GE<T", b"GE=T", b"GE>T", b"GE?T", b"GE[T",
                  b"GE\\T", b"GE]T", b"GE{T", b"GE}T", b"\x7f"):
            with self.subTest(method=m):
                self.assertReject(run(method=m), "R6", "method")

    def test_valid_method_tokens_pass_verbatim(self):
        for m in (b"GET", b"get", b"PROPFIND", b"M-SEARCH", b"!#$%&'*+-.^_`|~", b"a.b_c~d",
                  b"X" * 1000, b"CONNECTX", b"Connect"):
            with self.subTest(method=m):
                r = run(method=m)
                self.assertAccept(r)
                self.assertTrue(r.text.startswith(m.decode() + " / HTTP/1.1\n"))

    def test_r6_is_first_in_order(self):
        # violates R6, R5, R4, R7 and R1 at once
        r = run(method=b"BAD METHOD", target=b"/a b",
                headers=[(b"X", b"a\nb"), CT(), CT(), (b"Transfer-Encoding", b"chunked"),
                         (b"Content-Length", b"1")])
        self.assertReject(r, "R6")


# ───────────────────────────── R5 ─────────────────────────────
class TestR5Target(Base):
    def test_every_byte_in_every_position(self):
        for b in range(256):
            bad = b <= 0x20 or b == 0x7F
            for t in (b"/a" + bytes([b]) + b"b", bytes([b]) + b"/x", b"/x" + bytes([b]),
                      b"/x?q=" + bytes([b])):
                with self.subTest(byte=hex(b), target=t):
                    r = run(target=t)
                    if bad:
                        self.assertReject(r, "R5")
                    else:
                        self.assertAccept(r)

    def test_htab_and_nul_rejected(self):
        self.assertReject(run(target=b"/a\tb"), "R5")
        self.assertReject(run(target=b"/a\x00b"), "R5")

    def test_non_ascii_not_rejected_and_signalled(self):
        for t in (b"/\x80", b"/\xff", b"/caf\xc3\xa9", b"/\xc3", b"/\xed\xa0\x80"):
            r = run(target=t)
            self.assertAccept(r)
            self.assertIn("S-TARGET-NONASCII", r.signals)

    def test_r5_on_absolute_form_and_connect(self):
        self.assertReject(run(target=b"http://h/a b"), "R5")
        self.assertReject(run(method=b"CONNECT", target=b"h:443 x"), "R5")
        self.assertReject(run(target=b"http://h\x00/"), "R5")

    def test_percent_triplets_any_case_pass_and_are_preserved(self):
        r = run(target=b"/%2f%2F%7e%7E?q=%C3%a9+%41")
        self.assertAccept(r)
        self.assertEqual(r.text, "GET /%2f%2F%7e%7E?q=%C3%a9+%41 HTTP/1.1\n")


# ───────────────────────────── R4 ─────────────────────────────
class TestR4FieldValues(Base):
    def test_every_byte_in_content_type_and_unrelated_header(self):
        for b in range(256):
            bad = b in (0x00, 0x0A, 0x0D)
            for hdr in ((b"Content-Type", b"text/plain; x=a" + bytes([b]) + b"b"),
                        (b"X-Other", b"val" + bytes([b]) + b"ue"),
                        (b"Cookie", bytes([b])),
                        (b"Authorization", b"Bearer t" + bytes([b]))):
                with self.subTest(byte=hex(b), header=hdr[0]):
                    r = run(headers=[hdr])
                    if bad:
                        self.assertReject(r, "R4")
                    else:
                        self.assertAccept(r)

    def test_obs_text_and_htab_pass(self):
        r = run(headers=[(b"X-A", b"a\tb\x80\xff"), (b"Cookie", b"\x80\x81")])
        self.assertAccept(r)
        r = run(headers=[CT(b"text/plain;\tcharset=utf-8")])
        self.assertAccept(r)

    def test_r4_beats_later_checks(self):
        r = run(headers=[(b"X", b"a\rb"), CT(), CT()])  # also R7
        self.assertReject(r, "R4")

    def test_r4_header_with_crlf_injection_attempt(self):
        r = run(headers=[(b"X", b"a\r\nContent-Type: evil")])
        self.assertReject(r, "R4")

    def test_r4_applies_to_connect_too(self):
        self.assertReject(run(method=b"CONNECT", target=b"h:1", headers=[(b"X", b"\n")]), "R4")


# ───────────────────────────── R7 ─────────────────────────────
class TestR7ContentType(Base):
    def test_duplicates_any_case_rejected(self):
        for names in ((b"Content-Type", b"Content-Type"), (b"Content-Type", b"content-type"),
                      (b"CONTENT-TYPE", b"content-TYPE")):
            r = run(headers=[(names[0], b"text/plain"), (names[1], b"text/plain")])
            self.assertReject(r, "R7")

    def test_even_identical_and_empty_duplicates(self):
        self.assertReject(run(headers=[CT(b""), CT(b"")]), "R7")
        self.assertReject(run(headers=[CT(b"a/b"), (b"X", b"1"), CT(b"a/b")]), "R7")

    def test_single_with_params_passes(self):
        r = run(headers=[CT(b'multipart/form-data; boundary="a b"; charset=utf-8')],
                body=b"x")
        self.assertAccept(r)
        self.assertIn("Content-Type: multipart/form-data; boundary=\"a b\"; charset=utf-8\n",
                      r.text)

    def test_ct_like_names_are_not_content_type(self):
        r = run(headers=[(b"X-Content-Type", b"a"), (b"Content-Type-Options", b"b"), CT()])
        self.assertAccept(r)

    def test_connect_dup_ct_is_r7_not_unsupported(self):
        self.assertReject(run(method=b"CONNECT", target=b"h:1", headers=[CT(), CT()]), "R7")


# ───────────────────────────── R1 residual / R2 ─────────────────────────────
class TestFramingResidual(Base):
    TE = b"Transfer-Encoding"
    CL = b"Content-Length"

    def test_valid_counterparts_pass(self):
        self.assertAccept(run(headers=[(self.CL, b"3"), CT()], body=b"abc"))
        self.assertAccept(run(headers=[(self.TE, b"chunked"), CT()], body=b"abc"))
        self.assertAccept(run(headers=[(self.TE, b"Chunked"), CT()], body=b"abc"))
        self.assertAccept(run(headers=[(self.TE, b" chunked \t"), CT()], body=b"abc"))
        self.assertAccept(run(headers=[(self.CL, b" 3\t"), CT()], body=b"abc"))
        self.assertAccept(run(headers=[(self.CL, b"0")], body=b""))
        self.assertAccept(run(headers=[(self.CL, b"03"), CT()], body=b"abc"))

    def test_r1_vectors(self):
        cases = {
            "te+cl": ([(self.TE, b"chunked"), (self.CL, b"3")], "HTTP/1.1"),
            "te+cl-lowercase": ([(b"transfer-encoding", b"chunked"), (b"content-length", b"3")],
                                "HTTP/1.1"),
            "multiple-te-fields": ([(self.TE, b"chunked"), (self.TE, b"chunked")], "HTTP/1.1"),
            "multiple-te-fields-gzip": ([(self.TE, b"gzip"), (self.TE, b"chunked")],
                                        "HTTP/1.1"),
            "te-on-1.0": ([(self.TE, b"chunked")], "HTTP/1.0"),
            "te-on-1.0-lower": ([(self.TE, b"chunked")], "http/1.0"),
            "te-empty": ([(self.TE, b"")], "HTTP/1.1"),
            "te-only-commas": ([(self.TE, b" , ,")], "HTTP/1.1"),
            "chunked-not-final": ([(self.TE, b"chunked, gzip")], "HTTP/1.1"),
            "chunked-twice": ([(self.TE, b"chunked, chunked")], "HTTP/1.1"),
            "chunked-first-of-three": ([(self.TE, b"chunked, gzip, chunked")], "HTTP/1.1"),
            "dup-cl-same": ([(self.CL, b"3"), (self.CL, b"3")], "HTTP/1.1"),
            "dup-cl-diff": ([(self.CL, b"3"), (self.CL, b"4")], "HTTP/1.1"),
            "cl-list": ([(self.CL, b"3, 3")], "HTTP/1.1"),
            "cl-empty": ([(self.CL, b"")], "HTTP/1.1"),
            "cl-neg": ([(self.CL, b"-3")], "HTTP/1.1"),
            "cl-plus": ([(self.CL, b"+3")], "HTTP/1.1"),
            "cl-hex": ([(self.CL, b"0x3")], "HTTP/1.1"),
            "cl-space-inside": ([(self.CL, b"3 3")], "HTTP/1.1"),
            "cl-alpha": ([(self.CL, b"abc")], "HTTP/1.1"),
            "cl-unicode-digit": ([(self.CL, "\u0663".encode())], "HTTP/1.1"),
            "cl-float": ([(self.CL, b"3.0")], "HTTP/1.1"),
            "cl-lt-body": ([(self.CL, b"2")], "HTTP/1.1"),
            "cl-gt-body": ([(self.CL, b"4")], "HTTP/1.1"),
        }
        for name, (hdrs, ver) in cases.items():
            with self.subTest(case=name):
                self.assertReject(run(headers=hdrs + [CT()], body=b"abc", ver=ver), "R1")

    def test_r2_vectors(self):
        for v in (b"gzip", b"deflate", b"identity", b"compress", b"gzip, chunked",
                  b"deflate, chunked", b"x-foo", b"chunkedx", b"chunk"):
            with self.subTest(te=v):
                self.assertReject(run(headers=[(self.TE, v), CT()], body=b"abc"), "R2")

    def test_r2_on_http10_is_r1_first(self):
        self.assertReject(run(headers=[(self.TE, b"gzip")], ver="HTTP/1.0"), "R1")

    def test_te_plus_cl_with_unknown_te_is_r1_first(self):
        self.assertReject(run(headers=[(self.TE, b"gzip"), (self.CL, b"3")], body=b"abc"), "R1")

    def test_empty_cl_zero_with_empty_body(self):
        self.assertAccept(run(headers=[(self.CL, b"0")]))
        self.assertReject(run(headers=[(self.CL, b"1")]), "R1")

    def test_r1_does_not_leak_into_http2(self):
        self.assertAccept(run(headers=[(self.CL, b"3"), CT()], body=b"abc", ver="HTTP/2.0"))
        self.assertAccept(run(headers=[CT()], body=b"abc", ver="HTTP/2"))

    def test_r1_precedes_connect_unsupported(self):
        r = run(method=b"CONNECT", target=b"h:1",
                headers=[(self.TE, b"chunked"), (self.CL, b"1")])
        self.assertReject(r, "R1")

    def test_cl_with_content_encoded_body_counts_received_bytes(self):
        enc = gz(b"hello world")
        r = run(headers=[(self.CL, str(len(enc)).encode()), (b"Content-Encoding", b"gzip"), CT()],
                body=enc)
        self.assertAccept(r)
        self.assertEqual(r.text, run(headers=[CT()], body=b"hello world").text)


# ───────────────────────────── R3 / R8 cap ─────────────────────────────
class TestR3ContentCoding(Base):
    CE = b"Content-Encoding"
    PLAIN = b'{"a": "hello", "b": [1, 2, 3]}' * 5

    def dec(self, coding, body, extra_headers=()):
        return run(headers=[(self.CE, coding), CT(b"application/json")] + list(extra_headers),
                   body=body)

    def expected_text(self):
        return run(headers=[CT(b"application/json")], body=self.PLAIN).text

    def test_stdlib_codings_decode_to_same_text(self):
        for coding, body in ((b"gzip", gz(self.PLAIN)), (b"x-gzip", gz(self.PLAIN)),
                             (b"deflate", zlib.compress(self.PLAIN)),
                             (b"deflate", raw_deflate(self.PLAIN)),
                             (b"identity", self.PLAIN)):
            with self.subTest(coding=coding):
                r = self.dec(coding, body)
                self.assertAccept(r)
                self.assertEqual(r.text, self.expected_text())

    def test_case_insensitive_and_whitespace(self):
        for coding in (b"GZIP", b"GzIp", b"  gzip  ", b"gzip,", b",gzip", b"\tgzip\t", b"X-GZIP"):
            with self.subTest(coding=coding):
                r = self.dec(coding, gz(self.PLAIN))
                self.assertAccept(r)
                self.assertEqual(r.text, self.expected_text())

    @need_br
    def test_br_case_insensitive(self):
        self.assertAccept(self.dec(b"BR", brotli.compress(self.PLAIN)))

    def test_multiple_content_encoding_fields_concatenate_in_order(self):
        body = gz(zlib.compress(self.PLAIN))
        r = run(headers=[(self.CE, b"deflate"), (self.CE, b"gzip"), CT(b"application/json")],
                body=body)
        self.assertAccept(r)
        self.assertEqual(r.text, self.expected_text())

    def test_stacked_reverse_order(self):
        good = gz(zlib.compress(self.PLAIN))  # applied deflate then gzip
        r = self.dec(b"deflate, gzip", good)
        self.assertAccept(r)
        self.assertEqual(r.text, self.expected_text())
        # opposite header order must fail: it would decode gzip as zlib first
        self.assertReject(self.dec(b"gzip, deflate", good), "R3")
        # identity anywhere in the stack is a no-op
        self.assertAccept(self.dec(b"identity, gzip, identity", gz(self.PLAIN)))
        self.assertAccept(self.dec(b"gzip, gzip", gz(gz(self.PLAIN))))

    @need_br
    @need_zstd
    def test_stacked_all_four(self):
        body = brotli.compress(zstandard.ZstdCompressor().compress(gz(zlib.compress(self.PLAIN))))
        # applied: deflate, gzip, zstd, br
        r = self.dec(b"deflate, gzip, zstd, br", body)
        self.assertAccept(r)
        self.assertEqual(r.text, self.expected_text())

    def test_unknown_codings_r3(self):
        for c in (b"compress", b"x-compress", b"gzip;q=1", b"foo", b"gzipp", b"g zip",
                  b"chunked", b"gzip, foo", b"foo, gzip", b"snappy", b"lz4", b"dcb", b"dcz",
                  b"zstd1", b"\x80", b"gzip\x7f"):
            with self.subTest(coding=c):
                self.assertReject(self.dec(c, gz(self.PLAIN)), "R3", "content-coding-unknown")

    def test_unknown_coding_with_empty_body_is_still_r3(self):
        self.assertReject(run(headers=[(self.CE, b"foo")]), "R3", "content-coding-unknown")

    def test_corrupted_and_truncated_streams_r3(self):
        g = gz(self.PLAIN)
        z = zlib.compress(self.PLAIN)
        bad = {
            "gzip-garbage": (b"gzip", b"not gzip at all"),
            "gzip-truncated": (b"gzip", g[:-5]),
            "gzip-header-only": (b"gzip", g[:10]),
            "gzip-bad-crc": (b"gzip", g[:-8] + bytes([g[-8] ^ 1]) + g[-7:]),
            "gzip-bad-len": (b"gzip", g[:-1] + bytes([g[-1] ^ 1])),
            "gzip-trailing-garbage": (b"gzip", g + b"garbage"),
            "gzip-trailing-one-byte": (b"gzip", g + b"\x01"),
            "gzip-zlib-stream": (b"gzip", z),
            "deflate-garbage": (b"deflate", b"\xff\xff\xff\xff\xff"),
            "deflate-truncated": (b"deflate", z[:-6]),
            "deflate-bad-adler": (b"deflate", z[:-1] + bytes([z[-1] ^ 1])),
            "deflate-trailing-garbage": (b"deflate", z + b"xx"),
            "deflate-gzip-stream": (b"deflate", g),
            "xgzip-truncated": (b"x-gzip", g[:-5]),
        }
        for name, (coding, body) in bad.items():
            with self.subTest(case=name):
                self.assertReject(self.dec(coding, body), "R3", "content-coding-decode-failure")

    @need_br
    def test_corrupted_br_r3(self):
        b = brotli.compress(self.PLAIN)
        for name, body in (("garbage", b"\xff\xff\xff\xff\xff\xff"), ("truncated", b[:-3]),
                           ("trailing", b + b"junk")):
            with self.subTest(case=name):
                self.assertReject(self.dec(b"br", body), "R3", "content-coding-decode-failure")

    @need_zstd
    def test_corrupted_zstd_r3(self):
        z = zstandard.ZstdCompressor().compress(self.PLAIN)
        for name, body in (("garbage", b"garbage garbage"), ("truncated", z[:-3]),
                           ("bad-magic", b"\x00" + z[1:]), ("magic-only", z[:4]),
                           ("trailing-garbage", z + b"junk")):
            with self.subTest(case=name):
                self.assertReject(self.dec(b"zstd", body), "R3", "content-coding-decode-failure")

    @need_br
    @need_zstd
    def test_all_codings_decode_equal(self):
        enc = {b"gzip": gz(self.PLAIN), b"deflate": zlib.compress(self.PLAIN),
               b"br": brotli.compress(self.PLAIN),
               b"zstd": zstandard.ZstdCompressor().compress(self.PLAIN)}
        for coding, body in enc.items():
            self.assertEqual(self.dec(coding, body).text, self.expected_text(), coding)

    def test_decoder_unavailable_is_r3_with_named_reason(self):
        with unittest.mock.patch.object(cr, "decoder_available", lambda c: False):
            r = self.dec(b"br", b"whatever")
            self.assertReject(r, "R3", "content-coding-decoder-unavailable:br")
            r = self.dec(b"gzip", gz(self.PLAIN))
            self.assertReject(r, "R3", "content-coding-decoder-unavailable:gzip")

    def test_missing_libs_environment_behaviour(self):
        if brotli is None:
            self.assertReject(self.dec(b"br", b"\x0b\x00\x80a\x03"), "R3",
                              "content-coding-decoder-unavailable:br")
        if zstandard is None:
            self.assertReject(self.dec(b"zstd", b"\x28\xb5\x2f\xfd\x00"), "R3",
                              "content-coding-decoder-unavailable:zstd")

    def test_gzip_nul_padding_and_multi_member(self):
        self.assertAccept(self.dec(b"gzip", gz(self.PLAIN) + b"\x00" * 7))
        r = self.dec(b"gzip", gz(self.PLAIN[:10]) + gz(self.PLAIN[10:]))
        self.assertAccept(r)
        self.assertEqual(r.text, self.expected_text())

    def test_decoded_empty_body_renders_no_blank_line(self):
        r = self.dec(b"gzip", gz(b""))
        self.assertAccept(r)
        self.assertEqual(r.text, "GET / HTTP/1.1\nContent-Type: application/json\n")

    def test_stray_encoding_with_empty_body_is_not_decoded(self):
        self.assertAccept(run(headers=[(self.CE, b"gzip")]))

    def test_r3_precedes_connect_and_follows_framing(self):
        # CONNECT returns UNSUPPORTED before R3 (author order); R1 still wins.
        r = run(method=b"CONNECT", target=b"h:1", headers=[(self.CE, b"foo")], body=b"x")
        self.assertEqual(r.outcome, UNSUPPORTED)
        r = run(headers=[(self.CE, b"foo"), (b"Content-Length", b"9")], body=b"x")
        self.assertReject(r, "R1")


class TestR8Cap(Base):
    CE = b"Content-Encoding"

    def at_cap(self, make, coding, cap):
        ok = run(headers=[(self.CE, coding), CT()], body=make(b"a" * cap), limits=L(cap))
        over = run(headers=[(self.CE, coding), CT()], body=make(b"a" * (cap + 1)), limits=L(cap))
        return ok, over

    def check_boundary(self, make, coding, cap=1000):
        ok, over = self.at_cap(make, coding, cap)
        self.assertAccept(ok, f"exactly cap must pass for {coding!r}: {ok.reason}")
        self.assertEqual(ok.audit["decoded_body_bytes"], cap)
        self.assertReject(over, "R8", "decoded-body-over-cap")

    def test_identity_boundary(self):
        self.check_boundary(lambda b: b, b"identity")
        ok = run(headers=[CT()], body=b"a" * 50, limits=L(50))
        over = run(headers=[CT()], body=b"a" * 51, limits=L(50))
        self.assertAccept(ok)
        self.assertReject(over, "R8", "decoded-body-over-cap")

    def test_gzip_boundary(self):
        self.check_boundary(gz, b"gzip")
        self.check_boundary(gz, b"x-gzip")

    def test_deflate_boundary(self):
        self.check_boundary(zlib.compress, b"deflate")
        self.check_boundary(raw_deflate, b"deflate")

    @need_br
    def test_br_boundary(self):
        self.check_boundary(brotli.compress, b"br")

    @need_zstd
    def test_zstd_boundary(self):
        self.check_boundary(zstandard.ZstdCompressor().compress, b"zstd")

    # REGRESSION (review finding, fixed 2026-10-13, D63): R8 applies to the DECODED body
    # (§5.3). A tiny content-coded body whose decoded size is exactly the cap must pass even
    # though its received (coded) length exceeds the cap.
    def test_tiny_caps(self):
        for cap in (1, 2, 3):
            self.check_boundary(gz, b"gzip", cap=cap)
            self.check_boundary(zlib.compress, b"deflate", cap=cap)

    def test_gzip_multimember_crossing_cap(self):
        m = gz(b"a" * 600)
        ok = run(headers=[(self.CE, b"gzip"), CT()], body=m + gz(b"a" * 400), limits=L(1000))
        over = run(headers=[(self.CE, b"gzip"), CT()], body=m + gz(b"a" * 401), limits=L(1000))
        self.assertAccept(ok)
        self.assertReject(over, "R8")

    def test_bombs_are_bounded_and_r8(self):
        zeros = b"\x00" * (60 * 1024 * 1024)
        cases = [("gzip", gz(zeros)), ("deflate", zlib.compress(zeros)),
                 ("deflate", raw_deflate(zeros)), ("gzip", gz(gz(zeros)[:0] + zeros))]
        if brotli:
            cases.append(("br", brotli.compress(zeros, quality=1)))
        if zstandard:
            cases.append(("zstd", zstandard.ZstdCompressor().compress(zeros)))
        for coding, body in cases:
            with self.subTest(coding=coding, compressed=len(body)):
                r = run(headers=[(self.CE, coding.encode()), CT()], body=body, limits=L(1000))
                self.assertReject(r, "R8", "decoded-body-over-cap")

    def test_stacked_bomb(self):
        body = gz(gz(b"\x00" * (50 * 1024 * 1024)))
        r = run(headers=[(self.CE, b"gzip, gzip"), CT()], body=body, limits=L(10000))
        self.assertReject(r, "R8")

    def test_cap_applies_to_any_media_type(self):
        r = run(headers=[CT(b"application/octet-stream")], body=b"a" * 11, limits=L(10))
        self.assertReject(r, "R8", "decoded-body-over-cap")
        r = run(body=b"a" * 11, limits=L(10))  # no CT either
        self.assertReject(r, "R8", "decoded-body-over-cap")

    def test_unsupported_media_below_cap_is_signal_only(self):
        body = b"z" * 50000
        r = run(headers=[CT(b"application/octet-stream")], body=body,
                limits=L(1 << 20, token_budget=100, count_tokens=len))
        self.assertAccept(r)
        self.assertIn("S-OVERSIZE", r.signals)
        self.assertIn("S-MEDIA-UNSUPPORTED", r.signals)
        self.assertEqual(r.size, cr.SIZE_OVER)
        self.assertEqual(r.text.count("z"), 50000)  # never truncated

    # REGRESSION (review finding, fixed 2026-10-13, D63): §5.3 R8 is "decoded body above the
    # hard decompression cap". An incompressible body of exactly `cap` bytes grows under
    # gzip/deflate framing; only its decoded size may be compared with the cap.
    def test_incompressible_body_exactly_cap_after_decode_passes(self):
        cap = 2000
        data = random.Random(7).randbytes(cap)
        for coding, make in ((b"gzip", gz), (b"deflate", zlib.compress)):
            enc = make(data)
            self.assertGreater(len(enc), cap)
            r = run(headers=[(self.CE, coding), CT(b"application/octet-stream")], body=enc,
                    limits=L(cap))
            self.assertAccept(r, f"{coding!r}: decoded == cap must pass; got {r.reason}")


# ───────────────────────────── R8 budget ─────────────────────────────
class TestR8Budget(Base):
    PREFIX = "GET / HTTP/1.1\nContent-Type: text/plain\n\n"

    def req(self, nbody, limits, ct=b"text/plain", body_char=b"a"):
        return run(headers=[CT(ct)], body=body_char * nbody, limits=limits)

    def test_exact_count_tokens_boundary(self):
        B = 100
        n_ok = B - len(self.PREFIX)
        lim = L(10000, token_budget=B, count_tokens=len)
        r = self.req(n_ok, lim)
        self.assertAccept(r)
        self.assertEqual(r.size, cr.SIZE_WITHIN)
        self.assertEqual(len(r.text), B)
        r = self.req(n_ok + 1, lim)
        self.assertReject(r, "R8", "text-over-token-budget")
        self.assertEqual(r.size, cr.SIZE_OVER)
        self.assertEqual(r.audit["reject"], "R8")

    def test_count_tokens_called_on_final_text_only(self):
        seen = []

        def counter(t):
            seen.append(t)
            return 1

        r = self.req(5, L(1000, token_budget=10, count_tokens=counter))
        self.assertAccept(r)
        self.assertEqual(seen, [r.text])

    def test_not_called_on_earlier_rejects(self):
        seen = []

        def counter(t):
            seen.append(t)
            return 1

        lim = L(100, token_budget=10, count_tokens=counter)
        run(method=b"BAD M", limits=lim)
        run(target=b"/a b", limits=lim)
        run(method=b"CONNECT", target=b"h:1", limits=lim)
        self.assertEqual(seen, [])

    def test_unchecked_without_budget(self):
        r = self.req(10000, L(1 << 20))
        self.assertAccept(r)
        self.assertEqual(r.size, cr.SIZE_UNCHECKED)

    def test_data_plane_byte_bounds(self):
        B = 100
        lim = L(1 << 20, token_budget=B, max_bytes_per_token=48)
        base = len(self.PREFIX)
        cases = [(B - base, cr.SIZE_WITHIN), (B - base + 1, cr.SIZE_NEEDS_EXACT_COUNT),
                 (48 * B - base, cr.SIZE_NEEDS_EXACT_COUNT), (48 * B - base + 1, None)]
        for n, expect in cases:
            with self.subTest(body=n, expect=expect):
                r = self.req(n, lim)
                if expect is None:
                    self.assertReject(r, "R8", "text-over-token-budget")
                    self.assertEqual(r.size, cr.SIZE_OVER)
                else:
                    self.assertAccept(r)
                    self.assertEqual(r.size, expect)

    def test_data_plane_bounds_measure_utf8_bytes_not_chars(self):
        B = 100
        lim = L(1 << 20, token_budget=B, max_bytes_per_token=48)
        # 'é' is 2 bytes: text of exactly B chars but > B bytes must NOT be WITHIN
        n = B - len(self.PREFIX)
        r = run(headers=[CT()], body="é".encode() * n, limits=lim)
        self.assertAccept(r)
        self.assertEqual(len(r.text), B)
        self.assertEqual(r.size, cr.SIZE_NEEDS_EXACT_COUNT)

    def test_data_plane_out_of_scope_is_signal_only(self):
        B = 100
        lim = L(1 << 20, token_budget=B, max_bytes_per_token=48)
        r = self.req(48 * B + 10, lim, ct=b"application/xml")
        self.assertAccept(r)
        self.assertIn("S-OVERSIZE", r.signals)
        self.assertEqual(r.size, cr.SIZE_OVER)

    def test_in_scope_types_all_rejected_over_budget(self):
        lim = L(10000, token_budget=60, count_tokens=len)
        for ct in (b"application/x-www-form-urlencoded", b"application/json", b"text/plain",
                   b"TEXT/PLAIN; charset=utf-8", b"Application/JSON"):
            with self.subTest(ct=ct):
                r = self.req(200, lim, ct=ct)
                self.assertReject(r, "R8", "text-over-token-budget")

    def test_out_of_scope_types_never_r8_on_budget(self):
        lim = L(10000, token_budget=60, count_tokens=len)
        for ct in (b"multipart/form-data; boundary=x", b"application/xml", b"image/png",
                   b"application/octet-stream", b"text/html", b"text/plain, text/plain"):
            with self.subTest(ct=ct):
                r = self.req(200, lim, ct=ct)
                self.assertAccept(r)
                self.assertIn("S-OVERSIZE", r.signals)

    def test_body_without_ct_out_of_scope(self):
        r = run(body=b"a" * 200, limits=L(10000, token_budget=60, count_tokens=len))
        self.assertAccept(r)
        self.assertIn("S-OVERSIZE", r.signals)
        self.assertIn("S-CT-ABSENT", r.signals)
        self.assertIn("S-MEDIA-UNSUPPORTED", r.signals)

    def test_empty_body_in_scope_target_over_budget_is_r8(self):
        r = run(target=b"/" + b"a" * 500, limits=L(10000, token_budget=60, count_tokens=len))
        self.assertReject(r, "R8", "text-over-token-budget")

    def test_limits_validation(self):
        for kw in ({"max_decoded_body": 0}, {"max_decoded_body": -1}, {"max_decoded_body": True},
                   {"max_decoded_body": 10, "token_budget": 0},
                   {"max_decoded_body": 10, "count_tokens": len},   # needs budget
                   {"max_decoded_body": 10, "max_bytes_per_token": 48},
                   {"max_decoded_body": 10, "token_budget": 5, "count_tokens": 3}):
            with self.subTest(kw=kw):
                with self.assertRaises(ValueError):
                    Limits(**kw)


# ───────────────────────────── CONNECT / target forms ─────────────────────────────
class TestConnect(Base):
    def test_connect_unsupported(self):
        r = run(method=b"CONNECT", target=b"example.com:443",
                headers=[(b"Host", b"example.com:443")])
        self.assertEqual(r.outcome, UNSUPPORTED)
        self.assertIsNone(r.text)
        self.assertIsNone(r.reject)
        self.assertIn("S-CONNECT", r.signals)
        self.assertEqual(r.audit["target_form"], "authority")

    def test_connect_with_body_and_origin_target_still_unsupported(self):
        for t in (b"/", b"*", b"http://x/", b"host:1"):
            r = run(method=b"CONNECT", target=t, headers=[CT()], body=b"abc")
            self.assertEqual(r.outcome, UNSUPPORTED, t)
            self.assertIsNone(r.text)

    def test_other_methods_with_authority_target_are_not_connect(self):
        r = run(method=b"GET", target=b"example.com:443")
        self.assertAccept(r)
        self.assertNotIn("S-CONNECT", r.signals)
        r = run(method=b"connect", target=b"/")
        self.assertAccept(r)  # methods are case-sensitive (RFC 9110 §9.1)

    def test_connect_does_not_echo_target(self):
        r = run(method=b"CONNECT", target=b"SENTINELHOST.invalid:443")
        self.assertNotIn("SENTINELHOST", repr(r))


class TestTargetForms(Base):
    def test_absolute_form_reduced_to_origin_form(self):
        cases = {
            b"http://user:pw@host:8080/a/b?x=1#f": "/a/b?x=1#f",
            b"http://host": "/",
            b"http://host/": "/",
            b"http://host?q=1": "/?q=1",
            b"http://host#f": "/#f",
            b"http://host:80": "/",
            b"HTTP://HOST/X": "/X",
            b"https://[::1]:8443/p?q": "/p?q",
            b"ftp://h/%2F%2f": "/%2F%2f",
            b"http://h//": "//",
            b"http://h/a/../b/./c": "/a/../b/./c",
            b"http://h/x@y": "/x@y",
            b"http://a@b@c/d": "/d",
            b"http://:@/": "/",
            b"http:///p": "/p",
            b"http://": "/",
            b"HtTp+x-y.z://h/p": "/p",
        }
        for t, expect in cases.items():
            with self.subTest(target=t):
                r = run(target=t)
                self.assertAccept(r)
                self.assertEqual(r.text, f"GET {expect} HTTP/1.1\n")
                self.assertEqual(r.audit["target_form"], "absolute")

    def test_absolute_form_authority_only_in_audit_and_userinfo_never(self):
        r = run(target=b"http://SENTINELUSER:SENTINELPW@auth.example:81/p")
        self.assertNotIn("auth.example", r.text)
        self.assertEqual(r.audit["authority"], "auth.example:81")
        self.assertTrue(r.audit["authority_userinfo_present"])
        self.assertNotIn("SENTINELUSER", repr(r))
        self.assertNotIn("SENTINELPW", repr(r))

    def test_absolute_form_nonascii_authority_does_not_crash(self):
        r = run(target=b"http://h\xff\xc3/p\xff")
        self.assertAccept(r)
        self.assertIn("S-TARGET-NONASCII", r.signals)

    def test_asterisk_form(self):
        r = run(method=b"OPTIONS", target=b"*")
        self.assertEqual(r.text, "OPTIONS * HTTP/1.1\n")
        self.assertEqual(r.audit["target_form"], "asterisk")

    def test_origin_form_variants_preserved(self):
        for t in (b"/", b"//", b"/?", b"/#", b"/a?b=c&d", b"//host/x", b"/%", b"/%zz",
                  b"/a\\b", b"/.", b"/..", b"/a/%2e%2e/b", b"/\xc2\x85", b"/\xe2\x80\xa8",
                  b"/?q=%u0041", b"/<script>", b"/'\"`"):
            with self.subTest(target=t):
                r = run(target=t)
                self.assertAccept(r)
                self.assertTrue(r.text.startswith("GET " + t.decode("utf-8") + " HTTP/1.1\n"))

    def test_empty_target_is_rendered_not_crashed(self):
        r = run(target=b"")  # no reject exists for it in §5.3; must still round-trip (I8)
        self.assertAccept(r)
        self.assertEqual(r.text, "GET  HTTP/1.1\n")
        self.assertEqual(parse_canonical(r.text).target, b"")

    def test_nonutf8_target_escapes_lowercase_hex(self):
        r = run(target=b"/\xff\xFE%FF")
        self.assertEqual(r.text, "GET /\\xff\\xfe%FF HTTP/1.1\n")
        self.assertFalse(r.audit["target_utf8"])

    def test_version_always_http11(self):
        for v in ("HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/2.0", "HTTP/3", "junk", ""):
            r = run(ver=v)
            self.assertTrue(r.text.endswith(" HTTP/1.1\n"))
            self.assertEqual(r.audit["http_version_received"], v)


# ───────────────────────────── text / body / content-type rules ─────────────────────────────
class TestRendering(Base):
    def test_only_content_type_header_in_text(self):
        hdrs = [(b"Host", b"h.example"), (b"User-Agent", b"ua"), (b"Accept", b"*/*"),
                (b"X-Sentinel-Header-Name", b"v"), CT(b"text/plain"),
                (b"Cookie", b"c"), (b"Authorization", b"Bearer t"),
                (b"Content-Length", b"1"), (b"Content-Encoding", b"identity")]
        r = run(headers=hdrs, body=b"x")
        self.assertEqual(r.text, "GET / HTTP/1.1\nContent-Type: text/plain\n\nx")
        for name in (b"Host", b"User-Agent", b"Accept", b"X-Sentinel-Header-Name", b"Cookie",
                     b"Authorization", b"Content-Length", b"Content-Encoding"):
            self.assertNotIn(name.decode().lower(), r.text.lower())

    def test_ct_line_verbatim_name_case_fixed_value_trimmed(self):
        r = run(headers=[(b"cOnTeNt-TyPe", b" \t Text/Plain;Charset=UTF-8 \t ")], body=b"x")
        self.assertEqual(r.text, "GET / HTTP/1.1\nContent-Type: Text/Plain;Charset=UTF-8\n\nx")
        self.assertEqual(r.audit["media_type"], "text/plain")

    def test_ct_absent_no_line_and_empty_body_no_blank(self):
        self.assertEqual(run().text, "GET / HTTP/1.1\n")
        self.assertEqual(run(headers=[CT()]).text, "GET / HTTP/1.1\nContent-Type: text/plain\n")

    def test_body_verbatim_bom_crlf(self):
        body = b"\xef\xbb\xbfline1\r\nline2\rline3\n\n"
        r = run(headers=[CT()], body=body)
        self.assertEqual(r.text, "GET / HTTP/1.1\nContent-Type: text/plain\n\n\ufeffline1\r\nline2\rline3\n\n")

    def test_body_starting_with_newline_keeps_exactly_one_separator(self):
        r = run(headers=[CT()], body=b"\n\nx")
        self.assertEqual(r.text, "GET / HTTP/1.1\nContent-Type: text/plain\n\n\n\nx")

    def test_invalid_utf8_body_escapes(self):
        r = run(headers=[CT()], body=b"a\xffb\xe2\x82c\xed\xa0\x80")
        self.assertEqual(r.text.split("\n\n", 1)[1], "a\\xffb\\xe2\\x82c\\xed\\xa0\\x80")
        self.assertIn("S-BODY-UTF8", r.signals)
        r = run(headers=[CT()], body=b"a\\xffb")  # literal: same text, no signal
        self.assertNotIn("S-BODY-UTF8", r.signals)

    def test_ct_iso8859_1_decoding(self):
        r = run(headers=[CT(b"text/plain; x=\xe9\xff")], body=b"x")
        self.assertIn("Content-Type: text/plain; x=\u00e9\u00ff\n", r.text)
        self.assertIn("S-CT-NONASCII", r.signals)

    def test_ct_malformed_rendered_as_received(self):
        for v in (b"", b"garbage", b"text/", b"/plain", b"text/plain;;=", b"a/b, c/d",
                  b"a b/c", b"text/plain; charset", b"text/plain; x=\"unterminated"):
            with self.subTest(ct=v):
                r = run(headers=[CT(v)], body=b"x")
                self.assertIn("S-CT-MALFORMED", r.signals)
                self.assertIn(f"Content-Type: {v.decode()}\n", r.text)
                self.assertIn("S-MEDIA-UNSUPPORTED", r.signals)

    def test_ct_wellformed_no_malformed_signal(self):
        for v in (b"text/plain", b"text/plain;", b"text/plain ; ", b'text/plain; a="b c"; d=e',
                  b'text/plain; a="\\"q\\""', b"APPLICATION/JSON;charset=utf-8", b"a/b;x=y;;z=w"):
            with self.subTest(ct=v):
                r = run(headers=[CT(v)], body=b"x")
                self.assertNotIn("S-CT-MALFORMED", r.signals)

    def test_media_scope_matrix(self):
        for ct, in_scope in ((b"application/x-www-form-urlencoded", True),
                             (b"application/json; charset=utf-8", True),
                             (b"TEXT/PLAIN", True), (b"text/html", False),
                             (b"multipart/form-data; boundary=b", False),
                             (b"application/xml", False), (b"application/octet-stream", False),
                             (b"application/problem+json", False), (b"text/plain,", False)):
            with self.subTest(ct=ct):
                r = run(headers=[CT(ct)], body=b"x")
                self.assertEqual("S-MEDIA-UNSUPPORTED" in r.signals, not in_scope)

    def test_signals_sorted_tuple(self):
        r = run(target=b"/\xff%u0041%00%2541", headers=[CT(b"junk")], body=b"\xff")
        self.assertIsInstance(r.signals, tuple)
        self.assertEqual(list(r.signals), sorted(r.signals))
        self.assertTrue(set(r.signals) <= cr.IMPLEMENTED_SIGNALS)

    def test_signal_detectors(self):
        def sig(target=b"/", body=b"", ct=b"text/plain"):
            return set(run(target=target, headers=[CT(ct)], body=body).signals)
        self.assertEqual(sig(), set())
        self.assertEqual(sig(b"/%41"), set())
        self.assertEqual(sig(b"/%25"), set())
        self.assertIn("S-ENC-MULTI", sig(b"/%2541"))
        self.assertIn("S-ENC-U", sig(b"/%u0041"))
        self.assertIn("S-ENC-U", sig(b"/%U0041"))
        self.assertIn("S-ENC-NUL", sig(b"/%00"))
        self.assertNotIn("S-ENC-NUL", sig(b"/%2500"))
        self.assertIn("S-UTF8-OVERLONG", sig(b"/%C0%AF"))
        self.assertIn("S-UTF8-OVERLONG", sig(b"/\xc0\xaf"))
        self.assertIn("S-ENC-NUL", sig(body=b"a=%00"))
        self.assertIn("S-ENC-U", sig(body=b"a=%u0041"))
        self.assertIn("S-ENC-MULTI", sig(body=b"a=%2541"))
        self.assertIn("S-CHARSET", sig(ct=b"text/plain; charset=iso-8859-1", body=b"x"))
        self.assertNotIn("S-CHARSET", sig(ct=b'text/plain; charset="UTF-8"', body=b"x"))
        self.assertNotIn("S-CHARSET", sig(ct=b"text/plain; charset=us-ascii", body=b"x"))
        self.assertIn("S-CT-ABSENT", set(run(body=b"x").signals))
        self.assertNotIn("S-CT-ABSENT", set(run().signals))

    def test_ct_mismatch_only_json(self):
        def sig(body, ct=b"application/json"):
            return set(run(headers=[CT(ct)], body=body).signals)
        self.assertNotIn("S-CT-MISMATCH", sig(b'{"a":1}'))
        self.assertNotIn("S-CT-MISMATCH", sig(b"[1,2]"))
        self.assertNotIn("S-CT-MISMATCH", sig(b""))
        self.assertIn("S-CT-MISMATCH", sig(b"{"))
        self.assertIn("S-CT-MISMATCH", sig(b"not json"))
        self.assertIn("S-CT-MISMATCH", sig(b"NaN"))
        self.assertIn("S-CT-MISMATCH", sig(b"\xff"))
        self.assertNotIn("S-CT-MISMATCH", sig(b"{", ct=b"text/plain"))

    def test_json_pathological_bodies_do_not_raise(self):
        for body in (b"[" * 200000, b"{" * 100000, b"1" * 100000, b'"' + b"\\" * 99999,
                     b"[" * 100000 + b"]" * 100000):
            r = run(headers=[CT(b"application/json")], body=body)
            self.assertEqual(r.outcome, ACCEPT)

    def test_i6_byte_preservation(self):
        body = b'{"z":1,"a":2,"z":3} a+b%2b%2B %7e%7E'
        r = run(headers=[CT(b"application/json")], body=body)
        self.assertTrue(r.text.endswith(body.decode()))


# ───────────────────────────── invariants ─────────────────────────────
class TestInvariants(Base):
    BODY = b'{"user": "o\'neil", "q": "1 OR 1=1 --"}'

    def base_headers(self):
        return [CT(b"application/json")]

    def test_i5_metadata_invariance(self):
        base = run(headers=self.base_headers(), body=self.BODY)
        variants = [
            [(b"Host", b"a.example"), (b"User-Agent", b"x"), (b"Accept", b"*/*"),
             (b"Accept-Language", b"en"), (b"Cookie", b"a=b"), (b"Authorization", b"Basic eA==")]
            + self.base_headers(),
            self.base_headers() + [(b"HOST", b"b"), (b"user-agent", b"y")],
            [(b"Content-Length", str(len(self.BODY)).encode())] + self.base_headers(),
            [(b"content-type", b"application/json")],
            [(b"CONTENT-TYPE", b"application/json"), (b"X-Forwarded-For", b"1.2.3.4")],
        ]
        for i, h in enumerate(variants):
            for ver in ("HTTP/1.0", "HTTP/1.1", "HTTP/2.0"):
                with self.subTest(variant=i, ver=ver):
                    r = run(headers=h, body=self.BODY, ver=ver)
                    self.assertEqual(r.text, base.text)
                    self.assertEqual(r.signals, base.signals)

    @need_br
    @need_zstd
    def test_i4_framing_independence(self):
        ref = run(headers=self.base_headers(), body=self.BODY).text
        cases = [
            [(b"Content-Length", str(len(self.BODY)).encode())] + self.base_headers(), self.BODY,
            [(b"Transfer-Encoding", b"chunked")] + self.base_headers(), self.BODY,
            [(b"Content-Encoding", b"gzip")] + self.base_headers(), gz(self.BODY),
            [(b"Content-Encoding", b"br")] + self.base_headers(), brotli.compress(self.BODY),
            [(b"Content-Encoding", b"zstd")] + self.base_headers(),
            zstandard.ZstdCompressor().compress(self.BODY),
            [(b"Content-Encoding", b"deflate")] + self.base_headers(), zlib.compress(self.BODY),
        ]
        for i in range(0, len(cases), 2):
            r = run(headers=cases[i], body=cases[i + 1])
            self.assertEqual(r.text, ref, cases[i])

    def test_determinism_and_no_input_mutation(self):
        parts = P(target=b"http://u:p@h/%2f?x=\xff", headers=[CT(b"text/plain"), (b"X", b"1")],
                  body=b"a\xffb")
        lim = L(1000, token_budget=100, count_tokens=len)
        rs = [canonicalize(parts, lim) for _ in range(5)]
        self.assertTrue(all(r == rs[0] for r in rs))
        self.assertTrue(all(r.audit is not rs[0].audit for r in rs[1:]))
        other = P(target=b"http://u:p@h/%2f?x=\xff", headers=[CT(b"text/plain"), (b"X", b"1")],
                  body=b"a\xffb")
        self.assertEqual(canonicalize(other, lim), rs[0])
        rs[0].audit["x"] = 1
        self.assertNotIn("x", canonicalize(parts, lim).audit)

    def test_audit_never_holds_header_values(self):
        s = lambda n: f"SENTINEL_{n}_7f3a91"  # noqa: E731
        hdrs = [(b"Authorization", s("auth").encode()), (b"Cookie", s("cookie").encode()),
                (b"Host", s("host").encode()), (b"User-Agent", s("ua").encode()),
                (b"Referer", s("ref").encode()), (b"Origin", s("origin").encode()),
                (b"X-Api-Key", s("key").encode()), (b"Accept", s("accept").encode())]
        scenarios = {
            "accept": dict(headers=hdrs + [CT()], body=b"x"),
            "accept-empty": dict(headers=hdrs),
            "connect": dict(method=b"CONNECT", target=b"h:1", headers=hdrs),
            "r4": dict(headers=hdrs + [(b"X", b"bad\nvalue " + s("r4").encode())]),
            "r6": dict(method=b"BAD M", headers=hdrs),
            "r5": dict(target=b"/a b", headers=hdrs),
            "r7": dict(headers=hdrs + [CT(), CT()]),
            "r1": dict(headers=hdrs + [(b"Transfer-Encoding", b"chunked"),
                                       (b"Content-Length", b"1")], body=b"x"),
            "r8": dict(headers=hdrs + [CT()], body=b"x" * 5000),
        }
        for name, kw in scenarios.items():
            with self.subTest(scenario=name):
                r = run(limits=L(1000, token_budget=100, count_tokens=len), **kw)
                dump = repr(r)
                for v in ("auth", "cookie", "host", "ua", "ref", "origin", "key", "accept", "r4"):
                    self.assertNotIn(s(v), dump)
                if r.text:
                    self.assertNotIn("SENTINEL", r.text)

    def test_audit_never_holds_target_or_body(self):
        r = run(target=b"/SENTINELPATH?q=SENTINELQ", headers=[CT()], body=b"SENTINELBODY")
        d = repr(r.audit)
        self.assertNotIn("SENTINELPATH", d)
        self.assertNotIn("SENTINELQ", d)
        self.assertNotIn("SENTINELBODY", d)

    # REGRESSION (review finding, fixed 2026-10-13, D63 P12): §5.2 inventories other headers
    # "by name only (no values)". Only known coding names reach audit["content_codings"];
    # a client-chosen unknown coding is recorded as "<other>", never echoed.
    def test_unknown_content_encoding_value_not_echoed_in_audit(self):
        r = run(headers=[(b"Content-Encoding", b"SENTINEL_coding_92d1")], body=b"x")
        self.assertEqual(r.reject, "R3")
        self.assertNotIn("sentinel_coding_92d1", repr(r).lower())

    def test_header_names_inventory_is_names_only(self):
        r = run(headers=[(b"X-Name", b"v"), (b"Cookie", b"c")])
        self.assertEqual(r.audit["header_names"], ["X-Name", "Cookie"])

    def test_text_never_contains_other_header_names_or_values(self):
        r = run(headers=[(b"X-Evil-Name", b"X-Evil-Value"), CT(), (b"Cookie", b"k=v")], body=b"b")
        for needle in ("X-Evil", "Cookie", "k=v"):
            self.assertNotIn(needle, r.text)

    def test_i3_idempotence_and_i8_recoverable(self):
        cases = [
            P(), P(target=b"/a?b=%41"), P(headers=[CT()], body=b"hello"),
            P(headers=[CT(b"")]), P(headers=[CT(b"")], body=b"x"),
            P(headers=[CT(b"junk\x85\xff")], body=b"\n\n\nx\n"),
            P(target=b"/\xff\xc2\x85\xe2\x80\xa8", body=b"\xff\xfe", headers=[CT()]),
            P(target=b"http://h", method=b"PUT", body=b"\x00\x01", headers=[CT(b"a/b")]),
            P(target=b"*", method=b"OPTIONS"), P(target=b""),
            P(headers=[CT(b"text/plain")], body=b"\n"),
            P(headers=[CT(b"text/plain")], body=b"Content-Type: x\n\nGET / HTTP/1.1\n"),
            P(method=b"M-SEARCH", target=b"/\\x41", body=b"\\x41"),
        ]
        big = L(10 ** 9)
        for parts in cases:
            with self.subTest(parts=parts):
                r = canonicalize(parts, big)
                self.assertAccept(r)
                p = parse_canonical(r.text)
                self.assertEqual(canonicalize(p, big).text, r.text)
                self.assertEqual(p.method, parts.method)
                self.assertEqual(p.http_version, "HTTP/1.1")
                ct = [v for n, v in parts.headers if n.lower() == b"content-type"]
                self.assertEqual(len(p.headers), len(ct))

    def test_i8_body_boundary_not_confused_by_body_content(self):
        r = run(headers=[CT()], body=b"Content-Type: evil\n\nGET / HTTP/1.1\n\nbody")
        p = parse_canonical(r.text)
        self.assertEqual(p.headers, ((b"Content-Type", b"text/plain"),))
        self.assertEqual(p.body, b"Content-Type: evil\n\nGET / HTTP/1.1\n\nbody")
        r = run(body=b"hi")  # no CT line: body starts right after the blank line
        p = parse_canonical(r.text)
        self.assertEqual((p.headers, p.body), ((), b"hi"))

    def test_parse_canonical_rejects_non_grammar(self):
        for t in ("", "GET / HTTP/1.1", "GET /a b HTTP/1.1\n", "GET / HTTP/1.0\n",
                  "GET / HTTP/1.1\nHost: x\n", "GET / HTTP/1.1\n\n", "GET / HTTP/1.1\nx"):
            with self.subTest(t=t):
                with self.assertRaises(ValueError):
                    parse_canonical(t)

    def test_wrong_types_are_programming_errors(self):
        with self.assertRaises(TypeError):
            canonicalize("x", L())
        with self.assertRaises(TypeError):
            canonicalize(P(), None)
        with self.assertRaises(TypeError):
            RequestParts(method="GET", target=b"/")
        with self.assertRaises(TypeError):
            RequestParts(method=b"GET", target=b"/", headers=[("a", b"b")])
        with self.assertRaises(TypeError):
            RequestParts(method=b"GET", target=b"/", body="str")

    def test_list_headers_accepted(self):
        r = canonicalize(RequestParts(b"GET", b"/", headers=[(b"A", b"b")]), L())
        self.assertAccept(r)

    def test_reject_precedence_chain(self):
        # R5 > R4 > R7 > R1 > R3
        self.assertReject(run(target=b"/a b", headers=[(b"X", b"\n"), CT(), CT()]), "R5")
        self.assertReject(run(headers=[(b"X", b"\n"), CT(), CT()]), "R4")
        self.assertReject(run(headers=[CT(), CT(), (b"Content-Length", b"x")]), "R7")
        self.assertReject(run(headers=[(b"Content-Length", b"x"), (b"Content-Encoding", b"foo")]),
                          "R1")
        # R2 (TE gzip) is checked with the framing, before R3
        self.assertReject(run(headers=[(b"Transfer-Encoding", b"gzip"),
                                       (b"Content-Encoding", b"foo")], body=b"x"), "R2")
        self.assertReject(run(headers=[(b"Content-Encoding", b"foo")], body=b"x" * 2000,
                              limits=L(100)), "R3")  # R3 before R8 cap


# ───────────────────────────── pathological regex / robustness ─────────────────────────────
def _run_isolated(ct_expr, timeout=8):
    code = (
        "import sys;sys.path.insert(0,%r);import canonical_request as c;"
        "ct=%s;"
        "r=c.canonicalize(c.RequestParts(b'GET',b'/',headers=((b'Content-Type',ct),),body=b'x'),"
        "c.Limits(1000));print(r.outcome)" % (DATA_PLANE_DIR, ct_expr))
    return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                          timeout=timeout)


class TestRobustness(Base):
    def test_linear_pathological_content_types_are_fast(self):
        for expr in ('b"a/b"+b";x=y"*20000+b"@"', 'b"a/b;x=\\""+b"\\\\a"*20000',
                     'b"a/b"+b" "*100000+b"\\x01"', 'b"a/"+b"b"*200000+b"\\x01"',
                     'b"a/b;x=\\""+b"a"*200000'):
            with self.subTest(expr=expr[:40]):
                p = _run_isolated(expr)
                self.assertEqual(p.returncode, 0, p.stderr[-300:])
                self.assertEqual(p.stdout.strip(), "ACCEPT")

    # REGRESSION (review finding, fixed 2026-10-13, D63): the media-type regex once backtracked
    # exponentially on "a/b" + "; "*n + "@" (n=40 -> hours), a DoS and an I7 bounded-time
    # failure. The match must stay linear; the subprocess timeout guards against regressions.
    def test_content_type_redos_bounded_time(self):
        for expr in ('b"a/b"+b"; "*40+b"@"', 'b"a/b"+b";\\t"*40+b"@"',
                     'b"text/plain"+b" ; "*40+b"\\x01"'):
            try:
                p = _run_isolated(expr, timeout=5)
            except subprocess.TimeoutExpired:
                self.fail(f"catastrophic backtracking on Content-Type {expr}")
            self.assertEqual(p.stdout.strip(), "ACCEPT")

    def test_large_inputs_do_not_raise(self):
        r = run(target=b"/" + b"a" * 2_000_000, limits=L(1 << 30))
        self.assertAccept(r)
        r = run(headers=[(b"X-" + bytes([i % 256]) * 3, b"v") for i in range(5000)])
        self.assertAccept(r)
        r = run(headers=[(b"Content-Encoding", b"gzip," * 20000)], body=b"")
        self.assertAccept(r)


# ───────────────────────────── I7 totality fuzz ─────────────────────────────
class TestTotalityFuzz(Base):
    N = 2500
    OUTCOMES = {ACCEPT, REJECT, UNSUPPORTED}

    @staticmethod
    def rbytes(rng, maxlen=40):
        mode = rng.random()
        n = rng.randint(0, maxlen)
        if mode < 0.4:
            return bytes(rng.randrange(256) for _ in range(n))
        if mode < 0.8:
            return bytes(rng.choice(b"/?&=%+;:, \t\r\n\x00\\\"'<>{}[]abcXYZ019.-_~*@#\xff\xc3\xa9")
                         for _ in range(n))
        return bytes(rng.randrange(0x20, 0x7F) for _ in range(n))

    def gen(self, rng):
        method = rng.choice([b"GET", b"POST", b"PUT", b"CONNECT", b"OPTIONS", b"get", b"PROPFIND",
                             b"M-SEARCH", b"", b"BAD M"]) if rng.random() < 0.7 else self.rbytes(rng, 10)
        r = rng.random()
        if r < 0.3:
            target = b"/" + self.rbytes(rng)
        elif r < 0.45:
            target = rng.choice([b"http://", b"https://", b"ftp://"]) + self.rbytes(rng)
        elif r < 0.55:
            target = rng.choice([b"*", b"", b"h:443", b"/", b"//", b"/%", b"/%u00", b"/?"])
        else:
            target = self.rbytes(rng)
        names = [b"Content-Type", b"content-type", b"Content-Encoding", b"Transfer-Encoding",
                 b"Content-Length", b"Host", b"Cookie", b"X-A"]
        headers = []
        for _ in range(rng.randint(0, 5)):
            name = rng.choice(names) if rng.random() < 0.9 else self.rbytes(rng, 12)
            k = rng.random()
            if name.lower() == b"content-type" and k < 0.6:
                value = rng.choice([b"text/plain", b"application/json", b"application/xml; x=y",
                                    b"application/x-www-form-urlencoded; charset=utf-8",
                                    b"a/b;" + self.rbytes(rng, 10), b'x/y; z="' + self.rbytes(rng, 8)])
            elif name.lower() == b"content-encoding" and k < 0.7:
                value = rng.choice([b"gzip", b"deflate", b"br", b"zstd", b"identity", b"gzip, br",
                                    b"foo", b"x-gzip", b"GZIP,", b""])
            elif name.lower() == b"transfer-encoding" and k < 0.7:
                value = rng.choice([b"chunked", b"gzip", b"chunked, gzip", b"", b"identity"])
            elif name.lower() == b"content-length" and k < 0.7:
                value = rng.choice([b"0", b"5", b"-1", b"x", b"1,2", str(rng.randint(0, 60)).encode()])
            else:
                value = self.rbytes(rng, 30)
            headers.append((name, value))
        b = rng.random()
        plain = self.rbytes(rng, 60)
        if b < 0.15:
            body = b""
        elif b < 0.55:
            body = plain
        elif b < 0.7:
            body = gz(plain)
        elif b < 0.8:
            body = zlib.compress(plain)
        elif b < 0.9:
            body = (gz(plain) if rng.random() < 0.5 else zlib.compress(plain))[:rng.randint(0, 20)]
        else:
            body = (brotli.compress(plain) if brotli else plain) if rng.random() < 0.5 else (
                zstandard.ZstdCompressor().compress(plain) if zstandard else plain)
        ver = rng.choice(["HTTP/1.1", "HTTP/1.0", "HTTP/2.0", "", "x"])
        cap = rng.choice([1, 10, 50, 5000, 1 << 20])
        kw = {}
        if rng.random() < 0.5:
            kw["token_budget"] = rng.choice([1, 20, 100, 435])
            kw["count_tokens"] = len if rng.random() < 0.5 else None
            if kw["count_tokens"] is None:
                kw["max_bytes_per_token"] = rng.choice([1, 2, 48])
        return P(method, target, headers, body, ver), Limits(cap, **kw)

    def test_totality_seeded(self):
        rng = random.Random(20261013)
        seen = {ACCEPT: 0, REJECT: 0, UNSUPPORTED: 0}
        rejects = {}
        for i in range(self.N):
            parts, lim = self.gen(rng)
            try:
                r = canonicalize(parts, lim)
            except Exception as e:  # noqa: BLE001
                self.fail(f"case {i}: {type(e).__name__}: {e}\n{parts!r}")
            self.assertIn(r.outcome, self.OUTCOMES)
            seen[r.outcome] += 1
            if r.outcome == ACCEPT:
                self.assertIsInstance(r.text, str)
                self.assertIsNone(r.reject)
                self.assertTrue(r.text.startswith(parts.method.decode() + " "))
                self.assertTrue(r.text.split("\n", 1)[0].endswith(" HTTP/1.1"))
                self.assertNotIn("\r\n\r\n", r.text.split("\n")[0])
                self.assertEqual(r.audit["text_sha256"] is not None, True)
                # I3/I8 on everything accepted (unbounded limits: escapes grow the text)
                big = Limits(10 ** 9)
                p = parse_canonical(r.text)
                self.assertEqual(canonicalize(p, big).text, r.text, f"case {i}")
            elif r.outcome == REJECT:
                self.assertIn(r.reject, {"R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8"})
                self.assertIsNone(r.text)
                self.assertTrue(r.reason)
                rejects[r.reject] = rejects.get(r.reject, 0) + 1
            else:
                self.assertIsNone(r.text)
                self.assertIn("S-CONNECT", r.signals)
            # determinism
            self.assertEqual(canonicalize(parts, lim), r)
        # the corpus must actually exercise every outcome and most rejects
        self.assertTrue(all(v > 0 for v in seen.values()), seen)
        self.assertGreaterEqual(len(rejects), 6, rejects)

    def test_totality_all_single_bytes_every_field(self):
        for b in range(256):
            x = bytes([b])
            for parts in (P(method=x), P(target=x), P(target=b"/" + x), P(body=x),
                          P(body=x, headers=[CT(x)]), P(headers=[(x, x)]),
                          P(headers=[(b"Content-Encoding", x)], body=b"y"),
                          P(headers=[(b"Transfer-Encoding", x)]),
                          P(headers=[(b"Content-Length", x)]),
                          P(headers=[CT(b"a/b;" + x)], body=b"y"),
                          P(method=b"CONNECT", target=x), P(target=b"http://" + x)):
                r = canonicalize(parts, L(100, token_budget=10, count_tokens=len))
                self.assertIn(r.outcome, self.OUTCOMES)


if __name__ == "__main__":
    unittest.main()
