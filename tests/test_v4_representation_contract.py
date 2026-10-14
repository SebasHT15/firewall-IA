"""Characterization tests: how a request becomes the text V4 scores.

These tests PIN CURRENT BEHAVIOUR of the existing V4 representation. They do not
assert that the behaviour is right; several of the pinned facts are train/serve
differences that the V5 canonical-input work (issue #64, Workstream A) wants to
remove. If one of these tests fails after an intentional change, update it in the
same commit and say so: the failure is the signal that the V4 representation moved.

See reports/v5/freeze-prep/A_http_representation_audit.md for what each pin means.

Two halves, two environments:

* SERVING side, `data_plane.render_request()` (mitmproxy request -> text sent to
  /classify). Needs the data plane environment (mitmproxy + httpx); otherwise these
  classes are skipped:
      .venv-dataplane/bin/python -m unittest tests.test_v4_representation_contract -v
* TRAINING side, `scripts/dataset/parse_dataset_v4.py` (`render_request`,
  `build_envelope`, `canonical_key`). Standard library only at import time (pandas is
  imported lazily inside load_csic), so these run in any environment.

No GPU, no model, no network, no mitmproxy process and no dataset file: every input
is a small synthetic request or a seeded call of the generator. Behaviour already
pinned in tests/test_data_plane.py (no-body layout, blank line before the body,
headers as received, D1 round trip over eval.jsonl) and in tests/test_request_features.py
(Host/User-Agent never features) is deliberately not asserted again here.
"""

import gzip
import json
import os
import random
import re
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "data_plane"))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts", "dataset"))

import parse_dataset_v4 as gen  # noqa: E402  (training-side renderer; stdlib at import)

try:
    import httpx
    from mitmproxy import http
    from mitmproxy.test import tflow, tutils
    import data_plane
    HAVE_DATA_PLANE_ENV = True
except ImportError:  # the ML environment has neither mitmproxy nor httpx
    HAVE_DATA_PLANE_ENV = False

needs_data_plane = unittest.skipUnless(
    HAVE_DATA_PLANE_ENV, "needs the data plane environment (.venv-dataplane)")


# ── Helpers ───────────────────────────────────────────────────────────────
def _b(value):
    return value if isinstance(value, bytes) else value.encode()


def make_request(method="GET", path="/", headers=None, content=b"",
                 http_version=b"HTTP/1.1", scheme="http", port=80):
    """A mitmproxy request with exactly these headers (same idiom as test_data_plane)."""
    headers = headers if headers is not None else [("Host", "h.example")]
    return tutils.treq(
        method=_b(method), path=_b(path), host="h.example", port=port, scheme=_b(scheme),
        http_version=http_version,
        headers=http.Headers([(_b(k), _b(v)) for k, v in headers]), content=content)


def split_text(text):
    """(request_line, header_lines, body) of a rendered request, the way the model's
    own training texts are laid out. The body is None when there is no blank line."""
    head, sep, body = text.partition("\n\n")
    request_line, *header_lines = head.split("\n")
    return request_line, header_lines, (body if sep else None)


def header_names(text):
    return [line.split(":", 1)[0] for line in split_text(text)[1]]


def render_with(shape, payload, seeds=range(400), **kw):
    """Yield (seed, text) of the training renderer for `shape`, one per seed."""
    for seed in seeds:
        yield seed, gen.render_request(random.Random(seed), shape, payload, **kw)


def first(shape, payload, predicate, **kw):
    """The first seeded rendering for which predicate(text) holds."""
    for _, text in render_with(shape, payload, **kw):
        if predicate(text):
            return text
    raise AssertionError(f"no seed in range produced a matching {shape} request")


# ══════════════════════════════════════════════════════════════════════════
# SERVING SIDE
# ══════════════════════════════════════════════════════════════════════════
@needs_data_plane
class TestServingFraming(unittest.TestCase):
    """What the classifier text says about framing (notes F and G)."""

    def test_chunked_keeps_its_header_and_adds_no_content_length(self):
        # mitmproxy hands the addon a de-chunked body and leaves the TE header alone.
        req = make_request("POST", "/login", content=b"q=1", headers=[
            ("Host", "h.example"), ("Transfer-Encoding", "chunked"),
            ("Content-Type", "application/x-www-form-urlencoded")])
        self.assertEqual(
            data_plane.render_request(req),
            "POST /login HTTP/1.1\nHost: h.example\nTransfer-Encoding: chunked\n"
            "Content-Type: application/x-www-form-urlencoded\n\nq=1")

    def test_content_length_is_rendered_as_received_even_when_it_is_wrong(self):
        # The renderer never recomputes or validates the framing headers.
        req = make_request("POST", "/", content=b"q=1",
                           headers=[("Host", "h.example"), ("Content-Length", "99")])
        self.assertEqual(data_plane.render_request(req),
                         "POST / HTTP/1.1\nHost: h.example\nContent-Length: 99\n\nq=1")

    def test_gzip_body_is_shown_decoded_under_the_compressed_content_length(self):
        compressed = gzip.compress(b"q=hello")
        req = make_request("POST", "/", content=compressed, headers=[
            ("Host", "h.example"), ("Content-Encoding", "gzip"),
            ("Content-Length", str(len(compressed)))])
        text = data_plane.render_request(req)
        self.assertEqual(split_text(text)[2], "q=hello")
        self.assertIn(f"Content-Length: {len(compressed)}", text)
        self.assertNotEqual(len(compressed), len(b"q=hello"))

    def test_undecodable_or_unknown_content_encoding_leaves_the_body_as_is(self):
        for encoding, body in (("gzip", b"not gzip at all"), ("x-unknown", b"q=1")):
            with self.subTest(encoding=encoding):
                req = make_request("POST", "/", content=body, headers=[
                    ("Host", "h.example"), ("Content-Encoding", encoding)])
                self.assertEqual(split_text(data_plane.render_request(req))[2],
                                 body.decode())

    def test_framing_and_hop_by_hop_headers_are_not_filtered(self):
        names = ["Connection", "Proxy-Connection", "Keep-Alive", "Upgrade", "TE",
                 "Transfer-Encoding", "Content-Length", "Content-Encoding"]
        req = make_request("POST", "/", content=b"q=1",
                           headers=[("Host", "h.example")] + [(n, "x") for n in names])
        self.assertEqual(header_names(data_plane.render_request(req)), ["Host"] + names)

    def test_obs_fold_and_lone_cr_survive_into_one_rendered_header(self):
        req = make_request(headers=[("Host", "h.example"), ("X-Fold", "a\r\n b"),
                                    ("X-Cr", "a\rb")])
        text = data_plane.render_request(req)
        self.assertIn("X-Fold: a\r\n b", text)
        self.assertIn("X-Cr: a\rb", text)


@needs_data_plane
class TestServingEncoding(unittest.TestCase):
    """Path, query and body encoding as the model sees it."""

    def test_percent_encoding_is_neither_decoded_nor_normalized(self):
        path = "/p%2Fq?a=%27%2527+b&c=%23&d=%2f&e=%E2%82%AC"
        self.assertEqual(data_plane.render_request(make_request(path=path)),
                         f"GET {path} HTTP/1.1\nHost: h.example")

    def test_form_body_percent_encoding_is_kept_verbatim(self):
        body = b"user=O%27Brien&pw=a%23b%21&note=a+b%2Bc"
        req = make_request("POST", "/", content=body, headers=[
            ("Host", "h.example"), ("Content-Type", "application/x-www-form-urlencoded")])
        self.assertEqual(split_text(data_plane.render_request(req))[2], body.decode())

    def test_json_body_is_kept_verbatim_including_escapes_and_spacing(self):
        body = b'{"a":1, "b" :"\\u0027",\n"c":[1,2]}'
        req = make_request("POST", "/", content=body, headers=[
            ("Host", "h.example"), ("Content-Type", "application/json")])
        self.assertEqual(split_text(data_plane.render_request(req))[2], body.decode())

    def test_body_bytes_are_decoded_as_utf8_with_replacement(self):
        # Content-Type charset is ignored; invalid bytes collapse to U+FFFD, so two
        # different byte strings can render to the same text.
        text_a = data_plane.render_request(make_request("POST", content=b"a=\xff\xfeb"))
        text_b = data_plane.render_request(make_request("POST", content=b"a=\xc3\x28b"))
        self.assertTrue(split_text(text_a)[2].startswith("a=\ufffd\ufffd"))
        self.assertIn("\ufffd", split_text(text_b)[2])
        latin1 = make_request("POST", content="é".encode("latin-1"), headers=[
            ("Host", "h.example"), ("Content-Type", "text/plain; charset=latin-1")])
        self.assertEqual(split_text(data_plane.render_request(latin1))[2], "\ufffd")

    def test_utf8_bom_and_whitespace_only_bodies_are_kept(self):
        bom = data_plane.render_request(make_request("POST", content=b"\xef\xbb\xbfa=1"))
        self.assertEqual(split_text(bom)[2], "\ufeffa=1")
        newline = data_plane.render_request(make_request("POST", content=b"\n"))
        self.assertTrue(newline.endswith("\n\n\n"))

    def test_crlf_and_blank_lines_inside_the_body_are_kept(self):
        body = b"0\r\n\r\nX\n\nY"
        text = data_plane.render_request(make_request("POST", content=body))
        self.assertEqual(split_text(text)[2], "0\r\n\r\nX\n\nY")

    def test_non_utf8_path_and_header_bytes_become_lone_surrogates(self):
        # surrogateescape in mitmproxy's str view of the target and the headers.
        path_text = data_plane.render_request(make_request(path=b"/a?q=\xff"))
        self.assertIn("\udcff", path_text)
        header_text = data_plane.render_request(
            make_request(headers=[("Host", "h.example"), ("X-Bin", b"\xff\xfe")]))
        self.assertIn("X-Bin: \udcff\udcfe", header_text)
        with self.assertRaises(UnicodeEncodeError):
            path_text.encode("utf-8")


@needs_data_plane
class TestServingRequestLine(unittest.TestCase):
    def test_http_version_is_rendered_verbatim(self):
        # The training generator only ever writes HTTP/1.1.
        for version in (b"HTTP/1.0", b"HTTP/2.0"):
            with self.subTest(version=version):
                text = data_plane.render_request(make_request(http_version=version))
                self.assertEqual(split_text(text)[0], f"GET / {version.decode()}")

    def test_scheme_and_port_are_not_part_of_the_text(self):
        plain = data_plane.render_request(make_request(scheme="http", port=80))
        tls = data_plane.render_request(make_request(scheme="https", port=443))
        self.assertEqual(plain, tls)

    def test_method_is_uppercased_by_mitmproxy(self):
        self.assertEqual(split_text(data_plane.render_request(make_request("get")))[0],
                         "GET / HTTP/1.1")

    def test_empty_query_marker_is_kept(self):
        self.assertEqual(split_text(data_plane.render_request(make_request(path="/?")))[0],
                         "GET /? HTTP/1.1")

    def test_there_is_no_size_limit_in_the_renderer(self):
        body = b"a=" + b"x" * 300_000
        text = data_plane.render_request(make_request("POST", content=body))
        self.assertEqual(len(split_text(text)[2]), len(body))


@needs_data_plane
class TestServingFailClosedOnUnencodableText(unittest.IsolatedAsyncioTestCase):
    """A non-UTF-8 byte in the target or a header makes the text unserializable as
    JSON, so the classifier is never asked: the addon's catch-all blocks with 503."""

    async def run_addon(self, req):
        seen = []

        def handler(request):
            seen.append(request)
            return httpx.Response(200, json={"status": "ok", "decision": "ALLOW",
                                             "reason": "r", "model_latency_ms": 1.0})
        gateway = data_plane.FirewallGateway("http://classifier.test/classify", 1.0,
                                             transport=httpx.MockTransport(handler))
        flow = tflow.tflow(req=req)
        with self.assertLogs("firewall.data_plane", level="ERROR") as logs:
            await gateway.request(flow)
        return flow, seen, "\n".join(logs.output)

    async def test_non_utf8_target_is_blocked_with_503_and_never_classified(self):
        flow, seen, log_text = await self.run_addon(make_request(path=b"/a?q=\xff"))
        self.assertEqual(seen, [])
        self.assertEqual(flow.response.status_code, 503)
        self.assertIn("unexpected data plane error", log_text)

    async def test_non_utf8_body_is_classified_with_replacement_characters(self):
        seen = []

        def handler(request):
            seen.append(json.loads(request.content)["request"])
            return httpx.Response(200, json={"status": "ok", "decision": "ALLOW",
                                             "reason": "r", "model_latency_ms": 1.0})
        gateway = data_plane.FirewallGateway("http://classifier.test/classify", 1.0,
                                             transport=httpx.MockTransport(handler))
        flow = tflow.tflow(req=make_request("POST", content=b"a=\xffb"))
        await gateway.request(flow)
        self.assertIsNone(flow.response)
        self.assertEqual(seen, ["POST / HTTP/1.1\nHost: h.example\n\na=\ufffdb"])


# ══════════════════════════════════════════════════════════════════════════
# TRAINING SIDE  (parse_dataset_v4.py)
# ══════════════════════════════════════════════════════════════════════════
class TestTrainingEnvelope(unittest.TestCase):
    ORDER = ["Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding",
             "Connection", "X-Requested-With", "Cookie"]

    def test_envelope_header_order_is_fixed_not_randomised(self):
        # build_envelope's docstring says the order is randomised; the code draws only
        # PRESENCE. Host is always first and the relative order never changes.
        for seed in range(500):
            names = [n for n, _ in gen.build_envelope(random.Random(seed))]
            self.assertEqual(names[0], "Host")
            self.assertEqual(names, sorted(names, key=self.ORDER.index), seed)

    def test_envelope_never_contains_framing_or_hop_by_hop_extras(self):
        seen = set()
        for seed in range(500):
            seen.update(n for n, _ in gen.build_envelope(random.Random(seed)))
        self.assertTrue(seen <= set(self.ORDER))
        for name in ("Content-Length", "Transfer-Encoding", "Proxy-Connection",
                     "Keep-Alive", "Expect", "Upgrade", "TE", "Content-Encoding"):
            self.assertNotIn(name, seen)

    def test_user_agent_and_host_come_from_pools_shared_by_both_classes(self):
        hosts, agents = set(), set()
        for seed in range(500):
            for name, value in gen.build_envelope(random.Random(seed)):
                if name == "Host":
                    hosts.add(value)
                elif name == "User-Agent":
                    agents.add(value)
        self.assertTrue(hosts <= set(gen.HOSTS))
        self.assertTrue(agents <= set(gen.USER_AGENTS))


class TestTrainingRendering(unittest.TestCase):
    def test_request_line_is_always_http_1_1_and_lines_are_lf_separated(self):
        for shape in gen.SHAPES:
            for seed in range(25):
                text = gen.render_request(random.Random(seed), shape, None)
                request_line, headers, _ = split_text(text)
                self.assertRegex(request_line, r"^[A-Z]+ \S+ HTTP/1\.1$")
                self.assertTrue(all(": " in h for h in headers))
                self.assertFalse(text.startswith("\n"))

    def test_content_length_appears_only_in_the_framing_shape(self):
        # Training bodies carry no Content-Length, unlike nearly every real client body.
        for shape in gen.SHAPES:
            for seed in range(60):
                text = gen.render_request(random.Random(seed), shape, None)
                has_cl = "Content-Length" in header_names(text)
                self.assertEqual(has_cl, shape == "framing_headers", (shape, seed))

    def test_transfer_encoding_is_never_rendered_for_benign_requests(self):
        for shape in gen.SHAPES:
            for seed in range(60):
                text = gen.render_request(random.Random(seed), shape, None)
                self.assertNotIn("Transfer-Encoding", header_names(text), (shape, seed))

    def test_benign_framing_counterpart_has_an_exact_content_length_before_content_type(self):
        text = gen.render_request(random.Random(1), "framing_headers", "data=abcdef123456")
        _, headers, body = split_text(text)
        self.assertEqual(body, "data=abcdef123456")
        self.assertEqual(headers[-2], f"Content-Length: {len(body)}")
        self.assertTrue(headers[-1].startswith("Content-Type: "))

    def test_smuggling_rows_carry_literal_crlf_and_conflicting_framing_in_the_text(self):
        structural = {"variant": "CL.TE",
                      "headers": [("Content-Length", "13"), ("Transfer-Encoding", "chunked")],
                      "body": "0\r\n\r\nSMUGGLED"}
        text = gen.render_request(random.Random(1), "framing_headers", None,
                                  structural=structural, category="Request Smuggling")
        request_line, headers, body = split_text(text)
        self.assertTrue(request_line.startswith("POST "))
        self.assertEqual(headers[-3:-1], ["Content-Length: 13", "Transfer-Encoding: chunked"])
        # Real CR and LF characters, not escapes. mitmproxy would reject this request
        # (TE + CL) before the addon, and would de-chunk a valid one.
        self.assertEqual(body, "0\r\n\r\nSMUGGLED")

    def test_obfuscated_te_variants_render_the_odd_bytes_verbatim(self):
        by_label = {label: (headers, body)
                    for label, headers, body in gen.SMUGGLING_VARIANTS}
        headers, body = by_label["TE space"]
        text = gen.render_request(random.Random(2), "framing_headers", None,
                                  structural={"variant": "TE space", "headers": headers,
                                              "body": body},
                                  category="Request Smuggling")
        self.assertIn("\nTransfer-Encoding : chunked\n", text)
        headers, body = by_label["TE tab"]
        text = gen.render_request(random.Random(2), "framing_headers", None,
                                  structural={"variant": "TE tab", "headers": headers,
                                              "body": body},
                                  category="Request Smuggling")
        self.assertIn("\nTransfer-Encoding: \tchunked\n", text)

    def test_attack_payload_is_percent_encoded_exactly_once_in_the_query(self):
        text = first("file_param", "' OR 1=1", lambda t: t.startswith("GET "),
                     param_name="q", category="SQL Injection")
        self.assertIn("?q=%27%20OR%201%3D1 HTTP/1.1", text)

    def test_payload_that_is_already_encoded_gets_a_second_layer(self):
        # quote(safe="") re-encodes the "%": the model is trained on %25XX for such
        # sources, while a client that encodes once sends %XX.
        text = first("file_param", "%27%20OR", lambda t: t.startswith("GET "),
                     param_name="q", category="SQL Injection")
        self.assertIn("?q=%2527%2520OR ", text)

    def test_form_body_is_quote_encoded_with_percent20_never_plus(self):
        text = first("form_post", "a b'c#d!", lambda t: t.startswith("POST "),
                     param_name="note", category="SQL Injection")
        self.assertEqual(split_text(text)[2], "note=a%20b%27c%23d%21")

    def test_json_attack_body_uses_python_default_separators(self):
        text = first("json_body", "x", lambda t: t.startswith("POST "),
                     category="NoSQL Injection")
        body = split_text(text)[2]
        self.assertRegex(body, r'^\{"[a-z]+": "x"\}$')  # ", " and ": ", never compact

    def test_benign_form_style_body_can_be_labelled_application_json(self):
        # Generator artifact: for shapes that allow both content types, the benign
        # branch writes "name=value" whatever Content-Type was drawn.
        mismatches = 0
        for _, text in render_with("query_param", None, seeds=range(300)):
            _, headers, body = split_text(text)
            if body is not None and "Content-Type: application/json" in headers:
                with self.assertRaises(ValueError):
                    json.loads(body)
                self.assertRegex(body, r"^[a-z_]+=")
                mismatches += 1
        self.assertGreater(mismatches, 0)


class TestTrainingRenderingMatchesServingRenderer(unittest.TestCase):
    """File-independent form of test_data_plane's D1 round-trip: generator text ->
    mitmproxy request -> data_plane.render_request gives the same text back. It shows
    the two LAYOUTS agree; it says nothing about whether the two DISTRIBUTIONS do."""

    @needs_data_plane
    def test_generated_rows_survive_a_trip_through_the_serving_renderer(self):
        texts = []
        for shape in gen.SHAPES:
            for seed in range(20):
                texts.append(gen.render_request(random.Random(seed), shape, None))
                if shape not in ("framing_headers", "repeated_params"):
                    texts.append(gen.render_request(random.Random(seed), shape, "' or 1=1 --",
                                                    param_name="q", category="SQL Injection"))
        for label, headers, body in gen.SMUGGLING_VARIANTS:
            texts.append(gen.render_request(
                random.Random(3), "framing_headers", None,
                structural={"variant": label, "headers": headers, "body": body},
                category="Request Smuggling"))
        for text in texts:
            request_line, header_lines, body = split_text(text)
            method, rest = request_line.split(" ", 1)
            target, version = rest.rsplit(" ", 1)
            req = tutils.treq(
                method=method.encode(), path=target.encode(), http_version=version.encode(),
                headers=http.Headers([tuple(p.encode() for p in line.split(": ", 1))
                                      for line in header_lines]),
                content=(body or "").encode())
            self.assertEqual(data_plane.render_request(req), text)


class TestCanonicalKeyIsAGroupingKeyNotAModelInput(unittest.TestCase):
    """D16: canonical_key collapses variants for the grouped split. It is lossy
    (lower-cases, decodes) and must not be confused with a canonical model input."""

    def test_decodes_at_most_three_percent_layers(self):
        self.assertEqual(gen.canonical_key("%252527"), "'")       # 3 layers: fully decoded
        self.assertEqual(gen.canonical_key("%25252527"), "%27")   # 4 layers: one remains

    def test_encoding_case_and_whitespace_variants_share_one_key(self):
        variants = ["' OR 1=1", "%27%20OR%201%3D1", "%27+or+1%3d1", "' Or\t1=1", "'  OR   1=1"]
        self.assertEqual({gen.canonical_key(v) for v in variants}, {"' or 1=1"})

    def test_plus_is_a_space_everywhere_and_comments_are_removed(self):
        self.assertEqual(gen.canonical_key("a+b"), "a b")
        self.assertEqual(gen.canonical_key("SEL/**/ECT"), "select")
        self.assertEqual(gen.canonical_key("cat${IFS}x"), "cat x")

    def test_key_is_not_the_text_the_model_sees(self):
        payload = "O%27Brien"
        self.assertNotEqual(gen.canonical_key(payload), payload)
        self.assertEqual(gen.canonical_key(payload), "o'brien")

    def test_html_and_unicode_escapes_collapse_onto_the_plain_character(self):
        for variant in ("&lt;script&gt;", "\\u003cscript\\u003e", "%3Cscript%3E"):
            self.assertEqual(gen.canonical_key(variant), "<script>")


if __name__ == "__main__":
    unittest.main()
