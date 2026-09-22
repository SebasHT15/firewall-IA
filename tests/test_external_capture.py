"""External Test v1 — capture addon and byte-exact replay round-trip.

Needs mitmproxy, so it runs in the DATA PLANE environment:
    .venv-dataplane/bin/python -m unittest discover -s tests -p 'test_external_capture.py' -v
Under python3.12 it is reported as skipped, like tests/test_data_plane.py.

The round-trip test is the one that matters. External Test v1 freezes a request text,
labels it, and later replays it through the gateway. If replay does not reproduce that
exact text at the classifier, V4 is scored on something other than what was labelled and
the evaluation is void. So the full chain is exercised here against mitmproxy's own
parser, with no model and no network:

    rendered text --wire.to_wire()--> wire bytes --mitmproxy parse--> render_request() --> text
"""

import json
import os
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "data_plane"))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts", "external"))

try:
    from mitmproxy.net.http import http1
    from mitmproxy.test import tflow, tutils
    import data_plane
    import wire
    os.environ.setdefault("CAPTURE_OUT", os.path.join(tempfile.gettempdir(), "cap.jsonl"))
    import capture_addon
except ImportError as exc:                                  # pragma: no cover
    raise unittest.SkipTest(f"data plane environment required: {exc}")


def reparse(wire_bytes: bytes):
    """What mitmproxy makes of these bytes — the proxy's own parser, not a stand-in."""
    head, _, body = wire_bytes.partition(b"\r\n\r\n")
    req = http1.read_request_head(head.split(b"\r\n"))
    req.data.content = body          # direct: the .content setter would inject Content-Length
    return req


def roundtrip(text: str) -> str:
    return data_plane.render_request(reparse(wire.to_wire(text)))


class TestRendererIdentity(unittest.TestCase):
    """The capture addon must use the PRODUCTION renderer, not a copy of it.

    A second implementation of the D1 representation could drift from the data plane's,
    and every frozen case would then describe text the model is never shown. Same
    object-identity guarantee test_model has against inference_core.
    """

    def test_capture_addon_uses_the_data_plane_renderer_object(self):
        self.assertIs(capture_addon.render_request, data_plane.render_request)

    def test_capture_addon_registers_no_enforcing_addon(self):
        # Importing data_plane constructs a FirewallGateway as a module-level side effect.
        # It must never reach mitmproxy's addon list: this proxy classifies nothing.
        self.assertEqual(len(capture_addon.addons), 1)
        self.assertIsInstance(capture_addon.addons[0], capture_addon.CaptureAddon)
        for addon in capture_addon.addons:
            self.assertNotIsInstance(addon, data_plane.FirewallGateway)


class TestCaptureAddon(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = os.path.join(self.tmp.name, "capture.jsonl")
        self.addon = capture_addon.CaptureAddon(out_path=self.out, tag="unit")
        self.addCleanup(self.tmp.cleanup)

    def record(self, flow):
        self.addon.request(flow)
        with open(self.out, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def test_records_the_rendered_text_and_its_hash(self):
        flow = tflow.tflow(req=tutils.treq(method=b"GET", path=b"/products?a=1"))
        rec = self.record(flow)[-1]
        self.assertEqual(rec["request_text"], data_plane.render_request(flow.request))
        self.assertEqual(rec["request_sha256"], wire.sha256_text(rec["request_text"]))
        self.assertEqual(rec["tag"], "unit")

    def test_does_not_answer_or_block_the_flow(self):
        flow = tflow.tflow(req=tutils.treq())
        flow.response = None
        self.addon.request(flow)
        self.assertIsNone(flow.response, "the capture proxy must forward everything")

    def test_sequence_numbers_increase(self):
        for _ in range(3):
            self.addon.request(tflow.tflow(req=tutils.treq()))
        with open(self.out, encoding="utf-8") as f:
            seqs = [json.loads(line)["seq"] for line in f if line.strip()]
        self.assertEqual(seqs, [1, 2, 3])


class TestByteExactRoundTrip(unittest.TestCase):
    """rendered -> wire -> mitmproxy -> rendered must be the identity function."""

    def assert_roundtrip(self, text):
        self.assertEqual(roundtrip(text), text)
        self.assertEqual(wire.sha256_text(roundtrip(text)), wire.sha256_text(text))

    def test_simple_get(self):
        self.assert_roundtrip("GET /products HTTP/1.1\nHost: shop.fwlab.test:9100\n"
                              "Accept: text/html")

    def test_query_parameters_including_encoded_values(self):
        self.assert_roundtrip("GET /search?q=espresso%20beans&page=2&sort=price HTTP/1.1\n"
                              "Host: shop.fwlab.test:9100\nAccept: */*")

    def test_header_order_and_repeats_survive(self):
        self.assert_roundtrip("GET /cart HTTP/1.1\nHost: shop.fwlab.test:9100\n"
                              "Cookie: fwlab_session=u%3Dlab-user\n"
                              "Cookie: fwlab_cart=2x1\n"
                              "Accept-Language: en-GB,en;q=0.9\n"
                              "User-Agent: Mozilla/5.0 (X11; Linux x86_64)")

    def test_post_form_body(self):
        body = "address=12+Lab+Street&card_last4=0000"
        self.assert_roundtrip(f"POST /checkout HTTP/1.1\nHost: shop.fwlab.test:9100\n"
                              f"Content-Type: application/x-www-form-urlencoded\n"
                              f"Content-Length: {len(body)}\n\n{body}")

    def test_post_json_body(self):
        body = '{"product_id": 4, "quantity": 3, "note": "leave at reception"}'
        self.assert_roundtrip(f"POST /api/orders HTTP/1.1\nHost: api.fwlab.test:9100\n"
                              f"Content-Type: application/json\n"
                              f"Content-Length: {len(body)}\n\n{body}")

    def test_non_ascii_query_survives(self):
        self.assert_roundtrip("GET /search?q=caf%C3%A9 HTTP/1.1\n"
                              "Host: shop.fwlab.test:9100\nAccept: */*")

    def test_payload_bearing_request_is_not_altered_in_transit(self):
        # An authorized lab attack case. Replay must not normalise, decode or re-encode
        # any part of it; the model has to see exactly the frozen bytes.
        self.assert_roundtrip(
            "GET /products?category=office%27%20OR%20%271%27%3D%271 HTTP/1.1\n"
            "Host: shop.fwlab.test:9100\nAccept: */*\n"
            "User-Agent: python-httpx/0.28.1")

    def test_capture_of_a_replayed_request_matches_the_original_capture(self):
        """The exact property fidelity_check.py verifies at runtime, in miniature."""
        original = ("GET /products?category=sport&page=2 HTTP/1.1\n"
                    "Host: shop.fwlab.test:9100\nAccept: text/html\n"
                    "User-Agent: Mozilla/5.0")
        captured_again = data_plane.render_request(reparse(wire.to_wire(original)))
        self.assertEqual(wire.sha256_text(captured_again), wire.sha256_text(original))


if __name__ == "__main__":
    unittest.main()
