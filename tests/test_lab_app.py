"""lab-app receipt log — /healthz exclusion (docker/lab-app/app.py).

Needs Flask, which is present in the DATA PLANE environment (mitmproxy depends on it):
    .venv-dataplane/bin/python -m unittest discover -s tests -p 'test_lab_app.py' -v
Under python3.12 it is reported as skipped.

The receipt log is External v1 evidence: it is how "this request reached the destination"
becomes a recorded fact for L2 and L3. Two properties matter and pull in opposite
directions, so both are pinned:

  1. the container's own healthcheck must NOT pollute the log;
  2. no request that arrives through a proxy may ever go unrecorded — not even one to
     /healthz — or a delivered request would be scored as not delivered.
"""

import importlib
import json
import os
import sys
import tempfile
import unittest

APP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "docker", "lab-app")

try:
    import flask  # noqa: F401
except ImportError as exc:                                  # pragma: no cover
    raise unittest.SkipTest(f"Flask required (data plane environment): {exc}")

PROXY_ADDR = "172.18.0.5"      # what a request forwarded by capture-proxy/data-plane carries


class LabAppTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = os.path.join(self.tmp.name, "lab-app-access.jsonl")
        os.environ["ACCESS_LOG"] = self.log
        sys.path.insert(0, APP_DIR)
        self.addCleanup(sys.path.remove, APP_DIR)
        sys.modules.pop("app", None)
        self.app_module = importlib.import_module("app")     # reads ACCESS_LOG at import
        self.client = self.app_module.app.test_client()

    def get(self, path, remote=PROXY_ADDR, **kw):
        return self.client.get(path, environ_base={"REMOTE_ADDR": remote}, **kw)

    def receipts(self):
        if not os.path.exists(self.log):
            return []
        with open(self.log, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]


class TestHealthcheckExclusion(LabAppTestCase):
    def test_container_healthcheck_is_served(self):
        self.assertEqual(self.get("/healthz", remote="127.0.0.1").status_code, 200)

    def test_container_healthcheck_is_not_recorded(self):
        self.get("/healthz", remote="127.0.0.1")
        self.get("/healthz", remote="::1")
        self.assertEqual(self.receipts(), [])

    def test_proxied_request_to_healthz_IS_recorded(self):
        # The blind spot a path-only exclusion would have created.
        self.assertEqual(self.get("/healthz", remote=PROXY_ADDR).status_code, 200)
        rec = self.receipts()
        self.assertEqual(len(rec), 1)
        self.assertEqual(rec[0]["path"], "/healthz")

    def test_only_healthz_is_exempt_from_loopback(self):
        # Loopback in general is not exempt: only the healthcheck path is.
        self.get("/products", remote="127.0.0.1")
        self.assertEqual([r["path"] for r in self.receipts()], ["/products"])


class TestReceiptsUnchangedForTraffic(LabAppTestCase):
    """Every other request is recorded exactly as before the change."""

    def test_proxied_traffic_is_recorded_with_its_query(self):
        self.get("/products?category=office&page=2")
        rec = self.receipts()
        self.assertEqual(len(rec), 1)
        self.assertEqual(rec[0]["path"], "/products?category=office&page=2")
        self.assertEqual(rec[0]["method"], "GET")

    def test_request_is_recorded_even_when_the_route_does_not_exist(self):
        # A 404 still means the request REACHED the destination.
        self.assertEqual(self.get("/favicon.ico").status_code, 404)
        self.assertEqual([r["path"] for r in self.receipts()], ["/favicon.ico"])

    def test_post_is_recorded(self):
        self.client.post("/api/orders", json={"product_id": 1, "quantity": 2},
                         environ_base={"REMOTE_ADDR": PROXY_ADDR})
        rec = self.receipts()
        self.assertEqual(rec[0]["method"], "POST")
        self.assertGreater(rec[0]["content_length"], 0)

    def test_routes_still_respond_as_before(self):
        for path, status in (("/", 200), ("/products", 200), ("/products/1", 200),
                             ("/products/999", 404), ("/search?q=mug", 200),
                             ("/api/products", 200), ("/api/me", 200)):
            with self.subTest(path=path):
                self.assertEqual(self.get(path).status_code, status)


class TestReflectedValuesAreEscaped(LabAppTestCase):
    """The lab app must be INERT (protocol 5.1): request-derived values reflected into an
    HTML response are escaped text, never live markup. Regression guard for the removal of
    {{ body|safe }}. These are captured REQUESTS in External v1, so this changes no candidate
    text; it only proves a reflected payload cannot execute if a browser renders a response.
    """

    XSS = "<script>alert(1)</script>"
    IMG = "<img src=x onerror=alert(1)>"

    def html(self, resp):
        self.assertEqual(resp.mimetype, "text/html")
        return resp.get_data(as_text=True)

    def assert_inert(self, html, real_tag, escaped_marker):
        # the real tag opener must NOT appear (no element is created); the escaped form must.
        self.assertNotIn(real_tag, html, f"{real_tag!r} rendered as live markup")
        self.assertIn(escaped_marker, html)

    def test_search_query_is_escaped(self):
        from urllib.parse import quote
        html = self.html(self.get("/search?q=" + quote(self.XSS)))
        self.assert_inert(html, "<script", "&lt;script&gt;")

    def test_products_category_is_escaped(self):
        from urllib.parse import quote
        html = self.html(self.get("/products?category=" + quote(self.IMG)))
        self.assert_inert(html, "<img", "&lt;img")

    def test_unknown_product_id_is_escaped(self):
        # '<script>' has no slash, so it is a single path segment -> 404 "no product ..."
        resp = self.get("/products/<script>")
        self.assertEqual(resp.status_code, 404)
        self.assert_inert(self.html(resp), "<script", "&lt;script&gt;")

    def test_session_cookie_is_escaped_on_profile(self):
        self.client.set_cookie("fwlab_session", self.XSS)
        resp = self.get("/profile")
        self.assertEqual(resp.status_code, 200)          # a session is present -> profile page
        self.assert_inert(self.html(resp), "<script", "&lt;script&gt;")

    def test_cart_cookie_is_escaped(self):
        self.client.set_cookie("fwlab_cart", self.IMG)
        resp = self.get("/cart")
        self.assert_inert(self.html(resp), "<img", "&lt;img")

    def test_checkout_form_keys_are_escaped(self):
        resp = self.client.post("/checkout", data={self.XSS: "1"},
                                environ_base={"REMOTE_ADDR": PROXY_ADDR})
        self.assert_inert(resp.get_data(as_text=True), "<script", "&lt;script&gt;")

    def test_attribute_breakout_quotes_are_escaped(self):
        from urllib.parse import quote
        html = self.html(self.get("/search?q=" + quote('a" onmouseover="alert(1)')))
        # both the double quote and the payload survive only as escaped text
        self.assertIn("&#34;", html)
        self.assertNotIn('" onmouseover="', html)

    def test_form_structure_preserved_for_browser_flows(self):
        # the DOM the Playwright flows drive must be intact, or capture traffic would change
        search = self.html(self.get("/search"))
        self.assertIn("name='q'", search)
        self.assertIn("action='/search'", search)
        product = self.html(self.get("/products/1"))
        self.assertIn("name='product_id'", product)
        self.assertIn("action='/cart'", product)
        self.assertIn("name='quantity'", product)
        cart = self.html(self.get("/cart"))
        self.assertIn("action='/checkout'", cart)
        self.assertIn("name='card_last4'", cart)

    def test_benign_values_still_visible_as_text(self):
        # escaping must not drop the value; a normal category is still shown
        html = self.html(self.get("/products?category=office"))
        self.assertIn("category=office", html)


class TestShouldRecordPredicate(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, APP_DIR)
        self.addCleanup(sys.path.remove, APP_DIR)
        os.environ.setdefault("ACCESS_LOG", os.path.join(tempfile.gettempdir(), "x.jsonl"))
        sys.modules.pop("app", None)
        self.m = importlib.import_module("app")

    def test_truth_table(self):
        cases = [("/healthz", "127.0.0.1", False), ("/healthz", "::1", False),
                 ("/healthz", PROXY_ADDR, True), ("/products", "127.0.0.1", True),
                 ("/products", PROXY_ADDR, True), ("/healthz/x", "127.0.0.1", True)]
        for path, addr, expected in cases:
            with self.subTest(path=path, addr=addr):
                self.assertIs(self.m.should_record(path, addr), expected)


if __name__ == "__main__":
    unittest.main()
