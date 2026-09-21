"""External Test v1 — benign ALLOW candidate specs for the client-driven slices.

Three of the five benign slices are produced by non-browser real clients and are therefore
enumerable up front (the browser slices are procedural and are captured whole, one record
per real request, by drive_traffic.py's Playwright flows):

    api-json          Python httpx, JSON GET/POST/PUT against the API routes, varied bodies
    api-query         curl, query-parameter-heavy GETs: filters, pagination, sorting, encoding
    unseen-structure  mixed curl/httpx, benign requests whose STRUCTURE has zero / near-zero
                      support in datasets/v4_clean/ (protocol 4.3, RQ4)

Every request is a legitimate interaction the lab application is designed (or would
reasonably be expected) to serve, so ground truth is ALLOW, assigned before exposure from
the intent of the flow — never from a V4 prediction.

UNSEEN-STRUCTURE IS UNSEEN-INPUT ROBUSTNESS, NOT OOD DETECTION (protocol 4.3, RQ4). The
structural axes are chosen from direct counts over datasets/v4_clean/ (31,340 rows), which
observed only: methods {GET, POST, PUT, PATCH, DELETE, HEAD}; fifteen header names; content
types {x-www-form-urlencoded, json, text/xml, application/xml}; and Host ports {none, 8000,
8080}. Anything outside those sets has zero support. Those counts are the repository
evidence; the slice measures how V4's ALLOW/BLOCK behaves on such structures, and claims no
novelty score, no calibrated uncertainty and no OOD signal.
"""

from __future__ import annotations

import json as _json_mod

from spec_lib import Spec, SHOP_HOST, API_HOST

# The fifteen header names observed in datasets/v4_clean/ (see analysis evidence). Any name
# outside this set has ZERO support and is a legitimate unseen-structure axis.
V4_HEADER_NAMES = {
    "host", "user-agent", "cookie", "content-type", "accept", "accept-language",
    "accept-encoding", "connection", "x-requested-with", "authorization", "origin",
    "referer", "content-length", "transfer-encoding",
}
V4_CONTENT_TYPES = {"application/x-www-form-urlencoded", "application/json",
                    "text/xml", "application/xml"}
V4_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}


def _allow(group, client, method, host, path, technique, description, *,
           body=None, body_type="none", headers=None, confidence="high",
           review="auto-accepted", basis=None) -> Spec:
    return Spec(
        group=group, expected_decision="ALLOW", client=client, method=method,
        host=host, path=path, technique=technique, description=description,
        ground_truth_basis=basis or ("Legitimate interaction the lab application is "
                                     "designed to serve; benign by the intent of the flow."),
        payload_placement="none", payload="", body=body, body_type=body_type,
        headers=headers or [], label_confidence=confidence, review_status=review)


# ══════════════════════════════════════════════════════════════════════════
# api-json — httpx, JSON API interaction, varied bodies
# ══════════════════════════════════════════════════════════════════════════
def api_json() -> list[Spec]:
    g, H = "api-json", API_HOST
    S = []
    # JSON GETs (httpx, Accept: application/json)
    acc = [("Accept", "application/json")]
    for path, tech, desc in [
        ("/api/products", "list", "List all products"),
        ("/api/products?category=office", "list-filter", "List office products"),
        ("/api/products?category=sport", "list-filter", "List sport products"),
        ("/api/products?category=food", "list-filter", "List food products"),
        ("/api/products/1", "detail", "Product 1 detail"),
        ("/api/products/2", "detail", "Product 2 detail"),
        ("/api/products/4", "detail", "Product 4 detail"),
        ("/api/products/5", "detail", "Product 5 detail"),
        ("/api/products/7", "detail", "Product 7 detail"),
        ("/api/products/8", "detail", "Product 8 detail"),
        ("/api/me", "session", "Session probe"),
    ]:
        S.append(_allow(g, "httpx", "GET", H, path, tech, desc, headers=acc))
    # JSON POST /api/orders — varied bodies
    ct = [("Content-Type", "application/json")]
    bodies = [
        ({"product_id": 1, "quantity": 1}, "single-item", "One-item order"),
        ({"product_id": 4, "quantity": 3}, "single-item", "Multi-quantity order"),
        ({"product_id": 8, "quantity": 2, "note": "leave at reception"}, "with-note",
         "Order with a note"),
        ({"items": [{"product_id": 2, "quantity": 1}, {"product_id": 8, "quantity": 2}]},
         "multi-item", "Two-line order"),
        ({"items": [{"product_id": 3, "quantity": 5}], "address": {"street": "12 Lab Street",
         "city": "Testville", "zip": "00001"}}, "nested-address", "Order with nested address"),
        ({"product_id": 5, "quantity": 1, "gift_wrap": True, "message": "Happy birthday"},
         "gift", "Gift-wrapped order"),
        ({"product_id": 6, "quantity": 4, "coupon": "SAVE10"}, "coupon", "Order with a coupon"),
        ({"cart": [1, 2, 3], "quantity_map": {"1": 2, "2": 1, "3": 1}}, "cart-map",
         "Order with a quantity map"),
        ({"product_id": 7, "quantity": 1, "note": "café au lait ☕"}, "unicode",
         "Order with unicode note"),
        ({"product_id": 2, "quantity": 1, "metadata": {"source": "mobile", "ab": "B"}},
         "metadata", "Order carrying metadata"),
        ({"items": [{"product_id": i, "quantity": 1} for i in range(1, 9)]}, "full-cart",
         "Order with all eight products"),
        ({}, "empty", "Empty JSON body"),
        ({"product_id": 3, "quantity": 1, "delivery": {"window": "09:00-12:00",
         "instructions": "ring twice"}}, "delivery", "Order with delivery window"),
        ({"product_id": 1, "quantity": 1, "loyalty_id": "LM-0042"}, "loyalty",
         "Order with a loyalty id"),
        ({"product_id": 4, "quantity": 2, "tags": ["sport", "sale"]}, "tags",
         "Order with tag array"),
        ({"product_id": 8, "quantity": 1, "price_seen": 9.90}, "price-seen",
         "Order echoing seen price"),
    ]
    bodies += [
        ({"product_id": 2, "quantity": 1, "discount_code": "WELCOME"}, "discount",
         "Order with a discount code"),
        ({"product_id": 5, "quantity": 2, "shipping": {"method": "express", "cost": 4.99}},
         "shipping", "Order with a shipping method"),
        ({"product_id": 6, "quantity": 1, "billing": {"name": "L. User", "country": "GB"}},
         "billing", "Order with billing details"),
        ({"product_id": "3", "quantity": "2"}, "string-numbers",
         "Order with string-typed numbers"),
        ({"product_id": 1, "quantity": 1, "currency": "EUR", "locale": "fr-FR"}, "i18n",
         "Order with currency and locale"),
        ({"idempotency_key": "idem-77c1", "product_id": 4, "quantity": 1}, "idempotency",
         "Order carrying an idempotency key in the body"),
        ({"product_id": 7, "quantity": 3, "coupons": ["A1", "B2", "C3"]}, "coupon-array",
         "Order with multiple coupons"),
        ({"customer": {"id": 501, "tier": "gold"}, "product_id": 8, "quantity": 1},
         "customer", "Order with a customer object"),
        ({"product_id": 2, "quantity": 1, "notes": ["fragile", "no substitutions"]},
         "note-list", "Order with a list of notes"),
        ({"product_id": 3, "quantity": 1, "scheduled_for": "2026-10-01T09:00:00Z"},
         "scheduled", "Scheduled order"),
        ({"pickup": {"store_id": 12, "slot": "afternoon"}, "product_id": 5, "quantity": 1},
         "pickup", "Click-and-collect order"),
        ({"product_id": 6, "quantity": 1, "priority": "high", "sla": "next-day"}, "priority",
         "Priority order"),
        ({"product_id": 1, "quantity": 1, "referrer": "newsletter-2026-09"}, "referrer",
         "Order with a referrer tag"),
        ({"product_id": 4, "quantity": 2, "insurance": False, "warranty_years": 2},
         "warranty", "Order with warranty options"),
        ({"product_id": 8, "quantity": 1, "attributes": {"engraving": "café", "font": "serif"}},
         "attributes", "Order with product attributes"),
        ({"basket_id": "bskt-9001", "lines": [{"sku": "USB-C", "qty": 2}]}, "basket",
         "Order referencing a basket"),
    ]
    for obj, tech, desc in bodies:
        S.append(_allow(g, "httpx", "POST", H, "/api/orders", tech, desc,
                        body=_json_mod.dumps(obj, ensure_ascii=False), body_type="json",
                        headers=ct))
    # A few PUTs — the app has no PUT route, so these are benign 405s, still real captured
    # JSON API requests (protocol 4.3 names GET/POST/PUT).
    for obj, tech, desc in [
        ({"product_id": 1, "quantity": 9}, "put-update", "Idempotent-style order update"),
        ({"status": "cancelled"}, "put-status", "Order status update"),
        ({"address": {"street": "9 New Road"}}, "put-address", "Address update"),
    ]:
        S.append(_allow(g, "httpx", "PUT", H, "/api/orders/1001", tech, desc,
                        body=_json_mod.dumps(obj, ensure_ascii=False), body_type="json",
                        headers=ct,
                        basis="JSON API request against an order resource; the app has no "
                              "PUT handler so it returns 405, but the request is a benign "
                              "real API interaction and is captured/labelled like any other.",
                        confidence="high"))
    # A couple of JSON GETs with an explicit charset Accept
    S.append(_allow(g, "httpx", "GET", H, "/api/products/3", "detail",
                    "Product 3 detail with charset Accept",
                    headers=[("Accept", "application/json; charset=utf-8")]))
    S.append(_allow(g, "httpx", "GET", H, "/api/products/6", "detail",
                    "Product 6 detail", headers=acc))
    return S


# ══════════════════════════════════════════════════════════════════════════
# api-query — curl, query-parameter-heavy GETs
# ══════════════════════════════════════════════════════════════════════════
def api_query() -> list[Spec]:
    g = "api-query"
    S = []
    shop = [
        ("/products?category=office&page=1&sort=price&limit=10", "filter-sort-page"),
        ("/products?category=sport&page=2&sort=name&limit=25", "filter-sort-page"),
        ("/products?category=food&page=1&sort=id&limit=5", "filter-sort-page"),
        ("/products?page=3&sort=id", "page-sort"),
        ("/products?sort=price&limit=50", "sort-limit"),
        ("/products?category=office", "filter"),
        ("/products?category=sport", "filter"),
        ("/products?category=food", "filter"),
        ("/products?page=1&limit=0", "boundary-limit-zero"),
        ("/products?page=100&limit=10", "boundary-high-page"),
        ("/products?sort=name&limit=1", "single"),
        ("/products?category=office&category=sport", "repeated-param"),
        ("/products?limit=-1", "negative-limit"),
        ("/products?sort=", "empty-sort"),
        ("/products?category=&page=&sort=&limit=", "all-empty"),
        ("/products?category=office&sort=price&sort=name", "repeated-sort"),
        ("/products?utm_source=newsletter&utm_medium=email&category=office", "tracking-params"),
        ("/products?page=2&per_page=20&order=asc", "alt-param-names"),
    ]
    for path, tech in shop:
        S.append(_allow(g, "curl", "GET", SHOP_HOST, path, tech,
                        f"Storefront query: {tech}"))
    search = [
        ("/search?q=mug", "search-plain"),
        ("/search?q=keyboard", "search-plain"),
        ("/search?q=espresso%20beans", "search-encoded-space"),
        ("/search?q=usb-c+hub", "search-plus-space"),
        ("/search?q=caf%C3%A9", "search-unicode"),
        ("/search?q=yoga%20mat&limit=5", "search-plus-limit"),
        ("/search?q=", "search-empty"),
        ("/search?q=stand&category=office", "search-with-filter"),
        ("/search?q=shoes&page=2", "search-paged"),
        ("/search?q=bottle&sort=price", "search-sorted"),
        ("/search?q=100%25%20cotton", "search-encoded-percent"),
        ("/search?q=a%26b", "search-encoded-amp"),
    ]
    for path, tech in search:
        S.append(_allow(g, "curl", "GET", SHOP_HOST, path, tech, f"Search query: {tech}"))
    api = [
        ("/api/products?category=food&limit=5", "api-filter-limit"),
        ("/api/products?category=office", "api-filter"),
        ("/api/products?category=sport&sort=price", "api-filter-sort"),
        ("/api/products?page=1&limit=3", "api-page"),
        ("/api/products?fields=id,name,price", "api-fields"),
        ("/api/products?category=food&category=office", "api-repeated"),
        ("/api/products?q=mug&category=food", "api-search-filter"),
        ("/api/products?limit=100", "api-high-limit"),
        ("/api/products?sort=-price", "api-desc-sort"),
        ("/api/products?category=office&debug=1", "api-debug-flag"),
        ("/api/products?category=sport&in_stock=true", "api-bool-flag"),
        ("/api/products?ids=1,2,3", "api-id-list"),
        ("/api/products?category=food&format=json", "api-format"),
        ("/api/products?min_price=10&max_price=90", "api-price-range"),
        ("/api/products?category=office&sort=name&page=1&limit=8&view=grid", "api-many-params"),
        ("/api/products?category=sport&tag=sale&tag=new", "api-repeated-tag"),
        ("/api/products?updated_since=2026-09-01", "api-date-filter"),
        ("/api/products?category=food&locale=en-GB", "api-locale"),
    ]
    for path, tech in api:
        S.append(_allow(g, "curl", "GET", API_HOST, path, tech, f"API query: {tech}"))
    return S


# ══════════════════════════════════════════════════════════════════════════
# unseen-structure — mixed clients, structural features with ZERO/near-zero V4 support
# ══════════════════════════════════════════════════════════════════════════
def unseen_structure() -> list[Spec]:
    g = "unseen-structure"
    S = []

    def basis_method(m):
        return (f"Benign request using HTTP method {m}, which has ZERO support in "
                f"datasets/v4_clean/ (observed methods: {sorted(V4_METHODS)}). "
                f"Unseen-input robustness (RQ4), not OOD detection.")

    def basis_header(names):
        return (f"Benign request carrying header name(s) {names} absent from the fifteen "
                f"header names observed in datasets/v4_clean/. Unseen structural feature "
                f"(RQ4), not OOD detection.")

    def basis_ct(ct):
        return (f"Benign request with Content-Type {ct!r}, outside the four content types "
                f"observed in datasets/v4_clean/ ({sorted(V4_CONTENT_TYPES)}). Unseen "
                f"structure (RQ4), not OOD detection.")

    # ── unseen METHODS: OPTIONS (CORS preflight) + TRACE (0 support) ──
    for host, path, desc in [
        (SHOP_HOST, "/products", "CORS preflight for product list"),
        (SHOP_HOST, "/cart", "CORS preflight for cart"),
        (API_HOST, "/api/products", "CORS preflight for API list"),
        (API_HOST, "/api/orders", "CORS preflight for order create"),
    ]:
        S.append(_allow(g, "curl", "OPTIONS", host, path, "cors-preflight", desc,
                        headers=[("Origin", "http://shop.fwlab.test"),
                                 ("Access-Control-Request-Method", "POST"),
                                 ("Access-Control-Request-Headers", "content-type")],
                        basis=basis_method("OPTIONS") + " Access-Control-Request-* header "
                        "names are also absent from the corpus."))
    S.append(_allow(g, "curl", "OPTIONS", SHOP_HOST, "/", "options-root",
                    "Bare OPTIONS on root", basis=basis_method("OPTIONS")))
    S.append(_allow(g, "curl", "OPTIONS", API_HOST, "/api/products/1", "options-detail",
                    "OPTIONS on a product detail", basis=basis_method("OPTIONS")))

    # ── unseen HEADER names on ordinary GETs ──
    unseen_header_reqs = [
        ([("Range", "bytes=0-1023")], "/static/app.css", "Ranged static fetch", "Range"),
        ([("Range", "bytes=1024-")], "/static/app.js", "Open-ended range", "Range"),
        ([("If-Range", '"v1"'), ("Range", "bytes=0-99")], "/static/logo.svg",
         "Conditional range", "If-Range"),
        ([("If-Modified-Since", "Wed, 01 Jan 2025 00:00:00 GMT")], "/products",
         "Conditional GET", "If-Modified-Since"),
        ([("If-None-Match", 'W/"abc123"')], "/products/1", "ETag conditional", "If-None-Match"),
        ([("Cache-Control", "no-cache")], "/products", "No-cache directive", "Cache-Control"),
        ([("Pragma", "no-cache")], "/", "Legacy no-cache", "Pragma"),
        ([("DNT", "1")], "/products", "Do-Not-Track", "DNT"),
        ([("Upgrade-Insecure-Requests", "1")], "/", "UIR hint", "Upgrade-Insecure-Requests"),
        ([("Sec-Fetch-Site", "same-origin"), ("Sec-Fetch-Mode", "navigate"),
          ("Sec-Fetch-Dest", "document")], "/products", "Fetch-metadata set", "Sec-Fetch-*"),
        ([("Priority", "u=1, i")], "/products", "Priority hint", "Priority"),
        ([("X-Forwarded-For", "203.0.113.7")], "/products", "Forwarded-for hint",
         "X-Forwarded-For"),
        ([("X-Real-IP", "203.0.113.7")], "/", "Real-IP hint", "X-Real-IP"),
        ([("Via", "1.1 edge-cache")], "/products", "Via proxy chain", "Via"),
        ([("Accept-Datetime", "Thu, 31 May 2007 20:35:00 GMT")], "/products",
         "Memento datetime", "Accept-Datetime"),
        ([("Accept-CH", "Sec-CH-UA")], "/", "Client-hints ask", "Accept-CH"),
        ([("X-Request-ID", "b3a1c2d4")], "/products", "Request correlation id (benign)",
         "X-Request-ID"),
        ([("Save-Data", "on")], "/products", "Save-Data hint", "Save-Data"),
        ([("Sec-CH-UA-Platform", '"Linux"')], "/", "UA platform client-hint", "Sec-CH-UA-Platform"),
        ([("Warning", '199 - "misc"')], "/products", "Warning header", "Warning"),
        ([("TE", "trailers")], "/products", "TE trailers negotiation", "TE"),
        ([("Max-Forwards", "10")], "/", "Max-Forwards limit", "Max-Forwards"),
        ([("From", "shopper@fwlab.test")], "/products", "From mailbox header", "From"),
        ([("Forwarded", "for=203.0.113.7;proto=http")], "/products", "RFC 7239 Forwarded",
         "Forwarded"),
        ([("Sec-GPC", "1")], "/products", "Global Privacy Control", "Sec-GPC"),
        ([("Device-Memory", "8"), ("Downlink", "10"), ("RTT", "50")], "/products",
         "Network/device client-hints", "Device-Memory/Downlink/RTT"),
        ([("Idempotency-Key", "idem-00aa")], "/products", "Idempotency key header",
         "Idempotency-Key"),
        ([("Prefer", "return=minimal")], "/products", "Prefer return=minimal", "Prefer"),
        ([("X-HTTP-Method-Override", "GET")], "/products", "Method override header",
         "X-HTTP-Method-Override"),
    ]
    for headers, path, desc, hname in unseen_header_reqs:
        S.append(_allow(g, "curl", "GET", SHOP_HOST, path, "unseen-header", desc,
                        headers=headers, basis=basis_header(hname)))

    # ── unseen CONTENT-TYPES on benign POST bodies ──
    S.append(_allow(g, "curl", "POST", SHOP_HOST, "/checkout", "ct-text-plain",
                    "Checkout note as text/plain",
                    body="please deliver after 6pm", body_type="text",
                    headers=[("Content-Type", "text/plain")], basis=basis_ct("text/plain")))
    S.append(_allow(g, "curl", "POST", API_HOST, "/api/orders", "ct-csv",
                    "Bulk order as CSV",
                    body="product_id,quantity\n1,2\n4,1\n", body_type="csv",
                    headers=[("Content-Type", "text/csv")], basis=basis_ct("text/csv")))
    S.append(_allow(g, "curl", "POST", API_HOST, "/api/orders", "ct-ndjson",
                    "Streamed orders as ND-JSON",
                    body='{"product_id":1,"quantity":1}\n{"product_id":2,"quantity":1}\n',
                    body_type="text", headers=[("Content-Type", "application/x-ndjson")],
                    basis=basis_ct("application/x-ndjson")))
    # NOTE: multipart/form-data is deliberately NOT used here. A real multipart body carries
    # CRLF part separators, and the classifier representation would then contain CR, which
    # wire.assert_canonical rejects (LF-only) so the case could never replay byte-exactly.
    # The unseen content-type axis is covered by the LF-safe bodies above and below instead.
    S.append(_allow(g, "curl", "POST", API_HOST, "/api/orders", "ct-graphql",
                    "Order query as application/graphql",
                    body="{ products { id name } }", body_type="text",
                    headers=[("Content-Type", "application/graphql")],
                    basis=basis_ct("application/graphql")))
    S.append(_allow(g, "curl", "POST", SHOP_HOST, "/checkout", "ct-html",
                    "Checkout note as text/html body",
                    body="<p>leave at reception</p>", body_type="text",
                    headers=[("Content-Type", "text/html")], basis=basis_ct("text/html")))
    S.append(_allow(g, "httpx", "PATCH", API_HOST, "/api/orders", "patch-merge",
                    "PATCH merge on orders (benign, method present but rare on this route)",
                    body='{"quantity":2}', body_type="json",
                    headers=[("Content-Type", "application/merge-patch+json")],
                    basis=basis_ct("application/merge-patch+json"), confidence="medium"))

    # ── unseen PORT / host-form (benign) ──
    # lab traffic already rides port 9100 (0 corpus support); these make the axis explicit
    # by pairing it with an uncommon-but-benign structure. Marked medium: naturally arising
    # in-lab, so weaker as an isolated signal.
    S.append(_allow(g, "curl", "GET", SHOP_HOST, "/products", "host-trailing-dot",
                    "Fully-qualified host with trailing dot",
                    headers=[("Host", f"{SHOP_HOST}.:9100")],
                    basis=("Benign request whose Host is a fully-qualified name with a "
                           "trailing dot on port 9100; port 9100 has zero support in "
                           "datasets/v4_clean/ (observed ports: none, 8000, 8080). RQ4."),
                    confidence="medium", review="needs-review"))
    S.append(_allow(g, "curl", "HEAD", SHOP_HOST, "/products/2", "head-detail",
                    "HEAD on a product detail (rare method+route combination)",
                    basis=("Benign HEAD request; HEAD is rare in the corpus and the "
                           "/products/<id> route shape has near-zero support. RQ4."),
                    confidence="medium"))
    S.append(_allow(g, "curl", "GET", SHOP_HOST, "/.well-known/security.txt",
                    "well-known", "Well-known security.txt probe (benign)",
                    basis=("Benign request to a /.well-known/ path; that path prefix has "
                           "zero support in datasets/v4_clean/. RQ4."),
                    confidence="medium"))
    return S


def build() -> list[Spec]:
    specs: list[Spec] = []
    for fn in (api_json, api_query, unseen_structure):
        specs.extend(fn())
    return specs


if __name__ == "__main__":
    from collections import Counter
    c = Counter(s.group for s in build())
    for slc in ("api-json", "api-query", "unseen-structure"):
        print(f"{slc:18s} {c[slc]}")
    print(f"{'TOTAL':18s} {sum(c.values())}")
