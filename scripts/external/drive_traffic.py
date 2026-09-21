"""External Test v1 — benign traffic drivers (DRAFT capture phase only).

Drives the lab application with REAL clients so real requests can be captured, labelled and
frozen, with the CAPTURE proxy in the path and the firewall data plane and control plane
absent (ground truth must be assigned before V4 sees anything — D37).

Two of the five benign slices are BROWSER slices, produced here by Playwright/Chromium and
captured whole (a page load emits its own sub-resource requests; those are real benign
traffic and are captured and labelled like any other request, declared before exposure):

    browser-navigation      page loads, category and product views, pagination, static assets
    browser-forms-session   login, search and checkout forms; cookies and session continuity

The other three benign slices (api-json, api-query, unseen-structure) are enumerable and are
driven from benign_specs.py by send.py; run_capture.py orchestrates all flows. This module
is also runnable standalone for debugging a single browser flow.

No request carries a marker, correlation id or test header — every header is model input
(ml_evaluation_methodology.md section 8). Distinct URLs are used so Chromium hits the
network rather than its cache, and each flow is captured to its own offset window.

    python3 drive_traffic.py navigation    --proxy http://capture-proxy:8081 --base http://shop.fwlab.test:9100
    python3 drive_traffic.py forms-session --proxy http://capture-proxy:8081 --base http://shop.fwlab.test:9100
"""

import argparse
import sys

LAUNCH_ARGS_NOTE = (
    # --no-sandbox / --disable-dev-shm-usage are process-isolation and shared-memory flags
    # for running Chromium as root in a container. Neither changes the engine, the header
    # set or anything that reaches the wire, so the traffic stays genuine Chromium traffic.
    "container launch flags only")


def _launch(p, proxy):
    return p.chromium.launch(args=[f"--proxy-server={proxy}", "--no-sandbox",
                                   "--disable-dev-shm-usage"])


def _goto(pg, url):
    try:
        pg.goto(url, wait_until="load")
    except Exception as exc:                       # a 404/405 still reached the app
        print(f"  goto {url} -> {type(exc).__name__} (still captured)", flush=True)


# ── browser-navigation ───────────────────────────────────────────────────────
def browser_navigation(base: str, proxy: str) -> int:
    """Distinct-URL navigation so every hit reaches the network and is captured."""
    from playwright.sync_api import sync_playwright

    nav_paths = [
        "/", "/products",
        "/products?category=office", "/products?category=sport", "/products?category=food",
        "/products/1", "/products/2", "/products/3", "/products/4",
        "/products/5", "/products/6", "/products/7", "/products/8",
        "/products?page=1&sort=price&limit=10", "/products?page=2&sort=name&limit=10",
        "/products?page=3&sort=id&limit=5", "/products?category=office&page=1&sort=price",
        "/products?category=sport&sort=name", "/products?category=food&limit=3",
        "/products?sort=price", "/products?sort=name", "/products?sort=id",
        "/search", "/search?q=mug", "/search?q=keyboard", "/search?q=espresso",
        "/search?q=usb", "/search?q=shoes", "/search?q=bottle",
        "/static/app.css", "/static/app.js", "/static/logo.svg", "/static/vendor.css",
        "/static/main.js", "/static/theme.css", "/static/icons.svg",
        "/products/1", "/products/2",           # revisits via distinct nav intent
        "/products?category=office&page=2", "/products?category=sport&page=2",
        "/api/products", "/api/products/1", "/api/me",
        "/profile", "/cart", "/login",
    ]
    with sync_playwright() as p:
        browser = _launch(p, proxy)
        ctx = browser.new_context()
        pg = ctx.new_page()
        for path in nav_paths:
            _goto(pg, base + path)
        ctx.close()
        browser.close()
    print(f"browser-navigation complete ({len(nav_paths)} navigations)", flush=True)
    return 0


# ── browser-forms-session ────────────────────────────────────────────────────
def browser_forms_session(base: str, proxy: str) -> int:
    """Login, search and checkout forms with cookie/session continuity in ONE context."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = _launch(p, proxy)
        ctx = browser.new_context()          # one cookie jar; session builds up
        pg = ctx.new_page()

        # search form submissions (GET)
        for q in ("keyboard", "mug", "espresso beans", "usb-c hub", "running shoes",
                  "yoga mat", "water bottle", "ceramic"):
            _goto(pg, base + "/search")
            try:
                pg.fill("input[name=q]", q)
                pg.click("button")
                pg.wait_for_load_state("load")
            except Exception as exc:
                print(f"  search {q!r} -> {type(exc).__name__}", flush=True)

        # login -> session cookie -> authenticated profile
        _goto(pg, base + "/login")
        try:
            pg.fill("input[name=username]", "lab-user")
            pg.fill("input[name=password]", "lab-pass")
            pg.click("button[type=submit]")
            pg.wait_for_load_state("load")
        except Exception as exc:
            print(f"  login -> {type(exc).__name__}", flush=True)
        _goto(pg, base + "/profile")

        # add several products to cart, then view cart and check out (POST + cookies)
        for pid, qty in ((1, "1"), (2, "2"), (4, "1"), (5, "3"), (7, "1"), (8, "2")):
            _goto(pg, base + f"/products/{pid}")
            try:
                pg.fill("input[name=quantity]", qty)
                pg.click("button[type=submit]")
                pg.wait_for_load_state("load")
            except Exception as exc:
                print(f"  add-to-cart {pid} -> {type(exc).__name__}", flush=True)
        _goto(pg, base + "/cart")
        for addr in ("12 Lab Street", "9 New Road", "1 Testville Ave"):
            _goto(pg, base + "/cart")
            try:
                pg.fill("input[name=address]", addr)
                pg.click("button[type=submit]")
                pg.wait_for_load_state("load")
            except Exception as exc:
                print(f"  checkout {addr!r} -> {type(exc).__name__}", flush=True)

        # revisit authenticated pages to exercise session continuity
        _goto(pg, base + "/profile")
        _goto(pg, base + "/api/me")
        _goto(pg, base + "/cart")

        ctx.close()
        browser.close()
    print("browser-forms-session complete", flush=True)
    return 0


# ── browser-forms-session PRE-FREEZE SUPPLEMENT ──────────────────────────────
def browser_forms_supplement(base: str, proxy: str) -> int:
    """Pre-freeze supplemental browser-forms-session flow (Phase D deficit correction).

    The original browser-forms-session flow re-navigated to bare /search and /cart, emitting
    byte-identical GET requests that collapsed under the internal-duplicate gate to 37 < 40
    eligible. This flow adds GENUINELY DISTINCT benign form/session interactions that the app
    already supports, exercising dimensions the first flow did not:

      * a SECOND authenticated identity (shopper2) — distinct login body, distinct session
        cookie, distinct authenticated /profile and /api/me;
      * CART/SESSION TRANSITIONS — the fwlab_cart cookie evolves (…->3x2->6x1), so each
        GET /cart is a different request reflecting a different point in the workflow, and the
        checkout completes an authenticated cart that was built here;
      * an UNAUTHENTICATED guest workflow — add-to-cart, view cart and checkout with NO
        session cookie, a different access path from the authenticated one.

    Every produced form-submit / cookie-bearing GET differs from the existing DRAFT by session
    state or form semantics — not by a cosmetic value. Distinctness is verified by the same
    Phase D internal-duplicate gate (against the existing DRAFT), which drops any request that
    still collapses. Navigation GETs used to reach forms (e.g. GET /products/3) may duplicate
    existing cases; the supplement gate keeps the EXISTING case and drops the supplement copy,
    so no other cell is touched.
    """
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = _launch(p, proxy)

        # Context 1 — a second authenticated user builds and checks out a cart
        ctx = browser.new_context()
        pg = ctx.new_page()
        _goto(pg, base + "/login")
        try:
            pg.fill("input[name=username]", "shopper2")
            pg.fill("input[name=password]", "s2-pass")
            pg.click("button[type=submit]")          # POST /login (shopper2) -> GET /profile
            pg.wait_for_load_state("load")
        except Exception as exc:
            print(f"  login(shopper2) -> {type(exc).__name__}", flush=True)
        _goto(pg, base + "/api/me")                  # GET /api/me (session shopper2)
        # add product 3, then product 6 (the cart cookie transitions between the two)
        for pid, qty in (("3", "2"), ("6", "1")):
            _goto(pg, base + f"/products/{pid}")
            try:
                pg.fill("input[name=quantity]", qty)
                pg.click("button[type=submit]")      # POST /cart -> GET /cart (new cart state)
                pg.wait_for_load_state("load")
            except Exception as exc:
                print(f"  add-to-cart(auth {pid}) -> {type(exc).__name__}", flush=True)
        # the last redirect left us on /cart with the built cart -> authenticated checkout
        try:
            pg.fill("input[name=address]", "48 Session Way")
            pg.click("button[type=submit]")          # POST /checkout (auth shopper2)
            pg.wait_for_load_state("load")
        except Exception as exc:
            print(f"  checkout(auth) -> {type(exc).__name__}", flush=True)
        ctx.close()

        # Context 2 — an UNAUTHENTICATED guest cart + checkout (no session cookie)
        ctx2 = browser.new_context()
        pg2 = ctx2.new_page()
        _goto(pg2, base + "/products/2")
        try:
            pg2.fill("input[name=quantity]", "5")
            pg2.click("button[type=submit]")         # POST /cart (guest) -> GET /cart (guest)
            pg2.wait_for_load_state("load")
            pg2.fill("input[name=address]", "5 Guest Lane")
            pg2.click("button[type=submit]")         # POST /checkout (guest)
            pg2.wait_for_load_state("load")
        except Exception as exc:
            print(f"  guest workflow -> {type(exc).__name__}", flush=True)
        ctx2.close()

        browser.close()
    print("browser-forms-supplement complete", flush=True)
    return 0


FLOWS = {"navigation": browser_navigation, "forms-session": browser_forms_session,
         "forms-supplement": browser_forms_supplement}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("flow", choices=sorted(FLOWS))
    ap.add_argument("--base", required=True, help="lab-app base URL inside the lab network")
    ap.add_argument("--proxy", required=True, help="CAPTURE proxy, e.g. http://capture-proxy:8081")
    args = ap.parse_args(argv)
    return FLOWS[args.flow](args.base, args.proxy)


if __name__ == "__main__":
    sys.exit(main())
