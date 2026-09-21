"""External Test v1 — benign traffic drivers (DRAFT capture phase only).

Drives the lab application with REAL clients so that real requests can be captured,
labelled and frozen. Run with the CAPTURE proxy in the path and the firewall data plane
and control plane absent: this phase must produce cases without V4 seeing anything (D37).

    browser   Playwright/Chromium: navigation, forms, cookies/session
    api       Python httpx: JSON API flows
    query     curl: query-parameter-heavy GETs

Nothing here assigns ground truth and nothing here writes cases. It only makes traffic;
the capture proxy records it, and labelling happens afterwards, in Phase C.

No request carries a marker, correlation id or test header — every header is model input
(ml_evaluation_methodology.md section 8). Flows are separated in the capture by running
them one at a time with a distinct CAPTURE_TAG on the capture proxy.

    python3 drive_traffic.py browser --proxy http://capture-proxy:8081 --base http://shop.fwlab.test:9100
    python3 drive_traffic.py api     --proxy http://capture-proxy:8081 --base http://api.fwlab.test:9100
    python3 drive_traffic.py query   --proxy http://capture-proxy:8081 --base http://shop.fwlab.test:9100
"""

import argparse
import subprocess
import sys


# ── browser flows ──────────────────────────────────────────────────────────
def run_browser(base: str, proxy: str) -> int:
    """Chromium, driven by Playwright, through the capture proxy.

    A page load emits sub-resource requests of its own. Those are real benign traffic and
    are captured and labelled like any other request rather than filtered out; their
    inclusion is declared in the protocol before exposure.
    """
    from playwright.sync_api import sync_playwright

    # --no-sandbox            Chromium refuses to start as root, which is how it runs in
    #                         this container.
    # --disable-dev-shm-usage Docker gives /dev/shm 64 MB by default; Chromium crashes on
    #                         larger pages without this.
    # Both are process-isolation and shared-memory flags. Neither changes the engine, the
    # header set, the connection behaviour or anything else that reaches the wire, so the
    # traffic stays genuine Chromium traffic.
    launch_args = [f"--proxy-server={proxy}", "--no-sandbox", "--disable-dev-shm-usage"]

    with sync_playwright() as p:
        browser = p.chromium.launch(args=launch_args)
        ctx = browser.new_context()          # a fresh cookie jar; session builds up below
        pg = ctx.new_page()

        # navigation
        for path in ("/", "/products", "/products?category=office", "/products?category=sport",
                     "/products/1", "/products/4", "/products/7", "/search"):
            pg.goto(base + path, wait_until="load")

        # search form
        pg.goto(base + "/search", wait_until="load")
        pg.fill("input[name=q]", "keyboard")
        pg.click("button")
        pg.wait_for_load_state("load")

        # login form -> session cookie -> authenticated page
        pg.goto(base + "/login", wait_until="load")
        pg.fill("input[name=username]", "lab-user")
        pg.fill("input[name=password]", "lab-pass")
        pg.click("button[type=submit]")
        pg.wait_for_load_state("load")
        pg.goto(base + "/profile", wait_until="load")

        # add to cart -> cart -> checkout, carrying cookies
        pg.goto(base + "/products/2", wait_until="load")
        pg.fill("input[name=quantity]", "2")
        pg.click("button[type=submit]")
        pg.wait_for_load_state("load")
        pg.goto(base + "/cart", wait_until="load")
        pg.fill("input[name=address]", "12 Lab Street")
        pg.click("button[type=submit]")
        pg.wait_for_load_state("load")

        # static assets
        for asset in ("app.css", "app.js", "logo.svg"):
            pg.goto(f"{base}/static/{asset}", wait_until="load")

        ctx.close()
        browser.close()
    print("browser flows complete", flush=True)
    return 0


# ── API flows ──────────────────────────────────────────────────────────────
def run_api(base: str, proxy: str) -> int:
    import httpx

    # trust_env=False so only the explicit proxy below is used.
    with httpx.Client(proxy=proxy, trust_env=False, timeout=30.0) as c:
        for path in ("/api/products", "/api/products?category=office",
                     "/api/products?category=sport", "/api/products?category=food",
                     "/api/products/1", "/api/products/5", "/api/products/8", "/api/me"):
            c.get(base + path)
        for payload in (
            {"product_id": 1, "quantity": 1},
            {"product_id": 4, "quantity": 3, "note": "leave at reception"},
            {"items": [{"product_id": 2, "quantity": 1}, {"product_id": 8, "quantity": 2}],
             "address": {"street": "12 Lab Street", "city": "Testville"}},
        ):
            c.post(base + "/api/orders", json=payload)
    print("api flows complete", flush=True)
    return 0


# ── query-parameter flows ──────────────────────────────────────────────────
def run_query(base: str, proxy: str) -> int:
    paths = [
        "/products?category=office&page=1&sort=price&limit=10",
        "/products?category=sport&page=2&sort=name&limit=25",
        "/products?page=3&sort=id",
        "/search?q=mug", "/search?q=espresso%20beans", "/search?q=usb-c+hub",
        "/search?q=caf%C3%A9", "/api/products?category=food&limit=5",
    ]
    rc = 0
    for path in paths:
        r = subprocess.run(["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code} ",
                            "-x", proxy, base + path])
        rc |= r.returncode
    print("\nquery flows complete", flush=True)
    return rc


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("flow", choices=("browser", "api", "query"))
    ap.add_argument("--base", required=True, help="lab-app base URL inside the lab network")
    ap.add_argument("--proxy", required=True, help="CAPTURE proxy, e.g. http://capture-proxy:8081")
    args = ap.parse_args(argv)
    return {"browser": run_browser, "api": run_api, "query": run_query}[args.flow](
        args.base, args.proxy)


if __name__ == "__main__":
    sys.exit(main())
