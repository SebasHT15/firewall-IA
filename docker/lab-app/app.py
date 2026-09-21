"""firewall-IA Docker Lab — `lab-app`, the External Test v1 destination application.

A small but genuinely interactive web application: pages and routes, HTML forms, cookie
sessions, a JSON API and query parameters. Real browsers and API clients drive it, and the
requests they produce become External Test v1 cases.

DELIBERATELY NOT VULNERABLE.
    External v1 measures classification (L1) and enforcement (L2/L3). A request the
    gateway blocks never arrives here, so whether this app *could* be exploited changes no
    metric at any level. Attack payloads that do arrive are stored as inert text and
    echoed back escaped; nothing is interpolated into a query, a shell, a path or a
    template. "attack delivered" in External v1 means a malicious request REACHED this
    app, never that it succeeded. Keeping the app inert removes a vulnerable service from
    the lab while measuring exactly the same thing.

RECEIPTS
    Every request is appended to an append-only JSONL log before it is served, same
    pattern as the smoke-test `destination` service. This is how "the request did not
    arrive" becomes a recorded fact rather than an absence of output.

The smoke-test `destination` service is untouched and still serves the Docker Lab checks.
"""

import datetime
import json
import os
import threading

from flask import (Flask, jsonify, make_response, redirect, render_template_string,
                   request, url_for)
from markupsafe import Markup

ACCESS_LOG = os.environ.get("ACCESS_LOG", "/logs/lab-app-access.jsonl")
PORT = int(os.environ.get("PORT", "9100"))

app = Flask(__name__)
_log_lock = threading.Lock()

# ── Inert catalogue ────────────────────────────────────────────────────────
PRODUCTS = [
    {"id": 1, "name": "Aluminium Laptop Stand", "category": "office", "price": 51.25},
    {"id": 2, "name": "Mechanical Keyboard",    "category": "office", "price": 89.00},
    {"id": 3, "name": "USB-C Hub",              "category": "office", "price": 34.50},
    {"id": 4, "name": "Running Shoes",          "category": "sport",  "price": 74.99},
    {"id": 5, "name": "Yoga Mat",               "category": "sport",  "price": 22.10},
    {"id": 6, "name": "Water Bottle",           "category": "sport",  "price": 12.00},
    {"id": 7, "name": "Espresso Beans 1kg",     "category": "food",   "price": 18.40},
    {"id": 8, "name": "Ceramic Mug",            "category": "food",   "price": 9.90},
]

# INERT RENDERING (External v1 requires the lab app to be inert; protocol section 5.1).
#
# `body` is rendered with Jinja autoescaping ({{ body }}, NOT {{ body|safe }}). Each route
# composes `body` as a markupsafe.Markup out of TRUSTED static markup (the forms, lists and
# links the browser flows drive) plus request-derived values interpolated with Markup.format,
# which HTML-escapes every substituted value. A reflected `<script>`/`onerror=` payload is
# therefore stored and echoed as escaped text, never as live HTML — nothing request-derived
# reaches an HTML sink unescaped. The page structure (form field names, actions, buttons,
# link hrefs) is unchanged, so the External v1 requests clients make are unchanged.
PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>{{ title }}</title></head>
<body><h1>{{ title }}</h1>{{ body }}
<nav><a href="/">home</a> <a href="/products">products</a> <a href="/search">search</a>
<a href="/cart">cart</a> <a href="/login">login</a> <a href="/profile">profile</a></nav>
</body></html>"""


def receipt() -> None:
    """Record that this request reached the destination."""
    entry = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "method": request.method,
        "path": request.full_path.rstrip("?") or request.path,
        "host_header": request.headers.get("Host"),
        "user_agent": request.headers.get("User-Agent"),
        "content_length": request.content_length or 0,
        "client_ip": request.remote_addr,
    }
    line = json.dumps(entry, ensure_ascii=False)
    with _log_lock:
        with open(ACCESS_LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
    print("RECEIVED " + line, flush=True)


# The Docker healthcheck polls /healthz every few seconds from INSIDE this container.
# Those probes are infrastructure, not traffic under test, and recording them buried the
# experimental receipts (41 of 49 entries in the Phase B capture gate).
#
# The exclusion is deliberately narrow: only /healthz AND only from the container's own
# loopback. Anything arriving through a proxy has the proxy container's address, so a
# proxied request is ALWAYS recorded, even to /healthz. Excluding /healthz by path alone
# would create a blind spot: a request that reached this app would leave no receipt, and
# L2/L3 would score it as "not delivered".
HEALTHCHECK_PATH = "/healthz"
LOOPBACK = {"127.0.0.1", "::1"}


def should_record(path: str, remote_addr) -> bool:
    """True unless this is the container's own healthcheck probe."""
    return not (path == HEALTHCHECK_PATH and remote_addr in LOOPBACK)


@app.before_request
def _record():
    if should_record(request.path, request.remote_addr):
        receipt()


def page(title, body):
    return render_template_string(PAGE, title=title, body=body)


# ── Pages ──────────────────────────────────────────────────────────────────
@app.get("/")
def home():
    return page("fwlab shop", Markup("<p>Lab storefront for External Test v1.</p>"))


@app.get("/products")
def products():
    # Query parameters are read and echoed as ESCAPED TEXT via Markup.format; never reach an
    # HTML sink as live markup. Product fields come from the trusted catalogue.
    cat = request.args.get("category", "")
    page_n = request.args.get("page", "1")
    sort = request.args.get("sort", "id")
    limit = request.args.get("limit", "10")
    items = [p for p in PRODUCTS if not cat or p["category"] == cat]
    rows = Markup("").join(
        Markup("<li><a href='/products/{}'>{}</a> {}</li>").format(
            p["id"], p["name"], f"{p['price']:.2f}") for p in items)
    return page("products", Markup("<p>category={} page={} sort={} limit={}</p><ul>{}</ul>")
                .format(cat, page_n, sort, limit, rows))


@app.get("/products/<pid>")
def product(pid):
    found = next((p for p in PRODUCTS if str(p["id"]) == str(pid)), None)
    if not found:
        return page("not found", Markup("<p>no product {}</p>").format(pid)), 404
    return page(found["name"],
                Markup("<p>{} — {}</p>"
                       "<form method='post' action='/cart'>"
                       "<input type='hidden' name='product_id' value='{}'>"
                       "<input name='quantity' value='1'>"
                       "<button type='submit'>add to cart</button></form>")
                .format(found["category"], f"{found['price']:.2f}", found["id"]))


@app.get("/search")
def search():
    q = request.args.get("q", "")
    hits = [p for p in PRODUCTS if q.lower() in p["name"].lower()] if q else []
    rows = Markup("").join(Markup("<li>{}</li>").format(p["name"]) for p in hits)
    return page("search",
                Markup("<form method='get' action='/search'>"
                       "<input name='q' value=''><button>search</button></form>")
                + Markup("<p>query={}, {} hit(s)</p><ul>{}</ul>").format(q, len(hits), rows))


@app.get("/login")
def login_form():
    return page("login", Markup("<form method='post' action='/login'>"
                                "<input name='username'><input name='password' type='password'>"
                                "<button type='submit'>sign in</button></form>"))


@app.post("/login")
def login():
    # No credential checking: this is a session-behaviour fixture, not an auth system.
    user = request.form.get("username", "guest")
    resp = make_response(redirect(url_for("profile")))
    resp.set_cookie("fwlab_session", f"u={user}", httponly=True, samesite="Lax")
    return resp


@app.get("/profile")
def profile():
    session = request.cookies.get("fwlab_session")
    if not session:
        return redirect(url_for("login_form"))
    return page("profile", Markup("<p>session={}</p>").format(session))


@app.route("/cart", methods=["GET", "POST"])
def cart():
    if request.method == "POST":
        pid = request.form.get("product_id", "")
        qty = request.form.get("quantity", "")
        resp = make_response(redirect(url_for("cart")))
        resp.set_cookie("fwlab_cart", f"{pid}x{qty}", samesite="Lax")
        return resp
    return page("cart", Markup("<p>cart={}</p>"
                               "<form method='post' action='/checkout'>"
                               "<input name='address'><input name='card_last4' value='0000'>"
                               "<button type='submit'>checkout</button></form>")
                .format(request.cookies.get("fwlab_cart")))


@app.post("/checkout")
def checkout():
    return page("checkout",
                Markup("<p>order placed, fields={}</p>").format(sorted(request.form.keys())))


@app.get("/static/<path:asset>")
def static_asset(asset):
    return app.response_class(f"/* {asset} */\n", mimetype="text/plain")


# ── JSON API ───────────────────────────────────────────────────────────────
@app.get("/api/products")
def api_products():
    cat = request.args.get("category")
    items = [p for p in PRODUCTS if not cat or p["category"] == cat]
    return jsonify({"count": len(items), "items": items,
                    "query": {k: v for k, v in request.args.items()}})


@app.get("/api/products/<pid>")
def api_product(pid):
    found = next((p for p in PRODUCTS if str(p["id"]) == str(pid)), None)
    return (jsonify(found), 200) if found else (jsonify({"error": "not found"}), 404)


@app.post("/api/orders")
def api_orders():
    payload = request.get_json(silent=True)
    return jsonify({"status": "accepted",
                    "echo_keys": sorted(payload.keys()) if isinstance(payload, dict) else None}), 201


@app.get("/api/me")
def api_me():
    return jsonify({"session": request.cookies.get("fwlab_session")})


@app.get("/healthz")
def healthz():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    os.makedirs(os.path.dirname(ACCESS_LOG) or ".", exist_ok=True)
    with open(ACCESS_LOG, "a", encoding="utf-8"):
        pass
    print(f"lab-app ready: port={PORT} access_log={ACCESS_LOG}", flush=True)
    app.run(host="0.0.0.0", port=PORT, threaded=True)
