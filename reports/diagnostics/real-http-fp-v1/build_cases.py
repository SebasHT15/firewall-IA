"""Build the pre-registered case list for the real-http-fp-v1 diagnostic.

Writes cases.jsonl next to this file. Run once, before any request is sent:

    python3.12 reports/diagnostics/real-http-fp-v1/build_cases.py

Every case is benign by construction (expected_label = ALLOW); the model's output is
never used to assign a label. Each case changes ONE variable against a reference case
of the same group (`pair_with`). The proxy subset is fixed here, before any result
exists, so it cannot be chosen after seeing decisions.

Texts follow data_plane.render_request(): `METHOD /target HTTP/1.1`, one `Name: value`
line per header, LF line endings, no trailing newline, blank line + body only when
there is a body. The case id is experiment metadata and never appears in a text.
"""
import hashlib
import json
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
EVAL = os.path.join(REPO, "datasets", "v4_clean", "eval.jsonl")
SEED = 42
N_EVAL_ROWS = 10

UA_CURL = "curl/8.18.0"                    # curl installed on this machine
UA = {
    "curl-8.18.0": UA_CURL,
    "curl-8.5.0": "curl/8.5.0",
    "wget": "Wget/1.25.0",                  # wget installed on this machine
    "firefox": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
    "chrome": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
               "Chrome/128.0.0.0 Safari/537.36"),
    "python-requests": "python-requests/2.32.5",
    "python-httpx": "python-httpx/0.28.1",
    "python-urllib": "Python-urllib/3.12",
}
COOKIE = "sessionid=7c9e6679f2a1b3c4"

# Base contexts: realistic header sets of real clients, in the order they send them.
CONTEXTS = {
    # curl through an explicit HTTP proxy (adds Proxy-Connection)
    "K1-curl-proxy": ("/index.html", [("User-Agent", UA_CURL), ("Accept", "*/*"),
                                      ("Proxy-Connection", "Keep-Alive")]),
    # curl straight to the server
    "K2-curl-direct": ("/index.html", [("User-Agent", UA_CURL), ("Accept", "*/*")]),
    # a desktop browser navigation
    "K3-browser": ("/index.html", [
        ("User-Agent", UA["firefox"]),
        ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        ("Accept-Language", "en-US,en;q=0.5"),
        ("Accept-Encoding", "gzip, deflate"),
        ("Connection", "keep-alive"),
        ("Upgrade-Insecure-Requests", "1")]),
    # a Python API client
    "K4-python-api": ("/api/products?id=42", [
        ("User-Agent", UA["python-requests"]), ("Accept-Encoding", "gzip, deflate"),
        ("Accept", "*/*"), ("Connection", "keep-alive")]),
}

HOSTS = ["localhost:9000", "127.0.0.1:9000", "127.0.0.2:9000", "[::1]:9000",
         "192.168.1.20:9000", "10.0.0.15:9000", "app.fwlab.test:9000",
         "shop.example.com:9000"]
PATHS = ["/", "/index.html", "/about.html", "/products?id=42", "/api/products",
         "/favicon.ico", "/miembros/imagenes/zarauz.jpg"]
PORTS = [None, 80, 3000, 8000, 8080, 9000, 12345, 18080, 19000, 20000, 30000, 65000]


def render(method, target, headers, body=None):
    text = "\n".join([f"{method} {target} HTTP/1.1"] + [f"{k}: {v}" for k, v in headers])
    if body:
        text += "\n\n" + body
    return text


def ctx_headers(ctx, host):
    return [("Host", host)] + list(CONTEXTS[ctx][1])


def without(headers, name):
    return [(k, v) for k, v in headers if k.lower() != name.lower()]


def replaced(headers, name, value):
    return [(k, value if k.lower() == name.lower() else v) for k, v in headers]


cases = []
counters = {}


def add(family, group, variable, value, method, target, headers, *, ref=False,
        proxy=None, source="constructed", notes=None, body=None):
    counters[family] = counters.get(family, 0) + 1
    case_id = f"{family}-{counters[family]:03d}"
    text = render(method, target, headers, body)
    cases.append({
        "case_id": case_id, "family": family, "group": group,
        "variable": variable, "value": value, "is_reference": ref,
        "pair_with": None,                       # filled below from the group reference
        "expected_label": "ALLOW", "source": source,
        "text": text, "text_sha256": hashlib.sha256(text.encode()).hexdigest(),
        "proxy": proxy,                          # curl reproduction spec, or None
        "excluded": False, "notes": notes,
    })


def curl_spec(host, path, remove=(), add_headers=(), ua=None):
    return {"host_header": host, "path": path, "remove": list(remove),
            "add": [list(h) for h in add_headers], "user_agent": ua}


# A. HOST / LOOPBACK — only the Host value changes; port fixed at 9000.
for ctx in CONTEXTS:
    path = CONTEXTS[ctx][0]
    for h in HOSTS:
        add("HOST", f"HOST|{ctx}", "Host", h, "GET", path, ctx_headers(ctx, h),
            ref=(h == "localhost:9000"),
            proxy=curl_spec(h, path) if ctx == "K1-curl-proxy" else None)

# B. PATH — only the request target changes. Also under a loopback Host, where the
# 2026-09-17 audit reported that the path modulated the loopback effect.
for ctx, host in (("K1-curl-proxy", "localhost:9000"), ("K2-curl-direct", "localhost:9000"),
                  ("K3-browser", "localhost:9000"), ("K1-curl-proxy", "127.0.0.1:9000")):
    for p in PATHS:
        proxied = ctx == "K1-curl-proxy" and (
            (host == "localhost:9000" and p in ("/", "/index.html", "/products?id=42",
                                                "/miembros/imagenes/zarauz.jpg"))
            or (host == "127.0.0.1:9000" and p in ("/", "/index.html",
                                                  "/miembros/imagenes/zarauz.jpg")))
        add("PATH", f"PATH|{ctx}|{host}", "path", p, "GET", p, ctx_headers(ctx, host),
            ref=(p == "/index.html"), proxy=curl_spec(host, p) if proxied else None)

# C. PORT — only the port in Host changes (None = no port), for two hostnames.
for hostname in ("localhost", "app.fwlab.test"):
    for port in PORTS:
        h = hostname if port is None else f"{hostname}:{port}"
        proxied = hostname == "localhost" and port in (9000, 18080, 19000, 65000)
        add("PORT", f"PORT|K1-curl-proxy|{hostname}", "port", port, "GET", "/index.html",
            ctx_headers("K1-curl-proxy", h), ref=(port == 9000),
            proxy=curl_spec(h, "/index.html") if proxied else None)

# D. HEADERS — one header removed or added against a base context.
toggles = {
    "K1-curl-proxy": [("-User-Agent",), ("-Proxy-Connection",), ("-Accept",),
                      ("+Connection", "close"), ("+Cookie", COOKIE)],
    "K2-curl-direct": [("-User-Agent",), ("-Accept",), ("+Connection", "close"),
                       ("+Cookie", COOKIE), ("+Proxy-Connection", "Keep-Alive")],
    "K3-browser": [("-User-Agent",), ("-Accept",), ("+Cookie", COOKIE),
                   ("=Connection", "close")],
}
for host in ("localhost:9000", "127.0.0.1:9000"):
    for ctx, ops in toggles.items():
        if host == "127.0.0.1:9000" and ctx == "K3-browser":
            continue
        base = ctx_headers(ctx, host)
        group = f"HDR|{ctx}|{host}"
        add("HDR", group, "headers", "base", "GET", "/index.html", base, ref=True,
            proxy=curl_spec(host, "/index.html") if ctx == "K1-curl-proxy" else None)
        for op in ops:
            name = op[0][1:]
            if op[0][0] == "-":
                hdrs, val = without(base, name), f"remove {name}"
                spec = curl_spec(host, "/index.html", remove=[name])
            elif op[0][0] == "+":
                hdrs, val = base + [(name, op[1])], f"add {name}: {op[1]}"
                spec = curl_spec(host, "/index.html", add_headers=[(name, op[1])])
            else:
                hdrs, val = replaced(base, name, op[1]), f"set {name}: {op[1]}"
                spec = None
            proxied = ctx == "K1-curl-proxy" and spec is not None and (
                host == "localhost:9000"
                or val in ("add Cookie: " + COOKIE, "remove Proxy-Connection"))
            add("HDR", group, "headers", val, "GET", "/index.html", hdrs,
                proxy=spec if proxied else None)

# D2. Interaction User-Agent x Proxy-Connection (reported as changing together on
# 2026-09-17): the full 2x2 grid in the curl context, for both hosts.
for host in ("localhost:9000", "127.0.0.1:9000"):
    full = ctx_headers("K1-curl-proxy", host)
    group = f"UAxPC|{host}"
    for ua_on in (True, False):
        for pc_on in (True, False):
            hdrs = full
            if not ua_on:
                hdrs = without(hdrs, "User-Agent")
            if not pc_on:
                hdrs = without(hdrs, "Proxy-Connection")
            add("UAxPC", group, "UA x Proxy-Connection",
                f"UA {'on' if ua_on else 'off'}, PC {'on' if pc_on else 'off'}",
                "GET", "/index.html", hdrs, ref=(ua_on and pc_on))

# E. UA VALUE — only the User-Agent value changes.
for ctx, host in (("K1-curl-proxy", "localhost:9000"), ("K1-curl-proxy", "127.0.0.1:9000"),
                  ("K2-curl-direct", "localhost:9000")):
    for name, ua in UA.items():
        proxied = (ctx == "K1-curl-proxy" and host == "localhost:9000"
                   and name in ("curl-8.18.0", "wget", "firefox"))
        add("UA", f"UA|{ctx}|{host}", "User-Agent", name, "GET", "/index.html",
            replaced(ctx_headers(ctx, host), "User-Agent", ua), ref=(name == "curl-8.18.0"),
            proxy=curl_spec(host, "/index.html", ua=ua) if proxied else None)

# F. IN-DISTRIBUTION HOST SWAP — ALLOW rows of the V4 eval split (label from the
# dataset), with only the Host value swapped. Counterexample family from 2026-09-17.
rows = [json.loads(line) for line in open(EVAL) if line.strip()]
allow_idx = [i for i, r in enumerate(rows) if r["output"].startswith("ALLOW")]
picked = sorted(random.Random(SEED).sample(allow_idx, N_EVAL_ROWS))
for i in picked:
    text = rows[i]["input"]
    head, sep, body = text.partition("\n\n")
    lines = head.split("\n")
    method, target, _ = lines[0].split(" ", 2)
    headers = [tuple(l.split(": ", 1)) for l in lines[1:]]
    if not any(k.lower() == "host" for k, _ in headers):
        continue
    orig_host = next(v for k, v in headers if k.lower() == "host")
    group = f"EVALSWAP|row{i}"
    for label, h in (("original", orig_host), ("localhost:9000", "localhost:9000"),
                     ("127.0.0.1:9000", "127.0.0.1:9000")):
        add("EVALSWAP", group, "Host", label, method, target,
            replaced(headers, "Host", h), ref=(label == "original"),
            source=f"datasets/v4_clean/eval.jsonl row {i} (label ALLOW)",
            body=body if sep else None)
        # the original row must be reproduced byte for byte
        if label == "original":
            assert cases[-1]["text"] == text, f"row {i} not reproduced exactly"

# Pair every non-reference case with its group's reference.
refs = {c["group"]: c["case_id"] for c in cases if c["is_reference"]}
for c in cases:
    if not c["is_reference"]:
        c["pair_with"] = refs[c["group"]]

with open(os.path.join(HERE, "cases.jsonl"), "w") as f:
    for c in cases:
        f.write(json.dumps(c, ensure_ascii=False) + "\n")

unique = {c["text_sha256"] for c in cases}
proxy_cases = [c for c in cases if c["proxy"]]
print(f"cases {len(cases)} · unique texts {len(unique)} · proxy cases {len(proxy_cases)} "
      f"(unique proxy texts {len({c['text_sha256'] for c in proxy_cases})}) · "
      f"eval rows {picked}")
