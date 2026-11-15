"""
Transport fidelity of the TLS / HTTP/2 front, with a V5 DOUBLE. It proves mechanisms, not detection.

    .venv-dataplane/bin/python -B scripts/local_stack/transport_check.py --config scripts/local_stack/stack.example.json --out <new evidence dir> --work <new private dir>

The same logical request goes through three transports:

    plain    HTTP/1.1 straight to the gateway (no front): the reference path of every earlier experiment
    tls_h1   HTTP/1.1 over TLS through the front
    tls_h2   HTTP/2 over TLS through the front (converted to one HTTP/1.1 message per stream)

The upstream is `raw_sink.py`, which keeps the exact bytes it received. A forwarder between the gateway
and the V5 double keeps the SHA-256 of the canonical text V5 was asked about. For every case and
transport the check records: what the client got, whether and how the upstream received it (method,
target, Host, relevant headers, body, framing), the gateway record (applied, stage, status), the
canonical digest at V5, and the front's own log (did it reach the gateway at all).

It passes when, for each case, method, target, relevant headers, body, canonical text, decision and
reception are equal across transports, except the normalizations the front declares (body re-framed with
Content-Length, cookie crumbs joined, underscore header names dropped), which are asserted as such.
Special cases (smuggling-shaped framing, absolute form, :authority/Host mismatch, multiplexing, a stream
cancelled mid-body, connection reuse, TLS resumption, h2c, plain HTTP to the TLS port, size limits)
are checked against a stated safety property and their observed behaviour is recorded.

The V5 double BLOCKs any canonical text containing `evil`. Cases are synthetic and authored here.
"""
import argparse
import base64
import hashlib
import json
import os
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
OPS = os.path.join(REPO, "scripts", "gateway_ops")
sys.path[:0] = [HERE, OPS, os.path.join(REPO, "data_plane")]

import fault_proxy as FP          # noqa: E402
import live_stack as L            # noqa: E402
import stack as S                 # noqa: E402
import wire_clients as WC         # noqa: E402

AUTHORITY = "notes.fwlab.test"
TRANSPORTS = ("plain", "tls_h1", "tls_h2")
# Headers the front may add or rewrite by construction. Anything else at the upstream that the client
# did not send is a failure.
STRUCTURAL = {"host", "content-length", "transfer-encoding"}
ADDED_BY_PROXIES = {"x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "x-real-ip", "forwarded",
                    "via", "x-request-id"}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Tail:
    def __init__(self, path):
        self.path = path
        self.offset = 0

    def mark(self):
        self.offset = os.path.getsize(self.path) if os.path.exists(self.path) else 0

    def new(self):
        if not os.path.exists(self.path):
            return []
        with open(self.path, "rb") as fh:
            fh.seek(self.offset)
            data = fh.read()
        lines = data.split(b"\n")
        return [json.loads(x) for x in lines[:-1] if x.strip()]


class Observer:
    def __init__(self, state, proxy):
        self.sink = Tail(state["app_log"])
        self.decisions = Tail(state["gateway_decisions"])
        self.front = Tail(state["front_access_log"])
        self.proxy = proxy
        self.calls = 0

    def mark(self):
        for t in (self.sink, self.decisions, self.front):
            t.mark()
        self.calls = self.proxy.classify_calls

    def collect(self, expect_front, wait=2.0):
        """New lines since mark. Waits for the asynchronous logs to settle."""
        deadline = time.monotonic() + wait
        while True:
            decisions = [r for r in self.decisions.new() if r.get("kind") == "decision"]
            front = self.front.new()
            if (decisions or time.monotonic() > deadline) and (not expect_front or front or time.monotonic() > deadline):
                break
            time.sleep(0.05)
        time.sleep(0.15)
        received = [WC.parse_request(base64.b64decode(r["b64"])) for r in self.sink.new()]
        decisions = [r for r in self.decisions.new() if r.get("kind") == "decision"]
        calls = self.proxy.classify_calls - self.calls
        return {"received": received, "decisions": decisions, "front": self.front.new(),
                "v5_calls": calls, "canonical_sha256": self.proxy.canonical_sha256 if calls else None}


# ─────────────────────────────── cases ───────────────────────────────
def case(cid, method, target, headers=(), body=b"", *, forward=True, note="", h2_cookie_crumbs=None,
         front_drops=(), chunked=False, h2_no_content_length=False, transports=TRANSPORTS):
    return {"id": cid, "method": method, "target": target, "headers": list(headers), "body": body,
            "forward": forward, "note": note, "h2_cookie_crumbs": h2_cookie_crumbs,
            "front_drops": list(front_drops), "chunked": chunked,
            "h2_no_content_length": h2_no_content_length, "transports": list(transports)}


FORM = ("Content-Type", "application/x-www-form-urlencoded")
JSON = ("Content-Type", "application/json")
TEXT = ("Content-Type", "text/plain; charset=utf-8")


def matrix_cases():
    big = b"a" * 19000
    return [
        case("get_root", "GET", "/"),
        case("get_static", "GET", "/static/app.css", [("Accept", "text/css")]),
        case("get_query_encoded", "GET", "/search?q=caf%C3%A9+au+lait&tag=a%2Fb&x=1&x=2&empty="),
        case("post_form", "POST", "/notes", [FORM], b"title=Hello&body=World+%21&tag=home&csrf_token=t0k"),
        case("post_json", "POST", "/api/v1/notes", [JSON, ("Authorization", "Bearer aaa.bbb.ccc")],
             b'{"title":"Plan","body":"Ship v1","tag":"work"}'),
        case("put_json", "PUT", "/api/v1/notes/7", [JSON], b'{"title":"Renamed"}'),
        case("patch_text", "PATCH", "/api/v1/notes/7", [TEXT], "naïve café\n".encode("utf-8")),
        case("delete_bearer", "DELETE", "/api/v1/notes/7", [("Authorization", "Bearer aaa.bbb.ccc")]),
        case("options", "OPTIONS", "/api/v1/notes"),
        case("head", "HEAD", "/static/app.css"),
        case("session_csrf_headers", "POST", "/account/email",
             [FORM, ("Cookie", "fwlab_sid=s3ss10n; theme=dark"), ("X-CSRF-Token", "t0k"),
              ("Origin", "https://notes.fwlab.test:8443"), ("Referer", "https://notes.fwlab.test:8443/account")],
             b"email=a%40example.test", h2_cookie_crumbs=["fwlab_sid=s3ss10n", "theme=dark"],
             note="HTTP/2 sends two cookie fields; the front must join them as one Cookie header"),
        case("underscore_header", "GET", "/notes", [("X_Forwarded_For", "203.0.113.9"), ("X-Lab-Note", "kept")],
             front_drops=["x_forwarded_for"],
             note="nginx drops header names with underscores (default); plain HTTP/1.1 keeps it"),
        case("block_query", "GET", "/search?q=evil", forward=False),
        case("block_json", "POST", "/api/v1/notes", [JSON], b'{"title":"evil"}', forward=False),
        case("body_19000", "POST", "/notes", [TEXT], big),
        case("chunked_body", "POST", "/notes", [TEXT], b"chunked body of a note", chunked=True,
             transports=("plain", "tls_h1"),
             note="the front re-frames a chunked body with Content-Length; the canonical text must not change"),
        case("h2_body_without_length", "POST", "/notes", [TEXT], b"stream body without length",
             h2_no_content_length=True, transports=("tls_h2",),
             note="compared with post_text_reference"),
        case("post_text_reference", "POST", "/notes", [TEXT], b"stream body without length"),
    ]


# ─────────────────────────────── one exchange per transport ───────────────────────────────
class Runner:
    def __init__(self, state, proxy):
        self.state = state
        self.ports = state["ports"]
        self.obs = Observer(state, proxy)
        ca = state["pki"]["ca_cert"]
        self.tls_h1 = WC.tls_context(ca, ("http/1.1",))
        self.tls_h2 = WC.tls_context(ca, ("h2",))

    def send(self, c, transport):
        self.obs.mark()
        head = c["method"] == "HEAD"
        if transport == "tls_h2":
            client = WC.H2Client(self.ports["front_tls"], self.tls_h2, AUTHORITY)
            try:
                headers = [(n, v) for n, v in c["headers"] if not (c["h2_cookie_crumbs"] and n.lower() == "cookie")]
                hdrs = WC.h2_request_headers(c["method"], c["target"], AUTHORITY, headers, c["body"],
                                             content_length=not c["h2_no_content_length"])
                for crumb in c["h2_cookie_crumbs"] or ():
                    hdrs.append(("cookie", crumb))
                sid = client.request(hdrs, c["body"])
                got = client.collect([sid])[sid]
                result = {"status": got["status"], "error": None if got["status"] else
                          (f"reset:{got['reset']}" if got["reset"] is not None else client.terminated or "no_response"),
                          "body": got["body"], "alpn": client.alpn}
            finally:
                client.close()
        else:
            raw = WC.build_h1(c["method"], c["target"], AUTHORITY, c["headers"], c["body"], chunked=c["chunked"])
            if transport == "plain":
                result = WC.h1_exchange(self.ports["gateway"], raw, head=head)
            else:
                result = WC.h1_exchange(self.ports["front_tls"], raw, tls=self.tls_h1, server_hostname=AUTHORITY,
                                        head=head)
        seen = self.obs.collect(expect_front=transport != "plain")
        return summarize(c, transport, result, seen)


def summarize(c, transport, result, seen):
    row = {"case": c["id"], "transport": transport, "client_status": result.get("status"),
           "client_error": result.get("error"), "alpn": result.get("alpn"),
           "client_body_sha256": sha(result.get("body") or b""),
           "firewall_answer": (result.get("body") or b"").startswith(b"Request blocked by firewall-IA")
           or (result.get("body") or b"").startswith(b"Request rejected by firewall-IA"),
           "received_count": len(seen["received"]), "v5_calls": seen["v5_calls"],
           "canonical_sha256": seen["canonical_sha256"]}
    if seen["received"]:
        r = seen["received"][0]
        names = [n.lower() for n, _ in r["headers"]]
        row["received"] = {"method": r["method"], "target": r["target"], "version": r["version"],
                           "framing": r["framing"], "body_sha256": sha(r["body"]), "body_bytes": len(r["body"]),
                           "header_names": names,
                           "host": [v for n, v in r["headers"] if n.lower() == "host"],
                           "headers": {n.lower(): v for n, v in r["headers"]
                                       if n.lower() not in ("content-length", "transfer-encoding")},
                           "header_name_case": [n for n, _ in r["headers"]]}
    if seen["decisions"]:
        d = seen["decisions"][-1]
        row["gateway"] = {"records": len(seen["decisions"]), "applied": d.get("applied"),
                          "deciding_stage": d.get("deciding_stage"), "http_status": d.get("http_status"),
                          "reason": d.get("reason"), "canonical_outcome": d.get("canonical_outcome")}
    if seen["front"]:
        f = seen["front"][-1]
        row["front"] = {"protocol": f["protocol"], "status": f["status"], "upstream_status": f["upstream_status"],
                        "tls_protocol": f["tls_protocol"], "tls_reused": f["tls_reused"],
                        # nginx fills upstream_status with 502 when it could not connect: only a
                        # connect time proves the gateway was reached.
                        "reached_gateway": f["upstream_connect_time"] not in ("", "-")}
    row["attribution"] = attribute(row)
    return row


def attribute(row):
    """Which layer produced the answer the client saw."""
    front = row.get("front")
    if front is not None and not front["reached_gateway"]:
        return "front"
    if row["received_count"]:
        return "upstream"
    if row.get("gateway") and row["gateway"]["applied"] == "DENY":
        return "firewall"
    if row["client_status"] is None:
        return "no_answer"
    # mitmproxy's own HTTP/1.1 layer answered before the cascade saw a request (e.g. CL+TE, over
    # body_size_limit): still the gateway process, but no decision record exists.
    return "gateway_protocol"


# ─────────────────────────────── matrix checks ───────────────────────────────
def expected_headers(c, transport):
    exp = {}
    for n, v in c["headers"]:
        n = n.lower()
        if transport != "plain" and n in c["front_drops"]:
            continue
        exp[n] = v
    return exp


def check_matrix_case(c, rows):
    problems = []
    by = {r["transport"]: r for r in rows}
    for t, r in by.items():
        want_forward = c["forward"]
        if want_forward and r["received_count"] != 1:
            problems.append(f"{t}: received {r['received_count']} times, expected once")
        if not want_forward and r["received_count"]:
            problems.append(f"{t}: blocked case reached the upstream")
        if not want_forward and r["client_status"] != 403:
            problems.append(f"{t}: blocked case answered {r['client_status']}")
        if want_forward and r["client_status"] != 200:
            problems.append(f"{t}: forwarded case answered {r['client_status']}")
        g = r.get("gateway")
        if g is None:
            problems.append(f"{t}: no gateway record")
        elif g["applied"] != ("FORWARD" if want_forward else "DENY"):
            problems.append(f"{t}: gateway applied {g['applied']}")
        if r["v5_calls"] != 1:
            problems.append(f"{t}: V5 called {r['v5_calls']} times")
        if t != "plain" and not (r.get("front") or {}).get("reached_gateway"):
            problems.append(f"{t}: front log does not show the gateway")
        rec = r.get("received")
        if rec:
            if rec["method"] != c["method"]:
                problems.append(f"{t}: method {rec['method']}")
            if rec["target"] != c["target"]:
                problems.append(f"{t}: target changed")
            if rec["host"] != [AUTHORITY]:
                problems.append(f"{t}: Host {rec['host']}")
            if rec["body_sha256"] != sha(c["body"]):
                problems.append(f"{t}: body changed ({rec['body_bytes']} bytes)")
            for n, v in expected_headers(c, t).items():
                if rec["headers"].get(n) != v:
                    problems.append(f"{t}: header {n} = {rec['headers'].get(n)!r}")
            for n in c["front_drops"]:
                if t != "plain" and n in rec["headers"]:
                    problems.append(f"{t}: {n} should be dropped by the front")
            sent = set(expected_headers(c, t)) | STRUCTURAL
            extra = sorted(set(rec["header_names"]) - sent)
            if extra:
                problems.append(f"{t}: headers not sent by the client: {extra}")
            if set(rec["header_names"]) & ADDED_BY_PROXIES - set(expected_headers(c, t)):
                problems.append(f"{t}: proxy header added")
            want_framing = ("chunked" if c["chunked"] else "content-length") if t == "plain" else "content-length"
            if c["body"] and rec["framing"] != want_framing:
                problems.append(f"{t}: framing {rec['framing']}, expected {want_framing}")
            if rec["header_names"].count("cookie") > 1:
                problems.append(f"{t}: more than one Cookie header")
    digests = {r["canonical_sha256"] for r in rows}
    if len(digests) != 1:
        problems.append("canonical text differs across transports")
    statuses = {(r.get("gateway") or {}).get("applied") for r in rows}
    if len(statuses) != 1:
        problems.append("decision differs across transports")
    return problems


# ─────────────────────────────── special cases ───────────────────────────────
def special_cases(run, plain_reference):
    out = []
    ports = run.ports

    def record(cid, prop, rows, ok, note=""):
        out.append({"case": cid, "property": prop, "passed": bool(ok), "rows": rows, "note": note})

    # 1. Content-Length and Transfer-Encoding together (request smuggling shape)
    raw = (f"POST /notes HTTP/1.1\r\nHost: {AUTHORITY}\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n"
           "Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n").encode()
    rows = []
    for t in ("plain", "tls_h1"):
        run.obs.mark()
        res = (WC.h1_exchange(ports["gateway"], raw) if t == "plain" else
               WC.h1_exchange(ports["front_tls"], raw, tls=run.tls_h1, server_hostname=AUTHORITY))
        rows.append(summarize({"id": "cl_te"}, t, res, run.obs.collect(expect_front=t != "plain")))
    ok = all(r["received_count"] == 0 or (r["received"]["framing"] != "none" and
             r["received"]["header_names"].count("content-length") + r["received"]["header_names"].count("transfer-encoding") == 1)
             for r in rows)
    record("cl_and_te_together", "never delivered with two framings; rejected or re-framed once", rows, ok)

    # 2. absolute-form target
    raw = f"GET http://{AUTHORITY}/notes HTTP/1.1\r\nHost: {AUTHORITY}\r\n\r\n".encode()
    rows = []
    for t in ("plain", "tls_h1"):
        run.obs.mark()
        res = (WC.h1_exchange(ports["gateway"], raw) if t == "plain" else
               WC.h1_exchange(ports["front_tls"], raw, tls=run.tls_h1, server_hostname=AUTHORITY))
        rows.append(summarize({"id": "absolute"}, t, res, run.obs.collect(expect_front=t != "plain")))
    ok = all(r["received_count"] == 0 or (r["received"]["target"].startswith("/") and r.get("gateway"))
             for r in rows)
    record("absolute_form_target", "never delivered in absolute form; if delivered, decided on the origin form",
           rows, ok)

    # 3. HTTP/2 :authority and host disagree
    run.obs.mark()
    client = WC.H2Client(ports["front_tls"], run.tls_h2, AUTHORITY, validate=False)
    try:
        sid = client.request([(":method", "GET"), (":scheme", "https"), (":authority", AUTHORITY),
                              (":path", "/notes"), ("host", "other.fwlab.test")])
        got = client.collect([sid])[sid]
    finally:
        client.close()
    row = summarize({"id": "authority"}, "tls_h2", {"status": got["status"], "body": got["body"],
                                                    "error": None if got["status"] else "no_response"},
                    run.obs.collect(expect_front=True))
    ok = row["received_count"] == 0 or (len(row["received"]["host"]) == 1)
    record("h2_authority_host_mismatch", "at most one Host reaches the gateway", [row], ok,
           note="which value wins is recorded in rows[0].received.host")

    # 4. multiplexing: 8 streams on one connection
    run.obs.mark()
    client = WC.H2Client(ports["front_tls"], run.tls_h2, AUTHORITY)
    targets = [f"/notes?page={i}" for i in range(7)] + ["/search?q=evil"]
    try:
        sids = [client.request(WC.h2_request_headers("GET", t, AUTHORITY)) for t in targets]
        got = client.collect(sids)
    finally:
        client.close()
    time.sleep(0.5)
    seen = run.obs.collect(expect_front=True)
    received_targets = sorted(r["target"] for r in seen["received"])
    statuses = [got[s]["status"] for s in sids]
    ok = (received_targets == sorted(targets[:7]) and statuses[:7] == [200] * 7 and statuses[7] == 403
          and len(seen["decisions"]) == 8)
    record("h2_multiplexed_streams", "each stream delivered once or blocked, decided once",
           [{"statuses": statuses, "received": len(seen["received"]), "decisions": len(seen["decisions"]),
             "front_lines": len(seen["front"]), "v5_calls": seen["v5_calls"]}], ok)

    # 5. a stream cancelled in the middle of its body
    run.obs.mark()
    client = WC.H2Client(ports["front_tls"], run.tls_h2, AUTHORITY)
    try:
        body = b"x" * 4000
        sid = client.request(WC.h2_request_headers("POST", "/notes", AUTHORITY, [TEXT], body), body, end=False,
                             partial=1500)
        time.sleep(0.3)
        client.reset(sid)
        time.sleep(0.5)
    finally:
        client.close()
    seen = run.obs.collect(expect_front=True, wait=1.5)
    ok = not seen["received"] and not seen["decisions"] and seen["v5_calls"] == 0
    record("h2_stream_cancelled_mid_body", "a cancelled stream is never classified nor delivered",
           [{"received": len(seen["received"]), "decisions": len(seen["decisions"]), "v5_calls": seen["v5_calls"],
             "front": seen["front"][-1] if seen["front"] else None}], ok)

    # 6. connection reuse: three requests on one TLS HTTP/1.1 connection
    run.obs.mark()
    statuses = []
    with WC.connect(ports["front_tls"], tls=run.tls_h1, server_hostname=AUTHORITY) as sock:
        for i in range(3):
            sock.sendall(WC.build_h1("GET", f"/notes?n={i}", AUTHORITY))
            statuses.append(WC.read_response(sock)[0])
    time.sleep(0.3)
    seen = run.obs.collect(expect_front=True)
    conns = {f["connection"] for f in seen["front"]}
    ok = statuses == [200] * 3 and len(seen["received"]) == 3 and len(conns) == 1
    record("tls_h1_keepalive", "three requests on one client connection, each delivered once",
           [{"statuses": statuses, "received": len(seen["received"]), "client_connections_at_front": len(conns),
             "connection_requests": [f["connection_requests"] for f in seen["front"]]}], ok)

    # 7. TLS session resumption (TLS 1.2 and 1.3)
    rows = []
    for version in ("TLSv1_2", "TLSv1_3"):
        ctx = WC.tls_context(run.state["pki"]["ca_cert"], ("http/1.1",))
        ctx.minimum_version = ctx.maximum_version = getattr(__import__("ssl").TLSVersion, version)
        run.obs.mark()
        first = WC.h1_exchange(ports["front_tls"], WC.build_h1("GET", "/notes", AUTHORITY), tls=ctx,
                               server_hostname=AUTHORITY)
        second = WC.h1_exchange(ports["front_tls"], WC.build_h1("GET", "/notes", AUTHORITY), tls=ctx,
                                server_hostname=AUTHORITY, session=first.get("tls_session"))
        seen = run.obs.collect(expect_front=True)
        rows.append({"version": version, "statuses": [first["status"], second["status"]],
                     "client_reused": [first.get("tls_session_reused"), second.get("tls_session_reused")],
                     "front_reused": [f["tls_reused"] for f in seen["front"]]})
    ok = all(r["statuses"] == [200, 200] for r in rows)
    record("tls_new_and_resumed", "new and resumed TLS sessions both served; reuse recorded", rows, ok,
           note="whether a resumption happened is an observation for the latency runs, not a pass condition")

    # 8. h2c (prior knowledge) straight at the plain gateway port
    run.obs.mark()
    try:
        with socket.create_connection(("127.0.0.1", ports["gateway"]), timeout=5) as s:
            s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + b"\x00\x00\x00\x04\x00\x00\x00\x00\x00")
            s.settimeout(3)
            answer = s.recv(200)
    except OSError as exc:
        answer = f"error:{type(exc).__name__}".encode()
    seen = run.obs.collect(expect_front=False, wait=1.0)
    ok = not seen["received"] and seen["v5_calls"] == 0
    record("h2c_prior_knowledge_to_gateway", "the gateway never forwards nor classifies HTTP/2",
           [{"answer_head": answer[:40].decode("latin-1"), "received": len(seen["received"]),
             "v5_calls": seen["v5_calls"], "decisions": len(seen["decisions"])}], ok)

    # 9. plain HTTP to the TLS port
    run.obs.mark()
    res = WC.h1_exchange(ports["front_tls"], WC.build_h1("GET", "/", AUTHORITY))
    seen = run.obs.collect(expect_front=True, wait=1.0)
    ok = not seen["received"] and seen["v5_calls"] == 0
    record("plain_http_to_tls_port", "answered by the front, never forwarded",
           [{"status": res["status"], "received": len(seen["received"]), "v5_calls": seen["v5_calls"],
             "front": seen["front"][-1] if seen["front"] else None}], ok)

    # 10. dot segments and encoded slashes. nginx validates the path before proxying; whatever it does,
    # it must either forward the client's target unchanged or answer itself (and be attributed).
    for cid, target in (("dot_segments_raw", "/static/../notes"),
                        ("dot_segments_encoded_slash", "/notes/..%2F..%2Fetc%2Fpasswd"),
                        ("dot_segments_escape_root", "/../../etc/passwd"),
                        ("traversal_in_query", "/files?name=..%2F..%2Fprivate%2Fcanary.txt"),
                        ("encoded_dot_segments", "/static/%2e%2e/notes"),
                        ("double_slash", "//notes//1")):
        c = case(cid, "GET", target)
        rows = [run.send(c, t) for t in TRANSPORTS]
        ok = all((r["received_count"] == 1 and r["received"]["target"] == target and r["attribution"] == "upstream")
                 or (r["received_count"] == 0 and r["attribution"] in ("front", "firewall", "gateway_protocol"))
                 for r in rows)
        record(cid, "the client's target is delivered unchanged, or the answer is attributed to the layer "
                    "that refused it", rows, ok,
               note="a front refusal is not a model decision and is reported apart in any evaluation")

    # 11. bodies above the canonical limit and above the front limit
    for cid, size in (("body_over_canonical_limit", 30000), ("body_over_front_limit", 70000)):
        c = case(cid, "POST", "/notes", [TEXT], b"b" * size)
        rows = [run.send(c, t) for t in TRANSPORTS]
        ok = all(r["received_count"] == 0 and r["v5_calls"] == 0 and r["client_status"] and r["client_status"] >= 400
                 for r in rows)
        record(cid, "never delivered nor classified; answered 4xx by the gateway or the front", rows, ok)
    return out


# ─────────────────────────────── main ───────────────────────────────
def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--work", required=True)
    args = parser.parse_args(argv)
    if os.path.exists(args.out) or os.path.exists(args.work):
        sys.exit("refusing to reuse --out or --work")
    os.makedirs(args.out)
    os.makedirs(args.work)
    cfg = S.load_config(args.config)
    manifest_path, _ = S.check_manifest(cfg)

    double_port = L.free_port()
    double_log = open(os.path.join(args.work, "v5-double.log"), "ab")
    double = subprocess.Popen([L.PYTHON, os.path.join(OPS, "service_doubles.py"), "--role", "v5", "--port",
                               str(double_port), "--manifest", manifest_path], stdout=double_log,
                              stderr=subprocess.STDOUT, start_new_session=True)
    proxy = None
    stack_work = os.path.join(args.work, "stack")
    started = False
    try:
        S.wait_until(lambda: S.http_get(f"http://127.0.0.1:{double_port}/health")[0] == 200, 15, "V5 double", double)
        proxy = FP.FaultProxy(f"http://127.0.0.1:{double_port}")
        code = S.main(["up", "--config", args.config, "--work", stack_work, "--v5", "url:" + proxy.url,
                       "--upstream", "raw-sink"])
        if code != 0:
            raise SystemExit(f"stack up failed ({code})")
        started = True
        state = S.State(stack_work).load()
        run = Runner(state, proxy)
        rows, verdicts = [], []
        reference = {}
        for c in matrix_cases():
            case_rows = [run.send(c, t) for t in c["transports"]]
            rows.extend(case_rows)
            reference[c["id"]] = case_rows
            verdicts.append({"case": c["id"], "transports": c["transports"], "note": c["note"],
                             "problems": check_matrix_case(c, case_rows) if len(c["transports"]) > 1 or c["forward"]
                             else []})
        # Re-framed bodies must give the canonical text of the same body sent with Content-Length.
        pairs = [("chunked_body", "plain", "chunked_body", "tls_h1"),
                 ("h2_body_without_length", "tls_h2", "post_text_reference", "plain")]
        for a, ta, b, tb in pairs:
            ra = next(r for r in reference[a] if r["transport"] == ta)
            rb = next(r for r in reference[b] if r["transport"] == tb)
            ok = ra["canonical_sha256"] == rb["canonical_sha256"] and ra.get("received", {}).get("body_sha256") == \
                rb.get("received", {}).get("body_sha256")
            verdicts.append({"case": f"{a}[{ta}] == {b}[{tb}]", "transports": [ta, tb],
                             "note": "same canonical text and body after re-framing",
                             "problems": [] if ok else ["canonical text or body differs"]})
        specials = special_cases(run, reference)
        identity = state["identity"]
    finally:
        if os.path.exists(os.path.join(stack_work, S.STATE_FILE)) and not started:
            pass                      # a failed `up` already stopped what it started
        elif started:
            S.main(["down", "--work", stack_work])
        if proxy is not None:
            proxy.close()
        double.terminate()
        double.wait(timeout=5)
        double_log.close()
    clean = _clean(stack_work)
    passed = all(not v["problems"] for v in verdicts) and all(s["passed"] for s in specials) and clean["clean"]
    doc = {"schema": "firewall-local-stack-transport-check/v1", "created_utc": time.time(),
           "kind": "MECHANISM_CHECK_WITH_V5_DOUBLE", "detection_quality": "NOT_MEASURED",
           "identity": identity, "passed": passed, "verdicts": verdicts, "special_cases": specials,
           "rows": rows, "clean_after": clean,
           "cases": [{k: (v.decode("latin-1") if isinstance(v, bytes) and len(v) < 200 else
                          (f"<{len(v)} bytes sha256={sha(v)}>" if isinstance(v, bytes) else v))
                      for k, v in c.items()} for c in matrix_cases()]}
    with open(os.path.join(args.out, "TRANSPORT.json"), "x", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True, default=str)
        fh.write("\n")
    print(json.dumps({"passed": passed, "matrix_failures": [v for v in verdicts if v["problems"]],
                      "special_failures": [s["case"] for s in specials if not s["passed"]],
                      "clean": clean["clean"]}, indent=2, default=str))
    return 0 if passed else 1


def _clean(stack_work):
    state = S.State(stack_work)
    state.load()
    return S.clean_report(state)


if __name__ == "__main__":
    sys.exit(main())
