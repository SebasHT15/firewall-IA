"""
Application controls and rejection attribution through the local stack, with a V5 DOUBLE.

    .venv-dataplane/bin/python -B scripts/local_stack/app_check.py --config scripts/local_stack/stack.example.json --out <new evidence dir> --work <new private dir> [--effect-smoke]

It runs one browser-like session scenario (login with CSRF, session rotation, notes, logout) and one API
scenario (JWT: issue, scope, algorithm confusion, signature, claims, revocation) through three paths:

    direct   HTTP/1.1 to the application itself, no firewall: what the application decides on its own
    tls_h1   HTTP/1.1 over TLS through the front and the gateway
    tls_h2   HTTP/2 over TLS through the front and the gateway, one connection per scenario

For every request the LAYER that answered is measured from three independent logs, never from the status
alone: the front's access log (did it reach the gateway), the gateway's decision record (DENY/FORWARD),
and the application's own log (served, or rejected with a control and a closed reason). The response is
also checked for the matching marker (`X-Fwlab-Rejected`, or the firewall's body).

Pass: every request gets the expected status, layer, control and reason on every path; the application's
answers are the same with and without the firewall for every request the firewall forwards. Requests
the V5 double blocks (they contain `evil`) are the only firewall rejections, and they never reach the
application. JWT and CSRF are decided by the application only: no token or cookie reaches a model,
because canonical-request/v1 carries neither.

`--effect-smoke` also starts the vulnerable effect routes and shows that each effect oracle fires on a
direct control and on a request the double lets through. It shows the oracle works; it measures no
detector.
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import sys
import time
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import harness as H              # noqa: E402
import stack as S                # noqa: E402
import transport_check as TC     # noqa: E402
import wire_clients as WC        # noqa: E402

AUTHORITY = "notes.fwlab.test"
PATHS = ("direct", "tls_h1", "tls_h2")
FIREWALL_BODIES = (b"Request blocked by firewall-IA", b"Request rejected by firewall-IA")


# ─────────────────────────────── lab secrets, derived like the application ───────────────────────────────
class Lab:
    def __init__(self, seed_hex):
        self.seed = bytes.fromhex(seed_hex)
        self.jwt_key = self.derive("jwt-hs256")
        self.kid = "k1-" + hashlib.sha256(self.jwt_key).hexdigest()[:12]

    def derive(self, label):
        return hmac.new(self.seed, label.encode("ascii"), hashlib.sha256).digest()

    def password(self, user):
        return base64.urlsafe_b64encode(self.derive("password:" + user)).decode("ascii")[:20]

    @staticmethod
    def b64(data):
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    def token(self, *, header=None, claims=None, key=None, digest=hashlib.sha256, signature=None, **over):
        now = int(time.time())
        h = {"alg": "HS256", "typ": "JWT", "kid": self.kid, **(header or {})}
        c = {"iss": "fwlab-notes", "aud": "fwlab-notes-api", "sub": "alice", "iat": now, "nbf": now,
             "exp": now + 300, "jti": "lab-" + os.urandom(6).hex(), "scope": "notes:read", **(claims or {})}
        for k, v in over.items():
            if v is None:
                c.pop(k, None)
            else:
                c[k] = v
        signing = self.b64(json.dumps(h, separators=(",", ":")).encode()) + "." + \
            self.b64(json.dumps(c, separators=(",", ":")).encode())
        if signature is None:
            signature = self.b64(hmac.new(key or self.jwt_key, signing.encode(), digest).digest())
        return signing + "." + signature


# ─────────────────────────────── clients per path ───────────────────────────────
class Client:
    def __init__(self, path, state):
        self.path = path
        self.state = state
        self.cookies = {}
        self.ports = state["ports"]
        self.h2 = None
        ca = state["pki"]["ca_cert"]
        self.tls_h1 = WC.tls_context(ca, ("http/1.1",))
        self.tls_h2 = WC.tls_context(ca, ("h2",))

    def close(self):
        if self.h2:
            self.h2.close()

    def send(self, method, target, headers=(), body=b""):
        headers = list(headers)
        if self.cookies:
            headers.append(("Cookie", "; ".join(f"{k}={v}" for k, v in self.cookies.items())))
        if self.path == "tls_h2":
            if self.h2 is None:
                self.h2 = WC.H2Client(self.ports["front_tls"], self.tls_h2, AUTHORITY)
            sid = self.h2.request(WC.h2_request_headers(method, target, AUTHORITY, headers, body), body)
            got = self.h2.collect([sid])[sid]
            status, resp_headers, resp_body = got["status"], [(k.lower(), v) for k, v in got["headers"]], got["body"]
        else:
            raw = WC.build_h1(method, target, AUTHORITY, headers, body)
            if self.path == "direct":
                with WC.connect_host(self.state["app_ip"], self.state["ports_app"]) as sock:
                    sock.sendall(raw)
                    status, resp_headers, resp_body = WC.read_response(sock, head_request=method == "HEAD")
            else:
                res = WC.h1_exchange(self.ports["front_tls"], raw, tls=self.tls_h1, server_hostname=AUTHORITY,
                                     head=method == "HEAD")
                status, resp_headers, resp_body = res["status"], res["headers"], res["body"]
        for name, value in resp_headers:
            if name == "set-cookie":
                cookie, _, attrs = value.partition(";")
                k, _, v = cookie.strip().partition("=")
                if "max-age=0" in attrs.lower() or "1970" in attrs or not v:
                    self.cookies.pop(k, None)
                else:
                    self.cookies[k] = v
        return status, resp_headers, resp_body or b""


def csrf_from(body):
    m = re.search(rb'name=csrf_token value="([^"]+)"', body)
    return m.group(1).decode() if m else None


# ─────────────────────────────── measurement ───────────────────────────────
class Recorder:
    def __init__(self, state, proxy, path, observe_only=False):
        """observe_only: the firewall arm is a comparator (CRS) whose decisions are recorded, not expected.
        A row then passes when its attribution is complete and consistent."""
        self.path = path
        self.observe_only = observe_only and path != "direct"
        crs = state.get("crs")
        self.waf = TC.Tail(crs["audit_log"]) if crs else None
        self.app = TC.Tail(state["app_log"])
        self.decisions = TC.Tail(state["gateway_decisions"])
        self.front = TC.Tail(state["front_access_log"])
        self.proxy = proxy
        self.rows = []
        self.front_base = self._front_lines()
        self.front_sent = 0

    def _front_lines(self):
        try:
            with open(self.front.path, "rb") as fh:
                return fh.read().count(b"\n")
        except OSError:
            return 0

    def _wait_front(self, timeout=2.0):
        """nginx writes an access line when it finalizes a request, which on a kept-alive HTTP/2
        connection can be after the client already has the answer. Wait until every request sent so far
        has its line, so no line is attributed to the wrong request."""
        deadline = time.monotonic() + timeout
        while self._front_lines() - self.front_base < self.front_sent and time.monotonic() < deadline:
            time.sleep(0.02)

    def step(self, client, sid, method, target, headers=(), body=b"", *, expect, direct=None):
        """expect / direct: (status, layer, control, reason). `direct` overrides expect on the direct path."""
        if self.path != "direct":
            self._wait_front()
        for t in (self.app, self.decisions, self.front) + ((self.waf,) if self.waf else ()):
            t.mark()
        calls = self.proxy.classify_calls if self.proxy else 0
        status, resp_headers, resp_body = client.send(method, target, headers, body)
        if self.path != "direct":
            self.front_sent += 1
            self._wait_front()
        deadline = time.monotonic() + (0.05 if self.path == "direct" else 1.5)
        while True:
            app_lines = self.app.new()
            decisions = [r for r in self.decisions.new() if r.get("kind") == "decision"]
            front = self.front.new()
            settled = self.path == "direct" or (front and (app_lines or decisions))
            if settled or time.monotonic() > deadline:
                break
            time.sleep(0.03)
        waf_blocks = []
        if self.waf is not None and self.path != "direct":
            time.sleep(0.1)
            waf_blocks = [w["transaction"] for w in self.waf.new() if w["transaction"].get("is_interrupted")]
        layer, control, reason = measure(self.path, app_lines, decisions, front, waf_blocks)
        marker = dict(resp_headers).get("x-fwlab-rejected")
        consistent = True
        if layer == "app_rejected":
            consistent = marker == f"{control}/{reason}"
        elif layer == "firewall" and control == "crs":
            consistent = not app_lines and marker is None and len(waf_blocks) == 1
        elif layer == "firewall":
            consistent = resp_body.startswith(FIREWALL_BODIES) and marker is None
        want = direct if (self.path == "direct" and direct is not None) else expect
        got = (status, layer, control, reason)
        row = {"path": self.path, "step": sid, "method": method, "expected": list(want), "observed": list(got),
               "passed": ((layer != "unattributed") if self.observe_only else tuple(want) == got)
               and consistent and len(app_lines) <= 1,
               "marker_consistent": consistent, "app_lines": len(app_lines),
               "gateway": [{"applied": d.get("applied"), "stage": d.get("deciding_stage"),
                            "http_status": d.get("http_status")} for d in decisions],
               "front": [{"protocol": f["protocol"], "status": f["status"], "upstream_status": f["upstream_status"],
                          "upstream_connect_time": f["upstream_connect_time"]} for f in front],
               "waf_rules": sorted({m["details"]["ruleId"] for w in waf_blocks for m in w.get("messages", [])}),
               "v5_calls": (self.proxy.classify_calls - calls) if self.proxy else
               sum(1 for d in decisions if d.get("v5"))}
        if app_lines and app_lines[-1].get("effect") is not None:
            row["effect"] = app_lines[-1]["effect"]
        self.rows.append(row)
        return status, resp_headers, resp_body


def measure(path, app_lines, decisions, front, waf_blocks=()):
    if front and all(f["upstream_connect_time"] in ("", "-") for f in front):
        return "front", None, None
    if waf_blocks and not app_lines:
        return "firewall", "crs", None
    if app_lines:
        line = app_lines[-1]
        if line["outcome"] == "app_rejected":
            return "app_rejected", line["control"], line["reason"]
        return "app", None, None
    if decisions and decisions[-1].get("applied") == "DENY":
        return "firewall", decisions[-1].get("deciding_stage"), None
    return "unattributed", None, None


# ─────────────────────────────── scenarios ───────────────────────────────
APP = "app"
REJ = "app_rejected"
FW = "firewall"
ORIGIN = ("Origin", "https://notes.fwlab.test:8443")
FORM = ("Content-Type", "application/x-www-form-urlencoded")
JSON_CT = ("Content-Type", "application/json")


def form(**fields):
    from urllib.parse import urlencode
    return urlencode(fields).encode()


def session_scenario(rec, client, lab):
    s = rec.step
    s(client, "home", "GET", "/", expect=(200, APP, None, None))
    s(client, "notes_without_session", "GET", "/notes", expect=(303, REJ, "session", "session_required"))
    _, _, body = s(client, "login_form", "GET", "/login", expect=(200, APP, None, None))
    anon_sid, pre_csrf = client.cookies.get("fwlab_sid"), csrf_from(body)
    pw = lab.password("alice")
    s(client, "login_without_csrf", "POST", "/login", [FORM, ORIGIN], form(username="alice", password=pw),
      expect=(403, REJ, "csrf", "token_missing"))
    s(client, "login_bad_csrf", "POST", "/login", [FORM, ORIGIN],
      form(username="alice", password=pw, csrf_token="x" * 43), expect=(403, REJ, "csrf", "token_invalid"))
    s(client, "login_cross_origin", "POST", "/login", [FORM, ("Origin", "https://attacker.example")],
      form(username="alice", password=pw, csrf_token=pre_csrf), expect=(403, REJ, "csrf", "origin_mismatch"))
    s(client, "login_cross_referer", "POST", "/login", [FORM, ("Referer", "https://attacker.example/x")],
      form(username="alice", password=pw, csrf_token=pre_csrf), expect=(403, REJ, "csrf", "referer_mismatch"))
    s(client, "login_wrong_password", "POST", "/login", [FORM, ORIGIN],
      form(username="alice", password="not-the-password", csrf_token=pre_csrf),
      expect=(401, REJ, "login", "bad_credentials"))
    s(client, "login_ok", "POST", "/login", [FORM, ORIGIN], form(username="alice", password=pw, csrf_token=pre_csrf),
      expect=(303, APP, None, None))
    new_sid = client.cookies.get("fwlab_sid")
    rec.rows[-1]["session_rotated"] = bool(new_sid) and new_sid != anon_sid
    rec.rows[-1]["passed"] &= rec.rows[-1]["session_rotated"]
    _, _, body = s(client, "notes_list", "GET", "/notes", expect=(200, APP, None, None))
    csrf = csrf_from(body)
    s(client, "create_with_prelogin_csrf", "POST", "/notes", [FORM, ORIGIN],
      form(title="T", body="b", tag="x", csrf_token=pre_csrf), expect=(403, REJ, "csrf", "token_invalid"))
    saved = dict(client.cookies)
    client.cookies["fwlab_sid"] = anon_sid
    s(client, "create_with_prelogin_session", "POST", "/notes", [FORM, ORIGIN],
      form(title="T", body="b", tag="x", csrf_token=csrf), expect=(303, REJ, "session", "session_required"))
    client.cookies = saved
    s(client, "create_note", "POST", "/notes", [FORM, ORIGIN],
      form(title="Release checklist", body="Tag the build and notify the team.", tag="work", csrf_token=csrf),
      expect=(303, APP, None, None))
    s(client, "create_title_too_long", "POST", "/notes", [FORM, ORIGIN],
      form(title="t" * 121, body="b", tag="x", csrf_token=csrf), expect=(400, REJ, "validation", "field_too_long"))
    s(client, "csrf_in_header", "POST", "/account/email", [FORM, ORIGIN, ("X-CSRF-Token", csrf)],
      form(email="alice@example.test"), expect=(303, APP, None, None))
    s(client, "own_note", "GET", "/notes/1", expect=(200, APP, None, None))
    s(client, "other_users_note", "GET", "/notes/3", expect=(404, REJ, "authorization", "not_owner_or_missing"))
    s(client, "search", "GET", "/search?q=groceries", expect=(200, APP, None, None))
    s(client, "search_blocked_by_double", "GET", "/search?q=evil", expect=(403, FW, "v5", None),
      direct=(200, APP, None, None))
    s(client, "create_blocked_by_double", "POST", "/notes", [FORM, ORIGIN],
      form(title="evil", body="b", tag="x", csrf_token=csrf), expect=(403, FW, "v5", None),
      direct=(303, APP, None, None))
    s(client, "static_css", "GET", "/static/app.css", expect=(200, APP, None, None))
    s(client, "healthz", "GET", "/healthz", expect=(200, APP, None, None))
    s(client, "unknown_route", "GET", "/nope", expect=(404, REJ, "routing", "not_found"))
    s(client, "logout", "POST", "/logout", [FORM, ORIGIN], form(csrf_token=csrf), expect=(303, APP, None, None))
    client.cookies["fwlab_sid"] = new_sid
    s(client, "after_logout", "GET", "/notes", expect=(303, REJ, "session", "session_required"))


def api_scenario(rec, client, lab):
    s = rec.step
    pw = lab.password("alice")

    def bearer(tok):
        return [("Authorization", "Bearer " + tok)]

    s(client, "token_bad_password", "POST", "/api/v1/token", [JSON_CT],
      json.dumps({"username": "alice", "password": "nope"}).encode(), expect=(401, REJ, "login", "bad_credentials"))
    s(client, "token_not_json", "POST", "/api/v1/token", [("Content-Type", "text/plain")], b"alice",
      expect=(415, REJ, "validation", "json_required"))
    _, _, body = s(client, "token_read", "POST", "/api/v1/token", [JSON_CT],
                   json.dumps({"username": "alice", "password": pw}).encode(), expect=(200, APP, None, None))
    read = json.loads(body)["access_token"]
    _, _, body = s(client, "token_write", "POST", "/api/v1/token", [JSON_CT],
                   json.dumps({"username": "alice", "password": pw, "scope": "notes:read notes:write"}).encode(),
                   expect=(200, APP, None, None))
    write = json.loads(body)["access_token"]
    s(client, "no_token", "GET", "/api/v1/notes", expect=(401, REJ, "jwt", "token_missing"))
    s(client, "basic_scheme", "GET", "/api/v1/notes", [("Authorization", "Basic YWxpY2U6eA==")],
      expect=(401, REJ, "jwt", "malformed"))
    s(client, "list_read", "GET", "/api/v1/notes", bearer(read), expect=(200, APP, None, None))
    now = int(time.time())
    # A valid token whose payload is replaced: the original header and signature stay.
    head, payload_b64, signature = read.split(".")
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)))
    tampered = head + "." + lab.b64(json.dumps({**payload, "sub": "bob"}, separators=(",", ":")).encode()) \
        + "." + signature
    cases = [
        ("alg_none", lab.token(header={"alg": "none"}, signature=""), "alg_not_allowed"),
        ("alg_hs512", lab.token(header={"alg": "HS512"}, digest=hashlib.sha512), "alg_not_allowed"),
        ("alg_rs256_confusion", lab.token(header={"alg": "RS256"}), "alg_not_allowed"),
        ("tampered_subject", tampered, "bad_signature"),
        ("wrong_key", lab.token(key=b"k" * 32), "bad_signature"),
        ("unknown_kid", lab.token(header={"kid": "k0-000000000000"}), "unknown_kid"),
        ("crit_header", lab.token(header={"crit": ["exp"]}), "crit_unsupported"),
        ("expired", lab.token(exp=now - 10, iat=now - 400, nbf=now - 400), "expired"),
        ("not_yet_valid", lab.token(nbf=now + 120), "not_yet_valid"),
        ("wrong_audience", lab.token(aud="other-api"), "bad_audience"),
        ("wrong_issuer", lab.token(iss="someone-else"), "bad_issuer"),
        ("unknown_subject", lab.token(sub="mallory"), "unknown_subject"),
        ("missing_exp", lab.token(exp=None), "claim_missing_or_type"),
        ("string_exp", lab.token(exp=str(now + 300)), "claim_missing_or_type"),
        ("three_parts_garbage", "a.b.c", "malformed"),
    ]
    for name, token, reason in cases:
        s(client, name, "GET", "/api/v1/notes", bearer(token), expect=(401, REJ, "jwt", reason))
    s(client, "write_with_read_scope", "POST", "/api/v1/notes", bearer(read) + [JSON_CT],
      json.dumps({"title": "x"}).encode(), expect=(403, REJ, "jwt", "insufficient_scope"))
    _, _, body = s(client, "create_api", "POST", "/api/v1/notes", bearer(write) + [JSON_CT],
                   json.dumps({"title": "API note", "body": "from the API", "tag": "api"}).encode(),
                   expect=(201, APP, None, None))
    created = json.loads(body)["id"] if body.startswith(b"{") else None
    s(client, "create_api_blocked_by_double", "POST", "/api/v1/notes", bearer(write) + [JSON_CT],
      json.dumps({"title": "evil"}).encode(), expect=(403, FW, "v5", None), direct=(201, APP, None, None))
    s(client, "json_malformed", "POST", "/api/v1/notes", bearer(write) + [JSON_CT], b'{"title": ',
      expect=(400, REJ, "validation", "json_malformed"))
    s(client, "other_users_note_api", "GET", "/api/v1/notes/3", bearer(write),
      expect=(404, REJ, "authorization", "not_owner_or_missing"))
    if created is not None:
        s(client, "delete_api", "DELETE", f"/api/v1/notes/{created}", bearer(write), expect=(204, APP, None, None))
    s(client, "revoke", "POST", "/api/v1/token/revoke", bearer(write), expect=(200, APP, None, None))
    s(client, "after_revoke", "GET", "/api/v1/notes", bearer(write), expect=(401, REJ, "jwt", "revoked"))


def effect_smoke(rec, client, _lab=None):
    """Each effect oracle on a benign control and on its attack. The double forwards both: this is the
    oracle working, not a detection result."""
    s = rec.step
    s(client, "effect_sql_benign", "GET", "/share/search?tag=work", expect=(200, APP, None, None))
    s(client, "effect_sql_attack", "GET", "/share/search?tag=x%27%20OR%201%3D1--", expect=(200, APP, None, None))
    s(client, "effect_files_benign", "GET", "/files?name=handbook.txt", expect=(200, APP, None, None))
    s(client, "effect_files_attack", "GET", "/files?name=..%2Fprivate%2Fcanary.txt", expect=(200, APP, None, None))
    s(client, "effect_redirect_benign", "GET", "/continue?to=%2Fnotes", expect=(302, APP, None, None))
    s(client, "effect_redirect_attack", "GET", "/continue?to=https%3A%2F%2Fattacker.example%2F", expect=(302, APP, None, None))
    s(client, "effect_xss_benign", "GET", "/share/preview?title=Weekly", expect=(200, APP, None, None))
    s(client, "effect_xss_attack", "GET", "/share/preview?title=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
      expect=(200, APP, None, None))


EFFECT_EXPECT = {"effect_sql_benign": False, "effect_sql_attack": True, "effect_files_benign": False,
                 "effect_files_attack": True, "effect_redirect_benign": False, "effect_redirect_attack": True,
                 "effect_xss_benign": False, "effect_xss_attack": True}


def run_path(path, state, proxy, lab, effect, observe_only=False):
    rec = Recorder(state, proxy, path, observe_only)
    for scenario in (session_scenario, api_scenario) + ((effect_smoke,) if effect else ()):
        client = Client(path, state)
        try:
            scenario(rec, client, lab)
        finally:
            client.close()
    return rec.rows


def effect_rows(rows):
    """Each effect-smoke row must carry the application's oracle, and it must fire exactly on the attack."""
    for row in rows:
        if row["step"] in EFFECT_EXPECT:
            effect = row.get("effect")
            row["passed"] &= effect is not None and any(effect.values()) == EFFECT_EXPECT[row["step"]]


def summary(rows):
    table = {}
    for path in PATHS:
        mine = [r for r in rows if r["path"] == path]
        counts = Counter(r["observed"][1] for r in mine)
        controls = Counter(f"{r['observed'][2]}/{r['observed'][3]}" for r in mine if r["observed"][1] == REJ)
        table[path] = {"requests": len(mine), "passed": sum(r["passed"] for r in mine),
                       "by_layer": dict(counts), "application_rejections": dict(sorted(controls.items())),
                       "v5_calls": sum(r["v5_calls"] for r in mine)}
    return table


def cross_path(rows):
    """For every step the firewall forwards, the application's answer is the same with and without it."""
    problems = []
    by = {}
    for r in rows:
        by.setdefault(r["step"], {})[r["path"]] = r
    for step, paths in by.items():
        direct = paths.get("direct")
        for p in ("tls_h1", "tls_h2"):
            other = paths.get(p)
            if direct is None or other is None or other["observed"][1] == FW:
                continue
            if direct["observed"] != other["observed"]:
                problems.append(f"{step}: direct {direct['observed']} vs {p} {other['observed']}")
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--effect-smoke", action="store_true")
    args = parser.parse_args(argv)
    if os.path.exists(args.out) or os.path.exists(args.work):
        sys.exit("refusing to reuse --out or --work")
    os.makedirs(args.out)
    holder = {}
    extra = ("--effect-routes",) if args.effect_smoke else ()
    with H.doubled_stack(args.config, args.work, "app", extra, holder) as (state, proxy):
        state["ports_app"] = state["endpoints"]["app_direct"].rsplit(":", 1)[1]
        lab = Lab(state["seed"])
        rows = []
        for path in PATHS:
            rows.extend(run_path(path, state, proxy, lab, args.effect_smoke))
        if args.effect_smoke:
            effect_rows(rows)
        identity = state["identity"]
    problems = cross_path(rows)
    failed = [r for r in rows if not r["passed"]]
    passed = not failed and not problems and holder.get("clean", {}).get("clean", False)
    doc = {"schema": "firewall-local-stack-app-check/v1", "created_utc": time.time(),
           "kind": "MECHANISM_CHECK_WITH_V5_DOUBLE", "detection_quality": "NOT_MEASURED",
           "identity": identity, "passed": passed, "summary": summary(rows), "cross_path_problems": problems,
           "failed_steps": [{"path": r["path"], "step": r["step"], "expected": r["expected"],
                             "observed": r["observed"], "marker_consistent": r["marker_consistent"]} for r in failed],
           "rows": rows, "clean_after": holder.get("clean")}
    with open(os.path.join(args.out, "APP_CHECK.json"), "x", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(json.dumps({"passed": passed, "summary": doc["summary"], "failed": doc["failed_steps"][:20],
                      "cross_path_problems": problems[:20], "clean": (holder.get("clean") or {}).get("clean")},
                     indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
