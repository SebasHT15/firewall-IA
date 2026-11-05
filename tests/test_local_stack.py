"""
Unit tests of the local stack package (scripts/local_stack). CPU only: no Docker, no GPU, no model.

    .venv-dataplane/bin/python -B -m unittest discover -s tests -p 'test_local_stack.py'

The live checks (transport_check.py, app_check.py, failure_check.py) need Docker and are run separately.
"""
import base64
import hashlib
import hmac
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = os.path.join(REPO, "scripts", "local_stack")
sys.path.insert(0, PKG)

import stack as S             # noqa: E402
import wire_clients as WC     # noqa: E402

SEED = "11" * 32
_TMP = tempfile.mkdtemp(prefix="fwlab-notes-test-")
os.environ.update(FWLAB_SECRET_SEED=SEED, FWLAB_LOG=os.path.join(_TMP, "app.jsonl"),
                  FWLAB_ALLOWED_ORIGINS="https://notes.fwlab.test:8443", FWLAB_DATA_DIR=os.path.join(_TMP, "data"),
                  FWLAB_EFFECT_ROUTES="1")
_spec = importlib.util.spec_from_file_location("fwlab_notes_app_under_test", os.path.join(PKG, "notes_app", "app.py"))
APP = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(APP)

import app_check as A          # noqa: E402  (after the env: it imports nothing of the app)
import transport_check as TC   # noqa: E402

ORIGIN = {"Origin": "https://notes.fwlab.test:8443"}


def log_lines():
    with open(os.environ["FWLAB_LOG"], encoding="utf-8") as fh:
        return [json.loads(x) for x in fh if x.strip()]


class AppTestCase(unittest.TestCase):
    def setUp(self):
        self.client = APP.app.test_client()
        self.lab = A.Lab(SEED)

    def login(self):
        r = self.client.get("/login")
        csrf = A.csrf_from(r.data)
        r = self.client.post("/login", data={"username": "alice", "password": self.lab.password("alice"),
                                             "csrf_token": csrf}, headers=ORIGIN)
        self.assertEqual(r.status_code, 303)
        page = self.client.get("/notes")
        return A.csrf_from(page.data)


class SessionsAndCsrf(AppTestCase):
    def test_csrf_reasons(self):
        r = self.client.get("/login")
        csrf = A.csrf_from(r.data)
        pw = self.lab.password("alice")
        cases = [({"username": "alice", "password": pw}, ORIGIN, "csrf/token_missing"),
                 ({"username": "alice", "password": pw, "csrf_token": "x"}, ORIGIN, "csrf/token_invalid"),
                 ({"username": "alice", "password": pw, "csrf_token": csrf}, {"Origin": "https://evil.example"},
                  "csrf/origin_mismatch"),
                 ({"username": "alice", "password": pw, "csrf_token": csrf}, {"Referer": "https://evil.example/"},
                  "csrf/referer_mismatch")]
        for data, headers, marker in cases:
            r = self.client.post("/login", data=data, headers=headers)
            self.assertEqual(r.status_code, 403, marker)
            self.assertEqual(r.headers["X-Fwlab-Rejected"], marker)

    def test_csrf_without_session(self):
        fresh = APP.app.test_client()
        r = fresh.post("/login", data={"username": "alice", "password": "x", "csrf_token": "y"}, headers=ORIGIN)
        self.assertEqual(r.headers["X-Fwlab-Rejected"], "csrf/no_session")

    def test_login_rotates_session_and_token(self):
        self.client.get("/login")
        before = self.client.get_cookie("fwlab_sid").value
        pre_csrf = A.csrf_from(self.client.get("/login").data)
        new_csrf = self.login()
        after = self.client.get_cookie("fwlab_sid").value
        self.assertNotEqual(before, after)
        self.assertNotEqual(pre_csrf, new_csrf)
        r = self.client.post("/notes", data={"title": "t", "csrf_token": pre_csrf}, headers=ORIGIN)
        self.assertEqual(r.headers["X-Fwlab-Rejected"], "csrf/token_invalid")

    def test_cookie_flags(self):
        r = self.client.get("/login")
        cookie = r.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)

    def test_logout_destroys_session(self):
        csrf = self.login()
        self.assertEqual(self.client.post("/logout", data={"csrf_token": csrf}, headers=ORIGIN).status_code, 303)
        r = self.client.get("/notes")
        self.assertEqual(r.headers["X-Fwlab-Rejected"], "session/session_required")

    def test_wrong_password_and_object_authorization(self):
        r = self.client.get("/login")
        csrf = A.csrf_from(r.data)
        r = self.client.post("/login", data={"username": "alice", "password": "no", "csrf_token": csrf},
                             headers=ORIGIN)
        self.assertEqual(r.headers["X-Fwlab-Rejected"], "login/bad_credentials")
        self.login()
        bobs = next(n for n in APP.Store.notes.values() if n["owner"] == "bob")["id"]
        r = self.client.get(f"/notes/{bobs}")
        self.assertEqual((r.status_code, r.headers["X-Fwlab-Rejected"]), (404, "authorization/not_owner_or_missing"))


class Jwt(AppTestCase):
    def call(self, token):
        return self.client.get("/api/v1/notes", headers={"Authorization": "Bearer " + token})

    def test_valid_token_and_scope(self):
        r = self.client.post("/api/v1/token", json={"username": "alice", "password": self.lab.password("alice")})
        token = r.get_json()["access_token"]
        self.assertEqual(self.call(token).status_code, 200)
        r = self.client.post("/api/v1/notes", json={"title": "x"}, headers={"Authorization": "Bearer " + token})
        self.assertEqual((r.status_code, r.get_json()["error"]), (403, "insufficient_scope"))

    def test_rejections(self):
        lab, now = self.lab, int(time.time())
        cases = {
            "alg_not_allowed": [lab.token(header={"alg": "none"}, signature=""),
                                lab.token(header={"alg": "HS512"}, digest=hashlib.sha512),
                                lab.token(header={"alg": "RS256"})],
            "bad_signature": [lab.token(key=b"k" * 32)],
            "unknown_kid": [lab.token(header={"kid": "nope"})],
            "crit_unsupported": [lab.token(header={"crit": ["exp"]})],
            "expired": [lab.token(exp=now - 1)],
            "not_yet_valid": [lab.token(nbf=now + 60)],
            "bad_audience": [lab.token(aud="x"), lab.token(aud=["x", "y"])],
            "bad_issuer": [lab.token(iss="x")],
            "unknown_subject": [lab.token(sub="mallory")],
            "claim_missing_or_type": [lab.token(exp=None), lab.token(exp=True), lab.token(jti=None)],
            "malformed": ["a.b", "a.b.c", "!!.!!.!!"],
        }
        for reason, tokens in cases.items():
            for token in tokens:
                r = self.call(token)
                self.assertEqual((r.status_code, r.get_json()["error"]), (401, reason), token[:40])
                self.assertIn("Bearer", r.headers["WWW-Authenticate"])

    def test_audience_list_accepted_and_revocation(self):
        token = self.lab.token(aud=["other", "fwlab-notes-api"])
        self.assertEqual(self.call(token).status_code, 200)
        self.assertEqual(self.client.post("/api/v1/token/revoke",
                                          headers={"Authorization": "Bearer " + token}).status_code, 200)
        self.assertEqual(self.call(token).get_json()["error"], "revoked")

    def test_signature_is_hs256_of_the_derived_key(self):
        key = hmac.new(bytes.fromhex(SEED), b"jwt-hs256", hashlib.sha256).digest()
        self.assertEqual(APP.JWT_KEY, key)
        token = APP.issue_token("alice", "notes:read")
        head, payload, sig = token.split(".")
        expected = hmac.new(key, f"{head}.{payload}".encode(), hashlib.sha256).digest()
        self.assertEqual(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)), expected)


class LogAndEffects(AppTestCase):
    def test_one_line_per_request_with_outcome(self):
        before = len(log_lines())
        self.client.get("/")
        self.client.get("/does-not-exist")
        rows = log_lines()[before:]
        self.assertEqual([(r["outcome"], r["control"], r["reason"]) for r in rows],
                         [("served", None, None), ("app_rejected", "routing", "not_found")])
        self.assertNotIn("raw_target", rows[0])      # targets are hashed unless FWLAB_LOG_TARGETS=1

    def test_effect_oracles(self):
        probes = [("/share/search?tag=work", "canary_in_response", False),
                  ("/share/search?tag=x' OR 1=1--", "canary_in_response", True),
                  ("/files?name=handbook.txt", "canary_in_response", False),
                  ("/files?name=../private/canary.txt", "canary_in_response", True),
                  ("/continue?to=/notes", "external_location", False),
                  ("/continue?to=https://attacker.example/", "external_location", True),
                  ("/continue?to=//attacker.example/", "external_location", True),
                  ("/share/preview?title=Weekly", "unescaped_reflection", False),
                  ("/share/preview?title=<script>1</script>", "unescaped_reflection", True)]
        for target, key, fired in probes:
            self.client.get(target)
            self.assertEqual(log_lines()[-1]["effect"][key], fired, target)


class StackConfig(unittest.TestCase):
    def base(self):
        with open(os.path.join(PKG, "stack.example.json"), encoding="utf-8") as fh:
            return json.load(fh)

    def write(self, doc):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as fh:
            json.dump(doc, fh)
        return path

    def test_example_loads_and_defaults_to_v5_only(self):
        cfg = S.load_config(os.path.join(PKG, "stack.example.json"))
        self.assertEqual(cfg["mode"], "V5_ONLY")
        self.assertIsNone(cfg["fast_path"])

    def test_refusals(self):
        for change in ({"mode": "V4_ONLY"}, {"mode": "CASCADE_OBSERVE"}, {"fast_path": {"policy": "x"}},
                       {"extra": 1}):
            doc = {**self.base(), **change}
            with self.assertRaises(S.StackError, msg=str(change)):
                S.load_config(self.write(doc))
        doc = self.base()
        doc["ports"]["guard"] = doc["ports"]["gateway"]
        with self.assertRaises(S.StackError):
            S.load_config(self.write(doc))

    def test_crs_section(self):
        cfg = S.load_config(os.path.join(PKG, "stack.example.json"))
        self.assertEqual((cfg["crs"]["blocking_paranoia"], cfg["crs"]["anomaly_inbound"],
                          cfg["crs"]["anomaly_outbound"]), (1, 5, 4))
        doc = self.base()
        doc["crs"]["port"] = doc["ports"]["front_tls"]
        with self.assertRaises(S.StackError):
            S.load_config(self.write(doc))
        doc = self.base()
        doc["crs"]["rule_exclusions"] = []
        with self.assertRaises(S.StackError):
            S.load_config(self.write(doc))

    def test_crs_templates_listen_on_loopback_without_own_healthz(self):
        with open(os.path.join(PKG, "crs", "default.conf.template"), encoding="utf-8") as fh:
            listens = [l.strip() for l in fh if l.strip().startswith("listen")]
        self.assertEqual(listens, ["listen 127.0.0.1:${PORT} default_server;"])
        with open(os.path.join(PKG, "crs", "location_common.conf.template"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertNotIn("location /healthz", text)
        self.assertNotIn("stub_status", text)

    def test_front_upstream_can_be_the_comparator(self):
        cfg = self.base()
        self.assertIn("server 127.0.0.1:8460 ", S.render_nginx(cfg, cfg["ports"], upstream_port=8460))

    def test_manifest_pin_is_checked(self):
        doc = self.base()
        doc["manifest"]["sha256"] = "0" * 64
        with self.assertRaises(S.StackError):
            S.check_manifest(S.load_config(self.write(doc)))

    def test_nginx_render_fills_every_variable(self):
        cfg = self.base()
        text = S.render_nginx(cfg, cfg["ports"])
        self.assertNotIn("${", text)
        self.assertIn("proxy_next_upstream off;", text)
        self.assertIn(f"server 127.0.0.1:{cfg['ports']['gateway']} ", text)
        directives = [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]
        set_headers = sorted(line.split()[1] for line in directives if line.startswith("proxy_set_header"))
        self.assertEqual(set_headers, ["Connection", "Host"])      # nothing added to the client's headers


class ProcessSafety(unittest.TestCase):
    def test_reused_pid_is_never_signalled(self):
        me = os.getpid()
        component = {"name": "x", "kind": "process", "pid": me, "pgid": os.getpgid(me),
                     "start_ticks": S.proc_start_ticks(me) + 1, "argv": []}
        self.assertEqual(S.stop_process(component), "gone")      # and this test is still running

    def test_zombie_is_not_alive(self):
        child = subprocess.Popen([sys.executable, "-c", "pass"])
        deadline = time.monotonic() + 5
        while S.proc_start_ticks(child.pid) is not None and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertIsNone(S.proc_start_ticks(child.pid))
        child.wait()

    def test_stop_own_group(self):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
        component = {"name": "sleeper", "kind": "process", "pid": child.pid, "pgid": child.pid,
                     "start_ticks": S.proc_start_ticks(child.pid), "argv": []}
        self.assertEqual(S.stop_process(component), "terminated")
        self.assertIsNotNone(child.poll())


class WireAndAttribution(unittest.TestCase):
    def test_parse_chunked_and_length(self):
        raw = WC.build_h1("POST", "/x?a=1", "h", [("Content-Type", "text/plain")], b"hello world", chunked=True)
        parsed = WC.parse_request(raw)
        self.assertEqual((parsed["method"], parsed["target"], parsed["body"], parsed["framing"]),
                         ("POST", "/x?a=1", b"hello world", "chunked"))
        raw = WC.build_h1("PUT", "/y", "h", (), b"abc")
        self.assertEqual(WC.parse_request(raw)["framing"], "content-length")

    def test_front_attribution_uses_connect_time(self):
        row = {"front": {"reached_gateway": False}, "received_count": 0, "client_status": 502}
        self.assertEqual(TC.attribute(row), "front")
        row = {"front": {"reached_gateway": True}, "received_count": 0, "client_status": 403,
               "gateway": {"applied": "DENY"}}
        self.assertEqual(TC.attribute(row), "firewall")
        nginx_502 = [{"upstream_connect_time": "-", "upstream_status": "502"}]
        self.assertEqual(A.measure("tls_h1", [], [], nginx_502)[0], "front")
        app_line = [{"outcome": "app_rejected", "control": "jwt", "reason": "expired"}]
        reached = [{"upstream_connect_time": "0.000", "upstream_status": "401"}]
        self.assertEqual(A.measure("tls_h1", app_line, [{"applied": "FORWARD"}], reached),
                         ("app_rejected", "jwt", "expired"))


if __name__ == "__main__":
    unittest.main()
