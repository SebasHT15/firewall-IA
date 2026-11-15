"""
fwlab-notes — an INDEPENDENT laboratory application for the local Firewall-IA stack.

It imports nothing from this repository: Flask and the standard library only, so the application and
its controls do not depend on the firewall under test. It is a small team-notes service with:

    sessions   server-side store, opaque random id in an HttpOnly SameSite=Lax cookie, new id at login
               (no session fixation), idle and absolute expiry, logout destroys the session
    CSRF       synchronizer token bound to the session, sent as form field `csrf_token` or header
               `X-CSRF-Token`, compared in constant time; Origin/Referer checked when present
               (OWASP CSRF Prevention Cheat Sheet). Rotated at login
    JWT        HS256 only, fixed `kid`, exact `iss`/`aud`, `exp`/`nbf`/`iat`, existing `sub`, `jti` with
               revocation, `scope` per operation. Every rejection has a closed reason code

Every control is a deterministic rule: the same request in the same state gets the same answer. No model
takes part, and no credential ever reaches a model. Every request leaves exactly one line in
`FWLAB_LOG` (JSONL, append only), written after the answer, which says whether THE APPLICATION served
or rejected it and why. Requests the firewall stops never arrive here, so a rejection of the backend
and a rejection of the firewall are recorded by different processes.

Optional EFFECT routes (`FWLAB_EFFECT_ROUTES=1`) are DELIBERATELY VULNERABLE, synthetic and disposable:
SQL injection, path traversal, open redirect, reflected XSS, each with an effect oracle in the log.
They exist only to observe whether a delivered attack had an effect, and must only run inside the
isolated Docker network of `scripts/local_stack/stack.py`.

Environment:
    FWLAB_SECRET_SEED      required, hex. Derives the JWT key and the lab passwords
    FWLAB_LOG              JSONL path (default /evidence/notes-app.jsonl)
    FWLAB_BIND, FWLAB_PORT default 0.0.0.0, 9300
    FWLAB_ALLOWED_ORIGINS  comma-separated origins accepted by the CSRF origin check
    FWLAB_COOKIE_SECURE    1: Secure flag on the session cookie (behind the TLS front)
    FWLAB_EFFECT_ROUTES    1: mount the vulnerable effect routes
    FWLAB_DATA_DIR         writable directory for the effect fixtures (default /tmp/fwlab-notes)
    FWLAB_LOG_TARGETS      1: also log the raw target (lab evidence; synthetic traffic only)
"""
import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
import urllib.parse
from pathlib import Path

from flask import Flask, g, make_response, redirect, request
from markupsafe import escape

APP_ID = "fwlab-notes/v1"
LOG_SCHEMA = "fwlab-notes-log/v1"
SEED = bytes.fromhex(os.environ["FWLAB_SECRET_SEED"])
LOG_PATH = Path(os.environ.get("FWLAB_LOG", "/evidence/notes-app.jsonl"))
ALLOWED_ORIGINS = frozenset(o.strip() for o in os.environ.get("FWLAB_ALLOWED_ORIGINS", "").split(",")
                            if o.strip())
COOKIE_SECURE = os.environ.get("FWLAB_COOKIE_SECURE") == "1"
EFFECT_ROUTES = os.environ.get("FWLAB_EFFECT_ROUTES") == "1"
LOG_TARGETS = os.environ.get("FWLAB_LOG_TARGETS") == "1"
DATA_DIR = Path(os.environ.get("FWLAB_DATA_DIR", "/tmp/fwlab-notes"))

SESSION_COOKIE = "fwlab_sid"
SESSION_IDLE_SECONDS = 900
SESSION_ABSOLUTE_SECONDS = 3600
MAX_SESSIONS = 20000
JWT_ISSUER = "fwlab-notes"
JWT_AUDIENCE = "fwlab-notes-api"
JWT_TTL_SECONDS = 300
JWT_SCOPES = frozenset({"notes:read", "notes:write"})
MAX_TITLE = 120
MAX_BODY = 4000
CANARY = "FWLAB_NOTES_CANARY_" + hashlib.sha256(SEED + b"canary").hexdigest()[:16]


def derive(label: str) -> bytes:
    return hmac.new(SEED, label.encode("ascii"), hashlib.sha256).digest()


def lab_password(user: str) -> str:
    """Synthetic credential of a lab user, derived from the run seed. The check scripts derive it the
    same way; it is never written to a file of the repository."""
    return base64.urlsafe_b64encode(derive("password:" + user)).decode("ascii")[:20]


JWT_KEY = derive("jwt-hs256")
JWT_KID = "k1-" + hashlib.sha256(JWT_KEY).hexdigest()[:12]
USERS = ("alice", "bob")
_PBKDF2_ITER = 50000
_SALTS = {u: derive("salt:" + u)[:16] for u in USERS}
_PASSWORD_HASHES = {u: hashlib.pbkdf2_hmac("sha256", lab_password(u).encode(), _SALTS[u], _PBKDF2_ITER)
                    for u in USERS}

app = Flask(__name__)
app.config.update(MAX_CONTENT_LENGTH=64 * 1024)
logging.getLogger("werkzeug").setLevel(logging.WARNING)


# ─────────────────────────────── state ───────────────────────────────
class Store:
    lock = threading.Lock()
    sessions = {}          # sid -> {"user", "csrf", "created", "seen"}
    revoked_jti = set()
    notes = {}             # id -> {"id", "owner", "title", "body", "tag"}
    next_note = 1
    seq = 0


def _seed_notes():
    for owner, title, body, tag in (("alice", "Welcome", "First note of alice.", "intro"),
                                    ("alice", "Groceries", "Milk, bread, coffee.", "home"),
                                    ("bob", "Standup", "Discuss the release plan.", "work")):
        _add_note(owner, title, body, tag)


def _add_note(owner, title, body, tag):
    with Store.lock:
        nid = Store.next_note
        Store.next_note += 1
        Store.notes[nid] = {"id": nid, "owner": owner, "title": title, "body": body, "tag": tag}
    return nid


_seed_notes()


# ─────────────────────────────── rejection bookkeeping ───────────────────────────────
class Rejection(Exception):
    """Raised by a control. The answer and the log line carry the same closed code."""

    def __init__(self, status: int, control: str, reason: str, headers=None, location=None):
        super().__init__(reason)
        self.status, self.control, self.reason = status, control, reason
        self.headers = headers or {}
        self.location = location


def json_response(status, payload, headers=None):
    resp = make_response(json.dumps(payload, sort_keys=True), status)
    resp.headers["Content-Type"] = "application/json"
    for k, v in (headers or {}).items():
        resp.headers[k] = v
    return resp


@app.errorhandler(Rejection)
def _rejected(exc: Rejection):
    g.rejection = (exc.control, exc.reason)
    if exc.location:
        resp = redirect(exc.location, code=303)
    elif request.path.startswith("/api/"):
        resp = json_response(exc.status, {"error": exc.reason, "control": exc.control,
                                          "rejected_by": "application"}, exc.headers)
    else:
        resp = make_response(f"<!doctype html><title>Rejected</title><p>Rejected by fwlab-notes: "
                             f"{exc.control}/{exc.reason}</p>", exc.status)
        resp.headers["Content-Type"] = "text/html; charset=utf-8"
    resp.headers["X-Fwlab-Rejected"] = f"{exc.control}/{exc.reason}"
    return resp


@app.errorhandler(404)
def _not_found(_exc):
    return _rejected(Rejection(404, "routing", "not_found"))


@app.errorhandler(405)
def _not_allowed(_exc):
    return _rejected(Rejection(405, "routing", "method_not_allowed"))


@app.errorhandler(413)
def _too_large(_exc):
    return _rejected(Rejection(413, "validation", "body_too_large"))


@app.before_request
def _receive():
    g.received = time.time()
    g.rejection = None
    g.effect = None
    # Read before any form parsing consumes the stream.
    g.body = request.get_data(cache=True)


@app.after_request
def _log(response):
    raw_target = request.environ.get("RAW_URI") or request.full_path
    relevant = {}
    for name in ("host", "content-type", "content-length", "cookie", "authorization", "x-csrf-token",
                 "origin", "referer"):
        value = request.headers.get(name)
        if value is not None:
            relevant[name] = hashlib.sha256(value.encode("latin-1", "replace")).hexdigest()
    with Store.lock:
        Store.seq += 1
        seq = Store.seq
    control, reason = g.get("rejection") or (None, None)
    row = {"schema": LOG_SCHEMA, "app": APP_ID, "seq": seq, "received_utc": g.get("received"),
           "finished_utc": time.time(), "method": request.method,
           "endpoint": request.endpoint, "rule": request.url_rule.rule if request.url_rule else None,
           "raw_target_sha256": hashlib.sha256(raw_target.encode("latin-1", "replace")).hexdigest(),
           "body_sha256": hashlib.sha256(g.get("body", b"")).hexdigest(),
           "body_bytes": len(g.get("body", b"")),
           "header_names": [k.lower() for k in request.headers.keys()],
           "relevant_header_sha256": relevant, "status": response.status_code,
           "outcome": "app_rejected" if control else "served", "control": control, "reason": reason,
           "effect": g.get("effect")}
    if LOG_TARGETS:
        row["raw_target"] = raw_target
    line = json.dumps(row, sort_keys=True) + "\n"
    with Store.lock, LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(line)
    return response


# ─────────────────────────────── sessions and CSRF ───────────────────────────────
def _new_session(user=None):
    now = time.time()
    sid = secrets.token_urlsafe(32)
    with Store.lock:
        if len(Store.sessions) >= MAX_SESSIONS:
            oldest = min(Store.sessions, key=lambda s: Store.sessions[s]["seen"])
            del Store.sessions[oldest]
        Store.sessions[sid] = {"user": user, "csrf": secrets.token_urlsafe(32), "created": now,
                               "seen": now}
    return sid


def _current_session():
    """(sid, session) for a live session, or (None, None)."""
    sid = request.cookies.get(SESSION_COOKIE)
    if not sid:
        return None, None
    now = time.time()
    with Store.lock:
        session = Store.sessions.get(sid)
        if session is None:
            return None, None
        if now - session["seen"] > SESSION_IDLE_SECONDS or now - session["created"] > SESSION_ABSOLUTE_SECONDS:
            del Store.sessions[sid]
            return None, None
        session["seen"] = now
    return sid, session


def _set_session_cookie(resp, sid):
    resp.set_cookie(SESSION_COOKIE, sid, httponly=True, samesite="Lax", secure=COOKIE_SECURE, path="/")


def require_user():
    sid, session = _current_session()
    if session is None or not session["user"]:
        raise Rejection(303, "session", "session_required", location="/login")
    return sid, session


def _origin_of(url: str):
    parts = urllib.parse.urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}"


def check_csrf(session):
    """Synchronizer token plus the standard-header origin check. Raises Rejection."""
    origin = request.headers.get("Origin")
    referer = request.headers.get("Referer")
    if origin is not None:
        if origin not in ALLOWED_ORIGINS:
            raise Rejection(403, "csrf", "origin_mismatch")
    elif referer is not None:
        if _origin_of(referer) not in ALLOWED_ORIGINS:
            raise Rejection(403, "csrf", "referer_mismatch")
    if session is None:
        raise Rejection(403, "csrf", "no_session")
    sent = request.headers.get("X-CSRF-Token")
    if sent is None and request.mimetype in ("application/x-www-form-urlencoded", "multipart/form-data"):
        sent = request.form.get("csrf_token")
    if not sent:
        raise Rejection(403, "csrf", "token_missing")
    if not hmac.compare_digest(sent.encode("utf-8", "replace"), session["csrf"].encode("ascii")):
        raise Rejection(403, "csrf", "token_invalid")


def page(title, body, status=200):
    resp = make_response(f"<!doctype html><html><head><meta charset=utf-8><title>{escape(title)}</title>"
                         f"<link rel=stylesheet href=/static/app.css></head><body>{body}</body></html>",
                         status)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    resp.headers["Cache-Control"] = "no-store"
    return resp


def form_fields(session):
    return f'<input type=hidden name=csrf_token value="{escape(session["csrf"])}">'


# ─────────────────────────────── HTML routes ───────────────────────────────
@app.get("/")
def home():
    return page("fwlab notes", "<h1>fwlab notes</h1><p>Team notes.</p><a href=/login>Sign in</a>")


@app.get("/healthz")
def healthz():
    return json_response(200, {"status": "ok", "app": APP_ID})


@app.get("/static/app.css")
def css():
    resp = make_response("body{font-family:sans-serif;max-width:40em;margin:2em auto}\n")
    resp.headers["Content-Type"] = "text/css"
    return resp


@app.get("/static/app.js")
def js():
    resp = make_response("document.documentElement.dataset.ready='1';\n")
    resp.headers["Content-Type"] = "application/javascript"
    return resp


@app.get("/login")
def login_form():
    sid, session = _current_session()
    if session is None:
        sid = _new_session()
        session = Store.sessions[sid]
    resp = page("Sign in", "<form method=post action=/login>" + form_fields(session) +
                "<input name=username><input name=password type=password><button>Sign in</button></form>")
    _set_session_cookie(resp, sid)
    return resp


@app.post("/login")
def login():
    sid, session = _current_session()
    check_csrf(session)
    user = request.form.get("username", "")
    password = request.form.get("password", "")
    if not _password_ok(user, password):
        raise Rejection(401, "login", "bad_credentials")
    with Store.lock:
        Store.sessions.pop(sid, None)          # the pre-login id and token die here
    new_sid = _new_session(user)
    resp = redirect("/notes", code=303)
    _set_session_cookie(resp, new_sid)
    return resp


def _password_ok(user, password):
    if user not in _PASSWORD_HASHES:
        hashlib.pbkdf2_hmac("sha256", password.encode(), b"0" * 16, _PBKDF2_ITER)   # same work
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8", "replace"), _SALTS[user], _PBKDF2_ITER)
    return hmac.compare_digest(digest, _PASSWORD_HASHES[user])


@app.post("/logout")
def logout():
    sid, session = require_user()
    check_csrf(session)
    with Store.lock:
        Store.sessions.pop(sid, None)
    resp = redirect("/", code=303)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


def _notes_of(user):
    with Store.lock:
        return [dict(n) for n in Store.notes.values() if n["owner"] == user]


@app.get("/notes")
def notes_page():
    _sid, session = require_user()
    tag = request.args.get("tag")
    items = [n for n in _notes_of(session["user"]) if tag is None or n["tag"] == tag]
    rows = "".join(f"<li><a href=/notes/{n['id']}>{escape(n['title'])}</a> [{escape(n['tag'])}]</li>"
                   for n in items)
    return page("Notes", f"<h1>Notes of {escape(session['user'])}</h1><ul>{rows}</ul>"
                "<form method=post action=/notes>" + form_fields(session) +
                "<input name=title><textarea name=body></textarea><input name=tag><button>Add</button>"
                "</form>")


@app.get("/notes/<int:nid>")
def note_page(nid):
    _sid, session = require_user()
    note = _owned_note(nid, session["user"])
    return page(note["title"], f"<h1>{escape(note['title'])}</h1><p>{escape(note['body'])}</p>")


def _owned_note(nid, user):
    with Store.lock:
        note = Store.notes.get(nid)
        note = dict(note) if note else None
    if note is None or note["owner"] != user:
        # Not distinguishable from a missing note: no object enumeration across users.
        raise Rejection(404, "authorization", "not_owner_or_missing")
    return note


def _validated_note(fields):
    title, body, tag = (fields.get("title"), fields.get("body", ""), fields.get("tag", ""))
    if not isinstance(title, str) or not title.strip():
        raise Rejection(400, "validation", "title_required")
    if not isinstance(body, str) or not isinstance(tag, str):
        raise Rejection(400, "validation", "field_type")
    if len(title) > MAX_TITLE or len(body) > MAX_BODY or len(tag) > 32:
        raise Rejection(400, "validation", "field_too_long")
    return title, body, tag


@app.post("/notes")
def create_note():
    _sid, session = require_user()
    check_csrf(session)
    title, body, tag = _validated_note(request.form)
    nid = _add_note(session["user"], title, body, tag)
    return redirect(f"/notes/{nid}", code=303)


@app.post("/notes/<int:nid>/delete")
def delete_note(nid):
    _sid, session = require_user()
    check_csrf(session)
    _owned_note(nid, session["user"])
    with Store.lock:
        Store.notes.pop(nid, None)
    return redirect("/notes", code=303)


@app.get("/search")
def search():
    _sid, session = require_user()
    q = request.args.get("q", "")
    hits = [n for n in _notes_of(session["user"]) if q.lower() in (n["title"] + n["body"]).lower()]
    return page("Search", f"<p>Results for {escape(q)}: {len(hits)}</p>")


@app.get("/account")
def account():
    _sid, session = require_user()
    return page("Account", f"<p>{escape(session['user'])}</p><form method=post action=/account/email>"
                + form_fields(session) + "<input name=email><button>Save</button></form>")


@app.post("/account/email")
def account_email():
    _sid, session = require_user()
    check_csrf(session)
    email = request.form.get("email", "")
    if "@" not in email or len(email) > 254:
        raise Rejection(400, "validation", "email_invalid")
    return redirect("/account", code=303)


# ─────────────────────────────── JWT ───────────────────────────────
def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    if not text or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                       for c in text):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def jwt_sign(header: dict, claims: dict, key: bytes = None) -> str:
    signing = (b64u_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode()) + "." +
               b64u_encode(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode()))
    sig = hmac.new(key or JWT_KEY, signing.encode("ascii"), hashlib.sha256).digest()
    return signing + "." + b64u_encode(sig)


def issue_token(user, scope, now=None):
    now = int(now if now is not None else time.time())
    claims = {"iss": JWT_ISSUER, "aud": JWT_AUDIENCE, "sub": user, "iat": now, "nbf": now,
              "exp": now + JWT_TTL_SECONDS, "jti": secrets.token_urlsafe(16), "scope": scope}
    return jwt_sign({"alg": "HS256", "typ": "JWT", "kid": JWT_KID}, claims)


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def verify_token(token: str, now=None):
    """Claims of a valid token, or raises Rejection(401, "jwt", <reason>)."""
    def bad(reason):
        return Rejection(401, "jwt", reason,
                         headers={"WWW-Authenticate": f'Bearer error="invalid_token", '
                                                      f'error_description="{reason}"'})
    now = time.time() if now is None else now
    parts = token.split(".")
    if len(parts) != 3:
        raise bad("malformed")
    try:
        header = json.loads(b64u_decode(parts[0]))
        signature = b64u_decode(parts[2]) if parts[2] else b""
    except (ValueError, binascii.Error, UnicodeDecodeError):
        raise bad("malformed")
    if not isinstance(header, dict):
        raise bad("malformed")
    if header.get("alg") != "HS256":           # covers "none", RS256/ES256 confusion, HS384/HS512
        raise bad("alg_not_allowed")
    if "crit" in header:
        raise bad("crit_unsupported")
    if header.get("kid") != JWT_KID:
        raise bad("unknown_kid")
    expected = hmac.new(JWT_KEY, (parts[0] + "." + parts[1]).encode("ascii"), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, signature):
        raise bad("bad_signature")
    try:
        claims = json.loads(b64u_decode(parts[1]))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        raise bad("malformed")
    if not isinstance(claims, dict):
        raise bad("malformed")
    if claims.get("iss") != JWT_ISSUER:
        raise bad("bad_issuer")
    aud = claims.get("aud")
    if not (aud == JWT_AUDIENCE or (isinstance(aud, list) and JWT_AUDIENCE in aud)):
        raise bad("bad_audience")
    for name in ("exp", "iat"):
        if not _is_int(claims.get(name)):
            raise bad("claim_missing_or_type")
    if "nbf" in claims and not _is_int(claims["nbf"]):
        raise bad("claim_missing_or_type")
    if now >= claims["exp"]:
        raise bad("expired")
    if now < claims.get("nbf", claims["iat"]):
        raise bad("not_yet_valid")
    if claims.get("sub") not in USERS:
        raise bad("unknown_subject")
    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti:
        raise bad("claim_missing_or_type")
    with Store.lock:
        if jti in Store.revoked_jti:
            raise bad("revoked")
    scope = claims.get("scope")
    if not isinstance(scope, str):
        raise bad("claim_missing_or_type")
    return claims


def bearer_claims(needed_scope):
    value = request.headers.get("Authorization")
    if value is None:
        raise Rejection(401, "jwt", "token_missing", headers={"WWW-Authenticate": "Bearer"})
    kind, _, token = value.partition(" ")
    if kind.lower() != "bearer" or not token or " " in token:
        raise Rejection(401, "jwt", "malformed", headers={"WWW-Authenticate": 'Bearer error="invalid_request"'})
    claims = verify_token(token)
    if needed_scope not in claims["scope"].split():
        raise Rejection(403, "jwt", "insufficient_scope",
                        headers={"WWW-Authenticate": f'Bearer error="insufficient_scope", scope="{needed_scope}"'})
    return claims


def json_body():
    if request.mimetype != "application/json":
        raise Rejection(415, "validation", "json_required")
    try:
        doc = json.loads(g.body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise Rejection(400, "validation", "json_malformed")
    if not isinstance(doc, dict):
        raise Rejection(400, "validation", "json_object_required")
    return doc


@app.post("/api/v1/token")
def api_token():
    doc = json_body()
    user, password = doc.get("username"), doc.get("password")
    scope = doc.get("scope", "notes:read")
    if not isinstance(user, str) or not isinstance(password, str) or not _password_ok(user, password):
        raise Rejection(401, "login", "bad_credentials")
    if not isinstance(scope, str) or not set(scope.split()) <= JWT_SCOPES or not scope.split():
        raise Rejection(400, "validation", "bad_scope")
    return json_response(200, {"access_token": issue_token(user, " ".join(sorted(set(scope.split())))),
                               "token_type": "Bearer", "expires_in": JWT_TTL_SECONDS})


@app.post("/api/v1/token/revoke")
def api_revoke():
    claims = bearer_claims("notes:read")
    with Store.lock:
        Store.revoked_jti.add(claims["jti"])
    return json_response(200, {"revoked": True})


@app.get("/api/v1/notes")
def api_notes():
    claims = bearer_claims("notes:read")
    return json_response(200, {"notes": [{k: n[k] for k in ("id", "title", "tag")}
                                         for n in _notes_of(claims["sub"])]})


@app.get("/api/v1/notes/<int:nid>")
def api_note(nid):
    claims = bearer_claims("notes:read")
    return json_response(200, _owned_note(nid, claims["sub"]))


@app.post("/api/v1/notes")
def api_create():
    claims = bearer_claims("notes:write")
    title, body, tag = _validated_note(json_body())
    return json_response(201, {"id": _add_note(claims["sub"], title, body, tag)})


@app.delete("/api/v1/notes/<int:nid>")
def api_delete(nid):
    claims = bearer_claims("notes:write")
    _owned_note(nid, claims["sub"])
    with Store.lock:
        Store.notes.pop(nid, None)
    return make_response("", 204)


# ─────────────────────────────── EFFECT routes (opt-in, vulnerable) ───────────────────────────────
def _effect_fixture():
    public = DATA_DIR / "public"
    private = DATA_DIR / "private"
    public.mkdir(parents=True, exist_ok=True)
    private.mkdir(parents=True, exist_ok=True)
    (public / "handbook.txt").write_text("Team handbook, public.\n")
    (public / "changelog.txt").write_text("v1: first release.\n")
    (private / "canary.txt").write_text(CANARY + "\n")


def _observe(body: bytes, *, location=None, reflected=None):
    effect = {"canary_in_response": CANARY.encode() in body}
    if location is not None:
        parts = urllib.parse.urlsplit(location)
        effect["external_location"] = bool(parts.netloc) or location.startswith("//")
    if reflected is not None:
        effect["unescaped_reflection"] = ("<" in reflected or ">" in reflected or '"' in reflected) \
            and reflected.encode("utf-8", "replace") in body
    g.effect = effect


if EFFECT_ROUTES:
    _effect_fixture()

    @app.get("/share/search")
    def effect_sql():
        conn = sqlite3.connect(":memory:")
        try:
            conn.execute("CREATE TABLE shared(tag TEXT, title TEXT, public INTEGER)")
            conn.executemany("INSERT INTO shared VALUES(?,?,?)", [("intro", "Welcome", 1),
                                                                   ("work", "Release plan", 1),
                                                                   ("secret", CANARY, 0)])
            query = "SELECT title FROM shared WHERE tag='" + request.args.get("tag", "intro") + "' AND public=1"
            resp = json_response(200, {"titles": [r[0] for r in conn.execute(query)]})
        except sqlite3.Error:
            resp = json_response(400, {"error": "invalid query"})
        finally:
            conn.close()
        _observe(resp.get_data())
        return resp

    @app.get("/files")
    def effect_files():
        target = (DATA_DIR / "public" / request.args.get("name", "handbook.txt")).resolve()
        if not target.is_relative_to(DATA_DIR.resolve()) or not target.is_file():
            resp = make_response("not found", 404)
        else:
            resp = make_response(target.read_bytes())
            resp.headers["Content-Type"] = "text/plain"
        _observe(resp.get_data())
        return resp

    @app.get("/continue")
    def effect_redirect():
        to = request.args.get("to", "/notes")
        resp = redirect(to, code=302)
        _observe(resp.get_data(), location=resp.headers.get("Location", ""))
        return resp

    @app.get("/share/preview")
    def effect_xss():
        title = request.args.get("title", "Untitled")
        resp = make_response("<!doctype html><html><body><h1>" + title + "</h1></body></html>")
        resp.headers["Content-Type"] = "text/html; charset=utf-8"
        _observe(resp.get_data(), reflected=title)
        return resp


if __name__ == "__main__":
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    app.run(host=os.environ.get("FWLAB_BIND", "0.0.0.0"), port=int(os.environ.get("FWLAB_PORT", "9300")),
            threaded=True, debug=False, use_reloader=False)
