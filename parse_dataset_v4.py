#!/usr/bin/env python3.12
"""
firewall-IA — v4 CLEAN dataset generator  (experiments E2 + E3)

Run:
    python3.12 parse_dataset_v4.py
    python3.12 parse_dataset_v4.py --out-dir datasets/v4_clean --seed 42

WHY THIS IS A SEPARATE FILE FROM parse_dataset.py
    parse_dataset.py is the generator that produced the HISTORICAL dataset.
    E2 is a before/after comparison, so the historical generator is the control
    condition and must remain executable and unmodified. This is not an
    architectural preference — deleting the control would make the E2
    comparison unreproducible.

────────────────────────────────────────────────────────────────────────────
WHAT THIS FIXES  (audit findings F1, F2, F7, F8; decisions D1, D13-D16)

F1  Envelope shortcuts. The historical generator drew ALLOW and BLOCK from
    DIFFERENT envelope distributions, so Host alone predicted the label at
    93.72%, and Content-Type / header-set / header-count / body-presence /
    HTTP-method were independent shortcuts on top of that.

    Fix: ONE envelope generator, used by both classes, plus SHAPE MATCHING —
    every attack "request shape" (method set, path pool, parameter names,
    content type, special headers) has benign traffic generated in the SAME
    shape and in matched volume. Shortcuts are removed structurally rather
    than one at a time.

F2  26.65% train/eval leakage from splitting a pool that already contained
    duplicates.

    Fix (E3/D16): split by GROUP IDENTITY before rendering. Order is
    source -> canonical group -> split assignment -> render -> augment.
    A payload and every variant derived from it land in the same split.

F7  Label noise: prose lines scraped as payloads, unresolved fuzzer
    placeholders such as {FILE}, raw spaces producing invalid request lines.

    Fix: fenced-code and .txt wordlists only, placeholder/prose/markdown
    rejection with per-reason accounting, and percent-encoding of payloads
    into the request-target.

F8  Obfuscation used simultaneously as training augmentation and as
    adversarial evidence.

    Fix (D15): transforms are partitioned into TRAIN_TRANSFORMS and
    HELD_OUT_TRANSFORMS. Held-out transforms generate NOTHING in this phase;
    they are reserved for a future adversarial suite.

────────────────────────────────────────────────────────────────────────────
NOT DONE HERE, DELIBERATELY

  * ###END### has been REMOVED (D5, experiment E4). Labels are now
    "ALLOW | <reason>" / "BLOCK | <reason>", terminating via native EOS.
  * Weak categories are never inflated (D14). No floors, no upsampling, no
    duplication, no fabrication. Scarce categories are reported as
    INSUFFICIENT DATA and, where they have no held-out rows, as NOT EVALUABLE
    (D18) — Request Smuggling is both.

CATEGORY CONTRIBUTION CONTROL — D17 FINAL (defaults of this script)

  Two INDEPENDENT levers, controlling two DIFFERENT quantities:

    --cap-policy B              source-agnostic: CSIC-derived BLOCK groups
                                count toward the same per-category budget as
                                PayloadsAllTheThings/hardcoded groups.

    --cap-per-category 2500     LOGICAL-GROUP DIVERSITY control.
                                Applied BEFORE rendering. Bounds how many
                                distinct source payloads any one category may
                                contribute.

    --row-cap-per-category 4000 RENDERED-ROW CONTRIBUTION control.
                                Applied AFTER rendering/dedup, BEFORE final
                                balancing. Bounds how much any one category
                                actually contributes to training.

  Why BOTH are required: a group cap alone cannot control training
  contribution, because a CSIC group is a request SHAPE that collapsed many
  original records and every record still renders. Measured: at a 2,500-group
  cap, SQL Injection still produced 5,545 rows while Path Traversal produced
  2,511. The row cap acts directly on the quantity that matters.

  Row selection is deterministic, source-stratified, and breadth-first
  (one row per logical group before any second row), so it removes redundant
  RENDERINGS before it removes logical DIVERSITY. Measured at these settings:
  100% logical-group retention in every category.

  HARD FLOOR: row cap must be >= group cap, else retention is pinned at
  row_cap/group_cap by arithmetic. The script refuses to run otherwise.
  * The 18,478 CSIC anomalous rows the keyword categorizer could not classify
    stay OUT of the baseline (D2). They are counted and reported as
    CSIC_ANOMALOUS_RESERVED, not deleted and not relabelled.
  * No adversarial test suite (D15).
  * No training. The dataset must pass E0 and be reviewed first.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import subprocess
import sys
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime, timezone
from urllib.parse import quote, unquote_plus

# ══════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════
HERE = os.path.dirname(os.path.abspath(__file__))
PAYLOADS_REPO = os.path.expanduser("~/PayloadsAllTheThings")
CSIC_PATH = os.path.join(HERE, "csic_database.csv")

DEFAULT_OUT_DIR = os.path.join(HERE, "datasets", "v4_clean")
DEFAULT_MANIFEST = os.path.join(HERE, "datasets", "manifest_v4_clean.json")

EVAL_FRACTION = 0.20
RANDOM_SEED = 42

INSTRUCTION = (
    "You are a network security firewall classifier. "
    "Analyze the following HTTP request and respond with exactly: "
    "ALLOW or BLOCK | <one sentence reason>."
)

# D5 (experiment E4): the custom ###END### stop token is REMOVED. Labels
# terminate with the model's NATIVE EOS. finetune.py's format_example() appends
# a literal "</s>", which was verified on the installed stack to tokenize to
# eos_token_id 2, and TRL 1.4 does not double-append because the formatted text
# already ends with EOS.

ALLOW_LABEL = "ALLOW | Normal HTTP request with no attack patterns detected."


# ══════════════════════════════════════════════════════════════════════════
# SHARED HTTP ENVELOPE  (E2 core)
#
# Every pool below is used by BOTH classes. There is no benign-only or
# attack-only host, user-agent, cookie or accept header anywhere in this file.
# Envelope values are drawn from an RNG seeded by the sample's GROUP ID, so
# they are deterministic per sample and statistically independent of the label.
# ══════════════════════════════════════════════════════════════════════════
HOSTS = [
    "api.example.com", "app.example.com", "shop.example.com", "www.example.com",
    "portal.example.com", "admin.example.com", "dashboard.example.com",
    "api.shopfront.io", "store.retailco.net", "gateway.fintrust.co",
    "secure.bankone.example", "intranet.corp.local", "services.healthnet.org",
    "cms.newsdaily.example", "api.travelhub.io", "booking.flyaway.example",
    "account.streamly.tv", "api.logistics.example", "hr.enterprise.example",
    "support.helpdesk.example", "files.storagebox.example", "api.devtools.io",
    "checkout.marketplace.example", "auth.identity.example", "media.cdn.example",
    "target.com", "target.internal.com", "localhost:8080", "10.20.30.40:8000",
    "staging.example.com", "qa.example.com", "beta.example.com",
]

USER_AGENTS = [
    None, None, None,   # absent is a legitimate, class-independent option
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/122.0 Mobile Safari/537.36",
    "Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)",
    "curl/8.5.0", "python-requests/2.31.0", "PostmanRuntime/7.36.3",
    "Go-http-client/2.0", "okhttp/4.12.0", "axios/1.6.7", "Java/17.0.9",
    "Apache-HttpClient/5.3 (Java/17)", "Wget/1.21.4", "insomnia/8.6.1",
    "MobileApp/3.1.0 (Android 13)", "MobileApp/3.1.0 (iOS 17.2)",
]

ACCEPT_HEADERS = [
    None, "*/*", "application/json", "text/html,application/xhtml+xml,application/xml;q=0.9",
    "application/json, text/plain, */*",
]
ACCEPT_LANGUAGE = [None, "en-US,en;q=0.9", "es-ES,es;q=0.9,en;q=0.8", "fr-FR,fr;q=0.9"]
ACCEPT_ENCODING = [None, "gzip, deflate", "gzip, deflate, br"]
CONNECTIONS = [None, "keep-alive", "close"]

COOKIE_NAMES = ["JSESSIONID", "sessionid", "session", "SID", "auth_token", "sid", "PHPSESSID"]
EXTRA_COOKIES = ["theme=light", "lang=en", "tz=UTC", "consent=1", "cart=3", "ab=B"]

XREQ_HEADERS = [None, "XMLHttpRequest"]


def _hex(rng, n):
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def _b64ish(rng, n):
    al = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(rng.choice(al) for _ in range(n))


def make_cookie(rng):
    if rng.random() < 0.45:
        return None
    parts = [f"{rng.choice(COOKIE_NAMES)}={_hex(rng, 26).upper()}"]
    for c in EXTRA_COOKIES:
        if rng.random() < 0.18:
            parts.append(c)
    return "; ".join(parts)


def make_bearer(rng):
    """A syntactically ordinary JWT-shaped bearer token (benign-looking)."""
    return f"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{_b64ish(rng, 40)}.{_b64ish(rng, 43)}"


def build_envelope(rng, host=None):
    """The single shared envelope generator. Returns an ordered header list.

    Header ORDER is also randomised from a shared pool so that header-name-set
    and header-count carry no class information.
    """
    h = [("Host", host or rng.choice(HOSTS))]
    ua = rng.choice(USER_AGENTS)
    if ua:
        h.append(("User-Agent", ua))
    for name, pool, p in (
        ("Accept", ACCEPT_HEADERS, 0.55),
        ("Accept-Language", ACCEPT_LANGUAGE, 0.35),
        ("Accept-Encoding", ACCEPT_ENCODING, 0.35),
        ("Connection", CONNECTIONS, 0.30),
    ):
        if rng.random() < p:
            v = rng.choice(pool)
            if v:
                h.append((name, v))
    if rng.random() < 0.20:
        xr = rng.choice(XREQ_HEADERS)
        if xr:
            h.append(("X-Requested-With", xr))
    ck = make_cookie(rng)
    if ck:
        h.append(("Cookie", ck))
    return h


# ══════════════════════════════════════════════════════════════════════════
# REQUEST SHAPES  (E2 shape matching)
#
# A "shape" is the structural envelope of a request: which methods are valid,
# which paths, which parameter names, what content type, which extra headers.
#
# Every attack category is mapped to one or more shapes. The benign generator
# then produces benign traffic in the SAME shapes, in MATCHED volume, so that
# shape carries no label information. Shapes marked causal=True are documented
# exceptions where the structure IS the attack (see CAUSAL_EXCEPTIONS).
# ══════════════════════════════════════════════════════════════════════════
BODYLESS_METHODS = ["GET", "GET", "GET", "DELETE", "HEAD"]
BODY_METHODS = ["POST", "POST", "PUT", "PATCH"]

SHAPES: dict[str, dict] = {
    # ── generic parameterised endpoints ──────────────────────────────────
    "query_param": {
        "paths": ["/api/users", "/api/items", "/search", "/api/products",
                  "/api/orders", "/list", "/api/records", "/browse",
                  "/api/v1/entries", "/catalog", "/api/customers"],
        "params": ["id", "q", "name", "search", "filter", "category",
                   "user", "item", "query", "keyword", "sort"],
        "methods": "both",
        "content_types": ["application/x-www-form-urlencoded", "application/json"],
    },
    # ── file / path handling ─────────────────────────────────────────────
    "file_param": {
        "paths": ["/download", "/api/files", "/static", "/view", "/api/documents",
                  "/export", "/api/attachments", "/media"],
        "params": ["file", "path", "page", "doc", "template", "filename",
                   "include", "resource"],
        "methods": "both",
        "content_types": ["application/x-www-form-urlencoded"],
    },
    # ── outbound-URL handling (SSRF / open redirect shape) ───────────────
    "url_param": {
        "paths": ["/redirect", "/api/fetch", "/proxy", "/api/webhook",
                  "/callback", "/api/preview", "/link", "/api/import"],
        "params": ["url", "next", "redirect", "target", "callback",
                   "return_to", "dest", "u", "src"],
        "methods": "both",
        "content_types": ["application/x-www-form-urlencoded", "application/json"],
    },
    # ── authenticated API (JWT shape) ────────────────────────────────────
    "auth_bearer": {
        "paths": ["/api/me", "/api/account", "/api/profile", "/api/session",
                  "/api/v1/token", "/api/admin/users", "/api/permissions"],
        "params": ["scope", "fields", "expand"],
        "methods": "both",
        "content_types": ["application/json"],
        "always_headers": ["Authorization"],
    },
    # ── JSON document APIs (NoSQL / deserialization shape) ───────────────
    "json_body": {
        "paths": ["/api/query", "/api/search", "/api/filter", "/api/find",
                  "/api/reports", "/api/aggregate", "/api/objects"],
        "params": [],
        "methods": "body",
        "content_types": ["application/json"],
    },
    # ── XML / SOAP APIs (XXE shape) ──────────────────────────────────────
    "xml_body": {
        "paths": ["/api/xml", "/soap", "/api/import", "/services/parse",
                  "/api/feed", "/xmlrpc.php"],
        "params": [],
        "methods": "body",
        "content_types": ["application/xml", "text/xml"],
    },
    # ── GraphQL ──────────────────────────────────────────────────────────
    "graphql": {
        "paths": ["/graphql", "/api/graphql", "/v1/graphql", "/query"],
        "params": ["query"],
        "methods": "body",
        "content_types": ["application/json"],
    },
    # ── directory / identity lookup (LDAP shape) ─────────────────────────
    "directory_lookup": {
        "paths": ["/api/directory", "/api/lookup", "/api/users/search",
                  "/ldap/search", "/api/employees"],
        "params": ["username", "uid", "cn", "user", "dn", "mail"],
        "methods": "both",
        "content_types": ["application/x-www-form-urlencoded"],
    },
    # ── template / rendering (SSTI shape) ────────────────────────────────
    "template_param": {
        "paths": ["/render", "/api/template", "/preview", "/api/email/render",
                  "/api/report/build"],
        "params": ["template", "tpl", "name", "greeting", "subject", "body"],
        "methods": "both",
        "content_types": ["application/x-www-form-urlencoded", "application/json"],
    },
    # ── form submission (XSS / SQLi in POST bodies) ──────────────────────
    "form_post": {
        "paths": ["/login", "/comment", "/api/feedback", "/register",
                  "/api/notes", "/contact", "/api/reviews", "/profile/update"],
        "params": ["username", "password", "comment", "message", "body",
                   "title", "email", "note", "content"],
        "methods": "body",
        "content_types": ["application/x-www-form-urlencoded"],
    },
    # ── shell-adjacent operations (command injection shape) ──────────────
    "exec_param": {
        "paths": ["/api/ping", "/api/tools/dns", "/admin/diagnostics",
                  "/api/convert", "/api/backup"],
        "params": ["host", "cmd", "target", "domain", "input", "arg"],
        "methods": "both",
        "content_types": ["application/x-www-form-urlencoded"],
    },
    # ── CAUSAL SHAPES — structure IS the attack ──────────────────────────
    "cross_origin_state_change": {          # CSRF
        "paths": ["/account/email", "/api/transfer", "/settings/password",
                  "/api/users/role", "/admin/delete", "/api/subscription"],
        "params": ["email", "amount", "to", "role", "new_password", "plan"],
        "methods": "body",
        "content_types": ["application/x-www-form-urlencoded"],
        "always_headers": ["Origin", "Referer"],
        "causal": True,
    },
    "framing_headers": {                    # request smuggling
        "paths": ["/", "/api/submit", "/upload", "/api/stream"],
        "params": [],
        "methods": "body",
        "content_types": ["application/x-www-form-urlencoded"],
        "always_headers": ["Content-Length"],
        "causal": True,
    },
    "repeated_params": {                    # HPP
        "paths": ["/api/users", "/search", "/api/filter", "/api/access",
                  "/admin/query", "/api/order"],
        "params": ["id", "role", "action", "status", "permission", "user",
                   "level", "scope", "mode", "page"],
        "methods": "both",
        "content_types": ["application/x-www-form-urlencoded"],
        "causal": True,
    },
    "header_reflection": {                  # CRLF injection
        "paths": ["/redirect", "/api/log", "/api/track", "/response", "/api/header"],
        "params": ["url", "next", "redirect", "location", "callback", "ref",
                   "return", "target"],
        "methods": "both",
        "content_types": ["application/x-www-form-urlencoded"],
        "causal": True,
    },
}

# category -> (BLOCK reason label, shape name(s))
CATEGORY_SHAPES: dict[str, tuple[str, list[str]]] = {
    "SQL Injection":                  ("SQL injection payload detected.",
                                       ["query_param", "form_post", "directory_lookup"]),
    "XSS Injection":                  ("Cross-site scripting payload detected.",
                                       ["query_param", "form_post"]),
    "Directory Traversal":            ("Path traversal attack detected.",
                                       ["file_param", "query_param"]),
    "Command Injection":              ("Command injection payload detected.",
                                       ["exec_param", "query_param"]),
    "LDAP Injection":                 ("LDAP injection payload detected.",
                                       ["directory_lookup"]),
    "XXE Injection":                  ("XML external entity injection detected.",
                                       ["xml_body"]),
    "Cross-Site Request Forgery":     ("CSRF attack pattern detected.",
                                       ["cross_origin_state_change"]),
    "Open Redirect":                  ("Open redirect payload detected.",
                                       ["url_param"]),
    "Server Side Request Forgery":    ("Server-side request forgery attack detected.",
                                       ["url_param"]),
    "JSON Web Token":                 ("JWT token manipulation attack detected.",
                                       ["auth_bearer"]),
    "GraphQL Injection":              ("GraphQL injection payload detected.",
                                       ["graphql"]),
    "NoSQL Injection":                ("NoSQL injection payload detected.",
                                       ["json_body", "query_param"]),
    "Server Side Template Injection": ("Server-side template injection payload detected.",
                                       ["template_param"]),
    "File Inclusion":                 ("File inclusion attack detected.",
                                       ["file_param"]),
    "Insecure Deserialization":       ("Insecure deserialization payload detected.",
                                       ["json_body", "form_post"]),
    "Request Smuggling":              ("HTTP request smuggling attack detected.",
                                       ["framing_headers"]),
}

HARDCODED_SHAPES = {
    "CRLF Injection":            ("CRLF injection payload detected.", ["header_reflection"]),
    "HTTP Parameter Pollution":  ("HTTP parameter pollution detected.", ["repeated_params"]),
    "XPath Injection":           ("XPath injection payload detected.", ["directory_lookup"]),
}

# Whole fenced block is one payload (line-splitting would destroy semantics)
BLOCK_LEVEL_CATEGORIES = {"XXE Injection", "Request Smuggling", "Insecure Deserialization"}

# Documented exceptions where an envelope feature is ALLOWED to correlate with
# BLOCK because it constitutes part of the attack itself (E2 section B).
CAUSAL_EXCEPTIONS = {
    "Cross-Site Request Forgery": (
        "Origin/Referer must be cross-origin for the attack to exist. Benign "
        "counterparts in the same shape carry same-origin Origin/Referer, so "
        "PRESENCE of the headers is non-predictive; only the cross-origin "
        "RELATIONSHIP correlates with BLOCK."),
    "Request Smuggling": (
        "Conflicting/duplicated Content-Length and Transfer-Encoding framing "
        "headers ARE the attack. Benign counterparts carry a single correct "
        "Content-Length, so header presence is non-predictive; the conflict "
        "is."),
    "HTTP Parameter Pollution": (
        "Duplicate parameter names ARE the attack. Benign counterparts in the "
        "same shape use the same parameter names and paths without "
        "duplication."),
    "CRLF Injection": (
        "Encoded CR/LF sequences interacting with the request-target and "
        "response headers ARE the attack. The payload itself carries the "
        "signal; the envelope is shared."),
}


# ══════════════════════════════════════════════════════════════════════════
# STAGE 2 — NORMALIZATION / QUALITY FILTERING
# ══════════════════════════════════════════════════════════════════════════
# Uppercase-in-single-braces = fuzzer placeholder ({FILE}, {PATH}).
# Deliberately does NOT match SSTI payloads like {{7*7}} or {{config}}.
PLACEHOLDER_RE = re.compile(r"\{[A-Z][A-Z0-9_]{1,}\}")
PLACEHOLDER_LITERALS = (
    "FUZZ", "§", "^^", "<<<", "REPLACE_ME", "YOUR_", "CHANGEME", "[...]",
    "...", "XXXXX", "TODO", "$FILE$", "%%FILE%%", "INSERT_", "PLACEHOLDER",
)
MARKDOWN_START = ("|", "#", ">", "- ", "* ", "+ ", "---", "===", "```", "//", "<!--")
REFERENCE_HOSTS = ("github.com", "twitter.com", "medium.com", "youtube.com",
                   "portswigger.net/web-security", "owasp.org", "hackerone.com",
                   "book.hacktricks", "blog.", "docs.", "wikipedia.org")
ATTACK_HINTS = ("'", '"', "<", ">", ";", "|", "&", "$", "`", "../", "..\\",
                "%", "(", ")", "{", "}", "[", "]", "=", "*", "\\", "/", ":")
PROSE_RE = re.compile(r"^[A-Z][a-z]+(?:\s+[A-Za-z,'()-]+){5,}[.!?]?$")

MIN_LEN, MAX_LEN = 4, 400


def quality_filter(raw: str, category: str) -> tuple[str | None, str]:
    """Return (accepted_payload, reason). reason == 'accepted' on success.

    Every rejection reason is counted and reported — nothing is dropped
    silently (E2: 'Do not silently throw away large amounts of source data').
    """
    s = raw.strip()
    if not s:
        return None, "empty"
    # strip a single layer of surrounding backticks/quotes commonly used in docs
    if len(s) > 2 and s[0] == s[-1] and s[0] in "`":
        s = s[1:-1].strip()
    if len(s) < MIN_LEN:
        return None, "too_short"
    if len(s) > MAX_LEN:
        return None, "too_long"
    if any(s.startswith(p) for p in MARKDOWN_START):
        return None, "markdown_artifact"
    if PLACEHOLDER_RE.search(s):
        return None, "fuzzer_placeholder"
    if any(lit in s for lit in PLACEHOLDER_LITERALS):
        return None, "fuzzer_placeholder"
    # control characters other than tab would corrupt the rendered request
    if any(unicodedata.category(c) == "Cc" and c != "\t" for c in s):
        return None, "control_chars"
    low = s.lower()
    # reference links (but SSRF/redirect payloads that ARE urls are kept when
    # they point at internal/metadata/evil targets rather than documentation)
    if low.startswith(("http://", "https://")) and any(h in low for h in REFERENCE_HOSTS):
        return None, "reference_link"
    if PROSE_RE.match(s) and not any(a in s for a in ("'", '"', "<", ";", "|", "$", "`", "../")):
        return None, "prose"
    if not any(a in s for a in ATTACK_HINTS):
        # a payload with no structural character at all is almost certainly
        # documentation text or a bare word from a wordlist header
        if " " in s:
            return None, "no_payload_indicator"
    return s, "accepted"


FENCE_RE = re.compile(r"```(?:[\w+.-]*)\n(.*?)```", re.DOTALL)


def extract_sources(stats: dict) -> list[dict]:
    """STAGE 1+2 — extract and quality-filter PayloadsAllTheThings payloads.

    Deterministic: all directory and file traversal is sorted.
    """
    out = []
    for category in sorted(CATEGORY_SHAPES):
        cat_dir = os.path.join(PAYLOADS_REPO, category)
        if not os.path.isdir(cat_dir):
            # [SKIP] is an ERROR, not a warning (audit / CONTEXT.md §6)
            raise SystemExit(
                f"FATAL: category directory not found: {cat_dir}\n"
                f"PayloadsAllTheThings may have renamed it. Refusing to generate a "
                f"dataset with a silently missing category."
            )
        cand = 0
        for root, dirs, files in os.walk(cat_dir):
            dirs.sort()
            for fname in sorted(files):
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, PAYLOADS_REPO)
                raws: list[str] = []
                if fname.endswith(".md"):
                    try:
                        content = open(fpath, encoding="utf-8", errors="ignore").read()
                    except OSError:
                        continue
                    for blk in FENCE_RE.findall(content):
                        if category in BLOCK_LEVEL_CATEGORIES and blk.count("\n") > 1:
                            raws.append(blk.strip())          # whole block = 1 payload
                        else:
                            raws.extend(blk.splitlines())
                elif fname.endswith(".txt"):
                    try:
                        raws.extend(open(fpath, encoding="utf-8", errors="ignore").read().splitlines())
                    except OSError:
                        continue
                else:
                    continue
                for raw in raws:
                    cand += 1
                    payload, reason = quality_filter(raw, category)
                    stats["reject_reasons"][reason] += 1
                    if payload is None:
                        continue
                    out.append({"payload": payload, "category": category,
                                "source": rel, "origin": "payloadsallthethings"})
        stats["candidates_per_category"][category] += cand
    return out


# ══════════════════════════════════════════════════════════════════════════
# HARDCODED CATEGORIES  (not present as PayloadsAllTheThings directories)
# ══════════════════════════════════════════════════════════════════════════
CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:%20session=hijacked", "%0d%0aSet-Cookie:%20admin=true",
    "%0d%0aLocation:%20https://evil.example", "%0aLocation:%20https://evil.example",
    "%0d%0aX-Injected:%20header", "%0d%0aContent-Type:%20text/html",
    "%0d%0aContent-Length:%200", "%0aContent-Type:%20text/html%0a%0a<html>injected</html>",
    "value%0d%0aSet-Cookie:%20session=hijacked", "value%0d%0aX-Frame-Options:%20ALLOW",
    "%0d%0aHTTP/1.1%20200%20OK", "test%0d%0aSet-Cookie:%20access=admin;%20HttpOnly",
    "%0d%0aRefresh:%200;url=https://phishing.example", "a%0aSet-Cookie:%20token=stolen",
    "%0d%0aAccess-Control-Allow-Origin:%20*", "value%0d%0aX-XSS-Protection:%200",
    "test%0d%0aContent-Security-Policy:%20default-src%20*",
    "foo%0d%0a%0d%0a<html><script>alert(1)</script></html>",
    "value%250d%250aSet-Cookie:%20session%3Dhijacked",
    "%E5%98%8D%E5%98%8ASet-Cookie:%20injected=true",
    "%00%0d%0aSet-Cookie:%20admin=true",
    "next%3D%250d%250aSet-Cookie%3A%20session%3Dhijacked",
    "value%0d%0aTransfer-Encoding:%20chunked",
    "https://example.com%0d%0aSet-Cookie:%20csrftoken=bypassed",
]

XPATH_PAYLOADS = [
    "' or '1'='1", "' or '1'='1' --", "x' or name()='username' or 'x'='y",
    "') or ('1'='1", "admin' or 1=1 or 'x'='x", "' or 1=1 and '1'='1",
    "' or ''='", "x' or 'x'='x", "') or '1'='1' or ('x'='x",
    "' or position()=1 or '", "' or string-length(name())>0 or '",
    "' or count(/*)>0 or '", "a' or 'a'='a", "' or 'x'='x", "') or ('a'='a",
    "x'; SELECT * FROM users; --", "' or position()>0 or '", "admin' or '1",
    "'] | //user/*[contains(*,'", "x' or true() or 'x'='y",
    "' or local-name()='admin' or 'x'='y", "admin'/*", "' or name()!='x' or '",
    "' or //*[@name]", "') or 1=1 or ('", "x' or string(//user/password)!='",
    "'  or  '1'  =  '1", "' or count(/root/*)=1 or '", "'or'1'='1",
    "' or starts-with(name(), 'admin') or '", "' or substring(password,1,1)='a",
]

# HPP is structural: the attack is the duplicate parameter, not a payload string.
HPP_PARAM_SETS = [
    ("id", ["1", "2", "99999"]), ("role", ["user", "admin"]),
    ("role", ["viewer", "admin", "superadmin"]), ("action", ["view", "delete", "drop"]),
    ("status", ["active", "inactive", "deleted"]), ("permission", ["read", "write", "execute"]),
    ("access", ["public", "internal", "private"]), ("type", ["user", "admin", "system"]),
    ("group", ["users", "admins"]), ("level", ["1", "5", "99"]),
    ("user", ["bob", "admin"]), ("flag", ["0", "1", "true"]),
    ("override", ["false", "true"]), ("priority", ["low", "high", "critical"]),
    ("scope", ["self", "all"]), ("mode", ["read", "write", "admin"]),
    ("filter", ["none", "bypass"]), ("cmd", ["view", "delete", "exec"]),
    ("page", ["1", "99", "-1"]), ("token", ["abc", "admin_token"]),
]

SMUGGLING_VARIANTS = [
    ("CL.TE", [("Content-Length", "13"), ("Transfer-Encoding", "chunked")], "0\r\n\r\nSMUGGLED"),
    ("TE.CL", [("Transfer-Encoding", "chunked"), ("Content-Length", "4")], "5c\r\nGPOST /x"),
    ("TE.TE obfuscated", [("Transfer-Encoding", "chunked"), ("Transfer-Encoding", "identity")], "0\r\n\r\n"),
    ("TE space", [("Transfer-Encoding ", "chunked"), ("Content-Length", "6")], "0\r\n\r\n"),
    ("double CL", [("Content-Length", "6"), ("Content-Length", "0")], "SMUGGL"),
    ("TE tab", [("Transfer-Encoding", "\tchunked"), ("Content-Length", "4")], "0\r\n\r\n"),
]


def build_hardcoded_sources() -> list[dict]:
    out = []
    for p in CRLF_PAYLOADS:
        out.append({"payload": p, "category": "CRLF Injection",
                    "source": "hardcoded:CRLF_PAYLOADS", "origin": "hardcoded"})
    for p in XPATH_PAYLOADS:
        out.append({"payload": p, "category": "XPath Injection",
                    "source": "hardcoded:XPATH_PAYLOADS", "origin": "hardcoded"})
    for name, values in HPP_PARAM_SETS:
        out.append({"payload": json.dumps({"param": name, "values": values}),
                    "category": "HTTP Parameter Pollution",
                    "source": "hardcoded:HPP_PARAM_SETS", "origin": "hardcoded",
                    "structural": True})
    for label, headers, body in SMUGGLING_VARIANTS:
        out.append({"payload": json.dumps({"variant": label, "headers": headers, "body": body}),
                    "category": "Request Smuggling",
                    "source": "hardcoded:SMUGGLING_VARIANTS", "origin": "hardcoded",
                    "structural": True})
    return out


# ══════════════════════════════════════════════════════════════════════════
# STAGE 3+4 — CANONICALIZATION AND GROUP IDENTITY  (E3 / D16)
# ══════════════════════════════════════════════════════════════════════════
def canonical_key(payload: str) -> str:
    """Collapse encoding/case/whitespace variants onto one logical identity.

    Two payloads that differ only by URL-encoding, case, or whitespace belong
    to the SAME group and therefore always land in the same split. This is what
    prevents an obfuscated variant of a training payload appearing in eval.
    """
    s = payload
    for _ in range(3):                      # undo multi-layer percent-encoding
        try:
            nxt = unquote_plus(s)
        except Exception:
            break
        if nxt == s:
            break
        s = nxt
    s = s.replace("\\u003c", "<").replace("\\u003e", ">").replace("\\u0027", "'")
    s = s.replace("&lt;", "<").replace("&gt;", ">").replace("&#39;", "'").replace("&quot;", '"')
    s = re.sub(r"/\*.*?\*/", "", s)         # SEL/**/ECT -> SELECT
    s = re.sub(r"\s+", " ", s)              # tab/space obfuscation
    s = s.replace("${IFS}", " ")
    s = s.strip().lower()
    return s


def group_id(kind: str, key: str) -> str:
    return hashlib.sha256(f"{kind}\x00{key}".encode()).hexdigest()[:32]


def assign_split(gid: str, eval_fraction: float, salt: str) -> str:
    """Deterministic, order-independent group -> split assignment.

    Uses a hash bucket rather than a shuffled list so the assignment is stable
    regardless of iteration order, dataset size, or Python hash seeding.
    """
    h = hashlib.sha256(f"{salt}\x00{gid}".encode()).digest()
    bucket = int.from_bytes(h[:8], "big") % 10_000
    return "eval" if bucket < int(eval_fraction * 10_000) else "train"


# ══════════════════════════════════════════════════════════════════════════
# STAGE 7 — TRANSFORM POOLS  (D15)
#
# TRAIN_TRANSFORMS may be used to augment training AND eval rows (each within
# its own split, so no group crosses over).
# HELD_OUT_TRANSFORMS generate NOTHING in this phase. They are reserved
# exclusively for a future adversarial evaluation suite and must never be used
# to produce training examples.
# ══════════════════════════════════════════════════════════════════════════
def t_url_encode(p, rng):
    table = {"'": "%27", "<": "%3C", ">": "%3E", " ": "%20", ";": "%3B", "=": "%3D"}
    return "".join(table.get(c, c) for c in p)


_SQL_KW = re.compile(r"\b(SELECT|UNION|DROP|WHERE|FROM|INSERT|UPDATE|DELETE|TABLE|ORDER|HAVING|GROUP)\b", re.I)


def t_case_variation(p, rng):
    return _SQL_KW.sub(lambda m: "".join(c.upper() if rng.random() > 0.5 else c.lower()
                                         for c in m.group(0)), p)


_COMMENT_SUBS = [("SELECT", "SEL/**/ECT"), ("UNION", "UN/**/ION"), ("DROP", "DR/**/OP"),
                 ("WHERE", "WH/**/ERE"), ("FROM", "FR/**/OM"), ("INSERT", "INS/**/ERT")]


def t_sql_comment(p, rng):
    r = p
    for a, b in _COMMENT_SUBS:
        r = re.sub(a, b, r, flags=re.I, count=1)
    return r


def t_whitespace_tab(p, rng):
    return p.replace(" ", "\t")


TRAIN_TRANSFORMS = {
    "url_encode": t_url_encode,
    "case_variation": t_case_variation,
    "sql_comment_inject": t_sql_comment,
    "whitespace_tab": t_whitespace_tab,
}

# Defined, documented, and DELIBERATELY UNUSED in this phase.
HELD_OUT_TRANSFORMS = {
    "double_url_encode": "percent-encode, then encode each % as %25",
    "unicode_escape": r"escape < > ' \" as \uXXXX",
    "html_entity": "named/numeric HTML entity encoding",
    "bash_ifs": "replace spaces with ${IFS}; backtick exec -> $()",
    "mixed_case_percent": "randomise hex case in percent-escapes (%2F vs %2f)",
    "param_fragmentation": "split a payload across repeated parameters",
}


# ══════════════════════════════════════════════════════════════════════════
# STAGE 6 — RENDERING  (shared envelope for both classes)
# ══════════════════════════════════════════════════════════════════════════
def encode_target_value(v: str) -> str:
    """Percent-encode a value for safe placement in a request-target.

    Prevents the historical 'raw space in request-target' artifact, which was
    100% pure toward BLOCK (1,418 vs 0).
    """
    return quote(v, safe="")


def render_headers(pairs) -> str:
    return "\n".join(f"{k}: {v}" for k, v in pairs)


def render_request(rng, shape_name: str, payload_value: str | None, *,
                   param_name: str | None = None,
                   structural: dict | None = None,
                   category: str | None = None) -> str:
    """Render one HTTP request in the given shape, using the SHARED envelope."""
    shape = SHAPES[shape_name]
    path = rng.choice(shape["paths"])
    methods = (BODYLESS_METHODS + BODY_METHODS if shape["methods"] == "both"
               else BODY_METHODS if shape["methods"] == "body" else BODYLESS_METHODS)
    method = rng.choice(methods)
    has_body = method in ("POST", "PUT", "PATCH")
    headers = build_envelope(rng)
    body = None
    query = ""

    always = shape.get("always_headers", [])
    if "Authorization" in always:
        headers.append(("Authorization", f"Bearer {payload_value if category == 'JSON Web Token' else make_bearer(rng)}"))
        if category == "JSON Web Token":
            payload_value = None            # payload lives in the header
    if "Origin" in always:
        host = dict(headers)["Host"]
        if category == "Cross-Site Request Forgery":
            evil = rng.choice(["https://evil.example", "null", "https://attacker.test",
                               "https://" + host.split(":")[0] + ".evil.example"])
            headers.append(("Origin", evil))
            headers.append(("Referer", (evil if evil != "null" else "https://attacker.test") + "/x"))
        else:
            headers.append(("Origin", f"https://{host}"))
            headers.append(("Referer", f"https://{host}{path}"))

    ct_pool = shape["content_types"]
    ctype = rng.choice(ct_pool)

    # ── structural (causal) categories ───────────────────────────────────
    if structural and category == "HTTP Parameter Pollution":
        qs = "&".join(f"{structural['param']}={quote(v, safe='')}" for v in structural["values"])
        if has_body:
            headers.append(("Content-Type", "application/x-www-form-urlencoded"))
            body = qs
        else:
            query = "?" + qs
    elif structural and category == "Request Smuggling":
        method = "POST"
        has_body = True
        for k, v in structural["headers"]:
            headers.append((k, v))
        headers.append(("Content-Type", ctype))
        body = structural["body"]
    elif shape_name == "repeated_params":       # benign counterpart: no duplication
        names = rng.sample(shape["params"], k=min(3, len(shape["params"])))
        qs = "&".join(f"{n}={quote(BENIGN_VALUES(rng, n), safe='')}" for n in names)
        if has_body:
            headers.append(("Content-Type", "application/x-www-form-urlencoded"))
            body = qs
        else:
            query = "?" + qs
    elif shape_name == "framing_headers":       # benign counterpart: correct framing
        method = "POST"
        has_body = True
        payload_value = payload_value or f"data={_b64ish(rng, 12)}"
        headers.append(("Content-Length", str(len(payload_value))))
        headers.append(("Content-Type", ctype))
        body = payload_value
    # ── ordinary payload placement ───────────────────────────────────────
    elif shape_name in ("json_body", "graphql"):
        headers.append(("Content-Type", "application/json"))
        has_body = True
        if method not in BODY_METHODS:
            method = rng.choice(BODY_METHODS)
        if shape_name == "graphql":
            body = json.dumps({"query": payload_value}) if payload_value else \
                json.dumps({"query": rng.choice(BENIGN_GRAPHQL)})
        else:
            body = payload_value if (payload_value and payload_value.lstrip().startswith(("{", "["))) \
                else json.dumps({rng.choice(["filter", "where", "match", "q"]):
                                 payload_value or BENIGN_VALUES(rng, "q")})
    elif shape_name == "xml_body":
        headers.append(("Content-Type", ctype))
        has_body = True
        if method not in BODY_METHODS:
            method = rng.choice(BODY_METHODS)
        body = payload_value or rng.choice(BENIGN_XML)
    elif payload_value is None:
        # benign request in a shape whose payload slot is unused
        if shape["params"]:
            n = rng.choice(shape["params"])
            v = encode_target_value(BENIGN_VALUES(rng, n))
            if has_body:
                headers.append(("Content-Type", ctype))
                body = f"{n}={v}"
            else:
                query = f"?{n}={v}"
        elif has_body:
            headers.append(("Content-Type", ctype))
            body = f"data={_b64ish(rng, 10)}"
    else:
        n = param_name or (rng.choice(shape["params"]) if shape["params"] else "q")
        if has_body:
            headers.append(("Content-Type", ctype))
            if ctype == "application/json":
                body = json.dumps({n: payload_value})
            else:
                body = f"{n}={quote(payload_value, safe='')}"
        else:
            query = f"?{n}={encode_target_value(payload_value)}"

    lines = [f"{method} {path}{query} HTTP/1.1", render_headers(headers)]
    out = "\n".join(lines)
    if body is not None:
        out += "\n\n" + body
    return out


# ══════════════════════════════════════════════════════════════════════════
# BENIGN GENERATION  (D13 — parametrized, not replicated templates)
# ══════════════════════════════════════════════════════════════════════════
FIRST_NAMES = ["ana", "luis", "maria", "john", "sara", "diego", "emma", "raj", "yuki",
               "omar", "lena", "pablo", "nina", "tom", "chloe", "hugo", "ines", "karl"]
LAST_NAMES = ["garcia", "smith", "lopez", "kumar", "tanaka", "muller", "rossi", "dubois",
              "silva", "novak", "haddad", "olsen", "walsh", "moreau"]
PRODUCTS = ["laptop", "headphones", "desk-lamp", "coffee-maker", "monitor", "keyboard",
            "backpack", "sneakers", "notebook", "webcam", "router", "chair"]
CITIES = ["madrid", "lisbon", "oslo", "kyoto", "austin", "lima", "cairo", "dublin"]
DEPARTMENTS = ["sales", "engineering", "finance", "support", "marketing", "legal"]
STATUSES = ["active", "pending", "archived", "draft", "shipped", "closed"]
FILE_NAMES = ["report", "invoice", "summary", "manual", "export", "receipt", "policy"]
FILE_EXTS = ["pdf", "csv", "xlsx", "png", "txt", "json", "docx"]
SORTS = ["created_at", "-created_at", "name", "-price", "relevance", "updated_at"]

BENIGN_GRAPHQL = [
    "query { user(id: 42) { id name email } }",
    "query GetOrders($s: String) { orders(status: $s) { id total } }",
    "mutation { createNote(title: \"standup\", body: \"notes\") { id } }",
    "query { products(first: 20) { edges { node { id title price } } } }",
    "query { me { id displayName preferences { theme locale } } }",
    "mutation { updateProfile(input: {city: \"oslo\"}) { ok } }",
]

BENIGN_XML = [
    '<?xml version="1.0"?><order><id>4821</id><item>laptop</item><qty>1</qty></order>',
    '<?xml version="1.0"?><invoice><number>INV-2044</number><total>149.90</total></invoice>',
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
    '<GetCustomer><Id>7781</Id></GetCustomer></soap:Body></soap:Envelope>',
    '<?xml version="1.0"?><feed><entry><title>release notes</title></entry></feed>',
    '<?xml version="1.0"?><employee><name>ana garcia</name><dept>finance</dept></employee>',
]


def BENIGN_VALUES(rng, param_name: str) -> str:
    """Realistic, semantically valid value for a parameter name."""
    n = param_name.lower()
    if n in ("id", "item", "level", "page", "amount", "qty"):
        return str(rng.randint(1, 99999))
    if n in ("user", "username", "uid", "name"):
        return rng.choice(FIRST_NAMES) + rng.choice(["", "." + rng.choice(LAST_NAMES), str(rng.randint(1, 99))])
    if n in ("email", "mail"):
        return f"{rng.choice(FIRST_NAMES)}.{rng.choice(LAST_NAMES)}@example.com"
    if n in ("q", "query", "search", "keyword"):
        return rng.choice([rng.choice(PRODUCTS), f"{rng.choice(PRODUCTS)} reviews",
                           rng.choice(CITIES), f"how to return a {rng.choice(PRODUCTS)}"])
    if n in ("file", "doc", "filename", "resource", "path", "include", "template", "tpl"):
        return f"{rng.choice(FILE_NAMES)}-{rng.randint(2020, 2026)}.{rng.choice(FILE_EXTS)}"
    if n in ("url", "next", "redirect", "target", "callback", "return_to", "dest", "u", "src"):
        return rng.choice([f"https://{rng.choice(HOSTS)}/dashboard",
                           f"/account/{rng.choice(['orders', 'settings', 'profile'])}",
                           f"https://{rng.choice(HOSTS)}/webhooks/{_hex(rng, 8)}"])
    if n in ("category", "filter", "type", "group", "dept"):
        return rng.choice(DEPARTMENTS + PRODUCTS)
    if n in ("status", "state", "mode", "scope", "role", "permission", "access", "action"):
        return rng.choice(STATUSES + ["read", "write", "self", "member", "view"])
    if n == "sort":
        return rng.choice(SORTS)
    if n in ("host", "domain", "cmd", "arg", "input"):
        return rng.choice([f"{rng.choice(CITIES)}.example.com", "8.8.8.8", "status", "healthcheck"])
    if n in ("password", "new_password"):
        return _b64ish(rng, 12)
    if n in ("comment", "message", "body", "note", "content", "greeting", "subject", "title"):
        return rng.choice([
            f"Thanks, the {rng.choice(PRODUCTS)} arrived on time.",
            f"Please update my address to {rng.choice(CITIES)}.",
            "Meeting moved to Thursday at 10:00.",
            f"Can I exchange the {rng.choice(PRODUCTS)} for a different colour?",
            "Ticket resolved, closing this out.",
        ])
    if n in ("cn", "dn"):
        return f"cn={rng.choice(FIRST_NAMES)},ou={rng.choice(DEPARTMENTS)},dc=example,dc=com"
    if n in ("fields", "expand", "plan", "to"):
        return rng.choice(["id,name", "summary", "pro", "team", "basic"])
    return rng.choice(PRODUCTS + CITIES + STATUSES)


def build_benign_sources(shape_demand: Counter, rng: random.Random) -> list[dict]:
    """Generate benign logical samples SHAPE-MATCHED to the BLOCK pool.

    For each shape, produce as many distinct benign logical samples as there
    are BLOCK samples in that shape. Diversity comes from the parameter space,
    not from replicating templates (D13).
    """
    out = []
    for shape_name, demand in sorted(shape_demand.items()):
        seen = set()
        attempts = 0
        while len(seen) < demand and attempts < demand * 40:
            attempts += 1
            shape = SHAPES[shape_name]
            path = rng.choice(shape["paths"])
            if shape["params"]:
                pname = rng.choice(shape["params"])
                pval = BENIGN_VALUES(rng, pname)
            else:
                pname, pval = "", rng.choice(BENIGN_XML + BENIGN_GRAPHQL) \
                    if shape_name in ("xml_body", "graphql") else _b64ish(rng, 10)
            key = f"{shape_name}|{path}|{pname}|{pval}"
            if key in seen:
                continue
            seen.add(key)
            out.append({"shape": shape_name, "path": path, "param": pname,
                        "value": pval, "category": "BENIGN",
                        "source": f"synthetic:{shape_name}", "origin": "synthetic_benign"})
    return out


# ══════════════════════════════════════════════════════════════════════════
# CSIC 2010
# ══════════════════════════════════════════════════════════════════════════
def csic_category(request_str: str) -> str | None:
    s = request_str.lower()
    dec = unquote_plus(request_str).lower()

    def has(kws):
        return any(k in s or k in dec for k in kws)

    if has(["union", "select", "drop", "insert", "update", "delete", "or '1'='1",
            "--", ";--", "xp_", "exec", "cast(", "convert(", "waitfor",
            "benchmark(", "sleep(", "0x", "char(", "concat("]):
        return "SQL injection payload detected."
    if has(["<script", "</script>", "alert(", "onerror=", "onload=", "onclick=",
            "javascript:", "<img", "<svg", "<iframe", "document.cookie"]):
        return "Cross-site scripting payload detected."
    if has(["/etc/passwd", "/etc/shadow", "/bin/sh", "cmd.exe", "whoami", "cat ",
            "ls ", "wget ", "curl ", "nc ", "bash", ";ls", "|ls", "$(", "`"]):
        return "Command injection payload detected."
    if has(["../", "..\\", "%2e%2e", "/etc/", "/proc/", "php://filter", "file://"]):
        return "Path traversal attack detected."
    if has(["*)(", ")(|(", "*)(uid=", ")(cn="]):
        return "LDAP injection payload detected."
    if has(["<!entity", 'system "', "file:///", "<!doctype"]):
        return "XML external entity injection detected."
    if has(["169.254.169.254", "127.0.0.1", "internal.", "0.0.0.0", "metadata.google"]):
        return "Server-side request forgery attack detected."
    if has(["$where", "$gt", "$ne", "$regex", '{"$']):
        return "NoSQL injection payload detected."
    if has(["%0d%0a", "%0a%0d"]):
        return "CRLF injection payload detected."
    return None          # generic fallback -> CSIC_ANOMALOUS_RESERVED (D2)


def load_csic(stats: dict, cache_path: str | None = None) -> tuple[list[dict], list[dict]]:
    """Parse CSIC 2010. Optionally cached — the cache stores the parsed result
    only, so it cannot change the output, and it is keyed on the CSV hash."""
    if cache_path and os.path.isfile(cache_path):
        import pickle
        with open(cache_path, "rb") as f:
            blob = pickle.load(f)
        if blob.get("csv_sha256") == sha256_file(CSIC_PATH):
            stats["CSIC_ANOMALOUS_RESERVED"] = blob["reserved"]
            stats["csic_malformed"] = blob["malformed"]
            return blob["normals"], blob["anomalous"]

    import pandas as pd
    from urllib.parse import urlparse

    df = pd.read_csv(CSIC_PATH)
    normals, anomalous = [], []
    reserved = 0
    for _, row in df.iterrows():
        label, method, url = row.get("Unnamed: 0"), row.get("Method"), row.get("URL")
        if pd.isna(method) or pd.isna(url):
            stats["csic_malformed"] += 1
            continue
        u = str(url).strip()
        if " HTTP/" in u:
            u = u[: u.rfind(" HTTP/")]
        parsed = urlparse(u)
        path = parsed.path
        if path.startswith("/tienda1"):
            path = path[len("/tienda1"):]
        path = path or "/"
        body = row.get("content")
        body = str(body) if not pd.isna(body) and str(body).strip() else None
        rec = {"method": str(method), "path": path, "query": parsed.query,
               "body": body, "origin": "csic"}
        if str(label) == "Normal":
            rec["category"] = "BENIGN"
            normals.append(rec)
        elif str(label) == "Anomalous":
            probe = f"{method} {path}?{parsed.query}\n{body or ''}"
            cat = csic_category(probe)
            if cat is None:
                reserved += 1               # D2 — counted, not deleted, not relabelled
                continue
            rec["reason"] = cat
            anomalous.append(rec)
    stats["CSIC_ANOMALOUS_RESERVED"] = reserved
    if cache_path:
        import pickle
        os.makedirs(os.path.dirname(os.path.abspath(cache_path)), exist_ok=True)
        with open(cache_path, "wb") as f:
            pickle.dump({"csv_sha256": sha256_file(CSIC_PATH), "normals": normals,
                         "anomalous": anomalous, "reserved": reserved,
                         "malformed": stats["csic_malformed"]}, f)
    return normals, anomalous


def csic_group_key(rec: dict) -> str:
    """Collapse CSIC near-duplicates (same shape, different literal values).

    Record identity alone would let `cantidad=1` sit in train while
    `cantidad=2` sits in eval — an exact-match gate would pass while real
    near-duplicate leakage remained. Collapsing digits and decoding percent
    escapes puts all variants of one request shape in the same group.
    """
    from urllib.parse import parse_qsl
    parts = [rec["method"], rec["path"]]
    kv = parse_qsl(rec["query"], keep_blank_values=True) if rec["query"] else []
    if rec["body"]:
        kv += parse_qsl(rec["body"], keep_blank_values=True)
    for k, v in sorted(kv):
        v = unquote_plus(v).lower()
        v = re.sub(r"\d+", "#", v)
        v = re.sub(r"\s+", " ", v).strip()
        parts.append(f"{k}={v[:120]}")
    return "|".join(parts)


def render_csic(rng, rec: dict) -> str:
    """Re-render a CSIC record under the SHARED envelope.

    The semantic content (method, path, query, body) is preserved exactly.
    Only the envelope — Host, User-Agent, Cookie, Accept-* — is redrawn from
    the shared pools, which is what removes the historical
    `Host: target.com` + single-Konqueror-UA confound.
    """
    headers = build_envelope(rng)
    q = f"?{rec['query']}" if rec["query"] else ""
    lines = [f"{rec['method']} {rec['path']}{q} HTTP/1.1"]
    if rec["body"]:
        headers.append(("Content-Type", "application/x-www-form-urlencoded"))
    out = lines[0] + "\n" + render_headers(headers)
    if rec["body"]:
        out += "\n\n" + rec["body"]
    return out


# ══════════════════════════════════════════════════════════════════════════
# MAIN PIPELINE
# ══════════════════════════════════════════════════════════════════════════
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def git_rev(repo):
    try:
        r = subprocess.run(["git", "-C", os.path.expanduser(repo), "rev-parse", "HEAD"],
                           capture_output=True, text=True, timeout=10)
        return r.stdout.strip() if r.returncode == 0 else "<unavailable>"
    except Exception:
        return "<unavailable>"


def main():
    ap = argparse.ArgumentParser(description="firewall-IA v4 clean dataset generator (E2+E3)")
    ap.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    ap.add_argument("--manifest", default=DEFAULT_MANIFEST)
    ap.add_argument("--seed", type=int, default=RANDOM_SEED)
    ap.add_argument("--eval-fraction", type=float, default=EVAL_FRACTION)
    ap.add_argument("--augment-per-group", type=int, default=1,
                    help="training-pool obfuscated variants per eligible group")
    ap.add_argument("--cap-per-category", type=int, default=2500,
                    help="Max LOGICAL GROUPS per malicious attack category, applied "
                         "before rendering and augmentation (DECISIONS.md D17 FINAL). "
                         "Controls source/category DIVERSITY dominance. "
                         "Use 0 to disable and reproduce the uncapped candidate.")
    ap.add_argument("--cap-policy", choices=["A", "B"], default="B",
                    help="A (default, D17 as approved): cap applies only to "
                         "PayloadsAllTheThings/hardcoded attack groups. "
                         "B (source-agnostic, DEFAULT, D17 FINAL): CSIC-derived BLOCK "
                         "groups also count toward the same per-category budget.")
    ap.add_argument("--row-cap-per-category", type=int, default=4000,
                    help="Max RENDERED BLOCK ROWS per malicious category, applied "
                         "after rendering/dedup and before final balancing "
                         "(DECISIONS.md D17 FINAL). Controls final training "
                         "CONTRIBUTION. Must be >= --cap-per-category or logical "
                         "diversity is lost by arithmetic. 0 = off.")
    ap.add_argument("--stats-json", default=None,
                    help="Optional side-car statistics file with per-category source "
                         "attribution (used by the cap sensitivity analysis).")
    ap.add_argument("--csic-cache", default=None,
                    help="Optional path for a parsed-CSIC cache (speeds up repeated "
                         "runs; does not affect output).")
    args = ap.parse_args()

    # A category cannot represent G logical groups in fewer than G rendered
    # rows: the breadth-first round robin runs out of budget on its first pass
    # and group retention pins at exactly row_cap/group_cap. Measured at
    # row_cap=2000 / group_cap=2500 -> 80.0% retention in four categories.
    # Refuse rather than silently destroy logical diversity.
    if 0 < args.row_cap_per_category < args.cap_per_category:
        raise SystemExit(
            f"FATAL: --row-cap-per-category ({args.row_cap_per_category}) is below "
            f"--cap-per-category ({args.cap_per_category}).\n"
            f"This would cap logical-group retention at "
            f"{100 * args.row_cap_per_category / args.cap_per_category:.1f}% by "
            f"arithmetic, destroying logical diversity rather than redundancy.\n"
            f"See reports/e2_e3_row_cap_sensitivity.txt section 3."
        )

    rng = random.Random(args.seed)
    stats = {"reject_reasons": Counter(), "candidates_per_category": Counter(),
             "csic_malformed": 0, "CSIC_ANOMALOUS_RESERVED": 0}

    print("[1/9] Extracting PayloadsAllTheThings sources...")
    patt = extract_sources(stats)
    print(f"      accepted payload candidates: {len(patt):,}")

    print("[2/9] Hardcoded categories...")
    hardcoded = build_hardcoded_sources()
    print(f"      hardcoded logical samples: {len(hardcoded):,}")

    print("[3/9] Canonicalizing + assigning group identities...")
    groups: dict[str, dict] = {}
    for rec in patt + hardcoded:
        key = canonical_key(rec["payload"]) if not rec.get("structural") else rec["payload"]
        gid = group_id("attack", key)
        if gid not in groups:
            groups[gid] = {"gid": gid, "category": rec["category"], "payload": rec["payload"],
                           "source": rec["source"], "origin": rec["origin"],
                           "structural": rec.get("structural", False), "n_variants": 0}
        groups[gid]["n_variants"] += 1
    print(f"      unique attack groups: {len(groups):,} "
          f"(from {len(patt) + len(hardcoded):,} raw accepted -> "
          f"{len(patt) + len(hardcoded) - len(groups):,} collapsed as duplicates)")

    # ── D17 — per-category cap on LOGICAL GROUPS, before rendering/augmentation
    #
    # Applied to malicious attack categories only; benign groups are untouched.
    # Selection is by sorted group id, which is a sha256 of the canonical
    # payload — deterministic, independent of iteration order, and stable
    # across seed changes. Scarce categories are never upsampled and nothing is
    # duplicated to meet a floor (D14).
    groups_before_cap = Counter(g["category"] for g in groups.values())
    cap_report: dict[str, dict] = {}

    print("[4/9] Loading CSIC 2010...")
    csic_normal, csic_anom = load_csic(stats, args.csic_cache)
    print(f"      CSIC Normal: {len(csic_normal):,}  Anomalous(categorized): {len(csic_anom):,}")
    print(f"      CSIC_ANOMALOUS_RESERVED (D2, excluded): {stats['CSIC_ANOMALOUS_RESERVED']:,}")

    csic_groups: dict[str, dict] = {}
    for rec in csic_anom:
        gid = group_id("csic_attack", csic_group_key(rec))
        csic_groups.setdefault(gid, {"gid": gid, "recs": [], "reason": rec["reason"],
                                     "label": "BLOCK"})["recs"].append(rec)
    for rec in csic_normal:
        gid = group_id("csic_benign", csic_group_key(rec))
        csic_groups.setdefault(gid, {"gid": gid, "recs": [], "reason": None,
                                     "label": "ALLOW"})["recs"].append(rec)
    print(f"      CSIC groups: {len(csic_groups):,} "
          f"(from {len(csic_normal) + len(csic_anom):,} records)")

    # ── D17 — per-category cap on LOGICAL GROUPS, before rendering/augmentation
    #
    # Policy A (D17 as approved): only PayloadsAllTheThings/hardcoded attack
    #   groups count toward the budget.
    # Policy B (sensitivity analysis only, NOT approved): CSIC-derived BLOCK
    #   groups count toward the SAME per-category budget, so category dominance
    #   is controlled source-agnostically.
    #
    # Selection is by sorted group id — a sha256 of the canonical payload —
    # so it is deterministic, order-independent, and stable across seed changes.
    # Under policy B the merged pool is sorted by the same key, which mixes the
    # two sources without preferring either. Benign groups are never capped,
    # scarce categories are never upsampled, and nothing is duplicated (D14).
    REASON_TO_CATEGORY = {r: c for c, (r, _) in
                          {**CATEGORY_SHAPES, **HARDCODED_SHAPES}.items()}

    if args.cap_per_category > 0:
        bycat: dict[str, list] = defaultdict(list)
        for g in groups.values():
            bycat[g["category"]].append(("attack", g["gid"], g))
        if args.cap_policy == "B":
            for gid, g in csic_groups.items():
                if g["label"] != "BLOCK":
                    continue
                cat = REASON_TO_CATEGORY.get(g["reason"])
                if cat is None:                     # CSIC-only composite label
                    cat = "CSIC:" + g["reason"]
                bycat[cat].append(("csic", gid, g))

        keep_attack, drop_csic = {}, set()
        for c in sorted(bycat):
            entries = sorted(bycat[c], key=lambda e: e[1])   # deterministic
            keep, drop = entries[: args.cap_per_category], entries[args.cap_per_category:]
            for kind, gid, g in keep:
                if kind == "attack":
                    keep_attack[gid] = g
            for kind, gid, g in drop:
                if kind == "csic":
                    drop_csic.add(gid)
            if drop:
                cap_report[c] = {
                    "before": len(entries), "after": len(keep), "removed": len(drop),
                    "removed_attack": sum(1 for k, _, _ in drop if k == "attack"),
                    "removed_csic": sum(1 for k, _, _ in drop if k == "csic"),
                }
        total_removed = sum(v["removed"] for v in cap_report.values())
        print(f"      D17 cap = {args.cap_per_category} logical groups/category "
              f"(policy {args.cap_policy})")
        print(f"      attack groups: {len(groups):,} -> {len(keep_attack):,}"
              + (f" | CSIC BLOCK groups dropped: {len(drop_csic):,}" if drop_csic else ""))
        print(f"      {total_removed:,} groups removed from {len(cap_report)} categor"
              f"{'y' if len(cap_report) == 1 else 'ies'}")
        for c in sorted(cap_report, key=lambda c: -cap_report[c]["removed"]):
            v = cap_report[c]
            extra = (f"  [attack -{v['removed_attack']:,} / csic -{v['removed_csic']:,}]"
                     if args.cap_policy == "B" else "")
            print(f"        CAPPED  {c:<32} {v['before']:>6} -> {v['after']:>5} "
                  f"(-{v['removed']:,}){extra}")
        untouched = len(groups_before_cap) - sum(
            1 for c in cap_report if c in groups_before_cap)
        print(f"        {untouched} attack categor"
              f"{'y' if untouched == 1 else 'ies'} below the cap, preserved as-is")
        groups = keep_attack
        if drop_csic:
            csic_groups = {gid: g for gid, g in csic_groups.items() if gid not in drop_csic}

    print("[5/9] Shape demand + benign generation...")
    # assign a stable shape per group (deterministic from gid)
    for g in groups.values():
        _, shapes = (CATEGORY_SHAPES.get(g["category"]) or HARDCODED_SHAPES[g["category"]])
        idx = int(g["gid"][:8], 16) % len(shapes)
        g["shape"] = shapes[idx]

    # Demand must match RENDERED BLOCK ROWS, not group count. Augmentation emits
    # up to augment_per_group extra rows per non-structural group; matching only
    # group count leaves the shared-envelope population ~2:1 BLOCK-heavy, which
    # reintroduces a method/shape confound via the leftover CSIC-only ALLOW mass.
    shape_demand = Counter()
    for g in groups.values():
        n = 1 + (0 if g["structural"] else args.augment_per_group)
        shape_demand[g["shape"]] += n

    benign = build_benign_sources(shape_demand, rng)
    print(f"      synthetic benign logical samples: {len(benign):,} "
          f"across {len(shape_demand)} shapes")
    bgroups: dict[str, dict] = {}
    for rec in benign:
        gid = group_id("benign", f"{rec['shape']}|{rec['path']}|{rec['param']}|{rec['value']}")
        bgroups[gid] = {"gid": gid, **rec}

    print("[6/9] Deterministic group -> split assignment...")
    salt = f"firewall-IA-v4-{args.seed}"
    for coll in (groups, bgroups, csic_groups):
        for gid, g in coll.items():
            g["split"] = assign_split(gid, args.eval_fraction, salt)

    print("[7/9] Rendering (shared envelope) + training-pool augmentation...")
    rows = {"train": [], "eval": []}
    per_cat = defaultdict(lambda: Counter())

    def emit(split, inp, out_label, cat, src="attack", gid=""):
        # "_"-prefixed keys are in-memory provenance tags used for the row-cap
        # and for statistics. They are stripped before writing, so the JSONL
        # output is unaffected.
        rows[split].append({"instruction": INSTRUCTION, "input": inp,
                            "output": out_label,
                            "_src": src, "_cat": cat, "_gid": gid})
        per_cat[cat][split] += 1

    for g in sorted(groups.values(), key=lambda x: x["gid"]):
        cat = g["category"]
        reason, _ = (CATEGORY_SHAPES.get(cat) or HARDCODED_SHAPES[cat])
        label = f"BLOCK | {reason}"
        srng = random.Random(f"{salt}|{g['gid']}")
        structural = json.loads(g["payload"]) if g["structural"] else None
        pv = None if g["structural"] else g["payload"]
        emit(g["split"], render_request(srng, g["shape"], pv, structural=structural,
                                        category=cat), label, cat, gid=g["gid"])
        # augmentation: training-pool transforms only, same split as the base group
        if not g["structural"] and args.augment_per_group > 0:
            for i in range(args.augment_per_group):
                tname = sorted(TRAIN_TRANSFORMS)[int(g["gid"][8 + i], 16) % len(TRAIN_TRANSFORMS)]
                variant = TRAIN_TRANSFORMS[tname](g["payload"], srng)
                if variant != g["payload"]:
                    emit(g["split"], render_request(srng, g["shape"], variant,
                                                    category=cat), label, cat,
                         gid=g["gid"])

    for g in sorted(bgroups.values(), key=lambda x: x["gid"]):
        srng = random.Random(f"{salt}|{g['gid']}")
        emit(g["split"], render_request(srng, g["shape"], None), ALLOW_LABEL,
             "BENIGN-synthetic", src="synthetic_benign", gid=g["gid"])

    for gid, g in sorted(csic_groups.items()):
        srng = random.Random(f"{salt}|{gid}")
        for rec in g["recs"]:
            if g["label"] == "ALLOW":
                emit(g["split"], render_csic(srng, rec), ALLOW_LABEL, "BENIGN-csic",
                     src="csic_benign", gid=gid)
            else:
                emit(g["split"], render_csic(srng, rec), f"BLOCK | {g['reason']}",
                     "CSIC:" + g["reason"], src="csic_attack", gid=gid)

    print(f"      rendered: train={len(rows['train']):,} eval={len(rows['eval']):,}")

    print("[8/9] Deduplicating + validating...")
    for sp in ("train", "eval"):
        seen, uniq = set(), []
        for r in rows[sp]:
            if r["input"] in seen:
                continue
            seen.add(r["input"])
            uniq.append(r)
        dropped = len(rows[sp]) - len(uniq)
        print(f"      {sp}: dropped {dropped:,} exact duplicates -> {len(uniq):,}")
        rows[sp] = uniq

    tr_in = set(r["input"] for r in rows["train"])
    overlap = [r for r in rows["eval"] if r["input"] in tr_in]
    if overlap:
        rows["eval"] = [r for r in rows["eval"] if r["input"] not in tr_in]
        print(f"      removed {len(overlap):,} cross-split collisions "
              f"(distinct groups rendering to an identical string)")

    all_gids = set()
    for coll in (groups, bgroups, csic_groups):
        for gid, g in coll.items():
            all_gids.add((gid, g["split"]))
    assert len({g for g, _ in all_gids}) == len(all_gids), "INVARIANT VIOLATED: group in both splits"
    for sp in ("train", "eval"):
        for r in rows[sp]:
            first = r["input"].split("\n", 1)[0]
            m = re.match(r"^[A-Z]+ (\S+) HTTP/1\.1$", first)
            assert m, f"INVARIANT VIOLATED: malformed request line: {first[:80]}"
    print("      invariants OK: no shared groups, no malformed request-targets")

    # ── RENDERED-ROW CAP per malicious category ──────────────────────────
    #
    # Applied AFTER valid rendering and deduplication, BEFORE final balancing.
    # Malicious (BLOCK) categories only; benign is never row-capped.
    #
    # Selection method — SOURCE-STRATIFIED, GROUP-PRESERVING ROUND ROBIN:
    #   1. The category's quota is split between the two splits in proportion
    #      to their current row counts, so the train/eval ratio is preserved.
    #   2. Within a split, the quota is divided between SOURCES
    #      (PayloadsAllTheThings/hardcoded vs CSIC) in proportion to their
    #      current row counts, by largest remainder. Neither source is deleted
    #      first, and the natural source mix is preserved.
    #   3. Within a source stratum, rows are taken ROUND ROBIN over logical
    #      groups: one row from every group, then a second from every group,
    #      and so on until the quota is met. This maximises the number of
    #      distinct logical groups that survive, so row capping costs row
    #      REDUNDANCY before it costs logical DIVERSITY.
    #   4. All ordering is by sha256 of content, so selection is deterministic
    #      and independent of iteration order.
    #
    # Nothing is fabricated, nothing is upsampled, no group is moved between
    # splits, and attack semantics are untouched.
    row_cap_report: dict[str, dict] = {}
    if args.row_cap_per_category > 0:
        def _h(r):
            return hashlib.sha256(r["input"].encode()).hexdigest()

        blk_by_cat: dict[str, dict[str, list]] = defaultdict(lambda: {"train": [], "eval": []})
        for sp in ("train", "eval"):
            for r in rows[sp]:
                if r["output"].startswith("BLOCK"):
                    lbl = r["output"].strip()
                    blk_by_cat[lbl][sp].append(r)

        def subsample(pool: list, quota: int) -> list:
            """Round robin over logical groups, within source strata."""
            if len(pool) <= quota:
                return pool
            by_src: dict[str, list] = defaultdict(list)
            for r in pool:
                by_src["csic" if r["_src"] == "csic_attack" else "patt"].append(r)
            # proportional split of the quota, largest remainder
            alloc, rema = {}, []
            for s, rs in by_src.items():
                exact = quota * len(rs) / len(pool)
                alloc[s] = int(exact)
                rema.append((exact - int(exact), s))
            for _, s in sorted(rema, reverse=True)[: quota - sum(alloc.values())]:
                alloc[s] += 1
            out = []
            for s in sorted(by_src):
                rs, q = by_src[s], min(alloc[s], len(by_src[s]))
                by_group: dict[str, list] = defaultdict(list)
                for r in rs:
                    by_group[r["_gid"]].append(r)
                for gid in by_group:
                    by_group[gid].sort(key=_h)
                gids = sorted(by_group)
                picked, depth = [], 0
                while len(picked) < q:
                    added = False
                    for gid in gids:
                        if depth < len(by_group[gid]):
                            picked.append(by_group[gid][depth])
                            added = True
                            if len(picked) >= q:
                                break
                    if not added:
                        break
                    depth += 1
                out.extend(picked)
            return out

        for lbl, splits in sorted(blk_by_cat.items()):
            total = len(splits["train"]) + len(splits["eval"])
            if total <= args.row_cap_per_category:
                continue
            before_groups = len({r["_gid"] for sp in splits for r in splits[sp]})
            before_csic = sum(1 for sp in splits for r in splits[sp]
                              if r["_src"] == "csic_attack")
            keep_ids = set()
            for sp in ("train", "eval"):
                q = round(args.row_cap_per_category * len(splits[sp]) / total)
                for r in subsample(splits[sp], q):
                    keep_ids.add(id(r))
            for sp in ("train", "eval"):
                rows[sp] = [r for r in rows[sp]
                            if not (r["output"].strip() == lbl)
                            or id(r) in keep_ids]
            kept = [r for sp in ("train", "eval") for r in rows[sp]
                    if r["output"].strip() == lbl]
            row_cap_report[lbl] = {
                "rows_before": total, "rows_after": len(kept),
                "rows_removed": total - len(kept),
                "groups_before": before_groups,
                "groups_after": len({r["_gid"] for r in kept}),
                "csic_rows_before": before_csic,
                "csic_rows_after": sum(1 for r in kept if r["_src"] == "csic_attack"),
            }
        if row_cap_report:
            print(f"      row cap = {args.row_cap_per_category} rendered rows/category")
            for lbl in sorted(row_cap_report, key=lambda l: -row_cap_report[l]["rows_removed"]):
                v = row_cap_report[lbl]
                short = lbl[len("BLOCK | "):][:34]
                print(f"        {short:<36} rows {v['rows_before']:>5}->{v['rows_after']:>5} "
                      f"(-{v['rows_removed']:>4})  groups {v['groups_before']:>5}->"
                      f"{v['groups_after']:>5}")

    # Class balance, STRATIFIED BY HTTP METHOD.
    #
    # A global 1:1 trim leaves method predictive whenever the two classes draw
    # from sources with different method mixes — here, CSIC preserves its
    # original (GET/POST-only) methods while synthetic traffic spans all six.
    # Balancing within each method forces P(BLOCK | method) = 0.5 exactly, so
    # method carries no label information, and 1:1 overall follows.
    #
    # Trimming (never duplicating) is the only balancing operation used, per D14.
    for sp in ("train", "eval"):
        by_method = defaultdict(lambda: {"ALLOW": [], "BLOCK": []})
        for r in rows[sp]:
            m = r["input"].split(" ", 1)[0]
            by_method[m][r["output"][:5]].append(r)
        kept, dropped = [], 0
        for m in sorted(by_method):
            a, b = by_method[m]["ALLOW"], by_method[m]["BLOCK"]
            n = min(len(a), len(b))
            for pool in (a, b):
                pool.sort(key=lambda r: hashlib.sha256(r["input"].encode()).hexdigest())
            kept.extend(a[:n] + b[:n])
            dropped += (len(a) - n) + (len(b) - n)
        kept.sort(key=lambda r: hashlib.sha256(r["input"].encode()).hexdigest())
        rows[sp] = kept
        print(f"      {sp} method-stratified 1:1 -> {len(kept):,} rows "
              f"({dropped:,} trimmed across {len(by_method)} methods)")

    print("[9/9] Writing dataset + manifest...")
    os.makedirs(args.out_dir, exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(args.manifest)), exist_ok=True)
    paths = {}
    for sp in ("train", "eval"):
        p = os.path.join(args.out_dir, f"{sp}.jsonl")
        with open(p, "w", encoding="utf-8") as f:
            for r in rows[sp]:
                f.write(json.dumps({k: v for k, v in r.items()
                                    if not k.startswith("_")},
                                   ensure_ascii=False) + "\n")
        paths[sp] = p

    final_cat = Counter()
    for sp in ("train", "eval"):
        for r in rows[sp]:
            o = r["output"].strip()
            final_cat[o] += 1

    group_split = Counter()
    for coll_name, coll in (("attack", groups), ("benign_synthetic", bgroups), ("csic", csic_groups)):
        for g in coll.values():
            group_split[f"{coll_name}:{g['split']}"] += 1

    logical_per_cat = Counter(g["category"] for g in groups.values())
    insufficient = sorted([c for c, n in logical_per_cat.items() if n < 100],
                          key=lambda c: logical_per_cat[c])

    # ── D18 — a category with no held-out evidence is NOT EVALUABLE.
    # Determined from the rendered eval split, not asserted by hand.
    eval_rows_per_reason = Counter()
    for r in rows["eval"]:
        if r["output"].startswith("BLOCK"):
            eval_rows_per_reason[r["output"].strip()] += 1
    train_rows_per_reason = Counter()
    for r in rows["train"]:
        if r["output"].startswith("BLOCK"):
            train_rows_per_reason[r["output"].strip()] += 1
    not_evaluable = sorted(
        lbl for lbl in train_rows_per_reason if eval_rows_per_reason[lbl] == 0
    )

    manifest = {
        "dataset_name": "firewall-IA v4 clean (candidate)",
        "version": "v4-clean-candidate",
        "status": "CANDIDATE — not a validated baseline until E0 passes and it is reviewed",
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "generator": os.path.basename(__file__),
        "generator_git_commit": git_rev(HERE),
        "payloadsallthethings_commit": git_rev(PAYLOADS_REPO),
        "seed": args.seed,
        "eval_fraction_requested": args.eval_fraction,
        "cap_per_category": args.cap_per_category or None,
        "cap_policy_variant": args.cap_policy,
        "cap_policy": (
            "D17: max logical groups per malicious attack category, applied before "
            "HTTP rendering and augmentation. Selection is by sorted group id "
            "(sha256 of the canonical payload) — deterministic and order-independent. "
            "Benign categories are not capped. Scarce categories are never upsampled."
            if args.cap_per_category else "no cap applied"),
        "row_cap_per_category": args.row_cap_per_category or None,
        "row_cap_policy": (
            "D17 FINAL: max rendered BLOCK rows per malicious category, applied after "
            "rendering/dedup and before final balancing. Selection is deterministic, "
            "source-stratified (proportional by largest remainder), and breadth-first "
            "(one row per logical group before any second row), so it removes redundant "
            "renderings before logical diversity. Hard floor: row cap >= group cap."
            if args.row_cap_per_category else "no rendered-row cap applied"),
        "row_cap_effect": row_cap_report,
        "capped_categories": cap_report,
        "logical_groups_per_category_before_cap": dict(groups_before_cap),
        "augment_per_group": args.augment_per_group,
        "source_counts": {
            "patt_candidates_scanned": int(sum(stats["candidates_per_category"].values())),
            "patt_accepted_after_filter": len(patt),
            "hardcoded_logical": len(hardcoded),
            "attack_groups_unique": len(groups),
            "csic_normal_records": len(csic_normal),
            "csic_anomalous_categorized": len(csic_anom),
            "CSIC_ANOMALOUS_RESERVED": stats["CSIC_ANOMALOUS_RESERVED"],
            "csic_malformed_skipped": stats["csic_malformed"],
            "csic_groups": len(csic_groups),
            "synthetic_benign_groups": len(bgroups),
        },
        "rejection_reasons": dict(stats["reject_reasons"]),
        "candidates_per_category": dict(stats["candidates_per_category"]),
        "logical_groups_per_category": dict(logical_per_cat),
        "group_split_counts": dict(group_split),
        "final_rows": {"train": len(rows["train"]), "eval": len(rows["eval"]),
                       "total": len(rows["train"]) + len(rows["eval"])},
        "achieved_eval_ratio": round(len(rows["eval"]) / max(1, len(rows["train"]) + len(rows["eval"])), 4),
        "label_counts": {
            "ALLOW": sum(1 for sp in rows for r in rows[sp] if r["output"].startswith("ALLOW")),
            "BLOCK": sum(1 for sp in rows for r in rows[sp] if r["output"].startswith("BLOCK")),
        },
        "final_category_counts": dict(final_cat),
        "insufficient_data_categories": {c: logical_per_cat[c] for c in insufficient},
        "not_evaluable_categories": {
            lbl: {"train_rows": train_rows_per_reason[lbl], "eval_rows": 0,
                  "policy": "D18: INSUFFICIENT DATA / NOT EVALUABLE — no category-level "
                            "accuracy, recall, or other performance claim may be made."}
            for lbl in not_evaluable},
        "transform_pools": {
            "train_pool_used": sorted(TRAIN_TRANSFORMS),
            "held_out_never_used_in_this_dataset": HELD_OUT_TRANSFORMS,
        },
        "causal_envelope_exceptions": CAUSAL_EXCEPTIONS,
        "artifact_sha256": {sp: sha256_file(paths[sp]) for sp in ("train", "eval")},
        "artifact_bytes": {sp: os.path.getsize(paths[sp]) for sp in ("train", "eval")},
        "known_limitations": [
            "CANDIDATE dataset. Not a validated baseline until check_dataset.py passes "
            "and the dataset is reviewed.",
            "CSIC BLOCK labels are assigned by an 11-rule keyword heuristic (audit F6). "
            "Any future rule-vs-AI comparison on this subset would be circular.",
            "Categories listed under not_evaluable_categories have ZERO held-out eval "
            "rows and are NOT EVALUABLE (D18). No performance claim may be made for them.",
            "Categories listed under insufficient_data_categories have too few unique "
            "logical samples to support a per-category performance claim.",
            "Held-out transforms were used to generate NOTHING here; obfuscation "
            "robustness against them is therefore unmeasured by design (D15).",
            "Labels terminate via native EOS (D5/E4); no custom stop token is used.",
            "Synthetic benign traffic is generated, not captured. Its realism is bounded "
            "by the parameter pools in this file.",
        ],
    }
    with open(args.manifest, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    # Optional side-car statistics with source attribution, for the cap
    # sensitivity analysis. Derived from the FINAL rows (post dedup, post
    # method-stratified balancing), so it reflects what actually ships.
    if args.stats_json:
        cat_rows = defaultdict(lambda: {"train": 0, "eval": 0,
                                        "attack": 0, "csic_attack": 0})
        cat_groups = defaultdict(set)
        for sp in ("train", "eval"):
            for r in rows[sp]:
                if not r["output"].startswith("BLOCK"):
                    continue
                lbl = r["output"].strip()
                cat = REASON_TO_CATEGORY.get(lbl[len("BLOCK | "):], lbl)
                cat_rows[cat][sp] += 1
                cat_rows[cat][r["_src"] if r["_src"] in ("csic_attack",) else "attack"] += 1
                cat_groups[cat].add(r["_gid"])
        total_block = sum(v["train"] + v["eval"] for v in cat_rows.values())
        stats_out = {
            "scenario": {"cap": args.cap_per_category, "policy": args.cap_policy,
                         "row_cap": args.row_cap_per_category or None},
            "row_cap_report": row_cap_report,
            "rows": {"train": len(rows["train"]), "eval": len(rows["eval"]),
                     "total": len(rows["train"]) + len(rows["eval"])},
            "labels": manifest["label_counts"],
            "logical_groups_per_category": dict(logical_per_cat),
            "logical_groups_before_cap": dict(groups_before_cap),
            "capped_categories": cap_report,
            "csic_groups_remaining": len(csic_groups),
            "block_rows_per_category": {
                c: {"total": v["train"] + v["eval"], "train": v["train"], "eval": v["eval"],
                    "from_patt_hardcoded": v["attack"], "from_csic": v["csic_attack"],
                    "groups_represented": len(cat_groups[c]),
                    "pct_of_block": round(100 * (v["train"] + v["eval"]) / max(1, total_block), 3)}
                for c, v in sorted(cat_rows.items(), key=lambda kv: -(kv[1]["train"] + kv[1]["eval"]))},
            "total_block_rows": total_block,
            "csic_rows_retained": {
                "block": sum(1 for sp in ("train", "eval") for r in rows[sp]
                             if r["_src"] == "csic_attack"),
                "benign": sum(1 for sp in ("train", "eval") for r in rows[sp]
                              if r["_src"] == "csic_benign")},
            "insufficient_data_categories": {c: logical_per_cat[c] for c in insufficient},
            "not_evaluable_categories": sorted(not_evaluable),
        }
        os.makedirs(os.path.dirname(os.path.abspath(args.stats_json)), exist_ok=True)
        with open(args.stats_json, "w", encoding="utf-8") as f:
            json.dump(stats_out, f, indent=2, ensure_ascii=False)

    print(f"\n  train : {paths['train']}  ({len(rows['train']):,} rows)")
    print(f"  eval  : {paths['eval']}  ({len(rows['eval']):,} rows)")
    print(f"  manifest: {args.manifest}")
    print(f"\n  achieved eval ratio: {manifest['achieved_eval_ratio']:.4f} "
          f"(requested {args.eval_fraction})")
    if insufficient:
        print("\n  INSUFFICIENT DATA (unique logical groups < 100):")
        for c in insufficient:
            print(f"    {logical_per_cat[c]:>6}  {c}")
    if not_evaluable:
        print("\n  NOT EVALUABLE (D18 — zero held-out eval rows):")
        for lbl in not_evaluable:
            print(f"    train={train_rows_per_reason[lbl]:>4} eval=0   {lbl}")
    print("\n  Next: python3.12 check_dataset.py --train "
          f"{paths['train']} --eval {paths['eval']}")


if __name__ == "__main__":
    main()
