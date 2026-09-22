import os
import re
import json
import random

# ── Configuración ──────────────────────────────────────────────
PAYLOADS_REPO   = os.path.expanduser("~/PayloadsAllTheThings")
OUTPUT_TRAIN    = os.path.expanduser("~/Desktop/firewall-IA/train.jsonl")
OUTPUT_EVAL     = os.path.expanduser("~/Desktop/firewall-IA/eval.jsonl")
CSIC_PATH       = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "csic_database.csv")  # repo root
EVAL_SPLIT          = 0.2
RANDOM_SEED         = 42
OBFUSCATION_TARGET  = 2000   # nº de BLOCK obfuscados a generar (ALLOW se balancea igual)
HARDCODED_WRAPS     = 8      # nº de HTTP wrappers por payload en categorías hardcodeadas

INSTRUCTION = (
    "You are a network security firewall classifier. "
    "Analyze the following HTTP request and respond with exactly: "
    "ALLOW or BLOCK | <one sentence reason>. Then output ###END###"
)

# ── Categorías a parsear ────────────────────────────────────────
CATEGORIES = {
    "SQL Injection":                  "BLOCK | SQL injection payload detected.",
    "XSS Injection":                  "BLOCK | Cross-site scripting payload detected.",
    "Directory Traversal":                 "BLOCK | Path traversal attack detected.",
    "Command Injection":              "BLOCK | Command injection payload detected.",
    "LDAP Injection":                 "BLOCK | LDAP injection payload detected.",
    "XXE Injection":                  "BLOCK | XML external entity injection detected.",
    "Cross-Site Request Forgery":                 "BLOCK | CSRF attack pattern detected.",
    "Open Redirect":                  "BLOCK | Open redirect payload detected.",
    "Server Side Request Forgery":    "BLOCK | Server-side request forgery attack detected.",
    "JSON Web Token":                 "BLOCK | JWT token manipulation attack detected.",
    "GraphQL Injection":              "BLOCK | GraphQL injection payload detected.",
    "NoSQL Injection":                "BLOCK | NoSQL injection payload detected.",
    "Server Side Template Injection": "BLOCK | Server-side template injection payload detected.",
    "File Inclusion":                 "BLOCK | File inclusion attack detected.",
    "Insecure Deserialization":       "BLOCK | Insecure deserialization payload detected.",
    "Request Smuggling":              "BLOCK | HTTP request smuggling attack detected.",
}

# ── Payloads hardcodeados — categorías fuera de PayloadsAllTheThings ──

CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:%20session=hijacked",
    "%0d%0aSet-Cookie:%20admin=true",
    "%0d%0aLocation:%20https://evil.com",
    "%0aLocation:%20https://evil.com",
    "%0d%0aX-Injected:%20header",
    "%0d%0aContent-Type:%20text/html",
    "%0d%0aContent-Length:%200",
    "%0aContent-Type:%20text/html%0a%0a<html>injected</html>",
    "value%0d%0aSet-Cookie:%20session=hijacked",
    "value%0d%0aX-Frame-Options:%20ALLOW",
    "%0d%0aHTTP/1.1%20200%20OK",
    "value%0d%0aHTTP/1.1%20302%20Found%0d%0aLocation:%20https://evil.com",
    "test%0d%0aSet-Cookie:%20access=admin;%20HttpOnly",
    "%0d%0aRefresh:%200;url=https://phishing.com",
    "a%0aSet-Cookie:%20token=stolen",
    "%0d%0aAccess-Control-Allow-Origin:%20*",
    "value%0d%0aX-XSS-Protection:%200",
    "test%0d%0aContent-Security-Policy:%20default-src%20*",
    "foo%0d%0a%0d%0a<html><script>alert(1)</script></html>",
    "%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>",
    "value%250d%250aSet-Cookie:%20session%3Dhijacked",
    "%E5%98%8D%E5%98%8ASet-Cookie:%20injected=true",
    "%00%0d%0aSet-Cookie:%20admin=true",
    "next%3D%250d%250aSet-Cookie%3A%20session%3Dhijacked",
    "value\r\nSet-Cookie: injected=true",
    "value\nSet-Cookie: injected=true",
    "value\r\nLocation: https://evil.com",
    "https://example.com%0d%0aSet-Cookie:%20csrftoken=bypassed",
    "https://example.com%0aSet-Cookie:%20session=stolen",
    "value%0d%0aTransfer-Encoding:%20chunked",
]

HPP_PARAMS_VALUES = [
    ("id",         ["1", "2", "99999"]),
    ("role",       ["user", "admin"]),
    ("role",       ["viewer", "admin", "superadmin"]),
    ("action",     ["view", "delete", "drop"]),
    ("status",     ["active", "inactive", "deleted"]),
    ("permission", ["read", "write", "execute"]),
    ("access",     ["public", "internal", "private"]),
    ("type",       ["user", "admin", "system"]),
    ("group",      ["users", "admins"]),
    ("level",      ["1", "5", "99"]),
    ("user",       ["bob", "admin"]),
    ("flag",       ["0", "1", "true"]),
    ("override",   ["false", "true"]),
    ("priority",   ["low", "high", "critical"]),
    ("scope",      ["self", "all"]),
    ("mode",       ["read", "write", "admin"]),
    ("filter",     ["none", "bypass"]),
    ("cmd",        ["view", "delete", "exec"]),
    ("page",       ["1", "99", "-1"]),
    ("token",      ["abc", "admin_token"]),
]

HPP_PATHS = [
    "/api/users", "/search", "/api/filter", "/api/access",
    "/admin/query", "/api/order", "/api/data", "/api/settings",
    "/api/roles", "/api/permissions",
]

XPATH_PAYLOADS = [
    "' or '1'='1",
    "' or '1'='1' --",
    "x' or name()='username' or 'x'='y",
    "') or ('1'='1",
    "admin' or 1=1 or 'x'='x",
    "' or 1=1 and '1'='1",
    "' or ''='",
    "x' or 'x'='x",
    "') or '1'='1' or ('x'='x",
    "' or position()=1 or '",
    "admin']%00",
    "' or string-length(name())>0 or '",
    "' or count(/*)>0 or '",
    "a' or 'a'='a",
    "' or 'x'='x",
    "') or ('a'='a",
    "x'; SELECT * FROM users; --",
    "' or position()>0 or '",
    "admin' or '1",
    "'] | //user/*[contains(*,'",
    "x' or true() or 'x'='y",
    "' or local-name()='admin' or 'x'='y",
    "admin'/*",
    "' or name()!='x' or '",
    "'] | //*[contains(.,",
    "' or //*[@name]",
    "') or 1=1 or ('",
    "x' or string(//user/password)!='",
    "'  or  '1'  =  '1",
    "admin' or '1'='1",
    "' or count(/root/*)=1 or '",
    "'or'1'='1",
    "' or starts-with(name(), 'admin') or '",
    "x')] | //user[contains(@name,'a",
    "' or substring(password,1,1)='a",
]

# ── Tráfico legítimo sintético ──────────────────────────────────
LEGIT_REQUESTS = [
    # ── REST API — GET resources ───────────────────────────────
    "GET /api/users HTTP/1.1\nHost: api.example.com",
    "GET /api/users/123 HTTP/1.1\nHost: api.example.com",
    "GET /api/users/456/profile HTTP/1.1\nHost: api.example.com",
    "GET /api/products HTTP/1.1\nHost: api.shop.com",
    "GET /api/products/789 HTTP/1.1\nHost: api.shop.com",
    "GET /api/products/789/reviews HTTP/1.1\nHost: api.shop.com",
    "GET /api/orders HTTP/1.1\nHost: api.shop.com",
    "GET /api/orders/ORD-20240312-001 HTTP/1.1\nHost: api.shop.com",
    "GET /api/invoices/INV-9921 HTTP/1.1\nHost: billing.example.com",
    "GET /api/teams/42/members HTTP/1.1\nHost: api.company.com",
    "GET /api/projects/15/tasks HTTP/1.1\nHost: api.pm.com",
    "GET /api/comments/thread/88 HTTP/1.1\nHost: api.forum.com",
    "GET /api/notifications HTTP/1.1\nHost: api.app.com",
    "GET /api/settings/preferences HTTP/1.1\nHost: api.app.com",
    "GET /api/dashboard/summary HTTP/1.1\nHost: analytics.example.com",
    "GET /api/reports/monthly HTTP/1.1\nHost: analytics.example.com",
    "GET /api/categories HTTP/1.1\nHost: api.shop.com",
    "GET /api/tags HTTP/1.1\nHost: api.blog.com",
    "GET /api/config HTTP/1.1\nHost: api.app.com",
    "GET /api/health HTTP/1.1\nHost: api.example.com",
    "GET /api/version HTTP/1.1\nHost: api.example.com",
    # ── REST API — POST create ─────────────────────────────────
    "POST /api/users HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"name\":\"Alice Smith\",\"email\":\"alice@example.com\",\"role\":\"viewer\"}",
    "POST /api/orders HTTP/1.1\nHost: api.shop.com\nContent-Type: application/json\n\n{\"product_id\":42,\"quantity\":3,\"shipping_address\":\"123 Main St\"}",
    "POST /api/comments HTTP/1.1\nHost: api.forum.com\nContent-Type: application/json\n\n{\"post_id\":7,\"body\":\"Great article, thanks for sharing!\"}",
    "POST /api/sessions HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"username\":\"bob\",\"password\":\"hunter2\"}",
    "POST /api/payments HTTP/1.1\nHost: billing.example.com\nContent-Type: application/json\n\n{\"amount\":4999,\"currency\":\"USD\",\"method\":\"card\",\"token\":\"tok_visa\"}",
    "POST /api/subscriptions HTTP/1.1\nHost: api.saas.com\nContent-Type: application/json\n\n{\"plan\":\"pro\",\"billing_cycle\":\"monthly\",\"seats\":5}",
    "POST /api/tickets HTTP/1.1\nHost: support.example.com\nContent-Type: application/json\n\n{\"subject\":\"Cannot access my account\",\"priority\":\"medium\",\"category\":\"auth\"}",
    "POST /api/events HTTP/1.1\nHost: api.calendar.com\nContent-Type: application/json\n\n{\"title\":\"Team standup\",\"start\":\"2024-04-01T09:00:00Z\",\"duration\":30}",
    "POST /api/files/upload HTTP/1.1\nHost: api.storage.com\nContent-Type: multipart/form-data; boundary=----WebKitFormBoundary\n\n----WebKitFormBoundary\nContent-Disposition: form-data; name=\"file\"; filename=\"report.pdf\"",
    "POST /api/feedback HTTP/1.1\nHost: api.app.com\nContent-Type: application/json\n\n{\"rating\":4,\"comment\":\"Works well, minor UI issues\",\"page\":\"/dashboard\"}",
    # ── REST API — PUT/PATCH update ────────────────────────────
    "PUT /api/users/42 HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"email\":\"newemail@example.com\",\"phone\":\"+1-555-0100\"}",
    "PUT /api/products/99 HTTP/1.1\nHost: api.shop.com\nContent-Type: application/json\n\n{\"price\":29.99,\"stock\":150,\"visible\":true}",
    "PATCH /api/orders/ORD-20240312-001 HTTP/1.1\nHost: api.shop.com\nContent-Type: application/json\n\n{\"status\":\"shipped\",\"tracking_number\":\"1Z999AA10123456784\"}",
    "PATCH /api/users/7/settings HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"notifications\":true,\"theme\":\"dark\",\"language\":\"en\"}",
    "PATCH /api/tasks/55 HTTP/1.1\nHost: api.pm.com\nContent-Type: application/json\n\n{\"status\":\"done\",\"completed_at\":\"2024-04-02T14:30:00Z\"}",
    # ── REST API — DELETE ──────────────────────────────────────
    "DELETE /api/users/99 HTTP/1.1\nHost: api.example.com",
    "DELETE /api/sessions/current HTTP/1.1\nHost: api.example.com",
    "DELETE /api/cart/items/3 HTTP/1.1\nHost: api.shop.com",
    "DELETE /api/notifications/read HTTP/1.1\nHost: api.app.com",
    # ── Pagination, sorting, filtering ────────────────────────
    "GET /api/products?page=1&limit=20 HTTP/1.1\nHost: api.shop.com",
    "GET /api/products?page=3&per_page=50&sort=price&order=asc HTTP/1.1\nHost: api.shop.com",
    "GET /api/users?page=2&limit=10&sort=created_at&direction=desc HTTP/1.1\nHost: api.example.com",
    "GET /api/orders?status=delivered&from=2024-01-01&to=2024-03-31 HTTP/1.1\nHost: api.shop.com",
    "GET /api/logs?level=error&limit=100&offset=200 HTTP/1.1\nHost: api.example.com",
    "GET /api/products?category=electronics&brand=sony&min_price=100&max_price=500 HTTP/1.1\nHost: api.shop.com",
    "GET /api/users?role=editor&active=true&department=marketing HTTP/1.1\nHost: api.example.com",
    "GET /api/transactions?type=credit&currency=USD&page=1&limit=25 HTTP/1.1\nHost: billing.example.com",
    "GET /api/articles?tag=python&published=true&sort=views&order=desc HTTP/1.1\nHost: api.blog.com",
    "GET /api/events?start=2024-04-01&end=2024-04-30&calendar=work HTTP/1.1\nHost: api.calendar.com",
    # ── Search queries with innocent keywords ──────────────────
    "GET /search?q=how+to+drop+weight+naturally HTTP/1.1\nHost: health.example.com",
    "GET /search?q=union+workers+rights+2024 HTTP/1.1\nHost: news.example.com",
    "GET /search?q=select+the+best+laptop+for+students HTTP/1.1\nHost: shop.example.com",
    "GET /search?q=where+to+buy+organic+coffee HTTP/1.1\nHost: search.example.com",
    "GET /search?q=script+writing+tips+for+beginners HTTP/1.1\nHost: learn.example.com",
    "GET /search?q=table+of+contents+template HTTP/1.1\nHost: docs.example.com",
    "GET /search?q=delete+old+photos+from+icloud HTTP/1.1\nHost: support.apple.example.com",
    "GET /search?q=insert+coin+arcade+game HTTP/1.1\nHost: games.example.com",
    "GET /search?q=executive+OR+manager+job+opening HTTP/1.1\nHost: jobs.example.com",
    "GET /search?q=join+our+community+forum HTTP/1.1\nHost: community.example.com",
    "GET /search?q=update+your+browser HTTP/1.1\nHost: support.example.com",
    "GET /search?q=where+clause+in+excel+formulas HTTP/1.1\nHost: docs.example.com",
    "GET /api/search?q=select+your+subscription+plan HTTP/1.1\nHost: app.saas.com",
    "GET /api/search?q=drop-down+menu+component HTTP/1.1\nHost: ui.example.com",
    "GET /api/search?q=inner+join+yoga+classes HTTP/1.1\nHost: fitness.example.com",
    # ── Static assets ──────────────────────────────────────────
    "GET /index.html HTTP/1.1\nHost: example.com",
    "GET /about.html HTTP/1.1\nHost: example.com",
    "GET /favicon.ico HTTP/1.1\nHost: example.com",
    "GET /robots.txt HTTP/1.1\nHost: example.com",
    "GET /sitemap.xml HTTP/1.1\nHost: example.com",
    "GET /assets/css/main.css HTTP/1.1\nHost: example.com",
    "GET /assets/js/bundle.js HTTP/1.1\nHost: example.com",
    "GET /images/logo.png HTTP/1.1\nHost: example.com",
    "GET /images/hero-banner.jpg HTTP/1.1\nHost: shop.com",
    "GET /fonts/roboto-regular.woff2 HTTP/1.1\nHost: cdn.example.com",
    "GET /static/media/intro-video.mp4 HTTP/1.1\nHost: cdn.example.com",
    "GET /docs/setup.html HTTP/1.1\nHost: docs.example.com",
    "GET /docs/api-reference.html HTTP/1.1\nHost: docs.example.com",
    "GET /changelog HTTP/1.1\nHost: docs.example.com",
    "GET /privacy-policy HTTP/1.1\nHost: example.com",
    "GET /terms-of-service HTTP/1.1\nHost: example.com",
    # ── Authentication and auth flows ──────────────────────────
    "POST /oauth/token HTTP/1.1\nHost: auth.example.com\nContent-Type: application/x-www-form-urlencoded\n\ngrant_type=authorization_code&code=abc123&redirect_uri=https://app.example.com/callback",
    "POST /oauth/token HTTP/1.1\nHost: auth.example.com\nContent-Type: application/x-www-form-urlencoded\n\ngrant_type=refresh_token&refresh_token=def456&client_id=myapp",
    "GET /oauth/authorize?response_type=code&client_id=myapp&scope=openid+email&state=xyz HTTP/1.1\nHost: auth.example.com",
    "POST /auth/logout HTTP/1.1\nHost: app.example.com\nAuthorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEyMyIsImV4cCI6MTcwMDAwMDAwMH0.valid_signature",
    "GET /api/me HTTP/1.1\nHost: api.example.com\nAuthorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEyMyIsImV4cCI6MTcwMDAwMDAwMH0.valid_signature",
    "GET /api/profile HTTP/1.1\nHost: api.example.com\nAuthorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzQ1NiIsImV4cCI6MTcwMDAwMDAwMH0.valid_sig2",
    "GET /api/data HTTP/1.1\nHost: api.example.com\nX-API-Key: sk_live_abcdef1234567890abcdef1234567890",
    "GET /api/reports HTTP/1.1\nHost: analytics.example.com\nX-API-Key: ak_prod_9f8e7d6c5b4a3210fedcba9876543210",
    "POST /api/verify-email HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"token\":\"verify_abc123def456\",\"user_id\":789}",
    "POST /api/reset-password HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"reset_token\":\"rst_xyz789\",\"new_password\":\"myNewSecurePass!\"}",
    "POST /api/2fa/verify HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"code\":\"847291\",\"backup\":false}",
    # ── Admin panel legitimate requests ────────────────────────
    "GET /admin/dashboard HTTP/1.1\nHost: app.example.com\nAuthorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.admin_valid_sig",
    "GET /admin/users?page=1&limit=50 HTTP/1.1\nHost: app.example.com",
    "GET /admin/users/42/activity HTTP/1.1\nHost: app.example.com",
    "POST /admin/users/42/suspend HTTP/1.1\nHost: app.example.com\nContent-Type: application/json\n\n{\"reason\":\"Violated terms of service\",\"duration\":\"7d\"}",
    "DELETE /admin/users/99/sessions HTTP/1.1\nHost: app.example.com",
    "GET /admin/orders?status=pending&page=1 HTTP/1.1\nHost: shop.example.com",
    "PATCH /admin/products/55 HTTP/1.1\nHost: shop.example.com\nContent-Type: application/json\n\n{\"featured\":true,\"category\":\"electronics\"}",
    "GET /admin/reports/revenue?period=monthly&year=2024 HTTP/1.1\nHost: analytics.example.com",
    "POST /admin/coupons HTTP/1.1\nHost: shop.example.com\nContent-Type: application/json\n\n{\"code\":\"SAVE20\",\"discount\":20,\"type\":\"percent\",\"expires\":\"2024-12-31\"}",
    "PUT /admin/settings/email HTTP/1.1\nHost: app.example.com\nContent-Type: application/json\n\n{\"smtp_host\":\"mail.example.com\",\"port\":587,\"tls\":true}",
    "GET /admin/audit-log?action=delete&from=2024-03-01 HTTP/1.1\nHost: app.example.com",
    "POST /admin/roles HTTP/1.1\nHost: app.example.com\nContent-Type: application/json\n\n{\"name\":\"content-editor\",\"permissions\":[\"posts:read\",\"posts:write\"]}",
    # ── File operations ────────────────────────────────────────
    "POST /api/files HTTP/1.1\nHost: storage.example.com\nContent-Type: multipart/form-data; boundary=----Boundary\n\n----Boundary\nContent-Disposition: form-data; name=\"file\"; filename=\"avatar.jpg\"\nContent-Type: image/jpeg",
    "POST /api/files HTTP/1.1\nHost: storage.example.com\nContent-Type: multipart/form-data; boundary=----Boundary\n\n----Boundary\nContent-Disposition: form-data; name=\"file\"; filename=\"document.pdf\"\nContent-Type: application/pdf",
    "GET /api/files/d41d8cd98f00b204e9800998ecf8427e HTTP/1.1\nHost: storage.example.com",
    "GET /api/files/d41d8cd98f00b204e9800998ecf8427e/download HTTP/1.1\nHost: storage.example.com",
    "DELETE /api/files/abc123def456 HTTP/1.1\nHost: storage.example.com",
    "GET /cdn/uploads/2024/03/profile-photo.jpg HTTP/1.1\nHost: cdn.example.com",
    "GET /cdn/uploads/2024/01/product-image-1.webp HTTP/1.1\nHost: cdn.example.com",
    "PUT /api/files/abc123def456/metadata HTTP/1.1\nHost: storage.example.com\nContent-Type: application/json\n\n{\"name\":\"final-report-v2.pdf\",\"public\":false}",
    # ── Webhooks and callbacks ─────────────────────────────────
    "POST /webhooks/stripe HTTP/1.1\nHost: app.example.com\nStripe-Signature: t=1680000000,v1=abc123def456\nContent-Type: application/json\n\n{\"type\":\"payment_intent.succeeded\",\"data\":{\"object\":{\"amount\":4999}}}",
    "POST /webhooks/github HTTP/1.1\nHost: ci.example.com\nX-GitHub-Event: push\nX-Hub-Signature-256: sha256=abc123\nContent-Type: application/json\n\n{\"ref\":\"refs/heads/main\",\"repository\":{\"full_name\":\"org/repo\"}}",
    "POST /webhooks/sendgrid HTTP/1.1\nHost: app.example.com\nContent-Type: application/json\n\n[{\"event\":\"delivered\",\"email\":\"user@example.com\",\"timestamp\":1680000000}]",
    "GET /oauth/callback?code=authcode_abc123&state=csrf_xyz789 HTTP/1.1\nHost: app.example.com",
    "POST /webhooks/twilio HTTP/1.1\nHost: app.example.com\nContent-Type: application/x-www-form-urlencoded\n\nMessageSid=SM123&From=%2B15005550006&Body=Hello+world",
    "POST /webhooks/slack HTTP/1.1\nHost: app.example.com\nContent-Type: application/json\n\n{\"type\":\"url_verification\",\"challenge\":\"3eZbrw1aBm2rZgRNFdxV2595E9CY3gmdALWMmHkvFXO7tYXAYM8P\"}",
    # ── Mobile app traffic ─────────────────────────────────────
    "GET /api/feed?page=1&limit=20 HTTP/1.1\nHost: api.app.com\nUser-Agent: MyApp/2.3.1 (iPhone; iOS 17.2; Scale/3.00)\nAccept: application/json",
    "POST /api/sessions HTTP/1.1\nHost: api.app.com\nUser-Agent: MyApp/2.3.1 (Android 14; Pixel 8)\nContent-Type: application/json\n\n{\"device_id\":\"uuid-1234-5678\",\"push_token\":\"fcm_token_abc\"}",
    "GET /api/products/featured?lat=37.7749&lon=-122.4194&radius=10 HTTP/1.1\nHost: api.app.com\nUser-Agent: ShopApp/1.0 (iPhone; iOS 16.5)",
    "PATCH /api/users/me HTTP/1.1\nHost: api.app.com\nUser-Agent: MyApp/3.1.0 (Android 13; Samsung Galaxy S23)\nContent-Type: application/json\n\n{\"push_notifications\":true,\"location_sharing\":false}",
    "POST /api/analytics/events HTTP/1.1\nHost: api.app.com\nUser-Agent: MyApp/2.3.1 (iPhone; iOS 17.2)\nContent-Type: application/json\n\n{\"event\":\"screen_view\",\"screen\":\"home\",\"session_id\":\"sess_abc\"}",
    "GET /api/sync?last_sync=1680000000&device_id=uuid-9876 HTTP/1.1\nHost: api.app.com\nUser-Agent: MyApp/2.0.0 (Android 12; OnePlus 9)",
    "GET /api/config/remote?platform=ios&version=2.3.1 HTTP/1.1\nHost: api.app.com\nUser-Agent: MyApp/2.3.1 (iPhone; iOS 17.2)",
    # ── GraphQL legitimate queries ─────────────────────────────
    "POST /graphql HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"query\":\"{ user(id: \\\"123\\\") { id name email createdAt } }\"}",
    "POST /graphql HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"query\":\"{ products(category: \\\"electronics\\\", limit: 10) { id name price stock } }\"}",
    "POST /graphql HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"query\":\"mutation { updateUser(id: \\\"42\\\", input: { name: \\\"Alice\\\", email: \\\"alice@example.com\\\" }) { id name } }\"}",
    "POST /graphql HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"query\":\"{ orders(userId: \\\"99\\\", status: \\\"shipped\\\") { id total trackingNumber } }\"}",
    "POST /graphql HTTP/1.1\nHost: api.shop.com\nContent-Type: application/json\n\n{\"query\":\"{ cart(sessionId: \\\"sess_abc123\\\") { items { productId quantity price } total } }\"}",
    # ── JSON bodies — nested objects and arrays ────────────────
    "POST /api/orders/bulk HTTP/1.1\nHost: api.shop.com\nContent-Type: application/json\n\n{\"orders\":[{\"product_id\":1,\"qty\":2},{\"product_id\":5,\"qty\":1},{\"product_id\":9,\"qty\":3}]}",
    "PUT /api/users/42/permissions HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"permissions\":{\"reports\":[\"read\",\"export\"],\"users\":[\"read\"],\"billing\":[\"read\",\"write\"]}}",
    "POST /api/notifications/send HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"recipients\":[\"user1@example.com\",\"user2@example.com\"],\"subject\":\"Weekly report\",\"template\":\"weekly_summary\",\"data\":{\"week\":14,\"year\":2024}}",
    "POST /api/import/csv HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"mapping\":{\"column_0\":\"name\",\"column_1\":\"email\",\"column_2\":\"role\"},\"skip_header\":true,\"delimiter\":\",\"}",
    "PUT /api/pipeline/stages HTTP/1.1\nHost: api.crm.com\nContent-Type: application/json\n\n{\"stages\":[{\"name\":\"Lead\",\"order\":1},{\"name\":\"Qualified\",\"order\":2},{\"name\":\"Closed\",\"order\":3}]}",
    "POST /api/surveys/submit HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"survey_id\":77,\"responses\":[{\"question_id\":1,\"answer\":5},{\"question_id\":2,\"answer\":\"Very satisfied\"}]}",
    # ── Miscellaneous common endpoints ────────────────────────
    "GET /api/status HTTP/1.1\nHost: api.example.com",
    "GET /api/ping HTTP/1.1\nHost: api.example.com",
    "GET /health HTTP/1.1\nHost: api.example.com",
    "GET /metrics HTTP/1.1\nHost: monitoring.example.com",
    "POST /contact HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{\"name\":\"Bob Jones\",\"email\":\"bob@example.com\",\"message\":\"I need help with my account\"}",
    "POST /api/newsletter/subscribe HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"email\":\"user@example.com\",\"lists\":[\"weekly\",\"product-updates\"]}",
    "POST /api/newsletter/unsubscribe HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"email\":\"user@example.com\",\"reason\":\"Too many emails\"}",
    "GET /api/countries HTTP/1.1\nHost: api.example.com",
    "GET /api/timezones HTTP/1.1\nHost: api.example.com",
    "GET /api/currencies HTTP/1.1\nHost: api.example.com",
    "GET /api/languages HTTP/1.1\nHost: api.example.com",
    "GET /blog/post/getting-started-with-kubernetes HTTP/1.1\nHost: blog.example.com",
    "GET /blog/post/how-to-select-a-database-for-your-app HTTP/1.1\nHost: blog.example.com",
    "GET /blog/post/union-types-in-typescript-explained HTTP/1.1\nHost: blog.example.com",
    "GET /blog/post/drop-shipping-vs-retail-compared HTTP/1.1\nHost: blog.example.com",
    "GET /blog/post/scripting-automations-with-python HTTP/1.1\nHost: blog.example.com",
    "GET /blog/post/where-to-host-your-next-project HTTP/1.1\nHost: blog.example.com",
    "GET /ui/dropdown?action=drop&item=table HTTP/1.1\nHost: app.example.com",
    "POST /api/tables/create HTTP/1.1\nHost: db-gui.example.com\nContent-Type: application/json\n\n{\"name\":\"customer_events\",\"columns\":[{\"name\":\"id\",\"type\":\"uuid\"},{\"name\":\"event\",\"type\":\"text\"}]}",
    "GET /api/tables HTTP/1.1\nHost: db-gui.example.com",
    "GET /api/tables/users/columns HTTP/1.1\nHost: db-gui.example.com",
    "POST /api/export HTTP/1.1\nHost: app.example.com\nContent-Type: application/json\n\n{\"format\":\"csv\",\"table\":\"orders\",\"filters\":{\"status\":\"completed\"}}",
    "GET /api/scripts HTTP/1.1\nHost: automation.example.com",
    "GET /api/scripts/45/runs HTTP/1.1\nHost: automation.example.com",
    "POST /api/scripts/45/run HTTP/1.1\nHost: automation.example.com\nContent-Type: application/json\n\n{\"parameters\":{\"env\":\"staging\",\"dry_run\":true}}",
    "GET /api/jobs?status=completed&page=1 HTTP/1.1\nHost: api.example.com",
    "GET /api/queue/pending HTTP/1.1\nHost: api.example.com",
    "POST /api/cache/invalidate HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"keys\":[\"product:123\",\"product:456\"]}",
    "GET /api/features HTTP/1.1\nHost: api.example.com",
    "GET /api/changelog HTTP/1.1\nHost: api.example.com",
    "GET /api/plans HTTP/1.1\nHost: billing.example.com",
    "POST /api/checkout HTTP/1.1\nHost: shop.example.com\nContent-Type: application/json\n\n{\"cart_id\":\"cart_abc123\",\"coupon\":\"SAVE10\",\"payment_method\":\"stripe\"}",
    "GET /api/cart HTTP/1.1\nHost: shop.example.com",
    "POST /api/cart/items HTTP/1.1\nHost: shop.example.com\nContent-Type: application/json\n\n{\"product_id\":42,\"variant_id\":\"color-blue-size-m\",\"quantity\":1}",
    "DELETE /api/cart/items/42 HTTP/1.1\nHost: shop.example.com",
    "GET /api/wishlist HTTP/1.1\nHost: shop.example.com",
    "POST /api/wishlist/items HTTP/1.1\nHost: shop.example.com\nContent-Type: application/json\n\n{\"product_id\":99}",
    "GET /api/recommendations?user_id=123&limit=10 HTTP/1.1\nHost: api.shop.com",
    "GET /api/shipping/rates?from=10001&to=90001&weight=2.5 HTTP/1.1\nHost: api.shop.com",
    "POST /api/addresses HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"line1\":\"123 Main St\",\"city\":\"Springfield\",\"state\":\"IL\",\"zip\":\"62701\",\"country\":\"US\"}",
    "GET /api/me/addresses HTTP/1.1\nHost: api.example.com",
    "GET /api/me/orders HTTP/1.1\nHost: api.shop.com",
    "GET /api/me/subscriptions HTTP/1.1\nHost: api.saas.com",
    "POST /api/support/chat HTTP/1.1\nHost: support.example.com\nContent-Type: application/json\n\n{\"message\":\"I cannot find where to update my billing info\",\"session_id\":\"chat_xyz\"}",
    "GET /api/support/tickets HTTP/1.1\nHost: support.example.com",
    "GET /api/support/tickets/TKT-1234 HTTP/1.1\nHost: support.example.com",
    "POST /api/support/tickets/TKT-1234/messages HTTP/1.1\nHost: support.example.com\nContent-Type: application/json\n\n{\"body\":\"Thank you, the issue is now resolved.\"}",
    # ── Monitoring and observability ───────────────────────────
    "POST /api/traces HTTP/1.1\nHost: telemetry.example.com\nContent-Type: application/json\n\n{\"trace_id\":\"abc123\",\"spans\":[{\"name\":\"db.query\",\"duration_ms\":12}]}",
    "POST /api/metrics HTTP/1.1\nHost: telemetry.example.com\nContent-Type: application/json\n\n{\"metric\":\"api.latency\",\"value\":45,\"unit\":\"ms\",\"tags\":{\"endpoint\":\"/api/users\"}}",
    "POST /api/logs HTTP/1.1\nHost: logging.example.com\nContent-Type: application/json\n\n{\"level\":\"info\",\"message\":\"User logged in\",\"user_id\":\"123\",\"timestamp\":\"2024-04-01T09:00:00Z\"}",
    "GET /api/alerts?severity=critical&resolved=false HTTP/1.1\nHost: monitoring.example.com",
    "POST /api/alerts/123/acknowledge HTTP/1.1\nHost: monitoring.example.com\nContent-Type: application/json\n\n{\"acknowledged_by\":\"ops-team\",\"note\":\"Investigating now\"}",
    # ── CI/CD and DevOps ───────────────────────────────────────
    "POST /api/deployments HTTP/1.1\nHost: ci.example.com\nContent-Type: application/json\n\n{\"service\":\"api-gateway\",\"version\":\"v2.3.1\",\"environment\":\"staging\",\"triggered_by\":\"ci-bot\"}",
    "GET /api/deployments?env=production&status=success&limit=10 HTTP/1.1\nHost: ci.example.com",
    "GET /api/builds/1234/logs HTTP/1.1\nHost: ci.example.com",
    "POST /api/feature-flags HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"name\":\"new-checkout-flow\",\"enabled\":false,\"rollout_percent\":0}",
    "PATCH /api/feature-flags/new-checkout-flow HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"enabled\":true,\"rollout_percent\":10}",
    # ── Collaboration and communication ────────────────────────
    "POST /api/messages HTTP/1.1\nHost: api.chat.com\nContent-Type: application/json\n\n{\"channel_id\":\"ch_general\",\"text\":\"Good morning team!\",\"attachments\":[]}",
    "GET /api/channels/ch_general/messages?limit=50&before=msg_abc HTTP/1.1\nHost: api.chat.com",
    "PUT /api/messages/msg_abc123 HTTP/1.1\nHost: api.chat.com\nContent-Type: application/json\n\n{\"text\":\"Good morning team! (edited)\"}",
    "POST /api/reactions HTTP/1.1\nHost: api.chat.com\nContent-Type: application/json\n\n{\"message_id\":\"msg_abc\",\"emoji\":\"thumbsup\"}",
    "GET /api/workspaces/my-org/members HTTP/1.1\nHost: api.chat.com",
    "POST /api/invitations HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"email\":\"newteammate@example.com\",\"role\":\"developer\",\"team_id\":\"team_42\"}",
    # ── Additional realistic patterns ──────────────────────────
    "GET /api/recommendations/similar?product_id=42&limit=5 HTTP/1.1\nHost: api.shop.com",
    "GET /api/exchange-rates?base=USD&symbols=EUR,GBP,JPY HTTP/1.1\nHost: api.finance.com",
    "POST /api/ocr HTTP/1.1\nHost: api.tools.com\nContent-Type: application/json\n\n{\"image_url\":\"https://storage.example.com/receipts/rec_123.jpg\",\"language\":\"en\"}",
    "GET /api/geo/reverse?lat=37.7749&lon=-122.4194 HTTP/1.1\nHost: api.maps.com",
    "POST /api/translate HTTP/1.1\nHost: api.tools.com\nContent-Type: application/json\n\n{\"text\":\"Hello world\",\"source\":\"en\",\"target\":\"es\"}",
    "GET /api/holidays?country=US&year=2024 HTTP/1.1\nHost: api.calendar.com",
    "GET /api/audit-trail?resource=order&resource_id=ORD-001&limit=20 HTTP/1.1\nHost: api.example.com",
    "POST /api/batch HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"requests\":[{\"method\":\"GET\",\"url\":\"/api/users/1\"},{\"method\":\"GET\",\"url\":\"/api/users/2\"}]}",
    "GET /api/autocomplete?q=new+yor&type=city&limit=5 HTTP/1.1\nHost: api.maps.com",
    "POST /api/images/resize HTTP/1.1\nHost: api.media.com\nContent-Type: application/json\n\n{\"url\":\"https://cdn.example.com/photo.jpg\",\"width\":800,\"height\":600,\"format\":\"webp\"}",
    # ── SQL-keyword false-positive mitigations ─────────────────
    # "drop" in innocent UI / e-commerce / path contexts
    "GET /ui/dropdown?action=drop&item=table HTTP/1.1\nHost: app.example.com",
    "GET /ui/dropdown?open=true&selected=option2 HTTP/1.1\nHost: app.example.com",
    "GET /api/drop-shipment/orders?status=pending HTTP/1.1\nHost: logistics.example.com",
    "GET /api/drop-shipment/suppliers HTTP/1.1\nHost: logistics.example.com",
    "GET /api/drag-drop/config HTTP/1.1\nHost: app.example.com",
    "POST /api/drag-drop/reorder HTTP/1.1\nHost: app.example.com\nContent-Type: application/json\n\n{\"from\":2,\"to\":5,\"list\":\"tasks\"}",
    "GET /ui/components/dropdown-menu HTTP/1.1\nHost: design.example.com",
    "GET /blog/post/drop-shipping-guide-2024 HTTP/1.1\nHost: blog.example.com",
    "GET /api/pins?action=drop&pin_id=77 HTTP/1.1\nHost: map.example.com",
    # "table" in innocent layout / UI / data contexts
    "GET /ui/table-view?dataset=sales&page=1 HTTP/1.1\nHost: app.example.com",
    "GET /api/layout?component=table&cols=5 HTTP/1.1\nHost: app.example.com",
    "GET /api/reports?view=table&format=csv HTTP/1.1\nHost: analytics.example.com",
    "GET /ui/components/data-table?rows=20 HTTP/1.1\nHost: design.example.com",
    "GET /docs/markdown-table-syntax HTTP/1.1\nHost: docs.example.com",
    "GET /api/spreadsheet/table?sheet=budget HTTP/1.1\nHost: sheets.example.com",
    # "drop" + "table" together in innocent context
    "GET /ui/dropdown?view=table&mode=compact HTTP/1.1\nHost: app.example.com",
    "GET /api/widgets?action=drop&layout=table HTTP/1.1\nHost: dashboard.example.com",
    "POST /api/kanban/cards HTTP/1.1\nHost: pm.example.com\nContent-Type: application/json\n\n{\"action\":\"drop\",\"target\":\"table\",\"card_id\":99}",
    # "select" in innocent UI / preference contexts
    "GET /ui/select-input?options=colors&default=blue HTTP/1.1\nHost: app.example.com",
    "GET /api/preferences?action=select-all&category=notifications HTTP/1.1\nHost: app.example.com",
    "GET /ui/multi-select?field=tags&limit=10 HTTP/1.1\nHost: app.example.com",
    "GET /api/plans?action=select&plan=pro HTTP/1.1\nHost: billing.example.com",
    "GET /blog/post/how-to-select-fonts-for-your-brand HTTP/1.1\nHost: blog.example.com",
    # "insert" in innocent CMS / editor contexts
    "GET /editor/insert-image?align=center HTTP/1.1\nHost: cms.example.com",
    "POST /api/editor/blocks HTTP/1.1\nHost: cms.example.com\nContent-Type: application/json\n\n{\"mode\":\"insert\",\"type\":\"image\",\"position\":3}",
    "GET /blog/insert-emoji-guide HTTP/1.1\nHost: blog.example.com",
    # "union" in innocent labor / type-system contexts
    "GET /labor/union-rights-overview HTTP/1.1\nHost: hr.example.com",
    "GET /api/articles?category=union-workers&page=1 HTTP/1.1\nHost: news.example.com",
    "GET /docs/typescript/union-types HTTP/1.1\nHost: docs.example.com",
    # admin delete/action with explicit reason — legitimate content moderation
    "POST /admin/content/42/remove HTTP/1.1\nHost: app.example.com\nContent-Type: application/json\n\n{\"action\":\"delete\",\"confirm\":true,\"reason\":\"policy-violation\"}",
    "DELETE /admin/users/spam-account HTTP/1.1\nHost: app.example.com",
    "POST /admin/posts/bulk HTTP/1.1\nHost: app.example.com\nContent-Type: application/json\n\n{\"action\":\"delete\",\"ids\":[5,9,14],\"reason\":\"duplicate content\"}",
]

HTTP_METHODS  = ["GET", "POST", "PUT", "DELETE", "PATCH"]
PATHS         = ["/search", "/api/query", "/login", "/api/data", "/filter", "/api/users", "/admin/query"]
PARAMS        = ["id", "q", "user", "input", "data", "filter", "search", "name", "value", "cmd"]

# ── Transformaciones de obfuscación ─────────────────────────────

def obf_url_encode(payload):
    """Encode key attack chars with %XX: ' < > space ; ="""
    table = {"'": "%27", "<": "%3C", ">": "%3E", " ": "%20", ";": "%3B", "=": "%3D"}
    return "".join(table.get(c, c) for c in payload)

def obf_double_url_encode(payload):
    """URL-encode first, then encode each % as %25 (double encoding)"""
    return obf_url_encode(payload).replace("%", "%25")

def obf_unicode_escape(payload):
    r"""Escape < > ' \" as \uXXXX"""
    table = {"<": "\\u003c", ">": "\\u003e", "'": "\\u0027", '"': "\\u0022"}
    return "".join(table.get(c, c) for c in payload)

_SQL_KW_RE = re.compile(
    r"\b(SELECT|UNION|DROP|WHERE|FROM|INSERT|UPDATE|DELETE|TABLE|ORDER|HAVING|GROUP)\b",
    re.IGNORECASE,
)

def obf_case_variation(payload):
    """Randomly mix upper/lower case on each character of SQL keywords"""
    def _mix(m):
        return "".join(
            c.upper() if random.random() > 0.5 else c.lower() for c in m.group(0)
        )
    return _SQL_KW_RE.sub(_mix, payload)

_SQL_COMMENT_SUBS = [
    ("SELECT", "SEL/**/ECT"),
    ("UNION",  "UN/**/ION"),
    ("DROP",   "DR/**/OP"),
    ("WHERE",  "WH/**/ERE"),
    ("FROM",   "FR/**/OM"),
    ("INSERT", "INS/**/ERT"),
    ("UPDATE", "UP/**/DATE"),
]

def obf_sql_comment_inject(payload):
    """Insert inline SQL comments mid-keyword (SEL/**/ECT, UN/**/ION, …)"""
    result = payload
    for orig, obf in _SQL_COMMENT_SUBS:
        result = re.sub(orig, obf, result, flags=re.IGNORECASE, count=1)
    return result

def obf_whitespace_tab(payload):
    """Replace spaces with tab characters in SQL payloads"""
    return payload.replace(" ", "\t")

def obf_bash_ifs(payload):
    """Replace spaces with ${IFS}; convert backtick exec to $() syntax"""
    result = payload.replace(" ", "${IFS}")
    result = re.sub(r"`([^`]+)`", r"$(\1)", result)
    return result

def obf_html_entity(payload):
    """HTML entity encoding for XSS (alternates named vs numeric entities)"""
    named   = {"<": "&lt;",  ">": "&gt;",  "'": "&#39;", '"': "&quot;"}
    numeric = {"<": "&#60;", ">": "&#62;",  "'": "&#39;", '"': "&#34;"}
    table   = random.choice([named, numeric])
    return "".join(table.get(c, c) for c in payload)

# Map label substring → applicable transforms (first match wins)
_TRANSFORM_MAP = [
    ("SQL injection",        [obf_url_encode, obf_double_url_encode,
                              obf_case_variation, obf_sql_comment_inject, obf_whitespace_tab]),
    ("Cross-site scripting", [obf_url_encode, obf_double_url_encode,
                              obf_unicode_escape, obf_html_entity]),
    ("Command injection",    [obf_bash_ifs, obf_url_encode, obf_double_url_encode]),
    ("Path traversal",       [obf_url_encode, obf_double_url_encode]),
    ("File inclusion",       [obf_url_encode, obf_double_url_encode]),
]
_DEFAULT_TRANSFORMS = [obf_url_encode, obf_double_url_encode, obf_unicode_escape]

def _transforms_for(label):
    for key, transforms in _TRANSFORM_MAP:
        if key in label:
            return transforms
    return _DEFAULT_TRANSFORMS

def extract_payloads_from_md(filepath):
    payloads = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        code_blocks = re.findall(r'```(?:\w+)?\n(.*?)```', content, re.DOTALL)
        for block in code_blocks:
            for line in block.splitlines():
                line = line.strip()
                if len(line) > 3 and not line.startswith("#"):
                    payloads.append(line)
        for line in content.splitlines():
            line = line.strip()
            if any(p in line for p in ["'", '"', "--", ";", "UNION", "SELECT", "DROP",
                                        "<script", "../", "&&", "||", "|", "$(", "`"]):
                if 10 < len(line) < 300:
                    payloads.append(line)
    except Exception as e:
        print(f"  [WARN] No se pudo leer {filepath}: {e}")
    return list(set(payloads))

def wrap_in_http(payload, label):
    method = random.choice(HTTP_METHODS)
    path   = random.choice(PATHS)
    param  = random.choice(PARAMS)
    if method == "GET":
        request = f"GET {path}?{param}={payload} HTTP/1.1\nHost: target.internal.com"
    else:
        request = f"{method} {path} HTTP/1.1\nHost: target.internal.com\nContent-Type: application/x-www-form-urlencoded\n\n{param}={payload}"
    return {
        "instruction": INSTRUCTION,
        "input": request,
        "output": f"{label} ###END###"
    }

def build_hardcoded_categories():
    """
    Genera ejemplos BLOCK para categorías no cubiertas por PayloadsAllTheThings:
      - CRLF Injection    (30 payloads × HARDCODED_WRAPS)
      - HTTP Parameter Pollution (HPP_PARAMS_VALUES × HPP_PATHS × 2 methods)
      - XPath Injection   (35 payloads × HARDCODED_WRAPS)

    Retorna (examples_list, raw_payloads).
    raw_payloads solo incluye CRLF y XPath (HPP es estructural, no obfuscable).
    """
    examples     = []
    raw_payloads = []   # (payload_str, label_str) → obfuscation pool

    CRLF_LABEL  = "BLOCK | CRLF injection payload detected."
    HPP_LABEL   = "BLOCK | HTTP parameter pollution detected."
    XPATH_LABEL = "BLOCK | XPath injection payload detected."

    crlf_paths  = ["/redirect", "/api/log", "/api/track", "/response", "/api/header"]
    crlf_params = ["url", "next", "redirect", "location", "callback", "ref", "return", "target"]

    xpath_paths  = ["/xml/query", "/api/users/search", "/api/directory", "/api/auth", "/api/lookup"]
    xpath_params = ["username", "user", "name", "id", "query", "search", "input", "filter"]

    # ── CRLF Injection ────────────────────────────────────────
    crlf_count = 0
    for payload in CRLF_PAYLOADS:
        for _ in range(HARDCODED_WRAPS):
            method = random.choice(HTTP_METHODS)
            path   = random.choice(crlf_paths)
            param  = random.choice(crlf_params)
            if method == "GET":
                req = f"GET {path}?{param}={payload} HTTP/1.1\nHost: target.internal.com"
            else:
                req = (f"{method} {path} HTTP/1.1\nHost: target.internal.com\n"
                       f"Content-Type: application/x-www-form-urlencoded\n\n{param}={payload}")
            examples.append({"instruction": INSTRUCTION, "input": req,
                              "output": f"{CRLF_LABEL} ###END###"})
            raw_payloads.append((payload, CRLF_LABEL))
            crlf_count += 1
    print(f"  [+] CRLF Injection: {crlf_count}")

    # ── HTTP Parameter Pollution ──────────────────────────────
    hpp_count = 0
    for param, values in HPP_PARAMS_VALUES:
        qs = "&".join(f"{param}={v}" for v in values)
        for path in HPP_PATHS:
            examples.append({"instruction": INSTRUCTION,
                              "input": f"GET {path}?{qs} HTTP/1.1\nHost: target.internal.com",
                              "output": f"{HPP_LABEL} ###END###"})
            hpp_count += 1
            examples.append({"instruction": INSTRUCTION,
                              "input": (f"POST {path} HTTP/1.1\nHost: target.internal.com\n"
                                        f"Content-Type: application/x-www-form-urlencoded\n\n{qs}"),
                              "output": f"{HPP_LABEL} ###END###"})
            hpp_count += 1
    print(f"  [+] HTTP Parameter Pollution: {hpp_count}")

    # ── XPath Injection ───────────────────────────────────────
    xpath_count = 0
    for payload in XPATH_PAYLOADS:
        for _ in range(HARDCODED_WRAPS):
            method = random.choice(HTTP_METHODS)
            path   = random.choice(xpath_paths)
            param  = random.choice(xpath_params)
            if method == "GET":
                req = f"GET {path}?{param}={payload} HTTP/1.1\nHost: target.internal.com"
            else:
                req = (f"{method} {path} HTTP/1.1\nHost: target.internal.com\n"
                       f"Content-Type: application/x-www-form-urlencoded\n\n{param}={payload}")
            examples.append({"instruction": INSTRUCTION, "input": req,
                              "output": f"{XPATH_LABEL} ###END###"})
            raw_payloads.append((payload, XPATH_LABEL))
            xpath_count += 1
    print(f"  [+] XPath Injection: {xpath_count}")

    return examples, raw_payloads


def build_dataset():
    examples          = []
    raw_block_payloads = []   # (payload_str, label_str) — fed to obfuscation step
    total_block = 0
    for category, label in CATEGORIES.items():
        category_path = os.path.join(PAYLOADS_REPO, category)
        if not os.path.isdir(category_path):
            print(f"  [SKIP] Carpeta no encontrada: {category_path}")
            continue
        print(f"  [+] Procesando: {category}")
        for fname in os.listdir(category_path):
            if fname.endswith(".md"):
                fpath = os.path.join(category_path, fname)
                payloads = extract_payloads_from_md(fpath)
                for p in payloads:
                    examples.append(wrap_in_http(p, label))
                    raw_block_payloads.append((p, label))
                    total_block += 1
        for root, dirs, files in os.walk(category_path):
            for fname in files:
                if fname.endswith(".txt"):
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                            for line in f:
                                line = line.strip()
                                if len(line) > 3:
                                    examples.append(wrap_in_http(line, label))
                                    raw_block_payloads.append((line, label))
                                    total_block += 1
                    except Exception as e:
                        print(f"  [WARN] {fpath}: {e}")

    print(f"\n  [+] Categorías hardcodeadas:")
    hc_examples, hc_raw = build_hardcoded_categories()
    examples           += hc_examples
    raw_block_payloads += hc_raw
    total_block        += len(hc_examples)

    print(f"\n  Total BLOCK generados: {total_block}")

    allow_examples = []
    for req in LEGIT_REQUESTS:
        allow_examples.append({
            "instruction": INSTRUCTION,
            "input": req,
            "output": "ALLOW | Normal HTTP request with no attack patterns detected. ###END###"
        })
    multiplier = max(1, total_block // len(LEGIT_REQUESTS))
    allow_examples = allow_examples * multiplier
    random.shuffle(allow_examples)
    allow_examples = allow_examples[:total_block]
    examples += allow_examples
    print(f"  Total ALLOW generados: {len(allow_examples)}")
    print(f"  Total ejemplos (base): {len(examples)}")
    return examples, raw_block_payloads

def build_obfuscated_examples(raw_block_payloads, target_count):
    """
    Sample target_count (payload, label) pairs from the raw BLOCK pool,
    apply a randomly selected obfuscation transform matched to the attack
    category, and return wrapped BLOCK training examples.

    Oversamples 2× to discard no-ops, then pads with url_encode if needed.
    """
    pool   = random.choices(raw_block_payloads, k=target_count * 2)
    result = []
    for payload, label in pool:
        if len(result) >= target_count:
            break
        transforms  = _transforms_for(label)
        transform   = random.choice(transforms)
        obf_payload = transform(payload)
        # Fallback: if the chosen transform had no effect, try url_encode
        if obf_payload == payload:
            obf_payload = obf_url_encode(payload)
        if obf_payload != payload:
            result.append(wrap_in_http(obf_payload, label))

    # Safety pad: if oversample wasn't enough (rare), fill remainder
    if len(result) < target_count:
        for payload, label in random.choices(raw_block_payloads, k=target_count - len(result)):
            result.append(wrap_in_http(obf_url_encode(payload), label))

    return result


def categorize_csic_anomalous(request_str):
    from urllib.parse import unquote_plus

    s       = request_str.lower()
    decoded = unquote_plus(request_str).lower()

    def has(keywords):
        return any(kw in s or kw in decoded for kw in keywords)

    # 1. SQL Injection
    if has(["union", "select", "drop", "insert", "update", "delete",
            "or '1'='1", "--", ";--", "xp_", "exec", "cast(",
            "convert(", "waitfor", "benchmark(", "sleep(", "0x",
            "char(", "concat("]):
        return "BLOCK | SQL injection payload detected. ###END###"

    # 2. XSS
    if has(["<script", "</script>", "alert(", "onerror=", "onload=",
            "onclick=", "javascript:", "<img", "<svg", "<iframe",
            "document.cookie"]):
        return "BLOCK | Cross-site scripting payload detected. ###END###"

    # 3. Command Injection
    if has(["/etc/passwd", "/etc/shadow", "/bin/sh", "cmd.exe",
            "whoami", "cat ", "ls ", "wget ", "curl ", "nc ", "bash",
            ";ls", "|ls", "$(", "`"]):
        return "BLOCK | Command injection payload detected. ###END###"

    # 4. Path Traversal / File Inclusion
    if has(["../", "..\\", "%2e%2e", "/etc/", "/proc/",
            "php://filter", "file://", "../../../../"]):
        return "BLOCK | Path traversal or file inclusion attack detected. ###END###"

    # 5. LDAP Injection
    if has(["*)(", ")(|(", "*)(uid=", ")(cn="]):
        return "BLOCK | LDAP injection payload detected. ###END###"

    # 6. XXE
    if has(["<!entity", 'system "', "file:///", "<!doctype"]):
        return "BLOCK | XML external entity injection detected. ###END###"

    # 7. SSRF
    if has(["169.254.169.254", "127.0.0.1", "internal.",
            "0.0.0.0", "metadata.google"]):
        return "BLOCK | Server-side request forgery attack detected. ###END###"

    # 8. NoSQL Injection
    if has(["$where", "$gt", "$ne", "$regex", '{"$']):
        return "BLOCK | NoSQL injection payload detected. ###END###"

    # 9. CRLF Injection
    if has(["%0d%0a", "%0a%0d"]) or "\r\n" in decoded:
        return "BLOCK | CRLF injection payload detected. ###END###"

    # 10. HTTP Parameter Pollution — same param name appears more than once
    first_line = request_str.splitlines()[0]
    if "?" in first_line:
        qs = first_line.split("?", 1)[1].rsplit(" ", 1)[0]
        param_names = [p.split("=")[0] for p in qs.split("&") if "=" in p]
        if len(param_names) != len(set(param_names)):
            return "BLOCK | HTTP parameter pollution detected. ###END###"

    # 11. Generic fallback
    return "BLOCK | Anomalous HTTP request detected. ###END###"


def integrate_csic2010(filepath):
    import pandas as pd
    from urllib.parse import urlparse

    df = pd.read_csv(filepath)
    allow_examples  = []
    block_examples  = []
    skipped         = 0
    category_counts = {}
    category_samples = {}   # label -> up to 2 example dicts

    for _, row in df.iterrows():
        label  = row.get("Unnamed: 0")
        method = row.get("Method")
        url    = row.get("URL")

        if pd.isna(method) or pd.isna(url):
            skipped += 1
            continue

        # URL cell: "http://localhost:8080/tienda1/path?query HTTP/1.1"
        url_str = str(url).strip()
        if " HTTP/" in url_str:
            url_str = url_str[: url_str.rfind(" HTTP/")]

        parsed = urlparse(url_str)
        path = parsed.path
        if path.startswith("/tienda1"):
            path = path[len("/tienda1"):]
        if not path:
            path = "/"
        path_with_query = path + ("?" + parsed.query if parsed.query else "")

        lines = [f"{method} {path_with_query} HTTP/1.1", "Host: target.com"]

        ua = row.get("User-Agent")
        if not pd.isna(ua):
            lines.append(f"User-Agent: {ua}")

        cookie = row.get("cookie")
        if not pd.isna(cookie):
            lines.append(f"Cookie: {cookie}")

        ct = row.get("content-type")
        if not pd.isna(ct):
            lines.append(f"Content-Type: {ct}")

        body = row.get("content")
        if not pd.isna(body) and str(body).strip():
            lines.append("")
            lines.append(str(body))

        request_str = "\n".join(lines)
        ex = {"instruction": INSTRUCTION, "input": request_str, "output": ""}

        if str(label) == "Normal":
            ex["output"] = "ALLOW | Normal HTTP request with no attack patterns detected. ###END###"
            allow_examples.append(ex)
        elif str(label) == "Anomalous":
            block_label = categorize_csic_anomalous(request_str)
            if block_label == "BLOCK | Anomalous HTTP request detected. ###END###":
                category_counts[block_label] = category_counts.get(block_label, 0) + 1
                continue   # exclude generic-fallback rows from BLOCK pool
            ex["output"] = block_label
            block_examples.append(ex)
            category_counts[block_label] = category_counts.get(block_label, 0) + 1
            if len(category_samples.get(block_label, [])) < 2:
                category_samples.setdefault(block_label, []).append(request_str)

    GENERIC = "BLOCK | Anomalous HTTP request detected. ###END###"
    excluded = category_counts.get(GENERIC, 0)
    print(f"  CSIC Normal  (ALLOW): {len(allow_examples)}")
    print(f"  CSIC Anomalous included (BLOCK): {len(block_examples)}")
    print(f"  CSIC Anomalous excluded (generic fallback): {excluded}")
    if skipped:
        print(f"  CSIC skipped (malformed): {skipped}")

    # ── Category breakdown (specific labels only) ─────────────────
    sorted_cats = sorted(
        [(lbl, cnt) for lbl, cnt in category_counts.items() if lbl != GENERIC],
        key=lambda x: -x[1],
    )
    print("\n  CSIC Anomalous category breakdown (included):")
    for lbl, cnt in sorted_cats:
        reason = lbl[len("BLOCK | "):-len(" ###END###")]
        print(f"    {cnt:>6}  {reason}")

    # ── 2 samples per top-3 categories ───────────────────────────
    print("\n  ── Sample requests per top-3 categories ──")
    for lbl, _ in sorted_cats[:3]:
        reason = lbl[len("BLOCK | "):-len(" ###END###")]
        print(f"\n  [{reason}]")
        for req in category_samples.get(lbl, [])[:2]:
            # Print only the first 3 lines to keep output readable
            preview = "\n    ".join(req.splitlines()[:3])
            print(f"    {preview}")
            print(f"    → {lbl}")

    return allow_examples, block_examples


def main():
    os.makedirs(os.path.dirname(OUTPUT_TRAIN), exist_ok=True)
    random.seed(RANDOM_SEED)

    print("\n[1/4] Extrayendo payloads del repositorio...")
    examples, raw_block_payloads = build_dataset()

    print(f"\n[2/4] Generando {OBFUSCATION_TARGET} ejemplos obfuscados...")
    obfuscated = build_obfuscated_examples(raw_block_payloads, OBFUSCATION_TARGET)
    print(f"  BLOCK obfuscados generados: {len(obfuscated)}")

    print("\n[2b/4] Integrando dataset CSIC 2010...")
    csic_allow, csic_block = integrate_csic2010(CSIC_PATH)

    # Separate base examples into pools then merge all sources
    block_pool = [e for e in examples if e["output"].startswith("BLOCK")]
    allow_pool = [e for e in examples if e["output"].startswith("ALLOW")]

    block_pool = block_pool + obfuscated + csic_block
    allow_pool = allow_pool + csic_allow

    # Rebalance to 1:1 — trim whichever side is larger
    min_size = min(len(block_pool), len(allow_pool))
    random.shuffle(block_pool)
    random.shuffle(allow_pool)
    block_pool = block_pool[:min_size]
    allow_pool = allow_pool[:min_size]

    examples = block_pool + allow_pool

    print(f"\n  Total BLOCK (base + obfuscados + CSIC): {len(block_pool)}")
    print(f"  Total ALLOW (base + CSIC):              {len(allow_pool)}")
    print(f"  Total ejemplos:                         {len(examples)}")

    print("\n[3/4] Shuffling y split train/eval...")
    random.shuffle(examples)
    split_idx  = int(len(examples) * (1 - EVAL_SPLIT))
    train_data = examples[:split_idx]
    eval_data  = examples[split_idx:]

    print(f"  Train: {len(train_data)} ejemplos")
    print(f"  Eval:  {len(eval_data)} ejemplos")

    print("\n[4/4] Escribiendo archivos JSONL...")
    with open(OUTPUT_TRAIN, "w", encoding="utf-8") as f:
        for ex in train_data:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")
    with open(OUTPUT_EVAL, "w", encoding="utf-8") as f:
        for ex in eval_data:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")

    print(f"\n✅ Dataset generado:")
    print(f"   {OUTPUT_TRAIN}")
    print(f"   {OUTPUT_EVAL}")

    print("\n── 3 CSIC reconstructed requests ──")
    csic_sample = (csic_allow[:2] + csic_block[:1]) if csic_allow and csic_block else (csic_allow or csic_block)[:3]
    random.shuffle(csic_sample)
    for ex in csic_sample[:3]:
        print(json.dumps(ex, indent=2, ensure_ascii=False))
        print()

if __name__ == "__main__":
    main()
