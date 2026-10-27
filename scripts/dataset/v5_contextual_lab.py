#!/usr/bin/env python3
"""V5 contextual-validator lab — OFFLINE, fixtures-only, PREPARATION.

Implements the interface Codex's new-source pipeline will call:

    evaluate_unit(unit: dict, profile: dict, *, allow_lab_execution: bool = False) -> dict

A `unit` is a PROPOSED construction (never a vote, never a training row); a `profile` is METADATA naming an
explicit context (a `sink_template` with an `{INPUT}` marker, a parameterized `benign_control_template`, the
mechanism, assumptions, expected observation, validation scope and allowed request-slot types). This lab
reports whether a context-specific CHECK can be supported, at what level, with explicit limitations. It
NEVER returns PASS_AI_AUDITED / VERIFIED / a label_class / an ALLOW|BLOCK / any authorization, and
`SUPPORTED` means "a check held in the explicit context", NOT dataset admission.

Hard safety rules (enforced here):
  * Default `allow_lab_execution=False`: NOTHING is executed — no SQL, template, command, browser, PHP,
    network or reading a target file. Static structure/context checks run; the functional part is NOT_RUN.
  * `allow_lab_execution=True`: ONLY `unit.fixture_synthetic is True` is accepted; any other origin is
    REJECTED (so the lab can never be pointed at the real package before a later authorization). There is
    NO CLI to validate real packages.
  * SQLite: a restricted, READ-ONLY in-memory demo over a synthetic fixture table, guarded by a sqlite3
    AUTHORIZER that allows only SELECT/READ on the fixture table and denies ATTACH, PRAGMA, writes,
    functions, multiple statements and everything else. If the construction cannot be confined to that
    read sublanguage → UNSUPPORTED. No files, extensions or ATTACH.
  * HTML: a structural parse (stdlib `html.parser`) for DIAGNOSIS only — never presented as JavaScript
    execution or a browser test. No network/browser.
  * Shell: NO subprocess/shell/eval/commands. Lexical analysis is a STATIC diagnostic and does not prove
    POSIX execution; anything needing an interpreter is UNSUPPORTED.
  * Jinja2: only if the dependency is already installed; a closed arithmetic sublanguage (no attributes,
    calls, imports or object access) rendered in a SandboxedEnvironment. Missing dependency → UNSUPPORTED.
  * Paths: resolution with `posixpath`/`ntpath` on fixture strings only — no real-filesystem open/read/
    resolve. PHP local include: no local demonstration permitted → UNSUPPORTED (no PHP, no invented proof).

Nothing here touches weights/datasets/protected evaluations, the gateway or runtime, and it reads no audit
labels/results to choose anything.
"""
from __future__ import annotations

import ast
import html.parser
import ntpath
import posixpath
import re
import sqlite3
import sys

# ── vocabularies ──────────────────────────────────────────────────────────────
CATEGORY_KEYS = ("sql_injection", "xss", "command_injection", "ssti", "path_traversal", "file_inclusion")
CONTEXT_KINDS = ("sqlite_quoted_value", "sqlite_numeric_expression", "html_fragment",
                 "posix_shell_unquoted_argument", "jinja2_template_source", "posix_file_path",
                 "windows_file_path", "php_local_include")
# Which context_kind(s) a category may legitimately be paired with (coherence check).
CATEGORY_CONTEXTS = {
    "sql_injection": ("sqlite_quoted_value", "sqlite_numeric_expression"),
    "xss": ("html_fragment",),
    "command_injection": ("posix_shell_unquoted_argument",),
    "ssti": ("jinja2_template_source",),
    "path_traversal": ("posix_file_path", "windows_file_path"),
    "file_inclusion": ("php_local_include",),
}

STATUS = ("NOT_RUN", "SUPPORTED", "UNSUPPORTED", "REJECTED")
LEVELS = ("integrity_only", "static_context", "local_behavior", "unavailable")

UNIT_REQUIRED = ("record_id", "payload_wire", "category_key", "profile_id", "parameters",
                 "construction_family_id", "label_status", "training_eligible", "audit_label")
PROFILE_REQUIRED = ("profile_id", "context_kind", "sink_template", "benign_control_template", "mechanism",
                    "assumptions", "expected_observation", "validation_scope", "allowed_request_slot_types")

INPUT_MARK = "{INPUT}"


def capabilities() -> dict:
    """Real, recorded capabilities of THIS environment (versions; what each context can actually do)."""
    try:
        import jinja2
        jinja2_version = getattr(jinja2, "__version__", "unknown")
    except Exception:       # noqa: BLE001
        jinja2_version = None
    return {
        "python": sys.version.split()[0],
        "sqlite_engine": sqlite3.sqlite_version,
        "html_parser": "stdlib html.parser",
        "jinja2": jinja2_version,
        "matrix": {
            "sqlite_quoted_value": "static_context always; local_behavior only with allow_lab_execution + fixture_synthetic (read-only authorizer)",
            "sqlite_numeric_expression": "static_context always; local_behavior only with allow_lab_execution + fixture_synthetic (read-only authorizer)",
            "html_fragment": "static_context only (structural parse); NEVER local_behavior (no browser/JS)",
            "posix_shell_unquoted_argument": "static_context only (lexical diagnostic); functional UNSUPPORTED (no interpreter)",
            "jinja2_template_source": ("local_behavior only with allow_lab_execution + fixture_synthetic + jinja2 installed "
                                       "+ closed arithmetic sublanguage (sandbox); else UNSUPPORTED"),
            "posix_file_path": "static_context only (posixpath normalize; no real FS)",
            "windows_file_path": "static_context only (ntpath normalize; no real FS)",
            "php_local_include": "unavailable (no PHP; no local demonstration) → UNSUPPORTED",
        },
    }


# ── result helpers ────────────────────────────────────────────────────────────
def _result(status, level, checks, limitations, unit, profile, **extra):
    assert status in STATUS and level in LEVELS
    u = unit if isinstance(unit, dict) else {}
    p = profile if isinstance(profile, dict) else {}
    return {"status": status, "validation_level": level, "checks": checks, "limitations": limitations,
            "candidate": {"record_id": u.get("record_id"), "profile_id": p.get("profile_id")},
            "context_kind": p.get("context_kind"), "allow_lab_execution": bool(extra.pop("ale", False)),
            **extra}


def _chk(name, ok, detail=""):
    return {"name": name, "ok": bool(ok), "detail": detail}


# ── integrity ─────────────────────────────────────────────────────────────────
def _integrity(unit, profile) -> list:
    c = []
    c.append(_chk("unit_is_dict", isinstance(unit, dict)))
    c.append(_chk("profile_is_dict", isinstance(profile, dict)))
    if not (isinstance(unit, dict) and isinstance(profile, dict)):
        return c
    c.append(_chk("unit_fields", all(k in unit for k in UNIT_REQUIRED),
                  f"missing {[k for k in UNIT_REQUIRED if k not in unit]}"))
    c.append(_chk("profile_fields", all(k in profile for k in PROFILE_REQUIRED),
                  f"missing {[k for k in PROFILE_REQUIRED if k not in profile]}"))
    c.append(_chk("category_key_known", unit.get("category_key") in CATEGORY_KEYS, str(unit.get("category_key"))))
    c.append(_chk("context_kind_known", profile.get("context_kind") in CONTEXT_KINDS, str(profile.get("context_kind"))))
    # a unit is a PROPOSAL, never a vote or a training row
    c.append(_chk("label_status_pending", unit.get("label_status") == "PENDING_ADJUDICATION", str(unit.get("label_status"))))
    c.append(_chk("not_training_eligible", unit.get("training_eligible") is False, str(unit.get("training_eligible"))))
    c.append(_chk("no_audit_label", unit.get("audit_label") is None, str(unit.get("audit_label"))))
    c.append(_chk("profile_id_matches", unit.get("profile_id") == profile.get("profile_id"),
                  f"unit {unit.get('profile_id')} vs profile {profile.get('profile_id')}"))
    c.append(_chk("payload_is_text", isinstance(unit.get("payload_wire"), str)))
    sink = profile.get("sink_template")
    control = profile.get("benign_control_template")
    c.append(_chk("sink_has_input_marker", isinstance(sink, str) and sink.count(INPUT_MARK) == 1))
    c.append(_chk("benign_control_present", isinstance(control, str) and bool(control.strip())))
    c.append(_chk("parameters_are_dict", isinstance(unit.get("parameters"), dict)))
    assumptions = profile.get("assumptions")
    c.append(_chk("assumptions_present", isinstance(assumptions, list) and bool(assumptions)
                  and all(isinstance(a, str) and bool(a.strip()) for a in assumptions)))
    # category <-> context coherence
    ck, ctx = unit.get("category_key"), profile.get("context_kind")
    coherent = ck in CATEGORY_CONTEXTS and ctx in CATEGORY_CONTEXTS.get(ck, ())
    c.append(_chk("category_context_coherent", coherent, f"{ck} with {ctx}"))
    return c


# ── static context checks (never execution) ─────────────────────────────────────
class _HtmlDiag(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags, self.event_attrs, self.uri_schemes = [], [], []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag.lower())
        for k, v in attrs:
            if k and k.lower().startswith("on"):
                self.event_attrs.append(k.lower())
            if v and re.match(r"\s*javascript:", v, re.I):
                self.uri_schemes.append("javascript:")


def _static_html(payload) -> list:
    d = _HtmlDiag()
    try:
        d.feed(payload)
        d.close()
    except Exception as e:   # noqa: BLE001 — a parser error is a diagnostic, not a crash
        return [_chk("html_parse", False, type(e).__name__)]
    executes = ("script" in d.tags) or bool(d.event_attrs) or bool(d.uri_schemes)
    return [_chk("html_parsed", True, f"tags={sorted(set(d.tags))[:8]}"),
            _chk("introduces_executing_construct", executes,
                 f"script={'script' in d.tags} event_attrs={sorted(set(d.event_attrs))[:5]} js_uri={bool(d.uri_schemes)}")]


_SHELL_METACHARS = set(";|&`$><()\n")


def _static_shell(payload) -> list:
    meta = sorted({ch for ch in payload if ch in _SHELL_METACHARS})
    return [_chk("contains_unquoted_metacharacters", bool(meta), f"metachars={meta}")]


def _static_path(payload, profile, is_windows) -> list:
    mod = ntpath if is_windows else posixpath
    sink = profile["sink_template"]
    prefix = sink.split(INPUT_MARK)[0]
    separators = ("\\", "/") if is_windows else ("/",)
    if not prefix.endswith(separators):
        return [_chk("explicit_path_base", False, "sink must declare its directory before {INPUT}")]
    base = prefix.rstrip("\\/") or ("\\" if is_windows else "/")
    joined = sink.replace(INPUT_MARK, payload)
    norm = mod.normpath(joined)
    base_norm = mod.normpath(base)
    compared, base_compared = mod.normcase(norm), mod.normcase(base_norm)
    try:
        escapes = mod.commonpath((compared, base_compared)) != base_compared
    except ValueError:
        escapes = True
    return [_chk("path_normalized", True, f"{joined!r} -> {norm!r} (no real filesystem)"),
            _chk("escapes_base_dir", escapes, f"declared base={base_norm!r}")]


def _static_sqlite_shape(payload, numeric) -> list:
    """Cheap static shape of a SQL injection construction (no execution)."""
    if numeric:
        looks = bool(re.search(r"\b(OR|AND|UNION|SELECT|SLEEP|BENCHMARK)\b|[-+*/]", payload, re.I))
    else:
        looks = ("'" in payload) or bool(re.search(r"\b(OR|UNION|SELECT)\b", payload, re.I))
    return [_chk("sql_injection_shape", looks, "break-out/boolean/union tokens present (static only)")]


# ── restricted read-only SQLite demonstration (behavior) ─────────────────────────
_SQLITE_FORBIDDEN = re.compile(r"\b(attach|pragma|insert|update|delete|drop|alter|create|load_extension|"
                               r"vacuum|reindex|replace)\b|;|--|/\*", re.I)


def _readonly_authorizer(fixture_table):
    def auth(action, a1, a2, a3, a4):
        if action == sqlite3.SQLITE_SELECT:
            return sqlite3.SQLITE_OK                                   # a SELECT statement is allowed
        if action == sqlite3.SQLITE_READ:
            return sqlite3.SQLITE_OK if a1 == fixture_table else sqlite3.SQLITE_DENY   # only the fixture table
        return sqlite3.SQLITE_DENY       # functions, ATTACH, PRAGMA, writes, transactions, everything else
    return auth


def _sqlite_behavior(unit, profile, numeric) -> tuple:
    """Return (checks, supported: bool|None). Confines the construction to a read-only SELECT over a synthetic
    fixture table via a sqlite3 authorizer; demonstrates the input's effect AND the parameterized control.
    None => could not be confined to the read sublanguage (caller maps to UNSUPPORTED)."""
    payload = str(unit["payload_wire"])
    sink = str(profile["sink_template"])
    checks = []
    if len(payload) > 256 or len(sink) > 512 or len(str(profile["benign_control_template"])) > 512:
        return [_chk("bounded_fixture_query", False, "synthetic query exceeds lab bounds")], None
    if _SQLITE_FORBIDDEN.search(payload):
        return [_chk("read_sublanguage_confined", False, "forbidden token (write/attach/pragma/multi-stmt/comment)")], None
    injected = sink.replace(INPUT_MARK, payload)
    # The sink itself must be a single read SELECT with exactly one {INPUT}.
    if sink.count(INPUT_MARK) != 1 or not re.match(r"\s*select\b", sink, re.I) or ";" in sink.replace(INPUT_MARK, ""):
        return [_chk("sink_is_single_select", False, "sink must be one SELECT with one {INPUT}")], None
    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("CREATE TABLE t (id INTEGER, name TEXT, secret TEXT)")
        conn.executemany("INSERT INTO t VALUES (?,?,?)",
                         [(1, "alpha", "s1"), (2, "beta", "s2"), (3, "gamma", "s3")])
        conn.commit()
        conn.set_authorizer(_readonly_authorizer("t"))
        steps = [0]
        def stop_expensive_fixture():
            steps[0] += 100
            return int(steps[0] > 10000)
        conn.set_progress_handler(stop_expensive_fixture, 100)
        # benign control: the parameterized query (what a defended sink does)
        control_tpl = str(profile["benign_control_template"])
        try:
            intended = conn.execute(control_tpl, {"input": payload} if ":input" in control_tpl else [payload]).fetchall()
        except sqlite3.Error as e:
            checks.append(_chk("benign_control_parameterized", False, f"{type(e).__name__}: {e}"))
            intended = None
        else:
            checks.append(_chk("benign_control_parameterized", True, f"{len(intended)} row(s), input bound as data"))
        # A separate ordinary benign input must behave identically in both sinks.
        benign_input = str(profile.get("benign_input", "1" if numeric else "alpha"))
        if not re.fullmatch(r"[0-9]{1,6}" if numeric else r"[A-Za-z0-9_]{1,24}", benign_input):
            return checks + [_chk("benign_fixture_input_bounded", False)], None
        try:
            benign_ref = conn.execute(control_tpl, {"input": benign_input} if ":input" in control_tpl else [benign_input]).fetchall()
            benign_vulnerable = conn.execute(sink.replace(INPUT_MARK, benign_input)).fetchall()
        except sqlite3.Error as e:
            return checks + [_chk("benign_input_matches_defended_reference", False, type(e).__name__)], None
        benign_ok = benign_ref == benign_vulnerable
        checks.append(_chk("benign_input_matches_defended_reference", benign_ok,
                           "ordinary input agrees in vulnerable and parameterized sinks"))
        # the injected query (what the vulnerable sink does), confined by the authorizer
        try:
            got = conn.execute(injected).fetchall()
        except sqlite3.Error as e:
            # authorizer denial or syntax: outside the confined read sublanguage
            return checks + [_chk("injected_within_read_authorizer", False, f"{type(e).__name__}: {e}")], None
        effect = intended is not None and got != intended
        checks.append(_chk("injected_within_read_authorizer", True, f"{len(got)} row(s)"))
        checks.append(_chk("input_changes_read_result_vs_control", effect,
                           "injected read differs from the parameterized control (context effect shown)"))
        return checks, bool(effect and benign_ok)
    finally:
        conn.close()


_JINJA_ARITH = re.compile(r"^\s*\{\{\s*[0-9\+\-\*/\(\)\s]+\s*\}\}\s*$")


def _bounded_arithmetic(expr):
    """Closed, bounded arithmetic reference; no Python eval or exponentiation."""
    if len(expr) > 128:
        raise ValueError("arithmetic expression too long")
    tree = ast.parse(expr, mode="eval")
    if len(list(ast.walk(tree))) > 32:
        raise ValueError("arithmetic expression too complex")
    def visit(node):
        if isinstance(node, ast.Expression):
            return visit(node.body)
        if isinstance(node, ast.Constant) and type(node.value) is int and abs(node.value) <= 10000:
            return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
            value = visit(node.operand)
            result = value if isinstance(node.op, ast.UAdd) else -value
        elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv)):
            left, right = visit(node.left), visit(node.right)
            if isinstance(node.op, ast.Add): result = left + right
            elif isinstance(node.op, ast.Sub): result = left - right
            elif isinstance(node.op, ast.Mult): result = left * right
            elif isinstance(node.op, ast.Div): result = left / right
            else: result = left // right
        else:
            raise ValueError("arithmetic operator/value outside closed lab grammar")
        if abs(result) > 1000000000:
            raise ValueError("arithmetic result exceeds lab bound")
        return result
    return visit(tree)


def _jinja_behavior(unit, profile) -> tuple:
    """Fixture-only bounded arithmetic in a sandbox; no object access or eval."""
    payload = str(unit["payload_wire"])
    if profile["sink_template"] != INPUT_MARK:
        return [_chk("bounded_template_sink", False, "closed lab requires a literal {INPUT} source sink")], False
    if not _JINJA_ARITH.fullmatch(payload):
        return [_chk("closed_arithmetic_sublanguage", False, "not a pure {{ arithmetic }} expression")], False
    expr = payload.strip()[2:-2].strip()
    try:
        expected = str(_bounded_arithmetic(expr))
    except (ValueError, SyntaxError, ArithmeticError, RecursionError):
        return [_chk("bounded_arithmetic_reference", False, "expression outside bounded lab arithmetic")], False
    try:
        from jinja2.sandbox import SandboxedEnvironment
        from jinja2 import TemplateError
    except Exception:
        return [_chk("jinja2_available", False, "jinja2 not installed")], None
    env = SandboxedEnvironment()
    try:
        rendered = env.from_string(payload).render()
    except (TemplateError, ArithmeticError, ValueError):
        return [_chk("sandbox_render", False, "sandbox arithmetic failed")], False
    ok = rendered.strip() == expected
    defended = env.from_string("{{ value }}").render(value=payload)
    control_ok = defended == payload
    benign = str(profile.get("benign_input", "plain text"))
    if not re.fullmatch(r"[A-Za-z0-9 _-]{1,64}", benign):
        return [_chk("benign_template_input_bounded", False)], False
    benign_ok = env.from_string(benign).render() == env.from_string("{{ value }}").render(value=benign)
    return [_chk("jinja2_available", True),
            _chk("sandbox_render_matches_arithmetic", ok, f"rendered {rendered.strip()!r} vs {expected!r}"),
            _chk("data_only_reference_preserves_literal", control_ok, "bound value is not reinterpreted as template source"),
            _chk("benign_input_matches_data_only_reference", benign_ok)], bool(ok and control_ok and benign_ok)


# ── the public entry ────────────────────────────────────────────────────────────
def evaluate_unit(unit: dict, profile: dict, *, allow_lab_execution: bool = False) -> dict:
    """See the module docstring. Returns the closed result contract; never a label/authorization."""
    integ = _integrity(unit, profile)
    if not all(c["ok"] for c in integ):
        return _result("REJECTED", "integrity_only", integ,
                       ["unit/profile integrity failed; nothing evaluated"], unit, profile, ale=allow_lab_execution)

    # Origin guard: lab execution is only ever permitted on this round's synthetic fixtures.
    if allow_lab_execution and unit.get("fixture_synthetic") is not True:
        return _result("REJECTED", "integrity_only",
                       integ + [_chk("origin_guard", False, "allow_lab_execution requires fixture_synthetic is True")],
                       ["execution refused: only fixture_synthetic units may run in the lab (real package needs a "
                        "later authorization; there is no CLI for it)"], unit, profile, ale=allow_lab_execution)

    ctx = profile["context_kind"]
    numeric = ctx == "sqlite_numeric_expression"
    payload = str(unit["payload_wire"])
    checks = list(integ)
    lim = []

    # ---- contexts that are STATIC-ONLY regardless of allow_lab_execution ----
    if ctx == "html_fragment":
        checks += _static_html(payload)
        lim.append("structural parse only; NOT JavaScript execution or a browser test (no net/browser)")
        return _result("SUPPORTED", "static_context", checks, lim, unit, profile, ale=allow_lab_execution)

    if ctx == "posix_shell_unquoted_argument":
        checks += _static_shell(payload)
        lim += ["lexical diagnostic only; does NOT prove POSIX execution (no subprocess/shell/eval)",
                "functional validation needs an interpreter → UNSUPPORTED"]
        return _result("UNSUPPORTED", "static_context", checks, lim, unit, profile, ale=allow_lab_execution)

    if ctx in ("posix_file_path", "windows_file_path"):
        checks += _static_path(payload, profile, is_windows=ctx == "windows_file_path")
        lim.append("path normalization on strings only; no real-filesystem open/read/resolve")
        return _result("SUPPORTED", "static_context", checks, lim, unit, profile, ale=allow_lab_execution)

    if ctx == "php_local_include":
        lim.append("no PHP and no local inclusion demonstration permitted → UNSUPPORTED (no invented proof)")
        return _result("UNSUPPORTED", "unavailable", checks, lim, unit, profile, ale=allow_lab_execution)

    # ---- contexts with an optional confined behavioral demo ----
    if ctx in ("sqlite_quoted_value", "sqlite_numeric_expression"):
        checks += _static_sqlite_shape(payload, numeric)
        if not allow_lab_execution:
            lim.append("functional SQL NOT_RUN (allow_lab_execution=False); static shape only")
            return _result("NOT_RUN", "static_context", checks, lim, unit, profile, ale=allow_lab_execution)
        bchecks, supported = _sqlite_behavior(unit, profile, numeric)
        checks += bchecks
        if supported is None:
            lim.append("construction could not be confined to a read-only SELECT over the fixture table → UNSUPPORTED")
            return _result("UNSUPPORTED", "static_context", checks, lim, unit, profile, ale=allow_lab_execution)
        lim.append("in-memory read-only demo over a synthetic fixture table (authorizer-confined); a context "
                   "support, NOT dataset admission and NOT a label")
        return _result("SUPPORTED" if supported else "UNSUPPORTED", "local_behavior", checks, lim, unit, profile,
                       ale=allow_lab_execution)

    if ctx == "jinja2_template_source":
        if not allow_lab_execution:
            lim.append("functional render NOT_RUN (allow_lab_execution=False)")
            return _result("NOT_RUN", "static_context",
                           checks + [_chk("ssti_shape", "{{" in payload and "}}" in payload, "template delimiters present")],
                           lim, unit, profile, ale=allow_lab_execution)
        jchecks, supported = _jinja_behavior(unit, profile)
        checks += jchecks
        if supported is None:
            lim.append("jinja2 not installed → UNSUPPORTED (nothing installed)")
            return _result("UNSUPPORTED", "unavailable", checks, lim, unit, profile, ale=allow_lab_execution)
        lim.append("closed arithmetic sublanguage in a SandboxedEnvironment (no attributes/calls/imports); "
                   "confirms a template-evaluation context, NOT an RCE/sandbox-escape proof")
        return _result("SUPPORTED" if supported else "UNSUPPORTED", "local_behavior", checks, lim, unit, profile,
                       ale=allow_lab_execution)

    # unreachable given the integrity context_kind check
    return _result("UNSUPPORTED", "unavailable", checks, ["unhandled context_kind"], unit, profile, ale=allow_lab_execution)


if __name__ == "__main__":
    import json
    print(json.dumps(capabilities(), indent=2, sort_keys=True))
