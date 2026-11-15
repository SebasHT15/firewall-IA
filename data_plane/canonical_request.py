"""
firewall-IA — `canonical-request/v1`, the V5 model-input contract (stage 1, NOT integrated).

Implements V5-DATA-SPEC-r3 §5.2–§5.6 (FROZEN by D62; decisions D56, D57). One pure,
deterministic function turns the parsed parts of one HTTP request into either

    ACCEPT       the canonical model text + an audit record + signals
    REJECT       a contract reject R1(residual)…R8 with a stable reason + audit record
    UNSUPPORTED  outside the contract (CONNECT, signal S-CONNECT); policy decided at
                 integration. Not a reject and not a text.

Model text grammar (§5.2), nothing else ever reaches the model:

    {METHOD} {TARGET} HTTP/1.1\n
    [Content-Type: {value}\n]
    [\n{BODY}]                      only when BODY is non-empty

NOTHING here is wired into the gateway: `data_plane.py` keeps V4's D1 rendering (D56).
The generator and the gateway adapter that will both call `canonicalize` do not exist yet.

What this module deliberately does NOT do:
- no percent-decoding, re-encoding, hex-case change or dot-segment removal (§5.2, I6);
- no header other than `Content-Type` in the text, and no header VALUE in the audit
  record (names only); the absolute-form authority goes to the audit record only (D57);
- no truncation, ever (§5.5): an oversize request is R8 (or S-OVERSIZE), never cut;
- no tokenizer: the exact token count is injected by the caller (`Limits.count_tokens`),
  so the data plane (D33, no ML dependency) and the control plane share this module;
- no invented constants: `MAX_DECODED_BODY`, the token budget `B` and the bytes-per-token
  bound are PENDING (§11.2) and must be passed in `Limits` by the caller;
- R1 (wire framing) is NOT verified here. Only the residual framing facts that survive
  parsing (Transfer-Encoding value, Content-Length validity) are checked; R1 stays
  UNVERIFIED as a project control until the wire-level tests at integration (§5.3).

Escape-ambiguity limitation (§5.2, D62, accepted, NOT solved): an invalid octet rendered
as `\\xNN` is textually identical to a client that literally sent the four characters
`\\xNN`. The S-BODY-UTF8 / S-TARGET-NONASCII signals tell them apart for deterministic
layers and logs only; the model never sees signals. Such requests are outside the V5
training distribution.

Dependencies: standard library only for import, identity, gzip and deflate. `br` and
`zstd` need the third-party `brotli` and `zstandard` packages (Python 3.12 has no stdlib
decoder for either). Both are already installed in `.venv-dataplane` as dependencies of
mitmproxy 12.2.3. They are imported lazily; when one is missing the request is rejected
R3 with reason `content-coding-decoder-unavailable:<coding>` so the gap is never silent.
This is a stated deviation from the "stdlib-only" wording of §5.1 (see the stage report).
"""

import hashlib
import re
import urllib.parse
import zlib
from dataclasses import dataclass, field
from typing import Callable, Optional

CONTRACT_ID = "canonical-request/v1"
SPEC_ID = "V5-DATA-SPEC-r3"

ACCEPT = "ACCEPT"
REJECT = "REJECT"
UNSUPPORTED = "UNSUPPORTED"

# Size outcomes (§5.5). UNCHECKED = the caller supplied no budget (B is PENDING).
SIZE_UNCHECKED = "UNCHECKED"
SIZE_WITHIN = "WITHIN_BUDGET"
SIZE_OVER = "OVER_BUDGET"
SIZE_NEEDS_EXACT_COUNT = "NEEDS_EXACT_COUNT"  # data plane: between B and max_bpt*B bytes

# §2.2 training-scope media types (APPROVED D56; the list itself is PROPOSED in r3).
V5_TRAINING_MEDIA_TYPES = frozenset({
    "application/x-www-form-urlencoded",
    "application/json",
    "text/plain",
})

# The frozen S-list (§5.3). IMPLEMENTED_SIGNALS is what this stage can emit; the rest
# need header values or destination context owned by the integration layer (D57).
ALL_SIGNALS = frozenset({
    "S-ENC-MULTI", "S-ENC-U", "S-ENC-NUL", "S-UTF8-OVERLONG",
    "S-BODY-UTF8", "S-CHARSET", "S-CT-MISMATCH", "S-CT-MALFORMED", "S-CT-NONASCII",
    "S-TARGET-NONASCII", "S-MEDIA-UNSUPPORTED",
    "S-JWT-ALG-NONE", "S-JWT-EMPTY-SIG", "S-JWT-KID", "S-JWT-KEYURL",
    "S-ORIGIN-CROSS", "S-OVERSIZE", "S-CT-ABSENT", "S-CONNECT",
})
DEFERRED_SIGNALS = frozenset({
    "S-JWT-ALG-NONE", "S-JWT-EMPTY-SIG", "S-JWT-KID", "S-JWT-KEYURL", "S-ORIGIN-CROSS",
})
IMPLEMENTED_SIGNALS = ALL_SIGNALS - DEFERRED_SIGNALS

# Reject ids and the fixed order in which the checks run; the first failing check wins,
# so the outcome and its reason are a deterministic function of the parts.
REJECT_ORDER = ("R6", "R5", "R4", "R7", "R1", "R2", "R3", "R8")

# ───────────────────────────── grammar pieces ─────────────────────────────
# RFC 9110 §5.6.2 token.
_TCHAR = rb"!#$%&'*+\-.^_`|~0-9A-Za-z"
_TOKEN_RE = re.compile(rb"[" + _TCHAR + rb"]+\Z")
# RFC 9112 §3.2: no SP, no CTL (0x00-0x1F), no DEL in the request-target (R5).
_TARGET_FORBIDDEN_RE = re.compile(rb"[\x00-\x20\x7f]")
_ABSOLUTE_FORM_RE = re.compile(rb"[A-Za-z][A-Za-z0-9+.\-]*://")
# RFC 9110 §8.3.1 media-type, with §5.6.6 parameters (empty parameters allowed) and
# §5.6.4 quoted-string (obs-text allowed). Applied to the ISO-8859-1 decoded value.
_TOKEN_S = r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+"
_QSTRING_S = r'"(?:[\t \x21\x23-\x5b\x5d-\x7e\x80-\xff]|\\[\t \x21-\x7e\x80-\xff])*"'
_PARAM_S = _TOKEN_S + r"=(?:" + _TOKEN_S + r"|" + _QSTRING_S + r")"
# Each `;` iteration is "OWS ; [OWS parameter]" and whitespace after the last `;` is matched
# once at the end, so no whitespace can be split between two iterations: the match is linear
# (an ambiguous form backtracked exponentially on `a/b` + "; "*40 + "@", found in review).
_MEDIA_TYPE_RE = re.compile(
    r"(" + _TOKEN_S + r")/(" + _TOKEN_S + r")((?:[ \t]*;(?:[ \t]*" + _PARAM_S + r")?)*)[ \t]*\Z")
_PARAM_RE = re.compile(r"[ \t]*;(?:[ \t]*(" + _TOKEN_S + r")=(" + _TOKEN_S + r"|" + _QSTRING_S + r"))?")
_OWS = " \t"

# Signal detectors, applied to the raw target bytes and to the decoded body bytes as
# whole strings (percent-decoding is local, so this equals a per-value evaluation).
_PCT_RE = re.compile(rb"%[0-9A-Fa-f]{2}")
_PCT_U_RE = re.compile(rb"%[uU][0-9A-Fa-f]{4}")
# RFC 3629 §3/§10: overlong forms (C0/C1 lead; E0 followed by 80-9F; F0 followed by 80-8F).
_OVERLONG_RE = re.compile(
    rb"[\xc0\xc1][\x80-\xbf]|\xe0[\x80-\x9f][\x80-\xbf]|\xf0[\x80-\x8f][\x80-\xbf]{2}")

_KNOWN_CODINGS = ("identity", "gzip", "x-gzip", "deflate", "br", "zstd")
# Transfer codings defined by RFC 9112 §7 plus the x- aliases of §7.2 (P12, D63). Only names
# from these lists reach the audit record; anything else (including content codings this
# module cannot decode) is logged as "<other>", never as the client-chosen string.
_KNOWN_TRANSFER_CODINGS = ("chunked", "compress", "deflate", "gzip", "x-compress", "x-gzip")


def _coding_name(c, known):
    return c if c in known else "<other>"


# ───────────────────────────── public types ─────────────────────────────
@dataclass(frozen=True)
class RequestParts:
    """What an adapter hands to `canonicalize`.

    method        request method bytes as received
    target        request-target bytes as received (origin-, absolute-, asterisk- or
                  authority-form; HTTP/2 adapters pass `:path`)
    http_version  received version string, audit only (e.g. "HTTP/1.0", "HTTP/2.0")
    headers       (name, value) byte pairs in received order, names in received case
    body          message body after transfer decoding (de-chunked), still content-coded
    """
    method: bytes
    target: bytes
    http_version: str = "HTTP/1.1"
    headers: tuple = ()
    body: bytes = b""

    def __post_init__(self):
        if not isinstance(self.method, bytes) or not isinstance(self.target, bytes):
            raise TypeError("method and target must be bytes")
        if not isinstance(self.http_version, str):
            raise TypeError("http_version must be str")
        if not isinstance(self.body, bytes):
            raise TypeError("body must be bytes")
        headers = tuple(self.headers)
        for pair in headers:
            if (not isinstance(pair, tuple) or len(pair) != 2
                    or not isinstance(pair[0], bytes) or not isinstance(pair[1], bytes)):
                raise TypeError("headers must be (bytes, bytes) pairs")
        object.__setattr__(self, "headers", headers)


@dataclass(frozen=True)
class Limits:
    """Caller-supplied limits. Every value is PENDING in r3 §11.2, so none has a default.

    max_decoded_body    hard decompression / body cap in bytes (R8 for any media type).
                        PENDING until gateway integration; must then be >= 48·B (§5.5).
    token_budget        B in tokens. None = size not checked here (SIZE_UNCHECKED).
    count_tokens        exact content-token counter (control plane / generator). When
                        given, it decides the size outcome.
    max_bytes_per_token data-plane reverse bound (V4 measurement: 48, to be re-verified
                        on the V5 tokenizer). Used only when count_tokens is None.
    """
    max_decoded_body: int
    token_budget: Optional[int] = None
    count_tokens: Optional[Callable[[str], int]] = None
    max_bytes_per_token: Optional[int] = None

    def __post_init__(self):
        for name in ("max_decoded_body", "token_budget", "max_bytes_per_token"):
            v = getattr(self, name)
            if name != "max_decoded_body" and v is None:
                continue
            if isinstance(v, bool) or not isinstance(v, int) or v <= 0:
                raise ValueError(f"{name} must be a positive int, got {v!r}")
        if self.count_tokens is not None and not callable(self.count_tokens):
            raise ValueError("count_tokens must be callable")
        if self.token_budget is None and (self.count_tokens or self.max_bytes_per_token):
            raise ValueError("count_tokens / max_bytes_per_token need token_budget")


@dataclass(frozen=True)
class CanonicalResult:
    outcome: str                      # ACCEPT | REJECT | UNSUPPORTED
    text: Optional[str]               # model text, only for ACCEPT
    reject: Optional[str]             # R1…R8, only for REJECT
    reason: Optional[str]             # stable machine-readable reason
    signals: tuple                    # sorted, no enforcement effect (D57)
    size: str                         # SIZE_* (ACCEPT only; UNCHECKED otherwise)
    audit: dict = field(compare=True)  # never holds header values, target or body


class _Reject(Exception):
    def __init__(self, rid, reason):
        super().__init__(rid, reason)
        self.rid, self.reason = rid, reason


# ───────────────────────────── helpers ─────────────────────────────
def _latin1(b):
    return b.decode("latin-1")


def _render_bytes(b):
    """Strict UTF-8; invalid octets become `\\xNN` (lowercase hex, Python backslashreplace)."""
    try:
        return b.decode("utf-8"), True
    except UnicodeDecodeError:
        return b.decode("utf-8", "backslashreplace"), False


def _list_elements(values):
    """RFC 9110 §5.6.1 list syntax over several field lines; empty elements dropped."""
    out = []
    for v in values:
        for elem in _latin1(v).split(","):
            elem = elem.strip(_OWS)
            if elem:
                out.append(elem)
    return out


def _header_values(headers, lname):
    return [v for n, v in headers if n.lower() == lname]


def _classify_target(method, target):
    """Returns (form, rendered_target_bytes, audit_extra)."""
    if method == b"CONNECT":
        return "authority", None, {}
    if target.startswith(b"/"):
        return "origin", target, {}
    if target == b"*":
        return "asterisk", target, {}
    m = _ABSOLUTE_FORM_RE.match(target)
    if m:
        scheme = target[:m.end() - 3]
        rest = target[m.end():]
        cut = len(rest)
        for sep in (b"/", b"?", b"#"):
            i = rest.find(sep)
            if i != -1:
                cut = min(cut, i)
        authority, path_query = rest[:cut], rest[cut:]
        userinfo = b"@" in authority
        host = authority.rsplit(b"@", 1)[-1]
        if not path_query.startswith(b"/"):
            path_query = b"/" + path_query  # RFC 9112 §3.2.1: empty path is "/"
        return "absolute", path_query, {
            "scheme": _latin1(scheme).lower(),
            "authority": host.decode("utf-8", "backslashreplace"),
            "authority_userinfo_present": userinfo,
        }
    # Not one of the RFC 9112 §3.2 forms. No reject exists for this in r3 §5.3, so it is
    # rendered byte-preserved and only marked in the audit record.
    return "other", target, {}


def _parse_media_type(ct):
    """ct = trimmed ISO-8859-1 value. Returns (type/subtype lowercased, params) or None."""
    m = _MEDIA_TYPE_RE.match(ct)
    if not m:
        return None
    params = []
    for pm in _PARAM_RE.finditer(m.group(3)):
        if pm.group(1):
            val = pm.group(2)
            if val.startswith('"'):
                val = re.sub(r"\\(.)", r"\1", val[1:-1])
            params.append((pm.group(1).lower(), val))
    return f"{m.group(1)}/{m.group(2)}".lower(), params


# ───────────────────────────── framing (residual R1, R2) ─────────────────────────────
def _check_framing(parts, audit):
    te_fields = _header_values(parts.headers, b"transfer-encoding")
    cl_fields = _header_values(parts.headers, b"content-length")
    te = [e.split(";", 1)[0].strip(_OWS).lower() for e in _list_elements(te_fields)]
    audit["framing"] = {
        "transfer_encoding": [_coding_name(c, _KNOWN_TRANSFER_CODINGS) for c in te],
        "transfer_encoding_fields": len(te_fields),
        "content_length_fields": len(cl_fields),
        "body_bytes_received": len(parts.body),
    }
    # R1 residual facts (RFC 9112 §6.1-§6.3). The wire-level R1 vectors never reach here.
    if te_fields and cl_fields:
        raise _Reject("R1", "framing-te-and-cl")
    if len(te_fields) > 1:
        raise _Reject("R1", "framing-multiple-te")
    if te_fields:
        if parts.http_version.upper() == "HTTP/1.0":
            raise _Reject("R1", "framing-te-on-http10")
        if not te:
            raise _Reject("R1", "framing-te-empty")
        if "chunked" in te and (te[-1] != "chunked" or te.count("chunked") > 1):
            raise _Reject("R1", "framing-chunked-not-final")
        if any(c != "chunked" for c in te):
            raise _Reject("R2", "transfer-coding-not-chunked")
    if cl_fields:
        if len(cl_fields) > 1:
            raise _Reject("R1", "framing-duplicate-cl")
        value = cl_fields[0].strip(b" \t")
        if not re.fullmatch(rb"[0-9]+", value):
            raise _Reject("R1", "framing-invalid-cl")
        if int(value) != len(parts.body):
            raise _Reject("R1", "framing-cl-body-mismatch")
        audit["framing"]["content_length"] = int(value)


# ───────────────────────────── content codings (R3, R8 cap) ─────────────────────────────
# Resource bounds (D63). For every coding the decoded output is checked against the cap after
# each bounded step, and work is linear in input + output:
#   * zlib (gzip, deflate): `max_length` makes each step's output exact, so out <= cap + 1.
#   * br: input fed in 32 KiB slices; each step asks for at most one output block
#     (`output_buffer_limit=1`); Brotli 1.2.0 then returns <= 32,752 bytes per step, so
#     out <= cap + 32,752. The ring buffer is bounded
#     by the format (window <= 16 MiB; the large-window extension is off by default).
#   * zstd: input fed in 64-byte slices. A block decodes to <= 128 KiB and takes >= 4 input
#     bytes, so out <= cap + 17 x 128 KiB. The declared window is not limited here: its buffer
#     is only touched as output is produced, which the cap bounds (measured, D63).
#   * Several members / frames are walked by offset with slices that grow from 64 bytes, so a
#     body of many tiny members is never re-copied once per member (no quadratic time).
_SLICE_MIN = 64
_SLICE_MAX = 64 * 1024
_ZSTD_SLICE = 64
_BR_SLICE = 32 * 1024
_NON_NUL_RE = re.compile(rb"[^\x00]")


def _check_cap(out, cap):
    if len(out) > cap:
        raise _Reject("R8", "decoded-body-over-cap")


def _zlib_member(mv, pos, wbits, cap, out):
    """Decode one zlib/gzip/raw-deflate stream starting at `pos` into `out`; returns its end."""
    d = zlib.decompressobj(wbits=wbits)
    step = _SLICE_MIN
    while True:
        chunk = mv[pos:pos + step]
        if not chunk:
            raise zlib.error("truncated stream")
        pos += len(chunk)
        while chunk:
            out += d.decompress(chunk, cap + 1 - len(out))
            _check_cap(out, cap)
            if d.eof:
                return pos - len(d.unused_data)
            chunk = d.unconsumed_tail
        step = min(step * 2, _SLICE_MAX)


def _decode_gzip(data, cap):
    # CPython gzip.decompress semantics: several members, NUL padding between/after them.
    mv, out, pos = memoryview(data), bytearray(), 0
    while True:
        pos = _zlib_member(mv, pos, 31, cap, out)
        m = _NON_NUL_RE.search(data, pos)
        if m is None:
            return bytes(out)
        pos = m.start()


def _decode_deflate(data, cap):
    # RFC 9110 §8.4.1.2: "deflate" is zlib-wrapped; it notes that some implementations send
    # raw deflate, so (like mitmproxy) a raw stream is accepted when the zlib header fails.
    mv = memoryview(data)
    try:
        out = bytearray()
        end = _zlib_member(mv, 0, 15, cap, out)
    except zlib.error:
        out = bytearray()
        end = _zlib_member(mv, 0, -15, cap, out)
    if end != len(data):
        raise zlib.error("trailing data after deflate stream")
    return bytes(out)


def _decode_br(data, cap):
    import brotli
    d = brotli.Decompressor()
    out, pos = bytearray(), 0
    while not d.is_finished():
        # Input goes in slices (each call's cost grows with the input the decoder still buffers,
        # so feeding the whole body at once was quadratic); output is drained one block per call.
        if pos < len(data) and d.can_accept_more_data():
            chunk = data[pos:pos + _BR_SLICE]
            pos += len(chunk)
            out += d.process(chunk, output_buffer_limit=1)
        else:
            step = d.process(b"", output_buffer_limit=1)
            if not step:  # no output, no input left to give: the stream is truncated
                raise ValueError("truncated brotli stream")
            out += step
        _check_cap(out, cap)
    if pos < len(data):
        raise ValueError("trailing data after brotli stream")
    return bytes(out)


def _decode_zstd(data, cap):
    import zstandard
    dctx = zstandard.ZstdDecompressor()
    mv, out, pos = memoryview(data), bytearray(), 0
    while pos < len(data):  # one iteration per frame; a truncated frame never reaches eof
        obj = dctx.decompressobj()
        while not obj.eof:
            chunk = mv[pos:pos + _ZSTD_SLICE]
            if not chunk:
                raise ValueError("truncated zstd frame")
            pos += len(chunk)
            out += obj.decompress(chunk)
            _check_cap(out, cap)
        pos -= len(obj.unused_data)
    return bytes(out)


_DECODERS = {"gzip": _decode_gzip, "x-gzip": _decode_gzip, "deflate": _decode_deflate,
             "br": _decode_br, "zstd": _decode_zstd}
_DECODER_MODULE = {"br": "brotli", "zstd": "zstandard"}


def decoder_available(coding):
    """True when this environment can decode `coding` (br/zstd need third-party modules)."""
    mod = _DECODER_MODULE.get(coding)
    if mod is None:
        return coding in _KNOWN_CODINGS
    try:
        __import__(mod)
    except ImportError:
        return False
    return True


def _decode_body(parts, cap, audit):
    codings = [c.lower() for c in _list_elements(_header_values(parts.headers, b"content-encoding"))]
    audit["content_codings"] = [_coding_name(c, _KNOWN_CODINGS) for c in codings]
    for c in codings:
        if c not in _KNOWN_CODINGS:
            raise _Reject("R3", "content-coding-unknown")
    body = parts.body
    # R8 applies to the DECODED body (§5.3): an identity body is its own decoded body; a coded
    # body is bounded by every decoder's output limit, never by its received length.
    if all(c == "identity" for c in codings) and len(body) > cap:
        raise _Reject("R8", "decoded-body-over-cap")
    if body:  # nothing to decode in an empty body; stray codings are recorded, not failed
        for c in reversed(codings):
            if c == "identity":
                continue
            if not decoder_available(c):
                raise _Reject("R3", f"content-coding-decoder-unavailable:{c}")
            try:
                body = _DECODERS[c](body, cap)
            except _Reject:
                raise
            except Exception:  # every library failure is a decode failure (R3)
                raise _Reject("R3", f"content-coding-decode-failure:{c}")
    audit["decoded_body_bytes"] = len(body)
    return body


# ───────────────────────────── signals ─────────────────────────────
def _encoding_signals(data, signals):
    if _PCT_U_RE.search(data):
        signals.add("S-ENC-U")
    if b"%00" in data:
        signals.add("S-ENC-NUL")
    once = urllib.parse.unquote_to_bytes(data) if b"%" in data else data
    if once is not data and _PCT_RE.search(once):
        signals.add("S-ENC-MULTI")
    if _OVERLONG_RE.search(data) or (once is not data and _OVERLONG_RE.search(once)):
        signals.add("S-UTF8-OVERLONG")


def _json_parses(text):
    def _reject_constant(_):
        raise ValueError("non-standard JSON constant")
    import json
    try:
        json.loads(text, parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        return False
    return True


# ───────────────────────────── the contract ─────────────────────────────
def canonicalize(parts, limits):
    """Pure function: RequestParts × Limits → CanonicalResult. Never raises on input data
    (I7); raises only for programming errors (wrong types, invalid Limits)."""
    if not isinstance(parts, RequestParts):
        raise TypeError("parts must be RequestParts")
    if not isinstance(limits, Limits):
        raise TypeError("limits must be Limits")
    signals = set()
    audit = {
        "contract": CONTRACT_ID,
        "spec": SPEC_ID,
        "http_version_received": parts.http_version,
        "header_names": [_latin1(n) for n, _ in parts.headers],
        "body_bytes_received": len(parts.body),
    }

    def _done(outcome, *, text=None, rid=None, reason=None, size=SIZE_UNCHECKED):
        if text is not None:
            raw = text.encode("utf-8")
            audit["text_bytes"] = len(raw)
            audit["text_sha256"] = hashlib.sha256(raw).hexdigest()
        return CanonicalResult(outcome, text, rid, reason, tuple(sorted(signals)), size, audit)

    try:
        # R6 — method is an RFC 9110 token.
        if not _TOKEN_RE.match(parts.method):
            raise _Reject("R6", "method-not-token")
        method = parts.method.decode("ascii")
        audit["method"] = method
        # R5 — no SP / CTL / DEL in the target.
        if _TARGET_FORBIDDEN_RE.search(parts.target):
            raise _Reject("R5", "target-sp-ctl-del")
        # R4 — CR, LF or NUL in any field value (obs-text is valid, HTAB is valid).
        for _, value in parts.headers:
            if re.search(rb"[\r\n\x00]", value):
                raise _Reject("R4", "field-value-cr-lf-nul")
        # R7 — more than one Content-Type field.
        ct_fields = _header_values(parts.headers, b"content-type")
        if len(ct_fields) > 1:
            raise _Reject("R7", "duplicate-content-type")
        # R1 (residual) and R2.
        _check_framing(parts, audit)
        # CONNECT (authority-form): a tunnel, outside the V5 contract.
        form, target, extra = _classify_target(parts.method, parts.target)
        audit["target_form"] = form
        audit.update(extra)
        if form == "authority":
            signals.add("S-CONNECT")
            return _done(UNSUPPORTED, reason="connect-outside-contract")
        # R3 and the R8 decompression cap.
        body = _decode_body(parts, limits.max_decoded_body, audit)
    except _Reject as r:
        audit["reject"] = r.rid
        return _done(REJECT, rid=r.rid, reason=r.reason)

    # ── rendering (§5.2) ──
    target_text, target_utf8 = _render_bytes(target)
    if any(b >= 0x80 for b in target):
        signals.add("S-TARGET-NONASCII")
    audit["target_utf8"] = target_utf8
    _encoding_signals(target, signals)

    lines = [f"{method} {target_text} HTTP/1.1\n"]
    media = None
    if ct_fields:
        ct = _latin1(ct_fields[0]).strip(_OWS)
        if any(ord(ch) >= 0x80 for ch in ct):
            signals.add("S-CT-NONASCII")
        parsed = _parse_media_type(ct)
        if parsed is None:
            signals.add("S-CT-MALFORMED")
        else:
            media, params = parsed
            charsets = [v.lower() for k, v in params if k == "charset"]
            if any(cs not in ("utf-8", "us-ascii") for cs in charsets):
                signals.add("S-CHARSET")
        audit["media_type"] = media
        lines.append(f"Content-Type: {ct}\n")

    if body:
        body_text, body_utf8 = _render_bytes(body)
        if not body_utf8:
            signals.add("S-BODY-UTF8")
        _encoding_signals(body, signals)
        if not ct_fields:
            signals.add("S-CT-ABSENT")
        if media == "application/json" and not (body_utf8 and _json_parses(body_text)):
            signals.add("S-CT-MISMATCH")
        lines.append("\n" + body_text)
        audit["body_utf8"] = body_utf8
    # §2.2 / §5.2 (P5, D63): a declared Content-Type outside §2.2 (or malformed) is out of
    # scope even with an empty body; without Content-Type only a body-less request is in scope.
    in_scope = (media in V5_TRAINING_MEDIA_TYPES) if ct_fields else not body
    if not in_scope:
        signals.add("S-MEDIA-UNSUPPORTED")
    audit["media_in_training_scope"] = in_scope
    text = "".join(lines)

    # ── size (§5.5): R8 inside §2.2, S-OVERSIZE outside; never truncated ──
    size = _size(text, limits)
    if size == SIZE_OVER:
        if in_scope:
            audit["reject"] = "R8"
            audit["text_bytes"] = len(text.encode("utf-8"))
            return CanonicalResult(REJECT, None, "R8", "text-over-token-budget",
                                   tuple(sorted(signals)), size, audit)
        signals.add("S-OVERSIZE")
    return _done(ACCEPT, text=text, size=size)


def _size(text, limits):
    budget = limits.token_budget
    if budget is None:
        return SIZE_UNCHECKED
    if limits.count_tokens is not None:
        n = limits.count_tokens(text)
        return SIZE_OVER if n > budget else SIZE_WITHIN
    if limits.max_bytes_per_token is not None:
        n_bytes = len(text.encode("utf-8"))
        if n_bytes <= budget:  # <= 1 token per byte
            return SIZE_WITHIN
        if n_bytes > limits.max_bytes_per_token * budget:  # >= 1 token per max_bpt bytes
            return SIZE_OVER
        return SIZE_NEEDS_EXACT_COUNT
    return SIZE_UNCHECKED


# ───────────────────────────── reference parser (I3, I8) ─────────────────────────────
def parse_canonical(text):
    """Reference parser of the canonical grammar: text → RequestParts (version HTTP/1.1).

    Splits only on "\\n" (never str.splitlines(): U+0085, U+2028 and friends are ordinary
    characters of the target, the Content-Type value or the body). Raises ValueError on a
    string that is not in the canonical grammar. Content escapes (`\\xNN`) come back as
    literal text: that is the accepted escape-ambiguity limitation (I8)."""
    nl = text.find("\n")
    if nl == -1:
        raise ValueError("no request line")
    line, rest = text[:nl], text[nl + 1:]
    suffix = " HTTP/1.1"
    if not line.endswith(suffix) or " " not in line[:-len(suffix)]:
        raise ValueError("malformed request line")
    method, target = line[:-len(suffix)].split(" ", 1)
    if " " in target:
        raise ValueError("space in target")
    headers = []
    prefix = "Content-Type: "
    if rest.startswith(prefix):
        nl = rest.find("\n")
        if nl == -1:
            raise ValueError("unterminated Content-Type line")
        headers.append((b"Content-Type", rest[len(prefix):nl].encode("latin-1")))
        rest = rest[nl + 1:]
    if rest:
        if not rest.startswith("\n") or len(rest) == 1:
            raise ValueError("body must follow one blank line and be non-empty")
        body = rest[1:].encode("utf-8")
    else:
        body = b""
    return RequestParts(method=method.encode("ascii"), target=target.encode("utf-8"),
                        http_version="HTTP/1.1", headers=tuple(headers), body=body)
