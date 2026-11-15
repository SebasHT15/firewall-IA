"""
firewall-IA — thin adapter: one mitmproxy request -> an immutable RequestSnapshot, and an
ADMITTED snapshot -> the canonical-request/v1 `cr.RequestParts`.

SHADOW / OBSERVE-ONLY, PREPARATION for issue #68. Nothing here enforces or forwards; it only
builds the input the canonical observer sends to its worker. V4 via /classify stays the only
decision (D4, D25, D34, D43).

ONE canonicalize, no duplication (invariant I1). This module never normalizes, decodes, lowercases
or re-encodes anything: it copies the RAW received parts and hands them, unchanged, to
`canonical_request.canonicalize` exactly as `scripts/dataset/v5_render.py` does (object identity of
`cr.canonicalize`). All decoding, the R3/R8 decode cap, signals and size live in canonical_request.

WHY raw_content AND NOT get_content()/.content/.text (verified against mitmproxy 12.2.3
`mitmproxy/http.py`):
  * `req.raw_content`  -> body after TRANSFER decoding (de-chunked) but STILL content-coded, and it
                          NEVER raises. This is exactly `cr.RequestParts.body`'s contract. `None`
                          means a missing/streamed body; `b""` means a present-but-empty body. The
                          two are DISTINCT and this adapter keeps them distinct (no `or b""`).
  * `req.get_content()`/`.content`/`.text` -> UNDO the content coding (and `.text` the charset).
                          Feeding already-decoded bytes to canonicalize, while the Content-Encoding
                          header is still present, would make it decode a second time (R3 failure)
                          AND bypass the project-owned R8 decompression cap. So they are NEVER used.

TARGET FORMS (verified against `mitmproxy/net/http/http1/read.py:166-201`): mitmproxy parses the
request line and splits an absolute-form target, lowercasing the scheme and moving the authority into
`req.data.authority`, so `req.data.path` is the FAITHFUL raw target ONLY for origin-form and
asterisk-form. Absolute-form and authority-form (CONNECT) cannot be recovered from `data.path`
without re-synthesizing wire facts, which this adapter refuses to do: such a request is marked
out-of-scope and never submitted. We do NOT change tunnel policy or protocol support.

CONNECT LIFECYCLE (not assumed): a CONNECT request may or may not surface at mitmproxy's HTTP
`request` hook depending on proxy mode (for intercepted HTTPS the INNER requests get their own
hooks; the CONNECT itself is often handled by the proxy layer and need not reach an addon's
`request`). This adapter therefore does not rely on seeing CONNECT; if one is passed it is marked
`connect_authority_form` and left alone.

HTTP VERSION: only HTTP/1.0 and HTTP/1.1 are in scope. HTTP/2 / HTTP/3 (and anything else) carry a
`unsupported_http_version` marker: their request line, pseudo-headers and framing differ and this
observation slice does not model them. This does not change what protocols the gateway supports.

NO LOGGING of request bytes anywhere in this module.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Optional

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:   # -I drops the script directory; the worker imports this module
    sys.path.insert(0, HERE)

import canonical_request as cr  # noqa: E402  (the ONE canonicalize, I1)

CONTRACT_ID = cr.CONTRACT_ID   # "canonical-request/v1"

# Request-target forms (RFC 9112 §3.2).
FORM_ORIGIN = "origin"
FORM_ASTERISK = "asterisk"
FORM_ABSOLUTE = "absolute"
FORM_AUTHORITY = "authority"   # CONNECT
FORM_OTHER = "other"
FORMS = (FORM_ORIGIN, FORM_ASTERISK, FORM_ABSOLUTE, FORM_AUTHORITY, FORM_OTHER)

# Only these two forms give a faithfully-recoverable raw target from req.data.path.
_IN_SCOPE_FORMS = frozenset({FORM_ORIGIN, FORM_ASTERISK})
_SUPPORTED_VERSIONS = frozenset({"HTTP/1.0", "HTTP/1.1"})

# Closed scope-reason tokens (safe to log).
SCOPE_ABSOLUTE = "absolute_form"
SCOPE_CONNECT = "connect_authority_form"
SCOPE_OTHER_FORM = "unrecognized_target_form"
SCOPE_UNSUPPORTED_VERSION = "unsupported_http_version"


@dataclass(frozen=True)
class RequestSnapshot:
    """An immutable copy of the raw received parts of one request, plus scope metadata.

    `snapshot_id`     a caller-supplied id, unique within the observer session, used ONLY to
                      correlate a worker reply with the request that produced it.
    `form`            the request-target form (one of FORMS).
    `http_version`    the received version string, e.g. "HTTP/1.1" (audit only in canonicalize).
    `version_supported`  http_version in {HTTP/1.0, HTTP/1.1}.
    `in_scope`        True only when the form is origin/asterisk AND the version is supported;
                      only an in-scope snapshot may be converted to RequestParts and submitted.
    `scope_reason`    a closed token naming why not in scope, or None when in scope.
    `method`          raw method bytes as received (req.data.method).
    `target`          raw request-target bytes (req.data.path) for origin/asterisk forms; None
                      otherwise (absolute/authority/other: not faithfully recoverable).
    `headers`         ((name, value), ...) byte pairs in received order, case and repeats.
    `body`            req.raw_content: de-chunked, still content-coded; None = missing/streamed,
                      b"" = present but empty. The two are kept distinct.
    """
    snapshot_id: int
    form: str
    http_version: str
    version_supported: bool
    in_scope: bool
    scope_reason: Optional[str]
    method: bytes
    target: Optional[bytes]
    headers: tuple
    body: Optional[bytes]

    @property
    def body_available(self) -> bool:
        """False when the body is missing/streamed (None). A present empty body (b"") is True."""
        return self.body is not None


def _classify_form(req) -> str:
    """Map a mitmproxy request to a target form without touching the wire target itself.

    Uses `req.first_line_format` (mitmproxy's own parse: 'authority' for CONNECT, 'absolute' when an
    authority is present, else 'relative') and distinguishes asterisk-form within 'relative'."""
    try:
        fmt = req.first_line_format
    except Exception:  # noqa: BLE001 — a non-request object: treat as unrecognized
        return FORM_OTHER
    if fmt == "authority":
        return FORM_AUTHORITY
    if fmt == "absolute":
        return FORM_ABSOLUTE
    if fmt == "relative":
        # origin-form starts with "/"; asterisk-form is exactly "*".
        raw = req.data.path
        if raw == b"*":
            return FORM_ASTERISK
        if isinstance(raw, bytes) and raw.startswith(b"/"):
            return FORM_ORIGIN
        return FORM_OTHER
    return FORM_OTHER


@dataclass(frozen=True)
class RawClassification:
    """The cheap facts about a request that the observer needs BEFORE deciding whether to
    materialize the full snapshot: enough to answer BODY_UNAVAILABLE and OUT_OF_SCOPE and to run the
    admission scan, without building the header tuple or copying the body. `method`/`target` are
    small byte fields read directly from `req.data`; `body_is_none` is a cheap `is None` test on
    `req.raw_content` that neither decodes nor copies the body."""
    form: str
    http_version: str
    version_supported: bool
    in_scope: bool
    scope_reason: Optional[str]
    body_is_none: bool
    method: bytes
    target: Optional[bytes]


def classify_raw(req) -> RawClassification:
    """Cheap classification: no header-tuple materialization, no body copy. Reads only the small
    request-line fields and the `raw_content is None` flag."""
    method = bytes(req.data.method)
    http_version = req.http_version
    if not isinstance(http_version, str):
        http_version = bytes(http_version).decode("ascii", "replace")
    version_supported = http_version in _SUPPORTED_VERSIONS
    body_is_none = req.raw_content is None   # no decode, no copy

    form = _classify_form(req)
    if form in _IN_SCOPE_FORMS:
        target: Optional[bytes] = bytes(req.data.path)
    else:
        target = None   # absolute/authority/other: not faithfully recoverable; do not reconstruct

    if form not in _IN_SCOPE_FORMS:
        scope_reason = {FORM_ABSOLUTE: SCOPE_ABSOLUTE, FORM_AUTHORITY: SCOPE_CONNECT}.get(
            form, SCOPE_OTHER_FORM)
        in_scope = False
    elif not version_supported:
        scope_reason = SCOPE_UNSUPPORTED_VERSION
        in_scope = False
    else:
        scope_reason = None
        in_scope = True
    return RawClassification(form=form, http_version=http_version,
                             version_supported=version_supported, in_scope=in_scope,
                             scope_reason=scope_reason, body_is_none=body_is_none, method=method,
                             target=target)


def admit_raw(req, caps, classification: RawClassification) -> Optional[str]:
    """Scan the raw request against the admission caps with EARLY EXIT, WITHOUT materializing the
    adapter's header tuple. Returns a DROP token, or None to admit. `caps` is duck-typed (it only
    needs the max_* integer attributes), so the observer owns the concrete cap values.

    This iterates `req.headers.fields` and stops at the first header that pushes the count or the
    cumulative name+value byte total over the cap; it does not build a list of `(bytes, bytes)`
    pairs to count them. `len(req.raw_content)` reads the already-received body's length (the bytes
    are in memory regardless; `len` neither copies nor decodes them)."""
    if len(classification.method) > caps.max_method_bytes:
        return "method_too_long"
    target = classification.target
    if target is None or len(target) > caps.max_target_bytes:
        return "target_too_long"
    body = req.raw_content
    if body is None or len(body) > caps.max_body_bytes:
        return "body_too_large"
    count = 0
    total = 0
    for name, value in req.headers.fields:
        count += 1
        if count > caps.max_header_count:
            return "too_many_headers"       # early exit: no further fields are consumed
        total += len(name) + len(value)
        if total > caps.max_header_bytes:
            return "header_bytes_exceeded"
    return None


def build_snapshot(req, snapshot_id: int) -> RequestSnapshot:
    """Materialize a RequestSnapshot from a mitmproxy `http.Request`. Called only for ADMITTED
    requests (after classify_raw + admit_raw), so this is where the header tuple is built.
    `snapshot_id` is supplied by the caller (the observer's monotonic counter) and only used for
    reply correlation.

    This copies raw bytes; it does not decode, normalize or render anything. `bytes(x)` on a value
    that is already `bytes` returns the SAME object in CPython (no copy): the calls here normalize
    type, they do not duplicate the body. It never raises for a well-formed mitmproxy request; the
    observer still guards the call (ADAPTER_ERROR) because the object is third-party."""
    c = classify_raw(req)
    headers = tuple((bytes(n), bytes(v)) for n, v in req.headers.fields)
    # raw_content: None stays None (missing/streamed); b"" stays b"" (present empty). NEVER or b"".
    body = req.raw_content
    if body is not None:
        body = bytes(body)
    return RequestSnapshot(
        snapshot_id=snapshot_id, form=c.form, http_version=c.http_version,
        version_supported=c.version_supported, in_scope=c.in_scope, scope_reason=c.scope_reason,
        method=c.method, target=c.target, headers=headers, body=body)


def snapshot_to_parts(snapshot: RequestSnapshot) -> cr.RequestParts:
    """Pure: an ADMITTED snapshot -> cr.RequestParts. Raises ValueError if the snapshot is not
    admissible (not in scope, or body missing); callers must have already handled those as the
    OUT_OF_SCOPE / BODY_UNAVAILABLE statuses, so reaching here with one is a programming error."""
    if not snapshot.in_scope:
        raise ValueError(f"snapshot not in scope: {snapshot.scope_reason}")
    if snapshot.target is None:
        raise ValueError("in-scope snapshot has no target")
    if snapshot.body is None:
        raise ValueError("snapshot body is unavailable (missing/streamed)")
    # cr.RequestParts validates types and raises TypeError on anything malformed.
    return cr.RequestParts(method=snapshot.method, target=snapshot.target,
                           http_version=snapshot.http_version, headers=snapshot.headers,
                           body=snapshot.body)


def make_limits(max_decoded_body: int) -> cr.Limits:
    """The lab Limits for shadow observation: the R8 decode cap is enforced, but NO token budget is
    supplied, so the canonical size is UNCHECKED. That is a VALID approved lab setting (it simply
    keeps Fast Path ineligible); it is NOT a misconfiguration. The V5 token budget B is PENDING
    (V5-DATA-SPEC-r3 §11.2) and is deliberately not invented here."""
    return cr.Limits(max_decoded_body=max_decoded_body, token_budget=None,
                     max_bytes_per_token=None, count_tokens=None)
