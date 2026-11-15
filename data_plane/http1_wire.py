"""
firewall-IA — strict HTTP/1.1 request wire parser (the cascade's HTTP PARSER +
framing-validation stage), for the isolated lab.

Reads one HTTP/1.1 request message from a byte buffer and splits it into the
`canonical_request.RequestParts` the rest of the pipeline expects, deciding the
message body length deterministically (single Content-Length, or chunked
Transfer-Encoding) and de-chunking it. It owns the wire framing: ambiguous or
unsafe framing (Transfer-Encoding together with Content-Length, multiple
Content-Length, a non-chunked transfer coding, a malformed chunk sequence) is a
framing FAILURE — the lab denies such a request, it never forwards it.

FRAMING VERIFICATION, and why it is real here (not a renamed PROFILE_MATCHED):
in this lab a single owner reads the exact client bytes AND forwards those exact
bytes to the controlled upstream. There is no intermediate proxy whose framing
could diverge from what this parser saw, so "the bytes decided here are the bytes
delivered" holds by construction. A clean parse of one complete, unambiguously
framed HTTP/1.1 message therefore yields `fast_path.FramingEvidence(VERIFIED)`
bound to that request. SCOPE: HTTP/1.1 over a local socket only — this says
NOTHING about HTTP/2, TLS termination, or a deployment behind a separate proxy.

The parser bounds header and body size; it never trusts attacker-controlled
lengths beyond those bounds. Standard library only.
"""

import re
from dataclasses import dataclass
from typing import Optional

import fast_path as fp
from canonical_request import RequestParts

MAX_HEAD = 64 * 1024            # request line + headers
MAX_BODY = 8 * 1024 * 1024      # de-chunked / declared body cap for the lab
MAX_CHUNKS = 100_000

_TOKEN_RE = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_CTL_SP_RE = re.compile(rb"[\x00-\x20\x7f]")      # SP / CTL / DEL forbidden in target
_FIELD_NAME_RE = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

# Statuses for framing verification at the wire.
FRAMING_OK = "FRAMING_OK"
FRAMING_BAD = "FRAMING_BAD"


class WireError(ValueError):
    """The request could not be parsed into a single, unambiguously framed message."""
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class WireParse:
    parts: RequestParts
    framing: object            # fast_path.FramingEvidence
    consumed: int              # bytes of `buf` this message occupied
    leftover: bytes            # bytes after the message (pipelining; lab is 1/conn)
    body_framing: str          # how the body was framed: "none" | "content-length" | "chunked"


def _split_head(buf: bytes):
    idx = buf.find(b"\r\n\r\n")
    if idx == -1:
        raise WireError("no-header-terminator")
    if idx > MAX_HEAD:
        raise WireError("head-too-large")
    return buf[:idx], buf[idx + 4:]


def _parse_request_line(line: bytes):
    # METHOD SP request-target SP HTTP-version ; exactly two single spaces.
    parts = line.split(b" ")
    if len(parts) != 3:
        raise WireError("malformed-request-line")
    method, target, version = parts
    if not _TOKEN_RE.match(method):
        raise WireError("method-not-token")
    if target == b"" or _CTL_SP_RE.search(target):
        raise WireError("target-sp-ctl-del")
    if version not in (b"HTTP/1.1", b"HTTP/1.0"):
        raise WireError("unsupported-http-version")
    return method, target, version.decode("ascii")


def _parse_field_line(raw: bytes, *, empty_reason: str):
    """Validate one HTTP field line (header or trailer) and return (name, value).
    Same rules for both, so framing is never validated two divergent ways: no
    folding, a token field-name, a colon, and no CTL in the value."""
    if raw == b"":
        raise WireError(empty_reason)
    if raw[:1] in (b" ", b"\t"):
        raise WireError("obsolete-line-folding")   # RFC 9112 §5.2: reject folding
    if b":" not in raw:
        raise WireError("header-without-colon")
    name, _, value = raw.partition(b":")
    if not _FIELD_NAME_RE.match(name):
        raise WireError("bad-header-name")
    value = value.strip(b" \t")
    if re.search(rb"[\r\n\x00]", value):
        raise WireError("header-value-ctl")
    return name, value


def _parse_headers(head: bytes):
    lines = head.split(b"\r\n")
    request_line = lines[0]
    headers = [_parse_field_line(raw, empty_reason="empty-header-line") for raw in lines[1:]]
    return request_line, tuple(headers)


def _header_all(headers, lname):
    return [v for n, v in headers if n.lower() == lname]


def _read_chunked(rest: bytes):
    """De-chunk a chunked body. Returns (body, consumed). Strict: hex sizes, CRLF
    delimiters, a terminating 0-size chunk. Chunk extensions and trailers after
    the final chunk are consumed but not forwarded."""
    body = bytearray()
    pos = 0
    chunks = 0
    while True:
        nl = rest.find(b"\r\n", pos)
        if nl == -1:
            raise WireError("chunk-size-unterminated")
        size_line = rest[pos:nl]
        size_token = size_line.split(b";", 1)[0].strip()
        if not re.fullmatch(rb"[0-9A-Fa-f]+", size_token):
            raise WireError("chunk-size-not-hex")
        size = int(size_token, 16)
        pos = nl + 2
        chunks += 1
        if chunks > MAX_CHUNKS:
            raise WireError("too-many-chunks")
        if size == 0:
            # Trailer section: zero or more VALID trailer fields, then a blank line.
            # Each trailer line is validated with the same field rules as a header,
            # so a malformed trailer (e.g. "not-a-header") is a framing FAILURE.
            while True:
                tnl = rest.find(b"\r\n", pos)
                if tnl == -1:
                    raise WireError("chunk-trailer-unterminated")
                line = rest[pos:tnl]
                pos = tnl + 2
                if line == b"":
                    break   # blank line terminates the trailer section
                _parse_field_line(line, empty_reason="chunk-trailer-empty-line")
            return bytes(body), pos
        if len(body) + size > MAX_BODY:
            raise WireError("body-too-large")
        chunk = rest[pos:pos + size]
        if len(chunk) < size:
            raise WireError("chunk-data-short")
        body += chunk
        pos += size
        terminator = rest[pos:pos + 2]
        if terminator in (b"", b"\r"):
            raise WireError("chunk-data-terminator-incomplete")
        if terminator != b"\r\n":
            raise WireError("chunk-data-not-crlf-terminated")
        pos += 2


def parse_request(buf: bytes) -> WireParse:
    """Parse one HTTP/1.1 request from `buf`. Raises WireError on any framing
    ambiguity or malformation (the lab denies those, fail-closed)."""
    head, rest = _split_head(buf)
    request_line, headers = _parse_headers(head)
    method, target, version = _parse_request_line(request_line)

    te_fields = _header_all(headers, b"transfer-encoding")
    cl_fields = _header_all(headers, b"content-length")

    # Unambiguous framing only. These mirror canonical_request R1/R2 but are
    # decided HERE because the body boundary must be known to read the message.
    if te_fields and cl_fields:
        raise WireError("framing-te-and-cl")
    if len(te_fields) > 1:
        raise WireError("framing-multiple-te")
    if len(cl_fields) > 1:
        raise WireError("framing-duplicate-cl")

    head_len = len(head) + 4
    if te_fields:
        te = [e.split(b";", 1)[0].strip().lower() for e in te_fields[0].split(b",")]
        if te != [b"chunked"]:
            raise WireError("transfer-coding-not-single-chunked")
        if version == "HTTP/1.0":
            raise WireError("framing-te-on-http10")
        body, consumed_body = _read_chunked(rest)
        body_framing = "chunked"
        consumed = head_len + consumed_body
        leftover = rest[consumed_body:]
    elif cl_fields:
        value = cl_fields[0].strip(b" \t")
        if not re.fullmatch(rb"[0-9]+", value):
            raise WireError("framing-invalid-cl")
        n = int(value)
        if n > MAX_BODY:
            raise WireError("body-too-large")
        if len(rest) < n:
            raise WireError("body-short")
        body = rest[:n]
        body_framing = "content-length"
        consumed = head_len + n
        leftover = rest[n:]
    else:
        body = b""
        body_framing = "none"
        consumed = head_len
        leftover = rest

    parts = RequestParts(method=method, target=target, http_version=version,
                         headers=headers, body=body)
    framing = fp.FramingEvidence(
        fp.FRAMING_VERIFIED,
        f"single-owner {version} parse-and-forward; body_framing={body_framing}")
    return WireParse(parts=parts, framing=framing, consumed=consumed,
                     leftover=leftover, body_framing=body_framing)


def unverified(reason: str):
    """FramingEvidence for a request the lab could not frame-verify (denied)."""
    return fp.FramingEvidence(fp.FRAMING_UNVERIFIED, reason)
