"""External Test v1 — conversion between the CLASSIFIER REPRESENTATION and the WIRE.

Two different byte strings describe the same HTTP request, and External v1 depends on
never confusing them:

  CLASSIFIER REPRESENTATION  what `data_plane.render_request()` produces and what V4 is
                             asked to classify (D1). Origin-form target, LF line endings,
                             blank line before a body. This is what a frozen case stores
                             and what its SHA-256 is taken over.

  WIRE FORM                  what actually travels to an explicit HTTP proxy. ABSOLUTE-form
                             target (RFC 9112 §3.2.2), CRLF line endings.

Byte-exact replay therefore is NOT "send the frozen text". It is:

    frozen text -> to_wire() -> proxy -> mitmproxy parses -> render_request() -> text again

and the fidelity requirement is that the final text equals the frozen text byte for byte.
This module owns that conversion and nothing else. It has no dependencies, so it is
testable in the ML environment where mitmproxy is not installed.
"""

import hashlib
import re

CRLF = b"\r\n"


class WireError(ValueError):
    """The rendered text cannot be turned into a faithful wire request."""


def sha256_text(text: str) -> str:
    """SHA-256 over the classifier representation, UTF-8 encoded."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def assert_canonical(text: str) -> None:
    """Reject a request text that is not in the exact form `render_request()` produces.

    `render_request()` joins its lines with "\n" and adds NO trailing newline, so a
    bodyless request ends at the last header character. A hand-written case carrying a
    stray trailing newline, or CRLF endings, would be frozen under a SHA-256 that replay
    can never reproduce — the proxy would render the canonical form and the hashes would
    disagree for every such case. Catching it before freeze costs nothing; catching it
    after freeze costs an external_v2.
    """
    if "\r" in text:
        raise WireError("CR found: the classifier representation uses LF endings only")
    _, sep, body = text.partition("\n\n")
    if not sep and text.endswith("\n"):
        raise WireError("bodyless request ends with a trailing newline; the canonical "
                        "form ends at the last header character")
    if sep and body == "":
        raise WireError("blank line present but body empty; render_request() emits the "
                        "blank line only when there is a body")


def parse_rendered(text: str):
    """Split a classifier representation into its parts.

    Returns (method, target, version, headers, body) where `headers` is a list of
    (name, value) pairs in the order they were rendered, repeats preserved, and `body`
    is a str or None.

    The first blank line separates headers from body. A header value cannot contain a
    newline, so the first "\\n\\n" is unambiguous.
    """
    if not text:
        raise WireError("empty request text")
    head, sep, body = text.partition("\n\n")
    lines = head.split("\n")
    request_line = lines[0]
    parts = request_line.split(" ")
    if len(parts) != 3:
        raise WireError(f"malformed request line: {request_line!r}")
    method, target, version = parts

    headers = []
    for line in lines[1:]:
        if not line:
            continue
        name, colon, value = line.partition(": ")
        if not colon:
            raise WireError(f"malformed header line: {line!r}")
        headers.append((name, value))

    return method, target, version, headers, (body if sep else None)


def header_value(headers, name):
    """First value of `name`, case-insensitively, or None."""
    lowered = name.lower()
    for k, v in headers:
        if k.lower() == lowered:
            return v
    return None


def to_wire(text: str, strict: bool = True) -> bytes:
    """Build the exact bytes to send to an explicit HTTP proxy.

    Headers are emitted verbatim: same names, same values, same order, repeats kept.
    Nothing is added, removed, reordered or normalised — every header is model input
    (ml_evaluation_methodology.md section 8), so rewriting one would change what is being
    tested.

    The ONLY transformation is the request target: origin-form becomes absolute-form,
    because that is what a proxy requires. mitmproxy parses it back to origin-form, so
    `render_request()` reproduces the original text.

    With `strict` (the default) a Content-Length that disagrees with the body length is an
    error rather than something silently corrected. Rewriting it would desynchronise the
    frozen text from the bytes sent; a mismatch means the case must be fixed before freeze,
    not patched at replay time.
    """
    method, target, version, headers, body = parse_rendered(text)

    if target.startswith(("http://", "https://")):
        absolute = target                     # already absolute-form
    else:
        host = header_value(headers, "Host")
        if not host:
            raise WireError("origin-form target with no Host header: cannot build "
                            "an absolute-form request line")
        if not target.startswith("/"):
            raise WireError(f"origin-form target must start with '/': {target!r}")
        absolute = f"http://{host}{target}"

    body_bytes = body.encode("utf-8") if body is not None else b""

    if strict:
        declared = header_value(headers, "Content-Length")
        if declared is not None:
            try:
                declared_n = int(declared.strip())
            except ValueError:
                raise WireError(f"non-integer Content-Length: {declared!r}")
            if declared_n != len(body_bytes):
                raise WireError(
                    f"Content-Length {declared_n} != body {len(body_bytes)} bytes. "
                    "The case is inconsistent; fix it before freezing rather than "
                    "rewriting the header at replay time.")
        if header_value(headers, "Transfer-Encoding"):
            raise WireError("Transfer-Encoding is out of scope for External v1 replay; "
                            "lab traffic uses Content-Length framing only")

    out = [f"{method} {absolute} {version}".encode("utf-8")]
    out += [f"{name}: {value}".encode("utf-8") for name, value in headers]
    return CRLF.join(out) + CRLF + CRLF + body_bytes


# ── Response reading ───────────────────────────────────────────────────────
_STATUS_RE = re.compile(rb"^HTTP/\d\.\d (\d{3})")


def read_response(sock, timeout_note="") -> tuple[int, dict, bytes]:
    """Read one HTTP/1.1 response from a socket. Returns (status, headers, body).

    Deliberately minimal and deliberately does NOT send `Connection: close` to make its
    life easier — adding a header would alter the request under test. So keep-alive
    framing is handled here instead: Content-Length, then chunked, then read-to-close.
    """
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf += chunk
    if not buf:
        raise WireError(f"no response from the proxy{timeout_note}")

    head, _, rest = buf.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    m = _STATUS_RE.match(lines[0])
    if not m:
        raise WireError(f"malformed status line: {lines[0]!r}")
    status = int(m.group(1))

    headers = {}
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        if colon:
            headers[name.decode("latin-1").strip().lower()] = value.decode("latin-1").strip()

    body = rest
    if "content-length" in headers:
        want = int(headers["content-length"])
        while len(body) < want:
            chunk = sock.recv(65536)
            if not chunk:
                break
            body += chunk
        body = body[:want]
    elif headers.get("transfer-encoding", "").lower() == "chunked":
        body = _read_chunked(sock, body)
    else:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            body += chunk
    return status, headers, body


def _read_chunked(sock, initial: bytes) -> bytes:
    buf, out = initial, b""
    while True:
        while b"\r\n" not in buf:
            chunk = sock.recv(65536)
            if not chunk:
                return out
            buf += chunk
        size_line, _, buf = buf.partition(b"\r\n")
        try:
            size = int(size_line.split(b";")[0], 16)
        except ValueError:
            return out
        if size == 0:
            return out
        while len(buf) < size + 2:
            chunk = sock.recv(65536)
            if not chunk:
                return out + buf[:size]
            buf += chunk
        out += buf[:size]
        buf = buf[size + 2:]
