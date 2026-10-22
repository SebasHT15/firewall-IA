"""
firewall-IA — LOCAL WIRE-EVIDENCE HARNESS for canonical-request/v1 R1/R2/P4/P9 (issue #68, §8).

READ-THIS-FIRST / HONESTY BARS (owner corrections, reproduced so the code cannot drift from them):
  * "a request reached the addon" is NOT evidence of R1. By the time an addon's `request` hook runs,
    mitmproxy has already parsed and de-chunked the wire bytes; `raw_content` is de-chunked and still
    content-coded, it is NOT the original wire octets. R1 (wire framing) can only be evidenced by the
    CLIENT-OBSERVED outcome at the socket and by the DIVERGENCE between the two hops (client->proxy vs
    proxy->upstream), never by what the addon received.
  * A NORMALIZED forward is NOT enforcement of a stricter project REJECT rule. If mitmproxy accepts a
    smuggling vector, rewrites its framing and forwards it, that is normalization by a third-party
    parser under one tested configuration — it is recorded as NORMALIZED_FORWARD, never as "R1
    enforced".
  * Parser reachability and P4 target handling are established ONLY by observed wire results, never by
    reading mitmproxy's source.
  * Wire evidence here establishes behaviour of the TESTED LAB PROFILE only (mitmproxy 12.2.3,
    validate_inbound_headers=true, HTTP/1.1, the pinned decoders). Runtime framing stays
    UNAVAILABLE / UNVERIFIED globally until a scoped wire-level control is implemented AND approved.
    Nothing here sets VERIFIED globally, and nothing here claims R1 can never be established later.

WHAT THIS MODULE IS
  A standard-library (for the client/stub/sink) local lab:
    * RawClient      — sends EXACT attacker-controlled bytes over a fresh, bounded, timed TCP socket.
                       NOT httpx/requests/curl: those re-frame TE/CL, collapse duplicate headers and
                       fix chunking, which would sanitize the vector before it ever hit the wire.
    * ClassifierStub — a local HTTP server answering POST /classify deterministically (status ok,
                       decision ALLOW) and COUNTING hits, so "did the addon call the classifier?" is
                       observable.
    * UpstreamSink   — a local raw-TCP HTTP/1.1 server that records the method/target/version, the
                       header block (duplicates preserved) and the body length it ACTUALLY received,
                       so TE/CL divergence between the two hops is observable — not just accept/reject.
    * LabProfile     — launches mitmdump 12.2.3 as a reverse proxy to the sink, with the HTTP/1.1 lab
                       options, loading scripts/wire_evidence/lab_addon.py (the REAL FirewallGateway +
                       the REAL canonical observer, pointed at the stub; config.yaml is NOT touched).
    * VECTORS        — the exact-byte catalogue (R1 / R2 / P4 / P9 / VALID counterparts / drift).
    * run_wire_lab() — drives every vector through the live profile and classifies the outcome.
    * contract_level_residual() — runs the project-owned canonical_request.canonicalize() on the
                       parts that SURVIVE parsing, as a COMPLEMENTARY, clearly-labelled body of
                       evidence (parts-level, not wire). It is never conflated with the wire result.

Loopback only. Never sends to an external target. Writes no request bytes to any log.
"""
from __future__ import annotations

import hashlib
import http.server
import json
import os
import socket
import socketserver
import ssl  # noqa: F401  (imported for completeness; the lab is cleartext HTTP/1.1)
import struct  # noqa: F401
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_PLANE_DIR = os.path.join(REPO_ROOT, "data_plane")
VENV_PY = os.path.join(REPO_ROOT, ".venv-dataplane", "bin", "python")
MITMDUMP = os.path.join(REPO_ROOT, ".venv-dataplane", "bin", "mitmdump")
LAB_ADDON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lab_addon.py")

LOOPBACK = "127.0.0.1"
CRLF = b"\r\n"

# Outcome classification (closed enum; recorded verbatim in the evidence JSON).
OUT_PARSER_REJECT = "PARSER_REJECT"          # mitmproxy answered an error before the addon; no upstream delivery
OUT_NORMALIZED_FORWARD = "NORMALIZED_FORWARD"  # accepted + forwarded (possibly rewritten); NOT R1 enforcement
OUT_ADDON_BLOCK = "ADDON_BLOCK"              # addon ran and returned 403 (model BLOCK) — not an R1 control
OUT_FAIL_CLOSED = "FAIL_CLOSED"              # addon ran and returned 503 (classifier unavailable)
OUT_CONN_RESET = "CONN_RESET"                # peer reset / closed with no HTTP response
OUT_TIMEOUT = "TIMEOUT"                      # no response within the client deadline
OUT_CLIENT_ERROR = "CLIENT_ERROR"            # local harness/socket error sending the vector
OUTCOMES = (OUT_PARSER_REJECT, OUT_NORMALIZED_FORWARD, OUT_ADDON_BLOCK, OUT_FAIL_CLOSED,
            OUT_CONN_RESET, OUT_TIMEOUT, OUT_CLIENT_ERROR)


# ───────────────────────────── free-port helper ─────────────────────────────
def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((LOOPBACK, 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ───────────────────────────── raw-socket client ─────────────────────────────
@dataclass
class ClientResult:
    """What the CLIENT observed at the socket — the primary R1 signal."""
    sent_bytes: int
    response_bytes: bytes           # raw bytes read back (bounded); b"" if none
    status_line: Optional[str]      # first line of the HTTP response, or None
    status_code: Optional[int]
    reset: bool                     # connection reset / closed with no response
    timed_out: bool
    error: Optional[str]            # a local socket error string, or None
    elapsed_ms: float

    @property
    def response_head(self) -> str:
        # Head only, never a body, and decoded latin-1 for safe display of the status/headers.
        head = self.response_bytes.split(b"\r\n\r\n", 1)[0]
        return head.decode("latin-1", "replace")


def _response_complete(buf: bytes) -> bool:
    """True once a full HTTP response (status + headers + a Content-Length body, if any) is read,
    so the client can stop without waiting out the whole deadline on a keep-alive connection."""
    if b"\r\n\r\n" not in buf:
        return False
    head, body = buf.split(b"\r\n\r\n", 1)
    for ln in head.split(b"\r\n")[1:]:
        if ln.lower().startswith(b"content-length:"):
            try:
                want = int(ln.split(b":", 1)[1].strip())
            except ValueError:
                return False
            return len(body) >= want
    # No Content-Length in the response head: cannot know the end without a close; keep reading.
    return False


class RawClient:
    """Sends EXACT bytes over one fresh TCP connection and reads the reply within a deadline."""

    def __init__(self, host: str, port: int, deadline_s: float = 3.0, recv_cap: int = 64 * 1024):
        self.host, self.port, self.deadline_s, self.recv_cap = host, port, deadline_s, recv_cap

    def send(self, raw: bytes) -> ClientResult:
        started = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.deadline_s)
        reset = timed_out = False
        error = None
        buf = bytearray()
        try:
            sock.connect((self.host, self.port))
            sock.sendall(raw)
            # NB: we deliberately do NOT half-close (shutdown SHUT_WR). A half-close makes mitmproxy
            # tear the client connection down on some paths, which would masquerade as a reset and
            # corrupt the evidence. We rely on the response's framing (the sink answers
            # `Connection: close`, so the proxy closes the read side when it is done) or the deadline.
            while len(buf) < self.recv_cap:
                try:
                    chunk = sock.recv(min(16384, self.recv_cap - len(buf)))
                except socket.timeout:
                    timed_out = True
                    break
                except ConnectionResetError:
                    reset = True
                    break
                if not chunk:
                    break
                buf += chunk
                if _response_complete(buf):   # full status+headers+CL body read: stop, don't wait out the deadline
                    break
        except (ConnectionResetError, BrokenPipeError):
            reset = True
        except socket.timeout:
            timed_out = True
        except OSError as exc:
            error = type(exc).__name__
        finally:
            try:
                sock.close()
            except OSError:
                pass
        elapsed_ms = (time.perf_counter() - started) * 1000
        status_line = status_code = None
        if buf[:5] in (b"HTTP/", b"http/") or buf[:4] == b"HTTP":
            status_line = buf.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            try:
                status_code = int(status_line.split(" ", 2)[1])
            except (IndexError, ValueError):
                status_code = None
        return ClientResult(len(raw), bytes(buf), status_line, status_code,
                            reset and not buf, timed_out and not buf, error, elapsed_ms)


# ───────────────────────────── classifier stub ─────────────────────────────
class _ClassifierHandler(http.server.BaseHTTPRequestHandler):
    server_version = "wire-lab-classifier/1"

    def log_message(self, *a):   # never log request bytes
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        _ = self.rfile.read(length) if length else b""   # read & discard; count only
        self.server.record_hit(length)                   # type: ignore[attr-defined]
        payload = json.dumps(self.server.verdict).encode("ascii")  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class ClassifierStub:
    """Deterministic local /classify. Records how many times the addon called it (and payload sizes),
    so classifier reachability is observable without ever logging request content."""

    def __init__(self, decision: str = "ALLOW"):
        self.verdict = {"status": "ok", "decision": decision, "reason": "wire-lab stub"}
        self._hits: list[int] = []
        self._lock = threading.Lock()
        self.port = free_port()
        self._srv = http.server.ThreadingHTTPServer((LOOPBACK, self.port), _ClassifierHandler)
        self._srv.verdict = self.verdict          # type: ignore[attr-defined]
        self._srv.record_hit = self._record       # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)

    def _record(self, size: int):
        with self._lock:
            self._hits.append(size)

    @property
    def url(self) -> str:
        return f"http://{LOOPBACK}:{self.port}/classify"

    def hit_count(self) -> int:
        with self._lock:
            return len(self._hits)

    def start(self):
        self._thread.start()

    def stop(self):
        self._srv.shutdown()
        self._srv.server_close()


# ───────────────────────────── upstream sink ─────────────────────────────
@dataclass
class SinkRecord:
    """What the UPSTREAM actually received after mitmproxy re-serialized and forwarded the request.
    Divergence between this and the client-sent vector is the real smuggling signal."""
    request_line: str
    headers: list                 # [(name, value), ...] duplicates preserved, in received order
    header_names: list
    body_len: int                 # body bytes actually read by the sink
    chunked: bool                 # sink saw a chunked body
    content_length_hdr: Optional[str]
    transfer_encoding_hdr: Optional[str]
    raw_head: str                 # the received header block (latin-1), for manual inspection
    truncated: bool               # the sink hit its read cap
    body_sha256: Optional[str] = None   # SHA-256 of the body the sink actually received (hop 2).
    #   Used ONLY by this TEST harness to prove BYTE identity across the hop; the production
    #   observer never hashes request bytes (privacy). For a chunked body this is the sha of the
    #   DE-CHUNKED payload, so it is only compared against a de-chunked client body.


class _SinkHandler(socketserver.BaseRequestHandler):
    READ_CAP = 256 * 1024
    TIMEOUT = 2.0

    def handle(self):
        self.request.settimeout(self.TIMEOUT)
        data = bytearray()
        try:
            while b"\r\n\r\n" not in data and len(data) < self.READ_CAP:
                chunk = self.request.recv(8192)
                if not chunk:
                    break
                data += chunk
        except (socket.timeout, OSError):
            pass
        if b"\r\n\r\n" not in data:
            # No complete header block arrived: record what we have and answer anyway.
            self.server.record(_parse_sink(bytes(data), b"", False, 0))  # type: ignore[attr-defined]
            self._reply()
            return
        head, rest = bytes(data).split(b"\r\n\r\n", 1)
        hdrs = _header_pairs(head)
        cl = _first(hdrs, "content-length")
        te = _first(hdrs, "transfer-encoding")
        body = bytearray(rest)
        chunked = te is not None and "chunked" in te.lower()
        truncated = False
        try:
            if chunked:
                body, truncated = _read_chunked(self.request, body, self.READ_CAP)
            elif cl is not None:
                want = int(cl.strip()) if cl.strip().isdigit() else 0
                while len(body) < want and len(body) < self.READ_CAP:
                    chunk = self.request.recv(min(8192, want - len(body)))
                    if not chunk:
                        break
                    body += chunk
        except (socket.timeout, OSError, ValueError):
            pass
        rec = _parse_sink(head, bytes(body), chunked, len(body))
        rec.content_length_hdr, rec.transfer_encoding_hdr = cl, te
        rec.truncated = truncated
        self.server.record(rec)   # type: ignore[attr-defined]
        self._reply()

    def _reply(self):
        try:
            self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                                 b"Connection: close\r\n\r\nok")
        except OSError:
            pass


def _header_pairs(head: bytes):
    lines = head.split(b"\r\n")[1:]
    out = []
    for ln in lines:
        if not ln:
            continue
        if b":" in ln:
            n, v = ln.split(b":", 1)
            out.append((n.decode("latin-1", "replace"), v.decode("latin-1", "replace").strip()))
    return out


def _first(hdrs, lname):
    for n, v in hdrs:
        if n.lower() == lname:
            return v
    return None


def _read_chunked(sock, body: bytearray, cap: int):
    # Minimal bounded de-chunk so the sink can report how many payload bytes it received.
    out = bytearray()
    buf = bytearray(body)
    truncated = False
    while True:
        while b"\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                return out, truncated
            buf += chunk
            if len(buf) > cap:
                return out, True
        size_line, buf = buf.split(b"\r\n", 1)
        try:
            size = int(size_line.split(b";", 1)[0].strip(), 16)
        except ValueError:
            return out, True
        if size == 0:
            break
        while len(buf) < size + 2:
            chunk = sock.recv(4096)
            if not chunk:
                return out, True
            buf += chunk
            if len(out) + len(buf) > cap:
                truncated = True
                break
        out += buf[:size]
        buf = buf[size + 2:]
        if truncated:
            break
    return out, truncated


def _parse_sink(head: bytes, body: bytes, chunked: bool, body_len: int) -> SinkRecord:
    first = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    hdrs = _header_pairs(head)
    sha = hashlib.sha256(bytes(body)).hexdigest() if body else hashlib.sha256(b"").hexdigest()
    return SinkRecord(request_line=first, headers=hdrs, header_names=[n for n, _ in hdrs],
                      body_len=body_len, chunked=chunked, content_length_hdr=None,
                      transfer_encoding_hdr=None, raw_head=head.decode("latin-1", "replace"),
                      truncated=False, body_sha256=sha)


class UpstreamSink:
    def __init__(self):
        self._records: list = []
        self._lock = threading.Lock()
        self.port = free_port()
        self._srv = socketserver.ThreadingTCPServer((LOOPBACK, self.port), _SinkHandler)
        self._srv.allow_reuse_address = True
        self._srv.record = self._record   # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)

    def _record(self, rec: SinkRecord):
        with self._lock:
            self._records.append(rec)

    @property
    def url(self) -> str:
        return f"http://{LOOPBACK}:{self.port}"

    def count(self) -> int:
        with self._lock:
            return len(self._records)

    def drain(self) -> list:
        with self._lock:
            recs, self._records = self._records, []
            return recs

    def start(self):
        self._thread.start()

    def stop(self):
        self._srv.shutdown()
        self._srv.server_close()


# ───────────────────────────── mitmdump lab profile ─────────────────────────────
@dataclass
class LabProfile:
    sink_url: str
    classifier_url: str
    validate_inbound_headers: bool = True
    http2: bool = False
    observer: bool = True
    framing: bool = False          # enable the shadow FRAMING observer (issue #68 Track B, v2 lab)
    listen_port: int = field(default_factory=free_port)
    _proc: Optional[subprocess.Popen] = None
    _logpath: Optional[str] = None

    def argv(self) -> list:
        return [
            MITMDUMP,
            "--mode", f"reverse:{self.sink_url}",
            "--listen-host", LOOPBACK, "-p", str(self.listen_port),
            "-s", LAB_ADDON,
            "--set", f"validate_inbound_headers={'true' if self.validate_inbound_headers else 'false'}",
            "--set", f"http2={'true' if self.http2 else 'false'}",
            "--set", "connection_strategy=lazy",
            "--set", "termlog_verbosity=info",
            "--set", "flow_detail=0",
            # stream_large_bodies is deliberately LEFT UNSET: its default (never stream) buffers the
            # whole body so req.raw_content is present at the request hook, which the observer needs.
            # (Setting it to 0 would stream EVERY body and make raw_content None — observed.)
        ]

    def requested_options(self) -> dict:
        """The options this profile REQUESTED via argv (--set ...), plus the ones deliberately left
        at their mitmproxy default. 'EFFECTIVE' values are read back from the running lab and recorded
        separately by the runner (lab_addon logs them); the two must not be conflated."""
        req = {}
        argv = self.argv()
        for i, tok in enumerate(argv):
            if tok == "--set" and i + 1 < len(argv) and "=" in argv[i + 1]:
                k, v = argv[i + 1].split("=", 1)
                req[k] = v
            if tok == "--mode" and i + 1 < len(argv):
                req["mode"] = argv[i + 1]
        req["stream_large_bodies"] = "<unset: mitmproxy default (never stream); buffers raw_content>"
        return req

    def env(self) -> dict:
        e = dict(os.environ)
        e["WIRE_LAB_CLASSIFIER_URL"] = self.classifier_url
        e["WIRE_LAB_TIMEOUT"] = "3.0"
        e["WIRE_LAB_OBSERVER"] = "1" if self.observer else "0"
        # Track B (v2): enable the shadow FRAMING observer on top of the canonical observer. The
        # gateway's configure() hook then samples the EFFECTIVE profile and a FRAMING OBS line is
        # logged beside each CANONICAL OBS line. Observe-only; no traffic effect.
        e["WIRE_LAB_FRAMING"] = "1" if self.framing else "0"
        e["WIRE_LAB_OBSERVER_PY"] = VENV_PY
        e["WIRE_LAB_MAX_DECODED_BODY"] = str(1 << 20)
        e["WIRE_LAB_OBS_TIMEOUT"] = "0.5"
        e["WIRE_LAB_OBS_STARTUP"] = "10"
        e["PYTHONDONTWRITEBYTECODE"] = "1"
        return e

    _logf = None

    def start(self, logpath: str, startup_deadline_s: float = 20.0):
        self._logpath = logpath
        self._logf = open(logpath, "wb")
        self._proc = subprocess.Popen(self.argv(), stdout=self._logf, stderr=subprocess.STDOUT,
                                      env=self.env(), cwd=REPO_ROOT)
        # Wait until the proxy accepts a TCP connection on its listen port.
        deadline = time.time() + startup_deadline_s
        while time.time() < deadline:
            if self._proc.poll() is not None:
                raise RuntimeError(f"mitmdump exited early (code {self._proc.returncode}); see {logpath}")
            try:
                s = socket.create_connection((LOOPBACK, self.listen_port), timeout=0.5)
                s.close()
                time.sleep(1.0)   # small grace for the addon's running()/prewarm()
                return
            except OSError:
                time.sleep(0.25)
        raise RuntimeError(f"mitmdump did not open {LOOPBACK}:{self.listen_port} in time; see {logpath}")

    def stop(self):
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=5)
        if self._logf is not None:
            try:
                self._logf.close()
            except OSError:
                pass
            self._logf = None


# ───────────────────────────── vector catalogue ─────────────────────────────
def _gzip_member(payload: bytes) -> bytes:
    import gzip
    return gzip.compress(payload)


def client_body(raw: bytes) -> bytes:
    """The body portion a vector placed on the wire (everything after the first CRLFCRLF). For the
    CL-framed P9 vectors this is exactly the coded body bytes the client sent."""
    if b"\r\n\r\n" not in raw:
        return b""
    return raw.split(b"\r\n\r\n", 1)[1]


def body_sha256(body: bytes) -> str:
    return hashlib.sha256(bytes(body)).hexdigest()


def bodies_identical(sent_body: bytes, received_sha256: Optional[str]) -> bool:
    """TRUE only when the upstream received byte-for-byte what the client sent. Compares SHA-256, so
    an equal-length-but-different-bytes forward FAILS this check (length equality is not identity)."""
    if received_sha256 is None:
        return False
    return body_sha256(sent_body) == received_sha256


@dataclass(frozen=True)
class Vector:
    vid: str
    group: str                    # R1 | R2 | P4 | P9 | VALID | DRIFT
    raw: bytes                    # EXACT bytes placed on the wire
    description: str
    justification: str            # the RFC clause / smuggling rationale
    expected_parser: str          # reject | forward | either (hypothesis for the TESTED profile)
    expected_contract: str        # residual canonicalize() outcome on surviving parts, or 'wire-only'
    facts_lost: str               # which wire facts do NOT survive parsing into RequestParts
    counterpart: Optional[str] = None   # vid of the VALID counterpart (for a reject vector)


def _v(vid, group, raw, desc, just, ep, ec, lost, counterpart=None) -> Vector:
    return Vector(vid, group, raw, desc, just, ep, ec, lost, counterpart)


# Exact-byte vectors. Line endings are explicit CRLF; nothing here is assembled by a sanitizing client.
VECTORS: list = [
    # ---- VALID counterparts (must be accepted by the contract; the profile should forward) ----
    _v("VALID-GET", "VALID",
       b"GET /ok HTTP/1.1\r\nHost: sink.test\r\n\r\n",
       "Well-formed body-less GET.", "RFC 9112 §3.", "forward", "ACCEPT",
       "none relevant"),
    _v("VALID-CL", "VALID",
       b"POST /ok HTTP/1.1\r\nHost: sink.test\r\nContent-Length: 5\r\n\r\nhello",
       "Single valid Content-Length with a matching 5-byte body.", "RFC 9112 §6.", "forward",
       "ACCEPT", "chunk sizes/ext (none here)"),
    _v("VALID-CL-OWS", "VALID",
       b"POST /ok HTTP/1.1\r\nHost: sink.test\r\nContent-Length:  5 \r\n\r\nhello",
       "Legal OWS around the Content-Length value (`:  5 `) with a 5-byte body. MUST be treated as "
       "VALID, not as an invalid CL.", "RFC 9110 §5.6.3 OWS around field values.", "forward",
       "ACCEPT (canonicalize strips OWS before the digit check)", "exact OWS bytes"),
    _v("VALID-CHUNKED", "VALID",
       b"POST /ok HTTP/1.1\r\nHost: sink.test\r\nTransfer-Encoding: chunked\r\n\r\n"
       b"5\r\nhello\r\n0\r\n\r\n",
       "Valid single chunked body.", "RFC 9112 §7.1.", "forward",
       "ACCEPT (parser de-chunks; body=b'hello' survives)",
       "chunk framing (de-chunked away before the addon)"),
    _v("VALID-OBSTEXT", "VALID",
       b"GET /ok HTTP/1.1\r\nHost: sink.test\r\nX-Note: caf\xe9\r\n\r\n",
       "Header value carrying an obs-text octet (0xE9). R4 VALID counterpart: obs-text is permitted.",
       "RFC 9110 §5.5 obs-text.", "forward", "ACCEPT (obs-text is not R4)", "none relevant"),
    _v("VALID-HTAB", "VALID",
       b"GET /ok HTTP/1.1\r\nHost: sink.test\r\nX-Note: a\tb\r\n\r\n",
       "Header value containing HTAB. R4 VALID counterpart: HTAB is permitted in a field value.",
       "RFC 9110 §5.5.", "forward", "ACCEPT (HTAB is not R4)", "none relevant"),
    _v("VALID-HTTP10", "VALID",
       b"GET /ok HTTP/1.0\r\nHost: sink.test\r\n\r\n",
       "Valid body-less GET on HTTP/1.0 (origin-form, IN adapter scope, canonicalizes OK+ACCEPT). The "
       "D70 defect-A fix requires EXACTLY HTTP/1.1 for framing PROFILE_MATCHED, so this must now "
       "surface as FRAMING OBS UNATTESTABLE / HTTP_VERSION_NOT_11 — never a positive, never the "
       "UNAVAILABLE/HTTP_VERSION_OUT_OF_SCOPE path (that path is for HTTP/2+ which the adapter rejects "
       "as unsupported_http_version). The HTTP/1.1 counterpart VALID-GET stays PROFILE_MATCHED.",
       "RFC 9112 §2.3 HTTP-version; D70 defect-A (version boundary).", "forward",
       "ACCEPT (HTTP/1.0 is in adapter scope; version_supported=True)",
       "the 1.0 version token survives into the snapshot and is carried to evaluate()"),

    # ---- R1: conflicting / invalid framing (residual facts survive as parts) ----
    _v("R1-TECL", "R1",
       b"POST /x HTTP/1.1\r\nHost: s\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n"
       b"5\r\nhello\r\n0\r\n\r\n",
       "Transfer-Encoding AND Content-Length together (classic TE.CL smuggling).",
       "RFC 9112 §6.1: if both present, CL MUST be ignored; divergent front/back-end framing.",
       "reject", "R1 framing-te-and-cl", "which header the peer honoured; chunk framing",
       counterpart="VALID-CHUNKED"),
    _v("R1-DUPCL-EQ", "R1",
       b"POST /x HTTP/1.1\r\nHost: s\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
       "Two Content-Length fields with equal values.", "RFC 9112 §6.3.4: multiple CL is invalid.",
       "reject", "R1 framing-duplicate-cl", "that there were two CL lines",
       counterpart="VALID-CL"),
    _v("R1-DUPCL-NE", "R1",
       b"POST /x HTTP/1.1\r\nHost: s\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!",
       "Two Content-Length fields with DIFFERENT values (6 vs 5) — a request-smuggling primitive.",
       "RFC 9112 §6.3.4.", "reject", "R1 framing-duplicate-cl",
       "which length each hop used", counterpart="VALID-CL"),
    _v("R1-BADCL-HEX", "R1",
       b"POST /x HTTP/1.1\r\nHost: s\r\nContent-Length: 0x5\r\n\r\nhello",
       "Non-digit Content-Length (`0x5`).", "RFC 9112 §6.3: CL is 1*DIGIT.", "reject",
       "R1 framing-invalid-cl", "exact CL bytes", counterpart="VALID-CL"),
    _v("R1-BADCL-PLUS", "R1",
       b"POST /x HTTP/1.1\r\nHost: s\r\nContent-Length: +5\r\n\r\nhello",
       "Signed Content-Length (`+5`).", "RFC 9112 §6.3: no sign permitted.", "reject",
       "R1 framing-invalid-cl", "exact CL bytes", counterpart="VALID-CL"),
    _v("R1-MULTITE", "R1",
       b"POST /x HTTP/1.1\r\nHost: s\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n"
       b"5\r\nhello\r\n0\r\n\r\n",
       "Two separate Transfer-Encoding fields.", "RFC 9112 §6.1; multiple TE lines invite "
       "parser disagreement.", "reject", "R1 framing-multiple-te",
       "that TE arrived on two separate lines", counterpart="VALID-CHUNKED"),
    _v("R1-TE-EMPTY", "R1",
       b"POST /x HTTP/1.1\r\nHost: s\r\nTransfer-Encoding: \r\n\r\nhello",
       "Empty Transfer-Encoding value.", "RFC 9112 §6.1: TE is a non-empty coding list.", "reject",
       "R1 framing-te-empty", "exact empty value", counterpart="VALID-CHUNKED"),
    _v("R1-TE10", "R1",
       b"POST /x HTTP/1.0\r\nHost: s\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
       "Transfer-Encoding: chunked on an HTTP/1.0 request line.",
       "RFC 9112 §6.1: chunked is undefined for HTTP/1.0; smuggling via downgrade.", "reject",
       "R1 framing-te-on-http10", "the 1.0 version token (audit only in parts)",
       counterpart="VALID-CHUNKED"),
    _v("R1-CHUNK-NONFINAL", "R1",
       b"POST /x HTTP/1.1\r\nHost: s\r\nTransfer-Encoding: chunked, gzip\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
       "`chunked` is not the FINAL transfer coding (`chunked, gzip`).",
       "RFC 9112 §6.1: chunked MUST be final.", "reject", "R1 framing-chunked-not-final",
       "coding order on the wire", counterpart="VALID-CHUNKED"),
    _v("R1-CHUNK-REPEAT", "R1",
       b"POST /x HTTP/1.1\r\nHost: s\r\nTransfer-Encoding: chunked, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
       "`chunked` applied twice.", "RFC 9112 §6.1: chunked appears at most once, final.", "reject",
       "R1 framing-chunked-not-final", "coding list on the wire", counterpart="VALID-CHUNKED"),
    _v("R1-WS-COLON", "R1",
       b"GET /x HTTP/1.1\r\nHost : s\r\n\r\n",
       "Whitespace BEFORE the header colon (`Host : s`).",
       "RFC 9112 §5.1: no whitespace between field-name and colon; a smuggling/desync primitive.",
       "reject", "wire-only (never reaches canonicalize as a parts fact)",
       "the space before the colon is NOT representable in RequestParts headers",
       counterpart="VALID-GET"),
    _v("R1-BADCHUNK", "R1",
       b"POST /x HTTP/1.1\r\nHost: s\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nhello\r\n0\r\n\r\n",
       "Malformed chunk size (`zz` is not hex).", "RFC 9112 §7.1: chunk-size is 1*HEXDIG.",
       "reject", "wire-only (de-chunking happens in the parser, not in canonicalize)",
       "chunk grammar is consumed by the parser before parts exist", counterpart="VALID-CHUNKED"),
    _v("R1-OBSFOLD", "R1",
       b"GET /x HTTP/1.1\r\nHost: s\r\nX-Fold: a\r\n\tb\r\n\r\n",
       "Obsolete line folding (obs-fold) inside a header value.",
       "RFC 9112 §5.2: obs-fold is deprecated; MUST reject or unfold.", "either",
       "wire-only; IF unfolded into a value with CR/LF it would be R4, otherwise not a parts fact",
       "the fold structure; only the unfolded value (if any) survives", counterpart="VALID-GET"),
    _v("R1-BARE-LF", "R1",
       b"GET /x HTTP/1.1\nHost: s\n\n",
       "Bare LF line endings instead of CRLF in the head.",
       "RFC 9112 §2.2: recipients may reject bare LF; a desync primitive.", "either",
       "wire-only (line-terminator handling is the parser's; not a parts fact)",
       "the exact line terminators", counterpart="VALID-GET"),

    # ---- R2: a transfer coding other than chunked (DISTINCT from R1) ----
    _v("R2-TE-GZIP", "R2",
       b"POST /x HTTP/1.1\r\nHost: s\r\nTransfer-Encoding: gzip\r\n\r\nhello",
       "A lone non-chunked transfer coding (`Transfer-Encoding: gzip`).",
       "RFC 9112 §6.1 (server may answer 501); the classified content would differ from the executed "
       "content. This is R2, not R1.", "either", "R2 transfer-coding-not-chunked",
       "whether the body was length-delimited at all", counterpart="VALID-CHUNKED"),

    # ---- P4: request-target forms (established ONLY by observed wire behaviour) ----
    _v("P4-ABSFORM", "P4",
       b"GET http://sink.test/abs-target HTTP/1.1\r\nHost: sink.test\r\n\r\n",
       "Absolute-form request-target (proxy form).",
       "RFC 9112 §3.2.2. The adapter marks absolute-form OUT_OF_SCOPE (authority not faithfully "
       "recoverable from data.path); canonicalize is never run for it.", "forward",
       "n/a (adapter: OUT_OF_SCOPE, never submitted)",
       "mitmproxy splits the authority into data.authority; data.path alone cannot reconstruct it"),
    _v("P4-ASTERISK", "P4",
       b"OPTIONS * HTTP/1.1\r\nHost: sink.test\r\n\r\n",
       "Asterisk-form (`OPTIONS *`).", "RFC 9112 §3.2.4.", "forward",
       "ACCEPT with target rendered `*` (in-scope form)", "none relevant"),
    _v("P4-OTHER", "P4",
       b"GET not-a-path HTTP/1.1\r\nHost: sink.test\r\n\r\n",
       "A target that is neither origin-, absolute-, asterisk- nor authority-form.",
       "RFC 9112 §3.2: no other form is defined; P4 (D63) renders byte-preserved as target_form=other, "
       "CONDITIONED on integration showing it never reaches the model unnoticed.", "either",
       "wire-only / CONDITIONED; adapter form classification depends on the parsed first_line_format",
       "whether the parser accepted or rewrote the odd target"),

    # ---- P9: content-coding of the body (raw_content must be forwarded coded) ----
    _v("P9-GZIP-2MEMBER", "P9",
       b"", "Two concatenated gzip members in the body (built at runtime).",
       "RFC 9110 §8.4.1; canonicalize/CPython decode BOTH members (superset); mitmproxy's own decoder "
       "would stop at the first. The adapter forwards raw_content, so the wire body must be byte-"
       "preserved across the hop.", "forward",
       "ACCEPT (both members decoded) — superset behaviour, P9 CONDITIONED (owner choice open)",
       "none (the point is that raw_content is NOT re-coded)"),
    _v("P9-GZIP-NUL-MEMBER", "P9",
       b"", "gzip member, NUL padding, second gzip member.",
       "P9 differential: this module + CPython decode the member after NUL padding; five other backends "
       "stop at the first. CONDITIONED (owner choice: keep superset vs R3).", "forward",
       "ACCEPT (member-after-NUL decoded) — CONDITIONED", "none"),
    _v("P9-GZIP-TRAILING", "P9",
       b"", "gzip member followed by non-NUL trailing garbage.",
       "P9: trailing non-NUL data after a member is R3 in this module.", "forward",
       "R3 content-coding-decode-failure:gzip (trailing data)", "none"),
]


def _materialize_p9():
    """Fill the empty P9 vector bodies with real gzip bytes + a matching Content-Length head."""
    import gzip
    m1 = gzip.compress(b"alpha=1")
    m2 = gzip.compress(b"&beta=2")
    bodies = {
        "P9-GZIP-2MEMBER": m1 + m2,
        "P9-GZIP-NUL-MEMBER": m1 + (b"\x00" * 8) + m2,
        "P9-GZIP-TRAILING": m1 + b"TRAILING-GARBAGE",
    }
    out = []
    for v in VECTORS:
        if v.group == "P9" and not v.raw:
            body = bodies[v.vid]
            head = (b"POST /x HTTP/1.1\r\nHost: sink.test\r\nContent-Encoding: gzip\r\n"
                    b"Content-Type: application/x-www-form-urlencoded\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n")
            out.append(Vector(v.vid, v.group, head + body, v.description, v.justification,
                              v.expected_parser, v.expected_contract, v.facts_lost, v.counterpart))
        else:
            out.append(v)
    return out


def all_vectors() -> list:
    return _materialize_p9()


# ───────────────────────────── outcome classification ─────────────────────────────
def classify(cr: ClientResult, sink_delivered: bool, classifier_called: bool) -> str:
    if cr.error:
        return OUT_CLIENT_ERROR
    if sink_delivered:
        return OUT_NORMALIZED_FORWARD    # accepted + forwarded (possibly rewritten); NOT R1 enforcement
    if cr.status_code is not None:
        if cr.status_code == 403:
            return OUT_ADDON_BLOCK
        if cr.status_code == 503:
            return OUT_FAIL_CLOSED
        if 400 <= cr.status_code < 500:
            # A 4xx with no upstream delivery and (typically) no classifier call = parser rejected
            # the request before the addon ran.
            return OUT_PARSER_REJECT
        return OUT_NORMALIZED_FORWARD
    if cr.reset:
        return OUT_CONN_RESET
    if cr.timed_out:
        return OUT_TIMEOUT
    return OUT_CONN_RESET


# ───────────────────────────── contract-level residual (NOT wire) ─────────────────────────────
def contract_level_residual() -> list:
    """Run the PROJECT-OWNED canonical_request.canonicalize() directly on the parts that would
    SURVIVE parsing, for the residual-R1 / R2 cases. This is parts-level evidence of the contract
    control; it is explicitly NOT wire evidence and is reported in its own section."""
    if DATA_PLANE_DIR not in sys.path:
        sys.path.insert(0, DATA_PLANE_DIR)
    import canonical_request as cr

    limits = cr.Limits(max_decoded_body=1 << 20)
    cases = [
        ("R1-TECL", b"POST", b"/x", "HTTP/1.1",
         [(b"Transfer-Encoding", b"chunked"), (b"Content-Length", b"5")], b"hello"),
        ("R1-DUPCL-EQ", b"POST", b"/x", "HTTP/1.1",
         [(b"Content-Length", b"5"), (b"Content-Length", b"5")], b"hello"),
        ("R1-DUPCL-NE", b"POST", b"/x", "HTTP/1.1",
         [(b"Content-Length", b"5"), (b"Content-Length", b"6")], b"hello!"),
        ("R1-BADCL-HEX", b"POST", b"/x", "HTTP/1.1", [(b"Content-Length", b"0x5")], b"hello"),
        ("R1-BADCL-PLUS", b"POST", b"/x", "HTTP/1.1", [(b"Content-Length", b"+5")], b"hello"),
        ("R1-CL-OWS-VALID", b"POST", b"/x", "HTTP/1.1", [(b"Content-Length", b"  5 ")], b"hello"),
        ("R1-MULTITE", b"POST", b"/x", "HTTP/1.1",
         [(b"Transfer-Encoding", b"gzip"), (b"Transfer-Encoding", b"chunked")], b"hello"),
        ("R1-TE-EMPTY", b"POST", b"/x", "HTTP/1.1", [(b"Transfer-Encoding", b"")], b"hello"),
        ("R1-TE10", b"POST", b"/x", "HTTP/1.0", [(b"Transfer-Encoding", b"chunked")], b"hello"),
        ("R1-CHUNK-NONFINAL", b"POST", b"/x", "HTTP/1.1",
         [(b"Transfer-Encoding", b"chunked, gzip")], b"hello"),
        ("R2-TE-GZIP", b"POST", b"/x", "HTTP/1.1", [(b"Transfer-Encoding", b"gzip")], b"hello"),
        ("R4-OBSTEXT-VALID", b"GET", b"/x", "HTTP/1.1", [(b"X-Note", b"caf\xe9")], b""),
        ("R4-HTAB-VALID", b"GET", b"/x", "HTTP/1.1", [(b"X-Note", b"a\tb")], b""),
        ("R4-CRLF-REJECT", b"GET", b"/x", "HTTP/1.1", [(b"X-Bad", b"a\r\nb")], b""),
    ]
    out = []
    for cid, method, target, ver, headers, body in cases:
        parts = cr.RequestParts(method=method, target=target, http_version=ver,
                                headers=tuple(headers), body=body)
        res = cr.canonicalize(parts, limits)
        out.append({"case": cid, "outcome": res.outcome, "reject": res.reject,
                    "reason": res.reason, "signals": sorted(res.signals)})
    return out
