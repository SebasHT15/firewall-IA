"""
firewall-IA — isolated cascade lab: raw-socket HTTP/1.1 gateway + controlled upstream.

A self-contained lab that proves the cascade DECIDES and the decision is ENFORCED
on real sockets, with a single owner reading the client bytes and forwarding the
exact same bytes to a local sink (so framing verification is genuine for the
HTTP/1.1 scope — see `data_plane/http1_wire.py`).

    client --bytes--> Gateway --(FORWARD: same bytes)--> UpstreamSink
                             (DENY: 403, nothing forwarded)

The Gateway takes an already-assembled `cascade.CascadeRouter`, so the same
transport drives doubles (tests) and the real Model 2 + V5 cascade. It records a
structured JSONL line per request (correlation id, applied action, deciding
stage, canonical outcome, Fast Path / Model 2 / V5 summaries, timings) and never
logs request payloads, headers or secrets.

L-levels (D41): the record carries the model/system DECISION (L1), whether the
upstream actually received the request (L2: `upstream_received`), and the client
response status (L3 is derived offline by comparing to the reference label).

Standard library only. ThreadingTCPServer; one request per connection (the lab
closes after answering, so there is no pipelining ambiguity).
"""

import json
import hashlib
import os
import socket
import socketserver
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "data_plane"))

import cascade as C          # noqa: E402
import cascade_runtime as RT  # noqa: E402
import http1_wire as W       # noqa: E402

READ_CAP = 16 * 1024 * 1024
SOCK_TIMEOUT = 10.0


# ───────────────────────────── upstream sink ─────────────────────────────
@dataclass
class SinkRecord:
    method: str
    target: str
    body_len: int
    wire_sha256: str = ""
    wire_bytes: int = 0


class UpstreamSink:
    """A controlled HTTP/1.1 upstream that records what it receives and answers 200.

    Raw socket (not http.server) so it reads the exact bytes the gateway forwards
    and frames the body the same way the gateway parsed it."""

    def __init__(self, host="127.0.0.1", port=0):
        self.records: list = []
        self._lock = threading.Lock()
        sink = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(SOCK_TIMEOUT)
                buf = _read_one_request(self.request)
                if buf is None:
                    return
                try:
                    w = W.parse_request(buf)
                    rec = SinkRecord(w.parts.method.decode("latin-1"),
                                     w.parts.target.decode("latin-1"), len(w.parts.body),
                                     hashlib.sha256(buf[:w.consumed]).hexdigest(), w.consumed)
                except W.WireError:
                    rec = SinkRecord("?", "?", -1)
                with sink._lock:
                    sink.records.append(rec)
                self.request.sendall(OK_RESPONSE)

        self._server = socketserver.ThreadingTCPServer((host, port), Handler)
        self._server.daemon_threads = True
        self.host, self.port = self._server.server_address

    def start(self):
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        self._server.shutdown()
        self._server.server_close()

    def received(self):
        with self._lock:
            return list(self.records)


# ───────────────────────────── request reader ─────────────────────────────
# WireError reasons that mean "the message is not complete yet, read more" — as
# opposed to a malformed framing the parser has already decided. Driving the read
# off the parser's own verdict means the body boundary is computed in exactly ONE
# place (http1_wire): a chunked terminator sequence (\r\n0\r\n\r\n) that legitimately
# appears INSIDE chunk data never ends the read early, because the read advances by
# the declared chunk sizes, not by substring search.
_WIRE_INCOMPLETE = frozenset({
    "no-header-terminator",       # head not yet fully received
    "body-short",                 # Content-Length body not yet fully received
    "chunk-size-unterminated",    # chunk size line not yet complete
    "chunk-data-short",           # chunk data not yet fully received
    "chunk-data-terminator-incomplete", # data CRLF split across recv calls
    "chunk-trailer-unterminated", # trailer section not yet complete
})


def _read_one_request(sock) -> Optional[bytes]:
    """Read exactly one HTTP/1.1 request (head + framed body) from `sock`.

    Reads until `http1_wire.parse_request` can frame a complete message, reusing
    the parser's framing semantics rather than re-implementing body detection.
    On a parser verdict of "incomplete" more bytes are read; on success (or any
    other framing verdict, which the caller will re-parse and reject) the buffer is
    returned. Bounded by READ_CAP."""
    buf = b""
    while True:
        try:
            W.parse_request(buf)
            return buf                      # a complete, framed message is present
        except W.WireError as e:
            if e.reason not in _WIRE_INCOMPLETE:
                return buf                  # decided framing (malformed or final)
        if len(buf) > READ_CAP:
            return buf                      # bounded; parser re-rejects as too large
        try:
            chunk = sock.recv(8192)
        except socket.timeout:
            return buf or None
        if not chunk:
            return buf or None              # peer closed; return what we have
        buf += chunk


def _forward(upstream_addr, raw_bytes: bytes, timeout=SOCK_TIMEOUT) -> bytes:
    with socket.create_connection(upstream_addr, timeout=timeout) as s:
        s.sendall(raw_bytes)
        resp = b""
        while True:
            chunk = s.recv(8192)
            if not chunk:
                break
            resp += chunk
            if len(resp) > READ_CAP:
                break
        return resp


def _http_response(status_line: str, body: bytes) -> bytes:
    """Build a complete HTTP/1.1 response whose Content-Length is computed from the
    body, so the declared length always matches the bytes sent (length-respecting
    clients read exactly `len(body)` bytes)."""
    head = (f"HTTP/1.1 {status_line}\r\nContent-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n").encode("ascii")
    return head + body


DENY_RESPONSE = _http_response("403 Forbidden", b"Request blocked by firewall-IA lab.")
PROTOCOL_RESPONSE = _http_response("400 Bad Request", b"Malformed request (framing).")
OK_RESPONSE = _http_response("200 OK", b"ok")


# ───────────────────────────── gateway ─────────────────────────────
@dataclass
class GatewayConfig:
    upstream_addr: tuple
    token_budget_B: int = 415
    log_sink: Optional[Callable[[dict], None]] = None


class CascadeGateway:
    """Raw-socket HTTP/1.1 gateway driven by an injected `cascade.CascadeRouter`."""

    def __init__(self, router: C.CascadeRouter, config: GatewayConfig,
                 host="127.0.0.1", port=0):
        self.router = router
        self.config = config
        self.limits = RT.v5_limits(config.token_budget_B)
        gw = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                gw._handle(self.request)

        self._server = socketserver.ThreadingTCPServer((host, port), Handler)
        self._server.daemon_threads = True
        self.host, self.port = self._server.server_address

    def _emit(self, record: dict):
        if self.config.log_sink:
            self.config.log_sink(record)

    def _handle(self, sock):
        cid = uuid.uuid4().hex[:12]
        t_start = time.perf_counter()
        sock.settimeout(SOCK_TIMEOUT)
        buf = _read_one_request(sock)
        if not buf:
            return
        record = {"correlation_id": cid}
        try:
            w = W.parse_request(buf)
        except W.WireError as e:
            record.update({"applied": "DENY", "deciding_stage": "wire",
                           "reason": f"wire_{e.reason}", "upstream_received": False})
            self._emit(record)
            sock.sendall(PROTOCOL_RESPONSE)
            return
        raw_text = buf[:w.consumed].decode("latin-1")
        record["wire_sha256"] = hashlib.sha256(buf[:w.consumed]).hexdigest()
        snapshot = RT.build_snapshot(w.parts, w.framing, self.limits,
                                     correlation_id=cid, raw_request_text=raw_text)
        result = self.router.route(snapshot)
        forwarded = False
        try:
            if result.applied == C.FORWARD:
                resp = _forward(self.config.upstream_addr, buf[:w.consumed])
                forwarded = True
                sock.sendall(resp)
            else:
                sock.sendall(DENY_RESPONSE)
        except OSError:
            # upstream failure on a FORWARD: fail-closed to the client.
            sock.sendall(DENY_RESPONSE)
        record.update(_result_record(result))
        record["upstream_received"] = forwarded
        record["gateway_ms"] = (time.perf_counter() - t_start) * 1000
        self._emit(record)

    def start(self):
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        self._server.shutdown()
        self._server.server_close()


def _result_record(result: C.CascadeResult) -> dict:
    return {
        "applied": result.applied,
        "deciding_stage": result.deciding_stage,
        "mode": result.mode,
        "canonical_outcome": result.canonical_outcome,
        "canonical_reject": result.canonical_reject,
        "fast_path": result.fast_path,
        "model2": result.model2,
        "v5": result.v5,
        "v4": result.v4,
        "cascade_applied": result.cascade_applied,
        "cascade_stage": result.cascade_stage,
        "reason": result.reason,
        "timings_ms": result.timings_ms,
    }
