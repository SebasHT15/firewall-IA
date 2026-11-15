"""
firewall-IA — framing control of the mitmproxy deployment: `gateway-framing/v1`.

WHY THE LAB GUARANTEE DOES NOT TRANSFER. In `http1_wire` a single owner reads the client's bytes and
forwards those same bytes. mitmproxy does neither: it parses the client's message, may tolerate and
normalize forms the project parser rejects (bare LF, D70), and SERIALIZES A NEW MESSAGE from its
request object when it contacts the upstream. Built-in addons that run AFTER a script's `request`
hook (map_remote, modify_headers, modify_body, sticky*, upstream_auth) can still change that object.
What was inspected and what the upstream parses are therefore two different byte sequences, and
`framing_evidence.PROFILE_MATCHED` (D70) says nothing about the second one. It stays observation-only
and is not used here.

THE CONTROL. This module binds the decision to the message the upstream really receives, at the one
hop the project can own:

    client -> mitmproxy -> EgressGuard (loopback, this module) -> upstream

  1. Before deciding, `bind_delivery` serializes the request with mitmproxy's own assembler (exactly
     what `Http1Client` sends), parses that with the strict project parser and refuses anything that
     is not one complete, unambiguous message equal to the request object. The decision is taken on
     those parts, so a tolerated inbound form is decided in the form the upstream will receive.
  2. A FORWARD issues a single-use ticket for the digest of those bytes (`TicketBook`).
  3. `EgressGuard` receives what mitmproxy really serialized, frames it with the same strict parser,
     redeems a ticket for those exact bytes and only then forwards THOSE bytes. Anything else (bytes
     changed after the hook, a second smuggled message, no decision at all, a changed runtime profile)
     is not delivered.

WHAT THIS ATTESTS, AND WHAT IT DOES NOT. `EGRESS_BOUND` means: this request was decided on one
strictly framed message, and that message is the only thing that can reach the upstream for that
decision. It does NOT attest the client's inbound bytes, which mitmproxy consumed (a normalized
bare-LF request stays normalized), and it says nothing about what a non-conforming upstream parser
does with a conforming message. HTTP/1.1 cleartext inbound only: TLS and HTTP/2 inbound are rejected
explicitly because neither was tested, even though the egress hop would be the same.

`FramingEvidence(VERIFIED)` for the Fast Path is produced from this per-request binding only when the
deployment enables it (`verified_evidence`); it needs an owner ruling outside the lab (D70). It is
never derived from a profile match or from a constant.

No correlation header is ever added: every header is model input.

Standard library plus `mitmproxy.net.http.http1` (imported where used).
"""

import asyncio
import collections
import hashlib
import logging
import os
import sys
import time
from dataclasses import dataclass
from typing import Callable, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import canonical_adapter as adapter  # noqa: E402
import fast_path as fp  # noqa: E402
import framing_evidence as fe  # noqa: E402
import http1_wire as W  # noqa: E402

log = logging.getLogger("firewall.data_plane.framing")

CONTRACT_ID = "gateway-framing/v1"
EGRESS_BOUND = "EGRESS_BOUND"

# The versioned scope. Changing any entry is a new contract id, with its own evidence.
SCOPE = {
    "contract": CONTRACT_ID,
    "gateway": "mitmproxy reverse mode behind a project-owned loopback egress guard",
    "mitmproxy_version": fe.TESTED_MITMPROXY_VERSION,
    "inbound": "HTTP/1.1 cleartext, origin-form, exactly one Host, buffered complete body, "
               "no trailers, no upgrade",
    "attests": "decided message == message delivered to the upstream, per request",
    "does_not_attest": "the client's inbound bytes; TLS; HTTP/2; HTTP/3; upstream parser conformance",
    "rejected_explicitly": ["HTTP/1.0", "HTTP/2", "HTTP/3", "TLS inbound", "absolute-form",
                            "authority-form", "asterisk-form", "streamed bodies", "trailers",
                            "protocol upgrades", "WebSocket", "zero or repeated Host"],
}

# Scope rejections: (closed reason, HTTP status of the explicit answer).
SCOPE_HTTP_VERSION = ("scope_http_version", 505)
SCOPE_TLS_INBOUND = ("scope_tls_inbound", 501)
SCOPE_TARGET_FORM = ("scope_target_form", 501)
SCOPE_STREAMED_BODY = ("scope_streamed_body", 501)
SCOPE_TRAILERS = ("scope_trailers", 501)
SCOPE_UPGRADE = ("scope_upgrade", 501)
SCOPE_HOST_COUNT = ("scope_host_count", 400)

# The WireError reasons meaning "not complete yet". Same set as scripts/cascade_lab/lab_server.py;
# tests/test_gateway_framing.py compares the two so they cannot drift.
WIRE_INCOMPLETE = frozenset({
    "no-header-terminator", "body-short", "chunk-size-unterminated", "chunk-data-short",
    "chunk-data-terminator-incomplete", "chunk-trailer-unterminated",
})

# Binding failures (closed).
BINDING_ASSEMBLE_FAILED = "binding_assemble_failed"
BINDING_INCOMPLETE = "binding_incomplete"
BINDING_TRAILING_BYTES = "binding_trailing_bytes"
BINDING_PARTS_MISMATCH = "binding_parts_mismatch"

# Egress events (closed).
EVENT_DELIVERED = "DELIVERED"
EVENT_PASSTHROUGH = "PASSTHROUGH"
EVENT_REJECTED = "REJECTED"
REJECT_UNTICKETED = "unticketed"
REJECT_STALE_PROFILE = "stale_profile"
REJECT_WIRE = "wire"
REJECT_TOO_LARGE = "too_large"
REJECT_TRUNCATED = "truncated"

BAD_GATEWAY = (b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")


# ─────────────────────────────── effective profile ───────────────────────────────
# Option -> required EFFECTIVE value. Anything that can bypass HTTP handling or change the request
# after the hook is here. `mode` and `body_size_limit` are checked against the deployment's values.
# `flow_detail` is here for the log: mitmdump's default prints every URL, query string included.
REQUIRED_OPTIONS = {
    "flow_detail": 0,
    "validate_inbound_headers": True,
    "http2": False,
    "http3": False,
    "websocket": False,
    "rawtcp": False,
    "stream_large_bodies": None,
    "connection_strategy": "lazy",
    "keep_host_header": True,
    "ignore_hosts": [],
    "allow_hosts": [],
    "tcp_hosts": [],
    "udp_hosts": [],
    "anticache": False,
    "anticomp": False,
    "modify_headers": [],
    "modify_body": [],
    "map_remote": [],
    "map_local": [],
    "stickycookie": None,
    "stickyauth": None,
    "upstream_auth": None,
    "server_replay": [],
    "client_replay": [],
}


@dataclass(frozen=True)
class DeploymentProfile:
    """EFFECTIVE runtime values, sampled from mitmproxy, never from configuration intent. Holds no
    request data. `relevant_fingerprint` is what `framing_evidence.RelevantProfileGeneration` needs,
    so a change and change-back (A->B->A) between decision and delivery is detected."""
    mitmproxy_version: object
    mode_marker: object
    mode_fingerprint: object
    body_size_limit: object
    options: tuple

    def relevant_fingerprint(self) -> tuple:
        return (self.mitmproxy_version, self.mode_fingerprint, repr(self.body_size_limit),
                repr(self.options))


def sample_profile(options, mitmproxy_version) -> DeploymentProfile:
    """Never raises: an unreadable option is `UNAVAILABLE_FIELD`, which matches no required value."""
    def read(name):
        try:
            return getattr(options, name, fe.UNAVAILABLE_FIELD)
        except Exception:  # noqa: BLE001 — a hostile/odd options object must not break sampling
            return fe.UNAVAILABLE_FIELD

    marker, fingerprint = fe._canon_mode(read("mode"))
    return DeploymentProfile(
        mitmproxy_version=mitmproxy_version, mode_marker=marker, mode_fingerprint=fingerprint,
        body_size_limit=read("body_size_limit"),
        options=tuple((name, read(name)) for name in sorted(REQUIRED_OPTIONS)))


def profile_problems(profile: DeploymentProfile, *, body_size_limit: str,
                     expected_target: tuple) -> tuple:
    """Closed reasons why the effective profile is not the one `gateway-framing/v1` was tested on.
    Empty means it is. Each reason is a fixed option name, never a value. `expected_target` is
    (host, port) of the reverse-mode destination: the guard when the cascade is authoritative."""
    problems = []
    if profile.mitmproxy_version != fe.TESTED_MITMPROXY_VERSION:
        problems.append("mitmproxy_version")
    if profile.body_size_limit != body_size_limit:
        problems.append("option:body_size_limit")
    if profile.mode_fingerprint != ("reverse", "http", *expected_target):
        problems.append("option:mode")
    for name, value in profile.options:
        if value is fe.UNAVAILABLE_FIELD or value != REQUIRED_OPTIONS[name]:
            problems.append(f"option:{name}")
    return tuple(problems)


def launch_options(*, body_size_limit: str) -> dict:
    """The `--set` values a launcher passes so that `profile_problems` comes back empty."""
    out = {k: ("true" if v is True else "false") for k, v in REQUIRED_OPTIONS.items()
           if isinstance(v, bool)}
    out["connection_strategy"] = REQUIRED_OPTIONS["connection_strategy"]
    out["flow_detail"] = str(REQUIRED_OPTIONS["flow_detail"])
    out["body_size_limit"] = body_size_limit
    return out


# ─────────────────────────────── scope gate ───────────────────────────────
def check_scope(flow) -> Optional[tuple]:
    """(reason, status) when this request is outside `gateway-framing/v1`, else None. Runs before any
    other work: unsupported is an explicit answer, never a best effort."""
    req = flow.request
    client = getattr(flow, "client_conn", None)
    if getattr(client, "tls_established", False):
        return SCOPE_TLS_INBOUND
    if req.http_version != fe.TESTED_HTTP_VERSION:
        return SCOPE_HTTP_VERSION
    if adapter._classify_form(req) != adapter.FORM_ORIGIN:
        return SCOPE_TARGET_FORM
    if req.stream or req.raw_content is None:
        return SCOPE_STREAMED_BODY
    if req.trailers:
        return SCOPE_TRAILERS
    if "upgrade" in req.headers or "upgrade" in req.headers.get("connection", "").lower():
        return SCOPE_UPGRADE
    if len(req.headers.get_all("host")) != 1:     # RFC 9112 §3.2: exactly one, or a routing ambiguity
        return SCOPE_HOST_COUNT
    return None


# ─────────────────────────────── per-request binding ───────────────────────────────
class BindingError(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class DeliveryBinding:
    """The one message this request will be, if forwarded. `parts` are what gets decided."""
    wire: bytes
    wire_sha256: str
    parts: object            # canonical_request.RequestParts from the strict parse
    body_framing: str
    generation: int

    def framing_evidence(self, verified: bool) -> fp.FramingEvidence:
        if not verified:
            return fp.FramingEvidence(fp.FRAMING_UNVERIFIED, f"{CONTRACT_ID}:{EGRESS_BOUND}:not-enabled")
        return fp.FramingEvidence(fp.FRAMING_VERIFIED,
                                  f"{CONTRACT_ID}:{EGRESS_BOUND}:generation={self.generation}")


def bind_delivery(req, generation: int) -> DeliveryBinding:
    """Serialize as mitmproxy will, parse strictly, and require equality with the request object.
    Raises BindingError with a closed reason, or `http1_wire.WireError` for a framing the strict
    parser refuses (for example an obsolete fold mitmproxy tolerated)."""
    from mitmproxy.net.http import http1
    try:
        wire = http1.assemble_request(req)
    except Exception:  # noqa: BLE001 — third-party serializer: any failure means no binding
        raise BindingError(BINDING_ASSEMBLE_FAILED) from None
    try:
        parsed = W.parse_request(wire)
    except W.WireError as exc:
        if exc.reason in WIRE_INCOMPLETE:
            raise BindingError(BINDING_INCOMPLETE) from None
        raise
    if parsed.consumed != len(wire) or parsed.leftover:
        raise BindingError(BINDING_TRAILING_BYTES)
    parts = parsed.parts
    if (parts.method != bytes(req.data.method) or parts.target != bytes(req.data.path)
            or parts.body != req.raw_content
            or parts.headers != tuple((bytes(n), bytes(v)) for n, v in req.headers.fields)):
        raise BindingError(BINDING_PARTS_MISMATCH)
    return DeliveryBinding(wire, hashlib.sha256(wire).hexdigest(), parts, parsed.body_framing,
                           generation)


# ─────────────────────────────── tickets ───────────────────────────────
@dataclass(frozen=True)
class Ticket:
    wire_sha256: str
    correlation_id: str
    generation: int
    expires_at: float


class TicketBook:
    """Single-use permissions to deliver one exact message, bounded in number and time. Identical
    messages in flight are separate tickets, consumed in order. Event-loop thread only."""

    def __init__(self, max_tickets: int, ttl_seconds: float, clock=time.monotonic):
        self.max_tickets = max_tickets
        self.ttl_seconds = ttl_seconds
        self._clock = clock
        self._by_digest: dict = {}
        self._order: collections.deque = collections.deque()
        self.expired = 0

    def __len__(self) -> int:
        return len(self._order)

    def _expire(self) -> None:
        now = self._clock()
        while self._order and self._order[0].expires_at <= now:
            ticket = self._order.popleft()
            queue = self._by_digest.get(ticket.wire_sha256)
            if queue and queue[0] is ticket:
                queue.popleft()
                self.expired += 1
                if not queue:
                    del self._by_digest[ticket.wire_sha256]

    def issue(self, wire_sha256: str, correlation_id: str, generation: int) -> bool:
        """False when the book is full: the caller must not forward."""
        self._expire()
        if len(self._order) >= self.max_tickets:
            return False
        ticket = Ticket(wire_sha256, correlation_id, generation, self._clock() + self.ttl_seconds)
        self._by_digest.setdefault(wire_sha256, collections.deque()).append(ticket)
        self._order.append(ticket)
        return True

    def redeem(self, wire_sha256: str) -> Optional[Ticket]:
        self._expire()
        queue = self._by_digest.get(wire_sha256)
        if not queue:
            return None
        ticket = queue.popleft()
        if not queue:
            del self._by_digest[wire_sha256]
        self._order.remove(ticket)
        return ticket


# ─────────────────────────────── egress guard ───────────────────────────────
class EgressGuard:
    """The project-owned hop in front of the upstream, on the gateway's event loop.

    One upstream connection per mitmproxy connection. Requests are framed with the strict parser and
    forwarded as the exact received bytes; the response direction is a byte pipe, because this control
    is about what reaches the upstream.

    `enforcing()` is True while the cascade is authoritative. While V4 holds authority (OBSERVE,
    rollback) the guard must not be able to change V4's action, so it forwards everything and only
    records what enforcement would have done."""

    def __init__(self, *, listen_port: int, upstream: tuple, book: TicketBook,
                 enforcing: Callable, generation: Callable, on_event: Callable,
                 max_message_bytes: int, idle_timeout_seconds: float):
        self.listen_port = listen_port
        self.upstream = upstream
        self.book = book
        self._enforcing = enforcing
        self._generation = generation
        self._on_event = on_event
        self.max_message_bytes = max_message_bytes
        self.idle_timeout_seconds = idle_timeout_seconds
        self._server = None
        self._connections: set = set()

    @property
    def listening(self) -> bool:
        return self._server is not None and self._server.is_serving()

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._serve, "127.0.0.1", self.listen_port,
                                                  limit=self.max_message_bytes + 65536)
        self.listen_port = self._server.sockets[0].getsockname()[1]

    async def aclose(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        for writer in list(self._connections):
            writer.close()

    def _event(self, event: str, **fields) -> None:
        try:
            self._on_event({"kind": "egress", "contract": CONTRACT_ID, "event": event, **fields})
        except Exception:  # noqa: BLE001 — accounting must never decide delivery
            log.exception("egress event dropped")

    async def _serve(self, reader, writer) -> None:
        self._connections.add(writer)
        upstream_writer = None
        pump = None
        buf = bytearray()
        raw_passthrough = False
        try:
            while True:
                try:
                    data = await asyncio.wait_for(reader.read(65536), self.idle_timeout_seconds)
                except (asyncio.TimeoutError, ConnectionError):
                    return
                if not data:
                    if buf and self._enforcing():
                        self._event(EVENT_REJECTED, reason=REJECT_TRUNCATED, wire_bytes=len(buf))
                    return
                buf += data
                if raw_passthrough:
                    upstream_writer.write(bytes(buf))
                    buf.clear()
                    await upstream_writer.drain()
                    continue
                while buf:
                    verdict = self._next_message(buf)
                    if verdict is None:
                        break                    # incomplete: read more
                    message, reject, ticket = verdict
                    if reject is not None:
                        if self._enforcing():
                            self._event(EVENT_REJECTED, reason=reject, wire_bytes=len(buf))
                            if pump is None:
                                writer.write(BAD_GATEWAY)
                                await writer.drain()
                            return
                        # V4 authority: record, then stop parsing this connection.
                        self._event(EVENT_PASSTHROUGH, reason=reject, wire_bytes=len(buf))
                        message = bytes(buf)
                        raw_passthrough = True
                    if upstream_writer is None:
                        try:
                            upstream_reader, upstream_writer = await asyncio.open_connection(
                                *self.upstream)
                        except OSError:
                            self._event(EVENT_REJECTED, reason="upstream_unreachable",
                                        wire_bytes=len(message))
                            return
                        pump = asyncio.ensure_future(self._pump(upstream_reader, writer))
                    upstream_writer.write(message)
                    await upstream_writer.drain()
                    if ticket is not None:
                        self._event(EVENT_DELIVERED, correlation_id=ticket.correlation_id,
                                    wire_bytes=len(message), wire_sha256=ticket.wire_sha256,
                                    enforcing=bool(self._enforcing()))
                    del buf[:len(message)]
        except (ConnectionError, asyncio.IncompleteReadError):
            return
        finally:
            self._connections.discard(writer)
            if pump is not None:
                pump.cancel()
            if upstream_writer is not None:
                upstream_writer.close()
            writer.close()

    def _next_message(self, buf: bytearray):
        """None when more bytes are needed; else (message bytes, reject reason or None, ticket or
        None). Enforcement is decided here, per message, on the exact bytes about to be forwarded.
        DELIVERED is only claimed by the caller, after those bytes were written to the upstream."""
        if len(buf) > self.max_message_bytes:
            return b"", REJECT_TOO_LARGE, None
        snapshot = bytes(buf)
        try:
            parsed = W.parse_request(snapshot)
        except W.WireError as exc:
            if exc.reason in WIRE_INCOMPLETE:
                return None
            return b"", f"{REJECT_WIRE}:{exc.reason}", None
        message = snapshot[:parsed.consumed]
        digest = hashlib.sha256(message).hexdigest()
        ticket = self.book.redeem(digest)
        if ticket is None:
            if self._enforcing():
                return b"", REJECT_UNTICKETED, None
            self._event(EVENT_PASSTHROUGH, reason=REJECT_UNTICKETED, wire_bytes=len(message),
                        wire_sha256=digest)
            return message, None, None
        if ticket.generation != self._generation() and self._enforcing():
            return b"", REJECT_STALE_PROFILE, None
        return message, None, ticket

    @staticmethod
    async def _pump(upstream_reader, writer) -> None:
        """Upstream to mitmproxy, unchanged. When the upstream ends, this connection ends."""
        try:
            while True:
                data = await upstream_reader.read(65536)
                if not data:
                    return
                writer.write(data)
                await writer.drain()
        except (ConnectionError, asyncio.CancelledError):
            return
        finally:
            writer.close()
