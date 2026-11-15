"""
Test clients for the local stack: exact HTTP/1.1 bytes over plain TCP or TLS, and HTTP/2 over TLS with
the `h2` library. A TEST CLIENT, never in a request path. It also parses an HTTP/1.1 request as an
upstream received it, independently of the gateway's parser.
"""
import socket
import ssl
import time

import h2.config
import h2.connection
import h2.errors
import h2.events
import h2.exceptions


# ─────────────────────────────── HTTP/1.1 ───────────────────────────────
def _dechunk(data: bytes):
    """(body, trailers bytes) of a complete chunked body."""
    out, pos = bytearray(), 0
    while True:
        line_end = data.index(b"\r\n", pos)
        size = int(data[pos:line_end].split(b";")[0], 16)
        pos = line_end + 2
        if size == 0:
            return bytes(out), data[pos:]
        out += data[pos:pos + size]
        pos += size + 2


def parse_request(raw: bytes) -> dict:
    """Fields of one HTTP/1.1 request message exactly as received."""
    head, _, rest = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    method, target, version = lines[0].split(b" ", 2)
    headers = []
    for line in lines[1:]:
        name, _, value = line.partition(b":")
        headers.append((name.decode("latin-1"), value.strip(b" \t").decode("latin-1")))
    lower = [n.lower() for n, _ in headers]
    if "transfer-encoding" in lower:
        body, _trailers = _dechunk(rest)
        framing = "chunked"
    elif "content-length" in lower:
        body, framing = rest, "content-length"
    else:
        body, framing = rest, "none"
    return {"method": method.decode("latin-1"), "target": target.decode("latin-1"),
            "version": version.decode("latin-1"), "headers": headers, "body": body, "framing": framing}


def read_response(sock, head_request=False, timeout=10.0):
    """(status, headers, body) of one response; status None when the connection ended first."""
    sock.settimeout(timeout)
    buf = b""
    try:
        while b"\r\n\r\n" not in buf:
            data = sock.recv(65536)
            if not data:
                return None, [], buf
            buf += data
        head, _, rest = buf.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        status = int(lines[0].split(b" ", 2)[1])
        headers = []
        for line in lines[1:]:
            n, _, v = line.partition(b":")
            headers.append((n.decode("latin-1").lower(), v.strip().decode("latin-1")))
        names = dict(headers)
        if head_request or status in (204, 304) or 100 <= status < 200:
            return status, headers, b""
        if "chunked" in names.get("transfer-encoding", ""):
            while True:
                try:
                    body, _ = _dechunk(rest)
                    return status, headers, body
                except (ValueError, IndexError):
                    data = sock.recv(65536)
                    if not data:
                        return None, headers, rest
                    rest += data
        if "content-length" in names:
            length = int(names["content-length"])
            while len(rest) < length:
                data = sock.recv(65536)
                if not data:
                    return None, headers, rest
                rest += data
            return status, headers, rest[:length]
        while True:
            data = sock.recv(65536)
            if not data:
                return status, headers, rest
            rest += data
    except (OSError, ValueError, IndexError):
        return None, [], buf


def build_h1(method, target, host, headers=(), body=b"", chunked=False, chunk_size=None):
    lines = [f"{method} {target} HTTP/1.1", f"Host: {host}"]
    lines += [f"{n}: {v}" for n, v in headers]
    if chunked:
        lines.append("Transfer-Encoding: chunked")
    elif body:
        lines.append(f"Content-Length: {len(body)}")
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
    if chunked:
        size = chunk_size or max(1, len(body) // 3 or 1)
        for i in range(0, len(body), size):
            part = body[i:i + size]
            raw += f"{len(part):x}\r\n".encode() + part + b"\r\n"
        raw += b"0\r\n\r\n"
    else:
        raw += body
    return raw


def tls_context(ca_cert, alpn):
    ctx = ssl.create_default_context(cafile=ca_cert)
    ctx.set_alpn_protocols(list(alpn))
    return ctx


def connect(port, *, tls=None, server_hostname=None, session=None, timeout=10.0, timings=None):
    started = time.perf_counter()
    raw = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    if timings is not None:
        timings["tcp_connect_ms"] = (time.perf_counter() - started) * 1000
    if tls is None:
        return raw
    try:
        sock = tls.wrap_socket(raw, server_hostname=server_hostname, session=session,
                               do_handshake_on_connect=False)
        started = time.perf_counter()
        sock.do_handshake()
        if timings is not None:
            timings["tls_handshake_ms"] = (time.perf_counter() - started) * 1000
        return sock
    except Exception:
        raw.close()
        raise


def connect_host(host, port, timeout=10.0):
    return socket.create_connection((host, int(port)), timeout=timeout)


def h1_exchange(port, raw, *, tls=None, server_hostname=None, head=False, session=None, timeout=10.0):
    """One request on a new connection. Returns a result dict."""
    started = time.perf_counter()
    timings = {}
    try:
        sock = connect(port, tls=tls, server_hostname=server_hostname, session=session,
                       timeout=timeout, timings=timings)
    except (OSError, ssl.SSLError) as exc:
        return {"status": None, "error": f"connect:{type(exc).__name__}", "headers": [], "body": b""}
    with sock:
        info = {}
        if tls is not None:
            info = {"alpn": sock.selected_alpn_protocol(), "tls_version": sock.version(),
                    "tls_session_reused": sock.session_reused}
        try:
            sock.sendall(raw)
        except OSError as exc:
            return {"status": None, "error": f"send:{type(exc).__name__}", "headers": [], "body": b"", **info}
        status, headers, body = read_response(sock, head_request=head, timeout=timeout)
        if tls is not None:
            info["tls_session"] = sock.session
    return {"status": status, "error": None if status else "no_response", "headers": headers, "body": body,
            "elapsed_ms": (time.perf_counter() - started) * 1000, **timings, **info}


# ─────────────────────────────── HTTP/2 ───────────────────────────────
class H2Client:
    """One TLS connection with ALPN h2. Streams are opened with `request` and collected with `collect`."""

    def __init__(self, port, tls, server_hostname, timeout=10.0, validate=True, session=None):
        self.connect_timings = {}
        self.sock = connect(port, tls=tls, server_hostname=server_hostname, timeout=timeout,
                            session=session, timings=self.connect_timings)
        self.alpn = self.sock.selected_alpn_protocol()
        if self.alpn != "h2":
            raise RuntimeError(f"ALPN {self.alpn!r}")
        config = h2.config.H2Configuration(client_side=True, header_encoding=None,
                                           validate_outbound_headers=validate,
                                           normalize_outbound_headers=False)
        self.conn = h2.connection.H2Connection(config=config)
        self.conn.initiate_connection()
        self.flush()
        self.streams = {}
        self.terminated = None

    def flush(self):
        data = self.conn.data_to_send()
        if data:
            self.sock.sendall(data)

    def pump(self, timeout=10.0):
        self.sock.settimeout(timeout)
        data = self.sock.recv(65536)
        if not data:
            self.terminated = self.terminated or "eof"
            return
        for ev in self.conn.receive_data(data):
            s = self.streams.get(getattr(ev, "stream_id", None))
            if isinstance(ev, h2.events.ResponseReceived) and s is not None:
                s["headers"] = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in ev.headers]
                s["status"] = int(dict(s["headers"])[":status"])
            elif isinstance(ev, h2.events.DataReceived) and s is not None:
                s["body"] += ev.data
                self.conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
            elif isinstance(ev, h2.events.StreamEnded) and s is not None:
                s["ended"] = True
            elif isinstance(ev, h2.events.StreamReset) and s is not None:
                s["reset"] = int(ev.error_code)
            elif isinstance(ev, h2.events.ConnectionTerminated):
                self.terminated = f"goaway:{int(ev.error_code)}"
        self.flush()

    def request(self, headers, body=b"", end=True, partial=None):
        """Open a stream. `partial`: send only that many body bytes and leave the stream open."""
        sid = self.conn.get_next_available_stream_id()
        self.streams[sid] = {"status": None, "headers": [], "body": b"", "ended": False, "reset": None}
        has_body = bool(body)
        self.conn.send_headers(sid, [(k.encode("latin-1"), v.encode("latin-1")) for k, v in headers],
                               end_stream=end and not has_body)
        self.flush()
        if has_body:
            payload = body if partial is None else body[:partial]
            pos = 0
            stream = self.streams[sid]
            try:
                while pos < len(payload):
                    if stream["reset"] is not None or stream["ended"] or self.terminated:
                        return sid          # the server answered early (e.g. 413) and closed the stream
                    room = min(self.conn.local_flow_control_window(sid), self.conn.max_outbound_frame_size)
                    if room <= 0:
                        try:
                            self.pump(timeout=5.0)
                        except (socket.timeout, TimeoutError):
                            return sid
                        continue
                    self.conn.send_data(sid, payload[pos:pos + room])
                    pos += room
                    self.flush()
                if end and partial is None:
                    self.conn.end_stream(sid)
                    self.flush()
            except h2.exceptions.StreamClosedError:
                return sid
        return sid

    def reset(self, sid):
        self.conn.reset_stream(sid, error_code=h2.errors.ErrorCodes.CANCEL)
        self.flush()

    def collect(self, sids, timeout=10.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not self.terminated:
            if all(self.streams[s]["ended"] or self.streams[s]["reset"] is not None for s in sids):
                break
            try:
                self.pump(timeout=max(0.05, deadline - time.monotonic()))
            except (socket.timeout, TimeoutError):
                break
            except (OSError, h2.exceptions.ProtocolError) as exc:
                self.terminated = f"error:{type(exc).__name__}"
        return {s: self.streams[s] for s in sids}

    def close(self):
        try:
            self.conn.close_connection()
            self.flush()
        except Exception:  # noqa: BLE001 — closing a test connection
            pass
        self.sock.close()



def h2_request_headers(method, target, authority, headers=(), body=b"", content_length=True):
    out = [(":method", method), (":scheme", "https"), (":authority", authority), (":path", target)]
    out += [(n.lower(), v) for n, v in headers]
    if body and content_length:
        out.append(("content-length", str(len(body))))
    return out
