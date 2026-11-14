"""Measured HTTP clients for the challenge-app trial transport strata.

Each result includes the entire response body for private oracle evaluation. The
public trial row stores only its length and SHA-256. A reused TLS session is
reported as observed; requesting resumption does not imply that it happened.
"""
import time

import wire_clients as WC

TRANSPORTS = ("h1_plain_gateway", "h1_tls_new", "h1_tls_resumed", "h1_tls_keepalive",
              "h2_tls_new", "h2_tls_resumed", "h2_tls_keepalive")


class TrialClient:
    def __init__(self, state, transport):
        if transport not in TRANSPORTS:
            raise ValueError("unknown transport stratum")
        if transport == "h1_plain_gateway" and not state.get("gateway_config"):
            raise ValueError("plain gateway transport requires a cascade arm")
        self.state = state
        self.transport = transport
        self.host = state["hostname"]
        self.port = state["ports"]["front_tls"]
        self.h1_context = WC.tls_context(state["pki"]["ca_cert"], ("http/1.1",))
        self.h2_context = WC.tls_context(state["pki"]["ca_cert"], ("h2",))
        self.h1_session = None
        self.h2_session = None
        self.h1_sock = None
        self.h1_connect_timings = {}
        self.h2_conn = None
        self.connection_requests = 0

    def request(self, method, target, headers=(), body=b""):
        # One measurement covers connect/TLS (if needed) through final response.
        # A broken persistent connection is reset for the NEXT request; NEVER
        # retry the current request implicitly (it may already have had effects).
        start = time.perf_counter()
        try:
            result = self._request(method, target, headers, body)
        except Exception as exc:  # transport libraries use their own protocol exception types
            result = {"status": None, "headers": [], "body": b"",
                      "error": type(exc).__name__}
        result["elapsed_ms"] = (time.perf_counter() - start) * 1000
        if result.get("error") is not None:
            self.close()
        return result

    def _request(self, method, target, headers=(), body=b""):
        transport = self.transport
        if transport == "h1_plain_gateway":
            raw = WC.build_h1(method, target, self.host, headers, body)
            return WC.h1_exchange(self.state["ports"]["gateway"], raw, head=method == "HEAD")
        if transport.startswith("h1_"):
            raw = WC.build_h1(method, target, self.host, headers, body)
            if transport == "h1_tls_keepalive":
                if self.h1_sock is None:
                    self.h1_sock = WC.connect(self.port, tls=self.h1_context, server_hostname=self.host,
                                              timings=self.h1_connect_timings)
                    self.connection_requests = 0
                t0 = time.perf_counter()
                self.h1_sock.sendall(raw)
                status, response_headers, response_body = WC.read_response(
                    self.h1_sock, head_request=method == "HEAD")
                self.connection_requests += 1
                return {"status": status, "headers": response_headers, "body": response_body,
                        "error": None if status else "no_response",
                        "elapsed_ms": (time.perf_counter() - t0) * 1000,
                        "alpn": self.h1_sock.selected_alpn_protocol(),
                        "tls_version": self.h1_sock.version(),
                        "tls_session_reused": self.h1_sock.session_reused,
                        "tcp_connect_ms": self.h1_connect_timings.get("tcp_connect_ms")
                        if self.connection_requests == 1 else 0.0,
                        "tls_handshake_ms": self.h1_connect_timings.get("tls_handshake_ms")
                        if self.connection_requests == 1 else 0.0,
                        "connection_requests": self.connection_requests}
            session = self.h1_session if transport == "h1_tls_resumed" else None
            result = WC.h1_exchange(self.port, raw, tls=self.h1_context,
                                    server_hostname=self.host, head=method == "HEAD", session=session)
            self.h1_session = result.pop("tls_session", self.h1_session)
            self.connection_requests += 1
            result["connection_requests"] = 1
            return result

        reused_connection = transport == "h2_tls_keepalive"
        t0 = time.perf_counter()
        if not reused_connection or self.h2_conn is None:
            session = self.h2_session if transport == "h2_tls_resumed" else None
            self.h2_conn = WC.H2Client(self.port, self.h2_context, self.host, session=session)
            self.connection_requests = 0
        conn = self.h2_conn
        request_headers = WC.h2_request_headers(method, target, self.host, headers, body)
        sid = conn.request(request_headers, body)
        stream = conn.collect([sid])[sid]
        self.connection_requests += 1
        result = {"status": stream["status"], "headers": stream["headers"],
                  "body": stream["body"], "error": stream["reset"] or conn.terminated,
                  "elapsed_ms": (time.perf_counter() - t0) * 1000,
                  "alpn": conn.alpn, "tls_version": conn.sock.version(),
                  "tls_session_reused": conn.sock.session_reused,
                  "tcp_connect_ms": conn.connect_timings.get("tcp_connect_ms")
                  if self.connection_requests == 1 else 0.0,
                  "tls_handshake_ms": conn.connect_timings.get("tls_handshake_ms")
                  if self.connection_requests == 1 else 0.0,
                  "connection_requests": self.connection_requests}
        self.h2_session = conn.sock.session
        if not reused_connection:
            conn.close()
            self.h2_conn = None
        return result

    def close(self):
        if self.h1_sock is not None:
            self.h1_sock.close()
            self.h1_sock = None
        if self.h2_conn is not None:
            self.h2_conn.close()
            self.h2_conn = None
