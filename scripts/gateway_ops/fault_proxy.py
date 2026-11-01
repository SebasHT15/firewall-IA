"""
A small HTTP forwarder in front of a V5 service, which can fail on request. The same injection then
works against a real service, whose weights cannot be made to misbehave at will, and against a double.

Everything else passes through unchanged. `identity` overrides fields of /health or /contract, to show
the gateway a service that is not the one in its manifest while the real one keeps running. It counts the
calls that reached the service, which is an independent count of V5 calls.
Standard library only. A test fixture: it is never in a deployment path.
"""
import json
import socket
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
# Every way a V5 answer can be unusable. A gateway must deny on each one.
ANSWER_FAULTS = {
    "error500": (500, {"detail": "injected"}),
    "error422": (422, {"detail": "injected"}),
    "saturated503": (503, {"detail": "Saturated"}),
    "bad_json": (200, b"{not json"),
    "invalid_vocabulary": (200, {"status": "invalid", "decision": None,
                                 "invalid_reason": "not_in_vocabulary", "generate_ms": 1.0}),
    "invalid_no_eos": (200, {"status": "invalid", "decision": None, "invalid_reason": "no_eos",
                             "generate_ms": 1.0}),
    "content_rejected": (200, {"status": "invalid", "decision": None,
                               "invalid_reason": "content_rejected", "generate_ms": 0.0}),
    "ok_without_decision": (200, {"status": "ok", "decision": None, "generate_ms": 1.0}),
    "unknown_status": (200, {"status": "maybe", "decision": "ALLOW", "generate_ms": 1.0}),
}
CONNECTION_FAULTS = ("hang", "drop")


class FaultProxy:
    def __init__(self, upstream: str, hang_seconds: float = 30.0):
        self.upstream = upstream.rstrip("/")
        self.hang_seconds = hang_seconds
        self.fault = None
        self.identity = {}
        self.classify_calls = 0
        self._lock = threading.Lock()
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def reply(self, status, payload):
                data = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def forward(self, data=None, method="GET"):
                request = urllib.request.Request(proxy.upstream + self.path, data=data, method=method,
                                                 headers={"Content-Type": "application/json"})
                try:
                    with OPENER.open(request, timeout=30) as response:
                        return response.status, response.read()
                except urllib.error.HTTPError as exc:
                    return exc.code, exc.read()
                except OSError:
                    return 502, {"detail": "service unreachable"}

            def do_GET(self):
                status, body = self.forward()
                if status == 200 and self.path in proxy.identity:
                    body = {**json.loads(body), **proxy.identity[self.path]}
                self.reply(status, body)

            def do_POST(self):
                data = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                fault = proxy.fault if self.path == "/classify" else None
                if fault in ANSWER_FAULTS:
                    self.reply(*ANSWER_FAULTS[fault])
                elif fault == "hang":
                    time.sleep(proxy.hang_seconds)
                    self.close_connection = True
                elif fault == "drop":
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.close_connection = True
                else:
                    if self.path == "/classify":
                        with proxy._lock:
                            proxy.classify_calls += 1
                    self.reply(*self.forward(data, "POST"))

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
