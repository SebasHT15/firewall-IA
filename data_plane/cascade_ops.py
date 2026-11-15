"""
firewall-IA — operational primitives of the cascade gateway: counters, a bounded background
worker, a bounded JSONL record sink and a loopback admin listener.

NOTHING HERE MAY REACH A REQUEST'S FATE. A full queue, a slow disk or a broken log drops a record
and counts the drop; it never blocks the request path and never changes a decision.

Records and metrics carry closed codes, identifiers and numbers only. `safe_record` removes any key
that could hold request content, and `Metrics` replaces any label that is not a short closed token,
so a programming mistake loses a value instead of writing a payload to disk.

Standard library only.
"""

import asyncio
import json
import logging
import math
import os
import queue
import re
import threading
import time
from typing import Callable, Optional

import http1_wire as W

log = logging.getLogger("firewall.data_plane.cascade_ops")

_LABEL = re.compile(r"^[A-Za-z0-9_:.\-]{1,64}$")
LATENCY_BUCKETS_MS = (1, 2, 5, 10, 25, 50, 100, 200, 400, 800, 1600, 3200, 6400)
FORBIDDEN_RECORD_KEYS = frozenset({
    "text", "canonical_text", "canonical_request", "body", "headers", "header", "target", "path",
    "query", "url", "payload", "raw", "raw_request", "raw_request_text", "request", "wire",
    "authorization", "cookie",
})
_ADMIN_MAX_REQUEST = 4096


def safe_record(record: dict) -> dict:
    """A copy of `record` without any key that could carry request content, at any depth."""
    def clean(value):
        if isinstance(value, dict):
            return {k: clean(v) for k, v in value.items() if str(k).lower() not in FORBIDDEN_RECORD_KEYS}
        if isinstance(value, (list, tuple)):
            return [clean(v) for v in value]
        return value
    return clean(record)


class Metrics:
    """Thread-safe counters, gauges and latency histograms, rendered in Prometheus text format."""

    def __init__(self):
        self._lock = threading.Lock()
        self._counters: dict = {}
        self._gauges: dict = {}
        self._hist: dict = {}

    @staticmethod
    def _key(name, labels):
        items = tuple(sorted((k, v if isinstance(v, str) and _LABEL.match(v) else "other")
                             for k, v in labels.items()))
        return name, items

    def inc(self, name: str, amount: int = 1, **labels) -> None:
        key = self._key(name, labels)
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + amount

    def gauge(self, name: str, value: float, **labels) -> None:
        key = self._key(name, labels)
        with self._lock:
            self._gauges[key] = value

    def observe_ms(self, name: str, value: float, **labels) -> None:
        if value is None or not math.isfinite(value):
            return
        key = self._key(name, labels)
        with self._lock:
            hist = self._hist.setdefault(key, {"count": 0, "sum": 0.0,
                                               "buckets": [0] * len(LATENCY_BUCKETS_MS)})
            hist["count"] += 1
            hist["sum"] += value
            for i, edge in enumerate(LATENCY_BUCKETS_MS):
                if value <= edge:
                    hist["buckets"][i] += 1

    def value(self, name: str, **labels) -> int:
        with self._lock:
            return self._counters.get(self._key(name, labels), 0)

    def total(self, name: str) -> int:
        with self._lock:
            return sum(v for (n, _), v in self._counters.items() if n == name)

    def snapshot(self) -> dict:
        def row(key, value):
            return {"name": key[0], "labels": dict(key[1]), "value": value}
        with self._lock:
            return {"counters": [row(k, v) for k, v in sorted(self._counters.items())],
                    "gauges": [row(k, v) for k, v in sorted(self._gauges.items())],
                    "histograms": [row(k, {"count": v["count"], "sum": v["sum"],
                                           "le_ms": dict(zip(map(str, LATENCY_BUCKETS_MS),
                                                             v["buckets"]))})
                                   for k, v in sorted(self._hist.items())]}

    def render(self) -> str:
        def fmt(items, extra=()):
            parts = [f'{k}="{v}"' for k, v in tuple(items) + tuple(extra)]
            return "{" + ",".join(parts) + "}" if parts else ""
        lines = []
        with self._lock:
            for (name, items), value in sorted(self._counters.items()):
                lines.append(f"{name}{fmt(items)} {value}")
            for (name, items), value in sorted(self._gauges.items()):
                lines.append(f"{name}{fmt(items)} {value}")
            for (name, items), hist in sorted(self._hist.items()):
                for edge, count in zip(LATENCY_BUCKETS_MS, hist["buckets"]):
                    lines.append(f"{name}_bucket{fmt(items, (('le', str(edge)),))} {count}")
                lines.append(f"{name}_bucket{fmt(items, (('le', '+Inf'),))} {hist['count']}")
                lines.append(f"{name}_sum{fmt(items)} {hist['sum']:.3f}")
                lines.append(f"{name}_count{fmt(items)} {hist['count']}")
        return "\n".join(lines) + "\n"


class BoundedWorker:
    """A bounded queue served by daemon threads. `submit` never blocks and never raises: it answers
    whether the item was accepted. `close` stops intake, drains for at most `drain_seconds` and
    returns what was left, so the caller can account for every item instead of losing it silently."""

    def __init__(self, handler: Callable, maxsize: int, workers: int = 1, name: str = "worker"):
        self._handler = handler
        self._queue: queue.Queue = queue.Queue(maxsize)
        self._closed = threading.Event()
        self._threads = [threading.Thread(target=self._run, name=f"{name}-{i}", daemon=True)
                         for i in range(workers)]
        for t in self._threads:
            t.start()

    def submit(self, item) -> bool:
        if self._closed.is_set():
            return False
        try:
            self._queue.put_nowait(item)
            return True
        except queue.Full:
            return False

    def qsize(self) -> int:
        return self._queue.qsize()

    def _run(self):
        while True:
            try:
                item = self._queue.get(timeout=0.05)
            except queue.Empty:
                if self._closed.is_set():
                    return
                continue
            try:
                self._handler(item)
            except Exception:  # noqa: BLE001 — a handler fault must not end the worker
                log.exception("background handler failed; item dropped")

    def close(self, drain_seconds: float = 0.0) -> list:
        self._closed.set()
        deadline = time.monotonic() + drain_seconds
        for t in self._threads:
            t.join(max(0.0, deadline - time.monotonic()))
        left = []
        while True:
            try:
                left.append(self._queue.get_nowait())
            except queue.Empty:
                return left


class JsonlSink:
    """Append-only JSONL with size-based rotation behind a bounded queue. A disk that cannot keep up
    costs records, counted in `firewall_log_dropped_total`, never request latency."""

    def __init__(self, path: str, max_bytes: int, max_files: int, queue_size: int,
                 metrics: Optional[Metrics] = None):
        self.path = path
        self.max_bytes = max_bytes
        self.max_files = max_files
        self._metrics = metrics or Metrics()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._fh = open(path, "a", encoding="utf-8")
        self._size = self._fh.tell()
        self._worker = BoundedWorker(self._write, queue_size, name="jsonl-sink")

    def write(self, record: dict) -> None:
        try:
            line = json.dumps(safe_record(record), separators=(",", ":"), sort_keys=True,
                              allow_nan=False)
        except (TypeError, ValueError):
            self._metrics.inc("firewall_log_dropped_total", reason="unserializable")
            return
        if not self._worker.submit(line):
            self._metrics.inc("firewall_log_dropped_total", reason="queue_full")

    def _rotate(self):
        self._fh.close()
        for i in range(self.max_files - 1, 0, -1):
            older = f"{self.path}.{i}"
            if os.path.exists(older):
                if i == self.max_files - 1:
                    os.unlink(older)
                else:
                    os.replace(older, f"{self.path}.{i + 1}")
        if self.max_files > 1:
            os.replace(self.path, f"{self.path}.1")
        else:
            os.unlink(self.path)
        self._fh = open(self.path, "a", encoding="utf-8")
        self._size = 0

    def _write(self, line: str):
        try:
            if self._size + len(line) + 1 > self.max_bytes:
                self._rotate()
            self._fh.write(line + "\n")
            self._fh.flush()
            self._size += len(line) + 1
            self._metrics.inc("firewall_log_written_total")
        except OSError:
            self._metrics.inc("firewall_log_dropped_total", reason="write_error")

    def close(self, drain_seconds: float = 2.0) -> None:
        left = self._worker.close(drain_seconds)
        for line in left:
            self._write(line)
        try:
            self._fh.close()
        except OSError:
            pass


class AdminServer:
    """Loopback-only `/healthz`, `/readyz`, `/status` and `/metrics`. It is a separate listener so no
    client request can reach it through the proxy and no special path exists on the proxied port."""

    def __init__(self, port: int, *, ready: Callable, status: Callable, metrics: Metrics):
        self.port = port
        self._ready = ready
        self._status = status
        self._metrics = metrics
        self._server = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._serve, "127.0.0.1", self.port)
        self.port = self._server.sockets[0].getsockname()[1]

    async def _serve(self, reader, writer):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2.0)
            if len(head) > _ADMIN_MAX_REQUEST:
                return
            parsed = W.parse_request(head)
            status, ctype, body = self._answer(parsed.parts.method, parsed.parts.target)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError,
                W.WireError):
            status, ctype, body = "400 Bad Request", "text/plain", b"bad request\n"
        try:
            writer.write(f"HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\n"
                         f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                         .encode("ascii") + body)
            await writer.drain()
        except OSError:
            pass
        finally:
            writer.close()

    def _answer(self, method: bytes, target: bytes):
        if method != b"GET":
            return "405 Method Not Allowed", "text/plain", b"GET only\n"
        if target == b"/healthz":
            return "200 OK", "application/json", b'{"status":"alive"}\n'
        if target == b"/readyz":
            ready, detail = self._ready()
            body = json.dumps({"ready": ready, **detail}, sort_keys=True).encode("utf-8") + b"\n"
            return ("200 OK" if ready else "503 Service Unavailable"), "application/json", body
        if target == b"/status":
            return ("200 OK", "application/json",
                    json.dumps(self._status(), sort_keys=True).encode("utf-8") + b"\n")
        if target == b"/metrics":
            return "200 OK", "text/plain; version=0.0.4", self._metrics.render().encode("utf-8")
        return "404 Not Found", "text/plain", b"not found\n"

    async def aclose(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
