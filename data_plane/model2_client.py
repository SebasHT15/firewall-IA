"""
firewall-IA — gateway side of the Model 2 worker.

`Model2WorkerClient.decide` is the router's `model2_decide` stage. It runs on the router's threads,
so it is synchronous, and every failure mode is an exception or a non-OK status: the router already
turns both into DEFER, so a dead, slow, busy or lying worker can only send a request to V5, never
block it and never allow it. A reply that claims anything but BLOCK/DEFER is a protocol violation.

The lifecycle mirrors the other workers (`hybrid_shadow_process`, `canonical_observer`): background
start, one exchange at a time, a deadline that ends in SIGKILL + reap, backoff, and giving up after
`max_consecutive_failures` until `heal()` retries. Those two are event-loop objects; this one is
thread-based because the router is, and it holds only that difference.

Handshake identity is compared with the manifest. A worker that loaded another artifact or policy is
INCOMPATIBLE: that is deterministic, it is never retried and it keeps the gateway not-ready.

Standard library only.
"""

import json
import logging
import math
import os
import selectors
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import Optional

HERE = os.path.dirname(os.path.abspath(__file__))

if HERE not in sys.path:
    sys.path.insert(0, HERE)

import canonical_observer as ipc  # noqa: E402

log = logging.getLogger("firewall.data_plane.model2")

PROTOCOL = "model2-worker-ipc/v1"
WORKER_SCRIPT = os.path.join(HERE, "model2_worker.py")

STARTING = "STARTING"
READY = "READY"
BACKOFF = "BACKOFF"
DISABLED = "DISABLED"
INCOMPATIBLE = "INCOMPATIBLE"
CLOSED = "CLOSED"

_DECISIONS = ("BLOCK", "DEFER")


class Model2Unavailable(RuntimeError):
    """No answer from Model 2 for this request. The router defers to V5."""


@dataclass(frozen=True)
class Model2Reply:
    decision: str
    status: str
    p_block: Optional[float]
    threshold: Optional[float]
    feature_view: str
    model_artifact_sha256: str
    policy_id: Optional[str]
    policy_sha256: Optional[str]
    policy_status: Optional[str]


def worker_argv(python: str, identity, max_frame_bytes: int, script: str = WORKER_SCRIPT) -> list:
    return [python, "-I", script, "--artifact", identity.artifact_path,
            "--artifact-sha256", identity.artifact_sha256, "--policy", identity.policy_path,
            "--max-frame-bytes", str(max_frame_bytes)]


class Model2WorkerClient:
    def __init__(self, argv: list, identity, bounds, max_frame_bytes: int,
                 env: Optional[dict] = None, clock=time.monotonic):
        self.argv = list(argv)
        self.identity = identity
        self.bounds = bounds
        self.max_frame_bytes = max_frame_bytes
        self._env = ipc.worker_environment() if env is None else env
        self._clock = clock
        self._lock = threading.Lock()         # one exchange at a time
        self._proc: Optional[subprocess.Popen] = None
        self._state = STARTING
        self._detail: Optional[str] = None
        self._failures = 0
        self._not_before = 0.0
        self._next_id = 0
        self._closed = False
        self._starting = False
        self.ever_ready = False
        self.spawn_count = 0
        self.kill_count = 0

    # ── state ───────────────────────────────────────────────────────────
    @property
    def state(self) -> str:
        return self._state

    def status(self) -> dict:
        return {"state": self._state, "detail": self._detail, "failures": self._failures}

    @property
    def incompatible(self) -> bool:
        return self._state == INCOMPATIBLE

    # ── lifecycle ───────────────────────────────────────────────────────
    def start(self) -> None:
        """Start the worker in the background. Never blocks and never raises. It runs on the gateway's
        event loop too, so a lock held by an exchange means "try again later", not "wait"."""
        if not self._lock.acquire(blocking=False):
            return
        try:
            if (self._closed or self._starting or self._proc is not None
                    or self._state in (DISABLED, INCOMPATIBLE)
                    or self._clock() < self._not_before):
                return
            self._starting = True
            self._state = STARTING
        finally:
            self._lock.release()
        threading.Thread(target=self._start_worker, name="model2-start", daemon=True).start()

    def _start_worker(self) -> None:
        proc = None
        try:
            self.spawn_count += 1
            try:
                proc = subprocess.Popen(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, env=self._env,
                                        start_new_session=True)
            except (OSError, ValueError):
                self._failed("worker_spawn_failed")
                return
            try:
                hello = self._read_frame(proc, self._clock() + self.bounds.startup_timeout_seconds)
            except (TimeoutError, OSError, ValueError) as exc:
                self._kill(proc)
                self._failed("worker_startup_timeout" if isinstance(exc, TimeoutError)
                             else "worker_protocol_error")
                return
            problem = self._handshake_problem(hello)
            if problem is not None:
                self._kill(proc)
                with self._lock:
                    self._state = INCOMPATIBLE
                    self._detail = problem
                log.warning("model 2 worker incompatible: %s", problem)
                return
            with self._lock:
                if self._closed:
                    self._kill(proc)
                    return
                self._proc = proc
                self._state = READY
                self._detail = None
                self.ever_ready = True
        finally:
            self._starting = False

    def _handshake_problem(self, hello: dict) -> Optional[str]:
        if hello.get("protocol") != PROTOCOL:
            return "protocol_mismatch"
        if hello.get("ready") is not True:
            return "worker_not_ready"
        identity = self.identity
        for key, expected in (("model_artifact_sha256", identity.artifact_sha256),
                              ("feature_view", identity.feature_view),
                              ("policy_sha256", identity.policy_sha256),
                              ("policy_status", identity.policy_status)):
            if hello.get(key) != expected:
                return f"{key}_mismatch"
        return None

    def _failed(self, detail: str) -> None:
        self._failures += 1
        self._detail = detail
        if self._failures >= self.bounds.max_consecutive_failures:
            self._state = DISABLED
        else:
            self._state = BACKOFF
            self._not_before = self._clock() + self.bounds.restart_backoff_seconds

    def _kill(self, proc: subprocess.Popen) -> None:
        self.kill_count += 1
        for stream in (proc.stdin, proc.stdout):
            try:
                stream.close()
            except (OSError, ValueError):
                pass
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            log.warning("model 2 worker %s not reaped after SIGKILL", proc.pid)

    def heal(self) -> None:
        """From the gateway's periodic probe: notice a dead worker without waiting for a request, and
        give a gave-up one another chance. A deterministic INCOMPATIBLE is never retried."""
        if not self._lock.acquire(blocking=False):
            return
        try:
            proc = self._proc
            if proc is not None and proc.poll() is not None:
                self._drop(proc, "worker_exited")
            if self._state == DISABLED and not self._closed:
                self._state = BACKOFF
                self._failures = 0
                self._not_before = 0.0
        finally:
            self._lock.release()
        self.start()

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._state = CLOSED
            proc, self._proc = self._proc, None
        if proc is not None:
            self._kill(proc)

    # ── framed I/O with one deadline ────────────────────────────────────
    def _read_exactly(self, fd: int, n: int, deadline: float) -> bytes:
        out = bytearray()
        with selectors.DefaultSelector() as sel:
            sel.register(fd, selectors.EVENT_READ)
            while len(out) < n:
                left = deadline - self._clock()
                if left <= 0 or not sel.select(left):
                    raise TimeoutError("read deadline")
                chunk = os.read(fd, n - len(out))
                if not chunk:
                    raise ConnectionError("worker closed its pipe")
                out += chunk
        return bytes(out)

    def _read_frame(self, proc, deadline: float) -> dict:
        fd = proc.stdout.fileno()
        (length,) = struct.unpack(">I", self._read_exactly(fd, ipc.LENGTH_PREFIX, deadline))
        if length > ipc.MAX_REPLY_BYTES:
            raise ValueError("reply over the frame cap")
        return ipc._decode_reply(self._read_exactly(fd, length, deadline))

    def _write_all(self, proc, data: bytes, deadline: float) -> None:
        fd = proc.stdin.fileno()
        os.set_blocking(fd, False)
        view = memoryview(data)
        with selectors.DefaultSelector() as sel:
            sel.register(fd, selectors.EVENT_WRITE)
            while view:
                left = deadline - self._clock()
                if left <= 0 or not sel.select(left):
                    raise TimeoutError("write deadline")
                try:
                    view = view[os.write(fd, view):]
                except BlockingIOError:
                    continue

    # ── the router's stage ──────────────────────────────────────────────
    def decide(self, *, canonical_outcome: str, canonical_text: Optional[str]) -> Model2Reply:
        deadline = self._clock() + self.bounds.timeout_seconds
        left = deadline - self._clock()
        if not self._lock.acquire(timeout=max(left, 0.0)):
            raise Model2Unavailable("busy")
        try:
            proc = self._proc
            if proc is not None and proc.poll() is not None:
                self._drop(proc, "worker_exited")
                proc = None
            if proc is None:
                raise Model2Unavailable(self._state)
            self._next_id += 1
            request_id = self._next_id
            frame = ipc.encode_frame(
                json.dumps({"id": request_id, "canonical_outcome": canonical_outcome,
                            "canonical_text": canonical_text}).encode("utf-8"),
                self.max_frame_bytes)
            try:
                self._write_all(proc, frame, deadline)
                reply = self._read_frame(proc, deadline)
                result = self._validate(reply, request_id)
            except TimeoutError:
                self._drop(proc, "worker_timeout")
                raise Model2Unavailable("timeout") from None
            except (OSError, ValueError, ipc.FrameError):
                self._drop(proc, "worker_protocol_error")
                raise Model2Unavailable("protocol") from None
            self._failures = 0
            return result
        finally:
            self._lock.release()
            if self._proc is None:
                self.start()

    def _drop(self, proc, detail: str) -> None:
        self._proc = None
        self._kill(proc)
        self._failed(detail)

    def _validate(self, reply: dict, request_id: int) -> Model2Reply:
        if reply.get("id") != request_id or reply.get("ok") is not True:
            raise ValueError("reply does not answer this request")
        decision = reply.get("decision")
        if decision not in _DECISIONS:          # ALLOW does not exist at this boundary
            raise ValueError("decision outside BLOCK/DEFER")
        status = reply.get("status")
        if not isinstance(status, str):
            raise ValueError("status is not a string")
        p_block = reply.get("p_block")
        if p_block is not None and (isinstance(p_block, bool) or not isinstance(p_block, (int, float))
                                    or not math.isfinite(p_block) or not 0.0 <= p_block <= 1.0):
            raise ValueError("p_block is not a probability")
        identity = self.identity
        if (reply.get("model_artifact_sha256") != identity.artifact_sha256
                or reply.get("policy_sha256") != identity.policy_sha256):
            raise ValueError("reply from another identity")
        return Model2Reply(decision, status, p_block, reply.get("threshold"),
                           reply.get("feature_view"), reply.get("model_artifact_sha256"),
                           reply.get("policy_id"), reply.get("policy_sha256"),
                           reply.get("policy_status"))
