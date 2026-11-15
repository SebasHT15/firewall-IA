"""
firewall-IA — canonical-request/v1 OBSERVER, SEPARATE-PROCESS runtime (issue #68, PREPARATION).

SHADOW / OBSERVE-ONLY. This module produces a `CanonicalObservation` to be logged and nothing
else. There is no ALLOW path, no threshold, no Fast Path eligibility decided here. V4 via /classify
stays the only enforcement decision (D4, D25, D34, D43). The gateway wiring (data_plane.py,
config.yaml) is the coordinator's; this module is dedicated to the observation slice.

WHY A SEPARATE PROCESS (not synchronous-in-hook, not a thread):
  canonicalize is NOT CPU-light. Measured on this machine (2026-10-21, .venv-dataplane, Python
  3.12): a ~1 MiB body of ~52,400 concatenated empty gzip members (decodes to 0 bytes, stays under
  the 1 MiB R8 cap) takes 28.3-29.7 ms in `canonical_request.canonicalize`; a 1 MiB identity body
  ~9.5 ms; a tiny request ~0.01 ms. 28 ms of GIL-holding work on the event loop would stall the
  gateway for every other request. A THREAD timeout would stop WAITING but could not CANCEL that
  work (CPython cannot kill a running thread). Only a worker PROCESS can be bounded and, on
  overrun, SIGKILLed and reaped so the computation actually stops. The lifecycle below is modelled
  on `hybrid_shadow_process.ProcessShadowRunner`.

KEY DIFFERENCE from the Analyzer worker: this worker runs in the DATA-PLANE interpreter (stdlib
plus the brotli/zstandard that mitmproxy already ships) — NO numpy/sklearn/torch. Because the
worker must itself canonicalize, the IPC carries a bounded request SNAPSHOT (method/target/headers/
body), not 34 numeric features. So the 64 KiB newline-JSON line of the Analyzer IPC is NOT used
here: the wire is a LENGTH-PREFIXED BINARY FRAME (4-byte big-endian length + payload) with an
explicit maximum; any frame over the maximum is a protocol error and the worker is killed. The
worker returns a SMALL reply carrying ONLY safe fields (codes/sizes/hash). No request byte — not
the target, a query, a header value or the body — is ever placed in a reply, a status or a log.

ADMISSION BOUNDING (before any copy/submit): the WHOLE snapshot is bounded — method length, target
length, header count, aggregate header bytes, body bytes, and the serialized snapshot size — and
the worker's reply size is bounded on read. Anything over a bound is DROP (an observation status),
NEVER an HTTP reject: dropping an observation cannot change what the client receives. A cap on the
body alone would not bound the whole snapshot, and no cap here can reclaim memory mitmproxy already
spent RECEIVING the request before this hook ran — that pre-buffer limit belongs to mitmproxy
options (`body_size_limit`, `stream_large_bodies`) and is the coordinator's to set.

STATUSES (all explicit; a canonical REJECT is a SUCCESSFUL observation, status OK + outcome REJECT):
  OK               canonicalize ran; carries its outcome (ACCEPT/REJECT/UNSUPPORTED), reject code,
                   size state, target_form, signals and safe audit sizes
  BODY_UNAVAILABLE req.raw_content is None (missing/streamed); NOT substituted with b""
  OUT_OF_SCOPE     absolute-form / authority-form(CONNECT) / unrecognized form / unsupported version
  ADAPTER_ERROR    building the snapshot from the request object failed
  BUSY             one observation already in flight (no queue)
  DROP             the snapshot exceeded an admission bound (oversize); never submitted
  TIMEOUT          the worker exceeded the deadline and HAS BEEN SIGKILLed and reaped
  UNAVAILABLE      no usable worker (starting / backing off / disabled / exited)
  EXCEPTION        an unexpected error, or a protocol violation on the reply (worker killed)

LOGGING POLICY: `format_record` emits closed codes, enumerations and numbers only. Worker-supplied
detail tokens pass `safe_detail` (a short conservative pattern) before they can be logged.
"""
from __future__ import annotations

import asyncio
import math
import os
import re
import struct
import sys
import time
from dataclasses import dataclass
from typing import Optional

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import canonical_adapter as adapter  # noqa: E402
import canonical_request as cr  # noqa: E402

PROTOCOL = "canonical-observer-ipc/v1"
WORKER_SCRIPT = os.path.join(HERE, "canonical_worker.py")

# ── IPC frame limits ────────────────────────────────────────────────────────
# The length prefix is a 4-byte big-endian unsigned int; frames above the configured maximum are a
# protocol error. The reply is always small.
LENGTH_PREFIX = 4
MAX_REPLY_BYTES = 64 * 1024

# ── lab admission caps (LAB-ONLY; NOT production defaults) ───────────────────
# These are explicit values for the observation slice, recorded here from synthetic boundary tests;
# the owner/coordinator chooses real values at wiring. The received-body admission cap is set equal
# to the decoded-body R8 cap so the two bounds are consistent. The 28-30 ms figure in the module
# header is an OBSERVED synthetic duration at a 1 MiB cap, NOT a proven worst-case bound on
# canonicalize time; the separate worker process is justified by responsiveness and cancellability,
# not by any claim that this cap bounds decode cost.
LAB_MAX_DECODED_BODY = 1 << 20          # 1 MiB decoded/decompression cap (R8)


@dataclass(frozen=True)
class AdmissionCaps:
    """Bounds on the WHOLE snapshot, checked before any copy/submit. All LAB-ONLY."""
    max_method_bytes: int = 32          # longest real method token is far shorter
    max_target_bytes: int = 8 * 1024    # 8 KiB request-target
    max_header_count: int = 100
    max_header_bytes: int = 64 * 1024   # aggregate name+value bytes
    max_body_bytes: int = 1 << 20       # 1 MiB received body (== decoded cap)
    # The serialized snapshot can only be a little larger than its parts; this is the hard frame cap.
    max_snapshot_bytes: int = (1 << 20) + (96 * 1024)   # body + target + headers + framing headroom

    @property
    def max_frame_bytes(self) -> int:
        return self.max_snapshot_bytes + 4096   # small envelope margin


DEFAULT_CAPS = AdmissionCaps()

# ── statuses ─────────────────────────────────────────────────────────────────
OK = "OK"
BODY_UNAVAILABLE = "BODY_UNAVAILABLE"
OUT_OF_SCOPE = "OUT_OF_SCOPE"
ADAPTER_ERROR = "ADAPTER_ERROR"
BUSY = "BUSY"
DROP = "DROP"
TIMEOUT = "TIMEOUT"
UNAVAILABLE = "UNAVAILABLE"
EXCEPTION = "EXCEPTION"
STATUSES = (OK, BODY_UNAVAILABLE, OUT_OF_SCOPE, ADAPTER_ERROR, BUSY, DROP, TIMEOUT,
            UNAVAILABLE, EXCEPTION)

_DETAIL = re.compile(r"^[A-Za-z0-9_:@.=\-]{1,96}$")
WORKER_ENV_KEYS = ("PATH",)


def safe_detail(value, fallback: str = "malformed_detail") -> str:
    """A detail token that may have come from another process: only a short conservative token is
    ever logged."""
    return value if isinstance(value, str) and _DETAIL.match(value) else fallback


class FrameError(ValueError):
    """A malformed or over-long IPC frame. Always fatal to the worker (kill, no reuse)."""


class _Reservation:
    """A unique single-use token identifying one admitted capture's claim on the single in-flight
    slot. Identity (not equality) is what matters: a release or a run only acts when its capture's
    token IS the observer's currently-active reservation."""
    __slots__ = ()


# ── frame envelope ───────────────────────────────────────────────────────────
def encode_frame(payload: bytes, max_bytes: int) -> bytes:
    if len(payload) > max_bytes:
        raise FrameError(f"frame payload {len(payload)} over max {max_bytes}")
    return struct.pack(">I", len(payload)) + payload


def _read_exactly_sync(fh, n: int) -> Optional[bytes]:
    """Read exactly n bytes from a binary file object, or None at a clean EOF before any byte."""
    chunks, remaining = [], n
    while remaining:
        chunk = fh.read(remaining)
        if not chunk:
            return None if remaining == n else b""   # clean EOF vs truncation
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_frame_sync(fh, max_bytes: int) -> Optional[bytes]:
    """Worker side: read one frame from a blocking binary stream. None at clean EOF (gateway gone).
    Raises FrameError on truncation or an over-long frame."""
    header = _read_exactly_sync(fh, LENGTH_PREFIX)
    if header is None:
        return None
    if len(header) < LENGTH_PREFIX:
        raise FrameError("truncated length prefix")
    (n,) = struct.unpack(">I", header)
    if n > max_bytes:
        raise FrameError(f"frame length {n} over max {max_bytes}")
    payload = _read_exactly_sync(fh, n)
    if payload is None or len(payload) < n:
        raise FrameError("truncated frame payload")
    return payload


async def read_frame_async(reader: asyncio.StreamReader, max_bytes: int) -> bytes:
    """Gateway side: read one frame. Raises FrameError on an over-long frame; propagates
    asyncio.IncompleteReadError (an EOFError) when the worker closed the pipe."""
    header = await reader.readexactly(LENGTH_PREFIX)
    (n,) = struct.unpack(">I", header)
    if n > max_bytes:
        raise FrameError(f"frame length {n} over max {max_bytes}")
    return await reader.readexactly(n)


# ── snapshot payload codec (binary; carries arbitrary request bytes safely) ───
def _put_bytes(out: bytearray, b: bytes) -> None:
    out += struct.pack(">I", len(b))
    out += b


def _get_bytes(mv: memoryview, pos: int) -> tuple[bytes, int]:
    if pos + 4 > len(mv):
        raise FrameError("truncated length field")
    (n,) = struct.unpack(">I", mv[pos:pos + 4])
    pos += 4
    if pos + n > len(mv):
        raise FrameError("field length exceeds payload")
    return bytes(mv[pos:pos + n]), pos + n


def encode_snapshot(snapshot: adapter.RequestSnapshot, max_decoded_body: int) -> bytes:
    """Serialize an ADMITTED snapshot to the frame payload the worker canonicalizes. Only method/
    target/headers/body plus the id and the decode cap cross the wire; nothing is logged."""
    if snapshot.target is None or snapshot.body is None:
        raise FrameError("cannot encode a non-admitted snapshot")
    out = bytearray()
    out += struct.pack(">QQ", snapshot.snapshot_id, max_decoded_body)
    _put_bytes(out, snapshot.http_version.encode("ascii", "replace"))
    _put_bytes(out, snapshot.method)
    _put_bytes(out, snapshot.target)
    out += struct.pack(">I", len(snapshot.headers))
    for name, value in snapshot.headers:
        _put_bytes(out, name)
        _put_bytes(out, value)
    _put_bytes(out, snapshot.body)
    return bytes(out)


def decode_snapshot(payload: bytes) -> tuple[int, int, cr.RequestParts]:
    """Worker side: frame payload -> (snapshot_id, max_decoded_body, cr.RequestParts). Reuses the
    adapter's single conversion site so there is exactly one place that builds RequestParts."""
    mv = memoryview(payload)
    if len(mv) < 16:
        raise FrameError("truncated snapshot header")
    snapshot_id, max_decoded_body = struct.unpack(">QQ", mv[:16])
    pos = 16
    ver, pos = _get_bytes(mv, pos)
    method, pos = _get_bytes(mv, pos)
    target, pos = _get_bytes(mv, pos)
    if pos + 4 > len(mv):
        raise FrameError("truncated header count")
    (nh,) = struct.unpack(">I", mv[pos:pos + 4])
    pos += 4
    if nh > DEFAULT_CAPS.max_header_count + 1:   # a sane upper guard independent of the live caps
        raise FrameError("implausible header count")
    headers = []
    for _ in range(nh):
        name, pos = _get_bytes(mv, pos)
        value, pos = _get_bytes(mv, pos)
        headers.append((name, value))
    body, pos = _get_bytes(mv, pos)
    if pos != len(mv):
        raise FrameError("trailing bytes after snapshot")
    rebuilt = adapter.RequestSnapshot(
        snapshot_id=snapshot_id, form=adapter.FORM_ORIGIN,
        http_version=ver.decode("ascii", "replace"), version_supported=True, in_scope=True,
        scope_reason=None, method=method, target=target, headers=tuple(headers), body=body)
    return snapshot_id, int(max_decoded_body), adapter.snapshot_to_parts(rebuilt)


# ── the observation record and its log line ───────────────────────────────────
@dataclass(frozen=True)
class CanonicalObservation:
    """What the observer learned about one request, or why it could not. Only OK carries the
    canonical result; every other status carries a closed detail token and no request-derived
    value."""
    status: str
    detail: Optional[str] = None
    outcome: Optional[str] = None          # ACCEPT | REJECT | UNSUPPORTED (OK only)
    reject: Optional[str] = None           # R1..R8 (OK + REJECT only)
    reason: Optional[str] = None           # canonical reject reason (closed, from the contract)
    size: Optional[str] = None             # SIZE_* (OK only)
    target_form: Optional[str] = None      # origin | absolute | ... (closed enum)
    signals: tuple = ()                    # sorted canonical signal codes (closed enum)
    decoded_body_bytes: Optional[int] = None
    content_codings: tuple = ()
    transfer_encoding: tuple = ()
    text_sha256: Optional[str] = None      # kept for offline analysis; NOT logged
    canonicalize_ms: Optional[float] = None
    elapsed_ms: float = 0.0

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}, got {self.status!r}")
        if self.status != OK and self.outcome is not None:
            raise ValueError("only an OK observation carries a canonical outcome")


def format_record(tag: str, obs: CanonicalObservation) -> str:
    """One log line: closed codes, enumerations and numbers only. NEVER a target, query, header
    value, body or exception message. `text_sha256` is deliberately omitted from the line."""
    parts = [f"[{tag}] CANONICAL OBS {obs.status}"]
    if obs.outcome is not None:
        parts.append(f"outcome={obs.outcome}")
    if obs.reject is not None:
        parts.append(f"reject={obs.reject}")
    if obs.reason is not None:
        parts.append(f"reason={safe_detail(obs.reason)}")
    if obs.size is not None:
        parts.append(f"size={obs.size}")
    if obs.target_form is not None:
        parts.append(f"target_form={obs.target_form}")
    if obs.signals:
        parts.append(f"signals={','.join(obs.signals)}")
    if obs.content_codings:
        parts.append(f"content_codings={','.join(obs.content_codings)}")
    if obs.transfer_encoding:
        parts.append(f"transfer_encoding={','.join(obs.transfer_encoding)}")
    if obs.decoded_body_bytes is not None:
        parts.append(f"decoded_body_bytes={obs.decoded_body_bytes}")
    if obs.detail:
        parts.append(f"detail={safe_detail(obs.detail)}")
    if obs.canonicalize_ms is not None:
        parts.append(f"canon={obs.canonicalize_ms:.3f}ms")
    parts.append(f"elapsed={obs.elapsed_ms:.3f}ms")
    return " ".join(parts)


# ── the synchronous-capture handle ─────────────────────────────────────────────
@dataclass
class Capture:
    """The result of the SYNCHRONOUS `capture()` boundary step. Either:

      * EARLY (`is_early=True`): a cheap gate already decided the outcome (disabled/busy/out-of-scope/
        body-unavailable/drop/unavailable/adapter-error). It carries a ready `CanonicalObservation`
        and holds NO worker reservation; `run_captured` returns that observation immediately.
      * ADMITTED (`is_early=False`): the request passed every gate, a single-use RESERVATION token
        has been taken, and the immutable snapshot has been built once and encoded into `frame`.
        `run_captured` performs the IPC exchange and releases the reservation (token-scoped) in its
        finally.

    `profile`, `profile_generation`, `form` and `http_version` are bound for the framing-observation
    log line (the gateway reads them back); the observer itself never interprets
    `profile`/`profile_generation`. `http_version` is the ORIGINAL received version, taken from the
    SAME immutable snapshot (never inferred from normalized canonical text). `reservation` is the
    token this admitted capture holds; `consumed` marks it spent (run once or released) so a repeated
    run or a stale/late release is a safe no-op.
    """
    is_early: bool
    form: Optional[str] = None
    http_version: Optional[str] = None                    # ORIGINAL received version (snapshot-time)
    profile: object = None
    profile_generation: Optional[int] = None
    observation: Optional[CanonicalObservation] = None    # early only
    proc: object = None                                   # admitted only
    snapshot_id: Optional[int] = None                     # admitted only
    frame: Optional[bytes] = None                         # admitted only
    started: Optional[float] = None                       # admitted only (perf_counter at capture)
    reservation: object = None                            # admitted only: the single-use token
    consumed: bool = False                                # True once run or released (idempotency)


# ── worker environment / argv ─────────────────────────────────────────────────
def worker_environment() -> dict:
    """What the worker gets: the PATH and a no-bytecode flag, nothing else (no proxy variables,
    no credentials, no Python startup hooks). The decoders are single-threaded C already."""
    env = {k: os.environ[k] for k in WORKER_ENV_KEYS if k in os.environ}
    env.update({"PYTHONDONTWRITEBYTECODE": "1"})
    return env


def worker_argv(python: str, max_decoded_body: int, max_frame_bytes: int) -> list:
    """`-I`: isolated mode, so no PYTHON* variable, user site or working directory can place other
    code on the worker's import path."""
    return [python, "-I", WORKER_SCRIPT, "--max-decoded-body", str(max_decoded_body),
            "--max-frame-bytes", str(max_frame_bytes)]


# ── the process observer ───────────────────────────────────────────────────────
class ProcessCanonicalObserver:
    """Runs canonicalize in a worker process, one observation at a time, no queue. Same lifecycle
    shape as ProcessShadowRunner: prewarm / background start / backoff / permanent-disable /
    SIGKILL+reap on timeout / close / aclose."""

    def __init__(self, argv: list, timeout_seconds: float, startup_timeout_seconds: float,
                 restart_backoff_seconds: float, max_consecutive_failures: int,
                 max_decoded_body: int, caps: AdmissionCaps = DEFAULT_CAPS,
                 env: Optional[dict] = None, clock=time.monotonic) -> None:
        for name, value in (("timeout_seconds", timeout_seconds),
                            ("startup_timeout_seconds", startup_timeout_seconds)):
            if isinstance(value, bool) or not value > 0 or not math.isfinite(value):
                raise ValueError(f"{name} must be > 0, got {value!r}")
        if isinstance(restart_backoff_seconds, bool) or not restart_backoff_seconds >= 0 \
                or not math.isfinite(restart_backoff_seconds):
            raise ValueError(f"restart_backoff_seconds must be >= 0, got {restart_backoff_seconds!r}")
        if isinstance(max_consecutive_failures, bool) \
                or not isinstance(max_consecutive_failures, int) or max_consecutive_failures < 1:
            raise ValueError("max_consecutive_failures must be an integer >= 1, got "
                             f"{max_consecutive_failures!r}")
        if isinstance(max_decoded_body, bool) or not isinstance(max_decoded_body, int) \
                or max_decoded_body <= 0:
            raise ValueError(f"max_decoded_body must be a positive int, got {max_decoded_body!r}")
        self.argv = list(argv)
        self.timeout_seconds = float(timeout_seconds)
        self.startup_timeout_seconds = float(startup_timeout_seconds)
        self.restart_backoff_seconds = float(restart_backoff_seconds)
        self.max_consecutive_failures = max_consecutive_failures
        self.max_decoded_body = max_decoded_body
        self.caps = caps
        self._env = worker_environment() if env is None else env
        self._clock = clock
        self._proc: Optional[asyncio.subprocess.Process] = None
        self.worker_version: Optional[str] = None
        # Single-in-flight reservation: holds the active capture's unique token, or None when idle.
        # Replaces the old boolean `_busy` so a release can be scoped to the exact token that owns the
        # reservation (a stale/late release can never free a newer one).
        self._reservation: Optional[_Reservation] = None
        self._start_task: Optional[asyncio.Task] = None
        self._failures = 0
        self._not_before = 0.0
        self._permanent: Optional[str] = None
        self._cause: Optional[str] = None
        self._closed = False
        self._next_id = 0
        self.spawn_count = 0
        self.kill_count = 0
        # Background reap tasks for workers found dead during a synchronous capture() (see
        # _schedule_reap): tracked so they are not garbage-collected mid-flight.
        self._reap_tasks: set = set()

    # -- introspection ----------------------------------------------------------
    @property
    def worker_pid(self) -> Optional[int]:
        return None if self._proc is None else self._proc.pid

    def startup_summary(self) -> tuple[int, str]:
        import logging
        return logging.INFO, ("canonical observer: shadow, separate process (logged only, never "
                              "used for decisions) timeout=%.3fs startup_timeout=%.1fs "
                              "restart_backoff=%.1fs max_consecutive_failures=%d max_decoded_body=%d"
                              "; worker starts in the background"
                              % (self.timeout_seconds, self.startup_timeout_seconds,
                                 self.restart_backoff_seconds, self.max_consecutive_failures,
                                 self.max_decoded_body))

    def _current_unavailable(self) -> str:
        if self._permanent:
            return self._permanent
        if self._start_task is not None and not self._start_task.done():
            return "worker_starting"
        if self._clock() < self._not_before:
            return self._cause or "worker_restarting"
        return "worker_starting"

    # -- lifecycle --------------------------------------------------------------
    def prewarm(self) -> None:
        try:
            self._maybe_start()
        except RuntimeError:
            pass   # no running loop: the first observe() starts it

    def _maybe_start(self) -> None:
        if (self._closed or self._permanent or self._proc is not None
                or (self._start_task is not None and not self._start_task.done())
                or self._clock() < self._not_before):
            return
        self._start_task = asyncio.get_running_loop().create_task(self._start())

    def _note_failure(self) -> None:
        self._failures += 1
        if self._failures >= self.max_consecutive_failures:
            self._permanent = "worker_disabled"
        else:
            self._not_before = self._clock() + self.restart_backoff_seconds

    @staticmethod
    def _close_transports(proc: asyncio.subprocess.Process) -> None:
        """Close the worker's stdin writer and its subprocess transport (which owns the stdout/
        stderr read pipes) best-effort. Idempotent: closing an already-closed stream/transport is a
        no-op. Doing this at shutdown is what prevents the `BaseSubprocessTransport.__del__: Event
        loop is closed` warning when the proc is later garbage-collected."""
        if proc.stdin is not None:
            try:
                proc.stdin.close()
            except Exception:  # noqa: BLE001 — shutdown best-effort
                pass
        transport = getattr(proc, "_transport", None)
        if transport is not None:
            try:
                transport.close()
            except Exception:  # noqa: BLE001 — the loop may already be closing
                pass

    async def _kill(self, proc: asyncio.subprocess.Process) -> None:
        """SIGKILL, reap (bounded wait), and close the transports. After this the PID is gone and
        the handle is dropped if it is ours. If reaping does NOT complete, we do NOT claim success:
        the observer is permanently disabled so no later request trusts a possibly-live worker."""
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        self.kill_count += 1
        reaped = True
        try:
            await asyncio.wait_for(proc.wait(), 5.0)
        except asyncio.TimeoutError:   # SIGKILL not reaped in 5 s: do not pretend it is gone
            reaped = False
            self._permanent = "reap_failed_worker_disabled"
        self._close_transports(proc)
        if self._proc is proc and reaped:
            self._proc = None

    async def _start(self) -> None:
        proc = None
        try:
            self.spawn_count += 1
            try:
                proc = await asyncio.create_subprocess_exec(
                    *self.argv, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL, env=self._env,
                    limit=self.caps.max_frame_bytes, start_new_session=True)
            except (OSError, ValueError):
                self._cause = "worker_spawn_failed"
                self._note_failure()
                return
            try:
                payload = await asyncio.wait_for(
                    read_frame_async(proc.stdout, MAX_REPLY_BYTES), self.startup_timeout_seconds)
                hello = _decode_reply(payload)
            except asyncio.TimeoutError:
                await self._kill(proc)
                self._cause = "worker_startup_timeout"
                self._note_failure()
                return
            except (FrameError, ValueError, asyncio.IncompleteReadError):
                await self._kill(proc)
                self._cause = "worker_protocol_error"
                self._note_failure()
                return
            if hello.get("ready") is True and hello.get("protocol") == PROTOCOL \
                    and hello.get("contract") == adapter.CONTRACT_ID:
                version = hello.get("version")
                self.worker_version = version if isinstance(version, str) and version else "unknown"
                self._cause = None
                self._proc = proc
                proc = None
                return
            # A ready:false or a mismatched handshake is deterministic: retrying cannot change it.
            await self._kill(proc)
            proc = None
            self._permanent = "handshake_mismatch"
        except asyncio.CancelledError:
            if proc is not None:
                await self._kill(proc)
                proc = None
            raise
        finally:
            if proc is not None and self._proc is not proc and proc.returncode is None:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass

    def close(self) -> None:
        """Synchronous shutdown (mitmproxy's `done` hook). IDEMPOTENT and safe during startup, an
        exchange, a timeout, or after an earlier close().

        It SIGKILLs the worker and closes its stdin/stdout pipe transports best-effort, so no
        `BaseSubprocessTransport.__del__` warning is emitted. It CANNOT await, so it does NOT reap:
        on Linux the SIGKILLed child becomes a zombie that asyncio's child watcher (or aclose(), or
        the OS at gateway exit) collects. It deliberately does NOT discard the proc handle, so a
        following `aclose()` can still reap it exactly once."""
        self._closed = True
        if self._start_task is not None and not self._start_task.done():
            self._start_task.cancel()
        proc = self._proc                     # keep the handle: aclose() needs it to reap
        if proc is not None:
            if proc.returncode is None:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
            self._close_transports(proc)

    async def aclose(self) -> None:
        """Asynchronous shutdown that REAPS the worker. IDEMPOTENT and safe after a prior close(),
        during startup, or during an exchange."""
        self._closed = True
        task = self._start_task
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        proc = self._proc
        if proc is not None:
            await self._kill(proc)            # kill (idempotent) + reap + close transports + drop
        # Drain any background reap tasks scheduled by capture() for earlier dead workers.
        if self._reap_tasks:
            for task in list(self._reap_tasks):
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                except Exception:  # noqa: BLE001 — shutdown best-effort; _kill already guards
                    pass

    # -- synchronous worker reaping (no await) ----------------------------------
    def _schedule_reap(self, proc) -> None:
        """Reap a worker found dead during the SYNCHRONOUS capture() WITHOUT blocking the hook.

        capture() cannot await, but a dead worker still needs its PID reaped and its pipe transports
        closed (otherwise a `BaseSubprocessTransport.__del__: Event loop is closed` warning is
        emitted at GC). We therefore fire-and-forget the existing `_kill` coroutine as a tracked
        task when a loop is running. `_kill` is idempotent and only clears `self._proc` when it is
        still this exact handle, so a restart that has already installed a NEW worker is never
        disturbed. When there is NO running loop (e.g. a bare prewarm during setup), we kill the PID
        synchronously and close the transports, deferring the actual wait()-reap to the next
        aclose()/OS collection — exactly as close() documents."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            if proc.returncode is None:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
            self._close_transports(proc)
            return
        task = loop.create_task(self._kill(proc))
        self._reap_tasks.add(task)
        task.add_done_callback(self._reap_tasks.discard)

    # -- reservation helpers (token-scoped, single-in-flight) -------------------
    def _release_reservation(self, token) -> None:
        """Clear the active reservation ONLY if `token` still owns it. A stale/late token (one a
        newer reservation has already superseded) is a no-op, so it can never free a newer claim."""
        if token is not None and self._reservation is token:
            self._reservation = None

    # -- synchronous capture + async run ----------------------------------------
    def capture(self, req, *, profile=None, profile_generation=None) -> Capture:
        """SYNCHRONOUS boundary step: run every cheap gate, take the single-use RESERVATION token iff
        admitted, then build the ONE immutable snapshot and encode its frame — all without awaiting
        and without raising. Any failure is guarded into an EARLY Capture carrying a ready
        CanonicalObservation; only an ADMITTED Capture holds the reservation (released later by
        run_captured's token-scoped finally, or by release_captured if it is never run).

        The gates are, in order, exactly today's observe() steps: closed/permanent/busy; cheap
        classify_raw; body-none; out-of-scope; cheap admit_raw; worker availability resolved WITHOUT
        awaiting (a dead worker is reaped via _schedule_reap and a restart scheduled via the existing
        non-awaiting _maybe_start). No header tuple or body copy is made on any cheap path; the single
        body copy happens only in build_snapshot for an admitted request. `http_version` (the ORIGINAL
        received version) is bound onto EVERY capture from the same classification, never inferred
        from normalized canonical text."""
        started = time.perf_counter()

        def elapsed() -> float:
            return (time.perf_counter() - started) * 1000

        def early(obs: CanonicalObservation, form=None, version=None) -> Capture:
            return Capture(is_early=True, form=form, http_version=version, profile=profile,
                           profile_generation=profile_generation, observation=obs)

        try:
            # 1. Cheapest gates: no snapshot for a closed/disabled/busy observer.
            if self._closed:
                return early(CanonicalObservation(UNAVAILABLE, detail="worker_disabled",
                                                  elapsed_ms=elapsed()))
            if self._permanent:
                return early(CanonicalObservation(UNAVAILABLE, detail=self._permanent,
                                                  elapsed_ms=elapsed()))
            if self._reservation is not None:   # single in-flight: a reservation is already active
                return early(CanonicalObservation(BUSY, detail="in_flight", elapsed_ms=elapsed()))

            # 2. Cheap request classification (no header-tuple materialization, no body copy).
            try:
                info = adapter.classify_raw(req)
            except Exception as exc:  # noqa: BLE001 — type only, never a message
                return early(CanonicalObservation(ADAPTER_ERROR,
                                                  detail=f"classify:{type(exc).__name__}",
                                                  elapsed_ms=elapsed()))
            version = info.http_version          # ORIGINAL received version, from this classification
            if info.body_is_none:
                return early(CanonicalObservation(BODY_UNAVAILABLE, detail="raw_content_none",
                                                  target_form=info.form, elapsed_ms=elapsed()),
                             form=info.form, version=version)
            if not info.in_scope:
                return early(CanonicalObservation(OUT_OF_SCOPE, detail=info.scope_reason,
                                                  target_form=info.form, elapsed_ms=elapsed()),
                             form=info.form, version=version)

            # 3. Cheap admission scan with early exit (never builds the adapter's header tuple).
            try:
                drop = adapter.admit_raw(req, self.caps, info)
            except Exception as exc:  # noqa: BLE001
                return early(CanonicalObservation(ADAPTER_ERROR, detail=f"admit:{type(exc).__name__}",
                                                  elapsed_ms=elapsed()), form=info.form, version=version)
            if drop is not None:
                return early(CanonicalObservation(DROP, detail=drop, target_form=info.form,
                                                  elapsed_ms=elapsed()), form=info.form, version=version)

            # 4. Worker availability WITHOUT awaiting. Only ADMITTED work reaches here.
            proc = self._proc
            if proc is not None and proc.returncode is not None:
                self._proc = None            # drop the handle first so a restart can install a new one
                self._schedule_reap(proc)    # fire-and-forget reap: never blocks the hook
                self._cause = "worker_restarting"
                self._note_failure()
                proc = None
            if proc is None:
                detail = self._current_unavailable()
                self._maybe_start()          # non-awaiting: schedules the background start task
                if self._start_task is not None and not self._start_task.done():
                    detail = "worker_starting"
                return early(CanonicalObservation(UNAVAILABLE, detail=self._permanent or detail,
                                                  elapsed_ms=elapsed()), form=info.form, version=version)

            # 5. Take the single-use reservation iff admitted, THEN the one snapshot copy + encode.
            token = _Reservation()
            self._reservation = token
            self._next_id += 1
            snapshot_id = self._next_id
            try:
                snapshot = adapter.build_snapshot(req, snapshot_id)
                payload = encode_snapshot(snapshot, self.max_decoded_body)
            except Exception as exc:  # noqa: BLE001 — release the reservation we just took
                self._release_reservation(token)
                return early(CanonicalObservation(ADAPTER_ERROR, detail=f"build:{type(exc).__name__}",
                                                  elapsed_ms=elapsed()), form=info.form, version=version)
            # Enforce the serialized-snapshot limit explicitly (not merely the larger frame envelope).
            if len(payload) > self.caps.max_snapshot_bytes:
                self._release_reservation(token)
                return early(CanonicalObservation(DROP, detail="snapshot_too_large",
                                                  target_form=info.form, elapsed_ms=elapsed()),
                             form=info.form, version=version)
            try:
                frame = encode_frame(payload, self.caps.max_frame_bytes)
            except FrameError:
                self._release_reservation(token)
                return early(CanonicalObservation(DROP, detail="snapshot_too_large",
                                                  target_form=info.form, elapsed_ms=elapsed()),
                             form=info.form, version=version)

            # ADMITTED: the reservation is held; run_captured will do the IPC and release the token.
            return Capture(is_early=False, form=info.form, http_version=version, profile=profile,
                           profile_generation=profile_generation, proc=proc,
                           snapshot_id=snapshot_id, frame=frame, started=started, reservation=token)
        except Exception as exc:  # noqa: BLE001 — capture() must NEVER raise into the hook
            # The only reservation site is step 5, which has its own token-scoped release paths;
            # reaching here means an unexpected fault before/around them, so no token is held.
            return early(CanonicalObservation(ADAPTER_ERROR, detail=f"capture:{type(exc).__name__}",
                                              elapsed_ms=elapsed()))

    async def run_captured(self, capture: Capture) -> CanonicalObservation:
        """Complete a Capture, SINGLE-USE. An EARLY capture returns its ready observation (nothing to
        release). An already-consumed capture (run once, or released) returns a safe closed
        `EXCEPTION capture_consumed` WITHOUT touching the worker or any state. Otherwise it marks the
        capture consumed, performs the IPC exchange under the single whole-exchange deadline (SAME
        timeout/cancel/broken-pipe/id-mismatch handling; an id mismatch stays `EXCEPTION
        ipc_id_mismatch`, so a cross/late reply can never be attributed here), and in `finally`
        releases the reservation TOKEN-SCOPED (only if this capture's token is still the active one)."""
        if capture.is_early:
            return capture.observation
        if capture.consumed:
            # Guards a double-run and a run after release: no worker exchange, no state change.
            spent = ((time.perf_counter() - capture.started) * 1000
                     if capture.started is not None else 0.0)
            return CanonicalObservation(EXCEPTION, detail="capture_consumed", elapsed_ms=spent)
        capture.consumed = True
        try:
            return await self._exchange(capture.proc, capture.snapshot_id, capture.frame,
                                        capture.started)
        finally:
            self._release_reservation(capture.reservation)

    def release_captured(self, capture: Capture) -> None:
        """Release the reservation held by an ADMITTED capture that will NOT be run (e.g. the gateway
        could not schedule run_captured, or a task was cancelled BEFORE its coroutine first ran).
        SYNCHRONOUS, never awaits, never raises. IDEMPOTENT and TOKEN-SCOPED: it frees the slot ONLY
        when this capture's token still owns the active reservation, then marks the capture consumed.
        A no-op for an early/`None`/already-consumed/stale (old-handle) capture — so a delayed
        done-callback or an old handle can NEVER free a newer reservation. The worker was never
        written to (capture only built/encoded the frame), so it stays in sync and is left running."""
        try:
            if capture is None or capture.is_early or capture.consumed:
                return
            self._release_reservation(capture.reservation)   # frees only if still the active token
            capture.consumed = True                           # this handle is now spent
        except Exception:  # noqa: BLE001 — must never raise into the hook
            pass

    # -- one observation (back-compat wrapper) ----------------------------------
    async def observe(self, req) -> CanonicalObservation:
        """Observe one request = capture() then run_captured(). Preserved so existing callers/tests
        keep working; the gateway wiring uses capture()/run_captured() directly so the request never
        awaits the completion. Reservation/BUSY semantics (no queue, single in-flight) are identical
        end to end."""
        return await self.run_captured(self.capture(req))

    async def _write_and_read(self, proc, frame: bytes) -> bytes:
        """Write the snapshot frame, drain it, then read exactly one reply frame. The caller wraps
        this WHOLE coroutine in a single deadline, so a worker that stops reading its stdin (which
        makes `drain()` block) cannot evade the timeout — the deadline covers the write/drain too."""
        proc.stdin.write(frame)
        await proc.stdin.drain()
        return await read_frame_async(proc.stdout, MAX_REPLY_BYTES)

    async def _exchange(self, proc, snapshot_id, frame, started) -> CanonicalObservation:
        def elapsed() -> float:
            return (time.perf_counter() - started) * 1000

        try:
            reply_payload = await asyncio.wait_for(
                self._write_and_read(proc, frame), self.timeout_seconds)
        except asyncio.TimeoutError:
            # Stuck anywhere in write/drain/read: END the worker, do not merely stop waiting.
            await self._kill(proc)
            self._note_failure()
            return CanonicalObservation(TIMEOUT, detail="worker_killed", elapsed_ms=elapsed())
        except asyncio.CancelledError:
            # Cancelled mid-exchange: the worker may hold an undelivered reply and be
            # desynchronised. Invalidate it (SIGKILL + reap) and NEVER reuse it; the reservation is
            # released (token-scoped) by run_captured()'s finally. Then propagate the cancellation.
            await self._kill(proc)
            self._note_failure()
            raise
        except (BrokenPipeError, ConnectionResetError, asyncio.IncompleteReadError, EOFError):
            code = proc.returncode
            await self._kill(proc)
            self._note_failure()
            detail = f"worker_exited:rc={code}" if code is not None else "worker_exited"
            return CanonicalObservation(UNAVAILABLE, detail=safe_detail(detail), elapsed_ms=elapsed())
        except FrameError:
            await self._kill(proc)   # oversize reply: desynchronised or hostile
            self._note_failure()
            return CanonicalObservation(EXCEPTION, detail="ipc_frame_too_large", elapsed_ms=elapsed())

        try:
            reply = _decode_reply(reply_payload)
        except (FrameError, ValueError):
            await self._kill(proc)
            self._note_failure()
            return CanonicalObservation(EXCEPTION, detail="ipc_malformed_reply", elapsed_ms=elapsed())
        if reply.get("id") != snapshot_id:
            await self._kill(proc)   # a reply for another request is never cross-attributed
            self._note_failure()
            return CanonicalObservation(EXCEPTION, detail="ipc_id_mismatch", elapsed_ms=elapsed())

        canon_ms = reply.get("canonicalize_ms")
        canon_ms = (float(canon_ms) if isinstance(canon_ms, (int, float))
                    and not isinstance(canon_ms, bool) and math.isfinite(canon_ms)
                    and canon_ms >= 0 else None)

        if reply.get("ok") is not True:
            # The worker could not canonicalize (unexpected error in a pure function): infra, not a
            # canonical REJECT. Keep the dimensions separate: this is EXCEPTION, never status OK.
            await self._kill(proc)
            self._note_failure()
            return CanonicalObservation(EXCEPTION, detail=safe_detail(reply.get("detail")),
                                        canonicalize_ms=canon_ms, elapsed_ms=elapsed())

        try:
            obs = _observation_from_reply(reply, canon_ms, elapsed())
        except (ValueError, TypeError, KeyError):
            await self._kill(proc)
            self._note_failure()
            return CanonicalObservation(EXCEPTION, detail="ipc_contract_violation",
                                        elapsed_ms=elapsed())
        self._failures = 0   # a healthy answer ends a failure streak
        return obs


# ── reply codec (small JSON, safe fields only) ────────────────────────────────
def _decode_reply(payload: bytes) -> dict:
    import json

    def _reject_constant(name):
        raise ValueError(f"non-finite JSON constant {name}")

    value = json.loads(payload.decode("utf-8"), parse_constant=_reject_constant)
    if not isinstance(value, dict):
        raise ValueError("reply is not an object")
    return value


def encode_reply(message: dict, max_bytes: int = MAX_REPLY_BYTES) -> bytes:
    """A reply frame. `allow_nan=False` so no NaN/Infinity can reach the wire."""
    import json
    payload = json.dumps(message, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return encode_frame(payload, max_bytes)


_OUTCOMES = (cr.ACCEPT, cr.REJECT, cr.UNSUPPORTED)
_SIZES = (cr.SIZE_UNCHECKED, cr.SIZE_WITHIN, cr.SIZE_OVER, cr.SIZE_NEEDS_EXACT_COUNT)


def _observation_from_reply(reply: dict, canon_ms, elapsed_ms: float) -> CanonicalObservation:
    """Validate a worker OK reply into an observation. Raises on anything off-contract."""
    outcome = reply["outcome"]
    if outcome not in _OUTCOMES:
        raise ValueError("bad outcome")
    reject = reply.get("reject")
    if reject is not None and (not isinstance(reject, str) or not re.fullmatch(r"R[1-8]", reject)):
        raise ValueError("bad reject")
    size = reply.get("size")
    if size is not None and size not in _SIZES:
        raise ValueError("bad size")
    signals = tuple(reply.get("signals") or ())
    if any(not isinstance(s, str) or s not in cr.ALL_SIGNALS for s in signals):
        raise ValueError("bad signal")
    target_form = reply.get("target_form")
    if target_form is not None and target_form not in adapter.FORMS:
        raise ValueError("bad target_form")
    codings = tuple(reply.get("content_codings") or ())
    te = tuple(reply.get("transfer_encoding") or ())
    if any(not isinstance(x, str) for x in codings + te):
        raise ValueError("bad coding list")
    dbb = reply.get("decoded_body_bytes")
    if dbb is not None and (isinstance(dbb, bool) or not isinstance(dbb, int) or dbb < 0):
        raise ValueError("bad decoded_body_bytes")
    sha = reply.get("text_sha256")
    if sha is not None and (not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha)):
        raise ValueError("bad text_sha256")
    reason = reply.get("reason")
    return CanonicalObservation(
        OK, detail=None, outcome=outcome, reject=reject,
        reason=safe_detail(reason) if isinstance(reason, str) else None,
        size=size, target_form=target_form, signals=signals, decoded_body_bytes=dbb,
        content_codings=codings, transfer_encoding=te, text_sha256=sha,
        canonicalize_ms=canon_ms, elapsed_ms=elapsed_ms)


# ── factory ────────────────────────────────────────────────────────────────────
def build_process_observer(python: str, timeout_seconds: float, startup_timeout_seconds: float,
                           restart_backoff_seconds: float, max_consecutive_failures: int,
                           max_decoded_body: int = LAB_MAX_DECODED_BODY,
                           caps: AdmissionCaps = DEFAULT_CAPS) -> ProcessCanonicalObserver:
    """The runtime the gateway would use: the worker script under the DATA-PLANE interpreter
    (`python` is the data-plane venv's python, the same one that runs the gateway)."""
    argv = worker_argv(python, max_decoded_body, caps.max_frame_bytes)
    return ProcessCanonicalObserver(argv, timeout_seconds, startup_timeout_seconds,
                                    restart_backoff_seconds, max_consecutive_failures,
                                    max_decoded_body, caps)
