"""
firewall-IA — Hybrid shadow Analyzer, SEPARATE-PROCESS runtime (PROPOSED for D52).

    gateway (data plane venv, stdlib only)                 worker (analyzer venv, numpy + sklearn)
    ------------------------------------------             -----------------------------------------
    extract_features(D1 text)                              verify SHA-256 of the artifact, THEN unpickle
      -> one JSON line on the worker's stdin  ----------->   analyze_strict(features)
      <- one JSON line on its stdout  <-------------------   {"signals": ...} or an explicit failure
    re-validate with the D50 contract -> ShadowResult

WHY A PROCESS. (a) D33: the data plane environment has no numpy / scikit-learn and may not
get them; the worker runs under the analyzer environment's own interpreter. (b) The analysis
holds the GIL in bursts: measured in-process, it stalled the gateway's event loop for up to
~13 ms. Here the gateway only moves bytes; the computation happens in another process.
This is a PROPOSAL until the owner ratifies it as D52; nothing about it is decided.

V4 STAYS THE ONLY DECISION. Like hybrid_shadow.py, this module returns a `ShadowResult` to be
logged and nothing else. No ALLOW path, no threshold, no Model 2.

IPC. The worker's stdin/stdout pipes: local, owned by the gateway process, no socket, no
port, no file. Newline-delimited JSON, one message each way per request, the worker answers
exactly one request at a time. Every line is bounded (MAX_LINE_BYTES): a longer one is a
protocol error and the worker is killed. The gateway sends the 34 extracted FEATURES, never
the request text, so the worker never holds a request's content. Worker stderr is discarded
(it could carry text); the worker writes nothing but protocol lines to stdout.

BOUNDED SUBMISSION. One request in flight, ever. A request that arrives meanwhile is BUSY at
once: there is no queue, no backlog, no pending list that could grow.

OUTCOMES (hybrid_shadow statuses, all explicit):
  UNAVAILABLE   worker not ready (starting / restarting after a failure / gave up), or the
                artifact could not be verified or loaded (worker says why)
  BUSY          one analysis already in flight
  OK            answer received and re-validated here against the D50 contract
  INVALID_OUTPUT  the answer violates the contract, includes NaN/Infinity, or breaks the protocol
  FAILED        the worker raised, or exited
  TIMEOUT       the worker did not answer in time AND HAS BEEN KILLED (SIGKILL) and reaped

HUNG WORKER. When an analysis exceeds `timeout_seconds`, the worker is killed with SIGKILL and
reaped (`await proc.wait()`), its pipes closed, and the result is TIMEOUT with detail
`worker_killed`. The same happens after any protocol violation. A killed or crashed worker is
replaced by a fresh one no sooner than `restart_backoff_seconds` later, started in the
background (a request never waits for it; meanwhile requests are UNAVAILABLE). After
`max_consecutive_failures` consecutive failures (a success resets the count) the runtime stops
retrying: UNAVAILABLE(worker_disabled) until the gateway restarts. A deterministic startup
failure (artifact missing, hash mismatch, dependencies missing, contract mismatch) disables
at once: retrying cannot change it. If the gateway itself dies, the worker sees EOF on stdin
and exits; the worker is also started in its own session so the kill reaches only it.

NOT CLAIMED. The worker has no memory or CPU limit (an RLIMIT on a numpy/OpenMP process is
not safe to assume). Killing is by SIGKILL on one PID; a worker's own children, if it ever
had any, are not tracked (the Analyzer starts none).

LOGGING POLICY. Same as hybrid_shadow.py. Worker-supplied `detail` strings are accepted only
if they match a conservative pattern; anything else becomes `malformed_detail`.
"""

import asyncio
import dataclasses
import json
import math
import os
import re
import sys
import time
from typing import Any, Callable, Optional

import hybrid_contracts as contracts
import hybrid_shadow as shadow
import request_features

MAX_LINE_BYTES = 64 * 1024
PROTOCOL = "hybrid-shadow-ipc/v1"
WORKER_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hybrid_shadow_worker.py")

_DETAIL = re.compile(r"^[A-Za-z0-9_:@.=\-]{1,96}$")
WORKER_ENV_KEYS = ("PATH",)


def safe_detail(value: Any, fallback: str = "malformed_detail") -> str:
    """A worker-supplied detail is data from another process: only a short conservative
    token is ever logged."""
    return value if isinstance(value, str) and _DETAIL.match(value) else fallback


def encode_line(message: dict) -> bytes:
    """One protocol line. `allow_nan=False`: a NaN or Infinity cannot be put on the wire."""
    line = json.dumps(message, separators=(",", ":"), allow_nan=False).encode() + b"\n"
    if len(line) > MAX_LINE_BYTES:
        raise ValueError("message exceeds MAX_LINE_BYTES")
    return line


def _reject_constant(name: str):
    raise ValueError(f"non-finite JSON constant {name}")


def decode_line(line: bytes) -> dict:
    """Parse one protocol line, rejecting NaN / Infinity / -Infinity tokens, which Python's
    json would otherwise accept. Raises ValueError for anything else that is not an object."""
    if not line.endswith(b"\n") or len(line) > MAX_LINE_BYTES:
        raise ValueError("not a bounded complete line")
    value = json.loads(line, parse_constant=_reject_constant)
    if not isinstance(value, dict):
        raise ValueError("not an object")
    return value


def worker_environment() -> dict:
    """What the worker gets: one OpenMP/BLAS thread each and the PATH, nothing else
    (no proxy variables, no credentials, no Python startup hooks)."""
    env = {k: os.environ[k] for k in WORKER_ENV_KEYS if k in os.environ}
    env.update({"OMP_NUM_THREADS": "1", "OPENBLAS_NUM_THREADS": "1", "MKL_NUM_THREADS": "1",
                "PYTHONDONTWRITEBYTECODE": "1"})
    return env


def worker_argv(python: str, artifact_path: str) -> list:
    """`-I`: isolated mode, so no PYTHON* variable, user site or working directory can put
    other code on the worker's import path."""
    return [python, "-I", WORKER_SCRIPT, "--artifact", artifact_path]


class ProcessShadowRunner:
    """Runs the Analyzer in a worker process. Same `run()` contract as ShadowRunner."""

    def __init__(self, argv: list, timeout_seconds: float, startup_timeout_seconds: float,
                 restart_backoff_seconds: float, max_consecutive_failures: int,
                 extract: Optional[Callable[[str], request_features.RequestFeatures]] = None,
                 env: Optional[dict] = None, clock: Callable[[], float] = time.monotonic) -> None:
        for name, value in (("timeout_seconds", timeout_seconds),
                            ("startup_timeout_seconds", startup_timeout_seconds)):
            if isinstance(value, bool) or not value > 0 or not math.isfinite(value):
                raise ValueError(f"{name} must be > 0, got {value!r}")
        if isinstance(restart_backoff_seconds, bool) or not restart_backoff_seconds >= 0 \
                or not math.isfinite(restart_backoff_seconds):
            raise ValueError(f"restart_backoff_seconds must be >= 0, got {restart_backoff_seconds!r}")
        if isinstance(max_consecutive_failures, bool) or not isinstance(max_consecutive_failures, int) \
                or max_consecutive_failures < 1:
            raise ValueError(f"max_consecutive_failures must be an integer >= 1, got "
                             f"{max_consecutive_failures!r}")
        self.argv = list(argv)
        self.timeout_seconds = float(timeout_seconds)
        self.startup_timeout_seconds = float(startup_timeout_seconds)
        self.restart_backoff_seconds = float(restart_backoff_seconds)
        self.max_consecutive_failures = max_consecutive_failures
        self._extract = extract
        self._env = worker_environment() if env is None else env
        self._clock = clock
        self._proc: Optional[asyncio.subprocess.Process] = None
        self.analyzer_version: Optional[str] = None
        self._busy = False
        self._start_task: Optional[asyncio.Task] = None
        self._failures = 0
        self._not_before = 0.0
        self._permanent: Optional[str] = None
        self._cause: Optional[str] = None   # why the last start failed, while backing off
        self._closed = False
        self._next_id = 0
        self.spawn_count = 0
        self.kill_count = 0

    # -- introspection (tests, startup line) ------------------------------------
    @property
    def worker_pid(self) -> Optional[int]:
        return None if self._proc is None else self._proc.pid

    @property
    def provider(self):
        """Gateway-facing: None while no worker is usable. (The in-process runner's attribute.)"""
        return None if self._proc is None else self

    @property
    def unavailable_detail(self) -> Optional[str]:
        return self._current_unavailable()

    def _current_unavailable(self) -> str:
        """Why no worker is usable right now."""
        if self._permanent:
            return self._permanent
        if self._start_task is not None and not self._start_task.done():
            return "worker_starting"
        if self._clock() < self._not_before:
            return self._cause or "worker_restarting"
        return "worker_starting"

    def startup_summary(self) -> tuple[int, str]:
        import logging
        return logging.INFO, ("hybrid shadow analyzer: shadow, separate process (logged only, "
                              "never used for decisions) timeout=%.3fs startup_timeout=%.1fs "
                              "restart_backoff=%.1fs max_consecutive_failures=%d; worker starts in "
                              "the background" % (self.timeout_seconds, self.startup_timeout_seconds,
                                                  self.restart_backoff_seconds,
                                                  self.max_consecutive_failures))

    # -- lifecycle ----------------------------------------------------------------
    def prewarm(self) -> None:
        """Start the worker in the background if an event loop is running. Never raises."""
        try:
            self._maybe_start()
        except RuntimeError:
            pass   # no running loop: the first run() starts it

    def _maybe_start(self) -> None:
        if (self._closed or self._permanent or self._proc is not None
                or (self._start_task is not None and not self._start_task.done())
                or self._clock() < self._not_before):
            return
        self._start_task = asyncio.get_running_loop().create_task(self._start())

    def _note_failure(self) -> None:
        """Count a failure; bounded recovery: back off, and after too many, stop for good."""
        self._failures += 1
        if self._failures >= self.max_consecutive_failures:
            self._permanent = "worker_disabled"
        else:
            self._not_before = self._clock() + self.restart_backoff_seconds

    async def _kill(self, proc: asyncio.subprocess.Process) -> None:
        """SIGKILL, reap, close the pipes. After this the PID is gone."""
        try:
            proc.kill()
        except ProcessLookupError:
            pass   # already dead
        self.kill_count += 1
        try:
            await asyncio.wait_for(proc.wait(), 5.0)
        except asyncio.TimeoutError:   # SIGKILL not reaped in 5 s: leave it to the OS, say so
            self._permanent = "worker_disabled"
        if proc.stdin is not None:
            proc.stdin.close()
        if self._proc is proc:
            self._proc = None

    async def _start(self) -> None:
        proc = None
        try:
            self.spawn_count += 1
            try:
                proc = await asyncio.create_subprocess_exec(
                    *self.argv, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL, env=self._env, limit=MAX_LINE_BYTES,
                    start_new_session=True)
            except (OSError, ValueError):
                self._cause = "worker_spawn_failed"
                self._note_failure()
                return
            try:
                line = await asyncio.wait_for(proc.stdout.readline(), self.startup_timeout_seconds)
                hello = decode_line(line)
            except asyncio.TimeoutError:
                await self._kill(proc)
                self._cause = "worker_startup_timeout"
                self._note_failure()
                return
            except (ValueError, asyncio.LimitOverrunError):
                await self._kill(proc)
                self._cause = "worker_protocol_error"
                self._note_failure()
                return
            if hello.get("ready") is True:
                version, schema = hello.get("version"), hello.get("feature_schema")
                if (not isinstance(version, str) or not version
                        or schema != request_features.FEATURE_SCHEMA_VERSION):
                    await self._kill(proc)
                    self._permanent = "feature_contract_mismatch"
                    return
                self.analyzer_version = version
                self._cause = None
                self._proc = proc
                proc = None   # ownership handed over
                return
            # ready:false -> a deterministic reason. Retrying cannot change it.
            detail = hello.get("detail")
            self._permanent = detail if detail in shadow.UNAVAILABLE_DETAILS else "load_failed"
            await self._kill(proc)
            proc = None
        except asyncio.CancelledError:
            # Shutdown while the worker was still starting: end it and reap it before
            # letting the cancellation through (awaiting here is allowed; cancel throws once).
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
        """Synchronous shutdown (mitmproxy's `done` hook): SIGKILL the worker. Does not wait."""
        self._closed = True
        if self._start_task is not None and not self._start_task.done():
            self._start_task.cancel()
        proc, self._proc = self._proc, None
        if proc is not None and proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass

    async def aclose(self) -> None:
        """Shutdown that also reaps the worker."""
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
            await self._kill(proc)

    # -- one analysis -----------------------------------------------------------------
    async def run(self, raw_request: str) -> shadow.ShadowResult:
        started = time.perf_counter()

        def elapsed() -> float:
            return (time.perf_counter() - started) * 1000

        def unavailable(detail: str) -> shadow.ShadowResult:
            return shadow.ShadowResult(shadow.UNAVAILABLE, detail, self.analyzer_version,
                                       elapsed_ms=elapsed())

        if self._closed:
            return unavailable("worker_disabled")
        if self._permanent:
            return unavailable(self._permanent)
        if self._busy:   # checked and set with no await between: asyncio is single-threaded
            return shadow.ShadowResult(shadow.BUSY, None, self.analyzer_version, elapsed_ms=elapsed())
        proc = self._proc
        if proc is not None and proc.returncode is not None:
            # Died while idle: reap, count it, and fall through to "no worker".
            await self._kill(proc)
            self._cause = "worker_restarting"
            self._note_failure()
            proc = None
        if proc is None:
            detail = self._current_unavailable()
            self._maybe_start()   # only starts when allowed (not backing off, not disabled)
            if self._start_task is not None and not self._start_task.done():
                detail = "worker_starting"
            return unavailable(self._permanent or detail)

        self._busy = True
        try:
            return await self._analyze(proc, raw_request, started)
        finally:
            self._busy = False

    async def _analyze(self, proc, raw_request: str, started: float) -> shadow.ShadowResult:
        version = self.analyzer_version

        def elapsed() -> float:
            return (time.perf_counter() - started) * 1000

        def done(status, detail=None, analyze_ms=None, **kw) -> shadow.ShadowResult:
            e = elapsed()
            return shadow.ShadowResult(
                status, detail, version, analyze_ms=analyze_ms, elapsed_ms=e,
                overhead_ms=None if analyze_ms is None else max(0.0, e - analyze_ms), **kw)

        try:
            extract = self._extract or request_features.extract_features
            features = extract(raw_request)
            self._next_id += 1
            message_id = self._next_id
            line = encode_line({"id": message_id, "features": dataclasses.asdict(features)})
        except Exception as exc:  # noqa: BLE001
            return done(shadow.FAILED, f"extract:{type(exc).__name__}")

        try:
            reply_line = await asyncio.wait_for(self._exchange(proc, line), self.timeout_seconds)
        except asyncio.TimeoutError:
            # The worker is stuck (or too slow): END it, do not merely stop waiting for it.
            await self._kill(proc)
            self._note_failure()
            return done(shadow.TIMEOUT, "worker_killed")
        except (BrokenPipeError, ConnectionResetError, EOFError):
            code = proc.returncode if proc.returncode is not None else await self._reap(proc)
            await self._kill(proc)
            self._note_failure()
            return done(shadow.FAILED, f"worker_exited:rc={code}")
        except (ValueError, asyncio.LimitOverrunError):   # over-long line / StreamReader limit
            await self._kill(proc)
            self._note_failure()
            return done(shadow.INVALID_OUTPUT, "ipc_line_too_long")

        try:
            reply = decode_line(reply_line)
        except ValueError:
            await self._kill(proc)   # desynchronised or hostile: do not keep talking to it
            self._note_failure()
            return done(shadow.INVALID_OUTPUT, "ipc_malformed_or_non_finite")
        if reply.get("id") != message_id:
            await self._kill(proc)
            self._note_failure()
            return done(shadow.INVALID_OUTPUT, "ipc_id_mismatch")

        analyze_ms = reply.get("analyze_ms")
        analyze_ms = (float(analyze_ms) if isinstance(analyze_ms, (int, float))
                      and not isinstance(analyze_ms, bool) and math.isfinite(analyze_ms)
                      and analyze_ms >= 0 else None)
        if reply.get("ok") is not True:
            kind, detail = reply.get("kind"), safe_detail(reply.get("detail"))
            if kind == "invalid":   # the worker refused an output (e.g. non-finite): a worker still healthy
                return done(shadow.INVALID_OUTPUT, detail, analyze_ms)
            if kind == "unavailable" and detail in shadow.UNAVAILABLE_DETAILS:
                return done(shadow.UNAVAILABLE, detail, analyze_ms)
            return done(shadow.FAILED, detail if kind == "failed" else "worker_protocol_error",
                        analyze_ms)

        # Defence in depth: the gateway re-validates the answer with the D50 contract itself.
        try:
            output = contracts.AnalyzerOutput(reply["signals"], reply.get("version"))
            attack, category, probability, out_version = shadow._summarize(output)
        except shadow.InvalidAnalyzerOutput as exc:
            return done(shadow.INVALID_OUTPUT, safe_detail(str(exc)), analyze_ms)
        except (ValueError, TypeError, KeyError):
            return done(shadow.INVALID_OUTPUT, "contract_violation", analyze_ms)
        if out_version != version:
            return done(shadow.INVALID_OUTPUT, "version_mismatch", analyze_ms)
        self._failures = 0   # a healthy answer ends a failure streak
        return done(shadow.OK, None, analyze_ms, attack=attack, category=category,
                    category_probability=probability)

    @staticmethod
    async def _exchange(proc, line: bytes) -> bytes:
        proc.stdin.write(line)
        await proc.stdin.drain()
        reply = await proc.stdout.readline()
        if not reply:
            raise EOFError
        return reply

    @staticmethod
    async def _reap(proc) -> Optional[int]:
        try:
            return await asyncio.wait_for(proc.wait(), 1.0)
        except asyncio.TimeoutError:
            return None


def build_process_runner(python: str, artifact_path: str, timeout_seconds: float,
                         startup_timeout_seconds: float, restart_backoff_seconds: float,
                         max_consecutive_failures: int) -> ProcessShadowRunner:
    """The runtime the gateway uses: the worker script under the analyzer interpreter."""
    return ProcessShadowRunner(worker_argv(python, artifact_path), timeout_seconds,
                               startup_timeout_seconds, restart_backoff_seconds,
                               max_consecutive_failures)
