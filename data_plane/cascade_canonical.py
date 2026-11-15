"""
firewall-IA — canonicalization for the cascade decision path, in worker processes.

REUSE, NOT A SECOND IMPLEMENTATION. `canonical_observer.ProcessCanonicalObserver` already owns the
lifecycle D69 made mandatory: a separate process, a deadline that really stops the work (SIGKILL +
reap), backoff, bounded snapshots, closed statuses. `InlineCanonicalClient` subclasses it and changes
only what the decision path needs: the worker script, and reading the text frame that follows each
safe reply. The one `canonical_request.canonicalize` still runs exactly once per request, in the
worker. A timeout here is a real end of the computation, which a thread could not give.

`CanonicalPool` puts several single-in-flight clients behind one bounded wait. The observer's rule of
"no queue, BUSY when occupied" fits a shadow that may skip a request; an authoritative gateway must
instead wait a bounded time, so the wait lives here and the observer stays unchanged.

Standard library only.
"""

import asyncio
import collections
import dataclasses
import hashlib
import os
import sys
from dataclasses import dataclass, field
from typing import Optional

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import canonical_observer as obs  # noqa: E402

WORKER_SCRIPT = os.path.join(HERE, "cascade_canonical_worker.py")


@dataclass(frozen=True)
class CanonicalView:
    """What the router and the Fast Path read from a canonical result (the same duck type as
    `canonical_request.CanonicalResult`), rebuilt from the worker's safe reply plus the text."""
    outcome: str
    text: Optional[str]
    reject: Optional[str]
    reason: Optional[str]
    signals: tuple
    size: Optional[str]
    audit: dict = field(default_factory=dict)


@dataclass(frozen=True)
class CanonicalOutcome:
    """`view` is set when the worker canonicalized; otherwise `failure` holds a closed token."""
    view: Optional[CanonicalView]
    failure: Optional[str]
    status: str
    elapsed_ms: float = 0.0
    canonicalize_ms: Optional[float] = None


class InlineCanonicalClient(obs.ProcessCanonicalObserver):
    """One worker process, one request at a time, returning the canonical text as well."""

    def __init__(self, *args, max_text_bytes: int, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_text_bytes = max_text_bytes
        self._text: Optional[bytes] = None

    async def _write_and_read(self, proc, frame: bytes) -> bytes:
        # The base class wraps this whole coroutine in its single deadline, so a worker stuck
        # between the two frames is killed exactly like one stuck before the first.
        proc.stdin.write(frame)
        await proc.stdin.drain()
        reply = await obs.read_frame_async(proc.stdout, obs.MAX_REPLY_BYTES)
        self._text = await obs.read_frame_async(proc.stdout, self.max_text_bytes)
        return reply

    def revive(self) -> None:
        """Restart a dead worker without waiting for a request. The base class only notices one in
        capture(), and a gateway that is not ready never reaches capture(): without this, losing every
        worker would deny forever. Never awaits and never raises."""
        proc = self._proc
        if proc is not None and proc.returncode is not None:
            self._proc = None
            self._schedule_reap(proc)
            self._cause = "worker_restarting"
            self._note_failure()
        if self._proc is None and not self._permanent:
            self._maybe_start()

    async def complete(self, capture) -> CanonicalOutcome:
        self._text = None
        observation = await self.run_captured(capture)
        text_bytes, self._text = self._text, None
        return self._outcome(observation, text_bytes)

    @staticmethod
    def _outcome(observation, text_bytes) -> CanonicalOutcome:
        def failed(token):
            return CanonicalOutcome(None, token, observation.status, observation.elapsed_ms,
                                    observation.canonicalize_ms)

        if observation.status != obs.OK:
            return failed(obs.safe_detail(observation.detail, observation.status.lower()))
        text = None
        if observation.outcome == "ACCEPT":
            # An ACCEPT without the exact text it hashed is not usable: never forward or classify on
            # a text that the safe reply does not vouch for.
            if (not text_bytes
                    or hashlib.sha256(text_bytes).hexdigest() != observation.text_sha256):
                return failed("text_unavailable")
            text = text_bytes.decode("utf-8")
        audit = {"target_form": observation.target_form,
                 "content_codings": observation.content_codings,
                 "framing": {"transfer_encoding": observation.transfer_encoding},
                 "text_sha256": observation.text_sha256}
        return CanonicalOutcome(
            CanonicalView(observation.outcome, text, observation.reject, observation.reason,
                          observation.signals, observation.size, audit),
            None, obs.OK, observation.elapsed_ms, observation.canonicalize_ms)


def inline_worker_argv(python: str, *, max_decoded_body: int, token_budget: int,
                       max_bytes_per_token: int, max_frame_bytes: int,
                       max_text_bytes: int) -> list:
    return [python, "-I", WORKER_SCRIPT, "--max-decoded-body", str(max_decoded_body),
            "--token-budget", str(token_budget), "--max-bytes-per-token", str(max_bytes_per_token),
            "--max-frame-bytes", str(max_frame_bytes), "--max-text-bytes", str(max_text_bytes)]


def admission_caps(max_received_body: int) -> obs.AdmissionCaps:
    """The observer's whole-snapshot bounds, with the received-body bound from configuration."""
    headroom = obs.DEFAULT_CAPS.max_snapshot_bytes - obs.DEFAULT_CAPS.max_body_bytes
    return dataclasses.replace(obs.DEFAULT_CAPS, max_body_bytes=max_received_body,
                               max_snapshot_bytes=max_received_body + headroom)


def build_client(bounds, canonical_limits, max_received_body: int,
                 max_text_bytes: int) -> InlineCanonicalClient:
    caps = admission_caps(max_received_body)
    argv = inline_worker_argv(bounds.python, max_decoded_body=canonical_limits.max_decoded_body,
                              token_budget=canonical_limits.token_budget_B,
                              max_bytes_per_token=canonical_limits.max_bytes_per_token,
                              max_frame_bytes=caps.max_frame_bytes, max_text_bytes=max_text_bytes)
    return InlineCanonicalClient(argv, bounds.timeout_seconds, bounds.startup_timeout_seconds,
                                 bounds.restart_backoff_seconds, bounds.max_consecutive_failures,
                                 canonical_limits.max_decoded_body, caps,
                                 max_text_bytes=max_text_bytes)


class CanonicalPool:
    """Several `InlineCanonicalClient`s behind one bounded wait. All methods run on the gateway's
    event loop. `factory()` builds a client, so a client that disabled itself can be replaced."""

    def __init__(self, factory, workers: int):
        self._factory = factory
        self._clients = [factory() for _ in range(workers)]
        self._free = collections.deque(self._clients)
        self._waiters: collections.deque = collections.deque()

    def prewarm(self) -> None:
        for client in self._clients:
            client.prewarm()

    def status(self) -> dict:
        ready = sum(1 for c in self._clients
                    if c._proc is not None and c._proc.returncode is None and not c._permanent)
        return {"workers": len(self._clients), "ready": ready, "free": len(self._free),
                "disabled": sum(1 for c in self._clients if c._permanent)}

    def heal(self) -> None:
        """From the gateway's periodic probe: restart dead workers, and replace clients that gave up
        (`max_consecutive_failures`), so a failure streak does not leave the gateway denying until a
        restart. It must not depend on traffic. Only idle clients are replaced."""
        for i, client in enumerate(self._clients):
            if client._permanent and client in self._free:
                self._free.remove(client)
                client.close()
                fresh = self._factory()
                self._clients[i] = fresh
                fresh.prewarm()
                self._release(fresh)
            elif not client._permanent:
                client.revive()

    def _release(self, client) -> None:
        while self._waiters:
            waiter = self._waiters.popleft()
            if not waiter.done():
                waiter.set_result(client)
                return
        self._free.append(client)

    async def _acquire(self, wait_seconds: float):
        if self._free:
            return self._free.popleft()
        waiter = asyncio.get_running_loop().create_future()
        self._waiters.append(waiter)
        try:
            return await asyncio.wait_for(waiter, wait_seconds)
        except asyncio.TimeoutError:
            return None

    async def canonicalize(self, req, wait_seconds: float) -> CanonicalOutcome:
        """Wait a bounded time for a free worker, then canonicalize `req`. Never raises for a worker
        failure: that is a `failure` token the caller turns into a fail-closed answer. A worker that
        is restarting must not deny a request another worker can serve, so UNAVAILABLE moves on to
        the next one (canonicalization is pure). TIMEOUT does not: that input stopped a worker."""
        outcome = CanonicalOutcome(None, "pool_wait_timeout", obs.BUSY)
        for _ in range(len(self._clients)):
            client = await self._acquire(wait_seconds)
            if client is None:
                return outcome
            try:
                outcome = await client.complete(client.capture(req))
            finally:
                self._release(client)
            if outcome.status != obs.UNAVAILABLE:
                return outcome
        return outcome

    def try_capture(self, req):
        """Synchronous, for the observe path: an immediate capture, or None when every worker is
        occupied. The caller must pass the result to `finish`."""
        if not self._free:
            return None
        client = self._free.popleft()
        try:
            return client, client.capture(req)
        except Exception:  # noqa: BLE001 — capture() is guarded, but the slot must never leak
            self._release(client)
            raise

    async def finish(self, handle) -> CanonicalOutcome:
        client, capture = handle
        try:
            return await client.complete(capture)
        finally:
            client.release_captured(capture)
            self._release(client)

    def close(self) -> None:
        for client in self._clients:
            client.close()

    async def aclose(self) -> None:
        for client in self._clients:
            await client.aclose()
