"""
firewall-IA — the cascade in the mitmproxy gateway.

`CascadeRuntime` connects the transport-independent router (`cascade.py`, `cascade_runtime.py`) to a
mitmproxy flow. It adds no stage logic: it binds the request to its delivered bytes
(`gateway_framing`), canonicalizes once in a worker (`cascade_canonical`), gives that one snapshot to
the router on a bounded thread pool, applies the action, and accounts for it.

    V5_ONLY / CASCADE_ACTIVE   the router decides. Everything that prevents a decision is a DENY:
                               out of scope, not ready, saturated, no canonical result, V5 failure.
                               A FORWARD also issues the ticket the egress guard demands.
    CASCADE_OBSERVE            V4 decides through the unchanged path, first. Afterwards, off the
                               request path, the cascade computes what it would have done, inside
                               `after_v4`, which cannot raise and never touches the flow. The guard
                               is not in the path, so no cascade component can stop V4's delivery.
    V4_ONLY                    no runtime at all: the addon is exactly the V4 gateway.

RETURN TO V4 without a restart: while `rollback_file` exists, the authoritative modes hand every
request to the V4 path and the guard forwards without enforcing. The V4 service must be running; if
it is not, V4's own fail-closed applies.

The client never learns which stage or reason decided: only the status separates a security block
(403), a protocol reject (400), an unsupported request (501/505), a too-large body (413) and an
unavailable decision (503).

Records and metrics carry closed codes, identifiers and numbers. The canonical text, the target, the
headers and the body are never logged. The wire digest is lab evidence and off by default
(`log_wire_sha256`), since a hash of a short request can be inverted.
"""

import asyncio
import concurrent.futures
import dataclasses
import json
import logging
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import Optional

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from mitmproxy import http  # noqa: E402

import canonical_observer as cobs  # noqa: E402
import cascade as C  # noqa: E402
import cascade_canonical as CC  # noqa: E402
import cascade_manifest as CM  # noqa: E402
import cascade_ops as ops  # noqa: E402
import cascade_runtime as RT  # noqa: E402
import fast_path_audit as FA  # noqa: E402
import framing_evidence as fe  # noqa: E402
import gateway_framing as GF  # noqa: E402
import http1_wire as W  # noqa: E402
import model2_client as M2C  # noqa: E402

log = logging.getLogger("firewall.data_plane.cascade")

CONTRACT_ID = "firewall-cascade-gateway/v1"
RECORD_SCHEMA = "firewall-cascade-decision/v1"
PROBE_TIMEOUT_SECONDS = 2.0

BLOCKED_BODY = "Request blocked by firewall-IA.\n"
UNAVAILABLE_BODY = "Request blocked by firewall-IA: decision unavailable (fail-closed).\n"
PROTOCOL_BODY = "Request rejected by firewall-IA: malformed or unsupported.\n"

_ANSWERS = {400: PROTOCOL_BODY, 403: BLOCKED_BODY, 413: PROTOCOL_BODY, 501: PROTOCOL_BODY,
            503: UNAVAILABLE_BODY, 505: PROTOCOL_BODY}

# The V5 client reaches a local service. The stdlib opener would honour HTTP_PROXY, which on a shell
# configured to use this gateway routes the classification back through it (same reason as
# `trust_env=False` in data_plane.py). Installed once, for this process only.
_DIRECT_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def install_direct_opener() -> None:
    urllib.request.install_opener(_DIRECT_OPENER)


def _http_json(url: str, timeout: float) -> Optional[dict]:
    try:
        with _DIRECT_OPENER.open(url, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            value = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


class V5ServiceClient(RT.V5HttpClient):
    """`V5HttpClient`, keeping what the service reports about each call. The router needs only the
    decision, but under load the queue, the inference time and whether a verified decoder fell back
    are what explain a latency, and a saturated service, a timeout and a refused connection are
    different problems. These fields are measurements: none of them reaches a decision.
    tests/test_data_plane_cascade.py checks that it answers exactly like the base class."""

    FIELDS = ("queue_wait_ms", "pipeline_ms", "service_ms", "generated_tokens", "decoder_verified",
              "decoder_fallback")

    def __init__(self, url: str, timeout_s: float, metrics: ops.Metrics):
        super().__init__(url, timeout_s)
        self._metrics = metrics
        self._local = threading.local()

    def _failed(self, detail: str) -> C.V5Reply:
        self._metrics.inc("firewall_v5_client_errors_total", detail=detail)
        return C.V5Reply(status="error", detail=detail)

    def __call__(self, canonical_text: str) -> C.V5Reply:
        self._local.fields = None
        data = json.dumps({"canonical_request": canonical_text}).encode("utf-8")
        request = urllib.request.Request(self.url, data=data, method="POST",
                                         headers={"Content-Type": "application/json"})
        try:
            with _DIRECT_OPENER.open(request, timeout=self.timeout_s) as resp:
                if resp.status != 200:
                    return self._failed(f"http_{resp.status}")
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return self._failed(f"http_{exc.code}")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            return self._failed(type(exc).__name__)
        except ValueError:
            return self._failed("bad_json")
        self._local.fields = {name: payload.get(name) for name in self.FIELDS}
        return C.V5Reply(status=payload.get("status", "error"), decision=payload.get("decision"),
                         invalid_reason=payload.get("invalid_reason"),
                         generate_ms=payload.get("generate_ms"))

    def take_fields(self):
        """What the last call on this thread reported, once."""
        fields, self._local.fields = getattr(self._local, "fields", None), None
        return fields


class CascadeRuntime:
    def __init__(self, cfg, manifest, *, v4_health_url: str, policy, canonical_pool, model2,
                 v5_client, sink, auditor, metrics: ops.Metrics,
                 manifest_problems: tuple = ()):
        self.cfg = cfg
        self.manifest = manifest
        self.manifest_problems = manifest_problems
        self.enabled = manifest is not None and not manifest_problems
        self.v4_health_url = v4_health_url
        self.policy = policy
        self.pool = canonical_pool
        self.model2 = model2
        self.v5_client = v5_client
        self.sink = sink
        self.auditor = auditor
        self.metrics = metrics
        self.authoritative_config = cfg.mode in CM.AUTHORITATIVE_MODES
        self.verified_evidence = cfg.framing.verified_evidence
        self.router = None
        if self.authoritative_config:
            self.router = self._build_router(cfg.mode)
        egress = cfg.framing.egress
        self.book = GF.TicketBook(egress.max_tickets, egress.ticket_ttl_seconds)
        self._generation = fe.RelevantProfileGeneration()
        self.guard = None
        if self.authoritative_config:
            self.guard = GF.EgressGuard(
                listen_port=egress.listen_port, upstream=(egress.upstream_host, egress.upstream_port),
                book=self.book, enforcing=self.authoritative,
                generation=lambda: self._generation.generation, on_event=self._on_egress,
                max_message_bytes=W.MAX_HEAD + W.MAX_BODY, idle_timeout_seconds=egress.idle_timeout_seconds)
        self.expected_target = ((("127.0.0.1", egress.listen_port)) if self.authoritative_config
                                else (egress.upstream_host, egress.upstream_port))
        self._profile_problems: tuple = ("profile_not_sampled",)
        self._v5_problems: tuple = ("v5_not_probed",)
        self._v4_ok = False
        self._rollback = False
        self._slots = asyncio.Semaphore(cfg.max_inflight)
        self._waiting = 0
        self._pending_observe = 0
        self._tasks: set = set()
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=cfg.max_inflight + cfg.observe_max_pending, thread_name_prefix="cascade")
        self.admin = None
        if cfg.observability.admin_port:
            self.admin = ops.AdminServer(cfg.observability.admin_port, ready=self.readiness,
                                         status=self.status, metrics=metrics)
        self._probe_task = None

    def _build_router(self, mode, v4_client=None) -> C.CascadeRouter:
        return RT.build_router(C.CascadeConfig(mode=mode, fast_path_policy=self.policy),
                               model2_decider=self.model2, v5_client=self.v5_client,
                               v4_client=v4_client)

    # ── authority ───────────────────────────────────────────────────────
    def _rollback_active(self) -> bool:
        active = os.path.exists(self.cfg.rollback_file)
        if active != self._rollback:
            self._rollback = active
            self.metrics.gauge("firewall_rollback_active", 1 if active else 0)
            (log.warning if active else log.info)(
                "return to V4 %s", "ACTIVE: V4 decides every request" if active else "cleared")
        return active

    def authoritative(self) -> bool:
        return self.authoritative_config and not self._rollback_active()

    def effective_mode(self) -> str:
        return C.V4_ONLY if self._rollback_active() else self.cfg.mode

    # ── readiness ───────────────────────────────────────────────────────
    def configure(self, options, mitmproxy_version) -> None:
        profile = GF.sample_profile(options, mitmproxy_version)
        self._generation.observe(profile)
        self._profile_problems = GF.profile_problems(
            profile, body_size_limit=self.cfg.framing.body_size_limit,
            expected_target=self.expected_target)
        if self._profile_problems:
            log.warning("effective profile is outside %s: %s", GF.CONTRACT_ID,
                        ",".join(self._profile_problems))

    def problems(self) -> tuple:
        """Closed reasons why the cascade may not decide right now."""
        if not self.enabled:
            return tuple(self.manifest_problems) or ("manifest_unusable",)
        out = []
        if self.cfg.framing.contract != GF.CONTRACT_ID:
            out.append("framing_contract_unsupported")
        out.extend(f"framing:{p}" for p in self._profile_problems)
        out.extend(self._v5_problems)
        if self.pool.status()["ready"] == 0:
            out.append("canonical_workers_unavailable")
        if self.authoritative_config and (self.guard is None or not self.guard.listening):
            out.append("egress_guard_down")
        if self.model2 is not None:
            # A worker that crashes later is degraded and defers to V5. One that never proved its
            # identity against the manifest is not the configured cascade, in ACTIVE or in OBSERVE.
            if self.model2.incompatible:
                out.append("model2_incompatible")
            elif not self.model2.ever_ready:
                out.append("model2_not_started")
        return tuple(dict.fromkeys(out))

    def readiness(self) -> tuple:
        mode = self.effective_mode()
        cascade_problems = self.problems()
        detail = {"mode": self.cfg.mode, "effective_mode": mode,
                  "cascade_problems": list(cascade_problems), "degraded": self._degraded()}
        if mode in CM.AUTHORITATIVE_MODES:
            return not cascade_problems, detail
        return self._v4_ok, {**detail, "v4_ready": self._v4_ok}

    def _degraded(self) -> list:
        out = []
        if self.model2 is not None and self.model2.state != M2C.READY:
            out.append(f"model2_{self.model2.state}")   # requests defer to V5
        return out

    def status(self) -> dict:
        manifest = self.manifest
        model2 = manifest.model2 if manifest is not None else None
        return {
            "contract": CONTRACT_ID, "framing_contract": GF.CONTRACT_ID, "mode": self.cfg.mode,
            "effective_mode": self.effective_mode(),
            "deployment_profile": self.cfg.deployment_profile,
            "manifest_id": manifest.manifest_id if manifest else None,
            "manifest_sha256": manifest.sha256 if manifest else None,
            "manifest_status": manifest.status if manifest else None,
            "token_budget_B": manifest.canonical.token_budget_B if manifest else None,
            "model2_policy_status": model2.policy_status if model2 else None,
            "fast_path_activation": self.cfg.fast_path.activation,
            "fast_path_policy_status": self.policy.status if self.policy else None,
            "verified_evidence": self.verified_evidence,
            "canonical_workers": self.pool.status() if self.pool else None,
            "model2_worker": self.model2.status() if self.model2 else None,
            "tickets": len(self.book), "tickets_expired": self.book.expired,
            "egress_guard": bool(self.guard and self.guard.listening),
        }

    async def _probe(self) -> None:
        loop = asyncio.get_running_loop()
        while True:
            await self.probe_once(loop)
            await asyncio.sleep(self.cfg.probe_interval_seconds)

    async def probe_once(self, loop=None) -> None:
        loop = loop or asyncio.get_running_loop()
        timeout = PROBE_TIMEOUT_SECONDS
        health_url = self.cfg.v5_url.rstrip("/") + "/health"
        contract_url = self.cfg.v5_url.rstrip("/") + "/contract"
        if self.manifest is not None:
            health = await loop.run_in_executor(self._executor, _http_json, health_url, timeout)
            contract = await loop.run_in_executor(self._executor, _http_json, contract_url, timeout)
            self._v5_problems = (("v5_unreachable",) if health is None
                                 else CM.v5_contract_problems(self.manifest, health, contract))
        v4 = await loop.run_in_executor(self._executor, _http_json, self.v4_health_url, timeout)
        self._v4_ok = bool(v4 and v4.get("status") == "ok" and v4.get("model_loaded") is True)
        if self.pool is not None:
            self.pool.heal()
        if self.model2 is not None:
            self.model2.heal()
        if self.guard is not None and not self.guard.listening:
            await self._restart_guard()
        ready, _ = self.readiness()
        self.metrics.gauge("firewall_ready", 1 if ready else 0)
        self.metrics.gauge("firewall_tickets", len(self.book))

    async def _restart_guard(self) -> None:
        """The guard shares this process, so a listener that stopped can be started again. Until then
        the gateway is not ready and denies: nothing reaches the application unguarded."""
        try:
            await self.guard.start()
            self.metrics.inc("firewall_guard_restarts_total", result="ok")
            log.warning("egress guard restarted")
        except OSError as exc:
            self.metrics.inc("firewall_guard_restarts_total", result="failed")
            log.warning("egress guard restart failed (%s)", type(exc).__name__)

    # ── lifecycle ───────────────────────────────────────────────────────
    async def start(self) -> None:
        install_direct_opener()
        if self.enabled:
            self.pool.prewarm()
            if self.model2 is not None:
                self.model2.start()
        if self.guard is not None:
            try:
                await self.guard.start()
            except OSError as exc:
                log.warning("egress guard did not start (%s): the cascade stays not-ready",
                            type(exc).__name__)
        if self.admin is not None:
            await self.admin.start()
        self._probe_task = asyncio.ensure_future(self._probe())

    def close(self) -> None:
        if self._probe_task is not None:
            self._probe_task.cancel()
        if self.auditor is not None:
            self.auditor.close()
        if self.model2 is not None:
            self.model2.close()
        if self.pool is not None:
            self.pool.close()
        self._executor.shutdown(wait=False, cancel_futures=True)
        if self.sink is not None:
            self.sink.close()

    async def aclose(self) -> None:
        self.close()
        if self.guard is not None:
            await self.guard.aclose()
        if self.admin is not None:
            await self.admin.aclose()
        if self.pool is not None:
            await self.pool.aclose()

    # ── accounting ──────────────────────────────────────────────────────
    def _emit(self, record: dict) -> None:
        if self.sink is not None:
            self.sink.write(record)

    def _base_record(self, correlation_id: str) -> dict:
        manifest = self.manifest
        return {"kind": "decision", "schema": RECORD_SCHEMA, "correlation_id": correlation_id,
                "utc": time.time(), "mode": self.cfg.mode,
                "manifest_id": manifest.manifest_id if manifest else None,
                "manifest_sha256": manifest.sha256 if manifest else None,
                "framing_contract": GF.CONTRACT_ID}

    def _on_egress(self, event: dict) -> None:
        self.metrics.inc("firewall_egress_total", event=event["event"],
                         reason=(event.get("reason") or "none").split(":", 1)[0])
        if not self.cfg.observability.log_wire_sha256:
            event = {k: v for k, v in event.items() if k != "wire_sha256"}
        self._emit({**event, "utc": time.time(), "mode": self.cfg.mode})

    def _route(self, router, snapshot) -> tuple:
        """Runs on a router thread: the fields of the V5 call are that thread's."""
        result = router.route(snapshot)
        take = getattr(self.v5_client, "take_fields", None)
        return result, take() if take is not None else None

    def _account(self, result: C.CascadeResult, record: dict, stage_ms: dict) -> None:
        self.metrics.inc("firewall_requests_total", mode=record["mode"],
                         applied=record.get("applied") or "NONE",
                         stage=record.get("deciding_stage") or "none")
        if result is not None:
            self.metrics.inc("firewall_canonical_total", outcome=result.canonical_outcome or "none")
            if result.fast_path:
                self.metrics.inc("firewall_fast_path_total", decision=result.fast_path["decision"])
            if result.model2:
                self.metrics.inc("firewall_model2_total", decision=result.model2.get("decision") or "none",
                                 status=result.model2.get("status") or "none")
            if result.v5:
                self.metrics.inc("firewall_v5_total", status=result.v5.get("status") or "none",
                                 decision=result.v5.get("decision") or "none")
        for stage, value in stage_ms.items():
            self.metrics.observe_ms("firewall_stage_ms", value, stage=stage)

    def _result_fields(self, result: C.CascadeResult) -> dict:
        return dataclasses.asdict(result)

    # ── authoritative path ──────────────────────────────────────────────
    def _deny(self, flow, record: dict, status: int, stage: str, reason: str, started: float,
              result: Optional[C.CascadeResult] = None, stage_ms: Optional[dict] = None) -> None:
        flow.response = http.Response.make(status, _ANSWERS[status],
                                           {"Content-Type": "text/plain; charset=utf-8"})
        elapsed = (time.perf_counter() - started) * 1000
        record.update({"applied": C.DENY, "deciding_stage": stage, "reason": reason,
                       "http_status": status, "gateway_ms": elapsed, "stage_ms": stage_ms or {}})
        log.log(logging.WARNING if status == 403 else logging.ERROR,
                "[%s] DENY stage=%s reason=%s status=%d", record["correlation_id"], stage, reason,
                status)
        self._account(result, record, {**(stage_ms or {}), "gateway": elapsed})
        self._emit(record)

    async def _admit(self) -> bool:
        if self._slots.locked():
            if self._waiting >= self.cfg.max_waiting:
                return False
            self._waiting += 1
            try:
                await asyncio.wait_for(self._slots.acquire(), self.cfg.max_wait_seconds)
                return True
            except asyncio.TimeoutError:
                return False
            finally:
                self._waiting -= 1
        await self._slots.acquire()
        return True

    async def enforce(self, flow) -> None:
        """The whole authoritative decision. An exception escaping here reaches the addon's `request`
        hook, which answers fail-closed like every other unexpected gateway error."""
        started = time.perf_counter()
        correlation_id = flow.id.replace("-", "")[:12]
        record = self._base_record(correlation_id)

        rejection = GF.check_scope(flow)
        if rejection is not None:
            self._deny(flow, record, rejection[1], "framing", rejection[0], started)
            return
        ready, detail = self.readiness()
        if not ready:
            record["not_ready"] = detail["cascade_problems"]
            self._deny(flow, record, 503, "readiness", "not_ready", started)
            return
        admission_start = time.perf_counter()
        admitted = await self._admit()
        admission_ms = (time.perf_counter() - admission_start) * 1000
        if not admitted:
            self.metrics.inc("firewall_admission_total", result="saturated")
            self._deny(flow, record, 503, "admission", "saturated", started,
                       stage_ms={"admission": admission_ms})
            return
        self.metrics.inc("firewall_admission_total", result="admitted")
        release = True
        try:
            release = await self._decide(flow, record, started, correlation_id, admission_ms)
        finally:
            if release:
                self._slots.release()

    async def _decide(self, flow, record, started, correlation_id, admission_ms=0.0) -> bool:
        """Returns False only when a timed-out router thread still holds the slot."""
        stage_ms = {"admission": admission_ms}
        t0 = time.perf_counter()
        try:
            binding = GF.bind_delivery(flow.request, self._generation.generation)
        except GF.BindingError as exc:
            self._deny(flow, record, 400, "framing", exc.reason, started)
            return True
        except W.WireError as exc:
            self._deny(flow, record, 400, "framing", f"wire_{exc.reason}", started)
            return True
        stage_ms["binding"] = (time.perf_counter() - t0) * 1000
        record["framing_status"] = GF.EGRESS_BOUND
        record["delivered_bytes"] = len(binding.wire)
        record["body_framing"] = binding.body_framing
        if self.cfg.observability.log_wire_sha256:
            record["wire_sha256"] = binding.wire_sha256

        t0 = time.perf_counter()
        outcome = await self.pool.canonicalize(flow.request, self.cfg.max_wait_seconds)
        stage_ms["canonical_with_wait"] = (time.perf_counter() - t0) * 1000
        stage_ms["canonical"] = outcome.elapsed_ms
        if outcome.view is None:
            self.metrics.inc("firewall_canonical_failed_total", status=outcome.status)
            status = 413 if outcome.status == cobs.DROP else 503
            self._deny(flow, record, status, "canonical", f"canonical_{outcome.status.lower()}",
                       started, stage_ms=stage_ms)
            return True

        parts = binding.parts
        snapshot = C.Snapshot(method=parts.method, target=parts.target,
                              http_version=parts.http_version, headers=parts.headers,
                              body=parts.body, canonical=outcome.view,
                              framing=binding.framing_evidence(self.verified_evidence),
                              correlation_id=correlation_id)
        loop = asyncio.get_running_loop()
        future = loop.run_in_executor(self._executor, self._route, self.router, snapshot)
        try:
            result, v5_service = await asyncio.wait_for(asyncio.shield(future),
                                                        self.cfg.decision_deadline_seconds)
        except asyncio.TimeoutError:
            future.add_done_callback(lambda _: self._slots.release())
            self._deny(flow, record, 503, "deadline", "decision_deadline", started, stage_ms=stage_ms)
            return False
        stage_ms.update({k.removesuffix("_ms"): v for k, v in result.timings_ms.items()})
        record.update(self._result_fields(result))
        record["v5_service"] = v5_service

        if result.applied == C.FORWARD:
            if not self.book.issue(binding.wire_sha256, correlation_id, binding.generation):
                self.metrics.inc("firewall_tickets_refused_total")
                self._deny(flow, record, 503, "egress", "ticket_book_full", started, result, stage_ms)
                return True
            elapsed = (time.perf_counter() - started) * 1000
            record.update({"gateway_ms": elapsed, "http_status": None, "stage_ms": stage_ms})
            self._account(result, record, {**stage_ms, "gateway": elapsed})
            self._emit(record)
            log.info("[%s] FORWARD stage=%s", correlation_id, result.deciding_stage)
            if result.deciding_stage == C.STAGE_FAST_PATH and self.auditor is not None:
                self.auditor.submit(correlation_id=correlation_id, decision=result.fast_path,
                                    canonical_text=outcome.view.text, applied=True)
            return True

        if result.deciding_stage == C.STAGE_PROTOCOL:
            status = 400
        elif result.reason in ("v5_block", "model2_block"):
            status = 403
        else:
            status = 503
        self._deny(flow, record, status, result.deciding_stage, result.reason, started, result,
                   stage_ms)
        return True

    # ── observe path ────────────────────────────────────────────────────
    def after_v4(self, flow) -> None:
        """V4 already decided and its action is on the flow. Computes the cascade off the request
        path. Never raises and never changes the flow."""
        try:
            self._after_v4(flow)
        except Exception as exc:  # noqa: BLE001 — by type only: a message could quote the request
            self.metrics.inc("firewall_observe_total", status="internal_error")
            log.warning("cascade observation failed (%s); V4 unchanged", type(exc).__name__)

    def _skip_observation(self, status: str, correlation_id: str, **fields) -> None:
        self.metrics.inc("firewall_observe_total", status=status)
        self._emit({**self._base_record(correlation_id), "observation": status, **fields})

    def _after_v4(self, flow) -> None:
        if self.cfg.mode != C.CASCADE_OBSERVE or self._rollback_active():
            return
        correlation_id = flow.id.replace("-", "")[:12]
        if not self.enabled:
            self._skip_observation("disabled", correlation_id, not_ready=list(self.manifest_problems))
            return
        problems = self.problems()
        if problems:
            self._skip_observation("not_ready", correlation_id, not_ready=list(problems))
            return
        rejection = GF.check_scope(flow)
        if rejection is not None:
            self._skip_observation("out_of_scope", correlation_id, reason=rejection[0])
            return
        try:
            binding = GF.bind_delivery(flow.request, self._generation.generation)
        except (GF.BindingError, W.WireError) as exc:
            self._skip_observation("framing_rejected", correlation_id,
                                   reason=getattr(exc, "reason", "wire"))
            return
        if self._pending_observe >= self.cfg.observe_max_pending:
            self._skip_observation("saturated", correlation_id)
            return
        handle = self.pool.try_capture(flow.request)
        if handle is None:
            self._skip_observation("saturated", correlation_id)
            return
        if flow.response is None:
            v4 = C.V4Reply(status="ok", decision="ALLOW")
        elif flow.response.status_code == 403:
            v4 = C.V4Reply(status="ok", decision="BLOCK")
        else:
            v4 = C.V4Reply(status="error", detail=f"http_{flow.response.status_code}")
        self._pending_observe += 1
        task = asyncio.get_running_loop().create_task(
            self._observe(handle, binding, correlation_id, v4))
        self._tasks.add(task)

        def done(t):
            self._tasks.discard(t)
            self._pending_observe -= 1

        task.add_done_callback(done)

    async def _observe(self, handle, binding, correlation_id, v4_reply) -> None:
        record = self._base_record(correlation_id)
        try:
            outcome = await self.pool.finish(handle)
            if outcome.view is None:
                self._skip_observation("canonical_unavailable", correlation_id,
                                       reason=outcome.failure)
                return
            parts = binding.parts
            snapshot = C.Snapshot(method=parts.method, target=parts.target,
                                  http_version=parts.http_version, headers=parts.headers,
                                  body=parts.body, canonical=outcome.view,
                                  framing=binding.framing_evidence(self.verified_evidence),
                                  correlation_id=correlation_id)
            router = self._build_router(C.CASCADE_OBSERVE, v4_client=lambda _: v4_reply)
            result, v5_service = await asyncio.get_running_loop().run_in_executor(
                self._executor, self._route, router, snapshot)
            record.update(self._result_fields(result))
            record["v5_service"] = v5_service
            record["observation"] = "computed"
            self.metrics.inc("firewall_observe_total", status="computed")
            self.metrics.inc("firewall_observe_agreement_total",
                             agreement="same" if result.applied == result.cascade_applied else "different")
            self._account(result, record, {k.removesuffix("_ms"): v
                                           for k, v in result.timings_ms.items()})
            self._emit(record)
            if result.cascade_stage == C.STAGE_FAST_PATH and self.auditor is not None:
                self.auditor.submit(correlation_id=correlation_id, decision=result.fast_path,
                                    canonical_text=outcome.view.text, applied=False)
        except Exception as exc:  # noqa: BLE001 — V4 already acted; this only loses an observation
            self._skip_observation("internal_error", correlation_id, reason=type(exc).__name__)


def build_runtime(cfg) -> CascadeRuntime:
    """The real runtime for a validated configuration. Raises `ManifestError` when an authoritative
    mode cannot be enabled, which stops mitmdump before it listens. In OBSERVE a problem disables only
    the observation: V4 must keep running, and /readyz says why the cascade is off."""
    metrics = ops.Metrics()
    obs_cfg = cfg.observability
    sink = ops.JsonlSink(obs_cfg.decision_log, obs_cfg.max_log_bytes, obs_cfg.max_log_files,
                         obs_cfg.log_queue_size, metrics)
    manifest = None
    problems: tuple = ()
    policy = None
    try:
        manifest = CM.load_manifest(cfg.manifest_path)
        problems = CM.validate_consistency(cfg, manifest)
        policy = CM.resolve_fast_path_policy(cfg.fast_path)
    except CM.ManifestError as exc:
        if cfg.mode in CM.AUTHORITATIVE_MODES:
            sink.close(0.0)
            raise
        # WARNING, not ERROR: mitmdump exits on an error logged during startup, and V4 must keep serving.
        log.warning("cascade observation disabled: %s", exc)
        manifest, problems = None, ("manifest_unusable",)
    if problems and cfg.mode in CM.AUTHORITATIVE_MODES:
        sink.close(0.0)
        raise CM.ManifestError(f"manifest not enabled for {cfg.mode}: {','.join(problems)}")

    pool = model2 = v5_client = auditor = None
    if manifest is not None and not problems:
        canonical = cfg.canonical
        pool = CC.CanonicalPool(
            lambda: CC.build_client(canonical.bounds, manifest.canonical,
                                    canonical.max_received_body, canonical.max_text_bytes),
            canonical.workers)
        if manifest.model2 is not None and cfg.mode != C.V5_ONLY:
            # A canonical text may need up to 6 JSON bytes per byte, plus the small envelope.
            frame_cap = 6 * canonical.max_text_bytes + 4096
            model2 = M2C.Model2WorkerClient(
                M2C.worker_argv(cfg.model2.python, manifest.model2, frame_cap),
                manifest.model2, cfg.model2, frame_cap)
        v5_client = V5ServiceClient(cfg.v5_url, cfg.v5_timeout_seconds, metrics)
        if cfg.fast_path.activation != "disabled":
            audit_client = RT.V5HttpClient(cfg.v5_url, timeout_s=cfg.fast_path.audit.timeout_seconds)
            auditor = FA.FastPathAuditor(cfg.fast_path.audit, audit_client, sink.write, metrics)
    return CascadeRuntime(cfg, manifest, v4_health_url=cfg.v4_url.rstrip("/") + "/health",
                          policy=policy, canonical_pool=pool, model2=model2, v5_client=v5_client, sink=sink,
                          auditor=auditor, metrics=metrics, manifest_problems=problems)
