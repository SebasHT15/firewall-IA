"""
firewall-IA — asynchronous audit of Fast Path permissions: `fast-path-audit/v1`.

A FAST_ALLOW skips every model stage, so it needs a second look that cannot slow it down. This module
gives that look to a traceable sample, AFTER the permission was applied.

NOTHING HERE CAN CHANGE A PERMISSION. `submit` runs after the gateway applied the action, returns a
status the gateway only counts, and holds no reference to the flow, the ticket or the policy. A
disagreement is a record and a counter: it does not revoke the delivered request, does not touch the
policy and takes no automatic action. Every record says so (`retroactive_effect: none`).

  sampling    deterministic: sha256(salt | correlation_id) mapped to [0, 1) and compared with the
              rate. A record carries the bucket and a salt id, so any selection can be recomputed.
              The correlation id is not chosen by the client.
  saturation  a bounded queue, in items and in bytes. A full queue is a SATURATED record.
  timeout     each audit has its own deadline. A stuck auditor is abandoned on a daemon thread, and
              `max_abandoned` bounds them, after which audits are AUDITOR_STUCK instead of new threads.
  errors      an exception or a non-ok reply is a record, never an exception here.
  shutdown    intake stops, the queue drains for at most `shutdown_drain_seconds`, and whatever is
              left gets a DROPPED_SHUTDOWN record: every eligible permission ends in exactly one record.

The canonical text stays in memory only while queued. It is never written to a record.

Standard library only.
"""

import hashlib
import logging
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from cascade_ops import BoundedWorker, Metrics

log = logging.getLogger("firewall.data_plane.fast_path_audit")

CONTRACT_ID = "fast-path-audit/v1"

NOT_SAMPLED = "NOT_SAMPLED"
ENQUEUED = "ENQUEUED"
SATURATED = "SATURATED"
CLOSED = "CLOSED"
AUDITED = "AUDITED"
TIMEOUT = "TIMEOUT"
ERROR = "ERROR"
AUDITOR_STUCK = "AUDITOR_STUCK"
DROPPED_SHUTDOWN = "DROPPED_SHUTDOWN"

AGREE = "AGREE"                # the auditor would also have allowed it
DISAGREE = "DISAGREE"          # the auditor would have blocked it; recorded, nothing else happens
INCONCLUSIVE = "INCONCLUSIVE"  # no usable auditor answer


def sample_bucket(salt: str, correlation_id: str) -> float:
    digest = hashlib.sha256(f"{salt}|{correlation_id}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") / 2 ** 64


@dataclass
class _Item:
    record: dict
    text: str
    enqueued: float


class FastPathAuditor:
    """`classify(canonical_text)` is the auditor stage (the V5 client): it returns an object with
    `.status` and `.decision`, and may raise. `sink(record)` persists a record."""

    def __init__(self, config, classify: Callable, sink: Callable,
                 metrics: Optional[Metrics] = None, clock=time.monotonic):
        self.config = config
        self._classify = classify
        self._sink = sink
        self._metrics = metrics or Metrics()
        self._clock = clock
        self.salt_id = hashlib.sha256(config.sample_salt.encode("utf-8")).hexdigest()[:12]
        self._lock = threading.Lock()
        self._queued_bytes = 0
        self._abandoned = 0
        self._closed = False
        self._worker = BoundedWorker(self._audit, config.queue_size, config.workers,
                                     name="fast-path-audit")

    def _emit(self, record: dict) -> None:
        self._metrics.inc("firewall_fast_path_audit_total", status=record["status"],
                          verdict=record.get("verdict") or "none")
        try:
            self._sink(record)
        except Exception:  # noqa: BLE001 — a broken sink loses a record, nothing more
            self._metrics.inc("firewall_fast_path_audit_sink_errors_total")

    def submit(self, *, correlation_id: str, decision: dict, canonical_text: str,
               applied: bool) -> str:
        """Called after the action was applied. Never blocks, never raises; the answer is only for
        accounting. `applied` is False for a hypothetical FAST_ALLOW seen in OBSERVE."""
        status = NOT_SAMPLED
        try:
            bucket = sample_bucket(self.config.sample_salt, correlation_id)
            record = {"kind": "fast_path_audit", "contract": CONTRACT_ID,
                      "correlation_id": correlation_id, "rule_id": decision.get("rule_id"),
                      "policy_id": decision.get("policy_id"),
                      "policy_sha256": decision.get("policy_sha256"),
                      "policy_status": decision.get("policy_status"), "applied": bool(applied),
                      "sample_rate": self.config.sample_rate, "sample_bucket": bucket,
                      "salt_id": self.salt_id, "sampled": bucket < self.config.sample_rate,
                      "retroactive_effect": "none", "verdict": None}
            self._metrics.inc("firewall_fast_path_audit_eligible_total")
            if not record["sampled"]:
                self._emit({**record, "status": NOT_SAMPLED})
                return NOT_SAMPLED
            size = len(canonical_text.encode("utf-8"))
            with self._lock:
                closed = self._closed
                room = self._queued_bytes + size <= self.config.max_queue_bytes
                if not closed and room:
                    self._queued_bytes += size
            if closed:
                status = CLOSED
            elif not room:
                status = SATURATED
            elif self._worker.submit(_Item({**record, "text_bytes": size}, canonical_text,
                                           self._clock())):
                self._metrics.gauge("firewall_fast_path_audit_queue_depth", self._worker.qsize())
                return ENQUEUED
            else:
                with self._lock:
                    self._queued_bytes -= size
                status = SATURATED
            self._emit({**record, "status": status})
            return status
        except Exception:  # noqa: BLE001 — the permission was applied; auditing must stay out of it
            self._metrics.inc("firewall_fast_path_audit_submit_errors_total")
            return ERROR

    def _release(self, item: _Item) -> None:
        with self._lock:
            self._queued_bytes -= item.record.pop("text_bytes", 0)
        item.text = ""

    def _audit(self, item: _Item) -> None:
        started = self._clock()
        queue_wait_ms = (started - item.enqueued) * 1000
        text = item.text
        self._release(item)
        record = {**item.record, "queue_wait_ms": queue_wait_ms}
        with self._lock:
            stuck = self._abandoned >= self.config.max_abandoned
        if stuck:
            self._emit({**record, "status": AUDITOR_STUCK, "verdict": INCONCLUSIVE})
            return
        box: dict = {}

        def call():
            try:
                box["reply"] = self._classify(text)
            except Exception as exc:  # noqa: BLE001 — by type only: a message could quote the request
                box["error"] = type(exc).__name__

        thread = threading.Thread(target=call, name="fast-path-audit-call", daemon=True)
        thread.start()
        thread.join(self.config.timeout_seconds)
        audit_ms = (self._clock() - started) * 1000
        record["audit_ms"] = audit_ms
        self._metrics.observe_ms("firewall_fast_path_audit_ms", audit_ms)
        if thread.is_alive():
            with self._lock:
                self._abandoned += 1
            self._metrics.inc("firewall_fast_path_audit_abandoned_total")
            self._emit({**record, "status": TIMEOUT, "verdict": INCONCLUSIVE})
            return
        if "error" in box:
            self._emit({**record, "status": ERROR, "verdict": INCONCLUSIVE, "detail": box["error"]})
            return
        reply = box.get("reply")
        status, decision = getattr(reply, "status", None), getattr(reply, "decision", None)
        if status == "ok" and decision == "ALLOW":
            verdict = AGREE
        elif status == "ok" and decision == "BLOCK":
            verdict = DISAGREE
            log.warning("fast path audit DISAGREE correlation=%s rule=%s; recorded only, the "
                        "applied permission is unchanged", record["correlation_id"], record["rule_id"])
        else:
            verdict = INCONCLUSIVE
        self._emit({**record, "status": AUDITED, "verdict": verdict, "auditor_status": status})

    def close(self) -> None:
        """Stop intake, drain with a deadline and account for what is left. Idempotent."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
        for item in self._worker.close(self.config.shutdown_drain_seconds):
            self._release(item)
            self._emit({**item.record, "status": DROPPED_SHUTDOWN, "verdict": INCONCLUSIVE})
