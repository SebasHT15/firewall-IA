"""Counters, bounded background work, the JSONL sink and the audit of Fast Path permissions.

    .venv-dataplane/bin/python -m unittest discover -s tests -p 'test_cascade_ops.py' -v

Doubles for the auditor; threads and time are real.
"""
import dataclasses
import json
import os
import sys
import tempfile
import threading
import time
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "data_plane"))

import cascade_ops as ops       # noqa: E402
import fast_path_audit as FA    # noqa: E402


class SafeRecordTests(unittest.TestCase):
    def test_request_content_keys_are_removed_at_any_depth(self):
        record = {"correlation_id": "x", "canonical_text": "SECRET", "nested": {"body": "SECRET",
                  "keep": 1}, "list": [{"target": "SECRET", "ok": True}], "reasons": ["CLOSED"]}
        cleaned = json.dumps(ops.safe_record(record))
        self.assertNotIn("SECRET", cleaned)
        self.assertIn("CLOSED", cleaned)
        self.assertIn('"keep": 1', cleaned)


class MetricsTests(unittest.TestCase):
    def test_counts_and_render(self):
        m = ops.Metrics()
        m.inc("firewall_x_total", stage="v5")
        m.inc("firewall_x_total", 2, stage="v5")
        m.observe_ms("firewall_ms", 3.0, stage="v5")
        self.assertEqual(m.value("firewall_x_total", stage="v5"), 3)
        text = m.render()
        self.assertIn('firewall_x_total{stage="v5"} 3', text)
        self.assertIn('firewall_ms_bucket{stage="v5",le="5"} 1', text)
        self.assertIn('firewall_ms_count{stage="v5"} 1', text)

    def test_a_label_that_is_not_a_closed_token_is_replaced(self):
        m = ops.Metrics()
        m.inc("firewall_x_total", stage="' OR 1=1 --")
        text = m.render()
        self.assertNotIn("OR 1=1", text)
        self.assertIn('stage="other"', text)


class BoundedWorkerTests(unittest.TestCase):
    def test_full_queue_refuses_without_blocking(self):
        release = threading.Event()
        worker = ops.BoundedWorker(lambda _: release.wait(5), maxsize=1, workers=1)
        self.addCleanup(release.set)
        self.assertTrue(worker.submit(1))
        time.sleep(0.1)                     # taken by the thread
        self.assertTrue(worker.submit(2))   # queued
        started = time.monotonic()
        self.assertFalse(worker.submit(3))  # full
        self.assertLess(time.monotonic() - started, 0.05)

    def test_handler_failure_does_not_end_the_worker(self):
        seen = []

        def handler(item):
            if item == 1:
                raise RuntimeError("boom")
            seen.append(item)

        worker = ops.BoundedWorker(handler, maxsize=4)
        with self.assertLogs("firewall.data_plane.cascade_ops", level="ERROR"):
            worker.submit(1)
            worker.submit(2)
            worker.close(2.0)
        self.assertEqual(seen, [2])

    def test_close_returns_what_was_not_served(self):
        release = threading.Event()
        worker = ops.BoundedWorker(lambda _: release.wait(5), maxsize=4, workers=1)
        self.addCleanup(release.set)
        worker.submit(1)
        time.sleep(0.1)
        worker.submit(2)
        worker.submit(3)
        self.assertEqual(sorted(worker.close(0.0)), [2, 3])
        self.assertFalse(worker.submit(4))


class JsonlSinkTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = os.path.join(self.dir.name, "sub", "log.jsonl")

    def test_writes_records_without_content(self):
        sink = ops.JsonlSink(self.path, 1024, 2, 16)
        sink.write({"kind": "x", "body": "SECRET"})
        sink.close()
        with open(self.path, encoding="utf-8") as fh:
            self.assertEqual(json.loads(fh.read()), {"kind": "x"})

    def test_rotation_is_bounded(self):
        sink = ops.JsonlSink(self.path, 100, 3, 256)
        for i in range(40):
            sink.write({"kind": "row", "i": i, "pad": "x" * 30})
        sink.close()
        names = sorted(os.listdir(os.path.dirname(self.path)))
        self.assertEqual(names, ["log.jsonl", "log.jsonl.1", "log.jsonl.2"])

    def test_unserializable_record_is_counted_not_raised(self):
        metrics = ops.Metrics()
        sink = ops.JsonlSink(self.path, 1024, 1, 4, metrics)
        sink.write({"bad": float("nan")})
        sink.close()
        self.assertEqual(metrics.value("firewall_log_dropped_total", reason="unserializable"), 1)


@dataclasses.dataclass
class AuditConfig:
    sample_rate: float = 1.0
    sample_salt: str = "s"
    queue_size: int = 8
    max_queue_bytes: int = 1 << 20
    workers: int = 1
    timeout_seconds: float = 0.2
    max_abandoned: int = 2
    shutdown_drain_seconds: float = 1.0
    max_audits_per_second: float = 1000.0
    burst: int = 1000
    yield_when_v5_inflight: int = 1000
    max_queue_age_seconds: float = 60.0


@dataclasses.dataclass
class Reply:
    status: str
    decision: object = None


DECISION = {"rule_id": "r1", "policy_id": "p", "policy_sha256": "a" * 64, "policy_status": "PROPOSED"}


class AuditTests(unittest.TestCase):
    def build(self, classify, **config):
        self.records = []
        self.metrics = ops.Metrics()
        auditor = FA.FastPathAuditor(AuditConfig(**config), classify, self.records.append,
                                     self.metrics)
        self.addCleanup(auditor.close)
        return auditor

    def submit(self, auditor, cid="cid-1", text="GET / HTTP/1.1\n"):
        return auditor.submit(correlation_id=cid, decision=DECISION, canonical_text=text, applied=True)

    def wait(self, count=1, timeout=2.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and len(self.records) < count:
            time.sleep(0.005)
        self.assertGreaterEqual(len(self.records), count)
        return self.records

    def test_agree(self):
        auditor = self.build(lambda text: Reply("ok", "ALLOW"))
        self.assertEqual(self.submit(auditor), FA.ENQUEUED)
        record = self.wait()[0]
        self.assertEqual((record["status"], record["verdict"]), (FA.AUDITED, FA.AGREE))
        self.assertEqual(record["retroactive_effect"], "none")

    def test_disagreement_is_only_a_record(self):
        auditor = self.build(lambda text: Reply("ok", "BLOCK"))
        self.submit(auditor)
        record = self.wait()[0]
        self.assertEqual(record["verdict"], FA.DISAGREE)
        self.assertEqual(record["retroactive_effect"], "none")
        self.assertTrue(record["applied"])
        self.assertEqual(self.metrics.value("firewall_fast_path_audit_total", status=FA.AUDITED,
                                            verdict=FA.DISAGREE), 1)

    def test_sampling_is_deterministic_and_recomputable(self):
        auditor = self.build(lambda text: Reply("ok", "ALLOW"), sample_rate=0.5)
        ids = [f"cid-{i}" for i in range(200)]
        for cid in ids:
            self.submit(auditor, cid)
        self.wait(200)
        sampled = sum(1 for r in self.records if r["sampled"])
        self.assertTrue(40 < sampled < 160)
        for record in self.records:
            bucket = FA.sample_bucket("s", record["correlation_id"])
            self.assertEqual(record["sample_bucket"], bucket)
            self.assertEqual(record["sampled"], bucket < 0.5)

    def test_rate_zero_audits_nothing_but_records_eligibility(self):
        calls = []
        auditor = self.build(lambda text: calls.append(text), sample_rate=0.0)
        self.assertEqual(self.submit(auditor), FA.NOT_SAMPLED)
        self.assertEqual(calls, [])
        self.assertEqual(self.records[0]["status"], FA.NOT_SAMPLED)

    def test_queue_saturation(self):
        release = threading.Event()
        self.addCleanup(release.set)
        auditor = self.build(lambda text: (release.wait(5), Reply("ok", "ALLOW"))[1], queue_size=1,
                             timeout_seconds=5.0)
        statuses = [self.submit(auditor, f"c{i}") for i in range(4)]
        self.assertIn(FA.SATURATED, statuses)
        self.assertTrue(all(r["status"] == FA.SATURATED for r in self.records))

    def test_byte_bound_saturation(self):
        release = threading.Event()
        self.addCleanup(release.set)
        auditor = self.build(lambda text: (release.wait(5), Reply("ok", "ALLOW"))[1],
                             max_queue_bytes=10, timeout_seconds=5.0)
        self.assertEqual(self.submit(auditor, "c1", "x" * 11), FA.SATURATED)
        self.assertEqual(self.submit(auditor, "c2", "x" * 5), FA.ENQUEUED)

    def test_timeout_abandons_and_moves_on(self):
        release = threading.Event()
        self.addCleanup(release.set)
        auditor = self.build(lambda text: release.wait(10), timeout_seconds=0.05)
        started = time.monotonic()
        self.submit(auditor)
        record = self.wait()[0]
        self.assertEqual((record["status"], record["verdict"]), (FA.TIMEOUT, FA.INCONCLUSIVE))
        self.assertLess(time.monotonic() - started, 1.0)

    def test_abandoned_auditors_are_bounded(self):
        release = threading.Event()
        self.addCleanup(release.set)
        calls = []

        def stuck(text):
            calls.append(text)
            release.wait(10)

        auditor = self.build(stuck, timeout_seconds=0.02, max_abandoned=2)
        for i in range(4):
            self.submit(auditor, f"c{i}")
        self.wait(4)
        self.assertEqual(len(calls), 2)
        self.assertEqual([r["status"] for r in self.records].count(FA.AUDITOR_STUCK), 2)

    def test_auditor_exception_never_escapes_and_quotes_nothing(self):
        def boom(text):
            raise RuntimeError(text)

        auditor = self.build(boom)
        self.submit(auditor, text="SECRET REQUEST")
        record = self.wait()[0]
        self.assertEqual((record["status"], record["detail"]), (FA.ERROR, "RuntimeError"))
        self.assertNotIn("SECRET", json.dumps(record))

    def test_a_broken_sink_loses_a_record_and_nothing_else(self):
        metrics = ops.Metrics()

        def broken(record):
            raise OSError("disk")

        auditor = FA.FastPathAuditor(AuditConfig(sample_rate=0.0), lambda t: None, broken, metrics)
        self.addCleanup(auditor.close)
        self.assertEqual(auditor.submit(correlation_id="c", decision=DECISION, canonical_text="t",
                                        applied=True), FA.NOT_SAMPLED)
        self.assertEqual(metrics.value("firewall_fast_path_audit_sink_errors_total"), 1)

    def test_invalid_input_is_contained(self):
        auditor = self.build(lambda text: Reply("ok", "ALLOW"))
        self.assertEqual(auditor.submit(correlation_id="c", decision=None, canonical_text="t",
                                        applied=True), FA.ERROR)

    def test_record_never_holds_the_text(self):
        auditor = self.build(lambda text: Reply("invalid"))
        self.submit(auditor, text="SECRET REQUEST")
        self.assertNotIn("SECRET", json.dumps(self.wait()[0]))

    def test_shutdown_accounts_for_every_item(self):
        release = threading.Event()
        self.addCleanup(release.set)
        auditor = self.build(lambda text: (release.wait(5), Reply("ok", "ALLOW"))[1], queue_size=8,
                             timeout_seconds=5.0, shutdown_drain_seconds=0.05)
        for i in range(4):
            self.submit(auditor, f"c{i}")
        auditor.close()
        statuses = [r["status"] for r in self.records]
        self.assertEqual(statuses.count(FA.DROPPED_SHUTDOWN), 3)
        self.assertEqual(self.submit(auditor, "late"), FA.CLOSED)
        release.set()
        self.wait(5)
        self.assertEqual(len({r["correlation_id"] for r in self.records}), 5)


class Clock:
    now = 100.0

    def __call__(self):
        return self.now


class AuditBudgetTests(unittest.TestCase):
    """The audit must not displace the traffic that is waiting for a decision."""

    def build(self, classify=None, clock=time.monotonic, traffic=lambda: 0, **config):
        self.records = []
        self.metrics = ops.Metrics()
        auditor = FA.FastPathAuditor(AuditConfig(**config), classify or (lambda text: Reply("ok", "ALLOW")),
                                     self.records.append, self.metrics, clock=clock,
                                     traffic_in_v5=traffic)
        self.addCleanup(auditor.close)
        return auditor

    def submit(self, auditor, cid):
        return auditor.submit(correlation_id=cid, decision=DECISION, canonical_text="GET /\n", applied=True)

    def settled(self, auditor, seconds=3.0):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            counts = auditor.accounting()
            if counts["in_flight"] == 0:
                return counts
            time.sleep(0.005)
        self.fail(f"audits still in flight: {counts}")

    def assertAddsUp(self, counts):
        self.assertEqual(counts["requested"],
                         counts["completed"] + counts["discarded"] + counts["failed"] + counts["in_flight"])

    def test_token_bucket_caps_audits_and_refills(self):
        clock = Clock()
        auditor = self.build(clock=clock, max_audits_per_second=1.0, burst=2)
        self.assertEqual([self.submit(auditor, f"c{i}") for i in range(3)],
                         [FA.ENQUEUED, FA.ENQUEUED, FA.RATE_LIMITED])
        clock.now += 1.0
        self.assertEqual(self.submit(auditor, "c3"), FA.ENQUEUED)
        self.assertEqual(self.metrics.value("firewall_fast_path_audit_discarded_total",
                                            reason="rate_limited"), 1)
        self.assertAddsUp(self.settled(auditor))

    def test_bucket_never_exceeds_its_burst(self):
        clock = Clock()
        auditor = self.build(clock=clock, max_audits_per_second=1000.0, burst=2)
        clock.now += 3600.0
        self.assertEqual([self.submit(auditor, f"c{i}") for i in range(3)].count(FA.RATE_LIMITED), 1)

    def test_a_rate_limited_audit_is_recorded_not_lost(self):
        auditor = self.build(clock=Clock(), max_audits_per_second=1.0, burst=1)
        self.submit(auditor, "c0")
        self.submit(auditor, "c1")
        record = next(r for r in self.records if r["status"] == FA.RATE_LIMITED)
        self.assertEqual((record["retroactive_effect"], record["correlation_id"]), ("none", "c1"))

    def test_audit_waits_for_the_traffic_and_then_runs(self):
        busy = [3]
        calls = []
        auditor = self.build(lambda t: (calls.append(busy[0]), Reply("ok", "ALLOW"))[1],
                             traffic=lambda: busy[0], yield_when_v5_inflight=1)
        self.submit(auditor, "c")
        time.sleep(0.05)
        self.assertEqual(calls, [])
        busy[0] = 0
        counts = self.settled(auditor)
        self.assertEqual(calls, [0])
        self.assertEqual(counts["completed"], 1)

    def test_threshold_is_the_configured_one(self):
        calls = []
        auditor = self.build(lambda t: (calls.append(t), Reply("ok", "ALLOW"))[1], traffic=lambda: 1,
                             yield_when_v5_inflight=2)
        self.submit(auditor, "c")
        self.settled(auditor)
        self.assertEqual(len(calls), 1)

    def test_audit_that_never_gets_room_expires_without_calling_v5(self):
        calls = []
        auditor = self.build(lambda t: calls.append(t), traffic=lambda: 8, yield_when_v5_inflight=1,
                             max_queue_age_seconds=0.03)
        self.submit(auditor, "c")
        counts = self.settled(auditor)
        self.assertEqual(calls, [])
        self.assertEqual(self.records[-1]["status"], FA.EXPIRED)
        self.assertEqual(counts["discarded"], 1)
        self.assertEqual(self.metrics.value("firewall_fast_path_audit_discarded_total", reason="expired"), 1)

    def test_a_blocked_auditor_never_delays_submit(self):
        auditor = self.build(traffic=lambda: 8, yield_when_v5_inflight=1, queue_size=2,
                             max_queue_age_seconds=5.0, shutdown_drain_seconds=0.0)
        started = time.perf_counter()
        statuses = [self.submit(auditor, f"c{i}") for i in range(50)]
        self.assertLess(time.perf_counter() - started, 0.5)
        self.assertIn(FA.SATURATED, statuses)

    def test_shutdown_ends_a_held_audit_in_a_record(self):
        auditor = self.build(traffic=lambda: 8, yield_when_v5_inflight=1, max_queue_age_seconds=30.0,
                             shutdown_drain_seconds=0.2)
        self.submit(auditor, "c")
        auditor.close()
        counts = self.settled(auditor)
        self.assertEqual(self.records[-1]["status"], FA.DROPPED_SHUTDOWN)
        self.assertEqual(counts["discarded"], 1)

    def test_a_failing_traffic_signal_ends_the_audit_in_a_record(self):
        def broken():
            raise RuntimeError("signal")

        auditor = self.build(traffic=broken)
        self.submit(auditor, "c")
        counts = self.settled(auditor)
        self.assertEqual((counts["failed"], self.records[-1]["status"]), (1, FA.ERROR))
        self.assertEqual(auditor.accounting()["queued_bytes"], 0)

    def test_requested_completed_discarded_failed_add_up(self):
        replies = iter([Reply("ok", "ALLOW"), Reply("ok", "BLOCK"), Reply("invalid"), RuntimeError("x")])

        def classify(text):
            reply = next(replies)
            if isinstance(reply, Exception):
                raise reply
            return reply

        auditor = self.build(classify, clock=time.monotonic, max_audits_per_second=1e-6, burst=4)
        for i in range(6):
            self.submit(auditor, f"c{i}")
        counts = self.settled(auditor)
        self.assertEqual((counts["requested"], counts["completed"], counts["discarded"], counts["failed"]),
                         (6, 3, 2, 1))
        self.assertAddsUp(counts)
        self.assertEqual(self.metrics.total("firewall_fast_path_audit_requested_total"), 6)
        self.assertEqual(self.metrics.total("firewall_fast_path_audit_completed_total"), 3)
        self.assertEqual(self.metrics.total("firewall_fast_path_audit_discarded_total"), 2)
        self.assertEqual(self.metrics.total("firewall_fast_path_audit_failed_total"), 1)
        self.assertEqual(self.metrics.value("firewall_fast_path_audit_completed_total", verdict=FA.DISAGREE), 1)

    def test_not_sampled_is_eligible_but_not_requested(self):
        auditor = self.build(sample_rate=0.0)
        self.submit(auditor, "c")
        self.assertEqual(auditor.accounting()["requested"], 0)
        self.assertEqual(self.metrics.total("firewall_fast_path_audit_eligible_total"), 1)

    def test_timeout_and_stuck_auditors_are_failed_not_completed(self):
        release = threading.Event()
        self.addCleanup(release.set)
        auditor = self.build(lambda t: release.wait(10), timeout_seconds=0.02, max_abandoned=1)
        self.submit(auditor, "c0")
        self.submit(auditor, "c1")
        counts = self.settled(auditor)
        self.assertEqual((counts["completed"], counts["failed"]), (0, 2))
        self.assertEqual(self.metrics.value("firewall_fast_path_audit_failed_total", reason="timeout"), 1)
        self.assertEqual(self.metrics.value("firewall_fast_path_audit_failed_total", reason="auditor_stuck"), 1)

    def test_contention_in_every_order_still_adds_up(self):
        busy = [0]
        auditor = self.build(traffic=lambda: busy[0], yield_when_v5_inflight=1, queue_size=4,
                             max_queue_age_seconds=0.02, max_audits_per_second=500.0, burst=4)
        threads = [threading.Thread(target=lambda n=n: [self.submit(auditor, f"{n}-{i}") for i in range(50)])
                   for n in range(4)]
        for thread in threads:
            thread.start()
        for i in range(20):
            busy[0] = i % 2
            self.assertAddsUp(auditor.accounting())
            time.sleep(0.002)
        for thread in threads:
            thread.join()
        busy[0] = 0
        counts = self.settled(auditor, 5.0)
        self.assertEqual(counts["requested"], 200)
        self.assertAddsUp(counts)
        self.assertEqual(counts["queued_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
