"""Accounting of the gateway load checks. Standard library, no model, no GPU.

    .venv-dataplane/bin/python -B -m unittest discover -s tests -p 'test_load_lib.py'
"""
import asyncio
import hashlib
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "scripts", "gateway_ops"))

import load_lib as LL  # noqa: E402


def row(status, latency=100.0, sha="a", outcome=None, t=0.0):
    return {"status": status, "latency_ms": latency, "lag_ms": 0.0, "t_sched": t, "wire_sha256": sha,
            "outcome": outcome or ("response" if status else "client_timeout")}


class PercentileTests(unittest.TestCase):
    def test_nearest_rank_has_no_interpolation(self):
        self.assertEqual(LL.nearest_rank([1, 2, 3, 4], 50), 2)
        self.assertEqual(LL.nearest_rank(list(range(1, 101)), 95), 95)
        self.assertEqual(LL.nearest_rank(list(range(1, 101)), 99), 99)

    def test_small_samples_flag_p99(self):
        self.assertTrue(LL.dist([1.0, 2.0])["p99_low_confidence"])
        self.assertNotIn("p99_low_confidence", LL.dist([1.0] * 100))
        self.assertEqual(LL.dist([]), {"n": 0})


class ScheduleTests(unittest.TestCase):
    def test_poisson_is_reproducible_and_near_the_rate(self):
        a = LL.poisson_offsets(5.0, 200.0, 7)
        self.assertEqual(a, LL.poisson_offsets(5.0, 200.0, 7))
        self.assertNotEqual(a, LL.poisson_offsets(5.0, 200.0, 8))
        self.assertTrue(900 < len(a) < 1100)
        self.assertLess(a[-1], 200.0)

    def test_order_is_seeded_cycles_and_ignores_input_order(self):
        cases = [{"id": f"c{i}"} for i in range(5)]
        a, b = LL.TrafficOrder(cases, 1), LL.TrafficOrder(list(reversed(cases)), 1)
        self.assertEqual(a.sha256, b.sha256)
        self.assertNotEqual(a.sha256, LL.TrafficOrder(cases, 2).sha256)
        self.assertEqual(a.take(6)[5]["id"], a.cases[0]["id"])


class AccountingTests(unittest.TestCase):
    def test_a_fast_rejection_is_not_useful_work(self):
        rows = [row(200) for _ in range(5)] + [row(503, 1.0) for _ in range(95)]
        result = LL.client_accounting(rows, 10.0)
        self.assertEqual(result["offered"], 100)
        self.assertEqual(result["completed"], 100)
        self.assertEqual(result["useful"], 5)
        self.assertEqual(result["rejected_503"], 95)
        self.assertLess(result["useful_per_s"], 1.0)
        self.assertTrue(LL.is_saturated(result))

    def test_healthy_step_is_not_saturated(self):
        self.assertFalse(LL.is_saturated(LL.client_accounting([row(200)] * 96 + [row(503)] * 4, 10.0)))

    def test_slow_answers_saturate_even_if_all_useful(self):
        self.assertTrue(LL.is_saturated(LL.client_accounting([row(200, 2500.0)] * 100, 10.0)))

    def test_a_step_with_no_useful_answer_is_saturated(self):
        self.assertTrue(LL.is_saturated(LL.client_accounting([row(503)] * 10, 10.0)))

    def test_timeouts_and_errors_are_counted_apart(self):
        rows = [row(None), row(None, outcome="connection_error:OSError"),
                row(None, outcome="closed_without_response"), row(502), row(400)]
        result = LL.client_accounting(rows, 1.0)
        self.assertEqual((result["client_timeouts"], result["connection_errors"],
                          result["closed_without_response"], result["bad_gateway_502"]), (1, 1, 1, 1))
        self.assertEqual(result["other_status"], {"400": 1})

    def test_rate_uses_the_tail_when_it_outlasts_the_window(self):
        result = LL.client_accounting([row(200, 20000.0, t=0.0)], 10.0)
        self.assertAlmostEqual(result["span_s"], 20.0)


class L2Tests(unittest.TestCase):
    def sink(self, *hashes):
        return [{"wire_sha256": h} for h in hashes]

    def test_same_multiset_is_conformant(self):
        rows = [row(200, sha="a"), row(200, sha="a"), row(403, sha="b")]
        self.assertTrue(LL.l2_multiset(rows, self.sink("a", "a"))["conformant"])

    def test_forwarded_but_not_received_is_a_fault(self):
        result = LL.l2_multiset([row(200, sha="a")], [])
        self.assertFalse(result["conformant"])
        self.assertEqual(result["answered_200_not_received"], 1)

    def test_blocked_but_received_is_a_fault(self):
        result = LL.l2_multiset([row(403, sha="a")], self.sink("a"))
        self.assertFalse(result["conformant"])
        self.assertEqual(result["denied_but_received"], 1)

    def test_identical_messages_are_counted_not_merged(self):
        result = LL.l2_multiset([row(200, sha="a"), row(403, sha="a")], self.sink("a", "a"))
        self.assertEqual(result["denied_but_received"], 1)

    def test_a_request_the_client_gave_up_on_is_indeterminate(self):
        result = LL.l2_multiset([row(None, sha="a")], self.sink("a"))
        self.assertTrue(result["conformant"])
        self.assertEqual(result["received_after_client_gave_up"], 1)

    def test_reception_nobody_asked_for_is_a_fault(self):
        result = LL.l2_multiset([], self.sink("z"))
        self.assertFalse(result["conformant"])
        self.assertEqual(result["received_without_any_request"], 1)


class RecoveryTests(unittest.TestCase):
    def test_counts_from_the_end_of_the_load_to_the_first_clean_run(self):
        probes = [row(503, t=10.0 + i) for i in range(5)] + [row(200, t=15.0 + i) for i in range(10)]
        self.assertAlmostEqual(LL.recovery_seconds(probes, 10.0, 500.0), 5.0)

    def test_slow_success_is_not_recovered(self):
        probes = [row(200, 900.0, t=i) for i in range(5)] + [row(200, 100.0, t=5 + i) for i in range(10)]
        self.assertAlmostEqual(LL.recovery_seconds(probes, 0.0, 500.0), 5.0)

    def test_never_recovered(self):
        self.assertIsNone(LL.recovery_seconds([row(503, t=i) for i in range(30)], 0.0, 500.0))


class ParserTests(unittest.TestCase):
    def test_v4_path_lines_give_numbers_only(self):
        lines = ["[ab] ALLOW GET h:80/secret reason='x' (classifier 251 ms)",
                 "[cd] BLOCK (fail-closed) GET h:80/secret cause=classifier timeout (after 3004 ms)",
                 "[ef] received GET h:80/secret (body 0 bytes)"]
        self.assertEqual(LL.gateway_v4_ms(lines), [251.0, 3004.0])

    def test_service_logs(self):
        self.assertEqual(LL.v4_model_ms(["classify: status=ok decision=ALLOW reason='x' model_latency_ms=250.5"]),
                         [250.5])
        counts = LL.v5_service_counts(["x classify: ok decision=BLOCK generate_ms=300.1",
                                       "x classify: saturated (>8 in flight), returning 503",
                                       "x classify: GPU lock wait exceeded 15.0s, returning 503"])
        self.assertEqual(counts["generate_ms"], [300.1])
        self.assertEqual((counts["saturated"], counts["lock_timeouts"]), (1, 1))

    def test_metrics_delta_keeps_counters_and_ignores_histograms(self):
        before = LL.parse_metrics('firewall_x_total{a="b"} 2\n')
        after = LL.parse_metrics('firewall_x_total{a="b"} 5\nfirewall_ms_bucket{le="1"} 9\nfirewall_ready 1\n')
        self.assertEqual(LL.metric_delta(before, after), {'firewall_x_total{a="b"}': 3.0})

    def test_log_tail_returns_each_complete_line_once(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write("one\ntwo")
        self.addCleanup(os.unlink, fh.name)
        tail = LL.LogTail(fh.name)
        self.assertEqual(tail.read(), ["one"])
        with open(fh.name, "a") as fh2:
            fh2.write("\nthree\n")
        self.assertEqual(tail.read(), ["two", "three"])
        self.assertEqual(tail.read(), [])


class DecisionTests(unittest.TestCase):
    def test_routes_stages_queue_and_decoder_path(self):
        records = [{"kind": "decision", "applied": "FORWARD", "deciding_stage": "v5", "gateway_ms": 400.0,
                    "stage_ms": {"admission": 1.0}, "timings_ms": {"v5_ms": 390.0, "model2_ms": 0.5},
                    "v5_service": {"queue_wait_ms": 90.0, "pipeline_ms": 295.0, "service_ms": 385.0,
                                   "decoder_fallback": True}},
                   {"kind": "decision", "applied": "DENY", "deciding_stage": "model2", "gateway_ms": 2.0,
                    "stage_ms": {}, "timings_ms": {"model2_ms": 0.4}, "reason": "model2_block"},
                   {"kind": "decision", "observation": "not_ready"}]
        result = LL.decision_accounting(records)
        self.assertEqual(result["records"], 2)
        v5 = result["routes"]["v5"]["stages_ms"]
        self.assertEqual(v5["v5_queue"]["p50"], 90.0)
        self.assertEqual(v5["v5_hop_outside_service"]["p50"], 5.0)
        self.assertEqual(result["routes"]["v5"]["decoder_pipeline_ms"]["fallback"]["n"], 1)
        self.assertEqual(result["routes"]["model2"]["reasons"], {"model2_block": 1})


class ClientTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.behavior = "ok"

        async def serve(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            if self.behavior == "hang":
                await asyncio.sleep(5)
            elif self.behavior == "close":
                pass
            else:
                writer.write(b"HTTP/1.1 503 x\r\nContent-Length: 2\r\n\r\nno")
                await writer.drain()
            writer.close()

        self.server = await asyncio.start_server(serve, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        wire = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"
        self.case = {"id": "c", "wire_bytes": wire, "wire_sha256": hashlib.sha256(wire).hexdigest()}

    async def asyncTearDown(self):
        self.server.close()

    async def test_latency_counts_from_the_scheduled_arrival(self):
        rows = await LL.open_loop("127.0.0.1", self.port, [self.case] * 2, [0.0, 0.05], 2.0)
        self.assertEqual([r["status"] for r in rows], [503, 503])
        self.assertLess(max(r["lag_ms"] for r in rows), 50)

    async def test_arrivals_do_not_wait_for_slow_responses(self):
        self.behavior = "hang"
        started = asyncio.get_running_loop().time()
        tasks = await LL.launch("127.0.0.1", self.port, [self.case] * 3, [0.0, 0.01, 0.02], 0.2)
        self.assertLess(asyncio.get_running_loop().time() - started, 0.15)
        rows = await asyncio.gather(*tasks)
        self.assertEqual({r["outcome"] for r in rows}, {"client_timeout"})

    async def test_closed_without_response(self):
        self.behavior = "close"
        rows = await LL.open_loop("127.0.0.1", self.port, [self.case], [0.0], 1.0)
        self.assertEqual(rows[0]["outcome"], "closed_without_response")

    async def test_connection_refused(self):
        self.server.close()
        await self.server.wait_closed()
        rows = await LL.open_loop("127.0.0.1", self.port, [self.case], [0.0], 1.0)
        self.assertTrue(rows[0]["outcome"].startswith("connection_error"))


if __name__ == "__main__":
    unittest.main()
