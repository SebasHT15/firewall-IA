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


    def test_a_cut_body_is_neither_complete_nor_useful(self):
        cut = row(None, outcome="incomplete_body")
        cut["partial_status"] = 200
        result = LL.client_accounting([row(200), cut], 1.0)
        self.assertEqual((result["offered"], result["completed"], result["useful"]), (2, 1, 1))
        self.assertEqual(result["incomplete_body"], 1)
        self.assertEqual(result["incomplete_by_head_status"], {"200": 1})
        self.assertEqual(result["statuses"], {"200": 1})
        self.assertFalse(LL.useful(cut))

    def test_a_cut_body_breaks_a_recovery_run(self):
        probes = [row(200, t=float(i)) for i in range(9)] + [row(None, outcome="incomplete_body", t=9.0)]
        self.assertIsNone(LL.recovery_seconds(probes, 0.0, 500.0))

    def test_rows_written_before_the_correction_still_read(self):
        result = LL.client_accounting([row(200)], 1.0)
        self.assertEqual((result["useful"], result["incomplete_body"]), (1, 0))


class ResponseFramingTests(unittest.IsolatedAsyncioTestCase):
    async def read(self, data):
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()
        return await LL._read_response(reader)

    async def test_declared_length_not_delivered_has_no_status(self):
        row_ = await self.read(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc")
        self.assertIsNone(row_["status"])
        self.assertEqual(row_["partial_status"], 200)
        self.assertEqual(row_["outcome"], "incomplete_body")
        self.assertEqual((row_["body_bytes"], row_["declared_body_bytes"]), (3, 10))

    async def test_whole_body_is_a_response(self):
        row_ = await self.read(b"HTTP/1.1 403 x\r\nContent-Length: 3\r\n\r\nabc")
        self.assertEqual((row_["status"], row_["outcome"]), (403, "response"))
        self.assertNotIn("partial_status", row_)

    async def test_body_in_several_reads(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nab")
        task = asyncio.ensure_future(LL._read_response(reader))
        await asyncio.sleep(0)
        reader.feed_data(b"cd")
        reader.feed_eof()
        self.assertEqual((await task)["status"], 200)

    async def test_zero_length_is_complete(self):
        self.assertEqual((await self.read(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))["status"], 200)

    async def test_no_body_statuses_ignore_what_follows(self):
        row_ = await self.read(b"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n")
        self.assertEqual((row_["status"], row_["framing"]), (204, "none"))

    async def test_interim_response_is_skipped(self):
        row_ = await self.read(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx")
        self.assertEqual(row_["status"], 200)

    async def test_chunked_complete_and_cut(self):
        whole = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
        self.assertEqual((await self.read(whole))["status"], 200)
        self.assertEqual((await self.read(whole[:-5]))["outcome"], "incomplete_body")
        trailers = whole[:-2] + b"X-T: 1\r\n\r\n"
        self.assertEqual((await self.read(trailers))["status"], 200)

    async def test_close_delimited_is_marked_because_a_cut_cannot_be_seen(self):
        row_ = await self.read(b"HTTP/1.1 200 OK\r\n\r\nabc")
        self.assertEqual((row_["status"], row_["close_delimited"]), (200, True))

    async def test_excess_bytes_are_reported(self):
        self.assertEqual((await self.read(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nabc"))["excess_bytes"], 2)

    async def test_conflicting_lengths_cannot_be_framed(self):
        with self.assertRaises(ValueError):
            await self.read(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab")

    async def test_nothing_is_closed_without_response(self):
        self.assertEqual((await self.read(b"HTTP/1.1 20"))["outcome"], "closed_without_response")


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

    def test_a_cut_200_is_indeterminate_not_a_proof_of_delivery(self):
        cut = {**row(None, sha="a", outcome="incomplete_body"), "partial_status": 200}
        self.assertEqual(LL.l2_multiset([cut], [])["forwarded"], 0)
        self.assertEqual(LL.l2_multiset([cut], [])["answered_200_not_received"], 0)
        self.assertEqual(LL.l2_multiset([cut], self.sink("a"))["received_after_client_gave_up"], 1)

    def test_a_cut_denial_that_was_received_is_still_a_fault(self):
        cut = {**row(None, sha="a", outcome="incomplete_body"), "partial_status": 403}
        result = LL.l2_multiset([cut], self.sink("a"))
        self.assertFalse(result["conformant"])
        self.assertEqual(result["denied_but_received"], 1)

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


class DecoderPathTests(unittest.TestCase):
    def path(self, verified, fallback, generated=9):
        return LL.decoder_path({"decoder_verified": verified, "decoder_fallback": fallback,
                                "generated_tokens": generated})

    def test_each_kept_pair_has_its_own_path(self):
        self.assertEqual(self.path(True, False), "verified")
        self.assertEqual(self.path(False, True), "fallback")
        self.assertEqual(self.path(False, False, 0), "no_generation")
        self.assertEqual(self.path(None, None), "native")
        self.assertEqual(self.path(None, None, 0), "no_generation")

    def test_no_fallback_alone_does_not_prove_verification(self):
        self.assertNotEqual(self.path(False, False, 0), "verified")
        self.assertEqual(self.path(False, False, 9), "inconsistent")
        self.assertEqual(self.path(True, True), "inconsistent")

    def test_a_refusal_before_generation_is_not_inference(self):
        record = {"kind": "decision", "applied": "DENY", "deciding_stage": "v5", "gateway_ms": 2.0,
                  "timings_ms": {"v5_ms": 3.0},
                  "v5_service": {"queue_wait_ms": 0.0, "pipeline_ms": 0.7, "service_ms": 0.8,
                                 "generated_tokens": 0, "decoder_verified": False,
                                 "decoder_fallback": False}}
        route = LL.decision_accounting([record])["routes"]["v5"]
        self.assertNotIn("verified", route["decoder_pipeline_ms"])
        self.assertEqual(route["decoder_pipeline_ms"]["no_generation"]["n"], 1)
        self.assertNotIn("v5_inference", route["stages_ms"])
        self.assertEqual(route["stages_ms"]["v5_no_generation"]["n"], 1)


class ClientTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.behavior = "ok"

        async def serve(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            if self.behavior == "hang":
                await asyncio.sleep(5)
            elif self.behavior == "close":
                pass
            elif self.behavior == "cut":
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc")
                await writer.drain()
            elif self.behavior == "stall":
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc")
                await writer.drain()
                await asyncio.sleep(5)
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

    async def test_body_cut_by_the_peer_is_not_a_status(self):
        self.behavior = "cut"
        rows = await LL.open_loop("127.0.0.1", self.port, [self.case], [0.0], 1.0)
        self.assertEqual((rows[0]["status"], rows[0]["partial_status"]), (None, 200))
        self.assertEqual(rows[0]["outcome"], "incomplete_body")
        self.assertFalse(LL.useful(rows[0]))

    async def test_a_body_that_stalls_is_a_timeout(self):
        self.behavior = "stall"
        rows = await LL.open_loop("127.0.0.1", self.port, [self.case], [0.0], 0.2)
        self.assertEqual((rows[0]["status"], rows[0]["outcome"]), (None, "client_timeout"))

    async def test_connection_refused(self):
        self.server.close()
        await self.server.wait_closed()
        rows = await LL.open_loop("127.0.0.1", self.port, [self.case], [0.0], 1.0)
        self.assertTrue(rows[0]["outcome"].startswith("connection_error"))


if __name__ == "__main__":
    unittest.main()
