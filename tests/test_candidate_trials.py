"""The tools of the trials after training: GPU gate, fault injection, load configuration and analysis.
No model, no GPU.

    .venv-dataplane/bin/python -B -m unittest discover -s tests -p 'test_candidate_trials.py'
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(REPO, "data_plane"), os.path.join(REPO, "scripts", "gateway_ops")]

import canonical_request as cr  # noqa: E402
import candidate_compare as CC  # noqa: E402
import candidate_compare_report as CR  # noqa: E402
import candidate_load_summary as CS    # noqa: E402
import cascade_manifest as CM   # noqa: E402
import fault_proxy as FP        # noqa: E402
import http1_wire               # noqa: E402
import gpu_gate                 # noqa: E402
import live_stack as L          # noqa: E402
import load_analyze as LA       # noqa: E402
import load_check as LK         # noqa: E402
import load_lib as LL           # noqa: E402

FIXTURE = os.path.join(REPO, "reports/v5/hybrid/gateway-integration-v1/preparation-2026-11-01/fixtures/"
                             "doubles-candidate.json")
DOUBLES = os.path.join(REPO, "scripts", "gateway_ops", "service_doubles.py")


def compare_row(reference="BLOCK", v5=None, model2=None, applied="DENY", status=403, received=0,
                equal=None, canonical=True, census=True):
    return {"id": "c", "cohort": "dev", "reference": reference, "wire_origin": "built",
            "classification": {"v5": dict({"status": None, "decision": None}, **(v5 or {})),
                               "model2": dict({"decision": None}, **(model2 or {}))},
            "action": {"applied": applied, "deciding_stage": "v5", "reason": None}, "status": status,
            "reception": {"received": received, "bytes_equal_sent": equal},
            "canonical_equals_census": canonical, "v5_equals_census": census, "client_ms": 5.0}


class CompareLayersTests(unittest.TestCase):
    """Classification, action, status and reception are read apart: one never stands for another."""

    def test_a_built_wire_keeps_method_target_type_and_body(self):
        text = 'PATCH /api/a?b=1 HTTP/1.1\nContent-Type: application/json\n\n{"x": 1}'
        parsed = http1_wire.parse_request(CC.build_wire(text))
        self.assertEqual(cr.parse_canonical(text).body, parsed.parts.body)
        self.assertEqual((b"PATCH", b"/api/a?b=1"), (parsed.parts.method, parsed.parts.target))
        self.assertIn((b"Content-Type", b"application/json"), list(parsed.parts.headers))

    def test_a_request_without_body_has_no_length(self):
        self.assertNotIn(b"Content-Length", CC.build_wire("GET /a?b=1 HTTP/1.1\n"))

    def test_an_early_block_counts_as_the_decision_of_model2(self):
        row = compare_row(model2={"decision": "BLOCK"})
        self.assertEqual("BLOCK", CC.decided(row))
        self.assertTrue(CC.action_follows(row) and CC.status_follows(row) and CC.reception_follows(row))

    def test_an_invalid_v5_answer_is_no_decision(self):
        row = compare_row(v5={"status": "invalid"}, applied="DENY", status=503)
        self.assertIsNone(CC.decided(row))
        self.assertEqual(1, CC.confusion([row])["NO_DECISION"])
        self.assertFalse(CC.action_follows(row))
        self.assertTrue(CC.status_follows(row))

    def test_a_forward_needs_the_same_bytes_at_the_sink(self):
        row = compare_row(reference="ALLOW", v5={"status": "ok", "decision": "ALLOW"}, applied="FORWARD",
                          status=200, received=1, equal=False)
        self.assertFalse(CC.reception_follows(row))
        self.assertEqual(1, CC.confusion([row])["TN"])

    def test_a_denial_that_reached_the_sink_is_caught(self):
        self.assertFalse(CC.reception_follows(compare_row(received=1, equal=True)))

    def test_a_different_canonical_is_reported_not_counted(self):
        rows = [compare_row(v5={"status": "ok", "decision": "BLOCK"}),
                dict(compare_row(), id="d", canonical_equals_census=False),
                dict(compare_row(), id="e", canonical_equals_census=None)]
        part = CC.summarize(rows)["dev"]["round_trip"]
        self.assertEqual({"reached_v5": 2, "canonical_equal": 1, "different": ["d"]}, part)

    def test_the_row_keeps_no_wire(self):
        case = {"id": "c", "cohort": "dev", "label": "ALLOW", "wire_origin": "built",
                "canonical_sha256": "a" * 64, "wire_sha256": "b" * 64, "wire_bytes": b"x"}
        row = CC.layered_row(case, "V5_ONLY", 200, 1, {"v5": {"status": "ok", "decision": "ALLOW"}},
                             sink_sha256="b" * 64, seen_sha256="a" * 64, client_ms=1.0, census=None)
        self.assertEqual((True, True), (row["canonical_equals_census"], row["reception"]["bytes_equal_sent"]))
        self.assertNotIn("wire_bytes", json.dumps(row))
        self.assertNotIn("b" * 64, json.dumps(row))


    def test_a_census_is_compared_on_status_and_decision_with_the_service_fields_kept(self):
        case = {"id": "c", "cohort": "dev", "label": "ALLOW", "wire_origin": "built",
                "canonical_sha256": "a" * 64, "wire_sha256": "b" * 64}
        record = {"v5": {"status": "ok", "decision": "ALLOW"}, "v5_service": {"generated_tokens": 13}}
        row = lambda census: CC.layered_row(case, "V5_ONLY", 200, 1, record, sink_sha256="b" * 64,  # noqa: E731
                                            seen_sha256="a" * 64, client_ms=1.0, census=census)
        self.assertTrue(row({"status": "ok", "decision": "ALLOW", "reason": "x"})["v5_equals_census"])
        self.assertFalse(row({"status": "ok", "decision": "BLOCK"})["v5_equals_census"])
        self.assertEqual(13, row(None)["classification"]["v5"]["generated_tokens"])


class CompareReportTests(unittest.TestCase):
    def test_a_different_answer_is_listed_by_case(self):
        rows = [dict(compare_row(v5={"status": "ok", "decision": "ALLOW"}), id="a"),
                dict(compare_row(v5={"status": "ok", "decision": "BLOCK"}), id="b"),
                dict(compare_row(model2={"decision": "BLOCK"}), id="c")]
        census = {"a": {"status": "ok", "decision": "ALLOW"}, "b": {"status": "ok", "decision": "ALLOW"}}
        self.assertEqual({"compared": 2, "same": 1, "different": ["b"]}, CR.same_as_census(rows, census))

    def test_a_counterfactual_must_match_the_stage_as_well(self):
        row = dict(compare_row(model2={"decision": "BLOCK"}), id="a")
        row["action"]["deciding_stage"] = "model2"
        self.assertEqual(1, CR.same_as_counterfactual([row], {"a": {"decision": "BLOCK",
                                                                    "deciding_stage": "model2"}})["same"])
        self.assertEqual(0, CR.same_as_counterfactual([row], {"a": {"decision": "BLOCK",
                                                                    "deciding_stage": "v5"}})["same"])

    def test_the_effect_of_model2_comes_from_the_two_gateway_runs(self):
        alone = {"a": compare_row(v5={"status": "ok", "decision": "ALLOW"})}
        active = {"a": compare_row(model2={"decision": "BLOCK", "p_block": 0.95})}
        active["a"]["action"]["deciding_stage"] = "model2"
        effect = CR.model2_effect(active, alone)
        self.assertEqual(1, effect["early_blocks"])
        self.assertEqual(("ALLOW", "BLOCK"), (effect["changed"][0]["v5_alone"], effect["changed"][0]["cascade"]))


class LoadSummaryTests(unittest.TestCase):
    def test_totals_name_the_step_that_broke_reception(self):
        client = {key: 1 for key in CS.TOTALS}
        runs = {"r": {"steps": [{"label": "a", "client": client, "L2": {"conformant": True}},
                                {"label": "b", "client": client, "L2": {"conformant": False}}]}}
        out = CS.totals(runs)
        self.assertEqual((2, ["r/b"]), (out["offered"], out["L2_not_conformant"]))

    def test_an_analysis_or_a_note_is_not_a_run(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in ("analysis-ladder.json", "rates_from_ladder.json", "protocol.json", "soak_x.json"):
                with open(os.path.join(directory, name), "w", encoding="utf-8") as fh:
                    json.dump({"name": name}, fh)
            self.assertEqual(["soak_x"], list(LA.load_runs(directory)))
            self.assertEqual(["soak_x"], list(CS.results(directory)))


class ForeignGpuTests(unittest.TestCase):
    def test_a_desktop_window_is_not_a_foreign_model(self):
        apps = "10033, /usr/bin/ptyxis, 40\n112691, /usr/bin/gnome-text-editor, 72\n"
        self.assertEqual([], LK.foreign_compute(apps, set()))

    def test_real_work_of_someone_else_stops_the_run_and_ours_does_not(self):
        apps = "500, /usr/bin/python3.12, 1426\n501, /usr/bin/python3.12, 1400\n"
        self.assertEqual(["501, /usr/bin/python3.12, 1400"], LK.foreign_compute(apps, {500}))

    def test_a_memory_nvidia_smi_cannot_read_is_not_taken_as_work(self):
        self.assertEqual([], LK.foreign_compute("500, x, [N/A]\n", set()))


class GpuGateTests(unittest.TestCase):
    def status(self, document):
        fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        self.addCleanup(os.unlink, fh.name)
        json.dump(document, fh)
        fh.close()
        return fh.name

    def test_only_a_hand_off_allows_a_model(self):
        self.assertIsNone(gpu_gate.refusal(self.status({"state": "AVAILABLE_FOR_CLAUDE"})))
        self.assertIsNone(gpu_gate.refusal(self.status({"state": "IN_USE_BY_CLAUDE"})))
        self.assertIn("AVAILABLE_FOR_CODEX", gpu_gate.refusal(self.status({"state": "AVAILABLE_FOR_CODEX"})))
        self.assertIsNotNone(gpu_gate.refusal(self.status({"state": "IN_USE_BY_CODEX"})))
        self.assertIsNotNone(gpu_gate.refusal(self.status({})))

    def test_an_unreadable_file_refuses(self):
        self.assertIn("unreadable", gpu_gate.refusal("/nonexistent/GPU_STATUS.json"))


class FaultProxyTests(unittest.TestCase):
    def setUp(self):
        self.port = L.free_port()
        self.service = f"http://127.0.0.1:{self.port}"
        self.proc = subprocess.Popen([sys.executable, DOUBLES, "--role", "v5", "--port", str(self.port),
                                      "--manifest", FIXTURE], stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
        self.addCleanup(self.proc.wait)
        self.addCleanup(self.proc.terminate)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and L.http_get(self.service + "/health", 0.2)[0] != 200:
            time.sleep(0.02)
        self.proxy = FP.FaultProxy(self.service, hang_seconds=0.5)
        self.addCleanup(self.proxy.close)

    def classify(self):
        import urllib.request
        request = urllib.request.Request(self.proxy.url + "/classify", method="POST",
                                         data=json.dumps({"canonical_request": "GET / HTTP/1.1\n"}).encode(),
                                         headers={"Content-Type": "application/json"})
        try:
            with L.OPENER.open(request, timeout=3) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def test_passes_through_and_counts_calls_to_the_service(self):
        status, body = self.classify()
        self.assertEqual((status, json.loads(body)["decision"]), (200, "ALLOW"))
        self.assertEqual(self.proxy.classify_calls, 1)

    def test_an_answer_fault_never_reaches_the_service(self):
        for fault in FP.ANSWER_FAULTS:
            self.proxy.fault = fault
            self.assertEqual(self.classify()[0], FP.ANSWER_FAULTS[fault][0])
        self.assertEqual(self.proxy.classify_calls, 0)

    def test_identity_fields_can_be_overridden_and_the_rest_stays(self):
        self.proxy.identity = {"/health": {"adapter_sha256": "0" * 64}}
        health = json.loads(L.http_get(self.proxy.url + "/health")[1])
        self.assertEqual(health["adapter_sha256"], "0" * 64)
        self.assertTrue(health["model_loaded"])

    def test_every_answer_fault_is_denied_by_the_v5_client(self):
        import cascade_ops as ops
        import cascade_gateway as CG
        client = CG.V5ServiceClient(self.proxy.url + "/classify", 1.0, ops.Metrics())
        for fault in FP.ANSWER_FAULTS:
            self.proxy.fault = fault
            reply = client("GET / HTTP/1.1\n")
            self.assertFalse(reply.status == "ok" and reply.decision in ("ALLOW", "BLOCK"), fault)


class DoubleTests(unittest.TestCase):
    def test_serial_inference_queues_reports_and_refuses_beyond_its_bound(self):
        import service_doubles as SD
        SD.State.inference_ms, SD.State.max_inflight, SD.State.decoder = 1.0, 1, "native"
        status, body = SD.serial_inference("v5", "x")
        self.assertEqual((status, body["decoder_fallback"], body["generated_tokens"]), (200, None, 9))
        SD.State.inside = 1
        self.addCleanup(setattr, SD.State, "inside", 0)
        self.assertEqual(SD.serial_inference("v5", "x")[0], 503)


class ConfigurationTests(unittest.TestCase):
    def parser(self):
        parser = argparse.ArgumentParser()
        parser.error = lambda message: (_ for _ in ()).throw(ValueError(message))
        return parser

    def args(self, **overrides):
        values = dict(candidate_manifest=FIXTURE, with_v4=False, phase=["ladder"], recovery_rate=None,
                      quick=False, manifest=None, verified_manifest=None, verified_profile=None)
        return argparse.Namespace(**{**values, **overrides})

    def test_a_candidate_does_not_need_v4(self):
        args = self.args()
        LK.configure(self.parser(), args)
        self.assertEqual(args.runs, LK.CANDIDATE_RUNS)
        self.assertNotIn("v4", args.manifests)
        self.assertFalse(any(mode == "CASCADE_OBSERVE" for _, mode in args.runs))
        self.assertFalse(any(mode == "CASCADE_OBSERVE" for _, mode in args.recovery_runs))

    def test_v4_is_only_there_when_asked_for(self):
        args = self.args(with_v4=True)
        LK.configure(self.parser(), args)
        self.assertIn(("v4", "V4_ONLY"), args.runs)

    def test_the_service_of_a_candidate_gets_its_own_adapter_and_recipe(self):
        args = self.args()
        LK.configure(self.parser(), args)
        manifest = CM.load_manifest(FIXTURE)
        env = args.service_env["candidate"]
        self.assertEqual(env["FIREWALL_V5_ADAPTER_DIR"], manifest.v5.adapter_path)
        self.assertEqual(env["FIREWALL_V5_RECIPE"], manifest.v5.recipe_path)
        self.assertNotIn("FIREWALL_V5_RUNTIME_PROFILE", env)

    def test_recovery_rate_of_a_candidate_is_never_the_rate_of_v4(self):
        with self.assertRaisesRegex(ValueError, "recovery-rate"):
            LK.configure(self.parser(), self.args(phase=["recovery"]))
        LK.configure(self.parser(), self.args(phase=["recovery"], recovery_rate=30.0))

    def test_a_v1_manifest_is_not_a_candidate(self):
        path = os.path.join(REPO, "reports/v5/hybrid/gateway-integration-v1/manifests/dev_fixture_baseline34.json")
        with self.assertRaisesRegex(ValueError, "v2"):
            LK.configure(self.parser(), self.args(candidate_manifest=path))

    def test_the_load_run_configuration_keeps_its_shape(self):
        args = self.args(candidate_manifest=None, manifest=FIXTURE, verified_manifest=FIXTURE,
                         verified_profile=os.path.join(
                             REPO, "reports/v5/successor-2026-10-30/verified-suffix/service-final/"
                                   "verified-suffix.EXPERIMENTAL.json"))
        LK.configure(self.parser(), args)
        self.assertEqual(args.runs, LK.RUNS)
        self.assertTrue(args.with_v4)
        self.assertEqual(args.service_env["verified"]["FIREWALL_V5_ALLOW_EXPERIMENTAL_RUNTIME"], "1")


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        os.makedirs(os.path.join(self.dir.name, "rows"))

    def rows(self, name, latencies):
        with open(os.path.join(self.dir.name, "rows", f"{name}.jsonl"), "w", encoding="utf-8") as fh:
            for value in latencies:
                fh.write(json.dumps({"step": "soak", "status": 200, "outcome": "response",
                                     "latency_ms": value}) + "\n")

    def test_percentiles_of_repetitions_are_pooled_never_averaged(self):
        # Rep 1 is fast with a tail, rep 2 is uniformly slower: the mean of the two P95 is a number
        # that no pooled distribution has.
        fast = [10.0] * 94 + [1000.0] * 6
        slow = [100.0] * 100
        self.rows("soak_candidate_V5_ONLY_rep1", fast)
        self.rows("soak_candidate_V5_ONLY_rep2", slow)
        result = LA.soak_pooled(self.dir.name, {"soak_candidate_V5_ONLY_rep1": {}, "soak_candidate_V5_ONLY_rep2": {}})
        pooled = result["soak_candidate_V5_ONLY"]["latency_useful_ms"]
        self.assertEqual(pooled["p95"], LL.nearest_rank(fast + slow, 95))
        mean_of_p95 = (LL.nearest_rank(fast, 95) + LL.nearest_rank(slow, 95)) / 2
        self.assertNotEqual(pooled["p95"], mean_of_p95)

    def test_queue_peaks_are_maxima(self):
        steps = [{"resources": {"queues": {"admission_waiting": {"mean": 1.0, "max": 3}}}},
                 {"resources": {"queues": {"admission_waiting": {"mean": 2.0, "max": 7}}}}, {"resources": {}}]
        self.assertEqual(LA.queue_peaks(steps), {"admission_waiting": 7})

    def test_soak_rates_follow_the_configurations_that_ran(self):
        tables = {"candidate/V5_ONLY": {"max_sustainable_per_rep": [10, 12]},
                  "candidate/CASCADE_ACTIVE": {"max_sustainable_per_rep": [20]}}
        self.assertEqual(LA.soak_rates(tables), {"candidate": 7.0})
        self.assertEqual(LA.soak_high_rate(tables), 7.0)

    def test_an_analysis_is_never_replaced(self):
        path = os.path.join(self.dir.name, "analysis.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{}")
        result = subprocess.run([sys.executable, os.path.join(REPO, "scripts/gateway_ops/load_analyze.py"),
                                 "--run", self.dir.name], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FileExistsError", result.stderr)
        with open(path, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "{}")


if __name__ == "__main__":
    unittest.main()
