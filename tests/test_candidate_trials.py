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

import cascade_manifest as CM   # noqa: E402
import fault_proxy as FP        # noqa: E402
import gpu_gate                 # noqa: E402
import live_stack as L          # noqa: E402
import load_analyze as LA       # noqa: E402
import load_check as LK         # noqa: E402
import load_lib as LL           # noqa: E402

FIXTURE = os.path.join(REPO, "reports/v5/hybrid/gateway-integration-v1/preparation-2026-11-01/fixtures/"
                             "doubles-candidate.json")
DOUBLES = os.path.join(REPO, "scripts", "gateway_ops", "service_doubles.py")


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
