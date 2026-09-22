"""External Test v1 latency observations — pinned against the committed Phase F evidence.

Read-only: runs scripts/external/summarize_latency_observations.py over
reports/external/external-v1-run-001/. These figures are observations, not a benchmark and
not end-to-end latency; the test exists so the numbers quoted in README.md, CONTEXT.md and
docs/technical_reference.md cannot drift from the evidence they were derived from.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts", "external"))
import summarize_latency_observations as slo  # noqa: E402


class TestLatencyObservations(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.obs = slo.observations()

    def test_gateway_values_match_the_phase_f_log_exactly(self):
        cc = self.obs["cross_check"]
        self.assertEqual(cc["data_plane_log_decision_lines"], 1200)
        self.assertEqual(cc["gateway_records_with_latency"], 1200)
        self.assertTrue(cc["identical_values_in_order"])

    def test_observation_counts(self):
        self.assertEqual(self.obs["gateway_classifier_call_ms"]["all"]["count"], 1200)
        for rep in (1, 2, 3):
            self.assertEqual(
                self.obs["gateway_classifier_call_ms"]["by_repetition"][rep]["count"], 400)
            self.assertEqual(self.obs["direct_generate_ms"]["by_repetition"][rep]["count"], 100)
        self.assertEqual(self.obs["direct_generate_ms"]["all"]["count"], 300)
        self.assertEqual(self.obs["direct_client_wall_ms"]["all"]["count"], 300)

    def test_quoted_gateway_figures(self):
        s = self.obs["gateway_classifier_call_ms"]["all"]
        self.assertEqual((s["min_ms"], s["p50_ms"], s["p95_ms"], s["p99_ms"], s["max_ms"]),
                         (163.0, 220.0, 255.0, 268.0, 570.0))
        self.assertAlmostEqual(s["mean_ms"], 213.50, places=2)

    def test_quoted_direct_figures(self):
        s = self.obs["direct_generate_ms"]["all"]
        self.assertAlmostEqual(s["p50_ms"], 193.10, places=2)
        self.assertAlmostEqual(s["p95_ms"], 247.89, places=2)
        self.assertAlmostEqual(s["mean_ms"], 201.33, places=2)

    def test_uses_the_benchmark_percentile_definition(self):
        self.assertTrue(self.obs["gateway_classifier_call_ms"]["all"]["percentile_method"]
                        .startswith("nearest-rank"))

    def test_labelled_as_observation_not_benchmark(self):
        self.assertIn("not a benchmark", self.obs["kind"])
        self.assertIn("Issue #18", self.obs["kind"])


if __name__ == "__main__":
    unittest.main()
