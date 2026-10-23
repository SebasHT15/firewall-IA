import json
import unittest
from unittest.mock import patch
from scripts.model2 import grouped_fixture_experiment as exp


class TestGroupedFixtureExperiment(unittest.TestCase):
    def options(self):
        return dict(demonstration_threshold=.5, confidence_level=.95, n_resamples=100, seed=0)

    def test_shared_fixture_two_views_and_preserved_label_metadata(self):
        report = exp.run(**self.options())
        self.assertEqual(report["metadata"]["TRAIN"]["rows"], 232)
        self.assertEqual(report["metadata"]["VALIDATION"]["rows"], 24)
        self.assertEqual(report["metadata"]["VALIDATION"]["label_status"], {"VERIFIED": 24})
        self.assertEqual(report["metadata"]["TRAIN"]["connected_components"], 4)
        self.assertEqual(report["metadata"]["VALIDATION"]["pair_groups"], 12)
        self.assertEqual(report["metadata"]["VALIDATION"]["connected_components"], 1)
        self.assertIsNone(report["selected_variant"])
        self.assertFalse(report["weights_saved"])
        self.assertEqual([v["input_fields"] for v in report["variants"]], [34, 32])
        for variant in report["variants"]:
            self.assertEqual(variant["validation"]["point"]["label_provenance"], "fixture_synthetic")
            self.assertEqual(variant["validation"]["point"]["records"], 24)
            for interval in variant["validation"]["uncertainty"]["intervals"].values():
                self.assertEqual(interval["status"], "INSUFFICIENT_CONTRIBUTING_GROUPS")
                self.assertIsNone(interval["interval"])
        self.assertEqual([v["feature_overlap"]["shared_vectors"] for v in report["variants"]], [0, 2])
        self.assertNotIn("group_by_id", json.dumps(report))

    def test_reader_failure_never_reaches_fit(self):
        with patch.object(exp.integration.exchange, "load_examples", side_effect=ValueError("refused")), \
             patch.object(exp.integration.experiment, "_fit_fixture") as fit:
            with self.assertRaisesRegex(ValueError, "refused"):
                exp.run(**self.options())
            fit.assert_not_called()

    def test_source_drift_refuses_report(self):
        with patch.object(exp, "source_hashes", side_effect=[{"a": "before"}, {"a": "after"}]):
            with self.assertRaisesRegex(RuntimeError, "source changed"):
                exp.run(**self.options())
