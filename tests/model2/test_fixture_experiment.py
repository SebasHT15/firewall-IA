"""Engineering checks only: no assertion of security accuracy on fake labels."""
from dataclasses import replace
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

import numpy as np
from scripts.model2 import fixture_experiment as exp


class TestFixtureExperiment(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = exp.fixtures()
        cls.encoder, cls.scaler, cls.validation, cls.probabilities = exp._fit_fixture(cls.rows)

    def test_validation_only_category_is_not_learned(self):
        self.assertIn("method=GET", self.encoder.get_feature_names_out())
        self.assertNotIn("method=OPTIONS", self.encoder.get_feature_names_out())
        self.assertEqual(len(self.probabilities), 8)
        self.assertTrue(np.isfinite(self.probabilities).all())

    def test_validation_outlier_does_not_change_fitted_preprocessing(self):
        row = self.validation[0]
        text = "CUSTOM /synthetic?x=" + "x" * 10000 + " HTTP/1.1\n"
        changed = replace(row, text=text, text_sha256=exp._digest(text))
        altered = [changed if r.row_id == row.row_id else r for r in self.rows]
        encoder, scaler, _, _ = exp._fit_fixture(altered)
        self.assertEqual(list(encoder.get_feature_names_out()), list(self.encoder.get_feature_names_out()))
        np.testing.assert_array_equal(scaler.mean_, self.scaler.mean_)
        np.testing.assert_array_equal(scaler.scale_, self.scaler.scale_)
        self.assertEqual(scaler.n_samples_seen_, 24)

    def test_validation_labels_never_change_predictions(self):
        altered = [replace(r, label="BLOCK" if r.label == "ALLOW" else "ALLOW")
                   if r.split == "VALIDATION" else r for r in self.rows]
        _, _, _, probabilities = exp._fit_fixture(altered)
        np.testing.assert_array_equal(probabilities, self.probabilities)

    def test_row_group_ids_are_not_learned(self):
        altered = [replace(r, row_id="row-secret-" + r.row_id,
                           group_id="group-secret-" + r.group_id) for r in self.rows]
        encoder, _, _, probabilities = exp._fit_fixture(altered)
        np.testing.assert_array_equal(probabilities, self.probabilities)
        names = list(encoder.get_feature_names_out())
        self.assertEqual(names, list(self.encoder.get_feature_names_out()))
        for name in names:
            self.assertIn(name.split("=")[0], exp.FEATURES)

    def test_group_overlap_is_rejected(self):
        bad = replace(self.validation[0], group_id=self.rows[0].group_id)
        with self.assertRaisesRegex(ValueError, "overlap"):
            exp._fit_fixture([bad if r.row_id == bad.row_id else r for r in self.rows])

    def test_duplicate_text_across_splits_is_rejected(self):
        bad = replace(self.validation[0], text=self.rows[0].text,
                      text_sha256=self.rows[0].text_sha256)
        with self.assertRaisesRegex(ValueError, "overlap"):
            exp._fit_fixture([bad if r.row_id == bad.row_id else r for r in self.rows])

    def test_integrity_and_role_failures_are_rejected(self):
        for changes in ({"text_sha256": "0" * 64}, {"split": "INTERNAL_TEST"},
                        {"provenance": "ai_audited"}, {"representation": "D1"},
                        {"row_id": ""}, {"label": "DEFER"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                exp._fit_fixture([replace(self.rows[0], **changes), *self.rows[1:]])

    def test_one_class_empty_and_duplicate_are_rejected(self):
        choices = ([], [*self.rows, self.rows[0]],
                   [r for r in self.rows if r.split != "TRAIN" or r.label == "ALLOW"],
                   [r for r in self.rows if r.split != "VALIDATION"])
        for rows in choices:
            with self.subTest(length=len(rows)), self.assertRaises(ValueError):
                exp._fit_fixture(rows)

    def test_ablation_removes_only_named_fields(self):
        all_fields = exp.feature_dict(self.rows[0].text)
        ablated = exp.feature_dict(self.rows[0].text, omit_direct_path=True)
        self.assertEqual(set(all_fields) - set(ablated), {"path_length", "path_depth"})
        # Surface evidence still contains path information; no path-free claim.
        self.assertIn("slash_count", ablated)

    def test_repeated_fit_is_deterministic_in_this_environment(self):
        _, _, _, probabilities = exp._fit_fixture(self.rows)
        np.testing.assert_array_equal(probabilities, self.probabilities)

    def test_report_is_scoped_and_contains_no_text_or_saved_weights(self):
        report = exp.run_fixture_experiment(demonstration_threshold=0.5)
        self.assertEqual(report["scope"], "FIXTURE_ONLY")
        self.assertFalse(report["weights_saved"])
        self.assertFalse(report["operational_policy_approved"])
        self.assertIsNone(report["selected_variant"])
        serialized = json.dumps(report)
        for row in self.rows:
            self.assertNotIn(row.text, serialized)
        for variant in report["variants"]:
            metrics = variant["validation"]
            self.assertEqual(metrics["label_provenance"], "fixture_synthetic")
            self.assertEqual(metrics["early_block_false_positive_rate"]["denominator"], 4)

    def test_source_drift_invalidates_report(self):
        with patch.object(exp, "_source_hashes", side_effect=[{"a": "before"}, {"a": "after"}]):
            with self.assertRaisesRegex(RuntimeError, "source changed"):
                exp.run_fixture_experiment(demonstration_threshold=0.5)

    def test_bad_thresholds_and_data_arguments_are_rejected(self):
        for value in (True, float("nan"), float("inf"), -1, 2):
            with self.subTest(value=value), self.assertRaises(ValueError):
                exp.run_fixture_experiment(demonstration_threshold=value)
        result = subprocess.run([
            sys.executable, "-B", "-m", "scripts.model2.fixture_experiment",
            "--demonstration-threshold", "0.5", "--dataset", "/nonexistent/not-read"],
            cwd=exp.ROOT, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unrecognized arguments", result.stderr)


if __name__ == "__main__":
    unittest.main()
