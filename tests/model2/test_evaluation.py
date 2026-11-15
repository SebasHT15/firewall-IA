import dataclasses
import unittest
from scripts.model2.evaluation import ValidationScore, summarize_validation


class TestValidationMetrics(unittest.TestCase):
    def setUp(self):
        self.rows = [ValidationScore(str(i), str(i), "VALIDATION", label, "fixture_synthetic",
                                      "all_traffic_fast_path_ineligible", score)
                     for i, (label, score) in enumerate((("ALLOW", .9), ("ALLOW", .1),
                                                         ("BLOCK", .95), ("BLOCK", .5)))]

    def test_block_defer_denominators_are_explicit(self):
        result = summarize_validation(self.rows, threshold=.8)
        self.assertEqual(result["early_block_false_positive_rate"],
                         {"numerator": 1, "denominator": 2, "value": .5})
        self.assertEqual(result["attack_early_block_rate"]["value"], .5)
        self.assertEqual(result["block_precision"]["value"], .5)
        self.assertEqual(result["defer_rate"]["value"], .5)
        self.assertFalse(result["operational_policy_approved"])

    def test_threshold_boundary_is_inclusive(self):
        result = summarize_validation(self.rows, threshold=.95)
        self.assertEqual(result["block_precision"]["numerator"], 1)
        self.assertEqual(result["early_block_false_positive_rate"]["numerator"], 0)

    def test_no_benign_does_not_mean_zero_false_positive_rate(self):
        result = summarize_validation(self.rows[2:], threshold=1)
        self.assertIsNone(result["early_block_false_positive_rate"]["value"])
        self.assertIsNone(result["block_precision"]["value"])

    def test_protected_train_and_unspecified_roles_are_refused(self):
        for role in ("TRAIN", "INTERNAL_TEST", "E6_RESERVE", "EXTERNAL", ""):
            with self.subTest(role=role), self.assertRaises(ValueError):
                summarize_validation([dataclasses.replace(self.rows[0], role=role)], threshold=.8)

    def test_v4_v5_and_pending_labels_are_not_ground_truth(self):
        for provenance in ("v4_prediction", "v5_prediction", "PENDING_ADJUDICATION", ""):
            with self.subTest(provenance=provenance), self.assertRaises(ValueError):
                summarize_validation([dataclasses.replace(self.rows[0], label_provenance=provenance)], threshold=.8)

    def test_mixed_provenance_and_population_are_refused(self):
        for change in ({"label_provenance": "ai_audited"}, {"population": "fast_path_continue"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                summarize_validation([self.rows[0], dataclasses.replace(self.rows[1], **change)], threshold=.8)

    def test_invalid_probabilities_thresholds_duplicates_and_empty_refused(self):
        for p in (True, float("nan"), float("inf"), -1, 2, 10**1000):
            with self.subTest(p=p), self.assertRaises(ValueError):
                summarize_validation(self.rows, threshold=p)
            with self.subTest(posterior=p), self.assertRaises(ValueError):
                summarize_validation([dataclasses.replace(self.rows[0], p_block=p)], threshold=.8)
        for rows in ([], [self.rows[0], self.rows[0]]):
            with self.assertRaises(ValueError):
                summarize_validation(rows, threshold=.8)

    def test_reference_and_group_id_required(self):
        for change in ({"reference_label": "DEFER"}, {"group_id": ""}, {"row_id": None}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                summarize_validation([dataclasses.replace(self.rows[0], **change)], threshold=.8)
