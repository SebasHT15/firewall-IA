from dataclasses import replace
import unittest

from scripts.model2.evaluation import ValidationScore
from scripts.model2.grouped_evaluation import summarize_grouped_validation as summarize


def row(i, group, label, score):
    return ValidationScore(str(i), group, "VALIDATION", label, "fixture_synthetic",
                           "all_traffic_fast_path_ineligible", score)


class TestGroupedEvaluation(unittest.TestCase):
    def setUp(self):
        self.rows = [row(0, "a", "ALLOW", .9), row(1, "a", "BLOCK", .9),
                     row(2, "b", "ALLOW", .1), row(3, "b", "BLOCK", .9),
                     row(4, "c", "ALLOW", .1), row(5, "c", "BLOCK", .1)]
        self.options = dict(threshold=.5, group_definition="synthetic_shared_pair",
                            confidence_level=.95, n_resamples=500, seed=9)

    def test_row_weighted_denominators_and_group_diagnostics(self):
        report = summarize(self.rows, **self.options)
        self.assertEqual(report["point"]["early_block_false_positive_rate"]["value"], 1 / 3)
        self.assertEqual(report["group_summary"]["benign_groups_with_false_block"], 1)
        self.assertFalse(report["operational_policy_approved"])
        ci = report["uncertainty"]["intervals"]["early_block_false_positive_rate"]
        self.assertEqual(ci["status"], "ESTIMATED_CONDITIONAL")
        self.assertLess(ci["interval"]["low"], ci["interval"]["high"])

    def test_replicating_rows_within_groups_does_not_invent_sample_size(self):
        base = summarize(self.rows, **self.options)
        expanded = [replace(r, row_id=f"{r.row_id}:{j}") for r in self.rows for j in range(5)]
        report = summarize(expanded, **self.options)
        self.assertEqual(base["uncertainty"], report["uncertainty"])
        self.assertEqual(report["group_summary"]["groups"], 3)
        self.assertEqual(report["point"]["records"], 30)

    def test_order_is_irrelevant_and_local_rng_is_reproducible(self):
        self.assertEqual(summarize(self.rows, **self.options),
                         summarize(list(reversed(self.rows)), **self.options))

    def test_zero_observed_errors_do_not_produce_zero_width_risk_bound(self):
        rows = [replace(r, p_block=.1 if r.reference_label == "ALLOW" else .9) for r in self.rows]
        ci = summarize(rows, **self.options)["uncertainty"]["intervals"]["early_block_false_positive_rate"]
        self.assertEqual(ci["status"], "DEGENERATE_RESAMPLES")
        self.assertIsNone(ci["interval"])

    def test_single_component_has_no_interval(self):
        report = summarize([replace(r, group_id="one") for r in self.rows], **self.options)
        for ci in report["uncertainty"]["intervals"].values():
            self.assertEqual(ci["status"], "INSUFFICIENT_CONTRIBUTING_GROUPS")
            self.assertIsNone(ci["interval"])

    def test_undefined_resamples_are_counted_not_discarded(self):
        rows = [row(0, "a", "ALLOW", .9), row(1, "b", "ALLOW", .1), row(2, "c", "BLOCK", .9)]
        ci = summarize(rows, **self.options)["uncertainty"]["intervals"]["early_block_false_positive_rate"]
        self.assertGreater(ci["undefined_resamples"], 0)
        self.assertEqual(ci["defined_resamples"] + ci["undefined_resamples"], 500)
        self.assertEqual(ci["status"], "UNDEFINED_RESAMPLES")
        self.assertIsNone(ci["interval"])

    def test_missing_class_has_no_denominator(self):
        rows = [r for r in self.rows if r.reference_label == "BLOCK"]
        ci = summarize(rows, **self.options)["uncertainty"]["intervals"]["early_block_false_positive_rate"]
        self.assertEqual(ci["status"], "NO_DENOMINATOR")

    def test_invalid_configuration_and_protected_roles_refused(self):
        for change in ({"confidence_level": True}, {"confidence_level": float("nan")},
                       {"n_resamples": True}, {"n_resamples": 1}, {"seed": -1},
                       {"group_definition": ""}, {"threshold": float("inf")}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                summarize(self.rows, **{**self.options, **change})
        with self.assertRaises(ValueError):
            summarize([replace(r, role="INTERNAL_TEST") for r in self.rows], **self.options)
