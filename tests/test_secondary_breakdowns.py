"""External Test v1 — SECONDARY breakdowns (protocol §4.3 / §10).

Recomputes the breakdowns from the frozen cases and the committed run records and checks
them against the committed report, so the published tables cannot drift from the evidence.
Also pins the properties that keep this a completion of pre-registered analysis rather than
error analysis. Needs the ML environment (the frozen D19 scorer imports torch); skipped
elsewhere.
"""

import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts", "external"))
REPORT = os.path.join(ROOT, "reports", "external", "external-v1-secondary-breakdowns",
                      "secondary_breakdowns.json")

try:
    import torch  # noqa: F401  the frozen scorer's module imports it
    import secondary_breakdowns as sb
except ImportError as exc:  # data-plane environment
    raise unittest.SkipTest(f"needs the ML environment: {exc}")


class TestSecondaryBreakdowns(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.computed = sb.compute()
        with open(REPORT, encoding="utf-8") as f:
            cls.committed = json.load(f)

    def test_committed_report_matches_a_fresh_computation(self):
        self.assertEqual(self.computed, self.committed)

    def test_only_the_four_section_10_dimensions(self):
        self.assertEqual(tuple(self.computed["breakdowns"]), sb.DIMENSIONS)
        self.assertEqual(sb.DIMENSIONS, ("client_profile", "host_type", "method", "body_type"))
        self.assertIn("route_family", self.computed["not_produced"])

    def test_headline_population_and_confusion_unchanged(self):
        self.assertEqual(self.computed["headline_n"], 400)
        self.assertEqual(self.computed["excluded_nondeterministic"], [])
        self.assertEqual(self.computed["headline_confusion"],
                         {"TP": 199, "FP": 68, "FN": 1, "TN": 132})

    def test_every_dimension_reconciles_with_the_headline(self):
        for dim, block in self.computed["breakdowns"].items():
            self.assertTrue(block["reconciles_with_headline"], dim)
            self.assertEqual(sum(v["n"] for v in block["values"].values()), 400, dim)

    def test_rates_carry_numerator_denominator_and_status(self):
        for block in self.computed["breakdowns"].values():
            for v in block["values"].values():
                for key, den_key in (("fpr", "allow_support"), ("recall_block", "block_support")):
                    r = v[key]
                    self.assertEqual(r["den"], v[den_key])
                    expected = ("NOT EVALUABLE" if r["den"] == 0 else
                                "OK" if r["den"] >= 30 else "INSUFFICIENT DATA")
                    self.assertEqual(r["evidence_status"], expected)

    def test_rule_of_three_only_on_zero_error_rates_and_beside_the_observed_value(self):
        for block in self.computed["breakdowns"].values():
            for v in block["values"].values():
                for key, errors in (("fpr", v["confusion"]["FP"]),
                                    ("recall_block", v["confusion"]["FN"])):
                    r, b = v[key], v[key]["rule_of_three"]
                    if r["den"] == 0 or errors != 0:
                        self.assertIsNone(b)
                        continue
                    # observed value untouched: 0% FPR / 100% recall stays as observed
                    self.assertEqual(r["pct"], 0.0 if key == "fpr" else 100.0)
                    self.assertAlmostEqual(b["upper_bound_pct"], min(100.0, 300.0 / r["den"]))
                    self.assertLessEqual(b["upper_bound_pct"], 100.0)
                    self.assertEqual(b["informative"], r["den"] > 3)
                    if key == "recall_block":
                        self.assertAlmostEqual(b["recall_lower_bound_pct"],
                                               100.0 - b["upper_bound_pct"])

    def test_labelled_secondary_and_rule_of_three_approximate(self):
        self.assertIn("SECONDARY", self.computed["label"])
        self.assertIn("not production prevalence", self.computed["label"])
        self.assertIn("approximate", self.computed["rule_of_three"])
        self.assertIn("not an exact confidence interval", self.computed["rule_of_three"])


if __name__ == "__main__":
    unittest.main()
