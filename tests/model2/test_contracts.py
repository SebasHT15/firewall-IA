import dataclasses
import unittest
from scripts.model2 import contracts as c


class TestBoundary(unittest.TestCase):
    def setUp(self):
        self.features = c.rf.extract_features("GET /synthetic HTTP/1.1\n")
        self.evidence = c.C1Evidence(self.features, c.REPRESENTATION, "ACCEPT")
        self.decider = c.NoModelDecider()

    def test_valid_evidence_without_model_defers_without_posterior(self):
        result = self.decider.decide(self.evidence)
        self.assertIs(result.status, c.Status.MODEL_UNAVAILABLE)
        self.assertIsNone(result.decision)
        self.assertIsNone(result.p_block)
        self.assertIs(result.next_action, c.Decision.DEFER)

    def test_missing_evidence_is_explicit(self):
        for evidence in (None, dataclasses.replace(self.evidence, features=None)):
            self.assertIs(self.decider.decide(evidence).status, c.Status.EVIDENCE_MISSING)

    def test_d1_cannot_enter_canonical_interface(self):
        result = self.decider.decide(dataclasses.replace(self.evidence, representation="D1"))
        self.assertIs(result.reason, c.Reason.REPRESENTATION_MISMATCH)
        self.assertIs(result.next_action, c.Decision.DEFER)

    def test_non_accept_cannot_enter(self):
        for outcome in ("REJECT", "UNSUPPORTED", "", None):
            with self.subTest(outcome=outcome):
                result = self.decider.decide(dataclasses.replace(self.evidence, canonical_outcome=outcome))
                self.assertIs(result.reason, c.Reason.CANONICAL_NOT_ACCEPTED)

    def test_corrupt_evidence_is_rejected(self):
        changes = ({"symbol_count": -1}, {"symbol_count": True}, {"symbol_ratio": float("nan")},
                   {"symbol_ratio": float("inf")}, {"symbol_ratio": 1.1}, {"symbol_ratio": True},
                   {"has_body": 1}, {"body_format": "invented"}, {"schema_version": "future"},
                   {"entropy_bits_per_char": 10**1000})
        for change in changes:
            with self.subTest(change=change):
                features = dataclasses.replace(self.features, **change)
                evidence = dataclasses.replace(self.evidence, features=features)
                self.assertIs(self.decider.decide(evidence).reason, c.Reason.C1_INVALID)

    def test_foreign_object_defers(self):
        self.assertIs(self.decider.decide({}).next_action, c.Decision.DEFER)

    def test_allow_is_not_an_output(self):
        with self.assertRaises(ValueError):
            c.Decision("ALLOW")
        with self.assertRaises(ValueError):
            c.Model2Result(c.Status.OK, c.Reason.SYNTHETIC_RESULT, "ALLOW", 1.0)

    def test_failed_stage_cannot_smuggle_a_block_or_probability(self):
        for kwargs in ({"decision": c.Decision.BLOCK}, {"p_block": 0.9}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                c.Model2Result(c.Status.MODEL_UNAVAILABLE, c.Reason.MODEL_NOT_TRAINED, **kwargs)

    def test_invalid_probability_is_not_clamped(self):
        for p in (None, True, float("nan"), float("inf"), -0.1, 1.1, "0.9", 10**1000):
            with self.subTest(p=p), self.assertRaises(ValueError):
                c.Model2Result(c.Status.OK, c.Reason.SYNTHETIC_RESULT, c.Decision.BLOCK, p)

    def test_synthetic_block_and_defer_are_distinct(self):
        for decision in c.Decision:
            result = c.Model2Result(c.Status.OK, c.Reason.SYNTHETIC_RESULT, decision, 0.8)
            self.assertIs(result.next_action, decision)

    def test_invalid_status_reason_is_rejected(self):
        for status, reason in (("OK", c.Reason.SYNTHETIC_RESULT),
                               (c.Status.MODEL_UNAVAILABLE, "free text"),
                               (c.Status.EVIDENCE_INVALID, c.Reason.MODEL_NOT_TRAINED)):
            with self.subTest(status=status, reason=reason), self.assertRaises(ValueError):
                c.Model2Result(status, reason)
