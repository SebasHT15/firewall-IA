"""Tests for the Model 2 decision policy parser (`data_plane/model2_policy.py`)."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "data_plane"))

import model2_policy as mp  # noqa: E402

GOOD = {
    "schema": "model2-decision-policy/v1",
    "policy_id": "p1",
    "status": "LAB_EXPERIMENTAL",
    "feature_view": "baseline_34",
    "model_artifact_sha256": "a" * 64,
    "threshold": 0.9,
}


class PolicyTests(unittest.TestCase):
    def test_valid_lab_policy(self):
        p = mp.parse_policy(dict(GOOD))
        self.assertEqual(p.policy_id, "p1")
        self.assertEqual(p.threshold, 0.9)
        self.assertEqual(len(p.sha256), 64)

    def test_binds_requires_both_view_and_sha(self):
        p = mp.parse_policy(dict(GOOD))
        self.assertTrue(p.binds(feature_view="baseline_34", artifact_sha256="a" * 64))
        self.assertFalse(p.binds(feature_view="baseline_34", artifact_sha256="b" * 64))
        self.assertFalse(p.binds(feature_view="target-path-neutralized/v1", artifact_sha256="a" * 64))

    def test_rejects_wrong_schema(self):
        d = dict(GOOD, schema="other")
        self.assertRaises(mp.PolicyError, mp.parse_policy, d)

    def test_rejects_unknown_keys(self):
        d = dict(GOOD, extra=1)
        self.assertRaises(mp.PolicyError, mp.parse_policy, d)

    def test_rejects_bad_feature_view(self):
        d = dict(GOOD, feature_view="nope")
        self.assertRaises(mp.PolicyError, mp.parse_policy, d)

    def test_rejects_threshold_out_of_range(self):
        self.assertRaises(mp.PolicyError, mp.parse_policy, dict(GOOD, threshold=1.5))
        self.assertRaises(mp.PolicyError, mp.parse_policy, dict(GOOD, threshold=-0.1))

    def test_rejects_bool_threshold(self):
        self.assertRaises(mp.PolicyError, mp.parse_policy, dict(GOOD, threshold=True))

    def test_rejects_bad_sha(self):
        self.assertRaises(mp.PolicyError, mp.parse_policy, dict(GOOD, model_artifact_sha256="xyz"))

    def test_approved_requires_approval_record(self):
        self.assertRaises(mp.PolicyError, mp.parse_policy, dict(GOOD, status="APPROVED"))
        ok = dict(GOOD, status="APPROVED",
                  approval={"approved_by": "owner", "date": "2026-10-26", "decision_ref": "Dxx"})
        p = mp.parse_policy(ok)
        self.assertEqual(p.status, "APPROVED")

    def test_lab_policies_on_disk_parse_and_bind(self):
        base = os.path.join(REPO, "reports/v5/hybrid/cascade-lab/policies")
        b = mp.load_policy(os.path.join(base, "model2_lab_baseline34.json"))
        self.assertEqual(b.feature_view, "baseline_34")
        self.assertEqual(b.status, "LAB_EXPERIMENTAL")
        self.assertEqual(b.model_artifact_sha256,
                         "da6f6eb85c5a687bd038c6298baf59abdbe0489a80c8993b74a34dae7c60aa38")
        a = mp.load_policy(os.path.join(base, "model2_lab_path-ablation32.json"))
        self.assertEqual(a.feature_view, "target-path-neutralized/v1")
        self.assertEqual(a.model_artifact_sha256,
                         "6fda4fa0d0bacd7573234e3b2ebdda23706af1a6312c3fe33e185c0237664d15")


if __name__ == "__main__":
    unittest.main()
