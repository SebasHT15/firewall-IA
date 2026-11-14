"""An analysis-only policy scores Model 2 but leaves every decision to V5."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "data_plane"))

import model2_decider as decider  # noqa: E402
import model2_policy as policy  # noqa: E402

ARTIFACT = ROOT / "model-output-model2/final/v4-d82-20261027T052308Z/baseline34.json"
SHA = "da6f6eb85c5a687bd038c6298baf59abdbe0489a80c8993b74a34dae7c60aa38"


class DeferOnlyTests(unittest.TestCase):
    def test_high_score_is_observed_but_never_blocks(self):
        common = {"schema": "model2-decision-policy/v1", "policy_id": "test",
                  "status": "LAB_EXPERIMENTAL", "feature_view": "baseline_34",
                  "model_artifact_sha256": SHA, "threshold": 0.9}
        active = decider.Model2Decider(str(ARTIFACT), expected_sha256=SHA,
                                       policy=policy.parse_policy(common))
        shadow = decider.Model2Decider(str(ARTIFACT), expected_sha256=SHA,
                                       policy=policy.parse_policy(dict(common, decision_mode="DEFER_ONLY")))
        request = "GET / HTTP/1.1\n"
        self.assertEqual(active.decide(canonical_outcome="ACCEPT", canonical_text=request).decision, "BLOCK")
        result = shadow.decide(canonical_outcome="ACCEPT", canonical_text=request)
        self.assertEqual(result.status, "OK")
        self.assertGreater(result.p_block, 0.9)
        self.assertEqual(result.decision, "DEFER")
        with patch.object(decider.M2, "score", return_value=1.0):
            saturated = shadow.decide(canonical_outcome="ACCEPT", canonical_text=request)
        self.assertEqual(saturated.p_block, 1.0)
        self.assertEqual(saturated.decision, "DEFER")
        self.assertEqual(shadow.decide(canonical_outcome="REJECT", canonical_text=None).decision, "DEFER")

    def test_selective_guard_defers_benign_edges_and_preserves_attack_candidate(self):
        guarded = policy.parse_policy({"schema": "model2-decision-policy/v1", "policy_id": "guarded-test",
                                       "status": "LAB_EXPERIMENTAL", "decision_mode": "GUARDED_ENFORCE",
                                       "guard_id": policy.SELECTIVE_GUARD,
                                       "feature_view": "baseline_34", "model_artifact_sha256": SHA,
                                       "threshold": 0.9})
        model = decider.Model2Decider(str(ARTIFACT), expected_sha256=SHA, policy=guarded)
        benign = ("GET / HTTP/1.1\n",
                  "GET /search?q=caf%C3%A9+y+t%C3%A9 HTTP/1.1\n",
                  "GET /search?q=2+%3C+3+and+5+%3E+4 HTTP/1.1\n",
                  "POST /checkout HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\n"
                  "address=Apt%20%234%2FB%2C%2010%20O%27Neil")
        for text in benign:
            with self.subTest(text=text):
                self.assertEqual(model.decide(canonical_outcome="ACCEPT", canonical_text=text).decision,
                                 "DEFER")
        attack = "GET /catalog?id=1%27+OR+1%3D1+--+&view=1 HTTP/1.1\n"
        self.assertEqual(model.decide(canonical_outcome="ACCEPT", canonical_text=attack).decision,
                         "BLOCK")


if __name__ == "__main__":
    unittest.main()
