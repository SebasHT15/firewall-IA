"""E5 aggregation tests for the cascade lab metrics (`scripts/cascade_lab/metrics.py`).

Two layers:
  1. Synthetic unit tests of `binary_confusion` — the E5 contract: invalids are
     counted as errors in BOTH classes in the PRINCIPAL view (BLOCK invalid -> FN,
     ALLOW invalid -> FP), excluded in the PARSEABLE_ONLY view, and split into
     content-boundary rejections vs genuine model-output errors.
  2. A cross-check that recomputes the kept trial JSONL (no inference) and matches
     the independently recomputed numbers for the baseline34 cascade and V5-only.
"""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "scripts", "cascade_lab"))

import metrics as M  # noqa: E402

PAIRED = os.path.join(REPO, "reports/v5/hybrid/cascade-lab/results/dev_paired_v1.jsonl")


class BinaryConfusionE5Tests(unittest.TestCase):
    def test_invalids_counted_as_errors_in_both_classes(self):
        # 1 TP, 1 TN, then one invalid in EACH class.
        items = [
            ("BLOCK", "BLOCK", None),
            ("ALLOW", "ALLOW", None),
            ("BLOCK", None, "no_eos"),        # BLOCK invalid -> principal FN
            ("ALLOW", None, "not_in_vocabulary"),  # ALLOW invalid -> principal FP
        ]
        conf = M.binary_confusion(items)
        p = conf["principal"]
        self.assertEqual((p["TP"], p["TN"], p["FP"], p["FN"], p["N"]), (1, 1, 1, 1, 4))
        # PARSEABLE_ONLY drops both invalids.
        v = conf["parseable_only"]
        self.assertEqual((v["TP"], v["TN"], v["FP"], v["FN"], v["N"]), (1, 1, 0, 0, 2))
        self.assertEqual(conf["invalid"]["total"], 2)

    def test_content_boundary_split_from_model_errors(self):
        items = [
            ("BLOCK", None, "content_rejected"),     # content-boundary (runtime)
            ("BLOCK", None, "no_eos"),               # genuine model error
            ("BLOCK", None, "not_in_vocabulary"),    # genuine model error
        ]
        inv = M.binary_confusion(items)["invalid"]
        self.assertEqual(inv["total"], 3)
        self.assertEqual(inv["content_boundary_rejections"], 1)
        self.assertEqual(inv["model_output_errors"], 2)
        self.assertEqual(inv["other"], 0)
        # All three are still errors (BLOCK-labelled invalids) in PRINCIPAL.
        p = M.binary_confusion(items)["principal"]
        self.assertEqual((p["FN"], p["TP"]), (3, 0))

    def test_parseable_only_matches_principal_when_no_invalids(self):
        items = [("BLOCK", "BLOCK", None), ("ALLOW", "BLOCK", None),
                 ("BLOCK", "ALLOW", None), ("ALLOW", "ALLOW", None)]
        conf = M.binary_confusion(items)
        self.assertEqual(conf["principal"]["N"], conf["parseable_only"]["N"])
        self.assertEqual(conf["invalid"]["total"], 0)


class KeptTrialCrossCheckTests(unittest.TestCase):
    """Recompute from the kept JSONL and match the independent recomputation."""

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(PAIRED):
            raise unittest.SkipTest("kept trial JSONL not present")
        with open(PAIRED, encoding="utf-8") as fh:
            rows = [json.loads(l) for l in fh if l.strip()]
        cls.accept = [r for r in rows if r.get("canonical_outcome") == "ACCEPT"]

    def test_population(self):
        labels = [r["label"] for r in self.accept]
        self.assertEqual(len(self.accept), 578)
        self.assertEqual(labels.count("ALLOW"), 300)
        self.assertEqual(labels.count("BLOCK"), 278)

    def test_cascade_baseline34_principal(self):
        items = [(r["label"],) + M.cascade_cell(r, "model2_baseline34")[:2] for r in self.accept]
        p = M.binary_confusion(items)["principal"]
        self.assertEqual((p["TP"], p["TN"], p["FP"], p["FN"]), (199, 289, 11, 79))
        self.assertAlmostEqual(p["recall_block"], 0.7158, places=4)
        self.assertAlmostEqual(p["fpr"], 0.0367, places=4)
        self.assertAlmostEqual(p["f1_block"], 0.8156, places=4)

    def test_v5_only_principal_recall(self):
        items = [(r["label"],) + M.v5_cell(r) for r in self.accept]
        conf = M.binary_confusion(items)
        self.assertAlmostEqual(conf["principal"]["recall_block"], 0.6655, places=4)
        # All four invalid V5 outputs are present, split 2 content-boundary / 2 model.
        self.assertEqual(conf["invalid"]["total"], 4)
        self.assertEqual(conf["invalid"]["content_boundary_rejections"], 2)
        self.assertEqual(conf["invalid"]["model_output_errors"], 2)

    def test_early_block_call_avoidance_counterfactual(self):
        early = sum(1 for r in self.accept
                    if (r.get("model2_baseline34") or {}).get("decision") == "BLOCK")
        self.assertEqual(early, 125)
        self.assertAlmostEqual(early / len(self.accept), 0.2163, places=4)


if __name__ == "__main__":
    unittest.main()
