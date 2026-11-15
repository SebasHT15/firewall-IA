"""Focused guards for proposed correction data and the training gate."""
from argparse import Namespace
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

from scripts.v52_correction import build_candidate as build
from scripts.v52_correction import train_candidate as train
from scripts.v52_correction import analyze_training_run as census


CALLBACK = "172.18.0.2"


class CorrectionContracts(unittest.TestCase):
    def test_every_generated_pair_matches_declared_application_policy(self):
        makers = {
            "ssrf": lambda t, i: build.fetch_pair(t, i, CALLBACK),
            "open_redirect": build.redirect_pair,
            "path_traversal": build.traversal_pair,
        }
        for family, maker in makers.items():
            for template in range(6):
                allow, block = maker(template, 1100 + template)
                for label, target in (("ALLOW", allow), ("BLOCK", block)):
                    with self.subTest(family=family, template=template, label=label):
                        row = build.make_row("TRAIN", family, template, 0, label, target,
                                             policy="test-policy")
                        build.check_policy(row, CALLBACK)

    def test_policy_rejects_false_benign_claims(self):
        cases = [
            ("ssrf", "/fetch?" + urlencode({"url": "http://172.18.0.2:9200/internal/token"})),
            ("ssrf", "/fetch?" + urlencode({"url": "http://assets.fwlab.test:9200/internal/token"})),
            ("open_redirect", "/go?" + urlencode({"next": "http://shop.fwlab.test:9200/private"})),
            ("open_redirect", "/go?" + urlencode({"next": "javascript:alert(1)"})),
            ("path_traversal", "/download?" + urlencode({"file": "../private/canary.txt"})),
            ("path_traversal", "/download?" + urlencode({"file": "docs/missing.txt"})),
        ]
        for family, target in cases:
            with self.subTest(family=family, target=target):
                row = build.make_row("TRAIN", family, 0, 0, "ALLOW", target,
                                     policy="test-policy")
                with self.assertRaisesRegex(ValueError, "policy mismatch"):
                    build.check_policy(row, CALLBACK)

    def test_training_gate_rejects_draft_before_private_rows(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "PACKAGE.PROPOSED.json"
            package.write_text("{}\n")
            draft = root / "owner-admission.DRAFT.json"
            draft.write_text('{"status":"DRAFT_PENDING_OWNER"}\n')
            args = Namespace(mode="train", package=package, authorization=draft,
                             report_dir=root / "report", run_id="blocked")
            with patch.object(train, "load", side_effect=AssertionError("rows opened")):
                with self.assertRaisesRegex(ValueError, "committed owner admission required"):
                    train.run(args)
            self.assertFalse(args.report_dir.exists())

    def test_training_census_keeps_invalids_as_errors(self):
        pairs = [
            ({"output": "BLOCK | Server-side request forgery attack detected."},
             {"status": "ok", "ended_with_eos": True,
              "generated": "BLOCK | Server-side request forgery attack detected."}),
            ({"output": "BLOCK | Open redirect payload detected."},
             {"status": "invalid", "ended_with_eos": False,
              "invalid_reason": "not_in_vocabulary", "generated": "BLOCK-ish"}),
            ({"output": build.ALLOW},
             {"status": "invalid", "ended_with_eos": False,
              "invalid_reason": "not_in_vocabulary", "generated": "ALLOW-ish"}),
            ({"output": build.ALLOW},
             {"status": "ok", "ended_with_eos": True, "generated": build.ALLOW}),
        ]
        report = census.measure(iter(pairs))
        self.assertEqual(report["n"], 4)
        self.assertEqual(report["principal_E5"], {"TP": 1, "TN": 1, "FP": 1, "FN": 1})
        self.assertEqual(report["status"]["invalid"], 2)
        self.assertEqual(report["block_reason"], {"eligible": 1, "exact": 1})


if __name__ == "__main__":
    unittest.main()
