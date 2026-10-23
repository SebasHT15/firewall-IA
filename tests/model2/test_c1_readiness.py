import dataclasses
import json
import subprocess
import sys
import unittest
from scripts.model2 import c1_readiness as audit


class TestCompatibility(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = {case.id: audit.compare(case) for case in audit.fixtures()}

    def test_common_requests_have_parity(self):
        for case in ("empty_get", "encoded_query", "form", "json", "utf8_body", "gzip_one"):
            with self.subTest(case=case):
                self.assertTrue(self.rows[case]["equal"], self.rows[case])

    def test_invalid_utf8_exposes_difference(self):
        row = self.rows["invalid_utf8"]
        self.assertTrue(row["compared"])
        self.assertFalse(row["equal"])
        self.assertIn("body_length", row["changed_fields"])
        self.assertIn("S-BODY-UTF8", row["canonical_signals"])

    def test_literal_escape_has_different_provenance_signal(self):
        self.assertNotIn("S-BODY-UTF8", self.rows["literal_escape"]["canonical_signals"])

    def test_gzip_members_expose_difference(self):
        self.assertTrue(self.rows["gzip_two"]["compared"])
        self.assertFalse(self.rows["gzip_two"]["equal"])
        self.assertIn("body_param_count", self.rows["gzip_two"]["changed_fields"])

    def test_rejected_requests_have_no_parity_claim(self):
        for case in ("duplicate_content_type", "gzip_invalid"):
            self.assertEqual(self.rows[case]["canonical_outcome"], "REJECT")
            self.assertFalse(self.rows[case]["compared"])
            self.assertIsNone(self.rows[case]["equal"])

    def test_host_user_agent_do_not_change_features(self):
        parts = audit.cr.RequestParts(b"GET", b"/synthetic")
        baseline = audit.rf.extract_features(audit.cr.canonicalize(parts, audit.cr.Limits(1024)).text)
        for case in audit.fixtures()[-2:]:
            self.assertTrue(self.rows[case.id]["equal"])
            changed = dataclasses.replace(parts, headers=case.headers)
            features = audit.rf.extract_features(audit.cr.canonicalize(changed, audit.cr.Limits(1024)).text)
            self.assertEqual(features, baseline)

    def test_report_does_not_serialize_request_text_or_values(self):
        serialized = json.dumps(list(self.rows.values()))
        for marker in ("O%27Brien", "example.invalid", "José", "fixture-a", "not-gzip"):
            self.assertNotIn(marker, serialized)
        for row in self.rows.values():
            self.assertNotIn("text", row)
            self.assertNotIn("features", row)

    def test_cli_refuses_dataset_arguments(self):
        result = subprocess.run([sys.executable, "-B", "-m", "scripts.model2.c1_readiness",
                                 "--dataset", "/synthetic/not-read"], cwd=audit.ROOT,
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("accepts no input", result.stderr)

    def test_dataset_read_guard(self):
        with self.assertRaises(PermissionError):
            audit.deny_dataset_reads("open", (str(audit.ROOT / "datasets" / "synthetic.jsonl"),))
