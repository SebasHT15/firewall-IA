"""Boundary test for the blocking concentration gate."""
import json
from pathlib import Path
import tempfile
import unittest

from scripts.dataset.v5_cs7_check import check


class CS7CheckTest(unittest.TestCase):
    def test_single_use_blocks_a_twenty_row_class(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for split in ("TRAIN", "VALIDATION", "INTERNAL_TEST"):
                with (root / f"rows.{split}.meta.jsonl").open("w") as fh:
                    for label in ("ALLOW", "BLOCK"):
                        for i in range(20):
                            entries = [["p", "one"]] if split == "VALIDATION" and label == "ALLOW" and i == 0 else []
                            fh.write(json.dumps({"disposition": "split", "label": label,
                                                 "value_entries": entries}) + "\n")
            result = check(root)
            self.assertFalse(result["blocking_pass"])
            self.assertEqual(result["cells"]["VALIDATION|ALLOW"]["max_element_share"], .05)
            self.assertEqual(result["cells"]["VALIDATION|ALLOW"]["status"], "BLOCK")
            prereg = root / "prereg.json"
            prereg.write_text(json.dumps({"ratified": {"acceptance_thresholds": {"C-S7": {
                "owner_ruling": "D76", "TRAIN": "BLOCK_ABOVE_0.03",
                "VALIDATION": "WARN_ONLY_REPORT_EXCESS",
                "INTERNAL_TEST": "WARN_ONLY_REPORT_EXCESS"}}}}))
            amended = check(root, prereg)
            self.assertTrue(amended["blocking_pass"])
            self.assertEqual(amended["cells"]["VALIDATION|ALLOW"]["raw_status"], "BLOCK")
            self.assertEqual(amended["cells"]["VALIDATION|ALLOW"]["status"], "WARN")


if __name__ == "__main__":
    unittest.main()
