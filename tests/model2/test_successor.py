import hashlib
import unittest

from scripts.model2 import successor
from scripts.model2.identity_groups import connected_groups


class SuccessorCohortTest(unittest.TestCase):
    def test_short_route_cohort_is_canonical_and_split_disjoint(self):
        rows = successor.cohort({"TRAIN": [], "VALIDATION": []})
        hashes = {split: {r["text_sha256"] for r in items} for split, items in rows.items()}
        self.assertFalse(hashes["TRAIN"] & hashes["VALIDATION"])
        self.assertIn(hashlib.sha256(b"GET / HTTP/1.1\n").hexdigest(), hashes["TRAIN"])
        self.assertTrue(all("fwlab-notes" not in r["text"] and "/notes" not in r["text"]
                            for items in rows.values() for r in items))
        manifest = "0" * 64
        examples = {split: [successor.to_example(r, split, i, manifest)
                            for i, r in enumerate(items)] for split, items in rows.items()}
        self.assertEqual(len(connected_groups(examples)), sum(map(len, rows.values())))

    def test_parent_overlap_refused(self):
        root_hash = hashlib.sha256(b"GET / HTTP/1.1\n").hexdigest()
        with self.assertRaisesRegex(ValueError, "overlaps parent"):
            successor.cohort({"TRAIN": [{"text_sha256": root_hash}], "VALIDATION": []})


if __name__ == "__main__":
    unittest.main()
