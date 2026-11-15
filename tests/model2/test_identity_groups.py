from copy import deepcopy
import unittest
from scripts.model2.identity_groups import connected_groups


def example(index, split="TRAIN"):
    prefix = f"{split}-{index}"
    return {"row_index": index, "split": split, "identities": {
        "text_sha256": prefix + "text", "pair_id": prefix + "pair",
        "struct_cluster_id": prefix + "cluster", "template_id": prefix + "template",
        "payload_family_id": None, "payload_record_id": None, "value_entries": []}}


class TestIdentityGroups(unittest.TestCase):
    def setUp(self):
        self.examples = {"TRAIN": [example(i) for i in range(4)],
                         "VALIDATION": [example(0, "VALIDATION")]}

    def test_transitive_links_across_different_dimensions(self):
        a, b, c, d = self.examples["TRAIN"]
        b["identities"]["pair_id"] = a["identities"]["pair_id"]
        b["identities"]["payload_family_id"] = c["identities"]["payload_family_id"] = "family"
        groups = connected_groups(self.examples)
        self.assertEqual(groups[("TRAIN", 0)], groups[("TRAIN", 2)])
        self.assertNotEqual(groups[("TRAIN", 0)], groups[("TRAIN", 3)])

    def test_value_entry_pair_is_atomic_and_dimension_is_namespaced(self):
        a, b, c, d = self.examples["TRAIN"]
        a["identities"]["value_entries"] = [["pool-a", "value"]]
        b["identities"]["value_entries"] = [["pool-b", "value"]]
        c["identities"]["value_entries"] = [["pool-a", "value"]]
        d["identities"]["pair_id"] = a["identities"]["template_id"]
        groups = connected_groups(self.examples)
        self.assertEqual(groups[("TRAIN", 0)], groups[("TRAIN", 2)])
        self.assertEqual(len(set(groups.values())), 4)

    def test_overlap_is_refused_before_fitting(self):
        self.examples["VALIDATION"][0]["identities"]["template_id"] = self.examples["TRAIN"][0]["identities"]["template_id"]
        with self.assertRaisesRegex(ValueError, "crosses"):
            connected_groups(self.examples)

    def test_order_independent_and_does_not_mutate_metadata(self):
        before = deepcopy(self.examples)
        result = connected_groups(self.examples)
        self.assertEqual(self.examples, before)
        self.examples["TRAIN"].reverse()
        self.assertEqual(result, connected_groups(self.examples))

    def test_missing_schema_bad_entry_and_duplicate_index_refused(self):
        for kind in ("missing", "entry", "duplicate", "role"):
            rows = deepcopy(self.examples)
            if kind == "missing":
                del rows["TRAIN"][0]["identities"]["pair_id"]
            elif kind == "entry":
                rows["TRAIN"][0]["identities"]["value_entries"] = [["pool"]]
            elif kind == "duplicate":
                rows["TRAIN"].append(rows["TRAIN"][0])
            else:
                rows["INTERNAL_TEST"] = []
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                connected_groups(rows)
