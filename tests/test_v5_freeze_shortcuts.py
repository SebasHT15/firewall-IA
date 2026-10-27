"""Inject shortcut defects into tiny datasets and require the gates to fire."""
import json
from pathlib import Path
import tempfile
import unittest

from scripts.dataset.v5_shortcut_checks import check as check_structure
from scripts.dataset.v5_token_purity import check as check_tokens
from scripts.dataset.v5_structure_probe import check as check_probe


class FreezeShortcutMutationTest(unittest.TestCase):
    def _dataset(self, root: Path, *, leak_carrier=False, leak_token=False):
        for split in ("TRAIN", "VALIDATION", "INTERNAL_TEST"):
            with (root / f"rows.{split}.meta.jsonl").open("w") as meta, \
                    (root / f"rows.{split}.jsonl").open("w") as data:
                for i in range(20):
                    for label in ("ALLOW", "BLOCK"):
                        row = {"label": label, "pair_id": f"{split}-{i}",
                               "payload_family_id": f"family-{split}" if label == "BLOCK" else None,
                               "carrier": "query" if leak_carrier and label == "BLOCK" else "form",
                               "method": "POST", "media_type": "form", "encoder_profile": "base",
                               "length_bin": 1, "field_names": [], "struct_cluster_id": "cluster",
                               "template_id": "template", "placement_mode": "replace",
                               "attacked_slot_role": "data", "attacked_slot_type": "free_string",
                               "leaf_spans": {"value": [7, 12]}}
                        text = "POST x=VALUE HTTP/1.1" + (" LEAKMARK" if leak_token and label == "BLOCK" else "")
                        meta.write(json.dumps(row) + "\n")
                        data.write(json.dumps({"text": text}) + "\n")

    def test_envelope_label_leak_blocks_s1_and_s2(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._dataset(root, leak_carrier=True)
            r = check_structure(root)
            self.assertFalse(r["blocking_pass_for_checks_run"])
            self.assertIn("carrier", r["splits"]["TRAIN"]["C-S1"]["global_block_features"])
            self.assertGreater(r["splits"]["TRAIN"]["C-S2"]["blocked_levels"], 0)
            self.assertGreater(r["splits"]["TRAIN"]["C-S6"]["blocked_levels"], 0)

    def test_unmasked_label_token_blocks_s3(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._dataset(root, leak_token=True)
            r = check_tokens(root)
            self.assertFalse(r["blocking_pass"])
            self.assertGreater(r["splits"]["TRAIN"]["block_tokens"], 0)

    def test_structure_probe_passes_clean_and_blocks_injected_label_feature(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._dataset(root)
            self.assertEqual(check_probe(root)["status"], "PASS")
            self._dataset(root, leak_carrier=True)
            result = check_probe(root)
            self.assertEqual(result["status"], "BLOCK")
            self.assertGreater(result["accuracy"], .65)


if __name__ == "__main__":
    unittest.main()
