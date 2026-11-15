"""Shared synthetic interface and snapshot regressions; never real data."""
import builtins
from collections import Counter
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.model2 import v5_fixture_integration as integration


class TestV5FixtureIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="model2-v5-integration-test-")
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        integration.build_fixture(self.directory)

    def test_shared_examples_fit_without_metadata_features(self):
        examples = integration.exchange.load_examples(str(self.directory))
        self.assertEqual({s: len(rows) for s, rows in examples.items()},
                         {"TRAIN": 232, "VALIDATION": 24})
        original = json.dumps(examples, sort_keys=True)
        encoder, scaler, validation, probabilities = integration.experiment._fit_fixture(
            integration._fixture_rows(examples))
        self.assertEqual(json.dumps(examples, sort_keys=True), original)
        self.assertEqual(scaler.n_samples_seen_, 232)
        self.assertEqual(len(probabilities), 24)
        self.assertTrue(all(row.split == "VALIDATION" for row in validation))
        for feature in encoder.get_feature_names_out():
            self.assertIn(feature.split("=")[0], integration.experiment.FEATURES)

    def test_consume_and_fit_open_each_allowed_file_once_and_no_protected_files(self):
        opened = []
        real_open = builtins.open
        def spy(path, *args, **kwargs):
            if isinstance(path, (str, Path)) and Path(path).is_relative_to(self.directory):
                opened.append(Path(path).name)
            return real_open(path, *args, **kwargs)
        with patch("builtins.open", side_effect=spy):
            examples = integration.exchange.load_examples(str(self.directory))
            integration.experiment._fit_fixture(integration._fixture_rows(examples))
        self.assertEqual(Counter(opened), Counter({
            "manifest.json": 1, "rows.TRAIN.jsonl": 1, "rows.TRAIN.meta.jsonl": 1,
            "rows.VALIDATION.jsonl": 1, "rows.VALIDATION.meta.jsonl": 1}))

    def test_disk_change_after_hash_does_not_replace_consumed_snapshot(self):
        reader = integration.exchange
        parse = reader.D.parse_split
        changed = False
        def change_disk_before_parse(rows_text, meta_text, split):
            nonlocal changed
            if split == "TRAIN" and not changed:
                metas = [json.loads(line) for line in meta_text.split("\n") if line.strip()]
                metas[0]["label_status"] = "PENDING"
                (self.directory / "rows.TRAIN.meta.jsonl").write_text(
                    "\n".join(json.dumps(m) for m in metas) + "\n", encoding="utf-8")
                changed = True
            return parse(rows_text, meta_text, split)
        with patch.object(reader.D, "parse_split", side_effect=change_disk_before_parse):
            examples = reader.load_examples(str(self.directory))
        self.assertTrue(changed)
        self.assertNotEqual(examples["TRAIN"][0]["label_status"], "PENDING")
        # The next load sees the modified bytes and refuses; no stale gate reuse.
        with self.assertRaisesRegex(reader.ExampleExchangeError, "ARTIFACT_HASH_MISMATCH"):
            reader.load_examples(str(self.directory))

    def test_failed_reader_never_reaches_learner(self):
        with patch.object(integration.exchange, "load_examples",
                          side_effect=integration.exchange.ExampleExchangeError("fixture refusal")), \
             patch.object(integration.experiment, "_fit_fixture") as fit:
            with self.assertRaises(integration.exchange.ExampleExchangeError):
                integration.run(demonstration_threshold=0.5)
            fit.assert_not_called()

    def test_report_preserves_fixture_scope_and_original_label_metadata(self):
        report = integration.run(demonstration_threshold=0.5)
        self.assertEqual(report["scope"], "FIXTURE_ONLY")
        self.assertEqual(report["dataset_metadata"]["TRAIN"]["rows"], 232)
        self.assertEqual(report["validation"]["records"], 24)
        self.assertEqual(report["validation"]["label_provenance"], "fixture_synthetic")
        self.assertFalse(report["operational_policy_approved"])
        self.assertFalse(report["weights_saved"])
        original = integration.exchange.load_examples(str(self.directory))
        for split, rows in original.items():
            self.assertEqual(report["dataset_metadata"][split]["label_status"],
                             dict(Counter(ex["label_status"] for ex in rows)))
            self.assertEqual(report["dataset_metadata"][split]["label_basis"],
                             dict(Counter(str(ex["label_basis"]) for ex in rows)))
        self.assertEqual(len(report["fixture_manifest_sha256"]), 64)

    def test_source_drift_invalidates_integration_report(self):
        with patch.object(integration, "source_hashes", side_effect=[{"a": "before"}, {"a": "after"}]):
            with self.assertRaisesRegex(RuntimeError, "source changed"):
                integration.run(demonstration_threshold=0.5)


if __name__ == "__main__":
    unittest.main()
