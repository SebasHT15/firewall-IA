"""hybrid_analyzer_v1 builder tests (Hybrid Architecture Phase 2B, Issue #53).

Checks that the builder reproduces the frozen Phase 2A design (D47-D51): determinism,
the grouped VALIDATION split, no leakage across TRAIN / VALIDATION, the category mapping,
JWT kept out of fitting, and the INTERNAL TEST flags.

Standard library only. Needs the local V4-clean files (not distributed; see
docs/data_sources.md); skipped without them.
    python3.12 -m unittest tests.test_hybrid_analyzer_dataset -v
"""

import dataclasses
import hashlib
import json
import os
import subprocess
import sys
import unittest
from collections import defaultdict

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "data_plane"))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts", "dataset"))

import build_hybrid_analyzer_v1 as builder  # noqa: E402
import hybrid_contracts as contracts  # noqa: E402
import request_features as rf  # noqa: E402

V4 = os.path.join(REPO_ROOT, "datasets", "v4_clean")
HAVE_V4 = all(os.path.exists(os.path.join(V4, f"{s}.jsonl")) for s in ("train", "eval"))


class TestFrozenRules(unittest.TestCase):
    """Pure rules; no dataset needed."""

    def test_validation_bucket_is_the_d51_formula(self):
        for key in ("get /a?x=1\n\n", "post /login?\napplication/json\n{}", ""):
            h = hashlib.sha256(f"hybrid-analyzer-v1-validation\x00{key}".encode()).digest()
            expected = int.from_bytes(h[:8], "big") % 10_000 < 2_000
            self.assertEqual(builder.design.in_validation(key), expected)

    def test_validation_bucket_independent_of_hash_seed(self):
        keys = [f"key-{i}" for i in range(200)]
        code = ("import sys; sys.path.insert(0, 'scripts/dataset'); "
                "import analyze_analyzer_targets as d; "
                f"print(''.join('1' if d.in_validation(k) else '0' for k in {keys!r}))")
        outs = {subprocess.run([sys.executable, "-c", code], cwd=REPO_ROOT, check=True,
                               capture_output=True, text=True,
                               env={**os.environ, "PYTHONHASHSEED": seed}).stdout
                for seed in ("0", "1", "4242")}
        self.assertEqual(len(outs), 1)
        self.assertIn("1", outs.pop())   # ~20% of 200 keys

    def test_category_mapping_is_d47_d49(self):
        t = builder.design.analyzer_target
        self.assertEqual(t("BENIGN"), (0, None, None))
        self.assertEqual(t("Directory Traversal"), (1, "path_file_access", None))
        self.assertEqual(t("File Inclusion"), (1, "path_file_access", None))
        self.assertEqual(t("SQL Injection"), (1, "sql_injection", None))
        self.assertEqual(t("XSS Injection"), (1, "xss", None))
        self.assertEqual(t("Command Injection"), (1, "command_injection", None))
        self.assertEqual(t("Server Side Template Injection"), (1, "ssti", None))
        self.assertEqual(t("Open Redirect"), (1, "open_redirect", None))
        self.assertEqual(t("Server Side Request Forgery"), (1, "ssrf", None))
        for residual in ("CRLF Injection", "XXE Injection", "NoSQL Injection", "LDAP Injection",
                         "GraphQL Injection", "Cross-Site Request Forgery", "XPath Injection",
                         "HTTP Parameter Pollution", "Insecure Deserialization",
                         "Request Smuggling"):
            self.assertEqual(t(residual), (1, "other_attack", None), residual)
        self.assertEqual(t("JSON Web Token"), (1, None, "unsupported_jwt"))

    def test_mapping_targets_are_exactly_the_contract_vocabulary(self):
        targets = set(builder.design.ANALYZER_CATEGORY.values()) | {"other_attack"}
        self.assertEqual(targets, set(contracts.ANALYZER_CATEGORIES))

    def test_feature_fields_are_requestfeatures_v2_in_order(self):
        fields = [f.name for f in dataclasses.fields(rf.RequestFeatures)][:-1]
        self.assertEqual(list(builder.FEATURE_FIELDS), fields)
        self.assertEqual(len(builder.FEATURE_FIELDS), 34)
        self.assertEqual(rf.FEATURE_SCHEMA_VERSION, "request-features/v2")


@unittest.skipUnless(HAVE_V4, "datasets/v4_clean not present (regenerate it locally)")
class TestBuiltDataset(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.data, cls.stats, cls.detail, _ = builder.build()
        cls.rows = [json.loads(line) for line in cls.data.decode("utf-8").splitlines()]
        cls.texts = {}
        for split in ("train", "eval"):
            with open(os.path.join(V4, f"{split}.jsonl"), encoding="utf-8") as f:
                cls.texts[split] = [json.loads(line) for line in f]

    def test_reproduces_the_frozen_phase2a_counts(self):
        self.assertEqual(self.stats, builder.EXPECTED)
        self.assertEqual(len(self.rows), 31_340)

    def test_deterministic_in_process_and_across_hash_seeds(self):
        again, _, _, _ = builder.build()
        self.assertEqual(again, self.data)
        code = ("import sys, hashlib; sys.path.insert(0, 'scripts/dataset'); "
                "import build_hybrid_analyzer_v1 as b; "
                "print(hashlib.sha256(b.build()[0]).hexdigest())")
        digest = subprocess.run([sys.executable, "-c", code], cwd=REPO_ROOT, check=True,
                                capture_output=True, text=True,
                                env={**os.environ, "PYTHONHASHSEED": "97"}).stdout.strip()
        self.assertEqual(digest, hashlib.sha256(self.data).hexdigest())

    def test_rows_join_back_to_v4_and_carry_no_request_text(self):
        for r in self.rows[:: 97]:
            src = self.texts[r["meta_v4_split"]][r["meta_v4_line"]]
            self.assertEqual(r["row_id"], hashlib.sha256(src["input"].encode()).hexdigest())
            expected = dataclasses.asdict(rf.extract_features(src["input"]))
            del expected["schema_version"]
            self.assertEqual(r["features"], expected)
            self.assertNotIn(src["input"], json.dumps(r, ensure_ascii=False))

    def test_only_features_are_model_input(self):
        allowed = {"row_id", "role", "slice", "features", "target_attack", "target_category"}
        for r in self.rows[:50]:
            self.assertEqual(list(r["features"]), list(builder.FEATURE_FIELDS))
            self.assertTrue(all(k in allowed or k.startswith("meta_") for k in r))

    def test_roles_follow_the_v4_split(self):
        for r in self.rows:
            if r["meta_v4_split"] == "train":
                self.assertIn(r["role"], ("train", "validation"))
            else:
                self.assertEqual(r["role"], "internal_test")

    def test_no_train_validation_overlap(self):
        keys = defaultdict(lambda: defaultdict(set))
        for r in self.rows:
            if r["role"] in ("train", "validation"):
                for k in ("meta_feature_vector_sha256", "meta_canonical_request_sha256",
                          "meta_group_id"):
                    keys[k][r["role"]].add(r[k])
        for k, by_role in keys.items():
            self.assertEqual(by_role["train"] & by_role["validation"], set(), k)

    def test_validation_assignment_is_by_group(self):
        roles = defaultdict(set)
        for r in self.rows:
            if r["meta_group_id"] is not None:
                roles[r["meta_group_id"]].add(r["role"])
        self.assertTrue(all(len(v) == 1 for v in roles.values()))

    def test_targets_and_jwt(self):
        for r in self.rows:
            if r["meta_v4_category"] == "JSON Web Token":
                self.assertEqual((r["slice"], r["target_category"]), ("unsupported_jwt", None))
            elif r["meta_v4_decision"] == "ALLOW":
                self.assertEqual((r["target_attack"], r["target_category"], r["slice"]), (0, None, None))
            else:
                self.assertEqual(r["target_attack"], 1)
                self.assertIn(r["target_category"], contracts.ANALYZER_CATEGORIES)
                self.assertIsNone(r["slice"])
        self.assertEqual(self.detail["unsupported_jwt_rows_by_role"],
                         {"train": 82, "validation": 13, "internal_test": 16})

    def test_test_flags_are_against_train_union_validation_without_jwt(self):
        used = [r for r in self.rows if r["role"] in ("train", "validation") and r["slice"] is None]
        vec = {r["meta_feature_vector_sha256"] for r in used}
        canon = {r["meta_canonical_request_sha256"] for r in used}
        for r in self.rows:
            if r["role"] == "internal_test":
                self.assertEqual(r["meta_feature_vector_in_train"], r["meta_feature_vector_sha256"] in vec)
                self.assertEqual(r["meta_canonical_request_in_train"],
                                 r["meta_canonical_request_sha256"] in canon)
            else:
                self.assertIsNone(r["meta_feature_vector_in_train"])


if __name__ == "__main__":
    unittest.main()
