"""hybrid_analyzer_v2 tests (Hybrid Architecture Phase 2B run-002, Issue #53, D54).

Checks the recovered V4 generator provenance, the D54 grouping (canonical request OR
feature vector OR generator group, transitively), the stratified VALIDATION carve-out,
zero TRAIN <-> VALIDATION leakage under all three relations, JWT kept out of fitting and
the INTERNAL TEST flags against TRAIN u VALIDATION.

Needs what the V4 generator needs: the ML environment (pandas), the local V4-clean files,
csic_database.csv and ~/PayloadsAllTheThings at the manifest commit. Skipped otherwise.
    python3.12 -m unittest tests.test_hybrid_analyzer_dataset_v2 -v
"""

import hashlib
import json
import os
import random
import subprocess
import sys
import unittest
from collections import defaultdict

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "data_plane"))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts", "dataset"))

import build_hybrid_analyzer_v2 as v2  # noqa: E402
import hybrid_contracts as contracts  # noqa: E402

try:
    import pandas  # noqa: F401  (the V4 generator reads the CSIC CSV with it)
    HAVE_PANDAS = True
except ImportError:
    HAVE_PANDAS = False
V4 = os.path.join(REPO_ROOT, "datasets", "v4_clean")
HAVE_INPUTS = (HAVE_PANDAS and os.path.exists(os.path.join(REPO_ROOT, "csic_database.csv"))
               and all(os.path.exists(os.path.join(V4, f"{s}.jsonl")) for s in ("train", "eval"))
               and os.path.isdir(os.path.expanduser("~/PayloadsAllTheThings")))


def _row(canon, vec, gid, label="BENIGN"):
    return {"_canon": canon, "_vec": vec, "_gid": gid, "_slice": None,
            "_category": None if label == "BENIGN" else label}


class TestGroupingRules(unittest.TestCase):
    """Pure functions; no data needed."""

    def test_relation_is_transitive_over_all_three_keys(self):
        rows = [_row("a", 1, "g1"), _row("b", 1, "g2"),   # a~b: same vector
                _row("c", 2, "g2"),                       # b~c: same generator group
                _row("c", 3, "g3"),                       # c~d: same canonical request
                _row("e", 4, "g4")]                       # unrelated
        members = v2.components(rows)
        self.assertEqual(len(members), 2)
        self.assertEqual({r["_group"] for r in rows[:4]}, {"a"})   # smallest canonical request
        self.assertEqual(rows[4]["_group"], "e")

    def test_generator_group_alone_links_rows(self):
        rows = [_row("x", 1, "same"), _row("y", 2, "same")]
        v2.components(rows)
        self.assertEqual(rows[0]["_group"], rows[1]["_group"])

    def test_stratified_split_is_deterministic_and_order_independent(self):
        rnd = random.Random(1)
        rows = [_row(f"r{i}", i, f"g{i // 3}", rnd.choice(["BENIGN", "xss", "ssrf"]))
                for i in range(600)]
        members = v2.components(rows)
        a, rep_a = v2.stratified_validation(members)
        shuffled = dict(sorted(members.items(), key=lambda kv: rnd.random()))
        b, rep_b = v2.stratified_validation(shuffled)
        self.assertEqual(a, b)
        self.assertEqual(rep_a, rep_b)
        for stratum, info in rep_a.items():
            if info["rows"] >= 100:
                self.assertAlmostEqual(info["validation_share"], 0.20, delta=0.03, msg=stratum)

    def test_whole_groups_only(self):
        rows = [_row(f"r{i}", i, f"g{i // 5}") for i in range(500)]
        members = v2.components(rows)
        chosen, _ = v2.stratified_validation(members)
        by_gid = defaultdict(set)
        for r in rows:
            by_gid[r["_gid"]].add(r["_group"] in chosen)
        self.assertTrue(all(len(v) == 1 for v in by_gid.values()))


@unittest.skipUnless(HAVE_INPUTS, "needs pandas, V4-clean, csic_database.csv and PayloadsAllTheThings")
class TestBuiltV2(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.data, cls.stats, cls.detail, _ = v2.build()
        cls.rows = [json.loads(line) for line in cls.data.decode("utf-8").splitlines()]
        cls.dev = [r for r in cls.rows if r["role"] in ("train", "validation")]

    def test_invariants_hold(self):
        v2.check(self.stats)                      # raises on any violation
        self.assertEqual(self.stats["train_validation_overlap"],
                         {"canonical_request": 0, "feature_vector": 0, "generator_family": 0,
                          "d54_group": 0})

    def test_deterministic_and_matches_manifest(self):
        again, _, _, _ = v2.build()
        self.assertEqual(again, self.data)
        manifest = os.path.join(REPO_ROOT, "datasets", "manifest_hybrid_analyzer_v2.json")
        if os.path.exists(manifest):
            self.assertEqual(hashlib.sha256(self.data).hexdigest(),
                             json.load(open(manifest))["artifact"]["sha256"])

    def test_split_reproducible_across_hash_seeds(self):
        code = ("import sys, hashlib; sys.path.insert(0, 'scripts/dataset'); "
                "import build_hybrid_analyzer_v2 as b; "
                "print(hashlib.sha256(b.build()[0]).hexdigest())")
        digest = subprocess.run([sys.executable, "-c", code], cwd=REPO_ROOT, check=True,
                                capture_output=True, text=True,
                                env={**os.environ, "PYTHONHASHSEED": "31"}).stdout.strip()
        self.assertEqual(digest, hashlib.sha256(self.data).hexdigest())

    def test_no_overlap_under_each_relation(self):
        for key in ("meta_canonical_request_sha256", "meta_feature_vector_sha256",
                    "meta_generator_group_id", "meta_group_id"):
            trn = {r[key] for r in self.dev if r["role"] == "train"}
            val = {r[key] for r in self.dev if r["role"] == "validation"}
            self.assertEqual(trn & val, set(), key)

    def test_generator_groups_never_span_v4_splits(self):
        splits = defaultdict(set)
        for r in self.rows:
            splits[r["meta_generator_group_id"]].add(r["meta_v4_split"])
        self.assertTrue(all(len(s) == 1 for s in splits.values()))

    def test_recovered_csic_groups_match_the_generator_definition(self):
        import parse_dataset_v4 as gen
        import analyze_analyzer_targets as design
        texts = {}
        for split in ("train", "eval"):
            with open(os.path.join(V4, f"{split}.jsonl"), encoding="utf-8") as f:
                texts[split] = [json.loads(line)["input"] for line in f]
        checked = 0
        for r in self.rows:
            src = r["meta_generator_source"]
            if src not in ("csic_benign", "csic_attack"):
                continue
            m, p, q, _, body = design.parse_text(texts[r["meta_v4_split"]][r["meta_v4_line"]])
            key = gen.csic_group_key({"method": m, "path": p, "query": q, "body": body})
            self.assertEqual(r["meta_generator_group_id"], gen.group_id(src, key))
            checked += 1
        self.assertEqual(checked, 7_273 + 3_906)

    def test_jwt_and_targets(self):
        for r in self.rows:
            if r["meta_v4_category"] == "JSON Web Token":
                self.assertEqual((r["slice"], r["target_category"]), ("unsupported_jwt", None))
            elif r["meta_v4_decision"] == "BLOCK":
                self.assertIn(r["target_category"], contracts.ANALYZER_CATEGORIES)
        v1_file = os.path.join(REPO_ROOT, "datasets", "hybrid_analyzer_v1", "hybrid_analyzer_v1.jsonl")
        if os.path.exists(v1_file):   # targets and features are unchanged from v1
            with open(v1_file, encoding="utf-8") as f:
                old = {(r["meta_v4_split"], r["meta_v4_line"]): r for r in map(json.loads, f)}
            for r in self.rows[::53]:
                o = old[(r["meta_v4_split"], r["meta_v4_line"])]
                for k in ("row_id", "features", "target_attack", "target_category", "slice"):
                    self.assertEqual(r[k], o[k], k)

    def test_test_flags_are_against_train_union_validation(self):
        used = [r for r in self.dev if r["slice"] is None]
        for key, flag in (("meta_feature_vector_sha256", "meta_feature_vector_in_train"),
                          ("meta_canonical_request_sha256", "meta_canonical_request_in_train"),
                          ("meta_generator_group_id", "meta_generator_family_in_train")):
            ref = {r[key] for r in used}
            for r in self.rows:
                if r["role"] == "internal_test":
                    self.assertEqual(r[flag], r[key] in ref, flag)
        full = [r for r in self.rows if r["role"] == "internal_test" and r["slice"] is None]
        self.assertEqual(len(full), 6_190)
        self.assertEqual(sum(not r["meta_feature_vector_in_train"] for r in full), 5_456)


if __name__ == "__main__":
    unittest.main()
