"""Tests for scripts/dataset/v5_dataset_checks.py (Issue #64, Workstream B).

Synthetic, in-memory or tempdir inputs only; standard library only; no model, no real dataset.

    python3 -m unittest tests.test_v5_dataset_checks -v
"""

import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts", "dataset"))

import parse_dataset_v4  # noqa: E402
import v5_dataset_checks as chk  # noqa: E402


def req(value, path="/a"):
    return f"GET {path}?q={value} HTTP/1.1\nHost: h.example"


def write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


class Reuse(unittest.TestCase):
    def test_canonical_key_is_the_generators_function(self):
        self.assertIs(chk.canonical_key, parse_dataset_v4.canonical_key)


class DuplicateTests(unittest.TestCase):
    def test_clean_splits_pass(self):
        r = chk.find_duplicates({"train": [{"input": req("a")}], "val": [{"input": req("b")}]})
        self.assertTrue(r["ok"])
        self.assertEqual(r["across"]["train|val"]["exact_shared_keys"], 0)

    def test_exact_cross_split_fails(self):
        r = chk.find_duplicates({"train": [{"input": req("a")}, {"input": req("x")}],
                                 "val": [{"input": req("a")}]})
        self.assertFalse(r["ok"])
        a = r["across"]["train|val"]
        self.assertEqual((a["exact_shared_keys"], a["canonical_shared_keys"]), (1, 1))
        self.assertEqual(a["examples"], [{"train": 0, "val": 0}])

    def test_canonical_only_cross_split_fails(self):
        # %27 vs ' and case differ textually, identical canonical identity (D16)
        r = chk.find_duplicates({"train": [{"input": req("O%27Neil")}],
                                 "val": [{"input": req("o'neil")}]})
        a = r["across"]["train|val"]
        self.assertFalse(r["ok"])
        self.assertEqual((a["exact_shared_keys"], a["canonical_shared_keys"]), (0, 1))

    def test_within_split_duplicates_reported_and_gated_only_on_request(self):
        splits = {"train": [{"input": req("a")}, {"input": req("a")}, {"input": req("A")}],
                  "val": [{"input": req("z")}]}
        r = chk.find_duplicates(splits)
        self.assertTrue(r["ok"])
        self.assertEqual(r["within"]["train"],
                         {"rows": 3, "exact_duplicate_rows": 1, "canonical_duplicate_rows": 2})
        self.assertFalse(chk.find_duplicates(splits, fail_on_within_exact=True)["ok"])

    def test_three_splits_pairwise_and_custom_field(self):
        splits = {"a": [{"t": "x1"}], "b": [{"t": "x2"}], "c": [{"t": "X1"}]}
        r = chk.find_duplicates(splits, text_field="t")
        self.assertEqual(set(r["across"]), {"a|b", "a|c", "b|c"})
        self.assertEqual(r["across"]["a|c"]["canonical_shared_keys"], 1)
        self.assertEqual(r["across"]["a|c"]["exact_shared_keys"], 0)

    def test_missing_text_field_is_an_error(self):
        with self.assertRaises(ValueError):
            chk.find_duplicates({"a": [{"x": 1}], "b": [{"input": "y"}]})


class GroupTests(unittest.TestCase):
    def rows(self, *vals, field="template_id"):
        return [{field: v} for v in vals]

    def test_disjoint_passes(self):
        r = chk.check_group_disjointness({"tr": self.rows("t1", "t2"), "va": self.rows("t3")},
                                         ["template_id"])
        self.assertTrue(r["ok"])
        self.assertEqual(r["keys"]["template_id"]["distinct_values"], {"tr": 2, "va": 1})

    def test_overlap_fails_with_example(self):
        r = chk.check_group_disjointness({"tr": self.rows("t1", "t2"), "va": self.rows("t2")},
                                         ["template_id"])
        self.assertFalse(r["ok"])
        i = r["keys"]["template_id"]["intersections"]["tr|va"]
        self.assertEqual((i["count"], i["examples"]), (1, ["t2"]))

    def test_missing_field_fails(self):
        r = chk.check_group_disjointness({"tr": [{"template_id": "a"}, {}],
                                          "va": [{"template_id": None}]}, ["template_id"])
        self.assertFalse(r["ok"])
        self.assertEqual(r["keys"]["template_id"]["missing_rows"], {"tr": 1, "va": 1})

    def test_composite_key_disjoint_when_only_the_pair_differs(self):
        tr = [{"provider": "p1", "tpl": "t1"}]
        va = [{"provider": "p1", "tpl": "t2"}]
        self.assertTrue(chk.check_group_disjointness({"tr": tr, "va": va},
                                                     [("provider", "tpl")])["ok"])
        self.assertFalse(chk.check_group_disjointness({"tr": tr, "va": va}, ["provider"])["ok"])

    def test_several_keys_one_failure_fails_all(self):
        tr = [{"p": "p1", "f": "f1"}]
        va = [{"p": "p2", "f": "f1"}]
        r = chk.check_group_disjointness({"tr": tr, "va": va}, ["p", "f"])
        self.assertFalse(r["ok"])
        self.assertTrue(r["keys"]["p"]["ok"])
        self.assertFalse(r["keys"]["f"]["ok"])

    def test_unhashable_values_are_supported(self):
        a = [{"ids": [1, 2]}]
        b = [{"ids": [1, 2]}]
        self.assertFalse(chk.check_group_disjointness({"a": a, "b": b}, ["ids"])["ok"])


class LabelTests(unittest.TestCase):
    def test_consistent_labels_pass(self):
        r = chk.check_label_consistency({
            "tr": [{"input": req("a"), "label": "ALLOW"}, {"input": req("b"), "label": "BLOCK"}],
            "va": [{"input": req("a"), "label": "ALLOW"}]})
        self.assertTrue(r["ok"])
        self.assertEqual((r["rows"], r["distinct_canonical_keys"]), (3, 2))

    def test_canonical_conflict_across_splits(self):
        r = chk.check_label_consistency({
            "tr": [{"input": req("O%27Neil"), "label": "ALLOW"}],
            "va": [{"input": req("o'neil"), "label": "BLOCK"}]})
        self.assertFalse(r["ok"])
        self.assertEqual((r["canonical_conflicts"], r["exact_conflicts"],
                          r["conflicts_spanning_splits"]), (1, 0, 1))
        self.assertEqual(r["examples"][0]["ALLOW"], [{"split": "tr", "row": 0}])

    def test_exact_conflict_within_one_split(self):
        r = chk.check_label_consistency({
            "tr": [{"input": req("a"), "label": "ALLOW"}, {"input": req("a"), "label": "BLOCK"}]})
        self.assertFalse(r["ok"])
        self.assertEqual((r["canonical_conflicts"], r["exact_conflicts"],
                          r["conflicts_spanning_splits"]), (1, 1, 0))

    def test_label_fn_for_v4_style_outputs(self):
        import check_dataset
        r = chk.check_label_consistency(
            {"tr": [{"input": req("a"), "output": "ALLOW | fine"}],
             "va": [{"input": req("a"), "output": "BLOCK | sqli"}]},
            label_fn=check_dataset.label_of)
        self.assertFalse(r["ok"])

    def test_missing_label_is_an_error(self):
        with self.assertRaises(ValueError):
            chk.check_label_consistency({"tr": [{"input": req("a")}]})


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = self.tmp.name
        self.f1 = os.path.join(self.d, "train.jsonl")
        self.f2 = os.path.join(self.d, "val.jsonl")
        write_jsonl(self.f1, [{"input": "a"}])
        write_jsonl(self.f2, [{"input": "b"}, {"input": "c"}])

    def v5(self):
        return {"artifacts": [
            {"path": "train.jsonl", "sha256": sha(self.f1), "bytes": os.path.getsize(self.f1)},
            {"path": "val.jsonl", "sha256": sha(self.f2)}]}

    def status(self, r):
        return {a["name"]: a["status"] for a in r["artifacts"]}

    def test_v5_layout_ok_from_path(self):
        mp = os.path.join(self.d, "manifest.json")
        with open(mp, "w") as f:
            json.dump(self.v5(), f)
        r = chk.verify_manifest(mp, base_dir=self.d)
        self.assertTrue(r["ok"])
        self.assertEqual(self.status(r), {"train.jsonl": "ok", "val.jsonl": "ok"})

    def test_hybrid_layout(self):
        m = {"artifact": {"path": "train.jsonl", "sha256": sha(self.f1)}}
        self.assertTrue(chk.verify_manifest(m, base_dir=self.d)["ok"])

    def test_v4_layout_needs_explicit_paths(self):
        m = {"artifact_sha256": {"train": sha(self.f1), "eval": sha(self.f2)},
             "artifact_bytes": {"train": os.path.getsize(self.f1), "eval": os.path.getsize(self.f2)}}
        r = chk.verify_manifest(m, base_dir=self.d)
        self.assertFalse(r["ok"])
        self.assertEqual(self.status(r), {"train": "unresolved", "eval": "unresolved"})
        r = chk.verify_manifest(m, base_dir=self.d, paths={"train": self.f1, "eval": self.f2})
        self.assertTrue(r["ok"])

    def test_sha_mismatch_after_edit(self):
        m = self.v5()
        write_jsonl(self.f2, [{"input": "tampered"}])
        r = chk.verify_manifest(m, base_dir=self.d)
        self.assertFalse(r["ok"])
        self.assertEqual(self.status(r), {"train.jsonl": "ok", "val.jsonl": "sha_mismatch"})

    def test_bytes_mismatch_missing_malformed_unsafe(self):
        m = self.v5()
        m["artifacts"][0]["bytes"] += 1
        m["artifacts"].append({"path": "gone.jsonl", "sha256": "0" * 64})
        m["artifacts"].append({"path": "bad.jsonl", "sha256": "xyz"})
        m["artifacts"].append({"path": "../outside.jsonl", "sha256": "0" * 64})
        r = chk.verify_manifest(m, base_dir=self.d)
        self.assertEqual(self.status(r), {"train.jsonl": "bytes_mismatch", "val.jsonl": "ok",
                                          "gone.jsonl": "missing", "bad.jsonl": "malformed",
                                          "../outside.jsonl": "unsafe_path"})
        self.assertFalse(r["ok"])

    def test_manifest_without_artifacts_is_an_error(self):
        with self.assertRaises(ValueError):
            chk.verify_manifest({"seed": 1}, base_dir=self.d)

    def test_real_repo_manifest_layouts_are_recognised_when_present(self):
        # layout recognition only; the real (gitignored) JSONL files may be absent
        for name, expect in (("manifest_v4_clean.json", 2), ("manifest_hybrid_analyzer_v2.json", 1)):
            p = os.path.join(REPO_ROOT, "datasets", name)
            if not os.path.exists(p):
                self.skipTest(f"{name} not present")
            with open(p) as f:
                self.assertEqual(len(chk.manifest_artifacts(json.load(f))), expect)


class CollisionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.p_v4 = os.path.join(self.tmp.name, "v4.jsonl")
        self.p_diag = os.path.join(self.tmp.name, "diag.jsonl")
        write_jsonl(self.p_v4, [{"input": req("alpha")}, {"input": req("beta")}])
        write_jsonl(self.p_diag, [{"text": req("O%27Neil")}])

    def test_no_collision_passes(self):
        r = chk.check_protected_collisions(
            [{"input": req("gamma")}],
            [{"name": "v4", "path": self.p_v4}, {"name": "diag", "path": self.p_diag,
                                                  "text_field": "text"}])
        self.assertTrue(r["ok"])

    def test_exact_and_canonical_collisions_with_per_set_field(self):
        cand = [{"input": req("alpha")},          # exact vs v4
                {"input": req("BETA")},           # canonical (case) vs v4
                {"input": req("o'neil")},         # canonical (%27) vs diag
                {"input": req("fresh")}]
        r = chk.check_protected_collisions(
            cand, [{"name": "v4", "path": self.p_v4},
                   {"name": "diag", "path": self.p_diag, "text_field": "text"}])
        self.assertFalse(r["ok"])
        v4, diag = r["protected"]["v4"], r["protected"]["diag"]
        self.assertEqual((v4["exact_collision_rows"], v4["canonical_collision_rows"],
                          v4["candidate_row_indices"]), (1, 2, [0, 1]))
        self.assertEqual((diag["exact_collision_rows"], diag["canonical_collision_rows"],
                          diag["candidate_row_indices"]), (0, 1, [2]))

    def test_result_never_contains_request_text(self):
        secret = "SECRETVALUE9"
        r = chk.check_protected_collisions(
            [{"input": req(secret)}], [{"name": "p", "rows": [{"input": req(secret)}]}])
        self.assertFalse(r["ok"])
        self.assertNotIn(secret.lower(), json.dumps(r).lower())

    def test_inputs_are_not_mutated(self):
        cand = [{"input": req("alpha")}]
        before = json.dumps(cand)
        chk.check_protected_collisions(cand, [{"name": "p", "path": self.p_v4}])
        self.assertEqual(json.dumps(cand), before)


class CliTests(unittest.TestCase):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = chk.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = self.tmp.name
        self.tr, self.va, self.bad = (os.path.join(d, n) for n in ("tr.jsonl", "va.jsonl", "bad.jsonl"))
        write_jsonl(self.tr, [{"input": req("a"), "label": "ALLOW", "family_id": "f1"}])
        write_jsonl(self.va, [{"input": req("b"), "label": "BLOCK", "family_id": "f2"}])
        write_jsonl(self.bad, [{"input": req("A"), "label": "BLOCK", "family_id": "f1"}])

    def test_pass_and_fail_exit_codes(self):
        code, out, _ = self.run_cli("duplicates", "--split", f"tr={self.tr}", "--split", f"va={self.va}")
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(out)["ok"])
        code, _, _ = self.run_cli("duplicates", "--split", f"tr={self.tr}", "--split", f"bad={self.bad}")
        self.assertEqual(code, 2)
        code, _, _ = self.run_cli("groups", "--split", f"tr={self.tr}", "--split", f"bad={self.bad}",
                                  "--key", "family_id")
        self.assertEqual(code, 2)
        code, _, _ = self.run_cli("labels", "--split", f"tr={self.tr}", "--split", f"bad={self.bad}")
        self.assertEqual(code, 2)
        code, _, _ = self.run_cli("collisions", "--candidate", self.va,
                                  "--protected", f"tr={self.tr}")
        self.assertEqual(code, 0)

    def test_cannot_run_exit_code(self):
        code, _, err = self.run_cli("duplicates", "--split", f"tr={self.tr}")
        self.assertEqual(code, 3)
        self.assertIn("FATAL", err)
        code, _, _ = self.run_cli("duplicates", "--split", f"tr={self.tr}",
                                  "--split", "va=/nonexistent.jsonl")
        self.assertEqual(code, 3)


if __name__ == "__main__":
    unittest.main()
