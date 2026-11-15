"""Tests for scripts/dataset/audit_v5_attack_pool.py (synthetic data; PATT not needed)."""
import json
import math
import os
import random
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "scripts", "dataset"))
import audit_v5_attack_pool as A  # noqa: E402


def canon(s):  # simple stand-in for parse_dataset_v4.canonical_key
    return " ".join(s.lower().split())


def make_rows(n_per_cat, cats):
    rows = []
    for c in cats:
        for i in range(n_per_cat[c]):
            rows.append({"payload": f"{c[:3]}-payload-{i}", "category": c,
                         "source": f"{c}/f{i % 3}.txt"})
    return rows


class WilsonTests(unittest.TestCase):
    def test_known_values(self):
        # k=5, n=10 -> classic Wilson 95%: [0.2366, 0.7634]
        lo, hi = A.wilson_interval(5, 10)
        self.assertAlmostEqual(lo, 0.2366, places=3)
        self.assertAlmostEqual(hi, 0.7634, places=3)
        # k=0, n=10 -> [0, 0.2775]
        lo, hi = A.wilson_interval(0, 10)
        self.assertEqual(lo, 0.0)
        self.assertAlmostEqual(hi, 0.2775, places=3)
        # k=10, n=10 -> [0.7225, 1]
        lo, hi = A.wilson_interval(10, 10)
        self.assertAlmostEqual(lo, 0.7225, places=3)
        self.assertAlmostEqual(hi, 1.0, places=9)
        # k=1, n=30 -> [0.0059, 0.1667]
        lo, hi = A.wilson_interval(1, 30)
        self.assertAlmostEqual(lo, 0.0059, places=3)
        self.assertAlmostEqual(hi, 0.1667, places=3)

    def test_edge_cases(self):
        self.assertEqual(A.wilson_interval(0, 0), (0.0, 1.0))
        with self.assertRaises(ValueError):
            A.wilson_interval(3, 2)
        lo, hi = A.wilson_interval(37, 100)
        self.assertTrue(0 <= lo < 0.37 < hi <= 1)
        self.assertTrue(math.isfinite(lo) and math.isfinite(hi))


class PoolAndSamplingTests(unittest.TestCase):
    cats = ["SQL Injection", "XSS Injection", "JSON Web Token"]
    sizes = {"SQL Injection": 100, "XSS Injection": 60, "JSON Web Token": 12}

    def pools(self, shuffle_seed=None, dup=False):
        rows = make_rows(self.sizes, self.cats)
        if dup:  # case/whitespace duplicates must collapse onto one canonical identity
            rows += [dict(r, payload=r["payload"].upper() + "  ") for r in rows[:5]]
        if shuffle_seed is not None:
            random.Random(shuffle_seed).shuffle(rows)
        return A.build_pool(rows, canon)

    def test_pool_dedup_and_structural(self):
        pools = self.pools(dup=True)
        self.assertEqual({c: len(v) for c, v in pools.items()}, self.sizes)
        rows = [{"payload": '{"a": 1}', "category": "X", "source": "h", "structural": True},
                {"payload": '{"a": 1}', "category": "X", "source": "h", "structural": True}]
        self.assertEqual(len(A.build_pool(rows, canon)["X"]), 1)

    def test_listing_hash_order_independent(self):
        h1 = A.pool_listing_sha256(self.pools(shuffle_seed=1))
        h2 = A.pool_listing_sha256(self.pools(shuffle_seed=2))
        h3 = A.pool_listing_sha256(self.pools())
        self.assertEqual(h1, h2)
        self.assertEqual(h1, h3)
        other = A.build_pool(make_rows({**self.sizes, "SQL Injection": 99}, self.cats), canon)
        self.assertNotEqual(h1, A.pool_listing_sha256(other))

    def test_sampling_deterministic_and_order_independent(self):
        n = {"SQL Injection": 10, "XSS Injection": 8, "JSON Web Token": 5}
        s1 = A.stratified_sample(self.pools(shuffle_seed=1), n, "seed-a")
        s2 = A.stratified_sample(self.pools(shuffle_seed=99), n, "seed-a")
        self.assertEqual(s1, s2)
        s3 = A.stratified_sample(self.pools(), n, "seed-b")
        self.assertNotEqual([r["canonical_sha256"] for r in s1],
                            [r["canonical_sha256"] for r in s3])

    def test_stratum_sizes_ids_and_ranks(self):
        n = {"SQL Injection": 10, "XSS Injection": 8, "JSON Web Token": 50}  # 50 > pool 12
        s = A.stratified_sample(self.pools(), n, "seed-a")
        counts = {}
        for r in s:
            counts[r["category"]] = counts.get(r["category"], 0) + 1
        self.assertEqual(counts, {"SQL Injection": 10, "XSS Injection": 8, "JSON Web Token": 12})
        self.assertEqual(len({r["sample_id"] for r in s}), len(s))
        self.assertEqual(set(s[0]), {"sample_id", "category", "payload", "canonical_sha256",
                                     "source_file", "pool_rank"})
        sql = [r["pool_rank"] for r in s if r["category"] == "SQL Injection"]
        self.assertEqual(sql, list(range(1, 11)))

    def test_prefix_property(self):
        # a larger n_c extends (never reshuffles) the smaller sample for the same seed
        small = A.stratified_sample(self.pools(), {"SQL Injection": 5}, "s")
        large = A.stratified_sample(self.pools(), {"SQL Injection": 12}, "s")
        self.assertEqual([r["canonical_sha256"] for r in small],
                         [r["canonical_sha256"] for r in large][:5])

    def test_allocation(self):
        tiers = A.TIERS
        sizes = {"SQL Injection": 1278, "XSS Injection": 2238, "Directory Traversal": 10219,
                 "JSON Web Token": 80, "Request Smuggling": 7, "NoSQL Injection": 83}
        n = A.allocate(sizes)
        self.assertGreaterEqual(n["SQL Injection"], tiers["SQL Injection"][1])
        self.assertLessEqual(n["Directory Traversal"], A.PROPORTIONAL_CAP)
        self.assertEqual(n["Request Smuggling"], 7)          # floor above pool -> whole pool
        self.assertEqual(n["JSON Web Token"], 10)
        self.assertEqual(n["NoSQL Injection"], 15)
        for c, v in n.items():
            self.assertLessEqual(v, sizes[c])


class SummarizeTests(unittest.TestCase):
    def setUp(self):
        self.sample = [
            {"sample_id": "A0001", "category": "SQL Injection", "source_file": "a.txt"},
            {"sample_id": "A0002", "category": "SQL Injection", "source_file": "a.txt"},
            {"sample_id": "A0003", "category": "SQL Injection", "source_file": "b.md"},
            {"sample_id": "A0004", "category": "JSON Web Token", "source_file": "c.md"},
        ]
        self.ann = [
            {"sample_id": "A0001", "label_class": "VERIFIABLE", "failure_mode": None, "note": ""},
            {"sample_id": "A0002", "label_class": "UNCERTAIN", "failure_mode": "encoding_garbage", "note": ""},
            {"sample_id": "A0003", "label_class": "INCORRECT", "failure_mode": "prose", "note": ""},
            {"sample_id": "A0004", "label_class": "INCORRECT", "failure_mode": "tool_output",
             "better_category": "Other", "note": ""},
        ]

    def test_summarize_counts_and_intervals(self):
        r = A.summarize(self.sample, self.ann)
        sql = r["per_category"]["SQL Injection"]
        self.assertEqual(sql["n"], 3)
        self.assertEqual(sql["counts"], {"VERIFIABLE": 1, "PROBABLY_CORRECT": 0,
                                         "UNCERTAIN": 1, "INCORRECT": 1})
        self.assertEqual(sql["not_usable_uncertain_or_incorrect"]["k"], 2)
        self.assertEqual(sql["incorrect_only"]["k"], 1)
        lo, hi = A.wilson_interval(2, 3)
        self.assertEqual(sql["not_usable_uncertain_or_incorrect"]["wilson95"], [lo, hi])
        self.assertEqual(sql["failure_modes_by_class"],
                         {"INCORRECT:prose": 1, "UNCERTAIN:encoding_garbage": 1})
        ov = r["overall_unweighted_sample"]
        self.assertEqual(ov["n"], 4)
        self.assertEqual(ov["incorrect_only"]["k"], 2)
        self.assertEqual(r["per_category"]["JSON Web Token"]["better_category_for_wrong_category"],
                         {"Other": 1})
        self.assertEqual(r["family_breakdown_by_source_file"]["SQL Injection :: a.txt"]["VERIFIABLE"], 1)

    def test_validation(self):
        self.assertEqual(A.validate_annotations(self.sample, self.ann), [])
        bad = self.ann[:3] + [{"sample_id": "A0004", "label_class": "NOPE", "failure_mode": None}]
        self.assertTrue(any("bad label_class" in e for e in A.validate_annotations(self.sample, bad)))
        missing = self.ann[:3]
        self.assertTrue(any("no annotation" in e for e in A.validate_annotations(self.sample, missing)))
        inc = self.ann[:2] + [{"sample_id": "A0003", "label_class": "INCORRECT", "failure_mode": None},
                              self.ann[3]]
        self.assertTrue(any("INCORRECT needs failure_mode" in e
                            for e in A.validate_annotations(self.sample, inc)))
        dup = self.ann + [self.ann[0]]
        self.assertTrue(any("duplicate" in e for e in A.validate_annotations(self.sample, dup)))

    def test_jsonl_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.jsonl")
            A.write_jsonl(p, self.ann)
            self.assertEqual(A.read_jsonl(p), self.ann)


class FilterTests(unittest.TestCase):
    def flags(self, payload, cat):
        return A.structural_flags(payload, cat)

    def test_flags_junk(self):
        self.assertIn("placeholder_token", self.flags("?redirect_url={payload}", "Open Redirect"))
        self.assertIn("doc_annotation", self.flags("(&(sn=a)(password=B*)) : KO", "LDAP Injection"))
        self.assertIn("tool_output_marker", self.flags("swissky@crashlab:~$ id", "Command Injection"))
        self.assertIn("bare_word", self.flags("onKeyDown", "XSS Injection"))
        self.assertIn("url_plus_label", self.flags("http://2852039166 Dotless decimal",
                                                   "Server Side Request Forgery"))
        self.assertIn("malformed_percent", self.flags("%c1%pc%c1%pcboot.ini", "Directory Traversal"))
        self.assertIn("literal_0x_escape", self.flags("0x2e0x2e0x2fboot.ini", "File Inclusion"))
        self.assertIn("dangling_opener", self.flags("possibleTypes {", "GraphQL Injection"))
        self.assertIn("tool_invocation", self.flags("sqlmap -u http://x/?id=1", "SQL Injection"))
        self.assertIn("prose_sentence", self.flags(
            "The Object.keys method returns an array of a given object own property names",
            "XSS Injection"))

    def test_does_not_flag_clean_payloads(self):
        for p, c in [("' or '1'='1", "SQL Injection"), ("../../../../etc/passwd", "Directory Traversal"),
                     ("%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc/passwd", "Directory Traversal"),
                     ("<script>alert(1)</script>", "XSS Injection"),
                     ("{{7*7}}", "Server Side Template Injection"),
                     ("<%= 7*7 %>", "Server Side Template Injection"),
                     ("; id", "Command Injection"), ("cat /etc/passwd", "Command Injection"),
                     ("http://169.254.169.254/latest/meta-data/", "Server Side Request Forgery"),
                     ("%0d%0aSet-Cookie:%20a=b", "CRLF Injection"),
                     ("' UNION SELECT NULL--", "SQL Injection"),
                     ("admin' or '1'='1' -- ", "SQL Injection")]:
            self.assertEqual(self.flags(p, c), [], (p, c))

    def test_evaluate_filters_on_synthetic(self):
        pools = {"Open Redirect": [
            {"category": "Open Redirect", "payload": "//evil.example", "canonical_key": "a",
             "canonical_sha256": "1", "source_file": "x"},
            {"category": "Open Redirect", "payload": "?next={payload}", "canonical_key": "b",
             "canonical_sha256": "2", "source_file": "x"},
            {"category": "Open Redirect", "payload": "/\\/evil.example", "canonical_key": "c",
             "canonical_sha256": "3", "source_file": "x"}]}
        sample = [{"sample_id": "A1", "category": "Open Redirect", "payload": "//evil.example"},
                  {"sample_id": "A2", "category": "Open Redirect", "payload": "?next={payload}"}]
        ann = [{"sample_id": "A1", "label_class": "VERIFIABLE", "failure_mode": None},
               {"sample_id": "A2", "label_class": "INCORRECT", "failure_mode": "placeholder"}]
        r = A.evaluate_filters(pools, sample, ann)["Open Redirect"]
        self.assertEqual(r["pool_flagged"], 1)
        self.assertEqual(r["sample_bad_caught_by_filters"], 1)
        self.assertEqual(r["sample_survivors"]["VERIFIABLE"], 1)
        self.assertEqual(r["estimated_clean_verifiable_or_probable"]["point"], 2)


class SecondAnnotationTests(unittest.TestCase):
    def test_binary_agreement_kappa_known_value(self):
        # 2x2: both=20, only_first=5, only_second=10, neither=15 (n=50)
        a = ["I"] * 20 + ["I"] * 5 + ["V"] * 10 + ["V"] * 15
        b = ["I"] * 20 + ["V"] * 5 + ["I"] * 10 + ["V"] * 15
        r = A.binary_agreement(a, b, lambda c: c == "I")
        self.assertEqual((r["both"], r["only_first"], r["only_second"], r["neither"]), (20, 5, 10, 15))
        # po = 0.7; pe = (25*30 + 20*25)/2500 = 0.5; kappa = 0.4
        self.assertAlmostEqual(r["observed_agreement"], 0.7)
        self.assertAlmostEqual(r["cohen_kappa"], 0.4)

    def test_binary_agreement_length_mismatch(self):
        with self.assertRaises(ValueError):
            A.binary_agreement(["V"], [], lambda c: True)

    def test_adjudicate_rules(self):
        first = {"a": "VERIFIABLE", "b": "VERIFIABLE", "c": "INCORRECT", "d": "UNCERTAIN"}
        second = {"a": "VERIFIABLE", "b": "PROBABLY_CORRECT", "c": "PROBABLY_CORRECT", "d": "INCORRECT"}
        out = A.adjudicate(first, second, {"c": "INCORRECT", "d": "UNCERTAIN"})
        self.assertEqual(out["a"], ("VERIFIABLE", "agreement"))
        self.assertEqual(out["b"], ("PROBABLY_CORRECT", "conservative_v_p"))
        self.assertEqual(out["c"], ("INCORRECT", "override"))
        self.assertEqual(out["d"], ("UNCERTAIN", "override"))

    def test_adjudicate_refuses_unresolved_disagreement(self):
        with self.assertRaises(ValueError):
            A.adjudicate({"x": "INCORRECT"}, {"x": "VERIFIABLE"}, {})

    def test_human_review_sample_is_stratified_deterministic_and_order_independent(self):
        sample = [{"sample_id": f"S{c[:2]}{i:03d}", "category": c, "payload": "p", "source_file": "f"}
                  for c in ("Cat A", "Cat B", "Cat C") for i in range(20)]
        n = {"Cat A": 4, "Cat B": 2}
        r1 = A.human_review_sample(sample, n, seed="s")
        shuffled = sample[:]
        random.Random(7).shuffle(shuffled)
        r2 = A.human_review_sample(shuffled, n, seed="s")
        self.assertEqual([r["sample_id"] for r in r1], [r["sample_id"] for r in r2])
        counts = {c: sum(1 for r in r1 if r["category"] == c) for c in ("Cat A", "Cat B", "Cat C")}
        self.assertEqual(counts, {"Cat A": 4, "Cat B": 2, "Cat C": 0})
        self.assertNotEqual([r["sample_id"] for r in r1],
                            [r["sample_id"] for r in A.human_review_sample(sample, n, seed="t")])


class HumanReviewTests(unittest.TestCase):
    def test_batches_preserve_order_and_cover_all(self):
        rows = [{"sample_id": f"A{i:04d}"} for i in range(95)]
        groups = A.batches(rows, 12)
        self.assertEqual(len(groups), 8)
        self.assertEqual([len(g) for g in groups], [12] * 7 + [11])
        self.assertEqual([r for g in groups for r in g], rows)
        with self.assertRaises(ValueError):
            A.batches(rows, 0)

    def test_validate_human_labels_detects_incomplete_and_bad_rows(self):
        ids = ["A1", "A2", "A3"]
        labels = [{"sample_id": "A1", "label_class": "VERIFIABLE", "failure_mode": ""},
                  {"sample_id": "A2", "label_class": "", "failure_mode": ""},
                  {"sample_id": "A3", "label_class": "INCORRECT", "failure_mode": ""},
                  {"sample_id": "A9", "label_class": "UNCERTAIN", "failure_mode": ""}]
        errs = A.validate_human_labels(ids, labels)
        self.assertTrue(any("A2: not reviewed yet" in e for e in errs))
        self.assertTrue(any("A3: INCORRECT needs failure_mode" in e for e in errs))
        self.assertTrue(any("A9: not in the human-review sample" in e for e in errs))
        ok = [{"sample_id": "A1", "label_class": "VERIFIABLE", "failure_mode": ""},
              {"sample_id": "A2", "label_class": "UNCERTAIN", "failure_mode": ""},
              {"sample_id": "A3", "label_class": "INCORRECT", "failure_mode": "prose"}]
        self.assertEqual(A.validate_human_labels(ids, ok), [])

    def test_compare_human_lists_disagreements_without_resolving(self):
        human = {"A1": "VERIFIABLE", "A2": "INCORRECT", "A3": "UNCERTAIN"}
        llm = {"A1": "PROBABLY_CORRECT", "A2": "INCORRECT", "A3": "VERIFIABLE"}
        cat = {"A1": "X", "A2": "X", "A3": "Y"}
        r = A.compare_human(human, llm, cat)
        self.assertEqual(r["n"], 3)
        self.assertEqual(r["exact_class_agreement"], 1)
        self.assertEqual([d["sample_id"] for d in r["disagreements"]], ["A1", "A3"])
        self.assertEqual(r["per_category_human"]["X"]["human_incorrect"]["k"], 1)
        self.assertEqual(r["per_category_human"]["Y"]["human_uncertain_or_incorrect"]["k"], 1)
        self.assertEqual(human["A3"], "UNCERTAIN")  # inputs untouched


if __name__ == "__main__":
    unittest.main()
