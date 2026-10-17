"""Stage-4 template catalogue tests (issue #74): parsing, typed slots, template_id (I-4), the §4.2
compatibility table, the Jaccard template audit, declared merges and I-16 cross-carrier conflicts.

    python3 -m unittest tests.test_v5_catalog -v
"""

import copy
import json
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "scripts", "dataset"))

import v5_catalog as K  # noqa: E402
import v5_identities as I  # noqa: E402

with open(K.DEFAULT_LEXICON, encoding="utf-8") as fh:
    LEXICON = json.load(fh)


def cat(*templates):
    return {"schema": K.CATALOG_SCHEMA, "templates": list(templates)}


def q(name, cluster, path, fields, method="GET", carrier="query"):
    return {"name": name, "cluster": cluster, "carrier": carrier, "method": method, "path": path, "fields": fields}


FS = {"type": "free_string", "names": "text"}
INT = {"type": "int", "names": "int"}


class RealCatalog(unittest.TestCase):
    def setUp(self):
        self.c = K.load_catalog()

    def test_audit_passes_and_every_carrier_has_three_clusters(self):
        rep = K.audit(self.c)
        self.assertTrue(rep["ok"], rep["findings"])
        self.assertEqual(rep["cross_carrier"], [])
        for carrier in K.CARRIERS:
            self.assertGreaterEqual(rep["strata"][carrier]["clusters"], 3, carrier)

    def test_every_compatible_category_has_a_slot(self):
        cov = K.coverage(self.c)
        self.assertEqual(cov["categories_without_slot"], [])
        self.assertEqual(set(cov["category_carriers"]), set(K.INJECTION_CATEGORIES) | set(K.POLICY_CATEGORIES))

    def test_template_ids_are_unique_and_recomputable(self):
        ids = [t.template_id for t in self.c.templates]
        self.assertEqual(len(ids), len(set(ids)))
        for t in self.c.templates:
            self.assertEqual(t.template_id, I.template_id(t.skeleton()))
            self.assertEqual(t.media_type, K.CARRIER_MEDIA[t.carrier])

    def test_cluster_table_matches_stage3_contract(self):
        table = K.cluster_table(self.c)
        for t in self.c.templates:
            self.assertEqual(table.template_cluster[t.template_id], t.struct_cluster_id)
            self.assertEqual(table.cluster_stratum[t.struct_cluster_id], t.carrier)
        self.assertEqual(table.near_duplicates, ())

    def test_no_names_family_pool(self):
        self.assertFalse(any("names_family" in s.pools for t in self.c.templates for s in t.slots))

    def test_json_key_paths_are_positional(self):
        order = next(t for t in self.c.templates if t.name == "j-order-a")
        self.assertEqual([s.key_path for s in order.slots], [(0, "[]", 0, 0), (0, "[]", 0, 1), (1,), (2,)])
        batch = next(t for t in self.c.templates if t.name == "j-batch-a")
        self.assertEqual(batch.body.kind, "array")
        self.assertEqual(batch.slots[0].key_path, ("[]", 0, 0))
        self.assertEqual(batch.name_sites()[0], (("[]", 0, 0), "text", ("[]", 0)))


class CompatibilityTable(unittest.TestCase):
    def test_table_is_the_frozen_section_4_2(self):
        self.assertEqual(K.SLOT_COMPATIBILITY["free_string"],
                         {K.SQLI, K.XSS, K.CMDI, K.SSTI, K.NOSQL, K.XPATH, K.CRLF})
        self.assertEqual(K.SLOT_COMPATIBILITY["url"], {K.SSRF, K.REDIRECT})
        self.assertEqual(K.SLOT_COMPATIBILITY["path_file"], {K.PATH_FILE})
        self.assertEqual(K.SLOT_COMPATIBILITY["json_leaf"], {K.NOSQL, K.SQLI, K.XSS, K.SSTI})
        for t in K.SCALAR_SLOT_TYPES:
            self.assertNotIn(t, K.SLOT_COMPATIBILITY)


class TemplateIdentity(unittest.TestCase):
    def test_field_names_do_not_distinguish_templates(self):
        a = q("a", "c-a", ["x", "y"], [FS, INT])
        b = q("b", "c-b", ["x", "y"], [{"type": "free_string", "names": "url"}, {"type": "int", "names": "number"}])
        with self.assertRaisesRegex(K.CatalogError, "same structural skeleton"):
            K.catalog_from_objects(cat(a, b), LEXICON)

    def test_structure_changes_the_id(self):
        base = K.catalog_from_objects(cat(q("a", "c-a", ["x", "y"], [FS, INT])), LEXICON).templates[0]
        for variant in (q("a", "c-a", ["x", "z"], [FS, INT]), q("a", "c-a", ["x", "y"], [INT, FS]),
                        q("a", "c-a", ["x", "y"], [FS, INT], method="DELETE"), q("a", "c-a", ["x", "y"], [FS])):
            t = K.catalog_from_objects(cat(variant), LEXICON).templates[0]
            self.assertNotEqual(t.template_id, base.template_id)


class Refusals(unittest.TestCase):
    def bad(self, tpl, msg):
        with self.assertRaisesRegex(K.CatalogError, msg):
            K.catalog_from_objects(cat(tpl), LEXICON)

    def test_malformed_templates(self):
        self.bad(q("a", "c", ["x"], [{"type": "html", "names": "text"}]), "unknown type")
        self.bad(q("a", "c", ["x"], [FS], method="POST"), "method")
        self.bad(q("a", "c|x", ["x"], [FS]), "cluster")
        self.bad(q("a", "c", ["X"], [FS]), "path segment")
        self.bad(q("a", "c", ["x"], [{"type": "free_string"}]), "needs `names`")
        self.bad(q("a", "c", ["x"], [{"type": "free_string", "names": "nope"}]), "unknown field-name list")
        self.bad(q("a", "c", ["x"], [INT]), "no attackable slot")
        self.bad(q("a", "c", ["x"], [{"type": "enum", "names": "enum", "choices": ["a"]}, FS]), "enum needs")
        self.bad(q("a", "c", ["x"], [{"type": "free_string", "names": "text", "pools": ["names_family"]}]), "pools")
        self.bad(q("a", "c", ["x"], [{"type": "int", "names": "int", "pools": ["streets"]}, FS]), "takes no pools")
        self.bad(q("a", "c", ["x"], [{"type": "json_leaf", "names": "text"}]), "not allowed in the query")
        self.bad(q("a", "c", ["x", {"type": "free_string"}], [FS]), "attackable path slot outside")
        self.bad({"name": "a", "cluster": "c", "carrier": "text", "method": "POST", "path": ["x"],
                  "text": {"type": "free_string", "names": "text"}}, "takes no `names`")
        self.bad({"name": "a", "cluster": "c", "carrier": "json", "method": "POST", "path": ["x"],
                  "json": {"object": []}}, "at least one child")
        self.bad({"name": "a", "cluster": "c", "carrier": "json", "method": "POST", "path": ["x"],
                  "json": {"object": [{"type": "json_leaf", "names": "text"}], "names": "object"}}, "root takes no")
        self.bad({"name": "a", "cluster": "c", "carrier": "path", "method": "GET", "path": ["x", {"type": "int"}]},
                 "no attackable slot")
        self.bad({"name": "a", "cluster": "c", "carrier": "form", "method": "POST", "path": ["x"]}, "needs `fields`")

    def test_duplicate_names_and_schema(self):
        with self.assertRaisesRegex(K.CatalogError, "declared twice"):
            K.catalog_from_objects(cat(q("a", "c", ["x"], [FS]), q("a", "c", ["y"], [FS])), LEXICON)
        with self.assertRaisesRegex(K.CatalogError, "schema"):
            K.catalog_from_objects({"schema": "v0", "templates": []}, LEXICON)
        lex = copy.deepcopy(LEXICON)
        del lex["lists"]["url"]
        with self.assertRaisesRegex(K.CatalogError, "lacks lists"):
            K.catalog_from_objects(cat(q("a", "c", ["x"], [FS])), lex)

    def test_more_keys_than_names(self):
        lex = copy.deepcopy(LEXICON)
        lex["lists"]["int"] = ["a"]
        with self.assertRaisesRegex(K.CatalogError, "with only 1 names"):
            K.catalog_from_objects(cat(q("a", "c", ["x"], [FS, INT, INT])), lex)


LONG = ["shop", "store", "catalog", "department", "aisle", "shelf"]


class Audit(unittest.TestCase):
    def test_undeclared_same_carrier_near_duplicate_stops(self):
        c = K.catalog_from_objects(cat(q("a", "c-a", LONG, [FS, INT]), q("b", "c-b", LONG, [FS, INT, INT])), LEXICON)
        rep = K.audit(c)
        self.assertFalse(rep["ok"])
        self.assertEqual([f["code"] for f in rep["findings"]], ["UNDECLARED_NEAR_DUPLICATE"])
        self.assertEqual(rep["proposed_cluster_merges"], [["c-a", "c-b"]])
        with self.assertRaises(K.CatalogStop):
            K.cluster_table(c)
        # the fix is a declared merge, never a split; the merged id is the smallest member id
        table = K.cluster_table(c, [["c-b", "c-a"]])
        self.assertEqual(set(table.template_cluster.values()), {"c-a"})
        self.assertTrue(K.audit(c, [["c-a", "c-b"]])["ok"])

    def test_same_cluster_near_duplicates_are_fine(self):
        c = K.catalog_from_objects(cat(q("a", "c-a", LONG, [FS, INT]), q("b", "c-a", LONG, [FS, INT, INT])), LEXICON)
        rep = K.audit(c)
        self.assertTrue(rep["ok"])
        self.assertEqual(len(rep["intra_cluster_pairs"]), 1)

    def test_i16_cross_carrier_conflict_stops_and_cannot_be_merged(self):
        a = q("a", "c-a", LONG, [FS, INT, FS], method="DELETE")
        b = q("b", "c-b", LONG, [FS, INT, FS], method="DELETE")
        b["carrier"] = "form"
        b["method"] = "PUT"
        a["method"] = "GET"
        a["path"] = b["path"] = LONG + ["item", "detail"]
        c = K.catalog_from_objects(cat(a, b), LEXICON)
        rep = K.audit(c)
        self.assertEqual([f["code"] for f in rep["findings"]], ["I16_CROSS_CARRIER"])
        self.assertEqual(rep["proposed_cluster_merges"], [])
        merged = K.audit(c, [["c-a", "c-b"]])            # D-2: a cluster may not span two carrier strata
        self.assertIn("CLUSTER_SPANS_STRATA", [f["code"] for f in merged["findings"]])
        with self.assertRaises(K.CatalogStop):
            K.cluster_table(c, [["c-a", "c-b"]])

    def test_few_clusters_is_flagged_not_blocking(self):
        c = K.catalog_from_objects(cat(q("a", "c-a", ["x"], [FS])), LEXICON)
        rep = K.audit(c)
        self.assertTrue(rep["ok"])
        self.assertEqual(rep["strata"]["query"]["flag"], "NOT_EVALUABLE_STRUCTURE")
        self.assertIn("NOT_EVALUABLE_STRUCTURE", [i["code"] for i in rep["info"]])


class CLI(unittest.TestCase):
    def test_audit_cli(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            out, md = os.path.join(d, "a.json"), os.path.join(d, "a.md")
            self.assertEqual(K.main(["audit", "--out", out, "--summary", md]), 0)
            with open(out, encoding="utf-8") as fh:
                self.assertTrue(json.load(fh)["audit"]["ok"])


if __name__ == "__main__":
    unittest.main()
