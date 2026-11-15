"""Stage-3 split tests (issue #72): cuts, ranks, steps 1–3, the E6 reserve, evaluability, config
validation, the partition / membership contract, and invariants SPL-1…SPL-9 with an injected
violation for every gate (A5). Synthetic identities only; nothing here reads a real pool.

    python3 -m unittest tests.test_v5_split -v
"""

import ast
import contextlib
import copy
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "scripts", "dataset"))

import v5_identities as I  # noqa: E402
import v5_split as S  # noqa: E402
import v5_split_checks as K  # noqa: E402
from parse_dataset_v4 import canonical_key  # noqa: E402

SPLIT_PY = os.path.join(REPO, "scripts", "dataset", "v5_split.py")


def vocab_config(**over):
    cv = {"source": "stage2_dedup_scope", "order": "python_str_code_point", "categories": ["cat_a", "cat_b"]}
    return K.fixture_config(category_vocabulary=cv, family_merges=[], **over)


def fam(pfid, cats=("cat_a",), native=()):
    return S.FamilyIdentity(pfid, tuple(cats), tuple(native))


def fams(n, cat="cat_a", prefix="f", native_first=0):
    return [fam(f"{prefix}{i:05d}", (cat,), ("double_encoding",) if i < native_first else ()) for i in range(n)]


class Cuts(unittest.TestCase):
    def test_cut_table(self):
        expected = {0: (0, 0, 0), 1: (0, 0, 1), 2: (0, 0, 2), 3: (1, 1, 1), 4: (1, 1, 2), 5: (1, 1, 3),
                    10: (2, 1, 7), 15: (3, 2, 10), 25: (5, 3, 17), 45: (9, 5, 31), 147: (29, 15, 103),
                    148: (30, 15, 103), 194: (39, 19, 136), 195: (39, 20, 136)}
        for n, cut in expected.items():
            self.assertEqual(S.cuts(n), cut, n)

    def test_floor_half_up_differs_from_python_round(self):
        # floor(0.10·25 + 0.5) = 3 while round(2.5) = 2 (banker's rounding): the spec forbids round()
        self.assertEqual(S.cuts(25)[1], 3)
        self.assertEqual(round(0.10 * 25), 2)
        with open(SPLIT_PY, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        calls = {n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        self.assertNotIn("round", calls)
        self.assertFalse(any(isinstance(n, ast.Constant) and isinstance(n.value, float) for n in ast.walk(tree)),
                         "no float constant may enter the cut arithmetic")

    def test_invalid_n(self):
        for bad in (-1, 1.0, True, "3"):
            with self.assertRaises(S.InvalidInput):
                S.cuts(bad)


class Ranks(unittest.TestCase):
    def test_rank_is_ascending_salted_nul_sha256(self):
        ids = [f"id{i}" for i in range(50)]
        dig = {i: hashlib.sha256(f"v5-split-v1\0payload\0{i}".encode()).hexdigest() for i in ids}
        self.assertEqual(S.ranked("payload", ids), sorted(ids, key=lambda i: dig[i]))
        self.assertEqual(S.ranked("payload", reversed(ids)), S.ranked("payload", ids))

    def test_lowest_ranks_go_to_test_then_validation(self):
        order = [f"x{i}" for i in range(10)]
        a = S.assign_by_rank(order)
        self.assertEqual([a[x] for x in order], ["INTERNAL_TEST"] * 2 + ["VALIDATION"] + ["TRAIN"] * 7)

    def test_duplicates_and_empty_ids_refused(self):
        with self.assertRaises(S.InvalidInput):
            S.ranked("value", ["a", "a"])
        with self.assertRaises(S.InvalidInput):
            S.ranked("value", [""])


class Clusters(unittest.TestCase):
    def test_strata_and_not_evaluable_structure(self):
        cs = {f"c{i}": "query" for i in range(10)} | {"j1": "json", "j2": "json"}
        a, rep = S.assign_clusters(cs, ["json", "query", "form"])
        self.assertEqual(rep["json"]["flag"], S.NOT_EVALUABLE_STRUCTURE)
        self.assertEqual(rep["form"], {"n": 0, "TRAIN": 0, "VALIDATION": 0, "INTERNAL_TEST": 0,
                                       "flag": S.NOT_EVALUABLE_STRUCTURE})
        self.assertEqual({a["j1"], a["j2"]}, {"TRAIN"})
        self.assertEqual((rep["query"]["INTERNAL_TEST"], rep["query"]["VALIDATION"]), (2, 1))
        with self.assertRaises(S.InvalidInput):
            S.assign_clusters({"c": "xml"}, ["query"])


class FamiliesAndE6(unittest.TestCase):
    def run_cat(self, n, native=0, policy=None):
        a, rep, _ = S.assign_families(fams(n, native_first=native), policy)
        return a, rep["cat_a"]

    def test_attempt_1_boundary_R_30(self):
        _, r = self.run_cat(363)                                   # R = ceil(29.04) = 30
        self.assertEqual((r["R"], r["outcome"], r["reserve_size"]), (30, S.ATTEMPT_WITH_RESERVE, 30))
        self.assertEqual((r["INTERNAL_TEST"], r["VALIDATION"], r["TRAIN"]), (67, 33, 233))
        _, r = self.run_cat(362)                                   # R = 29 -> attempt 2
        self.assertEqual((r["R"], r["outcome"], r["note"]), (29, S.ATTEMPT_NO_RESERVE, "no reserve: not defensible"))
        self.assertEqual(r["attempt_1"], {"skipped": "R = 29 < 30"})

    def test_attempt_2_and_not_evaluable_boundary(self):
        _, r = self.run_cat(148)
        self.assertEqual((r["outcome"], r["INTERNAL_TEST"]), (S.ATTEMPT_NO_RESERVE, 30))
        a, r = self.run_cat(147)
        self.assertEqual((r["outcome"], r["TRAIN"]), (S.NOT_EVALUABLE, 147))
        self.assertEqual(set(a.values()), {"TRAIN"})
        _, r = self.run_cat(2)
        self.assertEqual((r["outcome"], r["TRAIN"]), (S.NOT_EVALUABLE, 2))

    def test_reserve_takes_forced_native_families_first(self):
        a, r = self.run_cat(400, native=10)
        forced = {f"f{i:05d}" for i in range(10)}
        self.assertTrue(all(a[p] == S.E6_RESERVE for p in forced))
        self.assertEqual(r["reserve_size"], 32)
        self.assertEqual(r["enc5_retired_forms"], {})
        # the other 22 reserve slots are the lowest-ranked non-forced families
        order = [p for p in S.ranked("payload", [f"f{i:05d}" for i in range(400)]) if p not in forced]
        self.assertEqual({p for p in order[:22]}, {p for p, s in a.items() if s == S.E6_RESERVE} - forced)

    def test_forced_overflow_needs_an_explicit_policy(self):
        with self.assertRaises(S.StopBuild) as cm:
            self.run_cat(400, native=40)
        self.assertEqual(cm.exception.findings[0]["code"], "E6_FORCED_OVERFLOW")

    def test_forced_overflow_is_reported_when_a_later_category_shares_families(self):
        # round-3 review: a later stratum that counts the blocked stratum's families must not mask the stop
        fs = fams(400, "cat_a", "a", native_first=40) + [fam("s0", ("cat_a", "cat_b"))] + fams(50, "cat_b", "b")
        with self.assertRaises(S.StopBuild) as cm:
            S.assign_families(fs, None)
        codes = sorted(f["code"] for f in cm.exception.findings)
        self.assertEqual(codes, ["E6_FORCED_OVERFLOW", "STRATUM_NOT_EVALUATED"])
        inp = K.fixture_inputs(vocab_config(pools=["fx_names", "fx_streets", "names_family"],
                                            value_pool_precedence=["fx_names", "fx_streets", "names_family"]))
        with self.assertRaises(S.StopBuild) as cm:                  # build() collects every step's findings
            S.build(inp["config"], inp["table"], fs, inp["values"])
        self.assertEqual(sorted(f["code"] for f in cm.exception.findings),
                         ["E6_FORCED_OVERFLOW", "POOL_UNAVAILABLE", "STRATUM_NOT_EVALUATED"])

    def test_own_reserve_and_shared_reserve_are_reported_apart(self):
        # a NOT_EVALUABLE category can hold a reserve family placed by an earlier stratum (one identity)
        fs = [fam(f"a{i:04d}", ("cat_a", "cat_b") if i < 50 else ("cat_a",)) for i in range(400)] + fams(20, "cat_b", "b")
        inp = K.fixture_inputs(vocab_config())
        a = S.build(inp["config"], inp["table"], fs, inp["values"])
        e6 = a.manifest("x")["families"]["e6_reserve"]
        shared = e6["reserve_families_from_other_strata"].get("cat_b", 0)
        self.assertEqual(shared, a.evaluability["cat_b"]["reserve"])
        self.assertIn("cat_b", e6["categories_without_own_reserve"])
        self.assertEqual("cat_b" in e6["categories_without_reserve"], shared == 0)
        self.assertNotIn("cat_a", e6["categories_without_own_reserve"])
        a, r = self.run_cat(400, native=40, policy="reserve_equals_forced")
        self.assertEqual((r["reserve_size"], r["outcome"]), (40, S.ATTEMPT_WITH_RESERVE))
        a, r = self.run_cat(400, native=40, policy="enc5_retire")
        self.assertEqual(r["reserve_size"], 32)
        self.assertGreater(r["enc5_retired_forms"]["double_encoding"], 0)

    def test_native_forms_are_retired_when_there_is_no_reserve(self):
        _, r = self.run_cat(200, native=3)
        self.assertEqual((r["outcome"], r["enc5_retired_forms"]), (S.ATTEMPT_NO_RESERVE, {"double_encoding": 3}))

    def test_attempt_1_rejected_when_not_evaluable_after_reserve(self):
        # the only reachable path: a forced reserve (250 > R = 30) leaves 125 families, TEST 25 < 30
        a, r = self.run_cat(375, native=250, policy="reserve_equals_forced")
        self.assertFalse(r["attempt_1"]["evaluable"])               # 125 remaining -> TEST 25 < 30
        self.assertEqual(r["outcome"], S.ATTEMPT_NO_RESERVE)
        self.assertNotIn(S.E6_RESERVE, a.values())
        self.assertEqual(r["enc5_retired_forms"], {"double_encoding": 250})

    def test_multi_category_family_ranked_once_and_counted_everywhere(self):
        fs = fams(200, "cat_b", "b") + [fam(f"s{i:03d}", ("cat_a", "cat_b")) for i in range(150)]
        a, rep, fx = S.assign_families(fs, None)
        self.assertEqual(rep["cat_a"]["n"], 150)                    # stratum = first category
        self.assertEqual(rep["cat_b"]["n"], 200)
        ev = S.category_evaluability(fx, a)
        self.assertEqual(ev["cat_b"]["families_in_splits"], 350)
        self.assertEqual(ev["cat_a"]["flag"], S.EVALUABLE)

    def test_stratum_outcome_agrees_with_final_flag(self):
        # I-8 hybrid (round 3): 50 own families of cat_b + 200 placed by cat_a's stratum are counted together
        inp = K.fixture_inputs(vocab_config())
        fs = [fam(f"a{i:04d}", ("cat_a", "cat_b") if i < 200 else ("cat_a",)) for i in range(400)] + fams(50, "cat_b", "b")
        a = S.build(inp["config"], inp["table"], fs, inp["values"])
        ov = a.outcome_vs_flag()
        self.assertEqual(ov["cat_b"]["stratum_outcome"], S.ATTEMPT_NO_RESERVE)
        self.assertEqual(ov["cat_b"]["final_flag"], S.EVALUABLE)
        self.assertFalse(ov["cat_b"]["diverges"])
        self.assertFalse(ov["cat_a"]["diverges"])
        self.assertTrue(K.gate_spl8(a)["ok"])
        m = a.manifest("x")
        self.assertNotIn("cat_b", m["families"]["e6_reserve"]["categories_without_reserve"])   # 16 of its families are reserved
        self.assertGreater(a.evaluability["cat_b"]["reserve"], 0)

    def test_reserve_never_counts_toward_evaluability(self):
        a, _, fx = S.assign_families(fams(400), None)
        ev = S.category_evaluability(fx, a)["cat_a"]
        self.assertEqual((ev["families_in_splits"], ev["reserve"]), (368, 32))

    def test_categories_outside_the_configured_vocabulary_are_refused(self):
        with self.assertRaises(S.InvalidInput):
            S.assign_families(fams(5, "cat_x"), None, vocabulary=["cat_a"])
        a, _, _ = S.assign_families(fams(5, "cat_a"), None, vocabulary=["cat_a", "cat_b"])
        self.assertEqual(len(a), 5)

    def test_bad_family_inputs(self):
        with self.assertRaises(S.InvalidInput):
            S.assign_families([fam("x"), fam("x")], None)
        with self.assertRaises(S.InvalidInput):
            S.assign_families([fam("x", ("b", "a"))], None)              # unsorted categories
        with self.assertRaises(S.InvalidInput):
            S.assign_families([fam("x", ())], None)


class Values(unittest.TestCase):
    def test_minimum_20_per_split_blocks_the_build(self):
        ok = {"p": [f"v{i}" for i in range(195)]}
        a, rep = S.assign_values(ok, ["p"])
        self.assertEqual(rep["p"]["VALIDATION"], 20)
        with self.assertRaises(S.StopBuild) as cm:
            S.assign_values({"p": [f"v{i}" for i in range(194)]}, ["p"])
        self.assertEqual(cm.exception.findings[0]["code"], "POOL_TOO_SMALL")

    def test_missing_pool_blocks_and_extra_pool_is_invalid(self):
        with self.assertRaises(S.StopBuild) as cm:
            S.assign_values({"p": [f"v{i}" for i in range(300)]}, ["p", "names_family"])
        self.assertEqual([f["code"] for f in cm.exception.findings], ["POOL_UNAVAILABLE"])
        with self.assertRaises(S.InvalidInput):
            S.assign_values({"q": ["v"]}, ["p"])
        with self.assertRaises(S.InvalidInput):
            S.assign_values({"p": ["v", "v"]}, ["p"])
        ids = [f"v{i}" for i in range(250)]
        with self.assertRaises(S.InvalidInput):                     # one id in two pools
            S.assign_values({"p": ids, "q": ids[:200] + [f"w{i}" for i in range(50)]}, ["p", "q"])


class Config(unittest.TestCase):
    def test_fixture_config_is_valid_and_hash_stable(self):
        cfg = K.fixture_config()
        self.assertEqual(S.config_sha256(S.validate_config(cfg)), S.config_sha256(json.loads(json.dumps(cfg))))

    def test_invalid_configs_are_rejected(self):
        base = K.fixture_config()
        bad = [
            {"salt": "v5-split-v2"},
            {"shares_percent": {"INTERNAL_TEST": 15, "VALIDATION": 15, "TRAIN": 70}},
            {"evaluability": {"min_families": 50, "min_internal_test_families": 30}},
            {"value_min_per_split": 10},
            {"near_duplicate_jaccard": "0.50"},
            {"near_duplicate_jaccard": 0.6},
            {"e6": {"reserve_percent": 10, "min_reserve_families": 30, "forced_overflow_policy": None}},
            {"e6": {"reserve_percent": 8, "min_reserve_families": 30, "forced_overflow_policy": "drop"}},
            {"master_seed": True}, {"master_seed": ""},
            {"carrier_strata": []}, {"pools": ["a", "a"]},
            {"category_vocabulary": "d47"},
            {"category_vocabulary": {"source": "d47", "order": "python_str_code_point", "categories": ["a"]}},
            {"category_vocabulary": {"source": "stage2_dedup_scope", "order": "python_str_code_point", "categories": []}},
            {"family_merges": [["only-one"]]},
            {"cluster_share": {"warn": "0.02", "block": "0.05", "status": "APPROVED"}},
            {"cluster_share": {"warn": "0.05", "block": "0.02", "status": "PROPOSED"}},
            {"cluster_share": {"warn": 0.02, "block": "0.05", "status": "PROPOSED"}},
            {"schema": "v5-split-config/v0"},
            {"shares_percent": {"INTERNAL_TEST": 20.0, "VALIDATION": 10, "TRAIN": 70}},
            {"evaluability": {"min_families": 100.0, "min_internal_test_families": 30}},
            {"cluster_share": {"warn": "1/50", "block": "0.05", "status": "PROPOSED"}},
            {"cluster_share": {"warn": "1e-2", "block": "0.05", "status": "PROPOSED"}},
            {"schema": "v5-split-config/v2"},                               # round-2 config (holds) refused
            {"value_equivalence_holds": []},                                # the hold is removed (round 3, policy B)
            {"value_equivalence_semantic_notes": ["i'm terrified of wasps."]},
            {"value_equivalence_semantic_notes": {"k": " "}},
            {"value_equivalence": "canonical_key/v1"},
            {"value_pool_precedence": ["fx_names"]},                         # must list every configured pool
        ]
        for over in bad:
            cfg = copy.deepcopy(base)
            cfg.update(over)
            with self.assertRaises(S.InvalidConfig, msg=str(over)):
                S.validate_config(cfg)
        cfg = copy.deepcopy(base)
        cfg["extra"] = 1
        with self.assertRaises(S.InvalidConfig):
            S.validate_config(cfg)
        cfg = copy.deepcopy(base)
        del cfg["master_seed"]
        with self.assertRaises(S.InvalidConfig):
            S.validate_config(cfg)


def fixture():
    inp = K.fixture_inputs()
    return inp, K.build_from(inp)


def rows_from(inp, a, per_cluster=3):
    """Small rows drawn ONLY from each split's partitions (test helper, not a generator)."""
    value_text = {(p, I.value_entry_id(p, v)): v for p, vs in inp["pool_values"].items() for v in vs}
    root = {k: f for f, ks in a.family_member_keys.items() for k in ks}
    payload_of = {}
    for r in sorted(inp["records"], key=lambda r: r["record_id"]):
        payload_of.setdefault(root[I.payload_family_id(r["payload_wire"])], r["payload_wire"])
    rows = []
    for split in S.SPLITS:
        part = a.partition(split)
        families = sorted({p for ps in part.families_by_category.values() for p in ps})
        for c in part.clusters:
            tmpls = [t for t in part.templates if a.template_cluster[t] == c]
            for i in range(per_cluster):
                rng = I.row_rng(split, c, "q0", i)
                ves = [[pool, rng.choice(part.values_by_pool[pool])] for pool in sorted(part.values_by_pool)]
                p = rng.choice(families)
                rows.append({"split": split, "struct_cluster_id": c, "template_id": rng.choice(tmpls),
                             "pair_id": I.pair_id(split, c, "q0", i), "payload_family_id": p,
                             "payload": payload_of[p], "value_entries": ves,
                             "values": [value_text[(x, y)] for x, y in ves], "text": f"{split}|{c}|{i}"})
    return rows


class BuildAndContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inp, cls.a = fixture()
        cls.rows = rows_from(cls.inp, cls.a)

    def test_partitions_exclude_the_reserve_and_cover_every_identity_once(self):
        with self.assertRaises(S.InvalidInput):
            self.a.partition(S.E6_RESERVE)
        seen = []
        for s in S.SPLITS:
            p = self.a.partition(s)
            seen += [(k, x) for k, xs in p.families_by_category.items() for x in xs]
        reserve = {p for p, s in self.a.families.items() if s == S.E6_RESERVE}
        self.assertEqual(len(reserve), 32)
        self.assertFalse(reserve & {x for _, x in seen})

    def test_merges_must_match_the_config(self):
        cfg = K.fixture_config(family_merges=[])
        with self.assertRaises(S.InvalidInput):
            S.build(cfg, self.inp["table"], self.inp["families"].values(), self.inp["values"])
        cfg = K.fixture_config(cluster_merges=[])
        with self.assertRaises(S.InvalidInput):
            S.build(cfg, self.inp["table"], self.inp["families"].values(), self.inp["values"])

    def test_blocking_findings_are_collected(self):
        decls = K.fixture_template_decls()
        d0 = decls[0]
        decls.append(I.TemplateDecl("dup-near", "fx-form-zzzz", d0.carrier_stratum, d0.tokens))
        table = I.resolve_clusters(decls, self.inp["config"]["cluster_merges"])
        values = dict(self.inp["values"])
        values["fx_names"] = values["fx_names"][:100]
        with self.assertRaises(S.StopBuild) as cm:
            S.build(self.inp["config"], table, self.inp["families"].values(), values)
        self.assertEqual(sorted(f["code"] for f in cm.exception.findings),
                         ["POOL_TOO_SMALL", "UNDECLARED_NEAR_DUPLICATE_TEMPLATES"])

    def test_names_family_blocked_pool_blocks_only_value_assignment(self):
        cfg = K.fixture_config(pools=["fx_names", "fx_streets", "names_family"],
                               value_pool_precedence=["fx_names", "fx_streets", "names_family"])
        with self.assertRaises(S.StopBuild) as cm:
            S.build(cfg, self.inp["table"], self.inp["families"].values(), self.inp["values"])
        self.assertEqual([f["code"] for f in cm.exception.findings], ["POOL_UNAVAILABLE"])
        # identities and families are still buildable on their own
        self.assertEqual(len(S.assign_families(self.inp["families"].values(), None)[0]), len(self.inp["families"]))

    def test_artifacts_are_deterministic(self):
        with tempfile.TemporaryDirectory() as t:
            h1 = S.write_assignment(self.a, os.path.join(t, "a"))
            h2 = S.write_assignment(fixture()[1], os.path.join(t, "b"))
            self.assertEqual(h1, h2)
            with open(os.path.join(t, "a", "manifest.json"), encoding="utf-8") as fh:
                m = json.load(fh)
            self.assertEqual(m["config_sha256"], S.config_sha256(m["config"]))
            self.assertEqual(m["artifacts"][0]["sha256"], h1["assignment_sha256"])
            self.assertEqual(len(m["families"]["e6_reserve"]["payload_family_ids"]), 32)
            self.assertEqual(m["clusters"]["per_stratum"]["form"]["flag"], S.NOT_EVALUABLE_STRUCTURE)

    def test_cluster_share_uses_proposed_thresholds_only(self):
        rows = [{"split": "TRAIN", "struct_cluster_id": "big"}] * 6 + \
               [{"split": "TRAIN", "struct_cluster_id": f"c{i}"} for i in range(94)]
        out = S.cluster_shares(rows, K.fixture_config())
        self.assertEqual(out["TRAIN"]["big"]["class"], "BLOCK")
        self.assertEqual(out["TRAIN"]["c1"]["class"], "OK")
        self.assertEqual(out["TRAIN"]["big"]["threshold_status"], "PROPOSED")
        out = S.cluster_shares(rows[:3] + rows[6:], K.fixture_config())
        self.assertEqual(out["TRAIN"]["big"]["class"], "WARN")              # 3/97 > 2%


class Invariants(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inp, cls.a = fixture()
        cls.rows = rows_from(cls.inp, cls.a)

    def test_all_gates_pass_on_the_fixture(self):
        g = K.run_gates(self.a, self.rows, self.inp["pool_values"], self.inp["records"])
        self.assertEqual({k: v["ok"] for k, v in g.items()},
                         {k: True for k in ("SPL-3", "SPL-4", "SPL-5", "SPL-6", "SPL-7", "SPL-8", "SPL-9")})

    def test_spl1_order_independence(self):
        raw = {"config": self.inp["config"], "decls": K.fixture_template_decls(),
               "records": self.inp["records"], "values": self.inp["values"]}
        r = K.spl1_order_independence(raw, permutations=4)
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["distinct"], 1)
        # A5: an order-dependent ranking (input order kept) must be caught
        with mock.patch.object(S, "ranked", lambda kind, ids: list(ids)):
            self.assertFalse(K.spl1_order_independence(raw, permutations=2)["ok"])

    def test_spl2_hashseed_independence(self):
        r = K.spl2_hashseed_independence(seeds=("0", "123"))
        self.assertTrue(r["ok"], r)

    def test_spl3_fires_on_each_identity_kind(self):
        for key in ("struct_cluster_id", "template_id", "pair_id", "payload_family_id", "value_entries"):
            rows = copy.deepcopy(self.rows)
            other = next(r for r in rows if r["split"] != rows[0]["split"])
            other[key] = rows[0][key]
            g = K.gate_spl3(self.a, rows)
            self.assertFalse(g["ok"], key)
            self.assertFalse(g["rows"]["value_entry" if key == "value_entries" else key]["ok"], key)

    def test_spl3_missing_identity_and_table_conflict(self):
        rows = copy.deepcopy(self.rows)
        del rows[0]["pair_id"]
        self.assertFalse(K.gate_spl3(self.a, rows)["ok"])
        _, a = fixture()
        a.template_cluster["ghost-template"] = "no-such-cluster"
        self.assertEqual(K.gate_spl3(a)["identities_not_in_exactly_one_partition"], 1)

    def test_spl4_asserts_and_never_removes(self):
        rows = copy.deepcopy(self.rows)
        reserve = next(p for p, s in self.a.families.items() if s == S.E6_RESERVE)
        test_val = next(v for (p, v), s in self.a.values.items() if s == "INTERNAL_TEST")
        tr = next(i for i, r in enumerate(rows) if r["split"] == "TRAIN")
        rows[tr]["payload_family_id"] = reserve
        rows[tr]["value_entries"] = rows[tr]["value_entries"] + [["fx_names", test_val]]
        n = len(rows)
        g = K.gate_spl4(self.a, rows)
        self.assertFalse(g["ok"])
        self.assertEqual(g["rows_violating"], 1)
        self.assertEqual(len(g["examples"][0]["violations"]), 2)
        self.assertEqual(len(rows), n)
        with self.assertRaises(S.SplitMembershipError):
            self.a.assert_row(dict(rows[tr], template_id="not-a-template"))
        with self.assertRaises(S.SplitMembershipError):
            self.a.assert_row(dict(rows[tr], split="E6_RESERVE"))

    def test_spl5_static_imports_and_mutation(self):
        self.assertTrue(K.gate_spl5()["ok"])
        for bad in ("from canonical_request import canonicalize\n", "from parse_dataset_v4 import canonical_key\n",
                    "import v5_identities\n"):
            with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as fh:
                fh.write("import hashlib\n" + bad)
            try:
                self.assertFalse(K.gate_spl5(fh.name)["ok"], bad)
            finally:
                os.unlink(fh.name)

    def test_spl6_fires_on_text_payload_and_value_duplicates(self):
        def first(rows, split):
            return next(r for r in rows if r["split"] == split)
        rows = copy.deepcopy(self.rows)
        first(rows, "INTERNAL_TEST")["text"] = first(rows, "TRAIN")["text"].upper()     # canonical duplicate only
        self.assertFalse(K.gate_spl6(self.a, rows)["rows_text"]["ok"])
        rows = copy.deepcopy(self.rows)
        first(rows, "INTERNAL_TEST")["payload"] = first(rows, "TRAIN")["payload"].upper()
        self.assertFalse(K.gate_spl6(self.a, rows)["rows_payload"]["ok"])
        rows = copy.deepcopy(self.rows)
        te = first(rows, "INTERNAL_TEST")
        te["values"] = te["values"][:-1] + [first(rows, "TRAIN")["values"][0].lower()]
        self.assertFalse(K.gate_spl6(self.a, rows)["rows_values"]["ok"])

    def test_spl6_unreadable_rows_fail_instead_of_skipping(self):
        rows = copy.deepcopy(self.rows)
        del rows[0]["text"]
        g = K.gate_spl6(self.a, rows)
        self.assertFalse(g["ok"])
        self.assertEqual(g["rows_text"]["unreadable_rows"], 1)
        rows = copy.deepcopy(self.rows)
        rows[0]["values"] = []
        self.assertFalse(K.gate_spl6(self.a, rows)["ok"])

    def test_spl6_pool_level_conflict_is_detected_before_rendering(self):
        """A value and its case variant (one NFC + casefold key) assigned to different splits must fail,
        and the pre-render check must stop the build. Deduplication is bypassed on purpose."""
        pv = self.inp["pool_values"]
        for i in range(500):
            v = f"Casefixture {K._letters(i)}"
            pv2 = {"fx_names": pv["fx_names"] + [v, v.upper()], "fx_streets": pv["fx_streets"]}
            inp = dict(self.inp, pool_values=pv2,
                       values={p: [I.value_entry_id(p, x) for x in xs] for p, xs in pv2.items()})
            a2 = K.build_from(inp)
            s1, s2 = (a2.values[("fx_names", I.value_entry_id("fx_names", x))] for x in (v, v.upper()))
            if s1 != s2:
                break
        self.assertNotEqual(s1, s2, "no straddling pair found")
        g = K.gate_spl6(a2, pool_values=pv2)
        self.assertFalse(g["ok"])
        self.assertEqual(g["pool_values"]["equivalent_groups_spanning_splits"], 1)
        self.assertEqual(g["pool_values"]["exact_groups_spanning_splits"], 0)
        with self.assertRaises(S.StopBuild) as cm:
            K.pre_render_value_check(a2, pv2)
        self.assertEqual(cm.exception.findings[0]["code"], "VALUE_EQUIVALENCE_SPANS_SPLITS")
        self.assertTrue(K.pre_render_value_check(self.a, self.inp["pool_values"]))     # clean fixture passes

    def test_fixture_semantic_note_end_to_end(self):
        # policy B through the builder: the note changes the ledger and the config hash, never the selection
        key = I.value_equivalence_key(K.fixture_pool_values()["fx_names"][5])
        cfg = K.fixture_config(value_equivalence_semantic_notes={key: "synthetic: members differ in meaning"})
        inp = K.fixture_inputs(cfg)
        e = [x for x in inp["value_dedup"]["excluded"] if I.value_equivalence_key(x["value"]) == key]
        self.assertEqual(len(e), 1)
        self.assertEqual((e[0]["exclusion_reason"], e[0]["synonym"]), (I.VALUE_POLICY_REASON, False))
        self.assertEqual(inp["values"], self.inp["values"])
        a = K.build_from(inp)
        K.pre_render_value_check(a, inp["pool_values"])
        self.assertNotEqual(S.config_sha256(a.config), S.config_sha256(K.build_from(self.inp).config))

    def test_fixture_deduplication_ledger(self):
        vd = self.inp["value_dedup"]
        self.assertEqual(len(vd["excluded"]), K.FIXTURE_VALUE_DUPLICATES)
        for e in vd["excluded"]:
            self.assertEqual(e["exclusion_reason"], I.VALUE_DUPLICATE_REASON)
            self.assertEqual(I.value_equivalence_key(e["value"]), I.value_equivalence_key(e["representative"]["value"]))
            self.assertTrue(e["source_ref"] and e["representative"]["source_ref"])
        cross = [e for e in vd["excluded"] if e["pool_id"] != e["representative"]["pool_id"]]
        self.assertEqual([(e["pool_id"], e["representative"]["pool_id"]) for e in cross], [("fx_streets", "fx_names")])

    def test_spl6_attack_records_branch_fires(self):
        """Two records with one canonical_key whose families sit in different splits must fail. By
        construction that cannot happen, so the family lookup is patched to simulate a defect."""
        self.assertTrue(K.gate_spl6(self.a, records=self.inp["records"])["ok"])
        tr = next(f for f, s in self.a.families.items() if s == "TRAIN")
        te = next(f for f, s in self.a.families.items() if s == "INTERNAL_TEST")
        wire = next(r["payload_wire"] for r in self.inp["records"] if I.payload_family_id(r["payload_wire"]) == tr)
        recs = [{"payload_wire": wire}, {"payload_wire": wire.upper()}]
        real = I.payload_family_id
        with mock.patch.object(K.I, "payload_family_id", lambda w: te if w == wire.upper() else real(w)):
            g = K.gate_spl6(self.a, records=recs)
        self.assertFalse(g["ok"])
        self.assertEqual(g["attack_records"]["canonical_groups_spanning"], 1)

    def test_spl7_fires_on_a_reserve_family_in_a_row(self):
        reserve = next(p for p, s in self.a.families.items() if s == S.E6_RESERVE)
        rows = copy.deepcopy(self.rows)
        rows[0]["payload_family_id"] = reserve
        self.assertFalse(K.gate_spl7(self.a, rows)["ok"])
        # a reserve payload under another family's id (or none) is caught by recomputing the family
        wire = next(r["payload_wire"] for r in self.inp["records"]
                    if I.payload_family_id(r["payload_wire"]) in self.a.family_member_keys[reserve])
        for pf in (rows[1]["payload_family_id"], None):
            rows = copy.deepcopy(self.rows)
            rows[0]["payload"], rows[0]["payload_family_id"] = wire, pf
            g = K.gate_spl7(self.a, rows)
            self.assertFalse(g["ok"])
            self.assertEqual((g["rows_payload_family_mismatch"], g["rows_with_reserve_family"]), (1, 1))

    def test_spl8_fires_on_a_hand_set_flag(self):
        inp, a = fixture()
        a.evaluability["fx_gamma"]["flag"] = S.EVALUABLE
        self.assertFalse(K.gate_spl8(a)["ok"])

    def test_spl9_fires_until_merges_are_declared(self):
        recs = []
        for i in range(150):
            w = K.fixture_word("spl9", i)
            recs.append({"record_id": f"a{i}", "status": "ACCEPTED", "payload_wire": f"tok{w} com{w} ext{w}",
                         "dedup_scope": "fx_alpha", "native_forms": []})
            recs.append({"record_id": f"b{i}", "status": "ACCEPTED", "payload_wire": f"tok{w} com{w} ext{w} mor{w}",
                         "dedup_scope": "fx_alpha", "native_forms": []})
        for r in recs:
            r["canonical_key"] = canonical_key(r["payload_wire"])
        cfg = K.fixture_config(family_merges=[])
        inp = dict(self.inp, config=cfg, families=I.build_families(recs), records=recs)
        g = K.gate_spl9(K.build_from(inp))
        self.assertEqual(g["status"], "FAIL")
        self.assertGreater(g["cross_partition_family_pairs"], 0)
        merges = I.propose_merges(I.family_near_duplicate_pairs(inp["families"]))
        self.assertEqual(len(merges), 150)
        self.assertTrue(all(len(m) == 2 for m in merges))                # no chaining between unrelated words
        cfg = K.fixture_config(family_merges=merges)
        inp = dict(inp, config=cfg, families=I.build_families(recs, merges))
        a = K.build_from(inp)
        self.assertEqual(K.gate_spl9(a)["status"], "PASS")
        self.assertEqual(len(a.family_merges), 150)

    def test_spl9_reserve_counts_as_a_partition(self):
        # I-11: a near-duplicate of an E6 reserve family placed in a split fails SPL-9
        a = copy.copy(self.a)
        reserve = next(p for p, s in self.a.families.items() if s == S.E6_RESERVE)
        train = next(p for p, s in self.a.families.items() if s == "TRAIN")
        a.family_member_keys = dict(self.a.family_member_keys, **{train: (reserve + "x",)})
        self.assertEqual(K.gate_spl9(a)["status"], "FAIL")

    def test_spl9_unobservable_short_keys_block_never_pass(self):
        inp = K.fixture_inputs(vocab_config())
        fs = [fam(K.fixture_word("obs", i)) for i in range(200)] + [fam("id", ("cat_a",)), fam(";id", ("cat_a",))]
        g = K.gate_spl9(S.build(inp["config"], inp["table"], fs, inp["values"]))
        self.assertEqual((g["ok"], g["status"]), (False, "BLOCKED_UNOBSERVABLE"))
        self.assertEqual(g["unobservable_keys"], [";id", "id"])

    def test_spl9_cross_split_pair_fails_before_unobservable_blocks(self):
        inp = K.fixture_inputs(vocab_config())
        fs = [fam(K.fixture_word("obs", i)) for i in range(200)] + [fam("id", ("cat_a",))]
        a = S.build(inp["config"], inp["table"], fs, inp["values"])
        p, q = sorted(a.families)[:2]
        a.family_member_keys[p] = ("union select aaaa from bbbb",)
        a.family_member_keys[q] = ("union select aaaa from bbbbb",)
        if a.families[p] == a.families[q]:                        # make sure the pair straddles two partitions
            a.families[q] = S.TRAIN if a.families[p] != S.TRAIN else S.INTERNAL_TEST
        g = K.gate_spl9(a)
        self.assertEqual((g["ok"], g["status"]), (False, "FAIL"))      # a real leak is reported as FAIL
        self.assertEqual(g["unobservable_keys"], ["id"])


class SPL2Negative(unittest.TestCase):
    """SPL-2 must FAIL on a builder whose output depends on PYTHONHASHSEED, and PASS on the real one.
    The defective builder exists only inside a temporary directory of this test."""

    BAD = (
        "import sys\n"
        "sys.path.insert(0, {dataset!r})\n"
        "import v5_split as S, v5_split_checks as K\n"
        "S.ranked = lambda kind, ids: sorted(ids, key=hash)   # str hash depends on PYTHONHASHSEED\n"
        "sys.exit(K.main(['fixture', '--quiet'] + sys.argv[1:]))\n")
    GOOD = (
        "import sys\n"
        "sys.path.insert(0, {dataset!r})\n"
        "import v5_split_checks as K\n"
        "sys.exit(K.main(['fixture', '--quiet'] + sys.argv[1:]))\n")

    def run_script(self, body):
        with tempfile.TemporaryDirectory() as t:
            path = os.path.join(t, "builder.py")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(body.format(dataset=os.path.join(REPO, "scripts", "dataset")))
            return K.spl2_hashseed_independence(seeds=("1", "2", "3"), script=path)

    def test_seed_dependent_builder_fails(self):
        r = self.run_script(self.BAD)
        self.assertFalse(r["ok"])
        self.assertGreater(r["distinct_assignments"], 1)

    def test_real_builder_passes_through_the_same_harness(self):
        r = self.run_script(self.GOOD)
        self.assertTrue(r["ok"])
        self.assertEqual(r["distinct_assignments"], 1)


class CodeVersions(unittest.TestCase):
    def test_config_must_name_the_rules_this_code_implements(self):
        with self.assertRaises(S.InvalidConfig):
            K.check_code_versions(K.fixture_config(pfid_rules_version="pfid-rules/v2"))
        with self.assertRaises(S.InvalidConfig):
            K.check_code_versions(K.fixture_config(value_equivalence="nfc/v0"))
        K.check_code_versions(K.fixture_config())


class HybridEvaluability(unittest.TestCase):
    """I-8, hybrid reading (owner ruling, stage 3 round 3). Strata run in category order; an attempt
    counts the stratum's own non-reserve families plus the category's families already placed by an
    earlier stratum (never a reserve one). The round-2 stratum-local reading is recomputed here as a
    reference only, to show that every fixture below separates the two readings where stated."""

    @staticmethod
    def local_outcome(fs, cat, policy=None):
        """Round-2 reading (superseded): the attempt sees only the stratum's own families."""
        own = [f for f in fs if f.stratum_category == cat]
        _, rep, _ = S.assign_families(own, policy)
        return rep[cat]["outcome"]

    def shared(self, n, cats=("cat_a", "cat_b"), native_first=0, prefix="a"):
        return [fam(f"{prefix}{i:04d}", cats, ("double_encoding",) if i < native_first else ()) for i in range(n)]

    def build(self, fs, **cfg):
        inp = K.fixture_inputs(vocab_config(**cfg))
        return S.build(inp["config"], inp["table"], fs, inp["values"])

    def test_evaluable_case_differs_from_the_local_reading(self):
        fs = self.shared(200) + fams(200, "cat_a", "x") + fams(120, "cat_b", "b")
        assign, rep, fx = S.assign_families(fs, None)
        self.assertEqual(self.local_outcome(fs, "cat_b"), S.NOT_EVALUABLE)      # 120 own: TEST 24 < 30
        r = rep["cat_b"]
        self.assertEqual(r["outcome"], S.ATTEMPT_NO_RESERVE)
        self.assertEqual(r["foreign"]["n"], 200)
        self.assertEqual(r["attempt_2"]["counted"]["total"], 120 + r["foreign"]["in_splits"])
        self.assertEqual(r["attempt_2"]["counted"][S.INTERNAL_TEST], 24 + r["foreign"][S.INTERNAL_TEST])
        self.assertEqual((r["INTERNAL_TEST"], r["VALIDATION"], r["TRAIN"]), S.cuts(120))   # own cuts unchanged
        ev = S.category_evaluability(fx, assign)["cat_b"]
        self.assertEqual(ev["families_in_splits"], r["attempt_2"]["counted"]["total"])      # no double count
        self.assertEqual(ev[S.INTERNAL_TEST], r["attempt_2"]["counted"][S.INTERNAL_TEST])
        self.assertEqual(ev["flag"], S.EVALUABLE)
        a = self.build(fs)
        self.assertFalse(any(d["diverges"] for d in a.outcome_vs_flag().values()))

    def test_reserve_case_differs_from_the_local_reading(self):
        # cat_b: 400 own, 300 with a native form (forced > R = 32), policy reserve_equals_forced. Alone, the
        # 100 remaining give TEST 20 < 30 (attempt 1 rejected); with cat_a's 200 placed families it holds.
        fs = self.shared(200) + fams(200, "cat_a", "x") + fams(400, "cat_b", "b", native_first=300)
        policy = "reserve_equals_forced"
        self.assertEqual(self.local_outcome(fs, "cat_b", policy), S.ATTEMPT_NO_RESERVE)
        assign, rep, _ = S.assign_families(fs, policy)
        r = rep["cat_b"]
        self.assertEqual(r["outcome"], S.ATTEMPT_WITH_RESERVE)
        self.assertEqual((r["R"], r["reserve_size"], r["attempt_1"]["remaining"], r["attempt_1"]["internal_test"]),
                         (32, 300, 100, 20))                          # R, reserve and cuts on own families only
        self.assertGreaterEqual(r["attempt_1"]["counted"][S.INTERNAL_TEST], 30)
        reserve_b = {p for p, x in assign.items() if x == S.E6_RESERVE and p.startswith("b")}
        self.assertEqual(reserve_b, {f"b{i:05d}" for i in range(300)})            # exactly the forced families
        self.assertFalse(any(d["diverges"] for d in self.build(fs, e6={"reserve_percent": 8, "min_reserve_families": 30,
                                                                      "forced_overflow_policy": policy}).outcome_vs_flag().values()))

    def test_not_evaluable_case(self):
        fs = self.shared(20) + fams(200, "cat_a", "x") + fams(60, "cat_b", "b")
        assign, rep, fx = S.assign_families(fs, None)
        self.assertEqual(rep["cat_b"]["outcome"], S.NOT_EVALUABLE)
        self.assertEqual(self.local_outcome(fs, "cat_b"), S.NOT_EVALUABLE)
        self.assertEqual({assign[f"b{i:05d}"] for i in range(60)}, {S.TRAIN})
        self.assertEqual(S.category_evaluability(fx, assign)["cat_b"]["flag"], S.NOT_EVALUABLE)

    def test_foreign_reserve_families_never_count(self):
        # all 400 cat_a families also occur in cat_b; cat_a reserves 32 of them; cat_b has 10 own families
        fs = self.shared(400) + fams(10, "cat_b", "b")
        assign, rep, fx = S.assign_families(fs, None)
        f = rep["cat_b"]["foreign"]
        self.assertEqual((f["n"], f["reserve"], f["in_splits"]), (400, 32, 368))
        self.assertEqual(rep["cat_b"]["attempt_2"]["counted"]["total"], 368 + 10)
        ev = S.category_evaluability(fx, assign)["cat_b"]
        self.assertEqual((ev["families_in_splits"], ev["reserve"]), (378, 32))

    def test_category_without_own_stratum(self):
        fs = self.shared(200)
        assign, rep, fx = S.assign_families(fs, None)
        self.assertEqual(rep["cat_b"]["outcome"], "no_own_stratum")
        self.assertTrue(rep["cat_b"]["evaluable"])
        self.assertEqual(S.category_evaluability(fx, assign)["cat_b"]["flag"], S.EVALUABLE)
        self.assertFalse(self.build(fs).outcome_vs_flag()["cat_b"]["diverges"])

    def test_earlier_strata_are_never_changed_and_each_family_is_assigned_once(self):
        cat_a = self.shared(200) + fams(200, "cat_a", "x")
        alone, _, _ = S.assign_families(cat_a, None)
        fs = cat_a + fams(120, "cat_b", "b")
        assign, _, _ = S.assign_families(fs, None)
        self.assertEqual({p: assign[p] for p in alone}, alone)       # cat_b's stratum moves nothing of cat_a
        self.assertEqual(sorted(assign), sorted(f.payload_family_id for f in fs))

    def test_order_independent(self):
        import random
        fs = self.shared(200) + fams(200, "cat_a", "x") + fams(120, "cat_b", "b", native_first=5)
        ref = S.assign_families(fs, None)[:2]
        for seed in range(4):
            xs = list(fs)
            random.Random(seed).shuffle(xs)
            self.assertEqual(S.assign_families(xs, None)[:2], ref)

    def test_spl8_fails_on_an_injected_divergence(self):
        a = self.build(self.shared(200) + fams(200, "cat_a", "x") + fams(120, "cat_b", "b"))
        self.assertTrue(K.gate_spl8(a)["ok"])
        a.family_report["cat_b"]["outcome"] = S.NOT_EVALUABLE             # a hand-set stratum outcome
        g = K.gate_spl8(a)
        self.assertFalse(g["ok"])
        self.assertEqual(g["outcome_flag_divergences"], ["cat_b"])


class Cli(unittest.TestCase):
    def test_fixture_command_writes_passing_gates(self):
        with tempfile.TemporaryDirectory() as t:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(K.main(["fixture", "--out", t, "--quiet"]), 0)
            with open(os.path.join(t, "manifest.json"), encoding="utf-8") as fh:
                m = json.load(fh)
            self.assertTrue(all(g["ok"] for g in m["gates"].values()))
            self.assertIn("SYNTHETIC", m["fixture"])

    def test_census_counts_on_a_small_synthetic_pool(self):
        recs = K.fixture_records()[:40]
        recs.append({"record_id": "empty1", "status": "ACCEPTED", "payload_wire": "%0a%0d", "canonical_key": "",
                     "dedup_scope": "fx_alpha", "native_forms": []})
        with tempfile.TemporaryDirectory() as t:
            ap = os.path.join(t, "attack_pool.jsonl")
            with open(ap, "w") as fh:
                fh.write("".join(json.dumps(r) + "\n" for r in recs))
            bd = os.path.join(t, "benign")
            os.makedirs(bd)
            with open(os.path.join(bd, "streets.jsonl"), "w") as fh:
                for i, v in enumerate(("Elm Street", "ELM STREET", "Oak Road")):
                    fh.write(json.dumps({"value": v, "value_entry_id": I.value_entry_id("streets", v),
                                         "source_ref": f"s#{i}", "flags": []}) + "\n")
            res = K.census(ap, bd, semantic_notes={}, vocabulary=[c for c, _ in K.FIXTURE_CATEGORIES])
        self.assertEqual([r["record_id"] for r in res["records_with_empty_family_key"]], ["empty1"])
        self.assertEqual(res["values"]["per_pool"]["names_family"], {"status": "BLOCKED (no pool file)"})
        self.assertEqual((res["values"]["groups"], res["values"]["excluded_total"]), (1, 1))
        self.assertEqual(res["values"]["per_pool"]["streets"]["n_after"], 2)
        self.assertFalse(res["values"]["per_pool"]["streets"]["meets_minimum_20"])
        dumped = json.dumps(res)
        for text in ("Elm Street", "ELM STREET", "Oak Road"):
            self.assertNotIn(text, dumped)                               # no benign value text
        self.assertNotIn('"split"', dumped)                              # no assignment of any identity
        with self.assertRaises(I.IdentityError):                         # unknown note keys are refused, never filtered
            with tempfile.TemporaryDirectory() as t2:
                os.makedirs(os.path.join(t2, "benign"))
                with open(os.path.join(t2, "benign", "streets.jsonl"), "w") as fh:
                    fh.write(json.dumps({"value": "Oak Road", "value_entry_id": I.value_entry_id("streets", "Oak Road"),
                                         "source_ref": "s#0", "flags": []}) + "\n")
                with open(os.path.join(t2, "attack_pool.jsonl"), "w") as fh:
                    fh.write("".join(json.dumps(r) + "\n" for r in recs[:-1]))
                K.census(os.path.join(t2, "attack_pool.jsonl"), os.path.join(t2, "benign"), semantic_notes={"no such value": "x"},
                         vocabulary=[c for c, _ in K.FIXTURE_CATEGORIES])
        ids = {r["record_id"] for r in recs} - {"empty1"}
        self.assertFalse(any(i in dumped for i in ids))

    def test_outputs_never_overwrite_stage2_pools(self):
        for d in ("attack", "benign", "raw"):
            with self.assertRaises(SystemExit):
                K.guard_output(os.path.join(K.C.DEFAULT_OUT_DIR, d, "attack_pool.jsonl"))
        with self.assertRaises(SystemExit):
            K.guard_output("/tmp/external_v1/x.json")
        self.assertTrue(K.guard_output(os.path.join(K.C.DEFAULT_OUT_DIR, "stage3", "census.json")))


if __name__ == "__main__":
    unittest.main()
