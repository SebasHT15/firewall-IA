"""Stage-4 constructive-generator integration tests (issue #74).

Synthetic, harmless fixtures only (`v5_fixture`): abstract attack markers with NO exploit content,
synthetic benign pools. These tests exercise the STRUCTURE of the pipeline — pairs, the one-leaf
change, identity consistency, canonical rendering, label / exclusion handling, reproducibility and
the SPL / M / ENC invariants that synthetic data can verify. They assert nothing about real attack
detection. Anything that would need real payloads, a pending methodological decision or protected
data is left as an explicit skip with its dependency named — never replaced by a synthetic PASS.

    python3 -m unittest tests.test_v5_generator -v
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from collections import Counter
from fractions import Fraction

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "scripts", "dataset"))
sys.path.insert(0, os.path.join(REPO, "data_plane"))

import canonical_request as cr  # noqa: E402
import v5_catalog as K  # noqa: E402
import v5_fixture as F  # noqa: E402
import v5_generator as G  # noqa: E402
import v5_labels as L  # noqa: E402
import v5_identities as I  # noqa: E402
import v5_oracle as O  # noqa: E402
import v5_render as R  # noqa: E402
import v5_rebalance as V9  # noqa: E402
import v5_split as S  # noqa: E402
from parse_dataset_v4 import canonical_key  # noqa: E402

FIXTURE_PY = os.path.join(REPO, "scripts", "dataset", "v5_fixture.py")

_BUILD = None


def shared_build():
    """Build the clean fixture once and reuse it across the structural test classes."""
    global _BUILD
    if _BUILD is None:
        world, gen, gates = F.generate()
        _BUILD = (world, gen, gates)
    return _BUILD


class _SharedFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.world, cls.gen, cls.gates = shared_build()
        cls.rows = cls.gen["rows"]
        cls.split_rows = [r for r in cls.rows if r["meta"]["disposition"] == "split"]


class FixtureBuild(_SharedFixture):
    """The gates are the backbone of the structural circuit."""

    def test_all_gates_pass(self):
        summary = {k: (v if isinstance(v, bool) else v.get("ok")) for k, v in self.gates.items()}
        self.assertTrue(self.gates["ok"], json.dumps(summary))

    def test_pairs_generated_in_all_three_splits(self):
        splits = {r["meta"]["split"] for r in self.split_rows}
        self.assertEqual(splits, set(S.SPLITS), "a rich category must place families in every split")

    def test_no_abandonment_or_shortfall_in_the_clean_fixture(self):
        self.assertEqual(dict(self.gen["abandoned"]), {})
        self.assertEqual(self.gen["shortfalls"], [])
        self.assertEqual(dict(self.gen["pairs"]), {"complete": len(self.split_rows) // 2})


class PairIntegrity(_SharedFixture):
    def test_cm2_gate(self):
        g = self.gates["C-M2"]
        self.assertTrue(g["ok"], g["examples"])
        self.assertGreater(g["pairs"], 0)

    def test_cm2_flags_a_second_difference(self):
        """verify_pair is clean on a real pair and flags a difference outside the attacked leaf."""
        pairs = {}
        for r in self.split_rows:
            pairs.setdefault(r["meta"]["pair_id"], {})[r["meta"]["pair_role"]] = r
        d = next(d for d in pairs.values() if set(d) == {"benign", "twin"})
        b, t = d["benign"], d["twin"]
        self.assertEqual(G.verify_pair(b["meta"], t["meta"], b["text"], t["text"]), [])
        tampered = "X" + t["text"][1:]                      # mutate the method token (outside every leaf)
        self.assertTrue(G.verify_pair(b["meta"], t["meta"], b["text"], tampered))

    def test_every_complete_pair_is_allow_plus_block(self):
        pairs = {}
        for r in self.split_rows:
            pairs.setdefault(r["meta"]["pair_id"], {})[r["meta"]["pair_role"]] = r["meta"]
        for pid, d in pairs.items():
            self.assertEqual(set(d), {"benign", "twin"})
            self.assertEqual(d["benign"]["label"], L.ALLOW)
            self.assertEqual(d["twin"]["label"], L.BLOCK)
            self.assertEqual(d["benign"]["output"], L.ALLOW_OUTPUT)
            self.assertTrue(d["twin"]["output"].startswith("BLOCK | "))

    def test_exactly_one_leaf_differs_in_the_canonical_text(self):
        pairs = {}
        for r in self.split_rows:
            pairs.setdefault(r["meta"]["pair_id"], {})[r["meta"]["pair_role"]] = r
        for pid, d in pairs.items():
            b, t = d["benign"], d["twin"]
            tb, tt = b["text"], t["text"]
            self.assertNotEqual(tb, tt)
            sid = b["meta"]["attacked_slot"]
            # one contiguous difference, inside the attacked leaf's span in both texts
            p = 0
            while p < min(len(tb), len(tt)) and tb[p] == tt[p]:
                p += 1
            s = 0
            while s < min(len(tb), len(tt)) - p and tb[-1 - s] == tt[-1 - s]:
                s += 1
            for row in (b, t):
                a0, a1 = row["meta"]["leaf_spans"][sid]
                self.assertTrue(a0 <= p and len(row["text"]) - s <= a1,
                                f"difference escapes the attacked leaf in {pid}")
            # every non-attacked leaf renders identically in both rows
            for k, (a0, a1) in b["meta"]["leaf_spans"].items():
                if k != sid:
                    c0, c1 = t["meta"]["leaf_spans"][k]
                    self.assertEqual(tb[a0:a1], tt[c0:c1], f"non-attacked leaf {k} differs in {pid}")


class IdentityConsistency(_SharedFixture):
    def test_spl_gates_on_generated_rows(self):
        for name, g in self.gates["SPL"].items():
            self.assertTrue(g["ok"], f"{name}: {g}")

    def test_assert_row_accepts_every_split_row_and_rejects_tampering(self):
        a = self.world.assignment
        r = self.split_rows[0]["meta"]
        row = {"split": r["split"], "struct_cluster_id": r["struct_cluster_id"], "template_id": r["template_id"],
               "payload_family_id": r["payload_family_id"], "value_entries": [tuple(x) for x in r["value_entries"]]}
        a.assert_row(row)                                   # belongs to its split
        other = next(s for s in S.SPLITS if s != r["split"])
        with self.assertRaises(S.SplitMembershipError):
            a.assert_row({**row, "split": other})

    def test_payload_family_matches_the_recomputed_family(self):
        for r in self.split_rows:
            if r["meta"]["pair_role"] == "twin":
                rec = self.world.records[r["meta"]["payload_record_id"]]
                self.assertEqual(r["meta"]["payload_family_id"], I.payload_family_id(rec["payload_wire"]))



class CanonicalRepresentation(_SharedFixture):
    def test_every_split_row_is_accept_and_round_trips(self):
        for r in self.split_rows:
            text = r["text"]
            self.assertIsNotNone(text)
            res = cr.canonicalize(cr.parse_canonical(text), self.world.limits)   # I3
            self.assertEqual(res.text, text)
            self.assertEqual(res.outcome, cr.ACCEPT)

    def test_only_content_type_header_and_no_truncation(self):
        for r in self.split_rows:
            lines = r["text"].split("\n")
            self.assertTrue(lines[0].endswith(" HTTP/1.1"))
            if r["meta"]["media_type"] is None:
                self.assertTrue(len(lines) == 1 or lines[1] == "")
            else:
                self.assertTrue(lines[1].startswith("Content-Type: "))
            self.assertLessEqual(r["meta"]["tokens"], self.world.gen_cfg["token_budget"]["B"])

    def test_json_bodies_parse_under_their_declared_type(self):
        for r in self.split_rows:
            if r["meta"]["carrier"] == "json":
                json.loads(r["text"].split("\n\n", 1)[1])      # A-G2


class Reproducibility(_SharedFixture):
    def test_two_in_process_builds_are_identical(self):
        _, gen2, _ = F.generate()
        a = [r["meta"] for r in self.rows]
        b = [r["meta"] for r in gen2["rows"]]
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))

    def test_cli_byte_identical_across_pythonhashseed(self):
        shas = {}
        with tempfile.TemporaryDirectory() as tmp:
            for seed in ("0", "97", "random"):
                out = os.path.join(tmp, f"o{seed}")
                env = dict(os.environ, PYTHONHASHSEED=seed)
                subprocess.run([sys.executable, FIXTURE_PY, "generate", "--out", out, "--quiet"],
                               check=True, env=env, capture_output=True, timeout=600)
                shas[seed] = {n: F.C.sha256_file(os.path.join(out, n)) for n in
                              ("manifest.json", "rows.TRAIN.meta.jsonl", "assignment/manifest.json")}
        first = next(iter(shas.values()))
        self.assertTrue(all(v == first for v in shas.values()), shas)


class LabelsAndExclusions(unittest.TestCase):
    """Label classes and the simulated exclusion paths, via the label functions and small worlds."""

    @classmethod
    def setUpClass(cls):
        cls.table = L.load_policy_table()
        cls.oracle = O.BenignOracle(F.fixture_attack_records(), O.OracleConfig(12, "FIXTURE"))
        cls.basis = L.AttackBasis("fixture_synthetic")

    def rec(self, cat, reason, **over):
        wire = f"synthmark {cat} 0001"
        r = {"record_id": "r1", "status": "ACCEPTED", "synthetic": True, "payload_wire": wire,
             "payload_logical": wire, "payload_wire_form": R.PLAIN, "canonical_key": canonical_key(wire),
             "dedup_scope": cat, "native_forms": [], "reason_string": reason}
        r.update(over)
        return r

    def test_benign_leaf_verified_allow(self):
        lab = L.label_benign_leaf("free_string", "Zqsynthname", L.DATA, None, self.table)
        self.assertEqual((lab.status, lab.label, lab.rule), (L.VERIFIED, L.ALLOW, L.RULE_BENIGN))

    def test_oracle_reject_excludes_the_benign_leaf(self):
        lab = L.label_benign_leaf("free_string", "whatever", L.DATA, "exact_canonical_key", self.table)
        self.assertEqual((lab.status, lab.exclusion), (L.EXCLUDED, L.ORACLE_REJECT))

    def test_attack_leaf_verified_block_with_v4_reason(self):
        lab = L.label_attack_leaf(self.rec("SQL Injection", "SQL injection payload detected."),
                                  "SQL Injection", "free_string", "synthmark", L.DATA, self.table,
                                  self.basis, ["SQL Injection"])
        self.assertEqual((lab.status, lab.label, lab.rule), (L.VERIFIED, L.BLOCK, L.RULE_ATTACK))
        self.assertIn(lab.reason, L.BLOCK_REASONS)

    def test_attack_leaf_untrained_category_out_of_scope(self):
        lab = L.label_attack_leaf(self.rec("SQL Injection", "SQL injection payload detected."),
                                  "SQL Injection", "free_string", "x", L.DATA, self.table, self.basis, ["XSS Injection"])
        self.assertEqual((lab.status, lab.exclusion, lab.exclusion_kind), (L.EXCLUDED, L.OUT_OF_SCOPE, "category"))

    def test_attack_leaf_audit_incorrect_is_audit_reject(self):
        rec = self.rec("SQL Injection", "SQL injection payload detected.", audit_verdict="INCORRECT")
        lab = L.label_attack_leaf(rec, "SQL Injection", "free_string", "x", L.DATA, self.table, self.basis,
                                  ["SQL Injection"])
        self.assertEqual((lab.status, lab.exclusion), (L.EXCLUDED, L.AUDIT_REJECT))

    def test_no_attack_pool_item_is_allow_m6(self):
        for cat, reason, stype in (("SQL Injection", "SQL injection payload detected.", "free_string"),
                                   ("path_file_access", "Path traversal attack detected.", "path_file")):
            lab = L.label_attack_leaf(self.rec(cat, reason), cat, stype, "x", L.DATA, self.table, self.basis, [cat])
            self.assertEqual(lab.label, L.BLOCK)            # VERIFIED BLOCK, never ALLOW and never unlabelled
            self.assertEqual(lab.status, L.VERIFIED)

    def test_policy_category_url_classes(self):
        rec = self.rec("Server Side Request Forgery", "irrelevant")
        block = L.label_attack_leaf(rec, "Server Side Request Forgery", "url", "gopher://synthetic.invalid/x",
                                    L.DATA, self.table, self.basis, ["Server Side Request Forgery"])
        self.assertEqual((block.status, block.label, block.policy_id), (L.POLICY_DEFINED, L.BLOCK, "POL-URL-SCHEME"))
        loop = L.label_attack_leaf(rec, "Server Side Request Forgery", "url", "http://127.0.0.1/x", L.DATA,
                                   self.table, self.basis, ["Server Side Request Forgery"])
        self.assertEqual((loop.status, loop.exclusion, loop.slice), (L.EXCLUDED, L.INSUFFICIENT_CONTEXT, L.CTX_LOOPBACK))

    def test_m8_label_functions_take_no_field_name(self):
        self.assertTrue(L.check_m8_signature()["ok"])

    def test_m8_renaming_fields_does_not_change_labels(self):
        """Vary the field name within one role and assert the label is unchanged; only the ROLE
        (navigation vs data), not the name string, may change anything — and only inclusion (M-8)."""
        t = self.table
        # two distinct DATA-role names -> the same role -> byte-identical label for the same value
        self.assertEqual(L.slot_role("q", t), L.DATA)
        self.assertEqual(L.slot_role("search", t), L.DATA)
        v = "Zqsynthvalue"
        a = L.label_benign_leaf("free_string", v, L.slot_role("q", t), None, t)
        b = L.label_benign_leaf("free_string", v, L.slot_role("search", t), None, t)
        self.assertEqual((a.label, a.status, a.rule, a.policy_id), (b.label, b.status, b.rule, b.policy_id))
        # a public URL under several distinct DATA-role url names: all identical POL-URL-PUBLIC ALLOW
        u = "https://www.example.com/x"
        labels = {nm: L.label_benign_leaf("url", u, L.slot_role(nm, t), None, t) for nm in ("website", "homepage", "callback")}
        for nm, lab in labels.items():
            self.assertEqual((lab.status, lab.policy_id, lab.label), (L.POLICY_DEFINED, "POL-URL-PUBLIC", L.ALLOW), nm)
        # the SAME url under a navigation-role name differs only by inclusion (excluded), never by the name itself
        nav = L.label_benign_leaf("url", u, L.slot_role("redirect", t), None, t)
        self.assertEqual((nav.status, nav.exclusion, nav.slice), (L.EXCLUDED, L.INSUFFICIENT_CONTEXT, L.CTX_OPEN_REDIRECT))

    def test_combine_precedence_exclusion_wins(self):
        excl = L.LeafLabel(None, L.EXCLUDED, exclusion=L.INSUFFICIENT_CONTEXT, exclusion_kind=L.CTX_LOOPBACK,
                           slice=L.CTX_LOOPBACK)
        allow = L.LeafLabel(L.ALLOW, L.VERIFIED, L.RULE_BENIGN)
        self.assertIs(L.combine([allow, excl], self.table), excl)


class OverLimitAndExclusionDisposition(unittest.TestCase):
    def test_over_limit_excludes_without_truncation(self):
        world = F.build_world(gen_cfg=F.fixture_gen_config(
            token_budget={"B": 5, "counter": "utf8_bytes_upper_bound", "status": "PROPOSED"}))
        gen = G.generate(world)
        over = [r for r in gen["rows"] if r["meta"]["exclusion_reason"] == L.OVER_LIMIT]
        self.assertTrue(over, "a 5-token budget must exclude rows")
        for r in over:
            self.assertEqual(r["meta"]["label_status"], L.EXCLUDED)
            self.assertIsNone(r["text"])                   # no truncation, ever (§5.5)
            self.assertIsNone(r["meta"]["output"])

    def test_oracle_reject_excludes_benign_and_withholds_the_twin(self):
        """End to end: in a single-free_string-slot (text) template with replace placement, a benign
        value that collides with an attack canonical_key is ORACLE_REJECT, so the benign row is EXCLUDED
        (counted, ORACLE_REJECT) and its BLOCK twin is withheld. The exclusion+withheld paths run with data."""
        from parse_dataset_v4 import canonical_key
        n = 250                                            # >= 20 per split after the cuts
        wires = [f"synthmark sqli {i:04d} collide" for i in range(n)]
        recs = [{"record_id": f"c-{i:04d}", "status": "ACCEPTED", "synthetic": True, "payload_wire": w,
                 "payload_logical": w, "payload_wire_form": R.PLAIN, "canonical_key": canonical_key(w),
                 "dedup_scope": "SQL Injection", "native_forms": [], "reason_string": "SQL injection payload detected.",
                 "source_file": "SYNTHETIC/collide.txt"} for i, w in enumerate(wires)]
        text_tpls = [{"name": f"t-collide-{i}", "cluster": "t-collide", "carrier": "text", "method": "POST",
                      "path": ["notes", f"v{i}"], "text": {"type": "free_string"}} for i in range(4)]
        with open(K.DEFAULT_LEXICON, encoding="utf-8") as fh:
            lexicon = json.load(fh)
        catalog = K.catalog_from_objects({"schema": K.CATALOG_SCHEMA, "templates": text_tpls}, lexicon)
        split_cfg = F.fixture_split_config(carrier_strata=list(K.CARRIERS), pools=["names_given"],
                                           value_pool_precedence=["names_given"],
                                           category_vocabulary={"source": "stage2_dedup_scope",
                                                                "order": "python_str_code_point",
                                                                "categories": ["SQL Injection"]})
        gen_cfg = F.fixture_gen_config(
            trained_categories={"categories": ["SQL Injection"], "status": "PROPOSED"},
            placement_shares={"replace": 1, "prefix": 0, "suffix": 0, "embedded": 0, "status": "PROPOSED"})
        world = F.build_world(catalog=catalog, records=recs, pool_values={"names_given": list(wires)},
                              split_cfg=split_cfg, gen_cfg=gen_cfg)
        self.assertEqual(world.oracle.check(wires[0], "free_string"), "exact_canonical_key")
        gen = G.generate(world)
        by_pair = {}
        for r in gen["rows"]:
            by_pair.setdefault(r["meta"]["pair_id"], {})[r["meta"]["pair_role"]] = r["meta"]
        self.assertEqual(dict(gen["pairs"]), {"incomplete": sum(1 for _ in by_pair)})   # no pair completes
        self.assertTrue(by_pair)
        for pid, d in by_pair.items():
            self.assertEqual(d["benign"]["disposition"], "excluded_counted")
            self.assertEqual(d["benign"]["exclusion_reason"], L.ORACLE_REJECT)
            self.assertIsNone(d["benign"]["text"] if "text" in d["benign"] else None)
            self.assertEqual(d["twin"]["label"], L.BLOCK)
            self.assertEqual(d["twin"]["disposition"], "withheld_sibling")


class EncodingControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.world, cls.gen, cls.gates = F.generate()

    def test_enc_gate_and_enc7_self_test(self):
        self.assertTrue(self.gates["ENC"]["ok"], self.gates["ENC"])
        self.assertTrue(self.gates["ENC-7"]["ok"], self.gates["ENC-7"])
        self.assertTrue(self.gates["ENC-7"]["enc3_fired"] and self.gates["ENC-7"]["enc4_feature_moved"])

    def test_held_out_form_detection(self):
        self.assertIn("double_encoding", R.held_out_forms("GET /a?x=%2541 HTTP/1.1\n"))
        self.assertEqual(R.held_out_forms("GET /a?x=%41 HTTP/1.1\n"), [])

    def test_enc1_plain_payload_encoded_once(self):
        enc = R.encode_plain("a b&c", "query", R.EncoderProfile())
        self.assertEqual(enc, "a%20b%26c")                 # one decode returns the logical value

    def test_enc3_non_native_held_out_form_abandons_the_pair(self):
        """A pre-encoded marker carrying %2541 but NOT declaring double_encoding is abandoned (never emitted)."""
        recs = []
        for i in range(5):
            wire = f"synthmark%2541sqli{i:04d}"             # abstract; %2541 is a (non-native, undeclared) double form
            recs.append({"record_id": f"bad-{i}", "status": "ACCEPTED", "synthetic": True, "payload_wire": wire,
                         "payload_logical": wire, "payload_wire_form": R.PRE_ENCODED,
                         "canonical_key": canonical_key(wire), "dedup_scope": "SQL Injection",
                         "native_forms": [], "reason_string": "SQL injection payload detected."})
        world = F.build_world(records=recs,
                              gen_cfg=F.fixture_gen_config(trained_categories={"categories": ["SQL Injection"],
                                                                               "status": "PROPOSED"}))
        gen = G.generate(world)
        self.assertEqual(dict(gen["pairs"]), {}, "every pair must be abandoned by ENC-3")
        self.assertTrue(any(k.startswith("enc3_non_native_held_out_form") for k in gen["abandoned"]),
                        dict(gen["abandoned"]))


class ControlledErrors(unittest.TestCase):
    def test_generator_config_refusals(self):
        with self.assertRaises(G.GeneratorConfigError):
            G.validate_gen_config(F.fixture_gen_config(mode="nope"))
        with self.assertRaises(G.GeneratorConfigError):
            G.validate_gen_config(F.fixture_gen_config(twins_per_pair=2))
        with self.assertRaises(O.OracleError):
            G.validate_gen_config(F.fixture_gen_config(oracle={"L": 4, "status": "FIXTURE"}))  # L never <= 4

    def test_fixture_build_requires_synthetic_basis(self):
        with self.assertRaises(G.GeneratorConfigError):
            G.validate_gen_config(F.fixture_gen_config(attack_label_basis="post_filter_audit"))

    def test_attack_basis_refuses_non_synthetic_and_unaudited(self):
        rec = {"record_id": "r", "status": "ACCEPTED", "payload_wire": "x", "reason_string": "SQL injection payload detected."}
        with self.assertRaises(L.LabelBlocked):
            L.AttackBasis("fixture_synthetic").check(rec, "SQL Injection")   # no synthetic: true
        with self.assertRaises(L.LabelBlocked):
            L.NO_BASIS.check({**rec, "synthetic": True}, "SQL Injection")     # post_filter_audit, nothing passed

    def test_too_small_pool_stops_the_build_with_pool_too_small(self):
        pools = F.fixture_pool_values()
        pools["names_given"] = pools["names_given"][:5]     # below the 20-per-split minimum
        with self.assertRaises(S.StopBuild) as cm:
            F.build_world(pool_values=pools)
        self.assertIn("POOL_TOO_SMALL", {f["code"] for f in cm.exception.findings})

    def test_real_build_is_not_authorized(self):
        world = F.build_world()
        unmet = G.real_build_preconditions(world.gen_cfg, list(world.records.values()), world.pool_values)
        codes = {u["code"] for u in unmet}
        self.assertIn("REAL_SPLIT_NOT_AUTHORIZED", codes)
        self.assertIn("D64_B_POST_FILTER_AUDIT", codes)     # fixture records are PENDING_ADJUDICATION
        self.assertIn("D64_C_NAMES_FAMILY", codes)          # names_family not loaded into this fixture world (#75)
        self.assertIn("PREREGISTRATION_MISSING", codes)
        self.assertIn("VALUE_NOT_RATIFIED", codes)          # fixture statuses are PROPOSED / FIXTURE

    def test_names_family_loaded_clears_only_d64_c(self):
        # #75 / I-14: once names_family is among the loaded pools the D64_C gate clears (pure key
        # membership), WITHOUT unlocking a real build — every other precondition still refuses, and no
        # other pool is silently substituted for it.
        world = F.build_world()
        pools = dict(world.pool_values)
        pools["names_family"] = {}                          # present as a loaded pool
        unmet = G.real_build_preconditions(world.gen_cfg, list(world.records.values()), pools)
        codes = {u["code"] for u in unmet}
        self.assertNotIn("D64_C_NAMES_FAMILY", codes)
        self.assertIn("REAL_SPLIT_NOT_AUTHORIZED", codes)
        self.assertIn("D64_B_POST_FILTER_AUDIT", codes)
        self.assertIn("PREREGISTRATION_MISSING", codes)
        self.assertIn("VALUE_NOT_RATIFIED", codes)

    # ── effective validators (handoff 2026-10-23): the refusals are conditional, not fixed impossibilities ──
    def test_authorization_is_an_effective_validator_not_an_unconditional_no(self):
        world = F.build_world()
        recs = list(world.records.values())
        # a complete authorization record STILL refuses while no schema is ratified (refuse-by-default) ...
        auth = {"scope": "REAL_BUILD", "authorized_by": "owner", "date": "2026-10-23", "owner_decision": "D-x"}
        codes = {u["code"] for u in G.real_build_preconditions(world.gen_cfg, recs, world.pool_values,
                                                               build_authorization=auth)}
        self.assertIn("REAL_SPLIT_NOT_AUTHORIZED", codes)
        # ... and once the owner ratifies a schema and supplies the bound record, THAT gate clears (effective).
        with mock.patch.object(G, "REAL_BUILD_AUTH_SCHEMA", G.PROPOSED_REAL_BUILD_AUTH_SCHEMA):
            ok = dict(auth, schema=G.PROPOSED_REAL_BUILD_AUTH_SCHEMA)
            codes = {u["code"] for u in G.real_build_preconditions(world.gen_cfg, recs, world.pool_values,
                                                                   build_authorization=ok)}
            self.assertNotIn("REAL_SPLIT_NOT_AUTHORIZED", codes)
            # an invalid record (wrong scope) is still refused — not skipped
            bad = dict(ok, scope="EXPERIMENTAL")
            codes = {u["code"] for u in G.real_build_preconditions(world.gen_cfg, recs, world.pool_values,
                                                                   build_authorization=bad)}
            self.assertIn("REAL_SPLIT_NOT_AUTHORIZED", codes)

    def test_attack_eligibility_binds_to_sealed_category_outcomes(self):
        world = F.build_world()
        recs = list(world.records.values())
        cats = {G._record_category(r) for r in recs} - {None}
        self.assertTrue(cats)                                   # the fixture records carry a category
        # every category PASS → the audit gate clears (records are not forced to VERIFIED)
        passing = {c: G.OUTCOME_PASS for c in cats}
        codes = {u["code"] for u in G.real_build_preconditions(world.gen_cfg, recs, world.pool_values,
                                                               category_outcomes=passing)}
        self.assertNotIn("D64_B_POST_FILTER_AUDIT", codes)
        # a rejected category keeps its records out of the build (no rejected data advances it)
        one = sorted(cats)[0]
        mixed = dict(passing, **{one: "FAIL"})
        unmet = G.real_build_preconditions(world.gen_cfg, recs, world.pool_values, category_outcomes=mixed)
        d64 = [u for u in unmet if u["code"] == "D64_B_POST_FILTER_AUDIT"]
        self.assertTrue(d64 and any(repr(one) in u["detail"] for u in d64))


def _i9(enabled=True, **over):
    # cap="warn" is the literal D62 default (both bands reduce); tests set explicit TEST thresholds.
    i9 = {"enabled": enabled, "warn_share": "0.02", "block_share": "0.05", "cap": "warn",
          "max_iterations": 100, "max_rounds": 5, "owner_rulings": {}, "status": "PROPOSED"}
    i9.update(over)
    return i9


# TRAIN-only categories (NOT_EVALUABLE: all families go to TRAIN), so VALIDATION / INTERNAL_TEST have
# no cells and the realised-share loop can be exercised on TRAIN alone with an EXPLICIT TEST threshold
# — the production 2% / 5% values are never forced onto this small fixture.
TRAIN_ONLY = ["Command Injection", "path_file_access"]


def _train_only_cfg(**i9over):
    return F.fixture_gen_config(trained_categories={"categories": TRAIN_ONLY, "status": "PROPOSED"},
                               i9=_i9(**i9over))


class I9Rebalancing(unittest.TestCase):
    """I-9 step-5: realised-share-driven rebalance + regenerate in the generator (the quota math is
    covered by tests.test_v5_rebalance). All thresholds here are EXPLICIT TEST values, never ratified."""

    def test_disabled_by_default(self):
        _, gen, _ = shared_build()
        self.assertFalse(gen["i9_report"]["enabled"])

    def test_default_cap_is_warn_literal_d62(self):
        """The default enforceable reduction trigger is WARN (D62 §4.6 step 5: both bands reduce)."""
        self.assertEqual(F.fixture_gen_config()["i9"]["cap"], "warn")

    def test_real_build_blocks_a_non_warn_cap(self):
        """A real build with cap != 'warn' is refused (I9_CAP_NOT_LITERAL), never silently accepted."""
        cfg = G.validate_gen_config(_train_only_cfg(cap="block"))
        codes = {u["code"] for u in G.real_build_preconditions(cfg, [], {})}
        self.assertIn("I9_CAP_NOT_LITERAL", codes)
        cfg_warn = G.validate_gen_config(_train_only_cfg(cap="warn"))
        self.assertNotIn("I9_CAP_NOT_LITERAL", {u["code"] for u in G.real_build_preconditions(cfg_warn, [], {})})

    def test_realised_cells_count_only_admitted_complete_pairs(self):
        """Realised shares are measured on admitted rows; EXCLUDED/withheld pairs do not count."""
        # the oracle-collision world (single-slot) produces only excluded benign + withheld twins
        from parse_dataset_v4 import canonical_key
        wires = [f"synthmark sqli {i:04d} collide" for i in range(250)]
        recs = [{"record_id": f"c-{i:04d}", "status": "ACCEPTED", "synthetic": True, "payload_wire": w,
                 "payload_logical": w, "payload_wire_form": R.PLAIN, "canonical_key": canonical_key(w),
                 "dedup_scope": "SQL Injection", "native_forms": [], "reason_string": "SQL injection payload detected."}
                for i, w in enumerate(wires)]
        tpls = [{"name": f"t-c-{i}", "cluster": "t-c", "carrier": "text", "method": "POST",
                 "path": ["notes", f"v{i}"], "text": {"type": "free_string"}} for i in range(4)]
        with open(K.DEFAULT_LEXICON, encoding="utf-8") as fh:
            catalog = K.catalog_from_objects({"schema": K.CATALOG_SCHEMA, "templates": tpls}, json.load(fh))
        split_cfg = F.fixture_split_config(pools=["names_given"], value_pool_precedence=["names_given"],
                                           category_vocabulary={"source": "stage2_dedup_scope",
                                                                "order": "python_str_code_point",
                                                                "categories": ["SQL Injection"]})
        gen_cfg = F.fixture_gen_config(trained_categories={"categories": ["SQL Injection"], "status": "PROPOSED"},
                                       placement_shares={"replace": 1, "prefix": 0, "suffix": 0,
                                                         "embedded": 0, "status": "PROPOSED"})
        world = F.build_world(catalog=catalog, records=recs, pool_values={"names_given": list(wires)},
                              split_cfg=split_cfg, gen_cfg=gen_cfg)
        gen = G.generate(world)
        self.assertEqual(G.realised_cells(gen), {})          # no admitted complete pair -> no realised cells
        self.assertGreater(len(gen["rows"]), 0)              # but rows were generated (all excluded/withheld)

    def test_enabled_infeasible_stops_and_names_clusters(self):
        # At a 5% cap the clean fixture is infeasible (single-cluster VAL/TEST carriers and low-cluster
        # TRAIN carriers): the realised-share loop must stop and name every offending cluster.
        with self.assertRaises(V9.StopBuild) as cm:
            G.generate_balanced(F.build_world(gen_cfg=F.fixture_gen_config(i9=_i9())))
        codes = {f["code"] for f in cm.exception.findings}
        self.assertEqual(codes, {"I9_REQUIRED_CONCEPT_RULING_NEEDED"})
        self.assertTrue(all("of the split" in f["detail"] for f in cm.exception.findings))   # split-denominator share

    def test_realised_loop_rebalances_and_converges_under_the_cap(self):
        """TRAIN-only categories; an 8% TEST cap makes a 10% cluster over-cap, feasibly redistributable.
        The loop rebalances, regenerates, and converges with every realised share <= the cap."""
        world = F.build_world(gen_cfg=_train_only_cfg(warn_share="0.08", block_share="0.20"))
        gen = G.generate_balanced(world)
        rep = gen["i9_report"]
        self.assertTrue(rep["converged"])
        self.assertEqual(rep["rounds"][0]["outcome"], "rebalanced")      # a real redistribution happened
        self.assertEqual(rep["rounds"][-1]["outcome"], "converged")
        per = Counter((r["meta"]["split"], r["meta"]["struct_cluster_id"])
                      for r in gen["rows"] if r["meta"]["disposition"] == "split")
        totals = Counter(s for (s, _) in per.elements())
        for (split, _cl), n in per.items():
            self.assertLessEqual(Fraction(n, totals[split]), Fraction("0.08"))   # realised share <= cap
        self.assertTrue(G.run_gates(world, gen, F.fixture_pool_value_lists())["ok"])

    def test_realised_loop_is_reproducible(self):
        cfg = _train_only_cfg(warn_share="0.08", block_share="0.20")
        a = G.generate_balanced(F.build_world(gen_cfg=cfg))
        b = G.generate_balanced(F.build_world(gen_cfg=cfg))
        self.assertEqual(json.dumps([r["meta"] for r in a["rows"]], sort_keys=True),
                         json.dumps([r["meta"] for r in b["rows"]], sort_keys=True))
        self.assertEqual(json.dumps(a["i9_report"]["rounds"], sort_keys=True),
                         json.dumps(b["i9_report"]["rounds"], sort_keys=True))

    def test_high_cap_converges_without_rebalancing(self):
        world = F.build_world(gen_cfg=_train_only_cfg(warn_share="0.50", block_share="0.60"))
        rep = G.generate_balanced(world)["i9_report"]
        self.assertTrue(rep["converged"])
        self.assertEqual([r["outcome"] for r in rep["rounds"]], ["converged"])

    def test_manifest_records_quotas_realised_and_outcomes(self):
        world = F.build_world(gen_cfg=_train_only_cfg(warn_share="0.08", block_share="0.20"))
        gen = G.generate_balanced(world)
        rnd = gen["i9_report"]["rounds"][0]
        for key in ("planned_pairs", "realised_pairs", "realised_shares", "attempts", "over_cap", "outcome"):
            self.assertIn(key, rnd)

    def test_quota_change_preserves_earlier_rows_byte_identical(self):
        """D62 §4.6 step 4 seed = (SALT, split, cluster, quota=category slug, attempt i); the numeric
        pair-count is NOT in the seed, so reducing or raising a cell's target keeps the lower-index rows
        byte-identical. This is what makes I-9 rebalancing (step 5) reproducible."""
        world = F.build_world()
        _, cells = G.plan_cells(world)
        cell = sorted(k for k in cells if k[0] == "TRAIN")[0]

        def fingerprints(target):
            plan = {k: dict(v) for k, v in cells.items()}
            plan[cell]["pairs"] = target
            gen = G.generate(world, plan=plan)
            out = {}
            for r in gen["rows"]:
                m = r["meta"]
                if (m["split"], m["struct_cluster_id"], m["twin_category"]) == cell:
                    out[(m["attempt"], m["pair_role"])] = hashlib.sha256(
                        (json.dumps(m, sort_keys=True) + "|" + (r["text"] or "")).encode()).hexdigest()
            return out
        small, large = fingerprints(2), fingerprints(5)
        self.assertEqual(sorted({a for a, _ in small}), [0, 1])
        self.assertTrue(set(small) <= set(large))                       # the small build is a prefix
        self.assertTrue(all(small[k] == large[k] for k in small))       # and byte-identical row-for-row

    def test_explicit_plan_drives_generation(self):
        """A reduced cell target yields fewer complete pairs; a raised target yields more (plan honored)."""
        world = F.build_world()
        _, cells = G.plan_cells(world)
        train = sorted(k for k in cells if k[0] == "TRAIN")
        low, high = train[0], train[1]
        plan = {k: dict(v) for k, v in cells.items()}
        plan[low]["pairs"], plan[high]["pairs"] = 1, 3
        gen = G.generate(world, plan=plan)
        from collections import Counter
        benign = Counter((r["meta"]["split"], r["meta"]["struct_cluster_id"], r["meta"]["twin_category"])
                         for r in gen["rows"]
                         if r["meta"]["disposition"] == "split" and r["meta"]["pair_role"] == "benign")
        self.assertEqual(benign[low], 1)
        self.assertEqual(benign[high], 3)
        self.assertFalse(gen["i9_report"]["enabled"])       # explicit plan override, not rebalanced


class NamesFamilyConsumption(unittest.TestCase):
    """#75 / I-14: the generator actually CONSUMES a loaded names_family pool — a template slot draws
    from it, the row records names_family-namespaced provenance, and an absent/empty pool refuses with
    no silent substitution. Synthetic fixtures only; the global fixtures are untouched; real-build and
    training gates stay blocked; no real split. This is downstream availability validation, distinct
    from the membership-only D64_C precondition in test_names_family_loaded_clears_only_d64_c."""

    def _world(self, pool_values):
        n = 250                                             # >= 20 per split
        wires = [f"synthmark sqli {i:04d} nf" for i in range(n)]
        recs = [{"record_id": f"nf-{i:04d}", "status": "ACCEPTED", "synthetic": True, "payload_wire": w,
                 "payload_logical": w, "payload_wire_form": R.PLAIN, "canonical_key": canonical_key(w),
                 "dedup_scope": "SQL Injection", "native_forms": [],
                 "reason_string": "SQL injection payload detected.", "source_file": "SYNTHETIC/nf.txt"}
                for i, w in enumerate(wires)]
        tpls = [{"name": f"nf-text-{i}", "cluster": "nf-text", "carrier": "text", "method": "POST",
                 "path": ["notes", f"v{i}"], "text": {"type": "free_string", "pools": ["names_family"]}}
                for i in range(4)]
        with open(K.DEFAULT_LEXICON, encoding="utf-8") as fh:
            lexicon = json.load(fh)
        catalog = K.catalog_from_objects({"schema": K.CATALOG_SCHEMA, "templates": tpls}, lexicon)
        split_cfg = F.fixture_split_config(carrier_strata=list(K.CARRIERS), pools=["names_family"],
                                           value_pool_precedence=["names_family"],
                                           category_vocabulary={"source": "stage2_dedup_scope",
                                                                "order": "python_str_code_point",
                                                                "categories": ["SQL Injection"]})
        gen_cfg = F.fixture_gen_config(
            trained_categories={"categories": ["SQL Injection"], "status": "PROPOSED"},
            placement_shares={"replace": 1, "prefix": 1, "suffix": 1, "embedded": 1, "status": "PROPOSED"})
        return F.build_world(catalog=catalog, records=recs, pool_values=pool_values,
                             split_cfg=split_cfg, gen_cfg=gen_cfg)

    def test_generator_consumes_loaded_names_family_pool(self):
        fam = [f"Fam{F._word('names_family_fixture', i, 10).capitalize()}" for i in range(250)]
        world = self._world({"names_family": fam})
        # a genuinely LOADED pool with namespaced identities (not an empty dict standing in for one)
        self.assertEqual(len(world.pool_values["names_family"]), 250)
        for vid, val in world.pool_values["names_family"].items():
            self.assertEqual(vid, I.value_entry_id("names_family", val))
        gen = G.generate(world)
        benign = [r for r in gen["rows"] if r["meta"]["pair_role"] == "benign"]
        self.assertTrue(benign, "expected benign rows drawing from names_family")
        famset = set(fam)
        drew = 0
        for r in benign:
            # value_entries record [pool_id, value_entry_id]; values record the drawn strings (parallel)
            for (pool, vid), val in zip(r["meta"]["value_entries"], r["meta"]["values"]):
                self.assertEqual(pool, "names_family")                          # recorded pool provenance
                self.assertEqual(vid, I.value_entry_id("names_family", val))    # id is names_family-namespaced
                self.assertIn(val, famset)                                      # value came from the loaded pool
                drew += 1
        self.assertGreater(drew, 0)
        self.assertTrue(any(r["meta"]["disposition"] == "split" for r in benign), "pairs should complete")
        # real-build/training gates stay blocked: D64_C clears (pool loaded) but everything else refuses
        unmet = {u["code"] for u in G.real_build_preconditions(
            world.gen_cfg, list(world.records.values()), world.pool_values)}
        self.assertNotIn("D64_C_NAMES_FAMILY", unmet)
        self.assertIn("REAL_SPLIT_NOT_AUTHORIZED", unmet)
        self.assertIn("VALUE_NOT_RATIFIED", unmet)

    def test_absent_names_family_refuses_without_silent_substitution(self):
        # the template REQUIRES names_family; supplying a different pool must not be substituted for it
        with self.assertRaises(S.StopBuild) as cm:
            self._world({})
        codes = {f["code"] for f in cm.exception.findings}
        self.assertIn("POOL_UNAVAILABLE", codes)

    def test_empty_names_family_stops_the_build(self):
        with self.assertRaises(S.StopBuild) as cm:
            self._world({"names_family": []})
        codes = {f["code"] for f in cm.exception.findings}
        self.assertTrue({"POOL_UNAVAILABLE", "POOL_TOO_SMALL"} & codes, codes)


class PendingDependencies(unittest.TestCase):
    """Controls that CANNOT be validated with synthetic data — recorded as skips, never a synthetic PASS."""

    @unittest.skip("Needs the real post-filter audit (spec §7) and adjudicated payloads: no VERIFIED attack "
                   "data exists; synthetic markers cannot stand in for attack ground truth.")
    def test_attack_category_detection_quality(self):
        pass

    @unittest.skip("Needs the ratified L, oracle signatures and benign pools (spec §4.4, §11.2 PENDING): the "
                   "oracle's containment/signature calibration is a pilot decision, not a synthetic assertion.")
    def test_oracle_signature_calibration(self):
        pass

    @unittest.skip("Needs the real split preconditions (D64): names_family is built and available (#75), but no "
                   "real split is authorized and its real-build precedence is unratified, so cross-split leakage on "
                   "real identities is not verifiable here.")
    def test_real_split_leakage(self):
        pass


class AuthorizedBuild(unittest.TestCase):
    """The public authorized-build entry (#82 wiring). Real builds are refuse-by-default; the positive control
    exercises capture → selection → generation → persistence on a SYNTHETIC world (preconditions mocked empty,
    since they are tested separately). No real dataset is built."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.out = os.path.join(self.tmp, "out")
        self.world = F.build_world()
        self.cats = sorted({G._record_category(r) for r in self.world.records.values()} - {None})

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _auth(self, **over):
        p = os.path.join(self.tmp, "auth.json")
        rec = {"schema": G.PROPOSED_REAL_BUILD_AUTH_SCHEMA, "scope": "REAL_BUILD", "preregistration_sha256": "pre",
               "authorized_by": "owner", "date": "2026-10-23", "owner_decision": "D-x"}
        from tests.v5_audit_fixture import make_bundle
        self.bundle=make_bundle(os.path.join(self.tmp,'evidence'),records=list(self.world.records.values()),
                               outcomes={c:G.OUTCOME_PASS for c in self.cats})
        rec['audit_evidence']=self.bundle
        rec.update(over)
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(rec, fh)
        return p

    def _exchange(self, outcomes=None, **over):
        p=self.bundle['exchange']['path']
        if outcomes is not None or over:
            with open(p) as fh: rec=json.load(fh)
            if outcomes is not None:rec['category_outcomes']=outcomes
            rec.update(over)
            with open(p,'w') as fh:json.dump(rec,fh)
        return p

    def test_missing_records_refuse_and_persist_nothing(self):
        res = G.authorized_build(self.world, authorization_path=None, audit_exchange_path=None, out_dir=self.out,
                                 pool_values_list=F.fixture_pool_value_lists())
        self.assertEqual(res["status"], "REFUSED")
        codes = {u["code"] for u in res["unmet"]}
        self.assertIn("AUTHORIZATION_UNREADABLE", codes)
        self.assertIn("AUDIT_EXCHANGE_UNREADABLE", codes)
        self.assertFalse(os.path.exists(os.path.join(self.out, "manifest.json")))   # nothing written
        self.assertTrue(res["pools_without_real_builder"])                          # real pools still missing

    def test_refuse_by_default_even_with_complete_records(self):
        res = G.authorized_build(self.world, authorization_path=self._auth(), audit_exchange_path=self._exchange(),
                                 out_dir=self.out, preregistration_sha256="pre",
                                 pool_values_list=F.fixture_pool_value_lists())
        self.assertEqual(res["status"], "REFUSED")  # schema activation is not a dataset permission
        self.assertIn("AUTHORIZATION_NOT_COMMITTED", {u["code"] for u in res["unmet"]})

    def test_selected_category_must_be_admitted(self):
        if not self.cats:
            self.skipTest("fixture has no attack categories")
        self._auth()
        ex = self._exchange({**{c: G.OUTCOME_PASS for c in self.cats}, self.cats[0]: "FAIL"})
        res = G.authorized_build(self.world, authorization_path=os.path.join(self.tmp,'auth.json'), audit_exchange_path=ex,
                                 out_dir=self.out, category_selection=self.cats,
                                 pool_values_list=F.fixture_pool_value_lists())
        self.assertEqual(res["status"], "REFUSED")
        self.assertIn("AUDIT_EXCHANGE_UNBOUND", {u["code"] for u in res["unmet"]})

    def test_positive_control_builds_and_persists_on_synthetic_world(self):
        # preconditions are tested elsewhere; here we verify the WIRING proceeds to generation + persistence.
        with mock.patch.object(G, "real_build_preconditions", return_value=[]), mock.patch.object(G.AE,'is_committed',return_value=True):
            res = G.authorized_build(self.world, authorization_path=self._auth(), audit_exchange_path=self._exchange(),
                                     out_dir=self.out, preregistration_sha256="pre", category_selection=self.cats,
                                     pool_values_list=F.fixture_pool_value_lists())
        self.assertEqual(res["status"], "BUILT", res)
        self.assertTrue(os.path.isfile(os.path.join(self.out, "manifest.json")))
        self.assertEqual(res["source_report_sha256"], self.bundle['report']['sha256'])
        self.assertEqual(res["category_selection"], self.cats)


if __name__ == "__main__":
    unittest.main()
