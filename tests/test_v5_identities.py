"""Stage-3 identity tests (issue #72): payload_family_id, merges, template_id, struct_cluster_id,
value_entry_id reuse, pair_id / per-row RNG and the near-duplicate audit. Synthetic strings only.

    python3 -m unittest tests.test_v5_identities -v
"""

import hashlib
import os
import random
import subprocess
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "scripts", "dataset"))

import v5_identities as I  # noqa: E402
import v5_pools_common as C  # noqa: E402
from parse_dataset_v4 import canonical_key  # noqa: E402


def rec(rid, wire, cat="cat_a", native=(), status="ACCEPTED"):
    return {"record_id": rid, "status": status, "payload_wire": wire, "canonical_key": canonical_key(wire),
            "dedup_scope": cat, "native_forms": list(native)}


class PayloadFamilyId(unittest.TestCase):
    def test_rules_in_spec_order(self):
        P = I.payload_family_id
        self.assertEqual(P("SLEEP(5)"), "sleep(0)")                          # canonical_key lowercases; digit -> 0
        self.assertEqual(P("a   b\tc"), "abc")                                # whitespace removed
        self.assertEqual(P("aaaaaaab"), "aaab")                               # run > 3 -> 3
        self.assertEqual(P("aaab"), "aaab")                                   # run of 3 kept
        self.assertEqual(P("1' or 1=1--"), P("2' OR 7=9--"))                  # digit values collapse
        self.assertEqual(P("%27%20or%201%3D1--"), P("' or 1=1--"))            # encodings share the family
        self.assertEqual(P("SEL/**/ECT 1"), P("select 1"))                    # D16 comment collapse

    def test_digit_runs_collapse_to_one_zero(self):
        # owner ruling D-5: every maximal run of ASCII digits becomes one "0"
        P = I.payload_family_id
        self.assertEqual(P("sleep(5)"), "sleep(0)")
        self.assertEqual(P("sleep(5)"), P("sleep(10)"))
        self.assertEqual(P("sleep(10)"), P("sleep(99999)"))
        self.assertEqual(P("order by 1,2,3"), "orderby0,0,0")                    # separate runs stay separate
        self.assertNotEqual(P("order by 1,2"), P("order by 12"))
        self.assertEqual(P("a1b22c333"), "a0b0c0")
        self.assertEqual(P("x١٢"), "x١٢")                     # non-ASCII digits untouched (I-19)
        self.assertEqual(I._family_key("sleep(10)", per_digit=True), "sleep(00)")  # superseded v1 rule, diagnostics

    def test_hosts_ips_emails(self):
        P = I.payload_family_id
        self.assertEqual(P("http://evil.example/x"), "http://H/x")
        self.assertEqual(P("http://evil.example/x"), P("http://other.test/x"))
        self.assertEqual(P("http://127.0.0.1:8080/"), "http://H:0/")
        self.assertEqual(P("gopher://[::1]:25/"), "gopher://H:0/")
        self.assertEqual(P("::ffff:127.0.0.1"), "H")
        self.assertEqual(P("http://0x7f.0x0.0x0.0x1/"), "http://H/")
        self.assertEqual(P("ping 10.0.0.1"), "pingH")
        self.assertEqual(P("mail a.b@corp.example now"), "mailHnow")
        self.assertEqual(P("http://good.example@evil.example"), "http://H")  # userinfo confusion
        self.assertEqual(P("//evil.example"), "//H")
        self.assertEqual(P("http://localhost/"), "http://H/")
        for host in ("2130706433", "017700000001", "0x7f000001", "evil.example.", "münchen.example"):
            self.assertEqual(P(f"http://{host}/x"), "http://H/x", host)       # integer IP forms, FQDN dot, IDN

    def test_redirect_forms_of_spec_4_3(self):
        # owner ruling D-6: only the POL-REDIRECT-DIFF / userinfo forms §4.3 lists
        P = I.payload_family_id
        for form, key in (("/\\evil.example", "/\\H"), ("\\/\\/evil.example/", "\\/\\/H/"),
                          ("//\\/evil.example/", "//\\/H/"), ("/%2F%2Fevil.example", "///H"),
                          ("/%09/evil.example", "//H"), ("/%0d%0a/evil.example", "//H"),
                          ("https:evil.example", "https:H"), ("/https:evil.example", "/https:H"),
                          ("http://good.example@0x7f000001/", "http://H@H/"),
                          ("http:good.example@3627734734", "http:H@H"),
                          ("/?url=/\\/evil.example&next=/\\/evil.example", "/?url=/\\/H&next=/\\/H")):
            self.assertEqual(P(form), key, form)

    def test_separator_runs_mask_hosts_only_in_url_context(self):
        # round-2 review: `//` or `\\` outside URL context is a path or a comment, never a host
        P = I.payload_family_id
        for p in ("alert(1)//document.cookie", "x=1;//a.b", "..//boot.ini", "c:\\\\php.ini", "....\\\\boot.ini",
                  "\\\\windows\\\\system32\\\\cmd.exe", "-//W3C//DTD", "select 1//2", "x//0x1f"):
            self.assertNotIn("H", P(p), p)
        for p, key in (('"><a href=//evil.example>', '"><ahref=//H>'), ("gopher://127.0.0.1:25/", "gopher://H:0/"),
                       ("\\\\evil.example\\share", "\\\\H\\share"), ("x='//evil.example'", "x='//H'")):
            self.assertEqual(P(p), key, p)

    def test_integer_ipv4_after_plain_scheme(self):
        # owner ruling D-6 residual (round 3): `https:h` (POL-REDIRECT-DIFF) with a dword / 0x-hex host
        # (POL-URL-OBFUSCATED) is masked like the same host after `//`
        P = I.payload_family_id
        for form, key in (("http:3627734734", "http:H"), ("http:0xd83ad6ce", "http:H"),
                          ("https:3627734734/x", "https:H/x"), ("HTTP:0XD83AD6CE", "http:H"),
                          ("http:0xd8.0x3a.0xd6.0xce", "http:H"), ("http:216.58.214.206", "http:H"),
                          ("/?next=http:3627734734", "/?next=http:H"),
                          ("http:3H6k7lIAiqjfNeN@3627734734", "http:0h0k0liaiqjfnen@H")):
            self.assertEqual(P(form), key, form)
        self.assertEqual(P("http:3627734734"), P("http:evil.example"))     # one family, as for `//`
        # after D-5 every digit run is one `0`: `http:80` is the same key (a WHATWG host, 0.0.0.80)
        self.assertEqual(P("http:80"), "http:H")
        # not a scheme, or not the whole host: left alone
        for p in ("xhttp:123", "http:12a", "ahttps:0x1", "php.ini", "document.cookie", "..//boot.ini",
                  "alert(1)//document.cookie", "c:\\\\php.ini"):
            self.assertNotIn("H", P(p), p)

    def test_lexical_non_hosts_stay_unmasked(self):
        P = I.payload_family_id
        for p in ("../../etc/php.ini", "..\\/boot.ini", "..\\/..\\/windows/win.ini", "document.cookie",
                  "<script>alert(document.cookie)</script>", "?next=evil.example", "javascript:alert(1)",
                  "\u3031evil.example", "\uff0f\uff0fevil.example"):
            self.assertNotIn("H", P(p).replace("http", ""), p)

    def test_documented_ipv6_lexical_limitation(self):
        # I-2 limitation: a hex word pair around "::" is syntactically an IPv6 address
        self.assertEqual(I.payload_family_id("dead::beef"), "H")

    def test_lexical_non_hosts_are_kept(self):
        P = I.payload_family_id
        for p in ("../../etc/php.ini", "<script>alert(document.cookie)</script>", "java.lang.Runtime",
                  "php://filter/resource=index.php", "waitfor delay '0:0:5'", "select '1'::int", "foo::bar"):
            self.assertNotIn("H", P(p), p)
        self.assertNotEqual(P("../../etc/php.ini"), P("../../etc/my.cnf"))

    def test_empty_key_is_refused(self):
        for p in ("%0a%0d", "   ", "/* only a comment */"):
            with self.assertRaises(I.IdentityError):
                I.payload_family_id(p)

    def test_lone_surrogate_is_an_identity_error(self):
        with self.assertRaises(I.IdentityError):
            I.payload_family_id("\ud800x payload")
        with self.assertRaises(I.IdentityError):
            I.build_families([rec("r1", "\ud800x payload")])

    def test_rule_order_is_the_listed_order(self):
        # I-18: whitespace is removed after the run collapse, as listed; spaced runs are not collapsed
        self.assertEqual(I.payload_family_id("aaaa"), "aaa")
        self.assertEqual(I.payload_family_id("a a a a"), "aaaa")

    def test_stable_across_processes_and_hash_seeds(self):
        code = ("import sys; sys.path.insert(0, %r); import v5_identities as I; "
                "print(I.payload_family_id(\"HTTP://Evil.example/%%27 OR 1=1--  aaaaaa\"))"
                % os.path.join(REPO, "scripts", "dataset"))
        outs = {subprocess.run([sys.executable, "-c", code], env=dict(os.environ, PYTHONHASHSEED=s),
                               capture_output=True, text=True, check=True).stdout for s in ("0", "1", "999")}
        self.assertEqual(len(outs), 1)


class Families(unittest.TestCase):
    def test_variants_group_and_stratum_is_first_category(self):
        fams = I.build_families([rec("r1", "' or 1=1--", "SQL Injection"),
                                 rec("r2", "%27%20OR%202%3D2--", "XPath Injection"),
                                 rec("r3", "<svg onload=alert(1)>", "XSS Injection", native=["html_entity"])])
        self.assertEqual(len(fams), 2)
        f = fams[I.payload_family_id("' or 1=1--")]
        self.assertEqual(f.categories, ("SQL Injection", "XPath Injection"))
        self.assertEqual(f.stratum_category, "SQL Injection")
        self.assertEqual(f.members, ("r1", "r2"))
        self.assertTrue(fams[I.payload_family_id("<svg onload=alert(1)>")].has_native_held_out_form)

    def test_explicit_merge_uses_smallest_member_id(self):
        recs = [rec("r1", "zeta payload"), rec("r2", "alpha payload"), rec("r3", "mid payload")]
        ids = sorted(I.payload_family_id(r["payload_wire"]) for r in recs)
        fams = I.build_families(recs, merges=[[ids[2], ids[0]]])
        self.assertEqual(sorted(fams), sorted([ids[0], ids[1]]))
        self.assertEqual(fams[ids[0]].merged_from, (ids[0], ids[2]))
        self.assertEqual(fams[ids[0]].members, ("r1", "r2"))
        # transitive merges resolve to one component
        fams = I.build_families(recs, merges=[[ids[0], ids[1]], [ids[1], ids[2]]])
        self.assertEqual(list(fams), [ids[0]])

    def test_input_order_does_not_matter(self):
        recs = [rec(f"r{i}", f"payload {chr(97 + i % 26)}{chr(97 + i // 26)}x", f"cat_{i % 3}") for i in range(60)]
        ref = I.build_families(recs)
        for k in range(3):
            sh = list(recs)
            random.Random(k).shuffle(sh)
            self.assertEqual(I.build_families(sh), ref)

    def test_negative_inputs(self):
        with self.assertRaises(I.IdentityError):
            I.build_families([rec("r1", "x payload"), rec("r1", "y payload")])            # duplicate id
        with self.assertRaises(I.IdentityError):
            I.build_families([rec("r1", "x payload", status="EXCLUDED")])                 # not ACCEPTED
        bad = rec("r1", "x payload")
        bad["canonical_key"] = "tampered"
        with self.assertRaises(I.IdentityError):
            I.build_families([bad])                                                      # provenance integrity
        with self.assertRaises(I.IdentityError):
            I.build_families([rec("r1", "x payload")], merges=[["x payload", "unknown"]])  # unknown merge id
        with self.assertRaises(I.IdentityError):
            I.build_families([rec("r1", "x payload")], merges=[["xpayload"]])             # 1-id merge
        two = [rec("r1", "x payload"), rec("r2", "y payload")]
        for bad in ([["xpayload", "xpayload"]], [["xpayload", "ypayload", "ypayload"]], ["xpayload"],
                    [["xpayload", 3]]):
            with self.assertRaises(I.IdentityError, msg=repr(bad)):
                I.build_families(two, merges=bad)
        with self.assertRaises(I.IdentityError) as cm:
            I.build_families([rec("r1", "ok payload"), rec("r2", "%0a%0d"), rec("r3", "/* c */")])
        self.assertIn("2 record(s)", str(cm.exception))                                  # all listed, none dropped


class ValueEntryId(unittest.TestCase):
    def test_reuses_stage2_formula(self):
        self.assertIs(I.value_entry_id, C.value_entry_id)
        nfd = "René"                                   # NFD form of "René"
        expected = hashlib.sha256("names_given\0René".encode("utf-8")).hexdigest()
        self.assertEqual(I.value_entry_id("names_given", nfd), expected)
        self.assertNotEqual(I.value_entry_id("names_given", "Morgan"), I.value_entry_id("names_family", "Morgan"))


def skel(carrier="query", path=("api", "{int}"), slots=(((0,), "string"),), method="GET", mt=None):
    return I.TemplateSkeleton(method, carrier, mt, tuple(path), tuple(slots))


def vrec(pool, value, ref=None):
    return {"value": value, "value_entry_id": I.value_entry_id(pool, value), "source_ref": ref or f"{pool}:{value}"}


class ValueDeduplication(unittest.TestCase):
    """Owner ruling D-3: NFC + casefold equivalence, deterministic representative, ledger. Round 3
    (policy B): no hold; a group whose members differ in meaning is deduplicated like any other and the
    excluded member records the difference and the policy reason."""
    NOTE = {"i'm terrified of wasps.": "not synonyms: insect vs acronym"}
    PREC = ["symbols", "streets", "names_given", "prose_en"]

    def pools(self):
        return {"names_given": [vrec("names_given", v) for v in ("MacKinnon", "Mackinnon", "O", "O'Hara", "Ren\u0065\u0301")],
                "symbols": [vrec("symbols", v) for v in ("O+", "O'Hara", "René")],
                "streets": [vrec("streets", v) for v in ("Bahnhofstraße", "Bahnhofstrasse", "Elm  Street", "Elm Street")],
                "prose_en": [vrec("prose_en", v) for v in ("I'm terrified of wasps.", "I'm terrified of WASPs.")]}

    def test_equivalence_is_nfc_casefold_not_canonical_key(self):
        K = I.value_equivalence_key
        self.assertEqual(K("MacKinnon"), K("Mackinnon"))
        self.assertEqual(K("Straße"), K("STRASSE"))
        self.assertEqual(K("Ren\u0065\u0301"), K("René"))                      # NFC
        self.assertNotEqual(K("O"), K("O+"))                                     # '+' is not a space here
        self.assertNotEqual(K("C++"), K("C"))
        self.assertNotEqual(K("Elm  Street"), K("Elm Street"))                   # spaces are not collapsed

    def test_representatives_ledger_and_precedence(self):
        d = I.dedup_value_pools(self.pools(), self.PREC, self.NOTE)
        kept = {p: [r["value"] for r in rs] for p, rs in d["kept"].items()}
        self.assertIn("O", kept["names_given"])
        self.assertIn("O+", kept["symbols"])
        self.assertIn("O'Hara", kept["symbols"])                                 # cross-pool: precedence
        self.assertNotIn("O'Hara", kept["names_given"])
        self.assertNotIn("Ren\u0065\u0301", kept["names_given"])                 # NFC equal to symbols' "René"
        self.assertEqual(len([v for v in kept["names_given"] if v.casefold() == "mackinnon"]), 1)
        self.assertEqual(len([v for v in kept["streets"] if "bahnhof" in v.casefold()]), 1)
        self.assertEqual(kept["prose_en"], ["I'm terrified of wasps."])               # policy B: no hold
        self.assertEqual(d["semantic_notes_applied"], ["i'm terrified of wasps."])
        total_in = sum(len(v) for v in self.pools().values())
        self.assertEqual(sum(len(v) for v in d["kept"].values()) + len(d["excluded"]), total_in)  # nothing lost
        for e in d["excluded"]:
            rep = e["representative"]
            self.assertEqual(I.value_equivalence_key(e["value"]), I.value_equivalence_key(rep["value"]))
            self.assertEqual(rep["value_entry_id"], I.value_entry_id(rep["pool_id"], rep["value"]))  # frozen formula
            self.assertTrue(e["source_ref"] and rep["source_ref"])
            self.assertLessEqual(self.PREC.index(rep["pool_id"]), self.PREC.index(e["pool_id"]))
        # within one pool the representative is the smallest value_entry_id
        mk = [vrec("names_given", v)["value_entry_id"] for v in ("MacKinnon", "Mackinnon")]
        kept_id = [r["value_entry_id"] for r in d["kept"]["names_given"] if r["value"].casefold() == "mackinnon"][0]
        self.assertEqual(kept_id, min(mk))

    def test_semantic_difference_is_recorded_not_declared_synonym(self):
        d = I.dedup_value_pools(self.pools(), self.PREC, self.NOTE)
        w = [e for e in d["excluded"] if e["value"] == "I'm terrified of WASPs."]
        self.assertEqual(len(w), 1)
        e = w[0]
        self.assertEqual(e["exclusion_reason"], I.VALUE_POLICY_REASON)
        self.assertIn("split_contamination", e["exclusion_reason"])
        self.assertIs(e["synonym"], False)
        self.assertEqual(e["semantic_difference"], self.NOTE["i'm terrified of wasps."])
        self.assertEqual(e["representative"]["value"], "I'm terrified of wasps.")
        self.assertEqual(e["value_entry_id"], I.value_entry_id("prose_en", "I'm terrified of WASPs."))  # unchanged id
        self.assertLess(e["representative"]["value_entry_id"], e["value_entry_id"])           # the current rule chose
        others = [x for x in d["excluded"] if x is not e]
        self.assertTrue(others and all(x["exclusion_reason"] == I.VALUE_DUPLICATE_REASON and "synonym" not in x
                                       for x in others))
        # without the note the same member is excluded: the note changes the ledger, never the selection
        plain = I.dedup_value_pools(self.pools(), self.PREC)
        self.assertEqual(plain["kept"], d["kept"])

    def test_independent_of_input_order(self):
        ref = I.dedup_value_pools(self.pools(), self.PREC, self.NOTE)
        for seed in range(4):
            pools = {p: list(rs) for p, rs in reversed(list(self.pools().items()))}
            for rs in pools.values():
                random.Random(seed).shuffle(rs)
            self.assertEqual(I.dedup_value_pools(pools, self.PREC, self.NOTE), ref)

    def test_invalid_inputs(self):
        with self.assertRaises(I.IdentityError):
            I.dedup_value_pools(self.pools(), ["symbols", "streets"])                           # pool missing
        with self.assertRaises(I.IdentityError):
            I.dedup_value_pools(self.pools(), self.PREC, {"no such key": "x"})
        with self.assertRaises(I.IdentityError):
            I.dedup_value_pools(self.pools(), self.PREC, {"o": "single-member key"})          # not a group
        with self.assertRaises(I.IdentityError):
            I.dedup_value_pools(self.pools(), self.PREC, {"i'm terrified of wasps.": " "})    # empty note
        bad = self.pools()
        bad["symbols"][0] = dict(bad["symbols"][0], value_entry_id="0" * 64)
        with self.assertRaises(I.IdentityError):
            I.dedup_value_pools(bad, self.PREC)                                                 # formula mismatch
        dup = self.pools()
        dup["symbols"].append(dict(dup["symbols"][0]))
        with self.assertRaises(I.IdentityError):
            I.dedup_value_pools(dup, self.PREC)


class TemplateAndClusters(unittest.TestCase):
    def test_template_id_excludes_names_by_construction(self):
        a = skel()
        self.assertEqual(I.template_id(a), I.template_id(skel()))
        self.assertNotEqual(I.template_id(a), I.template_id(skel(slots=(((0,), "int"),))))
        self.assertNotEqual(I.template_id(a), I.template_id(skel(carrier="json", method="POST", mt="application/json")))
        with self.assertRaises(I.IdentityError):
            I.template_id(skel(slots=((("username",), "string"),)))                     # a name in a key path
        with self.assertRaises(I.IdentityError):
            I.template_id(skel(slots=(((True,), "string"),)))
        self.assertEqual(len(I.template_id(a)), 64)

    def _decl(self, i, cluster, stratum="query", near=False):
        sk = skel(path=("api", "shared" if near else f"seg{i}", f"leaf{i}" if not near else "leaf"))
        return I.TemplateDecl(f"t{i}", cluster, stratum, I.template_tokens(sk))

    def test_cluster_merges_and_smallest_id(self):
        decls = [self._decl(1, "c-b"), self._decl(2, "c-a"), self._decl(3, "c-c")]
        t = I.resolve_clusters(decls, merges=[["c-c", "c-b"]])
        self.assertEqual(t.template_cluster, {"t1": "c-b", "t2": "c-a", "t3": "c-b"})
        self.assertEqual(t.cluster_members["c-b"], ["c-b", "c-c"])

    def test_cluster_conflicts_are_refused(self):
        with self.assertRaises(I.IdentityError):
            I.resolve_clusters([self._decl(1, "c1"), self._decl(1, "c2")])               # template twice
        with self.assertRaises(I.IdentityError):
            I.resolve_clusters([self._decl(1, "c1", "query"), self._decl(2, "c2", "json")], [["c1", "c2"]])
        with self.assertRaises(I.IdentityError):
            I.resolve_clusters([self._decl(1, "c1")], [["c1", "nope"]])
        with self.assertRaises(I.IdentityError):                                          # audit cannot be skipped
            I.resolve_clusters([I.TemplateDecl("t9", "c9", "query")])

    def test_undeclared_near_duplicate_templates_are_reported(self):
        decls = [self._decl(1, "c1", near=True), self._decl(2, "c2", near=True), self._decl(3, "c3")]
        t = I.resolve_clusters(decls)
        self.assertEqual([(a, b) for a, b, *_ in t.near_duplicates], [("t1", "t2")])
        self.assertEqual(I.resolve_clusters(decls, [["c1", "c2"]]).near_duplicates, ())


class PairAndRng(unittest.TestCase):
    def test_row_rng_is_the_spec_string(self):
        self.assertEqual(I.row_seed("TRAIN", "c1", "q0", 7), "v5-split-v1|TRAIN|c1|q0|7")
        a = [I.row_rng("TRAIN", "c1", "q0", 7).random() for _ in range(3)]
        self.assertEqual(a, [random.Random("v5-split-v1|TRAIN|c1|q0|7").random() for _ in range(3)])

    def test_row_rng_independent_of_hash_seed(self):
        code = ("import sys; sys.path.insert(0, %r); import v5_identities as I; "
                "print(I.row_rng('TRAIN','c1','q0',3).random(), I.pair_id('TRAIN','c1','q0',3))"
                % os.path.join(REPO, "scripts", "dataset"))
        outs = {subprocess.run([sys.executable, "-c", code], env=dict(os.environ, PYTHONHASHSEED=s),
                               capture_output=True, text=True, check=True).stdout for s in ("0", "77")}
        self.assertEqual(len(outs), 1)

    def test_pair_id_and_ambiguous_coordinates(self):
        self.assertNotEqual(I.pair_id("TRAIN", "c1", "q0", 1), I.pair_id("TRAIN", "c1", "q0", 2))
        self.assertNotEqual(I.pair_id("TRAIN", "c1", "q0", 1), I.pair_id("VALIDATION", "c1", "q0", 1))
        for bad in (("TRAIN", "c|1", "q0", 1), ("TRAIN", "c1", "", 1), ("TRAIN", "c1", "q0", -1),
                    ("TRAIN", "c1", "q0", True)):
            with self.assertRaises(I.IdentityError):
                I.pair_id(*bad)

    def test_nul_join_refuses_ambiguous_parts(self):
        with self.assertRaises(I.IdentityError):
            I.nul_sha256("a\0b", "c")
        self.assertEqual(I.nul_sha256("a", "b\0c"), hashlib.sha256(b"a\0b\0c").hexdigest())


class Representation(unittest.TestCase):
    """Owner ruling D-1: set of contiguous 4-grams of Unicode code points of each pre-merge family key."""

    def test_code_point_set_semantics(self):
        self.assertEqual(I.payload_shingles("abcde"), frozenset({"abcd", "bcde"}))
        self.assertEqual(I.payload_shingles("aaaaaa"), frozenset({"aaaa"}))             # a set, not a multiset
        self.assertEqual(I.payload_shingles("ñ’é√x"), frozenset({"ñ’é√", "’é√x"}))      # code points, not bytes
        self.assertEqual(len("ñ’é√x".encode("utf-8")), 11)
        self.assertEqual(I.payload_shingles("abcd"), frozenset({"abcd"}))

    def test_short_keys_are_unobservable_never_padded(self):
        for k in ("id", ";id", "'--", "../", "0"):
            self.assertEqual(I.payload_shingles(k), frozenset())
            self.assertTrue(I.is_unobservable(k))
        fams = I.build_families([rec("r1", ";id"), rec("r2", "; cat /etc/passwd")])
        self.assertEqual(I.unobservable_keys(fams), [";id"])
        self.assertEqual(I.family_near_duplicate_pairs(fams), [])

    def _pair(self, a, b):
        fams = I.build_families([rec("r1", a), rec("r2", b)])
        return len(fams) == 2 and bool(I.family_near_duplicate_pairs(fams))

    def test_positive_examples(self):
        for a, b in (("../../../../etc/passwd", "../../../../../../../etc/passwd"),
                     ("union all select 'inj'||'ect'||'xxx',2,3", "union all select 'inj'||'ect'||'xxx',2,3,4"),
                     ("' or '1'='1' --", "' or '1'='1' #"),
                     ("<svg onload=alert(1)>", "<svg onload=alert(1)>//"),
                     ("${self.module.cache.util.os.system('id')}", "${self.module.runtime.util.os.system('id')}")):
            self.assertTrue(self._pair(a, b), (a, b))

    def test_negative_examples(self):
        for a, b in (("/etc/php.ini", "c:\\apache\\logs\\access.log"),
                     ("admin' --", "admin' or 1=1 or 'x'='x"),
                     ("../../../etc/passwd", "cat</etc/passwd"),
                     ("<script>alert(1)</script>", "{{7*7}}"),
                     ("http://evil.example/", "/etc/shadow")):
            self.assertFalse(self._pair(a, b), (a, b))


class NearDuplicates(unittest.TestCase):
    def test_exact_threshold_and_index(self):
        toks = {"a": frozenset({"one", "two", "thr"}), "b": frozenset({"one", "two", "thr", "fou", "fiv"}),
                "c": frozenset({"one", "two", "six", "sev"}), "d": frozenset()}
        pairs = I.near_duplicate_pairs(toks)
        self.assertEqual([(a, b) for a, b, *_ in pairs], [("a", "b")])     # 3/5 = 0.60 exactly is included
        self.assertTrue(I.is_near_duplicate(3, 5))
        self.assertFalse(I.is_near_duplicate(59, 100))
        self.assertEqual(I.near_duplicate_pairs(toks, {"a": "X", "b": "X", "c": "Y", "d": "Y"}), [])

    def test_matches_brute_force(self):
        rnd = random.Random(3)
        vocab = [f"w{i:02d}x" for i in range(12)]
        toks = {f"k{i}": frozenset(rnd.sample(vocab, rnd.randint(0, 5))) for i in range(80)}
        brute = []
        keys = sorted(toks)
        for i, a in enumerate(keys):
            for b in keys[i + 1:]:
                A, B = toks[a], toks[b]
                if A and B and len(A | B) and 5 * len(A & B) >= 3 * len(A | B):
                    brute.append((a, b))
        self.assertEqual([(a, b) for a, b, *_ in I.near_duplicate_pairs(toks)], brute)

    def test_merge_proposals_are_components(self):
        self.assertEqual(I.propose_merges([("b", "c", 1, 1), ("a", "b", 1, 1), ("x", "y", 1, 1)]),
                         [["a", "b", "c"], ["x", "y"]])


if __name__ == "__main__":
    unittest.main()
