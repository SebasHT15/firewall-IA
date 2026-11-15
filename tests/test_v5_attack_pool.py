"""Tests for scripts/dataset/build_v5_attack_pool.py.

A small PATT-shaped fixture tree is built in a temp dir (no real PATT, no network). The builder is run
with a stub PATT guard; the real guard (`check_patt`) is tested with a mocked `subprocess.run`.
"""
import hashlib
import json
import os
import sys
import tempfile
import unittest
from collections import Counter
from types import SimpleNamespace
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts", "dataset"))
import build_v5_attack_pool as B  # noqa: E402

p4, C = B.p4, B.C
FENCE = "```"
STUB_GUARD = lambda patt: {"commit": B.PINNED_PATT_COMMIT, "clean": True}   # noqa: E731


def md(*blocks):
    return "# Title\n\nText.\n\n" + "\n".join(f"{FENCE}\n" + "\n".join(b) + f"\n{FENCE}\n" for b in blocks)


FIXTURE = {
    "SQL Injection/README.md": md(
        ["' OR 1=1 --", "' OR 1=1 --", "%27%20OR%201%3D1%20--", "| col | col |", "a", "SELECT {FILE}"],
        ["' or '1'='1", "?q={payload}", "swissky@crashlab:~$ id"]),
    "SQL Injection/Intruder/FUZZDB_X.txt": "' or 'x'='x\n' UNION SELECT 1,2 --\n",
    "SQL Injection/Intruder/Generic.txt": "1' AND SLEEP(5)#\n\n' or '1'='1\n",
    "XSS Injection/Intruders/x.txt": "<script>alert(1)</script>\n\\u003cscript\\u003ealert(1)\n&lt;img src=x onerror=alert(1)&gt;\n",
    "Directory Traversal/Intruder/a.txt": "../../etc/passwd\n..%c0%aF../etc/passwd\n",
    "File Inclusion/Intruders/b.txt": "../../etc/passwd\n%252e%252e/etc/passwd\n",
    "Command Injection/Intruder/c.txt": ";cat${IFS}/etc/passwd\ncat /etc/passwd # Read Users\n| id\n",
    "Command Injection/Intruder/d.txt": "%0a%0d\n",                     # empty canonical_key (owner ruling D-4)
    "SQL Injection/Intruder/e.txt": "/* only a comment */\n",          # empty canonical_key (owner ruling D-4)
    # stage-3 admissibility (owner ruling, round 3): result-table borders (one repeated) and short keys
    "SQL Injection/Intruder/f.txt": "+------+---------+\n+------+---------+\n+---+\n' --\n",
    "Open Redirect/Intruder/g.txt": "/%5cexample.com\n/%5cexample.org\n/%5cevil.example/login\n",
    "Command Injection/Intruder/h.txt": "& id\n",
    "Server Side Template Injection/Ruby.md": md(["<%= 7*7 %> # Rendered RCE", "{{7*7}}"]),
    "Server Side Request Forgery/README.md": md(["http://169.254.169.254/latest/meta-data/"]),
    "JSON Web Token/README.md": md(["eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ."]),
    "XXE Injection/README.md": md(['<?xml version="1.0"?>\n<!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]>\n<x>&a;</x>'],
                                  ['<!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]>']),
}
EMPTY_AND_BAD = {
    "Open Redirect/empty.txt": "",
    "Open Redirect/unterminated.md": f"# T\n\n{FENCE}\n//evil.example.com/%2f..\n",
}


def write_tree(root, files, raw_files=None):
    for cat in p4.CATEGORY_SHAPES:
        os.makedirs(os.path.join(root, cat), exist_ok=True)
    for rel, text in files.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
    for rel, data in (raw_files or {}).items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)


def write_denylist(path, denied_paths, schema="v5-patt-third-party-denylist/v1"):
    doc = {"schema": schema, "status": "PROPOSED",
           "denied": [{"path": p, "reason": "fuzzdb_prefix", "evidence_kind": "name", "evidence": "x",
                       "basis": "spec_initial_list", "status": "PROPOSED"} for p in denied_paths],
           "reviewed_not_denied": []}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)


def jl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(x) for x in fh if x.strip()]


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        t = cls.tmp.name
        cls.patt = os.path.join(t, "patt")
        write_tree(cls.patt, {**FIXTURE, **EMPTY_AND_BAD},
                   {"Command Injection/Intruder/bad.txt": b"' or 1=1 --\n\xff\xfe junk' or 2=2 --\n"})
        cls.deny = os.path.join(t, "deny.json")
        write_denylist(cls.deny, ["SQL Injection/Intruder/FUZZDB_X.txt"])
        cls.out = os.path.join(t, "out")
        cls.manifest = B.build(cls.patt, cls.out, cls.deny, patt_guard=STUB_GUARD)
        d = os.path.join(cls.out, "attack")
        cls.acc, cls.exc = jl(os.path.join(d, B.POOL_NAME)), jl(os.path.join(d, B.EXCLUDED_NAME))
        cls.all = cls.acc + cls.exc

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def find(self, rows, **kw):
        return [r for r in rows if all(r[k] == v for k, v in kw.items())]


class ExtractionTests(Base):
    def test_provenance_and_position(self):
        cands, files = B.extract_patt(self.patt)
        sql = [c for c in cands if c["source_file"] == "SQL Injection/README.md"]
        self.assertEqual(sql[0]["source_kind"], "md")
        self.assertEqual((sql[0]["block_index"], sql[0]["line_index"]), (0, 0))
        second = [c for c in sql if c["block_index"] == 1]
        self.assertEqual(second[0]["line_index"], 0)
        self.assertEqual(second[0]["raw"], "' or '1'='1")
        gen = [c for c in cands if c["source_file"] == "SQL Injection/Intruder/Generic.txt"]
        self.assertEqual([(c["block_index"], c["line_index"], c["raw"]) for c in gen],
                         [(None, 0, "1' AND SLEEP(5)#"), (None, 1, ""), (None, 2, "' or '1'='1")])
        self.assertTrue(all(c["source_kind"] == "txt" for c in gen))
        self.assertEqual(files["SQL Injection/README.md"]["sha256"],
                         hashlib.sha256(open(os.path.join(self.patt, "SQL Injection", "README.md"), "rb").read()).hexdigest())

    def test_block_level_category_keeps_whole_block(self):
        cands, _ = B.extract_patt(self.patt)
        xxe = [c for c in cands if c["category"] == "XXE Injection"]
        self.assertEqual(len(xxe), 2)
        self.assertTrue(xxe[0]["block_level"])
        self.assertEqual((xxe[0]["block_index"], xxe[0]["line_index"]), (0, 0))
        self.assertIn("<!DOCTYPE", xxe[0]["raw"])
        self.assertIn("\n", xxe[0]["raw"])
        # V4 quirk kept on purpose: a multi-line block holds control characters (newline), so V4 rejects it
        self.assertEqual(p4.quality_filter(xxe[0]["raw"], "XXE Injection")[1], "control_chars")
        self.assertFalse(xxe[1]["block_level"])

    def test_equivalence_with_v4_loop_on_fixture(self):
        cands, _ = B.extract_patt(self.patt)
        mine = [(c["category"], q[0], c["source_file"]) for c in cands
                for q in [p4.quality_filter(c["raw"], c["category"])] if q[0] is not None]
        v4_rows, v4_stats = B.v4_reference(self.patt)
        v4 = [(r["category"], r["payload"], r["source"]) for r in v4_rows]
        self.assertEqual(Counter(mine), Counter(v4))
        self.assertEqual(mine, v4)
        self.assertTrue(len(mine) > 10)
        self.assertEqual(Counter(c["category"] for c in cands), Counter(v4_stats["candidates_per_category"]))
        eq = self.manifest["v4_equivalence"]
        self.assertTrue(eq["multiset_equal"] and eq["ordered_equal"] and eq["reject_reason_counts_equal"])

    def test_v4_reject_reason_is_kept(self):
        r = self.find(self.all, source_file="SQL Injection/README.md", payload_raw="| col | col |")[0]
        self.assertEqual((r["status"], r["exclusion_reason"]), ("EXCLUDED", "v4_filter:markdown_artifact"))
        self.assertEqual(r["v4_filter_reason"], "markdown_artifact")
        r = self.find(self.all, payload_raw="SELECT {FILE}")[0]
        self.assertEqual(r["exclusion_reason"], "v4_filter:fuzzer_placeholder")

    def test_malformed_inputs(self):
        # undecodable bytes are dropped like V4 (errors="ignore"); nothing crashes
        bad = self.find(self.all, source_file="Command Injection/Intruder/bad.txt")
        self.assertTrue(any(r["status"] == "ACCEPTED" for r in bad))
        self.assertTrue(all("�" not in r["payload_raw"] for r in bad))
        self.assertEqual(self.find(self.all, source_file="Open Redirect/empty.txt"), [])
        self.assertEqual(self.find(self.all, source_file="Open Redirect/unterminated.md"), [])
        self.assertEqual(self.manifest["per_file"]["Open Redirect/empty.txt"]["candidates"], 0)

    def test_record_id_is_stable_and_unique(self):
        ids = [r["record_id"] for r in self.all]
        self.assertEqual(len(ids), len(set(ids)))
        r = self.find(self.all, source_file="SQL Injection/Intruder/Generic.txt", line_index=0)[0]
        want = hashlib.sha256("\0".join([r["source_file"], r["source_kind"], "", "0", r["payload_raw"]])
                              .encode()).hexdigest()[:16]
        self.assertEqual(r["record_id"], want)


class ExclusionTests(Base):
    def test_category_deny_list_counted_and_excluded(self):
        for cat in ("JSON Web Token", "XXE Injection"):
            rows = self.find(self.all, category_v4=cat, v4_filter_reason="accepted")
            self.assertEqual(len(rows), 1)
            self.assertEqual((rows[0]["status"], rows[0]["exclusion_reason"]), ("EXCLUDED", "category_not_extracted_v5"))
            self.assertEqual(self.manifest["counts"][cat]["category_denied"], 1)
            self.assertEqual(self.manifest["counts"][cat]["accepted"], 0)
        self.assertEqual(self.find(self.acc, category_v4="JSON Web Token"), [])
        self.assertTrue(set(self.manifest["denied_categories"]) >= {"JSON Web Token", "XXE Injection", "GraphQL Injection",
                                                                   "LDAP Injection", "Insecure Deserialization",
                                                                   "Cross-Site Request Forgery", "Request Smuggling"})

    def test_hpp_and_smuggling_hardcoded_lists_are_not_built(self):
        cats = {r["category_v4"] for r in self.all if r["source_kind"] == "hardcoded"}
        self.assertEqual(cats, {"CRLF Injection", "XPath Injection"})
        self.assertEqual(self.find(self.all, category_v4="HTTP Parameter Pollution"), [])

    def test_third_party_deny_list(self):
        rows = self.find(self.all, source_file="SQL Injection/Intruder/FUZZDB_X.txt")
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(r["status"] == "EXCLUDED" and r["exclusion_reason"] == "third_party_file"
                            and r["denylist_reason"] == "fuzzdb_prefix" for r in rows))
        self.assertEqual(self.manifest["counts"]["SQL Injection"]["third_party_denied"], 2)
        self.assertEqual(self.manifest["denylist"]["sha256"], hashlib.sha256(open(self.deny, "rb").read()).hexdigest())

    def test_denylist_path_missing_from_patt_is_fatal(self):
        with tempfile.TemporaryDirectory() as t:
            dl = os.path.join(t, "d.json")
            write_denylist(dl, ["SQL Injection/Intruder/NOPE.txt"])
            with self.assertRaises(SystemExit):
                B.build(self.patt, os.path.join(t, "o"), dl, patt_guard=STUB_GUARD)

    def test_denylist_schema_and_status_checked(self):
        with tempfile.TemporaryDirectory() as t:
            dl = os.path.join(t, "d.json")
            write_denylist(dl, [], schema="other/v9")
            with self.assertRaises(SystemExit):
                B.load_denylist(dl)

    def test_structural_exclusions_with_reasons(self):
        r = self.find(self.all, payload_raw="?q={payload}")[0]
        self.assertEqual(r["exclusion_reason"], "structural:placeholder_token")
        self.assertEqual(r["structural_flags"][0], "placeholder_token")
        r = self.find(self.all, payload_raw="swissky@crashlab:~$ id")[0]
        self.assertEqual(r["exclusion_reason"], "structural:tool_output_marker")
        # trailing documentation comment is a rejection outside SSTI
        r = self.find(self.all, payload_raw="cat /etc/passwd # Read Users")[0]
        self.assertEqual(r["exclusion_reason"], "structural:trailing_doc_comment")
        self.assertEqual(r["category_v4"], "Command Injection")

    def test_empty_canonical_identity_is_excluded_with_provenance(self):
        # owner ruling D-4: no payload_family_id can be built; excluded, never relabelled, provenance kept
        rows = [r for r in self.all if r["payload_wire"] in ("%0a%0d", "/* only a comment */")]
        self.assertEqual(len(rows), 2)
        for r in rows:
            self.assertEqual(r["canonical_key"], "")
            self.assertEqual((r["status"], r["exclusion_reason"]), (C.EXCLUDED, B.IDENTITY_EMPTY))
            self.assertEqual(r["d59_exclusion_reason"], "AUDIT_REJECT")
            self.assertIsNone(r["label_status"])
            self.assertTrue(r["source_file"] and r["line_index"] is not None and r["record_id"])
            self.assertIn(r["category_v4"], ("Command Injection", "SQL Injection"))
        self.assertFalse(any(r["canonical_key"] == "" for r in self.acc))
        self.assertFalse(any(r.get("duplicate_of") in {x["record_id"] for x in rows} for r in self.all))

    def test_identity_admissibility_exclusions(self):
        # stage-3 owner ruling (round 3): never relabelled, provenance kept, D59 AUDIT_REJECT (PROPOSED)
        borders = [r for r in self.all if r["payload_raw"] in ("+------+---------+", "+---+")]
        self.assertEqual(len(borders), 3)                     # the repeated border is not a "duplicate"
        short = [r for r in self.all if r["payload_raw"] in ("' --", "& id", "/%5cexample.com", "/%5cexample.org")]
        self.assertEqual(len(short), 4)
        for rows, reason in ((borders, B.NOT_A_PAYLOAD_TABLE_BORDER), (short, B.IDENTITY_UNOBSERVABLE)):
            for r in rows:
                self.assertEqual((r["status"], r["exclusion_reason"]), (C.EXCLUDED, reason), r["payload_raw"])
                self.assertEqual(r["d59_exclusion_reason"], "AUDIT_REJECT")
                self.assertIsNone(r["label_status"])
                self.assertIsNone(r["duplicate_of"])
                self.assertTrue(r["source_file"] and r["line_index"] is not None and r["record_id"])
        self.assertEqual(B.I.family_key("/%5cexample.org"), "/\\H")    # one short key, two records, both excluded
        keys = {B.I.family_key(r["payload_wire"]) for r in borders + short}
        for r in self.acc:
            k = B.I.family_key(r["payload_wire"])
            self.assertFalse(B.I.is_unobservable(k), r["payload_wire"])
            self.assertNotIn(k, keys)
        self.assertTrue(self.find(self.acc, payload_raw="/%5cevil.example/login"))      # long key: kept
        counts = self.manifest["identity_admissibility"]["excluded_by_reason"]
        self.assertEqual(counts, {B.IDENTITY_UNOBSERVABLE: 4, B.NOT_A_PAYLOAD_TABLE_BORDER: 3})
        # the fixture holds none of the reviewed records: a stale or absent reviewed id is listed, never silent
        self.assertEqual(self.manifest["identity_admissibility"]["reviewed_records_not_seen"], sorted(B.REVIEWED_DEGENERATE))

    def test_reviewed_degenerate_records_need_their_reviewed_key(self):
        rid = "40e435d53f53c46b"                                   # `%0Aid`, reviewed in round 3
        self.assertEqual(B.admissibility_reason({"record_id": rid, "payload_wire": "%0Aid"}),
                         "identity_degenerate:command_separator_lost")
        with self.assertRaises(SystemExit):                        # same record, different identity: review again
            B.admissibility_reason({"record_id": rid, "payload_wire": "%0Acat /etc/passwd"})
        # an unreviewed record never inherits the reviewed reason; its short key falls to e3
        self.assertEqual(B.admissibility_reason({"record_id": "0000000000000000", "payload_wire": "%0Aid"}),
                         B.IDENTITY_UNOBSERVABLE)
        self.assertIsNone(B.admissibility_reason({"record_id": "0000000000000000", "payload_wire": "' or 1=1 --"}))
        for rid, (key, reason) in B.REVIEWED_DEGENERATE.items():
            self.assertTrue(B.I.is_unobservable(key) and B.is_inadmissible(reason), rid)

    def test_no_readmission_through_another_source(self):
        recs = [{"record_id": "a", "status": C.EXCLUDED, "exclusion_reason": B.IDENTITY_UNOBSERVABLE, "payload_wire": "' --"},
                {"record_id": "b", "status": C.ACCEPTED, "exclusion_reason": None, "payload_wire": "%27%20--"}]
        with self.assertRaises(SystemExit):
            B._check_no_readmission(recs)
        recs[1]["payload_wire"] = "' or 1=1 --"
        B._check_no_readmission(recs)

    def test_ssti_comment_is_stripped_not_dropped(self):
        r = self.find(self.acc, payload_raw="<%= 7*7 %> # Rendered RCE")[0]
        self.assertEqual(r["transform"], "stripped_doc_comment")
        self.assertEqual(r["payload_wire"], "<%= 7*7 %>")
        self.assertEqual(r["payload_v4"], "<%= 7*7 %> # Rendered RCE")
        self.assertEqual((r["category_v4"], r["d47_category"], r["reason_string"]),
                         ("Server Side Template Injection", "ssti", p4.CATEGORY_SHAPES["Server Side Template Injection"][0]))
        self.assertEqual(r["canonical_key"], p4.canonical_key("<%= 7*7 %>"))
        plain = self.find(self.acc, payload_raw="{{7*7}}")[0]
        self.assertIsNone(plain["transform"])
        self.assertEqual(self.manifest["counts"]["Server Side Template Injection"]["ssti_comment_stripped_accepted"], 1)


class DuplicateTests(Base):
    def test_exact_and_canonical_duplicates(self):
        rows = self.find(self.all, source_file="SQL Injection/README.md", block_index=0)
        by_raw = {(r["line_index"]): r for r in rows}
        keeper, exact, canon = by_raw[0], by_raw[1], by_raw[2]
        self.assertEqual(keeper["status"], "ACCEPTED")
        self.assertEqual((exact["status"], exact["exclusion_reason"], exact["duplicate_of"]),
                         ("EXCLUDED", "duplicate_exact", keeper["record_id"]))
        self.assertEqual((canon["exclusion_reason"], canon["duplicate_of"]), ("duplicate_canonical", keeper["record_id"]))
        self.assertEqual(keeper["canonical_key"], canon["canonical_key"])

    def test_first_by_source_file_and_position_is_kept(self):
        # '/etc/passwd' traversal is in Directory Traversal/a.txt and File Inclusion/b.txt (one D49 scope)
        dt = self.find(self.all, source_file="Directory Traversal/Intruder/a.txt", line_index=0)[0]
        fi = self.find(self.all, source_file="File Inclusion/Intruders/b.txt", line_index=0)[0]
        self.assertEqual(dt["status"], "ACCEPTED")
        self.assertEqual((fi["exclusion_reason"], fi["duplicate_of"]), ("duplicate_exact", dt["record_id"]))
        self.assertEqual((fi["category_v4"], dt["category_v4"]), ("File Inclusion", "Directory Traversal"))

    def test_cross_category_duplicate_is_not_excluded_and_not_relabelled(self):
        sqli = self.find(self.acc, category_v4="SQL Injection", payload_wire="' or '1'='1")
        xp = self.find(self.acc, category_v4="XPath Injection", payload_wire="' or '1'='1")
        self.assertEqual(len(sqli), 1)
        self.assertEqual(len(xp), 1)
        self.assertEqual(sqli[0]["also_in_categories"], ["XPath Injection"])
        self.assertEqual(xp[0]["also_in_categories"], ["SQL Injection"])
        scopes = [tuple(x["scopes"]) for x in self.manifest["cross_category_canonical_duplicates"]]
        self.assertIn(("SQL Injection", "XPath Injection"), scopes)

    def test_duplicate_of_points_to_an_accepted_record(self):
        acc_ids = {r["record_id"] for r in self.acc}
        for r in self.exc:
            if r["exclusion_reason"].startswith("duplicate_"):
                self.assertIn(r["duplicate_of"], acc_ids)
            else:
                self.assertIsNone(r["duplicate_of"])


class FieldTests(Base):
    def test_no_record_is_ever_verified(self):
        self.assertTrue(all(r["label_status"] == C.LABEL_PENDING for r in self.acc))
        self.assertTrue(all(r["label_status"] is None for r in self.exc))
        for name in (B.POOL_NAME, B.EXCLUDED_NAME):
            with open(os.path.join(self.out, "attack", name), encoding="utf-8") as fh:
                text = fh.read()
            self.assertNotIn(C.LABEL_VERIFIED, text)
        self.assertIn("no payload is VERIFIED", self.manifest["status"])

    def test_filters_never_change_category_or_reason_string(self):
        for r in self.all:
            top = r["source_file"].split("/")[0]
            if r["source_kind"] == "hardcoded":
                cat = {"hardcoded:CRLF_PAYLOADS": "CRLF Injection", "hardcoded:XPATH_PAYLOADS": "XPath Injection"}[r["source_file"]]
                want = p4.HARDCODED_SHAPES[cat][0]
            else:
                cat, want = top, p4.CATEGORY_SHAPES[top][0]
            self.assertEqual(r["category_v4"], cat)
            self.assertEqual(r["reason_string"], want)
        self.assertEqual(self.find(self.acc, category_v4="Directory Traversal")[0]["d47_category"], "path_file_access")
        self.assertEqual(self.find(self.acc, category_v4="File Inclusion")[0]["d47_category"], "path_file_access")

    def test_tier_is_proposed_and_licence(self):
        self.assertEqual(self.find(self.acc, category_v4="SQL Injection")[0]["tier"], "primary_PROPOSED")
        self.assertEqual(self.find(self.acc, category_v4="Server Side Request Forgery")[0]["tier"], "report_only_PROPOSED")
        self.assertEqual(self.find(self.acc, category_v4="SQL Injection")[0]["license"], B.LICENSE_PATT)
        crlf = self.find(self.acc, category_v4="CRLF Injection")
        self.assertTrue(crlf)
        self.assertTrue(all(r["license"] == B.LICENSE_PROJECT and r["source_kind"] == "hardcoded" for r in crlf))

    def test_wire_form_and_logical(self):
        pre = self.find(self.acc, payload_wire="..%c0%aF../etc/passwd")[0]
        self.assertEqual(pre["payload_wire_form"], "pre_encoded")
        self.assertEqual(pre["logical_decode"], "invalid_utf8_kept_verbatim")
        self.assertEqual(pre["payload_logical"], pre["payload_wire"])
        enc = self.find(self.acc, payload_wire="%252e%252e/etc/passwd")[0]
        self.assertEqual(B.logical_of(enc["payload_wire"]), ("%2e%2e/etc/passwd", "decoded_once"))
        self.assertEqual(enc["payload_logical"], "%2e%2e/etc/passwd")
        plain = self.find(self.acc, payload_wire="../../etc/passwd")[0]
        self.assertEqual((plain["payload_wire_form"], plain["payload_logical"]), ("plain", "../../etc/passwd"))
        self.assertEqual(B.wire_form("%zz"), "plain")
        self.assertEqual(B.wire_form("a%4"), "plain")
        self.assertEqual(B.wire_form("a%4f"), "pre_encoded")

    def test_native_forms(self):
        nf = B.native_forms
        self.assertEqual(nf("%252e%252e/etc"), ["double_encoding"])
        self.assertEqual(nf("\\u003cscript\\u003e"), ["unicode_escape"])
        self.assertEqual(nf("&lt;a&gt;"), ["html_entity"])
        self.assertEqual(nf("&#x3c;a&#60;"), ["html_entity"])
        self.assertEqual(nf("a&b;c"), [])                      # not a real entity name
        self.assertEqual(nf(";cat${IFS}/etc"), ["ifs"])
        self.assertEqual(nf("..%c0%aF.."), ["mixed_case_hex"])
        self.assertEqual(nf("%2F%2e"), [])                     # mixed ACROSS tokens is not token-level mixed
        self.assertEqual(B.hex_case_profile("%2F%2e"), "mixed_across_tokens")
        self.assertEqual(nf("plain text"), [])
        self.assertIn("param_fragmentation", self.manifest["native_forms_not_detected"])
        self.assertTrue(set(B.NATIVE_FORM_ORDER) <= {"double_encoding", "unicode_escape", "html_entity", "ifs", "mixed_case_hex"})
        # propagated into records
        # V4 quirk kept on purpose: PLACEHOLDER_RE (`{UPPER}`) also matches `${IFS}`, so V4 rejects it
        # before the builder sees it; `ifs` can therefore never be native in the V4-filtered pool
        r = self.find(self.exc, payload_raw=";cat${IFS}/etc/passwd")[0]
        self.assertEqual(r["exclusion_reason"], "v4_filter:fuzzer_placeholder")
        self.assertEqual(self.find(self.acc, payload_wire="&lt;img src=x onerror=alert(1)&gt;")[0]["native_forms"], ["html_entity"])


class ArtifactTests(Base):
    def test_manifest_integrity(self):
        m = json.load(open(os.path.join(self.out, "attack", B.MANIFEST_NAME), encoding="utf-8"))
        self.assertEqual(m["schema"], B.BUILDER_SCHEMA)
        self.assertEqual(sorted(a["path"] for a in m["artifacts"]), [B.EXCLUDED_NAME, B.POOL_NAME])
        for a in m["artifacts"]:
            data = open(os.path.join(self.out, "attack", a["path"]), "rb").read()
            self.assertEqual(a["sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(a["bytes"], len(data))
            self.assertEqual(a["records"], data.count(b"\n"))
        for p, h in m["code_fingerprint"].items():
            self.assertEqual(h, hashlib.sha256(open(os.path.join(ROOT, p), "rb").read()).hexdigest())
        self.assertTrue(any(p.endswith("build_v5_attack_pool.py") for p in m["code_fingerprint"]))
        self.assertEqual(len(m["filter_rules_fingerprint"]), 64)
        self.assertEqual(m["patt"]["commit"], B.PINNED_PATT_COMMIT)
        self.assertTrue(m["patt"]["clean"])
        self.assertFalse(m["per_source_file_share"]["cap_applied"])
        self.assertTrue(any("MIT" in x and "ASSUMPTION" in x for x in m["known_limitations"]))

    def test_counts_are_consistent(self):
        for cat, t in self.manifest["counts"].items():
            rows = self.find(self.all, category_v4=cat)
            self.assertEqual(t["extracted"], len(rows))
            self.assertEqual(t["accepted"], len(self.find(self.acc, category_v4=cat)))
            self.assertEqual(t["extracted"], t["v4_filter_rejected"] + t["category_denied"] + t["third_party_denied"]
                             + t["structural_excluded"] + t["identity_undefined"] + t["identity_inadmissible"] + t["duplicate_exact"]
                             + t["duplicate_canonical"] + t["accepted"])

    def test_share_report_flags_without_capping(self):
        sh = self.manifest["per_source_file_share"]["scopes"]["SQL Injection"]
        self.assertEqual(sum(f["accepted"] for f in sh["files"]), sh["accepted"])
        self.assertTrue(all(f["above_25pct"] == (f["share"] > 0.25) for f in sh["files"]))
        self.assertEqual(sh["accepted"], len(self.find(self.acc, category_v4="SQL Injection")))

    def test_determinism_two_runs_byte_identical(self):
        with tempfile.TemporaryDirectory() as t:
            B.build(self.patt, t, self.deny, patt_guard=STUB_GUARD)
            for name in (B.POOL_NAME, B.EXCLUDED_NAME, B.MANIFEST_NAME):
                a = open(os.path.join(self.out, "attack", name), "rb").read()
                b = open(os.path.join(t, "attack", name), "rb").read()
                self.assertEqual(hashlib.sha256(a).hexdigest(), hashlib.sha256(b).hexdigest(), name)
        det = B.verify_determinism(self.patt, self.out, self.deny, patt_guard=STUB_GUARD)
        self.assertTrue(det["identical"])


class GuardTests(unittest.TestCase):
    def fake_git(self, head, status):
        def run(cmd, **kw):
            out = head if "rev-parse" in cmd else status
            return SimpleNamespace(stdout=out + "\n", returncode=0)
        return run

    def test_wrong_commit_refused(self):
        with mock.patch.object(B.subprocess, "run", self.fake_git("0" * 40, "")):
            with self.assertRaises(SystemExit):
                B.check_patt("/x")

    def test_dirty_tree_refused(self):
        with mock.patch.object(B.subprocess, "run", self.fake_git(B.PINNED_PATT_COMMIT, " M README.md")):
            with self.assertRaises(SystemExit):
                B.check_patt("/x")

    def test_pinned_and_clean_accepted(self):
        with mock.patch.object(B.subprocess, "run", self.fake_git(B.PINNED_PATT_COMMIT, "")):
            self.assertEqual(B.check_patt("/x"), {"commit": B.PINNED_PATT_COMMIT, "clean": True})

    def test_build_stops_on_a_bad_guard_before_writing(self):
        with tempfile.TemporaryDirectory() as t:
            patt = os.path.join(t, "patt")
            write_tree(patt, {})
            out = os.path.join(t, "out")

            def refuse(_):
                raise SystemExit("REFUSED")
            with self.assertRaises(SystemExit):
                B.build(patt, out, os.path.join(t, "d.json"), patt_guard=refuse)
            self.assertFalse(os.path.exists(out))

    def test_protected_paths_refused(self):
        with tempfile.TemporaryDirectory() as t:
            ok = os.path.join(t, "patt")
            write_tree(ok, {})
            dl = os.path.join(t, "d.json")
            write_denylist(dl, [])
            for bad in (os.path.join(t, "external_v1", "patt"), os.path.join(t, "reports", "external", "patt")):
                write_tree(bad, {})
                with self.assertRaises(SystemExit):
                    B.build(bad, os.path.join(t, "o"), dl, patt_guard=STUB_GUARD)
            with self.assertRaises(SystemExit):
                B.build(ok, os.path.join(t, "internal_test", "o"), dl, patt_guard=STUB_GUARD)
            with self.assertRaises(SystemExit):
                B.load_denylist(os.path.join(t, "csic_database.csv"))
            with self.assertRaises(SystemExit):
                B.load_denylist(os.path.join(t, "eval.jsonl"))
            self.assertFalse(os.path.exists(os.path.join(t, "o")))

    def test_missing_category_directory_is_fatal(self):
        with tempfile.TemporaryDirectory() as t:
            os.makedirs(os.path.join(t, "SQL Injection"))
            with self.assertRaises(SystemExit):
                B.extract_patt(t)


class PlanTests(unittest.TestCase):
    def test_plan_uses_d47_vocabulary_and_proposed_tiers(self):
        self.assertEqual(set(B.hybrid_contracts.ANALYZER_CATEGORIES) >= {d for _, d in B.PLAN.values()}, True)
        self.assertEqual({t for t, _ in B.PLAN.values()}, {"primary_PROPOSED", "report_only_PROPOSED"})
        self.assertEqual(sorted(c for c, (t, _) in B.PLAN.items() if t == "primary_PROPOSED"),
                         sorted(["SQL Injection", "XSS Injection", "Directory Traversal", "File Inclusion",
                                 "Command Injection", "Server Side Template Injection"]))
        self.assertEqual(set(B.DENIED_CATEGORIES), {"Cross-Site Request Forgery", "GraphQL Injection",
                                                    "Insecure Deserialization", "JSON Web Token", "LDAP Injection",
                                                    "Request Smuggling", "XXE Injection"})
        self.assertFalse(set(B.DENIED_CATEGORIES) & set(B.PLAN))

    def test_default_denylist_file_is_valid(self):
        doc, denied, sha = B.load_denylist(B.DEFAULT_DENYLIST)
        self.assertEqual(len(sha), 64)
        self.assertGreaterEqual(len(denied), 23)
        self.assertEqual(doc["status"], "APPROVED")                        # v2, D66
        self.assertTrue(all(e["status"] == "APPROVED" and e["evidence"] for e in denied.values()))
        for p in ("SQL Injection/Intruder/Auth_Bypass.txt", "SQL Injection/Intruder/Auth_Bypass2.txt",
                  "XSS Injection/Intruders/jsonp_endpoint.txt"):
            self.assertIn(p, denied)
        for p in ("XSS Injection/Intruders/XSSDetection.txt", "XSS Injection/Intruders/IntrudersXSS.txt",
                  "Directory Traversal/Intruder/dotdotpwn.txt", "File Inclusion/Intruders/JHADDIX_LFI.txt"):
            self.assertIn(p, denied)
        self.assertTrue(len([p for p in denied if "/FUZZDB_" in p]) == 8)
        # the four files the spec only "noted for review" are adjudicated explicitly
        decided = set(denied) | {e["path"] for e in doc["reviewed_not_denied"]}
        for p in ("XSS Injection/Intruders/jsonp_endpoint.txt", "SQL Injection/Intruder/Auth_Bypass.txt",
                  "SQL Injection/Intruder/Auth_Bypass2.txt"):
            self.assertIn(p, decided)
            self.assertIn(p, denied)          # v1 kept them flagged; v2 denies them on content evidence (D66)
            self.assertNotIn(p, {e["path"] for e in doc["reviewed_not_denied"]})


if __name__ == "__main__":
    unittest.main()
