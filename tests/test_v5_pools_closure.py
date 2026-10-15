"""Stage-2 closure tests (issue #70): D59 mapping, interpreter control, provenance, count
reconciliation and deny-list evidence. Small fixtures only; the PATT check skips without the clone.

    python3 -m unittest tests.test_v5_pools_closure -v
"""

import contextlib
import io
import json
import os
import re
import sys
import tempfile
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "scripts", "dataset"))

import v5_pools_common as C  # noqa: E402
import reconcile_v5_attack_pool as R  # noqa: E402
import build_v5_benign_pools as B  # noqa: E402

FIX = os.path.join(REPO, "tests", "fixtures", "v5_benign")
PATT = os.path.expanduser("~/PayloadsAllTheThings")
DENYLIST = os.path.join(REPO, "scripts", "dataset", "v5_lexicon", "patt_third_party_denylist_v1.json")


class D59Mapping(unittest.TestCase):
    def test_known_reasons_map_into_the_d59_vocabulary_or_none(self):
        cases = {"v4_filter:too_short": "AUDIT_REJECT", "structural:placeholder_token": "AUDIT_REJECT",
                 "third_party_file": "OUT_OF_SCOPE", "category_not_extracted_v5": "OUT_OF_SCOPE",
                 "oracle_exact_collision": "ORACLE_REJECT", "possible_full_name": "OUT_OF_SCOPE",
                 "duplicate_canonical": None, "duplicate_value": None, "malformed_row": None}
        for reason, expected in cases.items():
            self.assertEqual(C.d59_exclusion_reason(reason), expected, reason)
        for v in C.d59_mapping_table()["exact"].values():
            self.assertTrue(v is None or v in C.D59_REASONS)

    def test_unknown_reason_fails_loudly(self):
        with self.assertRaises(KeyError):
            C.d59_exclusion_reason("some_new_reason")

    def test_benign_build_keeps_original_reason_and_adds_d59(self):
        with tempfile.TemporaryDirectory() as out, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(B.main(["build", "--raw-dir", FIX, "--out-dir", out]), 0)
            exc = C.read_jsonl(os.path.join(out, "benign", "benign_excluded.jsonl"))
            with open(os.path.join(out, "benign", "manifest.json"), encoding="utf-8") as fh:
                man = json.load(fh)
        self.assertTrue(exc)
        for r in exc:
            self.assertIn("exclusion_reason", r)
            self.assertEqual(r["d59_exclusion_reason"], C.d59_exclusion_reason(r["exclusion_reason"]))
        self.assertEqual(sum(man["d59_exclusion_counts"].values()), len(exc))
        self.assertEqual(man["provenance"]["generator_version"], C.GENERATOR_VERSION)
        self.assertIn("python", man)


class InterpreterAndProvenance(unittest.TestCase):
    def test_verified_interpreter_passes(self):
        if f"{sys.version_info.major}.{sys.version_info.minor}" in C.VERIFIED_PYTHON:
            self.assertFalse(C.check_python()["override_used"])

    def test_unverified_interpreter_refused_unless_overridden(self):
        with mock.patch.object(C, "VERIFIED_PYTHON", ("9.9",)), mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(C.PYTHON_OVERRIDE_ENV, None)
            with self.assertRaises(SystemExit):
                C.check_python()
            os.environ[C.PYTHON_OVERRIDE_ENV] = "1"
            info = C.check_python()
            self.assertTrue(info["override_used"])
            self.assertFalse(info["verified"])

    def test_provenance_records_commit_and_tree_state(self):
        p = C.provenance([os.path.join(REPO, "scripts", "dataset", "v5_pools_common.py")])
        self.assertEqual(p["generator_version"], C.GENERATOR_VERSION)
        self.assertRegex(p["source_commit"] or "", r"^[0-9a-f]{40}$")
        self.assertIn(p["working_tree_clean"], (True, False))
        self.assertIsInstance(p["code_files_modified_or_untracked"], list)


def _rec(rid, cat, status, reason=None, v4="accepted", key="k", scope=None, src="f.txt"):
    return {"record_id": rid, "category_v4": cat, "status": status, "exclusion_reason": reason,
            "v4_filter_reason": v4, "canonical_key": key, "dedup_scope": scope or cat, "source_file": src,
            "label_status": C.LABEL_PENDING if status == C.ACCEPTED else None}


class Reconciliation(unittest.TestCase):
    def test_ledger_sums_and_waterfall(self):
        recs = [_rec("1", "SQLi", C.ACCEPTED, key="a"),
                _rec("2", "SQLi", C.EXCLUDED, "duplicate_canonical", key="a"),
                _rec("3", "SQLi", C.EXCLUDED, "structural:prose_sentence", key="b"),
                _rec("4", "SQLi", C.EXCLUDED, "third_party_file", key="c", src="deny.txt"),
                _rec("5", "SQLi", C.EXCLUDED, "v4_filter:too_short", v4="too_short", key=None)]
        led = R.ledger(recs)["SQLi"]
        self.assertEqual((led["extracted"], led["ACCEPTED"], led["v4_filter"], led["structural"],
                          led["third_party_file"], led["duplicate_canonical"]), (5, 1, 1, 1, 1, 1))
        w = R.waterfall(recs, spec_initial={"deny.txt"}, denied={"deny.txt"})["SQLi"]
        self.assertEqual((w["U0_v4_accepted"], w["U1_minus_spec_initial_denylist"], w["accepted_rows"]), (3, 2, 1))

    def test_unknown_bucket_fails(self):
        with self.assertRaises(ValueError):
            R.ledger([_rec("1", "X", C.EXCLUDED, "mystery")])

    def test_real_pool_reconciles_if_built(self):
        d = os.path.join(C.DEFAULT_OUT_DIR, "attack")
        if not os.path.isfile(os.path.join(d, "manifest.json")):
            self.skipTest("attack pool not built locally (gitignored)")
        res = R.reconcile(d, DENYLIST)
        self.assertEqual(res["total_extracted"], res["accepted"] + res["excluded"])
        for cat, row in res["ledger"].items():
            m = res["manifest_counts"][cat]
            self.assertEqual((row["extracted"], row["ACCEPTED"]), (m["extracted"], m["accepted"]), cat)


class DenylistEvidence(unittest.TestCase):
    def test_stage2_denials_have_evidence_present_in_patt(self):
        if not os.path.isdir(PATT):
            self.skipTest("PATT clone not available")
        with open(DENYLIST, encoding="utf-8") as fh:
            deny = json.load(fh)
        self.assertEqual(deny["status"], "PROPOSED")
        for e in deny["denied"]:
            self.assertEqual(e["status"], "PROPOSED")
            self.assertTrue(e["evidence"], e["path"])
            if not e["basis"].startswith("stage2"):
                continue
            with open(os.path.join(PATT, e["path"]), encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
            quoted = re.findall(r'"([^"]{6,})"', e["evidence"].replace('\\"', '"'))
            self.assertTrue(any(q in text for q in quoted), (e["path"], quoted))


if __name__ == "__main__":
    unittest.main()
