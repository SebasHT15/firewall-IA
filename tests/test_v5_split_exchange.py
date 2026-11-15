#!/usr/bin/env python3
"""Tests for the consumer-side V5 split-assignment METADATA reader (v5_split_exchange.py).

Synthetic fixtures only (built with the existing `v5_split_checks` builders). NO real pool, NO real
split, NO protected data. Covers the clean path and regressions for the four defects Codex reproduced:
  D1 no `strict` bypass — a contaminated artifact can never yield data;
  D2 verify + consume use ONE read (no TOCTOU re-read);
  D3 content integrity over consumed bytes (assignment-only edit caught; a coordinated rewrite passes the
     hash but is still caught structurally; a trusted external digest is honoured);
  D4 per-record type/field validation (missing kind/id, non-dict records refused).
"""
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
for _p in (os.path.join(REPO, "scripts", "training"), os.path.join(REPO, "scripts", "dataset")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import v5_split_exchange as X   # noqa: E402
import v5_split_checks as SC    # noqa: E402
import v5_split as S            # noqa: E402


def _build_fixture_dir(out_dir: str) -> str:
    S.write_assignment(SC.build_from(SC.fixture_inputs()), out_dir)
    return out_dir


class SplitExchangeTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="v5-exchange-")
        _build_fixture_dir(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- helpers ----------------------------------------------------------------
    def _records(self):
        with open(os.path.join(self.tmp, X.ASSIGNMENT_FILE), encoding="utf-8") as fh:
            return [json.loads(ln) for ln in fh if ln.strip()]

    def _write_lines(self, lines):
        with open(os.path.join(self.tmp, X.ASSIGNMENT_FILE), "w", encoding="utf-8") as fh:
            for ln in lines:
                fh.write(ln + "\n")

    def _reseal(self):
        """Simulate a COORDINATED rewrite: update manifest.assignment_sha256 to the current file bytes."""
        with open(os.path.join(self.tmp, X.ASSIGNMENT_FILE), "rb") as fh:
            got = hashlib.sha256(fh.read()).hexdigest()
        mp = os.path.join(self.tmp, X.MANIFEST_FILE)
        with open(mp, encoding="utf-8") as fh:
            m = json.load(fh)
        m["assignment_sha256"] = got
        with open(mp, "w", encoding="utf-8") as fh:
            json.dump(m, fh)

    def _set_manifest(self, **kw):
        mp = os.path.join(self.tmp, X.MANIFEST_FILE)
        with open(mp, encoding="utf-8") as fh:
            m = json.load(fh)
        m.update(kw)
        with open(mp, "w", encoding="utf-8") as fh:
            json.dump(m, fh)

    # -- clean path -------------------------------------------------------------
    def test_clean_fixture_verifies_empty_and_loads_train_val(self):
        self.assertEqual(X.verify_exchange(self.tmp), [])
        ex = X.load_exchange(self.tmp)
        self.assertEqual(set(ex), {X.TRAIN, X.VALIDATION})
        self.assertTrue(len(ex[X.TRAIN]) + len(ex[X.VALIDATION]) > 0)

    def test_excluded_splits_are_never_returned(self):
        recs = self._records()
        excluded = {(r["kind"], r["id"]) for r in recs if r["split"] in X.EXCLUDED_SPLITS}
        returned = {(r["kind"], r["id"]) for rows in X.load_exchange(self.tmp).values() for r in rows}
        self.assertEqual(excluded & returned, set())

    def test_value_entry_identities_consumable_without_real_pool(self):
        kinds = {r["kind"] for rows in X.load_exchange(self.tmp).values() for r in rows}
        self.assertIn("value_entry", kinds)

    # -- D1: no strict bypass ---------------------------------------------------
    def test_no_strict_bypass_and_contaminated_artifact_always_raises(self):
        with self.assertRaises(TypeError):
            X.load_exchange(self.tmp, strict=False)          # the bypass kwarg no longer exists
        recs = self._records()
        train = next(r for r in recs if r["split"] == X.TRAIN)
        self._write_lines([json.dumps(r) for r in recs] + [json.dumps({**train, "split": X.VALIDATION})])
        self._reseal()                                       # isolate the structural defect from the hash
        self.assertTrue(X.verify_exchange(self.tmp))         # diagnostic-only API reports it
        with self.assertRaises(X.ExchangeError):             # ...but there is NO way to get rows
            X.load_exchange(self.tmp)

    # -- D2: one read, no TOCTOU ------------------------------------------------
    def test_verify_and_consume_use_a_single_read(self):
        calls = {"n": 0}
        orig = X._read_once

        def counting(d):
            calls["n"] += 1
            return orig(d)
        X._read_once = counting
        try:
            X.load_exchange(self.tmp)
        finally:
            X._read_once = orig
        self.assertEqual(calls["n"], 1)

    # -- D3: content integrity --------------------------------------------------
    def test_assignment_only_edit_is_caught_by_content_hash(self):
        recs = self._records()
        i = next(k for k, r in enumerate(recs) if r["split"] == X.TRAIN)
        recs[i] = {**recs[i], "split": X.VALIDATION}
        self._write_lines([json.dumps(r) for r in recs])     # file edited, manifest NOT resealed
        codes = {d["code"] for d in X.verify_exchange(self.tmp)}
        self.assertIn("ASSIGNMENT_SHA_MISMATCH", codes)
        with self.assertRaises(X.ExchangeError):
            X.load_exchange(self.tmp)

    def test_coordinated_rewrite_passes_hash_but_structure_still_caught(self):
        recs = self._records()
        train = next(r for r in recs if r["split"] == X.TRAIN)
        self._write_lines([json.dumps(r) for r in recs] + [json.dumps({**train, "split": X.VALIDATION})])
        self._reseal()
        codes = {d["code"] for d in X.verify_exchange(self.tmp)}
        self.assertNotIn("ASSIGNMENT_SHA_MISMATCH", codes)   # the hash alone cannot catch a coordinated rewrite
        self.assertTrue({"IDENTITY_MULTIPLE_SPLITS", "TRAIN_VALIDATION_OVERLAP"} & codes)

    def test_trusted_external_digest_mismatch_is_reported(self):
        codes = {d["code"] for d in X.verify_exchange(self.tmp, expected_assignment_sha256="0" * 64)}
        self.assertIn("ASSIGNMENT_SHA_UNTRUSTED", codes)

    # -- D4: type / field validation --------------------------------------------
    def test_record_missing_kind_and_id_is_refused(self):
        recs = self._records()
        self._write_lines([json.dumps(r) for r in recs] + [json.dumps({"split": X.TRAIN})])
        self._reseal()
        self.assertIn("MALFORMED_RECORD", {d["code"] for d in X.verify_exchange(self.tmp)})
        with self.assertRaises(X.ExchangeError):
            X.load_exchange(self.tmp)

    def test_non_dict_record_is_refused(self):
        recs = self._records()
        self._write_lines([json.dumps(r) for r in recs] + ["123", json.dumps("a-string")])
        self._reseal()
        self.assertIn("MALFORMED_RECORD", {d["code"] for d in X.verify_exchange(self.tmp)})

    # -- manifest integrity -----------------------------------------------------
    def test_schema_mismatch_is_refused(self):
        self._set_manifest(schema="something-else/v9")
        self.assertIn("EXCHANGE_SCHEMA", {d["code"] for d in X.verify_exchange(self.tmp)})

    def test_tampered_config_sha_is_refused(self):
        self._set_manifest(config_sha256="0" * 64)
        self.assertIn("CONFIG_SHA_MISMATCH", {d["code"] for d in X.verify_exchange(self.tmp)})

    def test_missing_files_report_not_crash(self):
        empty = tempfile.mkdtemp(prefix="v5-exchange-empty-")
        try:
            self.assertIn("MANIFEST_UNREADABLE", {d["code"] for d in X.verify_exchange(empty)})
        finally:
            shutil.rmtree(empty, ignore_errors=True)

    def test_unicode_line_separator_in_a_value_is_not_split(self):
        # A literal U+2028 inside a record value must NOT split the record (LF-only split, not splitlines()).
        recs = self._records()
        i = next((k for k, r in enumerate(recs) if r["kind"] == "value_entry"), 0)
        recs[i] = {**recs[i], "id": recs[i]["id"] + " x"}
        with open(os.path.join(self.tmp, X.ASSIGNMENT_FILE), "w", encoding="utf-8") as fh:
            for r in recs:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")   # literal char in the file
        self._reseal()
        codes = {d["code"] for d in X.verify_exchange(self.tmp)}
        self.assertNotIn("ASSIGNMENT_UNREADABLE", codes)
        self.assertNotIn("MALFORMED_RECORD", codes)
        self.assertEqual(verify := X.verify_exchange(self.tmp), [], verify)

    def test_diagnostics_are_closed_strings(self):
        self._set_manifest(config_sha256="0" * 64)
        for d in X.verify_exchange(self.tmp):
            self.assertIsInstance(d["code"], str)
            self.assertIsInstance(d.get("detail", ""), str)


if __name__ == "__main__":
    unittest.main()
