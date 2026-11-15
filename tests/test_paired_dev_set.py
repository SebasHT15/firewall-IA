"""Synthetic tests for the paired development diagnostic (issue #59):
scripts/evaluation/paired_dev_set.py, paired_dev_analyze.py.

They never touch External Test v1: a module-level guard fails the suite if anything under
datasets/external_v1/, reports/external/ or docker/.lab-logs/ is opened. No V4 or Analyzer model
is run.

    .venv-analyzer/bin/python -m unittest tests.test_paired_dev_set -v
"""

import builtins
import io as _io
import json
import os
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts", "evaluation"))
sys.path.insert(0, os.path.join(REPO_ROOT, "data_plane"))

import paired_dev_set as gen  # noqa: E402  (stdlib only)

try:
    import numpy as np  # noqa: F401
    import paired_dev_analyze as pa  # noqa: E402
    HAVE_ML = True
except ImportError:
    HAVE_ML = False

_FORBIDDEN = tuple(os.path.realpath(os.path.join(REPO_ROOT, p)) for p in
                   ("datasets/external_v1", "reports/external", "docker/.lab-logs"))
_ORIG_OPEN, _ORIG_IO_OPEN, _ORIG_OS_OPEN = builtins.open, _io.open, os.open
_HITS = []


def _check(path):
    if isinstance(path, (str, bytes, os.PathLike)):
        try:
            real = os.path.realpath(os.fsdecode(path))
        except (TypeError, ValueError):
            return
        if any(real == f or real.startswith(f + os.sep) for f in _FORBIDDEN):
            _HITS.append(real)
            raise AssertionError("a test opened External Test v1 data")


def _open(file, *a, **k):
    _check(file)
    return _ORIG_OPEN(file, *a, **k)


def _io_open(file, *a, **k):
    _check(file)
    return _ORIG_IO_OPEN(file, *a, **k)


def _os_open(path, *a, **k):
    _check(path)
    return _ORIG_OS_OPEN(path, *a, **k)


def setUpModule():
    builtins.open, _io.open, os.open = _open, _io_open, _os_open


def tearDownModule():
    builtins.open, _io.open, os.open = _ORIG_OPEN, _ORIG_IO_OPEN, _ORIG_OS_OPEN
    if _HITS:
        raise AssertionError("External Test v1 data was opened during the tests")


class TestGenerationInvariants(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases, cls.problems = gen.generate()
        cls.man = gen.build_manifest(cls.cases)

    def test_no_oracle_or_duplicate_problems(self):
        self.assertEqual(self.problems, [])

    def test_determinism(self):
        again, _ = gen.generate()
        self.assertEqual([c["request_text"] for c in self.cases],
                         [c["request_text"] for c in again])

    def test_every_case_has_matching_sha_and_is_wire_canonical(self):
        sys.path.insert(0, os.path.join(REPO_ROOT, "scripts", "external"))
        import wire
        for c in self.cases:
            self.assertEqual(gen.sha_text(c["request_text"]), c["request_sha256"])
            wire.assert_canonical(c["request_text"])      # raises if not round-trippable
            wire.to_wire(c["request_text"], strict=True)

    def test_label_matches_role(self):
        for c in self.cases:
            self.assertEqual(c["label"], "BLOCK" if c["role"] == "attack" else "ALLOW")

    def test_hosts_never_loopback(self):
        for c in self.cases:
            self.assertNotIn("127.0.0.1", c["host"])
            self.assertNotIn("localhost", c["host"])


class TestUnitOfAnalysis(unittest.TestCase):
    """The owner's core finding: a repeated text / shared payload is not an independent unit."""

    @classmethod
    def setUpClass(cls):
        cls.cases, _ = gen.generate()
        cls.man = gen.build_manifest(cls.cases)

    def test_independent_attack_payloads_are_canonically_distinct_within_family(self):
        seen = set()
        for c in self.cases:
            if c["independent_attack_unit"]:
                key = (c["family"], c["payload_canonical"])
                self.assertNotIn(key, seen, f"duplicate canonical payload {key}")
                seen.add(key)

    def test_placement_variants_are_not_independent(self):
        pv = [c for c in self.cases if c["placement_variant"]]
        self.assertTrue(pv)  # the sub-study exists
        for c in pv:
            self.assertFalse(c["independent_attack_unit"])

    def test_manifest_reports_unique_benign_texts_separately_from_records(self):
        u = self.man["units"]
        # reused benign twins must not be hidden: unique texts <= records, and the gap is reported
        self.assertLessEqual(u["unique_benign_twin_texts"], u["benign_twin_records"])
        self.assertIn("dependency_components (same canonical payload OR same text)", u)
        self.assertLess(u["dependency_components (same canonical payload OR same text)"],
                        u["total_request_records"])

    def test_conclusion_families_meet_30_distinct_payloads(self):
        for fam in gen.CONCLUSION_FAMILIES:
            self.assertGreaterEqual(self.man["conclusion_family_independent_payloads"][fam], 30, fam)
            self.assertTrue(self.man["conclusion_family_meets_D18_30_independent"][fam])

    def test_sink_type_tags_are_honest(self):
        # every attack carries a sink_type; benign carries none; cmdi has no natural sink in the lab
        for c in self.cases:
            if c["role"] == "attack" and not c["placement_variant"]:
                self.assertIn(c["sink_type"], ("natural_sink", "generic_carrier", "header_borne"))
            if c["role"] == "benign":
                self.assertIsNone(c["sink_type"])
        cov = self.man["conclusion_family_sink_coverage"]
        self.assertEqual(cov["command_injection"]["natural_sink"], 0)
        self.assertGreater(cov["ssrf"]["natural_sink"], 0)

    def test_complete_pairs_on_same_endpoint(self):
        by_pair = {}
        for c in self.cases:
            if c["pair_id"].startswith("pair:"):
                by_pair.setdefault(c["pair_id"], []).append(c)
        for pid, members in by_pair.items():
            roles = {m["role"] for m in members}
            self.assertEqual(roles, {"attack", "benign"})
            self.assertEqual(len({m["placement"] for m in members}), 1)  # same endpoint/placement


class TestOracleAndLabels(unittest.TestCase):
    def test_benign_with_hard_token_is_rejected(self):
        bad = gen.make_case("B", "g", "p", "benign", "benign_twin", "t", "search_q",
                            "../../etc/passwd", "oops")
        self.assertIsNotNone(gen.oracle_check(bad))

    def test_attack_not_matching_family_is_rejected(self):
        bad = gen.make_case("A", "g", "p", "attack", "sql_injection", "t", "search_q",
                            "just a normal phrase", "mislabel")
        self.assertIsNotNone(gen.oracle_check(bad))

    def test_benign_english_keywords_stay_benign(self):
        for v in ("how to select a good password", "drop shipping guide", "credit union account"):
            ok = gen.make_case("B", "g", "p", "benign", "benign_twin", "t", "search_q", v, "ok")
            self.assertIsNone(gen.oracle_check(ok))

    def test_label_is_malicious_attempt_not_exploitation(self):
        # oracle_reason must not claim successful exploitation of the inert app
        cases, _ = gen.generate()
        for c in cases:
            if c["role"] == "attack":
                self.assertNotIn("exploit", c["oracle_reason"].lower().replace("not exploitation", ""))


@unittest.skipUnless(HAVE_ML, "needs numpy + scikit-learn (.venv-analyzer)")
class TestAnalysisGuards(unittest.TestCase):
    def test_hash_check_rejects_every_mismatch(self):
        exp = "a" * 64
        self.assertEqual(pa.hash_problems(exp, exp, exp), [])
        # before wrong, after == before (the chained-comparison blind spot)
        self.assertTrue(pa.hash_problems("b" * 64, "b" * 64, exp))
        # after wrong only
        self.assertTrue(pa.hash_problems(exp, "c" * 64, exp))
        # changed during run
        self.assertTrue(pa.hash_problems(exp, "d" * 64, exp))

    def test_invalid_output_is_not_a_false_negative(self):
        units = [
            {"scored": True, "role": "attack", "label": "BLOCK", "family": "ssrf",
             "independent_attack_unit": True, "payload_canonical": "x", "signal_location": "surface",
             "sink_type": "natural_sink", "v4_decision": "INVALID", "attack": 0.9},
            {"scored": True, "role": "attack", "label": "BLOCK", "family": "ssrf",
             "independent_attack_unit": True, "payload_canonical": "y", "signal_location": "surface",
             "sink_type": "natural_sink", "v4_decision": "ALLOW", "attack": 0.8},
            {"scored": True, "role": "attack", "label": "BLOCK", "family": "command_injection",
             "independent_attack_unit": True, "payload_canonical": "z", "signal_location": "surface",
             "sink_type": "generic_carrier", "v4_decision": "ALLOW", "attack": 0.2},
        ]
        out = pa.attacks_v4_misses_high_analyzer(units)
        self.assertEqual(out["v4_allow_total (delivered attacks not blocked)"], 2)
        self.assertEqual(out["v4_allow_natural_sink (closest to a detection concern)"], 1)
        self.assertEqual(
            out["v4_allow_generic_carrier (delivery/classification context, not detection)"], 1)
        self.assertEqual(out["v4_invalid_outputs (NOT false negatives)"], 1)
        self.assertEqual(out["allow_natural_sink_analyzer_at_or_above_0_5"], 1)
        self.assertEqual(out["allow_total_analyzer_at_or_above_0_5"], 1)

    def test_build_units_scores_only_faithful_captures(self):
        cases = [
            {"case_id": "ATK-0001", "request_text": "GET /a HTTP/1.1\nHost: h", "request_sha256": "s1",
             "group_id": "g", "pair_id": "p", "role": "attack", "label": "BLOCK", "family": "ssrf",
             "technique": "t", "endpoint": "/a", "placement": "search_q", "host": "h",
             "signal_location": "surface", "d47_category": "ssrf", "conclusion_family": True,
             "payload_canonical": "x", "independent_attack_unit": True, "placement_variant": False},
            {"case_id": "ATK-0002", "request_text": "GET /b HTTP/1.1\nHost: h", "request_sha256": "s2",
             "group_id": "g", "pair_id": "p", "role": "attack", "label": "BLOCK", "family": "ssrf",
             "technique": "t", "endpoint": "/b", "placement": "search_q", "host": "h",
             "signal_location": "surface", "d47_category": "ssrf", "conclusion_family": True,
             "payload_canonical": "y", "independent_attack_unit": True, "placement_variant": False},
        ]
        raw = [
            {"case_id": "ATK-0001", "capture_ok": True, "v4_decision": "BLOCK"},
            {"case_id": "ATK-0002", "capture_ok": False, "v4_decision": "BLOCK"},  # not faithful
        ]
        units, problems, excluded = pa.build_units(cases, raw)
        scored = [u for u in units if u.get("scored")]
        self.assertEqual(len(scored), 1)
        self.assertEqual(scored[0]["case_id"], "ATK-0001")
        self.assertEqual(scored[0]["text"], cases[0]["request_text"])  # exact captured/designed text
        self.assertEqual(excluded, 1)

    def test_external_v1_paths_refused(self):
        for p in ("datasets/external_v1/cases.jsonl", "reports/external/x.json",
                  "docker/.lab-logs/capture/x.jsonl"):
            with self.assertRaises(pa.da.ForbiddenSource):
                pa.da.dev_path(os.path.join(REPO_ROOT, p))

    def test_vector_level_counts_one_row_per_vector_no_text_inflation(self):
        units = [
            {"scored": True, "role": "attack", "label": "BLOCK", "v4_decision": "BLOCK",
             "attack": 0.2, "band": pa.da.band(0.2), "feature_vector_sha256": "v1"},
            {"scored": True, "role": "attack", "label": "BLOCK", "v4_decision": "BLOCK",
             "attack": 0.2, "band": pa.da.band(0.2), "feature_vector_sha256": "v1"},
            {"scored": True, "role": "benign", "label": "ALLOW", "v4_decision": "ALLOW",
             "attack": 0.8, "band": pa.da.band(0.8), "feature_vector_sha256": "v2"},
        ]
        vl = pa.da.vector_level([u for u in units])
        self.assertEqual(vl["distinct_vectors"], 2)


if __name__ == "__main__":
    unittest.main()
