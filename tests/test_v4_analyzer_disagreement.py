"""Synthetic tests for the V4 ↔ Analyzer disagreement diagnostics (issue #57):
scripts/evaluation/v4_analyzer_disagreement.py and v4_manual_suite_decisions.py.

They never touch External Test v1: a module-level guard fails the suite if anything under
datasets/external_v1/, reports/external/ or docker/.lab-logs/ is opened. No model is run
except a tiny synthetic stand-in.

    .venv-analyzer/bin/python -m unittest tests.test_v4_analyzer_disagreement -v
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

try:
    import numpy as np
    import v4_analyzer_disagreement as da  # noqa: E402
    HAVE_ML = True
except ImportError:
    HAVE_ML = False
import v4_manual_suite_decisions as manual  # noqa: E402  (stdlib only)

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


def unit(label, v4, attack, **kw):
    u = {"label": label, "v4_decision": v4, "attack": attack, "band": da.band(attack),
         "extreme": da.extreme(attack), "feature_vector_sha256": kw.pop("vec", "v"),
         "category_top1": kw.pop("top", "xss"), "seen_train_validation": False,
         "seen_train_validation_jwt": False, "in_internal_test_relation": False,
         "exact_text_in_v4_train": False, "exact_text_in_v4_eval": False}
    u.update(kw)
    return u


class TestManualSuite(unittest.TestCase):
    def test_suite_is_read_literally_and_matches_the_protocol(self):
        cases, digest = manual.manual_suite()
        self.assertEqual(len(cases), 135)
        self.assertEqual(digest, manual.SUITE_SHA256)
        self.assertEqual(sum(c[1] == "BLOCK" for c in cases), 109)

    def test_consistency_check_against_stored_counts(self):
        stored = {"manual_per_case_category": {"A": {"n": 2, "ok": 1}, "B": {"n": 1, "ok": 1}},
                  "binary": {"confusion_matrix": {"TP": 1, "FP": 0, "FN": 1, "TN": 1}}}
        recs = [{"category": "A", "expected": "BLOCK", "decision": "BLOCK", "status": "ok"},
                {"category": "A", "expected": "BLOCK", "decision": "ALLOW", "status": "ok"},
                {"category": "B", "expected": "ALLOW", "decision": "ALLOW", "status": "ok"}]
        chk = manual.score_against_stored(recs, stored)
        self.assertTrue(chk["per_category_matches"] and chk["confusion_matches"])
        recs[1]["status"] = "invalid"                 # invalid: counted wrong, never coerced
        recs[1]["decision"] = None
        chk = manual.score_against_stored(recs, stored)
        self.assertTrue(chk["per_category_matches"])  # still a miss for A, FN for the BLOCK case
        recs[2]["decision"] = "BLOCK"
        chk = manual.score_against_stored(recs, stored)
        self.assertFalse(chk["per_category_matches"])
        self.assertFalse(chk["confusion_matches"])


@unittest.skipUnless(HAVE_ML, "needs numpy + scikit-learn (.venv-analyzer)")
class TestGuardsAndRules(unittest.TestCase):
    def test_external_v1_paths_are_refused_including_symlinks(self):
        for p in ("datasets/external_v1/cases.jsonl", "reports/external/external-v1-run-001/results.jsonl",
                  "docker/.lab-logs/capture/extv1-draft.jsonl",
                  "reports/hybrid/analyzer-external-v1-run-001/aggregate_results.json"):
            with self.assertRaises(da.ForbiddenSource):
                da.dev_path(os.path.join(REPO_ROOT, p))
        with tempfile.TemporaryDirectory() as d:
            link = os.path.join(d, "innocent.jsonl")
            os.symlink(os.path.join(REPO_ROOT, "datasets", "external_v1", "cases.jsonl"), link)
            with self.assertRaises(da.ForbiddenSource):
                da.read_jsonl(link)
        self.assertEqual(da.dev_path(da.S1_CASES), da.S1_CASES)
        self.assertEqual(_HITS, [])

    def test_bands_edges_and_extremes(self):
        self.assertEqual(da.band(0.0), "[0,0.1)")
        self.assertEqual(da.band(0.1), "[0.1,0.5)")
        self.assertEqual(da.band(0.5), "[0.5,0.9)")
        self.assertEqual(da.band(0.9), "[0.9,1]")
        self.assertEqual(da.band(1.0), "[0.9,1]")
        with self.assertRaises(ValueError):
            da.band(1.2)
        self.assertEqual((da.extreme(0.009), da.extreme(0.01), da.extreme(0.99)), ("low", None, "high"))

    def test_signal_location_and_d47_mapping(self):
        self.assertEqual(da.signal_location("JWT Attacks"), "header-only")
        self.assertEqual(da.signal_location("CSRF"), "header-only")
        self.assertEqual(da.signal_location("HTTP Request Smuggling"), "header-dependent")
        self.assertEqual(da.signal_location("CRLF Injection"), "surface")
        self.assertEqual(da.d47_category("File Inclusion", "x", "BLOCK"), "path_file_access")
        self.assertIsNone(da.d47_category("JWT Attacks", "x", "BLOCK"))
        self.assertEqual(da.d47_category("Adversarial", "SQL UNION mixed case", "BLOCK"), "sql_injection")
        self.assertEqual(da.d47_category("Adversarial", "XSS unicode-escaped tags", "BLOCK"), "xss")
        self.assertIsNone(da.d47_category("Adversarial", "Legit blog URL", "ALLOW"))
        cases, _ = manual.manual_suite()
        cats = {c[2] for c in cases if c[1] == "BLOCK"} - {"Adversarial"}
        self.assertEqual(cats - set(da.SUITE_TO_D47), set())
        unmapped_adv = [c for c in cases if c[2] == "Adversarial" and c[1] == "BLOCK"
                        and da.d47_category(c[2], c[3], c[1]) is None]
        self.assertEqual(unmapped_adv, [])


@unittest.skipUnless(HAVE_ML, "needs numpy + scikit-learn (.venv-analyzer)")
class TestLoaders(unittest.TestCase):
    def write(self, d, name, rows):
        p = os.path.join(d, name)
        with _ORIG_OPEN(p, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        return p

    def test_s1_excludes_v4_eval_texts_and_checks_repetitions(self):
        t_ref, t_host, t_eval = ("GET / HTTP/1.1\nHost: localhost", "GET / HTTP/1.1\nHost: 127.0.0.1",
                                 "GET /x HTTP/1.1\nHost: a")
        cases = [
            {"case_id": "H-1", "family": "HOST", "variable": "Host", "value": "localhost", "pair_with": None,
             "expected_label": "ALLOW", "source": "constructed", "text": t_ref, "text_sha256": da.sha_text(t_ref)},
            {"case_id": "H-2", "family": "HOST", "variable": "Host", "value": "127.0.0.1", "pair_with": "H-1",
             "expected_label": "ALLOW", "source": "constructed", "text": t_host, "text_sha256": da.sha_text(t_host)},
            {"case_id": "E-1", "family": "EVALSWAP", "variable": "Host", "value": "orig", "pair_with": None,
             "expected_label": "ALLOW", "source": "datasets/v4_clean/eval.jsonl row 7 (label ALLOW)",
             "text": t_eval, "text_sha256": da.sha_text(t_eval)},
        ]
        res = []
        for t, decs in ((t_ref, ["ALLOW"] * 3), (t_host, ["BLOCK", "BLOCK", "ALLOW"]), (t_eval, ["ALLOW"] * 3)):
            for rep, dcs in enumerate(decs, 1):
                res.append({"phase": "direct", "rep": rep, "text_sha256": da.sha_text(t),
                            "decision": dcs, "reason": "r", "status": "ok"})
        with tempfile.TemporaryDirectory() as d:
            units, pairs, meta = da.load_s1(self.write(d, "c.jsonl", cases), self.write(d, "r.jsonl", res))
        self.assertEqual(meta["excluded_from_v4_eval (D54)"], 1)
        self.assertEqual(meta["scored_unique_texts"], 2)
        self.assertEqual(meta["v4_rep_inconsistent"], 1)
        self.assertEqual({u["v4_decision"] for u in units}, {"ALLOW", "BLOCK"})
        self.assertEqual(pairs, [{"family": "HOST", "variable": "Host", "value": "127.0.0.1",
                                  "a": da.sha_text(t_ref), "b": da.sha_text(t_host), "location": "header"}])
        self.assertTrue(all(t_eval != u["text"] for u in units))

    def test_s2_rejects_mismatched_decision_records(self):
        cases, _ = manual.manual_suite()
        recs = [{"index": i, "text_sha256": da.sha_text(c[0]), "expected": c[1], "decision": c[1],
                 "reason": "r", "status": "ok"} for i, c in enumerate(cases)]
        recs[3]["text_sha256"] = "0" * 64
        recs[5]["status"] = "invalid"
        with tempfile.TemporaryDirectory() as d:
            units, meta = da.load_s2(self.write(d, "dec.jsonl", recs))
        self.assertEqual(len(units), 134)
        self.assertIn("V4 decision record does not match its suite case", meta["problems"])
        self.assertEqual([u for u in units if u["unit_id"] == "S2:005"][0]["v4_decision"], "INVALID")


@unittest.skipUnless(HAVE_ML, "needs numpy + scikit-learn (.venv-analyzer)")
class TestAggregation(unittest.TestCase):
    def test_crosstab_and_reporting_convention(self):
        us = [unit("ALLOW", "BLOCK", 0.05), unit("ALLOW", "BLOCK", 0.95), unit("ALLOW", "ALLOW", 0.5),
              unit("BLOCK", "BLOCK", 0.99)]
        ct = {(r["label"], r["v4_decision"], r["band"]): r["n"] for r in da.crosstab(us)}
        self.assertEqual(ct[("ALLOW", "BLOCK", "[0,0.1)")], 1)
        self.assertEqual(ct[("ALLOW", "ALLOW", "[0.5,0.9)")], 1)
        rt = da.at_reporting_threshold(us)
        self.assertEqual(rt["ALLOW | ALLOW | attack>=0.5"], 1)
        self.assertEqual(rt["ALLOW | BLOCK | attack<0.5"], 1)
        self.assertEqual(sum(rt.values()), 4)
        self.assertEqual(da.extremes(us), {"BLOCK | BLOCK | high": 1})

    def test_pairs_vectors_category_and_overlap(self):
        a = unit("ALLOW", "ALLOW", 0.2, vec="v1", text_sha256="a")
        b = unit("ALLOW", "BLOCK", 0.2, vec="v1", text_sha256="b")      # header flip, same features
        c = unit("ALLOW", "ALLOW", 0.7, vec="v2", text_sha256="c")      # path change, new features
        pairs = [{"family": "HOST", "location": "header", "a": "a", "b": "b"},
                 {"family": "PATH", "location": "surface", "a": "a", "b": "c"}]
        out = {(p["family"], p["v4"], p["analyzer"]): p["pairs"]
               for p in da.pair_analysis(pairs, {"a": a, "b": b, "c": c})}
        self.assertEqual(out, {("HOST", "V4 flips", "Analyzer identical"): 1,
                               ("PATH", "V4 same", "Analyzer changes"): 1})
        self.assertEqual(da.vectors_with_both_v4_decisions([a, b, c]),
                         {"distinct_vectors": 2, "vectors_with_both_v4_decisions": 1, "texts_in_those_vectors": 2})
        s = [unit("BLOCK", "BLOCK", 0.9, d47_expected="xss", top="xss"),
             unit("BLOCK", "BLOCK", 0.9, d47_expected="ssrf", top="path_file_access"),
             unit("BLOCK", "ALLOW", 0.1, d47_expected=None, top="xss", seen_train_validation=True)]
        cu = da.category_usefulness(s)
        self.assertEqual((cu["block_cases_with_d47_mapping"], cu["top1_agrees"]), (2, 1))
        self.assertEqual(da.overlap(s)["seen_train_validation"], {"allow": 0, "block": 1})
        self.assertEqual(da.shared_label_vectors([unit("ALLOW", "ALLOW", .1, vec="z"),
                                                  unit("BLOCK", "BLOCK", .1, vec="z")]), 1)


@unittest.skipUnless(HAVE_ML, "needs numpy + scikit-learn (.venv-analyzer)")
class TestAuditFixes(unittest.TestCase):
    def test_vector_level_counts_one_row_per_vector(self):
        us = [unit("ALLOW", "BLOCK", 0.2, vec="v1"), unit("ALLOW", "ALLOW", 0.2, vec="v1"),
              unit("ALLOW", "ALLOW", 0.2, vec="v1"), unit("ALLOW", "ALLOW", 0.8, vec="v2")]
        out = da.vector_level(us)
        self.assertEqual(out["distinct_vectors"], 2)
        rows = {r["vector"]: r for r in out["vectors"]}
        self.assertEqual((rows["v1"]["texts"], rows["v1"]["v4_block"], rows["v1"]["v4_mix"]), (3, 1, "ALLOW/BLOCK"))
        cross = {(r["labels"], r["v4"], r["band"]): r["vectors"] for r in out["cross_label_mix_v4_mix_band (vectors)"]}
        self.assertEqual(cross, {("ALLOW", "ALLOW/BLOCK", "[0.1,0.5)"): 1, ("ALLOW", "ALLOW", "[0.5,0.9)"): 1})

    def test_extra_headers_tag(self):
        self.assertEqual(da.extra_headers("GET / HTTP/1.1\nHost: a\nAuthorization: Bearer x\nContent-Type: a/b\n\nk: v"),
                         ["authorization"])
        self.assertEqual(da.extra_headers("GET / HTTP/1.1\nHost: a"), [])

    def test_membership_keeps_no_internal_test_labels_or_ids(self):
        rows = [{"row_id": "r1", "role": "train", "slice": None, "target_attack": 1, "meta_v4_decision": "BLOCK",
                 "meta_feature_vector_sha256": "v1", "meta_canonical_request_sha256": "c1"},
                {"row_id": "r2", "role": "internal_test", "slice": None, "target_attack": 0,
                 "meta_v4_decision": "ALLOW", "meta_feature_vector_sha256": "v2",
                 "meta_canonical_request_sha256": "c2"}]
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "ds.jsonl")
            with _ORIG_OPEN(p, "w") as f:
                f.write("".join(json.dumps(r) + "\n" for r in rows))
            m = os.path.join(d, "m.json")
            with _ORIG_OPEN(m, "w") as f:
                json.dump({"artifact": {"sha256": da.ev.sha256_file(p)}}, f)
            kept = da.load_membership(p, m)
            with _ORIG_OPEN(m, "w") as f:
                json.dump({"artifact": {"sha256": "0" * 64}}, f)
            with self.assertRaises(ValueError):
                da.load_membership(p, m)
        self.assertEqual(set(kept[1]), set(da.MEMBERSHIP_FIELDS))
        self.assertEqual(kept[0]["row_id"], "r1")
        sets = da.role_sets(kept)
        self.assertEqual(sets["internal_test"]["vec"], {"v2"})


if __name__ == "__main__":
    unittest.main()
