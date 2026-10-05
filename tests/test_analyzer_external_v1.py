"""Synthetic validation of scripts/evaluation/analyzer_external_v1.py (the single aggregate
evaluation of the frozen Analyzer on External Test v1, D53).

SYNTHETIC ONLY. These tests never read External Test v1: a module-level guard makes any
`open()` of datasets/external_v1/cases.jsonl fail the suite, every path the evaluator uses is
redirected to temporary fixtures, and the real report folder is checked to be unchanged.

Needs numpy and scikit-learn (research environment, D52):
    .venv-analyzer/bin/python -m unittest tests.test_analyzer_external_v1 -v
"""

import builtins
import contextlib
import io as _io
import warnings
import dataclasses
import hashlib
import io
import json
import math
import os
import pickle
import sys
import tempfile
import unittest
from unittest import mock

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "data_plane"))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts", "training"))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts", "evaluation"))

try:
    import numpy as np
    from sklearn.ensemble import HistGradientBoostingClassifier
    import hybrid_analyzer as ha  # noqa: E402
    import analyzer_external_v1 as ev  # noqa: E402
    HAVE_ML = True
except ImportError:  # data-plane environment: skip
    HAVE_ML = False

import request_features as rf  # noqa: E402

_REAL_CASES = os.path.realpath(os.path.join(REPO_ROOT, "datasets", "external_v1", "cases.jsonl"))
_EXT_DIR = os.path.realpath(os.path.join(REPO_ROOT, "datasets", "external_v1"))
_REAL_REPORT = os.path.join(REPO_ROOT, "reports", "hybrid", "analyzer-external-v1-run-001")
_ORIG_OPEN = builtins.open
_ORIG_IO_OPEN = _io.open
_ORIG_OS_OPEN = os.open
_REAL_OPENED = []
_REPORT_BEFORE = None


_V4_RUNS = os.path.realpath(os.path.join(REPO_ROOT, "reports", "external"))


def _forbidden_path(path):
    """External v1 cases, and per-case V4 evidence (results.jsonl, raw/) of External runs."""
    real = os.path.realpath(path)
    if real == _REAL_CASES or real.startswith(_EXT_DIR + os.sep):
        return True
    if real.startswith(_V4_RUNS + os.sep):
        return os.path.basename(real) == "results.jsonl" or (os.sep + "raw" + os.sep) in real
    return False


def _check(file):
    if isinstance(file, (str, bytes, os.PathLike)):
        try:
            hit = _forbidden_path(os.fsdecode(file))
        except (TypeError, ValueError):
            hit = False
        if hit:
            _REAL_OPENED.append(1)
            raise AssertionError("a synthetic test tried to open External v1 / per-case V4 evidence")


def _guarded_open(file, *args, **kwargs):
    _check(file)
    return _ORIG_OPEN(file, *args, **kwargs)


def _guarded_io_open(file, *args, **kwargs):
    _check(file)
    return _ORIG_IO_OPEN(file, *args, **kwargs)


def _guarded_os_open(path, *args, **kwargs):
    _check(path)
    return _ORIG_OS_OPEN(path, *args, **kwargs)


def _report_snapshot():
    if not os.path.isdir(_REAL_REPORT):
        return {}
    out = {}
    for name in sorted(os.listdir(_REAL_REPORT)):
        p = os.path.join(_REAL_REPORT, name)
        if os.path.isfile(p):
            with _ORIG_OPEN(p, "rb") as f:
                out[name] = hashlib.sha256(f.read()).hexdigest()
    return out


def setUpModule():
    global _REPORT_BEFORE
    _REPORT_BEFORE = _report_snapshot()
    builtins.open = _guarded_open
    _io.open = _guarded_io_open
    os.open = _guarded_os_open


def tearDownModule():
    builtins.open = _ORIG_OPEN
    _io.open = _ORIG_IO_OPEN
    os.open = _ORIG_OS_OPEN
    if _REAL_OPENED:
        raise AssertionError("External Test v1 was opened by the synthetic tests")
    if _report_snapshot() != _REPORT_BEFORE:
        raise AssertionError("the real report folder changed during the synthetic tests")


# ── synthetic fixtures ──────────────────────────────────────────────────────
BENIGN_TEXT = {
    "browser-navigation": "GET /page/{i}/view HTTP/1.1\nAccept: text/html",
    "browser-forms-session": "POST /login HTTP/1.1\nContent-Type: application/x-www-form-urlencoded"
                             "\nCookie: s=abc\n\nuser=u{i}&pass=p{i}",
    "api-json": "POST /api/items HTTP/1.1\nContent-Type: application/json\n\n{{\"id\": {i}, \"n\": \"x\"}}",
    "api-query": "GET /api/items?page={i}&sort=asc HTTP/1.1\nAccept: */*",
    "unseen-structure": "OPTIONS /api/items/{i} HTTP/1.1\nContent-Type: application/x-unseen",
}
ATTACK_TEXT = {
    "sqli": "GET /search?q=%27%20OR%201%3D1--{i} HTTP/1.1\nAccept: */*",
    "cmdi": "GET /ping?host=127.0.0.1;cat%20/etc/passwd{i} HTTP/1.1\nAccept: */*",
    "xss": "GET /c?m=%3Cscript%3Ealert({i})%3C/script%3E HTTP/1.1\nAccept: */*",
    "path-traversal": "GET /file?name=../../../../etc/passwd{i} HTTP/1.1\nAccept: */*",
    "ssrf": "GET /fetch?url=http://169.254.169.254/latest/{i} HTTP/1.1\nAccept: */*",
}
CELL_CATEGORY = ev.CATEGORY_MAP if HAVE_ML else {}


def sha(t):
    return hashlib.sha256(t.encode("utf-8")).hexdigest()


def sha_file(p):
    with _ORIG_OPEN(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def make_cases(per_cell=40):
    rows = []
    for cell in ev.CELLS:
        tmpl = BENIGN_TEXT.get(cell) or ATTACK_TEXT[cell]
        for i in range(per_cell):
            text = tmpl.format(i=i)
            benign = cell in ev.BENIGN_CELLS
            rows.append({"case_id": f"SYNCASE-{cell}-{i:03d}", "primary_cell": cell,
                         "expected_decision": "ALLOW" if benign else "BLOCK",
                         "attack_category": None if benign else cell,
                         "benign_slice": cell if benign else None,
                         "payload_placement": "none" if benign else
                         ("header" if cell == "ssrf" and i < 2 else "query"),
                         "request_text": text, "request_sha256": sha(text),
                         "selection_key": sha(f"syn|{cell}|{i}")})
    return rows


def write_external(d, rows, tamper=None):
    cases = os.path.join(d, "cases.jsonl")
    with _ORIG_OPEN(cases, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    digest = sha_file(cases)
    ihash = ev.integrity_hash(rows)
    manifest = {"status": "FROZEN", "frozen": True, "artifact_sha256": digest,
                "integrity_hash": ihash}
    if tamper == "manifest_hash":
        manifest["integrity_hash"] = "0" * 64
    mpath = os.path.join(d, "manifest.json")
    with _ORIG_OPEN(mpath, "w", encoding="utf-8") as f:
        json.dump(manifest, f)
    sums = os.path.join(d, "SHA256SUMS")
    with _ORIG_OPEN(sums, "w", encoding="utf-8") as f:
        f.write(f"{'f' * 64 if tamper == 'sums' else digest}  cases.jsonl\n")
    return cases, mpath, sums, digest, ihash


def train_text(cat, i):
    return {
        "benign": f"GET /shop/item/{i}?ref=home HTTP/1.1\nAccept: text/html",
        "sql_injection": f"GET /s?q=1%27%20UNION%20SELECT%20{i}-- HTTP/1.1",
        "xss": f"GET /s?q=%3Cimg%20src=x%20onerror=alert({i})%3E HTTP/1.1",
        "path_file_access": f"GET /f?p=..%2F..%2F..%2Fetc%2F{i} HTTP/1.1",
        "command_injection": f"GET /p?h=a%7Cwhoami%3B{i} HTTP/1.1",
        "ssti": f"GET /t?n=%7B%7B{i}*{i}%7D%7D HTTP/1.1",
        "open_redirect": f"GET /r?next=https://evil.example/{i} HTTP/1.1",
        "ssrf": f"GET /u?url=http://127.0.0.1:{i}/admin HTTP/1.1",
        "other_attack": f"POST /x HTTP/1.1\nContent-Type: application/xml\n\n<!DOCTYPE a [<!ENTITY e SYSTEM 'file:///{i}'>]>",
    }[cat]


def make_model(version="synthetic/test"):
    feats, y, ycat_feats, ycat = [], [], [], []
    for i in range(60):
        feats.append(rf.extract_features(train_text("benign", i)))
        y.append(0)
        for k, c in enumerate(ha.CATEGORIES):
            if i % 4 == 0:
                f = rf.extract_features(train_text(c, i))
                feats.append(f)
                y.append(1)
                ycat_feats.append(f)
                ycat.append(k)
    enc = ha.FeatureEncoder("tree", log1p=False).fit(feats)
    am = HistGradientBoostingClassifier(max_iter=20, random_state=0).fit(enc.transform(feats), y)
    cm = HistGradientBoostingClassifier(max_iter=20, random_state=0).fit(enc.transform(ycat_feats), ycat)
    return ha.AnalyzerModel(version, enc, am, enc, cm)


@unittest.skipUnless(HAVE_ML, "needs numpy + scikit-learn (.venv-analyzer)")
class TestFeaturesAndModelContract(unittest.TestCase):
    def test_extraction_is_the_frozen_extractor_in_frozen_order(self):
        text = "POST /a/b?x=1&x=2 HTTP/1.1\nContent-Type: application/json\n\n{\"k\": [1, {\"z\": 2}]}"
        self.assertEqual(ev.extract([text])[0], rf.extract_features(text))
        self.assertEqual(len(ha.FEATURE_FIELDS), 34)
        with _ORIG_OPEN(os.path.join(ev.RUN002_DIR, "frozen_selection.json"), encoding="utf-8") as f:
            frozen = json.load(f)
        self.assertEqual(list(ha.FEATURE_FIELDS), frozen["feature_order"])
        self.assertEqual(rf.FEATURE_SCHEMA_VERSION, "request-features/v2")

    def test_host_and_user_agent_do_not_change_features(self):
        a = "GET /x?q=1 HTTP/1.1\nHost: a.example\nUser-Agent: curl/8"
        b = "GET /x?q=1 HTTP/1.1\nHost: other.internal\nUser-Agent: Mozilla/5.0"
        self.assertEqual(ev.extract([a]), ev.extract([b]))

    @unittest.skipUnless(os.path.exists(os.path.join(REPO_ROOT, "model-output-hybrid-analyzer-v2",
                                                     "recommended.pkl")), "frozen artifact absent")
    def test_frozen_artifact_loads_unchanged_and_meets_the_contract(self):
        path = os.path.join(REPO_ROOT, ev.ANCHORS["model_path"])
        before = sha_file(path)
        analyzer = ev.load_model(path, ev.ANCHORS["model_sha256"])
        self.assertEqual(sha_file(path), before)
        with _ORIG_OPEN(os.path.join(ev.RUN002_DIR, "frozen_selection.json"), encoding="utf-8") as f:
            frozen = json.load(f)
        with _ORIG_OPEN(os.path.join(ev.RUN002_DIR, "preprocessing.json"), encoding="utf-8") as f:
            pre = json.load(f)
        self.assertEqual(ev.verify_feature_contract(analyzer, frozen, pre), [])
        # a synthetic (non-frozen) model fails the same contract
        self.assertTrue(ev.verify_feature_contract(make_model(), frozen, pre))
        # scoring synthetic texts through the frozen model satisfies AnalyzerOutput
        feats = ev.extract([t.format(i=3) for t in list(BENIGN_TEXT.values()) + list(ATTACK_TEXT.values())])
        p, pc, check = ev.score(analyzer, feats)
        self.assertEqual(check, {"contract_violations": 0, "analyze_vs_batch_attack_mismatches": 0,
                                 "non_finite_attack": 0})
        self.assertTrue(np.all((p >= 0) & (p <= 1)))
        np.testing.assert_allclose(pc.sum(axis=1), 1.0, atol=1e-9)

    def test_load_model_refuses_a_different_hash(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "m.pkl")
            with _ORIG_OPEN(p, "wb") as f:
                pickle.dump(make_model(), f)
            with self.assertRaises(ev.PreflightError):
                ev.load_model(p, "0" * 64)

    @unittest.skipUnless(os.path.exists(ev.DATASET_V2) if HAVE_ML else False, "dataset v2 absent")
    def test_vector_hash_reproduces_the_v2_relation_on_development_rows(self):
        rows = ha.load_dataset(ev.DATASET_V2, ev.DATASET_V2_MANIFEST, verify=False,
                               roles={"validation"})[:300]
        self.assertTrue(rows)
        for r in rows:
            self.assertEqual(ev.vector_hash(r["features"]), r["meta_feature_vector_sha256"])


@unittest.skipUnless(HAVE_ML, "needs numpy + scikit-learn (.venv-analyzer)")
class TestMetrics(unittest.TestCase):
    def test_wilson_known_values(self):
        lo, hi = ev.wilson(0, 40)
        self.assertEqual(lo, 0.0)
        self.assertAlmostEqual(hi, 0.087622, places=5)
        lo, hi = ev.wilson(20, 40)
        self.assertAlmostEqual(lo + hi, 1.0, places=6)
        self.assertIsNone(ev.wilson(0, 0))

    def test_headline_known_confusion_and_threshold_is_inclusive(self):
        y = np.array([1, 1, 1, 1, 0, 0, 0, 0])
        p = np.array([0.9, 0.5, 0.4, 0.8, 0.1, 0.5, 0.2, 0.3])
        t = ev.headline(y, p)["at_reporting_threshold_0_5"]
        self.assertEqual((t["tp"], t["tn"], t["fp"], t["fn"]), (3, 3, 1, 1))
        self.assertEqual(t["recall_block"]["num"], 3)
        self.assertEqual(t["recall_block"]["den"], 4)
        self.assertEqual(t["fpr"]["num"], 1)
        self.assertEqual(t["fpr"]["den"], 4)

    def test_threshold_free_metrics_known_values(self):
        y = np.array([0] * 50 + [1] * 50)
        h = ev.headline(y, np.full(100, 0.5))["threshold_free"]
        self.assertAlmostEqual(h["roc_auc"], 0.5)
        self.assertAlmostEqual(h["brier"], 0.25)
        self.assertAlmostEqual(h["log_loss"], math.log(2), places=6)
        h = ev.headline(y, np.r_[np.full(50, 0.2), np.full(50, 0.8)])["threshold_free"]
        self.assertEqual(h["roc_auc"], 1.0)
        self.assertEqual(h["pr_auc"], 1.0)
        self.assertAlmostEqual(h["brier"], 0.04)

    def test_extreme_probabilities_keep_log_loss_finite(self):
        y = np.array([0, 1, 0, 1])
        h = ev.headline(y, np.array([1.0, 0.0, 0.0, 1.0]))["threshold_free"]
        self.assertTrue(math.isfinite(h["log_loss"]))

    def test_per_cell_counts_auc_and_rule_of_three(self):
        rows = make_cases(per_cell=40)
        y = np.array([ev.LABEL[r["expected_decision"]] for r in rows])
        cells = [r["primary_cell"] for r in rows]
        p = np.where(y == 1, 0.9, 0.1).astype(float)
        p[cells.index("api-json")] = 0.7          # one FP in api-json
        p[cells.index("ssrf")] = 0.2              # one FN in ssrf
        out = ev.per_cell(y, p, cells)
        self.assertEqual((out["api-json"]["fp"], out["api-json"]["tn"]), (1, 39))
        self.assertEqual((out["ssrf"]["tp"], out["ssrf"]["fn"]), (39, 1))
        self.assertEqual(out["sqli"]["support_status"], "OK")
        self.assertIsNotNone(out["sqli"]["zero_error_bound"])
        self.assertIsNone(out["ssrf"]["zero_error_bound"])
        self.assertEqual(out["browser-navigation"]["roc_auc_vs_all_block"], 1.0)
        self.assertLess(out["ssrf"]["roc_auc_all_allow_vs_cell"], 1.0)

    def test_category_block_known_matrix(self):
        cats = list(ha.CATEGORIES)
        true = ["sqli"] * 4 + ["ssrf"] * 4
        p = np.zeros((8, 8))
        for i in range(4):
            p[i, cats.index("sql_injection")] = 1.0
        for i in range(4, 7):
            p[i, cats.index("ssrf")] = 1.0
        p[7, cats.index("other_attack")] = 1.0       # predicted into an unsampled category
        out = ev.category_block(true, p)
        self.assertEqual(out["top1_accuracy"]["num"], 7)
        self.assertEqual(out["predicted_into_unsampled_categories"], 1)
        self.assertEqual(out["per_category"]["ssrf"]["recall"], 0.75)
        self.assertEqual(out["confusion_true_rows"]["rows"]["ssrf"][cats.index("other_attack")], 1)
        self.assertEqual(sorted(out["not_evaluable_not_sampled"]), ["open_redirect", "other_attack", "ssti"])

    def test_reliability_small_bins_are_suppressed(self):
        y = np.array([0] * 30 + [1] * 31)
        p = np.r_[np.full(30, 0.02), np.full(30, 0.98), [0.5]]   # the 0.5 bin holds one case
        rel = ev.reliability_suppressed(y, p)
        published = [b for b in rel["bins"] if isinstance(b["n"], int)]
        self.assertEqual(sum(b["n"] for b in published), 61 - rel["hidden_cases"])
        self.assertTrue(rel["hidden_cases"] == 0 or rel["hidden_cases"] >= 10)
        self.assertTrue(any(b["n"] == "suppressed" for b in rel["bins"]))
        self.assertFalse(any("mean_predicted" in b for b in rel["bins"] if not isinstance(b["n"], int)))

    def test_bootstrap_is_deterministic_and_stratified(self):
        y = np.array([0] * 40 + [1] * 40)
        p = np.linspace(0.01, 0.99, 80)
        a = ev.stratified_bootstrap(y, p, n_boot=50)
        b = ev.stratified_bootstrap(y, p, n_boot=50)
        self.assertEqual(a, b)
        lo, hi = a["ci95"]["roc_auc"]
        self.assertLessEqual(lo, hi)

    def test_feature_disjoint_view_needs_support(self):
        y = np.array([0] * 50 + [1] * 50)
        p = np.linspace(0.01, 0.99, 100)
        in_dev = np.zeros(100, bool)
        in_dev[:10] = True
        in_dev[50:60] = True                                      # 10 excluded per class
        cells = ["A"] * 50 + ["B"] * 50
        self.assertEqual(ev.feature_disjoint_view(y, p, in_dev, cells)["status"], "OK")
        y = np.array([0] * 40 + [1] * 40)
        p = np.linspace(0.01, 0.99, 80)
        in_dev = np.zeros(80, bool)
        in_dev[:20] = True
        self.assertIn("INSUFFICIENT DATA",
                      ev.feature_disjoint_view(y, p, in_dev, ["A"] * 40 + ["B"] * 40)["status"])

    def test_d54_groups_join_header_only_variants_and_equal_vectors(self):
        texts = ["GET /a?q=1 HTTP/1.1\nCookie: x=1",       # same canonical request as the next
                 "GET /a?q=1 HTTP/1.1\nCookie: x=2",
                 "GET /a?q=%31 HTTP/1.1",                    # canonical_key decodes -> same group
                 "GET /zz?q=2 HTTP/1.1",
                 "POST /b HTTP/1.1\nContent-Type: application/json\n\n{\"k\": 1}"]
        g = ev.d54_groups(texts, ev.extract(texts))
        self.assertEqual(len(set(g[:3].tolist())), 1)
        self.assertEqual(len(set(g.tolist())), 3)

    def test_group_weighted_and_error_concentration_are_numbers_only(self):
        # ALLOW: group "a" (10 cases, all FP) + 10 singletons (TN); BLOCK: 10 singletons, one FN
        y = np.array([0] * 20 + [1] * 10)
        p = np.array([0.9] * 10 + [0.1] * 10 + [0.2] + [0.9] * 9)
        groups = np.array(["a"] * 10 + [f"n{i}" for i in range(10)] + [f"b{i}" for i in range(10)])
        cells = ["A"] * 10 + ["B"] * 10 + ["C"] * 10
        out = ev.group_weighted(y, p, groups, cells)
        self.assertEqual(out["status"], "OK")
        self.assertEqual(out["n_groups"], 21)
        ec = out["error_concentration"]
        self.assertEqual(ec["false_positives"], {"errors": 10, "distinct_groups": 1,
                                                 "largest_error_group": 10, "share_in_top_2_groups": 1.0})
        self.assertEqual(ec["false_negatives"]["errors"], 1)
        self.assertAlmostEqual(out["metrics_each_group_weighs_1"]["fpr"], 1 / 11, places=5)
        ev.assert_aggregate_only(out, {"a", "b"} - {"a", "b"})

    def test_payload_visibility_split(self):
        y = np.array([1, 1, 1, 1, 0])
        p = np.array([0.9, 0.1, 0.2, 0.8, 0.9])
        out = ev.by_placement_visibility(y, p, ["query", "header", "cookie", "json", "none"])
        self.assertEqual((out["visible"]["block_cases"], out["visible"]["tp"]), (2, 2))
        self.assertEqual((out["invisible"]["block_cases"], out["invisible"]["fn"]), (2, 2))
        self.assertEqual(out["invisible"]["support_status"], "INSUFFICIENT DATA")
        self.assertNotIn("unmapped", out)

    def test_internal_reference_reads_the_frozen_second_look(self):
        ref = ev.internal_reference()
        self.assertIn("SECOND-LOOK", ref["label"])
        self.assertEqual(ref["view"], "internal_test_feature_disjoint")
        self.assertAlmostEqual(ref["comparable"]["roc_auc"], 0.993594, places=5)

    def test_reliability_hidden_pool_is_never_one_to_nine_cases(self):
        y = np.array([0] * 30 + [1] * 30 + [1])
        p = np.r_[np.full(30, 0.02), np.full(30, 0.98), [0.5]]
        rel = ev.reliability_suppressed(y, p)
        self.assertGreaterEqual(rel["hidden_cases"], 10)        # one stray case forces a big bin out
        for k in range(1, 10):                                     # never a 1..9 hidden pool
            q = np.r_[np.full(40, 0.02), np.full(40, 0.98), np.full(k, 0.5)]
            yy = np.r_[np.zeros(40), np.ones(40 + k)]
            h = ev.reliability_suppressed(yy, q)["hidden_cases"]
            self.assertTrue(h == 0 or h >= 10, (k, h))

    def test_feature_disjoint_view_is_suppressed_when_one_case_would_be_differenced(self):
        y = np.array([0] * 40 + [1] * 40)
        p = np.linspace(0.01, 0.99, 80)
        in_dev = np.zeros(80, bool)
        cells = ["A"] * 40 + ["B"] * 40
        in_dev[3] = True                                          # exactly one excluded case
        out = ev.feature_disjoint_view(y, p, in_dev, cells)
        self.assertIn("SUPPRESSED", out["status"])
        self.assertNotIn("threshold_free", out)
        self.assertIn("IDENTICAL", ev.feature_disjoint_view(y, p, np.zeros(80, bool), cells)["status"])

    def test_feature_disjoint_view_resists_differencing_against_cells(self):
        # code-audit shapes: (a) a whole cell + one case of another cell excluded;
        # (b) all but one case of a cell excluded. Both pass a per-class count rule.
        y = np.array([0] * 120 + [1] * 120)
        p = np.linspace(0.01, 0.99, 240)
        cells = ["A"] * 40 + ["B"] * 40 + ["C"] * 40 + ["D"] * 120
        a = np.zeros(240, bool)
        a[:40] = True
        a[40] = True
        b = np.zeros(240, bool)
        b[:39] = True
        for in_dev in (a, b):
            out = ev.feature_disjoint_view(y, p, in_dev, cells)
            self.assertIn("SUPPRESSED", out["status"])
            self.assertNotIn("threshold_free", out)

    def test_group_weighted_resists_differencing_against_cells(self):
        y = np.array([0] * 40 + [1] * 40)
        p = np.linspace(0.01, 0.99, 80)
        cells = ["A"] * 40 + ["B"] * 40
        groups = np.array([f"g{i}" for i in range(80)])
        groups[:10] = "big"                       # 10 grouped cases: alone it would pass
        groups[40:43] = "tiny"                    # but a cell x size part of 3 cases leaks
        self.assertIn("SUPPRESSED", ev.group_weighted(y, p, groups, cells)["status"])
        groups[40:43] = ["s1", "s2", "s3"]
        self.assertEqual(ev.group_weighted(y, p, groups, cells)["status"], "OK")
        in_dev = np.zeros(80, bool)
        in_dev[:5] = True                         # joint cell x in-dev x size part of 5
        self.assertIn("SUPPRESSED", ev.group_weighted(y, p, groups, cells, in_dev)["status"])

    def test_placement_means_are_suppressed_when_a_part_is_small(self):
        y = np.ones(20, int)
        p = np.linspace(0.1, 0.9, 20)
        out = ev.by_placement_visibility(y, p, ["query"] * 15 + ["header"] * 5)
        self.assertIn("suppressed", out["visible"]["mean_attack"])
        self.assertIn("suppressed", out["invisible"]["mean_attack"])
        out = ev.by_placement_visibility(y, p, ["query"] * 10 + ["cookie"] * 10)
        self.assertIsInstance(out["invisible"]["mean_attack"], float)

    def test_group_weighted_is_suppressed_when_few_cases_are_grouped(self):
        y = np.array([0] * 20 + [1] * 20)
        p = np.linspace(0.01, 0.99, 40)
        groups = np.array([f"g{i}" for i in range(40)])
        groups[1] = "g0"                                           # one pair: 2 pooled cases
        out = ev.group_weighted(y, p, groups, ["A"] * 20 + ["B"] * 20)
        self.assertIn("SUPPRESSED", out["status"])
        self.assertNotIn("metrics_each_group_weighs_1", out)

    def test_bootstrap_is_stratified_and_seed_follows_the_protocol(self):
        self.assertEqual(ev.BOOT_SEED, int.from_bytes(
            hashlib.sha256(b"analyzer-external-v1-run-001").digest()[:8], "big"))
        y = np.array([1] + [0] * 60)          # an unstratified resample would often lack the positive
        p = np.linspace(0.01, 0.99, 61)
        out = ev.stratified_bootstrap(y, p, n_boot=300)
        self.assertEqual(out["ci95"]["roc_auc"][0] is not None, True)

    def test_non_finite_probability_is_counted(self):
        class Fake:
            version = "fake"

            def attack_proba(self, f):
                return np.array([0.2, float("nan")])

            def category_proba(self, f):
                return np.full((2, 8), 1 / 8)

            def analyze(self, f):
                raise ValueError("contract")

        _, _, check = ev.score(Fake(), [object(), object()])
        self.assertEqual(check["non_finite_attack"], 1)
        self.assertEqual(check["contract_violations"], 2)


@unittest.skipUnless(HAVE_ML, "needs numpy + scikit-learn (.venv-analyzer)")
class TestIntegrity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        self.rows = make_cases()

    def tearDown(self):
        self.tmp.cleanup()

    def anchors(self, digest, ihash):
        return dict(ev.ANCHORS, cases_sha256=digest, integrity_hash=ihash)

    def test_clean_synthetic_set_passes(self):
        c, m, s, digest, ihash = write_external(self.d, self.rows)
        _, checks = ev.verify_external(c, m, s, anchors=self.anchors(digest, ihash))
        self.assertEqual(checks["problems"], [])
        self.assertEqual((checks["allow"], checks["block"]), (200, 200))

    def test_tampered_text_is_detected_without_naming_the_case(self):
        rows = make_cases()
        rows[5]["request_text"] += "x"
        c, m, s, digest, ihash = write_external(self.d, rows)
        _, checks = ev.verify_external(c, m, s, anchors=self.anchors(digest, ihash))
        self.assertIn("1 request_sha256 value(s) do not recompute", checks["problems"])
        self.assertNotIn(rows[5]["case_id"], json.dumps(checks))

    def test_wrong_anchor_manifest_and_sums_are_detected(self):
        c, m, s, digest, ihash = write_external(self.d, self.rows, tamper="manifest_hash")
        _, checks = ev.verify_external(c, m, s, anchors=self.anchors("1" * 64, ihash))
        self.assertIn("integrity hash != manifest", checks["problems"])
        self.assertIn("cases SHA-256 != anchor", checks["problems"])
        with tempfile.TemporaryDirectory() as d2:
            c, m, s, digest, ihash = write_external(d2, self.rows, tamper="sums")
            _, checks = ev.verify_external(c, m, s, anchors=self.anchors(digest, ihash))
            self.assertTrue(any("SHA256SUMS" in x for x in checks["problems"]))

    def test_balance_cells_and_label_consistency(self):
        rows = make_cases()
        rows[0]["expected_decision"] = "BLOCK"            # ALLOW cell labelled BLOCK
        rows[-1]["expected_decision"] = "MAYBE"           # unknown label
        c, m, s, digest, ihash = write_external(self.d, rows)
        _, checks = ev.verify_external(c, m, s, anchors=self.anchors(digest, ihash))
        joined = " | ".join(checks["problems"])
        self.assertIn("unknown expected_decision", joined)
        self.assertIn("inconsistent with their cell", joined)
        self.assertIn("balance", joined)

    def test_missing_or_unmapped_placement_is_a_preflight_problem(self):
        rows = make_cases()
        del rows[3]["payload_placement"]
        rows[-1]["payload_placement"] = "trailer"          # a BLOCK case, outside the mapping
        c, m, s, digest, ihash = write_external(self.d, rows)
        _, checks = ev.verify_external(c, m, s, anchors=self.anchors(digest, ihash))
        joined = " | ".join(checks["problems"])
        self.assertIn("1 case(s) without a string payload_placement", joined)
        self.assertIn("1 BLOCK case(s) with a payload_placement outside", joined)

    def test_missing_files_stop_the_preflight(self):
        with self.assertRaises(ev.PreflightError):
            ev.verify_external(os.path.join(self.d, "nope.jsonl"), os.path.join(self.d, "m.json"),
                               os.path.join(self.d, "S"))

    def test_real_external_v1_is_refused_without_the_run_flag(self):
        with self.assertRaises(ev.PreflightError):
            ev.load_cases(ev.REAL_CASES)
        with self.assertRaises(ev.PreflightError):
            ev.verify_external(ev.REAL_CASES, ev.REAL_MANIFEST, ev.REAL_EXT_SUMS)
        self.assertEqual(_REAL_OPENED, [])

    def test_write_exclusive_never_overwrites(self):
        p = os.path.join(self.d, "x.json")
        ev.write_exclusive(p, "a")
        with self.assertRaises(FileExistsError):
            ev.write_exclusive(p, "b")
        with _ORIG_OPEN(p) as f:
            self.assertEqual(f.read(), "a")


@unittest.skipUnless(HAVE_ML, "needs numpy + scikit-learn (.venv-analyzer)")
class TestAggregateOnlyGuard(unittest.TestCase):
    def test_rejects_case_ids_texts_keys_and_long_lists(self):
        forbidden = {"SYNCASE-x-001", "a" * 64, "GET /secret/request/text HTTP/1.1"}
        ev.assert_aggregate_only({"n": 400, "ci": [0.1, 0.2]}, forbidden)
        for bad in ({"note": "SYNCASE-x-001"}, {"h": "a" * 64},
                    {"x": ["GET /secret/request/text HTTP/1.1"]}, {"request_text": "t"},
                    {"case_id": 1}, {"p": [0.1] * 17}, {"k": {"SYNCASE-x-001": 1}}):
            with self.assertRaises(ev.PreflightError):
                ev.assert_aggregate_only(bad, forbidden)

    def test_rejects_large_dicts_and_numpy_values(self):
        for bad in ({str(i): 0.1 for i in range(400)}, {"a": np.float64(0.3)}, {"a": np.zeros(3)}):
            with self.assertRaises(ev.PreflightError):
                ev.assert_aggregate_only(bad, set())

    def test_empty_or_incomplete_sha256sums_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "SHA256SUMS")
            with _ORIG_OPEN(p, "w") as f:
                f.write("")
            self.assertGreater(ev.verify_sha256sums(p)[1], 0)
            with _ORIG_OPEN(os.path.join(d, "a.txt"), "w") as f:
                f.write("x")
            with _ORIG_OPEN(p, "w") as f:
                f.write(f"{sha_file(os.path.join(d, 'a.txt'))}  a.txt\n")
            self.assertEqual(ev.verify_sha256sums(p), (1, 0))
            self.assertEqual(ev.verify_sha256sums(p, must_list=("cases.jsonl",)), (1, 1))

    def test_error_message_never_contains_the_offending_value(self):
        try:
            ev.assert_aggregate_only({"note": "SYNCASE-x-001"}, {"SYNCASE-x-001"})
        except ev.PreflightError as exc:
            self.assertNotIn("SYNCASE", str(exc))


# ── end-to-end synthetic run (every path redirected) ────────────────────────
@unittest.skipUnless(HAVE_ML, "needs numpy + scikit-learn (.venv-analyzer)")
class TestSyntheticRun(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.rows = make_cases()
        ext = os.path.join(d, "ext")
        os.makedirs(ext)
        cases, manifest, sums, digest, ihash = write_external(ext, self.rows)
        self.report = os.path.join(d, "report")
        os.makedirs(self.report)
        with _ORIG_OPEN(os.path.join(self.report, "PROTOCOL.md"), "w") as f:
            f.write("synthetic protocol\n")
        ev.write_prereg(self.report)
        model = make_model()
        mpath = os.path.join(d, "model.pkl")
        with _ORIG_OPEN(mpath, "wb") as f:
            pickle.dump(model, f)
        run002 = os.path.join(d, "run002")
        os.makedirs(run002)
        with _ORIG_OPEN(os.path.join(run002, "preprocessing.json"), "w") as f:
            json.dump({"hist_gb": {"attack": {"columns": model.attack_encoder.columns},
                                   "category": {"columns": model.category_encoder.columns}}}, f)
        frozen = {"feature_order": list(ha.FEATURE_FIELDS), "winner_attack": "hist_gb",
                  "winner_category": "hist_gb"}
        # synthetic development set: one-digit api-query pages. Features count characters, so
        # these share one vector with the 10 one-digit External cases and none with the rest.
        dev = os.path.join(d, "dev.jsonl")
        with _ORIG_OPEN(dev, "w") as f:
            for i in range(0, 10, 2):
                feat = rf.extract_features(BENIGN_TEXT["api-query"].format(i=i))
                f.write(json.dumps({"role": "train", "slice": None,
                                    "features": dataclasses.asdict(feat),
                                    "meta_feature_vector_sha256": ev.vector_hash(feat)}) + "\n")
        dev_manifest = os.path.join(d, "dev_manifest.json")
        with _ORIG_OPEN(dev_manifest, "w") as f:
            json.dump({"artifact": {"sha256": sha_file(dev)}}, f)
        v4 = os.path.join(d, "v4.json")
        with _ORIG_OPEN(v4, "w") as f:
            json.dump({"L1": {"TP": 1, "TN": 1, "FP": 0, "FN": 0,
                              "recall_block_ADR": {"num": 1, "den": 1, "pct": 100.0},
                              "FPR": {"num": 0, "den": 1, "pct": 0.0},
                              "per_cell": {"sqli": {"fpr": None, "recall_block": {"num": 1, "den": 1}}}}}, f)
        anchors = dict(ev.ANCHORS, cases_sha256=digest, integrity_hash=ihash,
                       model_path=os.path.relpath(mpath, ev.REPO_ROOT), model_sha256=sha_file(mpath),
                       model_version=model.version)
        head = ev._git("rev-parse", "HEAD").stdout.strip()
        ok_checks = {"model_sha256": anchors["model_sha256"], "frozen_selection_sha256": "f" * 64,
                     "problems": []}
        self.patches = [
            mock.patch.object(ev, "REAL_CASES", cases), mock.patch.object(ev, "REAL_MANIFEST", manifest),
            mock.patch.object(ev, "REAL_EXT_SUMS", sums), mock.patch.object(ev, "REPORT_DIR", self.report),
            mock.patch.object(ev, "RUN002_DIR", run002), mock.patch.object(ev, "DATASET_V2", dev),
            mock.patch.object(ev, "DATASET_V2_MANIFEST", dev_manifest),
            mock.patch.object(ev, "V4_SUMMARY", v4), mock.patch.dict(ev.ANCHORS, anchors),
            mock.patch.object(ev, "verify_git", lambda: {"branch": "syn", "head": head,
                                                         "uncommitted_paths": [], "problems": []}),
            mock.patch.object(ev, "verify_model_and_reports", lambda: (frozen, ok_checks)),
            mock.patch.object(ev, "run_synthetic_tests", lambda: (True, "OK")),
        ]
        for p in self.patches:
            p.start()
        self.forbidden = ev.forbidden_from_cases(self.rows)

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def run_cli(self, *argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code = ev.main(list(argv))
        return code, buf.getvalue()

    def files(self):
        out = {}
        for name in sorted(os.listdir(self.report)):
            with _ORIG_OPEN(os.path.join(self.report, name), encoding="utf-8") as f:
                out[name] = f.read()
        return out

    def assert_no_case_data(self, text):
        for s in self.forbidden:
            self.assertNotIn(s, text)
        self.assertNotIn("SYNCASE", text)
        self.assertNotIn("request_text", text)

    def test_changed_protocol_after_preregistration_blocks_the_run(self):
        with _ORIG_OPEN(os.path.join(self.report, "PROTOCOL.md"), "a") as f:
            f.write("edited after pre-registration\n")
        code, out = self.run_cli("run", "--confirm-single-run")
        self.assertEqual(code, 2)
        self.assertIn("differ from PREREGISTRATION.json", out)
        self.assertNotIn("run_attempt.json", os.listdir(self.report))
        code, out = self.run_cli("prereg")            # exclusive: cannot be refreshed
        self.assertEqual(code, 2)

    def test_exception_inside_preflight_prints_the_class_only(self):
        def boom():
            raise RuntimeError(f"{self.rows[0]['case_id']} {self.rows[0]['request_text']}")
        with mock.patch.object(ev, "verify_environment", boom):
            code, out = self.run_cli("run", "--confirm-single-run")
        self.assertEqual(code, 2)
        self.assertIn("RuntimeError", out)
        self.assert_no_case_data(out)
        self.assertNotIn("run_attempt.json", os.listdir(self.report))

    def test_warning_with_case_text_is_counted_not_printed(self):
        real = ev.score
        leak = self.rows[0]["request_text"]

        def noisy(analyzer, features):
            warnings.warn(f"odd input {leak}", RuntimeWarning)
            return real(analyzer, features)

        with mock.patch.object(ev, "score", noisy):
            code, out = self.run_cli("run", "--confirm-single-run")
        self.assertEqual(code, 0, out)
        files = self.files()
        self.assertEqual(json.loads(files["aggregate_results.json"])["warnings_during_run"].get("RuntimeWarning"), 1)
        for text in list(files.values()) + [out]:
            self.assert_no_case_data(text)

    def test_confirmation_flag_is_required(self):
        code, out = self.run_cli("run")
        self.assertEqual(code, 2)
        self.assertNotIn("run_attempt.json", os.listdir(self.report))

    def test_single_run_writes_only_aggregates_and_refuses_a_second_start(self):
        code, out = self.run_cli("run", "--confirm-single-run")
        self.assertEqual(code, 0, out)
        files = self.files()
        self.assertEqual(set(files), {"PROTOCOL.md", "PREREGISTRATION.json", "run_attempt.json",
                                      "aggregate_results.json", "run_metadata.json", "console.log"})
        for name, text in files.items():
            self.assert_no_case_data(text)
        self.assert_no_case_data(out)
        res = json.loads(files["aggregate_results.json"])
        self.assertEqual(res["attack_headline"]["n"], 400)
        self.assertEqual(res["external_v1"]["allow"], 200)
        self.assertEqual(res["contract_check"]["contract_violations"], 0)
        self.assertEqual(res["descriptive"]["feature_vector_in_dev_train_validation"],
                         {"allow": 10, "block": 0})
        self.assertEqual(res["descriptive"]["encoded_as_unseen_other"]["method"]["allow"], 40)
        self.assertEqual(res["block_by_payload_visibility"]["invisible"]["block_cases"], 2)
        self.assertGreater(res["group_weighted_diagnostic (D55)"]["n_groups"], 0)
        self.assertIn("SECOND-LOOK", res["internal_reference_second_look"]["label"])
        self.assertEqual(json.loads(files["run_metadata.json"])["runs_started"], 1)
        before = {n: sha(t) for n, t in files.items()}
        code2, out2 = self.run_cli("run", "--confirm-single-run")
        self.assertEqual(code2, 2)
        self.assertIn("REFUSED", out2)
        self.assertEqual({n: sha(t) for n, t in self.files().items()}, before)
        # and the preflight now reports the run as started
        code3, out3 = self.run_cli("preflight")
        self.assertEqual(code3, 2)

    def test_failure_records_stage_and_class_only_and_blocks_retry(self):
        leak = self.rows[0]

        def boom(*a, **k):
            raise ValueError(f"{leak['case_id']} {leak['request_text']} p=0.123456")

        with mock.patch.object(ev, "score", boom):
            code, out = self.run_cli("run", "--confirm-single-run")
        self.assertEqual(code, 3)
        files = self.files()
        self.assertNotIn("aggregate_results.json", files)
        fail = json.loads(files["run_failure.json"])
        self.assertEqual((fail["stage"], fail["exception_class"]), ("inference", "ValueError"))
        for text in list(files.values()) + [out]:
            self.assert_no_case_data(text)
            self.assertNotIn("0.123456", text)
            self.assertNotIn("Traceback", text)
        code2, out2 = self.run_cli("run", "--confirm-single-run")
        self.assertEqual(code2, 2)

    def test_per_case_output_is_caught_before_anything_is_written(self):
        real = ev.compute_aggregates

        def leaky(y, p, *a, **k):
            out = real(y, p, *a, **k)
            out["leak"] = [float(x) for x in p]       # 400 per-case probabilities
            return out

        with mock.patch.object(ev, "compute_aggregates", leaky):
            code, out = self.run_cli("run", "--confirm-single-run")
        self.assertEqual(code, 3)
        files = self.files()
        self.assertNotIn("aggregate_results.json", files)
        self.assertEqual(json.loads(files["run_failure.json"])["stage"], "aggregate-check")

    def test_failed_preflight_does_not_start_the_run(self):
        with mock.patch.dict(ev.ANCHORS, {"integrity_hash": "0" * 64}):
            code, out = self.run_cli("run", "--confirm-single-run")
        self.assertEqual(code, 2)
        self.assertIn("PREFLIGHT FAILED", out)
        self.assertEqual(set(os.listdir(self.report)), {"PROTOCOL.md", "PREREGISTRATION.json"})
        self.assert_no_case_data(out)

    def test_preflight_record_is_exclusive_and_never_calls_the_model(self):
        no = AssertionError("inference called")
        with mock.patch.object(ev, "score", side_effect=no), \
                mock.patch.object(ha.AnalyzerModel, "attack_proba", side_effect=no), \
                mock.patch.object(ha.AnalyzerModel, "category_proba", side_effect=no), \
                mock.patch.object(ha.AnalyzerModel, "analyze", side_effect=no):
            code, out = self.run_cli("preflight", "--record")
            self.assertEqual(code, 0, out)
            self.assert_no_case_data(self.files()["preflight.json"])
            code, out = self.run_cli("preflight", "--record")
            self.assertEqual(code, 2)          # FileExistsError -> STOPPED, nothing overwritten


class TestEnvironmentIsNotSilentlySkipped(unittest.TestCase):
    def test_research_environment_runs_every_test(self):
        if ".venv-analyzer" in sys.prefix:
            self.assertTrue(HAVE_ML, "the evaluator failed to import in the research environment")


if __name__ == "__main__":
    unittest.main()
