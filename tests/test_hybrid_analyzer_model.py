"""Lightweight Request Analyzer Phase 2B tests (Issue #53): preprocessing, model input
schema, AnalyzerOutput produced by a trained Analyzer, and basic reproducibility.

Needs numpy and scikit-learn, which live ONLY in the research environment (D52); the
module is skipped elsewhere:
    .venv-analyzer/bin/python -m unittest tests.test_hybrid_analyzer_model -v

They test this project's code (encoder, wiring, contract), not scikit-learn.
"""

import math
import os
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "data_plane"))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts", "training"))

try:
    import numpy as np
    import sklearn  # noqa: F401
    HAVE_SKLEARN = True
except ImportError:
    HAVE_SKLEARN = False

import hybrid_contracts as contracts  # noqa: E402
import request_features as rf  # noqa: E402

if HAVE_SKLEARN:
    import hybrid_analyzer as ha  # noqa: E402
    import run_hybrid_analyzer_baselines as runner  # noqa: E402

FORM = "application/x-www-form-urlencoded"


def req(method="GET", target="/", ctype=None, body=""):
    lines = [f"{method} {target} HTTP/1.1"] + ([f"Content-Type: {ctype}"] if ctype else [])
    text = "\n".join(lines)
    return text + "\n\n" + body if body else text


BENIGN = [rf.extract_features(t) for t in (
    req(target="/shop/item?id=12"), req(target="/search?q=laptop&page=2"),
    req("POST", "/login", FORM, "user=ana&pass=secret"), req(target="/a/b/c"),
    req("POST", "/api/cart", "application/json", '{"sku": "A-1", "qty": 2}'),
    req(target="/news?day=3"), req(target="/p?x=hello"), req(target="/"))]
ATTACK = [rf.extract_features(t) for t in (
    req(target="/item?id=1%27%20OR%20%271%27%3D%271"), req(target="/q?s=%3Cscript%3Ealert(1)%3C/script%3E"),
    req(target="/f?file=..%2F..%2F..%2Fetc%2Fpasswd"), req(target="/x?c=%3Bcat%20/etc/passwd"),
    req("POST", "/t", FORM, "name=%7B%7B7*7%7D%7D"), req(target="/r?next=http%3A%2F%2Fevil.example"),
    req(target="/u?url=http%3A%2F%2F169.254.169.254%2F"), req("PUT", "/v", "text/xml", "<!DOCTYPE x [<!ENTITY a SYSTEM 'file:///'>]>"))]


@unittest.skipUnless(HAVE_SKLEARN, "numpy / scikit-learn only in .venv-analyzer (D52)")
class TestFeatureEncoder(unittest.TestCase):

    def test_columns_follow_requestfeatures_order_and_are_stable(self):
        a = ha.FeatureEncoder("linear").fit(BENIGN + ATTACK)
        b = ha.FeatureEncoder("linear").fit(list(reversed(BENIGN + ATTACK)))
        self.assertEqual(a.columns, b.columns)
        base = [c.split("=")[0] for c in a.columns]
        self.assertEqual(list(dict.fromkeys(base)), list(ha.FEATURE_FIELDS))
        self.assertEqual(ha.FEATURE_FIELDS[0], "method")
        self.assertEqual(len(ha.FEATURE_FIELDS), 34)

    def test_model_input_schema_has_no_metadata(self):
        enc = ha.FeatureEncoder("tree").fit(BENIGN)
        x = enc.transform(ATTACK)
        self.assertEqual(x.shape, (len(ATTACK), len(enc.columns)))
        self.assertFalse(any(c.startswith("meta_") or c in ("row_id", "role", "slice")
                             for c in enc.columns))

    def test_statistics_come_only_from_fit_rows(self):
        enc = ha.FeatureEncoder("linear").fit(BENIGN)
        before = enc.to_dict()
        enc.transform(ATTACK)                       # transforming never refits
        self.assertEqual(enc.to_dict(), before)
        expected = np.mean([math.log1p(f.percent_encoded_count) for f in BENIGN])
        self.assertAlmostEqual(enc.mean["percent_encoded_count"], expected)
        self.assertEqual(enc.levels["method"], ["GET", "POST", ha.OTHER])

    def test_unseen_open_category_goes_to_other_and_closed_enum_rejects(self):
        enc = ha.FeatureEncoder("tree").fit(BENIGN)
        put = rf.extract_features(req("PUT", "/x", "text/xml", "<a/>"))
        row = dict(zip(enc.columns, enc.encode_row(put)))
        self.assertEqual(row[f"method={ha.OTHER}"], 1.0)
        self.assertEqual(row[f"content_type={ha.OTHER}"], 1.0)
        self.assertEqual(row["body_format=other"], 1.0)
        bad = rf.RequestFeatures(**{**{n: getattr(put, n) for n in ha.FEATURE_FIELDS},
                                    "body_format": "yaml"})
        with self.assertRaises(ValueError):
            enc.encode_row(bad)

    def test_tree_mode_keeps_raw_values_and_linear_mode_scales(self):
        f = ATTACK[0]
        tree = dict(zip(*(lambda e: (e.columns, e.encode_row(f)))(ha.FeatureEncoder("tree").fit(BENIGN))))
        self.assertEqual(tree["percent_encoded_count"], f.percent_encoded_count)
        self.assertEqual(tree["has_percent_encoding"], 1.0)
        lin = ha.FeatureEncoder("linear").fit(BENIGN)
        v = dict(zip(lin.columns, lin.encode_row(f)))["percent_encoded_count"]
        self.assertAlmostEqual(v, (math.log1p(f.percent_encoded_count) - lin.mean["percent_encoded_count"])
                               / lin.std["percent_encoded_count"])

    def test_ablation_drops_exactly_the_path_fields(self):
        enc = ha.FeatureEncoder("tree", drop=ha.PATH_ABLATION).fit(BENIGN)
        self.assertNotIn("path_length", enc.columns)
        self.assertNotIn("path_depth", enc.columns)
        self.assertEqual(len(enc.fields), 32)
        with self.assertRaises(ValueError):
            ha.FeatureEncoder("tree", drop=("host",))

    def test_round_trip(self):
        enc = ha.FeatureEncoder("linear").fit(BENIGN + ATTACK)
        again = ha.FeatureEncoder.from_dict(enc.to_dict())
        np.testing.assert_array_equal(enc.transform(ATTACK), again.transform(ATTACK))


def _fake_rows(features, attack, categories):
    return [{"features": f, "target_attack": a, "target_category": c, "meta_group_id": str(i)}
            for i, (f, a, c) in enumerate(zip(features, attack, categories))]


@unittest.skipUnless(HAVE_SKLEARN, "numpy / scikit-learn only in .venv-analyzer (D52)")
class TestPipeline(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cats = list(contracts.ANALYZER_CATEGORIES)
        train = _fake_rows(BENIGN + ATTACK, [0] * 8 + [1] * 8, [None] * 8 + cats)
        val = _fake_rows(list(reversed(BENIGN + ATTACK)), [1] * 8 + [0] * 8,
                         list(reversed(cats)) + [None] * 8)
        cls.data = {"attack": {"train": train, "validation": val,
                               "y_train": ha.y_attack(train), "y_validation": ha.y_attack(val)},
                    "category": {"train": ha.block_rows(train), "validation": ha.block_rows(val)}}
        cls.data["category"]["y_train"] = ha.y_category(cls.data["category"]["train"])
        cls.data["category"]["y_validation"] = ha.y_category(cls.data["category"]["validation"])

    def test_fit_eval_fits_preprocessing_on_train_only(self):
        enc, *_ = runner.fit_eval(ha, "attack", "logreg", {"C": 1.0, "log1p": True}, self.data)
        ref = ha.FeatureEncoder("linear").fit([r["features"] for r in self.data["attack"]["train"]])
        self.assertEqual(enc.to_dict(), ref.to_dict())
        enc_c, *_ = runner.fit_eval(ha, "category", "hist_gb", {"max_iter": 5}, self.data)
        ref_c = ha.FeatureEncoder("tree").fit([r["features"] for r in self.data["category"]["train"]])
        self.assertEqual(enc_c.to_dict(), ref_c.to_dict())

    def _analyzer(self, family, attack_params, category_params, seed=0):
        enc_a, m_a, *_ = runner.fit_eval(ha, "attack", family, attack_params, self.data, seed=seed)
        enc_c, m_c, *_ = runner.fit_eval(ha, "category", family, category_params, self.data, seed=seed)
        return ha.AnalyzerModel(f"hybrid-analyzer-v1/{family}-test", enc_a,
                                ha.finalize_for_inference(m_a), enc_c, ha.finalize_for_inference(m_c))

    def test_analyzer_output_is_a_valid_contract(self):
        for family, pa, pc in (("logreg", {"C": 1.0}, {"C": 1.0}),
                               ("random_forest", {"n_estimators": 10}, {"n_estimators": 10}),
                               ("hist_gb", {"max_iter": 10}, {"max_iter": 10})):
            an = self._analyzer(family, pa, pc)
            for f in BENIGN + ATTACK:
                with self.subTest(family=family):
                    out = an.analyze(f)
                    self.assertIsInstance(out, contracts.AnalyzerOutput)
                    self.assertTrue(0.0 <= out.signals["attack"] <= 1.0)
                    cats = [out.signals[s] for s in contracts.CATEGORY_SIGNALS]
                    self.assertTrue(all(0.0 <= p <= 1.0 for p in cats))
                    self.assertAlmostEqual(math.fsum(cats), 1.0, delta=1e-6)
                    self.assertEqual(set(out.signals), {"attack", *contracts.CATEGORY_SIGNALS})

    def test_batch_and_single_request_agree(self):
        an = self._analyzer("hist_gb", {"max_iter": 10}, {"max_iter": 10})
        batch = an.attack_proba(ATTACK)
        single = [an.analyze(f).signals["attack"] for f in ATTACK]
        np.testing.assert_allclose(batch, single, rtol=0, atol=1e-12)

    def test_category_model_must_cover_the_8_categories(self):
        an = self._analyzer("logreg", {"C": 1.0}, {"C": 1.0})
        partial = ha.make_model("logreg", {"C": 1.0}).fit(
            an.category_encoder.transform(ATTACK[:4]), [0, 1, 2, 3])
        with self.assertRaises(ValueError):
            ha.AnalyzerModel("v", an.attack_encoder, an.attack_model, an.category_encoder, partial)

    def test_same_seed_reproduces_probabilities(self):
        for family in ("random_forest", "hist_gb"):
            params = {"n_estimators": 20} if family == "random_forest" else {"max_iter": 20}
            a = runner.fit_eval(ha, "attack", family, params, self.data, seed=3)[2]
            b = runner.fit_eval(ha, "attack", family, params, self.data, seed=3)[2]
            np.testing.assert_array_equal(a, b)


@unittest.skipUnless(HAVE_SKLEARN, "numpy / scikit-learn only in .venv-analyzer (D52)")
class TestMetricsAndSlices(unittest.TestCase):

    def test_confusion_counts_use_the_reporting_threshold(self):
        m = ha.attack_metrics([0, 0, 1, 1, 1], [0.1, 0.5, 0.49, 0.9, 1.0], with_bins=False)
        self.assertEqual((m["tp"], m["tn"], m["fp"], m["fn"]), (2, 1, 1, 1))
        self.assertAlmostEqual(m["fpr"], 0.5)
        self.assertAlmostEqual(m["fnr"], 1 / 3, places=6)   # metrics are reported to 6 decimals

    def test_reliability_of_a_calibrated_constant(self):
        rel = ha.reliability_bins([0, 1, 0, 1], [0.5, 0.5, 0.5, 0.5])
        self.assertEqual(rel["ece"], 0.0)

    def test_views_keep_jwt_out_of_fitting_and_test_views(self):
        rows = [{"role": role, "slice": sl, "meta_feature_vector_in_train": flag}
                for role, sl, flag in (("train", None, None), ("train", "unsupported_jwt", None),
                                       ("validation", "unsupported_jwt", None),
                                       ("internal_test", None, True), ("internal_test", None, False),
                                       ("internal_test", "unsupported_jwt", False))]
        v = ha.views(rows)
        for name in ("train", "validation", "internal_test_full", "internal_test_feature_disjoint"):
            self.assertTrue(all(r["slice"] is None for r in v[name]), name)
        self.assertEqual(len(v["internal_test_full"]), 2)
        self.assertEqual(len(v["internal_test_feature_disjoint"]), 1)
        self.assertEqual(len(v["unsupported_jwt"]), 1)

    def test_calibration_folds_are_whole_groups(self):
        groups = [f"g{i % 37}" for i in range(400)]
        y = np.array([i % 2 for i in range(400)])
        x = np.linspace(-2, 2, 400).reshape(-1, 1)
        model = ha.make_model("logreg", {"C": 1.0}).fit(x, y)
        cal, chosen, final, oof = runner.calibration_cv(ha, model, x, y, np.array(groups))
        self.assertIn(chosen, runner.CALIBRATION_METHODS)
        self.assertEqual(sum(cal["native"]["fold_rows"]), 400)
        self.assertEqual(len(oof), 400)


@unittest.skipUnless(HAVE_SKLEARN, "numpy / scikit-learn only in .venv-analyzer (D52)")
class TestRun002Evaluation(unittest.TestCase):
    """Row vs group weighting, dev-only loading, the run-002 winner rule, and the
    feature-disjoint definition on the real v2 file."""

    def test_group_weighting_gives_each_group_weight_one(self):
        # group g1: 3 benign rows all wrong; g2, g3: one attack each, both right
        y = [0, 0, 0, 1, 1]
        p = [0.9, 0.9, 0.9, 0.8, 0.7]
        rowm = ha.attack_metrics(y, p, with_bins=False)
        gw = ha.attack_metrics_group_weighted(y, p, ["g1", "g1", "g1", "g2", "g3"])
        self.assertAlmostEqual(rowm["accuracy"], 0.4)
        self.assertEqual(gw["n_groups"], 3)
        self.assertAlmostEqual(gw["fp"], 1.0)          # three rows, one group
        self.assertAlmostEqual(gw["accuracy"], 2 / 3, places=6)

    def test_load_dataset_can_exclude_internal_test(self):
        import json as _json
        import tempfile
        feats = {n: getattr(BENIGN[0], n) for n in ha.FEATURE_FIELDS}
        lines = [_json.dumps({"row_id": str(i), "role": role, "slice": None, "features": feats,
                              "target_attack": 0, "target_category": None})
                 for i, role in enumerate(("train", "validation", "internal_test"))]
        with tempfile.TemporaryDirectory() as d:
            path, man = os.path.join(d, "x.jsonl"), os.path.join(d, "m.json")
            with open(path, "w") as f:
                f.write("\n".join(lines) + "\n")
            with open(man, "w") as f:
                _json.dump({"artifact": {"sha256": ha.sha256_file(path)}}, f)
            rows = ha.load_dataset(path, man, roles=runner.DEV_ROLES)
            self.assertEqual({r["role"] for r in rows}, {"train", "validation"})
            self.assertEqual(len(ha.load_dataset(path, man)), 3)

    @staticmethod
    def _evidence(brier, f1, ci_a, ci_c, lat_a, lat_c):
        fams = list(brier)
        val = {"saved_models": {f: {} for f in fams},
               "attack": {f: {"validation_calibrated_oof": {"brier": brier[f]}} for f in fams},
               "category": {f: {"validation": {"macro_f1": f1[f]}} for f in fams},
               "paired_bootstrap_validation_all_pairs": {
                   "attack (calibrated out-of-fold probabilities)": {
                       ref: {f"{f} - {ref}": {"brier_diff": {"ci95": ci_a(f, ref)}}
                             for f in fams if f != ref} for ref in fams},
                   "category (macro-F1)": {
                       ref: {f"{f} - {ref}": {"macro_f1_diff": {"ci95": ci_c(f, ref)}}
                             for f in fams if f != ref} for ref in fams}}}
        lat = {"models": {f: {"artifact_bytes": 1, "latency_ms": {
            "attack_inference": {"p50": lat_a[f]}, "category_inference": {"p50": lat_c[f]}}}
            for f in fams}}
        return val, lat

    def test_winner_rule_prefers_cheapest_among_statistically_tied(self):
        brier = {"logreg": 0.07, "random_forest": 0.020, "hist_gb": 0.021}
        f1 = {"logreg": 0.46, "random_forest": 0.69, "hist_gb": 0.73}
        tie_rf_hgb = lambda f, ref: ([-0.003, 0.004] if {f, ref} == {"random_forest", "hist_gb"}
                                     else [0.03, 0.06])
        clear = lambda f, ref: [-0.09, -0.02]
        val, lat = self._evidence(brier, f1, tie_rf_hgb, clear,
                                  {"logreg": 0.4, "random_forest": 8.0, "hist_gb": 1.2},
                                  {"logreg": 0.1, "random_forest": 7.5, "hist_gb": 8.3})
        attack, category, rec = runner.mechanical_winners(val, lat)
        self.assertEqual(rec["attack"]["best"], "random_forest")
        self.assertEqual(sorted(rec["attack"]["statistically_tied_with_best"]),
                         ["hist_gb", "random_forest"])
        self.assertEqual(attack, "hist_gb")          # tied and cheaper
        self.assertEqual(category, "hist_gb")        # best, nothing tied

    def test_feature_disjoint_is_against_train_union_validation(self):
        path = os.path.join(REPO_ROOT, "datasets", "hybrid_analyzer_v2", "hybrid_analyzer_v2.jsonl")
        if not os.path.exists(path):
            self.skipTest("hybrid_analyzer_v2 not built locally")
        rows = ha.load_dataset(path, os.path.join(REPO_ROOT, "datasets",
                                                  "manifest_hybrid_analyzer_v2.json"))
        v = ha.views(rows)
        dev = {r["meta_feature_vector_sha256"] for r in v["train"] + v["validation"]}
        val_only = {r["meta_feature_vector_sha256"] for r in v["validation"]}
        disjoint = v["internal_test_feature_disjoint"]
        self.assertEqual(len(disjoint), 5_456)
        self.assertFalse(any(r["meta_feature_vector_sha256"] in dev for r in disjoint))
        # a vector seen only in VALIDATION still excludes the row
        excluded_by_val = [r for r in v["internal_test_full"]
                           if r["meta_feature_vector_sha256"] in val_only]
        self.assertTrue(all(r not in disjoint for r in excluded_by_val))


@unittest.skipUnless(HAVE_SKLEARN, "numpy / scikit-learn only in .venv-analyzer (D52)")
class TestFrozenRun002Artifact(unittest.TestCase):
    """The frozen run-002 Analyzer (gitignored pickle): hash, loading, contract and
    deterministic inference on VALIDATION rows (never INTERNAL TEST)."""

    def test_frozen_artifact_loads_and_answers_the_contract(self):
        import json as _json
        import pickle
        report = os.path.join(REPO_ROOT, "reports", "hybrid", "phase2b-analyzer-v2-run-002")
        frozen_path = os.path.join(report, "frozen_selection.json")
        if not os.path.exists(frozen_path):
            self.skipTest("run-002 not frozen locally")
        with open(frozen_path) as f:
            rec = _json.load(f)["recommended"]
        path = os.path.join(REPO_ROOT, rec["path"])
        if not os.path.exists(path):
            self.skipTest("frozen model pickle not present (gitignored)")
        self.assertEqual(ha.sha256_file(path), rec["sha256"])
        with open(path, "rb") as f:
            analyzer = pickle.load(f)
        self.assertEqual(analyzer.version, rec["analyzer_version"])
        rows = ha.load_dataset(
            os.path.join(REPO_ROOT, "datasets", "hybrid_analyzer_v2", "hybrid_analyzer_v2.jsonl"),
            os.path.join(REPO_ROOT, "datasets", "manifest_hybrid_analyzer_v2.json"),
            roles=("validation",))[:300]
        for r in rows:
            out = analyzer.analyze(r["features"])
            self.assertTrue(0.0 <= out.signals["attack"] <= 1.0)
            self.assertAlmostEqual(math.fsum(out.signals[c] for c in contracts.CATEGORY_SIGNALS),
                                   1.0, delta=1e-6)
            self.assertEqual(out.signals, analyzer.analyze(r["features"]).signals)


if __name__ == "__main__":
    unittest.main()
