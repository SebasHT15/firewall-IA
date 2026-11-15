from dataclasses import replace
import unittest
import numpy as np

from scripts.model2 import fixture_experiment as exp
from scripts.model2.feature_views import neutralize_target_path


class TestPathAblation(unittest.TestCase):
    def test_all_path_character_and_entropy_effects_are_removed(self):
        a = "GET /alpha HTTP/1.1\n"
        b = "GET /%FF/;;;;;;/José/abcabc HTTP/1.1\n"
        self.assertNotEqual(exp.feature_dict(a, omit_direct_path=True), exp.feature_dict(b, omit_direct_path=True))
        self.assertEqual(exp.feature_dict(a, neutralize_path=True), exp.feature_dict(b, neutralize_path=True))
        self.assertNotIn("path_length", exp.feature_dict(a, neutralize_path=True))
        self.assertEqual(len(exp.feature_dict(a, neutralize_path=True)), 32)

    def test_query_body_and_unicode_line_separators_are_preserved(self):
        rest = "Content-Type: text/plain\n\na\u0085b\u2028c\u2029d /keep/path"
        source = "POST /remove?q=/keep/%2F HTTP/1.1\n" + rest
        self.assertEqual(neutralize_target_path(source), "POST /?q=/keep/%2F HTTP/1.1\n" + rest)
        self.assertNotEqual(exp.feature_dict(source, neutralize_path=True),
                            exp.feature_dict(source.replace("/keep/%2F", "different"), neutralize_path=True))

    def test_asterisk_supported_and_noncanonical_input_refused(self):
        self.assertEqual(neutralize_target_path("OPTIONS * HTTP/1.1\n"), "OPTIONS / HTTP/1.1\n")
        for text in ("GET http://host/path HTTP/1.1\n", "GET / HTTP/1.0\n", "GET / HTTP/1.1\nHost: x\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                neutralize_target_path(text)

    def test_fitted_predictions_invariant_when_only_train_validation_paths_change(self):
        rows = exp.fixtures()
        altered = []
        for row in rows:
            text = row.text.replace("/fixture/", "/;;;;/%%%%/long-structural-change/")
            altered.append(replace(row, text=text, text_sha256=exp._digest(text)))
        a = exp._fit_fixture(rows, neutralize_path=True)
        b = exp._fit_fixture(altered, neutralize_path=True)
        self.assertEqual(list(a[0].get_feature_names_out()), list(b[0].get_feature_names_out()))
        np.testing.assert_array_equal(a[1].mean_, b[1].mean_)
        np.testing.assert_array_equal(a[3], b[3])
