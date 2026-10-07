"""Tests for the V5 benign coverage audit (scripts/dataset/audit_v5_benign_coverage.py).

Synthetic inputs only, standard library only. They cover the logic that could silently produce
wrong counts: decoding, lexical matching, body/JSON classification, parameter counting, group
counting, support status, order independence and the forbidden-input guard.

    python3 -m unittest tests.test_v5_benign_coverage_audit -v
"""

import os
import random
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts", "dataset"))

import audit_v5_benign_coverage as audit  # noqa: E402


def markers(text):
    return audit.extract_markers(text)["markers"]


class DecodingTests(unittest.TestCase):
    def test_single_and_double_encoding(self):
        self.assertEqual(audit.decode_layers("%27"), ("'", 1))
        self.assertEqual(audit.decode_layers("%2527"), ("'", 2))
        self.assertEqual(audit.decode_layers("%252527", max_layers=3), ("'", 3))

    def test_plus_is_space_only_in_form_mode_and_first_layer(self):
        self.assertEqual(audit.decode_layers("a+b", form=True), ("a b", 0))
        self.assertEqual(audit.decode_layers("a+b"), ("a+b", 0))
        # '%2B' decodes to a literal '+', which a later layer must not turn into a space
        self.assertEqual(audit.decode_layers("a%2Bb", form=True), ("a+b", 1))

    def test_invalid_percent_is_left_alone(self):
        self.assertEqual(audit.decode_layers("100%"), ("100%", 0))
        self.assertEqual(audit.decode_layers("%zz"), ("%zz", 0))

    def test_double_encoding_marker(self):
        m = markers("GET /a?x=%252e%252e%252f HTTP/1.1\nHost: h")
        self.assertIn("encoding:double_or_more", m)
        self.assertIn("char:..", m)
        self.assertNotIn("encoding:double_or_more", markers("GET /a?x=%2e%2e HTTP/1.1\nHost: h"))


class LexicalTests(unittest.TestCase):
    def test_whole_token_case_insensitive(self):
        rx = audit.term_regex("select")
        self.assertTrue(rx.search("SELECT * from t"))
        self.assertTrue(rx.search("please select_all"))      # '_' is not a letter or digit
        self.assertFalse(rx.search("selection"))
        self.assertFalse(rx.search("preselect"))

    def test_short_terms_do_not_match_inside_words(self):
        self.assertFalse(audit.term_regex("and").search("android"))
        self.assertFalse(audit.term_regex("or").search("order"))
        self.assertTrue(audit.term_regex("or").search("tea or coffee"))

    def test_lexical_reads_decoded_values_not_headers(self):
        m = markers("GET /s?q=credit%20union HTTP/1.1\nHost: h\nX-Note: select")
        self.assertIn("lexical:union", m)
        self.assertNotIn("lexical:select", m)

    def test_free_text(self):
        self.assertTrue(audit.is_free_text("please leave at the door"))
        self.assertFalse(audit.is_free_text("a b c"))
        self.assertFalse(audit.is_free_text("1 2 3 4"))


class BodyAndJsonTests(unittest.TestCase):
    def test_body_syntax(self):
        self.assertEqual(audit.body_syntax("")[0], "none")
        self.assertEqual(audit.body_syntax('{"a":1}')[0], "json_object")
        self.assertEqual(audit.body_syntax("[1,2]")[0], "json_array")
        self.assertEqual(audit.body_syntax("{not json")[0], "other")
        self.assertEqual(audit.body_syntax("a=1&b=two%20words")[0], "form_pairs")
        self.assertEqual(audit.body_syntax("<x/>")[0], "xml")
        self.assertEqual(audit.body_syntax("just some text")[0], "other")

    def test_json_profile(self):
        _, v = audit.body_syntax('{"a":1,"b":{"c":[true,null,"x y z w"]},"a":2}')
        p = audit.json_profile(v)
        self.assertEqual(p["top_keys"], 2)
        self.assertTrue(p["duplicate_keys"])
        self.assertTrue(p["nested_object"] and p["array_inside"])
        self.assertTrue(p["number"] and p["bool"] and p["null"] and p["string"])
        self.assertEqual(p["depth"], 3)
        _, flat = audit.body_syntax('{"q":"x"}')
        self.assertEqual(audit.json_profile(flat)["depth"], 1)
        self.assertFalse(audit.json_profile(flat)["nested_object"])

    def test_declared_content_type_mismatch(self):
        t = "POST /a HTTP/1.1\nHost: h\nContent-Type: application/json\n\npassword=abc"
        m = markers(t)
        self.assertIn("structure:declared_ct_body_mismatch", m)
        self.assertIn("structure:body_syntax=form_pairs", m)

    def test_json_markers(self):
        t = ('POST /a HTTP/1.1\nHost: h\nContent-Type: application/json\n\n'
             '{"id":3,"callback":"https://x.example/h","note":"call me before noon please"}')
        m = markers(t)
        for expected in ("json:top_keys=3", "json:number", "json:url_string",
                         "json:free_text_string", "structure:url_valued_param",
                         "lexical:call", "field:security_sensitive_name"):
            self.assertIn(expected, m)


class ParameterTests(unittest.TestCase):
    def test_pairs(self):
        self.assertEqual(audit.parse_pairs("a=1&&b=2"), [("a", "1"), ("b", "2")])
        self.assertEqual(audit.parse_pairs("flag&x="), [("flag", ""), ("x", "")])

    def test_counts_and_repeats(self):
        m = markers("GET /a?x=1&x=2&y=3 HTTP/1.1\nHost: h")
        self.assertIn("structure:query_params=3", m)
        self.assertIn("structure:total_params=3", m)
        self.assertIn("structure:repeated_param_names", m)
        form = ("POST /a?q=1 HTTP/1.1\nHost: h\nContent-Type: application/x-www-form-urlencoded"
                "\n\nusername=o%27neil&password=pa%24%24")
        m = markers(form)
        self.assertIn("structure:total_params=3", m)
        self.assertIn("structure:query_and_body", m)
        self.assertIn("form:body_fields=2", m)
        self.assertIn("field:password_value_has_symbol", m)
        self.assertIn("char:'", m)


class EnvelopeTests(unittest.TestCase):
    def test_host(self):
        self.assertIn("envelope:host_loopback", markers("GET / HTTP/1.1\nHost: 127.0.0.1:8080"))
        self.assertIn("envelope:host_loopback", markers("GET / HTTP/1.1\nHost: [::1]:9000"))
        self.assertIn("envelope:host_port=other", markers("GET / HTTP/1.1\nHost: [::1]:9000"))
        self.assertIn("envelope:host_port=none", markers("GET / HTTP/1.1\nHost: a.example"))
        self.assertNotIn("envelope:host_loopback", markers("GET / HTTP/1.1\nHost: 10.0.0.1"))
        self.assertIn("envelope:host_loopback_name", markers("GET / HTTP/1.1\nHost: localhost:8080"))
        self.assertIn("envelope:host_loopback_ip", markers("GET / HTTP/1.1\nHost: 127.0.0.1"))

    def test_internal_address_literal_position(self):
        in_host = markers("GET / HTTP/1.1\nHost: 127.0.0.1:9000")
        self.assertIn("anywhere:internal_address_literal", in_host)
        self.assertNotIn("lexical:internal_address_literal", in_host)
        in_value = markers("GET /f?url=http%3A%2F%2F169.254.169.254%2F HTTP/1.1\nHost: h")
        self.assertIn("lexical:internal_address_literal", in_value)
        self.assertNotIn("lexical:internal_address_literal",
                         markers("GET /v?ver=1127.0.0.12 HTTP/1.1\nHost: h"))

    def test_ua_family(self):
        self.assertEqual(audit.ua_family("curl/8.18.0"), "curl")
        self.assertEqual(audit.ua_family("python-requests/2.31"), "python")
        self.assertEqual(audit.ua_family("Mozilla/5.0 (X11)"), "browser")
        self.assertEqual(audit.ua_family(None), "absent")

    def test_content_markers_ignore_headers(self):
        a = markers("GET /a?q=x HTTP/1.1\nHost: h\nUser-Agent: curl/8")
        b = markers("GET /a?q=x HTTP/1.1\nHost: 127.0.0.1\nUser-Agent: Mozilla/5.0")
        strip = lambda ms: {m for m in ms if not m.startswith(("envelope:", "anywhere:"))}  # noqa: E731
        self.assertEqual(strip(a), strip(b))


class AggregationTests(unittest.TestCase):
    ROWS = [
        {"text": "GET /a?q=it%27s HTTP/1.1\nHost: h", "label": "BLOCK", "gen_group": "g1",
         "d54_group": "d1", "source": "attack"},
        {"text": "GET /b?q=it%27s HTTP/1.1\nHost: h", "label": "BLOCK", "gen_group": "g1",
         "d54_group": "d1", "source": "attack"},
        {"text": "GET /b?q=it%27s HTTP/1.1\nHost: h", "label": "BLOCK", "gen_group": "g2",
         "d54_group": "d1", "source": "attack"},
        {"text": "GET /c?q=plain HTTP/1.1\nHost: h", "label": "ALLOW", "gen_group": "g3",
         "d54_group": "d3", "source": "synthetic_benign"},
    ]

    def test_counts_by_unit(self):
        agg = audit.aggregate(self.ROWS)
        quote = agg["markers"]["char:'"]
        self.assertEqual(quote["BLOCK"], {"rows": 3, "unique_texts": 2, "generator_groups": 2,
                                          "d54_groups": 1})
        self.assertEqual(quote["ALLOW"]["rows"], 0)
        self.assertEqual(quote["benign_support"], "ABSENT")
        self.assertEqual(quote["benign_group_share"], 0.0)
        self.assertEqual(agg["totals"]["ALLOW"]["generator_groups"], 1)

    def test_order_independent(self):
        rows = list(self.ROWS)
        random.Random(7).shuffle(rows)
        self.assertEqual(audit.aggregate(rows), audit.aggregate(self.ROWS))

    def test_support_status(self):
        self.assertEqual(audit.support_status(0), "ABSENT")
        self.assertEqual(audit.support_status(29), "SCARCE")
        self.assertEqual(audit.support_status(30), "SUPPORTED")

    def test_contrast_counts_unique_texts_and_flags_inconsistency(self):
        train = audit.aggregate(self.ROWS)["markers"]
        units = [
            {"source": "d", "text_sha256": "1", "text": "GET /x?q=o%27neil HTTP/1.1\nHost: h",
             "label": "ALLOW", "v4_decision": "BLOCK", "v4_consistent": True, "v4_reasons": {"r"}},
            {"source": "d", "text_sha256": "2", "text": "GET /c?q=plain HTTP/1.1\nHost: h",
             "label": "ALLOW", "v4_decision": "BLOCK", "v4_consistent": True, "v4_reasons": {"r"}},
        ]
        c = audit.contrast(units, train)
        self.assertEqual(c["benign_unique_texts"], 2)
        self.assertEqual(c["per_uncovered_marker"]["char:'"]["BLOCK"], 1)
        self.assertEqual(c["per_uncovered_marker"]["char:'"]["train_attack_generator_groups"], 2)


class GuardTests(unittest.TestCase):
    def test_refuses_forbidden_inputs(self):
        for p in ("datasets/v4_clean/eval.jsonl", "datasets/external_v1/cases.jsonl",
                  "reports/external/external-v1-run-001/summary.json",
                  "docker/.lab-logs/capture/x"):
            with self.assertRaises(PermissionError):
                audit.guarded_path(p)
        self.assertTrue(audit.guarded_path("datasets/v4_clean/train.jsonl").endswith("train.jsonl"))


if __name__ == "__main__":
    unittest.main()
