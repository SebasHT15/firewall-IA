"""Synthetic, offline C1 extension contract tests."""
from dataclasses import replace
import unittest

from scripts.model2 import c1_extensions as c1
import canonical_request as cr


def request(target=b"/fixture", body=b"", content_type=None, *, limit=65536):
    headers = () if content_type is None else ((b"Content-Type", content_type),)
    return cr.canonicalize(cr.RequestParts(b"POST" if body else b"GET", target,
                                               headers=headers, body=body),
                           cr.Limits(max_decoded_body=limit))


class TestC1Extensions(unittest.TestCase):
    def test_types_urls_lexemes_and_one_decode_without_decision(self):
        result = request(b"/fixture?a=https%3A%2F%2Fexample.invalid%2Fx&b=42&c=true"
                         b"&d=select&e=%3Cscript%3E")
        evidence = c1.extract_extension(result)
        self.assertEqual(evidence.status, "COMPLETE")
        self.assertEqual(evidence.raw.count, 5)
        self.assertEqual(evidence.raw.url_https, 0)
        self.assertEqual(evidence.decoded_once.url_https, 1)
        self.assertEqual(evidence.decoded_once.integer, 1)
        self.assertEqual(evidence.decoded_once.boolean, 1)
        self.assertEqual(evidence.decoded_once.lex_select, 1)
        self.assertEqual(evidence.decoded_once.lex_script, 1)
        self.assertEqual(evidence.view_conflicts, 2)
        self.assertFalse(evidence.learned_input_admitted)

    def test_form_plus_and_query_plus_have_distinct_semantics(self):
        result = request(b"/fixture?q=a+b", b"f=a+b&url=http%3A%2F%2Fa.invalid",
                         b"application/x-www-form-urlencoded")
        evidence = c1.extract_extension(result)
        self.assertEqual(evidence.value_sources, ("query", "form"))
        self.assertEqual(evidence.decoded_once.url_http, 1)
        self.assertEqual(evidence.view_conflicts, 2)  # form plus and encoded URL

    def test_lexical_boundaries_and_url_shape_do_not_imply_attack(self):
        evidence = c1.extract_extension(request(
            b"/fixture?a=selection&b=unionized&c=scripture&d=https%3A%2F%2F"
            b"&e=select%20union%20script"))
        self.assertEqual(evidence.decoded_once.url_https, 0)  # no hostname
        self.assertEqual(evidence.decoded_once.lex_select, 1)
        self.assertEqual(evidence.decoded_once.lex_union, 1)
        self.assertEqual(evidence.decoded_once.lex_script, 1)
        self.assertFalse(evidence.learned_input_admitted)

    def test_json_nested_scalars_and_duplicate_members_are_counted(self):
        result = request(b"/fixture", b'{"a":"https://a.invalid","a":["union",3,null,true]}',
                         b"application/json")
        evidence = c1.extract_extension(result)
        self.assertEqual(evidence.status, "COMPLETE")
        self.assertEqual(evidence.raw.count, 5)
        self.assertEqual(evidence.raw.null, 1)
        self.assertEqual(evidence.raw.boolean, 1)
        self.assertEqual(evidence.raw.url_https, 1)
        self.assertEqual(evidence.raw.lex_union, 1)
        self.assertEqual(evidence.view_conflicts, 0)

    def test_invalid_percent_decoded_view_is_missing_not_zero(self):
        for value in (b"%ZZ", b"%ff", b"%u0041"):
            with self.subTest(value=value):
                evidence = c1.extract_extension(request(b"/fixture?x=" + value))
                self.assertEqual(evidence.status, "PARTIAL")
                self.assertIsNone(evidence.decoded_once)
                self.assertIn("decoded_view_invalid", evidence.facts_missing)

    def test_body_without_supported_value_parser_is_partial(self):
        evidence = c1.extract_extension(request(b"/fixture", b"hello select", b"text/plain"))
        self.assertEqual(evidence.status, "PARTIAL")
        self.assertIn("body_values_unsupported", evidence.facts_missing)
        self.assertEqual(evidence.raw.count, 0)

    def test_bounds_fail_closed_without_truncating_values(self):
        long_value = b"x" * (c1.MAX_VALUE_CHARS + 1)
        evidence = c1.extract_extension(request(b"/fixture?x=" + long_value))
        self.assertEqual(evidence.status, "UNAVAILABLE")
        self.assertIsNone(evidence.raw)
        self.assertIn("values_over_offline_bound", evidence.facts_missing)
        oversized = request(b"/fixture?x=" + b"a" * c1.MAX_TEXT_BYTES,
                            limit=c1.MAX_TEXT_BYTES + 100)
        evidence = c1.extract_extension(oversized)
        self.assertEqual(evidence.status, "UNAVAILABLE")
        self.assertIsNone(evidence.baseline)
        many = b"/fixture?" + b"&".join(b"x=1" for _ in range(c1.MAX_VALUES + 1))
        evidence = c1.extract_extension(request(many))
        self.assertEqual(evidence.status, "UNAVAILABLE")
        self.assertIsNone(evidence.raw)

    def test_nonaccept_has_no_feature_claim_and_signals_preserved(self):
        result = request(b"/fixture", b"x", b"text/plain")
        rejected = replace(result, outcome=cr.REJECT, text=None, reject="R8")
        evidence = c1.extract_extension(rejected)
        self.assertEqual(evidence.status, "UNAVAILABLE")
        self.assertIsNone(evidence.baseline)
        self.assertEqual(evidence.canonical_signals, rejected.signals)

    def test_invalid_result_or_signal_refused(self):
        result = request()
        with self.assertRaises(TypeError):
            c1.extract_extension(None)
        with self.assertRaises(ValueError):
            c1.extract_extension(replace(result, signals=("UNKNOWN",)))
        with self.assertRaises(ValueError):
            c1.extract_extension(replace(result, text="malformed"))
        with self.assertRaises(ValueError):
            c1.extract_extension(replace(result, size="invented"))
        with self.assertRaises(ValueError):
            c1.extract_extension(replace(result, audit={**result.audit, "text_sha256": "0" * 64}))

    def test_header_and_labels_do_not_enter_value_facts(self):
        a = request(b"/fixture?x=ordinary")
        b = cr.canonicalize(cr.RequestParts(
            b"GET", b"/fixture?x=ordinary",
            headers=((b"Host", b"select.invalid"), (b"User-Agent", b"script union"))),
            cr.Limits(max_decoded_body=65536))
        ea, eb = c1.extract_extension(a), c1.extract_extension(b)
        self.assertEqual(ea.raw, eb.raw)
        self.assertEqual(ea.decoded_once, eb.decoded_once)
        self.assertEqual(ea.baseline, eb.baseline)

    def test_json_native_type_is_distinct_from_lexical_shape(self):
        result = request(b"/fixture", b'["true",true,"42",42,1e400,null,""]', b"application/json")
        evidence = c1.extract_extension(result)
        self.assertEqual(evidence.json_types, c1.JsonScalarTypes(string=3, number=2, boolean=1, null=1))
        self.assertEqual(evidence.raw.scientific, 1)
        self.assertEqual(evidence.raw.boolean, 2)  # Shape includes the string "true".
        self.assertEqual(evidence.raw.empty, 1)
        self.assertEqual(evidence.raw.null, 1)

    def test_url_shape_refuses_parser_normalization_and_invalid_ports(self):
        import json
        values = ["\thttps://a.invalid", "http://a.invalid:99999", "https://a.invalid:bad",
                  "http://a.in\nvalid", "https://a.invalid"]
        result = request(b"/fixture", json.dumps(values).encode(), b"application/json")
        evidence = c1.extract_extension(result)
        self.assertEqual(evidence.raw.url_http, 0)
        self.assertEqual(evidence.raw.url_https, 1)

    def test_ascii_lexemes_do_not_fold_unicode_long_s(self):
        evidence = c1.extract_extension(request(b"/fixture", '["ſcript","SCRIPT"]'.encode(), b"application/json"))
        self.assertEqual(evidence.raw.lex_script, 1)

    def test_unavailable_difference_is_not_reported_as_zero(self):
        evidence = c1.extract_extension(request(b"/fixture?x=%ff"))
        self.assertIsNone(evidence.view_conflicts)
        self.assertIsNone(evidence.decoded_once)

    def test_reference_grammar_rejects_empty_body_separator(self):
        import hashlib
        result = request()
        text = result.text + "\n"
        result = replace(result, text=text, audit={**result.audit, "text_sha256": hashlib.sha256(text.encode()).hexdigest()})
        with self.assertRaises(ValueError):
            c1.extract_extension(result)


if __name__ == "__main__":
    unittest.main()
