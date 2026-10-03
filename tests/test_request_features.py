"""Request feature extraction tests (Hybrid Architecture Phase 1,
data_plane/request_features.py and data_plane/hybrid_contracts.py).

These tests check DESCRIPTIONS, never security decisions: the module makes none.
A request full of quotes and brackets is expected to have high symbol counts, not
to be "blocked".

Standard library only, so the module runs in both environments:
    python3.12 -m unittest tests.test_request_features -v
    .venv-dataplane/bin/python -m unittest tests.test_request_features -v
"""

import asyncio
import dataclasses
import json
import math
import os
import subprocess
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PLANE_DIR = os.path.join(REPO_ROOT, "data_plane")
sys.path.insert(0, DATA_PLANE_DIR)

import hybrid_contracts as contracts  # noqa: E402
import request_features as rf  # noqa: E402

extract = rf.extract_features

FORM = "application/x-www-form-urlencoded"


def req(method="GET", target="/", headers=(), body=""):
    """Build D1 text exactly like data_plane.render_request() lays it out."""
    lines = [f"{method} {target} HTTP/1.1"] + [f"{k}: {v}" for k, v in headers]
    text = "\n".join(lines)
    return text + "\n\n" + body if body else text


def fields(features):
    return dataclasses.asdict(features)


class TestDeterminism(unittest.TestCase):
    SAMPLES = [
        "",
        req(target="/search?q=laptop&q=tv", headers=[("Host", "shop.example")]),
        req("POST", "/api/orders", [("Content-Type", "application/json")],
            '{"items": [{"sku": "A-1", "qty": 2}], "note": "café"}'),
        req(target="/p?id=1%27%20OR%20%271%27%3D%271"),
    ]

    def test_same_request_gives_the_same_features(self):
        for text in self.SAMPLES:
            with self.subTest(text=text[:40]):
                self.assertEqual(extract(text), extract(text))

    def test_identical_across_processes_and_hash_seeds(self):
        script = (
            "import dataclasses, json, sys\n"
            f"sys.path.insert(0, {DATA_PLANE_DIR!r})\n"
            "import request_features as rf\n"
            "texts = json.loads(sys.stdin.read())\n"
            "print(json.dumps([dataclasses.asdict(rf.extract_features(t)) for t in texts]))\n"
        )
        expected = [fields(extract(t)) for t in self.SAMPLES]
        for seed in ("0", "1", "12345"):
            with self.subTest(PYTHONHASHSEED=seed):
                out = subprocess.run(
                    [sys.executable, "-c", script], input=json.dumps(self.SAMPLES),
                    capture_output=True, text=True, check=True,
                    env={**os.environ, "PYTHONHASHSEED": seed})
                self.assertEqual(json.loads(out.stdout), expected)

    def test_deep_json_is_classified_the_same_in_any_call_context(self):
        # Python's JSON parser gives up at a nesting depth that depends on the
        # caller's stack (top level vs inside an asyncio task, as in the
        # gateway, vs under nested C calls). Near that depth the features must
        # not depend on where extract_features() is called from.
        def under_c_calls(text, n=50):
            return extract(text) if n == 0 else list(map(lambda t: under_c_calls(t, n - 1), [text]))[0]

        async def in_task(text):
            return extract(text)

        for depth in (9_890, 9_950, 9_994, 9_997, 9_999, 10_005):
            for closed in (True, False):
                body = "[" * depth + ("]" * depth if closed else "")
                text = req("POST", "/x", [("Content-Type", "application/json")], body)
                with self.subTest(depth=depth, closed=closed):
                    top = extract(text)
                    self.assertEqual(asyncio.run(in_task(text)), top)
                    self.assertEqual(under_c_calls(text), top)
                    self.assertEqual(top.body_format, "json_invalid")

    def test_imports_no_model_proxy_or_control_plane_code(self):
        probe = ("import sys\n"
                 f"sys.path.insert(0, {DATA_PLANE_DIR!r})\n"
                 "import request_features, hybrid_contracts\n"
                 "heavy = ('mitmproxy', 'torch', 'transformers', 'fastapi', 'httpx', 'yaml',\n"
                 "         'inference_core', 'classifier_api', 'data_plane')\n"
                 "print(sorted(m for m in heavy if m in sys.modules))\n")
        out = subprocess.run([sys.executable, "-c", probe],
                             capture_output=True, text=True, check=True)
        self.assertEqual(out.stdout.strip(), "[]")


class TestRequestGeneral(unittest.TestCase):
    def test_empty_request(self):
        f = extract("")
        self.assertEqual(f.method, "")
        self.assertEqual(f.body_format, "none")
        self.assertEqual(f.content_type, "")
        self.assertFalse(f.has_body)
        self.assertFalse(f.has_percent_encoding)
        numbers = {k: v for k, v in fields(f).items()
                   if isinstance(v, (int, float)) and not isinstance(v, bool)}
        self.assertTrue(numbers)
        self.assertEqual(set(numbers.values()), {0})
        self.assertEqual(f.schema_version, rf.FEATURE_SCHEMA_VERSION)

    def test_simple_get(self):
        f = extract(req(target="/index.html", headers=[("Host", "shop.example"),
                                                       ("Accept", "*/*")]))
        self.assertEqual(f.method, "GET")
        self.assertEqual((f.path_length, f.query_length, f.body_length), (11, 0, 0))
        self.assertEqual(f.path_depth, 1)
        self.assertEqual(f.total_param_count, 0)
        self.assertFalse(f.has_body)
        # "/index.html": 9 alphanumerics, "/" and "." are the 2 symbols. The
        # "*/*" of the Accept header is not counted: headers are not surface.
        self.assertEqual(f.symbol_count, 2)
        self.assertEqual(f.slash_count, 1)
        self.assertAlmostEqual(f.alnum_ratio, 9 / 11)
        self.assertAlmostEqual(f.symbol_ratio, 2 / 11)

    def test_get_with_query_parameters(self):
        f = extract(req(target="/search?q=laptop&page=2&sort=price"))
        self.assertEqual((f.path_length, f.query_length), (7, 26))
        self.assertEqual((f.query_param_count, f.body_param_count, f.total_param_count),
                         (3, 0, 3))
        self.assertEqual((f.equals_count, f.ampersand_count), (3, 2))
        self.assertEqual(f.repeated_param_name_count, 0)

    def test_post_form(self):
        f = extract(req("POST", "/login", [("Content-Type", FORM)], "user=ana&pass=x"))
        self.assertEqual(f.content_type, FORM)
        self.assertEqual(f.body_format, "form")
        self.assertTrue(f.has_body)
        self.assertEqual(f.body_length, 15)
        self.assertEqual((f.query_param_count, f.body_param_count, f.total_param_count),
                         (0, 2, 2))

    def test_json_body(self):
        body = '{"user": {"name": "ana", "roles": ["a", "b"]}, "items": [{"sku": 1}]}'
        f = extract(req("POST", "/api/users?dry_run=1",
                        [("Content-Type", "application/json")], body))
        self.assertEqual(f.body_format, "json")
        # user, name, roles, items, sku
        self.assertEqual(f.body_param_count, 5)
        self.assertEqual(f.total_param_count, 6)
        # {} > {} > [] is 3 levels; {} > [] > {} is also 3.
        self.assertEqual(f.json_depth, 3)

    def test_empty_body(self):
        f = extract(req("POST", "/submit", [("Content-Type", FORM), ("Content-Length", "0")]))
        self.assertFalse(f.has_body)
        self.assertEqual(f.body_length, 0)
        self.assertEqual(f.body_format, "none")
        self.assertEqual(f.body_param_count, 0)

    def test_repeated_parameters(self):
        f = extract(req(target="/s?a=1&a=2&b=3&c&c"))
        self.assertEqual(f.query_param_count, 5)
        self.assertEqual(f.repeated_param_name_count, 2)       # a and c
        f = extract(req("POST", "/s?id=1", [("Content-Type", FORM)], "id=2&x=1"))
        self.assertEqual(f.repeated_param_name_count, 1)       # id: query and body
        f = extract(req(target="/s?a=1&&b=2&"))
        self.assertEqual(f.query_param_count, 2)               # empty segments are not parameters

    def test_long_path(self):
        path = "/" + "/".join(["segment"] * 200)
        f = extract(req(target=path))
        self.assertEqual(f.path_length, 1600)
        self.assertEqual(f.path_depth, 200)
        self.assertEqual(f.slash_count, 200)
        self.assertEqual(f.query_length, 0)

    def test_common_benign_request(self):
        text = req(target="/products?category=books&page=2", headers=[
            ("Host", "shop.example"), ("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)"),
            ("Accept", "text/html,application/xhtml+xml"), ("Accept-Language", "es-ES,es;q=0.9"),
            ("Cookie", "session=abc123; theme=dark"), ("Referer", "http://shop.example/")])
        f = extract(text)
        self.assertEqual((f.method, f.body_format, f.query_param_count), ("GET", "none", 2))
        self.assertFalse(f.has_percent_encoding)
        # "/", "=", "&", "=": the "?" separating path from query belongs to
        # neither, so it is not part of the surface.
        self.assertEqual(f.symbol_count, 4)
        for name in ("single_quote_count", "double_quote_count", "parenthesis_count",
                     "semicolon_count", "backslash_count", "angle_bracket_count",
                     "pipe_count", "percent_count", "brace_count", "non_ascii_count"):
            self.assertEqual(getattr(f, name), 0, name)


class TestContentTypes(unittest.TestCase):
    def test_json_media_type_variants(self):
        for ct in ("application/json", "application/json; charset=utf-8",
                   "Application/JSON", "application/vnd.api+json"):
            with self.subTest(content_type=ct):
                f = extract(req("POST", "/x", [("Content-Type", ct)], '{"a": 1}'))
                self.assertEqual(f.body_format, "json")
                self.assertEqual(f.body_param_count, 1)
        f = extract(req("POST", "/x", [("Content-Type", "application/json; charset=utf-8")], "{}"))
        self.assertEqual(f.content_type, "application/json")  # parameters dropped

    def test_json_top_level_array_and_scalar(self):
        array = extract(req("POST", "/x", [("Content-Type", "application/json")], "[1, 2, [3]]"))
        self.assertEqual((array.body_format, array.body_param_count, array.json_depth),
                         ("json", 0, 2))
        scalar = extract(req("POST", "/x", [("Content-Type", "application/json")], "42"))
        self.assertEqual((scalar.body_format, scalar.json_depth), ("json", 0))

    def test_duplicate_json_keys_are_members_as_written(self):
        # Like a repeated form parameter (a=1&a=2 -> 2), a repeated JSON key is
        # a member; a dict would silently keep only the last one.
        for body, members in (('{"a": 1, "a": 2}', 2), ('{"o": {"k": 1, "k": 2}, "k": 3}', 4)):
            with self.subTest(body=body):
                f = extract(req("POST", "/x", [("Content-Type", "application/json")], body))
                self.assertEqual((f.body_format, f.body_param_count), ("json", members))

    def test_large_json_integer_is_still_json(self):
        # Valid JSON. Python's int-digit limit (4,300 by default, configurable
        # per process) must not turn it into json_invalid.
        body = '{"n": ' + "9" * 5000 + ', "m": -12}'
        f = extract(req("POST", "/x", [("Content-Type", "application/json")], body))
        self.assertEqual((f.body_format, f.body_param_count, f.json_depth), ("json", 2, 1))

    def test_json_nesting_cap(self):
        cap = rf.MAX_JSON_DEPTH
        at_cap = extract(req("POST", "/x", [("Content-Type", "application/json")],
                             "[" * cap + "]" * cap))
        self.assertEqual((at_cap.body_format, at_cap.json_depth), ("json", cap))
        over = extract(req("POST", "/x", [("Content-Type", "application/json")],
                           "[" * (cap + 1) + "]" * (cap + 1)))
        self.assertEqual((over.body_format, over.json_depth, over.body_param_count),
                         ("json_invalid", 0, 0))

    def test_invalid_json_is_described_not_raised(self):
        for body in ('{"a": ', "not json", "[" * 100_000):
            with self.subTest(body=body[:12]):
                f = extract(req("POST", "/x", [("Content-Type", "application/json")], body))
                self.assertEqual(f.body_format, "json_invalid")
                self.assertEqual((f.body_param_count, f.json_depth), (0, 0))

    def test_other_media_types_are_not_parsed(self):
        for ct in ("text/plain", "multipart/form-data; boundary=x", "application/xml"):
            with self.subTest(content_type=ct):
                f = extract(req("POST", "/x", [("Content-Type", ct)], "a=1&b=2"))
                self.assertEqual(f.body_format, "other")
                self.assertEqual(f.body_param_count, 0)
        f = extract(req("POST", "/x", body="a=1&b=2"))  # no Content-Type at all
        self.assertEqual((f.content_type, f.body_format), ("", "other"))


class TestCharactersAndSyntax(unittest.TestCase):
    def test_percent_encoding(self):
        f = extract(req(target="/p?q=caf%C3%A9%20au%20lait"))
        surface_length = len("/p") + len("q=caf%C3%A9%20au%20lait")
        self.assertEqual(f.percent_encoded_count, 4)
        self.assertTrue(f.has_percent_encoding)
        self.assertAlmostEqual(f.percent_encoded_ratio, 12 / surface_length)
        self.assertEqual(f.percent_count, 4)

    def test_malformed_percent_is_not_an_encoded_character(self):
        f = extract(req(target="/p?a=100%&b=%zz&c=%4"))
        self.assertEqual(f.percent_encoded_count, 0)
        self.assertFalse(f.has_percent_encoding)
        self.assertEqual(f.percent_count, 3)

    def test_patterns_are_not_formed_across_part_boundaries(self):
        # Path, query and body are not adjacent in the request ("?" and the
        # blank line sit between them), so nothing may be matched across them.
        f = extract(req(target="/a%2?0b"))
        self.assertEqual((f.percent_encoded_count, f.has_percent_encoding), (0, False))
        self.assertEqual(extract(req(target="/xa?aa=1")).longest_char_run, 2)
        f = extract(req("POST", "/p?k=bb", [("Content-Type", "text/plain")], "bbb"))
        self.assertEqual(f.longest_char_run, 3)

    def test_counts_are_taken_on_the_text_as_received(self):
        # %27 is an encoded quote: it is counted as encoding, not as a quote.
        f = extract(req(target="/p?id=1%27"))
        self.assertEqual((f.single_quote_count, f.percent_encoded_count), (0, 1))

    def test_each_syntactic_character(self):
        body = "'\"();\\<>|&={}%"
        f = extract(req("POST", "/x", [("Content-Type", "text/plain")], body))
        expected = {
            "single_quote_count": 1, "double_quote_count": 1, "parenthesis_count": 2,
            "semicolon_count": 1, "slash_count": 1, "backslash_count": 1,
            "angle_bracket_count": 2, "pipe_count": 1, "ampersand_count": 1,
            "equals_count": 1, "percent_count": 1, "brace_count": 2,
        }
        self.assertEqual({k: getattr(f, k) for k in expected}, expected)
        self.assertEqual(f.symbol_count, 15)               # 14 in the body + "/" of the path
        self.assertAlmostEqual(f.symbol_ratio, 15 / 16)   # surface "/x" + body

    def test_syntactically_suspicious_structure_is_only_described(self):
        f = extract(req(target="/item?id=1'%20OR%20'1'='1;--<script>alert(1)</script>"))
        self.assertEqual(f.single_quote_count, 4)
        self.assertEqual(f.angle_bracket_count, 4)
        self.assertEqual(f.parenthesis_count, 2)
        self.assertEqual(f.semicolon_count, 1)
        self.assertGreater(f.symbol_ratio, 0.3)
        # Description only. There is nothing to assert about ALLOW/BLOCK.
        self.assertFalse(hasattr(f, "decision"))

    def test_unicode(self):
        body = '{"nombre": "José Ñandú", "ciudad": "東京"}'
        f = extract(req("POST", "/api/perfil", [("Content-Type", "application/json")], body))
        self.assertEqual(f.non_ascii_count, 5)            # é Ñ ú 東 京
        self.assertEqual(f.body_format, "json")
        self.assertEqual(f.body_length, len(body))        # characters, not bytes
        ascii_alnum = sum(ch.isascii() and ch.isalnum() for ch in "/api/perfil" + body)
        self.assertAlmostEqual(f.alnum_ratio, ascii_alnum / len("/api/perfil" + body))

    def test_repeated_characters_and_entropy(self):
        # "X" with no target: the surface is the body alone.
        same = extract("X\n\naaaa")
        self.assertEqual(same.longest_char_run, 4)
        self.assertEqual(same.entropy_bits_per_char, 0.0)
        self.assertEqual(math.copysign(1, same.entropy_bits_per_char), 1.0)  # not -0.0
        mixed = extract("X\n\nabab")
        self.assertEqual(mixed.longest_char_run, 1)
        self.assertAlmostEqual(mixed.entropy_bits_per_char, 1.0)
        self.assertEqual(extract(req(target="/a/....//b")).longest_char_run, 4)


class TestMissingValues(unittest.TestCase):
    def test_partial_request_lines(self):
        self.assertEqual((extract("GET /").method, extract("GET /").path_length), ("GET", 1))
        f = extract("GET /a?x=1")                        # no HTTP version
        self.assertEqual((f.path_length, f.query_param_count), (2, 1))
        f = extract("DELETE")                            # no target either
        self.assertEqual((f.method, f.path_length), ("DELETE", 0))

    def test_malformed_headers_and_body_without_headers(self):
        f = extract("GET /x HTTP/1.1\nheader-without-colon\n: no name")
        self.assertEqual((f.content_type, f.body_format), ("", "none"))
        f = extract("POST /x HTTP/1.1\n\nabc")
        self.assertEqual((f.body_length, f.content_type, f.body_format), (3, "", "other"))

    def test_rejects_non_text(self):
        for value in (None, b"GET / HTTP/1.1"):
            with self.subTest(value=value), self.assertRaises(TypeError):
                extract(value)


class TestMetadataExclusion(unittest.TestCase):
    """D44: Host and User-Agent are never features, directly or indirectly. In
    Phase 1 no header other than Content-Type is read at all."""

    BASE = dict(method="POST", target="/api/search?q=books",
                body='{"q": "books"}')

    def text(self, headers):
        return req(headers=[("Content-Type", "application/json")] + headers, **self.BASE)

    def test_host_and_user_agent_change_nothing(self):
        reference = extract(self.text([("Host", "shop.example"), ("User-Agent", "curl/8.18.0")]))
        variants = [
            [],
            [("Host", "127.0.0.1:9000"), ("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)")],
            [("Host", "a'b\"c<d>%27.test"), ("User-Agent", "sqlmap/1.8 ' OR 1=1 -- ünïcode")],
            [("host", "LOWER.CASE"), ("user-agent", "x" * 5000)],
        ]
        for headers in variants:
            with self.subTest(headers=[k for k, _ in headers]):
                self.assertEqual(extract(self.text(headers)), reference)

    def test_other_headers_are_not_featurized_in_phase_1(self):
        reference = extract(self.text([]))
        for header in (("Cookie", "id=1' OR '1'='1"), ("Referer", "http://evil.test/<x>"),
                       ("Accept", "*/*"), ("X-Forwarded-For", "10.0.0.1")):
            with self.subTest(header=header[0]):
                self.assertEqual(extract(self.text([header])), reference)

    def test_no_field_names_host_agent_or_a_decision(self):
        names = {f.name for f in dataclasses.fields(rf.RequestFeatures)}
        for forbidden in ("host", "agent", "decision", "verdict", "label", "score"):
            self.assertFalse([n for n in names if forbidden in n], forbidden)


class TestContracts(unittest.TestCase):
    def test_decision_output_accepts_only_its_vocabulary(self):
        for decision in ("ALLOW", "BLOCK", "UNCERTAIN"):
            out = contracts.DecisionOutput(decision, 0.5, "reason")
            self.assertEqual(out.decision, decision)
        for bad in ("allow", "MAYBE", "", None):
            with self.subTest(decision=bad), self.assertRaises(ValueError):
                contracts.DecisionOutput(bad, 0.5, "reason")

    def test_decision_confidence_must_be_in_the_unit_interval(self):
        for bad in (-0.01, 1.01, float("nan"), float("inf"), "0.5", True, False, None):
            with self.subTest(confidence=bad), self.assertRaises(ValueError):
                contracts.DecisionOutput("BLOCK", bad, "reason")


class TestAnalyzerOutput(unittest.TestCase):
    """D50: `attack` plus an optional, complete category distribution; no confidence."""

    def categories(self, top="sql_injection", p=0.65):
        rest = (1 - p) / (len(contracts.ANALYZER_CATEGORIES) - 1)
        return {contracts.CATEGORY_PREFIX + c: (p if c == top else rest)
                for c in contracts.ANALYZER_CATEGORIES}

    def test_vocabulary_is_the_frozen_one(self):
        self.assertEqual(contracts.ANALYZER_CATEGORIES,
                         ("sql_injection", "xss", "path_file_access", "command_injection",
                          "ssti", "open_redirect", "ssrf", "other_attack"))

    def test_no_global_confidence(self):
        names = {f.name for f in dataclasses.fields(contracts.AnalyzerOutput)}
        self.assertEqual(names, {"signals", "analyzer_version"})

    def test_attack_alone_or_with_a_full_category_distribution(self):
        self.assertEqual(contracts.AnalyzerOutput({"attack": 0.12}, "a").signals["attack"], 0.12)
        out = contracts.AnalyzerOutput({"attack": 0.94, **self.categories()}, "a")
        self.assertAlmostEqual(sum(v for k, v in out.signals.items() if k != "attack"), 1.0)

    def test_attack_is_required_and_a_probability(self):
        with self.assertRaises(ValueError):
            contracts.AnalyzerOutput(self.categories(), "a")
        for bad in (-0.01, 1.01, float("nan"), float("inf"), "0.5", True, None):
            with self.subTest(attack=bad), self.assertRaises(ValueError):
                contracts.AnalyzerOutput({"attack": bad}, "a")

    def test_unknown_signals_are_rejected(self):
        for key in ("confidence", "category:jwt", "category:path_traversal", "sqli"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                contracts.AnalyzerOutput({"attack": 0.5, key: 0.1}, "a")

    def test_category_distribution_must_be_complete_and_sum_to_one(self):
        partial = dict(list(self.categories().items())[:3])
        with self.assertRaises(ValueError):
            contracts.AnalyzerOutput({"attack": 0.9, **partial}, "a")
        skewed = self.categories()
        skewed["category:xss"] += 0.01
        with self.assertRaises(ValueError):
            contracts.AnalyzerOutput({"attack": 0.9, **skewed}, "a")
        negative = self.categories(p=1.2)
        with self.assertRaises(ValueError):
            contracts.AnalyzerOutput({"attack": 0.9, **negative}, "a")

    def test_decision_input_joins_features_and_analysis(self):
        features = extract(req())
        analysis = contracts.AnalyzerOutput({"attack": 0.0}, "analyzer-x")
        joined = contracts.DecisionInput(features, analysis)
        self.assertIs(joined.features, features)
        self.assertIs(joined.analysis, analysis)

    def test_contracts_are_immutable(self):
        out = contracts.DecisionOutput("ALLOW", 1.0, "r")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            out.decision = "BLOCK"
        with self.assertRaises(dataclasses.FrozenInstanceError):
            extract(req()).method = "POST"


if __name__ == "__main__":
    unittest.main()
