"""Fast Path eligibility (data_plane/fast_path.py), SHADOW ONLY.

Standard library only; runs in either environment:
    python3 -m unittest discover -s tests -p 'test_fast_path.py' -v

Test-only values: the Limits below (`max_decoded_body`, `token_budget`) are fixtures so that a
canonical-request/v1 result can be built in a test. They are NOT proposed gateway values; those
are PENDING in V5-DATA-SPEC-r3 §11.2. The policy in tests/fixtures is an EXAMPLE for tests, not
a deployable policy.
"""

import json
import os
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "data_plane"))

import canonical_request as cr  # noqa: E402
import fast_path as fp  # noqa: E402

POLICY_PATH = os.path.join(REPO_ROOT, "tests", "fixtures", "fast_path_policy_example.json")
TEST_LIMITS = cr.Limits(max_decoded_body=1_000_000, token_budget=10_000, max_bytes_per_token=48)
HOST = ("Host", "shop.example")
VERIFIED = fp.FramingEvidence(fp.FRAMING_VERIFIED, "test fixture")


def policy():
    return fp.load_policy(POLICY_PATH)


def make(method="GET", target="/api/items/42", headers=(HOST,), body=b"", version="HTTP/1.1",
         framing=VERIFIED, canonical="auto", limits=TEST_LIMITS):
    """A FastPathInput whose canonical result is the real canonicalize() of the same parts."""
    raw_headers = tuple((n.encode("latin-1"), v.encode("latin-1")) for n, v in headers)
    m, t = method.encode(), target.encode("utf-8") if isinstance(target, str) else target
    if canonical == "auto":
        canonical = cr.canonicalize(
            cr.RequestParts(method=m, target=t, http_version=version, headers=raw_headers,
                            body=body), limits)
    return fp.FastPathInput(method=m, target=t, http_version=version, headers=raw_headers,
                            body=body, canonical=canonical, framing=framing)


class Base(unittest.TestCase):
    def setUp(self):
        self.policy = policy()

    def decide(self, **kw):
        return fp.evaluate(make(**kw), self.policy)

    def assertContinue(self, decision, *reasons):
        self.assertEqual(decision.decision, fp.CONTINUE, decision)
        for r in reasons:
            self.assertIn(r, decision.reasons, decision)
        self.assertFalse(decision.enforced)

    def assertAllow(self, decision, rule_id=None):
        self.assertEqual(decision.decision, fp.FAST_ALLOW, decision)
        self.assertEqual(decision.reasons, ())
        self.assertFalse(decision.enforced)
        if rule_id:
            self.assertEqual(decision.rule_id, rule_id)


class TestEligible(Base):
    def test_item_request_matches_a_rule(self):
        d = self.decide()
        self.assertAllow(d, "item-by-id")
        self.assertEqual(d.policy_status, "PROPOSED")
        self.assertEqual(d.policy_sha256, self.policy.sha256)

    def test_head_and_query_with_declared_grammar(self):
        self.assertAllow(self.decide(method="HEAD", target="/api/items/7?lang=es&page=3"),
                         "item-by-id")

    def test_second_rule_and_header_case_and_ows(self):
        self.assertAllow(self.decide(target="/healthz", headers=(("HOST", "shop.example"),)),
                         "health")
        self.assertAllow(self.decide(headers=(("host", "  shop.example "),)), "item-by-id")

    def test_uint_boundaries(self):
        self.assertAllow(self.decide(target="/api/items/0"))
        self.assertAllow(self.decide(target="/api/items/999999"))

    def test_decision_is_deterministic(self):
        self.assertEqual(self.decide(), self.decide())


class TestPrerequisites(Base):
    """Protocol validation first: unmet prerequisites are all reported, rules are not consulted."""

    def test_no_policy(self):
        d = fp.evaluate(make(), None)
        self.assertContinue(d, "POLICY_UNAVAILABLE")

    def test_framing_unavailable_and_unverified(self):
        self.assertContinue(self.decide(framing=fp.FramingEvidence()), "FRAMING_UNAVAILABLE")
        self.assertContinue(self.decide(framing=fp.FramingEvidence(fp.FRAMING_UNVERIFIED)),
                            "FRAMING_UNVERIFIED")

    def test_canonical_unavailable(self):
        self.assertContinue(self.decide(canonical=None), "CANONICAL_UNAVAILABLE")

    def test_canonical_reject_and_unsupported(self):
        framing_conflict = make(headers=(HOST, ("Transfer-Encoding", "chunked"),
                                         ("Content-Length", "0")))
        self.assertEqual(framing_conflict.canonical.outcome, cr.REJECT)
        self.assertContinue(fp.evaluate(framing_conflict, self.policy), "CANONICAL_NOT_ACCEPTED")
        connect = make(method="CONNECT", target="shop.example:443")
        self.assertEqual(connect.canonical.outcome, cr.UNSUPPORTED)
        self.assertContinue(fp.evaluate(connect, self.policy), "CANONICAL_NOT_ACCEPTED")

    def test_all_unmet_prerequisites_are_reported_together(self):
        d = fp.evaluate(make(framing=fp.FramingEvidence(), canonical=None), None)
        self.assertEqual(d.reasons, ("POLICY_UNAVAILABLE", "FRAMING_UNAVAILABLE",
                                     "CANONICAL_UNAVAILABLE"))

    def test_rules_are_not_evaluated_before_prerequisites(self):
        # A request that matches a rule perfectly still yields only prerequisite reasons.
        d = self.decide(framing=fp.FramingEvidence())
        self.assertEqual(d.reasons, ("FRAMING_UNAVAILABLE",))
        self.assertNotIn("NO_RULE_MATCHED", d.reasons)

    def test_a_canonical_result_for_another_request_is_refused(self):
        other = make(target="/healthz").canonical
        self.assertContinue(self.decide(canonical=other), "CANONICAL_MISMATCH")


class TestExclusions(Base):
    def reasons(self, **kw):
        return dict(fp.match_reasons(make(**kw), self.policy))

    def test_unknown_path_and_absence_of_suspicion_is_not_enough(self):
        # Nothing about this request looks suspicious. There is no rule for it: CONTINUE.
        d = self.decide(target="/search?q=laptop")
        self.assertContinue(d, "NO_RULE_MATCHED")

    def test_method_not_in_rule(self):
        for method in ("POST", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE"):
            self.assertContinue(self.decide(method=method), "NO_RULE_MATCHED")

    def test_body_present(self):
        # No Content-Type with a body: the canonical layer already signals S-CT-ABSENT.
        self.assertContinue(self.decide(headers=(HOST, ("Content-Length", "2")), body=b"{}"))
        self.assertContinue(self.decide(headers=(HOST, ("Content-Type", "application/json"),
                                                 ("Content-Length", "2")), body=b"{}"))
        self.assertEqual(self.reasons(body=b"x")["item-by-id"], "BODY_PRESENT")

    def test_percent_encoding_fragment_and_dot_segments(self):
        self.assertEqual(self.reasons(target="/api/items/4%32")["item-by-id"],
                         "PERCENT_ENCODING_PRESENT")
        self.assertEqual(self.reasons(target="/api/items/42#x")["item-by-id"],
                         "FRAGMENT_PRESENT")
        for target in ("/api/items/../items/42", "/api/./items/42", "//api/items/42",
                       "/api/items/42/", "/api//items/42", "/API/items/42"):
            self.assertContinue(self.decide(target=target), "NO_RULE_MATCHED")

    def test_uint_grammar_edges(self):
        for value in ("007", "1234567", "+1", "-1", "1.5", "", "0x10", "1e3", " 1"):
            self.assertContinue(self.decide(target=f"/api/items/{value}"))

    def test_non_ascii_and_control_bytes_in_target(self):
        # The canonical layer signals or rejects these first; either way the answer is CONTINUE.
        self.assertContinue(self.decide(target="/api/items/١٢"), "SIGNALS_PRESENT")
        self.assertContinue(self.decide(target=b"/api/items/\xff"))
        self.assertContinue(self.decide(target=b"/api/items/4\x002"), "CANONICAL_NOT_ACCEPTED")
        self.assertContinue(self.decide(target=b"/api/items/4 2"), "CANONICAL_NOT_ACCEPTED")
        # Independently of the canonical layer, the policy matcher refuses them too.
        for target in ("/api/items/١٢".encode(), b"/api/items/\xff", b"/api/items/4\x002"):
            self.assertEqual(self.reasons(target=target)["item-by-id"], "TARGET_MALFORMED")

    def test_target_forms_other_than_origin(self):
        absolute = self.decide(target="http://shop.example/healthz")
        self.assertContinue(absolute, "TARGET_FORM_NOT_ORIGIN")
        self.assertContinue(self.decide(method="OPTIONS", target="*"), "TARGET_FORM_NOT_ORIGIN")
        self.assertEqual(self.reasons(target="healthz")["health"], "TARGET_NOT_ORIGIN_FORM")

    def test_query_strictness(self):
        cases = {
            "/api/items/42?": "QUERY_MALFORMED",
            "/api/items/42?lang": "QUERY_MALFORMED",
            "/api/items/42?lang=": "QUERY_VALUE_NOT_ALLOWED",
            "/api/items/42?lang=en=es": "QUERY_MALFORMED",
            "/api/items/42?=en": "QUERY_MALFORMED",
            "/api/items/42?lang=en&": "QUERY_MALFORMED",
            "/api/items/42?lang=en&lang=es": "QUERY_PARAM_REPEATED",
            "/api/items/42?x=1": "QUERY_PARAM_UNKNOWN",
            "/api/items/42?lang=fr": "QUERY_VALUE_NOT_ALLOWED",
            "/api/items/42?lang=EN": "QUERY_VALUE_NOT_ALLOWED",
            "/api/items/42?page=1000": "QUERY_VALUE_NOT_ALLOWED",
            "/api/items/42?lang=en;page=1": "QUERY_MALFORMED",
        }
        for target, reason in cases.items():
            self.assertEqual(self.reasons(target=target)["item-by-id"], reason, target)
            self.assertContinue(self.decide(target=target), "NO_RULE_MATCHED")

    def test_headers_must_be_listed_with_a_declared_value(self):
        extra = {
            "unlisted header": (HOST, ("User-Agent", "curl/8")),
            "cookie": (HOST, ("Cookie", "a=b")),
            "referer": (HOST, ("Referer", "http://evil.example/")),
            "x-forwarded-for": (HOST, ("X-Forwarded-For", "127.0.0.1")),
            "content-length": (HOST, ("Content-Length", "0")),
        }
        for label, headers in extra.items():
            self.assertContinue(self.decide(headers=headers), "NO_RULE_MATCHED")
            self.assertEqual(self.reasons(headers=headers)["item-by-id"], "HEADER_NOT_ALLOWED",
                             label)
        self.assertEqual(self.reasons(headers=(("Host", "evil.example"),))["item-by-id"],
                         "HEADER_VALUE_NOT_ALLOWED")
        self.assertEqual(self.reasons(headers=(HOST, HOST))["item-by-id"], "HEADER_REPEATED")
        self.assertEqual(self.reasons(headers=(("Host", "shop.example:80"),))["item-by-id"],
                         "HEADER_VALUE_NOT_ALLOWED")

    def test_framing_headers_are_excluded_by_the_canonical_result(self):
        for headers in ((HOST, ("Transfer-Encoding", "chunked")),
                        (HOST, ("Transfer-Encoding", "identity")),
                        (HOST, ("Content-Encoding", "gzip"))):
            d = self.decide(headers=headers)
            self.assertContinue(d)
            self.assertNotEqual(d.decision, fp.FAST_ALLOW)

    def test_content_type_outside_scope_is_excluded(self):
        d = self.decide(headers=(HOST, ("Content-Type", "application/xml")))
        self.assertContinue(d)       # canonical signal S-MEDIA-UNSUPPORTED and not a listed header

    def test_header_injection_bytes_are_rejected_by_the_canonical_layer(self):
        d = self.decide(headers=(HOST, ("X-A", "b\r\nHost: evil")))
        self.assertContinue(d, "CANONICAL_NOT_ACCEPTED")

    def test_http_version(self):
        self.assertContinue(self.decide(version="HTTP/1.0"))
        self.assertContinue(self.decide(version="HTTP/2.0"))   # not in this policy's versions

    def test_size_must_be_within_budget(self):
        unchecked = cr.Limits(max_decoded_body=1_000_000)
        self.assertContinue(self.decide(limits=unchecked), "SIZE_NOT_WITHIN_BUDGET")


class TestMalformedAndAmbiguousInputs(Base):
    def test_wrong_types_are_programming_errors_for_the_input_type(self):
        with self.assertRaises(TypeError):
            fp.FastPathInput(method="GET", target=b"/", http_version="HTTP/1.1", headers=(),
                             body=b"", canonical=None)
        with self.assertRaises(TypeError):
            fp.FastPathInput(method=b"GET", target=b"/", http_version="HTTP/1.1",
                             headers=(("Host", "x"),), body=b"", canonical=None)

    def test_safe_evaluate_never_raises(self):
        for bad in (None, object(), "GET /", 42):
            d = fp.safe_evaluate(bad, self.policy)
            self.assertContinue(d, "EVALUATION_ERROR")

    def test_odd_requests_do_not_crash(self):
        for target in (b"", b"/", b"?", b"/?", b"/" + b"a" * 100_000, b"/\xc3\x28"):
            self.assertContinue(self.decide(target=target))
        for method in ("", "G ET", "GET\n"):
            self.assertContinue(fp.safe_evaluate(
                make(method=method.encode() if False else method), self.policy))

    def test_header_name_and_value_oddities(self):
        for headers in ((("Ho st", "shop.example"),), ((" Host", "shop.example"),),
                        (("Host", "shop.example\t"),), (("Host", "shop.exämple"),),
                        (("", "shop.example"),)):
            self.assertContinue(self.decide(headers=headers))

    def test_every_reason_is_in_the_closed_list(self):
        probes = [make(), make(method="POST"), make(canonical=None), make(target="/x?y"),
                  make(headers=(("A", "b"),)), make(framing=fp.FramingEvidence())]
        for inp in probes:
            for pol in (self.policy, None):
                d = fp.safe_evaluate(inp, pol)
                self.assertIn(d.decision, fp.DECISIONS)
                self.assertTrue(set(d.reasons) <= set(fp.REASONS))


class TestIndependenceFromTheContractModule(unittest.TestCase):
    """The gateway must not import canonical_request (D56) and fast_path.py is loaded by it."""

    def test_constants_match_the_contract(self):
        self.assertEqual(fp.CANONICAL_CONTRACT_ID, cr.CONTRACT_ID)
        self.assertEqual(fp.CANONICAL_ACCEPT, cr.ACCEPT)
        self.assertEqual(fp.CANONICAL_SIZE_WITHIN, cr.SIZE_WITHIN)

    def test_fast_path_does_not_import_the_contract(self):
        import ast
        with open(fp.__file__, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                names.add(node.module.split(".")[0])
        self.assertTrue(names <= set(sys.stdlib_module_names), names)
        self.assertNotIn("canonical_request", names)


class TestDecisionContract(unittest.TestCase):
    def test_no_block_exists(self):
        self.assertEqual(fp.DECISIONS, ("FAST_ALLOW", "CONTINUE"))
        with self.assertRaises(ValueError):
            fp.FastPathDecision("BLOCK", ("NO_RULE_MATCHED",))
        with self.assertRaises(ValueError):
            fp.FastPathDecision("ALLOW")

    def test_shadow_only(self):
        with self.assertRaises(ValueError):
            fp.FastPathDecision(fp.FAST_ALLOW, rule_id="r", enforced=True)

    def test_shape_rules(self):
        with self.assertRaises(ValueError):
            fp.FastPathDecision(fp.FAST_ALLOW)                       # needs a rule id
        with self.assertRaises(ValueError):
            fp.FastPathDecision(fp.FAST_ALLOW, ("NO_RULE_MATCHED",), rule_id="r")
        with self.assertRaises(ValueError):
            fp.FastPathDecision(fp.CONTINUE)                         # needs a reason
        with self.assertRaises(ValueError):
            fp.FastPathDecision(fp.CONTINUE, ("MADE_UP",))

    def test_framing_status_is_closed(self):
        with self.assertRaises(ValueError):
            fp.FramingEvidence("MAYBE")

    def test_module_has_no_score_or_threshold(self):
        public = [n for n in dir(fp) if not n.startswith("_")]
        for name in public:
            self.assertNotIn("score", name.lower())
            self.assertNotIn("threshold", name.lower())
            self.assertNotIn("weight", name.lower())


class TestPolicyValidation(unittest.TestCase):
    def doc(self):
        with open(POLICY_PATH, encoding="utf-8") as fh:
            return json.load(fh)

    def assertRejected(self, mutate):
        doc = self.doc()
        mutate(doc)
        with self.assertRaises(fp.PolicyError):
            fp.parse_policy(doc)

    def test_example_loads_and_hash_is_stable(self):
        a, b = fp.load_policy(POLICY_PATH), fp.load_policy(POLICY_PATH)
        self.assertEqual(a.sha256, b.sha256)
        self.assertEqual(len(a.rules), 2)

    def test_hash_changes_with_content(self):
        doc = self.doc()
        doc["rules"][1]["headers"]["host"]["values"] = ["other.example"]
        self.assertNotEqual(fp.parse_policy(doc).sha256, fp.load_policy(POLICY_PATH).sha256)

    def test_rejections(self):
        self.assertRejected(lambda d: d.update(extra=1))
        self.assertRejected(lambda d: d.update(schema="x"))
        self.assertRejected(lambda d: d.update(canonical_contract="canonical-request/v2"))
        self.assertRejected(lambda d: d.update(status="DRAFT"))
        self.assertRejected(lambda d: d.update(status="APPROVED"))      # no approval record
        self.assertRejected(lambda d: d.update(rules=[]))
        self.assertRejected(lambda d: d.update(http_versions=["HTTP/3"]))
        self.assertRejected(lambda d: d["rules"][0].update(methods=["POST"]))
        self.assertRejected(lambda d: d["rules"][0].update(methods=[]))
        self.assertRejected(lambda d: d["rules"][0].update(id=d["rules"][1]["id"]))
        self.assertRejected(lambda d: d["rules"][0]["path"].append(".."))
        self.assertRejected(lambda d: d["rules"][0]["path"].append("a/b"))
        self.assertRejected(lambda d: d["rules"][0]["path"].append({"type": "regex", "p": ".*"}))
        self.assertRejected(lambda d: d["rules"][0]["path"].append(
            {"type": "uint", "max_digits": 10}))
        self.assertRejected(lambda d: d["rules"][0]["path"].append(
            {"type": "uint", "max_digits": True}))
        self.assertRejected(lambda d: d["rules"][0]["query"].update(
            z={"type": "enum", "values": []}))
        self.assertRejected(lambda d: d["rules"][0]["query"].update(
            z={"type": "enum", "values": ["a%20b"]}))
        self.assertRejected(lambda d: d["rules"][0]["query"].update(
            z={"type": "enum", "values": ["a&b"]}))
        self.assertRejected(lambda d: d["rules"][0].update(required_query=["undeclared"]))
        for header in ("Transfer-Encoding", "content-encoding", "Upgrade", "Expect", "TE"):
            self.assertRejected(lambda d, h=header: d["rules"][0]["headers"].update(
                {h: {"type": "enum", "values": ["x"]}}))
        self.assertRejected(lambda d: d["rules"][0]["headers"].update(
            {"Host": {"type": "enum", "values": ["a"]}}))                 # repeats after lowering

    def test_approved_needs_a_complete_approval_record(self):
        doc = self.doc()
        doc["status"] = "APPROVED"
        doc["approval"] = {"approved_by": "owner", "date": "2026-10-20", "decision_ref": "D-x"}
        self.assertEqual(fp.parse_policy(doc).status, "APPROVED")
        doc["approval"]["date"] = " "
        with self.assertRaises(fp.PolicyError):
            fp.parse_policy(doc)

    def test_unreadable_policy(self):
        with self.assertRaises(OSError):
            fp.load_policy(os.path.join(REPO_ROOT, "tests", "fixtures", "missing.json"))
        with self.assertRaises(fp.PolicyError):
            fp.load_policy(os.path.join(REPO_ROOT, "tests", "test_fast_path.py"))


if __name__ == "__main__":
    unittest.main()
