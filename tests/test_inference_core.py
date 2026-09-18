"""Contract tests for the shared V4 inference core.

No model is loaded here: everything under test is pure string handling — the
decision contract, the prompt template and the parser. These are the pieces
that must never differ between evaluation and runtime.

Run:  python3.12 -m unittest discover -s tests -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "control_plane"))

import inference_core as core


class TestParsePrediction(unittest.TestCase):
    """The frozen E4/E5 parsing policy."""

    def test_valid_allow(self):
        self.assertEqual(
            core.parse_prediction("ALLOW | Normal HTTP request with no attack patterns detected."),
            ("ALLOW", "Normal HTTP request with no attack patterns detected", "ok"),
        )

    def test_valid_block(self):
        self.assertEqual(
            core.parse_prediction("BLOCK | SQL injection payload detected."),
            ("BLOCK", "SQL injection payload detected", "ok"),
        )

    def test_surrounding_whitespace_is_tolerated(self):
        self.assertEqual(
            core.parse_prediction("  BLOCK |   Path traversal attack detected.  "),
            ("BLOCK", "Path traversal attack detected", "ok"),
        )

    def test_missing_trailing_period(self):
        self.assertEqual(
            core.parse_prediction("BLOCK | no period here"),
            ("BLOCK", "no period here", "ok"),
        )

    def test_continuation_after_reason_is_ignored(self):
        self.assertEqual(
            core.parse_prediction("BLOCK | XSS detected. trailing rambling"),
            ("BLOCK", "XSS detected", "ok"),
        )

    def test_lowercase_decision_is_not_accepted(self):
        # The contract is uppercase. Accepting "allow" would silently widen it.
        self.assertEqual(core.parse_prediction("allow | looks benign."), (None, None, "invalid"))

    def test_garbage_is_invalid(self):
        self.assertEqual(core.parse_prediction("total garbage, no contract"), (None, None, "invalid"))

    def test_empty_is_invalid(self):
        self.assertEqual(core.parse_prediction(""), (None, None, "invalid"))

    def test_none_is_invalid(self):
        self.assertEqual(core.parse_prediction(None), (None, None, "invalid"))

    def test_decision_without_pipe_is_invalid(self):
        self.assertEqual(core.parse_prediction("BLOCK SQL injection detected."), (None, None, "invalid"))

    def test_invalid_output_is_never_coerced(self):
        """The security-critical property: no unparseable output becomes a
        decision — least of all ALLOW."""
        for text in ["", None, "total garbage", "I think this request is fine",
                     "the payload looks like it should be allowed", "ALLOWED without pipe",
                     "maybe block it?"]:
            decision, reason, status = core.parse_prediction(text)
            self.assertEqual(status, "invalid", f"{text!r} should be invalid")
            self.assertIsNone(decision, f"{text!r} produced a decision")
            self.assertIsNone(reason, f"{text!r} produced a reason")
            self.assertNotEqual(decision, "ALLOW")


class TestBuildPrompt(unittest.TestCase):
    """The prompt must match training (finetune.py:format_example) exactly,
    minus the answer the model is asked to produce."""

    def test_matches_training_template(self):
        req = "GET /index.html HTTP/1.1\nHost: example.com"
        expected = (f"<|system|>\n{core.INSTRUCTION}</s>\n"
                    f"<|user|>\n{req}</s>\n"
                    f"<|assistant|>\n")
        self.assertEqual(core.build_prompt(req), expected)

    def test_request_text_is_embedded_verbatim(self):
        req = "POST /a?b=1' OR '1'='1 HTTP/1.1\r\nHost: t.com\r\n\r\nbody|with|pipes"
        self.assertIn(req, core.build_prompt(req))

    def test_ends_with_assistant_turn(self):
        self.assertTrue(core.build_prompt("x").endswith("<|assistant|>\n"))


class TestNormalizeReason(unittest.TestCase):
    def test_case_space_and_period_invariance(self):
        self.assertEqual(
            core.normalize_reason("  SQL Injection   Payload Detected. "),
            core.normalize_reason("sql injection payload detected"),
        )

    def test_distinct_reasons_stay_distinct(self):
        self.assertNotEqual(
            core.normalize_reason("SQL injection payload detected."),
            core.normalize_reason("Cross-site scripting payload detected."),
        )

    def test_none_becomes_empty(self):
        self.assertEqual(core.normalize_reason(None), "")


class TestRuntimeConfig(unittest.TestCase):
    """Guards on the settings the V4 baseline was measured under."""

    def test_default_adapter_is_v4_clean(self):
        self.assertTrue(core.DEFAULT_ADAPTER_DIR.endswith("model-output-v4-clean"),
                        f"unexpected default adapter: {core.DEFAULT_ADAPTER_DIR}")

    def test_default_adapter_is_not_the_absent_v3(self):
        self.assertNotIn("model-output-v3", core.DEFAULT_ADAPTER_DIR)

    def test_generation_bound_unchanged(self):
        self.assertEqual(core.MAX_NEW_TOKENS, 40)

    def test_base_model_unchanged(self):
        self.assertEqual(core.BASE_MODEL, "TinyLlama/TinyLlama-1.1B-Chat-v1.0")


if __name__ == "__main__":
    unittest.main()
