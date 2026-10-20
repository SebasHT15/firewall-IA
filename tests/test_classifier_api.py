"""Control-plane HTTP tests.

The heavy model is never loaded: `inference_core.classify_timed` (the function
the endpoint calls; it carries the EOS termination signal) is replaced with
a stub that returns a canned decoder output, and `app.state` is populated by
hand. That keeps these tests fast while still exercising the real endpoint
code, the real schemas and the real parser.

`TestClient` is deliberately NOT used as a context manager, so the lifespan —
and therefore the real model load — does not run.

Run:  python3.12 -m unittest discover -s tests -v
"""

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "control_plane"))

from fastapi.testclient import TestClient

import classifier_api
import inference_core as core

client = TestClient(classifier_api.app)

BENIGN = "GET /index.html HTTP/1.1\nHost: example.com"
ATTACK = "GET /api/users?id=1' OR '1'='1 HTTP/1.1\nHost: target.com"


def fake_inference(raw_output, latency_ms=12.5, ended_with_eos=True):
    """Stand in for core.classify_timed, returning a canned decoder output and
    the measure dict (only the keys the endpoint reads)."""
    measure = {"generate_ms": latency_ms, "ended_with_eos": ended_with_eos}
    return lambda tok, mdl, request, device, **kw: (raw_output, dict(measure))


class ModelLoadedTestCase(unittest.TestCase):
    """Base: pretend the model finished loading, without loading it."""

    def setUp(self):
        classifier_api.app.state.tokenizer = object()
        classifier_api.app.state.model = object()
        classifier_api.app.state.device = "cpu"

    def tearDown(self):
        classifier_api.app.state.tokenizer = None
        classifier_api.app.state.model = None
        classifier_api.app.state.device = None


class TestHealth(ModelLoadedTestCase):
    def test_health_reports_loaded_model(self):
        r = client.get("/health")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["status"], "ok")
        self.assertTrue(body["model_loaded"])
        self.assertTrue(body["adapter_dir"].endswith("model-output-v4-clean"))

    def test_health_reports_unloaded_model(self):
        classifier_api.app.state.model = None
        r = client.get("/health")
        self.assertEqual(r.status_code, 200)      # process is up ...
        self.assertFalse(r.json()["model_loaded"])  # ... but not ready


class TestClassifyValid(ModelLoadedTestCase):
    def test_allow(self):
        with patch.object(core, "classify_timed",
                          fake_inference("ALLOW | Normal HTTP request with no attack patterns detected.")):
            r = client.post("/classify", json={"request": BENIGN})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), {
            "status": "ok",
            "decision": "ALLOW",
            "reason": "Normal HTTP request with no attack patterns detected",
            "model_latency_ms": 12.5,
        })

    def test_block(self):
        with patch.object(core, "classify_timed",
                          fake_inference("BLOCK | SQL injection payload detected.")):
            r = client.post("/classify", json={"request": ATTACK})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), {
            "status": "ok",
            "decision": "BLOCK",
            "reason": "SQL injection payload detected",
            "model_latency_ms": 12.5,
        })

    def test_latency_is_reported_from_the_core(self):
        with patch.object(core, "classify_timed",
                          fake_inference("ALLOW | fine.", latency_ms=234.5)):
            r = client.post("/classify", json={"request": BENIGN})
        self.assertAlmostEqual(r.json()["model_latency_ms"], 234.5)


class TestClassifyInvalidOutput(ModelLoadedTestCase):
    """§3.3 — an unparseable model output is reported, never coerced."""

    def test_invalid_output_reported_explicitly(self):
        with patch.object(core, "classify_timed", fake_inference("total garbage, no contract")):
            r = client.post("/classify", json={"request": BENIGN})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), {
            "status": "invalid",
            "decision": None,
            "reason": None,
            "model_latency_ms": 12.5,
        })

    def test_invalid_output_is_never_silently_allowed(self):
        """The security-critical regression test. A model output that cannot be
        parsed must never reach the caller as ALLOW."""
        garbage = [
            "",
            "total garbage",
            "I think this request is fine",
            "the payload looks like it should be allowed",
            "ALLOWED without a pipe",
            "allow | lowercase is not the contract.",
            "Sure! Here is my analysis of the request:",
        ]
        for text in garbage:
            with patch.object(core, "classify_timed", fake_inference(text)):
                r = client.post("/classify", json={"request": BENIGN})
            body = r.json()
            self.assertEqual(r.status_code, 200, text)
            self.assertEqual(body["status"], "invalid", f"{text!r} was not flagged invalid")
            self.assertIsNone(body["decision"], f"{text!r} produced a decision")
            self.assertNotEqual(body["decision"], "ALLOW", f"{text!r} became ALLOW")

    def test_the_word_allow_in_prose_does_not_become_a_decision(self):
        """Guards against the legacy `if 'BLOCK' in output else ALLOW` shape."""
        with patch.object(core, "classify_timed",
                          fake_inference("This request does not contain BLOCK-worthy payloads")):
            r = client.post("/classify", json={"request": BENIGN})
        self.assertEqual(r.json()["status"], "invalid")
        self.assertIsNone(r.json()["decision"])


class TestTruncatedGenerationIsNeverAllow(ModelLoadedTestCase):
    """A generation that stopped on the token cap (no native EOS) is incomplete.
    `EXTRACT_RE` ends in `$`, so the text alone still parses as a decision;
    the endpoint must use the termination signal and report `invalid`."""

    def _post(self, text, **kw):
        with patch.object(core, "classify_timed", fake_inference(text, **kw)):
            return client.post("/classify", json={"request": BENIGN})

    def test_truncated_allow_is_invalid_not_allow(self):
        r = self._post("ALLOW | Normal HTTP request with no attack patterns",
                       ended_with_eos=False)
        body = r.json()
        self.assertEqual(r.status_code, 200)
        self.assertEqual(body["status"], "invalid")
        self.assertIsNone(body["decision"])
        self.assertIsNone(body["reason"])

    def test_truncated_one_character_allow_is_invalid(self):
        self.assertEqual(self._post("ALLOW | N", ended_with_eos=False).json()["status"], "invalid")

    def test_truncated_block_is_invalid_too(self):
        # Not a safety hole (the data plane blocks both), but one rule for every cut:
        # no decision is taken from a generation that did not finish.
        body = self._post("BLOCK | SQL injection payload", ended_with_eos=False).json()
        self.assertEqual((body["status"], body["decision"]), ("invalid", None))

    def test_missing_termination_flag_fails_closed(self):
        def no_flag(tok, mdl, request, device, **kw):
            return "ALLOW | Normal HTTP request with no attack patterns detected.", {"generate_ms": 1.0}
        with patch.object(core, "classify_timed", no_flag):
            r = client.post("/classify", json={"request": BENIGN})
        self.assertEqual(r.status_code, 500)       # KeyError -> "Inference failed" -> data plane blocks
        self.assertNotIn("ALLOW", r.text)

    def test_non_boolean_termination_flag_fails_closed(self):
        body = self._post("ALLOW | Normal HTTP request with no attack patterns detected.",
                          ended_with_eos="yes").json()
        self.assertEqual((body["status"], body["decision"]), ("invalid", None))

    def test_complete_generation_is_unchanged(self):
        allow = self._post("ALLOW | Normal HTTP request with no attack patterns detected.",
                           ended_with_eos=True).json()
        block = self._post("BLOCK | SQL injection payload detected.", ended_with_eos=True).json()
        self.assertEqual((allow["status"], allow["decision"]), ("ok", "ALLOW"))
        self.assertEqual((block["status"], block["decision"]), ("ok", "BLOCK"))

    def test_end_to_end_through_the_real_generation_path(self):
        """No stub on classify_timed: a model that never emits EOS (token cap)
        and decodes to an ALLOW-looking text must come out invalid."""
        torch = __import__("torch")

        class Tok:
            eos_token_id = 2
            def __call__(self, prompt, return_tensors=None):
                class B(dict):
                    def to(self, d): return self
                return B(input_ids=torch.tensor([[1] * 7]))
            def decode(self, ids, skip_special_tokens=False):
                return "ALLOW | Normal HTTP request with no attack patterns"

        class Mdl:
            def __init__(self, tail): self.tail = tail
            def generate(self, **kw):
                n = kw["input_ids"].shape[1]
                return torch.tensor([[1] * n + [5] * (kw["max_new_tokens"] - len(self.tail)) + self.tail])

        classifier_api.app.state.tokenizer = Tok()
        classifier_api.app.state.device = "cpu"
        for tail, want in (([], ("invalid", None)),            # 40 tokens, no EOS: truncated
                           ([2], ("ok", "ALLOW"))):            # EOS is the 40th token: complete
            classifier_api.app.state.model = Mdl(tail)
            body = client.post("/classify", json={"request": BENIGN}).json()
            self.assertEqual((body["status"], body["decision"]), want, tail)


class TestErrorHandling(ModelLoadedTestCase):
    def test_model_not_loaded_returns_503(self):
        classifier_api.app.state.model = None
        r = client.post("/classify", json={"request": BENIGN})
        self.assertEqual(r.status_code, 503)
        self.assertNotIn("ALLOW", r.text)

    def test_inference_exception_returns_500_without_traceback(self):
        def boom(*a, **kw):
            raise RuntimeError("CUDA out of memory at 0xdeadbeef")

        with patch.object(core, "classify_timed", boom):
            r = client.post("/classify", json={"request": BENIGN})
        self.assertEqual(r.status_code, 500)
        self.assertEqual(r.json()["detail"], "Inference failed")
        # No internals leak to the client.
        self.assertNotIn("Traceback", r.text)
        self.assertNotIn("deadbeef", r.text)
        self.assertNotIn("ALLOW", r.text)

    def test_missing_field_is_rejected(self):
        self.assertEqual(client.post("/classify", json={}).status_code, 422)

    def test_wrong_field_name_is_rejected(self):
        self.assertEqual(client.post("/classify", json={"http": BENIGN}).status_code, 422)

    def test_empty_request_is_rejected(self):
        self.assertEqual(client.post("/classify", json={"request": ""}).status_code, 422)

    def test_wrong_type_is_rejected(self):
        self.assertEqual(client.post("/classify", json={"request": 42}).status_code, 422)


class TestParityWithCore(ModelLoadedTestCase):
    """The endpoint must not re-implement the contract: for the same decoder
    output, the API and inference_core must agree exactly."""

    CASES = [
        "ALLOW | Normal HTTP request with no attack patterns detected.",
        "BLOCK | SQL injection payload detected.",
        "  BLOCK |   Path traversal attack detected.  ",
        "BLOCK | XSS detected. trailing rambling",
        "BLOCK | no period here",
        "total garbage, no contract",
        "",
    ]

    def test_api_matches_core_parse_prediction(self):
        for raw in self.CASES:
            expected_decision, expected_reason, expected_status = core.parse_prediction(raw)
            with patch.object(core, "classify_timed", fake_inference(raw)):
                body = client.post("/classify", json={"request": BENIGN}).json()
            self.assertEqual(body["status"], expected_status, raw)
            self.assertEqual(body["decision"], expected_decision, raw)
            self.assertEqual(body["reason"], expected_reason, raw)

    def test_api_uses_the_shared_parser_object(self):
        self.assertIs(classifier_api.core.parse_prediction, core.parse_prediction)
        self.assertIs(classifier_api.core.classify_timed, core.classify_timed)


if __name__ == "__main__":
    unittest.main()
