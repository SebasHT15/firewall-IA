"""Hybrid Architecture shadow Analyzer tests (data_plane/hybrid_shadow.py, hybrid_boundary.py).

The shadow path OBSERVES: it never decides. These tests check that every outcome of the
Analyzer is an explicit, distinct status; that a failure is never dressed as a score; that
the wait is bounded; that the artifact is verified before it is unpickled; and that the
Model 2 / fallback boundary stays unimplemented.

Standard library only for the runner tests, so they run in both environments:
    python3.12 -m unittest tests.test_hybrid_shadow -v
    .venv-dataplane/bin/python -m unittest tests.test_hybrid_shadow -v
The frozen-artifact tests need numpy + scikit-learn AND the gitignored artifact (D55); they
are skipped otherwise. Point FIREWALL_ANALYZER_ARTIFACT at it when it is not in this tree:
    .venv-analyzer/bin/python -m unittest tests.test_hybrid_shadow -v
"""

import asyncio
import dataclasses
import hashlib
import json
import os
import re
import sys
import tempfile
import threading
import time
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "data_plane"))

import hybrid_boundary as boundary  # noqa: E402
import hybrid_contracts as contracts  # noqa: E402
import hybrid_shadow as shadow  # noqa: E402
import request_features as rf  # noqa: E402

RAW = ("POST /account?token=secret-token-123 HTTP/1.1\nContent-Type: "
       "application/x-www-form-urlencoded\n\nuser=ana&password=hunter2' OR 1=1--")


def signals(attack=0.9, category="sql_injection", with_categories=True):
    out = {contracts.ATTACK: attack}
    if with_categories:
        out.update({s: (1.0 if s == contracts.CATEGORY_PREFIX + category else 0.0)
                    for s in contracts.CATEGORY_SIGNALS})
    return out


class FakeProvider:
    """An AnalyzerProvider whose behaviour the test chooses."""

    version = "fake-analyzer/test"
    feature_schema = rf.FEATURE_SCHEMA_VERSION

    def __init__(self, behaviour=None):
        self.behaviour = behaviour or (lambda f: contracts.AnalyzerOutput(signals(), self.version))
        self.calls = 0

    def analyze(self, features):
        self.calls += 1
        return self.behaviour(features)


def write(path, data):
    with open(path, "wb" if isinstance(data, bytes) else "w") as f:
        f.write(data)


def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def run(runner, raw=RAW):
    return asyncio.run(runner.run(raw))


class TestStatuses(unittest.TestCase):
    def test_valid_analysis_records_score_category_and_time(self):
        runner = shadow.ShadowRunner(FakeProvider(), timeout_seconds=2.0)
        result = run(runner)
        runner.close()
        self.assertEqual(result.status, shadow.OK)
        self.assertEqual(result.attack, 0.9)
        self.assertEqual((result.category, result.category_probability), ("sql_injection", 1.0))
        self.assertEqual(result.analyzer_version, FakeProvider.version)
        self.assertIsNone(result.detail)
        self.assertGreaterEqual(result.analyze_ms, 0)
        self.assertGreaterEqual(result.elapsed_ms, result.analyze_ms)

    def test_provider_thread_init_runs_in_the_worker_thread(self):
        names = []
        provider = FakeProvider()
        provider.thread_init = lambda: names.append(threading.current_thread().name)
        runner = shadow.ShadowRunner(provider, 2.0)
        run(runner)
        runner.close()
        self.assertEqual(len(names), 1)
        self.assertTrue(names[0].startswith("hybrid-shadow"), names)

    def test_the_analyzer_receives_the_features_of_the_same_text(self):
        seen = []
        provider = FakeProvider(lambda f: seen.append(f) or contracts.AnalyzerOutput(
            signals(), provider.version))
        runner = shadow.ShadowRunner(provider, 2.0)
        run(runner)
        runner.close()
        self.assertEqual(seen, [rf.extract_features(RAW)])

    def test_category_is_optional_and_never_invented(self):
        provider = FakeProvider(lambda f: contracts.AnalyzerOutput(
            signals(0.3, with_categories=False), "fake"))
        runner = shadow.ShadowRunner(provider, 2.0)
        result = run(runner)
        runner.close()
        self.assertEqual(result.status, shadow.OK)
        self.assertEqual((result.attack, result.category, result.category_probability),
                         (0.3, None, None))

    def test_no_analyzer_is_unavailable_not_a_score(self):
        for detail in shadow.UNAVAILABLE_DETAILS:
            with self.subTest(detail=detail):
                result = run(shadow.ShadowRunner(None, 1.0, detail))
                self.assertEqual((result.status, result.detail), (shadow.UNAVAILABLE, detail))
                self.assertIsNone(result.attack)
                self.assertIsNone(result.category)

    def test_a_runner_without_analyzer_must_say_why(self):
        with self.assertRaises(ValueError):
            shadow.ShadowRunner(None, 1.0)
        with self.assertRaises(ValueError):
            shadow.ShadowRunner(None, 1.0, "because")

    def test_feature_schema_mismatch_is_unavailable(self):
        provider = FakeProvider()
        provider.feature_schema = "request-features/v1"
        runner = shadow.ShadowRunner(provider, 2.0)
        result = run(runner)
        runner.close()
        self.assertEqual((result.status, result.detail),
                         (shadow.UNAVAILABLE, "feature_contract_mismatch"))
        self.assertEqual(provider.calls, 0, "an Analyzer fitted on other features must not run")

    def test_analyzer_exception_is_failed_and_does_not_quote_the_request(self):
        def boom(features):
            raise RuntimeError("boom token=secret-token-123 hunter2")

        runner = shadow.ShadowRunner(FakeProvider(boom), 2.0)
        result = run(runner)
        runner.close()
        self.assertEqual(result.status, shadow.FAILED)
        self.assertIsNone(result.attack)
        self.assertTrue(result.detail.startswith("analyze:RuntimeError@"), result.detail)
        for leaked in ("boom", "secret-token-123", "hunter2"):
            self.assertNotIn(leaked, result.detail)

    def test_extractor_exception_is_failed_at_the_extract_stage(self):
        def broken(text):
            raise OSError("disk token=secret-token-123")

        runner = shadow.ShadowRunner(FakeProvider(), 2.0, extract=broken)
        result = run(runner)
        runner.close()
        self.assertEqual(result.status, shadow.FAILED)
        self.assertTrue(result.detail.startswith("extract:OSError@"), result.detail)
        self.assertNotIn("secret", result.detail)

    def test_a_value_error_from_the_model_is_failed_not_invalid_output(self):
        def model_bug(features):
            raise ValueError("encoder exploded")

        runner = shadow.ShadowRunner(FakeProvider(model_bug), 2.0)
        result = run(runner)
        runner.close()
        self.assertEqual(result.status, shadow.FAILED)
        self.assertTrue(result.detail.startswith("analyze:ValueError@"), result.detail)

    def test_invalid_output_is_its_own_status(self):
        def unchecked(attack, **extra):
            """An AnalyzerOutput that skipped validation, as a buggy provider could produce."""
            output = object.__new__(contracts.AnalyzerOutput)
            object.__setattr__(output, "signals", {contracts.ATTACK: attack, **extra})
            object.__setattr__(output, "analyzer_version", "fake")
            return output

        cases = {
            "not an AnalyzerOutput": ({"attack": 0.9}, "not_analyzer_output"),
            "None": (None, "not_analyzer_output"),
            "attack above 1": (unchecked(1.5), "contract_violation"),
            "attack NaN": (unchecked(float("nan")), "contract_violation"),
            "partial categories": (unchecked(0.5, **{"category:xss": 1.0}), "contract_violation"),
            "unknown signal": (unchecked(0.5, junk=0.1), "contract_violation"),
        }
        for name, (output, detail) in cases.items():
            with self.subTest(name):
                runner = shadow.ShadowRunner(FakeProvider(lambda f, o=output: o), 2.0)
                result = run(runner)
                runner.close()
                self.assertEqual((result.status, result.detail), (shadow.INVALID_OUTPUT, detail))
                self.assertIsNone(result.attack, "an invalid answer must not leave a score behind")

    def test_the_contract_rejecting_the_answer_is_invalid_output(self):
        # The real Analyzer builds its answer through AnalyzerOutput, which raises ValueError.
        def bad_probabilities(features):
            return contracts.AnalyzerOutput(signals(attack=1.7), "fake")

        runner = shadow.ShadowRunner(FakeProvider(bad_probabilities), 2.0)
        result = run(runner)
        runner.close()
        self.assertEqual((result.status, result.detail), (shadow.INVALID_OUTPUT, "contract_violation"))

    def test_provider_may_declare_its_output_invalid(self):
        def declared(features):
            raise shadow.InvalidAnalyzerOutput("wrong_shape")

        runner = shadow.ShadowRunner(FakeProvider(declared), 2.0)
        result = run(runner)
        runner.close()
        self.assertEqual((result.status, result.detail), (shadow.INVALID_OUTPUT, "wrong_shape"))

    def test_only_ok_results_may_carry_a_score(self):
        for status in shadow.STATUSES:
            if status != shadow.OK:
                with self.subTest(status=status), self.assertRaises(ValueError):
                    shadow.ShadowResult(status, attack=0.5)
        with self.assertRaises(ValueError):
            shadow.ShadowResult(shadow.OK)   # an OK without a score
        with self.assertRaises(ValueError):
            shadow.ShadowResult("MAYBE")

    def test_every_failure_status_is_distinct_from_ok(self):
        self.assertEqual(len(set(shadow.STATUSES)), len(shadow.STATUSES))
        self.assertEqual(set(shadow.STATUSES),
                         {"OK", "UNAVAILABLE", "INVALID_OUTPUT", "FAILED", "TIMEOUT", "BUSY"})


class TestBoundedExecution(unittest.TestCase):
    def test_a_slow_analyzer_times_out_without_waiting_for_it(self):
        release = threading.Event()
        self.addCleanup(release.set)
        runner = shadow.ShadowRunner(FakeProvider(lambda f: release.wait(30) or None), 0.1)
        started = time.perf_counter()
        result = run(runner)
        waited = time.perf_counter() - started
        release.set()
        runner.close()
        self.assertEqual(result.status, shadow.TIMEOUT)
        self.assertIsNone(result.attack)
        self.assertLess(waited, 1.0, "the shadow path waited for an analysis that was stuck")
        self.assertGreaterEqual(result.elapsed_ms, 90)

    def test_while_an_analysis_is_stuck_new_requests_get_busy_not_a_queue(self):
        release, started = threading.Event(), threading.Event()
        self.addCleanup(release.set)

        def slow(features):
            started.set()
            release.wait(30)
            return contracts.AnalyzerOutput(signals(), "fake")

        provider = FakeProvider(slow)
        runner = shadow.ShadowRunner(provider, 0.05)

        async def scenario():
            first = await runner.run(RAW)
            second = await runner.run(RAW)
            third = await runner.run(RAW)
            return first, second, third

        first, second, third = asyncio.run(scenario())
        self.assertEqual(first.status, shadow.TIMEOUT)
        self.assertEqual((second.status, third.status), (shadow.BUSY, shadow.BUSY))
        self.assertLess(second.elapsed_ms, 50)
        self.assertEqual(provider.calls, 1, "a BUSY request must not reach the Analyzer")
        # The slot frees only when the stuck analysis really ends.
        release.set()
        deadline = time.time() + 5
        while runner._in_flight and time.time() < deadline:
            time.sleep(0.01)
        result = run(runner)
        runner.close()
        self.assertEqual(result.status, shadow.OK)

    def test_timeout_must_be_positive_and_finite(self):
        for bad in (0, -1, float("inf"), float("nan")):
            with self.subTest(timeout=bad), self.assertRaises(ValueError):
                shadow.ShadowRunner(FakeProvider(), bad)

    def test_a_closed_runner_reports_failed_not_an_exception(self):
        runner = shadow.ShadowRunner(FakeProvider(), 1.0)
        runner.close()
        result = run(runner)
        self.assertEqual(result.status, shadow.FAILED)
        self.assertTrue(result.detail.startswith("submit:"))
        self.assertFalse(runner._in_flight, "a failed submit must free the slot")


class TestRecordAndLogging(unittest.TestCase):
    def record(self, result, v4="ALLOW"):
        return shadow.ShadowRecord("ab12cd34", v4, result)

    def test_ok_line_carries_numbers_and_the_v4_outcome(self):
        line = shadow.format_record(self.record(shadow.ShadowResult(
            shadow.OK, None, "v-test", 0.912345, "xss", 0.75, 1.5, 2.25), "BLOCK"))
        self.assertEqual(
            line, "[ab12cd34] HYBRID SHADOW OK v4=BLOCK analyzer=v-test attack=0.9123 "
                  "category=xss(0.750) analyze=1.500ms elapsed=2.250ms schema=hybrid-shadow/v1")

    def test_failures_are_visible_in_the_line(self):
        for result in (shadow.ShadowResult(shadow.UNAVAILABLE, "dependencies_missing"),
                       shadow.ShadowResult(shadow.INVALID_OUTPUT, "contract_violation", "v"),
                       shadow.ShadowResult(shadow.FAILED, "analyze:RuntimeError@x.py:1", "v"),
                       shadow.ShadowResult(shadow.TIMEOUT, None, "v"),
                       shadow.ShadowResult(shadow.BUSY, None, "v")):
            line = shadow.format_record(self.record(result))
            with self.subTest(status=result.status):
                self.assertIn(f"HYBRID SHADOW {result.status} ", line)
                self.assertNotIn("attack=", line)
                self.assertNotIn("category=", line)

    def test_fail_closed_v4_is_not_written_as_a_model_block(self):
        self.assertEqual(shadow.v4_outcome("BLOCK", failed_closed=True), shadow.V4_FAIL_CLOSED)
        self.assertEqual(shadow.v4_outcome("BLOCK", failed_closed=False), "BLOCK")
        self.assertEqual(shadow.v4_outcome("ALLOW", failed_closed=False), "ALLOW")

    def test_the_line_carries_no_request_content(self):
        provider = FakeProvider(lambda f: contracts.AnalyzerOutput(signals(), "fake"))
        runner = shadow.ShadowRunner(provider, 2.0)
        result = run(runner)
        runner.close()
        line = shadow.format_record(self.record(result))
        for leaked in ("secret-token-123", "token", "hunter2", "password", "/account", "OR 1=1"):
            self.assertNotIn(leaked, line)

    def test_shadow_lines_do_not_match_the_decision_parsers(self):
        """External v1, the latency summarizer and docker/demo.sh find decisions in the
        data plane log by regex; a shadow line, even one saying v4=BLOCK, must not match."""
        sys.path.insert(0, os.path.join(REPO_ROOT, "scripts", "external"))
        import external_v1_run
        import summarize_latency_observations
        parsers = [external_v1_run._ALLOW_RE, external_v1_run._BLOCK_RE,
                   external_v1_run._FAILCLOSED_RE, summarize_latency_observations.DECISION_LINE,
                   re.compile(r"\] (ALLOW|BLOCK) ")]
        for v4 in ("ALLOW", "BLOCK", shadow.V4_FAIL_CLOSED):
            for result in (shadow.ShadowResult(shadow.OK, None, "v", 0.5, None, None, 1.0, 1.0),
                           shadow.ShadowResult(shadow.FAILED, "analyze:E@f.py:1", "v"),
                           shadow.ShadowResult(shadow.UNAVAILABLE, "artifact_missing")):
                line = "[12:00:00.000] " + shadow.format_record(self.record(result, v4))
                with self.subTest(v4=v4, status=result.status):
                    self.assertFalse(any(p.search(line) for p in parsers), line)


class TestFrozenAnalyzerLoading(unittest.TestCase):
    """The artifact is a pickle: it is hashed against the frozen evidence BEFORE pickle sees it."""

    def evidence(self, directory, artifact_bytes, version="hybrid-analyzer-v2/test", sha=None):
        path = os.path.join(directory, "frozen_selection.json")
        with open(path, "w") as f:
            json.dump({"recommended": {
                "analyzer_version": version,
                "sha256": sha or hashlib.sha256(artifact_bytes).hexdigest()}}, f)
        return path

    def assert_unavailable(self, detail, *args, **kwargs):
        with self.assertRaises(shadow.AnalyzerUnavailable) as caught:
            shadow.load_frozen_analyzer(*args, **kwargs)
        self.assertEqual(caught.exception.detail, detail)

    def test_not_configured(self):
        for value in (None, ""):
            self.assert_unavailable("artifact_not_configured", value)

    def test_unreadable_or_malformed_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            artifact = os.path.join(d, "a.pkl")
            write(artifact, b"x")
            self.assert_unavailable("evidence_unreadable", artifact, os.path.join(d, "none.json"))
            bad = os.path.join(d, "bad.json")
            write(bad, "{}")
            self.assert_unavailable("evidence_unreadable", artifact, bad)

    def test_missing_artifact(self):
        with tempfile.TemporaryDirectory() as d:
            self.assert_unavailable("artifact_missing", os.path.join(d, "none.pkl"),
                                    self.evidence(d, b"x"))

    def test_a_different_file_is_refused_and_never_unpickled(self):
        """A pickle that would run code, with the wrong hash, must not be read by pickle."""
        with tempfile.TemporaryDirectory() as d:
            marker = os.path.join(d, "executed")
            payload = (b"cos\nsystem\n(S'touch " + marker.encode() + b"'\ntR.")
            artifact = os.path.join(d, "recommended.pkl")
            write(artifact, payload)
            evidence = self.evidence(d, b"the frozen bytes")
            self.assert_unavailable("artifact_hash_mismatch", artifact, evidence)
            self.assertFalse(os.path.exists(marker), "an unverified pickle was executed")

    def test_build_runner_turns_every_unavailability_into_a_status(self):
        runner = shadow.build_runner(None, 1.0)
        result = run(runner)
        self.assertEqual((result.status, result.detail),
                         (shadow.UNAVAILABLE, "artifact_not_configured"))
        runner = shadow.build_runner("/nonexistent/recommended.pkl", 1.0)
        self.assertEqual(run(runner).detail, "artifact_missing")

    def test_without_the_ml_stack_the_verified_artifact_is_unavailable(self):
        """The data plane environment (D33) has no numpy: the Analyzer must say so."""
        try:
            import numpy  # noqa: F401
            self.skipTest("numpy is installed; this case needs the data plane environment")
        except ImportError:
            pass
        with tempfile.TemporaryDirectory() as d:
            artifact = os.path.join(d, "recommended.pkl")
            write(artifact, b"not a real pickle")
            self.assert_unavailable("dependencies_missing", artifact,
                                    self.evidence(d, b"not a real pickle"))
        self.assertNotIn("sklearn", sys.modules)


def _frozen_artifact_path():
    path = os.environ.get("FIREWALL_ANALYZER_ARTIFACT", shadow.DEFAULT_ARTIFACT)
    return path if os.path.isfile(path) else None


def _have_ml_stack():
    try:
        import numpy, sklearn  # noqa: F401
        return True
    except ImportError:
        return False


@unittest.skipUnless(_have_ml_stack() and _frozen_artifact_path(),
                     "needs numpy + scikit-learn and the frozen artifact (gitignored, D55)")
class TestRealFrozenAnalyzer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.provider = shadow.load_frozen_analyzer(_frozen_artifact_path())

    def test_loads_the_frozen_analyzer_and_its_feature_contract(self):
        self.assertEqual(self.provider.version, "hybrid-analyzer-v2/attack=hist_gb,category=hist_gb")
        self.assertEqual(self.provider.feature_schema, rf.FEATURE_SCHEMA_VERSION)

    def test_shadow_analysis_equals_calling_the_analyzer_directly(self):
        runner = shadow.ShadowRunner(self.provider, 5.0)
        for raw in (RAW, "GET /search?q=laptop HTTP/1.1\nHost: shop.example",
                    "GET / HTTP/1.1", "POST /x HTTP/1.1\nContent-Type: application/json\n\n{bad"):
            with self.subTest(raw=raw[:20]):
                result = run(runner, raw)
                direct = self.provider.analyze(rf.extract_features(raw))
                self.assertEqual(result.status, shadow.OK)
                self.assertEqual(result.attack, direct.signals[contracts.ATTACK])
                self.assertIn(result.category, contracts.ANALYZER_CATEGORIES)
                self.assertEqual(result.analyzer_version, direct.analyzer_version)
        runner.close()

    def test_a_tampered_copy_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            copy = os.path.join(d, "recommended.pkl")
            write(copy, read_bytes(_frozen_artifact_path()) + b"\x00")
            with self.assertRaises(shadow.AnalyzerUnavailable) as caught:
                shadow.load_frozen_analyzer(copy)
            self.assertEqual(caught.exception.detail, "artifact_hash_mismatch")

    def test_a_changed_feature_contract_is_unavailable(self):
        from unittest.mock import patch
        with patch.object(rf, "FEATURE_SCHEMA_VERSION", "request-features/v3"):
            with self.assertRaises(shadow.AnalyzerUnavailable) as caught:
                shadow.load_frozen_analyzer(_frozen_artifact_path())
        self.assertEqual(caught.exception.detail, "feature_contract_mismatch")


class _StubEncoder:
    fields = ()

    def to_dict(self):
        return {"stub": True}

    def encode_row(self, features):
        return [0.0, 1.0]


class _StubAttackModel:
    """A fitted attack model whose probability the test chooses."""

    def __init__(self, attack):
        self.attack = attack

    def predict_proba(self, x):
        import numpy as np
        return np.array([[1.0 - self.attack, self.attack]])


class _StubCategoryModel:
    def __init__(self, category):
        self.category = category if category is not None else [1 / 8] * 8
        self.classes_ = list(range(8))

    def predict_proba(self, x):
        import numpy as np
        return np.array([self.category])


def _stub_analyzer_model(attack=0.5, category=None):
    """The frozen AnalyzerModel class around stubs (no weights, no artifact)."""
    sys.path.insert(0, shadow.TRAINING_DIR)
    try:
        import hybrid_analyzer as ha
    finally:
        sys.path.remove(shadow.TRAINING_DIR)
    return ha.AnalyzerModel("stub/test", _StubEncoder(), _StubAttackModel(attack),
                            _StubEncoder(), _StubCategoryModel(category))


@unittest.skipUnless(_have_ml_stack(), "needs numpy + scikit-learn (the analyzer environment)")
class TestNonFiniteOutputIsRejected(unittest.TestCase):
    """scripts/training/hybrid_analyzer.py:453 turns a NaN attack into 0.0 (`min(1.0,
    max(0.0, nan))`). The shadow path must reject it before it can look like a score."""

    FEATURES = rf.extract_features(RAW)

    def test_the_frozen_analyze_masks_nan_as_a_valid_zero(self):
        """CHARACTERIZATION of the unmodified frozen code: this is the defect."""
        output = _stub_analyzer_model(attack=float("nan")).analyze(self.FEATURES)
        self.assertEqual(output.signals[contracts.ATTACK], 0.0)

    def test_analyze_strict_rejects_what_the_frozen_analyze_masks(self):
        for name, attack in (("NaN", float("nan")), ("+inf", float("inf")),
                             ("-inf", float("-inf")), ("above 1", 1.7), ("below 0", -0.4)):
            with self.subTest(attack=name):
                with self.assertRaises(shadow.InvalidAnalyzerOutput):
                    shadow.analyze_strict(_stub_analyzer_model(attack=attack), self.FEATURES)

    def test_a_non_finite_category_probability_is_rejected(self):
        for bad in (float("nan"), float("inf")):
            category = [0.0] * 7 + [bad]
            with self.subTest(bad=bad), self.assertRaises(shadow.InvalidAnalyzerOutput):
                shadow.analyze_strict(_stub_analyzer_model(category=category), self.FEATURES)

    def test_wrong_category_arity_is_rejected(self):
        with self.assertRaises(shadow.InvalidAnalyzerOutput):
            shadow.analyze_strict(_stub_analyzer_model(category=[0.5, 0.5]), self.FEATURES)

    def test_float_noise_is_not_rejected_and_is_clamped_like_the_frozen_code(self):
        for attack in (-1e-9, 1.0 + 1e-9, 0.0, 1.0):
            with self.subTest(attack=attack):
                model = _stub_analyzer_model(attack=attack)
                self.assertEqual(shadow.analyze_strict(model, self.FEATURES).signals,
                                 model.analyze(self.FEATURES).signals)

    def test_through_the_runner_a_nan_model_is_invalid_output_not_a_score(self):
        provider = shadow.FrozenAnalyzer(_stub_analyzer_model(attack=float("nan")),
                                         rf.FEATURE_SCHEMA_VERSION)
        runner = shadow.ShadowRunner(provider, 5.0)
        result = run(runner)
        runner.close()
        self.assertEqual((result.status, result.detail), (shadow.INVALID_OUTPUT, "non_finite_output"))
        self.assertIsNone(result.attack)


@unittest.skipUnless(_have_ml_stack() and _frozen_artifact_path(),
                     "needs numpy + scikit-learn and the frozen artifact (gitignored, D55)")
class TestStrictInferenceEqualsFrozenInference(unittest.TestCase):
    def test_bit_identical_to_analyzer_model_analyze_on_the_real_artifact(self):
        provider = shadow.load_frozen_analyzer(_frozen_artifact_path())
        import random
        rng = random.Random(0)
        alphabet = "abcXYZ019 '\"<>()/;|&=%{}\\.-_"
        requests = [RAW, "GET / HTTP/1.1", "GET /a?q=1' OR 1=1-- HTTP/1.1\nHost: x",
                    "POST /x HTTP/1.1\nContent-Type: application/json\n\n{bad"]
        for _ in range(300):
            method = rng.choice(["GET", "POST", "PUT", "DELETE"])
            target = "/" + "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 60)))
            body = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 80)))
            ctype = rng.choice(["application/x-www-form-urlencoded", "application/json", "text/plain"])
            requests.append(f"{method} {target} HTTP/1.1\nContent-Type: {ctype}" +
                            (f"\n\n{body}" if body else ""))
        for raw in requests:
            features = rf.extract_features(raw)
            strict = shadow.analyze_strict(provider._model, features)
            frozen = provider._model.analyze(features)
            self.assertEqual(dict(strict.signals), dict(frozen.signals), raw)
            self.assertEqual(strict.analyzer_version, frozen.analyzer_version)

    def test_the_artifact_is_read_once_and_the_verified_bytes_are_what_gets_unpickled(self):
        """Hash and unpickle see the same bytes: deleting the file after the read changes nothing."""
        with tempfile.TemporaryDirectory() as d:
            copy = os.path.join(d, "recommended.pkl")
            write(copy, read_bytes(_frozen_artifact_path()))
            real_read = shadow._read_verified

            def read_then_remove(path, expected):
                data = real_read(path, expected)
                os.remove(path)
                return data

            from unittest.mock import patch
            with patch.object(shadow, "_read_verified", read_then_remove):
                provider = shadow.load_frozen_analyzer(copy)
            self.assertFalse(os.path.exists(copy))
            self.assertEqual(provider.version, "hybrid-analyzer-v2/attack=hist_gb,category=hist_gb")


class TestModel2AndFallbackBoundary(unittest.TestCase):
    def test_model2_is_explicitly_unimplemented(self):
        self.assertEqual(boundary.MODEL2_STATUS, "UNIMPLEMENTED")
        self.assertEqual(boundary.SEMANTIC_FALLBACK_STATUS, "UNIMPLEMENTED")
        features = rf.extract_features(RAW)
        decision_input = contracts.DecisionInput(
            features, contracts.AnalyzerOutput(signals(), "fake"))
        with self.assertRaises(boundary.Model2Unimplemented):
            boundary.UnimplementedDecisionStage().decide(decision_input)
        self.assertTrue(issubclass(boundary.Model2Unimplemented, NotImplementedError))

    def test_the_boundary_uses_the_approved_contracts_and_adds_none(self):
        self.assertIs(boundary.DecisionInput, contracts.DecisionInput)
        self.assertIs(boundary.DecisionOutput, contracts.DecisionOutput)
        public = {n for n, v in vars(boundary).items()
                  if isinstance(v, type) and v.__module__ == boundary.__name__}
        self.assertEqual(public, {"DecisionStage", "SemanticFallback", "Model2Unimplemented",
                                  "UnimplementedDecisionStage"})

    def test_nothing_in_the_gateway_or_the_shadow_path_reaches_the_boundary(self):
        for name in ("data_plane.py", "hybrid_shadow.py"):
            source = read_bytes(os.path.join(REPO_ROOT, "data_plane", name)).decode()
            with self.subTest(module=name):
                self.assertNotRegex(source, r"(?m)^\s*(import|from)\s+hybrid_boundary")
                self.assertNotIn("DecisionOutput", source)
                self.assertNotIn("DecisionInput", source)

    def test_the_shadow_result_has_no_decision_of_its_own(self):
        fields = {f.name for f in dataclasses.fields(shadow.ShadowResult)}
        self.assertFalse(fields & {"decision", "verdict", "allow", "block", "confidence",
                                   "threshold", "uncertain"})


if __name__ == "__main__":
    unittest.main()
