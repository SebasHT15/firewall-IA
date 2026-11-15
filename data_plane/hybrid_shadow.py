"""
firewall-IA — Hybrid Architecture, Lightweight Request Analyzer in SHADOW mode.

    D1 text -> request_features.extract_features() -> frozen Analyzer -> ShadowResult
                                                                         (logged, nothing else)

OBSERVE ONLY. This module never produces, changes or vetoes an enforcement outcome.
V4, through `/classify`, is the only decision (D43, D4/D25/D34). There is no ALLOW path
here, no threshold, no Model 2 and no fallback: a `ShadowResult` carries what the
Analyzer *reported* (its `attack` probability and the auxiliary category of D46/D50)
and how that went. Nothing in the gateway reads it to decide.

REUSED, NOT REBUILT
  request_features.extract_features   the D1 text -> RequestFeatures v2 contract (D43)
  hybrid_contracts.AnalyzerOutput     the Analyzer's output contract (D50); every signal is
                                      validated by it, and an `AnalyzerOutput` that is not
                                      one is rejected here as INVALID_OUTPUT
  scripts/training/hybrid_analyzer    the frozen `AnalyzerModel` (D54/D55), loaded from its
                                      pickled artifact through the same pickle interface
                                      `run_hybrid_analyzer_baselines.py` wrote and read, and
                                      called through `analyze_strict`, which adds the finiteness
                                      guard the frozen `analyze` lacks (that file is untouched) it

RUNTIME IS A PROPOSAL (D52). The Analyzer needs numpy and scikit-learn; the data plane
environment has neither and D33 forbids installing them there. The runtime the gateway uses is
the separate worker process of `hybrid_shadow_process.py`, PROPOSED for D52 and not ratified
(docs/hybrid_shadow_runtime.md). `ShadowRunner` below is the in-process, thread-based runner:
it takes any `AnalyzerProvider` and is kept for tests and for callers that already run in the
ML environment. Measured, it stalls the host event loop for up to ~13 ms (GIL), which is why the
gateway does not use it. `load_frozen_analyzer` (shared by both runtimes) reports
UNAVAILABLE(dependencies_missing) in an environment without the ML stack.

EXPLICIT, DISTINCT STATUSES — a failure is never an OK result:

  OK              the Analyzer answered and the answer satisfies the D50 contract
  UNAVAILABLE     no usable Analyzer (artifact absent / hash differs from the frozen
                  evidence / ML dependencies missing / load failed / feature contract
                  differs); `detail` says which
  INVALID_OUTPUT  the Analyzer answered but the answer violates the D50 contract
  FAILED          the Analyzer (or the extractor) raised
  TIMEOUT         the Analyzer did not finish within the bound; the request never waited
  BUSY            a previous analysis is still running; this request was not analysed
                  (one analysis at a time, no queue, so memory and threads stay bounded)

BOUNDED. `ShadowRunner.run` is awaited by a background task, never by the request hook, and
is itself bounded by `timeout_seconds`. Python cannot kill a running thread, so a timed-out
analysis keeps its single worker until it ends; meanwhile new requests get BUSY instead of
queueing behind it.

LOGGING POLICY. A shadow line holds the request id (the gateway's per-flow tag), the status,
numbers, the V4 decision word and the analyzer version. Never a path, query, header, body,
exception message or traceback text; a failure logs the exception type and stage only.
"""

import asyncio
import concurrent.futures
import dataclasses
import hashlib
import json
import logging
import math
import os
import sys
import threading
import time
import traceback
from typing import Any, Callable, Optional, Protocol

import hybrid_contracts as contracts
import request_features

log = logging.getLogger("firewall.data_plane.shadow")

SHADOW_SCHEMA = "hybrid-shadow/v1"

OK = "OK"
UNAVAILABLE = "UNAVAILABLE"
INVALID_OUTPUT = "INVALID_OUTPUT"
FAILED = "FAILED"
TIMEOUT = "TIMEOUT"
BUSY = "BUSY"
STATUSES = (OK, UNAVAILABLE, INVALID_OUTPUT, FAILED, TIMEOUT, BUSY)

# Closed vocabularies for `detail`: never free text, never an exception message.
UNAVAILABLE_DETAILS = ("artifact_not_configured", "artifact_missing", "evidence_unreadable",
                       "artifact_hash_mismatch", "dependencies_missing", "load_failed",
                       "feature_contract_mismatch",
                       # Separate-process runtime (hybrid_shadow_process.py): the worker is
                       # not ready to take this request, or has been given up on.
                       "worker_starting", "worker_restarting", "worker_disabled",
                       "worker_spawn_failed", "worker_startup_timeout", "worker_protocol_error")

# V4's word for "no decision was obtained" (fail-closed BLOCK, D34), kept distinct from a model BLOCK.
V4_FAIL_CLOSED = "FAIL_CLOSED"

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# The frozen Analyzer (run-002, D54/D55): its identity lives in versioned evidence. The
# pickle itself is gitignored ("model artifacts stay out of git", D55).
FROZEN_EVIDENCE = os.path.join(REPO_ROOT, "reports", "hybrid", "phase2b-analyzer-v2-run-002",
                               "frozen_selection.json")
DEFAULT_ARTIFACT = os.path.join(REPO_ROOT, "model-output-hybrid-analyzer-v2", "recommended.pkl")
TRAINING_DIR = os.path.join(REPO_ROOT, "scripts", "training")
# The feature contract the frozen Analyzer was fitted on (experiment_config.json: feature_schema).
FROZEN_FEATURE_SCHEMA = "request-features/v2"


class AnalyzerUnavailable(Exception):
    """Raised by a loader. `detail` is one of UNAVAILABLE_DETAILS."""

    def __init__(self, detail: str) -> None:
        assert detail in UNAVAILABLE_DETAILS, detail
        super().__init__(detail)
        self.detail = detail


class InvalidAnalyzerOutput(Exception):
    """A provider may raise this to say its output violates the contract."""


class AnalyzerProvider(Protocol):
    """What the shadow path needs from an Analyzer, nothing more."""

    version: str
    feature_schema: str   # the RequestFeatures schema_version it was fitted on

    def analyze(self, features: request_features.RequestFeatures) -> contracts.AnalyzerOutput:
        ...


# ── result ─────────────────────────────────────────────────────────────────
@dataclasses.dataclass(frozen=True)
class ShadowResult:
    """What the Analyzer reported about one request, or why it did not.

    `attack`, `category` and `category_probability` are None unless status is OK: a
    failure is never represented by a score. `category` is auxiliary context only (D46):
    the top-1 of the D47 distribution, present only when the Analyzer gave all of it.
    `analyze_ms` is the Analyzer call alone (None when it never ran); `elapsed_ms` is
    everything the shadow path spent on this request, as the caller saw it.
    """

    status: str
    detail: Optional[str] = None
    analyzer_version: Optional[str] = None
    attack: Optional[float] = None
    category: Optional[str] = None
    category_probability: Optional[float] = None
    analyze_ms: Optional[float] = None
    elapsed_ms: float = 0.0
    # Separate-process runtime only: time the shadow path spent on this request OUTSIDE the
    # Analyzer's own execution (feature serialisation, IPC, scheduling, decoding), i.e.
    # elapsed_ms - analyze_ms. None when the Analyzer never reported its own time.
    overhead_ms: Optional[float] = None

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}, got {self.status!r}")
        if self.status != OK and (self.attack is not None or self.category is not None
                                  or self.category_probability is not None):
            raise ValueError("only an OK result carries a score")
        if self.status == OK and self.attack is None:
            raise ValueError("an OK result carries the attack probability")


@dataclasses.dataclass(frozen=True)
class ShadowRecord:
    """A shadow result correlated with the ACTIVE V4 outcome for the same request.

    `request_id` is the gateway's existing per-flow tag (`flow.id[:8]`), the one every
    other log line of that request carries. `v4_decision` is "ALLOW", "BLOCK" or
    V4_FAIL_CLOSED, as already enforced; it is an observation, never an input.
    """

    request_id: str
    v4_decision: str
    result: ShadowResult
    schema_version: str = SHADOW_SCHEMA


def v4_outcome(decision: str, failed_closed: bool) -> str:
    """Name V4's outcome for a record. A fail-closed BLOCK is not a model BLOCK."""
    return V4_FAIL_CLOSED if failed_closed else decision


def format_record(record: ShadowRecord) -> str:
    """One log line. Numbers, enumerations and the analyzer version only."""
    r = record.result
    parts = [f"[{record.request_id}] HYBRID SHADOW {r.status}", f"v4={record.v4_decision}"]
    if r.detail:
        parts.append(f"detail={r.detail}")
    if r.analyzer_version:
        parts.append(f"analyzer={r.analyzer_version}")
    if r.status == OK:
        parts.append(f"attack={r.attack:.4f}")
        if r.category is not None:
            parts.append(f"category={r.category}({r.category_probability:.3f})")
        else:
            parts.append("category=none")
    if r.analyze_ms is not None:
        parts.append(f"analyze={r.analyze_ms:.3f}ms")
    if r.overhead_ms is not None:
        parts.append(f"overhead={r.overhead_ms:.3f}ms")
    parts.append(f"elapsed={r.elapsed_ms:.3f}ms")
    parts.append(f"schema={record.schema_version}")
    return " ".join(parts)


# ── validation of an Analyzer answer ───────────────────────────────────────
def _summarize(output: Any) -> tuple[float, Optional[str], Optional[float], str]:
    """(attack, top category, its probability, version) of a valid output, or raise
    InvalidAnalyzerOutput. Re-checks the D50 contract instead of trusting the type: a
    provider could hand back an object that was never validated."""
    if not isinstance(output, contracts.AnalyzerOutput):
        raise InvalidAnalyzerOutput("not_analyzer_output")
    try:
        # Re-validate: dataclasses are frozen, but the Mapping inside may have been mutated.
        revalidated = contracts.AnalyzerOutput(dict(output.signals), output.analyzer_version)
    except (ValueError, TypeError) as exc:
        raise InvalidAnalyzerOutput("contract_violation") from exc
    if not isinstance(revalidated.analyzer_version, str) or not revalidated.analyzer_version:
        raise InvalidAnalyzerOutput("no_analyzer_version")
    signals = revalidated.signals
    category = probability = None
    if contracts.CATEGORY_SIGNALS[0] in signals:
        # First maximum wins a tie, in the fixed D47 order, so the choice is deterministic.
        best = max(contracts.CATEGORY_SIGNALS, key=lambda s: signals[s])
        category, probability = best[len(contracts.CATEGORY_PREFIX):], float(signals[best])
    attack = float(signals[contracts.ATTACK])
    if not math.isfinite(attack):   # belt and braces: _check_probability already rejects it
        raise InvalidAnalyzerOutput("non_finite_attack")
    return attack, category, probability, revalidated.analyzer_version


def _raised_in_contract(exc: BaseException) -> bool:
    """True when a ValueError was raised by hybrid_contracts itself, i.e. by the D50
    validation of the answer, not by the model code that preceded it."""
    frames = traceback.extract_tb(exc.__traceback__)
    return bool(frames) and os.path.basename(frames[-1].filename) == "hybrid_contracts.py"


def _where(exc: BaseException) -> str:
    frame = traceback.extract_tb(exc.__traceback__)[-1]
    return f"{type(exc).__name__}@{os.path.basename(frame.filename)}:{frame.lineno}"


# ── the runner ─────────────────────────────────────────────────────────────
class ShadowRunner:
    """Runs one Analyzer analysis per request, bounded, off the request path.

    `provider` None means no Analyzer is usable; `unavailable_detail` then says why and
    every `run` reports UNAVAILABLE without touching the request.
    """

    def __init__(self, provider: Optional[AnalyzerProvider], timeout_seconds: float,
                 unavailable_detail: Optional[str] = None,
                 extract: Callable[[str], request_features.RequestFeatures] = None) -> None:
        if not timeout_seconds > 0 or not math.isfinite(timeout_seconds):
            raise ValueError(f"timeout_seconds must be > 0, got {timeout_seconds!r}")
        if provider is None and unavailable_detail not in UNAVAILABLE_DETAILS:
            raise ValueError("a runner without a provider needs an UNAVAILABLE detail, "
                             f"one of {UNAVAILABLE_DETAILS}")
        self.provider = provider
        self.timeout_seconds = float(timeout_seconds)
        self.unavailable_detail = unavailable_detail
        # Looked up at call time so a test (or a hot reload) sees the extractor in use.
        self._extract = extract
        # One worker: one analysis in flight, ever. No queue to grow without bound.
        # A provider may define `thread_init()`, run once in the worker thread (OpenMP thread
        # counts are per thread: see FrozenAnalyzer.thread_init).
        self._executor = (None if provider is None else concurrent.futures.ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="hybrid-shadow",
            initializer=getattr(provider, "thread_init", None)))
        self._lock = threading.Lock()
        self._in_flight = False

    @property
    def analyzer_version(self) -> Optional[str]:
        return None if self.provider is None else getattr(self.provider, "version", None)

    def startup_summary(self) -> tuple[int, str]:
        """(log level, line) the gateway prints when it starts."""
        if self.provider is None:
            return logging.WARNING, (f"hybrid shadow analyzer: UNAVAILABLE ({self.unavailable_detail}); "
                                     "every request will be recorded as UNAVAILABLE. V4 is unaffected")
        return logging.INFO, ("hybrid shadow analyzer: shadow (logged only, never used for decisions) "
                              f"analyzer={self.analyzer_version} timeout={self.timeout_seconds:.3f}s")

    def prewarm(self) -> None:
        """Nothing to start: the Analyzer is already loaded in this process."""

    def close(self) -> None:
        """Stop accepting work. Does not wait for, or kill, a running analysis."""
        if self._executor is not None:
            self._executor.shutdown(wait=False, cancel_futures=True)

    def _release(self, _future=None) -> None:
        with self._lock:
            self._in_flight = False

    def _analyze_blocking(self, raw_request: str) -> ShadowResult:
        """Runs in the worker thread. Never raises: every outcome is a ShadowResult."""
        version = self.analyzer_version
        started = time.perf_counter()
        stage = "extract"
        try:
            extract = self._extract or request_features.extract_features
            features = extract(raw_request)
            stage = "analyze"
            if features.schema_version != self.provider.feature_schema:
                return ShadowResult(UNAVAILABLE, "feature_contract_mismatch", version)
            t0 = time.perf_counter()
            output = self.provider.analyze(features)
            analyze_ms = (time.perf_counter() - t0) * 1000
        except InvalidAnalyzerOutput as exc:
            return ShadowResult(INVALID_OUTPUT, str(exc) or "invalid_output", version,
                                analyze_ms=(time.perf_counter() - started) * 1000)
        except ValueError as exc:
            took = (time.perf_counter() - started) * 1000
            if stage == "analyze" and _raised_in_contract(exc):
                return ShadowResult(INVALID_OUTPUT, "contract_violation", version, analyze_ms=took)
            return ShadowResult(FAILED, f"{stage}:{_where(exc)}", version, analyze_ms=took)
        except Exception as exc:  # noqa: BLE001 — a shadow fault must stay a shadow fault
            took = (time.perf_counter() - started) * 1000
            return ShadowResult(FAILED, f"{stage}:{_where(exc)}", version, analyze_ms=took)
        try:
            attack, category, probability, out_version = _summarize(output)
        except InvalidAnalyzerOutput as exc:
            return ShadowResult(INVALID_OUTPUT, str(exc) or "invalid_output", version,
                                analyze_ms=analyze_ms)
        return ShadowResult(OK, None, out_version, attack, category, probability, analyze_ms)

    async def run(self, raw_request: str) -> ShadowResult:
        """Analyse one D1 request text. Always returns, within about `timeout_seconds`
        (the worker may keep running past it; see the module docstring)."""
        started = time.perf_counter()

        def elapsed() -> float:
            return (time.perf_counter() - started) * 1000

        if self.provider is None:
            return ShadowResult(UNAVAILABLE, self.unavailable_detail, None, elapsed_ms=elapsed())
        with self._lock:
            if self._in_flight:
                return ShadowResult(BUSY, None, self.analyzer_version, elapsed_ms=elapsed())
            self._in_flight = True
        try:
            future = self._executor.submit(self._analyze_blocking, raw_request)
        except Exception as exc:  # noqa: BLE001 — executor shut down, thread start failure, ...
            self._release()
            return ShadowResult(FAILED, f"submit:{type(exc).__name__}", self.analyzer_version,
                                elapsed_ms=elapsed())
        # The slot frees when the worker really ends, not when we stop waiting for it.
        future.add_done_callback(self._release)
        try:
            result = await asyncio.wait_for(asyncio.wrap_future(future), self.timeout_seconds)
        except asyncio.TimeoutError:
            return ShadowResult(TIMEOUT, None, self.analyzer_version, elapsed_ms=elapsed())
        except Exception as exc:  # noqa: BLE001 — _analyze_blocking should not raise; if it does, say so
            return ShadowResult(FAILED, f"runner:{type(exc).__name__}", self.analyzer_version,
                                elapsed_ms=elapsed())
        return dataclasses.replace(result, elapsed_ms=elapsed())


# ── the frozen Analyzer ────────────────────────────────────────────────────
# Version of the inference wrapper below. Recorded in the worker handshake, so a result can
# always be traced to the guard that produced it.
INFERENCE_GUARD = "nonfinite-reject/strict-v1"
_RANGE_TOLERANCE = 1e-6   # = hybrid_contracts._SUM_TOLERANCE: float noise only, never a clamp of garbage


def analyze_strict(model: Any, features: request_features.RequestFeatures) -> contracts.AnalyzerOutput:
    """`AnalyzerModel.analyze`, with the numeric guard it lacks.

    WHY. `hybrid_analyzer.AnalyzerModel.analyze` (scripts/training/hybrid_analyzer.py:453)
    builds the attack signal as `min(1.0, max(0.0, attack))`. For a NaN `attack` that
    expression returns 0.0, because every comparison with NaN is false and `max(0.0, nan)`
    keeps its first argument: a broken model output reached the D50 contract as a perfectly
    valid "attack = 0.0", and was lost before any validation could see it. A finite value
    outside [0, 1] is clamped the same silent way.

    WHAT THIS DOES INSTEAD. The same computation with the same frozen encoders and models
    (no weights, no frozen file touched), but BEFORE clamping it rejects a non-finite
    `attack` or category probability, and an `attack` outside [0, 1] by more than float
    noise, as InvalidAnalyzerOutput. For every valid output the result is bit-identical to
    `AnalyzerModel.analyze` (tests/test_hybrid_shadow.py checks it on the real artifact).

    Uses `model._shared`, a private attribute of the frozen class, to follow its encoder
    sharing exactly; if that class changes, the equivalence test fails.
    """
    import numpy as np   # the ML environment only; this is never reached without it

    xa = np.array([model.attack_encoder.encode_row(features)])
    xc = xa if model._shared else np.array([model.category_encoder.encode_row(features)])
    attack = float(model.attack_model.predict_proba(xa)[0, 1])
    category = [float(p) for p in model.category_model.predict_proba(xc)[0]]
    if len(category) != len(contracts.ANALYZER_CATEGORIES):
        raise InvalidAnalyzerOutput("category_arity")
    if not math.isfinite(attack) or not all(math.isfinite(p) for p in category):
        raise InvalidAnalyzerOutput("non_finite_output")
    if not -_RANGE_TOLERANCE <= attack <= 1.0 + _RANGE_TOLERANCE:
        raise InvalidAnalyzerOutput("attack_out_of_range")
    signals = {contracts.ATTACK: min(1.0, max(0.0, attack))}
    signals.update({contracts.CATEGORY_PREFIX + c: category[i]
                    for i, c in enumerate(contracts.ANALYZER_CATEGORIES)})
    return contracts.AnalyzerOutput(signals, model.version)


class FrozenAnalyzer:
    """The frozen `AnalyzerModel`, behind the AnalyzerProvider protocol."""

    def __init__(self, model: Any, feature_schema: str) -> None:
        self._model = model
        self.version = model.version
        self.feature_schema = feature_schema

    def thread_init(self) -> None:
        """One OpenMP thread in the worker. HistGradientBoosting predicts with OpenMP, whose
        thread count is a per-thread setting: limiting it in the loading thread does not
        reach the worker, which then fans out to every core. Measured: ~8 ms per request
        with one thread, ~47 ms with the default fan-out inside the shadow worker."""
        try:
            from threadpoolctl import threadpool_limits
            self._limits = threadpool_limits(limits=1)   # kept alive for the thread's lifetime
        except ImportError:
            pass

    def analyze(self, features: request_features.RequestFeatures) -> contracts.AnalyzerOutput:
        return analyze_strict(self._model, features)


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_verified(path: str, expected_sha: str) -> bytes:
    """The artifact's bytes, read ONCE and hashed in memory: the bytes that were verified
    are the bytes that get unpickled, so the file cannot be swapped between check and use."""
    with open(path, "rb") as f:
        data = f.read()
    if hashlib.sha256(data).hexdigest() != expected_sha:
        raise AnalyzerUnavailable("artifact_hash_mismatch")
    return data


def load_frozen_analyzer(artifact_path: Optional[str] = None,
                         evidence_path: str = FROZEN_EVIDENCE) -> FrozenAnalyzer:
    """Load the frozen Analyzer, or raise AnalyzerUnavailable(detail).

    Order matters: the artifact is a pickle, and unpickling runs code. Its bytes are read
    once and hashed against the SHA-256 recorded in the frozen evidence BEFORE pickle sees
    them; bytes that differ are never loaded. Only then are the ML dependencies imported
    and the feature contract compared.
    """
    if not artifact_path:
        raise AnalyzerUnavailable("artifact_not_configured")
    try:
        with open(evidence_path, encoding="utf-8") as f:
            recommended = json.load(f)["recommended"]
        expected_sha, expected_version = recommended["sha256"], recommended["analyzer_version"]
    except (OSError, ValueError, KeyError, TypeError):
        raise AnalyzerUnavailable("evidence_unreadable") from None
    if not os.path.isfile(artifact_path):
        raise AnalyzerUnavailable("artifact_missing")
    try:
        artifact_bytes = _read_verified(artifact_path, expected_sha)
    except OSError:
        raise AnalyzerUnavailable("artifact_missing") from None

    try:
        # Imports numpy + scikit-learn; absent in the data plane environment (D33).
        sys.path.insert(0, TRAINING_DIR)
        try:
            import hybrid_analyzer as ha
        finally:
            sys.path.remove(TRAINING_DIR)
    except ImportError:
        raise AnalyzerUnavailable("dependencies_missing") from None
    try:
        import pickle
        model = pickle.loads(artifact_bytes)
        if not isinstance(model, ha.AnalyzerModel) or model.version != expected_version:
            raise AnalyzerUnavailable("load_failed")
    except AnalyzerUnavailable:
        raise
    except Exception:  # noqa: BLE001
        raise AnalyzerUnavailable("load_failed") from None

    # Feature contract: the encoders must read exactly the fields the current extractor
    # produces, and the extractor must still speak the schema the Analyzer was fitted on.
    fields = tuple(f.name for f in dataclasses.fields(request_features.RequestFeatures)
                   if f.name != "schema_version")
    if (request_features.FEATURE_SCHEMA_VERSION != FROZEN_FEATURE_SCHEMA
            or tuple(model.attack_encoder.fields) != fields
            or tuple(model.category_encoder.fields) != fields):
        raise AnalyzerUnavailable("feature_contract_mismatch")

    return FrozenAnalyzer(model, FROZEN_FEATURE_SCHEMA)


def build_runner(artifact_path: Optional[str], timeout_seconds: float,
                 evidence_path: str = FROZEN_EVIDENCE) -> ShadowRunner:
    """A runner over the frozen Analyzer, or over nothing (UNAVAILABLE) when it cannot be
    loaded. Never raises for an unavailable Analyzer: that is a status, not a crash."""
    try:
        provider = load_frozen_analyzer(artifact_path, evidence_path)
    except AnalyzerUnavailable as exc:
        return ShadowRunner(None, timeout_seconds, exc.detail)
    return ShadowRunner(provider, timeout_seconds)
