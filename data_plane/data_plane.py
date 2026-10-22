"""
firewall-IA — Data Plane (mitmproxy addon).

Authorized inline interception. Every HTTP request that reaches the proxy is
sent to the Control Plane (`classifier_api.py`, POST /classify), and the answer
is enforced here, before anything is forwarded:

    client -> mitmdump + this addon -> POST /classify -> ALLOW: forwarded to the destination
                                                      -> BLOCK: answered by the proxy, never forwarded

The model is never loaded here. The data plane only speaks HTTP to the control
plane and runs in its own environment (see requirements-data-plane.txt).

FAIL-CLOSED (D4, D25, D28). A request is forwarded ONLY when the classifier
answers HTTP 200 with `status: "ok"` and `decision: "ALLOW"`. Everything else
blocks: timeout, connection error, a non-200 answer (503 model not loaded,
500 inference failure, ...), a body that is not valid JSON, `status: "invalid"`,
a missing or unknown decision, and any unexpected error inside this addon.
A model BLOCK is answered with 403 and a classifier failure with 503, so the
two stay distinguishable. The client is never told the model's reason.

SHADOW FEATURE EXTRACTION (Hybrid Architecture Phase 1, D43). When enabled, the
text sent to the classifier is also described by
`request_features.extract_features()`, after the verdict, and the result is
logged as a "FEATURE EXTRACTION (shadow)" line. Nothing reads it: the decision,
enforcement and fail-closed are those above. An extractor error is logged and
ignored; it never blocks a request (that would turn an experimental component
into a new source of BLOCKs).

SHADOW ANALYZER (Hybrid Architecture, `hybrid_shadow.py`, `hybrid_shadow_process.py`). When
`data_plane.shadow_analyzer` is enabled, the frozen lightweight Analyzer scores the same
features AFTER the verdict. It runs in a SEPARATE worker process under the analyzer
environment's interpreter (this environment has no numpy / scikit-learn, D33; the runtime
is a proposal pending D52), in a background task the request never waits for, bounded by its
own timeout; a worker that exceeds it is killed and replaced. Its score,
auxiliary category, status and time are logged on a "HYBRID SHADOW" line carrying the same
`[tag]` as that request's V4 decision line. Nothing reads it: V4 is the only decision, there
is no new ALLOW path, and an Analyzer that is unavailable, invalid, failing or slow is a
status in that line, never a BLOCK or an ALLOW. Scheduling and extraction overhead still
need measurement; the request does not await analyzer completion. Off unless configured.

SHADOW FAST PATH (Hybrid Architecture, PROPOSED; `fast_path.py`). When enabled, each request is also
evaluated for a hypothetical FAST_ALLOW, after the verdict, and the answer is logged as a
"FAST PATH (shadow)" line next to V4's decision. Nothing reads it: every request still goes to
the classifier, V4 decides, enforcement and fail-closed are those above. FAST_ALLOW is a
recorded hypothesis, never a bypass. Its protocol prerequisites (a canonical-request ACCEPT and
VERIFIED wire framing) are not produced by the gateway today, so it logs CONTINUE with the
unmet prerequisites. Errors are logged and ignored.

RUN (from the repository root, in the data plane environment):
    .venv-dataplane/bin/mitmdump -s data_plane/data_plane.py --listen-host 127.0.0.1 -p 8080

The classifier URL, timeout and shadow switch are read from config.yaml when the
script loads. Restart mitmdump after editing this file or request_features.py.
"""

import asyncio
import logging
import os
import time
import traceback
from typing import NamedTuple, Optional

import httpx
import yaml
from mitmproxy import ctx, http

# Sibling module: mitmproxy puts this script's directory on sys.path while
# loading it, as the tests and capture_addon.py do explicitly.
import hybrid_shadow
import hybrid_shadow_process

import fast_path
import request_features
# Canonical-request/v1 OBSERVER (issue #68, scope approved D69). Shadow/observe-only: the gateway
# imports the observer (which owns the one `canonical_request.canonicalize`); V4's D1 rendering and
# the feature extractor stay contract-free. Importing it is cheap (stdlib until a body is decoded).
import canonical_observer

log = logging.getLogger("firewall.data_plane")
# A child logger, so feature lines can be filtered apart from decision lines.
features_log = logging.getLogger("firewall.data_plane.features")
shadow_log = logging.getLogger("firewall.data_plane.shadow")

fastpath_log = logging.getLogger("firewall.data_plane.fastpath")
canonical_log = logging.getLogger("firewall.data_plane.canonical")
# httpx logs every classifier call at INFO; the ALLOW/BLOCK line already covers it.
logging.getLogger("httpx").setLevel(logging.WARNING)

# config.yaml stays at the repository root; this file lives in data_plane/.
CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "config.yaml")

BLOCKED_BODY = "Request blocked by firewall-IA.\n"
UNAVAILABLE_BODY = "Request blocked by firewall-IA: classifier unavailable (fail-closed).\n"


# ── Configuration ──────────────────────────────────────────────────────────
def load_config(path: str = CONFIG_PATH) -> tuple[str, float]:
    """Return `(classifier_url, classifier_timeout_seconds)` from config.yaml.

    Raises on a missing file, a missing key or an invalid value. Raised while
    mitmdump loads the script, that makes mitmdump exit before it starts
    listening (verified on mitmproxy 12.2.3): a misconfigured gateway never runs.
    """
    with open(path, encoding="utf-8") as f:
        section = yaml.safe_load(f)["data_plane"]
    url = section["classifier_url"]
    timeout = float(section["classifier_timeout_seconds"])
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        raise ValueError(f"data_plane.classifier_url must be an http(s) URL, got {url!r}")
    if not timeout > 0:
        raise ValueError(f"data_plane.classifier_timeout_seconds must be > 0, got {timeout}")
    return url, timeout


def load_shadow_feature_extraction(path: str = CONFIG_PATH) -> bool:
    """Return `data_plane.shadow_feature_extraction` from config.yaml (D43).

    Optional: absent means off, so a configuration written before this switch
    existed (e.g. docker/config.docker.yaml, which the External v1 capture proxy also
    loads) keeps its exact behaviour. When present it must be a YAML boolean;
    anything else raises, like every other invalid gateway setting.
    """
    with open(path, encoding="utf-8") as f:
        section = yaml.safe_load(f)["data_plane"]
    value = section.get("shadow_feature_extraction", False)
    if not isinstance(value, bool):
        raise ValueError("data_plane.shadow_feature_extraction must be true or false, "
                         f"got {value!r}")
    return value


class ShadowAnalyzerConfig(NamedTuple):
    python: str                         # the analyzer environment's interpreter (absolute)
    artifact_path: str                  # absolute
    timeout_seconds: float
    startup_timeout_seconds: float
    restart_backoff_seconds: float
    max_consecutive_failures: int


_SHADOW_ANALYZER_KEYS = ("enabled", "runtime", "python", "artifact_path", "timeout_seconds",
                         "startup_timeout_seconds", "restart_backoff_seconds",
                         "max_consecutive_failures")


def load_shadow_analyzer(path: str = CONFIG_PATH) -> Optional[ShadowAnalyzerConfig]:
    """Return `data_plane.shadow_analyzer` from config.yaml, or None when it is off.

    Optional like `shadow_feature_extraction`: absent, or `enabled: false`, means off. When
    enabled, EVERY key is required: this file picks no default bound or interpreter for the
    Analyzer (the values are operational and the runtime is a proposal, D52). `runtime` must
    be `process`, the separate-process runtime (hybrid_shadow_process.py); relative paths
    resolve against the repository root. Anything invalid raises, like every gateway setting.
    """
    with open(path, encoding="utf-8") as f:
        section = yaml.safe_load(f)["data_plane"]
    value = section.get("shadow_analyzer")
    if value is None:
        return None
    if not isinstance(value, dict) or not isinstance(value.get("enabled"), bool):
        raise ValueError("data_plane.shadow_analyzer must be a mapping with a boolean `enabled`, "
                         f"got {value!r}")
    unknown = set(value) - set(_SHADOW_ANALYZER_KEYS)
    if unknown:
        raise ValueError(f"data_plane.shadow_analyzer: unknown keys {sorted(unknown)}")
    if not value["enabled"]:
        return None
    missing = [k for k in _SHADOW_ANALYZER_KEYS if k not in value]
    if missing:
        raise ValueError(f"data_plane.shadow_analyzer: missing keys {missing}")
    if value["runtime"] != "process":
        raise ValueError(f"data_plane.shadow_analyzer.runtime must be 'process', got {value['runtime']!r}")

    def number(key, minimum, inclusive=False):
        v = value[key]
        if isinstance(v, bool) or not isinstance(v, (int, float)) \
                or not (v >= minimum if inclusive else v > minimum):
            raise ValueError(f"data_plane.shadow_analyzer.{key} must be a number "
                             f"{'>=' if inclusive else '>'} {minimum}, got {v!r}")
        return float(v)

    def file(key):
        v = value[key]
        if not isinstance(v, str) or not v:
            raise ValueError(f"data_plane.shadow_analyzer.{key} must be a non-empty string, got {v!r}")
        return os.path.join(os.path.dirname(CONFIG_PATH), v)

    failures = value["max_consecutive_failures"]
    if isinstance(failures, bool) or not isinstance(failures, int) or failures < 1:
        raise ValueError("data_plane.shadow_analyzer.max_consecutive_failures must be an "
                         f"integer >= 1, got {failures!r}")
    return ShadowAnalyzerConfig(file("python"), file("artifact_path"), number("timeout_seconds", 0),
                                number("startup_timeout_seconds", 0),
                                number("restart_backoff_seconds", 0, inclusive=True), failures)

def load_shadow_fast_path(path: str = CONFIG_PATH) -> tuple[bool, str | None]:
    """Return `(data_plane.shadow_fast_path, data_plane.fast_path_policy_file)` from config.yaml.

    Both are optional: absent means off / no policy, so a configuration written before this
    switch existed keeps its exact behaviour. The switch must be a YAML boolean and the policy
    file a string or null; anything else raises, like every other invalid gateway setting.
    """
    with open(path, encoding="utf-8") as f:
        section = yaml.safe_load(f)["data_plane"]
    enabled = section.get("shadow_fast_path", False)
    if not isinstance(enabled, bool):
        raise ValueError(f"data_plane.shadow_fast_path must be true or false, got {enabled!r}")
    policy_file = section.get("fast_path_policy_file")
    if policy_file is not None and not isinstance(policy_file, str):
        raise ValueError("data_plane.fast_path_policy_file must be a string or null, "
                         f"got {policy_file!r}")
    return enabled, policy_file


class CanonicalObserverConfig(NamedTuple):
    python: str                         # the data-plane interpreter (absolute); NOT the analyzer env
    timeout_seconds: float
    startup_timeout_seconds: float
    restart_backoff_seconds: float
    max_consecutive_failures: int
    max_decoded_body: int


_CANONICAL_OBSERVER_KEYS = ("enabled", "python", "timeout_seconds", "startup_timeout_seconds",
                            "restart_backoff_seconds", "max_consecutive_failures", "max_decoded_body")


def load_canonical_observer(path: str = CONFIG_PATH) -> Optional[CanonicalObserverConfig]:
    """Return `data_plane.shadow_canonical_observer` from config.yaml, or None when off (issue #68,
    scope approved D69).

    Optional like the Analyzer switch: absent, or `enabled: false`, means off. When enabled every key
    is required except `max_decoded_body` (defaults to the D69 lab cap). The worker runs under the
    DATA-PLANE interpreter (stdlib + the brotli/zstandard mitmproxy already ships), NOT the analyzer
    environment: it needs no numpy/scikit-learn. Anything invalid raises, like every gateway setting.
    `token_budget` is deliberately not configurable here — it stays unset, so the canonical size is
    UNCHECKED and the Fast Path stays ineligible (the V5 token budget B is PENDING, §11.2)."""
    with open(path, encoding="utf-8") as f:
        section = yaml.safe_load(f)["data_plane"]
    value = section.get("shadow_canonical_observer")
    if value is None:
        return None
    if not isinstance(value, dict) or not isinstance(value.get("enabled"), bool):
        raise ValueError("data_plane.shadow_canonical_observer must be a mapping with a boolean "
                         f"`enabled`, got {value!r}")
    unknown = set(value) - set(_CANONICAL_OBSERVER_KEYS)
    if unknown:
        raise ValueError(f"data_plane.shadow_canonical_observer: unknown keys {sorted(unknown)}")
    if not value["enabled"]:
        return None
    required = [k for k in _CANONICAL_OBSERVER_KEYS if k != "max_decoded_body"]
    missing = [k for k in required if k not in value]
    if missing:
        raise ValueError(f"data_plane.shadow_canonical_observer: missing keys {missing}")

    def number(key, minimum, inclusive=False):
        v = value[key]
        if isinstance(v, bool) or not isinstance(v, (int, float)) \
                or not (v >= minimum if inclusive else v > minimum):
            raise ValueError(f"data_plane.shadow_canonical_observer.{key} must be a number "
                             f"{'>=' if inclusive else '>'} {minimum}, got {v!r}")
        return float(v)

    python = value["python"]
    if not isinstance(python, str) or not python:
        raise ValueError("data_plane.shadow_canonical_observer.python must be a non-empty string, "
                         f"got {python!r}")
    python = os.path.join(os.path.dirname(CONFIG_PATH), python)
    failures = value["max_consecutive_failures"]
    if isinstance(failures, bool) or not isinstance(failures, int) or failures < 1:
        raise ValueError("data_plane.shadow_canonical_observer.max_consecutive_failures must be an "
                         f"integer >= 1, got {failures!r}")
    mdb = value.get("max_decoded_body", canonical_observer.LAB_MAX_DECODED_BODY)
    if isinstance(mdb, bool) or not isinstance(mdb, int) or mdb <= 0:
        raise ValueError("data_plane.shadow_canonical_observer.max_decoded_body must be a positive "
                         f"int, got {mdb!r}")
    return CanonicalObserverConfig(python, number("timeout_seconds", 0),
                                   number("startup_timeout_seconds", 0),
                                   number("restart_backoff_seconds", 0, inclusive=True), failures, mdb)


# ── Request representation (D1) ────────────────────────────────────────────
def render_request(request: http.Request) -> str:
    """Render a request as the raw HTTP text that `/classify` expects (D1).

    Same layout as the V4 dataset the model was trained and evaluated on
    (`parse_dataset_v4.render_request`):

        METHOD /path?query HTTP/1.1
        Name: value                   <- one line per header
                                      <- blank line, only when there is a body
        body

    LF line endings and an origin-form target. Headers are rendered exactly as
    received (order, case and repeats kept) and are never filtered or
    normalized toward the training distribution.
    """
    lines = [f"{request.method} {request.path} {request.http_version}"]
    lines += [f"{name}: {value}" for name, value in request.headers.items(multi=True)]
    text = "\n".join(lines)
    # get_content() undoes Content-Encoding (gzip, br, ...), so the model sees
    # the body the destination will process; strict=False keeps the raw bytes
    # if decoding fails.
    body = request.get_content(strict=False)
    if body:
        text += "\n\n" + body.decode("utf-8", errors="replace")
    return text


# ── Classifier call ────────────────────────────────────────────────────────
class Verdict(NamedTuple):
    decision: str               # "ALLOW" or "BLOCK", nothing else
    reason: str | None = None   # the model's reason, when the classifier gave one
    failure: str | None = None  # set only on a fail-closed BLOCK: why no decision was obtained


def fail_closed(failure: str) -> Verdict:
    return Verdict("BLOCK", failure=failure)


async def ask_classifier(client: httpx.AsyncClient, url: str, raw_request: str) -> Verdict:
    """POST one raw request to /classify and interpret the answer.

    Only an explicit, well-formed ALLOW allows. Every other outcome becomes a
    fail-closed BLOCK carrying a short description of what went wrong.
    """
    try:
        response = await client.post(url, json={"request": raw_request})
    except httpx.TimeoutException:
        return fail_closed("classifier timeout")
    except httpx.HTTPError as exc:  # connection refused, reset, protocol error, ...
        return fail_closed(f"classifier unreachable ({type(exc).__name__})")

    if response.status_code != 200:
        # 503: model not loaded (D28). 500: inference failed. 422: input rejected.
        return fail_closed(f"classifier returned HTTP {response.status_code}")
    try:
        body = response.json()
    except ValueError:
        return fail_closed("classifier returned invalid JSON")
    if not isinstance(body, dict):
        return fail_closed("classifier returned unexpected JSON")

    status, decision = body.get("status"), body.get("decision")
    if status != "ok" or decision not in ("ALLOW", "BLOCK"):
        # status "invalid" means the model output did not satisfy the contract (D25).
        return fail_closed(f"no valid decision (status={status!r}, decision={decision!r})")
    reason = body.get("reason")
    return Verdict(decision, reason if isinstance(reason, str) else None)


# ── Shadow feature extraction (Hybrid Architecture Phase 1, D43) ───────────
def shadow_extract(tag: str, raw_request: str) -> None:
    """Describe the request and log the description. Returns nothing, so no
    caller can act on it, and never raises.

    The log line is a summary of numbers and request type only: no path, no
    query values, no body (same policy as the decision lines). An extractor
    failure is logged with the exception type and code location only, since
    an exception message could quote the request.
    """
    started = time.perf_counter()
    try:
        f = request_features.extract_features(raw_request)
        elapsed_ms = (time.perf_counter() - started) * 1000
        features_log.info(
            "[%s] FEATURE EXTRACTION (shadow) %.3f ms %s method=%s content_type=%r "
            "body_format=%s len=%d/%d/%d params=%d/%d repeated=%d pct_encoded=%d "
            "symbols=%d (%.3f) non_ascii=%d entropy=%.3f",
            tag, elapsed_ms, f.schema_version, f.method, f.content_type, f.body_format,
            f.path_length, f.query_length, f.body_length, f.query_param_count,
            f.body_param_count, f.repeated_param_name_count, f.percent_encoded_count,
            f.symbol_count, f.symbol_ratio, f.non_ascii_count, f.entropy_bits_per_char)
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - started) * 1000
        where = traceback.extract_tb(exc.__traceback__)[-1]
        features_log.warning(
            "[%s] FEATURE EXTRACTION (shadow) failed after %.3f ms: %s at %s:%d; "
            "ignored, the request continues unchanged",
            tag, elapsed_ms, type(exc).__name__, os.path.basename(where.filename), where.lineno)


# ── Shadow Analyzer (Hybrid Architecture) ──────────────────────────────────
async def shadow_analyze(runner, tag: str, raw_request: str,
                         verdict: Verdict) -> None:
    """Score the request with the Analyzer and log the result beside V4's outcome.

    Returns nothing and never raises, so no caller can act on it. `verdict` is read only to
    NAME V4's outcome in the record; it is already enforced and is not touched.
    """
    v4 = hybrid_shadow.v4_outcome(verdict.decision, verdict.failure is not None)
    try:
        result = await runner.run(raw_request)
        record = hybrid_shadow.ShadowRecord(tag, v4, result)
        shadow_log.info("%s", hybrid_shadow.format_record(record))
    except Exception as exc:  # noqa: BLE001 — exception type only: a message could quote the request
        shadow_log.warning("[%s] HYBRID SHADOW FAILED v4=%s detail=internal:%s; ignored, "
                           "the request continues unchanged", tag, v4, type(exc).__name__)

# ── Shadow Fast Path (PROPOSED; see fast_path.py) ───────────────────────────
class GatewayEvidence:
    """The two protocol-validation prerequisites of the Fast Path, as the gateway can supply them.

    Today it can supply neither:
    - canonical: the canonical-request/v1 `canonicalize()` is not integrated here (D56: the data
      plane keeps V4's D1 rendering and must not import the contract) and its `Limits` values (max decoded body, token budget) are
      PENDING in V5-DATA-SPEC-r3 §11.2, so no ACCEPT can be produced without inventing them;
    - framing: wire-level framing (R1) is not verified by any project control; mitmproxy's own
      header validation is third-party behaviour the project neither pins nor tests (D57).
    Both answers are therefore "unavailable", and the Fast Path stays ineligible. A later change
    replaces these two methods (or passes a subclass) once the dependencies exist."""

    def canonical(self, req: http.Request):
        return None

    def framing(self, req: http.Request) -> fast_path.FramingEvidence:
        return fast_path.FramingEvidence(
            fast_path.FRAMING_UNAVAILABLE,
            "no project-owned wire-level framing control (canonical-request R1) in the gateway")


def fast_path_input(req: http.Request, evidence: GatewayEvidence) -> fast_path.FastPathInput:
    """Raw received parts of a mitmproxy request plus the two prerequisites."""
    return fast_path.FastPathInput(
        method=req.data.method, target=req.data.path, http_version=req.http_version,
        headers=tuple((bytes(n), bytes(v)) for n, v in req.headers.fields),
        body=req.raw_content or b"",
        canonical=evidence.canonical(req), framing=evidence.framing(req))


def shadow_fast_path(tag: str, req: http.Request, policy, policy_problem: str | None,
                     evidence: GatewayEvidence, v4_decision: str) -> None:
    """Evaluate the Fast Path for this request and log the hypothesis beside V4's decision.
    Returns nothing, so no caller can act on it, and never raises.

    The line carries codes and identifiers only: no path, query, header value or body (same
    policy as the decision lines). `v4=` is V4's decision, logged for later analysis; it is
    not a label and nothing here compares or enforces."""
    started = time.perf_counter()
    try:
        decision = fast_path.safe_evaluate(fast_path_input(req, evidence), policy)
        if policy_problem and policy is None:
            # A policy that failed to load is reported as such, not as "absent".
            decision = fast_path.FastPathDecision(
                fast_path.CONTINUE,
                tuple("POLICY_INVALID" if r == "POLICY_UNAVAILABLE" else r
                      for r in decision.reasons))
        elapsed_ms = (time.perf_counter() - started) * 1000
        if decision.decision == fast_path.FAST_ALLOW:
            fastpath_log.info(
                "[%s] FAST PATH (shadow) FAST_ALLOW (hypothetical; V4 decision unchanged) "
                "rule=%s policy=%s/%s v4=%s %.3f ms", tag, decision.rule_id,
                decision.policy_id, (decision.policy_sha256 or "")[:8], v4_decision, elapsed_ms)
        else:
            fastpath_log.info(
                "[%s] FAST PATH (shadow) CONTINUE reasons=%s policy=%s v4=%s %.3f ms",
                tag, ",".join(decision.reasons),
                (decision.policy_sha256 or "none")[:8], v4_decision, elapsed_ms)
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - started) * 1000
        where = traceback.extract_tb(exc.__traceback__)[-1]
        fastpath_log.warning(
            "[%s] FAST PATH (shadow) failed after %.3f ms: %s at %s:%d; "
            "ignored, the request continues unchanged",
            tag, elapsed_ms, type(exc).__name__, os.path.basename(where.filename), where.lineno)


# ── mitmproxy addon ────────────────────────────────────────────────────────
def blocked_response(verdict: Verdict) -> http.Response:
    """The proxy's own answer. Setting it on a flow in the `request` hook stops
    mitmproxy from contacting the destination."""
    headers = {"Content-Type": "text/plain; charset=utf-8"}
    if verdict.failure:
        return http.Response.make(503, UNAVAILABLE_BODY, headers)
    return http.Response.make(403, BLOCKED_BODY, headers)


class FirewallGateway:
    def __init__(self, classifier_url: str, timeout_seconds: float,
                 transport: httpx.AsyncBaseTransport | None = None,
                 shadow_features: bool = False,
                 shadow_analyzer=None,
                 shadow_fast_path: bool = False,
                 fast_path_policy_file: str | None = None,
                 fast_path_evidence: GatewayEvidence | None = None,
                 canonical_observer=None) -> None:
        self.classifier_url = classifier_url
        self.timeout_seconds = timeout_seconds
        self.transport = transport  # None in production; tests pass an httpx.MockTransport
        self.shadow_features = shadow_features
        self.shadow_analyzer = shadow_analyzer
        # Canonical-request/v1 shadow observer (issue #68, D69), or None when off. Observe-only: it
        # never affects V4's decision, is never awaited by the request path, and GatewayEvidence
        # still returns canonical=None so the Fast Path stays ineligible (the observer→Fast Path
        # connection is deliberately deferred; see observe_canonical).
        self.canonical_observer = canonical_observer
        # Strong references: asyncio keeps only weak ones to running tasks.
        self._shadow_tasks: set[asyncio.Task] = set()

        self.shadow_fast_path = shadow_fast_path
        self.fast_path_evidence = fast_path_evidence or GatewayEvidence()
        # An unreadable or invalid policy never stops the gateway: the shadow Fast Path just has
        # no policy (CONTINUE, POLICY_INVALID). Only the error class is kept, never its text.
        self.fast_path_policy = None
        self.fast_path_policy_problem = None
        if shadow_fast_path and fast_path_policy_file:
            path = fast_path_policy_file
            if not os.path.isabs(path):
                path = os.path.join(os.path.dirname(CONFIG_PATH), path)
            try:
                self.fast_path_policy = fast_path.load_policy(path)
            except (OSError, fast_path.PolicyError) as exc:
                self.fast_path_policy_problem = type(exc).__name__

    def running(self) -> None:
        log.info("data plane ready: classifier=%s timeout=%.1fs policy=fail-closed",
                 self.classifier_url, self.timeout_seconds)
        features_log.info("feature extraction: %s",
                          "shadow (logged only, never used for decisions)"
                          if self.shadow_features else "off")
        runner = self.shadow_analyzer
        if runner is None:
            shadow_log.info("hybrid shadow analyzer: off")
        else:
            level, message = runner.startup_summary()
            shadow_log.log(level, "%s", message)
            runner.prewarm()   # a separate-process runner starts its worker here, in the background

        fastpath_log.info(
            "fast path: %s", "shadow (hypothetical FAST_ALLOW logged only; V4 decides every "
            "request)" if self.shadow_fast_path else "off")
        if self.shadow_fast_path and self.fast_path_policy_problem:
            fastpath_log.warning("fast path policy not loaded (%s): every request will log "
                                 "CONTINUE", self.fast_path_policy_problem)

        observer = self.canonical_observer
        if observer is None:
            canonical_log.info("canonical observer: off")
        else:
            level, message = observer.startup_summary()
            canonical_log.log(level, "%s", message)
            observer.prewarm()   # starts the worker in the background; the request path never waits

    async def request(self, flow: http.HTTPFlow) -> None:
        if flow.response is not None:
            # Already answered by mitmproxy itself (e.g. block_list, see done()):
            # nothing will be forwarded, so there is nothing to classify.
            return
        # mitmproxy logs an exception raised by a hook and then FORWARDS the
        # request anyway (verified on 12.2.3), so no exception may escape here.
        try:
            await self.enforce(flow)
        except Exception:
            log.exception("[%s] BLOCK (fail-closed) unexpected data plane error", flow.id[:8])
            flow.response = blocked_response(fail_closed("data plane error"))

    async def enforce(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        tag = flow.id[:8]
        # The query string and the body stay out of the log: they may carry
        # credentials or personal data, and they are attacker-controlled.
        target = f"{req.method} {req.pretty_host}:{req.port}{req.path.split('?', 1)[0]}"
        log.info("[%s] received %s (body %d bytes)", tag, target, len(req.raw_content or b""))

        started = time.perf_counter()
        # Rendered once: the shadow extractor below describes exactly the text
        # the classifier received.
        raw_request = render_request(req)
        # trust_env=False ignores HTTP_PROXY & co., so a shell configured to use
        # this proxy cannot route the classifier call back through the proxy.
        async with httpx.AsyncClient(transport=self.transport, timeout=self.timeout_seconds,
                                     trust_env=False) as client:
            verdict = await ask_classifier(client, self.classifier_url, raw_request)
        elapsed_ms = (time.perf_counter() - started) * 1000

        # After the verdict: the extractor cannot affect what V4 received or
        # decided, and its time stays out of "(classifier N ms)", which keeps
        # its definition (render_request + the /classify call).
        if self.shadow_features:
            shadow_extract(tag, raw_request)  # timed and logged on its own line
        if self.shadow_fast_path:
            # Same position and guarantees as the extractor: after the verdict, own log line,
            # no return value, no exception. V4 has already decided and is not re-asked.
            shadow_fast_path(tag, req, self.fast_path_policy, self.fast_path_policy_problem,
                             self.fast_path_evidence, verdict.decision)

        if self.shadow_analyzer is not None:
            self.spawn_shadow_analysis(tag, raw_request, verdict)
        if self.canonical_observer is not None:
            # Same position and guarantees as the other observers: after the verdict, own log line,
            # background task the request never awaits, no return value, no exception, V4 untouched.
            self.spawn_canonical_observation(tag, req)

        if verdict.decision == "ALLOW":
            log.info("[%s] ALLOW %s reason=%r (classifier %.0f ms)",
                     tag, target, verdict.reason, elapsed_ms)
            return
        if verdict.failure:
            log.error("[%s] BLOCK (fail-closed) %s cause=%s (after %.0f ms)",
                      tag, target, verdict.failure, elapsed_ms)
        else:
            log.warning("[%s] BLOCK %s reason=%r (classifier %.0f ms)",
                        tag, target, verdict.reason, elapsed_ms)
        flow.response = blocked_response(verdict)

    def spawn_shadow_analysis(self, tag: str, raw_request: str, verdict: Verdict) -> None:
        """Start the shadow analysis in the background and return at once. Nothing here
        can fail the request: scheduling errors are logged and dropped."""
        try:
            task = asyncio.get_running_loop().create_task(
                shadow_analyze(self.shadow_analyzer, tag, raw_request, verdict))
            self._shadow_tasks.add(task)
            task.add_done_callback(self._shadow_tasks.discard)
        except Exception as exc:  # noqa: BLE001
            shadow_log.warning("[%s] HYBRID SHADOW not started: %s; ignored, the request "
                               "continues unchanged", tag, type(exc).__name__)

    def spawn_canonical_observation(self, tag: str, req: http.Request) -> None:
        """Start the canonical observation in the background and return at once. Nothing here can
        fail the request: scheduling errors are logged and dropped."""
        try:
            task = asyncio.get_running_loop().create_task(self.observe_canonical(tag, req))
            self._shadow_tasks.add(task)
            task.add_done_callback(self._shadow_tasks.discard)
        except Exception as exc:  # noqa: BLE001
            canonical_log.warning("[%s] CANONICAL OBS not started: %s; ignored, the request "
                                  "continues unchanged", tag, type(exc).__name__)

    async def observe_canonical(self, tag: str, req: http.Request) -> None:
        """Observe the request's canonical form and log it beside V4's decision. Returns nothing and
        never raises, so no caller can act on it. The line carries closed codes and numbers only (no
        target, query, header value, body or exception message). The observer result is NOT fed back
        into GatewayEvidence: the Fast Path stays ineligible (canonical=None), by design (D69)."""
        try:
            obs = await self.canonical_observer.observe(req)
            canonical_log.info("%s", canonical_observer.format_record(tag, obs))
        except Exception as exc:  # noqa: BLE001 — type only: a message could quote the request
            canonical_log.warning("[%s] CANONICAL OBS failed detail=internal:%s; ignored, the "
                                  "request continues unchanged", tag, type(exc).__name__)

    def done(self) -> None:
        if self.shadow_analyzer is not None:
            self.shadow_analyzer.close()   # SIGKILLs a separate-process worker
        if self.canonical_observer is not None:
            self.canonical_observer.close()   # SIGKILLs the canonical worker
        # mitmdump reloads a script whenever its file changes. If the new version
        # fails to load, the proxy keeps running WITHOUT this addon and forwards
        # traffic unclassified (verified on 12.2.3). So if this addon is removed
        # while the proxy is still running, switch on mitmproxy's built-in
        # block_list, which runs before any script, for all traffic until
        # mitmdump is restarted. On a normal shutdown there is nothing to do.
        if ctx.master.should_exit.is_set():
            return
        ctx.options.update(block_list=["/~all/503"])
        log.error("data plane addon unloaded while the proxy is running: "
                  "blocking ALL traffic (503) until mitmdump is restarted")


def build_shadow_analyzer(config: Optional[ShadowAnalyzerConfig]):
    """The shadow runner for a configuration, or None when the feature is off. Nothing is
    loaded or started here: the worker process starts in the background after the gateway is
    running, and an Analyzer that cannot be loaded is a status in the shadow lines
    (UNAVAILABLE), never a startup failure. The gateway must not stop being a gateway because
    an experiment is missing its artifact."""
    if config is None:
        return None
    return hybrid_shadow_process.build_process_runner(
        config.python, config.artifact_path, config.timeout_seconds,
        config.startup_timeout_seconds, config.restart_backoff_seconds,
        config.max_consecutive_failures)


def build_canonical_observer(config: Optional[CanonicalObserverConfig]):
    """The canonical observer for a configuration, or None when off. Nothing is loaded or started
    here: the worker process starts in the background after the gateway is running, and a worker that
    cannot start is a status in the observation lines (UNAVAILABLE), never a startup failure."""
    if config is None:
        return None
    return canonical_observer.build_process_observer(
        config.python, config.timeout_seconds, config.startup_timeout_seconds,
        config.restart_backoff_seconds, config.max_consecutive_failures,
        max_decoded_body=config.max_decoded_body)


_SHADOW_FAST_PATH = load_shadow_fast_path()
addons = [FirewallGateway(*load_config(), shadow_features=load_shadow_feature_extraction(),
                          shadow_analyzer=build_shadow_analyzer(load_shadow_analyzer()),
                          shadow_fast_path=_SHADOW_FAST_PATH[0],
                          fast_path_policy_file=_SHADOW_FAST_PATH[1],
                          canonical_observer=build_canonical_observer(load_canonical_observer()))]
