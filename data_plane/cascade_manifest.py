"""
firewall-IA — versioned model manifest and gateway configuration for the cascade.

Two documents, two owners:

  firewall-cascade-model-manifest/v1   WHAT is served. Written by whoever delivers a model
      candidate: V5 identity (adapter, recipe, template fingerprint, vocabulary, B), Model 2
      identity (artifact, feature view, decision policy) and the canonical limits that follow
      from B. Nothing here is hard-coded in the gateway: a new candidate is a new manifest.

  firewall-cascade-model-manifest/v2   The same, for a model CANDIDATE. It adds what v1 leaves to
      the service: where the adapter and the recipe are, the base model, the whole token contract and
      an explicit runtime. `runtime: null` is a decision (the recipe's own runtime), and a profile is
      accepted only when its own file binds it to THIS adapter and recipe, so a fast profile measured
      on earlier weights cannot travel with a copied manifest. v1 stays readable for the fixtures and
      runs that already use it; a new candidate is v2.

  firewall-cascade-gateway-config/v2   HOW the gateway runs it. Written by the operator: mode,
      deployment profile, worker bounds, admission, framing, Fast Path activation and audit budget,
      observability.

Both are parsed strictly: an unknown key, a missing key or a wrong type raises, there are no
default operating values, and a value is never coerced. A problem found when loading stops the
gateway from enabling the cascade; a problem found at runtime (V5 serving another contract) makes it
not-ready. Neither is ever accepted silently.

ENABLEMENT IS NOT APPROVAL. `deployment_profile: lab` allows experimental policies (the 0.9 Model 2
threshold is LAB_EXPERIMENTAL and stays reported as such). `deployment_profile: production` refuses
every authoritative mode unless the manifest and the policies carry an approval record; this module
only checks that the record exists, it ratifies nothing.

Standard library only, except PyYAML in `load_gateway_config` (the data-plane environment has it).
"""

import dataclasses
import hashlib
import json
import math
import os
import re
from dataclasses import dataclass
from typing import Optional

import canonical_request as CR
import cascade as C
import fast_path as fp
import model2_policy as mp

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MANIFEST_SCHEMA = "firewall-cascade-model-manifest/v1"
CANDIDATE_SCHEMA = "firewall-cascade-model-manifest/v2"
CONFIG_SCHEMA = "firewall-cascade-gateway-config/v2"
PROFILE_SCHEMAS = ("v5-inference-profile/v1", "v5-inference-profile/v2")
NATIVE_DECODER = "native"
ADAPTER_WEIGHTS = "adapter_model.safetensors"

MANIFEST_STATUSES = ("EXPERIMENTAL", "APPROVED")
PROFILE_STATUSES = ("EXPERIMENTAL", "APPROVED")
DEPLOYMENT_PROFILES = ("lab", "production")
AUTHORITATIVE_MODES = (C.V5_ONLY, C.CASCADE_ACTIVE)
FAST_PATH_ACTIVATIONS = ("disabled", "experimental_fixture", "production")

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX = re.compile(r"^[0-9a-f]{8,128}$")
_ID = re.compile(r"^[A-Za-z0-9_.:\-]{1,128}$")
_BODY_SIZE = re.compile(r"^[1-9][0-9]*[kmg]?$")


class ManifestError(ValueError):
    """The manifest or configuration cannot be used. Its message never carries request data."""


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _keys(section, required, optional=(), where=""):
    if not isinstance(section, dict):
        raise ManifestError(f"{where} must be a mapping")
    unknown = set(section) - set(required) - set(optional)
    if unknown:
        raise ManifestError(f"{where}: unknown keys {sorted(unknown)}")
    missing = [k for k in required if k not in section]
    if missing:
        raise ManifestError(f"{where}: missing keys {missing}")


def _int(section, key, where, minimum=1):
    v = section[key]
    if isinstance(v, bool) or not isinstance(v, int) or v < minimum:
        raise ManifestError(f"{where}.{key} must be an integer >= {minimum}")
    return v


def _num(section, key, where, inclusive=False):
    v = section[key]
    ok = (not isinstance(v, bool) and isinstance(v, (int, float)) and math.isfinite(v)
          and (v >= 0 if inclusive else v > 0))
    if not ok:
        raise ManifestError(f"{where}.{key} must be a number {'>= 0' if inclusive else '> 0'}")
    return float(v)


def _hex64(section, key, where):
    v = section[key]
    if not isinstance(v, str) or not _HEX64.match(v):
        raise ManifestError(f"{where}.{key} must be a 64-hex digest")
    return v


def _str(section, key, where):
    v = section[key]
    if not isinstance(v, str) or not v.strip():
        raise ManifestError(f"{where}.{key} must be a non-empty string")
    return v


def _bool(section, key, where):
    v = section[key]
    if not isinstance(v, bool):
        raise ManifestError(f"{where}.{key} must be true or false")
    return v


def _path(value, base):
    return value if os.path.isabs(value) else os.path.normpath(os.path.join(base, value))


def _approval(doc, where):
    appr = doc.get("approval")
    if (not isinstance(appr, dict)
            or any(not isinstance(appr.get(k), str) or not appr[k].strip()
                   for k in ("approved_by", "date", "decision_ref"))):
        raise ManifestError(f"{where}: APPROVED needs approval.approved_by/date/decision_ref")


# ─────────────────────────────── model manifest ───────────────────────────────
@dataclass(frozen=True)
class CanonicalLimits:
    contract: str
    max_decoded_body: int
    token_budget_B: int
    max_bytes_per_token: int


@dataclass(frozen=True)
class TokenContract:
    max_length: int
    margin: int
    overhead: int
    label_budget: int
    max_new_tokens: int


@dataclass(frozen=True)
class RuntimeBinding:
    """A runtime profile as its own file states it, checked against the manifest that names it."""
    profile_path: str
    profile_sha256: str
    profile_id: str
    status: str
    precision: str
    double_quant: bool
    decoder: str
    decoder_sha256: Optional[str]
    evidence_path: Optional[str]
    evidence_sha256: Optional[str]


@dataclass(frozen=True)
class V5Identity:
    adapter_sha256: str
    recipe_sha256: str
    template_fingerprint: str
    vocabulary: tuple
    token_budget_B: int
    runtime_profile_sha256: Optional[str] = None
    # v2 only: a v1 manifest leaves these to the service.
    adapter_path: Optional[str] = None
    recipe_path: Optional[str] = None
    base_model: Optional[str] = None
    base_revision: Optional[str] = None
    token_contract: Optional[TokenContract] = None
    runtime: Optional[RuntimeBinding] = None


@dataclass(frozen=True)
class Model2Identity:
    artifact_path: str
    artifact_sha256: str
    feature_view: str
    policy_path: str
    policy_sha256: str
    policy_id: str
    policy_status: str


@dataclass(frozen=True)
class ModelManifest:
    manifest_id: str
    status: str
    canonical: CanonicalLimits
    v5: V5Identity
    model2: Optional[Model2Identity]
    sha256: str
    source_path: Optional[str] = None
    schema: str = MANIFEST_SCHEMA

    @property
    def is_candidate(self) -> bool:
        return self.schema == CANDIDATE_SCHEMA


def parse_manifest(doc, base_dir: str = REPO_ROOT, source_path: Optional[str] = None) -> ModelManifest:
    """Validate a manifest document and everything it can check OFFLINE: the Model 2 artifact bytes,
    the decision policy and its binding to that artifact. V5 is compared with the running service
    at readiness (`v5_contract_problems`), because only the service knows what it loaded."""
    where = "manifest"
    _keys(doc, ("schema", "manifest_id", "status", "canonical", "v5", "model2"), ("approval", "note"),
          where)
    schema = doc["schema"]
    if schema not in (MANIFEST_SCHEMA, CANDIDATE_SCHEMA):
        raise ManifestError(f"manifest.schema must be {MANIFEST_SCHEMA!r} or {CANDIDATE_SCHEMA!r}")
    manifest_id = _str(doc, "manifest_id", where)
    if not _ID.match(manifest_id):
        raise ManifestError("manifest.manifest_id has characters outside the closed set")
    status = doc["status"]
    if status not in MANIFEST_STATUSES:
        raise ManifestError(f"manifest.status must be one of {MANIFEST_STATUSES}")
    if status == "APPROVED":
        _approval(doc, where)

    w = "manifest.canonical"
    section = doc["canonical"]
    _keys(section, ("contract", "max_decoded_body", "token_budget_B", "max_bytes_per_token"), (), w)
    if section["contract"] != CR.CONTRACT_ID:
        raise ManifestError(f"{w}.contract {section['contract']!r} is not the served "
                            f"{CR.CONTRACT_ID!r}")
    canonical = CanonicalLimits(section["contract"], _int(section, "max_decoded_body", w),
                                _int(section, "token_budget_B", w),
                                _int(section, "max_bytes_per_token", w))
    # §5.5 of the canonical spec: the decode cap cannot be below the data-plane reverse bound.
    if canonical.max_decoded_body < canonical.max_bytes_per_token * canonical.token_budget_B:
        raise ManifestError(f"{w}.max_decoded_body must be >= max_bytes_per_token * token_budget_B")

    v5 = _parse_v5(doc["v5"], schema, base_dir)
    if v5.token_budget_B != canonical.token_budget_B:
        raise ManifestError("manifest.v5.token_budget_B differs from manifest.canonical")

    model2 = None
    if doc["model2"] is not None:
        model2 = _parse_model2(doc["model2"], base_dir)

    digest = hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":"),
                                       ensure_ascii=True).encode("ascii")).hexdigest()
    return ModelManifest(manifest_id, status, canonical, v5, model2, digest, source_path, schema)


_V5_COMMON = ("adapter_sha256", "recipe_sha256", "template_fingerprint", "vocabulary", "token_budget_B")
_V5_CANDIDATE = ("adapter_path", "recipe_path", "base_model", "base_revision", "max_length", "margin",
                 "overhead", "label_budget", "max_new_tokens", "runtime")
_RUNTIME_KEYS = ("profile_path", "profile_sha256", "verification_evidence_path",
                 "verification_evidence_sha256")


def _parse_v5(section, schema, base_dir) -> V5Identity:
    w = "manifest.v5"
    candidate = schema == CANDIDATE_SCHEMA
    if candidate:
        _keys(section, _V5_COMMON + _V5_CANDIDATE, (), w)
    else:
        _keys(section, _V5_COMMON, ("runtime_profile_sha256",), w)
    fingerprint = _str(section, "template_fingerprint", w)
    if not _HEX.match(fingerprint):
        raise ManifestError(f"{w}.template_fingerprint must be lowercase hex")
    vocabulary = section["vocabulary"]
    if (not isinstance(vocabulary, list) or not vocabulary
            or any(not isinstance(v, str) or not v for v in vocabulary)
            or len(set(vocabulary)) != len(vocabulary)):
        raise ManifestError(f"{w}.vocabulary must be a non-empty list of distinct strings")
    adapter, recipe = _hex64(section, "adapter_sha256", w), _hex64(section, "recipe_sha256", w)
    budget = _int(section, "token_budget_B", w)
    if not candidate:
        profile = section.get("runtime_profile_sha256")
        if profile is not None:
            profile = _hex64(section, "runtime_profile_sha256", w)
        return V5Identity(adapter, recipe, fingerprint, tuple(vocabulary), budget, profile)

    if not any(v.startswith("ALLOW") for v in vocabulary):
        # An output space with no ALLOW could only ever deny. That is a delivery mistake, not a policy.
        raise ManifestError(f"{w}.vocabulary has no ALLOW output")
    if not any(v.startswith("BLOCK") for v in vocabulary):
        raise ManifestError(f"{w}.vocabulary has no BLOCK output")
    tokens = TokenContract(_int(section, "max_length", w), _int(section, "margin", w, minimum=0),
                           _int(section, "overhead", w), _int(section, "label_budget", w),
                           _int(section, "max_new_tokens", w))
    if tokens.max_new_tokens < tokens.label_budget:
        raise ManifestError(f"{w}.max_new_tokens is below label_budget: a valid label would not fit")
    if budget + tokens.overhead + tokens.label_budget + tokens.margin > tokens.max_length:
        raise ManifestError(f"{w}: token_budget_B + overhead + label_budget + margin exceeds max_length")
    runtime = section["runtime"]
    if runtime is not None:
        runtime = _parse_runtime(runtime, adapter, recipe, base_dir)
    return V5Identity(adapter, recipe, fingerprint, tuple(vocabulary), budget,
                      runtime.profile_sha256 if runtime else None,
                      _path(_str(section, "adapter_path", w), base_dir),
                      _path(_str(section, "recipe_path", w), base_dir),
                      _str(section, "base_model", w), _str(section, "base_revision", w), tokens, runtime)


def _parse_runtime(section, adapter_sha256, recipe_sha256, base_dir) -> RuntimeBinding:
    """The profile file is read here because the binding is in it. Its own fields decide, not anything
    the manifest says about them: a profile carried over from other weights stops at this point,
    before a service is started for it."""
    w = "manifest.v5.runtime"
    _keys(section, _RUNTIME_KEYS, (), w)
    path = _path(_str(section, "profile_path", w), base_dir)
    expected = _hex64(section, "profile_sha256", w)
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        raise ManifestError(f"{w}.profile_path unreadable ({type(exc).__name__})") from None
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ManifestError(f"{w}: profile bytes do not match profile_sha256")
    try:
        profile = json.loads(raw)
    except ValueError as exc:
        raise ManifestError(f"{w}: profile is not valid JSON ({type(exc).__name__})") from None
    if not isinstance(profile, dict) or profile.get("schema") not in PROFILE_SCHEMAS:
        raise ManifestError(f"{w}: unknown profile schema")
    if profile.get("adapter_sha256") != adapter_sha256:
        raise ManifestError(f"{w}: profile is bound to another adapter; a runtime profile does not "
                            "carry over to new weights")
    if profile.get("recipe_sha256") != recipe_sha256:
        raise ManifestError(f"{w}: profile is bound to another recipe")
    status = profile.get("status")
    if status not in PROFILE_STATUSES:
        raise ManifestError(f"{w}: profile status {status!r} is not enabled")
    decoder = profile.get("decoder", NATIVE_DECODER)
    decoder_sha256 = profile.get("decoder_sha256")
    evidence_path = section["verification_evidence_path"]
    evidence_sha256 = section["verification_evidence_sha256"]
    if decoder == NATIVE_DECODER:
        if evidence_path is not None or evidence_sha256 is not None:
            raise ManifestError(f"{w}: a native profile carries no decoder verification")
    else:
        # The verified decoder must agree with native generation on these weights and this
        # vocabulary, and that is an empirical result. Without it there is nothing to adopt.
        evidence_path = _path(_str(section, "verification_evidence_path", w), base_dir)
        evidence_sha256 = _hex64(section, "verification_evidence_sha256", w)
        try:
            with open(evidence_path, "rb") as fh:
                evidence_raw = fh.read()
            evidence = json.loads(evidence_raw)
        except OSError as exc:
            raise ManifestError(f"{w}.verification_evidence_path unreadable "
                                f"({type(exc).__name__})") from None
        except ValueError as exc:
            raise ManifestError(f"{w}: evidence is not valid JSON ({type(exc).__name__})") from None
        if hashlib.sha256(evidence_raw).hexdigest() != evidence_sha256:
            raise ManifestError(f"{w}: evidence bytes do not match verification_evidence_sha256")
        if not isinstance(evidence, dict) or evidence.get("profile_sha256") != expected:
            raise ManifestError(f"{w}: evidence does not name this profile")
    return RuntimeBinding(path, expected, _str(profile, "profile_id", w), status,
                          _str(profile, "precision", w), _bool(profile, "double_quant", w), decoder,
                          decoder_sha256, evidence_path, evidence_sha256)


def _parse_model2(section, base_dir) -> Model2Identity:
    w = "manifest.model2"
    _keys(section, ("artifact_path", "artifact_sha256", "feature_view", "policy_path",
                    "policy_sha256"), (), w)
    artifact_path = _path(_str(section, "artifact_path", w), base_dir)
    artifact_sha256 = _hex64(section, "artifact_sha256", w)
    feature_view = _str(section, "feature_view", w)
    policy_path = _path(_str(section, "policy_path", w), base_dir)
    policy_sha256 = _hex64(section, "policy_sha256", w)
    try:
        actual = sha256_file(artifact_path)
    except OSError as exc:
        raise ManifestError(f"{w}.artifact_path unreadable ({type(exc).__name__})") from None
    if actual != artifact_sha256:
        raise ManifestError(f"{w}: artifact bytes do not match artifact_sha256")
    try:
        policy = mp.load_policy(policy_path)
    except (OSError, mp.PolicyError) as exc:
        raise ManifestError(f"{w}: policy not usable ({type(exc).__name__})") from None
    if policy.sha256 != policy_sha256:
        raise ManifestError(f"{w}: policy document does not match policy_sha256")
    if not policy.binds(feature_view=feature_view, artifact_sha256=artifact_sha256):
        raise ManifestError(f"{w}: policy is not bound to this artifact and feature view")
    return Model2Identity(artifact_path, artifact_sha256, feature_view, policy_path, policy_sha256,
                          policy.policy_id, policy.status)


def load_manifest(path: str, base_dir: str = REPO_ROOT) -> ModelManifest:
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except OSError as exc:
        raise ManifestError(f"manifest unreadable ({type(exc).__name__})") from None
    except ValueError as exc:
        raise ManifestError(f"manifest is not valid JSON ({type(exc).__name__})") from None
    return parse_manifest(doc, base_dir, source_path=path)


def enablement_problems(manifest: ModelManifest, mode: str, deployment_profile: str) -> tuple:
    """Closed reasons why this manifest may not be enabled in this mode and profile."""
    problems = []
    if mode == C.CASCADE_ACTIVE and manifest.model2 is None:
        problems.append("model2_required_for_cascade_active")
    if deployment_profile == "production" and mode in AUTHORITATIVE_MODES:
        if manifest.status != "APPROVED":
            problems.append("manifest_not_approved_for_production")
        if (mode == C.CASCADE_ACTIVE and manifest.model2 is not None
                and manifest.model2.policy_status != "APPROVED"):
            problems.append("model2_policy_not_approved_for_production")
        runtime = manifest.v5.runtime
        if runtime is not None and runtime.status != "APPROVED":
            problems.append("runtime_profile_not_approved_for_production")
    return tuple(problems)


def candidate_file_problems(manifest: ModelManifest) -> tuple:
    """A v2 manifest against the files it names, offline. The gateway does not read these at runtime,
    since the service loads them; this is what lets a delivery be refused before anything is started."""
    v5 = manifest.v5
    if not manifest.is_candidate:
        return ()
    problems = []
    try:
        if sha256_file(os.path.join(v5.adapter_path, ADAPTER_WEIGHTS)) != v5.adapter_sha256:
            problems.append("adapter_bytes_mismatch")
    except OSError:
        problems.append("adapter_unreadable")
    try:
        if sha256_file(v5.recipe_path) != v5.recipe_sha256:
            problems.append("recipe_bytes_mismatch")
    except OSError:
        problems.append("recipe_unreadable")
    runtime = v5.runtime
    if runtime is not None and runtime.decoder != NATIVE_DECODER:
        decoder = os.path.join(REPO_ROOT, "scripts", "v5_successor", "verified_suffix.py")
        try:
            if sha256_file(decoder) != runtime.decoder_sha256:
                problems.append("decoder_bytes_mismatch")
        except OSError:
            problems.append("decoder_unreadable")
    return tuple(problems)


def v5_contract_problems(manifest: ModelManifest, health: dict, contract: dict) -> tuple:
    """Compare what the V5 service reports with the manifest. Closed reasons; empty means bound."""
    v5 = manifest.v5
    problems = []
    if not isinstance(health, dict) or health.get("model_loaded") is not True:
        return ("v5_model_not_loaded",)
    if health.get("adapter_sha256") != v5.adapter_sha256:
        problems.append("v5_adapter_mismatch")
    # Precision and quantization change the inference. A manifest names the runtime it was measured
    # under, or none for the recipe's own: the same weights under another runtime are not it, so an
    # experimental profile can never be picked up silently.
    profile = health.get("runtime_profile")
    served = profile.get("sha256") if isinstance(profile, dict) else None
    if served != v5.runtime_profile_sha256:
        problems.append("v5_runtime_profile_mismatch")
    if v5.runtime is not None and isinstance(profile, dict):
        # What the service says it runs, against what the profile file said when the manifest loaded.
        for key, expected in (("adapter_sha256", v5.adapter_sha256),
                              ("recipe_sha256", v5.recipe_sha256),
                              ("precision", v5.runtime.precision),
                              ("double_quant", v5.runtime.double_quant),
                              ("decoder", v5.runtime.decoder),
                              ("decoder_sha256", v5.runtime.decoder_sha256)):
            if profile.get(key, NATIVE_DECODER if key == "decoder" else None) != expected:
                problems.append(f"v5_runtime_{key}_mismatch")
    if not isinstance(contract, dict):
        return tuple(problems) + ("v5_contract_unavailable",)
    checks = [("template_fingerprint", v5.template_fingerprint),
              ("recipe_sha256", v5.recipe_sha256),
              ("token_budget_B", v5.token_budget_B),
              ("vocabulary", list(v5.vocabulary))]
    if v5.token_contract is not None:
        checks += [("base_model", v5.base_model), ("base_revision", v5.base_revision)]
        checks += list(dataclasses.asdict(v5.token_contract).items())
    for key, expected in checks:
        if contract.get(key) != expected:
            problems.append(f"v5_{key}_mismatch")
    if health.get("template_fingerprint") != v5.template_fingerprint:
        problems.append("v5_template_fingerprint_mismatch")
    return tuple(dict.fromkeys(problems))


# ─────────────────────────────── gateway configuration ───────────────────────────────
@dataclass(frozen=True)
class WorkerBounds:
    python: str
    timeout_seconds: float
    startup_timeout_seconds: float
    restart_backoff_seconds: float
    max_consecutive_failures: int


@dataclass(frozen=True)
class CanonicalWorkers:
    bounds: WorkerBounds
    workers: int
    max_received_body: int
    max_text_bytes: int


@dataclass(frozen=True)
class EgressConfig:
    listen_port: int
    upstream_host: str
    upstream_port: int
    ticket_ttl_seconds: float
    max_tickets: int
    idle_timeout_seconds: float


@dataclass(frozen=True)
class FramingConfig:
    contract: str
    body_size_limit: str
    egress: EgressConfig
    verified_evidence: bool
    owner_ruling_ref: Optional[str]


@dataclass(frozen=True)
class AuditConfig:
    sample_rate: float
    sample_salt: str
    queue_size: int
    max_queue_bytes: int
    workers: int
    timeout_seconds: float
    max_abandoned: int
    shutdown_drain_seconds: float
    max_audits_per_second: float
    burst: int
    yield_when_v5_inflight: int
    max_queue_age_seconds: float


@dataclass(frozen=True)
class FastPathConfig:
    activation: str
    policy_file: Optional[str]
    policy_sha256: Optional[str]
    application_contract_ref: Optional[str]
    audit: AuditConfig


@dataclass(frozen=True)
class ObservabilityConfig:
    decision_log: str
    max_log_bytes: int
    max_log_files: int
    log_queue_size: int
    admin_port: int
    log_wire_sha256: bool


@dataclass(frozen=True)
class GatewayConfig:
    mode: str
    deployment_profile: str
    manifest_path: str
    listen_host: str
    listen_port: int
    v4_url: str
    v4_timeout_seconds: float
    v5_url: str
    v5_timeout_seconds: float
    model2: WorkerBounds
    canonical: CanonicalWorkers
    max_inflight: int
    max_waiting: int
    max_wait_seconds: float
    decision_deadline_seconds: float
    observe_max_pending: int
    framing: FramingConfig
    fast_path: FastPathConfig
    observability: ObservabilityConfig
    rollback_file: str
    probe_interval_seconds: float


_LOOPBACK = ("127.0.0.1", "::1", "localhost")


def _bounds(section, base_dir, where) -> WorkerBounds:
    _keys(section, ("python", "timeout_seconds", "startup_timeout_seconds",
                    "restart_backoff_seconds", "max_consecutive_failures"), (), where)
    return WorkerBounds(_path(_str(section, "python", where), base_dir),
                        _num(section, "timeout_seconds", where),
                        _num(section, "startup_timeout_seconds", where),
                        _num(section, "restart_backoff_seconds", where, inclusive=True),
                        _int(section, "max_consecutive_failures", where))


def _port(section, key, where):
    v = _int(section, key, where)
    if v > 65535:
        raise ManifestError(f"{where}.{key} must be a TCP port")
    return v


def parse_gateway_config(doc, base_dir: str = REPO_ROOT) -> GatewayConfig:
    """Strict: no key has a default, so every operating value is an explicit, reviewed choice."""
    w = "cascade_gateway"
    _keys(doc, ("schema", "mode", "deployment_profile", "manifest", "listen", "v4", "v5", "model2",
                "canonical", "admission", "framing", "fast_path", "observability", "rollback_file",
                "probe_interval_seconds"), (), w)
    if doc["schema"] != CONFIG_SCHEMA:
        raise ManifestError(f"{w}.schema must be {CONFIG_SCHEMA!r}")
    mode = doc["mode"]
    if mode not in C.MODES:
        raise ManifestError(f"{w}.mode must be one of {C.MODES}")
    profile = doc["deployment_profile"]
    if profile not in DEPLOYMENT_PROFILES:
        raise ManifestError(f"{w}.deployment_profile must be one of {DEPLOYMENT_PROFILES}")

    s = doc["listen"]
    _keys(s, ("host", "port"), (), f"{w}.listen")
    listen_host, listen_port = _str(s, "host", f"{w}.listen"), _port(s, "port", f"{w}.listen")

    def service(name):
        section = doc[name]
        where = f"{w}.{name}"
        _keys(section, ("url", "timeout_seconds"), (), where)
        url = _str(section, "url", where)
        if not url.startswith(("http://", "https://")):
            raise ManifestError(f"{where}.url must be an http(s) URL")
        return url, _num(section, "timeout_seconds", where)

    v4_url, v4_timeout = service("v4")
    v5_url, v5_timeout = service("v5")

    model2 = _bounds(doc["model2"], base_dir, f"{w}.model2")

    s = doc["canonical"]
    _keys(s, ("worker", "workers", "max_received_body", "max_text_bytes"), (), f"{w}.canonical")
    canonical = CanonicalWorkers(_bounds(s["worker"], base_dir, f"{w}.canonical.worker"),
                                 _int(s, "workers", f"{w}.canonical"),
                                 _int(s, "max_received_body", f"{w}.canonical"),
                                 _int(s, "max_text_bytes", f"{w}.canonical"))

    s = doc["admission"]
    _keys(s, ("max_inflight", "max_waiting", "max_wait_seconds", "decision_deadline_seconds",
              "observe_max_pending"), (), f"{w}.admission")
    max_inflight = _int(s, "max_inflight", f"{w}.admission")
    max_waiting = _int(s, "max_waiting", f"{w}.admission", minimum=0)
    max_wait = _num(s, "max_wait_seconds", f"{w}.admission")
    deadline = _num(s, "decision_deadline_seconds", f"{w}.admission")
    observe_pending = _int(s, "observe_max_pending", f"{w}.admission")

    if deadline <= v5_timeout + model2.timeout_seconds:
        # A deadline inside the stage timeouts would deny on slowness that a stage still tolerates.
        raise ManifestError(f"{w}.admission.decision_deadline_seconds must exceed the V5 and Model 2 "
                            "timeouts together")

    framing = _parse_framing(doc["framing"], profile, f"{w}.framing")
    fast_path_cfg = _parse_fast_path(doc["fast_path"], profile, framing, base_dir, f"{w}.fast_path")

    s = doc["observability"]
    where = f"{w}.observability"
    _keys(s, ("decision_log", "max_log_bytes", "max_log_files", "log_queue_size", "admin_port",
              "log_wire_sha256"), (), where)
    observability = ObservabilityConfig(_path(_str(s, "decision_log", where), base_dir),
                                        _int(s, "max_log_bytes", where),
                                        _int(s, "max_log_files", where),
                                        _int(s, "log_queue_size", where),
                                        _port(s, "admin_port", where),
                                        _bool(s, "log_wire_sha256", where))
    if observability.log_wire_sha256 and profile != "lab":
        # A hash of a low-entropy request can be inverted: it is lab evidence, not a log field.
        raise ManifestError(f"{where}.log_wire_sha256 is only valid in the lab profile")

    return GatewayConfig(
        mode=mode, deployment_profile=profile,
        manifest_path=_path(_str(doc, "manifest", w), base_dir),
        listen_host=listen_host, listen_port=listen_port, v4_url=v4_url,
        v4_timeout_seconds=v4_timeout, v5_url=v5_url,
        v5_timeout_seconds=v5_timeout, model2=model2, canonical=canonical,
        max_inflight=max_inflight, max_waiting=max_waiting, max_wait_seconds=max_wait,
        decision_deadline_seconds=deadline, observe_max_pending=observe_pending, framing=framing,
        fast_path=fast_path_cfg, observability=observability,
        rollback_file=_path(_str(doc, "rollback_file", w), base_dir),
        probe_interval_seconds=_num(doc, "probe_interval_seconds", w))


def _parse_framing(s, profile, where) -> FramingConfig:
    _keys(s, ("contract", "body_size_limit", "egress_guard", "verified_evidence", "owner_ruling_ref"),
          (), where)
    contract = _str(s, "contract", where)
    body_size_limit = s["body_size_limit"]
    if not isinstance(body_size_limit, str) or not _BODY_SIZE.match(body_size_limit):
        raise ManifestError(f"{where}.body_size_limit must be a mitmproxy size such as '1m'")
    e = s["egress_guard"]
    eg = f"{where}.egress_guard"
    _keys(e, ("listen_port", "upstream_host", "upstream_port", "ticket_ttl_seconds", "max_tickets",
              "idle_timeout_seconds"), (), eg)
    egress = EgressConfig(_port(e, "listen_port", eg), _str(e, "upstream_host", eg),
                          _port(e, "upstream_port", eg), _num(e, "ticket_ttl_seconds", eg),
                          _int(e, "max_tickets", eg), _num(e, "idle_timeout_seconds", eg))
    verified = _bool(s, "verified_evidence", where)
    ref = s["owner_ruling_ref"]
    if ref is not None and (not isinstance(ref, str) or not ref.strip()):
        raise ManifestError(f"{where}.owner_ruling_ref must be null or a non-empty string")
    if verified and profile == "production" and ref is None:
        # D70 keeps FRAMING_VERIFIED pending an owner ruling; the lab can exercise the mechanism.
        raise ManifestError(f"{where}.verified_evidence in production needs owner_ruling_ref")
    return FramingConfig(contract, body_size_limit, egress, verified, ref)


def _parse_fast_path(s, profile, framing, base_dir, where) -> FastPathConfig:
    _keys(s, ("activation", "policy_file", "policy_sha256", "application_contract_ref", "audit"),
          (), where)
    activation = s["activation"]
    if activation not in FAST_PATH_ACTIVATIONS:
        raise ManifestError(f"{where}.activation must be one of {FAST_PATH_ACTIVATIONS}")
    policy_file = s["policy_file"]
    policy_sha = s["policy_sha256"]
    contract_ref = s["application_contract_ref"]

    a = s["audit"]
    aw = f"{where}.audit"
    _keys(a, ("sample_rate", "sample_salt", "queue_size", "max_queue_bytes", "workers",
              "timeout_seconds", "max_abandoned", "shutdown_drain_seconds", "max_audits_per_second",
              "burst", "yield_when_v5_inflight", "max_queue_age_seconds"), (), aw)
    rate = _num(a, "sample_rate", aw, inclusive=True)
    if rate > 1.0:
        raise ManifestError(f"{aw}.sample_rate must be in [0, 1]")
    audit = AuditConfig(rate, _str(a, "sample_salt", aw), _int(a, "queue_size", aw),
                        _int(a, "max_queue_bytes", aw), _int(a, "workers", aw),
                        _num(a, "timeout_seconds", aw), _int(a, "max_abandoned", aw),
                        _num(a, "shutdown_drain_seconds", aw, inclusive=True),
                        _num(a, "max_audits_per_second", aw), _int(a, "burst", aw),
                        _int(a, "yield_when_v5_inflight", aw),
                        _num(a, "max_queue_age_seconds", aw))

    if activation == "disabled":
        if policy_file is not None or policy_sha is not None:
            raise ManifestError(f"{where}: a disabled Fast Path carries no policy")
        return FastPathConfig(activation, None, None, contract_ref, audit)

    if not isinstance(policy_file, str) or not policy_file:
        raise ManifestError(f"{where}.policy_file is required when activation != disabled")
    if not isinstance(policy_sha, str) or not _HEX64.match(policy_sha):
        raise ManifestError(f"{where}.policy_sha256 is required when activation != disabled")
    if not framing.verified_evidence:
        raise ManifestError(f"{where}: activation needs framing.verified_evidence, otherwise "
                            "every request would be CONTINUE and the policy would never apply")
    if activation == "experimental_fixture" and profile != "lab":
        raise ManifestError(f"{where}: an experimental fixture only runs in the lab profile")
    if activation == "production":
        if profile != "production":
            raise ManifestError(f"{where}: activation production needs the production profile")
        if not isinstance(contract_ref, str) or not contract_ref.strip():
            raise ManifestError(f"{where}.application_contract_ref is required in production: "
                                "a positive policy needs the real application's contract")
    return FastPathConfig(activation, _path(policy_file, base_dir), policy_sha, contract_ref, audit)


def resolve_fast_path_policy(cfg: FastPathConfig) -> Optional[fp.Policy]:
    """The policy the router may use, or None when the Fast Path is disabled. A policy that does not
    match its pinned digest, or whose status does not fit the activation, raises: an operator who
    asked for a Fast Path must not silently get another policy or none."""
    if cfg.activation == "disabled":
        return None
    try:
        policy = fp.load_policy(cfg.policy_file)
    except (OSError, fp.PolicyError) as exc:
        raise ManifestError(f"fast_path policy not usable ({type(exc).__name__})") from None
    if policy.sha256 != cfg.policy_sha256:
        raise ManifestError("fast_path policy does not match policy_sha256")
    if cfg.activation == "production" and policy.status != "APPROVED":
        raise ManifestError("fast_path activation production needs an APPROVED policy")
    if cfg.activation == "experimental_fixture" and policy.status == "APPROVED":
        raise ManifestError("an APPROVED policy is not an experimental fixture")
    return policy


def load_gateway_config(path: str, base_dir: str = REPO_ROOT) -> GatewayConfig:
    import yaml
    try:
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
    except OSError as exc:
        raise ManifestError(f"gateway config unreadable ({type(exc).__name__})") from None
    if not isinstance(doc, dict) or "cascade_gateway" not in doc:
        raise ManifestError("gateway config must hold a cascade_gateway mapping")
    return parse_gateway_config(doc["cascade_gateway"], base_dir)


def validate_consistency(cfg: GatewayConfig, manifest: ModelManifest) -> tuple:
    """Cross-document checks. Closed reasons; empty means the two documents fit together."""
    problems = list(enablement_problems(manifest, cfg.mode, cfg.deployment_profile))
    if cfg.canonical.max_received_body > manifest.canonical.max_decoded_body:
        problems.append("max_received_body_over_max_decoded_body")
    return tuple(problems)
