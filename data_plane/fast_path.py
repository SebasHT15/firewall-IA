"""
firewall-IA — Fast Path eligibility, SHADOW ONLY (Hybrid Architecture; PROPOSED, no decision record yet).

    validated canonical request -> Fast Path -> FAST_ALLOW | CONTINUE -> (Analyzer -> Model 2 -> V5)

This module answers one question about one request: "could the Fast Path hypothetically
let it skip the model stages?". It only OBSERVES. Nothing in the gateway reads the
answer: V4 still decides every request, enforcement and fail-closed are untouched
(D4, D25, D34, D43). `FAST_ALLOW` here is a recorded hypothesis, never a permission.

CONSERVATIVE BY CONSTRUCTION
- The absence of suspicious features is NOT evidence. There is no suspicion score, no weight
  and no threshold anywhere in this module. FAST_ALLOW needs POSITIVE, closed-world evidence:
  the request must match, completely, a rule of an owner-supplied policy that declares the
  application context explicitly (D57: "a policy that depends on application context must
  state that context explicitly"). No policy, or no full match, means CONTINUE.
- Eligibility is evaluated only AFTER the protocol-validation prerequisites hold: a
  `canonical-request/v1` ACCEPT for this very request and framing evidence that is VERIFIED
  by a project control. When either is unavailable (today, in the gateway: both are), the
  answer is CONTINUE with the unmet prerequisites, and the rules are not even looked at.
- Every doubt is CONTINUE: any failure, any malformed or ambiguous input, any exception.
- Headers are not covered by the canonical text (it carries Content-Type only), yet V4
  reads them. So the Fast Path inspects them itself: every header must be listed by the
  rule with a closed value grammar, otherwise CONTINUE.
- The only grammars are `enum` (exact strings) and `uint` (bounded decimal digits).
  Alphabet-based "looks harmless" classes are deliberately not offered: a value made of
  letters and digits can still be an attack (a command name, an internal address).
- v1 scope: GET and HEAD, origin-form target, no body, no percent-encoding, no fragment,
  no Transfer-Encoding, no content coding, no canonical signal.

Standard library only (D33): importable in the data plane environment.
"""

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Optional

CONTRACT_ID = "fast-path/v1-shadow"
POLICY_SCHEMA = "fast-path-policy/v1"

# Values of the canonical-request/v1 contract that this module reads from a result object. They
# are repeated here, not imported, because the gateway must not import the contract before it is
# integrated (D56; tests/test_canonical_request.py guards that). A test compares each one with
# canonical_request.py so they cannot drift.
CANONICAL_CONTRACT_ID = "canonical-request/v1"
CANONICAL_ACCEPT = "ACCEPT"
CANONICAL_SIZE_WITHIN = "WITHIN_BUDGET"

FAST_ALLOW = "FAST_ALLOW"
CONTINUE = "CONTINUE"
DECISIONS = (FAST_ALLOW, CONTINUE)          # no BLOCK exists in this contract

# Framing evidence statuses. Only VERIFIED can pass. VERIFIED must come from a project-owned,
# tested wire-level control (R1 of canonical-request/v1 §5.3); mitmproxy's own header
# validation is third-party behaviour the project neither pins nor tests (D57).
FRAMING_VERIFIED = "VERIFIED"
FRAMING_UNVERIFIED = "UNVERIFIED"
FRAMING_UNAVAILABLE = "UNAVAILABLE"
FRAMING_STATUSES = (FRAMING_VERIFIED, FRAMING_UNVERIFIED, FRAMING_UNAVAILABLE)

SAFE_METHODS = ("GET", "HEAD")
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_DIGITS = frozenset("0123456789")
# Never expressible in a policy header map (they change message framing or semantics).
_FORBIDDEN_HEADERS = frozenset({"transfer-encoding", "content-encoding", "upgrade", "expect",
                                "te", "trailer", "proxy-authorization"})
MAX_UINT_DIGITS = 9

# Closed list of reason codes. A CONTINUE carries at least one; a FAST_ALLOW carries none.
REASONS = (
    # prerequisites (protocol validation)
    "POLICY_UNAVAILABLE", "POLICY_INVALID",
    "FRAMING_UNAVAILABLE", "FRAMING_UNVERIFIED",
    "CANONICAL_UNAVAILABLE", "CANONICAL_NOT_ACCEPTED", "CANONICAL_MISMATCH",
    # exclusions drawn from the canonical result
    "SIGNALS_PRESENT", "TARGET_FORM_NOT_ORIGIN", "CONTENT_CODING_PRESENT",
    "TRANSFER_ENCODING_PRESENT", "SIZE_NOT_WITHIN_BUDGET",
    # policy matching
    "NO_RULE_MATCHED", "BODY_PRESENT", "HTTP_VERSION_NOT_ALLOWED", "METHOD_NOT_ALLOWED",
    "TARGET_MALFORMED", "TARGET_NOT_ORIGIN_FORM", "FRAGMENT_PRESENT", "PERCENT_ENCODING_PRESENT",
    "PATH_NOT_MATCHED", "QUERY_MALFORMED", "QUERY_PARAM_UNKNOWN", "QUERY_PARAM_REPEATED",
    "QUERY_PARAM_MISSING", "QUERY_VALUE_NOT_ALLOWED",
    "HEADER_NOT_ALLOWED", "HEADER_REPEATED", "HEADER_VALUE_NOT_ALLOWED",
    "EVALUATION_ERROR",
)


# ───────────────────────────── policy ─────────────────────────────
class PolicyError(ValueError):
    """The policy is not acceptable. Never partially applied."""


@dataclass(frozen=True)
class Grammar:
    kind: str                      # "enum" | "uint"
    values: frozenset = frozenset()
    max_digits: int = 0

    def matches(self, value: str) -> bool:
        if self.kind == "enum":
            return value in self.values
        if value == "" or len(value) > self.max_digits or not all(c in _DIGITS for c in value):
            return False
        return value == "0" or value[0] != "0"          # no leading zeros


@dataclass(frozen=True)
class Rule:
    rule_id: str
    methods: tuple
    path: tuple                    # segments: str literal | Grammar
    query: tuple                   # ((name, Grammar), ...)
    required_query: frozenset
    headers: tuple                 # ((lowercase name, Grammar), ...)


@dataclass(frozen=True)
class Policy:
    policy_id: str
    status: str                    # PROPOSED | APPROVED (APPROVED needs an approval record)
    http_versions: tuple
    rules: tuple
    sha256: str


def _grammar(spec, *, header: bool, where: str) -> Grammar:
    if not isinstance(spec, dict) or "type" not in spec:
        raise PolicyError(f"{where}: grammar must be an object with 'type'")
    kind = spec["type"]
    if kind == "enum":
        if set(spec) != {"type", "values"}:
            raise PolicyError(f"{where}: enum takes exactly 'type' and 'values'")
        values = spec["values"]
        if not isinstance(values, list) or not values:
            raise PolicyError(f"{where}: enum values must be a non-empty list")
        for v in values:
            if not isinstance(v, str) or v == "":
                raise PolicyError(f"{where}: enum value {v!r} must be a non-empty string")
            ok = (all(0x20 <= ord(c) <= 0x7e for c in v) if header
                  else all(c in _UNRESERVED for c in v))
            if not ok:
                raise PolicyError(f"{where}: enum value {v!r} has a character outside the "
                                  f"{'printable ASCII' if header else 'unreserved'} set")
        return Grammar("enum", values=frozenset(values))
    if kind == "uint":
        if set(spec) != {"type", "max_digits"}:
            raise PolicyError(f"{where}: uint takes exactly 'type' and 'max_digits'")
        n = spec["max_digits"]
        if isinstance(n, bool) or not isinstance(n, int) or not 1 <= n <= MAX_UINT_DIGITS:
            raise PolicyError(f"{where}: max_digits must be an int in 1..{MAX_UINT_DIGITS}")
        return Grammar("uint", max_digits=n)
    raise PolicyError(f"{where}: unknown grammar type {kind!r} (only enum, uint)")


def _name(value, where):
    if (not isinstance(value, str) or value == ""
            or any(c not in _UNRESERVED for c in value)):
        raise PolicyError(f"{where}: {value!r} must be a non-empty string of unreserved characters")
    return value


def parse_policy(doc) -> Policy:
    """Validate a policy document and freeze it. Unknown keys, a wrong type or any value outside
    the closed grammar raises PolicyError; there is no lenient mode."""
    if not isinstance(doc, dict):
        raise PolicyError("policy must be an object")
    allowed = {"schema", "policy_id", "status", "approval", "canonical_contract",
               "http_versions", "rules"}
    unknown = set(doc) - allowed
    if unknown:
        raise PolicyError(f"unknown policy keys: {sorted(unknown)}")
    if doc.get("schema") != POLICY_SCHEMA:
        raise PolicyError(f"schema must be {POLICY_SCHEMA!r}")
    if doc.get("canonical_contract") != CANONICAL_CONTRACT_ID:
        raise PolicyError(f"canonical_contract must be {CANONICAL_CONTRACT_ID!r}")
    policy_id = doc.get("policy_id")
    if not isinstance(policy_id, str) or not policy_id.strip():
        raise PolicyError("policy_id must be a non-empty string")
    status = doc.get("status")
    if status not in ("PROPOSED", "APPROVED"):
        raise PolicyError("status must be PROPOSED or APPROVED")
    if status == "APPROVED":
        appr = doc.get("approval")
        if (not isinstance(appr, dict)
                or any(not isinstance(appr.get(k), str) or not appr[k].strip()
                       for k in ("approved_by", "date", "decision_ref"))):
            raise PolicyError("an APPROVED policy needs approval.approved_by/date/decision_ref")
    versions = doc.get("http_versions", ["HTTP/1.1"])
    if (not isinstance(versions, list) or not versions
            or any(v not in ("HTTP/1.1", "HTTP/2.0") for v in versions)):
        raise PolicyError("http_versions must be a non-empty list drawn from HTTP/1.1, HTTP/2.0")
    rules_doc = doc.get("rules")
    if not isinstance(rules_doc, list) or not rules_doc:
        raise PolicyError("rules must be a non-empty list")
    rules, seen = [], set()
    for i, r in enumerate(rules_doc):
        where = f"rules[{i}]"
        if not isinstance(r, dict) or set(r) - {"id", "methods", "path", "query",
                                                 "required_query", "headers"}:
            raise PolicyError(f"{where}: unknown or missing keys")
        rid = _name(r.get("id"), f"{where}.id")
        if rid in seen:
            raise PolicyError(f"{where}: duplicate rule id {rid!r}")
        seen.add(rid)
        methods = r.get("methods")
        if (not isinstance(methods, list) or not methods
                or any(m not in SAFE_METHODS for m in methods)):
            raise PolicyError(f"{where}.methods must be a non-empty list drawn from {SAFE_METHODS}")
        path_doc = r.get("path")
        if not isinstance(path_doc, list):
            raise PolicyError(f"{where}.path must be a list of segments ([] is '/')")
        segments = []
        for j, seg in enumerate(path_doc):
            if isinstance(seg, str):
                if _name(seg, f"{where}.path[{j}]") in (".", ".."):
                    raise PolicyError(f"{where}.path[{j}]: dot segments are not allowed")
                segments.append(seg)
            else:
                segments.append(_grammar(seg, header=False, where=f"{where}.path[{j}]"))
        query = []
        for qn, spec in (r.get("query") or {}).items():
            query.append((_name(qn, f"{where}.query name"),
                          _grammar(spec, header=False, where=f"{where}.query[{qn}]")))
        required = r.get("required_query", [])
        names = {q for q, _ in query}
        if not isinstance(required, list) or any(x not in names for x in required):
            raise PolicyError(f"{where}.required_query must list declared query names")
        headers = []
        for hn, spec in (r.get("headers") or {}).items():
            low = hn.lower() if isinstance(hn, str) else hn
            if (not isinstance(low, str) or low == "" or low in _FORBIDDEN_HEADERS
                    or any(c not in _UNRESERVED for c in low)):
                raise PolicyError(f"{where}.headers: {hn!r} is not an allowed header name")
            headers.append((low, _grammar(spec, header=True, where=f"{where}.headers[{hn}]")))
        if len({h for h, _ in headers}) != len(headers):
            raise PolicyError(f"{where}.headers: names repeat after lowercasing")
        rules.append(Rule(rid, tuple(methods), tuple(segments), tuple(query),
                          frozenset(required), tuple(headers)))
    digest = hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":"),
                                       ensure_ascii=True).encode("ascii")).hexdigest()
    return Policy(policy_id, status, tuple(versions), tuple(rules), digest)


def load_policy(path: str) -> Policy:
    """Read a policy file (JSON). Raises PolicyError / OSError; the caller decides what a bad
    policy means (the gateway adapter treats it as 'no policy': CONTINUE, never a crash)."""
    with open(path, encoding="utf-8") as fh:
        try:
            doc = json.load(fh)
        except ValueError as exc:
            raise PolicyError(f"not valid JSON: {exc.__class__.__name__}") from None
    return parse_policy(doc)


# ───────────────────────────── evidence and decision ─────────────────────────────
@dataclass(frozen=True)
class FramingEvidence:
    status: str = FRAMING_UNAVAILABLE
    detail: str = ""

    def __post_init__(self):
        if self.status not in FRAMING_STATUSES:
            raise ValueError(f"framing status must be one of {FRAMING_STATUSES}")


@dataclass(frozen=True)
class FastPathInput:
    """One request as the gateway saw it, plus the two pieces of protocol evidence.

    method/target/headers/body are the RAW received parts (bytes, received order and case).
    `canonical` is the `canonical-request/v1` result for this same request, or None when the
    gateway cannot produce it. `framing` is wire-level framing evidence."""
    method: bytes
    target: bytes
    http_version: str
    headers: tuple
    body: bytes
    canonical: Optional[Any]       # a canonical-request/v1 CanonicalResult, duck-typed
    framing: FramingEvidence = field(default_factory=FramingEvidence)

    def __post_init__(self):
        if not isinstance(self.method, bytes) or not isinstance(self.target, bytes):
            raise TypeError("method and target must be bytes")
        if not isinstance(self.http_version, str) or not isinstance(self.body, bytes):
            raise TypeError("http_version must be str and body bytes")
        for pair in self.headers:
            if (not isinstance(pair, tuple) or len(pair) != 2
                    or not all(isinstance(x, bytes) for x in pair)):
                raise TypeError("headers must be (bytes, bytes) pairs")


@dataclass(frozen=True)
class FastPathDecision:
    decision: str
    reasons: tuple = ()
    rule_id: Optional[str] = None
    policy_id: Optional[str] = None
    policy_sha256: Optional[str] = None
    policy_status: Optional[str] = None
    enforced: bool = False         # always False in this contract version

    def __post_init__(self):
        if self.decision not in DECISIONS:
            raise ValueError(f"decision must be one of {DECISIONS}, got {self.decision!r}")
        if self.enforced:
            raise ValueError("this contract version is shadow-only: enforced must be False")
        if any(r not in REASONS for r in self.reasons):
            raise ValueError(f"unknown reason in {self.reasons!r}")
        if self.decision == FAST_ALLOW and (self.reasons or not self.rule_id):
            raise ValueError("FAST_ALLOW carries a rule id and no reasons")
        if self.decision == CONTINUE and not self.reasons:
            raise ValueError("CONTINUE carries at least one reason")


def _cont(policy, *reasons):
    return FastPathDecision(CONTINUE, tuple(dict.fromkeys(reasons)),
                            policy_id=getattr(policy, "policy_id", None),
                            policy_sha256=getattr(policy, "sha256", None),
                            policy_status=getattr(policy, "status", None))


# ───────────────────────────── evaluation ─────────────────────────────
def _prerequisites(inp: FastPathInput, policy) -> list:
    """Protocol-validation prerequisites. All unmet ones are reported, so an integration gap is
    visible in full; rules are evaluated only when this list is empty."""
    unmet = []
    if policy is None:
        unmet.append("POLICY_UNAVAILABLE")
    if inp.framing.status == FRAMING_UNAVAILABLE:
        unmet.append("FRAMING_UNAVAILABLE")
    elif inp.framing.status != FRAMING_VERIFIED:
        unmet.append("FRAMING_UNVERIFIED")
    if inp.canonical is None:
        unmet.append("CANONICAL_UNAVAILABLE")
    elif getattr(inp.canonical, "outcome", None) != CANONICAL_ACCEPT:
        unmet.append("CANONICAL_NOT_ACCEPTED")
    return unmet


def _canonical_exclusions(inp: FastPathInput) -> list:
    res, out = inp.canonical, []
    audit = res.audit
    # The canonical result must describe THIS request, not another one.
    # The first line of the canonical text is `METHOD TARGET HTTP/1.1`; split on "\n" only.
    try:
        line = res.text.split("\n", 1)[0]
        method, _, rest = line.partition(" ")
        target = rest[:-len(" HTTP/1.1")] if rest.endswith(" HTTP/1.1") else None
        if (target is None or method.encode("ascii") != inp.method
                or target.encode("utf-8") != inp.target):
            out.append("CANONICAL_MISMATCH")
    except (ValueError, TypeError, AttributeError, UnicodeError):
        out.append("CANONICAL_MISMATCH")
    if res.signals:
        out.append("SIGNALS_PRESENT")
    if audit.get("target_form") != "origin":
        out.append("TARGET_FORM_NOT_ORIGIN")
    if any(c != "identity" for c in audit.get("content_codings", ())):
        out.append("CONTENT_CODING_PRESENT")
    if audit.get("framing", {}).get("transfer_encoding"):
        out.append("TRANSFER_ENCODING_PRESENT")
    if res.size != CANONICAL_SIZE_WITHIN:
        out.append("SIZE_NOT_WITHIN_BUDGET")
    return out


def _ascii_text(data: bytes, low: int, high: int):
    if any(not low <= b <= high for b in data):
        return None
    return data.decode("ascii")


def _match_rule(rule: Rule, inp: FastPathInput, versions) -> Optional[str]:
    """None when the rule matches the whole request; otherwise one reason code."""
    if inp.body:
        return "BODY_PRESENT"
    if inp.http_version not in versions:
        return "HTTP_VERSION_NOT_ALLOWED"
    method = _ascii_text(inp.method, 0x21, 0x7e)
    if method is None or method not in rule.methods:
        return "METHOD_NOT_ALLOWED"
    target = _ascii_text(inp.target, 0x21, 0x7e)
    if target is None or not target.startswith("/") or target.startswith("//"):
        return "TARGET_MALFORMED" if target is None else "TARGET_NOT_ORIGIN_FORM"
    if "#" in target:
        return "FRAGMENT_PRESENT"
    if "%" in target:
        return "PERCENT_ENCODING_PRESENT"
    path, has_query, query = target.partition("?")
    segments = [] if path == "/" else path[1:].split("/")
    if len(segments) != len(rule.path):
        return "PATH_NOT_MATCHED"
    for seg, spec in zip(segments, rule.path):
        if isinstance(spec, str):
            if seg != spec:
                return "PATH_NOT_MATCHED"
        elif not spec.matches(seg):
            return "PATH_NOT_MATCHED"
    declared = dict(rule.query)
    seen = set()
    if has_query:
        if query == "":
            return "QUERY_MALFORMED"
        for pair in query.split("&"):
            name, eq, value = pair.partition("=")
            if not eq or "=" in value or name == "":
                return "QUERY_MALFORMED"
            if name not in declared:
                return "QUERY_PARAM_UNKNOWN"
            if name in seen:
                return "QUERY_PARAM_REPEATED"
            seen.add(name)
            if not declared[name].matches(value):
                return "QUERY_VALUE_NOT_ALLOWED"
    if not rule.required_query <= seen:
        return "QUERY_PARAM_MISSING"
    allowed_headers = dict(rule.headers)
    seen_headers = set()
    for raw_name, raw_value in inp.headers:
        name = _ascii_text(raw_name, 0x21, 0x7e)
        value = _ascii_text(raw_value, 0x20, 0x7e)
        if name is None:
            return "HEADER_NOT_ALLOWED"
        low = name.lower()
        if low not in allowed_headers:
            return "HEADER_NOT_ALLOWED"
        if low in seen_headers:
            return "HEADER_REPEATED"
        seen_headers.add(low)
        if value is None or not allowed_headers[low].matches(value.strip(" ")):
            return "HEADER_VALUE_NOT_ALLOWED"
    return None


def evaluate(inp: FastPathInput, policy: Optional[Policy]) -> FastPathDecision:
    """The Fast Path decision for one request. Pure. FAST_ALLOW only when the prerequisites hold,
    no exclusion applies and one policy rule matches the whole request; CONTINUE otherwise."""
    unmet = _prerequisites(inp, policy)
    if unmet:
        return _cont(policy, *unmet)
    excluded = _canonical_exclusions(inp)
    if excluded:
        return _cont(policy, *excluded)
    for rule in policy.rules:
        if _match_rule(rule, inp, policy.http_versions) is None:
            return FastPathDecision(FAST_ALLOW, rule_id=rule.rule_id, policy_id=policy.policy_id,
                                    policy_sha256=policy.sha256, policy_status=policy.status)
    # One summary reason; the per-rule reasons would let a log reader enumerate the policy.
    return _cont(policy, "NO_RULE_MATCHED")


def match_reasons(inp: FastPathInput, policy: Policy) -> tuple:
    """Per-rule reason of the policy-matching stage, `((rule_id, reason | None), ...)`, for tests
    and offline analysis only. Not logged: it would let a log reader enumerate the policy. It
    skips the prerequisites and exclusions, so it says nothing about eligibility by itself."""
    return tuple((r.rule_id, _match_rule(r, inp, policy.http_versions)) for r in policy.rules)


def safe_evaluate(inp, policy) -> FastPathDecision:
    """`evaluate` that cannot raise: any error, including a wrong input type, is CONTINUE."""
    try:
        return evaluate(inp, policy)
    except Exception:
        return _cont(policy, "EVALUATION_ERROR")
