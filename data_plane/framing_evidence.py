"""
firewall-IA — HTTP/1.1 framing OBSERVATION evidence (issue #68, Track A; D70).

SHADOW / OBSERVE-ONLY, DEFAULT-OFF. This module produces a `FramingObservation` to be logged and
NOTHING else. It decides no enforcement, no forwarding and no Fast Path eligibility. V4 via
`/classify` stays the only enforced authority (D4, D25, D34, D43, D69). The gateway wiring that calls
`sample_profile`/`evaluate`/`format_record` is the coordinator's (`data_plane.py`); this module is
pure and dependency-light.

WHAT `PROFILE_MATCHED` MEANS — AND DOES NOT MEAN
  `PROFILE_MATCHED` means ONLY: "the sampled mitmproxy runtime profile is the documented tested one,
  and the observed canonical snapshot met the defined conditions (HTTP/1.1 origin/asterisk, complete
  body, valid reply correlation, unchanged relevant-profile generation between capture and reply, and
  a canonical OK + ACCEPT for THIS snapshot)." It is NOT a claim that the request was VERIFIED, that it
  is safe to forward, that it is Fast-Path eligible, or that the observed snapshot is byte-equivalent
  to what the upstream will parse on the wire. There is no project-owned wire-level framing control in
  this slice; runtime framing stays UNAVAILABLE/UNVERIFIED for the Fast Path (D57, D69). In particular:
    * A bare-LF request MAY reach `PROFILE_MATCHED` under these limited semantics (bare-LF is a
      wire-level fact that `canonical_request` never sees, so canonicalize can still ACCEPT it) — yet
      wire verification remains unavailable. `PROFILE_MATCHED` does not attest the wire.
    * An obsolete-line-folding request that canonicalize rejects (canonical `R4`) surfaces as
      `UNATTESTABLE` with reason `CANONICAL_REJECT`; it is NEVER relabelled as residual-framing success.

CONSERVATIVE BY CONSTRUCTION
  `evaluate` is the ONLY producer of `PROFILE_MATCHED`, and it is conservative: anything uncertain is
  `UNATTESTABLE` (in scope, but no positive observation can be established) or `UNAVAILABLE` (the
  observation could not be run at all). A canonical `REJECT` (status OK + outcome REJECT) is a
  SUCCESSFUL observation of a reject — a residual-framing failure when the reject is `R1`/`R2`, and
  still not a success for any earlier reject (`R4`/`R5`/`R6`/`R7`/`R8`); it is NEVER collapsed into a
  worker-infrastructure failure. A worker timeout, a dropped/oversize snapshot or a missing reply does
  NOT prove residual success either. This module re-runs NO framing rule and canonicalizes nothing; it
  reads the already-produced `CanonicalObservation`. It handles NO request bytes and computes NO
  content hash anywhere.

GENERATION DETECTION. `RelevantProfileGeneration.observe(profile)` bumps a monotonic counter whenever
the attestation-relevant fingerprint changes, so a config that goes A→B→A is detected as TWO bumps
(plain dict/value equality would miss the change-back). `evaluate` compares the generation sampled at
capture with the one at reply; any drift is `UNATTESTABLE` (`GENERATION_DRIFT`).

Standard library only (D33), plus the sibling `canonical_observer` status constants and
`canonical_adapter` form/scope constants (both stdlib-only at import time). The three canonical
outcome tokens are mirrored here as literals (like `fast_path.py`) so this module does not force an
import of the contract itself.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Optional

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import canonical_adapter as adapter  # noqa: E402  (form + scope constants only)
import canonical_observer as cobs  # noqa: E402  (observation status constants + CanonicalObservation)

CONTRACT_ID = "framing-observation/v1-shadow"

# Canonical-request/v1 outcome tokens, mirrored as literals (not imported) so this pure module does
# not pull in the contract; a test can pin them against canonical_request if it owns that guard.
CANONICAL_ACCEPT = "ACCEPT"
CANONICAL_REJECT = "REJECT"
CANONICAL_UNSUPPORTED = "UNSUPPORTED"


# ── field-unavailable sentinel ────────────────────────────────────────────────
class _Unavailable:
    """A single, hashable, comparable-by-identity marker for a profile field that could not be read.
    It is deliberately NOT any real option value (never None, never a bool, never a string), so it
    can never be mistaken for the tested value."""
    __slots__ = ()

    def __repr__(self) -> str:  # appears only in debugging, never in a log line
        return "UNAVAILABLE_FIELD"


UNAVAILABLE_FIELD = _Unavailable()
_MISSING = object()   # getattr default: the option is absent from this mitmproxy options object


# ── tested lab profile (EFFECTIVE runtime values, not config-file intent) ─────
# `mitmproxy 12.2.3; validate_inbound_headers=True; HTTP/2 disabled; stream_large_bodies=None;
#  body_size_limit=None; mode=reverse-proxy to a dynamic loopback port; connection_strategy=lazy`.
TESTED_MITMPROXY_VERSION = "12.2.3"
TESTED_VALIDATE_INBOUND_HEADERS = True
TESTED_HTTP2 = False                      # HTTP/2 disabled in the lab
TESTED_STREAM_LARGE_BODIES = None
TESTED_BODY_SIZE_LIMIT = None
# The dynamic loopback port is represented as a CLOSED marker, never the literal port, and never a
# match against an arbitrary deployment destination.
MODE_REVERSE_LOOPBACK = "reverse_proxy:loopback_dynamic_port"
TESTED_MODE = MODE_REVERSE_LOOPBACK
TESTED_CONNECTION_STRATEGY = "lazy"

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})


# ── STATUS vocabulary (closed) ────────────────────────────────────────────────
PROFILE_MATCHED = "PROFILE_MATCHED"
UNATTESTABLE = "UNATTESTABLE"
UNAVAILABLE = "UNAVAILABLE"
STATUS = (PROFILE_MATCHED, UNATTESTABLE, UNAVAILABLE)

# ── REASON vocabulary (closed) ────────────────────────────────────────────────
PROFILE_NOT_TESTED = "PROFILE_NOT_TESTED"
PROFILE_FIELD_UNAVAILABLE = "PROFILE_FIELD_UNAVAILABLE"
VALIDATE_INBOUND_HEADERS_OFF = "VALIDATE_INBOUND_HEADERS_OFF"
GENERATION_DRIFT = "GENERATION_DRIFT"
HTTP_VERSION_NOT_11 = "HTTP_VERSION_NOT_11"
CANONICAL_NOT_ACCEPTED = "CANONICAL_NOT_ACCEPTED"
CANONICAL_REJECT_REASON = "CANONICAL_REJECT"
CANONICAL_UNSUPPORTED_REASON = "CANONICAL_UNSUPPORTED"
CANONICAL_UNAVAILABLE = "CANONICAL_UNAVAILABLE"
BODY_UNAVAILABLE = "BODY_UNAVAILABLE"
TARGET_FORM_OUT_OF_SCOPE = "TARGET_FORM_OUT_OF_SCOPE"
HTTP_VERSION_OUT_OF_SCOPE = "HTTP_VERSION_OUT_OF_SCOPE"
NO_CANONICAL_OBSERVER = "NO_CANONICAL_OBSERVER"
WORKER_UNAVAILABLE = "WORKER_UNAVAILABLE"
WORKER_TIMEOUT = "WORKER_TIMEOUT"
WORKER_BUSY = "WORKER_BUSY"
SNAPSHOT_DROPPED = "SNAPSHOT_DROPPED"
ADAPTER_ERROR = "ADAPTER_ERROR"
REASON = (
    PROFILE_NOT_TESTED, PROFILE_FIELD_UNAVAILABLE, VALIDATE_INBOUND_HEADERS_OFF, GENERATION_DRIFT,
    HTTP_VERSION_NOT_11, CANONICAL_NOT_ACCEPTED, CANONICAL_REJECT_REASON,
    CANONICAL_UNSUPPORTED_REASON, CANONICAL_UNAVAILABLE, BODY_UNAVAILABLE, TARGET_FORM_OUT_OF_SCOPE,
    HTTP_VERSION_OUT_OF_SCOPE, NO_CANONICAL_OBSERVER, WORKER_UNAVAILABLE, WORKER_TIMEOUT, WORKER_BUSY,
    SNAPSHOT_DROPPED, ADAPTER_ERROR,
)

# The ONLY received version that can reach PROFILE_MATCHED.
TESTED_HTTP_VERSION = "HTTP/1.1"

_IN_SCOPE_FORMS = (adapter.FORM_ORIGIN, adapter.FORM_ASTERISK)


# ── the runtime profile ───────────────────────────────────────────────────────
@dataclass(frozen=True)
class FramingProfile:
    """The EFFECTIVE mitmproxy runtime values that bear on whether the lab's HTTP/1.1 framing
    behaviour is the tested one. Each field holds either the read value or `UNAVAILABLE_FIELD`.
    Never carries a request byte.

    `mode` is the PUBLIC closed marker (e.g. `reverse_proxy:loopback_dynamic_port`) — port- and
    destination-free, safe to compare for the tested CLASS and safe to log. `mode_fingerprint` is an
    INTERNAL component (the concrete effective transport+host+port, or a closed token) used ONLY in
    `relevant_fingerprint()` for generation-change detection; it is NEVER logged and never compared
    for the tested class, so a transport/destination/port change during an observation bumps the
    generation even though the public class marker may be unchanged."""
    mitmproxy_version: object
    validate_inbound_headers: object
    http2: object
    stream_large_bodies: object
    body_size_limit: object
    mode: object                 # PUBLIC closed marker (loggable; port/destination-free)
    connection_strategy: object
    mode_fingerprint: object = None   # INTERNAL concrete transport+host+port; NEVER logged

    def has_unavailable_field(self) -> bool:
        return any(v is UNAVAILABLE_FIELD for v in (
            self.mitmproxy_version, self.validate_inbound_headers, self.http2,
            self.stream_large_bodies, self.body_size_limit, self.mode, self.connection_strategy))

    def is_tested_profile(self) -> bool:
        """True iff EVERY field equals the documented tested profile. Uses the PUBLIC `mode` class
        marker (port-independent), NOT the internal fingerprint, so across-run dynamic ports still
        share the tested class. An unavailable field can never equal the tested value, so it makes
        this False (never silently 'tested')."""
        return (self.mitmproxy_version == TESTED_MITMPROXY_VERSION
                and self.validate_inbound_headers is TESTED_VALIDATE_INBOUND_HEADERS
                and self.http2 is TESTED_HTTP2
                and self.stream_large_bodies is TESTED_STREAM_LARGE_BODIES
                and self.body_size_limit is TESTED_BODY_SIZE_LIMIT
                and self.mode == TESTED_MODE
                and self.connection_strategy == TESTED_CONNECTION_STRATEGY)

    def relevant_fingerprint(self) -> tuple:
        """The hashable tuple of attestation-relevant fields, used ONLY for generation-change
        detection. Never logged as values. Uses the INTERNAL `mode_fingerprint` (concrete
        transport+host+port), so a transport/destination/port change bumps the generation."""
        return (self.mitmproxy_version, self.validate_inbound_headers, self.http2,
                self.stream_large_bodies, self.body_size_limit, self.mode_fingerprint,
                self.connection_strategy)


def _canon_mode(value) -> tuple:
    """Map an EFFECTIVE mitmproxy `mode` option to (PUBLIC marker, INTERNAL fingerprint).

    Tested CLASS (public marker `reverse_proxy:loopback_dynamic_port`) requires ALL of: a single
    mode; `reverse`; transport EXACTLY `http` (NOT https/http3/other); and a destination that is a
    loopback IP LITERAL (127.0.0.0/8 or ::1) or EXACTLY `localhost`. A DNS lookalike such as
    `127.synthetic.invalid` is NOT a literal and is rejected; no DNS resolution is ever done; a bare
    lexical `127.` prefix is insufficient. Any other shape yields a non-tested public token.

    The INTERNAL fingerprint carries the concrete effective transport+host+port (or a closed token)
    so a transport/destination/port change bumps the generation even within the tested class. It is
    NEVER logged. An unreadable value → (UNAVAILABLE_FIELD, UNAVAILABLE_FIELD). Never raises."""
    try:
        if value is _MISSING or value is UNAVAILABLE_FIELD:
            return UNAVAILABLE_FIELD, UNAVAILABLE_FIELD
        seq = list(value) if isinstance(value, (list, tuple)) else [value]
        if len(seq) != 1:
            return "multiple_modes", ("multiple_modes", tuple(_safe_str(s) for s in seq))
        spec = seq[0]
        if not isinstance(spec, str) or not spec:
            return UNAVAILABLE_FIELD, UNAVAILABLE_FIELD
        head, sep, rest = spec.partition(":")
        head = head.strip().lower()
        if not head.startswith("reverse"):
            return head, (head,)          # 'regular', 'transparent', 'socks5', ... (not tested)
        scheme, host, port = _parse_reverse_dest(rest if sep else "")
        fingerprint = ("reverse", scheme, host, port)
        if scheme == "http" and _is_loopback_literal(host):
            return MODE_REVERSE_LOOPBACK, fingerprint
        return "reverse_proxy:other", fingerprint
    except Exception:        # noqa: BLE001 — sampling must never raise
        return UNAVAILABLE_FIELD, UNAVAILABLE_FIELD


def _safe_str(value) -> str:
    try:
        return value if isinstance(value, str) else repr(value)
    except Exception:        # noqa: BLE001
        return "<?>"


def _parse_reverse_dest(rest: str) -> tuple:
    """Parse the upstream destination of a reverse mode spec into (scheme, host, port). `rest` is
    everything after `reverse:` — e.g. 'http://127.0.0.1:8080' (an optional '@bind' suffix is
    ignored). Lexical only; never resolves DNS or connects."""
    from urllib.parse import urlparse
    spec = (rest or "").strip().split("@", 1)[0]     # drop any @bind-address suffix
    if "://" not in spec:
        spec = "//" + spec.lstrip("/")
    parsed = urlparse(spec)
    scheme = (parsed.scheme or "").strip().lower()
    host = (parsed.hostname or "").strip()
    try:
        port = parsed.port
    except ValueError:        # malformed port text
        port = None
    return scheme, host, port


def _is_loopback_literal(host: str) -> bool:
    """True iff `host` is a loopback IP LITERAL (127.0.0.0/8 or ::1) or EXACTLY 'localhost'. A DNS
    name (even one starting '127.') is NOT a literal and returns False. No resolution is performed."""
    try:
        import ipaddress
        h = (host or "").strip()
        if h.lower() == "localhost":
            return True
        if h.startswith("[") and h.endswith("]"):
            h = h[1:-1]
        try:
            return ipaddress.ip_address(h).is_loopback      # 127.0.0.0/8, ::1
        except ValueError:
            return False      # not an IP literal (e.g. '127.synthetic.invalid')
    except Exception:        # noqa: BLE001
        return False


def sample_profile(options, mitmproxy_version) -> FramingProfile:
    """Read the EFFECTIVE runtime values off a mitmproxy options object (duck-typed via
    `getattr(options, name, _MISSING)`). A missing/unreadable field maps to `UNAVAILABLE_FIELD`,
    NOT to the tested value. Never raises."""
    def read(name):
        try:
            v = getattr(options, name, _MISSING)
        except Exception:    # noqa: BLE001 — a hostile/odd options object must not break sampling
            return UNAVAILABLE_FIELD
        return UNAVAILABLE_FIELD if v is _MISSING else v

    version = (mitmproxy_version if isinstance(mitmproxy_version, str) and mitmproxy_version
               else UNAVAILABLE_FIELD)
    mode_marker, mode_fingerprint = _canon_mode(read("mode"))
    return FramingProfile(
        mitmproxy_version=version,
        validate_inbound_headers=read("validate_inbound_headers"),
        http2=read("http2"),
        stream_large_bodies=read("stream_large_bodies"),
        body_size_limit=read("body_size_limit"),
        mode=mode_marker,
        connection_strategy=read("connection_strategy"),
        mode_fingerprint=mode_fingerprint,
    )


# ── monotonic relevant-profile generation ─────────────────────────────────────
class RelevantProfileGeneration:
    """A monotonic counter that bumps whenever the relevant profile fingerprint changes. Detects
    A→B→A as two bumps, which value equality against a single 'current' profile cannot. Never
    raises."""
    _NO_BASELINE = object()

    def __init__(self, generation: int = 0) -> None:
        self._generation = int(generation)
        self._last = RelevantProfileGeneration._NO_BASELINE

    @property
    def generation(self) -> int:
        return self._generation

    def observe(self, profile) -> int:
        """Record a freshly-sampled profile. The first call establishes the baseline (no bump);
        every later call that changes the fingerprint bumps the counter once."""
        try:
            fp = profile.relevant_fingerprint()
        except Exception:    # noqa: BLE001 — an unreadable profile never breaks the counter
            return self._generation
        if self._last is RelevantProfileGeneration._NO_BASELINE:
            self._last = fp
        elif fp != self._last:
            self._last = fp
            self._generation += 1
        return self._generation


# ── the framing observation record and its log line ───────────────────────────
@dataclass(frozen=True)
class FramingObservation:
    """What the framing observer concluded for one request. The canonical status and outcome are kept
    as SEPARATE dimensions from the framing `status`/`reasons`, so a canonical REJECT is never
    confused with the framing verdict. Carries only closed tokens and numbers."""
    status: str
    reasons: tuple = ()
    target_form: Optional[str] = None
    canonical_status: Optional[str] = None
    canonical_outcome: Optional[str] = None
    profile_generation: Optional[int] = None
    elapsed_ms: Optional[float] = None

    def __post_init__(self) -> None:
        if self.status not in STATUS:
            raise ValueError(f"status must be one of {STATUS}, got {self.status!r}")
        for r in self.reasons:
            if r not in REASON:
                raise ValueError(f"reason {r!r} not in the closed REASON set")
        if self.status == PROFILE_MATCHED and self.reasons:
            raise ValueError("PROFILE_MATCHED carries no reason")
        if self.status != PROFILE_MATCHED and not self.reasons:
            raise ValueError(f"{self.status} must carry at least one reason")


def format_record(tag: str, framing_obs: FramingObservation) -> str:
    """One `FRAMING OBS` log line: closed codes and numbers only. NEVER a target, query, header
    value, body or content hash."""
    parts = [f"[{tag}] FRAMING OBS {framing_obs.status}"]
    if framing_obs.reasons:
        parts.append("reasons=" + ",".join(framing_obs.reasons))
    if framing_obs.canonical_status is not None:
        parts.append(f"canonical_status={framing_obs.canonical_status}")
    if framing_obs.canonical_outcome is not None:
        parts.append(f"canonical_outcome={framing_obs.canonical_outcome}")
    if framing_obs.target_form is not None:
        parts.append(f"target_form={framing_obs.target_form}")
    if framing_obs.profile_generation is not None:
        parts.append(f"gen={framing_obs.profile_generation}")
    if framing_obs.elapsed_ms is not None:
        parts.append(f"elapsed={framing_obs.elapsed_ms:.3f}ms")
    return " ".join(parts)


def _dedupe(seq) -> tuple:
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return tuple(out)


# ── the pure evaluator (the ONLY producer of PROFILE_MATCHED) ──────────────────
def evaluate(*, profile, gen_at_capture, gen_at_reply, canonical_obs, form,
             canonical_available, http_version) -> FramingObservation:
    """Combine the snapshot-time profile, the two generations, the canonical observation, the target
    form and the ORIGINAL received `http_version` (carried from the same immutable snapshot, never
    inferred from normalized canonical text) into a single `FramingObservation`. PURE: no I/O, no
    canonicalization, no re-running of any framing rule. Conservative: `PROFILE_MATCHED` is produced
    only when EVERY condition holds (including `http_version == "HTTP/1.1"` EXACTLY); anything else is
    `UNATTESTABLE` or `UNAVAILABLE` with precise closed reason(s). HTTP/1.0 (in scope at the adapter,
    canonicalizes OK+ACCEPT) is `UNATTESTABLE` with `HTTP_VERSION_NOT_11`; adapter-out-of-scope
    versions (HTTP/2 etc.) stay on the `UNAVAILABLE`/`HTTP_VERSION_OUT_OF_SCOPE` path."""
    cstatus = getattr(canonical_obs, "status", None)
    coutcome = getattr(canonical_obs, "outcome", None)
    elapsed = getattr(canonical_obs, "elapsed_ms", None)

    def result(status, reasons):
        return FramingObservation(
            status=status, reasons=_dedupe(reasons), target_form=form,
            canonical_status=cstatus, canonical_outcome=coutcome,
            profile_generation=gen_at_capture, elapsed_ms=elapsed)

    # ── UNAVAILABLE gate: the observation could not be run at all ──────────────
    if not canonical_available or canonical_obs is None:
        # No usable canonical result exists; nothing else can be concluded.
        return result(UNAVAILABLE, (NO_CANONICAL_OBSERVER,))

    unavailable = []
    if profile is None or profile.has_unavailable_field():
        unavailable.append(PROFILE_FIELD_UNAVAILABLE)

    if cstatus != cobs.OK:
        # A canonical REJECT is status OK (handled below), so a non-OK status here is ALWAYS an
        # infrastructure/scope condition — never a canonical reject collapsed into infra.
        if cstatus == cobs.UNAVAILABLE:
            unavailable.append(WORKER_UNAVAILABLE)
        elif cstatus == cobs.BUSY:
            unavailable.append(WORKER_BUSY)
        elif cstatus == cobs.TIMEOUT:
            unavailable.append(WORKER_TIMEOUT)
        elif cstatus == cobs.DROP:
            unavailable.append(SNAPSHOT_DROPPED)
        elif cstatus == cobs.ADAPTER_ERROR:
            unavailable.append(ADAPTER_ERROR)
        elif cstatus == cobs.EXCEPTION:
            unavailable.append(WORKER_UNAVAILABLE)       # an IPC/worker fault, not a canonical reject
        elif cstatus == cobs.BODY_UNAVAILABLE:
            unavailable.append(BODY_UNAVAILABLE)
        elif cstatus == cobs.OUT_OF_SCOPE:
            detail = getattr(canonical_obs, "detail", None)
            unavailable.append(HTTP_VERSION_OUT_OF_SCOPE
                               if detail == adapter.SCOPE_UNSUPPORTED_VERSION
                               else TARGET_FORM_OUT_OF_SCOPE)
        else:
            unavailable.append(CANONICAL_UNAVAILABLE)

    if form not in _IN_SCOPE_FORMS and TARGET_FORM_OUT_OF_SCOPE not in unavailable:
        unavailable.append(TARGET_FORM_OUT_OF_SCOPE)

    if unavailable:
        return result(UNAVAILABLE, unavailable)

    # ── here: canonical status OK, form in scope, all profile fields available ──
    reasons = []
    if http_version != TESTED_HTTP_VERSION:              # HTTP/1.0, None or anything but HTTP/1.1
        reasons.append(HTTP_VERSION_NOT_11)
    if gen_at_capture != gen_at_reply:
        reasons.append(GENERATION_DRIFT)                 # the profile could have changed under us
    if not profile.is_tested_profile():
        if profile.validate_inbound_headers is False:
            reasons.append(VALIDATE_INBOUND_HEADERS_OFF)
        reasons.append(PROFILE_NOT_TESTED)
    if coutcome == CANONICAL_REJECT:
        reasons.append(CANONICAL_REJECT_REASON)          # residual-framing failure if R1/R2
    elif coutcome == CANONICAL_UNSUPPORTED:
        reasons.append(CANONICAL_UNSUPPORTED_REASON)
    elif coutcome != CANONICAL_ACCEPT:
        reasons.append(CANONICAL_NOT_ACCEPTED)

    if reasons:
        return result(UNATTESTABLE, reasons)

    # Every condition holds. This is ONLY "profile + observed snapshot met the defined conditions".
    return result(PROFILE_MATCHED, ())
