# #68 — per-request HTTP/1.1 framing OBSERVATION (second bounded slice, D70)

**Date:** 2026-10-21 · **Branch:** `feat/http1-framing-attestation` · **Status: IMPLEMENTED, default-off,
UNCOMMITTED. Observe-only. No enforcement.**

This slice adds a per-request HTTP/1.1 **framing observation** on top of the D69 canonical observer. It
decides nothing: V4 via `/classify` stays the only enforced authority, there is no new client-visible
reject, no Fast Path activation, and `GatewayEvidence` is unchanged. A matched lab profile is **not**
proof of verified wire framing. See `DECISIONS.md` D70 for the ruling and `acceptance-review.md` (Track C)
for the preservation/privacy verdicts and `../../canonical-request-v1/wire-evidence-v2/` (Track B) for the
real raw-socket lab.

## What it does

For each request that reaches the addon, when `data_plane.shadow_framing_observer` is on, the gateway
logs a closed-vocabulary `FRAMING OBS` line stating whether the **effective mitmproxy runtime profile**
and the **observed canonical snapshot** met a precisely defined set of conditions:

- `PROFILE_MATCHED` — the tested profile AND HTTP/1.1 origin/asterisk scope AND a complete body AND valid
  reply correlation AND an unchanged relevant-profile generation (capture == reply) AND a canonical
  `OK`+`ACCEPT` for that exact snapshot. **Meaning: only "profile and observed snapshot met the defined
  conditions".** NOT `FRAMING_VERIFIED`, not safe-to-forward, not Fast Path eligibility, not upstream
  equivalence.
- `UNATTESTABLE` — in scope but no positive observation can be established (canonical REJECT/UNSUPPORTED,
  generation drift, profile-not-tested, `validate_inbound_headers` off).
- `UNAVAILABLE` — the observation could not run (no canonical observer, a missing/unreadable profile
  field, worker busy/unavailable/timeout/drop, body unavailable, adapter error, out-of-scope form/version).

`framing_evidence.evaluate` is the ONLY producer of `PROFILE_MATCHED` and is conservative by
construction: a canonical `REJECT` is kept as a separate dimension and is never collapsed into a
worker-infrastructure failure; a reject before `R1`/`R2`, a timeout or a missing result never yields a
positive observation. `b""` stays distinct from `None`.

## Design (the owner's corrections, implemented)

- **One snapshot, synchronous capture.** The D69 `observe(req)` was split into a SYNCHRONOUS
  `capture(req, profile, profile_generation)` and an async `run_captured(capture)`. `capture()` samples
  the effective profile and materializes the immutable snapshot **together, with no intervening await**,
  at a defined post-V4 boundary; it runs the cheap disabled/BUSY/scope/body/admission/worker-availability
  gates **before** materialization, reserves atomically, and `release_captured()` frees the reservation
  if scheduling fails. Decoding/canonicalization stay in the existing worker and are **never awaited** by
  the request. One body copy, one canonicalization; `canonical_request.py` gets no new framing rule.
- **Effective provenance, not invented ingress history.** The profile is read from `ctx.options`
  (EFFECTIVE values, not config-file intent): `mitmproxy 12.2.3; validate_inbound_headers=True; http2 off;
  stream_large_bodies=None; body_size_limit=None; reverse-proxy to a dynamic loopback port (closed
  marker, never the literal port); connection_strategy=lazy`. A monotonic **relevant-profile generation**
  (bumped from the addon `configure()` hook) detects an A→B→A change between capture and reply, which
  value equality cannot. A profile sampled at snapshot time is evidence of runtime state at that boundary,
  not historical proof of the parser configuration when the bytes were parsed; pre-capture changes are
  unobservable and stated as such. Binding is to an internal non-content snapshot id + the captured
  generation; no request-content hash is introduced.
- **Default-off and non-intrusive.** `GatewayEvidence.canonical()` stays `None`, `.framing()` stays
  `UNAVAILABLE`; the Fast Path stays ineligible and never logs `FAST_ALLOW`. With `shadow_framing_observer`
  on but no canonical observer, every hooked request logs `FRAMING OBS UNAVAILABLE … NO_CANONICAL_OBSERVER`
  and no worker is started. A profile-sampling failure emits an explicit `UNAVAILABLE/PROFILE_FIELD_UNAVAILABLE`
  line and never changes the response. Any framing/observer failure is logged and dropped.

## Capture overhead (coordinator measurement — steady-state, synthetic; NOT a production bound)

N=200 per size, data-plane venv, mitmproxy 12.2.3. Only the synchronous `capture()` is on the request
path; the `run_captured()` round trip is never awaited by the request.

| body bytes | capture() SYNC ms p50/p95/max | run_captured() round-trip ms p50/p95/max |
|---|---|---|
| 0        | 0.0096 / 0.0182 / 0.0878 | 0.0572 / 0.1668 / 0.3618 |
| 1 024    | 0.0108 / 0.0252 / 0.2169 | 0.0749 / 0.2693 / 0.9858 |
| 65 536   | 0.0294 / 0.0535 / 0.1807 | 0.7455 / 1.0758 / 1.7707 |
| 262 144  | 0.0960 / 0.2068 / 0.3877 | 2.7088 / 3.9047 / 5.8278 |
| 1 048 576| 0.3514 / 0.4711 / 1.0950 | 10.4186 / 11.5520 / 16.3958 |

Two distinct quantities, reported separately: **capture duration** is a SYNCHRONOUS cost on the request
path; the **capture→reply round trip** (`run_captured`) is NOT on that path (the request never awaits it).
Claim supported: **"forwarding does not await the worker result"**, NOT zero added latency. Capture is
small but **not uniformly sub-millisecond**: at the 1 MiB cap capture p95 ≈ 0.44–0.47 ms and max ≈ 1.0 ms
(a tail sample tipped just over, 1.095 ms), while the round trip is ≈10 ms p50 at 1 MiB. Steady-state,
synthetic; **not** a basis for any production timeout (several samples; the worker's ~28 ms/1 MiB figure
from D69 is a separate observed data point). Re-measured after the reservation-token change (defect C)
with no material difference.

## Correction pass (2026-10-22) — three reproduced defects, before → after

Repaired within D70's existing observe-only, default-off boundaries (see the `DECISIONS.md` D70 correction
addendum). Each was reproduced with a failing test first, then fixed.

| Defect | Before | After |
|---|---|---|
| **A** version scope | HTTP/1.0 (OK+ACCEPT) wrongly → `PROFILE_MATCHED` | original version carried on the one snapshot; `evaluate` requires EXACTLY HTTP/1.1 → HTTP/1.0 → `UNATTESTABLE/HTTP_VERSION_NOT_11`; HTTP/1.1 unchanged |
| **B** mode/drift | `https`/`http3`/`127.synthetic.invalid` all "tested"; HTTP→HTTPS→HTTP generations `[0,0,0]` | validate reverse+http+loopback-literal only; public marker vs internal `mode_fingerprint`; HTTP→HTTPS→HTTP `[0,1,2]` |
| **C** reservation | pre-start task cancel wedged the observer at BUSY; unconditional release freed a newer reservation | single-use token reservation; idempotent token-scoped release; gateway done-callback backstop + coroutine close on scheduler failure |

Two coordinator-authored integration repairs in `data_plane.py` are disclosed (not claimed as independent
track work): **C1** (a profile-sampling failure now emits an explicit `UNAVAILABLE/PROFILE_FIELD_UNAVAILABLE`
line instead of a silent skip) and a **TypeError** in the framing-on-without-canonical-observer branch (now
passes `http_version=None` → `UNAVAILABLE/NO_CANONICAL_OBSERVER`).

## Evidence index

- `acceptance-review.md` — Track C preservation/privacy review: 8 acceptance gates + the 3 defects, all
  PASS; 40 tests in `tests/test_data_plane_framing_observer.py`. D70 recorded as APPROVED; C1 and the
  TypeError recorded as RESOLVED by the coordinator (Track C authored only the tests, claims no independence
  for those repairs).
- `../../canonical-request-v1/wire-evidence-v2/corrected/` — Track B corrected raw-socket lab: per-vector
  five dimensions (client / parser / reachability / canonical / framing), including the HTTP/1.0 →
  `UNATTESTABLE/HTTP_VERSION_NOT_11` row beside the HTTP/1.1 positive; the `validate_inbound_headers`
  true/false drift (`wire_control_demonstrated` and `framing_control_demonstrated` both true). **wire-evidence-v1
  AND the prior `wire-evidence-v2/` run are preserved byte-for-byte** (SHA-256 compared), and this corrected
  run's recorded hashes/metadata/results are likewise NOT overwritten.
  - *Config provenance:* the corrected run records `config_yaml_sha256=94adc604…`; the prior `23c1854…`
    differs only by a later coordinator comment-only label edit ("D70 PROPOSED"→"D70"); no runtime setting
    changed.
  - *Source provenance (read this precisely):* the corrected run recorded `data_plane/data_plane.py` at
    `425e31bd…`; the CURRENT file is `56b298da…`. The only difference is the subsequently-applied TypeError
    repair — the `http_version=None` argument added in the `canonical_available=False` (no-canonical-observer)
    branch. The lab ran with BOTH observers active and therefore never exercised that branch, so the lab is
    valid **for the version it recorded**; it is **not** a byte-for-byte run of the final file. The final
    no-canonical-observer branch is instead verified by the focused gateway test
    `test_logs_unavailable_no_canonical_observer_and_leaves_response_unchanged` (one of the 40 gateway-module
    tests). So this evidence is **"lab of the recorded version PLUS focused verification of the later
    repair"**, not a single run of the final bytes.
  - The runtime generation-drift interleaving is a labelled unit simulation: the live lab cannot
    deterministically change an option within the brief capture→reply window of one request (that window is
    the round-trip duration — e.g. ~0.06 ms p50 for a tiny body up to ~10 ms p50 at 1 MiB — NOT a fixed
    sub-millisecond value, and distinct from the synchronous capture duration).
- Focused tests (run per module to avoid a pre-existing cross-module mitmproxy logging-teardown artifact):
  `test_framing_evidence` (43), `test_canonical_observer` (38), `test_canonical_adapter` (16),
  `test_data_plane_canonical_observer` (21), `test_data_plane_framing_observer` (40),
  `test_data_plane_fast_path` (17), `test_data_plane_shadow_integration` (2), `test_wire_evidence_harness`
  (40) — **217 pass, 0 fail, 0 skip**. Each module was run as its OWN `python -m unittest tests.<module>`
  invocation (eight separate runs); they are not reported from one combined invocation. (A clean `git diff`
  on `tests/test_data_plane.py` shows the protected regression test was PRESERVED; non-execution is
  established by the command records never invoking it, not by the clean diff.)
- *Attribution:* the 217 focused tests and the raw-socket lab above were run and reported by Claude. An
  independent Codex review separately verified the three corrections and ran 209 selected tests green, with
  eight socket cases excluded from its selection and **no** independent repetition of the TCP lab; it found
  no new implementation blockers. The two figures are not the same run and should not be merged.

## Limitations / what a per-request VERIFIED would still require

The profile and the canonical result are now coherently bound to one bounded immutable request
observation, with drift and provenance limits tested. This is the observational boundary. Three
**distinct** future milestones remain — each needs its own owner ruling and they must NOT be conflated:

1. **Per-request wire-framing verification** (what a `FRAMING_VERIFIED` would require): a project-owned,
   tested wire-level framing control, with an explicit ruling on whether the pinned parser's tolerated
   bare-LF/obs-fold behaviour is acceptable, which hop is attested, and how a forwarded (possibly
   reserialized) request binds to the inspected snapshot. A matched lab profile is not this.
2. **Canonical size budget** — a ratified V5 token budget B / canonical `Limits` (today unset → size
   `UNCHECKED`). Independent of (1).
3. **Fast Path eligibility/activation** — a separate owner decision to feed any observation into the Fast
   Path and to enable it. Independent of (1) and (2); this slice provides no such input and
   `GatewayEvidence` stays `canonical=None`/`framing=UNAVAILABLE`.

**This slice settles none of these and does not activate the hybrid cascade.** The known valid-obs-text V4
`UnicodeEncodeError` in `render_request` is preserved and disclosed, not fixed.
