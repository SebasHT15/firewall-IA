# Framing OBSERVATION slice — preservation / privacy acceptance review (Track C)

Issue #68 · **D70 APPROVED (observe-only)** · branch `feat/http1-framing-attestation` · reviewed
2026-10-21, reconciled after the correction pass 2026-10-22.

**Scope.** Track C reviews Track A's `framing_evidence.py` and the coordinator's integration in
`data_plane.py` against the acceptance gates in `INTERFACE.md`, and writes the dedicated
preservation/privacy tests. This is a REVIEW, not an implementation of the slice: no non-test file
was edited. The slice is bounded, owner-approved, **shadow / observe-only, default-off**. V4 via
`/classify` remains the only enforced authority.

**Code under review (read, not modified):** `data_plane/data_plane.py` (`configure`,
`capture_and_schedule_observation`, `complete_canonical_observation`, `load_shadow_framing_observer`,
`GatewayEvidence`, the `addons=[...]` wiring, the done-callback reservation backstop);
`data_plane/framing_evidence.py` (`FramingProfile` with public `mode` marker + internal
`mode_fingerprint`, `sample_profile`, `RelevantProfileGeneration`, `evaluate` — the only producer of
`PROFILE_MATCHED`, now with a required `http_version` — and `format_record`);
`data_plane/canonical_observer.py` (`capture` / `run_captured` / `release_captured` / `Capture` with
`http_version` / `reservation` / `consumed`, and the token-scoped `_Reservation` replacing `_busy`).

**Tests written (Track C's exclusive files):**
- `tests/test_data_plane_framing_observer.py` (NEW)
- `reports/v5/hybrid/framing-attestation/acceptance-review.md` (this file)

**Run command and result (module run ON ITS OWN, as required):**
```
.venv-dataplane/bin/python -m unittest tests.test_data_plane_framing_observer
Ran 40 tests ... OK      # 40 passed, 0 skipped, 0 failed, 0 errors (stable across repeated runs)
```
No "Event loop is closed" teardown artifact appeared (that artifact only surfaces when several
mitmproxy async modules share one process; this module was run alone). No protected dataset is read;
`TestRenderRequest.test_reproduces_the_v4_dataset_representation` and the full `tests.test_data_plane`
module were NOT run. There are NO skipped tests (a skip would be a missing check, not a pass).

---

## Corrected defects — before / after (this correction pass)

The correction pass fixed three defects Track A reproduced plus one integration regression surfaced
during review. Attribution is stated precisely; Track C authored only the tests.

### Defect A — HTTP version exclusion (fixed by Track A in `framing_evidence.py` + coordinator wiring)
- **Before:** `evaluate` did not consider the received HTTP version, so an in-scope **HTTP/1.0**
  request (which canonicalizes OK+ACCEPT) could reach `PROFILE_MATCHED` — a false positive for a
  non-HTTP/1.1 request.
- **After:** `evaluate` takes a REQUIRED `http_version`, carried on the immutable snapshot as
  `Capture.http_version` (the ORIGINAL received version, never inferred from normalized canonical
  text); `TESTED_HTTP_VERSION == "HTTP/1.1"`; anything else adds the new closed reason
  `HTTP_VERSION_NOT_11` and blocks a positive. HTTP/2 etc. stay on the adapter-out-of-scope
  `UNAVAILABLE`/`HTTP_VERSION_OUT_OF_SCOPE` path.
- **Proven by:** `TestHttpVersionExclusion.test_http_1_1_reaches_profile_matched_http_1_0_is_unattestable`
  (through the REAL gateway + worker: HTTP/1.1 → `PROFILE_MATCHED`; HTTP/1.0 →
  `UNATTESTABLE … HTTP_VERSION_NOT_11` with `canonical_outcome=ACCEPT`);
  `TestHttpVersionExclusion.test_missing_or_odd_version_prevents_a_positive` and
  `TestEvaluateDimensions.test_http_version_not_11_blocks_a_positive` (None / "" / HTTP/1.0 / HTTP/2.0
  / wrong-case all blocked).

### Defect B — mode class vs fingerprint / generation drift (fixed by Track A in `framing_evidence.py`)
- **Before:** the mode handling conflated the tested CLASS with the concrete destination, so a port
  change could be missed and non-HTTP / DNS-lookalike destinations were not cleanly excluded.
- **After:** `FramingProfile` exposes a PUBLIC, port/destination-free `mode` marker (loggable; used
  for `is_tested_profile()`, which now requires reverse + transport exactly `http` + a loopback IP
  LITERAL or exactly `localhost`) and an INTERNAL `mode_fingerprint` (concrete transport+host+port,
  NEVER logged) used only in `relevant_fingerprint()`, so a transport/destination/port change bumps
  the monotonic generation even within the tested class, and A→B→A is two bumps.
- **Proven by:** `TestModeClassAndGeneration.test_is_tested_profile_rejects_non_http_and_dns_lookalike_destinations`
  (https / http3 / `127.synthetic.invalid` / `example.com` rejected; `127.0.0.1` literal accepted;
  a different port shares the tested class);
  `TestModeClassAndGeneration.test_transport_change_bumps_the_generation_a_b_a_is_two_bumps` (through
  the REAL `FirewallGateway.configure()`: HTTP→HTTPS→HTTP → generations `[0, 1, 2]`, not `[0,0,0]`);
  `TestModeClassAndGeneration.test_dynamic_port_change_within_the_tested_class_still_bumps_the_generation`;
  `TestSnapshotIdentity.test_generation_change_mid_observation_is_drift_through_the_gateway` (a
  transport change observed by `configure()` while the observation hangs → `UNATTESTABLE` /
  `GENERATION_DRIFT`, never `PROFILE_MATCHED`); privacy of the fingerprint is pinned by
  `TestPrivacy.test_destination_and_port_never_appear_in_the_framing_line` (port `65432` and host
  `127.0.0.1` absent from the line while the tested class still matches).

### Defect C — reservation (fixed by Track A in `canonical_observer.py` + coordinator done-callback)
- **Before:** a boolean `_busy` flag could be freed by a stale/late release and left no safe way to
  reclaim the slot if a scheduled completion was cancelled before it ran; `run_captured` was not
  single-use.
- **After:** `_busy` is replaced by a single-use `_Reservation` token; `_release_reservation(token)`
  is identity-scoped (a stale/late token is a no-op, so it can never free a newer claim);
  `run_captured` is single-use (a consumed capture returns `EXCEPTION detail="capture_consumed"`
  without touching the worker); `release_captured` is idempotent and token-scoped; and the gateway's
  `capture_and_schedule_observation` adds a done-callback backstop that releases the token if the
  completion task is cancelled before its coroutine runs, and closes the coroutine + releases on a
  scheduling failure (no "never awaited" leak, no wedge at BUSY).
- **Proven by:** `TestReservation.test_pre_start_cancellation_frees_the_reservation_for_the_next_request`
  (through the real gateway + observer: cancel the pending completion task → the next `capture()` is
  admitted, not BUSY); `TestReservation.test_stale_release_cannot_free_a_newer_reservation` (a repeat
  release of an old handle does NOT free the newer reservation → a third capture is BUSY);
  `TestReservation.test_repeated_run_captured_returns_capture_consumed`;
  `TestReservation.test_scheduler_failure_releases_the_reservation_and_leaves_the_request_untouched`
  (response untouched, `CANONICAL OBS not started` logged, reservation freed so a fresh capture is
  admitted).

### Integration regression — gate-8 `evaluate()` call missing `http_version` (found during review; fixed by the coordinator)
- **Before:** the `enforce()` branch for framing-on-without-canonical-observer called
  `framing_evidence.evaluate(...)` WITHOUT the now-required `http_version`, raising `TypeError` inside
  `enforce()`; it propagated to `request()`'s fail-closed guard, turning EVERY such request into a
  **503** and emitting NO `FRAMING OBS` line — violating gate 8 AND the observe-only invariant.
  (Confirmed empirically during review; the file was being edited concurrently, which is why an early
  run was briefly flaky.)
- **After:** Track B flagged it and the **COORDINATOR** repaired `data_plane.py` (that branch now
  passes `http_version=None`, and `canonical_available=False` short-circuits to
  `NO_CANONICAL_OBSERVER`). Track C did NOT edit that file.
- **Proven by:** `TestFramingOnWithoutCanonicalObserver.test_logs_unavailable_no_canonical_observer_and_leaves_response_unchanged`
  (ALLOW forwarded / BLOCK still 403, `FRAMING OBS UNAVAILABLE … NO_CANONICAL_OBSERVER`, one
  classifier call, no worker, no task). This now PASSES against the repaired file.

---

## Per-gate verdicts (all 8 gates kept)

### Gate 1 — Default-off — **PASS**
`TestDefaultOff`: config loads `False`; with framing off and no observer the client response + exact
V4 bytes equal a bare gateway's and no `FRAMING OBS` line is ever logged; `configure()` is a no-op
while off.

### Gate 2 — On/off equivalence — **PASS**
`TestOnOffEquivalence`: across all five V4 behaviours × a spread of canonical/framing outcomes
(PROFILE_MATCHED, canonical REJECT R1, worker TIMEOUT/UNAVAILABLE, observer raising), the client
response and V4-input bytes equal the framing-off baseline; `/classify` body byte-identical and
schema still `{"request"}`; **exactly one** classifier call on the classification path; **zero** and
no framing line for a pre-answered flow; an observer failure, a profile-sampling failure, and a
framing-`evaluate` failure each leave the response unchanged (the sampling-failure case also
confirms the C1 resolution below — an explicit line, never a silent skip).

### Gate 3 — GatewayEvidence unchanged — **PASS**
`TestGatewayEvidenceUnchanged`: `GatewayEvidence().canonical(req) is None`,
`.framing(req).status == fast_path.FRAMING_UNAVAILABLE` (≠ `FRAMING_VERIFIED`); with framing
observation producing `PROFILE_MATCHED` on its own line, the shadow Fast Path still logs `CONTINUE` /
`CANONICAL_UNAVAILABLE`, never `FAST_ALLOW`/`VERIFIED`. No policy deployed, no enforcement.

### Gate 4 — Privacy — **PASS**
`TestPrivacy`: a request soaked in synthetic markers (target, query, every header value, body) yields
`FRAMING OBS` / `CANONICAL OBS` lines with none of the markers and none of their SHA-256 digests (stub
PROFILE_MATCHED and canonical-REJECT, plus the REAL worker); a framing-`evaluate` exception is logged
as `detail=internal:RuntimeError` only; and the upstream destination/port (the internal mode
fingerprint) never appears in the line (Defect-B privacy). Scope note (as instructed): the guarantee
is for the NEW `FRAMING OBS` / `CANONICAL OBS` lines only, not the pre-existing `received …` /
decision lines, which carry synthetic request paths by design.

**Fields the observer logs (closed vocabulary only).** `format_record` emits only
`FRAMING OBS <status>` (`status` ∈ {`PROFILE_MATCHED`, `UNATTESTABLE`, `UNAVAILABLE`});
`reasons=<closed REASON tokens>`; `canonical_status=<closed canonical status>`;
`canonical_outcome=<ACCEPT|REJECT|UNSUPPORTED>`; `target_form=<closed enum>`; `gen=<int>`;
`elapsed=<float>ms`; and the `[tag]` prefix (`flow.id[:8]`, not content). The public `mode` marker is
NOT logged at all, and the internal `mode_fingerprint` is never logged. No target, query, header, body,
content hash, exception message, destination or port is representable; `FramingObservation.__post_init__`
structurally rejects any out-of-vocabulary status/reason.

### Gate 5 — Snapshot identity / no misattribution — **PASS**
`TestSnapshotIdentity`: the one immutable snapshot is built synchronously in `capture()`, so mutating
the request after capture (body + target) cannot change the observation (REAL worker:
`decoded_body_bytes` reflects capture time); generation drift (pure and the new end-to-end
mid-observation `configure()` bump) → `UNATTESTABLE`/`GENERATION_DRIFT`; a swapped/late worker reply
is rejected by the observer's `ipc_id_mismatch → EXCEPTION` guard (CITED from
`tests/test_canonical_observer.py`) and such an EXCEPTION can never become a positive framing
observation.

### Gate 6 — No unbounded state — **PASS**
`TestNoUnboundedState`: after 25 requests + drain, `_shadow_tasks` is empty and the gateway's
attribute set is unchanged (no per-flow cache); the `Capture` is a local of the completion coroutine,
not retained on the gateway.

### Gate 7 — Known V4 UnicodeEncodeError (valid obs-text) — **PASS (preserved + disclosed, NOT fixed)**
`TestKnownUnicodeDefectPreserved`: a valid obs-text header value (`0x80–0xFF`) renders to a lone
surrogate; `httpx.build_request` cannot UTF-8-encode the `/classify` body, raising before the
transport is contacted → **zero** classifier calls → fail-closed **503**. Framing observation (on)
neither masks, changes, nor repairs it, and is never reached. Defect D1 PRESERVED and DISCLOSED, NOT
fixed here.

### Gate 8 — Framing-on-without-canonical-observer — **PASS** (regression found + coordinator-resolved; see above)
`TestFramingOnWithoutCanonicalObserver`: `framing_observer=True`, `canonical_observer=None` → every
hooked request logs `FRAMING OBS UNAVAILABLE … NO_CANONICAL_OBSERVER` (ALLOW forwarded / BLOCK 403,
response unchanged), one classifier call, no observer object, no worker, no task; a pre-answered flow
logs nothing.

### Supplementary — pure `evaluate` dimensions — **PASS**
`TestEvaluateDimensions`: `evaluate` is the sole producer of `PROFILE_MATCHED`; conservative
classification pinned for NO_CANONICAL_OBSERVER, canonical REJECT (kept separate from worker infra
failure), worker TIMEOUT/BUSY/UNAVAILABLE/DROP/BODY_UNAVAILABLE, untested profile /
`validate_inbound_headers` off, HTTP_VERSION_NOT_11, out-of-scope form, and the exact `format_record`
string.

---

## C1 (from the first review) — **RESOLVED by the coordinator**
The first-pass review flagged C1: outside a mitmproxy context, `capture_and_schedule_observation` read
`ctx.options`, which raised and was mapped to `profile=None`, causing `complete_canonical_observation`
to **silently skip** the `FRAMING OBS` line. The **COORDINATOR** repaired this in `data_plane.py`
(a coordinator file, not Track C's): when framing observation is on, the gateway now ALWAYS produces a
profile — a reach-`ctx.options` failure passes `options=None` to `sample_profile` (which maps every
field to the explicit unavailable sentinel), and a hostile/odd options object falls back to an
all-unavailable `FramingProfile` — so a sampling failure now emits an explicit
`FRAMING OBS UNAVAILABLE … PROFILE_FIELD_UNAVAILABLE` line, NEVER a silent skip and NEVER a changed
response. Verified by `TestOnOffEquivalence.test_a_framing_or_observer_failure_never_changes_the_response`
case (b): with `sample_profile` patched to raise, a BLOCK stays 403 and a `FRAMING OBS` line is still
emitted. Track C did NOT author this repair.

## Remaining concerns (described, NOT edited)
None blocking. No content/destination/port leak, no misattribution, no unbounded-state, and no
V4-equivalence violation remains against the current files. The two defects surfaced during review
(the gate-8 `evaluate()` call missing `http_version`, and C1) are both resolved in coordinator files
by the coordinator, and the tests above pass against those repaired files.

## Authorship / review limitations (disclosed)
- Track C edited no non-test file. The gate-8 regression and C1 were fixed by the coordinator (Track B
  flagged the gate-8 TypeError); Track C does not claim independence for those repairs — it authored
  only the tests that now pass against them.
- The `ipc_id_mismatch → EXCEPTION` cross/late-reply guard is verified at the OBSERVER level by
  Track A's `tests/test_canonical_observer.py` (CITED); Track C adds only the gateway/evaluate
  consequence (such an EXCEPTION never yields `PROFILE_MATCHED`) and did not re-run A's observer suite.
- If the coordinator later needs to repair anything in `tests/test_data_plane_framing_observer.py`,
  that is a cross-track edit of Track C's exclusive file and must be disclosed in the integration
  record.
- Per the slice prohibitions, the full `tests.test_data_plane` module and the protected-dataset parity
  test were not run; no socket-restricted test was silently counted as a pass (the real-worker tests
  spawn a local subprocess, not a network socket).

## Architectural advance (stated precisely)
With this slice, a request's sampled mitmproxy runtime **profile** and the **canonical result** are
coherently bound to one **bounded, immutable request observation**, now with the ORIGINAL received
HTTP version (`http_version`), a port/destination-free public mode class plus an internal fingerprint
for drift detection, and a single-use token reservation — all sampled at the SAME post-verdict
boundary as the one immutable snapshot. `evaluate` fuses them with version (`HTTP_VERSION_NOT_11`),
drift (`GENERATION_DRIFT`) and provenance (`ipc_id_mismatch`) limits tested end-to-end, producing a
conservative, closed-vocabulary `FRAMING OBS` line whose single positive status, `PROFILE_MATCHED`,
means ONLY "the sampled runtime profile was the documented tested one and the observed snapshot met
the defined conditions (HTTP/1.1 origin/asterisk, complete body, valid correlation, unchanged
generation, canonical OK+ACCEPT)."

`PROFILE_MATCHED` is explicitly **not** a per-request wire VERIFIED, not safe-to-forward, not Fast Path
eligibility, and not an upstream-equivalence claim: there is no project-owned wire-level framing
control in this slice, so `fast_path` framing stays `UNAVAILABLE`/`UNVERIFIED` and `GatewayEvidence` is
untouched (a bare-LF request can still reach `PROFILE_MATCHED` under these limited semantics, yet the
wire is not attested). A genuine per-request **VERIFIED** would still require (a) a project-owned,
tested wire-level framing control (the canonical-request R1 residual), (b) the V5 token-budget `B` and
the canonical `Limits` ratified so a size-checked canonical ACCEPT is meaningful, and (c) an explicit
owner decision to let any such evidence feed the Fast Path. **This slice (D70 APPROVED, observe-only,
default off) settles none of that and does not activate the hybrid cascade**: it changes no
enforcement, forwarding, or Fast Path eligibility.
