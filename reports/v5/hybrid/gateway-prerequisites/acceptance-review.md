# Canonical observer — preservation / privacy / isolation acceptance review

Issue #68 (D69). Independent, READ-ONLY review by the preservation/acceptance track, of the
integrated canonical-request/v1 **shadow observer** wired into the data plane. Scope: V4
preservation, privacy/logging, isolation, representation-compatibility, protected-data boundary,
and over-claims. This note is INPUT to the coordinator, not an approval; nothing here authorizes
runtime.

Files reviewed (read-only): `data_plane/data_plane.py` (observer wiring), `data_plane/canonical_observer.py`,
`data_plane/canonical_adapter.py`, `data_plane/canonical_worker.py`, `config.yaml` (default-off block),
`tests/test_canonical_request.py` (amended guard `Isolation.test_gateway_and_v4_untouched_by_contract`),
`tests/test_canonical_adapter.py`, `tests/test_canonical_observer.py`.

Tests for this track: `tests/test_data_plane_canonical_observer.py` — **currently 21 tests** in the
coordinator's tree (the earlier draft had 20; the coordinator added one repaired-lifecycle case). They
drive the real `FirewallGateway` with an `httpx.MockTransport` classifier plus stub observers and, for
the process path, the real `ProcessCanonicalObserver` + worker. **Authorship note:** in the repair pass
the preservation/acceptance subagent hit a usage limit before applying changes; the **coordinator**
completed this acceptance work (the review-and-corrections and the added lifecycle test), so this is not
a fresh independent review. The independent review environment selected **20** of these tests and
explicitly excluded the socket-dependent connection-failure case (it needs a bindable local socket).

## What the behavioral tests prove (against the integrated gateway)

- **V4 preservation OFF vs ON.** For every V4 behaviour {ALLOW, model BLOCK→403, invalid→503,
  HTTP 500→503, timeout→503} × every observer behaviour {OK ACCEPT, OK REJECT, BODY_UNAVAILABLE,
  OUT_OF_SCOPE, DROP, BUSY, TIMEOUT, UNAVAILABLE, EXCEPTION, raises}, the client response AND the
  exact bytes V4 received equal the observer-off baseline. The `/classify` body stays
  `{"request": "<D1 text>"}`, byte-identical on and off. Exactly one classifier call for a classified
  request; **zero** calls and zero observations for a pre-answered flow. Observer cannot flip
  ALLOW↔BLOCK. Connection-failure (real closed socket) is 503 with the observer on.
- **Isolation.** Startup-unavailable / BUSY / DROP / TIMEOUT / crash / malformed-reply / scheduling
  failure never block or alter the request (V4 still asked exactly once). A hung observer does not
  delay forwarding (the request never awaits the background task). `(classifier N ms)` keeps its
  definition — a 300 ms observation does not appear in it. Addon unload still installs
  `/~all/503` and calls `observer.close()`. Combined with feature extraction + Fast Path on, the
  outcome still matches the all-off baseline.
- **Privacy.** With a request carrying distinct SENTINEL markers in target/query, `Authorization`,
  `Cookie`, `Host`, `User-Agent` and body: on the real-worker OK line, on the failure line, and on
  DROP/TIMEOUT/UNAVAILABLE/OUT_OF_SCOPE lines, every marker **and its sha256 hex** is absent; the
  line still carries the `[tag]` + status + a closed code/enum. The raise path logs
  `detail=internal:RuntimeError` and never the exception message.
- **Fast Path unchanged.** `GatewayEvidence.canonical(req)` is still `None`; with the observer on,
  the Fast Path logs `CONTINUE ... CANONICAL_UNAVAILABLE`, never `FAST_ALLOW`.
- **Default-off.** `load_canonical_observer()` returns `None` with the repository config (the block
  is commented out); `build_canonical_observer(None)` returns `None`.

## Independent review findings

**Confirmed**
- **One contract import path.** The gateway reaches `canonicalize` only through `canonical_observer`;
  it never `import canonical_request` directly. The amended guard
  (`tests/test_canonical_request.py:699-714`) now asserts `data_plane.py` imports `canonical_observer`
  but not `canonical_request`, and that `request_features.py` and `control_plane/inference_core.py`
  stay contract-free. V4's D1 rendering is untouched. The assertion was narrowed, not deleted.
- **Representation-compatibility safeguard is architectural, and A documented the trap.**
  `tests/test_canonical_adapter.py:157-170` (`TestRepresentationRegression`) records that
  `request-features/v2` stamps the **same** schema id for D1 text and for canonical-request/v1 text,
  so the Analyzer's `feature_schema` check is **not** a guard against mixing representations. The real
  safeguard is that the canonical observer runs on its own worker that never touches the Analyzer —
  confirmed: `canonical_observer.py` / `canonical_worker.py` / `canonical_adapter.py` import no
  `request_features`, `hybrid_shadow`, `hybrid_contracts` or `AnalyzerModel`; and in `data_plane.py`
  the Analyzer is fed `raw_request` (D1 text) while the observer is fed the raw request object, its
  output logged and never routed into the Analyzer or `GatewayEvidence`. No canonical text/feature can
  reach the frozen Analyzer.
- **No over-claims.** Framing stays UNVERIFIED (`GatewayEvidence.framing` → `FRAMING_UNAVAILABLE`);
  canonical stays `None` (Fast Path ineligible); the canonical size is UNCHECKED (no token budget),
  which independently keeps Fast Path ineligible (`SIZE_UNCHECKED` ≠ `SIZE_WITHIN`). Belt and
  suspenders; both verified.
- **No skipped/None body becomes empty on the canonicalize path.** `canonical_adapter.build_snapshot`
  keeps `req.raw_content` `None` distinct from `b""` (no `or b""`); a `None` body returns
  `BODY_UNAVAILABLE` and never reaches `canonicalize`. The only `or b""` in the flow is
  `data_plane.fast_path_input` (line 429), which does not canonicalize because the Fast Path is
  ineligible.
- **Privacy defense in depth.** `format_record` emits closed codes/enums/numbers only; `text_sha256`
  is held on the record but omitted from the line; worker-supplied `detail`/`reason` tokens pass the
  conservative `safe_detail` regex (observer side and again in `format_record`). `decoded_body_bytes`
  is a length, not content (the decision line already logs the received body length).
- **Protected-data accounting (corrected).** The observer modules and the authored
  `test_data_plane_canonical_observer.py` use synthetic requests only and never select the protected
  reader. HOWEVER, the full `tests.test_data_plane` run listed below (36 tests) **does** include
  `TestRenderRequest.test_reproduces_the_v4_dataset_representation`, which reads
  `datasets/v4_clean/eval.jsonl` (6,206 rows, confirmed present). That is the existing V4 **render-parity
  regression** — not model fitting and not a new evaluation. This is disclosed, not hidden, and the
  earlier blanket "synthetic-only / no protected access" claim does not stand; it is NOT characterized as
  authorized, and no claim of contamination or non-contamination is made either way (the dataset was not
  opened to investigate). For the repair pass, all new/targeted runs **exclude** that test and other
  protected readers by explicit selection,
  and the regression is preserved intact for its authorized contexts (not deleted or weakened).

**Earlier concern — RESOLVED by repair 2 (owner review correction incorporated)**
- The earlier draft claimed the snapshot body was "copied (~2x)" before admission. That framing was
  **wrong**: `bytes(x)` where `x` is already `bytes` returns the **same object** in CPython (no copy).
  The real defect the owner review confirmed was that `observe()` built the full snapshot —
  **materializing the whole `(name,value)` header tuple** — before the admission check, and did so even
  when BUSY/unavailable. **Repair 2 fixes this:** `observe()` now returns closed/permanent/BUSY with no
  snapshot built; `canonical_adapter.classify_raw` does the cheap form/body classification and
  `admit_raw` scans `req.headers.fields` with **early exit** on the count/byte caps (never building the
  tuple); only admitted requests are materialized, with an explicit serialized-snapshot size DROP. The
  old `_admit` (which operated on a built snapshot) was removed. Confirmed by
  `tests/test_canonical_adapter.py::TestAdmitRawEarlyExit` and
  `tests/test_canonical_observer.py::TestCheapAdmission`. The pre-buffer RECEIVE bound (mitmproxy
  `body_size_limit`/`stream_large_bodies`, bound #1) remains a distinct deferred deployment decision; it
  is not activated in this observation-only slice.

**Repairs 1 and 3 (owner review) — CONFIRMED in the repaired modules**
- **Repair 1 (one IPC deadline).** `_exchange` now wraps write+drain+read in a single
  `asyncio.wait_for(self._write_and_read(proc, frame), timeout_seconds)`, so a worker that stops reading
  stdin (blocking `drain()`) can no longer defer the deadline. On `TimeoutError` → SIGKILL + reap +
  `_note_failure` → TIMEOUT; on `CancelledError` → SIGKILL + reap the (possibly desynchronised) worker,
  do not reuse it, release `_busy`, re-raise. Id-check and oversize/malformed-reply kill unchanged.
- **Repair 3 (cleanup).** `close()` no longer nulls `self._proc` before reaping and now closes the
  subprocess transport (eliminating the `BaseSubprocessTransport.__del__: RuntimeError: Event loop is
  closed`); `_kill` only drops the handle when the reap succeeds (else sets a permanent
  `reap_failed_worker_disabled`, not a false "gone"); `close()`/`aclose()` are idempotent and safe
  during startup/exchange/after-timeout/after-close. **Honest residual (CONFIRMED, same as the existing
  Analyzer):** a *synchronous* mitmproxy `done()` does not `await`; `close()` SIGKILLs the child and
  closes its transports while **retaining the handle**. asyncio may collect the child while the event
  loop is still running (the review observed a reaped child with a live loop before `aclose()` was
  called); `aclose()` awaits full cleanup. Collection is NOT asserted to wait for gateway-process exit.
  V4 is unaffected and no transport is left unclosed. The gateway keeps `done()→close()` (an async reap
  in a sync `done` is not assumed).

## Test results (actual, observed)

`.venv-dataplane` = Python 3.12.15, mitmproxy 12.2.3, httpx 0.28.1. Synthetic requests only.

| module | result |
|---|---|
| `tests.test_data_plane_canonical_observer` (coordinator tree) | **Ran 21 — OK** (coordinator added one repaired-lifecycle case; the independent review env ran 20, excluding the socket-dependent connection-failure case) |
| `tests.test_canonical_adapter` (after repair 2) | **Ran 16 — OK** |
| `tests.test_canonical_observer` (after repairs 1–3) | **Ran 23 — OK** |
| `tests.test_canonical_request.Isolation` (amended guard) | **Ran 3 — OK** |
| `tests.test_data_plane` (**includes the `eval.jsonl` render-parity reader** — see accounting above) | **Ran 36 — OK** |
| `tests.test_data_plane_shadow_analyzer` | **Ran 30 — OK** |
| `tests.test_data_plane_fast_path` (standalone) | **Ran 17 — OK** |

Counts for `test_canonical_adapter`/`test_canonical_observer` are the post-repair totals (A added the
repair-1/2/3 fault and lifecycle tests). The coordinator re-ran the repaired suites and the
V4-preservation selection (excluding the `eval.jsonl` reader) — all green.

**Two DISTINCT event-loop symptoms (do not conflate):**
1. The **live-lab** `BaseSubprocessTransport.__del__: RuntimeError: Event loop is closed` (the observer's
   worker transport GC'd unclosed after the loop closed) was a REAL cleanup defect — fixed by repair 3
   (`close()` now closes the transport); B re-checks the fresh lab shutdown.
2. A SEPARATE, pre-existing cross-module `unittest` teardown ordering artifact: running several
   data-plane async modules in ONE invocation surfaces one `Event loop is closed` in
   `test_data_plane_fast_path.TestEquivalenceWithAndWithoutShadow.test_evidence_provider_failure_is_ignored`;
   it **reproduces without** any new file and each module passes standalone. Unrelated to this slice.
