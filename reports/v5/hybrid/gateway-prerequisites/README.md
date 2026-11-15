# #68 — Canonical gateway prerequisites: first bounded slice (APPROVED D69, IMPLEMENTED, uncommitted)

**Status: APPROVED (D69) for the LAB scope below and IMPLEMENTED default-off; the working tree is NOT
clean (uncommitted on `feat/hybrid-gateway-prerequisites`).** The owner approved this bounded shadow
observation slice (with the corrections incorporated); the lab settings are approved **for this
experiment only**. The code is integrated default-off: new modules `data_plane/canonical_adapter.py`,
`canonical_worker.py`, `canonical_observer.py`; gateway wiring + a commented-off
`data_plane.shadow_canonical_observer` block; the stage-1 import guard narrowed (not deleted); D69
recorded. **Still deferred/pending (production, not this slice):** final V5 token constant B and
production limits; the Brotli/zstandard deployment pins (mitmproxy 12.2.3 is already pinned); the
project-owned framing control and any `framing=VERIFIED`; the P9 superset-vs-R3 choice for active use;
HTTP/2 evidence; an active Fast Path policy/enforcement. The sections below keep the design, file plan,
acceptance matrix and the decision request that D69 answered. Base: branch
`feat/hybrid-gateway-prerequisites`, from `origin/develop` `1d1ca60` (PR #84 merge).

## 1. Verified base state

- PR #84 MERGED into `develop` at 2026-10-21T16:52:43Z; `76f7ab0` (names_family/D68) is an ancestor of
  HEAD. Branch `feat/hybrid-gateway-prerequisites` = `origin/develop` = `1d1ca60`, clean tree.
- The gateway today: `GatewayEvidence.canonical()` returns `None` and `framing()` returns
  `FRAMING_UNAVAILABLE` ([data_plane/data_plane.py:343](../../../../data_plane/data_plane.py)), so the
  Fast Path is always ineligible (`CONTINUE reasons=…FRAMING_UNAVAILABLE,CANONICAL_UNAVAILABLE`). V4
  decides every request, fail-closed. This is the intended initial state, not a bug.
- `canonical-request/v1`'s `Limits` (max decoded body, token budget B, bytes/token) are PENDING
  (V5-DATA-SPEC-r4 §11.2); no gateway values exist. Decoder pins verified installed in `.venv-dataplane`:
  mitmproxy 12.2.3, Brotli 1.2.0, zstandard 0.25.0 (all PROPOSED pins).

## 2. The one canonicalize API and adapter identity (I1)

The adapter MUST reuse the single `canonicalize` the generator uses — never re-implement
normalization/decoding. The generator does `import canonical_request as cr` and re-exports
`canonicalize = cr.canonicalize` with an object-identity test ([scripts/dataset/v5_render.py:30](../../../../scripts/dataset/v5_render.py)).
`canonicalize(parts: RequestParts, limits: Limits) -> CanonicalResult` is pure, deterministic, and
never raises on input data (I7) — only `TypeError` on wrong argument types.

**mitmproxy `http.Request` → `RequestParts` mapping (corrections over the existing `fast_path_input`
at [data_plane.py:352](../../../../data_plane/data_plane.py)):**

| field | source | correction / note |
|---|---|---|
| method | `req.data.method` | raw bytes as received (NOT `req.method`, which uppercases/surrogate-decodes) |
| target | `req.data.path` | exact for origin/asterisk-form; **absolute-form is lossy** (mitmproxy lowercases the scheme, moves authority out, synthesizes an empty path to `/`) and authority-form (CONNECT) is harmless (keyed off method). v1 should scope out absolute-form or record the documented loss — never reconstruct missing wire facts and label them observed. |
| http_version | `req.http_version` | str, audit only |
| headers | `tuple((bytes(n), bytes(v)) for n, v in req.headers.fields)` | received order/case/repeats (NOT `.items(multi=True)`, which is a lossy str view) |
| body | `req.raw_content` | de-chunked, **still content-coded** — exactly `RequestParts.body`'s contract. **`None` (missing/streamed) MUST NOT be coerced to `b""`** (the existing `fast_path_input` uses `or b""`, which this slice must not copy): `None` → explicit `BODY_UNAVAILABLE` status, `b""` → a real empty body. |

**Body accessor (critical):** pass `req.raw_content`, never `get_content()`/`.content`/`.text`.
`canonicalize` does its own content-coding decode under the R3/R8 cap; feeding it already-decoded bytes
while `Content-Encoding` is still present would re-decode (→ `R3 decode-failure`) and bypass the
project-owned memory cap. The V4/D1 renderer deliberately uses `get_content(strict=False)` (decoded,
destination-visible); the two body renderings are different functions and stay separate.

## 3. The three distinct bounds (do not conflate)

1. **Pre-buffer receive limit (mitmproxy-owned, before the hook).** mitmproxy reads the whole body into
   RAM per `expected_http_body_size` before `request()` fires. A cap on `raw_content` inside the adapter
   cannot protect memory already consumed. This belongs to mitmproxy config (`body_size_limit`,
   `stream_large_bodies` — the latter makes `raw_content` `None` → `BODY_UNAVAILABLE`). **This
   observation-only slice does not activate a new client-visible receive limit**; the receive-limit
   design is reported separately and left for approval.
2. **Observer submission/input cap (adapter-owned, after parsing).** Refuse to process/offload requests
   whose received `len(raw_content)` exceeds a chosen cap — an explicit status, never an ACCEPT.
3. **Decoded-body cap + decoder working memory (canonicalize-owned).** `Limits.max_decoded_body` + the
   bounded per-decoder steps. This is the only one that defends against a decompression bomb; it needs
   an owner value (≥ 48·B per §5.5). (1)/(2) bound received bytes; (3) bounds decoded bytes — not
   substitutes.

## 4. Decision matrix (PROPOSED; approve only what this slice depends on)

| # | Requirement | Existing evidence | Proposed choice (PROPOSED) | Scope of approval needed | Test | Remaining limitation |
|---|---|---|---|---|---|---|
| A | Scope & authority | V4 sole authority; both observers off (fast-path-contract §3) | Default-off **canonical observation**, HTTP/1.1-evidenced, synthetic local lab only. Preserve V4 D1 text, /classify schema, call-count, decision, forwarding. No new rejects, no bypass, no Model 2/V5. HTTP/2 stays unevidenced (do not disable runtime support). | Approve the default-off observation scope and HTTP/1.1-only evidence | V4 on/off outcome-equivalence across the 5 CLASSIFIER_BEHAVIOURS; default-off test | Observation ≠ enforcement; no FAST_ALLOW coverage |
| B | Resource profile / token budget | `Limits` PENDING §11.2; generator uses `48*B`, B fixture=12; D36 P95 ≤200 ms not met (269.58 ms) | **Lab-only**: observer submission cap 1,048,576 B; `max_decoded_body` 1,048,576 B; `token_budget=None`, `max_bytes_per_token=None`, no tokenizer → size **UNCHECKED**. B deferred. | Approve the lab-only numbers as PROPOSED test settings (not operational defaults, not ratified V5 constants) | Bounded synthetic decode tests; smoke overhead (startup vs steady) | UNCHECKED/NEEDS_EXACT_COUNT stay Fast-Path-ineligible; B unratified |
| C | P9 gzip/NUL & decoders | p9 differential: this module strict vs mitmproxy lenient; pins match installed | Preserve the existing conditioned P9 superset decoding **for observation only**, with differential regression tests. Keep decoder pins (mitmproxy 12.2.3/Brotli 1.2.0/zstandard 0.25.0). | Owner chooses superset-decode vs R3-reject-after-NUL **before active use** (not now); explicit production pins/wheel hashes | p9 differential regression; missing/unsupported decoder; decoded-cap | No universal backend equivalence; zstd 8 MB window deferred |
| D | Framing & HTTP versions | No project code sets `validate_inbound_headers`; residual R1 only in `_check_framing`; raw_content ≠ wire | Test an explicit HTTP/1.1 lab profile with `validate_inbound_headers=true`, exact version/config recorded. Framing stays **UNAVAILABLE/UNVERIFIED** globally. | Approve the framing-control **design** separately (item kept open); approve the lab profile for testing | Raw-socket R1 vectors + valid counterparts; P4 target-form probe | "whitespace before colon"/"malformed chunks" wire-only; P4 open; "reached addon" ≠ R1 |
| E | Policies, statuses, positive evidence | Fast Path needs policy+framing VERIFIED+canonical ACCEPT; none present | **No client-visible policy change.** Canonical ACCEPT/REJECT/UNSUPPORTED observed only; V4 BLOCK→403, failures→503 unchanged; SIGNAL never blocks; CONNECT UNSUPPORTED ≠ ALLOW; unsupported-media/oversize/escape → ineligible, never override V4. S-JWT-*/S-ORIGIN-CROSS deferred (D57). | None beyond A–D; future client-status mapping, application policy, grammars, tolerated miss rate stay explicit & pending | Isolation + privacy tests | No #68/#36 closure; no operational FAST_ALLOW |

## 5. Observation status vocabulary (a skipped body is never an empty body)

`OK` (carries the canonical outcome) · `BODY_UNAVAILABLE` (`raw_content is None`; distinct from `b""`) ·
`MALFORMED_CONFIG` (Limits/B/cap missing or invalid) · `ADAPTER_ERROR` (RequestParts `TypeError`, or
absolute-form refused) · `DECODER_FAILURE` (kept as the canonical `REJECT R3`) · `EXCEPTION` (type +
code location only) · `BUSY`/`DROP`/`TIMEOUT` (only if offloaded). A failure never carries text or a
score.

## 6. Isolation / runtime (measure before choosing)

`canonicalize` is stdlib, CPU-light, synchronous (no numpy/sklearn, D33 not implicated) → default is a
**synchronous, bounded, in-hook** call guarded by total exception capture, like `shadow_fast_path`
([data_plane.py:369](../../../../data_plane/data_plane.py)) — NOT the Analyzer's separate-process model
(that is ML-specific). The one risk to bound is a crafted content-coded body: a **thread timeout does
not cancel a CPython computation**, so anything above the submission cap (bound #2) is `DROP`/offload to
a process, never a best-effort inline decode. Operational timeouts/backoff must be **measured** for this
path (wall-time distribution over representative + adversarial inputs; event-loop lag on vs off); do not
copy unapproved Analyzer defaults. If isolation cannot be demonstrated, deliver the adapter/harness and
leave the runtime hook disabled and explicitly incomplete.

## 7. File plan (AFTER approval — not created in this slice)

New (stdlib-only, data-plane venv):
- `data_plane/canonical_adapter.py` — mitmproxy `http.Request` → `cr.RequestParts` (§2), and a
  `GatewayEvidence.canonical()` returning a real `CanonicalResult` (replacing the `None` stub).
- `data_plane/canonical_observer.py` — default-off wrapper: config gate, the §5 status vocabulary,
  submission cap (bound #2), `perf_counter`/own-logger/own-exception discipline, the §6 runtime choice.
- `tests/test_canonical_adapter.py` — target-form mapping; raw_content vs get_content (bomb + bad
  encoding); `None` vs `b""`; header order/case/repeats; HTTP/1.0/1.1/2.0; `TypeError` guards.
- `tests/test_canonical_observer.py` — default-off (no behaviour/log); each status on its trigger;
  "skipped body never becomes empty body"; never raises; never touches `flow.response`; classifier
  call-count unchanged; privacy marker test (§8).

Shared files — **coordinator only**, after approval:
- `data_plane/data_plane.py` — wire the observer into `enforce()` after the verdict; config loader
  mirroring `load_shadow_*`; `addons` wiring; swap `GatewayEvidence.canonical` to the adapter.
- `config.yaml` — a new default-off `data_plane.canonical_observer` block (B / max_decoded_body /
  submission-cap / runtime; all PENDING owner values) + mitmproxy `body_size_limit`/`stream_large_bodies`
  for bound #1 (design only; not activated client-visibly in this slice).
- `requirements-*.txt` — none needed for stdlib canonicalize; pin br/zstd explicitly only if the
  observer relies on them (else `R3 decoder-unavailable`).

## 8. Acceptance / evidence matrix (what the slice must prove)

- **Adapter/canonical identity:** generator and adapter use the SAME `canonicalize` object; canonical
  results match for synthetic `RequestParts` and actual parsed requests across body absence/`None`/empty,
  exact content-coding, duplicate/order/case headers, UTF-8/escape, target forms, size boundaries,
  gzip multi-member/padding/trailing/missing-decoder/unsupported/decoded-cap. Never truncate to fit.
  Distinguish fixture identity from executed wire integration.
- **Wire R1 + conditioned P4 (raw sockets, local services only):** TE+CL, dup/invalid CL, multiple TE,
  TE on HTTP/1.0, non-final/repeated chunked, whitespace before colon, malformed chunks, CR/LF/obs-fold —
  each with a VALID counterpart; preserve valid obs-text where permitted. Record vector id + justification,
  pinned parser/config/env, client status/connection outcome, whether addon/classifier/upstream reached,
  canonical outcome, actual vs expected, limitation. P4: show where out-of-form targets are
  rejected/detected; if the current V4 route still forwards them, disclose the gap and keep P4 open.
  Negative config/version/protocol cases so verification cannot silently survive drift. Header-only
  fixtures are insufficient for wire R1.
- **V4 preservation & isolation (observer off vs on, deterministic classifier):** byte-identical D1
  input + unchanged /classify schema; exactly one classifier call (zero for pre-rejected); identical
  forwarding for ALLOW / model BLOCK / invalid / truncated / timeout / connection failure; observer
  errors/missing-settings/oversize/busy/drop/worker-failure/timeout handled; no feedback into V4; the
  `(classifier N ms)` timing definition unchanged.
- **Privacy:** synthetic credential/header/body markers; assert no request text, canonical body,
  target/query, credential value or hash, client-controlled reason string or excluded header-derived
  feature leaks; log only a closed allowlist (flow.id[:8] tag, closed status enum, fixed reason codes,
  timing numbers, exception **type** only, `v4=` context). Do not dump the canonical audit dict.
- **Bounds/overhead:** smoke-level overhead (startup vs steady), resource behaviour; not #81's full
  benchmark, not a model-quality claim.

## 9. D56 conflict and the guard-test amendment (do not delete to green the suite)

Integrating a real adapter means `data_plane.py` imports `canonical_request`, which
`test_gateway_and_v4_untouched_by_contract` ([tests/test_canonical_request.py:699](../../../../tests/test_canonical_request.py))
forbids (D56). This needs an explicit owner integration ruling. After approval, **narrow, not delete**:
keep the import ban on `request_features.py` and `control_plane/inference_core.py` (feature extractor
and V4 inference path stay contract-free); replace the `data_plane.py` substring ban with stronger
behavioural assertions — default-off, on/off outcome-equivalence across the 5 behaviours, one/zero
classifier-call, the timing-definition assertion, and the privacy marker test. Keep `fast_path.py`'s
stdlib-only/no-contract-import guard as applicable.

## 10. Why V4 stays authoritative and Fast Path stays CONTINUE

With `token_budget=None`, canonical size is **UNCHECKED** → never `WITHIN_BUDGET` → the Fast Path
exclusion "size not WITHIN_BUDGET" always holds. Framing stays **UNVERIFIED** (no pinned, tested,
project-owned wire control; raw_content ≠ wire). No policy of record exists. Therefore even a canonical
ACCEPT with demonstrated HTTP/1.1 framing cannot justify FAST_ALLOW; every request stays `CONTINUE` and
V4 remains the only authority. A low attack score or absence of suspicious features is never evidence
for ALLOW.

## 11. Grouped owner decision request — ANSWERED by D69 (2026-10-21)

The owner approved (A) default-off canonical observation, HTTP/1.1-evidenced, synthetic local lab only,
with the V4-preservation guarantees; (B) the lab-only submission cap and `max_decoded_body` = 1,048,576 B
and `token_budget=None` (size UNCHECKED) **for this experiment only** (not operational defaults, B still
deferred); (D) the HTTP/1.1 `validate_inbound_headers=true` lab profile with framing kept
UNAVAILABLE/UNVERIFIED globally. The framing-control design, the P9 superset-vs-R3 choice, production
decoder pins, B ratification, the application policy and the tolerated miss rate remain open.

## 12. Implemented in this slice vs still out of scope

**Implemented (uncommitted, default-off, D69):** the three modules, the gateway wiring + config loader,
the commented-off config block, the narrowed guard test, and the D69 record. V4 preservation verified
(35 tests, excluding the protected eval-parity reader); the two module suites (29) pass; the
behavioural-preservation/privacy suite and the wire-evidence harness are delivered alongside.

**Still out of scope (separate gates / approvals):** final V5 token constant B and production limits;
Brotli/zstandard deployment pins + wheel hashes; the project-owned framing control and `framing=VERIFIED`;
the P9 superset-vs-R3 choice for active use; HTTP/2 evidence; active Fast Path policy/enforcement; Model
2 / V5 serving. Protected boundaries honoured: no R3, no INTERNAL/External Test opened, no real
split/freeze/train, no FINAL/SSRF/Q4_K_M, no invented Fast Path policy/score/threshold, no #68/#36/#38
closure. **Data-access accounting (corrected):** running the full `tests.test_data_plane` module
exercises the existing V4 **rendering-parity regression**
(`TestRenderRequest.test_reproduces_the_v4_dataset_representation`), which reads
`datasets/v4_clean/eval.jsonl` (6,206 rows). It is the existing D1 render-parity regression; it is
neither model fitting nor a new evaluation. This disclosure does not characterize that read as
authorized, nor does it claim contamination or non-contamination either way, and the dataset was not
opened to investigate. That reader was exercised when the full module ran in review; every
targeted/correction-pass run here **excludes** it (and all other protected readers) by explicit
selection, and the original regression is preserved unchanged.
Frozen hashes untouched (r3 `f1580634…`, r4
`54514850…`, prereg `1039a3dd…`).
