# V5 stage 1 — `canonical-request/v1` implementation (independent, NOT integrated)

**Date:** 2026-10-13 · **Branch:** `feat/v5-canonical-request` · **Spec:** `V5-DATA-SPEC-r3` (FROZEN, D62),
SHA-256 `f1580634d35d2baf10b99d7985f9bfb1e56ebc956326a58a61b665fc5958d9cb` verified before work began
(`cd reports/v5/v5-data-spec-draft && sha256sum -c SHA256SUMS` → OK, re-checked after the ratification
round). The spec, its `SHA256SUMS`, decisions D1–D62, the V4 runtime (`control_plane/inference_core.py`,
`data_plane/data_plane.py`) and every frozen artifact are unchanged. The owner's rulings on this stage are
recorded append-only as **D63** (2026-10-13).

Stage 1 delivers the contract as an independent, tested library. The gateway still renders V4's D1 text
(D56); no generator, dataset, model or policy exists. Nothing here enables a control or a block.

## 1. Files

| File | Role |
|---|---|
| `data_plane/canonical_request.py` | `canonicalize(RequestParts, Limits) → CanonicalResult` (ACCEPT / REJECT / UNSUPPORTED) and the reference parser `parse_canonical` (I3/I8). Stdlib-only at import |
| `control_plane/v5_tokenization.py` | §5.4 template-safe encoding and §5.5 budget helpers; parametrised template; no ML import |
| `scripts/dataset/measure_v5_template_budget.py` | deterministic tokenizer-only measurement → `tokenization_budget.json` |
| `tests/test_canonical_request.py` | contract tests: R2–R8 + counterparts, residual R1, I2–I10, representation, signals |
| `tests/test_canonical_request_review.py` | independent adversarial review tests (Agent B) |
| `tests/test_canonical_request_tokenization.py` | canonical texts through the §5.4 tokenization (special ids, additivity, R8 with a real counter, byte zones) |
| `tests/test_v5_tokenization_helper.py` | helper tests (equivalence with the frozen reference `encode_safe`, injection strings, AST hygiene) |
| `tests/test_canonical_request_limits.py` | decoder resource bounds: per-coding output bound, exact cap, linear time, peak RSS, large zstd window |
| `scripts/dataset/check_v5_gzip_padding_differential.py` | P9 local differential check → `p9_gzip_padding_differential.json` |
| `requirements-v5-canonical.txt` (repo root) | PROPOSED decoder pins for a generator environment without mitmproxy (not installed) |
| `tokenization_measurements.md`, `tokenization_budget.json` | measured values vs reference-only vs candidate vs PENDING |

## 2. Contract as implemented

```
canonicalize(parts, limits) -> CanonicalResult(outcome, text, reject, reason, signals, size, audit)
```

- `RequestParts(method: bytes, target: bytes, http_version: str, headers: ((name, value) bytes pairs, received order), body: bytes de-chunked, still content-coded)`.
- `Limits(max_decoded_body, token_budget=None, count_tokens=None, max_bytes_per_token=None)`. **No defaults are invented:** `MAX_DECODED_BODY`, `B` and the bytes-per-token bound are PENDING (§11.2) and must be passed by the caller. `max_decoded_body` is mandatory, so decompression is never unbounded.
- Text: `{METHOD} {TARGET} HTTP/1.1\n[Content-Type: {value}\n][\n{BODY}]` exactly as §5.2.

### 2.1 What goes where

| Category | Content |
|---|---|
| **Model text** | method as received; origin-form target bytes (absolute-form reduced to path+query, `*` for asterisk-form); constant `HTTP/1.1`; `Content-Type` value (outer OWS trimmed, ISO-8859-1); decoded body (strict UTF-8, invalid octets `\xNN`, BOM/CR/LF verbatim) |
| **Audit record** (never values of headers, target or body) | contract/spec ids, received version, method, header **names** in received order, framing facts (TE codings, field counts, CL value, received body bytes), content codings, decoded body bytes, target form, absolute-form scheme + authority (userinfo stripped, presence flagged), media type, `media_in_training_scope`, UTF-8 flags, reject id, text bytes + SHA-256 |
| **Signals** (no enforcement effect, D57) | implemented: `S-TARGET-NONASCII`, `S-BODY-UTF8`, `S-CT-NONASCII`, `S-CT-MALFORMED`, `S-CT-ABSENT`, `S-MEDIA-UNSUPPORTED`, `S-CHARSET`, `S-CT-MISMATCH` (application/json only), `S-ENC-MULTI`, `S-ENC-U`, `S-ENC-NUL`, `S-UTF8-OVERLONG`, `S-OVERSIZE`, `S-CONNECT` |
| **Deterministic rejects** | R6 → R5 → R4 → R7 → R1 (residual) → R2 → R3 / R8 (cap) → R8 (budget); first failing check wins; stable reason strings |
| **Unsupported / deferred** | `CONNECT` → `UNSUPPORTED` + `S-CONNECT` (no text; policy at integration). Deferred signals: `S-JWT-*` (4), `S-ORIGIN-CROSS` (need `Authorization` / `Origin` values and the destination authority, owned by the integration layer under D57's no-log rule) |

### 2.2 Interpretations where r3 is silent (rulings in D63)

| # | Point | Choice | Why | D63 status |
|---|---|---|---|---|
| P1 | Reject precedence | fixed order above | r3 lists rejects but no precedence; determinism needs one | RATIFIED |
| P2 | `CONNECT` outcome | third outcome `UNSUPPORTED`, no text | §5.2 says "outside the V5 contract"; rendering an authority-form target would put the destination authority in the model text (D57) | RATIFIED; I7 clarified; `UNSUPPORTED` never implies ALLOW |
| P3 | `\xNN` hex case | lowercase (Python `backslashreplace`) | §5.2 does not fix case; freeze-prep A §7.1 names `backslashreplace` | RATIFIED |
| P4 | Target not in any RFC 9112 §3.2 form | rendered byte-preserved, `target_form: other` | no R-rule covers it; inventing a reject is forbidden | **CONDITIONED**: integration must show such targets never reach the model unnoticed (not done) |
| P5 | Media scope | **corrected (D63):** with a `Content-Type`, in scope iff its media type ∈ §2.2 list (malformed = out), even with an empty body; without `Content-Type`, in scope iff the body is empty | literal §5.2 "Media type outside §2.2 → S-MEDIA-UNSUPPORTED" | RATIFIED with correction |
| P6 | Stray `Content-Encoding` on an empty body | codings validated (unknown → R3), nothing decoded | an empty octet string is not a stream; rejecting it would be an invented restriction | RATIFIED |
| P7 | `x-gzip` | alias of `gzip` | RFC 9110 §8.4.1.3 | RATIFIED |
| P8 | `deflate` without zlib wrapper | accepted (zlib first, raw fallback) | RFC 9110 §8.4.1.2 notes the non-conformant form; mitmproxy does the same | RATIFIED |
| P9 | gzip NUL padding | accepted between/after members; any other trailing data → R3 | CPython `gzip.decompress` semantics; trailing data after deflate/br/zstd → R3 | **CONDITIONED**: local differential done (§4.4), owner choice pending |
| P10 | Residual R1 | TE+CL, >1 TE field, TE on HTTP/1.0, empty TE, non-final or repeated `chunked`, >1 CL field, non-digit CL, CL ≠ body length | §5.3 "TE value and CL validity"; RFC 9112 §6.1–§6.3 | RATIFIED; R1 stays UNVERIFIED |
| P11 | `S-ENC-*` / `S-UTF8-OVERLONG` scope | raw target and decoded body as whole byte strings | percent-decoding is local, so this equals a per-value test | RATIFIED as diagnostic only |
| P12 | Coding names in the audit record | known names only, else `<other>`; transfer codings corrected to `chunked`, `compress`, `deflate`, `gzip`, `x-compress`, `x-gzip` | the audit record must not echo client-chosen header values (§5.2, D57); RFC 9112 §7, §7.2 | RATIFIED with correction |

## 3. "stdlib-only" versus `br` / `zstd` (clarified in D63; no r4)

§5.1 calls `canonicalize` "stdlib-only", but §5.2 (frozen) requires `br` and `zstd`, and Python 3.12 has
no stdlib decoder for either (`compression.zstd` exists only from 3.14; Brotli is never stdlib). The
phrase sits in §5.1, outside the detail D62 ratified, and D56 asks only for a "pure, deterministic
function", so no frozen requirement conflicts. D63 records the dated interpretation: the module imports
and runs on the standard library; `br` / `zstd` use `brotli` / `zstandard`, imported lazily; a missing
decoder is an explicit R3 `content-coding-decoder-unavailable:<c>`.

**Dependencies (PROPOSED).** `requirements-v5-canonical.txt` pins `Brotli==1.2.0` and `zstandard==0.25.0`
(libzstd 1.5.7, C backend), the versions `.venv-dataplane` already has through `mitmproxy==12.2.3`.
Nothing was installed. Verified on CPython 3.12.15 linux x86_64: with only those two packages and
`data_plane/` on `sys.path` (`python3.12 -I -S`), `canonicalize` decodes gzip, br and zstd and mitmproxy,
transformers and torch are not importable, so the V5 generator can run in its own environment.
`.venv-dataplane` and `requirements-data-plane.txt` were not touched. Hashes, other interpreters and the
data-plane pin are owner decisions.

## 4. Decompression limits (reviewed and corrected 2026-10-13)

### 4.1 What the code bounds

`max_decoded_body` (caller-supplied, production value PENDING) is compared with the accumulated decoded
output after **every** bounded decoding step, for each layer of a stacked coding. An identity body is
compared by its own length; a coded body is never rejected for its received length (R8 is about the
decoded body).

| Coding | Step | Held output before R8 (bound) | Measured, 64 MiB zero bomb, 1 MiB cap |
|---|---|---|---|
| gzip, deflate | `zlib` `max_length` = remaining + 1 | ≤ cap + 1 | cap + 1, 1.1 ms |
| br | 32 KiB input slices; `output_buffer_limit=1` per call (one output block) | ≤ cap + 32,752 (Brotli 1.2.0 block) | cap + 32,240, 5.4 ms |
| zstd | 64-byte input slices (≤ 17 blocks of ≤ 128 KiB) | ≤ cap + 2,228,224 | cap + 393,216, 0.3 ms |

### 4.2 Defects found and fixed in this review

1. **Brotli overshoot.** The previous code passed `output_buffer_limit=cap+1`; Brotli 1.2.0 treats it as
   "stop growing once reached" and grows its buffer in blocks, so a call could return far more:
   1,001 → 32,752; 100,000 → 229,328; 10,000,000 → 16,744,304 bytes. Fixed by draining one block per
   call. The old truncation test (`can_accept_more_data()`) was also wrong for this mode (it is already
   True while buffered input is still being decoded) and rejected a valid 1 MiB stream; truncation is now
   "a call yields nothing on an unfinished stream".
2. **Quadratic time on many members / frames.** Each gzip member and zstd frame re-copied the whole rest
   of the body (`unused_data`). 40,000 empty gzip members (800 KB) took 0.25 s and grew ~4× per doubling.
   Fixed by walking the body by offset with slices that grow from 64 bytes (zstd: fixed 64). Tested:
   ×4 input → < ×8 time, 80,000 members < 2 s.
3. **Quadratic Brotli drain (found by the independent decoder review).** With the whole body handed to
   Brotli at once, every one-block drain call re-scanned the input still buffered in the library:
   32 MB → 0.70 s, 64 MB → 15 s, 128 MB → 72 s (huge cap). Fixed by feeding 32 KiB input slices:
   128 MB → 0.1 s. Regression test: 32 MiB incompressible body < 3 s. 480 valid streams (quality 0–11,
   lgwin 10–24, sizes around 32,752 multiples, flush-generated empty metablocks) decode exactly and
   every truncation is rejected.

The independent review (Sonnet, read-only) also confirmed: the output bounds (a handcrafted
128 KiB-RLE zstd frame reached cap + 2,097,152 < the stated 2,228,224); exact-cap acceptance across
members, frames and stacked codings; every proper prefix rejected R3; ~4,400 valid Brotli streams with no
false "truncated"; 60,000 fuzz calls with no exception; the P5 rule. Informational: a non-empty coded body
that decodes to empty is treated as body-less (scope and `S-CT-ABSENT` follow the decoded body), and the
final `bytes(out)` copy makes the transient peak ≈ 2 × cap at return.

### 4.3 Memory and time (measured, `tests/test_canonical_request_limits.py`)

Peak RSS growth during `canonicalize` (VmHWM, fresh process that only decodes), 1 MiB cap: gzip /
deflate ≈ 1.4–1.8 MiB, br / zstd ≈ 4.7–5.3 MiB; a br stream with the maximum 16 MiB window ≈ 17 MiB; a zstd frame
declaring a 128 MiB window ≈ 4.9 MiB (the window buffer is only touched as output is produced, which the
cap bounds, so **no window reject was added**; RFC 9659's 8 MB limit for HTTP `zstd` is noted as an
integration option). 4 MiB of incompressible data decodes and renders in ≈ 0.2 s per coding.

**What is and is not guaranteed.** Output and time bounds are enforced by the code and pinned by tests;
the br bound depends on Brotli 1.2.0 (a test fails if a different version changes it). Peak memory is
measured, not proven: it adds the decoders' own state (br window ≤ 16 MiB, zstd window allocation) to the
cap. The compressed input itself is not bounded here: the gateway's body limit is an integration item.
Status: **TESTED for the local cases above; not a formal guarantee for every input.**

### 4.4 P9 — local differential check (`p9_gzip_padding_differential.json`)

Seven local components, ten fixed vectors (deterministic output, run twice, same SHA-256):

| Vector | this module | CPython 3.12 / 3.14 | mitmproxy `encoding.decode` | GNU gzip 1.14 | pigz | busybox | Node 22 `zlib` |
|---|---|---|---|---|---|---|---|
| NUL padding after last member (1 / 1000 B) | ok | ok | ok | ok | ok | ok | ok |
| two members | both | both | **first only** | both | both | both | both |
| member, 8 NUL, member | both | both | first only | first only (warning) | first only | first only | first only |
| trailing garbage / NUL + garbage / partial magic | R3 | error | first member | first member (warning/error) | first member | first member | error / ok / error |
| truncated member (trailer cut) | R3 | error | **accepted** (no trailer check) | error | error | error | error |

Findings: padding after the last member is accepted by every component. **They diverge on a member that
follows NUL padding** (this module and CPython decode it; five components stop at the first member), and
mitmproxy's decoder ignores **any** second member and trailing data. In every measured case this module
either rejects or inspects a superset of what another component executes; no equivalence with any other
backend is claimed. **Integration requirement:** the adapter must pass mitmproxy's `raw_content`, never
its decoded content. P9 remains CONDITIONED until the owner chooses between keeping the superset
behaviour and rejecting data after NUL padding as R3.

## 5. Token budget (§5.5) and the V5 template

See `tokenization_measurements.md`.
- **V4 reference (not V5):** overhead 56, `label_budget` 13, `B` 435.
- **V5 candidate (PROPOSED, D63; not frozen):** TinyLlama-Chat native structure (verified against the
  tokenizer's own chat template on the base snapshot `fe8a4ea` and the V4 copy), owner's candidate
  instruction, candidate vocabulary (V4 ALLOW string + 11 V4/D47 BLOCK strings of the §2.3 planned
  categories). Base TinyLlama tokenizer: **overhead 76, `label_budget` 13 (13 also over all 20 V4
  strings), candidate `B` = 512 − 76 − 13 − 8 = 415**; additivity 343/343; special ids in content 0/343;
  exactly one structural assistant turn in 343/343 texts and in the injected role-marker tests.
- **Final** `template_overhead`, `label_budget`, `B`: PENDING ratification of the template and the
  vocabulary (§2.3 tiering), then the preregistration. `max_length` 512 and margin 8 stay provisional.
- Strict output parser: PROPOSED (exact match against the ratified vocabulary after the first EOS;
  anything else `invalid`, enforced fail-closed by the data plane). Not implemented.

## 6. Escape ambiguity (D62 limitation — not solved)

Tested explicitly (`test_escape_ambiguity_is_stated_not_solved`): literal `\xff` and the invalid octet
0xFF produce the **same model text**; only the audit signal differs. Nothing in stage 1 claims otherwise.
Requests carrying `S-BODY-UTF8` / `S-TARGET-NONASCII` remain outside the V5 training distribution; an
unambiguous escape would need r4 and an owner decision.

## 7. Independent review (Agent B) and corrections

| Finding | Class | Correction |
|---|---|---|
| `Content-Type` media-type regex backtracked exponentially (`a/b` + `"; "`×40 + `@`: hours; passes R4) — a DoS and an I7 bounded-time failure | robustness bug | regex rewritten so each `;` iteration is unambiguous; 60 KB adversarial values now parse in ≤ 5 ms; regression test runs in a subprocess with a 5 s timeout |
| R8 cap was applied to the *received* length of coded bodies; an incompressible body of exactly `cap` decoded bytes was rejected | spec deviation (§5.3 R8 "decoded body") | received-length check kept only for identity bodies; decoders enforce the cap on output |
| Unknown `Content-Encoding` / `Transfer-Encoding` strings were echoed into the audit record | spec ambiguity, privacy | only registered coding names are recorded; others become `<other>` |
| CL ≠ body length as residual R1; empty-body media scope; empty target rendered; unknown coding on empty body still R3 | defensible choices | kept, documented as P5, P6, P10, P4 |

The four review tests that pinned these bugs as expected failures now pass as ordinary regression tests
(their comments were rewritten as regression descriptions on 2026-10-13). The ratification round added
the P5 correction, the P12 list correction and the two decoder fixes of §4.2.

## 8. Compliance matrix

TESTED = implemented and a named passing test exists. PARTIAL = implemented, but part of the requirement
needs a component that does not exist yet. DEFERRED = later stage by the spec. UNVERIFIED = deliberately
not claimed.

| Req | Status | Evidence |
|---|---|---|
| R1 | **UNVERIFIED** (residual facts implemented + tested) | `R1Residual`; wire-level vectors at integration (§5.3) |
| R2 | TESTED | `R2TransferCoding` + review matrix |
| R3 | TESTED (gzip, x-gzip, deflate, identity everywhere; br, zstd in `.venv-dataplane` only) | `R3ContentCoding`, review R3 tests |
| R4 | TESTED | `R4FieldValues` (+ obs-text/HTAB counterparts) |
| R5 | TESTED | `R5Target` (byte boundaries in review) |
| R6 | TESTED | `R6Method` |
| R7 | TESTED | `R7ContentType` |
| R8 cap | TESTED with test caps for the local cases of §4 (output + time bounds enforced, memory measured; `MAX_DECODED_BODY` PENDING) | `R8Size`, `test_canonical_request_limits`, review boundaries |
| R8 budget | TESTED as a rule (stand-in counter + real tokenizer counter, data-plane byte zones); `B` PENDING | `R8Size`, `test_r8_with_real_token_counter_exact_boundary` |
| I1 | **DEFERRED** | no generator or gateway adapter exists (stage 2 / integration) |
| I2 | PARTIAL | same parts → same bytes, across processes and hash seeds; end-to-end train/serve needs both adapters |
| I3 | TESTED on fixtures + 5,000-case fuzz; "every generated row" at stage 2 | `test_i3_*`, fuzz |
| I4 | TESTED at parts level (CL / chunked / gzip / deflate / br / zstd); wire level at integration | `test_i4_framing_independence` |
| I5 | TESTED | `test_i5_metadata_invariance` |
| I6 | TESTED | `test_i6_byte_preservation` |
| I7 | TESTED on a seeded fuzz corpus of 5,000 (+2,500 review); corpus size PROPOSED, owner ratification pending | `test_i7_*` |
| I8 | TESTED (structure); content-escape ambiguity accepted, not solved | `test_i8_*`, `test_escape_ambiguity_is_stated_not_solved` |
| I9 | PARTIAL (static check over current code; no generator call sites yet) | `test_i9_*` |
| I10 | TESTED for R2–R8 | the R-classes above |
| §5.4 tokenization | TESTED on the TinyLlama tokenizer with the V4 reference template and the V5 **candidate** template | helper + cross tests, `V5CandidateTemplate` |
| §5.5 constants | bytes/token bounds re-verified; candidate overhead 76 / label 13 / B 415 measured; **final values PENDING** template + vocabulary ratification | `tokenization_measurements.md` |
| P4 | **CONDITIONED, not validated** | integration |
| P9 | **CONDITIONED**; local differential done | `p9_gzip_padding_differential.json` |
| Signals | 14 of 19 implemented and tested; `S-JWT-*` ×4 and `S-ORIGIN-CROSS` DEFERRED; `S-CT-MISMATCH` JSON-only (PARTIAL) | signal tests |

## 9. Tests (2026-10-13, after the ratification round)

| Suite | `.venv-dataplane` (Py 3.12.15, brotli 1.2.0, zstandard 0.25.0) | `/usr/bin/python3.12` (transformers 5.8.0) |
|---|---|---|
| `test_canonical_request` | 76 run, OK, 1 skipped (missing-decoder path: decoders present) | 76 run, OK, 3 skipped (br/zstd) |
| `test_canonical_request_review` | 115 run, OK | 115 run, OK, 8 skipped (br/zstd) |
| `test_canonical_request_limits` | 7 run, OK | 7 run, OK, 2 skipped (zstd; br/zstd cases inside loops skipped) |
| `test_canonical_request_tokenization` | skipped (no transformers) | 8 run, OK |
| `test_v5_tokenization_helper` | 3 AST tests run, 15 skipped | 18 run, OK |
| `test_v5_tokenization_contract` (existing) | skipped | 29 run, OK |

No interpreter has both br/zstd and a tokenizer, so the union of both is the full coverage. Regressions:
`test_data_plane` + `test_request_features` (80, OK, data-plane env); `test_v4_representation_contract` +
`test_inference_core` + `test_classifier_api` (77, OK, 21 pre-existing skips, python3.12).
