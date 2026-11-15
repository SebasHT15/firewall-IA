# V5 canonical-request/v1 — Wire evidence (issue #68 §8, R1 / R2 / P4 / P9)

**Date:** 2026-10-21 · **Branch:** `feat/hybrid-gateway-prerequisites` · **Status: PREPARATION / observation slice.**
Nothing here enforces or forwards in production. This report records what an **actual local raw-socket
lab** observed; it does **not** ratify a runtime control.

Produced by `scripts/wire_evidence/` (harness + runner), tested by `tests/test_wire_evidence_harness.py`.
Machine-readable results: `wire_evidence_results.json`; run environment: `run_metadata.json`; raw proxy
logs: `mitmdump_lab.log`, `drift_vih_true.log`, `drift_vih_false.log`.

**Log-file honesty.** The closed-vocabulary / no-request-byte privacy guarantee is about the NEW
observer's own `CANONICAL OBS` lines only (A §observer, tested by C). The surrounding `mitmdump_lab.log`
is a **separate, pre-existing gateway log stream**: it contains the existing `FirewallGateway` lines
(`received METHOD host:port/path …` with the lab's synthetic paths, `ALLOW`, `BLOCK (fail-closed)`) and,
for the obs-text vector, a Python exception traceback. Those lines are not covered by the observer's
privacy guarantee and are not described here as closed-vocabulary. The lab paths are synthetic
(`/ok`, `/x`, `*`, `http://sink.test/...`); no real request data is involved.

**This report supersedes an earlier build** whose `run_metadata.json` listed `stream_large_bodies: 0`.
That was inaccurate (the launcher leaves the option UNSET). The metadata below is a fresh timestamped run
(`generated_at` in `run_metadata.json`) that records REQUESTED vs EFFECTIVE options read back from the
running lab; prior per-vector raw results were not retro-edited.

## Honesty bars (owner corrections, binding on every claim below)

1. **"A request reached the addon" is NOT evidence of R1.** By the time the addon's `request` hook runs,
   mitmproxy has already parsed and de-chunked the wire; `raw_content` is de-chunked and still
   content-coded, not the original octets. R1 is evidenced only by the **client-observed** socket
   outcome and by **hop divergence**, never by what the addon received.
2. **A normalized forward is NOT enforcement of a stricter project REJECT rule.** When mitmproxy accepts
   a vector, rewrites its framing and forwards it, that is recorded as `NORMALIZED_FORWARD`, never as
   "R1 enforced".
3. **Parser reachability and P4 handling are established only by observed wire results**, not by reading
   mitmproxy source.
4. **Scope of certification.** This establishes behaviour of the **tested lab profile only** (mitmproxy
   **12.2.3, pinned** in `requirements-data-plane.txt`, `validate_inbound_headers=true`, HTTP/1.1; the
   Brotli 1.2.0 / zstandard 0.25.0 decoders are the versions **observed in this lab**, and their direct
   deployment pins remain **unratified**). **Runtime framing stays
   UNAVAILABLE / UNVERIFIED globally** until a scoped wire-level control is implemented *and* approved.
   Nothing here sets `VERIFIED` globally, and nothing here claims R1 can never be established later.

## Lab profile (executed)

**Versions (observed in `.venv-dataplane`, recorded in `run_metadata.json`):** mitmproxy **12.2.3**,
Brotli **1.2.0**, zstandard **0.25.0**, CPython **3.12.15**. The `config.yaml` SHA-256 in
`run_metadata.json` (`1067068b…`) is the configuration **at the recorded run** and is retained as-is.
`config.yaml` has since received a **comment-only** edit (the ~30 ms worst-case→observed-duration
wording), so its current on-disk SHA differs from the recorded one; **no runtime setting or behaviour
changed**, and the recorded hash was not rewritten to pretend otherwise. The wire harness did not modify
`config.yaml` or `data_plane/data_plane.py` (those are the coordinator's integrated files).

**Version-claim honesty.** `mitmproxy==12.2.3` is a **pinned** data-plane dependency
(`requirements-data-plane.txt`). **Brotli 1.2.0 and zstandard 0.25.0 are OBSERVED** (transitive
dependencies of mitmproxy in `.venv-dataplane`); they are **not ratified direct deployment pins** here.
All version/profile claims are derived from the runtime metadata, not asserted independently.

**Requested vs effective options (read back from the running lab, `run_metadata.json`).** The launcher
REQUESTS `validate_inbound_headers=true`, `http2=false`, `connection_strategy=lazy`, `termlog_verbosity=info`,
`flow_detail=0`, and the reverse `mode`; it deliberately leaves `stream_large_bodies` UNSET. The EFFECTIVE
values read from the live instance (via `lab_addon`'s `EffectiveOptions` addon) were:
`validate_inbound_headers=True`, `http2=False`, `connection_strategy='lazy'`, `stream_large_bodies=None`
(mitmproxy default — never stream, so `raw_content` is buffered at the hook), `body_size_limit=None`,
`mode=['reverse:http://127.0.0.1:<sink>']`. There is no `stream_large_bodies=0` claim anywhere.

```
raw-socket client ──▶ mitmdump 12.2.3 (reverse proxy)  ──ALLOW──▶ upstream SINK (records hop 2)
   (stdlib socket,       --set validate_inbound_headers=true          (raw TCP, preserves dup headers,
    exact bytes,         --set http2=false                             reports body length actually read)
    no re-framing)       --set connection_strategy=lazy
                         -s scripts/wire_evidence/lab_addon.py  ──▶ /classify STUB (deterministic ALLOW,
                           (REAL data_plane.FirewallGateway +           counts hits)
                            REAL canonical-request/v1 observer,
                            pointed at the local stub; config.yaml untouched)
```

The real `FirewallGateway` request hook, fail-closed logic and the real separate-process
`canonical-request/v1` observer all run. The observer is enabled through the dedicated `lab_addon.py`
(it constructs the gateway with the observer, reading the stub URL from the environment) so that
`config.yaml` need not be touched. `stream_large_bodies` is left UNSET on purpose: its default buffers
the whole body so `raw_content` is present at the hook (setting it to `0` streams every body and makes
`raw_content` None — observed and corrected during bring-up).

**Raw sockets are mandatory.** httpx/requests/curl re-frame TE/CL, collapse duplicate headers and fix
chunking, which would sanitize a vector before it hit the wire. `tests/test_wire_evidence_harness.py`
proves the client+sink actually place and record two `Content-Length` lines a convenience client cannot.

Socket send boundaries are **not** HTTP message boundaries: a correctly framed body plus extra bytes, a
premature EOF and a true length mismatch are distinguished by the vector's own framing and the
client/sink observations, not by when `send()` returned.

---

## 1. R1 — wire framing (EXECUTED)

Observed outcomes under `validate_inbound_headers=true`. "Expected (hypothesis)" is the paper
prediction; "Observed (wire)" is executed. `expected_contract` is the residual outcome
`canonical_request.canonicalize()` gives on the parts that survive parsing — a **separate, parts-level**
control, confirmed in §5, never conflated with the wire result.

| Vector | Exact-byte gist | Justification | Expected (hyp.) | Observed (wire) | Upstream got it? |
|---|---|---|---|---|---|
| R1-TECL | `Transfer-Encoding: chunked` + `Content-Length: 5` | RFC 9112 §6.1 TE.CL | reject | **PARSER_REJECT (400)** | no |
| R1-DUPCL-EQ | two `Content-Length: 5` | §6.3.4 | reject | **PARSER_REJECT (400)** | no |
| R1-DUPCL-NE | `Content-Length: 5` + `: 6` | §6.3.4 (smuggling) | reject | **PARSER_REJECT (400)** | no |
| R1-BADCL-HEX | `Content-Length: 0x5` | §6.3 1\*DIGIT | reject | **PARSER_REJECT (400)** | no |
| R1-BADCL-PLUS | `Content-Length: +5` | §6.3 no sign | reject | **PARSER_REJECT (400)** | no |
| R1-MULTITE | two `Transfer-Encoding` lines | §6.1 | reject | **PARSER_REJECT (400)** | no |
| R1-TE-EMPTY | `Transfer-Encoding:` (empty) | §6.1 | reject | **PARSER_REJECT (400)** | no |
| R1-TE10 | `Transfer-Encoding: chunked` on HTTP/1.0 | §6.1 downgrade | reject | **PARSER_REJECT (400)** | no |
| R1-CHUNK-NONFINAL | `Transfer-Encoding: chunked, gzip` | §6.1 chunked final | reject | **PARSER_REJECT (400)** | no |
| R1-CHUNK-REPEAT | `Transfer-Encoding: chunked, chunked` | §6.1 | reject | **PARSER_REJECT (400)** | no |
| R1-WS-COLON | `Host : s` (space before colon) | §5.1 (desync) | reject | **PARSER_REJECT (400)** | no |
| R1-BADCHUNK | chunk size `zz` (not hex) | §7.1 | reject | **CONN_RESET** (no response, torn down) | no |
| R1-OBSFOLD | obs-fold continuation (`a` CRLF HTAB `b`) | §5.2 obs-fold | either | **NORMALIZED_FORWARD (200)** — see finding A | **yes** |
| R1-BARE-LF | bare-LF line endings in the head | §2.2 | either | **NORMALIZED_FORWARD (200)** — see finding B | **yes** |

**Headline (counts from the saved JSON):** of the 14 R1 vectors, **11 were PARSER_REJECT (HTTP 400)**,
**1 was CONN_RESET** (R1-BADCHUNK, connection torn down, no response), and **2 were NORMALIZED_FORWARD**
(R1-OBSFOLD and R1-BARE-LF, accepted+normalized and forwarded). So **12 of 14 did not reach upstream**
(11 × 400 + 1 reset; classifier never called for them) and 2 reached upstream after normalization — not
"12 HTTP rejections plus a reset". This rejection is **wire-level behaviour of a third-party parser
under the tested configuration**, *not* a project-owned control (see §4).

**Finding A (obs-fold — a normalized forward that the contract rejects).** R1-OBSFOLD was **accepted,
unfolded and forwarded** (client 200, upstream received a single `X-Fold` header). The real
`canonical-request/v1` observer, running the project contract on the forwarded parts, **REJECTED the same
request `R4 field-value-cr-lf-nul`** (correlated by tag in `mitmdump_lab.log`). So the parser's "accept +
normalize" is *not* the contract's "clean": a request the parser forwarded would be rejected by the
canonical contract. This is exactly why a normalized forward must never be counted as R1 enforcement.

**Finding B (bare-LF tolerated).** R1-BARE-LF was accepted, normalized to CRLF and forwarded (client 200);
the observer then ACCEPTED the resulting parts. The tested profile tolerates bare-LF framing — a
smuggling-relevant tolerance worth recording, not a contract reject.

### VALID counterparts (must pass — EXECUTED)

| Vector | Observed (wire) | Observer (canonicalize on forwarded parts) |
|---|---|---|
| VALID-GET | NORMALIZED_FORWARD (200) | OK / ACCEPT (origin) |
| VALID-CL (`Content-Length: 5`, 5-byte body) | NORMALIZED_FORWARD (200) | OK / ACCEPT, decoded_body_bytes=5 |
| **VALID-CL-OWS** (`Content-Length:  5 `, legal OWS, 5-byte body) | NORMALIZED_FORWARD (200) | **OK / ACCEPT, decoded_body_bytes=5** — legal OWS treated as VALID, not as an invalid CL |
| VALID-CHUNKED | NORMALIZED_FORWARD (200); upstream still chunked | OK / ACCEPT, transfer_encoding=chunked, body=5 |
| VALID-HTAB (HTAB in value) | NORMALIZED_FORWARD (200) | **OK / ACCEPT, decoded_body_bytes=0** (correlated obs line) |
| **VALID-OBSTEXT** (obs-text octet `0xE9`) | **FAIL_CLOSED (503)** — see finding C | — (never reached the observer) |

**Finding C (a real train/serve bug in the CURRENT V4 path).** VALID-OBSTEXT carries a header value with an
obs-text octet (`0xE9`), which the contract treats as a VALID R4 counterpart (ACCEPT, §5). On the wire the
**current gateway fail-closed with 503**: `data_plane.render_request` / the httpx `/classify` POST raised
`UnicodeEncodeError: 'utf-8' codec can't encode character '\udce9'` (surrogateescape from mitmproxy's
header decode), caught as an "unexpected data plane error" → 503. The classifier was never called. This is
a genuine gap in the V4 D1 rendering that the canonical contract (ISO-8859-1 header handling, obs-text
permitted) is designed to remove — captured here as live evidence, not hypothesis.

---

## 2. R2 — non-chunked transfer coding (DISTINCT from R1, EXECUTED)

| Vector | Justification | Observed (wire) | Contract (parts) |
|---|---|---|---|
| R2-TE-GZIP (`Transfer-Encoding: gzip`, lone) | RFC 9112 §6.1; classified ≠ executed content | **PARSER_REJECT (400)** | REJECT **R2** transfer-coding-not-chunked |

R2 is kept as its own group and its own contract reject (R2, not R1). Under the tested profile the parser
rejects a lone non-chunked transfer coding at the wire; the contract would reject it R2 at the parts level.

---

## 3. P4 — request-target forms (established ONLY by observed wire behaviour)

| Vector | Observed (wire) | Observer | Note |
|---|---|---|---|
| P4-ABSFORM (`GET http://sink.test/abs-target`) | NORMALIZED_FORWARD (200); upstream saw the absolute-form line | **OUT_OF_SCOPE / absolute_form** | adapter refuses to reconstruct the authority from `data.path`; canonicalize is never run |
| P4-ASTERISK (`OPTIONS *`) | NORMALIZED_FORWARD (200) | OK / ACCEPT, target_form=asterisk | in-scope form |
| P4-OTHER (`GET not-a-path`) | **PARSER_REJECT (400)** | — (not forwarded) | the odd target did not survive the parser under this profile |

**P4 stays CONDITIONED (D63).** The lab shows that under this profile absolute-form is *forwarded on the
wire* but the observer marks it OUT_OF_SCOPE (never submitted to the model), and that an unrecognized
target form was rejected by the parser here. This is evidence for **this profile only**; it does **not**
discharge the P4 condition (that out-of-form targets never reach the model unnoticed in the integrated
gateway). No future P4 guarantee is claimed.

---

## 4. P9 — content coding of the body (EXECUTED; raw_content byte-preservation across the hop)

The P9 bodies are real gzip. Byte identity across the hop is proven by **SHA-256 computed at the
client-send side and at the upstream-sink-received side** (not by length — equal length is not identity;
a negative unit test confirms equal-length-but-different-bytes FAILS the check). The SHA-256 is computed in
the TEST harness only; the production observer never hashes request bytes. All three P9 cases were
**byte-identical** across the hop, proving mitmproxy forwards the **coded** body unchanged (it does not
re-decode), so the integration requirement "pass `raw_content`, never decoded content" is satisfiable — and
the observer, reading `raw_content`, decodes it.

| Vector | Body (gzip) | sent len / sha256 | upstream len / sha256 | byte-identical | Observer (canonicalize) |
|---|---|---|---|---|---|
| P9-GZIP-2MEMBER | member(`alpha=1`)+member(`&beta=2`) | 54 / `eb3e1480…` | 54 / `eb3e1480…` | **TRUE** | OK / ACCEPT, content_codings=gzip, **decoded_body_bytes=14** (both members) |
| P9-GZIP-NUL-MEMBER | member, 8×NUL, member | 62 / `cbd6d067…` | 62 / `cbd6d067…` | **TRUE** | OK / ACCEPT, content_codings=gzip, **decoded_body_bytes=14** (member after NUL decoded) |
| P9-GZIP-TRAILING | member + non-NUL garbage | 43 / `839b7ef6…` | 43 / `839b7ef6…` | **TRUE** | OK / **REJECT R3** content-coding-decode-failure:gzip |

(Full SHA-256 values are in `wire_evidence_results.json` under each P9 result's `byte_identity`. The
canonicalizer and P9 policy were NOT altered to make these pass.)

**Superset behaviour confirmed on live wire traffic:** the observer decodes two members and the
member-after-NUL-padding (14 decoded bytes = both members), and rejects trailing non-NUL data as R3 —
exactly the P9 behaviour of `p9_gzip_padding_differential.json`, now demonstrated end-to-end through
mitmproxy. **P9 remains CONDITIONED (D63): the owner's choice between keeping this superset behaviour and
rejecting data-after-NUL as R3 is unmade.** The existing conditioned behaviour was retained; **no receive
limit, production pin or zstd window restriction was changed** by this lab.

---

## 5. Contract-level residual control (PARTS-LEVEL, explicitly NOT wire evidence)

`scripts/wire_evidence/harness.py::contract_level_residual()` runs the project-owned
`canonical_request.canonicalize()` directly on the parts that survive parsing. This complements the wire
evidence; it is the project's own control and is never conflated with what mitmproxy does.

| Case | Outcome |
|---|---|
| R1-TECL / DUPCL / BADCL / MULTITE / TE-EMPTY / TE-ON-1.0 / CHUNK-NONFINAL | REJECT **R1** (matching reason strings) |
| R2-TE-GZIP | REJECT **R2** |
| legal-OWS `Content-Length:  5 ` | **ACCEPT** (OWS stripped before the digit check) |
| obs-text value, HTAB value | **ACCEPT** (R4 counterparts) |
| CR/LF in a value | REJECT **R4** |

All pinned by `tests/test_wire_evidence_harness.py` (18 tests, incl. 2 guarded live tests, all pass under
`.venv-dataplane`).

## 6. Enforcement locus — which facts are lost during parsing

- **Before the addon (mitmproxy parser, third-party, tested profile):** TE/CL conflicts, duplicate/invalid
  CL, multi/empty TE, TE-on-1.0, non-final/repeated chunked, whitespace-before-colon, malformed chunks —
  all rejected at the wire here (§1). The exact wire framing (chunk sizes/extensions, CL padding, line
  terminators, bytes-after-body, which hop honoured which length) is **consumed by the parser and does not
  survive into `RequestParts`**.
- **Survives into `canonicalize()` as residual facts:** the TE header value, CL field count + value,
  `len(body)` — the parts-level R1/R2 checks of §5.
- **Lost / normalized:** obs-fold is unfolded (finding A), bare-LF is rewritten to CRLF (finding B),
  absolute-form authority is moved to `data.authority` so `data.path` alone cannot reconstruct it
  (P4 OUT_OF_SCOPE).
- **Empty body vs unavailable body stay distinct.** In this run the body-less requests (VALID-GET,
  VALID-HTAB, R1-BARE-LF, `OPTIONS *`) presented `raw_content == b""` (present-but-empty) → the observer
  canonicalized them to **OK / ACCEPT, decoded_body_bytes=0** (no `BODY_UNAVAILABLE` lines occurred; the
  status tally is OK×12 + OUT_OF_SCOPE×1). `BODY_UNAVAILABLE` is reserved for `raw_content is None`
  (missing/streamed), which the adapter never substitutes with `b""`; it simply did not arise under this
  buffered profile. The earlier draft of this report wrongly recorded VALID-HTAB as `BODY_UNAVAILABLE`;
  corrected here from the correlated `CANONICAL OBS` evidence.

Because these facts are gone by the hook, **the observer’s view is not R1 evidence** — the R1 evidence is
the client/socket outcome and the hop divergence in §1, §4.

## 7. Drift — the control must not silently survive a wrong configuration

Discriminating vector **R1-TECL**, run twice (`drift_vih_true.log`, `drift_vih_false.log`):

| `validate_inbound_headers` | Observed | Upstream delivered |
|---|---|---|
| **true** (tested profile) | PARSER_REJECT (400) | no |
| **false** | NORMALIZED_FORWARD (200) | **yes** |

`control_demonstrated = true`: the control changes this vector's wire outcome. With the control **off**,
the TE+CL smuggling vector is forwarded to the upstream. The runner does **not** require every vector to
flip; it reports a single discriminating vector, and would state "control not demonstrated" otherwise.

## 7b. Re-run against A's fixed observer — shutdown health (defect-6 check)

This corrected lab was re-run against A's repaired `canonical_observer` (repairs 1–3: single-deadline
write+drain+read, admit-before-materialize, `close()` closes the subprocess transport). Scanned from the
actual `mitmdump_lab.log` and recorded in `wire_evidence_results.json` under
`wire_evidence.shutdown_health`:

- `BaseSubprocessTransport.__del__` RuntimeError: **not present** (`del_runtimeerror = false`).
- "Event loop is closed": **not present** (`event_loop_is_closed = false`) ⇒ `del_runtimeerror_gone = true`.
- The pre-repair defect is **eliminated.** In THIS live lab's `mitmdump_lab.log` the benign asyncio
  "Close running child process" info line did not appear (`close_running_child_process = false`): this
  lab shutdown was clean. (Specific to the lab log — A's observer UNIT tests do emit two benign
  "Close running child process: kill" notices, without the destructor traceback; a clean lab log is not
  a claim that every test run is silent.)
- `other_tracebacks = 1` — the single traceback in the log is the **pre-existing obs-text 503**
  (`UnicodeEncodeError '\udce9'`, finding C), a surfaced V4 finding, **not** the shutdown defect and **not
  fixed here** by design.

Wrapper OK + canonical REJECT remain distinct from infrastructure failure: the status tally for the run is
`OK×12, OUT_OF_SCOPE×1` with `ACCEPT×10, REJECT×2` (R4 obs-fold, R3 P9-trailing) and `fail_closed×1`
(obs-text, outside the observer path) — i.e. canonical REJECTs are successful observations, not failures.

## 8. What can NOT be certified from this slice

1. **No global `VERIFIED` for R1.** This certifies the **tested lab profile only**. Runtime framing stays
   **UNAVAILABLE / UNVERIFIED globally** until a scoped, project-owned wire-level control is implemented
   and approved. (It can be established later; it simply is not, here.)
2. **mitmproxy's parser is third-party.** The project does not own or pin its framing behaviour; a
   mitmproxy upgrade could change any row in §1. The evidence is dated to 12.2.3 + `validate_inbound_headers=true`.
3. **P4 and P9 remain CONDITIONED (D63).** The lab informs the owner's pending choices; it does not make
   them. No future P4 guarantee and no P9 superset-vs-R3 decision is implied.
4. **A normalized forward is not enforcement** (findings A/B): several vectors the parser forwarded would
   be rejected by the contract; the gap between the two is the point, not a pass.
5. **HTTP/2 / HTTP/3 are unevidenced.** `http2=false`; the adapter marks non-1.0/1.1 versions
   `unsupported_http_version`. Their framing differs and is out of scope for this slice.
6. **Scope / token budget not exercised.** The lab observes `size=UNCHECKED` (no token budget `B`, PENDING
   §11.2); R8-budget and Fast-Path eligibility are deliberately not tested here.
7. **The upstream-observed header value may differ from the addon-observed value** (finding A): the lab
   records both hops but does not claim they are identical.

## 9. Files

| File | Role |
|---|---|
| `scripts/wire_evidence/harness.py` | raw-socket client, classifier stub, upstream sink, mitmdump lab profile, the exact-byte vector catalogue, outcome classifier, contract-level residual |
| `scripts/wire_evidence/lab_addon.py` | dedicated mitmproxy addon: builds the REAL gateway + observer pointed at the lab stub (config.yaml / data_plane.py untouched) |
| `scripts/wire_evidence/run_wire_evidence.py` | runs the lab over every vector + drift, parses the observer lines, writes the artifacts |
| `tests/test_wire_evidence_harness.py` | 18 tests (vector well-formedness, client/sink fidelity incl. duplicate headers, classification, contract residual, 2 guarded live tests) |
| `wire_evidence_results.json`, `run_metadata.json`, `mitmdump_lab.log`, `drift_vih_{true,false}.log` | executed outputs (this directory) |
