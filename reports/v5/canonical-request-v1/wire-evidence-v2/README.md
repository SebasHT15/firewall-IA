# V5 canonical-request/v1 — Wire evidence **v2** (framing observation slice, issue #68)

**Date:** 2026-10-21 · **Branch:** `feat/http1-framing-attestation` · **Status: PREPARATION / SHADOW,
OBSERVE-ONLY.** Nothing here enforces or forwards in production. This report records what an **actual
local raw-socket lab** observed with BOTH the shadow canonical observer AND the new shadow **framing**
observer enabled. It does **not** ratify a runtime control. V4 via `/classify` remains the only
enforced authority; `GatewayEvidence.canonical()` stays `None`, `framing()` stays `UNAVAILABLE`, and
the Fast Path stays `CONTINUE` (D4, D25, D34, D43, D69; D70 PROPOSED).

Produced by `scripts/wire_evidence/run_wire_evidence_v2.py` (reusing `harness.py` + `lab_addon.py`),
tested by `tests/test_wire_evidence_harness.py`. Machine-readable results:
`wire_evidence_v2_results.json`; run environment: `run_metadata.json`; raw proxy logs:
`mitmdump_lab.log`, `drift_vih_true.log`, `drift_vih_false.log`.

## Relationship to v1 (PRESERVED UNCHANGED)

This **extends** `../wire-evidence-v1/` — it does not replace it. The v1 directory
(`wire_evidence_results.json`, `run_metadata.json`, `mitmdump_lab.log`,
`drift_vih_{true,false}.log`, `README.md`) is kept byte-for-byte as the historical D69 lab and the v1
runner (`run_wire_evidence.py`) is not modified. v2 adds, on top of v1:

- the shadow **framing** observer (Track A's `data_plane/framing_evidence.py`), wired through the
  integrated gateway's new `configure()` hook / `capture_and_schedule_observation` /
  `complete_canonical_observation` path (coordinator's `data_plane.py`), enabled in the lab via
  `lab_addon.py` (`WIRE_LAB_FRAMING=1`) **without touching `config.yaml` or `data_plane.py`**;
- **five separate per-vector dimensions** (below) instead of v1's single wire-outcome row;
- the **framing outcome under `validate_inbound_headers` drift**, not just the wire outcome;
- a new profile marker: the reverse-proxy destination is the closed token
  `reverse_proxy:loopback_dynamic_port` (the dynamic port is never matched literally).

**Log-file honesty (unchanged from v1).** The closed-vocabulary / no-request-byte privacy guarantee is
about the observer's own `CANONICAL OBS` and `FRAMING OBS` lines only. The surrounding
`mitmdump_lab.log` is a **separate, pre-existing gateway log stream** (`received METHOD host:port/path
…`, `ALLOW`, `BLOCK (fail-closed)`, and the obs-text exception traceback). Those lines are **not**
covered by the observer's closed-vocabulary guarantee and are not described here as closed-vocabulary.
All lab paths are synthetic (`/ok`, `/x`, `*`, `http://sink.test/...`); no real request data is used.

## What `PROFILE_MATCHED` means — and does NOT mean

`PROFILE_MATCHED` means **only**: the sampled mitmproxy runtime profile is the documented tested one,
the target form is HTTP/1.1 origin/asterisk, the relevant-profile generation was unchanged between
capture and reply, and the canonical observation was `OK` + `ACCEPT` for that one snapshot. It is
**never** a claim of VERIFIED, safe-to-forward, Fast-Path eligibility, or wire-equivalence to what the
upstream parses. There is no project-owned wire-level framing control in this slice; runtime framing
stays **UNAVAILABLE / UNVERIFIED globally**. In particular (both observed live below): a **bare-LF**
request MAY reach `PROFILE_MATCHED` (bare-LF is a wire fact `canonical_request` never sees, so it
ACCEPTs the normalized parts) yet wire verification is unavailable; an **obs-fold** request that
canonicalize rejects (`R4`) surfaces as `UNATTESTABLE` / `CANONICAL_REJECT`, **never** relabelled as
residual-framing success.

## Lab profile (executed)

```
raw-socket client ──▶ mitmdump 12.2.3 (reverse proxy, dynamic loopback port) ──ALLOW──▶ upstream SINK
   (stdlib socket,      --set validate_inbound_headers=true                               (raw TCP; records
    exact bytes,        --set http2=false                                                  method/target,
    no re-framing)      --set connection_strategy=lazy                                      dup headers,
                        -s scripts/wire_evidence/lab_addon.py                               body length,
                          REAL data_plane.FirewallGateway                                   body SHA-256)
                          + REAL canonical-request/v1 observer (shadow)        ──▶ /classify STUB
                          + REAL framing observer (WIRE_LAB_FRAMING=1)             (deterministic ALLOW,
                          config.yaml / data_plane.py untouched                     counts hits)
```

**Versions (from `run_metadata.json`):** mitmproxy **12.2.3** (pinned in `requirements-data-plane.txt`),
Brotli **1.2.0**, zstandard **0.25.0** (OBSERVED transitive deps, not ratified direct pins), CPython
**3.12.15**. `config.yaml` SHA-256 at the run is recorded in `run_metadata.json`; the wire harness did
**not** modify `config.yaml` or `data_plane/data_plane.py`.

**Requested vs EFFECTIVE options (EFFECTIVE read back from the running lab via `lab_addon`'s
`EffectiveOptions`, recorded in `run_metadata.json` — NOT config-file intent):**
`validate_inbound_headers=True`, `http2=False`, `connection_strategy='lazy'`,
`stream_large_bodies=None` (mitmproxy default — never stream, so `raw_content` is buffered at the
hook), `body_size_limit=None`, `mode=['reverse:http://127.0.0.1:<dynamic>']`. The framing observer
samples these EFFECTIVE values; all seven fields equal the documented tested profile, so
`FramingProfile.is_tested_profile()` is True in this run and the relevant-profile generation stays `0`
throughout (no option change). **D69 lab caps:** `max_decoded_body = max received body = 1,048,576`;
**token budget UNSET** (canonical `size=UNCHECKED`, Fast Path ineligible).

## Five dimensions, per vector (EXECUTED)

For every vector we record, as **separate** dimensions: **(1)** the exact **client** outcome at the
socket; **(2)** what the **parser** did (rejected/normalized-forwarded, and how); **(3)**
**reachability** (addon / `/classify` / upstream sink); **(4)** the **CANONICAL OBS** line; **(5)** the
**FRAMING OBS** line. A parser rejection **before** the addon leaves `—` in dimensions 4–5: it has
socket evidence only and **no in-hook/project record**, which we never fabricate. Attribution is
order-based over the fully-flushed log (mitmdump block-buffers its log stream; the one warm-up flow is
skipped and the remaining 13 addon-reaching flows map 1:1 in send order — correlation report in the
JSON: 14 flows, 13 addon-reaching, 0 method mismatches, no count skew).

| Vector | 1 Client | 2 Parser | 3 addon / clf / sink | 4 CANONICAL OBS | 5 FRAMING OBS |
|---|---|---|---|---|---|
| VALID-GET | NORMALIZED_FORWARD (200) | NORMALIZED_FORWARD | ✓ / ✓ / ✓ | OK / ACCEPT (origin) | **PROFILE_MATCHED** |
| VALID-CL | NORMALIZED_FORWARD (200) | NORMALIZED_FORWARD | ✓ / ✓ / ✓ | OK / ACCEPT, body=5 | **PROFILE_MATCHED** |
| VALID-CL-OWS | NORMALIZED_FORWARD (200) | NORMALIZED_FORWARD | ✓ / ✓ / ✓ | OK / ACCEPT, body=5 | **PROFILE_MATCHED** |
| VALID-CHUNKED | NORMALIZED_FORWARD (200) | NORMALIZED_FORWARD | ✓ / ✓ / ✓ | OK / ACCEPT, TE=chunked, body=5 | **PROFILE_MATCHED** |
| VALID-OBSTEXT | **FAIL_CLOSED (503)** | ACCEPTED_THEN_GATEWAY_FAILCLOSED | ✓ / ✗ / ✗ | — (never reached observer) | — (gateway fail-closed first) |
| VALID-HTAB | NORMALIZED_FORWARD (200) | NORMALIZED_FORWARD | ✓ / ✓ / ✓ | OK / ACCEPT, body=0 | **PROFILE_MATCHED** |
| R1-TECL | PARSER_REJECT (400) | REJECTED_400 | ✗ / ✗ / ✗ | — | — |
| R1-DUPCL-EQ | PARSER_REJECT (400) | REJECTED_400 | ✗ / ✗ / ✗ | — | — |
| R1-DUPCL-NE | PARSER_REJECT (400) | REJECTED_400 | ✗ / ✗ / ✗ | — | — |
| R1-BADCL-HEX | PARSER_REJECT (400) | REJECTED_400 | ✗ / ✗ / ✗ | — | — |
| R1-BADCL-PLUS | PARSER_REJECT (400) | REJECTED_400 | ✗ / ✗ / ✗ | — | — |
| R1-MULTITE | PARSER_REJECT (400) | REJECTED_400 | ✗ / ✗ / ✗ | — | — |
| R1-TE-EMPTY | PARSER_REJECT (400) | REJECTED_400 | ✗ / ✗ / ✗ | — | — |
| R1-TE10 | PARSER_REJECT (400) | REJECTED_400 | ✗ / ✗ / ✗ | — | — |
| R1-CHUNK-NONFINAL | PARSER_REJECT (400) | REJECTED_400 | ✗ / ✗ / ✗ | — | — |
| R1-CHUNK-REPEAT | PARSER_REJECT (400) | REJECTED_400 | ✗ / ✗ / ✗ | — | — |
| R1-WS-COLON | PARSER_REJECT (400) | REJECTED_400 | ✗ / ✗ / ✗ | — | — |
| R1-BADCHUNK | **CONN_RESET** (no response) | CONN_RESET_NO_RESPONSE | ✗ / ✗ / ✗ | — | — |
| R1-OBSFOLD | NORMALIZED_FORWARD (200) | NORMALIZED_FORWARD | ✓ / ✓ / ✓ | **OK / REJECT / R4** (field-value-cr-lf-nul) | **UNATTESTABLE** (CANONICAL_REJECT) |
| R1-BARE-LF | NORMALIZED_FORWARD (200) | NORMALIZED_FORWARD | ✓ / ✓ / ✓ | OK / ACCEPT (origin) | **PROFILE_MATCHED** (wire unverified) |
| R2-TE-GZIP | PARSER_REJECT (400) | REJECTED_400 | ✗ / ✗ / ✗ | — | — |
| P4-ABSFORM | NORMALIZED_FORWARD (200) | NORMALIZED_FORWARD | ✓ / ✓ / ✓ | **OUT_OF_SCOPE** (absolute) | **UNAVAILABLE** (TARGET_FORM_OUT_OF_SCOPE) |
| P4-ASTERISK | NORMALIZED_FORWARD (200) | NORMALIZED_FORWARD | ✓ / ✓ / ✓ | OK / ACCEPT (asterisk) | **PROFILE_MATCHED** |
| P4-OTHER | PARSER_REJECT (400) | REJECTED_400 | ✗ / ✗ / ✗ | — | — |
| P9-GZIP-2MEMBER | NORMALIZED_FORWARD (200) | NORMALIZED_FORWARD | ✓ / ✓ / ✓ | OK / ACCEPT, gzip, body=14 | **PROFILE_MATCHED** |
| P9-GZIP-NUL-MEMBER | NORMALIZED_FORWARD (200) | NORMALIZED_FORWARD | ✓ / ✓ / ✓ | OK / ACCEPT, gzip, body=14 | **PROFILE_MATCHED** |
| P9-GZIP-TRAILING | NORMALIZED_FORWARD (200) | NORMALIZED_FORWARD | ✓ / ✓ / ✓ | **OK / REJECT / R3** (content-coding-decode-failure:gzip) | **UNATTESTABLE** (CANONICAL_REJECT) |

**Tallies (from the saved JSON):** client outcome `NORMALIZED_FORWARD×12, PARSER_REJECT×13,
CONN_RESET×1, FAIL_CLOSED×1`; canonical `OK/ACCEPT×9, OK/REJECT/R4×1, OK/REJECT/R3×1, OUT_OF_SCOPE×1,
none×15`; framing `PROFILE_MATCHED×9, UNATTESTABLE/CANONICAL_REJECT×2,
UNAVAILABLE/TARGET_FORM_OUT_OF_SCOPE×1, none×15`. Observer status tally `OK×12, OUT_OF_SCOPE×1`;
decisions `ALLOW×13, fail_closed×1, received×14` (14 = 13 addon-reaching vectors + 1 warm-up). **This is
NOT "all 14 R1 vectors were HTTP rejects":** of the 14 R1 vectors, 11 were 400, 1 was a connection
reset, and 2 (obs-fold, bare-LF) were normalized and forwarded.

### Expected truths verified and stated plainly

1. **A parser rejection before the addon has socket evidence only and NO in-hook record.** All 13
   parser-rejected / reset vectors show `addon_reached=false`, `classifier_called=false`,
   `upstream=false`, and **no** CANONICAL/FRAMING line was produced or fabricated for them.
2. **obs-fold's canonical `R4` surfaces as `UNATTESTABLE` / `CANONICAL_REJECT`,** never relabelled as
   residual-framing success (R1-OBSFOLD row; correlated same-tag in `mitmdump_lab.log`).
3. **bare-LF MAY reach `PROFILE_MATCHED`** under the limited semantics yet is normalized traffic with
   **wire verification unavailable** (R1-BARE-LF row).
4. **Absolute-form yields a framing `UNAVAILABLE` (out-of-scope) line, not a fabricated positive**
   (P4-ABSFORM: canonical `OUT_OF_SCOPE/absolute` → framing `UNAVAILABLE TARGET_FORM_OUT_OF_SCOPE`).
   In-scope origin- and asterisk-form targets reach `PROFILE_MATCHED`.
5. **VALID-OBSTEXT still fails closed (503)** via the pre-existing V4 `render_request`
   `UnicodeEncodeError '\udce9'` — the same real train/serve gap v1 found. It is **preserved and
   disclosed, not fixed here**; the request never reached the observer, so there is no CANONICAL/FRAMING
   line (dimensions 4–5 are `—`). This is the single traceback counted by the shutdown scan
   (`other_tracebacks=1`), not a shutdown defect.

## Drift — the control must not silently survive a wrong configuration

Discriminating vector **R1-TECL**, run twice with BOTH observers ON (`drift_vih_true.log`,
`drift_vih_false.log`); the EFFECTIVE options are saved in each run and in
`wire_evidence_v2_results.json → drift.runs[*].effective_options`.

| `validate_inbound_headers` (EFFECTIVE) | Client / parser | addon reached | CANONICAL OBS | FRAMING OBS |
|---|---|---|---|---|
| **true** (tested profile) | PARSER_REJECT (400), not delivered | **no** | — (socket evidence only) | — (no in-hook record; not fabricated) |
| **false** | NORMALIZED_FORWARD (200), delivered | **yes** | OK / **REJECT / R1** | **UNATTESTABLE** (VALIDATE_INBOUND_HEADERS_OFF, PROFILE_NOT_TESTED, CANONICAL_REJECT) |

`wire_control_demonstrated=true` **and** `framing_control_demonstrated=true`: with the control **off**
the TE+CL smuggling vector is forwarded, the addon runs, canonicalize REJECTs it `R1`, and framing is
**UNATTESTABLE** — it can **never** be `PROFILE_MATCHED` once the profile is no longer the tested one.
With the control **on** the vector never reaches the addon, so there is no framing line at all. The
runner reports a single discriminating vector and would say "not demonstrated" otherwise; it does not
require every vector to flip.

### Runtime generation-drift path: what was exercised for real vs simulated

- **Real, in this lab:** the integrated gateway's mitmproxy `configure()` hook runs at startup and
  establishes the relevant-profile generation **baseline** (`gen=0`), which every FRAMING OBS line in
  this run carries (`gen=0`). The two drift runs are **real** separate-process runs under genuinely
  different EFFECTIVE `validate_inbound_headers`, read back from each live instance.
- **Unit simulation (labelled as such):** the **capture≠reply generation DRIFT** conclusion
  (`gen_at_capture != gen_at_reply → UNATTESTABLE/GENERATION_DRIFT`) and a runtime `configure()`
  **generation BUMP** (including A→B→A counted as two bumps) are pinned in
  `tests/test_wire_evidence_harness.py` — the first as a pure `framing_evidence.evaluate` simulation,
  the second by driving the **real** `FirewallGateway.configure()` hook with a changing options object.
  The live lab cannot deterministically change a mitmproxy option in the sub-millisecond window between
  a single request's capture and its worker reply, so the interleaved drift itself is **not** claimed as
  a live-lab result. These unit simulations are kept clearly separate from the real-lab runs above.

## Tests

`tests/test_wire_evidence_harness.py` under `.venv-dataplane`
(`.venv-dataplane/bin/python -m unittest tests.test_wire_evidence_harness`): **35 tests — all pass, 0
skipped, 0 failed** in this environment (`Ran 35 tests … OK`). That is v1's 21 (vector catalogue,
client/sink fidelity incl. duplicate headers, classification, byte identity, contract-level residual,
2 guarded live tests) plus v2's **14** additions: LabProfile framing plumbing (1); v2 log parsing +
order-based attribution (3); `framing_evidence.evaluate` semantics (7: PROFILE_MATCHED,
obs-fold→UNATTESTABLE, bare-LF→PROFILE_MATCHED, absolute-form→UNAVAILABLE, no-observer→UNAVAILABLE,
vih-off→UNATTESTABLE, generation-drift UNIT SIMULATION); the real `configure()`→generation bump UNIT
SIMULATION + framing-off no-op (2); and 1 guarded live framing test. The 3 guarded live tests
(`TestLiveLabProfile`×2, `TestLiveFramingObserver`×1) actually ran green here (mitmdump present); they
**skip** (not fail) when mitmdump cannot start, so a socket-restricted sandbox is a disclosed missing
test, not a pass.

## What can NOT be certified from this slice (unchanged from v1)

1. **No global `VERIFIED` for R1.** This certifies the tested lab profile only; runtime framing stays
   UNAVAILABLE/UNVERIFIED globally until a scoped, project-owned wire-level control is implemented and
   approved. `PROFILE_MATCHED` is not that control.
2. **mitmproxy's parser is third-party** (12.2.3 + `validate_inbound_headers=true`); an upgrade could
   change any wire row.
3. **P4 and P9 remain CONDITIONED (D63).** The lab informs the owner's pending choices; it does not make
   them. No receive limit, production pin, zstd window, token budget `B` or P9 superset-vs-R3 decision
   was changed here.
4. **A normalized forward is not enforcement** (obs-fold / bare-LF): the gap between what the parser
   forwarded and what the contract would reject is the point.
5. **HTTP/2 / HTTP/3 are unevidenced** (`http2=false`).
6. **Scope / token budget not exercised:** `size=UNCHECKED`; Fast-Path eligibility is not tested.

## Files

| File | Role |
|---|---|
| `scripts/wire_evidence/run_wire_evidence_v2.py` | the v2 runner (framing on, five dimensions, order-based log attribution, drift with framing) |
| `scripts/wire_evidence/harness.py` | shared raw-socket client / classifier stub / upstream sink / lab profile / vector catalogue (extended with the `framing` flag) |
| `scripts/wire_evidence/lab_addon.py` | the real gateway + canonical + framing observer, pointed at the lab stub (extended to pass `framing_observer`) |
| `tests/test_wire_evidence_harness.py` | 36 tests incl. the v2 framing additions + guarded live tests |
| `wire_evidence_v2_results.json`, `run_metadata.json`, `mitmdump_lab.log`, `drift_vih_{true,false}.log` | executed outputs (this directory) |
