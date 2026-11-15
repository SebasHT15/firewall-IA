# V5 canonical-request/v1 — Wire evidence **v2 (CORRECTED run)**, issue #68 / D70

**Date:** 2026-10-22 · **Branch:** `feat/http1-framing-attestation` · **Status: PREPARATION / SHADOW,
OBSERVE-ONLY, DEFAULT-OFF.** Nothing here enforces or forwards in production. V4 via `/classify`
remains the only enforced authority; `GatewayEvidence.canonical()` stays `None`, `framing()` stays
`UNAVAILABLE`, the Fast Path stays `CONTINUE` (D4, D25, D34, D43, D69, **D70 APPROVED**).

This is a **corrected re-run** of the framing-observation wire lab against the gateway **after three
reproduced defects were fixed** (fixes are Track A's / the coordinator's, in `data_plane/*`; this track
only re-ran the lab and added version-boundary coverage). It lives in its own directory and does
**not** rewrite the prior v2 run.

Produced by `scripts/wire_evidence/run_wire_evidence_v2.py` (output dir passed as argv), reusing
`harness.py` + `lab_addon.py`; tested by `tests/test_wire_evidence_harness.py`. Artifacts in this dir:
`wire_evidence_v2_results.json`, `run_metadata.json`, `mitmdump_lab.log`, `drift_vih_true.log`,
`drift_vih_false.log`.

## Preservation / provenance (read this first)

- **`../../wire-evidence-v1/` is preserved byte-for-byte** (the D69 lab).
- **The prior `../` v2 run is preserved byte-for-byte** (its `run_metadata.json`,
  `wire_evidence_v2_results.json`, logs, README). This corrected run is a **separate directory**; no
  prior hash was rewritten.
- **`config.yaml` provenance:** the prior v2 recorded `config_yaml_sha256 = 23c1854…`; this corrected
  run records the **current** `config_yaml_sha256 = 94adc604…`. The only difference is a coordinator
  **comment-only** edit ("D70 PROPOSED" → "D70") made after the prior run; **no runtime setting or
  gateway behaviour changed**. `run_metadata.json → config_yaml_provenance` states this.
- **Source provenance:** `run_metadata.json → source_provenance.files` records the SHA-256 of the
  exact implementation files this run exercised (`data_plane/framing_evidence.py`,
  `canonical_observer.py`, `canonical_adapter.py`, `canonical_request.py`, `data_plane.py`, plus the
  lab harness/addon/runner), tying the evidence to the corrected gateway sources.

## What the three fixes changed, and what this run confirms

- **Defect A (version boundary) — DIRECTLY EXERCISED HERE.** `framing_evidence.evaluate` now requires
  the ORIGINAL received `http_version` and `PROFILE_MATCHED` requires it to be **exactly `HTTP/1.1`**.
  The new **VALID-HTTP10** vector (valid body-less `GET /ok HTTP/1.0`, origin-form, in adapter scope,
  canonical **OK + ACCEPT**) now logs **`FRAMING OBS UNATTESTABLE … HTTP_VERSION_NOT_11`** — previously
  it would have wrongly `PROFILE_MATCHED`. Its HTTP/1.1 counterpart **VALID-GET stays
  `PROFILE_MATCHED`** (positives unchanged). This is the **UNATTESTABLE/HTTP_VERSION_NOT_11** path, kept
  distinct from the **UNAVAILABLE/HTTP_VERSION_OUT_OF_SCOPE** path reserved for HTTP/2+ (which the
  adapter rejects as `unsupported_http_version`).
- **Defect B (mode validation = transport + address).** Confirmed the lab's
  `reverse:http://127.0.0.1:<dynamic>` profile **still matches the tested profile**
  (`is_tested_profile()` True this run). `https://`, HTTP/3 and non-loopback / DNS-lookalike
  (`127.0.0.1.evil.com`) reverse modes are no longer "tested" — pinned in the unit tests
  (`TestFramingEvaluateSemantics.test_*_mode_*`); the proxy transport was not reconfigured.
- **Defect C (reservation ownership).** No wire-visible behaviour change beyond robustness; the
  shutdown scan is clean (`del_runtimeerror_gone=true`, `other_tracebacks=1` = the pre-existing
  obs-text 503 only, see below).

## Lab profile (EXECUTED, corrected run)

```
raw-socket client ──▶ mitmdump 12.2.3 (reverse proxy, dynamic loopback port) ──ALLOW──▶ upstream SINK
   (exact bytes,       --set validate_inbound_headers=true  --set http2=false                (records method/
    no re-framing)     --set connection_strategy=lazy                                          target, dup
                       -s scripts/wire_evidence/lab_addon.py  (REAL FirewallGateway            headers, body
                         + REAL canonical-request/v1 observer + REAL framing observer,          length, SHA-256)
                          WIRE_LAB_FRAMING=1; config.yaml / data_plane.py untouched)  ──▶ /classify STUB (ALLOW)
```

**Exact command:**
`.venv-dataplane/bin/python -I scripts/wire_evidence/run_wire_evidence_v2.py \
reports/v5/canonical-request-v1/wire-evidence-v2/corrected` (exit 0; loopback only).

**Versions (from `run_metadata.json`):** mitmproxy **12.2.3** (pinned), Brotli **1.2.0**, zstandard
**0.25.0** (OBSERVED transitive, not ratified pins), CPython **3.12.15**. **EFFECTIVE options** read
back from the live instance: `validate_inbound_headers=True`, `http2=False`,
`connection_strategy='lazy'`, `stream_large_bodies=None`, `body_size_limit=None`,
`mode=['reverse:http://127.0.0.1:<dynamic>']` → marker `reverse_proxy:loopback_dynamic_port`. All seven
fields equal the tested profile; relevant-profile generation stayed `0` throughout. **D69 caps:**
`max_decoded_body = max received body = 1,048,576`; **token budget UNSET** (`size=UNCHECKED`, Fast Path
ineligible).

## Five dimensions, per vector (EXECUTED — 28 vectors)

Separate dimensions: **(1)** client outcome · **(2)** parser (reject / normalized-forward, how) ·
**(3)** reachability (addon / `/classify` / sink) · **(4)** CANONICAL OBS · **(5)** FRAMING OBS. A
parser rejection **before** the addon leaves 4–5 as `—` (socket evidence only, no in-hook record, never
fabricated). Attribution is order-based over the fully-flushed log (mitmdump block-buffers): correlation
report in the JSON = **15 flows, 14 addon-reaching, warm-up 1, 0 method mismatches, no count skew**.

| Vector | 1 Client | 2 Parser | 3 addon/clf/sink | 4 CANONICAL OBS | 5 FRAMING OBS |
|---|---|---|---|---|---|
| **VALID-GET (HTTP/1.1)** | NORMALIZED_FORWARD 200 | NORMALIZED_FORWARD | ✓/✓/✓ | OK/ACCEPT (origin) | **PROFILE_MATCHED** |
| **VALID-HTTP10 (HTTP/1.0)** | NORMALIZED_FORWARD 200 | NORMALIZED_FORWARD | ✓/✓/✓ | OK/ACCEPT (origin) | **UNATTESTABLE / HTTP_VERSION_NOT_11** |
| VALID-CL | NORMALIZED_FORWARD 200 | NORMALIZED_FORWARD | ✓/✓/✓ | OK/ACCEPT, body=5 | PROFILE_MATCHED |
| VALID-CL-OWS | NORMALIZED_FORWARD 200 | NORMALIZED_FORWARD | ✓/✓/✓ | OK/ACCEPT, body=5 | PROFILE_MATCHED |
| VALID-CHUNKED | NORMALIZED_FORWARD 200 | NORMALIZED_FORWARD | ✓/✓/✓ | OK/ACCEPT, TE=chunked, body=5 | PROFILE_MATCHED |
| VALID-OBSTEXT | **FAIL_CLOSED 503** | ACCEPTED_THEN_GATEWAY_FAILCLOSED | ✓/✗/✗ | — (never reached observer) | — |
| VALID-HTAB | NORMALIZED_FORWARD 200 | NORMALIZED_FORWARD | ✓/✓/✓ | OK/ACCEPT, body=0 | PROFILE_MATCHED |
| R1-TECL / DUPCL-EQ / DUPCL-NE / BADCL-HEX / BADCL-PLUS / MULTITE / TE-EMPTY / TE10 / CHUNK-NONFINAL / CHUNK-REPEAT / WS-COLON | PARSER_REJECT 400 | REJECTED_400 | ✗/✗/✗ | — | — |
| R1-BADCHUNK | **CONN_RESET** (no response) | CONN_RESET_NO_RESPONSE | ✗/✗/✗ | — | — |
| R1-OBSFOLD | NORMALIZED_FORWARD 200 | NORMALIZED_FORWARD | ✓/✓/✓ | **OK/REJECT/R4** | **UNATTESTABLE / CANONICAL_REJECT** |
| R1-BARE-LF | NORMALIZED_FORWARD 200 | NORMALIZED_FORWARD | ✓/✓/✓ | OK/ACCEPT (origin) | **PROFILE_MATCHED** (HTTP/1.1; wire unverified) |
| R2-TE-GZIP | PARSER_REJECT 400 | REJECTED_400 | ✗/✗/✗ | — | — |
| P4-ABSFORM | NORMALIZED_FORWARD 200 | NORMALIZED_FORWARD | ✓/✓/✓ | **OUT_OF_SCOPE** (absolute) | **UNAVAILABLE / TARGET_FORM_OUT_OF_SCOPE** |
| P4-ASTERISK | NORMALIZED_FORWARD 200 | NORMALIZED_FORWARD | ✓/✓/✓ | OK/ACCEPT (asterisk) | PROFILE_MATCHED |
| P4-OTHER | PARSER_REJECT 400 | REJECTED_400 | ✗/✗/✗ | — | — |
| P9-GZIP-2MEMBER / NUL-MEMBER | NORMALIZED_FORWARD 200 | NORMALIZED_FORWARD | ✓/✓/✓ | OK/ACCEPT, gzip, body=14 | PROFILE_MATCHED |
| P9-GZIP-TRAILING | NORMALIZED_FORWARD 200 | NORMALIZED_FORWARD | ✓/✓/✓ | **OK/REJECT/R3** | **UNATTESTABLE / CANONICAL_REJECT** |

**Tallies (from the saved JSON).** client: `NORMALIZED_FORWARD×13, PARSER_REJECT×13, CONN_RESET×1,
FAIL_CLOSED×1`. canonical: `OK/ACCEPT×10, OK/REJECT/R4×1, OK/REJECT/R3×1, OUT_OF_SCOPE×1, none×15`.
framing: `PROFILE_MATCHED×9, UNATTESTABLE/CANONICAL_REJECT×2, **UNATTESTABLE/HTTP_VERSION_NOT_11×1**,
UNAVAILABLE/TARGET_FORM_OUT_OF_SCOPE×1, none×15`. Observer status `OK×13, OUT_OF_SCOPE×1`; decisions
`ALLOW×14, fail_closed×1, received×15` (15 = 14 addon-reaching + 1 warm-up).

### HTTP/1.0 vs HTTP/1.1 — the correction, stated plainly

| Vector | version | canonical | framing (CORRECTED) | framing (prior v2 would have been) |
|---|---|---|---|---|
| VALID-GET | HTTP/1.1 | OK/ACCEPT | **PROFILE_MATCHED** | PROFILE_MATCHED (unchanged) |
| VALID-HTTP10 | HTTP/1.0 | OK/ACCEPT | **UNATTESTABLE / HTTP_VERSION_NOT_11** | *(vector did not exist; the pre-fix evaluator had no version gate and would have accepted HTTP/1.0)* |

### Other honesty truths (unchanged, re-verified)

1. **Parser rejection before the addon = socket evidence only, NO in-hook record.** All 13
   parser-rejected / reset vectors: `addon=false`, `/classify` not called, no CANONICAL/FRAMING line —
   none fabricated.
2. **obs-fold → `UNATTESTABLE` / `CANONICAL_REJECT`**, never relabelled as residual-framing success.
3. **bare-LF → `PROFILE_MATCHED`** (it is HTTP/1.1; bare-LF is a wire fact canonicalize never sees), yet
   wire verification is unavailable — `PROFILE_MATCHED` does not attest the wire.
4. **absolute-form → framing `UNAVAILABLE` (out-of-scope)**, not a fabricated positive; in-scope
   origin/asterisk HTTP/1.1 → `PROFILE_MATCHED`.
5. **VALID-OBSTEXT still 503** via the pre-existing V4 `render_request` `UnicodeEncodeError '\udce9'` —
   preserved + disclosed, **not fixed here**; it never reached the observer (dimensions 4–5 `—`). This
   is the single `other_tracebacks=1` in the shutdown scan, not a shutdown defect.

**Log-file honesty (unchanged).** The closed-vocabulary / no-request-byte guarantee covers only the
observer's `CANONICAL OBS` / `FRAMING OBS` lines. The surrounding `mitmdump_lab.log` is a separate,
pre-existing gateway stream (`received …`, `ALLOW`, `BLOCK (fail-closed)`, the obs-text traceback) and
is not covered by it. All paths are synthetic (`/ok`, `/x`, `*`, `http://sink.test/...`).

## Drift — `validate_inbound_headers` true vs false (both observers on)

Discriminating vector **R1-TECL**, EFFECTIVE options saved per run (`drift_vih_true.log`,
`drift_vih_false.log`, and in the JSON).

| `validate_inbound_headers` (EFFECTIVE) | Client / parser | addon | CANONICAL OBS | FRAMING OBS |
|---|---|---|---|---|
| **true** (tested) | PARSER_REJECT 400, not delivered | no | — (socket only) | — (no in-hook record) |
| **false** | NORMALIZED_FORWARD 200, delivered | yes | OK / **REJECT / R1** | **UNATTESTABLE** (VALIDATE_INBOUND_HEADERS_OFF, PROFILE_NOT_TESTED, CANONICAL_REJECT) |

`wire_control_demonstrated=true` **and** `framing_control_demonstrated=true`: with the control off the
smuggling vector is forwarded, canonicalize REJECTs it R1 and framing is **UNATTESTABLE** — never
`PROFILE_MATCHED` once the profile is no longer the tested one; with it on the vector never reaches the
addon.

**Runtime generation drift:** the gateway's `configure()` hook establishes the generation **baseline**
for real in this lab (`gen=0` on every FRAMING OBS line), and the two vih drift runs are **real**
separate-process runs under genuinely different EFFECTIVE options. The **capture≠reply interleaved
generation drift** (`gen_at_capture != gen_at_reply → UNATTESTABLE/GENERATION_DRIFT`) and a runtime
`configure()` generation **bump** (A→B→A = two bumps) remain **LABELED UNIT SIMULATIONS** in
`tests/test_wire_evidence_harness.py` — the live lab cannot change a mitmproxy option in the sub-ms
window between a single request's capture and its worker reply, so the interleave is **not** claimed as
a live result.

## Tests

`.venv-dataplane/bin/python -m unittest tests.test_wire_evidence_harness` — see the parent report run
log for exact counts (this corrected pass adds the version-boundary and mode-boundary unit tests:
HTTP/1.0→UNATTESTABLE/HTTP_VERSION_NOT_11, HTTP/1.1 positive unchanged, HTTP/2→UNAVAILABLE/
HTTP_VERSION_OUT_OF_SCOPE, lab reverse+http+loopback stays tested, https/non-loopback not tested; all
pre-existing `evaluate` unit tests updated to pass the now-required `http_version`). The 3 guarded live
tests skip (not fail) when mitmdump cannot start — a socket skip is a disclosed missing check, not a
pass.

## What can NOT be certified (unchanged from v1/v2)

No global `VERIFIED` for R1; mitmproxy's parser is third-party (12.2.3 + vih=true); P4/P9 remain
CONDITIONED (D63); a normalized forward is not enforcement; HTTP/2/3 unevidenced; scope/token budget not
exercised (`size=UNCHECKED`). `PROFILE_MATCHED` means only "profile + observed snapshot met the defined
conditions (now including exactly HTTP/1.1)" — never VERIFIED / safe-to-forward / Fast-Path eligible /
wire-equivalent.

## Files (this corrected run)

| File | Role |
|---|---|
| `wire_evidence_v2_results.json` | per-vector five dimensions, tallies, correlation report, drift, shutdown health |
| `run_metadata.json` | EFFECTIVE runtime profile, versions, `config_yaml_sha256=94adc604…` + provenance, `source_provenance` SHAs |
| `mitmdump_lab.log`, `drift_vih_{true,false}.log` | raw proxy logs (pre-existing gateway stream; not closed-vocabulary) |
| `../../wire-evidence-v1/*`, `../*` | PRESERVED byte-for-byte (not written by this run) |
| `scripts/wire_evidence/run_wire_evidence_v2.py` (+ `harness.py`, `lab_addon.py`) | the runner (now takes an output dir), harness (now has the HTTP/1.0 vector + framing flag), addon |
| `tests/test_wire_evidence_harness.py` | tests incl. the new version/mode-boundary coverage + guarded live tests |
