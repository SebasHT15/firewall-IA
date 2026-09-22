# External Test v1 — protocol

> **Status update — 2026-09-21, first-stage close: FROZEN and EXECUTED.**
> The protocol below is kept exactly as pre-registered; where it says "DRAFT" or "not yet
> executed" it describes the state when it was written.
>
> - **Frozen** at commit `36df2ee`: 400 cases (200 ALLOW / 200 BLOCK, 10 cells × 40),
>   integrity hash `ccac5f55eee27f94a79295f0022edf6eac792abe828ed1a1fe5f43ac85c5e52b`,
>   seed `external-v1-freeze-v1`, V4 exposure before freeze zero —
>   [`../datasets/external_v1/manifest.json`](../datasets/external_v1/manifest.json).
> - **Executed** as `external-v1-run-001` with the runner at commit `9656df9`: 1,200 gateway
>   requests (400 × 3) and 300 direct `/classify` calls (100 × 3), 0 execution errors, 0
>   nondeterminism — [`../reports/external/external-v1-run-001/`](../reports/external/external-v1-run-001/).
>   Headline results: [`../README.md`](../README.md#5-external-test-v1).
> - **Disclosed deviation from §11 — methodology limitation of External Test v1.**
>   The preregistered proxy-to-`/classify` byte-equivalence check was not executed during
>   `external-v1-run-001` because the data-plane runtime did not contain `strace`.
>   Therefore, External Test v1 does not contain direct byte-for-byte evidence that the
>   classifier input for all 400 gateway cases was identical to the frozen `request_text`.
>
>   The existing byte-fidelity checks from the capture/replay infrastructure and prior HTTP
>   diagnostics provide supporting evidence, and the predeclared 100-case direct-vs-gateway
>   check showed 100/100 decision agreement. However, decision agreement is not itself
>   proof of byte equivalence and must not be presented as such.
>
>   This deviation does not change any recorded L1/L2/L3 result or frozen artifact. It is a
>   methodology limitation of External Test v1 and should be corrected prospectively in
>   External Test v2.
>
>   What the supporting evidence is, precisely — none of it is a capture of the data
>   plane's `/classify` input for these 400 cases:
>   - *Capture/replay infrastructure (Phase B, §4.2):* replaying captured requests through
>     the capture proxy, which uses the same `render_request()` as the data plane,
>     reproduced the captured text byte for byte (8/8 `curl`, 12/12 Chromium; evidence
>     committed at [`../reports/external/external-v1-phase-b-fidelity/`](../reports/external/external-v1-phase-b-fidelity/)); and the
>     offline round-trip test `render → wire → mitmproxy parse → render_request()` is the
>     identity (`tests/test_external_capture.py`).
>   - *Prior HTTP diagnostic:* in `real-http-fp-v1`, 78/78 proxy-to-`/classify` texts
>     captured with `strace` were byte-identical to the registered texts — different
>     requests, an earlier session.
>   - *Run records:* in `results.jsonl`, `sent_sha256` is the hash of the frozen text the
>     replay client sent, computed client-side, so `text_matches_registered: true` records
>     only that the client sent the frozen text. It is **not** evidence of what the
>     classifier received.
> - **Disclosed deviation from §7 — CSIC-ancestry check not executed.** Check 7 of the
>   pre-registered gate (payload substring vs `csic_database.csv`; a non-blocking **WARN**
>   requiring a logged manual ruling) was not implemented in the Phase D gate and was not
>   executed: `datasets/external_v1/gate/gate_summary.json` lists the sources checked (V4
>   train and eval, `real-http-fp-v1`, the smoke fixtures, the other candidates) and CSIC is
>   not among them. The exact and canonical collision checks did cover the CSIC-derived rows
>   that are part of V4 train + eval; what was not run is the substring screen against the
>   raw CSIC file. As a WARN-level check it could not have blocked the freeze, and its
>   absence does not change any frozen case or any recorded L1/L2/L3 result. It is **not**
>   reconstructed after exposure, which would apply the check with choices made after the
>   results were known. **External Test v2 must implement and run it before freeze** (D40).
> - **External Test v2 must restore the check (D40):** the bytes the data plane sends to
>   `/classify` are captured for every gateway execution, hashed and compared with the
>   frozen `request_text`, with the capture tooling verified present and working in the
>   execution environment before any case is sent.
> - **Secondary breakdowns (§4.3, §10)** were produced at stage close from the frozen case
>   metadata and the committed run records, without changing any case or result:
>   `client_profile`, `host_type`, `method`, `body_type` —
>   [`../reports/external/external-v1-secondary-breakdowns/`](../reports/external/external-v1-secondary-breakdowns/).
>   `route_family` (§4.3) is pre-registered, not produced: it is not in the frozen metadata
>   and was never assigned to the browser-captured cases, so producing it would require a
>   post-exposure choice.
> - Decisions recording this methodology: D38–D42 in [`../DECISIONS.md`](../DECISIONS.md).
>   Any change to a frozen case now requires External v2 (§9).

**Status: DRAFT protocol, approved scope, NOT yet executed.**
Written 2026-09-21, before any External Test v1 case exists and before V4 has seen any
proposed case. This document is frozen *before* the data, in the same order D19 froze the
V4 evaluation methodology before the V4 training run, so metric definitions cannot be
chosen after seeing results.

> **V4 exposure status at the time of writing: ZERO.** No proposed External v1 case has
> been sent to `/classify`, through the gateway or otherwise.

---

## 1. Purpose and research questions

External Test v1 is a **formal independent external evaluation** of the existing V4 model
and of the complete gateway. It is not a diagnostic. It answers:

| # | Question | Answered by |
|---|---|---|
| **RQ1** | How well does V4 classify new traffic independent of its fine-tuning data? | L1 headline |
| **RQ2** | How much does performance change from internal evaluation to external traffic? | L1 generalization gap vs `reports/v4_clean_eval.json` |
| **RQ3** | Does performance change across external traffic slices / distribution shifts? | L1 per-slice, per-category |
| **RQ4** | How robust is V4 to legitimate and malicious request structures absent from the fine-tuning corpus? | L1 `unseen-structure` slice |
| **RQ5** | Does the gateway correctly enforce V4's decisions end to end? | L2, L3 |

**RQ4 is a robustness question, not an OOD-detection question.** V4 has no calibrated
confidence or OOD score, and none is introduced here. No result in this evaluation may be
described as OOD *detection*. "Unseen structure" means only: feature values with zero or
near-zero support in the V4 fine-tuning corpus, counted directly from
`datasets/v4_clean/`.

---

## 2. Three measurement levels — never merged

For each case we observe **G** = ground truth (assigned before exposure), **D** = V4's
decision, **E** = the gateway's observed behaviour (HTTP status + destination receipt).

| Level | Compares | Question | Error means |
|---|---|---|---|
| **L1 — model** | G vs D | did the model judge correctly? | FP, FN, invalid output |
| **L2 — enforcement** | D vs E | did the gateway faithfully execute the decision? | enforcement fault |
| **L3 — end-to-end** | G vs delivery | what actually happened to the traffic? | attack delivered, benign broken |

**L2's contract is fixed by D34 and is independent of whether D was correct:**

```
D = ALLOW                                   → 200 + destination receipt PRESENT
D = BLOCK                                   → 403 + destination receipt ABSENT
D = invalid | 5xx | timeout | unreachable   → 503 + destination receipt ABSENT
```

L3 = L1 ∘ L2. If L2 is perfect, L3 equals L1, and that equality is itself a reportable
result. Every L3 failure is attributed to **model error** or **gateway-enforcement error**.
An attack V4 misses and the gateway then forwards correctly is an L1 error and an L3
security failure but **not** an L2 error. These three must never be collapsed into one
number.

---

## 3. Metrics

### L1 — model / classification

Computed by importing the frozen D19 scoring code (`scripts/evaluation/test_model.py`:
`score_binary`, `percentile`), never a reimplementation. **BLOCK is the positive class.**

TP · TN · FP · FN · invalid outputs (count and rate) · Accuracy · Precision(BLOCK) ·
Recall / ADR · F1(BLOCK) · FPR = FP/(FP+TN) · FNR = FN/(FN+TP).

Reporting rules, from `docs/ml_evaluation_methodology.md` §5:

- Every percentage carries its **numerator and denominator**.
- Accuracy is never reported alone.
- **Prevalence is stated wherever precision or accuracy appears.** External v1 is 50/50 by
  construction; that is not the prevalence of real traffic.
- Zero errors on *n* is reported as a bound (95% upper ≈ 3/*n*), never as "0%".
- **Invalid outputs are never coerced** — counted as an incorrect decision, mapped to the
  opposite of expected, reported as a separate rate, with a parseable-only view alongside.
  This is evaluation policy and is deliberately distinct from D4 runtime fail-closed.

Breakdowns: per **attack category** (ground-truth category, not model reason) and per
**benign slice**, each with an `evidence_status` column.

**Secondary, not headline:** reason-match accuracy (D19 level 2) over correctly-blocked
attacks only, so a reason mismatch can never reduce binary recall.

### Support rule (D18 / D19, `MIN_EVAL_SUPPORT = 30`)

| Support *n* | Status | Permitted |
|---|---|---|
| **≥ 30** | `OK` | performance claim permitted |
| **1–29** | `INSUFFICIENT DATA` | exploratory only, no performance claim |
| **0** | `NOT EVALUABLE` | no claim of any kind |

**No artificial duplication to reach 30.** A scarce cell stays scarce and is reported as
such. This applies to primary slices and to every secondary breakdown.

### L2 — gateway enforcement

Enforcement-conformance rate (numerator/denominator) · a decision × outcome matrix
(ALLOW / BLOCK / no-valid-decision) × (forwarded / 403 / 503 / other) · destination
receipts that should not exist · missing receipts that should exist · fail-closed
activations with cause. **Reported separately from L1.**

### L3 — end-to-end outcome

Four counts: **benign delivered** · **benign broken** · **attacks stopped** ·
**attacks delivered**. Each failure attributed to model error or enforcement error.

> **Terminology, binding on every report.** **"attack delivered" means: a ground-truth
> malicious HTTP request reached the protected destination.** It does **not** mean the
> target was successfully exploited. External v1 does not measure exploitation: `lab-app`
> is not required to be vulnerable (§5.1), nothing checks whether a delivered request had
> any effect, and no exploitation claim may be derived from this count. Likewise "attack
> stopped" means the request did not reach the destination, not that an exploit was
> prevented.

### RQ2 — generalization comparison

Side by side against the V4 internal figures in `reports/v4_clean_eval.json`
(6,206 rows, 3,103/3,103):

| Metric | V4 internal | External v1 | Gap |
|---|---|---|---|
| Accuracy | 98.49% | — | — |
| Precision (BLOCK) | 99.93% | — | — |
| Recall / ADR | 97.04% | — | — |
| F1 (BLOCK) | 98.46% | — | — |
| FPR | 0.06% (2/3,103) | — | — |
| FNR | 2.96% (92/3,103) | — | — |
| Invalid rate | 0.00% | — | — |

Gap = internal − external, per metric, and per category for the five categories chosen
because V4 publishes per-category recall for them (§6.2).

**Mandatory caveat wherever this table appears:** V4's internal `eval.jsonl` served both as
validation and as the internal evaluation, so it is **not an independent internal test**
(D24). The comparison is external-vs-*internal-eval*, not external-vs-independent-internal.
Both sides are 50/50, so the comparison is not distorted by prevalence.

---

## 4. Traffic design

### 4.1 Provenance — real clients and applications inside the authorized Docker Lab

External v1 is **not** a list of handwritten strings posted to `/classify`. All traffic is
produced by real HTTP clients against a real application running inside the Docker Lab.

| Class | Origin | Clients |
|---|---|---|
| Benign | real browser and API client interaction with the lab application | Playwright/Chromium; Python `httpx`; `curl` |
| Malicious | pre-registered authorized attack requests targeting the lab application | Python `httpx`; `curl` |

**Authorization limit.** Every request targets services inside the Docker Lab, owned by
this project. No external or third-party system is a target, under any circumstance.

### 4.2 Capture → label → freeze → replay

The core mechanism, and the reason ground truth can be assigned before exposure:

```
DRAFT capture   real clients drive the lab app  ── NO PROXY, NO CLASSIFIER ──▶ captured requests
     ↓
labelling       ground truth assigned to every captured request
     ↓
gate            independence + integrity checks (§7)
     ↓
FREEZE          cases.jsonl + manifest + SHA-256, committed
     ↓
execution       frozen texts replayed BYTE-EXACTLY through the gateway
```

Capture happens with the proxy and classifier **absent from the path**, so V4 cannot
influence what the set contains. Replay is byte-exact via a raw-socket client, so what V4
is scored on is exactly what was labelled.

A browser page load emits sub-resource requests (assets, favicon). **These are captured and
labelled like any other request** — they are real benign traffic — rather than filtered out.
Their inclusion is declared here, before exposure.

#### How Chromium-generated requests are captured

Chromium is launched by Playwright with `--proxy-server=http://capture-proxy:8081`, so
every request it makes — page loads, form submissions, XHR, sub-resources — traverses the
`capture-proxy` service. That service is **the data-plane image running a capture-only
addon**: same mitmproxy version as the firewall, with the firewall addon replaced by
`scripts/external/capture_addon.py`, which

- **imports `render_request` from `data_plane/data_plane.py`** rather than copying it, so
  the captured text is produced by the one implementation of the D1 representation. A test
  asserts object identity (`capture_addon.render_request is data_plane.render_request`),
  the same guarantee `test_model` holds against `inference_core`;
- writes one JSONL record per request — text, SHA-256, byte counts, method, host, path,
  sequence, timestamp — and **forwards everything untouched**;
- **classifies nothing, blocks nothing, and never contacts the control plane.** The
  `FirewallGateway` object that `data_plane` constructs on import is never registered with
  mitmproxy; a test asserts the addon list contains only the capture addon.

Capturing at the proxy rather than at the application is deliberate: the application sees
what a WSGI server parsed, whereas the proxy sees what V4 would be handed.

**Precise sense of "before model exposure":** the *firewall* data plane and the control
plane are absent from the path. A passive capture proxy is present, and must be — it is
what makes the captured text identical to the text the firewall would later classify. No
model is in the path at any point during capture.

#### Verifying capture fidelity before the final DRAFT

The chain is only valid if a captured request, replayed, is handed to the classifier as the
same bytes. That is verified **before** the DRAFT is built, with no model in the path:

```
1. clients → capture-proxy → lab-app                 ⇒ capture_original.jsonl
2. replay.py --target capture (same capture proxy)   ⇒ capture_replayed.jsonl
3. fidelity_check.py compares the two by SHA-256
```

`fidelity_check.py` must report **PASS — replay is byte-exact** before Phase C proceeds. A
mismatch prints the differing lines, because a fidelity failure has to be actionable.

The same property is unit-tested offline against mitmproxy's own parser
(`tests/test_external_capture.py::TestByteExactRoundTrip`): rendered text → `to_wire()` →
mitmproxy parse → `render_request()` must be the identity function, across query
encodings, repeated headers, cookies, form and JSON bodies, non-ASCII and payload-bearing
requests.

**Canonical form is enforced.** `render_request()` emits no trailing newline after the last
header and uses LF endings. A case stored in any other form would be frozen under a hash
replay can never reproduce, so `wire.assert_canonical()` rejects it, and `replay.py` calls
it before every send.

**Secondary live pass.** A declared subset is additionally driven live by Playwright and
`curl` through the proxy at execution time. This provides L2/L3 evidence under genuine
browser behaviour and is the basis of the professor demo. Its request texts are not
byte-identical to the frozen ones; it is reported separately and **contributes no L1
headline metric**.

### 4.3 Benign slices — 5 slices, pre-declared

| Slice | Content | Client |
|---|---|---|
| `browser-navigation` | page loads, link navigation, static assets, redirects | Playwright/Chromium |
| `browser-forms-session` | login, search and checkout forms; cookies and session continuity; GET and POST | Playwright/Chromium |
| `api-json` | JSON GET/POST/PUT against the API routes, varied bodies | Python `httpx` |
| `api-query` | query-parameter-heavy GETs: filters, pagination, sorting, encoded values | `curl` |
| `unseen-structure` | benign requests whose structural features have **zero or near-zero support in `datasets/v4_clean/`** — host forms, ports, path shapes and header profiles counted directly from the V4 splits | mixed |

`unseen-structure` exists to answer RQ4 — **unseen-input robustness, not OOD detection.**
It measures how V4's ALLOW/BLOCK decisions behave on structures with little or no support in
the fine-tuning corpus. It does **not** measure, and must never be reported as, the model
detecting that an input is out of distribution: V4 emits no confidence, no novelty score and
no OOD signal, and none is added here. The slice is **informed by** `real-http-fp-v1`, which is
permitted; its **concrete cases are never reused**, which is enforced by the gate (§7). The
slice is a declared structural axis sampled fresh, not a replay of known failures. It is
expected to be harder, it is one fifth of the benign population by pre-declared design, and
it is always reported separately as well as inside the headline.

Secondary dimensions recorded on every case and reported as breakdowns subject to the
support rule: `client_profile`, `host_type`, `method`, `body_type`, `route_family`.

### 4.4 Malicious categories — 5 categories, pre-declared

Chosen because V4 publishes per-category held-out recall for all five, which makes the RQ2
per-category gap computable, and because each can be represented credibly against the lab
application.

| Category | V4 internal recall | Why included |
|---|---|---|
| SQL injection | 90.94% (743/817) | largest internal FN source |
| Command injection | 87.31% (117/134) | second FN source |
| Cross-site scripting | 100% | internal ceiling — does it hold externally? |
| Path traversal | 100% | internal ceiling |
| Server-side request forgery | 98.41% (62/63) | dominant BLOCK reason in the `real-http-fp-v1` diagnostic |

The remaining 14 V4 categories are **out of scope for External v1** and are recorded as
`NOT EVALUABLE (not sampled)` — not as failures, and not silently omitted.

**Payload independence.** Malicious payloads are **authored against the lab application's
own routes, parameters and schema**, and are *not* drawn from PayloadsAllTheThings, which at
commit `e961fef` is V4's training source.

> **App-specific authoring reduces direct reuse risk. Independence from V4 fine-tuning and
> development data is established by the pre-freeze exact/canonical collision gate (§7).**

Authoring style is a risk-reduction measure, not evidence. No case is treated as independent
because of how it was written; independence is a gate result. Any collision is rejected and
replaced.

**No evasion or obfuscation.** The six held-out transform families of D15 are **not** used.
Evasion resistance is the separate E6 suite and is explicitly out of scope (§12).

### 4.5 Balance

**50% ALLOW / 50% BLOCK**, fixed here, before exposure. **This balance is not changed after
V4 results are seen**, for any reason.

---

## 5. Application and client environment

### 5.1 `lab-app` — a new service; the smoke destination stays untouched

The existing `destination` service is a two-page static origin, sufficient for plumbing and
used by the Docker Lab smoke tests. It is **left exactly as it is**, so
`./docker/smoke_test.sh` keeps working unchanged.

A **new** service, `lab-app`, is added for External v1:

| Requirement | Provided by |
|---|---|
| realistic pages and routes | `/`, `/products`, `/products/<id>`, `/search`, `/cart`, `/checkout`, `/login`, `/profile`, `/static/*` |
| forms | GET search; POST login, add-to-cart, checkout |
| cookies / session | signed session cookie, login state, cart contents |
| JSON / API endpoints | `GET /api/products`, `GET /api/products/<id>`, `POST /api/orders`, `GET /api/me` |
| query parameters | `category`, `q`, `page`, `sort`, `limit` |
| observable receipts | append-only JSONL receipt log, same pattern as `destination` |
| controlled attack target | reachable only inside the lab network |

**The lab app deliberately need not be exploitable.** External v1 measures classification
and enforcement, not exploitation: an attack that V4 blocks never reaches the app, so
whether the app *would* have been vulnerable changes no metric at any of the three levels.
This is why a small purpose-built app is preferred over DVWA or Juice Shop — it is smaller,
fully reproducible, deterministic in its receipts, faster to start for the demo, and
carries no vulnerable-service risk inside the lab. Attack *success* is out of scope and is
stated as a limitation (§13).

### 5.2 `generator` — traffic generation service

One new service, behind a compose profile so neither `docker compose up` nor the smoke
tests are affected:

- Playwright + Chromium for browser flows
- `httpx` and `curl` for API and attack flows
- a raw-socket replay client for byte-exact execution of frozen cases

### 5.3 Network

Unchanged bridge network. `lab-app` receives aliases (`shop.fwlab.test`, `api.fwlab.test`)
so `host_type` can vary. **Scope stays plain HTTP/1.1 through an explicit proxy** — no
HTTPS, HTTP/2, WebSockets or transparent proxying.

---

## 6. Repository layout

```
datasets/external_v1/
  manifest.json          identity, provenance, counts, hashes, status, limitations
  cases.jsonl            the frozen cases
  SHA256SUMS
  fixtures/              lab-app content the cases assume
  build/                 capture + authoring scripts, source notes
  GROUND_TRUTH.md        labelling rules and resolved disagreements

scripts/external/external_v1.py     one tool, subcommands (mirrors benchmark_inference.py)
    capture | label | check | freeze | run | score | self-test

reports/external/external-v1-run-001/
  manifest.json  results.jsonl  summary.json  summary.md  raw/  SHA256SUMS
```

---

## 7. Independence checks — the pre-freeze gate

Run in DRAFT, with no model contact. Uses `parse_dataset_v4.canonical_key()` — the same
canonicalization that guarantees V4's own grouped split (D16), so External v1 is held to
the standard V4 was.

| # | Check | Against | On hit |
|---|---|---|---|
| 1 | exact raw-text duplicate | V4 train + eval (31,340 rows) | **FAIL** |
| 2 | **canonical/logical collision** | V4 train + eval payload keys | **FAIL** |
| 3 | internal duplicates | within External v1, exact and canonical | **FAIL** |
| 4 | diagnostic reuse | `reports/diagnostics/real-http-fp-v1/cases.jsonl` (149 texts) | **FAIL** |
| 5 | smoke-fixture reuse | the Docker Lab ALLOW/BLOCK fixtures | **FAIL** |
| 6 | near-duplicate | token-shingle Jaccard vs V4, above threshold | **WARN** → manual ruling, logged |
| 7 | CSIC ancestry | payload substring vs `csic_database.csv` | **WARN** → manual ruling, logged |

Check 2 is the one that matters: exact matching alone would pass an encoded variant of a
training payload. `canonical_key()` undoes three layers of percent-encoding, unicode
escapes, HTML entities, SQL comments, `${IFS}`, whitespace runs and case.

**The gate is blocking.** Freeze cannot proceed while any FAIL exists, mirroring the rule
that no training starts while `check_dataset.py` reports FAIL. Every WARN is resolved in
writing before freeze.

**Limit of the independence claim, to be stated in the manifest and in every report:**
External v1's independence is verified against **V4's fine-tuning and development data**,
which is in-repo and checkable. **No claim is made of independence from TinyLlama's
pretraining corpus**, which cannot be inspected.

---

## 8. Ground truth

- Assigned during DRAFT, **before any model exposure**, from the captured request and the
  intent of the flow that produced it — never from V4's output.
- Benign: a request is ALLOW if it is a legitimate interaction the application is designed
  to serve. Malicious: BLOCK, with the ground-truth attack category recorded.
- Ambiguous cases are **excluded**, not guessed, and the exclusion is logged with its
  reason. Exclusions happen only in DRAFT.
- **Two-pass review.** A second pass re-reads every label independently. Every
  disagreement and its resolution is recorded in `GROUND_TRUTH.md`.
- Ground truth is attached to the **case**, not to a byte string. A client adding
  `Proxy-Connection` does not make a benign request malicious. Text divergence between the
  registered and the transmitted request is recorded as provenance, never as a relabel.

---

## 9. Freeze and immutability

```
1. capture  (no proxy, no classifier)
2. label    (two-pass review)
3. check    (§7 gate — must be clean)
4. trim     deterministically to the declared counts (§10), seed recorded
5. freeze   SHA-256 of cases.jsonl and every fixture; manifest status = FROZEN; frozen_utc
6. commit   the dataset commit hash is recorded
7. ONLY NOW may any case reach the gateway
```

**Exact immutability definition.** External v1 becomes immutable at the git commit
containing `datasets/external_v1/manifest.json` with `status: "FROZEN"`, populated
`artifact_sha256` and `frozen_utc`, which must be an ancestor of every run that cites it.
After that commit **any change to any case requires external_v2** — including correcting a
case later found to be mislabelled. A mislabelled case is disclosed as a known defect of v1
and fixed in v2.

**D37 tripwire, recorded in the manifest.** Reporting aggregate and per-slice metrics does
not consume the set. The moment individual External v1 errors are inspected and used to
develop, train or select V5, External v1 becomes development / error-analysis data for V5
and **external_v2 is required** before any V5 claim.

---

## 10. Composition — fixed before exposure

**400 unique cases: 200 ALLOW / 200 BLOCK.**

| Benign slice | Cases | | Malicious category | Cases |
|---|---:|---|---|---:|
| `browser-navigation` | 40 | | SQL injection | 40 |
| `browser-forms-session` | 40 | | Command injection | 40 |
| `api-json` | 40 | | Cross-site scripting | 40 |
| `api-query` | 40 | | Path traversal | 40 |
| `unseen-structure` | 40 | | Server-side request forgery | 40 |
| **ALLOW total** | **200** | | **BLOCK total** | **200** |

Every primary cell is at 40 ≥ 30, so all ten carry `OK` status. Secondary breakdowns
(`client_profile`, `host_type`, `method`, `body_type`) take whatever support arises
naturally and are reported under the support rule — several will legitimately land in
`INSUFFICIENT DATA`, and are reported that way rather than padded.

**Authoring buffer.** DRAFT produces ≈1.2× target per cell. The gate rejects collisions,
then step 4 trims deterministically (recorded seed) to exactly the counts above. This
prevents a gate rejection from silently dropping a cell below 30.

**Execution volume.** 400 cases × 3 repetitions = 1,200 gateway requests, plus a declared
direct-`/classify` consistency subset of 100 × 3 = 300. At the measured ≈230 ms steady
model latency this is ≈6 minutes of inference.

---

## 11. Execution

- **Primary channel:** frozen texts replayed byte-exactly through the complete system —
  client → data plane → control plane → V4 → enforcement → destination. All L1, L2 and L3
  headline metrics come from here.
- **Auxiliary channel:** a declared 100-case subset also sent directly to `/classify`. This
  is a **per-layer consistency control only** — it verifies the proxy and the API agree on
  identical text, as `real-http-fp-v1` did 78/78. It never contributes a headline metric.
- **3 repetitions.** Greedy decoding is deterministic (D27), so repetition tests service
  state, not variance. Headline metrics come from repetition 1; any case differing across
  repetitions is flagged, counted and disclosed, and excluded from the headline.
- **One run = one immutable experiment id** (`external-v1-run-001`). The runner refuses to
  overwrite an id that already has results (the D32 rule).
- **Capture what was actually classified.** The bytes the proxy sent to `/classify` are
  captured (`strace`, as in `real-http-fp-v1`), hashed and compared with the registered
  text. Mismatches are recorded, never silently accepted.
- **No markers in requests under test** — no correlation IDs, no test headers. Every header
  is model input (methodology §8). Correlation is by ordering and captured-text hash.
- Visible processes, all logs tee'd and committed under the run's `raw/` (methodology §13).
- **Latency observed during the run is an observation, not a benchmark.** D36 is not
  evaluated by External v1, and no latency figure from it is comparable to
  `baseline-local-v1`.

### Result schema

`results.jsonl`, one record per (case, repetition, channel):

```jsonc
{
  "case_id": "...", "repetition": 1, "channel": "gateway",
  "registered_sha256": "...", "sent_sha256": "...", "text_matches_registered": true,
  "decision": "BLOCK", "reason": "...", "status": "ok",
  "http_status": 403, "destination_receipt": false, "fail_closed_cause": null,
  "model_latency_ms": 231.2,
  "l1_outcome": "TP", "l2_conformant": true, "l3_outcome": "attack_stopped"
}
```

`summary.json` carries L1 (with per-category and per-slice tables and `evidence_status`),
L2, L3, the RQ2 comparison, determinism, and the layer-consistency result.

---

## 12. Out of scope — explicitly not done in External v1

Adversarial / evasion suite (E6, D15 held-out transforms) · explicit OOD detector ·
calibration and uncertainty metrics · shortcut-learning experiments · formal overfitting
study · V4.1 / V5 · dataset expansion · fast path · suspicious scoring · asynchronous
validation · GGUF · llama.cpp · embedded hardware · formal end-to-end latency benchmark
(Issue #18) · HTTPS / HTTP/2 / WebSockets · concurrency and load.

Adversarial / evasion work is **future work** and does not block this evaluation.

---

## 13. Limitations of the resulting evaluation

Stated in advance so they cannot be chosen after the fact:

1. **Independence is verified against V4's fine-tuning and development data only.** No
   claim is made about TinyLlama's pretraining corpus.
2. **50/50 prevalence is a construction, not reality.** Precision and accuracy are
   prevalence-dependent; operational values will differ.
3. **One application, one lab.** Traffic comes from a single purpose-built application on
   one machine. It is real client traffic, but not traffic from a production service or a
   diverse application population.
4. **Five of nineteen attack categories.** The other fourteen are `NOT EVALUABLE (not
   sampled)`; External v1 says nothing about them.
5. **No evasion resistance measured**, by design.
6. **Attack success is not measured.** The lab app is not required to be exploitable; only
   classification and enforcement are measured.
7. **One model version, one seed, one adapter, one machine.** No confidence intervals
   across training runs.
8. **Plain HTTP/1.1 through an explicit proxy only.**
9. **Sequential execution.** Concurrency and load are untested; the control plane
   serializes inference on one GPU.
10. **The internal comparison baseline is not an independent internal test** (D24), so the
    RQ2 gap is measured against V4's validation-and-evaluation split.
11. **Latency observations are not benchmark results.**
12. Benign ground truth reflects the intent of the flow that produced the request, judged by
    this project; it is not adjudicated by an external party.
