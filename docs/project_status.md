# Current project state — 2026-11-14

This document describes the local candidate and the evidence available for integration.
Implementation, experimental acceptance, Git integration and academic acceptance are separate states.

## Candidate and routing

Candidate: `fastv5-public-v3-headerguard-v2-20261111`. Mode: `FAST_PATH_V5`.
The owner directed removal of Model 2 from the new active path on 2026-11-11.
The candidate was evaluated on 2026-11-13; its results satisfy the campaign's C1–C5 criteria.
That finding is experimental acceptance within the measured scope, not an academic scope amendment
or an operational production approval.

```text
client -- TLS / HTTP/2 or HTTP/1.1 --> nginx front
       -- normalized HTTP/1.1 --> mitmproxy scope / framing / canonical validation
       --> optional app-bound request-header sink guard (Inf3ct)
       --> public-resource Fast Path --> V5.1 for requests that CONTINUE
       --> egress guard --> isolated challenge application
```

Model 2 is neither started nor called in this mode. The historical `CASCADE_ACTIVE`,
`CASCADE_OBSERVE`, `V4_ONLY` and `V5_ONLY` modes remain available for their recorded experiments.
Application HTTP sessions are evaluation units; the model still classifies requests independently.

| Identity | Value / source |
| --- | --- |
| Base | TinyLlama/TinyLlama-1.1B-Chat-v1.0, revision `fe8a4ea1ffedaf415f4da2f062534de366a451e6` |
| Selected adapter | V5.1, run `v51-policy-20261101T210119Z` |
| Adapter digest | `f101b2f1a8e849220adb0bd7948a4ab681579f0b3fac24629cdc1831c127c20c` |
| Representation | `canonical-request/v1`; unchanged by this architecture campaign |
| Model runtime | HF/PEFT, experimental verified-suffix profile pinned by the manifest |
| Candidate manifest | [manifest.EXPERIMENTAL.json](../reports/v5/fastv5-2026-11-11/manifest.EXPERIMENTAL.json) |
| Fast Path policies | [public-v3 policies](../reports/v5/fastv5-2026-11-11/policies/) |
| Header guard | `request-header-sink-guard/v2`, app-bound to Inf3ct |
| Apps | sec-challenges/Web, commit `be8e4e8f1c6aa12a17430146d569870d96d43dd5` |
| Frozen campaign | 451 files; manifest SHA-256 `ae1cf86fc7c3710f35014501fadbea0a0b03ad9e097fb2fd2bbc9d969b69e51d` |

Weights are local, ignored artifacts; cloning the source does not supply the adapter.
Use the manifest to validate an existing artifact, rather than silently substituting another model.

## Primary campaign results

Source: [2026-11-13 results](../reports/v5/architecture-campaign-2026-11-13/RESULTS.md)
and [primary metrics](../reports/v5/architecture-campaign-2026-11-13/METRICS.json).
The [public audit records](../reports/v5/architecture-campaign-2026-11-13/audit/README.md)
preserve the independent recount, reciprocal review and M01–M35 coverage.

Primary transport: `h1_tls_new`. Population: 985 benign requests in 172 sessions,
65 eligible attack sessions, 68 injection steps and 584 boundary probes.
These are distinct denominators. Benign traffic contains 151 canonical texts and 934 HTTP identities;
repeated observations do not become independent model inputs.

| Arm | Benign FP / 985 | Complete benign sessions / 172 | Injection TP / FN, 68 steps | Attack sessions with effect prevented / 65 |
| --- | --- | --- | --- | --- |
| V5.1 only | 211 | 21 | 51 / 17 | 48 |
| Fast Path + V5.1 | 3 | 169 | 51 / 17 | 48 |
| Fast Path + V5.1 + header guard | 3 | 169 | 66 / 2 | 63 |
| ModSecurity + OWASP CRS 4.25.2 PL1 | 0 | 172 | 53 / 15 | 50 |

The direct control is not a detector: all 65 eligible attack effects were observable there.
A complete benign session meets the expected oracle for every step, including expected legitimate errors.

Fast Path avoided 789/985 benign synchronous V5 calls (80.10%); 196 remained.
Audit sampling was **0** in this campaign. This is measured savings at that setting, not an estimate
including an enabled background auditor. There were no injection steps routed through Fast Path,
no boundary-contract violations, and no Fast Path response differences from the direct control
in the measured checks.

Attribution matters:
- Fast Path accounts for the benign FP reduction; V5.1 weights did not improve.
- The deterministic guard prevents the 15 header-SSTI sessions missed by V5-only and CRS PL1.
- V5 retains three benign false positives on inspected dynamic requests.
- Two stored-HTML-via-header effects persist with the candidate; CRS prevents those two.
- The model's exact reason matches 30/45 adjudicated correctly blocked V5 injection steps.
  Four further HTML cases are unadjudicated; guard decisions are outside this explanation denominator.

The h2 keepalive subset covers three apps, 566 benign requests and 49 eligible attack sessions:
candidate FP 3; effects prevented 47/49. It is a subset, not a repetition of the full six-app matrix.

## Load, reliability and latency scope

The final load profile uses 32 workers, open-loop arrivals, 20 seconds per point, three repetitions,
a 1,000 ms end-to-end SLO, and a fixed 4/8/16/32/64 requests/s ladder.
On the declared An0nB0ard read-only cycle, V5-only sustained 16 requests/s and the candidate 32;
direct/CRS reached the 64 requests/s ceiling. This is a client/SLO-constrained laboratory result.
ObC00ki3s V5-only was FP-bound even at the lowest load, so it has no latency-capacity estimate.

Fault trials use manual restarts and one observation per scenario. Recovery after the scheduled
restart took approximately 12.4–13.2 seconds. They do not establish autonomous recovery or prolonged
soak reliability. Resource samples are diagnostic; energy and isolated GPU consumption were not measured.

Do not conflate:
1. D36's P95 inference-pipeline target;
2. the academic plan's P95 added end-to-end latency target;
3. the campaign's 1,000 ms load SLO.
Subtracting the P95 of two separate arms does not produce the P95 of paired added latency.

## Earlier findings retained

| Milestone | Result and role |
| --- | --- |
| [V5.1 post-training](../reports/v5/successor-post-training-2026-11-01/INFORME.md) | Selected local successor; checkpoint selection data is not an independent test. |
| [Model 2 successor](../reports/v5/model2-successor-2026-11-05/INFORME.md) | Fixing the short-root case did not produce a generally superior learned stage. |
| [Model 2 guarded](../reports/v5/model2-guarded-2026-11-05/INFORME.md) | Scoped abstention policy evaluated; retained as historical research. |
| [V5.2 disposition](../reports/v5/v52-training-runs/v52-correction-20261105T031357Z/NOT_SELECTED.md) | Corrected four shared-validation FP and introduced 13 FN; not selected. |
| [Six apps, 7 November](../reports/v5/challenge-apps-campaign-2026-11-07/RESULTS.md) | Seven benign FP, no useful habitual Fast Path coverage (0/130), and header-SSTI leakage motivated the new candidate. |
| [Earlier load](../reports/v5/hybrid/gateway-integration-v1/load-run-1/INFORME_CARGA.md) | V4 lacks admission control and recovered slowly under overload; this remains a legacy limitation. |
| [GGUF diagnostics](../reports/v5/training-readiness/README.md) | V4/smoke exports exist. Q4_K_M changed nine V4 BLOCK decisions to ALLOW on 64 synthetic inputs; it was not authorized for gateway decisions. |

The earlier background Fast Path auditor is implemented and was exercised with real models.
Its historical agreement/disagreement and overhead evidence is in the
[load report](../reports/v5/hybrid/gateway-integration-v1/load-run-1/INFORME_CARGA.md)
and [V5.1 trials](../reports/v5/hybrid/gateway-integration-v1/candidate-trials-2026-11-01/INFORME.md).
Removing Model 2 does not remove the distinct asynchronous auditor.

## Flag-acquisition campaign (14 November)

A separate flag campaign was delivered on 2026-11-14:
[run-1 results](../reports/v5/flag-acquisition-2026-11-14/run-1/RESULTS.md),
[metrics](../reports/v5/flag-acquisition-2026-11-14/run-1/METRICS.json) and
[protocol](../reports/v5/flag-acquisition-2026-11-14/run-1/PROTOCOL.md). It names its own candidate,
protocol, state resets and denominators, is measured on `h1_tls_new` only, and is **not** pooled
with the 13 November architecture campaign. Raw cases and runs are private, outside Git; the public
[evidence index](../reports/v5/flag-acquisition-2026-11-14/run-1/EVIDENCE_INDEX.json) carries their SHA-256.

Objective: obtain each app's flag over HTTP against the `direct` control, then replay the same sealed
sequences through each arm (3 reps, clean state) to see whether and where the architecture prevents it.

| Flag outcome | Apps | Note |
| --- | --- | --- |
| Flag recorded over HTTP on `direct` | An0nB0ard, CatP1cs, Inf3ct, D33pTh0ught (4/6) | runtime full-string oracles, 3/3 reps; An0nB0ard login uses a fixed credential |
| Exploit sequences evaluated | traversal (CatP1cs), SQLi credential disclosure (An0nB0ard), header SSTI (Inf3ct) | **3** distinct sequences |
| No HTTP acquisition | ObC00ki3s | flag computed in-browser; server never sees it |
| Not retrieved (budgeted) | ag3ncy | correct password not found in a fixed offline budget; admin branch unmeasured |
| Legitimate (correctly allowed) | D33pTh0ught `answer=42` | a correct puzzle answer is not a WAF exploit; allowed on every arm |

Prevention of the three exploit primitives (denominator 9 = 3 primitives × 3 reps):
`fastv5_guard` **9/9**; `v5only` 6/9; `fastv5` 6/9; `crs` 6/9. This combines **6/6 prevented
flag retrievals** (CatP1cs/Inf3ct) and **3/3 prevented credential disclosures** (An0nB0ard).
The other three firewall arms prevent 3/6 flag retrievals plus 3/3 disclosures.
V5.1 blocks the traversal and the
SQLi credential read (target-visible); the deterministic `request_guard` blocks the header SSTI that
V5.1, the Fast Path ablation and CRS all leave `PERSISTED`. The guard block is attributed to
`request_guard`, not to V5.

Distinctions preserved:
- The three exploit apps ship the **same placeholder flag**; the evidence is about the full-string
  retrieval *mechanism*, not three distinct secrets. 9/9 is three repeated sequences — **not** nine
  independent techniques nor six exploited apps.
- An0nB0ard's **SQLi credential disclosure** is blocked on every firewall arm. Its independent login
  uses a credential fixed in the sealed cases and returns the flag on every arm. No dynamically
  coupled extraction-to-login chain was measured. The
  [audit correction](../reports/v5/flag-acquisition-2026-11-14/run-1/AUDIT_CORRECTIONS.md)
  qualifies the original report without changing rows, metrics or the earlier campaign.
- Effect-prevention counts (13 November) are not flag-prevention counts (14 November); the two
  campaigns keep separate denominators.

## Scope and integration

These are six deliberately vulnerable Flask laboratory applications and agent-generated traffic.
They do not establish organic user behavior, adaptive-attacker resistance, behavior on new apps,
or production traffic risk. Policies are app-specific; the complete architecture is not zero-shot.

The academic embedded objective and the final-model GGUF/runtime path remain pending.
No dated supervisor approval replacing those deliverables is recorded by this documentation update.
Future research remains in [future_work.md](future_work.md).
The [integration resolution](integration_resolution_2026-11-14.md) maps outstanding criteria and
distinguishes completed work from retired plans. V4 operational support/fallback is retired;
its vulnerability is unpatched and retained modes serve isolated historical reproduction only.

Git baseline at the start of this documentation pass:
`feat/hybrid-cascade-integration`, HEAD `f61fa108aebe6e3431a32c36d0c3977b0a4f812a`.
The tested candidate has substantial local/untracked changes and is not yet merged to `develop`.
The agreed sequence is coherent commits and **one PR to develop after Claude's results and the
documentation are complete**; Sebas creates the later PR to main.
