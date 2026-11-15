# firewall-IA

An HTTP application-layer security gateway built around a fine-tuned TinyLlama-1.1B classifier,
with deterministic application contracts, explicit enforcement and reproducible laboratory evaluation.

**Current candidate, evaluated 2026-11-13: Fast Path + V5.1, with an app-bound header guard.
Model 2 is absent from the candidate's active path.**
This checkout contains local candidate changes and public reports; integration to develop is being prepared.

Start with [current state and limits](docs/project_status.md), the [documentation map](docs/index.md)
and [working context](CONTEXT.md).

## Architecture

~~~text
client -- TLS / HTTP/1.1 or HTTP/2 --> nginx front
       -- HTTP/1.1 --> mitmproxy scope / framing / canonical checks
       --> optional Inf3ct header-sink guard
       --> public-resource Fast Path
       --> V5.1 for requests that CONTINUE
       --> egress guard --> isolated application
~~~

- **Fast Path** permits requests covered by an application-bound public-resource contract.
  Unsupported headers, ambiguous input or unmatched routes continue to inspection.
- **V5.1** uses canonical-request/v1 and a pinned HF/PEFT runtime. Valid ALLOW permits delivery;
  BLOCK denies with 403; invalid or unavailable required classification fails closed.
- **Header guard** is a separately attributed deterministic control for Inf3ct's Jinja header sink.
  It does not change V5.1 weights and does not cover general stored HTML.
- **Egress guard** binds classification to the request delivered upstream. This controlled reverse-proxy
  boundary does not attest to preservation of the original client wire bytes.
- **Historical modes** retain Model 2 and V4 for reproduction. They are not the candidate's fallback.
  V4 retains known prompt-input and admission-control limitations.

Manifest: [v51-fast-path-v5-lab-20261111](reports/v5/fastv5-2026-11-11/manifest.EXPERIMENTAL.json).
Mode: FAST_PATH_V5. Arm: fastv5_guard; fastv5 is the ablation without the header guard.
The classifier remains stateless per request, even when evaluated with multi-step application sessions.

## Measured result

[The sealed 13 November campaign](reports/v5/architecture-campaign-2026-11-13/RESULTS.md)
uses six vulnerable lab apps, 985 benign requests in 172 sessions, 65 eligible attack sessions,
68 injection steps and 584 boundary probes over the primary h1 TLS transport.

| Arm | Benign FP / 985 | Complete benign sessions / 172 | Attack sessions with effect prevented / 65 |
| --- | --- | --- | --- |
| V5.1 only | 211 | 21 | 48 |
| Fast Path + V5.1 | 3 | 169 | 48 |
| Candidate with header guard | 3 | 169 | 63 |
| ModSecurity + OWASP CRS 4.25.2 PL1 | 0 | 172 | 50 |

Fast Path avoids **789/985 benign V5 calls (80.10%)** at audit sampling rate 0.
On the fixed An0nB0ard load cycle, the candidate sustains 32 requests/s under the declared
1,000 ms SLO, versus 16 for V5-only; direct/CRS reach the 64 requests/s ceiling.

Interpretation:
- Benign recovery comes from routing public resources through Fast Path, not better weights.
- The extra header-SSTI prevention comes from the deterministic guard, not the model.
- Three V5 false positives and two stored-HTML-via-header effects remain.
- The 985 benign observations represent 151 canonical texts, not independent model inputs.
- App-specific policies and agent-generated traffic do not establish production risk,
  unseen-app generalization or superiority over CRS in general.
- Effect prevention is not automatically flag prevention; the
  [separate 14 November flag campaign](reports/v5/flag-acquisition-2026-11-14/run-1/RESULTS.md)
  measures flag acquisition and prevention as its own experiment (see below).

See [primary metrics](reports/v5/architecture-campaign-2026-11-13/METRICS.json),
[HTTP/2 subset](reports/v5/architecture-campaign-2026-11-13/METRICS.h2.json),
[load](reports/v5/architecture-campaign-2026-11-13/LOAD_INDEX.json) and
[faults](reports/v5/architecture-campaign-2026-11-13/FAULT_INDEX.json).

## Flag-acquisition result (14 November, separate campaign)

A [separate flag campaign](reports/v5/flag-acquisition-2026-11-14/run-1/RESULTS.md) measured, over
`h1_tls_new` only, whether each app's flag can be obtained over HTTP and whether the architecture
prevents it. It is **not** merged with the 13 November architecture metrics.

- Flags were recorded on `direct` in **four of six apps**, 3/3 reps each: CatP1cs traversal,
  Inf3ct header SSTI, An0nB0ard login with a fixed lab credential, and the legitimate
  D33pTh0ught `answer=42`. ag3ncy's flag branch remains unmeasured.
- The candidate prevents **6/6 exploit-driven flag retrievals** in CatP1cs/Inf3ct, plus
  **3/3 SQLi credential disclosures** in An0nB0ard. The combined 9/9 mixes two outcomes;
  it is not nine prevented flags. V5-only, fastv5 and CRS each prevent 3/6 of those flag
  retrievals and 3/3 credential disclosures. Header SSTI is stopped by `request_guard`, not V5.
- An0nB0ard's login uses a credential fixed in the sealed cases and returns the flag on
  **every arm**. The experiment proves credential disclosure and its blocking, not a dynamic
  extraction-to-login chain or prevention of the login flag. See the
  [independent audit correction](reports/v5/flag-acquisition-2026-11-14/run-1/AUDIT_CORRECTIONS.md).
- The three exploit apps ship the **same placeholder flag**; the result is about the retrieval
  *mechanism* (recorded runtime full-string oracles), not three distinct secrets. 9/9 is three repeated
  sequences, **not** nine independent techniques nor six exploited apps.
- ObC00ki3s has no HTTP-acquirable flag (client-side only); ag3ncy's password was not found within a
  fixed budget (admin branch unmeasured). The legitimate D33pTh0ught retrieval is correctly allowed
  on every arm and is not counted as a miss.

## Run the laboratory

Environment pins and prerequisites: [local stack](docs/local_stack.md) and
[challenge apps](docs/challenge_apps.md). The app checkout, Docker images and local model weights
are separate prerequisites; a source clone does not include them.

Arms: direct, v5only, fastv5, fastv5_guard, crs, and historical guarded.
The old guarded_fast variant is generated with --arm guarded --fast-path; it is not a separate CLI arm.
A CPU double verifies routing/attribution; quality measurements require the real pinned model.

Inspect commands without starting Docker or loading a model:

~~~bash
.venv-dataplane/bin/python scripts/local_stack/challenges/challenge_stack.py --help
.venv-dataplane/bin/python scripts/local_stack/challenges/challenge_stack.py config --help
~~~

After building the pinned app image, create a fresh candidate configuration outside the repository:

~~~bash
.venv-dataplane/bin/python scripts/local_stack/challenges/challenge_stack.py config --app Inf3ct --arm fastv5_guard --out /tmp/inf3ct.fastv5-guard.json
~~~

Config pins app/image/manifest/policy identities and refuses overwriting existing outputs.
Read the [candidate lifecycle](docs/challenge_apps.md#current-candidate-2026-11-13) before starting services.
Coordinate Docker, ports and GPU with the active campaign owner.
Work directories contain keys, credentials and request logs and belong outside Git.

## Tests

Focused candidate and measurement checks, without Docker or GPU:

~~~bash
.venv-dataplane/bin/python -m unittest tests.test_fastv5_candidate tests.test_fastv5_measurement
~~~

Broader tests have different environment/data prerequisites. Some historical tests read protected
evaluation datasets; blanket discovery is not an appropriate documentation-only check.
Historical test counts remain in dated reports; they are not a current whole-repository count.

## Evidence and development history

- [Current candidate identities, denominators and limitations](docs/project_status.md)
- [Architecture campaign, 13 November](reports/v5/architecture-campaign-2026-11-13/README.md)
- [Independent audit and metric coverage](reports/v5/architecture-campaign-2026-11-13/audit/README.md)
- [Flag-acquisition campaign, 14 November (h1 only)](reports/v5/flag-acquisition-2026-11-14/run-1/RESULTS.md)
- [Six-app campaign, 7 November](reports/v5/challenge-apps-campaign-2026-11-07/RESULTS.md)
- [V5.1 post-training and runtime](reports/v5/successor-post-training-2026-11-01/INFORME.md)
- [V5.2 not-selected record](reports/v5/v52-training-runs/v52-correction-20261105T031357Z/NOT_SELECTED.md)
- [Historical V4, Analyzer and External v1 reference](docs/technical_reference.md)
- [Decision log](DECISIONS.md), [issue review](docs/issue_closure_2026-11-14.md), [future work](docs/future_work.md)
- [Previous README](docs/history/README-through-2026-10-21.md), [previous context](docs/history/CONTEXT-through-2026-10-26.md)

Model, dataset, representation, runtime, app contract and gateway versions are separate identities.
Earlier DEV, selection-validation, protected-test and architecture results are not pooled.
Historical V4/smoke GGUF experiments do not export the selected V5.1 model.
Embedded selection, final-model export/backend integration and physical deployment remain pending.

## Repository layout

| Path | Purpose |
| --- | --- |
| control_plane/ | V4/V5 classifier services, tokenization and inference |
| data_plane/ | Canonicalization, routing, Fast Path, header guard and delivery |
| scripts/local_stack/ | TLS/H2 front, isolated apps and stack lifecycle |
| scripts/local_stack/challenges/ | Six-app adapters and measurement helpers |
| tests/ | Scoped unit, integration and regression checks |
| reports/ | Versioned public reports, counts, hashes and evidence |
| docs/ | Operation, methodology, current state and history |

## Integration and license

The agreed integration is one PR to develop after source, evidence, documentation and Claude's flag
campaign are ready. Sebas prepares the later PR to main. A lab verdict does not imply a branch merge.
The [integration resolution](docs/integration_resolution_2026-11-14.md) records issue reasons and
unfinished criteria. V4 operational support/fallback is retired; historical entrypoints remain for
isolated reproduction with their unresolved input-token and overload limitations.

Original code and documentation use the [MIT license](LICENSE). Third-party apps and data keep their
own terms; see [data sources](docs/data_sources.md). Private payload evidence, keys, credentials
and model artifacts are not redistributed here.
