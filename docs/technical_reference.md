# firewall-IA — technical reference

Component-level detail for the control plane, the data plane, the inference benchmark and
the dataset. It was moved here verbatim from the top-level README when the first
functional gateway stage was closed (2026-09-21), so the README could stay a short front
page. Statements that later evidence made stale were corrected in place and are marked
*(updated at stage close)*.

- Headline status and results: [`../README.md`](../README.md)
- Authoritative current technical state: [`../CONTEXT.md`](../CONTEXT.md)
- Decisions D1–D53: [`../DECISIONS.md`](../DECISIONS.md)
- Docker Lab and the demo: [`../docker/README.md`](../docker/README.md)
- External Test v1 methodology: [`external_test_v1_protocol.md`](external_test_v1_protocol.md)

Contents: [Control Plane](#control-plane-issue-15) ·
[Data Plane](#data-plane-issues-16-17--first-version) ·
[Shadow feature extraction](#shadow-feature-extraction-hybrid-architecture-phase-1) ·
[Inference Benchmark](#inference-benchmark-issue-9) ·
[External v1 latency observations](#external-test-v1--latency-observations-derived) ·
[External v1 secondary breakdowns](#external-test-v1--secondary-breakdowns-pre-registered) ·
[Phase B fidelity](#capture--replay-fidelity--external-v1-phase-b) ·
[Dataset Integrity](#dataset-integrity) ·
[Known Limitations](#known-limitations) ·
[Roadmap](#roadmap) ·
[Repository Workflow](#repository-workflow)

---

## Control Plane (Issue #15)

`classifier_api.py` exposes the V4 classifier over HTTP. It **classifies and reports —
it does not enforce**. Enforcement, including fail-closed, lives in the
[data plane](#data-plane-issues-16-17--first-version).

```
test_model.py  -->  inference_core.py  <--  classifier_api.py
```

`inference_core.py` is the **single owner** of the V4 inference pipeline: the decision
contract (`INSTRUCTION`, `EXTRACT_RE`), the prompt template, model loading, generation
and parsing. Both the evaluation harness and the control plane import it, so runtime and
evaluation cannot drift apart. The previous `classifier_api.py` — which targeted the
absent `model-output-v3`, used a different quantization compute dtype, and silently
coerced unparseable output to ALLOW — was deleted and rewritten against this core.

The active adapter is `model-output-v4-clean/`, resolved relative to the repository and
overridable with `FIREWALL_ADAPTER_DIR`. The model is loaded once at startup.

### Endpoints

`GET /health` — always 200 while the process is up; `model_loaded` carries readiness.

```json
{"status": "ok", "model_loaded": true, "adapter_dir": ".../model-output-v4-clean"}
```

`POST /classify` — body `{"request": "<raw HTTP request text>"}`, the same representation
used in training and evaluation (D1), never structured method/path/header fields.

```json
{"status": "ok", "decision": "BLOCK", "reason": "Cross-site scripting payload detected", "model_latency_ms": 223.25}
{"status": "invalid", "decision": null, "reason": null, "model_latency_ms": 12.5}
```

An unparseable model output is **never coerced** into a decision — not to ALLOW, not to
BLOCK. It is reported as `status: "invalid"` with a null decision and null reason (D25).
Other responses: `422` malformed body, `503` model not loaded (D28), `500` inference
failure — no traceback is ever returned to the client.

`model_latency_ms` is **model-side inference only**, the same scope the V4 evaluation
uses. It covers `generate()` alone, so it is not the Decision D36 latency objective's instrument,
which covers the whole inference pipeline (see [Inference Benchmark](#inference-benchmark-issue-9)).
It is not end-to-end latency, which has not been measured yet.

### Running it

```bash
python3.12 -m uvicorn --app-dir control_plane classifier_api:app --host 127.0.0.1 --port 8000
curl -s http://127.0.0.1:8000/health
```

### Runtime evidence

Executed against the real V4 adapter on an RTX 4090 Laptop GPU:

- Model loaded once at startup, in 2.4 s on CUDA
- `GET /health` -> 200, `model_loaded: true`, correct adapter path
- A real ALLOW row and a real BLOCK row from `datasets/v4_clean/eval.jsonl` classified
  in agreement with their labels
- 30 fixed eval rows (15 ALLOW / 15 BLOCK): 0 invalid outputs, and 30/30 identical
  answers on repeat — greedy decoding is deterministic
- Request bodies are not written to the log
- 37 unit tests pass, including a regression test that an unparseable output can never
  become ALLOW

**Latency — preliminary, not a benchmark.** The first inference after process start
measured **512.8 ms** (CUDA warm-up / cold start). Steady-state, with the model already
warm: **n=30, P50 232.5 ms, mean 211.5 ms, min 159.5 ms, max 241.9 ms**. The 512.8 ms
warm-up sample was measured separately and is **not** included in those statistics.

Read this as runtime evidence that the control plane works, and as a preliminary
steady-state signal — **not** as a performance result. It is a small functional sample
and is **not** comparable to the formal model-side P95 of 270.8 ms, which is a different
statistic measured over the full 6,206-row split. The controlled benchmark is Issue #9.
It must report cold-start and steady-state as **separate** sets: the warm-up sample is
neither to be silently discarded nor pooled into steady-state statistics without saying so.

---

## Data Plane (Issues #16, #17) — first version

`data_plane.py` is a mitmproxy addon: an **authorized inline interception** point, not a
man-in-the-middle attack. Every HTTP request that reaches the proxy is classified by the
control plane before anything is forwarded.

```
HTTP client --(HTTP proxy 127.0.0.1:8080)--> mitmdump -s data_plane/data_plane.py
                                                 |  render_request(): raw HTTP text (D1)
                                                 v
                                   POST http://127.0.0.1:8000/classify   (control plane: the model)
                                                 |
               ALLOW <---------------------------+---------------------------> BLOCK / no valid decision
                 |                                                               |
   forwarded to the destination                            answered by the proxy, never forwarded:
                                                           403 model BLOCK, 503 fail-closed
```

The data plane **never loads the model**; it only speaks HTTP to the control plane. The two
run as separate processes in separate Python environments (D33).

**What is sent to `/classify`.** The unchanged contract `{"request": "<raw HTTP text>"}`, in
the exact layout of the V4 dataset: `METHOD /path?query HTTP/1.1`, one `Name: value` line
per header, LF line endings, and a blank line plus the body only when there is a body.
Headers are passed exactly as received, never filtered or normalized. A unit test rebuilds
all 6,206 held-out rows as mitmproxy requests and checks that the rendering reproduces
each one byte for byte.

### Fail-closed (D4, D34)

| Classifier outcome | Client gets | Forwarded |
|---|---|---|
| HTTP 200, `status: "ok"`, `decision: "ALLOW"` | the destination's response | **yes** |
| HTTP 200, `status: "ok"`, `decision: "BLOCK"` | `403` | no |
| HTTP 200, `status: "invalid"` | `503` | no |
| Any non-200 (`503` model not loaded, `500` inference failure, ...) | `503` | no |
| Timeout, connection refused, network error | `503` | no |
| Invalid JSON, missing or unknown `status`/`decision` | `503` | no |
| Unexpected error inside the addon | `503` | no |

The client never receives the model's reason; it is written to the proxy log. The internal
classifier client ignores `HTTP_PROXY`/`HTTPS_PROXY` (`trust_env=False`), so a shell configured
to use the gateway cannot route the classifier call back through it.

Two mitmproxy 12.2.3 behaviours were verified to **fail open** by default, and are handled:

- An exception raised inside an addon hook is logged and the request is **forwarded
  anyway**. The addon's `request` hook catches every exception and blocks.
- mitmdump **hot-reloads** a script when its file changes; if the new version fails to
  load, the proxy keeps running **without the addon**. When the addon is unloaded while
  the proxy is running, it switches mitmproxy's built-in `block_list` to block all
  traffic (`503`) until mitmdump is restarted. **Restart mitmdump after editing
  `data_plane.py`.**

If the addon or `config.yaml` fails to load at startup, mitmdump exits with code 1 (observed
about 1 ms after its port opens).

### Configuration

`config.yaml`, read when the addon loads:

```yaml
data_plane:
  classifier_url: http://127.0.0.1:8000/classify
  classifier_timeout_seconds: 3.0
```

The timeout is an **operational limit for detecting a failed or hung classifier** and
applying fail-closed. It is **not** the project's latency objective (Decision D36) and is not derived
from latency measurements. 3 s is a conservative initial value, to be tuned with end-to-end
evidence (Issue #18). See D35.

### Setup (once)

mitmproxy 12.2.3 pins `typing-extensions<=4.14` on Python 3.12, while the control plane's
pydantic 2.13.4 needs `>=4.14.1`. The data plane therefore gets its own environment, and
nothing is installed into the ML/control-plane interpreter (D33):

```bash
uv venv --python 3.12 --seed .venv-dataplane
.venv-dataplane/bin/python -m pip install -r requirements-data-plane.txt
```

### Running it locally (three terminals, from the repository root)

```bash
# 1 — control plane (ML environment)
python3.12 -m uvicorn --app-dir control_plane classifier_api:app --host 127.0.0.1 --port 8000

# 2 — a destination app to protect
mkdir -p /tmp/fw-demo && echo '<h1>destination reached</h1>' > /tmp/fw-demo/index.html
python3.12 -m http.server 9000 --bind 127.0.0.1 --directory /tmp/fw-demo

# 3 — gateway (data plane environment); wait for "data plane ready"
.venv-dataplane/bin/mitmdump -s data_plane/data_plane.py --listen-host 127.0.0.1 -p 8080
```

Clients use the gateway as an explicit HTTP proxy at `127.0.0.1:8080` (`curl -x`,
`http_proxy`, or a browser's manual HTTP proxy for plain `http://` sites). The proxy
terminal logs one line per request received and one per decision: method, host, path, and
the model's reason or the failure cause. The addon does not log query strings or bodies;
mitmdump's own per-flow line shows the shortened URL, and `--set flow_detail=0` hides it.

### Manual verification

Verified on 2026-09-16 with the real V4 model loaded. Terminal 2's log shows what actually
reached the destination.

**1 — ALLOW.** With the classifier running:

```bash
curl -i -x http://127.0.0.1:8080 http://localhost:9000/index.html
```

The model answers `ALLOW`, the proxy lets the request through, the client receives `200`,
and terminal 2 logs `GET /index.html`:
`client -> proxy -> classifier -> ALLOW -> destination`.

**2 — BLOCK.** A SQL injection request through the proxy:

```bash
curl -i -x http://127.0.0.1:8080 "http://localhost:9000/products?id=1%27%20OR%20%271%27%3D%271"
```

The classifier answers `BLOCK`, the proxy returns `403 Forbidden`, and terminal 2 logs
nothing: the block happens before the destination is contacted.

**3 — Fail-closed.** Stop the classifier completely (Ctrl+C in terminal 1) and repeat
request 1. The client receives `HTTP/1.1 503 Service Unavailable` with the body
`Request blocked by firewall-IA: classifier unavailable (fail-closed).`, and terminal 2
logs no new GET:

```
client -> proxy -> classifier unavailable
                -> 503
                X  destination
```

Two other failure paths were each exercised once during development: a classifier that
accepts connections but never answers (`503` after ~3 s), and a classifier running without
a loaded model (`FIREWALL_ADAPTER_DIR=/nonexistent`, `503`). Every failure path in the
table above is covered by the unit tests.

### Real client traffic: the `real-http-fp-v1` diagnostic

This is a **known limitation of the model/dataset** with traffic from real clients, **not**
a data plane defect. It is not worked around by rewriting headers or changing
`render_request()`. First observed with curl, 2026-09-16:

- `GET /index.html` with `Host: 127.0.0.1:9000` was BLOCK ("Server-side request forgery")
  on every repetition. The same request with `Host: localhost:9000` or a domain name was
  ALLOW. Sent directly to `/classify` with `Host: 127.0.0.1:9000`, `GET /` and
  `GET /products?id=42` were also BLOCK. Only a few `Host` variants were tried, so the
  role of `Host` is an **open finding still to be isolated experimentally**, not a
  demonstrated cause.
- `GET /` with `Host: localhost:9000` was BLOCK ("HTTP request smuggling"). The cause was
  not isolated.
- curl adds `Proxy-Connection: Keep-Alive` in proxy mode, a header that appears in 0 V4
  training rows. Removing it did not change the decision for the request tested, so it
  is **not** a confirmed cause, and its wider effect has not been evaluated.
- In the V4 splits, `127.0.0.1` never appears as a `Host` value, and elsewhere it appears
  only in BLOCK rows (58 train, 12 eval). IP-literal and port-bearing hosts
  (`10.20.30.40:8000`, `localhost:8080`) do appear, balanced across labels. This is
  consistent with the observation above but does not demonstrate a cause.

**2026-09-17: raw data lost — historical antecedent only.** A controlled one-variable A/B
experiment on these false positives was run against `/classify` directly and through the
proxy. Its raw records (texts sent, decisions, logs) were written under `/tmp` and were
lost at the next reboot. An audit summary survives outside the repository. It is **not** a
substitute for the raw data, its figures cannot be re-verified, and it is not cited as
evidence.

#### Repeated and persisted: `real-http-fp-v1` (2026-09-18)

That work was repeated correctly. The reproducible experiment —
pre-registered cases, every raw record, the four process logs, the code and the manifest —
is committed at
[`reports/diagnostics/real-http-fp-v1/`](../reports/diagnostics/real-http-fp-v1/); the
write-up is its
[`summary.md`](../reports/diagnostics/real-http-fp-v1/summary.md).

**Design.** 175 pre-registered cases over 149 unique HTTP texts, 3 repetitions per text —
447 direct calls to `/classify` — plus 26 curl commands × 3 = 78 requests through the
gateway.

| What it established | Result |
|---|---|
| Output validity | 0 invalid outputs in 447 direct calls |
| Determinism | 149/149 unique texts: same decision **and** same reason on all 3 repetitions |
| Proxy → `/classify` fidelity | 78/78 captured texts byte-identical to the pre-registered text |
| Proxy vs direct API | 78/78 same decision, 78/78 same reason |
| Gateway enforcement — ALLOW | 48/48 forwarded and reached the destination |
| Gateway enforcement — BLOCK | 30/30 returned `403` and did not reach the destination |
| Fail-closed | no `503` occurred during this run |

**Diagnostic finding.** 37 of the 149 constructed benign texts were classified BLOCK
(SSRF 25, file inclusion 4, HTTP parameter pollution 3, open redirect 3, request
smuggling 2).

> **37/149 is a diagnostic count, not a false-positive rate.** The case mix was built to
> provoke failures, so none of its proportions is a performance metric and none
> extrapolates to real traffic. The internal formal-split FPR is **0.06%** (2 of 3,103
> benign rows), see [V4 internal evaluation](../README.md#4-v4-internal-evaluation).
> *(updated at stage close)* External Test v1 later measured **68/200** on its own benign
> cases — a test-specific figure on a 50/50 constructed set, not an operational FPR either
> (see [External Test v1](../README.md#5-external-test-v1)).

**What the evidence supports.** Coverage gaps / out-of-distribution inputs, possible
spurious correlations (for example loopback Host → SSRF) and joint-feature context
sensitivity are all *compatible* with the observations. The experiment does **not**
demonstrate overfitting and does **not** establish causality for `Host`, path, port or
headers.

*(updated at stage close)* The demo no longer uses this local three-terminal setup; it
runs in the Docker Lab on the validated smoke fixtures — see
[`../docker/README.md`](../docker/README.md#demo).

### Shadow feature extraction (Hybrid Architecture Phase 1)

*(Added 2026-10-01, Issue #49, decisions D43, D44 and D45.)* The first stage of the proposed
**Hybrid Architecture** — feature extraction → lightweight request analyzer → small decision
model → V4 as fallback for uncertain cases → enforcement. "Hybrid Architecture" is not
"V5": V5 is the next model revision of D37 / D40 (D45). **Only the first stage exists**,
and it runs in **shadow mode**: it describes every request and nothing acts on the
description.

```
request ─► render_request() ─► D1 text ─► POST /classify ─► V4 verdict ─┬─► extract_features(same text) ─► "FEATURE EXTRACTION (shadow)" log line   (nothing reads it)
           └──────────── timed as "(classifier N ms)" ───────────┘      └─► ALLOW / BLOCK enforced, fail-closed   (unchanged)
```

**What it is.** `data_plane/request_features.py`, standard library only: a deterministic
function from the D1 text to a frozen `RequestFeatures` object. It works on the same string
V4 receives, rendered once per request, so a feature computed in the gateway and one
computed offline over a dataset are identical. It makes **no decision**: no ALLOW, BLOCK,
UNCERTAIN, score or threshold. The counts below are descriptions, not blocking rules.

**What it does not do yet.** No lightweight request analyzer, no small decision model, no
`UNCERTAIN`, no routing, no effect on V4, enforcement or fail-closed, no training, no
dataset change. `data_plane/hybrid_contracts.py` defines `AnalyzerOutput` (frozen in Phase
2A, D50: `signals` with a required `attack` probability, `P̂(BLOCK | features)` on V4-clean's
50 / 50 prior, and optionally all eight `category:<id>` probabilities given attack, summing to
1 — ids in `ANALYZER_CATEGORIES`, D47; no global confidence; `analyzer_version`),
`DecisionInput` (`features`, `analysis`) and `DecisionOutput` (`decision` ∈ ALLOW / BLOCK /
UNCERTAIN, rejected otherwise, never coerced; `confidence` in [0, 1]; `reason`). They are
contracts only: nothing produces or consumes them. The Analyzer's design (targets, dataset,
splits, metrics) is in
[`../reports/hybrid/phase2a-analyzer-design/`](../reports/hybrid/phase2a-analyzer-design/).

**Excluded (D44).** `Host` and `User-Agent` are never features, directly or indirectly. The
only header read is `Content-Type`. Character and syntax features are computed over the
**surface** = path + query + body (the `?` separator belongs to neither), never over
headers, and **on the text as received**: nothing is percent-decoded, so `%27` counts as an
encoded character, not as a quote.

**Features — schema `request-features/v2`:**

| Group | Feature | Type | Definition |
|---|---|---|---|
| request | `method` | str | first token of the request line |
| request | `path_length` | int | characters of the path (target before `?`) |
| request | `query_length` | int | characters after `?`; 0 without query |
| request | `body_length` | int | characters of the body (rendered text, not bytes) |
| request | `has_body` | bool | body is non-empty |
| request | `content_type` | str | media type of the first `Content-Type`, lowercase, parameters dropped; `""` if absent |
| request | `body_format` | str | `none` (no body) · `form` (`application/x-www-form-urlencoded`) · `json` (`application/json` or `+json`, parsed) · `json_invalid` (JSON type, unparseable or nested deeper than 1,000) · `other` (anything else; not parsed, not sniffed) |
| request | `query_param_count` | int | non-empty `&`-separated segments of the query |
| request | `body_param_count` | int | form: non-empty segments; JSON: object members at any depth, as written (a repeated key counts); otherwise 0 |
| request | `total_param_count` | int | query + body parameters |
| request | `repeated_param_name_count` | int | parameter names (raw, query + form body) occurring more than once |
| characters | `alnum_ratio` | float | ASCII letters and digits / surface length |
| characters | `symbol_count` | int | ASCII punctuation characters (the 32 of `string.punctuation`) — the "special characters" |
| characters | `symbol_ratio` | float | `symbol_count` / surface length — the symbol density |
| characters | `non_ascii_count` | int | characters above U+007F |
| characters | `percent_encoded_count` | int | valid `%XX` triplets, matched within path, query and body separately |
| characters | `percent_encoded_ratio` | float | 3 × `percent_encoded_count` / surface length |
| characters | `has_percent_encoding` | bool | `percent_encoded_count` > 0 |
| characters | `longest_char_run` | int | longest run of one repeated character, within path, query or body |
| characters | `entropy_bits_per_char` | float | Shannon entropy of the surface's character distribution |
| structure | `path_depth` | int | non-empty `/` segments of the path |
| structure | `json_depth` | int | maximum container nesting of a parsed JSON body; 0 otherwise |
| syntax | `single_quote_count` · `double_quote_count` · `semicolon_count` · `slash_count` · `backslash_count` · `pipe_count` · `ampersand_count` · `equals_count` · `percent_count` | int | occurrences of `'` `"` `;` `/` `\` `\|` `&` `=` `%` |
| syntax | `parenthesis_count` · `angle_bracket_count` · `brace_count` | int | occurrences of `(`+`)`, `<`+`>`, `{`+`}` |
| — | `schema_version` | str | `request-features/v2`; bumped whenever a feature is added or redefined (v1 was the pre-review definition, only in `reports/hybrid/phase1-feature-extraction-v1/`) |

Ratios are 0.0 on an empty surface. Missing parts count as empty: any string yields
features, never an exception (a non-string is a `TypeError`). The result depends only on
the text: JSON integers are not converted (the interpreter's int-digit limit cannot change
`body_format`), and nesting is capped at 1,000 because the depth at which Python's parser
gives up depends on the caller's stack (measured 9,897–9,997).

**Configuration.** `config.yaml`, read when the addon loads:

```yaml
data_plane:
  shadow_feature_extraction: true   # false, or absent: not run
```

Optional and a YAML boolean; any other value stops mitmdump at startup. The Docker Lab's
`docker/config.docker.yaml` does not set it, so the lab, the demo and the External v1
capture proxy run with it off. Restart mitmdump after changing it or after editing
`request_features.py` (a hot reload of `data_plane.py` does not reload that module).

**Failure policy.** An extractor exception is caught on its own and logged as
`FEATURE EXTRACTION (shadow) failed … <ExceptionType> at <file>:<line>; ignored`, without
the exception message (it could quote the request). The verdict already obtained from
the classifier is enforced unchanged. It is **never** a `403` or `503`: fail-closed still means "no valid
decision from the classifier" (D34), and an experimental component must not become a new
source of BLOCKs (D43).

**Observing it.** With the switch on, mitmdump prints at startup
`feature extraction: shadow (logged only, never used for decisions)` (or `off`), and per
request, after the classifier answered and before the decision line:

```
[13:22:07.867] [8e2068c3] received POST localhost:9000/products.html (body 30 bytes)
[13:22:08.151] [8e2068c3] FEATURE EXTRACTION (shadow) 0.081 ms request-features/v2 method=POST content_type='application/x-www-form-urlencoded' body_format=form len=14/0/30 params=0/1 repeated=0 pct_encoded=0 symbols=9 (0.205) non_ascii=0 entropy=4.298
[13:22:08.151] [8e2068c3] BLOCK POST localhost:9000/products.html reason='Server-side request forgery attack detected' (classifier 284 ms)
```

The flow tag ties them. The feature line is a summary — `len` is path/query/body
lengths, `params` query/body counts — with no path, no query values, no body and no Host or
User-Agent. Its `… ms` is the extractor call alone. Feature lines use the logger
`firewall.data_plane.features` and do not match the decision-line regexes of
`external_v1_run.py`, `summarize_latency_observations.py` or `docker/demo.sh` (tested). The
decision line is the model decision and keeps its exact format, and its
`(classifier N ms)` keeps its definition from before Phase 1 — `render_request()` plus the
`/classify` call — because the extractor runs after that timer (tested).

**Overhead** (measured 2026-10-01, `reports/hybrid/phase1-feature-extraction-v2/`). In
process, over the 6,206 V4 eval texts × 3 passes (n = 18,618): min 0.0101 · mean 0.0185 ·
P50 0.0169 · P95 0.0301 · max 0.1588 ms per request. Live in the gateway, n = 34: P50
0.052 · P95 0.125 · max 0.132 ms. The cost grows linearly with body size (1 KiB ≈ 0.05 ms,
10 KiB ≈ 0.47 ms, 100 KiB ≈ 4.7 ms, 1 MiB ≈ 53 ms, synthetic form bodies) and runs
synchronously on mitmproxy's event loop. Phase 1 deliberately adds no limit,
truncation or optimization for large bodies; it is a consideration for later phases.
Reproduce:

```bash
.venv-dataplane/bin/python scripts/benchmarks/benchmark_request_features.py
```

### Tests

```bash
# request feature extraction and Hybrid Architecture contracts (44 tests; standard library only, runs in either environment)
python3.12 -m unittest tests.test_request_features -v

# data plane (36 tests, including shadow mode; no model, no running services)
.venv-dataplane/bin/python -m unittest discover -s tests -p 'test_data_plane.py' -v

# everything else (ML environment); modules that need mitmproxy or Flask are reported
# as skipped and run in the data plane environment instead (see ../README.md#tests)
python3.12 -m unittest discover -s tests -v
```

### Scope of this first version

The following are outside this version's scope or not yet evaluated. They are not
implementation defects.

- Validated: plain HTTP/1.1 through an explicit proxy, locally and in the Docker Lab
- HTTPS/TLS: not validated
- HTTP/2: not validated
- WebSockets: not validated
- Large request bodies: not evaluated
- Concurrency: not characterized (the control plane serializes inference on one GPU, so
  simultaneous requests queue)
- End-to-end benchmark: pending (Issue #18)
- Model behaviour on real HTTP traffic: diagnosed in `real-http-fp-v1` (see above) and
  evaluated independently in External Test v1 *(updated at stage close;* see
  [`../README.md`](../README.md#5-external-test-v1)*)*
- Heuristics, suspicious score, fast path: not implemented (Issues #35–#38)
- Request feature extraction (Hybrid Architecture Phase 1): shadow mode only — logged,
  never used for a decision (see [Shadow feature extraction](#shadow-feature-extraction-hybrid-architecture-phase-1))

---

## Inference Benchmark (Issue #9)

`benchmark_inference.py` measures how long the V4 classifier takes to generate one
decision, under a fixed protocol, together with the full environment it ran in. The
reference experiment is **`baseline-local-v1`** — measured, frozen, and never overwritten.

**Scope: `generate()` only.** Prompt construction, tokenization, host→device transfer,
decoding and parsing are timed and reported separately and are never pooled into the
primary metric — together they contribute about 0.58 ms at P95. This is **not** API
latency and **not** gateway latency; end-to-end is Issue #18.

**Latency objective (Decision D36): P95 of the inference pipeline ≤ 200 ms in steady state — not
met.** The pipeline is prompt construction, tokenization, transfer, `generate()`, decoding
and parsing. Model load, cold start and warm-up are excluded from it and reported
separately; HTTP transport, network, the proxy and the destination are excluded. In `baseline-local-v1` the
steady-state pipeline P95 is **269.58 ms** (`generate()` alone: 269.01 ms). Decision D36 supersedes
D3, which stated the 200 ms figure as an end-to-end budget; reports produced before Decision D36 use
that older wording.

### `baseline-local-v1` — measured on 2026-09-09

3 independent runs × the full 6,206-row held-out split = **18,618 real classifications**,
on an RTX 4090 Laptop GPU, batch size 1, concurrency 1, model loaded once per process.

| | mean | P50 | **P95** | P99 | min | max | stdev |
|---|---:|---:|---:|---:|---:|---:|---:|
| steady state, pooled (ms) | 227.86 | 238.82 | **269.01** | 275.90 | 155.80 | 337.16 | 32.43 |
| steady state, full inference pipeline, pooled (ms) *(added at stage close, from `summary.json`)* | 228.33 | 239.26 | **269.58** | 276.54 | 156.19 | 338.52 | 32.43 |

Reported **separately**, never pooled into the above and never discarded:

| population | values |
|---|---|
| model load, per process | 2275.5 · 2251.6 · 2416.6 ms |
| first inference, per process (cold start) | 418.2 · 410.4 · 446.2 ms |
| warm-up, 4 per run | 159.5 – 271.2 ms |

Peak memory, PyTorch allocator, this process only: **935.5 MiB allocated / 1170.0 MiB
reserved**. 11.63 generated tokens on average; **0 of 18,618** generations hit the
40-token safety bound.

**Quality at that latency** — same E5 metrics, over the same requests: attack detection
**97.04%**, **2 false positives** and **92 false negatives** per run of 3,103 each,
**0 invalid outputs**, accuracy 98.49%. The three runs were bit-identical: 0 of 6,206 rows
differed in decision or in reason text.

> **Run-to-run variation is the finding that matters most.** P95 across the three runs was
> 244.03, 266.55 and 273.21 ms — a spread of **11.17%**. Pairing each row with itself
> across runs shows run 3 slower than run 1 in **99.5%** of 6,206 requests, with the GPU
> starting run 1 at 48 °C and run 3 at 72 °C. **A future candidate claiming a reduction
> smaller than ~11% on this machine has not demonstrated anything** unless run order and
> thermal state are controlled.

Full report: [`reports/v4_inference_benchmark.md`](../reports/v4_inference_benchmark.md).
Artifacts: [`reports/benchmarks/baseline-local-v1/`](../reports/benchmarks/baseline-local-v1/).

### Reproduce it, and compare a future run

```bash
python3.12 scripts/benchmarks/benchmark_inference.py self-test          # statistics only, no model
python3.12 scripts/benchmarks/benchmark_inference.py estimate --runs 3  # duration before committing to it
python3.12 scripts/benchmarks/benchmark_inference.py protocol --experiment <new-id> --runs 3
python3.12 scripts/benchmarks/benchmark_compare.py --baseline baseline-local-v1 --candidate <new-id>
```

`benchmark_compare.py` reports, per statistic,
`reduction = 100 × (baseline − candidate) / baseline` and the distinct speedup factor
`baseline / candidate`. It **refuses** to call two results comparable merely because both
are in milliseconds: timing scope, dataset hash, request count, selection, order,
protocol, batch size and concurrency must match, and a mismatch exits non-zero. A hardware
change demands re-running the base version on that hardware; simultaneous hardware and
software changes are reported as a joint effect; and a speed gain is never printed without
naming any quality degradation beside it. See D31 and D32.

### Historical antecedents — preserved, not comparable

The Issue #8 model-side P95 of **270.8 ms** and the Issue #15 preliminary observation
(first inference 512.8 ms, steady n=30 P50 232.5 ms) remain as measured, under their own
protocols. They are **not** `baseline-local-v1` results. Pointing the comparison tool at
the former produces `NOT COMPARABLE` with 6 blocking differences — the demonstration is
committed at
[`vs-historical-e5.md`](../reports/benchmarks/baseline-local-v1/vs-historical-e5.md).

---

## External Test v1 — latency observations (derived)

*(Added at stage close, 2026-09-22.)* **Observational only.** These are not a benchmark and
not end-to-end latency; the formal client-to-destination benchmark is Issue #18 and is
**pending**. Derived read-only from the committed records of `external-v1-run-001` — no case
was re-run:

```bash
python3.12 scripts/external/summarize_latency_observations.py          # add --json for the full result
```

Statistics use `scripts/benchmarks/benchmark_inference.summarize()`: nearest-rank
percentiles, no interpolation, no sample removed — the `baseline-local-v1` definition.
Pinned by `tests/test_latency_observations.py`.

**What each series measures** (read from the implementation):

| Series | Measured by | Scope |
|---|---|---|
| gateway `model_latency_ms` | `data_plane.py`: `perf_counter()` before and after `ask_classifier()`, logged as `(classifier N ms)` with `%.0f`, parsed by the runner from `raw/data-plane-phase-f.log` | the data plane's wall time for its `POST /classify` call — HTTP client setup, the request, all control-plane handling including the inference pipeline, the response. **Despite its name, not model-side time**; integer ms |
| direct `model_latency_ms` | the `/classify` response field, set by `inference_core.classify_raw()` | `generate()` only, device-synchronized (D31) — model-side |
| direct `wall_ms` | the runner's `perf_counter()` around its `POST /classify` | client-side HTTP round trip to the control plane |

**Cross-check.** The 1,200 gateway values in `results.jsonl` equal the 1,200 decision lines
of `raw/data-plane-phase-f.log`, value for value and in order. No observation is null.

| Series (ms) | n | min | mean | P50 | P95 | P99 | max | stdev |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **gateway `model_latency_ms`, all** | 1,200 | 163.00 | 213.50 | 220.00 | 255.00 | 268.00 | 570.00 | 33.69 |
| gateway, repetition 1 | 400 | 163.00 | 209.72 | 215.00 | 253.00 | 264.00 | 570.00 | 36.85 |
| gateway, repetition 2 | 400 | 168.00 | 215.64 | 226.00 | 257.00 | 274.00 | 287.00 | 32.06 |
| gateway, repetition 3 | 400 | 170.00 | 215.14 | 228.00 | 254.00 | 259.00 | 284.00 | 31.69 |
| gateway, decision ALLOW | 399 | 230.00 | 247.19 | 246.00 | 259.00 | 281.00 | 570.00 | 17.98 |
| gateway, decision BLOCK | 801 | 163.00 | 196.72 | 190.00 | 245.00 | 264.00 | 284.00 | 26.32 |
| **direct `model_latency_ms` (generate() only), all** | 300 | 157.38 | 201.33 | 193.10 | 247.89 | 258.13 | 264.18 | 31.51 |
| direct, repetition 1 | 100 | 159.28 | 200.62 | 187.70 | 245.63 | 254.61 | 255.34 | 31.95 |
| direct, repetition 2 | 100 | 157.38 | 200.31 | 195.85 | 249.89 | 258.41 | 264.18 | 32.30 |
| direct, repetition 3 | 100 | 160.92 | 203.08 | 192.67 | 240.62 | 252.51 | 258.16 | 30.48 |
| **direct `wall_ms`, all** | 300 | 159.36 | 203.49 | 195.02 | 250.19 | 260.37 | 267.03 | 31.62 |

Reading limits:

- The gateway series covers all 400 cases; the direct series covers the predeclared 100-case
  subset. Different populations and scopes — not a paired comparison, and the difference
  between them is not a measurement of proxy overhead.
- The per-decision split is descriptive; no cause is attributed to the difference.
- The single 570 ms maximum is retained, as every sample is; no warm-up or thermal control
  was applied during the run.
- None of these figures is comparable to `baseline-local-v1` (different protocol, scope and
  populations) or evaluates Decision D36.
- The raw gateway records also hold a client-side `elapsed_ms` per replayed request. It is
  **deliberately not summarized**: a sequential single-client replay that includes the lab
  app, with no warm-up or thermal control, is not the Issue #18 measurement.

---

## External Test v1 — secondary breakdowns (pre-registered)

*(Added at stage close, 2026-09-22.)* **SECONDARY, not headline.** The breakdowns by
`client_profile`, `host_type`, `method` and `body_type` pre-registered in protocol §4.3 /
§10, computed from the frozen case metadata and the committed run records with the frozen
D19 scorer and the runner's headline population (gateway channel, repetition 1). Full
tables, statuses and zero-error bounds:
[`../reports/external/external-v1-secondary-breakdowns/secondary_breakdowns.md`](../reports/external/external-v1-secondary-breakdowns/secondary_breakdowns.md)
(JSON beside it). `route_family` is pre-registered, not produced (the report explains why).
Regenerate or check: `python3.12 scripts/external/secondary_breakdowns.py`;
`tests/test_secondary_breakdowns.py` recomputes it against the committed report.

---

## Capture / replay fidelity — External v1 Phase B

*(Added at stage close, 2026-09-22.)* Verified before the Phase C DRAFT was built, with no
classifier in the path (protocol §4.2):

| Check | Result |
|---|---|
| `curl`: capture → raw-socket replay through the same capture proxy → capture; SHA-256 per request | **8 / 8 byte-exact** |
| Chromium / Playwright: predeclared subset, first 12 of 22 captured requests replayed (10 not replayed by design) | **12 / 12 byte-exact** |
| Offline: `render → to_wire() → mitmproxy parse → render_request()` is the identity across query encodings, repeated headers, cookies, form / JSON bodies, non-ASCII and payload-bearing requests | unit tests, `tests/test_external_capture.py` |

**Checker semantics** (`scripts/external/fidelity_check.py`, `tests/test_fidelity_check.py`):
requests are compared by SHA-256; with `--expect N`, exactly N must be selected on both sides
and all must match; a declared subset is reported as "not replayed by design", not as a
count mismatch; the originals are selected with `replay.py`'s own rule (`--only-host`
filter, then limit, in file order), so both sides compare the same requests.

**Evidence (committed at stage close):**
[`../reports/external/external-v1-phase-b-fidelity/`](../reports/external/external-v1-phase-b-fidelity/)
— the four original capture/replay files copied byte-for-byte from the machine-local,
gitignored `docker/.lab-logs/capture/` (no traffic regenerated, sources unmodified, SHA-256
verified identical, `SHA256SUMS`), plus the checker's output re-run on the copies. The
original result is also recorded in the message of commit `16da803`. Reproduce:

```bash
.venv-dataplane/bin/python scripts/external/fidelity_check.py --capture reports/external/external-v1-phase-b-fidelity/raw/capture.jsonl --split-after 8 --expect 8
```

```bash
.venv-dataplane/bin/python scripts/external/fidelity_check.py --capture reports/external/external-v1-phase-b-fidelity/raw/browser_smoke.jsonl --split-after 22 --expect 12
```

This establishes capture-proxy replay fidelity. It is supporting evidence only and is
**not** a capture of what the data plane sent to `/classify` during External v1 (see the
§11 status note in [`external_test_v1_protocol.md`](external_test_v1_protocol.md)).

---

## Dataset Integrity

The current dataset is `datasets/v4_clean/` — **25,134 train / 6,206 eval / 31,340 total**,
balanced at 15,670 ALLOW / 15,670 BLOCK.

### Dataset sources

Generated by `parse_dataset_v4.py` (seed 42). Counts are from
[`datasets/manifest_v4_clean.json`](../datasets/manifest_v4_clean.json) unless marked otherwise.

| Source | What V4 takes from it | Counts |
|---|---|---|
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings), commit `e961fef` | attack payloads from 16 category directories: fenced code blocks in `.md` files and lines of `.txt` files, quality-filtered | 39,396 candidates scanned, 33,517 accepted |
| Hardcoded payloads in `parse_dataset_v4.py` | CRLF, XPath, HTTP parameter pollution and request-smuggling payloads | 81 (XPath 31, CRLF 24, HPP 20, smuggling 6; the split is read from the generator source) |
| CSIC 2010 (`csic_database.csv`; local only, not distributed — [`data_sources.md`](data_sources.md)) | Normal records become ALLOW. Anomalous records become BLOCK only when an 11-rule keyword heuristic assigns a category (F6); the rest are reserved (D2) | 36,000 normal · 5,900 anomalous categorized · 19,165 anomalous reserved, not used |
| Synthetic benign generator (`parse_dataset_v4.py`) | parametrized benign requests in the same request shapes as the attacks (D13) | 19,785 logical groups |

**Every row is rendered by the generator.** Attack payloads are placed into synthetic
request shapes. CSIC records keep their method, path (with the `/tienda1` prefix removed),
query and body; their original headers are discarded, and the envelope (Host, User-Agent,
Cookie, Accept-*) is redrawn from the same pools used for every other source. CSIC rows are
therefore **derived from CSIC 2010 and re-rendered into the V4 HTTP representation**, not
requests as originally recorded.

After grouping and the D17 caps, the logical groups are: attack (PayloadsAllTheThings plus
hardcoded) 9,977, of which 8,037 train / 1,940 eval; CSIC 8,251, of which 6,577 / 1,674;
synthetic benign 19,785, of which 15,802 / 3,983. Attack groups also yield obfuscated
variants from the training transform pool (D15). Of the 15,670 BLOCK rows, **3,906 come
from CSIC** ([`reports/e2_e3_row_cap_sensitivity.txt`](../reports/e2_e3_row_cap_sensitivity.txt),
which reproduced this dataset bit-identically), so 11,764 come from PayloadsAllTheThings
and the hardcoded payloads. The split of the 15,670 ALLOW rows between CSIC and the
synthetic generator is not recorded in the manifest or the reports.

**Why the earlier dataset was rejected.** An audit found that the previous corpus leaked
its own labels: a classifier reading *only* the `Host` header — never the payload —
scored about 93.4–93.7%, higher than the ~91% then attributed to the model. Roughly
26.65% of the evaluation split also appeared verbatim in training. Any accuracy measured
under those conditions was uninterpretable, so the dataset was rebuilt rather than reused.

**Current state**, measured by the integrity gate:

- **0.00%** train→eval leakage
- **0.00%** duplicate rows within either split
- **0** deterministic label reveals
- **0** blocking failures
- Incidental metadata features sit at roughly the 50% majority baseline — the strongest
  reaches 51.16%, and `Host` itself now scores 49.73%
- The gate still returns **WARNING** for category scarcity, which is reported rather
  than papered over

Reports: [`reports/e0_dataset_integrity_v4_clean.txt`](../reports/e0_dataset_integrity_v4_clean.txt),
[`reports/e2_e3_clean_dataset.txt`](../reports/e2_e3_clean_dataset.txt).
Dataset identity is pinned in [`datasets/manifest_v4_clean.json`](../datasets/manifest_v4_clean.json).

---

## Known Limitations

- **False negatives are concentrated.** 91 of 92 missed attacks (~98.9%) fall in two
  categories: SQL injection (74) and command injection (17). Their binary recall is
  90.94% (743/817) and 87.31% (117/134) respectively.
- **Ten categories are flagged INSUFFICIENT DATA** and their per-category numbers are
  exploratory only — several rest on fewer than 20 held-out examples.
- **HTTP request smuggling is NOT EVALUABLE** — it has zero held-out examples, so no
  claim about it can be made.
- **The evaluation split also drove best-checkpoint selection.** In V4, `eval.jsonl` was
  used both for validation (it selected `checkpoint-2200` on `eval_loss`) and for the
  internal evaluation reported above. It is held out from training but is **not** an
  independent test set (D24). From V5 on, TRAIN, VALIDATION, INTERNAL TEST and EXTERNAL
  TEST are separate sets (D37); see
  [`docs/ml_evaluation_methodology.md`](ml_evaluation_methodology.md).
- **The Docker Lab's checks are plumbing, not evaluation.** ALLOW/BLOCK/fail-closed are
  verified to work in containers, on three hand-written requests. That says nothing about
  the model's behaviour on real or unseen traffic, and no metric may be derived from it.
  The same applies to `docker/demo.sh`, which reuses those fixtures.
- **External generalization gap on benign traffic** *(updated at stage close — replaces
  "No external evaluation exists")*. External Test v1 (400 frozen cases, captured from
  real clients in the lab before V4 exposure) measured BLOCK recall 199/200 but **68/200
  false positives on its benign cases**, concentrated in `api-json` (21/40) and
  `unseen-structure` (24/40). That 34% is specific to this 50/50 constructed test, not an
  operational FPR; it does not prove overfitting and is not formal OOD detection. See
  [`../README.md`](../README.md#5-external-test-v1).
- **External v1 is one application in one lab, five of nineteen attack categories,**
  plain HTTP/1.1, sequential execution, and no evasion suite — the limits pre-registered
  in [`external_test_v1_protocol.md`](external_test_v1_protocol.md) §13.
- **No adversarial held-out evaluation has been performed.** Evasion resistance is
  unmeasured by design.
- **The latency objective is not met.** Decision D36 sets P95 of the inference pipeline ≤ 200 ms
  in steady state; `baseline-local-v1` measures 269.58 ms (270.8 ms historically,
  `generate()` only). It is an **optimization objective**, not an acceptance criterion for
  the current gateway (D35), and it is why inference optimization is prioritized (M2,
  D23). End-to-end latency is a different quantity with no threshold, and no formal
  end-to-end benchmark exists yet (Issue #18).
- **No quantized comparison exists yet** — GGUF/Q4_K_M is unbuilt.
- **No physical embedded validation exists yet.**
- **CSIC BLOCK labels come from a keyword heuristic**, so the CSIC-derived portion of
  per-category results inherits that circularity.
- **The data plane is a first version, validated locally with plain HTTP/1.1 only.**
  HTTPS, HTTP/2, WebSockets, large bodies and concurrency are not yet validated. See
  [Scope of this first version](#scope-of-this-first-version).
- **The classifier timeout is operational.** 3 s is an initial limit for detecting a
  failed classifier and applying fail-closed. It is not the latency objective, and it
  will be tuned with end-to-end evidence (D35).
- **The model produced false positives on constructed benign HTTP requests.** Measured
  reproducibly in `real-http-fp-v1`: 37 of 149 constructed benign texts were BLOCK. That
  is a **diagnostic count on a mix built to provoke failures, not a false-positive rate**.
  See [Real client traffic](#real-client-traffic-the-real-http-fp-v1-diagnostic).
- **Concurrency is serialized but unvalidated.** One GPU, one inference at a time;
  behaviour under simultaneous load has not been measured.
- **Cold-start latency is materially higher than steady state**, and the two must never
  be pooled — measured at 1.75× the steady P50, see [Inference Benchmark](#inference-benchmark-issue-9).
- **Latency varies by ~11% between back-to-back runs on this machine**, driven by run
  order and GPU thermal state. Any future improvement claim smaller than that is not
  distinguishable from run-order variation without controlling for it.
- **The benchmark is single-request**: batch size 1, concurrency 1, one process. It says
  nothing about behaviour under concurrent load.
- **The baseline exists for one machine only.** No embedded or alternative-hardware
  baseline has been measured, and cross-hardware comparison requires re-running the base
  version on the new hardware (D32).

---

## Roadmap

| Milestone | Scope |
|---|---|
| **M1 — V4 Clean Baseline** | Dataset integrity through the first interpretable baseline |
| **M2 — Quantized Deployment** | LoRA merge, GGUF, Q4_K_M, llama.cpp, quantized regression |
| **M3 — Inline Gateway** | FastAPI + mitmproxy, fail-closed enforcement, end-to-end latency |
| **M4 — Embedded Deployment** | Requirements, platform selection, deployment, benchmarking |
| **M5 — Research / Project Results** | Architecture, results, limitations, reproducibility |

**M1 — completed**

- E0 dataset integrity gate
- E1 QLoRA pipeline compatibility
- E2/E3 envelope neutralization and leakage-free grouped split
- E4 native EOS cleanup
- E5 frozen evaluation methodology
- Issue #7 — V4 clean baseline training

**Also complete since the V4 baseline** *(updated at stage close)*

- Issue #8 — V4 clean security evaluation, metrics in `reports/v4_clean_eval.json`
- Issue #9 — controlled inference benchmark, `baseline-local-v1` frozen in `reports/benchmarks/`
- Real-HTTP diagnostic `real-http-fp-v1`, persisted in `reports/diagnostics/`
- Repository organized by responsibility (structural only)
- Docker Lab, runtime verified, closure report in `reports/lab/docker-lab-v1/`
- External Test v1 — frozen at `36df2ee`, executed as `external-v1-run-001`
- Docker demo (`docker/demo.sh`), runtime verified from a clean state

The current ordered plan after the first-stage release is kept in one place:
[`../CONTEXT.md`](../CONTEXT.md) ("Current checkpoint") and
[`../README.md`](../README.md#next-steps).

**M3 — partially started ahead of M2 (D26)**

- Issue #15 — FastAPI control plane: **complete**
- Issue #16 — mitmproxy inline data plane: **first version implemented**, verified locally and in the Docker Lab
- Issue #17 — fail-closed enforcement: **first version implemented**, verified locally and in the Docker Lab; timeout to be tuned
- Gateway enforcement and proxy/API consistency: **validated** in `real-http-fp-v1` (78/78)
  and in External Test v1 (L2 1,200/1,200 conformant; direct-vs-gateway decision agreement
  100/100 on the predeclared subset — decision consistency, not byte-equivalence evidence;
  External v1 did not run the proxy-to-`/classify` byte check, see
  [`external_test_v1_protocol.md`](external_test_v1_protocol.md))
- Issue #18 — end-to-end gateway latency (no-fast-path baseline): not started

Latency-reduction layer — **designed, not built** (D29, D30):

- Issue #35 — heuristic suspicious scoring: not started
- Issue #36 — benign fast-path ALLOW: not started
- Issue #37 — asynchronous model validation of fast-path traffic: not started
- Issue #38 — fast-path calibration and benchmark: not started

The fast path is an **allow-only** optimization: traffic scored clearly benign skips
synchronous inference, everything else still goes to the model, and there is **no
heuristic fast BLOCK** (D29). Fast-path traffic is re-classified afterwards, off the
critical path, so heuristic false ALLOWs are measured rather than invisible — this is
evidence collection, **not** online learning, and the model is never updated
automatically (D30).

The control plane was built on the current HuggingFace/PEFT backend to establish a
functional, integrable baseline. That does **not** make HF/PEFT the deployment backend —
D23 still holds, and GGUF/llama.cpp remains on the critical path.

---

## Repository Workflow

```
main                     stable checkpoints
└── develop              active integration branch
    ├── feature/<issue>-<slug>
    ├── fix/<issue>-<slug>
    ├── test/<issue>-<slug>
    ├── perf/<issue>-<slug>
    └── docs/<issue>-<slug>
```

Flow: **Issue → branch from `develop` → Conventional Commits → PR → `develop`**.
Temporary branches are deleted after merge.

Commit format is `type(scope): description` — types `feat` `fix` `perf` `refactor`
`test` `docs` `chore` `ci`; scopes include `dataset` `training` `evaluation` `inference`
`api` `proxy` `deployment` `embedded` `research` `docs`.
