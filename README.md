# firewall-IA

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python&logoColor=white)
![Model](https://img.shields.io/badge/Model-TinyLlama--1.1B-orange?logo=huggingface&logoColor=white)
![Fine-tuning](https://img.shields.io/badge/Fine--tuning-QLoRA%204--bit-green)
![Status](https://img.shields.io/badge/Status-V4%20clean%20baseline-brightgreen)
![Dataset gate](https://img.shields.io/badge/E0%20gate-no%20blocking%20failures-brightgreen)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

## Overview

**firewall-IA is an AI-powered application-layer HTTP security gateway.**

It classifies individual HTTP requests with a fine-tuned TinyLlama-1.1B-Chat model
(QLoRA, 4-bit) and returns a decision under a strict contract:

```
ALLOW | <reason>
BLOCK | <reason>
```

This is a **pre-thesis research project**, not a product. The classifier is
**stateless at the application-request level** — each request is judged independently,
with no session or behavioural context — and it is **not** a replacement for a
conventional stateful network firewall.

The long-term objective is an inline HTTP gateway with optimized inference, deployed on
embedded Linux hardware and validated against real traffic in an authorized laboratory.

---

## Current Architecture

```
HTTP Client
    |
    v
Data Plane — inline gateway ..........  FIRST VERSION (mitmproxy addon, data_plane.py)
    |                                                   enforces ALLOW/BLOCK, fail-closed
    v
Control Plane — POST /classify .......  IMPLEMENTED   (FastAPI, classifier_api.py)
    |
    v
inference_core — V4 pipeline .........  IMPLEMENTED   (TinyLlama + model-output-v4-clean)
    |
    v
status=ok -> ALLOW | BLOCK           .  IMPLEMENTED   (enforced by the data plane;
status=invalid -> no decision                          invalid/error/timeout -> BLOCK)
```

**Implemented today**

- Dataset generation, integrity gating and the frozen V4-clean dataset
- QLoRA fine-tuning pipeline (transformers 5.8 / TRL 1.4)
- The trained V4-clean classifier adapter (`model-output-v4-clean/`)
- Frozen evaluation methodology and harness
- `inference_core.py` — the single owner of the V4 inference pipeline, imported by both
  the evaluation harness (`test_model.py`) and the control plane (`classifier_api.py`)
- **FastAPI control plane (`classifier_api.py`)** — implemented and executed against the
  real V4 model. `GET /health` and `POST /classify` verified end to end. It classifies
  and reports; it does not enforce anything. See [Control Plane](#control-plane-issue-15).
- **Controlled model-side inference benchmark (`benchmark_inference.py`)** — executed on
  the real GPU against the real adapter. The reproducible reference `baseline-local-v1`
  is frozen in `reports/benchmarks/`. See [Inference Benchmark](#inference-benchmark-issue-9).
- **Data plane, first version (`data_plane.py`)** — mitmproxy addon that sends every HTTP
  request to `POST /classify` and enforces the answer, fail-closed. Executed locally
  against the real V4 model. See [Data Plane](#data-plane-issues-16-17--first-version).
- **Real-HTTP diagnostic validation (`real-http-fp-v1`)** — a reproducible experiment,
  persisted with all of its raw data in
  [`reports/diagnostics/real-http-fp-v1/`](reports/diagnostics/real-http-fp-v1/). It
  validated proxy / direct-API consistency and gateway enforcement, and it recorded the
  model's behaviour on constructed benign requests. See
  [Real client traffic](#real-client-traffic-the-real-http-fp-v1-diagnostic).
- **Repository organized by responsibility** — control plane, data plane and scripts split
  into their own directories. See [Repository layout](#repository-layout).

- **Docker Lab (`compose.yaml`, `docker/`)** — the whole system in containers: control
  plane on CUDA, data plane, a destination origin and a one-shot smoke client. Built and
  **runtime verified**: GPU passthrough works, V4 loads from a read-only mounted adapter,
  and ALLOW / BLOCK / fail-closed / recovery all pass as infrastructure checks. See
  [Docker Lab](#docker-lab).

**Planned, not built**

- **External Test v1** — an independent, frozen external evaluation set, and the full
  external security and gateway-enforcement evaluation run through it. **This is the next
  work.**
- Classifier timeout tuned with end-to-end evidence (today: a conservative operational 3 s)
- HTTPS / HTTP/2 / WebSocket interception validation (the first data plane targets plain HTTP/1.1)
- GGUF export, Q4_K_M quantization, llama.cpp inference
- End-to-end gateway latency measurement
- Fast path, suspicious score, asynchronous classification (Issues #35–#38 — designed, not built)
- Concurrency / load validation (the inference benchmark is deliberately concurrency 1)
- Embedded Linux deployment

Nothing in the "planned" list should be read as working today. In particular, **no external
evaluation results exist** — the external test set has not been built.

### Repository layout

```
control_plane/     classifier_api.py, inference_core.py     FastAPI + the V4 pipeline
data_plane/        data_plane.py                            mitmproxy inline gateway
scripts/dataset/   parse_dataset.py, parse_dataset_v4.py, check_dataset.py
scripts/training/  finetune.py
scripts/evaluation/test_model.py
scripts/benchmarks/benchmark_inference.py, benchmark_env.py, benchmark_compare.py
tests/             unit tests for all of the above
docs/              ml_evaluation_methodology.md
datasets/          v4_clean/ and its manifest
reports/           frozen experiment records (benchmarks/, diagnostics/, ...)

compose.yaml       Docker Lab stack
docker/            Docker Lab: per-service images, config override, smoke harness
.dockerignore      allowlist; keeps model/datasets/reports/.git out of build contexts
```

Run everything from the repository root. `config.yaml`, `csic_database.csv` and the
historical `train.jsonl`/`eval.jsonl` stay at the root. The 2026-09-20 reorganization was
**structural only**: no behaviour, dataset or model changed, and the model and dataset
hashes are unchanged.

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
uses. It covers `generate()` alone, so it is not the D36 latency objective's instrument,
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
applying fail-closed. It is **not** the project's latency objective (D36) and is not derived
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
[`reports/diagnostics/real-http-fp-v1/`](reports/diagnostics/real-http-fp-v1/); the
write-up is its
[`summary.md`](reports/diagnostics/real-http-fp-v1/summary.md).

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
> extrapolates to real traffic. The model's measured FPR is the formal-split **0.06%**
> (2 of 3,103 benign rows), see
> [V4-clean Baseline Results](#v4-clean-baseline-results).

**What the evidence supports.** Coverage gaps / out-of-distribution inputs, possible
spurious correlations (for example loopback Host → SSRF) and joint-feature context
sensitivity are all *compatible* with the observations. The experiment does **not**
demonstrate overfitting and does **not** establish causality for `Host`, path, port or
headers.

For the demo, use `localhost` in destination URLs.

### Tests

```bash
# data plane (21 tests; no model, no running services)
.venv-dataplane/bin/python -m unittest discover -s tests -p 'test_data_plane.py' -v

# everything else (ML environment); the data plane module is reported as skipped
python3.12 -m unittest discover -s tests -v
```

### Scope of this first version

The following are outside this version's scope or not yet evaluated. They are not
implementation defects.

- Validated: plain HTTP/1.1 through an explicit proxy, locally
- HTTPS/TLS: not validated
- HTTP/2: not validated
- WebSockets: not validated
- Large request bodies: not evaluated
- Concurrency: not characterized (the control plane serializes inference on one GPU, so
  simultaneous requests queue)
- End-to-end benchmark: pending (Issue #18)
- Model behaviour on real HTTP traffic: diagnosed in `real-http-fp-v1` (see above); an
  independent external evaluation is still pending (D22)
- Heuristics, suspicious score, fast path: not implemented (Issues #35–#38)

---

## Docker Lab

A compose stack that runs the **existing** system end to end in containers, so
**External Test v1** can later be executed in a reproducible environment:

```
client ──▶ data-plane (mitmproxy) ──▶ POST /classify ──▶ control-plane (FastAPI)
                                                              │
                                                       inference_core
                                                              │
                                                       TinyLlama + V4
                                                              │
                     ALLOW / BLOCK ◀───────────────────────────
                          │
              enforcement in the data plane
                          │
                    destination app
```

It is **infrastructure**. No model, dataset, prompt, parser, generation parameter,
request representation (D1), enforcement rule (D4/D34) or evaluation methodology
changed, and **no production code was modified**: the data plane's Docker configuration
is bind-mounted over `config.yaml` rather than added as an override inside
`data_plane.py`, so the local workflow above keeps working unchanged.

**Requires a GPU.** The control plane runs V4 on CUDA, so the host needs an NVIDIA driver
**and the NVIDIA Container Toolkit**. Without the toolkit the control-plane container
fails to start rather than falling back to CPU — a CPU run is a *different execution
environment* from the measured CUDA baseline and must never be reported as comparable.
The **V4 adapter is bind-mounted read-only** from `model-output-v4-clean/` and is never
copied into an image, as is the HuggingFace cache holding the TinyLlama base.

| Service | Base | Role |
|---|---|---|
| `control-plane` | `ubuntu:24.04` + Python 3.12 + torch 2.6.0+cu124 + `requirements.txt` | FastAPI → `inference_core` → TinyLlama + V4. The only service that loads the model or needs the GPU. |
| `data-plane` | `python:3.12-slim` + `requirements-data-plane.txt` | mitmdump running the unchanged `data_plane.py`. Never loads the model. |
| `destination` | `python:3.12-slim`, stdlib only | The protected origin. Appends every request it receives to a JSONL receipt log, which is how a BLOCK is proved *not* to have arrived. |
| `client` | `python:3.12-slim`, stdlib only | One-shot smoke client, behind a compose profile. |

Two images, not one, because mitmproxy's `typing-extensions<=4.14` pin still conflicts
with the control plane's pydantic `>=4.14.1` (D33). Two processes, not one, because the
HTTP boundary between the planes is deliberate. The V4 adapter is **bind-mounted
read-only, never copied into an image**.

### Build and run

```bash
docker compose build
docker compose up -d control-plane data-plane destination
./docker/smoke_test.sh
```

Each run tees to `docker/.lab-logs/smoke-<timestamp>.log` together with the three
services' logs. Full detail — prerequisites, network map, manual phases and every design
choice — is in [`docker/README.md`](docker/README.md).

### What the smoke test validates

Runtime verified on 2026-09-21 (`smoke-20260921T011153Z`, `all infrastructure smoke
checks passed`):

| Check | Result |
|---|---|
| **A** startup / readiness — `/health` reports `model_loaded: true` | **PASS** |
| GPU passthrough; V4 loads on CUDA from the mounted adapter | **PASS** |
| **B** ALLOW → HTTP 200, destination **receives** the request | **PASS** |
| **C** BLOCK → HTTP 403, destination receives **0** requests | **PASS** |
| **D** fail-closed: classifier stopped → HTTP 503, destination receives **0** | **PASS** |
| **E** recovery — control plane healthy again, ALLOW works | **PASS** |

Receipt evidence comes from the destination's own JSONL access log, so "the request did
not arrive" is a recorded fact rather than an absence of console output. Closure report:
[`reports/lab/docker-lab-v1/`](reports/lab/docker-lab-v1/).

### What it does NOT validate

> **Infrastructure plumbing only.** Three hand-written requests. **Not** External Test v1,
> **not** an evaluation, **not** a benchmark, **not** a diagnostic. No accuracy,
> precision, recall, FPR, FNR, latency or throughput figure may be derived from them; the
> `model_latency_ms` values in the run log are incidental service logging, not a
> measurement. The smoke fixtures are infrastructure fixtures and stay separate from any
> future external evaluation set (D37).

Also out of scope and unvalidated by this run: HTTPS/TLS, HTTP/2, WebSockets, transparent
proxying, large bodies, concurrency and load, and end-to-end latency (Issue #18).

> **The repository does not distribute the model.** `model-output-v4-clean/` is gitignored
> and is never copied into an image, and the TinyLlama base snapshot is mounted read-only
> from the host HuggingFace cache. The lab reproduces the **environment**, not the model
> artifact: both must already exist locally.

---

## Inference Benchmark (Issue #9)

`benchmark_inference.py` measures how long the V4 classifier takes to generate one
decision, under a fixed protocol, together with the full environment it ran in. The
reference experiment is **`baseline-local-v1`** — measured, frozen, and never overwritten.

**Scope: `generate()` only.** Prompt construction, tokenization, host→device transfer,
decoding and parsing are timed and reported separately and are never pooled into the
primary metric — together they contribute about 0.58 ms at P95. This is **not** API
latency and **not** gateway latency; end-to-end is Issue #18.

**Latency objective (D36): P95 of the inference pipeline ≤ 200 ms in steady state — not
met.** The pipeline is prompt construction, tokenization, transfer, `generate()`, decoding
and parsing. Model load, cold start and warm-up are excluded from it and reported
separately; HTTP transport, network, the proxy and the destination are excluded. In `baseline-local-v1` the
steady-state pipeline P95 is **269.58 ms** (`generate()` alone: 269.01 ms). D36 supersedes
D3, which stated the 200 ms figure as an end-to-end budget; reports produced before D36 use
that older wording.

### `baseline-local-v1` — measured on 2026-09-09

3 independent runs × the full 6,206-row held-out split = **18,618 real classifications**,
on an RTX 4090 Laptop GPU, batch size 1, concurrency 1, model loaded once per process.

| | mean | P50 | **P95** | P99 | min | max | stdev |
|---|---:|---:|---:|---:|---:|---:|---:|
| steady state, pooled (ms) | 227.86 | 238.82 | **269.01** | 275.90 | 155.80 | 337.16 | 32.43 |

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

Full report: [`reports/v4_inference_benchmark.md`](reports/v4_inference_benchmark.md).
Artifacts: [`reports/benchmarks/baseline-local-v1/`](reports/benchmarks/baseline-local-v1/).

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
[`vs-historical-e5.md`](reports/benchmarks/baseline-local-v1/vs-historical-e5.md).

---

## Current Research Status

| Stage | Status |
|---|---|
| Dataset integrity gate (E0) | Complete |
| V4-clean dataset (E2/E3) | Complete |
| QLoRA compatibility (E1) | Complete |
| Native EOS cleanup (E4) | Complete |
| Evaluation methodology (E5) | Complete |
| V4 clean training (Issue #7) | Complete |
| V4 security evaluation (Issue #8) | Complete |
| FastAPI control plane (Issue #15) | Complete |
| Controlled inference benchmark (Issue #9) | Complete |
| Inline data plane (Issue #16) | First version implemented, verified locally |
| Fail-closed enforcement (Issue #17) | First version implemented, verified locally; timeout to be tuned |
| Inline HTTP gateway (plain HTTP/1.1, validated locally) | First version implemented |
| ML evaluation methodology (D36, D37) | Complete |
| Real-HTTP diagnostic `real-http-fp-v1` | Complete — reproducible and persisted |
| Repository organized by responsibility | Complete |
| **Docker Lab** | **Complete — runtime verified** (checks A–E pass; GPU passthrough and CUDA model load confirmed) |
| **External Test v1** | **Next** — not started; the set does not exist yet |
| **Full external evaluation through the complete gateway** | Not started — depends on the two above |
| **Professor demo** | Not started |
| **README / results / standards alignment / future work** | Not started |
| End-to-end gateway latency (Issue #18) | Not started — after the sequence above |
| Heuristic suspicious scoring (Issue #35) | Planned |
| Benign fast path (Issue #36) | Planned |
| Async fast-path validation (Issue #37) | Planned |
| Failure analysis of the 92 false negatives | Not yet tracked by a dedicated issue |
| GGUF / Q4_K_M | Planned |
| llama.cpp inference | Planned |
| Embedded deployment | Planned |

---

## V4-clean Baseline Results

First scientifically interpretable baseline. Measured on the held-out
evaluation split: **6,206 rows (3,103 ALLOW / 3,103 BLOCK)**.

| Metric | Value |
|---|---|
| Accuracy | 98.49% |
| Attack recall (BLOCK) | 97.04% |
| Precision (BLOCK) | 99.93% |
| F1 (BLOCK) | 98.46% |
| False positive rate | 0.06% (2 / 3,103 benign) |
| False negative rate | 2.96% (92 / 3,103 attacks) |
| Invalid output rate | 0.00% (0 / 6,206) |
| Model-side P95 latency | 270.8 ms |

Confusion matrix — TP 3,011 · FN 92 · FP 2 · TN 3,101.

> **Read these numbers with their limits.** This is a single training run on a single
> seed, evaluated on synthetic requests plus requests derived from CSIC 2010 (see
> [Dataset sources](#dataset-sources)). It is **not** evidence of
> evasion resistance, **not** end-to-end gateway performance, and **not** a measurement
> on real production traffic. Per-category results are **not** equally reliable: one
> category is unevaluable and ten are flagged insufficient-data. The latency figure is
> model-side only. See [Known Limitations](#known-limitations).

Full detail: [`reports/v4_clean_baseline_results.txt`](reports/v4_clean_baseline_results.txt).

---

## Dataset Integrity

The current dataset is `datasets/v4_clean/` — **25,134 train / 6,206 eval / 31,340 total**,
balanced at 15,670 ALLOW / 15,670 BLOCK.

### Dataset sources

Generated by `parse_dataset_v4.py` (seed 42). Counts are from
[`datasets/manifest_v4_clean.json`](datasets/manifest_v4_clean.json) unless marked otherwise.

| Source | What V4 takes from it | Counts |
|---|---|---|
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings), commit `e961fef` | attack payloads from 16 category directories: fenced code blocks in `.md` files and lines of `.txt` files, quality-filtered | 39,396 candidates scanned, 33,517 accepted |
| Hardcoded payloads in `parse_dataset_v4.py` | CRLF, XPath, HTTP parameter pollution and request-smuggling payloads | 81 (XPath 31, CRLF 24, HPP 20, smuggling 6; the split is read from the generator source) |
| CSIC 2010 (`csic_database.csv`) | Normal records become ALLOW. Anomalous records become BLOCK only when an 11-rule keyword heuristic assigns a category (F6); the rest are reserved (D2) | 36,000 normal · 5,900 anomalous categorized · 19,165 anomalous reserved, not used |
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
from CSIC** ([`reports/e2_e3_row_cap_sensitivity.txt`](reports/e2_e3_row_cap_sensitivity.txt),
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

Reports: [`reports/e0_dataset_integrity_v4_clean.txt`](reports/e0_dataset_integrity_v4_clean.txt),
[`reports/e2_e3_clean_dataset.txt`](reports/e2_e3_clean_dataset.txt).
Dataset identity is pinned in [`datasets/manifest_v4_clean.json`](datasets/manifest_v4_clean.json).

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
  [`docs/ml_evaluation_methodology.md`](docs/ml_evaluation_methodology.md).
- **The Docker Lab's checks are plumbing, not evaluation.** ALLOW/BLOCK/fail-closed are
  verified to work in containers, on three hand-written requests. That says nothing about
  the model's behaviour on real or unseen traffic, and no metric may be derived from it.
- **No external evaluation exists.** The external test set (External Test v1) has not been
  built, so there is no measurement of V4 outside its own internal distribution and no
  result from running the complete gateway against an independent set (D22, D37).
- **Captured real laboratory traffic has not been validated yet.** `real-http-fp-v1` used
  benign texts built by hand from real clients' header sets, not captured user traffic.
- **No adversarial held-out evaluation has been performed.** Evasion resistance is
  unmeasured by design.
- **The latency objective is not met.** D36 sets P95 of the inference pipeline ≤ 200 ms
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

**Also complete since the V4 baseline**

- Issue #8 — V4 clean security evaluation: **complete**, metrics archived in
  `reports/v4_clean_eval.json`
- Issue #9 — controlled inference benchmark: **complete**, `baseline-local-v1` frozen in
  `reports/benchmarks/`
- Real-HTTP diagnostic: **complete**, `real-http-fp-v1` persisted in `reports/diagnostics/`
- Repository organized by responsibility: **complete**, structural only
- Docker Lab: **complete and runtime verified**, closure report in `reports/lab/docker-lab-v1/`

**Next work — in this order, and not reordered**

1. **External Test v1** — an independent, frozen external evaluation set. It does not exist
   yet. When built it is independent of the V4 dataset, frozen before V4 is evaluated on
   it, and ships with ground truth, categories, slices, a manifest and hashes. It measures
   TP/TN/FP/FN, accuracy, BLOCK precision, recall / attack detection rate, F1, FPR, FNR,
   invalid outputs and per-category / per-slice metrics, and it verifies gateway
   enforcement as well as classification. Its main execution runs through the complete
   system; direct `/classify` calls are auxiliary per-layer consistency controls only. It
   is not designed around the known failures of `real-http-fp-v1`, and if its individual
   errors later guide V5 it stops being an independent test for V5 (D37).
2. **Full external security and gateway-enforcement evaluation** — executed in the Docker
   Lab: client → data plane → control plane → V4 → data plane → destination
3. **Professor demo** — ALLOW, BLOCK and fail-closed shown live on a small demo subset,
   with the external-test results presented already computed
4. **README / results / standards alignment / future work**

**Deferred until after that sequence**

- Issue #18 — end-to-end gateway latency
- Failure analysis of the 92 false negatives (D21) — outstanding work, not currently
  tracked by a dedicated issue
- Decision gate: a targeted V4.1 only if the evidence requires it, otherwise proceed to M2

**M3 — partially started ahead of M2 (D26)**

- Issue #15 — FastAPI control plane: **complete**
- Issue #16 — mitmproxy inline data plane: **first version implemented**, verified locally
- Issue #17 — fail-closed enforcement: **first version implemented**, verified locally; timeout to be tuned
- Gateway enforcement and proxy/API consistency: **validated** in `real-http-fp-v1`
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

---

## Reproducibility / Reports

| Path | Contents |
|---|---|
| [`reports/`](reports/) | Every experiment record — E0 through the V4 baseline |
| [`reports/benchmarks/`](reports/benchmarks/) | Inference benchmark experiments; `baseline-local-v1` is the frozen reference |
| [`reports/diagnostics/real-http-fp-v1/`](reports/diagnostics/real-http-fp-v1/) | Real-HTTP diagnostic: pre-registered cases, raw records, process logs, code and manifest |
| [`reports/lab/docker-lab-v1/`](reports/lab/docker-lab-v1/) | Docker Lab closure report: architecture, prerequisites, smoke results A–E, defects found and fixed |
| [`reports/v4_inference_benchmark.md`](reports/v4_inference_benchmark.md) | Issue #9 benchmark report — protocol, environment, results |
| [`datasets/manifest_v4_clean.json`](datasets/manifest_v4_clean.json) | Dataset identity: hashes, seed, source commit, generation policy |
| [`CONTEXT.md`](CONTEXT.md) | Current technical state and immediate roadmap |
| [`DECISIONS.md`](DECISIONS.md) | Project decision log (D1–D37) |
| [`docs/ml_evaluation_methodology.md`](docs/ml_evaluation_methodology.md) | Evaluation rules: data sets, metrics, diagnostics vs benchmarks, latency layers |
| [`requirements.txt`](requirements.txt) | Direct dependencies, pinned to the verified environment |
| [`requirements-data-plane.txt`](requirements-data-plane.txt) | Data plane dependencies (mitmproxy), for the separate `.venv-dataplane` environment |
| [`config.yaml`](config.yaml) | Runtime configuration — today only the data plane section |
| [`compose.yaml`](compose.yaml) · [`docker/`](docker/) | Docker Lab: the stack, per-service images, the data-plane config override and the smoke harness |

Dataset generation is deterministic and verified bit-identical across `PYTHONHASHSEED`
values. Environment: Python 3.12, torch 2.6.0+cu124, transformers 5.8.0, TRL 1.4.0,
PEFT 0.19.1, bitsandbytes 0.49.2, on an RTX 4090 Laptop GPU.

> Use `python3.12` explicitly — `python3` resolves to 3.14, which does not have the ML stack.

---

## Credits

- Attack payloads: [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) by [@swisskyrepo](https://github.com/swisskyrepo), commit `e961fef`
- CSIC 2010 HTTP dataset (Spanish Research National Council), re-rendered into the V4 representation
- The remaining training data (benign requests and a small set of hardcoded payloads) is generated by `parse_dataset_v4.py`; see [Dataset sources](#dataset-sources)
- Base model: [TinyLlama-1.1B-Chat-v1.0](https://huggingface.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0)
- Fine-tuning stack: [HuggingFace PEFT](https://github.com/huggingface/peft) + [TRL](https://github.com/huggingface/trl)
