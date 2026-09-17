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

**Planned, not built**

- Classifier timeout tuned with end-to-end evidence (today: a conservative operational 3 s)
- HTTPS / HTTP/2 / WebSocket interception validation (the first data plane targets plain HTTP/1.1)
- GGUF export, Q4_K_M quantization, llama.cpp inference
- End-to-end gateway latency measurement
- Fast path, suspicious score, asynchronous classification (Issues #35–#38 — designed, not built)
- Concurrency / load validation (the inference benchmark is deliberately concurrency 1)
- Embedded Linux deployment
- Real HTTP laboratory validation

Nothing in the "planned" list should be read as working today.

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
uses. It is not end-to-end latency, which has not been measured yet.

### Running it

```bash
python3.12 -m uvicorn classifier_api:app --host 127.0.0.1 --port 8000
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
HTTP client --(HTTP proxy 127.0.0.1:8080)--> mitmdump -s data_plane.py
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
applying fail-closed. It is **not** the project's latency objective (D3) and is not derived
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
python3.12 -m uvicorn classifier_api:app --host 127.0.0.1 --port 8000

# 2 — a destination app to protect
mkdir -p /tmp/fw-demo && echo '<h1>destination reached</h1>' > /tmp/fw-demo/index.html
python3.12 -m http.server 9000 --bind 127.0.0.1 --directory /tmp/fw-demo

# 3 — gateway (data plane environment); wait for "data plane ready"
.venv-dataplane/bin/mitmdump -s data_plane.py --listen-host 127.0.0.1 -p 8080
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

### Real client traffic: observed model false positives

This is a **known limitation of the model/dataset** with traffic from real clients, **not**
a data plane defect. It is not worked around by rewriting headers or changing
`render_request()`, and it will be studied separately (D22). Observed with curl, 2026-09-16:

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
- Model behaviour on real HTTP traffic: needs deeper evaluation (see above, D22)
- Heuristics, suspicious score, fast path: not implemented (Issues #35–#38)

---

## Inference Benchmark (Issue #9)

`benchmark_inference.py` measures how long the V4 classifier takes to generate one
decision, under a fixed protocol, together with the full environment it ran in. The
reference experiment is **`baseline-local-v1`** — measured, frozen, and never overwritten.

**Scope: `generate()` only.** Prompt construction, tokenization, host→device transfer,
decoding and parsing are timed and reported separately and are never pooled into the
primary metric — together they contribute about 0.58 ms at P95. This is **not** API
latency and **not** gateway latency; end-to-end is Issue #18, and the D3 objective of
end-to-end P95 ≤ 200 ms is not evaluated here.

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
python3.12 benchmark_inference.py self-test          # statistics only, no model
python3.12 benchmark_inference.py estimate --runs 3  # duration before committing to it
python3.12 benchmark_inference.py protocol --experiment <new-id> --runs 3
python3.12 benchmark_compare.py --baseline baseline-local-v1 --candidate <new-id>
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
| Heuristic suspicious scoring (Issue #35) | Planned |
| Benign fast path (Issue #36) | Planned |
| Async fast-path validation (Issue #37) | Planned |
| Failure analysis of the 92 false negatives | Not yet tracked by a dedicated issue |
| Real HTTP laboratory validation | Planned |
| GGUF / Q4_K_M | Planned |
| llama.cpp inference | Planned |
| Inline HTTP gateway (plain HTTP/1.1, validated locally) | First version implemented |
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
> seed, evaluated on a synthetic + CSIC-2010 traffic mixture. It is **not** evidence of
> evasion resistance, **not** end-to-end gateway performance, and **not** a measurement
> on real production traffic. Per-category results are **not** equally reliable: one
> category is unevaluable and ten are flagged insufficient-data. The latency figure is
> model-side only. See [Known Limitations](#known-limitations).

Full detail: [`reports/v4_clean_baseline_results.txt`](reports/v4_clean_baseline_results.txt).

---

## Dataset Integrity

The current dataset is `datasets/v4_clean/` — **25,134 train / 6,206 eval / 31,340 total**,
balanced at 15,670 ALLOW / 15,670 BLOCK.

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
- **The evaluation split also drove best-checkpoint selection.** It is a held-out
  evaluation/validation split, not a completely untouched final test set.
- **Real HTTP laboratory traffic has not been validated yet.**
- **No adversarial held-out evaluation has been performed.** Evasion resistance is
  unmeasured by design.
- **Model-side P95 is already above 200 ms** — 269.0 ms under the Issue #9 protocol,
  270.8 ms historically. D3 (end-to-end P95 ≤ 200 ms) is a project **performance
  objective**, not an acceptance criterion for the current gateway, and no formal
  end-to-end benchmark exists yet (Issue #18). The model-side figure is why inference
  optimization is prioritized (M2, D23, D35).
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
- **The model produced false positives on real client traffic** during local
  verification, e.g. `GET /index.html` with `Host: 127.0.0.1:9000`. See
  [Real client traffic](#real-client-traffic-observed-model-false-positives).
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

**M1 — next**

- Issue #8 — V4 clean security evaluation: **complete**, metrics archived in
  `reports/v4_clean_eval.json`
- Issue #9 — controlled inference benchmark: **complete**, `baseline-local-v1` frozen in
  `reports/benchmarks/`
- Failure analysis of the 92 false negatives (D21) — outstanding work, not currently
  tracked by a dedicated issue
- Real HTTP laboratory validation
- Decision gate: a targeted V4.1 only if the evidence requires it, otherwise proceed to M2

**M3 — partially started ahead of M2 (D26)**

- Issue #15 — FastAPI control plane: **complete**
- Issue #16 — mitmproxy inline data plane: **first version implemented**, verified locally
- Issue #17 — fail-closed enforcement: **first version implemented**, verified locally; timeout to be tuned
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
| [`reports/v4_inference_benchmark.md`](reports/v4_inference_benchmark.md) | Issue #9 benchmark report — protocol, environment, results |
| [`datasets/manifest_v4_clean.json`](datasets/manifest_v4_clean.json) | Dataset identity: hashes, seed, source commit, generation policy |
| [`CONTEXT.md`](CONTEXT.md) | Current technical state and immediate roadmap |
| [`DECISIONS.md`](DECISIONS.md) | Project decision log (D1–D35) |
| [`requirements.txt`](requirements.txt) | Direct dependencies, pinned to the verified environment |
| [`requirements-data-plane.txt`](requirements-data-plane.txt) | Data plane dependencies (mitmproxy), for the separate `.venv-dataplane` environment |
| [`config.yaml`](config.yaml) | Runtime configuration — today only the data plane section |

Dataset generation is deterministic and verified bit-identical across `PYTHONHASHSEED`
values. Environment: Python 3.12, torch 2.6.0+cu124, transformers 5.8.0, TRL 1.4.0,
PEFT 0.19.1, bitsandbytes 0.49.2, on an RTX 4090 Laptop GPU.

> Use `python3.12` explicitly — `python3` resolves to 3.14, which does not have the ML stack.

---

## Credits

- Training data: [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) by [@swisskyrepo](https://github.com/swisskyrepo)
- CSIC 2010 HTTP dataset (Spanish Research National Council)
- Base model: [TinyLlama-1.1B-Chat-v1.0](https://huggingface.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0)
- Fine-tuning stack: [HuggingFace PEFT](https://github.com/huggingface/peft) + [TRL](https://github.com/huggingface/trl)
