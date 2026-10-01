# Hybrid Architecture Phase 1 — request feature extraction: shadow-mode run and extractor overhead (v1, superseded)

> **Superseded by [`../phase1-feature-extraction-v2/`](../phase1-feature-extraction-v2/).**
> This run was made on the pre-review working tree, which was never committed. The review
> before commit (2026-10-01) changed two things: the feature definitions (schema
> `request-features/v1` → `v2`: patterns no longer matched across the path / query / body
> boundaries, duplicate JSON keys counted, JSON validity independent of interpreter limits
> and call stack), and the integration point (extraction moved after the classifier call,
> so `(classifier N ms)` again includes `render_request()`). Everything below describes
> the v1 code and is kept as recorded. Raw files are unchanged (`raw/SHA256SUMS` verifies);
> this directory was first written as `reports/v5/phase1-feature-extraction-v1/` and moved
> before any commit (terminology, D45), so some raw logs and the two scripts still print
> that path.

**Kind: functional validation and overhead observation.** Not an evaluation of any model,
not a benchmark under D32, not Issue #18 (end-to-end latency). No model metric may be
derived from the requests below: they are 11 hand-written requests, not a sample of
anything.

Issue #49 · decisions D43 (shadow mode) and D44 (`Host` / `User-Agent` exclusion) ·
component description (current code): [`docs/technical_reference.md`](../../../docs/technical_reference.md#shadow-feature-extraction-hybrid-architecture-phase-1)

Date: 2026-10-01. Machine: RTX 4090 Laptop GPU, 13th Gen Intel Core i9-13900HX, Python
3.12. Code: branch `feature/v5-request-feature-extraction`, uncommitted working tree on
top of `46a6424`.

## 1. What was run

### Live run through the real gateway, shadow off then on

Processes, each in its own visible terminal, output teed to `raw/`:

| Process | Command | Log |
|---|---|---|
| control plane, real V4 on CUDA | `python3.12 -m uvicorn --app-dir control_plane classifier_api:app --host 127.0.0.1 --port 8000` | `raw/control-plane.log` (both runs, one process) |
| destination (lab `serve.py`, loopback) | [`run_destination.py`](run_destination.py) with `ACCESS_LOG` per run | `raw/destination-shadow-{off,on}.log`, receipts `raw/destination-access-shadow-{off,on}.jsonl` |
| data plane | `.venv-dataplane/bin/mitmdump -s data_plane/data_plane.py --listen-host 127.0.0.1 -p 8080` | `raw/data-plane-shadow-{off,on}.log` |
| client | [`send_requests.sh`](send_requests.sh): 11 fixed requests × 3 | `raw/client-shadow-{off,on}.log` |

1. `config.yaml` set to `shadow_feature_extraction: false`; gateway and destination
   started; the client sent the 33 requests.
2. Gateway and destination stopped; `config.yaml` restored to `true`; both restarted
   (fresh receipt log); the client sent the same 33 requests. The control plane stayed up
   across both runs.
3. `/health` and `/classify` called directly (`raw/control-plane-api-check.log`).
4. Control plane stopped; one benign request sent through the shadow-on gateway
   (`raw/client-failclosed-shadow-on.log`).

The requests carry no marker header and include no External Test v1 case and no dataset
row (`send_requests.sh` lists them).

### In-process extractor timing

[`scripts/benchmarks/benchmark_request_features.py`](../../../scripts/benchmarks/benchmark_request_features.py),
data-plane environment → [`extractor_overhead.json`](extractor_overhead.json). Corpus: the
6,206 texts of `datasets/v4_clean/eval.jsonl`, `input` field only (labels not read),
SHA-256 `61f15591…` verified against the manifest; one warm-up pass reported apart, then 3
measured passes. Plus synthetic form bodies of 1 KiB – 1 MiB, 20 calls each.

## 2. Results

### Shadow mode changes nothing in the decision path

| Check | Shadow off | Shadow on |
|---|---|---|
| Client statuses (33 requests) | 12 × 200, 21 × 403 | identical, request by request; `client-shadow-{off,on}.log` have the same SHA-256 |
| Data-plane decision lines (parsed with `external_v1_run.py`'s regexes) | 12 ALLOW, 21 BLOCK | identical decision **and reason**, in the same order |
| Destination receipts | 12 (the 12 ALLOW) | 12 (the same 12) |
| `FEATURE EXTRACTION (shadow)` lines | 0 (`feature extraction: off`) | 34 (33 + the fail-closed request), 0 failures |
| Feature lines matched by a decision-line parser (`external_v1_run.py`, `demo.sh`) | — | 0 |
| Payload text in feature lines (query values, body, path, Host, User-Agent) | — | none found |

Fail-closed with shadow on: control plane stopped → feature line logged, then
`BLOCK (fail-closed) … cause=classifier unreachable (ConnectError)`, client `503`,
destination receipts 12 → 12.

`/health` → 200 `{"status":"ok","model_loaded":true,…}`; `/classify` on a benign D1 text →
200 `ALLOW`; empty request → 422. Unchanged behaviour.

**Observation, not a result.** Three of the hand-written benign requests (`post-json`,
`get-repeated`, `get-long-path`) were BLOCK in both runs, as were the five attack-like
ones. That is V4 behaviour, identical with shadow off and on; it is a count on 11
constructed requests, not a rate (D42), and it was not analysed.

### Extractor overhead

**In-process, V4 eval corpus** (`extractor_overhead.json`, ms per `extract_features()` call,
nearest-rank percentiles, no sample removed):

| Population | n | min | mean | P50 | P95 | P99 | max |
|---|---:|---:|---:|---:|---:|---:|---:|
| warm-up pass (reported apart) | 6,206 | 0.0083 | 0.0155 | 0.0143 | 0.0262 | 0.0301 | 0.1735 |
| measured, 3 passes pooled | 18,618 | 0.0082 | 0.0153 | 0.0141 | 0.0257 | 0.0299 | 0.0403 |

Per pass P95: 0.0257 · 0.0256 · 0.0258 ms.

**By body size** (synthetic form body, 20 calls each):

| Body | min | mean | P50 | P95 | max |
|---|---:|---:|---:|---:|---:|
| 1 KiB | 0.0463 | 0.0482 | 0.0481 | 0.0498 | 0.0521 |
| 10 KiB | 0.4153 | 0.4330 | 0.4315 | 0.4482 | 0.4526 |
| 100 KiB | 4.2385 | 4.3262 | 4.3181 | 4.4042 | 4.4487 |
| 1 MiB | 47.8602 | 48.3086 | 48.3518 | 48.5893 | 48.7682 |

Cost grows roughly linearly with body size (≈ 0.05 ms per KiB).

**Live, in the gateway** (the `… ms` of each feature line: the extractor call only,
excluding log formatting), n = 34: min 0.037 · mean 0.114 · P50 0.061 · P95 0.086 ·
max 2.039 ms. The maximum is one repetition of `get-unicode-pct`; the same text took
0.060 and 0.041 ms in the other two and produced identical features. Its cause is not
established; the sample is kept.

## 3. Reading limits

- n = 34 live samples is a functional observation, not a latency distribution.
- The in-process figures are one machine and one Python build. They are not comparable to
  `baseline-local-v1` (different component, scope and protocol) and say nothing about D36,
  which concerns the inference pipeline.
- The extractor runs synchronously on mitmproxy's event loop. Its cost is added to every
  shadow-on request; at the measured rate a 1 MiB body costs ≈ 48 ms. Large bodies are
  outside the validated scope of the data plane (technical reference, "Scope of this first
  version").
- The `(classifier N ms)` figure of the decision lines no longer includes
  `render_request()` (now rendered once, before the classifier call, so the extractor and
  the classifier see the same string). That is a scope change of microseconds in an
  observational log value; it is not a benchmark.

## 4. Files

| File | Content |
|---|---|
| `send_requests.sh` | the 11 pre-declared client requests |
| `run_destination.py` | runs `docker/destination/serve.py` bound to 127.0.0.1 |
| `extractor_overhead.json` | in-process timing output (written once, never overwritten) |
| `raw/` | every process log and both receipt logs; `raw/SHA256SUMS` |
