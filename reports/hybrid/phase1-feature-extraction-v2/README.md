# Hybrid Architecture Phase 1 — request feature extraction: shadow-mode run and extractor overhead (v2)

**Kind: functional validation and overhead observation.** Not an evaluation of any model,
not a benchmark under D32, not Issue #18 (end-to-end latency). No model metric may be
derived from the requests below: they are 11 hand-written requests, not a sample of
anything.

Issue #49 · decisions D43 (shadow mode), D44 (`Host` / `User-Agent` exclusion), D45
(terminology) · component description:
[`docs/technical_reference.md`](../../../docs/technical_reference.md#shadow-feature-extraction-hybrid-architecture-phase-1)

**This run validates the code as reviewed for commit** (feature schema
`request-features/v2`; shadow extraction after the classifier call). It supersedes
[`../phase1-feature-extraction-v1/`](../phase1-feature-extraction-v1/), produced on the
pre-review working tree and kept as evidence.

Date: 2026-10-01. Machine: RTX 4090 Laptop GPU, 13th Gen Intel Core i9-13900HX, Python
3.12.14. Code: branch `feature/v5-request-feature-extraction` (name predates D45),
uncommitted working tree on top of `46a6424`.

## 1. What was run

Same procedure and same 11 requests as v1 (`send_requests.sh` differs from v1's only in
comments).

| Process | Command | Log |
|---|---|---|
| control plane, real V4 on CUDA | `python3.12 -m uvicorn --app-dir control_plane classifier_api:app --host 127.0.0.1 --port 8000` | `raw/control-plane.log` (both runs, one process) |
| destination (lab `serve.py`, loopback) | [`run_destination.py`](run_destination.py), `ACCESS_LOG` per run | `raw/destination-shadow-{off,on}.log`, receipts `raw/destination-access-shadow-{off,on}.jsonl` |
| data plane | `.venv-dataplane/bin/mitmdump -s data_plane/data_plane.py --listen-host 127.0.0.1 -p 8080` | `raw/data-plane-shadow-{off,on}.log` |
| client | [`send_requests.sh`](send_requests.sh): 11 fixed requests × 3 | `raw/client-shadow-{off,on}.log` |

1. `config.yaml` set to `shadow_feature_extraction: false`; gateway and destination
   started; 33 requests sent.
2. Gateway and destination stopped; `config.yaml` restored to `true`; both restarted
   (fresh receipt log); the same 33 requests sent. The control plane stayed up.
3. `/health` and `/classify` called directly (`raw/control-plane-api-check.log`).
4. Control plane stopped and its port confirmed closed; one benign request sent through
   the shadow-on gateway (`raw/client-failclosed-shadow-on.log`).

In-process timing: [`scripts/benchmarks/benchmark_request_features.py`](../../../scripts/benchmarks/benchmark_request_features.py)
in the data-plane environment → [`extractor_overhead.json`](extractor_overhead.json). Corpus:
the 6,206 texts of `datasets/v4_clean/eval.jsonl`, `input` field only (labels not read),
SHA-256 `61f15591…` verified against the manifest; one warm-up pass reported apart, then 3
measured passes; plus synthetic form bodies of 1 KiB – 1 MiB, 20 calls each.

No External Test v1 case, no dataset row and no marker header was sent.

## 2. Results

### Shadow mode changes nothing in the decision path

| Check | Shadow off | Shadow on |
|---|---|---|
| Client statuses (33 requests) | 12 × 200, 21 × 403 | identical request by request; `client-shadow-{off,on}.log` have the same SHA-256 (also the same as v1's) |
| Decision lines (parsed with `external_v1_run.py`'s regexes) | 12 ALLOW, 21 BLOCK | identical decision **and reason**, same order |
| Destination receipts | 12 (the 12 ALLOW) | 12 (the same 12) |
| `FEATURE EXTRACTION (shadow)` lines | 0 (`feature extraction: off`) | 34 (33 + the fail-closed request), all `request-features/v2`, 0 failures |
| Line order per flow | — | `received` → `FEATURE EXTRACTION` → decision, for all 34 flows |
| Feature lines matched by a decision-line parser (`external_v1_run.py`, `summarize_latency_observations.py`, `demo.sh`) | — | 0 |
| Path, query values, body, Host or User-Agent in feature lines | — | none |

Fail-closed with shadow on: with port 8000 closed, the feature line is logged, then
`BLOCK (fail-closed) … cause=classifier unreachable (ConnectError)`; the client gets `503`;
destination receipts stay at 12.

`/health` → 200 `{"status":"ok","model_loaded":true,…}`; `/classify` on a benign D1 text →
200 `ALLOW`; empty request → 422.

**Observation, not a result.** Three hand-written benign requests (`post-json`,
`get-repeated`, `get-long-path`) were BLOCK in both runs, as were the five attack-like
ones: V4 behaviour, identical with shadow off and on; a count on 11 constructed requests,
not a rate (D42); not analysed.

### `(classifier N ms)` keeps its definition

It times `render_request()` plus the `/classify` call, as before Phase 1; the extractor
runs after it (proven by `test_classifier_time_keeps_its_definition` in
`tests/test_data_plane.py`).
Observed P50 243 ms off vs 258 ms on (n = 33 each). V4's own `generate()` time in
`raw/control-plane.log` moved the same way, P50 236.2 → 250.5 ms, so the difference is
model-side, consistent with the run-order / thermal drift documented for
`baseline-local-v1`; it is not attributed to the extractor. Observations, not a benchmark.

### Extractor overhead

**In-process, V4 eval corpus** (ms per `extract_features()` call, nearest-rank, no sample
removed):

| Population | n | min | mean | P50 | P95 | P99 | max |
|---|---:|---:|---:|---:|---:|---:|---:|
| warm-up pass (reported apart) | 6,206 | 0.0099 | 0.0186 | 0.0168 | 0.0312 | 0.0399 | 0.1634 |
| measured, 3 passes pooled | 18,618 | 0.0101 | 0.0185 | 0.0169 | 0.0301 | 0.0367 | 0.1588 |

Per pass P95: 0.0300 · 0.0303 · 0.0300 ms.

**By body size** (synthetic form body, 20 calls each):

| Body | min | mean | P50 | P95 | max |
|---|---:|---:|---:|---:|---:|
| 1 KiB | 0.0513 | 0.0527 | 0.0525 | 0.0541 | 0.0565 |
| 10 KiB | 0.4556 | 0.4696 | 0.4693 | 0.4805 | 0.4833 |
| 100 KiB | 4.5966 | 4.7333 | 4.7065 | 4.9525 | 4.9820 |
| 1 MiB | 52.2388 | 53.2494 | 53.0887 | 54.1616 | 57.5263 |

**Live, in the gateway** (the `… ms` of each feature line: the extractor call alone),
n = 34: min 0.039 · mean 0.062 · P50 0.052 · P95 0.125 · max 0.132 ms.

v1 measured lower figures (pooled P95 0.0257 ms). Code (schema v1 → v2) and time both
differ between the two runs, so the difference is not attributed to either.

## 3. Reading limits

- n = 34 live samples is a functional observation, not a latency distribution.
- One machine, one Python build; not comparable to `baseline-local-v1` (different
  component, scope and protocol); says nothing about D36.
- The extractor runs synchronously on mitmproxy's event loop, so its cost is added to every
  shadow-on request; it grows linearly with body size (≈ 53 ms for 1 MiB here). Large
  bodies are outside the validated scope of the data plane; no limit or optimization was
  added in Phase 1.

## 4. Files

| File | Content |
|---|---|
| `send_requests.sh` | the 11 pre-declared client requests (same as v1) |
| `run_destination.py` | runs `docker/destination/serve.py` bound to 127.0.0.1 |
| `extractor_overhead.json` | in-process timing output (written once, never overwritten) |
| `raw/` | every process log and both receipt logs; `raw/SHA256SUMS` |
