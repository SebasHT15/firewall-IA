# docker-lab-v1 — Docker Lab closure report

**Report type: INFRASTRUCTURE VERIFICATION.** It records that the existing
firewall-IA system runs end to end in containers. It is **not** an evaluation,
**not** a benchmark, **not** a diagnostic and **not** External Test v1. No
accuracy, precision, recall, FPR, FNR, latency or throughput figure may be derived
from anything in this report.

Date: 2026-09-21. Evidence run: `smoke-20260921T011153Z`.

---

## 1. Objective

Provide a reproducible containerized environment in which the current system can be
run end to end, so that **External Test v1** can later be executed against the
complete gateway rather than against `/classify` alone.

The lab is infrastructure. Nothing about the system's meaning changed: no model, no
dataset, no prompt, no parser, no generation parameter, no request representation
(D1), no enforcement rule (D4/D34), no evaluation methodology. **No production code
was modified** — the data plane's Docker configuration is bind-mounted over
`config.yaml` instead of being added as an override inside `data_plane.py`, so the
local non-Docker workflow is unchanged.

## 2. Architecture

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

| Service | Base | Role |
|---|---|---|
| `control-plane` | `ubuntu:24.04` + Python 3.12 + torch 2.6.0+cu124 + `requirements.txt` | FastAPI → `inference_core` → TinyLlama + V4. Only service that loads the model or uses the GPU. |
| `data-plane` | `python:3.12-slim` + `requirements-data-plane.txt` | mitmdump running the unchanged `data_plane.py`. Never loads the model. |
| `destination` | `python:3.12-slim`, stdlib only | Protected origin. Appends every received request to a JSONL receipt log. |
| `client` | `python:3.12-slim`, stdlib only | One-shot smoke client, behind a compose profile. |

Design constraints preserved:

- **Two images, not one (D33).** mitmproxy pins `typing-extensions<=4.14` on
  Python 3.12; the control plane's pydantic needs `>=4.14.1`. The existing
  environment split became an image boundary.
- **Two processes, not one.** The data plane still reaches the control plane over
  HTTP. Merging them would have been convenient and would have destroyed a
  deliberate separation.
- **The adapter is mounted, never copied.** `FIREWALL_ADAPTER_DIR=/opt/firewall-ia/adapter`,
  bind-mounted read-only from the gitignored `model-output-v4-clean/`.
  `.dockerignore` is an allowlist so the model, datasets, reports and `.git` cannot
  enter a build context.
- **HuggingFace cache read-only with `HF_HUB_OFFLINE=1`**, so the container reuses
  the verified TinyLlama base snapshot rather than fetching another revision.
- **Explicit bridge network, service-name DNS.** `control-plane:8000` and
  `destination:9000` are unpublished; only the gateway is published, on
  `127.0.0.1:8080`.
- **GPU required, never silently skipped.** Without the NVIDIA Container Toolkit the
  control plane fails to start rather than falling back to CPU, because a CPU run is
  a different execution environment from `reports/benchmarks/baseline-local-v1/`.

The destination also answers to the alias `app.fwlab.test`. That hostname was chosen
**and is disclosed** because `reports/diagnostics/real-http-fp-v1/` observed ordinary
hostnames of that shape as ALLOW in every context it tested, while loopback hosts
flipped to BLOCK. It keeps the ALLOW check about transport instead of re-measuring
the model. Request headers are urllib's defaults; nothing was shaped to steer V4.

## 3. Prerequisites

| Requirement | Status on the development machine |
|---|---|
| Docker Engine 29.1.3, Compose v5.5.1 | present |
| Docker socket access for the invoking user | initially missing, resolved by the operator |
| NVIDIA driver 595.84, RTX 4090 Laptop | present |
| NVIDIA Container Toolkit | initially missing, **installed by the operator**; GPU passthrough then worked |
| `model-output-v4-clean/` present locally | present (gitignored, not distributed by the repository) |
| TinyLlama base snapshot in the host HuggingFace cache | present (mounted read-only) |

**The repository does not distribute the model.** The lab reproduces the
*environment*, not the model artifact; both the adapter and the base snapshot must
already exist locally.

## 4. Evidence run

```bash
docker compose build
docker compose up -d control-plane data-plane destination
./docker/smoke_test.sh
```

- Harness and service logs: committed as
  `raw/smoke-20260921T011153Z-PASS-final.log` (machine-local original:
  `docker/.lab-logs/smoke-20260921T011153Z.log`)
- Destination receipt log: committed as `raw/destination-access.jsonl`
  (cumulative across runs; the evidence run contributed the two ALLOW receipts at
  `01:11:55` and `01:12:07`)

Final line of the run: `all infrastructure smoke checks passed`.

Model load, from the control-plane service log in that run:

```
Loading model from /opt/firewall-ia/adapter ...
startup: loading adapter /opt/firewall-ia/adapter
startup: model ready on cuda in 1.7 s
```

## 5. Results

| Check | Result | Observed |
|---|---|---|
| **A** startup / readiness | **PASS** | `control plane healthy (/health reports model_loaded: true)`; GPU passthrough and CUDA model load confirmed |
| **B** ALLOW | **PASS** | `status=200 (expected 200)`; destination received 1 new request, receipt `GET /index.html host=app.fwlab.test:9000`; destination page returned to the client |
| **C** BLOCK | **PASS** | `status=403 (expected 403)`; destination received **0** new requests; body `Request blocked by firewall-IA.` |
| **D** fail-closed | **PASS** | control plane confirmed `exited` **before** the request and `exited` **after** it; `status=503 (expected 503)`; destination received **0** new requests; body `Request blocked by firewall-IA: classifier unavailable (fail-closed).` |
| **E** recovery | **PASS** | control plane healthy again; ALLOW `status=200`, destination received the request |

Receipt evidence comes from the destination's own append-only JSONL log, so "the
request did not arrive" is a recorded fact rather than an absence of console output.

## 6. Defects found during validation, and their fixes

Both were found by running the lab. Neither was a fault of the gateway, and neither
changed system behaviour.

### 6.1 V4 could not load inside the container

`bitsandbytes` imports Triton, whose NVIDIA backend compiles a small CPython
extension on first import — at model load time. The bare `ubuntu:24.04` image had no
toolchain:

```
RuntimeError: Failed to find C compiler. Please specify via CC environment variable.
```

FastAPI still started and `/health` kept reporting `model_loaded: false`, so the
healthcheck correctly never went healthy. The failure was visible, not silent. This
never appeared locally because the host already has a toolchain.

**Fix — `docker/control-plane/Dockerfile` only.** Added to the existing apt layer:

- `build-essential` — the C compiler Triton looks for (`cc`/`gcc`), plus `libc6-dev`.
- `python3-dev` — the CPython headers (`Python.h`) the generated extension includes.

V4 then loaded on CUDA. No production code, no `requirements.txt`, no package
version, no model or inference configuration changed.

> Note on evidence: the harness log for that first attempt, committed as
> `raw/smoke-20260921T002643Z-FAILED-toolchain-partial.log`, captured only phase A — the
> run was interrupted before the service-log dump — so the traceback itself was read
> from the container logs at the time and is **not** in that file.

### 6.2 The first fail-closed attempt was invalid

`docker compose run client failclosed` resolves the client's dependency graph:

```
client → data-plane → control-plane (condition: service_healthy)
```

so Compose **restarted the classifier that had just been stopped** and waited until
it was healthy. `raw/smoke-20260921T004432Z-FAILED-invalid-failclosed.log` records the
sequence
`Stopping → Stopped → Starting → Started → Waiting → Healthy`, after which the
request returned `status=200 (expected 503)` and the destination received it.

**This was a smoke-test orchestration defect, not a fail-open of the gateway.** The
data plane was never presented with an unavailable classifier, so nothing about
fail-closed was exercised.

**Fix — `docker/smoke_test.sh` only**, plus the matching manual sequence in
`docker/README.md` and a warning comment in `compose.yaml`:

- `--no-deps` on the fail-closed invocation, and only there. `data-plane` and
  `destination` are already running from phase A, so dependency resolution costs
  nothing to skip.
- An assertion that the control plane is stopped immediately **before** the request,
  which skips and fails the case rather than producing a meaningless result.
- A re-check immediately **after**, so a classifier that returned mid-request is
  reported as untrustworthy instead of passing.

Fail-closed semantics, `data_plane.py` and control-plane production code were not
touched. The next run validated fail-closed correctly (§5, check D).

## 7. Verified claims

- The system runs end to end in containers: client → data plane → `/classify` →
  control plane → `inference_core` → V4 → decision → enforcement → destination.
- GPU passthrough works; the control plane runs on CUDA and loads V4 from a
  read-only mounted adapter.
- The control-plane healthcheck reflects real readiness (`model_loaded`), not merely
  process liveness (D28).
- ALLOW is forwarded and reaches the destination.
- BLOCK returns 403 and the destination receives nothing.
- Fail-closed returns 503 and the destination receives nothing, with the classifier
  confirmed stopped before and after the request.
- The gateway recovers: the control plane becomes healthy again and ALLOW works.
- The two planes remain separate processes in separate images with their own
  dependency sets.
- The local non-Docker workflow is unaffected: the root `config.yaml` is unchanged
  and still targets `127.0.0.1`.

## 8. Unverified and out of scope

Not touched by this run, and not claimed:

- **Any model-quality property.** Three hand-written requests. No accuracy,
  precision, recall, FPR, FNR or ADR. The `model_latency_ms` values visible in the
  run log are incidental service logging, not a measurement, and no latency claim
  may be built from them.
- **External Test v1** — does not exist. This lab is where it will later run.
- HTTPS/TLS interception, HTTP/2, WebSockets, transparent proxying.
- Large request bodies; concurrency and load (the control plane still serializes
  inference on one GPU).
- End-to-end gateway latency (Issue #18).
- Fast path, suspicious scoring, asynchronous classification (Issues #35–#38);
  GGUF/llama.cpp; embedded deployment. The lab reproduces the current no-fast-path
  baseline and nothing else.
- Any hardware other than this machine.

## 9. Raw evidence

The logs are **committed with this report**, in `raw/`. They are byte-identical copies
of the run output; the machine-local originals under `docker/.lab-logs/` were left in
place and are still gitignored as working output. `raw/SHA256SUMS` pins every copy.

| `raw/` file | Run | Status | Content |
|---|---|---|---|
| `smoke-20260921T011153Z-PASS-final.log` | 2026-09-21 01:11:53Z | **PASS — the evidence run** | harness output plus control-plane, data-plane and destination logs. This is the run §5 reports. |
| `smoke-20260921T004432Z-FAILED-invalid-failclosed.log` | 2026-09-21 00:44:32Z | **FAILED — diagnostic only** | the run whose fail-closed case was invalid (§6.2). Its A/B/C/E cases passed, but its **D case proves nothing**: Compose restarted the classifier, so the 200 it records is not a gateway result. Do not read this file as evidence of behaviour. |
| `smoke-20260921T002643Z-FAILED-toolchain-partial.log` | 2026-09-21 00:26:43Z | **FAILED — partial capture** | the first attempt (§6.1). It stops at phase A: the run was interrupted before the service-log dump, so **the `Failed to find C compiler` traceback is NOT in this file** — it was read from the container logs at the time. Kept for the record of what the harness captured, not as proof of the root cause. |
| `destination-access.jsonl` | — | receipt log | the destination's append-only receipts, **cumulative across all three runs**. The evidence run contributed the two ALLOW receipts at `01:11:55` and `01:12:07`; there is no receipt for the BLOCK or fail-closed requests, which is the point. |
| `SHA256SUMS` | — | integrity | checksums of the four files above (`sha256sum -c SHA256SUMS`) |

Two of these are records of **failed or invalid runs**, kept because the defects they
document are part of how this lab was validated (§6). Neither is evidence that the
gateway behaves correctly; only the PASS run is.

Re-running `./docker/smoke_test.sh` writes a new timestamped log under
`docker/.lab-logs/` and overwrites nothing here.

`reports/benchmarks/baseline-local-v1/` and `reports/diagnostics/real-http-fp-v1/`
were not read, modified or overwritten by this work.

## 10. Reproducing

```bash
docker compose build
docker compose up -d control-plane data-plane destination
./docker/smoke_test.sh
```

Prerequisites, the network map and every design choice are in
[`docker/README.md`](../../../docker/README.md).
