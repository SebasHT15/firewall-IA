# firewall-IA — Docker Lab

A reproducible laboratory that runs the **existing** firewall-IA system end to end
in containers:

```
client ──▶ data plane (mitmproxy) ──▶ POST /classify ──▶ control plane (FastAPI)
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

**This is infrastructure.** It changes no model, dataset, prompt, parser,
generation parameter, request representation (D1), enforcement rule (D4/D34) or
evaluation methodology. Its purpose is to be the environment in which
**External Test v1** is later executed. It is not that test, and the smoke checks
below are not an evaluation.

---

## Status — 2026-09-21: runtime verified

Built and run. GPU passthrough works, the control plane runs on **CUDA**, V4 loads
from the read-only mounted adapter, and the five infrastructure checks pass. The
final run, `smoke-20260921T011153Z`, ended with `all infrastructure smoke checks
passed`.

| Check | Result |
|---|---|
| **A** startup / readiness — `/health` reports `model_loaded: true` | **PASS** |
| GPU passthrough; `startup: model ready on cuda` from `/opt/firewall-ia/adapter` | **PASS** |
| **B** ALLOW → 200, destination receives the request | **PASS** |
| **C** BLOCK → 403, destination receives 0 | **PASS** |
| **D** fail-closed → 503, destination receives 0, classifier `exited` before and after | **PASS** |
| **E** recovery — healthy again, ALLOW works | **PASS** |

Raw evidence is committed with the closure report at
[`../reports/lab/docker-lab-v1/`](../reports/lab/docker-lab-v1/), under its `raw/`
directory. `.lab-logs/` here holds the machine-local originals and stays gitignored.

**These are plumbing checks, not an evaluation.** See the warning under
[Smoke tests](#smoke-tests).

---

## Prerequisites

| Requirement | Why | Checked with |
|---|---|---|
| Docker Engine + Compose v2 | runs the lab | `docker --version`, `docker compose version` |
| Permission to use the Docker socket | membership of the `docker` group, or `sudo docker` | `docker info` |
| NVIDIA driver | the control plane runs V4 on the GPU | `nvidia-smi` |
| **NVIDIA Container Toolkit** | passes the GPU into the control-plane container | `nvidia-ctk --version` |
| **`model-output-v4-clean/` present locally** | the V4 adapter | `ls model-output-v4-clean/adapter_model.safetensors` |
| Local HuggingFace cache with the TinyLlama base | mounted read-only, so nothing is downloaded | `ls ~/.cache/huggingface/hub` |

> **The repository does not distribute the model.** `model-output-v4-clean/` is
> gitignored (157 MB) and is deliberately never copied into an image. Without it
> locally, the lab builds but the control plane cannot start. The same applies to
> the TinyLlama base snapshot in the HuggingFace cache. **Reproducibility of this
> lab is reproducibility of the *environment*, not of the model artifact.**

### Setting up the host

Two prerequisites were missing when the lab was first written (2026-09-20) and were
resolved by the operator before the verified run. If you are setting up a new
machine, these are the host changes required — Docker socket access and the NVIDIA
Container Toolkit:

```bash
# 1. Docker socket access (docker group membership is root-equivalent on this host;
#    alternatively prefix every lab command with sudo).
sudo usermod -aG docker "$USER"
newgrp docker          # or log out and back in

# 2. NVIDIA Container Toolkit (official repository, Ubuntu).
#    https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html
sudo nvidia-ctk runtime configure --runtime=docker
sudo systemctl restart docker

# 3. Verify the GPU is visible from a container.
docker run --rm --gpus all ubuntu:24.04 nvidia-smi
```

### If the NVIDIA Container Toolkit is missing

`docker/control-plane` requests a GPU through
`deploy.resources.reservations.devices`. Without the toolkit the container **fails
to start** — which is the intended behaviour. A CPU run is a **different execution
environment** from the CUDA baseline recorded in
`reports/benchmarks/baseline-local-v1/`; results from it must never be presented
as comparable. Install the toolkit (a host change, outside this lab's scope) or
run the system locally as before.

---

## Layout

```
compose.yaml                    the lab (repository root, canonical Compose name)
docker/
  README.md                     this file
  .env.example                  optional overrides; the lab runs without a .env
  config.docker.yaml            data-plane config, mounted over /app/config.yaml
  control-plane/Dockerfile      Ubuntu 24.04 + Python 3.12 + torch 2.6.0+cu124 + requirements.txt
  data-plane/Dockerfile         python:3.12-slim + requirements-data-plane.txt
  destination/                  Dockerfile, serve.py, www/
  client/                       Dockerfile, smoke_test.py
  smoke_test.sh                 host-side runner for the four checks
.dockerignore                   allowlist: keeps model/datasets/reports/.git out of build contexts
```

### Why it is built this way

- **Two images, not one (D33).** mitmproxy 12.2.3 pins `typing-extensions<=4.14`
  on Python 3.12; the control plane's pydantic 2.13.4 needs `>=4.14.1`. The
  existing local split into two environments is preserved as two images. Docker
  does not get to "solve" the conflict by merging them.
- **Two processes, not one.** The data plane talks to the control plane over HTTP
  exactly as before. Combining proxy and model into one container would be
  convenient and would destroy the separation the project chose deliberately.
- **No production code was modified.** `data_plane.py` reads `config.yaml` next to
  the repository root; the lab bind-mounts `docker/config.docker.yaml` over it
  rather than adding an environment override to a validated component. The root
  `config.yaml` is untouched, so the local workflow in the main README still works.
- **The adapter is mounted, never copied.** `FIREWALL_ADAPTER_DIR` already existed
  in `inference_core.py`; the lab sets it to `/opt/firewall-ia/adapter` and
  bind-mounts the host directory read-only.
- **The HuggingFace cache is mounted read-only, offline.** `HF_HUB_OFFLINE=1`
  means the container reuses the exact base snapshot this project was verified
  against instead of silently fetching a different revision.

### Networking

An explicit bridge network, `firewall-lab`. Services address each other by service
name through Docker's DNS — `127.0.0.1` inside one container is that container, not
another.

| Service | Address inside the lab | Published to the host |
|---|---|---|
| control-plane | `control-plane:8000` | **no** |
| data-plane | `data-plane:8080` | `127.0.0.1:8080` (loopback only) |
| destination | `destination:9000`, alias `app.fwlab.test:9000` | **no** |
| client | — (one-shot) | — |

The destination also answers to `app.fwlab.test`. That alias is chosen, and
disclosed, because `reports/diagnostics/real-http-fp-v1/` observed ordinary
hostnames of that shape as ALLOW in every context it tested, while loopback hosts
flipped to BLOCK. It keeps the ALLOW smoke check about transport instead of
re-measuring the model.

---

## Running it

```bash
docker compose build
docker compose up -d control-plane data-plane destination
docker compose ps
```

Watch it work (the project's rule is visible processes and persisted logs —
`docs/ml_evaluation_methodology.md` §13):

```bash
docker compose logs -f
```

Stop it:

```bash
docker compose down
```

### Smoke tests

```bash
./docker/smoke_test.sh
```

Five checks: **A** startup/readiness, **B** ALLOW forwarded, **C** BLOCK answered
403 and not forwarded, **D** classifier stopped → 503 and not forwarded, **E**
control plane restarted and ALLOW verified again. The script asserts that the
control plane is stopped immediately before the fail-closed request **and still
stopped after it**, so a classifier that came back mid-test can never be mistaken
for a result.

Individual phases, equivalent to what the script does:

```bash
docker compose run --rm client allow
docker compose run --rm client block
# --no-deps is REQUIRED for the fail-closed case: without it Compose resolves
# client -> data-plane -> control-plane (service_healthy) and restarts the classifier
# you just stopped, so the request gets a normal ALLOW and tests nothing.
docker compose stop control-plane
docker compose ps -a control-plane            # must NOT be "running", before ...
docker compose run --rm --no-deps client failclosed
docker compose ps -a control-plane            # ... and still not "running", after
docker compose start control-plane            # restore, then re-run `client allow`
```

**The control plane must stay stopped for the whole fail-closed step.** A 503 only
demonstrates fail-closed if the classifier was genuinely unavailable when the
request was sent; if anything restarted it in between, the result means nothing.
That is exactly the defect the first attempt hit — see the closure report.

Evidence of what actually reached the origin is the destination's receipt log:

```bash
cat docker/.lab-logs/destination-access.jsonl
```

> **These are infrastructure smoke tests.** Three hand-written requests. They are
> **not** External Test v1, **not** an evaluation, **not** a benchmark and **not** a
> diagnostic. No accuracy, precision, recall, FPR, FNR or latency figure may be
> derived from them. The smoke fixtures are infrastructure fixtures and stay
> conceptually separate from any future external evaluation set (D37).

---

## What the lab does not do

Out of scope here, unchanged from the local gateway's scope: HTTPS/TLS
interception, HTTP/2, WebSockets, transparent proxying, Kubernetes, concurrency or
load testing, production deployment. No fast path, no suspicious scoring, no
asynchronous classification, no GGUF/llama.cpp. The lab reproduces the current
no-fast-path baseline and nothing else.
