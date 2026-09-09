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
Data Plane — inline gateway ..........  NOT BUILT     (mitmproxy; would enforce fail-closed)
    |
    v
Control Plane — POST /classify .......  IMPLEMENTED   (FastAPI, classifier_api.py)
    |
    v
inference_core — V4 pipeline .........  IMPLEMENTED   (TinyLlama + model-output-v4-clean)
    |
    v
status=ok -> ALLOW | BLOCK           .  IMPLEMENTED   (reported to the caller,
status=invalid -> no decision                          NOT enforced on any traffic)
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

**Planned, not built**

- Inline interception data plane (mitmproxy)
- Fail-closed enforcement in a live path
- Classifier timeout
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
it does not enforce**. Nothing intercepts or blocks traffic yet: the data plane
(mitmproxy) and inline fail-closed enforcement are not built.

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
uses. It is not end-to-end latency; there is no data plane to measure end to end.

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

## Inference Benchmark (Issue #9)

`benchmark_inference.py` measures how long the V4 classifier takes to generate one
decision, under a fixed protocol, together with the full environment it ran in. The
reference experiment is **`baseline-local-v1`** — measured, frozen, and never overwritten.

**Scope: `generate()` only.** Prompt construction, tokenization, host→device transfer,
decoding and parsing are timed and reported separately and are never pooled into the
primary metric — together they contribute about 0.58 ms at P95. This is **not** API
latency and **not** gateway latency; end-to-end is Issue #18, and the D3 budget of
end-to-end P95 ≤ 200 ms is neither passed nor failed here.

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
| Inline data plane (Issue #16) | Planned |
| Fail-closed enforcement (Issue #17) | Planned |
| Heuristic suspicious scoring (Issue #35) | Planned |
| Benign fast path (Issue #36) | Planned |
| Async fast-path validation (Issue #37) | Planned |
| Failure analysis of the 92 false negatives | Not yet tracked by a dedicated issue |
| Real HTTP laboratory validation | Planned |
| GGUF / Q4_K_M | Planned |
| llama.cpp inference | Planned |
| Inline gateway | Planned |
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
- **Model-side P95 (269.0 ms under the Issue #9 protocol; 270.8 ms historically) already
  exceeds the whole 200 ms end-to-end budget**, so the current HuggingFace path is not a
  viable deployment backend without optimization.
- **No quantized comparison exists yet** — GGUF/Q4_K_M is unbuilt.
- **No physical embedded validation exists yet.**
- **CSIC BLOCK labels come from a keyword heuristic**, so the CSIC-derived portion of
  per-category results inherits that circularity.
- **The control plane reports; it does not enforce.** `POST /classify` returns
  `status: "invalid"` for unparseable model output, and 5xx on failure. Nothing acts on
  that yet — fail-closed (D4) belongs to the data plane, which is not built.
- **No classifier timeout has been derived.** D3 makes the latency budget a prerequisite
  for choosing one, and the value is still undecided.
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
- Issue #16 — mitmproxy inline data plane: not started
- Issue #17 — fail-closed enforcement: not started
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
| [`DECISIONS.md`](DECISIONS.md) | Project decision log (D1–D30) |
| [`requirements.txt`](requirements.txt) | Direct dependencies, pinned to the verified environment |

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
