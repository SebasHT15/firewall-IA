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
Inline Gateway  ......................  PLANNED  (mitmproxy data plane)
    |
    v
Classifier  ..........................  IMPLEMENTED  (TinyLlama + QLoRA adapter)
    |
    v
ALLOW / BLOCK  .......................  IMPLEMENTED  (decision contract)
    |
    v
Destination Server
```

**Implemented today**

- Dataset generation, integrity gating and the frozen V4-clean dataset
- QLoRA fine-tuning pipeline (transformers 5.8 / TRL 1.4)
- The trained V4-clean classifier adapter
- Frozen evaluation methodology and harness
- A FastAPI control-plane service (`classifier_api.py`) — written and now runnable,
  but not yet integrated into a gateway

**Planned, not built**

- Inline interception data plane (mitmproxy)
- GGUF export, Q4_K_M quantization, llama.cpp inference
- Fail-closed enforcement in a live path
- End-to-end gateway latency measurement
- Embedded Linux deployment
- Real HTTP laboratory validation

Nothing in the "planned" list should be read as working today.

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
| Formal V4 evaluation | Complete |
| Controlled inference benchmark (Issue #9) | Next |
| Security error analysis (Issue #8) | Next |
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
- **Model-side P95 (270.8 ms) already exceeds the whole 200 ms end-to-end budget**, so
  the current HuggingFace path is not a viable deployment backend without optimization.
- **No quantized comparison exists yet** — GGUF/Q4_K_M is unbuilt.
- **No physical embedded validation exists yet.**
- **CSIC BLOCK labels come from a keyword heuristic**, so the CSIC-derived portion of
  per-category results inherits that circularity.

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

- Issue #8 — security / error analysis of the 92 false negatives
- Issue #9 — controlled inference benchmark
- Real HTTP laboratory validation
- Decision gate: a targeted V4.1 only if the evidence requires it, otherwise proceed to M2

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
| [`datasets/manifest_v4_clean.json`](datasets/manifest_v4_clean.json) | Dataset identity: hashes, seed, source commit, generation policy |
| [`CONTEXT.md`](CONTEXT.md) | Current technical state and immediate roadmap |
| [`DECISIONS.md`](DECISIONS.md) | Project decision log (D1–D24) |

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
