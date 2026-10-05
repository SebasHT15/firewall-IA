# firewall-IA

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python&logoColor=white)
![Model](https://img.shields.io/badge/Model-TinyLlama--1.1B-orange?logo=huggingface&logoColor=white)
![Fine-tuning](https://img.shields.io/badge/Fine--tuning-QLoRA%204--bit-green)
![Stage](https://img.shields.io/badge/Stage-first%20functional%20gateway-blue)
![Production](https://img.shields.io/badge/production--ready-no-lightgrey)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

**An authorized, inline, application-layer (HTTP L7) security gateway that classifies
each HTTP request with a fine-tuned TinyLlama model (V4) and enforces the decision,
fail-closed.**

This is a pre-thesis research project. It is **not production-ready**.

**Research direction (since 2026-10):** a **Hybrid Architecture** — deterministic request
features → a small learned **Lightweight Request Analyzer** (Model 1, **frozen**) → a **Small
Decision Model** (Model 2, not built) → TinyLlama V4 only as the fallback for uncertain cases.
Today V4 still makes every decision; see [§2](#hybrid-architecture--target-under-construction).

---

## 1. Purpose

firewall-IA sits in the path of HTTP traffic, asks a language-model classifier whether
each request should pass, and enforces the answer:

```
ALLOW | <reason>
BLOCK | <reason>
```

- **WAF-like, HTTP L7 only.** It inspects individual HTTP requests. It is **not** a
  replacement for a stateful network firewall, and it keeps no session state: every
  request is judged independently.
- **Authorized deployment.** The gateway is an authorized inline interception point, not a
  man-in-the-middle. All traffic in this repository — demo, diagnostics, External Test
  v1 — is generated inside a local lab against services the project owns.
- **Current runtime:** HuggingFace transformers + PEFT, loading the V4 QLoRA adapter
  (`model-output-v4-clean/`, checkpoint 2200) over TinyLlama-1.1B-Chat, on **CUDA**.
  GGUF / llama.cpp is **future work** (D23); the HF path is a functional baseline, not the
  deployment target.

---

## 2. Architecture

### Deployed today

```
client
  │  plain HTTP/1.1, explicit proxy
  ▼
data plane ─────────── mitmproxy addon (data_plane/data_plane.py)
  │  POST /classify {"request": "<raw HTTP text>"}
  ▼
control plane ──────── FastAPI (control_plane/classifier_api.py)
  │
  ▼
inference_core ─────── the single V4 pipeline (control_plane/inference_core.py)
  │                    TinyLlama-1.1B-Chat + V4 adapter, greedy decoding
  ▼
ALLOW / BLOCK ──────── back to the data plane, which enforces
  │
  ▼
protected destination  (reached only on ALLOW)
```

- **Data plane** — renders every request into the exact raw-text representation V4 was
  trained on (D1; unit-tested byte for byte against all 6,206 eval rows), sends it to the
  control plane and enforces the answer. It never loads the model.
- **Control plane** — `GET /health` (readiness via `model_loaded`, D28) and
  `POST /classify`. It classifies and reports; it does not enforce. An unparseable model
  output is reported as `status: "invalid"` and never coerced into a decision (D25).
- **inference_core** — the only owner of prompt, model loading, generation and parsing,
  imported by both the control plane and the evaluation harness so runtime and evaluation
  cannot drift apart.
- **Request feature extraction (Hybrid Architecture Phase 1, shadow mode)** — when the
  `data_plane.shadow_feature_extraction` switch is on, the data plane also describes each
  request as 34 deterministic features (`data_plane/request_features.py`, RequestFeatures v2)
  and only logs them. Nothing reads them: V4 still makes every decision, and enforcement and
  fail-closed are unchanged. `Host` and `User-Agent` are never features (D43, D44;
  [technical reference](docs/technical_reference.md#shadow-feature-extraction-hybrid-architecture-phase-1)).
  The data plane does **not** compute a heuristic suspicious score.
  *Terminology (D45):* **V4** is the current TinyLlama model; **V5** is a future TinyLlama
  revision (D37, D40), never the new architecture.
- **Two processes, two Python environments** (D33): mitmproxy's pins conflict with the ML
  stack, and the HTTP boundary between the planes is deliberate.

### Fail-closed enforcement (D4, D34)

| Classifier outcome | Client receives | Forwarded to destination |
|---|---|---|
| `status: ok` + `ALLOW` | the destination's response | **yes** |
| `status: ok` + `BLOCK` | `403` | no |
| `status: invalid` | `503` | no |
| timeout, connection failure, non-200, malformed response, unexpected addon error | `503` | no |

Nothing except a valid ALLOW reaches the destination. The classifier timeout (3 s) is an
operational failure limit that triggers fail-closed, not a latency target (D35).

### Hybrid Architecture — target, under construction

```
HTTP request → data plane (mitmproxy) → render_request() → RequestFeatures v2
  → control plane (FastAPI)* → Model 1: Lightweight Request Analyzer
  → Model 2: Small Decision Model → ALLOW / BLOCK / UNCERTAIN
        UNCERTAIN → TinyLlama V4 fallback → decision
  → data plane enforcement (fail-closed)
```
\*Where Models 1–2 will run is decided after measurement (D52).

| Component | Status |
|---|---|
| Request Feature Extraction (RequestFeatures v2) | **DONE** — shadow mode |
| Model 1 — Lightweight Request Analyzer | **FROZEN** — offline research artifact, not in the gateway |
| Model 2 — Small Decision Model | not implemented |
| Cascade orchestrator · UNCERTAIN routing · TinyLlama selective fallback | not implemented |
| Hybrid shadow integration · Hybrid enforcement | not implemented |
| External validation of the Hybrid system | pending |
| Embedded deployment | future |

**Model 1** (`hybrid-analyzer-v2/attack=hist_gb,category=hist_gb`) outputs
`attack = P̂(BLOCK | features)` (HistGradientBoosting, native probabilities) and an auxiliary
distribution over 8 attack categories given attack (context, not a decision). On the
feature-disjoint INTERNAL TEST view — a **second look**, not an untouched test — ROC-AUC
0.994, recall 0.959 and FPR 0.059 at the 0.5 reporting threshold; ≈ 8.9 ms per request. Its
limitations (encoding / path shortcuts, weak `ssrf` category, JWT blind spot) and the full
methodology: [`reports/hybrid/phase2b-analyzer-v2-run-002/`](reports/hybrid/phase2b-analyzer-v2-run-002/).
**External Test v1, its one aggregate post-freeze evaluation** (offline, D53):
ROC-AUC 0.943, Brier 0.127, ECE 0.126 (over-confident), and at the reporting-only 0.5 recall
188/200 and FPR 50/200 on this 50/50 test (`api-json` 29/40); the category head does not transfer
(top-1 74/200) —
[`reports/hybrid/analyzer-external-v1-run-001/`](reports/hybrid/analyzer-external-v1-run-001/).
Model 1 stays frozen; this is not a gateway or cascade result.
"Analyzer frozen" does not mean the Hybrid Architecture is finished.

---

## 3. Project status

### Implemented and verified

| Component | Evidence |
|---|---|
| **V4 classifier** — TinyLlama-1.1B-Chat + QLoRA 4-bit adapter, leakage-free V4-clean dataset | [§4](#4-v4-internal-evaluation), [`reports/v4_clean_eval.json`](reports/v4_clean_eval.json) |
| **FastAPI control plane** — `/health`, `/classify`, invalid outputs never coerced | unit tests; [technical reference](docs/technical_reference.md#control-plane-issue-15) |
| **mitmproxy data plane** — byte-exact V4 rendering, HTTP decisions | unit tests; [technical reference](docs/technical_reference.md#data-plane-issues-16-17--first-version) |
| **ALLOW / BLOCK enforcement** | `real-http-fp-v1` (48/48 forwarded, 30/30 → 403); External Test v1 L2 1,200/1,200 |
| **Fail-closed behaviour** | unit tests for every failure path; Docker smoke check D; demo stage 4 |
| **Controlled inference benchmark** `baseline-local-v1` (Issue #9) | [`reports/v4_inference_benchmark.md`](reports/v4_inference_benchmark.md) |
| **Docker Lab** — control plane on CUDA, data plane, destination, lab app | smoke checks A–E, [`reports/lab/docker-lab-v1/`](reports/lab/docker-lab-v1/) |
| **Real-HTTP diagnostic** `real-http-fp-v1` | [`reports/diagnostics/real-http-fp-v1/`](reports/diagnostics/real-http-fp-v1/) |
| **External Test v1** — frozen 400-case set, executed through the complete gateway | [§5](#5-external-test-v1), [`reports/external/external-v1-run-001/`](reports/external/external-v1-run-001/) |
| **Docker demo / smoke path** — `docker/demo.sh`, `docker/smoke_test.sh` | [§6](#6-demo); demo runtime-verified from a clean lab |
| **Request feature extraction, shadow mode** (Hybrid Architecture Phase 1, Issue #49) — describes requests, decides nothing | unit + gateway integration tests; live run with V4, shadow off vs on identical: [`reports/hybrid/phase1-feature-extraction-v2/`](reports/hybrid/phase1-feature-extraction-v2/) |
| **Lightweight Request Analyzer (Model 1), frozen offline** (Issues #51, #53; D46–D55) — not integrated into the gateway | [`reports/hybrid/phase2b-analyzer-v2-run-002/`](reports/hybrid/phase2b-analyzer-v2-run-002/); dataset `hybrid_analyzer_v2`, unit tests; External v1 aggregate evaluation [`reports/hybrid/analyzer-external-v1-run-001/`](reports/hybrid/analyzer-external-v1-run-001/) |

### Future — not implemented

- Fast path and heuristic suspicious score (D29 / D30, Issues #35–#38) — **deferred and
  optional**: not part of the current architecture, whose role is taken by RequestFeatures →
  learned Analyzer; may be evaluated later as a Model 2 feature if it adds value
- GGUF / Q4_K_M export and a llama.cpp runtime (M2)
- Embedded Linux deployment (M4)
- Formal end-to-end latency benchmark (Issue #18)
- HTTPS / TLS, HTTP/2 and WebSocket validation
- V5 — a possible TinyLlama revision for the external false positives found by External
  Test v1, to be decided after the V4 ↔ Analyzer disagreement analysis (External v2 required
  for any V5 claim, D40)
- Hybrid Architecture beyond Model 1: Small Decision Model, cascade orchestrator,
  UNCERTAIN → V4 fallback, gateway integration (see the status table in §2)
- Concurrency / load validation; adversarial / evasion suite (E6)

Nothing in this list works today.

---

## 4. V4 internal evaluation

**Dataset** (`datasets/v4_clean/`, E0 gate): 31,340 rows — 25,134 train / 6,206 eval — at
exactly 50% ALLOW / 50% BLOCK; exact train→eval leakage 0 / 6,206; 0 duplicates; 0
deterministic label reveals; strongest non-payload feature 51.16% against a 50% majority.
It replaced a corpus with 26.65% train→eval leakage in which the `Host` header alone scored
93.72%.

Held-out split of `datasets/v4_clean/`: **6,206 rows (3,103 ALLOW / 3,103 BLOCK)**.

| Metric | Value |
|---|---|
| Confusion matrix | TP 3,011 · FN 92 · FP 2 · TN 3,101 |
| Accuracy | 98.49% |
| Precision (BLOCK) | 99.93% |
| Recall / attack detection rate (BLOCK) | 97.04% |
| F1 (BLOCK) | 98.46% |
| False positive rate | ≈0.0645% (2 / 3,103) |
| False negative rate | 2.96% (92 / 3,103) |
| Invalid outputs | 0 |

> **This is an internal development evaluation, not an independent test.** The same split
> selected `checkpoint-2200` on `eval_loss` and produced these metrics (D24, D37). The
> population is synthetic plus CSIC-2010-derived requests rendered by the project's own
> generator. 91 of the 92 false negatives are SQL injection (74, recall 743/817) and command
> injection (17, recall 117/134). Of 19 attack categories, 8 have enough support to report
> (OK), 10 are INSUFFICIENT DATA and HTTP request smuggling is NOT EVALUABLE (0 eval rows).
> Detail: [`reports/v4_clean_baseline_results.txt`](reports/v4_clean_baseline_results.txt).

### Latency evidence — four classes, never pooled

| Class | Evidence | What it measures | Result |
|---|---|---|---|
| **A. Preliminary diagnostic** | Issue #15 control-plane check | `generate()` time, model warm | model load ≈ 2.4 s on CUDA · first inference 512.8 ms (kept separate) · steady state n = 30: mean 211.5 · P50 232.5 · min 159.5 · max 241.9 ms |
| **B. Formal inference benchmark** | `baseline-local-v1` (Issue #9): 3 fresh processes × 6,206 = 18,618 classifications, RTX 4090 Laptop GPU, batch 1 | `generate()` and the full inference pipeline, steady state; cold start and warm-up reported separately | `generate()`: mean 227.86 · P50 238.82 · **P95 269.01** · P99 275.90 ms · pipeline **P95 269.58 ms** |
| **C. External v1 observational timing** | `external-v1-run-001` (derived, not a benchmark) | gateway `model_latency_ms` = **data-plane wall time around `POST /classify`** · direct `model_latency_ms` = **control-plane `generate()`-only time** — different quantities | gateway n = 1,200: P50 220 · P95 255 ms · direct n = 300: P50 193.10 · P95 247.89 ms |
| **D. Formal end-to-end benchmark** | Issue #18 | client → gateway → destination | **pending — not measured** |

**The Decision D36 target — P95 of the steady-state inference pipeline ≤ 200 ms — is not
met (269.58 ms, class B).** Cold start and warm-up are never pooled into steady state; the
n = 30 run is not the benchmark; the two class-C series cover different populations (400
vs 100 cases) and scopes, so they are neither pooled nor compared as the same measurement;
nothing in A–C is end-to-end latency. Details:
[`reports/v4_inference_benchmark.md`](reports/v4_inference_benchmark.md) ·
[technical reference](docs/technical_reference.md#external-test-v1--latency-observations-derived) ·
[`CONTEXT.md` Q4](CONTEXT.md#q4-latency--four-experiments-never-merged).

---

## 5. External Test v1

An independent external evaluation of V4 and of the complete gateway, designed to measure
generalization and sensitivity to distribution shift on inputs V4 never saw. Protocol:
[`docs/external_test_v1_protocol.md`](docs/external_test_v1_protocol.md).

### Methodology

1. **Capture before exposure.** Real clients (Chromium via Playwright, `httpx`, `curl`)
   drove a purpose-built lab application inside the Docker Lab through a capture-only
   proxy — no classifier in the path. 489 requests captured (plus a documented 15-request
   pre-freeze supplement for one browser slice).
2. **Ground truth before exposure**, from the intent of the flow that produced each
   request, never from V4. Two-pass review; ambiguous cases excluded, not guessed (2 SSRF).
3. **Independence gate.** Zero exact and zero canonical collisions against V4 train + eval
   (31,340 rows), `real-http-fp-v1` and the Docker smoke fixtures; 0 near-duplicate
   warnings; 16 internal duplicates (5 exact groups) excluded. Capture/replay fidelity was
   verified beforehand: `curl` 8/8 and Chromium 12/12 byte-exact through the capture proxy
   ([evidence](reports/external/external-v1-phase-b-fidelity/)).
4. **Deterministic freeze.** From 484 eligible cases, exactly 40 per cell selected by a
   seeded content-independent key (`SHA256(seed|cell|case_id|request_sha256)`, seed
   `external-v1-freeze-v1`), frozen at commit **`36df2ee`** — 400 unique case ids, 400
   unique request SHA-256, 84 reserves kept as evidence, integrity hash `ccac5f55…`. V4
   exposure before freeze: **zero**. The set is immutable; any change requires External v2.
5. **400 cases, 200 ALLOW / 200 BLOCK, 10 cells × 40:**
   benign `browser-navigation`, `browser-forms-session`, `api-json`, `api-query`,
   `unseen-structure`; attack SQL injection, command injection, XSS, path traversal, SSRF.
6. **Execution** (`external-v1-run-001`, runner anchored at `9656df9`): 400 cases × 3
   repetitions = 1,200 requests through the complete gateway, plus a predeclared 100-case
   subset × 3 sent directly to `/classify` as a consistency control.
7. **Three levels, never merged:**
   **L1** model quality (ground truth vs V4) ·
   **L2** gateway enforcement (V4 decision vs data-plane behaviour) ·
   **L3** end-to-end outcome (ground truth vs delivery to the destination).

### Results

**L1 — model** (gateway channel, repetition 1; no nondeterministic cases)

| n | TP | TN | FP | FN | Invalid |
|---:|---:|---:|---:|---:|---:|
| 400 | 199 | 132 | 68 | 1 | 0 |

| Accuracy | Precision (BLOCK) | Recall / ADR (BLOCK) | F1 (BLOCK) | FPR | FNR |
|---|---|---|---|---|---|
| 82.75% (331/400) | 74.53% (199/267) | 99.50% (199/200) | 85.22% | 34.00% (68/200) | 0.50% (1/200) |

| Benign slice | FP / 40 | FPR | | Attack category | External recall | Internal V4 recall |
|---|---:|---:|---|---|---:|---:|
| browser-navigation | 7 | 17.5% | | SQL injection | 40/40 | 90.94% (743/817) |
| browser-forms-session | 4 | 10.0% | | Command injection | 40/40 | 87.31% (117/134) |
| api-json | 21 | 52.5% | | XSS | 40/40 | 100% |
| api-query | 12 | 30.0% | | Path traversal | 40/40 | 100% |
| unseen-structure | 24 | 60.0% | | SSRF | 39/40 | 98.41% (62/63) |

59 of the 68 false positives fall in `api-json`, `api-query` and `unseen-structure`.

**Zero-error results and the pre-registered rule-of-three bound.** SQL injection, command
injection, XSS and path traversal are each **observed at 40/40 = 100% recall**; that observed
value stands as recorded. Separately, protocol §3 requires a zero-error rate to carry the
methodology's approximate zero-event bound: an upper bound on the miss rate of
**≈ 3/40 = 7.5%**, equivalently an approximate 95% lower bound on recall of **≈ 92.5%**. The
same rule applies to invalid outputs: observed 0/400, approximate upper bound 3/400 = 0.75%.
This is the rule of three, not an exact confidence interval.

**Secondary breakdowns** (pre-registered, not headline): by `client_profile`, `host_type`,
`method` and `body_type`, with numerator, denominator and support status for every rate —
[`reports/external/external-v1-secondary-breakdowns/`](reports/external/external-v1-secondary-breakdowns/secondary_breakdowns.md).
`route_family` is pre-registered but not produced (it would need a post-exposure choice).

**L2 — enforcement:** 1,200 / 1,200 conformant. **Direct vs gateway:** 100 / 100 decision
agreement on the predeclared 100-case subset (decision consistency, not byte equivalence).
**Nondeterminism:** 0 (gateway and direct). **Execution errors:** 0.

**L3 — end to end:** benign delivered 132 · benign broken 68 · BLOCK-labelled stopped
199 · BLOCK-labelled delivered 1. "Delivered" means the request reached the lab app; it
does **not** mean exploitation.

**Interpretation.** V4 keeps very high external BLOCK recall, but shows a substantial
external generalization gap on benign traffic, concentrated in API and unseen-structure
requests. The gateway itself behaved correctly: every decision the data plane received was
enforced as specified, and on the predeclared subset the direct and gateway decisions agreed.
No cause of the false positives is claimed.

Evidence: frozen set [`datasets/external_v1/`](datasets/external_v1/) · run
[`reports/external/external-v1-run-001/`](reports/external/external-v1-run-001/)
([`summary.md`](reports/external/external-v1-run-001/summary.md),
[`summary.json`](reports/external/external-v1-run-001/summary.json)).

---

## 6. Demo

Requirements: NVIDIA GPU with the NVIDIA Container Toolkit, the V4 adapter in
`model-output-v4-clean/` and the TinyLlama base in the local HuggingFace cache — neither
is distributed by this repository. Details: [`docker/README.md`](docker/README.md#demo).

```bash
docker compose build
```

```bash
./docker/demo.sh
```

Under a minute once images are built; add `--step` to pause between stages. The script cleans the lab
(containers and network only), starts it, and shows:

```
[1/5] startup      /health model_loaded: true, V4 on CUDA, gateway policy fail-closed
[2/5] ALLOW        benign request            → 200, destination receives it
[3/5] BLOCK        SQL injection test request → 403, destination receives nothing
[4/5] fail-closed  control plane stopped     → 503, destination receives nothing
[5/5] recovery     control plane restarted   → benign request works again
DEMO PASS
```

It reuses the validated smoke fixtures — **not** External Test v1 cases — and fails loudly
(`DEMO FAIL`, non-zero exit) on any unexpected result. The canonical infrastructure check
remains `./docker/smoke_test.sh`.

---

## 7. Interpretation limits

- **External Test v1's 34% FPR is not a production FPR.** It is 68 of the 200 benign cases
  in this test: one lab application, a 50/50 class balance fixed by construction, and five
  pre-declared benign slices. Operational FPR, precision and accuracy depend on real
  traffic mix and will differ.
- **External Test v1 does not prove overfitting.** It shows an external generalization
  gap; its cause has not been analysed.
- **External Test v1 is not formal OOD detection.** V4 emits no confidence or novelty
  score. `unseen-structure` is a robustness slice of inputs with little or no support in
  the V4 corpus, nothing more.
- **Latency figures seen in these runs are not the Issue #18 benchmark.** `model_latency_ms`
  in External v1 records, smoke logs and demo output are incidental observations, and all
  measured V4 latency is inference-side, not end-to-end (§4). The Decision D36 objective — P95 of the
  inference pipeline ≤ 200 ms in steady state — is **not met** (`baseline-local-v1`:
  269.58 ms).
- **External v1 has no direct byte-level evidence of what the classifier received.** The
  preregistered proxy-to-`/classify` byte-equivalence check (protocol §11) was not executed
  in `external-v1-run-001` because the data-plane runtime did not contain `strace`. Earlier
  capture/replay and diagnostic byte checks are supporting evidence only, and the 100/100
  direct-vs-gateway result is decision agreement, not proof of byte equivalence. No
  recorded result or frozen artifact changes; External v2 must restore the check. Details:
  the protocol's status note.
- **External v1's pre-registered CSIC-ancestry warning check was not run.** Check 7 of the
  protocol's gate (a non-blocking substring screen against the raw CSIC data) was not
  implemented; the exact and canonical collision checks against V4 train + eval, which
  contain the CSIC-derived V4 rows, were. It changes no frozen case or recorded result, is
  not reconstructed after exposure, and is required in External v2.
- **The V4 internal metrics are not an independent test** (§4).
- **`real-http-fp-v1`'s 37/149 is a diagnostic count, not an FPR** — the case mix was built
  to provoke failures.
- **The demo and smoke checks are plumbing.** A handful of fixed requests; no model metric
  may be derived from them.

## Known limitations

- External Test v1 benign FPR **68/200 = 34% on this test**, highest in `api-json` (52.5%)
  and `unseen-structure` (60%)
- Decision D36 latency objective (P95 inference pipeline ≤ 200 ms) **not met** — 269.58 ms
- Formal end-to-end latency benchmark (Issue #18) pending
- HTTPS / TLS, HTTP/2 and WebSockets not validated; plain HTTP/1.1 through an explicit proxy only
- GGUF / llama.cpp not integrated; runtime is HF/PEFT on CUDA
- Fast path not implemented (deferred)
- Hybrid Architecture: only feature extraction (shadow) and an offline, frozen Model 1 exist;
  Model 1's FPR (≈ 0.06 on the internal second look) is far above V4's internal one; on External
  Test v1 (offline, aggregate) its ROC-AUC drops to 0.943, its probabilities are over-confident
  (ECE 0.126), FPR at the reporting-only 0.5 is 50/200 (`api-json` 29/40), header / cookie
  payloads are invisible to it (0/5) and its category head does not transfer
- Concurrency untested — one GPU serializes inference; no evasion / adversarial suite
- **Not production-ready**

**Not yet measured:** end-to-end latency (Issue #18), concurrency and behaviour under load,
throughput, a formal RAM / VRAM / CPU / GPU benchmark, HTTPS / HTTP/2 / WebSockets,
fast-path metrics, a GGUF / llama.cpp comparison, embedded hardware.

Full list: [`docs/technical_reference.md`](docs/technical_reference.md#known-limitations).
Every metric with its source and status:
[`CONTEXT.md` — quantitative snapshot](CONTEXT.md#quantitative-snapshot--v010-every-metric-with-its-source).

## Next steps

Done so far on the Hybrid Architecture (merged into `develop`):
**Phase 1** (Issue #49) request feature extraction ·
**Phase 2A** (Issue #51) Analyzer design frozen, D46–D53 ([report](reports/hybrid/phase2a-analyzer-design/)) ·
**Phase 2B** (Issue #53) Model 1 frozen ([run-002](reports/hybrid/phase2b-analyzer-v2-run-002/)).
Run-001 ([report](reports/hybrid/phase2b-analyzer-baselines/), [errata](reports/hybrid/phase2b-analyzer-baselines/ERRATA.md))
is kept as history: a TRAIN / VALIDATION generator-family leak found after its first INTERNAL
TEST look was corrected by D54, and INTERNAL TEST has since been read a second time.

Next, in order (detail and constraints: [`CONTEXT.md` §0.9](CONTEXT.md#09-next-steps-start-here-do-not-reopen-phase-2b-except-for-an-objective-bug)):

1. ~~One aggregate post-freeze evaluation of Model 1 on External Test v1~~ — **done**
   ([`analyzer-external-v1-run-001`](reports/hybrid/analyzer-external-v1-run-001/)); it shows
   aggregate behaviour only and does **not** show that a V4 + Analyzer cascade would help (no
   joint count; different operating points). Model 1 stays frozen.
2. **Disagreement analysis, TinyLlama V4 vs Model 1** — first diagnostic done on development data
   (issue #57, [`v4-analyzer-disagreement-v1`](reports/hybrid/v4-analyzer-disagreement-v1/)). A low
   Analyzer score is not shown to be a safe override of a V4 BLOCK: on texts it never saw, it scores
   10 attacks V4 blocks below 0.1. V4's header-flip false positives are invisible to it by design
   (D44). **The false-negative risk of a cascade cannot be estimated with the data we may use.**
   Recommendation (pending owner review): **C**, i.e. build a development diagnostic set with
   attacks, then test B (new features), V5 and a V4-reason-aware Model 2. External v1 cases stay
   unused.
3. Decide with evidence whether TinyLlama needs a V5 / hard-negative revision (External v2
   required for any V5 claim, D40).
4. **Model 2 — Small Decision Model**, then ALLOW / BLOCK / UNCERTAIN policy, cascade
   orchestrator, Hybrid shadow mode, Hybrid enforcement, end-to-end evaluation, a new
   independent external set.
5. Also open: Issue #18 (end-to-end latency), M2 (GGUF / llama.cpp), then embedded deployment (M4).

## Security and engineering references

firewall-IA is **informed by selected practices** from the frameworks below, used as
reference frameworks and design guidance. **It is not certified against, and does not claim
compliance or conformity with, any of them.** Only controls with evidence in this repository
are described as implemented.

- **Requirements engineering:** ISO/IEC/IEEE 29148:2018 — the main reference for *system*
  requirements (gateway, data plane, control plane, ML classifier, runtime, future embedded
  hardware) — with EARS syntax for normal, unwanted and failure behaviour. 29148 is a
  requirements standard, not a security certification.
- **Application / web security:** OWASP Top 10, OWASP API Security Top 10, OWASP ASVS, and
  the OWASP Core Rule Set as the traditional rule-based WAF reference and a possible future
  comparator (D9). firewall-IA does not implement CRS.
- **Cybersecurity and AI risk:** NIST CSF 2.0, NIST AI RMF 1.0, NIST SSDF (SP 800-218),
  ISO/IEC 27001 / 27002 / 27005, ISO/IEC 42001, ISO/IEC 23894, CIS Controls, MITRE CWE.

**Implemented and evidenced:** fail-closed enforcement, separation of classifier decision
from enforcement, no silent ALLOW on invalid responses, frozen external evaluation before
model exposure, L1/L2/L3 separation, no online learning, preserved raw evidence.
**Future work, not implemented:** least-privilege hardening, API authentication, rate
limiting, SIEM telemetry, formal threat modelling, HTTPS / HTTP/2 / WebSocket validation,
embedded hardening. Full mapping:
[`CONTEXT.md`](CONTEXT.md#security-and-engineering-references--alignment-not-compliance).

---

## Repository layout

```
control_plane/       classifier_api.py, inference_core.py          FastAPI + the V4 pipeline
data_plane/          data_plane.py                                 mitmproxy inline gateway
                     request_features.py, hybrid_contracts.py      Hybrid Architecture Phase 1: shadow feature extraction, stage contracts
scripts/dataset/     V4 dataset generation and the E0 integrity gate
scripts/training/    finetune.py; hybrid_analyzer.py, run_hybrid_analyzer_baselines.py (Analyzer research, own env)
scripts/evaluation/  test_model.py (frozen E5 scorer)
scripts/benchmarks/  inference benchmark and comparison tools
scripts/external/    External Test v1 capture, labelling, gate, freeze and run tooling
tests/               unit tests
docs/                methodology, External v1 protocol, technical reference
datasets/            manifest_v4_clean.json, manifest_hybrid_analyzer_v{1,2}.json (JSONL regenerated locally); external_v1/ (frozen)
reports/             experiment records: benchmarks/, diagnostics/, lab/, external/, hybrid/, E0–E5
compose.yaml         Docker Lab stack
docker/              per-service images, config override, smoke_test.sh, demo.sh
```

Run everything from the repository root.

## Documentation map

| Path | Contents |
|---|---|
| [`CONTEXT.md`](CONTEXT.md) | **§0: current state and handoff (read first)**; then the audit trail, full latency evidence, standards mapping |
| [`DECISIONS.md`](DECISIONS.md) | Append-only decision log (D1–D55) |
| [`docs/technical_reference.md`](docs/technical_reference.md) | Control plane, data plane, benchmark, dataset, full limitations |
| [`docs/ml_evaluation_methodology.md`](docs/ml_evaluation_methodology.md) | Evaluation rules: data roles, metrics, diagnostics vs benchmarks, latency layers |
| [`docs/external_test_v1_protocol.md`](docs/external_test_v1_protocol.md) | External Test v1 methodology, pre-registered before the data |
| [`docker/README.md`](docker/README.md) | Docker Lab: prerequisites, services, smoke test, demo |
| [`datasets/external_v1/`](datasets/external_v1/) | Frozen External Test v1: cases, manifest, hashes, gate and review evidence |
| [`reports/external/external-v1-run-001/`](reports/external/external-v1-run-001/) | External Test v1 execution: raw records, logs, L1/L2/L3 summary |
| [`reports/lab/docker-lab-v1/`](reports/lab/docker-lab-v1/) | Docker Lab closure report and raw smoke logs |
| [`reports/diagnostics/real-http-fp-v1/`](reports/diagnostics/real-http-fp-v1/) | Real-HTTP diagnostic: cases, raw records, process logs |
| [`reports/benchmarks/`](reports/benchmarks/) | Inference benchmark; `baseline-local-v1` is the frozen reference |
| [`reports/hybrid/`](reports/hybrid/) | Hybrid Architecture: Phase 1 shadow-mode live run and extractor overhead (`phase1-feature-extraction-v2` current, `-v1` superseded); Phase 2A Analyzer design; Phase 2B run-001 (`phase2b-analyzer-baselines`, not adopted; see its ERRATA) and run-002 (`phase2b-analyzer-v2-run-002`, Analyzer frozen); the one aggregate External v1 evaluation of the frozen Analyzer (`analyzer-external-v1-run-001`); the V4 ↔ Analyzer disagreement diagnostic on development data (`v4-analyzer-disagreement-v1`, issue #57) |
| [`datasets/manifest_v4_clean.json`](datasets/manifest_v4_clean.json) | V4 dataset identity: hashes, seed, source commit |
| [`docs/data_sources.md`](docs/data_sources.md) | Data not distributed by v0.1.0 (CSIC CSV, historical corpora): sizes, SHA-256, regeneration inputs, retained excerpts |
| [`LICENSE`](LICENSE) | MIT License for this repository's original code and documentation (third-party material excluded — see [License](#license)) |

## Tests

```bash
python3.12 -m unittest discover -s tests
```

```bash
.venv-dataplane/bin/python -m unittest tests.test_data_plane tests.test_external_capture tests.test_lab_app tests.test_latency_observations tests.test_request_features
```

```bash
.venv-analyzer/bin/python -m unittest tests.test_hybrid_analyzer_model tests.test_hybrid_analyzer_dataset tests.test_hybrid_analyzer_dataset_v2 tests.test_request_features tests.test_analyzer_external_v1 tests.test_v4_analyzer_disagreement
```

`tests.test_v4_analyzer_disagreement` (12 tests) and `tests.test_analyzer_external_v1` (48 tests)
are synthetic only and guarded against opening External Test v1; both need `.venv-analyzer`
(elsewhere 10 and 47 of their tests skip).

After Hybrid Architecture Phase 2B run-002 (2026-10-04): **ML environment — 333 tests
discovered, 309 passed, 24 expected skips** (the three mitmproxy/Flask modules and the 21
Analyzer model tests, which need scikit-learn); **data-plane environment — 117/117 passed**
(those three modules, `tests.test_latency_observations` and `tests.test_request_features`,
which needs only the standard library and runs in both); **Analyzer research environment — 91
tests, 83 passed, 8 expected skips** (the `hybrid_analyzer_v2` rebuild tests, which need the V4
generator's pandas and run in the ML environment; setup in
[the run-002 report](reports/hybrid/phase2b-analyzer-v2-run-002/README.md#12-reproduce--files-and-hashes)).
The dataset tests need the locally regenerated V4-clean (and, for v2, `csic_database.csv` and
PayloadsAllTheThings). After run-001 they were 316 / 297 / 19, 117 / 117 and 74 / 74; after
Phase 2A 286 / 283 / 3 and 117 / 117; after Phase 1 281 / 278 / 3 and 112 / 112; at stage close 242 / 239 / 3 and
61 / 61. The first command runs in the ML
environment; the second runs the skipped modules in the data-plane environment (setup:
[technical reference](docs/technical_reference.md#setup-once)). Use `python3.12`
explicitly — on the development machine `python3` is 3.14 without the ML stack.

Environment: Python 3.12, torch 2.6.0+cu124, transformers 5.8.0, TRL 1.4.0, PEFT 0.19.1,
bitsandbytes 0.49.2, RTX 4090 Laptop GPU.

## License

[MIT](LICENSE) — Copyright (c) 2026 SebasHT15.

Original source code and documentation in this repository are licensed under the MIT License
unless otherwise noted. Third-party models, datasets, libraries, and other external artifacts
remain subject to their respective licenses and terms.

The MIT License does not relicense any of the third-party material listed under
[Credits](#credits) — including the TinyLlama base model, the CSIC 2010 data, payloads drawn
from PayloadsAllTheThings, or the libraries, tools and container base images the project
uses. The raw CSIC data and the historical corpora are not distributed by this release; see
[`docs/data_sources.md`](docs/data_sources.md).

## Credits

- Attack payloads for V4 training: [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) by [@swisskyrepo](https://github.com/swisskyrepo), commit `e961fef`.
  Not vendored: V4 regeneration reads a separate local clone
- CSIC 2010 HTTP dataset (Spanish Research National Council), re-rendered into the V4 representation.
  **Not distributed by v0.1.0:** the raw `csic_database.csv` and the historical root
  `train.jsonl` / `eval.jsonl` (derived from it and PayloadsAllTheThings) are kept out of the
  tree; V4 regeneration needs a local copy verified by SHA-256 — see
  [`docs/data_sources.md`](docs/data_sources.md). Two short CSIC-derived request excerpts remain
  in `reports/diagnostics/real-http-fp-v1/cases.jsonl` as experimental evidence, subject to
  their source's terms
- Remaining training data generated by `parse_dataset_v4.py`; see [dataset sources](docs/technical_reference.md#dataset-sources)
- Base model: [TinyLlama-1.1B-Chat-v1.0](https://huggingface.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0),
  subject to its own license. Neither the base model nor the V4 adapter trained on it
  (`model-output-v4-clean/`) is distributed by this repository
- Fine-tuning stack: [HuggingFace PEFT](https://github.com/huggingface/peft) + [TRL](https://github.com/huggingface/trl);
  runtime and lab dependencies (`requirements*.txt`, `docker/*/requirements.txt`) and container
  base images are installed from their upstream sources under their own licenses
