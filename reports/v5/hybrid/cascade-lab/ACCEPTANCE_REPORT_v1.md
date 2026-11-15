<!-- PRIOR VERSION — preserved verbatim as reviewed (Codex, 2026-10-30). Superseded
by ACCEPTANCE_REPORT.md, which corrects the provenance of §4/§5 numbers (E5 PRINCIPAL
view as headline, call-avoidance vs latency separated, throughput vs goodput). This
file is kept only for the review audit trail; do not cite its numbers. -->

# Firewall-IA — Hybrid Cascade: lab integration & staged acceptance report

**Date:** 2026-10-27 (Costa Rica). **Branch:** `feat/hybrid-cascade-integration`
(base HEAD `499c8b2`). **Scope:** implement, connect and test *in an isolated lab*
the PDF cascade `WIRE HTTP → parser/framing/canonicalization → Fast Path → C1 →
Model 2 → V5`, reusing the parallel work. **Not** a deployment, **not** a security
certification, **not** an operational authorization. No protected set
(INTERNAL_TEST / STAB-HELD / E6 / external) was read or consumed. No training was
re-run, no ratified dataset/recipe/threshold was changed, no issue is closed here.

All new code is in **new files only** — `git diff --stat HEAD` is empty, so the
hash-bound Model 2 sources, the trained artifacts and every existing test are
untouched (the Model 2 `source_sha256` / FINAL-evidence gate still passes).

---

## 1. Artifacts verified (before any integration)

| Model | Artifact | SHA-256 verified | Load/verify | Real-weight check |
|---|---|---|---|---|
| V5 FINAL | `model-output-v5/final/v5-final-v4-20261027T022649Z/adapter` | `c27e363f…` (matches record) | base `TinyLlama-1.1B` rev `fe8a4ea` (4-bit nf4+dq) + LoRA loaded; **template fingerprint `ad93d3b6…` reproduced**; token contract re-measured (overhead 76, label 13, **B=415**) | benign→ALLOW, SQLi→BLOCK, traversal→BLOCK, XSS→BLOCK — all EOS-terminated, in-vocabulary |
| Model 2 baseline34 | `model-output-model2/final/v4-d82-20261027T052308Z/baseline34.json` | `da6f6eb8…` (matches) | `training.load_artifact` **full FINAL evidence check PASSED** in `.venv-analyzer` (numpy 2.5.3 / sklearn 1.9.1, matching recorded `library_versions`) | scorer reproduces p_block; SQLi 0.94, benign 0.02 |
| Model 2 path-ablation32 | `…/path-ablation32.json` | `6fda4fa0…` (matches) | same, feature_view `target-path-neutralized/v1` | — |

Dataset manifest bound in both Model 2 artifacts:
`c2e9c2f5…` (V5 v4). `operating_threshold=null`, `operational_policy_approved=false`
in both (by construction — the policy is separate, §3).

**Environments** (no single interpreter has everything): V5 inference →
`/usr/bin/python3.12` (torch 2.6.0+cu124 / transformers 5.8.0 / peft 0.19.1,
CUDA RTX 4090 16 GB); Model 2 FINAL load+score → `.venv-analyzer`; data-plane /
canonicalization / Fast Path / router → `.venv-dataplane` (stdlib) or
`.venv-analyzer`.

---

## 2. What was built (all reused the existing modules, none reimplemented)

| New module | Role | Reuses |
|---|---|---|
| `control_plane/v5_inference_core.py` | shared V5 pipeline (recipe→template/vocab/contract, 4-bit load, template-safe encode, bounded greedy gen, strict parse, per-stage timing, readiness/hashes) | `v5_tokenization.encode_prompt`, `v5_output_contract.parse_v5_output`, `v5_train_data` recipe helpers |
| `control_plane/v5_classifier_api.py` | V5 HTTP service on the **canonical** text; readiness/contract/hashes; GPU lock; bounded in-flight → 503; acquire timeout. Separate service; V4 untouched for comparison/reversion | `v5_inference_core` |
| `data_plane/http1_wire.py` | strict HTTP/1.1 **wire parser + framing validation**; de-chunking; rejects TE+CL, multiple CL, non-chunked TE, folding, short body → fail-closed | `canonical_request.RequestParts`, `fast_path.FramingEvidence` |
| `data_plane/model2_policy.py` | **separate, versioned, model-bound** BLOCK/DEFER policy (`p_block≥threshold`→BLOCK); no implicit 0.5; `LAB_EXPERIMENTAL`/`APPROVED` | — |
| `data_plane/model2_decider.py` | runtime BLOCK/DEFER stage; **fail-to-defer** on missing/unbound policy, non-ACCEPT canonical, scoring failure | `training.load_artifact` + `training.score` (ratified scorer) |
| `data_plane/cascade.py` | **pure** transport-independent router; modes V4_ONLY / V5_ONLY / CASCADE_OBSERVE / CASCADE_ACTIVE; one applied action + stage trace per request | — |
| `data_plane/cascade_runtime.py` | snapshot builder (canonicalize **once**, V5 budget), Fast Path input adapter, V5/V4 HTTP clients (fail-closed), in-process V5 client | `canonical_request`, `fast_path` |
| `scripts/cascade_lab/lab_server.py` | isolated lab: raw-socket HTTP/1.1 gateway + controlled upstream; single-owner parse-and-forward; enforces FORWARD/DENY; JSONL per request (no payloads) | all of the above |
| `scripts/cascade_lab/{make_dev_sample,run_cascade,metrics,integration_check,operational_check}.py` | dev sampler, paired driver, metrics, real-route verification, load test | — |

### Shared representation and routing (matches the PDF)
One canonical snapshot per request (`canonical_request.canonicalize`, size bounded
by B with the byte reverse-bound; exact B re-checked at the V5 boundary). Both
Model 2 (`score`) and V5 (`encode_prompt`) consume the **same** `CanonicalResult.text`
— not V4's D1 render. Routing (active):
`REJECT/UNSUPPORTED→DENY(protocol)` · `FAST_ALLOW→forward (no model call)` ·
`CONTINUE→Model 2` · `Model 2 BLOCK→DENY (no V5 call)` · `DEFER/any-non-OK→V5` ·
`V5 ALLOW→forward` · `V5 BLOCK→DENY` · `V5 invalid/error/timeout→DENY (never ALLOW)`.
Model 2 never emits ALLOW; the Model 2 score is never placed in the V5 prompt.

### Fast Path framing delta (why FAST_ALLOW is real here, not a renamed match)
In the lab a **single owner** reads the exact client bytes and forwards those exact
bytes to the controlled upstream, so "the bytes decided are the bytes delivered"
holds by construction — there is no proxy whose framing could diverge. A clean
parse of one unambiguously-framed HTTP/1.1 message yields
`FramingEvidence(VERIFIED)`, and with the lab positive policy
(`fast_path_lab_app.json`, a **synthetic** app — `/healthz`, `/status?page=<uint>`,
Host `lab.local`) FAST_ALLOW actually fires. **Scope: HTTP/1.1 over a local socket
only.** This says nothing about HTTP/2, TLS termination, or a deployment behind a
separate proxy, and it is *not* the mitmproxy D70 profile control.

---

## 3. Status ladder (honest separation)

- **Implemented:** every module in §2.
- **Tested with doubles (44 unit tests, all pass):**
  `test_cascade_router` (16 — every branch, fail-closed, modes, no-double-V5-call),
  `test_model2_policy` (10), `test_http1_wire` (13 — framing branches),
  `test_cascade_lab` (5 — **real sockets**, doubles for models: FORWARD reaches
  upstream, DENY/malformed do not).
- **Tested with real models (over real sockets):** `integration_check.py` —
  **ALL ROUTES OK**: FAST_ALLOW (forwarded, no Model 2/V5 call), Model 2 BLOCK
  (traversal p=0.90 → 403, **V5 not called**, upstream not reached), DEFER→V5 ALLOW
  (benign forwarded), DEFER→V5 BLOCK (SQLi p=0.66 → V5 BLOCK → 403), protocol
  reject (TE+CL → 400). Exactly 2 of 5 reached the upstream.
- **Measured:** the evaluation matrix of §4 (real V5 + real Model 2 on 600 dev
  requests) and the operational run of §5.
- **Pending / blocked:** see §6.

---

## 4. Evaluation matrix (measured — DEVELOPMENT data)

**Population & provenance.** 600 requests sampled (seed 20261026) from `eval.jsonl`
— the committed, **non-protected** legacy V4-era labeled set. This is DEVELOPMENT
traffic for **mechanism, route and cost** measurement; it may overlap V5 training
sources and **13 of 19 categories are outside V5's 6-category vocabulary**, so it is
**not** a generalization or security headline. Of 600: **22** are not valid
HTTP/1.1 request-lines (raw spaces in the target) → rejected at the wire stage
(correct protocol behavior); **578 ACCEPT** (300 ALLOW / 278 BLOCK reach the
models). Positive class = BLOCK. Percentiles nearest-rank, no outliers removed.
Full raw per-request data: `results/dev_paired_v1.jsonl`; summary + CSVs in
`results/metrics_v1/`.

### 4a. V5-only (binary; measured)
TP 185 · TN 297 · FP 3 · FN 89 · invalid 4 → **precision 0.984, recall 0.675,
FPR 0.010, F1 0.801, invalid-rate 0.0069**. (Low recall is dominated by the
out-of-vocab categories V5 was never trained to name; invalid counts as error
under E5, not a correct decision.)

### 4b. Model 2 — selective metrics (measured; DEFER is not FN; no ALLOW class)
| candidate | threshold | early-block FP | attack early-block | BLOCK precision | DEFER rate |
|---|---|---|---|---|---|
| baseline34 | 0.9 (lab) | **8/300 = 2.67%** | **117/278 = 42.1%** | **0.936** | 0.784 |
| path-ablation32 | 0.9 (lab) | 10/300 = 3.33% | 97/278 = 34.9% | 0.907 | 0.815 |

baseline34 dominates the ablation on the same rows (more attacks caught early,
fewer benign early-blocked, higher BLOCK precision) — consistent with the request
path carrying signal. **No operational winner is declared** (uncalibrated lab
threshold, no ratified early-block FP budget, no protected evaluation).

### 4c. Cascade (binary applied; Fast Path CONTINUE; measured)
| cascade | precision | recall | FPR | F1 | V5 calls | V5 calls avoided | Model 2 early-block |
|---|---|---|---|---|---|---|---|
| +baseline34 | 0.948 | **0.721** | 0.037 | 0.819 | 453/578 | **125 (21.6%)** | 125 |
| +ablation32 | 0.937 | 0.703 | 0.043 | 0.803 | 471/578 | 107 (18.5%) | 107 |

### 4d. Complementarity & cost (the headline question)
Cascade(baseline) vs V5-only, same requests: Model 2 correctly early-blocks **117**
attacks — **12** of which **V5 would have missed** (ALLOW) and 103 V5 would also
catch — while early-blocking **8 benign** that V5 would have allowed.
Net binary effect: **recall 0.675→0.721** (+4.6 pts) at the price of **FPR
0.010→0.037** and **precision 0.984→0.948**, plus **21.6% of V5 calls avoided**.
So under this lab threshold the cascade buys recall + compute savings with a higher
false-block rate — a real, visible tradeoff, **conditioned on an uncalibrated
threshold** with no ratified FP budget.

**Latency (measured ms, per stage; P95/P99 per-request, never summed):**
canonicalization mean 0.05 / p95 0.07 · Fast Path 0.01 / 0.02 · Model 2 score
(baseline) 0.10 / 0.13 · **V5 generate mean 263.8 / p50 282.7 / p95 292.7 / p99
297.7** (model-side generate only — **not** the D36 pipeline, observed during eval,
not the controlled D31/D36 benchmark).
**Derived** active-cascade mean (baseline, FP CONTINUE) =
`canon+fp+m2 + 0.784·v5_generate ≈ 206.9 ms` vs V5-only 263.8 ms → **≈21.6%
reduction** (derived from measured stages; assumes mutually-exclusive routes and no
extra rejects).

---

## 5. Operational / load (measured — `results/operational_v1/`)

- **Cold start:** V5 model load **3.9 s** (recorded at service startup).
- **Concurrency (1 GPU, 48 benign requests):** workers 1 → 3.5 rps, p95 297 ms;
  workers 4 → 3.5 rps, p50 ~1123 ms (GPU-serialized, latency grows with queue
  depth — no speedup, as expected); workers 16 → **40/48 return 503** (bounded
  in-flight = 8), 8 served. The saturation bound is **fail-closed** (503 → DENY).
- **Gateway end-to-end (real cascade, 32 requests):** bimodal — **p50 0.80 ms**
  (FAST_ALLOW / Model 2 early-block routes) vs **p95 289.6 ms** (V5 routes). L2
  enforcement confirmed: only forwarded requests reached the upstream.

---

## 6. Pending / blocked (declared, not hidden)

1. **Operational threshold / policy NOT selected.** The lab threshold 0.9 is
   experimental, to exercise the mechanism. Selecting one needs VALIDATION (40
   rows only) + eligible development data under the selection protocol; no
   early-block FP budget, miss tolerance or DEFER cap is ratified.
2. **No protected evaluation run.** INTERNAL_TEST / STAB-HELD / E6 / external were
   not touched. A single joint frozen run (one attempt) is prepared in principle
   but **not executed** — it requires the specific D60/D77 authorizations and
   frozen model+policy+protocol. The runner respects that scope; do not widen it.
3. **Framing scope = HTTP/1.1 local lab only.** No HTTP/2, no TLS, not a
   mitmproxy-in-the-middle deployment. The mitmproxy D70 profile control is a
   separate, still-open delta.
4. **Dev-data caveats.** eval.jsonl may overlap V5 training; 13/19 categories are
   out of V5's trained vocabulary; VALIDATION is 40 rows; CmdI/SQLi/SSTI/XSS are
   TRAIN-only/NOT_EVALUABLE. No generalization or production-protection claim is
   made from these numbers.
5. **C2 absent** (as required for the first cascade). Adding it needs a paired
   C1-only vs C1+C2 ablation with a pre-fixed metric and favorable interval.
6. **C1 extended evidence** stays metadata; it is not fed to the 34/32-field
   trained model (that would require a new recipe + training).

---

## 7. Issue criteria touched (NOT closed here)

- **#68** (active canonicalization, framing, integration conditions): canonical
  snapshot now feeds the decision path once; HTTP/1.1 framing verification and an
  active FAST_ALLOW branch demonstrated in the lab. HTTP/2-TLS and the mitmproxy
  delta remain open.
- **#83** (BLOCK/DEFER operative contract): real decider + separate versioned
  model-bound policy, fail-to-defer, BLOCK-no-V5 and DEFER→V5 proven with real
  models. Operational closure (calibrated threshold, protected eval) pending.
- **#36–#38** (Fast Path, async audit, benchmark): positive-policy FAST_ALLOW path
  active in the lab; the old "suspicious score" wording is **not** reinstated —
  reconcile #36/#38 text before implementing literally. Async audit of FAST_ALLOW
  is **not** yet implemented.
- **#81** (observer measurement): superseded for the cascade by the active-path
  measurement here; not a substitute for the frozen benchmark.
- **#36–#38 / D36:** D36 (P95 ≤200 ms, model-side pipeline, steady state) is **not**
  met — V5 generate p95 ≈293 ms here (and this is generate-only, not the full D36
  pipeline, measured during eval, not the controlled benchmark).

---

## 8. Reproduce

```bash
# 1. V5 service (system python, GPU)
/usr/bin/python3.12 -m uvicorn --app-dir control_plane v5_classifier_api:app --host 127.0.0.1 --port 8001
# 2. unit tests with doubles (data-plane venv)
.venv-dataplane/bin/python -m unittest tests.test_cascade_router tests.test_model2_policy tests.test_http1_wire tests.test_cascade_lab
# 3. real-model route verification (analyzer venv; service up)
.venv-analyzer/bin/python scripts/cascade_lab/integration_check.py
# 4. dev sample + paired evaluation + metrics
.venv-dataplane/bin/python scripts/cascade_lab/make_dev_sample.py --n 600 --out reports/v5/hybrid/cascade-lab/dev_sample_v1.jsonl
.venv-analyzer/bin/python scripts/cascade_lab/run_cascade.py --sample reports/v5/hybrid/cascade-lab/dev_sample_v1.jsonl --out reports/v5/hybrid/cascade-lab/results/dev_paired_v1.jsonl
.venv-analyzer/bin/python scripts/cascade_lab/metrics.py --paired reports/v5/hybrid/cascade-lab/results/dev_paired_v1.jsonl --out-dir reports/v5/hybrid/cascade-lab/results/metrics_v1
# 5. operational / load
.venv-analyzer/bin/python scripts/cascade_lab/operational_check.py --out reports/v5/hybrid/cascade-lab/results/operational_v1
```

**Hardware/software:** RTX 4090 Laptop 16 GB; torch 2.6.0+cu124, transformers
5.8.0, peft 0.19.1 (V5); numpy 2.5.3, sklearn 1.9.1 (Model 2); Python 3.12.16.

---

## 9. Bottom line

The lab starts and **every applicable route is exercised with real models, real
canonicalization, real HTTP transport and controlled errors**, ending each request
in a single enforced decision, with reproducible per-request evidence. On
development traffic the cascade avoids ~21.6% of V5 calls and raises recall by
~4.6 points, at the cost of a higher false-block rate — **all conditioned on an
uncalibrated lab threshold**. This is an engineering integration that works and is
measured; it is **not** a security certification, a calibrated operating point, or
a production authorization. The concrete remaining blocks are in §6.
