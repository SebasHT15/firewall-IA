# Firewall-IA — Hybrid Cascade: lab integration & staged acceptance report

**Date:** 2026-10-27 (Costa Rica). **Branch:** `feat/hybrid-cascade-integration`
(base HEAD `499c8b2`). **Scope:** implement, connect and test *in an isolated lab*
the PDF cascade `WIRE HTTP → parser/framing/canonicalization → Fast Path → C1 →
Model 2 → V5`, reusing the parallel work. **Not** a deployment, **not** a security
certification, **not** an operational authorization. No protected set
(INTERNAL_TEST / STAB-HELD / E6 / external) was read or consumed. No training was
re-run, no ratified dataset/recipe/threshold was changed, no issue is closed here.

All new code is in **new files only** — the hash-bound Model 2 sources, the trained
artifacts and every existing test are untouched (the Model 2 `source_sha256` /
FINAL-evidence gate still passes).

> **Provenance remediation (2026-10-30).** After an independent review, the §4/§5
> figures were recomputed **from the kept records only** (`results/dev_paired_v1.jsonl`;
> no inference re-run, no training, no protected set). The corrected summary is in
> `results/metrics_v2/` (the prior `results/metrics_v1/` and `ACCEPTANCE_REPORT_v1.md`
> are kept as the as-reviewed version). Three provenance errors are fixed here:
> (1) the headline binary numbers now use the **E5 PRINCIPAL** view (invalid outputs
> counted as errors in their true class) with a **parseable-only** view shown
> alongside — the prior headline silently dropped invalids; (2) the **21.6%** figure
> is a **counterfactual estimate of avoidable V5 calls** (125 early-BLOCK of 578
> observed predictions), **not** a measured time or call reduction; (3) load numbers
> separate **goodput** from **throughput** (which counts 503s). The latency sample is
> **not** the D31/D32/D36 benchmark and no D36-compliance claim is made.

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
`CONTINUE→Model 2` · `Model 2 BLOCK *and status OK*→DENY (no V5 call)` ·
`DEFER / non-OK status / Model 2 exception→V5` · `V5 ALLOW→forward` · `V5 BLOCK→DENY` ·
`V5 invalid/error/timeout→DENY (never ALLOW)`. An early BLOCK is honored only with an
OK status; a raised Model 2 error or an inconsistent (non-OK + BLOCK) reply fails to
DEFER into V5, never an early deny.
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
- **Tested with doubles (69 unit tests, all pass):**
  `test_cascade_router` (20 — every branch, fail-closed, modes, no-double-V5-call,
  **Model 2 exception / inconsistent non-OK+BLOCK / OBSERVE-keeps-V4** negatives),
  `test_model2_policy` (10), `test_http1_wire` (19 — framing branches incl. trailer
  validation and version declaration), `test_cascade_lab` (13 — **real sockets**,
  doubles for models: FORWARD reaches upstream, DENY/malformed do not, segmented
  chunk read, length-respecting responses), `test_cascade_metrics` (7 — E5
  aggregation + kept-JSONL cross-check).
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
Per-request records (decisions/timings/category only, **no payloads**):
`results/dev_paired_v1.jsonl`; corrected summary + CSVs in `results/metrics_v2/`
(prior, as-reviewed: `results/metrics_v1/`). The raw wire sample
(`dev_sample_v1.jsonl`, verbatim requests from the non-redistributable `eval.jsonl`)
is **kept local, not committed** — integrity + deterministic reproduction recipe in
`DATA_RETENTION.md`.

> **E5 views (never merged into one number).** PRINCIPAL counts every ACCEPT case:
> an invalid/None output is an incorrect security decision mapped to the OPPOSITE of
> the true label (BLOCK-invalid→FN, ALLOW-invalid→FP), so garbage earns no credit.
> PARSEABLE-ONLY excludes invalids. The 4 invalid V5 outputs (all on BLOCK-labelled
> attacks) split into **2 content-boundary rejections** (`content_rejected` — a
> runtime no-generation event, not a model-quality error) and **2 model-output
> errors** (`no_eos`, `not_in_vocabulary`). Both count as errors under PRINCIPAL.

### 4a. V5-only (binary; measured)
- **PRINCIPAL (E5, headline):** TP 185 · TN 297 · FP 3 · FN 93 (incl. 4 invalids)
  → **precision 0.984, recall 0.6655, FPR 0.010, F1 0.794**.
- **PARSEABLE-ONLY (invalids excluded, N=574):** recall 0.675, F1 0.801.
- Invalid-rate 4/578 = 0.0069 (2 content-boundary / 2 model-output).

(Low recall is dominated by the out-of-vocab categories V5 was never trained to
name. The prior report headlined the parseable-only recall 0.675 while claiming
invalids were counted as errors — the PRINCIPAL recall 0.6655 is the figure that
actually counts them.)

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
PRINCIPAL E5 (headline); parseable-only in brackets. "V5 calls avoided" is a
**counterfactual** count of early-BLOCKs, **not** a measured runtime saving (§4d).

| cascade | precision | recall (P / parseable) | FPR | F1 (P) | V5 calls | early-BLOCK (counterfactual avoidable) |
|---|---|---|---|---|---|---|
| +baseline34 | 0.948 | **0.7158** (0.721) | 0.037 | 0.816 | 453/578 | 125 (21.6% of ACCEPT) |
| +ablation32 | 0.937 | 0.6978 (0.703) | 0.043 | 0.800 | 471/578 | 107 (18.5% of ACCEPT) |

### 4d. Complementarity & cost (the headline question)
Cascade(baseline) vs V5-only, same requests: Model 2 correctly early-blocks **117**
attacks — **12** of which **V5 would have missed** (ALLOW) and 103 V5 would also
catch — while early-blocking **8 benign** that V5 would have allowed.

**Net binary effect (PRINCIPAL E5, derived from the confusions above — recomputed
from kept records, NOT an operating rate):** recall **0.6655→0.7158**
(**+5.04 pp**) at the price of FPR **0.010→0.037** (**8 extra false blocks over the
300 benign**) and precision 0.984→0.948. Under this lab threshold the cascade buys
recall with a higher false-block rate — a real, visible tradeoff **conditioned on an
uncalibrated threshold** with no ratified FP budget.

**Call avoidance (counterfactual, NOT a measured time/call reduction):** of the 578
ACCEPT requests, Model 2 early-BLOCKed **125 (21.6%)** on this pass's observed
predictions; with no positive Fast Path policy applied, those are the V5 calls the
early stage *could* avoid. This is an estimate from recorded decisions — it is **not**
a measured 21.6% reduction in wall-clock time or in issued calls.

**Latency (measured ms, per stage; P95/P99 per-request, never summed):**
canonicalization mean 0.05 / p95 0.07 · Fast Path 0.01 / 0.02 · Model 2 score
(baseline) 0.10 / 0.13 · **V5 generate mean 263.8 / p50 282.7 / p95 292.7 / p99
297.7** (model-side generate only — **not** the D36 pipeline, observed during eval,
not the controlled D31/D36 benchmark; **no D36-compliance claim**).
**Derived stage-time** active-cascade mean (baseline, FP CONTINUE) =
`canon+fp+m2 + 0.784·v5_generate ≈ 206.9 ms` — a derivation from per-stage means
assuming mutually-exclusive routes and no extra rejects, **not** a measured
end-to-end figure (for a measured end-to-end sample see §5, itself uncontrolled).

---

## 5. Operational / load (measured — `results/operational_v1/`)

- **Cold start:** V5 model load **3.9 s** (recorded at service startup).
- **Concurrency (1 GPU, 48 benign requests).** `throughput_rps` counts **every**
  response including 503s, so under saturation it is **not** a useful-work rate;
  `goodput_rps` counts only real classifications. Report both plus the 503 rate:
  - workers 1 → goodput ≈ 3.5 resp/s, 0% 503, p95 ≈ 297 ms (no saturation; here
    throughput == goodput).
  - workers 4 → goodput ≈ 3.5 resp/s, 0% 503, p50 ≈ 1123 ms (GPU-serialized, latency
    grows with queue depth — no speedup, as expected).
  - workers 16 → **40/48 return 503** (bounded in-flight = 8): **saturation rate
    0.833**, 8 served. **goodput ≈ 3.55 resp/s** vs **throughput_rps ≈ 21.28**
    (the 21.28 figure is inflated by the 40 fast-failing 503s and must not be read
    as capacity). The saturation bound is **fail-closed** (503 → DENY).
- **Gateway end-to-end (real cascade, 32 requests) — UNCONTROLLED sample, NOT the
  D31/D32/D36 benchmark** (no warm-up/steady-state separation; the mix includes
  zero-generation early-BLOCK / protocol rejects): bimodal — **p50 ≈ 0.80 ms**
  (FAST_ALLOW / Model 2 early-block routes) vs **p95 ≈ 289–293 ms** (V5 routes). No
  D36-compliance claim is made from this. L2 enforcement confirmed: only forwarded
  requests reached the upstream.

---

## 6. Pending / blocked (declared, not hidden)

1. **Operational threshold / policy NOT selected.** The lab threshold 0.9 is
   experimental, to exercise the mechanism. Selecting one needs VALIDATION (40
   rows only) + eligible development data under the selection protocol; no
   early-block FP budget, miss tolerance or DEFER cap is ratified.
2. **No protected evaluation run; no formal benchmark / full L1/L2/L3 breakdown.**
   INTERNAL_TEST / STAB-HELD / E6 / external were not touched. A single joint frozen
   run (one attempt, under a single-attempt guard) is prepared in principle but
   **not executed** — it requires the specific D60/D77 authorizations and frozen
   model+policy+protocol. The runner respects that scope; do not widen it. Note the
   L2 signal is not yet independent per case: `upstream_received` is currently set
   by `_forward` success in the gateway, **not** an independent per-case record of
   upstream reception — the authorized final eval needs that independent record plus
   the full L1/L2/L3 breakdown.
7. **V4↔V5 regression not validated.** Before any V4↔V5 regression comparison, the
   lab's V4 render equivalence must be validated first: the lab feeds V4 the wire
   **CRLF** `raw_text`, not the gateway's **D1 LF** render, so the two inputs are not
   yet shown equivalent. Until that is checked, OBSERVE-mode V4 numbers are not
   comparable to the ratified V4 path.
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
.venv-analyzer/bin/python -m unittest tests.test_cascade_router tests.test_model2_policy tests.test_http1_wire tests.test_cascade_lab tests.test_cascade_metrics
# 3. real-model route verification (analyzer venv; service up)
.venv-analyzer/bin/python scripts/cascade_lab/integration_check.py
# 4. dev sample + paired evaluation + metrics
.venv-dataplane/bin/python scripts/cascade_lab/make_dev_sample.py --n 600 --out reports/v5/hybrid/cascade-lab/dev_sample_v1.jsonl
.venv-analyzer/bin/python scripts/cascade_lab/run_cascade.py --sample reports/v5/hybrid/cascade-lab/dev_sample_v1.jsonl --out reports/v5/hybrid/cascade-lab/results/dev_paired_v1.jsonl
.venv-analyzer/bin/python scripts/cascade_lab/metrics.py --paired reports/v5/hybrid/cascade-lab/results/dev_paired_v1.jsonl --out-dir reports/v5/hybrid/cascade-lab/results/metrics_v2  # metrics_v1 kept as prior
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
development traffic, under the PRINCIPAL E5 view, the cascade raises recall
**+5.04 pp** (0.6655→0.7158) at the cost of **8 extra false blocks over 300 benign**
(FPR 0.010→0.037), and early-BLOCKs **21.6%** of ACCEPT requests — a **counterfactual
estimate of avoidable V5 calls, not a measured time/call reduction** — **all
conditioned on an uncalibrated lab threshold**. This is an engineering integration
that works and is measured; it is **not** a security certification, a calibrated
operating point, or a production authorization. The concrete remaining blocks are
in §6.
