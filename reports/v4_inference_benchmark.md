# V4 model-side inference benchmark — `baseline-local-v1`

**Issue #9.** The first controlled, reproducible measurement of how long the V4-clean
classifier takes to generate one decision, recorded together with the complete
environment it ran in, so that a future latency reduction can be stated as a percentage
**and** explained by what changed.

| | |
|---|---|
| Experiment id | **`baseline-local-v1`** — frozen; future runs take their own ids |
| Measured | 2026-09-09, 19:47:48 → 20:58:58 UTC (71.2 min) |
| Code | commit `d64de10a6ee399f1aa19afb1a5abecd0fbc7bf39`, clean working tree |
| Artifacts | [`reports/benchmarks/baseline-local-v1/`](benchmarks/baseline-local-v1/) |
| Harness | `benchmark_inference.py` · `benchmark_env.py` · `benchmark_compare.py` |
| Decisions | D31 (synchronized stopwatch) · D32 (experiment identity and comparison) |

> **Headline.** Steady-state model-side generation, pooled over 3 independent runs of the
> full 6,206-row held-out split (n = 18,618): **P95 269.01 ms**, P50 238.82 ms, mean
> 227.86 ms. Quality at that latency is unchanged from the V4 baseline — attack detection
> 97.04%, 2 false positives and 92 false negatives per run, 0 invalid outputs.
>
> This is `generate()` alone. It is **not** API latency and **not** gateway latency.
> The D3 budget of end-to-end P95 ≤ 200 ms covers the whole gateway, is measured by
> Issue #18, and is neither passed nor failed here.

---

## 1. What the stopwatch covers

| | operations |
|---|---|
| **In scope** — the primary metric | `generate()` |
| **Out of scope** — timed and reported separately, never pooled in | prompt construction · tokenization · host→device transfer · decoding · contract parsing |

Scope identifier: **`generate-only/device-synchronized/v1`**. Two results with different
scope identifiers are not comparable regardless of units, and `benchmark_compare.py`
blocks such a comparison.

The `generate()` timer is bracketed by `torch.cuda.synchronize()` on both sides, so it
measures GPU work that has **completed** rather than work that has been submitted (D31).

**The out-of-scope stages are not where the time goes.** Pooled over 18,618 requests, the
whole pipeline at P95 is 269.58 ms against 269.01 ms for `generate()` alone — everything
else together contributes about **0.58 ms**:

| stage | mean (ms) |
|---|---:|
| prompt construction | 0.0011 |
| tokenization | 0.2874 |
| host→device transfer | 0.1041 |
| **generation** | **227.8555** |
| decoding | 0.0698 |
| contract parsing | 0.0075 |

Means over all 18,618 steady-state requests of the three runs.

### The stopwatch correction is not an improvement

`classify_raw()` previously timed `generate()` without an explicit synchronization.
Making that guarantee explicit is a methodology change, so it was measured rather than
assumed — same requests, same process, interleaved A/B, n = 40 per arm, run twice:

| | unsynchronized | synchronized | delta |
|---|---:|---:|---:|
| before the baseline runs | 223.75 ms | 223.77 ms | +0.020 ms (+0.009%) |
| after the baseline runs | 235.08 ms | 234.17 ms | −0.909 ms (−0.387%) |

Below 0.4% and **inconsistent in sign** — indistinguishable from this machine's own
noise. HuggingFace `generate()` already synchronizes on every decoding step when it
evaluates stopping criteria, so the old timer was in practice already measuring completed
work. The synchronization is kept because it must also hold for future backends that may
not synchronize internally. The decoded output is identical through both paths.

Reproduce: `python3.12 benchmark_inference.py verify-timing --experiment <id> --limit 40`
→ [`timing_method_ab.json`](benchmarks/baseline-local-v1/timing_method_ab.json).

---

## 2. Environment

Every value below was read from the machine that ran the model, at the time it ran.
Full record: [`environment.json`](benchmarks/baseline-local-v1/environment.json).

| | |
|---|---|
| OS | Ubuntu 26.04.1 LTS (Resolute Raccoon), kernel `7.0.0-31-generic`, x86_64 |
| CPU | 13th Gen Intel Core i9-13900HX — 24 physical cores, 32 logical, governor `powersave` |
| RAM | 32,129,868 kB total (30.64 GiB), 8 GiB swap |
| GPU | NVIDIA GeForce RTX 4090 Laptop GPU, 16,376 MiB VRAM, compute capability 8.9, 76 SMs |
| GPU power | enforced limit 150 W, persistence mode disabled, compute mode Default |
| NVIDIA driver | **595.84**, reports support up to **CUDA 13.2** |
| CUDA used by PyTorch | **12.4** (`torch 2.6.0+cu124`), cuDNN 90100 |
| Python | 3.12.13 CPython, `/usr/bin/python3.12` |
| Libraries | transformers 5.8.0 · peft 0.19.1 · accelerate 1.13.0 · bitsandbytes 0.49.2 · tokenizers 0.22.2 · safetensors 0.7.0 · numpy 2.4.3 |
| Power | on AC, battery at 80% |

**The driver's CUDA 13.2 and PyTorch's CUDA 12.4 are different things.** 13.2 is the
maximum the driver can support; 12.4 is the runtime actually in use. They are recorded as
separate fields and must not be interchanged.

### Model identity

| | |
|---|---|
| Base model | `TinyLlama/TinyLlama-1.1B-Chat-v1.0`, revision `fe8a4ea1ffedaf415f4da2f062534de366a451e6` |
| Base weights | `model.safetensors` sha256 `6e6001da2106d475…` |
| Adapter | `model-output-v4-clean/`, `adapter_model.safetensors` sha256 `7bf168758a428fa7…` |
| LoRA | r=16, α=32, dropout 0.05, 7 target modules, `inference_mode: true` |
| Tokenizer | `tokenizer.json` sha256 `81bb383c61381596…` |

### Effective placement and quantization — read from the loaded model, not assumed

**628,221,952 parameters, 100% on `cuda:0`. Zero CPU-hosted parameters, zero CPU
buffers.** There was no silent CPU fallback.

Quantization as the loaded model reports it: `bitsandbytes`, `load_in_4bit: true`,
`bnb_4bit_quant_type: nf4`, `bnb_4bit_compute_dtype: bfloat16`,
`bnb_4bit_use_double_quant: **false**`, `bnb_4bit_quant_storage: uint8`. This is exactly
the canonical runtime configuration of **D27** — nothing was changed for the benchmark.

### Machine conditions, sampled before and after every run

| run | GPU °C before → after | power before → after | SM clock before → after | other GPU memory in use |
|---|---|---|---|---|
| 1 | 48 → 73 | 9.1 W → 78.4 W | 210 → 2310 MHz | 541 MiB (desktop session) |
| 2 | 70 → 76 | 27.1 W → 80.2 W | 540 → 2310 MHz | 545 MiB |
| 3 | 72 → 77 | 26.5 W → 78.6 W | 945 → 2310 MHz | 544 MiB |

The machine was a normal desktop session — GNOME Shell, Xwayland and a terminal held
~540 MiB of VRAM throughout. That is the environment being characterized, and it is
recorded rather than removed.

---

## 3. Protocol

Written to [`protocol.json`](benchmarks/baseline-local-v1/protocol.json) **before**
anything was measured.

| | |
|---|---|
| Dataset | `datasets/v4_clean/eval.jsonl`, **6,206 rows** (3,103 ALLOW / 3,103 BLOCK) |
| Dataset sha256 | `61f15591203609b4c583773184cd25edd6d1adc5f86959e009cfd47f6d370859` |
| Verification | matched against `datasets/manifest_v4_clean.json` before measuring; a mismatch aborts the run |
| Selection | **full split** — not reduced |
| Order | file order of the split; ALLOW/BLOCK are interleaved, not grouped |
| Seed | 42, used **only** to pick the cold-start and warm-up requests |
| Runs | **3**, each a fresh OS process |
| Process model | model loaded **once per process**, reused for every request in that run |
| Batch size | **1** |
| Concurrency | **1** |
| Generation | greedy (`do_sample=False`), native EOS, `max_new_tokens=40` as a safety bound |
| Percentiles | nearest-rank, `ceil(q·n)`, 1-indexed, no interpolation — the same definition as `test_model.percentile` (enforced by a test) |
| Outliers | **none removed**; extremes are characterized |

**Duration was estimated before starting:** 6,206 × 3 @ ~235 ms ≈ 24.4 min per run,
≈ 73 min total. Actual: 22.4 / 23.9 / 24.6 min of measurement per run, **71.2 min** end
to end (19:47:48 → 20:58:58 UTC).

A 20-request smoke run was executed first, to a throwaway location, purely to check the
instrumentation. Its numbers are not a result and are not in this report.

### Four populations, kept separate

| population | what it is | in the reported statistics? |
|---|---|---|
| 1. model load | `load_model()` in a fresh process | **no** — reported separately |
| 2. first inference | the first `generate()` in that process | **no** — reported separately |
| 3. warm-up | 4 further generations | **no** — reported separately |
| 4. steady state | the 6,206-request measurement pass | **yes** — this is the headline |

The requests for populations 2 and 3 were fixed in advance by seed 42 and are named in
`protocol.json`:

- **Cold start:** row **5238**
- **Warm-up:** rows **912, 204, 6074, 2253**

Those five rows are members of the split, so they are executed **again** inside the
steady-state pass. Their cold and warm samples stay in their own populations; the steady
sample of the same row is a separate, later observation. Greedy decoding is deterministic,
so re-running a row cannot change its decision — verified below.

Nothing was discarded. All 18,633 samples (18,618 steady + 3 cold + 12 warm-up) are in
the per-run JSONL files with their phase label.

---

## 4. Results

### Steady state — pooled over the 3 runs (n = 18,618)

| statistic | value (ms) |
|---|---:|
| mean | 227.86 |
| P50 | 238.82 |
| **P95 — primary metric** | **269.01** |
| P99 | 275.90 |
| min | 155.80 |
| max | 337.16 |
| standard deviation | 32.43 |

Tail, with nothing removed: P99.9 = 285.23 ms, P99.99 = 304.94 ms. Exactly **2 samples of
18,618 (0.011%) exceeded 300 ms**; 186 samples sit above P99. At the other end, 2,152
samples (11.6%) came in under 180 ms.

### Per run

| run | model load (ms) | first inference (ms) | warm-up (ms) | steady n | mean | P50 | P95 | P99 | min | max | stdev |
|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 2275.5 | 418.2 | 243.8, 228.6, 181.0, 159.5 | 6206 | 215.81 | 232.01 | 244.03 | 248.07 | 155.80 | 259.78 | 29.29 |
| 2 | 2251.6 | 410.4 | 244.1, 243.2, 189.5, 170.6 | 6206 | 230.77 | 244.39 | 266.55 | 272.37 | 166.03 | 285.63 | 30.74 |
| 3 | 2416.6 | 446.2 | 271.2, 265.8, 204.8, 184.0 | 6206 | 236.99 | 252.49 | 273.21 | 280.00 | 170.31 | 337.16 | 33.39 |

### Cold start and model load — the excluded populations

| population | run 1 | run 2 | run 3 | median |
|---|---:|---:|---:|---:|
| model load | 2275.5 | 2251.6 | 2416.6 | 2275.5 ms |
| first inference | 418.2 | 410.4 | 446.2 | 418.2 ms |

The first inference in a fresh process costs **1.75× the steady-state P50** and **1.84×
the pooled steady-state mean**. By the second warm-up request the cost is
already inside the steady range. Loading the model costs about **2.3 s**, paid once per
process — which is why the control plane loads at startup and never per request.

### Run-to-run variation — this matters more than any single number

| statistic | run values | range | range as % of mean |
|---|---|---:|---:|
| mean | 215.81, 230.77, 236.99 | 21.18 ms | **9.30%** |
| P50 | 232.01, 244.39, 252.49 | 20.48 ms | **8.43%** |
| **P95** | 244.03, 266.55, 273.21 | 29.18 ms | **11.17%** |
| P99 | 248.07, 272.37, 280.00 | 31.93 ms | 11.97% |
| min | 155.80, 166.03, 170.31 | 14.51 ms | 8.84% |
| max | 259.78, 285.63, 337.16 | 77.38 ms | 26.30% |

**The runs got monotonically slower, and it is not noise.** Pairing every row with itself
across runs — identical request, identical workload — removes any dataset effect:

| pair | mean difference | median difference | rows where the later run was slower |
|---|---:|---:|---:|
| run 2 − run 1 | +14.96 ms | +14.42 ms | **98.2%** of 6,206 |
| run 3 − run 1 | +21.18 ms | +20.83 ms | **99.5%** of 6,206 |
| run 3 − run 2 | +6.22 ms | +5.98 ms | 67.3% of 6,206 |

The GPU started run 1 at 48 °C and runs 2 and 3 at 70 °C and 72 °C, having had no time to
cool. A back-to-back protocol on a laptop measures a machine that is progressively hotter.

> **Consequence for every future comparison.** On this machine, run order alone moves the
> P95 by about **11%**. A candidate that claims a reduction smaller than that, measured in
> a different position in the run sequence, has not demonstrated anything. Either
> interleave baseline and candidate runs, or bring the GPU to a comparable thermal state
> before each run, or report the effect as being within run-order variation. This is the
> single most useful thing this baseline establishes.

**A caution about within-run trends.** Each run appears to accelerate towards the end
(run 3: 250.7 ms in the first decile against 209.6 ms in the last). That is a **workload
artifact, not warm-up**: mean generated tokens fall from 12.40 to 10.16 across the deciles
of the split. Normalized per generated token, every run in fact slows slightly (+7.0%,
+9.5%, +2.0% first decile to last), consistent with the thermal picture. Latency here is
driven overwhelmingly by output length.

### What drives a single request's latency

| factor | correlation with `generate_ms` |
|---|---:|
| generated tokens | **r = 0.934** |
| prompt tokens | r = −0.244 |

Autoregressive decoding dominates: **11.63 generated tokens on average** (min 9, max 13),
against a mean prompt of 191.9 tokens (min 74, max 815). That works out to roughly
**19.6 ms per generated token**. Prompt length has a weak negative correlation, which is
an artifact of longer requests happening to produce shorter reasons — not a claim that
longer prompts are faster.

**Zero of 18,618 generations hit the 40-token safety bound.** All terminated on native
EOS. No response was shortened to obtain a better time.

### Peak memory

| | value |
|---|---:|
| peak allocated during steady state | **935.5 MiB** |
| peak reserved during steady state | **1170.0 MiB** |
| allocated after model load | 837.1 MiB |
| whole-GPU memory in use, end of run | ~2,010 MiB |

**What this measures:** the PyTorch caching allocator's accounting **for this process
only**. `allocated` is live tensor memory; `reserved` is what the allocator holds from the
driver. Neither includes the CUDA context (a few hundred MiB) nor the ~540 MiB the desktop
session was using, which is why neither equals `nvidia-smi`'s figure. Peak counters were
re-armed after model load, so these are the peaks of the measured phase.

---

## 5. Quality at this latency

A latency number is only meaningful next to the quality produced at it. Scored with the
existing E5 methodology (`test_model.score_binary`, BLOCK as the positive class), over the
pooled 18,618 classifications.

| metric | value |
|---|---|
| Attack detection rate (recall, BLOCK) | **97.04%** (9,033 / 9,309) |
| False positives | **6** total — **2 per run** of 3,103 benign, FPR 0.064% |
| False negatives | **276** total — **92 per run** of 3,103 attacks, FNR 2.96% |
| Invalid outputs | **0** (0.00%) |
| Accuracy | 98.49% |
| Confusion matrix, per run | TP 3,011 · FP 2 · FN 92 · TN 3,101 |

**The three runs produced bit-identical results.** Not merely identical rates — for all
6,206 rows, **0 rows differed in decision and 0 rows differed in reason string** across
the three runs. Greedy decoding is deterministic, and this measures it rather than
assuming it.

These figures also match `reports/v4_clean_eval.json` exactly (accuracy, attack detection,
FPR and FNR all differ by +0.0000%). That is the strongest available evidence that adding
timing instrumentation did not perturb inference: same model, same prompt, same
parameters, same decisions, down to the reason text.

**No speed claim is being made here at all**, so there is no quality trade-off to declare.
When a future candidate does claim a reduction, `benchmark_compare.py` computes these same
metrics in the same pass and raises any degradation next to the speedup automatically.

---

## 6. Comparing a future run against this baseline

```bash
python3.12 benchmark_inference.py protocol --experiment <candidate-id> --runs 3
```

```bash
python3.12 benchmark_compare.py --baseline baseline-local-v1 --candidate <candidate-id> --markdown reports/benchmarks/<candidate-id>/vs-baseline.md
```

Against the original baseline **and** the candidate's own previous version in one report:

```bash
python3.12 benchmark_compare.py --baseline baseline-local-v1 --candidate <candidate-id> --previous <previous-candidate-id>
```

The formulas, per statistic, never blended into one number:

```
percentage reduction  =  100 × (baseline − candidate) / baseline
speedup factor        =  baseline / candidate
```

They are distinct: a 50% reduction is a 2.0× speedup, 75% is 4.0×. A negative reduction is
a regression and is reported as one. Missing values, zero references and negative
references are reported as undefined — never rendered as 0%.

**`baseline-local-v1` is frozen.** The harness refuses to overwrite an experiment that
already has a `summary.json`.

### The rules the tool enforces, not just documents

- **Shared units are not comparability.** Timing scope, dataset hash, request count,
  selection policy, order, protocol version, batch size and concurrency must match.
  A mismatch is blocking: the report is stamped NOT COMPARABLE and the tool exits 2.
- **Hardware changed ⇒ re-run the base version on that hardware.** A cross-machine
  difference is not evidence of a software improvement.
- **Hardware and software both changed ⇒ joint effect.** No causal attribution to either.
- **Never a speed claim alone.** Quality is compared in the same pass and any degradation
  is raised beside the speedup.

### Demonstrated on real data

Pointing the tool at the historical E5 evaluation produces
[`vs-historical-e5.md`](benchmarks/baseline-local-v1/vs-historical-e5.md) — **NOT
COMPARABLE, 6 blocking differences, exit code 2**, because the timing scope differs
(`generate-only/unsynchronized/v0`) and the legacy record never stated its selection
policy, order, batch size or concurrency. An unrecorded field is not a matching field.

That comparison also shows the numbers it refuses to endorse: the historical P95 of
270.8 ms against this baseline's 269.01 ms would read as a "0.68% reduction". **It is not
one.** The two were produced under different protocols, and the difference is an order of
magnitude smaller than this machine's 11% run-to-run variation.

---

## 7. Historical antecedents — preserved, not overwritten

These were measured under their own protocols. They remain valid records of what they
measured and are **not** `baseline-local-v1` results.

| record | figure | why it is not a comparand |
|---|---|---|
| `reports/v4_clean_eval.json` (Issue #8) | model-side P95 **270.8 ms** over 6,206 rows | single run, no separation of load / cold start / warm-up from steady state, unsynchronized timer |
| Issue #15 control-plane observation | first inference **512.8 ms**; steady n=30, P50 **232.5 ms** | a 30-request functional sample, not a benchmark |

Note that the Issue #15 cold-start observation (512.8 ms) is higher than the 410–446 ms
measured here across three fresh processes. Both are cold starts, but they were taken
under different conditions and are not two measurements of the same quantity.

---

## 8. Implemented · measured · pending

**Implemented**

- `classify_timed()` / `device_sync()` in `inference_core.py` — one generation path,
  instrumented, shared by the evaluation harness and the control plane
- `benchmark_env.py` — live environment manifest, unavailable values marked as such,
  environment variables allowlisted so no credentials are captured
- `benchmark_inference.py` — protocol, four separated populations, per-run artifacts,
  pooled and per-run aggregation, `verify-timing`, `smoke`, `estimate`, `self-test`
- `benchmark_compare.py` — reduction and speedup, incompatibility detection, attribution
  rules, speed-vs-quality pairing
- 74 new tests (`tests/test_benchmark.py`); 111 tests pass in total

**Measured on the real machine and real model**

- 3 independent runs × 6,206 real requests = 18,618 real classifications
- Steady-state P95 **269.01 ms**, P50 238.82 ms, mean 227.86 ms
- Cold start 410–446 ms, model load 2.25–2.42 s, both excluded from the above
- Peak allocated 935.5 MiB / reserved 1170.0 MiB, this process
- Quality identical to the V4 baseline; 0 invalid outputs; perfect determinism
- Run-to-run P95 variation of **11.17%**, attributed to run order and thermal state by
  paired per-row analysis

**Pending — explicitly not done here**

- End-to-end gateway latency and the D3 P95 ≤ 200 ms budget (**Issue #18**)
- API-level latency, including FastAPI and HTTP overhead
- Concurrency and load behaviour — this baseline is concurrency 1, batch size 1 by design
- Any optimization: GGUF / Q4_K_M / llama.cpp (M2, D23), fast path (#35–#38)
- A baseline on other hardware, including the embedded target (D10)
- Reducing the run-to-run variation by controlling thermal state between runs

**What this baseline does not say.** It does not say the gateway is fast enough; it does
not say the model is fast enough. Model-side P95 alone (269 ms) already exceeds the whole
200 ms end-to-end budget — which is the existing finding of D23, now measured under a
controlled protocol rather than inferred from a single evaluation run.
