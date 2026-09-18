# Inference benchmarks

Controlled model-side inference measurements (Issue #9). One directory per
**experiment**; an experiment id is permanent and is never reused or overwritten.

```
reports/benchmarks/
└── <experiment-id>/
    ├── protocol.json            what was measured, written BEFORE measuring
    ├── environment.json         the machine, read live at capture time
    ├── run-NN.json              one run: phases, statistics, quality, conditions
    ├── run-NN.samples.jsonl     every individual request measured in that run
    └── summary.json             aggregation across runs — the comparable artifact
```

`summary.json` is the unit of comparison. It carries an `identity` block (timing
scope, dataset hash, selection, protocol, batch size, concurrency, model,
hardware, library versions) and a `metrics` block with `metric_directions`, so a
report stays readable without the tool that produced it.

## Experiments

| id | date | what it is |
|---|---|---|
| `baseline-local-v1` | 2026-09-09 | The frozen reference. V4-clean adapter on the HF/PEFT backend, RTX 4090 Laptop GPU, full 6,206-row eval split × 3 runs. **Do not overwrite.** |

## Reproduce the baseline

```bash
python3.12 scripts/benchmarks/benchmark_inference.py self-test
```

```bash
python3.12 scripts/benchmarks/benchmark_inference.py smoke --out-dir /tmp/bench-smoke --limit 20
```

```bash
python3.12 scripts/benchmarks/benchmark_inference.py estimate --runs 3
```

```bash
python3.12 scripts/benchmarks/benchmark_inference.py protocol --experiment baseline-local-v1 --runs 3
```

The harness refuses to write over an experiment that already has a
`summary.json`. Reproducing the baseline on a fresh machine therefore means
choosing a **new** id — the numbers will differ, and that difference is the
point:

```bash
python3.12 scripts/benchmarks/benchmark_inference.py protocol --experiment baseline-<machine>-v1 --runs 3
```

## Measure a candidate and compare it

```bash
python3.12 scripts/benchmarks/benchmark_inference.py protocol --experiment <candidate-id> --runs 3
```

```bash
python3.12 scripts/benchmarks/benchmark_compare.py --baseline baseline-local-v1 --candidate <candidate-id> --markdown reports/benchmarks/<candidate-id>/vs-baseline.md --json reports/benchmarks/<candidate-id>/vs-baseline.json
```

Compare against the original baseline **and** the candidate's own previous
version in one report:

```bash
python3.12 scripts/benchmarks/benchmark_compare.py --baseline baseline-local-v1 --candidate <candidate-id> --previous <previous-candidate-id>
```

`benchmark_compare.py` exits non-zero when the two experiments are not
comparable (different timing scope, dataset, selection, protocol, batch size or
concurrency). That is a result, not a failure of the tool — fix the protocol, do
not pass `--allow-incompatible` to make the message go away.

## Rules that the tooling enforces

- **Shared units are not comparability.** Milliseconds on both sides prove
  nothing; the identity fields must match (D32).
- **Hardware changed ⇒ re-run the base version on that hardware.** A comparison
  across machines cannot attribute a difference to software.
- **Hardware *and* software changed ⇒ report a joint effect.** No causal split.
- **Never a speed claim alone.** Quality metrics are compared in the same pass
  and any degradation is raised beside the speedup.
- **Cold start, warm-up and steady state are separate populations** and are
  never pooled. Nothing is discarded — every sample is in the JSONL.
- **No outlier removal.** Extremes are characterized, not dropped.

## What these numbers are, and are not

The primary metric is model-side `generate()` only. Not API latency, not gateway
latency. End-to-end measurement is Issue #18.

**Latency objective (D36).** The objective is the P95 of the inference pipeline
(prompt construction, tokenization, transfer, `generate()`, decoding, parsing),
at most 200 ms in steady state. The harness records it as `steady_pipeline_p95_ms`.
In `baseline-local-v1` it is **269.58 ms**: not met. D36 supersedes D3, which
described 200 ms as an end-to-end budget. The `protocol.json` and `summary.json`
of `baseline-local-v1` were written before D36 and keep the D3 wording; they are
not rewritten.

## Historical antecedents — not benchmarks under this protocol

These are preserved as measured, under their own protocols, and are **not**
`baseline-local-v1` results:

- `reports/v4_clean_eval.json` — model-side P95 **270.8 ms** over the full split,
  Issue #8, single run, no phase separation, unsynchronized timer.
- The Issue #15 control-plane observation — first inference **512.8 ms**,
  steady-state n=30 P50 **232.5 ms**. A functional sample, not a benchmark.

`benchmark_compare.py` will load `reports/v4_clean_eval.json` and then **block**
it against a native report, because its timing scope and protocol differ. That
is the correct answer.
