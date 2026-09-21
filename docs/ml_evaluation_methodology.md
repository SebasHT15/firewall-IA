# ML evaluation methodology

Operational rules for every future evaluation, dataset change and training run in
firewall-IA. It does not replace the frozen metric definitions of E5 (D19,
[`reports/e5_evaluation_methodology.txt`](../reports/e5_evaluation_methodology.txt)); it
governs how evaluations are designed, read and acted on. Examples come from the V4 work;
their numbers live in the cited reports.

> **Latency objective:** D36 (P95 of the inference pipeline ≤ 200 ms in steady state),
> which supersedes D3. See §11.

---

## 1. Data sets and their roles

| Set | Used for | May drive decisions? | V4 today |
|---|---|---|---|
| **TRAIN** | fitting the weights | yes | `datasets/v4_clean/train.jsonl` |
| **VALIDATION** | checkpoint, hyperparameter and configuration selection; development decisions | yes | `eval.jsonl` (see below) |
| **INTERNAL TEST** | independent evaluation of the chosen model inside the distribution the generator defines | **no**, report only | `eval.jsonl`, but not independent (see below) |
| **EXTERNAL TEST** (frozen) | independent evaluation outside the internal distribution, on traffic that took no part in training or tuning | **no**, report only | does not exist yet |
| **ERROR-ANALYSIS / DEV** | inspecting individual failures, forming hypotheses, seeding A/B tests | yes | the 2026-09-16/17 diagnostic requests |

Rules:

- **Split by logical identity before rendering** (D16), for every set, including external
  ones. Variants of one payload, template or session never straddle two sets.
- **V4's `eval.jsonl` did two jobs.** It selected `checkpoint-2200` on `eval_loss`
  (validation) and produced the headline metrics (internal evaluation). It is held out from
  training but is **not** an independent test set (D24).
- **From V5 on, the four roles are separate sets (D37):** TRAIN → training · VALIDATION →
  checkpoint and configuration selection · INTERNAL TEST → independent internal evaluation,
  only ever reported · EXTERNAL TEST → independent evaluation outside the internal
  distribution. VALIDATION is a grouped split carved from training groups. If a version
  cannot follow this, every report on it must say so.
- **A test set stops being a test set once its individual errors drive a change.**
  Reporting aggregate and per-slice metrics costs nothing. Inspecting rows to design a
  dataset or model change turns that set into a development set for that change. Record it
  in the set's manifest and use a fresh test set for the next claim. This is D37, which
  generalizes the contamination rule of D22.
- **Frozen external test vs error-analysis set.** Both come from the same generation
  protocol and are split by group (application, route, payload identity, session). The
  frozen set is read only as aggregates and slices. The dev set is open. When the frozen
  set's rows have to be opened, it is retired to dev and a new frozen set is generated
  before the next version is claimed.
- **A comparison needs a set neither version trained on.** If V5 regenerates the dataset,
  V4 eval groups must stay out of V5 train, or the V4 eval can no longer compare the two.

## 2. Generalization

A good internal metric shows the model learned the distribution its generator produced. It
says nothing about inputs the generator never produced.

V4 shows both at once. Its internal FPR is 0.06% (2 / 3,103 benign), and minimal benign
curl requests still come back BLOCK: a loopback `Host`, the path `/`, `Host` ports from
19000 up. Train and eval contain **0** rows with a loopback `Host`, **0** with the path `/`
or `/index.html`, and only ports 8000 and 8080. The internal eval is silent on those inputs.
It gives no evidence either way.

Rules: before any claim about how the gateway will behave, evaluate on an external test
built from the traffic it will actually see: real clients, local and lab hosts, the
applications it protects. Single-feature shortcut checks (E0: no envelope feature above
51.16%) do not cover feature interactions or unseen values. Those need counterfactual A/B
tests (§8).

## 3. Overfitting is a hypothesis, not a label for failure

A model failing on new traffic is not evidence of overfitting by itself. Name the
explanation the evidence supports:

| Explanation | Meaning | Evidence required |
|---|---|---|
| Overfitting | fits train idiosyncrasies at the expense of held-out data **from the same distribution** | train ≫ held-out gap; held-out metric or loss worsening with more training; ideally across seeds |
| Distribution shift | same task, different input frequencies (client mix, header profiles, applications) | feature distributions differ between train and target; performance drops on the shifted slice while in-distribution stays stable |
| Out-of-distribution input | feature values with zero or near-zero training support | support count in train (loopback `Host`: 0 rows) |
| Spurious correlation / shortcut | decision driven by a feature that is label-correlated in train but not causal | **both** a label skew in train (`127.0.0.1` appears in 0 ALLOW / 58 BLOCK train rows) **and** a one-variable A/B that flips the decision |
| Coverage gap | a task region with too few logical groups | per-category and per-slice logical-group counts; errors concentrate there (D18 categories) |
| Label noise | the ground truth itself is wrong | re-inspection of labels; e.g. CSIC BLOCK labels come from a keyword heuristic (F6) |

V4 has one overfitting-type signal: `eval_loss` rose from 0.4632 at step 2200 to 0.4669 at
step 3144 (+0.8%), on a single seed and at loss level only. It is *consistent with* mild late
overfitting, and the best checkpoint was used regardless. It does not explain the
real-traffic false positives; those match out-of-distribution inputs and a possible
shortcut much better. Write "overfitting" only with gap evidence. Otherwise name the category
the evidence supports, or write "cause not established".

## 4. Error analysis before changing anything

1. **Identify** the FP and FN, with the exact input text and the model's reason.
2. **Group** them by pattern: category, source, client, host type, path, header set.
3. **Find what each group shares**, stated as a feature that can be counted.
4. **Contrast** that feature against train and eval: support and label split.
5. **Run controlled experiments** where the contrast is ambiguous (§8).
6. **Formulate one hypothesis** that the evidence supports, with its alternatives.
7. **Make one minimal change** that targets that hypothesis.
8. **Re-evaluate** on the same frozen sets, and check for regressions (§10).

Where V4 stands: false negatives are grouped (91 of 92 in SQL injection and command
injection), and steps 3–6 are still open. D21 forbids concluding "more data" before they
are done. The false positives found on 2026-09-17 went through steps 1–6: grouped into
loopback `Host`, path `/`, high `Host` port, and missing `User-Agent` with
`Proxy-Connection`; each had zero training support; A/B tests confirmed the effects in
context. No change has been made, which is correct at this stage.

**Keep raw results with the repository**, under `reports/<kind>/<experiment-id>/`. The raw
files of the 2026-09-17 experiment lived in a session scratchpad under `/tmp` and were lost
at the next reboot. Only an audit summary survives, outside the repository. It is not a
substitute for the raw data: its figures, used as examples in §7 and §8, cannot be
re-verified, so that run stands as a historical antecedent and not as evidence. **It was
repeated correctly on 2026-09-18 and persisted as `reports/diagnostics/real-http-fp-v1/`**,
which keeps the pre-registered cases, every raw record, the four process logs, the code and
the manifest inside the repository. That run, not the lost one, is the evidence on this
finding.

This changes nothing in the rules above. `real-http-fp-v1` is a **diagnostic** under §7, so
its 37 BLOCK decisions over 149 constructed benign texts are a **diagnostic count, not an
FPR** and not a rate of any kind: the case mix was built to provoke failures. The model's
measured FPR remains the one from the formal split.

## 5. Mandatory metrics

Binary decision, **BLOCK is the positive class** (D19) unless a report states otherwise:

| Metric | Definition |
|---|---|
| TP · TN · FP · FN | raw counts, always printed |
| Invalid outputs | count and rate over all requests |
| Accuracy | (TP + TN) / N |
| Precision BLOCK | TP / (TP + FP) |
| Recall BLOCK = ADR | TP / (TP + FN) |
| F1 BLOCK | 2 · P · R / (P + R) |
| FPR | FP / (FP + TN): benign denominator |
| FNR | FN / (FN + TP): attack denominator |

When applicable: FN and recall/ADR **per attack category** with the D18 evidence status;
FP **per source, client or request type**; reason accuracy only over TP (E5 level 2).

- Accuracy is never reported alone.
- Every percentage carries its numerator and denominator.
- Zero errors on *n* is a bound, not a zero rate: the 95% upper bound is ≈ 3/*n*.
- Precision and accuracy depend on class prevalence. State the test set's prevalence.
- Invalid outputs follow E5: never coerced, mapped to the opposite of the expected label,
  and shown next to a parseable-only view. Runtime fail-closed (503) is a separate concern.

## 6. Confusion matrix

Always this layout:

```
                 Pred ALLOW     Pred BLOCK
Real ALLOW           TN             FP
Real BLOCK           FN             TP
```

The E5 and V4 reports, and `test_model.py`, order both rows and columns BLOCK first. The
cell definitions are identical; those reports are not rewritten. New reports use this
layout.

## 7. Diagnostic experiments are not benchmarks

- A **benchmark or evaluation** uses a representative sample under a protocol fixed before
  measuring. Its rates can be reported.
- A **diagnostic experiment** is built to find or explain failures. Its composition is the
  experimenter's choice. Report pair-level outcomes and counts, never a rate.

Example (figures from the surviving audit summary, §4): in the 2026-09-17 experiment, 51 of
153 benign texts were classified BLOCK. All
51 came from constructed variants (51 / 93); the dataset rows gave 0 / 60. That proportion
reflects the experiment's design and is not an FPR of the model. The same holds for the
legacy 135-case manual suite: 6 FP out of 26 ALLOW cases is a diagnostic count. Latency
seen during a diagnostic run is an observation, not a benchmark.

Every report says in its first lines whether it is an evaluation or a diagnostic.

## 8. A/B tests and ablations

- Change **one variable**; keep the rest byte-identical. Record the exact text sent and
  its SHA-256.
- **Repeat** each case (≥ 3). Greedy decoding is deterministic, so repetition checks
  determinism and service state rather than estimating variance.
- **Test several contexts.** A flip in one context is "confirmed in that context", not
  general. In the 2026-09-17 audit summary (§4), changing only `localhost` to `127.0.0.1`
  in `Host` flipped ALLOW to BLOCK in 17
  of 50 pairs, left 21 unchanged and 12 were already BLOCK. Adding a `Cookie` or changing
  the path cancelled the effect.
- **Keep counterexamples** in the record. They bound the claim.
- **Separate layers.** Send the same text to `/classify` directly and through the proxy.
  30 / 30 identical decisions and reasons showed `render_request()` was not the cause.
- **Correlation is not causation.** A one-variable flip shows the model is sensitive to
  that feature in that context. It does not show *why* (for example, which training rows
  taught it).
- **Never add markers to a request under test** (correlation IDs, test headers). Every
  header is model input.

## 9. Reproducibility

Each formal evaluation records, where applicable: commit and dirty state · dataset version,
manifest and SHA-256 · model and adapter identity (hashes) · inference configuration (D27)
· seed · environment (`benchmark_env.py`) · sample size and selection · raw per-request
records · derived metrics. The existing tools already produce most of this: dataset
manifests, `test_model.py --json`, and `benchmark_inference.py`, which refuses to overwrite
an experiment id (D32).

## 10. Comparing versions

- V5, V6… are compared against the previous baseline **and** V4, on the same frozen sets,
  with the same metric code, side by side.
- The comparison shows per-category TP/FN (regressions in categories that were correct),
  FP per slice, invalid outputs, and latency through `benchmark_compare.py`.
- A version is not accepted because it fixes one case. The target failure must be fixed on
  the dev set **and** the frozen sets must show no regression beyond expected noise.
- Know the noise: per-category counts are small, and latency moves ≈ 11% between
  back-to-back runs on this laptop (`baseline-local-v1`).

## 11. Latency

| Layer | Covers | Instrument today |
|---|---|---|
| **Inference pipeline** | prompt construction, tokenization, transfer, `generate()`, decoding, parsing | `benchmark_inference.py` → `steady_pipeline_p95_ms`; `generate()` alone is its primary comparison metric (D31) |
| **`/classify`** | API receive → respond, including JSON and waiting on the inference lock | not instrumented; its `model_latency_ms` field covers `generate()` only |
| **Proxy → classifier** | the data plane's classifier call, round trip | `data_plane.py` log `(classifier N ms)` |
| **End-to-end** | extra time a client sees compared with going straight to the destination | none (Issue #18) |

**Objective (D36): P95 of the latency added by the inference pipeline ≤ 200 ms, in steady
state.** Model load, cold start and warm-up are reported separately; HTTP transport,
network, proxy and destination are excluded. It is measured under the `baseline-local-v1`
protocol: batch 1, concurrency 1, recorded hardware. The reference today is P95 **269.58
ms** (`generate()` alone 269.01 ms), so the objective is **not met**, and it must not be
presented as met. It is **not** an end-to-end objective; end-to-end latency is still
measured and reported, with no threshold defined. Reports produced before D36 use D3's
end-to-end wording and are not rewritten.

- Cold start, warm-up and steady state are separate populations and are never pooled
  silently.
- It is a benchmark only with a protocol written before measuring (D32). Anything else is
  an observation and is called one.
- Every latency number names its layer.

## 12. Before retraining or changing the dataset

A single failing example is an observation. It is not a reason to change the dataset or
the model.

```
observation → reproduction → error analysis → dataset analysis
            → external evaluation → hypothesis → justified change
```

Before a change, the change request states: the failures it targets (with counts), the
analysis that grouped them, the support found in train and eval, the external-test result,
the hypothesis and its alternatives, and the sets that will judge it. This extends D21.

## 13. Live runs

Evaluation runs that send traffic through the system keep every process visible: the
classifier, the proxy, the destination server and the client each run in the foreground,
in their own terminal pane or tab. Each process's output is also written to a per-run log
file kept with the run's results. Silent background runs are not used for evaluations.
