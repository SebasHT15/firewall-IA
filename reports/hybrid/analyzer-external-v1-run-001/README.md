# Analyzer × External Test v1 — `analyzer-external-v1-run-001`

**EVALUATION — offline, aggregate only.** This is the one post-freeze aggregate evaluation of
the frozen Lightweight Request Analyzer (Model 1) on External Test v1, as D53 allows under D40
and D45. It is **not** an evaluation of the gateway, of a Hybrid cascade, of Model 2 or of any
ALLOW / BLOCK / UNCERTAIN policy. The 0.5 threshold is **reporting-only** (D55). Model 1 stays
frozen and unchanged.

| | |
|---|---|
| Date (UTC) | 2026-10-05T05:13:20Z → 05:13:37Z |
| Base commit | `6641cc650cbfea063326a1689a0de7ee42c6c7dc` (`develop` = `origin/develop`), branch `research/hybrid-analyzer-external-v1-aggregate`; evaluator, tests and this folder uncommitted at run time |
| Analyzer | `hybrid-analyzer-v2/attack=hist_gb,category=hist_gb` · `model-output-hybrid-analyzer-v2/recommended.pkl` · 8,866,799 B · SHA-256 `79eb7265a7a3abd9f5a499234732042a9100729b4434971a02d73e03f6a2ff9b` |
| Freeze record | `reports/hybrid/phase2b-analyzer-v2-run-002/frozen_selection.json` · `86271a46…` |
| External v1 | `datasets/external_v1/cases.jsonl` · `721dfdaa6425463ae0ce26520f6d47986fdc7388468b55d7b1a5bffed822d342` · integrity hash `ccac5f55eee27f94a79295f0022edf6eac792abe828ed1a1fe5f43ac85c5e52b` · frozen at `36df2ee` |
| Environment | `.venv-analyzer`: Python 3.12.15 · numpy 2.5.3 · scikit-learn 1.9.1 · scipy 1.18.1 · joblib 1.6.0 · threadpoolctl 3.7.0 (identical to the run-002 test) |
| Evaluator | `scripts/evaluation/analyzer_external_v1.py` · `95809aa2cdd96e23b51d5e89fe7d532befc2908bd8a620116fd2e4e567360c02` |
| Tests | `tests/test_analyzer_external_v1.py` (48 synthetic tests) · `339c418baf6e0e5381c5086e330b776e5f19ebe9cb18f1e29575420add2fa28f` |
| Protocol | [`PROTOCOL.md`](PROTOCOL.md) · `6227213894a69fd5bccb005434fe634ee4a8660b553b0a6ca13a5cbfc3b07fbc` |
| Command | `.venv-analyzer/bin/python scripts/evaluation/analyzer_external_v1.py run --confirm-single-run` |
| Runs started | **1** (no retry; `run_metadata.json`: `runs_started 1`, `retries 0`) |

## 1. Procedure (fixed before exposure)

The plan, the metrics, the not-applicable list and the interpretation limits were written in
[`PROTOCOL.md`](PROTOCOL.md) before the Analyzer scored any External v1 case. The protocol was
revised twice before exposure, after two independent read-only audits, and both revisions are
recorded in its §8:

- a **methodology audit** led to the payload-visibility split, the group-weighted diagnostic,
  the internal reference and extra interpretation limits;
- a **code audit** found differencing leaks and led to a k ≥ 10 rule for every published figure.

The hashes of the protocol, the evaluator and the tests were frozen in
[`PREREGISTRATION.json`](PREREGISTRATION.json) and posted in the session transcript before the
run. `run` refuses to start if any of them changes.

The evaluator:

1. **Preflight, with no inference.** It checks:
   - branch, D39 ancestry and the allowlist of uncommitted paths;
   - that the frozen evidence is unchanged at HEAD;
   - the External v1 manifest, cases, per-case request hashes, integrity hash and `SHA256SUMS`;
   - balance 200 / 200, 10 cells × 40, and labels consistent with their cells;
   - the artifact hash and size;
   - the run-001 and run-002 `SHA256SUMS`;
   - the frozen code hashes and the dataset v2 hashes;
   - environment versions;
   - the feature schema and order, and the encoder columns against run-002 `preprocessing.json`;
   - the development vector relation, recomputed on 25,039 / 25,039 rows;
   - the `PREREGISTRATION.json` hashes and HEAD.

   The result is in [`preflight.json`](preflight.json).
2. **Synthetic test suite.** 48/48 passed, run in a subprocess before the start.
3. **Start of the single run.** `run_attempt.json` is created exclusively; its existence blocks
   any later start.
4. **Feature extraction.** Each frozen `request_text` (the D1 text) goes through
   `request_features.extract_features` (v2, 34 features) and then the encoders frozen inside
   the artifact.
5. **Scoring.** One batch `predict_proba` for `attack` and the category head. The contract
   path `analyze()` is also run per request and compared with the batch result.
6. **Aggregation and write.** Aggregate metrics only. An output scanner rejects case ids,
   request hashes or texts, numpy values, lists longer than 16 and dicts with more than 24 keys.

Nothing was refitted, recalibrated or thresholded.

## 2. Data

400 cases: **200 ALLOW / 200 BLOCK**, 50/50 by construction (D42), so **not an operational
prevalence**. There are 10 pre-registered cells of 40 cases each:

- 5 benign slices: `browser-navigation`, `browser-forms-session`, `api-json`, `api-query`,
  `unseen-structure`;
- 5 attack categories: `sqli`, `cmdi`, `xss`, `path-traversal`, `ssrf`.

Every cell has support status `OK` (n ≥ 30). Labels are the frozen `expected_decision`, set
from flow intent before any model exposure.

## 3. Results — `attack` head (n = 400)

**Threshold-free.** 95% CI from a class-stratified case bootstrap (2,000 resamples). The cases
are not independent draws, so the intervals are optimistic.

| Metric | External v1 | 95% CI | Internal reference † |
|---|---:|---|---:|
| ROC-AUC | **0.943** | 0.922 – 0.961 | 0.994 |
| PR-AUC (chance level 0.5) | 0.946 | 0.926 – 0.962 | not compared (prevalence) |
| Brier | **0.127** | 0.102 – 0.156 | 0.033 |
| Log loss | 0.471 | 0.372 – 0.584 | 0.106 |
| ECE (15 bins) | **0.126** | — | 0.024 |

† Same frozen Analyzer, run-002 `internal_test_feature_disjoint` (n = 5,456, 55.6% BLOCK).
That is a **SECOND-LOOK INTERNAL EVALUATION AFTER METHODOLOGY CORRECTION — NOT AN UNTOUCHED
TEST** (D54). The gap is internal second look → external. It is not proven overfitting (D42).

**Reliability.** The k-rule hid the 11 middle bins: 53 cases sit in [0.133, 0.867].

| Bin | n | Mean predicted | Observed frequency |
|---|---:|---:|---:|
| [0, 0.067) | 114 | 0.013 | 0.009 |
| [0.067, 0.133) | 15 | 0.109 | 0.133 |
| [0.867, 0.933) | 21 | 0.903 | 0.524 |
| [0.933, 1] | 197 | 0.990 | 0.848 |

The top bins are **over-confident**: about 15% of the cases scored ≥ 0.933 are ALLOW. The low
bins are well calibrated.

**At the reporting-only 0.5 threshold (D55).** The confusion matrix uses the methodology §6
layout.

```
                 Pred ALLOW     Pred BLOCK
Real ALLOW        TN 150         FP  50
Real BLOCK        FN  12         TP 188
```

| Rate | Value | Wilson 95% |
|---|---|---|
| Recall (BLOCK) | 188/200 = 94.0% | 89.8 – 96.5% |
| FPR | 50/200 = 25.0% | 19.5 – 31.4% |
| FNR | 12/200 = 6.0% | 3.5 – 10.2% |
| Precision (BLOCK), at 50/50 prevalence | 188/238 = 79.0% | 73.4 – 83.7% |
| Accuracy, at 50/50 prevalence | 338/400 = 84.5% | 80.6 – 87.7% |
| F1 (BLOCK) | 0.858 | — |

**Contract check.** 0 `AnalyzerOutput` contract violations, 0 mismatches between `analyze()`
and the batch result, 0 non-finite probabilities, 0 warnings during the run.

### Per cell (n = 40 each, status OK)

| Benign slice | FP / 40 | FPR (Wilson 95%) | Mean `attack` | ROC-AUC vs all 200 BLOCK |
|---|---:|---|---:|---:|
| browser-navigation | 4 | 10.0% (4.0–23.1) | 0.111 | 0.989 |
| browser-forms-session | 4 | 10.0% (4.0–23.1) | 0.132 | 0.978 |
| **api-json** | **29** | **72.5% (57.2–83.9)** | 0.681 | 0.843 |
| api-query | 13 | 32.5% (20.1–48.0) | 0.371 | 0.914 |
| unseen-structure | 0 | 0.0% (0–8.8; rule of three ≈ 7.5%) | 0.081 | 0.992 |

| Attack cell | TP / 40 | Recall (Wilson 95%) | Mean `attack` | ROC-AUC, all 200 ALLOW vs cell |
|---|---:|---|---:|---:|
| sqli | 39 | 97.5% (87.1–99.6) | 0.969 | 0.979 |
| **cmdi** | **32** | **80.0% (65.2–89.5)** | 0.831 | 0.888 |
| xss | 38 | 95.0% (83.5–98.6) | 0.961 | 0.970 |
| path-traversal | 40 | 100% (91.2–100; rule of three ≈ 7.5%) | 0.996 | 0.992 |
| ssrf | 39 | 97.5% (87.1–99.6) | 0.911 | 0.886 |

### BLOCK recall by payload visibility (pre-registered, PROTOCOL §3.2b)

| Placement | BLOCK cases | TP · FN | Recall at 0.5 | Status |
|---|---:|---|---|---|
| visible (query / path / form / json) | 195 | 188 · 7 | 96.4% (92.8–98.3) | OK |
| invisible (header / cookie; D44) | 5 | 0 · 5 | 0/5 | INSUFFICIENT DATA — exploratory |

Five of the 12 false negatives carry their payload in a header or cookie. RequestFeatures never
reads those (D44), so this is a **structural blind spot** like JWT (D48), not a generalization
result. The 5-case count is a small-n count accepted by the protocol's k-rule exemption for
confusion counts.

## 4. Category head (auxiliary context, D46 — not a security decision)

The category head was evaluated on the 200 ground-truth BLOCK cases. The mapping comes from
D47 / D49: `sqli → sql_injection`, `cmdi → command_injection`, `xss → xss`,
`path-traversal → path_file_access`, `ssrf → ssrf`.

- **Top-1 accuracy:** 74/200 = **37.0%** (Wilson 30.6–43.9%).
- **Macro-F1 over the 5 sampled categories:** 0.351. This is not comparable with the internal
  8-class figure of 0.664.
- **Multiclass log loss:** 4.31.
- **Multiclass Brier:** 1.007.
- **Mean top-1 probability:** 0.823, so the head is confident and mostly wrong.
- **Predictions into categories External v1 does not sample** (`ssti`, `open_redirect`,
  `other_attack`): 37 of 200.

| True → predicted | sql_inj | xss | path_file | cmd_inj | ssti | open_redir | ssrf | other | Recall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| sqli | 12 | 7 | 8 | 1 | 4 | 3 | 5 | 0 | 30% |
| cmdi | 3 | 8 | 14 | 2 | 2 | 6 | 3 | 2 | 5% |
| xss | 2 | 29 | 3 | 1 | 4 | 0 | 1 | 0 | 72.5% |
| path-traversal | 3 | 0 | 28 | 0 | 0 | 2 | 7 | 0 | 70% |
| ssrf | 4 | 2 | 16 | 1 | 1 | 11 | 3 | 2 | 7.5% |

The category head does not transfer to External v1, except partly for `xss` and
`path_file_access`. This is consistent with its documented reliance on `path_length` (an
endpoint artifact) and its weak internal `ssrf` F1 (≈ 0.25).

## 5. Descriptive aggregates and diagnostics

- **Distinct 34-feature vectors:** 325 among 400 cases. 6 cases share a vector with a case of
  the other label.
- **Feature vector also in `hybrid_analyzer_v2` TRAIN ∪ VALIDATION:** 2 ALLOW, 0 BLOCK.
- **`method` / `content_type` encoded as unseen `__other__`:** 5 / 5 ALLOW cases, 0 BLOCK.
- **Feature-disjoint view: `SUPPRESSED`.** The k-rule triggered because one cell ×
  in-development part holds 1 case, and publishing it would let a reader difference
  individual cases against the per-cell figures. Since only 2 of 400 cases are "in
  development", the full set is effectively feature-disjoint.
- **Group-weighted diagnostic (D55): `SUPPRESSED` by the k-rule**, with counts only:
  - 324 groups under the D54 relation without its generator component;
  - 17 groups hold more than one case, covering 93 cases;
  - one cell × group-size part holds 1 case.

  This is an expected, pre-registered outcome of the privacy rule, not a defect. Row-weighted
  metrics remain the reported metrics (D55).

## 6. Side by side with V4 (published aggregates only)

V4 was measured **through the complete gateway** (`external-v1-run-001`, L1, repetition 1), at
its real decision. The Analyzer is measured **offline** on the frozen D1 text, at the
**reporting-only** 0.5. V4 reads the whole D1 text, headers included; the Analyzer reads 34
features.

**This is not an operating-point comparison and not a cascade estimate.** No joint V4 ×
Analyzer count was computed (PROTOCOL §3.5), and none can be inferred from these marginals.

| On External v1 | V4 (gateway, real decision) | Analyzer (offline, 0.5 reporting-only) |
|---|---|---|
| Recall (BLOCK) | 199/200 | 188/200 |
| FPR | 68/200 | 50/200 |
| browser-navigation FP | 7/40 | 4/40 |
| browser-forms-session FP | 4/40 | 4/40 |
| api-json FP | 21/40 | 29/40 |
| api-query FP | 12/40 | 13/40 |
| unseen-structure FP | 24/40 | 0/40 |
| sqli · cmdi · xss · path-traversal · ssrf recall | 40 · 40 · 40 · 40 · 39 /40 | 39 · 32 · 38 · 40 · 39 /40 |

## 7. Interpretation (prudent)

**Supported by this run:**

- The frozen Analyzer **ranks** External v1 requests well but clearly below its internal
  second look: ROC-AUC 0.943 (CI 0.92–0.96) vs 0.994.
- Its **probabilities are over-confident** externally: ECE 0.126 vs 0.024, Brier 0.127 vs 0.033,
  with ≈ 15% ALLOW among the cases scored ≥ 0.933. Native probabilities that were well
  calibrated internally do not stay calibrated on this external shift.
- At the reporting-only 0.5, it shows 25% FPR and 94% recall on this 50/50 test. The FPR is
  concentrated in `api-json` (72.5%) and `api-query` (32.5%). The recall loss sits in `cmdi`
  (80%) and in payloads the features cannot see (0/5 header / cookie).
- The **category head does not transfer** (top-1 37%). It is context only and must not be
  relied on for External-like traffic.

**Not supported by this run:**

- That the Analyzer is better or worse than V4 as a firewall. The two were measured
  differently, and 0.5 is not an operating point.
- That a V4 + Analyzer cascade would reduce V4's false positives. The marginal slice patterns
  differ — for example, `unseen-structure` FP is 0/40 for the Analyzer and 24/40 for V4 —
  but **case-level overlap is unknown**, and estimating it from External v1 would consume the
  set (D40 / D45).
- Any operational FPR, precision or prevalence (D42), or a cause for the errors. No case was
  inspected.
- That Model 1 should be changed. **D53: this result does not modify Model 1**; no threshold,
  calibrator or feature is chosen from it.

## 8. Limitations

- One lab application, 5 of 19 attack categories, n = 40 per cell. The CIs are optimistic
  because the cases are clustered.
- 15-bin ECE at n = 400 is biased upward. Log loss is driven by a few confident errors.
- The internal reference is a second look, not an untouched test (D54).
- Unseen `method` / `content_type` values (5 ALLOW cases) fall into an `__other__` column that
  is constant in TRAIN, so those cases are extrapolation.
- V4's per-cell External v1 aggregates were known before Hybrid Phase 2A. That is not
  consumption, but the programme was not blind to External v1 at aggregate level.
- **Disclosed deviation — pre-registration not committed.** The owner instructed "no commit /
  push / PR" for this checkpoint. Pre-registration is therefore self-attested:
  `PREREGISTRATION.json` was written exclusively, `run` checked its hashes, and the same hashes
  were posted in the session transcript before the run. It has no external timestamp. Commit
  `PROTOCOL.md`, `PREREGISTRATION.json`, the evaluator, the tests and these results together.
- Some outputs are suppressed by the k ≥ 10 rule: the feature-disjoint view, the group-weighted
  diagnostic, the 11 middle reliability bins and the visibility means. This is the price of
  aggregate-only output.

## 9. What this does to the data roles

- **External v1 is not consumed** (D40): only aggregate and per-cell figures were produced; no
  individual case, prediction or error was inspected or persisted.
- External v1 remains V4's valid external record and was used here exactly once for Model 1
  (D53). **Model 1 stays frozen.** No new decision was taken.
- The next step (FP / disagreement analysis V4 ↔ Analyzer) starts on **development and
  diagnostic data**, such as `real-http-fp-v1`, not on External v1 cases.

## Files

| File | Content |
|---|---|
| `PROTOCOL.md` | Pre-registered protocol, with 2 pre-exposure revisions (§8) |
| `PREREGISTRATION.json` | Hashes of protocol / evaluator / tests and HEAD, before exposure |
| `preflight.json` | All integrity checks, no inference |
| `run_attempt.json` | Created exclusively at the start; embeds the preflight at start |
| `aggregate_results.json` | Every aggregate figure (source of this README) |
| `run_metadata.json` | Timing, command, environment, hashes, `runs_started 1` |
| `console.log` | Everything the run printed (aggregates only) |
| `SHA256SUMS` | Hashes of all of the above |
