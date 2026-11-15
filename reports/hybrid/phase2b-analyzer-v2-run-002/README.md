# Hybrid Architecture Phase 2B — run-002: `hybrid_analyzer_v2` and the frozen Lightweight Analyzer

**Kind: experiment record (research environment).** Issue #53 · decisions **D54** (generator-group
grouping, `hybrid_analyzer_v2`, one second look) and **D55** (evaluation conventions) · 2026-10-03/04.

**Status: Lightweight Request Analyzer — FROZEN** as
`hybrid-analyzer-v2/attack=hist_gb,category=hist_gb` (§11). External Test v1 was **not read**.
Nothing is integrated into the gateway. Run-001
([`../phase2b-analyzer-baselines/`](../phase2b-analyzer-baselines/), with its
[`ERRATA.md`](../phase2b-analyzer-baselines/ERRATA.md)) is unchanged historical evidence.

> INTERNAL TEST results in §9 are a **SECOND-LOOK INTERNAL EVALUATION AFTER METHODOLOGY
> CORRECTION — NOT AN UNTOUCHED TEST.** INTERNAL TEST was first read by run-001.

| § | Content |
|---|---|
| 1 | Why run-002 exists |
| 2 | Generator-group audit and provenance recovery |
| 3 | `hybrid_analyzer_v2` |
| 4 | Protocol (what is unchanged, what changed, and why) |
| 5 | VALIDATION results |
| 6 | Ablation |
| 7 | Interpretability |
| 8 | Latency and footprint |
| 9 | Freeze, then the second look |
| 10 | run-001 vs run-002 |
| 11 | Frozen Analyzer, risks, criteria |
| 12 | Reproduce · files and hashes |

---

## 1. Why run-002 exists

Run-001 selected models on a VALIDATION carve-out (D51) whose groups ignored the V4 generator's
own grouping. With the generator groups recovered exactly (§2), **646 of 4,980 run-001
VALIDATION rows (13.0%) had a generator sibling in TRAIN** and 520 generator groups were split
across TRAIN / VALIDATION; between V4 train and V4 eval the count is 0. VALIDATION was easier
than INTERNAL TEST, and the run-001 choice (random forest + isotonic) did not transfer. D54
corrects the grouping; run-002 repeats the selection on the corrected data with the run-001
families and grids, then reads INTERNAL TEST once more after a complete freeze.

## 2. Generator-group audit and provenance recovery

`parse_dataset_v4.py` (the V4 generator) splits train / eval by `group_id(kind, key)`:

| Kind | Key | Rows of one group |
|---|---|---|
| `attack` | `canonical_key(payload)` | the base rendering + its augmentation variant(s), possibly on different paths / parameters |
| `csic_attack`, `csic_benign` | `csic_group_key`: method, path, parameters with digits collapsed and values decoded | every CSIC record of that request shape |
| `benign` (synthetic) | `shape|path|param|value` | always 1 (the renderer redraws path, parameter and value) |

The id lives only in memory (`_gid`) and is stripped when the JSONL is written. It is **recovered,
not approximated**:
[`scripts/dataset/recover_v4_provenance.py`](../../../scripts/dataset/recover_v4_provenance.py)
re-runs the unmodified generator (default arguments = V4 manifest: seed 42, eval 0.2, cap 2500
policy B, row cap 4000, one augmentation), observes each written row's `_gid`, and accepts
the result only if both regenerated files are **byte-identical** to V4-clean
(`4459f686…` / `61f15591…`). Inputs verified: `csic_database.csv` (`c420f0bc…`),
PayloadsAllTheThings at `e961fef`. 22,230 generator groups; none spans V4 train / eval.

**Independent audit** (Opus subagent, read-only), done before any v2 model was fitted:

- *Attack rows:* the input was re-rendered from the recovered gid for 11,764 / 11,764 rows.
- *Synthetic benign rows:* re-rendered for 8,397 / 8,397.
- *CSIC rows:* `group_id(kind, csic_group_key(...))` was recomputed for 11,179 / 11,179; this
  check is also a unit test.
- *Generator logic:* no other relation crosses the generator's split. Exact duplicates removed
  by dedup always share a gid.
- *Should-fix items:* the manifest's code hashes were stale, and two accepted properties needed
  documenting (below). Both were applied before training.

## 3. `hybrid_analyzer_v2`

[`scripts/dataset/build_hybrid_analyzer_v2.py`](../../../scripts/dataset/build_hybrid_analyzer_v2.py) ·
manifest [`datasets/manifest_hybrid_analyzer_v2.json`](../../../datasets/manifest_hybrid_analyzer_v2.json)
(`40f958ea…`) · JSONL regenerated locally (gitignored): 31,340 rows, SHA-256
`e8da8674435ed65057161bb4c74b41dc4aa1d8bf876b0327c53ecba7c0d99b75`. Byte-identical across runs
and `PYTHONHASHSEED` values. Runs in the ML environment, because the generator needs pandas.
Features, targets, JWT policy and INTERNAL TEST views are identical to v1 (unit-tested).

**Group** = connected components over V4 train of "same canonical request OR same feature
vector OR same generator group". **VALIDATION** ≈ 20%, stratified by group target, groups never
split. Salt `hybrid-analyzer-v2-validation`.

| | TRAIN | VALIDATION | v1 (TRAIN / VALIDATION) |
|---|---:|---:|---:|
| rows (all) | 20,175 | 4,959 (19.73% of V4 train) | 20,141 / 4,993 |
| fitted (JWT out) | 20,104 | 4,935 | 20,059 / 4,980 |
| ALLOW / BLOCK | 10,117 / 9,987 | 2,450 / 2,485 | 10,028 / 10,031 · 2,539 / 2,441 |
| `unsupported_jwt` rows (never fitted) | 71 | 24 | 82 / 13 |
| D54 groups (largest) | 13,575 (417) | 3,216 (395) | — |

| Category | TRAIN | VALIDATION | VALIDATION share of stratum |
|---|---:|---:|---:|
| `sql_injection` | 2,561 | 622 | 20.0% |
| `xss` | 2,334 | 586 | 20.0% |
| `path_file_access` | 3,282 | 824 | 20.0% |
| `command_injection` | 486 | 121 | 19.9% |
| `ssti` | 314 | 79 | 20.1% |
| `open_redirect` | 166 | 42 | 20.2% |
| `ssrf` | 149 | 37 | 19.9% |
| `other_attack` | 695 | 174 | 20.0% |
| `mixed` stratum (label-conflict groups) | — | — | 5.0% (see below) |

- **Development groups:** 16,791 in total. Sizes: 14,305 of size 1, 2,110 of size 2, 237 of 3–5,
  93 of 6–10, 18 of 11–50, 23 of 51–200, 5 above 200. 5,151 rows sit in groups of ≥ 10.
- **Leakage TRAIN ↔ VALIDATION** (builder-asserted and unit-tested): canonical request **0**,
  feature vector **0**, generator group **0**, D54 group 0.
- **Internal duplication is not leakage** (distinct canonical requests / vectors / generator
  groups / D54 groups):
  - TRAIN 20,175 rows: 16,564 / 15,148 / 14,343 / 13,575.
  - VALIDATION 4,959 rows: 3,774 / 3,600 / 3,389 / 3,216.
  - INTERNAL TEST 6,206 rows: 5,139 / 4,917 / 4,498 / 4,443 (V4 eval groups, used for
    group-weighted test metrics).
- **INTERNAL TEST flags** (against TRAIN ∪ VALIDATION, JWT excluded): vector 734, canonical
  request 127, generator family **0**. Views: full 6,190, feature-disjoint 5,456,
  `unsupported_jwt` 16 — all unchanged from v1.
- **Accepted properties (audit):**
  - VALIDATION shares nothing with TRAIN, whereas INTERNAL TEST full shares 734 vectors with
    the development set. VALIDATION therefore mirrors the **feature-disjoint** view.
  - The two large `mixed` CSIC components (benign + `sql_injection`, 223 and 216 rows) can
    never enter VALIDATION under the 20% rule. VALIDATION is therefore slightly easier on CSIC
    benign-vs-SQLi ambiguity: such rows are 0.26% of VALIDATION, 0.86% of INTERNAL TEST and
    1.23% of TRAIN. §9.1 shows where this mattered.

## 4. Protocol

**Unchanged from run-001:**
- the three families and every grid configuration (LR 5 attack / 7 category, RF 4 / 4,
  HGB 4 / 4; full list in `experiment_config.json` or in run-001's README §5);
- preprocessing (LR: `log1p` counts in the grid, standardization fit on TRAIN, one-hot with an
  `__other__` bucket; trees: raw values and the same one-hot);
- per-family selection rules (attack: highest VALIDATION ROC-AUC; category: highest macro-F1);
- 5 calibration group folds, seeds, bootstrap (1,000 resamples of groups), permutation
  importance, the benchmark harness and the ablation policy;
- no MLP.

**Changed, all declared before any v2 model was fitted:**

| Change | Run-001 | Run-002 | Origin |
|---|---|---|---|
| Dataset | v1 (D51) | v2 (D54) | the defect |
| `select` / `bench` input | full file | TRAIN + VALIDATION rows only (asserted) | hardening |
| Calibration rule | Brier bootstrap CI < 0 | same, **and** OOF log loss not worse (guard) | owner's instruction to be careful with isotonic; informed by run-001's test (D55) |
| Cross-family winner | judgement | **mechanical**: lowest calibrated-OOF Brier / highest macro-F1; families whose paired group-bootstrap CI vs the best includes 0 are tied; among tied, lowest bench P50 | to minimize post-test adaptation |
| Test group unit | canonical request | D54 group of V4 eval | group-weighted diagnostic over families |
| Test label, guards | — | second-look label; `bench` / `freeze` / `test` refuse to overwrite frozen evidence; `test` pins dataset and records code hashes | code review before freeze |

The 0.5 threshold is **reporting-only** (D55): it fills confusion counts and is not an operating
point. Two read-only subagents were used: one audited the provenance and split (§2), the other
reviewed the freeze / test / metrics code before the freeze. It found no scoring bug; its
process fixes (bench guard, latency-to-model check, atomic test write, dataset pinning) were
applied before `freeze`.

## 5. VALIDATION results (hybrid_analyzer_v2, 4,935 fitted rows)

### Attack

**Per-family selection.** The VALIDATION ROC-AUC of each configuration:

- **LR:** C 0.01 → 0.9633 · 0.1 → 0.9665 · 1 → 0.9666 · 10 → 0.9666 · **C 1 without log1p →
  0.9701**. In run-001 `log1p` won marginally; here its absence wins.
- **RF:** **300/1 → 0.9895** · 100/1 → 0.9880 · 100/5 → 0.9889 · 300/5 → 0.9894.
- **HGB:** 100/15 → 0.9947 · **100/31 → 0.9961** · 300/15 → 0.9961 · 300/31 → 0.9958.

Selected configuration per family, final outputs. No calibrator passed the rule for any
family, so native = calibrated OOF:

| | TP | TN | FP | FN | Acc | Prec | Recall | F1 | FPR | FNR | ROC-AUC | PR-AUC | Brier | log loss | ECE |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| prior | 2,485 | 0 | 2,450 | 0 | 0.496 | — | 1.000 | — | 1.000 | 0 | 0.500 | — | 0.250 | — | — |
| LR | 2,298 | 2,203 | 247 | 187 | 0.912 | 0.903 | 0.925 | 0.914 | 0.101 | 0.075 | 0.9701 | 0.9768 | 0.0606 | 0.210 | 0.030 |
| RF | 2,411 | 1,976 | 474 | 74 | 0.889 | 0.836 | 0.970 | 0.898 | 0.193 | 0.030 | 0.9895 | 0.9919 | 0.0448 | 0.167 | 0.059 |
| **HGB** | 2,401 | 2,419 | **31** | 84 | **0.977** | **0.987** | 0.966 | **0.977** | **0.013** | 0.034 | **0.9961** | **0.9967** | **0.0192** | **0.072** | **0.008** |

**Group-weighted (3,205 VALIDATION groups, diagnostic):**

| | FPR | ROC-AUC | Brier |
|---|---:|---:|---:|
| LR | 0.149 | 0.958 | 0.075 |
| RF | 0.031 | 0.992 | 0.027 |
| HGB | 0.024 | 0.993 | 0.026 |

RF's row-level FPR is dominated by a single 395-row CSIC benign group (92% of its FPs are in its
top two groups). In run-001 it was HGB that misjudged a large CSIC cluster. Single-vector
clusters swing row-level metrics in whichever direction a model errs on them, which is why the
group-weighted view is a standing diagnostic (D55).

**Calibration** (OOF over 5 group folds; ΔBrier = candidate − native, group-bootstrap 95% CI):

| Family | sigmoid | isotonic | Kept |
|---|---|---|---|
| LR | ΔBrier [−0.0002, +0.0014] | ΔBrier [−0.0024, +0.0023]; log loss 0.214 vs 0.210 | **native** |
| RF | ΔBrier [+0.0001, +0.0072] | ΔBrier [−0.0131, +0.0073]; 1,991 exact-1 outputs | **native** |
| HGB | ΔBrier [−0.00004, +0.0010] | ΔBrier [−0.0001, +0.0013]; log loss 0.089 vs 0.072; 3,270 exact 0/1 | **native** |

No calibrator was supported. "Uncalibrated" is the selected outcome. HGB native has VALIDATION
ECE 0.008 and no exact 0/1 outputs.

**Seed stability:**
- RF ROC-AUC across seeds 0 / 1 / 2: 0.9895 / 0.9903 / 0.9890.
- HGB is identical across seeds (no stochastic component with these settings).
- LR is deterministic.

### Category (BLOCK rows, 2,485)

| | macro-F1 | micro-F1 | log loss | mean top-1 P | top-1 ECE |
|---|---:|---:|---:|---:|---:|
| majority (`path_file_access`) | 0.062 | — | — | — | — |
| LR (C 10, balanced) | 0.453 | 0.627 | 1.160 | 0.587 | 0.054 |
| RF (100, balanced_subsample) | 0.636 | 0.811 | 0.797 | 0.747 | 0.069 |
| **HGB (300, balanced)** | **0.683** | **0.825** | 0.745 | 0.926 | 0.103 |

HGB per class (P / R / F1, support):

| Class | P | R | F1 | Support |
|---|---:|---:|---:|---:|
| `sql_injection` | 0.850 | 0.794 | 0.821 | 622 |
| `xss` | 0.791 | 0.853 | 0.821 | 586 |
| `path_file_access` | 0.913 | 0.944 | 0.928 | 824 |
| `command_injection` | 0.533 | 0.537 | 0.535 | 121 |
| `ssti` | 0.750 | 0.646 | 0.694 | 79 |
| `open_redirect` | 0.679 | 0.452 | 0.543 | 42 |
| `ssrf` | 0.444 | 0.324 | 0.375 | 37 |
| `other_attack` | 0.743 | 0.747 | 0.745 | 174 |

Confusion matrices for every family are in `validation_results.json`. HGB's category
probabilities are over-confident (mean top-1 0.93 vs accuracy 0.82) and are not calibrated
(D46: auxiliary context).

**Paired group bootstrap, 95% CI.** Attack, calibrated-OOF ΔBrier:
- RF − HGB: [+0.0002, +0.0708]
- LR − HGB: [+0.0316, +0.0532]

Category, Δ macro-F1:
- RF − HGB: [−0.076, −0.019]
- LR − HGB: [−0.263, −0.193]

No family is tied with HGB in either task.

## 6. Mandatory category ablation (D46) — without `path_length`, `path_depth`

| Family | VALIDATION macro-F1 full → ablation (Δ) | INTERNAL TEST disjoint, second look (Δ) |
|---|---|---|
| LR | 0.453 → 0.451 (−0.002) | 0.486 → 0.483 (−0.003) |
| RF | 0.636 → 0.598 (−0.038) | 0.637 → 0.578 (−0.059) |
| **HGB** | 0.683 → 0.621 (**−0.061**) | 0.664 → 0.601 (**−0.063**) |

HGB per-class Δ F1 on VALIDATION:
- large drops: `ssti` −0.197, `command_injection` −0.122;
- smaller drops: `ssrf` −0.037, `xss` −0.034, `open_redirect` −0.030, `other_attack` −0.030,
  `sql_injection` −0.024, `path_file_access` −0.018.

The diagnostic variant that also drops `slash_count`: HGB −0.076, RF −0.043, LR −0.001.

*Interpretation:* about 0.06 macro-F1 of HGB's category quality depends on two path-structure
fields that proxy the synthetic endpoint. That is a quarter of HGB's gain over LR, concentrated
in `ssti` and `command_injection`; the large classes barely move. This is the same picture as
run-001 (−0.070 / −0.079). The category remains **low-confidence auxiliary context**. No
"shortcut" threshold is invented.

## 7. Interpretability (field-level permutation importance on VALIDATION; LR coefficients)

| Model | Top fields (rank of the watched fields) |
|---|---|
| **attack HGB** (frozen) | `percent_encoded_ratio` #1, `percent_count` #2, `symbol_count` #3, `total_param_count`, `alnum_ratio`, `entropy_bits_per_char` #6, `path_length` #7; `body_length` #9, `query_length` #10, `method` #14, `content_type` #18, `body_format` #25 |
| **category HGB** (frozen) | **`path_length` #1**, `entropy_bits_per_char` #2, `percent_encoded_ratio` #3, `alnum_ratio`, `longest_char_run`, `symbol_count`, `body_format` #7, `path_depth` #9 |
| attack RF | `symbol_count`, `percent_count`, `percent_encoded_ratio`, `body_length`, `percent_encoded_count`, `query_length` |
| attack LR | `ampersand_count` (coef −5.50), `semicolon_count` (+3.12), `query_length` (+2.69), `body_length` (+1.66) |

The shortcuts survive the corrected grouping:
- **Attack:** percent-encoding is the main signal, then raw symbol counts. The generator
  percent-encodes query and form payloads (Phase 2A §4).
- **Category:** `path_length` is the strongest single field, which is the endpoint artifact.
- **Low importance for attack:** `content_type`, `body_format` and `method`; the envelope
  neutralization still holds.

No feature was removed.

## 8. Latency and footprint

Same harness and controls as run-001: one request per call, single thread, a fresh process per
model, 500 warm-up calls, 4,935 VALIDATION requests × 2 passes (n = 9,870), nearest-rank
percentiles, scikit-learn `predict_proba`. Milliseconds.

| | LR | RF | HGB | **frozen Analyzer** (HGB + HGB) |
|---|---:|---:|---:|---:|
| artifact (bytes) | 7,156 | 93,597,029 | 8,850,902 | **8,866,799** |
| `pickle.load` (s) | 0.0001 | 0.061 | 0.026 | 0.029 |
| RSS after load (MiB) | +0.0 | +180.2 | +15.2 | **+15.2** |
| first call | 1.13 | 11.37 | 9.70 | 9.90 |
| preprocessing P50 / P95 | 0.022 / 0.024 | 0.015 / 0.019 | 0.016 / 0.023 | 0.018 / 0.021 |
| attack inference P50 / P95 / P99 / max | 0.061 / 0.073 / 0.078 / 0.108 | 7.78 / 8.06 / 8.20 / 12.05 | 0.47 / 0.55 / 0.58 / 1.48 | **0.49 / 0.54 / 0.57 / 1.26** |
| category inference P50 / P95 / P99 / max | 0.056 / 0.063 / 0.067 / 0.095 | 2.76 / 2.90 / 2.99 / 3.77 | 8.10 / 8.73 / 9.04 / 16.65 | **8.39 / 8.66 / 8.85 / 19.97** |
| **Analyzer call** P50 / P95 / P99 / max | 0.14 / 0.15 / 0.16 / 0.25 | 10.53 / 10.87 / 11.08 / 12.88 | 8.60 / 9.34 / 9.69 / 13.87 | **8.92 / 9.22 / 9.43 / 15.76** |
| extraction + Analyzer P50 / P95 | 0.18 / 0.20 | 10.64 / 10.98 | 8.66 / 9.39 | 8.99 / 9.30 |
| throughput (req/s, one thread) | 7,301 | 96.9 | 113.7 | 111.5 |
| contract violations | 0 | 0 | 0 | 0 |

Against run-001's frozen composite (RF attack + HGB category: 17.08 / 17.85 ms, 48.8 MB,
+93 MiB), the run-002 Analyzer is about half the latency, 5.5× smaller and 6× lighter in memory.

- **Attack:** 0.49 ms P50. The **category model** (300 iterations × 8 classes) is 94% of the
  call.
- **LR:** faster than in run-001 (0.14 vs 0.50 ms), because it now has no calibration wrapper.
- No threshold exists for this component and none is set. The runtime is still to be decided
  (D52).

## 9. Freeze, then the second look

**Freeze** — [`frozen_selection.json`](frozen_selection.json), SHA-256
`86271a46b9e2dbf85fe2c421c68c9b45ea0e73b6de7dd23eac6065a7b454b8a5`, written **2026-10-04 06:10:33 UTC**.
It records:
- the dataset name, manifest and artifact hashes, grouping semantics and split salt;
- the feature order and both encoders (exact preprocessing);
- the candidate families, both grids and every selection, calibration and winner rule;
- the mechanical winner record;
- the exact hyperparameters: attack HGB `max_iter=100, max_leaf_nodes=31`; category HGB
  `max_iter=300, class_weight=balanced`; both with `learning_rate=0.1, early_stopping=False`;
- the calibration choice (native, with its bootstrap steps);
- the VALIDATION metrics, including group-weighted ones, and the ablation result;
- the 0.5 reporting-only policy;
- the SHA-256 of every model, of `recommended.pkl` (`79eb7265…`), of the evidence files and of
  the code.

**Second look.**
- The frozen file hash was re-checked at **06:14:28 UTC**.
- `test` ran once after that. It verified every hash, the dataset and the run, and recorded
  `code_changed_since_freeze: []`.
- It also recorded the hash of run-001's `internal_test_results.json` (`d1c40280…`, unchanged).

### 9.1 Attack — INTERNAL TEST (second look)

| View | Model | TP | TN | FP | FN | Acc | Prec | Recall | F1 | FPR | FNR | ROC-AUC | PR-AUC | Brier | log loss | ECE |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **disjoint (5,456; 55.6% BLOCK)** | LR | 2,765 | 2,155 | 268 | 268 | 0.902 | 0.912 | 0.912 | 0.912 | 0.111 | 0.088 | 0.9666 | 0.9771 | 0.0679 | 0.228 | 0.026 |
| | RF | 2,912 | 2,262 | 161 | 121 | 0.948 | 0.948 | 0.960 | 0.954 | 0.066 | 0.040 | 0.9863 | 0.9894 | 0.0415 | 0.157 | 0.032 |
| | **HGB (frozen)** | 2,909 | 2,279 | 144 | 124 | **0.951** | **0.953** | 0.959 | **0.956** | **0.059** | 0.041 | **0.9936** | **0.9953** | **0.0335** | **0.106** | **0.024** |
| full (6,190; 49.9% BLOCK) | LR | 2,773 | 2,764 | 339 | 314 | 0.895 | 0.891 | 0.898 | 0.895 | 0.109 | 0.102 | 0.9654 | 0.9712 | 0.0702 | 0.233 | 0.033 |
| | RF | 2,952 | 2,892 | 211 | 135 | 0.944 | 0.933 | 0.956 | 0.945 | 0.068 | 0.044 | 0.9811 | 0.9814 | 0.0465 | 0.274 | 0.038 |
| | **HGB (frozen)** | 2,949 | 2,911 | 192 | 138 | **0.947** | **0.939** | 0.955 | **0.947** | **0.062** | 0.045 | **0.9928** | **0.9935** | **0.0362** | **0.113** | **0.026** |

**Group-weighted** (each V4-eval D54 group weighs 1; the disjoint view has 4,064 groups):

| Model | FPR | Recall | ROC-AUC | Brier |
|---|---:|---:|---:|---:|
| LR | 0.153 | 0.914 | 0.958 | 0.078 |
| RF | 0.040 | 0.969 | 0.993 | 0.028 |
| **HGB** | **0.030** | 0.967 | **0.994** | **0.026** |

Full view: HGB FPR 0.026, ROC-AUC 0.995.

**Where the row-level FPR comes from.** 93 of HGB's 144 disjoint FPs (65%) are one CSIC GET
request shape: 96 rows, of which 93 are labelled benign and 3 SQL injection. In the full view
it is 139 of 192, from 159 rows (139 benign + 20 SQLi). It is the CSIC benign-vs-SQLi
label-conflict pattern that the `mixed` stratum keeps out of VALIDATION (§3); HGB scores it
≈ 0.77 (reliability bin 0.73–0.80: mean P 0.77, observed attack rate 0.20). Excluding that
one group, the disjoint FPR is ≈ 0.022. The group-weighted FPR moves from 0.024 (VALIDATION) to
0.030 (test), so the correction made VALIDATION representative. In run-001 the frozen model
went from 0.034 to 0.100 with errors spread over many groups (§10). Errors are concentrated as
follows: FN top-2 groups 36% (disjoint); RF's top FP group is the same request shape.

**Reliability, disjoint, HGB native.**
- 1,883 rows score below 0.067: mean P 0.015, observed attack rate 0.008.
- 2,722 rows score at or above 0.933: mean P 0.996, observed 0.9985.
- Mid bins are sparse and noisy, apart from the conflict cluster at 0.73–0.80.
- ECE is 0.024; there are no exact 0/1 outputs.

**Recall per V4 reason (HGB, disjoint):**

| V4 reason | Support | Recall |
|---|---:|---:|
| SQL Injection | 765 | 0.928 |
| XSS | 707 | 0.983 |
| Directory Traversal | 506 | 0.996 |
| File Inclusion | 494 | 0.949 |
| Command Injection | 134 | 0.873 |
| CRLF | 112 | 0.982 |
| SSTI | 88 | 0.989 |
| SSRF | 63 | 0.984 |
| Open Redirect | 50 | 0.980 |

Reasons with fewer than 30 rows are INSUFFICIENT DATA:

| V4 reason | Support | Recall |
|---|---:|---:|
| XXE | 27 | 0.852 |
| GraphQL | 22 | 0.955 |
| LDAP | 21 | 0.952 |
| NoSQL | 17 | 1.000 |
| XPath | 11 | 1.000 |
| CSRF | 8 | 1.000 |
| Insecure Deserialization | 5 | 1.000 |
| HPP | 3 | 0.333 |
| Request Smuggling | 0 | absent |

All families and both views are in the JSON.

**`unsupported_jwt`** (16 rows, never fitted): scored attack-like by HGB 1 / 16 (mean P 0.083),
RF 0 / 16, LR 0 / 16. The blind spot persists by design (D48).

**Memorization diagnostic.** On the 734 full-view rows whose vector is in the development set:
lookup accuracy 0.914, HGB 0.916, RF 0.913, LR 0.841. Run-001's HGB scored 0.574 there. The
static-GET failure is gone.

### 9.2 Category — INTERNAL TEST (second look)

macro-F1, by view:

| View | Majority | LR | RF | **HGB** |
|---|---:|---:|---:|---:|
| disjoint | 0.062 | 0.486 | 0.637 | **0.664** |
| full | 0.061 | 0.487 | 0.639 | **0.667** |

HGB micro-F1 on the disjoint view is 0.830.

HGB per class, disjoint:

| Class | P | R | F1 | Support |
|---|---:|---:|---:|---:|
| `sql_injection` | 0.849 | 0.837 | 0.843 | 765 |
| `xss` | 0.795 | 0.857 | 0.825 | 707 |
| `path_file_access` | 0.925 | 0.948 | 0.936 | 1,000 |
| `command_injection` | 0.598 | 0.590 | 0.594 | 134 |
| `ssti` | 0.578 | 0.545 | 0.561 | 88 |
| `open_redirect` | 0.609 | 0.560 | 0.583 | 50 |
| **`ssrf`** | 0.440 | 0.175 | **0.250** | 63 |
| `other_attack` | 0.757 | 0.690 | 0.722 | 226 |

HGB confusion matrix, disjoint (rows true, columns predicted; order sqli, xss, path, cmdi,
ssti, redirect, ssrf, other):

```
sql_injection      640  59  18  18  11   5   0  14
xss                 41 606  15  12  11   0   3  19
path_file_access     6  19 948   6   4   5   9   3
command_injection   12  19  10  79   3   1   1   9
ssti                13  17   5   3  48   0   0   2
open_redirect        6   2  10   2   0  28   1   1
ssrf                14  11  13   7   0   5  11   2
other_attack        22  29   6   5   6   2   0 156
```

`AnalyzerOutput` was built for every INTERNAL TEST row by every family and by the frozen
composite: **0 contract violations**. The composite's outputs equal its parts.

## 10. run-001 vs run-002

| | run-001 (frozen, not adopted) | run-002 (frozen, adopted) |
|---|---|---|
| Development set | v1, D51 groups (13.0% generator siblings in VALIDATION) | v2, D54 groups (0 siblings) |
| Attack winner | RF 300 / leaf 1 + **isotonic** | **HGB** 100 / 31, **native** |
| Category winner | HGB 300 balanced | HGB 300 balanced (retrained on v2 TRAIN) |
| Attack VALIDATION (calibrated OOF), row-weighted: ROC-AUC / Brier / FPR | 0.9946 / 0.0189 / 0.020 | 0.9961 / 0.0192 / 0.013 |
| Attack VALIDATION, group-weighted: ROC-AUC / FPR | 0.9936 / 0.034 | 0.9928 / 0.024 |
| Attack test disjoint, row-weighted: ROC-AUC / PR-AUC / Brier / log loss / FPR / recall | 0.9753 / 0.9673 / 0.0429 / **0.547** / 0.075 / 0.964 | **0.9936 / 0.9953 / 0.0335 / 0.106 / 0.059** / 0.959 |
| Attack test disjoint, group-weighted: ROC-AUC / FPR / Brier | 0.969 / 0.100 / 0.050 | **0.994 / 0.030 / 0.026** |
| VALIDATION → test, group-weighted FPR | 0.034 → 0.100 (did not transfer) | 0.024 → 0.031 (transferred) |
| Category test disjoint macro-F1 | 0.689 | 0.664 |
| Path ablation Δ (test disjoint, HGB category) | −0.079 | −0.063 |
| JWT detected | 0 / 16 | 1 / 16 |
| Analyzer call P50 / P95 · size · RSS | 17.08 / 17.85 ms · 48.8 MB · +93 MiB | **8.92 / 9.22 ms · 8.9 MB · +15 MiB** |

Run-002's test numbers are a second look and are not fully independent of run-001. The decision
not to adopt run-001 was taken before the second look, and every run-002 choice comes from
VALIDATION v2 and pre-declared rules. Category macro-F1 is 0.025 lower in run-002. With the
corrected grouping VALIDATION also reads lower (0.683 vs 0.731), consistent with v1 having been
optimistic.

## 11. Frozen Analyzer, risks, criteria

**`hybrid-analyzer-v2/attack=hist_gb,category=hist_gb` — FROZEN.** Artifact
`model-output-hybrid-analyzer-v2/recommended.pkl` (gitignored; 8,866,799 bytes; `79eb7265…`).
- **Attack:** HistGradientBoosting, 100 iterations, 31 leaves, native probabilities.
- **Category:** HistGradientBoosting, 300 iterations, balanced class weights.
- **Preprocessing:** raw numerics, booleans 0/1, one-hot categoricals with an `__other__`
  bucket, fit on v2 TRAIN.
- **Input:** the 34 RequestFeatures v2 fields only.

| Freeze criterion | Evidence |
|---|---|
| Grouping backed by real provenance and reproducible | byte-identical regeneration; independent re-rendering audit; unit tests |
| TRAIN ↔ VALIDATION leakage 0 under all three relations | builder assertion + `test_no_overlap_under_each_relation` |
| Preprocessing frozen, fit on TRAIN only | `preprocessing.json`, `frozen_selection.json`; unit tests |
| Selection on VALIDATION only | `select` / `bench` load TRAIN + VALIDATION rows only (asserted); mechanical rule |
| Model and calibration frozen before the test | freeze 06:10:33 UTC < test; hashes verified by `test` |
| Second look after the freeze, once | `test` refuses to run twice; `code_changed_since_freeze: []` |
| No new serious methodological defect | VALIDATION → test agree at group level; the residual row-level gap is one label-conflict CSIC cluster, a data property documented before training (§3) |
| Reproducible artifacts | two `select` runs gave byte-identical models; dataset byte-identical across seeds |
| Tests pass | 333 (ML), 117 (data plane), 91 (Analyzer env) — see the main README |
| External v1 not used | not read by any script of this run |

**Remaining risks**
- **Shortcuts.** Attack leans on percent-encoding and symbol counts; the category leans on
  `path_length` (endpoint artifact, ablation −0.06). Real traffic encodes differently.
  External v1 (D53) is the next measure.
- **Label-conflict clusters.** CSIC request shapes labelled both benign and SQLi produce
  confident mid-range FPs (≈ 0.77). The row-level FPR is cluster-sensitive (0.059 vs 0.022
  without one group).
- **FPR vs V4.** Disjoint FPR is 0.059 against V4's 0.0006 on the same split (V4 is a
  reference only, D24). The Analyzer is an input to the Decision Model, not a replacement for
  V4.
- **Weak categories.** `ssrf` F1 0.25, `ssti` 0.56, `open_redirect` 0.58, `command_injection`
  0.59; `other_attack` is a residual bucket; 8 V4 reasons have fewer than 30 test rows.
- **Category over-confidence.** Mean top-1 P is 0.93 against an accuracy of 0.83, and the
  category is uncalibrated. Use it as context only.
- **JWT.** Blind (1 / 16), by design (D48).
- **Second look.** INTERNAL TEST has now been read twice. Further claims need External v1
  (aggregate, D53) or new data.
- **Runtime.** These are scikit-learn numbers. The category model dominates the latency
  (8.4 of 8.9 ms); an export or runtime choice (D52) may change this.

## 12. Reproduce · files and hashes

```bash
python3.12 scripts/dataset/build_hybrid_analyzer_v2.py                    # or --check
.venv-analyzer/bin/python scripts/training/run_hybrid_analyzer_baselines.py --run run-002 select
.venv-analyzer/bin/python scripts/training/run_hybrid_analyzer_baselines.py --run run-002 bench
.venv-analyzer/bin/python scripts/training/run_hybrid_analyzer_baselines.py --run run-002 freeze
.venv-analyzer/bin/python scripts/training/run_hybrid_analyzer_baselines.py --run run-002 bench --models recommended --out latency_recommended.json
.venv-analyzer/bin/python scripts/training/run_hybrid_analyzer_baselines.py --run run-002 test   # done once; refuses now
```

| File | Content |
|---|---|
| `experiment_config.json` | run, dataset and grouping, feature order, preprocessing, grids, every rule (incl. winner rule and calibration guard), seeds, environment |
| `preprocessing.json` | fitted encoders per family (attack, category, path ablation) |
| `validation_results.json` | every configuration's VALIDATION metrics, calibration CV with bootstrap steps and reliability bins, group-weighted and error-concentration diagnostics, category per class and confusion matrices, both ablations, importance, all-pairs paired bootstraps, model hashes |
| `latency_results.json`, `latency_recommended.json` | load, memory, per-stage latency distributions, throughput, contract checks |
| `frozen_selection.json` | the v2 freeze (§9) |
| `internal_test_results.json` | the second look: both views, `unsupported_jwt`, code hashes at test, environment, run-001 hash |
| `logs/` | `select.log` and `select_repeat.log` (the two identical-model `select` runs; `validation_results.json` is from the repeat, identical except wall-clock fields), `bench.log`, `bench_recommended.log`, `test.log` |
| `SHA256SUMS` | hashes of the files above |

Models (gitignored, `model-output-hybrid-analyzer-v2/`):

| File | Bytes | SHA-256 |
|---|---:|---|
| `recommended.pkl` (frozen) | 8,866,799 | `79eb7265a7a3abd9f5a499234732042a9100729b4434971a02d73e03f6a2ff9b` |
| `hist_gb.pkl` | 8,850,902 | `bf0233ce4288d6d88db45b1b4e79738573d34a9362dc5b46c259c74f5a839371` |
| `random_forest.pkl` | 93,597,029 | `58584e71d6b25deca86e336d393843ed442b18f4f1a0e5252eb47a07d9777fd0` |
| `logreg.pkl` | 7,156 | `07d22a62ea2e72741dc4fdd798ac74cdc53c9bac33927a0f39892cd0f3ed60e6` |
| `hist_gb_category_path_ablation.pkl` | 2,840,435 | `08255ead88babf835c2daa00175506b90c35a83d447139677ecdf6e37b6c22c7` |
| `random_forest_category_path_ablation.pkl` | 172,669,172 | `347b4ad7acb7856680ec77403081510199d91b3ccbeebb60d431d741110c6759` |
| `logreg_category_path_ablation.pkl` | 5,341 | `d26335d21d7a16e0b3c59560bd84541034d40a086cc3c23537d16e0803291601` |
