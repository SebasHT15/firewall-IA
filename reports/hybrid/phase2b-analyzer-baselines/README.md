# Hybrid Architecture Phase 2B — Analyzer dataset, baselines and evaluation

**Kind: experiment record (research environment).** Issue #53 · design frozen in Phase 2A
(D46–D53, [`../phase2a-analyzer-design/`](../phase2a-analyzer-design/)) · 2026-10-03.

**Status: executed, NOT frozen.** Model selection ran on VALIDATION only, the selection
was frozen, and INTERNAL TEST was evaluated **once** (run-001). After that run, a
reproducible methodological error was found in the frozen D51 VALIDATION carve-out
(§10): 11.2% of VALIDATION rows have a generator-group sibling in TRAIN, against 0% for
V4 eval vs V4 train. VALIDATION was therefore optimistic, and the selection and
calibration that produced the frozen models are compromised. Run-001 stands as recorded
and is not repeated here. The fix and any second INTERNAL TEST look are decisions for the
owner (§13). External Test v1 was **not read** (D53). Nothing was integrated into the
gateway; V4, V4-clean and RequestFeatures are unchanged.

| § | Content |
|---|---|
| 1 | Reproduce |
| 2 | `hybrid_analyzer_v1` |
| 3 | Environment |
| 4 | Preprocessing |
| 5 | Configurations tried and selection rules |
| 6 | VALIDATION results (attack, calibration, category, ablation, interpretability) |
| 7 | Latency and footprint |
| 8 | Freeze |
| 9 | INTERNAL TEST run-001 |
| 10 | Post-test finding: VALIDATION siblings |
| 11 | Answers to the six Phase 2B questions |
| 12 | Risks and limitations |
| 13 | Decisions awaiting owner approval |
| 14 | Next steps |
| 15 | Files and hashes |

Every number below comes from the JSON files in this folder (§15). "OOF" = out-of-fold
inside VALIDATION. Rates use the 0.5 **reporting** threshold (a convention to fill
confusion matrices, not an operating point; no threshold was tuned). Percentiles are
nearest-rank.

---

## 1. Reproduce

```bash
# dataset (standard library; V4-clean must be present locally)
python3.12 scripts/dataset/build_hybrid_analyzer_v1.py            # or --check to verify
# research environment (D52: never the data plane)
uv venv --python 3.12 --seed .venv-analyzer
.venv-analyzer/bin/python -m pip install -r requirements-analyzer-research.txt
# stages (each refuses to run out of order; `test` refuses to run twice)
.venv-analyzer/bin/python scripts/training/run_hybrid_analyzer_baselines.py select
.venv-analyzer/bin/python scripts/training/run_hybrid_analyzer_baselines.py bench
.venv-analyzer/bin/python scripts/training/run_hybrid_analyzer_baselines.py freeze --attack random_forest --category hist_gb --rationale "…"
.venv-analyzer/bin/python scripts/training/run_hybrid_analyzer_baselines.py bench --models recommended --out latency_recommended.json
.venv-analyzer/bin/python scripts/training/run_hybrid_analyzer_baselines.py test
# post-test diagnostic (standard library)
python3.12 scripts/dataset/diagnose_hybrid_analyzer_v1_siblings.py --out …/validation_sibling_diagnostic.json
```

Reproducibility checks performed: the dataset is byte-identical across runs, interpreters
(`python3.12`, `.venv-analyzer`) and `PYTHONHASHSEED` values; two consecutive `select`
runs produced byte-identical model pickles and `validation_results.json` identical except
the wall-clock `fit_seconds` / `created_utc` fields; the sibling diagnostic is
byte-identical across hash seeds.

## 2. `hybrid_analyzer_v1`

Built by [`scripts/dataset/build_hybrid_analyzer_v1.py`](../../../scripts/dataset/build_hybrid_analyzer_v1.py)
exactly as D51 specifies; the reason → category mapping, VALIDATION bucket and parser are
imported from the Phase 2A analysis script so they cannot drift. The builder **asserts every
Phase 2A count** and refuses to overwrite its output. Manifest:
[`datasets/manifest_hybrid_analyzer_v1.json`](../../../datasets/manifest_hybrid_analyzer_v1.json);
the JSONL is regenerated locally like V4 (D6) and gitignored.

| Role / view | Rows | Fitted (JWT out) | ALLOW / BLOCK |
|---|---:|---:|---|
| TRAIN | 20,141 | 20,059 | 10,028 / 10,031 |
| VALIDATION | 4,993 | 4,980 | 2,539 / 2,441 |
| INTERNAL TEST — `internal_test_full` | 6,190 | — | 3,103 / 3,087 |
| INTERNAL TEST — `internal_test_feature_disjoint` | 5,456 | — | 2,423 / 3,033 (55.6% BLOCK, D42) |
| `unsupported_jwt` (V4 eval) | 16 | never fitted | — (TRAIN 82 / VALIDATION 13 also flagged) |

- Groups 18,720 (largest 417 rows). TRAIN ↔ VALIDATION overlap: **0** feature vectors, **0**
  canonical requests, 0 group ids (asserted and unit-tested).
- Flags on INTERNAL TEST (vs TRAIN ∪ VALIDATION, JWT out): `meta_feature_vector_in_train` 734,
  `meta_canonical_request_in_train` 127. No row is removed.
- Category targets (TRAIN / VALIDATION / full / disjoint): `sql_injection` 2,566 / 617 / 817 / 765 ·
  `xss` 2,360 / 560 / 708 / 707 · `path_file_access` 3,285 / 821 / 1,000 / 1,000 ·
  `command_injection` 491 / 116 / 134 / 134 · `ssti` 315 / 78 / 88 / 88 · `open_redirect` 162 / 46 /
  51 / 50 · `ssrf` 144 / 42 / 63 / 63 · `other_attack` 708 / 161 / 226 / 226.
- Per row: `row_id` (SHA-256 of the V4 `input`; the text is not copied), `role`, `slice`,
  `features` (34 RequestFeatures v2 values — **the only model input**), `target_attack`,
  `target_category`, and `meta_*` offline metadata (V4 split / line / reason / category,
  inferred source and shape, group id, canonical-request and feature-vector hashes, the two
  test flags).
- Artifact: 31,340 rows, 49,453,235 bytes, SHA-256
  `b370186b8d3c461e4efa462bf36c29e2e9b018df9b077f23660aa7025754cd87`; source V4-clean train
  `4459f686…262b`, eval `61f15591…0859` (generator `1bf412f`).

## 3. Environment

`.venv-analyzer` (D52; separate from the ML and data-plane environments; D33 intact):
Python 3.12.15, numpy 2.5.3, scikit-learn 1.9.1, scipy 1.18.1, joblib 1.6.0,
threadpoolctl 3.7.0 (+ narwhals 2.26.0, cloudpickle 3.1.2 pulled by scikit-learn) —
[`requirements-analyzer-research.txt`](../../../requirements-analyzer-research.txt). CPU: 13th Gen
Intel Core i9-13900HX, 32 logical CPUs (full record in `experiment_config.json`). pandas was not needed.

## 4. Preprocessing

[`scripts/training/hybrid_analyzer.py`](../../../scripts/training/hybrid_analyzer.py) `FeatureEncoder`;
fitted on TRAIN rows only (attack: all fitted TRAIN rows; category: TRAIN BLOCK rows); persisted
per model in [`preprocessing.json`](preprocessing.json) and inside each pickle. Columns follow
RequestFeatures field order.

| Family | int counts (25) | float ratios (4) | booleans (2) | `method`, `content_type` | `body_format` |
|---|---|---|---|---|---|
| Logistic regression | `log1p`, then standardized (TRAIN mean / std) | standardized | 0/1, not scaled | one-hot over TRAIN values + `__other__` | one-hot over the closed enum (unknown → error) |
| Random forest, HistGradientBoosting | raw | raw | 0/1 | same one-hot | same one-hot |

`log1p` was checked, not assumed: LR with C = 1 and no `log1p` scored VALIDATION ROC-AUC 0.9667
vs 0.9673 with it (attack) and macro-F1 0.410 vs 0.415 (category); `log1p` was kept. No
feature was added or removed (the ablation removes fields only in its own models).

## 5. Configurations tried and selection rules

Every configuration fitted (complete list; also in `experiment_config.json`). Fixed:
LR lbfgs / L2 / `max_iter` 5000; RF `max_features='sqrt'`; HGB `learning_rate` 0.1,
**`early_stopping=False`** (the default would carve a random, row-level split from TRAIN);
seed 0. VALIDATION score of each:

| Task | Family | Configurations (VALIDATION score) | Selected |
|---|---|---|---|
| attack (ROC-AUC) | LR | C 0.01 → 0.9625 · 0.1 → 0.9660 · **1 → 0.9673** · 10 → 0.9671 · C 1 no-log1p → 0.9667 | C = 1, log1p |
| | RF | (trees, min leaf) 100/1 → 0.99535 · **300/1 → 0.99558** · 100/5 → 0.99496 · 300/5 → 0.99520 | 300 / 1 |
| | HGB | (iter, leaves) 100/15 → 0.9843 · 100/31 → 0.9861 · 300/15 → 0.9849 · **300/31 → 0.9888** | 300 / 31 |
| category (macro-F1) | LR | C ∈ {0.1, 1, 10} × class_weight ∈ {none, balanced} → 0.391 / 0.415 / 0.444 / 0.431 / 0.449 / **0.463** · C 1 no-log1p → 0.410 | C = 10, balanced |
| | RF | (trees, class_weight) 100/none 0.669 · 300/none 0.656 · 100/balanced_subsample 0.684 · **300/balanced_subsample 0.691** | 300, balanced_subsample |
| | HGB | (iter, class_weight) 100/none 0.716 · 300/none 0.719 · 100/balanced 0.722 · **300/balanced 0.731** | 300, balanced |

Rules (pre-declared in `experiment_config.json`): attack — highest VALIDATION ROC-AUC, tie →
lower Brier; category — highest macro-F1, tie → lower log loss; calibration — see §6.2. The
cross-family winner is a judgement over the issue's ten criteria, recorded by `freeze` before
INTERNAL TEST (§8).

**Floor baselines (VALIDATION).** Attack prior (P = TRAIN prevalence 0.50007; majority BLOCK at
0.5): accuracy 0.490, ROC-AUC 0.500, Brier 0.250. Category majority (`path_file_access`, the most
frequent TRAIN class): macro-F1 0.063, micro-F1 0.336. Feature-vector lookup (memorization
diagnostic, never a candidate): covers 0 VALIDATION rows by construction.

**MLP: not trained** (issue item 11). Decided on VALIDATION after the first `select` run: the tree
families reach group-weighted attack ROC-AUC ≈ 0.995, the remaining attack errors concentrate
in a few groups, and the category ceiling is label / endpoint-bound (§6.4), not capacity-bound.

**Amendments made after a VALIDATION result and before INTERNAL TEST** (recorded in
`experiment_config.json`; `logs/select_run1.log` keeps the first run):

1. *Diagnostics added:* group-weighted attack metrics (each group weighs 1) and error
   concentration. Reason: 281 of HGB's 325 VALIDATION false positives were two CSIC benign
   groups. Not selection criteria.
2. *Calibration rule:* "lowest OOF Brier" → "move to a more complex calibrator only if a paired
   group-bootstrap 95% interval of the OOF Brier difference is entirely below 0". The first
   rule picked isotonic for RF on a 0.0003 Brier margin, which does not meet the issue's
   requirement that a technique without statistical support is not used.
3. *Determinism fix:* VALIDATION predictions are now made single-threaded. A parallel forest
   sums tree votes in thread order, which changed the last bits of the probabilities and,
   through them, the isotonic calibrator's pickle (trees and metrics were unaffected).

## 6. VALIDATION results

### 6.1 Attack — selected configuration per family

Native probabilities, 4,980 rows (2,441 BLOCK):

| | TP | TN | FP | FN | Acc | Prec | Recall | F1 | FPR | FNR | ROC-AUC | PR-AUC | Brier | ECE |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| prior | 2,441 | 0 | 2,539 | 0 | 0.490 | 0.490 | 1.000 | 0.658 | 1.000 | 0.000 | 0.500 | — | 0.250 | — |
| LR | 2,223 | 2,234 | 305 | 218 | 0.895 | 0.879 | 0.911 | 0.895 | 0.120 | 0.089 | 0.9673 | 0.9693 | 0.0705 | 0.029 |
| RF | 2,364 | 2,494 | 45 | 77 | 0.976 | 0.981 | 0.968 | 0.975 | 0.018 | 0.032 | **0.9956** | **0.9963** | **0.0197** | 0.018 |
| HGB | 2,372 | 2,214 | 325 | 69 | 0.921 | 0.879 | 0.972 | 0.923 | 0.128 | 0.028 | 0.9888 | 0.9900 | 0.0684 | 0.060 |

**Group-weighted diagnostic** (3,723 groups, each weighs 1), native: LR ROC-AUC 0.9556 / Brier
0.0801 / FPR 0.171 · RF 0.9946 / 0.0249 / 0.030 · **HGB 0.9951 / 0.0228 / 0.032**. HGB's
row-level gap is almost entirely two CSIC benign groups (86% of its FPs in its top two groups):
153 copies of `GET /miembros/imagenes/ogono.jpg` — no query, no encoding — scored **0.967** by HGB,
0.017 by RF, 0.007 by LR, and a 128-row group. Seed stability (seeds 0 / 1 / 2): RF ROC-AUC
0.9956 / 0.9958 / 0.9961; HGB identical (no stochastic component with these settings); LR
deterministic.

### 6.2 Calibration of `attack`

5 group folds inside VALIDATION (`sha256('hybrid-analyzer-v1-calibration-cv' NUL group)[:8] % 5`);
OOF Brier / log loss / ECE; "0/1" = OOF probabilities exactly 0 or 1 (errors among them):

| | native | sigmoid | isotonic | rule outcome (group-bootstrap 95% CI of ΔBrier) |
|---|---|---|---|---|
| LR | 0.0705 / 0.233 / 0.029 · 0/1: 1 (0) | 0.0706 / 0.234 / 0.031 · 1 (0) | 0.0677 / 0.236 / 0.020 · 982 (2) | sigmoid vs native [−0.00008, +0.00026] no · isotonic vs native [−0.0046, −0.0011] **isotonic** |
| RF | 0.0197 / 0.088 / 0.018 · 2,380 (2) | 0.0192 / 0.076 / 0.007 · 0 (0) | 0.0189 / 0.089 / 0.007 · 2,190 (3) | sigmoid vs native [−0.0015, +0.0006] no · isotonic vs native [−0.00145, −0.00003] **isotonic** |
| HGB | 0.0684 / 0.237 / 0.060 · 0 | 0.0728 / 0.234 / 0.070 · 0 | 0.0695 / 0.218 / 0.067 · 2,814 (2) | both intervals include 0 → **native** |

Calibrated OOF (what the frozen models output, measured honestly inside VALIDATION): LR
ROC-AUC 0.9661 / Brier 0.0677 / ECE 0.020; **RF 0.9946 / 0.0189 / 0.007**; HGB unchanged
(native). RF's isotonic interval only just excludes 0, and isotonic outputs exactly 0 or 1 for
44% of rows; this risk materialized on INTERNAL TEST (§9.1). Reliability bins:
`validation_results.json` → `attack.<family>.calibration_cv.<method>.oof_reliability`.

### 6.3 Category (BLOCK rows, 2,441)

| | macro-F1 | micro-F1 | log loss | mean top-1 P | top-1 ECE |
|---|---:|---:|---:|---:|---:|
| majority | 0.063 | 0.336 | — | — | — |
| LR | 0.463 | 0.630 | 1.184 | 0.597 | 0.063 |
| RF | 0.691 | 0.825 | 0.609 | 0.751 | 0.077 |
| **HGB** | **0.731** | **0.850** | 0.607 | 0.931 | 0.080 |

HGB per class (P / R / F1, support): `sql_injection` 0.891 / 0.835 / 0.862 (617) · `xss` 0.814 /
0.889 / 0.850 (560) · `path_file_access` 0.912 / 0.944 / 0.928 (821) · `command_injection` 0.583 /
0.543 / 0.563 (116) · `ssti` 0.747 / 0.718 / 0.732 (78) · `open_redirect` 0.684 / 0.565 / 0.619 (46) ·
`ssrf` 0.545 / 0.429 / 0.480 (42) · `other_attack` 0.850 / 0.776 / 0.812 (161). Confusion matrices for
every family are in `validation_results.json`. Paired group bootstrap vs LR: RF +0.227
[0.192, 0.262], HGB +0.268 [0.235, 0.300]. HGB is over-confident (mean top-1 0.931 vs micro
accuracy 0.850); no category calibration was applied (the contract only needs a distribution;
§13).

### 6.4 Mandatory ablation (D46) — without `path_length`, `path_depth`

Same grid, same selection rule, same data:

| Family | macro-F1 full | ablation | Δ | largest per-class F1 drops |
|---|---:|---:|---:|---|
| LR | 0.463 | 0.468 | +0.005 | `ssti` −0.035, `command_injection` −0.025 (others rise) |
| RF | 0.691 | 0.623 | **−0.067** | `ssrf` −0.175, `ssti` −0.161, `open_redirect` −0.098, `command_injection` −0.082 |
| HGB | 0.731 | 0.661 | **−0.070** | `ssti` −0.156, `command_injection` −0.139, `other_attack` −0.076, `open_redirect` −0.063 |

Diagnostic variant also dropping `slash_count` (which counts the path's slashes; VALIDATION
only): RF −0.064, HGB −0.087, LR −0.004. The large classes move little (`sql_injection`, `xss`,
`path_file_access` within −0.036…+0.008); the small classes carry the drop. Permutation importance
agrees: `path_length` is the **second** most important field of both tree category models.
*Interpretation (explicit, no significance threshold invented):* about 0.07 macro-F1 — roughly a
quarter of the tree models' gain over LR — depends on two path-structure fields that proxy the
synthetic endpoint, and it is concentrated in the scarce classes. The category therefore stays
**low-confidence context** for the Decision Model, as D46 anticipates.

### 6.5 Interpretability

Field-level permutation importance on VALIDATION (all columns of one RequestFeatures field
permuted together, 5 repeats; ranked by log-loss increase) — `validation_results.json` →
`interpretability`:

| Model | Top fields |
|---|---|
| attack RF (winner) | `symbol_count`, `percent_encoded_ratio`, `body_length`, `percent_count`, `percent_encoded_count`, `query_length`, `entropy_bits_per_char`, `alnum_ratio`, `total_param_count`, `has_percent_encoding` |
| attack HGB | `percent_encoded_ratio` (dominant, ROC-AUC −0.061), `percent_count`, `symbol_count`, `alnum_ratio`, `percent_encoded_count`, `entropy_bits_per_char`, `query_length` |
| attack LR | `query_length`, `body_length`, `percent_count`, `ampersand_count`, `total_param_count` (coefficients: `query_length` +5.85, `body_length` +3.79, `symbol_count` −2.68, `percent_count` +2.37) |
| category HGB (winner) | `entropy_bits_per_char`, **`path_length`**, `percent_encoded_ratio`, `alnum_ratio`, `longest_char_run`, `symbol_count`, `query_length` |
| category RF | `entropy_bits_per_char`, **`path_length`**, `percent_encoded_ratio`, `symbol_count`, `alnum_ratio` |

Shortcut reading: **percent-encoding** is the main attack signal — the generator percent-encodes
query and form payloads (Phase 2A §4), so the attack model partly learns "is encoded" rather than
attack syntax; raw syntax counts matter little. **Lengths** (`query_length`, `body_length`) are the
LR's strongest signal: attack rows are longer. **`path_length`** is a category shortcut (§6.4).
`content_type` / `body_format` / `method` rank low for every attack model (the E2 envelope
neutralization holds). No feature was removed.

## 7. Latency and footprint

One request per call, single thread (`OMP/OPENBLAS/MKL_NUM_THREADS=1`), fresh process per model,
scikit-learn `predict_proba` as is (no export or optimization, D52); 4,980 VALIDATION requests × 2
passes after 500 warm-up calls (n = 9,960). Milliseconds.

| | LR | RF | HGB | **recommended** (RF attack + HGB category) |
|---|---:|---:|---:|---:|
| artifact (bytes) | 8,515 | 203,065,623 | 9,556,862 | 48,779,141 |
| `pickle.load` (s) | 0.001 | 0.132 | 0.043 | 0.059 |
| RSS increase after load (MiB) | 0.2 | 390.1 | 16.4 | 93.0 |
| first call | 1.74 | 17.13 | 10.31 | 17.55 |
| preprocessing P50 / P95 | 0.027 / 0.029 | 0.016 / 0.021 | 0.018 / 0.022 | 0.022 / 0.027 |
| attack inference P50 / P95 / P99 / max | 0.405 / 0.436 / 0.461 / 0.613 | 7.93 / 8.60 / 8.97 / 16.72 | 1.20 / 1.29 / 1.34 / 2.63 | 8.41 / 8.87 / 9.30 / 17.87 |
| category inference P50 / P95 / P99 / max | 0.070 / 0.076 / 0.087 / 0.127 | 7.49 / 8.04 / 8.38 / 13.30 | 8.34 / 8.74 / 8.97 / 21.12 | 8.59 / 9.09 / 9.56 / 24.80 |
| **Analyzer call** P50 / P95 / P99 / max | **0.50 / 0.53 / 0.56 / 0.73** | 15.41 / 16.62 / 17.26 / 30.64 | 9.57 / 10.04 / 10.32 / 23.56 | **17.08 / 17.85 / 18.67 / 32.77** |
| extraction + Analyzer P50 / P95 | 0.55 / 0.59 | 15.50 / 16.74 | 9.65 / 10.14 | 17.17 / 17.92 |
| throughput (req/s, one thread) | 2,005 | 62.5 | 104.2 | 62.2 |
| contract violations | 0 | 0 | 0 | 0 |

Import of numpy + scikit-learn ≈ 0.46 s and ≈ 118 MiB RSS before any model. LR's attack call is
dominated by scikit-learn's calibration wrapper (0.41 ms vs 0.07 ms for its uncalibrated
category model). Tree costs scale with tree count: RF 300 trees per task; HGB category 300
iterations × 8 classes. RF's 203 MB is mostly its 8-class category forest, which the
recommended composite does not use. **No threshold exists for this component and none is set**;
for scale only, the V4 pipeline P95 is 269.58 ms (D36 context).

## 8. Freeze (before INTERNAL TEST)

[`frozen_selection.json`](frozen_selection.json): **attack = random_forest** (300 trees, leaf 1,
isotonic), **category = hist_gb** (300 iterations, balanced). The full rationale is in the file;
in short: RF had the best row-level VALIDATION quality and calibration, was robust on the CSIC
clusters where HGB is confidently wrong, and was group-weighted within 0.0015 ROC-AUC of HGB.
Its cost (~8 ms attack inference, ~93 MiB in the composite) is the main deployment risk,
deferred to D52. LR is ~30× faster but VALIDATION FPR 0.12 vs 0.02, not a marginal
difference. HGB leads the category on 7 of 8 classes (the recorded rationale says "6 of 8"; that
is a counting error in the frozen text: only `ssrf` is better under RF, 0.508 vs 0.480). The freeze composed both into
`recommended.pkl` (version `hybrid-analyzer-v1/attack=random_forest,category=hist_gb`) and
hashed every model and evidence file; `test` verified them.

## 9. INTERNAL TEST run-001 (read once)

Every frozen family was evaluated; the winner was fixed before. Flags: full view 734 rows with a
vector in TRAIN ∪ VALIDATION, 127 with a canonical request there. **The feature-disjoint view is
the reference for generalization.**

### 9.1 Attack

Frozen outputs (calibrated where chosen). Prevalence: full 0.499, disjoint 0.556 (D42).

| View | Model | TP | TN | FP | FN | Acc | Prec | Recall | F1 | FPR | FNR | ROC-AUC | PR-AUC | Brier | log loss | ECE |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| full (6,190) | prior | 3,087 | 0 | 3,103 | 0 | 0.499 | 0.499 | 1.000 | — | 1.000 | 0 | 0.500 | — | 0.250 | — | — |
| | LR | 2,802 | 2,687 | 416 | 285 | 0.887 | 0.871 | 0.908 | 0.889 | 0.134 | 0.092 | 0.9627 | 0.9587 | 0.0742 | 0.249 | 0.014 |
| | **RF** | 2,964 | 2,873 | 230 | 123 | 0.943 | 0.928 | 0.960 | 0.944 | 0.074 | 0.040 | 0.9678 | 0.9491 | 0.0478 | 0.754 | 0.034 |
| | HGB | 2,959 | 2,647 | 456 | 128 | 0.906 | 0.866 | 0.959 | 0.910 | 0.147 | 0.041 | 0.9843 | 0.9872 | 0.0785 | 0.263 | 0.073 |
| **disjoint (5,456)** | prior | 3,033 | 0 | 2,423 | 0 | 0.556 | 0.556 | 1.000 | — | 1.000 | 0 | 0.500 | — | 0.250 | — | — |
| | LR | 2,793 | 2,083 | 340 | 240 | 0.894 | 0.891 | 0.921 | 0.906 | 0.140 | 0.079 | 0.9628 | 0.9662 | 0.0733 | 0.249 | 0.013 |
| | **RF** | 2,924 | 2,241 | 182 | 109 | 0.947 | 0.941 | 0.964 | 0.953 | 0.075 | 0.036 | 0.9753 | 0.9673 | 0.0429 | 0.547 | 0.029 |
| | HGB | 2,919 | 2,266 | 157 | 114 | 0.950 | 0.949 | 0.962 | 0.956 | 0.065 | 0.038 | **0.9922** | **0.9944** | **0.0387** | **0.135** | 0.030 |

- **RF's isotonic calibration hurt on test.** RF native probabilities: ROC-AUC 0.9819 full /
  0.9865 disjoint, Brier 0.0473 / 0.0424, log loss 0.251 / 0.158. Calibrated: 0.9678 / 0.9753,
  0.0478 / 0.0429, **0.754 / 0.547**. Isotonic's flat steps tie many scores (ranking lost), and its
  exact 0/1 outputs turn errors into confident errors. Disjoint reliability, top bin: 2,774 rows,
  mean P 0.998, observed attack rate 0.967 (VALIDATION OOF: 0.998 vs 0.996).
- **VALIDATION → TEST gap.** RF FPR 0.018 (VAL) → 0.075 (disjoint); recall 0.968 → 0.964. LR
  and HGB move less on ranking (HGB disjoint ROC-AUC 0.992 vs VAL 0.989).
- **On the disjoint view HGB is better than the frozen RF on every threshold-free metric**
  (paired bootstrap vs LR, by canonical request: ROC-AUC Δ HGB +0.030 [0.022, 0.038], RF +0.013
  [0.006, 0.020]). In the full view HGB loses only because of a single 252-row CSIC benign group
  (55.7% of its FPs), the same plain-static-GET failure seen on VALIDATION; HGB's accuracy on the
  734 vector-covered rows is 0.574 (RF 0.916, lookup 0.914).
- Group-weighted disjoint (4,645 canonical requests): ROC-AUC LR 0.954 · RF 0.969 · HGB 0.991.

**Recall per original V4 reason** (disjoint view; same on full except SQLi and Open Redirect
supports 817 / 51):

| V4 reason | Analyzer category | support | LR | RF | HGB | D18 status |
|---|---|---:|---:|---:|---:|---|
| SQL Injection | `sql_injection` | 765 | 0.867 | 0.932 | 0.929 | OK |
| XSS Injection | `xss` | 707 | 0.956 | 0.986 | 0.980 | OK |
| Directory Traversal | `path_file_access` | 506 | 0.976 | 0.998 | 0.998 | OK |
| File Inclusion | `path_file_access` | 494 | 0.874 | 0.957 | 0.955 | OK |
| Command Injection | `command_injection` | 134 | 0.851 | 0.851 | 0.881 | OK |
| CRLF Injection | `other_attack` | 112 | 0.982 | 0.991 | 1.000 | OK |
| Server Side Template Injection | `ssti` | 88 | 0.989 | 1.000 | 0.989 | OK |
| Server Side Request Forgery | `ssrf` | 63 | 1.000 | 0.984 | 1.000 | OK |
| Open Redirect | `open_redirect` | 50 | 0.960 | 1.000 | 1.000 | OK |
| XXE Injection | `other_attack` | 27 | 0.926 | 0.963 | 0.963 | INSUFFICIENT DATA |
| GraphQL Injection | `other_attack` | 22 | 0.818 | 0.955 | 0.909 | INSUFFICIENT DATA |
| LDAP Injection | `other_attack` | 21 | 0.905 | 0.952 | 0.905 | INSUFFICIENT DATA |
| NoSQL Injection | `other_attack` | 17 | 1.000 | 1.000 | 1.000 | INSUFFICIENT DATA |
| XPath Injection | `other_attack` | 11 | 1.000 | 1.000 | 1.000 | INSUFFICIENT DATA |
| CSRF | `other_attack` | 8 | 1.000 | 1.000 | 1.000 | INSUFFICIENT DATA |
| Insecure Deserialization | `other_attack` | 5 | 1.000 | 1.000 | 1.000 | INSUFFICIENT DATA |
| HTTP Parameter Pollution | `other_attack` | 3 | 1.000 | 1.000 | 0.667 | INSUFFICIENT DATA |
| Request Smuggling | `other_attack` | 0 | — | — | — | absent from eval |

**`unsupported_jwt`** (16 rows, never fitted): scored attack-like at 0.5 by LR 0 / 16, RF 0 / 16
(mean P 0.055), HGB 1 / 16. The blind spot D48 predicted is confirmed: the Analyzer does not see
JWT attacks.

*Reference only, not comparable:* V4 on the same eval split (6,206 rows, JWT included; the split
also selected V4's checkpoint, D24): recall 0.970, FPR 0.00064. The Analyzer's FPR is two orders
of magnitude higher.

### 9.2 Category (BLOCK rows; full 3,087, disjoint 3,033)

| View | majority | LR | RF | **HGB** |
|---|---:|---:|---:|---:|
| macro-F1 full | 0.061 | 0.477 | 0.650 | **0.691** |
| macro-F1 disjoint | 0.062 | 0.476 | 0.648 | **0.689** |
| micro-F1 disjoint | 0.330 | 0.656 | 0.821 | 0.844 |

HGB per class, disjoint (P / R / F1, support): `sql_injection` 0.866 / 0.844 / 0.855 (765) · `xss`
0.795 / 0.885 / 0.838 (707) · `path_file_access` 0.926 / 0.952 / 0.939 (1,000) · `command_injection`
0.600 / 0.649 / 0.624 (134) · `ssti` 0.653 / 0.557 / 0.601 (88) · `open_redirect` 0.667 / 0.640 / 0.653
(50) · **`ssrf` 0.385 / 0.159 / 0.225 (63)** · `other_attack` 0.882 / 0.695 / 0.777 (226).

HGB confusion matrix, disjoint (rows true, columns predicted; order sqli, xss, path, cmdi, ssti,
redirect, ssrf, other):

```
sql_injection      646  64  21  16  10   2   0   6
xss                 33 626  17  15   7   3   2   4
path_file_access    10  18 952   4   3   3   8   2
command_injection    9  20   8  87   1   1   2   6
ssti                10  19   3   6  49   0   0   1
open_redirect        4   1   6   3   0  32   3   1
ssrf                17  10  15   5   0   5  10   1
other_attack        17  29   6   9   5   2   1 157
```

`ssrf` collapses on test (VALIDATION F1 0.48 → 0.22; most `ssrf` rows go to sqli / path / xss). The
VALIDATION → TEST drop in macro-F1 is ~0.04 for HGB and RF.

**Path ablation on INTERNAL TEST** (frozen ablated models): HGB 0.689 → 0.610 (**Δ −0.079**) disjoint,
RF 0.648 → 0.565 (Δ −0.082), LR +0.002. HGB per-class Δ F1: `ssti` −0.173, `open_redirect` −0.158,
`command_injection` −0.134, `ssrf` −0.094, `other_attack` −0.053, `path_file_access` −0.017, `xss`
−0.011, `sql_injection` +0.006. Without path fields, more rows of every class are predicted as
`command_injection` and `ssti` (confusion-matrix deltas in the JSON). Same reading as §6.4, slightly
larger.

### 9.3 Contract and memorization diagnostic

- `AnalyzerOutput` built for every INTERNAL TEST row by every family and by the recommended
  composite: **0 contract violations**; the composite's outputs equal its two parts exactly.
- Feature-vector lookup (diagnostic, not a candidate) on the 734 covered rows of the full view:
  lookup accuracy 0.914; RF 0.916, LR 0.835, HGB 0.574. On the 5,456 uncovered rows: RF 0.947,
  HGB 0.950, LR 0.894. RF does not gain from memorization here; HGB loses on the 252-row CSIC
  group.

## 10. Post-test finding: VALIDATION siblings (methodological error in D51)

[`validation_sibling_diagnostic.json`](validation_sibling_diagnostic.json), from
[`scripts/dataset/diagnose_hybrid_analyzer_v1_siblings.py`](../../../scripts/dataset/diagnose_hybrid_analyzer_v1_siblings.py)
(aggregate counts, deterministic). The V4 generator assigns its split per **generator group**: a CSIC
request shape with digits collapsed (`csic_group_key`), or one canonical payload rendered as a base
row plus an augmentation variant, possibly on different paths or parameters. D51 groups by
canonical **request** or feature vector, which is finer, so siblings of one generator group can be
split between TRAIN and VALIDATION, but never between V4 train and V4 eval:

| Proxy for the generator group | VALIDATION rows with a sibling in TRAIN | V4 eval rows with a sibling in V4 train |
|---|---:|---:|
| CSIC benign (`csic_group_key`, exact) | 95 / 1,209 (7.9%) | 0 / 1,363 |
| CSIC attack (`csic_group_key`, exact) | 132 / 600 (22.0%) | 0 / 816 |
| synthetic attack (longest canonical parameter value, approximate) | 329 / 1,841 (17.9%) | 0 / 2,271 |
| **total** | **556 / 4,980 (11.2%)** | **0 / 6,190** |

**Consequence.** VALIDATION was easier than INTERNAL TEST in a way that favours models that
memorize near-duplicates (RF with leaf 1) and calibrators that trust them (isotonic), which matches
§9.1: RF's FPR and calibration degraded on test while HGB's ranking held. The Phase 2A grouping
check only tested exact canonical-request and feature-vector overlap, which are indeed 0.

**Status of run-001.** INTERNAL TEST itself is not contaminated (0 siblings across the V4 split),
so run-001 is a valid measurement of the frozen models. What is compromised is the VALIDATION-based
selection and calibration that produced them. **The Analyzer is not frozen.** Fixing the carve-out
changes D51 → `hybrid_analyzer_v2` (manifest rule); any new INTERNAL TEST evaluation after
that would be a **second look** and must be reported as such (§13).

## 11. Answers to the six Phase 2B questions

1. **Security signal in RequestFeatures v2:** substantial for `attack`. Feature-disjoint
   ROC-AUC 0.963 (LR) to 0.992 (HGB) against 0.5 for the prior; recall ≈ 0.96 at FPR ≈ 0.065–0.075
   for the trees. Much of it is percent-encoding and length (§6.5), so it is partly a property of
   how the generator renders payloads.
2. **Best quality / latency / size:** for `attack`, HGB on the evidence that matters most
   (disjoint test: best ROC-AUC, Brier, log loss, FPR; 1.2 ms attack inference, 9.6 MB). Its
   reproducible confident errors on plain static GET requests are disqualifying until
   understood. The frozen RF is second on test (calibrated) and ~7× slower on attack. LR is
   0.5 ms and 8.5 KB but FPR ≈ 0.14.
3. **Generalization of `attack`:** moderate. Disjoint ≈ full, but VALIDATION overstated
   quality (RF FPR 0.018 → 0.075) because of §10.
4. **Usefulness of the category:** limited. HGB macro-F1 0.689 disjoint (majority 0.062).
   Good for `path_file_access` / `sql_injection` / `xss` (F1 0.84–0.94), weak for
   `command_injection` / `ssti` / `open_redirect` (0.60–0.65), unusable for `ssrf` (0.22).
5. **Endpoint dependence:** removing `path_length` and `path_depth` costs the tree models
   0.07–0.08 macro-F1, a quarter (VALIDATION) to a third (test) of their gain over LR,
   concentrated in the small classes (`ssti` −0.17, `open_redirect` −0.16,
   `command_injection` −0.13). The category is low-confidence context (D46).
6. **Calibration for the Decision Model:** feasible but not demonstrated.
   - Calibrators fitted on this VALIDATION do not transfer: RF + isotonic is overconfident on
     test and its exact-0/1 outputs triple log loss.
   - HGB native is reasonably calibrated on the disjoint view (ECE 0.030, Brier 0.039).
   - Calibration must be redone on a sibling-free VALIDATION; exact 0/1 outputs should not
     reach the Decision Model.

## 12. Risks and limitations

- **Leakage:** TRAIN ↔ VALIDATION generator-group siblings (§10) — the main finding. INTERNAL
  TEST is clean by the generator's construction (0 siblings) and by the flags.
- **Shortcuts:** percent-encoding and lengths drive `attack`; `path_length` drives part of the
  category. Real traffic encodes differently from the generator, so External v1 may disagree
  (not measured; D53).
- **Duplicate clusters:** single CSIC requests repeated 128–417 times under different envelopes
  dominate row-level metrics of any model that misjudges them. Group-weighted metrics are reported
  as a diagnostic.
- **HGB failure mode:** confident attack scores (≈ 0.97) on plain static GET requests (153- and
  252-row clusters). Its cause was not investigated in the trees.
- **Weak categories:** `ssrf` (test F1 0.22), `ssti`, `open_redirect`, `command_injection`;
  `other_attack` is a residual bucket. 11 V4 reasons have < 30 test rows (INSUFFICIENT DATA).
- **Calibration:** isotonic produced exact 0 / 1 probabilities and lost ranking on test; the
  category models are over-confident (HGB mean top-1 0.93 vs accuracy 0.84) and uncalibrated.
- **JWT:** 0–1 of 16 detected — a known blind spot (D48).
- **Cost:** RF / HGB per-request cost under scikit-learn is 10–17 ms and up to 390 MiB RSS.
  Untested whether an export (D52) changes that.
- **FPR vs V4:** 0.065–0.075 against V4's 0.0006 on the same split. The Analyzer is not a
  replacement for V4, which matches its role as an input to the Decision Model.

## 13. Decisions awaiting owner approval (nothing below is in DECISIONS.md yet)

1. **Accept the D51 error and its fix.** Add the generator group to the grouping — connected
   components over "same canonical request OR same feature vector OR same `csic_group_key`
   (CSIC) OR same canonical payload (attacks)" — as `hybrid_analyzer_v2`. Verify with the
   §10 diagnostic (target: 0 siblings). The canonical payload is not stored, so it would be
   recovered from the generator (re-running `parse_dataset_v4` with its in-memory `_gid`) or
   approximated as in §10. The choice is yours.
2. **Status of INTERNAL TEST run-001** (proposed: a valid measurement of models selected on a
   flawed VALIDATION; Phase 2B not frozen). Also whether a re-run after the fix is allowed,
   labelled as a **second look** at INTERNAL TEST.
3. **Calibration-rule amendment** (§5): already applied before test; it needs ratification.
   Optionally add "no exact 0 / 1 probability reaches the contract" as a requirement. This is
   new; D50 currently allows the closed interval.
4. **The 0.5 reporting threshold** used for confusion counts (convention only, not an
   operating point).
5. **Group-weighted metrics as a standing diagnostic** in Analyzer reports.
6. **MLP not trained** (§5).
7. **Model storage:** pickles stay in gitignored `model-output-hybrid-analyzer-v1/` (repo
   convention for model outputs); hashes are recorded here (§15).
8. **Winner:** the frozen RF / HGB choice is not proposed for freezing. After the fix,
   re-select under the same criteria. The evidence so far favours HGB for both tasks,
   conditional on explaining its static-GET failure.

## 14. Next steps

- **To freeze the Analyzer:** decide §13.1–13.2 → build `hybrid_analyzer_v2` and re-run
  `select` / `bench` / `freeze` unchanged → re-verify calibration on the corrected VALIDATION →
  an INTERNAL TEST evaluation labelled as a second look (if approved) → record decisions in
  DECISIONS.md.
- **To evaluate External v1:** only after that freeze, one aggregate run under D40 / D53.
- **To decide the runtime (D52):** after the freeze, measure an exported form of the winner (e.g.
  stdlib or a compact tree runtime) against the scikit-learn numbers in §7.
- **To start the Small Decision Model:** a frozen Analyzer with demonstrated calibration on a
  clean held-out set, plus the decision on whether a Hybrid stage may ever BLOCK without V4
  (open since Phase 1, D29).

## 15. Files and hashes

| File | Content |
|---|---|
| `experiment_config.json` | grids, fixed hyperparameters, rules and amendments, seeds, dataset hashes, environment |
| `preprocessing.json` | fitted encoders (attack, category, path ablation) per family |
| `validation_results.json` | every configuration's VALIDATION metrics, seed stability, calibration CV with reliability bins, category per class and confusion matrices, both ablations, permutation importance and LR coefficients, paired bootstraps, group-weighted and error-concentration diagnostics, model hashes |
| `latency_results.json`, `latency_recommended.json` | per-model load, memory, latency distributions per stage, throughput, contract checks |
| `frozen_selection.json` | winners, rationale, frozen configs, model and evidence hashes |
| `internal_test_results.json` | run-001: both views (all metrics, reliability, recall per reason, group-weighted, error concentration, category with confusion matrices, path ablation, contract checks, lookup diagnostic, bootstraps) and `unsupported_jwt` |
| `validation_sibling_diagnostic.json` | §10 |
| `logs/` | `select_run1.log` (first run, before the §5 amendments), `select.log` (final run), `bench.log`, `bench_recommended.log`, `test.log`. The two select logs are byte-identical: the amendments changed only outputs that are not printed (calibration choice, diagnostics, prediction threading) |
| `SHA256SUMS` | hashes of every file above |

Models (gitignored, `model-output-hybrid-analyzer-v1/`; SHA-256 also in `frozen_selection.json`):

| File | Bytes | SHA-256 |
|---|---:|---|
| `logreg.pkl` | 8,515 | `def1037c189122a8ead084af2150e4afbd3ab3aecb095c3b220a5f8bf8816c22` |
| `random_forest.pkl` | 203,065,623 | `49a8063182d233165853c8724cf0fbad14eb61470f43f2adacb190439ed43781` |
| `hist_gb.pkl` | 9,556,862 | `aa3eea25aaa23ffe652e67306a3de8cf42aec30f207c94e21f22ad6b49a86543` |
| `recommended.pkl` | 48,779,141 | `03426d38f1369b8ba6450c4a48ee5c512b4a083d636647448f08a18a3c47c22d` |
| `logreg_category_path_ablation.pkl` | 5,341 | `540ab16b1eda91a12b02510c61bd920fc5feeae483395ee6e11d7291a3c363a8` |
| `random_forest_category_path_ablation.pkl` | 51,496,135 | `b0cceeb5d05c1685eb785ef34d338cf5c8671a5f1d7b2f214c8e09c1cb5d49cd` |
| `hist_gb_category_path_ablation.pkl` | 2,840,315 | `0bb78a9b9ae74103625ce74292bd6d5c58c5fb869c559805336dd239a98b8120` |
