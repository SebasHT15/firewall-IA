# Analyzer × External Test v1 — pre-registered protocol (`analyzer-external-v1-run-001`)

**Status: FIXED BEFORE EXPOSURE.** Written on 2026-10-04, before the frozen Analyzer has
scored any External Test v1 case. Its SHA-256 (with the evaluator's and the tests') is first
recorded in `PREREGISTRATION.json` before exposure, and again in `run_attempt.json` and
`run_metadata.json`; `run` refuses to start on any mismatch (§5.9, §8). This file is not edited after
the run (post-run notes go in `README.md`).

**Type: EVALUATION (offline, aggregate only).** One post-freeze aggregate evaluation of the
frozen Lightweight Request Analyzer (Model 1) on External Test v1, as authorized by **D53**
under **D40 / D45**. It is **not** an evaluation of the gateway, of a Hybrid cascade, of
Model 2 or of any ALLOW / BLOCK / UNCERTAIN policy.

## 1. Question

How does the frozen Analyzer `hybrid-analyzer-v2/attack=hist_gb,category=hist_gb` behave,
in aggregate, on the 400 frozen External Test v1 cases — ranking (ROC-AUC, PR-AUC), probability
quality (Brier, log loss, ECE) and, at the reporting-only 0.5 threshold (D55), confusion counts —
overall and per pre-registered cell?

## 2. What is fixed (nothing below may change after exposure)

| Item | Value |
|---|---|
| Cases | `datasets/external_v1/cases.jsonl` — 400 cases, SHA-256 `721dfdaa6425463ae0ce26520f6d47986fdc7388468b55d7b1a5bffed822d342` |
| Manifest | `datasets/external_v1/manifest.json`, `status: FROZEN`, integrity hash `ccac5f55eee27f94a79295f0022edf6eac792abe828ed1a1fe5f43ac85c5e52b` (method: SHA-256 of newline-joined `case_id\|request_sha256`, ordered by cell then `selection_key`) |
| Freeze commit | `36df2ee` (must be an ancestor of HEAD, D39) |
| Labels | `expected_decision` (`BLOCK` = 1, positive class; `ALLOW` = 0), assigned from flow intent before any model exposure (`datasets/external_v1/GROUND_TRUTH.md`, protocol §8). Category label: `attack_category` of BLOCK cases. Labels are read as frozen; none is reinterpreted, corrected or excluded (D39) |
| Model input | `request_text` of each case, verbatim — the frozen D1 text (the format `render_request()` produces and the Analyzer was trained on, `build_hybrid_analyzer_v2.py` → `rf.extract_features(r["input"])`). V4's direct channel posted this exact string only for its 100-case consistency subset; the V4 headline came from the gateway channel, which re-rendered each replayed request live without a byte check (protocol §11 deviation, D40) → `request_features.extract_features()` (schema `request-features/v2`, 34 features; among headers only `Content-Type` is read, D44) → the encoders frozen **inside** the artifact |
| Artifact | `model-output-hybrid-analyzer-v2/recommended.pkl`, 8,866,799 B, SHA-256 `79eb7265a7a3abd9f5a499234732042a9100729b4434971a02d73e03f6a2ff9b`, version `hybrid-analyzer-v2/attack=hist_gb,category=hist_gb`; native probabilities, no calibrator (frozen 2026-10-04T06:10:33Z, run-002) |
| Freeze record | `reports/hybrid/phase2b-analyzer-v2-run-002/frozen_selection.json`, SHA-256 `86271a46b9e2dbf85fe2c421c68c9b45ea0e73b6de7dd23eac6065a7b454b8a5`; every file in that folder's `SHA256SUMS` must verify |
| Frozen code | every file in `frozen_selection.json` → `code_sha256` must hash as recorded (extractor, contract, `hybrid_analyzer.py`, runner, builders) |
| Environment | `.venv-analyzer`: Python 3.12.15, numpy 2.5.3, scikit-learn 1.9.1, scipy 1.18.1, joblib 1.6.0, threadpoolctl 3.7.0 — identical to the run-002 test environment; any difference blocks the run |
| Development data (for one descriptive count only) | `datasets/hybrid_analyzer_v2/hybrid_analyzer_v2.jsonl`, SHA-256 `e8da8674435ed65057161bb4c74b41dc4aa1d8bf876b0327c53ecba7c0d99b75`, manifest SHA-256 `40f958ea…` (as frozen) |
| Evaluator | `scripts/evaluation/analyzer_external_v1.py` (uncommitted at run time; its SHA-256, this file's and the tests' are recorded in `PREREGISTRATION.json`, then in `run_attempt.json`) |
| Reporting threshold | 0.5, `attack ≥ 0.5` → counted as BLOCK. **Reporting-only (D55); not an operating point; nothing is tuned on it** |

No retraining, re-fitting, re-calibration, threshold search, feature change or category
re-mapping happens. The frozen encoders map unseen `method` / `content_type` values to
`__other__` exactly as at freeze.

## 3. Metrics (all aggregate)

**3.1 Headline — `attack`, n = 400 (200 ALLOW / 200 BLOCK; 50/50 by construction, D42).**
Computed with the same metric code as run-002 (`hybrid_analyzer.attack_metrics`):

- threshold-free: **ROC-AUC**, **PR-AUC** (average precision; chance level = prevalence 0.5),
  **Brier**, **log loss** (probabilities clipped to [1e-15, 1 − 1e-15]), **ECE** (15 equal-width bins);
- at the reporting-only 0.5 threshold: TP · TN · FP · FN (also in the methodology §6 layout,
  `Real ALLOW: TN FP / Real BLOCK: FN TP`), accuracy, precision (BLOCK), recall, F1, FPR, FNR —
  every rate with numerator / denominator; precision and accuracy only with the 50/50
  prevalence stated;
- uncertainty: Wilson 95% intervals for recall, FPR, FNR, precision and accuracy; class-
  stratified case bootstrap (2,000 resamples, 200 + 200 drawn with replacement per class, seed
  = first 8 bytes of SHA-256(`analyzer-external-v1-run-001`), big-endian) percentile 95% intervals for
  ROC-AUC, PR-AUC, Brier and log loss. Cases come from one lab application and shared flows, so
  they are not independent draws: the intervals are **optimistic** and are reported as such.
- reliability table (15 bins): for each bin, `n`, mean predicted and observed frequency are
  published **only when n ≥ 10**; smaller bins are reported as `suppressed (<10)` so no small
  bin approximates an individual case. ECE uses every bin.
- small-sample caveats, stated in advance: 15-bin ECE at n = 400 is biased upward; log loss is
  dominated by a few confident errors (one error at the 1e-15 clip adds ≈ 34.5 / 400 ≈ 0.086);
  a zero-error count is shown with the **one-sided** rule-of-three bound ≈ 3/n *and* the
  two-sided Wilson upper bound (0/40 → 0.088), each labelled.

**3.2 Per pre-registered cell** (10 × 40; support status `OK` under D18 / D19, n ≥ 30):

- benign slices (`browser-navigation`, `browser-forms-session`, `api-json`, `api-query`,
  `unseen-structure`): FP · TN · FPR at 0.5 (Wilson 95%), mean `attack`, Brier within the
  cell, ROC-AUC of the slice against all 200 BLOCK cases;
- attack cells (`sqli`, `cmdi`, `xss`, `path-traversal`, `ssrf`): TP · FN · recall at 0.5
  (Wilson 95%), mean `attack`, Brier within the cell, ROC-AUC of all 200 ALLOW cases against
  the cell;
- a zero-error count is reported with the rule-of-three bound ≈ 3/40 (approximate, not an exact
  interval), as in the V4 report.

**3.2b BLOCK recall by payload visibility** (added before exposure, methodology audit). From the
frozen `payload_placement`: `query`, `path`, `form`, `json` → **visible** to RequestFeatures;
`header`, `cookie` → **invisible** (D44: the only header read is `Content-Type`). Per group: BLOCK
cases, TP · FN, recall at 0.5 (Wilson 95%), mean `attack`, D18 support status. Aggregate
metadata counts read before exposure: 195 visible / 5 invisible (2 header, 3 cookie); the
invisible group is therefore `INSUFFICIENT DATA` and exploratory only. A miss there is a
**structural blind spot** of the 34 features (like JWT, D48), not a generalization result.

**3.3 Category — auxiliary context, not a security decision (D46).** Over the 200 BLOCK cases
(the category head is `P̂(category | attack, features)`, evaluated on ground-truth BLOCK, as
internally). Fixed mapping, from D47 / D49 (no new category, no re-labelling):
`sqli → sql_injection`, `cmdi → command_injection`, `xss → xss`,
`path-traversal → path_file_access`, `ssrf → ssrf`. Reported: top-1 accuracy (Wilson 95%),
per-category precision / recall / F1 over the 5 sampled categories, macro-F1 over those 5
(**not comparable** with the 8-class internal macro-F1), the 5 × 8 confusion counts (true ×
predicted, including predictions into `ssti`, `open_redirect`, `other_attack`), multiclass log
loss and Brier on the true category, mean top-1 probability.

**3.4 Descriptive aggregates (context, no metric derives a decision from them).**

- distinct 34-feature vectors among the 400 cases; cases whose vector is shared by ALLOW and
  BLOCK cases;
- cases (per class) whose feature vector also occurs in `hybrid_analyzer_v2` TRAIN ∪
  VALIDATION (the D51 / D54 "feature vector in development" relation); if both classes keep
  ≥ 30 cases, the headline metrics on the **feature-disjoint view** (vector not in TRAIN ∪
  VALIDATION), as internally — otherwise its counts with status `INSUFFICIENT DATA`;
- per class, cases whose `method` or `content_type` falls into the encoder's `__other__`
  column (unseen at freeze);
- contract check: every case through `AnalyzerModel.analyze()` → count of `AnalyzerOutput`
  contract violations, and whether its `attack` equals the batch probability (a reported count,
  never fatal).

**3.4b Group-weighted diagnostic (D55)** (added before exposure, methodology audit). Groups =
connected components, **inside External v1**, of the D54 relation without its generator-family
component (External v1 has no generator): same D51 canonical request
(`parse_dataset_v4.canonical_key("{method} {path}?{query}\n{content_type}\n{body}")`, headers other
than `Content-Type` excluded) OR same 34-feature vector — the relation already applied inside V4
eval for the internal group-weighted metrics. This applies a decided relation; no new grouping
is invented. Reported: number of groups, groups with > 1 case, groups holding both labels;
`hybrid_analyzer.attack_metrics_group_weighted` (each group weighs 1); error concentration as
numbers only (errors, distinct groups holding them, largest error group, share in the top 2) —
no group metadata; group-bootstrap 95% intervals (1,000 resamples, same seed) for ROC-AUC and
Brier. Diagnostic only: never replaces the row-weighted metrics.

**3.4c Internal reference.** The same Analyzer's frozen run-002 figures on
`internal_test_feature_disjoint` (D51 primary view), read from `internal_test_results.json`
(hash verified by the run-002 `SHA256SUMS`), labelled verbatim "SECOND-LOOK INTERNAL EVALUATION
AFTER METHODOLOGY CORRECTION — NOT AN UNTOUCHED TEST". Compared only on ROC-AUC, Brier, log loss,
ECE, recall and FPR: its prevalence is 55.6% BLOCK, so PR-AUC, precision and accuracy are not
compared.

**3.5 Not applicable / not computed — stated so they cannot be added afterwards.**

| Item | Status | Why |
|---|---|---|
| Generator-family component of the D54 relation | NOT APPLICABLE | External v1 has no generator; the group-weighted diagnostic (§3.4b) uses the other two D54 relations |
| `unsupported_jwt` slice (D48) | NOT EVALUABLE | External v1 samples no JWT case |
| Categories `ssti`, `open_redirect`, `other_attack` | NOT EVALUABLE (not sampled) | no ground-truth case; predictions into them are counted as errors only |
| 14 of 19 V4 attack reasons | NOT EVALUABLE | External v1 samples 5 categories (protocol §13.4) |
| L2 / L3, latency | NOT APPLICABLE | offline evaluation; no gateway, no timing claim |
| Invalid outputs (E5) | replaced by the contract-violation count | the Analyzer returns a probability, not parsed text |
| Secondary breakdowns (`client_profile`, `method`, `host_type`, …) | NOT COMPUTED | not pre-registered for the Analyzer; only the 10 primary cells |
| Any operating threshold, threshold sweep, calibrator | NOT COMPUTED | D53 / D55 |
| **Joint V4 × Analyzer counts** (agreement, "V4 FP that the Analyzer scores < 0.5", any cascade-like figure) | **NOT COMPUTED** | that is the disagreement analysis, which must start on development / diagnostic data; on External v1 it would size a Hybrid component from test cases (D45). Only the published V4 marginal aggregates are placed beside the Analyzer's |

## 4. Output — aggregate only

**k-rule (K = 10), added before exposure after the code audit.** No published quantity may be a
function of fewer than 10 cases' predictions, directly **or by differencing two published
figures**. Consequently: reliability bins with n < 10 are hidden, and if the hidden pool would hold
1–9 cases the smallest published bins are hidden too (ECE covers every bin, so the pool's
contribution is otherwise derivable); the feature-disjoint view is published only if each class
excludes cases only in **input-determined parts of ≥ 10 cases**: membership in a cell, in the
"vector in development" set and in a group of a given size is computable from the cases without
the model, so every such restricted sum can be differenced against the per-cell figures. The
feature-disjoint view is published only if every non-empty cell × in-development part holds
≥ 10 cases; the group-weighted diagnostic only if every non-empty cell × group-size part (× in-
development, when the view is published) holds ≥ 10 cases; otherwise `SUPPRESSED`, counts only.
The payload-visibility means are published only if every part holds ≥ 10 cases (the 5-case
invisible group makes them `suppressed`; TP / FN counts stay, like per-cell confusion counts —
so the invisible group's 5-case recall is an accepted small-n count, exploratory only). Confusion counts (TP · TN · FP ·
FN), per cell or per group, are aggregate counts and are always published, as in the V4 report.

Written to `reports/hybrid/analyzer-external-v1-run-001/`: `PREREGISTRATION.json` and
`preflight.json` (no model call), `run_attempt.json` (created exclusively before any inference,
embedding the preflight at start), `aggregate_results.json`,
`run_metadata.json`, `console.log`, then `README.md` and `SHA256SUMS`. **Never written,
printed or logged:** request text, case ids, per-case labels, probabilities or predictions,
FP / FN lists, examples, per-case hashes of predictions, tracebacks. Before writing,
`aggregate_results.json` is scanned: no case id, no request SHA-256, no `request_text` key, no
numpy value, no list longer than 16 elements and no dict with more than 24 keys may appear; otherwise nothing is written and the run fails.
A failure records only the stage and the exception class name (never its message).

## 5. Preflight — conditions that prevent the run

The run does not start unless all hold:

1. branch `research/hybrid-analyzer-external-v1-aggregate`; HEAD descends from `36df2ee`;
   the only uncommitted paths are the evaluator, its tests and this report folder;
2. no tracked file differs from HEAD under `datasets/external_v1/`, `reports/external/`,
   `reports/hybrid/phase2b-analyzer-baselines/`, `reports/hybrid/phase2b-analyzer-v2-run-002/`;
3. External v1: manifest `FROZEN`; `cases.jsonl` SHA-256 = manifest = anchor; every
   `request_sha256` recomputes; integrity hash recomputes to the anchor; External v1
   `SHA256SUMS` verifies; 400 cases, 200 / 200, 10 cells × 40; labels consistent with cells
   (ALLOW ↔ benign slices, BLOCK ↔ attack cells, `attack_category` = cell);
4. artifact SHA-256 and size as frozen; `frozen_selection.json` hash; run-002 `SHA256SUMS`
   verifies; frozen code hashes match; dataset v2 and its manifest hash as frozen;
5. environment versions identical to the run-002 test environment;
6. feature schema `request-features/v2`, 34 fields, in the frozen `feature_order`; the encoder
   inside the artifact has exactly the columns recorded in run-002 `preprocessing.json`;
7. synthetic tests of the evaluator pass; both independent read-only audits report no blocker;
8. `run_attempt.json`, `aggregate_results.json` and `run_failure.json` do not exist (single run,
   D32 rule);
9. `PREREGISTRATION.json` exists, HEAD equals the commit it recorded, and the SHA-256 of this
   protocol, the evaluator and its tests still equal the values it recorded (see §8);
10. the artifact loads (bytes read once, hashed, then unpickled), passes the feature contract
    (§5.6) and the development vector relation recomputes on every TRAIN ∪ VALIDATION row —
    **inside the preflight**, before the run starts and with no inference; `internal_test_results.json`,
    run-002 `preprocessing.json` and V4's `summary.json` match their anchored SHA-256; every
    `SHA256SUMS` verifies at least one entry and External v1's lists `cases.jsonl`.

The artifact's SHA-256 is verified before it is unpickled. Every case must carry a string
`payload_placement` and `request_text`, and every BLOCK placement must be in the §3.2b mapping
(counted, never listed). The synthetic tests verify that neither the tests nor the evaluator
open anything under `datasets/external_v1/` or any per-case V4 evidence
(`reports/external/*/results.jsonl`, `raw/`) during the synthetic suite; in the real run the evaluator reads only V4's aggregate
`summary.json`.

## 6. Single run, no retry

The run is started **once** with `--confirm-single-run`. `run_attempt.json` is created
exclusively (`open(..., "x")`) before the cases are scored; its existence makes every later
start refuse. If the run fails after that point, the failure (stage + exception class) is
recorded and the work stops: **no automatic retry, no "fix and re-run" on External v1**;
the owner decides.

## 7. Interpretation limits (fixed in advance)

- 50/50 is a construction: precision, accuracy and FPR are test-specific (D42), never
  operational rates; `attack` is not an estimate of operational attack prevalence (D50).
- Offline: the Analyzer scores the frozen D1 text; External v1 has no byte-level evidence of
  what the gateway's classifier received (protocol §11 deviation) — irrelevant here, but the
  V4 comparison is therefore gateway-measured V4 vs offline Analyzer.
- The V4 figures are L1 of the gateway run `external-v1-run-001`; the comparison is side by
  side, never a cascade estimate.
- One lab application, five attack categories, n = 40 per cell; intervals optimistic (§3.1).
- The internal comparison baseline (INTERNAL TEST) is a **second look, not untouched** (D54).
- V4 reads the whole D1 text, headers included; the Analyzer reads 34 features. V4's 68/200 is
  at its real decision; the Analyzer's FPR is at the reporting-only 0.5. **This is not an
  operating-point comparison**, and no "Analyzer threshold at V4's FPR" (or any other threshold)
  is computed: that would be a threshold search on the test set.
- Payloads in headers or cookies (5 BLOCK cases) and the "unseen header names" axis of
  `unseen-structure` are invisible to the Analyzer by construction (D44).
- Unseen `method` / `content_type` values are encoded in an `__other__` column that is constant
  (zero) in TRAIN, so the trees never split on it: those cases are pure extrapolation.
- V4's External v1 aggregates (per cell) were published before Hybrid Phase 2A. That is not
  consumption under D40, but the Hybrid programme was not blind to External v1 at aggregate level.
- A good or bad result does not change Model 1 (D53). External v1 stays usable as V4's
  external record; this aggregate run does not consume it (D40). No individual case is
  inspected.

## 8. Pre-registration anchoring and revisions before exposure (disclosed)

- **Not committed before the run.** The owner's instruction for this checkpoint is "no commit,
  no push, no PR", so this protocol, the evaluator and its tests are uncommitted when the run
  starts. The methodology audit flagged this as self-attested. Mitigation: `PREREGISTRATION.json`
  is created exclusively (`prereg` command, no model call) with the SHA-256 of these three files
  and the HEAD commit; `run` refuses to start if any of them differs; the same hashes are posted
  in the session transcript before the run; the owner is asked to commit protocol, code and
  results together. This is a **disclosed deviation** from committed pre-registration.
- **Revision 1 (before exposure), after the independent methodology audit:** added §3.2b (payload
  visibility), §3.4b (group-weighted diagnostic with the D54 relation inside External v1,
  replacing the earlier NOT APPLICABLE), §3.4c (internal reference), small-sample caveats, the
  methodology §6 confusion layout, the feature-disjoint fallback, the pre-registration check and
  four interpretation limits; reworded the model-input row. After the auditor's re-check: a
  preflight check that every case has a string `payload_placement` / `request_text` with a
  mapped BLOCK placement, and wording fixes. No Analyzer output on External v1 existed when
  these changes were made.
- **Revision 2 (before exposure), after the independent code audit:** the k-rule of §4 (two
  differencing leaks found: feature-disjoint view vs headline, and ECE vs published bins; a
  third, found on the auditor's re-check: input-determined subsets differenced against the
  per-cell sums — closed by the part-based rule), the
  pre-inference checks moved into the preflight, HEAD pinned to `PREREGISTRATION.json`, anchors
  for `internal_test_results.json` / `preprocessing.json` / V4 `summary.json`, stricter
  `SHA256SUMS` checks, a dict-size / numpy guard, single-read artifact loading, and broader test
  guards (`builtins.open`, `io.open`, `os.open`; the whole `datasets/external_v1/` folder).
  Residual, accepted: a SIGKILL after `run_attempt.json` is written leaves no failure record (a
  retry is still refused).
