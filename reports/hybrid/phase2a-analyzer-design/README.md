# Hybrid Architecture Phase 2A — Analyzer target and dataset design

**Kind: design analysis — FROZEN (2026-10-01).** No model was trained, no dataset was created
or modified, and External Test v1 was not read. Issue #51 · builds on Phase 1 (D43–D45,
`request-features/v2`) · frozen decisions **D46–D53** in [`DECISIONS.md`](../../../DECISIONS.md).

Every V4-clean number below comes from [`analysis.json`](analysis.json); every external-dataset
measurement from [`external_datasets_measurements.json`](external_datasets_measurements.json);
the survey record per dataset is [`external_datasets.json`](external_datasets.json).

```bash
python3.12 scripts/dataset/analyze_analyzer_targets.py --out reports/hybrid/phase2a-analyzer-design/analysis.json
```

Input: `datasets/v4_clean/{train,eval}.jsonl`, SHA-256 verified against
`datasets/manifest_v4_clean.json` (generator commit `1bf412f`); the source-collision section
also reads PayloadsAllTheThings at the manifest's commit `e961fef` (verified). Only
aggregate statistics of the eval split were computed; no individual eval row or error
guided a choice (D37). The output is byte-identical across runs and `PYTHONHASHSEED` values.

| Section | Content |
|---|---|
| 1–6 | observations on V4-clean (6 includes the grouping check the freeze required) |
| 7–11 | the **frozen design** (D46–D53) |
| 12 | Phase 2B plan |
| 13–15 | External Dataset Survey, its impact, future candidates |
| 16 | criteria for closing Phase 2A |

The Phase 2A labels used when the decisions were issued map to the log as follows (the log
already has its own D1–D8, so the new entries are numbered after D45):

| Phase 2A | Decision | Subject |
|---|---|---|
| D1 | **D46** | two-level formulation: `attack` + auxiliary category; mandatory category ablation |
| D2 | **D47** | category vocabulary and the reason → category mapping |
| D3 | **D48** | JWT excluded from fitting; `unsupported_jwt` evaluation slice |
| D4 | **D49** | Directory Traversal + File Inclusion merged into `path_file_access` |
| D5 | **D50** | `AnalyzerOutput` semantics; no global confidence |
| D6 | **D51** | `hybrid_analyzer_v1`: source, roles, grouping, INTERNAL TEST views |
| D7 | **D52** | Analyzer runtime not decided; separate research environment; D33 intact |
| D8 | **D53** | External Test v1 not used before the Analyzer is frozen; aggregate-only after |

---

## 1. Dataset schema (observed)

- Fields: exactly `instruction`, `input`, `output` in all 31,340 rows. `instruction` is one
  constant string.
- `output` is always `ALLOW | <reason>` or `BLOCK | <reason>` (0 malformed); 20 distinct
  values: 1 ALLOW reason, 19 BLOCK reasons.
- **There is no category, source, group or provenance field.** The category exists only as
  the reason text. The generator's in-memory provenance (`_src`, `_cat`, `_gid`) is stripped
  before writing (`parse_dataset_v4.py`, "[9/9]").
- No input contains a label or reason string (0 / 31,340).

## 2. Distribution (observed)

31,340 rows — train 25,134 (12,567 ALLOW / 12,567 BLOCK), eval 6,206 (3,103 / 3,103).
"LG" = PayloadsAllTheThings/hardcoded logical groups from the manifest (CSIC groups are not
counted there). Status columns apply D18/D19: eval support < 30, LG < 100.

| Category (reason) | train | eval | % of all | % of BLOCK | LG | flags |
|---|---:|---:|---:|---:|---:|---|
| BENIGN (`Normal HTTP request…`) | 12,567 | 3,103 | 50.000 | — | — | |
| SQL Injection | 3,183 | 817 | 12.763 | 25.526 | 1,074 | |
| XSS Injection | 2,920 | 708 | 11.576 | 23.153 | 2,114 | |
| File Inclusion | 2,101 | 494 | 8.280 | 16.560 | 2,500 | |
| Directory Traversal (`Path traversal…`) | 2,005 | 506 | 8.012 | 16.024 | 2,500 | |
| Command Injection | 607 | 134 | 2.364 | 4.729 | 453 | |
| CRLF Injection | 399 | 112 | 1.631 | 3.261 | 21 | LG < 100 |
| Server Side Template Injection | 393 | 88 | 1.535 | 3.070 | 368 | |
| Open Redirect | 208 | 51 | 0.826 | 1.653 | 242 | |
| Server Side Request Forgery | 186 | 63 | 0.795 | 1.589 | 201 | |
| XXE Injection | 116 | 27 | 0.456 | 0.913 | 98 | eval < 30, LG < 100 |
| NoSQL Injection | 97 | 17 | 0.364 | 0.728 | 83 | eval < 30, LG < 100 |
| JSON Web Token | 95 | 16 | 0.354 | 0.708 | 80 | eval < 30, LG < 100 |
| LDAP Injection | 80 | 21 | 0.322 | 0.645 | 75 | eval < 30, LG < 100 |
| GraphQL Injection | 75 | 22 | 0.310 | 0.619 | 74 | eval < 30, LG < 100 |
| Cross-Site Request Forgery | 38 | 8 | 0.147 | 0.294 | 31 | eval < 30, LG < 100 |
| XPath Injection | 29 | 11 | 0.128 | 0.255 | 24 | eval < 30, LG < 100 |
| HTTP Parameter Pollution | 17 | 3 | 0.064 | 0.128 | 20 | eval < 30, LG < 100 |
| Insecure Deserialization | 11 | 5 | 0.051 | 0.102 | 12 | eval < 30, LG < 100 |
| Request Smuggling | 7 | **0** | 0.022 | 0.045 | 7 | **absent from eval** |

Eight categories have eval support ≥ 30 and LG ≥ 100 — the same eight reported as `OK`
in the V4 internal evaluation. Eleven do not.

## 3. Nature of the labels (observed)

**A. One category per request?** Yes, in the dataset: every row has exactly one of the 20
outputs. **The single label is partly a construction artifact:**

- *PayloadsAllTheThings:* the category is the **source directory**. 410 of 18,445 unique
  canonical payloads (2.2%) occur in more than one category directory; the generator keeps
  only the first in sorted order. 382 are Directory Traversal + File Inclusion (all kept as
  Directory Traversal); the rest are small (SQLi + XPath 6, SSTI + XSS 6, Open Redirect + XSS
  4, CSRF + XSS 3, XSS + XXE 3, …).
- *CSIC 2010:* BLOCK rows are labelled by the keyword heuristic `csic_category()` (audit F6),
  first match wins. Of the 3,906 CSIC-derived BLOCK rows, 408 (10.4%) match more than one
  rule family: SQL + command + path traversal 167, SQL + command 136, SQL + CRLF 50,
  SQL + XSS 49, XSS + command 6. The first match equals the label in 3,906 / 3,906, which
  validates the rule extraction.

**B. Multiple attack types in one request?** The dataset never labels it. Conceptually it
can happen in HTTP (and the source collisions above show payloads that are legitimately
more than one thing), but no row carries a second label, and the "negative" categories of a
row are not reliable negatives (a CSIC row labelled SQL may also match the command rules).

**C. What do categories describe?** A mix of three things, not only attack type:
1. the PayloadsAllTheThings directory a payload came from (folder-determined, F7);
2. the first matching CSIC keyword rule (F6): 66.7% of SQL Injection rows (2,668 / 4,000)
   and 95.5% of CRLF Injection rows (488 / 511) are CSIC-heuristic labels;
3. a hardcoded list (CRLF, XPath, HPP, Request Smuggling).
They are also tied to **synthetic request shapes**: each category is rendered only in its
1–3 shapes (`CATEGORY_SHAPES`), so the endpoint correlates with the category (section 5).
They are also exactly the reason strings V4 was trained to emit, so "category" and "V4
reason" are the same vocabulary here.

**D. Benign class?** Yes: one ALLOW reason, 15,670 rows (CSIC Normal 7,273, synthetic
8,397 — source inferred from the path, which reproduces the manifest's 3,906 CSIC BLOCK
rows exactly).

**E. Problematic labels:**

| Problem | Evidence | Affected |
|---|---|---|
| Too scarce to train or evaluate | eval < 30 and/or LG < 100 | 11 categories (table above); Request Smuggling has 0 eval rows |
| Not observable from RequestFeatures v2 | the JWT payload is placed only in `Authorization` (`render_request`), and 70.3% of JWT rows have the coarse feature profile of benign rows of the same shape (all other categories 0–14.4%) | JSON Web Token |
| Detected through the generator's payload text, not the attack mechanism | CSRF's and smuggling's causal signal is in headers (cross-origin `Origin`/`Referer`; conflicting `Content-Length`/`Transfer-Encoding`), which features do not read (D44); their rows are separable only by the PayloadsAllTheThings text or chunk body placed in the surface | CSRF, Request Smuggling |
| Heuristic-labelled (circular with keyword rules) | F6; shares above | SQL Injection (66.7%), CRLF (95.5%), XSS (17.7%), Command Injection (14.7%) |
| Arbitrary boundary | 382 shared payload groups resolved alphabetically | Directory Traversal vs File Inclusion |

## 4. RequestFeatures v2 as model input (observed)

| Type | Fields |
|---|---|
| numeric, int (25) | `path_length`, `query_length`, `body_length`, `query_param_count`, `body_param_count`, `total_param_count`, `repeated_param_name_count`, `symbol_count`, `non_ascii_count`, `percent_encoded_count`, `longest_char_run`, `path_depth`, `json_depth`, and 12 syntax counts (`single_quote_count` … `brace_count`) |
| numeric, float (4) | `alnum_ratio`, `symbol_ratio`, `percent_encoded_ratio`, `entropy_bits_per_char` |
| boolean (2) | `has_body`, `has_percent_encoding` |
| categorical (3) | `method` (6 values seen), `content_type` (5: `""`, form, JSON, `text/xml`, `application/xml`), `body_format` (5, a closed enum) |

`schema_version` is metadata, not an input. 31,340 rows map to 23,266 distinct vectors;
440 rows share a vector with a different label.

**Where the attack signal sits:** the generator percent-encodes query and form payloads, so
for the large categories the evidence is in `percent_encoded_count`, not in the raw syntax
counts — SQLi 91.0% of rows percent-encoded vs 2.5% with any raw quote / bracket /
semicolon / pipe / backslash / brace; XSS 88.6% vs 9.5%; Directory Traversal 97.0% vs
10.8%; benign 25.7% vs 1.0%. JSON/XML-bodied categories show raw syntax instead (GraphQL
100%, XXE 97.2%, NoSQL 58.8%).

## 5. Leakage and shortcuts (observed)

Single-variable lookup (fit on train, scored on eval; E0-style; reveal = ≥ 99% purity at
≥ 1% coverage):

| Variable | Kind | Decision (majority 0.500) | Category given BLOCK (majority 0.263) | Reveals |
|---|---|---:|---:|---:|
| `method` | runtime feature | 0.500 | 0.330 | 0 |
| `content_type` | runtime feature | 0.512 | 0.297 | 0 |
| `body_format` | runtime feature | 0.537 | 0.298 | 0 |
| `path_length` | runtime feature | 0.512 | **0.467** | 0 |
| `path_depth` | runtime feature | 0.501 | 0.348 | 0 |
| path (endpoint) | **offline only** | 0.554 | **0.653** | 0 |
| source (CSIC / synthetic) | **offline only** | 0.588 | 0.379 | 0 |

- **Binary target:** no runtime feature is a shortcut (content type 51.2% — the same
  51.16% E0 recorded). The E2 envelope neutralization holds for the Analyzer.
- **Category target:** confounded with dataset construction. The endpoint (offline) predicts
  the category at 65.3%, and `path_length`, a legitimate runtime feature, proxies it at
  46.7%, because each category is rendered on a small fixed set of synthetic paths. A
  category model trained here will partly learn "which synthetic endpoint", which real
  traffic does not follow.
- `Host` / `User-Agent`: not read by any feature (D44; tested in Phase 1).
- No label text in inputs; the constant `instruction` carries nothing.

**Runtime-valid inputs:** the 34 RequestFeatures v2 fields, nothing else.
**Offline-only metadata — never an Analyzer input:** `output`/reason, `instruction`,
source (CSIC / PayloadsAllTheThings / synthetic), endpoint and shape, generator group ids,
PayloadsAllTheThings directory and file, CSIC rule hits, augmentation transform, split
membership, manifest statistics.


## 6. Split validity and the grouping check (observed)

- **Mechanism (D16):** group ids — canonical payload for attacks, `shape|path|param|value` for
  synthetic benign, a digit-collapsed request key for CSIC — are hashed into train/eval
  before rendering; the generator asserts that no group is in both splits. Group ids are not
  in the JSONL.
- **Exact text** shared across splits: 0 (E0 agrees).
- **At the Analyzer's level** (headers are invisible to it), distinct groups coincide: 130 eval
  rows share a header-free request with some train row and 739 share a feature vector
  (counted against all of train). Inside train, 5,280 rows sit in canonical-request groups
  of ≥ 2, mostly a payload and its augmentation variant: a row-level split would leak.

**Grouping check required by the freeze.** VALIDATION (20%, salt
`hybrid-analyzer-v1-validation`) was carved from V4 train under two group definitions:

| | canonical request only | **canonical request or feature vector** (D51) |
|---|---:|---:|
| groups | 20,338 | 18,720 |
| largest group (rows) | 410 | 417 |
| VALIDATION share of V4 train | 19.93% | 19.87% |
| **VALIDATION rows whose feature vector is in effective TRAIN** | **465** | **0** |
| VALIDATION rows whose canonical request is in effective TRAIN | 0 | 0 |

Grouping by canonical request alone leaves 465 VALIDATION rows with an exact feature vector
present in TRAIN — the leak the feature-disjoint test view exists to remove, so model
selection would have been optimistic. Linking rows that share either key (connected
components) closes it without creating a giant group: the largest is one CSIC benign
request repeated with different envelopes (`POST /publico/vaciar.jsp`, 410 rows, plus 7
vector-linked rows).

**Reference set of the feature-disjoint view.** Measured against the fitted rows only, 331
eval rows whose exact vector appears only in VALIDATION would count as disjoint (5,787
rows). VALIDATION drives model selection and calibration, so the frozen view uses every
V4-train row available to the Analyzer (TRAIN ∪ VALIDATION, JWT excluded): **5,456 rows**.
This reference is also independent of the VALIDATION salt.

---

## 7. Frozen Analyzer target (D46, D47, D49)

**Formulation (D46).** Two levels:

1. `attack` — the primary signal, `P̂(BLOCK | RequestFeatures)`.
2. category — **auxiliary context**, a distribution over the vocabulary below given attack. It is
   not strong evidence for the future Decision Model until Phase 2B shows that it
   generalizes and does not rest mainly on synthetic endpoint artifacts. The mandatory
   ablation (section 12) decides that.

Not used: a flat 20-class multiclass, or a multilabel target built from the current labels
(one positive per row, unreliable negatives, section 3). Multilabel may be revisited only on
real external evidence (section 14).

**Vocabulary and mapping (D47, D49).** V4 reasons are kept only as provenance; the Analyzer
target is the right-hand column. Counts are rows in V4 train / eval.

| V4 reason (generator category) | Analyzer target | train | eval |
|---|---|---:|---:|
| Normal HTTP request with no attack patterns detected. (BENIGN) | `attack = 0`, no category | 12,567 | 3,103 |
| SQL injection payload detected. | `sql_injection` | 3,183 | 817 |
| Cross-site scripting payload detected. | `xss` | 2,920 | 708 |
| Path traversal attack detected. (Directory Traversal) | `path_file_access` | 2,005 | 506 |
| File inclusion attack detected. | `path_file_access` | 2,101 | 494 |
| Command injection payload detected. | `command_injection` | 607 | 134 |
| Server-side template injection payload detected. | `ssti` | 393 | 88 |
| Open redirect payload detected. | `open_redirect` | 208 | 51 |
| Server-side request forgery attack detected. | `ssrf` | 186 | 63 |
| CRLF injection payload detected. | `other_attack` | 399 | 112 |
| XML external entity injection detected. | `other_attack` | 116 | 27 |
| NoSQL injection payload detected. | `other_attack` | 97 | 17 |
| LDAP injection payload detected. | `other_attack` | 80 | 21 |
| GraphQL injection payload detected. | `other_attack` | 75 | 22 |
| CSRF attack pattern detected. | `other_attack` | 38 | 8 |
| XPath injection payload detected. | `other_attack` | 29 | 11 |
| HTTP parameter pollution detected. | `other_attack` | 17 | 3 |
| Insecure deserialization payload detected. | `other_attack` | 11 | 5 |
| HTTP request smuggling attack detected. | `other_attack` | 7 | 0 |
| JWT token manipulation attack detected. | **not fitted** — `unsupported_jwt` slice (D48) | 95 | 16 |

- `path_file_access` merges two reasons whose boundary is partly arbitrary: 382 of the source
  payloads sit in both PayloadsAllTheThings directories and were resolved alphabetically
  (section 3). The name is kept; the closest standard umbrella is CWE-73 (*External Control of
  File Name or Path*), which covers both traversal (CWE-22) and file inclusion (CWE-98). An
  external dataset makes the same grouping (ModSec-WP, section 13).
- `other_attack` is a **residual bucket** — the BLOCK reasons too scarce to be targets — and is
  not a semantic category; its members share nothing but their scarcity.

## 8. Frozen `AnalyzerOutput` (D50)

Formalized in [`data_plane/hybrid_contracts.py`](../../../data_plane/hybrid_contracts.py) (contract only;
no model):

| Signal | Meaning |
|---|---|
| `attack` | `P̂(BLOCK \| RequestFeatures)`, calibrated. **V4-clean is 50 / 50 by construction, so this is not an estimate of operational attack prevalence** (D42) |
| `category:<id>` for the 8 ids | `P̂(category = id \| attack, RequestFeatures)`; all 8 present and summing to 1, or all absent |

- **No global `confidence`.** Uncertainty is derived from the probabilities when needed:
  closeness of `attack` to 0.5, top-1 category probability, top-1 / top-2 margin, entropy.
  No additional score is invented.
- The contract rejects unknown signal names, a missing `attack`, values outside [0, 1], a
  partial category set and a category sum off 1 (tolerance 1e-6).
- `DecisionOutput` (the future Decision Model's answer) keeps its own `confidence`; D50
  concerns the Analyzer only.

Example: `AnalyzerOutput({"attack": 0.94, "category:sql_injection": 0.81, …}, "hybrid-analyzer-v1/<model-id>")`.

## 9. JWT (D48)

- **Why not fitted:** the JWT payload lives only in the `Authorization` header
  (`render_request`), which RequestFeatures v2 does not read (D44 reads only `Content-Type`);
  70.3% of JWT rows have the coarse feature profile of benign rows of the same shape. Fitting
  them would teach `attack` that benign-looking surfaces are attacks.
- **How it is evaluated:** its rows stay in V4-clean untouched and form the `unsupported_jwt`
  slice (train 95 → TRAIN 82 / VALIDATION 13; eval 16), reported separately as a known blind
  spot: the share of those rows the Analyzer scores as attack-like. They are outside both
  INTERNAL TEST views.
- **What supporting it would need:** a decision to read `Authorization` (or a derived,
  privacy-safe token feature) as an Analyzer input — a change to D44's Phase 1 scope — plus
  labelled evidence. No public labelled JWT-attack dataset was found (section 13).

## 10. `hybrid_analyzer_v1` (D51) — to be built in Phase 2B

| Role | Source | Rows | Fitted rows (JWT out) |
|---|---|---:|---:|
| TRAIN | V4 train, groups outside the VALIDATION bucket | 20,141 | 20,059 |
| VALIDATION | V4 train, groups in the bucket | 4,993 | 4,980 |
| INTERNAL TEST — `internal_test_full` | V4 eval, JWT excluded | 6,190 | — |
| INTERNAL TEST — `internal_test_feature_disjoint` | full minus rows whose feature vector occurs in TRAIN ∪ VALIDATION | 5,456 | — |
| `unsupported_jwt` slice | V4 eval JWT rows | 16 | — |

Targets per role (rows): BENIGN 10,028 / 2,539 / 3,103 / 2,423 · `sql_injection` 2,566 / 617 /
817 / 765 · `xss` 2,360 / 560 / 708 / 707 · `path_file_access` 3,285 / 821 / 1,000 / 1,000 ·
`command_injection` 491 / 116 / 134 / 134 · `ssti` 315 / 78 / 88 / 88 · `open_redirect` 162 / 46 /
51 / 50 · `ssrf` 144 / 42 / 63 / 63 · `other_attack` 708 / 161 / 226 / 226 (TRAIN / VALIDATION /
full / feature-disjoint). **Support check of the fitted rows** (`analysis.json`,
`fitted_support`; JWT excluded): ALLOW 10,028 / 2,539 and BLOCK 10,031 / 2,441 (TRAIN /
VALIDATION); every Analyzer category is present in both roles with VALIDATION shares of
18.5–22.6%; no class falls below the D19 support floor of 30. The smallest VALIDATION
supports are `ssrf` (42) and `open_redirect` (46): adequate, but category selection and
calibration on them carry more noise than on the large classes.

- **Source:** only V4-clean, verified by the manifest SHA-256; V4-clean is never modified.
- **Group (exact definition):** connected components over V4 train of the relation "same
  canonical request OR same feature vector", where canonical request =
  `parse_dataset_v4.canonical_key(f"{method} {path}?{query}\n{content_type}\n{body}")`
  (header-free surface) and feature vector = the 34 RequestFeatures v2 values in field order;
  the group key is the lexicographically smallest canonical request in the component.
- **VALIDATION:** group in VALIDATION iff
  `int.from_bytes(sha256("hybrid-analyzer-v1-validation" + "\x00" + group_key)[:8], "big") % 10000 < 2000`
  — deterministic, order-independent, independent of `PYTHONHASHSEED` (same mechanism as D16).
- **INTERNAL TEST views:** no row is removed; each eval row carries
  `meta_feature_vector_in_train` (734 rows) and an independent `meta_canonical_request_in_train`
  (127 rows), both against TRAIN ∪ VALIDATION. `internal_test_feature_disjoint` is the
  **primary reference for generalization claims**; every report gives both views, both counts
  and the views' class mix (full 3,087 BLOCK / 3,103 ALLOW; feature-disjoint 3,033 / 2,423 — no
  longer 50 / 50, so precision and accuracy must be stated with that prevalence, D42).
- **Per row:** `row_id` = SHA-256 of `input` (joins back to V4; the text is not copied), role,
  the 34 features, `target_attack`, `target_category`, slice, offline metadata prefixed
  `meta_` (V4 reason, inferred source, shape, group key, flags).
- **Manifest, versioning, reproducibility:** input hashes and generator commit, builder
  commit, feature schema `request-features/v2`, target schema `analyzer-targets/v1`, the
  mapping table, salt and fraction, counts per role × target, flag counts, output SHA-256;
  immutable once a model is trained on it (D32 / D39 rules); the JSONL is regenerated
  locally like V4 (D6). Any change → `hybrid_analyzer_v2`.

## 11. Runtime and External Test v1 (D52, D53)

- **Runtime (D52):** not decided. Phase 2B may use a separate research environment with numpy
  and scikit-learn; nothing is installed in the data-plane environment; D33 stands; the data
  plane is not changed. Where the Analyzer runs (stdlib inference of an exported model,
  control plane, or another justified option) is decided only after a winning model's
  quality, latency, size and memory are measured.
- **External v1 (D53):** not used for training, validation, model / feature / hyperparameter /
  threshold selection, error analysis, vocabulary or redesign. Only after target schema,
  preprocessing, model, hyperparameters and any thresholds are frozen on TRAIN / VALIDATION /
  INTERNAL TEST may one aggregate evaluation on External v1 be run, under D40; its individual
  errors are never inspected to change the Analyzer.

---

## 12. Phase 2B plan (not started)

1. **Build `hybrid_analyzer_v1`** exactly as section 10 (builder + manifest; assert counts
   against this report).
2. **Preprocessing:** one-hot for `method` and `content_type` with an `other` bucket for unseen
   runtime values; `body_format` as its closed enum; booleans 0/1; `log1p` + standardization
   (fit on TRAIN) for linear models and the MLP only; no feature dropped or added.
3. **Baselines:** prior / majority and the single-variable lookups (floor); logistic regression;
   random forest; HistGradientBoosting; a small MLP only if a clear gap remains. Small fixed
   grids.
4. **Model selection:** on VALIDATION only; calibration of `attack` (and of the category
   distribution if used) on VALIDATION; INTERNAL TEST read once, at the end.
5. **Mandatory category ablation (D46):** the category model with all RequestFeatures v2 vs
   without `path_length` and `path_depth` (at least). Question: how much category performance
   comes from the payload and how much from the synthetic endpoint. A large drop makes the
   category low-confidence context for the Decision Model.
6. **Latency / footprint benchmark:** per request (features → signals, and extraction +
   Analyzer); load and first call apart; warm-up apart; steady-state n, min, mean, P50, P95,
   P99, max (nearest-rank); single-thread throughput; artifact size; resident memory. No
   threshold exists for this component and none is set.
7. **Metrics on INTERNAL TEST (both views):** `attack` — TP / TN / FP / FN, precision, recall,
   F1, FPR, FNR, ROC-AUC, PR-AUC, Brier score and a reliability diagram / ECE, recall per V4
   reason with its D18 status; category (BLOCK rows) — macro-F1 (headline), per-class
   precision / recall / F1 with support, confusion matrix, the ablation delta; invalid outputs
   (contract violations) must be 0; JWT slice reported separately; V4 as a reference with its
   caveat (it used the eval split for checkpoint selection, D24).
8. **After the freeze only:** one aggregate External v1 evaluation (D53); then the runtime
   decision (D52).

---

## 13. External Dataset Survey

**Scope and method.** Public sources searched on 2026-10-01 (Kaggle, Hugging Face, Zenodo,
Harvard Dataverse, GitHub, university pages, papers). Each candidate was traced to its
primary source; properties come from the publisher's metadata, the authors' paper or page,
or were **measured** on the files with
[`scripts/dataset/survey_external_datasets.py`](../../../scripts/dataset/survey_external_datasets.py)
(local copies outside the repository; SR-BH 2020 was streamed, not stored). Where only a
secondary description exists, or nothing could be confirmed, the record says so. Full
per-dataset fields (URL, origin vs mirror, authors, paper, version, licence, size, format,
real or synthetic, request vs payload, labels, headers / path / query / body, multi-label,
source metadata, sessions, timestamps, deduplication, methodology, leakage, limitations,
fit): [`external_datasets.json`](external_datasets.json). Nothing was integrated.

| Dataset (primary source) | Licence | Traffic | Unit | Headers | Labels | Multi-label | Notable coverage | Classification |
|---|---|---|---|---|---|---|---|---|
| **SR-BH 2020** (Harvard Dataverse, doi:10.7910/DVN/OGOIXX; Comput. Secur. 2022) | CC0 1.0 | real, honeypot (1 WordPress site), 12 days | 907,815 rows: request fields + response fields | subset: Cookie, Referer, Origin, Content-Type, … — **no Authorization / Content-Length / Transfer-Encoding** | 13 CAPEC + Normal, CRS-derived, reviewed | **yes**: 9,238 rows ≥ 2 attack labels (2.4% of attacks) | smuggling 1,059, response splitting 19,738, verb tampering 5,437 | training (separate experiment), rare categories, multilabel research |
| **ECML/PKDD 2007** (LIRMM; Raïssi et al. 2007) | none stated | traffic from Bee Ware, attacks "constructed blindly", values sanitized (secondary) | full requests (XML) | yes, attack location can name a header | 7 attack types + Valid, `inContext`, attack interval | format: one type; paper: a sample "can target several classes" | LDAP, XPath, SSI | evaluation only, rare categories, header-based |
| **OWASP CRS regression tests** (coreruleset @ 8e78e03) | Apache-2.0 | synthetic rule fixtures | full requests (YAML), 10 raw | yes | CRS rule ids | no (1 stage of 5,120 tests) | protocol attacks, response splitting, smuggling, header injection; 1,018 benign stages | evaluation only, header-based, rare categories |
| **Thirty-Day ModSecurity** (Zenodo 10.5281/zenodo.17178461; Data 2025) | CC BY 4.0 | real production, anonymized | 142,705 full audit-log transactions | **all**: Authorization 40, Transfer-Encoding 20, Cookie 5,367 | CRS rule ids + tags | multi-rule: 8,194 with ≥ 2 families (5.7%) | lfi, protocol; **no benign** | evaluation only, header-based, multilabel research |
| **ModSec-WP** (Zenodo 10.5281/zenodo.21872151) | CC BY 4.0 | testbed, real plugin CVEs replayed | 108,883 rows: request line + body | only Host / User-Agent | 6 classes, single | no | File Inclusion = LFI + RFI + path traversal; WAF verdict columns (leak) | evaluation only |
| **GoTestWAF** (wallarm @ 8ed7bc2) | MIT | synthetic generator | 168 payloads × placeholders | `Header`, `UserAgent` placeholders | category per file | no | CRLF, LDAP, NoSQL, SSI, SSTI, mail | evaluation only, rare categories |
| sqliv5 (GitHub) | MIT | SQLiV3 + WAF-A-MoLE mutations | payloads | no | binary | no | SQLi evasion | evaluation only (E6 / D15 suite) |
| CSIC 2010 | unverified | generated, 1 app | full requests | yes | Normal / Anomalous | no | — | **not recommended** — already a V4 source |
| CSIC TORPEDA 2012 | unverified | generated | full requests (secondary) | yes (secondary) | 10 classes (secondary) | unverified | CRLF, SSI, LDAP, XPath | **not recommended** — primary source unreachable, unverifiable |
| HttpParamsDataset | MIT | CSIC 2010 values + tool payloads | parameter values | no | 5 types | no | — | **not recommended** — CSIC overlap, no request |
| FWAF | none | unknown | query strings | no | good / bad | no | — | **not recommended** — no licence, no provenance |
| Kaggle SQLi / XSS (Hussain) | unverified | compiled | payload strings | no | binary | no | — | **not recommended** — provenance and licence unverified |
| YangYang-Research web-attack-detection (HF) | MIT (card) | unstated | mixed | partial | binary | no | — | **not recommended** — sources unstated, likely V4-source overlap |
| H23Q (Comput. Secur. 2022) | unverified (paper CC BY 4.0) | lab | HTTP/2-3, QUIC flows | in pcaps | per flow | no | smuggling (HTTP/2) | **not recommended** — wrong protocol layer |
| CIC-IDS2017 (UNB) | research use, citation | lab | flows | in pcaps | per flow | no | 3 web attacks | **not recommended** — flow-level |
| Small payload lists (e.g. SunnyThakur25) | MIT | curated | 300 payloads | no | 4 types | no | — | **not recommended** — tiny |

**Answers.**

- **Worth a later inspection:** SR-BH 2020 (training-side experiment); ECML/PKDD 2007, CRS
  regression tests, the Thirty-Day ModSecurity set and GoTestWAF (evaluation).
- **Scarce V4 categories:** smuggling and response splitting (SR-BH, CRS), LDAP / XPath / SSI
  (ECML/PKDD, GoTestWAF), CRLF / NoSQL / SSTI (GoTestWAF).
- **Headers:** the Thirty-Day ModSecurity set (all headers as received), CRS tests and
  ECML/PKDD; SR-BH keeps only a header subset.
- **JWT:** none. No public labelled JWT-attack dataset was found; CRS has 5 test descriptions
  mentioning JWT.
- **Request smuggling:** SR-BH labels CAPEC-33 but drops the framing headers that constitute
  it; CRS has a handful of raw framing tests; H23Q is HTTP/2. No HTTP/1.1 request-level set
  with framing headers was found.
- **Multilabel:** SR-BH 2020 (annotated) and the Thirty-Day set (multiple CRS rules).
- **Too synthetic for training:** CRS tests, GoTestWAF, ECML/PKDD (blind attacks, sanitized
  values).
- **Leakage risk:** CSIC 2010 and anything derived from it (HttpParamsDataset), sets of unstated
  origin, CRS-derived labels (D9), response or WAF-verdict columns as inputs.
- **Strong provenance:** SR-BH 2020, Thirty-Day ModSecurity, ModSec-WP (DOI deposits with
  methodology), CRS tests and GoTestWAF (versioned repositories).
- **Do not use:** the nine marked not recommended.

**Future integration — flow only, no decision taken:**

```
external dataset → source / licence validation → schema normalization (to D1 text)
  → deduplication (and against V4-clean, External v1, real-http-fp-v1) → leakage analysis
  → taxonomy mapping → separate experiment → explicit decision about integration
```

Never `external dataset + V4-clean → training` without that explicit decision.

## 14. Impact of the survey on D46–D53

**Facts.** Real multi-label annotation exists (SR-BH 2020: 9,238 of 382,620 attack rows, 2.4%;
the Thirty-Day set: 5.7% of transactions with ≥ 2 CRS families), but both label sets derive
from CRS detections and use taxonomies (CAPEC, CRS families) different from V4's. No dataset
provides labelled JWT attacks. One independent dataset (ModSec-WP) groups LFI, RFI and path
traversal into one family. The datasets with full headers are evaluation-type (rule fixtures,
blocked-only traffic) or keep only a header subset.

**Interpretation.** Multi-label requests are real but rare and, where labelled, rule-derived —
not a basis for a multilabel Analyzer trained on V4-clean. The JWT blind spot cannot be closed
with public data. The DT / FI merge is consistent with independent practice. External data
could later strengthen rare categories and evaluate header-borne attacks.

**Decision. No — no dataset found justifies changing D46–D53.** `hybrid_analyzer_v1` stays
V4-clean-only. Multilabel stays a future research question.

## 15. Future dataset candidates

Separate experiments, each after the section 13 flow and only after `hybrid_analyzer_v1`
results exist:

1. **SR-BH 2020 → candidate `hybrid_analyzer_v2` experiment:** dedup (378,627 distinct
   method / target / body of 907,815), drop response fields, CAPEC → Analyzer mapping, compare
   against v1 on v1's INTERNAL TEST; also the natural place to study multilabel.
2. **Header-borne evaluation set:** CRS regression tests (protocol attack family) + the
   Thirty-Day ModSecurity set, to measure what RequestFeatures v2 cannot see — the evidence any
   future decision about header features (JWT, smuggling, CRLF) would need.
3. **Rare-category evaluation:** ECML/PKDD 2007 and GoTestWAF for LDAP, XPath, SSI, CRLF, NoSQL.

None of these is needed before building `hybrid_analyzer_v1`.

## 16. Criteria for closing Phase 2A

- [x] D46–D53 recorded in `DECISIONS.md`; Phase 2A labels mapped to them
- [x] `AnalyzerOutput` contract formalized (D50) and tested
- [x] Exact group definition, VALIDATION rule and INTERNAL TEST views documented and
      checked for grouping problems (section 6)
- [x] V4-clean numbers reproducible (`analysis.json`, byte-identical reruns)
- [x] External Dataset Survey documented with primary sources and measured evidence; impact
      assessed; no integration
- [x] No dataset, model, V4, gateway, enforcement or External v1 change
- [ ] Owner review and commit (then close #51; Phase 2B gets its own issue)
