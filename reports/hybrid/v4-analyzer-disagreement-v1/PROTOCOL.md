# V4 ↔ Analyzer disagreement diagnostics — protocol (`v4-analyzer-disagreement-v1`)

**Type: DIAGNOSTIC on development data.** Issue #57. Written on 2026-10-05, before the frozen Analyzer
scored any case listed here and before the V4 re-run in §3.2. It studies failures and
complementarity; it is **not** an evaluation, not an independent external test, and it fixes **no**
ALLOW / BLOCK / UNCERTAIN policy, threshold or calibrator. 0.5 appears only as the D55 reporting
convention. No model is trained or re-calibrated. Every count below is a diagnostic count on a
composition chosen by its authors: never an FPR, recall, prevalence or operational rate (D42,
methodology §7).

## 1. Questions

1. When V4 blocks a benign request, what does the Analyzer say?
2. Are there benign requests both treat as attacks?
3. Are there attacks V4 blocks that the Analyzer scores low (and the reverse)?
4. Which cases are outside what RequestFeatures v2 can observe (D44)?
5. What data are missing to estimate whether a cascade would rescue V4 false positives without
   letting more attacks through?

## 2. Sources and roles (inventory)

| # | Source | Labels | V4 decisions | Role for the Analyzer | Used here |
|---|---|---|---|---|---|
| S1 | `reports/diagnostics/real-http-fp-v1/` — 175 cases / 149 unique texts, all benign by construction (`cases.jsonl` `b60bafba…`, `results.jsonl` `03e1c78a…`) | `expected_label = ALLOW` | recorded: 149 texts × 3 direct calls, deterministic 3/3 (`results.jsonl`, phase `direct`) | never fitted, selected or evaluated on; checked for collisions by External v1's gate | **yes, except family `EVALSWAP`** |
| S1-x | `EVALSWAP` family of S1 (30 cases from 10 V4-clean **eval** rows) | ALLOW | recorded | V4-clean eval = Analyzer **INTERNAL TEST**; `Host` is not a feature, so its variants have the eval rows' vectors | **no** — scoring them would be a third look at INTERNAL TEST rows (D54) |
| S2 | Legacy 135-case manual suite, `scripts/evaluation/test_model.py` (`0cc3983f…`), literal lists `SYSTEMATIC_CASES + ADVERSARIAL_CASES + FALSE_POSITIVE_CASES` (JSON SHA-256 `7715c92a…`, identical to commit `2a188aa` used for the stored V4 run); 109 BLOCK / 26 ALLOW, 135 unique texts | hand-authored per case | **not stored per case** — only per-category counts (`reports/v4_clean_manual_diagnostic.json`, `bf378634…`: TP 104 · FP 6 · FN 5 · TN 20) → one deterministic V4 **re-run** (inference only, §3.2) | not fitted or selected on; overlap with TRAIN ∪ VALIDATION measured (§4) | **yes** |
| — | V4-clean train / Analyzer TRAIN ∪ VALIDATION | yes | none per row | fitted / selected | no (never independent evidence of false negatives) |
| — | V4-clean eval / Analyzer INTERNAL TEST (per-row V4 decisions exist: `reports/benchmarks/baseline-local-v1/*.samples.jsonl`) | yes | yes | INTERNAL TEST, read twice; D54 authorizes exactly one second look | **no** — a third look needs an owner decision |
| — | External Test v1, its runs and capture files (`datasets/external_v1/`, `reports/external/`, `docker/.lab-logs/`) | — | — | one aggregate evaluation done (D53) | **forbidden**: only published aggregates are cited, as a risk signal |
| — | Phase 1 live fixtures (11 hand-written requests, 4 attacks) and Docker smoke fixtures | yes | in logs only | none | no (too small; decisions only in logs) |

## 3. V4 decisions

**3.1 S1:** the recorded `direct` phase of `real-http-fp-v1` (`model-output-v4-clean`, adapter
`7bf16875…`). Per unique text, the decision of repetition 1; repetitions 2–3 must agree (they did
in the original run, 149/149) — any disagreement is reported, never resolved by vote.

**3.2 S2:** one re-run of the 135 manual cases with the current V4 runtime
(`control_plane/inference_core.py` `325e3149…`: `load_model`, `classify_raw`, `parse_prediction`) —
an **equivalent refactored runtime** of the `test_model.py` code at `2a188aa` that produced the stored
run (same prompt, nf4 / bf16 loading, greedy decoding, `max_new_tokens = 40`, inspected by the
audit; greedy decoding is the `inference_core` contract) — adapter `model-output-v4-clean`,
`adapter_model.safetensors` `7bf16875…`, in the ML environment, in suite order, once. Recorded per case: decision, reason, status. The
per-category correct counts and the confusion counts must reproduce the stored diagnostic
(`v4_clean_manual_diagnostic.json`); a mismatch is reported as such and nothing is re-run to "fix"
it. Matching counts cannot detect swaps between cases of the same label and category, so the
**per-case decisions are those of the re-run**, not a claim about the stored run. Invalid outputs
are kept as invalid (E5), never coerced.

## 4. Analyzer inference and relations

- Artifact `model-output-hybrid-analyzer-v2/recommended.pkl`, SHA-256 `79eb7265…` verified before
  unpickling, never written; `.venv-analyzer` (scikit-learn 1.9.1). Per text: `attack` and the 8
  category probabilities, from `request_features.extract_features(text)` (v2, 34 features).
- Relations, as at the v2 build: feature vector = the 34 values (`vector_hash`); D51 canonical
  request = `canonical_key("{method} {path}?{query}\n{content_type}\n{body}")`. For every scored
  text: is its vector / canonical request in Analyzer **TRAIN ∪ VALIDATION** (fitted rows; JWT rows
  reported separately)? in **INTERNAL TEST**? Is its exact text in V4-clean train or eval?
- **What counts as a "look" at INTERNAL TEST (revision 1):** Analyzer output joined with INTERNAL
  TEST labels or row identities. Because the Analyzer's output depends only on the feature vector, a
  scored text that shares a vector with INTERNAL TEST rows receives exactly their score; that alone
  is not a look, provided no INTERNAL TEST label, target, V4 metadata or row id is read. Hence:
  EVALSWAP stays excluded (its texts *are* eval rows with their eval label); texts that only share a
  vector / canonical request with INTERNAL TEST are scored and **flagged**; the membership loader keeps
  only `role`, `slice`, `meta_feature_vector_sha256`, `meta_canonical_request_sha256` (plus
  `row_id` for TRAIN / VALIDATION rows, for the canonical-relation self-check) and outputs booleans. Cases whose vector or canonical request is in
  TRAIN ∪ VALIDATION are **seen** and reported separately; they are not evidence of how the
  Analyzer generalizes.
- Duplicates and groups (revision 1): V4's unit is the **unique text**; the Analyzer's unit is the
  **distinct feature vector** (it cannot tell texts with the same vector apart). Every
  Analyzer-side result is counted **per distinct vector first**, texts second. S1's 119 scored texts
  collapse to 8 vectors (counted from features only, before any scoring) — S1 texts are **not**
  independent observations for the Analyzer. A/B pairs of S1 (`pair_with`) are analysed as pairs;
  that every header-family pair (HOST, PORT, HDR, UA, UAxPC) keeps the same Analyzer score is a
  **tautology of D44**, stated here in advance, not a finding.

## 5. What is reported

- Per source: unique texts, distinct vectors, overlap counts (§4).
- **Cross-tables** label × V4 decision × Analyzer `attack` band. Bands are fixed here and are
  **descriptive only, not a policy and not tuned**: `[0, 0.1)`, `[0.1, 0.5)`, `[0.5, 0.9)`,
  `[0.9, 1]`; "extreme" = `< 0.01` or `≥ 0.99`. The `0.5` edge is the D55 reporting convention.
  No other cut is searched.
- S1: Analyzer score per family / group for V4-BLOCK vs V4-ALLOW texts; for every A/B pair, whether
  V4 flips and whether the Analyzer score changes; whether the varied variable lives in a header the
  Analyzer reads (only `Content-Type`) or in the path / query / body.
- S2: per category — V4 decision, Analyzer band, the D47 category head (top-1) vs the D47 mapping of
  the suite category (SQL Injection → `sql_injection`; XSS Injection → `xss`; Command Injection →
  `command_injection`; Path Traversal and File Inclusion → `path_file_access`; SSTI → `ssti`; Open
  Redirect → `open_redirect`; SSRF → `ssrf`; LDAP, XXE, GraphQL, NoSQL, Insecure Deserialization,
  HTTP Request Smuggling, CRLF, HTTP Parameter Pollution, XPath, CSRF → `other_attack`; JWT Attacks
  → none, D48; Adversarial BLOCK cases by the leading words of their description: "SQL" →
  `sql_injection`, "XSS" → `xss`, "Path traversal" → `path_file_access`, "Command injection" →
  `command_injection`, "SSTI" → `ssti`).
- **Signal location** (fixed before scoring, from the category definitions and the D44 feature
  contract): JWT Attacks and CSRF → **header-only** (Authorization; Origin / Referer); HTTP Request
  Smuggling → **header-dependent** (the conflict is between Content-Length / Transfer-Encoding
  headers; the body framing is visible); every other case → **surface** (path / query / body). For
  S1, families HOST, PORT, HDR, UA, UAxPC vary a header the Analyzer does not read; PATH varies the
  path. Every S2 text (benign or attack) is also tagged with its header names other than `Host` and
  `Content-Type` (e.g. a valid JWT `Authorization`, `X-Hub-Signature`, CSIC `User-Agent` / `Cookie`):
  content the Analyzer never reads.
- Extreme probabilities: cases with `attack < 0.01` or `≥ 0.99`, by label and V4 decision; distinct
  vectors shared by texts of different labels.
- Category head: top-1 agreement on S2 attacks with a D47 mapping; category on benign texts that V4
  blocks vs V4's reason — **context only (D46)**: several suite labels do not map cleanly (e.g. an XSS
  and an Open Redirect case are both `javascript:` URLs; an XXE case targets 169.254.169.254; a GraphQL
  case carries `UNION SELECT`).
- Per-case records of S1 and S2 (texts, labels, V4 decision, Analyzer outputs) are written to the
  report: both are development / diagnostic data already in the repository. Measured results,
  examples and hypotheses are kept in separate sections.

## 6. Conclusions this diagnostic cannot support

- Any FPR, recall, precision or prevalence (D42); any operational threshold or policy.
- Any estimate of false-negative risk on real or external traffic: S2 has ≤ 5 cases per attack
  category, is hand-authored, partly overlaps training payload families, and its adversarial
  transforms reuse training augmentation; S1 has no attacks.
- That a cascade would or would not rescue V4's false positives in general, or on External v1.
- Any cause of V4's decisions beyond "this variable changed and the decision changed in this
  context" (methodology §8).
- Anything about External v1 beyond its published aggregates.
- Analyzer robustness / invariance to Host, port, User-Agent or other headers: it holds by
  construction (D44).
- Any count over texts presented as independent Analyzer evidence (e.g. "k / 37 false positives
  rescued"): S1 texts collapse to 8 vectors.
- Any band edge (0.1, 0.5, 0.9) as a candidate operating point, or "the Analyzer would allow": the
  policy is set later, with the Small Decision Model (D55).
- Probabilities on S1 / S2 read as calibrated confidence or prevalence (D50: learned on the 50 / 50
  V4-clean construction).
- Seen-vs-unseen differences read as memorization or overfitting (D42).
- Any finding about JWT or CSRF detection by the Analyzer: blind by construction.
- Anything about INTERNAL TEST performance, including texts that share a vector with it.
- Per-case equality between the S2 re-run and the stored legacy V4 run.

## 7. Guards

- The analysis code refuses by construction to open any path under `datasets/external_v1/`,
  `reports/external/`, `docker/.lab-logs/` or `reports/hybrid/analyzer-external-v1-run-001/`.
  External v1's published aggregates are cited in the report text only; the code reads none of it.
- Model 1 is used read-only; its hash is checked before and after. V4's adapter is used read-only.
- Outputs never overwrite: the report folder's result files are created exclusively.

## 8. Data-role consequences and revisions (recorded before scoring)

- **Role change (D37):** once their per-case errors are studied here, S1 and S2 become **Hybrid
  error-analysis / development data**. They cannot later serve as independent evidence for a cascade or
  a Decision Model.
- S2 was never part of External v1's collision gate (which checked V4 train / eval, `real-http-fp-v1`
  and the smoke fixtures); its overlap with External v1 is unknown and is **not** checked, because that
  would require opening External v1.
- Any Analyzer revision prompted by issue #57 cannot be re-measured on INTERNAL TEST, which had its one
  second look (D54); that needs an owner decision.
- **Revision 1 (before any scoring), after the independent data-roles audit:** definition of a "look" at
  INTERNAL TEST and a reduced membership loader (§4); per-vector-first counting and the D44 tautology
  stated in advance (§4); §3.2 wording (equivalent refactored runtime; per-case decisions from the
  re-run); header tags on every S2 text (§5); category caveats (§5); eight additions to §6; §7 guard
  wording; this section.
