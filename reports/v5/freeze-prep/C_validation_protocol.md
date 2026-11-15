# V5 dataset freeze preparation — Workstream C: experimental validation and reproducibility

> **Dated note (2026-10-12).** Superseded where it differs by **D60** and V5 DRAFT r3 §4.6, §7 and §9. Adopted: TRAIN 70 / VALIDATION 10 / INTERNAL TEST 20; a single sealed `STAB-HELD` (no `STAB-DEV`); evaluability per D60 (≥ 100 payload families, ≥ 30 in INTERNAL TEST); the E6 reserve. This protocol is kept unchanged as historical evidence.


Issue #64. Date: 2026-10-11. Branch at writing: `research/v5-data-spec-freeze-prep`, clean tree at start.
Status: **PROPOSAL for owner review. Not a decision, not frozen, nothing executed.** No model was run or
trained, no dataset was generated, no existing file was modified. Companion file:
[`consumed_sets.json`](consumed_sets.json) (machine-readable inventory; every path and every SHA-256 in
it was verified on disk on 2026-10-11).

Labels used throughout: **FACT** (cited file, report or decision ID), **INFERENCE** (reasoned from facts),
**PROPOSAL** (a design choice for the owner). Any number marked **PROPOSED** is a candidate threshold
with a stated rationale; none is approved. The names `B:duplicates`, `B:group_disjoint`,
`B:label_consistency`, `B:manifest_sha`, `B:protected_collisions` are descriptive labels for the five
check families that Workstream B implements in `scripts/dataset/v5_dataset_checks.py`. *(Coordinator
note, 2026-10-11: they map to `find_duplicates`, `check_group_disjointness`, `check_label_consistency`,
`verify_manifest` and `check_protected_collisions`; the last returns counts and candidate row indices
only, which satisfies the L7a counts-only guard.)*

---

## 1. Inventory summary

Full list: `consumed_sets.json` (19 entries). Summary by role.

| Group | Sets | Rows | Individual cases already influenced V5 design? | Allowed use for V5 |
|---|---|---:|---|---|
| V4 training data | `v4_clean_train` (`datasets/v4_clean/train.jsonl`, text key `input`) | 25,134 | YES, at distribution level (benign coverage audit, evidence matrix rows 6, 10-12) | collision gate; reuse as V5 source NOT decided |
| V4 validation / internal eval | `v4_clean_eval` (text key `input`); `hybrid_analyzer_v1/v2` (features and hashes only, no text) | 6,206; 31,340 | NO for eval rows (audit and probes "never opened" it); 10 eval rows were reused as EVALSWAP in `real-http-fp-v1` | collision gate; its generator groups stay out of every V5 split |
| Development / error-analysis (consumed) | `real_http_fp_v1` (175 cases, 149 unique texts), `v4_analyzer_disagreement_v1` (254), `legacy_manual_suite_135`, `paired_dev_v1` (434 records, 355 unique texts) | | YES | collision gate (exact, canonical, payload) |
| Development diagnostics (probes) | `minimal_pair_probe_v1` (2,120), `minimal_pair_probe_v2` (590) | | YES (their findings are the V5 spec) | collision gate plus element-level value-pool disjointness |
| Audits and design docs | `benign_coverage_audit_v1`, `v5_design_documents` | no texts | YES | concept level only |
| External Test v1 | `external_v1_frozen` (400, text key `request_text`), `external_v1_prefreeze_pool` (candidates and 84 reserves), `external_v1_execution_and_capture_artifacts`, `external_v1_aggregate_reports` | 400 | NO for individual cases; aggregate-level only | collision gate in counts-only mode; never TRAIN/VAL/TEST/tuning; aggregates concept level |
| Other protected texts | `docker_smoke_fixtures`, `historical_root_corpus` (99,132 rows, key `input`), `csic_database_csv` (61,065 rows) | | NO | collision gate / CSIC-ancestry warning |

FACT, text-field verification: `input` (V4-clean and the historical corpus), `text` (real-http-fp-v1, #57
records, probes, #59 records), `request_text` (#59 `cases.jsonl`). For External v1 the key
`request_text` was taken from documentation and code only, by design (D40): `docs/external_test_v1_protocol.md`
lines 19 and 58, `datasets/external_v1/README.md` line 41, `scripts/external/freeze_external_v1.py` lines
62 and 121, `scripts/external/label_candidates.py` line 93, `scripts/external/capture_addon.py` line 89.
The Analyzer datasets have no text key (they hold `meta_canonical_request_sha256`,
`meta_feature_vector_sha256` and, in v2, `meta_generator_group_id`); they add nothing to text-level
collision checks because they derive 1:1 from V4-clean.

FACT, storage: `datasets/v4_clean/*`, `datasets/hybrid_analyzer_v1/*` and `v2/*` are gitignored and pinned
only by manifest SHA-256 (`datasets/manifest_v4_clean.json`, `manifest_hybrid_analyzer_v*.json`); the
probes, `real-http-fp-v1`, #57 and #59 files and External v1 are tracked. `docker/.lab-logs/` (raw captures)
is gitignored.

INFERENCE: **every set that is not External v1 and not V4-clean is already development data for V5.**
The collision gate must therefore treat them all as "exact or canonical collision = rejection" for every
V5 split. Only V4-clean TRAIN gets a softer rule (see §4.2, L7), because reusing it as a source is an open
question.

---

## 2. D40 status of External Test v1

**FACT: the D40 tripwire is NOT triggered as of 2026-10-11.**

Evidence, in order of weight:

1. The tripwire definition is in `datasets/external_v1/manifest.json` (`d37_tripwire`): it fires "the
   moment individual External v1 errors are used to develop/train/select V5". D40 also requires a
   *separate* record of the transition beside the set; **no such record exists** (searched
   `datasets/external_v1/` and `reports/`; the manifest is unedited since `36df2ee`, 2026-09-21, per
   `git log`).
2. `CONTEXT.md` section 0.6: External v1 "executed once for V4 (aggregate + per-cell) and once for the
   frozen Model 1 ... Individual cases not inspected; doing so triggers D40 / D45". Known primary
   limitation: "no individual External v1 false positive has been inspected for model-improvement
   decisions".
3. Every V5-side artifact states it did not open External v1:
   `reports/v5/benign-coverage-audit-v1/README.md` ("Never opened", enforced by a code guard);
   `reports/v5/minimal-pair-probe-v1/README.md` line 21; `reports/hybrid/v4-analyzer-disagreement-v1/README.md`
   section 1; `reports/hybrid/v4-analyzer-paired-dev-v1/README.md` (overlap "UNKNOWN", never checked);
   `reports/hybrid/analyzer-external-v1-run-001/README.md` (aggregate only, output scanner rejects case ids).
4. DECISIONS.md D43 states the tripwire was untriggered after Phase 1; D53 and D54 reaffirm External v1
   unused.

What has already been done with it (permitted, does not consume it, D40 first sentence):
V4 run-001 (L1 TP 199, TN 132, FP 68, FN 1; `reports/external/external-v1-run-001/summary.md`),
secondary breakdowns, and one aggregate evaluation of the frozen Analyzer (D53).

**Caveat (INFERENCE).** "Not inspected" rests on the repository's self-statements; a negative cannot be
proven from files. Aggregate-level influence exists: the V5 priorities (benign JSON stability, API and
unseen-structure traffic) are consistent with the published aggregate FP concentration, and
`reports/v5/research-notes-v2/C2_analyzer_v3_spec.md` cites the Analyzer's External v1 ECE. D40 permits
this, but the V5 report must disclose it.

**Implications for V5 evaluation (PROPOSAL, grounded in D37, D39, D40, D45, D53):**

| If | Then |
|---|---|
| Branch P: nobody inspects an individual External v1 case or error before the V5 checkpoint, hyperparameters and any thresholds are frozen | External v1 may receive **one** aggregate-only V5 run (D53 analogue: pre-registration, `--confirm-single-run`, exclusive `run_attempt.json`, output scanner). A V4-vs-V5 comparison on it is valid but carries v1's disclosed limitations: no proxy-to-`/classify` byte evidence, no CSIC-ancestry check, 50/50 construction (D42), one lab application. |
| Branch C: any individual v1 case or error is inspected to guide any V5 change (data, prompt, model, threshold, checkpoint) | v1 becomes V5 development data; record date and transition beside the set in a new file (manifest untouched, D39); **no external V5 claim without External v2**; a V4-vs-V5 comparison on v1 must be labelled "on V5 development data". |
| Either branch | v1 is never TRAIN, VALIDATION, INTERNAL TEST, checkpoint, threshold or generator-design input. V5 data is collision-gated against all of `external_v1_*` in counts-only mode (§4.2, L7a). Hybrid components follow the same rule (D45). |

PROPOSAL: build External v2 regardless of branch (prerequisites §6.6). Reason: V5's stated purpose is
fixing benign FPs, which creates constant pressure to open v1's FPs; v1 lacks the two checks D40 added;
and a fresh external set is the only thing that supports "V5 generalizes better than V4" (§6.5). This is
open owner decision 1.

---

## 3. Partitioning strategy

### 3.1 Facts that constrain the design

- D37: four roles; VALIDATION "a grouped split carved from training groups"; INTERNAL TEST "only ever reported".
- D16: split by logical identity **before** rendering (source sample, group identity, split, rendering, derived variants).
- `docs/ml_evaluation_methodology.md` section 1: V4 eval groups stay out of V5 TRAIN or the V4 eval can no longer compare versions.
- V5 draft spec section 4: grouping `provider_family` -> `template_id` -> `family_id` -> value draw; each attack twin shares all keys with its benign row; leave-provider-out then purge.
- B2 `reports/v5/research-notes-v2/B2_datasets_followup.md` lines 134-136: **only GitHub and Stripe are confidently MIT**; "Leave-provider-out with two groups is degenerate for validation plus test".
- Probe manifests: `data_role: ... never copied into a V5 generator`; `pools_sha256` recorded for 18 (v1) and 17 (v2) pools.
- Precedent for stratified, hash-ordered, order-independent group carve-outs: D54 (VALIDATION ~20% by stratum, `sha256(salt NUL group_key)` order).
- Precedent for the largest group size: hybrid v1 manifest, 18,720 groups, largest 417 rows of 31,340.

### 3.2 Recommended option (PROPOSAL): family-level grouped split, provider as a stratum, not a holdout unit

"Option A". The simplest defensible choice with two licensed providers.

1. **Unit** = `family_id` (union-find component over identical or near-duplicate structure, the coarsest
   key that exists for every source). `template_id`, `pair_id`, `value_draw_id` are nested inside it and
   inherit its split automatically. Attack twins are generated *from* the benign row's `family_id` and
   `pair_id`, so a pair cannot straddle splits by construction (checked by M2).
2. **Assignment** before any rendering (D16): `bucket = int.from_bytes(sha256(b"v5-split-v1" + b"\0" + family_id)[:8], "big") % 10000`.
   PROPOSED target shares: INTERNAL TEST 15%, VALIDATION 15%, TRAIN 70% of `family_id`s. Hash order with a
   D54-style stratified greedy completion over strata (`provider_family` x family-concept x carrier), so
   every HIGH family reaches the minimums in §4.5 (C1). Where a stratum is too small, move whole families
   to evaluation until the minimum holds; never shrink the minimum. Deterministic, independent of
   `PYTHONHASHSEED` and input order (check A3). The salt and the function are frozen in the preregistration before any model output exists.
3. **Value pools are partitioned, not shared.** Each pool element (names, streets, handles, paths,
   hosts, synonyms) is assigned to exactly one split by `sha256(b"v5-pool-v1" NUL pool_id NUL element) % 100` (<70 / <85 / rest), and rows draw only from their split's partition. Attack payload canonical
   strings (`parse_dataset_v4.canonical_key`) get the same treatment, so a payload cannot be TRAIN in one
   family and TEST in another. Dominant tokens (B2: `octocat`, `rg1`) are removed or placed on both sides
   of the pair. Hosts follow the same rule (reserved RFC 2606 names only) and must also be disjoint from
   the lab hosts `*.fwlab.test` used by the dev sets. Minimum partition size per pool: PROPOSED 20
   elements per split, rationale: below it a single element exceeds the 1% dominance WARN in §4.4 (S7).
4. **Probe disjointness.** All V5 pools are built fresh from the neutral lexicon and must share **no
   element** with the 18 + 17 probe pools (element-level, not hash equality, see §4.2 L8).
5. **Near-duplicate purge** (backstop; union-find should already have merged these): run in order exact
   -> `canonical_key` -> template-hash (values replaced by class tokens) -> token-shingle Jaccard >= 0.60
   (External v1 gate precedent, `scripts/external/phase_d_gate.py` `NEAR_DUP_THRESHOLD`). Cross-split hits
   at the first three levels are a freeze failure (BLOCK). Jaccard hits are resolved by merging the two
   components and re-assigning (never by deleting evaluation rows), then re-running all checks. If a purge
   is unavoidable, delete from TRAIN only and record counts; evaluation rows stay stable.
6. **Reporting views.** INTERNAL TEST gets a full view and a payload-novel view (attack payloads absent
   from V4-clean train), following the D51 feature-disjoint precedent, so the V4 comparison is not
   flattered by shared PayloadsAllTheThings payloads.
7. **Provider-aware diagnostic, not a claim.** Report every metric per provider. INFERENCE: with two
   providers every split contains both, so INTERNAL TEST measures generalization to **unseen structural
   families of seen providers**, not to unseen providers. The report must say so; only External v2 supports
   cross-source claims.

### 3.3 Alternatives

| Option | Description | Verdict |
|---|---|---|
| B. Leave-provider-out | whole providers to VALIDATION and INTERNAL TEST (draft spec section 4) | **Not viable now**: two licensed providers give TRAIN = 1 provider and no VALIDATION. Becomes the preferred INTERNAL TEST design if >= 5 licence-verified providers exist (PROPOSED: >= 3 TRAIN, >= 1 VAL, >= 1 TEST). Then provider disjointness becomes BLOCKING in check L4. |
| C. Leave-template-out | `template_id` as the unit | Weaker than A: templates of one provider share naming and serialization style, so style leaks across the split (B2 residual risk 3.3). Rejected. |
| D. Family split plus provider-transfer rotation | A, plus two extra trainings (train on GitHub, test on Stripe and vice versa) as non-gating diagnostics | Cleanest measurement of provider shift with current sources; costs two extra QLoRA runs. Optional, report-only, owner choice. |
| E. Random row split | rejected: reproduces the F2 leakage (26.65%, D16) | Rejected. |

### 3.4 Roles in V5 (PROPOSAL, extends D37)

| Role | Set | Notes |
|---|---|---|
| TRAIN | 70% of V5 families | |
| VALIDATION | 15% of V5 families + `STAB-DEV` | checkpoint, hyperparameter and development decisions |
| INTERNAL TEST | 15% of V5 families + `STAB-HELD` | read once, after freeze (§6.3) |
| EXTERNAL TEST | External v2 (or v1 under Branch P) | §6.5 |
| Development / error analysis | paired dev v1, probes v1/v2, `real-http-fp-v1`, #57 records, manual suite | open for error analysis; never evidence for a claim |

---

## 4. Dataset acceptance criteria (pre-training freeze gate)

All checks run **before any model sees the data**, so their outcomes cannot be steered by model output
(D38 spirit). **BLOCKING** = any failure rejects the dataset version (§5). **WARNING** = resolved in
writing before freeze. Threshold status: "E0" = taken from `scripts/dataset/check_dataset.py` constants
(FACT); "Prec." = from another cited precedent (FACT); "PROPOSED" = this document.

### 4.1 Integrity and reproducibility

| ID | Check | PASS condition | Class | Threshold status and rationale |
|---|---|---|---|---|
| A1 | Manifest and shard SHA-256 (`B:manifest_sha`) | every shard SHA-256, row count and the aggregate integrity hash equal the manifest; manifest `status: FROZEN` only after all other checks pass | BLOCKING | Prec. D38/D39, External v1 manifest |
| A2 | Byte-identical regeneration | generator run twice in fresh processes from the same seed, pinned inputs and clean tree, with two different `PYTHONHASHSEED` values and a changed working directory: every shard and the manifest hash identically (timestamps live in a separate unhashed metadata file) | BLOCKING | Prec. `docs/data_sources.md` (V4 verified bit-identical under four `PYTHONHASHSEED` values); D54 accepts a regeneration only if byte-identical |
| A3 | Split-function determinism | permuting input order and `PYTHONHASHSEED` leaves the family-to-split map identical | BLOCKING | Prec. D54 |
| A4 | Source provenance | every source spec has a full 40-character commit SHA, file SHA-256, licence name and date checked; an unrecorded licence excludes the spec | BLOCKING | Prec. B2 section 5 |
| A5 | Checker self-test | each blocking checker fires on an injected violation of its own kind (one mutation per check) and passes on a clean fixture; unit tests green | BLOCKING | PROPOSED. Rationale: a checker that never failed is unverified (the Analyzer evaluator shipped 48 synthetic tests for the same reason) |
| A6 | E0 successor on the V5 files | `check_dataset.py` (or its V5 variant) exits 0 or 1, never 2 or 3 | BLOCKING | Prec. `docs/data_sources.md` ("must report WARNING with 0 blocking failures") |

### 4.2 Leakage

| ID | Check | PASS condition | Class | Threshold status and rationale |
|---|---|---|---|---|
| L1 | Exact duplicates across splits (`B:duplicates`) | 0 | BLOCKING | Prec. D16 outcome 0.00%; E0 `LEAKAGE_FAIL` is 1%, but D16 defines any overlap as a defect (`LEAKAGE_WARN = 0.0`) |
| L2 | Canonical duplicates across splits | 0 using `parse_dataset_v4.canonical_key` | BLOCKING | Prec. D16, D38 |
| L3 | Within-split duplicates | WARN if > 0 canonical duplicates; BLOCK if > 1% of a split | WARN/BLOCK | PROPOSED. Rationale: V4 reached 0.00% (D16); E0's own WARN is 10% (`DUP_WARN`), too loose for a generated set |
| L4 | Group disjointness (`B:group_disjoint`) | intersection across the three splits = 0 for `family_id`, `template_id`, `pair_id`, and each pool element (names, payload canon, host). `provider_family` is NOT required to be disjoint under Option A; report per-split provider counts. If Option B is later adopted, `provider_family` joins the BLOCKING list | BLOCKING | Prec. B2 section 4 leakage audit item 1 |
| L5 | Template-hash intersection | 0 across splits (hash after values -> class tokens) | BLOCKING | Prec. B2 section 4 item 2 |
| L6 | Token-shingle Jaccard cross-split | WARN for any pair >= 0.60; resolved by merging components and re-splitting (§3.2 step 5) | WARNING | Prec. `phase_d_gate.py` `NEAR_DUP_THRESHOLD = 0.60` |
| L7 | Protected-set collisions (`B:protected_collisions`) | per the `collision_policy` of each entry in `consumed_sets.json`: `BLOCK_ANY` = 0 exact and canonical collisions in the named V5 split; `REPORT_COUNT` = counted and published; `WARN_RULING` = logged manual ruling. Concretely: 0 against `v4_clean_eval`, probes v1/v2, paired dev, `real-http-fp-v1`, #57 records, manual suite, smoke fixtures and all `external_v1_*` in every V5 split; 0 against `v4_clean_train` in VALIDATION, INTERNAL TEST and the stability sets; TRAIN vs `v4_clean_train` counted only | BLOCKING | Prec. D38 step 3, D40 (External v2 gated against v1 and V5 dev data) |
| L7a | External v1 counts-only guard | the collision run against `external_v1_*` prints counts only: no case id, text or hash of a v1 case. A hit removes the V5 candidate; the v1 case is not looked at. Enforced by an output scanner like the Analyzer evaluator's | BLOCKING | PROPOSED. Rationale: surfacing a matched v1 case would be inspection and could start the D40 tripwire |
| L8 | Probe pool disjointness | for every V5 value pool and every probe pool (v1: 18, v2: 17), element-set intersection = 0; additionally V5 `pools_sha256` values are recorded and differ from all probe values. Pool contents come from the probe generator modules imported read-only (`scripts/evaluation/minimal_pair_probe_cases.py`, `minimal_pair_probe_v2_cases.py`) | BLOCKING | PROPOSED. Rationale: `pools_sha256` is a fingerprint; it proves equality or difference of a whole pool, not that two different pools share no element |
| L9 | V5 pools disjoint across V5 splits | 0 shared elements (value, payload, host pools) | BLOCKING | Prec. B2 section 4 table (`value_draw_id`) |
| L10 | Payload novelty (report) | publish per split the share of attack payload canonical strings present in `v4_clean_train`; WARN if > 50% in VALIDATION or INTERNAL TEST | WARNING | PROPOSED. Rationale: if most payloads were seen by V4, a V4-vs-V5 comparison on them is not about generalization |
| L11 | CSIC ancestry | payload substring screen of every V5 split vs `csic_database.csv` (SHA `c420f0bc...e44e637`); every hit needs a logged manual ruling | WARNING | Prec. protocol section 7 check 7 (WARN-level); required before freeze of External v2 (D40) |

### 4.3 Labels and pairs

| ID | Check | PASS condition | Class | Threshold status and rationale |
|---|---|---|---|---|
| M1 | Label consistency (`B:label_consistency`) | no canonical request carries two labels; labels in {ALLOW, BLOCK}; each BLOCK reason maps to the D47/V4 vocabulary | BLOCKING | FACT: CSIC-derived keyword labels were noisy (F6, D21); V5 must not inherit label conflicts |
| M2 | Pair integrity | 100% of attack rows have a benign twin in the same split sharing `provider_family`, `template_id`, `family_id`, `pair_id`; the value-masked template diff between twins is confined to the malicious slot | BLOCKING | Prec. draft spec section 4; #59 `pair_id` precedent |
| M3 | Class balance per split | share of BLOCK within [0.48, 0.52] PASS; WARN outside; BLOCK outside [0.45, 0.55] | WARN/BLOCK | PROPOSED. V4-clean is 3,103/3,103 in eval (D19); pairing makes 50% natural, so a deviation signals a generator defect |

### 4.4 Shortcut audits (E0 style)

| ID | Check | PASS condition | Class | Threshold status and rationale |
|---|---|---|---|---|
| S1 | Single carrier or envelope feature accuracy (method, content-type, carrier type, body syntax, param count, JSON shape and depth, path style, TE presence, serialization style, header set) on each split and within each family | margin over majority baseline < 0.03 PASS; WARN >= 0.03; BLOCK >= 0.10 or accuracy >= 0.80 | WARN/BLOCK | E0 constants: `SHORTCUT_ACC_FAIL 0.80`, `SHORTCUT_MARGIN_FAIL 0.20`, `SHORTCUT_ACC_WARN 0.65`, `SHORTCUT_MARGIN_WARN 0.10`. PROPOSED tightening: V4-clean's best feature was 51.16% against 50% (D20), and V5 is built symmetric, so E0's WARN margin (0.10) is promoted to BLOCK |
| S2 | Envelope value purity | no envelope value covering >= 1% of rows is >= 99% pure toward a label | BLOCKING | E0 (`PURITY_FAIL`, `PURITY_MIN_COVERAGE`) |
| S3 | Value-masked token purity (all tokens outside the value slot: keys, paths, glue words) | tokens covering >= 1% of rows: WARN at class purity >= 0.80, BLOCK at >= 0.95; `the`, `please`, `https` (evidence-matrix row 12) tracked individually, WARN at >= 0.70 | WARN/BLOCK | PROPOSED. Rationale: matrix row 12 found `the`/`please`/`https` benign-skewed (390/168/203) in V4 TRAIN; the 0.80 mirrors E0's absolute-accuracy FAIL |
| S4 | Structure-only probe (B2 section 4 item 3): a small logistic model on structure features only, fitted on TRAIN, scored on VALIDATION | accuracy <= 0.55 PASS, WARN > 0.55, BLOCK > 0.65 | WARN/BLOCK | PROPOSED. Rationale: chance is 0.50; 0.65 is E0's single-feature WARN level, here applied to the combined structure view. Calibrate once on the pilot (non-protected) build before the first VALIDATION look |
| S5 | Provider-identity probe | report only | REPORT | Prec. B2 section 4 item 4 |
| S6 | Carrier symmetry ratio, per family, per carrier-feature level covering >= 1% of the family: `r = min(n_ben, n_att) / max(n_ben, n_att)` | `r >= 0.80` PASS; WARN `0.5 <= r < 0.8`; BLOCK `r < 0.5` | WARN/BLOCK | PROPOSED. Rationale: `r = 0.8` means a level is 55.6% one class, `r = 0.5` means 66.7%, which is E0's 0.65 shortcut WARN; the draft spec (section 4) requires symmetry "when the concept allows" |
| S7 | Dominant element | no single value-pool element above 1% of any class in a split: WARN; above 3%: BLOCK | WARN/BLOCK | PROPOSED. Rationale: B2 names `octocat`/`rg1` as dominant tokens |

### 4.5 Counts and composition

| ID | Check | PASS condition | Class | Threshold status and rationale |
|---|---|---|---|---|
| C1 | Per-family minimum groups for the HIGH and MEDIUM-HIGH families of draft spec section 2 (encoded punctuation, apostrophes, street addresses, typed multi-key JSON, passwords with punctuation, external http(s) URLs, chunked envelope) | >= 100 `family_id`s in TRAIN, >= 30 in VALIDATION, >= 30 in INTERNAL TEST. Other families: shortfall is labelled INSUFFICIENT DATA, never inflated | HIGH families BLOCKING; others WARNING | Prec. D18 (`MIN_EVAL_SUPPORT = 30`), D47 (>= 30 rows and >= 100 groups), D14 (never inflate). Attack categories claimed in a report need >= 30 independent payloads in INTERNAL TEST |
| C2 | Largest group | largest `family_id` <= 2% of its split WARN above, BLOCK above 5% | WARN/BLOCK | PROPOSED. FACT anchor: V4 largest Analyzer group 417 rows of 25,134 train rows = 1.7% (hybrid v1 manifest) |
| C3 | Provider balance | each provider between 20% and 80% of each split (WARN); with 2 providers, the disclosure "leave-provider-out unavailable" is mandatory in the report | WARNING | PROPOSED |
| C4 | Held-out stability sets present and frozen | `STAB-DEV` and `STAB-HELD` (§6.4) generated, hashed, pool-disjoint from probes and from each other, committed before the first training step | BLOCKING | Prec. D38 (freeze before exposure) |

### 4.6 Hygiene

| ID | Check | PASS condition | Class | Rationale |
|---|---|---|---|---|
| H1 | Identity and secrets | all hosts are RFC 2606 / 6761 reserved; 0 vendor names, real hostnames, e-mail addresses or credential-like strings (pattern scan) in any row | BLOCKING | B2: normalise vendor identity; open-appsec excluded for credential-like strings (draft spec section 3) |
| H2 | Field-name special-casing | no generator rule keys on `address`, `password` or similar names | BLOCKING (code review) | Draft spec section 2 REJECT row; matrix row 2 |
| H3 | Raw framing bytes as ML text | none | BLOCKING | Draft spec section 2 REJECT row |

---

## 5. Rejection conditions

A V5 dataset **version** is REJECTED (not patched) when any of the following holds. Per D39 and the D54
precedent, a rejected version is preserved with its rejection report; the fix is a new version id, never an
in-place edit, and a defect found after any training has started means a new version and a retrain.

- R1 Any BLOCKING check in §4 fails.
- R2 Any exact or canonical collision with a `BLOCK_ANY` protected set in the named split, or any shared element with a probe pool.
- R3 Any cross-split overlap of `family_id`, `template_id`, `pair_id` or a partitioned pool element.
- R4 A label conflict, or a split attack row without its benign twin.
- R5 Regeneration from the recorded seed and pins is not byte-identical.
- R6 The split function, salt, strata or thresholds were changed after any model output on VALIDATION or INTERNAL TEST existed.
- R7 INTERNAL TEST, `STAB-HELD` or an External v1 or v2 case was opened or used for design before freeze (the set is consumed; record it, D37/D40).
- R8 A probe, paired-dev, `real-http-fp-v1` or External v1 text, template, field name or pool element appears in the generator inputs.
- R9 A source without a recorded licence or full commit pin, or a row with real identity or credentials.
- R10 Any BLOCKING checker lacks a passing self-test (A5).

Not a rejection but a mandatory disclosure: provider count below 5 (Option A used), aggregate-level influence
of External v1 (§2), WARNINGs that were resolved by ruling.

---

## 6. Training and evaluation protocol (post-freeze, not executed)

### 6.1 Order of operations (PROPOSAL)

1. Freeze the dataset (all §4 PASS, §8 report committed, manifest `status: FROZEN`).
2. Preregister: training configuration hash (base model, QLoRA settings, seeds, number of epochs), the **mechanical** checkpoint-selection rule on VALIDATION only (D54 style), the stability-gate criteria (§6.4), the metric set, and the evaluation order. Write `PREREGISTRATION.json` with file SHA-256s *before* any exposure and **commit it** (the Analyzer run's preregistration was not committed, a disclosed gap in `reports/hybrid/analyzer-external-v1-run-001/README.md`).
3. Train on TRAIN. Select the checkpoint with the preregistered rule on VALIDATION (and `STAB-DEV`).
4. Freeze checkpoint, thresholds and decoding configuration (D27). Write hashes.
5. Single read of INTERNAL TEST and `STAB-HELD` (§6.3, §6.4).
6. External evaluation (§6.5) only after step 5 and only under its own preregistration.

### 6.2 What VALIDATION is used for

Checkpoint selection, hyperparameters, early stopping, decoding configuration, development decisions
(D37). Error analysis for dataset or model change happens on VALIDATION and on the development sets listed
in §3.4, never on INTERNAL TEST, `STAB-HELD` or External. PROPOSED: at least 3 seeds for the final
configuration when budget allows; with a single seed the report says "single seed" next to every headline
number (V4 had one seed; `docs/ml_evaluation_methodology.md` section 3).

### 6.3 What INTERNAL TEST reports

Read once, after step 4, behind a single-run guard (`--confirm-single-run`, exclusive creation of
`run_attempt.json`, as in `analyzer_external_v1.py`). It reports, never selects:

- D19 metrics with BLOCK positive: TP, TN, FP, FN, invalid outputs (never coerced), accuracy, precision, recall, F1, FPR over the benign denominator, FNR over the attack denominator, each with numerator and denominator (D42).
- D18 evidence status per category; reason accuracy only over correctly blocked attacks (level 2).
- Per family, per carrier, per provider; group-weighted metrics beside row-weighted ones (D55 convention carried over as a diagnostic, PROPOSAL); full view and payload-novel view (§3.2 step 6).
- A second read is not allowed. A bug that invalidates the read is documented and taken to the owner (D54 rule), not repeated.

### 6.4 Benign stability gate (design, thresholds PROPOSED)

Motivation, FACT: V4 flipped benign texts on benign-to-benign swaps at 0.125 (v1 `CONTROL-COV`, not
material) and 0.175 (v2 `CONTROL-COV2`, material; JSON stratum 0.70)
(`reports/v5/minimal-pair-probe-v2/README.md`, `reports/v5/evidence-matrix/README.md` rows 9 and 14).
`reports/v5/v5-data-spec-draft/README.md` section 6 asks for a gate "not yet a threshold".

**Construction without reusing probe texts (PROPOSAL):**

1. New module, new master seed (for example `v5-stab-heldout-v1`), new neutral lexicon authored from the
   concept list of the draft spec section 2 (percent-encoded punctuation, apostrophes in names and non-name
   text, street addresses, typed multi-key JSON, external http/https URLs, chunked envelope, multi-field
   forms, free text), **not** from the probes' templates, field names, hosts or pools.
2. Two instances from the same generator with different seeds and disjoint pool partitions:
   `STAB-DEV` (VALIDATION role, usable while iterating) and `STAB-HELD` (INTERNAL TEST role, read once).
   Both frozen and hashed at dataset freeze; both pass L7 (protocol collisions), L8 (probe pools, element
   level) and L9 (disjoint from V5 TRAIN/VAL pools and from each other). Check with the L7a counts-only guard against External v1.
3. Contents per instance: (a) **control**, benign-to-benign same-class value swaps per carrier (query, form, JSON), >= 100 base pairs per carrier (PROPOSED: with 0 flips of 100 the Clopper-Pearson upper bound is about 0.036, with 5 of 100 it is about 0.11); (b) **treatment** contrasts for each HIGH family, >= 30 bases each (the probe v2 size); (c) **attack twins** on the same carriers, so a model cannot lower instability by always answering ALLOW.
4. Labels are benign or attack **by construction**, never from a model output (D38).
5. The generator is its own file, tested like `tests/test_v4_minimal_pair_probe_v2.py`; it records `pools_sha256` for every pool.
6. V4 is scored on both instances only as aggregate; per-case V4 output on `STAB-HELD` stays sealed until the V5 INTERNAL TEST read, because using V4's per-case errors to shape V5 data would consume `STAB-HELD` (D37).

**Gate criteria, PROPOSED, to be preregistered with the owner's ratification:**

| ID | Criterion on `STAB-HELD` | Rationale |
|---|---|---|
| G1 | V5 control flip rate: Clopper-Pearson 95% lower bound < 0.05 overall and in each carrier stratum (not "material" by probe v2's own definition), and the point estimate is below V4's on the same pairs (exact McNemar) | Re-uses the probe v2 materiality definition (`PROTOCOL.md` section 5) instead of inventing a new bar |
| G2 | For each HIGH family contrast: effect class (probe v2 section 5, with V5's own `C_hi`) is neither STRONG nor MODERATE in the A->B direction; contrasts whose reference is mostly BLOCK are reported UNTESTABLE and counted against the gate, not as passes | Prevents a pass through an untestable reference (v1 address lesson) |
| G3 | Count of BLOCK decisions over the benign bases, with numerator and denominator, no higher than V4's on the same texts; **no absolute FPR bar is set** (owner may add one) | D42: diagnostic counts, not rates |
| G4 | Attack-twin recall per carrier within 5 percentage points of V4's or better (non-inferiority margin) | PROPOSED margin equal to the 0.05 materiality bar; guards against an ALLOW-everything model |
| G5 | Determinism: repeat 10% of texts three times; any byte divergence stops the run | Prec. probe v2 section 6 |

### 6.5 V4-vs-V5 comparison rules

Rule (FACT, D37 and `docs/ml_evaluation_methodology.md` sections 1, 10): a comparison needs a set that neither version was trained or tuned on. PROPOSED addition: and whose individual cases did not shape either design.

| Set | Fair for V4-vs-V5? | Use |
|---|---|---|
| V5 INTERNAL TEST | partly: neither trained on it (L7 keeps V4 train out), but V5's generator was designed from V4's failure modes, so it is home-field for V5 | regression and coverage evidence; may not alone support "V5 better than V4" |
| `STAB-HELD` | yes if sealed as in §6.4 | stability gate |
| V4 `eval.jsonl` | no: V4 was checkpoint-selected on it (D24) and the Analyzer read it twice | report-only V4-favoured regression check; V5 TRAIN/VAL must exclude its groups |
| External v1 | Branch P only, labelled with its limitations; Branch C: "on V5 development data" (D40) | one aggregate run |
| External v2 | yes, the intended claim set | §6.6 |
| Paired dev, probes, `real-http-fp-v1`, #57 | no: V5 was designed from them | error analysis and sanity only |

Comparison hygiene: same frozen texts, same metric code, same decoding config (D27), same invalid-output
policy (D19), side by side; per-category TP/FN regressions shown (methodology section 10); latency only via
its instrument and only as a labelled observation (D36, D42).

### 6.6 External v2 prerequisites (D40, D38, D39)

Required before any V5 external-performance claim under Branch C, and PROPOSED under Branch P:

1. Written protocol before the data exists: composition, class balance, slices, metric definitions (D38).
2. D38 order: capture through a capture-only path with no classifier; ground truth from flow intent, two-pass review, ambiguous cases excluded and logged; independence gate (blocking) against V4 train and eval, all `consumed_sets.json` entries including External v1 (counts-only) and all V5 splits; deterministic seeded selection recorded; freeze commit with `status: FROZEN`, SHA-256s and integrity hash; **only then** any model contact. The freeze commit must be an ancestor of every run (D39). `v5_exposure_at_freeze` recorded as zero.
3. Proxy-to-`/classify` byte-equivalence capture present and verified working in the execution environment before the first case is sent (v1's runtime lacked `strace`); every gateway execution hashed and compared with the frozen `request_text`; a run that cannot capture does not start (D40).
4. CSIC-ancestry check implemented and executed before freeze against `csic_database.csv` (SHA `c420f0bc...e44e637`), hits ruled in writing (D40).
5. PROPOSED: new application routes and client mix beyond the v1 lab-app so v2 is not the same distribution as v1 (v1 limitation, `docs/external_test_v1_protocol.md` section 13).
6. Run id immutability (D32/D39): refuses an existing run id; raw evidence never rewritten.
7. Reporting per D41 (L1 model, L2 enforcement, L3 end-to-end, never merged; headline from repetition 1, unstable cases flagged and excluded, direct `/classify` as a consistency control) and D42 (test-specific rates with numerator, denominator and set name; 50/50 construction stated; no operational FPR; no "OOD detection" or "proven overfitting" language).
8. V4 is run on External v2 as well, in the same session and configuration, neither version having seen it. External v2 must never be opened during V5 error analysis.

### 6.7 Reporting rules in force

D19 (BLOCK positive, three levels, FPR prominent), D18 (evidence status; INSUFFICIENT DATA, never inflate), D41, D42, D45 (the word "V5" means the model, never the Hybrid Architecture), D55 conventions where they apply (0.5 is not an operating point; group-weighted diagnostic). Standards (OWASP, NIST, ISO/IEC, EARS) are alignment references, not compliance claims (memory: standards-alignment-not-compliance). Every report states in its first lines whether it is an evaluation or a diagnostic (methodology section 7).

---

## 7. Reproducibility checklist

| Item | Requirement | Anchor |
|---|---|---|
| Master seed and per-family seeds | recorded in the manifest | B2 section 5 |
| Generator identity | git commit, dirty-tree flag (clean tree required to freeze), file SHA-256 of generator, checks and tests | `hybrid` run metadata precedent |
| Source pins | full 40-character commit SHA and file SHA-256 per spec; licence record per spec; lexicon, K threshold, mapping, role-token seed | B2 section 5 |
| Environment | Python version, lockfile with hashes, OS image; separate research env per D33/D52; for training: torch, transformers, peft, bitsandbytes, CUDA, GPU, from `benchmark_env.py` | D33, methodology section 9 |
| Hashing | SHA-256 of every shard, manifest, preregistration, evaluator and tests; aggregate integrity hash (External v1 method) | D39 |
| Determinism proof | A2 and A3 results stored in the freeze report | §4.1 |
| Immutability | no run id reuse; harness refuses overwrite (D32); frozen dataset and stability sets change only through a new version id (D39); raw logs never rewritten | D32, D39 |
| Single-use guards | INTERNAL TEST, `STAB-HELD`, External: `--confirm-single-run`, exclusive `run_attempt.json`, output scanner | `analyzer_external_v1.py` precedent |
| Preregistration | written and committed before first exposure; contains thresholds and selection rules | §6.1 |
| Visible runs | classifier, proxy, destination, client in visible panes; logs tee'd to the run folder, not `/tmp` | methodology section 13; memory: visible-eval-processes |
| Datasets outside git | V4-style gitignored files are pinned by manifest SHA-256; V5 artifacts: record the same plus the regeneration command | `docs/data_sources.md` |
| Model artifacts | gitignored; SHA-256, size, config in the report | D55 |
| Decoding configuration | greedy, canonical V4 inference config (D27) | D27 |

---

## 8. Freeze-report template (`reports/v5/dataset-freeze-v1/README.md`)

1. **Header**: dataset id and version, date, commit, tree state, manifest SHA-256, "evaluation or diagnostic" statement (here: dataset freeze, no model).
2. **Identity and pins**: seeds, generator SHA, source commits and licences, pool hashes (`pools_sha256` for every pool), environment capture. Required numbers: 0 missing pins.
3. **Composition**: rows and `family_id`s per split; per provider x class x carrier x family; class balance per split; payload counts per category with D18 status. Required: all counts with denominators.
4. **Split method**: Option A (or B), salt, strata, share targets and realised shares; pool partition sizes.
5. **Acceptance table**: one row per check in §4 with measured value, threshold, PASS/WARN/FAIL and class. Required numbers: L1-L5 counts (all 0), L7 per protected set (count and policy), L8 shared elements (0), A2 hashes of both regenerations, S1 worst margin per family, S6 minimum `r`, C1 minimum counts per HIGH family.
6. **Shortcut audit**: S1-S4 tables; named tokens `the`, `please`, `https`.
7. **Stability sets**: `STAB-DEV` and `STAB-HELD` sizes, per-carrier bases (>= 100 control), hashes, disjointness results.
8. **Warnings and rulings**: each WARN with its written ruling; L11 CSIC hits.
9. **Disclosures**: provider count and the consequence for claims; aggregate-level External v1 influence; which dev sets informed design (reference `consumed_sets.json` SHA-256); known limitations.
10. **Rejection log**: earlier versions rejected and why.
11. **Freeze statement**: manifest `status: FROZEN`, preregistration SHA, commit id, "no model has seen this data".

---

## 9. Open owner decisions (maximum two)

1. **External branch.** Choose before V5 error analysis starts: (P) keep External v1 pristine for V5 (one aggregate run at most) and build External v2 in parallel, **recommended**; or (C) use v1 individual FPs for V5 error analysis, accepting that v1 becomes development data and External v2 is mandatory before any claim. Whichever is chosen, who inspects what must be written down on the day, and the transition record (if C) must sit beside the set, not in the manifest.
2. **Provider diversity versus family-level split.** With two licensed providers, Option A is the only viable split and INTERNAL TEST cannot support unseen-provider claims. Either accept Option A with the disclosure (recommended for now), or require >= 5 licence-verified providers before freeze (Option B). A related default assumption to confirm in the same decision: V4-clean TRAIN rows are **not** reused in V5 TRAIN; if they are, their D54 generator groups stay in TRAIN and the V4 eval groups stay out of every V5 split.

---

## 10. Limitations

- The "External v1 not inspected" conclusion rests on repository self-statements and on the absence of any transition record; it cannot be proven by file inspection.
- This workstream did not open External v1 cases, results or capture logs, and did not read INTERNAL TEST rows. Only line 1 of the train-role rows of `hybrid_analyzer_v2.jsonl` (key names and value lengths) and line 1 of non-External JSONL files were read to verify text keys. The External v1 text key is verified from docs and code only.
- All thresholds marked PROPOSED are unvalidated: no pilot build exists. S1-S4 and S6 should be calibrated once on a non-protected pilot before the first VALIDATION look, and the thresholds fixed in the preregistration.
- Option A cannot claim unseen-provider generalization. `STAB-HELD` is concept-built by the same team that ran the probes; it is disjoint in pools and texts, not independent in authorship (the same limitation as D38's independence claim: checked against development data only, nothing is claimed about TinyLlama's pretraining corpus).
- Check family names `B:*` are labels; the acceptance table assumes B implements them, and A5 requires B's checkers to demonstrate detection.
- The draft V5 Data Specification is still DRAFT: family priorities, the canonical input form and the decision on D1 are owner-gated and may change the families covered by C1 and S6.
- Tracked-in-git state of the root `train.jsonl` and `csic_database.csv` differs from what `docs/data_sources.md` says for v0.1.0 on this branch; the inventory records "unverified across branches" rather than asserting either.
- Issue #64's own text was not available to this workstream; scope was taken from the coordinator's brief.
