# V5 v4 dataset freeze report — 2026-10-26 (Costa Rica)

Dataset manifest REAL: `c2e9c2f50f56c059ce82945384858802357be88d899dc2710e20edd06a2b72df`. Formal freeze is a separate v5-dataset-freeze-record/v1; its issuance does not modify this manifest.
Owner direction: D78 exact chat instruction; A, B and C implemented as separate D79/D80/D81 records. No target model has trained.

## Identity and composition

3080 TRAIN, 40 VALIDATION, 40 INTERNAL_TEST; 1580 complete pairs; quota shortfalls 0.
Generator/split configs are ratified with the existing D74/D75/D76 values. Twelve H1-disallowed attack records and one symbols value were removed prospectively before generation.
All retained attack source lines are byte-identical to parent records and pass their own original path/census/SQLi component membership checks.
No normalization, fabricated label, new payload, category PASS transfer or combined-pool PASS. The projected merge declarations preserve equivalence relations among surviving IDs.
The full composition, assignment hashes, class/provider/category counts, source pins, seeds and environment are in the manifest and source-hygiene-ledger.json.
The validation/internal-test row and metadata artifacts are byte-identical to v3, verified in sealed-set-continuity.json. Earlier versions remain preserved.

## Acceptance

| Control | Measurement / acceptance |
|---|---|
| A1 | 14 declared artifact hashes/sizes valid in freeze-precheck.json |
| A2 | Two fresh CPython 3.14.4 processes, PYTHONHASHSEED 17/83, repo and /tmp cwd, manifest plus 14 artifacts byte-identical; clean tracked tree before/after |
| A3 / SPL | Manifest SPL-3…9 PASS; targeted Invariants tests include order/seed and violations; split principles unchanged |
| A4 | Retained source provenance/licence review; A4_SOURCE_REVIEW.md, parent A4, source hygiene ledger and local archives |
| A5 | 34 H1 tests and 27 targeted checker tests OK, zero skips in these targeted runs. Existing generator/dataset/shortcuts tests retained; no unsupported '83/83 generator' claim |
| A6 | Eleven factual checks pass on v4; aggregator freeze_ready remains false by design. Its unchanged fail-closed implementation and earlier mutation evidence remain accredited |
| I7 | Exact preregistered source pin and existing execution preserved in i7-continuity.json; deterministic corpus 2500/seed20261013 + 256-byte sweeps, neither fuzz method skipped |
| L1/L2/L4/L5/L9 | Manifest SPL-3/SPL-6: no cross-split identity/text/payload/value overlap; detailed counters in manifest |
| L7/L7a | Counts-only, 13 registered entries; all blocking sets checked and passing. CSIC extractor's unchecked warning is covered separately by L11 |
| L8 | Probe pool remaining overlap zero; new sources are subsets of prior verified pools |
| M-1…M-8 / C-M2 / C-M3 | Manifest label invariants/pair integrity PASS; complete twins; class share .5 per split. Targeted negative tests for M-1…8 and C-M3 |
| C-S1/S2/S6 | All thresholds pass in shortcut-partial.json; minimum symmetry ratio 1.0 |
| C-S3 | Token-purity report blocking PASS |
| C-S4 | Structure-only checker accuracy .5, PASS; a protocol quality probe, not either FINAL target model |
| C-S7 | TRAIN passes; small protected split concentrations retained as WARN under D76 |
| H1 | All 3160 rows pass corrected context/provenance-based checker; 0 confirmed or unresolved findings |
| H2/H3 | Source review PASS; 3160 texts, zero Transfer-Encoding header lines and zero raw chunk framing |
| STAB | Original sealed STAB-HELD retained; source-subset disjointness proof, seal unchanged, D77 G1–G5 linked; no sealed cases opened/evaluated |

## §11.3 evidence

post_filter_audit: original path_file_access, census CmdI/SSTI/XSS and SQLi v3 remain separate, each PASS_AI_AUDITED only for its declared categories.
blocking_checks: above reports plus acceptance.json and A2-regeneration.json. dataset_preregistration: committed before full build.
stab_held_sealed: original SEAL and D77 continuity. dataset_freeze_report: this report. Each is hash-bound by freeze-record.json.

## Warnings, disclosures and limits accepted in the readiness instruction

CmdI/SQLi/SSTI/XSS remain TRAIN-only/NOT_EVALUABLE per D60/D74; only path_file_access evaluable, with the two named single-structure exceptions.
L10 WARN high remains: VALIDATION 15/20 and INTERNAL_TEST 19/20; L11 has 0 hit record IDs.
STAB is project-authored/concept-built, not an independent traffic sample or human-adjudicated set. PATT legacy provenance lacks per-row hashes for 1666 parent rows; do not imply this was repaired.
AI_AUDITED is not human validation. No production security/performance, threshold, operational winner or runtime activation is authorized.
Local source archives are recovery-verified; no off-device backup is claimed. CPython3.14.4 is needed for manifest byte identity, while trainers use their pinned Python3.12 environments.

## Rejection/continuation log and next guards

v1 failed L8; v2 failed C-S7; v3 preserved with H1 failure; v4 corrects source hygiene prospectively before any model output.
The freeze is not a model result. PR to develop remains required under D73. Actual model fitting is not started here.
FINAL launch must recheck committed records, source/library bindings, eligibility and clean tree. INTERNAL_TEST/STAB are never used for checkpoint selection.
