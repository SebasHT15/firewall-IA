# Opus methodological review (single, pre-freeze) — v5-minimal-pairs-v2

Reviewer: Opus 4.8 (the session's main agent, acting as the single pre-freeze Opus methodological
review per the session protocol §15). Scope: find methodological problems capable of **invalidating
the causal interpretation** of the probe. Not a redesign, not a scope expansion. Inputs reviewed:
`PROTOCOL.md`, `minimal_pair_probe_v2_cases.py`, `run_v4_minimal_pair_probe_v2.py`,
`tests/test_v4_minimal_pair_probe_v2.py`, generated `cases.jsonl` + `manifest.json`. The prior Sonnet
review's four BLOCKERs and the accepted IMPORTANT findings were already applied; this review checks
whether anything invalidating remains.

Model-selection note: the `opus` subagent alias in this environment resolves to a model newer than
Opus 4.8, which the session's model-version constraint forbids. Rather than silently escalate, the
single Opus review is performed by the Opus 4.8 main agent. This preserves the "one Opus review,
≤ 4.8" requirement; it trades away the independent fresh context of a separate reviewer, mitigated by
the independent Sonnet review that preceded it.

## Checks and findings

**Single-variable isolation — PASS.** The generator builds all levels of a base from one `rng` draw,
so method/path/headers/carrier are identical across a base's levels (test
`test_every_base_level_skeleton_is_constant`). Value-only contrasts (`base->hash/punct`,
`plain->apostrophe`, `val_a->val_b`) keep the field name; the ADDR name contrasts change only the
field token. The `detail`→`address` rename adds one character of length; this is absorbed by the
`n_prose->n2_prose` (`detail`→`remark`) rename control, which calibrates any-rename instability
including the length change. Not invalidating.

**Controls — PASS (adequate, with stated limits).** (i) `punct` (`!`) is now encoding-matched to `#`
(`%21`↔`%23` in form/query, both literal in JSON), fixing the prior confound; `!` was near-null in v1
(1/30), so it is a conservative "any inserted punctuation" baseline, and `punct->hash` tests
`#`-specificity directly. (ii) CONTROL-COV2 is stratified over the four test domains
(handle/prose/token/JSON), so the effect bar `C_hi` reflects benign instability in the domains the
tests actually use, not only username handles; per-stratum control rates are reported. (iii) The ADDR
rename control exists. No control is missing that would invalidate a primary conclusion. Limit (not
invalidating): there is no covered-character control for the apostrophe, so C is explicitly scoped to
*generalization across classes*, not apostrophe-vs-other-character specificity.

**Hidden confounders — PASS (scoped).** The only deliberate confound is literal-vs-encoded crossed
with carrier (JSON vs form/query) in the `json_text`/`place_json` strata. The protocol was corrected
to treat literal-`#`/`'` vs `%23`/`%27` as a **descriptive, hypothesis-only** association and
explicitly **not** an encoding-causal claim; `generic` and `json_text` were further matched on
field+template to reduce the confound to carrier+encoding. The core questions (A field/value/format;
B general-vs-context among `%23`; C character-vs-name among `%27`) do not depend on the encoding
inference. Not invalidating.

**Ceiling / testability — PASS (the v1 lesson is now encoded).** A 0-discordant result falsifies only
when A→B was *testable* (reference-ALLOW ≥ ⌈2N/3⌉); otherwise it is `NO OBSERVED (UNTESTABLE)` and
cannot falsify. This directly prevents the v1 artefact where a street-value-under-`address` reference
was already BLOCK in 26/30. `n_street->a_street` and `n_numfmt->n_street` will self-report UNTESTABLE
if their reference is mostly BLOCK, rather than producing a false null. Not invalidating.

**Sample independence — PASS.** Bases are distinct across all factors (collision-avoidance loop; test
`test_bases_distinct_across_all_factors`), 15 distinct values per apostrophe class, and ≥10 distinct
nouns per hash context. Each base is scored once in phase 2 (seeded shuffle); pairs are within-base.
Template-vs-context is correctly scoped: the protocol reads a "context"/"class" as a
{field, carrier, template} bundle, not a field-level claim.

**Statistics — PASS.** Paired exact McNemar (two-sided), Holm within one pre-registered CONTENT family
of 10 hypothesis-bearing comparisons (control outside), Clopper-Pearson intervals, direction-aware
classes (B→A labelled non-supporting), MODERATE now requires raw McNemar p < 0.05, and the per-stratum
verdict + heterogeneity rule are pre-registered and implemented (tested end-to-end on synthetic
records). The heterogeneity rule is qualitative (≥1 effect stratum and ≥1 testable-null stratum)
rather than an exact k-sample test; at N=15/stratum this is the defensible, non-over-engineered choice
and is used only to detect, not to quantify, interaction. Not invalidating.

**Pre-registration completeness — PASS.** Hypotheses, IVs, levels, comparisons, controls, metrics,
effect + stratum classification, testability, falsification criteria (incl. H-A4), determinism STOP,
crash recovery, invalid-pair handling, seeds, generator/analysis versions, and the adapter +
`inference_core.py` hashes are all fixed before the freeze and asserted at run time.

**Leakage — PASS.** 0 case-text overlap with v1; 0 host overlap; v2 value pools disjoint from v1
pools; field names new except `address`, which is the independent variable under test (concept, not
base, reused). The Sonnet review's read-only scan additionally found 0 overlap of v2 pool values with
`train.jsonl`/`eval.jsonl`. #57/#60, External v1, INTERNAL TEST isolation rests on construction +
authorship (no mechanical cross-check run, by data-isolation policy); the fresh synthetic domain makes
incidental overlap implausible.

## Residual limitations (documented, not invalidating)

1. `n_numfmt`→`n_street` retains residual differences (street nouns, `Apt`, token count) beyond
   digits/caps; reported as covariates and read as "street-likeness," not a single isolated feature.
2. Literal-vs-encoded is carrier-confounded (descriptive only).
3. Per-stratum power is ~15; the stratum rule is deliberately conservative (an "indeterminate" band).
4. `plain` apostrophe references are apostrophe-stripped spellings (slight unusual-vs-standard
   contrast).

## Verdict

**No BLOCKER found.** The four Sonnet BLOCKERs were fixed and verified; no remaining issue invalidates
the causal interpretation. **FREEZE.**
