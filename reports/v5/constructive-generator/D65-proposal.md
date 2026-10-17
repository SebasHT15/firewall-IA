# D65 — V5 Stage 4 constructive generator: I-9 interpretation and deferred dataset configuration (proposal source)

**Status: APPROVED 2026-10-17 and recorded in `DECISIONS.md` as D65.** This file is the proposal source
that was approved; the canonical entry lives in `DECISIONS.md`. Earlier decisions are not altered, and
`V5-DATA-SPEC-r3` (SHA-256 `f1580634…`) is **not** modified and needs no r4.

- **Date:** 2026-10-17 (America/Costa_Rica)
- **Issue:** #74 (related: #75 `names_family`)
- **Implementation:** DONE on synthetic fixtures only in the Stage-4 working tree
  (`scripts/dataset/v5_catalog.py`, `v5_render.py`, `v5_labels.py`, `v5_oracle.py`, `v5_generator.py`,
  `v5_rebalance.py`, `v5_fixture.py`; data under `v5_templates/` and `v5_policy/`; tests
  `tests/test_v5_{catalog,generator,rebalance}.py`). **Not integrated**, no real split, no dataset, no
  training.

## 1. Context and relationship to D62 / D64

D62 froze `V5-DATA-SPEC-r3`, including §4.6 (identities, split, cluster-share step 5), §6 (encoding
controls) and §7 (acceptance), with the numeric thresholds and open lists kept PROPOSED per §11.2. D64
recorded the Stage-3 identity/split rulings and deferred to Stage 4 the template catalogue (I-4 and the
I-16 check), the slot model (I-6), the quota model and rebalancing rule (I-9), the ENC-5 overflow choice
(I-10) and the `names_family` identity (I-14). D65 records the Stage-4 interpretations and the dataset
configuration that stays deferred. It changes no frozen requirement and supersedes nothing; it interprets
text D62 left open and records owner decisions.

## 2. Approved interpretation of I-9 (cluster-share rebalancing, §4.6 step 5)

The generator applies step 5 as a deterministic **generate → measure realised cluster share → rebalance
the quota plan → regenerate** loop:

- the realised share is `rows of a cluster ÷ rows of its split`, computed over **admitted** rows only
  (`disposition == "split"`); EXCLUDED rows and abandoned/withheld pairs are not valid dataset rows;
- on a cluster over the enforceable cap, its quota is reduced to the cap and the removed pairs are
  redistributed proportionally to the **other clusters of the same carrier stratum and split**; a cluster
  is never fragmented and no identity or row moves between splits; per-split totals are preserved when a
  feasible solution exists;
- the loop stops with `StopBuild` and an explicit diagnostic if redistribution is impossible, does not
  converge within `max_rounds`, or would require an obligatory-concept exception that is not recorded;
- `row_rng` / `pair_id` are seeded by `(SALT, split, cluster, quota, i)` exactly as D62 §4.6 step 4
  requires, where `quota` is bound to the twin's **category slug** (a stable generation-bucket label, not
  the numeric pair-count) and `i` is the attempt index. The numeric target/pair-count is therefore **not**
  in the seed, so reducing or raising a cell's target preserves the lower-index rows byte-identically
  (verified by `test_quota_change_preserves_earlier_rows_byte_identical` and the reproducibility tests).
  This is the only reading of step 4 consistent with step 5's quota rebalancing; it does not change D62.
  The original quotas, adjusted quotas, realised rows, shares, attempts and outcome of each round are
  recorded in the manifest.

## 3. Difference between WARN and BLOCK

D62 §4.6 step 5 says *"On WARN or BLOCK, the cluster's row quota is reduced."* The approved reading is the
literal one: **WARN is the enforceable reduction trigger** — any cluster whose share exceeds WARN is
reduced — and **BLOCK is a higher-severity classification band** that is also reduced (it is a subset of
"above WARN"). Implemented as `i9.cap="warn"` (the default). `cap="block"` (reduce only above BLOCK) is
**not** authorized for a real build; `real_build_preconditions` emits `I9_CAP_NOT_LITERAL` so it cannot be
used silently. No r4 is needed: the frozen text is honored as written.

## 4. Pending numeric thresholds

The values **WARN = 2 % and BLOCK = 5 % remain PROPOSED** (§11.2). They are ratified only in the dataset
preregistration, on pilot evidence, to a band that is feasible for the final catalogue. They are never
raised arbitrarily to obtain a PASS; an infeasible configuration yields `StopBuild`. The fixtures are never
forced to satisfy them (I-9 tests use explicit TEST thresholds).

## 5. Infeasibility of the current catalogue (diagnostic)

With the split-row denominator and within-carrier redistribution, the minimum feasible cluster-share cap
per split on the synthetic fixture is: **TRAIN 6.90 %, INTERNAL_TEST 16.67 %, VALIDATION 33.33 %**
(`i9_feasibility_fixture.json`, `v5_rebalance.feasibility_analysis`). So neither 2 % nor 5 % is feasible in
any split at the current catalogue scale, because the cluster-count 70/10/20 split leaves few clusters per
carrier in the 10 % and 20 % splits. **These figures are diagnostic of the current catalogue and must be
recomputed if it changes.** They do not, by themselves, justify raising the thresholds.

## 6. Pending policy for small splits

No blanket exception for VALIDATION or INTERNAL_TEST is authorized. The policy for low-cluster splits — a
feasible cap, a per-cluster obligatory-concept ruling (each needing a specific justified owner decision), or
a different share granularity/unit (which would need an r4) — is decided with owner-approved evidence
before the real build. Until then an infeasible configuration stops the build.

## 7. I-10 (ENC-5 overflow) and fail-closed behaviour

The E6-reserve overflow mechanism (when payload families with native held-out forms exceed the reserve R)
is implemented and tested at the Stage-3 level, with both D62 alternatives available —
`reserve_equals_forced` (the reserve equals the forced families) and `enc5_retire` (retire the transform
from the held-out list and disclose it). The choice is **deferred**: `e6.forced_overflow_policy = None`, so
an unresolved overflow stops the build explicitly (fail-closed). Neither alternative is selected
automatically. The current attack pool does not trigger the overflow (forced families ≤ R). The selection
is ratified at the preregistration.

## 8. Guarantees implemented and tested

Synthetic fixtures only (601 tests on CPython 3.12 and 3.14; V4 behavioural suites unchanged):

- template catalogue with `template_id` (I-4), declared clusters, the Jaccard ≥ 0.60 audit and the I-16
  cross-carrier stop; the typed slot model (I-6) and the §4.2 compatibility table;
- the shared encoder (ENC-1/2/6) and rendering through the single stage-1 `canonicalize()` (I1), with
  per-row idempotence (I3), only `Content-Type` in the text (A-G3), and JSON bodies parsing under their
  declared type (A-G2);
- the §4.3 labeller with precedence and the `POL-*` table, invariants M-1…M-10, the §4.4 benign oracle
  (survival fixture passes; L and signatures PENDING);
- constructive pairs: exactly one leaf differs (proven on the canonical text), identities belong to the
  row's split, SPL-3…SPL-9 pass on generated rows, ENC-3/7 enforced, over-budget rows EXCLUDED `OVER_LIMIT`
  and never truncated;
- the I-9 realised-share loop of §2; deterministic and reproducible (data byte-identical across two
  `PYTHONHASHSEED` values and across CPython 3.12 / 3.14; the manifest differs only in the recorded Python
  version).

## 9. Limitations of the synthetic generator

The fixtures use abstract attack *markers* with no functional exploit content; the only real strings reused
are the V4/D47 reason labels (M-7). Nothing here is VERIFIED attack ground truth; the attack-label basis is
`fixture_synthetic` and `v5_labels.AttackBasis` refuses any record without `synthetic: true`. Benign pools
are synthetic stand-ins; `names_family` is BLOCKED (#75); `passwords`, `urls_public/relative`, `rel_paths`,
`addr_data` have fixture stand-ins only. Three acceptance controls that need real data — the post-filter
audit (§7), the oracle `L` / signature calibration (§4.4), and real-split leakage — are explicit test
skips, never a synthetic PASS.

## 10. Conditions to satisfy before the real build

All of D64's conditions remain, plus the Stage-4 items: the post-filter audit and payload adjudication
(no `PENDING_ADJUDICATION`); the final third-party deny-list; `names_family` built or a configuration
without it explicitly approved (#75); the dataset preregistration fixing the WARN/BLOCK values, the
small-split policy, `L`, the oracle signatures, placement shares, length bins, quotas, the token budget `B`
and the per-file cap; the I-10 overflow policy selected; `i9.cap="warn"` (a real build refuses any other);
every SPL / M / ENC / acceptance gate run on the real build; and INTERNAL TEST read once behind its
single-run guard. `real_build_preconditions` enumerates the unmet items and refuses today.

**Rationale.** The literal WARN reading keeps the generator faithful to the frozen contract without an r4;
deferring the numeric values and the small-split policy to the preregistration follows §11.2 and avoids
ratifying thresholds that are infeasible for the current catalogue; fail-closed I-10 avoids an unauthorized
automatic choice. Leakage safety, group/partition integrity and reproducibility are prioritised over
evaluable-family counts.

**Relationship to earlier entries.** Applies D62 (§4.6, §6, §7) and D64 (Stage-4 deliverables); amends
neither. D56–D64 and the frozen file are unchanged (SHA-256 `f1580634…`). No r4. Nothing is superseded.
