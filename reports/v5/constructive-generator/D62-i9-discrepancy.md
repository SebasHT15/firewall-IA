# D62 / I-9 interpretation note (issue #74) — RESOLVED by configuration, no r4

**Status: RESOLVED without modifying the frozen spec and without an r4** (owner decision 2026-10-17,
recorded as draft D65). The frozen `V5-DATA-SPEC-r3` is unchanged (SHA-256 `f1580634…`). This note records
the earlier discrepancy and how it was closed.

## The discrepancy (as it stood)

`V5-DATA-SPEC-r3` §4.6 step 5 (FROZEN, D62) states:

> Cluster share … WARN above 2%, BLOCK above 5% (values PROPOSED). **On WARN or BLOCK, the cluster's row
> quota is reduced and the difference is redistributed** proportionally to the other clusters of the same
> stratum and split. … Otherwise the configuration is rejected and the build stops.

Read literally, **both WARN and BLOCK trigger reduction**, so the enforceable reduction trigger is the WARN
threshold; BLOCK is a higher-severity band that is also reduced. An earlier provisional implementation set
`i9.cap="block"` (reduce only above BLOCK, WARN warning-only), which **deviated from the literal text**.

## Resolution (adopted)

**`i9.cap="warn"` is the compliant setting and is now the default.** With `cap="warn"` the rebalancer
reduces every cluster whose share exceeds the WARN threshold — i.e. both the WARN and BLOCK bands trigger
reduction, exactly as §4.6 step 5 states. BLOCK remains a reported severity classification. No logic change
was needed: the mechanism already supported `cap="warn"` (`v5_rebalance.py` `cap_frac = warn if
cfg["cap"]=="warn" else block`); only the default and the framing changed.

What this leaves open is **only PROPOSED values**, not a frozen-rule deviation:

- The numeric WARN / BLOCK values (2 % / 5 %) stay PROPOSED (§11.2), ratified at the dataset
  preregistration on pilot evidence to a **feasible** band for the final catalogue. They are never raised
  arbitrarily to force a PASS; an infeasible configuration yields `StopBuild`.
- No r4 is required, because the frozen text is honored as written and only its PROPOSED values remain open.

## Guardrails

- `i9.status` must be `PROPOSED` (`validate_i9_config`), so nothing here is claimed ratified.
- A **real build is blocked** while any value is PROPOSED: `real_build_preconditions` emits
  `VALUE_NOT_RATIFIED` for the i9 status, and additionally `I9_CAP_NOT_LITERAL` if a real build is ever
  configured with `cap != "warn"` — so `cap="block"` can never drive a real build silently.
- The fixtures are never forced to satisfy 2 % / 5 %; the I-9 tests use explicit TEST thresholds.

## Mathematical infeasibility of the proposed values with the current catalogue (diagnostic)

Computed with the split-row denominator (§4.6) and within-carrier redistribution
(`v5_rebalance.feasibility_analysis`, artifact `i9_feasibility_fixture.json`). Minimum feasible
cluster-share cap per split on the synthetic fixture:

| Split | Clusters | Min feasible cap |
|---|---|---|
| TRAIN | 22 | 6.90 % |
| INTERNAL_TEST | 6 | 16.67 % |
| VALIDATION | 3 | 33.33 % |

So neither 2 % nor 5 % is feasible in any split at the current catalogue scale (the cluster-count 70/10/20
split leaves few clusters per carrier in the 10 % and 20 % splits). **These figures are diagnostic of the
current catalogue and must be recomputed if it changes.** The final thresholds and the small-split policy
are decided by owner-approved evidence before the real build; no blanket VALIDATION / INTERNAL_TEST
exception is authorized, and each obligatory-concept ruling needs a specific, justified owner decision.
Until then an infeasible configuration correctly stops the build.
