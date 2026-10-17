# V5 Stage 4 — constructive generator (issue #74, UNCOMMITTED, branch `feat/v5-constructive-generator`)

Status: **READY FOR PR** (D65 APPROVED 2026-10-17), synthetic fixtures only, UNCOMMITTED. No real split,
no dataset, no training. `V5-DATA-SPEC-r3` (`f1580634…`), D62, D64, V4 and the gateway are unchanged. This
report is working documentation for the uncommitted session work; nothing here is a dataset-freeze artifact.

## Stage 4 acceptance (issue #74) — implementation criteria met

| # | Criterion | Status |
|---|---|---|
| 1 | Catalogue covers every §2.2 carrier; `template_id` + declared cluster + audit; undeclared same-stratum and cross-carrier (I-16) near-dups stop the build | **met** (`v5_catalog`, `tests/test_v5_catalog.py`) |
| 2 | Pairs identical in method/carrier/CT/structure/non-attack leaves; exactly one leaf differs; `assert_row`; SPL-3/4/6/7 on generated rows | **met** (C-M2 + SPL gates) |
| 3 | M-1…M-10 on generated rows; M-8 renaming; no attack-pool ALLOW; no VERIFIED before the post-filter audit | **met** |
| 4 | Oracle survival fixture passes; each rejection rule fires; L / signatures PENDING | **met** |
| 5 | Every row from `canonicalize()` ACCEPT; I3 per row; ENC-1/3/7; `OVER_LIMIT` never truncated | **met** |
| 6 | Byte-identical regeneration across two `PYTHONHASHSEED`; no real split; no INTERNAL TEST / External read; frozen spec, V4, gateway unchanged | **met** (data byte-identical across seeds **and** 3.12/3.14; manifest differs only in recorded `environment.python`) |
| 7 | Deferred D64 items resolved or carried: I-4, I-16, I-9 (quota + rebalance), I-10 (ENC-5 overflow choice), slot model (I-6) | **met**; **carried:** I-6 `pair_content_id` (optional diagnostic, non-blocking per D64 §S.6 — not implemented), I-14 `names_family` (data BLOCKED, #75) |

**I-9 cap semantics (RESOLVED, D65 APPROVED 2026-10-17):** the enforceable reduction trigger
is **WARN** (`i9.cap="warn"`, now the default) — WARN *and* BLOCK both trigger reduction per the literal
D62 §4.6 step 5; BLOCK is the higher-severity band. No r4; the frozen spec is unchanged. A real build with
`cap != "warn"` is blocked by `real_build_preconditions` (`I9_CAP_NOT_LITERAL`).

**Deferred to the pilot / preregistration (owner decision, do NOT treat as implementation gaps):** the
WARN/BLOCK numeric values (2 % / 5 %, PROPOSED) and the policy for low-cluster splits (VALIDATION /
INTERNAL_TEST) — each requires owner-approved evidence; no blanket exception is authorized, each
obligatory-concept ruling needs a specific justified owner decision, and the fixtures are never forced to
satisfy the proposed thresholds (an infeasible configuration yields `StopBuild`).

## Modules (`scripts/dataset/`)

| File | Role |
|---|---|
| `v5_catalog.py` + `v5_templates/` | 41 templates / 36 clusters; `template_id` (I-4), Jaccard ≥ 0.60 audit, I-16 cross-carrier stop |
| `v5_render.py` | shared encoder (ENC-1/2/6), render via stage-1 `canonicalize()` (I1), per-row I3, leaf spans, ENC-3/4 detectors |
| `v5_labels.py` + `v5_policy/policy_table_v1.json` | §4.3 classes/precedence, `POL-*` URL classes, M-1…M-10; lists PROPOSED |
| `v5_oracle.py` + `v5_policy/oracle_signatures_v1.json` | benign oracle (exact / containment ≥ L / signatures); L & signatures PENDING |
| `v5_rebalance.py` | **I-9 step-5 cluster-share rebalancing (new this session)** |
| `v5_generator.py` | pairs, one-leaf change, OVER_LIMIT (no truncation), labels, gates, manifest; I-9 wired in |
| `v5_fixture.py` | synthetic harmless fixture + CLI |

## I-9 cluster-share rebalancing (§4.6 step 5)

`v5_rebalance.rebalance(cells, i9cfg)` is pure deterministic quota math over
`{(split, cluster, category): {carrier, pairs}}`. For each split it:

1. computes each cluster's share = cluster pairs ÷ split pairs (rows = 2·pairs);
2. classifies WARN / BLOCK against the **config** thresholds (PROPOSED, never ratified here);
3. within each `(split, carrier)` group, reduces every cluster over the configured cap to the cap and
   water-fills the removed pairs to the other clusters of that group, proportional to their current
   pairs, never pushing one over the cap;
4. keeps every cluster whole, never moves pairs between splits, and preserves each split's total when a
   feasible solution exists;
5. **stops** (`StopBuild`, code `I9_REQUIRED_CONCEPT_RULING_NEEDED`) when a carrier group has too few
   clusters to absorb the excess (the limit is mathematically impossible), unless the owner has recorded
   a ruling for the offending cluster, in which case the cluster is kept over the cap and the ruling is
   recorded.

The generator applies it before rendering. `row_rng` / `pair_id` are seeded by `(SALT, split, cluster,
quota, i)` as D62 §4.6 step 4 requires, with `quota` = the twin's **category slug** (a stable bucket label,
not the numeric pair-count) and `i` = attempt index. Because the numeric target is not in the seed, reducing
or raising a cell's quota keeps the lower-index rows byte-identical (proven by
`test_quota_change_preserves_earlier_rows_byte_identical`). It is **opt-in** (`gen_cfg.i9.enabled`, default
`false`).

### Decisions resolved by implementation (deterministic, documented — not arbitrary)

- **R1** share denominator = the whole split (all carriers), per the frozen text.
- **R3** a reduction / addition is spread across a cluster's categories proportional to their pairs, by
  largest remainder, tie-broken by category code-point order.
- **R4** redistribution weight = recipients' current pairs, water-filled, tie-broken by cluster id.
- **R5** quota changes keep `row_rng` / `pair_id` stable.

### Realised-share driver (owner decision, §4.6 step 5)

I-9 runs as a **generate → measure realised shares → rebalance → regenerate** loop (`generate_balanced`):

- the realised cluster share is computed over **admitted** rows only (`disposition == "split"`); EXCLUDED
  rows and abandoned/withheld pairs are not valid dataset rows and do not count;
- if a cluster exceeds the configured cap, the quota plan is rebalanced on the **realised** counts (reduce
  the over-cap cluster, redistribute within its carrier+split, identities and partitions intact) and the
  build regenerates; the loop repeats up to `i9.max_rounds`;
- it **stops** (`StopBuild`) if redistribution is impossible, does not converge, or would need an owner
  ruling that is not recorded — never a silent acceptance, never an automatic obligatory-concept exception;
- each round's planned quotas, realised pairs, realised shares, attempts and outcome are recorded in the
  manifest (`i9_rebalance.rounds`). As above, the seed excludes the numeric target, so regeneration with a
  changed quota keeps earlier rows byte-identical.

This supersedes the earlier "diagnostic only, no regeneration" sketch (owner decision). It is consistent
with §4.6 step 5 ("computed after generation … quota reduced and redistributed"), and with the cap set to
WARN the frozen text is honored as written (see below).

### I-9 cap: resolved and open items

- **R2 / Decision 1 — RESOLVED (D65 APPROVED).** The enforceable reduction trigger is **WARN**
  (`i9.cap="warn"`, default): WARN *and* BLOCK both trigger reduction, the literal D62 §4.6 step 5 reading;
  BLOCK is the higher-severity band. No logic change (the mechanism already supported it), no r4, frozen
  spec unchanged. See `D62-i9-discrepancy.md`.
- The WARN / BLOCK **values** (2 % / 5 %) remain PROPOSED (spec §11.2); the fixtures are never forced to
  satisfy them — I-9 tests use explicit TEST thresholds, and an infeasible config yields `StopBuild`.
- **Redistribution weight** (current pairs vs headroom) — current pairs adopted (R4); the alternative is open.

### Structural finding — the proposed thresholds are incompatible with the current catalogue

Feasibility analysis (`v5_rebalance.feasibility_analysis`, artifact `i9_feasibility_fixture.json`), computed
with the **split-row denominator** (§4.6; the cap is a share of the whole split, not of a carrier) and
within-carrier redistribution. The **minimum feasible cluster-share cap** per split on the synthetic fixture:

| Split | Clusters | Min feasible cap | 2 % feasible? | 5 % feasible? | Why |
|---|---|---|---|---|---|
| TRAIN | 22 | **6.90 %** | no | **no** | `form` carrier share 27.6 % over 5 clusters |
| INTERNAL_TEST | 6 | **16.67 %** | no | no | single-cluster `form`/`text` carriers |
| VALIDATION | 3 | **33.33 %** | no | no | one cluster per carrier (the 10 % split is tiny) |

So the PROPOSED 2 % / 5 % caps **cannot be satisfied in any split** with this catalogue — not even BLOCK = 5 %
in TRAIN. The cluster-count 70/10/20 split necessarily leaves few clusters per carrier in VALIDATION (10 %)
and INTERNAL_TEST (20 %). This is **not** worked around by owner-ruling every low-cluster cluster (the owner
did not authorize blanket exceptions), by growing the catalogue artificially, or by changing 70/10/20. It is
surfaced for an owner decision: raise the thresholds to a feasible band, change the share granularity/unit
(would need an r4), or accept specific, justified obligatory-concept rulings case by case.

## Tests and results

- `tests/test_v5_rebalance.py` (14): no-op; one over-cap; several over-cap; rounding; deterministic ties;
  insufficient capacity → stop; single-cluster carrier impossible → stop; owner ruling recorded + kept
  whole; no cross-split movement; carrier isolation; permuted input order; PYTHONHASHSEED independence
  (subprocess).
- `tests/test_v5_generator.py` I-9 integration: disabled by default; realised cells count only admitted
  complete pairs (EXCLUDED/withheld excluded); enabled-infeasible stops with split-denominator findings;
  the realised loop rebalances + regenerates + converges under an explicit TEST cap (8 %) with every
  realised share ≤ cap and gates green; reproducible (rows and rounds); high cap converges without
  rebalancing; the manifest records planned/realised/attempts/outcome per round; explicit plan drives
  generation.
- Full Stage 1–4 suite: **601 tests OK on CPython 3.14 and 3.12** (3 generator skips are real-dependency
  placeholders, never a synthetic PASS). V4 behavioural suites: **120 OK**.

### Independent read-only review (3 Sonnet audits) and the fixes applied

- **Rebalancer bug fixed.** The feasibility test counted owner-ruled clusters, so a build could stop even
  when a feasible solution existed (a ruled cluster stays whole above the cap and must drop out of the
  count, the pair sum and the recipient set). `rebalance()` now runs feasibility and redistribution over
  the **un-ruled** clusters only; regression test `test_ruled_cluster_exempt_while_unruled_sibling_is_still_rebalanced`.
- **Hardening added:** `rebalance()` rejects a cluster that spans two carriers and rejects negative pair
  counts; the dead clamp in `_spread` was removed; a `generate()` guard rejects slug-colliding categories.
- **Test quality raised:** the M-8 renaming test now actually varies field names within a role; the
  oracle-reject test now exercises the EXCLUDED + withheld-twin path end to end on a single-slot world; the
  M-6, missing-pool, real-build and I-9-stop tests assert exact codes/labels; added rounding per-cell, cap=warn,
  `_water_fill` non-convergence, config-refusal, and C-M2 mutation tests.
- **Stale note fixed:** `KNOWN_LIMITATIONS` no longer says I-9 is unimplemented; it now records that I-9
  caps on planned pairs and that realised post-generation shares are reported, not re-gated.
- **Surfaced, not fixed (owner call):** whether the realised post-generation share should be a hard gate
  (I-9 currently caps on the planned pairs; abandons/shortfalls can shift the realised share, reported as a
  diagnostic). No leakage path or cross-split contamination was found; SPL-3 holds on generated rows.

### Determinism evidence

- I-9 build reproducible in-process (identical row metadata on two builds).
- Rebalancer identical under permuted input order and across `PYTHONHASHSEED` 0 / 1 / 9999 (subprocess).
- Generator CLI manifest byte-identical across `PYTHONHASHSEED` (from the prior session, unchanged).

### The two pre-existing non-generator errors

`tests/test_inference_core.py` and `tests/test_classifier_api.py` fail at **collection** because `torch==2.6.0`
and `fastapi==0.136.3` (declared in `requirements.txt`, the full control-plane env) are not installed in
either local venv on this machine. They import `control_plane` modules only, reference no Stage 4 code, and
reproduce identically regardless of this work. They are environment gaps, not generator defects.

## Parameters still PROPOSED / PENDING

Catalogue cluster declarations; policy host/scheme/form lists and navigation lexicon; oracle `L` and
signatures; placement shares; length bins; quotas; encoder-profile weights; token budget `B`; I-9 WARN/BLOCK
numeric values and the low-cluster-split policy (the I-9 cap band is resolved: WARN, D65).
`names_family` pool BLOCKED (#75).

## Stage 4 closure

The **implementation acceptance criteria (1–7) are met** (table above), so Stage 4 is **READY FOR OWNER
REVIEW** at the implementation level. The owner decided to defer the I-9 threshold questions to the pilot /
preregistration (§11.2), so they do **not** block this closure — they are review items, not implementation
gaps. Pending owner actions, distinguished:

- **Review** the candidate catalogue, policy lists, oracle signatures and `L` (all PROPOSED/PENDING).
- **Rule at the pilot / preregistration:** the WARN/BLOCK values, which band is the enforceable cap (the D62
  discrepancy — see `D62-i9-discrepancy.md`), and the per-cluster obligatory-concept ruling policy. No
  blanket VALIDATION/INTERNAL_TEST exception is authorized; each exception needs a specific, justified owner
  decision.
- **Carried, non-blocking:** I-6 `pair_content_id` optional diagnostic (follow-up); I-14 `names_family` data
  (#75, BLOCKED).
- **Not part of stage-4 closure** (real-split only): the D64 conditions — post-filter audit, final deny-list,
  `names_family`, preregistration — all still open; `real_build_preconditions` refuses today.

## Commit / PR preparation (NOT done this session — owner performs it)

**18 new files** (untracked):

```
scripts/dataset/v5_catalog.py  v5_render.py  v5_labels.py  v5_oracle.py  v5_rebalance.py
scripts/dataset/v5_generator.py  v5_fixture.py
scripts/dataset/v5_templates/{catalog_v1.json, field_names_v1.json}
scripts/dataset/v5_policy/{policy_table_v1.json, oracle_signatures_v1.json}
tests/test_v5_catalog.py  tests/test_v5_generator.py  tests/test_v5_rebalance.py
reports/v5/constructive-generator/{README.md, D62-i9-discrepancy.md, D65-proposal.md, i9_feasibility_fixture.json}
```

**3 modified tracked files:** `CONTEXT.md` and `README.md` (Stage-4 status lines), and `DECISIONS.md`
(**D65 appended as APPROVED 2026-10-17** plus its index row; no earlier entry altered, frozen spec
untouched, no r4). No V4 / gateway / frozen-spec change.

Suggested commit subject: `feat(v5): implement stage 4 constructive generator (templates, pairs, labels, oracle, I-9)`.
PR into `develop`. The PR body should state: synthetic fixtures only; 601 tests OK on CPython 3.12 and 3.14;
V4 behavioural 120 OK; frozen `V5-DATA-SPEC-r3` / D62 / D64 unchanged (SHA-256 `f1580634…` verified); no real
split, dataset or training; I-9 cap band = WARN (literal D62, D65 APPROVED), WARN/BLOCK numeric values and the
low-cluster-split policy deferred to the pilot/preregistration; I-10 fail-closed (`None`); `names_family`
blocked (#75). Refs #74 (and #75).
