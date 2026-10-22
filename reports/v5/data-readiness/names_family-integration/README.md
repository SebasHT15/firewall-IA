# V5 `names_family` pool integration (I-14, issue #75) — 2026-10-21

> **Update:** this batch was committed and **merged via PR #84** into `develop`
> (2026-10-21T16:52:43Z, `76f7ab0`); the "uncommitted" framing below describes its preparation state.

Prepared on branch `feat/v5-pool-integration` (based on `origin/develop` at the PR #79 merge,
`79a8a6a`). This report
separates three distinct states — **catalogue capability**, **demonstrated generator consumption**
(synthetic) and **pending real-data integration** — and records the **owner decisions** (DR-75,
ratified as **D68** on 2026-10-21). It does not approve a dataset or authorize training, and it does
not run a real split.

## 1. Starting state (verified, not assumed)

- Acquisition is DONE and already committed (builder query `LIMIT 20000`, `2bf853f`; `git diff HEAD`
  empty). The pinned snapshot is installed at `datasets/v5_sources/raw/wikidata_family_names.json`,
  SHA-256 `039882220480b029074243f740f4eec07646029a0b6de8ce70f99454686d3ead`.
- The pool is BUILT locally: `benign/names_family.jsonl` = **12,104 accepted**; `status: BUILT`,
  `blocked_pools: []`. `raw/` and `benign/` are gitignored, so a fresh checkout rebuilds from the
  preserved evidence.
- The **adopted source snapshot** (acquisition) was already settled; **dataset-use** of the
  source/content and the cross-pool precedence are now ratified by **D68** (§5). No re-acquisition.

## 2. Three states, kept distinct

### (a) Catalogue capability — implemented (uncommitted)
`names_family` is listed in `SLOT_POOLS["free_string"]`/`["json_leaf"]` (`v5_catalog.py`), so a slot
*may* declare it. This is an allow-list entry, not a value precedence and not a mandate.

### (b) Demonstrated generator consumption — implemented, synthetic (uncommitted)
`tests/test_v5_generator.py::NamesFamilyConsumption` builds an isolated synthetic World whose text
template has a `free_string` slot with `pools=["names_family"]`, loads a **nonempty** `names_family`
pool (250 synthetic stand-ins, each with its real `value_entry_id = sha256("names_family" NUL NFC(v))`),
runs `G.generate`, and asserts that admitted benign rows record pool provenance `names_family`, a
names_family-namespaced `value_entry_id`, and a value drawn from the loaded pool. It also asserts that
an **absent** pool (`{}`) or an **empty** pool (`{"names_family": []}`) raises `StopBuild`
(`POOL_UNAVAILABLE` / `POOL_TOO_SMALL`) with **no silent substitution**, and that real-build gates stay
blocked. This replaces the earlier membership-only check (`pools["names_family"] = {}` in
`test_names_family_loaded_clears_only_d64_c`), which demonstrates the `D64_C` precondition clearing on
key membership — **not** a loaded, usable pool. An empty dict is the precondition signal, not a pool.
The global `FIXTURE_POOLS` are untouched, so every existing reproducibility fixture stays byte-identical.

### (c) Pending real-data integration — NOT done (owner-gated)
No real-World loader for `benign/names_family.jsonl` exists; the real split config `pools` +
`value_pool_precedence` are not set; `real_build_preconditions` still returns
`REAL_SPLIT_NOT_AUTHORIZED`, `D64_B_POST_FILTER_AUDIT`, `PREREGISTRATION_MISSING`, `VALUE_NOT_RATIFIED`.
The per-split ≥20 minimum is enforced by `v5_split.py` (`POOL_TOO_SMALL`/`StopBuild`, never lowered)
but is only **verified on execution** of a gated real build — it is not asserted here and must not be
described as "trivially satisfied".

## 3. Cross-pool equivalence — recomputed with the real `dedup_value_pools` (NFC + casefold, D-3)

Input (ACCEPTED records per pool; file SHA-256 prefixes): names_given 26,050 (`ea998f97…`),
names_family 12,104 (`7d65ea2c…`), prose_en 34,048 (`f378cb61…`), streets 12,604 (`316cd7a8…`),
symbols 295 (`eb149ef6…`). Total input 85,101. `dedup_value_pools` keeps one representative per
NFC+casefold group across **all five** pools by `(pool rank, smallest value_entry_id)`.

| order | names_given | names_family | prose_en | streets | symbols | total kept | excluded |
|---|---|---|---|---|---|---|---|
| **A** `symbols>streets>names_given>names_family>prose_en` | 26,029 | **11,311** | 34,045 | 12,572 | 295 | 84,252 | **849** |
| **B** `symbols>streets>names_family>names_given>prose_en` | 25,247 | **12,093** | 34,045 | 12,572 | 295 | 84,252 | **849** |

**Key correction.** The **excluded total (849) and total unique coverage (84,252) are invariant** to
the A/B order — precedence **redistributes representatives**, it does **not** increase unique coverage.
The A→B swap moves **782** representatives between `names_given` and `names_family`. Under the approved
Option B `names_family` keeps 12,093, losing only **11** — its **8 internal casefold duplicates** plus
the **3 values that collide with `symbols`** (`o'brien/o'connor/o'neil`), which outranks it. Under A it
keeps 11,311, additionally losing the 782 it shares with the then-higher-ranked `names_given`.
`symbols` (rank 0) and `streets` (rank 1) outrank both name pools in both orders, and `prose_en` is
**last** in the approved order — so each of their losses (`symbols` 0, `streets` −32, `prose_en` −3) is
independent of the names' relative order; only the names_family↔names_given share shifts. This
reproduces the owner's independent check exactly. (My earlier pairwise "783 / 6.5% vs 3.0%" framing was
wrong and is superseded.)

## 4. ß/ss equivalence — actual groups and representative choices

Across all pools there are 34 ß/ss equivalence groups (casefold maps `ß`→`ss`). Only **2** involve
`names_family`, and both are **internal** to it (no cross-pool ß/ss collision with another pool):

| equivalence key | members (both `names_family`) | kept by content-hash tie-break | excluded |
|---|---|---|---|
| `steinbeisser` | Steinbeißer, Steinbeisser | **Steinbeißer** (ß) | Steinbeisser |
| `fuss` | Fuß, Fuss | **Fuss** (ss) | Fuß |

The tie-break is content-hash deterministic (it keeps the ß-form in one group and the ss-form in the
other) — a deterministic representative choice for split-contamination control, **not** a claim that the
variants are linguistically or semantically interchangeable. **D68 ratifies this scoped handling for
these two `names_family` groups**: retain the content-hash representative, preserve the source variants
and record the excluded variant in the exclusion ledger. The broader cross-pool ß/ss and ß-tie-break
*semantic* policy stays open (D64 §3) and is not resolved here; non-ASCII counts alone do not resolve it.
(`names_family` has 6 ACCEPTED values
containing ß in total.)

## 5. DR-75 — RATIFIED by D68 (owner, 2026-10-21)

1. **Value precedence — Option B ratified** for these five pools only:
   `symbols > streets > names_family > names_given > prose_en`. Retained: names_family 12,093,
   names_given 25,247, prose_en 34,045, streets 12,572, symbols 295 = 84,252 kept, 849 excluded
   (identical total to Option A; the swap moves 782 representatives). It assigns precedence to no
   further pool. Recorded in `REAL_VALUE_PRECEDENCE` (`v5_split_checks.py`) and the stage-3 report.
2. **Dataset-source use — approved**: the pinned `LIMIT 20000` Q101352 snapshot (`039882…`) and its
   12,104-value pool are approved as a source of values for dataset construction, subject to the
   existing validation/eligibility controls; the arbitrary-subset limitation, provenance and archived
   snapshot are preserved; not reacquired. This does **not** mark rows VERIFIED, authorize a real build,
   freeze a dataset or permit training.
3. **ß/ss — approved**: retain the content-hash representative for the two internal `names_family`
   groups (`Steinbeißer` kept; `Fuss` kept), preserving source variants and the exclusion ledger.
   Equivalence for split-contamination control is not a claim of semantic interchangeability; not
   extended to other pools.

## 5b. #75 acceptance evidence vs the broader #82 build requirements (#75 stays OPEN)

D68 settles the #75 policy items (precedence, source-use, ß/ss). Keep two scopes distinct.

**#75 acceptance evidence (this batch).** Pinned snapshot + SHA-256 + licence + byte-identical rebuild
(done); ratified cross-pool precedence (D68); `POOL_UNAVAILABLE` / no silent substitution, demonstrated
in the generator; the ≥20-per-split minimum enforced in code. The *executed* ≥20-per-split verification
runs on the real build, which is #82 scope. This batch reads no protected data and does **not** access
INTERNAL TEST.

**#82 real-data build/pilot requirements (not this batch, owner-gated).**
- The post-filter audit complete and payloads adjudicated (R3 + #77), no `PENDING_ADJUDICATION`.
- A **real-data pool loader** for `benign/names_family.jsonl`. Reading and unit-testing such a loader is
  a bounded step that is **distinct from executing a real split** and need not touch INTERNAL TEST; it is
  **not implemented in this pass** and is deferred to #82 (or a scoped precursor).
- The dataset preregistration incorporating D68's precedence/source-use/ß-ss, plus the still-PENDING
  constants (WARN/BLOCK, L, oracle signatures, placement shares, length bins, quotas, token budget B,
  per-file cap, I-10 overflow policy).
- Every SPL/M/ENC/acceptance gate run and passing on the real build, including the ≥20-per-split minimum
  **executed** and SPL-6 under the ratified precedence; INTERNAL TEST read once behind its single-run
  guard — authorized only under #82's gates, never by this batch.
- Precedence for any additional configured pool (passwords, urls_*, rel_paths, addr_data) ruled.

## 6. Tests actually executed (2026-10-21, system `python3.12` 3.12.15)

- New `tests.test_v5_generator.NamesFamilyConsumption` (3 tests): consumption + provenance,
  absent-pool refusal, empty-pool refusal — **OK**.
- `tests.test_v5_generator`: **54 run, OK, 3 skipped**.
- Full `python3.12 -m unittest discover -s tests`: **1,347 run, OK, 141 skipped** (was 1,343 at the PR
  #79 merge; +4 added by this batch). Exit 0, zero FAIL/ERROR. Catalogue audit clean (41 templates).
- NOT run: `.venv-dataplane` / `.venv-analyzer` suites (gateway/shadow, out of scope for #75; counts
  overlap, do not sum). No model-quality or performance benchmark.

## 7. Architecture note (Fast Path prerequisites — correction)

Fast Path eligibility is **not** gated by framing alone. Verified framing evidence is **one** of
several prerequisites; the others include the **canonical-request integration** at the data-plane
adapter (#68), the **ratified canonical limits** (`MAX_DECODED_BODY`, token budget B — §11.2 PENDING)
and the **application/positive-rule policy** (#36/#38).

mitmproxy's `raw_content` is **message-body data, not the complete original wire framing**, so it
**cannot by itself establish R1** — CL/TE conflicts, duplicate/obsolete header forms and bare CR/LF live
in the request line and header block, not in the body. Where and how wire-framing evidence would be
observed and enforced on the deployed request path is **#68's design** (framing observation/enforcement).
This batch does **not** implement it and recommends no specific parser/control; `GatewayEvidence.framing`
is `UNAVAILABLE` by design today and stays so. A standalone fixture test is not equivalent to framing
verified on the deployed request path.

## 8. Limitations

- Collision/coverage/ß-ss figures were computed on the local gitignored artifacts; they reproduce the
  owner's independent check exactly, which cross-checks them, but a fresh checkout needs the preserved
  evidence to reproduce them.
- Precedence, dataset-use approval and the ß/ss policy are owner decisions; no code change satisfies the
  "ratified cross-pool precedence" criterion of #75.
- The per-split ≥20 minimum is enforced in code but is verified only on a gated real build (not run).
