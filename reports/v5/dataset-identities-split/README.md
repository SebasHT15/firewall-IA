# V5 stage 3 — dataset identities, grouping and deterministic split (issue #72)

**Date:** 2026-10-14 · **Branch:** `feat/v5-dataset-builder` (from `develop` = `a897284`) · **Spec:**
`V5-DATA-SPEC-r3` (FROZEN, D62), SHA-256 `f1580634d35d2baf10b99d7985f9bfb1e56ebc956326a58a61b665fc5958d9cb`,
verified before and after the work (`cd reports/v5/v5-data-spec-draft && sha256sum -c SHA256SUMS` → OK).
D56–D63, the frozen spec, the stage-1/2 code and filters, V4, its runtime and the gateway are unchanged.

**Status (2026-10-16): D64 APPROVED by the owner and recorded in `DECISIONS.md`; the stage-3 work is
READY FOR INTEGRATION** (not merged; issue #72 open until the owner closes it). This closes the stage-3
identity and split *contract*; it is **not** an approval of the V5 dataset. The owner's round-3 rulings
(short-key exclusions, value policy B, D-6 residual, hybrid I-8 with I-8b; I-6 and I-16 deferred) are
implemented and validated (§S). The §4.6 contract is tested on synthetic fixtures; the real-pool census is
diagnostic only (counts, no assignment persisted); no real split, pilot, rendering, label or training
exists. Still: `names_family` BLOCKED · deny-list PROPOSED · post-filter audit PENDING · payload
adjudication PENDING · cluster-share thresholds PROPOSED · real split NOT EXECUTED · V5 dataset NOT FROZEN.
*(Round-3 status before approval, kept: "READY FOR OWNER REVIEW — not closed … D64 is a draft (§S.13),
not recorded in `DECISIONS.md`".)* History is kept: sections 1–13 record
round 1, **§R** round 2 and **§S** round 3; where a later round changed something, the later section is
authoritative.

*(Round-2 status line, kept: "the §4.6 contract is implemented and tested on synthetic fixtures; the
real-pool census is diagnostic only"; open items then listed in §R.11.)*

## 1. Files

| File | Role |
|---|---|
| `scripts/dataset/v5_identities.py` | identities: `payload_family_id` (+ families, explicit merges), `template_id`, `struct_cluster_id` (declarations, merges, template near-duplicate audit), `pair_id`, per-row RNG, the near-duplicate primitives; re-exports stage 2's `value_entry_id` |
| `scripts/dataset/v5_split.py` | config validation, ranks, cuts, steps 1–3 (clusters, families + E6, value entries), evaluability, the partition / membership contract, step-5 cluster shares, deterministic artifacts. **Standard library only** (SPL-5) |
| `scripts/dataset/v5_split_checks.py` | gates SPL-1…SPL-9, the synthetic fixture, CLI `fixture` / `determinism` / `census` |
| `tests/test_v5_identities.py` | 25 tests |
| `tests/test_v5_split.py` | 45 tests |
| `census_summary.md` (this folder) | generated real-pool census, counts only |

Generated artifacts live under `datasets/v5_sources/stage3/` (gitignored).

**Reused, not re-implemented:** `parse_dataset_v4.canonical_key` (D16), `v5_pools_common.value_entry_id` /
`nfc` / `sha256_file` / `write_json` / `read_jsonl` / `assert_not_protected` / `check_python` (stage 2),
`v5_dataset_checks.find_duplicates` / `check_group_disjointness` (#64). The near-duplicate word
representation follows `scripts/external/phase_d_gate.py` (cited by C L6; re-stated, not imported, because
that module belongs to the External v1 gate).

## 2. Architecture

```
stage-2 attack records ──► v5_identities.build_families ──► Family(pfid, categories, native_forms,
  (ACCEPTED, PENDING)          (canonical_key reused,         members, merged_from, canonical_keys)
                                declared merges first)                          │
template declarations ───► v5_identities.resolve_clusters ──► ClusterTable ───┤
  (TemplateSkeleton → template_id)   (declared merges, near-dup audit)          │
stage-2 value pools ─────► value_entry_id (stage 2) ───────────────────────────┤
                                                                                ▼
                     v5_split.build(config, ClusterTable, families, values)  ── identities only
                        step 1 clusters · step 2 families + E6 · step 3 values
                        → SplitAssignment: partition(split), assert_row(row), manifest
                                                                                ▼
                     v5_split_checks: SPL-1…SPL-9 gates · fixture · determinism · census
```

`v5_split.py` imports only `__future__, hashlib, json, os, re, collections, dataclasses, fractions, typing`;
a static test fails on anything else (renderer, tokenizer, template, `canonical_key`, identity builder).
No module calls `canonicalize`, so stage 1's I9 static check stays clean.

## 3. Interpretations where the frozen text is silent (for the owner's ruling)

> **Round 1 record.** Superseded in round 2: I-1 (digit runs, D-5), I-2 (§4.3 redirect forms, D-6), I-5 (4-grams, D-1), I-13 (records excluded upstream, D-4), I-15 (NFC + casefold and pre-split deduplication, D-3); ratification status of every item in §R.1.


The frozen text was followed literally wherever it speaks. These are the points it leaves open. Each is
implemented in one place, named in the code, and changeable without touching anything else.

| # | Point | Implemented | Alternatives | Evidence / effect (census §9) |
|---|---|---|---|---|
| I-1 | "digits → `0`" | each ASCII digit → `0` (literal text) | digit runs → one `0` (pre-freeze proposal G §2.1) | families change only for 2–3-digit numbers: CmdI 397→392, SSRF 130→129, SSTI 334→333, XSS 378→377, path 1469→1466 |
| I-2 | what a "host" is | e-mail; IPv6 (bracketed, or with `::` / 7 colons); IPv4 as 4 dotted parts (decimal, octal, `0x`); in URL-authority position (after `//` or `\\`, RFC 3986 §3.2.2) a dotted reg-name (trailing dot and non-ASCII labels allowed), `localhost`, or a single all-digit / `0x` label (integer IPv4 forms). A bare dotted word outside a URL is **not** a host. Lexical limits: `dead::beef` is masked (valid IPv6 syntax); `curl evil.com` is not | mask every dotted word (collapses `php.ini`, `document.cookie`, `java.lang.Runtime`: measured as the most frequent dotted words in the pool); a TLD allowlist (an invented list; `.py`, `.pl`, `.sh` are real ccTLDs) | host masking: Open Redirect 202→128 families, SSRF 148→126 (stratum 122); 518 records carry `H` |
| I-3 | "character runs > 3 → 3" | one character repeated ≥ 4 times → 3 copies (so `....//` → `...//`); repeated substrings (`../../`) untouched | — | — |
| I-4 | `template_id` skeleton | G §2.1: method, carrier, media type, path segments, ordered (positional key path, value type); key paths are positions or `[]`, never names (refused) | — | contract only: no template exists |
| I-5 | SPL-9 / template audit representation | phase_d_gate words `[a-z0-9]{3,}` of each member `canonical_key`; families are near-duplicates if any member pair is; templates: tokens of the skeleton | character n-grams; the family key (rejected: whitespace removal glues words together, found while testing) | **decisive**, see B-1. 446 member keys (413 families) have no word and cannot be compared |
| I-6 | `pair_id` | `sha256(SALT NUL "pair" NUL split NUL cluster NUL quota NUL i)`, the row-RNG coordinates; coordinates containing `\|` or NUL are refused (two tuples could give one RNG string) | an id drawn by the generator | contract only |
| I-7 | category vocabulary for "lexicographically first category" | stage-2 `dedup_scope` (V4 category, traversal + inclusion = `path_file_access`, D49); Python code-point order | D47 categories (merge NoSQL / CRLF / XPath into `other_attack`, against §2.3's per-category evaluability) | 16 multi-category families; e.g. 7 XPath families have stratum SQL Injection |
| I-8 *(superseded: hybrid reading, §S.5)* | evaluability inside the step-2 attempts | attempts decide on the **stratum's own** families; the reported per-category flag (SPL-8) counts every family occurring in the category | a global fixed point (circular: strata depend on each other) | both are reported; they differ only through multi-category families |
| I-9 | step-5 rebalancing | share computation + WARN/BLOCK classification from the config's PROPOSED thresholds; **rebalancing not implemented** | — | needs the generator's quota model and an integer redistribution rule the text does not fix |
| I-10 | ENC-5 overflow ("reserve equals them … or ENC-5's alternative") | the config must name `reserve_equals_forced` or `enc5_retire`; `null` stops the build when overflow happens | a default | no overflow in the census (XSS: 18 forced ≤ R = 30) |
| I-11 | SPL-7 "no … variant appears in any split" | SPL-9 treats `E6_RESERVE` as a fourth partition, so a reserve family may not have a near-duplicate in any split | only exact family membership | stricter; reported separately |
| I-12 | form of `payload_family_id` | the normalised key itself (the text defines no hash for it) | a hash of the key | — |
| I-13 | empty family key | refused, all offenders listed | one family `""` | 2 ACCEPTED stage-2 records have an empty `canonical_key` (B-3) |
| I-14 | two name pools (owner ruling, stage-2 closure) | `names_given` and `names_family` are separate pools with their own `pool_id` in `value_entry_id`, partitioned separately; the same string in both pools gets two ids, so SPL-6 checks exact and canonical values **across** pools | one shared names pool id | `names_family` BLOCKED: nothing measurable yet; 3 exact / 5 canonical values already shared between `names_given` and `symbols` |
| I-15 | SPL-6 for values | exact (NFC) and canonical (`canonical_key`) value groups must not span splits; a violation fails the gate | a value-merge rule analogous to family merges (not in the text) | B-2 |
| I-16 | cluster spanning two strata after merges | refused (it would be ranked twice and could be fragmented) | — | — |
| I-17 | `master_seed` | required in the config and hashed; unused in stage 3 (§4.6 gives it no role beyond being hashed; the per-row RNG uses SALT only) | — | — |
| I-18 | order of the rules | the order the spec lists them: whitespace is removed after the run collapse, so `a a a a` → `aaaa` while `aaaa` → `aaa` | whitespace first | measured: SQL Injection 883→881 families; no other category changes |
| I-19 | Unicode normalisation of payloads | none beyond `canonical_key` (the text asks for NFC only in `value_entry_id`); ASCII digits only | NFC / NFKC before `canonical_key` | measured: 0 of 4,161 records change under NFC |

## 4. Identities and grouping

- **`payload_family_id`:** `canonical_key` → digits → hosts / IPs / e-mails → runs → whitespace, in the
  spec's order. Only `ACCEPTED` records; the stored `canonical_key` must equal `canonical_key(payload_wire)`
  (provenance integrity); duplicate record ids, unknown merge ids and one-id merges are refused.
- **Families.** One identity across categories. `categories` sorted; stratum = first; `native_forms` =
  union of the members' stage-2 `native_forms` (ENC-5). **Explicit merges** come from the config
  (`family_merges`), are applied before ranking, resolve transitively, and the merged id is the smallest
  member id. `build` refuses families whose merges differ from the config, so the config hash describes
  what was applied.
- **Near-duplicates.** Exact: an inverted index finds every pair sharing a word; Jaccard is compared as
  integers (`5·|A∩B| ≥ 3·|A∪B|`), checked against brute force. `propose_merges` returns union-find
  components as a **proposal**: the split never merges by itself.
- **`struct_cluster_id`.** Declared per template; declared merges (`cluster_merges`) resolve to the
  smallest member id; a template declared twice, an unknown merge id or a cluster spanning two strata is
  refused; undeclared near-duplicate templates in different clusters are reported and stop the build.
- **`value_entry_id`.** Stage 2's function, re-exported (`I.value_entry_id is C.value_entry_id`).

## 5. Split algorithm

- **Rank:** ascending hex `sha256(SALT NUL kind NUL id)`, kind ∈ {cluster, payload, value}; ties (never
  observed) by id. Duplicated or empty ids are refused.
- **Cuts:** `n_test = max(1, (20·n + 50) // 100)`, `n_val = max(1, (10·n + 50) // 100)`, TRAIN the rest;
  n < 3 → all TRAIN. Integers only: `round()` and float constants are absent (static test). Example where
  `round()` would differ: n = 25 → VALIDATION 3, `round(2.5)` = 2.
- **Step 1:** clusters ranked per carrier stratum of the config; n < 3 → `NOT_EVALUABLE_STRUCTURE`
  (also for a configured stratum with no cluster).
- **Step 2:** families ranked once on pfid, cut per stratum category (see §6).
- **Step 3:** value entries ranked per configured pool; every split needs ≥ 20 (n ≥ 195); a missing pool
  (`POOL_UNAVAILABLE`, e.g. `names_family`) or a small pool (`POOL_TOO_SMALL`) stops the build. Duplicate
  ids and pools absent from the config are invalid input.
- **Stop rule:** findings from every step are collected and raised together as `StopBuild`. Nothing is
  dropped, relaxed or fragmented.
- **Config** (`v5-split-config/v1`; now `v3`, §S.3): salt, shares, evaluability thresholds, E6 values, the value minimum
  and the near-duplicate threshold must restate the frozen values exactly (any difference is
  `InvalidConfig`); cluster-share thresholds must carry `status: "PROPOSED"`.
- **Contract for constructive generation (step 4):** `partition(split)` returns the split's clusters,
  templates, families per category (a multi-category family appears under each of its categories) and
  value entries per pool; `E6_RESERVE` is not a split and is refused. `assert_row(row)` raises on any
  identity outside the row's split (SPL-4); it never removes anything.

## 6. E6 reserve

Per stratum category with n families: `R = ceil(0.08·n)` = `(8n + 99) // 100`.
1. **Attempt 1** only if R ≥ 30. Native-form families are placed first; the rest of R is the lowest-ranked
   non-forced families. If forced > R, the config's policy applies (I-10). The remaining families are cut;
   accepted if remaining ≥ 100 and TEST ≥ 30 (reserve never counted).
2. **Attempt 2** without reserve; accepted if n ≥ 100 and TEST ≥ 30; note "no reserve: not defensible".
3. Otherwise `NOT_EVALUABLE`: every family in TRAIN.

Native forms of families that end outside the reserve are recorded as **ENC-5 retirements** per
category. The manifest lists the reserve identities, the categories without reserve, the merges and the
retirements. Boundaries tested: n = 363 (R = 30, attempt 1) / 362 (R = 29, attempt 2); n = 148 (TEST 30) /
147 (`NOT_EVALUABLE`); forced overflow with each policy; attempt 1 rejected after a large reserve.

## 7. Invariants

| ID | Implementation | Fixture result | Injected violation (A5) |
|---|---|---|---|
| SPL-1 | rebuild from shuffled declarations, records, merge groups and pools (5 permutations) | PASS, 1 distinct hash | — (identity of hashes) |
| SPL-2 | `fixture` in fresh interpreters, PYTHONHASHSEED 0 / 1 / 4242 / random, other cwd | PASS, byte-identical | — |
| SPL-3 | assignment table (one split per identity; templates follow clusters) + `check_group_disjointness` per kind on rows, value entries exploded | PASS | template and value entry copied into another split → FAIL |
| SPL-4 | `assert_row` on every row | PASS | reserve family + TEST value in a TRAIN row → 2 violations, rows untouched |
| SPL-5 | static import list of `v5_split.py` | PASS | temp module importing `canonical_request` flagged |
| SPL-6 | rows: text (exact + canonical), payload, values (NFC + canonical); pools: exact / canonical groups spanning splits; attack records: exact / canonical groups spanning splits | PASS | case-only text duplicate and value duplicate across splits → FAIL |
| SPL-7 | reserve never in a partition or row (+ I-11 via SPL-9) | PASS | reserve family in a row → FAIL |
| SPL-8 | flags recomputed from the assignment table alone | PASS | hand-set flag → FAIL |
| SPL-9 | exact Jaccard ≥ 0.60 between member keys of families in different partitions (incl. E6) | PASS | 150 near-duplicate pairs → FAIL; after adopting `propose_merges` → PASS |

**Scope of these results:** synthetic fixture (21 declared clusters, 20 after one merge; 40 templates;
661 families with variants; 2 pools). SPL-3, SPL-4 and SPL-6 on rows use small hand-drawn rows from the partitions (test helper, not
a generator). On a real build every SPL check must run again as a gate.

## 8. Reproducibility

> **Round 1 record.** Current commands, hashes and test counts: §R.9.


```
python3 scripts/dataset/v5_split_checks.py fixture --out datasets/v5_sources/stage3/fixture
python3 scripts/dataset/v5_split_checks.py determinism --out datasets/v5_sources/stage3/determinism
python3 scripts/dataset/v5_split_checks.py census --summary reports/v5/dataset-identities-split/census_summary.md
python3 -m unittest tests.test_v5_identities tests.test_v5_split -v
```

Final run (2026-10-14, after the review fixes). Four rebuilds — CPython 3.14.4 and 3.12.15, each with
`PYTHONHASHSEED` 0 and 31337 — gave identical bytes for every artifact:

| Artifact | SHA-256 |
|---|---|
| fixture `assignment.jsonl` | `73fa0edb294c02a8e61ce6d115aae95a45c0ef5001648cef17a98c15ad62266c` |
| fixture `manifest.json` | `34173bc45976078562e23bf9e287e977104e9152e4711e6a8f833c942f7e7c0e` |
| `census.json` | `6a2c016f1122335fd554b056287adae2c2ce1ad16ff1517e9d4a481df30f182f` |
| `census_summary.md` | `95217062bb45b588f73688696809c73fbb475347ad9195275c766fc968376f75` |
| `v5_identities.py` / `v5_split.py` / `v5_split_checks.py` | `2f0300d8…` / `7b9417ed…` / `46367bf3…` (full values in the fixture manifest `code_sha256`) |

`determinism` (SPL-1: 5 shuffled rebuilds; SPL-2: 4 fresh interpreters, PYTHONHASHSEED 0 / 1 / 4242 /
random, other working directories) passed on both interpreters. The fixture manifest records the config
hash, the full config, the E6 reserve identities, merges, ENC-5 retirements, the stratum outcome vs the
final flag per category, the gate results and the code hashes.

**Tests (final):** `test_v5_identities` 25 + `test_v5_split` 45 = 70, OK on 3.14.4, 3.12.15 and
`.venv-dataplane` (3.12.15). Regressions: stage 1/2 + checks + phase-D gate suites 448 OK (15 skipped)
on 3.14.4 and 450 OK (14 skipped) on 3.12; data-plane venv 349 OK (1 skipped, including `test_data_plane`
and `test_request_features`); V4 representation / inference / tokenizer suites on python3.12 132 OK
(21 skipped, pre-existing). Stage 1's I9 static check passes (no module calls both `canonicalize` and
`canonical_key`).

## 9. Real-pool census (counts only; `census_summary.md`)

> **Round 1 record** (pool of 4,163 records, rules v1, word representation). B-1, B-2 and B-3 were acted on in round 2; before/after figures in §R.6. `census_summary.md` is the round-2 census.


Inputs: stage-2 `attack_pool.jsonl` (4,163 records, all `PENDING_ADJUDICATION`) and the benign pools.
The step-2 figures are **projections**: the same function run in memory, only counts kept. They come
before the post-filter audit, the final deny-list, any merge and `names_family`. They are not
evaluability results.

### 9.1 Facts

- 3,807 families from 4,161 records (2 have no family, B-3); 16 multi-category; 29 with a native
  held-out form.
- Step-2 projection before merges: attempt 1 with reserve for SQL Injection (882, R = 71), XSS (374,
  R = 30, exactly at the threshold; 18 forced native-form families), Command Injection (397) and
  `path_file_access` (1,467); attempt 2 for SSTI (333, R = 27); `NOT_EVALUABLE` for CRLF, NoSQL, Open Redirect, SSRF and XPath — matching §2.3's
  "expected NOT EVALUABLE" rows, now computed.
- Value pools: every built pool meets ≥ 20 per split; `names_family` BLOCKED.

### 9.2 Findings that block a real build (owner rulings needed; nothing was changed)

- **B-1 — SPL-9 with the I-5 representation merges large components.** 25,510 near-duplicate family
  pairs form 331 components holding 2,578 families. Since a component that spans two partitions always
  has a crossing pair, SPL-9 holds only if each component sits in one split, which amounts to merging
  it. The largest component holds 455 `path_file_access` families (31.0% of the stratum; words such as
  `etc`, `passwd`). Open Redirect has 90 of 128 in one component, SSRF 53 of 122. If every component were
  merged: 1,560 families; Command Injection → `NOT_EVALUABLE` (147 < 148); SQL Injection (362, R = 29) and
  XSS (214) lose the reserve; only `path_file_access` keeps one. The representation (I-5) therefore decides
  evaluability and needs a ruling before any real build. This reproduces the D60 concern (33% at
  Jaccard 0.6 on V4 templates).
- **B-2 — canonical value duplicates.** `names_given` has 18 groups (36 values) that differ only by case,
  e.g. `MacKinnon` / `Mackinnon`; `prose_en` 3 groups; 5 canonical keys are shared by `names_given` and
  `symbols` (3 exactly). Ranked independently, such pairs usually land in different splits, and SPL-6 then
  stops the build. Options: a value-merge rule (not in the frozen text), or deduplicating the pools by
  `canonical_key` (a stage-2 selection change). Both need the owner.
- **B-3 — two ACCEPTED records without a family.** `%0a%0d` (Command Injection) and
  `/* Cassandra Comment */` (SQL Injection) have an empty D16 `canonical_key`, so no family can be defined
  (I-13). `build_families` refuses them; the census leaves them out and lists them.
- **B-4 — `names_family` BLOCKED.** Any configuration that lists it stops with `POOL_UNAVAILABLE`;
  everything else works without it.

## 10. Inherited items (stage 2), verified 2026-10-14

| Item | State | Stage-3 relation |
|---|---|---|
| `names_family` | **BLOCKED** (WDQS outage); no download attempted; no substitute | B-4; blocks step 3 only |
| XSS structural exclusions (~9 plausibly valid of 28 `literal_backslash_x` / `prose_sentence`) | unchanged; `literal_backslash_x` and the comment rules not touched | **impact measured:** the 9 rows form 8 family keys, 7 new; XSS would go 374 → 381 families, R 30 → 31; no step-2 outcome changes before or after merges. The two polyglot rows are near-duplicates (J = 0.73) of an existing family. A correction would add JS-escape vectors (coverage), not evaluability. It stays a separate proposal for the owner |
| Third-party deny-list | **PROPOSED**; no file removed; licences not declared verified | the census uses the current pool; family counts move when the list is finalised |
| Post-filter audit (§7) | **pending**; no payload VERIFIED; no category declared fit | every count above is pre-audit |
| Template / vocabulary / B = 415 | PROPOSED candidates | not used by stage 3 |

## 11. Limitations

> **Round 1 record.** Current residual risks: §R.10.


- Contract tested on synthetic fixtures; no real template, cluster declaration, row or generator exists.
- I-1…I-19 are open interpretations; I-2 and I-5 change family counts and evaluability.
- `pair_id` hashes the split, so SPL-3 for `pair_id` holds by construction at the identity level; it has
  teeth only on rows (a pair id copied into another split's row).
- `TemplateSkeleton` does not case-normalise the method or NFC the path segments; the template author
  declares them.
- The host regexes are quadratic on very long dotted / hex runs (about 0.6 s for 8,000 characters);
  payload-sized input is unaffected.
- 446 member keys (413 families) have no `[a-z0-9]{3,}` word, so SPL-9 cannot see their near-duplicates
  (mostly short SQLi / punctuation payloads).
- Step-5 rebalancing is not implemented (I-9).
- Python: verified on CPython 3.12.15 and 3.14.4 only (stage-2 interpreter control reused).

## 12. Relation to stage 4

Stage 4 (labels, oracle, attack-leaf operator) consumes `partition(split)` and `row_rng` / `pair_id` and
must call `assert_row` on every generated row and run every SPL gate (SPL-6 pool level and SPL-9 run as
gates, not inside `build`, because `build` sees identities only). Before a pilot build: the owner's rulings on I-1…I-19 and
B-1…B-4; the template catalogue with cluster declarations (`TemplateSkeleton` → `TemplateDecl`); the
final pool list in the config; the post-filter audit; `names_family`; the cluster-share thresholds and the
rebalancing rule in the preregistration.

## 13. Independent review

> **Round 1 record.** The SPL-2 limitation listed below was closed in round 2 (§R.8). Round-2 reviews: §R.12.


Three read-only reviews (Sonnet subagents; no file edits, no git operations), one per responsibility.
Every finding was reproduced by the coordinator before it was acted on.

| Review | Finding (severity) | Verified | Action |
|---|---|---|---|
| Split / E6 / leakage | stratum outcome and final flag can disagree, unreported; `categories_without_reserve` used the stratum outcome (MAJOR) | yes (probe: B NOT_EVALUABLE as stratum, EVALUABLE overall) | manifest `stratum_outcome_vs_final_flag` with `diverges`; reserve list from final counts; I-8 kept for the owner; test |
| | SPL-6 skipped the text check when a row lacked `text`; value check read a field rows may lack (MAJOR / MINOR) | yes | unreadable rows fail; values must align with value entries; tests |
| | SPL-7 only looked at the declared family id (MAJOR) | yes | family recomputed from the row payload; mismatch fails; tests |
| | SPL-9 passed families without member keys (MINOR) | yes | now fails; test |
| | cross-pool id check compared strings with tuples, so it was dead code (MINOR) | yes | fixed; test |
| | nested frozen values accepted `20.0`; `cluster_share` accepted `1/50`, `1e-2` (MINOR) | yes | strict type equality; decimal format; tests |
| | value canonical duplicates and SPL-9 are gates, not part of `build` (NOTE) | yes | documented (§12); B-2 |
| Stage-2 contract / tests | pool-level SPL-6 test was vacuous (both values in TRAIN) (MAJOR) | yes | searches for a straddling pair and asserts the failure |
| | SPL-3 table half was a tautology; rows tested two of five kinds; missing keys filtered out (MAJOR) | yes | table half now checks one partition per identity; all five kinds injected; missing identity fails |
| | SPL-1/SPL-5/SPL-6 lacked injected violations for some branches (MINOR) | yes | order-dependent ranking (patched) caught by SPL-1; `gate_spl5(path)` on three bad modules; payload and attack-record branches injected |
| | `--out` / `--summary` could overwrite stage-2 pools (MINOR) | yes | `guard_output` refuses `attack/`, `benign/`, `raw/` and protected paths; test |
| | small duplications (code hashes, assignment digest) (MINOR) | yes | `C.code_fingerprint` and one `assignment_bytes` helper |
| | SPL-2 cannot be shown to fire on a seed-dependent builder (MINOR) | yes | not fixed: needs a deliberately broken builder in a subprocess; recorded as a limitation |
| Identities | integer IPv4 forms, FQDN trailing dot and IDN hosts not masked in authority position (MAJOR) | yes | masked (within I-2); tests; census re-run (Open Redirect 130→128, SSRF 126→122) |
| | rule order makes spaced runs uncollapsed (MINOR/MAJOR) | yes | kept literal; I-18 with measured effect (2 SQLi families) |
| | no NFC before `canonical_key`; ASCII digits only (MINOR) | yes | I-19; measured 0 records affected |
| | `dead::beef` masked as IPv6 (MINOR) | yes | documented in I-2 (valid IPv6 syntax) |
| | lone surrogate raised `UnicodeEncodeError` at rank time (MINOR) | yes | `IdentityError` at family time; tests |
| | merge groups: duplicates, bare strings, non-str members accepted (MINOR) | yes | refused; tests |
| | templates without tokens skipped the near-duplicate audit (MINOR) | yes | refused; test |
| | I-3 alternative reading, `pair_id` SPL-3 vacuous at identity level, method case, regex cost (NOTE) | yes | §3 / §11 |

No reviewer found a contradiction with the frozen text, a leakage path from the E6 reserve, or a
determinism hazard.

---

## R. Round 2 — owner rulings and remediation (2026-10-14)

The owner reviewed the decision package (B-1…B-4, I-1…I-19) and authorized only the corrections below.
This round is **not** a general ratification of the interpretations or of the generator specification.
`V5-DATA-SPEC-r3`, D56–D63 and `DECISIONS.md` are unchanged; no D64 was recorded (draft in §R.13).

### R.1 Rulings and status

| Item | Ruling | Status after this round |
|---|---|---|
| I-5 / B-1 | **D-1**: SPL-9 = contiguous character 4-grams on the normalised family key, Jaccard ≥ 0.60 unchanged, whole components, explicit merges before ranking | IMPLEMENTED (§R.2). Keys shorter than 4 code points: BLOCKED, owner decision open |
| I-16 | **D-2**: not authorized to assign cross-carrier clusters; keep the explicit refusal | refusal kept; formal evaluation in §R.7 |
| I-15 / B-2 | **D-3**: prepare deterministic pre-split deduplication, NFC + casefold, frozen `value_entry_id` intact | IMPLEMENTED as a prepared step (§R.3); precedence and holds PROPOSED |
| I-13 / B-3 | **D-4**: exclude `%0a%0d` and `/* Cassandra Comment */` with an explicit, stable reason | IMPLEMENTED in the stage-2 builder (§R.4) |
| I-1 | **D-5**: each maximal run of digits → one `0` | IMPLEMENTED (`pfid-rules/v2`) |
| I-2 | **D-6**: only the URL / redirect forms of §4.3 | IMPLEMENTED (`pfid-rules/v2`) |
| I-3, I-7, I-11, I-12, I-17, I-18, I-19 | ratified provisionally | I-7: vocabulary now recorded in the config; I-19: stability measured in the census (0 records change under NFC) |
| I-6 | not ratified; review requested | analysis and proposal in §R.7; code unchanged |
| I-8 | keep the implementation; add a synthetic case where the readings differ | test added (§R.7) |
| I-4, I-9, I-10, I-14, I-16 | deferred | unchanged |
| B-4 | `names_family` stays BLOCKED | unchanged; no download, no substitute |

### R.2 D-1 — SPL-9 representation

- **Definition.** The **set** (not multiset) of contiguous 4-grams of **Unicode code points** (Python `str`
  slices, not UTF-8 bytes) of each pre-merge family key. Two families are near-duplicates when any pair of
  their pre-merge keys has Jaccard ≥ 0.60, compared exactly as integers (`5·|A∩B| ≥ 3·|A∪B|`). SPL-9 holds
  only if every connected component lies in one partition (TRAIN / VALIDATION / INTERNAL TEST /
  `E6_RESERVE`), which is what explicit merges of whole components before ranking achieve.
- **Keys shorter than 4 code points** have no 4-gram. They are **UNOBSERVABLE**: never padded, never
  compared with a smaller n, never silently passed. `gate_spl9` returns `BLOCKED_UNOBSERVABLE` (not PASS)
  while any exists. Real pool: 13 keys — `"--`, `'--`, `---`, `0` (SQLi), `&id`, `;id`, `id` (CmdI), `../`,
  three U+FFFD characters (path), `//H`, `/\H`, `\\H` (Open Redirect), `0*0` (SSTI). Alternatives for the owner: (a)
  exclude short-key families from TRAIN-eligible pools; (b) compare short keys by exact equality only
  (equivalent to declaring them unobservable); (c) boundary padding (`^key$`) for every key, which changes
  the representation ruled in D-1; (d) a reviewed, explicit merge list for these 13 keys.
- **n = 4 was chosen after a structural audit of the stage-2 attack pool** (component sizes, internal
  coherence, blind spots; round-2 decision package), **before any real split exists**. It was not chosen
  before the pool was known. Evaluability flags are the same for n = 4, 5, 6; only n = 3 differed.

Verification (all on the round-2 pool, 4,161 records):

| Check | Result |
|---|---|
| 1. Blindness of the 413 families | gone: every key of ≥ 4 code points has a representation; 13 short keys remain, reported and blocking |
| 2. Positive examples | traversal depths, `union all select …` column enumerations, `' or '1'='1' --` vs `#`, Mako `${self.module…}` chains: merged (`tests/test_v5_identities.py::Representation`) |
| 3. Negative examples | `php.ini` vs Apache `access.log`, `admin' --` vs a tautology, traversal vs `cat</etc/passwd`, XSS vs SSTI: not merged |
| 4. Component sizes | units after merging, by size — v1: 1 229 / 154 / 106 / 35 / 27 / 7 / **2 (>100)**; v2: 1 270 / 207 / 132 / 58 / 33 / 8 / **0** (sizes 1 / 2 / 3–5 / 6–10 / 11–50 / 51–100 / >100) |
| 5. Chaining | largest component 455 → 90; top-10 all single-category (v1: 4 mixed); SQLi components internal median J ≥ 0.94; `path_file_access` components (76, 60, 57, 36, 35) have median J 0.32–0.50 and 19–43% internal pairs < 0.3, but each holds one target concept (bare traversal sequences, Apache `access.log`, `httpd.conf`, …). Cross-category pairs 689 → 140 (OR↔XSS `javascript:` URIs, CmdI↔path `/etc/passwd`): merging them is leakage-conservative |
| 6. Injected SPL-9 failures | 150 near-duplicate pairs across splits → `FAIL`; after adopting `propose_merges` → `PASS` (150 two-member merges, no chaining); a near-duplicate of an E6 family in TRAIN → `FAIL` (I-11); short keys → `BLOCKED_UNOBSERVABLE` |
| 7. Census before/after | §R.6 |

### R.3 D-3 — value equivalence and pre-split deduplication

> **Partly superseded by §S.3 (policy B, round 3):** the `wasps` hold, "held groups fail closed", the loss
> figures (now 56 excluded, `prose_en` 3) and open item (1) below no longer apply. Kept as written.

- **Equivalence** `nfc_casefold/v1` = `NFC(value).casefold()`. `canonical_key` is no longer used for benign
  values (it URL-decodes `+`, so `O+` ~ `O`, `Disney+` ~ `Disney`; and `lower()` does not fold ß). No
  whitespace collapse: on these pools it adds 0 groups (NFKC and strip also add 0), while removing spaces
  would merge different values (`Ridgeway` / `Ridge Way`, `rock 'n' roll` / `rock'n'roll`).
- **Collisions** (real pools): 56 groups of 2 — `names_given` 18 (case variants; 2 share a Wikidata QID),
  `prose_en` 3, `streets` 32 (all `straße` / `strasse`, generated on purpose by the lexicon), across pools 3
  (`N'Diaye`, `O'Connor`, `O'Hara` in `names_given` and in `symbols` `apostrophe_surnames`). `O` / `O+` stay
  distinct.
- **Semantic review.** `wasps` / `WASPs` differ in meaning (insect vs acronym): **held**, not deduplicated.
  Case variants of names and sentences, and ß / ss, carry the same meaning.
- **Representative.** First by the configured pool precedence, then the smallest `value_entry_id`
  (content-defined; independent of file and input order, tested by shuffling). `value_entry_id` keeps its
  frozen formula; only which entries enter the split changes.
- **Precedence (RATIFIED by D68 for these five pools only):**
  `symbols, streets, names_family, names_given, prose_en` (Option B). The `symbols` vs `names_given`
  edge keeps its original rationale (the 3 cross-pool names are 3 of 15 `apostrophe_surnames` in
  `symbols`, 20%, against 3 of 80 apostrophe names in `names_given`, 3.75%, and `symbols` is the curated
  pool for that trait). The `names_family > names_given` edge was deferred to I-14 and is now ratified by
  D68; it redistributes 782 shared representatives (total unique coverage is invariant: 84,252 kept /
  849 excluded under either order). Pools beyond these five are not assigned a precedence. See
  `reports/v5/data-readiness/names_family-integration/README.md`.
- **Ledger.** Every excluded value keeps its pool, value, `value_entry_id`, `source_ref`, reason
  `value_equivalent_duplicate` and the representative's provenance; kept + excluded = input.
- **Loss** (real pools, four-pool stage-3 measurement, before `names_family`): 55 excluded —
  `names_given` 21 (apostrophe 3/80, hyphen 2/1215), `prose_en` 2, `streets` 32 (non-ASCII 17/1142: the
  hash tie-break drops the ß form in 17 of 32 pairs), `symbols` 0. Every pool still meets ≥ 20 per split.
  With `names_family` added under D68 Option B the total excluded is **849** across the five pools
  (names_family 11, names_given 803, streets 32, prose_en 3, symbols 0); see the integration report.
- **Pre-render check.** `pre_render_value_check` raises `StopBuild` (`VALUE_EQUIVALENCE_SPANS_SPLITS`) when an
  exact or equivalent group spans two splits; `fixture` runs it before writing anything, and SPL-6 uses the
  same equivalence. `build` itself still sees identities only (SPL-5).
- **SPL-3 / SPL-6.** Deduplication removes entries before ranking, so `value_entry_id` stays one-split
  (SPL-3) and exact / equivalent duplicates cannot straddle (SPL-6), except held groups, which fail closed.
- **Open for the owner:** (1) a hold only turns a possible leak into a stop: the `wasps` / `WASPs` pair would
  straddle with probability ≈ 0.46 under independent ranks (simulated today: same split), and keeping both
  deterministically together would need a value merge (r4) or an accepted exception; (2) whether ß / ss ties
  should prefer the non-ASCII member (coverage) instead of the hash; (3) the unexercised part of the
  precedence.

### R.4 D-4 — undefined identities excluded upstream

- New stage-2 step `e0`: a record whose D16 `canonical_key` is empty is EXCLUDED with
  `identity_undefined:empty_canonical_key` (D59 mapping `AUDIT_REJECT`, PROPOSED). Reason: no
  `payload_family_id` can be built (§4.6). It makes no claim that the payload is benign.
- Exactly two records changed: `39984cbf08fac821` (`%0a%0d`, Command Injection) and `a5e450af1f2ac579`
  (`/* Cassandra Comment */`, SQL Injection). Provenance kept; their mutual `also_in_categories` link is gone.
- Reconciliation: 39,451 = 4,161 ACCEPTED + 35,290 EXCLUDED; the other 39,449 records are byte-identical;
  no excluded record became ACCEPTED; all ACCEPTED are `PENDING_ADJUDICATION`; manifest hashes match the
  rebuilt files; only the Command Injection and SQL Injection ledger rows changed. `GENERATOR_VERSION`
  `v5-pools/1.2`. The general `empty` / `too_short` filters are unchanged.

### R.5 D-5 and D-6

- **D-5.** `sleep(5)`, `sleep(10)`, `sleep(99999)` share `sleep(0)`; separate runs stay separate
  (`order by 1,2,3` → `orderby0,0,0`); non-ASCII digits untouched (I-19).
- **D-6.** Host masking after a separator run (`//`, `\\`, `/\`, `\/\/`, with CR / LF / TAB inside) now
  requires **URL context**: start of the value, after `=`, a quote, a backtick or a space, or right after
  a scheme of two or more characters. This also corrects the round-1 rule, which masked any dotted word
  after `//` or `\\` anywhere (found by the round-2 review: `..//boot.ini`, `c:\\php.ini`,
  `alert(1)//document.cookie`). Added §4.3 forms: `/\h`, `\/\/h`, runs with CR / LF / TAB, `http:h` /
  `https:h` (dotted name or `localhost`), and an integer or `0x` host after the userinfo `@` of a URL.
  Unmasked by design: `php.ini`, `document.cookie`, `..\/boot.ini`, `?next=evil.example`, look-alike slashes
  (U+3031, U+FF0F), `http:80`. Effect on the pool: 44 keys changed — Open Redirect 41 (128 → 103 families
  with D-5), and 3 keys whose file names (`boot.ini`, `out.txt`, `a.txt`) v1 had masked. Known lexical
  limits kept: hex-letter `dead::beef` reads as IPv6 (0 real hits beyond `::1`); userinfo forms with a
  second dotted host after `\@` or `#@` keep that host.

### R.6 Census before / after (counts only; nothing assigned)

| | Round 1 (v1 rules, words) | Round 2 (v2 rules, 4-grams) |
|---|---:|---:|
| ACCEPTED records / without family | 4,163 / 2 | 4,161 / 0 |
| Families before merges | 3,807 | 3,771 |
| SPL-9 family pairs / components / families in them | 25,510 / 331 / 2,578 | 17,049 / 438 / 2,501 |
| Largest component / families without representation | 455 / 413 | 90 / 13 short keys |
| Families after merging every component | 1,560 | 1,708 |
| Command Injection | 147 NOT_EVALUABLE | 182, attempt 2 (no reserve) |
| SQL Injection | 362, attempt 2 | 388, attempt 1 (R = 32) |
| SSTI | 193, attempt 2 | 234, attempt 2 |
| XSS | 214, attempt 2 | 271, attempt 2 |
| `path_file_access` | 508, attempt 1 (R = 41) | 434, attempt 1 (R = 35) |
| CRLF / NoSQL / Open Redirect / SSRF / XPath | NOT_EVALUABLE | NOT_EVALUABLE (19 / 45 / 38 / 78 / 19) |
| Value equivalence groups / excluded / held | 26 (`canonical_key`) / — / — | 56 / 55 / 1 |

These outcomes are consequences of the ruled algorithm, not targets. They are pre-audit
(`PENDING_ADJUDICATION`), before the final deny-list and without `names_family`.

### R.7 I-6, I-8, I-16

- **I-6 (`pair_id`).** The current id hashes the generation coordinates, split included, so its
  cross-split check is true by construction. An **intrinsic identity exists without contradicting §4.6**:
  `pair_content_id = sha256(SALT NUL "pair-content" NUL template_id NUL canonical_json(ordered benign slot
  fillings as (slot position, pool_id, value_entry_id)))`, computed from identities only (SPL-5), before
  rendering, independent of the split. Proposal: keep `pair_id` for grouping a row with its twins and add
  `pair_content_id` as a check identity — a cross-split collision then shows that a template or value
  identity leaked (a data-dependent check, not a tautology), and a within-split collision shows a duplicate
  pair. Adding a check identity changes no frozen text. It needs the stage-4 slot model; not implemented.
- **I-8.** Implementation unchanged. New test `StratumVsGlobalEvaluability`: `cat_b` has 120 own families
  (TEST 24 < 30) and 200 families shared with `cat_a`. Stratum-local reading: NOT_EVALUABLE, all own
  families in TRAIN; a sequential "global" reading (reference computed in the test): evaluable; the final
  flag counts all occurring families (EVALUABLE) and the manifest marks the divergence. On the real pool the
  two readings coincide (≤ 7 foreign families per category).
- **I-16, formal evaluation.** §4.6 step 1 ranks clusters "within each carrier stratum", which presupposes
  one stratum per cluster, and the template audit requires near-duplicates to be "merged in the
  declarations, never split" with no stratum qualifier. (a) Assigning a cross-carrier cluster to its first
  carrier changes which ranking places templates of the other carrier and the n used for their
  `NOT_EVALUABLE_STRUCTURE` flag: an addition to the frozen procedure. (b) Restricting the audit to
  same-stratum pairs weakens a frozen rule. Both would need an r4 or an explicit owner decision. The
  current refusal is the frozen stop rule (D60: "the build reports the problem and stops"). Whether real
  templates ever produce the conflict is measurable only in stage 4.

### R.8 SPL-2 negative test

`spl2_hashseed_independence(script=…)` runs any builder that accepts `--out` in fresh interpreters
(PYTHONHASHSEED 1 / 2 / 3, separate working directories). `SPL2Negative` writes, inside a temporary
directory only, a builder that patches `ranked` to `sorted(ids, key=hash)`: SPL-2 fails with more than one
distinct assignment. The real `fixture` entry point through the same harness passes. No defective code is in
any production module.

### R.9 Validation

Final run, 2026-10-14, after every round-2 fix.

| Check | Result |
|---|---|
| `test_v5_identities` + `test_v5_split` | 87 tests OK on CPython 3.14.4, 3.12.15 and `.venv-dataplane` (3.12.15) |
| Stage 1/2 + checks + phase-D suites (with stage 3) | 466 OK (15 skipped) on 3.14.4; 468 OK (14 skipped) on 3.12 |
| Stage-2 suites alone (`test_v5_attack_pool`, `_pools_closure`, `_benign_pools`) | 105 OK on both |
| Data-plane venv (canonical request, `test_data_plane`, `test_request_features`) | 366 OK (1 skipped) |
| V4 representation / inference / tokenizer (python3.12) | 132 OK (21 skipped, pre-existing) |
| SPL-1 (5 shuffled rebuilds) / SPL-2 (4 interpreters, seeds 0 / 1 / 4242 / random) | PASS on 3.14 and 3.12 |
| SPL-3…SPL-9 on the fixture | PASS (SPL-9 `PASS`, 0 unobservable keys); pre-render value check clean; 2 fixture duplicates removed |
| Rebuilds: 3.14 and 3.12 × PYTHONHASHSEED 0 / 31337 | 4 identical runs each: fixture `assignment.jsonl` `571a0a06c9ca13e4d359e9f4f42509e9193757fd6f000c4d983a012543e93c11`, fixture `manifest.json` `cd73042f1a632272bd5b9a6f8e7565c6e7913ebfc6c5f0f65dc43d6470610700`, `census.json` `33db1665cb7edcfcf48b43327ea4cc4d95b78e3e6ee1493a9b34f15439cc8f1a` |
| `census_summary.md` | `7c6c8fbe8226dc13cd7c63d3f801c20d71d96132596bb23c7e1bf58ad9a54a14` |
| Code | `v5_identities.py` `da786829…`, `v5_split.py` `9b9e7592…`, `v5_split_checks.py` `e21bc075…` (full values in the fixture manifest) |
| Stage-2 attack pool (rebuilt with `--check-determinism` on 3.14; again on 3.12 into a scratch directory) | `attack_pool.jsonl` `576c2a9060bb4937d063bd6d63e81a884717c74ca3e38071c742f8c0c542d38b`, `attack_excluded.jsonl` `a5cf2c9c59ad91a995c85dacb13c725199e8514c906689ea815523defb292b22`, identical on both; manifest hashes match; reconciliation regenerated byte-identically |
| Stage-2 benign pools | pool files byte-identical to round 1 on 3.14 and 3.12; the manifest differs only in the recorded interpreter version and the attack pin |
| `V5-DATA-SPEC-r3` | `sha256sum -c SHA256SUMS` → OK |

### R.10 Residual risks

- 13 unobservable short keys block SPL-9 until the owner rules (§R.2).
- `path_file_access` components still chain within one target concept (median J 0.32–0.50); merging is
  conservative for leakage and reduces family counts.
- Near-duplicates of values beyond NFC + casefold are not grouped (SPL-6 does not require it): prose
  sentences that differ by punctuation or one token (Tatoeba templates), name spelling variants of one QID
  (`Huệ` / `Huê`), diacritic variants.
- Held value groups fail closed but do not guarantee same-split placement.
- All counts are pre post-filter audit; the deny-list is PROPOSED; `names_family` is BLOCKED.
- Templates, slots, rows and the generator do not exist: I-4, I-6, I-9 and I-16 can only be settled with
  them.

### R.11 What keeps stage 3 open

> **Superseded by §S.12.** Items 1 and 2 were ruled in round 3; item 3 is partly ruled (I-8) and partly
> deferred (I-6, I-16). Kept as written.

1. Owner decision on the 13 unobservable short keys (§R.2).
2. Owner decisions on the value precedence, the `wasps` hold and the ß / ss tie-break (§R.3).
3. I-6 (`pair_content_id` proposal), I-8 ratification, I-4 / I-9 / I-10 / I-14 / I-16 deferred to stage 4 or
   to `names_family`.
4. No real split has been executed; every SPL gate must run again on the real build.

### R.12 Independent review (round 2)

Six read-only Sonnet reviews: three on the decision package, three on the remediation. Every finding
used here was reproduced by the coordinator first.

| Review | Finding | Verified | Action |
|---|---|---|---|
| SPL-9 / identities | 4-gram representation, integer comparison, gate statuses correct; all 17,050 pairs re-derived by brute force | yes | — |
| | `//` / `\\` host rule (round 1) masked dotted words anywhere (`..//boot.ini`, `c:\\php.ini`, `alert(1)//document.cookie`) — contradicts D-6 | yes | fixed: URL context required; tests; census re-run |
| | report stale against the code | yes | §R written; round-1 sections marked |
| | hex-letter IPv6 (`dead::beef`), second host in some userinfo forms, ASCII-only digits | yes | documented limits (§R.5) |
| | `path_file_access` components chain within one target concept; merging every proposed component lowers Command Injection / XSS to attempt 2 | yes | §R.2 check 5, §R.10; merges are a proposal, not applied |
| Value equivalence | 56 / 55 / 1 reproduced; casefold creates no false equivalence in these pools; whitespace non-collapse supported | yes | — |
| | census silently filtered unknown holds while the builder rejected them | yes | fixed; test |
| | a hold fails closed but does not guarantee same-split placement; ß / ss tie-break loses 17 / 1142 non-ASCII; precedence partly unexercised; near-duplicates beyond case remain | yes | open owner items §R.3, §R.10 |
| D62 conformance / negative tests | spec, D56–D63, runtime untouched; D-4 exact (2 records, 39,451 rows); SPL-2 negative test sound; I-8 test exercises a difference; I-16 refusal intact | yes | I-8 test now also asserts the manifest divergence flag |
| | dataset-foundation figures (4,163) and CONTEXT text stale | yes | dated addendum in `dataset-foundation/README.md`; CONTEXT updated |

### R.13 Draft decision text (NOT recorded; for the owner's approval)

> **Superseded** by the round-3 draft in §S.13. Kept as written.

> **D64 — V5 stage 3 owner rulings (draft).** Date 2026-10-14, issue #72. Status: PROPOSED.
> Records, without amending `V5-DATA-SPEC-r3`: (1) SPL-9 representation = set of contiguous 4-grams of
> Unicode code points of each pre-merge family key, Jaccard ≥ 0.60 as frozen, whole components merged
> explicitly before ranking; n = 4 chosen after a structural audit of the stage-2 pool and before any real
> split; keys shorter than 4 code points are unobservable and block SPL-9 pending a ruling. (2) `digits → 0`
> = each maximal ASCII digit run becomes one `0`. (3) Host masking extended only to the §4.3
> POL-REDIRECT-DIFF forms and userinfo integer hosts. (4) Attack records with an empty D16 `canonical_key`
> are excluded upstream as `identity_undefined:empty_canonical_key`. (5) Benign value equivalence for
> SPL-6 and pre-split deduplication = NFC + casefold, with a recorded pool precedence, held groups and a
> pre-render stop. (6) Provisional ratification of I-3, I-7, I-11, I-12, I-17, I-18, I-19; I-6 and I-8 not
> ratified; I-4, I-9, I-10, I-14, I-16 deferred; cross-carrier clusters stay refused.

---

## S. Round 3 — final remediation and closure preparation (2026-10-16)

Round 3 began with a read-only decision audit (no file changed; no report file was written for it). The
owner then authorized the corrections below in the session prompt of 2026-10-16; that prompt is the
record of the rulings. Every factual basis was re-checked against the code and the data before anything
was changed (§S.2–§S.5). This round is **not** a general ratification and does **not** close stage 3:
D64 (§S.13) awaits the owner's approval and Git integration. `V5-DATA-SPEC-r3`, D56–D63,
`DECISIONS.md`, V4, its runtime and the gateway are unchanged.

### S.1 Rulings and status

| Item | Owner ruling (round 3) | Status after this round |
|---|---|---|
| 13 short family keys (20 records) + 2 observable table borders | exclude from the V5 training pool with specific, stable reasons; legitimate but unobservable payloads → `identity_unobservable_spl9`; table borders → `not_a_payload:result_table_border`; no change to Jaccard or n; no `PASS_DECLARED_UNOBSERVABLE` regime | IMPLEMENTED in the stage-2 builder (§S.2) |
| `wasps` / `WASPs` | policy B: hold removed; NFC + casefold on every group; current deterministic representative (keeps `wasps`); `WASPs` excluded with the semantic difference recorded | IMPLEMENTED (§S.3) |
| D-6 residual | mask the integer / `0x` host of `http:3627734734` / `http:0xd83ad6ce` (§4.3), minimal change | IMPLEMENTED, `pfid-rules/v3` (§S.4) |
| I-8 | hybrid reading, conditional on D62 conformance | IMPLEMENTED; no contradiction found (§S.5) |
| I-16 | keep the refusal; carrier-qualified tokens documented as a candidate only | unchanged (§S.6) |
| I-6 | `pair_content_id` not implemented, not in SPL-3, not blocking; candidate contract for stage 4 | documented only (§S.6) |
| `symbols > names_given` | candidate backed by the round-2 analysis; no global precedence ratified | unchanged; an unratified precedence that blocks a real build stops it |
| ß / ss | keep the current tie-break provisionally; document impact | unchanged; impact §S.3 |

### S.2 Short keys and table borders (identity admissibility, stage-2 steps e1–e3)

**Verification before the change** (pool `576c2a90…`, 4,161 ACCEPTED): the 13 keys shorter than 4 code
points carried 20 ACCEPTED records and 7 duplicates; 4 of the 20 were MySQL result-table borders
(`+----…+`, key `---`); two more borders (`+-----------+----…+`, key `------`; the six-column border, key
`------------------`) have keys long enough for SPL-9 and were near-duplicates of each other. All borders
come from `SQL Injection/MySQL Injection.md` (client output inside the README). Each record was read with
its source file and line.

**Rule** (`build_v5_attack_pool.py`, after D-4's e0 and **before** duplicate removal, so the whole canonical
group of an excluded record is excluded and no duplicate can take its place):

| Step | Test | Reason | D59 (PROPOSED) |
|---|---|---|---|
| e1 | `payload_wire` fully matches `\+(?:-+\+)+` | `not_a_payload:result_table_border` | `AUDIT_REJECT` |
| e2 | record listed in `REVIEWED_DEGENERATE` (9 record ids reviewed one by one, each with the family key it was reviewed under; a changed key stops the build; an unlisted record never inherits the reason) | `identity_degenerate:digits_only_key` (`1/*'*/`, `1/*!1111'*/` → `0`), `identity_degenerate:command_separator_lost` (`%0Aid`, `%0Aid%0A`, `%0a id %0a` → `id`: the LF separator is removed with the whitespace), `not_a_payload:isolated_arithmetic` (`7 * 7` → `0*0`, no template delimiter that would justify BLOCK) | `AUDIT_REJECT` |
| e3 | any other family key shorter than 4 code points | `identity_unobservable_spl9` | `AUDIT_REJECT` |

`_check_no_readmission` refuses the build if any ACCEPTED record, in any scope and from any file, carries
the family key of an e1–e3 record. The family key is `v5_identities.family_key` (imported; the stage-2
manifest now hashes `v5_identities.py` and records `pfid_rules_version`, the border pattern, the reviewed
records and the counts under `identity_admissibility`). `GENERATOR_VERSION` `v5-pools/1.3`.

**Result** (pool `4c5d5869…`): 39,451 = **4,139 ACCEPTED** + 35,312 EXCLUDED. Exactly **49** records changed:
22 ACCEPTED → EXCLUDED and 27 duplicates whose reason changed from `duplicate_*` to the e1–e3 reason;
the other 39,402 records are byte-identical; **0** records became ACCEPTED; every ACCEPTED record is
`PENDING_ADJUDICATION`; no `also_in_categories` link changed. By reason: `not_a_payload:result_table_border`
24 (6 ACCEPTED + 18 exact duplicates), `identity_unobservable_spl9` 16 (13 + 3),
`identity_degenerate:command_separator_lost` 6 (1 + 5), `identity_degenerate:digits_only_key` 2 (1 + 1),
`not_a_payload:isolated_arithmetic` 1. Every row, with provenance, is listed in
`reports/v5/dataset-foundation/attack_pool_reconciliation.md` §4.

**Coverage loss (stated, not hidden).** The 13 `identity_unobservable_spl9` ACCEPTED records are legitimate
payloads, now absent from the training pool. They are **not** declared benign. Lost concepts: short SQLi
comment terminators (`' --`, `" --`, `Auth_Bypass2.txt`), short command separators (`& id`, `; id`), the bare
traversal step in plain, double-encoded and overlong-UTF-8 form (`%2e%2e%2f`, `%252e%252e%252f`,
`%c0%ae%c0%ae%c0%af`; the latter decodes to three U+FFFD, an ambiguous identity), and scheme-relative open
redirects with a single host and nothing else (`/%09/h`, `/%5ch`, `\\h`; 7 records). Longer variants of
each concept stay in the pool (for example `' or 1=1 --`, `;cat /etc/passwd`, `../../etc/passwd`,
`/%5cevil.example/login`). None of the 22 ACCEPTED records had an ENC-5 native form; 9 were `pre_encoded`.
ACCEPTED per category: SQL Injection 929 → 920, Open Redirect 219 → 212, Command Injection 425 → 422,
Directory Traversal 172 → 170, SSTI 335 → 334. The evaluability flags do not change (§S.8).

### S.3 Value policy B (`wasps` / `WASPs`)

- `dedup_value_pools(pools, precedence, semantic_notes)`: the round-2 `holds` argument and the config key
  `value_equivalence_holds` are removed (config schema `v5-split-config/v3`; a v2 config or the old key is
  refused). NFC + casefold now deduplicates **every** group with the current rule: pool precedence, then the
  smallest `value_entry_id`.
- `wasps` is kept because the current rule selects it (`d8cfc83a…` < `fd9e7ff1…`; both in `prose_en`); the
  rule was not changed to obtain this. Shuffled inputs give the same result (test).
- `semantic_notes` (config `value_equivalence_semantic_notes`) changes only the ledger, never the selection
  (test: the kept set is identical with and without the note). The excluded `WASPs` row carries
  `exclusion_reason = value_equivalence_policy:split_contamination_guard`, `synonym: false` and the note
  "not synonyms: 'wasps' is the insect, 'WASPs' the acronym …; excluded only by the NFC + casefold
  equivalence policy that keeps equivalent values out of two splits", plus its pool, value,
  `value_entry_id`, `source_ref` and the representative's provenance. A note naming a key that is not a
  group of 2+ values, or an empty note, is refused.
- Real pools: 56 equivalence groups, **56 excluded** (55 `value_equivalent_duplicate` + 1 policy), kept +
  excluded = input in every pool; `prose_en` 34,048 → 34,045; every pool still ≥ 20 per split; `O` / `O+`
  distinct; no whitespace collapse; `value_entry_id` unchanged.
- ß / ss (provisional, decision pending): the `streets` lexicon generates 32 `straße` / `strasse` pairs; the
  hash tie-break keeps the ß form in 15 pairs and excludes it in 17 (flag loss `non_ascii` 17/1142; one pair
  also costs a hyphenated value, `has_hyphen` 1/1070). The tie-break and the identifier formula are unchanged.
- Precedence `symbols > names_given` (3 cross-pool names) was the analysis-backed candidate; **D68**
  (2026-10-21) ratifies the full five-pool order (Option B, `names_family` above `names_given`).
  Precedence for pools beyond these five is still unexercised and unratified; a real build whose
  configuration needs an unratified precedence must stop. This is a condition of the real build
  (§S.13 (f)); stage 3 has no real build, so no code enforces it yet (`validate_config` checks only that
  the precedence lists every configured pool).
- The real note is the constant `REAL_VALUE_SEMANTIC_NOTES`; the real-build configuration must carry it in
  `value_equivalence_semantic_notes`, so it is hashed with the config.

### S.4 D-6 residual — integer host after `http:`

- `_PLAIN_SCHEME_HOST` now uses the same host forms as the authority position (`_HOST`: dotted name,
  `localhost`, a single all-digit label or a `0x` label). Contract: §4.3 POL-REDIRECT-DIFF `https:h` with a
  POL-URL-OBFUSCATED dword / hex host. Nothing else changed: URL context, separator runs and the userinfo
  rule are as in round 2.
- **Measured effect:** exactly **2** ACCEPTED identities change — `http:0xd83ad6ce` (`http:0xd0ad0ce` →
  `http:H`, record `9cbad61e0d8948a1`) and `http:3627734734` (`http:0` → `http:H`, record
  `0ec58fa6a466d3c7`); both join the existing family `http:H`; families 3,771 → 3,769; SPL-9 pairs
  unchanged by this step (17,049).
- **Behaviour change to note:** `http:80` is now `http:H`. After D-5 every digit run is one `0`, so `http:80`
  and `http:3627734734` are the same key and cannot be told apart by any rule that follows the frozen order;
  a WHATWG URL parser also reads `http:80` as the host `0.0.0.80`, and `http://80/` was already masked in
  round 2. Round 2 listed `http:80` as unmasked by design; that test was changed. No pool record has this
  form.
- Still unmasked (tests): `php.ini`, `document.cookie`, `..//boot.ini`, `alert(1)//document.cookie`,
  `c:\\php.ini`, `x//0x1f`, `xhttp:123`, `http:12a`.

### S.5 I-8 — hybrid reading

- **Text (D62):** one identity per family, ranked once, assigned once, stratum = lexicographically first
  category, counted toward the evaluability of every category it occurs in; D60: evaluability "computed from
  real counts, after the reserve and partitioning".
- **Implementation** (`assign_families`): strata run in code-point order of the category. When stratum *c*
  runs, every family of *c* stratified elsewhere has an earlier stratum and is already placed. Attempts 1 and
  2 evaluate ≥ 100 / ≥ 30 on the stratum's own non-reserve families **plus** those foreign families in TRAIN /
  VALIDATION / INTERNAL TEST; a foreign reserve family never counts; each family is counted once per
  category. These are the counts SPL-8 uses, so the outcome cannot contradict the final flag; SPL-8 now also
  fails on any `stratum_outcome_vs_final_flag` divergence. A category whose families are all stratified
  elsewhere is reported as `no_own_stratum` with its counted evaluability.
- **R and the cuts** apply to the stratum's own families (interpretation **I-8b**, for the owner). The cuts
  are defined "for a stratum of size n" and cannot use the category's full count without re-cutting
  families already placed by earlier strata, which the ruling forbids; R is the one ambiguous quantity
  ("n is the number of families of the category after merges"). An "R on all occurring families" variant is
  implementable without moving anyone (reserve R_all minus the foreign reserve, drawn from own families), but
  it mixes two counts. Measured on the real pool by the round-3 review: it would change R by at most 1
  (before merges XSS 30 → 31, `path_file_access` 117 → 118, XPath 2 → 3; after merges SSTI 19 → 20, XSS
  22 → 23, `path_file_access` 35 → 36) and no outcome. Not a contradiction with the frozen text.
- **Tests** (`HybridEvaluability`): an evaluable case (120 own + 200 foreign: old reading NOT_EVALUABLE,
  hybrid attempt 2, own cuts unchanged); a reserve case (400 own, 300 forced, `reserve_equals_forced`: old
  reading attempt 2, hybrid attempt 1 with exactly the 300 forced families reserved); a not-evaluable case;
  foreign reserve families not counted (32 reserved of 400 shared → 368 counted); `no_own_stratum`; earlier
  strata unchanged by adding a later one; input-order independence; an injected outcome divergence fails
  SPL-8.
- **Real pool:** the hybrid and the stratum-local readings give the same outcome in every category, before
  and after merging every proposed component (≤ 7 foreign families per category). The ruling changes no
  real figure.

### S.6 Deferred: I-16 and I-6

- **I-16 (cross-carrier clusters):** the refusal stays (`resolve_clusters` raises when a resolved cluster
  spans two carrier strata). Not implemented: first-carrier assignment, a combined stratum, restricting the
  template audit to one carrier, exempting structures from SPL-9 / the template audit, carrier-qualified
  tokens. **Candidate (documented only):** template audit tokens qualified by carrier (`c:{carrier}|…`),
  which would make templates of different carriers non-comparable by construction — a change to the audit
  representation that needs a ruling. Stage 4 must present the real template catalogue; if two templates of
  different carriers reach Jaccard ≥ 0.60 and cannot be assigned validly, the build stops. No r4 is prepared.
- **I-6 (`pair_content_id`):** accepted conclusion — a collision of the candidate id already implies a shared
  template or value identity, which SPL-3 catches, so it gives no independent guarantee. Not implemented, not
  added to SPL-3, not blocking; the frozen `pair_id` is unchanged. **Candidate contract for stage 4:**
  `sha256(SALT NUL "pair-content" NUL template_id NUL canonical_json([(slot position, pool_id,
  value_entry_id), …]))`, computed from identities before rendering. Stage 4 must define the positional
  slots, the source identity of each value, the leaves that do not come from a pool, and the link between a
  benign row and its twins; only then can the id be specified and its use (diagnostic only) decided.

### S.7 SPL-9 pair reconciliation

Brute-force counts on the family keys (4-gram sets, `5·|A∩B| ≥ 3·|A∪B|`):

| Step | Records | Families (pre-merge) | Pairs | Components |
|---|---:|---:|---:|---:|
| Round 2 before the round-2 host fix (historical) | 4,161 | — | 17,050 | — |
| Round 2 (`pfid-rules/v2`) | 4,161 | 3,771 | 17,049 | 438 |
| + D-6 residual (`pfid-rules/v3`), same records | 4,161 | 3,769 | 17,049 | — |
| + e1–e3 exclusions (this round) | 4,139 | 3,754 | **17,048** | **437** |

The one pair lost is `------` ↔ `------------------`, the two observable table borders. The 13 short keys
had no 4-gram and were in no pair; `http:0` and `http:0xd0ad0ce` were in no pair. No count was adjusted.

### S.8 Census before / after (counts only; nothing assigned or persisted)

| | Round 2 | Round 3 |
|---|---:|---:|
| ACCEPTED records | 4,161 | 4,139 |
| Stage-2 identity exclusions (EXCLUDED, ledger) | 2 (`identity_undefined`) | 51 (2 + 49, §S.2) |
| Families before merges | 3,771 | 3,754 |
| SPL-9 pairs / components / families in them | 17,049 / 438 / 2,501 | 17,048 / 437 / 2,499 |
| Largest component | 90 | 90 |
| Unobservable short keys | 13 (20 records) | **0** |
| Families after merging every component | 1,708 | 1,692 |
| Before merges — attempt 1 (R) | CmdI 32, SQLi 71, XSS 30, path 118 | CmdI 32, SQLi 71, XSS 30, path 117 |
| Before merges — attempt 2 | SSTI | SSTI |
| After merges — attempt 1 (R) | SQLi 32, path 35 | SQLi 31, path 35 |
| After merges — attempt 2 | CmdI 182, SSTI 234, XSS 271 | CmdI 179, SSTI 233, XSS 271 |
| After merges — NOT_EVALUABLE | CRLF 19, NoSQL 45, OR 38, SSRF 78, XPath 19 | CRLF 19, NoSQL 45, OR 33, SSRF 78, XPath 19 |
| Final SPL-8 flags (both projections) | — | EVALUABLE: CmdI, SQLi, SSTI, XSS, path; NOT_EVALUABLE: CRLF, NoSQL, OR, SSRF, XPath |
| After merges: cross-partition SPL-9 pairs / unobservable keys | — | 0 / 0 |
| Value groups / excluded / held | 56 / 55 / 1 | 56 / 56 / 0 (1 by policy) |

E6 reserves defensible on these projections: before merges CmdI, SQLi, XSS (R = 30, exactly at the
threshold) and `path_file_access`; after merging every proposed component only SQLi (R = 31) and
`path_file_access` (R = 35). These are consequences of the ruled algorithm on a pre-audit pool
(`PENDING_ADJUDICATION`, PROPOSED deny-list, no `names_family`), not targets. Full table:
`census_summary.md`.

### S.9 Validation (2026-10-16, after every round-3 change)

| Check | Result |
|---|---|
| `test_v5_identities` + `test_v5_split` | 38 + 63 = **101 OK** (round 2: 87) |
| `test_v5_attack_pool` | 38 OK (3 new: admissibility, reviewed records, readmission) |
| Stage-2/3 core (identities, split, attack pool, pools closure, benign pools) | 209 OK on 3.14 and 3.12 |
| Stage 1/2/3 + checks + phase-D suites (16 modules) | **524 OK** (32 skipped) on CPython 3.14.4; **563 OK** (14 skipped) on 3.12 |
| Data-plane venv (canonical request ×4, `test_data_plane`, `test_request_features`, stage 3) | **380 OK** (2 skipped) |
| V4 representation, inference core, classifier API (python3.12) | **77 OK** (21 skipped, pre-existing) |
| SPL-1 (5 shuffled rebuilds) / SPL-2 (4 interpreters, seeds 0 / 1 / 4242 / random) | PASS on 3.14 and 3.12 |
| Fixture gates | SPL-3, SPL-5, SPL-6, SPL-7, SPL-8 (0 divergences), SPL-9 `PASS` |
| Rebuilds 3.14 / 3.12 × PYTHONHASHSEED 0 / 31337, byte-compared | fixture `assignment.jsonl` `571a0a06c9ca13e4d359e9f4f42509e9193757fd6f000c4d983a012543e93c11` (unchanged from round 2: no fixture identity is affected), fixture `manifest.json` `7d864477526b8a3c6eed5ff1f709336f2f62c6db6246c943086c99dbd5930fb5`, `census.json` `420ddc203f156bf0c918eaf71927c9c67e7e3acc5b7b765d2ee50efb5f53c991`, `census_summary.md` `509bcfa6b97c380f4ecefaf7ffd81415f36a6699ee8ea0d05d4d1e0a6157ba15` — 4 identical runs each |
| Stage-2 attack pool (3.14 with `--check-determinism`; again on 3.12 into a scratch directory) | `attack_pool.jsonl` `4c5d5869651fff35023d1fa538d1b0b7060751d7e6f4c9f05e76437b08666dbf`, `attack_excluded.jsonl` `8e3268c6bc1ff94e8779c35177a57f9e067dfda88a7549aa73f7328807b47944`, identical; manifest (3.14) `63668a1f…`, every code fingerprint equal to the current file (the manifest embeds the interpreter version, so its hash is interpreter-specific); reviewed records not seen: none; reconciliation regenerated |
| Stage-2 benign pools | pool files byte-identical to round 2; manifest (`4760ac50…`) differs only in the attack-pool pin, D59 mapping table, `v5_pools_common.py` fingerprint and generator version |
| `V5-DATA-SPEC-r3` | `sha256sum -c SHA256SUMS` → OK (`f1580634…`) |

### S.10 Independent review (round 3)

Four read-only Sonnet reviews (tool set without file editing; outputs only in the session scratch
directory; no git write). Every finding acted on was reproduced by the coordinator first.

| Review | Finding (severity) | Verified | Action |
|---|---|---|---|
| 1 — SPL-9, short keys, hosts | D-6 residual minimal: exactly 2 identities change (v2 rebuilt from `_NAME_HOST`, 0 mismatches with the round-2 keys); 0 changes on the 35,312 excluded rows; the 49 ledger rows correct; 17,048 pairs by brute force, single lost pair = the two borders | yes | — |
| | attack manifest fingerprint of `v5_identities.py` stale (MINOR) | yes | pool, benign manifest and reconciliation rebuilt; every fingerprint now matches (§S.9) |
| | border rule matched the unstripped wire (MINOR) | yes | matches `payload_wire.strip()`; 0 effect on the pool |
| | SPL-9 gives little protection to keys of 4–7 code points (52 ACCEPTED keys of 4–5, 10 in a pair) (NOTE) | yes | residual risk §S.12 |
| | userinfo forms fragment (`…@H` vs `H@H`); e-mails / IP literals masked anywhere (I-2, spec text) (NOTE) | yes | residual risk §S.12; not changed |
| 2 — values, SPL-6 | policy B as ruled; selection order-independent (30 shuffles); 56 groups; kept + excluded = input; 0 `value_entry_id` mismatches over 73,000 values; casefold collisions all expected (ß, İ, ς, no ligature in the pools) | yes | — |
| | round-2 text (R.3, R.11, §5 config v1, I-8 row) contradicts round 3 (MAJOR, documentation) | yes | marked superseded in place, history kept |
| | "unratified precedence stops" not enforced in code (MINOR) | yes | stated as a real-build condition (§S.3, §S.13 (f)) |
| | the note path not exercised through the fixture builder (MINOR) | yes | end-to-end fixture test added |
| 3 — I-8, E6, D62 | **conforms to D62**; hybrid exact by construction (no circularity), monotone; tests discriminate the readings (5 mutants) | yes | — |
| | an E6 forced-overflow `StopBuild` became `InvalidInput` when a later category shared a family, losing the findings (MAJOR) | yes, reproduced | blocked strata propagate a `STRATUM_NOT_EVALUATED` finding; `build()` collects all; 2 tests |
| | `categories_without_reserve` counts reserve families placed by another stratum (XPath holds 1 from SQLi) (MINOR) | yes | manifest adds `categories_without_own_reserve` and `reserve_families_from_other_strata`; test |
| | R-on-own justification overstated (NOTE) | yes | §S.5 rewritten as I-8b with the measured alternative |
| | the ≥ 100 total of attempt 1 is not distinguished by any test (equivalent mutant in reachable cases) (NOTE) | yes | recorded, not changed |
| 4 — reproducibility, negative tests | all hashes reproduced in 12 runs (2 interpreters × 2 seeds × 3 artifacts); family and equivalence keys identical under Unicode 15.0 (3.12) and 16.0 (3.14); 204 tests per interpreter; scope clean (no V4, gateway, `DECISIONS.md` or spec change) | yes | — |
| | untested: `check_code_versions`, unknown `value_equivalence`, precedence missing a pool, SPL-9 FAIL before BLOCKED, overflow through `build()` (MINOR) | yes | tests added |
| | census code fingerprint omitted `v5_pools_common.py` and `v5_dataset_checks.py` (MINOR) | yes | added (census hash `420ddc20…`) |
| | inadmissible-reason list defined three times (MINOR) | yes | one definition in `v5_pools_common`, imported by the builder and the reconciler |
| | a stale `REVIEWED_DEGENERATE` id would be silent (MINOR) | yes | manifest `reviewed_records_not_seen` (real build: none); test |
| | Unicode database version not recorded (NOTE) | yes | residual risk §S.12 |

No reviewer found a contradiction with the frozen text, a leakage path, or a determinism hazard.

### S.11 Deviations and their reasons

- **Exclusions applied before duplicate removal** (as D-4): 27 duplicates changed reason from `duplicate_*`
  to the e1–e3 reason. Reason: a duplicate can never be promoted to ACCEPTED in place of an excluded record.
- **Two new reasons not named in the prompt**, `identity_degenerate:digits_only_key` and
  `identity_degenerate:command_separator_lost`, and `not_a_payload:isolated_arithmetic` for `7 * 7`: the
  prompt asked for specific, stable reasons and named only `not_a_payload:result_table_border` and
  `identity_unobservable_spl9`.
- **`http:80` is now masked** (§S.4), contrary to the round-2 test; unavoidable under D-5 and the ratified
  rule order.
- **SPL-8 is stricter**: it also fails when a step-2 outcome contradicts the final flag (consistent with
  "computed from counts, never hand-set").
- **Config schema `v5-split-config/v3`**: the `value_equivalence_holds` key is removed and refused.
- **Stage-2 manifest hashes `v5_identities.py`**: the pool now depends on the stage-3 family key.

### S.12 Residual risks and blocks

- All counts are pre post-filter audit (`PENDING_ADJUDICATION`), on a PROPOSED deny-list, without
  `names_family` (BLOCKED); cluster-share thresholds PROPOSED; no payload VERIFIED; the dataset is not frozen.
- The excluded short payloads are a coverage gap (§S.2); SPL-9 protects keys of 4–7 code points weakly
  (one or a few 4-grams).
- `path_file_access` components chain within one target concept; merging every proposed component is
  conservative for leakage and lowers family counts (SQLi R 31, XSS without reserve after merges).
- Userinfo host forms fragment families (merged back by SPL-9); e-mails and IP literals are masked anywhere,
  as the spec text says; the owner may confirm that D-6 restricts only dotted names.
- Benign near-duplicates beyond NFC + casefold are not grouped. The five-pool precedence and the scoped
  `names_family` ß/ss representative handling are ratified by D68; the general cross-pool ß/ss semantic
  policy and precedence for pools beyond the five examined remain unratified.
- I-4, I-6, I-9, I-10, I-14, I-16 need stage-4 artefacts (templates, slots, quotas, `names_family`).
- Verified on CPython 3.12 (Unicode 15.0) and 3.14 (Unicode 16.0) only; the Unicode version is not
  recorded in the manifests.
- **Blocks:** no real split may run until the conditions in §S.13 hold; stage 4 may not start until D64 is
  approved, recorded and merged.

### S.13 Proposed decision text — D64 (NOT recorded; for the owner's review and formal approval)

> **Approved by the owner on 2026-10-16 (America/Costa_Rica) and recorded as D64 in `DECISIONS.md`**
> (status APPROVED; the deferred items are not approved for implementation). The draft below is kept as
> reviewed; the recorded entry is authoritative (§S.14).

This text replaces the round-2 draft (§R.13, kept). It records rulings the owner gave on 2026-10-14
(round 2) and 2026-10-16 (round 3) and what was implemented; it approves nothing retroactively. It
becomes a decision only when the owner approves it and it is entered in `DECISIONS.md`.

> ## D64 — V5 Stage 3: owner rulings for the identity and split contract
>
> - **Date:** 2026-10-16 (draft) · **Status:** PROPOSED — pending owner approval · **Issue:** #72
> - **Implementation:** DONE on synthetic fixtures (stage 3 libraries, not integrated); no real split.
>
> **Relationship.** Applies D62 (`V5-DATA-SPEC-r3` §4.6, SHA-256 `f1580634…`, unchanged) and D60
> (split principles, E6 reserve, evaluability from real counts). It amends neither: every item below is an
> interpretation of text the frozen specification leaves open, a data-admissibility rule for the stage-2
> pools, or a deferral. Nothing is superseded.
>
> **Scope.** Stage 3 only: the identities (`payload_family_id`, `template_id`, `struct_cluster_id`,
> `value_entry_id` reused, `pair_id`), explicit merges, the deterministic 70/10/20 assignment, the E6
> reserve, gates SPL-1…SPL-9, and the stage-2 selection changes those identities require. Out of scope:
> templates, slots, rows, rendering, labels, the generator (stage 4 onwards), training and integration.
>
> **Decision.**
> 1. **Identity rules (round 2, D-1…D-6).**
>    - D-1: the SPL-9 / template-audit near-duplicate representation is the set of contiguous 4-grams of
>      Unicode code points of each pre-merge family key; Jaccard ≥ 0.60 as frozen, compared as integers;
>      whole components are merged explicitly before ranking. n = 4 was chosen after a structural audit of
>      the stage-2 pool and before any real split.
>    - D-2: a cluster spanning two carrier strata is refused (the build stops).
>    - D-3: benign value equivalence for SPL-6 and pre-split deduplication = NFC + casefold; no whitespace
>      collapse; `value_entry_id` keeps its frozen formula.
>    - D-4: attack records with an empty D16 `canonical_key` are EXCLUDED upstream as
>      `identity_undefined:empty_canonical_key`.
>    - D-5: "digits → 0" = each maximal ASCII digit run becomes one `0`.
>    - D-6: hosts are masked only in the URL / redirect forms of §4.3 (separator runs in URL context,
>      `http(s):h`, userinfo integer hosts); a bare dotted word is not a host. Round-3 residual: the
>      integer / `0x` host of `http:h` (`http:3627734734`, `http:0xd83ad6ce`) is masked
>      (`pfid-rules/v3`); as a consequence `http:<digits>` is one key.
> 2. **Unobservable and inadmissible identities (round 3).** Before duplicate removal, the stage-2 builder
>    EXCLUDES: MySQL result-table borders (`not_a_payload:result_table_border`); records reviewed one by one
>    whose identity degenerated (`identity_degenerate:digits_only_key`,
>    `identity_degenerate:command_separator_lost`, `not_a_payload:isolated_arithmetic`); and every other
>    record whose family key is shorter than 4 code points (`identity_unobservable_spl9`). This is a
>    methodological admissibility rule, not a security statement: no excluded record is declared benign,
>    every record stays in the reconciliation ledger with its provenance, and no record with an excluded
>    family key may be ACCEPTED from any source. The Jaccard threshold and n are unchanged; no
>    "declared unobservable" pass exists; `gate_spl9` stays `BLOCKED_UNOBSERVABLE` while any short key is
>    present. The loss of the legitimate short payloads (16 records, 13 of them ACCEPTED) is a documented
>    coverage loss.
> 3. **Benign value policy (round 3, policy B).** NFC + casefold deduplicates every equivalence group with
>    one deterministic rule (configured pool precedence, then the smallest `value_entry_id`); there are no
>    holds. Where the members differ in meaning, the excluded member records the difference and the reason
>    `value_equivalence_policy:split_contamination_guard`; it is never presented as a synonym
>    (`wasps` kept, `WASPs` excluded). Only `symbols > names_given` is backed by analysis, as a candidate; no
>    global precedence is ratified, and a real build that needs an unratified precedence stops. The ß / ss
>    tie-break stays the content hash provisionally; its semantic policy is open.
> 4. **I-8, hybrid reading (round 3).** Strata are processed in code-point order of the category. Each
>    family is assigned once, in its stratum. An attempt's evaluability (≥ 100 families, ≥ 30 in INTERNAL
>    TEST) counts the stratum's own non-reserve families plus the category's families already placed by
>    earlier strata in TRAIN / VALIDATION / INTERNAL TEST; reserve families never count; nothing is counted
>    twice. Earlier strata are never changed; a stratum stopped by an E6 overflow stops every later
>    stratum that counts its families. The step-2 outcome must agree with the final SPL-8 flag; SPL-8 fails
>    otherwise.
>    - **I-8b (interpretation):** R, the roundings and the cuts apply to the stratum's own families. §4.6
>      defines the cuts "for a stratum of size n", and they cannot use the category's full count without
>      re-cutting families already placed by earlier strata, which would assign a family twice or change an
>      earlier stratum. R is the one ambiguous quantity ("n is the number of families of the category after
>      merges"); an "R on all occurring families" variant could be filled from own families without moving
>      anyone, but it would size the reserve on one count and cut on another. Measured on the real pool, that
>      variant changes R by at most 1 family and no outcome. I-8b is therefore the reading consistent with the
>      cuts, not a change to the frozen text.
> 5. **Deferred to stage 4.**
>    - I-16: cross-carrier clusters stay refused; carrier-qualified audit tokens are a candidate only; if
>      real templates of two carriers reach the threshold and cannot be assigned validly, the build stops.
>    - I-6: the frozen `pair_id` is unchanged; `pair_content_id` is a candidate diagnostic (not in SPL-3, not
>      blocking) to be specified with the stage-4 slot model.
>    - Also deferred: I-4 (template skeleton), I-9 (step-5 rebalancing rule), I-10 (ENC-5 overflow policy
>      choice), I-14 (`names_family` pool identity).
> 6. **Round-2 interpretations made binding for stage 3** (provisionally ratified on 2026-10-14): I-3 (a
>    single character repeated 4+ times → 3 copies), I-7 (category vocabulary = stage-2 `dedup_scope`, code-
>    point order), I-11 (`E6_RESERVE` is a fourth partition for SPL-9), I-12 (the family key is the id),
>    I-17 (`master_seed` required and hashed, unused in stage 3), I-18 (rule order as listed), I-19 (no
>    Unicode normalisation of payloads beyond `canonical_key`).
>
> **Implemented** (`scripts/dataset/v5_identities.py`, `v5_split.py`, `v5_split_checks.py`; stage-2
> `build_v5_attack_pool.py`, `reconcile_v5_attack_pool.py`, `v5_pools_common.py`; tests
> `test_v5_identities.py`, `test_v5_split.py`, `test_v5_attack_pool.py`): `pfid-rules/v3`,
> `v5-split-config/v3`, `v5-pools/1.3`, census `v5-stage3-census/v3`. Attack pool 39,451 = 4,139 ACCEPTED +
> 35,312 EXCLUDED (51 identity exclusions: 2 D-4 + 49 round 3), all ACCEPTED `PENDING_ADJUDICATION`.
>
> **Evidence.** Stage-3 tests 101 OK; stage 1/2/3 suites 524 OK (3.14) and 563 OK (3.12); data-plane venv 380
> OK; V4 suites 77 OK; SPL-1 and SPL-2 PASS; fixture SPL-3…SPL-9 PASS; byte-identical rebuilds on CPython
> 3.12 and 3.14 with PYTHONHASHSEED 0 and 31337 (fixture assignment `571a0a06…`, census `420ddc20…`, attack
> pool `4c5d5869…`); specification hash unchanged. Real-pool census (counts only): 3,754 families before
> merges, 1,692 after merging every proposed component, 17,048 SPL-9 pairs, largest component 90, 0
> unobservable keys; EVALUABLE CmdI, SQLi, SSTI, XSS, `path_file_access`; NOT EVALUABLE CRLF, NoSQL, Open
> Redirect, SSRF, XPath.
>
> **Limitations and remaining risks.** All counts are pre post-filter audit, on a PROPOSED deny-list and
> without `names_family`; `path_file_access` components chain within one target concept (merging is
> conservative for leakage and lowers family counts); near-duplicate benign values beyond NFC + casefold are
> not grouped; the excluded short payloads leave a coverage gap; the hybrid I-8 changes no real outcome
> today but would matter for multi-category families; templates, slots, rows and the generator do not
> exist, so I-4, I-6, I-9, I-16 remain untestable on real data; verified on CPython 3.12 and 3.14 only.
>
> **Still pending — not decided by D64.** The post-filter audit (spec §7) and the blind human review
> (§11.3); the final third-party deny-list (PROPOSED); `names_family` (BLOCKED); the approval of the
> stage-2 attack and benign pools (every ACCEPTED payload is `PENDING_ADJUDICATION`, no payload is VERIFIED,
> no category is declared fit); the cluster-share thresholds (PROPOSED). No real split exists and the V5
> dataset is not FROZEN.
>
> **Conditions for a real split.** (a) D64 approved and recorded; (b) post-filter audit done, the deny-list
> final, and every ACCEPTED payload adjudicated (none `PENDING_ADJUDICATION`); (c) `names_family` built,
> or a configuration without it explicitly approved; (d) the explicit family-merge list reviewed and
> written into the config; (e) the template catalogue with cluster declarations, passing the template audit;
> (f) a value precedence ratified for every configured pool; (g) the cluster-share thresholds and the
> rebalancing rule in the dataset preregistration; (h) every SPL gate run on the real build and passing,
> including SPL-9 with 0 unobservable keys; (i) INTERNAL TEST read once behind its single-run guard.
>
> **Conditions for starting stage 4.** D64 approved and recorded; the stage-3 work merged into `develop`
> through a reviewed PR; issue #72 closed by the owner. Stage 4 must deliver the template catalogue (I-4 and
> the I-16 check), the slot model (I-6), the quota model and rebalancing rule (I-9), the ENC-5 overflow
> choice (I-10) and the `names_family` identity (I-14), and run every SPL gate as a build gate.

### S.14 Owner approval and registration (2026-10-16)

- The owner approved the §S.13 text on 2026-10-16 (America/Costa_Rica), including D-1–D-6, the
  documented exclusions, the benign value policy and I-8b; I-6 and I-16 stay deferred to stage 4;
  `V5-DATA-SPEC-r3` and D56–D63 unchanged; `names_family`, the pending pools and the other real-split
  conditions stay blocked.
- Recorded as **D64** in `DECISIONS.md` (entry and index row; no earlier entry edited). Content equals
  §S.13, with three additions that only state facts of the approval: the date and status lines, "(met by
  this entry)" for real-split condition (a), and the reason for the 3.12 / 3.14 test-count difference in
  the evidence (the 39 extra tests on 3.12 are the tokenizer suites, which need `transformers`).
- No Stage-3 decision remains pending that would keep the contract open. Stage 4 has not started; it may
  start only after the stage-3 work is merged into `develop` and the owner closes #72.
