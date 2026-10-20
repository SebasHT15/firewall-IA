# V5 stage 2 — dataset foundation (issue #70)

**Status (2026-10-14):** implemented and tested, **not frozen**. Two things are still open:

- The template and vocabulary await the owner's ratification.
- The `names_family` pool is BLOCKED by a Wikidata (WDQS) outage.

This stage does **not** include identities beyond `value_entry_id`, a split, generation, a dataset freeze, training or gateway integration. `V5-DATA-SPEC-r3` (SHA-256 `f1580634…`) and D56–D63 are unchanged.

| Part | Document | Code | Tests |
|---|---|---|---|
| A. Template | `template_v5_proposal.md`, `template_v5_measurement.json` | `control_plane/v5_tokenization.py`, `control_plane/v5_output_contract.py`, `scripts/dataset/measure_v5_template_budget.py` | `tests/test_v5_output_contract.py` |
| B1. Benign pools | `benign_pools_summary.md` | `scripts/dataset/build_v5_benign_pools.py`, `scripts/dataset/v5_lexicon/{streets_v1,benign_symbols_v1}.json` | `tests/test_v5_benign_pools.py`, `tests/fixtures/v5_benign/` |
| B2. Attack pool | `attack_pool_summary.md` (generated) | `scripts/dataset/build_v5_attack_pool.py`, `scripts/dataset/v5_lexicon/patt_third_party_denylist_v1.json` | `tests/test_v5_attack_pool.py` |
| Shared | — | `scripts/dataset/v5_pools_common.py` | covered by the tests above |

Generated pools, raw downloads and manifests live in `datasets/v5_sources/`, which is gitignored.

**Reproduce:**

```
python3 scripts/dataset/build_v5_attack_pool.py --check-determinism
python3 scripts/dataset/build_v5_benign_pools.py build --attack-pool datasets/v5_sources/attack/attack_pool.jsonl
cd /tmp && HF_HUB_OFFLINE=1 python3.12 <repo>/scripts/dataset/measure_v5_template_budget.py --out <repo>/reports/v5/dataset-foundation/template_v5_measurement.json
```

**Independent review (stage 2, agent D, read-only).** No blocker was found. Every artifact was rebuilt sha256-identical.

| Finding | Severity | Status |
|---|---|---|
| Prose sentences naming real people | MAJOR | fixed: `possible_full_name` filter |
| Description labels in the given-name pool | MINOR | fixed |
| Sidecar licence not checked | MINOR | fixed |
| Protected-path guard checked only basenames | MINOR | fixed: CSIC and `v4_clean` anywhere in the path |

**Closure round (2026-10-14).** Owner rulings applied:
- template candidate kept;
- pilot vocabulary B;
- B = 415 candidate;
- two name pools;
- `possible_full_name` kept;
- deny-list PROPOSED.

Changes in this round:
- **Count reconciliation.** `scripts/dataset/reconcile_v5_attack_pool.py` writes `attack_pool_reconciliation.md` and checks these conditions:
  - the row ledger sums for every category;
  - the unique-canonical waterfall matches the accepted rows;
  - every accepted row is PENDING;
  - the artifact hashes match the manifest.
- **Manifests.** Both pool manifests now record `generator_version` (`v5-pools/1.1`), the source commit, the working-tree state, the Python check, the D59 mapping table and per-reason D59 counts.
- **D59 mapping.** Excluded records gain `d59_exclusion_reason` beside the original reason, which is never changed. The mapping is PROPOSED; an unknown reason fails loudly.
- **Python versions.** Pool artifacts were verified byte-identical on CPython 3.12.15 and 3.14.4. Other versions are refused unless `V5_POOLS_ALLOW_UNVERIFIED_PYTHON=1`, which is recorded.
- Tests: `tests/test_v5_pools_closure.py`.

**Recorded open items from the first review: all resolved in the closure round.**

- **Generator commit and tree state.** Recorded in both manifests. Builds from an uncommitted tree say `working_tree_clean: false` and list the modified code files. A rebuild after commit records the commit and a clean tree.
- **Python dependence.** Pool artifacts are byte-identical on 3.12.15 and 3.14.4. Unverified interpreters are refused, and an override is recorded.
- **D59 mapping.** Added; see above.

## Privacy filter: false-discard evaluation (`possible_full_name`, kept per owner ruling)

- **What it removes.** 4,107 English sentences, in 2,548 distinct matched word pairs.
  - The most frequent pairs include real public figures, for example "Elon Musk" (78), "Donald Trump" (40), "Joe Biden" (13) and "Jordan Peterson" (10). These are the intended target.
  - It also removes the fictional "Tom Jackson" (100), place names ("United States" 80, "New York" 42, "Los Angeles" 20) and sentence-initial function words ("The Kabyle" 30, "Did Tom" 18, "Is Tom" 16).
- **Proportionality.** Measured as each feature's rate among accepted versus discarded sentences:

| Feature | Accepted | Discarded |
|---|---:|---:|
| apostrophe | 26.6% | 24.1% |
| symbol | 30.7% | 31.5% |
| hyphen | 5.7% | 15.1% |
| non-ASCII | 3.5% | 7.9% |
| digit | 3.3% | 12.9% |

  Apostrophes and symbols, the V5-critical concepts, are **not** disproportionately removed: 542 accepted sentences with `; < > & % # + --` against 68 discarded. Hyphen, non-ASCII and digit sentences are removed at 2–4 times their base rate. Those are mostly news and proper-noun sentences.
- **Refinement tried and not adopted.** Skipping a sentence-initial stop-word pair would recover 796 sentences. In the sample, it also lets real names through, for example "If Anthony Weiner were…", because the stop-word match hides the overlapping name pair. Any change to the filter is a selection-policy change and needs the owner's authorization.

## Family-name alternatives (evaluated, NOT incorporated)

| Option | Licence and provenance | Fit for V5 | Status |
|---|---|---|---|
| Retry WDQS when the outage rule is lifted | CC0, same source and query as `names_given` | Best: same pipeline, apostrophes and non-ASCII preserved | Recommended; one attempt at a time, with a delay |
| Another endpoint serving the same Wikidata data (e.g. a QLever mirror) | CC0 data, but a third-party service and a different snapshot date | Same content; provenance must record the mirror and its date | Not verified; needs authorization |
| US Census 2010 surnames, File B: 162,253 surnames with ≥ 100 occurrences | US government work (17 U.S.C. §105). The census.gov page states **no** licence text (checked 2026-10-14) | US-centric. Casing and punctuation (apostrophes, hyphens) are not documented on the page | Not verified; needs authorization |

## Attack pool: reconciliation and exclusion audit (closure round)

The full ledger is in `attack_pool_reconciliation.md`. It is regenerated by `reconcile_v5_attack_pool.py` and is deterministic.

- **Rows.** 39,451 extracted = 4,163 ACCEPTED + 35,288 EXCLUDED.
  - In earlier reports the summary table left out the V4-quality-filter column. Those were the "not visible" exclusions: SQLi 439, XSS 473 and Directory Traversal 3,546 rows.
- **Unique canonical payloads,** from V4-accepted → spec §2.3 basis → full PROPOSED deny-list → accepted:

| Scope | V4-accepted | Spec §2.3 basis | Full deny-list | Accepted |
|---|---:|---:|---:|---:|
| SQL Injection | 1,278 | 1,000 | 1,000 | 930 |
| XSS | 2,238 | 705 | 436 | 382 |
| path_file_access (traversal + file inclusion) | 13,157 | 2,828 | 1,678 | 1,600 |

- **Why the counts drop.** The spec's figures (1,000 / 705 / 2,828) are reproduced exactly at the spec basis. The drops below them have two causes only:
  - the three new PROPOSED denials: XSS −269 (`IntrudersXSS.txt`, `XSSDetection.txt`) and path_file_access −1,150 (`Traversal.txt`);
  - the structural rules: SQLi −70, XSS −54, path_file_access −78.
- **Evidence for the new denials.** Re-verified against PATT and pinned by a test:
  - `IntrudersXSS.txt`: 111 of 179 non-empty lines are identical to BRUTELOGIC-XSS-STRINGS.
  - `XSSDetection.txt`: 63 of 202 lines are identical to RSNAKE_XSS, and 23 lines name ha.ckers.org.
  - `Traversal.txt`: lines 848–849 carry a header naming its third-party author.
    - Note: the header sits in the middle of the file. Lines 1–847 have no attribution of their own, and the whole file is denied.
- **Directory Traversal alone: 172 accepted.**
  - 19,392 of its 23,155 extracted rows come from `dotdotpwn.txt`, which the spec's initial deny-list excludes.
  - 3,546 rows fail the V4 filter.
  - The 172 come from `directory_traversal.txt` (100) and `README.md` (72).
  - Under D49 the evaluation scope is path_file_access, which has 1,600.
- **Suspected false exclusions.** I reviewed all structural exclusions of SQLi, XSS and Directory Traversal by hand.
  - **SQLi (70) and Directory Traversal (18):** correct per the audit rules. These are tool output, code lines, prose, `BURP-COLLABORATOR` placeholders and `%%32%65`-style malformed encodings.
  - **XSS:** about 9 of 79 look like valid payloads.
    - `literal_backslash_x` (14 rows): about 5 are complete JS-escape vectors, e.g. ``Set.constructor`al\x65rt\x2814\x29``, `<script>eval('\x61lert(...)')</script>`, and the `jaVasCript:` polyglot ×2. The other 9 are line fragments.
    - `prose_sentence` (14 rows): about 4 are valid payloads followed by a `//` comment or a remark, e.g. `<body ontouchstart=alert(1)> // …`.
  - Fixing either would be a **selection-policy change**: narrowing `literal_backslash_x`, or extending the SSTI comment-strip to XSS. Neither was made. Both need the owner's authorization.

## Addendum (2026-10-14, stage 3 owner ruling D-4; issue #72)

The text above is kept as recorded. One selection change was authorized afterwards:

- Two ACCEPTED attack records had an empty D16 `canonical_key`, so no `payload_family_id` can be built for them (V5-DATA-SPEC-r3 §4.6): `39984cbf08fac821` (`%0a%0d`, `Command Injection/Intruder/command_exec.txt`, line index 11) and `a5e450af1f2ac579` (`/* Cassandra Comment */`, `SQL Injection/Cassandra Injection.md`, line index 0).
- They are now EXCLUDED with `identity_undefined:empty_canonical_key` (D59 mapping `AUDIT_REJECT`, PROPOSED). This states only that they do not meet the current identity and selection requirements; it does not declare either one benign.
- Pool: 4,161 ACCEPTED + 35,290 EXCLUDED = 39,451 extracted. Every other record is byte-identical; no excluded record became ACCEPTED; every ACCEPTED record is still `PENDING_ADJUDICATION`. `GENERATOR_VERSION` is `v5-pools/1.2`.
- The general `empty` / `too_short` filters were not changed. The benign pool files are byte-identical; only their manifest (attack-pool pin, generator version) changed.
- `attack_pool_summary.md` and `attack_pool_reconciliation.md` are regenerated with a dedicated "Identity undefined" column.

## Addendum (2026-10-16, stage 3 round 3 owner ruling; issue #72)

The text and the D-4 addendum above are kept as recorded. A second selection change was authorized:

- New stage-2 steps e1–e3, after e0 and before duplicate removal, on the stage-3 family key
  (`v5_identities.family_key`, V5-DATA-SPEC-r3 §4.6): MySQL result-table borders → `not_a_payload:result_table_border`;
  nine individually reviewed records whose identity degenerated → `identity_degenerate:digits_only_key`,
  `identity_degenerate:command_separator_lost` or `not_a_payload:isolated_arithmetic`; every other family key shorter than
  the SPL-9 4-gram → `identity_unobservable_spl9`. D59 mapping `AUDIT_REJECT` (PROPOSED). Methodological admissibility,
  not a security claim: no record is declared benign; the unobservable ones are legitimate payloads and their loss is a
  documented coverage loss (stage-3 report §S.2).
- Pool: **4,139 ACCEPTED + 35,312 EXCLUDED = 39,451** extracted. 49 records changed (22 ACCEPTED → EXCLUDED, 27 duplicates
  re-attributed); the other 39,402 are byte-identical; no excluded record became ACCEPTED; a build-time check refuses any
  ACCEPTED record sharing a family key with an e1–e3 record; every ACCEPTED record is still `PENDING_ADJUDICATION`.
  `GENERATOR_VERSION` `v5-pools/1.3`; the attack manifest now hashes `v5_identities.py`.
- The benign pool files are byte-identical; only their manifest changed (attack-pool pin, D59 mapping table, generator
  version). `attack_pool_summary.md` and `attack_pool_reconciliation.md` are regenerated with an "Identity inadmissible"
  column; the reconciliation lists all 49 records with provenance (§4).

## Addendum (2026-10-19, data-readiness session; issues #75, #77)

The text above is kept as recorded. See `reports/v5/data-readiness/README.md`.

- **`names_family`:** still BLOCKED.
  - The 429 outage rule is still active.
  - With a policy-compliant User-Agent the query passes the rate limit, but it then hits the WDQS 60 s timeout.
  - The builder gained `acquire --endpoint` (first-party Wikimedia hosts only) and a new User-Agent. The query text is unchanged.
- **Deny-list:** candidate v2 (PROPOSED) = v1 + `Auth_Bypass.txt`, `Auth_Bypass2.txt`, `jsonp_endpoint.txt`, based on content evidence of third-party origin.
  - The candidate pool has 3,933 ACCEPTED; it is built separately and not adopted.
  - The deny-list loader now accepts a whole list marked `APPROVED`, with an approval record.
- **Canonical pool:** rebuilt with v1, byte-identical (`4c5d5869…`). Only the manifest changed, through the code fingerprint; `attack_pool_summary.md` was regenerated, and its only change is the manifest hash. The reconciliation is unchanged.
