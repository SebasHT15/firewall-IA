# V5 data readiness — sources and post-filter audit (2026-10-19)

**Status:** working-tree evidence for the owner, **uncommitted**. The V5 dataset is **not** ready for training. Nothing here
freezes a dataset, runs a real split, trains a model, or labels a payload VERIFIED. `V5-DATA-SPEC-r3` (SHA-256
`f1580634…`) and D62/D64/D65 are unchanged. Issues: #75 (`names_family`, evidence comment of 2026-10-19), #77 (post-filter audit, BLOCKED on the deny-list approval).

| Front | Result | Evidence |
|---|---|---|
| A. `names_family` (#75) | **BLOCKED.** The cause changed from a rate limit to a query that cannot finish within the WDQS timeout | `wdqs_attempts_2026-10-19.json` |
| B. Attack sources and deny-list | **Deny-list v2 APPROVED (D66, 2026-10-19)** with the XSS filters kept. Canonical pool rebuilt: 3,933 ACCEPTED, `ba385fa2…` | `scripts/dataset/v5_lexicon/patt_third_party_denylist_v2.json` (`3e557058…`), `DECISIONS.md` D66, `xss_known_false_exclusions.md`, `../dataset-foundation/attack_pool_reconciliation.md` |
| C. Post-filter audit (§7, D58) | **SUPERSEDED 2026-10-20 (D67/r4, see `round_status.json`):** a1 `claude-sonnet-5-5` 453/453 + a2 `claude-haiku-5-5` 453/453 COMPLETE; the blind human review is replaced by an AI third review (R3, not run); R3 materials prepared (217 unique). No category PASS; SSRF NOT SUPPORTED. The "DRAWN / human / PENDING_ANNOTATION" wording below is historical. | `../postfilter-audit/round-1/`, `../postfilter-audit/r3-review/` |

## A. `names_family` — BLOCKED

**Mechanism inspected.** `build_v5_benign_pools.py acquire` already pins a WDQS response (sidecar: url, endpoint,
query, retrieved_at, sha256, bytes, CC0 licence and its evidence URL, UA). The JSON is validated before anything is
written; an existing pin is never overwritten. `build` refuses a file whose hash, size, licence or query differs from
the code. The privacy rule is unchanged: only NAME items (Q101352) and their labels are read, never Q5 or person
properties, and names are recombined later.

**What happened: 8 requests in total, then stopped** (full log in `wdqs_attempts_2026-10-19.json`):

1. **The outage rule is still active.** `query.wikidata.org` answers HTTP 429 "Aggressively rate-limiting to 1 req / min — this rule was created during active wdqs outage", the same message as on 2026-10-14. It did so on both builder attempts, each in under 0.5 s.
2. **The other Wikimedia endpoint behaves the same way.** `query-main.wikidata.org` (Wikimedia, `wdqs1034`) answered a 3-row probe with HTTP 200, but answered the builder's full query with 429, twice.
3. **The User-Agent is the likely trigger.** The builder's old UA, "(research; contact via repo)", gave no usable contact, which Wikimedia's UA policy requires. With a UA that carries the public repo URL, the request was **not** rate-limited. This is consistent with the policy, but it rests on two requests and is not proven.
4. **The query itself cannot finish.** Without the 429, the pinned query (`LIMIT 50000`, `en`/`mul` label filter) reaches the WDQS 60 s timeout. The server cuts the JSON at about 1.98 MB (line 86,701). The builder refused the truncated file, and nothing was written.
   - At the observed rate, 50,000 rows would take several minutes. The query is therefore **infeasible as written** on WDQS, with or without the outage rule. This is an inference from two requests.

**Code changes (acquisition only; the query text is unchanged):**
- `--endpoint`, restricted to first-party Wikimedia WDQS hosts (`query.wikidata.org`, `query-main.wikidata.org`) and recorded in the sidecar. Third-party mirrors are refused.
- A policy-style UA with the public repository URL as the contact, and no personal data. The given-name sidecar keeps the UA it was fetched with.

**Not done, because Front A is blocked:**
- pin, licence record and SHA-256 of a family-name snapshot;
- pool rebuild;
- apostrophe and Unicode yield;
- NFC + casefold equivalence and cross-pool collisions against `names_given`/`symbols`;
- the per-split minimum.

The builder still reports `names_family` `BLOCKED: source not acquired` and is never substituted. The other benign pools are unchanged: semantically identical census before and after the rebuild; `names_given` 26,050, `prose_en` 34,048, `streets` 12,604, `symbols` 295.

**Options (none adopted; each needs the owner):**

| Option | Change | Provenance | Note |
|---|---|---|---|
| A1 | Lower the pinned `LIMIT` until the query fits in 60 s (≈ 5,000 at the observed rate), on `query-main` with the new UA | Wikidata CC0, first-party endpoint, arbitrary subset pinned by SHA-256 (as today) | Smallest change. Still far above the ≥ 200 pool minimum. The query text changes, so the owner must approve it |
| A2 | Keep `LIMIT 50000`; page by QID ranges, one pinned file per page | Same | More requests, several sidecars, a builder change |
| A3 | A third-party QLever mirror of Wikidata | CC0 data, third-party service and snapshot date | Documented earlier as needing authorization; not tried |
| A4 | US Census 2010 surnames | US government work; no licence text on the page | Documented earlier; US-centric; apostrophe casing undocumented; not tried |
| A5 | An owner-approved configuration without `names_family` | — | D64 condition (c) allows it explicitly |

## B. Attack sources and deny-list — proposal for approval

**Current pool verified.** The current code rebuilds the documented pool byte-identically:
- `attack_pool.jsonl` `4c5d5869…`: 4,139 ACCEPTED + 35,312 EXCLUDED = 39,451;
- all ACCEPTED rows are `PENDING_ADJUDICATION`;
- determinism check passes; the reconciliation is unchanged.

**PROPOSED items before this session:**
- The 23 deny-list entries of v1: spec initial list 20, plus 3 stage-2 content denials.
- Three items listed "unresolved for human review" in v1.
- The XSS filter question (about 9 suspected false exclusions in `literal_backslash_x` / `prose_sentence`). **Not changed here.** That is still an owner decision.

Earlier evidence for the 66 reviewed-not-denied files was reused, not repeated.

**New evidence: online provenance check of the unresolved items.** The comparison files were fetched read-only, compared by exact line, and not stored in the repository.

| File | Evidence | ACCEPTED rows |
|---|---|---:|
| `XSS Injection/Intruders/jsonp_endpoint.txt` | 44 of 45 endpoints are in `zigoo0/JSONBee@c0c87fc` `jsonp.txt` (**GPL-3.0**): 31 byte-identical lines and 13 with the same endpoint URL. 10 of 11 `#Vendor:` headers are identical. PATT added the file 2018-12-23, after JSONBee's creation (2018-10-29) | 45 |
| `SQL Injection/Intruder/Auth_Bypass.txt` | 77 of 78 lines are identical to the 77-line list `foospidy/payloads@38ac97f` `other/sqli/camoufl4g3.txt`. It was added there 2016-02-26, before PATT (2017-07-30). foospidy is GPL-3.0, and its README attributes the list to `github.com/camoufl4g3/SQLi-payload-Fuzz3R`, which now returns 404. SecLists' copy (MIT) dates from 2024-10-21, so it is downstream. **Certainty of third-party origin: high. Original licence: unknown** | 67 |
| `SQL Injection/Intruder/Auth_Bypass2.txt` | 117 of 119 lines are identical to the 117-line list `1N3/IntruderPayloads@9b84328` `FuzzLists/auth_bypass.txt`. It was added there 2016-05-04, before PATT (2017-08-06, commit "More Burp Intruder file"). The repository declares **no licence**. SecLists' copy (2024) is downstream. The file also has typographic corruption. **Certainty: high. Licence: none granted** | 99 |

Under the approved rule (spec §3.1: "content evidence of third-party origin triggers the same rule as a name or header"),
all three qualify for denial.

**Candidate deny-list v2** (`patt_third_party_denylist_v2.json`, `bb88c761…` (evidence text corrected 2026-10-19 after the final review; the list content is unchanged), status PROPOSED) = v1 plus the three
files above. Its candidate pool was built into the gitignored `datasets/v5_sources/candidate_denylist_v2/` and is
deterministic (`ba385fa2…`).

| Category | ACCEPTED v1 | ACCEPTED v2 | Families after proposed merges v1 → v2 | Evaluability |
|---|---:|---:|---:|---|
| SQL Injection | 920 | 759 | 383 → 324 | EVALUABLE → EVALUABLE |
| XSS Injection | 382 | 337 | 271 → 241 | EVALUABLE → EVALUABLE |
| XPath Injection | 31 | 31 | 19 → 25 | NOT_EVALUABLE (unchanged) |
| all others | unchanged | unchanged | unchanged | unchanged |
| **Total** | **4,139** | **3,933** | | no flag changes |

Exact record diff, v1 → v2:
- 211 rows removed: Auth_Bypass2 99, Auth_Bypass 67, jsonp_endpoint 45.
- 5 SQLi rows promoted from duplicate to ACCEPTED, because their first occurrence was in a denied file: 4 from `Generic_ErrorBased.txt`, 1 from `README.md`.
- 6 XPath rows lose their `also_in_categories: [SQL Injection]` link. That is why XPath families rise from 19 to 25: Auth_Bypass lines had chained XPath families into SQLi components.

The reconciliation of v2 balances: 39,451 = 3,933 + 35,518, and the hashes match. Evaluability is a consequence, not a target. No pool was grown to compensate.

**Kept with a flag, unchanged.** These files overlap with denied lists, but the shared lines are generic strings and do not show where the file came from:
- `directory_traversal.txt`
- `XSS_Polyglots.txt`
- `Linux-files.txt`
- `List_Of_File_To_Include.txt`

The licences of the denied lists were not re-verified: denial is a precaution, not a licence finding.

**Recommendation:** approve v2 as the final deny-list.

**What approving means mechanically.** The loader now accepts a list that is entirely `APPROVED` with
`approval.{approved_by, date, decision_ref}`, and refuses a mixed list. The builder default then points to the approved
file, the canonical pool is rebuilt, and the manifest records the approval.

### Final review of v2 (owner request, 2026-10-19)

**Exact v1 → v2 difference.** Three files are added to the deny-list; no category is touched.

| Category | ACCEPTED lost | Pre-merge families lost entirely | Other family changes |
|---|---:|---:|---|
| SQL Injection | 166 (Auth_Bypass 67, Auth_Bypass2 99) − 5 promoted duplicates = **161 net** (920 → 759) | **141**. Auth_Bypass: 62 of 67 touched; Auth_Bypass2: 79 of 88 touched; 14 touched families survive through other files | 5 families move from (SQLi, XPath) to XPath only. SQLi families 877 → 731, while XPath keeps 29 |
| XSS Injection | **45** (jsonp_endpoint), 382 → 337 | **43** (every touched family) | — |
| Other 8 categories | 0 | 0 | none |

Totals: 4,139 → 3,933 ACCEPTED; 184 families lost. No family gained. After the proposed merges, SQLi falls 383 → 324 and XSS 271 → 241. Both stay EVALUABLE (TEST 65 and 49 families) and keep 13 and 8 source files.

**Compliance with §3.1 (D62).**
- Item 1, file-level rule: each denial is backed by content evidence of third-party origin. None has a licence verified as compatible: JSONBee is GPL-3.0, IntruderPayloads has no licence, and the original camoufl4g3 licence is unknown.
- Items 2–5 are untouched: the structural filters, the per-file cap (still PENDING), the category deny-list and the provenance fields.
- No category is removed: the smallest affected category keeps 337 records.
- Nothing was added to compensate for the loss.

**Verdict: APPROVE v2.**

**Pending XSS filters** (the rules are unchanged in the code; the figures below are measured on the v2 candidate).
- `literal_backslash_x` excludes 14 rows: 9 multi-line Angular fragments, correctly excluded, and about 5 complete vectors (`Set.constructor…\x65…`, the `jaVasCript:` polyglot ×2, `eval('\x61lert…')`, `\x6A…javascript:alert(1)`). As a result, **0 of 337** accepted XSS payloads contain `\xNN`, so that obfuscation mechanism is absent.
- `prose_sentence` excludes 14 rows: 9 prose sentences and about 5 payloads followed by a `//` remark or in markdown-link form.
- **Recommendation: keep both rules for round 1 and document the exclusions as a coverage loss**, with record ids in this section's evidence:
  1. The filter must be final before the round-1 draw. A change after the draw costs the only re-audit §7 allows.
  2. The gain is about 10 rows, roughly 3% of XSS.
  3. D62 states that an invalid octet rendered as `\xNN` is textually identical to literal `\xNN`. Adding BLOCK-only `\xNN` payloads is a shortcut risk, and the pilot's C-S checks would have to measure it first.
  4. Narrowing `literal_backslash_x` would also admit the fragments unless the rule is rewritten.
- The alternative, if the mechanism matters, is a documented rule change **before** round 1, which requires the owner's authorization.

## C. Post-filter audit (§7, D58) — tooling

**Reused** from `audit_v5_attack_pool.py`:
- label classes and failure modes;
- the Wilson interval;
- annotation validation;
- the binary agreement / κ calculation;
- batching;
- human-label validation.

**New:** `scripts/dataset/audit_v5_postfilter.py`, covering every §7 item:

| §7 requirement | Implementation |
|---|---|
| Only the pool after the filters and the approved deny-list | `sample` refuses unless: the pool hash matches its manifest; the deny-list hash matches the one the pool was built with; the list is `APPROVED`; every record is ACCEPTED + `PENDING_ADJUDICATION`. `plan` (counts only) works on a PROPOSED list |
| Fresh sample, new seed, stratified by source file, n ≥ 50 or the whole pool | Category = `dedup_scope` (path_file_access = traversal ∪ FI, D49). Per-file quotas by largest remainder, at least one per file. Rank by `sha256(seed, category, record_id)`. Seeds of the pre-filter audit and of earlier rounds are refused. A round is never redrawn |
| Identifiers, seeds, hashes, provenance | `sample.jsonl` keeps `record_id`, source file, line/block, wire and logical forms, and the payload SHA-256. `audit_state.json` records the seed, the pool, manifest and deny-list hashes, the parameters and the code fingerprint. Byte-identical regeneration is tested |
| Two LLM annotators of different models, kept separate | `annotations_a1.jsonl` and `annotations_a2.jsonl` plus `annotators.json`. The same model (case-insensitive) is refused. LLM agreement is reported under the key `llm_agreement_not_human_validation` |
| Discrepancies adjudicated by an identified coordinator or owner | `adjudication-sheet` lists open disagreements. Each adjudication needs a named adjudicator, a role and a rationale. Overriding an agreed label is refused. V/P splits resolve to P by the recorded pre-filter rule, which affects neither gate rate |
| Blind human subsample, ≥ 20 per category | Drawn at `sample` time, before any LLM label exists, with a separate seed and stratified by file. The CSV carries no labels. `human-batch` shows the wire and logical forms. Every label row needs a reviewer identity. An empty row is PENDING, never defaulted |
| Wilson bounds, acceptance criteria, per-category report | `report` builds `report.json` and `report.md`. Statuses: `PENDING_ANNOTATION`, `PENDING_ADJUDICATION`, `PENDING_HUMAN_REVIEW`, `PASS`, `FAIL`. Human labels prevail on the subsample. A FIXTURE round never counts as a gate result. PASS makes a category eligible; it labels nothing VERIFIED |
| At most one re-audit | Round 2 needs: round 1 reported; a documented filter change (hashed); a changed pool; a new seed. It covers only the categories that FAILED. Round 3 is refused |

Every number (n = 50, human = 20, 20% / 35% / 20%, one re-audit) stays **PROPOSED** (§11.2) and is recorded in each round.

**Pass boundaries at these values:**

| n | C1 (Wilson-95 upper of INCORRECT ≤ 20%) | C2 (Wilson-95 upper of U+I ≤ 35%) |
|---:|---|---|
| 50 | ≤ 4 INCORRECT | ≤ 10 U+I |
| 31 (XPath, whole pool) | ≤ 1 INCORRECT | ≤ 5 U+I |
| 22 (CRLF, whole pool) | 0 INCORRECT | ≤ 3 U+I |

For reference only, and not a prediction: the adjudicated pre-filter INCORRECT rates were SQLi 13%, SSTI 20% and XSS 22%.

### Status per category

Superseded by §D: round 1 is drawn, and every category is `PENDING_ANNOTATION` (see
`../postfilter-audit/round-1/report.md`). No category is PASS and no payload is VERIFIED.

### What needs human review

1. **The pre-filter 95-item sample** (spec §11.3 item 1): 0 of 95 reviewed (`freeze-prep/E_attack_pool_audit/human_review/human_labels.csv` is empty).
2. **The post-filter blind subsample:** 200 items, created by `sample` once the deny-list is approved.
3. **The adjudication** of LLM disagreements, by the coordinator or the owner, named.
4. **The owner's approval** of deny-list v2.

## D. Owner approval and round-1 draw (2026-10-19)

**Approval recorded.** Recorded in D66 (`DECISIONS.md`) and in the deny-list file:
- `status: APPROVED`;
- an `approval` record (approver, date, decision reference, scope);
- every entry set to APPROVED.

The XSS rules `literal_backslash_x` and `prose_sentence` are kept unchanged. Ten known false exclusions are listed by
record id in `xss_known_false_exclusions.md` as a coverage loss. Recovering them is not authorized.

**Rebuild and reconciliation** (builder and reconciler defaults now point to v2):
- `attack_pool.jsonl` `ba385fa2…`: 3,933 ACCEPTED + 35,518 EXCLUDED = 39,451. Byte-identical to the reviewed candidate.
- Determinism check passes.
- `attack_pool_summary.md` and `attack_pool_reconciliation.md` regenerated. The reconciliation now states the
  deny-list status and hash, and refuses a deny-list that differs from the manifest.
- Benign manifest rebuilt; the benign pools are unchanged.
- The candidate copy in `datasets/v5_sources/candidate_denylist_v2/` is identical and is kept only as review evidence.

**Pre-sampling checks, all passed:**
- deny-list APPROVED, and its hash equals the manifest's;
- pool hash and record count match the manifest;
- every record is ACCEPTED + `PENDING_ADJUDICATION`;
- the filter decision was recorded before the draw;
- tests pass: 3.14 has 1,031 tests with 0 failures and 4 environment-gap import errors (`fastapi`, `httpx`,
  `torch` ×2); 3.12 runs 344 stage-2/3/4 + audit tests, all OK;
- spec SHA-256 `f1580634…` unchanged;
- no earlier round exists, and the seed is new.

**Round 1.** See `../postfilter-audit/round-1/README.md`.
- Seed: `v5-postfilter-audit-r1-2026-10-19-d66`.
- `sample.jsonl`: 453 items, `eb001e95…`.
- Blind human subsample: 200 items, `8667a427…`.
- Separate annotator packets: a1 `8b271935…`, a2 `f5c9f3d3…`.
- The draw reproduces byte-identically on CPython 3.12 and 3.14 with two hash seeds.
- Baseline report: 10 / 10 categories `PENDING_ANNOTATION`.

## Reproduce

```
python3 scripts/dataset/build_v5_attack_pool.py --check-determinism --summary reports/v5/dataset-foundation/attack_pool_summary.md
python3 scripts/dataset/build_v5_attack_pool.py --out datasets/v5_sources/candidate_denylist_v2 --denylist scripts/dataset/v5_lexicon/patt_third_party_denylist_v2.json --check-determinism
python3 scripts/dataset/reconcile_v5_attack_pool.py --attack-dir datasets/v5_sources/candidate_denylist_v2/attack --denylist scripts/dataset/v5_lexicon/patt_third_party_denylist_v2.json --out reports/v5/data-readiness/attack_pool_reconciliation_denylist_v2_candidate.md
python3 scripts/dataset/audit_v5_postfilter.py plan [--attack-dir datasets/v5_sources/candidate_denylist_v2/attack]
# after approval (owner): sample --round 1 --seed <new>; annotators write annotations_a1/a2.jsonl + annotators.json;
# adjudication-sheet; human-batch --batch N; report --round 1
```
