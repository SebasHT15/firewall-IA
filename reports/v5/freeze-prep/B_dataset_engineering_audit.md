# Workstream B — V5 dataset engineering audit (Issue #64, freeze preparation)

> **Dated note (2026-10-13).** Superseded where it differs by **D58/D59/D60** and V5 DRAFT r3. Examples: the labeling, metadata and grouping-key proposals are adopted only as written in r3 §4; the split follows r3 §4.6. This audit is kept unchanged as historical evidence.


Date: 2026-10-11. Status: **audit and proposals, not decisions.** Nothing here generates a dataset, trains,
runs a model or changes `DECISIONS.md`. Files created by this workstream: this report,
`scripts/dataset/v5_dataset_checks.py`, `tests/test_v5_dataset_checks.py`. No existing file was modified.
No External Test v1 case, `model-output-*` file or frozen report was read; no probe text, template or value
was copied into any material below.

Tags: **FACT** = read in the repo this session (cited `file:line` or report path). **INFERENCE** = follows
from facts, not measured. **PROPOSAL** = my design suggestion, owner decides. **OWNER** = open decision.
Every number below is quoted from a cited source; none is invented. Where I need a number I state the rule
(or the existing repo convention) and leave the value to the owner.

Scope boundaries: Workstream A owns the canonical HTTP rendering (I only note dependencies), Workstream C
owns the partition strategy and evaluation protocol (I only define the keys the generator must emit).

---

## 1. Reusable components (V4 generator, E0 gate, builders)

Cited lines are `scripts/dataset/parse_dataset_v4.py` (`P4`) unless stated.

| Component | Where | Reuse for V5 | Notes |
|---|---|---|---|
| `canonical_key(payload)` | P4:659-681 | **Import as is.** 3-layer `unquote_plus`, `\u003c`/HTML-entity decode, `/**/` strip, whitespace collapse, `${IFS}`, lowercase | FACT: operates on any string. It is already the project-wide identity (phase_d_gate, paired_dev_set mirrors it, analyzer D54). INFERENCE: applied to a **whole request** it also hashes the randomised envelope, so payload-level duplicates behind different envelopes are not detected. V5 must therefore also canonicalise at **leaf/payload level** (see §6 `payload_group_id`). |
| `group_id(kind, key)` | P4:684-685 | Import. `sha256(kind NUL key)[:32]` | Use distinct `kind` strings for `attack_payload`, `benign_value`, `template`, `family`. |
| `assign_split` idea | P4:688-696 | **Copy the idea, not the function**: hash-bucket, salt, order independent. | FACT: it is hard-wired to 2 splits (`eval` vs `train`). V5 needs k-way and a provider-level step first. |
| Shared envelope `build_envelope(rng, host)` | P4:216-243, pools P4:151-189 | Reuse as the **class-neutral** envelope source, seeded per group (P4:1358 `Random(f"{salt}|{gid}")`). | FACT: no benign-only or attack-only header pool exists. Workstream A may extend it (Content-Length on bodies, other ports, loopback-IP host — audit §3.4). Wrap, do not edit. |
| Attack pool: `extract_sources`, `quality_filter`, `build_hardcoded_sources` | P4:481-518, 524-572, 635-653 | **The only legitimate source of "attack twin" payloads.** | FACT: deterministic (sorted traversal), per-reason rejection accounting, aborts if a category directory is missing. External dependency `~/PayloadsAllTheThings` pinned only by commit in the manifest (`e961fef2…`, `datasets/manifest_v4_clean.json`). |
| Category→reason/shape maps `CATEGORY_SHAPES`, `HARDCODED_SHAPES`, `CAUSAL_EXCEPTIONS` | P4:392-457 | Reuse **category vocabulary and reason strings** (D47 vocabulary is built on them); use `CATEGORY_SHAPES` as the starting point for a slot-compatibility matrix (§5). | Shapes' path/param pools are V4 specific (see §2). |
| `TRAIN_TRANSFORMS` / `HELD_OUT_TRANSFORMS` (D15) | P4:708-751 | Reuse the partition, keep held-out transforms generating nothing. | FACT: today transforms are applied to attack payloads only (P4:1364-1371). |
| `encode_target_value`, `quote(v, safe="")` | P4:757-763 | Reuse **one encoder for both classes**. | See §2 item 10. |
| Grouped-before-render order (D16) | P4:1335-1376 | Keep the order SOURCE → group identity → split → render → variants. | |
| `sha256_file`, `git_rev` | P4:1128-1142; `check_dataset.sha256`/`git_rev` | Import `check_dataset.sha256`. | |
| Manifest idea (D6) | P4:1598-1680 | Keep the keys (generator, commit, seed, params, per-category counts, artifact SHA-256, known limitations) and extend (§8). | FACT: V4 manifest lists `artifact_sha256` by name **without paths**. |
| `git_state()` with `code_sha256` and `committed_unchanged` | `build_hybrid_analyzer_v2.py:308-321` | Re-implement these ~12 lines in the V5 builder (importing the builder pulls pandas/numpy). | Good provenance idiom: hashes of every code file the build depends on + clean-tree flag. |
| `pools_sha256()` (SHA-256 of each value pool) | `minimal_pair_probe_v2_cases.py:132-134`, `minimal_pair_probe_cases.py:194` | Reuse the **idiom** (`sha256(json.dumps(pool, sort_keys=True))`) for V5 pools. | Do **not** import or read the probe pools: disjointness is asserted against their recorded hashes/values by a test, not by sharing data. |
| `components()` union-find | `build_hybrid_analyzer_v2.py:84-111`; `paired_dev_set.dependency_components` 758-782 | Use the pattern for `family_id`. | FACT: both are tied to their own row schemas; neither is generic. |
| Forbidden-input guard `guarded_path` | `audit_v5_benign_coverage.py:65-73` | Copy the pattern into the V5 builder: refuse `datasets/external_v1`, `reports/external`, `docker/.lab-logs`, `datasets/v4_clean/eval.jsonl`. | |
| Marker extraction/aggregation | `audit_v5_benign_coverage.py:320-500`, `aggregate` 514-552, `support_status` 508 (MIN_GROUPS = 30) | Run unchanged on the **V5 candidate** as the distributional shortcut/coverage audit (§4 S1, S10). | FACT: `extract_markers(text)` and `aggregate(rows)` are generic (rows need `text,label,gen_group,d54_group,source`). `load_train_rows` is V4-specific. |
| E0 helpers | `check_dataset.py`: `load_jsonl` 111-122, `parse_request` 155-187, `fit_predict_accuracy` 209-225, `feature_extractors` 228-256, thresholds 49-83 | Import `load_jsonl`, `sha256`, `parse_request`, `fit_predict_accuracy`; reuse the **threshold constants** (80% absolute, +20 pt margin, 99% purity at 1% coverage). | FACT: `main()` (271-647) is V4 path and `output`-prefix specific, envelope features only, exact-match leakage only. |
| Collision gate pattern | `phase_d_gate.collision_check` 262-313, `internal_duplicates` 316-349 | Pattern only; generalised in `v5_dataset_checks.check_protected_collisions`. | FACT: hard-wired to External candidate dicts and V4/diag/smoke. |
| Freeze validation + integrity hash | `freeze_external_v1.validate` 131-168, `integrity_hash` 171-174 | Pattern for a V5 freeze validator: recompute SHA of every text, assert uniqueness, assert counts per cell. | |
| Manifest hash verification at load | `hybrid_analyzer.load_dataset` 70-85; `analyzer_external_v1.verify_sha256sums` 193-214 | Pattern; generalised in `verify_manifest`. | |
| Paired-oracle pattern | `paired_dev_set.oracle_check` 644-653, `FAMILY_SIGNATURES` 601-641 | Pattern for the generation-time label oracle (§5). | FACT: attack must match a family signature, benign must contain no hard attack token. |

## 2. Not reusable (V4-specific) — must NOT be carried into V5

All FACT, with the consequence (INFERENCE) in brackets.

1. **Fixed benign value pools** (`BENIGN_VALUES` P4:919-959; name/product/city pools 887-898): five fixed comment
   sentences (947-954), passwords are `_b64ish(12)`, alphanumeric only (945-946), single-token search values.
   Audit §3.2: `the` 390, `please` 168, `https` 203 benign-skewed groups vs 27/1/121 attack. [Reverse shortcuts, evidence-matrix #12.]
2. **Benign group identity is decoupled from rendered content.** The benign group id hashes
   `shape|path|param|value` (P4:1330-1333) but rendering calls `render_request(srng, g["shape"], None)`
   (P4:1373-1376), which **redraws** path, parameter and value (P4:853-865); `recover_v4_provenance.py` docstring
   confirms "the renderer redraws path, parameter and value". [Group-disjointness for synthetic benign is nominal:
   the same drawn value can sit in TRAIN and EVAL. V5 must render **from** the group's declared value tuple and assert it.]
3. **Declared Content-Type vs body mismatch only on benign.** Benign branch draws `ctype` from the shape's pool and
   emits a form body (P4:858-860); attack branch emits JSON when `ctype` is JSON (P4:870-871). Audit §3.3: 661 benign
   groups declare JSON with a form body vs 74 attack. [Carrier shortcut.]
4. **JSON bodies are single-key** (P4:844-846, 871); no multi-key, typed, nested JSON (audit §3.3, evidence-matrix #10).
5. **Single-parameter benign** forms/queries (P4:855-865).
6. **`HOSTS` doubles as the benign URL value pool** (P4:933-936 draws `rng.choice(HOSTS)`; `HOSTS` P4:151-162 contains
   `localhost:8080`, `10.20.30.40:8000`, `target.internal.com`, `intranet.corp.local`). [Benign-labelled internal URLs contradict the
   F5 rule "benign never targets internal/metadata hosts" (audit §8 F5). Never reuse envelope hosts as value pools.]
7. **Attack-only encoding:** attack payloads are always fully percent-encoded in query/form (`quote(..., safe="")`,
   P4:806, 873-875) while benign values contain no punctuation to encode. Audit §3.1: `%27` 19 benign vs 1,906 attack
   groups, `%23` 0 vs 624, double encoding 0 vs 3,142. [Encoding-layer shortcut, the core of evidence-matrix #6.]
8. **Attack-only variants.** Augmentation emits transform variants for attack groups only (P4:1364-1371);
   `whitespace_tab`, `/**/` and case variants therefore occur only on BLOCK rows. [Variant artefact ⇒ class.]
9. **Row-level destructive balancing:** method-stratified 1:1 trimming (P4:1529-1554), D17 round-robin row cap
   (nested `subsample`, P4:1455-1492, not importable). [Both break twin pairs. V5 pairs are balanced by construction; any trimming must remove whole pairs.]
10. **Tautological invariant.** The "no group in both splits" assertion (P4:1409-1413) compares `(gid, split)` tuples although
    `split` is a pure function of `gid`, so it cannot fail; the real cross-split protection is an **after-the-fact silent removal of eval rows
    whose text equals a train row** (P4:1402-1407). [V5 must assert on rendered rows carrying meta, and count/gate collisions instead of removing silently.]
11. **Provenance stripped from the output** (P4:1564-1566 drops `_gid/_src/_cat`); `recover_v4_provenance.py` had to re-run the generator under a `json`
    shim to recover it. [V5 persists meta (§6).]
12. **Two-way split** `train`/`eval` at 20% (P4:125, 688-696) and no provider or structure notion. [D37 needs 4 roles.]
13. **CSIC** (P4:996-1122): benign passes through `csic_group_key` digit-collapse; BLOCK labels come from an 11-rule keyword heuristic (audit F6, manifest limitation) and 19,165 anomalous records are reserved. The draft spec (§3) does not say whether CSIC stays (OWNER, §9 Q7).
14. **Monolithic `main()`** (P4:1145-1745) with module-level paths; nothing in the pipeline is importable besides the helpers above.
15. **Path/param pools in `SHAPES`** (P4:260-389) encode V4's endpoint vocabulary; V5's structure source is OpenAPI skeletons (research note I), not these.

## 3. Family-by-family gaps in the draft spec

FACT about the draft (`reports/v5/v5-data-spec-draft/README.md`): §2 gives concept, class and evidence per family but **no target counts or ratios,
no label rule, no named attack twin, no value source per family**; §3-§4 give sources and grouping at a general level. The draft's own §5 defers the canonical form to Workstream A.
"Specified?" below means: could an engineer implement the generator for this family without asking the owner.

Columns: **L** label rule, **C** carriers, **T** attack twin, **N** counts/ratios, **V** value source.

| Family (draft class) | Specified? | Missing / ambiguous |
|---|---|---|
| Percent-encoded punctuation `'` `#` `!` `&` `;` (HIGH) | Concept yes | **L**: when is `'`/`;`/`&` benign vs attack? Needs the benign/attack boundary rule of §5 (human syntax vs executable syntax). **C**: "many fields/carriers" — list of carriers/serialisations not fixed (query, form, JSON string, path segment? header?). **T**: twin = same slot with payload from the attack pool; slot-category compatibility matrix missing. **N**: none; propose cell-based rule (§7). **V**: Wikidata labels (CC0, real persons: recombine only) and synthetic punctuation insertion (research note I §3.2) — "inserted punctuation" is itself a generator fingerprint (R4/R6). Mechanism hypothesis (glyph vs `%` triplet) unresolved (evidence-matrix §3.2), so both literal and encoded forms are required **per carrier where legal**, which needs Workstream A's encoding rules. |
| Legitimate apostrophes (HIGH) | Yes as coverage breadth | Subsumed by the row above; no separate generator needed. Label rule and V as above. Spec should say "not a separate family" to avoid double counting. |
| Street addresses (HIGH) | Concept yes | **V**: no address corpus named. Research note B lists names (Wikidata) and free text (NQ) but **no address source** and no license; synthetic composition (number + street noun + unit) risks a fixed grammar = fingerprint. **L**: benign always; attack twin payload in the same slot. **C**: "vary field names" — pool of address-like **and** non-address field names, drawn independent of class. Evidence #1 says the trigger inside "street" is not isolated: generate broad variety (noun, `Apt/Unit/#`, ordinal, punctuation). |
| Realistic passwords (MED-HIGH) | Partly | **V**: NIST 800-63B printing-ASCII policy (B §3), no breached corpora — fine. **L** ambiguity: password slot with an attack payload = attack twin; "credential stuffing" is stateful/behavioural and **cannot be labelled per request** → declare NOT TESTABLE, not a family. **T**: login form with payload in `password` (and in `username`). **Risk**: random printing-ASCII strings can contain attack substrings (`'--`, `<s`); the oracle (§5) must reject and count them. |
| Multi-key typed JSON incl. nested/array (HIGH/MED) | Concept yes | **C**: depth, key count, type mix distribution unspecified (research note I §1.2 gives mechanics, no targets). **T**: payload in one leaf at varying depth; also JSON **keys** as injection points? (NoSQL operators as keys) — OWNER. **Content-Type/body consistency** must hold for both classes (fixes item 2.3). **Stability** target (§6 of draft) has no generator-side meaning until Workstream C defines the gate. |
| External URLs / callbacks / webhooks incl. `http://` (MED-HIGH) | Concept yes | **L is the open problem** (Q1 in §9): the draft excludes `next`/`return_url` shapes "which may legitimately BLOCK" but gives no rule for the rest. SSRF vs benign differs by **target** (internal/metadata/loopback/non-http schemes) not scheme (audit §8 F5). **Hosts**: reserved names only (RFC 2606, research note I §2.1); do not reuse `HOSTS` (item 2.6). |
| Multi-field forms (MEDIUM) | Concept yes | **L**: repeated names / arrays vs HPP (audit §8 F3 flags it, the draft does not). **N**: 2-field and 4-field absent in both classes (audit §3.3): the generator must emit the full field-count range in both classes. |
| Multi-parameter queries (MEDIUM) | Concept yes | Same as above; evidence says count alone is weak, so no priority beyond coverage. |
| Realistic free text (MEDIUM) | **No** | **V missing**: NQ queries are lowercase, unpunctuated (B §3) and CC BY-SA 3.0 (share-alike, OWNER/legal); no corpus with punctuation, sentences >64 chars and permissive license is selected. Candidates to verify (UNVERIFIED, no network used here): Tatoeba sentences, Common Voice sentence collector, Project Gutenberg. LLM-written text = new fingerprint (B §4.1, RESTGPT note). **T**: payload embedded in prose (not only replacing the field) or prose becomes "benign-looking leaf ⇒ benign". |
| Chunked framing in shared envelope (MED-HIGH) | **Contingent** | Depends on Workstream A: if V5 sees a canonical de-chunked request (draft §5 option C) the family becomes "TE header present + de-chunked body" at equal rates in both classes; if framing is removed from ML input (option B) the family disappears and **Request Smuggling** (7 logical groups, NOT EVALUABLE in V4 per manifest) loses its ML basis. **L**: smuggling = conflicting framing, deterministic; OWNER decides whether Request Smuggling stays an ML category. |
| SQL/shell-homonym prose (LOW) | Concept yes | Same free-text source gap. Cheap to fold into free text; not a separate generator. |
| Encoded paths (LOW) | Weak | Audit §8 F6 rates it a family (encoded `%2F`/`%20`, depth ≥ 4, literal `%25`) and the #60 diagnostic shows a mixed-decision profile on `%2F` static paths (audit §4); the draft rates it LOW on v1 evidence. Keep a minimal generator; label rule: benign encoded paths must never decode to `..`; traversal twin at the same depths. |
| Symmetric attack counterparts (REQUIRED) | Principle only | No definition of **which categories** go in **which slots**, **how** the payload enters (replace vs embed), nor the share per category (V4 D17 caps exist: 2,500 groups, 4,000 rows per category). |
| **Not in the draft but evidenced** | — | (a) **Envelope realism** (audit F7): `Content-Length` on every real body (9 of 13,686 V4 body rows have it, P4:364-370 shape only), ports other than 8000/8080, loopback-IP `Host`, `Proxy-Connection`; only chunked is mentioned. Dependency on Workstream A. (b) **Relationship to V4-clean data**: is V5 = V4 + new families, or a rebuild? The 19 V4 attack categories need benign counterparts today supplied by V4's shape-matched benign (and `BENIGN_XML`/`BENIGN_GRAPHQL`, P4:900-916). The draft never says. (c) **IP/host-valued data fields** (non-fetch): `127.0.0.1` occurs in 58 V4 TRAIN rows, all BLOCK, never as Host (audit §3.4, §6.6). |

## 4. Shortcut / contamination risks and measurable checks

Principle (FACT, draft §4, research note I R1-R11): a feature that predicts the class without reading the malicious content is a defect. Existing machinery measures the **envelope** only
(`check_dataset.feature_extractors` 228-256). The checks below extend it. "Reuse" names the existing function; "NEW" means to be written once Workstream A fixes the representation
(not written here: feature definitions depend on A, thresholds are policy).

Shared protocol for every check, **PROPOSAL**: fit a lookup table on TRAIN (`check_dataset.fit_predict_accuracy`, 209-225), score on VALIDATION; report accuracy, margin over majority, coverage, cell count; FAIL on the E0 constants (≥ 80% absolute, or +20 pt, or any value ≥ 99% pure at ≥ 1% coverage — `check_dataset.py:54-62`). Run **globally and inside every (family, carrier) cell**; a pass overall can hide a cell-level leak.

| # | Risk | Where it comes from | Measurable check | Status |
|---|---|---|---|---|
| S1 | **Token ⇒ class** (`the`, `please`, `https`, `select`, `octocat`, vendor words) | fixed benign pools (2.1); spec example placeholders (research note I R5) | (a) single-token lookup over decoded value leaves: any token with ≥ 1% coverage and ≥ 99% purity fails; (b) `audit_v5_benign_coverage.aggregate` on the candidate: per-marker `benign_group_share`, flag markers whose share is outside a pre-registered band; (c) vendor-token scan + 5-gram no-copy filter drop counts (research note I §2.3-2.4) | (b) **reuse**; (a) NEW; (c) in generator |
| S2 | **Carrier ⇒ class** (method, Content-Type, body syntax, declared-vs-actual type, field count, JSON shape, path style, query vs body) | benign/attack drawn from different carriers (2.3-2.5) | single-feature lookups on these; plus a **cell-balance table**: each (family, carrier) cell must contain both classes at ratio 1:1 within a pre-registered tolerance (twins make this exact by construction, so any deviation is a bug); explicit assertion `declared Content-Type == detected body syntax` for 100% of rows (`audit.body_syntax`, 157-177) | `parse_request` + `fit_predict_accuracy` **reuse**; body-syntax **reuse**; cell table NEW (small) |
| S3 | **Serialisation style ⇒ provider ⇒ class** (Stripe form-brackets vs GitHub JSON, research note B2 §3.3) | each provider has one natural style; attack rendered differently | (a) style × class contingency per provider; (b) **provider fingerprint probe**: lookup from structure-only features (method, path skeleton, key set, style) to `provider_family` on VALIDATION — report accuracy (B2 §4 item 4); (c) every skeleton rendered in ≥ 2 legal styles in both classes (counts per style × class equal) | NEW |
| S4 | **Length / token count ⇒ class** | PATT payloads are 4-400 chars (`MIN_LEN,MAX_LEN` P4:478) while benign pools are short; attack-only longer leaves | bucketed lookup on total length, body length, longest leaf length, token count; plus per-cell two-sample comparison (class share per length bucket within ±tolerance) | NEW |
| S5 | **Header set / count / order ⇒ class** | envelope drawn per class; CL only on smuggling shape | `check_dataset` 4a-4g and generic per-header scan **unchanged** on V5; extended list once A fixes the header set (CL, TE) | **reuse** |
| S6 | **Encoding layer count ⇒ class** (`%XX` only on attack, double encoding only on attack) | item 2.7 | histogram of percent-decoding layers (0..3) and presence of `%25`, `%27`, `%23`, `%21` per class per carrier; require both classes to populate each non-empty cell; `audit.decode_layers` 121-140 | **reuse** `decode_layers`; table NEW |
| S7 | **Field name ⇒ class** | slot names tied to class (`address`, `password`, `url` mostly benign or attack) | lookup on field name and on name tokens; evidence-matrix #2 says names are not drivers, so names must be drawn independent of class and of value role; report purity per name | NEW (tiny) |
| S8 | **Template / path skeleton ⇒ class** | endpoint mix differs between classes | structure-only probe (method, path template, key names, content type): AUC CI must cover 0.5 on grouped VALIDATION (research note B §4.2 item 2) | NEW; needs an AUC routine (rank statistic, stdlib) |
| S9 | **Value-pool entry ⇒ class** | entry used in one class only (placeholder tokens, sentences) | per `value_pool_id`/entry purity; an entry used by both classes appears in twin pairs (pair members share all non-attack leaves), so purity should be 50/50 for pair-shared leaves | NEW (needs meta) |
| S10 | **Slot-conditional punctuation** (`'` only in name slots, `#` only in URL slots; research note I R6) | natural-slot recipes | marker × slot-role contingency; every punctuation marker must occur in both classes in ≥ 3 distinct slot roles; reuse `extract_markers` + slot role from meta | partly **reuse** |
| S11 | **Attack-leaf form ⇒ class** ("leaf is a bare payload" vs "leaf is prose/name") | twin built by replacing a leaf | `placement_mode` (replace / prefix / suffix / embedded) recorded per attack row; benign twin shares the surrounding text in non-replace modes; share per mode pre-registered; lookup on "leaf has natural-language words" | NEW |
| S12 | **Generator fingerprint** ("looks synthetic" ⇒ benign; research note I R4) | benign from renderer, attack from a different corpus | attack leaves share renderer, pools and envelope with benign; report marker-distribution distance to an independent real sample read-only (B §4.2 item 6) — never tune to it | NEW + read-only report |
| S13 | **Variant artefacts ⇒ class** (tab, `/**/`, case runs) | transforms on attack only (2.8) | count of each transform artefact per class; either apply class-neutral variants to both classes or document attack-only artefacts as intended obfuscation | **reuse** `TRAIN_TRANSFORMS`, NEW count |
| S14 | **Provider ⇒ class** | provider with only one class | per-provider class ratio inside TRAIN | NEW (tiny) |
| S15 | **Duplicate / canonical leakage** | exact and canonical key shared across splits | `v5_dataset_checks.find_duplicates` on whole request **and** on `payload_canonical` / `value_canonical` fields | **implemented** |
| S16 | **Group leakage** | provider/template/family/payload/value-entry in two splits | `check_group_disjointness` on every key of §6 | **implemented** |
| S17 | **Label conflict** | same canonical key, two labels | `check_label_consistency` (whole request and leaf level) | **implemented** |
| S18 | **Protected-set collision** (V4, External v1, development diagnostics, probe sets) | accidental overlap | `check_protected_collisions`, counts only | **implemented** |
| S19 | **Manifest / artefact drift** | shards edited after the manifest | `verify_manifest` | **implemented** |
| S20 | **Pair-structure shortcut** (twin vs non-twin benign differ) | benign rows exist outside pairs | marker distribution of twin-benign vs non-twin benign leaves; if non-twin benign exists it must match | NEW |

INFERENCE: S1/S2/S6 are the three that explain most of the V4 benign false blocks recorded in the evidence matrix (#6, #12, audit §3.1-3.3); they should be the first gates implemented.

## 5. Labeling policy

### 5.1 Proposed rule (PROPOSAL, construction-time, never model- or keyword-inferred)

The label is a function of **provenance**, recorded as `label_rule`:

| `label_rule` | Condition | Label |
|---|---|---|
| `BENIGN_POOL_ONLY` | every slot value (leaf, field, path segment, query value, header value that is a model-visible slot) was drawn from a benign value generator, **and** it passes the benign oracle below | ALLOW |
| `ATTACK_POOL_LEAF` | exactly one slot value was produced by the **attack-leaf operator** from an entry of the existing attack pool (`extract_sources`/`build_hardcoded_sources`, after `quality_filter`) and the entry matches the slot-category compatibility matrix | BLOCK, reason = V4 reason string of the category |
| `STRUCTURAL_<CATEGORY>` | categories whose signal is structure, not a payload (CSRF cross-origin, smuggling conflicting framing, HPP, CRLF in headers): V4 `CAUSAL_EXCEPTIONS` (P4:438-457) | per V4 rule; **OWNER** whether any of these stay in V5 (§9 Q6) |
| (none) | any row that satisfies neither | **excluded and counted**, never labelled by guess (D14 spirit) |

**Benign oracle** (FACT precedent: `paired_dev_set.oracle_check` 644-653): reject a benign candidate when (i) any slot value's `canonical_key` equals an attack-pool `canonical_key`,
(ii) a slot value contains an attack-pool canonical payload of length ≥ L as a substring (L pre-registered by the owner), or (iii) it contains a **hard token** of its slot's compatible
categories. The denylist is derived from the attack pool itself, not copied from probe or paired-dev material. Rejections are counted in the manifest. The oracle is deliberately **slot-wise and
payload-level, not token-level**: `O'Neil`, `Apt #4`, `AT&T` and `100%` must survive; `' OR 1=1--` must not.

**Attack twin** (the draft's "symmetric counterpart"): same template, same carrier, same serialisation, same envelope, same non-attack leaves; one leaf differs. Two knobs must be pre-registered
and recorded per row to avoid S11: `placement_mode ∈ {replace, prefix+payload, payload+suffix, embedded}` and `slot_role`. Category per slot comes from the compatibility matrix
(PROPOSAL: start from `CATEGORY_SHAPES` P4:392-425: free-string slots ⇒ SQLi/XSS/cmdi/SSTI/LDAP/NoSQL; URL slots ⇒ SSRF/open redirect; path/file slots ⇒ traversal/LFI; JSON leaves ⇒ NoSQL/deserialization).
The benign twin is never "a different request in the same cell": it must be the same structure with the payload slot filled from the benign generator.

### 5.2 Cases that need an owner decision

| # | Case | Why it is ambiguous | Options |
|---|---|---|---|
| Q1 | **Open redirect / `next`, `return_url`, `redirect`, `return_to` with an external absolute URL** | the same value (`https://partner.example/x`) is a legitimate webhook target and an open-redirect payload; the draft §2 and evidence #8 flag it and leave it open. FACT: V4 benign draws same-host or relative values for these names (P4:933-936), V4 attack pool has "Open Redirect" 242 groups (manifest). | **A** exclude external URLs from redirect-role names in benign and keep them attack-only (clean rule, but makes "redirect-name ⇒ BLOCK-if-external" a name×value interaction by design); **B** drop Open Redirect as a V5 category; **C** slot-role rule: navigation-role names (pre-registered lexicon) ALLOW only relative/same-host, callback/webhook/import-role names ALLOW public external hosts, internal/metadata/non-http always BLOCK. PROPOSAL: C, with both labels present for **every** name in the lexicon (so name alone never decides). |
| Q2 | **Internal/private/loopback targets in URL slots** | enterprise apps legitimately call intranet hosts | PROPOSAL: policy label BLOCK for every SSRF-shaped target regardless of app (consistent with audit §8 F5); document as a policy, not a fact about benignness. |
| Q3 | **Passwords: benign vs credential stuffing** | stuffing is stateful, per-request content is a valid password | PROPOSAL: per-request label only; credential stuffing/brute force = NOT TESTABLE (stateful) and stays out; payload-in-password is the attack twin. |
| Q4 | **Benign text that *quotes* attack syntax** (a comment about SQL, a developer forum post, a security blog) and **legitimate query DSLs** (search operators, Mongo-style filters in an API that is *meant* to accept them, GraphQL) | WAF-level classification is syntactic; intent is not observable | OWNER: define "executable syntax in a slot that is not a documented syntax slot" ⇒ BLOCK, and decide whether to include documented-DSL slots as benign families (V4 already has benign GraphQL/XML pools). Default PROPOSAL: exclude, count as `AMBIGUOUS_EXCLUDED`. |
| Q5 | **HPP / repeated parameter names** | arrays as repeated names are normal (audit §3.3, F3), HPP attacks use the same syntax | OWNER: either (a) HPP only via privilege-semantic names (V4 `repeated_params` names, P4:372-380), which makes the *name* the signal and contradicts evidence #2, or (b) drop HPP from ML (deterministic duplicate-name policy elsewhere). |
| Q6 | **Structural categories (CSRF, smuggling, CRLF, HPP)** | signal is not a payload; interaction with Workstream A (canonical request, header policy D44) | OWNER after A. |
| Q7 | **CSIC** | D13 baseline source; 2010 Spanish e-shop; keyword-label noise (audit F6); the draft does not list it | OWNER: drop, or keep capped as a single `provider_family` that may only be TRAIN. |
| Q8 | **Benign values that resemble attack primitives**: `5'11"`, `a<b`, `C:\path`, `#hashtag`, hex colours vs `0x`, IPs as data, `100%` | each can be a real value and a real payload fragment | PROPOSAL: allowed in benign **only** when the oracle (payload-level) passes; each concept gets a quota in both classes; list pre-registered by owner. |
| Q9 | **Request Smuggling** if framing is validated deterministically (draft §5) | 7 logical groups in V4, NOT EVALUABLE | OWNER after A. |

## 6. Grouping keys the generator must emit (for Workstream C)

PROPOSAL, per row, persisted (not recomputed later; see item 2.11). All identifiers are deterministic `group_id(kind, key)` strings except `seed`.

| Field | Meaning |
|---|---|
| `provider_family`, `sub_family` | source API/provider; sub-family for per-provider caps (research note I §4.1) |
| `template_id` | SHA-256 of the canonical **structural** form (method, content type, path skeleton, body tree with types/optionality, depth; names excluded) |
| `family_id` | union-find component of templates (same `template_id` or typed-leaf-path Jaccard ≥ cutoff, cutoff OWNER) |
| `pair_id` | the benign row and all its attack twins; pairs never split |
| `twin_role` | `benign` / `attack` |
| `payload_group_id` | `group_id("attack", canonical_key(payload))` — the **same identity V4 uses**, so disjointness from V4 groups and between V5 splits can be asserted. Needed because provider-level holdout does not stop one PATT payload landing in TRAIN and VALIDATION through different templates |
| `value_pool_id`, `value_entry_ids` | pool name+version hash, entry hash(es) drawn; allows "no pool entry in two splits" (research note I §5.1 step 3) |
| `family`, `carrier`, `serialization`, `slot_role`, `placement_mode` | cell coordinates for S2/S3/S10/S11 |
| `attack_category`, `label`, `label_rule` | label provenance (§5.1) |
| `transform`, `variant_of` | D15/D16 variants (None for base row) |
| `seed` | per-row RNG seed string `f"{salt}|{group}"` (idiom P4:1358), not a global counter |
| `split` | assigned role (TRAIN/VALIDATION/INTERNAL TEST), recorded for audit only |
| `row_id` | `sha256(input)` — joins model-visible text to meta |
| `generator_version`, `schema_version` | provenance |

Storage (PROPOSAL, INFERENCE on trainer): keep the model-visible file V4-shaped (`instruction`, `input`, `output`) and write meta to a line-aligned sidecar `*.meta.jsonl`
(hashed in the manifest). `finetune.py` loads with `load_dataset("json")` and maps `format_example` (scripts/training/finetune.py:211-223); I did not test whether extra heterogeneous columns are
harmless, so the sidecar avoids the question. `v5_dataset_checks` takes any list of dicts, so it works on the merged rows.

Split mechanics (owned by C, stated here only as generator constraints): (1) split decided **before** render, on `provider_family` then structure (`family_id` purge), (2) payload groups and value entries partitioned
independently with a hash bucket and **k-way** assignment, (3) a row is placed in split S only if provider/family **and** payload group **and** value entries all belong to S (otherwise it is dropped and counted),
(4) assert on rendered rows with meta (§1 table, item 2.10).

## 7. Proposed minimal generator structure

Principle: reuse > rewrite; the V4 generator stays untouched (it is the control for earlier comparisons, same reason as in its own docstring).

```
scripts/dataset/
  v5_sources.py        SOURCE: load pinned specs -> neutral skeletons (research note I E1-E6); value pools (hashed);
                       attack pool = parse_dataset_v4.extract_sources + build_hardcoded_sources (imported)
  v5_groups.py         IDENTITY + SPLIT: template_id, family_id (union-find), pair_id, payload_group_id, value_entry ids;
                       provider-level then k-way hash-bucket assignment (idea of assign_split)
  v5_labels.py         label rules, slot-category matrix, benign oracle, attack-leaf operator (placement modes)
  v5_render.py         carriers -> request text through Workstream A's canonical renderer; envelope = build_envelope (wrapped)
  v5_generate.py       orchestration + CLI + manifest; calls the checks at the end
  v5_dataset_checks.py (exists) duplicates / groups / labels / manifest / protected collisions
```

Data flow (functions pure, RNG seeded per group, never a shared stream):

```
SOURCE (specs, pools, attack pool; all pinned and hashed)
  -> skeletons (types, optionality, depth; identity stripped)            [v5_sources]
  -> group identity: provider_family, template_id, family_id             [v5_groups]
  -> SPLIT (provider level, purge by family_id, k-way payload/value)     [v5_groups]   <- before any rendering (D16)
  -> pair construction: benign value tuple from pools; attack twin =
     same tuple with one leaf replaced via attack-leaf operator          [v5_labels]
  -> oracle: benign and attack validated, rejects counted                [v5_labels]
  -> render: shared envelope; carrier x serialisation variants in BOTH classes; D15/D16 variants   [v5_render]
  -> assert on rendered rows + meta (no silent drops), dedupe, write JSONL + meta sidecar   [v5_generate]
  -> manifest, then v5_dataset_checks + shortcut gates                   [v5_generate]
```

Rules distilled from §2: render **from** the declared tuple and assert identity↔content; one encoder for both classes; Content-Type must match the body; benign pools hashed and versioned; no URL value pool shared with envelope
hosts; balance by pairs, never by row trimming; variants apply to both classes or are recorded as attack-only.

## 8. Manifest and provenance (D6)

D6 (DECISIONS.md:220-258) requires: generator, source commit, params + seed, manifest, per-category counts, train/eval counts, SHA-256 of artefacts, deterministic generation. V4 manifest meets this
(P4:1598-1680) but lists artefact hashes without paths. PROPOSAL for V5, additions marked +:

- `schema: "v5-dataset-manifest/1"`, `status`, `data_role` per D37 (which splits are TRAIN/VALIDATION/INTERNAL TEST), `external_test_v1: "not read"` (precedent: hybrid_analyzer_v2 manifest).
- Generator provenance: `git head`, `committed_unchanged`, `code_sha256` of every dependency file (idiom `build_hybrid_analyzer_v2.git_state`), Python version, `PYTHONHASHSEED`, +lockfile hash of any parser library.
- Inputs: PATT commit **and** SHA-256 of the attack-pool extraction; OpenAPI spec repo **full 40-char commit** + file path + file SHA-256 per spec (B2 §5: short SHAs are not pins); per-spec licence record (`info.license`, `x-origin`, date) with missing licence = exclude; +`THIRD_PARTY_NOTICES` hash; value pools: name, version/date, `pools_sha256`; lexicon/denylist/K/cutoffs in one config file with its hash.
- Seeds: master seed, per-stage seeds `hash(master, stage, key)` (research note I §8), provider→split assignment written **before** generation.
- Counts: per `(split, family, carrier, label)`, per attack category, per provider, pairs, purged rows, rejected rows per reason (oracle, denylist, no-copy, schema), `AMBIGUOUS_EXCLUDED`.
- +`label_rules` histogram, `placement_mode` histogram, `serialization` × class table.
- +`checks`: the JSON outputs of `v5_dataset_checks` (duplicates, groups, labels, protected collisions) and the shortcut gates, embedded; the manifest is not valid without them.
- Artefacts: `artifacts: [{path, sha256, bytes}]` for every shard and sidecar (layout recognised by `verify_manifest`), +determinism evidence: second run byte-identical hash.
- `known_limitations` (as V4), including that diagnostic flips are not FPR (D42).
- Freeze discipline: immutable once a model is trained on it; any change is a new version (precedent D54, D39).

## 9. Open questions for the owner (consolidated)

1. Open-redirect names (Q1) and internal-target policy (Q2).
2. Is V5 TRAIN = V4-clean + new families, or a full rebuild (the draft is silent)? Which of the 19 V4 attack categories remain, and where do their benign counterparts come from?
3. Where does the payload enter a benign structure (`placement_mode` shares) and which categories are allowed per slot role?
4. Free-text and address value sources and licences (NQ share-alike; no address source named).
5. Provider diversity: only GitHub and Stripe are confidently MIT (draft §3); leave-provider-out is degenerate with two providers (B2 §3.3). Minimum number of provider groups to freeze?
6. Structural categories and Request Smuggling after Workstream A's decision; HPP policy (Q5).
7. CSIC kept or dropped (Q7).
8. Thresholds for S1-S20 (the E0 constants are proposed as defaults; numbers beyond them are not chosen here) and the L length in the benign oracle.

## 10. Utilities implemented

Search first (FACT, grep over `scripts/`, `tests/`, `data_plane/` for `dup|leak|collision|disjoint|manifest|sha256|verify|overlap|integrity`):
no generic equivalent exists. `check_dataset.py` (E0) is V4-path-specific, exact-match leakage only; `phase_d_gate.collision_check`/`internal_duplicates` are bound to External candidate dicts;
`build_hybrid_analyzer_v2.within_split/check` and `paired_dev_set.dependency_components` are bound to their schemas; `hybrid_analyzer.load_dataset` and `analyzer_external_v1.verify_sha256sums` verify one layout / a SHA256SUMS file.

Created `scripts/dataset/v5_dataset_checks.py` (standard library + `check_dataset.load_jsonl/sha256` + `parse_dataset_v4.canonical_key` **imported**, no re-implementation):

| Function | Contract |
|---|---|
| `find_duplicates(splits, text_field, key_fn=canonical_key, fail_on_within_exact=False)` | within-split exact and canonical duplicate counts; for every split pair, shared exact and canonical keys (rows and example indices). Fails on any cross-split canonical sharing. Works on any text field, so run it also on leaf-level fields. |
| `check_group_disjointness(splits, keys)` | for each key (field or composite tuple) the value sets are pairwise disjoint; missing key fields fail. |
| `check_label_consistency(splits, text_field, label_field/label_fn)` | one canonical key (and one exact text) never carries two labels, in or across splits. |
| `verify_manifest(manifest, base_dir, paths)` | recomputes SHA-256 and size of each listed artefact; recognises the V5 `artifacts` list, the hybrid `artifact` object and the V4 `artifact_sha256` map (needs `paths`). Declared paths cannot leave `base_dir`. |
| `check_protected_collisions(candidate, protected, text_field)` | exact and canonical collisions of candidate rows against protected sets with per-set text field; returns counts and candidate row indices only, never text. |
| `main(argv)` CLI | subcommands `duplicates`, `groups`, `labels`, `manifest`, `collisions`; exit 0 PASS, 2 FAIL, 3 could not run (same codes as `check_dataset.py`). |

Not implemented, deliberately: the shortcut/lookup audits (S1-S14, S20). They need Workstream A's request representation and policy thresholds; the building blocks to reuse are listed in §4.
Payload-level collision (`phase_d_gate.collision_check` substring logic) is not generalised: it depends on a chosen minimum payload length.

Tests: `tests/test_v5_dataset_checks.py`, unittest, tiny synthetic JSONL in tempdirs.

```
python3 -m unittest tests.test_v5_dataset_checks -v        # Python 3.14.4 -> Ran 31 tests ... OK
.venv-analyzer/bin/python -m unittest tests.test_v5_dataset_checks   # Python 3.12.15 -> Ran 31 tests ... OK
```

Verified on the real manifests (hash recomputation only; no case text was inspected): `verify_manifest` on `datasets/manifest_v4_clean.json` with explicit `paths` ⇒ train/eval `ok`;
on `datasets/manifest_hybrid_analyzer_v2.json` ⇒ `ok`. The `datasets/v4_clean/eval.jsonl` bytes were hashed once for this check and not opened for content.

## 11. Limitations

- Static analysis: I read code, manifests and reports; I did not regenerate V4, run the generator or measure any new number. Counts quoted come from the cited manifest/reports.
- `audit §3.x` statistics describe V4-clean TRAIN only; the V4 INTERNAL TEST and External v1 were not consulted.
- Line numbers are as of the working tree on branch `research/v5-data-spec-freeze-prep` at commit `5ce8c99`.
- The `finetune.py` behaviour with extra columns is not tested (sidecar proposed to avoid it).
- Licences of free-text/address candidates are UNVERIFIED (no network used); the legal read of OpenAPI-derived skeletons remains open (B2 §1).
- The utilities check the *generated* set; they cannot prove the benign oracle is complete or that synthetic values match real traffic (research note I R4).
- `canonical_key` lowercases and collapses whitespace, so it treats `Apt` and `apt` as the same identity; this is the project's accepted identity (D16) but is stricter than needed for leakage by case alone.
- Whole-request canonical keys include the envelope; leaf-level identity (§6) is required in addition.
