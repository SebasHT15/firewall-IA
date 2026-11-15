# E. PATT attack-pool quality and label audit (issue #64, subagent B)

**Status:** audit evidence for the V5 data specification. Nothing here is a frozen dataset or an approved plan. The annotation is an **LLM-assisted audit (Claude Sonnet subagent), not independent ground truth**; there was no second annotator at the time *(2026-10-12: a second, blind annotation by a different model and an adjudication now exist; see §11)* (see Limitations).

## 1. Purpose and scope

The V5 dataset plans to reuse the existing PayloadsAllTheThings (PATT) attack-payload extraction (`scripts/dataset/parse_dataset_v4.py`). V4 is known to carry scraper noise (CONTEXT.md section 12 F7; 94 of 95 V4 train JWT rows are not tokens). This audit measures, by reading a stratified random sample of the extraction output, how much of each category's pool is a usable attack payload of its assigned category, which failure families exist, whether the current `quality_filter` catches them, and what negative (non-signature) generator rules would help.

Out of scope and **not touched**: External Test v1, V4 eval / INTERNAL TEST, probes, any protected set, any model. The audit population is the output of `extract_sources` over PATT plus the four hardcoded categories of `build_hardcoded_sources` (CRLF, XPath, HPP, Request Smuggling variants; these are project-authored, not PATT, and are marked `hardcoded:` in `source_file`). No file was written into PATT or into any dataset.

## 2. Population

* PATT `~/PayloadsAllTheThings`, HEAD `e961fef231d8327bae83b563fab50aec2e6b77c0`, clean working tree (asserted by the script before every run).
* Extraction = unchanged V4 code: `extract_sources` (fenced code blocks of `.md`, lines of `.txt`; whole block for XXE / Request Smuggling / Insecure Deserialization), `quality_filter` (`MIN_LEN, MAX_LEN = 4, 400`), plus `build_hardcoded_sources`. The V4 module is imported, `PAYLOADS_REPO` is set to the path argument, and `quality_filter` is wrapped only to record per-category rejection reasons. The module has no import-time side effects and is stdlib-only.
* Pool = unique payloads per category under `canonical_key` (structural JSON rows use the raw string). The representative of a key is its first occurrence in the sorted traversal order.
* The V4 pipeline later applies additional steps (dedup, caps, rendering) that are **not** part of this audit population.

| Category | Tier | Origin | Candidate lines (pre-filter) | Accepted rows | Unique canonical payloads (pool) | Sample n |
|---|---|---|---:|---:|---:|---:|
| CRLF Injection | report_only | hardcoded | 0 | 24 | 22 | 15 |
| Command Injection | ml_primary | patt | 680 | 506 | 453 | 30 |
| Cross-Site Request Forgery | out_of_ml | patt | 59 | 50 | 31 | 10 |
| Directory Traversal | ml_primary | patt | 23155 | 19609 | 10219 | 36 |
| File Inclusion | ml_primary | patt | 8182 | 7653 | 3321 | 36 |
| GraphQL Injection | conditional | patt | 231 | 121 | 74 | 15 |
| HTTP Parameter Pollution | out_of_ml | hardcoded | 0 | 20 | 20 | 10 |
| Insecure Deserialization | out_of_ml | patt | 52 | 12 | 12 | 10 |
| JSON Web Token | out_of_ml | patt | 158 | 85 | 80 | 10 |
| LDAP Injection | report_only | patt | 171 | 107 | 76 | 15 |
| NoSQL Injection | report_only | patt | 151 | 118 | 83 | 15 |
| Open Redirect | ml_primary | patt | 380 | 257 | 242 | 30 |
| Request Smuggling | out_of_ml | patt+hardcoded | 9 | 7 | 7 | 7 |
| SQL Injection | ml_primary | patt | 1775 | 1336 | 1278 | 30 |
| Server Side Request Forgery | ml_primary | patt | 252 | 210 | 202 | 30 |
| Server Side Template Injection | ml_primary | patt | 566 | 393 | 369 | 30 |
| XPath Injection | report_only | hardcoded | 0 | 31 | 31 | 15 |
| XSS Injection | ml_primary | patt | 3416 | 2943 | 2238 | 36 |
| XXE Injection | conditional | patt | 159 | 116 | 102 | 15 |
| **Total** | | | 39396 | 33598 | 18860 | 395 |

Totals: 39,396 PATT candidate lines, 33,517 accepted by `quality_filter` plus 81 hardcoded rows = 33,598 accepted rows, 18,860 unique canonical payloads. Global `quality_filter` rejections (PATT only): fuzzer_placeholder 3,614; markdown_artifact 644; empty 556; too_long 373; no_payload_indicator 315; too_short 305; control_chars 63; prose 9.

Pool concentration (unique payloads): Directory Traversal is 98.3% `Intruder/dotdotpwn.txt` (10,046 of 10,219); XSS is 46% two fuzzdb template lists (`xss_alert.txt` 519 + `xss_alert_identifiable.txt` 515 of 2,238); File Inclusion is 35% `Traversal.txt` (1,174 of 3,321). Full per-file counts are in `summary.json` (`sampling.population_info.*.unique_canonical_by_source_file`).

## 3. Sampling

* Method: stratified by category. Within a category, pool items are ranked by `sha256(seed NUL category NUL canonical_key)` and the first `n_c` are taken. This is deterministic, independent of extraction order, and nested (a larger `n_c` extends the smaller sample).
* Seed: `v5-attack-audit-v1`.
* Allocation: `n_c = min(pool_c, max(floor_tier, min(36, round(300 * pool_c / sum_pool))))`. Proportional allocation alone would give DT, XSS and FI ~84% of the sample and 0-1 items to most other categories (e.g. JWT 80/18,860 x 300 = 1). Floors per V5-plan tier (not yet approved): ML-primary 30, report-only 15, conditional (XXE, GraphQL) 15, out-of-ML (JWT, CSRF, HPP, Request Smuggling, Insecure Deserialization) 10 as a check of known-bad families; the proportional term is capped at 36 to bound annotation effort. Because of the floors the total is **395, not 300**; the floors, not the proportional term, drive the size. A pool smaller than its floor is taken whole (Request Smuggling: 7).
* Directory Traversal and File Inclusion are sampled separately (they are separate PATT directories) even though D49 merges them into one category.
* Pool listing sha256 (`sha256` of the sorted lines `category TAB sha256(canonical_key)`, newline-joined): `1be3b423e20843d515fcbc82474420bc7b5cef4d9040203b1a25e4bfba34cdf3`.
* `sample.jsonl` sha256: `2c7886114433406ae81d2b6625136b861030cfcf0fe32f72496a2d554c53d65d` (395 rows; fields `sample_id, category, payload, canonical_sha256, source_file, pool_rank`).

The allocation table is the last column of the population table above.

## 4. Annotation protocol

Annotator: Claude Sonnet subagent reading each payload and its source file name; no execution, no tooling, no model, no second annotator. The labels are judgements from text alone, made after fixing the class definitions below. Annotation was conservative: when unsure, `UNCERTAIN`.

| Class | Definition |
|---|---|
| VERIFIABLE (V) | A concrete, syntactically recognisable payload of the **assigned** category that would be malicious in a typical injection slot of that category; the mechanism can be pointed at. |
| PROBABLY_CORRECT (P) | Plausibly a payload of that category but needs a specific context or sink (legacy parser, particular engine, decoding step), is a bare command/value, or is a fragment of a larger payload. |
| UNCERTAIN (U) | Cannot tell from text alone whether it is a working payload (e.g. malformed encodings, inert templated mutations). Not necessarily junk. |
| INCORRECT (I) | Not an attack payload (documentation prose, tool output, setup commands, placeholders, markdown/code residue, reference URLs, PoC source code) **or** a real payload of a different category (`better_category` recorded). |

`failure_mode` vocabulary: `prose, tool_output, placeholder, markdown_residue, setup_command, reference_url, wrong_category, truncated, encoding_garbage, other`. It is mandatory for INCORRECT and optionally recorded for P/U when a defect is present (e.g. trailing doc comment on a working payload). `other` for INCORRECT means "source-code line / PoC fragment / benign sample / bare wordlist token", described in `note`.

Conventions worth knowing when reading the numbers:
* Bare commands (`/usr/bin/id`), code-level injections (`exec('sleep 5')`) and bare URLs for open redirect were P, not V.
* Open-redirect and traversal items were V only when the exploit shape is unambiguous (e.g. `../` chains with a target file).
* Hardcoded (project-authored) rows were labelled on the same text-only basis.
* `UNCERTAIN` is **not** counted as INCORRECT; both the "U+I" and "I only" rates are reported.

## 5. Results

Event of interest: "payload is NOT a usable attack payload of its assigned category" = UNCERTAIN + INCORRECT (conservative) and INCORRECT only (strict). Wilson 95% intervals (no finite-population correction, so slightly conservative). **Wilson captures sampling uncertainty only. It does not capture systematic annotator error** (single LLM annotator, possible bias in either direction, no inter-annotator agreement).

| Category | Tier | n | V | P | U | I | UNCERTAIN+INCORRECT: k/n, rate [Wilson 95%] | INCORRECT only: k/n, rate [Wilson 95%] |
|---|---|---:|---:|---:|---:|---:|---|---|
| CRLF Injection | report_only | 15 | 13 | 2 | 0 | 0 | 0/15 = 0% [0, 20] | 0/15 = 0% [0, 20] |
| Command Injection | ml_primary | 30 | 11 | 16 | 0 | 3 | 3/30 = 10% [3, 26] | 3/30 = 10% [3, 26] |
| Cross-Site Request Forgery | out_of_ml | 10 | 0 | 0 | 0 | 10 | 10/10 = 100% [72, 100] | 10/10 = 100% [72, 100] |
| Directory Traversal | ml_primary | 36 | 0 | 9 | 27 | 0 | 27/36 = 75% [59, 86] | 0/36 = 0% [0, 10] |
| File Inclusion | ml_primary | 36 | 17 | 15 | 3 | 1 | 4/36 = 11% [4, 25] | 1/36 = 3% [0, 14] |
| GraphQL Injection | conditional | 15 | 1 | 3 | 0 | 11 | 11/15 = 73% [48, 89] | 11/15 = 73% [48, 89] |
| HTTP Parameter Pollution | out_of_ml | 10 | 0 | 7 | 3 | 0 | 3/10 = 30% [11, 60] | 0/10 = 0% [0, 28] |
| Insecure Deserialization | out_of_ml | 10 | 2 | 3 | 0 | 5 | 5/10 = 50% [24, 76] | 5/10 = 50% [24, 76] |
| JSON Web Token | out_of_ml | 10 | 0 | 1 | 1 | 8 | 9/10 = 90% [60, 98] | 8/10 = 80% [49, 94] |
| LDAP Injection | report_only | 15 | 2 | 0 | 0 | 13 | 13/15 = 87% [62, 96] | 13/15 = 87% [62, 96] |
| NoSQL Injection | report_only | 15 | 10 | 0 | 0 | 5 | 5/15 = 33% [15, 58] | 5/15 = 33% [15, 58] |
| Open Redirect | ml_primary | 30 | 2 | 25 | 0 | 3 | 3/30 = 10% [3, 26] | 3/30 = 10% [3, 26] |
| Request Smuggling | out_of_ml | 7 | 1 | 5 | 0 | 1 | 1/7 = 14% [3, 51] | 1/7 = 14% [3, 51] |
| SQL Injection | ml_primary | 30 | 19 | 3 | 4 | 4 | 8/30 = 27% [14, 44] | 4/30 = 13% [5, 30] |
| Server Side Request Forgery | ml_primary | 30 | 14 | 3 | 0 | 13 | 13/30 = 43% [27, 61] | 13/30 = 43% [27, 61] |
| Server Side Template Injection | ml_primary | 30 | 16 | 8 | 0 | 6 | 6/30 = 20% [10, 37] | 6/30 = 20% [10, 37] |
| XPath Injection | report_only | 15 | 12 | 1 | 1 | 1 | 2/15 = 13% [4, 38] | 1/15 = 7% [1, 30] |
| XSS Injection | ml_primary | 36 | 4 | 10 | 15 | 7 | 22/36 = 61% [45, 75] | 7/36 = 19% [10, 35] |
| XXE Injection | conditional | 15 | 0 | 5 | 2 | 8 | 10/15 = 67% [42, 85] | 8/15 = 53% [30, 75] |
| **All strata pooled (unweighted)** | | 395 | 124 | 116 | 56 | 99 | 155/395 = 39% [35, 44] | 99/395 = 25% [21, 30] |

"All strata pooled" is an unweighted pool over a stratified sample with arbitrary stratum sizes; it is **not** a population estimate. Pool-weighted over the eight ML-primary categories (18,322 unique payloads) the point estimates are U+I about 54% and I-only about 5%, dominated by Directory Traversal (56% of that pool, 75% U). Unweighted over the ML-primary sample (n=258): U+I 33%, I-only 14%; excluding Directory Traversal (n=222): U+I 27%, I-only 17%.

Failure modes over the whole sample (class : mode):

| Class : failure mode | Count |
|---|---:|
| UNCERTAIN:encoding_garbage | 40 |
| INCORRECT:other | 38 |
| INCORRECT:truncated | 20 |
| UNCERTAIN:other | 15 |
| INCORRECT:markdown_residue | 12 |
| INCORRECT:tool_output | 9 |
| INCORRECT:wrong_category | 8 |
| PROBABLY_CORRECT:markdown_residue | 6 |
| INCORRECT:placeholder | 5 |
| INCORRECT:setup_command | 4 |
| INCORRECT:prose | 3 |
| PROBABLY_CORRECT:other | 1 |
| UNCERTAIN:truncated | 1 |

Provenance contrast (pooled strata, same caveat): payloads from scraped markdown (`.md`, n=162) were INCORRECT in 85 cases (52%, Wilson [45, 60]%) but only 1 UNCERTAIN; payloads from wordlist `.txt` files (n=187) were INCORRECT in 13 (7%, [4, 12]%) but UNCERTAIN in 51 (27%); project-authored hardcoded rows (n=46) INCORRECT 1, UNCERTAIN 4. Within ML-primary: markdown I-only 32/93 (34%), wordlist I-only 5/165 (3%).

## 6. Problematic families

Counts are from the annotated sample (small n per family; read as indications, not rates).

1. **Scraped markdown code blocks split line by line (documentation/script residue).** Every category with a README-heavy source: CSRF 10/10 INCORRECT (HTML/JS PoC fragments; CSRF is not a request-borne string), LDAP README 12/12 (blind-injection filters with ` : OK`/` : KO` annotations, exploit-script lines), GraphQL README 11/15 (single lines of multi-line introspection queries, `query {`, `possibleTypes {`, error messages), JWT README 8/10 (menu text like "Please select a field number", JWK fragments, `"kid": ...` lines, sample claims), NoSQL README 5/10 (Ruby/Python script lines), SSRF `SSRF-Advanced-Exploitation.md` 6/7 (Python DNS-packet script lines, Redis/PHP code), SSRF README/Cloud-Instances (URL followed by a doc label such as `Dotless decimal`, `curl` command lines).
2. **Provenance-based prose/tool output the filter does not catch.** Shell-prompt lines (`swissky@crashlab:~$ ...`), database error messages, `Name:` nslookup output, Jackson exception text. `PROSE_RE` rejected only 9 lines in the entire extraction, while 3 prose sentences in this sample passed it.
3. **Placeholders that slip past `PLACEHOLDER_RE`/`PLACEHOLDER_LITERALS`.** `{payload}`, `?return_to={payload}`, `%(payload)s`, `BURP-COLLABORATOR-SUBDOMAIN` (the filter only knows UPPERCASE in single braces and a literal list). 5 INCORRECT in the sample; 21 of 242 Open Redirect pool entries match the lowercase-brace rule.
4. **Machine-generated mutation lists.** `dotdotpwn.txt` is 98% of the Directory Traversal pool; 27 of the 36 sampled DT items are UNCERTAIN, almost all `encoding_garbage` (literal `0x2e`/`0x5c` text, invalid escapes such as `%c1%pc`, `%c0%qf`, `%bg%qf`, `%c1%8s`, `??`/`.?` runs, `%%32%%65`). Zero DT items were INCORRECT or VERIFIABLE; the 9 P items are standard overlong-UTF-8 / `%uff0e` traversals. fuzzdb `xss_alert.txt` (519 pool entries) is similar: templated `<TAG onEVENT TAG onEVENT="javascript:javascript:alert(1)">` with duplicated attributes and literal `\xNN` text (11 of 13 sampled UNCERTAIN). Literal `\xNN` text affects 496 XSS pool entries.
5. **Typographic corruption in fuzzdb SQLi auth-bypass lists.** en-dash/prime characters in place of `--`/`'` (A0242, A0262); fused `SELECTCHAR(` tokens in sqlmap-style union lists (A0260, A0268).
6. **Wrong-category contamination of Intruder lists.** XXE lists contain XSS (4), SQLi (1) vectors (5 of 15 sampled XXE items); LDAP fuzz contains an XPath payload; the Command Injection list contains a `{{ }}` template expression; the hardcoded XPath list contains an SQL stacked query. 9 `wrong_category` in total.
7. **Truncated fragments.** 20 INCORRECT `truncated`: bare `<?php`, `<script>`, `&foo;`, `directives {`, JWK/JSON field lines. Many XXE `<!DOCTYPE ...>` declarations without a referencing entity were labelled P rather than V for the same reason.
8. **Trailing documentation comments on otherwise working payloads (SSTI).** `// Error-Based RCE`, `# Rendered RCE`, `# Burp Payload -> ...` (6 P with `markdown_residue`; 27 SSTI pool entries match the rule). These should be stripped, not dropped.
9. **Hardcoded categories are clean but tiny and template-like.** CRLF 13V/2P of 15, XPath 12V of 15, Request Smuggling and HPP 6-10 unique entries; they are project-authored, so their "correctness" shares the generator's assumptions.

### Do the existing `quality_filter` rules catch these?

Everything in the sample already passed `quality_filter`, so by construction the remaining failures are what it misses. Mapping the sample failure modes to the intended rule: prose (3 slipped; `PROSE_RE` requires a capitalised sentence of >= 6 plain words and no attack characters), placeholder (5 slipped; case and literal-list limitations), markdown residue (12 INCORRECT plus 6 working-but-residue P: `MARKDOWN_START` only tests the line prefix, trailing ` : OK`, doc labels and comments are not detected), reference URL (0 observed in the sample; the rule works on its hosts), setup commands (4, no rule), tool output (9, no rule), truncated (20, no rule), source-code lines and PoC fragments (about 38 `other`, no rule), wrong category (9, cannot be a structural filter), `encoding_garbage` (40 U, no rule). The existing rules do remove the large mass of the pre-filter noise (6,000+ lines: fuzzer placeholders 3,614, markdown artifacts 644, empty, too long/short), so the audit measures the residual.

## 7. Recommendations for the V5 generator

All proposals are **negative / structural** (junk detectors), not positive attack-keyword signatures, to avoid recreating CSIC-style circular labels (audit F6). They are proposals evaluated on the same sample they were designed from, so every number below is in-sample and optimistic.

**R1. Add 15 negative structural rules** (implemented as `structural_flags` in `scripts/dataset/audit_v5_attack_pool.py`, run with the `filters` subcommand): `malformed_percent` (URL-encoded categories: `%` not followed by a valid `%XX`/`%uXXXX` escape), `literal_0x_escape` and `qmark_runs` (path categories), `literal_backslash_x` (XSS), `placeholder_token` (lowercase `{word}`, `%(word)s`, `COLLABORATOR`), `doc_annotation` (` : OK/KO`), `url_plus_label`, `trailing_doc_comment`, `tool_output_marker` (shell prompt, `[+]`, `ERROR`, `Traceback`, `Name:`), `source_code_line`, `dangling_opener` (ends in `{ ( [ ,` with no closer), `bare_word`, `bare_html_tag`, `tool_invocation` (sqlmap/ysoserial/iconv/python..., and curl/wget/cat outside Command Injection), `prose_sentence`. In-sample result: they flag 93 of 395 sample items and catch 87 of the 155 UNCERTAIN/INCORRECT items (about 56%) while flagging 6 VERIFIABLE/PROBABLY_CORRECT items (the SSTI items with trailing doc comments and one shell loop). `trailing_doc_comment` should strip the comment rather than reject the row. Rules that depend on category (path, URL-encoded, XSS) must stay scoped to those categories; `%` is legitimate in SQL `LIKE` and `<%= %>` templates.

**R2. Cap provenance families.** The pool is dominated by single machine-generated lists. Cap the share of any one source file per category (suggested <= 25%) and, within `dotdotpwn.txt` and the `xss_alert*.txt` template lists, cap by logical skeleton, or quarantine them as "unverified mutations" outside the ML-primary training set. Without this, DT "diversity" is 10k permutations of a handful of ideas.

**R3. Source-level review instead of line-level trust for markdown.** Treat every `.md` source file as scraped documentation: markdown-sourced rows are INCORRECT ~52% of the time in this sample. Either (a) curate by whitelisting reviewed fenced blocks per file, or (b) exclude markdown sources for categories whose pool is mostly docs. The file-level decision is by provenance review, not by payload signature.

**R4. Category dispositions** (based on this sample; Wilson ranges in section 5):
* Exclude from ML and from any automatic extraction: **CSRF** (10/10 INCORRECT; not a payload), **JWT** (9/10 U+I; hand-written token set only, if at all), **Insecure Deserialization** (5/10 INCORRECT; 12 pool entries), **HPP** and **Request Smuggling** (hardcoded structural descriptions only).
* Manual curation required before use: **LDAP** (13/15 INCORRECT; only about 20 Intruder-list entries plausibly usable), **GraphQL** (11/15 INCORRECT; line-splitting destroys queries; use block-level extraction or hand-written queries), **XXE** (8/15 INCORRECT, 5 wrong-category; block-level only and review each entry), **NoSQL** (5/15 INCORRECT, all README code lines; the `Intruder/` lists and operator syntax lines are good), **SSRF** (13/30 INCORRECT; drop or hand-curate `SSRF-Advanced-Exploitation.md`, strip doc labels from `SSRF-Cloud-Instances.md`).
* Usable after R1-R3: **SQLi** (I 13%, U 13%; fuzzdb typographic corruption and fused tokens), **SSTI** (I 20%; strip comments), **Command Injection**, **Open Redirect** (placeholders), **File Inclusion** (the best category: 17V/15P of 36).
* Usable only after R2 and a better encoding-validity rule: **Directory Traversal** (0 INCORRECT but 75% UNCERTAIN) and **XSS** (19% I, 42% U).
* Report-only hardcoded sets (CRLF, XPath) are clean but small and share the generator's assumptions.

**R5. Gate ML-primary status per category by a measured acceptance threshold.** Suggested rule: a category enters ML-primary only if, on a fresh annotated sample of >= 50 post-filter survivors (new seed, never used for filter design), the upper Wilson 95% bound of INCORRECT is <= 20% and the UNCERTAIN share is reported and <= 25%, with the annotation redone by a second annotator or a human reviewer on at least a subset. This is not a number derived from the data; it is an example of the type of gate. Under it, with the current pre-filter pools, only File Inclusion (I upper 14%) and Directory Traversal (I upper 10%, but UNCERTAIN 75%) would pass on the INCORRECT criterion; the other ML-primary categories (I upper bounds: CmdI 26%, OR 26%, SQLi 30%, SSTI 37%, XSS 35%, SSRF 61%) need R1-R4 and re-measurement.

*(2026-10-13: superseded by the post-filter gate in V5 DRAFT r3 §7. That gate applies to every ML-trained category, uses Wilson upper bounds I ≤ 20% and U + I ≤ 35% plus a blind human subsample of ≥ 20, and a category that fails is excluded from TRAIN.)*

**R6. Estimated clean pool per category after filters** (method: N_pool - N_flagged, times the share of V+P among sample survivors of the filters, with the Wilson interval of that share scaled by N_after). In-sample, optimistic, based on 4-35 survivors per stratum, ranges are wide; "V only" is shown because P includes bare commands, bare URLs and overlong-encoded variants.

| Category | Pool | Flagged by the 15 structural rules | Bad (U+I) sample items caught / total bad | Bad rate among survivors (sample) | Est. clean pool, V+P [range] | Est. clean pool, V only [range] |
|---|---:|---:|---|---|---|---|
| CRLF Injection | 22 | 0 (0%) | 0/0 | 0/15 | 22 [18, 22] | 19 [14, 21] |
| Command Injection | 453 | 27 (6%) | 2/3 | 1/27 | 410 [348, 423] | 174 [104, 253] |
| Cross-Site Request Forgery | 31 | 7 (23%) | 1/10 | 9/9 | 0 [0, 7] | 0 [0, 7] |
| Directory Traversal | 10219 | 4599 (45%) | 20/27 | 7/16 | 3161 [1865, 4322] | 0 [0, 1088] |
| File Inclusion | 3321 | 219 (7%) | 1/4 | 3/35 | 2836 [2408, 3010] | 1507 [1023, 1999] |
| GraphQL Injection | 74 | 41 (55%) | 10/11 | 1/5 | 26 [12, 32] | 7 [1, 21] |
| HTTP Parameter Pollution | 20 | 0 (0%) | 0/3 | 3/10 | 14 [8, 18] | 0 [0, 6] |
| Insecure Deserialization | 12 | 2 (17%) | 2/5 | 3/8 | 6 [3, 9] | 2 [1, 6] |
| JSON Web Token | 80 | 37 (46%) | 3/9 | 6/7 | 6 [1, 22] | 0 [0, 15] |
| LDAP Injection | 76 | 57 (75%) | 11/13 | 2/4 | 10 [3, 16] | 10 [3, 16] |
| NoSQL Injection | 83 | 21 (25%) | 4/5 | 1/11 | 56 [39, 61] | 56 [39, 61] |
| Open Redirect | 242 | 23 (10%) | 3/3 | 0/27 | 219 [192, 219] | 16 [5, 51] |
| Request Smuggling | 7 | 0 (0%) | 0/1 | 1/7 | 6 [3, 7] | 1 [0, 4] |
| SQL Injection | 1278 | 71 (6%) | 4/8 | 4/26 | 1021 [802, 1133] | 882 [651, 1042] |
| Server Side Request Forgery | 202 | 46 (23%) | 10/13 | 3/20 | 133 [100, 148] | 109 [75, 133] |
| Server Side Template Injection | 369 | 61 (17%) | 2/6 | 4/24 | 257 [198, 287] | 205 [144, 253] |
| XPath Injection | 31 | 0 (0%) | 0/2 | 2/15 | 27 [19, 30] | 25 [17, 29] |
| XSS Injection | 2238 | 747 (33%) | 13/22 | 9/22 | 881 [578, 1144] | 271 [109, 574] |
| XXE Injection | 102 | 1 (1%) | 1/10 | 9/14 | 36 [17, 62] | 0 [0, 22] |

Interpretation: the usable ML-primary payload pool after filtering is on the order of 10^2 to 10^3 per category (CmdI ~410, OR ~220, SSRF ~130, SSTI ~257), not the 10^3-10^4 of the raw pool, and the DT / XSS / FI / SQLi figures are inflated by near-duplicate mutations (logical diversity is much smaller). Estimated V+P for ML-primary categories also ignores near-duplicate collapse beyond `canonical_key`.

## 8. Reproduction

Interpreter: `python3` (3.14) suffices; `parse_dataset_v4` is stdlib-only and importable with `.venv-analyzer/bin/python` as well. Run from the repo root.

```bash
python3 scripts/dataset/audit_v5_attack_pool.py extract            # prints per-category JSON; writes nothing
python3 scripts/dataset/audit_v5_attack_pool.py sample             # writes sample.jsonl and summary.json["sampling"]
# annotations.jsonl was written by hand (LLM annotator); then:
python3 scripts/dataset/audit_v5_attack_pool.py summarize          # summary.json["results"]
python3 scripts/dataset/audit_v5_attack_pool.py filters            # summary.json["filter_evaluation"]
python3 -m unittest tests.test_audit_v5_attack_pool -v             # 19 tests, synthetic data (14 originally; 5 added with the agreement / human-sample subcommands)
```

Recorded outputs:

```
$ python3 scripts/dataset/audit_v5_attack_pool.py extract | tail
  "pool_listing_sha256": "1be3b423e20843d515fcbc82474420bc7b5cef4d9040203b1a25e4bfba34cdf3",
  "totals": {"accepted_rows": 33598, "candidates_pre_filter": 39396, "unique_canonical": 18860}
  (patt_commit e961fef231d8327bae83b563fab50aec2e6b77c0; bounds MIN_LEN 4, MAX_LEN 400)

$ python3 scripts/dataset/audit_v5_attack_pool.py sample
wrote 395 rows to .../reports/v5/freeze-prep/E_attack_pool_audit/sample.jsonl
n_total 395; pool_listing_sha256 1be3b423e20843d515fcbc82474420bc7b5cef4d9040203b1a25e4bfba34cdf3
(sample.jsonl sha256 2c7886114433406ae81d2b6625136b861030cfcf0fe32f72496a2d554c53d65d; re-running gives an identical file)

$ python3 -m unittest tests.test_audit_v5_attack_pool -v
Ran 14 tests ... OK   (also OK with .venv-analyzer/bin/python)  [at first writing; now 19, see line 197]
```

`extract` and `sample` re-check that PATT HEAD equals the pinned commit and that the working tree is clean, and `filters` additionally re-checks that the pool listing sha256 equals the one recorded at sampling time.

## 9. Limitations

* **Single LLM annotator; no second annotator; no ground truth.** Systematic bias (e.g. conservatism on encoded variants, treating bare commands as P, treating README snippets as INCORRECT) is not captured by the intervals. Labels are text-only judgements, no execution against any target.
* The P/V boundary is a convention (context-dependence); results that depend on it (V-only clean-pool estimates) are the least reliable. U+I and I-only rates are more robust than V-vs-P splits.
* Per-category samples are small (7-36). Wilson intervals are wide and do not include annotation error. Family-level counts (section 6) are tiny.
* Stratum sizes are chosen by floor/cap, so the pooled overall rate is not a population estimate; the pool-weighted ML-primary figures use point estimates per stratum without intervals.
* Filters and clean-pool estimates were designed after seeing this sample (in-sample, optimistic). They need a fresh sample with a different seed before being used as acceptance evidence.
* The population is the extraction output only, before the later V4 pipeline steps (dedup across sources, caps, rendering). The audit says nothing about the benign side, the HTTP rendering, or model behaviour.
* Hardcoded categories are project-authored and were audited on the same text-only basis; their "correctness" does not validate the generator that consumes them.
* Standards (OWASP etc.) were not used as labelling authority; this is an alignment-style review, not compliance evidence.

## 10. Coordinator partial second annotation (added 2026-10-11)

The coordinator (main agent, Claude Opus 5.5) drew a 40-item subsample and labelled it **blind to `annotations.jsonl`**, then compared the two label sets. The draw was deterministic: sort `sample.jsonl` by `sha256("coord-check-v1" NUL sample_id)` and take the first 40. The same class definitions (§4) were used. Labels are in `coordinator_second_annotation.jsonl`.

| Event compared | Agreement | Cohen's κ |
|---|---|---|
| Exact class (4 classes) | 29/40 | — |
| Usable (VERIFIABLE or PROBABLY_CORRECT) vs not (UNCERTAIN or INCORRECT) | 36/40 | 0.75 |
| INCORRECT vs not | 40/40 | 1.00 |

All disagreements are grade differences:
- VERIFIABLE vs PROBABLY_CORRECT (7);
- strictness on literal `\xNN` escape text and fuzz templates (3);
- one entity-reference fragment (1).

No item that one annotator called INCORRECT was called usable by the other.

**Limitations.**
- Both annotators are LLMs (different models), so a shared bias is not excluded.
- n = 40 is a partial check, not a full second annotation.
- The coordinator saw the category, as the first annotator did.

The result supports using the INCORRECT class for filter design. It does **not** replace the fresh post-filter sample with a second annotator that §7 recommends before an ML-primary category is accepted.

## 11. Second annotation (different model), adjudication and human-review sample (added 2026-10-12, D58)

- **Second annotator.** A Claude **Opus** subagent annotated all 395 rows, blind to the first-annotator labels (`annotations_second.jsonl`).
  - Disclosed slip: its section-range command also printed §10 above. §10 holds only aggregate agreement figures from the coordinator's 40-item check and the kinds of disagreement found; it has no per-row labels.
- **Agreement, Sonnet vs Opus** (`python3 scripts/dataset/audit_v5_attack_pool.py agreement`):

  | Event | Agreement | Cohen's κ |
  |---|---|---|
  | Exact class | 315/395 | — |
  | Usable vs not | 369/395 | **0.863** |
  | INCORRECT vs not | 378/395 | **0.881** |

- **Adjudication** (coordinator, Claude Opus 5.5) produces `adjudicated.jsonl`:
  - 315 rows where both annotators agree;
  - 43 VERIFIABLE/PROBABLY_CORRECT splits, resolved to the conservative PROBABLY_CORRECT;
  - 37 explicit overrides in `adjudication_overrides.jsonl`. These are every disagreement that changes usability or the INCORRECT status.

  Rule: a payload is judged **as extracted**. Of the 37 overrides, 9 are marked `recoverable`: a real payload is present but wrapped in residue (trailing doc label, shell prompt, `curl` prefix, placeholder, `var_dump` wrapper). This supports **strip** filters rather than drop filters. 5 of the 13 INCORRECT SSRF items are recoverable.
- **Adjudicated results** (`summary.json` → `second_annotation.adjudicated_results`): INCORRECT counts per category are within ±1 of the first annotation.
- **What this is not.** Agreement between two LLMs is **not** human validation, and the Wilson intervals still cover sampling uncertainty only.
- **Human review.** A stratified, label-blind subsample of 95 rows over the V5-trained categories is prepared in `human_review/` (instructions in `human_review/README.md`). **It has not been reviewed yet.**
