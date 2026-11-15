# B — Benign-traffic sources for V5: deeper audit (research notes v2)

Date: 2026-10-06. **RECOMMENDATIONS ONLY, not decisions.** It continues
`reports/v5/research-notes-v1/README.md` §A and `reports/hybrid/phase2a-analyzer-design/` and
does not repeat them. The gaps it targets are those of `benign-coverage-audit-v1` §3/§8 (F1–F7).

**What was accessed.** Nothing in the repo was changed except this file. No dataset was
integrated, no model was run.
- **open-appsec.** Repo files and code through the GitHub API. The `legitimate.zip` **central
  directory only**, read with HTTP range requests (≈ 140 KB of the 1.20 GB archive). No member was
  downloaded.
- **ModSec-Learn derivative.** One 1.9 MB third-party file (`pralab/modsec-learn`,
  `data/dataset/legitimate_test.json`, MIT repo, 5,000 strings derived from open-appsec). It was
  processed in the session scratchpad, and **only aggregate counts were kept**: no value is quoted
  here. The file was then deleted.
- **Specs.** Full spec files of GitHub and Stripe; a seeded random sample of 300 APIs.guru specs
  (seed 20261006); a tree-only (blob-less) clone of `Azure/azure-rest-api-specs` to count example
  files. All of it lives in the scratchpad, not in the repo.

Labels: **FACT** = measured or read in a primary source in this session.
**INFERENCE** = my reasoning from facts. **UNVERIFIED** = not confirmed.

## Verdicts

| # | Source | Status | One-line reason |
|---|---|---|---|
| 1 | open-appsec WCP Legitimate | **EVAL-ONLY** (was "STRONG, conditional" in v1) | The only large, independent, real-browser benign set → most valuable as the **External v2 benign side**. It is a public, vendor-scored FPR benchmark, it contains credentials/PII, and much of it is third-party telemetry |
| 2a | GitHub `rest-api-description` | **STRONG** (structure + examples) | MIT. 350 body operations, **all** with request examples, nested JSON with 1–11 keys and depth ≤ 7 |
| 2b | Stripe `openapi` | **STRONG** (structure only) | MIT. 626 body operations, 611 form-urlencoded with bracket nesting. **0 examples**, so values must come from elsewhere |
| 2c | Azure `azure-rest-api-specs` examples | **POSSIBLE** | MIT. 329,436 example files, but placeholder-valued and a single provider style (ARM) |
| 2d | APIs.guru openapi-directory | **POSSIBLE, per spec** | CC0 only for contributed specs. 65% of APIs declare no licence. AWS/Google carry no body examples; ≈ 48% of APIs are Azure/Google/AWS |
| 2e | octokit/webhooks payload examples | **POSSIBLE** | MIT, 513 example files of real-shaped inbound webhook JSON. The repo is deprecated |
| 3a | Natural Questions | **POSSIBLE** (F2 values) | Real anonymised Google queries, CC BY-SA 3.0 (share-alike). Lowercase, punctuation-poor |
| 3b | Wikidata person/org labels | **POSSIBLE** (F1 values) | CC0. Real apostrophe, hyphen and non-ASCII names |
| 3c | NIST SP 800-63B §3.1.1.2 | **USE as a rule**, not data | Justifies symbol- and space-rich benign passwords |
| 3d | HTTP Archive | **EVAL-ONLY / UNVERIFIED** | Crawler page loads without interaction; data licence not found |
| 3e | ModSec-Learn dataset (open-appsec derivative) | **REJECT** | No licence on the dataset repo; contaminates #1 as an evaluation set |

---

## 1. open-appsec WAF Comparison Project — Legitimate Requests

### 1.1 Provenance and collection (primary sources)

| Claim | Status | Source |
|---|---|---|
| Recorded "by browsing to real-world websites and conducting various operations in the site (for example, sign-up, selecting products …)" | FACT (vendor statement) | repo README §Methodology, <https://github.com/openappsec/waf-comparison-project> (commit history 2023-07 → 2026-02) |
| v1 (blog of 2023-07-13): **973,964 requests, 185 sites, 12 categories** | FACT | <https://openappsec.io/post/best-waf-solutions-in-2023-real-world-comparison>; it equals the sum of `Legitimate Data Set categories.csv` in the repo (185 rows, 973,964), computed here |
| v2 (blog of 2024-12-01, tests Oct–Nov 2024): **1,040,242 requests, "692 real websites", 14 categories** | FACT (vendor statement) | <https://www.openappsec.io/post/best-waf-solutions-in-2024-2025-real-world-comparison>; <https://docs.openappsec.io/references/waf-comparison-project> |
| The 2026 edition (tests Dec 2025) reuses the same 1,040,242 / 692 numbers | FACT | <https://openappsec.io/post/best-waf-solutions-in-2026-real-world-comparison> |
| The GitHub README mixes v2's count with v1's "185 sites / 12 categories" | FACT (internal inconsistency of the README) | README §Legitimate Data Set |
| Who browsed, which browser/proxy recorded, and when | **UNVERIFIED — not documented anywhere** | none of the four pages above |
| Recording period of v1 ≈ **August 2022** | INFERENCE: epoch timestamps in the derived sample cluster at 1660… s/ms (= 2022-08-11 … 08-14 UTC); 24.9% of strings carry a 2022 ms epoch | §1.4 |
| v2 file names `browsing_2024_<site>_<xx>`, with `xx` ∈ {hl, ni, al, mu, az, …} | FACT (ZIP directory). That `xx` identifies the recording operator is **UNVERIFIED** | §1.3 |
| Maintainer: the traffic "is based on real-world traffic"; odd values will be "manually change[d]" next update | FACT — so the files are curated, not raw captures | issue #3, <https://github.com/openappsec/waf-comparison-project/issues/3> |
| Author is the open-appsec / Check Point vendor, whose product is benchmarked on the same data | FACT (conflict of interest) | 2026 blog; `report/templates/images/check_point.svg` |

### 1.2 Licence

- FACT: "The Legitimate Requests Dataset and the Tooling are available under Apache 2.0
  license." (README §License). The GitHub repo licence is Apache-2.0. The archive itself is
  hosted outside GitHub (`downloads.openappsec.io`, S3, `Last-Modified` 2024-12-01).
- So the data is explicitly covered, not only the code.
- **UNVERIFIED / legal review needed**:
  - whether a vendor can licence recorded requests that contain third-party sites' content and
    identifiers;
  - EU database rights;
  - personal data inside the files (§1.5): a licence does not create a GDPR legal basis.

### 1.3 Structure (code + ZIP central directory; no member read)

- **Record schema** (FACT, `wafs.py:_send_payloads`, `helper.py`): each member is one JSON
  **array** of objects with keys `method`, `url`, `headers` (dict), `data` (string body).
  - `url` is **relative** (it is appended to the WAF URL).
  - the original `Host` header is **removed** before replay (`send_request`).
  - The original target host survives only in `headers`.
- **No per-request metadata** (FACT): no timestamp, site, label provenance or response. The
  category comes from `assets/file_category_mapping.json` (695 file → category entries).
- **ZIP** (FACT, measured):
  - 692 members, all `Legitimate/<name>.json`;
  - 1,203,983,791 bytes compressed, **7.317 GB** uncompressed;
  - member mtimes 2024-10-15 / 2024-10-22 (repack date, not recording date);
  - **183** members are v1 recordings (in the CSV) and **509** are `browsing_2024_*`.
- **Size skew** (FACT): median member 4.9 MB. Six members hold **2.63 GB (36%)** — pcloud
  734 MB, onedrive 566, tiktok 539, box 501, drive 232, forever21 59. These are file-upload
  bodies.
- **"692 websites" ≠ 692 sites** (INFERENCE from file names, heuristic normalisation):
  - ≈ 566 distinct site stems;
  - 67 sites recorded in both 2022 and 2024;
  - 51 sites with several 2024 files (different `xx`).
- **Repeats** (FACT): 184 of 185 v1 per-file counts are multiples of 5. That *may* indicate
  replication or sampling in blocks of 5 (**UNVERIFIED**).
- **Benign label** (FACT): it is "legitimate" by construction (who generated it), not by
  adjudication. A WAF "false positive" in the tool is `status == 403` or a block-page string
  (`helper.py:send_request`).

### 1.4 Content measured on a derived sample (aggregate only)

ModSec-Learn's `legitimate_test.json` holds 5,000 strings that its authors derived from the open-appsec legitimate set. They are query strings and form bodies; the extraction script is not published (**UNVERIFIED** which fields were taken). This is **not** a sample of whole requests: no path, no headers, and **0/5,000 JSON bodies**. It says nothing about JSON in open-appsec. Proportions with Wilson 95% CI:

| Marker | Share |
|---|---|
| exact duplicates | 793 / 5,000 (15.9%) |
| ≥ 2 analytics-beacon keys (`tid`, `cid`, `gtm`, `_v`, `fst`, `guid`, …) | 27.2% [26.0, 28.5] |
| URL inside a value | 34.4% [33.1, 35.7] |
| UUID | 11.7% |
| decoded non-ASCII / Hebrew | 12.1% / 10.0% |
| `\|` / `[` `]` / `;` / `!` / `#` / `'` | 9.4% / 8.4% / 5.7% / 2.9% / 1.8% / 1.8% |
| Google-API-key-shaped string | 2.7% [2.3, 3.2] |
| e-mail-shaped / JWT-shaped | 0.3% / 0.3% |
| string > 1,000 chars | 9.1% |

**INFERENCE.**
1. Unlike V4-clean benign, the set carries the punctuation and encoding the audit found ABSENT
   (`|`, `[`, `]`, `;`, `#`, `'`). That is real F1/F5/F6 value.
2. A large share is **third-party telemetry** (ads/analytics beacons), not first-party
   application traffic. That inflates "benign" with a family the classifier will rarely judge
   behind an app's own gateway.
3. **Credential-shaped secrets and e-mail addresses are present.** Session UUIDs and analytics
   client ids are persistent pseudonymous identifiers.
4. The content is skewed to Israeli sites (Hebrew), consistent with site names such as shufersal,
   israir and rami_levy.

### 1.5 PII / anonymisation

- **No anonymisation is documented** in the README, the docs or the three blogs (FACT: absent).
- Present or likely:
  - **present** (§1.4, measured): e-mail-shaped strings, JWT-shaped tokens, browser API keys,
    persistent tracking ids;
  - **expected but UNVERIFIED**: `Cookie` / `Authorization` headers with live session tokens of
    the recording accounts, and sign-up/login flows ("log_up", "log_in" in 15+ file names) with
    whatever name, e-mail, phone, address and password the operator typed.
- Whether the operators used throwaway identities is UNVERIFIED.

### 1.6 Academic use and the "independent evaluation" problem

- **FACT: peer-reviewed precedent for training on it.** ModSec-Learn (Scano, Floris, Montaruli,
  Demetrio et al., *ModSec-Learn: Boosting ModSecurity with Machine Learning*, LNNS 2025,
  doi:10.1007/978-3-031-76459-2_3) took 25,000 legitimate samples from open-appsec. ModSec-AdvLearn
  (Floris et al., IEEE TIFS 2025, doi:10.1109/TIFS.2025.3583234; arXiv 2308.04964v4 §V) reuses
  them.
  - Their split (`pralab/modsec-learn/scripts/build_dataset.py`) is a **random 80/20 row split**
    (`random_state=77`), with no grouping by site or file.
  - **INFERENCE:** with the 15.9% exact duplicates above, their train/test overlap is likely
    non-zero.
- **FACT: it is a live public FPR benchmark.** Vendor TNRs are published on it, from 45.6% to
  99.94% (`report/waf_results_2025_2026.json`), and it is "updated annually".
- **INFERENCE:** training V5 on any part of it makes every later comparison on it non-independent
  (D-rules on independent evaluation). It is also the **only** large real-browser benign corpus
  with a permissive licence. Its highest value for this project is as the **benign side of
  External v2**.

### 1.7 Recommendation

**EVAL-ONLY.** Reserve it as an External v2 benign candidate, frozen before any V5 generator
work, under the External v1 freezing discipline.

If the owner nevertheless wants a training share, it must be a **site-disjoint** partition fixed
once: group key = normalised site, never file or row, with the 2022 and 2024 recordings of a site
kept together. It must never also be used for evaluation.

**Blockers before any use (eval included):**
1. a privacy pass (§5) with documented before/after counts;
2. a filter declaration:
   - first-party vs third-party by original `Host` vs the site's eTLD+1;
   - static assets;
   - upload bodies > N MB;
3. de-duplication by request hash;
4. an explicit note that the labels are by construction and the author is a benchmarked vendor;
5. a licence/legal read on the personal data in it.

---

## 2. API specifications (structure and examples)

### 2.1 Licence per source (FACT unless marked)

| Source | Spec licence | Examples' licence | Pinned commit (2026-10-06) |
|---|---|---|---|
| github/rest-api-description | MIT (`LICENSE.md`, © 2020 GitHub) | examples are inline in the same MIT file (`components/examples`) | `734bc9c1` |
| stripe/openapi | MIT (© 2011– Stripe) | spec has none; `openapi/fixtures3.json` (181 **response** resources, placeholder values) in the same MIT repo | `0082e0c9` |
| Azure/azure-rest-api-specs | MIT | `examples/*.json` (x-ms-examples) in the same MIT repo | `497a43f4` |
| APIs.guru openapi-directory | repo CC0-1.0, but README: "All API definitions contributed to project by authors are covered by the CC0 1.0 … All API definitions acquired from public sources under the Fair use principle" | inherits each origin's terms. Fair use is a US defence, not a licence → **per-spec check required** | `pushed_at` 2026-04-20 |
| octokit/webhooks | MIT (repo flagged DEPRECATED) | 513 `payload-examples` files | — |

**APIs.guru per-spec `info.license`** (FACT, `api.apis.guru/v2/list.json`, 2,529 APIs / 3,992
specs / 677 providers):

| Declared licence | APIs | Provider |
|---|---:|---|
| none | 1,643 (65%) | incl. 651 Azure, 181 apisetu.gov.in |
| CC BY 3.0 | 285 | 281 Google |
| Apache 2.0 | 271 + 109 | AWS; Twilio |
| MIT | 62 | various |

APIs.guru's own metrics report 688 invalid specs, 166 unreachable and "fixedPct 23". So its specs
are **modified copies**, and for redistribution the upstream (e.g. Azure's MIT repo) is the
cleaner source.

### 2.2 Example coverage (measured)

| Measure | GitHub | Stripe |
|---|---:|---:|
| operations | 1,232 | 644 |
| operations with a request body | 350 | 626 |
| … with a media-type example | **350 (100%)** | **0** |
| named request examples | 428 (533 in `components.examples`) | 0 |
| body content types | 348 `application/json` | 611 `x-www-form-urlencoded`, 14 JSON, 1 multipart |
| query params with an example | 28 / 1,101 | 0 / 1,020 |

**GitHub request-example values** (FACT):
- 1,480 leaves; 1,171 strings, of which **563 unique**;
- top-level keys 1–11; leaf depth up to 7;
- 192 int, 96 bool and 19 null leaves;
- 74 strings contain the placeholder `octocat`;
- punctuation is scarce (`'` 14, `!` 11, `#`/`;`/`&` 0);
- also credential-shaped placeholders (encrypted-secret strings, a PGP block).

**INFERENCE.** GitHub fills F4's structure (multi-key, nested, typed JSON, both classes absent in
TRAIN) but **not** F1's punctuation. Its value pool is tiny and placeholder-heavy, so `octocat` is
a reverse-shortcut risk of exactly the `the`/`please` kind.

**Stripe** (INFERENCE from FACT): its form bodies use bracket nesting (`a[b][c]=…`), so they
directly cover the audit's ABSENT benign `[`/`]` (0 benign vs 343/335 attack groups) and
multi-field forms (F3). The values must all come from corpora.

**Azure** (FACT): 329,436 example JSON files over 317 service directories (133,648 under
`stable/`), ≈ 104 k after collapsing api-versions (heuristic). They give request `parameters`
plus bodies, with placeholder values (`rg1`, `subid`, …).

**APIs.guru sample** (FACT; 298/300 specs fetched; Wilson 95%):

| Measure | Share |
|---|---|
| specs with ≥ 1 body operation | 74.8% [69.6, 79.4] |
| specs with ≥ 1 media-type/parameter-level body example | **22.8%** [18.4, 27.9] |
| specs with any example anywhere in the body schema | 41.3% [35.8, 46.9] |

By provider:
- AWS (36 specs) and Google (34): **0** examples;
- Azure (73): 54 with examples (inlined x-ms-examples), covering 239 of 245 body operations;
- others (155): 69 with any example.

Over all sampled specs, 1,490 of 4,028 body operations (37%) have some example.

---

## 3. Other benign sources (only those that add benign data)

| Source | Provenance (verified) | What it adds | Limits |
|---|---|---|---|
| **Natural Questions** — Kwiatkowski et al., TACL 2019, doi:10.1162/tacl_a_00276 | "real anonymized, aggregated queries issued to the Google search engine" (abstract). Licence CC BY-SA 3.0 (HF card `license:cc-by-sa-3.0`) | F2: real query text with function words and SQL homonyms | Share-alike on derived data (owner/legal decision). Lowercase, no `?` or punctuation, so no F1 |
| **Wikidata labels** | "All structured data … is released into the public domain under Creative Commons Zero" (<https://www.wikidata.org/wiki/Wikidata:Licensing>) | F1: real names with apostrophes, hyphens, non-ASCII, `&` in organisation names | Real persons' names: recombine first/last, never pair them with other attributes |
| **NIST SP 800-63B** (rev. 4, 2025-08-26) §3.1.1.2 | "Verifiers and CSPs SHOULD accept all printing ASCII … characters and the space character in passwords" | Normative ground for benign passwords containing `'` `;` `#` `!` spaces | A rule for a generator, not data. Never use breached-password corpora |
| **Web Fuzzing Dataset / EMB apps** (Sahin, Zhang & Arcuri, arXiv 2509.01612; v1 notes) | official repos | targets for capturing benign traffic driven by **realistic clients** | fuzzer traffic itself is not benign (§4) |
| **HTTP Archive** (<https://httparchive.org/faq>) | WebPageTest/Chrome page loads of CrUX URLs, no interaction | real URL/query shapes (F5/F6), evaluation only | data licence **UNVERIFIED**; GET-heavy, third-party-heavy |
| **ModSec-Learn dataset** (`pralab/modsec-learn-dataset`) | derivative of #1; GitHub licence field `null` | — | **REJECT**: no licence; overlaps #1 |

Kaggle sources: none were found with verifiable origin that adds benign HTTP (the v1 rejections
stand).

---

## 4. Methodology: realistic benign traffic from OpenAPI without endpoint shortcuts

### 4.1 What the literature says about generated values

- **RESTler** (Atlidakis, Godefroid & Polishchuk, ICSE 2019, doi:10.1109/ICSE.2019.00083)
  infers producer-consumer dependencies between request types from the spec plus response
  feedback. It is a *fuzzer*: its goal is bugs, not a natural value distribution.
- **EvoMaster** (Arcuri, ACM TOSEM 2019, doi:10.1145/3293455) is evolutionary white-box
  generation rewarded by coverage and faults, so inputs drift towards boundary and fault-inducing
  values.
- **Schemathesis** (Hatfield-Dodds & Dygalo, ICSE-Companion 2022, doi:10.1145/3510454.3528637)
  does property-based generation from OpenAPI/GraphQL schemas. Its schema-faithful *positive*
  generation is the right primitive for type/format validity; its negative/fuzzing modes are not
  benign.
- **RESTest** (Martin-Lopez, Segura & Ruiz-Cortés, ISSTA 2021 demo, doi:10.1145/3460319.3469082)
  notes that existing tools "mostly rely on random inputs".
  - **ARTE** (Alonso et al., IEEE TSE 2023, doi:10.1109/TSE.2022.3150618) extracts realistic
    inputs from knowledge bases (DBpedia).
  - Results: realistic inputs for **64.9%** of parameters; **57.3%** valid calls vs **20%** for
    random generation.
  - **INFERENCE:** random schema-valid strings are mostly unrealistic, and realism needs external
    value sources.
- **Kim, Xin, Sinha & Orso**, ISSTA 2022, doi:10.1145/3533767.3534401: across 10 tools on 20
  services, a common limitation is the "inability of … generating input values that satisfy
  specific constraints". They also report spec/implementation mismatches.
- **RESTGPT** (Kim, Stennett, Shah, Sinha & Orso, ICSE-NIER 2024, doi:10.1145/3639476.3639769):
  LLM-generated values from descriptions beat rule extraction.
  - **INFERENCE:** LLM-generated values would be a new generator fingerprint; if used, they need
    their own group and attack counterparts.
- **Survey:** Golmohammadi, Zhang & Arcuri, ACM TOSEM 2023, doi:10.1145/3617175 (92 papers).
  **None of these works evaluates distributional realism against real traffic** (INFERENCE from
  their abstracts and evaluation sections read here). Their realism is "valid/meaningful to the
  API", not "looks like production".
- **Shortcut risk:** Arp et al., USENIX Security 2022 (spurious correlations, sampling bias),
  already in v1.

### 4.2 Protocol proposal (for owner review)

1. **Pin and hash every input.** Record the spec commit SHA (§2.1), the corpus versions, the
   generator version and seeds, with a SHA-256 manifest. Per row, store provenance:
   `spec_id`, `operationId`, field path and value-source draw ids.
2. **Schema-paired classes.** Every sampled (operation, content type, field-set) emits benign
   and attack rows in fixed proportion. The attack places its payload in **one** field or leaf
   of the *same* rendered structure, with the same envelope (F7).
   - **Pre-registered shortcut gate:** a probe trained only on (method, path template, parameter
     and key names, content type) must be ≈ chance on grouped validation, e.g. AUC CI covering
     0.5. Otherwise the endpoint mix is a label shortcut.
3. **Grouping and holdout.**
   - Group key = **API/provider**, nested operation, then value-source draw (D16/D54 style).
   - Hold out **whole APIs** for validation and test (leave-provider-out), so evaluation
     measures transfer to unseen schemas, not memorised parameter names.
   - Keep Azure-style mega-providers from dominating: cap operations per provider.
4. **Schema-faithful types.** Respect `type`, `format`, `enum`, `pattern`, min/max and
   required/optional. Choose content types from the spec, which also removes the 661-group
   "form body under JSON type" skew.
   - Validate every benign row against its schema (jsonschema / openapi-core) and drop failures.
   - Fuzzer-style invalid inputs are **out of the benign class**.
5. **Values from real corpora, by semantic slot.** Map parameter semantics (name, description,
   format) to pools:
   - names → Wikidata;
   - free text / search → NQ (share-alike permitting);
   - passwords → NIST 800-63B character policy;
   - URLs → real public URLs (both schemes, never internal targets, F5);
   - numbers / dates → typed distributions.
   - Spec examples are a **low-weight** pool. Their placeholders (`octocat`, `rg1`, `subid`) must
     also appear in attack counterparts, or be removed.
6. **Distributional realism check without training on it.** Compare the audit's marker
   distributions (`extract_markers`) of the generated benign rows against an independent real
   sample (e.g. the frozen open-appsec evaluation partition). Report the distances only.
7. **Validation set.** Run the minimal-pair suite and #57/#60 as read-only diagnostics;
   External v2 for claims.

---

## 5. PII / privacy assessment methodology (captured or third-party traffic)

### 5.1 Scan

Run each detector per field location (request line, each header, cookie pair, query/form key,
JSON leaf) and record counts per detector.

| Class | Locations / patterns |
|---|---|
| **Credentials and secrets** | `Authorization`, `Cookie`, `X-Api-Key`, `X-CSRF-*` headers; keys matching pass/pwd/token/secret/session/auth/key/otp; JWT (`eyJ…\.…\.`); known key formats (cloud keys, Google `AIza…`, OAuth bearer). Tools: gitleaks (MIT), Yelp detect-secrets (Apache-2.0); trufflehog is AGPL-3.0, so licence-check it before using |
| **Direct identifiers** | e-mail, phone, postal address, person names (Microsoft Presidio, MIT, as NER + regex); payment cards (PAN + Luhn), IBAN, national ids |
| **Persistent pseudonymous identifiers** | analytics client ids (`cid`, `_ga`, `_fbp`), UUID session ids, device ids, IP addresses (also inside values) |
| **Quasi-identifiers** | timestamps, geo coordinates, locale + site + time combinations (NIST IR 8053, 2015, doi:10.6028/NIST.IR.8053; NIST SP 800-188, 2023, doi:10.6028/NIST.SP.800-188) |
| **Free text** | search boxes, notes, messages: sample them for manual review |

### 5.2 Strip

- **Drop** whole rows that cannot be cleaned: auth flows with real credentials, uploads with
  personal files.
- **Replace** identifiers with **class-preserving surrogates**: the same length bucket and the
  **same character-class profile**. Otherwise de-identification erases exactly the punctuation and
  encoding markers the audit needs; `!` in passwords is an example.
- Use consistent keyed-HMAC pseudonyms within a request or session, and destroy the key afterwards.
- Re-scan after stripping; the target is 0 hits for the secrets detectors.
- **Pseudonymised data is still personal data** (GDPR Recital 26), so access control and
  retention still apply. NIST SP 800-122 (doi:10.6028/NIST.SP.800-122) gives the
  confidentiality-impact framing.

### 5.3 Document

Write a datasheet (Gebru et al., *Datasheets for Datasets*, CACM 2021, doi:10.1145/3458723)
stating:
- source, licence, collection, consent and operators;
- detector versions and rules;
- per-detector counts before and after (counts only, never values);
- what was dropped vs replaced;
- residual-risk statement;
- legal basis (owner/legal);
- raw-vault location, access and retention.

Every number must be reproducible from a script with a hashed input manifest, as in
`benign-coverage-audit-v1`.

---

## 6. Open items (UNVERIFIED)

- open-appsec:
  - operators, tooling and recording dates;
  - whether test identities were used;
  - real JSON and header content;
  - the cause of the multiples of 5;
  - the true distinct-site count;
  - the legal adequacy of Apache-2.0 for recorded third-party traffic.
- ModSec-Learn's extraction rule.
- HTTP Archive data licence.
- Natural Questions share-alike implications for derived training rows.
- Whether the Census surname files keep apostrophes (not pursued; Wikidata preferred).
