# V5 Data Specification — r3 (FROZEN 2026-10-13, D62)

**Status: FROZEN — specification id `V5-DATA-SPEC-r3`, frozen 2026-10-13 by D62** (owner authorization of 2026-10-13, issue #64). The SHA-256 of this file at freeze is recorded in D62 and in `SHA256SUMS` beside it. The decisions it implements are APPROVED (D56–D61). The freeze makes this text **binding requirements for the future generator, dataset and integration**; it does **not** mean anything is implemented. The generator is not written, and only the independent utilities of §10 exist. The freeze is **scoped**: the values listed in §11.2 stay PROPOSED or PENDING until the step named there. Any change to frozen content needs a new revision (r4) and an owner decision; the frozen text is never edited in place (D39 spirit).

| Revision | Date | Issue | Content |
|---|---|---|---|
| r1 | 2026-10-06 | #62 | evidence-derived draft |
| r2 | 2026-10-11 | #64 | freeze-preparation review |
| r3 | 2026-10-11 | #64 | approved decisions D56–D61 incorporated |

The history is in §12.

## 0. How to read this document

| Tag | Meaning |
|---|---|
| **APPROVED (Dnn)** | Decided by the owner and recorded in `DECISIONS.md`. Binding for V5. Not implemented unless stated |
| **BINDING (Dnn)** | Follows from an earlier approved decision |
| **FROZEN (D62)** | Detail ratified by the owner at the 2026-10-13 freeze: binding, but not implemented |
| **PROPOSED** | Value or detail **not** ratified. It stays open until the step named in §11.2 (pilot, preregistration, stage review or integration) |
| **PENDING** | Value to be measured or chosen at a named later step (pilot build, preregistration). Never invented here |
| **IMPLEMENTED / TESTED** | Exists in the repo / has passing tests. Only the independent utilities in §10 qualify today |
| **Scope of the freeze** | Frozen: §4.6 (identities, deterministic split procedure, E6 reserve, grouping rules, invariants); §5.2–§5.6 (contract, representation, rejects and signals, tokenization, size procedure, invariants); §4.3 classes, separation of responsibilities and precedence; and the approved principles elsewhere. Not frozen: every value in §11.2 |

**Evidence base:**
- `reports/v5/evidence-matrix/` (audit and minimal-pair probes);
- `reports/v5/research-notes-v2/`;
- `reports/v5/freeze-prep/`:
  - A: HTTP representation;
  - B: dataset engineering;
  - C: validation protocol;
  - D: sources and licences;
  - E: attack-pool audit;
  - F: tokenizer and bounds;
  - G: labeling and split.

Diagnostic flip counts are never operational FPR (D42).

---

## 1. Principles

1. **BINDING (D16, D37, D40).** V5 learns concepts, never development-set texts, templates, field names, hosts or values.
2. **APPROVED (D58).** Content over carrier: benign and attack rows share the carrier, and the generator controls length and structure between classes.
3. Evidence before inclusion, and no growth for row count alone (D21).
4. **APPROVED (D56, D57).** Framing and protocol anomalies are deterministic. The model sees `canonical-request/v1` with `Content-Type` as its only header.
5. **APPROVED (D59).** Labels come from provenance, value structure and explicit policies, never from field names alone.
6. **BINDING (D14, D18).** Scarce categories are reported `NOT EVALUABLE`, never inflated. The 19 categories remain the long-term target.
7. **APPROVED (D57).** Coverage is stated along five dimensions. No protection is claimed for a control that does not exist.

---

## 2. Scope

### 2.1 Benign families (concepts; class = strength of evidence)

| Family | Class | Evidence (matrix #) | r3 rule |
|---|---|---|---|
| Legitimate punctuation, literal and percent-encoded (`'` `#` `!` `&` `;` `%` `+`), including apostrophes in names and non-name text | HIGH | #4, #5, #6 | Both forms in **both** classes on every legal carrier, through the shared encoder (§6) |
| Street addresses | HIGH | #1–#3 | Values from the in-repo synthetic street lexicon (D58). Field names are drawn independently of the value role |
| Multi-key / typed / nested JSON | HIGH | #9, #10 | Body must parse under its declared `Content-Type` in both classes. Stability target (§9.2) |
| Passwords with non-alphanumerics | MEDIUM-HIGH | #6 | NIST 800-63B printing ASCII. Values hitting the benign oracle are rejected and counted |
| External URLs, `http` and `https` | MEDIUM-HIGH | #8 | Labels per policy `POL-URL-PUBLIC` (§4.3). Reserved hosts only (RFC 2606). The envelope host pool is never reused as a value pool |
| Multi-field forms; multi-parameter queries | MEDIUM | #11 | Full field-count range in both classes |
| Natural prose including SQL/shell homonyms and partial syntax (`a<b`, `--`, `;`) | MEDIUM | #11, #12 | Values from the Tatoeba CC0 export. ALLOW only if the oracle passes (§4.4) |
| IP / hostname as non-URL data | MEDIUM | audit §3.4 | `POL-ADDR-DATA`, with a quota in both classes |
| Encoded paths | LOW | v1 | Minimal coverage. Never decodes to `..` in benign rows |
| Chunked framing family (r1) | — | #7 | **Removed** by D56: framing is not in the model text. Matrix #7 is closed by construction and replaced by invariance test I4 (§5.6) |
| Header-carried benign content (r2) | — | — | **Removed** by D57: no such header is in the text |
| Technical prose, code, markup with attack-like syntax | — | — | **Deferred** (D59). Recorded as a coverage limitation and a future evaluation candidate (§10) |
| Field-name special-casing; raw framing bytes as text | REJECT | #2; framing note | Never implemented |

Priority order for building the families:
1. punctuation, JSON, addresses;
2. passwords, URLs, forms and queries, prose, address-as-data;
3. encoded paths.

### 2.2 Media types in the V5 training scope (APPROVED D56; list PROPOSED)

The training data contains only:
- requests with no body;
- `application/x-www-form-urlencoded`;
- `application/json`;
- `text/plain`.

Every other media type is valid HTTP but outside the V5 training scope, and is marked with the signal `S-MEDIA-UNSUPPORTED` (§5.3). This includes `multipart/*`, `application/xml`, binary types, `application/octet-stream` and others. V5 has no evidence on these media types. Their enforcement policy is decided explicitly at gateway integration, and this document makes no claim about it.

### 2.3 Category coverage (APPROVED D57: five dimensions; per-category values and the primary / report-only tiering are PROPOSED, as of 2026-10-11)

Column definitions:
- **(1) ML-trained:** the V5 training plan. V5 is not trained yet, so every "yes" means *planned*.
- **(2) Evaluated:** computed under D60 after the split (≥ 100 payload families in the dataset and ≥ 30 in INTERNAL TEST).
- **(3) Deterministic control implemented and tested by the project.**
- **(4) Protection proposed only.**
- **(5) Not supported today:** marked for every category with **no ML training planned and no project-implemented control**, even when a protection is proposed in (4), so that (4) never reads as protection (D57). ML-trained categories show "—" in (5) because their coverage is the planned model, which is itself not trained yet.

The table has 18 rows because directory traversal and file inclusion form one category (D49). The long-term target remains V4's 19 categories (D18).

Pool counts are unique canonical payloads (`canonical_key`) of the V4 extraction at the pinned commit, before the D58 structural filters. "After the deny-list" keeps a payload if it occurs in at least one non-denied file. The exact computation over the 20 matched files is in `freeze-prep/README.md` §S3. Pool counts are **not** payload families. Families collapse digits, hosts and repeats (§4.6), so evaluability will be lower than these counts suggest; for example, `Traversal.txt` is dominated by `../` chains.

| Category | (1) ML-trained | (2) Evaluated | (3) Det. control | (4) Proposed protection | (5) Not supported | Notes |
|---|---|---|---|---|---|---|
| SQL injection | yes, primary | pending (computed) | no | — | — | pool 1,278 → **1,000** after the deny-list |
| XSS | yes, primary | pending | no | — | — | 2,238 → **705** after the deny-list |
| Directory traversal + file inclusion (D49) | yes, primary | pending | no | — | — | 13,157 → **2,828** (union; `dotdotpwn.txt` and `JHADDIX_LFI.txt` excluded) |
| Command injection | yes, primary | pending | no | — | — | 453 |
| SSTI | yes, primary | pending | no | — | — | 369 |
| SSRF | yes, report-only (policy classes of §4.3 only) | **expected NOT EVALUABLE** (computed) | no | egress / destination policy | — | 202 before policy exclusions; audit 43% INCORRECT |
| Open redirect | yes, report-only (parser-differential forms only) | expected NOT EVALUABLE (computed) | no | redirect allowlist policy | — | pool 242; plain external URLs in navigation roles are excluded |
| NoSQL | yes, report-only | expected NOT EVALUABLE (computed; pool 83 < 100) | no | — | — | |
| CRLF (parameter-borne) | yes, report-only | expected NOT EVALUABLE (computed; pool 22) | no | header CR/LF reject (r3 §5.3 R4) | — | project-authored hardcoded list |
| XPath | yes, report-only | expected NOT EVALUABLE (computed; pool 31) | no | — | — | project-authored hardcoded list |
| LDAP | no (deferred) | — | no | — | **yes, for V5** | audit 87% INCORRECT; hand curation needed |
| GraphQL | no (deferred) | — | no | depth/introspection policy | **yes, for V5** | 73% INCORRECT |
| XXE | no (deferred; XML outside §2.2) | — | no | XML parser hardening | **yes, for V5** | 53% INCORRECT, 73% unusable; mixed with XSS/SQLi |
| Insecure deserialization | no | — | no | media-type policy | **yes** | 12 payloads |
| JWT | no | — | no | structural checks (`alg: none`, empty signature, `kid` pattern, `jku`/`x5u`/`jwk`) as SIGNALS | **yes, today**; signature forgery is never in scope (needs the key) | D48; 94 of 95 V4 rows are not tokens |
| CSRF | no | — | no | origin / `Sec-Fetch-Site` policy with a configured trusted-origin list | **yes, today** | needs application context |
| HPP | no | — | no | schema-aware duplicate-parameter policy | **yes, for V5** | same syntax as benign arrays |
| Request smuggling | no | — | **no**: mitmproxy's default validation is third-party behaviour, not pinned or tested by the project | pin `validate_inbound_headers=true` and test the r3 §5.3 R1 vectors | **yes** (no project control exists; mitmproxy's defaults mitigate many forms as third-party behaviour) | 7 rows |

Correct wording: "V5 is planned to train up to 10 categories (5 primary and 5 report-only; the tiering is PROPOSED, and every category is conditional on the post-filter audit of §7). Per-category evaluation is computed after the split. No category is protected by a project-implemented deterministic control today." No single "covered categories" count is used.

---

## 3. Sources and provenance (APPROVED D58)

| Use | Source | Licence (verified, `freeze-prep/D_sources_provenance.md`) | Conditions |
|---|---|---|---|
| Attack pool | PayloadsAllTheThings `e961fef231d8327bae83b563fab50aec2e6b77c0` | MIT | Third-party file deny-list (§3.1); MIT notice |
| Attack pool (project-authored) | Hardcoded CRLF and XPath lists in `parse_dataset_v4.build_hardcoded_sources` | repo MIT | Hashed in the manifest; HPP and smuggling lists are not used (§3.1 item 4) |
| Names | Wikidata given-name (Q202444) and family-name (Q101352) items | CC0 | Recombine only. No living person's full name. Pin a query snapshot by SHA-256. The yield of names with apostrophes is not measured yet (PENDING, stage 2) |
| Prose | Tatoeba `sentences_CC0` export | CC0 | Pin file SHA-256. The non-CC0 Tatoeba subset (CC BY 2.0 FR) is not used. Apply the personal-data filters of `D_sources_provenance.md` §4 |
| Streets | Synthetic street lexicon authored in this repository | repo MIT | Documented, diverse (noun / ordinal / unit / punctuation variety). No real personal address. Fingerprint risk audited (§7 C-S checks) |
| Structural reference (optional) | GitHub and Stripe OpenAPI specs | MIT | Statistics only; no identity, no examples rendered |
| Report-only slices (optional, local) | CSIC 2010 | no published licence | Never TRAIN, never redistributed, never an independent evaluation (V4 trained on it). Contains data its page says derives from real databases |
| Rejected | NQ (CC BY-SA), OpenStreetMap (ODbL), OpenAddresses (mixed licences, real addresses) | — | — |
| Eval-only (not used now) | open-appsec | Apache-2.0 / mixed | Personal-data review needed first |

### 3.1 Controlled PATT reuse (APPROVED D58; deny-list contents PROPOSED, finalized at generator stage 2)

1. **Third-party file deny-list.**
   - A PATT file whose **name or header** identifies a third-party origin is excluded, unless its licence is verified for the approved use and its attribution is recorded.
   - Initial list (FACT, files present at the pinned commit):
     - `SQL Injection/Intruder/FUZZDB_*.txt` (8 files);
     - `SQL Injection/Intruder/Generic_TimeBased.txt` (header "# from wapiti" references a GPL-2.0 project; applicability unverified);
     - `Directory Traversal/Intruder/dotdotpwn.txt`;
     - `File Inclusion/Intruders/JHADDIX_LFI.txt`;
     - `XSS Injection/Intruders/{xss_alert.txt, xss_alert_identifiable.txt, MarioXSSVectors.txt, 0xcela_event_handlers.txt, JHADDIX_XSS.txt, RSNAKE_XSS.txt, BRUTELOGIC-*, port_swigger_xss_cheatsheet_event_handlers.txt}`.
   - The final list is reviewed file by file and hashed in the manifest.
   - Content with no named origin is used under PATT's MIT licence as an **assumption**, not a verified fact. A missing header does not prove authorship, and PATT has many contributors. The residual licensing risk is disclosed in the manifest's known limitations.
   - Not denied by name, but noted for review at stage 2: `jsonp_endpoint.txt`; `XSSDetection.txt`, whose content matches the RSnake / ha.ckers.org vectors; `IntrudersXSS.txt`; `SQL Injection/Intruder/Auth_Bypass*.txt`, described as fuzzdb-derived in `E_attack_pool_audit/` §6. Content evidence of third-party origin triggers the same rule as a name or header. The extensionless `payloads-sql-blind-*` and `SQL-Injection` lists are FuzzDB-style but are not read by the extraction today.
2. **Negative structural filters** from the audit (`E_attack_pool_audit/` §7): prose, tool output, placeholders (including lowercase forms such as `{payload}`), markdown residue, shell prompts, setup commands, truncated fragments, reference URLs.
   - SSTI trailing documentation comments are stripped, not dropped.
   - Never positive keyword signatures (audit F6 circularity).
3. **Per-source-file cap** on a category's share. The value is PENDING (pilot).
4. **Category deny-list:** JWT, CSRF, HPP, request smuggling, insecure deserialization, LDAP, GraphQL and XXE are not extracted for V5 (§2.3).
5. Each payload carries `source_file`, `payload_logical`, `payload_wire_form` and `native_forms` (§6).

---

## 4. Generation, labeling and split

### 4.1 Carrier symmetry (APPROVED D58)

Benign and attack rows share, whenever the concept allows:
- method;
- carrier;
- `Content-Type` and body syntax;
- cardinality and JSON shape;
- path style;
- serialisation;
- client encoder;
- the canonical form (§5).

**Length control.** Attack twins are drawn from length bins matched to their benign counterparts. Long benign prose and short attacks are both present.

### 4.2 Pairs and the attack twin (APPROVED D58; parameters PROPOSED)

- **The twin:** same template, carrier, serialisation and non-attack leaves; exactly one leaf differs.
- **Slot compatibility:**

  | Slot | Compatible categories |
  |---|---|
  | free string | SQLi / XSS / CmdI / SSTI / NoSQL / XPath / CRLF |
  | URL | SSRF / open redirect (policy classes only) |
  | path or file | traversal + file inclusion |
  | JSON leaf | NoSQL / SQLi / XSS / SSTI |

- **Placement:** `placement_mode ∈ {replace, prefix, suffix, embedded}` is recorded. The shares are PROPOSED at the pilot.
- **Balance by pairs.** No row trimming.

### 4.3 Labeling policy (classes and principles APPROVED D59; label classes, `POL-*` policy classes and assumed contexts, separation of responsibilities and the precedence order FROZEN D62. The concrete host / scheme / form lists and the navigation-role lexicon are **PROPOSED**: the lists in the table are examples to be closed at generator stage 4, §11.2)

A label is a function of provenance, value structure and explicit policies. The slot role, inferred from field names, may only decide **inclusion**. **Attack-pool items are never relabelled ALLOW**: if their value class is not a BLOCK class, they are excluded.

**VERIFIED** (unequivocal, by construction):

| Rule | Label |
|---|---|
| Benign generator value (name, prose, street, password, JSON scalar, relative path) that passes the benign oracle (§4.4) | ALLOW |
| Attack-pool payload of an **injection-type** category (SQLi, XSS, traversal + file inclusion, CmdI, SSTI, NoSQL, XPath, CRLF) that passed the deny-list, filters and post-filter audit, placed in a compatible slot (§4.2) | BLOCK + V4/D47 reason string |

**Exception:** SSRF and open-redirect BLOCK labels are **never** VERIFIED. They come only from a `POL-*` BLOCK class below and are `POLICY_DEFINED`, even when the payload comes from the attack pool.

**POLICY_DEFINED** (each `policy_id` states its rule and the application context it assumes; the policy table is versioned and hashed in the manifest):

| `policy_id` | Value class (deterministic test) | Label | Assumed application context |
|---|---|---|---|
| `POL-URL-META` | URL host in link-local `169.254.0.0/16` (which includes the common cloud metadata address), `fd00:ec2::254`, `metadata.google.internal`, `100.100.100.200` | BLOCK | The application does not legitimately receive client-supplied URLs targeting cloud metadata or link-local services |
| `POL-URL-SCHEME` | URL scheme other than `http`/`https`, e.g. `gopher`, `dict`, `file`, `ldap`, `jar`, `php`, `expect`, `netdoc`, `javascript`, `data` | BLOCK | The application accepts only `http(s)` URLs from clients |
| `POL-URL-OBFUSCATED` | Host in decimal / octal / hex / dword IPv4, IPv4-mapped IPv6, userinfo `@` confusion, mixed-radix forms | BLOCK | The application does not legitimately receive host representations whose only function is defeating host validation |
| `POL-REDIRECT-DIFF` | `//h`, `/\h`, `\/\/h`, `/%2F%2Fh`, `https:h`, CR / LF / TAB inside a URL value | BLOCK | The application does not legitimately receive scheme-relative or malformed URL forms in URL values |
| `POL-URL-PUBLIC` | Absolute `http(s)` URL to a public host (RFC 2606 stand-ins), no attack structure, in a non-navigation role | ALLOW | The application authorizes public destinations. Destination authorization is enforced by the application or an egress policy, **not** by V5. **Not** a claim that every external callback is legitimate |
| `POL-ADDR-DATA` | IP address or hostname in a non-URL field | ALLOW | Non-URL values are not dereferenced by the application |

**Precedence (first match wins; deterministic):**
1. `POL-URL-META`
2. `POL-URL-SCHEME`
3. `POL-URL-OBFUSCATED`
4. `POL-REDIRECT-DIFF`
5. the `INSUFFICIENT_CONTEXT` exclusions below
6. `POL-URL-PUBLIC`
7. `POL-ADDR-DATA`

Consequences:
- `metadata.google.internal` is BLOCK under `POL-URL-META`, although `.internal` hosts are otherwise excluded.
- An obfuscated loopback, such as `2130706433` or IPv4-mapped `::ffff:127.0.0.1`, is BLOCK under `POL-URL-OBFUSCATED`. The label tracks the evasive representation, not the destination.
- A non-HTTP scheme to an internal host, such as `gopher://127.0.0.1`, is BLOCK under `POL-URL-SCHEME`. The label tracks the scheme, not the destination.
- A plain `http(s)` loopback or private destination is excluded.

**EXCLUDED** (never in TRAIN; counted):

| Case | `exclusion_reason` | Slice |
|---|---|---|
| URL to loopback (`localhost`, `127/8`, `[::1]`), private (RFC 1918, `fc00::/7`), `.internal`, `.local`, `.lan`, single-label host | `INSUFFICIENT_CONTEXT` | `ctx_loopback`, `ctx_private` |
| Absolute external URL in a navigation role (`next`, `return_to`, `redirect`, `continue`, …), benign draw or attack-pool item | `INSUFFICIENT_CONTEXT` | `ctx_open_redirect` |
| Attack-pool item whose value class is not a BLOCK class | `INSUFFICIENT_CONTEXT` | `ctx_attack_unclassified` |
| Deliberately constructed evaluation rows in which benign text quotes a complete attack-pool payload | `AMBIGUOUS` | `quoted_syntax` |
| Legitimate DSLs, technical prose, code, markup | `OUT_OF_SCOPE` (deferred family) | none until a curated set exists |
| Generator-sampled benign value rejected by the oracle (§4.4), never deliberately constructed | `ORACLE_REJECT` | — |
| Attack-pool item rejected by the deny-list, filters or audit | `AUDIT_REJECT` | — |
| Category outside V5 ML scope (§2.3) | `OUT_OF_SCOPE` | — |
| Row over the token budget (§5.5) | `OVER_LIMIT` | — |
| Stateful cases (credential stuffing, IDOR, authorization, rate abuse) | no rows; declared NOT TESTABLE | — |

**One reason per row.** The first matching reason is recorded, in this order:
1. `OUT_OF_SCOPE` (category)
2. `AUDIT_REJECT`
3. `ORACLE_REJECT`
4. `INSUFFICIENT_CONTEXT`. Within it, the specific `ctx_loopback` / `ctx_private` / `ctx_open_redirect` before `ctx_attack_unclassified`.
5. `AMBIGUOUS`
6. `OUT_OF_SCOPE` (deferred family)
7. `OVER_LIMIT`, evaluated last, after rendering.

The navigation-role lexicon decides inclusion only. Every lexicon name also appears in included rows: relative URLs (ALLOW) and `POL-REDIRECT-DIFF` forms (BLOCK).

### 4.4 Benign oracle (APPROVED D59; L PENDING)

The oracle is derived from the attack pool only, never from probe or development material. A benign value is rejected (`ORACLE_REJECT`) when any of the following holds:
- its `canonical_key` equals an attack-pool `canonical_key`;
- it contains an attack-pool canonical payload of length ≥ L;
- it contains a breakout signature of a compatible category.

Constraints:
- The signature list is versioned and hashed.
- L is calibrated on the pilot. It is never V4's `MIN_LEN=4`.
- Values like `O'Neil`, `Apt #4`, `AT&T`, `100%` and `a<b` must survive. This is a test fixture.

### 4.5 Label metadata and invariants (APPROVED D59)

| ID | Invariant / validation |
|---|---|
| M-1 | `label_status ∈ {VERIFIED, POLICY_DEFINED, EXCLUDED}` for every generated row |
| M-2 | `exclusion_reason` present **iff** `EXCLUDED`, with a value in {`AMBIGUOUS`, `INSUFFICIENT_CONTEXT`, `ORACLE_REJECT`, `AUDIT_REJECT`, `OUT_OF_SCOPE`, `OVER_LIMIT`} |
| M-3 | `policy_id` present **iff** `POLICY_DEFINED`, and it resolves in the versioned policy table whose SHA-256 is in the manifest |
| M-4 | TRAIN and VALIDATION hold **no** `EXCLUDED` row. The INTERNAL TEST headline holds none. `AMBIGUOUS` / `INSUFFICIENT_CONTEXT` rows exist only in slice files. Other exclusions are counted in the manifest only |
| M-5 | Every BLOCK row has `attack_category`, `payload_family_id`, and `label_rule` = `ATTACK_POOL_LEAF` or a BLOCK policy. No ALLOW row has a `payload_family_id` |
| M-6 | No attack-pool item carries ALLOW |
| M-7 | BLOCK reason strings are in the D47/V4 vocabulary. Traversal and file-inclusion rows keep their source-specific V4 reason strings, while D49 governs only their joint evaluation category. `POL-*` BLOCK rows carry `attack_category` = SSRF for `POL-URL-META` / `POL-URL-SCHEME` / `POL-URL-OBFUSCATED`, and open redirect for `POL-REDIRECT-DIFF` (the `javascript:` / `data:` forms of `POL-URL-SCHEME` are XSS) |
| M-8 | The label function takes no field-name input. A test renames fields within a role and asserts identical labels |
| M-9 | The manifest counts rows per (split, category, class, `label_status`, `exclusion_reason`, `policy_id`) |
| M-10 | Metrics are reported for `VERIFIED`, for `POLICY_DEFINED` and combined. Slices report BLOCK counts with denominators only (D42) |

Model output stays `ALLOW | reason` / `BLOCK | reason` (D25, D4). Metadata lives in a line-aligned `*.meta.jsonl` sidecar (PROPOSED storage).

### 4.6 Split algorithm (principles APPROVED D60; procedure FROZEN D62; cluster-share thresholds PROPOSED)

**APPROVED by D60** (the principles):
- constructive generation;
- the identities listed below;
- TRAIN 70 / VALIDATION 10 / INTERNAL TEST 20;
- groups never fragmented, and the build stops when correct assignment is impossible;
- the 2% cluster share as a diagnostic only;
- evaluability computed from real counts (≥ 100 families and ≥ 30 in INTERNAL TEST);
- a reserve of about 8%, only where defensible.

**FROZEN by D62** (made binding at the 2026-10-13 freeze): the identity definitions, conventions, cuts, reserve procedure, value-pool rule, constructive generation, cluster non-fragmentation and rebalancing rule, and invariants SPL-1–SPL-9 below.

**Still PROPOSED** (excluded from the freeze, resolved per §11.2): the cluster-share WARN / BLOCK values (2% / 5%) in step 5.

**Identities:**
- **`template_id`:** structural skeleton, field names excluded.
- **`struct_cluster_id`:** declared by the template author. Undeclared near-duplicate templates (Jaccard ≥ 0.60 audit) are merged in the declarations, never split. A merged cluster's id is the lexicographically smallest member id.
- **`payload_family_id`:** `canonical_key` + digits → `0`, hosts / IPs / e-mails → `H`, character runs > 3 → 3, whitespace removed. Variants and encodings share their family. Explicit family merges (SPL-9) happen **before** ranking, and the merged id is the smallest member id.
  - A family is one identity across categories: it is ranked once, on `pfid` alone.
  - Its **stratum category** is the lexicographically first category it occurs in.
  - It counts toward the evaluability of every category it occurs in.
- **`value_entry_id`:** `sha256(pool_id NUL NFC(element))` for elements of the HIGH-concept leaf pools: names, streets, prose, passwords, URLs.
- **`pair_id`:** a benign row and its twins.

**Conventions.** Hash inputs are joined with a NUL byte (D54 convention). Ranks run in ascending order of the hexadecimal digest. For a stratum of size n, the cuts are:
- `n_test = max(1, floor(0.20·n + 0.5))`;
- `n_val = max(1, floor(0.10·n + 0.5))`;
- TRAIN takes the rest.

The lowest ranks go to INTERNAL TEST, then VALIDATION, then TRAIN. The minimum of 1 applies only when n ≥ 3; a stratum with n < 3 goes entirely to TRAIN. Python's `round()` is **not** used.

**Assignment, before rendering.** Frozen in the generator config and hashed in the manifest:
- `SALT = "v5-split-v1"`;
- the master seed;
- the list of carrier strata;
- the pool list;
- the shares.

1. **Clusters.** Within each carrier stratum, rank by `sha256(SALT NUL "cluster" NUL id)` and apply the cuts. A stratum with n < 3 is flagged `NOT_EVALUABLE_STRUCTURE`: its templates appear only in TRAIN, so no unseen-structure evaluation exists for that carrier, and the report says so.
2. **Payload families,** per stratum category, ranked by `sha256(SALT NUL "payload" NUL pfid)`.
   - **Reserve size.** `R = ceil(0.08·n)`, where n is the number of families of the category after merges. Families with native held-out forms (ENC-5) are counted inside R and placed first. If they exceed R, the reserve equals them, recorded as such, or ENC-5's alternative applies.
   - **Attempt 1, with the reserve** (only if R ≥ 30). Reserve the first R by rank (forced families first), then apply the cuts to the rest. Evaluability counts only families in TRAIN ∪ VALIDATION ∪ INTERNAL TEST, never the reserve. If it holds (≥ 100 and ≥ 30 in INTERNAL TEST), accept.
   - **Attempt 2, without the reserve.** Apply the cuts to all families. If evaluable, accept; record "no reserve: not defensible".
   - **Otherwise `NOT EVALUABLE`.** All families go to TRAIN, with no reserve.
   - Each step is deterministic and runs before any rendering.
3. **Value entries,** per pool, ranked by `sha256(SALT NUL "value" NUL value_entry_id)`, then the cuts. Each split needs ≥ 20 elements, so VALIDATION at 10% implies a pool of at least about 200. A pool that cannot meet this blocks the build; the pool is enlarged, and the minimum is never lowered.
4. **Constructive generation.** Each split draws only from its own partitions. The per-row RNG is `Random(f"{SALT}|{split}|{cluster}|{quota}|{i}")`, seeded from that string. Nothing is dropped for membership.
5. **Cluster share** = rows of one cluster ÷ rows of its split, computed after generation. WARN above 2%, BLOCK above 5% (**values PROPOSED**, excluded from the freeze; fixed in the dataset preregistration, §11.2).
   - On WARN or BLOCK, the cluster's row quota is reduced and the difference is redistributed proportionally to the other clusters of the same stratum and split. The cluster stays whole.
   - If a required concept is only expressible in that cluster, a written ruling **approved by the owner** is recorded.
   - Otherwise the configuration is rejected and the build **stops**.
   - A cluster is **never** fragmented.
   - Realised row shares per split are reported. The 70/10/20 shares apply to cluster and family **counts**, not to rows.

**Invariants (unit tests on fixtures, then gates on the real build):**

| ID | Invariant |
|---|---|
| SPL-1 | Order independence |
| SPL-2 | `PYTHONHASHSEED` independence |
| SPL-3 | No `struct_cluster_id` / `template_id` / `pair_id` / `payload_family_id` / `value_entry_id` in two splits |
| SPL-4 | Every row's identities belong to its split, asserted, never silently removed |
| SPL-5 | Assignment runs on identities only; the split module does not import the renderer |
| SPL-6 | Exact and canonical duplicates (full text, payload, value) stay within one split |
| SPL-7 | No `E6_RESERVE` family or variant appears in any split, and no training transform is applied to it |
| SPL-8 | Each category's evaluability flag is computed from counts, never hand-set |
| SPL-9 | 0 cross-split payload near-duplicates (Jaccard ≥ 0.60) after explicit family merges, which are listed in the manifest |

---

## 5. Canonical model input `canonical-request/v1` (APPROVED D56, D57)

### 5.1 Pipeline position

```
wire → mitmproxy (parse, de-chunk) → canonicalize(parts) → REJECT | text + audit record
     → tokenization (template-safe, §5.4) → V5
```

`canonicalize` is one pure, stdlib-only function shared by the generator and the gateway. Gateway integration is a later phase (D56). Until then the gateway keeps V4's D1 rendering.

**What the contract guarantees, and what it does not (D56).**
- **Guarantees:** identical text for training and inference given the same request parts; framing and hop-by-hop information removed from the model text; deterministic rejects with stated reasons.
- **No universal backend-equivalence guarantee:**
  - Percent-decoding, `+` handling, charset interpretation and path normalisation are application-specific. The model sees the bytes, not any particular backend's interpretation.
  - The text is computed from mitmproxy's parsed request. mitmproxy re-serialises the request upstream, and wire details are lost before `canonicalize` runs: chunk extensions and sizes, `Content-Length` padding, line endings, bytes after the framed body (A §4 items 4–9).
  - A clean canonical text therefore does not prove clean wire framing. Wire-level framing is the deterministic validator's job (R1).

### 5.2 Text grammar and byte rules (FROZEN D62; implements D56)

```
{METHOD} {TARGET} HTTP/1.1\n
[Content-Type: {value}\n]
[\n{BODY}]                      (only when BODY is non-empty)
```

| Element | Rule |
|---|---|
| Method | As received. Must be an RFC 9110 token, else **R6** |
| Version | Always rendered `HTTP/1.1`. The received version goes to the audit record. Rendering is identical for 1.0 / 1.1 / 2; HTTP/2 compatibility is tested before integration |
| Target | Rendered in **origin-form** (path + query).<br>• Bytes are preserved: no percent-decoding, no re-encoding, no hex-case change, no dot-segment removal. Visible ASCII `0x21–0x7E` is kept as is.<br>• **Absolute-form** (proxy requests) is reduced to its origin-form path + query. The authority goes **only** to the audit record, never to the text (D44/D57).<br>• **Asterisk-form** (`OPTIONS *`) renders `*`. `CONNECT` (authority-form) is a tunnel, not an application request: it is outside the V5 contract and gets signal `S-CONNECT`; its policy is decided at integration.<br>• SP / CTL / DEL → **R5**.<br>• Non-ASCII octets are outside RFC 3986, but are **not rejected**, for client compatibility. Valid UTF-8 is rendered as UTF-8. Invalid UTF-8 octets are rendered as `\xNN`, the same rule as the body. Both get signal `S-TARGET-NONASCII` |
| `Content-Type` | The only header (D57), omitted when absent. Value with outer whitespace trimmed, decoded as **ISO-8859-1** (total and injective over octets; RFC 9110 §5.5 allows `obs-text`); signal `S-CT-NONASCII` if any octet ≥ 0x80. Not media-type grammar → rendered as received, signal `S-CT-MALFORMED`. Duplicate field → **R7** |
| Other headers | Never in the text. Inventoried in the audit record by name only (no values). **`obs-text` octets are valid and never rejected.** CR / LF / NUL in any field value → **R4** |
| Transfer coding | `chunked` removed by the parser. Any other transfer coding → **R2** |
| Content coding | `gzip`, `deflate`, `br`, `zstd` decoded, stacked codings in reverse order; `identity` passes. Unknown coding or decode failure → **R3**. The decoded size is bounded by §5.5 (decompression-bomb guard) |
| Body bytes → text | Strict UTF-8 decode; a leading BOM and all CR / LF are kept verbatim. Invalid UTF-8 → decoded with `\xNN` escapes for the invalid octets and signal `S-BODY-UTF8`. The `charset` parameter is not used for decoding; it stays visible in the `Content-Type` line. The escape form can coincide with literal `\xNN` text (see the **escape-ambiguity limitation** below this table) |
| Media type outside §2.2 | Rendered by the same rules, signal `S-MEDIA-UNSUPPORTED`. Its enforcement policy is explicit and decided at integration |
| Body without `Content-Type` | Rendered without a `Content-Type` line. Outside the §2.2 training scope: signals `S-CT-ABSENT` and `S-MEDIA-UNSUPPORTED` |
| Empty body | No blank line, no placeholder |

**Escape-ambiguity limitation (stated, not solved).** An invalid octet rendered as `\xNN` (body or target) is textually identical to a client that literally sent the four characters `\xNN`.
- The audit-record signal (`S-BODY-UTF8` / `S-TARGET-NONASCII`) distinguishes the two cases **for deterministic layers and logs only**.
- The **model never sees the signal**, so V5 cannot tell them apart. The signal does **not** guarantee disambiguation for the model.
- Consequences:
  - Requests carrying these signals are outside the V5 training distribution. The generator emits no invalid-UTF-8 content.
  - V5 decisions on them have no evidence behind them.
  - Any enforcement policy for them is decided explicitly at integration.
- A future contract revision could use an unambiguous escape, for example by also escaping literal backslashes. That would need a new revision and an owner decision.

### 5.3 Rejects and signals (requirement APPROVED D56/D57; R-list and S-list FROZEN D62; `MAX_DECODED_BODY` value PENDING)

Every reject needs a test vector that must be rejected and a valid counterpart that must pass. A reject is a contract outcome, distinct from the fail-closed 503 (D34); the client-visible status is decided at integration.

| ID | Reject condition | Justification | Valid counterpart that must pass |
|---|---|---|---|
| R1 | Conflicting or invalid framing: TE + CL, duplicate or invalid CL, multiple TE, TE on HTTP/1.0, non-final `chunked`, whitespace before the colon, malformed chunks | RFC 9112 §6.1–§6.3, §5.1; parser-disagreement / smuggling (note H). Today largely enforced by mitmproxy defaults (note G), to be pinned and tested | single valid CL; valid chunked |
| R2 | Transfer coding other than `chunked` | RFC 9112 §6.1 (a server may answer 501); the classified content would differ from the executed content (A §4, item 4) | `chunked` |
| R3 | Unknown content coding or decode failure | RFC 9110 §8.4 (a server may answer 415 for an unacceptable content coding); undecodable content cannot be inspected | gzip / br / deflate / zstd bodies |
| R4 | CR, LF or NUL in any field value | RFC 9110 §5.5 (reject or replace with SP) | value with `obs-text` octets; value with HTAB |
| R5 | Target with SP / CTL / DEL | RFC 9112 §3.2 (no whitespace in the request-target); RFC 3986 §2 | `%XX` triplets of any case; non-ASCII path, rendered with a signal |
| R6 | Method not an RFC 9110 token | RFC 9110 §9.1, §5.6.2 | extension-method tokens |
| R7 | More than one `Content-Type` field | RFC 9110 §5.3 and §8.3 (`Content-Type` is not a list-based field); parser disagreement | single `Content-Type` with parameters |
| R8 | For media types **inside** §2.2: rendered text over the token budget. For **any** media type: decoded body above the hard decompression cap `MAX_DECODED_BODY` (PENDING) | Resource bound (RFC 9110 §15.5.14, 413); truncation would hide payload tails | request exactly at the budget; a large body of an unsupported media type below the cap (signal only) |

Signals are recorded in the audit record and have **no enforcement effect** (D57). They are:
- `S-ENC-MULTI`: a value still holding a valid `%XX` after one decode;
- `S-ENC-U` (`%u`), `S-ENC-NUL` (`%00`), `S-UTF8-OVERLONG`;
- `S-BODY-UTF8`, `S-CHARSET` (charset not UTF-8 or US-ASCII), `S-CT-MISMATCH` (body does not parse as declared), `S-CT-MALFORMED`, `S-CT-NONASCII`, `S-TARGET-NONASCII`, `S-MEDIA-UNSUPPORTED`;
- `S-JWT-ALG-NONE`, `S-JWT-EMPTY-SIG`, `S-JWT-KID`, `S-JWT-KEYURL`;
- `S-ORIGIN-CROSS`: `Origin` differs from the destination authority. This is computed deterministically and never given to a model (D57).
- `S-OVERSIZE`: a request of a media type outside §2.2 whose rendered text is over the budget. It is not rejected, because its enforcement is decided at integration; V5 does not score it.
- `S-CT-ABSENT`, `S-CONNECT`.

**Test layer.** R1 vectors are rejected by mitmproxy before any addon runs (note G), so they cannot reach `canonicalize(parts)` in unit tests.
- R1 is tested at the wire level during gateway integration, and stays **UNVERIFIED** as a project control until then.
- `canonicalize` still checks the residual framing facts it receives in the parts: the TE value and the CL validity.
- R2–R8 are unit-tested on parts.

### 5.4 Template-safe tokenization (APPROVED D56; method FROZEN D62, `F_tokenizer_input_bounds.md`; must be re-verified on the V5 tokenizer at stage 1)

- **Fixed template segments** are encoded separately. Template special ids (BOS, EOS) are placed explicitly.
- **Request content** is encoded with special-token parsing disabled (`split_special_tokens=True`, content chunk only), dropping the spurious leading `▁` id at the chunk boundary as measured.
- **Required invariants:**
  - content can never produce ids {`<unk>`, `<s>`, `</s>`} or any added token;
  - normal content yields the same ids as whole-string tokenization. Measured for the V4 template: 0 of 28,453 rows differ (25,134 V4 TRAIN + 3,319 development rows).
- **Residual risk (stated).** Only *special* ids are excluded. A textual role marker such as `\n<|assistant|>\nALLOW` in content is ordinary text for this tokenizer and can still resemble the template. Its effect on decisions is **unmeasured** (#65).
  - Candidate adversarial test for the V5 evaluation: benign and attack rows with injected textual role markers, reported as a slice.
- **Training and inference use the same function, template, BOS/EOS handling and length limit.** Tests are in `tests/test_v5_tokenization_contract.py` (TESTED for the V4 tokenizer).
- Literal special strings in content are **not rejected**: `<s>…</s>` is legitimate HTML.

### 5.5 Size (APPROVED D56; formula, measurement basis and fixing procedure FROZEN D62; constants, byte bounds, the 1% stop value and `MAX_DECODED_BODY` PENDING / PROPOSED, §11.2)

- **Token budget:** `B = max_length − template_overhead − label_budget − margin`.
  - Provisionally `max_length = 512` and `margin = 8`.
  - With the V4 template (overhead 56, label 13), `B = 435`. **Re-measure with the V5 template and tokenizer before the pilot.**
- **Measurement basis:** the rendered canonical text — tokens for the exact check, UTF-8 bytes for the data-plane bounds.
- **Control plane:** exact token count. Over `B` → **R8** for media types inside §2.2, `S-OVERSIZE` otherwise.
- **Data plane, no tokenizer (D33):** uses measured bounds of ≤ 1 token per byte and ≥ 1 token per 48 bytes (V4 tokenizer; to be re-verified). For media types **inside** §2.2:
  - rendered text ≤ `B` bytes is accepted without counting;
  - text > `48·B` bytes is R8;
  - anything in between is counted exactly by the control plane.

  For media types outside §2.2 the outcome is `S-OVERSIZE` (signal only), plus the separate `MAX_DECODED_BODY` cap.
- **Fixing procedure and stop criteria for the constants** (procedure FROZEN; executed at generator stage 1; values recorded in the dataset preregistration):
  - `template_overhead`: tokens of the final V5 template without content, measured with the V5 tokenizer.
  - `label_budget`: the maximum token count over the **fixed output vocabulary** (`ALLOW | …` / `BLOCK | <D47 reason>` + EOS), not over TRAIN rows, so it is not circular.
  - `margin`: 8, as approved provisionally. It changes only by owner decision.
  - **Bytes-per-token bounds:** re-verified on the V5 tokenizer (longest-token byte length; byte-fallback ≤ 1 token per byte). If either bound fails, it is recomputed, and the data-plane thresholds follow.
  - **Stop:** if the pilot build has more than 1% `OVER_LIMIT` rows in any category × class cell (threshold PROPOSED), generation stops and a `max_length` decision goes to the owner. The budget is never raised silently.
  - `MAX_DECODED_BODY` affects only the runtime; the generator's bodies are bounded by `B`. It is fixed at **gateway integration** as a resource bound, and must be ≥ `48·B` bytes so that it never rejects a request the token rule would accept.
- **Training generation:** a row over `B` is **excluded** (`OVER_LIMIT`) and counted per category × class. **No truncation, ever** (V4 truncated away the label of 89 TRAIN rows, D61). The acceptance gate reports the excluded share per cell (§7).

### 5.6 Contract invariants (FROZEN D62; fuzz-corpus size PROPOSED; A §8)

| ID | Invariant |
|---|---|
| I1 | One shared function: a test asserts that the generator and the gateway adapter import the same `canonicalize` object |
| I2 | Train/serve byte equality for the same parts |
| I3 | Idempotence: `canonicalize(parse(text)) == text` for every generated row, where `parse` is the reference parser of the canonical grammar |
| I4 | Framing independence: CL / chunked / gzip / br produce the same text |
| I5 | Metadata invariance: `Host`, UA, `Accept*`, `Cookie`, `Authorization`, header order and case, a valid CL and the version leave the text unchanged |
| I6 | Byte preservation of `%XX`, `+`, hex case and JSON key order |
| I7 | Totality: text or reject, never an exception or truncation. Checked on every generated row and on a fixed fuzz corpus (size PROPOSED at stage 1) |
| I8 | Unambiguous structure: the request line, the optional `Content-Type` line and the body boundary are always recoverable. Body and target *content* escapes (`\xNN`) may coincide with literal text. This is the accepted escape-ambiguity limitation of §5.2; the audit signal does not resolve it for the model |
| I9 | `canonical_key` is never applied to the model text (static check: no call site takes rendered text) |
| I10 | Every R2–R8 vector is rejected and every counterpart passes (unit level). R1 is checked at the wire level at integration |

---

## 6. Encoding controls (APPROVED D58, D60, D61)

| # | Control | Gate |
|---|---|---|
| ENC-1 | Each payload carries `payload_logical` and `payload_wire_form ∈ {plain, pre_encoded}`. Pre-encoded payloads are inserted verbatim; plain payloads are encoded exactly once | Unit test: no `quote` on `pre_encoded`; one decode returns `payload_logical` |
| ENC-2 | One shared client encoder set for both classes: `%20` / `+`, reserved characters literal or encoded where legal, uppercase hex, JSON compact or spaced | Per-class encoding-feature frequencies within tolerance (A-G1) |
| ENC-3 | **Blocking held-out-form gate in every split.** No row contains a D15 held-out form (double encoding `%25[0-9A-Fa-f]{2}`, `\uXXXX`, HTML entities, `${IFS}`, mixed-case hex, parameter fragmentation) unless the source payload holds it natively (`native_forms`) | Count of non-native held-out forms = 0 |
| ENC-4 | Class-difference audit of encoding features (layer count, `%25`, hex case, `+` vs `%20`) | C-S1 thresholds (§7). The V4 reference failure is `%25XX` ⇒ BLOCK at 63.8% |
| ENC-5 | Payload families with native held-out forms go to `E6_RESERVE` when the category supports a reserve. Otherwise the transform family is retired from the held-out list and this is disclosed | Recorded in the manifest |
| ENC-6 | Pre-encoded payloads normalized to uppercase hex, or `mixed_case_percent` retired as held-out. RFC 3986 §6.2.2.1 makes hex case equivalent for conforming decoders, but a non-conforming backend could differ. Normalisation is therefore applied only where the generator's decode check (ENC-1) confirms an identical decoded value | ENC-3 |
| ENC-7 | Mutation self-test: injecting `%2527` into a benign row fires ENC-3 and ENC-4 | A5 |
| ENC-8 | `payload_family_id` collapses encodings and variants, so no encoding of a TRAIN payload reaches TEST | SPL-3, SPL-6 |

---

## 7. Dataset acceptance criteria (pre-training gate)

Status per criterion:
- **APPROVED**: the check is mandatory.
- **PROPOSED**: the threshold is to be ratified in the dataset preregistration after the pilot build. A threshold is never relaxed after any model output exists (C-R6).

**Pilot and threshold-fixing procedure** (PROPOSED; generator stage 6):
1. **Pilot build.** Use the frozen generator configuration with every quota scaled to 10%. The pilot is never used for model training or any evaluation claim.
2. **Run the gates.** Every check in this table runs on the pilot.
3. **Thresholds** may only be **tightened** from the PROPOSED defaults on pilot evidence. Loosening one needs a written owner ruling recorded in the preregistration.
4. **Preregistration.** The owner ratifies the final values in `reports/v5/dataset-preregistration-v1/` (thresholds, constants, `L`, placement shares, per-file cap, deny-list hash). It is committed before the full build.
5. **Stop:** if a BLOCKING check fails twice in a row for the same cause, the work stops and goes to the owner. It never proceeds by relaxing the check.

| Group | Checks | Source | Threshold status |
|---|---|---|---|
| Integrity and reproducibility | A1 manifest SHA-256; A2 byte-identical regeneration under two `PYTHONHASHSEED` values; A3 split determinism; A4 source pins and licences (§3); A5 every blocking checker fires on an injected violation; A6 E0-successor gate | C §4.1 | APPROVED checks; A2/A3 exact |
| Leakage | L1/L2 0 exact / canonical cross-split; L4 0 identity overlap (SPL-3); L5 0 template-hash overlap; L7 0 collisions with every `BLOCK_ANY` set in `freeze-prep/consumed_sets.json` (External v1 in counts-only mode, L7a); L8 0 elements shared with the probe pools; L9 V5 pools disjoint across splits; L6/L10/L11 warnings | C §4.2 | 0-thresholds APPROVED; warnings PROPOSED |
| Labels and pairs | M-1…M-10 (§4.5); C-M2 pair integrity; C-M3 class balance per split [0.48, 0.52] | D59; C §4.3 | M-checks APPROVED; balance band PROPOSED |
| Shortcuts | C-S1 single-feature lookup (envelope, carrier, encoding features ENC-4, length bins, field names): BLOCK at margin ≥ 0.10 or accuracy ≥ 0.80; C-S2 value purity (E0); C-S3 token purity; C-S4 structure-only probe; C-S6 carrier symmetry ratio; C-S7 dominant pool element | C §4.4; B §4 | **PROPOSED** (pilot calibration) |
| Counts and composition | Evaluability per D60 (computed); C2 cluster share 2% WARN / 5% BLOCK (diagnostic, never fragmenting); C3 provider balance; C4 `STAB-HELD` frozen before training | D60; C §4.5 | D60 rule APPROVED; numeric C2/C3 PROPOSED |
| Representation | I1–I10 (§5.6); every row ≤ `B` tokens; tokenization invariants (§5.4); A-G2 every body parses under its declared `Content-Type`; A-G3 the only header line in the text is `Content-Type` | D56, D57 | Checks APPROVED and FROZEN (D62). The value of `B` and the fuzz-corpus size are PENDING / PROPOSED (§11.2) |
| Encoding | ENC-1–ENC-8 (§6) | D61 | APPROVED |
| Over-limit | `OVER_LIMIT` share reported per category × class. A cell above the threshold triggers an investigation for a length shortcut | D56 | threshold **PROPOSED** (pilot) |
| **Attack-pool post-filter audit** (D58: categories must pass) | Applies to **every ML-trained category** (primary and report-only); traversal ∪ file inclusion is one category (D49).<br>**Sample:** a fresh sample drawn **after** the deny-list and filters, stratified by source file within the category, with a new seed and n ≥ 50 (or the whole pool if smaller).<br>**Annotation:** annotator 1 and annotator 2 are LLMs of different models. Discrepancies are adjudicated by the coordinator or the owner, with the adjudicator recorded.<br>**Human review:** an independent **human** reviews, **blind** to the LLM labels, a stratified subsample of **≥ 20 items per category**. On that subsample, human labels prevail.<br>**Pass**, all three conditions:<br>1. the Wilson 95% upper bound of adjudicated INCORRECT is ≤ 20%;<br>2. the Wilson 95% upper bound of adjudicated UNCERTAIN + INCORRECT is ≤ 35%;<br>3. the human-subsample INCORRECT share is ≤ 20% (point estimate, e.g. ≤ 4 of 20).<br>**Fail:** per D58 ('must pass'), the category is **excluded from V5 TRAIN** and reported NOT SUPPORTED for V5. At most **one** re-audit is allowed, only after a documented filter change, with a new seed. There are no further re-draws (C-R6).<br>For reference only (pre-filter, not a gate result): the adjudicated INCORRECT rates were SQLi 13%, SSTI 20% and XSS 22%, so the filters are needed. The existing 95-item human sample is pre-filter and does **not** satisfy this gate.<br>LLM agreement is never reported as human validation | D58 | n, the human minimum, 20% / 35% / 20% and the re-audit limit PROPOSED; the gate itself APPROVED |
| Hygiene | H1 identities and secrets scan; H2 no field-name special-casing; H3 no framing bytes in text | C §4.6 | APPROVED |

**Rejection.** Any failed blocking check rejects the dataset version, following conditions C-R1–C-R10 of C §5. The rejected version is preserved, and a new version id follows.
- Version ids follow `v5-dataset-vN`, with N incremented.
- The split assignment (`SALT`, cuts) is reused unchanged by the next version, so INTERNAL TEST identities never move to TRAIN.
- If any model output on a rejected version's VALIDATION or INTERNAL TEST exists, that INTERNAL TEST is no longer fresh, and the successor needs new identities for it (D37).

---

## 8. Manifest and provenance (APPROVED D58, D6)

The manifest records:
- schema and status;
- D37 role per split;
- generator commit, clean-tree flag and per-file code SHA-256;
- the Python environment;
- source pins (PATT commit, Tatoeba file SHA-256, Wikidata snapshot SHA-256, street-lexicon SHA-256);
- licences and attributions (third-party notices policy);
- the deny-list and filter-set hashes;
- the policy-table hash;
- seeds and `SALT`;
- counts per §4.5 M-9;
- evaluability flags;
- E6 reserve contents (identities only);
- embedded check outputs;
- `artifacts: [{path, sha256, bytes}]`;
- determinism evidence;
- known limitations;
- the split configuration hash (SALT, master seed, strata, cuts) and the realised counts and row shares per split;
- the family and cluster merges;
- E6 reserve sizes and the categories without a reserve;
- ENC-5 retirements;
- owner rulings (cluster share, threshold loosening);
- the preregistration SHA-256.

The V5 dataset directory is explicitly gitignored.

---

## 9. Evaluation protocol (summary; C §6, D60)

1. **Roles (D37).**
   - TRAIN fits the model.
   - VALIDATION selects checkpoints and hyperparameters, and serves development decisions, together with the development probes.
   - INTERNAL TEST is read once after the checkpoint and thresholds are frozen, behind a single-run guard, with cluster-level bootstrap CIs.
   - `E6_RESERVE` is for #29 only: it is never rendered into any V5 split, never used for development, and is rendered only by the future held-out evasion suite under its own preregistration.
2. **Stability.** `STAB-HELD` is a sealed stability set built by its own generator, lexicon and salt. It passes C-L7/C-L8/C-L9 and is read **once**, after the checkpoint and thresholds are frozen, behind the same single-run guard as INTERNAL TEST. It is element-disjoint from V5 pools and probe pools. It holds control swaps per carrier, HIGH-family contrasts and attack twins. Gate criteria C-G1–C-G5 (C §6.4) are PROPOSED for ratification in the training preregistration. No absolute FPR bar is set (D42).
3. **External evaluation.**
   - External v1 (D40) gets at most one preregistered aggregate V5 run (D60), with an output scanner, and only **after** the V5 checkpoint, thresholds and the INTERNAL TEST read are frozen (D53 analogue). Inspecting any individual case converts it to V5 development data.
   - **External v2** is required for any V5 external claim. It is built under D38 with the byte-equivalence and CSIC-ancestry checks.
4. **What INTERNAL TEST can support:** generalization to unseen templates, payload families and value entries from the same authors, grammar and PATT source. It supports nothing about unseen providers, real traffic or operational rates.

---

## 10. Implemented today, and stated limitations

**IMPLEMENTED and TESTED** (independent utilities, uncommitted):

| File | What it does | Tests |
|---|---|---|
| `scripts/dataset/v5_dataset_checks.py` | duplicates, group disjointness, label consistency, manifest SHA-256, protected collisions | 31 |
| `scripts/dataset/audit_v5_attack_pool.py` | extraction, stratified sampling, summaries, second-annotation agreement, adjudication, human-review sample | 19 |
| `scripts/dataset/measure_v5_token_lengths.py` | aggregate token-length tables | — |
| `tests/test_v5_tokenization_contract.py` | template-safe tokenization invariants (V4 tokenizer) | 29 |
| `tests/test_v4_representation_contract.py` | characterization of current V4 representation | 40 |

**Not implemented:** `canonicalize()`, the generator, the policy table, the oracle, the split module, the shortcut audits, the stability-set generator, every deterministic control in §2.3.

**Coverage limitations (stated):**
- Header-borne attacks are invisible to the model text (D57).
- Technical prose, code and markup are deferred.
- LDAP, GraphQL, XXE, deserialization, JWT, CSRF and HPP are not V5 ML tasks.
- Media types outside §2.2 have no V5 evidence.
- Plain loopback, private destinations and open-redirect-by-allowlist cases are measured only in slices.
- V5 will not be compared with V4 on equal terms on CSIC-derived slices.

---

## 11. Freeze record

### 11.1 Freeze (D62)

| Freeze requirement | Status at freeze (2026-10-13) |
|---|---|
| 1. Necessary decisions approved | **Met**: D56–D61 |
| 2. Licences and provenance verified | **Met for the chosen sources** (§3). PATT content with no named origin is used under MIT as a **disclosed assumption** (§3.1). The third-party deny-list is rule-based: a file stays excluded unless verified |
| 3. Attack-pool quality audit completed and accepted | **Met as exploratory evidence** (owner accepted). A second annotation by a different model exists, and the human-review sample is prepared. The human review and the post-filter audit are **dataset-freeze** conditions (§11.3), not spec-freeze conditions |
| 4. Tokenization and size contract defined | **Met for the contract** (§5.4–§5.5). The constants are PENDING (§11.2) |
| 5. Acceptance criteria documented | **Met** (§7). The thresholds stay PROPOSED (§11.2) |
| 6. No known critical blocker | Met. Residual items are in §11.2 and §11.3 |
| 7. Explicit owner authorization to freeze | **Given 2026-10-13**, scoped as in §0 |

### 11.2 Register of values that remain PROPOSED or PENDING (excluded from the freeze)

None of these is approved. Each is resolved only at the step named, and every resolution is recorded in `reports/v5/dataset-preregistration-v1/` (owner-ratified, committed before the full build) or in a later owner decision.

| Value | Section | Current status | Resolved when and how |
|---|---|---|---|
| Cluster-share WARN / BLOCK (2% / 5%) | §4.6 step 5, §7 C2 | PROPOSED | Pilot (stage 6) → preregistration. Tighten only; loosening needs a written owner ruling |
| `OVER_LIMIT` stop value (1% per category × class cell) | §5.5 | PROPOSED | Pilot (stage 6) → preregistration |
| Fuzz-corpus size for I7 | §5.6 | PROPOSED | Generator stage 1 |
| `template_overhead`, `label_budget`, `B` | §5.5 | PENDING | Generator stage 1, measured with the V5 template and tokenizer by the frozen procedure → preregistration |
| `max_length` (512) and margin (8) | §5.5 | Provisional (D56) | Re-verified at stage 1; changed only by owner decision (stop rule in §5.5) |
| Bytes-per-token bounds (≤ 1 token per byte, ≥ 1 per 48 bytes) and the derived data-plane byte limits | §5.5 | PENDING | Stage 1, re-verified on the V5 tokenizer |
| `MAX_DECODED_BODY` | §5.3 R8, §5.5 | PENDING | Gateway integration, as a resource bound ≥ `48·B` bytes |
| All §7 acceptance thresholds (C-S1…C-S7, C-M3 band, C3, L6/L10/L11 warnings, post-filter 20% / 35% / human 20%, n ≥ 50, human ≥ 20, re-audit limit) | §7 | PROPOSED | Pilot → preregistration. Thresholds are never relaxed after any model output exists |
| Category distribution (primary / report-only tiering; trained categories) | §2.3 | PROPOSED | Decided by the post-filter audit (§7) and computed evaluability (§4.6); confirmed in the dataset freeze report |
| Concrete host / scheme / form lists and the navigation-role lexicon | §4.3 | PROPOSED | Generator stage 4 (labels module), reviewed by the owner, hashed in the policy table |
| Benign-oracle length `L` and signature list | §4.4 | PENDING | Pilot → preregistration |
| Placement-mode shares | §4.2 | PROPOSED | Pilot → preregistration |
| Per-source-file cap | §3.1 | PENDING | Pilot → preregistration |
| Final third-party deny-list (file-by-file review) and notices | §3.1 | PROPOSED | Generator stage 2 |
| Pilot size (10% of quotas) and other pilot-procedure details | §7 | PROPOSED | Ratified with the preregistration |

### 11.3 Mandatory before the dataset freeze (not spec-freeze conditions)

1. **Owner's human review of the 95-item pre-filter sample.** Done with `human-batch` and `human-compare`, followed by a review of the disagreements.
2. The **post-filter audit** of every ML-trained category (§7), including a blind human subsample of ≥ 20 per category.
3. Every BLOCKING check of §7, including byte-identical regeneration.
4. The preregistration of §11.2 values, committed before the full build.
5. `STAB-HELD` built and sealed.
6. The dataset freeze report (C §8 template).

## 12. Revision history

- **r1 (2026-10-06, #62).** Initial evidence-derived draft.
- **r2 (2026-10-11, #64).** Freeze-preparation review:
  - status tags;
  - attack side;
  - labeling;
  - grouping keys;
  - the `canonical-request/v1` proposal;
  - acceptance links;
  - P1–P5 pending.
- **r3 (2026-10-11, #64).** Approved decisions D56–D61 incorporated. Changes:
  - chunked and header-carried families removed;
  - media-type scope added;
  - five-dimension coverage table;
  - sources fixed (Wikidata CC0, Tatoeba CC0, in-repo streets) with the third-party deny-list;
  - `POL-*` policy table with assumed contexts;
  - metadata invariants M-1…M-10;
  - split algorithm with E6 reserve and non-fragmentation rule;
  - byte and encoding rules, justified rejects R1–R8 with valid counterparts, signals;
  - template-safe tokenization;
  - size procedure with per-category × class over-limit accounting;
  - encoding controls ENC-1–ENC-8;
  - consolidated acceptance gate including the post-filter audit;
  - freeze-readiness table.

  Earlier text is preserved in git history (r1 at `5ce8c99`; r2 is uncommitted session work).
- **r3 amended (2026-10-13, #64).** Session-5 consistency corrections, documentary only. No approved decision was changed. Detail written after approval is re-tagged PROPOSED (binding at freeze); split, size, labeling-precedence and post-filter-gate procedures are made unambiguous; pilot, threshold-fixing, versioning and protected-evaluation rules are added. The list is in `freeze-prep/README.md` §S5.
- **r3 FROZEN (2026-10-13, D62).** The freeze was scoped by the owner. Before freezing: the §4.6 "everything else becomes binding" ambiguity was replaced by explicit FROZEN / PROPOSED lists; the §4.3 freeze scope was delimited (classes, contexts, separation, precedence; concrete lists stay open); the `\xNN` escape-ambiguity limitation was stated, without claiming the audit signal disambiguates for the model; the §11.2 register of open values was added.
