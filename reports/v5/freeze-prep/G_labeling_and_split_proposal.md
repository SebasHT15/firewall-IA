# G — Labeling policy (P4) and split algorithm (P5): final proposal for owner approval

> **Dated note (2026-10-12).** Approved **with adjustments** as **D59** and **D60**. The authoritative text is V5 DRAFT r3 §4.3–§4.6. Adjustments: URL-based labels are `POLICY_DEFINED` with explicit contexts (`POL-*`); external callbacks are not assumed legitimate; the 150-family figure is replaced by computed evaluability; the 2% cluster share is a diagnostic only. This proposal is kept unchanged as historical evidence.


Issue #64. Date: 2026-10-11. Author: coordinator (main agent).

Status *(historical; see the dated note above)*: **PROPOSED. Not approved, not frozen.** This document consolidates the second critical review (session report, 2026-10-11) and the coordinator's re-analysis. It contains:
- a labeling policy;
- a split algorithm precise enough to implement and test;
- the D15 encoding controls.

Nothing here is implemented. Candidate schema fields (`label_status`, `exclusion_reason`, …) are candidates, not an approved schema.

Tags: **FACT** (verified; cited), **INFERENCE**, **PROPOSAL**.

---

## 1. Labeling policy (P4)

### 1.1 Governing principle

V5 sees only the canonical request text (P1/P2). It has no application context: no allowlists, no authorization state, no server configuration.

**INFERENCE.** If the correct label for a text depends on context the text does not contain, the same text deserves different labels in different deployments. Training on either label is label noise by construction.

**PROPOSAL — three rules:**

1. **R-L1. A training label is a function of the value, never of the field name.** Slot role, which in practice is inferred from the field name, may decide only whether a row is *included*; it never decides the label. This answers the owner's requirement that the parameter name must not determine the label.
2. **R-L2. A training label is either VERIFIED or POLICY_DEFINED.**
   - **VERIFIED:** follows from provenance by construction. Either a benign generator value that passes the benign oracle, or an attack-pool payload accepted by the attack-pool audit (`E_attack_pool_audit/`) in a slot compatible with its category.
   - **POLICY_DEFINED:** follows from an explicit, app-independent rule written in this document. It is reported separately.

   Everything else is excluded from TRAIN.
3. **R-L3. Excluded rows are never silent.** They are counted in the manifest. Context-dependent ones form evaluation slices that report the BLOCK-rate only, with no accuracy, FP or FN claim, because no ground truth exists for them.

### 1.2 SSRF and internal destinations

**FACT.** V4 TRAIN has 186 SSRF BLOCK rows: 47 metadata, 50 loopback (including obfuscated), 8 private, 6 non-HTTP scheme, 75 other (coordinator count, regex over decoded text). V4 labelled them by PayloadsAllTheThings folder, with no host semantics.

The label is decided by the **class of the URL value**. URL here means a value that parses as an absolute URL, or as a scheme-relative `//host` reference.

| Value class (deterministic test) | Label | `label_status` | Rationale |
|---|---|---|---|
| **U1. Cloud metadata / link-local destination**: host in `169.254.0.0/16`, `fd00:ec2::254`, `metadata.google.internal`, `100.100.100.200` | BLOCK | POLICY_DEFINED | No legitimate client supplies a cloud-metadata endpoint as a URL value. The policy is stated, not assumed universal |
| **U2. Obfuscated host representation**: decimal / octal / hex / dword IPv4, IPv4-mapped IPv6, `@` userinfo confusion, mixed-radix dotted forms, trailing-dot or encoded-dot tricks | BLOCK | VERIFIED (attack-pool provenance) | The representation has no purpose except bypassing a host check. Present in the PayloadsAllTheThings SSRF folders |
| **U3. Non-HTTP fetch schemes**: `gopher:`, `dict:`, `file:`, `ldap:`, `jar:`, `php:`, `expect:`, `netdoc:` | BLOCK | POLICY_DEFINED | A client-supplied URL with these schemes targets a server-side fetcher |
| **U4. Plain loopback**: `localhost`, `127.0.0.0/8`, `[::1]`, no obfuscation | **Excluded** | `INSUFFICIENT_CONTEXT` | Legitimate as a dev callback or OAuth loopback redirect (RFC 8252); an SSRF when it reaches a server-side fetcher. Text cannot tell. Slice `ctx_loopback` |
| **U5. Private / internal**: RFC 1918, `fc00::/7`, `.internal`, `.local`, `.lan`, single-label hosts | **Excluded** | `INSUFFICIENT_CONTEXT` | Depends on the deployment. Slice `ctx_private` |
| **U6. Public external**: RFC 2606 reserved names as stand-ins, `http` or `https` | ALLOW | VERIFIED | Benign generator value. Matrix #8 (`http://` over-block) requires both schemes |
| **U7. Address as data, no scheme** (IP or hostname in a non-URL field, e.g. "server: 10.0.0.5") | ALLOW, with a quota in both classes | VERIFIED | Breaks V4's shortcut "loopback string ⇒ BLOCK"; the 58 V4 rows with `127.0.0.1` were all BLOCK (audit §3.4) |

**Consequences.**
- PayloadsAllTheThings SSRF payloads of class U4/U5 are **excluded** from TRAIN, not relabelled.
- The model's behaviour on plain loopback and private targets is therefore **unspecified and measured only** (slices). This is a stated limitation, not hidden risk.
- The right control for U4/U5 is an operator-configured **egress / destination policy** in the deterministic layer, where application context exists. That is out of scope for V5 training.

### 1.3 Open redirects

**FACT.** V4 TRAIN has 208 Open Redirect rows, none internal. PayloadsAllTheThings Open Redirect payloads are dominated by external hosts and scheme or slash tricks.

Whether a plain external URL in a navigation parameter is a vulnerability depends on the server's redirect allowlist, which the text does not contain.

| Case | Label | `label_status` |
|---|---|---|
| Relative or same-site path (`/account/orders`) | ALLOW | VERIFIED |
| Plain external absolute URL (U6) in a non-navigation role (webhook, callback-for-fetch, website, image, link) | ALLOW | VERIFIED |
| Plain external absolute URL in a **navigation role** (`next`, `return_to`, `redirect`, `continue`) — benign draw **or** attack-pool payload | **Excluded** | `INSUFFICIENT_CONTEXT`; slice `ctx_open_redirect` |
| **Parser-differential / scheme forms**: `//h`, `/\h`, `\/\/h`, `/%2F%2Fh`, `https:h`, `https://trusted@h`, `https://trusted.h` used as a confusable, tab / CR / LF inside the URL | BLOCK | VERIFIED |
| `javascript:` / `data:` URLs in any URL slot | BLOCK | VERIFIED (XSS mechanism) |

The navigation-role lexicon decides **inclusion only**, under R-L1. The label never changes with the name, because the role only removes rows.

To prevent a shortcut, every name in the lexicon also appears in included benign rows with relative URLs, and in BLOCK rows with parser-differential forms.

Consequence: Open Redirect is reported as **"structural redirect forms only"**. It is likely INSUFFICIENT DATA under D18 after exclusion; that is to be measured, not assumed.

### 1.4 Prose and technical content containing attack-like syntax

The r2/second-review rule ("exclude all benign text that cites attack syntax") is **too broad**. It would leave the model with no benign examples of SQL keywords, angle brackets, quotes, `--`, `;`, shell words or code. Those are exactly the legitimate inputs V4 over-blocks (matrix #6, #11).

The problem cannot be solved fully from text. A stored-XSS attempt and a forum post quoting the same `<script>` tag are byte-identical. The policy separates what *can* be verified:

| Case | Label | `label_status` |
|---|---|---|
| **Attack-like vocabulary and partial syntax without an executable payload**: SQL homonyms ("select the union of"), `a<b`, `x > 3`, `O'Neil`, "rock 'n' roll", `--` as a dash, `;` in prose, `rm`/`cat` as words, `100%`, `#hashtag`, `C:\path` | ALLOW | VERIFIED, **iff** the benign oracle passes |
| **Benign code and markup without an injection breakout**: a parameterized query (`... WHERE id = ?`), a JS/Python snippet with no HTML/script tags, Markdown, math, in a field whose value is a complete fragment | **DEFERRED** (not in V5-min) | — | Needs a licensed code or technical corpus and a definition of "breakout" per sink. Candidate for a later family; evaluation slice `tech_content` only if a curated set exists |
| **Text containing a complete payload from the attack pool, or one of its canonical signatures** ("quoted" or not) | **Excluded** | `AMBIGUOUS`; slice `quoted_syntax` | Byte-identical to an embedded attack; never ALLOW |
| **Attack twin with `placement_mode = embedded`** (prose plus payload) | BLOCK | VERIFIED | Consistent with the row above: a payload in text is never ALLOW, and the ambiguous benign reading is simply not trained |

**Benign oracle** (deterministic, derived from the attack pool only, never from probe or dev material). A benign value is rejected when any of the following holds:
- its `canonical_key` equals an attack-pool `canonical_key`;
- it contains an attack-pool canonical payload of length ≥ L (L calibrated on the pilot, never the V4 `MIN_LEN=4`);
- it contains a breakout signature of its slot's compatible categories. The signature list is versioned and hashed in the manifest.

Rejections are counted per signature.

### 1.5 Stateful and authorization-dependent cases

No training rows. They are declared **NOT TESTABLE** by a stateless request classifier:
- credential stuffing and brute force;
- IDOR and broken access control;
- business-logic abuse;
- rate abuse;
- CSRF token validity;
- JWT signature validity.

### 1.6 Candidate metadata (not an approved schema)

Two fields instead of one flat enum, because "excluded" and "why" are independent.

| Field | Candidate values | Meaning |
|---|---|---|
| `label_status` | `VERIFIED`, `POLICY_DEFINED`, `EXCLUDED` | Whether the row has a trainable label and its basis |
| `exclusion_reason` (only when `EXCLUDED`) | `AMBIGUOUS` (text-intrinsic: either reading possible), `INSUFFICIENT_CONTEXT` (decidable only with application context), `ORACLE_REJECT`, `AUDIT_REJECT` (attack-pool item failed the audit), `OUT_OF_SCOPE` (category handled outside ML) | Accounting and slice routing |

The model output stays `ALLOW | reason` / `BLOCK | reason`. D25 and D4 are unchanged; no third output is introduced.

`EXCLUDED` rows with reason `AMBIGUOUS` or `INSUFFICIENT_CONTEXT` are generated inside the split partition of their identities (§2), so a slice never leaks into TRAIN. They are reported per slice as BLOCK counts with denominators (D42).

---

## 2. Split algorithm (P5)

### 2.1 Identities

| Identity | Definition (PROPOSAL) | Granularity |
|---|---|---|
| `template_id` | `sha256` of the canonical structural skeleton: method; carrier (`query`/`form`/`json`/`path`/`xml`); `Content-Type` media type; path skeleton with id-like segments replaced by type tokens; for bodies and queries, the ordered list of (positional key path, value type). Field **names are excluded** | One authored template, independent of naming |
| `struct_cluster_id` | **Declared in the template source by its author**: templates that are variants of one endpoint pattern share a cluster. In V5-min templates are hand-written (30–60), so no automated similarity clustering is needed. An audit (token-shingle Jaccard ≥ 0.60 between templates, C L6) reports undeclared near-duplicates, which are resolved by **merging declarations**, never by splitting | Unit of structural split |
| `payload_family_id` | `canonical_key(payload)` (D16) followed by: digit runs → `0`; hostnames, IPs and e-mail → `H`; runs of one character longer than 3 → 3; whitespace removed. Every D15 training variant and every encoder rendering of a payload therefore shares its family | Unit of payload split |
| `value_entry_id` | `sha256(pool_id NUL element)` for elements of the **HIGH-concept leaf pools** (names, streets, prose, passwords, URLs) | Unit of value split |
| `pair_id` | A benign row and all its attack twins | Generated inside one split |

**FACT (second review, revisor C).** Similarity union-find over V4 benign templates produced a component holding 33% of rows at Jaccard 0.6. Exact templates alone gave a largest unit of 3.3%. Declared clusters avoid transitive chaining by construction.

### 2.2 Assignment (before any rendering, D16)

Constants are frozen in the generator config and hashed in the manifest:
- `SALT = "v5-split-v1"`;
- `SHARES = TRAIN 0.70 / VALIDATION 0.10 / INTERNAL_TEST 0.20`.

1. **Clusters.** Group `struct_cluster_id`s by stratum = carrier.
   - Within a stratum, sort by `sha256(SALT ‖ "cluster" ‖ id)`.
   - Assign by rank: the first `round(0.20·n)` (minimum 1) go to INTERNAL_TEST, the next `round(0.10·n)` (minimum 1) to VALIDATION, the rest to TRAIN.
   - A stratum with n < 3 goes entirely to TRAIN and is flagged `NOT_EVALUABLE_STRUCTURE`.
2. **Payload families, per category.** Sort by `sha256(SALT ‖ "payload" ‖ category ‖ pfid)`.
   - *Optional* `E6_RESERVE`: the first 8% of families of categories with ≥ 200 families. These go into no split and are reserved for the future held-out evasion suite (#29, D15).
   - Then INTERNAL_TEST 20%, VALIDATION 10%, TRAIN 70% by rank.
   - A category with fewer than 150 families after reserve and audit filtering (so that TEST would hold < 30, the D18 minimum) goes entirely to TRAIN and is reported `NOT EVALUABLE` (D18). It is never forced into TEST.
3. **Value entries, per pool.** Sort by `sha256(SALT ‖ "value" ‖ pool_id ‖ element)` and assign 20 / 10 / 70 by rank.
   - Minimum partition size: 20 elements per split per pool (C §3.2).
   - A pool that cannot meet the minimum blocks the build, and the pool is enlarged. Shrinking the minimum is not allowed.

Assignment is by **rank, not by modulo bucket**. This gives exact shares on small sets, and it is independent of input order and `PYTHONHASHSEED`.

### 2.3 Constructive generation

For each split S, cluster c ∈ S and concept quota q:

1. Draw value tuples **only** from S's value partitions.
2. Build the benign row.
3. Build each attack twin by drawing a payload family **only** from S's payload partition of a slot-compatible category.
4. The per-row RNG is `Random(f"{SALT}|{S}|{c}|{q}|{i}")`. There is no shared stream.
5. Render through `canonicalize()`.

Nothing is dropped for split membership: the drop rate is 0 by construction. This replaces the infeasible "drop unless all identities agree" rule, which would put 0.15³ ≈ 0.34% of rows in VALIDATION at 15%.

### 2.4 The 2% concern: clusters are never fragmented

A cluster's **row** share is controlled by generation quotas, not by structure. If a cluster exceeds the share bound (WARN > 2%, BLOCK > 5% of its split; C C2):

1. **Rebalance quotas** deterministically: generate fewer rows from that cluster and more from others. The cluster stays whole.
2. If a required concept is only expressible in that cluster, the cluster **stays whole**. The excess is reported with a written ruling in the freeze report.
3. If neither works, **reject the configuration and stop** the build. A new config version is needed (D39 spirit).

A cluster is **never split** across TRAIN / VALIDATION / TEST to satisfy a percentage. Refining the clustering is allowed only as an authored change to the template declarations, recorded in the config history. It never happens automatically at build time.

### 2.5 Invariants (each a unit test on synthetic fixtures, then a gate on the real build)

| ID | Invariant |
|---|---|
| S-I1 | Order independence: shuffling every input list yields an identical identity → split map |
| S-I2 | `PYTHONHASHSEED` independence (two values, byte-identical map) |
| S-I3 | No `struct_cluster_id`, `template_id`, `pair_id`, `payload_family_id` or `value_entry_id` is in two splits (`check_group_disjointness`) |
| S-I4 | Every row's identities belong to the row's split (membership assertion, no silent removal) |
| S-I5 | The split module does not import the renderer, and assignment runs on identities only (structural test: assignment input contains no rendered text) |
| S-I6 | Every exact or canonical full-text duplicate stays within one split; so does every payload- and value-level duplicate (`find_duplicates` on `input`, `payload`, `value` fields) |
| S-I7 | No `E6_RESERVE` family appears in any split |
| S-I8 | Each category is either `OK` (≥ 30 payload families in INTERNAL_TEST) or flagged `NOT EVALUABLE`; the flag is computed, never hand-set |
| S-I9 | Cross-split payload near-duplicates (shingle Jaccard ≥ 0.60 on payload canonical strings): 0 after explicit family merges; merges are listed in the manifest |

### 2.6 Protected evaluations (unchanged constraints)

- **D40:** External Test v1 is never opened case-by-case. At most one preregistered aggregate V5 run (Branch P), with an output scanner. Any individual inspection converts it to V5 development data. **External v2** is required for any V5 external claim; it is a separate issue and does not gate the data freeze.
- **Development data:** probes v1/v2, `real-http-fp-v1`, #57 and #59 sets. They may be used for development; they are never training material and never evidence for a claim.
- **INTERNAL TEST:** read once, after the checkpoint and thresholds are frozen, behind a single-run guard. Cluster-level bootstrap CIs (rows are correlated within clusters and payload families).
- **`STAB-HELD`:** its own generator, lexicon and salt. Element-disjoint from every V5 pool and from the probe pools. Sealed until the INTERNAL TEST read.
- **`E6_RESERVE`:** payload identities only. Its rendering is reserved for #29.

**What INTERNAL TEST can support (and nothing more):** generalization to unseen hand-written templates, unseen payload families and unseen value entries, **from the same authors, the same grammar and the same PayloadsAllTheThings source**. It says nothing about unseen providers, real traffic or deployment FPR (D42).

---

## 3. D15 encoding controls for V5

FACTs, recomputed by the coordinator and the second review:
- `%25XX` appears in 3,473 BLOCK / 0 ALLOW V4 TRAIN rows and 881 / 0 eval rows.
- By source: 697 CSIC-native, 2,057 renderer re-encoding of pre-encoded PayloadsAllTheThings payloads, 719 `url_encode` variants.
- The 137 lowercase-hex rows are native PayloadsAllTheThings bytes, not `mixed_case_percent` output.
- `HELD_OUT_TRANSFORMS` are descriptions with no code.
- The rule "`%25XX` ⇒ BLOCK" alone scores 63.8% on train and 64.2% on eval, with 0 false BLOCKs.

| # | Control (PROPOSAL) | Test / gate |
|---|---|---|
| E1 | **Logical payload vs wire form.** Each pool item carries `payload_logical` (fully decoded once, via `canonical_key`-style decoding without case folding) and `payload_wire_form ∈ {plain, pre_encoded}`. Pre-encoded items are inserted **verbatim**; plain items are encoded **once** by the shared client encoder | Unit test: `quote` is never applied to a `pre_encoded` item; encoder output decodes back to `payload_logical` in one pass |
| E2 | **One shared encoder set for both classes** (`%20` / `+`, reserved literal vs encoded where legal, uppercase hex) | G1 (A §8): per-class frequency of each encoding feature within tolerance per carrier |
| E3 | **Held-out form gate (BLOCKING), in every split.** Scan rendered text for each D15 held-out form (double encoding `%25[0-9A-F]{2}`, `\uXXXX` escapes, HTML entities, `${IFS}`, mixed-case hex, repeated-parameter fragmentation). A row may contain a held-out form only if its **source** payload already contains it (`native_form = true`, recorded) | Count of rows with a non-native held-out form = 0 |
| E4 | **Class-difference audit of encodings**: lookup accuracy of each encoding feature (layer count, `%25`, lowercase hex, `+` vs `%20`) | Fails at the S1 thresholds (C §4.4); `%25XX` ⇒ BLOCK at 63.8% is the reference failure |
| E5 | **Native held-out forms**: native pre-encoded payloads (for example `%252e` traversal) are legitimate attack data, but they make "held-out" impossible for that form. Either (a) route every payload family with a native held-out form to `E6_RESERVE`, or (b) keep them and **retire** that transform family from the held-out list, disclosing it | Decision for #29; recommended (a) when the family count allows |
| E6 | **Uppercase-hex normalisation** of pre-encoded payloads (semantics-preserving), or retire `mixed_case_percent` as held-out | E3 covers it |
| E7 | **Mutation self-test**: injecting `%2527` into a benign row must fire E3 and E4 | C A5 |
| E8 | **Payload identity separation**: `payload_family_id` collapses encodings and D15 variants (§2.1), so no encoding of a TRAIN payload appears in TEST | S-I3, S-I6 |

**V4 limitation to document** (owner-authorized; dated addendum style; D15's original text untouched):
- D15's held-out separation is not effective at the rendered-text level for double encoding.
- A payload-level encoding cue (`%25XX`) is a BLOCK-only shortcut in V4 data. E0 audits only non-payload features, so D20's "no shortcut" statement covers the envelope only.
- Published V4 claims are not invalidated: evasion robustness was always reported as unmeasured.

Recommended places:
- a dated note under D15 / D20 in `DECISIONS.md` (if the owner authorizes);
- issue #25 (limitations);
- a prerequisite note on #29.
