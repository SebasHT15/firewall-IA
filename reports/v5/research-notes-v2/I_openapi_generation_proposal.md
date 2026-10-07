# I. OpenAPI as a structural source: generation proposal (2026-10-06)

**RESEARCH NOTE, not a decision. Nothing here is implemented, downloaded or generated.** Every
policy choice is an owner decision not yet taken. It builds on `B_datasets.md` §2 (licences, example
coverage, measured counts) and §4 (literature, protocol 4.2) and does not repeat them. Where this
note says "B §x" it means those sections.

Label convention: **FACT** = read from a primary source or from B's measurements; **HYPOTHESIS** =
a design bet that no measurement here supports; **OWNER** = a decision for the owner.

## 0. Principle

**SCHEMA SHAPE != APPLICATION IDENTITY.** A spec is used only to learn *what a request looks like*
(which slots exist, their types, how deep, how many, how serialised). It is never used for *what the
request is about* (which vendor, endpoint, field vocabulary, enum literal, example value). So the
pipeline has one-way information flow: spec → **structure profile** (identity stripped) → renderer
(synthetic values). No spec string reaches a generated row except through an explicit allowlist
(§2.3).

Scope decision to keep this simple (OWNER): start with the three MIT sources in B §2.1 (GitHub,
Stripe, Azure). Apache-2.0 / CC BY specs and APIs.guru are phase 2 (§6).

---

## 1. Extraction: what is read from a spec, and what is kept

### 1.1 Pipeline (6 steps, all deterministic)

| # | Step | Output |
|---|---|---|
| E1 | **Pin and load** each spec at its pinned commit (§8). Dereference `$ref` (cycle cut at depth 6, `allOf` merged, `oneOf`/`anyOf` expanded to one *branch list*). | resolved operation list |
| E2 | **Flatten each operation** to a *request skeleton*: method, content type, path template, parameters (`in`: path/query/header/cookie, `style`, `explode`), body schema tree. | skeleton (still carries identity) |
| E3 | **Measure** the skeleton into a structure profile (§1.2). | profile (numbers and type labels only) |
| E4 | **Normalise** (§2) so the profile no longer contains vendor identity. | neutral template |
| E5 | **Dedupe** templates by canonical structural hash (§4.1). | template table |
| E6 | **Emit a manifest** with counts, hashes, and the list of dropped operations and why. | manifest |

FACT (OAS 3.1.0, <https://spec.openapis.org/oas/v3.1.0.html>): the Schema Object is a superset of
JSON Schema 2020-12; a Parameter Object has required `name` and `in`, plus `style`/`explode` that
control serialisation; every path-template expression `{x}` must match a path parameter; `style:
deepObject` serialises nested objects as `name[key]=value`. This is why the structure can be
extracted mechanically and why Stripe-style bracket nesting is a spec-given shape, not an invention.

Simplest sufficient extraction: no response-feedback, no dependency inference (the RESTler
approach in B §4.1). Requests are rendered **independently**; path ids are synthetic. The firewall
sees one request at a time, so producer-consumer realism is not needed (HYPOTHESIS, cheap to
check later with the shortcut gate).

### 1.2 What the profile records (per operation, per slot)

Everything below is a **number or a type label**, not a literal.

| Aspect | Recorded | Source in spec | If absent |
|---|---|---|---|
| Type | `string/integer/number/boolean/null/array/object`, plus `format` | `type`, `format` | `string` |
| Required vs optional | per field, bool | `required` | optional |
| Optional inclusion rate | **not in a spec** → drawn per render from a Beta prior (e.g. Beta(2,2)); required fields always 1 | n/a | HYPOTHESIS: specs say nothing about real-client usage of optional fields |
| Cardinality, object | number of keys, required count | schema | n/a |
| Cardinality, array | `minItems`/`maxItems`, else geometric on 1..5 | schema | geometric |
| Free-form maps | `additionalProperties`: draw k = 1..4 generic keys | schema | none |
| Nesting depth | max and per-leaf depth after `$ref` expansion, capped at 6 (GitHub request examples reach 7, B §2.2) | tree | n/a |
| Union choice | `oneOf`/`anyOf`: branch picked uniformly per render | schema | n/a |
| Enums | **cardinality, literal length class, casing style** (lower, UPPER_SNAKE, kebab, camel) | `enum` | n/a |
| Strings | length bucket (`minLength`/`maxLength`, else a default band), `pattern` → one of ~10 generator classes (uuid, hex, slug, digits, date, ...), `format` (email, uri, date-time, uuid, byte, password, ...) | schema | free text |
| Numbers | int vs float, `minimum`/`maximum`/`multipleOf`; else log-uniform magnitude bucket | schema | log-uniform |
| Booleans | P(true)=0.5, nudged toward `default` only if present | schema | 0.5 |
| URL-like slots | slot class `url`, `callback`, `webhook`, `redirect`, `file-path`, from `format: uri` or from the *generic* name lexicon (§2.2) | schema + name | `string` |
| Serialisation | content type (JSON / `x-www-form-urlencoded` / `multipart`), param `style` + `explode` | spec | OAS defaults |
| Envelope | method, path-segment count, number and position of path params, number of query params, presence of body, header-parameter count | operation | n/a |

**Corpus-level summary** (also emitted, used only for reporting, §9): the joint histogram of (depth,
leaf count, key count, type mix, content type), so the generated set's structural distribution can be
compared with the specs and with an independent real sample.

**Not recorded at all**: `summary`, `description`, `operationId`, `tags`, `externalDocs`, `info.*`,
`servers[].url`, example values, `default` literals (only "has default" as a bool), vendor extensions
(`x-*`), schema component names.

---

## 2. Normalisation: stripping vendor identity

Applied in E4, to the profile. The order is fixed; each rule has a deterministic seed derived from
(master seed, template-id) so a given template always maps to the same neutral names.

### 2.1 Paths and hosts

| Item | Rule |
|---|---|
| Endpoint path | Keep the **skeleton**: segment count, which segments are `{param}`, each literal segment's *shape class* (length bucket; lower/kebab/snake/camel; has extension; is a version marker `vN`). Replace each literal segment with a word from a **neutral lexicon** (§2.4) of that shape class. `GET /repos/{owner}/{repo}/issues` therefore becomes something like `/w1/{p1}/{p2}/w2`, never the original words. |
| Version prefix | `/v1`, `/v2022-01-01` etc. → normalised to a generic `vN` form. |
| Path params | Re-typed by their schema: int id, uuid, slug, hex digest, ISO date, percent-encoded string (§3.3). Parameter *names* follow §2.2. |
| Hostname (Host header, `servers`, URL values) | Never copied. Use **reserved names**: FACT, RFC 2606 (<https://www.rfc-editor.org/rfc/rfc2606.html>) reserves `.test`, `.example`, `.invalid`, `.localhost` and `example.com/.net/.org`. Draw synthetic subdomain labels under `.example`, `.test`, `example.com/.net/.org`. The *same* host family is used for benign and attack rows (§7, R3). |
| Ports, schemes | Drawn from a small realistic set; both `http` and `https` (B §4.2 item 5, F5). |
| Auth headers | No credential-shaped values. If an auth header is rendered at all, it is a synthetic opaque token of random length, **identical in distribution for both classes**. (B §2.2 noted credential-shaped placeholders in GitHub examples; none are used.) |

### 2.2 Field names: three tiers

1. **Generic allowlist (kept).** A name is kept only if it passes both: (a) it appears in at least
   K=5 distinct *providers or Azure service directories* of the pinned corpus (document
   frequency, computed once and frozen with the lexicon); (b) it does not match the vendor denylist
   (§2.4). Typical survivors: `name`, `email`, `id`, `title`, `description`, `url`, `limit`,
   `page`, `status`, `type`, `callback_url`. K is OWNER-tunable; the point is that a name common
   across vendors identifies no vendor. (HYPOTHESIS: K=5 is enough; verify with the shortcut gate.)
2. **Vendor-specific (neutralised).** Any other name is replaced by a neutral-lexicon word, keeping
   *casing style* and *word count* (`html_url` → two-word snake_case neutral name). The mapping is
   consistent **inside** a template and different across templates.
3. **Structural names that matter semantically (kept as slot class, not as name).** The slot class
   (§3.1) is decided *before* renaming, from the original name plus schema; after renaming, the
   class survives as a profile attribute so a neutral-named field can still receive an email-shaped
   value. HYPOTHESIS: the model should learn shape of the *value*, so some neutral-named fields
   holding emails or URLs is desirable and mirrors real apps with idiosyncratic names.

### 2.3 Enums, defaults and examples

- Enum literals: replaced by synthetic literals of the same cardinality, length class and casing
  style. Universal families (`true/false`, `asc/desc`, `json/xml`, `ASC/DESC`) are on an explicit
  allowlist and kept.
- `default`, `example`, `examples`, `x-ms-examples`: **never rendered.** They are used for exactly
  two things: (a) as input to the **no-copy denylist** (below) and (b) the "has default/example"
  bit.
- **No-copy filter (post-render, mandatory).** Build a hash set of every example/enum/default
  string (length ≥ 4) and every identifier word in the specs. Reject a rendered row if any string
  leaf equals one, or shares a character 5-gram window with one beyond a threshold (OWNER).
  This removes `octocat`/`rg1`/`subid`-class placeholders (B §2.2 INFERENCE: reverse-shortcut risk).

### 2.4 Lexicons (frozen, versioned, hashed)

- **Neutral lexicon**: a list of common English words and short pseudo-words, *disjoint* from the
  vendor denylist, bucketed by shape class. Source is OWNER (e.g. a word list with a permissive
  licence; not derived from the specs).
- **Vendor denylist**: tokens harvested automatically from `info.title`, `servers[].url` host
  labels, the spec file/dir name, `operationId` words, component schema names, `x-*` keys, and the
  provider name. Plus a hand list (github, stripe, azure, octocat, ARM, ...). Used as a final
  **vendor-token scan**: any generated row whose tokens intersect the denylist is dropped and
  counted (a non-zero drop count is expected and reported, not hidden).

---

## 3. Synthetic values (shape-preserving, not copied)

### 3.1 Slot class selection (priority order)

1. `enum` → synthetic enum literal (§2.3).
2. `format` / `pattern` → the matching generator.
3. Generic name lexicon match (from the pre-rename name): email, password, url/callback/webhook/
   redirect, name, title, description/comment/message/body/text, query/search/q, path/filename, id.
4. Type fallback: string → free text; integer/number/boolean as in §1.2.

Schema validity is kept (B §4.2 item 4): every benign row is validated against its schema
(`jsonschema`/`openapi-core`) *before* neutralisation of enums, then re-validated structurally after;
failures are dropped. Fuzzer-style invalid inputs are out of the benign class.

### 3.2 Per-slot recipes

Value *pools* (names, free text, URLs) come from the independent corpora already evaluated in B §3
and §4.2 item 5 (Wikidata labels, NQ if the share-alike licence is accepted, NIST-style password
rules). This note adds the **composition rules** so shape is realistic. Rates below are
**HYPOTHESIS priors** chosen for *coverage*, not fit to any real sample (§7, R8); the owner should
set them wide.

| Slot class | Recipe | Punctuation coverage target |
|---|---|---|
| Human name | Recombine first/last from the name pool (never a real full-name pair, B §3). | `'` (e.g. O'Neil), `-`, `.`, space, non-ASCII letters, `&` for organisation names: each present at a **non-zero floor** (e.g. ≥ 2–5% of name leaves) |
| Free text / description / comment | Sentences from the free-text pool, 1–3 sentences, with punctuation inserted: `, . ! ? ' " ; : ( ) -`, occasional `#` (hashtag, issue ref, "No. #3"), `&`, emoji rarely. Function words kept (the `the`/`please` lesson in B). | each marker ≥ floor; `#` and `'` explicitly present (V4 minimal-pair probe found them STRONG) |
| Search query | Short lowercase-or-mixed query from the NQ-like pool, sometimes with `"quoted phrase"`, `+`, `-term`, `OR`. | quotes, `+`, `-` |
| Password | **NIST SP 800-63B §3.1.1.2** (B §3): all printing ASCII plus space accepted. Two modes at ~50/50: (a) random mixed 12–32 chars drawn from the full printing-ASCII set so `' ; # ! " & < > \` appear naturally; (b) passphrase of 3–5 words + digit + symbol. Never breached-password corpora. | whole printing-ASCII set |
| Email | local part from name pool (`.`, `+tag`, `_`, digits), domain from reserved names (§2.1). | `+`, `.` |
| URL / callback / webhook / redirect | scheme `http` or `https`; host under reserved names with 1–3 labels; optional port; 0–4 path segments; optional percent-encoded segment; optional query (`k=v&k2=v2`, one value percent-encoded); optional fragment `#section`. **Never** loopback, private ranges, link-local, metadata endpoints or `file:`/`gopher:` schemes in the benign class (F5); those belong to attack counterparts. | `#`, `%XX`, `?`, `&`, `=`, `:` |
| File path / filename | relative paths with extension, 1–3 segments; spaces and `%20`; no `..` in benign. | `.` `/` `%` |
| Path-parameter value | typed by schema (§2.1). For string params, 30–50% plain slugs, rest percent-encoded per RFC 3986 (space → `%20`, `/` → `%2F` inside one segment, UTF-8 multi-byte → `%C3%A9`). **Single-encoded only** in benign. | `%XX` |
| Id / uuid / hex / digits | generator by `pattern`/length class. | none |
| Integer / number | log-uniform within `minimum`/`maximum`, or magnitude bucket 0..10^9; floats 1–4 decimals; occasional negatives only if the schema allows. | none |
| Boolean / null | §1.2 | none |
| Date-time | ISO-8601 within a plausible window, with `Z` or `+hh:mm`. | `:` `+` `-` |
| Enum | uniform over the synthetic literals. | none |

**Anti-copy rules**: (a) draw from pools, not spec text; (b) the no-copy filter (§2.3); (c) each
generated string leaf is stored with a **value-draw id** (pool, entry hash, recipe) so the split step
(§5.2) can keep the same draw out of two splits.

### 3.3 Rendering

Render the skeleton exactly as the spec says: JSON body key order = template order; form bodies with
bracket nesting for `deepObject`/Stripe-style fields; multipart only when the spec says so; query
serialisation per `style`/`explode`; percent-encoding per RFC 3986. Body size follows the leaf
count and string-length buckets; `Content-Length` is computed, not drawn (the V4 probe found it has no
effect; keep it consistent so it cannot become a label shortcut).

---

## 4. Grouping: how requests become families

A **row** has: `spec_id`, `provider_family`, `template_id`, `family_id`, `value_draw_ids`,
`attack_twin_id` (the paired class from B §4.2 item 2).

### 4.1 Three nested keys

1. **`provider_family`**: the source API (GitHub, Stripe, ...). For Azure, one family for the final
   test purposes, but service directories (317, B §2.2) are recorded as `sub_family` for train/val
   grouping and for per-provider caps.
2. **`template_id`**: SHA-256 of the *canonical structural form* of the neutral template: method,
   content type, path skeleton (param positions), body tree with types, optionality, enum cardinality,
   depth — **names excluded** (they were already neutralised and differ arbitrarily).
3. **`family_id`**: connected component of templates under "same `template_id` **or** typed-leaf-path
   multiset Jaccard ≥ 0.8 (OWNER-tunable)". Union-find; deterministic. Near-duplicate shapes
   (create-issue vs create-ticket) therefore fall in one family.

A benign row and its attack twin share `template_id`, `family_id`, `provider_family` and split
**by construction**. Attack rows differ from the benign twin in one field's value only (B §4.2).

### 4.2 Caps

To stop mega-providers (Azure) and repetitive templates from dominating: cap templates per
`sub_family`, and renders per template (e.g. ≤ 20 renders, drawn over distinct value-draws). Caps are
applied *before* the split and logged in the manifest.

---

## 5. Split strategy: no structural template in both train and test

### 5.1 Procedure (4 steps)

1. **Assign providers to splits, pre-registered.** Choose by a seeded hash of `provider_family`
   *before* looking at any model result, e.g. one family to TEST, one to VAL, the rest to TRAIN
   (B §4.2 item 3, "leave-provider-out"). Write the assignment into the manifest first.
2. **Purge by structure.** For every `family_id` that contains a template from a VAL/TEST provider,
   remove the *entire* `family_id` from TRAIN (test priority; VAL purges TRAIN too). This is what
   guarantees "no structural template in both": equal `template_id` and Jaccard-near-duplicates
   cannot straddle the boundary even when two vendors have a same-shaped endpoint.
3. **Value-draw disjointness.** Partition each value pool by `hash(entry) mod 3` (or by seed range
   for procedural generators) so no pool entry or generator seed appears in two splits. The
   no-copy filter is applied once more across splits.
4. **Verify.** Assert in a read-only check: (a) empty intersection of `template_id`, `family_id`,
   `provider_family` and `value_draw_id` across splits; (b) report the number of rows purged and the
   residual class balance per split.

Library note (FACT): scikit-learn's `GroupKFold` "ensures that the same group is not represented in
both testing and training sets", and `StratifiedGroupKFold`/`GroupShuffleSplit` hold out whole groups
(<https://scikit-learn.org/stable/modules/cross_validation.html>). Use `family_id` as the group for
any CV inside TRAIN; the provider-level holdout is the outer split.

### 5.2 Primitive shapes (OWNER decision)

Templates with ≤ 2 leaves, depth 1 and no nested/array body (e.g. `{name: string}`, a single query
parameter) exist in every real app. Purging them would strip train of the commonest real shapes.
Proposal: mark them **primitive**; they may appear on both sides but carry disjoint value draws and
are capped per split. HYPOTHESIS: they carry no application identity. If the shortcut gate (§9) fails
on them, drop the exception.

### 5.3 Honest limit

With only three MIT sources the outer holdout is one or two *families*. A single held-out vendor is a
weak estimate of "unseen schemas". Mitigation is phase 2 (more providers) and reporting a
per-`sub_family` diagnostic, not a claim.

---

## 6. Attribution and licence handling

| Source | Licence (B §2.1, FACT) | What to carry |
|---|---|---|
| GitHub rest-api-description | MIT | Copyright notice and MIT permission notice in a `THIRD_PARTY_NOTICES` file shipped with the dataset and the generator; source URL and commit SHA |
| stripe/openapi | MIT | Same |
| Azure/azure-rest-api-specs | MIT | Same |
| Apache-2.0 specs (AWS, Twilio, via upstream) | Apache-2.0 | FACT (<https://www.apache.org/licenses/LICENSE-2.0> §4): give recipients a copy of the licence, keep copyright/patent/trademark notices, mark modified files, carry any `NOTICE` text. Phase 2 only. |
| Google specs (CC BY 3.0 via APIs.guru) | CC BY 3.0 | FACT (<https://creativecommons.org/licenses/by/3.0/legalcode> §4): keep copyright notices, give attribution, and clearly identify that changes were made. Phase 2 only. |
| APIs.guru aggregate | CC0 for the repo; origin terms for each spec; "Fair use" for some (B §2.1) | **Do not use** unless the per-spec `info.license` is verified; prefer upstream |

Notes:
- **HYPOTHESIS / OWNER / legal**: the generated rows contain no spec text (only neutral words and
  synthetic values), so they are plausibly not a copy of "a substantial portion". Attribution is
  still carried because the *structure profile* is a derivative of the specs. The safe, cheap choice
  is to ship the notices regardless. This is not legal advice.
- Per-row `spec_id` and the pinned SHA are internal provenance, **not** model features (§7, R2).
- `THIRD_PARTY_NOTICES` must be regenerated when a source is added; the manifest hash covers it.
- The pools (Wikidata CC0, NQ CC BY-SA 3.0) have their own conditions (B §3); NQ share-alike is an
  OWNER decision already flagged there.

---

## 7. Leakage and overfitting risks, with mitigations

| # | Risk | Mitigation here | Residual |
|---|---|---|---|
| R1 | **Vendor words leak** (path words, field names, enum literals, hosts, description fragments) so the model memorises "this is a GitHub/Stripe request". | Profile records no literals (§1.2); neutral lexicon for paths/names/enums (§2); reserved hostnames; vendor denylist scan + 5-gram no-copy filter on every row (§2.3–2.4). | Generic names kept by tier 1 can still be vendor-flavoured; a frequency threshold K is a heuristic. Medium. |
| R2 | **Structural fingerprint** per app: same-shaped template in train and test, or `spec_id` used as a feature. | `template_id`/`family_id` + provider holdout + purge (§4–5); `spec_id`, `provider_family` kept out of model inputs. | Fuzzy near-duplicates under the Jaccard threshold. Medium. |
| R3 | **Benign/attack envelope asymmetry**: attacks rendered differently from benign (different host, headers, order, length), so envelope predicts label. | Attack twin = same template, same renderer, same envelope, one leaf changed (B §4.2 item 2). Shared host family and shared auth-token distribution (§2.1). Pre-registered shortcut gate: a probe using only (method, path skeleton, key names, content type, body length) must be ≈ chance on grouped validation. | Depends on the attack side, which this note does not define. |
| R4 | **Generator fingerprint**: all benign rows come from the same synthetic renderer, so "looks synthetic" = benign. | Attack values drawn by the same renderer and pools, not a separate attack corpus; independent real data kept for eval only (B §1.7); report marker-distribution distances (B §4.2 item 6) without tuning to them. | The strongest residual: nobody has shown that synthetic values match real distributions (B §4.1: literature does not test distributional realism). |
| R5 | **Spec-example placeholders** (`octocat`, `rg1`, `subid`) become shortcut tokens. | Examples never rendered; no-copy filter; denylist (§2.3). | Low. |
| R6 | **Slot-specific punctuation** (e.g. `'` only in name slots, `#` only in URL slots) teaches location→label shortcuts. | Punctuation floors apply across *all* free-string slot classes, not only the "natural" one; attack twins use the same slot placements (§3.2). | HYPOTHESIS; check with the minimal-pair suite, read-only. |
| R7 | **Spec bias**: specs describe API-style JSON/form traffic, not browser HTML forms, long GET query strings or cookies; GET operations have no body (B §2.2). | Report coverage honestly; use OpenAPI as one structural source, together with other benign sources in B §3. Do not claim whole-distribution realism. | High, by nature of the source. |
| R8 | **Rates tuned to a real sample** (would be training on the eval set). | Rates are wide, fixed priors; comparison to the real sample is read-only reporting (B §4.2 item 6). | Owner discipline. |
| R9 | **Optional-field and cardinality realism**: spec maxima/optionals do not equal real usage. | Beta prior over inclusion, geometric array lengths, caps per template. | HYPOTHESIS, unverified. |
| R10 | **Few providers**: the outer holdout is 1–2 families (§5.3). | Pre-registered assignment; per-`sub_family` diagnostic; phase 2 adds Apache-2.0/CC BY providers. | High until more providers are added. |
| R11 | **Licence/attribution** failure. | §6. | Legal reading is OWNER. |

---

## 8. Reproducibility: what to pin

| Item | Pin |
|---|---|
| Spec inputs | Repo URL + **commit SHA** per source (B §2.1 lists `734bc9c1`, `0082e0c9`, `497a43f4` at 2026-10-06) + SHA-256 of every spec file actually read. Never "latest". |
| Lexicons | SHA-256 of the neutral lexicon, vendor denylist, generic-name allowlist (with its K and corpus SHA), password-rule file, pool snapshots (Wikidata dump date, NQ version). |
| Extraction | **Git blob SHA and SHA-256 of the extraction script**, and of the renderer; the dependency lockfile (YAML/JSON-Schema/openapi-core versions) and Python version. |
| Seeds | One **master seed**; derived per-stage/per-template seeds as `hash(master, stage, spec_id, operation key)`, so adding or removing a spec does **not** reshuffle the others. Provider→split assignment seed pinned and written to the manifest *before* generation. |
| Thresholds | K (name frequency), Jaccard cutoff, caps, punctuation floors, Beta prior, no-copy n-gram threshold: all in one config file whose hash is recorded. |
| Outputs | SHA-256 of the profile table, template table, row file(s), split manifest, and `THIRD_PARTY_NOTICES`. |
| Per-row provenance | `spec_id`, `operationId` (internal only), field path, `template_id`, `family_id`, value-draw ids, generator version. |
| Determinism check | Run twice; the byte-identical output hash is a precondition for freezing. Dropped-row counts (denylist, no-copy, schema failures, purge) are part of the manifest. |

---

## 9. Gates before the dataset is used (pre-registered, read-only)

1. **Shortcut gate** (B §4.2 item 2): probe on envelope + names only; AUC CI must cover 0.5 on
   grouped validation. Fail → fix R3/R6, do not tune the model.
2. **Leak assertions** (§5.1 step 4): zero intersections of template, family, provider, value-draw.
3. **Identity scan**: vendor-token scan and no-copy filter drop counts reported; zero hits in the
   shipped rows.
4. **Distribution report** (not a target): marker distributions of generated benign vs an
   independent real sample, plus the corpus-level structure summary (§1.2) vs the specs.
5. **Minimal-pair suite and #57/#60** as read-only diagnostics; External v2 for claims.

---

## 10. Open items (OWNER)

- Provider assignment to TRAIN/VAL/TEST (and whether Azure is one family or many).
- K, Jaccard cutoff, caps, punctuation floors; whether primitive shapes are exempt (§5.2).
- Neutral lexicon source; NQ share-alike acceptance.
- Whether and when to add Apache-2.0 / CC BY providers (phase 2) and verify APIs.guru per-spec
  licences (B §2.1).
- Legal read of the attribution approach in §6 (UNVERIFIED, not legal advice).

## Sources cited (fetched this session)

- OpenAPI Specification 3.1.0: <https://spec.openapis.org/oas/v3.1.0.html>
- RFC 2606 (reserved DNS names): <https://www.rfc-editor.org/rfc/rfc2606.html>
- Apache License 2.0: <https://www.apache.org/licenses/LICENSE-2.0>
- CC BY 3.0 legal code: <https://creativecommons.org/licenses/by/3.0/legalcode>
- scikit-learn cross-validation (group splitters): <https://scikit-learn.org/stable/modules/cross_validation.html>
- All other facts (spec counts, licences, literature, NIST 800-63B, Wikidata, NQ): `B_datasets.md` §2–4,
  which cites its own primary sources.
