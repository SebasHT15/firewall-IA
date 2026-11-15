# B2 — Benign-traffic sources: follow-up on open questions (research notes v2)

Date: 2026-10-06. **RECOMMENDATIONS ONLY, not decisions.** It advances `B_datasets.md` and does not
repeat it. Nothing in the repo was changed except this file. No dataset was downloaded or integrated and no
model was run. No dataset is proposed for integration now; this note only answers what the V5 Data
Spec needs to state.

Labels: **FACT** = read in a primary source in this session (URL given).
**CORRELATION** = two facts that co-occur; no causal claim.
**HYPOTHESIS** = proposal or reasoning, untested here.
**UNVERIFIED** = not confirmed.
Numbers marked "(B)" are carried from `B_datasets.md` (measured there, not re-measured here).

---

## 1. Licence and provenance of the three structural sources

| Source | Licence name (FACT) | Licence source URL | Redistribution / derived use |
|---|---|---|---|
| GitHub `rest-api-description` | MIT, copyright holder GitHub | <https://raw.githubusercontent.com/github/rest-api-description/main/LICENSE.md> | FACT: MIT grants free use, copy, modify and distribute, on condition that the copyright and licence notice are kept in copies or substantial portions (standard MIT text). Derived statistics or a vendor-neutral skeleton are within "modify/use". Whether a skeleton counts as a "substantial portion" is **UNVERIFIED (legal read)**. |
| Stripe `openapi` | The MIT License, copyright Stripe, Inc. (2011–present) | <https://raw.githubusercontent.com/stripe/openapi/master/LICENSE> | Same MIT terms. Applies to the repo including `spec3.*` and `fixtures*`. |
| APIs.guru `openapi-directory` | Mixed. Repo README: contributed definitions are CC0 1.0; definitions "acquired from public sources" are republished under a "Fair use principle" | <https://raw.githubusercontent.com/APIs-guru/openapi-directory/main/README.md> | **Not uniformly permitted.** Fair use is not a licence, so redistribution of acquired specs inherits each origin's terms. Per-spec `info.license` is the control. Share of specs with no declared licence: 65% of 2,529 APIs (B, from `api.apis.guru/v2/list.json`). |

Provenance facts:

- **GitHub.** Two folders: `descriptions` (OpenAPI 3.0) and `descriptions-next` (3.1), each as *bundled* and
  *dereferenced*. Bundled is the recommended form. The description is "kept up to date with the description
  used to validate GitHub API requests" (FACT). Vendor-specific concepts are expressed as custom extensions
  documented in `extensions.md`. Source: <https://github.com/github/rest-api-description>.
  The "no traditional code examples" statement on that page differs from the B measurement that all 350 body
  operations carry inline media-type examples (B). I do not reconcile this here: the README probably means
  language code samples, not JSON examples. **UNVERIFIED reading.**
- **Stripe.** `spec3.{json,yaml}` (public) and `spec3.sdk.{json,yaml}` (with "special annotations, deprecated
  endpoints, and pre-release features"). Directories `/latest/`, `/preview/` and a legacy `/openapi/` that is
  v1-only. Vendor extensions: `x-expandableFields`, `x-expansionResources`, `x-resourceId`. Fixtures:
  `openapi/fixtures{2,3}.*` (response resources). Source: <https://github.com/stripe/openapi>.
  Note: B pinned the legacy `/openapi/` layout; the README now recommends `/latest/`. The two may differ
  (v1 only vs v1+v2). **The Data Spec must name one directory and file.**
- **APIs.guru.** The `x-origin` property records the origin URL of each definition (README, URL above), so
  per-spec provenance is machine-readable. B found 688 invalid specs and "fixedPct 23" (B), so specs may be
  modified copies of upstream.
- **OpenAPI format itself.** The OpenAPI Specification v3.1.0 text is licensed Apache-2.0
  (FACT, <https://spec.openapis.org/oas/v3.1.0.html>). Parsing the *format* needs no further licence.

**Gaps that stay UNVERIFIED (not closable from public pages):**

- MIT covers copyright only. **Trademark and brand names are not licensed** by MIT (general legal knowledge,
  not verified against a source here). This reinforces the vendor-neutralisation in §3: the shipped
  artefact should not carry vendor names or marks.
- Whether the *API's own terms of service* restrict derived use of the spec. Not checked for GitHub or Stripe.
- Whether a statistical skeleton is a derivative work. Needs a legal read.

**Verdicts for the Data Spec:**

| Source | Verdict | Condition |
|---|---|---|
| GitHub | Licence-clear for structural use | keep MIT notice in the provenance manifest; pin file and SHA |
| Stripe | Licence-clear for structural use | same; pin `latest` vs legacy |
| APIs.guru | **Per-spec only** | admit a spec only if its upstream licence is permissive and recorded; prefer the upstream repo over the APIs.guru copy |

---

## 2. open-appsec legitimate requests: EVAL-ONLY status

**Conclusion unchanged: EVAL-ONLY** (B §1.7, B verdict #1). Not reopened. Reasons, each with its source:

1. It is a **public, vendor-scored FPR benchmark**, updated annually. Using it for training would make later
   comparisons on it non-independent (FACT: B §1.6, `report/waf_results_2025_2026.json`;
   <https://docs.openappsec.io/references/waf-comparison-project> describes the dataset as the basis of the
   precision/false-positive measurement and does not mention training use).
2. It is the only large, real-browser, permissively licensed benign corpus, so its highest value is as the
   **benign side of External v2** (INFERENCE, B §1.6).
3. Documented privacy gap: neither the README nor the docs page states any anonymisation, and the data
   contains credential-shaped strings and e-mail-shaped values (B §1.4/§1.5; README fetch re-confirmed
   "no anonymisation statement": <https://raw.githubusercontent.com/openappsec/waf-comparison-project/main/README.md>).
4. Licence text re-confirmed: the README states the Legitimate Requests Dataset is under Apache 2.0 (same
   URL). That grants copyright permission but does not resolve the personal-data question (B §1.2, UNVERIFIED).

New observation (FACT, same README fetch): the README says "1,040,242 requests from 185 real websites across 12
categories", while the docs page says "692 real websites in 14 categories". This repeats the inconsistency
already in B §1.1; the site count must not be quoted in the Data Spec.

---

## 3. Schema-extraction feasibility without vendor memorisation

**Short answer: feasible for the structure; not free of residual fingerprints.** HYPOTHESIS, backed by the
format facts below. It was not prototyped in this session.

### 3.1 What OpenAPI exposes (FACT, <https://spec.openapis.org/oas/v3.1.0.html>)

- The Schema Object is a superset of JSON Schema 2020-12: `type`, `format`, `enum`, `required`, `properties`,
  `pattern`, `minimum`, `allOf/oneOf/anyOf`. So types, enums, required/optional, nesting and value shapes are
  declared, not inferred.
- For `application/x-www-form-urlencoded`, the Encoding Object (`style`, `explode`) controls how
  objects and arrays are serialised. Query parameters default to `style=form`, `explode=true`. So the
  **wire serialisation is separable from the schema**.
- Example objects exist (`value` / `externalValue`) but are optional. B measured them: GitHub 350/350 body
  operations, Stripe 0, APIs.guru 22.8% of specs (B).

### 3.2 Vendor-neutralisation approach (proposal)

Extract a **skeleton** per (operation, content type), then discard identity. A neutral skeleton keeps:

| Keep (structure) | Drop or replace (identity) |
|---|---|
| JSON type per node; `format` as a *class* (date-time, uri, email, uuid, int32…) | host, `servers`, base path, path literals (path **shape** kept: segment count, parameter positions) |
| depth, fan-out, array cardinality (`minItems`/`maxItems`), nullable | `operationId`, `summary`, `description`, tags, `externalDocs` |
| `required` vs optional ratio per object | all `x-*` vendor extensions (`x-github`, `x-expansionResources`, `x-resourceId`, …) |
| enum **arity** and value-shape class (e.g. "short lowercase token", "numeric string") | enum literals, `example`/`examples` literals, default literals |
| numeric ranges, string length bounds, `pattern` as a character-class profile | vendor tokens inside patterns (e.g. object-id prefixes) |
| parameter location (path/query/header/cookie/body) | header names that are vendor-specific |

Key-name handling is the hard part (HYPOTHESIS):

- Property names carry real benign semantics (`email`, `page`, `limit`) and also vendor identity
  (`octocat`-style tokens, vendor object names).
- Proposed rule, **cross-provider support threshold**: keep a name only if it occurs in at least *K*
  independent providers (K to be fixed and pre-registered). Rarer names are mapped to a role token drawn from
  a neutral lexicon, matched by type and format (a K-anonymity idea applied across providers). The mapping is
  deterministic given a seed and recorded in the manifest.
- Why name handling matters: the B §4.2 shortcut gate (a probe on method, path template, key names, content
  type that must be at chance) is the test that decides whether neutralisation was enough.

### 3.3 Residual risks (CORRELATION and HYPOTHESIS, not measured here)

- **Serialisation style is a vendor fingerprint.** B: 611 of 626 Stripe body operations are
  form-urlencoded with bracket nesting, while GitHub is JSON (348 of 350). CORRELATION: provider and
  content type are almost one-to-one in these two sources. If attack rows are rendered in a different style
  than benign rows, the style becomes a label shortcut. HYPOTHESIS: render each skeleton in every
  serialisation the schema legally allows, in **both** classes, and record style as a nuisance variable.
- **Skeleton shape can still identify a provider** (a distinctive nesting profile). The leave-provider-out
  split and the shortcut gate are the controls, not the neutraliser alone.
- **Only two strong providers.** GitHub and Stripe are two groups. Leave-provider-out with two groups
  is degenerate for validation plus test. Diversity then depends on APIs.guru, which has the per-spec
  licence problem (§1) and, per B, AWS/Google specs with zero examples and a 48% Azure/Google/AWS share.
  This is the single biggest risk (see end).
- **Spec fidelity.** A cited study of ten REST testing tools on 20 services reports spec/implementation
  mismatches (Kim, Xin, Sinha & Orso, ISSTA 2022, doi:10.1145/3533767.3534401, as cited in B §4.1). A
  skeleton describes what the spec says, not what real clients send.
- **Values are not extracted.** Realistic values come from separate pools (B §4.2 step 5). This note does not
  change that.

---

## 4. Grouping and anti-leakage strategy for splits

Why: when samples have a group structure, a random row split lets the model learn group-specific patterns;
scikit-learn's documentation names this leakage and provides `GroupKFold`, `StratifiedGroupKFold`,
`LeaveOneGroupOut` and `GroupShuffleSplit` (FACT,
<https://scikit-learn.org/stable/modules/cross_validation.html>). Leakage is a documented, field-wide cause of
inflated results (Kapoor & Narayanan, *Patterns* 2023: 17 fields, 294 papers, eight leakage types; FACT,
<https://pmc.ncbi.nlm.nih.gov/articles/PMC10499856>). Near-duplicates between train and test are common:
Lee et al. report train/test overlap affecting over 4% of the validation set of standard datasets (ACL 2022,
FACT, <https://aclanthology.org/2022.acl-long.577>). B §1.6 shows the same risk in the ModSec-Learn split
(random row split, 15.9% exact duplicates; B).

Proposal (HYPOTHESIS, for owner review). Every row gets four keys, and a split assignment is made **once, at the
coarsest key**:

| Key | Definition | Rule |
|---|---|---|
| `provider_group` | normalised API provider (eTLD+1 of the origin or the upstream repo) | Whole providers go to one split only. Split by provider first (B §4.2 step 3). |
| `skeleton_family` | hash of the neutral skeleton (§3.2), before values | All renderings, serialisations and values of one skeleton stay in one split. |
| `pair_id` | the benign row and its attack counterparts built from the same structure (F7 in B) | Pairs never split. A split pair lets a model learn the envelope by seeing one side. |
| `value_draw_id` | draw from a value pool (name list, query corpus) | The same pool element may not appear on both sides if it is a dominant token (`octocat`, `rg1`). Either remove or place it in attack counterparts too (B §4.2 step 5). |

Required leakage audit before freezing (each must pass; counts reported, never values):

1. Intersection of `provider_group`, of `skeleton_family` and of `pair_id` across splits = 0.
2. Exact-duplicate intersection by request hash = 0, and **template-hash** intersection = 0 (hash after
   replacing values with class tokens; this catches near-duplicates that an exact hash misses).
3. Shortcut gate: a probe on structure only (method, path template, key names, content type, serialisation
   style) is at chance on grouped validation (B §4.2 step 2). Add the serialisation style to its features.
4. Group-identity probe: a probe that predicts `provider_group` from the benign skeleton should be reported
   as a fingerprint measure; high accuracy means neutralisation failed.
5. Real-traffic side: sites in any real-traffic partition (open-appsec for External v2) are separate and are
   never mixed into generated families. A leakage between generated benign and the frozen eval partition
   is checked by template hash (item 2).
6. Value-source realism checks use the frozen eval partition for **distances only** (B §4.2 step 6).

---

## 5. Reproducibility pins for the future generator

HYPOTHESIS (a checklist). Each item is recorded in one hashed manifest; a rebuild must be bit-identical.

| Pin | What exactly | Note |
|---|---|---|
| Spec source commit | **Full 40-character SHA**, not a branch or a short SHA | B recorded short SHAs on 2026-10-06: GitHub `734bc9c1`, Stripe `0082e0c9`, Azure `497a43f4`. These are *not* the full SHAs. Expand them. APIs.guru in B has only a `pushed_at` date, which is **not** a pin; take a commit SHA. |
| Exact file path | GitHub: `descriptions` (3.0) or `descriptions-next` (3.1), bundled or dereferenced. Stripe: `/latest/spec3.json`, `/preview/`, or legacy `/openapi/`, and public vs `spec3.sdk` | These variants differ in content (sources: the two READMEs above). Also pin each file's SHA-256. |
| Per-spec licence record | `info.license` and `x-origin` for every admitted APIs.guru spec, plus the date checked | The 65%-no-licence rate (B) means a missing field must exclude, not default-admit. |
| Neutralisation inputs | the neutral lexicon, the K threshold, the role-token mapping, the seed | Part of the extraction script's inputs. |
| Extraction script | git commit SHA **and** SHA-256 of the file, plus the entry-point arguments | The B protocol (§4.2 step 1) already requires generator version and seeds. |
| Environment | Python version, lockfile with hashes for the parser and validator libraries (jsonschema / openapi-core), OS image | A library update can change which rows validate. |
| Value pools | version and date of each corpus (Wikidata dump date, NQ version, NIST text revision), plus the pool SHA-256 | Wikidata is CC0 (<https://www.wikidata.org/wiki/Wikidata:Licensing>, B). NQ is CC BY-SA 3.0 (B). |
| Generation | master seed and per-family seeds; row counts per (provider, class) | Per-row provenance: `spec_id`, `operationId` (internal only), field path, `value_draw_id`. |
| Split assignment | the group keys of §4 and the function that maps group to split, frozen before any model training | Follow the External v1 freezing discipline (B §1.7). |
| Output | SHA-256 of every shard and of the manifest | The shipped data should not contain `operationId` or vendor names; keep that mapping in a private vault if needed. |

---

## Open questions remaining for owner

1. **Legal read:** is a vendor-neutral skeleton plus synthetic values a derivative of an MIT spec that needs
   the notice kept? Do GitHub's and Stripe's API terms of service add limits? (UNVERIFIED.)
2. **Provider diversity:** with only GitHub and Stripe as clear-licence strong sources, which further
   upstream-licensed specs will be admitted so leave-provider-out has enough groups? What minimum number
   of provider groups does the Data Spec require?
3. **Serialisation policy:** render each skeleton in every legal serialisation, or only the spec's own? This
   decides whether style stays a label shortcut.
4. **K threshold** for keeping a property name across providers, and its pre-registered value.
5. **Stripe variant:** `/latest/` or legacy `/openapi/`? **GitHub variant:** 3.0 or 3.1, bundled or
   dereferenced?
6. **open-appsec:** the site count (185 vs 692) and the operator/recording facts remain undocumented by the
   vendor. Not needed for the Data Spec while it stays EVAL-ONLY, but the freeze note for External v2 needs
   them.
7. Whether a template-hash audit (§4 item 2) is the agreed definition of "near-duplicate" for splits.
