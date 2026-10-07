# V5 Data Specification — DRAFT (for owner review, not frozen)

Date: 2026-10-06. Issue #62. Status: **DRAFT**. This is a specification *derived from evidence*; it is
**not** a decision, **not** frozen, and the generator is **not** implemented. Nothing here trains V5,
generates a dataset, integrates an external dataset, or changes the runtime, D1, `inference_core`, or
`DECISIONS.md`. The next phase (owner-gated) is: review this spec → freeze → implement generator →
tests → generate/validate dataset → train/freeze V5.

Evidence base: `reports/v5/evidence-matrix/` (benign coverage audit + minimal-pair v1 + v2),
`reports/v5/research-notes-v2/` (datasets, OpenAPI generation, framing). Each family below is
classified **HIGH / MEDIUM / LOW / REJECT** by the evidence that supports *including* it, with the
matrix row(s) cited. "Diagnostic flip counts are not operational FPR" applies throughout.

## 1. Design principles (carried from the project, not new decisions)

1. V5 learns **concepts**, never the probe/audit texts, templates, field names, hostnames or values
   (data-isolation; the probes record `pools_sha256` for disjointness assertions).
2. **Content/semantics over carrier shortcuts** (evidence-matrix #12 reverse shortcuts): benign and
   attack must share the carrier wherever the concept allows (carrier symmetry, §4).
3. **Evidence before inclusion**: a family is included only with matrix support; speculative families
   are REJECT or LOW until evidenced.
4. **Simplicity / no over-engineering**: prefer the smallest set of families that closes the measured
   gaps; do not add families "because a source exists".
5. **Framing security is deterministic, not ML** (framing note): V5 receives a canonical application
   request (§5); it is not asked to adjudicate request-smuggling framing.

## 2. Benign family specification (concepts; classification by evidence)

| Family | Class | Evidence (matrix #) | Concept to cover (not templates) | Notes |
|---|---|---|---|---|
| **Percent-encoded punctuation** (`%27` `'`, `%23` `#`, `%21` `!`, and the same glyphs literal) | **HIGH** | #4, #5, #6, audit %27/%21/%23 absent | Legitimate `'`/`#`/`!`/`&`/`;` that ordinary form/URL encoding turns into `%XX`, across many fields | The single most important gap; treat as one class, not per-glyph |
| **Legitimate apostrophes** across contexts (names, contractions, possessives, titles, places) | **HIGH** | #5 (FALSIFIED name-only) | apostrophes are benign in name **and** non-name text | subsumed by the encoded-punctuation class but listed for coverage breadth |
| **Street addresses** (number + street + unit) | **HIGH** | #1, #2, #3 | realistic postal-address values are benign | value, not field name; vary field names so no `address`-token shortcut |
| **Realistic passwords** with non-alphanumerics | **MEDIUM-HIGH** | #6, audit (315 benign CSIC only) | passwords containing `#`,`!`,`'`,`@`, etc. | the encoded-punctuation gap manifests here |
| **Multi-key / typed JSON** (≥2 keys, number/bool/null, nested, URL-valued) | **HIGH** | #9, #10 (0 benign groups) | realistic JSON bodies of several shapes | also a **stability** target (JSON control flipped 0.70) |
| **Legitimate external URLs / callbacks / webhooks**, incl. `http://` | **MEDIUM-HIGH** | #8 | benign values that are URLs with either scheme | exclude open-redirect **parameter shapes** (`next`/`return_url`) which may legitimately BLOCK — labeling question |
| **Multi-field forms** (2+ fields) | **MEDIUM** | #11 (0 benign groups) | realistic forms with several fields | |
| **Multi-parameter queries** | **MEDIUM** | #11 | queries with 2–4 params | v1 found parameter *count* alone weak; include for coverage, not as a driver |
| **Realistic free text / English prose** | **MEDIUM** | #11, #12 | natural prose, varied (break the fixed-sentence shortcut) | |
| **Chunked framing in the shared envelope** (`Transfer-Encoding: chunked` + de-chunked body) | **MEDIUM-HIGH** | #7 | TE appears on benign **and** attack, so it is not a shortcut | depends on §5 canonicalization decision; keep smuggling = *conflicting* framing |
| **SQL/shell-homonym prose** (`select`, `union` as English) | **LOW** | #11; v1 no strong flip | benign prose using attack-keyword homonyms | v1 showed weak effect; low priority |
| **Encoded paths** (`%2F`, depth) | **LOW** | v1 no strong effect | | include minimally, not a driver |
| **Nested/array JSON as the only benign JSON** | **MEDIUM** | #10 | depth ≥ 2 benign | part of the JSON family |
| **Symmetric attack counterparts** for every family | **REQUIRED** | #6, #7, #8 + §4 | each benign concept has an attack twin sharing carrier | prevents carrier shortcuts |
| **Field-name special-casing** (e.g. treat `address`/`password` names as signals) | **REJECT** | #2 (WEAKENED) | — | names are not drivers; do not encode them |
| **Raw framing bytes as ML text** (chunk sizes, TE+CL) | **REJECT** | framing note (option A unsupported) | — | framing is validated deterministically, not modeled |

### 2.1 Priority order for the generator (from the matrix)
HIGH-priority, build first: percent-encoded punctuation; street addresses; multi-key/typed JSON (+
stability); apostrophe breadth. Then: passwords with punctuation, external `http(s)` URLs, chunked
envelope, multi-field forms/queries, free text. LOW last or omit: SQL-homonym prose, encoded paths.

## 3. Data sources (from research notes B2 / I — structure, not identity)

- **OpenAPI structural extraction** (`research-notes-v2/I_openapi_generation_proposal.md`): use
  OpenAPI specs as a source of request **structure** (types, cardinalities, nesting, enums,
  required/optional, value shapes), **never application identity**. GitHub and Stripe OpenAPI are
  **MIT** (redistribution permitted with notice); APIs.guru is per-spec (verify `info.license` /
  `x-origin` one at a time). Normalize away vendor identity (endpoint paths → structural skeletons,
  hosts → RFC 2606 reserved, vendor field names neutralized unless shared by ≥K providers, enum
  literals synthetic, spec examples never rendered). (`research-notes-v2/B2_datasets_followup.md`.)
- **open-appsec** stays **EVAL-ONLY**, not TRAIN (vendor-scored FPR benchmark, no anonymization,
  credential-like strings). Apache-2.0 covers copyright, not the personal-data question.
- **Serialisation style is a vendor fingerprint** (Stripe form-urlencoded, GitHub JSON): render each
  structural skeleton in multiple legal serialisations, in **both** classes, so style is not a
  shortcut.
- **Biggest source risk**: provider diversity — only GitHub/Stripe are confidently MIT, so
  leave-provider-out holdout is weak until more providers are licence-verified.

## 4. Carrier symmetry and anti-leakage (per family)

For every V5 family, benign and attack rows must share, when the concept allows: HTTP method, carrier
type (query / form / JSON), `Content-Type`, parameter cardinality, JSON shape, path style, and the
canonical envelope (§5). The attack twin differs only in the **malicious content**, never in a
carrier feature a classifier could exploit.

- **Grouping**: `provider_family` → structural `template_id` (names excluded from the hash) →
  `family_id` (union-find on identical/near-duplicate structure) → value draw. Each attack twin shares
  all grouping keys with its benign row.
- **Split**: leave-provider-out holdout (seeded), then purge any `family_id` touching a VAL/TEST
  provider from TRAIN; value-draw pools partitioned across splits; a read-only assertion checks empty
  intersections; a template-hash (values → class tokens) near-duplicate audit runs before freeze.
- **Reverse-shortcut guard** (matrix #12): no benign-only fixed sentences/URLs/tokens; diversify
  benign text and values so no token predicts the class.

## 5. Canonical Model Input — DRAFT (does not change D1; no implementation)

Motivated by the framing note (`research-notes-v2/framing_recommendation_note.md`): framing /
request-smuggling security should be deterministic, and training and serving must share the **same**
canonicalization. Proposed future pipeline (recommendation, **not** a decision):

```
wire request → strict deterministic HTTP framing validation (reject non-compliant; RFC 9110/9112)
             → canonical application request  → Fast Path → Analyzer → Decision Model → V5
```

**What the canonical application request should preserve for the ML text** (candidate; owner to
decide): method; origin-form path; query (as received, one encoding layer visible); the application
body **de-chunked and content-decoded** (the bytes the backend will actually interpret); the
application-relevant headers V4 already sees (envelope: Host/User-Agent/Accept/Content-Type), subject
to D44's header policy for the Analyzer.

**What should be resolved out of the ML text** (framing / hop-by-hop; validated deterministically):
`Transfer-Encoding`/chunk framing, `Content-Length`, TE+CL conflicts, duplicate/invalid CL, chunk
extensions/trailers, `Expect`, `Connection`/`Proxy-Connection`/`Keep-Alive`/`Upgrade`. These become a
**structured audit record** (not ML text): the raw framing observed, the validation verdict, and any
normalization applied — for logging and for the Decision Model's deterministic signals, never as
free-text fed to V5.

**Binding condition** (framing note, INFERENCE from RFCs + WAFFLED/CVE-2013-5705): the representation
V5 scores must be the **same bytes the backend will interpret** after validation, or inspection and
execution diverge. Therefore **training and serving must call one shared canonicalization function**.

**Open future decisions (owner):** (a) choose option B (validate + remove framing from ML input) vs C
(validate + ML sees a canonical request) — this draft assumes C; (b) specify the canonical form
exactly (what is stripped vs kept); (c) decide whether this **extends or replaces D1** for V5 (D1 is
**not** changed here); (d) where strict framing validation sits relative to the Fast Path and the
client-visible behavior for framing rejections. The chunked-envelope benign family (§2) is contingent
on (a)/(b): if V5 sees a canonical de-chunked request, the family models "TE present + de-chunked body
as the gateway renders it", exactly what v1 measured.

## 6. Stability requirement (new, from matrix #9/#14)

Beyond coverage, V5 must **reduce benign decision-boundary instability**, which the v2 control
measured at 17.5% overall and **70% on the JSON carrier**. The generator should therefore produce
**dense, diverse** benign coverage of each carrier (especially JSON), and V5 acceptance should include
a benign-stability gate (e.g. minimal-pair flip rate on held-out benign perturbations), not only
aggregate FPR. This is a spec requirement, not yet a threshold.

## 7. What this draft deliberately does NOT do

No generator, no dataset, no training, no external-dataset integration, no runtime/D1/`inference_core`
change, no `DECISIONS.md` edit, no commit. Family priorities and the canonical-input option are
**recommendations for owner review**.
