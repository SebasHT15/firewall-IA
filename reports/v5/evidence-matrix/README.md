# V5 FP evidence matrix — benign coverage audit + minimal-pair v1 + minimal-pair v2

Date: 2026-10-06. Issue #62. Consolidates three frozen diagnostics into one matrix to drive the V5
Data Specification. **All three are DEVELOPMENT / diagnostic data.** Nothing here is an operational
false-positive rate: diagnostic flip counts on constructed benign pairs are not deployment FPR
(recall and FPR are evaluated later on appropriate datasets). Conclusions are scoped
"for this experiment", never "proved globally".

Sources: **AUDIT** = `reports/v5/benign-coverage-audit-v1/` (counts over V4-clean TRAIN groups);
**V1** = `reports/v5/minimal-pair-probe-v1/` (frozen causal probe); **V2** =
`reports/v5/minimal-pair-probe-v2/` (this session). Evidence types: COVERAGE (distributional fact),
CAUSAL (paired minimal-pair flip on frozen V4), HYPOTHESIS. Strength legend: STRONG-FTE = strong for
this experiment; SUPPORTED; INCONCLUSIVE; WEAKENED; FALSIFIED-FCP = falsified for the current probe.

## 1. Matrix

| # | Finding | Source | Evidence | Magnitude | Strength | Interpretation | V5 implication | Priority | Remaining uncertainty |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Street-address **value semantics** induce BLOCK | V2 `n_prose→n_street` 0.73; `n_numfmt→n_street` 0.70 | CAUSAL | 20–22/30 flips; street ref already BLOCK 24/30 | STRONG-FTE | A number+street-name+unit value flips benign→BLOCK regardless of field name | Add realistic street-address benign values (and attack counterparts) across fields/carriers | HIGH | exact lexical trigger within "street" (noun vs Apt vs token count) not isolated |
| 2 | Field name `address` is **not** a material driver | V2 `n_prose→a_prose` 0.10 (<C_hi, p=0.25); rename ctrl `n2_prose` 0/30 | CAUSAL | 3/30 vs control 0.175 | WEAKENED (H-A1) | The v1 "address blocks" was the value, not the token `address` | Do **not** special-case field names; model value content | HIGH | name may add a little atop a street value (`n_street→a_street` untestable) |
| 3 | Digits/number-format alone do **not** block | V2 `n_prose→n_numfmt` 0.23 (<C_hi, p=0.45) | CAUSAL | 5/30 | WEAKENED (H-A3) | `Bay 54 Shelf 32` (caps+2 numbers) ≈ benign noise | Numeric/structured benign values are fine; the street combination matters | MEDIUM | — |
| 4 | `#` sensitivity is **not `#`-specific** | V2 `base→hash` 0.55 ≈ `base→punct`(`!`) 0.53; `punct→hash` null | CAUSAL | 32/60 vs 32/60 | STRONG-FTE | `#`(%23) and `!`(%21) flip equally in form/query | Treat as a **class** (encoded punctuation), not a `#` rule | HIGH | — |
| 5 | Legitimate apostrophe effect is **not surname/name-bound** | V2 `plain→apostrophe` heterogeneous: surname .93, contraction .60, title .53, possessive .40 (all %27); place_json(literal ') .00 | CAUSAL | 37/75; 4/5 classes effect | FALSIFIED-FCP (name-semantics) | `%27` apostrophe flips across name **and** non-name text | Cover legitimate apostrophes in names, contractions, possessives, titles | HIGH | literal `'` (JSON) null is carrier-confounded |
| 6 | V4 over-blocks **percent-encoded punctuation** (`%27`,`%23`,`%21`) from ordinary encoding | V2 (#4,#5 converge) + AUDIT (%27=19,%21=19,%23=0 benign vs 1906/416/624 attack) | CAUSAL + COVERAGE → HYPOTHESIS (mechanism) | strong form/query flips; near-absent in benign TRAIN | SUPPORTED (as coverage-driven); HYPOTHESIS (as "%"-triplet mechanism) | Benign TRAIN almost never shows legitimate `%27/%23/%21`, so V4 reads them as attack-like | **Central V5 family**: legitimate punctuation that percent-encodes, across many fields/carriers, with symmetric attack use | HIGH | literal-vs-encoded is carrier-confounded; exact trigger (`%` vs glyph) not isolated |
| 7 | `Transfer-Encoding: chunked` (de-chunked body) flips benign→BLOCK | V1 `F-CL:absent→te_chunked` 18/40 flip (0.45); 18/33 conditional (0.55) | CAUSAL | STRONG | STRONG-FTE | Envelope train/serve skew: TE only seen on smuggling rows in TRAIN | Add chunked framing to the **shared** benign+attack envelope; keep smuggling = conflicting framing; validate framing deterministically (not ML) | MEDIUM-HIGH | deployment frequency of chunked clients UNVERIFIED |
| 8 | `http://` vs `https://` external URL flips | V1 `F-URL:https_external→http_external` 18/30 | CAUSAL | STRONG | STRONG-FTE | benign TRAIN URLs are 203 `https`, 7 `http` (AUDIT 3.2) | Cover legitimate `http://` callbacks/webhooks; keep open-redirect shape as attack | MEDIUM | open-redirect param names (`next`/`return_url`) may legitimately warrant BLOCK |
| 9 | **JSON carrier decisions are highly unstable** to benign content | V2 CONTROL-COV2 `json` stratum 0.70 (vs handle/prose/token 0.00) | CAUSAL (control) | 7/10 flips | STRONG-FTE | V4 has essentially no multi-key / typed / stable JSON benign coverage | Build benign JSON family: multi-key, numeric/bool/null, nested, URL-valued; stabilize | HIGH | interacts with #6 (JSON strata there unreliable) |
| 10 | No multi-key / typed JSON in benign TRAIN | AUDIT 3.3 (benign JSON: top-level keys≥2 = 0; number/bool/null leaf = 0) | COVERAGE | 0 benign groups | STRONG-FTE (distributional) | explains #9 | same as #9 | HIGH | — |
| 11 | Two-field forms, SQL-homonym prose, English function words absent/scarce in benign TRAIN | AUDIT 3.2–3.3 (`and/or/from`≈0 benign; form 2-field=0) | COVERAGE | near-0 benign | SUPPORTED | benign TRAIN is lexically/structurally impoverished | Cover multi-field forms and natural English prose (incl. SQL-homonyms) as benign | MEDIUM | V1 found SQL-homonyms in prose no strong flip — lower priority |
| 12 | Benign-only **reverse shortcuts** (`the`,`please`,`https`) | AUDIT 3.2 | COVERAGE | 390/168/203 benign-skewed | SUPPORTED (risk) | synthetic generator's fixed sentences/URL pool leak class | V5 must avoid token⇒class shortcuts; diversify benign text | HIGH | — |
| 13 | V4 is deterministic (runtime) | V1 (212×4, 0 div) + V2 (59×3, 0 div) | FACT | 0 divergences | STRONG-FTE | flips are **decision-boundary sensitivity**, not runtime nondeterminism | training/serving reproducibility assumption holds | — | — |
| 14 | Benign decision-boundary **instability** exists even benign→benign | V1 CONTROL-COV 0.125 (not material); V2 CONTROL-COV2 0.175 **material**, driven by JSON 0.70 | CAUSAL (control) | 12.5% / 17.5% | SUPPORTED | different benign values alone flip some of the time; JSON worst | V5 must raise benign density/diversity to shrink this margin; report per-carrier | HIGH | the 12.5–17.5% is dataset-specific, not universal |

## 2. Conclusions by strength

**STRONG FOR THIS EXPERIMENT** (robust within the probe, beat control and matched ~0 non-JSON baseline):
street-address value semantics (#1); `#`-non-specificity, i.e. `#`≈`!` encoded (#4); apostrophe
generalization across `%27` classes (#5); `Transfer-Encoding: chunked` (#7); `http://`→BLOCK (#8);
JSON-carrier instability (#9); determinism (#13).

**SUPPORTED:** percent-encoded-punctuation over-blocking as a coverage-driven effect (#6, mechanism is
hypothesis); typed/multi-key JSON absence (#10); impoverished benign lexicon/structure (#11); reverse
shortcuts (#12); benign instability margin (#14).

**WEAKENED / FALSIFIED for the current probe:** field-name `address` as a driver — WEAKENED (#2);
digits/format alone — WEAKENED (#3); apostrophe effect as **surname/name-semantic** — **FALSIFIED**
(#5, it generalizes to non-name contexts).

**INCONCLUSIVE / carrier-confounded:** literal-`#`/`'` (JSON) vs encoded — the JSON strata are
confounded with carrier and with the material JSON instability (#9), so the "%"-triplet-vs-glyph
mechanism (#6) stays HYPOTHESIS.

## 3. Remaining unknowns (for V5 design, not blockers)

1. The exact trigger inside "street value" (street noun vs `Apt` vs token count) — not isolated; V5
   covers realistic addresses broadly rather than a single feature.
2. Whether the encoded-punctuation effect is the `%` triplet or the glyph — carrier-confounded; V5
   covers both encoded and literal forms with carrier symmetry rather than betting on the mechanism.
3. Deployment frequency of chunked clients, `http://` callbacks, multi-key JSON — operational, not
   estimable from diagnostics; informs priority, not inclusion.
4. Open-redirect parameter names where BLOCK may be correct (#8) — a labeling question for V5, not a
   pure FP.

These are design inputs, not blockers: none prevents writing a defensible V5 Data Specification.
