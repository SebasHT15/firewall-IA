# V4 minimal-pair probe v2 (`v5-minimal-pairs-v2`) — pre-registration protocol

Status: **PRE-REGISTRATION**. This document is frozen by SHA-256 together with the case generator,
the manifest, `cases.jsonl`, and the runner *before* any inference. After the freeze the design is
not changed in response to results. Issue: #62. Branch: `research/v5-minimal-pairs-v2`.

DEVELOPMENT DIAGNOSTIC DATA. Every case is a **benign** request, by construction. These cases, their
templates, field names, hosts, and value pools are **never** V5 training, validation, or
checkpoint-selection data. V5 may learn only the *concepts* the results demonstrate — never these
texts. The manifest records `pools_sha256` so a future V5 builder can assert disjointness.

## 0. Purpose and relation to v1

v1 (`reports/v5/minimal-pair-probe-v1/`, frozen) established strong V4 ALLOW→BLOCK effects for a
legitimate apostrophe in a surname (30/30), `#` in a password value (19/30 flip; `-`=0/30, `@`=3/30,
`!`=1/30 in the same field, so the effect is `#`-specific there), and `Transfer-Encoding: chunked`.
It also found that an "address" field carrying a street value was **already BLOCK at baseline in
26/30 bases** (`F-ADDR:plain`, `baseline_allow_rate`=0.13), so the *cause* of the address blocking
was never isolated. v2 does **not** repeat v1. It runs one small, benign-only, pre-registered
follow-up that isolates three remaining causal questions that can materially change the V5 Data
Specification:

- **A — ADDRESS**: which property of an address field/value is associated with the block — the field
  NAME, the street VALUE-SEMANTICS, or the numeric FORMAT?
- **B — `#` CONTEXT**: is `#` a general V4 sensitivity, or is there a `#` × field/context interaction?
- **C — APOSTROPHE GENERALIZATION**: does the effect belong to the apostrophe *character* or to
  surname/name *semantics*?

No attack counterparts (recall is evaluated later with appropriate datasets, §scope). One
experimental dimension changes per pair.

## 1. Data isolation (mandatory)

v2 bases are **new**. Nothing is copied from: minimal-pair v1 templates/pools, issues #57/#60,
`fwlab`, External Test v1, or the V4 eval / INTERNAL TEST sets. v2 uses a fresh fictitious domain
(a community recreation centre), fresh reserved-example hosts, and field names, value pools, and
templates that do not reuse v1's. A verification test (`tests/`) asserts the v2 case `text_sha256`
set is disjoint from v1's, and that v2's field-name/host pools do not intersect v1's. All v2 values
are freshly authored for this probe and are not drawn from any dataset.

## 2. Model, rendering, determinism (FACTS inherited, verified at run time)

- Inference is on the **frozen V4** via `control_plane/inference_core.py`, greedy decoding, exactly
  as v1. The runner verifies `adapter_model.safetensors` SHA-256 == `7bf168758a428fa7775dff0328de3d07d3063ddf99b961dc8b8406a0dce93de1` (model-output-v4-clean) and
  records `inference_core.py` SHA-256 and the full environment.
- Each case `text` is the request exactly as the gateway renders it to V4 (D1 /
  `render_request`): LF line endings, origin-form target, one `Name: value` header line, a blank
  line then body only when a body exists, no trailing newline. Query and form values are
  percent-encoded with `quote(v, safe="")` (so a literal `#`→`%23`, `'`→`%27`); **JSON** string
  bodies keep the literal character (`#`, `'`). This difference is used deliberately in B and C.
- V4 is deterministic (v1: 212 texts × 4 runs, 0 byte divergences). This is **runtime determinism**,
  distinct from **decision-boundary sensitivity** (different benign inputs flipping). A repetition
  control is still run (§6). "same-input divergence" ≠ "different-input decision flip".

## 3. Factors, levels, and comparisons (independent variables)

All factors are block `CONTENT`. A *base* is one fresh value tuple; each base is rendered at every
level of its factor; a *comparison* pairs a reference level with one other level of the same base,
differing in exactly one declared dimension. Carrier (GET query vs form body vs JSON body) is held
**constant within a base** and varied across bases for diversity, except where the carrier *is* the
context being studied (B/C JSON strata).

### F2-ADDR — ADDRESS isolation (n_bases = 30)
Carrier per base: GET query (even base index) or form body (odd), constant across that base's levels.
Levels `(field_name, value_kind)`:

| level | field name | value | role |
|---|---|---|---|
| `n_prose`  | neutral (`detail`)  | neutral non-location prose, no digits (opinions/thanks) | **reference** |
| `n2_prose` | neutral (`remark`)  | same prose as `n_prose` | neutral→neutral rename control |
| `n_street` | neutral (`detail`)  | realistic street address, capitalised, two numbers (`<n> <Street Name> Apt <u>`) | |
| `n_numfmt` | neutral (`detail`)  | capitalised label+number format, two numbers, **not** an address (e.g. `Bay 42 Shelf 7`) | |
| `a_prose`  | address (`address`) | neutral prose (same as `n_prose`) | |
| `a_street` | address (`address`) | street address (same as `n_street`) | |

Comparisons (each isolates one dimension):

| id | contrast | isolates |
|---|---|---|
| `F2-ADDR:n_prose->n_street`  | value prose→street, neutral name | VALUE-SEMANTICS (street); also a composite (adds digits, caps, length) |
| `F2-ADDR:n_prose->n_numfmt`  | value prose→label+number, neutral name | FORMAT (digits + caps + structure, no street semantics) |
| `F2-ADDR:n_numfmt->n_street` | value numfmt→street, neutral name | STREET-semantics beyond digits/caps (residual: street nouns + `Apt`, token count) |
| `F2-ADDR:n_prose->a_prose`   | name neutral→address, prose value | FIELD-NAME (pure) |
| `F2-ADDR:n_street->a_street` | name neutral→address, street value | FIELD-NAME (with street value) |
| `F2-ADDR:n_prose->n2_prose`  | name `detail`→`remark`, prose value | RENAME instability (any-rename control for the field-name contrasts) |

Stratum = carrier (`query` / `body`). `n_numfmt` is capitalised with two numbers to match `n_street` on
case and digit count; residual differences (street nouns, `Apt`, token count, and prose length) are
reported as covariates in `side_effects_level_minus_reference` and acknowledged in §7.

### F2-HASH — `#` context generalization (n_bases = 60; 15 per context)
Levels per base: `base` (no special char) = **reference**; `hash` (one `#` inserted at a controlled,
legitimate position); `punct` (one `!` inserted at the **same** position — a covered-character
control). `!` is used instead of `-` because, like `#`, it percent-encodes under `quote(safe="")`
(`%21`) in the form/query contexts and stays literal in JSON, so `hash` vs `punct` is matched on the
encoding dimension; `-` is unreserved (stays literal everywhere) and before a number reads as a
negative value, which v1 already showed is null (0/30). Contexts (stratum), 15 bases each:

| context | field | carrier | `#`/`!` appears as |
|---|---|---|---|
| `passlike`   | `passcode` | form body | `%23` / `%21` |
| `identifier` | `ref_code` | GET query | `%23` / `%21` |
| `generic`    | `caption`  | form body | `%23` / `%21` |
| `json_text`  | `caption`  | JSON body | literal `#` / `!` |

`generic` and `json_text` share the field name (`caption`) and value template (`<noun> <n> of <m>`),
so they differ only in carrier + encoding; `passlike`/`identifier` use their own fields/templates.

Comparisons: `F2-HASH:base->hash` (MAIN, 60 bases), `F2-HASH:base->punct` (covered-char CONTROL, 60
bases), `F2-HASH:punct->hash` (direct `#`-specificity test, 60 bases). Stratum = context. This
separates: (a) `#` effect overall; (b) context dependence (per-stratum rule, §7); (c) `#`-specific vs
any inserted (encoded) punctuation (`punct->hash` directly, plus `base->hash` vs `base->punct`); (d)
a **descriptive** association of literal `#` (`json_text`) vs `%23` (others) — **not** a clean
encoding-causal isolation, because literal-vs-encoded is confounded with carrier (JSON vs form/query);
this is stated as hypothesis-only in §7.

### F2-APOS — apostrophe generalization (n_bases = 75; 15 per class)
Levels per base: `plain` (apostrophe absent) = **reference**; `apostrophe` (one legitimate `'` added,
one character). Classes (stratum), 15 bases each:

| class | field | carrier | `'` appears as | example plain → apostrophe |
|---|---|---|---|---|
| `contraction` | `caption`       | form body | `%27` | `its open late` → `it's open late` |
| `possessive`  | `caption`       | GET query | `%27` | `the clubs schedule` → `the club's schedule` |
| `title`       | `display_label` | form body | `%27` | `childrens hour` → `children's hour` |
| `place_json`  | `place_label`   | JSON body | literal `'` | `kings lynn` → `king's lynn` |
| `surname`     | `full_name`     | form body | `%27` | `ocallaghan` → `o'callaghan` (fresh surnames) |

Comparison: `F2-APOS:plain->apostrophe` (MAIN, 75 bases). Stratum = class. Separates: general
character effect (flips across all classes) vs character×context (only some; per-stratum rule §7). The
`surname` class is an **in-run positive control** (v1 found surname apostrophe 30/30), so "name-bound"
no longer rests only on the cross-study v1 comparison. Literal `'` (`place_json`) vs `%27` (others) is
a **descriptive** association confounded with carrier/field (§7), hypothesis-only. The `plain`
reference is an apostrophe-stripped spelling, so `plain→apostrophe` also contrasts slightly-unusual vs
standard text — a limitation noted in §7. There is no covered-character control for the apostrophe, so
C tests *generalization across classes*, not specificity of the apostrophe among characters (§7 C).

### CONTROL-COV2 — content instability control (n_bases = 40; 10 per stratum)
Two different fresh benign values swapped, same structure/carrier. **Stratified** to match the three
questions' domains, so the control bar reflects the instability of each domain rather than only of
username handles: `handle` (`display_name`, form/query), `prose` (`detail`, two neutral sentences,
form), `token` (`passcode`, two alnum tokens, form), `json` (`comment_text`, two JSON strings, JSON).
Comparison `CONTROL-COV2:val_a->val_b` (40 bases); per-stratum flip rates are also reported. Measures
v2's **own** decision-boundary sensitivity between different benign inputs (v1's analogue was 12.5%,
not material). The overall CP-95 upper bound `C_hi` is the effect bar for classification (§5); per-
stratum rates inform interpretation. The v1 12.5% is **not** treated as a universal constant.

## 4. Metrics, testability, and multiplicity (per comparison)

N (valid pairs), ALLOW→BLOCK (A→B), BLOCK→ALLOW (B→A), ALLOW→ALLOW, BLOCK→BLOCK, flip rate with
Clopper-Pearson 95% CI, net direction, baseline-ALLOW rate, reference-ALLOW / reference-BLOCK counts,
conditional A→B (with CI) and conditional B→A, direction consistency, **exact McNemar** (two-sided),
**Holm**-adjusted p within the CONTENT family, and per-stratum 2×2 tables. Both the **flip rate**
(dominant flips / all pairs) and the **conditional A→B** (flips / baseline-ALLOW pairs) are reported,
always labelled, so the 18/40-vs-18/33 ambiguity from v1 cannot recur (see `SANITY_18-33_vs_18-40.md`).

**Testability (the v1 address lesson).** A contrast is **testable for A→B** only if its
reference-ALLOW count ≥ `ceil(2N/3)` (i.e. the reference is mostly ALLOW, so a BLOCK flip is possible
to observe). A 0-discordant result is `NO OBSERVED EFFECT` only when A→B was testable; otherwise it is
`NO OBSERVED (UNTESTABLE)` (flagged `UNTESTABLE_A_TO_B`) and **cannot falsify** any hypothesis. A
ceiling reference (mostly BLOCK, e.g. a street value under `address`) therefore yields UNTESTABLE, not
a false null.

**Holm family (pre-registered membership).** One `CONTENT` family of the **10** hypothesis-bearing
comparisons: 6 × F2-ADDR, F2-HASH `base->hash`, `base->punct`, `punct->hash`, and F2-APOS
`plain->apostrophe`. The two F2-HASH control/specificity contrasts (`base->punct`, `punct->hash`) are
included because they are hypothesis-bearing (does any punctuation flip? is `#` specific?); including
them is conservative. `CONTROL-COV2` is **outside** every family (raw p only).

**P-value is not the primary result.** Interpretation prioritizes magnitude, direction, consistency,
control-relative effect, and reproducibility.

## 5. Effect classification (pre-registered, direction-aware, relative to v2's own control)

Let `C_hi` = Clopper-Pearson 95% **upper** bound of the CONTROL-COV2 flip rate measured **in this
run**. A→B is the **hypothesised** direction (a benign change inducing BLOCK). For a comparison with
`n` valid pairs, `d = A→B + B→A` discordant, `dominant = max(A→B,B→A)`, `direction` = A→B if A→B ≥ B→A
else B→A:

- **NO OBSERVED EFFECT** / **NO OBSERVED (UNTESTABLE)**: `d = 0` (testable vs untestable per §4).
- **STRONG EFFECT (direction)**: `dominant/n ≥ 0.20` AND `dominant/d ≥ 0.80` AND Holm-rejected
  (CONTENT family) AND `flip_rate > C_hi`.
- **MODERATE EFFECT (direction)**: `dominant/n ≥ 0.10` AND `dominant ≥ 6` AND `dominant/d ≥ 0.80` AND
  raw McNemar p < 0.05 AND `flip_rate > C_hi`.
- **WEAK / INCONCLUSIVE**: otherwise (≥1 discordant).

A `B→A` (reverse) result is labelled `(B→A)` and does **not** support the FP hypotheses. Thresholds
match v1 (continuity); the control bar `C_hi` and the raw-significance requirement for MODERATE are
computed/applied on v2 data. Instability is **material** iff the CONTROL-COV2 flip-rate CP lower bound
≥ 0.05 (reported with that caveat). Determinism failure (§6) ⇒ all effect classes WITHHELD.

**Per-stratum verdict (for the B/C heterogeneity rule).** For each stratum (N≈15): `effect (A→B)` iff
A→B ≥ 6 AND consistency ≥ 0.80 AND `flip_rate > C_hi` AND A→B ≥ B→A; `no effect (testable)` iff
A→B ≤ 2 AND reference-ALLOW ≥ 10; otherwise `indeterminate`. A comparison is **heterogeneous** iff at
least one stratum is `effect (A→B)` and at least one is `no effect (testable)`.

## 6. Determinism control and run integrity (falsifiable STOP)

Phase 1 scores a seeded 10% repeat subset `REPEAT_RUNS = 3` times. **Any** byte divergence in the raw
V4 output on a repeated text ⇒ **STOP**; phase 2 (main scoring) is not run and no effect is
interpreted (a determinism STOP is a result and is **not** rerun). Phase 2 scores every unique text
once in a seeded shuffled order and cross-checks the repeated texts against phase 1.

**Crash recovery (pre-registered):** `records.jsonl` is opened exclusively; if a run crashes before
`run_meta.json` is written, the partial `raw/` is moved aside to `raw.aborted-<utc>/` and the run is
repeated **in full** (never appended). **Invalid pairs:** a pair with a non-`ok` status on either side
is dropped from that comparison and counted in `n_invalid_pairs`; a comparison with > 5 % dropped is
flagged `HIGH_INVALID` and read with caution. (v1 had 0 invalid outputs in 2 756 classifications.)

## 7. Hypotheses, predictions, and falsification criteria (pre-registered)

Throughout: "**effect**" = STRONG or MODERATE in the **A→B** direction; "**testable null**" =
`NO OBSERVED EFFECT` or WEAK with A→B testable (§4); `NO OBSERVED (UNTESTABLE)` and B→A results **never
falsify**.

**A — ADDRESS.** H-A1 FIELD-NAME, H-A2 VALUE-SEMANTICS(street), H-A3 FORMAT, H-A4 unknown.
- **FIELD-NAME (H-A1)** supported iff `n_prose->a_prose` and/or `n_street->a_street` show an effect
  **beyond** the rename control `n_prose->n2_prose` (if `n2_prose` itself flips at a comparable rate,
  the "address" effect is attributed to renaming, not the token `address`). H-A1 **falsified** iff
  both name contrasts are testable nulls while a value contrast shows an effect.
- **VALUE-SEMANTICS street (H-A2)** supported iff `n_prose->n_street` shows an effect; **falsified**
  iff `n_prose->n_street` is a testable null.
- **FORMAT (H-A3)** supported iff `n_prose->n_numfmt` shows an effect; it is "digits/format suffice"
  iff additionally `n_numfmt->n_street` is a testable null (if `n_numfmt` is already mostly BLOCK,
  `n_numfmt->n_street` is UNTESTABLE and is reported as such, not as evidence). "Street beyond
  format" supported iff `n_numfmt->n_street` shows an effect. FORMAT **falsified** iff
  `n_prose->n_numfmt` is a testable null while `n_prose->n_street` shows an effect.
- **H-A4 (unknown):** if no A contrast shows a testable effect, the result is H-A4 / inconclusive.
- Note: `n_prose->n_street` is a composite (value semantics + digits + caps + length); `n_numfmt` and
  the name contrasts decompose it. Residual covariates (length, token count) are reported.

**B — `#` CONTEXT.** On the MAIN `base->hash`:
- **General character effect** iff `base->hash` is an effect and **not heterogeneous** across contexts
  (per-stratum rule, §5). **`#`×context interaction** (general effect **falsified**) iff `base->hash`
  is **heterogeneous** (≥1 `effect` stratum and ≥1 `testable null` stratum).
- **`#`-specific vs any punctuation:** compare directly via `punct->hash` and via `base->hash` vs
  `base->punct`. `#`-specific iff `punct->hash` shows an effect (and/or `base->hash` is an effect while
  `base->punct` is a testable null); not `#`-specific iff `base->punct` shows a comparable effect.
- **Literal `#` vs `%23`:** a **descriptive, hypothesis-only** association — if the three `%23`
  contexts show an effect but `json_text` (literal `#`) is a testable null, that is consistent with an
  encoding-triplet reading **but is confounded with carrier (JSON vs form/query)** and does **not**
  establish encoding causality.

**C — APOSTROPHE.** On the MAIN `plain->apostrophe`:
- **General character effect** iff an effect and **not heterogeneous** across classes. **Character ×
  context (name/surname-bound)** (general effect **falsified**) iff **heterogeneous** — in particular
  the `surname` in-run positive control is an effect while one or more non-name classes are testable
  nulls.
- **Literal `'` vs `%27`:** same descriptive, carrier-confounded, hypothesis-only caveat as B.
- C tests *generalization across benign classes*, not specificity of the apostrophe among characters
  (no covered-character apostrophe control). The `plain` reference is apostrophe-stripped, so the
  contrast also carries a slight "unusual vs standard spelling" difference (limitation).

## 8. Scope limits

Benign only; no attack counterparts. ≥30 bases per **main** comparison (`F2-HASH:base->hash` 60,
`F2-APOS:plain->apostrophe` 75, each F2-ADDR contrast 30, CONTROL-COV2 40). Per-stratum N (15) is a
lower-powered within-question breakdown with its own pre-registered verdict rule (§5). This probe does
**not** attempt to fully characterize V4. No v3 is proposed unless v2 surfaces a concrete, material
blocker for the V5 design.

## 9. Pre-registered provenance (filled at freeze)

- Base commit (`git HEAD`): recorded in `raw/run_meta.json` → `git_head` at run time (as v1), and in
  the freeze log in `README.md`. It is deliberately **not** in the hashed `cases.jsonl`/`manifest.json`
  so those stay byte-reproducible from the seed alone. (No commit is made this session; the future PR
  commits the frozen files and the commit hash is added to the freeze log.)
- V4 adapter SHA-256: `7bf168758a428fa7775dff0328de3d07d3063ddf99b961dc8b8406a0dce93de1` (asserted at run).
- `control_plane/inference_core.py` SHA-256: `325e3149ef014e2422f1a1a41337b1a8f8d41b5ccba8016b547f9573d7f0f954`
  (pre-registered and **asserted** at run, before the model loads).
- Model identifiers / environment: recorded in `raw/run_meta.json` (python, torch, transformers,
  peft, device, gpu). The base model is the one the adapter targets (pinned via the adapter hash).
- Seed: `20261007` (generator). Order seed: `v5-minimal-pairs-v2|order`. Generator version:
  `v5-minimal-pairs-v2/generator-2`. Analysis version: `v5-minimal-pairs-v2/analysis-2`.
- Pre-execution SHA-256 of `PROTOCOL.md`, `minimal_pair_probe_v2_cases.py`, `manifest.json`,
  `cases.jsonl`, `run_v4_minimal_pair_probe_v2.py`: in `SHA256SUMS` (this directory), created at
  freeze. The runner re-verifies all anchors before scoring and refuses to overwrite raw records.
