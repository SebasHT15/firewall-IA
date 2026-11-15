# D67 — V5 post-filter audit: AI-assisted review in place of the unavailable human review (PROPOSED, rev 3)

- **Date:** 2026-10-19 (America/Costa_Rica). **Status:** PROPOSED, **not approved**. If approved, the owner appends it
  to `DECISIONS.md` as D67 and the corresponding spec becomes `V5-DATA-SPEC-r4`.
- **Issue:** #77.
- **Spec:** `V5-DATA-SPEC-r4` (PROPOSED). The minimal diff against the frozen r3 is `r3-to-r4-minimal.diff` (updated to
  this rev 3). The frozen r3 (`f1580634d35d2baf10b99d7985f9bfb1e56ebc956326a58a61b665fc5958d9cb`) is **not** edited.
- **Revision history of this proposal:**
  - rev 1 (untracked, overwritten; recoverable only from the prior session transcript) proposed the AI review but
    (a) read reviewer R3's INCORRECT share as an error metric, (b) used an automatic most-adverse-label tie-break, and
    (c) measured R3 agreement against a final decision that already contained R3's own vote.
  - rev 2 (partial, preserved at `_preserved/D67-proposal.rev2-partial.md`) began the corrections but was interrupted
    after §3.
  - rev 3 (this file) completes the corrections. The exact changes from rev 1 are listed in §10.
- **Preserved originals:** `_preserved/D67-proposal.rev2-partial.md` (rev 2) and `_preserved/r3-to-r4-minimal.rev1.diff`
  (rev 1). Nothing is deleted.

> **Do not approve as settled fact.** This document is a methodology *proposal*. Every numeric acceptance value in §8 is
> OPEN and must be preregistered and owner-approved **before** reviewer R3 produces any output (C-R6). No category is
> approved, no payload is VERIFIED, and FINAL training stays BLOCKED (§11).

---

## 1. What is preserved, unchanged

- D58 and D62 as historical records, the frozen r3 text (`f1580634…`), and D66.
- Every round-1 artifact: the sample (`eb001e95…`, seed `v5-postfilter-audit-r1-2026-10-19-d66`), the 200-item
  subsample (`8667a427…`), packets, batches and their hashes, `round_status.json`, `agreement_report.json`,
  `report.md`/`report.json`.
- The annotations: a1 = `claude-sonnet-5-5`, 453/453 (`ea956073…`); a2 = `claude-haiku-5-5`, 453/453 (`c497d098…`);
  the supplementary `claude-opus-5-5` partial (377 rows, descriptive only, not in the gate).
- The agreement result: 351/453 exact, 102 disagreements, κ(INCORRECT-vs-not)=0.8978, κ(usable-vs-not)=0.8391,
  explicitly recorded as **LLM–LLM agreement, not human validation**.
- The 69 V/P decisions made by the owner-approved rule `vp_split_to_probably_correct/v1`, its trace
  (`adjudication_rule_applied.jsonl`) and its disclosed discrepancies, and the list of 33 gate-relevant disagreements.
- No evidence is overwritten, relabelled, redrawn or deleted. This proposal changes **procedure for the next step**, not
  any recorded result.

## 2. Post-hoc methodological deviation (disclosed, no equivalence claimed)

- D58 and r3 §7 require an independent, **blind human** review whose labels prevail on a stratified subsample.
- This proposal replaces that human review with an **AI-assisted review**. The owner decided this **after** the
  round-1 LLM results existed and after seeing their aggregate counts per category (69 V/P, 33 other). That is a
  **post-hoc change of evidence type**, and it conflicts with the spirit of C-R6 ("never relaxed after any model output
  exists").
- **The AI-assisted review is not methodologically equivalent to human review, and nothing in this proposal claims it
  is.** Every result produced under D67 is labelled **"AI-audited — no independent human review"** (status vocabulary in
  §4).
- The stated reason is the unavailability of specialised human reviewers. That is a **constraint, not a justification of
  quality**, and not a finding that the AI review is sufficient.
- Because of this deviation, the numeric acceptance values that the human review previously anchored are **reopened**
  (§8). They are not carried over as approved simply because they appeared in rev 1 or in r3's PROPOSED register.

## 3. Reviewers and roles

- **a1, a2** — the existing round-1 LLM annotators, one provider: a1 `claude-sonnet-5-5`, a2 `claude-haiku-5-5`. Their
  453/453 labels are frozen inputs; they are **not** re-run.
- **R3** — a third reviewer, an LLM from a **different provider** than a1/a2, run **blind** to the a1/a2 labels. ChatGPT
  is *proposed*; its exact model, version, date, interface and settings are **PENDING owner approval** (§9) and, once
  fixed, recorded with R3's raw output kept. R3 is **not a human**: its labels never "prevail" as human labels did in
  r3.
- **Adjudicator** — the coordinator or, for anything the reproducible rule (§6) leaves `UNRESOLVED`, the **owner**. Each
  adjudicated decision is traced per item.

## 4. Status and label vocabulary (kept semantically distinct)

These terms are **not** synonyms. None of them is conferred by model agreement.

| Term | Level | Meaning | What it is **not** |
|---|---|---|---|
| `VERIFIED` | per-payload (`label_status`, D59) | provenance **and** value structure independently established for that payload | **Never** conferred by any audit, by LLM consensus, or by R3. The audit leaves `label_status` untouched. |
| `AI_AUDITED` | provenance tag on any D67 result | the post-filter audit was carried out with LLM reviewers and **no independent human review** | not a quality grade; not `VERIFIED`; not human-validated |
| `PASS_AI_AUDITED` | per-category gate status | the AI-audited gate conditions (§7) were met, so the category is **eligible for V5 TRAIN** | **strictly weaker** than a human-validated pass; implies nothing about any individual payload being `VERIFIED` |
| `INSUFFICIENT_EVIDENCE` | per-category gate status | coverage/resolution conditions (§7) not met | not a FAIL on quality; the category is **not supported** for V5 until evidence is completed |
| `FAIL` | per-category gate status | a quantitative condition (§7.1–§7.2) is violated | — |

- A category that reaches `PASS_AI_AUDITED` is reported as **AI-audited, not VERIFIED by humans**, everywhere it appears.
- **Consensus between models (a1, a2, R3) can never raise a payload to `VERIFIED`.**

## 5. Three evidence types — kept distinct, never conflated

1. **Model disagreement** — a1, a2 (and R3) assigning different labels to the same item. It is a *signal of uncertainty*
   only. **Model disagreement is never reported as empirical ground-truth error.**
2. **Adjudicated quality classification** — the label the reproducible rule (§6) assigns to an item (e.g. adjudicated
   INCORRECT). It is a *classification under a stated rule applied to AI labels*, not an independently established fact.
3. **Independently established error** — a payload shown wrong against a trusted reference label. **This project has no
   trusted independent reference labels for the post-filter pool.** Therefore:
   - the **true error rate of the annotators cannot be established**, and
   - every Wilson bound in §7 bounds the **adjudicated-INCORRECT rate under the AI adjudication**, which is itself not
     ground truth, and must be reported as such — never as "the payload error rate".

## 6. Reproducible adjudication rule (r4)

Applied per item, in order. Both original a1/a2 labels are always kept unchanged; each decision is traced.

1. **Agreement.** a1 = a2 (= R3 where R3 labelled it) → that label.
2. **Approved V/P rule.** Exactly one of {a1, a2} = VERIFIABLE and the other = PROBABLY_CORRECT, no UNCERTAIN/INCORRECT
   involved → PROBABLY_CORRECT, by the owner-approved `vp_split_to_probably_correct/v1` (unchanged from round 1; gate
   effect none, since both are usable).
3. **Majority of {a1, a2, R3}.** A strict majority (≥ 2 of the labels present) → the majority label.
4. **No majority.** The three available labels are all distinct, **or** a tie leaves no majority → **`UNRESOLVED`**.
   - `UNRESOLVED` is **not** automatically classified as INCORRECT (this removes rev 1's "most-adverse-of-the-three"
     tie-break).
   - An `UNRESOLVED` item is routed to an **identified owner decision**; the owner's recorded label replaces
     `UNRESOLVED` and is traced.
5. **Missing reviewer response.** An item for which a reviewer produced no parseable label is treated as *that reviewer
   not voting*. If this leaves no majority, the item is `UNRESOLVED` (step 4). A missing response is never silently
   dropped and never counted as a correct or an incorrect label.

> There is **no automatic most-adverse / most-negative tie-break anywhere** in this rule.

## 7. Gate definition (per ML-trained category)

### 7.0 Populations, denominators and the 16 overlapping records

- **Category audit sample** `S_c`: the round-1 draw for category *c* (n as drawn: e.g. CRLF 22, XPath 31, others 50).
  Each physical record is counted **once** in `S_c`.
- **Subsample** `H_c` ⊆ `S_c`: the stratified ≥ 20-item-per-category subsample that in r3 went to the human reviewer and
  under r4 goes to R3 (blind).
- **Gate-relevant disagreement set** `G`: the 33 disagreements whose resolution can move a gate rate.
- **The 16 records that are in both the 200-item subsample and the 33 disagreements** are a single physical set. They
  are counted **once** in each denominator in which they appear: once in their category's `S_c`, and once in `G`. They
  are **not** double-counted within any single rate. Where an item is both in `H_c` and in `G`, R3's one label on it
  serves both the subsample-coverage computation and the disagreement resolution; it is still one record.
- **Wilson denominator for category *c*** = |`S_c`| (every drawn record). Items that end `UNRESOLVED` or `MISSING` are
  **not** dropped from the denominator; they are handled by §7.3 (they block PASS rather than being scored as INCORRECT,
  so disagreement is never converted into an error count).

### 7.1 Quantitative conditions (carried from r3, still PROPOSED — see §8)

Computed on adjudicated labels over the denominator |`S_c`|, using the **Wilson score interval at 95%, upper bound**:

- **C1:** Wilson-95 upper bound of adjudicated **INCORRECT** ≤ `θ_INC`.
- **C2:** Wilson-95 upper bound of adjudicated **UNCERTAIN + INCORRECT** ≤ `θ_UI`.

These bound an AI-adjudicated classification rate, not a human error rate (§5.3).

### 7.2 R3 diagnostic signals (diagnostic, **not** a pass threshold by default)

- **D-R3-incorrect:** R3's own INCORRECT share on `H_c`. This is **reported as a diagnostic of reviewer disagreement**,
  **not** as an error metric and **not** as a substitute for the retired human-error condition. Whether it also becomes
  a hard gate threshold is an OPEN value (§8); it is **not** assumed to be so.
- **D-R3-agreement:** R3's agreement with the **a1/a2-only adjudication** (steps 1–2 of §6, i.e. **excluding R3's own
  vote**) on `H_c`. Measuring R3 against a decision that already contains R3's vote is circular and is **not** used;
  this metric is **diagnostic, not independent validation**, in line with the requirement that agreement with a
  decision incorporating R3's own vote is diagnostic only.

### 7.3 Coverage / resolution condition (prevents approval on unresolved evidence)

- A category may reach `PASS_AI_AUDITED` **only if every gate-relevant item (`G` ∩ `c`, and all of `H_c`) has a resolved
  adjudicated label** — i.e. none left `UNRESOLVED`, `MISSING`, or flagged `FURTHER_REVIEW` by R3.
- If any such item is unresolved, the category status is `INSUFFICIENT_EVIDENCE` (not supported) until the owner
  resolves it (§6 step 4). Unresolved evidence **blocks** approval; it is **not** scored as INCORRECT to force a FAIL
  and **not** waved through to a PASS.
- A separate, explicit **maximum-unresolved fraction** before owner escalation is an OPEN value (§8); its default
  interpretation here is **zero unresolved gate-relevant items at PASS time**.

### 7.4 Category outcome

- All of C1, C2 and §7.3 satisfied → `PASS_AI_AUDITED` (tagged `AI_AUDITED`, never `VERIFIED`).
- C1 or C2 violated on resolved evidence → `FAIL`.
- §7.3 not satisfied → `INSUFFICIENT_EVIDENCE`.
- On `FAIL` or `INSUFFICIENT_EVIDENCE`, per D58 ("must pass") the category is **excluded from V5 TRAIN** and reported
  NOT SUPPORTED for V5. At most **one** re-audit, only after a documented filter change, with a new seed; no further
  re-draws (C-R6).

## 8. Numeric acceptance values — all OPEN, preregistered and approved before R3 runs

Per the requirement that no figure be automatically retained or reinterpreted, the following are **OPEN**. Each must be
fixed in a preregistration, justified as far as the evidence permits, and **owner-approved before any R3 output is
observed** (C-R6). None is approved by this document.

| Symbol | Meaning | rev-1 value (NOT retained) | Status |
|---|---|---|---|
| `θ_INC` | C1 bound on adjudicated INCORRECT | 20% | OPEN — preregister |
| `θ_UI` | C2 bound on adjudicated UNCERTAIN+INCORRECT | 35% | OPEN — preregister |
| `θ_R3I` | whether/at what level R3 INCORRECT share gates | 20% (used as metric — rejected) | OPEN — default **diagnostic only** |
| `θ_R3A` | whether/at what level R3 agreement gates | 80% (circular — rejected) | OPEN — default **diagnostic only** |
| `θ_UNRES` | max unresolved gate-relevant fraction at PASS | 10% | OPEN — default **0 unresolved** |
| `n` | per-category sample floor | ≥ 50 (or whole pool) | OPEN — preregister |
| `|H_c|` | per-category subsample floor | ≥ 20 | OPEN — preregister |

- The two rates `θ_INC`/`θ_UI` reproduce r3's PROPOSED numbers for continuity, but they are **reopened** by the
  post-hoc deviation (§2) and remain PROPOSED/OPEN, not approved.
- `θ_R3I` and `θ_R3A` are, by default, **diagnostics, not gates** (§7.2). Promoting either to a hard threshold is an
  owner decision taken in the preregistration, before R3 runs.

## 9. Decisions still requiring owner approval (none assumed granted)

1. Final D67 wording and whether to adopt `V5-DATA-SPEC-r4`.
2. The explicit post-hoc-deviation ruling (§2) as recorded policy.
3. The status semantics of §4 and their enforcement implications (what `PASS_AI_AUDITED` does and does not permit).
4. R3 as third reviewer and its **exact model and version** (ChatGPT only proposed).
5. The adjudication rule §6, in particular `UNRESOLVED` → owner, no auto-INCORRECT.
6. Every OPEN numeric value in §8, preregistered **before** R3 runs.
7. Any modification that would allow FINAL training on AI-audited evidence (see §11).

Recommendations in this file are **recommendations**, not approvals.

## 10. What changed from rev 1 (the required corrections)

1. **Historical artifacts and annotations preserved** — §1; originals copied to `_preserved/`.
2. **Post-hoc deviation disclosed; no human-validation equivalence claimed** — §2.
3. **Three evidence types distinguished** (model disagreement / adjudicated classification / independently established
   error), with the explicit statement that the true annotator error rate is not establishable — §5.
4. **R3 agreement is measured against the a1/a2-only adjudication and labelled diagnostic**, not against a decision
   containing R3's own vote — §7.2 (fixes rev 1's circular agreement measure).
5. **Three distinct labels without a majority → `UNRESOLVED` → owner**, never automatic INCORRECT — §6 (removes rev 1's
   most-adverse tie-break).
6. **`AI_AUDITED`, `PASS_AI_AUDITED`, `VERIFIED` kept distinct**; consensus never confers `VERIFIED` — §4.
7. **Exact denominators, Wilson-95 definition, coverage, the 16 overlapping records, missing responses and unresolved
   records all defined** — §7.0–§7.3.
8. **No category approval while gate-relevant evidence is unresolved** — §7.3 (`INSUFFICIENT_EVIDENCE`).
9. **FINAL training stays blocked** — §11.
10. **R3 INCORRECT share is no longer read as an error metric**; it is a diagnostic, and its use as a gate is an OPEN,
    pre-registered, owner-approved choice — §7.2, §8.
11. **The rev-1 figures (20/35/20/80/10) are not auto-retained**; all numeric values are OPEN in §8.

## 11. Compatibility with the data and training gates (FINAL stays BLOCKED)

- This proposal changes only r3 §7 (post-filter audit row), the §11.2 threshold register and §11.3 items 1–2. All other
  r3 text is unchanged; the frozen r3 file is not edited.
- It does **not** relax any BLOCKING check of r3 §7, the byte-identical-regeneration requirement, or the preregistration
  requirement of §11.2.
- **FINAL TinyLlama V5 training remains BLOCKED** until (a) this methodology is approved, (b) every §8 value is
  preregistered and owner-approved before R3 runs, (c) the categories needed for TRAIN reach `PASS_AI_AUDITED` under it,
  and (d) all other training-readiness conditions (the 27 recorded in the training-readiness closeout) are satisfied.
  AI-audited evidence does **not** by itself unblock FINAL training; that is an explicit owner decision (§9.7).
- `names_family` stays BLOCKED (#75); this proposal does not address it.

---

**STATUS: PROPOSED (rev 3), not approved.** This file is internally complete. It must not be read as an owner decision,
a dataset-freeze authorization, or a training-unblock. The companion `r3-to-r4-minimal.diff` has been updated to match
this rev. No commit, branch, or PR is made by preparing it.
