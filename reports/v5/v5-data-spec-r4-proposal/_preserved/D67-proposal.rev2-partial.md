# D67 — V5 post-filter audit: AI-assisted review in place of the unavailable human review (PROPOSED, rev 2)

- **Date:** 2026-10-19 (America/Costa_Rica). **Status:** PROPOSED, not approved. If approved, the owner appends it to
  `DECISIONS.md` as D67.
- **Issue:** #77.
- **Spec:** `V5-DATA-SPEC-r4` (PROPOSED). The minimal diff against the frozen r3 is `r3-to-r4-minimal.diff`. The
  frozen r3 (`f1580634…`) is not edited.
- **Rev 2:** applies the owner's ten corrections of 2026-10-19 to rev 1. The changes are listed in §9.

## 1. What is preserved, unchanged

- D58 and D62 as historical records, the frozen r3 text, and D66.
- Every round-1 artifact: the sample (`eb001e95…`, seed `v5-postfilter-audit-r1-2026-10-19-d66`), the 200-item
  subsample (`8667a427…`), packets, batches and their hashes.
- The annotations: a1 = `claude-sonnet-5-5`, 453/453; a2 = `claude-haiku-5-5`, 453/453; the supplementary Opus 5.5
  partial.
- The 69 V/P decisions made by the owner-approved rule `vp_split_to_probably_correct/v1`, and the list of 33
  gate-relevant disagreements.
- No evidence is overwritten, relabelled or redrawn.

## 2. Post-hoc methodological deviation (disclosed, no equivalence claimed)

- D58 and r3 §7 require an independent, **blind human** review whose labels prevail.
- This proposal replaces it with an AI-assisted review. The owner decided this **after** the round-1 LLM results
  existed and after seeing their aggregate counts per category. That is a post-hoc change of evidence type, and it
  conflicts with the spirit of C-R6 ("never relaxed after any model output exists").
- **The AI-assisted review is not methodologically equivalent to human review, and nothing in this proposal claims it
  is.** Every result produced under D67 is labelled **"AI-audited — no independent human review"**.
- The reason is the stated unavailability of specialised human reviewers. This is a constraint, not a justification of
  quality.

## 3. Roles and terms

**Reviewers:**
- **a1, a2:** the existing LLM annotators (one provider).
- **R3:** the third reviewer, an LLM from a different provider; ChatGPT is proposed. Its exact model, date, interface
  and settings are recorded, and its raw output is kept.
- **Adjudicator:**

---

**INCOMPLETE DRAFT (2026-10-19).** The write of rev 2 was interrupted after section 3, and the rest of rev 2 is missing. Rev 1 was overwritten by this partial write. `r3-to-r4-minimal.diff` still reflects rev 1 and has **not** been updated to the rev-2 corrections. Do not approve from this file.
