# Coordinator instructions — R3 review execution and adjudication (D67 / V5-DATA-SPEC-r4)

**These files are COORDINATOR-ONLY and must never be shown to R3:** `coordinator/manifest.jsonl`,
`coordinator/membership.json`, `coordinator/integrity.json`, this file. R3 receives only `reviewer/R3_PROMPT.md`,
`reviewer/rubric.md` (optional; the rubric is inlined in the prompt), and one `reviewer/batch_XX.jsonl` at a time.

This step prepares materials. **Do not execute R3 here, and do not compute any acceptance result until R3 is complete.**

## 1. Running R3 (separate session)
- Reviewer: **ChatGPT GPT-6**, a different provider than a1 (`claude-sonnet-5-5`) / a2 (`claude-haiku-5-5`), run
  **blind**. Fresh session per batch; paste `R3_PROMPT.md` then one batch.
- Each of the **217** unique records is labelled **once**; reuse that one label wherever the record is also in the
  subsample or the disagreement set (overlap = 16).
- **Record at run time** (never prepopulated, never invented): the exposed model designation, execution date,
  interface, available settings, and the raw output (store verbatim, with the batch file's SHA-256).
- **Designation mismatch:** if the exposed designation is not ChatGPT GPT-6, **STOP and flag to the owner before
  evaluation** — do not silently substitute a reviewer.
- Unevaluated items (refusal/truncation/failure) are logged as `UNEVALUATED`, never given a fabricated label.

## 2. Adjudication (D67/r4 §6 — do not redesign)
Per record, using `membership.json` (a1/a2 labels) and R3's label:
1. **Agreement:** a1 = a2 → that label (R3 is a minority vote and never overrides a concordant pair).
2. **Approved V/P rule:** exactly one of {a1,a2} VERIFIABLE and the other PROBABLY_CORRECT (no UNCERTAIN/INCORRECT) →
   PROBABLY_CORRECT (`vp_split_to_probably_correct/v1`).
3. **Majority — only with all three valid labels:** for a1 ≠ a2, a strict majority of {a1,a2,R3} applies **only when all
   three labels are present**.
4. **UNRESOLVED:** a three-way disagreement (three distinct labels) **or** any missing required vote → `UNRESOLVED` →
   an **evidence-based owner decision** (documented; may dispose procedurally, exclude, or commission further review;
   **cannot manufacture ground truth**). Never auto-INCORRECT. A missing R3 label is a non-vote, never scored as correct
   or incorrect.

## 3. Gate (per ML-trained category — frozen in the preregistration)
- **C1:** Wilson-95 upper bound of adjudicated INCORRECT **≤ 20%**. **C2:** Wilson-95 upper bound of adjudicated
  UNCERTAIN+INCORRECT **≤ 35%**.
- **Denominator = the category's size in the original 453-record frame** (see `../preregistration/`):
  CRLF 22, XPath 31, all others 50. **The targeted 33 disagreements add NO separate Wilson denominator** — they resolve
  labels in place. Each physical record (incl. the 16 overlap) counts **once** per rate.
- **Coverage 100%** and **zero** gate-relevant `UNRESOLVED`/`MISSING`/`FURTHER_REVIEW` items are required for a category
  to reach `PASS_AI_AUDITED`. Otherwise `INSUFFICIENT_EVIDENCE` (not supported). Unresolved evidence never becomes
  INCORRECT to force a FAIL.
- **Model agreement (incl. R3) is diagnostic only**, never independent ground-truth validation; R3's INCORRECT share and
  R3-vs-(a1,a2-only) agreement are diagnostics, not thresholds.
- A `PASS_AI_AUDITED` category is **AI-audited, not VERIFIED by humans**; no audit result sets a payload's
  `label_status = VERIFIED`, and no category is PASS merely because the methodology was approved.

## 4. Standing dispositions (coordinator note — not shown to R3)
- **SSRF is already NOT SUPPORTED** (recorded C1 failure, 21/50 concordant INCORRECT); it stays excluded pending a
  separately approved correction + re-audit. R3 still labels its 20 subsample records blind; this does not restore
  eligibility.
- FINAL training stays **BLOCKED** regardless of any audit result (separate owner authorization required).
