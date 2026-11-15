# V5-DATA-SPEC-r4 — freeze & provenance record

- **Specification id:** `V5-DATA-SPEC-r4`
- **Status:** **APPROVED & FROZEN** by **D67** (owner approval, 2026-10-20, issue #77).
- **Canonical artifact:** `reports/v5/v5-data-spec-r4/README.md`
- **SHA-256 (r4, frozen):** `54514850e9875f4a71d6ad3726d95746bb4e61687db4f56b072e0a01bfdc01be`

## Provenance (byte-reproducible)

- **Source revision:** `V5-DATA-SPEC-r3`, `reports/v5/v5-data-spec-draft/README.md`, SHA-256
  `f1580634d35d2baf10b99d7985f9bfb1e56ebc956326a58a61b665fc5958d9cb` (FROZEN 2026-10-13, D62) — **unchanged**.
- **Change:** the minimal unified diff `reports/v5/v5-data-spec-r4-proposal/r3-to-r4-minimal.diff`.
- **Reproduce:** applying that diff with `git apply -p1` to a copy of the frozen r3 yields this exact file
  (SHA `54514850…`). Verified on an isolated copy; the frozen r3 is never patched. The diff touches only §7
  (post-filter audit row), §11.2 (threshold register) and §11.3 (items 1–2); all other text is r3 verbatim.

## r3 → r4 distinction

- r4 **inherits** the r3 body verbatim except the three amended locations above. The body still carries r3's own status
  paragraph as history; the **binding r4 protocol** is the amended §7 post-filter audit (AI-assisted third review) plus
  the §11.2 / §11.3 changes, as ratified by D67.
- The version-line wording inside the body ("r4 (PROPOSED, D67 …)") predates ratification and reflects the candidate
  state; it is **superseded by this freeze record**: D67 is APPROVED (2026-10-20) and r4 is FROZEN. The byte content is
  intentionally left identical to the validated-diff output to preserve reproducibility.

## Scope (unchanged by the freeze)

- The specification is frozen; the **dataset is not**. No category is `PASS_AI_AUDITED` and no payload is `VERIFIED`
  merely because r4 is approved. The post-filter audit (reviewer R3) has **not** run.
- FINAL TinyLlama V5 training remains **BLOCKED** (see D67 and `reports/v5/.../followup-issue-ai-audit-gate.md`).

## Related records

- Decision: `DECISIONS.md` → D67.
- Preregistration of acceptance criteria: `reports/v5/postfilter-audit/preregistration/v5-postfilter-prereg-r4.json`.
- Historical D67 drafts/diffs: `reports/v5/v5-data-spec-r4-proposal/_preserved/`.
