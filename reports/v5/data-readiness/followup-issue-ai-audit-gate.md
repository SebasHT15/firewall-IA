# Follow-up issue (DRAFT for owner to file) — Make the r4 AI-audited training gate enforceable, not procedural

**Status:** DRAFT, not filed as of 2026-10-20. Active trainer unchanged. A candidate implementation
and its negative tests are preserved as `proposals/final-gate-ai-audit.patch`, not applied.
Prepared under D67 ratification (#77); owner authorization schema still requires ratification.
**Area:** `scripts/training/v5_train_data.py`, `scripts/training/finetune_v5.py` (now present on
both `develop` and the consolidated `feat/v5-data-readiness` branch; training code merged via PR #78).
**Severity:** medium (safety-relevant; FINAL is blocked today, so no live exposure).

## Summary
D67 (APPROVED 2026-10-20) replaces the §7 blind **human** review with an AI-assisted third review (R3) and retires the
§11.3 item-1 "owner's human review of the 95-item pre-filter sample". The `develop` training-readiness code predates
this and encodes the human-review requirement. Two concrete items must be handled deliberately when `feat/v5-data-readiness`
and this r4 protocol are integrated with `develop`, so that AI-audited evidence cannot **silently** satisfy the FINAL
training gate.

## Evidence (original inspection of `develop`; line numbers describe that revision)
1. `v5_train_data.py:82` (verbatim intent): the mandatory-gate list "… (e.g. an r4 that replaces the human review)
   must update this list deliberately, never implicitly." The list still contains:
   - `human_review_prefilter_sample`  (§11.3 item 1 — **retired by D67/r4**)
   - `post_filter_audit`              (§11.3 item 2 — §7 audit)
2. `v5_train_data.py:431` — FINAL requires `attack_label_basis == "post_filter_audit"`. **This check does not
   distinguish an AI-audited pass from a human-audited pass.**
3. `v5_train_data.py:296` — rows train only if `label_status ∈ {VERIFIED, POLICY_DEFINED}` (good: category
   `PASS_AI_AUDITED` does not by itself make a row trainable; the audit never sets `VERIFIED`).
4. `finetune_v5.py` — FINAL refuses (return 3, `GateRefused`) without committed `--dataset-prereg`, `--freeze-record`
   (`v5-dataset-freeze-record/v1`) and `--training-prereg` (`v5-training-preregistration/v1`); none exists yet.

## Why it matters
With the human-review gate retired and `attack_label_basis == "post_filter_audit"` indifferent to review type, once the
gate list is updated for r4 the code would accept AI-audited labels for FINAL **without a distinct, code-checked owner
authorization**. The intended guarantee ("AI-audited evidence does not feed FINAL until separately authorized", D67 #10)
is currently **procedural**, not enforceable in code.

## Proposed change (do NOT apply here; FINAL stays blocked)
1. Update the mandatory-gate list deliberately for r4: retire `human_review_prefilter_sample`; keep `post_filter_audit`
   bound to the §7 AI-audited protocol.
2. Add an explicit, enforceable review-type marker to the dataset manifest, e.g. `audit_type ∈ {human, ai_audited}`, and
   make FINAL **refuse** `ai_audited` unless a separate, committed owner authorization record (its own schema + hash) is
   supplied — a distinct decision from the dataset/training preregistrations.
3. Keep `PASS_AI_AUDITED` strictly separate from `VERIFIED` in both code and reports; forbid any path that would set
   `label_status = VERIFIED` from an audit pass.

## Acceptance
- FINAL refuses an `ai_audited` dataset without the separate owner authorization record (gate-only test).
- No implicit retirement of a mandatory gate; the list change is explicit and tested.
- No `VERIFIED` is derivable from an audit pass.

## Scope / safety
Documentation only. The trainer is **not** changed here; FINAL remains blocked; no weights touched; the frozen r3 and
the approved r4 thresholds are not modified.
