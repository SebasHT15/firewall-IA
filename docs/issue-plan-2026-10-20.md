# Issue disposition and follow-up drafts — 2026-10-20

Snapshot verified against GitHub while PR #79 was OPEN. This is a plan, not evidence that issues
were edited or closed. No issue was opened, closed or commented on by this documentation update.

## Existing issues: what can close

**No currently open issue should be closed solely because PR #79 is merged.** Relevant criteria:

| Issue | Actual status | Action / remaining criterion |
| --- | --- | --- |
| [#75](https://github.com/SebasHT15/firewall-IA/issues/75), family-name pool | OPEN; acquisition resolved, consumer acceptance incomplete | Update the stale outage status. Verify ratified cross-pool precedence, value identities/SPL-6, ≥20 per split or refusal, and explicit generator availability. Keep open. |
| [#77](https://github.com/SebasHT15/firewall-IA/issues/77), post-filter audit | OPEN; D67/r4 frozen, R3 unexecuted | Update old r3/human-review/deny-list wording to the approved r4 protocol. Complete blind R3, adjudication, category gates and owner report review. Keep open. |
| [#68](https://github.com/SebasHT15/firewall-IA/issues/68), canonical gateway prerequisites | OPEN/BLOCKED | Existing issue covers framing, adapter, limits, policies and conditioned D63 decisions. Owner start approval is still required by its scope. Do not create a duplicate. |
| [#36](https://github.com/SebasHT15/firewall-IA/issues/36), benign Fast Path | OPEN | Observer code is partial progress, not ALLOW routing. Reconcile criteria with the proposed positive-rule policy and #68 prerequisites, then validate before enforcement. |
| [#37](https://github.com/SebasHT15/firewall-IA/issues/37), deferred model validation | OPEN | No active Fast Path traffic exists yet. Analyzer shadow is not this deferred classifier validation feature. |
| [#38](https://github.com/SebasHT15/firewall-IA/issues/38), Fast Path benchmark | OPEN | No path split, security tradeoff or latency benefit has been measured. Reconcile score-threshold wording with the approved eventual policy. |
| [#35](https://github.com/SebasHT15/firewall-IA/issues/35), heuristic suspicious score | OPEN; scope mismatch | No score was implemented. Recommend a recorded D29 scope decision; if the owner retires it, close as not planned/superseded with a pointer to #36, never as completed. |
| [#65](https://github.com/SebasHT15/firewall-IA/issues/65), input template tokens | OPEN | EOS output-completion fix does not sanitize input. Keep open for the authorized diagnostic and decision. |
| [#18](https://github.com/SebasHT15/firewall-IA/issues/18), end-to-end latency | OPEN | Baseline without active Fast Path and layer-specific P50/P95/P99 still needed. Unit tests do not close this issue. |
| [#23](https://github.com/SebasHT15/firewall-IA/issues/23), final architecture docs | OPEN | Current continuity improves, but final architecture is still being built; retain for final specification and evidence. |
| #24/#25, final results / limitations | OPEN | Partial historical reports and this handoff do not complete final experimental reporting or reproducibility. |

Stages **#67, #70, #72, #74** and Analyzer milestones **#49, #51, #53, #56, #57, #59** are already
CLOSED. Do not reopen or close them again for work delivered in #79. Model 2, data-pilot and
training-authorization work need their own scoped follow-ups below.

GGUF/runtime #10–#14 and embedded #19–#22 remain open. Offline export diagnostics do not
complete deployment. In particular, #11's Q4_K_M target needs reconciliation with the owner
decision that Q4_K_M is not authorized; do not launch it from the old issue title. #27–#31
remain separate future-work items; this PR does not complete them.

## Suggested updates to existing issues (ready for owner review)

### #75 status text

PR #79 adopts the pinned Wikidata Q101352 LIMIT-20000 snapshot (SHA-256
`039882220480b029074243f740f4eec07646029a0b6de8ce70f99454686d3ead`). The local source-pool
rebuild accepts 12,104 family-name values, with no blocked source pools and passing survival
fixtures. Acquisition is resolved; the generator still excludes names_family from SLOT_POOLS.
The issue stays open for ratified cross-pool precedence, equivalence/SPL-6 checks, per-split
minima or refusal, and consumer integration. Evidence: `names_family-candidate/ADOPTION.md`
and provenance under `reports/v5/data-readiness/`. Do not repeat live WDQS acquisition.

### #77 status and criteria update

D66 approves deny-list v2. D67 adopts frozen r4 with disclosed AI-assisted third review,
not independent human validation. a1 and a2 have 453 annotations each; 217 unique records are
prepared for blind R3 (200 ∪ 33, overlap 16), not yet reviewed. r4 criteria are preregistered:
Wilson-95 upper INCORRECT ≤20%, U+I ≤35%, coverage 100%, zero gate-relevant unresolved cases
for acceptance. Denominators remain the original category counts in the 453 frame. No
small-category exception. SSRF is NOT SUPPORTED. Update old human-review gates to D67
without rewriting historical comments. A category pass never yields VERIFIED or FINAL
authorization. Keep this issue open until R3, adjudication and category reporting complete.

## New issues recommended (drafts; not filed)

### A. Enforce r4 audit provenance and separate FINAL training authorization

Labels: `feature`, `testing`, `priority:high`.

Problem: the active training gate predates r4 and does not encode all distinctions required
by D67. A candidate patch already exists in `reports/v5/data-readiness/proposals/`; apply
nothing implicitly. The detailed draft is `reports/v5/data-readiness/followup-issue-ai-audit-gate.md`.

Acceptance:
- Ratify the provenance, row-label and independent owner-authorization schema.
- Explicitly migrate the retired mandatory gate; reject ambiguous/unsupported protocols.
- FINAL rejects missing, invalid, tampered, foreign or insufficient authorization/provenance.
- PASS_AI_AUDITED cannot become VERIFIED through a category-level pass.
- Negative tests exercise refusal paths; legacy approved contracts remain covered.
- No training run or weight change is part of this issue.

### B. Validate combined Analyzer and Fast Path shadow runtime in the lab

Labels: `testing`, `performance`, `priority:high`.

Problem: unit/process tests establish isolation, but operational overhead and useful shadow
evidence remain unmeasured. This is not #37 deferred model validation or #38 active bypass calibration.

Acceptance:
- Pin lab workload, artifact hashes, settings and environment; no protected-test tuning.
- Compare observers off/on under the same V4 decision path; preserve exact classifier input
  and forwarding behavior under observer failure, timeout, busy and restart conditions.
- Report latency overhead by layer, throughput, memory, worker saturation/drops and status
  counts, with cold start separated. Record observations rather than claiming no overhead.
- Current gateway Fast Path remains CONTINUE without framing/canonical evidence; do not fake
  prerequisites to report operational bypass coverage.
- No active routing, policy approval or model-quality claim follows from this measurement.

### C. Integrate V5 source pools, identities, split and generator for a gated real-data pilot

Labels: `feature`, `testing`, `priority:high`, `blocked`.

Dependencies: #75 consumer acceptance, #77 category decisions, required template/constants,
quota/precedence and preregistration approvals. Independent stages are already delivered.

Acceptance:
- Pin inputs and all required approvals before a real build; missing prerequisites refuse.
- Carry audit provenance and row eligibility without relabelling AI-only evidence VERIFIED.
- Run the existing identity/split/generator gates on the actual approved configuration;
  report minima, leakage, cluster shares, evaluability and exclusions reproducibly.
- No silent substitute pool, invented approval, threshold relaxation or protected-set use.
- Report a pilot with limits; dataset freeze and FINAL training require their separate gates.

### D. Ratify and implement Model 2 BLOCK/DEFER contract and evaluation protocol

Labels: `feature`, `research`, `testing`, `priority:high`.

Starting proposal: `reports/v5/hybrid/model2-contract-proposal.md`. Production runtime,
early-block authority, training evidence and operating policy remain unapproved.

Acceptance:
- Ratify the output contract, evidence availability, C1/C2 boundaries and BLOCK authority.
- Support missing/invalid/unavailable evidence with DEFER-equivalent behavior; no ALLOW output.
- Establish representation compatibility, data partitions, evaluation protocol and source-specific
  reporting before fitting or choosing operating thresholds. Agreement with V4 is not ground truth.
- Define C1-only / optional-C2 comparisons without assuming the learned component adds value.
- Implement the approved contract and deterministic tests; train/evaluate only under its
  separately satisfied data/experiment gates. Initial integration remains observational.

Later, create a separate selective-fallback/orchestration issue once contracts and V5 readiness
are concrete. Do not open duplicate Fast Path or canonicalization issues now.

## PR #79 metadata

Title: **Integrate V5 data readiness, inference safety and hybrid shadow runtime**

Suggested labels: `feature`, `bug`, `research`, `testing`, `documentation`, `priority:high`.
No automatic `Closes #...` directive: no open issue's full acceptance is met by this PR.
Description should include the consolidation, EOS fix, default-off shadow hooks, r4/R3
preparation, family-name acquisition, unapplied gate proposal, actual test counts and local-only
evidence preservation. Add this documentation refresh as continuity work, not a new approval.
