# firewall-IA — current working context

Checkpoint: **2026-11-14**, repository/documentation consolidation incorporating Claude's
delivered flag evidence ([flag-acquisition run-1](reports/v5/flag-acquisition-2026-11-14/run-1/RESULTS.md), h1 only).
Final Codex review: 431 scoped tests pass without skips; frozen sources are intact. Source,
public evidence and documentation are being delivered in four coherent commits for one develop PR.
The independent flag interpretation correction and D87 issue dispositions are authoritative over
the original handoff wording. Consult git/GitHub for the current commit and PR/issue states.
Read [project status](docs/project_status.md) for the candidate, measurements and limits.
The previous context is preserved in [historical CONTEXT](docs/history/CONTEXT-through-2026-10-26.md).
Its old current-branch and approval statements describe their original stage.

## Objective and ownership

- Sebas assigned Claude flag retrieval/control experiments and Codex repository/documentation work.
- Codex prepares documentation, issue evidence and coherent commits.
- Preserve runtime, policies, weights, apps and frozen 13 November evidence during this pass.
- Claude owns Docker, ports, GPU, app state and new flag runs; do not stop another owner's resources.
- No new model training is part of this consolidation.
- Final flow: one PR to develop after both deliverables; Sebas creates the later main PR.
- D87 adopts the PC-closeout issue dispositions; see docs/integration_resolution_2026-11-14.md.

## Git baseline for this pass

Checkout: /home/sebas/Desktop/firewall-IA.
Branch: feat/hybrid-cascade-integration.
HEAD: f61fa108aebe6e3431a32c36d0c3977b0a4f812a.
develop: ecba4c6d0a1ba44ba6d9dcec3fb81bdf0da723a6 (three committed changes behind HEAD).
Runtime changes and reports from 5–13 November remain local/untracked.
Recheck status before staging; do not use indiscriminate git add -A.

The old "only Sebas does Git" direction was superseded by his explicit instruction to Codex
to prepare commits and one PR. It does not authorize merging main or publishing services.

## Tested architecture

Candidate: fastv5-public-v3-headerguard-v2-20261111.
Mode: FAST_PATH_V5; arms fastv5 and fastv5_guard.
V5.1 and canonical-request/v1 unchanged; Model 2 absent from this active candidate.
App-bound positive-resource contracts; Inf3ct adds request-header-sink-guard/v2.
Flow: nginx TLS/H2 -> mitmproxy validation/canonicalization -> optional header guard ->
Fast Path -> V5.1 for CONTINUE -> egress guard -> app.

Manifest: reports/v5/fastv5-2026-11-11/manifest.EXPERIMENTAL.json.
Adapter digest: f101b2f1a8e849220adb0bd7948a4ab681579f0b3fac24629cdc1831c127c20c.
Apps commit: be8e4e8f1c6aa12a17430146d569870d96d43dd5 (sec-challenges/Web).
Freeze digest: ae1cf86fc7c3710f35014501fadbea0a0b03ad9e097fb2fd2bbc9d969b69e51d (451 files).

## Architecture evidence from 13 November

Public reports: reports/v5/architecture-campaign-2026-11-13/.
Independent audit: 1,640 evidence checks, no remaining discrepancies.
C1–C5 PASS is experimental acceptance within the measured lab scope, not supervisor/production approval.

Primary h1: 985 benign requests / 172 sessions; 65 attack sessions / 68 injection steps; 584 boundary probes.
Those benign observations contain 151 canonical texts, not 985 independent texts.
V5-only: FP 211; complete sessions 21; effects prevented 48.
Fast Path + V5.1: FP 3; complete sessions 169; effects prevented 48.
Candidate with guard: FP 3; complete sessions 169; effects prevented 63.
CRS: FP 0; complete sessions 172; effects prevented 50.
The direct control is not a detector.

Fast Path avoids 789/985 benign V5 calls (80.10%) at audit rate 0; 196 continue to V5.
Model reason exact-match: 30/45 adjudicated V5 true-positive injection steps.
Three benign V5 FP and two stored-HTML-via-header effects remain.
Header-SSTI rescues belong to the guard; benign recovery belongs to Fast Path.
HTTP/2 numbers refer to a three-app subset.
Final load: 32 workers, 20 s/point, three repetitions, SLO 1,000 ms and fixed ladder.
An0nB0ard: candidate 32 requests/s vs V5-only 16 under that protocol, not intrinsic GPU capacity.

## Historical findings

- V5.2 fixes four shared-validation FP but adds 13 FN; not selected.
- Model 2 broke benign root-route sessions and added no value in the six-app population.
- Initial Fast Path coverage was 0/130 habitual requests despite passing exact-fixture smokes.
- V4 lacks admission control and retains issue #65's prompt-input concern.
  Its operational support/fallback is retired; retained modes are for isolated historical reproduction.
- Background Fast Path audit is distinct from Model 2; historical enabled runs exist.
  Final audit rate 0 does not prove active auditing in that campaign.
- Q4_K_M was a diagnostic with unsafe V4 flips; no final V5.1 GGUF is delivered.

## Local source of truth and evidence boundaries

Coordination:
/home/sebas/Documents/Codex/2026-11-02/firewall-ia-cierre-pc-paper/coordination/architecture-2026-11-11

CANDIDATE.json, SOURCE_FREEZE.json, TEST_PROTOCOL.md, POPULATION_MANIFEST.json, RUNNER_MANIFEST.json,
AUDIT_FINAL.md and CROSS_REVIEW_CLAUDE.md record the closed architecture campaign.
Its old Claude/Codex DONE states are not the status of the new flag assignment.

Private architecture evidence:
/home/sebas/Documents/Codex/2026-11-02/fwlab-architecture-private/2026-11-11/test/

Preserve frozen reports and protected test boundaries. Later flag experiments are new evidence with
their own identities and denominators; do not overwrite the prior campaign.
Flag claims need direct controls, full response/oracle evidence and fixed replay chains.
A legitimate puzzle answer or login with an already known credential is not a WAF exploit.

Codex's final flag audit: candidate prevents 6/6 exploit-driven flag retrievals (CatP1cs/Inf3ct)
and 3/3 SQLi credential disclosures (An0nB0ard). Its fixed-credential login returns the flag on
every arm; no dynamic extraction-to-login chain was measured. Original metric values are retained
with AUDIT_CORRECTIONS.md. Existing five-arm Inf3ct H2 exploration (105 rows) is indexed separately,
not pooled with run-1 or the 13 November subset.

## Next steps

1. Deliver the reviewed commits through one develop PR and record actual issue states there.
2. Preserve run-1's audit-qualified H1 result, private artifacts and excluded existing H2 records.
3. Review/merge is separate from the measured lab verdict. Sebas makes the later main PR.
4. Continue the selected-model export/runtime and physical embedded work only under its own protocol.

Useful: [documentation map](docs/index.md), [current state](docs/project_status.md),
[issue review](docs/issue_closure_2026-11-14.md), [future work](docs/future_work.md).
