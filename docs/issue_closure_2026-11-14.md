# Issue disposition for the develop integration

**Final integration disposition:** [integration_resolution_2026-11-14.md](integration_resolution_2026-11-14.md)
and D87 supersede the proposed categories below. Completed work is separated from not_planned
retirements; original #18/#38/#65/#68 gaps remain explicit. The flag result is six prevented
flag retrievals plus three prevented credential disclosures, not nine prevented flags.

Prepared on 2026-11-14 from the prior read-only review and the current checkout.
This is a review checklist, not an assertion that any issue has been closed.
Evidence links describe local changes that must be included in coherent commits before claiming delivery.

Each row is categorised so Codex resolves the issue for its **real reason**, not administrative
convenience. Categories: **IV** implemented & verified in the measured lab scope · **RN** research
completed with a negative/limited result · **DS** design superseded/replaced · **FS** out of current
scope (future work) · **CP** acceptance criterion still pending. A category is not a closure; closing
still needs the staged diff, the evidence link and the issue's own reason.

| Issues | Category | Evidence | Remaining acceptance before closing |
| --- | --- | --- | --- |
| #23 | IV | README, CONTEXT, project_status, operation guides, D83–D86 | verify navigation/links and that the delivered files are staged |
| #24 | IV | 13 Nov report + **14 Nov flag campaign now incorporated** (README, project_status, challenge_apps, D86) | confirm both campaigns are referenced with separate denominators and preserved limits |
| #25 | IV | reproducibility, dependencies, private/public boundary in README/project_status/challenge_apps | state that a source clone supplies neither weights nor private campaign rows |
| #28 | IV | CRS comparator in the [13 Nov report](../reports/v5/architecture-campaign-2026-11-13/RESULTS.md) **and** in the [flag campaign](../reports/v5/flag-acquisition-2026-11-14/run-1/RESULTS.md) (CRS 6/9, misses header SSTI) | close only for this measured scope and version/config |
| #36 | IV | active app-bound Fast Path, evaluated (ablation + load) | reconcile the old scalar-score wording; it is the owner-directed app-contract policy, not the original heuristic score |
| #37 | IV | asynchronous auditor implemented; historical enabled runs measured | link those runs; state the final campaigns used audit rate 0; reconcile the obsolete suspicious-score field without hiding changes |
| #38 | IV | same-population Fast Path ablations + load | reconcile threshold-calibration wording; list denominator/overhead/percentile evidence; **retain any unmet criterion explicitly** |
| #83 | RN | Model 2 BLOCK/DEFER implemented and evaluated; unfavourable → withdrawn from the candidate | record the negative result and withdrawal; completing the research does not require retaining the component |
| #35 | DS | original non-ML heuristic score replaced (D83, #36) | resolve as not planned/superseded; do **not** mark implemented |
| #81 | DS | original V4-only shadow-observer experiment ≠ the later active campaign | retire explicitly if unneeded; do not claim the final campaign completed that experiment |
| #18 | CP | load reports exist | distinguish, against the exact original criteria: **(1)** no-Fast-Path/direct baseline, **(2)** *added* end-to-end latency (paired, not a subtraction of two arms' P95), **(3)** layer-specific P50/P95/P99, **(4)** throughput and cold start, **(5)** the 1,000 ms load SLO as a third, separate target. Do not close merely because load reports exist |
| #68 | CP | controlled-egress (`gateway-framing/v1`) implementation | map requirements **one by one** (adapter/raw-content, R1/P4/P9, limits, signals, HTTP/2, parser) to the implementation; **controlled egress does not attest to preservation of the original client wire bytes**; preserve/transfer each remnant explicitly, do not close the umbrella by inference |
| #65 | CP | V5 uses template-safe tokenization | V4's prompt-input security issue is **unresolved**; separate V4 from V5: either fix and validate V4, or explicitly retire supported V4 operation with a reason. **Using V5 does not fix V4.** V4 also lacks admission control |
| #10/#11 | FS | historical V4/smoke exports; Q4_K_M rejected | reconcile historical generation/diagnostic completion with the V5.1 **export objective**; a produced artifact did not approve Q4_K_M; keep a clear path to the final-model export |
| #12–#14, #19–#22 | FS | — | destination runtime, quantized evaluation and physical embedded work remain pending; see [future work](future_work.md) |
| #27/#29/#30/#31 | FS | proposals retained in [future work](future_work.md) | a `not_planned`/out-of-scope disposition needs an explicit scope rationale, **not** a completed label; these investigations were not performed |

Issue numbers above refer to [SebasHT15/firewall-IA](https://github.com/SebasHT15/firewall-IA/issues).

## PR and closure sequence

1. Claude's flag campaign is delivered ([run-1](../reports/v5/flag-acquisition-2026-11-14/run-1/), h1 only)
   and incorporated into the documentation; review its report, candidate identity, controls and hashes before staging.
2. Consolidate source, tests, public evidence and documentation. Exclude raw credentials/bodies,
   private keys, weights and disposable run directories.
3. Verify the final staged diff and appropriate checks. Prepare commits with a subject and body that
   explain the delivered behavior, evidence and limitations.
4. Open a single PR from `feat/hybrid-cascade-integration` to `develop`.
5. Resolve each accepted issue with its actual reason and links. Sebas opens `develop → main`.

Closing keywords in a PR description are interpreted only for a PR targeting the default branch.
Do not assume that merging to develop closes issues automatically:
[GitHub's issue/PR linking rules](https://docs.github.com/en/issues/tracking-your-work-with-issues/using-issues/linking-a-pull-request-to-an-issue).
No merge to main or blanket completed closure is part of this preparation.
