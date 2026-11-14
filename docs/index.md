# Documentation map

Start with the [README](../README.md), then the [current project state](project_status.md).

| Need | Document |
| --- | --- |
| Resume development and coordinate the integration | [CONTEXT](../CONTEXT.md) |
| Understand the current candidate, evidence and limits | [Project status](project_status.md) |
| Run the six laboratory applications and candidate arms | [Challenge apps](challenge_apps.md) |
| Read the 14 November flag-acquisition campaign (h1 only) | [Flag campaign run-1](../reports/v5/flag-acquisition-2026-11-14/run-1/RESULTS.md) |
| Understand TLS/H2, containers, attribution and isolation | [Local stack](local_stack.md) |
| Operate gateway modes and understand historical return to V4 | [Cascade gateway](cascade_gateway.md) |
| Deliver and verify a model/runtime candidate | [Candidate handoff](cascade_candidate_handoff.md) |
| Read approved technical decisions and recorded experiment status | [Decision log](../DECISIONS.md) |
| Prepare issue dispositions for the develop PR | [Issue closure review](issue_closure_2026-11-14.md) |
| Check final issue reasons, V4 retirement and unmet criteria | [Integration resolution](integration_resolution_2026-11-14.md) |
| Review independent final tests and retained-evidence checks | [Integration review](../reports/v5/integration-review-2026-11-14/README.md) |
| Review the 2026-11-14 documentation handoff to Codex | [Documentation handoff](DOCUMENTATION_HANDOFF_CODEX_2026-11-14.md) |
| Track research outside this integration | [Future work](future_work.md) |
| Read historical V4, Analyzer, dataset and benchmark details | [Technical reference](technical_reference.md) |
| Understand data provenance and redistribution | [Data sources](data_sources.md) |
| Understand evaluation rules | [ML evaluation](ml_evaluation_methodology.md), [External v1](external_test_v1_protocol.md) |
| Recover the previous landing page and session memory | [Historical README](history/README-through-2026-10-21.md), [historical CONTEXT](history/CONTEXT-through-2026-10-26.md) |

## Experimental evidence

The [13 November campaign index](../reports/v5/architecture-campaign-2026-11-13/README.md)
is the current architecture result. Earlier reports keep their original populations, candidate
versions and scope. Their old verdicts are not silently reinterpreted as final-model results.
Its [public audit records](../reports/v5/architecture-campaign-2026-11-13/audit/README.md)
include byte-identical copies of the independent audit, reciprocal review and metric coverage.

The [14 November flag-acquisition campaign](../reports/v5/flag-acquisition-2026-11-14/run-1/RESULTS.md)
is a separate experiment (h1 only), kept apart from the architecture metrics and their denominators.
Its [audit correction](../reports/v5/flag-acquisition-2026-11-14/run-1/AUDIT_CORRECTIONS.md)
separates prevented flags from credential disclosure and retains the excluded H2 exploration.

Frozen runtime/test manifests describe the measured sources. Subsequent documentation changes
do not change that experimental identity. Raw request bodies, credentials, run work directories,
private flag artifacts and model weights stay outside Git.
