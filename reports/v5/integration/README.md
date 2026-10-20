# V5 readiness and shadow integration — 2026-10-20

All reviewed changes are consolidated on `feat/v5-data-readiness` for one PR to `develop`.
The original development worktrees remain unchanged as local recovery copies. Git integration
does not authorize R3 execution, FINAL training, or hybrid enforcement.

## Continuity

PR #79 is open against `develop` at the 2026-10-20 checkpoint. Current project state and the
next-session prompt are in `../../../docs/continuity-2026-10-20.md`; issue disposition and
ready-to-file follow-ups are in `../../../docs/issue-plan-2026-10-20.md`. The root README,
CONTEXT and technical reference now point to this state. DECISIONS has a status note while
retaining every historical decision entry unchanged. These documentation changes do not
authorize an experiment, ratify a policy, or change any frozen evidence.

## Included behavior

- D67 and V5-DATA-SPEC-r4 ratification, frozen preregistration, post-filter audit tooling and
  preparation of 217 unique blinded R3 records. No R3 labels or category PASS are produced.
- Pinned family-name acquisition and provenance: 12,104 accepted values; source-pool build
  has no blocked source and passes its survival fixtures. Generator inclusion remains pending.
- The HF/PEFT gateway rejects truncated output using token-level EOS evidence. The response
  schema and complete-response behavior are unchanged; legacy text-only benchmark parsing
  retains its recorded semantics.
- An isolated Analyzer worker and a conservative Fast Path observer coexist in the gateway.
  Both ship off. V4 remains the only enforced decision. Fast Path remains ineligible in the
  current gateway because canonical ACCEPT and project-owned framing evidence are unavailable.
- The Model 2 proposal retains BLOCK/DEFER, C1 deterministic features and optional learned C2
  evidence. It is not an implemented decision model or a ratified enforcement policy.
- The proposed FINAL audit-provenance gate is preserved as an **unapplied patch** under
  `../data-readiness/proposals/`. Its authorization schema remains pending ratification.

## Validation on the consolidated tree

| Command/environment | Result |
| --- | --- |
| `python3.12 -m unittest discover -s tests -v` | 1,343 run; OK, 141 skipped |
| `.venv-dataplane/bin/python -m unittest tests.test_fast_path tests.test_data_plane_fast_path tests.test_data_plane_shadow_integration tests.test_data_plane_shadow_analyzer tests.test_data_plane tests.test_hybrid_shadow_process tests.test_canonical_request tests.test_canonical_request_limits tests.test_canonical_request_review tests.test_canonical_request_tokenization tests.test_request_features` | 408 run; OK, 2 skipped |
| `.venv-analyzer/bin/python -m unittest tests.test_hybrid_shadow tests.test_hybrid_shadow_process` | 83 run; OK, 2 skipped |

These runs overlap and must not be added into a distinct-test total. The extra environments
exercise mitmproxy and frozen Analyzer dependencies unavailable in the system test environment.
Combined-hook regression tests check unchanged V4 response, identical classifier input,
exactly one classifier call, failure isolation and a pending Analyzer alongside hypothetical
FAST_ALLOW. Existing dependency ResourceWarnings and deprecation warnings remain.

The first final-test attempt ran before network permission was restored: local socket tests
were denied, and one logging test reached its timeout. The permitted rerun above passed without
changing production code or relaxing test expectations. The initial general run was interrupted;
the complete permitted run is the result reported here.

Frozen specification/preregistration hashes and R3 checksums pass. All 59 excluded evidence
files match their preservation hashes and remain outside Git. Extracting the recorded evidence
archive into an empty scratch directory and rebuilding R3 reproduces all eight generated files
byte for byte. Only the R3 README checksum was refreshed for the integration-status wording;
review packets, membership, source hashes and sample selection are unchanged.

## Preservation and remaining work

Raw payload-bearing evidence and source snapshots remain outside Git under the existing data
policy. `../data-readiness/evidence-preservation-manifest.json` records the evidence archive,
checksums and restore procedure. The owner also has a verified archive of the pending work,
original patches and index states. Both archives are local to the same machine; this is not
an off-device backup. A fresh checkout needs the preserved evidence to reproduce the audit.

Remaining work: execute the authorized independent R3 review in a fresh reviewer session;
compute adjudication and category gates; resolve generator pool precedence and family-name
inclusion; ratify the training provenance/authorization contract before any FINAL training;
implement and verify wire framing and canonical gateway integration before Fast Path activation;
measure shadow overhead and evidence quality; implement and validate Model 2 and V5 fallback.
SSRF remains unsupported. None of these pending steps is claimed complete by this integration.
