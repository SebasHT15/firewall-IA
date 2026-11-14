# PC integration resolution and retained acceptance gaps

Recorded by Codex on 2026-11-14 under Sebas's instruction to consolidate the PC result,
resolve issues with their actual reasons, prepare commits and open one PR to develop.
This is an engineering scope disposition, not supervisor approval or delivery of the
embedded objective. Original issue descriptions and historical reports are preserved.

The report [integration review](../reports/v5/integration-review-2026-11-14/README.md)
records validation. Flag conclusions use the [independent correction](../reports/v5/flag-acquisition-2026-11-14/run-1/AUDIT_CORRECTIONS.md).

## Disposition of the original issues

| Issues | Resolution for this integration | Reason and evidence |
| --- | --- | --- |
| #23 | completed | Current plane boundaries, stateless model, authorized inline role, diagrams, D83–D87 and operation are documented in README, project_status and cascade guides. |
| #24 | completed for the scoped experimental record | Published prior experiments, negative alternatives, architecture results/audit and separate flag primitives. A body of lab evidence, not completion of every future evaluation. |
| #25 | completed | Dependencies, artifact identities, private/public prerequisites, seeds/manifests, label and evaluation limits, omitted tests and future work are explicit. |
| #28 | completed | Pinned ModSecurity/CRS PL1, independent direct controls and same-case arm comparison in 13/14 November reports. No global superiority claim. |
| #36 | original scalar gate superseded; not_planned | Active app-contract routing is implemented/tested and measured (789/985 benign bypasses), but it is not the original suspicious-score threshold. D83 replaces that design; do not check obsolete criteria as implemented. |
| #37 | completed with explicit contract-field replacement | Bounded asynchronous audit and failure/saturation/overhead evidence exist. Rule/policy IDs replace the nonexistent suspicious score. See historical enabled runs and tests/test_cascade_ops.py; final audit rate 0 is disclosed. |
| #38 | original threshold-calibration deliverable superseded; not_planned | Same-population ablations and load support retaining app contracts. No heuristic scalar was calibrated and the full cold-start/paired added-latency matrix is not claimed. |
| #83 | completed research with negative result | BLOCK/DEFER contract, tests, gated fitting and evaluation delivered; successors/guards did not justify retaining Model 2. C2 remains optional, not a claimed fitted comparison. |
| #35, #81 | not_planned, superseded | Neither a non-ML suspicious score nor the original V4-only observer overhead campaign is the selected architecture. Historical implementation is retained. |
| #18 | not_planned, incomplete historical benchmark scope | Layer, gateway, direct and throughput measurements exist; a complete first V4/no-Fast-Path matrix with every original cold-start and paired-added-latency criterion is not accredited. Retained gaps are below; existing timing data remain valid within their scopes. |
| #65 | not_planned, V4 operational support retired | V4 is retained solely for historical reproduction. Its special-token input defect is not patched and no new steering diagnostic was run. The supported PC candidate uses V5.1; this does not fix V4 or prove immunity to textual prompt injection. |
| #68 | not_planned, original umbrella superseded by bounded integration | Adapter/canonical parsing/strict output/egress-bound integration exist. Original inbound-wire, contextual-signal and general H2/production requirements are not all met; exact map follows. |
| #27, #29, #30, #31 | not_planned, outside this PC delivery | Reserved CSIC study, held-out evasion, stateful classification and SIEM extension remain in future_work.md; none is marked performed. |
| #10–#14, #19–#22 | keep open | Selected-model export/backend/evaluation and physical embedded requirements/deployment remain the deployment workstream. Historical V4/smoke export is not V5.1 export. |

Completed here means delivered implementation/research/documentation in the referenced scope.
It does not mean merged to develop/main; the PR carries the actual integration state.
The not_planned dispositions preserve unfinished work rather than calling it complete.

## #18 and #38: exact performance boundary

Existing evidence: real-run-1/REPORTE_REAL.md §5 gives separate pipeline, service, direct API,
router, gateway and client timing; perf JSONL retains warmups separately. load-run-1/INFORME_CARGA.md
and candidate-trials-2026-11-01/INFORME.md include layer percentiles, throughput, enabled-audit
overhead and disagreements. The 13 November V5-only/direct/candidate ablations and load
provide a newer application population and a separate 1,000 ms client SLO.

Not accredited as one complete original deliverable: first-V4/no-bypass same-workload direct
and gateway baseline, all layer/path P50/P95/P99, first-inference/cold-load distributions,
and a declared paired per-request added-latency calculation. Subtracting independent-arm
P95 values is not P95 of added latency. A successor benchmark must identify load vs
first inference vs TLS warmup, model/artifact, app/workload, concurrency and quantile method.
This remains future validation, including the destination-runtime/embedded work under
#14/#22 where applicable; it is not an achieved ≤200 ms end-to-end claim.

## #65: retirement boundary

The current integration provides no supported operational fallback to V4. V4_ONLY,
CASCADE_OBSERVE and old entrypoints remain available solely to reproduce historical
experiments in isolation. Their presence does not confer support or a security fix.
The candidate does not silently roll back to V4 on V5 failure; it denies according to
its existing policy. Frozen V4 training/inference artifacts are unchanged.

Reintroducing supported V4 requires its own authorized DEV-only diagnostic, train/serve
tokenization fix, special-token invariant tests and revalidation. It also needs admission
control work. Closing #65 as retired/not_planned records this scope decision, not a claim
that a vulnerability ceased to exist. V5's template-safe tokenization protects special-ID
placement only; ordinary role-marker/prompt-injection robustness remains unmeasured.

## #68: original requirement map

| Original requirement | Delivered evidence / remaining boundary |
| --- | --- |
| mitmproxy raw_content adapter | canonical_adapter.py preserves dechunked/content-coded raw_content; None differs from empty. The active gateway decides the bound serialized upstream message. |
| R1 and validate_inbound_headers | Pinned mitmproxy 12.2.3, header-validation drift checks, strict http1_wire parser and gateway_framing tests. Egress attestation is not original inbound-wire byte preservation. |
| P4 target forms | gateway-framing/v1 explicitly rejects absolute/authority/asterisk forms in the active reverse deployment; scope tests cover these. Broader proxy forms remain unsupported. |
| P9 gzip member after NUL | Shared canonical decoder retains its documented superset semantics; historical differential and wire evidence remain. No new general production P9 approval or decoder revision is inferred. |
| HTTP/2 | nginx terminates TLS/H2 and forwards H1.1; the 13 November subset tests that deployment. The gateway parser itself does not support inbound H2/HTTP3. |
| Limits | Candidate pins B=415, max_bytes_per_token=48, max_decoded_body=19920; manifest enforces ≥48×B. Received-body and text/worker limits are explicit. A general RFC9659 8 MB zstd window policy is not accredited. |
| Status/policy | Scope rejects and canonical failures deny explicitly; unsupported never implies ALLOW. Fast Path refuses signals/unknown contracts, model errors deny. This is not approval of a broader production escape/media policy. |
| JWT/origin contextual signals | S-JWT-* and S-ORIGIN-CROSS are still DEFERRED_SIGNALS in canonical_request.py. Authentication/session/CSRF remain application responsibilities. General contextual integration is unfinished. |
| Decoder pins | requirements-v5-canonical.txt pins Brotli 1.2.0 and zstandard 0.25.0; data-plane requirements remain separate and mitmproxy is pinned. No global production-dependency acceptance is inferred. |
| I1 / I2 | Shared canonical_request.canonicalize, generator/adapter tests, canonical worker and measured gateway roundtrip/receipt evidence. Not an attestation to original pre-normalization client bytes. |
| Strict V5 parser | Fixed vocabulary/status contract and fail-closed router; invalid output is an error, not a detector TP. Vocabulary-safe public reasons are bounded separately. |

Future work retains the unfulfilled inbound-wire attestation, broader protocol support,
contextual signals, decoder-window/production-policy validation and performance requirements.
This transfer is explicit; no umbrella completion is inferred from egress binding.
