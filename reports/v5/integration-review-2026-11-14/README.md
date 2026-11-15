# Final integration review — 14 November 2026

Codex reviewed the existing checkout and Claude's documentation handoff before preparing the
develop integration. This pass used retained evidence and CPU tests; it did not train a model,
start Docker/services, issue new attack requests or use GPU. The frozen measured runtime is unchanged.

## Validation

- **431 tests in 20 modules, zero skips, all pass.** [TESTS.json](TESTS.json) lists the exact modules
  and interpreters. Run each module in a fresh process with `<python> -m unittest <module>`.
  Data-plane and analyzer dependencies are intentionally separate; combined interpreter/module
  invocations are not equivalent. No broad protected-dataset discovery was performed.
- **451 frozen source hashes and 70 Model-2-bound immutable sources match.**
- Flag audit: **30 row hashes, 18 case/seal/score hashes, 30 clean runs, 260 H1 rows and
  20 target/arm comparisons** verified. [VERIFICATION.json](VERIFICATION.json) records the recount.
- An0nB0ard's three fixed-credential logins return their flag on all five arms. The candidate
  prevents 6/6 exploit flag retrievals and 3/3 credential disclosures, not nine flags or a dynamic
  extraction-to-login chain. Read [AUDIT_CORRECTIONS.md](../flag-acquisition-2026-11-14/run-1/AUDIT_CORRECTIONS.md)
  and [AUDITED_INTERPRETATION.json](../flag-acquisition-2026-11-14/run-1/AUDITED_INTERPRETATION.json).
- Existing excluded H2 evidence is retained: five Inf3ct arms, 105 rows, matching hashes and clean
  runs. Its [scope record](../flag-acquisition-2026-11-14/run-1/H2_SCOPE_RECORD.json) is separate from
  both primary H1 totals and the 13 November H2 subset.
- The publication inventory was scanned for private-key/token patterns and raw request/body fields
  in new JSON/JSONL. No matching keys, raw payload fields or token patterns were found. This is a
  bounded automated review plus file/schema inspection, not a universal absence-of-secrets proof.
  Two raw-text Model-2 cohorts and its coefficient artifact were excluded and preserved locally;
  [PRIVATE_ARTIFACTS.json](../model2-successor-2026-11-05/PRIVATE_ARTIFACTS.json) records their hashes.
  Four captured console files retain their original trailing padding under narrow .gitattributes
  rules; two generated historical matrices retain their final blank line. Source/current-documentation
  whitespace checks remain enabled. Final local-link review covered 306 targets; three historical
  anchors were rebound to archived CONTEXT without rewriting their historical content.

The initial combined test invocation encountered the repository's legacy `data_plane` module/package
collision and lacked analyzer numpy/scipy. A later invocation used one nonexistent test name.
These command/environment errors were resolved with existing modules and fresh processes in their
proper environments. No measured source was edited to turn a failing test green.

## Issue meaning and remaining work

[Integration resolution](../../../docs/integration_resolution_2026-11-14.md) maps the original criteria,
including #18/#38 timing gaps, V4 retirement (#65), and each #68 item. Completed implementation and
research are distinguished from not_planned design/scope retirements. Export/backend and embedded
#10–#14/#19–#22 remain pending. Scope retirement does not complete an academic deliverable.

V4's input-token vulnerability is unpatched. Its operational support/fallback is retired; entrypoints
remain for isolated historical reproduction. The current candidate denies on unavailable V5;
adopting V5 does not establish prompt-injection immunity.

## Reproduction boundary

The tests of real Model-2 artifacts need the already pinned local artifacts and analyzer packages;
the repository does not supply model weights. Full evidence verification needs the private case/run
paths listed in the evidence indices. Public reports supply hashes and bounded metadata, not raw
HTTP bodies, TLS keys, model weights or organic traffic. Source-only clones cannot replay private
experiments without those separately supplied inputs.
