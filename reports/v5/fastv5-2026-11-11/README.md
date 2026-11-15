# FAST_PATH_V5 public-resource candidate (2026-11-11)

**Documentation update, 2026-11-14:** DEV and the frozen architecture campaign were completed on
13 November. See [the final results](../architecture-campaign-2026-11-13/RESULTS.md) and
[current project status](../../../docs/project_status.md). The candidate met C1–C5 in the declared
lab scope; this is not a production or academic scope approval. The old handoff notes below are
preserved as historical status and do not imply that validation remains pending.

**DEV integration validation in progress; not yet frozen, evaluated on TEST or promoted.** Claude resumed after its usage limit. The current shared states and checkpoint are authoritative; the earlier pause did not complete validation.

The new mode preserves the proxy, framing/canonical validation and delivery guard. It routes through an optional, application-bound header-sink rule, Fast Path, then the unchanged V5.1 service. Model2 is neither started nor called; its old artifacts and historical arms remain for reproducibility.

`manifest.EXPERIMENTAL.json` has model2=null and the same canonical contract, V5.1 adapter, recipe, vocabulary and decoder as the historical reference. `policies/*.public-v2.json` are reproducible public-resource policy documents, not measured results. Runtime configurations additionally bind the full application image identity and source-tree hash.

New challenge arms: `fastv5` and `fastv5_guard`. The latter adds a separately attributed Jinja header-sink rule only on Inf3ct; evaluate both on that app to isolate its effect. Direct, V5_ONLY and CRS are the comparators. Existing guarded/guarded_fast semantics are preserved.

Coordination and exact run contract:
`/home/sebas/Documents/Codex/2026-11-02/firewall-ia-cierre-pc-paper/coordination/architecture-2026-11-11/`

Read `CANDIDATE.json`, `RUNTIME_CONTRACT.md` and `CODEX_CHECKPOINT.md`. Claude owns Docker/GPU/ports, app/population controls and DEV validation. Resume there before freezing or opening TEST verdicts. No commit/push performed.

Current handoff: public-v3 + header-sink-guard/v2, 241 documented unit tests. DEV v3 revalidation and final campaign are pending. The original Claude session became idle; the automatic continuation failed HTTP401 (expired OAuth) before tools. See current CODEX_CHECKPOINT and CLAUDE_CONTINUE_NOW for resumption. No final results or promotion are claimed.
