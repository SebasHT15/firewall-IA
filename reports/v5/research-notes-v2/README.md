# V5 / Hybrid research notes v2 (2026-10-06)

**RESEARCH NOTES, not decisions.** Five read-only subagents produced these alongside the V4
minimal-pair probe (`reports/v5/minimal-pair-probe-v1/`). A sixth subagent's work, the review of
the probe's protocol, is in that folder as `PROTOCOL_REVIEW.md`.

What the subagents did not do:
- download or integrate any dataset;
- train or run a model (subagent F ran mitmproxy on loopback only);
- change any runtime file.

Every policy choice in these notes is an **owner decision not yet taken**. Claims marked
UNVERIFIED in a note are unverified.

| Note | Question | Headline |
|---|---|---|
| [B_datasets.md](B_datasets.md) | Benign data sources for V5 | open-appsec Legitimate **downgraded to EVAL-ONLY**: a live public FP benchmark, telemetry-heavy, with secret-shaped strings, already trained on by ModSec-Learn. GitHub and Stripe OpenAPI are **STRONG** for structure (MIT), with a value pool from real corpora. A reproducible OpenAPI-generation protocol is proposed |
| [C_analyzer_v3.md](C_analyzer_v3.md) | Analyzer v3 design | v2 failed by its input view and objective (encoding counts, endpoint length, V4's own labels). Recommended: C1, a deterministic engine first, then C2, a per-value L1-logistic on hashed n-grams, only if gates G0–G9 pass. Correction: "Treelite C99 export" is now Treelite import + TL2cgen |
| [D_decision_model_shadow_schema.md](D_decision_model_shadow_schema.md) | Shadow routing-data schema for BLOCK/DEFER | Four stores (structured event, sampled raw vault, blind adjudication, manifest); HMAC pseudonymisation; baselines B0–B3c; win criteria W1–W8; sample sizes (cap 1% needs ≥ 299 benign groups with 0 errors) |
| [E_verdict_only.md](E_verdict_only.md) | Verdict-prefix early stop | `^\s*(ALLOW\|BLOCK)\b\s*\|\s*\S` preserves **decision and status** by construction (proof + 200k fuzz), **not the reason**. 4 tokens minimum. Draft D56. Latency gain is a hypothesis until measured |
| [F_mitmproxy_dechunking.md](F_mitmproxy_dechunking.md) | Does mitmproxy de-chunk before `render_request`? | **FACT** (12.2.3, source + loopback test): yes. `Transfer-Encoding: chunked` is kept and no `Content-Length` is added. `Content-Length` bodies are passed unchanged. gzip is decoded, but the compressed `Content-Length` stays. `Expect` is stripped |

## Follow-ups noticed (not acted on)

- **B read an extra file.** Subagent B read one 1.9 MB derived sample published by the
  ModSec-Learn project (5,000 strings from open-appsec), kept aggregate counts only, and deleted
  it. It was outside the listed reads; the owner should confirm this was acceptable.
- **D: `control_plane/classifier_api.py` logs the first 200 characters of an invalid model
  output.** On real traffic that can quote the request. `hybrid_contracts.DecisionOutput`
  (ALLOW/BLOCK/UNCERTAIN + `confidence`) conflicts with a BLOCK/DEFER Decision Model and D50.
- **E: today's parser returns `ok` with an empty reason** for `"ALLOW | "`, which is stricter
  wording in D25 than the regex enforces.
