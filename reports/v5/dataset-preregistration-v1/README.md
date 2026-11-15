# V5 dataset preregistration v1 — PARTIAL (owner ratification 2026-10-23, D71)

**Status: PARTIAL.** This records the §11.2 values **ratified by the owner on 2026-10-23 (D71)**:
`V5_CANDIDATE_TEMPLATE`, `PILOT_VOCABULARY` and the token budget `B=415`. The remaining §11.2 values stay
**PENDING the pilot** (stage 6) and must be added here, committed, **before the full build** (gate F4).
This file is NOT the complete preregistration until every §11.2 row below is resolved.

Branch `feat/hybrid-training-ready` (base `97b0be0`). Nothing here trains, builds or activates runtime;
V4 keeps authority. `AI_AUDITED/PASS_AI_AUDITED ≠ VERIFIED`; this ratification does not relax any gate.

## Ratified now (D71)

| Value | Ratified value | Source / evidence | Hash |
|---|---|---|---|
| **Prompt template** | `V5_CANDIDATE_TEMPLATE` (TinyLlama-Chat structure + owner candidate instruction 2026-10-13; `control_plane/v5_tokenization.py`) | D63 candidate; structure tested (`encode_prompt == apply_chat_template`) | spec r4 `54514850…` |
| **Vocabulary** | `PILOT_VOCABULARY` = `VOCABULARY_ALT_B` (alt B, pilot #70): 7 outputs | `control_plane/v5_output_contract.py` | — |
| **Token budget `B`** | **415** = `max_length` 512 − `template_overhead` 76 − `label_budget` 13 − `margin` 8 | `reports/v5/canonical-request-v1/tokenization_measurements.md`; measured on the base TinyLlama tokenizer (behaviourally identical to V4) | — |
| `max_length` / `margin` | 512 / 8 | ratified as the components of B=415 (D71); were provisional D56/D62 | — |

`PILOT_VOCABULARY` (alt B) outputs ratified:
```
ALLOW | Normal HTTP request with no attack patterns detected.
BLOCK | SQL injection payload detected.
BLOCK | Cross-site scripting payload detected.
BLOCK | Path traversal attack detected.
BLOCK | File inclusion attack detected.
BLOCK | Command injection payload detected.
BLOCK | Server-side template injection payload detected.
```

**Re-verification before FINAL (not a new decision):** `template_overhead`, `label_budget` and `B` must be
re-measured on the **V5 tokenizer artifact** when it exists (`scripts/dataset/measure_v5_template_budget.py`,
tokenizer-only). The ratified `B=415` is the candidate measured on the base tokenizer; if the V5 tokenizer
differs, the re-measured value is preregistered here and the recipe updated — a measurement, not a re-decision.

## Still PENDING (resolve at the pilot → add here before the build)

| §11.2 value | Section | Resolved when |
|---|---|---|
| Cluster-share WARN / BLOCK (candidate 2% / 5%) | §4.6 step 5, §7 C2 | pilot (stage 6) — measured cluster-share distribution; only tighten |
| `OVER_LIMIT` stop value (1% per category×class cell) | §5.5 | pilot |
| Fuzz-corpus size for I7 | §5.6 | generator stage 1 |
| All §7 acceptance thresholds (C-S1…C-S7, C-M3, C3, L6/L10/L11, post-filter INCORRECT ≤20% / U+I ≤35% / coverage 100% / 0 unresolved, n≥50, subsample ≥20) | §7 | pilot → prereg; owner-approved before R3 |
| Category distribution (primary / report-only; trained categories) | §2.3 | post-filter audit (§7) + evaluability |
| Host / scheme / form lists + navigation-role lexicon | §4.3 | generator stage 4 (labels), owner-reviewed, hashed in the policy table |
| Benign-oracle length `L` + signature list | §4.4 | pilot |
| Placement-mode shares | §4.2 | pilot |
| Per-source-file cap | §3.1 | pilot |
| Final third-party deny-list (file-by-file) | §3.1 | generator stage 2 (D66 v2 candidate exists) |
| Pilot size (10% of quotas) + pilot procedure | §7 | ratified with this preregistration |

## What this unblocks

With the template, vocabulary and B ratified, the recipe sections `template`/`vocabulary`/`token_budget`
are RATIFIED (`scripts/training/v5_training_recipe_v1.json`), so FINAL's F7 no longer flags them. The
**pilot** (an EXPERIMENTAL build of 10% of quotas) can proceed once there is a built provisional dataset
and a written `v5-experimental-authorization/v1` — the pilot then measures cluster-share, which is
preregistered here before the full build. Owner decision reference: D71.
