# Round 1 — completing the second LLM annotation (diagnosis and options, 2026-10-19)

> **SUPERSEDED 2026-10-20 — see `annotators.json` and `round_status.json`.** This document describes the interim
> Opus-5.5 path. The FINAL annotator 2 is `claude-haiku-5-5` at **453/453** (option A); the `claude-opus-5-5` run is the
> **supplementary partial** (377/453, descriptive only, never in the gate) under `annotation_a2_opus55_partial/`. The
> status line below is historical.

**Status:** `PENDING_ANNOTATION`, by owner decision (2026-10-19).
- Annotator a2 (`claude-opus-5-5`) has 377/453 valid labels.
- Batch 05 (76 items) is pending; see `annotation_a2/batch_05_interruption.json`.
- The `claude-opus-4-8` fallback labels are **excluded**: model results are not mixed.
- Nothing was relabelled, copied from a1, or retried further.
- The sample, the pools and D62–D66 are unchanged.

## Diagnosis

- **Safety-classifier stops occurred in 5 of the 14 annotation attempts.** They were all on the output side, after
  both reads had succeeded:

  | Annotator | Batch / attempt | Evidence | Outcome |
  |---|---|---|---|
  | a1 (Sonnet 5.5) | b06 | `stop_reason: refusal` in the transcript | recovered by the same model |
  | a2 (Opus 5.5) | b02 | `stop_reason: refusal` in the transcript | recovered by the same model |
  | a2 (Opus 5.5) | b05 attempt 1 | `stop_reason: refusal` in the transcript | not recovered |
  | a2 (Opus 5.5) | b05 attempt 2 | `stop_reason: refusal` ×2 in the transcript | then the harness fell back to Opus 4.8 |
  | a2 (Opus 5.5) | b06 attempt 1 | the agent's own hand-back only; no `refusal` stop reason in the transcript | not recovered |

  - The transcripts do not identify a triggering item.
  - The interruption is recorded at batch level and attributed to no record.
- **Opus 5.5 cannot complete batch 05 under the frozen protocol.** Getting labels from it would need a retry loop,
  rewording or splitting, all of which are excluded because they work around the filter.
- **Model availability** (checked from the transcript API field):
  - `claude-haiku-5-5`: available.
  - `claude-fable-5-1`: unavailable on this account (HTTP 429, out of usage credits).
  - Opus 4.8 can't be selected.

## Options compatible with D58

D58: annotator 1 and annotator 2 are LLMs of different models; discrepancies are adjudicated; the sample is unchanged.

| Option | What | D58 / validity | Cost and risk |
|---|---|---|---|
| **A (recommended)** | **New complete a2 = `claude-haiku-5-5` on all 453 items.** Same packets, template, batches and bounded protocol: at most one retry per batch, no fallback accepted, model checked per turn. **Pre-registered before any Haiku label exists.** Opus 5.5's 377 labels are kept as a supplementary, descriptive LLM annotation and never enter the gate | One model per annotator, both different from a1. a2 also differs from the coordinator, so either the owner or the coordinator can adjudicate (owner recommended) | Available now; about 6 agents. Haiku is a smaller model, so expect more UNCERTAIN labels and more disagreements to adjudicate. Same-provider limitation remains. A classifier stop on Haiku would trigger the stop rule, and the round moves to option B |
| B | **New complete a2 = an LLM from another provider**, run by the owner outside this harness with the same packets, template and output format. Raw responses and the model id from the API response are kept; the coordinator validates and collects | Strongest independence; removes the same-provider limitation | Needs the owner's runtime and credentials, which the coordinator does not handle. Weaker provenance unless raw API logs are kept. That provider may filter as well |
| C | Keep Opus 5.5 for 377 and take batch 05 from a different model | a2 would be two models: the same mixing the owner rejected | Not recommended |
| D | A person annotates batch 05 as a2 | D58 defines a2 as an LLM; this needs a new owner ruling. It also blurs the separation from the blind human review | Not recommended |
| E | Retry, reword or split for Opus 5.5 | Works around the safety filter | Excluded |

**Selection rule for A (pre-registration).**
- The a2 used in the gate is fixed **before** the run: `claude-haiku-5-5` for all 453 items, whatever its labels turn
  out to be.
- The Opus 5.5 partial annotation is reported descriptively only.
- Nothing is chosen afterwards by comparing which annotator "agrees better".
- **Implementation step:** move the Opus files to a supplementary slot (`annotation_a2_opus55_partial/`). This keeps
  the raw files and their hashes, and the sample and packets are not touched. Then rebuild `annotation_a2/` for Haiku
  with the identical packet.

## In parallel: blind human review (ready now)

- The materials are ready: 200 items, 17 batches, 20 per category, an empty template, and `human_review/README.md`.
- The review needs no LLM output, so it can start now.
- **Blindness note.** The owner has seen per-category LLM label counts (aggregates) in the session report. No item-level
  label has been shown. The reviewer must not open:
  - `annotations_*`, `annotation_a*/`, `discrepancy_sheet.jsonl`, `agreement_report.json`, `round_status.json`;
  - this file's companions.
