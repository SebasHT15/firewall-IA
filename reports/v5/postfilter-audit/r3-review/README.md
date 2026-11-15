# R3 review materials — V5 post-filter audit (PREPARED, not executed)

Prepared under ratified **D67 / V5-DATA-SPEC-r4** (`54514850…`) and the sealed preregistration
(`../preregistration/v5-postfilter-prereg-r4.json`, `1039a3dd…`). **R3 has not run. No labels exist. No category is
PASS. FINAL training stays BLOCKED.** The commit containing the specification, preregistration and checksums anchors this preparation; raw review inputs are preserved separately.

## Populations (verified from record IDs)
Frame 453 · blind subset 200 · gate-relevant disagreements 33 · overlap 16 · **unique R3 records 217** (= 200 ∪ 33).
Each record is labelled once; the overlap is reused. Per-category Wilson denominators come from the 453 frame; the 33
add no separate denominator.

## Layout
- `reviewer/` — **give these to the fresh ChatGPT GPT-6 session only.**
  - `R3_PROMPT.md` — self-contained prompt (rubric inlined).
  - `rubric.md` — approved class definitions (verbatim from round 1).
  - `response_schema.json` — label + unevaluated response shapes.
  - `batch_01.jsonl … batch_05.jsonl` — 217 blinded packets (fields: sample_id, category, payload_logical,
    payload_wire, source_file). **No labels, no membership, no outcome clues.** Deterministic order by sample_id;
    batches of 50 (last 17).
- `coordinator/` — **COORDINATOR ONLY, never shown to R3.**
  - `coordinator_instructions.md` — execution, adjudication (D67 §6) and gate (C1/C2/coverage) contract.
  - `manifest.jsonl` — canonical manifest (provenance + `payload_wire_sha256`) per unique record.
  - `membership.json` — subset/disagreement/overlap flags and a1/a2 labels (for adjudication).
  - `integrity.json` — counts, uniqueness, membership relations, omission/duplicate checks, source hashes.
- `build_r3_review.py` — deterministic builder; reproduces every file above from the frozen round-1 artifacts.
- `SHA256SUMS` — checksums of the prepared artifacts (local verification only; **not** a Git anchor).

## Reproduce
`python3 -I reports/v5/postfilter-audit/r3-review/build_r3_review.py [--round1 <dir> --out <dir>]` rewrites the
materials deterministically; with no flags it defaults to the sibling `round-1/` and this directory. Point `--round1`
at the restored evidence bundle's `round-1/` when the source files are not present in the repo.

**The source files are REQUIRED — a hash does not substitute for them.** The builder's required inputs
(`sample.jsonl`, `annotations_a1.jsonl`, `annotations_a2.jsonl`, `adjudication_pending.jsonl`,
`human_review/human_review_sample.csv`) are not optional and, because they carry payload text, are kept out of Git and
delivered through the owner-preserved evidence bundle. When checking `SHA256SUMS`, use
`sha256sum -c --ignore-missing SHA256SUMS` ONLY to skip the five intentionally-excluded `reviewer/batch_*.jsonl` in a
repo-only checkout — never to mask a missing REQUIRED input: if an input is absent, regeneration must fail, not pass.

## Restrictions honored
No R3 execution, no labels, no training, no FINAL unblock, no threshold or sample-membership change, no frozen-evidence
modification and no SSRF restoration. Git integration does not authorize R3 or training.
