# Independent human review — attack-pool audit (issue #64, D58)

**Purpose.** An independent human check of the LLM-assisted attack-pool audit. The two LLM annotations, Claude Sonnet and Claude Opus, agree well with each other. LLM-to-LLM agreement is **not** human validation (D58). This file gives a human reviewer a stratified, label-blind subsample.

## Blind protocol

- **Do not open** any of these files before you finish:
  - `../annotations.jsonl`
  - `../annotations_second.jsonl`
  - `../adjudication_overrides.jsonl`
  - `../adjudicated.jsonl`
  - `../coordinator_second_annotation.jsonl`
  - `../summary.json`
  - `../README.md` §5–§11
- Read only `../README.md` §4 for the class definitions.
- The CSV `human_review_sample.csv` is the fixed, label-blind sample. It is read-only, and the generator refuses to overwrite it. It has 95 rows. They were drawn by
  `python3 scripts/dataset/audit_v5_attack_pool.py human-sample` (seed `v5-attack-human-review-v1`):
  - 10 each from SQL injection, XSS, directory traversal, file inclusion, command injection, SSTI, SSRF and open redirect;
  - 5 each from NoSQL, CRLF and XPath.

  These are the categories V5 trains on (D57). Rows are interleaved, with no prior labels.

## Procedure (batches of 12; 8 batches, the last has 11)

1. **Show one batch.** Run
   `python3 scripts/dataset/audit_v5_attack_pool.py human-batch --batch N` for N = 1 to 8.
   - It prints, for each item, only the stable `sample_id`, the category, the source file and the payload.
   - It never shows a prior label.
   - On its first run it creates `human_labels.csv`, an empty template with one row per item and its batch number. The template is never overwritten.
2. **Record your decision.** Use one of two ways:
   - edit `human_labels.csv` directly in a spreadsheet or editor; or
   - reply in chat per item, for example `A0258: INCORRECT / placeholder — <reason>`. The coordinator then copies your words verbatim into `human_labels.csv` and does not change them.
3. **Columns to fill in** `human_labels.csv`:

   | Column | Values |
   |---|---|
   | `label_class` | `VERIFIABLE` / `PROBABLY_CORRECT` / `UNCERTAIN` / `INCORRECT`, as defined in `../README.md` §4. Judge the payload **as extracted**: residue such as a trailing documentation label, a shell prompt or a placeholder makes it `INCORRECT` even if a real payload is inside. Note in the justification when it would be recoverable |
   | `failure_mode` | Required for `INCORRECT`: `prose`, `tool_output`, `placeholder`, `markdown_residue`, `setup_command`, `reference_url`, `wrong_category`, `truncated`, `encoding_garbage`, `other` |
   | `better_category` | Only when the payload is real but belongs to another category |
   | `justification` | Your reason. Short is fine |

   When unsure, use `UNCERTAIN`; it is a valid answer, not a failure. Never execute a payload.
4. **Compare, only after all 95 are filled.**
   `python3 scripts/dataset/audit_v5_attack_pool.py human-compare` refuses to run while any row is empty or invalid. Once the review is complete, it writes `comparison.json`, which contains:
   - the agreement with the adjudicated LLM labels;
   - the human per-category rates, with Wilson intervals;
   - the full disagreement list.

   Disagreements are **not** resolved automatically, and a disagreement does not imply that either side is wrong. Earlier annotation files are never modified.

## How the result is used

The coordinator will compare the human labels with the adjudicated LLM labels and report:
- agreement, with Cohen's κ, on "usable vs not" and "INCORRECT vs not";
- every disagreement.

A material disagreement means the LLM audit cannot be relied on for that category. "Material" means the human INCORRECT share sits clearly above the adjudicated one, under the rule in DRAFT r3 §7. The post-filter acceptance gate (DRAFT r3 §7) also requires a human-reviewed subsample on the **filtered** pool; this review is on the **pre-filter** pool and does not replace it.
