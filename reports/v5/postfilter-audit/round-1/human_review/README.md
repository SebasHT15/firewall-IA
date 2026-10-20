# Blind human review — post-filter audit, round 1 (V5-DATA-SPEC-r3 §7, D58)

**Purpose.** An independent human review of a stratified subsample: 20 items per category, 200 in total. On these
items, human labels prevail over the LLM labels (§7). Criterion 3 of the gate is this subsample's INCORRECT share,
which must be ≤ 20% (at most 4 of 20, PROPOSED).

**Blind protocol.** Do not open any of these until all 200 rows are filled:
- `../annotations_a1.jsonl`, `../annotations_a2.jsonl`;
- `../annotation_a1/`, `../annotation_a2/`;
- `../adjudication*.jsonl`, `../report.*`;
- the pre-filter audit labels in `reports/v5/freeze-prep/E_attack_pool_audit/`.

The subsample was drawn when the sample was drawn, before any LLM label existed (seed
`v5-postfilter-audit-r1-2026-10-19-d66/human`). `human_review_sample.csv` is fixed: the report refuses to run if its
SHA-256 changes.

## Procedure

1. Show one batch at a time. There are 17 batches of 12; the last has 8.

   ```
   python3 scripts/dataset/audit_v5_postfilter.py human-batch --round 1 --batch N
   ```

   Each item prints its `sample_id`, category, source file, wire form and logical (decoded) form. No label is shown.
2. Fill `human_labels.csv` in place, one row per `sample_id`, in a spreadsheet or editor. Alternatively, reply in chat
   per item; the coordinator then copies your words verbatim and changes nothing. For example:
   `PF1-0004: INCORRECT / prose — <reason>`.

   | Column | Value |
   |---|---|
   | `reviewer` | Your name or handle. **Required on every labelled row** |
   | `label_class` | `VERIFIABLE`, `PROBABLY_CORRECT`, `UNCERTAIN` or `INCORRECT`, using the class definitions in `../annotation_a1/README.md` (the definitions only; open nothing else there) |
   | `failure_mode` | Required for INCORRECT: `prose`, `tool_output`, `placeholder`, `markdown_residue`, `setup_command`, `reference_url`, `wrong_category`, `truncated`, `encoding_garbage`, `other` |
   | `better_category` | Only when the payload is real but belongs to another category |
   | `justification` | A short reason |

   - Judge the payload **as extracted**. Residue makes it INCORRECT; you can note in the justification when it would be
     recoverable.
   - UNCERTAIN is a valid answer.
   - Never execute a payload.
   - An empty row counts as **not reviewed** (PENDING). It is never filled with a default.
3. Run the report whenever you like. Categories stay `PENDING_HUMAN_REVIEW` until all of their 20 rows are labelled.

## Update (2026-10-19)

**Spreadsheet option.** `human_labels.csv` is now a self-contained review sheet:
- batch order;
- read-only `category`, `source_file`, `payload` (wire) and `payload_logical` columns;
- the fill-in columns `reviewer`, `label_class`, `failure_mode`, `better_category` and `justification`.

It contains no LLM label. Fill it directly; `human-batch` still works for terminal reading.

**Also do not open** until the review is complete:
- `../adjudication/`, `../adjudication_*.jsonl`;
- `../annotation_a2_opus55_partial/`;
- `../a2_completion_options.md`, `../round_status.json`, `../report.*`.

`adjudication-workbook --part 2`, which holds the items you are reviewing, is refused until all 200 rows are labelled.

**Blindness caveat.** During the coordinator session the LLM annotators' hand-backs, with item-level labels and notes,
were returned into the session transcript. If the reviewer read them, the review is not blind for those items.
Before starting, the reviewer either:
- records in `justification` of the first row: "did not read item-level LLM hand-backs"; or
- hands the review to an independent person who has not seen the session.
