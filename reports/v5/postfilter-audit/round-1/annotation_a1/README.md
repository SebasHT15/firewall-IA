# Post-filter audit round 1 — LLM annotator a1 (blind to annotator a2)

You are annotator **a1**. Annotate every item of `packet.jsonl` in this folder (453 items) from the payload text alone.
Never execute a payload. Do **not** read: `../annotation_a2/`, `../../annotations_a2.jsonl`, `../../human_review/`,
`../../adjudication*.jsonl`, `../../report.*`, or the pre-filter audit labels in `reports/v5/freeze-prep/E_attack_pool_audit/`.

**Classes** (the pre-filter audit definitions, unchanged):

| Class | Definition |
|---|---|
| VERIFIABLE | A concrete, syntactically recognisable payload of the **assigned** category that would be malicious in a typical injection slot of that category; the mechanism can be pointed at |
| PROBABLY_CORRECT | Plausibly a payload of that category but needs a specific context or sink (legacy parser, particular engine, decoding step), is a bare command/value, or is a fragment of a larger payload |
| UNCERTAIN | Cannot tell from text alone whether it is a working payload (e.g. malformed encodings, inert templated mutations). Not necessarily junk |
| INCORRECT | Not an attack payload (documentation prose, tool output, setup commands, placeholders, markdown/code residue, reference URLs, PoC source code) **or** a real payload of a different category (`better_category` recorded) |

Judge the payload **as extracted** (`payload_wire`; `payload_logical` is the decoded view). Residue such as a trailing
documentation label, a shell prompt or a placeholder makes it INCORRECT even if a real payload is inside. When unsure,
use UNCERTAIN. `failure_mode` is required for INCORRECT, one of: prose, tool_output, placeholder, markdown_residue, setup_command, reference_url, wrong_category, truncated, encoding_garbage, other.

**Output.** Write `../annotations_a1.jsonl` (one JSON object per line, every `sample_id` exactly once):

    {"sample_id": "PF1-0001", "label_class": "VERIFIABLE", "failure_mode": null, "better_category": null, "note": "short reason"}

The coordinator records your model identifier in `../../annotators.json` (`a1.model`); annotator 1 and annotator 2 must be
different models (D58). LLM agreement is never human validation.
