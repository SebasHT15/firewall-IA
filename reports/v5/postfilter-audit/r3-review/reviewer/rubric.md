# R3 audit rubric — V5 post-filter attack-pool audit (ratified, reused verbatim from round 1)

These class definitions are the **approved** pre-filter audit definitions used unchanged for annotators a1/a2
(`reports/v5/postfilter-audit/round-1/annotation_a1/README.md`). They are not modified for R3.

You classify each item **for its assigned `category`**, judging the payload **as extracted** (`payload_wire`;
`payload_logical` is the decoded view).

| Class | Definition |
|---|---|
| **VERIFIABLE** | A concrete, syntactically recognisable payload of the **assigned** category that would be malicious in a typical injection slot of that category; the mechanism can be pointed at. |
| **PROBABLY_CORRECT** | Plausibly a payload of that category but needs a specific context or sink (legacy parser, particular engine, decoding step), is a bare command/value, or is a fragment of a larger payload. |
| **UNCERTAIN** | Cannot tell from the text alone whether it is a working payload (e.g. malformed encodings, inert templated mutations). Not necessarily junk. **Use this whenever the context is insufficient to decide.** |
| **INCORRECT** | Not an attack payload (documentation prose, tool output, setup commands, placeholders, markdown/code residue, reference URLs, PoC source code) **or** a real payload of a different category (record `better_category`). |

Rules:
- Residue such as a trailing documentation label, a shell prompt, or a placeholder makes it **INCORRECT** even if a
  real payload is inside.
- When unsure, use **UNCERTAIN**.
- `failure_mode` is **required** for INCORRECT, one of:
  `prose, tool_output, placeholder, markdown_residue, setup_command, reference_url, wrong_category, truncated, encoding_garbage, other`.
- `better_category` only when the payload is real but belongs to another category; else null.
- Judge from the text alone. **Never execute, fetch, decode-and-run, or visit anything.**
