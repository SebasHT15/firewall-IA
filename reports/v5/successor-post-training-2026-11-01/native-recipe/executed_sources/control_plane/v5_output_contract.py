"""V5 output contract: fixed vocabulary, template fingerprint and the strict output parser.

PROPOSED (D63; stage 2 issue). Nothing here is wired into the runtime: V4 keeps
`inference_core.parse_prediction` (D25). Stdlib only, no ML import.

Contract (D25, D4/D5, spec r3 §4.5):
- the model emits exactly one string of the ratified vocabulary, then its native EOS;
- the V5 parser accepts an output only if, after removing ASCII whitespace at both ends, it is
  EXACTLY one vocabulary string and generation stopped on EOS. There is no search, no
  case folding, no prefix match and no coercion: anything else is `invalid`, with a reason;
- `invalid` carries no decision. The data plane enforces it fail-closed (D4, D34), exactly as it
  does for V4 today. The parser decides nothing about traffic.

Vocabulary: ALLOW reuses the V4 contract string (`parse_dataset_v4.ALLOW_LABEL`); BLOCK strings are
the V4/D47 reason strings (spec §4.5 M-7). WHICH BLOCK strings are trained depends on the §2.3
category tiering, which is PROPOSED: both alternatives are listed and none is ratified.
"""

import hashlib
import json
from dataclasses import dataclass

ALLOW_OUTPUT = "ALLOW | Normal HTTP request with no attack patterns detected."

# V4/D47 reason strings (scripts/dataset/parse_dataset_v4.py), traversal and file inclusion separate (D49).
_BLOCK = {
    "sql_injection": "BLOCK | SQL injection payload detected.",
    "xss": "BLOCK | Cross-site scripting payload detected.",
    "path_traversal": "BLOCK | Path traversal attack detected.",
    "file_inclusion": "BLOCK | File inclusion attack detected.",
    "command_injection": "BLOCK | Command injection payload detected.",
    "ssti": "BLOCK | Server-side template injection payload detected.",
    "ssrf": "BLOCK | Server-side request forgery attack detected.",
    "open_redirect": "BLOCK | Open redirect payload detected.",
    "nosql_injection": "BLOCK | NoSQL injection payload detected.",
    "crlf_injection": "BLOCK | CRLF injection payload detected.",
    "xpath_injection": "BLOCK | XPath injection payload detected.",
}
_PRIMARY = ("sql_injection", "xss", "path_traversal", "file_inclusion", "command_injection", "ssti")

# Alternative A (PROPOSED): every category §2.3 plans to train, primary + report-only (11 strings).
VOCABULARY_ALT_A = (ALLOW_OUTPUT,) + tuple(_BLOCK[k] for k in _BLOCK)
# Alternative B (PROPOSED): primary categories only (6 strings); report-only categories not trained.
VOCABULARY_ALT_B = (ALLOW_OUTPUT,) + tuple(_BLOCK[k] for k in _PRIMARY)

# Owner's choice for the V5 PILOT (2026-10-14, issue #70): alternative B. A CANDIDATE, not FROZEN or
# APPROVED: each category stays subject to the post-filter audit (spec §7), and the final vocabulary
# is fixed only in the dataset preregistration.
PILOT_VOCABULARY = VOCABULARY_ALT_B

OK = "ok"
INVALID = "invalid"
_WS = " \t\r\n"


@dataclass(frozen=True)
class ParsedOutput:
    status: str               # "ok" | "invalid"
    decision: object          # "ALLOW" | "BLOCK" | None
    reason: object            # vocabulary reason text (without "ALLOW | "), or None
    invalid_reason: object    # None | "no_eos" | "empty" | "not_in_vocabulary"


def parse_v5_output(text, vocabulary, *, ended_with_eos):
    """Strict parser. `text` is the decoded generation without special tokens; `ended_with_eos`
    is False when generation stopped on max_new_tokens or any other bound."""
    vocab = frozenset(vocabulary)
    if not ended_with_eos:
        return ParsedOutput(INVALID, None, None, "no_eos")
    if text is None or not text.strip(_WS):
        return ParsedOutput(INVALID, None, None, "empty")
    out = text.strip(_WS)
    if out not in vocab:
        return ParsedOutput(INVALID, None, None, "not_in_vocabulary")
    decision, reason = out.split(" | ", 1)
    return ParsedOutput(OK, decision, reason, None)


def check_vocabulary(vocabulary):
    """A vocabulary is a non-empty tuple of distinct `ALLOW | x` / `BLOCK | x` lines with one ALLOW."""
    v = tuple(vocabulary)
    if len(set(v)) != len(v):
        raise ValueError("duplicate vocabulary entry")
    for s in v:
        if not (s.startswith("ALLOW | ") or s.startswith("BLOCK | ")) or "\n" in s or s != s.strip(_WS):
            raise ValueError(f"malformed vocabulary entry {s!r}")
    if sum(s.startswith("ALLOW | ") for s in v) != 1:
        raise ValueError("exactly one ALLOW entry is required")
    return v


def fingerprint(template, vocabulary):
    """sha256 over the exact template segments and vocabulary (UTF-8, canonical JSON)."""
    payload = {"system": template.system, "user_prefix": template.user_prefix,
               "assistant_prefix": template.assistant_prefix,
               "structure": "BOS system EOS user_prefix+content EOS assistant_prefix [output EOS]",
               "vocabulary": list(check_vocabulary(vocabulary))}
    data = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest(), data
