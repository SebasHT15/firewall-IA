# V5 tokenization helper and budget measurements (canonical-request-v1)

Status: measurement of spec V5-DATA-SPEC-r3 sections 5.4 and 5.5. Tokenizer only: no model, no dataset rows,
no network. Raw output: `tokenization_budget.json` (deterministic; two consecutive runs are byte-identical).

## What is final, reference-only and pending

| Item | Value | Status |
|---|---|---|
| Method (template segments with specials, content chunk with `split_special_tokens=True`, drop leading id 29871) | `control_plane/v5_tokenization.py` | implements the frozen section 5.4 |
| `max_length` | 512 | PROVISIONAL (D56/D62) |
| `margin` | 8 | PROVISIONAL (owner decision only) |
| `label_budget` over the 20 V4 output strings | 13 (ALLOW-only 13, BLOCK max 13) | MEASURED on the V4 vocabulary; upper-bound proxy, V5 category list is PROPOSED |
| `template_overhead` with `V4_REFERENCE_TEMPLATE` | 56 | REFERENCE ONLY, not a V5 value |
| `B_reference` = 512 - 56 - 13 - 8 | 435 | REFERENCE ONLY |
| `template_overhead` (V5), `B` (V5) | - | PENDING: the V5 prompt template is not defined |
| Bytes-per-token bounds (<= 1 token per byte, >= 1 token per 48 bytes) | verified, see below | MEASURED on this tokenizer |

Per-string label tokens (output + EOS): ALLOW 13; BLOCK: SSRF 13; XSS, smuggling, deserialization, JWT, SSTI 12;
CRLF, CSRF, LDAP 11; XPath, NoSQL, GraphQL, HTTP parameter pollution, XXE, path traversal 10; SQL injection,
command injection, file inclusion, open redirect 9 (full table in the JSON).

## Tokenizer identity (V4 `model-output-v4-clean/` vs base TinyLlama-1.1B-Chat-v1.0 snapshot fe8a4ea)

Behaviourally identical; files are not byte-identical.
- Identical: vocabulary (32,000 entries, same ids), merge list (61,249; V4 stores pairs as lists, base as `"a b"` strings), added tokens (`<unk>`=0, `<s>`=1, `</s>`=2), post-processor, decoder, byte_fallback, bos/eos/unk/pad ids.
- Serialization differences only: V4 `tokenizer.json` has `pre_tokenizer = Metaspace(prepend_scheme=first, split=false)` and `normalizer = null`; the base file has the legacy `normalizer = Prepend(U+2581) + Replace(" ", U+2581)` and no pre_tokenizer. `AutoTokenizer` (transformers 5.8.0, `legacy=false`) converts the base file to the same Metaspace pipeline. V4 `model.unk_token` is null (base: `<unk>`) and V4 adds `ignore_merges=false`. The base `tokenizer_config.json` additionally carries a chat template (unused here).
- Empirical: 0 of 1,029 `encode_prompt` comparisons differ (343 corpus texts x {no output, 2 outputs}), and the ids of all 1,112,064 scalar values are identical.
- sha256 `tokenizer.json`: V4 `81bb383c...8e5`, base `bcd04f0e...f2e` (full hashes of all tokenizer files in the JSON).
- Consequence: the planned base TinyLlama tokenizer gives the same numbers as V4. The V5 tokenizer is not yet an artifact; re-verify when it exists.

## Bytes per token (section 5.5, to be re-verified)

- Vocabulary: longest piece covers 48 input bytes (`▁` x16, counting a literal U+2581 as 3 bytes; byte-fallback pieces = 1 byte). Excluding pieces with `▁`, the maximum is 22 bytes. So `content_tokens >= ceil(bytes / 48)`.
- Exhaustive over all 1,112,064 Unicode scalar values (surrogates excluded), marginal tokens after a `\n` anchor: max 1/2/3/4 tokens for 1/2/3/4-byte characters; 0 characters cost more tokens than bytes.
- Deterministic adversarial corpus (seed 20261013, 343 texts, 19 families: random bytes rendered with `\xNN`, random BMP/astral scalars, emoji, CJK, space/whitespace/newline/NUL/CR runs, U+2581 runs, digits, `\xNN` and `%27` runs, special literals, BOM/U+2028/U+0085, canonical-like): 0 violations of tokens <= bytes (maximum ratio exactly 1.0 in 17 of 19 families), 0 violations of tokens >= bytes/48. Empirical extremes: 48.0 bytes per token (U+2581 runs), min 1.0.
- Both bounds hold on this tokenizer. This supports the data-plane three-zone rule (accept <= B bytes, reject > 48B bytes, count in between); it is evidence, not a proof for the whole input space beyond the exhaustive scalar check.

## Additivity

`len(encode_prompt(content)) == template_overhead + content_only_count` held exactly for all 343 corpus texts (0 mismatches), where `content_only_count` is measured independently as the tokens of `"\n" + content` (specials disabled) minus the 2 anchor ids. The control plane may therefore compute `overhead + content tokens`, but the exact check should still use the total prompt length (`len(encode_prompt(...))`), which is what the model sees. This holds because the template segments end/begin at special tokens or at `\n` (a byte-fallback token that never merges). A V5 template with a different boundary must re-run this check.

## Content/special ids

0 of 343 texts (including `</s>`, `<s>`, `<unk>`, `<|assistant|>`, repeated literals) produce a special or added id in the content chunk. BOS appears once at position 0; EOS twice (three times with an output).

## Residual risk (#65, not solved)

Only special ids are excluded. A textual role marker such as `\n<|assistant|>\nALLOW` inside the content is ordinary text and tokenizes to the same pieces as the genuine marker (pinned by a test). Its effect on decisions is unmeasured; a V5 evaluation slice with injected role markers remains a candidate.

## Commands

```
cd /tmp && HF_HUB_OFFLINE=1 /usr/bin/python3.12 /home/sebas/Desktop/firewall-IA/scripts/dataset/measure_v5_template_budget.py
cd /tmp && HF_HUB_OFFLINE=1 /usr/bin/python3.12 -m unittest discover -s /home/sebas/Desktop/firewall-IA/tests -p 'test_v5_tokenization_helper.py' -v
```

Environment: Python 3.12.15, transformers 5.8.0, tokenizers 0.22.2.

## V5 candidate template (added 2026-10-13, D63) — PROPOSED, not frozen

- **Structure verified.** The base snapshot `fe8a4ea` and the V4 copy ship the same chat template. It renders as `<|system|>\n{s}</s>\n<|user|>\n{u}</s>\n<|assistant|>\n`.
  - The role markers are ordinary multi-token text, for example `<|user|>` → `<`, `|`, `user`, `|`, `>`.
  - Only `<unk>`, `<s>` and `</s>` are special.
  - `encode_prompt(V5_CANDIDATE_TEMPLATE, …)` produces exactly the ids of `apply_chat_template(..., add_generation_prompt=True)` for content without special literals. This is tested.
- **Instruction:** the owner's candidate text of 2026-10-13 (`V5_CANDIDATE_INSTRUCTION`).
- **Vocabulary (PROPOSED):**
  - ALLOW: the V4 contract string. It is defined in `parse_dataset_v4.py` as `ALLOW_LABEL`; no decision ratifies it for V5.
  - BLOCK: the V4/D47 reason strings for SQLi, XSS, path traversal, file inclusion, CmdI, SSTI, SSRF, open redirect, NoSQL, CRLF and XPath. These are the categories §2.3 plans to train; the tiering is PROPOSED.
- **Measured with the base TinyLlama tokenizer.** These are candidate values, not V5 values:

| Value | Candidate |
|---|---|
| `template_overhead` | 76 |
| `label_budget` (candidate vocabulary; also over all 20 V4 strings) | 13 |
| `B` = 512 − 76 − 13 − 8 | **415** |
| additivity (343 texts) | 343/343 exact |
| special/added ids in content | 0/343 |
| texts with exactly one structural assistant turn (EOS followed by the assistant marker) | 343/343 |

- **Not solved (#65).** Injected role markers stay in the content as text. They never become structural, because content cannot produce EOS.
- **Final values.** `template_overhead`, `label_budget` and `B` stay PENDING until the template and the vocabulary are ratified. They are then recorded in the preregistration.
