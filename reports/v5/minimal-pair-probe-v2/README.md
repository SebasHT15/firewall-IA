# V4 minimal-pair probe v2 (`v5-minimal-pairs-v2`) — results

DEVELOPMENT DIAGNOSTIC. Benign-only, frozen V4 (greedy, unchanged `inference_core`). Pre-registered in
`PROTOCOL.md`; reviewed by an independent Sonnet audit (`PROTOCOL_REVIEW` findings applied) and a
single Opus methodological review (`OPUS_METHOD_REVIEW.md`); then frozen by `SHA256SUMS` before any
inference. Issue #62. This file does not change the raw results; it summarizes and interprets them.

## Freeze / run provenance

- Base commit at freeze (`git HEAD`): `1b952ce1e31ce1ee9998697ffaf30e93bc0f352e`.
- Pre-execution anchors (`SHA256SUMS`): PROTOCOL.md `77ab7e86…`, manifest.json `6975f480…`,
  cases.jsonl `bb05e640…`, generator `d7ba290e…`, runner `18cea1c8…`.
- V4 adapter `7bf16875…` (asserted, unchanged after run); `inference_core.py` `325e3149…` (asserted).
- Environment (`raw/run_meta.json`): python 3.12.15, torch 2.6.0+cu124, transformers 5.8.0,
  peft 0.19.1, device cuda (NVIDIA GeForce RTX 4090 Laptop GPU), greedy decoding.
- 767 classifications (590 unique texts + 59 repeats × 3). **Determinism: 0 divergences**
  (`deterministic: true`). Status: 590/590 `ok`, 0 invalid. Global decisions: 351 ALLOW / 239 BLOCK.

## Results (see `results_table.md`, `results.json`)

Effect classes are **direction-aware** and relative to the v2 content instability control
CONTROL-COV2, whose flip rate was **0.175 [0.073, 0.328]** — **MATERIAL** (CP lower ≥ 0.05), so the
effect bar is `C_hi = 0.328`. The control is **stratified**: `handle` 0.00, `prose` 0.00, `token`
0.00, **`json` 0.70**. So for form/query (non-JSON) domains the matched benign-instability baseline is
~0, while the JSON carrier is extremely unstable on its own; `C_hi = 0.328` is inflated by JSON. The
form/query effects below beat both the inflated 0.328 bar and their ~0 matched baselines.

| Question | Comparison | A→B / N | flip [95% CI] | class | reading |
|---|---|---:|---|---|---|
| A | `n_prose→n_street` | 22/30 | 0.73 [0.54,0.88] | STRONG (A→B) | street value flips |
| A | `n_prose→n_numfmt` | 5/30 | 0.23 [0.10,0.42] | WEAK (< C_hi, p=0.45) | digits/format alone do **not** |
| A | `n_numfmt→n_street` | 20/30 | 0.70 [0.51,0.85] | STRONG (A→B) | street beyond digits/caps |
| A | `n_prose→a_prose` | 3/30 | 0.10 [0.02,0.27] | WEAK (< C_hi, p=0.25) | field name `address` alone does **not** |
| A | `n_street→a_street` | 4/30 | 0.13 | WEAK, **UNTESTABLE** | ref already BLOCK 24/30 (value) |
| A | `n_prose→n2_prose` | 0/30 | 0.07 | WEAK (0 A→B) | rename `detail`→`remark` does **not** |
| B | `base→hash` (`#`) | 32/60 | 0.55 [0.42,0.68] | STRONG (A→B) | `#`(%23) flips |
| B | `base→punct` (`!`) | 32/60 | 0.53 [0.40,0.66] | STRONG (A→B) | `!`(%21) flips **equally** |
| B | `punct→hash` | 7/60 | 0.25 | WEAK, **UNTESTABLE** | no `#`-over-`!` specificity |
| C | `plain→apostrophe` | 37/75 | 0.49 [0.38,0.61] | STRONG (A→B), **heterogeneous** | see per-class |
| ctrl | `CONTROL-COV2` | 5/40 | 0.175 [0.073,0.328] | WEAK, **material** | instability bar; JSON stratum 0.70 |

Per-stratum (N=15 each):

- **B `base→hash`**: `generic` 14/15 (0.93, effect), `passlike` 14/15 (0.93, effect), `identifier`
  4/15 (0.27, indeterminate; ref mostly BLOCK), `json_text` 0/15 (literal `#`; ref 7/15 ALLOW,
  indeterminate — JSON baseline already blocks). `base→punct` mirrors it: `generic` 0.93, `passlike`
  0.47, `identifier` 0.27, `json_text` 7/15 0.47.
- **C `plain→apostrophe`**: `surname` 14/15 (0.93, effect — in-run positive control confirms v1),
  `contraction` 9/15 (0.60), `title` 8/15 (0.53), `possessive` 6/15 (0.40) — all `%27`, all effect;
  `place_json` 0/15 (0.00, **testable null** — literal `'` in JSON). Heterogeneous **because** of the
  JSON/literal class, not because of name vs non-name.

## Interpretation (FACT / CAUSAL EVIDENCE / HYPOTHESIS, this probe only)

**A — ADDRESS (resolved for this probe).** The address block is driven by the **street value
semantics**, not by the field name and not by mere digits/format:
- STRONG: `n_prose→n_street` (0.73) and `n_numfmt→n_street` (0.70) — a street-address value induces
  BLOCK whether the field is `detail` and even starting from a capitalised two-number non-address
  (`Bay 54 Shelf 32`).
- Field name `address` is **not** a material driver: `n_prose→a_prose` 0.10 (< C_hi, p=0.25), and the
  rename control `n_prose→n2_prose` is 0/30 A→B. H-A1 (FIELD-NAME) **not supported / weakened**.
- Digits/format alone are **not** sufficient: `n_prose→n_numfmt` 0.23 (< C_hi, p=0.45). H-A3 (FORMAT)
  **weakened**; H-A2 (VALUE-SEMANTICS, street) **supported**.
- `n_street→a_street` is UNTESTABLE (street under neutral `detail` already BLOCK in 24/30), which is
  itself the direct confirmation that the **value**, not the name, carries the effect.

**B — `#` CONTEXT (resolved: not `#`-specific).** `base→hash` (0.55) ≈ `base→punct` (0.53), and
`punct→hash` is null/untestable. So **the effect is not specific to `#`**: inserting `#`(%23) or
`!`(%21) into a benign form/query value induces BLOCK at the same rate. It is **context-dependent by
power, not by kind**: strong in `generic`/`passlike`, underpowered in `identifier` (reference already
mostly BLOCK). CAUSAL for form/query; the literal-`#` JSON stratum added no flip, consistent with the
effect tracking the **percent-encoded triplet** rather than the `#` glyph — but this is HYPOTHESIS
only (confounded with the JSON carrier, whose benign instability is 0.70).

**C — APOSTROPHE (resolved: not name-bound).** The apostrophe effect **generalizes across all `%27`
classes** — surname (0.93), contraction (0.60), title (0.53), possessive (0.40) — so the
name/surname-semantics hypothesis is **FALSIFIED for this probe**: non-name legitimate apostrophes
(contractions, possessives, titles) flip too. The surname in-run positive control reproduces v1. The
only null is `place_json` (literal `'` in JSON), confounded with carrier. So the effect is a **general
character effect across percent-encoded (`%27`) benign contexts**, not a surname effect.

**Cross-cutting (HYPOTHESIS, converging A-independent).** B and C converge: V4 over-blocks benign
values carrying **percent-encoded punctuation** (`%27` apostrophe, `%23` `#`, `%21` `!`) produced by
ordinary form/URL encoding of legitimate characters, **largely independent of field name and semantic
context**. The literal (JSON) forms behave differently, but that comparison is carrier-confounded and
the JSON carrier is itself highly unstable (control 0.70). This is the single most important input to
V5 benign coverage.

**Material JSON instability (FACT).** Swapping one benign JSON string value for another flips V4 in
7/10 control bases. V4's decisions on JSON bodies are highly unstable to benign content — a coverage
and stability gap V5 must address, and a reason JSON-stratum reads here are treated as descriptive.

## Reproduction

```
python3   scripts/evaluation/minimal_pair_probe_v2_cases.py --out-dir reports/v5/minimal-pair-probe-v2   # regenerates cases/manifest (byte-identical)
python3   -m unittest tests.test_v4_minimal_pair_probe_v2 -v
# freeze is reports/v5/minimal-pair-probe-v2/SHA256SUMS (verified by the runner before scoring)
python3.12 scripts/evaluation/run_v4_minimal_pair_probe_v2.py run     --dir reports/v5/minimal-pair-probe-v2   # ML env; writes raw/ once
python3   scripts/evaluation/run_v4_minimal_pair_probe_v2.py analyze --dir reports/v5/minimal-pair-probe-v2   # stdlib; writes results.json + results_table.md
```
