# E. Verdict-prefix early stopping for V4: formal evaluation (research note v2)

**RESEARCH NOTE. Nothing here is a decision, an implementation, or a latency result.** No code
was changed, the GPU was not used, and no model was run. The checks were pure-Python regex checks
plus the V4 **tokenizer only** (`model-output-v4-clean/`, CPU, `CUDA_VISIBLE_DEVICES=""`). Scripts
were kept in the session scratchpad and are not part of the repo. Anything I could not check is
marked **UNVERIFIED**.

Builds on `reports/v5/research-notes-v1/README.md` §D. Object of study:

- **Parser (frozen, unchanged):** `EXTRACT_RE = r"\b(ALLOW|BLOCK)\b\s*\|\s*(.+?)\s*(?:\.|\n|$)"`,
  used with `re.search` → first match; `parse_prediction()` returns
  `(group(1).upper(), group(2).strip(), "ok")`, otherwise `(None, None, "invalid")`
  (`control_plane/inference_core.py`).
- **Proposed stop criterion `S`:** stop greedy generation as soon as
  `decode(new_ids, skip_special_tokens=True)` matches `^\s*(ALLOW|BLOCK)\b\s*\|\s*\S`.

Environment as pinned and installed: `transformers==5.8.0` (requirements.txt:24, and it is the
installed version), `tokenizers 0.22.2`, `torch==2.6.0`.

---

## 1. Parity: what holds and what does not

### 1.1 Theorem (decision and status parity)

Let `F` be the token sequence generated today, which ends at EOS or at `max_new_tokens`. Let `k`
be the first step at which `S` matches `t_k = D(F[:k])`, where `D` is the same decode call used
for the final text. Let `T = D(F)`. If `S(t_k)` holds, then `parse(t_k)` and `parse(T)` are
both `"ok"` and have the same decision. If `S` never matches, early-stop mode produces exactly
`F`, so the parity is trivial.

**Premises:**

- **P1, greedy prefix property.** Early-stop mode generates exactly `F[:k]`. The criterion runs
  after the token has been chosen and never touches logits (installed
  `generation/utils.py:2810-2822`: `argmax` → `cat` → `stopping_criteria(input_ids, scores)`).
  This is empirically supported: `baseline-local-v1` showed 3 runs bit-identical in decision and
  reason. It still needs the empirical gate in §6, because GPU determinism is measured, not
  proven.
- **P2, decode stability.** `T` begins with `t_k`, except that **the last character(s) of
  `t_k`** may differ when they come from an incomplete byte-fallback run (see §3.2). Even then,
  the character at that position in `T` is never `\n`.
- **P3, identical flags.** `S` and `EXTRACT_RE` are `str` patterns with the same flags, and `S`
  decodes with the same function and `skip_special_tokens` value as `classify_timed()` (`True`).

**Proof sketch** (Python `re` semantics, below):

1. `^\s*` puts only whitespace before the verdict, so the verdict starts at the beginning of the
   string or after a `\W` character. EXTRACT_RE's leading `\b` therefore holds there.
2. No match can start earlier, because whitespace contains no `A` or `B`. `re.search` returns the
   first location, so this is EXTRACT_RE's match, and `group(1)` is fixed by `t_k`, which is
   identical in `T` up to `\|\s*` (P2).
3. The character after `\|\s*` is `\S`, so it is not `\n`. In `T` it is still not `\n` (P2).
   `.` matches every character except `\n`, and the lazy `(.+?)` keeps extending until it reaches
   `\.`, `\n` or `$`, which always exists. So the match succeeds for **any** continuation.
4. Both texts are therefore `"ok"`, with the same `group(1)`. ∎

**Empirical checks (pure regex):**

- 200,000 random token strings over an adversarial alphabet: `ALLOW`, `BLOCK`, `ALLOWED`, `|`,
  space, `\n`, `.`, `é`, NBSP, U+2028, `\r`, `\t`, U+FFFD, `_`, …
  - Each string was cut at the first prefix where `S` matches: **0 decision mismatches and
    0 status mismatches** in 1,941 stops.
  - The reason differed in 1,181 of those 1,941 stops (61%).
- 2,880 byte-fallback substitution cases, where a partial U+FFFD resolves to NBSP, U+2028,
  U+2029, U+0085, U+3000, `é`, or U+FFFD followed by `\n`, plus suffixes: **0 mismatches**.

### 1.2 Field-by-field parity

| field | parity? | note |
|---|---|---|
| `decision` | **yes, by construction** (P1–P3) | |
| `status` | **yes, by construction** | stopping happens only on texts that are already `ok`; non-stopping texts are byte-identical |
| `reason` | **no** | For canonical outputs the captured reason is the **first reason token** (`"Normal"`, `"C"`, `"Server"`, `"X"`, `"In"`, `"J"`, `"L"`, `"No"`, …). That is 0/19 canonical reasons equal to the EOS reason. |
| raw text | no | it is a prefix (modulo §3.2) |
| `generated_tokens` | no | 4 for canonical outputs, against 9–13 today |
| `stopped_on_eos` | **semantics break** | `n_new < max_new_tokens` would report `True` for an early stop; it needs a `stop_reason` |

The first reason token cannot even stand in as a category, because it is **not injective**:

- `▁C` covers both CRLF and CSRF;
- `▁Server` covers both SSRF and SSTI.

D19 level 2 (category) **cannot be computed** from an early-stopped output.

### 1.3 Counterexamples: variants that break parity

These were found with the same fuzzing harness.

| variant | counterexample (partial → full) | effect |
|---|---|---|
| stop at the pipe, `^\s*(ALLOW\|BLOCK)\b\s*\|` | `"ALLOW\|"` (invalid) → `"ALLOW\|� ALLOW\|"` (ok) | 2,105 status and decision mismatches in fuzzing. It also turns a would-be invalid `"ALLOW \|\n"` into a stop on an invalid text, so it is unusable. |
| unanchored, no leading `\b`: `(ALLOW\|BLOCK)\b\s*\|\s*\S` | `"éALLOW\|\nALLOW"` → parse is invalid (the `\b` before the first ALLOW fails), but the full text `"…\|\|�ALLOWED"` is ok | status flips |
| first token only (`AL` / `B`), or first two | `ALLOW BLOCK \| x` → BLOCK today; `ALLOWED \| x` and `ALLOW \|` are invalid today | decision and invalid parity lost (research-notes-v1 §D) |
| `S` decodes with `skip_special_tokens=False` while the final decode uses `True` | `AL LOW ▁\| <unk>`: `S` sees `"ALLOW \|<unk>"` and stops; the final text `"ALLOW \|"` is **invalid**, while the full run might be `"ALLOW \|x"`, which is ok | status flips (towards fail-closed, but still a parity break) |
| `S` with `re.ASCII` | no counterexample found (0/1,560). The characters adjacent to the verdict that matter are ASCII in both semantics. | still not recommended: keep the flags identical to EXTRACT_RE (P3) |

### 1.4 Edge cases (current parser, measured)

| text | parse today | `S` stops? |
|---|---|---|
| `"  ALLOW \| x"`, `"\nALLOW \| x"`, `"\xa0ALLOW \| x"` | ALLOW ok | yes |
| `"ALLOW\|x"`, `"ALLOW\xa0\|\xa0x"` | ALLOW ok | yes |
| `"ALLOWED \| x"`, `"ALLOW_ \| x"`, `"allow \| x"`, `"xALLOW \| y"`, fullwidth `"ＡLLOW \| x"` | invalid | no |
| `"ALLOW \|"`, `"ALLOW \|\n"` | invalid | no |
| **`"ALLOW \| "`, `"ALLOW \|\t"`, `"ALLOW \|\r"`, `"ALLOW \| \n"`, `"ALLOW \| \xa0"`** | **ALLOW ok, reason `""`** | no; continues to EOS, so parity holds |
| `"ALLOW BLOCK \| x"`, `"The ALLOW \| y"`, `"ALLOWé \| x. BLOCK \| y"` | first later match | no; runs the full generation, so parity holds and only the latency gain is lost |
| `"BLOCK \| x. ALLOW \| y"` | BLOCK | yes, BLOCK |
| `"ALLOW \|\| x"`, `"ALLOW \| \|"`, `"ALLOW \| ."` | ok, reasons `"\| x"`, `"\|"`, `"."` | yes |
| `"ALLOW \| \n BLOCK \| y"` | ALLOW ok, reason `"BLOCK \| y"` (`\s*` crosses `\n`) | yes |

**Finding independent of this proposal.** The current parser already returns `status "ok"` with
an **empty reason** whenever the pipe is followed only by whitespace other than a lone newline,
for example `"ALLOW | "`. Research-notes-v1 says "`ALLOW |` is invalid". That is true without a
trailing space and false with one. It is not exercised by V4 (0 invalid or empty reasons in
18,618 baseline samples), but D25's statement "reason populated when ok" is not strictly
guaranteed by the regex.

## 2. Can early stopping turn invalid into valid, or valid into invalid?

**No, for `S` as specified (P1–P3).**

- Every stop happens on a text whose parse is `ok`, and that `ok` is shown in §1.1 to be the
  same as at EOS. A text that would be invalid at EOS therefore never contains an `S`-prefix
  (contrapositive).
- Outputs where the first match appears later are not anchored, so they run the full generation
  unchanged.

**Defence in depth (recommended):** after an early stop, assert
`parse_prediction(text).status == "ok"`. If the assertion fails, report `status: "invalid"`
(fail-closed) and log `stop_reason`.

**Empirical limit.** `baseline-local-v1` has **0 invalid outputs**, so the eval split cannot
demonstrate invalid parity. That must come from CPU unit tests with a scripted fake model that
emits chosen token sequences (byte-fallback runs, `<unk>`, `▁`, `<0x0A>`, `ALLOWED`, and so on).

## 3. Interaction with greedy decoding, HF StoppingCriteria and the tokenizer

### 3.1 HuggingFace generate (installed 5.8.0, source read)

- **Interface:** subclass `StoppingCriteria`; `__call__(input_ids, scores, **kwargs)` returns a
  `BoolTensor`.
  - The code returns shape `(batch,)`, for example `EosTokenCriteria`:
    `torch.isin(input_ids[:, -1], eos)`.
  - The docstring says `(batch_size, 1)`. This is an inconsistency in the HF docstring; follow
    the code.
- **When it is checked:** once per step, **after** the new token has been appended
  (`utils.py:2817-2822`). `input_ids` **includes the prompt**, so the criterion must slice from
  `prompt_len`. The stopped output therefore ends on the first reason token, with **no EOS**.
- **Merging:** a custom `StoppingCriteriaList` is merged with the defaults
  (`MaxLengthCriteria`, `EosTokenCriteria`); the code is at `utils.py:1281-1340`.
  - The docs page says "an error is thrown" if a criterion of the same type is passed twice.
  - The installed code **warns and keeps the custom one**.
  - Either way, a new class is simply appended.
- **`stop_strings` / `StopStringCriteria` is not suitable.** It matches literal strings and
  cannot express the `\b … \S` condition, so it would reintroduce the pipe-only counterexample.
- **Cost:**
  - Each step needs the new ids on the host (`.tolist()` → device-to-host copy plus sync). The
    loop already syncs every step: `this_peer_finished = unfinished_sequences.max() == 0`, then
    `elif this_peer_finished:` in `_has_unfinished_sequences` evaluates a tensor as a bool. So
    the added sync is probably cheap. **UNVERIFIED until measured.**
  - Decoding at most 4 tokens costs roughly 0.07 ms (the baseline mean decode time for 9–13
    tokens).
  - Cheap pre-filter that does not change semantics: evaluate the regex only once at least 2
    new tokens exist.
- **Greedy:** `do_sample=False` → `argmax`. The criterion does not affect which tokens are
  chosen. The prefill / decode structure is unchanged.

### 3.2 Tokenizer and incremental decode (V4 tokenizer, CPU)

- **Decoder chain:** `Replace(▁→' ') → ByteFallback → Fuse → Strip(' ', 1, 0)`, with Metaspace
  `prepend_scheme: first` and `byte_fallback: true`.
- **Strip** removes one leading space from the **whole** string, in partial and final decodes
  alike, so it is stable. `^\s*` absorbs any remaining leading whitespace.
- **Byte-fallback runs are the only non-prefix case** (measured):

  | ids appended to `AL LOW ▁\|` | decode |
  |---|---|
  | `<0xC2>` | `'ALLOW \|�'` |
  | `<0xC2><0xA0>` | `'ALLOW \|\xa0'` |
  | `<0xE2><0x80>` | `'ALLOW \|��'` |
  | `<0xE2><0x80><0xA8>` | `'ALLOW \| '` |

  So `S` **stops on a partial U+FFFD**, while the full decode at that position could be
  whitespace (NBSP, U+2028). The parse is still `ok` with the same decision: `.` matches those
  characters, and a UTF-8 lead byte never becomes `\n` (§1.1, 0/2,880). Only the reason (`"�"`
  versus whatever follows) differs.
- **Special tokens:** `</s>` and `<unk>` vanish with `skip_special_tokens=True` and appear
  literally with `False`. This is the P3 counterexample in §1.3.
- **Canonical token sequences** were obtained by tokenizing training-format strings. All 19
  eval outputs have:
  - `AL`(1964) `LOW`(27998) or `B`(29933) `LOCK`(21339);
  - then `▁|`(891);
  - then `▁<first reason token>`.

  `decode(prefix) == output prefix` and `decode(full) == output` hold for all 19.
- **Evidence that the model emits exactly this tokenization:** in all 18,618 baseline steady
  samples, `generated_tokens` equals the tokenizer length of the canonical output plus EOS
  (18,618/18,618). This is consistent with, but not proof of, identical ids; the baseline did not
  store raw ids.

## 4. Minimum text and the decision-only alternative

### 4.1 Minimum for the current parser

The minimum is **4 tokens = 4 forward passes (1 prefill + 3 decode)**: `AL LOW ▁| ▁X`. The
fourth token is necessary: stopping at `▁|` is not parity-preserving, because `"ALLOW |"`
followed by `\n` or EOS is invalid today.

| | today (baseline, incl. EOS) | with `S` (canonical outputs) |
|---|---|---|
| ALLOW | 13 tokens (9,579/9,579) | 4 |
| BLOCK | 9–13 tokens | 4 |

### 4.2 Offline extrapolation (hypothesis, not a result)

OLS of `generate_ms` on generated and prompt tokens over the baseline steady samples
(n = 18,618) gives:

- **18.2 ms per generated token**, intercept 11.5 ms, 0.023 ms per prompt token;
- per run: 17.4 / 17.8 / 19.6 ms per token.

Plugging in 4 tokens gives a predicted `generate_ms` P50 of about 88–89 ms and a P95 of about
91–93 ms for both decisions.

This is **an extrapolation outside the observed 9–13 token range**. It is confounded by thermal
state (run-to-run variation is 11%), and the cost of prefill alone was never measured separately.
**No latency claim.** It is also lower than the 100–120 ms guess in v1 §D; both are hypotheses.

### 4.3 A decision-only contract

The option is to retrain so the output is `ALLOW</s>` / `BLOCK</s>`, or to stop at `\b` after the
verdict.

- **Gain:** at most 1 forward pass (≈ 18 ms by the same extrapolation). `AL LOW` plus one
  lookahead token is still needed to establish `\b`: `ALLOWED` and `ALLOW BLOCK` exist.
- **Cost:**
  - a new model;
  - D19 level 2 is lost permanently;
  - the V4 baseline is invalidated;
  - a new evaluation is required.
- A one-pass logit comparison (`AL` against `B`) is a **different classifier**. It also removes
  the invalid state by construction, which weakens D25 / D4 (coercion).

**Verdict:** not worth it for V4. If V5 is retrained anyway, its contract could be designed
verdict-first, with the reason optional or behind a separate head. That would be a V5 decision.

## 5. Contract change needed (draft, NOT written to DECISIONS.md)

The proposed number is **D56** (next free; DECISIONS.md ends at D55). It amends **D25**: "when
`status == ok`, decision **and reason** are populated". It must also be reconciled with **D5**
(termination by native EOS), **D19**, **D32** and **D36**.

Draft wording:

> **D56 — Verdict-prefix decoding mode for V4 (runtime only).**
>
> - **Modes.** `inference_core` gains `decoding ∈ {"full", "verdict_prefix"}`, default `"full"`.
>   In `"verdict_prefix"` mode, greedy generation additionally stops when
>   `decode(new_ids, skip_special_tokens=True)` matches `^\s*(ALLOW|BLOCK)\b\s*\|\s*\S`, using
>   the same decode call and flags as the final text. `EXTRACT_RE` and `parse_prediction` are
>   unchanged.
> - **Reason semantics.** In `verdict_prefix` mode the reason is **not generated**. `/classify`
>   returns `status`, `decision`, `reason: null`, `decoding: "verdict_prefix"` and
>   `stop_reason ∈ {"eos", "verdict_prefix", "max_new_tokens"}`. The truncated first-token text
>   is never returned as a reason; it is not a category (`▁C`, `▁Server` are ambiguous).
>   Optional: log it, labelled `reason_prefix`.
> - **What stays.** The ok/invalid semantics of D25 and the fail-closed policy of D4 are
>   unchanged. The Data Plane already accepts `reason=None` (`data_plane.py:167-168` only gates
>   on `status` and `decision`). Invalid stays `200 status:"invalid"`, which becomes a fail-closed
>   503. If the post-stop parse is not `ok`, the output is reported invalid.
> - **Scope.** Evaluation (D19, `test_model.py`), External runs and research captures
>   (`paired_dev_capture.py`, `v4_analyzer_disagreement.py`, `external_v1_run.py` read
>   `reason`) stay in `full` mode. The mode is a deployment choice recorded in every response
>   and log line.
> - **Gate.** Activation requires a passed parity gate and a measured benchmark (D32 identities).
>   This is not a model change and does not touch the V4 baseline.

D5 is not reopened: D56 adds no stop token.

## 6. Clean benchmarking

1. **Identities (D32).**
   - `v4-full-local-v2` is a fresh control arm. `baseline-local-v1` stays immutable and is
     **not** the comparand, because of thermal state and run order (an 11% effect).
   - `v4-verdict-prefix-local-v1` is the treatment arm.
   - Add `decoding_mode` and `stop_criterion` (the regex text and flags) to `protocol.json` and
     to the environment/identity record. The comparator treats it as *the declared treatment*,
     never as a silent difference.
   - Timing scope stays `generate-only/device-synchronized/v1`. The D36 figure is
     `steady_pipeline_p95_ms`.
2. **Workload.**
   - `datasets/v4_clean/eval.jsonl` (6,206 rows, manifest-hash verified), labelled **"latency
     workload only"** (no model selection on it).
   - Add the paired dev set (issue #59) and the 135-case manual suite **for parity only**.
3. **Design.**
   - Smoke (throwaway id), then an in-process **paired ABBA**: for row *i*, run A→B when *i* is
     even and B→A when it is odd. Both arms use identical instrumentation; HF keeps no prefix
     cache between `generate` calls (**UNVERIFIED**, so check it).
   - Then the formal protocol: **≥ 3 fresh processes per arm, interleaved A B B A B A**, with GPU
     temperature, power and clock recorded before and after each run, and a cool-down or
     comparable start temperature.
   - Warm-up: the same seed-42 rows, 1 cold-start sample plus 4 warm-ups per process, excluded
     from statistics. No outlier removal.
   - **The GPU must be idle** (it is currently in use by another experiment).
4. **Parity gate (blocking, before any latency number is read):**
   - 100% identical `decision` **and** `status` per row between arms, on all rows of every set
     and in every run;
   - `stop_reason == "verdict_prefix"` rate reported;
   - any mismatch blocks;
   - plus the CPU scripted-model unit tests for invalid parity (§2);
   - reason parity is explicitly **not** expected and is not scored for arm B.
5. **Report**, per arm and as paired differences (bootstrap CI over rows):
   - mean, P50, P95 and P99 of `generate_ms` and `pipeline_ms`, overall **and by decision**
     (ALLOW is the slow path today);
   - generated-token distribution;
   - **prefill vs decode split**: TTFT (time to the first token) from a criterion or streamer
     timestamp after `device_sync`, applied identically in both arms, or from a separate
     `max_new_tokens=1` arm on the same rows; per-step decode time = (generate − TTFT) / (n − 1);
   - criterion overhead (time spent in `__call__`);
   - peak VRAM;
   - binary quality (D19 level 1) next to latency, with level 2 marked N/A for arm B.
6. **No latency claim without these measurements.** The §4 extrapolation stays labelled as a
   hypothesis.

## Sources

**Official documentation:**

- HF transformers, Generation: `generate(stopping_criteria=…)`, "Custom stopping criteria that
  complements the default stopping criteria …", and `GenerationConfig.stop_strings`:
  https://huggingface.co/docs/transformers/main/en/main_classes/text_generation (fetched
  2026-10-06).
- HF generation utilities (StoppingCriteria classes):
  https://huggingface.co/docs/transformers/main/en/internal/generation_utils. The fetch was
  truncated before that section, so the StoppingCriteria semantics above were **verified against
  installed 5.8.0 source** (`transformers/generation/stopping_criteria.py:21-56, 450-501`;
  `generation/utils.py:1281-1340, 2572-2586, 2740-2822`), not against the page.
- Python `re`: `search` ("first location"), `.` ("any character except a newline"), `$`,
  `\b` / `\s` / `\S` for str patterns, `re.ASCII`, lazy `+?`:
  https://docs.python.org/3/library/re.html (fetched 2026-10-06).
- `str.strip` and `str.isspace` (used by `\s`):
  https://docs.python.org/3/library/stdtypes.html#str.strip (not fetched; behaviour verified
  locally).
- HF tokenizers decoders (ByteFallback, Strip, Fuse):
  https://huggingface.co/docs/tokenizers/api/decoders (**not fetched**; behaviour measured
  locally on the V4 tokenizer).

**Repo:**

- `control_plane/inference_core.py`
- `control_plane/classifier_api.py:116-157`
- `data_plane/data_plane.py:140-168`
- `scripts/training/finetune.py:203-209`
- `scripts/benchmarks/benchmark_inference.py`
- `reports/v4_inference_benchmark.md`
- `reports/benchmarks/baseline-local-v1/run-0{1,2,3}.samples.jsonl`
- DECISIONS D4, D5, D19, D25, D32, D36

**UNVERIFIED:**

- GPU bitwise determinism of the early-stopped prefix (P1 empirically, only on the baseline);
- the added host sync cost;
- absence of cross-call cache effects in HF;
- the model's actual generated ids (only the counts match);
- every latency figure in §4.
