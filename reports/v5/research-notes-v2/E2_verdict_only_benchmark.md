# E2. Verdict-only early stop: benchmark protocol (research note v2)

**PROTOCOL ONLY. Nothing here is a decision, an implementation, or a latency result.**
No code was changed, no model was run, the GPU was not used. This note was written from reading
`reports/v5/research-notes-v2/E_verdict_only.md` (referred to below as **E**), `control_plane/inference_core.py`
(237 lines, line numbers below are from the current tree), `control_plane/classifier_api.py`,
`data_plane/data_plane.py` and `scripts/benchmarks/benchmark_inference.py`.

Labels used throughout: **FACT** (read in code or reported in E from a measurement),
**HYPOTHESIS** (not measured), **PROPOSED** (a choice this protocol makes, to be frozen before the first run).

> **The latency improvement remains a HYPOTHESIS until measured.** E section 4.2 extrapolates about
> 88-93 ms `generate_ms` from a regression fitted on 9-13 generated tokens, evaluated at 4 tokens, which is
> outside the observed range, and which E itself labels "no latency claim". This protocol exists to measure
> that hypothesis without changing production behavior: production stays in full-generation mode until the
> gates in section 6 pass and a separate decision (the D56 draft in E section 5) is taken.

Terminology: **arm A** = full generation (today's behavior, control); **arm B** = verdict-prefix early stop
(treatment); **S** = the stop criterion of section 2.

---

## 1. Code touch-points in `control_plane/inference_core.py`

### 1.1 What a future early stop would modify (FACT: locations; HYPOTHESIS: that this is sufficient)

| line(s) | what | change under early stop |
|---|---|---|
| 193-194 | `mdl.generate(**inputs, max_new_tokens=..., do_sample=False, pad_token_id=...)` inside `classify_timed` | the **only functional touch-point**: pass `stopping_criteria=StoppingCriteriaList([<S criterion bound to prompt_len>])` (HF appends it to the defaults, E 3.1) |
| 157 | `classify_timed(tok, mdl, request, device, max_new_tokens)` signature | would gain a mode parameter, default `"full"` |
| 203-213 | `n_new`, `stopped_on_eos = n_new < max_new_tokens` (212) | line 212 becomes wrong under early stop (a stop by S has `n_new < max_new_tokens` but did not stop on EOS). A `stop_reason` in `{"eos","verdict_prefix","max_new_tokens"}` must be recorded from the criterion's own flag, not inferred from the length |
| new constant near 61 | the pattern text of S | added next to, not replacing, `EXTRACT_RE` |

### 1.2 What stays untouched (FACT: these are what the V4 baseline was measured under, per the module docstring lines 10-13)

| line(s) | element | why it stays |
|---|---|---|
| 51-55, 69-78 | `INSTRUCTION`, `build_prompt` | prompt template; changing it invalidates the baseline |
| 61 | `EXTRACT_RE` | frozen parser; S is defined relative to it, so parity is proved against this exact pattern (E 1.1, premise P3) |
| 65 | `MAX_NEW_TOKENS = 40` | safety bound; early stop never raises it |
| 82-97 | `parse_prediction` | the parity gate compares its output in both arms; it must be the same function |
| 119-142 | `load_model` (4-bit nf4, bf16 compute, `tok.pad_token = tok.eos_token` at 137) | model, adapter, quantization identical in both arms |
| 183-190 | prompt build, tokenize, `.to(device)`, `device_sync` | identical pre-generation path |
| 195-196 | `device_sync` + `t4` after generate | timing scope `generate-only/device-synchronized/v1` unchanged |
| 198-200 | `prompt_len`, `new = out[0][prompt_len:]`, `tok.decode(new, skip_special_tokens=True)` | an early-stopped output simply ends without EOS; the slice and the decode (same flags as S, premise P3) work as they are |
| 216-237 | `classify_raw` | delegates to `classify_timed` (236); returns only `(text, generate_ms)`. Not touched by the benchmark |

### 1.3 Callers outside the file (FACT; they are consumers, not touch-points of the benchmark)

- `control_plane/classifier_api.py:134` (`classify_raw`), `:141` (`parse_prediction`), response model `:85-93`
  (`reason: Optional[str]`, so `None` is representable).
- `data_plane/data_plane.py:167-168` gates only on `status` and `decision`; `reason` is optional (`:171`).
- `scripts/benchmarks/benchmark_inference.py:412` (`classify_timed`), `:414` (`parse_prediction`),
  `:431` and `:519-520` (`stopped_on_eos` and its counts).

### 1.4 How the benchmark avoids touching `inference_core.py` (PROPOSED)

The measurement must not require editing the frozen runtime. The future harness should define a
**benchmark-local wrapper** (a new script under `scripts/benchmarks/`, not part of this note) that
reproduces lines 183-213 verbatim and adds `stopping_criteria` only in arm B. Risk: the wrapper can drift from
`classify_timed`. Mitigation, required before any timing:

1. Run the wrapper in arm-A mode (no criterion) on N rows and assert that the decoded text is
   byte-identical to `core.classify_timed(...)[0]` on the same rows. This is the same style of check as the
   existing `timing_method_ab` check (`benchmark_inference.py:944-945`).
2. Arm A and arm B use the same wrapper, the same instrumentation and the same process model; the only
   difference is the criterion. Arm A therefore never goes through a different code path than arm B.

---

## 2. Stopping criterion: when is the verdict contract provably satisfied?

**S (FACT, from E):** stop as soon as
`decode(new_ids, skip_special_tokens=True)` matches `^\s*(ALLOW|BLOCK)\b\s*\|\s*\S`
(str pattern, same flags as `EXTRACT_RE`, no `re.ASCII`), where `new_ids` is `input_ids[0, prompt_len:]`
(HF passes the prompt as part of `input_ids`; E 3.1).

**Why this is the contract boundary (FACT from E 1.1, conditional on P1-P3):** every text for which S holds
parses `ok` under `EXTRACT_RE` with the same `group(1)` as the full text, for any continuation, because `.`
matches everything except `\n` and the lazy `(.+?)` is always closed by `$`. Decision and status parity is
therefore by construction, tested on 200,000 adversarial strings (0 mismatches in 1,941 stops) and 2,880
byte-fallback cases (0 mismatches).

**Premises that this benchmark must verify empirically, because E proves them only on paper or on CPU:**

| premise (E 1.1) | status | verified by |
|---|---|---|
| P1 greedy prefix property: arm B generates exactly `F[:k]` | HYPOTHESIS on GPU (E: only baseline-local-v1 3-run identity) | parity gate, section 6 |
| P2 decode stability (only a trailing byte-fallback character may differ, never into `\n`) | FACT on CPU/tokenizer (E 3.2) | prefix diagnostic, section 6.3 |
| P3 identical decode call and flags | FACT by design | code review of the wrapper; unit test with `skip_special_tokens` mismatch counterexample (E 1.3) |

**What S does not give (FACT, E 1.2):** the reason. In arm B the reason is the first reason token and is not
valid as a category (`▁C` covers CRLF and CSRF; `▁Server` covers SSRF and SSTI). Reason parity is **not
expected and not scored**. D19 level 2 is N/A for arm B.

**Cheap prefilter (E 3.1):** evaluate S only when at least 2 new tokens exist. This can only delay a stop,
never create one, so it cannot break parity. The minimum text for S on canonical outputs is 4 tokens
(`AL LOW ▁| ▁X`), against 9-13 today (E 4.1).

---

## 3. Tokenizer implications and parser interaction

All FACT from E 3.2 (V4 tokenizer, CPU; decoder chain `Replace -> ByteFallback -> Fuse -> Strip`).

- **Leading space:** `Strip(' ', 1, 0)` removes one leading space from the whole decoded string in partial and
  final decodes alike; `^\s*` in S absorbs any other leading whitespace. Stable.
- **Byte-fallback runs** are the only case where a partial decode is not a prefix of the final decode: a
  partial `U+FFFD` can resolve to NBSP or U+2028 once more bytes arrive. S may stop on the partial `U+FFFD`.
  Decision and status are still identical (`.` matches those characters; a UTF-8 lead byte never becomes
  `\n`; 0/2,880 mismatches). Only the reason would differ. The prefix diagnostic of section 6.3 must tolerate
  exactly this case and no other.
- **Special tokens:** `</s>` and `<unk>` vanish with `skip_special_tokens=True` and appear literally with
  `False`. A wrapper that decodes with `False` inside the criterion and `True` at the end is a parity break
  (E 1.3). The unit tests must include this counterexample so that the wrapper is shown to use `True` in both.
- **Why not the shorter variants (FACT, E 1.3):** stopping at the pipe, unanchored patterns, or stopping at the
  first one or two tokens each have a concrete counterexample that flips decision or status. They are out of
  scope for this benchmark; arm B is S only.
- **`stop_strings` / `StopStringCriteria`** cannot express `\b ... \S` (E 3.1) and are not used.
- **Parser interaction:** `parse_prediction` (82-97) runs unchanged on the arm B text. Defence in depth
  (E 2): after an early stop, assert `parse_prediction(text)[2] == "ok"`; a failure is recorded as
  `stop_assert_failed` and counts as a parity-gate failure (section 6).
- **Pre-existing parser behavior to keep in mind (FACT, E 1.4):** `"ALLOW | "` (pipe plus whitespace other than
  a lone newline) already parses `ok` with an empty reason today. S does not stop on it (needs `\S`), so it
  runs to EOS and parity holds. This is independent of the early stop.

---

## 4. Invalid-output and fail-closed behavior under early stop

### 4.1 Where invalid is decided today (FACT)

`classifier_api.py:141` runs `parse_prediction`; an unmatched text returns `200 status:"invalid"`
(no coercion, D25). `data_plane.py:157-168` turns every non-200, a non-JSON body, `status != "ok"`, or a
decision outside `{ALLOW, BLOCK}` into a fail-closed BLOCK (D4). An inference exception becomes HTTP 500
(`classifier_api.py:135-138`), which is also a fail-closed BLOCK.

### 4.2 Behavior by case under early stop

| case | arm A today | arm B (S) | parity expectation |
|---|---|---|---|
| canonical `ALLOW \| reason</s>` / `BLOCK \| reason</s>` | ok, full reason | stops at token 4, ok, reason = first token (not returned as a reason in the D56 draft) | decision, status identical |
| text that never satisfies S (`ALLOWED \| x`, `allow \| x`, `ALLOW \|`, `ALLOW \|\n`, garbage) | invalid | S never fires, generation runs to EOS or cap, **byte-identical to arm A** | status invalid in both |
| match appears later (`ALLOW BLOCK \| x`, `The ALLOW \| y`) | decision from the first match | S is anchored, so no stop; full generation, byte-identical | identical (latency gain lost, parity kept) |
| pipe followed by whitespace only (`ALLOW \| `) | ok, empty reason | S needs `\S`, no stop, runs to EOS | identical |
| hits `max_new_tokens` (40) | per parse of the truncated text | same as A unless S fired earlier | identical on decision, status |
| criterion raises | not applicable | the exception propagates out of `generate`, so `classifier_api.py` returns 500, which is a fail-closed BLOCK | not a parity case; must be covered by a unit test that the exception is not swallowed |

**Fail-closed rule (PROPOSED, consistent with E 2 and the D56 draft):** early stop may only ever *shorten* an
output whose parse is already `ok`; it can never turn a would-be invalid text into a stop. If the post-stop
`parse_prediction` is not `ok`, the result is reported `invalid` (which the data plane blocks), logged with
`stop_reason`. Early stop adds no path to an ALLOW that arm A would not also produce.

### 4.3 Where invalid parity can and cannot be tested

- **FACT (E 2):** `baseline-local-v1` has **0 invalid outputs in 18,618 samples**, so the V4 eval split
  cannot demonstrate invalid parity on the GPU.
- **PROPOSED:** invalid parity is tested on CPU with scripted token sequences (no model weights needed beyond the
  tokenizer, plus a small scripted-forcing model for one generate-loop integration test):
  `ALLOWED`, `ALLOW_`, lowercase, fullwidth `ＡLLOW`, `ALLOW |` then EOS, `ALLOW |` then `\n`,
  `<unk>` and `▁` combinations, `<0x0A>`, byte-fallback runs (`<0xC2>`, `<0xC2><0xA0>`, `<0xE2><0x80>`,
  `<0xE2><0x80><0xA8>`), `ALLOW BLOCK | x`, `BLOCK | x. ALLOW | y`, and the `skip_special_tokens` counterexample.
  Assertion for each: arm A text and arm B text give the same `(decision, status)` through the real
  `parse_prediction`. Two levels: (i) the criterion alone over id sequences; (ii) one HF `generate` loop with a
  forced-token model, to confirm criterion placement after the token append (`generation/utils.py:2810-2822`
  per E).

---

## 5. Benchmark design

### 5.1 Identities and comparison (PROPOSED, from E 6 and the existing protocol/D32 conventions)

- **Arm A:** a fresh control `v4-full-local-v2`. **`baseline-local-v1` is not the comparand**: it is immutable
  and was measured under a different thermal state and run order (E: 11% run-to-run effect, 17.4/17.8/19.6 ms per
  token across its three runs).
- **Arm B:** `v4-verdict-prefix-local-v1`.
- Add `decoding_mode` and `stop_criterion` (regex text and flags) to the protocol and environment records, as the
  declared treatment. Everything else (model, adapter, quantization, prompt, `MAX_NEW_TOKENS`, batch 1,
  concurrency 1, `do_sample=False`) must be byte-identical between arms and is checked from the environment
  records.
- Timing scope stays `generate-only/device-synchronized/v1` for the primary generate metric; the D36 quantity is
  the pipeline P95 (`prompt_build + tokenize + transfer + generate + decode + parse`, as already summed at
  `benchmark_inference.py:437-439`).
- **The GPU must be idle** (E 6.3 notes it was in use by another experiment).

### 5.2 Workloads

| set | arms | purpose |
|---|---|---|
| `datasets/v4_clean/eval.jsonl` (6,206 rows, manifest-hash verified, file order as in baseline-local-v1) | A and B, full pass per run | **latency workload only** (no model selection on it); also the main parity set |
| paired development set (issue #59) | A and B | parity only (includes adversarial and benign pairs) |
| 135-case manual suite | A and B | parity only |
| CPU scripted cases (section 4.3) | A and B (CPU) | invalid-parity and tokenizer edge cases |

### 5.3 Run structure

1. **Smoke** with a throwaway experiment id: 50-100 rows, both arms, parity gate only, to catch harness bugs.
2. **Paired ABBA in one process (diagnostic, not the headline):** row *i* runs A then B if *i* is even, B then A
   if odd, so slow thermal drift and order effects cancel row by row. Whether HF keeps any cross-call state or
   prefix cache between `generate` calls is **UNVERIFIED** (E 6.3); the paired design is how this is checked
   (A-first and B-first rows must give the same A latency within noise).
3. **Formal protocol:** **at least 3 fresh processes per arm, interleaved A B B A B A**, one model load per
   process, batch size 1, concurrency 1 (same process model as baseline-local-v1). Record GPU temperature,
   power draw and SM clock before and after each run; start each run from a comparable temperature (cool-down
   if needed).
4. **Warm-up (same policy as baseline-local-v1, FACT from its protocol.json):** seed 42; 1 cold-start sample
   plus 4 warm-up samples per process, executed before measurement and **excluded from steady statistics**,
   reported separately. The warm-up rows must be the same rows in both arms. In arm B the warm-up must run
   with the criterion active so that its import and first-call cost are not paid inside the measurement.
5. **Steady phase:** all 6,206 rows in file order, no shuffling, no outlier removal (same as the baseline).

### 5.4 Sample size and statistical treatment (PROPOSED)

- N = 6,206 rows per run x 3 runs per arm = 18,618 steady samples per arm, matching the baseline's sample count.
  This is a census of the eval split, not a sample, so no power calculation is needed for the pass over the rows;
  the unit of uncertainty for the headline is the **run** (3 per arm, hence the number of runs, not the rows,
  limits how tight the cross-run statement can be). If the A-vs-B gap is not clearly larger than the run-to-run
  spread, the result is reported as "inconclusive", and more runs are added under a new experiment id, not by
  stopping when the number looks good.
- Per arm and per run, report: **mean, P50, P95, P99** of `generate_ms` and `pipeline_ms`, overall and **by decision
  (ALLOW and BLOCK)**, since ALLOW is the slow path today (13 tokens, E 4.1).
- Paired differences (B minus A), with a bootstrap CI over rows for the within-process ABBA diagnostic, and the
  per-run-pair difference (run *j* of A vs run *j* of B) for the formal protocol.
- **Generated-token count:** distribution per arm (`generated_tokens`), plus the fraction with
  `stop_reason == "verdict_prefix"`. Expected for canonical V4 outputs: 4 in arm B against 9-13 in arm A (E 4.1);
  this is a HYPOTHESIS about the model's actual ids (E: only counts matched, ids were not stored).
- **Prefill versus decode split:** time to first token via an identical timestamp mechanism in both arms, or a
  separate `max_new_tokens=1` run on the same rows; per-step decode time `(generate - TTFT) / (n - 1)`. This is
  required because E 4.2 notes that prefill cost was never measured separately, so the intercept of the
  extrapolation (11.5 ms) is uninterpreted.
- **Criterion overhead:** accumulated time inside the criterion's `__call__` (decode plus regex plus the
  device-to-host copy of the new ids), reported per request. E 3.1 estimates this as cheap (about 0.07 ms for the
  decode) but marks the added host sync cost UNVERIFIED.
- Peak VRAM (should be unchanged); binary decision quality (D19 level 1) beside latency; level 2 shown as N/A for
  arm B.

### 5.5 Pre-registered interpretation (PROPOSED, to be frozen before the first formal run)

- The latency win is **accepted for consideration** only if the parity gate (section 6) passes *and* in every one
  of the 3 run pairs the pipeline P95 of arm B is below arm A's by a margin larger than the largest within-arm
  run-to-run spread. The exact minimum effect threshold (for example a fixed percentage of A's P95) must be
  written into the protocol before running; this note does not pick the number so as not to bias it to the
  E 4.2 extrapolation.
- Whether arm B reaches the D36 target (P95 pipeline <= 200 ms; 269.58 ms today per memory notes) is **reported as
  a distance, not asserted**. E 4.2's 88-93 ms figure is a generate-only extrapolation and does not by itself
  predict a pipeline P95.
- A latency number from a run in which the parity gate failed is **not read** and is not reported as a result.

---

## 6. Decision parity gate (blocking)

**Rule:** the early stop must produce **byte-identical `decision` and `status`** per row, versus arm A full
generation on the same row, on the benchmark set. **Any mismatch rejects the latency win**, and no timing result
from that run is used. The gate is evaluated before any latency statistic is read.

### 6.1 What is compared

For every row of every set and every run, with `parse_prediction` being the core function (82-97) applied to each
arm's raw text:

| field | requirement | gating? |
|---|---|---|
| `decision` (`ALLOW`, `BLOCK` or `None`) | identical | **yes** |
| `status` (`ok` or `invalid`) | identical | **yes** |
| post-stop assertion `status == "ok"` when `stop_reason == "verdict_prefix"` | must hold in every stopped row | **yes** |
| `reason` | not expected equal (E 1.2: 0/19 canonical reasons equal) | **no**; arm B reason is not scored |
| raw text relation | arm B text is a prefix of arm A text, up to the one byte-fallback case of section 3 | diagnostic, reported with any exception listed |
| `generated_tokens`, `stop_reason` | differ by design | reported, not gating |

### 6.2 Coverage (what "byte-identical on the benchmark set" means in practice)

- All 6,206 eval rows, in each of the 3 formal runs of arm B, are compared against the arm A result for the same
  row. Because greedy decoding is deterministic, arm A itself must also be self-consistent across its 3 runs (as
  baseline-local-v1 was); a row where arm A differs from arm A across runs is reported as a GPU determinism
  finding, and the gate for that row is evaluated against each arm A run.
- The paired development set and the 135-case manual suite, once each per run.
- The CPU scripted cases of section 4.3 (the only place invalid parity can actually be exercised).

### 6.3 Outcome rules

- 0 mismatches in `decision` and `status` everywhere, post-stop assertion never fails: gate **passed**; latency
  analysis may proceed.
- Any `decision` or `status` mismatch, or any failed post-stop assertion: gate **failed**. The latency win is
  rejected; the mismatching rows are saved with ids, raw texts and token ids for analysis; the criterion is
  reconsidered under a new experiment id.
- A pass on the GPU sets is **empirical** support for premise P1 (a pass does not prove determinism; E marks bitwise
  GPU determinism UNVERIFIED), and a pass on the eval split says nothing about invalid parity (0 invalid
  outputs, section 4.3); the CPU cases carry that part.

---

## 7. FACT / HYPOTHESIS summary

**FACT (read in code or measured and reported in E):**
- The generation call and parsing sites are `inference_core.py:193-194` and `82-97`; the decode used for the final
  text is line 200 with `skip_special_tokens=True`; `stopped_on_eos` at 212 is inferred from length.
- S matches only texts that `EXTRACT_RE` parses `ok`, with identical decision, on 200,000 adversarial strings and
  2,880 byte-fallback cases (E 1.1); the reason differs in 61% of stops and cannot be a category.
- The data plane fail-closes on every non-ok or non-200 response (`data_plane.py:157-168`).
- baseline-local-v1 has 0 invalid outputs, so GPU-side invalid parity cannot come from the eval split.
- Canonical outputs need 4 tokens for S against 9-13 today (E 4.1).

**HYPOTHESIS (unproven until measured with this protocol):**
- That arm B lowers `generate_ms` and pipeline P95, and by how much (E 4.2 extrapolates to about 88-93 ms
  `generate_ms`, outside the fitted range).
- That the per-step cost is about 18 ms and constant, so that cutting from about 12 to 4 tokens is roughly linear.
- That the criterion's host sync and decode overhead is negligible; that HF keeps no cross-call cache that favors
  one arm; that the model emits exactly the canonical token ids; that greedy GPU decoding gives a bitwise-identical
  prefix.
- That any of this reaches the D36 target (P95 <= 200 ms).

---

## Sources

- E (`reports/v5/research-notes-v2/E_verdict_only.md`), which cites the installed transformers 5.8.0 source
  (`generation/stopping_criteria.py:21-56, 450-501`; `generation/utils.py:1281-1340, 2572-2586, 2740-2822`) and:
  - HF transformers, text generation and `stopping_criteria`:
    https://huggingface.co/docs/transformers/main/en/main_classes/text_generation
  - HF generation utilities (StoppingCriteria):
    https://huggingface.co/docs/transformers/main/en/internal/generation_utils (E could not fetch the relevant
    section, so StoppingCriteria semantics rest on the installed source reading in E, not on that page)
  - Python `re`: https://docs.python.org/3/library/re.html
  - HF tokenizers decoders: https://huggingface.co/docs/tokenizers/api/decoders (not fetched by E; measured locally)
- No new web searches were run for this note; the HF behavior claims are inherited from E and are not re-verified here.
- Repo: `control_plane/inference_core.py`, `control_plane/classifier_api.py:85-93, 126-157`,
  `data_plane/data_plane.py:140-172`, `scripts/benchmarks/benchmark_inference.py:395-440, 932-945`,
  `reports/benchmarks/baseline-local-v1/protocol.json`, DECISIONS D4, D19, D25, D32, D36 (as cited in E).
