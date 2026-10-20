# V5 training readiness — gated QLoRA trainer, smoke test and GGUF / llama.cpp path (closeout 2026-10-19)

| Item | Final status |
|---|---|
| **V5 training** | **SMOKE READY / FINAL BLOCKED.** The trainer is built and tested. FINAL refuses with 27 specific diagnostics (§6). **V5 is not trained** |
| **llama.cpp export + inference** | **WORKING as an offline CPU diagnostic.** Adapter → NF4-faithful merge → GGUF → `llama-server` fed token ids. Byte-reproducible. Not integrated, no CUDA build |
| **Quantization (owner decision, 2026-10-19)** | **bf16** = fidelity reference · **Q8_0** = provisional deployment candidate · **Q4_K_M** = **NOT authorized** for real gateway decisions |
| **V4, gateway, frozen specs** | **Unchanged.** No tracked file modified. V4 adapter `7bf16875…` matches the hash recorded in `reports/v4_inference_benchmark.md`. `V5-DATA-SPEC-r3` still `f1580634…` |

**Scope of the evidence:**
- Every model result in this report comes from **64 synthetic fixture inputs**, with abstract `synthmark` markers, a
  barely trained smoke adapter, and V4-clean on out-of-distribution text.
- These results compare runtimes with each other. They are **not** evidence of quality, recall, FPR or security for any
  model.
- **Equivalence on properly labelled V5 development data has NOT been evaluated**, because no such data exists yet (§6).

**Session context:**
- **Branch:** `feat/v5-training-readiness`, from `develop` at `cd9d54d`. Nothing committed.
- **Data-readiness work:** the uncommitted `feat/v5-data-readiness` work is in a GitHub Desktop stash and was not touched.
- **Data read:** only the stage-4 synthetic fixture. INTERNAL TEST, External Test, V4 `eval.jsonl`, CSIC and the
  post-filter round-1 items were not read.

---

## 1. What was built

| File | Purpose |
|---|---|
| `scripts/training/v5_train_data.py` | No-ML module: mode gates, manifest and artifact hashes, row and label checks, TRAIN × VALIDATION leakage checks, the token contract, template-safe example building |
| `scripts/training/finetune_v5.py` | V5 QLoRA trainer CLI: gates → tokenizer → 4-bit model → TRL SFT on pre-tokenized examples → adapter save → reload check → strict-format inference → `run_record.json` |
| `scripts/training/v5_training_recipe_v1.json` | Candidate recipe. **PROPOSED**, except `quantization` (D11 APPROVED) |
| `scripts/training/check_lora_merge_fidelity.py` | Deployment diagnostic: NF4 runtime vs bf16 merge vs NF4-faithful merge (§5) |
| `scripts/training/check_gguf_fidelity.py` | Deployment diagnostic: GGUF via `llama-server`, fed HF token ids, vs the HF NF4 runtime. Records every case and decision flip, text-tokenization parity, build info and CPU timings (§5b) |
| `tests/test_v5_training_gates.py` | 25 tests (19 pure + 6 tokenizer) |

- `scripts/training/finetune.py` (V4), `control_plane/` and `data_plane/` are unchanged.
- The V4 prompt is not reused for V5.
- Model outputs go only to the gitignored `model-output-v5/`. Runs are never overwritten.

## 2. The three modes (Training Readiness Gates)

Every mode, always:

- **Reads only TRAIN and VALIDATION.**
  - `load_split` raises on `INTERNAL_TEST` and `E6_RESERVE`.
  - A test spies on `open()` and proves that no INTERNAL_TEST, slice or assignment file is opened.
- **Path guards.** `assert_not_protected` (External, `eval.jsonl`, `internal_test`, CSIC, `v4_clean`) runs on the
  dataset and output paths. The output directory must sit under `model-output-v5/<mode>/`.
- **Artifact integrity.** The SHA-256 and size of every file read are checked against `manifest.json`.
- **Row checks:**
  - row/meta alignment;
  - `text_sha256` and `output` match;
  - split and disposition are correct;
  - `label_status` ∈ {VERIFIED, POLICY_DEFINED};
  - no excluded or slice row;
  - output ∈ the recipe vocabulary;
  - label ↔ output consistency.
- **Leakage.** TRAIN × VALIDATION must be disjoint on `text_sha256`, `pair_id`, `payload_family_id`,
  `payload_record_id`, `struct_cluster_id`, `template_id` and `value_entries`.
- **Example checks.** Any failure **stops the run**. Nothing is dropped silently, and nothing is truncated (§3).

| Mode | Accepts | Refuses |
|---|---|---|
| **SMOKE** | only a stage-4 fixture build: `status` FIXTURE, `fixture: true`, generator mode `fixture`, basis `fixture_synthetic` | any non-fixture manifest |
| **EXPERIMENTAL** | a non-fixture build plus `--authorization`: a `v5-experimental-authorization/v1` record (scope EXPERIMENTAL, `provisional: true`, the exact manifest SHA-256, authorized_by / date / reference / purpose, `uses_pending_labels_as_verified: false`) | fixtures; a missing or mismatched authorization; any PENDING / non-trainable label row |
| **FINAL** | only if all of F1–F9 hold | anything else, listing **every** failing condition before any model is loaded |

FINAL conditions (`gate_final`):

- **F1.** `status` REAL, generator mode `real`, and the build gates `ok`.
- **F2.** Every generator `value_statuses` entry is RATIFIED.
- **F3.** `attack_label_basis = post_filter_audit` (spec §7).
- **F4.** Dataset preregistration: committed and unmodified, under `reports/v5/dataset-preregistration-v1/`, and its
  SHA-256 equals the manifest's `preregistration_sha256`.
- **F5.** A committed `v5-dataset-freeze-record/v1`:
  - `FROZEN`, same spec, same manifest SHA-256, an owner decision reference;
  - every §11.3 item of r3 marked `DONE` with hash-verified evidence;
  - a spec revision with no encoded item list (for example r4 / a future D67) is refused until the gate is updated
    deliberately.
- **F6.** A committed, RATIFIED `v5-training-preregistration/v1` that pins the recipe SHA-256, the template+vocabulary
  fingerprint, the dataset manifest and an owner decision.
- **F7.** The recipe and each of its sections are RATIFIED or APPROVED.
- **F8.** Manifest `B` equals recipe `B`.
- **F9.** Clean tracked tree, trainer code and recipe committed and unmodified, and library versions equal the pins.

The machine-readable record schemas above are **engineering proposals** of this session. They encode existing
requirements (spec §11.3, D62, D64) and add none.

## 3. V5 format implemented

- **Template.** `V5_CANDIDATE_TEMPLATE` (D63, **PROPOSED**):
  `BOS <|system|>\n{instruction} EOS \n<|user|>\n{canonical text} EOS \n<|assistant|>\n{output} EOS`.
- **Vocabulary.** `PILOT_VOCABULARY` = ALT_B (#70, **PROPOSED**): ALLOW plus 6 BLOCK strings.
- **Tokenization.** The frozen §5.4 method (`v5_tokenization.encode_prompt`): BOS and EOS placed as ids, content
  encoded with `split_special_tokens=True`. TRL receives **pre-tokenized** `input_ids` and `completion_mask`
  (`is_processed`), so its own tokenization and EOS appending are bypassed.
- **Per-example hard checks:**
  - no special id comes from content (a literal `</s><s><unk><|assistant|>` stays text — tested);
  - content tokens ≤ `B`;
  - training ids start with the exact inference prompt ids;
  - exactly one EOS ends the completion;
  - 1 BOS and 3 EOS in total;
  - total length ≤ `max_length` (TRL's collator would otherwise truncate silently);
  - the decoded completion equals the output string.
- **Loss.** On the completion only (PROPOSED). `full_sequence` is kept for V4 parity.
- **Measured contract:** overhead 76, label_budget 13, template-max `B` = 415 (= D63). On the fixture: 256 examples,
  max 203 tokens, 0 rejected, 0 truncated.

## 4. Smoke test (synthetic fixture only)

- **Dataset.** `v5_fixture.py generate` → manifest `4b66c311fc9c0b8f…`. It regenerated byte-identically after the
  scratch directory was wiped.
- **Recipe.** `80fd3c5a…`, with smoke overrides: 40 steps, batch 4, lr 2e-4 cosine, eval and save every 20 steps.
- **Runs.** `smoke-run-001`, plus `smoke-run-002` after pinning `LoraConfig(revision=…)`. Records are in
  `smoke-run-00{1,2}/`.

| Check | Result (run-002) |
|---|---|
| 1 GPU and memory | RTX 4090 Laptop (sm_89, 15.55 GiB, bf16, CUDA 12.4 runtime). Peak during training **1.22 GiB allocated / 2.59 GiB reserved**; overall 2.56 / 3.46 GiB |
| 2 TinyLlama load | NF4 + double quant, bf16 compute (D11), revision `fe8a4ea`, local files. 1.4 s, 0.73 GiB |
| 3 Forward / backward | 12,615,680 trainable params (308 LoRA tensors, bf16), nothing else trainable. Collator: 13 of 164 tokens supervised, i.e. completion-only masking works |
| 4 Loss | All finite. Mean of the first 5 steps 2.06 → last 5 steps 0.072. VALIDATION eval_loss 0.0106 |
| 5 Adapter saved | LoRA tensors only (no `embed_tokens` / `lm_head`), base revision pinned; `checkpoint-40` written |
| 6 Reload | Base + adapter from disk: argmax identical on every completion token, max \|Δlogit\| 0.25–0.44. Checkpoint reloads with a finite forward pass |
| 7 Inference / format | 12 VALIDATION fixture prompts: strict V5 parser **12/12 `ok`, 12/12 ended on EOS**. A format check only, **not a quality metric** |

18.0 s end to end. Python 3.12.15, torch 2.6.0+cu124, transformers 5.8.0, trl 1.4.0, peft 0.19.1, bitsandbytes 0.49.2,
datasets 4.8.5, accelerate 1.13.0.

### 4.1 Completeness audit (closeout)

| Requirement | Implemented in | Evidence |
|---|---|---|
| V5 format (template, vocabulary, output contract) | `v5_train_data.build_example`, recipe | tests `WithTokenizer.*`; smoke check 7 |
| Template-safe tokenization (§5.4), no special ids from content | `encode_prompt` + `check_content_has_no_special_ids` | `test_special_token_literals_in_content_stay_text` |
| EOS: exactly one, ends the completion; generation stops on EOS | `build_example`; `run_generation` | tests; smoke 12/12 ended on EOS |
| No truncation; over-budget is a hard failure | `CONTENT_OVER_BUDGET`, `TRUNCATION_REQUIRED` | `test_over_budget_and_truncation_are_hard_failures` |
| Train prompt == inference prompt | `PROMPT_PREFIX_MISMATCH` check | fixture examples test |
| Completion-only loss | `completion_mask` + `completion_only_loss` | collator check (13 of 164 supervised) |
| SMOKE / EXPERIMENTAL / FINAL separation | `gate_smoke` / `gate_experimental` / `gate_final` | 19 pure tests; FINAL refusal record |
| Protected-set guards, INTERNAL TEST never opened | `load_split`, `assert_not_protected` | `test_internal_test_and_slices_are_never_opened` |
| Hashes, versions, seed, git state recorded | `run_record.json` | `smoke-run-002/run_record.json` |
| Adapter save (LoRA only) and reload | `adapter_inventory`, reload compare | smoke checks 5 and 6 |

**Not covered (stated):**
- **EXPERIMENTAL** was never run end to end: no authorized provisional dataset exists. Its gate logic is
  unit-tested on test doubles.
- **No resume** from a checkpoint: a FINAL run restarts from scratch.
- Same-seed GPU training is **not bitwise reproducible**: two runs diverge from step 6 on, max |Δloss| 0.0078.
- The final adapter is saved in **fp32** (50.5 MB) after `load_best_model_at_end`; checkpoints are bf16 (24 MB).

## 5. Merge step: LoRA → merged checkpoint

`merge-fidelity/`; 64 synthetic inputs; fidelity between runtimes, not accuracy.

| Comparison | V4-clean (V4 prompt) | V5 smoke (V5 template) |
|---|---|---|
| A NF4 runtime vs B bf16 base + adapter (unmerged) | 56/64 decisions | 57/64 |
| B vs C `merge_and_unload` into bf16 | 64/64 | 62/64 |
| A vs C: runtime vs naive merged artifact | 56/64 | 59/64 |
| **A vs D: runtime vs NF4-faithful merge** (`dequantize_4bit(NF4(W))` + LoRA, saved and reloaded) | **64/64 (64/64 generations)** | **64/64 (64/64)** |

**Verified finding** (D vs C is a controlled comparison):
- A QLoRA adapter is fitted to the NF4-dequantized base, so the naive bf16 merge is a different model.
- The NF4-faithful merge reproduces the runtime on these inputs.
- **Export only from the NF4-faithful merge.**

## 5b. GGUF + llama.cpp — measured

**Setup.** Nothing was installed system-wide, and the gateway was not touched.
- llama.cpp **b11381** (commit `836d57176dc699a726c55418e4f96b8ca628e1bf`, 2026-10-03) from
  github.com/ggml-org/llama.cpp, in `~/opt/llama.cpp`.
- **CPU-only** Release build: `-DGGML_CUDA=OFF -DLLAMA_CURL=OFF`, GNU 15.2.0, cmake 3.31.6 as a `uv tool`.
- Converter: llama.cpp's `gguf-py` via `PYTHONPATH`, plus `sentencepiece` 0.2.2 in `~/opt/llama-pydeps`, with the
  existing torch 2.6 / transformers 5.8 stack.

**Pipeline.**
- NF4-faithful merge → `convert_hf_to_gguf.py --outtype bf16` → `llama-quantize <bf16> <out> Q8_0|Q4_K_M 16`.
- The base `tokenizer.model` is copied next to the merged weights.

**Harness.** `check_gguf_fidelity.py`.
- Reference: the HF NF4 + adapter runtime on GPU (the `inference_core` configuration).
- `llama-server` on 127.0.0.1 (`-c 2048 -np 1 -t 16`) receives the **HF prompt token ids**: temperature 0, `top_k` 1,
  seed 0, `cache_prompt` false.
- Reports: `gguf-fidelity/v4_clean.json`, `v5_smoke_run_001.json` (run 2, all cases); `*_run1.json` (run 1).

| GGUF (NF4-faithful) | SHA-256 (prefix) | Size | V4-clean decisions / generations | V5 smoke decisions / generations |
|---|---|---|---|---|
| bf16 | V4 `5d4877afb7cb5ef9` · V5 `6cc228be19ce0a3f` | 2,099 MiB | 63/64 · 62/64 (1 ALLOW→BLOCK) | **64/64 · 64/64** |
| Q8_0 | V4 `5f2733ede0dbbd78` · V5 `1cf5b961f4121968` | 1,116 MiB | 63/64 · 60/64 (1 ALLOW→BLOCK) | 63/64 · 63/64 (1 ALLOW→BLOCK) |
| **Q4_K_M** | V4 `dadee91d96471cfe` · V5 `4079369059795235` | 637 MiB | **55/64** · 34/64 — **9/9 flips BLOCK→ALLOW** | **57/64** · 57/64 — **7/7 flips BLOCK→ALLOW** |

- All generations ended on EOS, with 0 INVALID.
- The single V4 bf16 difference (input 18) is the same case as in Q8_0. A CPU-vs-GPU numeric difference is a
  **hypothesis**, not verified.
- **Discrepancy cases preserved** in `decision_flips` (index, `text_sha256`, prompt length, HF and GGUF outputs,
  synthetic input text):
  - V4 Q4_K_M: inputs 0, 20, 22, 24, 27, 28, 32, 36, 44;
  - V5 Q4_K_M: 13, 23, 25, 27, 35, 37, 51;
  - V4 bf16 / Q8_0: 18;
  - V5 Q8_0: 49.
  - Every per-input outcome is in `cases`.

### 5c. Why Q4_K_M flips — recorded as a HYPOTHESIS, not a conclusion

Test (`q4_hypothesis_h1.json`): each Q4_K_M is compared with **its own bf16 GGUF** (same source weights, only the
quantization differs), on both chains.

| Chain | Q4_K_M vs its own bf16 (decisions) | Flips |
|---|---|---|
| V4 NF4-faithful (weights already NF4-rounded → Q4) | 54/64 | 10 BLOCK→ALLOW |
| V4 naive merge (original bf16 weights → Q4) | 58/64 | 3 BLOCK→ALLOW + 3 ALLOW→BLOCK |
| V5 NF4-faithful | 57/64 | 7 BLOCK→ALLOW |

**Interpretation:**
- **Established on these inputs:** Q4_K_M perturbs this classifier's greedy decisions in *both* chains. 4-bit K-quant
  precision alone is enough to change decisions.
- **Hypothesis H-Q4, NOT verified:** a second 4-bit rounding on NF4-dequantized weights adds to the effect and biases it
  toward ALLOW. The larger, one-directional effect in the faithful chain is *consistent with* H-Q4, but 10 vs 6 out of
  64 synthetic inputs does not discriminate.
- **Test to settle it later** (on V5 development data): Q4_K_M vs Q5_K_M / Q6_K, with and without an importance matrix
  built from TRAIN only, and runtime LoRA on a quantized base (`convert_lora_to_gguf.py`).

### 5d. Pre-tokenized input — which paths accept ids, and what is verified

| Path | Accepts ids | Verified |
|---|---|---|
| TRL `SFTTrainer` (training) | yes (`input_ids` + `completion_mask`; `is_processed` skips tokenization and EOS append) | collator check, smoke run |
| HF `generate` (reference runtime, smoke inference) | yes | smoke check 7, all fidelity runs |
| `llama-server /completion` with a token array | yes | `pretokenized_probe.json`: **no BOS is prepended** (`prompt_n` = ids sent, with or without BOS), so the client must send BOS, as `encode_prompt` does; the template's EOS ids pass through; output carries EOS id 2 with `stop_type: "eos"`; `/detokenize` = HF decode |
| `llama-server` text prompt / `/tokenize` | text | **0/64 parity** with HF on V4 prompts: llama.cpp inserts `▁` (29871) after every special `</s>`, and without special parsing `</s>` becomes 3 tokens. **Never send text**: V5 must send `encode_prompt` ids, and so would a V4 llama.cpp backend |
| Prompt longer than the context | — | `overflow_probe.json`: **rejected with HTTP 400** `exceed_context_size_error`, not truncated |
| Prompt fits but generation reaches the context end | — | **stops early**: `stop_type: "limit"`, `truncated: true`, partial text `ALLOW \| Normal HTTP request with`. The strict V5 parser makes this `invalid` (no EOS → fail-closed). **The V4 regex would read it as ALLOW.** Requirement: `n_ctx ≥ max_length + n_predict`, and any `stop_type ≠ "eos"` is invalid |

**Still to verify in llama-server before any integration:**
- the CUDA build (numerics and determinism vs CPU);
- `-np > 1` / continuous batching and `cache_prompt: true` (can they change greedy output?);
- concurrency, timeouts and server restarts;
- out-of-vocabulary or malformed id arrays;
- behaviour under context-shift options;
- re-validation on every llama.cpp version bump (pin the tag);
- the real V5 fuzz corpus through the id path.

### 5e. Reproducibility

- **Merge + GGUF chain is byte-identical** on regeneration (V4, `repro-check/`):
  - merged `model.safetensors` `e2db6655…`;
  - GGUF bf16 `5d4877af…`, Q8_0 `5f2733ed…`, Q4_K_M `dadee91d…`.
- **Fidelity runs:** run 1 and run 2 gave identical counts on identical files, and every run-1 difference recurs in
  run 2.
- **GPU training:** seeded but not bitwise reproducible (§4.1).
- **Commands, toolchain and per-file hashes:** `artifacts_manifest.json`.

### 5f. CPU timings — diagnostic only

Not a D31/D32 benchmark, and not D36 evidence. Measured with llama-server's own timings, 16 threads, i9-13900HX,
about 150 prompt tokens + about 13 generated:

| GGUF | Median (ms) | P95 (ms) |
|---|---|---|
| bf16 | 810–960 | 936–1106 |
| Q8_0 | 799–934 | 901–1032 |
| Q4_K_M | 551–601 | 650–700 |

All are far from 200 ms on CPU.

### 5g. Minimal plan for the later GPU evaluation (nothing installed now)

1. **Owner installs the CUDA toolkit** (`nvcc`; host gcc compatible with that CUDA version — gcc 15 likely needs a
   matching CUDA release or `-ccbin` with an older gcc). This is a system change, so it's the owner's.
2. **New build directory** `cmake -B build-cuda -DGGML_CUDA=ON -DCMAKE_CUDA_ARCHITECTURES=89` at the **same tag**
   b11381. The CPU build is kept.
3. **Re-run `check_gguf_fidelity.py`** for bf16 / Q8_0 (`-ngl 99`) and compare with the CPU cases. GPU-vs-CPU flips are
   recorded as cases.
4. **Latency** under a new experiment ID with the D31/D32 stopwatch rules (warm-up, n, P50/P95, device sync), against
   D36. Steady state, one slot, then concurrency.
5. **Q8_0 decision agreement on V5 VALIDATION / development data** once it exists: a preregistered acceptance rule for
   a quantization (for example, zero BLOCK→ALLOW flips beyond an owner-set bound). Never INTERNAL TEST or External
   before the freeze.

### 5h. Artifacts — what can be deleted without losing evidence (nothing was deleted)

Every file under `model-output-v5/` is hashed in `artifacts_manifest.json` (24.4 GiB in total).

| Path (gitignored) | Size | Status |
|---|---|---|
| `smoke/smoke-run-00{1,2}` | 0.2 GiB | **KEEP** (evidence; GPU training is not bitwise reproducible) |
| `gguf/v4-clean` (bf16 / Q8_0 / Q4_K_M) | 3.8 GiB | **KEEP** while the GGUF track is open (reference + candidate; regenerable byte-identically) |
| `repro-check/` | 5.8 GiB | **deletable**: byte-identical duplicates whose hashes are recorded |
| `merge-check/v4-clean-nf4dequant` | 2.0 GiB | **deletable**: regenerable byte-identically (verified) |
| `merge-check/v4-clean`, `merge-check/v5-smoke-run-001` (naive merges) | 4.1 GiB | **deletable**: regenerable |
| `merge-check/v5-smoke-run-001-nf4dequant` | 2.0 GiB | deletable: regenerable from the kept adapter (byte identity verified on the V4 chain only) |
| `gguf/v5-smoke-run-001`, `gguf/v4-clean-naive-merge-h1` | 6.4 GiB | deletable after review: regenerable; smoke / hypothesis material |

The cases and metrics these files produced are in the JSON reports, so deleting the files loses no recorded result.
Outside the repo: `~/opt/llama.cpp` (363 MB), `~/opt/llama-pydeps`, and the `cmake` uv tool.

## 6. What is missing before the FINAL V5 fine-tune

`final-gate-check/refusal_record.json`: **27 diagnostics**, exit 3 (F7 ×10, F2 ×8, F9 ×3, F4 ×2, F1, F3, F5, F6).

1. **A real V5 dataset (F1, F3).** D64 conditions (b)–(i):
   - post-filter round 1 is `PENDING_HUMAN_REVIEW_AND_ADJUDICATION` (human review 0/200, 33 items to adjudicate);
   - the pre-filter human review is 0/95, or the D67 / r4 replacement method is approved;
   - `names_family` BLOCKED (#75), or a configuration without it approved;
   - the family-merge list, value precedence and template audit on real data;
   - a real split with every SPL gate passing.
2. **Generator values ratified (F2):** placement shares, length bins, encoder profiles, oracle `L` and signatures,
   quota, B, trained categories, I-9 values.
3. **Dataset preregistration committed (F4):** `reports/v5/dataset-preregistration-v1/`.
4. **Dataset freeze record (F5):** all §11.3 items DONE, including `STAB-HELD` sealed and the freeze report. If r4
   changes §11.3, `FREEZE_ITEMS` gets an r4 entry by a reviewed change.
5. **Training preregistration (F6) and recipe ratification (F7):**
   - template, vocabulary, B / max_length / margin;
   - loss masking;
   - LoRA hyperparameters;
   - schedule (sized from the frozen dataset);
   - seed and library pins;
   - the acceptance rule for the exported quantization (§5g.5).
6. **Committed trainer code (F9).**
7. Recommended before FINAL (not gated):
   - save the final adapter in bf16;
   - decide whether bitwise determinism is required;
   - add resume-from-checkpoint.

## 7. Owner decisions recorded in this closeout (2026-10-19)

1. bf16 is the fidelity reference. Q8_0 is the provisional deployment candidate.
2. Q4_K_M is **not authorized** for real gateway decisions. The BLOCK→ALLOW discrepancies are documented and their
   cases preserved (§5b).
3. The Q4 explanation is a hypothesis (H-Q4, §5c), not a conclusion.
4. The 64 synthetic inputs are not evidence of quality, recall, FPR or security.
5. V4 and the gateway stay unchanged.

They are recorded here only. Whether they become a DECISIONS.md entry is the owner's choice at PR time.

## 8. Reproduce

```bash
python3.12 scripts/dataset/v5_fixture.py generate --out <FIXTURE_DIR>          # manifest 4b66c311…
python3.12 scripts/training/finetune_v5.py --mode smoke --dataset <FIXTURE_DIR> --run-id <id> --report-dir reports/v5/training-readiness/<id>
python3.12 scripts/training/finetune_v5.py --mode final --dataset <FIXTURE_DIR> --gate-only    # expected: REFUSED, exit 3
HF_HUB_OFFLINE=1 python3.12 -m unittest tests.test_v5_training_gates -v
python3.12 scripts/training/check_lora_merge_fidelity.py --adapter model-output-v4-clean --format v4 --dataset <FIXTURE_DIR> --n 64 --merged-dir model-output-v5/merge-check/v4-clean --report <json>
PYTHONPATH=~/opt/llama.cpp/gguf-py:~/opt/llama-pydeps python3.12 ~/opt/llama.cpp/convert_hf_to_gguf.py model-output-v5/merge-check/v4-clean-nf4dequant --outtype bf16 --outfile <bf16.gguf>
~/opt/llama.cpp/build/bin/llama-quantize <bf16.gguf> <out.gguf> Q8_0 16
python3.12 scripts/training/check_gguf_fidelity.py --format v4 --adapter model-output-v4-clean --dataset <FIXTURE_DIR> --gguf <*.gguf> --server ~/opt/llama.cpp/build/bin/llama-server --report <json>
```

`SHA256SUMS` in this folder covers every evidence file of this report.
