# firewall-IA — Project Decision Log

Authoritative record of confirmed project decisions. Companion to `CONTEXT.md` (project memory)
and `reports/` (experimental evidence).

**Rules for this file**

- One entry per decision. Entries are **append-only**; never rewrite or delete a decision.
- If a decision is later changed, add a **new** entry that supersedes it and mark the old one
  `SUPERSEDED BY Dxx`. Preserve the original text.
- Rationale is drawn only from recorded audit evidence and from the decisions as issued.
  Do not invent rationale.
- `Status` values: `APPROVED` · `APPROVED FOR FUTURE WORK` · `CORE REQUIREMENT` ·
  `FUTURE WORK` · `SUPERSEDED` · `PENDING ADVISOR`.
- `Implementation` values: `NOT YET` · `IN PROGRESS` · `DONE` · `N/A` ·
  `OUT OF CURRENT SCOPE`.

**Project identity (context for every decision below):** an inline AI-powered
application-layer security gateway for HTTP traffic. Stateless at the application-request
level. Not a conventional stateful network firewall.

---

## D1 — HTTP request representation

- **Date:** 2026-08-16
- **Status:** APPROVED
- **Implementation:** NOT YET — belongs to the future clean dataset work

**Decision.** Keep the HTTP envelope, but neutralize dataset shortcuts across classes.

Headers will **not** be stripped. The future regenerated dataset must preserve headers that
can legitimately carry security-relevant information, including cases such as
`Origin`/`Referer` and `Content-Length`/`Transfer-Encoding`.

However, non-causal envelope information — `Host`, `User-Agent`, generic cookies and similar
metadata — must not deterministically reveal ALLOW vs BLOCK. ALLOW and BLOCK examples must
draw these neutral envelope values from **shared distributions**.

**Rationale.** Audit finding F1: measured across all 99,132 examples, `Host` is a
near-perfect label predictor — `target.internal.com` is 42,979 BLOCK / 0 ALLOW, and 53 other
hosts are 26,290 ALLOW / 0 BLOCK. A classifier reading only the `Host` header scores ≈93%,
higher than the historical 91% attributed to the model. Related confounds: User-Agent is
present on 100% of CSIC rows and absent from 100% of PayloadsAllTheThings rows; a raw space
in the request-target occurs in 1,418 BLOCK and 0 ALLOW examples.

Stripping all headers would also remove the headers that are genuinely causal for CSRF
(`Origin`/`Referer`) and request smuggling (`Content-Length`/`Transfer-Encoding`) — two of the
weakest categories in the current dataset (46 and 52 examples respectively).

**Verification.** `check_dataset.py` must report no envelope shortcut before this is
considered satisfied.

---

## D2 — CSIC excluded anomalies

- **Date:** 2026-08-16
- **Status:** APPROVED FOR FUTURE WORK
- **Implementation:** N/A for the clean baseline — preserved conceptually

**Decision.** Do **not** reinstate the 18,478 currently excluded CSIC anomalous rows into the
main clean baseline yet. Preserve them conceptually as a separate future experimental
dataset. Do not assign weak generic labels to them in the main baseline at this stage.

**Potential future research question:** can the AI classifier detect anomalous traffic that
the existing CSIC keyword categorizer could not classify?

**Rationale.** Audit finding F6: `categorize_csic_anomalous()` assigns CSIC BLOCK labels with
an 11-rule keyword heuristic and discards the 18,478 rows (73.7% of CSIC Anomalous) it cannot
match — structural anomalies such as buffer overflow, integer tampering and cookie poisoning
with no keyword-detectable payload. Including them with a generic label would add examples
whose labels cannot be validated from request content. Keeping them separate preserves both
label quality in the baseline and the future research question intact.

---

## D3 — Latency target

- **Date:** 2026-08-16
- **Status:** APPROVED
- **Implementation:** N/A (a target, not a build task)

**Decision.** Initial engineering target: **end-to-end added latency P95 ≤ 200 ms.**

This is a **design target, not an already demonstrated capability.**

Future performance evaluation must measure separately:
model-only inference · model + API · proxy overhead · end-to-end · P50 · P95 · P99 ·
throughput.

**Rationale.** The audit recorded that no latency budget existed, which left every
performance item in the roadmap unfalsifiable. The previously recorded ~800 ms/request figure
is unverified (no trained model exists) and was in any case confounded by forced 40-token
generation (F5), so it never measured decision latency. A stated budget is a prerequisite for
choosing a classifier timeout, which is in turn a prerequisite for D4.

---

## D4 — Failure behavior

- **Date:** 2026-08-16
- **Status:** APPROVED
- **Implementation:** OUT OF CURRENT SCOPE — applies when the inline gateway is built

**Decision.** Default architecture decision: **FAIL-CLOSED.**

If the AI classifier times out, crashes, becomes unavailable, or returns an invalid decision,
traffic is **blocked** by default.

A future fallback mechanism may allow the proxy or a simpler local security mechanism to
temporarily take over. That fallback is **not** part of the current implementation scope.

**Rationale.** The audit flagged that fail-open vs fail-closed was undefined and that an
inline gateway which fails open is not a security control. Recording the decision explicitly
makes it a defensible, documented architectural property rather than an implementation
accident.

---

## D5 — `###END###`

- **Date:** 2026-08-16
- **Status:** APPROVED
- **Implementation:** **DONE — experiment E4, 2026-08-17**

**Decision.** Remove the custom `###END###` token. Use the model's native termination
behaviour instead. **Do not** attempt to repair `###END###` with `modules_to_save`.

Because the historical v3 model no longer exists, **do not claim a measured before/after
latency improvement from this change** unless a controlled experiment is later performed.
A latency improvement remains a **hypothesis**, not a result.

### Rationale (corrected against measured E1 evidence)

1. **`###END###` is unnecessary — native EOS already exists.** TinyLlama's `</s>` is
   `eos_token_id` 2, and `format_example()` already appended a literal `</s>` to every
   training sequence, verified to tokenize to id 2 on the installed stack.
2. **Under the observed E1 stack, resizing the tokenizer caused PEFT to persist the full
   `embed_tokens` and `lm_head` matrices.** `peft/utils/save_and_load.py:386` sets
   `save_embedding_layers=True` automatically when it detects a resize.
3. **The E1 smoke adapter totalled ~298 MB**, of which only ~24 MiB was actual LoRA tensors
   (12,615,680 params); the remaining ~250 MiB was 131,076,096 params of those two matrices.
4. **The custom token was never configured as a trainable token** — the saved
   `adapter_config.json` showed `modules_to_save=None` and `trainable_token_indices=None`, so
   it received no gradient and those matrices carried no trained information.
5. **Removing it simplifies the pipeline and supports the future GGUF / embedded-deployment
   objective** (D8 item 3, D10).

> **Note on two earlier claims, corrected during E1 and not repeated here:** the audit's
> original F5 stated that the embedding row was randomly re-initialised on every load and
> that the embedding/head matrices were never saved. Both were **wrong** on this stack —
> transformers 5.8 mean-resizes new rows, and PEFT does persist the matrices. What held is
> that the row received no gradient and never learned to be emitted.

### E4 implementation and verification (2026-08-17)

Files changed: `parse_dataset_v4.py` (INSTRUCTION + all output labels), `finetune.py`
(`add_special_tokens` / `resize_token_embeddings` removed), `test_model.py` and
`classifier_api.py` (tokenizer resize, `end_token_id`, `eos_token_id` override and
custom-token regex all removed; their extraction regex is byte-identical).

Output contract is unchanged: `ALLOW | <reason>` / `BLOCK | <reason>`.

Verified without any training run:

| Check | Result |
|---|---|
| Tokenizer vocabulary | 32,000 — **not resized**; added vocab is only `<unk>/<s>/</s>` |
| Formatted sequence termination | ends with `eos_token_id` 2; exactly 3 EOS, **no duplicate** |
| `embed_tokens` / `lm_head` in saved adapter | **NONE** — 12,615,680 params total |
| `modules_to_save` / `trainable_token_indices` | `None` / `None` |
| Generation | works with no `eos_token_id` override |
| Dataset regeneration | input side **byte-identical**; only label text changed |
| E0 regression | every metric byte-identical to the pre-E4 report |

**The structural cause of the E1 embedding/head inflation has been removed.** No production
adapter size is claimed, since no training run was performed.

Evidence: `reports/e4_remove_end_token.txt`.

### Additional deployment rationale — measured in E1, 2026-08-17

The E1 smoke test established that resizing the tokenizer causes PEFT to persist the **full**
`embed_tokens` and `lm_head` matrices into every checkpoint and into the final adapter
(`peft/utils/save_and_load.py:386` sets `save_embedding_layers=True` automatically on
detecting a resize).

Measured on the E1 smoke adapter:

| Component | Params | Size |
|---|---:|---:|
| LoRA tensors (308) | 12,615,680 | ~24 MiB |
| Full `embed_tokens` + `lm_head` | 131,076,096 | ~250 MiB |
| **Resulting adapter** | | **~298 MB** |

**The custom token causes roughly a 12× adapter-size inflation — despite the new token not
being configured as a trainable token** (`modules_to_save=None`, `trainable_token_indices=None`
in the saved `adapter_config.json`, so it receives no gradient and carries no trained
information).

This gives D5 a deployment reason independent of the original termination-behaviour argument,
and it bears directly on **D8 item 3** (GGUF / quantized deployment path) and **D10**
(embedded storage budget).

It also corrects part of the original audit finding F5: the new row is *not* randomly
initialised (transformers 5.8 mean-resizes from the existing embeddings' mean and covariance)
and is *not* re-randomised per load (PEFT persists it). What holds is that it receives no
gradient and never learns to be emitted. See `CONTEXT.md` §12 F5 and
`reports/e1_training_pipeline_smoke.txt` §7/§7a.

**`###END###` was subsequently removed in experiment E4 (2026-08-17).** See the D5 entry above.

---

## D6 — Dataset versioning

- **Date:** 2026-08-16
- **Status:** APPROVED
- **Implementation:** NOT YET — migration procedure must be documented and proposed first

**Decision.** Generated `train.jsonl` / `eval.jsonl` should **not** be treated as normal
long-term Git source files.

The reproducibility strategy is to version:

- the dataset generator
- the PayloadsAllTheThings commit
- generation parameters and seed
- a dataset manifest
- per-category counts
- train/eval counts
- SHA-256 hashes for generated artifacts

and to make generation deterministic.

**Explicit constraint.** Do **NOT** remove the currently tracked JSONL files yet.
Do **NOT** run `git rm --cached` yet. Document and propose the migration procedure first, so
historical evidence is not accidentally lost.

**Rationale.** Audit finding F9: `.gitignore` lists both JSONL files and earlier
documentation stated generated datasets were not versioned, but `git ls-files` confirms both
are tracked — ~43.5 MB committed without Git LFS. `.gitignore` has no effect on
already-tracked files. That tracking is currently the **only** reason the 99,132-example
dataset still exists, since the original v3 dataset and adapter were lost in the reinstall
precisely because they were gitignored. Until a manifest-based scheme is in place and
verified, removing the files would repeat that loss.

Separately, `parse_dataset.py` is non-deterministic despite `random.seed(42)` — the random
stream's consumption order depends on `list(set(payloads))` (varies with `PYTHONHASHSEED`)
and on unsorted `os.listdir()` / `os.walk()`. Determinism is a prerequisite for the manifest
scheme to be meaningful.

---

## D7 — Scientific integrity

- **Date:** 2026-08-16
- **Status:** APPROVED
- **Implementation:** N/A (a standing principle)

**Decision.** We explicitly accept that removing dataset artifacts may reduce model accuracy.
Scientific validity takes priority over preserving the historical 91% result. The objective
is to obtain a valid clean baseline first and improve performance from there.

**Rationale.** Audit findings F1 and F2 established that the current dataset's accuracy
numbers are uninterpretable: a `Host`-only classifier scores ≈93%, and 26.6% of the eval set
appears verbatim in train. Any number produced under those conditions measures shortcut
exploitation and memorisation rather than detection. A lower but valid number is worth more
than a higher but invalid one.

**Consequence for reporting.** The ~91% figure is historical context only. It is not the
current baseline and must not be used as a comparison point for future versions
(see `CONTEXT.md` §3).

---

## D8 — Core project scope

- **Date:** 2026-08-16
- **Status:** APPROVED, subject to advisor scope confirmation where necessary
- **Implementation:** IN PROGRESS (item 1)

**Decision.** The mandatory core project is:

1. clean and scientifically defensible dataset
2. validated AI classifier
3. GGUF / quantized deployment path
4. inline HTTP security gateway
5. security validation
6. sufficient performance evaluation to establish operational viability
7. physical deployment on embedded Linux hardware

Deep comparative performance studies and additional architecture extensions are **not**
mandatory for the core.

**Rationale.** The audit flagged scope risk: the prior roadmap held roughly seven major
deliverables (V5–V11) while V3 was not yet complete. This decision fixes the mandatory set
and explicitly demotes the rest, so scope growth is a deliberate act rather than a drift.

**Explicitly non-core:** stateful / session-aware classification, SIEM integration, and the
conventional rule-based comparison (see D9).

---

## D9 — Conventional rule-based comparison

- **Date:** 2026-08-16
- **Status:** FUTURE WORK
- **Implementation:** OUT OF CURRENT SCOPE

**Decision.** A conventional rules/WAF comparison is useful for data analysis and research,
but it is **not** currently a mandatory success criterion. Treat it as future work / optional
extension unless the advisor later requires it.

**Do NOT implement OWASP CRS / ModSecurity / Coraza now.**

**Rationale.** Per D8 this is outside the mandatory core. The audit also identified a design
problem that must be solved before any such comparison is meaningful (F6): CSIC BLOCK labels
are generated by an 11-rule keyword heuristic, so a rule-based baseline would score near-100%
on that portion by construction, making the comparison circular. If the comparison is later
required, it must use an independent, documented, versioned ruleset and must evaluate on data
that is not labelled by a keyword matcher — which connects it to D2.

**If later required, verify before citing:** current OWASP CRS / ModSecurity / Coraza
versions, licensing, and packaging on this platform. Do not cite these from memory.

---

## D10 — Embedded deployment

- **Date:** 2026-08-16
- **Status:** CORE REQUIREMENT
- **Implementation:** NOT YET — platform selection deferred

**Decision.** Physical embedded deployment is part of the mandatory project (D8 item 7).

The exact platform remains **TBD** between candidates such as Raspberry Pi and NVIDIA Jetson.
**Do not select the platform yet.**

Selection must be justified later using **measured** requirements:
memory · compute · latency · throughput · model footprint · power/thermal constraints where
practical.

**Rationale.** Hardware selection should be evidence-based. Choosing a platform before the
model footprint and latency characteristics are measured would make the choice a preference
rather than a finding. The relevant measurements depend on D3's metrics and on the
quantization work in D8 item 3, neither of which has been performed.

---

## D11 — Training numerical precision

- **Date:** 2026-08-17
- **Status:** APPROVED
- **Implementation:** DONE — applied to `finetune.py` 2026-08-17

**Decision.** Adopt BF16 for the current QLoRA training pipeline.

```
bf16 = True
fp16 = False
bnb_4bit_compute_dtype = torch.bfloat16
```

**Rationale.** TRL 1.4.0 casts trainable LoRA parameters to BF16 for 4-bit models
(`trl/trainer/sft_trainer.py:1088-1092`, following the QLoRA paper; there is no flag to
disable it). The E1 smoke test demonstrated that `fp16=True` is incompatible with that path
because `GradScaler` cannot unscale BF16 trainable tensors:

```
RuntimeError: "_amp_foreach_non_finite_check_and_unscale_cuda"
              not implemented for 'BFloat16'
```

The RTX 4090 supports BF16 natively (`torch.cuda.is_bf16_supported() = True`).

**This is an environment compatibility / numerical consistency decision. It must NOT later be
presented as a measured model-quality improvement.** No quality comparison between the fp16
and bf16 recipes exists, and none can be made — the fp16 path does not run at all on this
stack.

`bnb_4bit_compute_dtype` moves from `torch.float16` to `torch.bfloat16` under this decision.
E1 had deliberately left it at float16 pending approval, since it is quantization
configuration and was not required to fix the crash; it is now aligned for consistency with
the QLoRA reference configuration.

**Reproducer retained.** `python3.12 finetune.py --smoke --force-fp16` still reproduces the
original incompatibility for the record. It is opt-in only and contradicts this decision by
design.

Evidence: `reports/e1_training_pipeline_smoke.txt` §3a.

---

## D12 — Checkpoint retention

- **Date:** 2026-08-17
- **Status:** APPROVED
- **Implementation:** DONE — applied to `finetune.py` 2026-08-17

**Decision.** Set `save_total_limit=2` for the normal training recipe.

Do **not** change `save_steps` or any other training hyperparameter.

**Rationale.** E1 measured approximately 300 MB per checkpoint/adapter-scale artifact, and the
current production schedule (4 epochs, `save_steps=200`, ~9,900 optimizer steps) could produce
approximately 49 checkpoints — roughly 14.8 GB before optimizer state. Checkpoint retention
must therefore be bounded before any full training run.

Note that the ~300 MB per-checkpoint figure is itself inflated by the `###END###` resize
(see D5); once D5 is implemented, per-checkpoint size should fall to roughly 24 MiB of LoRA
tensors. `save_total_limit=2` remains correct regardless.

Evidence: `reports/e1_training_pipeline_smoke.txt` §9.

---

## D13 — Benign traffic strategy

- **Date:** 2026-08-17
- **Status:** APPROVED
- **Implementation:** DONE — `parse_dataset_v4.py`, 2026-08-17

**Decision.** For the current clean baseline use CSIC Normal traffic plus **improved** synthetic
benign traffic. Do **not** add a new external benign dataset in this phase.

The synthetic benign generator must not replicate a tiny set of templates hundreds of times.
Use parametrized generation producing semantically valid, diverse HTTP traffic from
combinations of method, endpoint, path parameters, query parameters, body schemas, header
profiles, parameter values and realistic application actions. Diversity must not come from
duplicating or trivially mutating identical strings.

**Rationale.** Audit measurement: the historical ALLOW pool was 49,566 rows containing only
23,516 unique inputs, and its synthetic half was **240 unique strings replicated ~110×**.

**Outcome.** 36,721 unique benign logical samples, zero replication; the ALLOW pool is now
100% unique. Values are generated per parameter semantics (ids are integers, emails are
addresses, comments are sentences). External benign datasets may be considered later.

Evidence: `reports/e2_e3_clean_dataset.txt` §6.

---

## D14 — Weak attack categories

- **Date:** 2026-08-17
- **Status:** APPROVED
- **Implementation:** DONE — enforced by `parse_dataset_v4.py`, 2026-08-17

**Decision.** Keep all 19 attack categories as the long-term target. Do **not** artificially
inflate weak categories through repeated duplicates or trivial transformations to equalize
counts. Where a category lacks sufficient high-quality unique samples, report it explicitly as
**INSUFFICIENT DATA** rather than pretending it is equally represented.

For this phase: measure clean unique samples per category, report scarcity, do not fabricate
examples to hit a target, do not remove weak categories silently.

**Implementation note.** No caps or floors were applied. `--cap-per-category` exists but
defaults to **OFF**, so no threshold has been invented. Trimming is the only balancing
operation used anywhere in the generator; nothing is ever duplicated.

**Outcome — 11 categories marked INSUFFICIENT DATA** (under 100 unique logical samples):
Request Smuggling (7), Insecure Deserialization (12), HPP (20), CRLF (21), XPath (24),
CSRF (31), GraphQL (74), LDAP (75), JWT (80), NoSQL (83), XXE (98).

**Request Smuggling has 7 rows, all in train and zero in eval — it is unevaluable on this
dataset.** No per-category performance claim may be made for any category on this list.

Evidence: `reports/e2_e3_clean_dataset.txt` §7.

---

## D15 — Obfuscation strategy

- **Date:** 2026-08-17
- **Status:** APPROVED
- **Implementation:** DONE (separation established) — adversarial suite NOT built

**Decision.** Obfuscation must no longer serve as both training augmentation and adversarial
evidence using the same transform families. Reserve some families for training augmentation
and others as held-out adversarial evaluation. Held-out families must never generate training
examples, and held-out evaluation should also use held-out base payload identities where
practical.

Do **not** implement the final adversarial test suite yet. This phase only restructures
generation so the separation is possible, and documents which transforms belong to which pool.

**Rationale.** Audit finding F8: obfuscated examples were derived from payloads already in the
dataset, and the 20 adversarial test cases reused the same transform families seen in
training. The adversarial suite was therefore in-distribution and measured learned transforms
rather than evasion resistance.

**Pools as implemented:**

| Pool | Transforms | Used in v4 clean? |
|---|---|---|
| Training | `url_encode`, `case_variation`, `sql_comment_inject`, `whitespace_tab` | Yes |
| **Held-out** | `double_url_encode`, `unicode_escape`, `html_entity`, `bash_ifs`, `mixed_case_percent`, `param_fragmentation` | **No — generates nothing** |

**Consequence to disclose:** robustness against held-out transforms is unmeasured by design.

Evidence: `reports/e2_e3_clean_dataset.txt` §9.

---

## D16 — Grouped split

- **Date:** 2026-08-17
- **Status:** APPROVED
- **Implementation:** DONE — `parse_dataset_v4.py`, 2026-08-17

**Decision.** Dataset splitting must occur by source/payload identity **before** rendering
wrappers and derived variants. The same logical source identity must never appear in both
train and eval through exact duplicates, HTTP wrappers, obfuscated variants or formatting
variants.

Required order:

```
SOURCE SAMPLE -> canonical/group identity -> TRAIN or EVAL -> HTTP rendering -> derived variants
```

**not** `source -> variants -> shuffle -> random row split`.

**Rationale.** Audit finding F2: 26.65% of eval appeared verbatim in train, because the
historical generator shuffled and split a pool that already contained duplicates. Model
selection via `load_best_model_at_end` on `eval_loss` was therefore fit to leaked data.

**Implementation.** Canonical keys undo percent-encoding (3 layers), unicode escapes, HTML
entities, inline SQL comments, `${IFS}`, whitespace runs and case — so an obfuscated variant
canonicalizes to the same group as its base. CSIC keys additionally collapse digit runs, since
record identity alone would let `cantidad=1` sit in train and `cantidad=2` in eval. Split is a
deterministic hash bucket, order-independent.

**Outcome:** exact train→eval leakage **0.00%**, within-split duplicates **0.00%**, achieved
eval ratio 0.1972 against a requested 0.20. Invariants are asserted at generation time and the
build fails if violated.

Evidence: `reports/e2_e3_clean_dataset.txt` §8.

---

## D17 — Category contribution control  *(FINAL)*

- **Date:** 2026-08-17
- **Status:** APPROVED — FINAL
- **Implementation:** DONE — `parse_dataset_v4.py` defaults, 2026-08-17

### FINAL POLICY

The final `v4_clean` dataset policy is:

| Lever | Value | Controls |
|---|---|---|
| Cap policy | **B — source-agnostic** | CSIC-derived BLOCK groups count toward the same per-category budget as PayloadsAllTheThings/hardcoded groups |
| Logical-group cap | **2,500 per malicious category** | **source/category DIVERSITY dominance** — applied *before* rendering |
| Rendered-row cap | **4,000 BLOCK rows per malicious category** | **final training CONTRIBUTION** — applied *after* rendering/dedup, *before* balancing |

These are two **independent levers controlling two different quantities**. The logical-group
cap bounds how many distinct source payloads a category may contribute. The rendered-row cap
bounds how much a category actually contributes to training. Both are required: a group cap
alone cannot control contribution, because a CSIC group is a request *shape* that collapsed
many original records and every record still renders. Measured at a 2,500-group cap, SQL
Injection still produced 5,545 rows while Path Traversal produced 2,511.

**Rendered-row selection must remain:** deterministic · source-stratified where multiple
sources contribute · group-preserving · breadth-first (one row per logical group before any
additional rows).

**Do not:** upsample scarce categories · duplicate examples · fabricate examples to reach a
target · force every category to the same row count.

**The purpose is NOT to make all 19 categories equally distributed.**

### Why H2 was selected

Compared with the alternatives measured in `reports/e2_e3_cap_sensitivity.txt` and
`reports/e2_e3_row_cap_sensitivity.txt`, H2 provides:

- ~31,340 total rows
- largest attack-category share ~25.5%
- ~66% of CSIC BLOCK traffic retained
- **100% logical-group retention after row-level subsampling**
- more evaluation data than H1 (6,206 vs 5,550 eval rows)
- substantially less category dominance than the previous cap1000_A candidate (47.3%)

**Key methodological justification:** the row cap removes *redundant renderings* without
eliminating *represented logical diversity*.

> **25.5% is NOT a universal balance threshold.** It is an observed result of the selected
> compromise, and must not be cited as a target or a standard.

### Hard floor, enforced in code

`row_cap` must be **≥** `group_cap`. A category cannot represent G logical groups in fewer
than G rows: the breadth-first round robin exhausts its budget on the first pass and group
retention pins at exactly `row_cap / group_cap`. Measured at row 2000 / group 2500 → 80.0%
retention in four categories. `parse_dataset_v4.py` now refuses to run below the floor rather
than silently destroying logical diversity.

---

### Superseded initial version (2026-08-17, preserved per this file's append-only rule)

The original D17 approved a uniform **1,000 logical-group cap under policy A**. It is retained
below because the sensitivity analyses that replaced it are only interpretable against it.
Two findings retired it: policy A could not control dominance at any cap (SQL Injection never
fell below 36.5% of BLOCK), and cap1000_A was Pareto-dominated — smaller *and* more dominated
than the policy-B alternatives.

**Original decision.** Apply a maximum of **1,000 LOGICAL GROUPS per malicious attack
category**, before HTTP rendering and augmentation.

Purpose: prevent source-rich categories such as Path Traversal from dominating training.

Requirements, all satisfied:

- cap by canonical logical group, **not** final rendered row count ✔
- deterministic selection under the existing seed ✔ (first N by sorted group id, which is a
  sha256 of the canonical payload — order-independent and stable across seed changes)
- do not upsample scarce categories ✔
- do not duplicate examples to meet a floor ✔ (trimming is the only balancing operation)
- preserve all uncapped categories as-is ✔ (15 categories untouched)
- report exactly which categories were capped and how many groups removed ✔

**Outcome under the superseded 1,000/policy-A setting — 4 categories capped, 12,656 logical groups removed:**

| Category | Before | After | Removed |
|---|---:|---:|---:|
| Directory Traversal | 10,218 | 1,000 | −9,218 |
| File Inclusion | 2,937 | 1,000 | −1,937 |
| XSS Injection | 2,224 | 1,000 | −1,224 |
| SQL Injection | 1,277 | 1,000 | −277 |

Attack logical groups 18,445 → 5,789. BLOCK volume spread 1,464.9:1 → 906.7:1.

> **⚠️ The cap shifted dominance rather than removing it.** Path Traversal fell from 19.08% to
> 3.74% of the dataset, but **SQL Injection rose to 23.67%** and is now the largest BLOCK
> category. D17 caps PayloadsAllTheThings/hardcoded logical groups; **CSIC-derived BLOCK rows
> are not capped**, and CSIC's anomalous pool is ~70% SQL injection. Whether to extend the cap
> to CSIC BLOCK groups is an open scope question — see `reports/e2_e3_clean_dataset.txt` §8.

> **⚠️ Correction.** The pre-cap figures used to recommend the 1,000 threshold contained
> transcription errors (Directory Traversal reported as 5,282, actually 10,218; SQL Injection
> reported as 3,741, actually 1,277). The cap is therefore more aggressive than described, and
> SQL Injection was capped when the recommendation implied it would not be. The threshold may
> warrant re-confirmation. Corrected figures: `reports/e2_e3_clean_dataset.txt` §0.

Verified: the cap did **not** reintroduce envelope confounds. Strongest incidental baseline
51.31% (Content-Type), nine of eleven at or below majority, zero deterministic reveals, zero
leakage.

Evidence: `reports/e2_e3_clean_dataset.txt` §1, §3, §5.

---

## D18 — Insufficient-data evaluation policy

- **Date:** 2026-08-17
- **Status:** APPROVED
- **Implementation:** DONE — enforced and recorded by `parse_dataset_v4.py`, 2026-08-17

**Decision.** Keep all 19 attack categories as the long-term project target. Categories without
sufficient independent held-out evaluation evidence must be explicitly marked:

> **INSUFFICIENT DATA / NOT EVALUABLE**

**No category-level accuracy, recall, or other performance claim may be made for such
categories.**

Do not force samples across train/eval merely to make every category evaluable. Do not weaken
the grouped split. Do not synthesize new samples in this step.

**Current candidate — NOT EVALUABLE:**

| Category | Train rows | Eval rows |
|---|---:|---:|
| HTTP Request Smuggling | 7 | **0** |

Determined from the rendered eval split by the generator, not asserted by hand, and recorded in
the manifest under `not_evaluable_categories`.

**INSUFFICIENT DATA (<100 unique logical groups)** — 11 categories: Request Smuggling (7),
Insecure Deserialization (12), HPP (20), CRLF (21), XPath (24), CSRF (31), GraphQL (74),
LDAP (75), JWT (80), NoSQL (83), XXE (98).

The cap did not affect any of these; all sit far below 1,000. Their scarcity is a **source
material** problem — PayloadsAllTheThings provides 56 fenced lines for CSRF and 61 for Request
Smuggling — and cannot be fixed by generator changes.

Evidence: `reports/e2_e3_clean_dataset.txt` §6.

---

## D19 — Frozen V4 evaluation methodology

- **Date:** 2026-08-17
- **Status:** APPROVED
- **Implementation:** DONE — `test_model.py`, experiment E5, 2026-08-17

**Decision.** The evaluation methodology for the first V4 clean baseline is frozen **before**
the training run, so metric definitions cannot be chosen after seeing results.

**Three levels, never combined into one headline number:**

| Level | Measures | Source |
|---|---|---|
| 1 — Binary security decision | ALLOW vs BLOCK | `datasets/v4_clean/eval.jsonl` |
| 2 — Attack category / reason | only over correctly-blocked attacks | same |
| 3 — Latency | model-side inference distribution | same |

**Primary source** is the held-out `datasets/v4_clean/eval.jsonl` (6,206 rows, 3,103 ALLOW /
3,103 BLOCK, 18 categories). The 135 hand-authored cases are **reclassified as a MANUAL
DIAGNOSTIC / REGRESSION SUITE**, preserved in full, reachable via `--mode manual`, and
explicitly **not** the headline metric.

**Positive class is BLOCK**, fixed in code as `POSITIVE_CLASS`. Never switch it silently.

**Binary/category separation.** A reason mismatch on a correctly-blocked attack is
`binary = CORRECT, category = INCORRECT`. Reason accuracy is computed only over
already-correctly-blocked examples, so a category mismatch can never reduce binary recall.

**FPR is reported separately and prominently**, normalised over the benign population
`FP/(FP+TN)`, never buried in overall accuracy. FNR is normalised over the attack population.

**Reason matching is exact after objective normalisation** (casefold, whitespace collapse,
single trailing period). No synonym table, no keyword heuristic, no partial credit — the model
is trained on 19 fixed reason strings, so exact match is the intended bar.

**Invalid outputs are never coerced.** An unparseable output is counted as an incorrect
security decision, mapped to the opposite of expected so it can never earn credit, reported as
a separate invalid-output rate, and accompanied by a parseable-only view. This is evaluation
policy and is deliberately distinct from D4's fail-closed *runtime* behaviour — a model
emitting garbage is not detecting anything.

**Latency** reports count, mean, P50, P95, P99, min, max, stdev; average alone is never
reported. Scope is **model-side inference only** and is stamped as such — it is not comparable
to D3's end-to-end P95 ≤ 200 ms budget.

**D18 is enforced by an evidence-status column**: `OK` / `INSUFFICIENT DATA` / `NOT EVALUABLE`.
Request Smuggling is `NOT EVALUABLE` (zero eval rows). Ten further categories are flagged
`INSUFFICIENT DATA`, from either the manifest's <100-logical-group list or eval support < 30.
Every percentage is printed with its numerator and denominator.

**Rationale.** The historical 91% was a single combined number over a suite where a degenerate
always-BLOCK classifier scored 80.7%, with 26 benign cases and 20-point per-category
resolution. Freezing definitions in advance, separating the three levels, and attaching an
evidence status to every category prevents that class of uninterpretable headline from
recurring.

Verified by `python3.12 test_model.py --mode self-test` (PASS) on controlled fixtures with no
model. Evidence: `reports/e5_evaluation_methodology.txt`.

---

## D20 — V4-clean baseline interpretation

- **Date:** 2026-08-18
- **Status:** APPROVED
- **Implementation:** N/A — an interpretation policy

**Decision.** The first full V4-clean training run (Issue #7) is accepted as the project's
**first scientifically interpretable baseline** under the frozen E5 methodology (D19).

It is explicitly **NOT** treated as:

- a final model,
- a production-ready model,
- proof of robustness on real traffic,
- proof of embedded viability.

Its role is to establish the reference point against which subsequent experiments are
measured.

**Rationale.** The historical ~91% was uninterpretable: a `Host`-only classifier scored
93.4–93.7% on that corpus and 26.65% of its eval split appeared verbatim in training. The V4
result (98.49% accuracy, 97.04% attack recall, 0.06% FPR on 3,103 benign rows) was measured on
a dataset where no incidental envelope feature exceeds 51.16% against a 50.00% majority
baseline, so it cannot be produced by those shortcuts. That makes it a usable reference — and
nothing more, given the limitations recorded in `reports/v4_clean_baseline_results.txt` §11.

Evidence: `reports/v4_clean_training.txt`, `reports/v4_clean_baseline_results.txt`.

---

## D21 — Evidence-driven dataset expansion

- **Date:** 2026-08-18
- **Status:** APPROVED
- **Implementation:** N/A — a standing policy

**Decision.** Do **not** expand the dataset merely to increase row count.

Additional data, or a V4.1 training run, will be considered only when analysis identifies a
defensible weakness such as:

- a systematic false-negative pattern,
- insufficient independent logical diversity,
- failures under external real HTTP laboratory traffic.

**Prioritise independent diversity over raw row count.**

**Explicitly not yet concluded:** that SQL injection or command injection require more
training samples. Those two categories hold 91 of 92 false negatives (~98.9%), but the cause
is not established — label noise in the CSIC-derived subset (audit F6) and payload-family
gaps are equally plausible explanations. **Issue #8 must analyse the observed failures
first.**

**Rationale.** D14 already forbids inflating weak categories with duplicates or fabricated
examples. D21 extends that principle from *category balance* to *corpus growth*: 31,340 rows
is not a deficiency in itself, and adding data before diagnosing the failure risks spending
effort on the wrong problem while contaminating a clean baseline.

---

## D22 — Real HTTP laboratory validation gate

- **Date:** 2026-08-18
- **Status:** APPROVED
- **Implementation:** NOT YET — planned external validation

**Decision.** Before the classifier is treated as sufficiently validated to progress toward
deployment, perform an **external validation using HTTP traffic generated by real
clients/applications in an authorized laboratory**.

This validation must remain **separate from V4 training**. It comprises:

- benign real HTTP traffic, and
- authorized malicious laboratory traffic.

**Contamination rule.** If failures observed during this validation later become training data
for a V4.1, a **fresh independent real-traffic evaluation set must be preserved** so that the
evaluation is never trained on.

**Scope limit.** This is *not* permission to test against systems outside the controlled
laboratory. All traffic must be generated against systems the project is authorized to test.

**Rationale.** The current benign population is synthetic plus CSIC 2010. A 0.06% false
positive rate on that mixture does not establish a low false positive rate on live traffic,
and the legacy manual suite's 23.08% FPR (on only 26 cases) is a weak but real
distribution-shift signal worth taking seriously rather than dismissing.

---

## D23 — The current HuggingFace inference path is not the deployment target

- **Date:** 2026-08-18
- **Status:** APPROVED
- **Implementation:** N/A — sets M2 priority

**Decision.** The measured V4 HuggingFace **model-side P95 is 270.8 ms**. The project
engineering target remains **D3: P95 end-to-end added latency ≤ 200 ms**.

Because model-side latency *alone* already exceeds the entire future end-to-end budget,
**GGUF / Q4_K_M / llama.cpp optimization is on the critical deployment path**, not an optional
refinement. M2 therefore precedes a viable M3.

**This does NOT constitute a formal D3 failure.** D3 is an end-to-end budget covering proxy +
API + model, and it has not been measured on a full gateway. The comparison here is a
one-sided lower bound: end-to-end latency cannot be lower than model-side latency, which is
sufficient to conclude that the *current backend* needs optimization — and not sufficient to
declare D3 passed or failed.

Evidence: `reports/v4_clean_baseline_results.txt` §9.

---

## D24 — Evaluation-set terminology

- **Date:** 2026-08-18
- **Status:** APPROVED
- **Implementation:** N/A — a reporting rule

**Decision.** `datasets/v4_clean/eval.jsonl` is a **held-out evaluation/validation split**.

It participated in periodic evaluation during training and in **best-checkpoint selection**
(`load_best_model_at_end=True` restored `checkpoint-2200` on its `eval_loss`). It must
therefore **NOT** be described as a completely untouched final test set.

Future external real-traffic validation (D22) and/or a separate independent test set should
provide the additional generalization evidence that this split cannot.

**Rationale.** The split is genuinely leakage-free with respect to training data (E0: 0.00%
exact leakage, grouped split per D16), so it is a valid held-out measurement. But it informed
model selection, which is a mild optimistic bias that must be disclosed rather than glossed.
Precision of language here is cheap; retracting an overstated claim later is not.

---

## D25 — Control Plane contract and invalid-output handling

- **Date:** 2026-09-05
- **Status:** APPROVED
- **Implementation:** DONE — `classifier_api.py` + `inference_core.py`, Issue #15

**Decision.** The Control Plane reports a classification; it does not enforce one.

`POST /classify` returns `status: "ok"` or `status: "invalid"`.

- `ALLOW` / `BLOCK` exist **only** for outputs that satisfy the E4 contract regex. When
  `status == "ok"`, `decision` and `reason` are populated.
- When the model output cannot be parsed, `status` is `"invalid"` and **both `decision`
  and `reason` are null**. The output is **NOT coerced** — not to `ALLOW`, not to
  `BLOCK`, and not by any heuristic that guesses what the model meant.
- The future Data Plane is responsible for applying **fail-closed** when it receives an
  `invalid` result, an error response, or a timeout.

**D4 remains in force.** D25 does **not** supersede it. D4 decides *what happens to
traffic* when the classifier is unusable (it is blocked); D25 decides *where that
decision is taken* (the Data Plane) and *what the Control Plane must report* so the
Data Plane can take it. D25 refines the separation of responsibilities between the two
planes; it changes nothing about the fail-closed policy itself.

**Rationale.** Coercion destroys the information the Data Plane needs. The deleted legacy
`classifier_api.py` mapped any unparseable output to `"BLOCK" if "BLOCK" in output else
"ALLOW"`, so a garbled or truncated generation silently became **ALLOW** — fail-open, and
indistinguishable from a genuine ALLOW decision at the caller. Reporting invalidity
explicitly is also what makes the evaluation and the runtime agree: `parse_prediction()`
has never coerced (frozen E5 policy), and the Control Plane now uses that same function.

Evidence: real-inference A/B parity over 30 held-out rows (0/30 mismatches) and 14 unit
assertions that an unparseable output can never surface as `ALLOW`.

---

## D26 — HF/PEFT Control Plane baseline before llama.cpp optimization

- **Date:** 2026-09-05
- **Status:** APPROVED
- **Implementation:** DONE — Issue #15

**Decision.** The Control Plane was deliberately implemented on the **current
HuggingFace/PEFT backend**, before any GGUF / llama.cpp work, to establish a functional
and integrable baseline for the inline gateway.

This **partially advances M3 ahead of M2**, inverting the previously recorded order in
which the FastAPI control plane (issue #15) depended on llama.cpp integration (issue #12).

**This does NOT make HF/PEFT the deployment backend.** GGUF export, Q4_K_M quantization
and llama.cpp inference remain pending and remain on the critical deployment path.

No multi-backend abstraction, factory or plugin layer was built. `inference_core.py` is
kept as the only place that loads a model and generates, so a future backend can replace
it without rewriting FastAPI — but no interface was designed for a second backend that
does not yet exist.

**Relationship to D23.** D23 concluded that the measured model-side P95 of 270.8 ms
already exceeds the entire 200 ms end-to-end budget of D3, and that GGUF/Q4_K_M/llama.cpp
optimization is therefore on the critical path rather than an optional refinement, so M2
precedes a *viable* M3. **That conclusion still holds and D23 is NOT superseded.** D26
only separates two things D23 did not distinguish: building the control plane, and
deploying it. A control plane can be built, tested and integrated on a backend that is
too slow to ship, and doing so de-risks the mitmproxy work without waiting for
quantization. D23 continues to govern what may eventually be deployed.

**Rationale.** The control plane is mostly HTTP plumbing over an inference call. Blocking
it on quantization would have left the whole gateway path unexercised while the backend
was optimized, and would have delayed discovery of contract problems — of which one
(silent ALLOW coercion, see D25) was real and is now fixed.

---

## D27 — Canonical V4 runtime inference configuration

- **Date:** 2026-09-05
- **Status:** APPROVED
- **Implementation:** DONE — `inference_core.load_model()`

**Decision.** The canonical **runtime** quantization configuration is:

```
load_in_4bit=True
bnb_4bit_quant_type="nf4"
bnb_4bit_compute_dtype=torch.bfloat16
```

with **no double quantization** at runtime.

This is exactly the configuration used by the V4 evaluation pipeline that produced the
baseline in `reports/v4_clean_eval.json`, and it is the configuration against which the
Control Plane was verified for parity. It now has a single definition, in
`inference_core.load_model()`, shared by the evaluation harness and the Control Plane.

**Training configuration may differ, and does.** `finetune.py` additionally sets
`bnb_4bit_use_double_quant=True`. That value is **not** mirrored into runtime, and
`finetune.py` is **not** being modified. Training and inference configurations do not have
to be identical; what matters is that runtime matches the configuration under which the
published metrics were measured.

**Rationale.** Before this decision three different quantization configurations existed in
the repository, and the deleted legacy `classifier_api.py` used `float16` as its compute
dtype — a value D11 had already moved away from. Serving under a configuration different
from the one the metrics were measured under would make any discrepancy between the API
and the evaluation unexplainable. Changing this configuration requires an experiment, not
a preference.

---

## D28 — Control Plane readiness behaviour

- **Date:** 2026-09-05
- **Status:** APPROVED
- **Implementation:** DONE — `classifier_api.py`

**Decision.** The FastAPI process **stays alive even if the model fails to load** at
startup. In that state:

- `GET /health` returns **200** with `model_loaded: false`
- `POST /classify` returns **503**

The failure is logged with its traceback at startup.

This lets a caller distinguish three different conditions that would otherwise collapse
into one: *service absent* (connection refused), *service up but not ready*
(`model_loaded: false`, 503), and *service ready* (`model_loaded: true`).

The future Data Plane must treat "up but not ready" as an unusable classifier and apply
**fail-closed** per **D4**, exactly as it would for an `invalid` result or a timeout. A
readable readiness signal is not permission to fail open.

**Rationale.** An inline gateway needs to tell "the classifier is broken" apart from "the
classifier is not there", because the two have different operational responses even though
both must block traffic. Exiting on a load failure would surface only as a refused
connection and would hide the reason, which is recoverable information the operator needs.

---

## Decision index

| ID | Topic | Status | Implementation |
|----|-------|--------|----------------|
| D1 | HTTP request representation — neutralize envelope shortcuts | APPROVED | NOT YET |
| D2 | CSIC excluded anomalies — keep out of baseline | APPROVED FOR FUTURE WORK | N/A |
| D3 | Latency target — P95 ≤ 200 ms end-to-end added | APPROVED | N/A |
| D4 | Failure behavior — FAIL-CLOSED | APPROVED | OUT OF CURRENT SCOPE |
| D5 | Remove `###END###`, use native termination | APPROVED | **DONE (E4)** |
| D6 | Dataset versioning — manifest-based, no `git rm` yet | APPROVED | NOT YET |
| D7 | Scientific integrity over the historical 91% | APPROVED | N/A |
| D8 | Core project scope — 7 mandatory items | APPROVED (advisor confirmation where needed) | IN PROGRESS |
| D9 | Conventional rule-based comparison | FUTURE WORK | OUT OF CURRENT SCOPE |
| D10 | Embedded deployment — platform TBD | CORE REQUIREMENT | NOT YET |
| D11 | Training precision — BF16 (compatibility, not quality) | APPROVED | DONE |
| D12 | Checkpoint retention — `save_total_limit=2` | APPROVED | DONE |
| D13 | Benign traffic — CSIC + parametrized synthetic, no external set | APPROVED | DONE |
| D14 | Weak categories — report INSUFFICIENT DATA, never inflate | APPROVED | DONE |
| D15 | Obfuscation — train pool vs held-out pool | APPROVED | DONE (suite not built) |
| D16 | Grouped split before rendering | APPROVED | DONE |
| D17 | Category contribution control — policy B, group cap 2,500, row cap 4,000 | **APPROVED FINAL** | DONE |
| D18 | INSUFFICIENT DATA / NOT EVALUABLE policy | APPROVED | DONE |
| D19 | Frozen V4 evaluation methodology | APPROVED | DONE (E5) |
| D20 | V4-clean baseline interpretation | APPROVED | N/A |
| D21 | Evidence-driven dataset expansion | APPROVED | N/A |
| D22 | Real HTTP laboratory validation gate | APPROVED | NOT YET |
| D23 | Current HF inference path is not the deployment target | APPROVED | N/A |
| D24 | Evaluation-set terminology | APPROVED | N/A |
| D25 | Control Plane contract — `status` ok/invalid, never coerced | APPROVED | **DONE (#15)** |
| D26 | HF/PEFT control-plane baseline before llama.cpp | APPROVED | **DONE (#15)** |
| D27 | Canonical V4 runtime inference configuration | APPROVED | **DONE (#15)** |
| D28 | Control Plane readiness behaviour — 200/`model_loaded`, 503 | APPROVED | **DONE (#15)** |

---

## Items still requiring advisor decision

Recorded here so they are not silently resolved by implementation.

- Whether dataset-artifact analysis (the envelope ablation, E2) is acceptable as a primary
  research contribution, given D7 accepts that accuracy may fall.
- Confirmation of the D8 core scope, particularly whether physical embedded deployment (D10)
  is required for the grade or is acceptable as documented future work.
- Whether the conventional rule-based comparison (D9) is ultimately required.
