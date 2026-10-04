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
- **Implementation:** **DONE — experiment E2, 2026-08-17** (shared envelope generator and
  shape matching in `parse_dataset_v4.py`; the verification below is met on `datasets/v4_clean/`:
  E0 reports no deterministic label reveal, warnings for category scarcity only —
  `reports/e0_dataset_integrity_v4_clean.txt`). *Status field updated 2026-10-01.*

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
- **SUPERSEDED BY D36** (2026-09-18). The original entry below is preserved unchanged.

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
- **Implementation:** **DONE (first version) — `data_plane.py`, 2026-09-16; see D34**

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
- **Implementation:** **DONE for V4 — External Test v1** (built under D38, frozen at
  `36df2ee`, executed as `external-v1-run-001`, 2026-09-21). The contamination rule below
  stays in force (D40). *Status field updated 2026-10-01.*

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

## D29 — Heuristic suspicious scoring and benign fast path

- **Date:** 2026-09-06
- **Status:** APPROVED
- **Implementation:** NOT YET — issues #35 (scoring), #36 (fast path), #38 (calibration)

**Decision.** The gateway will compute a fast, explainable **suspicious score** for each
request before deciding whether that request needs synchronous model inference.

- Only traffic scored **sufficiently benign** may take a **FAST ALLOW** path and be served
  without waiting for the model.
- Every remaining request goes to the model and is classified as it is today.
- **There is no heuristic fast BLOCK in the first version.** The score may allow a request;
  it may never block one on its own. A blocking decision requires the model.
- There is exactly one benign gate. A request that fails the benign threshold goes to the
  model; no second, looser threshold may allow it instead.
- Scoring signals, weights and thresholds must be **configurable and measurable**, and the
  fast path must be switchable off so the gateway can be compared against its own
  no-fast-path baseline.

**The purpose is latency, not security.** The fast path does not replace the model's
security classification; it decides only whether that classification has to happen *before*
the response instead of after (see **D30**). Any latency gain must be weighed against the
measured disagreement rate before the fast path is kept.

**Rationale.** **D23** records that model-side P95 (270.8 ms) already exceeds the entire
200 ms end-to-end budget of **D3**, so the average path has to get shorter somehow.
Quantization (M2) attacks the cost of each inference; the fast path attacks how often
inference is needed at all. They are independent and can both apply.

The asymmetry — allow-only, never block — is deliberate. A heuristic false ALLOW is
recoverable and measurable through D30's deferred validation; a heuristic false BLOCK
breaks legitimate traffic with no model judgement behind it and no signal that it happened.
The V4 error profile is already asymmetric in the same direction (92 false negatives
against 2 false positives), and this keeps the heuristic layer from adding a *new* class of
false positive on top.

This is **not** a second ML model, **not** online learning, and **not** an open-ended rule
catalogue. The initial signal set stays small, cheap and explainable.

---

## D30 — Deferred model validation for fast-path traffic

- **Date:** 2026-09-06
- **Status:** APPROVED
- **Implementation:** NOT YET — issue #37

**Decision.** Requests served through the **FAST ALLOW** path of **D29** are classified by
the model **afterwards**, asynchronously and outside the critical path.

- The served response never waits for that classification.
- For each validated request the system records the **fast-path decision**, the **model
  decision**, and whether they **agree**.
- Disagreements — the model returns BLOCK where the heuristic allowed — are counted and
  individually inspectable.
- A request that has already been served is **never retroactively blocked**.
- A failure in the validation path never affects the request that was already served.

The output is **evidence**: it measures the real cost of the fast path and curates
candidate data for a future model revision.

**There is no online learning.** The model, its adapter and its weights are never updated
automatically by this mechanism. Any model change remains a deliberate, evaluated action
under the existing training and evaluation decisions (**D19**, **D21**).

**Rationale.** Without deferred validation, a heuristic false ALLOW is invisible: the
request is served and nothing ever checks it. D29 is only defensible if the traffic it
waves through is still measured, so the disagreement rate becomes a number that can be
weighed against the latency gain rather than an assumption. It also produces exactly the
kind of evidence **D21** requires before any dataset expansion is considered — real traffic
the current system judged, rather than more synthetic rows.

Retroactive blocking is excluded because it is not achievable: the response has already
been delivered. Pretending otherwise would misrepresent the security property.

---

## D31 — Model-side latency is measured with a device-synchronized stopwatch

- **Date:** 2026-09-09
- **Status:** APPROVED
- **Implementation:** DONE — `inference_core.classify_timed()` / `device_sync()` (Issue #9)

**Decision.** The canonical model-side latency measurement is the time spent inside
`generate()`, bracketed by an explicit device synchronization on both sides.

```
IN  scope   generate()
OUT scope   prompt construction · tokenization · host->device transfer ·
            decoding · contract parsing
```

The out-of-scope stages are still timed, but they are reported as separate pipeline
stages and are never pooled into the primary metric. The scope carries an identifier —
`generate-only/device-synchronized/v1` — and two results with different scope
identifiers are **not comparable**, whatever units they are printed in.

**This is a stopwatch correction, not a model improvement.** CUDA kernel launches are
asynchronous: a timer stopped immediately after `generate()` returns can measure the
*submission* of work rather than its completion. `torch.cuda.synchronize()` removes that
class of error by construction. Nothing about the model, adapter, prompt, generation
parameters, parsing or quantization changed, and the decision returned for a given
request is unchanged (verified: identical output through both code paths).

**Measured effect of the correction on this machine.** Interleaved A/B measurement,
n=40 per arm, same requests, same process, run twice:

| measurement | unsynchronized mean | synchronized mean | delta |
|---|---:|---:|---:|
| before the baseline runs | 223.75 ms | 223.77 ms | **+0.020 ms (+0.009%)** |
| after the baseline runs (`verify-timing`) | 235.08 ms | 234.17 ms | **−0.909 ms (−0.387%)** |

The delta is **below 0.4% and inconsistent in sign**, i.e. indistinguishable from the
machine's own run-to-run noise. The explanation is that HuggingFace `generate()` already
forces a synchronization on every decoding step when it evaluates stopping criteria, so
the older timer was, in practice, already measuring completed work. The decoded output is
identical through both code paths.

Reproduce: `python3.12 benchmark_inference.py verify-timing --experiment <id> --limit 40`.
Record: `reports/benchmarks/baseline-local-v1/timing_method_ab.json`.

The correction is therefore kept for **guaranteed** correctness rather than for a
different number, and it must hold under future backends that may not synchronize
internally. It also means the historical figures were not inflated or deflated by
missing synchronization — but they remain **historical antecedents** rather than
comparands, because they were produced under a different protocol (single run, no
separation of load / cold start / warm-up from steady state). See **D32**.

**Rationale.** A latency programme whose first act is to optimize the engine (M2, D23)
must be able to prove that a later reduction is real. That requires knowing that the
stopwatch measures finished GPU work under every future backend, including ones that do
not happen to synchronize internally. Establishing the guarantee now — and quantifying
that it changes nothing today — is cheaper than discovering later that a "reduction" was
an artifact of asynchronous submission.

---

## D32 — Benchmark experiment identity, immutability and comparison rules

- **Date:** 2026-09-09
- **Status:** APPROVED
- **Implementation:** DONE — `benchmark_inference.py`, `benchmark_compare.py` (Issue #9)

**Decision.** Every inference benchmark is an **experiment with an identity**, stored
under `reports/benchmarks/<experiment-id>/`, and comparisons between experiments follow
fixed rules.

**Identity.** An experiment records its timing scope, dataset SHA-256, request selection
and order, protocol version, batch size, concurrency, run count, model and adapter
hashes, effective quantization, and the full machine environment. The reference
experiment is **`baseline-local-v1`**.

**Immutability.** `baseline-local-v1` is a fixed reference. A new measurement takes a new
experiment id; the harness refuses to overwrite an experiment that already has results.
A candidate may be compared against the original baseline **and** against its own
immediately preceding version.

**Comparison.**

```
percentage reduction  =  100 * (baseline - candidate) / baseline
speedup factor        =  baseline / candidate
```

These are distinct quantities — a 50% reduction is a 2.0x speedup — and are reported
separately, per statistic. A negative reduction is a regression and is reported as such.
Missing values, zero references and negative references are reported as undefined, never
silently rendered as 0%.

**Two results are not comparable merely because both are in milliseconds.** Timing scope,
dataset hash, request count, selection policy, request order, protocol version, batch
size and concurrency must match. A mismatch is **blocking**: the comparison is stamped
NOT COMPARABLE and the tool exits non-zero.

**Attribution.**

- A **hardware** change (GPU, CPU, device) does not block a comparison but invalidates
  any claim of a software improvement. The base version of the software must be re-run on
  the new hardware, and the candidate compared against *that*.
- When hardware and software both changed, the difference is reported as a **joint
  effect**. Causality is not attributed to either alone.
- A speed improvement is **never** presented without naming any accompanying quality
  degradation. The comparison tool raises this pairing automatically.

**Rationale.** The point of a baseline is to make a future claim falsifiable. Without a
recorded identity, "P95 dropped 40%" is unverifiable: the two runs could differ in
dataset, in what the stopwatch covered, in the machine, or in how many requests were
measured. Encoding the compatibility rules in the tool rather than in prose means an
invalid comparison fails loudly instead of being asserted confidently — and it is the
reason the historical 270.8 ms is blocked automatically when someone tries to use it as
a comparand (**D31**).

---

## D33 — Separate Python environments for the data plane and the ML/control plane

- **Date:** 2026-09-16
- **Status:** APPROVED
- **Implementation:** DONE — `.venv-dataplane`, `requirements-data-plane.txt` (Issue #16)

**Decision.** The data plane (mitmproxy) runs in its own Python environment,
`.venv-dataplane`, with its own dependency file, `requirements-data-plane.txt`.
`requirements.txt` remains the ML/control-plane stack and does not list mitmproxy. No data
plane dependency is installed into the ML interpreter, and no ML dependency is changed to
make mitmproxy fit.

**Rationale.** mitmproxy 12.2.3 pins `typing-extensions<=4.14` on Python < 3.13, while
pydantic 2.13.4, used by the control plane, requires `typing-extensions>=4.14.1`. A shared
interpreter would downgrade a dependency of the verified control plane. The planes only
talk over HTTP (D34), so separate environments cost nothing functionally. This is a scoped
exception to the "no virtual environments" preference in `CONTEXT.md` §2, which still
applies to the ML stack.

---

## D34 — Data plane enforcement: decisions over HTTP, 403 / 503, fail-closed

- **Date:** 2026-09-16
- **Status:** APPROVED
- **Implementation:** DONE (first version) — `data_plane.py` (Issues #16, #17)

**Decision.**

- The proxy obtains every decision from the control plane over HTTP (`POST /classify`,
  unchanged D25 contract). It **never loads the model**.
- `ALLOW` — HTTP 200 with `status: "ok"` and `decision: "ALLOW"` — lets the request
  continue to the destination. Nothing else does.
- `BLOCK` from the model: the proxy answers **`403`**, and the request is not forwarded.
- Classifier failure or no valid decision (timeout, connection error, non-200 answer,
  invalid JSON, `status: "invalid"`, missing or unknown decision, or an unexpected error
  inside the addon): the proxy answers **`503`**, and the request is not forwarded.
- **Fail-closed (D4) is confirmed** as the live behaviour.
- The internal HTTP client uses `trust_env=False`, so `HTTP_PROXY`/`HTTPS_PROXY` cannot
  route the classifier call back into the same proxy.

**Evidence.** `tests/test_data_plane.py` (21 tests). Manual run on 2026-09-16 with the real
V4 model:

- ALLOW reached the destination (`200`).
- A SQL injection request got `403` and never reached the destination.
- With the classifier stopped, a benign request got `503` and never reached the
  destination.

mitmproxy 12.2.3 forwards a request whose hook raised, and keeps proxying when a hot
reload of the script fails. Both behaviours were verified, and both are closed in
`data_plane.py`.

**Rationale.** Separate 403 and 503 answers keep "the model judged this request malicious"
distinct from "no decision could be obtained" for both client and operator. This carries
the D28 distinction through to traffic. `trust_env=False` removes the request loop that a
shell configured to use the gateway would otherwise create.

---

## D35 — D3 is a performance objective; the classifier timeout is operational

- **Date:** 2026-09-16
- **Status:** APPROVED
- **Implementation:** DONE — `config.yaml`, `data_plane.classifier_timeout_seconds: 3.0`

**Decision.**

- **P95 end-to-end ≤ 200 ms (D3) is a project performance objective.** It is **not** a
  blocking or acceptance criterion for the first data plane implementation.
- Existing latency figures are **model-side / control-plane** measurements: the Issue #8
  evaluation, the preliminary Issue #15 observation and `baseline-local-v1`. **No formal
  end-to-end benchmark of the complete system exists yet** (Issue #18).
- The data plane's classifier timeout is configurable, with an **initial value of 3 s**.
  It is an **operational limit** for detecting a failed or hung classifier and applying
  fail-closed (D34). It **does not represent the latency objective**, and it **will be
  tuned with end-to-end evidence**.

**Relationship to earlier entries.** Their text is preserved; none is superseded.

- D3's decision is unchanged. Its rationale described a stated latency budget as a
  prerequisite for choosing a classifier timeout, but the timeout is no longer chosen
  that way.
- D23, D26 and D29 describe model-side P95 as already exceeding "the entire 200 ms
  end-to-end budget". Those statements compare a model-side figure with the objective's
  value, and they motivate prioritizing inference optimization (M2) and the fast path.
  They are not end-to-end measurements and not a failed requirement; D23 already states
  that its comparison is not a formal D3 failure.

**Rationale.** A 200 ms timeout would sit below the measured steady-state model-side P50
(238.82 ms, `baseline-local-v1`), so it would have failed closed on at least half of the
requests in that measurement. The timeout answers "is the classifier broken?". The
objective answers "is the gateway fast enough?", a question only an end-to-end benchmark
can settle.

---

## D36 — Latency objective: P95 of the inference pipeline ≤ 200 ms (supersedes D3)

- **Date:** 2026-09-18
- **Status:** APPROVED — **supersedes D3**
- **Implementation:** N/A (an objective, not a build task). **Not met** by the current
  baseline.

**Decision.** The project latency objective is:

> **P95 of the latency added by the model inference pipeline ≤ 200 ms, in steady state.**

The inference pipeline is everything needed to turn one raw HTTP request into a valid
ALLOW/BLOCK decision:

- preparation for inference: prompt construction, tokenization, host→device transfer;
- model execution: `generate()`;
- post-processing: decoding and contract parsing into a valid `ALLOW` / `BLOCK` decision.

Excluded: initial model load · cold start (the first inference in a fresh process) and
warm-up · HTTP transport to and from the control plane · network latency · the data
plane / proxy · the destination server · complete end-to-end system latency.

**Measurement.**

- Steady state only. Model load, cold start and warm-up are measured and reported
  separately. They are never pooled into the objective's statistic and never discarded.
- Instrument: `benchmark_inference.py` under the `baseline-local-v1` protocol (batch size
  1, concurrency 1, recorded hardware). The statistic is `steady_pipeline_p95_ms`, scope
  `prompt+tokenize+transfer+generate+decode+parse`, which the harness already records.
  `generate()` stays the benchmark's primary comparison metric (D31, D32), and it accounts
  for almost all of the pipeline.
- `model_latency_ms` from `/classify` covers `generate()` only, and `test_model.py` pools
  the cold first inference into its latency figures. Neither is the objective's
  instrument.

**Current status: not met.** `baseline-local-v1` (2026-09-09, RTX 4090 Laptop GPU,
n = 18,618): steady-state pipeline P95 **269.58 ms**; `generate()` alone 269.01 ms. The
≤ 200 ms figure is an **optimization objective** and must not be presented as met. On this
machine P95 moves by about 11% between back-to-back runs, so progress claims must control
run order and thermal state (D32).

**Rationale.** The objective measures the cost of adding the ML component to the gateway,
not the total latency of every component in the system. The proxy, HTTP transport,
network and destination server exist with or without a classifier, and they depend on
deployment choices unrelated to the model. Stated at the inference pipeline, the objective
can be measured today with the existing harness, and the comparison with
`baseline-local-v1` is direct rather than a lower bound.

**Relationship to earlier entries.** Their text is preserved; none is rewritten.

- **D3 is superseded.** Its objective (end-to-end added latency P95 ≤ 200 ms) no longer
  applies. Its instruction to measure model-only, model + API, proxy overhead and
  end-to-end latency separately, with P50, P95, P99 and throughput, still stands.
- **D19, D23, D26, D29 and D35** describe the 200 ms objective as an end-to-end budget.
  That description is superseded. Their conclusions stand, and D23's becomes stronger: the
  inference latency is now compared with the objective directly, not as a one-sided lower
  bound, and the current HuggingFace path does not meet it. GGUF / Q4_K_M / llama.cpp
  (M2) stays on the critical path.
- **D35 otherwise stands.** The objective is not an acceptance criterion for the first
  data plane, and the 3 s classifier timeout is an operational limit not derived from it.
- **The fast path (D29, D30) is not the mechanism for meeting D36.** D36 measures the
  performance of the inference pipeline. The fast path is a future optimization of overall
  latency and load that avoids some inferences; it does not reduce the time of an
  inference.
- **End-to-end latency** is still measured and reported per layer (Issue #18). No
  end-to-end threshold is defined at present.
- Artifacts produced before this entry (`reports/e5_evaluation_methodology.txt`,
  `reports/v4_clean_baseline_results.txt`, `reports/v4_inference_benchmark.md`,
  `reports/benchmarks/baseline-local-v1/`) use the D3 wording and are not rewritten.

---

## D37 — Evaluation data roles from V5 on: train, validation, internal test, external test

- **Date:** 2026-09-18
- **Status:** APPROVED
- **Implementation:** NOT YET — applies from V5. V4 is not changed retrospectively.

**Decision.** From V5 on, every model version is developed and evaluated with four
separate data roles:

| Role | Used for | Never used for |
|---|---|---|
| **TRAIN** | fitting the weights | — |
| **VALIDATION** | checkpoint selection, hyperparameters and development decisions | reporting final results |
| **INTERNAL TEST** | independent evaluation inside the internal pipeline's distribution | selecting a checkpoint or tuning the model |
| **EXTERNAL TEST** | independent evaluation with respect to the internal pipeline: measuring generalization and comparing versions | correcting the model: its individual examples do not guide dataset or model changes |

- Sets are separated by logical identity before rendering (D16), external sets included.
- **A test set that guides a change is no longer a test set.** Reporting aggregate and
  per-slice metrics does not affect a test set. If the individual errors of a test set are
  inspected and those errors guide a dataset or model change, that set stops being an
  independent test and becomes **development / error-analysis data**. The change is
  recorded with the set, and claims about the next version need a test set that has not
  been used that way.
- Individual failures are studied, hypotheses formed and A/B tests seeded on
  development / error-analysis data (`docs/ml_evaluation_methodology.md` §1, §4).
- Comparing two versions requires a test set that neither version was trained or tuned on.

**V4 did not fully meet this separation.** `datasets/v4_clean/eval.jsonl` served as
VALIDATION, because `load_best_model_at_end` selected `checkpoint-2200` on its `eval_loss`,
and afterwards as the internal evaluation behind every reported V4 metric. It is held out
from training (0.00% exact leakage, grouped split per D16) but it is **not** an independent
internal test (D24). V4 has no external test. **V4 is not changed retrospectively:** its
results stand as reported, with this limitation stated.

**Consequences for V5.** VALIDATION is a grouped split carved from training groups, so the
internal test is only ever reported. If individual V4 eval errors, such as the 92 false
negatives under analysis (D21), guide V5 changes, `eval.jsonl` becomes development data for
those changes and cannot serve as an independent test of V5.

**Rationale.** A set used to select or correct a model is optimized against, so its metrics
become optimistic. Fixing the roles in advance keeps the internal and external tests
unbiased, and makes any contamination a recorded event rather than something discovered
after results are reported.

**Relationship to earlier entries.** Nothing is superseded. D37 extends **D24**, which
fixed the terminology for V4's eval split, and generalizes the contamination rule of
**D22** from real-traffic validation to every test set. The metric definitions of **D19**
are unchanged.

---

## D38 — External test construction: capture, label, gate and freeze before model exposure

- **Date:** 2026-09-21
- **Status:** APPROVED
- **Implementation:** DONE — External Test v1, frozen at `36df2ee`

**Decision.** An external test set is built in this order, and no case reaches the model —
directly or through the gateway — until the last step is committed:

1. **Capture.** Real clients drive applications the project owns, inside the authorized
   lab, through a capture-only path with no classifier. The frozen request text is the
   captured bytes, never a hand-written or hand-edited string.
2. **Ground truth.** Assigned from the intent of the flow that produced each request,
   never from a model output. Two-pass review; ambiguous cases are excluded, not guessed,
   and every exclusion is logged.
3. **Independence gate.** Blocking checks for exact and canonical collisions
   (`parse_dataset_v4.canonical_key`, D16) against the model's train and eval data, prior
   diagnostics and fixtures, plus internal duplicates. Freeze cannot proceed while any
   check fails.
4. **Deterministic selection** to the composition declared in advance: a seeded,
   content-independent key, sorted, first *n* per cell. Seed and key formula are recorded;
   no manual choice and no model output enter the selection.
5. **Freeze.** Cases, a manifest with `status: FROZEN`, SHA-256 sums and an aggregate
   integrity hash, committed.
6. **Only then** execution.

Composition, class balance, slices and metric definitions are fixed in a written
protocol before the data exists. The independence claim is limited to the development
data actually checked: no claim is made about the base model's pretraining corpus, global
novelty or out-of-distribution status.

**Rationale.** Labels or selections made after the model has been seen can be steered by
its output, knowingly or not. D19 froze the V4 metric definitions before training for the
same reason. `real-http-fp-v1` used benign texts built by hand from real clients' header
sets; capturing real traffic replaces that construction step.

**Relationship to earlier entries.** Realizes, for V4, the laboratory validation required
by **D22** and the EXTERNAL TEST role defined by **D37**. Uses the D16 canonicalization.
Nothing is superseded. Protocol: `docs/external_test_v1_protocol.md`.

---

## D39 — Frozen external test sets are immutable; any change requires a new version

- **Date:** 2026-09-21
- **Status:** APPROVED
- **Implementation:** DONE — External Test v1 (`datasets/external_v1/manifest.json`)

**Decision.**

- A frozen external set is immutable from the commit containing its manifest with
  `status: FROZEN`, `artifact_sha256` and `frozen_utc`. That commit must be an ancestor of
  every run that cites the set.
- **Any change to any case requires a new version** (External v2, v3, …), never an edit —
  including correcting a label later found to be wrong, removing a case or rebalancing a
  cell. A mislabel is disclosed as a known defect of the version it is in.
- **Reserve cases are not substitutes.** Eligible cases the seeded selection did not pick
  are kept as evidence of the selection and never replace a frozen case.
- A run verifies the frozen integrity hash before executing and refuses to reuse an
  existing run id (the **D32** rule).
- **Raw execution evidence is never rewritten.** When a raw log holds more than one run or
  session, the analysis uses a derived file beside it; the original stays byte-for-byte
  as captured.

**Rationale.** A test set that can be edited after its results are known can be optimized
against. Immutability turns every later change into a recorded new version instead of a
silent revision of the old one.

**Relationship to earlier entries.** Extends to evaluation sets the immutability and
identity rules **D32** set for benchmark experiments. Recorded in the External v1 manifest
(`immutability`).

---

## D40 — Using External Test v1 errors for V5 makes it V5 development data; External v2 is required for V5

- **Date:** 2026-09-21
- **Status:** APPROVED
- **Implementation:** NOT YET — triggers when V5 error analysis starts

**Decision.** Reporting External v1's aggregate and per-cell metrics does not consume it.
The moment individual External v1 cases or errors — for example its false positives — are
inspected to form hypotheses or to guide any V5 change (dataset, prompt, model,
threshold, checkpoint), External v1 becomes **V5 development / error-analysis data**:

- the transition and its date are recorded beside the set, in a separate record — the
  frozen manifest is not edited (D39);
- **any claim about V5's external performance requires External v2**, built under D38
  before V5 is exposed to it, and collision-gated against External v1 as well as against
  V5's own development data;
- **External v2 must execute the proxy-to-classifier byte-equivalence check** that External
  v1 preregistered (protocol §11) but did not run: for every gateway execution, the exact
  bytes the data plane sends to `/classify` are captured, hashed and compared with the
  frozen `request_text`, and every mismatch is recorded. The capture tooling is verified
  present and working in the execution environment before any case is sent; a run that
  cannot capture does not start. Client-side hashes of the text sent, and direct-vs-gateway
  decision agreement, do not substitute for this check;
- **External v2 must implement and run the CSIC-ancestry warning check** that External v1
  pre-registered (protocol §7, check 7) but did not execute, before freeze, against a local
  copy of the CSIC data verified by the SHA-256 in `docs/data_sources.md`. External v1's
  missing check is not reconstructed after exposure;
- External v1 remains the valid record of **V4's** external result. A V4-vs-V5 comparison
  on External v1 must be labelled as a comparison on V5 development data.

**Rationale.** Once its errors have guided the changes, a set measures how well V5 was fitted
to it, not how V5 generalizes. The byte-check requirement exists because External v1's
run-001 could not execute it (no `strace` in the data-plane runtime), so External v1 has no
direct byte-for-byte evidence that the classifier input equalled the frozen text for its
400 gateway cases. Decision agreement is not proof of byte equivalence.

**Relationship to earlier entries.** Applies the general rule of **D37** to External v1
and V5, and makes the consequence — External v2 — an explicit commitment. The External v1
manifest records the same tripwire (`d37_tripwire`).

---

## D41 — Gateway evaluations report L1, L2 and L3 separately

- **Date:** 2026-09-21
- **Status:** APPROVED
- **Implementation:** DONE — External Test v1 (`external-v1-run-001`)

**Decision.** Every evaluation executed through the gateway reports three levels and never
merges them into one number:

| Level | Compares | Error means |
|---|---|---|
| **L1 — model** | ground truth vs the model's decision | FP, FN, invalid output |
| **L2 — enforcement** | the model's decision vs the gateway's observed behaviour (HTTP status + destination receipt), under the D34 contract, whether or not the decision was correct | enforcement fault |
| **L3 — end-to-end** | ground truth vs delivery to the destination | BLOCK-labelled request delivered, benign request broken |

- Every L3 failure is attributed to a model error or an enforcement error. Example: ground
  truth BLOCK, model ALLOW, request forwarded → L1 false negative, L2 conformant, L3
  BLOCK-labelled request delivered.
- **Delivery is not exploitation.** A delivered BLOCK-labelled request reached the
  destination; attack success is not measured and is never implied.
- Headline L1 metrics come from the primary gateway channel, repetition 1. Cases that
  differ across repetitions are flagged, counted and excluded from the headline, never
  majority-voted. Direct `/classify` calls are a per-layer consistency control and never a
  headline metric.

**Rationale.** A single end-to-end figure cannot tell a model that misjudged a request from
a gateway that mishandled a correct decision, and those failures have different fixes.

**Relationship to earlier entries.** Builds on the enforcement contract of **D34**.
Defined for v1 in `docs/external_test_v1_protocol.md` §2; this entry makes it the rule for
every later gateway evaluation.

---

## D42 — External-test and diagnostic rates are reported as test-specific, never as operational rates

- **Date:** 2026-09-21
- **Status:** APPROVED
- **Implementation:** N/A — reporting rule

**Decision.**

- FPR, precision and accuracy measured on a test with a constructed class balance are
  always reported with their numerator, denominator and the test's name — for example
  "68/200 benign cases in External Test v1" — and **never** as an operational or
  production FPR, precision or prevalence. External v1 is 50/50 by construction.
- Diagnostic counts on case mixes built to provoke failures (for example
  `real-http-fp-v1`, 37/149) are diagnostic counts, not rates.
- A generalization gap is not described as proven overfitting without a study designed
  to test that. An unseen-structure or distribution-shift slice measures robustness; it is
  not described as OOD detection, which the model does not perform.
- Latency observed during an evaluation run is an observation, not a benchmark: the Decision D36
  objective is measured only by its instrument, and end-to-end latency only by Issue #18.

**Rationale.** Precision and accuracy depend on class prevalence, and a single lab
application with a fixed 50/50 mix does not represent any deployment's traffic. Reported
without its context, a test-specific rate reads as a deployment property.

**Relationship to earlier entries.** Extends the reporting discipline of **D18** and
**D19** to external tests and diagnostics. Consistent with the limitations pre-registered
in `docs/external_test_v1_protocol.md` §13.

---

## D43 — Hybrid Architecture Phase 1: request feature extraction runs in shadow mode; V4 stays the only decision

- **Date:** 2026-10-01
- **Status:** APPROVED
- **Implementation:** DONE (Phase 1) — Issue #49; `data_plane/request_features.py`,
  `data_plane/data_plane.py`, `config.yaml`

**Decision.**

- A deterministic, standard-library **request feature extractor** describes each request
  as a fixed set of features (`RequestFeatures`, schema `request-features/v2`). It
  produces no decision, score or threshold.
- **Input is the D1 text** — the string `render_request()` produces and `/classify`
  receives — rendered **once** per request, so the extractor and V4 see the same bytes,
  and a feature computed live equals one computed offline over a dataset.
- It runs in the **data plane**, after the classifier call returns and before the verdict
  is enforced, in **shadow mode**: its output is logged and nothing else reads it.
  Classification, routing, `ALLOW` / `BLOCK`, enforcement and fail-closed (D4, D25, D34)
  are unchanged; V4 through `/classify` is the only decision. Running after the call also
  keeps the decision line's `(classifier N ms)` at its earlier definition
  (`render_request()` plus the `/classify` call) without rendering twice.
- **An extractor failure is not a classifier failure.** It is caught on its own, logged
  (exception type and code location only), and the verdict already obtained is enforced
  unchanged. It never produces a `403` or `503` by itself. Fail-closed keeps applying
  exactly where D34 put it: no valid decision from the classifier.
- Switch: `data_plane.shadow_feature_extraction` in `config.yaml`, a YAML boolean.
  **Absent means off**, so configurations written before this entry keep their exact
  behaviour; an invalid value stops the gateway at startup, like any other invalid
  setting. The root `config.yaml` enables it; `docker/config.docker.yaml` does not set it,
  so the Docker Lab, the demo and the External v1 capture proxy are unchanged.
- The later stages have **contracts only** (`data_plane/hybrid_contracts.py`:
  `AnalyzerOutput`, `DecisionInput`, `DecisionOutput`). Nothing produces or consumes
  them; the analyzer's signal vocabulary is left open.

**Rationale.** The proposed Hybrid Architecture (D45: feature extraction → lightweight
request analyzer → small decision model → V4 as fallback) needs features whose behaviour on
real traffic is known before anything is allowed to act on them. Shadow mode yields that
evidence with no security cost. Treating an extractor fault as fail-closed would make an
experimental component a new source of BLOCKs; ignoring it costs nothing, because nothing
depends on its output. Measured on 2026-10-01 (`reports/hybrid/phase1-feature-extraction-v2/`):
the same 33 requests gave identical statuses, decisions, reasons and destination receipts
with shadow off and on; in-process extractor P95 0.0301 ms over the V4 eval texts
(n = 18,618).

**Relationship to earlier entries.** Nothing is superseded. D1 (representation), D4 / D25 /
D34 (enforcement, fail-closed) and D33 (separate environments: the extractor needs only
the standard library) hold unchanged. **D29 / D30 are untouched**: no score, no fast path.
Open for a later decision, not taken here: whether a Hybrid Architecture stage may ever
`BLOCK` without V4, which D29 excludes for its heuristic score. Phase 1 uses no External
Test v1 data, so the D40 tripwire is not triggered.

---

## D44 — `Host` and `User-Agent` are never request features

- **Date:** 2026-10-01
- **Status:** APPROVED
- **Implementation:** DONE (Phase 1) — `data_plane/request_features.py`, tests in
  `tests/test_request_features.py`

**Decision.**

- No request feature, and no input of a Hybrid Architecture model (analyzer or decision
  model), uses the `Host` or `User-Agent` headers, and no feature may be built to
  re-introduce them indirectly (a hash, a length, a character count, a presence flag, or
  similar).
- In Phase 1 the extractor reads **no header except `Content-Type`** (media type only).
  Character and syntax features are computed over path + query + body, never over headers.
  Featurizing any other header (for example `Cookie`, `Referer`, `Origin`) needs its own
  decision.
- Verified by test: changing or removing `Host` / `User-Agent` (and other non-`Content-Type`
  headers) leaves every feature identical.

**Rationale.** Audit F1 (D1): on the historical corpus `Host` alone classified 93.72% of
eval and `User-Agent` 67.94%. `real-http-fp-v1` showed V4 sensitive to a loopback `Host`.
These fields carry deployment and client identity, not request intent; a new model fed
them could relearn the shortcut V4-clean removed.

**Relationship to earlier entries.** Applies D1's envelope rule to the request-feature
pipeline as a hard exclusion. It does not change what V4 — or a future V5 model, which
D1 continues to govern — receives: `/classify` still gets the full D1 text, headers
included. Operational logs are not affected.

---

## D45 — Terminology: "V5" is the next model version; the multi-stage design is the "Hybrid Architecture"

- **Date:** 2026-10-01
- **Status:** APPROVED
- **Implementation:** DONE — documentation and Phase 1 code use these terms

**Decision.**

| Term | Meaning |
|---|---|
| **V4** | the current classifier: TinyLlama-1.1B-Chat + the V4 QLoRA adapter (`model-output-v4-clean/`) |
| **V5** / **V5 model** | the next revision of the model and its dataset — exactly the meaning of D37 and D40, unchanged |
| **Hybrid Architecture** | the proposed multi-stage design: request feature extraction → lightweight request analyzer → small decision model → V4 (or its successor) as fallback for uncertain cases → enforcement. Its steps are "Hybrid Architecture Phase N"; Phase 1 is D43 |

- "V5" alone is never used for the Hybrid Architecture, in documentation, issues, code or
  the academic report.
- The scope rules that protect test sets apply to **both**. D37's rule — a test set whose
  individual errors guide a change stops being a test set — covers every Hybrid
  Architecture component. Using External Test v1 cases or errors to design, train, tune or
  threshold any Hybrid component consumes External v1 exactly as D40 describes for V5, and
  any claim about that component's external performance needs External v2.
- Names created before this entry keep their spelling: the branch
  `feature/v5-request-feature-extraction` (already published).

**Rationale.** D37 and D40 already use "V5" for the next model version, and D40 ties a
concrete commitment to it ("External v2 is required for any V5 claim"). Reusing the name
for a pipeline would make that commitment ambiguous in issues, documentation and the
academic report. A separate name keeps both meanings precise without editing any earlier
entry.

**Relationship to earlier entries.** Nothing is superseded; D37 and D40 keep their text and
meaning. Like D24 (evaluation-set terminology), this is a reporting rule. D43 and D44 use
these terms.

---

## D46 — Analyzer formulation: `attack` plus an auxiliary category (Phase 2A D1)

- **Date:** 2026-10-01
- **Status:** APPROVED
- **Implementation:** design frozen (Issue #51); model in Phase 2B

**Decision.**

- The Lightweight Request Analyzer has two levels: a primary binary signal
  `attack = P̂(BLOCK | RequestFeatures)`, and an auxiliary category distribution given attack.
- The category is **context**, not strong evidence for the future Decision Model, until Phase
  2B shows that it generalizes and does not rest mainly on synthetic endpoint artifacts.
- **Mandatory Phase 2B ablation:** the category model with all RequestFeatures v2 vs the same
  model without the path-structure features that can proxy the synthetic endpoint (at least
  `path_length` and `path_depth`). A strong drop makes the category low-confidence context.
- Not used: a flat 20-class multiclass; a multilabel target built from the current labels.
  Multilabel may be revisited only on real external evidence.

**Rationale.** Phase 2A (`reports/hybrid/phase2a-analyzer-design/`): the binary label is clean,
balanced and envelope-neutral (no runtime feature beats 53.7% on it); the category label is
single-valued by construction precedence (410 multi-directory source payloads, 408 / 3,906 CSIC
rows matching several keyword families), scarce for 11 of 19 reasons, and confounded with
the synthetic endpoint (the path alone predicts the category given BLOCK at 65.3% vs 26.3%;
the runtime `path_length` at 46.7%). Separating the two levels mirrors D19, where a category
error never reduces binary recall.

**Relationship to earlier entries.** Extends D43 (Hybrid Architecture) and follows D19's
level separation. Nothing is superseded.

---

## D47 — Analyzer category vocabulary and reason mapping (Phase 2A D2)

- **Date:** 2026-10-01
- **Status:** APPROVED
- **Implementation:** DONE in the contract (`hybrid_contracts.ANALYZER_CATEGORIES`); mapping
  applied by the Phase 2B builder

**Decision.** Categories: `sql_injection`, `xss`, `path_file_access`, `command_injection`,
`ssti`, `open_redirect`, `ssrf`, `other_attack`. Mapping from V4 reasons: SQL injection →
`sql_injection`; Cross-site scripting → `xss`; Path traversal and File inclusion →
`path_file_access` (D49); Command injection → `command_injection`; Server-side template
injection → `ssti`; Open redirect → `open_redirect`; Server-side request forgery → `ssrf`;
CRLF, XXE, NoSQL, LDAP, GraphQL, CSRF, XPath, HTTP parameter pollution, insecure
deserialization and request smuggling → `other_attack`; JWT → not a target (D48). V4 reasons
are kept only as provenance metadata.

`other_attack` is a **residual bucket** for reasons too scarce to be targets; it is not a
semantic category and must not be described as one.

**Rationale.** The seven named categories are exactly those with eval support ≥ 30 and ≥ 100
logical groups (D18 / D19), with Path traversal and File inclusion merged; the other reasons
have 0–112 eval rows and < 100 logical groups. Nothing is invented: every id maps 1:1 to
existing reasons.

---

## D48 — JWT is excluded from Analyzer fitting; `unsupported_jwt` evaluation slice (Phase 2A D3)

- **Date:** 2026-10-01
- **Status:** APPROVED
- **Implementation:** applied by the Phase 2B builder

**Decision.**

- JWT rows are excluded from fitting (TRAIN and VALIDATION) while RequestFeatures v2 does not
  observe the `Authorization` evidence. They are not removed from V4-clean.
- They form the `unsupported_jwt` evaluation slice (V4 eval: 16 rows), reported separately as a
  known blind spot and kept out of both INTERNAL TEST views.
- No feature based on `Authorization`, cookies or other headers is added; that needs a later
  decision.

**Rationale.** The JWT payload is placed only in `Authorization` (`parse_dataset_v4.render_request`),
which D44 leaves unread; 70.3% of JWT rows have the coarse feature profile of benign rows of
the same shape. Fitting them would label benign-looking surfaces as attacks. The External
Dataset Survey found no public labelled JWT-attack dataset.

**Relationship to earlier entries.** Consequence of D44's Phase 1 scope; D44 is unchanged.

---

## D49 — Directory Traversal and File Inclusion form one Analyzer category (Phase 2A D4)

- **Date:** 2026-10-01
- **Status:** APPROVED
- **Implementation:** as D47

**Decision.** Both V4 reasons map to `path_file_access`. The original reasons survive only as
provenance and metadata.

**Rationale.** 382 canonical source payloads occur in both PayloadsAllTheThings directories and
were assigned to Directory Traversal by alphabetical order; both reasons share the
`file_param` shape. The boundary is partly arbitrary. The closest standard umbrella is CWE-73
(External Control of File Name or Path); an independent dataset (ModSec-WP, Zenodo
10.5281/zenodo.21872151) also groups LFI, RFI and path traversal into one family.

---

## D50 — `AnalyzerOutput` semantics; no global confidence (Phase 2A D5)

- **Date:** 2026-10-01
- **Status:** APPROVED
- **Implementation:** DONE — `data_plane/hybrid_contracts.py`, tests in
  `tests/test_request_features.py`

**Decision.**

- `attack` — required; a calibrated estimate of `P̂(BLOCK | features)`. V4-clean is 50 / 50 by
  construction, so it is **not** an estimate of operational attack prevalence (D42).
- `category:<id>` — `P̂(category | attack, features)` for the D47 ids; all present and summing to
  1, or all absent.
- No global `confidence` field and no invented confidence score. Uncertainty, when needed, is
  derived: closeness of `attack` to 0.5, top-1 probability, top-1 / top-2 margin, entropy.
- The contract rejects unknown signals, a missing `attack`, values outside [0, 1], a partial
  category set and a category sum off 1.

**Relationship to earlier entries.** Replaces the open-vocabulary `AnalyzerOutput` of Phase 1
(D43), which was explicitly a placeholder. `DecisionOutput` is unchanged.

---

## D51 — `hybrid_analyzer_v1`: source, roles, grouping and INTERNAL TEST views (Phase 2A D6)

- **Date:** 2026-10-01
- **Status:** APPROVED (the TRAIN ∪ VALIDATION reference set of the feature-disjoint view,
  which came out of the grouping check this decision required, was confirmed by the owner
  on 2026-10-01)
- **Implementation:** DONE — `hybrid_analyzer_v1`, Phase 2B run-001 (Issue #53)
- **Grouping and VALIDATION carve-out SUPERSEDED BY D54** (2026-10-03) for
  `hybrid_analyzer_v2`; `hybrid_analyzer_v1` and run-001 keep this definition. The original
  entry below is preserved unchanged.

**Decision.**

- Source: V4-clean only, verified by its manifest hashes. V4-clean is never modified.
- Roles: V4 train → Analyzer TRAIN + VALIDATION; V4 eval → INTERNAL TEST. No new random split.
- **Group:** connected components over V4 train of "same canonical request OR same feature
  vector", canonical request = `parse_dataset_v4.canonical_key` over
  `method path?query \n content_type \n body` (headers excluded), feature vector = the 34
  RequestFeatures v2 values; group key = the smallest canonical request in the component.
- **VALIDATION:** 20% of groups by `sha256("hybrid-analyzer-v1-validation" + NUL + group_key)`,
  first 8 bytes big-endian, `% 10000 < 2000` — deterministic, order-independent, independent of
  `PYTHONHASHSEED` and of global state.
- **INTERNAL TEST views:** `internal_test_full` (V4 eval, JWT excluded: 6,190 rows) and
  `internal_test_feature_disjoint` (full minus rows whose feature vector occurs in any V4-train
  row available to the Analyzer, TRAIN ∪ VALIDATION: 5,456 rows). Rows are flagged, never
  removed; an independent flag marks a canonical request seen in TRAIN ∪ VALIDATION (127 rows).
  Reports give both views, both counts and the view's class mix. The feature-disjoint view is
  the primary reference for generalization claims.

**Rationale.** Measured (`analysis.json`, `frozen_design`): grouping by canonical request alone
left 465 VALIDATION rows with a feature vector present in TRAIN; the combined definition leaves
0, with no giant group (18,720 groups, largest 417). Against fitted rows only, 331 eval rows
whose vector appears only in VALIDATION would count as disjoint; VALIDATION drives model
selection and calibration, so the reference set is TRAIN ∪ VALIDATION, which also makes the
view independent of the VALIDATION salt.

**Relationship to earlier entries.** Applies D16 (grouped splits), D37 (data roles; VALIDATION
carved from training groups) and D32 / D39 (immutable, versioned evaluation artifacts). The
feature-disjoint view has 3,033 BLOCK / 2,423 ALLOW rows, so its rates carry that prevalence
(D42).

---

## D52 — Analyzer runtime is decided after a winning model is measured (Phase 2A D7)

- **Date:** 2026-10-01
- **Status:** APPROVED
- **Implementation:** N/A

**Decision.** Phase 2B may use a separate research environment with numpy and scikit-learn.
Nothing is installed in the data-plane environment; D33 stands; the data plane is not changed.
Where the Analyzer runs — stdlib inference of an exported model, the control plane, or another
justified option — is decided only after a winning model's quality, latency, size and memory
are measured. No deployment optimization before that.

---

## D53 — External Test v1 is not used before the Analyzer is frozen; then aggregate only (Phase 2A D8)

- **Date:** 2026-10-01
- **Status:** APPROVED
- **Implementation:** N/A — a usage rule

**Decision.** External v1 is not used for training, validation, model selection, feature
selection, hyperparameter or threshold tuning, error analysis, vocabulary choice or Analyzer
redesign. Only after the target schema, preprocessing, model, hyperparameters and any
thresholds are frozen on TRAIN / VALIDATION / INTERNAL TEST may a single aggregate evaluation on
External v1 be run, under D40. Its individual errors are never inspected to modify the Analyzer.

**Relationship to earlier entries.** Applies D37 / D40 to the Hybrid Architecture as D45 requires.

---

## D54 — Analyzer groups include the V4 generator group; `hybrid_analyzer_v2`; one second look at INTERNAL TEST

- **Date:** 2026-10-03
- **Status:** APPROVED (owner instruction of 2026-10-03, after the run-001 finding)
- **Implementation:** DONE — Phase 2B run-002 (`reports/hybrid/phase2b-analyzer-v2-run-002/`):
  `hybrid_analyzer_v2` (SHA-256 `e8da8674…`, leakage 0 under the three relations), freeze
  2026-10-04 06:10:33 UTC, the one second look after it. Analyzer FROZEN as
  `hybrid-analyzer-v2/attack=hist_gb,category=hist_gb`

**Defect found (run-001).** D51 grouped V4-train rows by "same canonical request OR same
feature vector". The V4 generator splits train / eval by its own **generator group** (D16):
one canonical attack payload with its augmentation variant(s), one CSIC request shape
(`csic_group_key`: digits collapsed, values decoded), one synthetic benign template value.
Neither key D51 used captures that group (its rows differ in canonical request and in
feature vector), so its rows could fall on both sides of TRAIN / VALIDATION. With the generator groups recovered exactly (below), **646 of 4,980 fitted
VALIDATION rows (13.0%) had a sibling in TRAIN and 520 generator groups were split**, whereas
0 generator groups span V4 train / eval. VALIDATION was therefore easier than INTERNAL TEST;
it favoured memorizing models and a calibrator that did not transfer. It was found only after
INTERNAL TEST had been read once (run-001).

**Decision.**

- **Generator group, recovered from provenance, not approximated.** The unmodified generator
  (`parse_dataset_v4.py`, default arguments = the V4 manifest) is re-run into a temporary
  directory and each written row's in-memory `_gid` is observed
  (`scripts/dataset/recover_v4_provenance.py`). The observation is accepted only if both
  regenerated files are byte-identical to V4-clean and to its manifest SHA-256. V4, V4-clean and
  the generator are not modified.
- **`hybrid_analyzer_v2`** (`scripts/dataset/build_hybrid_analyzer_v2.py`): same source,
  targets, features and INTERNAL TEST views as v1 (D46–D51). Group = connected components over
  V4 train of "same canonical request OR same feature vector OR same generator group"; a group
  is never split.
- **VALIDATION:** ≈ 20% of V4 train, stratified by group target (BENIGN, the 8 categories,
  `unsupported_jwt`, or `mixed`). Inside a stratum, groups are visited in
  `sha256("hybrid-analyzer-v2-validation" NUL group_key)` order and a group joins VALIDATION
  when that brings the stratum's VALIDATION rows closer to 20%. Deterministic,
  order-independent, independent of `PYTHONHASHSEED`.
- **Leakage requirement:** TRAIN ↔ VALIDATION overlap must be 0 for canonical request,
  feature vector and generator group (asserted by the builder, unit-tested).
- **Accepted properties** (independent audit before any v2 model was fitted): VALIDATION
  shares nothing with TRAIN under the three relations, whereas `internal_test_full` shares 127
  canonical requests and 734 vectors with the development set. VALIDATION therefore mirrors
  `internal_test_feature_disjoint` and is pessimistic relative to the full view; like-for-like
  comparisons use the feature-disjoint view. The two large `mixed` CSIC components (benign +
  `sql_injection` sharing vectors, 223 and 216 rows) always stay in TRAIN under the 20% rule
  (`mixed` stratum 5% VALIDATION). Synthetic benign generator groups hold one row each, so the
  generator relation adds links only for attack payloads and CSIC request shapes.
- **INTERNAL TEST:** views unchanged (feature-disjoint against TRAIN ∪ VALIDATION); an added
  flag marks eval rows whose generator group occurs in TRAIN ∪ VALIDATION (0 by the generator's
  construction). Eval rows get group ids from the same relation inside V4 eval, used for
  group-weighted metrics.
- **INTERNAL TEST is no longer untouched.** It was read once by run-001. Exactly **one** second
  look is authorized, after a complete, hashed run-002 freeze, and must be labelled
  "SECOND-LOOK INTERNAL EVALUATION AFTER METHODOLOGY CORRECTION — NOT AN UNTOUCHED TEST". No
  test → change → test loop; an implementation bug that invalidates it is documented and
  brought to the owner, never repeated automatically.
- **Run-002 selection** uses VALIDATION v2 only, the run-001 families and grids unchanged, and
  pre-declared mechanical winner rules (recorded in the run's `experiment_config.json`).
- **Run-001** (`reports/hybrid/phase2b-analyzer-baselines/`, `hybrid_analyzer_v1`) is kept intact
  as historical evidence; its errata are documented beside it, not edited into frozen files.

**Relationship to earlier entries.** Supersedes D51's grouping and VALIDATION rule for v2 only;
D51's source, roles, targets and INTERNAL TEST views stand. Applies D16, D37 and D53. External
Test v1 remains unused.

---

## D55 — Analyzer evaluation conventions (Phase 2B)

- **Date:** 2026-10-03
- **Status:** APPROVED (owner ratification of 2026-10-03 of the run-001 proposals)
- **Implementation:** DONE in `scripts/training/run_hybrid_analyzer_baselines.py`

**Decision.**

- **Threshold 0.5 is reporting-only.** It fills confusion counts (TP / TN / FP / FN, precision,
  recall, FPR, FNR) for comparison. It is not the firewall's operating point and nothing is
  optimized around it; the operating policy (ALLOW / BLOCK / UNCERTAIN) is decided later with the
  Small Decision Model.
- **Group-weighted metrics are a standing diagnostic.** Every Analyzer report gives row-weighted
  metrics (the reported metrics) and, beside them, group-weighted ones (each group weighs 1) plus
  error concentration per group. Group-weighted metrics never replace row-weighted ones and are
  not selection criteria.
- **Calibration is adopted only on robust VALIDATION evidence.** Native → sigmoid → isotonic, in
  that order; a more complex method is adopted only if the paired group-bootstrap 95% interval of
  its out-of-fold Brier difference lies entirely below 0. From run-002 it must also not worsen
  out-of-fold log loss (a guard added because isotonic produced exact 0 / 1 probabilities in
  run-001; that motivation includes the run-001 INTERNAL TEST result and is recorded as such).
  "Uncalibrated" is a valid outcome.
- **No MLP** in this Analyzer iteration; the candidate families are logistic regression, random
  forest and HistGradientBoosting.
- **Model artifacts stay out of git** (`model-output-hybrid-analyzer-*/`, gitignored, like every
  model output). Their SHA-256, sizes, configurations and metadata are versioned in the reports.

---

## Decision index

| ID | Topic | Status | Implementation |
|----|-------|--------|----------------|
| D1 | HTTP request representation — neutralize envelope shortcuts | APPROVED | **DONE (E2)** |
| D2 | CSIC excluded anomalies — keep out of baseline | APPROVED FOR FUTURE WORK | N/A |
| D3 | Latency target — P95 ≤ 200 ms end-to-end added | **SUPERSEDED BY D36** | N/A |
| D4 | Failure behavior — FAIL-CLOSED | APPROVED | **DONE (first version, D34)** |
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
| D22 | Real HTTP laboratory validation gate | APPROVED | **DONE for V4 (External v1)** |
| D23 | Current HF inference path is not the deployment target | APPROVED | N/A |
| D24 | Evaluation-set terminology | APPROVED | N/A |
| D25 | Control Plane contract — `status` ok/invalid, never coerced | APPROVED | **DONE (#15)** |
| D26 | HF/PEFT control-plane baseline before llama.cpp | APPROVED | **DONE (#15)** |
| D27 | Canonical V4 runtime inference configuration | APPROVED | **DONE (#15)** |
| D28 | Control Plane readiness behaviour — 200/`model_loaded`, 503 | APPROVED | **DONE (#15)** |
| D29 | Heuristic suspicious scoring and benign fast path (allow-only) | APPROVED | NOT YET (#35, #36, #38) |
| D30 | Deferred model validation for fast-path traffic — no online learning | APPROVED | NOT YET (#37) |
| D31 | Model-side latency measured with a device-synchronized stopwatch | APPROVED | **DONE (#9)** |
| D32 | Benchmark experiment identity, immutability and comparison rules | APPROVED | **DONE (#9)** |
| D33 | Separate Python environments for the data plane and the ML/control plane | APPROVED | **DONE (#16)** |
| D34 | Data plane enforcement — HTTP decisions, 403 / 503, fail-closed | APPROVED | **DONE (first version, #16/#17)** |
| D35 | D3 is a performance objective; classifier timeout (3 s) is operational | APPROVED | **DONE** |
| D36 | Latency objective — P95 of the inference pipeline ≤ 200 ms, steady state (supersedes D3) | APPROVED | N/A — **not met** (269.58 ms) |
| D37 | Evaluation data roles from V5 — train / validation / internal test / external test; a test set whose errors guide changes becomes development data | APPROVED | NOT YET — from V5; V4 not changed |
| D38 | External test construction — capture, label, gate and freeze before model exposure | APPROVED | **DONE (External v1, `36df2ee`)** |
| D39 | Frozen external sets immutable — any change needs a new version; reserves never substitute; raw evidence never rewritten | APPROVED | **DONE (External v1)** |
| D40 | Using External v1 errors for V5 makes it V5 development data — External v2 required for V5 claims, with the proxy-to-`/classify` byte check and the CSIC-ancestry check External v1 did not run | APPROVED | NOT YET — triggers at V5 error analysis |
| D41 | Gateway evaluations report L1 model / L2 enforcement / L3 end-to-end separately | APPROVED | **DONE (`external-v1-run-001`)** |
| D42 | External-test and diagnostic rates are test-specific, never operational | APPROVED | N/A (reporting rule) |
| D43 | Hybrid Architecture Phase 1 — request feature extraction in shadow mode on the D1 text, after the classifier call; V4 stays the only decision; extractor failure ignored, never a BLOCK | APPROVED | **DONE (Phase 1, #49)** |
| D44 | `Host` and `User-Agent` are never request features; Phase 1 reads no header except `Content-Type` | APPROVED | **DONE (Phase 1, #49)** |
| D45 | Terminology — "V5" is the next model version (D37/D40); the multi-stage design is the "Hybrid Architecture"; test-set rules apply to both | APPROVED | **DONE** |
| D46 | Analyzer formulation — `attack` + auxiliary category given attack; mandatory category ablation in Phase 2B | APPROVED | design frozen (#51) |
| D47 | Analyzer category vocabulary (7 categories + residual `other_attack`) and the V4 reason mapping | APPROVED | **DONE (contract)**; builder in 2B |
| D48 | JWT excluded from Analyzer fitting; `unsupported_jwt` evaluation slice | APPROVED | builder in 2B |
| D49 | Directory Traversal + File Inclusion → `path_file_access` | APPROVED | as D47 |
| D50 | `AnalyzerOutput` — calibrated `attack`, conditional category distribution, no global confidence | APPROVED | **DONE (`hybrid_contracts.py`)** |
| D51 | `hybrid_analyzer_v1` — V4-clean only; grouped 80/20 VALIDATION from V4 train; INTERNAL TEST full + feature-disjoint | APPROVED (grouping **SUPERSEDED BY D54** for v2) | DONE (v1, run-001) |
| D52 | Analyzer runtime decided after a winning model is measured; D33 intact | APPROVED | N/A |
| D53 | External v1 unused before the Analyzer is frozen; then one aggregate evaluation under D40 | APPROVED | N/A (usage rule) |
| D54 | Analyzer groups include the recovered V4 generator group; `hybrid_analyzer_v2`; one labelled second look at INTERNAL TEST | APPROVED | DONE (run-002; Analyzer frozen) |
| D55 | Analyzer evaluation conventions: 0.5 reporting-only, group-weighted diagnostics, robust calibration rule, no MLP, artifacts gitignored with versioned hashes | APPROVED | DONE |

---

## Items still requiring advisor decision

Recorded here so they are not silently resolved by implementation.

- Whether dataset-artifact analysis (the envelope ablation, E2) is acceptable as a primary
  research contribution, given D7 accepts that accuracy may fall.
- Confirmation of the D8 core scope, particularly whether physical embedded deployment (D10)
  is required for the grade or is acceptable as documented future work.
- Whether the conventional rule-based comparison (D9) is ultimately required.
