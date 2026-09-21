# firewall-IA — Session Context for Claude Code

## 1. Project Overview

**Project identity: an inline AI-powered application-layer security gateway for HTTP traffic.**

The system is conceptually comparable to an application firewall / WAF-like security mechanism. It is **NOT** a replacement for a conventional stateful network firewall, and must not be described as one. The classifier is **stateless at the application-request level** — each HTTP request is classified independently, with no session context carried across requests. Being inline does not make it stateful.

firewall-IA is a fine-tuned TinyLlama-1.1B-Chat classifier. Given a raw HTTP request string, it outputs `ALLOW | <reason>` or `BLOCK | <reason>`, terminating on the model's native EOS (the `###END###` suffix was removed in E4 — see D5 in `DECISIONS.md`). The model is trained via LoRA (4-bit quantized) using supervised fine-tuning on a labeled dataset of generator-rendered HTTP requests: synthetic requests plus requests derived from CSIC 2010 (see §3, "Dataset used"). The end goal is a GGUF-exported model embedded behind an inline HTTP proxy for real-time application-layer classification.

The device is an **authorized inline supervisor (a legitimate security gateway), NOT a man-in-the-middle.** Maintain this distinction in all design discussion. Distinguish between: MITM attack / authorized inline interception / reverse proxy / security gateway / application-layer inspection. This project uses **authorized inline interception**.

> **Companion documents:**
> - `DECISIONS.md` — the project decision log (D1–D37). Read it before proposing architectural changes.
> - `docs/ml_evaluation_methodology.md` — evaluation rules: data sets, metrics, diagnostics vs benchmarks, latency layers.
> - `reports/` — experiment and audit outputs. Never overwrite a report; add a new one.

---

## Current checkpoint (2026-09-21)

**Read this first.** It states where the project is and what comes next. Everything below
explains how it got here; where an older section disagrees with this one, this one is
current.

**Completed**

- V4 clean baseline trained and evaluated (§3)
- Control plane implemented and validated (§5)
- Data plane / inline HTTP gateway implemented (§5b)
- ALLOW / BLOCK / fail-closed validated (§5b, §5c)
- ML evaluation methodology established (`docs/ml_evaluation_methodology.md`)
- **D36** (latency objective) and **D37** (evaluation data roles) recorded
- Reproducible diagnostic `reports/diagnostics/real-http-fp-v1/` completed and persisted (§5c)
- Proxy / direct-API consistency validated (§5c)
- Gateway enforcement validated (§5c)
- Repository reorganized by responsibility (§9)
- **Docker Lab COMPLETE and runtime verified** (§5d) — built and run. GPU
  passthrough works, the control plane runs on CUDA, V4 loads from the read-only
  mounted adapter, and the five infrastructure checks A–E all pass
  (startup/readiness, ALLOW, BLOCK, fail-closed, recovery). Closure report and
  committed raw logs: `reports/lab/docker-lab-v1/` (`raw/`). **Infrastructure only — not External Test v1, not
  a benchmark, no model metric.**

**Current baseline**

- TinyLlama **V4** (`model-output-v4-clean`, checkpoint 2200) — **unchanged** by all of the
  work above
- **`datasets/v4_clean/` unchanged** — hashes still match `datasets/manifest_v4_clean.json`
- No V5, no V4.1
- No external test set
- No fast path, no suspicious score, no asynchronous classification
- No GGUF / llama.cpp, no embedded deployment

**Next — in this order**

1. **External Test v1** — an independent, frozen external evaluation set (§13).
   **Not started.**
2. **Full external security + gateway-enforcement evaluation** —
   client → data plane → control plane → V4 → data plane → destination, executed
   in the Docker Lab (§5d)
3. **Professor demo** — ALLOW, BLOCK and fail-closed shown live on a small demo subset,
   with the external-test results presented already computed
4. **README / results / standards alignment / future work**

Do not reorder these. *(Docker Lab was step 1 of this sequence and is now done,
§5d; the remaining order is unchanged.)*

**Not to be reopened before that sequence produces evidence that requires it:** the
diagnostic false positives, another documentation audit, V5, the fast path, the suspicious
score, llama.cpp/GGUF, embedded hardware and inference optimization. They stay recorded in
§3, §5c and §13 as later work.

---

## 2. ENVIRONMENT — CRITICAL (post-Ubuntu-reinstall, 2026-05-24)

**The machine was reinstalled. The Python environment changed and this WILL bite you if ignored.**

- `python3` resolves to **Python 3.14** (`/usr/bin/python3`) — the ML stack is NOT installed here.
- The ML stack lives in **Python 3.12** (`/usr/bin/python3.12`, packages in `~/.local/lib/python3.12/site-packages`).
- **ALWAYS invoke `python3.12` explicitly** to run scripts: `python3.12 scripts/training/finetune.py`. Never `python3`.
- **ALWAYS install with `python3.12 -m pip install <pkg> --break-system-packages`.** Plain `pip` currently maps to 3.12 but `python3.12 -m pip` is unambiguous.
- Verify pip target anytime with `pip --version` (look for `(python 3.12)`).
- No virtual environments are used for the ML stack (project preference). Exception: the data plane runs in
  `.venv-dataplane`, because mitmproxy's pins conflict with the ML stack (**D33**).

Stack confirmed working in 3.12 (2026-05-24): torch 2.6.0+cu124 (CUDA True on RTX 4090 Laptop), transformers, peft, trl, bitsandbytes, accelerate, datasets, pandas. Driver NVIDIA 595.71.05, supports up to CUDA 13.2; torch cu124 wheels run fine via forward-compat.

---

## 3. CURRENT STATE — V4 CLEAN BASELINE ESTABLISHED (2026-08-18)

**This section supersedes §3-historical below for "where are we now?". Sections 3-historical
through 12b are retained as the audit trail that explains how we got here.**

Issue **#7 — Train V4 clean baseline** is **complete and merged** (PR #32). The project now
has its first scientifically interpretable baseline.

### Model

| | |
|---|---|
| Adapter | `model-output-v4-clean/` (gitignored) |
| Best checkpoint | `checkpoint-2200`, `eval_loss` 0.463187 — restored by `load_best_model_at_end` |
| Training | 3144/3144 steps, 4 epochs, `train_loss` 0.4696 |
| Runtime | 7782.9 s (129.7 min) |
| Peak GPU | 1.98 GiB allocated / 4.59 GiB reserved |
| Failures | 0 NaN, 0 Inf, 0 OOM |
| Adapter structure | 12,615,680 LoRA params, 308 tensors, ~48.2 MiB |
| `embed_tokens` / `lm_head` | **absent** — E4 custom-token resize fix holds under full training |

`eval_loss` bottomed at step 2200 and rose to 0.4669 by 3144 (+0.8%, one seed, loss only) —
**compatible with** mild overfitting in the final ~30%, not established by it. It says nothing
about the real-traffic false positives. For those, out-of-distribution inputs are a more
plausible hypothesis than overfitting, and neither is established (see
`docs/ml_evaluation_methodology.md` §3). The best checkpoint was selected
automatically; a shorter schedule was **not** explored and must not be assumed better without
an experiment.

### Dataset used

`datasets/v4_clean/` — 25,134 train / 6,206 eval / 31,340 total, 15,670 ALLOW / 15,670 BLOCK.
Hashes verified against `datasets/manifest_v4_clean.json` before training:

```
train.jsonl  4459f6861629279395acc57f99173d82bbda4dc8205a5f3bd08750dd528d262b
eval.jsonl   61f15591203609b4c583773184cd25edd6d1adc5f86959e009cfd47f6d370859
```

E0 immediately before training: 0.00% leakage, 0.00% duplicates in both splits, 0
deterministic label reveals, **0 blocking failures**. WARNING persists for category scarcity
only.

**Sources** (generator `parse_dataset_v4.py`, seed 42; counts from the manifest unless marked):

| Source | Role | Counts |
|---|---|---|
| PayloadsAllTheThings `e961fef` | attack payloads, 16 category directories (`.md` fenced blocks, `.txt` lines), quality-filtered | 39,396 candidates → 33,517 accepted |
| Hardcoded payloads in the generator | CRLF, XPath, HPP, request smuggling | 81 (XPath 31, CRLF 24, HPP 20, smuggling 6 — split read from the generator source) |
| CSIC 2010 | Normal → ALLOW; Anomalous → BLOCK only if the keyword heuristic categorizes it (F6), else reserved (D2) | 36,000 normal · 5,900 categorized · 19,165 reserved, unused |
| Synthetic benign generator | parametrized benign requests in the attack shapes (D13) | 19,785 logical groups |

Logical groups after grouping and the D17 caps: attack 9,977 (8,037 train / 1,940 eval),
CSIC 8,251 (6,577 / 1,674), synthetic benign 19,785 (15,802 / 3,983). Non-structural attack
groups get at most one obfuscated variant from the training transform pool. BLOCK rows:
3,906 from CSIC (`reports/e2_e3_row_cap_sensitivity.txt`, a bit-identical reproduction),
hence 11,764 from PayloadsAllTheThings plus hardcoded. The ALLOW split between CSIC and the
synthetic generator is not recorded anywhere.

**CSIC in V4 is derived, not raw.** Method, path (minus `/tienda1`), query and body are kept.
The original headers are discarded and the envelope is redrawn from the pools shared by every
source. These rows are *derived from CSIC 2010 and re-rendered into the V4 HTTP
representation*; do not describe them as real traffic. Historical-pipeline figures in §3-historical
and §10–§12 (6,587 / 18,478 CSIC anomalous, 240 benign templates) and the uncapped-candidate
figure in D13 (36,721 benign samples) are not V4 figures.

### Formal evaluation (frozen E5 methodology, D19)

Held-out split, 6,206 rows (3,103 ALLOW / 3,103 BLOCK). Confusion matrix
**TP 3,011 · FN 92 · FP 2 · TN 3,101**.

| Metric | Value |
|---|---|
| Accuracy | 98.49% |
| Precision (BLOCK) | 99.93% |
| Recall / attack detection | 97.04% |
| F1 (BLOCK) | 98.46% |
| False positive rate | 0.06% |
| False negative rate | 2.96% |
| Invalid output rate | 0.00% |

The error profile is strongly asymmetric — 92 false negatives against 2 false positives.
Operationally that is the safer direction for an inline gateway, but ~3% of attacks pass.

### Category failure concentration

**91 of 92 false negatives (98.9%) sit in two categories:**

| Category | FN | Binary recall |
|---|---:|---|
| SQL injection | 74 | 743/817 = 90.94% |
| Command injection | 17 | 117/134 = 87.31% |
| SSRF | 1 | 62/63 = 98.41% |

Every other evaluable category missed zero attacks. XSS, path traversal, file inclusion and
SSTI are at 100% binary recall.

**Do not conclude from this that SQLi and command injection need more training data.** That
is one hypothesis among several — label noise in the CSIC-derived subset (audit F6) and
payload-family gaps are equally plausible. The actual failures must be analysed first
(**D21**). NOTE: this analysis was previously attributed to issue #8; issue #8 is the V4
metrics evaluation and is now closed. The failure analysis has no dedicated issue yet — see
the roadmap below.

### Evidence status (D18)

- **NOT EVALUABLE (1):** HTTP request smuggling — zero held-out examples. No claim permitted.
- **INSUFFICIENT DATA (10):** HPP (3), insecure deserialization (5), CSRF (8), XPath (11),
  JWT (16), NoSQL (17), LDAP (21), GraphQL (22), XXE (27), CRLF (112 rows but only 21 unique
  logical groups). Their per-category numbers are exploratory only.

### Latency — model-side only

Historical, Issue #8, single evaluation run, unsynchronized timer — **kept as measured**:

| | mean | P50 | P95 | P99 | min | max | stdev |
|---|---|---|---|---|---|---|---|
| ms | 229.1 | 241.8 | 270.8 | 286.6 | 163.1 | 467.5 | 31.8 |

Peak evaluation VRAM 2,476 MiB. Generated tokens (n=300 sample): mean 11.58, P95 13; native
EOS terminated 100% of generations, none hit the 40-token cap.

**These are HuggingFace model-side inference times, NOT end-to-end gateway latency.**

**Latency objective — D36 (supersedes D3):** P95 of the latency added by the inference
pipeline (tokenization and preparation, `generate()`, decoding and parsing) ≤ 200 ms in
steady state. It excludes model load, cold start and warm-up (reported separately), HTTP
transport, network, proxy and destination. It is an **optimization objective**, not an
acceptance criterion (**D35**), and it is **not met**: `baseline-local-v1` pipeline P95 is
269.58 ms (below). This is why inference optimization is prioritized (**D23**). End-to-end
latency is a different quantity, still to be measured (Issue #18), with no threshold defined.

### Controlled benchmark — `baseline-local-v1` (Issue #9, 2026-09-09)

The reference measurement. 3 fresh processes × the full 6,206-row split = 18,618 real
classifications. Scope `generate-only/device-synchronized/v1` — `generate()` only, device
synchronized (**D31**). Batch 1, concurrency 1, model loaded once per process. Frozen;
future runs take their own experiment id (**D32**).

| steady state, pooled (n=18,618) | mean | P50 | **P95** | P99 | min | max | stdev |
|---|---|---|---|---|---|---|---|
| ms | 227.86 | 238.82 | **269.01** | 275.90 | 155.80 | 337.16 | 32.43 |

Reported separately, never pooled in, never discarded:

- **model load** 2275.5 / 2251.6 / 2416.6 ms — once per process
- **first inference (cold start)** 418.2 / 410.4 / 446.2 ms — **1.75× the steady P50**
- **warm-up** 4 per run, 159.5–271.2 ms

Peak memory, PyTorch allocator, this process only: 935.5 MiB allocated / 1170.0 MiB
reserved. Non-generate pipeline stages total ~0.58 ms at P95. Generated tokens mean 11.63
(r = 0.934 with latency); 0 of 18,618 hit the 40-token cap.

**Against D36:** steady-state inference-pipeline P95 (`steady_pipeline_p95_ms`, scope
`prompt+tokenize+transfer+generate+decode+parse`) is **269.58 ms**. The objective of
≤ 200 ms is not met. The artifacts in `reports/benchmarks/baseline-local-v1/` were written
before D36 and still describe the objective as D3's end-to-end budget; they are not
rewritten.

Quality at that latency, same E5 metrics: attack detection 97.04%, 2 FP and 92 FN per run,
0 invalid, accuracy 98.49% — **bit-identical across the 3 runs and identical to
`reports/v4_clean_eval.json`**, which is the evidence that the instrumentation did not
perturb inference.

**⚠ Run-to-run variation is 11.17% on P95** (244.03 / 266.55 / 273.21 ms). Paired per-row
analysis: run 3 was slower than run 1 in 99.5% of 6,206 requests, GPU starting at 48 °C for
run 1 and 72 °C for run 3. **Any future claim of an improvement below ~11% on this machine
is not distinguishable from run-order/thermal variation** unless it is controlled for.

Report: `reports/v4_inference_benchmark.md`. Artifacts:
`reports/benchmarks/baseline-local-v1/`. The historical 270.8 ms above is an antecedent,
not a comparand — `benchmark_compare.py` blocks that comparison (6 blocking differences).

### Legacy manual suite (diagnostic only)

135 cases (109 known-BLOCK / 26 known-ALLOW): accuracy 91.85%, recall 95.41%. **6 false
positives among 26 known-ALLOW samples in the manual diagnostic set.** This is a diagnostic
count, not an estimate of the model's FPR; the model's FPR is measured on the formal split
(2 of 3,103 benign rows). Not equivalent to the formal evaluation and never the headline. It
remains useful as a possible distribution-shift warning; the cause of those false positives
is not established.

### Current limitations

Single run, single seed, no confidence intervals · evasion resistance unmeasured by design
(D15) · benign population is synthetic + CSIC-2010-derived (re-rendered), so the 0.06% FPR
does not transfer to production traffic · CSIC label circularity (F6) · reason matching is
deliberately strict · `eval.jsonl` was used both for checkpoint selection (validation) and
for the internal evaluation, so it is held out from training but **not** an independent test
set (**D24**) · latency is model-side, laptop-class, batch size 1.

**Rule from V5 on** (**D37**, `docs/ml_evaluation_methodology.md` §1): TRAIN → training ·
VALIDATION → checkpoint/configuration selection · INTERNAL TEST → independent internal
evaluation · EXTERNAL TEST → independent evaluation outside the internal distribution. These
splits do not exist yet.

### Immediate roadmap

**Done since the V4 baseline:** Issue #15 — FastAPI Control Plane (§5), Issue #9 —
controlled inference benchmark (§3), Issues #16/#17 — data plane and fail-closed
enforcement (§5b), the reproducible real-HTTP diagnostic `real-http-fp-v1` (§5c), and the
structural repository reorganization (§9). This partially advances M3 ahead of M2 by
deliberate decision (**D26**); it does not make HF/PEFT the deployment backend, and **D23**
still holds.

**Issue numbering (reconciled against the tracker, 2026-09-06):** GitHub **#8** is
*Evaluate V4 clean security metrics* — **closed**, all ten acceptance criteria verified
against `reports/v4_clean_eval.json`. GitHub **#15** is the FastAPI Control Plane —
**closed**, merged via PR #34. Earlier text in this file described #8 as "analyse the 92
false negatives"; that failure analysis is real outstanding work (**D21**) but is not what
issue #8 says, and it still has no dedicated issue.

1. ~~**Issue #9** — controlled inference benchmark~~ — **DONE 2026-09-09.**
   `baseline-local-v1` measured and frozen; cold-start, warm-up and steady state kept as
   separate populations (§3). Next in this area: reduce the 11% run-to-run variation by
   controlling thermal state, and measure a second hardware baseline.
2. **Issue #16** — mitmproxy inline data plane — **first version implemented 2026-09-16** (§5b)
3. **Issue #17** — fail-closed enforcement (**D4**) — **first version implemented 2026-09-16** (§5b, **D34**).
   The 3 s classifier timeout is an operational limit for detecting classifier failure, not the
   latency objective; tune it with end-to-end evidence (**D35**)
4. ~~**Real-HTTP diagnostic**~~ — **DONE 2026-09-18.** `real-http-fp-v1`, persisted with
   all raw data (§5c). It is diagnostic evidence, not a benchmark and not an FPR.
5. ~~**Repository reorganization**~~ — **DONE 2026-09-20.** Structural only; the model and
   the datasets keep identical hashes (§9).

6. ~~**Docker Lab**~~ — **DONE 2026-09-21.** Built and run; GPU passthrough, CUDA
   model load and the five infrastructure checks A–E all pass (§5d). Closure
   report `reports/lab/docker-lab-v1/`. Infrastructure only.

**The current ordered work, from here** (the same order as "Current checkpoint" above — do
not reorder):

7. **External Test v1** — an independent, frozen external evaluation set; does not exist
   yet (§13, "External Test v1")
8. **Full external evaluation through the complete gateway** (**D22**) — client → data
   plane → control plane → V4 → data plane → destination
9. **Professor demo** — ALLOW, BLOCK and fail-closed live on a small demo subset, with the
   external-test results already computed
10. **README / results / standards alignment / future work**

**Later, only after that sequence:**

11. **Issue #18** — end-to-end gateway latency, the no-fast-path baseline
12. **Failure analysis of the 92 false negatives** (**D21**) — untracked
13. **Decision gate** — targeted V4.1 only if evidence requires it, otherwise proceed to M2
14. GGUF / Q4_K_M / llama.cpp (**Issues #10–#12**)
15. Quantized security regression
16. Embedded deployment

### Latency-reduction layer — designed, NOT built (D29, D30)

Four issues, all M3, none started. Do **not** describe any of them as implemented.

| Issue | Scope |
|---|---|
| **#35** | Heuristic suspicious scoring — standalone module, deterministic, explainable signals. No ML, no online learning. Parallelizable: it does not depend on the data plane. |
| **#36** | Benign fast-path ALLOW — one explicit threshold; clearly benign traffic skips synchronous inference. **No heuristic fast BLOCK.** Depends on #35, #16, #17. |
| **#37** | Asynchronous model validation of fast-path traffic — re-classifies off the critical path, records agreement/disagreement. Never blocks retroactively, never updates the model. Depends on #36. |
| **#38** | Fast-path calibration and benchmark — fast path off vs on, path split, disagreement rate, threshold recommendation. Depends on #18, #36, #37. |

The fast path exists for **latency**, not security: it decides only whether the model's
classification happens before the response or after it (**D30**), never whether a request
is malicious.

**Dataset expansion is NOT approved simply because the dataset has ~31k rows** (**D21**). More
data will be considered only on evidence from failure analysis, demonstrated independent
diversity gaps, or real-traffic validation. Independent diversity matters more than row count.

---

## 3-historical. State before the V4 baseline (as of 2026-05-24)

> Retained as the audit trail. **Superseded by §3 above** — the statements below about "no
> trained model" and "no experimental baseline" were true on 2026-08-16 and are no longer.

### What survived the reinstall / what was lost

- **LOST:** the original v3 adapter (`model-output-v3/`) and the exact v3 dataset. Both were gitignored (`model-output*/`, `train.jsonl`, `eval.jsonl`), so neither was in the repo. **The original 91%-accuracy v3 is NOT recoverable bit-for-bit.**
- **SURVIVED (in Git):** all scripts (`parse_dataset.py`, `finetune.py`, `test_model.py`), `csic_database.csv`, `README.md`, `CONTEXT.md`.
- **PRESENT on disk:** `~/PayloadsAllTheThings/` (re-cloned — newer version, see §6), stale local `train.jsonl`/`eval.jsonl` of 13,692 lines (NOT the v3 dataset — overwritten on 2026-05-24 regeneration).

### Model Versions

| Version | Location | Status |
|---------|----------|--------|
| v1, v2 | old `model-output*/` dirs | Lost in reinstall (gitignored) |
| v3 (original) | gone | Lost; reported ~91% acc, not reproducible bit-for-bit |
| **v3-rebuild** | `~/Desktop/firewall-IA/model-output-v3/` | **DOES NOT EXIST ON DISK** (verified 2026-08-16). Not trained. |

**CORRECTION (2026-08-16 audit; RESOLVED 2026-08-18 by Issue #7): at that time there was NO trained model anywhere in this project.** `model-output-v3/` is absent from disk. `finetune.py` has never successfully run on the current machine, and cannot (see §12, F4). `classifier_api.py` and `test_model.py` both fail at load time because `ADAPTER_DIR` does not exist.

**Consequence at that time: the project had NO experimental baseline.** That is no longer true — see §3.

### Status of the historical ~91% result

The ~91% / "0 false positives" figure from the original v3 is **historical context only. It is NOT the current baseline and must never be used as a comparison point for v4.** Reasons:

- The adapter and its exact dataset were lost in the reinstall; the result is not reproducible bit-for-bit.
- It was measured on a suite of 135 cases that is **109 BLOCK / 26 ALLOW**. A degenerate always-BLOCK classifier scores 80.7% on that suite, so 91% is +10.3 pp over the majority class — not +41 pp over chance.
- "0 false positives" was measured on **n = 26** ALLOW cases. By the rule of three the 95% upper bound on the true FPR is ≈ 11%. It is not a safety claim.
- Per-category accuracy was computed over 5 cases per category, i.e. 20 pp resolution. The reported "CSRF 40%" is literally 2 of 5.

Per **D7**, scientific validity takes priority over preserving this number. A clean baseline is expected to score lower, and that is an accepted outcome.

### Dataset — regenerated 2026-05-24 (the new baseline)

| Split | Path | Lines |
|-------|------|------:|
| Train | `~/Desktop/firewall-IA/train.jsonl` | 79,305 |
| Eval  | `~/Desktop/firewall-IA/eval.jsonl`  | 19,827 |
| **Total** | | **99,132** |

BLOCK: 49,566 | ALLOW: 49,566 | exact 1:1 balance.

**Paths are now unified to `~/Desktop/firewall-IA/`** in all three scripts (previously split between `~/ai-firewall/` and the project dir — fixed this session). `parse_dataset.py` OUTPUT, `finetune.py` TRAIN/EVAL, and `test_model.py` EVAL all point to `~/Desktop/firewall-IA/`.

### Why the dataset nearly doubled (52K → 99K) — CORRECTED 2026-08-16

The previous 52,670 dataset was silently **missing Path Traversal and CSRF** because `parse_dataset.py` looked for folder names that no longer exist in the current PayloadsAllTheThings (see §6). Fixing the two folder-name keys added ~46,000 examples.

> **⚠️ CORRECTION — the earlier claim in this section was FALSE.**
>
> This section previously said the ~46,000 increase came from "those two categories" and concluded that "add those categories is DONE". **That is wrong.** Measured directly against the generated `train.jsonl` + `eval.jsonl` on 2026-08-16:
>
> | Category | Examples | % of 99,132 |
> |----------|---------:|------------:|
> | Path traversal | **24,176** | 24.39% |
> | File inclusion | 8,447 | 8.52% |
> | **CSRF** | **46** | **0.05%** |
>
> The increase came **predominantly from Directory Traversal and related file-path data**. **CSRF contributed 46 examples.**
>
> **CSRF is NOT fixed. It remains, by this project's own reasoning, essentially untrained.** The v3 observation that "a model cannot be blamed for failing a category it never saw" still applies to CSRF today.
>
> The same applies to every other low-volume category — see the full per-category table in §11.

Run `python3.12 scripts/dataset/check_dataset.py` to re-measure this at any time. Do not restate category coverage from memory.

### Data Sources

1. **PayloadsAllTheThings** (`~/PayloadsAllTheThings/`) — `.md` code blocks + heuristic lines + `.txt` payload files across **16** active category directories (now includes Directory Traversal + Cross-Site Request Forgery).
2. **Hardcoded payloads** (in `parse_dataset.py`) — CRLF (240 wrapped), HPP (400), XPath (280).
3. **Synthetic LEGIT_REQUESTS templates** (in `parse_dataset.py`) — REST API, auth, mobile, GraphQL, webhook, false-positive mitigations; multiplied then trimmed.
4. **CSIC 2010 HTTP dataset** (`csic_database.csv`) — 61,065 real requests from a Spanish e-commerce app; 36,000 Normal (ALLOW) + 6,587 Anomalous included as BLOCK (18,478 generic-fallback excluded as noise).

### Attack Categories Covered — 19 total

From PayloadsAllTheThings (16):
SQL Injection, XSS Injection, **Directory Traversal**, Command Injection, LDAP Injection, XXE Injection, **Cross-Site Request Forgery**, Open Redirect, Server Side Request Forgery, JSON Web Token, GraphQL Injection, NoSQL Injection, Server Side Template Injection, File Inclusion, Insecure Deserialization, Request Smuggling.

Hardcoded (3): CRLF Injection, HTTP Parameter Pollution, XPath Injection.

**No category directory was SKIPPED in the 2026-05-24 run** — but "not skipped" does not mean "adequately covered". See the corrected volumes above and in §11.

---

## 4. Dataset imbalance — CONFIRMED 2026-08-16 (was: "suspected")

The 1:1 balance is BLOCK-vs-ALLOW **globally only**. Within the BLOCK pool the distribution is severely skewed. This was previously recorded as a hypothesis to test with `test_model.py`; it can be settled at the dataset level with **no model at all**, and it has been:

- **Path traversal 24,176 vs CSRF 46 — a 525:1 ratio.**
- Six categories are below 0.25% of the dataset: Request Smuggling (52), CSRF (46), GraphQL (118), LDAP (123), NoSQL (135), JWT (196).
- Within CSIC, SQL injection dominates the anomalous pool and is low-diversity (mostly the same `DROP TABLE usuarios` payload in the `cantidad` param of the same JSP endpoint).

The final 1:1 random trim (seed=42) did **not** mitigate this — it only balances BLOCK against ALLOW.

**Per-category rebalancing is a required task for the clean dataset**, not just BLOCK/ALLOW balancing. Note that any per-category accuracy claim also requires expanding `test_model.py` beyond 5 cases/category (20 pp resolution is not a measurement).

---

## 5. Control Plane — IMPLEMENTED AND VALIDATED (Issue #15, 2026-09-05)

**This section replaces the earlier description of `classifier_api.py`, which referred to
the v3 model, an `eos_token_id=end_token_id` override removed in E4, and a "built, not yet
validated" status. All three were obsolete.** The old `classifier_api.py` was deleted and
rewritten from scratch; git retains the history.

### Architecture

```
test_model.py  -->  inference_core.py  <--  classifier_api.py
```

`inference_core.py` is the **single owner** of the shared V4 runtime pipeline:

- the decision contract (`INSTRUCTION`, `EXTRACT_RE`, `MAX_NEW_TOKENS`)
- prompt construction (`build_prompt`) — identical to `finetune.py:format_example()`
  minus the answer the model is asked to produce
- model loading (`load_model`) and device resolution (`resolve_device`)
- generation (`classify_raw`) — greedy, native EOS, `max_new_tokens=40` as a safety bound
- parsing (`parse_prediction`) and reason normalisation (`normalize_reason`)

It imports nothing from this project — no scoring, no manifest handling, no dataset code,
no CLI. `split_output()` stayed in `test_model.py` because it parses dataset labels, which
is an evaluation concern. There is exactly one implementation of the contract, verified by
object identity (`test_model.parse_prediction is inference_core.parse_prediction`).

The active adapter is `model-output-v4-clean`, resolved relative to the repository root and
overridable via `FIREWALL_ADAPTER_DIR`. The default no longer points at the absent
`model-output-v3`.

### Control Plane

`classifier_api.py` — FastAPI, thin. HTTP -> validation -> `inference_core` -> response.
It re-implements nothing.

- `GET /health` -> `{status, model_loaded, adapter_dir}`. Always 200 while the process is
  up; `model_loaded` carries readiness (**D28**).
- `POST /classify` -> body `{"request": "<raw HTTP request text>"}`. Raw HTTP text, never
  structured method/path/header fields (**D1**).
- Response: `status` is `"ok"` or `"invalid"`. `decision` is `ALLOW`/`BLOCK` **only** when
  `status == "ok"`; on `"invalid"` both `decision` and `reason` are null.
- **An invalid output is never coerced** — not to ALLOW, not to BLOCK (**D25**).
- `model_latency_ms` is **model-side inference only**, the same scope the V4 evaluation
  uses. It is NOT end-to-end latency; no data plane exists to measure end to end.
- Errors: `422` malformed body, `503` model unavailable, `500` inference failure. No
  traceback reaches the client.
- The model is loaded once at startup via a FastAPI lifespan. One GPU, one inference at a
  time, serialized with a `threading.Lock`; endpoints are `def`, so FastAPI runs them in
  its threadpool. No queue, no scheduler.
- Runtime config is the V4 evaluation config: 4-bit nf4 with `bfloat16` compute dtype and
  **no** double quantization (**D27**).
- Request bodies are not logged.

### Security posture

- The Control Plane **reports**; it does not enforce. It surfaces `invalid`, `503` and
  `500`, and nothing acts on them.
- The Data Plane is responsible for applying **fail-closed** (**D4**) when it
  receives an invalid result, an error, or a timeout.
- Enforcement lives in the data plane (§5b), which applies fail-closed to `invalid`,
  non-200 answers, timeouts and connection errors.

### Validation evidence

- Extraction parity: AST equivalence against `git HEAD` for `parse_prediction`,
  `normalize_reason` and the contract constants; `build_prompt` byte-identical to the
  original inline template.
- Real-inference A/B on 30 fixed eval rows, pre-extraction code vs `inference_core`:
  **0/30 raw-output mismatches, 0/30 parsed-tuple mismatches**.
- `test_model.py --mode self-test`: PASS (48 checks).
- 37 unit tests pass, including a regression test that an unparseable output can never
  become ALLOW.
- Live: model loaded in 2.4 s on CUDA; `/health` 200; real ALLOW and BLOCK rows from
  `datasets/v4_clean/eval.jsonl` classified in agreement with their labels; 0 invalid
  outputs in 92 requests; 30/30 deterministic on repeat.

### Latency observed — preliminary, NOT a benchmark

- **Cold start:** the first inference after process start measured **512.8 ms** (CUDA
  warm-up).
- **Steady state:** n=30 measured with the model already warm — **P50 232.5 ms, mean
  211.5 ms, min 159.5 ms, max 241.9 ms**. The 512.8 ms warm-up sample was measured
  separately and is **not** included in these statistics.

This is runtime evidence, not a performance result. It is a small functional sample and is
**not** comparable to the formal model-side P95 of 270.8 ms, which is a different statistic
over the full 6,206-row split. **Do not claim the P95 improved.**

**Rule for the Issue #9 benchmark:** report cold-start and steady-state as two separate
sets. The warm-up sample must not be silently discarded, and must not be pooled into
steady-state statistics without saying so explicitly.

**Honoured 2026-09-09.** `baseline-local-v1` separates four populations, not two — model
load, first inference, warm-up and steady state — and every sample of every population is
on disk in the per-run JSONL. The controlled cold start measured 410–446 ms across three
fresh processes, against the 512.8 ms single observation above; both are cold starts taken
under different conditions and are not two measurements of the same quantity. See §3
"Controlled benchmark".

---

## 5b. Data Plane — FIRST VERSION (Issues #16/#17, 2026-09-16)

`data_plane.py` is a mitmproxy addon, run with
`.venv-dataplane/bin/mitmdump -s data_plane/data_plane.py --listen-host 127.0.0.1 -p 8080`.

- For every request it renders the raw D1 text and calls `POST /classify` (unchanged
  contract). It never loads the model.
- It forwards only an explicit `status: "ok"` + `decision: "ALLOW"`.
- A model BLOCK gets 403. A classifier failure or an invalid decision gets 503
  (fail-closed).

Decisions: **D33** (separate environment), **D34** (enforcement), **D35** (D3 objective vs.
timeout; the objective itself is now **D36**). Full description and reproduction steps: README, "Data Plane".

- **Separate environment (D33).** mitmproxy 12.2.3 pins `typing-extensions<=4.14` on
  Python 3.12, while pydantic 2.13.4 needs `>=4.14.1`. The data plane uses
  `.venv-dataplane` and `requirements-data-plane.txt`; `requirements.txt` is unchanged.
- **Config.** `config.yaml` holds `data_plane.classifier_url` and
  `data_plane.classifier_timeout_seconds` = 3.0. The timeout is an operational limit for
  detecting classifier failure, not the latency objective (D35).
- **mitmproxy fail-open behaviours verified on 12.2.3, and handled.**
  1. An exception in a hook is logged and the request is forwarded, so the hook catches
     everything and blocks.
  2. A failed hot reload leaves the proxy running without the addon, so on unload the
     addon enables the built-in `block_list` for all traffic (503) until restart.
  3. A load or config error at startup makes mitmdump exit with code 1, observed about
     1 ms after its port opens.
- **Tests.** `tests/test_data_plane.py` (21 tests), run with `.venv-dataplane/bin/python`.
  Under python3.12 the module is skipped.
- **Manual verification, 2026-09-16, real V4 model.**
  - ALLOW: `GET localhost:9000/index.html` → 200, and the destination logged the GET.
  - BLOCK: a SQL injection request → 403, and the destination logged nothing.
  - Classifier stopped: → 503, and the destination logged nothing.
  - Also exercised once each, with no request reaching the destination: XSS, path
    traversal, command injection and SQL injection in a POST body (all 403); a hung
    classifier (503 after 3.0 s); a model that was not loaded (503); an addon broken by a
    hot reload (503).
- **Finding: model false positives on real client traffic.** A model/dataset limitation
  (D22), not a data plane defect.
  - `GET /index.html` with `Host: 127.0.0.1:9000` → BLOCK "Server-side request forgery",
    on every repetition. Sent directly to `/classify` with the same Host, `GET /` and
    `GET /products?id=42` were also BLOCK. With `localhost:9000` or a domain, the same
    request is ALLOW. The role of `Host` is an open finding still to be isolated
    experimentally, not a demonstrated cause.
  - `GET /` with `localhost:9000` → BLOCK "HTTP request smuggling"; cause not isolated.
  - `Proxy-Connection` (0 V4 training rows) did not change the decision for the request
    tested, so it is **not** a confirmed cause.
  - In the V4 splits, `127.0.0.1` is never a Host value and elsewhere appears only in
    BLOCK rows (58 train / 12 eval). The `10.20.30.40:8000` and `localhost:8080` Hosts
    are balanced across labels. This is consistent with the observation above but does
    not demonstrate a cause.
  - Headers are not rewritten, and `render_request()` is not changed, to hide it. It is
    to be studied separately.
  - **Follow-up experiment, 2026-09-17: raw data lost — historical antecedent only.** A
    controlled one-variable A/B experiment (`/classify` direct and through the proxy) was
    run. Its raw records were written under `/tmp` and lost at the next reboot. An audit
    summary survives outside the repository; it is not a substitute for the raw data, and
    its figures cannot be re-verified. It is kept as an antecedent and is not evidence.
  - **That work was repeated and persisted, 2026-09-18:**
    `reports/diagnostics/real-http-fp-v1/`, with every raw record in the repository. It is
    the current evidence on this finding — see **§5c**.

---

## 5c. Real-HTTP diagnostic — `real-http-fp-v1` (2026-09-18, reproducible)

The 2026-09-17 follow-up lost its raw data and survives only as a non-re-verifiable
antecedent (§5b). **That work was repeated correctly.** The reproducible experiment lives at
`reports/diagnostics/real-http-fp-v1/` — pre-registered cases, every raw record, the four
process logs, the code and the manifest. Full write-up: its `summary.md`.

**What it is.** A **diagnostic** (`docs/ml_evaluation_methodology.md`): the case mix was
built to find and explain failures. It is **not** the external test, **not** a benchmark and
**not** an FPR estimate.

**What was run.** 175 pre-registered cases over 149 unique HTTP texts, 3 repetitions per
text — 447 direct calls to `/classify` — plus 26 curl commands × 3 = 78 requests through
the gateway.

**Validity and determinism**

- 0 invalid outputs in 447 direct calls.
- 149/149 unique texts gave the same decision **and** the same reason across all 3
  repetitions.

**Proxy / direct-API consistency**

- 78/78 texts captured from the proxy were byte-identical to the pre-registered text.
- 78/78 decisions matched between the proxy path and the direct API.
- 78/78 reasons matched.

**Gateway enforcement**

- 48/48 ALLOW decisions were forwarded and reached the destination.
- 30/30 BLOCK decisions returned 403 and did not reach it.
- No fail-closed 503 occurred during this run.

**Diagnostic finding.** 37 of the 149 constructed benign texts were classified BLOCK
(SSRF 25, file inclusion 4, HPP 3, open redirect 3, request smuggling 2). **37/149 is a
diagnostic count on a mix built to provoke failures — it is NOT a false-positive rate and
must never be reported as one.** The model's measured FPR is the formal-split 0.06% (§3).

**What the evidence supports.** Coverage gaps / out-of-distribution inputs, possible
spurious correlations (for example loopback Host → SSRF) and joint-feature context
sensitivity are all *compatible* with the observations. The experiment does **not**
demonstrate overfitting, does **not** establish causality for Host, path, port or headers,
and its proportions are **not** performance metrics for the model.

---

## 5d. Docker Lab — COMPLETE, RUNTIME VERIFIED (2026-09-21)

A containerized laboratory that runs the existing system end to end, so
**External Test v1** can later be executed in a reproducible environment. It is
**infrastructure**: no model, dataset, prompt, parser, generation parameter,
request representation (D1), enforcement rule (D4/D34) or evaluation methodology
changed. Full documentation: `docker/README.md`.

### Layout

`compose.yaml` at the repository root (canonical Compose v2 filename, discovered
from the root where every other command runs); all Docker assets under `docker/`:
`config.docker.yaml`, `control-plane/`, `data-plane/`, `destination/`, `client/`,
`smoke_test.sh`, `.env.example`, `README.md`. Plus `.dockerignore` at the root.
Nothing was moved; the §9 organization is unchanged.

### Four services

| Service | Image base | Role |
|---|---|---|
| `control-plane` | `ubuntu:24.04` + Python 3.12 + torch 2.6.0+cu124 + `requirements.txt` | FastAPI → `inference_core` → TinyLlama + V4. The only service that loads the model or needs the GPU. |
| `data-plane` | `python:3.12-slim` + `requirements-data-plane.txt` | mitmdump running the unchanged `data_plane.py`. Never loads the model. |
| `destination` | `python:3.12-slim`, stdlib only | The protected origin. Serves two static pages and appends every received request to a JSONL receipt log — this is how a BLOCK is proved *not* to have arrived. |
| `client` | `python:3.12-slim`, stdlib only | One-shot smoke client under a compose profile, so `docker compose up` does not fire traffic. |

### Design choices, and why

- **No production code was modified.** `data_plane.py` reads `config.yaml` beside
  the repository root; the lab bind-mounts `docker/config.docker.yaml` over it
  instead of adding an environment override to a validated component. The root
  `config.yaml` is untouched, so the local non-Docker workflow still works.
  Exactly one key differs: `classifier_url` →
  `http://control-plane:8000/classify`, because `127.0.0.1` inside a container is
  that container.
- **Two images, not one (D33).** mitmproxy's `typing-extensions<=4.14` pin against
  the control plane's pydantic `>=4.14.1` is preserved as an image boundary.
- **Two processes, not one.** The data plane still reaches the control plane over
  HTTP. Merging them would have been convenient and would have destroyed the
  separation the project chose deliberately.
- **The adapter is mounted, never copied.** `FIREWALL_ADAPTER_DIR` (already in
  `inference_core.py`) is set to `/opt/firewall-ia/adapter`; the host
  `model-output-v4-clean/` is bind-mounted there read-only. It is gitignored and
  must never enter an image layer. `.dockerignore` is an allowlist for the same
  reason: the repository root also holds `csic_database.csv` (28 MB), the
  historical `train.jsonl`/`eval.jsonl` (43 MB), `datasets/` and `reports/`.
- **HuggingFace cache mounted read-only with `HF_HUB_OFFLINE=1`,** so the container
  reuses the verified TinyLlama base snapshot instead of fetching a possibly
  different revision.
- **No fail-open introduced.** Nothing in the lab touches the enforcement path.
  The control-plane healthcheck asserts `model_loaded` (not just HTTP 200, per
  D28) and the data plane starts only after it passes — convenience, not safety:
  if the classifier disappears later the addon still fails closed.
- **GPU is requested, never silently skipped.** Without the NVIDIA Container
  Toolkit the control-plane container fails to start rather than falling back to
  CPU. A CPU run is a *different execution environment* from the
  `baseline-local-v1` CUDA baseline and must never be reported as comparable.

### Networking

Explicit bridge network `firewall-lab`, service-name DNS. `control-plane:8000`
and `destination:9000` are **not** published to the host; the data plane is
published on `127.0.0.1:8080` only. The destination also answers to the alias
`app.fwlab.test` — chosen and disclosed because `real-http-fp-v1` (§5c) observed
ordinary hostnames of that shape as ALLOW in every context tested, which keeps the
ALLOW smoke check about transport rather than re-measuring the model.

### Runtime verification — smoke run `20260921T011153Z`

The lab was built and run. Host prerequisites resolved: Docker and Compose work,
the **NVIDIA Container Toolkit works** and **GPU passthrough works**. The control
plane runs on **CUDA** and loads V4 from the read-only mounted adapter —
`startup: model ready on cuda in 1.7 s`, adapter `/opt/firewall-ia/adapter`.

Final run, `./docker/smoke_test.sh`, ended with `all infrastructure smoke checks
passed`:

| Check | Result | Evidence in the run log |
|---|---|---|
| **A** startup / readiness | **PASS** | `control plane healthy (/health reports model_loaded: true)` |
| **B** ALLOW | **PASS** | `status=200`, destination received 1 request (`GET /index.html`) |
| **C** BLOCK | **PASS** | `status=403`, destination received **0** requests; body `Request blocked by firewall-IA.` |
| **D** fail-closed | **PASS** | control plane `exited` before *and* after the request; `status=503`, destination received **0**; body `...classifier unavailable (fail-closed).` |
| **E** recovery | **PASS** | control plane healthy again, ALLOW `status=200` and received |

Raw evidence is **committed** with the closure report at `reports/lab/docker-lab-v1/`:
`raw/smoke-20260921T011153Z-PASS-final.log` (harness output plus all three services'
logs) and `raw/destination-access.jsonl` (the receipt log, cumulative across runs),
with `raw/SHA256SUMS`. The logs of the two failed validation attempts are committed
beside them, named `-FAILED-`. The machine-local originals stay under
`docker/.lab-logs/`, which remains gitignored working output.

Static checks, all still passing: `docker compose config` schema and
interpolation; `docker/config.docker.yaml` accepted by the real
`data_plane.load_config()` with a timeout identical to the root `config.yaml`;
**112 core tests pass with 1 expected skip**; **24 data plane tests pass**
(21 existing + 3 Docker-config drift tests). `datasets/v4_clean/` and
`model-output-v4-clean/` SHA-256 unchanged, dataset hashes still matching
`datasets/manifest_v4_clean.json`.

### Two defects found during validation, and their fixes

Both were found by running the lab; neither was a gateway fault.

1. **V4 could not load in the container.** `bitsandbytes` imports Triton, whose
   NVIDIA backend compiles a small CPython extension on first import. The bare
   `ubuntu:24.04` image had no toolchain, so model load failed with
   `RuntimeError: Failed to find C compiler. Please specify via CC environment
   variable.` FastAPI still started and `/health` stayed `model_loaded: false`,
   so the healthcheck correctly never went healthy — the failure was visible, not
   silent. **Fix: `docker/control-plane/Dockerfile` only**, adding
   `build-essential` (the C compiler) and `python3-dev` (the CPython headers the
   generated extension includes) to the existing apt layer. V4 then loaded on
   CUDA. No production code, requirement or version changed.
2. **The first fail-closed attempt was invalid.** `docker compose run client
   failclosed` resolves the dependency graph
   `client → data-plane → control-plane (condition: service_healthy)`, so Compose
   **restarted the classifier that had just been stopped** and waited until it was
   healthy. The run log shows `Stopping → Stopped → Starting → Started → Waiting →
   Healthy`, after which the request returned a normal ALLOW/200 and reached the
   destination. **This was a harness orchestration defect, not a fail-open of the
   gateway**: the data plane was never presented with an unavailable classifier.
   **Fix: `docker/smoke_test.sh` only** — `--no-deps` on the fail-closed
   invocation, plus an assertion that the control plane is stopped immediately
   before the request and still stopped after it, so a restart can never again be
   mistaken for a result. The manual sequence in `docker/README.md` carried the
   same defect and was corrected too. Fail-closed semantics were not touched.

### What the smoke tests are, and are not

`./docker/smoke_test.sh` runs the five checks above and tees every run to
`docker/.lab-logs/smoke-<timestamp>.log` together with the three services' logs,
so the raw evidence stays in the repository rather than in a terminal — the lesson
of the lost 2026-09-17 data (§5b).

**These are infrastructure smoke tests.** Three hand-written requests. They are
**not** External Test v1, **not** an evaluation, **not** a benchmark and **not** a
diagnostic. No accuracy, precision, recall, FPR, FNR, latency or throughput figure
may be derived from them — the `model_latency_ms` values visible in the run log
are incidental service logging, not a measurement. The smoke fixtures are
infrastructure fixtures and stay conceptually separate from any future external
evaluation set (**D37**). The frozen
`reports/benchmarks/baseline-local-v1/` and
`reports/diagnostics/real-http-fp-v1/` are never overwritten.

### Still out of scope for the lab

Unchanged from the local gateway's scope, and **not** validated by this run:
HTTPS/TLS interception, HTTP/2, WebSockets, transparent proxying, large request
bodies, concurrency and load (the control plane still serializes inference on one
GPU), end-to-end latency (Issue #18), and any model-quality claim. No fast path,
no suspicious scoring, no asynchronous classification, no GGUF/llama.cpp. The lab
reproduces the current no-fast-path baseline and nothing else.

---

## 6. PayloadsAllTheThings folder renames (root cause of missing categories)

The re-cloned repo renamed directories. `parse_dataset.py` CATEGORIES keys were updated this session:
- `"Path Traversal"` → `"Directory Traversal"` (NOT `Client Side Path Traversal`, which is a different, client-side attack — do not map to it).
- `"CSRF Injection"` → `"Cross-Site Request Forgery"`.

Output labels (the values, e.g. `"BLOCK | Path traversal attack detected."`) were left unchanged so they still match the test-suite expectations. Only the folder-name keys changed.

**Process lesson:** `[SKIP] Carpeta no encontrada` is currently SILENT — the script continues with missing categories. Treat `[SKIP]` as an ERROR, not a warning. A v4 improvement: make the script fail loudly (or at least summarize skipped categories prominently) if an expected folder is absent.

**Reproducibility — PayloadsAllTheThings commit RECORDED (2026-08-16):**

```
e961fef231d8327bae83b563fab50aec2e6b77c0
```

This is the commit present at `~/PayloadsAllTheThings/` when the current 99,132-example dataset was generated. Any regeneration intended to reproduce that dataset must check out this commit first. Re-verify with `git -C ~/PayloadsAllTheThings rev-parse HEAD`.

**Caveat — recording the commit is necessary but NOT sufficient for reproducibility.** `parse_dataset.py` is non-deterministic despite `random.seed(42)`, because the random stream's consumption order depends on `list(set(payloads))` (set iteration over strings varies with `PYTHONHASHSEED`, randomised per process) and on unsorted `os.listdir()` / `os.walk()` ordering. Two runs on this same machine at this same PATT commit will produce **different** datasets. Determinism is part of the D6 work.

---

## 7. v4 Plan — SUPERSEDED 2026-08-16

> **⚠️ The v4 plan recorded here was built on two premises that the audit disproved.**
>
> 1. *"Baseline already includes Path Traversal + CSRF … so 'add those categories' is DONE."* — **False.** CSRF has 46 examples (§3). It is not done.
> 2. *"Group 2: strengthen weak categories — JWT and GraphQL (genuinely weak, unlike CSRF which was just absent)."* — **The CSRF/JWT distinction does not hold.** CSRF (46), Request Smuggling (52), GraphQL (118), LDAP (123), NoSQL (135) and JWT (196) are all in the same low-volume regime. None of them is "genuinely weak" as opposed to "absent" — all are under-represented.
>
> There is also **no v3-rebuild baseline to measure against** (§3), so "trained+measured against the v3-rebuild baseline" is not currently executable.

Retained as still-valid from the original plan:

- **Remove `###END###`** (now **D5**, approved). Redundant — the inference regex already cuts on `.`/EOL, and TinyLlama's native `</s>` is the real stop token. Edit 3 files: `parse_dataset.py` (strip from INSTRUCTION + all outputs), `finetune.py` (remove `add_special_tokens` / `resize_token_embeddings`), `test_model.py` (simplify regex, drop `eos_token_id`). **Note:** the earlier characterisation of this as a mere "design-cleanliness change" understated it — see §12 F5, the token is structurally untrainable under the current LoRA config. But per **D5**, *do not claim a measured before/after latency improvement* unless a controlled experiment is later run; the historical v3 no longer exists to compare against.
- **Per-category rebalancing** — now confirmed necessary (§4), and broader than "JWT and GraphQL".
- **CSIC envelope bias fix** — subsuming into **D1** (shared envelope distributions across both classes), which is a stronger and more general fix.

**The current plan is the ordered experiment sequence in §13.** Do not restart v4 from this section.

---

## 8. Data strategy — proxy as a data factory (future)

Rather than sourcing a generic benign-traffic dataset (would carry its own app/era biases, same problem as CSIC), the stronger plan is to **capture realistic traffic via the proxy** once built. Validated in recent literature (capture via local proxy + Burp Logger, label as normal/attack).

Plan: put the proxy in front of a controlled app (DVWA / bWAPP, or a real app), browse legitimately → capture ALLOW; launch known attacks → capture BLOCK. **Same envelope for both ALLOW and BLOCK breaks the CSIC envelope bias at the root** — the model can no longer use User-Agent/cookies as a shortcut and must learn the payload. Labeling is reliable because the source is controlled. This is post-baseline, post-proxy work.

The weakest part of the current dataset is **legitimate-traffic diversity** (synthetic LEGIT_REQUESTS + 2010 CSIC normals), not attack diversity. Proxy capture directly addresses this.

---

## 9. Files and What They Do

**Locations** (run everything from the repository root): `control_plane/` — `classifier_api.py`,
`inference_core.py` · `data_plane/` — `data_plane.py` · `scripts/dataset/` — `parse_dataset.py`,
`parse_dataset_v4.py`, `check_dataset.py` · `scripts/training/` — `finetune.py` ·
`scripts/evaluation/` — `test_model.py` · `scripts/benchmarks/` — `benchmark_inference.py`,
`benchmark_env.py`, `benchmark_compare.py`. `config.yaml`, `csic_database.csv` and the historical
`train.jsonl`/`eval.jsonl` stay at the root.

**Docker Lab files (2026-09-20).** `compose.yaml` at the repository root; all
Docker assets under `docker/` (`config.docker.yaml`, one directory per service,
`smoke_test.sh`, `.env.example`, `README.md`); `.dockerignore` at the root. Nothing
in the layout above was moved. See §5d.

**Reorganization, 2026-09-20 — structural only.** Files were grouped by responsibility; no
behaviour, dataset or model changed. Verified afterwards: 112 core tests pass with 1
expected skip, the 21 data plane tests pass, the control plane and the data plane both start
from their new locations, the main self-tests pass, and the model and datasets keep
identical hashes.

### `parse_dataset.py`
Generates train/eval JSONL. Run `python3.12 scripts/dataset/parse_dataset.py`.
- `build_dataset()` — payloads from PayloadsAllTheThings + hardcoded categories + synthetic ALLOW pool.
- `build_obfuscated_examples(raw_block_payloads, 2000)` — 8 obfuscation transforms → 2,000 obfuscated BLOCK variants.
- `categorize_csic_anomalous(request_str)` — 11-rule heuristic on raw + `unquote_plus()`-decoded string.
- `integrate_csic2010(filepath)` — reconstructs HTTP requests from CSV (host→`target.com`, strips `/tienda1`), routes Normal→ALLOW, Anomalous→BLOCK (generic fallback filtered out).
- `main()` — build → obfuscate → integrate CSIC → merge → rebalance 1:1 (min-trim, seed=42) → shuffle → split 80/20 → write.

### `finetune.py`
LoRA fine-tune (4-bit NF4, rank=16, alpha=32). Run `python3.12 scripts/training/finetune.py`.
- `TRAIN_FILE`/`EVAL_FILE` → `~/Desktop/firewall-IA/`; `OUTPUT_DIR = model-output-v3` (already set).
- `resume_from_checkpoint=False` (set this session — fresh machine has no checkpoint to resume; `True` would crash).
- 4 epochs, batch 4, grad accum 8, lr 2e-4 cosine, **BF16 (D11)**, paged_adamw_8bit. Eval and save every 200 steps, `save_total_limit=2` (**D12**). `SFTConfig` + `SFTTrainer`.
- **Ported 2026-08-17 (E1) and verified running** — `SFTConfig`, `processing_class=`, `max_length=512`. See §12 F3 and `reports/e1_training_pipeline_smoke.txt`.
- `--smoke` runs a bounded compatibility test (500/100 examples, 12 steps, separate `model-output-e1-smoke/`). `--force-fp16` reproduces the pre-D11 incompatibility.
- **`###END###` removed 2026-08-17 (E4/D5).** No `add_special_tokens`, no `resize_token_embeddings`; termination is native EOS. See §12 F5 and `reports/e4_remove_end_token.txt`.

### `test_model.py`
**Evaluation harness — methodology FROZEN in E5 (D19).** Run `python3.12 scripts/evaluation/test_model.py --mode <mode>`.

Three modes, cleanly separated:
- `--mode dataset` *(default)* — **the primary scientific evaluation.** Runs `datasets/v4_clean/eval.jsonl` (6,206 rows, 3,103 ALLOW / 3,103 BLOCK, 18 categories).
- `--mode manual` — the legacy 135 hand-authored cases, reclassified as a **MANUAL DIAGNOSTIC / REGRESSION SUITE**. Preserved verbatim, prints a banner explaining why it is not the headline metric.
- `--mode self-test` — verifies the metric code on fixtures with **no model required**.

Reports three levels that are **never combined into one accuracy number**: (1) binary security decision with BLOCK as the positive class, full confusion matrix, precision/recall/F1, and FPR/FNR normalised over their own class populations; (2) attack category/reason, measured only over correctly-blocked attacks so a reason mismatch can never reduce binary recall; (3) latency (count/mean/P50/P95/P99/min/max/stdev), **model-side inference only** — `generate()` per row, with the cold first inference pooled in. It is not the D36 objective's instrument; that is `benchmark_inference.py`'s steady-state pipeline P95.

Invalid outputs are never coerced — counted as incorrect, mapped opposite to expected, reported as a separate rate alongside a parseable-only view. D18 is enforced by an `evidence_status` column (`OK` / `INSUFFICIENT DATA` / `NOT EVALUABLE`); every percentage carries its numerator and denominator. `--json` emits the machine-readable record.

Full specification: `reports/e5_evaluation_methodology.txt`.

### `benchmark_inference.py` · `benchmark_env.py` · `benchmark_compare.py`  *(added 2026-09-09 — Issue #9)*
**Controlled model-side inference benchmark.** Reuses `inference_core`; does not duplicate
inference logic and does not touch the `/classify` contract.

- `benchmark_inference.py` — `protocol` (spawns one fresh process per run), `run` (a single
  run), `summarize` (re-aggregate existing runs), `smoke`, `estimate`, `verify-timing`,
  `self-test`. Four populations kept separate — model load, first inference, warm-up,
  steady state — with cold-start/warm-up requests fixed in advance by seed 42 and excluded
  from the steady statistics without being discarded. Verifies the dataset against its
  manifest before measuring and refuses to overwrite an experiment that already has results.
  Percentiles are nearest-rank, identical to `test_model.percentile` (enforced by a test).
  No outlier removal. Quality comes from `test_model.score_binary`.
- `benchmark_env.py` — environment manifest read live from the machine: code identity
  (commit, dirty-diff hash, source hashes), OS/kernel, CPU/RAM, GPU/VRAM, NVIDIA driver and
  its *maximum supported* CUDA kept distinct from PyTorch's *actual* CUDA runtime, installed
  package versions, base-model revision, tokenizer/adapter hashes, effective CPU/GPU
  placement, effective quantization, and sampled power/thermal/load conditions. Unavailable
  values are recorded as null with a reason; environment variables are allowlisted.
- `benchmark_compare.py` — `reduction = 100 × (baseline − candidate) / baseline` and the
  distinct `speedup = baseline / candidate`, per statistic, handling missing values, zero
  references and regressions. Blocks incomparable reports (timing scope, dataset hash,
  request count, selection, order, protocol, batch, concurrency) with a non-zero exit.
  Flags hardware changes, joint hardware+software effects, and any quality degradation
  accompanying a speed gain. Accepts a legacy `test_model.py` result and correctly refuses
  to treat it as a peer.

### `check_dataset.py`  *(added 2026-08-16 — experiment E0)*
**Dataset integrity gate. Analysis-only — never mutates the dataset.** Run `python3.12 scripts/dataset/check_dataset.py`.
Measures, from the JSONL files each run (nothing hardcoded): per-category counts, duplication, exact train→eval leakage, envelope-confound distributions, trivial single-feature baselines, and SHA-256 hashes of all inputs. Exits `PASS` / `WARNING` / `FAIL`.
**Gate rule: no training run starts while this reports FAIL.**

### `csic_database.csv`
CSIC 2010. 61,065 rows × 17 cols. Label col `Unnamed: 0` (`"Normal"`/`"Anomalous"`). Used: `Method`, `URL`, `User-Agent`, `cookie`, `content-type`, `content`. `URL` cell format: `http://localhost:8080/tienda1/path?query HTTP/1.1`. Col `lenght` is an original-data typo.

---

## 10. Known Limitations and Intentional Decisions

- **CSIC User-Agent bias (still present):** all CSIC examples use the same Konqueror UA + JSESSIONID pattern. Fix is **D1** (shared envelope distributions) + proxy capture (§8).
- **18,478 CSIC Anomalous excluded:** structural anomalies (buffer overflow, integer tampering, cookie poisoning) with no keyword-detectable payload; generic label can't be validated from content. ~73.7% of CSIC Anomalous. **Per D2, these stay excluded from the clean baseline** and are preserved conceptually as a separate future experimental dataset.
- **CSIC attack diversity is narrow:** ~70% SQL, low payload variety (see §4).
- **`--` SQL keyword rule is broad** in `categorize_csic_anomalous()`; acceptable for e-commerce context, revisit if extended.
- **Latency: the ~800ms/request figure is UNVERIFIED and confounded.** No model exists to measure. It was also inflated by forced 40-token generation (§12 F5), so it was never a measure of decision latency. **Per D3 the design target is now defined: end-to-end added latency P95 ≤ 200 ms** — a target, not a demonstrated capability. Future measurement must decompose into model-only / model+API / proxy overhead / end-to-end, each with P50, P95, P99 and throughput. *(2026-09-18: the target is superseded by **D36** — P95 of the inference pipeline ≤ 200 ms in steady state, not end-to-end; see §3. The decomposition requirement still applies.)*
- **Failure behaviour: FAIL-CLOSED** per **D4**. If the classifier times out, crashes, is unavailable, or returns an invalid decision, traffic is blocked by default. A fallback mechanism is explicitly out of current scope.

---

## 11. Measured dataset composition (2026-08-16)

Measured directly from `train.jsonl` + `eval.jsonl` (99,132 examples). **Re-measure with `check_dataset.py`; do not quote these from memory after the dataset is regenerated.**

| Label | Count | % |
|-------|------:|--:|
| ALLOW | 49,566 | 50.00 |
| BLOCK — Path traversal | 24,176 | 24.39 |
| BLOCK — File inclusion | 8,447 | 8.52 |
| BLOCK — SQL injection | 7,040 | 7.10 |
| BLOCK — Cross-site scripting | 4,124 | 4.16 |
| BLOCK — Command injection | 1,469 | 1.48 |
| BLOCK — CRLF injection | 744 | 0.75 |
| BLOCK — SSTI | 697 | 0.70 |
| BLOCK — Insecure deserialization | 414 | 0.42 |
| BLOCK — HPP | 400 | 0.40 |
| BLOCK — Open redirect | 391 | 0.39 |
| BLOCK — XXE | 381 | 0.38 |
| BLOCK — SSRF | 312 | 0.31 |
| BLOCK — XPath | 301 | 0.30 |
| BLOCK — JWT | 196 | 0.20 |
| BLOCK — NoSQL | 135 | 0.14 |
| BLOCK — LDAP | 123 | 0.12 |
| BLOCK — GraphQL | 118 | 0.12 |
| BLOCK — Request smuggling | 52 | 0.05 |
| **BLOCK — CSRF** | **46** | **0.05** |

**ALLOW pool diversity (measured):** 49,566 ALLOW examples contain only **23,516 unique inputs**. Of these, the synthetic side is 26,290 examples drawn from just **240 unique strings** (≈110× replication); the remaining 23,276 are CSIC normals, all from one 2010 Spanish e-commerce app with one host, one User-Agent and one cookie pattern. Benign diversity is the weakest part of the dataset — §8 already says this; the measurement is worse than the prose implied.

---

## 12. Audit findings — 2026-08-16

Full audit: `reports/` (see also the standalone audit document produced 2026-08-16). Finding IDs are referenced throughout this file.

### F1 — CRITICAL — the `Host` header is a near-perfect label shortcut

Measured `Host` → label mapping across all 99,132 examples:

| Host | Total | ALLOW | BLOCK |
|------|------:|------:|------:|
| `target.internal.com` (all PayloadsAllTheThings + hardcoded + obfuscated) | 42,979 | **0** | 42,979 |
| `target.com` (all CSIC) | 29,863 | 23,276 | 6,587 |
| 53 other hosts (all synthetic LEGIT_REQUESTS) | 26,290 | **26,290** | **0** |

A classifier that reads **only the `Host` header** and never the payload scores **≈93% on this dataset — higher than the historical 91% attributed to the model.** `wrap_in_http()` hardcodes `target.internal.com` on every attack example; the synthetic benign templates use `example.com`-family hosts exclusively; CSIC uses `target.com`.

**Consequence: every accuracy number produced on this dataset is uninterpretable as evidence of attack detection.** Training loss can be minimised almost entirely from the `Host` token.

**`Host` is not the only shortcut.** The E0 gate run of 2026-08-16 (`reports/e0_dataset_integrity_current.txt`) scored every single non-payload feature by fitting a lookup table on train and evaluating on eval. Majority-class baseline is 49.91%:

| Non-payload feature alone | Eval accuracy | vs majority |
|---------------------------|--------------:|------------:|
| `Host` value | **93.72%** | +43.81 |
| `Content-Type` value | **82.62%** | +32.72 |
| Header-name set (structural fingerprint) | 76.84% | +26.94 |
| Header count | 75.88% | +25.97 |
| Body present/absent | 74.12% | +24.21 |
| HTTP method | 74.06% | +24.15 |
| `User-Agent` value / presence | 67.94% | +18.03 |
| `Cookie` presence | 67.14% | +17.23 |

**Every one of these is an independent shortcut**, and they are structural, not incidental:
- **HTTP method** — `wrap_in_http()` picks a random method for attack examples, so DELETE (90.8%), PATCH (92.9%) and PUT (91.8%) are near-pure BLOCK, while the synthetic benign templates are mostly GET/POST.
- **Content-Type / body / header-count / header-set** — a direct consequence of the three sources emitting three fixed request shapes: PayloadsAllTheThings wraps are `host` + optional `content-type`; CSIC always carries `cookie` + `user-agent`; synthetic ALLOW carries assorted realistic headers.
- **Malformed request-target** — a raw space inside the request-target appears in 1,418 BLOCK examples and **0 ALLOW** (100% pure). Cause: `wrap_in_http` interpolates raw scraped lines into `GET {path}?{param}={payload} HTTP/1.1` without percent-encoding.

**Implication for D1:** neutralizing `Host`, `User-Agent` and cookies is necessary but **not sufficient**. Method, body presence, `Content-Type`, and the header-name set must also be drawn from shared distributions across both classes, and payloads must be percent-encoded into the request-target. D1's "and similar metadata" clause is doing real work here — treat this table as its concrete scope.

**Nine deterministic label reveals** were flagged (a single envelope value ≥99% pure over ≥1% of the dataset): `target.internal.com`→BLOCK (43.36% of the dataset), seven `*.example.com`-family hosts→ALLOW, and the malformed-target artifact→BLOCK.

Re-measure with `check_dataset.py` after any regeneration. Do not quote this table once the dataset changes.

### F2 — CRITICAL — 26.6% train/eval leakage

Measured: **5,283 of 19,827 `eval.jsonl` inputs appear verbatim in `train.jsonl` (26.65%).** Unique inputs are 73.76% of train and 74.63% of eval — i.e. each split is also ~26% internally duplicated.

**The leakage is concentrated in just 253 distinct strings** (E0 run, 2026-08-16) — a handful of templates replicated hundreds of times. The single worst appears 171× in train and 39× in eval. This confirms the mechanism: it is template replication, not broad overlap.

Cause: `main()` shuffles and splits a pool that already contains exact duplicates (240 `LEGIT_REQUESTS` replicated ~110×; CRLF/XPath emit 8 wraps per payload; HPP is templated; obfuscated examples derive from payloads already in the base pool). There is no deduplication step anywhere in `parse_dataset.py`.

**Consequence:** `finetune.py` sets `load_best_model_at_end=True`, with `metric_for_best_model` defaulting to `eval_loss`. **Model selection is performed on a leaked validation set, so it rewards memorisation.**

The fix must dedup *and* split on a payload-identity key, so that obfuscated/wrapped variants of one payload cannot straddle the split.

### F3 — RESOLVED 2026-08-17 (E1) — `finetune.py` could not run on the installed stack

> **Resolved.** Ported to `SFTConfig` / `processing_class` / `max_length`; smoke test PASS. See `reports/e1_training_pipeline_smoke.txt`.
>
> **One recipe-affecting change was forced, now ratified as D11:** `fp16=True` → `bf16=True`. TRL 1.4 casts all trainable params to bfloat16 when the base model is 4-bit loaded (`sft_trainer.py:1088-1092`), and `fp16` routes through `GradScaler`, whose `_amp_foreach_non_finite_check_and_unscale_cuda` kernel has no BFloat16 implementation. fp16 + 4-bit QLoRA cannot run on TRL 1.4 at all. `python3.12 scripts/training/finetune.py --smoke --force-fp16` reproduces the crash. **D11 is a compatibility decision and must never be presented as a model-quality improvement** — no fp16-vs-bf16 quality comparison exists or can be made.
>
> **Also confirmed quantitatively, now ratified as D12:** the production recipe (4 epochs, `save_steps=200`, no `save_total_limit`) would produce ~49 checkpoints at ~302 MB each ≈ **14.8 GB before optimizer state**. `save_total_limit=2` is now set; `save_steps` and all other hyperparameters are unchanged.
>
> Original finding preserved below.

Installed and verified 2026-08-16: `transformers 5.8.0`, `trl 1.4.0`, `peft 0.19.1`, `torch 2.6.0+cu124`, `bitsandbytes 0.49.2`, `accelerate 1.13.0`, `datasets 4.8.5`.

Verified by introspecting `trl.SFTTrainer.__init__` on this machine — `dataset_text_field`, `max_seq_length` and `tokenizer` are **all rejected**. They moved onto `SFTConfig` / `processing_class`. `transformers.Trainer` also no longer accepts `tokenizer=`.

`finetune.py` passes all three. **Training is blocked until this is ported.** Environment drift, not a design flaw. There is no `requirements.txt` or lockfile anywhere in the repo, so further drift is likely.

*(Numbered F4 in the original audit document; renumbered here. The audit's F3 — benign diversity — is recorded in §11.)*

### F5 — RESOLVED 2026-08-17 (E4) — `###END###` was structurally untrainable

`finetune.py` adds `###END###` as a special token and calls `resize_token_embeddings`, appending a **randomly initialised** row to `embed_tokens` and `lm_head`. `LoraConfig.target_modules` covers only `q_proj, k_proj, v_proj, o_proj, gate_proj, up_proj, down_proj` — **`embed_tokens` and `lm_head` are in neither `target_modules` nor `modules_to_save`.** Therefore:

1. The new token's embedding and output-head row receive no gradient.
2. `generate(..., eos_token_id=end_token_id)` therefore almost certainly never fires — every inference runs the full `max_new_tokens=40`.

> **⚠️ CORRECTED 2026-08-17 by E1 measurement** (`reports/e1_training_pipeline_smoke.txt` §7a). Two parts of the original finding were wrong on this stack:
>
> - **"randomly initialised"** — wrong. transformers 5.8 mean-resizes new rows from a multivariate normal fitted to the existing embeddings' mean and covariance.
> - **"never saved / re-randomised on every load"** — wrong. PEFT force-saves **both full embedding matrices** when it detects a resize (`peft/utils/save_and_load.py:386`), so the row is persisted and deterministic across loads.
> - **"receives no gradient"** — **correct, and confirmed.** The saved `adapter_config.json` has `modules_to_save=None` and `trainable_token_indices=None`. The token is saved at its initialisation value and never learns to be emitted.
>
> **The strongest argument for D5 is now a measured cost, not load non-determinism:** the resize inflates the saved adapter from ~24 MiB (LoRA only, 12,615,680 params) to **298 MB**, because 131,076,096 params of full `embed_tokens` + `lm_head` matrices are written into every checkpoint and into the final adapter — carrying no trained information beyond the base model. **A ~12× size increase.** This bears directly on D8 item 3 (GGUF export) and D10 (embedded storage budget).
>
> TRL 1.4 has machinery that would fix this class of bug (`trainable_token_indices` + automatic `modules_to_save=["lm_head"]`), but it only fires for tokens TRL itself adds via chat-template cloning — not for tokens added externally as `finetune.py` does.

**RESOLVED 2026-08-17 by E4.** The token, the `add_special_tokens` call and the `resize_token_embeddings` call are gone from all four pipeline files; termination is native EOS (`</s>`, id 2). Verified without training: tokenizer vocabulary stays at 32,000, and the saved adapter contains **no** `embed_tokens`/`lm_head` tensors — 12,615,680 params total. The structural cause of the ~12× inflation is removed. **No latency improvement is claimed**; that remains a hypothesis until measured.

### F6 — HIGH — CSIC BLOCK labels are produced by the mechanism a rule-based baseline would use

`categorize_csic_anomalous()` assigns every CSIC BLOCK label with an 11-rule keyword heuristic, and **discards the 18,478 rows (73.7% of CSIC Anomalous) it cannot match**. The CSIC attack set is therefore, by construction, exactly the subset a keyword matcher detects.

This makes any future rule-vs-AI comparison circular on the CSIC portion. Per **D9** that comparison is future/optional work, so this is not currently blocking — but it must be addressed before any such comparison is attempted. Per **D2** the excluded rows are preserved as a separate future experimental dataset, which is precisely the portion where an AI classifier could plausibly show an advantage over a regex.

### F7 — HIGH — label noise from the markdown scraper

`extract_payloads_from_md()` has a second pass that accepts **any** line in a file (not only fenced code) containing one of `'` `"` `--` `;` `|` `UNION` `SELECT` `DROP` `<script` `../` `&&` `||` `$(` `` ` `` at 10–300 chars. English prose, markdown table rows and reference URLs all match. The `.txt` walk accepts every line over 3 characters.

Observed in the generated dataset:

```
GET /admin/query?data=var xhr = new XMLHttpRequest(); HTTP/1.1   → BLOCK | CSRF
GET /admin/query?search=&#x00003C HTTP/1.1                       → BLOCK | XSS
POST /admin/query … cmd=//..\/..\/..\/..\/..\{FILE}              → BLOCK | Path traversal
```

The last contains an **unresolved fuzzer template placeholder** `{FILE}`. The 24,176 path-traversal examples are largely raw fuzzing-wordlist entries, not HTTP requests.

### F8 — HIGH — obfuscation is not an independent generalization test

`build_obfuscated_examples()` samples from `raw_block_payloads`, the same pool used to build the base BLOCK examples — so the un-obfuscated original of nearly every obfuscated example is also in the dataset. The 20 `ADVERSARIAL_CASES` in `test_model.py` use the same transform families seen in training. **The adversarial suite is in-distribution**: it measures whether the model learned its 8 training transforms, not evasion resistance. A real evaluation needs held-out transforms and held-out base payloads.

### F9 — MEDIUM — generated JSONL are tracked in Git despite documentation saying otherwise

`.gitignore` lists `train.jsonl` and `eval.jsonl`, and earlier revisions of this file stated that generated datasets are "not versioned". **Both files are in fact tracked** (`git ls-files` confirms), totalling ~43.5 MB of JSONL committed without Git LFS (`.gitattributes` contains only `* text=auto`). `.gitignore` has no effect on already-tracked files.

This is currently the *only* reason the 99,132-example dataset still exists, so it is load-bearing historical evidence. **Per D6, do NOT `git rm --cached` these files yet** — the migration procedure must be documented and proposed first so historical evidence is not lost.

### Other findings carried forward

- **Non-deterministic generation** despite `seed=42` — see §6.
- **Silent `[SKIP]`** in `build_dataset()` is still armed (§6) — the exact failure that cost v3 two categories.
- **Unbounded checkpointing:** `save_steps=200` with `save_total_limit` unset ≈ 49 checkpoints (adapter + `paged_adamw_8bit` state) — disk-exhaustion risk on a laptop.
- **Test-suite contamination:** 1 of 135 cases appears verbatim in `train.jsonl`; 11 of 135 test payload *fragments* appear verbatim inside training text (~8%). Tolerable if disclosed; currently undisclosed.
- **Reason labels are folder-determined, not content-determined** — a payload in two PayloadsAllTheThings directories gets two different BLOCK reason strings.
- **Accidental partial ablation:** 110 of 136 `Host:` lines in `test_model.py` use `target.com` — the envelope where the F1 shortcut argues *against* blocking. If the lost v3 genuinely scored 91% there, that is weak evidence it learned something beyond the envelope. Unconfirmable now (no model), and an accident of test authorship rather than a designed control.

---

## 12b. Candidate clean dataset (v4) — E2 + E3, 2026-08-17

**Status: CANDIDATE. Not a validated baseline.** E0 returns WARNING (no blocking failures).
It must be reviewed before any training run. Full report: `reports/e2_e3_clean_dataset.txt`.

- Generator: **`parse_dataset_v4.py`** (new file). `parse_dataset.py` is left untouched and executable — it is the control condition for the E2 before/after comparison.
- Artifacts: `datasets/v4_clean/{train,eval}.jsonl` — **25,134 / 6,206 rows** (31,340 total), eval ratio 0.1980, exactly 1:1 ALLOW/BLOCK. Generated under **D17 FINAL** (policy B · group cap 2,500 · row cap 4,000).
- Evidence trail preserved: `reports/e2_e3_clean_dataset_uncapped.txt`, `reports/e0_dataset_integrity_v4_clean_uncapped.txt`, `datasets/manifest_v4_clean_uncapped.json`, plus the two sensitivity analyses that selected the final policy — `reports/e2_e3_cap_sensitivity.txt` and `reports/e2_e3_row_cap_sensitivity.txt`. Every scenario is exactly reproducible from the generator flags.

### D17 FINAL — two independent contribution levers

The finalized methodology distinguishes **two different quantities** that were previously conflated:

| Lever | Setting | Applied | Controls |
|---|---|---|---|
| Cap policy | **B — source-agnostic** | — | CSIC-derived BLOCK groups count toward the same per-category budget as PayloadsAllTheThings/hardcoded |
| **Logical-group cap** | **2,500 / malicious category** | *before* rendering | **source/category DIVERSITY dominance** — how many distinct source payloads a category may contribute |
| **Rendered-row cap** | **4,000 BLOCK rows / malicious category** | *after* rendering + dedup, *before* balancing | **final training CONTRIBUTION** — how much a category actually contributes to training |

**Both are required.** A group cap alone cannot control contribution: a CSIC group is a request *shape* that collapsed many original records, and every record still renders. Measured at a 2,500-group cap, SQL Injection still produced 5,545 rows while Path Traversal produced 2,511 — a group cap cannot reach that redundancy.

**Row selection** is deterministic, source-stratified (proportional by largest remainder, so neither PayloadsAllTheThings nor CSIC is deleted first), and **breadth-first** — one row per logical group before any second row. It therefore spends the budget on breadth before depth and removes redundant *renderings* before it removes logical *diversity*. Measured at the final settings: SQL Injection 5,545 → 4,000 rows at **100% logical-group retention**, and 100% retention in every other category.

**Hard floor, enforced in code:** `row_cap ≥ group_cap`. Below it, retention pins at exactly `row_cap/group_cap` by arithmetic (measured: 2000/2500 → 80.0% in four categories). The generator now refuses to run rather than silently destroying diversity.

> **25.5% largest-category share is an observed outcome of this compromise, not a target or a standard.** Do not cite it as a balance threshold.
- Manifest: `datasets/manifest_v4_clean.json` (SHA-256, counts, rejection reasons, limitations).
- The historical `train.jsonl` / `eval.jsonl` at repo root are **unchanged**.

### What E0 measures on it

| Metric | Historical | Candidate |
|---|---:|---:|
| E0 verdict | FAIL | WARNING |
| train→eval leakage | 26.65% | **0.00%** |
| within-split duplicates | 26.24% / 25.37% | **0.00% / 0.00%** |
| deterministic label reveals | 9 | **0** |
| `Host` baseline | 93.72% | **49.73%** |
| `Content-Type` baseline | 82.62% | 51.16% |
| header-name set | 76.84% | 49.21% |
| header count | 75.88% | 49.89% |
| body presence | 74.12% | 50.00% |
| HTTP method | 74.06% | 50.00% |
| User-Agent (value) | 67.94% | 50.47% |
| User-Agent (presence) | 67.94% | 49.76% |
| Cookie presence | 67.14% | 49.65% |
| majority baseline | 49.91% | 50.00% |

Eight of eleven incidental features sit **at or below** the majority baseline; the strongest is Content-Type at +1.16. **On this dataset no incidental envelope feature beats a coin flip.** This is a statement about the dataset only — no model has been trained on it.

### How (structural, not shortcut-by-shortcut)

1. **One shared envelope generator** for both classes — no benign-only or attack-only host, UA or cookie exists anywhere. CSIC records are re-rendered under it (semantics preserved, envelope redrawn), which kills the `target.com` + Konqueror signature.
2. **Shape matching** — 15 request "shapes" (method set, paths, params, content type, special headers). Every attack shape gets benign traffic in the *same* shape at *matched volume*. This collapsed Content-Type, header-set, header-count and body-presence simultaneously.
3. **Method-stratified class balancing** — within each HTTP method both classes are trimmed to the minimum, forcing `P(BLOCK | method) = 0.5`. Trimming only; nothing duplicated.

### Causal exceptions (deliberately allowed to correlate)

Measured: Origin **presence** 54.8% pure (non-predictive, because benign counterparts carry same-origin Origin/Referer), but Origin **cross-origin** 100% BLOCK — that relationship *is* the CSRF attack. Same pattern for smuggling framing headers and HPP duplicate parameters. All documented in the manifest under `causal_envelope_exceptions`.

### Reproducibility

Two consecutive runs with `PYTHONHASHSEED=random` produced **bit-identical** output — the historical generator could not do this. Sorted traversal, no set-iteration dependence, per-sample RNG seeded from group id, deterministic hash-bucket split.

### D17 FINAL — what the caps did

Group cap 2,500 (policy B, merged PATT+CSIC pool): Directory Traversal 10,218→2,500, SQL Injection 2,953→2,500, File Inclusion 2,937→2,500, XSS 2,628→2,500. Row cap 4,000: only SQL Injection exceeded it — **5,545 → 4,000 rows at 100% logical-group retention (2,500 → 2,500)**.

Largest attack-category share of BLOCK: **47.3% → 25.5%**. Top-3 combined 70.6% → 65.2%. Effective category count 6.36 → 7.42. Rows per represented logical group now 1.00–1.67 in every category — the redundancy that made row counts a misleading diversity proxy is gone.

Policy A was retired because it could not control dominance at any cap (SQL never fell below 36.5% of BLOCK) and cap1000_A was Pareto-dominated — smaller *and* more dominated than the policy-B alternatives. See `reports/e2_e3_cap_sensitivity.txt`.

CSIC BLOCK traffic retained: 3,906 of 5,900 rows (66%). This is the price paid for contribution control, and it is real: CSIC is the only non-synthetic attack traffic in the dataset.

### ⚠️ The dominant unresolved issue: category scarcity

**Request Smuggling is NOT EVALUABLE (D18)** — 7 train rows, **zero eval rows**. No category-level accuracy, recall, or other performance claim may be made for it. Recorded in the manifest under `not_evaluable_categories`, determined from the rendered split rather than asserted by hand.

**11 categories are marked INSUFFICIENT DATA** (<100 unique logical groups): Request Smuggling (7), Insecure Deserialization (12), HPP (20), CRLF (21), XPath (24), CSRF (31), GraphQL (74), LDAP (75), JWT (80), NoSQL (83), XXE (98). Neither cap affects any of them — all sit far below 2,500.

This is a *source material* problem (PayloadsAllTheThings has 56 fenced lines for CSRF, 61 for smuggling), not a generator problem, and per D14 nothing was fabricated to inflate them.

### Size caution

The finalized dataset is 31,340 rows, down from 53,756 uncapped and 99,132 historical. Method-stratified balancing trims hard once BLOCK shrinks (34,248 train + 5,567 eval rows trimmed). Smaller and valid is the intended trade (D7), but this remains a small dataset for a 1.1B model — worth weighing before training.

---

## 13. Current ordered plan

Supersedes the v4 plan in §7. Decisions D1–D18 are recorded in `DECISIONS.md`.

| Step | Experiment | Status |
|------|-----------|--------|
| **E0** | Dataset integrity gate (`check_dataset.py`) | **DONE 2026-08-16** — current dataset reports **FAIL**, as expected |
| **E1** | Port `finetune.py` to TRL 1.4 / transformers 5.8; smoke-test | **DONE 2026-08-17 — PASS** (`reports/e1_training_pipeline_smoke.txt`). Tooling unblocked. |
| — | Documentation correction (this file + `DECISIONS.md` + `README.md`) | CONTEXT + DECISIONS done 2026-08-16; **README still stale** |
| **E2** | Envelope neutralization — shared envelope + shape matching | **DONE 2026-08-17** (`reports/e2_e3_clean_dataset.txt`). Strongest incidental baseline 93.72% → 51.16%. |
| **E3** | Leakage-free grouped split | **DONE 2026-08-17.** Leakage 26.65% → 0.00%; duplicates → 0.00%. |
| **E4** | `###END###` removal (D5) | **DONE 2026-08-17** (`reports/e4_remove_end_token.txt`). Dataset regenerated; E0 metrics byte-identical. |
| **E5** | Freeze evaluation methodology (D19) | **DONE 2026-08-17** (`reports/e5_evaluation_methodology.txt`). Self-test PASS. |
| **#7** | **V4 clean baseline training run** | **DONE 2026-08-18 — merged (PR #32).** See §3 and `reports/v4_clean_baseline_results.txt`. |
| **#8** | V4 clean security metrics evaluation | **DONE 2026-08-18 — closed 2026-09-06.** `reports/v4_clean_eval.json`; all ten AC verified. |
| **#15** | FastAPI Control Plane | **DONE 2026-09-05 — merged (PR #34), closed.** See §5. |
| **#9** | Controlled inference benchmark | **DONE 2026-09-09 — `baseline-local-v1` measured and frozen. Closed 2026-09-14.** See §3. |
| **#16/#17** | Data plane, fail-closed | **FIRST VERSION 2026-09-16** — verified locally, see §5b |
| — | Real-HTTP diagnostic `real-http-fp-v1` | **DONE 2026-09-18** — reproducible and persisted, see §5c |
| — | Repository reorganization by responsibility | **DONE 2026-09-20** — structural only, see §9 |
| — | **Docker Lab** — reproducible environment for the whole system | **DONE 2026-09-21 — runtime verified.** Checks A–E pass, see §5d and `reports/lab/docker-lab-v1/` |
| — | **External Test v1** — independent, frozen external set | **NEXT — NOT STARTED**, does not exist yet (below) |
| — | **Full external evaluation through the complete gateway** (D22) | NOT STARTED — depends on the two above |
| — | **Professor demo** — ALLOW / BLOCK / fail-closed + demo subset | NOT STARTED |
| — | **README / results / standards alignment / future work** | NOT STARTED |
| **#18** | End-to-end latency | NOT STARTED — after the sequence above |
| — | Security / error analysis of the 92 false negatives (D21) | Outstanding — no dedicated issue |
| **#35–#38** | Suspicious scoring, fast path, async validation, calibration (D29/D30) | NOT STARTED |
| — | Decision gate: targeted V4.1 only if evidence requires it (D21) | Pending the failure analysis (#9 is done) |
| — | ~~Per-category rebalancing~~ | **SUPERSEDED by D17** — the logical-group cap (2,500) and rendered-row cap (4,000) now control category contribution. Scarce categories are reported, never inflated (D14/D18). |
| **E6** | Held-out evasion evaluation | NOT STARTED |
| **E8** | Quantization tradeoff (FP16 vs GGUF Q4_K_M) | NOT STARTED |
| **E9** | Inline overhead decomposition (per layer: inference pipeline / API / proxy / end-to-end; D3 decomposition, D36 objective) | NOT STARTED |
| **E7** | Conventional rule-based baseline | **FUTURE / OPTIONAL per D9** — do not implement now |

**Gate rule:** no training run starts while `check_dataset.py` reports FAIL.

### External Test v1 — does not exist yet

Nothing of it is built. When it is built, per **D37** and
`docs/ml_evaluation_methodology.md`:

- It is **independent of the V4 dataset**, and **frozen before V4 is evaluated on it**.
- It ships with ground truth, categories, slices, a manifest and hashes.
- It measures TP/TN/FP/FN, accuracy, BLOCK precision, recall / attack detection rate, F1,
  FPR, FNR, invalid outputs, and per-category / per-slice metrics.
- It also verifies **gateway enforcement**, not only classification.
- The **main execution runs through the complete system** — client → data plane → control
  plane → V4 → data plane → destination. Direct `/classify` calls are auxiliary per-layer
  consistency controls only.
- It is **not** designed around the already known failures of `real-http-fp-v1` (§5c).
- If its individual errors are later used to guide V5, it stops being an independent test
  for V5 (**D37**) and becomes development / error-analysis data.

**Core scope per D8:** clean dataset → validated classifier → GGUF/quantized deployment → inline HTTP gateway → security validation → sufficient performance evaluation → physical embedded deployment. Deep comparative studies and architecture extensions are **not** core.

---

## 14. How to Re-Orient at the Start of a New Session

1. Read **"Current checkpoint"** at the top of this file — it is the fastest reconstruction
   of where the project is and what comes next. Then this file, then `DECISIONS.md`.
2. **Use `python3.12`, not `python3`** (see §2). This is the #1 gotcha post-reinstall.
3. Read `scripts/dataset/parse_dataset.py`, `scripts/training/finetune.py`,
   `scripts/evaluation/test_model.py` for current config (locations in §9) — and read §12
   first, so you know which of their behaviours are already-identified defects rather than
   things to rediscover.
4. Check training status: `ls ~/Desktop/firewall-IA/model-output-v4-clean/`. **As of 2026-08-18 the V4-clean baseline EXISTS** (best checkpoint 2200). `model-output-v3/` never existed and is not the current model.
5. Confirm dataset: `wc -l datasets/v4_clean/train.jsonl` (expect 25,134) and `datasets/v4_clean/eval.jsonl` (expect 6,206). The root `train.jsonl`/`eval.jsonl` are the HISTORICAL leaky corpus — do not train on them.
6. **Run the integrity gate:** `python3.12 scripts/dataset/check_dataset.py --train datasets/v4_clean/train.jsonl --eval datasets/v4_clean/eval.jsonl`. No training starts while it reports FAIL. WARNING (category scarcity) is expected and acceptable.
7. Confirm no missing categories: run `parse_dataset.py` only if regenerating, and check for `[SKIP]` lines. `[SKIP]` is an ERROR, not a warning.
8. Verify PayloadsAllTheThings is at the recorded commit `e961fef231d8327bae83b563fab50aec2e6b77c0` (§6) if categories look off.
9. **Docker Lab:** built and runtime verified on 2026-09-21 (§5d). Bring it up with
   `docker compose up -d control-plane data-plane destination` and re-check it with
   `./docker/smoke_test.sh`. Its checks are infrastructure plumbing only — never
   quote them as model results.

### Language discipline

Never state that the system is "more secure" or "faster" than a conventional mechanism unless an experiment in `reports/` demonstrates it. Distinguish observation / measurement / hypothesis / interpretation / conclusion. Prefer "under the tested conditions…", "the experiment indicates…", "additional testing is required…". Do not present the 91% figure as a current result (§3).