# firewall-IA — Repository Migration & GitHub Backlog

**Date:** 2026-08-17
**Purpose:** Reorganise the repository for the course Git/GitHub grading criteria
(Conventional Commits, branch workflow, Issues, Milestones, clean history).

> **`gh` is not installed and no git credential helper is configured**, so no remote
> operation could be performed automatically. All local Git work is done. Everything in
> sections 2–6 must be executed by you.

---

## 1. What was done locally (complete)

| Action | Result |
|---|---|
| Renamed local `API` → `develop` | done, head `a9f03e0` |
| Cleared stale upstream (was `origin/API`) | done, so `push -u` sets it correctly |
| Deleted local `training` | done, was `d74ba9b`, safe `-d` deletion |
| Working tree | clean |
| Commits created / history rewritten | **none** |

> **STATUS UPDATE 2026-08-17 —** the remote work in section 2 has since been completed by the
> user: `develop` is published and tracking `origin/develop`, and the obsolete `API` and
> `training` remote branches were deleted. Section 2 is retained as a record of what was run.
>
> Note: local remote-tracking refs `origin/API` and `origin/training` may still appear until
> `git fetch --prune` is run from an authenticated session. Their presence locally does not
> mean the remote branches still exist.

### Verification that `training` was safe to delete

- `git log API..training` → **empty** (no unique commits)
- `git merge-base --is-ancestor training API` → **yes**
- `git merge-base --is-ancestor training main` → **yes** (already in main too)

### ⚠️ `main` / `develop` divergence — read before opening a develop→main PR

`main` (`ba3d7d9`) has **3 commits not in `develop`**:

```
ba3d7d9  Merge branch 'training'                                    (merge, 2 parents)
ec2fdc4  Merge pull request #2 from SebasHT15/training              (merge, 2 parents)
1c8c43e  feat: merge training branch — AI firewall classifier v2 ready (merge, 2 parents)
```

All three are **merge-bookkeeping commits carrying no unique content**: `main`'s tree is
byte-identical to `d74ba9b` (the old `training` head), which is `develop`'s base. So no
content is missing from `develop` — but the histories have diverged.

**Consequence:** a future `develop` → `main` PR will *not* be a fast-forward. Use a normal
merge commit (GitHub's default "Create a merge commit"). Do **not** rebase or force-push
`main` to "clean" this — the divergence is harmless and rewriting shared history is worse.

---

## 2. Remote commands you need to run

Run in order. Each is a branch-management operation; none creates a commit or rewrites history.

```bash
# 1. Publish develop and set its upstream
git push -u origin develop

# 2. Verify origin/develop exists and matches before deleting anything
git ls-remote --heads origin
git rev-parse develop origin/develop      # must be identical

# 3. ONLY after step 2 confirms origin/develop — delete the obsolete remotes
git push origin --delete API
git push origin --delete training

# 4. Prune stale remote-tracking refs
git fetch --prune

# 5. Final check
git branch -avv
```

### Then, in the GitHub UI (Settings → Branches)

1. Confirm the **default branch** is `main`.
2. Optional but recommended for the grading criteria — add a branch protection rule on
   `main`: require a pull request before merging. With a single developer you may leave
   "require approvals" at 0 so you can still merge your own PRs.

---

## 3. Branch policy (target structure)

```
main            stable / deliverable checkpoints; receives work via PR from develop
└── develop     active integration branch; feature branches merge here
    ├── feature/<issue>-<slug>
    ├── fix/<issue>-<slug>
    ├── test/<issue>-<slug>
    ├── perf/<issue>-<slug>
    └── docs/<issue>-<slug>
```

Permanent branches are **only** `main` and `develop`. Temporary branches are deleted after
merge. Do not reintroduce generic long-lived branches (`API`, `training`, `new`, `changes`).

**Flow:** Issue → branch from `develop` → work with Conventional Commits → push → PR to
`develop` → merge → close Issue → delete branch.
For stable checkpoints: `develop` → PR → `main`.

---

## 4. Conventional Commits policy (going forward only)

```
<type>(<scope>): <description>
```

**Types:** `feat` · `fix` · `perf` · `refactor` · `test` · `docs` · `chore` · `ci`
**Scopes:** `dataset` · `training` · `evaluation` · `inference` · `api` · `proxy` ·
`deployment` · `embedded` · `research` · `docs`

Historical commits are **not** rewritten. The five most recent commits already follow a
descriptive style close to this convention:

```
a9f03e0  evaluation: define metrics for v4 clean baseline
37c1846  model: remove custom end token and use native eos
1bf412f  dataset: finalize leakage-free v4 clean baseline candidate
def0c92  training: complete E1 QLoRA compatibility port
434e834  research: establish E0 dataset integrity baseline and project decisions
```

Going forward add the `type(scope):` prefix, e.g. `feat(training): train v4 clean baseline`.

---

## 5. Milestones to create

GitHub UI → Issues → Milestones → New milestone.

| # | Title | Objective | Exit criteria |
|---|---|---|---|
| M1 | **V4 Clean Baseline** | First scientifically defensible AI classifier baseline | clean dataset frozen · V4 trained · E5 metrics collected · model-side latency measured · baseline report complete |
| M2 | **Quantized Deployment** | Prepare the trained model for efficient deployment | quantized model loads · security metrics compared vs V4 · performance tradeoff documented |
| M3 | **Inline Gateway** | Operational inline HTTP security gateway | client→gateway→server works · malicious blocked · benign passes · failure behaviour verified · end-to-end P50/P95/P99 measured |
| M4 | **Embedded Deployment** | Deploy and validate on embedded Linux hardware | physical prototype operates · processes inline traffic · performance and resource measurements recorded |
| M5 | **Research / Graduation Results** | Consolidate evidence for the graduation project | final experimental record · architecture and methodology documented · limitations stated · reproducibility information available |

M1 is largely complete already (7 of 10 items). M4 is a **core** requirement, not optional.

---

## 6. Labels to create

Check existing labels first and reuse equivalents rather than duplicating.

**Type:** `feature` · `bug` · `research` · `testing` · `performance` · `documentation`
**Priority:** `priority:critical` · `priority:high` · `priority:medium` · `priority:low`
**Status/scope:** `blocked` · `future-work` · `insufficient-data` · `embedded`

GitHub ships `bug` and `documentation` by default — reuse those two.

---

## 7. Issues

> ### ⚠️ SUPERSEDED 2026-08-17 — this section is retained for context only
>
> The backlog below (`C1`–`C7`, `N1`–`N21`) was the **first draft**. The approved structure is
> now **`H1`–`H4` historical · `N1`–`N20` current/upcoming · `F1`–`F5` future-work**, which
> consolidates the seven historical items into four and renumbers the rest.
>
> **The authoritative, ready-to-execute definition is `scripts/github_bootstrap.sh`.**
> It creates every label, milestone and issue, captures the real issue numbers as GitHub
> assigns them, and writes dependency references (`Depends on #N`) using those real numbers —
> nothing is invented. Run it after installing and authenticating `gh`:
>
> ```bash
> sudo apt install gh && gh auth login
> DRY_RUN=1 bash scripts/github_bootstrap.sh   # preview, changes nothing
> bash scripts/github_bootstrap.sh             # create
> ```
>
> Existing labels, milestones and issues are detected and reused, never duplicated or
> overwritten. Nothing is ever deleted.
>
> The material below remains accurate as *content* — the acceptance criteria and evidence
> references were carried into the script — but the identifiers and grouping are stale.

### 7.1 COMPLETED / HISTORICAL

> Each description must open with:
> *"This issue documents already-completed, verified work. It is created retrospectively for
> project traceability."*
> Create these, then immediately close them.

---

**C1 — Implement dataset integrity gate (E0)**
Milestone: M1 · Labels: `research`, `testing`, `priority:critical`
Evidence: commit `434e834` · `check_dataset.py` · `reports/e0_dataset_integrity_current.txt`

Build an analysis-only gate that measures duplication, train→eval leakage, envelope confounds
and trivial single-feature baselines, and blocks training on FAIL.

Acceptance criteria:
- [x] Gate computes all metrics from the dataset at run time (nothing hardcoded)
- [x] Reports PASS / WARNING / FAIL with evidence
- [x] Never mutates the dataset
- [x] Rule adopted: no training run starts while the gate reports FAIL
- [x] Run against the historical dataset — result FAIL, as expected

---

**C2 — Fix TRL/Transformers QLoRA compatibility (E1)**
Milestone: M1 · Labels: `bug`, `priority:critical`
Evidence: commit `def0c92` · `reports/e1_training_pipeline_smoke.txt`
Depends on: C1

`finetune.py` could not run on the installed stack (transformers 5.8.0 / TRL 1.4.0).

Acceptance criteria:
- [x] `TrainingArguments` → `SFTConfig`; `dataset_text_field`/`max_length` moved; `tokenizer=` → `processing_class=`
- [x] Smoke test passes: load → 4-bit NF4 → LoRA attach → train → eval → save → reload
- [x] NF4 + double-quant verified working on bitsandbytes 0.49.2
- [x] Precision decision recorded (D11: bf16, forced by a GradScaler/BFloat16 incompatibility)
- [x] Checkpoint retention bounded (D12: `save_total_limit=2`)
- [x] Training recipe otherwise unchanged

---

**C3 — Remove HTTP envelope label leakage (E2)**
Milestone: M1 · Labels: `bug`, `research`, `priority:critical`
Evidence: commit `1bf412f` · `reports/e2_e3_clean_dataset.txt`
Depends on: C1

A classifier reading only the `Host` header scored 93.72% — higher than the model. Six further
envelope features were independent shortcuts.

Acceptance criteria:
- [x] One shared envelope generator used by both classes
- [x] Shape matching: every attack shape has benign traffic in the same shape at matched volume
- [x] Method-stratified balancing
- [x] Payloads percent-encoded into the request-target
- [x] Causal exceptions documented (CSRF Origin/Referer, smuggling framing headers, HPP duplicates)
- [x] All incidental baselines within ~1 point of the 50% majority baseline

---

**C4 — Implement leakage-free grouped dataset split (E3)**
Milestone: M1 · Labels: `bug`, `research`, `priority:critical`
Evidence: commit `1bf412f` · `reports/e2_e3_clean_dataset.txt`
Depends on: C3 *(landed in the same commit as C3 and C5)*

26.65% of the eval split appeared verbatim in train.

Acceptance criteria:
- [x] Split by canonical group identity **before** rendering and augmentation
- [x] Canonical keys undo encoding/case/whitespace/comment obfuscation
- [x] Deterministic, order-independent hash-bucket assignment
- [x] Invariant asserted at build time: no group in both splits
- [x] Exact leakage 0.00%, duplicates 0.00%
- [x] Generation bit-identical across `PYTHONHASHSEED` values

---

**C5 — Add category contribution controls (D17/D18)**
Milestone: M1 · Labels: `research`, `priority:high`, `insufficient-data`
Evidence: commit `1bf412f` · `reports/e2_e3_cap_sensitivity.txt` · `reports/e2_e3_row_cap_sensitivity.txt`
Depends on: C4

Acceptance criteria:
- [x] Sensitivity analysis over logical-group caps and rendered-row caps
- [x] Final policy: source-agnostic, 2,500 logical groups + 4,000 rendered BLOCK rows per category
- [x] Row selection deterministic, source-stratified, breadth-first (100% group retention)
- [x] Scarce categories never upsampled, duplicated or fabricated
- [x] INSUFFICIENT DATA / NOT EVALUABLE statuses recorded in the manifest

---

**C6 — Remove custom END token and use native EOS (E4/D5)**
Milestone: M1 · Labels: `refactor`→`feature`, `priority:high`
Evidence: commit `37c1846` · `reports/e4_remove_end_token.txt`
Depends on: C2

The tokenizer resize made PEFT persist full `embed_tokens`/`lm_head` matrices, inflating the
E1 smoke adapter to ~298 MB for ~24 MiB of real LoRA tensors.

Acceptance criteria:
- [x] Token removed from all four pipeline files
- [x] Tokenizer no longer resized (vocab stays 32,000)
- [x] Saved adapter contains no `embed_tokens`/`lm_head` tensors
- [x] Inference parser byte-identical between `test_model.py` and `classifier_api.py`
- [x] Dataset regenerated; input-side hash byte-identical, E0 metrics unchanged
- [x] No latency improvement claimed (unmeasured hypothesis)

---

**C7 — Define V4 clean evaluation methodology (E5/D19)**
Milestone: M1 · Labels: `testing`, `research`, `priority:critical`
Evidence: commit `a9f03e0` · `reports/e5_evaluation_methodology.txt`
Depends on: C4

Acceptance criteria:
- [x] Three levels never combined into one headline number
- [x] BLOCK fixed as the positive class
- [x] Reason mismatch cannot reduce binary recall
- [x] FPR/FNR normalised over their own class populations
- [x] Invalid outputs never coerced; reported separately
- [x] D18 enforced via an evidence-status column
- [x] Legacy 135-case suite preserved as a diagnostic/regression suite
- [x] Latency scaffolding (P50/P95/P99) in place, scoped model-side only
- [x] `--mode self-test` passes with no model

---

### 7.2 CURRENT — M1

**N1 — Train V4 clean baseline** ← **NEXT ACTIVE WORK ITEM**
Milestone: M1 · Labels: `feature`, `priority:critical`
Depends on: C1–C7 · Branch: `feature/<N>-v4-clean-training`

Run the first training on the clean dataset. All prerequisites are closed: E0 passes with
WARNING only, the pipeline runs, the dataset is leakage-free with neutralised envelopes, the
token defect is fixed, and metrics are frozen.

Acceptance criteria:
- [ ] `finetune.py` points at `datasets/v4_clean/` (currently the historical root files)
- [ ] Output adapter path decided and recorded (`test_model.py --adapter` default is `model-output-v3`)
- [ ] E0 re-run immediately before training; confirmed no FAIL
- [ ] Full training completes; adapter saved and reloadable
- [ ] Adapter size recorded (expected ~24 MiB of LoRA tensors, no embedding matrices)
- [ ] Peak GPU memory and wall-clock recorded
- [ ] Training/eval loss curves retained as evidence
- [ ] No dataset or methodology changes made during the run

---

**N2 — Evaluate V4 clean security metrics**
Milestone: M1 · Labels: `testing`, `research`, `priority:critical`
Depends on: N1 · Branch: `test/<N>-v4-security-evaluation`

Acceptance criteria:
- [ ] `test_model.py --mode dataset` run on the full held-out split
- [ ] Level 1 reported: accuracy, precision, recall, F1, FPR, FNR, confusion matrix, invalid-output rate
- [ ] Level 2 reported: per-category support, binary recall num/den, reason accuracy num/den
- [ ] Every category carries an evidence status; Request Smuggling reported NOT EVALUABLE
- [ ] Legacy manual suite run separately as a diagnostic, clearly not the headline
- [ ] `--json` record archived under `reports/`
- [ ] No metric definitions changed after seeing results

---

**N3 — Benchmark V4 model inference latency**
Milestone: M1 · Labels: `performance`, `priority:high`
Depends on: N1 · Branch: `perf/<N>-v4-inference-benchmark`

Acceptance criteria:
- [ ] Latency collected per example during evaluation
- [ ] count, mean, P50, P95, P99, min, max, stdev reported
- [ ] Explicitly labelled model-side inference only
- [ ] Not compared against the D3 end-to-end P95 ≤ 200 ms budget
- [ ] Hardware and precision recorded

---

### 7.3 UPCOMING — M2 Quantized Deployment

| ID | Title | Labels | Branch |
|---|---|---|---|
| N4 | Merge LoRA adapter and export FP16 merged model | `feature`, `priority:high` | `feature/<N>-merge-lora-fp16` |
| N5 | Convert model to GGUF and quantize to Q4_K_M | `feature`, `priority:high` | `feature/<N>-gguf-q4km` |
| N6 | Integrate llama.cpp inference path | `feature`, `priority:high` | `feature/<N>-llamacpp-inference` |
| N7 | Validate security regression after quantization | `testing`, `research`, `priority:critical` | `test/<N>-quantized-security-regression` |
| N8 | Compare latency and memory: FP16 vs Q4_K_M | `performance`, `priority:high` | `perf/<N>-quantization-tradeoff` |

N7 must reuse the **frozen E5 methodology unchanged** so the comparison is valid. Do not assume
quantization is lossless — measure it.

### 7.4 UPCOMING — M3 Inline Gateway

| ID | Title | Labels | Branch |
|---|---|---|---|
| N9 | Integrate FastAPI classifier control plane | `feature`, `priority:high` | `feature/<N>-fastapi-control-plane` |
| N10 | Integrate mitmproxy inline data plane | `feature`, `priority:critical` | `feature/<N>-mitmproxy-data-plane` |
| N11 | Implement ALLOW/BLOCK enforcement and fail-closed behaviour | `feature`, `priority:critical` | `feature/<N>-fail-closed-enforcement` |
| N12 | Decompose latency: model / model+API / proxy / end-to-end | `performance`, `priority:high` | `perf/<N>-latency-decomposition` |
| N13 | Benchmark end-to-end gateway latency and throughput | `performance`, `priority:high` | `perf/<N>-e2e-gateway-benchmark` |

N11 implements **D4 (fail-closed)**. N13 is the first point at which the D3 P95 ≤ 200 ms target
becomes measurable.

### 7.5 UPCOMING — M4 Embedded Deployment (core requirement)

| ID | Title | Labels | Branch |
|---|---|---|---|
| N14 | Define embedded hardware requirements from measured data | `research`, `embedded`, `priority:high` | `docs/<N>-embedded-requirements` |
| N15 | Select embedded platform (Raspberry Pi vs Jetson) on evidence | `research`, `embedded`, `priority:high` | `docs/<N>-platform-selection` |
| N16 | Deploy gateway on embedded hardware | `feature`, `embedded`, `priority:critical` | `feature/<N>-embedded-deployment` |
| N17 | Benchmark embedded latency, throughput and resource usage | `performance`, `embedded`, `priority:high` | `perf/<N>-embedded-benchmark` |

Per **D10** the platform must be chosen from measured requirements, so N14/N15 precede N16.

### 7.6 M5 Research / Graduation Results

| ID | Title | Labels | Branch |
|---|---|---|---|
| N18 | Consolidate final architecture documentation | `documentation`, `priority:high` | `docs/<N>-final-architecture` |
| N19 | Produce experiment tables, charts and results summary | `documentation`, `research`, `priority:high` | `docs/<N>-results-summary` |
| N20 | Document limitations and reproducibility evidence | `documentation`, `research`, `priority:critical` | `docs/<N>-limitations-reproducibility` |
| N21 | Rewrite README to reflect the V4 clean baseline | `documentation`, `priority:medium` | `docs/<N>-readme-refresh` |

N21 is real outstanding work: `README.md`'s status block, attack-category table and
"Blocking — dataset validity" section still describe the **pre-E2/E3** dataset (93.72% Host
baseline, 26.65% leakage, FAIL gate). Only the `###END###` entries were corrected in E4.

### 7.7 FUTURE WORK — not core, label `future-work`

| ID | Title | Labels |
|---|---|---|
| F1 | Evaluate reserved CSIC anomalies (19,165 records, D2) | `future-work`, `research` |
| F2 | Compare against a conventional rule-based/WAF baseline (D9) | `future-work`, `research` |
| F3 | Extended held-out adversarial/evasion evaluation (D15) | `future-work`, `research`, `testing` |
| F4 | Stateful session-aware classification | `future-work`, `research` |
| F5 | Advanced SIEM telemetry integration | `future-work` |

These must not silently become current deliverables. F3 is blocked on the held-out transform
pool reserved in D15 (`double_url_encode`, `unicode_escape`, `html_entity`, `bash_ifs`,
`mixed_case_percent`, `param_fragmentation`), which generates nothing in the current dataset.

---

## 8. After Issues exist

`scripts/github_bootstrap.sh` prints the full `logical id → real issue number` map when it
finishes, and ends by printing the exact branch command with N1's real number substituted.

Once **N1 — Train V4 clean baseline** has a real number:

```bash
git checkout develop
git checkout -b feature/<N1-number>-v4-clean-training
```

Do not create the branch before the Issue number is known — the branch name must carry it.

### Dependency map (logical ids; substitute real numbers after creation)

```
H1 H2 H3 H4  (historical, closed)
      └──────► N1  Train V4 clean baseline
                ├──► N2  Evaluate V4 clean security metrics
                ├──► N3  Benchmark V4 model inference latency
                └──► N4  Merge LoRA and export GGUF        (also needs N2)
                          └──► N5  Quantize to Q4_K_M
                                └──► N6  Integrate llama.cpp inference
                                      ├──► N7  Compare quantized security   (N5+N6)
                                      ├──► N8  Benchmark quantized latency  (N5+N6)
                                      └──► N9  FastAPI control plane
                                            └──► N10 mitmproxy data plane
                                                  └──► N11 fail-closed enforcement
                                                        └──► N12 end-to-end gateway latency (N10+N11)

N8 + N12 ──► N13 embedded requirements
              └──► N14 platform selection
                    └──► N15 embedded deployment
                          └──► N16 embedded benchmark

N17–N20 (M5 documentation) have no hard blockers; N18/N19 are most useful after N16.
F1–F5 are future-work with no milestone and are not on the critical path.
```
