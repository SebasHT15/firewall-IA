#!/usr/bin/env bash
# firewall-IA — GitHub project bootstrap
#
# Creates the labels, milestones and issues for the course Git/GitHub workflow.
# Prepared 2026-08-17. Nothing here touches source code, commits or history.
#
# PREREQUISITES
#   sudo apt install gh          # or: https://cli.github.com
#   gh auth login                # interactive, run it yourself
#   cd ~/Desktop/firewall-IA
#
# RUN
#   bash scripts/github_bootstrap.sh            # create everything
#   DRY_RUN=1 bash scripts/github_bootstrap.sh  # print actions, change nothing
#
# SAFETY
#   * Creating an object that already exists is tolerated and reported, never
#     duplicated or overwritten.
#   * Nothing is ever deleted, closed (except the four historical issues, by
#     design) or modified.
#   * Issue numbers are captured as they are assigned, so dependency references
#     ("Depends on #N") use REAL numbers. No number is invented.

set -uo pipefail

REPO="SebasHT15/firewall-IA"
DRY_RUN="${DRY_RUN:-0}"

run() {
  if [ "$DRY_RUN" = "1" ]; then printf '  [dry-run] %s\n' "$*"; return 0; fi
  "$@"
}

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

# ── preflight ─────────────────────────────────────────────────────────────
command -v gh >/dev/null 2>&1 || { echo "FATAL: gh not installed."; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "FATAL: gh not authenticated. Run: gh auth login"; exit 1; }
echo "repo: $REPO"
gh repo view "$REPO" --json nameWithOwner,visibility -q '"identity: " + .nameWithOwner + " (" + .visibility + ")"' 2>/dev/null || true

# ══════════════════════════════════════════════════════════════════════════
# LABELS  — reuse GitHub defaults (bug, documentation) rather than duplicating
# ══════════════════════════════════════════════════════════════════════════
say "LABELS"
mklabel() { # name colour description
  if gh label list --repo "$REPO" --limit 200 --json name -q '.[].name' 2>/dev/null | grep -qx "$1"; then
    echo "  reuse   $1"
  else
    echo "  create  $1"
    run gh label create "$1" --repo "$REPO" --color "$2" --description "$3" >/dev/null 2>&1 \
      || echo "    (create failed or already existed)"
  fi
}
mklabel feature            "0e8a16" "New capability"
mklabel bug                "d73a4a" "Defect or incorrect behaviour"
mklabel research           "7057ff" "Investigation, experiment or analysis"
mklabel testing            "0052cc" "Tests, evaluation and verification"
mklabel performance        "fbca04" "Latency, throughput or resource work"
mklabel documentation      "0075ca" "Documentation and reports"
mklabel "priority:critical" "b60205" "Blocks the critical path"
mklabel "priority:high"     "d93f0b" "Important, schedule soon"
mklabel "priority:medium"   "fbca04" "Normal priority"
mklabel "priority:low"      "c2e0c6" "Nice to have"
mklabel blocked            "000000" "Blocked by a dependency"
mklabel future-work        "cfd3d7" "Explicitly out of core scope"
mklabel insufficient-data  "e99695" "Insufficient evidence to support a claim"
mklabel embedded           "5319e7" "Embedded Linux hardware target"

# ══════════════════════════════════════════════════════════════════════════
# MILESTONES
# ══════════════════════════════════════════════════════════════════════════
say "MILESTONES"
mkmilestone() { # title description
  local existing
  existing=$(gh api "repos/$REPO/milestones?state=all" --paginate -q ".[] | select(.title==\"$1\") | .number" 2>/dev/null | head -1)
  if [ -n "$existing" ]; then
    echo "  reuse   #$existing  $1"
  else
    echo "  create  $1"
    run gh api "repos/$REPO/milestones" -f title="$1" -f description="$2" >/dev/null 2>&1 \
      || echo "    (create failed)"
  fi
}
mkmilestone "M1 — V4 Clean Baseline" \
"Objective: produce the first scientifically defensible AI classifier baseline.
Includes dataset integrity work, the clean leakage-free V4 dataset, native EOS cleanup, the frozen evaluation methodology, V4 clean training, V4 security evaluation and the first model-side inference benchmark.
Exit criteria: V4 clean dataset remains frozen; trained V4 adapter exists; E5 security metrics collected; model-side P50/P95/P99 measured; baseline report completed."

mkmilestone "M2 — Quantized Deployment" \
"Objective: prepare the trained model for efficient deployment.
Includes LoRA merge, merged FP16 model, GGUF conversion, Q4_K_M quantization, llama.cpp inference, quantized security regression and latency/memory comparison.
Exit criteria: quantized model loads; security results compared with baseline; performance tradeoff documented."

mkmilestone "M3 — Inline Gateway" \
"Objective: turn the classifier into an operational inline HTTP security gateway.
Includes the FastAPI control plane, mitmproxy data plane, ALLOW/BLOCK enforcement, fail-closed behaviour, timeout/error handling, latency decomposition and the end-to-end benchmark.
Exit criteria: client to gateway to server path works; benign traffic passes; malicious traffic can be blocked; failure behaviour verified; end-to-end P50/P95/P99 measured."

mkmilestone "M4 — Embedded Deployment" \
"Objective: deploy and validate the gateway on physical embedded Linux hardware. CORE scope.
Includes hardware requirements, platform comparison and selection, model deployment, functional validation, latency and throughput, CPU/RAM/GPU usage and thermal/power observations where practical.
Exit criteria: physical embedded prototype works; inline traffic processing verified; resource and performance measurements recorded."

mkmilestone "M5 — Research / Graduation Results" \
"Objective: consolidate the final experimental evidence and project documentation.
Includes final architecture documentation, experimental tables, charts, security results, latency/resource results, limitations, reproducibility evidence and a README refresh.
Exit criteria: architecture and methodology documented; final results assembled; limitations explicit; reproduction information available."

# ══════════════════════════════════════════════════════════════════════════
# ISSUES
# ══════════════════════════════════════════════════════════════════════════
declare -A NUM   # logical id -> real issue number

mkissue() { # id title milestone labels body
  local id="$1" title="$2" ms="$3" labels="$4" body="$5" existing out n
  existing=$(gh issue list --repo "$REPO" --state all --limit 300 --search "\"$title\" in:title" \
             --json number,title -q ".[] | select(.title==\"$title\") | .number" 2>/dev/null | head -1)
  if [ -n "$existing" ]; then
    NUM[$id]="$existing"; echo "  reuse   #$existing  $title"; return 0
  fi
  if [ "$DRY_RUN" = "1" ]; then
    NUM[$id]="?"; echo "  [dry-run] create  $title  [$ms] {$labels}"; return 0
  fi
  out=$(gh issue create --repo "$REPO" --title "$title" --body "$body" \
        --milestone "$ms" $(echo "$labels" | tr ',' '\n' | sed 's/^/--label /' | tr '\n' ' ') 2>&1)
  n=$(echo "$out" | grep -oE '/issues/[0-9]+' | grep -oE '[0-9]+' | head -1)
  if [ -n "$n" ]; then NUM[$id]="$n"; echo "  create  #$n  $title"
  else NUM[$id]="?"; echo "  FAILED  $title"; echo "    $out"; fi
}

dep() { # prints "Depends on #a, #b" from logical ids
  local out=""
  for k in "$@"; do
    [ -n "${NUM[$k]:-}" ] && [ "${NUM[$k]}" != "?" ] && out="$out #${NUM[$k]},"
  done
  [ -n "$out" ] && echo "**Depends on:**${out%,}" || echo "**Depends on:** (see dependency map)"
}

HIST_NOTE="Historical tracking issue created after completion to document verified work completed before formal GitHub Issue tracking was introduced."

# ── HISTORICAL (created, then closed) ─────────────────────────────────────
say "HISTORICAL ISSUES"

mkissue H1 "Investigate and eliminate dataset label leakage" "M1 — V4 Clean Baseline" "bug,research" \
"$HIST_NOTE

## Problem
The dataset contained label-determining artifacts that made any accuracy figure uninterpretable. A classifier reading **only the \`Host\` header** — never the payload — scored **93.72%**, higher than the ~91% then attributed to the model. Six further envelope features were independent shortcuts. Separately, **26.65%** of the eval split appeared verbatim in train.

## What was done
- Built \`check_dataset.py\`, an analysis-only integrity gate (duplication, leakage, envelope confounds, trivial single-feature baselines) with a PASS/WARNING/FAIL verdict.
- Adopted the rule: no training run starts while the gate reports FAIL.
- Rebuilt generation around one shared HTTP envelope generator used by both classes, with shape matching so every attack shape has benign traffic in the same shape at matched volume.
- Added method-stratified balancing and percent-encoded payloads into the request-target.
- Split by canonical group identity **before** rendering and augmentation, so a payload and all its variants land in the same split.
- Added category contribution controls (2,500 logical groups + 4,000 rendered BLOCK rows per malicious category).

## Result
- Exact train→eval leakage **26.65% → 0.00%**; duplicates **→ 0.00%**.
- Strongest incidental baseline **93.72% → ~51%**, against a 50% majority baseline.
- Deterministic label reveals **9 → 0**.
- Generation is bit-identical across \`PYTHONHASHSEED\` values.

## Evidence
- Commits \`434e834\`, \`1bf412f\`
- \`reports/e0_dataset_integrity_current.txt\`
- \`reports/e0_dataset_integrity_v4_clean.txt\`
- \`reports/e2_e3_clean_dataset.txt\`
- \`reports/e2_e3_cap_sensitivity.txt\`, \`reports/e2_e3_row_cap_sensitivity.txt\`
- Decisions D1, D13–D18"

mkissue H2 "Restore QLoRA training pipeline compatibility" "M1 — V4 Clean Baseline" "bug,testing" \
"$HIST_NOTE

## Problem
\`finetune.py\` could not run at all on the installed stack (transformers 5.8.0 / TRL 1.4.0). \`SFTTrainer\` rejected \`dataset_text_field\`, \`max_seq_length\` and \`tokenizer\`.

## What was done
- Ported to \`SFTConfig\`; moved \`dataset_text_field\` and \`max_length\` onto the config; \`tokenizer=\` → \`processing_class=\`.
- Diagnosed a structural precision incompatibility: TRL 1.4 casts trainable LoRA params to bf16 for 4-bit models, and \`fp16=True\` routes through \`GradScaler\`, whose unscale kernel has no BFloat16 implementation. Adopted bf16 (D11).
- Bounded checkpoint retention (D12, \`save_total_limit=2\`) after measuring ~300 MB per checkpoint against a schedule that would produce ~49.
- Verified NF4 + double-quant working on bitsandbytes 0.49.2.

## Result
Smoke test PASS: load → 4-bit NF4 → LoRA attach (12,615,680 params, 308 tensors) → train → eval → save → reload. Training recipe otherwise unchanged.

## Evidence
- Commit \`def0c92\`
- \`reports/e1_training_pipeline_smoke.txt\`
- Decisions D11, D12"

mkissue H3 "Remove custom END token and use native EOS" "M1 — V4 Clean Baseline" "bug,research" \
"$HIST_NOTE

## Problem
The custom \`###END###\` token required a tokenizer resize, which made PEFT set \`save_embedding_layers=True\` automatically and persist the **full** \`embed_tokens\` and \`lm_head\` matrices into every checkpoint. The E1 smoke adapter totalled ~298 MB for ~24 MiB of real LoRA tensors — the balance being 131,076,096 params carrying no trained information, since the token was never configured as trainable. This materially harms the GGUF / embedded-deployment path.

## What was done
- Removed the token, the \`add_special_tokens\` call, the \`resize_token_embeddings\` calls, the custom \`end_token_id\` and the \`eos_token_id\` override across all four pipeline files.
- Verified native EOS: \`</s>\` is id 2 and was already present in every training sequence; TRL appends EOS only when the text does not already end with it.
- Regenerated the dataset with methodology completely unchanged.

## Result
- Tokenizer vocabulary stays 32,000; saved adapter contains **no** \`embed_tokens\`/\`lm_head\` tensors.
- Dataset input-side hash **byte-identical**; E0 report byte-identical apart from the recorded commit.
- Output contract unchanged: \`ALLOW | <reason>\` / \`BLOCK | <reason>\`.
- No latency improvement claimed — that remains an unmeasured hypothesis.

## Evidence
- Commit \`37c1846\`
- \`reports/e4_remove_end_token.txt\`
- Decision D5"

mkissue H4 "Define V4 clean evaluation methodology" "M1 — V4 Clean Baseline" "testing,research" \
"$HIST_NOTE

## Problem
The historical 91% was a single combined number measured on a suite where a degenerate always-BLOCK classifier scored 80.7%, with only 26 benign cases and 20-percentage-point per-category resolution. Metric definitions needed freezing **before** any V4 training run so they could not be chosen after seeing results.

## What was done
Froze a three-level methodology that is never collapsed into one headline number:
1. **Binary security decision** — BLOCK as the fixed positive class, full confusion matrix, precision/recall/F1, FPR normalised over the benign population and FNR over the attack population.
2. **Attack category/reason** — measured only over correctly-blocked attacks, so a reason mismatch can never reduce binary recall.
3. **Latency** — count/mean/P50/P95/P99/min/max/stdev, scoped model-side only and explicitly not comparable to the D3 end-to-end budget.

Also: invalid outputs are never coerced (counted as incorrect, reported separately, with a parseable-only view); D18 enforced via an \`evidence_status\` column; every percentage printed with numerator and denominator; the legacy 135-case suite preserved as a diagnostic/regression suite behind \`--mode manual\`.

## Result
\`test_model.py --mode self-test\` passes on controlled fixtures with no model required.

## Evidence
- Commit \`a9f03e0\`
- \`reports/e5_evaluation_methodology.txt\`
- Decisions D18, D19"

say "CLOSING HISTORICAL ISSUES"
for id in H1 H2 H3 H4; do
  n="${NUM[$id]:-}"
  if [ -n "$n" ] && [ "$n" != "?" ]; then
    echo "  close #$n"
    run gh issue close "$n" --repo "$REPO" \
      --comment "Closed on creation: this is a retrospective tracking issue for work already completed and verified." >/dev/null 2>&1 || true
  fi
done

# ── M1 CURRENT ────────────────────────────────────────────────────────────
say "CURRENT / UPCOMING ISSUES"

mkissue N1 "Train V4 clean baseline" "M1 — V4 Clean Baseline" "feature,research,priority:critical" \
"## Objective
Train the first scientifically interpretable model using the frozen V4-clean dataset and the frozen training recipe.

$(dep H1 H2 H3 H4)

## Context
All prerequisites are closed. E0 passes with WARNING only (category scarcity, zero blocking failures); the pipeline runs on transformers 5.8 / TRL 1.4; the dataset is leakage-free with neutralised envelopes; the custom stop token is removed; evaluation metrics are frozen.

Two configuration decisions are needed before launching:
- \`finetune.py\`'s \`TRAIN_FILE\`/\`EVAL_FILE\` still point at the historical root \`train.jsonl\`/\`eval.jsonl\`, not \`datasets/v4_clean/\`.
- \`test_model.py --adapter\` defaults to \`model-output-v3\`; the new adapter directory must be chosen and kept consistent.

## Acceptance criteria
- [ ] Training uses \`datasets/v4_clean/train.jsonl\`
- [ ] Evaluation uses \`datasets/v4_clean/eval.jsonl\`
- [ ] Manifest hashes verified against \`datasets/manifest_v4_clean.json\` before training
- [ ] Output written to a NEW V4-clean adapter directory (no existing directory overwritten)
- [ ] Frozen QLoRA hyperparameters preserved (r=16, alpha=32, dropout 0.05, NF4 + double-quant, paged_adamw_8bit, lr 2e-4 cosine, warmup 0.05, batch 4, accum 8, bf16 per D11, save_total_limit=2 per D12)
- [ ] Training completes without NaN or OOM
- [ ] Best checkpoint identified
- [ ] Adapter reload verified
- [ ] Adapter size recorded (expect ~24 MiB of LoRA tensors, no embedding matrices)
- [ ] Peak GPU memory and wall-clock recorded
- [ ] Training report written to \`reports/\`
- [ ] No dataset or methodology change made during the run

## Recommended branch
\`feature/<this-issue-number>-v4-clean-training\`"

mkissue N2 "Evaluate V4 clean security metrics" "M1 — V4 Clean Baseline" "testing,research,priority:critical" \
"## Objective
Evaluate the trained V4 model using the frozen E5 methodology, without altering any metric definition.

$(dep N1)

## Acceptance criteria
- [ ] Primary evaluation uses the \`datasets/v4_clean\` eval split
- [ ] Binary metrics recorded: accuracy, precision, recall, F1, attack detection rate, confusion matrix
- [ ] FPR and FNR recorded, each normalised over its own class population
- [ ] Invalid-output rate recorded, with the parseable-only view alongside
- [ ] Per-category metrics recorded with numerator/denominator for every percentage
- [ ] D18 evidence status enforced on every category
- [ ] Request Smuggling reported NOT EVALUABLE (zero eval rows) — no samples moved to make it evaluable
- [ ] Legacy manual suite run separately and clearly not presented as the headline
- [ ] \`--json\` record archived under \`reports/\`
- [ ] No metric definitions changed after seeing results

## Recommended branch
\`test/<this-issue-number>-v4-security-evaluation\`"

mkissue N3 "Benchmark V4 model inference latency" "M1 — V4 Clean Baseline" "performance,priority:high" \
"## Objective
Establish the first real model-side latency baseline.

$(dep N1)

## Acceptance criteria
- [ ] mean, P50, P95, P99, min, max and standard deviation reported
- [ ] Scope explicitly marked model-side inference only
- [ ] Peak memory recorded if practical
- [ ] Hardware and precision recorded
- [ ] No claim that model latency equals end-to-end gateway latency; the D3 P95 <= 200 ms target is an end-to-end budget and is not evaluated here

## Recommended branch
\`perf/<this-issue-number>-v4-inference-benchmark\`"

# ── M2 ────────────────────────────────────────────────────────────────────
mkissue N4 "Merge LoRA and export GGUF model" "M2 — Quantized Deployment" "feature,priority:high" \
"## Objective
Merge the LoRA adapter into the base model and export GGUF for llama.cpp.

$(dep N1 N2)

## Acceptance criteria
- [ ] LoRA merged successfully
- [ ] Merged FP16 model validated (loads, produces the expected output contract)
- [ ] GGUF exported
- [ ] Conversion procedure documented reproducibly, including exact tool versions and flags
- [ ] Original adapter preserved unmodified

## Note
Verify llama.cpp conversion flags against current upstream documentation rather than from memory; the CLI surface changes frequently.

## Recommended branch
\`feature/<this-issue-number>-gguf-export\`"

mkissue N5 "Quantize model to Q4_K_M" "M2 — Quantized Deployment" "performance,feature,priority:high" \
"## Objective
Produce the Q4_K_M quantized artifact.

$(dep N4)

## Acceptance criteria
- [ ] Q4_K_M artifact generated
- [ ] Model loads with llama.cpp-compatible tooling
- [ ] Artifact size documented
- [ ] No baseline artifact overwritten

## Recommended branch
\`perf/<this-issue-number>-q4km-quantization\`"

mkissue N6 "Integrate llama.cpp inference" "M2 — Quantized Deployment" "feature,priority:high" \
"## Objective
Run the V4 model through llama.cpp and confirm the decision contract survives.

$(dep N5)

## Acceptance criteria
- [ ] V4 model runs through llama.cpp
- [ ] Output contract preserved: \`ALLOW | <reason>\` / \`BLOCK | <reason>\`
- [ ] Decision parsing verified against the frozen E5 parser
- [ ] Native EOS termination confirmed working in this runtime
- [ ] Reproducible command and configuration documented

## Recommended branch
\`feature/<this-issue-number>-llamacpp-inference\`"

mkissue N7 "Compare quantized security performance" "M2 — Quantized Deployment" "testing,research,priority:high" \
"## Objective
Quantify the security cost of quantization. Do not assume it is harmless.

$(dep N5 N6)

## Acceptance criteria
- [ ] Same eval dataset used as the V4 baseline
- [ ] Same frozen E5 metrics used, unchanged
- [ ] Security regression vs the HF/LoRA baseline reported per level (binary, category)
- [ ] Per-category deltas reported with support counts
- [ ] No post-hoc metric changes

## Recommended branch
\`test/<this-issue-number>-quantized-security-regression\`"

mkissue N8 "Benchmark quantized latency and memory" "M2 — Quantized Deployment" "performance,priority:high" \
"## Objective
Measure the performance side of the quantization tradeoff.

$(dep N5 N6)

## Acceptance criteria
- [ ] P50/P95/P99 latency
- [ ] Memory use
- [ ] Model size on disk
- [ ] Direct comparison against the HF baseline from the V4 inference benchmark
- [ ] Scope stated (model-side)

## Recommended branch
\`perf/<this-issue-number>-quantized-benchmark\`"

# ── M3 ────────────────────────────────────────────────────────────────────
mkissue N9 "Integrate FastAPI control plane" "M3 — Inline Gateway" "feature,priority:high" \
"## Objective
Bring \`classifier_api.py\` into service as the control plane. It has been written but never executed, because no adapter existed.

$(dep N6)

## Acceptance criteria
- [ ] Classifier endpoint works end to end
- [ ] Output contract enforced
- [ ] Invalid model responses handled explicitly, not silently coerced
- [ ] Inference backend configurable (HF adapter vs llama.cpp)
- [ ] Basic API test passes
- [ ] Generation/parsing behaviour stays equivalent to \`test_model.py\`

## Out of scope here
Auth, telemetry, SIEM integration.

## Recommended branch
\`feature/<this-issue-number>-fastapi-control-plane\`"

mkissue N10 "Integrate mitmproxy inline data plane" "M3 — Inline Gateway" "feature,priority:critical" \
"## Objective
Add the inline HTTP interception data plane in front of the control plane.

$(dep N9)

## Context
This is authorized inline interception by a legitimate security gateway, not a man-in-the-middle attack. Keep that distinction in the architecture documentation.

## Acceptance criteria
- [ ] HTTP request interception works
- [ ] Request forwarded to the classifier
- [ ] ALLOW traffic passes through to the destination
- [ ] BLOCK traffic is prevented from reaching the destination
- [ ] Architecture documented (data plane vs control plane)
- [ ] mitmproxy addon API verified against the installed version

## Recommended branch
\`feature/<this-issue-number>-mitmproxy-data-plane\`"

mkissue N11 "Implement fail-closed enforcement" "M3 — Inline Gateway" "feature,testing,priority:critical" \
"## Objective
Implement and verify D4: if the classifier times out, crashes, becomes unavailable or returns an invalid decision, traffic is BLOCKED by default.

$(dep N10)

## Acceptance criteria
- [ ] Classifier timeout blocks
- [ ] Classifier crash/error blocks
- [ ] Invalid response blocks
- [ ] Each failure mode tested explicitly, not assumed
- [ ] Timeout value chosen and justified against the D3 latency budget
- [ ] Behaviour documented as a security property

## Note
The fallback mechanism (proxy or simpler local mechanism temporarily taking over) is explicitly out of current scope per D4.

## Recommended branch
\`feature/<this-issue-number>-fail-closed\`"

mkissue N12 "Benchmark end-to-end gateway latency" "M3 — Inline Gateway" "performance,priority:critical" \
"## Objective
First measurement against the D3 target: end-to-end added latency P95 <= 200 ms.

$(dep N10 N11)

## Acceptance criteria
- [ ] Baseline path measured (no gateway)
- [ ] Gateway path measured
- [ ] Added latency computed as the difference
- [ ] P50/P95/P99 reported, never average alone
- [ ] Model / model+API / proxy overhead separated where practical
- [ ] Throughput and requests-per-second recorded
- [ ] D3 target evaluated correctly — against END-TO-END added latency, not model-side

## Recommended branch
\`perf/<this-issue-number>-gateway-latency\`"

# ── M4 ────────────────────────────────────────────────────────────────────
mkissue N13 "Define embedded hardware requirements" "M4 — Embedded Deployment" "research,embedded,priority:high" \
"## Objective
Derive hardware requirements from measured data, so platform selection is evidence-based rather than a preference (D10).

$(dep N8 N12)

## Acceptance criteria
- [ ] CPU requirements
- [ ] RAM requirements
- [ ] Storage requirements including model footprint
- [ ] Inference runtime support
- [ ] Latency needs derived from the D3 budget
- [ ] Throughput needs
- [ ] Power and thermal considerations
- [ ] Comparison criteria documented before any platform is named

## Recommended branch
\`docs/<this-issue-number>-embedded-requirements\`"

mkissue N14 "Select embedded deployment platform" "M4 — Embedded Deployment" "research,embedded,priority:high" \
"## Objective
Choose the deployment platform from the measured requirements. Per D10 the platform must not be chosen prematurely.

$(dep N13)

## Acceptance criteria
- [ ] Candidates compared against the measured requirements
- [ ] Raspberry Pi and NVIDIA Jetson considered where applicable
- [ ] Selection justified with evidence, not preference
- [ ] Decision recorded in \`DECISIONS.md\`

## Recommended branch
\`docs/<this-issue-number>-embedded-platform-selection\`"

mkissue N15 "Deploy gateway on embedded hardware" "M4 — Embedded Deployment" "feature,embedded,priority:critical" \
"## Objective
Physical embedded deployment. This is CORE project scope, not optional.

$(dep N14)

## Acceptance criteria
- [ ] Model runs on the physical device
- [ ] Gateway runs on the physical device
- [ ] Inline traffic flows through the device
- [ ] ALLOW/BLOCK functionality verified on hardware
- [ ] Deployment procedure documented reproducibly

## Recommended branch
\`feature/<this-issue-number>-embedded-deployment\`"

mkissue N16 "Benchmark embedded performance" "M4 — Embedded Deployment" "performance,embedded,priority:critical" \
"## Objective
Measure real operational viability on the embedded target.

$(dep N15)

## Acceptance criteria
- [ ] P50/P95/P99 latency
- [ ] Throughput
- [ ] CPU utilisation
- [ ] RAM utilisation
- [ ] GPU utilisation where applicable
- [ ] Thermal and power observations where practical
- [ ] Sustained stability test
- [ ] Comparison against the laptop-class baseline

## Recommended branch
\`perf/<this-issue-number>-embedded-benchmark\`"

# ── M5 ────────────────────────────────────────────────────────────────────
mkissue N17 "Consolidate final architecture documentation" "M5 — Research / Graduation Results" "documentation,priority:medium" \
"## Objective
Produce the final architecture documentation for the graduation project.

## Acceptance criteria
- [ ] Data plane / control plane architecture documented
- [ ] Project identity stated precisely: an inline AI-powered application-layer HTTP security gateway, stateless at the request level, not a conventional stateful network firewall
- [ ] Authorized inline interception distinguished from MITM
- [ ] Decision log summarised
- [ ] Diagrams where they help

## Recommended branch
\`docs/<this-issue-number>-architecture\`"

mkissue N18 "Consolidate final experimental results" "M5 — Research / Graduation Results" "research,documentation,priority:high" \
"## Objective
Assemble the complete experimental record.

## Acceptance criteria
- [ ] Experiment tables (E0 through the final benchmarks)
- [ ] Charts for security and performance results
- [ ] Security results with per-category evidence status
- [ ] Latency and resource results at every stage
- [ ] Every claim traceable to a report in \`reports/\`
- [ ] No unsupported comparative claims

## Recommended branch
\`docs/<this-issue-number>-results\`"

mkissue N19 "Document limitations and reproducibility" "M5 — Research / Graduation Results" "documentation,research,priority:high" \
"## Objective
State the limitations explicitly and make the work reproducible.

## Acceptance criteria
- [ ] Dataset limitations stated (category scarcity, NOT EVALUABLE categories, synthetic benign traffic, CSIC label circularity)
- [ ] Evaluation limitations stated (strict reason matching, no confidence intervals, evasion resistance unmeasured)
- [ ] Reproducibility information complete: seeds, PayloadsAllTheThings commit, manifest hashes, package versions
- [ ] Deferred and future work clearly separated from delivered work

## Recommended branch
\`docs/<this-issue-number>-limitations-reproducibility\`"

mkissue N20 "Refresh project README" "M5 — Research / Graduation Results" "documentation,priority:medium" \
"## Objective
Update README so it reflects the V4-clean architecture and current project state instead of the historical pre-E2/E3 description.

## Context
This is real outstanding work. README's status block, attack-category table and 'Blocking — dataset validity' section still describe the pre-E2/E3 dataset: a 93.72% Host baseline, 26.65% leakage and a FAIL gate. Only the \`###END###\` entries were corrected during E4.

## Acceptance criteria
- [ ] Status block reflects the current dataset and gate result
- [ ] Attack-category table regenerated from the current manifest
- [ ] Resolved limitations moved to history rather than presented as current
- [ ] Badges accurate
- [ ] Quickstart commands verified to work

## Recommended branch
\`docs/<this-issue-number>-readme-refresh\`"

# ── FUTURE WORK (no milestone) ────────────────────────────────────────────
say "FUTURE-WORK ISSUES (no milestone by design)"

mkfuture() { # id title body
  local existing out n
  existing=$(gh issue list --repo "$REPO" --state all --limit 300 --search "\"$2\" in:title" \
             --json number,title -q ".[] | select(.title==\"$2\") | .number" 2>/dev/null | head -1)
  if [ -n "$existing" ]; then NUM[$1]="$existing"; echo "  reuse   #$existing  $2"; return 0; fi
  if [ "$DRY_RUN" = "1" ]; then NUM[$1]="?"; echo "  [dry-run] create  $2  {future-work,research}"; return 0; fi
  out=$(gh issue create --repo "$REPO" --title "$2" --body "$3" --label future-work --label research 2>&1)
  n=$(echo "$out" | grep -oE '/issues/[0-9]+' | grep -oE '[0-9]+' | head -1)
  if [ -n "$n" ]; then NUM[$1]="$n"; echo "  create  #$n  $2"; else echo "  FAILED  $2"; echo "    $out"; fi
}

mkfuture F1 "Evaluate reserved CSIC anomaly set" \
"**FUTURE WORK — not on the critical path. Must not silently become a current deliverable.**

Per D2, 19,165 CSIC anomalous records are excluded from the clean baseline because the 11-rule keyword categorizer could not classify them. They are preserved, not relabelled, and remain identifiable.

**Research question:** can the AI classifier detect anomalous traffic that the keyword categorizer could not classify?

This is the portion of CSIC where an AI classifier could plausibly show an advantage over a regex, which is what makes it interesting."

mkfuture F2 "Compare against conventional WAF/rule baseline" \
"**FUTURE WORK — optional per D9. Not a mandatory success criterion.**

Blocked by a methodological problem that must be solved first (audit F6): CSIC BLOCK labels are assigned by an 11-rule keyword heuristic, so a rule-based baseline would score near-100% on that subset **by construction**, making the comparison circular.

If required later, it must use an independent, documented, versioned ruleset (e.g. OWASP CRS) and evaluate on data not labelled by a keyword matcher. Verify current versions, licensing and packaging before starting — do not cite from memory."

mkfuture F3 "Extended held-out adversarial/evasion evaluation" \
"**FUTURE WORK — after the clean baseline exists.**

The current adversarial cases are NOT evidence of evasion resistance: their transform families overlap the training-pool transforms used for augmentation, so they measure learned transforms rather than evasion.

Per D15 a held-out pool is already reserved and generates nothing in the current dataset: \`double_url_encode\`, \`unicode_escape\`, \`html_entity\`, \`bash_ifs\`, \`mixed_case_percent\`, \`param_fragmentation\`.

A real evaluation must distinguish seen transform families, held-out transform families, and held-out base payload identities, and must report detection rate, FN, FP and latency per family. Use controlled laboratory traffic only."

mkfuture F4 "Stateful/session-aware classification" \
"**FUTURE WORK — explicitly out of core scope.**

The current classifier is stateless at the application-request level: each request is classified independently. Being inline does not make it stateful.

A stateful extension could use previous requests, session information, cookies, authentication state, request frequency and behavioural history. It should only be considered after the stateless baseline is scientifically evaluated, and would enable a stateless-vs-stateful comparison."

mkfuture F5 "Advanced SIEM telemetry integration" \
"**FUTURE WORK — not core scope.**

Structured security telemetry: timestamp, request ID, HTTP method, endpoint metadata, decision, attack category, model version, inference latency, total latency.

Design constraint to respect from the start: do not log attacker-controlled payloads verbatim. Consider integration with SIEM, security monitoring, incident response and detection engineering workflows."

# ── SUMMARY ───────────────────────────────────────────────────────────────
say "SUMMARY — logical id -> real issue number"
for id in H1 H2 H3 H4 N1 N2 N3 N4 N5 N6 N7 N8 N9 N10 N11 N12 N13 N14 N15 N16 N17 N18 N19 N20 F1 F2 F3 F4 F5; do
  printf '  %-4s #%s\n' "$id" "${NUM[$id]:-not-created}"
done

say "NEXT"
echo "  The next active issue is N1 (Train V4 clean baseline) = #${NUM[N1]:-?}"
echo "  Create its branch with:"
echo "      git checkout develop && git checkout -b feature/${NUM[N1]:-N}-v4-clean-training"
