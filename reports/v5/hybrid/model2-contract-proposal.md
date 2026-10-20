# Model 2 (Small Decision Model) — contract proposal `model2-contract/v2` (BLOCK | DEFER)

**Status:** PROPOSED design only (2026-10-20). **Versioned proposal; integration does not ratify the operating policy.** Supersedes the earlier
ALLOW/BLOCK/UNCERTAIN draft (`model2-contract/v1`, written in the coordinator's checkout), which is withdrawn.
Nothing is approved, trained, implemented or enforced; no weights, no operating thresholds, no enforcement path.
FINAL V5 training stays **BLOCKED**. Companion: `fast-path-contract.md` (same directory).

## 0. Corrected architecture and what changes

```
validated canonical request → Fast Path (FAST_ALLOW | CONTINUE)
   → Analyzer: C1 (deterministic evidence) + optional C2 (learned evidence) — evidence only
   → Model 2 (BLOCK | DEFER)
   → V5 (ALLOW | BLOCK)                         [V4 stays the only enforcement decision during SHADOW]
```
- **Model 2 has no ALLOW output.** ALLOW comes only from the Fast Path (FAST_ALLOW) or from V5.
- Existing `hybrid_contracts.DecisionOutput` / `DECISIONS = (ALLOW, BLOCK, UNCERTAIN)` (D43 placeholder, no producer or
  consumer) **must not be used for Model 2**: it can express ALLOW. Model 2 gets its own output type; the old one is a
  placeholder to retire by decision (owner decision 1). `AnalyzerOutput` (D50), `RequestFeatures v2`, `canonical-request/v1`
  and the V5 strict parser are reused unchanged.
- **C1 is deterministic feature/evidence extraction. C2 is an optional learned analyzer.** The existing trained attack score and auxiliary category outputs both belong to the learned component. They are not the definitions of C1 and C2. Category outputs may be ablated separately within C2.


Verified facts: the frozen Analyzer (`hybrid-analyzer-v2`) runs only in the research env; where Models 1–2 run is open
(D52); its External v1 aggregate was over-confident (ECE 0.126) and its category head did not transfer (top-1 74/200);
a stage that BLOCKs without V4/V5 is **not decided** (D43; D29 forbids a heuristic BLOCK). A Model 2 BLOCK is exactly
that kind of early, final block, so it is a **new enforcement authority that this document does not grant.**

## 1. Input evidence and availability

| Slot | Source | Rule |
|---|---|---|
| `request_features` (C1) | deterministic `RequestFeatures v2` | pinned schema and input representation; serving/training alignment required |
| `analysis_c2` | Optional learned `AnalyzerOutput`, including `attack` | validated by D50; pinned `analyzer_version`; absent C2 is supported |
| `category_signals` | Optional auxiliary outputs within C2 | all present (sum 1 ± 1e-6) or all absent; separate value assessment |
| `canonical_outcome` | `canonical-request/v1` | Model 2 is invoked only on ACCEPT |
| `population_tag` | Fast Path result (`CONTINUE`) | metadata for evaluation and logs; **not a model feature** |

Each slot has an evidence state: `PRESENT`, `MISSING`, `INVALID`, `UNAVAILABLE` (+ closed reason code).
Not inputs in v2 (changing any needs a new input contract): `Host`/`User-Agent` or derivatives (D44/D57); other headers;
unapproved extra signals (D57 restrictions still apply); the Fast Path reasons; V4's or V5's decision; the
raw text; External v1 cases. D1 and canonical inputs must not be assumed feature-identical. Before reusing frozen learned weights on a new representation, test compatibility and any material differences; the current shadow keeps the frozen D1 feature path.

## 2. Output semantics and validation

```
Model2Output: decision ∈ {BLOCK, DEFER}, reason_code ∈ closed enum, p_block ∈ [0,1] (derived, not invented)
Model2Result: status ∈ {OK, EVIDENCE_MISSING, EVIDENCE_INVALID, EVIDENCE_UNAVAILABLE, MODEL_UNAVAILABLE,
              POLICY_UNAVAILABLE, MODEL_OUTPUT_INVALID, TIMEOUT}; output present iff status == OK;
              + model_id/sha256, policy_sha256, analyzer_version, feature_schema_version, evidence states, elapsed_ms
```
- `BLOCK` means "the evidence is sufficient to block early, without asking V5". `DEFER` means "no early block; V5
  decides". There is no third value and no way to say ALLOW or "uncertain".
- `p_block = P̂(BLOCK | evidence)` is the model's own posterior; the decision is `BLOCK` iff `p_block` reaches the
  policy's block level, else `DEFER`. There is **one** level, no ALLOW band. The level lives in a hashed
  `model2_policy.json` (`PROPOSED`/`APPROVED` with approver, date, decision reference — the D66 pattern); no value is proposed.
  Because the BLOCK is final and unreviewed, the default is DEFER: anything not clearing the level, and every non-OK status,
  is DEFER-equivalent.
- Validation (pure functions): versions → Analyzer signals (finite, no bool, [0,1], complete category set, sum 1) →
  feature fields present, typed, finite → raw posterior finite and in [0,1] → policy schema (finite numbers, status
  APPROVED outside tests) → construct the output. Non-finite or invalid values are rejected, never clamped. A policy or
  model artifact that is unpinned or fails its SHA-256 yields `*_UNAVAILABLE`. No free text from the model reaches a log or a response.

## 3. Delegation (DEFER → V5)
DEFER and every non-OK status route the request to the semantic fallback (V5; V4 is today's only implementation of "the
model that decides"). Model 2 never selects the fallback and never reads its answer. The fallback receives its own input
(V5: the canonical text) — not Model 2's output, so it cannot be anchored. Latency cost of delegation (D36, P95 ≤ 200 ms
pipeline objective, not met by V4: 269.58 ms) makes the **DEFER rate** a first-class reported metric.

## 4. Missing, invalid or unavailable evidence (fail-closed layering)
Model 2 failing must never make the gateway less safe than today: no ALLOW can originate in Model 2, so the failure
mode is simply "no early block ⇒ DEFER ⇒ V5"; if V5 is also unusable the existing D4/D34 fail-closed applies (403/503).
Plumbing exceptions become a status; in SHADOW they are swallowed exactly like the feature extractor's (D43).
Artifacts load only after SHA-256 verification (the frozen Analyzer is a pickle; an unpinned pickle in the gateway is out of contract).

## 5. SHADOW relationship to V4
V4 remains the sole enforcement. Model 2 runs after V4's verdict, observed only, behind a default-off switch (proposed
`data_plane.shadow_model2`), with the D43 A/B equivalence evidence and a bounded-time guarantee (value from measurement).
The log pairs Model 2's output with V4's decision for analysis; V4's decision is never an input, and **agreement with V4
is not ground truth** (§7).

## 6. C2: optional, must demonstrate incremental value
Model 2 must work with C2 absent. C2 is admitted only if a **preregistered paired ablation** (C1-only vs C1+C2, identical
data, fitting protocol and selection rule) shows, on VALIDATION, a paired group-bootstrap 95% interval for the primary
metric difference entirely on the favourable side, with no worse calibration (D55 log-loss guard). The primary metric is
the owner's (§9); candidates: early-block false positives at a fixed share of attacks blocked early. Known prior: the
category head is weak outside its development data (ssrf F1 ≈ 0.25; External top-1 74/200), so category-head usefulness must be assessed separately from the attack score. No ablation result is presumed. C1 is the deterministic baseline; existing path-feature ablation requirements remain applicable.

## 7. Evaluation population and false positives of early blocking
- **Population = traffic that reaches Model 2 after the Fast Path**, not raw traffic. Evaluation uses the Fast Path's
  `CONTINUE` set. While the Fast Path is ineligible (today: always), the reached population is all traffic, and reports
  say so; results are never transferred to a later Fast-Path-filtered population without re-evaluation, because the
  Fast Path removes exactly the easy benign traffic and changes the benign mix Model 2 sees.
- **Early-block false positive** = Model 2 `BLOCK` on a request whose independent reference label is benign. It is a final
  block with no second opinion, so it is the headline risk, reported as numerator/denominator/set name (D42), with Wilson
  and group-bootstrap (by `payload_family_id`/pair, D60) intervals, per benign class (the known V4 weak classes:
  api-json, unseen-structure, apostrophe/symbol names) and per Fast-Path residual class.
- Also reported: BLOCK precision and recall on the reached population, DEFER rate, joint V4 × Model 2 and V5 × Model 2
  confusion, latency.
- **Ground truth is not V4 agreement.** Reference labels must retain distinct evidence provenance: constructive-generation
  records and paired cases (D59/D60), AI-audited labels under D67/r4, and any independently established labels.
  AI consensus and adjudication alone do not establish independent ground truth or VERIFIED; report these groups separately. V4/V5 outputs are a triage signal; a hypothetical Model 2 BLOCK
  on a V4-ALLOW request enters a preregistered sample for independent adjudication, it is not auto-labelled by V4.
- Both Analyzer components and Model 2 are subject to this rule: "agrees with V4" is never a performance claim.

## 8. Training and protected data
Training is **not startable**: V4-clean rows carry in-sample Analyzer outputs (stacking leakage; INTERNAL TEST read twice);
the V5 dataset has no real split, R3 has not run, FINAL is blocked. Prerequisites: out-of-sample Analyzer outputs; the D54
contamination flags (canonical request, feature vector, generator family) because V4 and V5 pin the **same PATT revision**
(`e961fef…`); delegation behaviour fitted/selected on VALIDATION only (V5 outputs on V5 TRAIN are in-sample); a
preregistration before any fit (families, feature subset, selection rule, D55 calibration rule, metrics, owner targets);
D31 latency instrument. Never read by any Model 2 path: V5 INTERNAL_TEST (single-run guard, D60), E6_RESERVE, STAB-HELD,
External v1 individual cases (D40/D53), External v2 until frozen, the Analyzer's INTERNAL TEST, and development sets as
evidence. A joint cascade evaluation is **one** preregistered run. External claims need External v2.

## 9. Implement now vs. needs a trained model
| Now (no trained model; stdlib; nothing enforced) | Needs a trained, validated model |
|---|---|
| `Model2Output/Result`, closed enums, evidence states, validators + tests | model family, weights, feature subset |
| policy-file schema validator; hash-pinned loader | the block level (single threshold) and its calibration |
| `NoModelDecider` (always `MODEL_UNAVAILABLE`) proving DEFER-equivalent plumbing | BLOCK/DEFER behaviour, DEFER rate |
| shadow wiring behind a default-off switch + D43-style equivalence harness | shadow findings, early-block FP estimate |
| protected-role loader, contamination-flag tool, access log (+ tests) | any evaluation result, C2 verdict |
| D1-vs-canonical feature-equality test | an enforcement path (needs a new decision) |

## 10. Owner decisions
1. Retire `DecisionOutput`/`DECISIONS` (ALLOW/UNCERTAIN) as Model 2's contract in favour of `Model2Output` (BLOCK|DEFER).
2. Ratify the exact C1 feature contract and the proposed admission rule for optional learned C2 evidence, including a separate category-head ablation.
3. Whether Model 2 may ever issue a **final** BLOCK without V5 (the D29/D43 open question) — required before any routed mode; this document grants nothing.
4. Ratify the proposed isolated-process shadow runtime (D52); implementation is disabled by default.
5. Keep V4 decisions and Fast Path reasons outside learned inputs; review any additional deterministic signals individually against the input and leakage contracts.
6. Contaminated rows: exclude from fitting or report as slices.
7. Evaluation protection: one joint cascade run on V5 INTERNAL TEST, or a separate Model 2 hold-out; External v2 only.
8. Early-block FP tolerance, DEFER-rate/latency cap and the primary metric for §6 — fixed before training.
9. Who approves `model2_policy.json`; where artifacts live (gitignored, hashes versioned, D55).

## 11. Bounded sequence
**A. Now (after decisions 1–2, 4–5):** contract module + validators + `NoModelDecider` + tests; protected-role loader and
contamination tool; `AnalyzerProvider` (default `UNAVAILABLE`) and the shadow harness with its equivalence report;
preregistration template without numbers. **B. Only with a trained, preregistered model and decisions 3, 6–9:** fit →
select on VALIDATION → calibrate (D55) → freeze/hash → approve policy → shadow-evaluate → one preregistered cascade run →
External v2 for external claims → a separate decision for any routed or enforcing mode (not authorized here).
