# D2 — Decision Model: routing-dataset specification v2 and the DecisionOutput-vs-D50 conflict

**SPEC ONLY: not a decision, not a result.** Nothing was implemented, run, measured or changed.
This note refines note D (`D_decision_model_shadow_schema.md`, "note D") and does not replace it.
Every policy choice is an **owner decision not yet taken**. Statements are tagged **FACT** (checked in
a repository file named in the text), **HYPOTHESIS** (reasoned, not checked) or **UNVERIFIED**
(external claim not re-checked against a primary source).

| | |
|---|---|
| Date | 2026-10-06 |
| Branch | `research/v5-minimal-pairs-v2` (read-only) |
| Read | note D (all) · `data_plane/hybrid_contracts.py` · `DECISIONS.md` D29, D43, D44, D45, D50, D55 · `tests/test_request_features.py` (`TestContracts`) · `docs/technical_reference.md`, `CONTEXT.md`, `README.md` (grep of "UNCERTAIN") · `reports/hybrid/v4-analyzer-disagreement-v1/README.md` · `reports/hybrid/analyzer-external-v1-run-001/README.md` (aggregates only) · `reports/v5/minimal-pair-probe-v1/README.md` |
| Not read / not opened | External Test v1 cases, V4 eval rows, any case file of #57 / #60 |
| Terminology (D45) | "V5" = the next verdict **model**. The Decision Model (DM) is a Hybrid Architecture stage, never "V5". Today the verdict model is V4; "V5 verdict" below means "the verdict model's verdict" |

**Target (from the task, consistent with note D):** REQUEST → Fast Path (D29, FAST ALLOW only) →
Analyzer (evidence) → **DM: BLOCK or DEFER** → verdict model (ALLOW / BLOCK) → enforcement (D34).
The DM never outputs ALLOW. Ground truth must be independent of the verdict model.

---

## 1. Refined routing-dataset spec: what a future capture must contain

### 1.1 Role vocabulary (stricter than note D's "DM-in" column)

| Role | Meaning | May a DM model read it? |
|---|---|---|
| **INPUT** | known before the verdict-model call, allowed by D44, available in deployment | yes |
| **GATE** | a hard DEFER rule evaluated before any learning; may also be an input only if W5 (note D §11) shows it adds value | as a rule; as a feature only after W5 |
| **OUTCOME** | produced by the verdict model or enforcement after the DM acted | **never** |
| **LABEL** | adjudicated or constructed truth, or a quantity derived from it | **never** (target only) |
| **AUDIT** | provenance, versions, the DM's own output, timing | **never** |
| **SLICE** | used to stratify reports | **never** as a feature |
| **SAMPLING** | derived from the sampling design (some strata are defined with the verdict) | **never**, see §1.3 |

**Hard rule (restating note D §7):** the verdict, its status, its reason and every quantity derived
from them are OUTCOME or LABEL fields. Ingest validation must reject any DM configuration that
names a non-INPUT/GATE field.

### 1.2 The twelve capture groups

Field names refer to `routing-shadow/v1` in note D §3. "Δ" marks something this note adds or
changes.

| # | Group | Fields (note D) | Why it is needed | Role | Privacy handling |
|---|---|---|---|---|---|
| 1 | **Evidence vector** | `features` (34 values, `request-features/v2`), `features_status`, `g_featvec`; Δ `evidence_vector_version`, `evidence_vector_sha256`, per-component status | the DM's raw material. The "evidence vector" is the concatenation of groups 2–5 in a frozen order; storing the *values* (not only a hash) is what makes retraining and B2/B3 threshold selection possible | INPUT (`features`, statuses); `g_featvec`, hashes = AUDIT | P1 numeric. No `Host` / `User-Agent` derived field of any kind (D44). Never raw text |
| 2 | **Deterministic signals** | `det_indicators`, `det_strong_indicator`, `det_engine_version` | the only evidence not learned from V4-clean labels, so the only candidate for a model-independent BLOCK reason; B1 depends on it | INPUT; null today (engine A does not exist) | P1: family id, sink, decode layer, rule id. **Never the matched substring** (it is request content) |
| 3 | **Analyzer scores** | `analyzer_status`, `analyzer_attack`, `analyzer_category`, derived `unc_margin05`, `cat_*`; versions and hashes | the primary routing signal for B2/B3 | INPUT (context only for categories, D46) | P1 numbers. Δ **calibration honesty:** note D calls `analyzer_attack` "calibrated"; **FACT** (`docs/technical_reference.md`, run-002): the frozen Analyzer uses **native probabilities, no calibrator passed D55**. Store `calibrator_id = none` and treat `analyzer_attack_raw` as identical today. D50: no stored "confidence" |
| 4 | **Coverage / OOD** | `cov_*`, `parse_status`, `decode_depth`, `coverage_ok` | defines the regions where Analyzer scores are unreliable; hard DEFER gates | GATE (feature only after W5) | P1 booleans/counts. `cov_auth_bearer_present` stays unlogged until D44 is revised (it reads `Authorization`) |
| 5 | **Conflicts** | `conflict_flags`, `conflict_any` (thresholds `t_hi`, `t_lo` frozen first) | disagreement between group 2 and group 3 is where a single score hides risk | INPUT / GATE | P1 enums. Recomputable from groups 2–3, so store the flag **and** the threshold ids |
| 6 | **Lightweight proposal** | `dm_proposed`, `dm_score`, `baseline_decisions` (B0–B3c), `fast_path_hypothetical`, `dm_mode` | needed to compare policies on identical rows and to audit the shadow DM. "Lightweight proposal" is read here as the action the pre-verdict stages *would* take (the term is ambiguous in the task: **HYPOTHESIS** on meaning) | **AUDIT**. It is the DM's own output; feeding it back is circular | P0/P1 |
| 7 | **Verdict-model verdict** | `v_decision`, `v_reason_category`, `v_logit_margin`, `v_source`, `v_decoding_mode` | values deferral (`defer_value`, `v5_miss`, `v5_fp`) and defines strata S3/S5 | **OUTCOME, never an input** | P1. Normalized D47 category only; **never free text or generated tokens** (a free-text reason can echo the request). `v_logit_margin` is the most tempting leak: it exists only after the call the DM is meant to avoid |
| 8 | **Verdict validity / error** | `v_status`; Δ split `v_fail_kind ∈ {model_invalid, infra}` | `loss_defer` counts failure as fail-closed BLOCK (D34). **Δ** the two failure kinds carry different information: a model-invalid output depends on the request, a timeout depends on load. Only the first is evidence about the request. Both stay fail-closed in enforcement; estimators must not pool them | OUTCOME | P0. Exception text and `raw[:200]` of an invalid output never stored |
| 9 | **Adjudicated truth** | store A: `y`, `y_family`, `y_source`, `pass1/pass2`, `blinded_to`, `adj_status` | the safety target. Independent of the verdict model by construction (§2.3) | **LABEL** | P1. Adjudicator pseudonyms only; reports quote no raw text |
| 10 | **Latency** | `lat_*`, `concurrency_at_arrival`, `device` | `compute_saved_ms`, the D36 instrument, flood resilience (the DM's main claimed value). Pre-DM latencies (`lat_features_ms`, `lat_analyzer_ms`) are load- and size-dependent proxies and would be a shortcut | **AUDIT**, never an input | P1. Millisecond floats plus minute-truncated time are a weak fingerprint (**HYPOTHESIS**); keep them out of any published report |
| 11 | **Model / config versions** | all of note D §3.2 (`analyzer_*`, `verdict_*`, `prompt_template_sha256`, `epoch_id`, `gateway_commit`, `config_sha256`, `*_policy_sha256`) | pins what produced each row; a dataset never mixes epochs. Lets the builder regenerate `v` for sampled rows after a verdict-model change | **AUDIT** | P0. Key ids only, never keys (P4) |
| 12 | **Source / slice** | `source`, `deployment_id`, `privacy_regime`, `sampling_stratum`, `sampling_design_version`, `y_constructed_source` | slicing, per-source class-mix reporting, shortcut detection | **SLICE / SAMPLING**, never an input | P0. `deployment_id` is configured, never derived from `Host`. A model that sees `source` would learn "lab generator ⇒ label" (**HYPOTHESIS**, standard shortcut) |

### 1.3 Refinements to note D (what this note changes or adds)

1. **Sampling fields leak the verdict.** `sampling_stratum`, `pi_vault` and `pi_adjudication` are
   functions of `v_decision` / `v_status` (strata S3, S4, S5). They are therefore OUTCOME-derived.
   Note D marks them "DM-in = no" implicitly; this note states it explicitly. Horvitz–Thompson
   weights `1/π` may be used as **training weights**, never as features.
2. **In-sample Analyzer scores.** Note D flags `in_analyzer_dev` rows and excludes them from
   ROUTING-TEST only. **FACT:** the frozen Analyzer is a gradient-boosting model with
   `early_stopping=False` fitted on V4-clean train (`docs/technical_reference.md`). **HYPOTHESIS:**
   its scores on its own TRAIN rows are optimistic, so a DM trained on those rows would
   over-trust the Analyzer. Proposal: also exclude `in_analyzer_dev` rows from DM **TRAIN** and
   VAL (or use out-of-fold Analyzer scores). Report both choices; the owner picks.
3. **`in_verdict_model_train` is missing.** Note D has `in_v5_dev` and `in_analyzer_dev`. While the
   verdict model is V4, a row identical (by `g_canon` / `g_payload`) to V4-clean train/eval has a
   memorized `v`, which understates `v5_miss` and `v5_fp`. Add the flag keyed by
   `verdict_model_role`, with the same exclusion rule as `in_v5_dev`.
4. **Information-gap measurement belongs in the vault, not in R.** **FACT** (#57, S1): header-only
   A/B pairs flipped V4 in 19 of 101 pairs while the Analyzer changed in 0, "by construction, D44
   tautology". The DM may not read `Host` / `User-Agent` / other headers (D44), so it cannot see
   what moves the verdict model. Do **not** add header-derived fields to R (that would violate
   D44 for the DM's own training set). Measure the gap offline through vault replay of header
   variants on sampled items, and report it as a bound on what any DM can learn.
5. **`g_payload` exposure in real traffic.** It links a value (token, id) across endpoints for the
   lifetime of `k_content` (up to 12 months in note D). **HYPOTHESIS:** group independence only
   matters for rows that carry a label `y`, i.e. vault-sampled rows. Proposal for
   `privacy_regime = real`: compute `g_payload` **only for vault-sampled rows, at dataset-build
   time**, and drop it from R. Cost: unlabelled rows lose payload linkage, which no supervised
   step uses. In `lab` keep note D's design.
6. **Capture readiness gates (before any real-regime capture).** (a) The evidence schema, the
   Analyzer, the coverage gates and the verdict model are frozen and hashed per `epoch_id`
   (note D premise 5). (b) `sampling_design_version` is hashed before the epoch. (c) The
   `blinded_to` rule and the adjudication rubric exist. (d) The D43 question "may a Hybrid stage
   BLOCK without the model?" is answered (see §3.5: otherwise the DM has no action to take).
7. **Schema compatibility with the conflict (§3).** `dm_proposed ∈ {BLOCK, DEFER}` in note D is
   already independent of `DecisionOutput`. If the owner instead keeps a three-way vocabulary,
   `dm_proposed` and `baseline_decisions` change meaning, which is a MAJOR bump under note D §8.

---

## 2. Privacy and methodology (advancing note D, not repeating it)

### 2.1 Pseudonymization

Note D fixes the primitive (HMAC-SHA-256, 128-bit, per-purpose keys, `k_client` rotated every 30
days, `k_content` stable per dataset generation). Additions:

- **Role separation is the control that matters.** GDPR Art. 4(5) defines pseudonymisation as
  processing such that data cannot be attributed to a person without **separately kept additional
  information**, held under technical and organisational measures; pseudonymised data remain
  personal data (secondary summary, see Sources; **UNVERIFIED** against the primary text). So the
  spec requires: the logging service is the only key user; the research role reads R with no key
  access; the builder gets `k_content` only inside the dataset-freeze job. Without that
  separation the HMAC adds little.
- **Uniqueness audit before real capture (HYPOTHESIS, to measure).** R holds 34 numeric features
  at 100% coverage plus minute and `g_endpoint`. Before `privacy_regime = real`, compute on lab
  replay the share of rows that are unique under (feature vector, endpoint class, minute). If it
  is high, coarsen (for example `event_minute_utc` to 10 minutes, `seq_in_epoch` retained for
  ordering) before collecting.
- **No pseudonym is ever a model input** (all `g_*`). They exist for grouping, flood caps and
  leakage checks only.
- **Log hygiene.** OWASP's logging guidance names passwords, session identifiers, access tokens,
  keys and payment data as values that should not be logged raw and recommends removing, masking
  or hashing them (secondary summary of the OWASP Logging Cheat Sheet; **UNVERIFIED** against the
  primary page). This is consistent with note D §2 and §4 and is the reason the vault redacts
  before writing.

### 2.2 Raw-text sampling policy

Note D §4–5 sets the vault, strata S1–S6, keyed Poisson draw and flood cap. Additions:

- **R stays complete; the vault is the only sampled store.** Unchanged, and the reason selection
  bias affects only quantities that need `y`.
- **Optional S0 uniform audit stratum (HYPOTHESIS, not required).** A small `π0` over all rows,
  independent of every model output, gives a model-free check of the Horvitz–Thompson estimates
  and exposes a mis-specified stratum. Union inclusion probability is `1 − (1−π0)(1−π_s)`, logged
  in `pi_vault`. Skip it if sample budget is tight; the design stays valid without it
  (positivity floor S6).
- **Lab regime.** Synthetic traffic carries no PII, so raw text may be stored in versioned lab
  datasets (redaction may be disabled and recorded, note D §4). It still goes in the vault schema,
  not in R.
- **Replay limits.** A new verdict-model version can regenerate `v` only for vault rows. Because
  `π` is known and positive in every stratum, population estimates for the new version remain
  unbiased by Horvitz–Thompson, at higher variance (**HYPOTHESIS**, standard property, requires
  that π was positive for rows the new model errs on).

### 2.3 Blind adjudication and ground-truth independence

Independence of `y` from the verdict model is a **design invariant**, not a hope. Required:

1. **Blinded to:** `v_decision`, `v_reason_category`, `v_logit_margin`, `analyzer_*`, `dm_*`,
   baselines, **and also `sampling_stratum`, `source` and `y_constructed`** (a stratum such as S3
   reveals that the verdict model blocked the row). Note D lists the first group; the second is
   added here.
2. **Rubric** is the neutral note D §6 rule ("executable syntax of family f in a sink the backend
   interprets"), with D47 vocabulary. It must not be derived from the verdict model's reasons.
3. **Order and independence:** random presentation order, ≥ 2 independent pass-1 labels with no
   discussion, a third adjudicator only on disagreement (note D §6).
4. **No model-labelled truth.** No LLM, V4, V5 or Analyzer output may set or pre-fill `y` for
   ROUTING-TEST or for any metric. A model may be used only for queue ordering, and then it must
   not be the verdict model (**HYPOTHESIS**: a same-family labeller correlates with `v` and
   re-introduces imitation).
5. **Agreement is reported with a pre-declared floor.** Use Cohen's κ per batch (note D) and
   Krippendorff's α for the multi-rater/undeterminable case. A common convention (Krippendorff;
   secondary summary, **UNVERIFIED** against the primary text) relies on α ≥ 0.800 and treats
   0.667–0.800 as tentative. The owner declares the floor before adjudication; a batch below it
   is re-adjudicated or excluded, not averaged in.
6. **Seeded gold items (~5%)** of constructed lab cases with known `y`, unmarked, to estimate each
   adjudicator's error rate. The consumed #57/#60 diagnostics may seed *rubric examples* only
   (note D §6); they are not routing test data.
7. **Imitation drift monitor.** Report P(`y = v`) per stratum and per adjudicator on the blind
   queue. A rate far above the gold-item accuracy suggests the adjudicator is guessing the
   verdict model. Flag, do not auto-correct.
8. **Undeterminable is a bias source, not a nuisance.** It concentrates in exactly the hard
   cases a DM cares about (**HYPOTHESIS**). Beyond note D ("excluded and counted"), report every
   `τ` and `β` as an interval with undeterminable rows treated as all-attack and as all-benign.
   A win criterion that holds only when undeterminable is excluded does not count.
9. **Other sensors are raters, not truth.** A WAF/IDS verdict independent of the verdict model
   may help triage, but it is a noisy rater and never sets `y` alone.

### 2.4 Group independence

Note D §7 defines `routing_group` as connected components over `g_canon`, `g_payload`,
`g_featvec` and `g_client_day`. Additions:

- **Per-relation component report** at every build: largest component, share of rows, and the
  effect of dropping each relation (note D reports only the largest component).
- **Optional `g_template` relation (HYPOTHESIS):** HMAC of the canonical request with digit runs
  and long hex/base64 values normalized, to catch parametric near-duplicates (incrementing ids)
  that exact hashes miss. It may merge giant components; adopt only if the builder's report shows
  near-duplicate leakage between blocks.
- **Lab data adds the generator group `_gid`** (D54 analogue, note D §7); source-level and
  generator-level groups must never straddle roles.
- **Unit of analysis is the group, not the row.** **FACT** (#57): 119 constructed benign texts
  collapsed to 8 feature vectors, and one vector (`GET /index.html`) held 87 texts, 29 blocked
  and 58 allowed by V4. Any count, interval or sample-size claim uses Kish effective n over
  independent groups (note D §5, §11).

### 2.5 Leakage prevention (checklist, in addition to note D §7)

| # | Leak | Control |
|---|---|---|
| L1 | verdict (or any `v_*`) as a feature | role rule §1.1, ingest rejection |
| L2 | `sampling_stratum`, `π_*` as features | §1.3 item 1 |
| L3 | in-sample Analyzer scores | §1.3 item 2 |
| L4 | memorized verdict on verdict-model training rows | §1.3 item 3 |
| L5 | `source` / `deployment_id` / `y_constructed` shortcut | SLICE only; per-source class mix reported with every metric |
| L6 | coverage features computed against the very sets used to train the DM | `cov_*` history uses prior epochs only (note D); report `cov_featvec_seen_in_analyzer_dev` = true share per source. On lab data derived from V4-clean it is true by construction, so a DM trained there cannot learn it (**HYPOTHESIS**) |
| L7 | thresholds (`t_hi`, `t_lo`, `t₂`, `t₃`, gates) selected on TEST | selected on ROUTING-VAL, hashed before TEST (note D §7, D37) |
| L8 | the DM's own proposal as a feature, or active-mode feedback loop | `dm_*` is AUDIT; ε-holdout and `logging_propensity` (note D §9) |
| L9 | External Test v1 / V4 eval / #57 / #60 data in routing pools | never; D40 / D53 / D54 |
| L10 | one record in two roles (V5 candidate pool and routing pool) | registry in M (note D §7) |

---

## 3. CONFLICT ANALYSIS: `DecisionOutput` vs D50

### 3.1 What each side says (verbatim)

**`data_plane/hybrid_contracts.py`:**

```python
DECISIONS = ("ALLOW", "BLOCK", "UNCERTAIN")
...
@dataclass(frozen=True)
class DecisionOutput:
    """A future decision stage's answer. UNCERTAIN means "defer to V4"; how it
    is routed is not designed yet. Like `/classify` (D25), a value outside the
    vocabulary is rejected, never coerced."""

    decision: str       # one of DECISIONS
    confidence: float   # [0, 1]
    reason: str
```

`__post_init__` rejects `decision` outside `DECISIONS` and checks `confidence` is a probability
in [0, 1]. `tests/test_request_features.py::TestContracts` pins both
(`test_decision_output_accepts_only_its_vocabulary`,
`test_decision_confidence_must_be_in_the_unit_interval`). **FACT:** nothing produces or consumes
`DecisionOutput` (module docstring; `docs/technical_reference.md`).

**`DECISIONS.md` D50 (2026-10-01, APPROVED, DONE):**

> "No global `confidence` field and no invented confidence score. Uncertainty, when needed, is
> derived: closeness of `attack` to 0.5, top-1 probability, top-1 / top-2 margin, entropy."
>
> "Replaces the open-vocabulary `AnalyzerOutput` of Phase 1 (D43) ... `DecisionOutput` is
> unchanged."

### 3.2 The exact conflict, decomposed

The conflict has three parts. They are different in kind, so they are separated.

| Part | `DecisionOutput` | Opposed by | Literal contradiction of D50's text? |
|---|---|---|---|
| **C1** `confidence: float` required | a mandatory scalar in [0, 1] with no defined semantics | D50's **principle** "no invented confidence score" (stated for `AnalyzerOutput`) | **No.** D50's prohibition is scoped to the Analyzer's signals and D50 itself says "`DecisionOutput` is unchanged". The conflict is with the principle, and with the DM design where the only meaningful scalar is a score with a declared role (`dm_score`, note D) |
| **C2** `UNCERTAIN` | the third value, "defer to V4" | the DM vocabulary BLOCK / `DEFER_TO_V5` | No. Same action, different word. A nuance: UNCERTAIN names an epistemic state, but DEFER also fires for coverage-gate failures, parse errors and Analyzer errors, where the system is not "uncertain" about the request but cannot evaluate it |
| **C3** `ALLOW` is a legal DM output, and `BLOCK` / `ALLOW` are final | the docstring says only UNCERTAIN defers, so ALLOW and BLOCK are decisions taken **without** V4 | the premise of this project's DM: it **never ALLOWs**, and ALLOW originates only from the verdict model or from the D29 fast path with D30 deferred validation | Not D50 at all. It conflicts with **D29** (a heuristic score may allow but never block; allowing only through its own benign gate) and with D43's open question |

### 3.3 Documental or architectural?

- **C1 and C2 are DOCUMENTAL** (naming / field semantics). They can be fixed by renaming
  `UNCERTAIN` → a defer value and by redefining or deleting `confidence`, with no change to what
  the system is allowed to do.
- **C3 is ARCHITECTURAL** (semantics of authority). It answers "who may release a request":
  - three-way `DecisionOutput` = the DM is a **selective classifier**: it may ALLOW, may BLOCK, and
    abstains to V4 when unsure;
  - BLOCK/DEFER = the DM is a **rejector** with a one-sided action: it may block early or pass the
    request on, and every non-blocked request is judged by the verdict model.
  - These are different systems with different risk. In the first, a DM error becomes a delivered
    attack with no second look. **FACT** (D29): the project excluded a heuristic fast BLOCK and
    allowed only a gated fast ALLOW, with deferred validation (D30), because "a heuristic false
    BLOCK breaks legitimate traffic with no model judgement behind it". **FACT** (#57, S2): the
    Analyzer is confidently wrong in both directions on unseen texts (7 attacks scored < 0.01, 5
    benign scored ≥ 0.99), so there is no evidence that it could safely ALLOW.
  - A consumer-side rule ("the DM just never emits ALLOW") is weaker than the contract style the
    repository already uses (the docstring: out-of-vocabulary values are "rejected, never
    coerced"). If ALLOW is representable, any future orchestrator that maps `decision` to
    enforcement can release a request on a DM output.

**Verdict: ARCHITECTURAL overall,** with C1 and C2 documental sub-parts. D50 itself is not
contradicted by the text; it only (a) rejects invented confidences, which `DecisionOutput.confidence`
would be by the same reasoning, and (b) records `DecisionOutput` as unchanged, which freezes the
three-way vocabulary until another decision replaces it.

**Second-order architectural fact (FACT, D43):** whether *any* Hybrid stage may BLOCK without the
model is "open for a later decision". A BLOCK/DEFER DM is vacuous if the answer is no: its only
non-DEFER action is the light BLOCK. So the contract question cannot be settled before that one.

### 3.4 What would have to be decided (not decided here)

A future decision, called "D-next" here to avoid pre-empting a number, would need to rule on:

1. **The DM's output vocabulary:** exactly {BLOCK, DEFER}; ALLOW becomes unrepresentable (a new
   contract type, not a widening of `DecisionOutput`). Naming: `DEFER_TO_V5` ties the enum to a
   model name that does not exist yet and that D45 reserves for the next model; a neutral value
   (for example `DEFER`) plus the per-epoch `verdict_model_role` (note D) is more durable
   (**HYPOTHESIS**, owner choice).
2. **D43's open question:** may the DM issue a light BLOCK, and under which conditions (coverage
   gate, conflict flags, class-conditional cap α as in note D). This also settles the "D29
   tension" noted in `CONTEXT.md`.
3. **`confidence`:** delete it from the production contract, or replace it by a `score` whose
   meaning and threshold-selection rule are declared in advance. D50's rule ("derived, not
   invented") favors deletion; `dm_score` stays a shadow-log field (note D §3.5).
4. **`reason`:** a closed enum of evidence codes (for example `det_strong`, `analyzer_high`,
   `coverage_fail`, `conflict`, `analyzer_error`). Not free text: note D §2 shows free text can
   echo the request.
5. **DM failure semantics:** DM error or timeout yields DEFER (never ALLOW, never BLOCK), so the
   verdict model and D34 fail-closed still decide. Mirrors D43's rule that a shadow component's
   failure is caught on its own.
6. **Scope of the supersession:** only D50's sentence "`DecisionOutput` is unchanged" and the
   `DecisionOutput` / `DECISIONS` definitions. D50's `AnalyzerOutput` rules stay in force. The D29
   fast path remains the only non-model ALLOW and would need its own output type, not
   `DecisionOutput`.
7. **Fallout list (documental):** `hybrid_contracts.py` docstrings and `DECISIONS`,
   `tests/test_request_features.py::TestContracts`, `README.md`, `CONTEXT.md`,
   `docs/technical_reference.md` (the "ALLOW / BLOCK / UNCERTAIN" diagram and status rows), and the
   D55 sentence "the operating policy (ALLOW / BLOCK / UNCERTAIN) is decided later" (D55 may be
   left as history).

**Timing (FACT):** no producer or consumer exists, so changing the contract now costs one
dataclass, its two tests and wording in four documents. After a DM is built it costs a migration.
This is the cheapest moment, and it can be taken **before** any capture; capture does not depend on
it (§1.3 item 7).

**Alternative the owner may prefer (HYPOTHESIS):** keep a three-way selective classifier. This
needs evidence the repository does not have (a safe ALLOW region for the Analyzer) and would add a
delivered-attack path that the D29/D30 design deliberately avoided. Not recommended on current
evidence.

---

## 4. Does a learned DM have a chance? (policy vs ML)

**FACT**
- The learned evidence is one model. Its only external aggregate (D53, run-001, 50/50 by
  construction, not a prevalence, D42): ROC-AUC 0.943, FPR 25.0% (50/200) and recall about 94% at
  the reporting-only 0.5, with errors concentrated in `api-json` and `api-query`
  (`analyzer-external-v1-run-001/README.md`).
- On development data the verdict model's errors move with inputs the DM may not read:
  header-only A/B pairs flipped V4 in 19 / 101 pairs while the Analyzer changed in 0 (#57), and the
  minimal-pair probe found strong V4 sensitivity to apostrophe, `#`, `http` scheme and
  `Transfer-Encoding: chunked`, with no effect from `Content-Length`, ports and IP (memory note,
  `minimal-pair-probe-v1`). Which of those are covered by the 34 features was not checked here.
- Identical evidence vectors received both V4 verdicts (the `GET /index.html` vector: 29 BLOCK,
  58 ALLOW). A model that sees only the vector cannot separate them.

**HYPOTHESIS**
- The learnable part of a rejector is bounded by how well the permitted inputs predict the verdict
  model's errors. The evidence above suggests that bound is low for header- and envelope-driven
  errors, and the number of verdict-model errors available for training is small, so W5 (note D
  §11) will probably fail for an ML DM.
- A **policy** (gates + a Chow-style threshold chosen under a benign-block cap on VAL: baselines
  B1/B2/B3/B3c) is likely the shippable artifact, with the DM trained only if W5 passes. This is
  the same fallback note D already pre-registers ("otherwise the best feasible baseline ... or
  B0"). It is also what Chow's rule gives when V5 is near-perfect and the score is the sufficient
  statistic (Chow 1970; Jitkrittum et al. 2023 for when confidence-based deferral suffices; cited
  in note D, not re-verified here).
- The capture is worth building even if no ML DM follows: it is what selects the B2/B3 thresholds,
  estimates the benign-block cap with the sample sizes in note D §11, and measures the
  information gap of §1.3 item 4.

---

## 5. Open owner decisions (this note creates none)

1. Resolve §3.4 items 1 to 6 (output vocabulary, D43 light-BLOCK question, `confidence`, `reason`,
   failure semantics, supersession scope).
2. Exclude `in_analyzer_dev` rows from DM TRAIN/VAL, or use out-of-fold scores (§1.3 item 2).
3. Real-regime `g_payload` policy and timestamp coarsening, after the uniqueness audit (§1.3 item
   5, §2.1).
4. Agreement floor (κ / α) and the sensitivity-interval rule for undeterminable rows (§2.3).
5. Whether to include the S0 uniform audit stratum and the `g_template` relation (§2.2, §2.4).
6. All note D open items (costs or the cap α, retention periods, which headers may be read, D44).

## 6. Sources

Repository (FACT): `data_plane/hybrid_contracts.py`; `DECISIONS.md` D29, D43, D44, D45, D50, D55;
`tests/test_request_features.py` (`TestContracts`); `docs/technical_reference.md`; `CONTEXT.md`;
`reports/hybrid/v4-analyzer-disagreement-v1/README.md`;
`reports/hybrid/analyzer-external-v1-run-001/README.md`;
`reports/v5/minimal-pair-probe-v1/README.md`; note D.

External (3 web searches, 2026-10-06; search-result summaries, **primary texts not opened**):

| Claim | Source |
|---|---|
| Pseudonymisation under GDPR Art. 4(5) needs separately kept additional information; pseudonymised data remain personal data; Art. 5(1)(e) storage limitation | https://guidelines.panelfit.eu/the-gdpr/main-concepts/identification-pseudonymization-and-anonymization/pseudonymization/definition-of-pseudonymization-in-the-gdpr/ and https://guidelines.panelfit.eu/the-gdpr/main-principles/storage-limitation/ (secondary guidance; primary text: Regulation (EU) 2016/679, eur-lex) |
| Credentials, session ids, tokens, keys and payment data should be removed, masked or hashed in logs | OWASP Logging Cheat Sheet (via search summary; e.g. https://owasp-aasvs4.readthedocs.io/en/latest/V7.1.html for the related ASVS control) |
| Krippendorff's α convention: ≥ 0.800 reliable, 0.667-0.800 tentative | https://www.asc.upenn.edu/sites/default/files/2021-03/Answering%20the%20Call%20for%20a%20Standard%20Reliability%20Measure%20for%20Coding%20Data.pdf (Hayes & Krippendorff, summary; thresholds not re-read in the PDF) |

All other citations (Chow, Jitkrittum, TESSERACT, Horvitz-Thompson, etc.) are inherited from note D
§13 and not re-verified.
