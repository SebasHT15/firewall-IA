# Proposed decisions — first C1-only Model 2 experiment

**Batch closure, 2026-10-23:** documentation corrections completed; branch now
includes develop/D70 `7ee8570`, with 82 Codex tests passing on that base. See
`CIERRE_PREPARACION_2026-10-23.md`. The experiment decisions below remain proposals
for subsequent work, not unfinished implementation in the current preparation PR.

Status: PROPOSED, updated 2026-10-23. No real-data fitting or active policy authorized by this file.
These recommendations are ready to reconcile with Claude's V5/data packet; they
are not a request to repeat previously granted filesystem permissions.

Batch 2 exercised a fixed logistic-regression recipe on artificial fixtures only
(`fixture-experiment.json`). This implements the encoder/learner wiring without
ratifying candidate selection, label eligibility, operational threshold or risk
tolerance. Its narrow omission of path_length/path_depth is not the full required
path ablation. The real-experiment decisions below remain PROPOSED.

## Current addendum — implemented diagnostics, pending admission (2026-10-23)

The new fixture experiment implements full **request-target path** neutralization
before extraction, retaining query/body, and complete-group bootstrap diagnostics.
Those engineering items are no longer pending. They do not settle the real-data
group definition, feature admission, model selection protocol or numerical risk
tolerance. See `LOTE5_2026-10-23.md` and `grouped-fixture-experiment-v1.json`.

Proposed grouping connects all seven exchange identity dimensions transitively.
Its conservative application yields only one validation component in the current
synthetic fixture, so no interval is estimated. Do not weaken grouping merely to
manufacture sample size. A real experiment needs a preregistered sampling and
dependence rationale; independent components cannot be inferred from disjoint IDs.
The 0.5 threshold, 95% confidence setting, 1,000 draws and seed 0 are engineering
demonstration parameters, not approved risk tolerances or a selection procedure.

The current C1 extension is proposal-v2: native JSON scalar types are explicit,
separate from string/value shapes; scientific notation is counted; lexeme matching
uses ASCII case-folding; invalid ports/whitespace are not URL shapes. Missing decoded
views have null differences, not zero differences. The raw JSON view contains
parsed scalar semantics, not raw JSON syntax or wire bytes. New facts still require
an approved allowlist and missing-evidence semantics before learned use. COMPLETE
means complete only within `bounded_query_form_json_scalars_only`.

The earlier addendum below records proposal-v1 and its then-pending work.
Commit remains deferred to the end under the user's latest instruction.

## Historical addendum — bounded C1 extension proposal (2026-10-22)

`scripts/model2/c1_extensions.py` now implements a bounded offline subset of the
missing C1 facts. Its output keeps the existing `request-features/v2` baseline
separate from two aggregate views of query/form/JSON scalar values: literal and
one percent-decoded. Query `+` is literal; form `+` maps to space. Invalid percent
triplets or UTF-8 make the entire decoded view unavailable, not an all-zero
vector. JSON values retain boolean/null identity; numeric and string values
are classified by their textual shape. URL facts count only absolute HTTP(S)
values with a hostname; lexical facts count exact ASCII-boundary `select`,
`union` and `script` tokens. These are descriptive tokens, including in benign
text; none is called an attack indicator or weighted as suspicious.

Coverage includes sources parsed, missing/unsupported views, raw/decoded value
differences, canonical signals and size status. Bounded failures return
unavailable facts rather than a truncated sample. The 64 KiB/256-value/2048-
character limits are local engineering bounds, **not** approved operational
limits. No request text, values, labels, group IDs, host or user agent appear in
the envelope. The extractor takes a `CanonicalResult`; it cannot prove that the
result was derived from verified wire bytes or authorize any dataset.

Decision needed before training/runtime: pin the allowed feature fields,
interpretation of partial/unavailable evidence, whether any canonical signal
becomes a learned input, and the actual production bounds. Until then the
extension remains metadata-only (`learned_input_admitted=false`). A full path
ablation, group-aware uncertainty and a selected risk tolerance still remain
pending. The current 34 fields plus this scoped extension are **not** a claim
that the PDF's whole C1 is complete.

## 1. Representation and C1

Recommendation: fit new Model 2 candidates on features computed from the exact
`canonical-request/v1` ACCEPT text used in the dataset and intended runtime.
Do not reuse the frozen D1 Analyzer weights, and do not rename C2 as Model 2.

Use the 34 existing deterministic features as a named baseline. The compatibility
experiment demonstrates why switching representation silently is invalid. This
baseline is not the entire PDF C1. Define a new C1 envelope that separates:

- learned input fields with pinned extraction semantics;
- canonical status, size status, available signals, missing/unsupported evidence
  and feature version as explicit metadata;
- provenance, group IDs and labels, which never become learned features.

Recommendation for C1 extensions: specify bounded per-value type/URL facts and
lexical evidence with synthetic benign/attack counterparts; retain raw vs decoded
views explicitly. Reuse existing canonicalization and approved signals. Do not
add a manual suspicious score or make the feature extractor issue decisions.
Host/User-Agent and other prohibited headers stay out.

Decision needed: exact initial feature allowlist and which existing canonical
signals, if any, may be learned inputs. Until resolved, added signals stay metadata.

## 2. Learner and selection

Recommendation: regularized logistic regression as an interpretable baseline and
one HistGradientBoosting candidate family to test nonlinear combinations, using
the same permitted examples, splits and evaluation. Do not assume the latter wins.
Keep the search small and record its exact parameters before fitting. Fit encoder
statistics/vocabulary on TRAIN only; validation chooses the model/calibration and
threshold under the recorded rule. Preserve required path-feature ablation.

The implementation must not require a trained V5 or learned C2. C2 admission and
its out-of-sample predictions become a separate later experiment if pursued.

Decisions needed: approve the candidate families and bounded recipe; select the
primary validation criterion. Recommended priority is early-block false-positive
risk, followed by useful attack coverage/delegation and latency, with provenance-
specific reports. **No numerical tolerance is invented here.** Define the maximum
allowed risk and any coverage/latency target before fitting/selection. Include a
rule for insufficient data or no feasible threshold: no active block policy.

## 3. Shared data and scope

Recommendation: consume Claude's existing V5 manifest + aligned row/meta schema
once ready, with explicit TRAIN/VALIDATION files and artifact hashes. Do not invent
a competing dataset layout or read all roles and filter afterwards. Required
information: canonical representation/version, row ID, pair/family/cluster IDs,
reference label, label basis/provenance, allowed role, exclusions and contamination
flags. Derive only needed features from eligible canonical text.

No V4/V5 predictions as labels. AI-audited and constructive/policy-defined evidence
remain distinguishable. Metadata is used for validation and reporting, not features.
TRAIN/VALIDATION group integrity and known overlap with earlier artifacts must be
checked before fitting, without opening protected evaluations.

Model 2 sees Fast Path CONTINUE traffic. With Fast Path ineligible the observed
population is all traffic and must be named that way. A later active Fast Path
changes that population and requires evaluation of its residual traffic; metrics
cannot silently transfer from today's population.

Decisions needed: approved label eligibility/authorization, contamination handling,
and protected evaluation plan, reconciled with the V5 dataset protocol. The pure
metric module does not validate provenance authenticity or authorize dataset use.

## 4. Training, deployment and Model 2 authority

Recommendation: first produce an experimental offline candidate with immutable
run metadata and explicit limitations. Approving an experiment is separate from
authorizing the model to block live requests. Missing/invalid/unavailable evidence
remains DEFER-equivalent, and unavailable final inference retains fail-closed
behavior. No threshold has been chosen, no posterior fabricated and no MODEL2
policy file marked APPROVED by this batch.

## 5. Evidence already available to Claude

- Proposed Python boundary in `scripts/model2/contracts.py` (no trained decider).
- Actual D1/canonical synthetic compatibility in `c1-compatibility.json`.
- Pure validation point estimates in `scripts/model2/evaluation.py`; explicit
  denominators, provenance/population separation, no implicit threshold search.
- 28 passing tests, independent of V5 weights, datasets, C2 or GPU.

Before shared integration, reconcile local branch with merged D70. Codex has not
changed branches, refs, gateway, training files or historical decisions.
