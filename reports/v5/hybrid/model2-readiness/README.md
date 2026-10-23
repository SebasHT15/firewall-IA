# C1 / Model 2 — Codex preparation

## Current closure — ready for commit and PR to develop, 2026-10-23

The owner requires each branch's scope to be completed before opening its PR.
The preparation batch is complete; see `CIERRE_PREPARACION_2026-10-23.md`.
The branch was fast-forwarded to `develop`/D70
`7ee8570830f6e9bfaa3edfa381ca430693e911f4`, preserving all 42 then-local files
byte-for-byte. No new commit was created. **The PR target is develop, not main.**

The 56 data-plane + 26 analyzer tests were rerun successfully on that base.
Both current fixture reports still match their 25/5 pinned source hashes.
The A/B documentation review is closed: pilot prerequisites, complete F10,
literal candidates/hashes, wire diagnostic scope and latency wording corrected.
Codex made these closing edits under the owner's explicit instruction to finish
the batch. Runtime code/configuration remain identical to the D70 base.

No pending correction or integration-base task remains for this batch. Real-data
pilot, #80 implementation and active hybrid operation are subsequent tasks with
their own decisions and checks; this commit does not implicitly authorize them.
Earlier checkpoints below are historical and retain their dates and evidence.

## Previous checkpoint — target-path ablation and grouped diagnostics, 2026-10-23

**82 selected tests pass:** 56 in `.venv-dataplane`, 26 in `.venv-analyzer`,
two explicit invocations; no failures/errors/skips. Only built-in synthetic
fixtures were consumed. V4 remains the sole authority. The user's latest
instruction is **commit at the end**; HEAD remains `478524d`, no refs changed.

- `feature_views.py` neutralizes only the request-target path before extracting
  all baseline features, then omits the two constant direct path fields (32
  inputs). Query/body remain verbatim. Tests check prediction invariance under
  TRAIN/VALIDATION path changes. This supersedes the earlier narrow two-field
  omission for the new experiment; historical results retain their meaning.
- `identity_groups.py` connects all shared declared identities transitively.
  The generated V5 fixture has 232 TRAIN / 24 VALIDATION rows, but only **4 / 1
  connected components**, respectively. Twelve validation pairs do not supply
  twelve independent units under this proposed dependence rule.
- `grouped_evaluation.py` resamples complete groups at a fixed threshold and
  reports explicit insufficient/undefined/degenerate outcomes. In this fixture,
  **all intervals are null: INSUFFICIENT_CONTRIBUTING_GROUPS**. No variant or
  operating threshold is selected. The path-neutralized view has two shared
  TRAIN/VALIDATION feature vectors; these collisions are disclosed, not removed.
- C1 extension **proposal-v2** distinguishes native JSON types from lexical
  shapes, counts scientific notation, rejects malformed URL ports/whitespace
  as URL shapes, restricts lexeme case-folding to ASCII, and keeps unavailable
  view differences as null. `COMPLETE` covers only bounded query/form/JSON
  scalar extraction. New facts remain metadata, not learned inputs.

Current evidence: `grouped-fixture-experiment-v1.json`,
`c1-extension-evidence-v2.json`, and `LOTE5_2026-10-23.md` (method, commands,
limits and actual results). Earlier JSON files below are historical snapshots;
their hashes have not been refreshed to disguise later source changes.

## Prior checkpoint — Unicode reader closed; C1 extension facts, 2026-10-22

The final corrected V5 reader was checked independently at these exact source
hashes: `v5_train_data.py` `12152446443e5a2cd30c6c5de7e27355324270116d70022c29f00cc6e0c7986b`,
`v5_example_exchange.py` `6cc8a7ed1832f0f3376431148e7ba3d959dbf3176496ec9e25a1dd5f4cfa7f78`,
and `v5_split_exchange.py` `52c8130a1657bd6372f08bd4605c550824aa168ecffa7400439bf415b257d0de`.
Both readers split JSONL only on LF, retaining U+0085/U+2028/U+2029 within
strings. Snapshot and authorization fixes remain in place. **44 Claude tests
actually passed** (15 split, 10 example, 19 training gates); a tokenizer class
setup was additionally skipped because `transformers` is unavailable in the
data-plane environment. Codex repeated the 19 affected fixture/integration
tests after this fix; the other 28 retain their earlier run. The integration
again consumed **232 TRAIN / 24 VALIDATION** synthetic examples. Its final
source-pinned result is `v5-fixture-integration-unicode-corrected.json`.
`v5-fixture-integration.json` is a historical pre-Unicode snapshot and retains
its original hashes and claims. The Batch 3 text below is historical too; its
open Unicode finding and 41-test count were superseded by this checkpoint.

The new `scripts/model2/c1_extensions.py` produces bounded, offline **facts**
from a `CanonicalResult`: 34-field baseline, aggregate value types, HTTP(S)
URL shape, exact lexical token counts in literal and one-decoded views, plus
source coverage, missing views, view differences, canonical signals and size.
It does not score, decide, fit, load data or authorize training. New facts are
**not admitted as learned Model 2 inputs**. Limits (64 KiB text, 256 values,
2048 characters/value) bound this offline probe only; they are not ratified
production B/R8 values. Requests beyond them return unavailable facts without
truncation. The 34 fields remain a baseline, not complete C1; this extension
covers a scoped subset of the PDF's value/URL/lexical capability and does not
make C1 complete. See `c1-extension-evidence.json` and `DECISION_PACKET.md`.
Focused verification on this checkout: **38 data-plane tests** (the prior 28
plus 10 extension tests) and **19 analysis fixture/integration tests** passed in
two separate invocations, 57 successes, zero failures/errors. This new run does
not repeat Claude's 44 reader tests; their final verified source hashes and
prior run are recorded above. No broad discovery or protected-data tests ran.

Framing/#68 remains a separate Claude-owned front. D69/D70 are default-off
observation. `PROFILE_MATCHED` does not imply `FRAMING_VERIFIED`; the Fast Path
still continues and V4 remains the sole authority. Local HEAD `478524d` is
pre-D70; branch reconciliation belongs to the owner. No refs changed here.

## Batch 3 — shared V5 fixture integration, 2026-10-22

Implemented `scripts/model2/v5_fixture_integration.py`: generate the existing V5
fixture in a fresh temporary directory, consume Claude's corrected example reader,
extract the existing C1 baseline, fit encoder/scaler and ephemeral logistic
regression on **232 TRAIN** rows, evaluate **24 VALIDATION** rows. No caller data
path, saved weights, C2 or V5 inference. Evidence: `v5-fixture-integration.json`.

```sh
OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 .venv-analyzer/bin/python -B -m scripts.model2.v5_fixture_integration --demonstration-threshold 0.5
OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 .venv-analyzer/bin/python -B -m unittest tests.model2.test_v5_fixture_integration tests.model2.test_fixture_experiment
```

Six new tests pass: consume-and-fit contract, metadata exclusion, one read of each
allowed file, no protected-role file reads by the consumer, disk mutation after
hash does not replace the verified capture, reader refusal prevents fitting,
original label metadata preserved, and source drift refusal. There are six test
methods; some cover multiple properties. **47 Codex tests pass** (19 in analysis
environment, 28 in data-plane environment), zero failures/errors/skips.

Claude's suite was independently checked: **41 successful tests**, plus a skipped
WithTokenizer class setup (transformers unavailable), zero failures/errors.
The previous snapshot re-read and authorization-before-row-access findings are
closed for reader SHA `6cc8a7ed…`. A new semantics regression in the trainer's
`parse_split` remains: splitlines() splits literal Unicode U+0085/U+2028/U+2029
inside valid JSONL strings. Reproduction and requested correction are in the
handover. The current fixture runs, but this does not attest all Unicode inputs.

The generated fixture declares VERIFIED statuses and lacks row label_basis; the
report preserves that metadata literally. Its **fixture_synthetic** metric scope
is established by in-process fixture generation. These are not real audited
labels or security-performance results. Pair counts are descriptive; all identity
dimensions are checked by the shared reader, but statistical grouping/uncertainty
is still pending. C1 completion, real training prerequisites and active cascade
integration remain outstanding.

## Batch 2 — executable fixture learner, 2026-10-22

`scripts/model2/fixture_experiment.py` now exercises canonical ACCEPT → baseline
C1 → TRAIN-only DictVectorizer/StandardScaler → ephemeral logistic regression →
VALIDATION metrics. Fixed built-in fixtures only: **24 TRAIN / 8 VALIDATION**,
disjoint fixture pairs and text. Labels are artificial engineering labels, so
their separation/metrics do not measure security performance. No weights saved,
model artifact or runtime integration. The existing NoModelDecider stays unchanged.

Run with the existing CPU analysis environment (no dependency/pin changes):

```sh
OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 .venv-analyzer/bin/python -B -m unittest tests.model2.test_fixture_experiment -v
OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 .venv-analyzer/bin/python -B -m scripts.model2.fixture_experiment --demonstration-threshold 0.5
```

Evidence: `fixture-experiment.json`, Python 3.12.15 / sklearn 1.9.1, source hashes
and explicit recipe. 0.5 is an explicitly supplied **demonstration threshold**,
not a selected/approved operating point. Baseline 34 inputs and a second variant
omitting path_length/path_depth run without selecting a winner. That variant
still includes path-derived character/entropy evidence and is **not path-free**.

**13 new tests pass**, covering validation-only categories, validation outliers
not altering encoder/scaler fitting, labels/IDs not influencing predictions,
cross-split group/text contamination, integrity/role/provenance refusals, repeat
fit determinism in this environment, source drift, and CLI input restrictions.
The prior **28 tests were rerun and passed** in `.venv-dataplane`: **41 total**,
two explicit invocations/environments, 0 failures/errors/skips.

The new fixture generator is private engineering input, not another real dataset
format. No V5 manifest gate is attested by this run. Claude's real example loader
is still under active revision; a snapshot re-read issue was reproduced and
recorded in `HANDOVER_TO_CLAUDE.md`. No loader dependency was added yet.

Next: finish the verified row/meta snapshot handoff, exercise it with V5 fixtures,
complete the agreed C1 evidence schema/extensions, and settle the real experiment
recipe/label/risk rules before fitting a real candidate. Full path ablation,
group-aware uncertainty and joint architecture evaluation remain outstanding.

## Batch 1 — historical scope and evidence

2026-10-22. **Offline preparation / proposal; synthetic tests only.** No trained
model, chosen operating threshold, gateway import or new enforcement authority.
C2 is optional and excluded from this first version. C1 is deterministic and is
implemented/tested, not trained. Model 2 is the separate BLOCK/DEFER learner.

## Ownership and integration

Codex exclusively owns `scripts/model2/`, `tests/model2/` and this report directory.
Claude owns data/V5 preparation. Shared gateway, canonicalization, existing feature
extractor, legacy contracts, trainer, configuration and DECISIONS were not edited.

Baseline observed: local `feat/hybrid-training-integration` at `478524d` (D69).
GitHub PR #86 is merged at `7ee8570830f6e9bfaa3edfa381ca430693e911f4`, but that merge
was not yet included in this local branch when the batch began. This work does not
change refs. The owner must reconcile the branch before gateway integration. The
experiment JSON pins the actual local HEAD AND hashes of the source files used;
it is not presented as a run over the D70 merged tree.

## Implemented

- `scripts/model2/c1_readiness.py`: 18 built-in synthetic requests through the real
  D1 renderer and canonical adapter/function, comparing the existing 34 features.
  No dataset argument, no fitting, no weights. CLI has an extra dataset-path read
  guard. Reports fixture IDs, outcomes, signals and changed feature names, not
  request text or feature values. Guard is not a universal filesystem sandbox.
- `scripts/model2/contracts.py`: isolated proposed boundary accepting canonical C1
  evidence; typed BLOCK/DEFER only; missing/invalid evidence is explicit. The only
  decider is `NoModelDecider`: MODEL_UNAVAILABLE, no posterior, DEFER-equivalent.
  Successful BLOCK/DEFER result objects are explicitly synthetic fixtures only.
  Existing `hybrid_contracts.DecisionOutput` remains unchanged and is not reused.
- `scripts/model2/evaluation.py`: validation-only point estimates at a caller-supplied
  threshold, with explicit numerators/denominators. Separates reached populations
  and label provenance. Refuses mixed provenance, model predictions as labels,
  duplicate row IDs, invalid probabilities and roles other than VALIDATION.
  It neither selects nor approves a threshold; it does not load data or verify that
  caller-declared provenance is authentic. A verified manifest loader is still needed.

## C1 coverage against arqui2.pdf, sections 2–3

| PDF capability | Existing deterministic implementation | Remaining work |
|---|---|---|
| Request structure | Method, path/query/body lengths, parameter counts, repeated names, path/JSON depth | Validate representation and final feature contract |
| Character/encoding evidence | Character counts/ratios, percent-triplet counts, entropy, repeated runs | Existing extractor does not percent-decode; keep this distinction explicit |
| Transfer/content decoding | Existing canonicalizer handles decoding and produces signals | Do not implement another decoder; side-channel admission into learned evidence needs an explicit contract |
| Value types | Body format and JSON shape exist | Per-value URL/type evidence is not implemented as a complete C1 interface |
| URLs and lexical indicators | Current features count syntax; no dedicated URL or lexical detector fields | Define exact evidence, negative counterparts and cost before adding features |
| Coverage/conflict | Canonicalizer has explicit signals/outcomes | Not present in the 34-feature vector; full C1 must keep this metadata available without inventing learned inputs |
| Learned component C2 | Existing frozen Analyzer is a separate learned artifact | Not required or loaded for C1-only preparation |

**The existing extractor is a baseline, not proof that the whole PDF's C1 is done.**
This batch deliberately does not mark missing capabilities as implemented. Details
and recommended decisions are in `DECISION_PACKET.md`.

## Compatibility findings

Saved evidence: `c1-compatibility.json`.

- 18 synthetic cases; 16 canonical ACCEPT cases compared; 2 canonical REJECT cases
  excluded from parity comparison rather than counted as equivalent.
- 13 compared cases retain the same 34 features; 3 differ:
  - invalid UTF-8 in body: D1 replacement vs canonical byte escape;
  - invalid UTF-8 in target: representation-dependent character features;
  - concatenated gzip members: different body decoding and resulting parameter counts.
- Host/User-Agent variants do not alter the feature vector in the tested cases.
- Invalid octets and literal `\xNN` text can have the same canonical rendered text
  but different canonical signals. A feature-only interface must not be mistaken
  for a complete provenance/evidence interface.
- No weights were loaded. Findings do not establish model-quality degradation or
  improvement; they establish that automatic D1/canonical equivalence is false.
- HTTP/1.0 is included solely as an adapter/feature comparison case. It does not
  establish D70 framing eligibility. All accepted cases use lab-only body bounds
  with token budget unset and size UNCHECKED.

## Verification

Run from the repository, in the existing data-plane environment:

```sh
.venv-dataplane/bin/python -B -m unittest tests.model2.test_contracts tests.model2.test_c1_readiness tests.model2.test_evaluation -v
.venv-dataplane/bin/python -B -m scripts.model2.c1_readiness
```

**28 tests pass, 0 failures/errors/skips:** 11 boundary, 9 compatibility and 8
validation-metric tests. Cases cover invalid evidence, no ALLOW output, absence
of invented posterior, DEFER-equivalent errors, representation mismatch,
canonical rejects, actual decoding differences and metric denominator/refusal
rules. A model-learning or security performance claim does not follow from these
tests. No protected datasets, R3, real split/build/freeze/train or full
`tests.test_data_plane` execution occurred.

## Next executable work

1. Agree a C1 feature/evidence schema and the experiment protocol in the decision
   packet; keep C2 out. The present boundary stays a proposal until then.
2. Claude supplies the existing V5 manifest/row/meta interface proposal, split and
   label-provenance rules. Implement a selective TRAIN/VALIDATION loader rather
   than opening a combined dataset and filtering after reading protected rows.
3. Implement the approved C1 gaps and learner/encoder with synthetic fixtures;
   run real fitting only after an eligible manifest and experiment authorization.
4. Add group-aware uncertainty and the approved selection rule before claiming a
   usable operating point. Reserve joint/held-out evaluation to its protocol.
5. Hand an explicit interface to Claude for eventual gateway integration. Do not
   import this offline probe, synthetic result producer or placeholder as an
   active security decision.
