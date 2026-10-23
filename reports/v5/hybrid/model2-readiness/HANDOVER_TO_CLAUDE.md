# Codex → Claude: interface handover

## Current closure, 2026-10-23

The owner instructed Codex to finish all remaining preparation-PR corrections.
A/B are now corrected in place: real-pilot prerequisites and timing, complete
F10 and consumers, literal template/vocabulary/recipe and 11 source hashes,
diagnostic hop-comparison scope and measurable latency overhead. No further
correction prompt is pending. The earlier review requests below are historical.

The branch now includes develop/D70 `7ee8570` by fast-forward; all 42 existing
local batch files were preserved through that operation. 56+26 Codex tests pass
on the reconciled base. No new commit, push or PR was created. The owner will
commit; PR destination is **develop**. Full closure: `CIERRE_PREPARACION_2026-10-23.md`.

## Historical handover, 2026-10-23 — grouped fixture and review of A/B

Latest user instruction: **commit at the end**, same branch. HEAD is still
`478524d`. Codex changed only its three owned folders. The reader closure below
remains closed; no repeat reader review or protected-data access is requested.

Codex implemented target-path neutralization before feature extraction, connected
identity groups and whole-group conditional bootstrap diagnostics. The shared V5
fixture remains 232 TRAIN / 24 VALIDATION, now with 4 / 1 connected components;
all uncertainty intervals are correctly unavailable. C1 extension proposal-v2
adds native JSON types and tightens missing-view/URL/ASCII semantics. **82 tests
pass**, 56 data-plane and 26 analyzer in separate runs. No learned feature
admission, selected model, saved weights or active gateway. See `LOTE5_2026-10-23.md`.

Review of your new A/B documents (read-only; your files were not edited):

1. **A §2.1:** installed mitmproxy `addons/proxyserver.py:209` registers
   `validate_inbound_headers` with default **True**, not False. `Options()` alone
   does not register that addon option. Effective runtime attestation is still
   required; sampled post-parse state is not parser-time history.
2. **A §§2.3/6–8:** compare against existing D70 commit `b433505` read-only.
   `framing_evidence.py` already implements PROFILE_MATCHED, coherent snapshot,
   effective-profile checks and generation drift. Reconciliation is needed for
   integration, not for identifying that existing implementation. Specify the
   actual missing wire observation/control and forwarded-hop correlation delta.
   Introspecting Request proves a post-parse object lacks raw wire bytes; it does
   not by itself rule out every extension point. A hop divergence experiment is
   diagnostic evidence, not per-request verified enforcement.
3. **B §§1–2:** prompt template and §4.3 labeling policy are separate. Tokenizer
   overhead can be measured independently of URL policy ratification. Scripts
   live under `scripts/dataset/`. Candidate evidence already records overhead76,
   label budget13 and B415, plus two synthetic smoke runs; reconcile hashes and
   scope before proposing a repeat. No new GPU run is required for this packet.
4. **B §§0/6/8:** r4 activation is the complete #80 patch plus ratified
   authorization/provenance fields and its focused tests, not just SUPPORTED_SPECS.
   The current trainer remains r3; the patch remains unapplied. Provide exact
   candidate values, evidence fingerprints, remaining decisions and enabling
   artifacts. Separate candidate measurement, pilot, preregistration, full build
   and freeze so the order is not circular.

Keep B first. No real build/train, protected evaluation, runtime change, refs or
PR draft is requested in this continuation. Do not execute the default
`measure_v5_token_lengths.py`: its input list includes real development sources.
Use existing reports and code to prepare the concrete decisions. Experimental
training still needs an eligible, integrity-checked, built provisional dataset.

## Prior handover, 2026-10-22 — corrected reader and bounded C1 facts

The prior Unicode regression section below is **closed, historical feedback**.
The corrected reader hashes are `v5_train_data.py` `12152446443e5a2cd30c6c5de7e27355324270116d70022c29f00cc6e0c7986b`,
`v5_example_exchange.py` `6cc8a7ed1832f0f3376431148e7ba3d959dbf3176496ec9e25a1dd5f4cfa7f78`,
and `v5_split_exchange.py` `52c8130a1657bd6372f08bd4605c550824aa168ecffa7400439bf415b257d0de`.
The 44 Claude tests passed (15+10+19); Codex repeated 19 affected tests and
the 232/24 fixture integration. `v5-fixture-integration-unicode-corrected.json`
is the final evidence. Historical hashes and reports remain unmodified.

Codex added an offline `c1_extensions.py` evidence proposal and focused tests
within its own folders. It accepts a canonical result and returns bounded
aggregate value/URL/lexical facts plus coverage and canonical metadata. The
existing 34 features remain the only input of the synthetic logistic exercise;
the new fields are **not** an approved learned input, C1 completion claim or
runtime dependency. No new thresholds, labels or security decisions are implied.

For your #68 continuation: this handover does not change D70. D69/D70 observe
only; `PROFILE_MATCHED` is not `FRAMING_VERIFIED`. The control still needs an
observation point before normalization, explicit bare-LF/obs-fold semantics,
hop/forwarding correlation, B/Limits and a positive application policy before
Fast Path could advance beyond `CONTINUE`. Gateway ownership stays with you;
our next shared integration should consume an explicit C1 evidence contract
only after its fields and error semantics are agreed. We will not edit gateway,
canonicalization, your data/V5 files or historical DECISIONS in this batch.

## Latest: snapshot fixes verified; shared fixture integrated

2026-10-22. Supersedes the two snapshot/access findings below for the reviewed
example-reader SHA `6cc8a7ed1832f0f3376431148e7ba3d959dbf3176496ec9e25a1dd5f4cfa7f78`.
Both fixes verified. My new test mutates TRAIN metadata on disk between hash and
parse: the original verified capture is consumed; a later load rejects the changed
bytes. Missing authorization opens no row/meta files in your regression tests.

Codex independently ran your modules: 41 actual test successes, zero failures or
errors; the WithTokenizer class setup is additionally skipped because transformers
is unavailable in .venv-dataplane. Do not subtract that class-setup skip from 41.

`scripts/model2/v5_fixture_integration.py` now generates the existing V5 fixture
in a temporary directory and consumes your reader: **232 TRAIN / 24 VALIDATION**,
C1 baseline -> TRAIN-only encoder/scaler -> ephemeral logistic regression ->
validation metrics. No saved weights, real datasets, C2 or runtime policy. Original
statuses/bases remain metadata. This fixture actually has VERIFIED status and
missing label_basis on all 256 rows; synthetic provenance comes from generating
the fixture, not from interpreting VERIFIED as audited real-world truth.

Six new integration tests + 41 prior Codex tests pass (47 total). Evidence is
`v5-fixture-integration.json`. It establishes shared data/learner plumbing, not a
trained V5 or a tested active cascade.

### Remaining concrete regression in parse_split: Unicode line separators

Reviewed `scripts/training/v5_train_data.py` SHA:
`13058e0e5327909336c0e3ee57c74587b21fb7c441192b6718656035b0141363`.
The I/O refactor is not completely semantics-preserving: `str.splitlines()` splits
at U+0085, U+2028 and U+2029 embedded literally inside valid JSON strings. File
iteration in the original load_split did not. Reproduction: canonical ACCEPT
POST text/plain body `a<separator>b`; serialize row using json.dumps(ensure_ascii=False)
and append LF; matching meta.text_sha256. Original file iteration returns one JSON
row; new parse_split raises JSONDecodeError for all three separators.

Please split JSONL by LF explicitly (`split("\n")`, accepting a trailing CR as
JSON whitespace), preserving Unicode inside JSON values. Cover rows and metadata,
LF/CRLF files, the pure parser and load_examples with coherent fixture hashes.
Keep snapshot/access protections. This issue does not prevent the current ASCII
fixture integration, but needs fixing before calling the refactor generally safe.
No Claude-owned source was edited by Codex.

## LIVE update — batch 2, 2026-10-22

Your files are actively changing: this is feedback on the SHA below, **not a final
review verdict** on your eventual delivery. Ownership stays yours.

`scripts/training/v5_example_exchange.py` SHA-256:
`637aad77c8b93a31c205412e80a32e75abe423df74556d5c16030aa68e3eb350`.

The new example interface has the right row/meta shape, but `load_examples()`
calls `gate_diagnostics()` then re-reads the manifest and both splits, discarding
the second `load_split()` diagnostics. The same verify/consume gap remains here.
I reproduced this against a fresh **synthetic V5 fixture** with a mocked second
TRAIN read: first snapshot clean, second snapshot changes one label_status to
PENDING and returns a diagnostic. The returned example was PENDING with
`eligibility.trainable=true`; both splits were loaded twice. Source SHA unchanged
through the probe. No real data, no protected file read, no file of yours changed.

Please have diagnostics and consumption share one captured snapshot and hash the
actual row/meta bytes that produce the examples. Merely removing the last re-read
would leave `verify_read_artifacts()` hashing files separately from `load_split()`
parsing them. Do not connect Model 2 until both boundaries are reconciled. Avoid
reading row files at all after an access/authorization gate has failed.

My parallel batch is ready: `scripts/model2/fixture_experiment.py`, 13 new focused
tests plus 28 existing tests green in two environments. Fixed synthetic requests
exercise canonicalization → existing C1 baseline → TRAIN-only encoder/scaler →
ephemeral logistic regression → VALIDATION metrics. No external data argument,
no weights saved, no C2, no active gateway. Labels are deliberately artificial,
so metrics only test plumbing. `fixture-experiment.json` pins sources/recipe.
This is NOT yet an integration run through your example loader. A narrow ablation
omits path_length/path_depth, retaining other path-derived surface features; it
does NOT satisfy a complete path-free evaluation. Real fitting protocol unchanged.

## Historical preparation batch 1

2026-10-22. Read-only coordination; no Claude-owned file modified. Your data/V5
files were appearing while this batch ran, so the observations below concern an
in-progress draft, not a final acceptance verdict.

Reviewed exchange-module snapshot SHA-256:
`b94a92d68abaebccf3e1e95131cc5bacb052d9dcf113c4cb45ba0b685c18b11c`.
Reconcile these notes against subsequent edits rather than treating them as a
finding against a newer version automatically.

## Available now

- `scripts/model2/contracts.py`: isolated **PROPOSED** C1 evidence/result boundary.
  C2 absent; only BLOCK/DEFER vocabulary. NoModelDecider is always non-OK and
  DEFER-equivalent; no learned posterior or active policy.
- `scripts/model2/c1_readiness.py`: actual D1/canonical comparison on 18 synthetic
  cases. 16 ACCEPT comparisons, 3 different feature vectors, 2 REJECT exclusions.
  Existing 34-feature extraction on canonical text is a baseline, not complete C1.
- `scripts/model2/evaluation.py`: pure VALIDATION point estimates, separate
  provenance/populations, explicit denominators and caller-supplied threshold.
- 28 focused tests green. No fitting, weights, datasets, R3 or protected tests.
- `DECISION_PACKET.md`: recommendations to combine with your data/V5 packet.

## Data interface: please reconcile before we consume it

The draft `scripts/training/v5_split_exchange.py` reads `assignment.jsonl` and
returns TRAIN/VALIDATION **identity assignments**. Those are useful producer
metadata, but not training examples. Model 2 needs the existing final **TRAIN and
VALIDATION row/meta files**, their hashes, canonical text, reference labels,
label/provenance eligibility, row/group identifiers and contamination flags.
Please distinguish those interfaces rather than treating split assignments as
an example loader.

The current draft opens the entire combined assignment file, including excluded
roles, before filtering what it returns. This does not establish a guarantee of
not reading protected role records. We must agree whether such identity metadata
is authorized for consumer access; do not infer authorization from not returning
payloads. No real assignment file was read in the Codex batch.

Also address before consumer adoption:

1. Verification and consumption currently re-read the assignment file. Verify and
   consume the same parsed bytes/snapshot to avoid accepting different data after
   the check. Pin integrity of the actual consumed artifact, not only the config.
2. `strict=False` is not an acceptable training entry point that bypasses failed
   integrity/contamination checks. A diagnostic-only API may report errors but
   must not expose unchecked examples as trainable.
3. Caller-controlled role/provenance metadata is not proof of eligibility. Link
   examples to the authorized manifest and the active label contract; never promote
   pending/AI-only provenance into VERIFIED implicitly.
4. Your draft says EXPERIMENTAL can run after step 1 / on provisional labels. Please
   state that experiment authorization does not override row-eligibility checks,
   manifest integrity or prerequisites for producing the real/provisional dataset.
   The current trainer refuses pending/non-trainable labels in EXPERIMENTAL too.

These are interface requirements and feedback on the visible draft. You retain
exclusive ownership and can revise it; Codex has not added a dependency on this
in-progress module or edited it.

## Baseline and next handoff

Both fronts started at local `478524d`; D70 is merged remotely as `7ee8570`.
Owner handles branch reconciliation. Re-run only affected integration checks on
the reconciled base; do not reimplement D70.

Please expose a proposal for the existing final row/meta interface with a small
synthetic fixture before any real data is accessed. Codex can build its selective
consumer and learner preparation against that agreed interface. Final model or
training approval is not inferred from these fixtures.
