# V5 data/training readiness — Claude parallel front (2026-10-22)

**Branch:** `feat/hybrid-training-integration` (shared with Codex). **Base:** `478524d` (#85 merge).
**Scope:** data preparation / V5 only. Codex owns C1 + Model 2 (`scripts/model2/`, `tests/model2/`,
`reports/v5/hybrid/model2-readiness/`) — read-only for me. **V4 keeps the current authority; nothing here
activates a new decision, trains on pending material, or ratifies an open value.** This is my own report
for owner review, per the "propuesta en un reporte propio antes de pedir decisiones" instruction.

## 0. Base / Git state (verified, no refs changed)

- D70 (observe-only framing evidence) is **merged into `develop` via PR #86** (`b433505`), but this training
  branch sits at `478524d` and does **not** contain it yet. I did **not** re-implement or hand-copy D70;
  resolving the base is the owner's. All my work here is on data/V5 files independent of the gateway.
- Working tree clean at start. I changed no refs/branches/worktrees/stashes and no Codex files.

## 1. Reconciliation — #77 / #80 / #82 and the V5 pipeline (what is BUILT vs PENDING)

The V5 data+training code is **far more complete than a greenfield**; most of the "readiness" gap is
decisions/data, not missing code. Chronology distinguished from current state:

| Area | State now | Evidence |
|---|---|---|
| Benign pools + `names_family` | **ACQUIRED and integrated (D68, merged #84)** — do not re-acquire or reopen | `build_v5_benign_pools.py`, git `76f7ab0`, memory `v5-pool-integration` |
| Generator / render / oracle / labels | **BUILT + tested** (fixtures) | `scripts/dataset/v5_generator.py`, `v5_render.py`, `v5_oracle.py`, `v5_labels.py`; `test_v5_generator.py` |
| Identities / split / split-invariants | **BUILT + tested** — `v5-split-assignment/v1`, SPL-1…SPL-9 | `v5_identities.py`, `v5_split.py`, `v5_split_checks.py`; `test_v5_split.py`, `test_v5_identities.py` |
| Tokenization / output contract | **BUILT + tested** | `control_plane/v5_tokenization.py`, `v5_output_contract.py`; `test_v5_tokenization_contract.py` |
| Trainer (SMOKE/EXPERIMENTAL/FINAL gates) | **BUILT, SMOKE-ready, FINAL-blocked by gates** | `scripts/training/{v5_train_data,finetune_v5}.py`; `test_v5_training_gates.py`; memory `v5-training-readiness` |
| Spec **r4** | **FROZEN by D67** (SHA `54514850…`); touched §7/§11.2/§11.3 | `reports/v5/v5-data-spec-r4/FREEZE.md` |
| Trainer support for r4 | **NOT active** — `SUPPORTED_SPECS=("V5-DATA-SPEC-r3",)`; r4 activation is the **#80 unapplied patch** | `v5_train_data.py:68`; `reports/v5/data-readiness/proposals/final-gate-ai-audit.patch` |
| #77 post-filter attack-pool audit (R3) | **OPEN** — per-category PASS/FAIL not produced; R3 not run here | issue #77; memory `v5-d67-r4-recovery` |
| #80 r4 audit-provenance + FINAL authorization | **OPEN** — design exists as the reviewed patch; schema unratified | issue #80 |
| #82 real-data pilot integration | **OPEN** — no REAL build/split committed | issue #82 |

## 2. Exact gap to a REAL, eligible dataset (mapped to `gate_final` F1–F9)

Classified as **[CODE]** (missing/activatable code), **[DECISION]** (owner ratification), **[DATA]** (an
artifact that must be produced), so nothing blocked by a decision is hidden as a technical task.

1. **F1 REAL build + build gates** — [DATA] a real generator build (`manifest.status=REAL`, `gates.ok=true`); #82.
2. **F2 every generator value RATIFIED** — [DECISION] cluster-share thresholds, B, template, vocabulary are PROPOSED (§11.2).
3. **F3 attack labels = `post_filter_audit`** — [DATA] the #77 audit must PASS per category; R3 adjudication pending (blind session).
4. **F4 dataset preregistration committed, hash in manifest** — [DECISION+DATA] §11.2 values must be fixed and preregistered.
5. **F5 dataset freeze record covering §11.3** — [DATA] not produced. NB the trainer encodes **r3** §11.3 only.
6. **F6 training preregistration pinning recipe+template+vocabulary+dataset** — [DECISION+DATA] not committed.
7. **F7 recipe RATIFIED section-by-section** — [DECISION] the recipe is PROPOSED except `quantization` (APPROVED, D11).
8. **F8 token budget B consistent (manifest == recipe)** — [DECISION] B is a PROPOSED candidate (415), not an approved default.
9. **F9 clean tree + pinned libraries** — [CODE/ENV] reproducible; library pins are PROPOSED.
10. **r4 activation** — [CODE+DECISION] `SUPPORTED_SPECS` + `FREEZE_ITEMS` must gain `V5-DATA-SPEC-r4` deliberately; that is the #80 patch, which stays unratified (see §4).

**No example loader/validator is on the critical path that does not already exist.** The data pipeline
has them; my code adds the two *consumer-facing* contracts Codex needs (an example loader and a metadata
reader), reusing the existing loaders, plus the defect repairs Codex reproduced.

## 3. Code delivered (deliverable 3) — the EXAMPLE interface + the metadata reader (fixture-tested)

Two consumer-facing modules under my ownership (new), both reusing existing loaders, both IMPLEMENTED and
tested on synthetic fixtures — **no real pool, no real split, no training**:

### 3a. `scripts/training/v5_example_exchange.py` — the training-EXAMPLE interface (what Model 2 needs)
Exposes the existing final `rows.{split}.jsonl` / `rows.{split}.meta.jsonl` examples through the gated
`v5_train_data` loaders (`load_manifest`, `verify_read_artifacts`, `load_split`, `check_rows`,
`check_disjoint`, `recipe_vocabulary`, `IDENTITY_KEYS`). It returns a documented per-row example schema
(`text`, `output`, `label`, `label_status`, `label_basis`, `text_sha256`, `identities`, `manifest_sha256`,
`eligibility`) and enforces — **no bypass, any diagnostic raises**: only TRAIN/VALIDATION rows+meta are
opened (INTERNAL_TEST / E6_RESERVE / slices / the combined assignment are NEVER opened — a test spies on
`open()` to prove it); row/meta alignment and `text_sha256` are checked over the **bytes actually
consumed**; row eligibility (`label_status ∈ {VERIFIED, POLICY_DEFINED}`, not excluded/sliced, output in
vocabulary, label/output consistent) and TRAIN × VALIDATION disjointness hold; **fixture (SMOKE, no
authorization) is distinguished from authorized-real (EXPERIMENTAL, requires a committed
`v5-experimental-authorization/v1`)**. It never turns a V4/V5 decision into a label and never promotes an
AI-audited / policy-defined provenance into VERIFIED. Tests: `tests/test_v5_example_exchange.py` — **10 OK**.

Two further defects Codex reproduced in this reader, now **fixed with regressions**:
- **Single capture (no TOCTOU).** It previously verified via `gate_diagnostics` and then RE-READ the files
  (and the hashed bytes could differ from the parsed bytes). Now `_load_and_check` reads each allowed
  file's bytes ONCE, hashes THOSE bytes against the manifest `sha256`/`bytes`, and parses the SAME bytes
  (via a small behaviour-preserving refactor of `v5_train_data` — a new pure `parse_split(text)` that
  `load_split` now delegates to). Test asserts each allowed file is opened exactly once and a PENDING row
  with coherent hashes still fails on eligibility (`LABEL_NOT_TRAINABLE`), never returned as trainable.
- **Access gate before any open.** An access-gate failure (schema/spec, or missing EXPERIMENTAL
  authorization) now STOPS before opening any rows/meta file — in both the diagnostic and consume APIs.
  Test spies on `open()` and asserts ZERO rows/meta opens on an authorization failure. (The spy is
  test-only; the production module patches no `open()`.)

**Regression from my own `parse_split` refactor, now fixed (Codex caught it).** The refactor used
`str.splitlines()`, which also breaks JSONL on U+0085 / U+2028 / U+2029 — characters that are valid,
unescaped, inside a JSON string value — so a row/meta value containing one was wrongly split (the old
file-iterator split on LF/CRLF only). Fixed in BOTH `v5_train_data.parse_split` and
`v5_split_exchange._read_once`: split JSONL on **LF only** (accepting a trailing CR for CRLF), never on
Unicode line/paragraph separators (JSON strings never contain a literal LF/CR, so LF is the only true
record separator). Regressions: a `parse_split` unit test over all three characters in rows AND meta with
coherent `text_sha256`; a facade `load_examples` test with a LITERAL U+2028 in `text` and coherent
artifact hashes (loads, preserves the char); and a `v5_split_exchange` test with a literal U+2028 in a
record value (not split).

### 3b. `scripts/training/v5_split_exchange.py` — split-assignment METADATA reader (NOT an example loader)
Kept as a metadata tool for the `v5-split-assignment/v1` identity artifact, with Codex's four reproduced
defects **fixed** (see §4-bis) plus the LF-split fix above. Tests: `tests/test_v5_split_exchange.py` — **15 OK**.

Run: `.venv-dataplane/bin/python -m unittest tests.test_v5_example_exchange tests.test_v5_split_exchange`
→ **25 tests OK** (Python 3.12; stdlib-only deps); the `v5_train_data` refactor stays behaviour-preserving,
covered by `tests.test_v5_training_gates` (**19 OK, 1 pre-existing skip**). Ready for Codex to import.

**Executed vs verified (owner's distinction).** What these tests EXECUTE: the clean fixture load, the
open()-spy (exactly-once + no protected-role open), the access-gate-before-open behaviour, the
single-capture integrity (tampered bytes refused; PENDING-with-coherent-hashes refused), and the four
split-assignment defect regressions — all on the synthetic fixture, with no real data. What remains a
VERIFIED-by-reading-only guarantee (NOT test-executed here): the producer's full SPL-1…9 suite (the
consumer re-checks disjointness and artifact hashes, not the whole suite), and the #80 provenance/
authorization gates (unapplied patch — see §4). I do not present either as test-executed.

### 3c. Fixture loader vs REAL loader — the real `names_family` read path already exists and is fixture-tested
That `v5_fixture.py` invents synthetic pools does **not** by itself prove the real read path. It exists and
is tested without the real snapshot: `scripts/dataset/build_v5_benign_pools.py::load_pinned` +
`build_name_pool` (source `POOL_SOURCE["names_family"]="wikidata_family_names"`, builder schema
`v5-benign-pools/v1`, pinned snapshot dir `reports/v5/data-readiness/names_family-candidate/`), exercised by
`tests/test_v5_benign_pools.py` (`test_names_family_results`) against `tests/fixtures/v5_benign`
(real file layout, fake content) — it opens **no** real snapshot. So this is **not** a code gap; the real
build (#82) is a DATA/decision step, not missing code. I did not open the real pool.

### 4-bis. The four reproduced defects in `v5_split_exchange.py` — fixed with regressions
1. **`strict=False` bypass removed** — `load_exchange` no longer takes `strict`; a contaminated artifact can
   never yield data (it raises). `verify_exchange` is diagnostic-only and returns no data.
2. **No TOCTOU** — the artifact is read ONCE; verify and consume use the SAME parsed snapshot.
3. **Content integrity** — the consumed `assignment.jsonl` bytes are hashed against the manifest's recorded
   `assignment_sha256` (an assignment-only edit is caught), with an optional trusted `expected_assignment_sha256`.
   Disclosed limitation: `config_sha256` authenticates only the config; a coordinated rewrite of both the
   assignment and its recorded digest is self-consistent and passes the hash — it is still caught
   structurally (IDENTITY_MULTIPLE_SPLITS / TRAIN_VALIDATION_OVERLAP), and true authenticity needs an
   external trusted digest. Not a self-accepted file-derived digest.
4. **Type/field validation** — each record must be a dict with a known `kind`, a non-empty `id` and a known
   `split`; malformed/non-dict records are refused (`MALFORMED_RECORD`) and never returned.

**Distinction the owner asked for:** a producer guarantee *recorded in an artifact* (config/assignment
hashes, an identity list, the manifest's SPL summary) is **not** the same as a check the consumer actually
runs. My loaders re-execute at consume time: artifact-hash verification, row/meta alignment + text hash,
row eligibility and TRAIN × VALIDATION disjointness. They do **not** re-derive the full SPL-1…9 suite
(that is the producer's, in `v5_split_checks.py`); the consumer relies on it being recorded and re-checks
disjointness defensively.

## 4. Review of the #80 patch (`final-gate-ai-audit.patch`) — deliverable 4 (NOT applied)

665-line unapplied patch (SHA `470050c3…`) against develop `c5adceb`; touches `finetune_v5.py`,
`v5_train_data.py`, `test_v5_training_gates.py`. **Review verdict: sound and conservative; keep as an
isolated proposal pending ratification — do not apply here.** It correctly:

- Keeps `SUPPORTED_SPECS=("V5-DATA-SPEC-r3",)` **active**; r4 is left OUT with a comment that adding it is a
  deliberate one-line owner-reviewed step. An r4 manifest is therefore **refused**, not silently accepted.
- Separates **four concepts** the owner named: (1) audit *provenance* (`audit_type`; PROPOSED manifest field,
  absent today ⇒ FINAL refuses; never inferred from `attack_label_basis`), (2) category *outcome*
  (`PASS_AI_AUDITED` only makes a category eligible; FAIL/INSUFFICIENT/unknown refused), (3) row
  `label_status` (an `ai_audit` basis can **never** be `VERIFIED` → `AUDIT_CONFERRED_VERIFIED`), (4) a
  **separate** owner training authorization (`v5-ai-audit-training-authorization/v1-PROPOSED`; schema id
  inert ⇒ every ai_audited FINAL refused even with a record). This is exactly "AI_AUDITED ≠ VERIFIED" and
  "FINAL authorization ≠ protocol approval".
- Adds negative tests. Nothing is downgraded; unknown provenance is refused, not defaulted.

**Concern / what remains:** the authorization schema and the row `label_status_basis` provenance contract
are unratified; applying the patch does **not** authorize training or ratify its contracts. Recommendation
(table below): ratify the authorization schema + provenance field names, then take the one-line
`SUPPORTED_SPECS` activation — reviewed, never implicit.

**Status of the #80 synthetic provenance/authorization checks — PENDING, NOT executed.** I did *not* run
them. The patch's negative tests exercise code (`check_audit_rows`, `check_audit_category_outcomes`, the
`ai_audit`-aware `gate_final`, F10) that lives **only in the unapplied patch**; executing them would mean
applying the patch, which I am deliberately not doing while the schema is unratified. So the separation is
reviewed-by-reading, not test-executed here. Their existence in the patch is **not** evidence that they
pass against the live tree. Unblock: once the schema/provenance fields are ratified and the patch applied
(owner step), those negative tests run as part of `test_v5_training_gates.py`.

## 5. Pending-decision table (deliverable 5) — recommendation · rationale · consequence

`B=415` and the other candidates are **not** approved defaults. **Correction (owner feedback):**
EXPERIMENTAL is NOT "just an authorization" — the authorization does not waive row eligibility, artifact
integrity, or the requirements to have actually *built* a (provisional) dataset. The current trainer
refuses pending / non-trainable labels in EXPERIMENTAL too (rows must be `VERIFIED`/`POLICY_DEFINED`, and
the authorization must state `uses_pending_labels_as_verified:false`). FINAL additionally needs ratification
of the starred rows + the #77 audit + prereg + freeze + training-prereg + clean tree + pins.

| # | Decision | Recommendation | Rationale | Consequence if unset | EXP? | FINAL? |
|---|---|---|---|---|---|---|
| D-a | Token budget **B** (§11.2) | Preregister B from measured token lengths before FINAL; keep 415 as a *candidate* only | `measure_v5_token_lengths.py` exists; 415 is D63-provisional | F8 mismatch refuses FINAL | candidate ok | ★ required |
| D-b | Template id | Ratify `V5_CANDIDATE_TEMPLATE` or revise | D63 candidate, not frozen | F7 refuses FINAL | candidate ok | ★ required |
| D-c | Vocabulary | Ratify `PILOT_VOCABULARY` (alt B) or revise | owner pilot #70 | F7 refuses FINAL | candidate ok | ★ required |
| D-d | Cluster-share warn/block (§11.2) | Preregister thresholds; keep `status:PROPOSED` until then | `v5_split` refuses non-PROPOSED pre-prereg | F2 refuses FINAL | ok (PROPOSED) | ★ required |
| D-e | Recipe sections (lora/optim/loss/pins) | Ratify section-by-section after a SMOKE + a provenance check | only `quantization` is APPROVED (D11) | F7 refuses FINAL | ok | ★ required |
| D-f | r4 trainer activation (#80) | Ratify the authorization schema + provenance fields, then take the one-line `SUPPORTED_SPECS` step | patch reviewed, sound, isolated | r4 manifest refused | n/a | ★ required |
| D-g | Attack-label audit (#77/R3) | Run R3 in the blind session; require per-category `PASS_AI_AUDITED` | `attack_label_basis=post_filter_audit` is F3 | F3 refuses FINAL | EXP needs a built dataset whose rows are eligible (not fixture) | ★ required |
| D-h | EXPERIMENTAL run authorization | Issue a `v5-experimental-authorization/v1` naming one manifest, `provisional:true`, `uses_pending_labels_as_verified:false` | gates EXP, but does NOT waive row eligibility / integrity / the need for a built dataset | no EXP run (and the authorization alone is insufficient) | ★ required | n/a |

**EXPERIMENTAL vs FINAL:** EXPERIMENTAL = provisional, authorized data for one manifest, artifacts marked
provisional, **no performance claim**; FINAL = all starred rows ratified + #77 audit + prereg + freeze +
training-prereg + clean tree + pins. `AI_AUDITED/PASS_AI_AUDITED ≠ VERIFIED`; FINAL authorization ≠ protocol
approval.

## 6. Reproducible first EXPERIMENTAL run plan (deliverable 6) — manifest+authorization gated

No training happens until eligible data + explicit authorization exist. Dry-run gate check first:

```
# 1. Gate-only (loads no model) — shows exactly what a given manifest is missing:
python3.12 scripts/training/finetune_v5.py --mode experimental \
  --dataset <GENERATOR_OUT_DIR> --authorization <AUTH.json> --gate-only \
  --report-dir reports/v5/training-readiness/exp-dryrun
# 2. Only if gate PASSES: the same command without --gate-only runs the provisional fine-tune.
```

Preconditions (ALL must hold, else the gate refuses and nothing trains — the authorization alone is
insufficient): a non-fixture manifest that was actually BUILT; an `v5-experimental-authorization/v1` record
whose `dataset_manifest_sha256` matches, `scope=EXPERIMENTAL`, `provisional:true`,
`uses_pending_labels_as_verified:false`, with `authorized_by/date/reference/purpose`; and rows that pass
eligibility (`label_status ∈ {VERIFIED, POLICY_DEFINED}`, not excluded, output in vocabulary) and
TRAIN × VALIDATION disjointness. Artifacts are provisional — not a V5-quality claim, not FINAL.

**Consume ONLY the fixture TRAIN/VALIDATION examples (no real data, no authorization needed):**

```
# build a synthetic stage-4 fixture, then read its eligible TRAIN/VALIDATION examples:
python3.12 scripts/dataset/v5_fixture.py generate --out /tmp/v5fix --quiet
python3.12 scripts/training/v5_example_exchange.py --dataset /tmp/v5fix     # prints CONSUMABLE: {TRAIN, VALIDATION}
```

A SMOKE fine-tune on that fixture (`finetune_v5.py --mode smoke --dataset /tmp/v5fix`) validates the
pipeline end-to-end with **no** real data; per the owner this batch does not require re-running a GPU SMOKE
(the trainer already has that evidence).

## 7. The interfaces for Codex (Model 2 ↔ V5) — two distinct contracts, no parallel format

**Do not invent a parallel format.** Two existing contracts, with my two consumer modules on top:

**(a) EXAMPLES — what Model 2 trains/validates on → `v5_example_exchange.load_examples(dir)` (§3a).**
The examples are the existing `rows.{split}.jsonl` + `rows.{split}.meta.jsonl` (stage-4 generator output).
Each returned example carries: `text` (the `canonical-request/v1` ACCEPT text — the learned input),
`output`/`label` (reference), `label_status` + `label_basis` (eligibility + provenance — metadata, never a
feature, never promoted to VERIFIED), `text_sha256` (integrity over consumed bytes), `identities` (the
`IDENTITY_KEYS`: `text_sha256`, `pair_id`, `payload_family_id`, `payload_record_id`, `struct_cluster_id`,
`template_id`, `value_entries` — row/group/contamination ids), `manifest_sha256` (binds the example to the
authorized manifest), `eligibility`. The loader opens ONLY TRAIN/VALIDATION files, enforces eligibility +
disjointness, and distinguishes fixture (SMOKE) from authorized-real (EXPERIMENTAL). **This is the interface
Codex should build its selective consumer and learner-prep against.** Synthetic example (fixture):
`{"split":"TRAIN","text":"<canonical text>","output":"BLOCK | …","label":"BLOCK",
"label_status":"POLICY_DEFINED","label_basis":"policy_defined","text_sha256":"…",
"identities":{"payload_family_id":"…","struct_cluster_id":"…", …},"manifest_sha256":"…",
"eligibility":{"trainable":true}}`.

**(b) SPLIT METADATA — who-is-in-which-split → `v5_split_exchange` (§3b), `v5-split-assignment/v1`.**
Identity→split roles (cluster/template/payload_family/value_entry), seeded and deterministic, so **neither
model's output ever becomes the other's label**. Exclusions/contamination are the producer's SPL-1…9
(identity disjointness, E6 never in a split, near-duplicate bound, value groups never span splits);
`INTERNAL_TEST`/`E6_RESERVE` are never training inputs. This is **metadata**, not examples — consumers
should not open the combined assignment to then filter; the example loader (a) already restricts itself to
TRAIN/VALIDATION row files.

**Shared discipline:** no V4/V5 decision is ever a label; AI-audited/policy-defined provenance stays
distinguishable and is never implicitly promoted to VERIFIED; metadata is for validation/grouping/reporting,
not features. **C2 is out of scope:** no Analyzer predictions to seed a C1-only baseline, no trained V5
required to tune Model 2. Model 2's observed population today is *all* traffic (Fast Path ineligible); a
later active Fast Path changes that population and its metrics do not silently transfer. Joint evaluation on
protected sets is reserved to the approved protocol.

## 8. Unblock order for a first REAL run

1. Ratify the §11.2 values (B, template, vocabulary, cluster-share) → **preregistration committed**.
2. Run R3 (#77) in the blind session → per-category `PASS_AI_AUDITED` → attack labels `post_filter_audit`.
3. Ratify the #80 authorization schema + provenance fields → take the one-line r4 `SUPPORTED_SPECS` step.
4. REAL generator build (#82) → `manifest.status=REAL`, `gates.ok=true`, value statuses RATIFIED.
5. Commit the **dataset freeze record** (§11.3 of the manifest's spec revision) + the **training
   preregistration** (pins recipe+template+vocabulary+dataset) + ratify the recipe sections.
6. Clean tree + pinned libraries → `gate_final` empty → FINAL may start. (EXPERIMENTAL can run after step 1
   with a written authorization **and a built provisional dataset whose rows pass eligibility
   (`label_status ∈ {VERIFIED, POLICY_DEFINED}`, in vocabulary, not excluded) + artifact integrity** —
   **not on provisional labels** — for engineering only, with no performance claim. Per §5/§6 the trainer
   refuses pending/non-trainable labels in EXPERIMENTAL too, and the authorization alone is insufficient.)

## Limits honoured

No R3 here (blind session only); no reading of `datasets/v4_clean/eval.jsonl`, INTERNAL_TEST, E6_RESERVE,
STAB-HELD or individual External cases; no full `tests.test_data_plane` / its regression / broad discovery;
no real split/build/freeze/train, FINAL, SSRF, Q4_K_M, production pins or active policies; no missing
authorization disguised as a technical failure or papered over with substitute data. No commits/push/PR/
merge/branch/worktree/stash changes — the owner publishes. No Codex files touched. Historical DECISIONS are
append-only; **no new approval is recorded in this report** — these are recommendations for owner decision.
