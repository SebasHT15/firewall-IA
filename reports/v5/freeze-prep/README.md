# V5 Data Specification — freeze preparation (issue #64)

Date: 2026-10-11. Branch: `research/v5-data-spec-freeze-prep` (= `develop` = `5ce8c99`).

**Status (original, sessions 1–3): review, not a decision.** *(2026-10-12: the decisions were later approved and recorded as D56–D61, and the specification is DRAFT r3, still not frozen; see "Session 4".)* The specification is **not frozen**, and no `DECISIONS.md` entry was written at that stage. None of the following happened:
- training, model runs or benchmarks;
- dataset generation;
- any runtime, `inference_core` or fail-closed change;
- any change to frozen artifacts;
- any use of External Test v1 cases;
- any commit.

| File | Content |
|---|---|
| [`A_http_representation_audit.md`](A_http_representation_audit.md) | Workstream A: V4 train vs serve representation, framing, the proposed `canonical-request/v1` contract |
| [`B_dataset_engineering_audit.md`](B_dataset_engineering_audit.md) | Workstream B: reusable components, V4 defects not to carry over, family gaps, shortcut checks S1–S20, labeling, generator structure, manifest |
| [`C_validation_protocol.md`](C_validation_protocol.md) + [`consumed_sets.json`](consumed_sets.json) | Workstream C: protected/consumed-set inventory, D40 status, partitioning, acceptance gate, rejection, training and evaluation protocol, freeze-report template |
| `../v5-data-spec-draft/README.md` | The specification, revised to **DRAFT r2** |
| [`D_sources_provenance.md`](D_sources_provenance.md) | *(Session 3, 2026-10-11.)* Source licences verified against official sources; a minimal source set; privacy; the pre-freeze mandatory list |
| [`E_attack_pool_audit/`](E_attack_pool_audit/) | *(Session 3.)* PATT attack-pool label audit: n = 395, stratified, seed `v5-attack-audit-v1`. LLM-assisted, with a coordinator blind second annotation of 40 items |
| [`F_tokenizer_input_bounds.md`](F_tokenizer_input_bounds.md) | *(Session 3.)* Special-token evidence (#65), a safe tokenization method, length distributions, the `MAX_TEXT` procedure |
| [`G_labeling_and_split_proposal.md`](G_labeling_and_split_proposal.md) | *(Session 3.)* Final PROPOSED labeling policy (P4), split algorithm (P5) and D15 controls |

> **Session 3 note.** §6 below records the **first-round** recommendations. After the second critical review all five are **MODIFY**. The current proposals awaiting owner approval are in `G_…` (P4, P5) and in the session-3 report for P1–P3. None is approved yet. *(Updated 2026-10-12: all five were then approved with adjustments as D56–D60, plus D61; see "Session 4" at the end.)*

Tags: **FACT** (verified in code, data or a report; cited), **INFERENCE**, **PROPOSAL**.

## 1. Verified project state

| Item | State | Evidence |
|---|---|---|
| V4 (TinyLlama + QLoRA) is the only runtime decision maker | IMPLEMENTED | `data_plane/data_plane.py:102-126` renders the D1 text; D34 enforcement; D43 (features are shadow only) |
| Analyzer v2 | FROZEN, offline baseline, not integrated | D54, D55; `reports/hybrid/phase2b-analyzer-v2-run-002/` |
| Hybrid Architecture C1/C2, Decision Model | PROPOSED (research notes C2, D2) | `reports/v5/research-notes-v2/README.md`: "RESEARCH NOTES, not decisions" |
| V4 FP diagnostics (audit, probe v1, probe v2, evidence matrix) | DONE, development data | PR #61, PR #63; issue #62 closed |
| V5 Data Specification | DRAFT (r1 → r2 here), **not frozen** | this review |
| External Test v1 | FROZEN at `36df2ee`. The D40 tripwire is **not triggered** | manifest unedited since `36df2ee`; no transition record (C §2) |
| `datasets/v4_clean/` | present, gitignored, pinned by manifest SHA-256 | `verify_manifest` returns ok (B §10) |

Everything stated in the task brief matched the repository. One addition: `README.md:168` frames V5 as "a possible TinyLlama revision" for the external false positives. That is consistent with D45.

## 2. Workstreams

All three subagents ran with `model: sonnet`, passed explicitly to the Agent tool. The tool accepted the parameter, but its result does not echo back the model that actually served the run, so this report states the request, not a verified model identity. No subagent was escalated to Opus.

Scope rules for every subagent:
- read-only git;
- create-only file rules;
- no edits to existing files;
- no External v1 case reads.

The coordinator (Opus 5.5) spot-checked each one's key claims against code and data (§3).

| WS | Created | Tests | Coordinator verification |
|---|---|---|---|
| A — HTTP representation | `A_http_representation_audit.md`, `tests/test_v4_representation_contract.py` (40 characterization tests pinning **current** behaviour) | `.venv-dataplane`: 40 OK. Plain python3: 40 OK with 21 skipped (mitmproxy absent). With `test_data_plane` + `test_request_features`: 120 OK | Re-counted CL = 9 rows (A: 9 ✔), TE header lines = 5 (one `Transfer-Encoding ` with a trailing space; ✔), `%25XX` = 3,473 BLOCK / 0 ALLOW (✔). Confirmed `render_request` behaviour at `data_plane.py:102-126` |
| B — dataset engineering | `B_dataset_engineering_audit.md`, `scripts/dataset/v5_dataset_checks.py`, `tests/test_v5_dataset_checks.py` (31 tests) | python3 3.14 and `.venv-analyzer` 3.12: 31 OK each | Confirmed nominal benign group ids (`parse_dataset_v4.py:1330-1333` vs `:1373-1376`, `:853-865`), the tautological invariant (`:1409-1414`), `HOSTS` reused as the benign URL pool (`:151-162`, `:933-936`). Reviewed the code: stdlib only, imports `canonical_key` / `check_dataset`, outputs counts and indices only |
| C — validation and reproducibility | `C_validation_protocol.md`, `consumed_sets.json` (19 entries) | n/a (no code by design) | All 19 entries resolve on disk. Confirmed the D40 status. Mapped the `B:*` labels to B's real function names (coordinator note added in C) |

Work division: B owns the check utilities and C owns the thresholds and protocol. This avoided two overlapping validator modules.

## 3. Review findings on the r1 specification

**Blocking gaps (FACT about r1):**

1. **r1 conflicts with an APPROVED decision.**
   - r1 §5 removes `Content-Length`/`Transfer-Encoding` from the ML text. D1 requires preserving them, and D44 says V5 stays under D1.
   - A shows the clause is now either unreachable or information-free: conflicting framing is rejected by mitmproxy before the addon, and valid framing carries no attack information. A shows it is also skewed: TE appears on only 5 training rows (all BLOCK) and CL on only 9 (6 BLOCK, 3 ALLOW; §S4). TE flipped V4 in 18 of 33 baseline-ALLOW pairs. *(Wording corrected 2026-10-12.)*
   - It is still an amendment the owner must make → **P1**.
2. **r1 keeps `Host`/`User-Agent`/`Accept` in the canonical text.**
   - D44's rationale applies, and `real-http-fp-v1` showed V4 flipping on loopback Host, high ports, the Chrome UA and `Connection: close` (development data).
   - Dropping `Host` creates a **new gap found in this review**: V4's CSRF category is defined as Origin/Referer being cross-origin *relative to Host* (`parse_dataset_v4.py:438-443`). The proposed allowlist could not express it → **P2**.
3. **r1 specifies only the benign side.**
   - No attack source, slot compatibility, placement or category scope.
   - Nothing on V4-clean (reuse or rebuild) or CSIC.
   - No value source for addresses or free text → **P3** (B §3, §9).
4. **r1 has no labeling policy.** Redirect-role URLs, internal targets, credential stuffing, quoted attack syntax, HPP → **P4**.
5. **The r1 split cannot be executed.** It specifies leave-provider-out with two licensed providers. B2 already called that degenerate → **P5** (C §3).

**Non-blocking findings resolved in r2 with existing evidence:**

6. **D15's held-out separation does not hold in V4's rendered text (FACT, new).**
   *(Corrected 2026-10-13: as recorded in D61, D15 was not literally violated, because no held-out transform ever ran. Its purpose is compromised for double-encoding forms. The 137 lowercase-hex rows are native PATT bytes, not renderer output; see the second review and D61.)*
   - V4-clean TRAIN contains `%25XX` double encoding in 3,473 BLOCK / 0 ALLOW rows and lowercase-hex escapes in 137 BLOCK rows.
   - Cause: the renderer's `quote(..., safe="")` re-encodes the outputs of the `url_encode` training transform and payloads that are already percent-encoded (`parse_dataset_v4.py:708-711, 757-763`).
   - These are the forms of the held-out `double_url_encode` and `mixed_case_percent` families.
   - Consequences:
     - V5 rule (r2 §2.2): encode exactly once, and test it.
     - V4 disclosure: a future held-out evasion suite (E6, issue #29) would not be held out for those two families. This belongs in V4's limitations; this review did not edit those documents.
7. **V4 benign JSON was mostly not JSON:** 661/764 JSON-typed ALLOW bodies (A X11). This is a plausible mechanism for matrix #9/#10 (INFERENCE). r2 requires body syntax to match `Content-Type` (A G2).
8. **Benign group identity in V4 was nominal** (B §2.2). r2 requires rendering from the declared tuple, with an assertion.
9. **V4's leakage invariant was tautological** and was backed by a silent removal (B §2.10). r2 requires counted gates instead.
10. **Benign URL values reused envelope hosts**, including `localhost:8080` and `target.internal.com` labelled benign (B §2.6). r2 forbids this.
11. **Merged and contingent families:** apostrophes merged into punctuation; nested JSON merged into JSON; chunked made contingent on P1, because under B or C it becomes invariance test I4.

**Hypotheses, not facts:**
- "Real clients almost always send CL or chunked."
- "The canonical form will reduce FPs."
- "Payloads seen by V4 inflate a V4-vs-V5 comparison."

None is measured. The protocol (C §6) is designed to test the last two.

## 4. Changes made

**Documentation:**
- `reports/v5/v5-data-spec-draft/README.md` rewritten as DRAFT r2 (status tags, §2.2 attack side, §4 pairing/labels/keys, §5 contract, §7–§8 gate and manifest, §10 decisions, §11 history).
- `reports/v5/freeze-prep/` created (this README, A, B, C, `consumed_sets.json`).
- One coordinator note added in `C_validation_protocol.md`.

**Code and tests (new files only; no existing file modified):**
- `scripts/dataset/v5_dataset_checks.py` + `tests/test_v5_dataset_checks.py`: generic, read-only V5 checks. They:
  - import `canonical_key` (D16) and `check_dataset.load_jsonl/sha256`;
  - add no dependencies;
  - work on any text field (whole request or leaf);
  - return results with no request text.
- `tests/test_v4_representation_contract.py`: pins current V4 serving and training representation (including behaviours flagged as defects), so any later change is deliberate.

Not changed: `DECISIONS.md`, `CONTEXT.md`, `README.md`, runtime code, the V4 generator, every frozen dataset and report.

## 5. State of the specification

**Pending concrete decisions (P1–P5).** It is not blocked by missing evidence: every decision has an evidence-backed recommendation.

When P1–P5 are decided, the spec can be marked ready for freeze after the following edits:
1. Replace each PENDING tag with the chosen option.
2. Fill in L (oracle length) and the source licences.
3. Write the corresponding `DECISIONS.md` entries, with the owner's authorization.

Thresholds marked PROPOSED (C §4) are calibrated on a non-protected **pilot build** (plan stage 6) and fixed in the preregistration. They do not block the freeze of the specification itself.

## 6. Owner decisions (maximum five)

> **Historical (first round, 2026-10-11).** Superseded by D56–D60 and V5 DRAFT r3. Kept unchanged as the record of what was proposed.

### P1 — Canonical form of the V5 ML text, and D1 for V5

- **Problem.** Training and serving use different renderers. Framing headers are skewed: in training TE appears only on 5 BLOCK smuggling rows and CL on 9 rows (6 BLOCK, 3 ALLOW; §S4), while at serving every chunked client shows TE. TE flipped V4 in 18 of 33 baseline-ALLOW pairs. *(Wording corrected 2026-10-12.)* D1 requires keeping CL/TE in the text.
- **Alternatives:**

  | Option | Description | For | Against |
  |---|---|---|---|
  | Keep D1 as is | Framing headers stay in the text; add a chunked family | No decision change | Keeps skews X1–X6. Trains on smuggling text the serving path never produces |
  | **B** | Validate and remove framing; every other header stays | Smallest delta | Unbounded header noise remains; no invariance story |
  | **C (minimal)** | Validate; fixed grammar, header allowlist, de-chunked and decoded body, byte-preserving target and body; one shared `canonicalize()`; reject, never truncate | Removes X1–X6 by construction; testable invariants I1–I10 | Amends D1's CL/TE clause for V5; the text is a view, not the forwarded bytes |
  | **C2** | C plus a synthetic `Content-Length` | Keeps D1's wording | The header adds tokens and carries no information |

- **Recommendation: C (minimal)**, with deterministic rejects (A P3a) and `validate_inbound_headers=true` pinned by a test when the data plane is later touched.
- **Evidence:**
  - A §3–§6: X1–X19, top findings 2, 3 and 6;
  - framing note facts 1–8;
  - probe v1: TE 18/33, CL 1/33.
- **Consequence:**
  - The chunked family becomes invariance test I4.
  - Smuggling rows become validator vectors.
  - Plan stage 1 implements `canonicalize()` standalone.
  - A `DECISIONS.md` entry amends D1 **for V5 only**.

### P2 — Header allowlist and the structural categories

- **Problem.**
  - Which headers V5 sees. `Host`, UA and other envelope headers are a measured sensitivity (`real-http-fp-v1`) and D44's rationale.
  - What happens to categories whose signal is structure, not a payload:
    - Request Smuggling: 7 groups in V4, not evaluable.
    - CSRF: depends on `Host`.
    - HPP: 20 groups; the same syntax as benign arrays.
- **Alternatives (allowlist):**
  - (a) Keep the V4 envelope with shared distributions.
  - **(b) `Content-Type`, `Origin`, `Referer`, `Authorization`.**
  - (c) (b) + `Cookie`.
- **Alternatives (structural categories):**
  - **Smuggling:** ML category vs validator vectors.
  - **CSRF:**
    - keep `Host` in the text;
    - **compute the origin relation (same / cross / absent vs `Host`) in the canonicalizer as an audit-record signal for a deterministic policy;**
    - render the relation as a derived text line.
  - **HPP:**
    - keep with privilege-name semantics (contradicts matrix #2);
    - **leave the ML scope for V5 (INSUFFICIENT DATA) and include benign repeated-name arrays as coverage.**
- **Recommendation:**
  - Allowlist (b).
  - Smuggling → validator test vectors.
  - CSRF → deterministic origin-relation signal.
  - HPP out of the ML scope for V5.
  - Cookie-borne families are a later, evidence-gated addition.
  - V5 then covers 16 of V4's 19 categories as ML. The other three are handled deterministically or reported as INSUFFICIENT DATA. That is consistent with D14's "report, never inflate", but the change of scope must be recorded as a decision.
- **Evidence:**
  - A §5–§6;
  - `parse_dataset_v4.py:438-457` (`CAUSAL_EXCEPTIONS`);
  - D14 counts;
  - `reports/hybrid/v4-analyzer-paired-dev-v1/` (V4's misses there are header-borne JWT/CSRF, which supports keeping `Authorization`/`Origin`/`Referer`);
  - `real-http-fp-v1` summary.
- **Consequence:**
  - The generator emits no CSRF/HPP/Smuggling rows.
  - The audit record carries the origin relation.
  - A CSRF policy rule is future work outside V5 training.
  - The decision affects D1 (envelope clause) for V5 and is consistent with D44.

### P3 — Dataset composition and sources

- **Problem.** r1 does not say whether V5 is V4-clean plus new families or a rebuild, where attack twins come from, whether CSIC stays, or which licensed sources supply addresses and prose.
- **Alternatives:**
  - (a) V4-clean + appended families. This inherits V4's defects (B §2: fixed pools, attack-only encoding, non-JSON JSON, nominal groups, shortcut sources) and its training text cannot pass the canonical contract.
  - **(b) A rebuild with the new generator, reusing V4's *payload extraction* (PATT `e961fef2`) through the attack-leaf operator.**
  - (c) A rebuild with a new attack corpus. Not justified by evidence (D21).
- **CSIC:**
  - drop entirely; or
  - **anomalous excluded** (keyword-heuristic labels, audit F6), **normal kept** only as a provider family with generated twins, capped. Dropping is the simpler fallback.
- **Sources:**
  - Addresses and prose need licence-verified sources before freeze (candidates UNVERIFIED, r2 §3).
  - Synthetic compositional generation is allowed, but its grammar becomes a fingerprint (B R4), so it must be diversified.
- **Recommendation:**
  - (b).
  - CSIC normal as a twin provider family, otherwise dropped.
  - Licence verification is a precondition of freeze.
  - V4 eval payload groups are kept out of all V5 splits (C L7).
- **Evidence:** B §1–§3, §9; D13, D21; manifest `datasets/manifest_v4_clean.json`.
- **Consequence:** This defines plan stage 2 (sources) and stage 4 (labels). It needs a D13 successor for V5.

### P4 — Labeling of ambiguous cases

- **Problem.** The same bytes can be legitimate or malicious depending on the role of the slot:
  - redirect-role names with external URLs;
  - URLs to internal or loopback targets;
  - passwords;
  - text quoting attack syntax and legitimate query DSLs;
  - values like `5'11"`, `a<b`, `#hashtag`, IP-as-data.
- **Alternatives and recommendation (B §5.2):**
  - **Redirect URLs.** Slot-role lexicon (navigation vs callback roles), with both labels present for **every** name, so the name alone never decides. Alternatives: exclude external URLs from benign redirect names, or drop Open Redirect.
  - **Internal / metadata / loopback targets.** BLOCK as a documented *policy* label.
  - **Credential stuffing.** NOT TESTABLE (stateful); payload-in-password is the attack twin.
  - **Quoted syntax and DSLs.** Excluded and counted as `AMBIGUOUS_EXCLUDED`.
  - **Primitive-like values.** Allowed in benign only through the payload-level oracle, with quotas in both classes.
  - **Oracle length L.** Fixed at freeze. Suggested: the minimum attack-pool canonical payload length used by `quality_filter`; to be confirmed on the pilot.
- **Evidence:**
  - matrix #8 and remaining-unknown 4;
  - B §5;
  - audit F5;
  - `paired_dev_set.oracle_check` precedent.
- **Consequence:** These rules are written into `label_rule`. Every excluded row is counted. Plan stage 4.

### P5 — Split unit and external-evaluation regime

- **Problem.** r1's leave-provider-out split has two providers: TRAIN would be one provider and there would be no VALIDATION. External v1 is pristine, but V5's purpose (fixing FPs) puts pressure on opening its errors.
- **Alternatives:**
  - **Option A:** `family_id` hash split 70/15/15, provider as a stratum, pools partitioned at element level.
  - Option B: leave-provider-out with ≥ 5 licence-verified providers.
  - Option D: A plus two provider-transfer trainings, report-only, at extra QLoRA cost.
  - External regime: **Branch P** (v1 pristine; at most one aggregate V5 run) vs Branch C (consume v1; External v2 mandatory).
- **Recommendation:**
  - Option A, with the mandatory disclosure that INTERNAL TEST measures unseen *structural families of seen providers*, not unseen providers.
  - Branch P.
  - **Build External v2 either way.** It is required for any V5 external claim under D40, and it must carry the byte-equivalence and CSIC-ancestry checks.
  - Ratify the stability gate G1–G5 in the training preregistration.
  - Confirm that V4-clean TRAIN rows are not reused verbatim in V5 TRAIN (follows from P3 b).
- **Evidence:** C §2–§4, §6; B2 lines 134-136; D37, D40, D53/D54 precedents.
- **Consequence:** This fixes the split function and salt for plan stage 3. External v2 becomes its own issue, in parallel with the generator.

**Minor items, deferred to the stage that needs them:**

| Item | Deferred to |
|---|---|
| `MAX_TEXT` / `MAX_TARGET` (measure with the tokenizer) | stage 1 |
| `OPTIONS` method | stage 1 |
| JSON *keys* as injection points (NoSQL operators) | stage 4 |
| `placement_mode` shares | stage 4 |
| Meta sidecar vs extra columns (sidecar recommended; `finetune.py` not tested with extra columns) | stage 6 |
| Exact S1–S7 thresholds (pilot calibration) | stage 7 |
| `+` vs `%20` and other encoder-set membership | stage 5 |

## 7. Reusable components ready now

| Component | State |
|---|---|
| `v5_dataset_checks.find_duplicates / check_group_disjointness / check_label_consistency / verify_manifest / check_protected_collisions` + CLI | IMPLEMENTED, TESTED (31) |
| `consumed_sets.json`: protected-set inventory with text fields and per-split collision policy | Ready as input to `check_protected_collisions` (JSONL entries; CSIC CSV and source-embedded sets need the payload-level path noted in C) |
| `tests/test_v4_representation_contract.py`: baseline of current behaviour; future `canonicalize()` tests are written against it | IMPLEMENTED, TESTED (40) |
| Import list for the generator: `canonical_key`, `group_id`, `build_envelope` (wrap), `extract_sources`/`quality_filter`/`build_hardcoded_sources`, `TRAIN_TRANSFORMS`, `check_dataset.fit_predict_accuracy/parse_request`, `audit_v5_benign_coverage.extract_markers/aggregate`, the `guarded_path` pattern, the `git_state` idiom | Identified (B §1) |
| Contract `canonical-request/v1`, invariants I1–I10 and G1–G5 | PROPOSED (A §7–§8) |
| Acceptance gate, rejection conditions, freeze-report template, reproducibility checklist | PROPOSED (C §4–§8) |

## 8. Implementation plan for the V5 generator (after the freeze; not started)

> **Note (2026-10-12).** Stage 0's decisions are **done** (D56–D61). The freeze still needs a separate owner authorization. The freeze does **not** require the PENDING constants to be resolved: they are resolved at stage 1 (template constants) and stage 6 (pilot thresholds), as DRAFT r3 states. Where the stages below conflict with DRAFT r3 (file names aside), r3 wins: the header allowlist, 70/10/20, a single `STAB-HELD`, the E6 reserve, the post-filter audit.

Each stage is meant to become **one issue and one small PR**. Every stage:
- keeps V4, the runtime and the frozen artifacts untouched;
- adds unit tests on small synthetic data;
- stops for owner review if its stop condition fires.

**Stage 0 — Decisions and freeze (documentation only)**
- **Goal:** record P1–P5; spec r3 = FROZEN.
- **Files:** `DECISIONS.md` (owner-authorized), spec README, an `SHA256SUMS` for the spec.
- **Depends on:** owner.
- **Tests:** none.
- **Accept when:** no PENDING tags remain.
- **Risk:** scope creep in the decisions.
- **Stop if:** any P remains open.

**Stage 1 — `canonicalize()` standalone**
- **Goal:** the shared pure function, stdlib only, importable from both environments (D33).
- **Files:** `data_plane/canonical_request.py` (new; not wired into `data_plane.py`), `tests/test_canonical_request.py`.
- **Depends on:** P1, P2.
- **Tests:** I1–I10, framing vectors (the smuggling texts become reject vectors), and a tokenizer measurement that sets `MAX_TEXT` (ML env, read-only).
- **Accept when:**
  - all invariants pass;
  - `tests/test_v4_representation_contract.py` still passes unchanged (V4 untouched);
  - `test_data_plane` is green.
- **Risks:**
  - mitmproxy-specific parts leak into the pure function. Mitigation: an adapter layer.
  - The allowlist hides header-borne attacks (accepted in P2).
- **Stop if:** an invariant cannot hold without changing V4's serving path.

**Stage 2 — Sources and pools**
- **Goal:** pinned inputs.
  - Attack pool through imported V4 extraction.
  - OpenAPI skeletons for licence-verified specs.
  - Value pools with licence records and `pools_sha256`.
- **Files:** `scripts/dataset/v5_sources.py`, `tests/test_v5_sources.py`, a config file with lexicons and K.
- **Depends on:** P3.
- **Tests:**
  - determinism;
  - the identity-strip rules (no vendor tokens, RFC 2606 hosts only, H1);
  - **probe-pool element disjointness (C L8)**;
  - forbidden-input guard;
  - licence record present for every source (A4).
- **Accept when:** every pool is hashed and licensed, and L8 = 0.
- **Risk:** licences unavailable. Then the family is labelled INSUFFICIENT DATA and nothing is fabricated.
- **Stop if:** a HIGH family has no admissible source.

**Stage 3 — Identity and split**
- **Goal:** `template_id`, union-find `family_id`, `pair_id`, `payload_group_id`, element-level pool partition, k-way split before rendering.
- **Files:** `scripts/dataset/v5_groups.py`, `tests/test_v5_groups.py`.
- **Depends on:** P5.
- **Tests:**
  - A3: permutation and `PYTHONHASHSEED` invariance;
  - twins never straddle splits;
  - `check_group_disjointness` on synthetic fixtures.
- **Accept when:** split map deterministic and disjoint.
- **Risk:** small strata cannot reach the C1 minimums. Then families move to evaluation; the minimums are never lowered.
- **Stop if:** C1 is unreachable for a HIGH family.

**Stage 4 — Labels, oracle, attack-leaf operator**
- **Goal:** `label_rule`, slot-compatibility matrix, benign oracle, placement modes, excluded-row accounting.
- **Files:** `scripts/dataset/v5_labels.py`, `tests/test_v5_labels.py`.
- **Depends on:** P2, P4.
- **Tests:**
  - the oracle keeps `O'Neil`, `Apt #4`, `AT&T`, `100%` and rejects payload-bearing values;
  - every BLOCK row maps to the D47/V4 reason vocabulary;
  - label consistency (M1).
- **Accept when:** 0 unlabeled rows, and every exclusion is counted.
- **Risk:** the oracle's false-reject rate empties the punctuation family. Measure it on the pilot.
- **Stop if:** oracle rejects exceed a pilot-agreed share.

**Stage 5 — Rendering**
- **Goal:** client profiles (encoders, framing, header sets) sampled independently of the label; carriers and serialisations in both classes; D15 training variants recorded; text produced **only** through `canonicalize()`.
- **Files:** `scripts/dataset/v5_render.py`, `tests/test_v5_render.py`.
- **Depends on:** stages 1–4.
- **Tests:**
  - I2 (generator text == canonicalize(parts));
  - G1: encoding features independent of the label;
  - G2: body parses under `Content-Type`;
  - G3: allowlist only;
  - single encoding, no held-out transform forms (§3 finding 6).
- **Accept when:** all pass on synthetic fixtures.
- **Risk:** encoder sets introduce new fingerprints. Covered by the S6 check.
- **Stop if:** G1 cannot hold for a family.

**Stage 6 — Orchestration, manifest, pilot build**
- **Goal:** `v5_generate.py` CLI, meta sidecar, manifest (B §8), embedded check outputs; a **small pilot build** (non-protected, never used for evaluation claims) to calibrate thresholds.
- **Files:** `scripts/dataset/v5_generate.py`, `tests/test_v5_generate.py`.
- **Tests:**
  - A1 (`verify_manifest`);
  - A2 (two runs, two `PYTHONHASHSEED` values, byte-identical);
  - L1–L9 via `v5_dataset_checks`.
- **Accept when:** the pilot passes every implemented check, and determinism is proven.
- **Risk:** pilot thresholds get tuned to pass. Mitigation: thresholds are fixed in writing before the full build.
- **Stop if:** any BLOCKING check fails twice for the same cause.

**Stage 7 — Shortcut audits and checker self-tests**
- **Goal:** S1–S7 (reusing `check_dataset.fit_predict_accuracy` and `audit_v5_benign_coverage.aggregate`) and A5 mutation self-tests for every blocking check.
- **Files:** `scripts/dataset/v5_shortcut_audit.py`, tests.
- **Depends on:** stage 6 pilot.
- **Tests:** one injected violation per check fires; clean fixtures pass.
- **Accept when:** A5 is green.
- **Risk:** thresholds too loose to matter.
- **Stop if:** a known V4 shortcut (for example `%25XX`) is not detected when injected.

**Stage 8 — Stability sets**
- **Goal:** `STAB-DEV` / `STAB-HELD` generator (new seed and lexicon), element-disjoint from probes and V5 pools.
- **Files:** `scripts/evaluation/v5_stability_sets.py`, tests.
- **Depends on:** stages 1, 2, 5.
- **Tests:** C4, L7/L8/L9 on the sets; counts per carrier ≥ 100 control.
- **Accept when:** both sets are frozen and hashed before any training.
- **Risk:** authorship overlap with the probes (disclosed, C §10).
- **Stop if:** disjointness fails.

**Stage 9 — Full generation and freeze report**
- **Goal:** full build, the complete C §4 gate, the freeze report (C §8 template), manifest `status: FROZEN`. Owner approval is required.
- **Files:** `datasets/v5/` (gitignored, pinned by manifest), `reports/v5/dataset-freeze-v1/`.
- **Accept when:** every BLOCKING check passes and every WARNING has a written ruling.
- **Stop if:** any R1–R10 condition holds. The version is then rejected and preserved; a new version id follows.

**Parallel track (separate issue):** External v2 protocol and capture tooling (C §6.6). This can start as soon as P5 is decided.

**After stage 9 (separate, owner-gated):** training preregistration, V5 training, single INTERNAL TEST and `STAB-HELD` read, External v2.

## 9. Git status at the end of this session

See the final report in the session. Everything is left **uncommitted** for owner review. No commit, push, branch, merge or PR was made by the coordinator or any subagent.

---

## Session 4 (2026-10-11/12): decisions approved, DRAFT r3

**Approved by the owner (with adjustments) and recorded in `DECISIONS.md`:**

| Decision | Covers |
|---|---|
| D56 | P1: `canonical-request/v1`; modifies D1's scope for V5 only |
| D57 | P2: `Content-Type`-only text; control layers; coverage terminology; extends D44 |
| D58 | P3: composition and sources; V5 successor of D13 |
| D59 | P4: labeling and metadata |
| D60 | P5: split, protected evaluations, E6 reserve |
| D61 | Documented V4 limitations; addendum to D15 and D20 |

The specification is **DRAFT r3** (`../v5-data-spec-draft/README.md`): decisions approved, **not frozen**.

**Superseded first-round material in this folder.** §6 and §8 above, the 4-header allowlist in `A_…` §7, the 70/15/15 split and `STAB-DEV` in `C_…` §3, and the "PROPOSED" status of `G_…` are superseded by D56–D60 and DRAFT r3 where they differ. The reports are kept unchanged as historical evidence, each with a dated pointer at its top.

### §S3. Third-party deny-list impact (exact; coordinator, 2026-10-12)

The V4 extraction (`extract_sources`, pinned PATT `e961fef2`) was re-run in memory. A payload is kept if its `canonical_key` occurs in at least one non-denied file. The DRAFT r3 §3.1 deny-list matched **20 files**. `port_swigger_xss_cheatsheet_event_handlers.txt` was added after the r3 review, because its name identifies a third-party origin. The files are:
- `dotdotpwn.txt`;
- `JHADDIX_LFI.txt`;
- 8 × `FUZZDB_*.txt`;
- `Generic_TimeBased.txt`;
- `0xcela_event_handlers.txt`, `BRUTELOGIC-XSS-JS.txt`, `BRUTELOGIC-XSS-STRINGS.txt`, `JHADDIX_XSS.txt`, `MarioXSSVectors.txt`, `RSNAKE_XSS.txt`, `xss_alert.txt`, `xss_alert_identifiable.txt`, `port_swigger_xss_cheatsheet_event_handlers.txt`.

| Category | Unique canonical payloads before | After the deny-list |
|---|---:|---:|
| SQL injection | 1,278 | 1,000 |
| XSS | 2,238 | 705 (819 without the PortSwigger file) |
| Directory traversal | 10,219 | 173 |
| File inclusion | 3,321 | 2,778 |
| Traversal ∪ file inclusion (D49) | 13,157 | 2,828 |
| All other categories | unchanged | unchanged |

These counts precede the structural filters, the `payload_family_id` collapse, the E6 reserve and the split. Evaluability is computed after all of them (D60).

### Second annotation and human-review preparation

Details are in `E_attack_pool_audit/` README §11.
- The second annotator was a different model: a Claude Opus subagent, blind to the first labels.
- Agreement with the first annotator (Sonnet): κ = 0.863 on usable vs not, κ = 0.881 on INCORRECT vs not.
- The coordinator adjudicated 37 disagreements; 9 are recoverable residue.
- A blind, stratified sample of 95 rows is prepared for independent human review. **Not yet reviewed.**
- LLM agreement is not human validation.

### Residual items (none blocks a spec freeze; all block later stages as noted)

1. **Human review** of `E_attack_pool_audit/human_review/human_review_sample.csv` (owner or another person). It informs the post-filter gate; the post-filter audit itself is a dataset acceptance condition.
2. **V5 template constants** (template overhead, label budget, bytes-per-token bounds) are re-measured at generator stage 1, before the pilot.
3. **PROPOSED thresholds** in DRAFT r3 §7 are ratified in the dataset preregistration after the pilot build.
4. **Deny-list review** file by file, and the third-party notices policy, at generator stage 2. Unverified files stay excluded.
5. **Housekeeping at implementation time:** an explicit `.gitignore` entry for the V5 dataset directory; pinning `validate_inbound_headers=true` with a test (gateway-integration phase).
6. **External v2:** a separate issue, required before any V5 external claim (D40). It does not gate the data freeze.

### §S4. V4-clean TRAIN header and category counts cited by D56/D57 (coordinator, 2026-10-12)

Reproduce with `python3 reports/v5/freeze-prep/s4_v4_train_header_counts.py datasets/v4_clean/train.jsonl`. Output is aggregates only. The population is 25,134 rows.

| Measure | Count |
|---|---|
| `Content-Length` header | 9 rows: 6 BLOCK, **3 ALLOW** (the benign framing counterparts) |
| `Transfer-Encoding` header | 5 rows, all BLOCK |
| `Authorization` header | 137 rows: 95 BLOCK, 42 ALLOW |
| JWT-category rows | 95. Only 1 value starts with `Bearer eyJ` |
| Benign `Authorization` values | all 42 share one JWT header segment (`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`, HS256) |
| CSRF rows | 38: 27 have an `Origin` containing "evil" or "attacker", 11 have `Origin: null` |
| `Origin` and `Referer` | always co-occur: 66 rows (28 ALLOW, 38 BLOCK) carry both, 0 carry only one |
| `Cookie` header | 6,952 BLOCK / 6,931 ALLOW |

---

## Session 5 (2026-10-13): final freeze-readiness review

### Human review mechanism

The human review reuses the existing blind sample (`E_attack_pool_audit/human_review/`). It adds three subcommands to `scripts/dataset/audit_v5_attack_pool.py`, each unit-tested (22 tests in total):
- `human-batch`: prints one label-blind batch of 12 and creates an empty `human_labels.csv` template once;
- `human-compare`: refuses to run until all 95 rows are labelled; then it compares the human labels with the adjudicated LLM labels and lists the disagreements;
- `human-sample`: now refuses to overwrite the fixed sample.

Earlier annotation files were not modified; their SHA-256 values were checked before and after. **The review itself is the owner's and has not started.**

### Requirements by phase

| Phase | Requirement | Status |
|---|---|---|
| **Before the spec freeze** | D56–D61 approved | met |
| | r3 implements them, with APPROVED / PROPOSED / PENDING tags consistent | met after the session-5 corrections (§S5) |
| | Licences verified for the chosen sources | met (`D_…`) |
| | Attack-pool audit accepted as exploratory evidence | met (owner, 2026-10-11) |
| | Tokenization and size **contract** defined | met. The constants are deferred, with a procedure and a stop rule (r3 §5.5) |
| | Acceptance criteria documented and verifiable, with fixing procedures for deferred thresholds | met (r3 §7, pilot procedure) |
| | Owner ratifies the PROPOSED procedural detail of r3 (§4.6, §5.2–§5.6) by authorizing the freeze | **pending, owner** |
| | Explicit freeze authorization | **pending, owner** |
| **During the generator pilot** (stages 1–6) | V5 template constants, `B`, bytes-per-token bounds | pending |
| | `L`, placement shares, per-file cap, deny-list file review and notices | pending |
| | PROPOSED thresholds tightened or ratified in `dataset-preregistration-v1` | pending |
| | `.gitignore` entry for the V5 dataset directory | pending |
| **Before the dataset freeze** | Human review of the 95-sample completed and compared | pending, owner |
| | Post-filter audit per ML-primary category: two LLMs of different models, adjudication, human subsample ≥ 20, gate pass, otherwise demotion | pending |
| | All BLOCKING checks pass (r3 §7), including byte-identical regeneration | pending |
| | `STAB-HELD` built and sealed | pending |
| | Freeze report (C §8 template) | pending |
| **Before training V5** | Training preregistration: checkpoint rule, C-G1–C-G5 stability gate ratified, metrics | pending |
| | Template-safe tokenization implemented identically in training and inference (D56) | pending |
| | Dataset FROZEN | pending |
| **Before gateway integration of V5** | `canonicalize()` wired in behind a switch | pending |
| | `validate_inbound_headers=true` pinned and tested; R1 wire-level tests | pending |
| | `MAX_DECODED_BODY` fixed | pending |
| | Client-visible reject status and policies for unsupported media types, `S-OVERSIZE` and `CONNECT` | pending |
| | External v2 built (D38/D40) before any V5 external claim | pending |
| | #65 decision for V4 (separate) | pending |

### §S5. Session-5 corrections to DRAFT r3 (documentary; no approved decision changed)

Three independent Sonnet audits (A: contract and tokenization, B: dataset, labels and sources, C: split, evaluations and reproducibility) found no error in the approved decisions themselves. They found ambiguities and mis-tagging in r3, corrected as follows:

1. **Status tags.** Several r3 details had been written after approval, so they cannot carry the APPROVED tag. They are now tagged **PROPOSED, binding at the spec freeze**, with only the D56–D60 principles marked APPROVED:
   - §4.6 numeric and procedural split detail;
   - §5.2 byte rules;
   - the §5.3 R/S lists;
   - the §5.6 invariant list;
   - the §4.3 concrete lists and precedence;
   - the §2.3 tiering.
2. **Split (§4.6) made unambiguous:**
   - explicit rounding (`floor(x + 0.5)`, minimum 1 when n ≥ 3, lowest ranks to TEST);
   - NUL-joined hashes;
   - payload families ranked once across categories;
   - merges before ranking (merged id = smallest member);
   - `R = ceil(0.08·n)` with forced native-form families inside R;
   - an explicit with-reserve / without-reserve / NOT EVALUABLE procedure;
   - the cluster share defined as rows of the cluster over rows of the split;
   - quota rebalancing defined;
   - rulings approved by the owner.
3. **Size (§5.5).** The data-plane `48·B` reject now applies only to media types inside §2.2; outside them the outcome is the `S-OVERSIZE` signal, which removes a contradiction. Fixing procedures and stop rules were added for every deferred constant: `label_budget` from the fixed output vocabulary, which is non-circular; the margin; the byte bounds; `MAX_DECODED_BODY`, deferred to integration and set ≥ `48·B`.
4. **Labeling (§4.3).**
   - The `POL-URL-SCHEME`-over-loopback exception is stated.
   - `POL-URL-META` is described as link-local plus metadata.
   - A single-reason precedence is defined for EXCLUDED rows.
   - `attack_category` and reason strings are defined for `POL-*` rows and for merged traversal / file-inclusion rows.
5. **Post-filter gate (§7).**
   - It now covers every ML-trained category.
   - Stratification, adjudicator and blind human review are defined.
   - Human condition tightened to a point estimate ≤ 20%.
   - Failure means exclusion from TRAIN (D58 "must pass"); at most one re-audit.
   - The pre-filter 95-sample does not satisfy the gate.
6. **Pilot and threshold procedure (§7).**
   - Pilot at a 10% quota.
   - Thresholds may only be tightened, or loosened by a written owner ruling.
   - Preregistration in `reports/v5/dataset-preregistration-v1/`.
   - Stop after two failures with the same cause.
7. **Versioning and protection.**
   - Dataset version ids; INTERNAL TEST identities never move to TRAIN.
   - `STAB-HELD` single-read guard.
   - External v1 run only after the INTERNAL TEST read.
   - E6 reserve use rule.
   - Manifest additions.
8. **Coverage (§2.3).**
   - The column (5) definition is fixed.
   - Hand-asserted NOT EVALUABLE becomes "expected (computed)".
   - The smuggling row's wording is corrected.
9. **Sources (§3).**
   - The PATT unnamed-origin MIT coverage is a disclosed assumption.
   - Content-identified third-party files (`XSSDetection.txt`, `Auth_Bypass*.txt`) are added to the stage-2 review.
   - The Tatoeba personal-data filters are referenced.
10. **Evidence documents.**
    - Dated "superseded" pointers added to `D_…`, `B_…` and `F_…`.
    - The item-6 wording in this README corrected to match D61.
    - The `E_…` R5 gate pointer added.
    - The residual textual-marker risk added to `CONTEXT.md`.

**Not changed (flagged to the owner instead).** D56 says the byte rules are "exactly as DRAFT r3 §5.2 defines", and §5.2 is PROPOSED detail. Authorizing the freeze ratifies r3 §5.2 and makes the reference consistent. `DECISIONS.md` was **not** edited in session 5.

---

## Session 6 (2026-10-13): specification FROZEN (D62)

The owner authorized a **scoped freeze** of r3. The specification is now `V5-DATA-SPEC-r3`, with SHA-256 `f1580634…5958d9cb`, recorded in `../v5-data-spec-draft/SHA256SUMS` and in D62.

**Ratified as binding:**
- §4.6;
- §5.2–§5.6;
- the §4.3 classes, contexts, separation of responsibilities and precedence.

**Excluded from the freeze**, kept in r3 §11.2 with when and how each is resolved:
- the 2% / 5% cluster-share thresholds;
- the 1% over-limit stop value;
- the fuzz-corpus size;
- the template constants and `B`;
- the byte bounds;
- `MAX_DECODED_BODY`;
- the §7 thresholds;
- the §2.3 category distribution;
- the open §4.3 lists and lexicons;
- `L`, the placement shares, the per-file cap and the final deny-list.

**Corrections made before freezing:**
- the §4.6 "everything else becomes binding" ambiguity was replaced by explicit FROZEN and PROPOSED lists;
- the §4.3 freeze scope was delimited;
- the `\xNN` escape-ambiguity limitation is stated, and the text no longer claims that the audit signal disambiguates for the model.

The plan in §8 now starts at **stage 1**. Stage 0 (decisions and freeze) is done. The human review of the 95 items and the other conditions of r3 §11.3 are mandatory before the **dataset** freeze.
