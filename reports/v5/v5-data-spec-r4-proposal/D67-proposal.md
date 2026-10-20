# D67 — V5 post-filter audit: AI-assisted review in place of the unavailable human review (APPROVED 2026-10-20, rev 4)

- **Date:** 2026-10-19 drafted; **APPROVED 2026-10-20** (America/Costa_Rica). **Status:** **APPROVED** — registered in
  `DECISIONS.md` as **D67**; `V5-DATA-SPEC-r4` adopted and **FROZEN** (`reports/v5/v5-data-spec-r4/`, SHA-256
  `54514850…`); acceptance criteria preregistered and sealed
  (`reports/v5/postfilter-audit/preregistration/v5-postfilter-prereg-r4.json`, `1039a3dd…`) before any R3 output.
- **Issue:** #77.
- **Spec:** `V5-DATA-SPEC-r4` (PROPOSED). The companion `r3-to-r4-minimal.diff` is a **syntactically valid unified diff**
  that applies with `git apply -p1` to a copy of `reports/v5/v5-data-spec-draft/README.md` and reproduces r4
  byte-for-byte (verified SHA-256 `54514850…` on an isolated copy). The frozen r3 (`f1580634…`) is **not** edited.
- **Revision history:** rev 1 (prose) lost/overwritten, recoverable only from the prior transcript; its *diff* preserved
  at `_preserved/r3-to-r4-minimal.rev1.diff`. rev 2 partial at `_preserved/D67-proposal.rev2-partial.md`. rev 3 at
  `_preserved/D67-proposal.rev3.md` and `_preserved/r3-to-r4-minimal.rev3.descriptive.diff`. rev 4 is this file. Nothing
  is deleted.

> **APPROVED (D67, 2026-10-20).** The §8 acceptance values are preregistered and **frozen before** any R3 output
> (C-R6). Approval is of the **methodology only**: the dataset remains pending audit — **no category is PASS and no
> payload is `VERIFIED`** because the methodology was approved. R3 has not run. FINAL training stays **BLOCKED** (§11).

---

## 1. What is preserved, unchanged (decision 1)

- The frozen r3 text (`f1580634…`), **D58, D62 and D66** as historical records, and the APPROVED decisions D56–D65.
- Every round-1 artifact with its identifiers, hashes and seeds: the sample (`eb001e95…`, seed
  `v5-postfilter-audit-r1-2026-10-19-d66`), the 200-item subsample (`8667a427…`), packets, batches, `round_status.json`,
  `agreement_report.json`, `report.md`/`report.json`, `adjudication_rules.json`.
- The annotations: a1 = `claude-sonnet-5-5`, 453/453 (`ea956073…`); a2 = `claude-haiku-5-5`, 453/453 (`c497d098…`);
  the supplementary `claude-opus-5-5` partial (377 rows, descriptive only, not in the gate).
- The agreement result (351/453 exact, 102 disagreements = 69 V/P + 33 gate-relevant, κ as recorded), the 69 V/P
  decisions under `vp_split_to_probably_correct/v1` with its trace, and the 33-disagreement list.
- No evidence is overwritten, relabelled, redrawn or deleted. This proposal changes **procedure for the next step**.

## 2. Post-hoc methodological deviation (disclosed; no equivalence) (decision 2)

- D58 and r3 §7 require an independent, **blind human** review whose labels prevail on a stratified subsample.
- This proposal substitutes an **AI-assisted review**. The owner proposed it **after** the round-1 LLM results existed
  and after seeing their aggregate counts — a **post-hoc change of evidence type**, in tension with the spirit of C-R6.
- **The AI-assisted review is not methodologically equivalent to human review, and nothing here claims it is.** Every
  D67 result is labelled **"AI-audited — no independent human review"**.
- The reason is the unavailability of specialised human reviewers: a **constraint, not a justification of quality**.

## 3. Reviewers and roles (decision 3)

- **a1, a2** — the round-1 annotators, one provider: a1 `claude-sonnet-5-5`, a2 `claude-haiku-5-5`. Frozen inputs; not
  re-run.
- **R3** — a third reviewer, an LLM from a **different provider**, run **blind** to a1/a2. **Proposed: ChatGPT GPT-6.**
  The **exact model designation actually exposed at execution time**, the execution date and available configuration
  metadata are recorded then, with R3's raw output kept. **No internal model revision is invented.** R3 is **not a
  human**: its labels never "prevail".
- **Adjudicator** — the coordinator for the reproducible rule (§6); the **owner** for anything `UNRESOLVED`. Owner
  adjudication is **evidence-based** and permits procedural disposition, exclusion, or commissioning additional review;
  **it does not automatically establish ground-truth correctness** (decision 9). Each decision is traced.

## 4. Status and label vocabulary — kept distinct (decisions 11, 12)

None of these is conferred by model agreement.

| Term | Level | Meaning | Not |
|---|---|---|---|
| `VERIFIED` | per-payload (`label_status`, D59) | provenance **and** value structure independently established | **never** from any audit, LLM consensus, or R3; the audit leaves `label_status` untouched |
| `AI_AUDITED` | provenance tag on any D67 result | audit done with LLM reviewers, **no independent human review** | not a quality grade; not `VERIFIED` |
| `PASS_AI_AUDITED` | per-category gate status | §7 AI-audited conditions met → category **eligible** for V5 TRAIN | **strictly weaker** than a human-validated pass; confers no payload `VERIFIED` |
| `INSUFFICIENT_EVIDENCE` | per-category | coverage/resolution not met (§7.3) | not a quality FAIL; category **not supported** until evidence completed |
| `PENDING_*` | per-round/category state | `PENDING_ADJUDICATION` / `PENDING_HUMAN_REVIEW` as recorded in round 1 | not an acceptance |
| `FAIL` | per-category | a quantitative condition (§7.1) violated on resolved evidence | — |

- A `PASS_AI_AUDITED` category is reported as **AI-audited, not VERIFIED by humans**, everywhere.
- **Consensus between models (a1, a2, R3) can never raise a payload to `VERIFIED`.**

## 5. Three evidence types — never conflated (decision 11)

1. **Model disagreement** — a signal of uncertainty only. **Never reported as empirical ground-truth error.**
2. **Adjudicated quality classification** — the label the §6 rule assigns, under a stated rule applied to AI labels;
   not an independently established fact.
3. **Independently established error** — a payload shown wrong against a **trusted reference label**, which this project
   **does not have** for the post-filter pool. Therefore the **true annotator error rate is not establishable**.
   **Deterministic/stratified sampling alone does not prove statistical representativeness**; the §7 Wilson bounds
   describe the **adjudicated audit sample under the stated sampling assumptions**, never ground-truth error.

## 6. Reproducible adjudication rule (r4) (decisions 8, 9)

Per item, in order; both original a1/a2 labels kept; every decision traced.

1. **Agreement.** a1 = a2 → that label (R3 is a minority vote and does not override a concordant pair).
2. **Approved V/P rule.** Exactly one of {a1, a2} = VERIFIABLE, the other = PROBABLY_CORRECT, no UNCERTAIN/INCORRECT →
   PROBABLY_CORRECT (`vp_split_to_probably_correct/v1`, unchanged; gate effect none).
3. **Majority — only with all three present.** For a1 ≠ a2, a strict majority of {a1, a2, R3} is used **only when all
   three reviewer labels are present**.
4. **No majority / missing vote.** A **three-way disagreement** (three distinct labels) **or any missing required vote**
   → **`UNRESOLVED`**, routed to an identified **evidence-based** owner decision (never automatic INCORRECT). A missing
   response is a non-vote, never scored as a correct or incorrect label.

> There is **no automatic most-adverse tie-break** anywhere in this rule.

## 7. Gate definition (per ML-trained category)

### 7.0 Populations and denominators (decision 7)

- **Audit frame:** **453** records (stratified draw). **R3 blind subset:** **200**. **Gate-relevant disagreements:**
  **33**. **Overlap (200 ∩ 33):** **16**. **Total unique records requiring R3 review: 217** (= 200 ∪ 33).
- **Each record is counted once per relevant metric.** The 16 shared records carry one R3 label that serves both the
  subsample coverage and the disagreement resolution — one physical record.
- **The targeted 33 do not create an additional Wilson denominator.** The Wilson denominator for category *c* is **all
  drawn items of *c* in the 453** (per-category n: CRLF 22, XPath 31, the rest 50); the 33 only resolve labels already
  inside that frame.
- Items that end `UNRESOLVED`/`MISSING` are not dropped; they are handled by §7.3 (they block PASS, never scored as
  INCORRECT).

### 7.1 Quantitative conditions

Computed on adjudicated labels over the per-category denominator, Wilson score interval, 95%, upper bound:

- **C1:** Wilson-95 upper bound of adjudicated **INCORRECT** ≤ **20%**.
- **C2:** Wilson-95 upper bound of adjudicated **UNCERTAIN + INCORRECT** ≤ **35%**.

These bound an AI-adjudicated classification rate (§5.3), not a human error rate.

### 7.2 R3 diagnostics — diagnostic only (decision 10)

- **R3 INCORRECT share** on the subsample, and **R3 agreement with the a1/a2-only resolved reference** (excluding R3's
  own vote), are **diagnostics, not pass thresholds** and never a human error rate. The a1/a2-only resolved reference is
  the adjudication from steps 1–2 of §6; **unresolved disagreements are not scored in this comparison without a prior
  independent reference decision.**

### 7.3 Coverage / resolution (decisions 4, 8)

- `PASS_AI_AUDITED` requires **review coverage 100%** and **zero `UNRESOLVED`/`MISSING`/`FURTHER_REVIEW` gate-relevant
  items**. Any unresolved gate-relevant item → `INSUFFICIENT_EVIDENCE` (not supported) until the owner resolves it
  (§6.4). Unresolved evidence **blocks** approval; it is **never** scored as INCORRECT.

### 7.4 Category outcome; no small-n exception (decision 5)

- All of C1, C2, §7.3 → `PASS_AI_AUDITED` (tagged `AI_AUDITED`, never `VERIFIED`).
- C1 or C2 violated on resolved evidence → `FAIL`. §7.3 not met → `INSUFFICIENT_EVIDENCE`.
- **The thresholds are identical for every category. There is no post-hoc exception for small-n categories such as
  CRLF (n=22) or XPath (n=31)**, even though at those n the Wilson bound is wide (at n=22 the 20% ceiling tolerates 0
  adjudicated INCORRECT; at n=31, 1; at n=50, 4). A **failing category remains ineligible**.
- On `FAIL`/`INSUFFICIENT_EVIDENCE`, per D58 the category is **excluded from V5 TRAIN** and reported NOT SUPPORTED. At
  most **one** re-audit after a documented filter change, new seed; no further re-draws (C-R6).

### 7.5 SSRF recorded as failing C1 (decision 6)

- Round 1 reports **Server Side Request Forgery** with **21/50 concordant (a1 = a2) INCORRECT** classifications
  (Wilson-95 upper ≈ 55.8%), and **0** of the 33 disagreements — so its status does not depend on R3. Under C1 (≤ 20%)
  it **FAILS**.
- SSRF is **recorded as failing the current C1 criterion**, its evidence **preserved**, and it is **excluded from the
  eligible dataset pending a separately approved correction and re-audit** (C-R6: one re-audit only, after a documented
  filter change, new seed). No payload is relabelled.

## 8. Preregistered acceptance criteria (decision 4) — PROPOSED, approve before R3 runs

| Symbol | Criterion | Preregistered value | Status |
|---|---|---|---|
| C1 | Wilson-95 upper, adjudicated INCORRECT | ≤ **20%** | PROPOSED — approve & freeze before R3 |
| C2 | Wilson-95 upper, adjudicated UNCERTAIN+INCORRECT | ≤ **35%** | PROPOSED — approve & freeze before R3 |
| coverage | gate-relevant items reviewed/resolved | **100%** | PROPOSED |
| unresolved | gate-relevant items left `UNRESOLVED` at PASS | **0** | PROPOSED |
| R3 diagnostics | R3 INCORRECT share; R3-vs-(a1,a2) agreement | **diagnostic only** | PROPOSED (not a gate) |
| n, |H_c| | per-category sample floor; subsample floor | **≥ 50** (or whole pool); **≥ 20** | PROPOSED |

- These are **identical for all categories** (no small-n exception). They are **never relaxed after any model output
  exists** (C-R6). No earlier figure is retained implicitly; these are the values now preregistered.

## 9. Decisions still requiring owner approval (none assumed granted)

1. Final D67 wording and adoption of `V5-DATA-SPEC-r4`.
2. The post-hoc-deviation ruling (§2) as recorded policy.
3. **R3 = ChatGPT GPT-6** and recording its exposed designation at run time (§3).
4. The preregistered criteria of §8, approved and frozen **before** R3 runs.
5. The adjudication rule §6 (majority only with all three present; `UNRESOLVED` → evidence-based owner).
6. The SSRF disposition (§7.5) and any later correction + re-audit.
7. The status semantics of §4 and that no AI status confers `VERIFIED` or unblocks FINAL (§11).

Recommendations here are **recommendations**, not approvals.

## 10. Required technical corrections — done in this rev

- Existing proposal and diff **preserved** before changes (`_preserved/`, rev 1/2/3).
- `r3-to-r4-minimal.diff` **regenerated as a syntactically valid unified diff**.
- **Patch applicability verified on an isolated copy** (never the frozen r3): `git apply -p1 --check` clean; applying
  reproduces r4 (SHA-256 `54514850…`).
- **Frozen r3 SHA-256 reconfirmed `f1580634…`** (unmodified).
- Internal consistency between D67, r4 and the criteria verified (§12 checks).

## 11. Compatibility with the data and training gates — FINAL stays BLOCKED (decision 12)

- This proposal changes only r3 §7, §11.2 and §11.3 (items 1–2); all other r3 text is unchanged; the frozen file is not
  edited.
- **Gate-compatibility (read-only inspection of `develop`, where the V5 training pipeline from #78 lives; this branch
  has none of it):**
  - `scripts/training/finetune_v5.py` is gated SMOKE / EXPERIMENTAL / FINAL; **FINAL refuses (exit 3, `GateRefused`,
    nothing trained)** without a committed dataset preregistration, a `v5-dataset-freeze-record/v1` and a
    `v5-training-preregistration/v1`. None exists yet, so FINAL is refused today regardless of this proposal.
  - `scripts/training/v5_train_data.py` trains only rows whose **`label_status ∈ {VERIFIED, POLICY_DEFINED}`**
    (`LABEL_NOT_TRAINABLE` otherwise) and requires **`attack_label_basis == "post_filter_audit"`**. Because the audit
    never sets `label_status = VERIFIED`, a `PASS_AI_AUDITED` category does **not** by itself make rows trainable.
  - **Caveat:** the trainer's `attack_label_basis` check does **not** distinguish a human-audited from an AI-audited
    pass — it trusts whatever audit produced the labels. So the guarantee that AI-audited evidence will not feed FINAL
    is **procedural (owner authorization), not enforced in code**. This is exactly why FINAL must stay blocked until
    **separately authorized**.
- **FINAL TinyLlama V5 training remains BLOCKED** until (a) this methodology is approved, (b) §8 values are approved and
  frozen before R3 runs, (c) the needed categories reach `PASS_AI_AUDITED`, and (d) all training-readiness gates pass
  (dataset freeze record, preregistrations, byte-identical regeneration). AI-audited evidence does **not** by itself
  unblock FINAL. `names_family` stays BLOCKED (#75).

## 12. Internal-consistency checks (recorded)

- Review populations consistent across §7.0 and the round-1 data: 453 frame, 200 subset, 33 disagreements, 16 overlap,
  **217 unique = 200 + 33 − 16** (verified against the record IDs).
- Criteria in §7.1/§7.3/§8 and in the diff's §7 row and §11.2 register match (20% / 35% / 100% / 0; R3 diagnostic).
- SSRF 21/50 concordant INCORRECT consistent with `report.md`/`round_status.json`.
- r4 reproduced from frozen r3 by the valid diff; r3 SHA unchanged.

---

**STATUS: APPROVED (rev 4), 2026-10-20 — registered as D67; `V5-DATA-SPEC-r4` FROZEN.** The methodology is approved;
the dataset is not audited and no category is PASS. No commit, branch or PR was made here — all Git operations remain
under the owner's control.
