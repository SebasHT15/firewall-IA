# Paired V4 ↔ Analyzer development diagnostic — protocol (`v4-analyzer-paired-dev-v1`)

**Type: DIAGNOSTIC on DEVELOPMENT / ERROR-ANALYSIS data, from day one (D37, D45).** Issue #59.
It studies V4 ↔ frozen Analyzer disagreement and complementarity on paired benign / attack
requests built on the same lab endpoints. It is **not** an evaluation, **not** an independent
external test, and it fixes **no** ALLOW / BLOCK / UNCERTAIN policy, threshold or calibrator.
`0.5` appears only as the D55 reporting convention. No model is trained, re-fitted or
re-calibrated. Every count is a diagnostic count on a composition chosen by its authors — never
an FPR, FNR, recall, precision, prevalence or operational rate (D42, methodology §7). It is the
"option C" development set recommended by `v4-analyzer-disagreement-v1` (issue #57, PR #58).

This is **Revision 1**, written after the owner's pre-scoring review of Revision 0 and still
**before** any V4 or Analyzer scoring. The changes and their reasons are in §12. The protocol's
SHA-256 (of this revision) is recorded as a dated pre-run anchor in a comment on issue #59 before
scoring; the actual chronology is reported in the README (nothing here is claimed to have been
committed before the run — the owner handles commits).

## 1. Questions and hypotheses

1. Which V4 false positives (benign requests V4 BLOCKs) have **low** Analyzer scores, and which
   have **high** scores?
2. Which attacks V4 correctly BLOCKs also have **low** Analyzer scores (and does the surface /
   header-location split explain them, D44)?
3. Which attacks V4 **misses** (a genuine ALLOW) have **high** Analyzer scores?
4. Do paired benign / attack requests on the **same endpoint** separate under V4, under the
   Analyzer, under both, or neither?
5. Which apparent patterns are explained by shared templates, feature-vector collapse, headers
   excluded by D44, reused benign texts, or capture artefacts?
6. What evidence, if any, distinguishes the next options — a future Analyzer feature revision, V5
   work, or a V4-reason-aware Model 2 — **without choosing one here**?

Hypotheses carried from #57, examined **descriptively** (not confirmed here): H1 character-
counting not words; H2 a JSON / API shape shortcut; H3 V4's reason carries indirect header/token
signal a Model 2 could use. Counterexamples are kept.

## 2. Data role

DEVELOPMENT / ERROR-ANALYSIS from day one (D37). Once studied here these cases are Hybrid
development data and can never later serve as independent evidence for a cascade or a Decision
Model. This set is **not** an independent test of the eventual Hybrid system.

## 3. Unit of analysis (independence) — the central correction

The owner's review found that counting (technique × placement) as independent groups, and
reusing one benign value per placement, inflated the apparent sample. This revision fixes the
unit:

- **The independent attack unit is the DISTINCT CANONICAL PAYLOAD** (`parse_dataset_v4`-style
  canonicalisation: percent / entity decode, comment and `${IFS}` collapse, whitespace, case).
  Each attack payload appears in **exactly one placement** (its natural endpoint), so one
  independent attack record ⇔ one distinct canonical payload. Payloads are distributed across
  endpoints so a family still spans query / path / form / JSON surfaces. No two independent
  attack records in a family may share a canonical payload (asserted by the generator; an
  encoding variant that canonicalises onto an existing payload is a build error, not a new unit).
- **A category-level conclusion is drawn only for a family with ≥ 30 distinct canonical attack
  payloads** (D18); otherwise the family is **INSUFFICIENT INDEPENDENT SUPPORT**. Distinct
  *techniques* are reported alongside as a second unit.
- **Placement sensitivity** (does one payload behave differently across placements?) is a small,
  explicitly separate sub-study: a few payloads repeated across placements, every such record
  flagged `placement_variant = true` and **never** counted as an independent payload.
- **Benign near-neighbours** are drawn from realistic per-placement pools so each attack's twin
  is, where the pool allows, a **distinct, legitimate** request on the same endpoint. Benign
  observations are reported by **unique text**; any reuse (pool smaller than the number of
  attacks on a placement) is a reported dependency, **never** an independent benign observation.
- The report leads with honest units: total records; unique request texts; unique Analyzer
  feature vectors; distinct canonical attack payloads; distinct techniques; placement variants;
  unique benign texts; complete pairs; and dependency components (connected components of "same
  canonical payload OR same request text").

## 4. Ground truth — a semantic oracle, independent of any model; attempt, not exploitation

The label is fixed by construction, never by V4's decision / reason or the Analyzer score.

- An **attack** case carries a canonical malicious payload of a named family, placed where the
  endpoint accepts it. Label = BLOCK, meaning **"a malicious attack ATTEMPT by construction"**.
  The lab app is deliberately inert (`docker/lab-app/app.py`): it establishes that the request is
  **delivered** and how it is **classified**, and it does **not** — and this diagnostic does not —
  claim the payload would **successfully exploit** the app. `oracle_reason` records this.
- A **benign** case carries a legitimate value for that endpoint. Label = ALLOW.
- `paired_dev_set.oracle_check()` is a documented defensive **consistency assertion** (not a
  detector, never applied to model output): every attack payload must match its family's
  documented signature, and no benign **value** may contain a "hard" unambiguous attack token.
  Benign near-neighbours that deliberately carry SQL-ish / symbol-rich **English** (soft keywords
  *select*, *drop*, *union*, *or*) stay benign because those are not in the hard set. The build
  fails if any case violates the oracle (0 violations required before freeze). The independent
  reviewer inspects representative and ambiguous cases across every family and relabels / excludes
  any case where the construction intent is doubtful **before** the list is frozen.

## 5. Case generation — rules, groups, exclusions (`paired_dev_set.py`)

Deterministic (no randomness, no clock; same inputs → byte-identical `cases.jsonl`). Schema
`paired-dev-set/v1`. Built on the lab-app endpoints (`/search`, `/products`, `/products/<id>`,
`/static/<asset>`, `/api/products`, `/api/products/<id>`, `/login`, `/cart`, `/checkout`,
`/api/orders`, `/api/me`). Hosts are the lab aliases `shop.fwlab.test:9100` /
`api.fwlab.test:9100` — **never a loopback host**, which V4 treats as a shortcut (D1 / D44), so
the Host never confounds a benign case.

- Target families with a category-level conclusion intended (≥ 30 distinct canonical payloads):
  `sql_injection`, `xss`, `command_injection`, `path_file_access`, `ssrf`.
- Context families (reported; a category conclusion needs ≥ 30 payloads, else INSUFFICIENT
  INDEPENDENT SUPPORT): `ssti`, `open_redirect`, the D47 residual `other_attack`, and the
  header-borne `jwt` (D48: Analyzer blind by construction) and `csrf` (header-dependent; Analyzer
  blind to Origin / Referer, D44).
- **Faithfulness of the request line**: query / path payload values are percent-encoded so the
  request line round-trips through mitmproxy unchanged; messy payloads prefer form / JSON bodies
  (opaque under Content-Length). Every designed text passes `wire.assert_canonical` and
  `wire.to_wire(strict=True)` at generation time.
- **NOT TESTABLE through the faithful gateway** (not generated as attack cases; recorded as
  such): HTTP request smuggling (`wire.py` rejects Transfer-Encoding and any Content-Length
  mismatch; mitmproxy normalises framing); Host-header injection (the proxy connects to the
  request's Host; CRLF in a header does not render); stateful JWT / CSRF **bypass** (the inert app
  validates no auth and enforces no CSRF token).
- **Exclusions**: a case whose gateway capture is not byte-faithful, or whose V4 `/classify`
  errors, is recorded but **not scored** (§8); never silently dropped.

## 6. Gateway capture and the exact text scored (`paired_dev_capture.py`, in the lab)

Runs inside the lab `generator` container on the `firewall-lab` network. Per case, in order, one
request each (raw socket, no redirect following, strictly sequential — no marker is ever added to
a request under test, methodology §8):

1. **Fidelity** — `wire.to_wire(designed_text)` → the **capture proxy**, which imports the
   production `render_request` (object identity asserted by `tests/test_external_capture`); its
   one capture line's `request_text` must equal the designed text byte-for-byte and its SHA-256
   must match (`capture_ok`). **What this establishes, precisely:** the D1 text the *same*
   renderer produces from the wire bytes. It is **not** a byte-capture of the live data-plane →
   control-plane channel.
2. **Gateway enforcement** — the same wire bytes → the **firewall data plane** (V4 in the path).
   HTTP status is the enforced decision: 403 → BLOCK (model), 503 → fail-closed BLOCK, else →
   ALLOW / forwarded (D34). Kept **distinct** from pass 3.
3. **Decision + reason** — POST `{"request": captured_text}` to the **control plane** `/classify`,
   exactly as the gateway's `ask_classifier` does; records decision, reason, status (ok /
   invalid), model latency.

A `gateway_consistent` flag records whether pass 2 (enforcement) agrees with pass 3 (`/classify`)
on every case — the **empirical bridge** showing the data plane behaves the same as the text
scored in pass 3. **The text scored by both models is the captured gateway text** (identical to
the designed text when `capture_ok`). The Analyzer (`paired_dev_analyze.py`, offline,
`.venv-analyzer`) runs read-only on that text; its artifact SHA-256 (`79eb7265…`,
`model-output-hybrid-analyzer-v2/recommended.pkl`) is checked **explicitly** before and after and
must equal the expected value (both checks separate — a chained comparison would miss some
mismatches). The V4 adapter is `model-output-v4-clean` (`7bf16875…`), greedy decoding
(`inference_core`, D27).

## 7. Overlap / data-role checks — what they can and cannot establish

Membership only (reuses `v4_analyzer_disagreement.load_membership` / `role_sets`, which keep only
`role`, `slice`, feature-vector and canonical-request hashes, plus `row_id` for TRAIN /
VALIDATION):

- For every scored case: is its 34-feature vector or its D51 canonical request in
  `hybrid_analyzer_v2` **TRAIN ∪ VALIDATION** (fitted; JWT separate)? in **INTERNAL TEST**
  (membership flag only — no label, target, V4 metadata or row id is read; D54's two looks are
  exhausted, so a shared vector is **flagged**, never scored against INTERNAL TEST labels)? Is its
  exact text in V4-clean train or eval? The canonical-request relation is self-checked against the
  v2 build.
- **External Test v1 overlap is UNKNOWN** — never opened (D53); the analysis refuses any path
  under `datasets/external_v1/`, `reports/external/`, `docker/.lab-logs/` and the Analyzer's
  External v1 report. This set is development data, never an independent test of the Hybrid system.
- These establish **membership** (seen / unseen relations), not causation.

## 8. Decisions, INVALID handling, descriptive bins, stopping rules

- **V4 decision categories for a scored case are BLOCK, ALLOW, or INVALID** (the model produced an
  unparseable output; D25, never coerced). A **false negative is ONLY a genuine ALLOW on an
  attack.** INVALID outputs, `/classify` errors, gateway errors and capture mismatches are each
  counted in their own bucket and are **never** folded into "V4 missed an attack" or any other
  ordinary-decision count.
- **Primary Analyzer unit = the distinct feature vector** (the Analyzer cannot tell two texts with
  the same vector apart); results are counted per vector first, then per distinct payload, then
  per text. This prevents text-count inflation (header-only JWT / CSRF variants collapse to one
  vector because Authorization / Origin are unread).
- **Bands** (fixed; descriptive only, not tuned): `[0, 0.1)`, `[0.1, 0.5)`, `[0.5, 0.9)`,
  `[0.9, 1]`; "extreme" = `< 0.01` or `≥ 0.99`. `0.5` is the D55 reporting convention; no other
  cut is searched.
- **Stopping rules**: the case list, labels, units and this protocol are fixed and hashed before
  any scoring. Capture + classify run **once** per case; never re-run for a preferred outcome. A
  necessary post-scoring protocol change preserves the first run and uses a new run id.

## 9. Conclusions this diagnostic cannot support

- Any FPR, FNR, recall, precision or prevalence (D42); any operating threshold or policy; any band
  edge read as an operating point (D55).
- That a cascade would or would not rescue V4 false positives, or is safe on real / external
  traffic; any real-world rescue rate. The false-negative side is bounded only by this
  author-chosen composition, never estimated as a rate.
- That placement variants or reused benign texts are independent observations.
- That an attack payload **successfully exploits** the lab app (only attempt + classification).
- That an INVALID output or a classify / gateway / capture error is a V4 false negative.
- Any Analyzer robustness / invariance to Host, User-Agent, Origin, Referer or Authorization: it
  holds by construction (D44, D48), stated in advance.
- Any cause of a decision beyond "this variable changed and the decision changed in this context".
- Anything about External Test v1 (never opened) or INTERNAL TEST performance (membership only).
- Calibrated confidence (D50); memorization / overfitting (D42).

## 10. Guards

- The analysis refuses by construction to open any External Test v1 path (`dev_path`). The frozen
  Analyzer is read-only, hash-checked (both before and after, each against the expected value).
  The V4 adapter is read-only; its identity is recorded.
- Outputs are written exclusively; no existing report file is overwritten. Capture logs go to a
  fresh lab log directory, never `docker/.lab-logs/` (External v1).

## 11. Independent review

An independent, read-only subagent audits the data roles, grouping / unit, labels and capture
claims **before** scoring; its blocking findings are resolved (in this protocol, the generator,
capture and analysis) and, if an anchored file changes, a new revision is recorded and a new
anchor posted before scoring. A second independent subagent reviews the final counts and wording
**after** scoring.

## 12. Revision log

**Revision 0 → Revision 1** (after the owner's pre-scoring review; before any scoring):

1. **Unit of analysis.** Revision 0 counted (technique × placement) as independent "logical
   groups" (e.g. 47 for SQLi) and used one benign value per placement (12 unique benign twin
   texts for 238 twin records). *Reason:* that inflated the sample; the same payload across
   placements is not independent and a repeated benign text is not an independent observation.
   *Fix:* the independent unit is the distinct canonical attack payload (one placement each);
   ≥ 30 **distinct payloads** per conclusion family; placement sensitivity is a separate flagged
   sub-study; benign twins drawn from realistic pools and reported by unique text; honest unit
   reporting throughout (§3, §5, §8; `build_manifest` units; `honest_units` in the analysis).
2. **Labels.** *Reason:* the oracle is a consistency check, not proof of exploitability, and the
   lab is inert. *Fix:* labels are "malicious attack **attempt** by construction", never
   "successful exploitation"; the independent reviewer inspects ambiguous cases before freeze
   (§4, §9).
3. **Capture claim.** *Reason:* pass 1 does not capture the live data-plane → classifier bytes.
   *Fix:* the claim is narrowed to "the text the same `render_request` produces from the wire
   bytes", with pass-2-vs-pass-3 `gateway_consistent` as the empirical bridge; enforcement and
   `/classify` kept distinct (§6; `capture_fidelity_claim` in the results).
4. **Analyzer hash check.** *Reason:* a chained `before != after != expected` does not reject
   every mismatch. *Fix:* both hashes are checked explicitly against the expected value
   (`hash_problems`, §6, §10).
5. **INVALID / errors.** *Reason:* a missing / invalid / errored decision must never become a
   "V4 missed an attack". *Fix:* BLOCK / ALLOW / INVALID are distinct; a false negative is only a
   genuine ALLOW; INVALID, classify, gateway and capture errors are separate buckets (§8, §9;
   analysis functions).
