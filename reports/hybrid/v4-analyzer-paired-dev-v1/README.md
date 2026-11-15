# Paired V4 ↔ Analyzer development diagnostic — `v4-analyzer-paired-dev-v1`

**DIAGNOSTIC on DEVELOPMENT / ERROR-ANALYSIS data (issue #59). Not an evaluation, not an external
test.** The "option C" development set recommended by `v4-analyzer-disagreement-v1` (#57, PR #58).

For every captured development request it crosses: the oracle label · TinyLlama **V4**'s gateway
decision and reason · the frozen **Analyzer**'s `attack` probability and auxiliary category
(context only, D46). Nothing is trained, re-calibrated or thresholded. Bands are fixed descriptive
bins; `0.5` is only the D55 reporting convention. Every number is a **diagnostic count on a
composition chosen by its authors** — never an FPR, FNR, recall, precision, prevalence or
operational rate (D42, methodology §7).

| | |
|---|---|
| Date | 2026-10-06 |
| Branch / base | `research/hybrid-paired-development-set-v1`, base `dd042bb` (PR #58 merged), uncommitted |
| Protocol | [`PROTOCOL.md`](PROTOCOL.md) **Revision 1**, `459f5f91…`, written and anchored before scoring ([#59 anchor](https://github.com/SebasHT15/firewall-IA/issues/59#issuecomment-6008930322)) |
| Analyzer | `hybrid-analyzer-v2/attack=hist_gb,category=hist_gb`, `recommended.pkl` `79eb7265…`. Hash checked **before and after**, each against the expected value; **unchanged** |
| V4 | `model-output-v4-clean`, adapter `7bf16875…`, greedy decoding (`inference_core`, D27) |
| Lab | Docker lab gateway: control-plane (V4) · data-plane (firewall) · lab-app (`shop/api.fwlab.test`) · capture-proxy. Capture **434/434 byte-faithful**; gateway enforcement agreed with `/classify` on **434/434** |
| Code (final) | [`paired_dev_set.py`](../../../scripts/evaluation/paired_dev_set.py) `8ff5b4f3…` · [`paired_dev_capture.py`](../../../scripts/evaluation/paired_dev_capture.py) `8303d402…` · [`paired_dev_analyze.py`](../../../scripts/evaluation/paired_dev_analyze.py) `35e916fc…` · [`tests/test_paired_dev_set.py`](../../../tests/test_paired_dev_set.py) `f8fe1d7b…` — `paired_dev_set`/`paired_dev_analyze` relabeled post-scoring (#59 supplementary comment); anchor hashes `0c5af7d7…`/`bb0cea53…` |
| Evidence | [`cases.jsonl`](cases.jsonl) · [`manifest.json`](manifest.json) · [`records.jsonl`](records.jsonl) · [`results.json`](results.json) · [`raw/`](raw/) (capture, service logs, metadata) · [`SHA256SUMS`](SHA256SUMS) |

## 1. Units of analysis (honest; the central correction over Revision 0)

The independent attack unit is the **per-family distinct canonical payload**, each placed in a
single endpoint; placement variants and reused benign texts are **never** independent
observations. The generator forbids two independent attacks sharing a canonical payload **within a
family**. One canonical string — `file:///etc/passwd` — is used by **two** families as a genuinely
distinct technique (path file disclosure vs SSRF file scheme), so there are **201 independent
attack records across 200 distinct canonical payload strings**.

| Unit | Count |
|---|---:|
| Total request records | 434 |
| Unique request texts | 355 |
| Distinct Analyzer feature vectors | 337 |
| Attack records | 213 |
| — independent (per-family distinct canonical payload, one placement each) | **201** |
| — placement-sensitivity variants (DEPENDENT, never independent) | 12 |
| Distinct (family × canonical payload) pairs — the independence unit | 201 |
| Distinct canonical payload **strings** | 200 |
| — of which shared across families (`file:///etc/passwd`) | 1 |
| Benign records | 221 (201 twins → **121 distinct vectors**; 20 probes) |
| Complete attack/benign pairs (same endpoint) | 201 |
| Dependency components (same canonical payload string OR same text) | 342 |

**Distinct independent payloads per conclusion family (D18 ≥ 30 met):** sql_injection 33, xss 32,
command_injection 32, path_file_access 32, ssrf 32. Each family's payloads are materially distinct
canonical strings (verified; no duplicate within a family), **not** 30 re-encodings of one payload
(that was Revision 0's flaw).

**Natural-sink vs generic-carrier** (whether the field role is a plausible injection point for the
family; a V4 ALLOW on a generic carrier is delivery/classification context, **not** an operational
detection failure):

| Family | natural_sink | generic_carrier |
|---|---:|---:|
| sql_injection | 23 | 10 |
| xss | 14 | 18 |
| command_injection | **0** | 32 |
| path_file_access | 6 | 26 |
| ssrf | 24 | 8 |

The inert lab has **no shell sink**, so command_injection has 0 natural-sink cases, and only the
`/static` endpoint is a filesystem-path sink (path_file_access 6). This is stated plainly; these
families measure *flagging a delivered malicious token*, not catching an exploitable backend.

**Data-role overlap (membership only): all zero.** No scored case shares a feature vector or D51
canonical request with Analyzer **TRAIN ∪ VALIDATION** or **INTERNAL TEST**, and no exact text is
in V4-clean train/eval. The canonical-request relation reproduced the v2 build on 25,134/25,134
rows. **External Test v1 overlap is UNKNOWN** (never opened, D53). So this is a genuinely *unseen*
development set for both models.

## 2. The unit problem: texts vs feature vectors (D44)

434 records → **337 distinct feature vectors**. The only attack/benign vector collapses and the
only ALLOW/BLOCK-shared vectors are inside the header-borne `jwt` / `csrf` context families, where
the Analyzer is blind to `Authorization` / `Origin` / `Referer` **by construction** (D44, JWT also
D48) — exactly as predicted, not a finding. Every conclusion-family independent attack has its own
vector. Analyzer-side results are counted per vector first.

## 3. Measured results (diagnostic counts)

### 3.1 Label × V4 decision × Analyzer band (`attack ≥ 0.5` is the D55 reporting-only cut)

| Label | V4 | `attack < 0.5` | `attack ≥ 0.5` |
|---|---|---:|---:|
| benign (ALLOW) | ALLOW (V4 correct) | 31 | **122** |
| benign (ALLOW) | **BLOCK (V4 FP, 68)** | 4 | **64** |
| attack (BLOCK) | **ALLOW (V4 miss, 7)** | **7** | 0 |
| attack (BLOCK) | BLOCK (V4 correct, 206) | 3 | 203 |

V4 produced **0 INVALID** outputs. (The 206/7 attack split is over all 213 attack records; the 12
placement variants were all V4-BLOCK.)

### 3.2 Surface attacks — V4 blocks all; the Analyzer scores them high

All **203 surface attack cases** were V4-BLOCK (0 missed, 0 invalid). Analyzer `attack` median
0.998, min 0.679, **0 below 0.1**; for the five conclusion families, **0 below 0.5**. On this
unseen set the Analyzer scores every surface attack high — a **contrast** with #57, where a few
surface attacks V4 blocked fell in the Analyzer's lowest band.

### 3.3 The only V4 misses are header-borne, and the Analyzer is blind there

| Signal location | attack cases | V4 BLOCK | Analyzer `< 0.1` | Analyzer median |
|---|---:|---:|---:|---:|
| surface (path/query/body) | 203 | 203 | 0 | 0.998 |
| header-only (JWT `Authorization`) | 6 | 1 | 6 | 0.024 |
| header-dependent (CSRF `Origin`/`Referer`) | 4 | 2 | 0 | 0.114 |

All **7 attacks V4 missed** (genuine ALLOW) are header-borne: 5 JWT, 2 CSRF. The Analyzer scores
**all 7 below 0.5** (JWT 0.024, CSRF 0.114) — blind by construction (D44/D48). So the Analyzer
**cannot rescue V4's misses** on this set. There is no counterexample (no V4-missed surface attack,
and no high-Analyzer miss as in #57's GraphQL case).

### 3.4 V4 false positives (68 benign BLOCKed) — the Analyzer agrees with most

The Analyzer scores **64/68 at ≥ 0.5** (54 in `[0.9, 1]`); only 4 below 0.5 (2 below 0.1). So a
"low-Analyzer-score override" of a V4 BLOCK would rescue at most 4 of 68 here. By placement the FPs
cluster on `checkout_form` (25) and `login_form` (11); V4's reasons include "SQL injection" (22),
card-related reasons (22, fired on the benign `card_last4` / address), HPP (6), file inclusion (6),
XSS (5), SSRF (5). *(These 68 are a diagnostic count on constructed benign near-neighbours; not an
FPR.)*

### 3.5 The Analyzer's own benign-as-attack tendency

Of the 153 benign requests V4 correctly ALLOWs, the Analyzer scores **122 at ≥ 0.5**. Of 20
standalone benign probes (structures #57 flagged), **16 score ≥ 0.5** (13 in `[0.9, 1]`); V4 blocks
9/20. **42 benign cases score ≥ 0.99.** This reproduces, on unseen data, #57's hypothesis H2 that
the Analyzer reacts to JSON / form / structural shape rather than attack intent.

### 3.6 Paired separation on the same endpoint (201 complete pairs)

| | pairs |
|---|---:|
| V4 separates (attack BLOCK & benign ALLOW) | 135 |
| Analyzer `attack` higher on the attack twin | 176 |
| both separate | 126 |
| neither separates | 16 |

Analyzer gap (attack − benign) per pair: median **0.042**, min **−0.232**, max 0.972. The
Analyzer's separation is weak — on a same-endpoint pair it usually scores benign and attack
similarly high; sometimes the benign twin scores higher.

### 3.7 Auxiliary category (context only, D46)

Top-1 agrees on **56 / 207** mapped attacks — unreliable, as in #57; kept context only.

## 4. Answers to the six questions

1. **V4 false positives, low vs high Analyzer?** 68 benign V4-BLOCK; Analyzer **high (≥0.5) on 64**,
   low on 4 (2 below 0.1). The Analyzer mostly **agrees** with V4's false block.
2. **Attacks V4 blocks that the Analyzer scores low?** Essentially none: 1/194 independent below
   0.1 (0 surface), 3 below 0.5. Strong agreement on surface true positives (contrast #57).
3. **Attacks V4 misses that the Analyzer scores high?** **None.** All 7 V4 misses are header-borne;
   the Analyzer scores every one below 0.5 (blind by construction).
4. **Do paired benign/attack separate?** V4 separates 135/201; the Analyzer only weakly (median gap
   0.04); both 126; neither 16.
5. **What explains the patterns?** D44 header blindness (every FN is header-borne; Analyzer 0.024 /
   0.114); feature-vector collapse of JWT/CSRF; the Analyzer's structure/JSON shortcut (benign JSON
   & form score high); V4's card-field and keyword reasons on benign checkout/login. No External v1
   involvement; INTERNAL/TRAIN overlap zero; capture 434/434 faithful (no capture artefact).
6. **What distinguishes the next options?** See §6.

## 5. Supported conclusions

- **A low Analyzer score is not shown to be a safe override of a V4 BLOCK.** On V4's 68 false
  positives the Analyzer agrees (≥0.5) with 64; a low-score override rescues ≤ 4. Existence result,
  not a rate.
- **The Analyzer cannot rescue V4's false negatives on this set.** The only attacks V4 misses are
  header-borne (JWT/CSRF), where the Analyzer is blind by construction (D44/D48) and scores all
  below 0.5. A cascade built on RequestFeatures v2 inherits this blind spot.
- **On surface attacks, V4 and the Analyzer strongly agree** (both flag essentially all 203). The
  Analyzer adds little *complementary surface* coverage here — and, unlike #57, does not score
  surface attacks low, because this set is unseen and it generalises high.
- **The Analyzer over-flags benign structure** (122/153 V4-allowed benign, 16/20 probes, 42 at
  ≥0.99), a false-positive liability independent of V4.
- **The paired separation is weak** for the Analyzer (median gap 0.04; sometimes benign > attack).

## 6. What this cannot establish (and is not claimed)

- Any FPR / FNR / recall / precision / prevalence (D42); any operating threshold or policy; any
  band edge as an operating point (D55). The "68 V4 FPs" and "V4 blocks all 203 surface attacks"
  are **diagnostic counts on a constructed composition**, not rates.
- That a cascade would or would not be safe on real / external traffic; any rescue rate.
- That any payload **exploits** the inert lab app (attempt + classification only).
- That an INVALID / error is a false negative (there were 0 INVALIDs; the guard is in place).
- Analyzer robustness to Host / User-Agent / Origin / Referer / Authorization: holds by
  construction (D44/D48), stated in advance.
- Anything about External Test v1 (never opened) or INTERNAL TEST performance (membership only).
- Calibrated confidence (D50); memorization / overfitting (D42).

## 7. Limitations

- **The inert lab bounds "natural sink":** command_injection has 0 natural-sink cases, path
  traversal 6; these families largely measure token flagging, not exploitable detection.
- **Header-borne families are small** (JWT 6, CSRF 4) → **INSUFFICIENT INDEPENDENT SUPPORT** for a
  category conclusion; they are context for the FN-side finding only, and stateful bypass is **NOT
  TESTABLE** (documented in the manifest).
- **Benign twins reuse values** where a pool is smaller than the attacks on a placement (201 twins
  → 121 distinct vectors); benign observations are reported by unique text, not inflated.
- **Distinct canonical payload ≠ distinct attack concept:** several ssrf payloads are
  representation variants of a few targets (loopback / metadata), several path payloads are
  depth/scheme variants of `/etc/passwd`. They are legitimate distinct evasions, not 32 independent
  ideas.
- Diagnostic counts, never rates. Overlap with External v1 is UNKNOWN by design.

## 8. Recommendation for the NEXT technical branch (not implemented here)

This diagnostic sharpens #57's open question. Two regions matter, and they point apart:

- **False-negative side:** the only attacks either system misses are **header-borne** (JWT/CSRF),
  where the Analyzer is **structurally blind** (D44/D48). A Model 2 or cascade on RequestFeatures v2
  **cannot** help here. Closing it needs an **owner decision on a D44 revision** (letting a future
  Analyzer read `Authorization` / `Origin` / `Referer` for these families), with the D1-shortcut
  risk weighed — a decision, not code.
- **False-positive side:** V4's 68 benign false positives (checkout card fields, benign JSON/form,
  keyword queries) are **V4 defects**, and the Analyzer does not rescue them (it agrees, and
  over-flags benign structure itself).

**Recommended next branch: a V5 hard-negative development study** that uses this set's benign
near-neighbours (and V4's reasons on them) as hard negatives for V4's successor, under D37/D40 data
roles — because the evidence here shows the *cascade* path is blocked on both sides with the current
features, while V4's own false positives are concrete, reproducible defects. A cascade / Model 2 on
RequestFeatures v2 + the Analyzer score should **not** be built on this evidence. The D44 question is
raised for the owner, not decided here. No operating point is proposed (D55).

## 9. Open questions (for the owner)

1. Approve a D44 revision for header-borne families (JWT `Authorization`, CSRF `Origin`/`Referer`),
   given this is the only region a cascade could add FN coverage and V4's `Host`/`User-Agent` were
   shortcuts (D1)?
2. Prioritise a V5 hard-negative branch targeting V4's benign false positives seen here?
3. Should a lab with a real (sandboxed) file/command/SSRF sink be built so natural-sink coverage is
   not bounded by the inert app?

## 10. Review record

- **Owner pre-scoring review** found blockers: the unit-of-analysis inflation (technique × placement
  counted as independent; 12 unique benign twin texts for 238 records), label over-claim risk,
  capture-claim over-reach, a hash-check bug, and INVALID-as-false-negative. All resolved in
  **Protocol Revision 1** before anchoring (see PROTOCOL §12).
- **Independent pre-scoring audit** (read-only, Opus): **no blocking findings**; manifest recomputed
  exactly; every fix verified. Non-blocking NB-1/NB-2 (placement/sink meaningfulness, path sink) and
  NB-4 (cosmetic) were adopted: `sink_type` tagging, `/static` added to path traversal, canonicaliser
  order aligned.
- **Independent post-scoring review** (read-only, Opus): recomputed every headline count from
  `records.jsonl` and confirmed they reproduce; `sha256sum -c SHA256SUMS` all OK; verified the
  wording introduces no operational rate and the cascade/recommendation claims stay within the
  counts. **One blocking finding (B-1):** the aggregate "distinct canonical attack payloads = 201"
  and "dependency components = 343" were imprecise, because the string `file:///etc/passwd` is a
  distinct technique in both `path_file_access` and `ssrf` → **200 distinct canonical strings**
  across **201** independent (family × payload) records, and **342** string-keyed dependency
  components. **Resolved:** the unit is now reported precisely in §1, the manifest, `results.json`
  and the code (`independent_attack_records` 201 · `distinct_canonical_payload_strings` 200 ·
  `cross_family_shared_canonical_strings` 1 · dependency components 342). The five conclusion-family
  counts (33/32/32/32/32) are unaffected, and **no diagnostic conclusion changes**. Non-blocking
  notes (softening "generalises strongly"; the D45 "V5"=next-model wording; a card-reason sub-split)
  were adopted or noted here.

**Chronology note (precise):** the V4 / gateway capture ran **once** (raw records in `raw/`,
frozen, SHA in `raw/run_metadata.json`); it was **not** re-run. After the post-scoring review, the
**offline analysis** (`paired_dev_analyze.py`, deterministic) was re-run once to regenerate
`results.json` / `records.jsonl` with the corrected unit labels, and `manifest.json` was
regenerated from the **byte-identical** `cases.jsonl` (hash `879c7ddb…`, unchanged). The protocol
`cases.jsonl` content did not change; `manifest.json` and the three scripts (anchored pre-scoring)
were edited only to label the unit precisely — disclosed in a supplementary comment on #59 with the
new hashes. No V4 or Analyzer decision was recomputed to a different value.
