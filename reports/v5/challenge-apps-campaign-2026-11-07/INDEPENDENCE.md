# Phase 1 — Independence audit of the six challenge apps vs V5.1 + Model2 train/select data

**Date:** 2026-11-07 · **Status:** app-level independence supported; limits stated below.
No app whose independence cannot be sustained is called "unseen" here.

## 1. Question

Were any of the six `sec-challenges/Web` applications (pinned at
`be8e4e8f1c6aa12a17430146d569870d96d43dd5`) — their **names, routes, templates, asset
files, flag hints, or proposed cases** — present in the data used to **train or select**
V5.1 and Model2? Independence is claimed only for the *applications*, never for the
attack *vocabulary* (see §4).

## 2. Models and their corpus

Both models pin the **same** dataset manifest
`c2e9c2f50f56c059ce82945384858802357be88d899dc2710e20edd06a2b72df`
(`reports/v5/successor-training-2026-10-31-reviewed/dataset-manifest.EXPERIMENTAL.json`).

- **Model2** `baseline34.json` (`v4-d82-20261027T052308Z`): TRAIN = 3080 rows
  (1540 ALLOW / 1540 BLOCK) = `datasets/v5_sources/final_source_2026-10-26-v4/rows.TRAIN.jsonl`
  (sha `809ce774cf8d…`, 3080 lines), + VALIDATION. LogisticRegression on `baseline_34`, owner decision D82.
- **V5.1** adapter `v51-policy-20261101T210119Z`: augmented TRAIN = 5166 rows
  (`…/v51-training-candidate-20261031-reviewed/rows.TRAIN.jsonl`, sha `8b8b63cc84d3…`),
  VALIDATION 2080 rows; original V5 TRAIN preserved.

## 3. Method

Exhaustive case-insensitive byte-substring search over **every file** in the three
corpus roots that hold training and selection data for both models:

1. `…/ta/work/v51-training-candidate-20261031-reviewed/` (V5.1 TRAIN/VALIDATION rows + meta)
2. `…/ta/work/v51-source-partitions/` (TRAIN/VALIDATION/RESERVE candidate source rows)
3. `datasets/v5_sources/` (the full 434 MB source pool: `final_source_2026-10-26-v4`
   TRAIN/VALIDATION/INTERNAL_TEST + slices + assignment, plus `attack/`, `benign/`,
   `final_candidate/`, `stab_held_*`, `regeneration-*`, `stage3/`, `candidate_denylist_v2/`,
   and the pilot/hygiene sources).

**Coverage: 254 files, 2,803,691 lines, 468,404,767 bytes.** No corpus root was missing.
Per-file SHA-256 and line counts are recorded in `independence_audit.summary.json`;
raw match context (none, for app tokens) is in the private
`…/fwlab-campaign-private/2026-11-07/audit/independence_audit.raw.json`.
Audit script: `independence_audit.py` (session scratchpad; deterministic, re-runnable).

**App-identifying tokens searched** (a nonzero count would be a leak):
app names `An0nB0ard CatP1cs D33pTh0ught Inf3ct ObC00ki3s ag3ncy` (exact + de-leet
`anonboard catpics deepthought infect obcookies agency`); unique routes/handlers
`addentry get_entry get_password`; asset files `cks.js asking.js blackcat machine.jpg
anon.png avatar.png members.sql`; symbol `log_array`; flag hints
`may the force be with`, `answer to life`.

## 4. Results

| Token class | Example tokens | Hits in train/select corpus |
|---|---|---:|
| App names (exact + de-leet) | An0nB0ard, catpics, ObC00ki3s, agency … | **0** |
| Unique routes / handlers | addentry, get_entry, get_password | **0** |
| Asset filenames | cks.js, blackcat, machine.jpg, anon.png, avatar.png, members.sql | **0** |
| Symbols / flag hints | log_array, "may the force be with", "answer to life" | **0** |
| **Attack vocabulary (expected, NOT app leakage)** | `union select` (935), `' or '1'='1` (150), `../` (128 870), `/etc/passwd` (15 596), `{{7*7}}` (140) | present by design |

**No app-identifying token appears anywhere in the training or selection corpus.**
The only nonzero app-list entry was the deliberately-weak token `42` (378 758 hits —
byte counts, ids, offsets; discounted and not treated as the D33pTh0ught hint).

The attack-vocabulary tokens **are** present, and that is correct: V5.1/Model2 are
trained to detect SQLi, traversal and SSTI, so payload words must appear in their
corpus. Their presence says nothing about whether these six apps were seen.

## 5. The ObC00ki3s benign-JS case is a known DEV regression

V5.1 blocked the benign ObC00ki3s static JS (`Open redirect payload detected.`) during
the 2026-11-05 dry run — a **known** false positive, not a new finding. Per instruction it
is retained as a **separate DEV regression** (population tag distinct from the independent
test) and **excluded from the primary metric** of the independent campaign. It still has a
sealed row so the regression stays visible.

## 6. Limits (carried into every per-app report)

1. **Substring, not semantic.** The search finds literal app identifiers; it cannot prove
   the absence of *structurally similar* synthetic inputs.
2. **Vocabulary/structural overlap is expected and uncontrolled.** The attack cases I will
   author in Phase 2 use the same injection vocabulary the models trained on. This supports
   an **"unseen application / unseen effect-bearing request against a real app"** claim, **not**
   an "unseen attack family/payload" claim. A per-case exact-canonical-text overlap re-audit
   (hash each authored case's canonical text against the corpus) will be run **after** case
   authoring and reported before sealing.
3. **Selection pools, not just final splits.** The 434 MB `datasets/v5_sources/` pool is the
   superset from which TRAIN/VALIDATION/INTERNAL_TEST were drawn; it is searched in full, so
   the audit is conservative (broader than the exact fitted rows).
4. **App source tree not in scope of "training data".** The apps' own code
   (`render_template`, `send_file`) returns 0 because the corpus is HTTP-request rows, not
   server source — expected, and consistent with the apps being external to the corpus.

## 7. Conclusion

On the evidence, the six applications, their routes, templates, assets and flag hints are
**absent** from the V5.1 and Model2 training and selection data. The three detection-relevant
apps (An0nB0ard/SQLi, CatP1cs/traversal, Inf3ct/SSTI) may be described as **unseen
applications**; D33pTh0ught, ag3ncy and ObC00ki3s are out-of-vocabulary / false-positive
controls by design. The claim is **application-level independence**, bounded by the
vocabulary-overlap limit in §6.2.
