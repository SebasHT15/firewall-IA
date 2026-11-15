# V4 ↔ Analyzer disagreement diagnostics — `v4-analyzer-disagreement-v1`

**DIAGNOSTIC on development data (issue #57). Not an evaluation, not an external test.**

This study crosses, for each development text:

- the known label;
- TinyLlama V4's decision;
- the frozen Analyzer's `attack` probability;
- its auxiliary category (context only, D46).

Nothing was trained, re-calibrated or thresholded. No ALLOW / BLOCK / UNCERTAIN policy is
proposed. The bands below are fixed descriptive bins, and 0.5 appears only as the D55 reporting
convention. Every number is a **diagnostic count on a composition chosen by its authors**. None
is an FPR, recall, prevalence or operational rate (D42, methodology §7).

| | |
|---|---|
| Date | 2026-10-05 |
| Base | `develop` = `3c8e860` (PR #55 merged), branch `research/v4-analyzer-disagreement-diagnostics`, uncommitted |
| Protocol | [`PROTOCOL.md`](PROTOCOL.md) — written before scoring. Revision 1 (§8) was made after the independent data-roles audit and still before scoring |
| Analyzer | `hybrid-analyzer-v2/attack=hist_gb,category=hist_gb`, `recommended.pkl` `79eb7265…`. Hash checked before and after the run; **unchanged** |
| V4 | `model-output-v4-clean`, adapter `7bf16875…`, greedy decoding (`inference_core`) |
| Code | `scripts/evaluation/v4_analyzer_disagreement.py` `cd3452f9…` (= `evaluator_sha256` in `results.json`), `scripts/evaluation/v4_manual_suite_decisions.py` `c2efb06f…`, `tests/test_v4_analyzer_disagreement.py` `3c3f9634…` |
| Evidence | `results.json` (all counts) · `records.jsonl` (one record per scored development text) · `raw/` (V4 re-run records, metadata and logs) · `SHA256SUMS` |

## 1. Sources and roles

| Source | What | V4 decisions | Role for the Analyzer | Scored |
|---|---|---|---|---|
| **S1** `real-http-fp-v1` | 149 constructed benign unique texts | Recorded on 2026-09-18, 3/3 deterministic | Never fitted or selected on | **119 texts**. The 30 `EVALSWAP` texts are excluded: they are V4-clean eval rows, i.e. INTERNAL TEST, which D54 closed after one second look |
| **S2** legacy manual suite (`test_model.py`) | 135 hand-authored texts: 109 BLOCK / 26 ALLOW | **Re-run once** (inference only). It reproduces the stored legacy run exactly: every category, and TP 104 · FP 6 · FN 5 · TN 20 | Never fitted or selected on | **135 texts** |
| V4-clean train = Analyzer TRAIN ∪ VALIDATION | Fitted / selected | — | Seen | Not used. Never evidence of false negatives |
| V4-clean eval = Analyzer INTERNAL TEST | Per-row V4 decisions exist | — | Read twice; D54 allows no third look | **Not used**. Needs an owner decision |
| External Test v1 | — | — | One aggregate evaluation done (D53) | **Never opened.** Only its published aggregates are cited, as a risk signal |

**Overlap with the Analyzer's training data** (membership only, PROTOCOL §4):

- S1: 4 texts share a vector or canonical request with TRAIN ∪ VALIDATION. They are one CSIC
  image path, `/miembros/imagenes/zarauz.jpg`. The same 4 also share a vector or canonical request
  with INTERNAL TEST; they are flagged only, and no INTERNAL TEST label was read.
- S2: 2 benign texts are "seen" (the two CSIC-style cases). Both are V4-correct ALLOW in
  `[0, 0.1)`, so they change no false-positive or low-band count (`results.json` also gives the
  unseen-only tables).
- No exact text from either source is in V4-clean train or eval.
- The canonical-request relation reproduced the v2 build on 25,134 / 25,134 rows.

**After this study, S1 and S2 are Hybrid error-analysis data** (D37). They cannot later serve as
independent evidence for a cascade or a decision model.

## 2. The unit problem: texts vs feature vectors

V4 reads the whole D1 text. The Analyzer reads only 34 features of path, query, body and
`Content-Type` (D44), so two texts with the same feature vector always get the same Analyzer
score.

- **S1:** 119 texts collapse to **8 feature vectors**. The 37 texts V4 blocks fall on **5**
  vectors. One vector (`GET /index.html`) alone holds 87 texts: 29 that V4 blocks and 58 that
  V4 allows.
- **S2:** 135 texts give 134 vectors. The two `' OR '1'='1` spellings share one.

For S1, Analyzer-side results are therefore counted **per vector first**. S1 texts are not
independent Analyzer observations.

## 3. Measured results

### 3.1 S1 — V4 false positives on constructed benign requests (all ALLOW)

The 8 distinct vectors (primary unit):

| Vectors | V4 decisions on their texts | Analyzer band |
|---:|---|---|
| 3 | ALLOW only | `[0, 0.1)` |
| 4 | **ALLOW and BLOCK** | `[0, 0.1)` |
| 1 | **ALLOW and BLOCK** (`GET /`) | `[0.1, 0.5)`, 0.43 |

At the text level, all 119 texts score below 0.5:

| | V4 ALLOW | V4 BLOCK |
|---|---:|---:|
| Analyzer `attack < 0.5` | 82 | 37 |
| Analyzer `attack ≥ 0.5` | 0 | 0 |

The maximum Analyzer score on S1 is 0.43.

**A/B pairs.** Each pair changes one variable against a reference:

| Varied | V4 flips | Analyzer changes |
|---|---:|---:|
| A header (HOST, PORT, HDR, UA, UAxPC): 101 pairs | 19 | 0 — **by construction**, D44 tautology |
| The path (PATH): 24 pairs | 6 | 24 |

**V4's reasons on the 37 blocked texts:**

| V4 reason | Texts |
|---|---:|
| SSRF | 25 |
| File inclusion | 4 |
| HTTP parameter pollution | 3 |
| Open redirect | 3 |
| Request smuggling | 2 |

The Analyzer's category on these texts is mostly `other_attack`. It is conditioned on attack
and means nothing for scores this low.

### 3.2 S2 — the manual suite (109 BLOCK / 26 ALLOW)

**Label × V4 × Analyzer band (texts).** S2 has 134 vectors, so the text and vector counts
nearly coincide.

| Label | V4 | `[0,0.1)` | `[0.1,0.5)` | `[0.5,0.9)` | `[0.9,1]` |
|---|---|---:|---:|---:|---:|
| ALLOW | ALLOW (TN, 20) | 6 | 4 | 2 | **8** |
| ALLOW | **BLOCK (FP, 6)** | **3** | 0 | 0 | **3** |
| BLOCK | **ALLOW (FN, 5)** | 4 | 0 | 0 | 1 |
| BLOCK | BLOCK (TP, 104) | **10** | **10** | 11 | 73 |

**The complementarity question, per band.** Compare V4's errors with V4's correct attacks in
the same band:

- `[0, 0.1)` holds 3 of V4's false positives, **10 attacks V4 blocks** and 4 of V4's 5 misses.
  S2 has 4 attacks per benign text, so these counts reflect its mix; they are not a ratio of
  anything (D42).
- `[0.9, 1]` holds the other 3 V4 false positives and 8 benign texts V4 allows correctly.
- Overall, 20 of the 104 attacks V4 blocks (19 distinct vectors) score below 0.5.
- **V4 is often right for the wrong reason in that low band.** It blocks the CSRF cases as
  "Command injection" (×2), the Java serialized object as "JWT", and the pipe injection as "LDAP".
  S2 has **no benign form-urlencoded POST**, so V4's CSRF "hits" cannot be told apart from a
  false-positive pattern.

**Signal location of the 109 attacks**, fixed before scoring:

| Location | Texts | V4 BLOCK | Analyzer `< 0.1` | Analyzer median |
|---|---:|---:|---:|---:|
| surface (path / query / body) | 94 | 92 | 5 | 0.99 |
| header-only (JWT `Authorization`, CSRF `Origin` / `Referer`) | 10 | 7 | 9 | 0.003 |
| header-dependent (smuggling: CL / TE headers) | 5 | 5 | 0 | 0.46 |

The single header-only text at ≥ 0.1 (0.61) is the CSRF case whose body carries `csrf_token=`,
so that one has some surface signal.

**Benign texts (26):**

- The Analyzer scores ≥ 0.5 on **13**. V4 blocks **6**.
- By shape: 8 of the 9 benign JSON `POST` / `PUT` texts score ≥ 0.5 (median 0.974), against
  5 of the 17 benign `GET` texts. **The JSON attacks score the same way:** 7 of 9 at ≥ 0.5
  (median 0.979). On JSON bodies the Analyzer does not separate the two labels in S2.

### 3.3 Extreme probabilities (`< 0.01` or `≥ 0.99`), S1 + S2 texts

| Group | `< 0.01` | `≥ 0.99` |
|---|---:|---:|
| Benign, V4 ALLOW | 75 | 3 |
| Benign, V4 BLOCK | 33 | 2 |
| Attack, V4 BLOCK | 5 | 49 |
| Attack, V4 ALLOW | 2 | — |

- Seven attacks score **< 0.01**: all 5 JWT cases, a CSRF case and the Java serialized object.
  Two of the seven are V4 misses (one JWT, one CSRF).
- Five benign texts score **≥ 0.99**: webhook with base64, user feedback with HTML, login with
  special characters, search with "select", and the multi-ID batch fetch.

The Analyzer is confidently wrong in both directions on texts it was not fitted on.

### 3.4 Auxiliary category (context only, D46)

- On the 104 S2 attacks with a D47 mapping, top-1 agrees on **49**.
- The expected-category breakdown shows systematic drift:
  - `open_redirect` → `path_file_access` (5/5);
  - `sql_injection` is mostly predicted as something else (agrees 3/11);
  - `ssrf` agrees 1/5.
- Several suite labels do not map cleanly. For example, the XSS and Open Redirect
  `javascript:` URLs, and an XXE case that targets 169.254.169.254.
- The category says nothing useful on benign texts.

## 4. Development examples (illustrations, not counts)

These are individual S1 / S2 cases, which are allowed as development data.

- **V4 false positives on keyword text, which the Analyzer scores low:**
  - `GET /api/products/search?q=select+blue+jeans…` → V4 BLOCK ("SQL injection"), Analyzer 0.026;
  - `GET /ui/dropdown?action=drop&item=table` → V4 BLOCK ("HTTP parameter pollution"), 0.014;
  - `GET /api/search?q=select+your+plan` → V4 BLOCK, 0.024.
- **V4 true positives the Analyzer scores just as low:**
  - `GET /api/exec?cmd=\`id\`` → 0.037;
  - `GET /api/lookup?domain=example.com|whoami` → 0.042 (V4's reason: "LDAP");
  - `GET /redirect?url=javascript:alert(1)` → 0.060;
  - the Java serialized object → 0.003.

  These four are surface attacks; D44 header blindness does not explain them.
- **V4 false positives the Analyzer scores high:**
  - feedback JSON with `<b>` and `&` → 0.99;
  - webhook JSON with a base64 body → 0.997;
  - analytics date range → 0.98.

  The analytics case shows that "both systems treat it as an attack" can be a coincidence. V4's
  reason is "JWT token manipulation", about the `Authorization` header the Analyzer cannot see,
  while the Analyzer reacts to the query.
- **Benign API requests V4 allows but the Analyzer scores high:**
  - login JSON → 0.99;
  - settings `PUT` → 0.96;
  - GraphQL query → 0.92;
  - `?ids=1,2,3,4,5&fields=…` → 0.993;
  - `?q=how+to+select+a+good+password&lang=en` → 0.993.
- **Header-borne attacks:**
  - the 5 JWT cases score 0.0003–0.0033;
  - the valid-JWT benign case scores 0.024, almost the same vector;
  - 4 of 5 CSRF cases score below 0.1.
- **S1, `GET /index.html`:** V4 blocks it with `Host: 127.0.0.1` or a high port and allows it with
  `Host: localhost`. The Analyzer gives every variant 0.0013, because `Host` is not a feature.
- **S1, paths:** V4 also blocks with `Host: localhost` when only the path changes, e.g. `GET /`
  ("smuggling") and `GET /favicon.ico` ("file inclusion") in the curl contexts.

## 5. Hypotheses (not measured here; to be tested on a proper development set)

- **H1 — character counting, not words.** The Analyzer's low scores on keyword false positives
  and on the backtick / pipe / `javascript:` attacks may come from both having few symbols.
  RequestFeatures v2 has no token features. The report itself holds counterexamples: low-symbol
  queries such as `?q=how+to+select+…` and `?ids=1,2,3,4,5…` score ≥ 0.99. So the mechanism is
  at most partial.
- **H2 — a JSON / API shortcut.** JSON bodies score high whatever the label in S2 (benign 8/9,
  attacks 7/9 at ≥ 0.5). A `Content-Type` or body-shape shortcut is plausible but untested. The
  CSRF and JWT results above are not evidence for or against it.
- **H3 — what a Model 2 could see.** A Model 2 fed V4's decision **and reason** would indirectly
  carry some header and token signal. In the low band, V4's reasons differ between its false
  positives (HPP / SQLi in S2; SSRF, file inclusion, HPP, open redirect, smuggling in S1) and its
  true positives (JWT, command injection, LDAP, open redirect). Whether that separates them cannot
  be tested at this n. Using V4's output as a Model 2 input may also be an indirect `Host`
  channel, which is an open question under D44.

## 6. Answers to the five questions

1. **When V4 blocks a benign request, what does the Analyzer say?**
   - **S1:** below 0.5 on all 37 blocked texts (5 vectors; 4 of them below 0.1). Most of these
     blocks flip with a header change: 19 of 101 header pairs flip. Some flip with the path: 6 of
     24 path pairs. The Analyzer gives a blocked text and its allowed twin the same score when they
     differ only in a header. So its low score says nothing about why V4 blocked.
   - **S2** (6 false positives): low on the 3 keyword GET cases, ≥ 0.98 on the 3 API / JSON-style
     cases.
2. **Are there benign requests both treat as attacks?** Yes: 3 of S2's 6 V4 false positives. At
   least one agreement is coincidental, since the two systems react to different parts of the
   request. None in S1.
3. **Are there attacks V4 blocks that the Analyzer scores low?** Yes.
   - 20 of the 104 S2 attacks V4 blocks score below 0.5; 10 of them below 0.1.
   - Of those 10, 6 are header-only (JWT, CSRF: blind by construction).
   - **4 are surface attacks** (backtick, pipe, `javascript:`, Java serialized object).

   The reverse also exists: one V4-missed GraphQL introspection scores 0.92.
4. **What is outside RequestFeatures v2?**
   - Every header except `Content-Type`: in S1, Host, port, User-Agent, Proxy-Connection,
     Connection and Cookie; in S2, JWT `Authorization`, CSRF `Origin` / `Referer`, and smuggling
     CL / TE.
   - Words, as a structural fact: the features count characters, not tokens.
5. **What data are missing?** A labelled development set **with attacks**, which is
   generator-group-disjoint from V4-clean / hybrid_analyzer_v2. It needs enough cases per category
   (D18: ≥ 30), V4 decisions **with reasons**, and benign near-neighbours on the same endpoints:
   JSON APIs, form-urlencoded POSTs (absent from S2) and pages. It also needs low-symbol and keyword
   attacks, plain-URL SSRF / open redirect, and header-borne attacks.

   Nothing we may use today measures how many attacks would pass if V4's BLOCK were overridden:
   - S1 has no attacks;
   - S2 has ≤ 5 attacks per category, hand-authored;
   - INTERNAL TEST is closed (D54);
   - External v1 is forbidden.

## 7. Supported conclusions

- **A low Analyzer score is not shown to be a safe signal to override a V4 BLOCK.** On texts the
  Analyzer was never fitted on, it scores 10 attacks V4 blocks below 0.1. Four of them are not
  explained by D44 header blindness. This is an existence result, not a rate.
- **In S1, the Analyzer cannot tell V4's false positives from their allowed twins** when the twins
  differ only in a header. For this kind of false positive, that blindness is by design (D44) and
  is the property one would want. The open risk is entirely on the false-negative side, which S1
  cannot measure.
- **In S2, the Analyzer has its own high scores on API / JSON benign requests**, often extreme.
  They overlap with 3 of V4's 6 false positives. On JSON bodies it does not separate the labels:
  benign 8/9 and attacks 7/9 score ≥ 0.5. *(Context only, not used for any design: External v1's
  published aggregate points the same way, with `api-json` at 29/40 at the reporting-only 0.5.)*
- **The auxiliary category is not reliable on these texts** (49 / 104 top-1) and should stay
  context only (D46).
- **The false-negative risk of any cascade cannot be estimated with the data we may use.**

## 8. Not supported (and not claimed)

- Any rate (FPR, recall, precision, prevalence), threshold or policy. The band edges are not
  candidate operating points (D55).
- Ratios between labels within a band, which reflect S2's mix (104 attacks / 26 benign).
- "k / 37 false positives rescued": S1 has 8 vectors and no attacks.
- Any cause of V4's decisions beyond "this variable changed and the decision changed in this
  context".
- Analyzer robustness to headers: that holds by construction (D44).
- Calibrated confidence (D50); memorization or overfitting (D42).
- Anything about JWT / CSRF detection by the Analyzer, INTERNAL TEST, or External v1 cases.
- Per-case equality between the re-run and the stored legacy V4 run.

## 9. Limitations

- S1 is all benign and collapses to 8 vectors.
- S2 is small (5 per attack category), hand-authored and old:
  - its adversarial transforms reuse training augmentation;
  - 2 of its benign texts are CSIC shapes seen in training;
  - it has no benign form-urlencoded POST;
  - its overlap with External v1 is unknown and was not checked.
- V4's correct blocks are sometimes for the wrong reason (§3.2). "V4 BLOCK" is therefore a weaker
  ground for comparison than it looks.
- The S2 V4 decisions come from one deterministic re-run with the refactored runtime. Only the
  counts match the stored run.
- **The protocol was not committed before scoring.** It was written and revised before scoring,
  and `results.json` records its hash (`29d15048…`). That proves it did not change after the run,
  not when it was written.

## 10. Recommendation: **C**; B, V5 and a V4-reason-aware A are hypotheses C must test

**C — build a better development diagnostic set first.** The question behind a cascade is how
many V4 false positives can be rescued *without adding false negatives*. Its second half cannot be
measured with any data we may use (§6.5). This study shows the risk exists: V4-blocked surface
attacks in the Analyzer's lowest band (§7).

The proposed set is a development diagnostic, labelled as such from day one:

- captured through the lab gateway;
- generator-group-disjoint from V4-clean and hybrid_analyzer_v2;
- ≥ 30 cases per targeted category;
- paired benign / attack near-neighbours on the same JSON-API, form-POST and page endpoints;
- low-symbol and keyword attacks, and header-borne attacks (JWT, CSRF, Host / SSRF-via-header,
  smuggling);
- V4 decisions **and reasons** recorded;
- External-v1 collision checking only by owner decision.

**What C must decide between** (none is chosen here):

- **A with V4's reason as an input.** For false positives that flip with a header change, the Analyzer's blindness
  is the desired property. If V4's reason separates its false positives from its true positives
  in the low band (H3), a cautious Model 2 might work without new features. This is untested here.
  A Model 2 built only on RequestFeatures v2 + the Analyzer score would inherit the blind spots
  (§6.4).
- **B — new features or a future Analyzer.** Indicated by the header and word blind spots and by
  H1 / H2. Feature choice must come from development data such as C, **never from External v1**
  (D53). Model 1 v2 stays frozen as historical evidence.
- **V5 / hard negatives for V4.** The Host / port / path and keyword false positives are V4
  defects (CONTEXT §0.9 step 5). C's set would also serve this, under D37 / D40 roles.

## 11. Open questions (for the owner)

1. Approve building the C development set (scope, size, categories, collision policy)?
2. Should INTERNAL TEST ever be used for a V4 × Analyzer cross (a third look)? D54 says no without
   a decision.
3. Should header information enter the Hybrid pipeline (a D44 revision for `Host`, `Origin`,
   `Authorization`, CL / TE), given that `Host` and `User-Agent` were label shortcuts in V4's data
   (D1)? Is V4's output an acceptable indirect channel?
4. Should token-level features be considered for a future Analyzer (H1)?

## 12. Review record

- **Data-roles audit** (independent, read-only, before scoring): 2 blockers, resolved in protocol
  revision 1.
  - A definition of a "look" at INTERNAL TEST.
  - Per-vector-first counting, because S1 collapses to 8 vectors.
- **Analysis / conclusions review** (independent, read-only, after scoring): every count was
  recomputed and confirmed. 5 blocking wording issues were resolved in this README:
  - a missing `SHA256SUMS`;
  - a cross-label ratio;
  - an over-causal "header-driven";
  - External v1 cited inside the conclusions;
  - a mechanism stated as fact.

  Non-blocking points were adopted in §3.2 and §4–§10.
