# V4 minimal-pair probe — PROTOCOL (`v5-minimal-pairs-v1`)

**STATUS: PRE-REGISTERED.** This file, the case generator, the scoring/analysis script, the
manifest and the cases are hashed in `SHA256SUMS` **before any V4 inference**. `run` refuses to
start if any of them differs. Anything learned after execution goes to `README.md` under
**OBSERVED AFTER EXECUTION**. This file is never edited after the anchor; corrections are
appended to the README as dated deviations.

Derived from `reports/v5/benign-coverage-audit-v1/MINIMAL_PAIR_PROTOCOL_DRAFT.md`. Every change
from the draft is listed in §11 with its reason.

## 1. Question

> Which isolated changes to the content or envelope of a benign request produce reproducible
> ALLOW ↔ BLOCK changes in V4?

The probe separates the mechanisms that the coverage audit could not tell apart (audit §6.4, §7):

| ID | Mechanism |
|---|---|
| M-content | benign content coverage gaps in V4-clean TRAIN |
| M-envelope | envelope train/serve skew: `Content-Length` / `Transfer-Encoding` on ordinary bodies, unseen ports or port-host combinations, `Proxy-Connection`, a loopback or portless IP Host (an IP Host *with* a port, `10.20.30.40:8000`, is in V4's shared pool) |
| M-token | the `127.0.0.1` token, learned only in BLOCK rows, applied in the Host position |
| M-instability | decision instability near the boundary, on covered dimensions |

## 2. Data role and independence

- **DEVELOPMENT DIAGNOSTIC DATA.** It is never V5 training, validation or checkpoint-selection
  data. The V5 generator must not reuse its texts, templates or pools.
  - Each pool's SHA-256 is in `manifest.json → pools_sha256`.
  - V5 may use the *concepts* derived from the results (which mechanism to fix first), never
    the texts.
- **Every case is benign by construction.** It is a request to a fictitious municipal library
  and events portal. No attack counterpart is part of this probe; that keeps the question
  about false blocks and keeps the suite simple.
- **Nothing is copied from:**
  - `fwlab.test` or the lab-app routes;
  - any #57/#60 text, value or template;
  - External Test v1 (never opened);
  - INTERNAL TEST / V4 eval (never opened).

  Hosts are reserved example domains under `.example.net` / `.example.org` (RFC 2606/6761). They
  do not appear in V4's generator pool. Endpoints and value pools are written for this probe.
  Tests assert both rules (`tests/test_v4_minimal_pair_probe.py`).

## 3. Units, bases and pairs

- **Independent unit:** one *base*, i.e. one value tuple drawn once from the pools with a
  per-base RNG `Random("20261006|<factor>|<base>|<attempt>")`.
  - A base whose text repeats any earlier text, of any factor, is redrawn (`attempt + 1`).
  - Each factor has its own bases. Bases are never shared between factors.
  - In F-APOS, F-PUNCT and F-FREETEXT, the manipulated value itself is distinct for each of
    the 30 bases (surname, clause pair, keyword and sentence).
  - In F-WORD, every homonym appears in both carriers (3 GET + 2 form). Per-homonym counts are
    5 bases each, so they are **INSUFFICIENT DATA** (D19 support < 30) and descriptive only.
- **Levels** of one base are dependent and never counted as independent.
- **Comparison:** reference level vs one other level of the same base. The two texts differ in
  exactly one declared dimension. Tests check this for every pair:
  - ENVELOPE, CONTROL-ENV and F-CTB pairs keep the request line and body identical and change
    one header;
  - CONTENT pairs keep the header block identical and change either the request line or the
    body, never both.
  - The serve-like twins (`*_cl` levels) are the one exception: `Content-Length` follows the
    body, as it does on the wire.
- **Size:** at least 30 bases per factor (D19's support threshold; D18 is the < 100-group
  rule).
  - F-CL and CONTROL-COV have 40 bases; F-WORD has 60.
  - Totals: 20 factors, 48 comparisons, 2,120 cases, all of them unique texts.

## 4. Rendering (D1)

Same layout as `parse_dataset_v4.render_request`:
- `METHOD /target HTTP/1.1`, one `Name: value` line per header, LF line endings, no trailing
  newline;
- a blank line and the body only when there is a body;
- query and form values encoded with `quote(v, safe="")`, except where the encoding is the
  factor;
- JSON written with `json.dumps` default separators.

The base envelope is `Host`, `User-Agent` and `Accept`, drawn per base from probe pools. A body
request ends with `Content-Type`.

`Content-Length` is **absent** from every base. It appears only:
- at the F-CL `present` level, inserted directly before `Content-Type` with the correct UTF-8
  byte length;
- in the serve-like `*_cl` twins of F-NFIELDS and F-JSON.

F-CL `te_chunked` inserts `Transfer-Encoding: chunked` at the same position. The body stays
de-chunked, exactly as the gateway renders it.

**Pre-declared reading.** In V4's generator, "`Content-Length` then `Content-Type` as the last two
headers" and `Transfer-Encoding` occur only in the request-smuggling framing shape
(`parse_dataset_v4.py`, `framing_headers` and smuggling payloads). F-CL flips whose BLOCK reason
names request smuggling are therefore read as a **learned layout/token association**, not as
generic envelope novelty.

**Why absent in the bases.** Absent matches V4 TRAIN, where 9 of 13,686 body rows carry it. So
every content factor is measured in a train-like envelope, separately from the envelope skew. The
deployed gateway does pass `Content-Length` on real bodies (research note F: mitmproxy 12.2.3
passes it unchanged, and a chunked body arrives de-chunked with `Transfer-Encoding: chunked`).
That is exactly why F-CL is a factor.

The content × `Content-Length` interaction is tested on paired twins:
- F-NFIELDS `n1_cl → n2_cl`;
- F-JSON `k1_cl → k4_cl`.

F-CL's four body strata remain descriptive.

## 5. Factors and comparisons

| Factor | Block | Bases | Carrier | Comparisons (reference → level) | Tests |
|---|---|---:|---|---|---|
| F-CL | ENVELOPE | 40 | body; strata form 1 field / form 2 fields / JSON 1 key / JSON 3 keys (10 each) | absent → `Content-Length` (correct value) · absent → `Transfer-Encoding: chunked` (de-chunked body) | M-envelope |
| F-PORT | ENVELOPE | 30 | GET / form, alternating | none → `:8080` · none → `:8443` · none → `:30000` (every port on a DNS name is unseen; V4 has `:8080` only on `localhost`) | M-envelope |
| F-HOSTIP | ENVELOPE | 30 | GET / form | DNS → `127.0.0.1` · DNS → `10.0.0.5` · DNS → `203.0.113.10` (RFC 5737, public, portless) · `203.0.113.10` → `127.0.0.1` · `203.0.113.10` → `10.0.0.5` | M-token / M-envelope |
| F-PXY | ENVELOPE | 30 | GET / form | absent → `Proxy-Connection: keep-alive` | M-envelope |
| F-NQUERY | CONTENT | 30 | GET | 1 → 2 params · 1 → 4 params (neutral extras appended) | M-content |
| F-NFIELDS | CONTENT | 30 | form | 1 → 2 · 1 → 3 · 1 → 5 fields (neutral extras appended) · serve-like 1 → 2 fields, both with `Content-Length` | M-content (+ × CL) |
| F-PWD | CONTENT | 30 | form, 1 field | 12-char alphanumeric → one char replaced by `!` · `#` · `-` · `@`. `-` (literal) and `@` (encoded `%40`) are covered within-factor controls | M-content |
| F-APOS | CONTENT | 30 | GET / form | surname without → with apostrophe (`oneil` → `o'neil`) | M-content |
| F-ADDR | CONTENT | 30 | GET / form | `N Street Apt k` → insert `,` (covered) · insert `#` before the unit number · `,` → `#` (both encoded: an encoding-matched covered control) | M-content |
| F-PUNCT | CONTENT | 30 | GET / form, prose note | `A, B.` → `A; B.` · `A & B.` · `A, B!` · `A, B?` (`?` covered, control) | M-content |
| F-WORD | CONTENT | 60 | GET `q` / form `message`, prose | neutral synonym → SQL/shell homonym, one word, same slot. 12 homonyms × 5 bases: select, union, from, where, table, call, match, include, order, drop, and, or | M-content |
| F-FREETEXT | CONTENT | 30 | GET / form | one keyword → a natural sentence containing it (covered characters, no homonym) | M-content |
| F-JSON | CONTENT | 30 | JSON body, `application/json` | 1 string key → 4 string keys · 4 strings → one number · → one boolean · → one nested object · → one array · serve-like 1 → 4 keys, both with `Content-Length` | M-content (+ × CL) |
| F-CTB | CONTENT | 30 | form body | `Content-Type` form → `application/json` (body unchanged) | M-content (reverse shortcut, audit §3.3) |
| F-ENC | CONTENT | 30 | GET query | space as `%20` → `+` | M-content |
| F-PATH | CONTENT | 30 | GET path | depth 3 → depth 5 (two neutral segments) · `/` → `%2F` between the last two segments | M-content |
| F-URL | CONTENT | 30 | GET URL-valued param named `website` / `link` (not `next` / `return_url`, so an external URL is not the open-redirect shape) | https same host as `Host` → https external host · https external → http external | M-content |
| F-NAME | CONTENT | 30 | GET / form | parameter `note` → `template` · `callback` · `file`, identical benign value | M-content (name semantics) |
| CONTROL-COV | CONTROL | 40 | GET / form | username A → username B, both from covered classes (letters, digits, `.`, `-`) | M-instability |
| CONTROL-ENV | CONTROL | 30 | GET / form | absent → `Accept-Language: en-US,en;q=0.9` (a class-balanced V4 envelope value) | M-instability (envelope) |

**Inherent side effects, accepted and declared:**
- **Percent-encoding.** `!`, `#`, `'`, `;`, `&`, `,` and `?` are percent-encoded by `quote`, as
  every V4 TRAIN value is. The factor is "this character in the value", and its encoded form is
  how V4 always sees it.
- **Length.** Every content change alters body or request-target length. Without
  `Content-Length`, the envelope is unchanged.
- **F-FREETEXT** changes length and word count jointly, by nature.
- **F-PATH `%2F`** also lowers the literal segment count.
- **F-JSON 1 → 4 keys** changes cardinality only (all strings). Each type comparison changes a
  single leaf.

## 6. Execution

- **Model:** frozen V4 via the unchanged `control_plane/inference_core.py`. That is
  `load_model`, `classify_raw` (greedy, `do_sample=False`, `max_new_tokens=40`) and
  `parse_prediction`.
  - The envelope is part of the text, so the gateway is not needed.
  - No logits; `inference_core` is not modified.
  - The adapter SHA-256 `7bf16875…` is checked before and after.
- **Phase 1 — CONTROL-REP (determinism).**
  - 10% of unique texts (212, seeded sample) are scored 3 times.
  - Any difference in the raw generated text stops the run before phase 2. The analysis then
    withholds every effect class. The cause is analysed before anything is interpreted.
  - Phase 2 adds a 4th execution of those texts, which is also compared.
- **Phase 2.** Every unique text is scored once, in a shuffled order (seed
  `v5-minimal-pairs-v1|order`).
- **Single run.** Scoring runs once (`run` refuses to overwrite). The analysis is offline and
  deterministic from `raw/records.jsonl`.

## 7. Metrics, tests and pre-registered classification

**Per comparison.** Invalid outputs are excluded pairwise and counted (never coerced, E5/D25).
- N (valid pairs), and the four cells A→A, A→B, B→A, B→B.
- **Flip rate** = (A→B + B→A) / N, with an exact Clopper–Pearson 95% interval.
- **Net direction** = (A→B − B→A) / N.
- **Baseline ALLOW rate** (reference) and **paired ALLOW rate** (level).
- Conditional A→B among reference-ALLOW bases, and conditional B→A among reference-BLOCK bases.
- **Direction consistency** = max(A→B, B→A) / discordant.
- Reason changes when the decision is unchanged, and the BLOCK reasons involved in flips
  (secondary).

**Tests.**
- Exact McNemar, **two-sided**: binomial on the discordant pairs, p = 0.5.
- Holm correction **within two families**, α = 0.05:
  - ENVELOPE: 11 comparisons;
  - CONTENT: 35 comparisons.
- The two controls are outside every family and are reported with their raw p.
- **p-values are not the main result.** The interpretation rests on effect size, direction,
  consistency and reproducibility. "Not significant" never means "no effect".

**Effect class** (fixed here, implemented in `classify_effect`):

| Class | Condition (D = dominant-direction flips, N = valid pairs) |
|---|---|
| **STRONG EFFECT** | D/N ≥ 0.20 **and** consistency ≥ 0.80 **and** Holm rejects within its family **and** flip rate > the matched control's Clopper–Pearson 95% upper bound |
| **MODERATE EFFECT** | not STRONG; D ≥ 6 **and** D/N ≥ 0.10 **and** consistency ≥ 0.80 **and** flip rate > the matched control's 95% upper bound |
| **WEAK/INCONCLUSIVE** | ≥ 1 discordant pair and neither of the above (3–5 consistent flips land here) |
| **NO OBSERVED EFFECT** | 0 discordant pairs. This does not exclude an effect: with N = 30 the two-sided 95% upper bound of the flip rate is 0.116 |

- **Matched controls.**
  - ENVELOPE comparisons and F-CTB (a header change) are compared with CONTROL-ENV, which uses
    the same base builder.
  - CONTENT comparisons are compared with CONTROL-COV.
  - Controls are classified with neither the control condition nor Holm; their raw p < 0.05
    stands in for the Holm condition.
- **Sensitivity.**
  - Conditional A→B is reported among reference-ALLOW bases, with its Clopper–Pearson
    interval. Conditional B→A is reported among reference-BLOCK bases, likewise.
  - `LOW_SENSITIVITY_A_TO_B` is set when fewer than 20 bases are ALLOW at the reference. The
    absence of A→B flips is then not interpreted. `LOW_SENSITIVITY_B_TO_A` is symmetric.
- **Side effects** are reported per comparison, as level minus reference (min / mean / max):
  - characters;
  - `%XX` triplets;
  - prompt tokens (TinyLlama tokenizer, recorded at scoring time).
- **Reference decisions by Host value** are reported. The probe's hosts are new reserved
  domains, so this checks whether the host novelty itself pushes references toward BLOCK.
- **Factor-level reading.** The strongest class among the factor's comparisons, naming the
  comparison.

## 8. Hypotheses and falsification

**Hypotheses are supported only by STRONG comparisons**, which are Holm-controlled. MODERATE is
reported as suggestive and supports nothing on its own.

- **H-envelope.** At least one ENVELOPE comparison other than the `203.0.113.10 → …` contrasts
  is STRONG in the A→B direction. **Falsified** if none is.
- **H-token.** `203.0.113.10 → 127.0.0.1` is STRONG A→B **and** `203.0.113.10 → 10.0.0.5` is
  not.
  - Against a portless public IP Host, only the loopback literal moves V4. That supports the
    token association (M-token).
  - If DNS → `203.0.113.10` is itself STRONG A→B, any portless IP Host matters: M-envelope, not
    M-token.
  - Whether `10.x` literals occur in V4's attack payloads is UNVERIFIED, so `10.0.0.5` is not a
    neutral null.
- **H-content.** At least one of these is STRONG A→B:
  - F-PWD(`!`/`#`);
  - F-APOS;
  - F-ADDR(`#`);
  - F-PUNCT(`;`/`&`/`!`);
  - F-WORD;
  - F-NFIELDS;
  - F-NQUERY;
  - F-JSON(1 → 4 keys or any type);
  - F-PATH;
  - F-URL;
  - F-NAME.
  
  **Within-factor controls:** F-PWD(`-`, `@`), F-ADDR(`,`) and F-PUNCT(`?`) are covered
  characters, and `@`, `,` and `?` are percent-encoded like the uncovered ones. If they flip as
  often as the uncovered ones, the effect is a "value change" or "encoding" effect, not a
  coverage effect.
- **H-content-serve.** Whether a content effect survives the serve envelope is read from
  `n1_cl → n2_cl` and `k1_cl → k4_cl`, against `n1 → n2` and `k1_string → k4_strings`. This is
  descriptive unless STRONG.
- **H-reverse.** F-CTB(form → JSON type) shows B→A. Not a primary hypothesis: it is only
  observable if form references are blocked.
- **M-instability is material** if CONTROL-COV's flip-rate Clopper–Pearson lower bound is
  ≥ 0.05. Any comparison whose flip rate does not exceed its matched control's 95% upper bound
  is reported as **"not distinguishable from instability"**.
- **Gaps that do not matter.** A train gap whose comparison is NO OBSERVED EFFECT without a
  low-sensitivity flag is recorded as "gap without observed causal effect in V4". It is not
  "harmless".

## 9. Interpretation rules

- **CAUSAL EVIDENCE (for V4, in this suite).** A comparison classed STRONG or MODERATE, under a
  passed determinism control, is causal evidence that the isolated change moves V4's decision
  on these bases.
- **No generalisation.** These are diagnostic counts on an author-chosen composition, never
  rates of real traffic (D42). Nothing is generalised to all HTTP traffic, to V5, to External
  Test v1 or to deployment.
- **FACT / CORRELATION / CAUSAL EVIDENCE / HYPOTHESIS** are kept separate in the README.

## 10. Non-claims

No FPR, recall or operational rate. No claim that a factor without observed flips is harmless.
No claim about the weight of mechanisms in real traffic.

## 11. Changes from the draft (made before freezing; reasons)

1. **Benign only; attack counterparts excluded.** The question concerns false blocks; this
   keeps the suite small.
2. **McNemar two-sided instead of one-sided.** Some factors may move toward ALLOW (reverse
   shortcuts, F-CTB). A one-sided test would hide that.
3. **Effect classes and sensitivity flags pre-registered** (§7). The draft had only
   significance-based falsification.
4. **F-JSON comparisons isolate one change each.** The draft's levels changed cardinality and
   type together (e.g. "3 keys + number" vs "1 string key"). Type comparisons now use the
   4-string-key object as reference. Cardinality is 1 → 4 keys instead of 3, because a
   4-string object is needed to host the number and boolean leaves without changing the key
   count.
5. **F-ADDR `&` moved to F-PUNCT.** No natural one-character `&` insertion exists in an
   address. `!`/`;`/`&` are tested as single-character swaps in prose. `,` and `?` are covered
   controls.
6. **F-WORD:** `and` and `or` added. Audit §3.2 shows them in only 1 benign group each. Each
   homonym is paired with a neutral synonym in the same slot, rather than one fixed sentence
   for all words, which was not grammatical. 60 bases in one comparison, per-homonym counts
   descriptive.
7. **F-CTB reduced to one direction** (form body: form type → JSON type). That is the direction
   of the audited benign skew (661 groups).
8. **F-ENC reduced to `%20` → `+`.** The `%2F` path case moved to F-PATH, together with path
   depth (audit: depth ≥ 4 absent in both classes).
9. **F-FREETEXT added** (keyword → prose), as requested in the phase brief.
10. **CONTROL-ENV added.** It is an envelope instability control: a class-balanced header
    toggled.
11. **`Content-Length` absent in every non-F-CL base** (§4). The content × CL interaction is
    descriptive, from F-CL strata.
12. **The logit margin (draft §6) is not measured.** `inference_core` is not modified in this
    phase.
13. **Gateway subset (draft §7) not run.** The gateway rendering is documented from source and
    a loopback test (research note F) instead.

**After the methodology review** (`PROTOCOL_REVIEW.md`, subagent A), still before freezing.

14. **BLOCKER 1, falsifiability.**
    - Hypotheses are supported only by STRONG comparisons.
    - MODERATE is tightened to D ≥ 6, consistency ≥ 0.80 and the matched control's upper bound.
15. **BLOCKER 2, independent values.**
    - F-APOS has 30 distinct surnames.
    - F-PUNCT has 30 distinct clause pairs.
    - F-FREETEXT has 30 distinct keywords and sentences, from a 30-topic pool.
    - F-WORD carriers alternate by frame index. Per-homonym counts are INSUFFICIENT DATA.
    - Bases are unique across all factors.
16. **BLOCKER 3, H-token.** A `203.0.113.10` level was added, with `203 → 127` and `203 → 10`
    contrasts. M-envelope was reworded: an IP Host with a port is in TRAIN.
17. **BLOCKER 4, matched controls.** ENVELOPE comparisons and F-CTB are compared with
    CONTROL-ENV; CONTENT comparisons with CONTROL-COV.
18. **IMPORTANT items adopted.**
    - an F-CL `Transfer-Encoding: chunked` level;
    - the pre-declared smuggling-reason reading;
    - `Content-Length` serve-like twins for F-NFIELDS and F-JSON;
    - conditional rates with CIs; the low-sensitivity threshold raised to 20;
    - Holm within families, controls outside;
    - a non-vacuous instability rule;
    - encoding-matched covered controls (F-PWD `@`, F-ADDR `,` → `#`);
    - neutral F-URL parameter names;
    - port `:9100` replaced by `:8443`, since it was the #60 port;
    - side-effect and per-host reporting;
    - prompt-token counts from `classify_timed`, the function `classify_raw` delegates to.
19. **IMPORTANT items not adopted.**
    - **45 bases per factor.** Kept at 30–60. Stated cost: STRONG needs about 9–11
      one-direction flips out of 30 to survive Holm.
    - **F-APOS hyphen control.** A hyphenated surname is not a natural one-character
      counterpart; the encoding-matched controls cover the purpose.
    - **F-CTB stratum where references block.** F-CTB stays in the CONTENT family, read
      descriptively for B→A.
20. **NICE-TO-HAVE.**
    - Not done: a second-process CONTROL-REP, a logit margin, and a #57/#60 overlap check.
      For the overlap check, the generator pools were written independently and the tests
      assert the forbidden routes and hosts.
    - **V5 acceptance.** The envelope factor levels (ports, IP Hosts, `Content-Length`) cannot be
      kept disjoint from V5's envelope pools; only the content pools can.
