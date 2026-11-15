# Protocol review — V4 minimal-pair probe (`v5-minimal-pairs-v1`)

**Reviewer role:** experimental methodology (ML for HTTP security). **Read-only review.** No model
run, nothing trained, no existing file modified, nothing committed.

| | |
|---|---|
| Date | 2026-10-06 |
| Reviewed | `reports/v5/benign-coverage-audit-v1/MINIMAL_PAIR_PROTOCOL_DRAFT.md` (draft) · `reports/v5/minimal-pair-probe-v1/PROTOCOL.md` (the revised, not yet anchored protocol, found in the folder during review) · `scripts/evaluation/minimal_pair_probe_cases.py` SHA-256 `94fb3691…7f58` (570 lines; FACTORS dict, 20 factors, 40 comparisons, 1,900 cases) |
| Context read | audit `README.md` (§3.4, §6) · `DECISIONS.md` D1, D18, D19 (≥30 support), D42 · `parse_dataset_v4.py` 140–260, 760–1000 · `data_plane/data_plane.py` `render_request` · `control_plane/inference_core.py` |
| Not opened | `datasets/v4_clean/eval.jsonl`, `reports/external/`, `docker/.lab-logs/`, #57/#60 case files |
| Verification method | The generator was imported **in memory** (`PYTHONDONTWRITEBYTECODE=1`, from the scratchpad; no file written) to check that every comparison changes exactly one line, to count distinct factor-bearing values and to find duplicate texts. |

**Overall verdict.** The revised PROTOCOL.md and the generator already fix the draft's main isolation
defects: F-ENC was split, F-JSON uses adjacent contrasts, F-CTB is a type-only change, F-WORD uses
POS-matched neutral words, the tests are two-sided, and CONTROL-ENV was added. I checked all 40
comparisons: each one changes exactly one line, either the request line, one header line or the
body. F-CL and F-PXY insert one header line. The design is valid in outline. Four defects
remain that cannot be fixed after the single scoring run (`run` refuses to overwrite).

---

## BLOCKERS (change before anchoring)

### B1. H-content and H-envelope cannot be falsified as written (MODERATE plus "any of N")

PROTOCOL §7 defines MODERATE as D ≥ 3, D/N ≥ 0.10, consistency ≥ 0.70 and flip rate > CONTROL-COV's
*point* flip rate. §8 counts a hypothesis as supported if **any** of its comparisons is MODERATE.
H-content has about 30 comparisons and H-envelope 5.

Under pure boundary instability, the null the protocol wants to reject, assume a per-pair flip
probability of 0.05:
- P(X ≥ 3 of 30) ≈ 0.19 per comparison;
- consistency ≥ 0.70 is close to automatic, because benign references are mostly ALLOW and noise
  then flips mostly A→B;
- "> control's point rate" holds about half the time.

So P(at least one MODERATE among 25–30 content comparisons) is ≈ 0.95+. H-content is supported
regardless of mechanism. For comparison, D = 3, c = 0 gives exact two-sided p = 0.25, and Fisher
3/30 vs 0/40 gives p ≈ 0.07.

**Minimal fix (wording plus thresholds in `classify_effect`):**
1. H-content, H-envelope and H-token are **supported only by a STRONG comparison** (Holm-controlled).
   MODERATE is reported as "suggestive" and never counts as support.
2. Raise MODERATE to **D ≥ 6** (unadjusted exact two-sided p ≤ 0.031 at c = 0), **consistency ≥ 0.80**,
   and **flip rate > the matched control's Clopper–Pearson 95% upper bound** (not its point rate).
   D = 3–5 becomes WEAK/INCONCLUSIVE.

### B2. Pseudo-replication: some factors have far fewer than 30 independent factor-bearing values

The redraw rule (§3) only forbids identical *texts*. Bases that share the factor-bearing value but
differ in path or envelope are counted as independent. The in-memory generation shows:

| Factor | Distinct factor-bearing values over its bases | Cause |
|---|---|---|
| F-APOS | **12** surname pairs / 30 bases | `i % 12` |
| F-PUNCT | **12** clause pairs / 30 bases | `i % 12` |
| F-FREETEXT | **22** distinct sentences (5 frames) / 30 | `rng.choice` of 5 frames |
| F-WORD | 5 bases per homonym; homonym fully aliased with carrier | `i % 12` with carrier `i % 2` |

The F-WORD aliasing: select, from, table, match, order and `and` are always GET `q=`; union, where,
call, include, drop and `or` are always a form `message=` body.

A value-driven flip (for example one surname) then repeats 2–3 times and inflates D and McNemar.
That violates the D18/D19 independent-unit rule the protocol cites.

**Minimal fix:**
- ≥ 30 distinct surname pairs and ≥ 30 distinct clause pairs, indexed by `i` without a modulo;
- ≥ 30 distinct free-text sentences;
- in F-WORD, carrier = `(i // 12) % 2`, and state explicitly that per-homonym results (n = 5) are
  INSUFFICIENT DATA.

The alternative is to declare N_eff = number of distinct values and classify those factors as
INSUFFICIENT DATA.

### B3. H-token cannot be told apart from M-envelope with the current levels, and one premise is false

- PROTOCOL §1 and §8 treat "IP Host" as unseen. **It is seen:** V4's shared `HOSTS` pool contains
  `10.20.30.40:8000` and `localhost:8080` (`parse_dataset_v4.py:151-160`), balanced across classes
  (audit §3.4). What is unseen is a **loopback** IP and an **IP Host without a port**.
- `10.0.0.5` is a private literal, not a token-free null. Private and internal literals are
  plausible SSRF payload tokens. The README counts "any loopback/internal literal: 0 benign vs 85
  attack groups"; that 10.x literals are among them is UNVERIFIED.
- So "127 flips and 10.0.0.5 does not" and "both flip alike" each support more than one
  mechanism. "Higher class / non-overlapping CI" is also a comparison of two marginal results,
  where a paired test is available.

**Minimal fix:**
1. Add the level `ip_203.0.113.10` (RFC 5737, public, portless).
2. Add the paired comparisons `ip_203.0.113.10 → ip_127.0.0.1` and `ip_203.0.113.10 → ip_10.0.0.5`.
   Same bases; one Host line changes.
3. Reword M-envelope to read "loopback-IP / portless-IP Host".

H-token then holds if the 203→127 comparison is STRONG A→B. A portless public IP that flips like
127 points to M-envelope.

### B4. CONTROL-COV is the wrong instability reference for ENVELOPE factors

`control_env` uses the **same base builder** (`_host_base`) as F-PORT, F-HOSTIP and F-PXY, and
changes one class-balanced header. It is the matched control. CONTROL-COV changes a username value
on different bases. §7's STRONG and MODERATE conditions reference CONTROL-COV for every factor.

**Minimal fix (one rule):**
- ENVELOPE comparisons (F-CL, F-PORT, F-HOSTIP, F-PXY) and F-CTB, which is a one-header change, are
  compared against **CONTROL-ENV**.
- CONTENT comparisons are compared against CONTROL-COV.
- Optionally, use the stricter (larger) of the two upper bounds for both.

This could be filed under IMPORTANT, but it belongs here because it changes class assignment in
the one-shot run.

---

## IMPORTANT (should change)

1. **Add `Transfer-Encoding: chunked` as an F-CL level** (`absent → te_chunked`: a TE header and no
   CL, body unchanged).
   - Research note F: mitmproxy 12.2.3 de-chunks the body and keeps `Transfer-Encoding: chunked` with
     no `Content-Length`. That is the gateway's *other* real body rendering.
   - In V4's generator, TE appears only in the smuggling attack framings (`parse_dataset_v4.py:626-631`).
     The benign framing counterpart uses CL only (lines 826-833). CSIC benign TE count: UNVERIFIED.
   - Without this level, M-envelope covers only half of the deployed body envelope.
2. **F-CL placement equals V4's request-smuggling layout.** In training, `Content-Length` followed by
   `Content-Type` as the last two headers occurs only in `framing_headers` (lines 831-832, 3 benign /
   6 attack rows). Real clients often use this order too, so keep it, but:
   - pre-declare that F-CL flips with the reason "Request smuggling" are read as a **learned CL ⇒
     smuggling-shape association** (M-token-like), not as generic envelope novelty;
   - nice-to-have: a `cl_after_host` level to separate position from presence.
3. **Run content × CL as a paired comparison, not between bases.** F-CL's four strata (10 bases
   each) differ between bases, so "descriptively from F-CL strata" cannot show whether a content
   effect exists under CL. #60's confound is exactly this. Add CL-present twins to
   F-NFIELDS (n1, n2) and F-JSON (k1_string, k4_strings), giving a 2×2 within each base and
   about +120 cases.
   - Content factors without CL (training rendering) is the **right primary choice** for isolation.
   - Report that their results describe the train-format text, not the deployed one.
4. **Sensitivity and NO OBSERVED EFFECT.**
   - D/N and the "0.116" bound use all valid pairs. A→B can happen only on reference-ALLOW bases.
   - Report the **conditional** A→B rate and its one-sided 95% CP upper bound on n_A:

     | n_A | 0 flips | 1 flip | 2 flips |
     |---:|---:|---:|---:|
     | 20 | 0.139 | 0.216 | 0.283 |
     | 30 | 0.095 | 0.149 | 0.195 |
     | 40 | 0.072 | 0.113 | 0.149 |

   - Raise `LOW_SENSITIVITY_A_TO_B` from n_A < 10 to **n_A < 30** (D18/D19 spirit). With n_A = 10 and
     0 flips, the bound is 0.26.
   - "No flips in 30" excludes only conditional flip probabilities above ≈ 0.10 *on this suite's
     base distribution*. It says nothing about smaller effects, other bases or real traffic (D42).
   - Consider 45 bases per factor (≈ +50% inference, about 15 min) so that n_A ≥ 30 is likely.
5. **Holm power must be stated.**
   - Over 40 comparisons, the first Holm step (α/m = 0.00125) needs **≥ 11 discordant pairs in one
     direction, 0 reverse** (two-sided exact). STRONG therefore means about ≥ 11/30, whatever the
     D/N ≥ 0.20 clause says.
   - Holm is valid under the within-factor dependence (shared bases).
   - Remove the 2 controls from the family (they are not hypotheses; m = 38 leaves the threshold
     unchanged), or use declared families per block: ENVELOPE m = 7 (after B3: m = 9, threshold
     ≥ 10) and CONTENT.
6. **"M-instability is material if the CP lower bound > 0"** is true iff ≥ 1 control flip. It is
   vacuous. Report it as "instability observed (k/N)" and put the materiality judgement in B1 and
   B4's control comparison.
7. **Covered controls must match the encoding.**
   - F-PWD's `-` stays literal, while `!` and `#` become `%21` and `%23`. Add an `@` level (`%40`,
     covered via e-mails) and the comparisons `at → bang` and `at → hash`.
   - F-ADDR: add the direct pair `comma → hash` (both `%XX`, same length).
   - F-APOS has no covered control. Add `o-neil` and the comparison `hyphen → apostrophe`.
   - Otherwise "`!` flips, `-` doesn't" confounds the character with the `%XX` triplet, and
     "hash flips, comma doesn't" is a comparison of two marginal results rather than a paired test.
8. **F-URL and F-NAME `callback`: an external URL in `next` / `return_url` on `/session/end` is the
   textbook open-redirect shape.** `next` is a V4 `url_param` name. BLOCK may be correct policy
   there, not a false block. Either use a non-redirect name (for example `website` on a profile
   form), or label these comparisons policy-ambiguous and exclude them from H-content.
9. **F-PORT and F-HOSTIP premises.**
   - `:8080` on a DNS name is **not** a seen combination. In TRAIN, ports occur only as
     `localhost:8080` and `10.20.30.40:8000`. Do not read it as a covered-port control.
   - Port `9100` is the #60 port (audit §4). That contradicts "nothing copied from any #57/#60
     value". Declare it an explicit, intentional exception (re-testing #60's confound).
10. **Novel envelope (`*.example.net/.org`, new UA/Accept strings, always 3 headers).** Novelty
    shared by base and level is **not a confound**. It can push references toward BLOCK and lower
    n_A. Report n_A by host. If many factors hit `LOW_SENSITIVITY`, that is an outcome of the
    envelope choice, not evidence about the factor. Optional stratum: neutral reserved hosts from
    V4's own pool (for example `app.example.com`, excluding `target.*`, `intranet.corp.local`,
    `localhost:8080` and `10.20.30.40:8000`).
11. **F-WORD reference contamination.** The neutral frame "Where can I {w} the {t} workshop date"
    (select, frame 5) contains the homonym `where` in the reference. Replace it.
12. **F-CTB (H-reverse) is nearly untestable.** B→A needs blocked form references, and benign bases
    are mostly ALLOW. Inverting the reference does not help, because it is the same 2×2. If H-reverse
    matters, add a boundary-loaded stratum whose references plausibly BLOCK, for example a 2-field
    form or a `%21` value. Otherwise keep it explicitly descriptive (as §8 does).
13. **Pre-declare side-effect reporting per comparison:**
    - Δ raw length, Δ decoded length and Δ `%XX` count;
    - Δ TinyLlama token count (tokenizer only, no model);
    - Δ CL digits on CL twins.

    Accepted intrinsic side effects: length and tokens in F-NFIELDS, F-NQUERY, F-JSON 1→4, F-PATH
    and F-FREETEXT (which is a declared composite); encoding for punctuation; `, ` → ` & ` is a
    separator substitution; `%2F` lowers the segment count.

---

## NICE-TO-HAVE

- The cross-factor duplicate text `F-PXY|b24|absent` = `F-NQUERY|b06|n1` contradicts "bases are
  never shared". Score it once and list it in the manifest, or redraw it.
- Some `titles` contain uncovered or reverse-shortcut tokens (`salt and stone` → `and`;
  `the …` → `the`). They are constant within pairs, so they are not confounds; report them as
  moderators.
- Disjointness from #57/#60 values cannot be verified by this reviewer; for example, whether
  `o'neil` or any address equals a #60 checkout value is UNVERIFIED. Add a guarded overlap check
  that reports only counts.
- Logit margin through a separate read-only teacher-forced scoring script, with paired Wilcoxon,
  would add power without modifying `inference_core`.
- CONTROL-REP: batch-1, unpadded greedy is confirmed in `inference_core.classify_timed`. A second
  process or a different order would also catch kernel nondeterminism.
- Cite the threshold correctly: D18 is "< 100 groups"; the ≥ 30 rule is D19's eval-support
  threshold, applied by analogy.
- V5 acceptance use: envelope levels (`Proxy-Connection: keep-alive`, ports, CL) cannot be disjoint
  from V5's F7 pools. On those factors, V5 acceptance measures learning of the header, not
  generalisation. State this.
