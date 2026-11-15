# V4 minimal-pair probe — `v5-minimal-pairs-v1`

**DEVELOPMENT DIAGNOSTIC.** It is a causal probe of the frozen V4 using one-change-at-a-time pairs of
**benign** requests.
- Inference only, through the unchanged `inference_core`, with greedy decoding.
- Nothing was trained, tuned or thresholded.
- The cases are **development data**: they are never V5 training, validation or
  checkpoint-selection data, and their texts must not be copied into a V5 generator. V5 may use
  the *concepts* below.
- All figures are diagnostic counts on an author-chosen composition, not traffic rates (D42).

| | |
|---|---|
| Date | 2026-10-06; anchored 22:32:36Z, scored 22:32:54–22:43:56Z |
| Branch / base | `research/v5-benign-coverage-audit`, base `5602045`, uncommitted |
| Protocol | [`PROTOCOL.md`](PROTOCOL.md) (pre-registered) · review [`PROTOCOL_REVIEW.md`](PROTOCOL_REVIEW.md) |
| Code | `scripts/evaluation/minimal_pair_probe_cases.py` (generator) · `scripts/evaluation/run_v4_minimal_pair_probe.py` (run + analysis) |
| Evidence | `manifest.json` · `cases.jsonl` · `raw/records.jsonl` · `raw/run_meta.json` · `raw/run.log` · [`results.json`](results.json) · [`results_table.md`](results_table.md) |
| Anchors | `SHA256SUMS` (pre-execution, verified by `run` and `analyze`) · `RESULTS_SHA256SUMS` (post-execution) |
| Tests | `tests/test_v4_minimal_pair_probe.py`: 28 tests, pass on Python 3.12 and 3.14 |
| Never opened | V4 eval / INTERNAL TEST, External Test v1, #57/#60 case files |

---

## PART 1 — PRE-REGISTERED (summary; the binding text is `PROTOCOL.md`)

**Hashes anchored before any inference:**

| File | SHA-256 |
|---|---|
| `PROTOCOL.md` | `7db97be70000f8866a903c2984b4389228b0423b56dc315758a1604c1191741b` |
| `manifest.json` | `742b382fac9964dadbb644fc807aaed16511624e79c677334b53b8605ea4a7f9` |
| `cases.jsonl` | `9d9bc2d55fcd2bb36ec90687ad99b6e569826d060045464e7817b21736ea07fb` |
| `PROTOCOL_REVIEW.md` | `d285a5b150898e51f2105f5766f83e9f21535131b0098125db0b85447aa610e6` |
| `minimal_pair_probe_cases.py` | `6edd1f0e0321d56e840ed8ca7cd9a2571db3b79376acd1f7427c6a5b5e4ceca3` |
| `run_v4_minimal_pair_probe.py` | `dd55dfdce702597272f2af1cb8ffe43caeda43177a72fd928a072ce0e9372c8b` |

**Design in brief:**
- **Suite:** 20 factors (4 ENVELOPE, 14 CONTENT, 2 CONTROL), 48 comparisons, 2,120 unique
  benign texts of a fictitious library portal.
- **Bases:** 30–60 independent bases per factor. Each pair changes exactly one declared
  dimension, which the tests check.
- **Envelope:** train-like, with no `Content-Length` except where it is the factor.
- **Statistics:** exact McNemar, two-sided, with Holm within the ENVELOPE family (11
  comparisons) and within the CONTENT family (35).
- **Effect classes:** pre-registered, with matched controls: CONTROL-ENV for envelope and F-CTB,
  CONTROL-COV for content.
- **Hypotheses:** supported only by STRONG comparisons.
- **Determinism:** a 10% subset (212 texts) was scored 3 times before the main run, with
  stop-on-divergence.

**Changes to the draft** (`PROTOCOL.md` §11) were all made before freezing:
- items 1–13 by the main agent;
- items 14–20 after the methodology review, which found 4 blockers:
  - falsifiability (MODERATE too lax);
  - fewer than 30 independent values in F-APOS, F-PUNCT and F-FREETEXT, and homonym/carrier
    confounding;
  - H-token not separable from M-envelope;
  - envelope factors compared with the wrong control.

  All four were fixed, plus most IMPORTANT items.

---

## PART 2 — OBSERVED AFTER EXECUTION

### 2.1 Run integrity (FACT)

- **Anchors and model:** all anchors verified before scoring. The adapter SHA-256 `7bf16875…`
  was identical before and after, and `inference_core.py` was unchanged.
- **Classifications:** 2,756 = 212 × 3 determinism repeats + 2,120 main. Status `ok` on
  2,120 / 2,120 main texts; **0 invalid**.
- **Determinism:** each of the 212 repeated texts produced **byte-identical raw output** in all
  4 executions (3 in phase 1, 1 in phase 2). Divergences: 0 in raw output, 0 in decision,
  0 in reason. Effect classes are therefore not withheld.
- **Decisions over the 2,120 texts:** ALLOW 1,765, BLOCK 355.
- **Out-of-vocabulary reasons:** 38 of the 355 BLOCK reasons (10.7%) are not among V4's 19
  training reasons. The largest is "Password reset request detected" (26), all of them in
  password contexts.
- **The new probe hosts do not depress references.** By host, references are ALLOW 79–91% for
  each `*.example.net/.org` host and 90% for `203.0.113.10` (`results.json →
  reference_decisions_by_host`).
- **Methodological note.** `raw/run.log` had 2,756 identical transformers warnings
  (`max_new_tokens` vs `max_length`). They were collapsed into one counted line after the run.
  No other post-hoc change was made.

### 2.2 Results per comparison

- **N:** valid pairs.
- **A→B / B→A:** ALLOW→BLOCK and BLOCK→ALLOW at the level, vs the reference.
- **cond. A→B:** A→B among reference-ALLOW bases.
- **Holm p:** within the comparison's family; controls are outside the families.

Full table, including the A→A / B→B cells and flags: [`results_table.md`](results_table.md).

| Comparison | N | ref ALLOW | A→B | B→A | flip rate [95% CI] | cond. A→B [95% CI] | McNemar p | Holm p | Class |
|---|---:|---:|---:|---:|---|---|---:|---:|---|
| **ENVELOPE** | | | | | | | | | |
| F-CL absent → `Content-Length` | 40 | 33 | 1 | 0 | 0.03 [0.00, 0.13] | 0.03 [0.00, 0.16] | 1.00 | 1.00 | WEAK/INCONCL. |
| F-CL absent → `Transfer-Encoding: chunked` | 40 | 33 | **18** | 0 | **0.45 [0.29, 0.62]** | **0.55 [0.36, 0.72]** | <0.0001 | 0.0001 | **STRONG** |
| F-PORT none → :8080 / :8443 / :30000 | 30 each | 29 | 0 | 0 | 0.00 [0.00, 0.12] | 0.00 [0.00, 0.12] | 1.00 | 1.00 | NO OBSERVED |
| F-HOSTIP DNS → 127.0.0.1 / 10.0.0.5 / 203.0.113.10 | 30 each | 27 | 0 | 0 | 0.00 [0.00, 0.12] | 0.00 [0.00, 0.13] | 1.00 | 1.00 | NO OBSERVED |
| F-HOSTIP 203.0.113.10 → 127.0.0.1 / 10.0.0.5 | 30 each | 27 | 0 | 0 | 0.00 [0.00, 0.12] | 0.00 [0.00, 0.13] | 1.00 | 1.00 | NO OBSERVED |
| F-PXY absent → `Proxy-Connection` | 30 | 26 | 0 | 0 | 0.00 [0.00, 0.12] | 0.00 [0.00, 0.13] | 1.00 | 1.00 | NO OBSERVED |
| **CONTENT** | | | | | | | | | |
| F-APOS `oneil` → `o'neil` | 30 | 30 | **30** | 0 | **1.00 [0.88, 1.00]** | **1.00 [0.88, 1.00]** | <0.0001 | <0.0001 | **STRONG** |
| F-PWD alnum → `#` | 30 | 30 | **19** | 0 | **0.63 [0.44, 0.80]** | **0.63 [0.44, 0.80]** | <0.0001 | 0.0001 | **STRONG** |
| F-PWD alnum → `!` | 30 | 30 | 1 | 0 | 0.03 [0.00, 0.17] | 0.03 [0.00, 0.17] | 1.00 | 1.00 | WEAK/INCONCL. |
| F-PWD alnum → `@` (covered, encoded) | 30 | 30 | 3 | 0 | 0.10 [0.02, 0.27] | 0.10 [0.02, 0.27] | 0.25 | 1.00 | WEAK/INCONCL. |
| F-PWD alnum → `-` (covered) | 30 | 30 | 0 | 0 | 0.00 [0.00, 0.12] | 0.00 [0.00, 0.12] | 1.00 | 1.00 | NO OBSERVED |
| F-URL https external → **http** external | 30 | 30 | **18** | 0 | **0.60 [0.41, 0.77]** | **0.60 [0.41, 0.77]** | <0.0001 | 0.0003 | **STRONG** |
| F-URL https same host → https external | 30 | 29 | 0 | 1 | 0.03 [0.00, 0.17] | 0.00 [0.00, 0.12] | 1.00 | 1.00 | WEAK/INCONCL. |
| F-ADDR plain → `#` · `,` → `#` | 30 | **4** | 4 | 0 | 0.13 [0.04, 0.31] | 1.00 [0.40, 1.00] | 0.125 | 1.00 | WEAK/INCONCL. (LOW_SENS) |
| F-ADDR plain → `,` | 30 | 4 | 0 | 0 | 0.00 [0.00, 0.12] | 0.00 [0.00, 0.60] | 1.00 | 1.00 | NO OBSERVED (LOW_SENS) |
| F-PUNCT `,` → `;` / `&` / `!` / `?` | 30 each | 24 | 1 / 0 / 2 / 4 | 1 / 1 / 0 / 0 | 0.03–0.13 | 0.00–0.17 | ≥ 0.125 | 1.00 | WEAK/INCONCL. |
| F-WORD neutral → SQL/shell homonym | 60 | 56 | **0** | 2 | 0.03 [0.00, 0.12] | **0.00 [0.00, 0.06]** | 0.50 | 1.00 | WEAK/INCONCL. |
| F-FREETEXT keyword → sentence | 30 | 30 | 4 | 0 | 0.13 [0.04, 0.31] | 0.13 [0.04, 0.31] | 0.125 | 1.00 | WEAK/INCONCL. |
| F-NQUERY 1 → 2 / 1 → 4 params | 30 each | 30 | 0 | 0 | 0.00 [0.00, 0.12] | 0.00 [0.00, 0.12] | 1.00 | 1.00 | NO OBSERVED |
| F-NFIELDS 1 → 2 / 3 / 5 fields | 30 each | 21 | 0 | 1 / 2 / 2 | 0.03–0.07 | 0.00 [0.00, 0.16] | ≥ 0.5 | 1.00 | WEAK/INCONCL. |
| F-NFIELDS 1 → 2, both with `Content-Length` | 30 | 21 | 0 | 1 | 0.03 [0.00, 0.17] | 0.00 [0.00, 0.16] | 1.00 | 1.00 | WEAK/INCONCL. |
| F-JSON 1 → 4 string keys | 30 | 25 | 0 | **5** | 0.17 [0.06, 0.35] | 0.00 [0.00, 0.14] | 0.0625 | 1.00 | WEAK/INCONCL. |
| F-JSON 1 → 4 keys, both with `Content-Length` | 30 | 23 | 0 | **7** | 0.23 [0.10, 0.42] | 0.00 [0.00, 0.15] | 0.0156 | 0.50 | WEAK/INCONCL. |
| F-JSON 4 strings → number / boolean / array | 30 each | 30 | 0 | 0 | 0.00 [0.00, 0.12] | 0.00 [0.00, 0.12] | 1.00 | 1.00 | NO OBSERVED |
| F-JSON 4 strings → nested object | 30 | 30 | 2 | 0 | 0.07 [0.01, 0.22] | 0.07 [0.01, 0.22] | 0.50 | 1.00 | WEAK/INCONCL. |
| F-CTB form type → JSON type (form body) | 30 | 22 | 0 | 0 | 0.00 [0.00, 0.12] | 0.00 [0.00, 0.15] | 1.00 | 1.00 | NO OBSERVED |
| F-ENC `%20` → `+` | 30 | 30 | 0 | 0 | 0.00 [0.00, 0.12] | 0.00 [0.00, 0.12] | 1.00 | 1.00 | NO OBSERVED |
| F-PATH depth 3 → 5 / `/` → `%2F` | 30 each | 30 | 0 | 0 | 0.00 [0.00, 0.12] | 0.00 [0.00, 0.12] | 1.00 | 1.00 | NO OBSERVED |
| F-NAME `note` → `template` / `callback` / `file` | 30 each | 29–30 | 0 / 1 / 0 | 1 / 0 / 1 | 0.03 | ≤ 0.03 | 1.00 | 1.00 | WEAK/INCONCL. |
| **CONTROLS** | | | | | | | | | |
| CONTROL-COV username A → username B (covered) | 40 | 39 | 4 | 1 | 0.125 [0.042, 0.268] | 0.10 [0.03, 0.24] | 0.375 | — | WEAK/INCONCL. |
| CONTROL-ENV absent → `Accept-Language` | 30 | 27 | 0 | 0 | 0.00 [0.00, 0.12] | 0.00 [0.00, 0.13] | 1.00 | — | NO OBSERVED |

**No comparison is MODERATE.** Under the tightened rule, MODERATE requires a flip rate above the
matched control's upper bound: 0.268 for content, 0.116 for envelope. The only comparisons
above those bounds are the four STRONG ones.

### 2.3 Hypotheses (pre-registered criteria)

| Hypothesis | Verdict | Evidence |
|---|---|---|
| **H-envelope** | **SUPPORTED, by `Transfer-Encoding: chunked` only** | `Content-Length` 1/33, ports, IP Hosts and `Proxy-Connection` all 0 flips |
| **H-token** (`127.0.0.1` as Host) | **FALSIFIED in this suite** | 0/27 A→B for DNS → 127.0.0.1 and for 203.0.113.10 → 127.0.0.1 |
| **H-content** | **SUPPORTED** | F-APOS (30/30), F-PWD `#` (19/30), F-URL `http` (18/30) |
| Within-factor controls | covered characters do not reproduce the effect | `-` 0/30, `,` 0/4, `@` 3/30, `?` 4/24, against `'` 30/30 and `#` 19/30. So this is not a generic "value changed" or "one more `%XX`" effect |
| **H-content-serve** | `Content-Length` does not modulate content effects | `n1 → n2` and `n1_cl → n2_cl` both give 0 A→B / 1 B→A. `k1 → k4` gives 5 B→A, `k1_cl → k4_cl` gives 7 B→A |
| **H-reverse** (F-CTB) | not observed | 0/8 B→A among blocked references |
| **M-instability material** (CP lower bound ≥ 0.05) | **not met by the rule (0.042)**, but not negligible | CONTROL-COV: 5/40 flips, point 0.125, upper bound 0.268 |

### 2.4 FACT / CORRELATION / CAUSAL EVIDENCE / HYPOTHESIS

**CAUSAL EVIDENCE**, for V4, on these bases, under a passed determinism control:
1. **An apostrophe inside a surname** turns ALLOW into BLOCK on every base: 30/30 (GET 15/15,
   form 15/15). The reasons are mostly SQL injection (19), then command injection (6).
2. **`#` inside a password value** gives 19/30 ALLOW→BLOCK. The covered `-` gives 0/30 and the
   covered encoded `@` gives 3/30. 18 of the 19 reasons are the out-of-vocabulary "Password
   reset request detected".
3. **An `http://` scheme instead of `https://`** for the same external URL gives 18/30
   ALLOW→BLOCK. Changing only the host from same-origin to external, both https, gives 0 A→B.
4. **`Transfer-Encoding: chunked`** on an otherwise identical body gives 18/33 among
   reference-ALLOW bases. In the JSON 1-key stratum it is 10/10.
   - The pre-declared reading was "smuggling reason ⇒ learned framing association". It does
     **not apply**: no flip carries the request-smuggling reason (XSS 8, NoSQL 5, HPP 2, SQLi 2,
     cmdi 1).
   - So the header acts as an unseen-envelope trigger with an arbitrary attack label.

**FACT — no observed effect.** Exact upper bounds on the conditional A→B rate:
- **`Content-Length`:** 1/33 (upper bound 0.16), across four body shapes. This includes the
  2-field form and the 3-key JSON, both absent in TRAIN.
- **Unseen ports** on DNS names: 0/29 each (upper bound 0.12).
- **IP Hosts**, loopback included: 0/27 each (upper bound 0.13).
- **`Proxy-Connection`:** 0/26.
- **SQL/shell homonyms in prose:** 0/56 (upper bound 0.064).
- **2 or 4 query parameters:** 0/30.
- **JSON number, boolean or array leaves:** 0/30.
- **`+` vs `%20`; depth-5 or `%2F` paths:** 0/30.

None of these excludes a small effect, nor an effect in contexts the bases do not contain.

**FACT, observed but not a minimal-pair result: the address field.** F-ADDR *references*
(`N Street Apt k`, with no special character) were BLOCKED in 26 of 30 bases. The reasons were
command injection 9, SQLi 7 and XSS 5.
- This makes F-ADDR insensitive. It is a strong reference-level observation that the design did
  not isolate.
- **HYPOTHESIS:** the parameter name `address` or the digit + word + `Apt` pattern. It needs its
  own pre-registered pairs before it can be called a cause.

**CORRELATION / descriptive, not pre-registered as tests:**
- **JSON 1 → 4 keys** moves BLOCK → ALLOW (5/5 and 7/7 discordant pairs are B→A). Single-key
  JSON bodies are blocked more often than multi-key ones. This is consistent with TRAIN, where
  89% of single-key JSON groups are attacks: a reverse-shortcut direction.
- **F-PWD `#` × parameter name:** `new_password` BLOCK 14/15 vs `password` BLOCK 5/15, with n = 15
  each. **HYPOTHESIS:** an interaction with the parameter name.

**MODEL / UNKNOWN:**
- covered-character username changes flip 5/40 (CONTROL-COV);
- 10.7% of BLOCK reasons are invented;
- `?` instead of `.` in a sentence flips 4/24.

### 2.5 CONTENT vs ENVELOPE vs MODEL

| Source | What moved V4 (causal) | What did not (on these bases) |
|---|---|---|
| **CONTENT** | `'` in names; `#` in passwords; `http://` scheme | homonyms in prose, parameter or field count, JSON types, encodings, path depth, parameter names |
| **ENVELOPE** | `Transfer-Encoding: chunked` | `Content-Length`, ports, IP Host (including loopback), `Proxy-Connection`, `Accept-Language` |
| **MODEL / UNKNOWN** | instability on covered values (12.5% [4.2, 26.8]); OOV reasons; address-field reference blocks | — |

**Relation to the audit's open questions** (interpretation, not new data from #57/#60):
- **#60's `Content-Length` correlation is not causal on these bases.** `Content-Length` alone
  almost never flips V4, so #60's body-request blocks are more plausibly explained by their
  *content* (`'`, `#`, password and address fields) than by the envelope. This is a
  HYPOTHESIS, because #60 used other values.
- **#57's envelope-only blocks** (unseen ports, `Proxy-Connection`, loopback Host) were **not
  reproduced** with these bases. They may depend on other context, e.g. the bare `/` path in #57
  S1 (UNVERIFIED). This probe cannot say which.

### 2.6 What we cannot conclude

- **No rates of real traffic.** Nothing here is a false-positive rate, nor the weight of each
  mechanism in deployment (D42).
- **"No observed effect" is not "harmless".** Bounds are around 6–16% at N = 30–60. Contexts
  other than these bases (paths, other field names, other value positions) were not tested.
- **Effects at or below the instability control cannot be told apart.** Any effect under about
  27% flips falls below CONTROL-COV's upper bound. This covers punctuation, free text and
  JSON-shape effects.
- **Per-homonym results are INSUFFICIENT DATA,** with 5 bases each.
- **Untested:** interactions between factors, apart from the `Content-Length` twins, and attack
  counterparts. This probe says nothing about recall.
- **Not generalisable** to V5, External v1 or other models.

---

## PART 3 — Implications for V5 (concepts only; no probe text may be reused)

### 3.1 Priority matrix (evidence-driven)

| Factor | Evidence | Observed effect | V5 implication | Priority | Risk |
|---|---|---|---|---|---|
| Apostrophe in human values | STRONG, 30/30 | content coverage (`'` scarce: 19 benign groups) | benign names, addresses and text carrying `'` in natural syntax, in several fields; attack counterparts in the **same** fields | **HIGH** | SQLi recall: `'` is a genuine SQLi signal. Benign `'` must be natural, attacks must show executable syntax |
| `#` in values | STRONG (password, 19/30); same direction in the 4 sensitive address bases | content coverage (`#` absent in benign) | benign passwords, unit numbers and references with `#`; passwords from NIST SP 800-63B-style policies (note B) | **HIGH** | `#` is also a SQL comment and URL fragment; keep symmetric attack carriers |
| `http://` URLs | STRONG, 18/30 | content coverage (plain http 7 benign vs 535 attack groups) | benign external URLs with both schemes in URL-valued fields | **HIGH** | SSRF/redirect recall: the attack side must differ by **target** (internal, metadata, loopback), never by scheme |
| `Transfer-Encoding: chunked` | STRONG, 18/33 | envelope train/serve skew (TE unseen outside smuggling) | add chunked framing (TE with a de-chunked body, as the gateway renders it) to the **shared** envelope for both classes; keep smuggling defined by **conflicting** framing (TE + CL, obfuscated TE) | **MEDIUM–HIGH** (how common chunked clients are in deployment is UNVERIFIED) | smuggling recall; D1 envelope-shortcut gate |
| Instability on covered values | 5/40 (12.5%) | model boundary behaviour | V5 acceptance must include a stability/metamorphic suite; the Decision Model's coverage/deferral design should assume flip noise of about 10% | **MEDIUM–HIGH** | none for data; needs an evaluation gate |
| OOV reasons (10.7% of BLOCKs) | descriptive | model behaviour (extrapolation) | V5 reason contract and evaluation: count OOV reasons as a coverage signal | MEDIUM | — |
| Address-field reference blocks | 26/30 references blocked (not isolated) | unknown | **next probe before V5's generator is frozen** (§3.3); do not design V5 data on it yet | MEDIUM (pending evidence) | over-fitting to a hypothesis |
| Single- vs multi-key JSON | 5 and 7 B→A (descriptive) | reverse-shortcut direction | multi-key, typed JSON in **both** classes; it is already F4 of the audit | MEDIUM | new "multi-key ⇒ benign" shortcut if attacks stay single-key |
| `Content-Length` | 1/33, no effect | none observed | add it in **both** classes for realism (cheap, class-neutral); do **not** prioritise it as a cause | LOW | none |
| Ports, IP Host, `Proxy-Connection` | 0 flips | none observed | keep the envelope pool shared; no special work | LOW | — |
| SQL/shell homonyms in prose | 0/56 A→B | coverage gap without observed causal effect | natural prose remains useful for coverage, but is not a priority on V4 evidence | LOW–MEDIUM | the reverse shortcut (`the`, `please`) still needs breaking (audit F2) |
| Parameter/field counts, JSON types, `+`, path depth/`%2F`, parameter names | no or weak effect | gaps without observed effect | include through the schema-driven generator (audit F3/F4/F6); not as targeted fixes | LOW–MEDIUM | — |
| `;` `&` `!` `?` in prose; free-text length | weak, at instability level | not distinguishable from instability | — | LOW | — |

### 3.2 What NOT to touch yet

- Do not build envelope-specific V5 data for ports, IP Hosts, `Proxy-Connection` or
  `Content-Length` as *causes*.
- Do not build an SQL-homonym hard-negative family as a top priority.
- Do not design anything on the address finding until it is isolated.
- Do not change V4, `inference_core` or the runtime.

### 3.3 Next step

**V5 data specification**, the next node on the critical path, written from §3.1. Before the V5
generator is frozen, one small pre-registered follow-up probe should run, in the same format and
with new bases. It would isolate:
- the address-field reference blocks (parameter name vs value pattern);
- the `#` × parameter-name interaction;
- whether the `'` effect holds outside surnames (company names, prose).

---

## Reproduce

```bash
python3 scripts/evaluation/minimal_pair_probe_cases.py --out-dir <empty dir>      # byte-identical cases.jsonl
python3 -m unittest tests.test_v4_minimal_pair_probe -v
python3.12 scripts/evaluation/run_v4_minimal_pair_probe.py run --dir reports/v5/minimal-pair-probe-v1      # refuses: already scored
python3 scripts/evaluation/run_v4_minimal_pair_probe.py analyze --dir reports/v5/minimal-pair-probe-v1     # deterministic, from raw/records.jsonl
```

To score again on a different machine, copy `PROTOCOL.md`, `PROTOCOL_REVIEW.md`, `SHA256SUMS`,
`manifest.json` and `cases.jsonl` into an empty directory under the repository, then run `run`
there. It needs the ML environment (torch 2.6.0, transformers 5.8.0, peft 0.19.1) and the V4
adapter `7bf16875…`.
