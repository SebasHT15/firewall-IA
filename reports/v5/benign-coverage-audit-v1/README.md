# V5 benign coverage audit of V4-clean TRAIN — `benign-coverage-audit-v1`

**DATA AUDIT + DIAGNOSTIC CONTRAST.** It measures where the benign (ALLOW) side of V4-clean
TRAIN is missing or thin, and crosses those gaps with V4 decisions already recorded on two
consumed development diagnostics (#57, #60). It establishes facts about the training
distribution and correlations with V4 behaviour. **It does not establish causes and reports no
rate** (D42). Nothing is trained, fitted or thresholded; no model is run.

| | |
|---|---|
| Date | 2026-10-06 |
| Branch / base | `research/v5-benign-coverage-audit`, base `5602045` (PR #60 merged), uncommitted |
| Analysis | `audit_v5_benign_coverage.py` (`scripts/dataset/`), version `v5-benign-coverage-audit/v1` — SHA-256 in `SHA256SUMS` |
| Inputs | V4-clean TRAIN `4459f686…` (= manifest) · `hybrid_analyzer_v2.jsonl` `e8da8674…` (= manifest), **group ids of V4-train rows only** · #57 records `2c297fb1…` · #60 records `c268a313…` |
| Never opened | `datasets/v4_clean/eval.jsonl` (= Analyzer INTERNAL TEST), External Test v1, `reports/external/`, `docker/.lab-logs/`, any model — refused by code (`guarded_path`) |
| Evidence | [`results.json`](results.json) (every count below) · [`MINIMAL_PAIR_PROTOCOL_DRAFT.md`](MINIMAL_PAIR_PROTOCOL_DRAFT.md) · `SHA256SUMS` |
| Tests | `tests/test_v5_benign_coverage_audit.py`, 24 tests, pass on Python 3.12 and 3.14 |

## 1. Question and data roles

> Which regions of the benign request space are absent or thin in V4-clean TRAIN, and could
> they contribute to V4's false positives?

- **V4-clean TRAIN** (25,134 rows) — the distribution V4 was fitted on. Reading it does not
  consume any test.
- **Group ids** — from `hybrid_analyzer_v2`, which recovered the V4 generator group by re-running
  the unmodified generator (D54). Hybrid rows of V4 *eval* are skipped by a substring test on
  the raw line **before parsing**; the join covers V4-train lines 0–25,133 exactly once with 0
  label mismatches.
- **#57 and #60 records** — consumed development / error-analysis data (D37). Used read-only for
  correlation. Their templates are **not** proposed as V5 data (§7).
- INTERNAL TEST and External Test v1 are not used in any way.

## 2. Method

**Units.** Every marker is counted per class as rows, unique texts, **V4 generator groups**
(the independence unit, D16/D54) and D54 components. Benign: 12,567 rows = 12,567 unique texts
= **7,921 generator groups** (6,657 synthetic + 5,910 CSIC rows). Attack: 12,567 rows = **9,811
generator groups**.

**Support rule (D18), on benign generator groups:** **ABSENT** = 0 · **SCARCE** = 1–29 ·
**SUPPORTED** ≥ 30. `benign_group_share` = benign groups / (benign + attack groups).

**Markers** (pre-declared in code, `extract_markers`):
- **char** — on decoded content (path + decoded parameter values + JSON string leaves).
- **value_char** — separators inside values only.
- **encoding** — on the raw undecoded surface: `%XX` triplets, double encoding, `+`.
- **lexical** — whole-token, case-insensitive matches on decoded content.
- **structure** — method, declared Content-Type, body syntax (detected independently of the
  declared type), parameter counts, path depth, URL- and path-valued parameters, value kinds.
- **json** — keys, depth, nesting, arrays, numbers, booleans, null, URLs, free text.
- **form / field** — field counts, field-name classes, value properties.
- **envelope / anywhere** — headers only, audited and **never proposed as a model feature**
  (D44).

Decoding is iterative, at most 3 layers; `+` means a space only in the first layer of
query/form values.

**Dev contrast.** For every unique benign text in #57 and #60, markers whose TRAIN benign
support is not SUPPORTED are "uncovered". Counts are crossed with the recorded V4 decision.
Identical content-marker profiles with different V4 decisions are reported separately.

## 3. Results on V4-clean TRAIN (facts)

Benign markers by support status:

| Dimension | ABSENT | SCARCE | SUPPORTED |
|---|---:|---:|---:|
| char | 9 | 6 | 6 |
| encoding | 11 | 3 | 6 |
| lexical | 23 | 10 | 8 |
| structure | 9 | 7 | 39 |
| json | 7 | 0 | 4 |
| form / field | 1 / 0 | 1 / 0 | 4 / 12 |
| envelope | 1 | 3 | 26 |

### 3.1 Characters and encoding

All counts are generator groups (benign | attack); rows are in `results.json`.

| Marker (decoded content) | Benign | Attack | Status |
|---|---:|---:|---|
| `#` | 0 | 658 | ABSENT |
| `;` | 0 | 1,535 | ABSENT |
| `..` | 0 | 1,204 | ABSENT |
| `\` | 0 | 1,484 | ABSENT |
| `` ` `` | 0 | 213 | ABSENT |
| `\|` | 0 | 192 | ABSENT |
| `[` / `]` | 0 | 343 / 335 | ABSENT |
| `&` inside a value | 0 | 492 | ABSENT |
| literal `%` inside a value | 0 | 1,646 | ABSENT |
| `'` | 19 (all CSIC) | 2,065 | SCARCE |
| `!` | 19 (all CSIC) | 481 | SCARCE |
| `<` / `>` | 29 | 2,143 / 2,172 | SCARCE |
| `"` | 53 | 2,010 | SUPPORTED, share 0.026 |
| `(` / `)` | 59 | 2,537 / 2,961 | SUPPORTED, share ≈ 0.02 |
| non-ASCII (decoded) | 640 (all CSIC) | 2,295 | SUPPORTED |

| Encoding (raw) | Benign | Attack | Status |
|---|---:|---:|---|
| double encoding (≥ 2 layers) | 0 | 3,142 | ABSENT |
| `%25` | 0 | 3,582 | ABSENT |
| `%23` / `%3B` / `%3C` / `%7C` | 0 | 624 / 1,412 / 1,939 / 170 | ABSENT |
| `%27` / `%21` / `%22` | 19 / 19 / 2 | 1,906 / 416 / 1,713 | SCARCE |
| any `%XX` | 2,748 | 8,996 | SUPPORTED, share 0.23 |
| `%20` (synthetic benign only) | 1,278 | 2,331 | SUPPORTED |
| `+` in query or form (CSIC benign only) | 811 | 1,553 | SUPPORTED |

**Fact.** The benign side has essentially no punctuation beyond `-_.@,/:?`, no double
encoding and no literal `%`. Where `'` and `!` occur at all, they come only from CSIC.

### 3.2 Lexical (whole tokens, decoded)

| Term(s) | Benign groups | Attack groups |
|---|---:|---:|
| select, from, where, table, script, include, call, match, file, url (word), exec, null, sleep, etc, passwd, javascript, onerror, alert, root, insert, echo, eval | **0** each | 13 – 1,390 |
| and / or / union / drop / delete / order / cat | 1 / 1 / 1 / 2 / 2 / 2 / 3 | 248 / 184 / 174 / 105 / 70 / 62 / 116 |
| http (plain `http://`) | 7 | 535 |
| **https** | **203** | 121 |
| **the** | **390** | 27 |
| **please** | **168** | 1 |
| update | 314 | 197 |

**Fact.** Ordinary English function words (`and`, `or`, `from`) are almost absent from benign
TRAIN. A few benign-only tokens (`the`, `please`, `https`) come from the synthetic generator's
five fixed comment sentences and its URL pool. Those are **reverse shortcuts** (token ⇒ benign),
not just gaps.

### 3.3 Structure, forms and JSON

| Marker | Benign | Attack | Status |
|---|---:|---:|---|
| total params = 2 | **0** | 12 | ABSENT (both classes thin) |
| total params = 4 | 0 | 0 | absent in both |
| total params = 3 | 11 | 297 | SCARCE |
| query params = 2 / 4 | 0 / 0 | 5 / 0 | ABSENT |
| form body with exactly 2 fields | 0 | 1 | ABSENT |
| repeated parameter names | 0 | 17 | ABSENT |
| path depth ≥ 4 | 0 | 1–2 | ABSENT (both) |
| long value > 64 chars | 41 | 2,192 | SUPPORTED, share 0.018 |
| path-valued param | 97 | 1,487 | share 0.061 |
| well-formed JSON object body | 103 | 868 | share 0.106 |
| declared `application/json` with a **form** body | **661** | 74 | benign-skewed (D1 Content-Type randomization) |
| URL-valued param | 203 (all `https`) | 214 | SUPPORTED |

| JSON | Benign | Attack |
|---|---:|---:|
| top-level keys = 1 | 103 | 862 |
| top-level keys ≥ 2 | **0** | 6 |
| number / boolean / null leaf | **0 / 0 / 0** | 0 / 0 / 1 |
| nested object / array inside | 0 / 0 | 7 / 1 |
| depth ≥ 2 | 0 | 7 |
| URL string | 0 | 49 |

**Fact.** No JSON object in TRAIN, of either class, has more than 2 keys, a number or a boolean.
The only well-formed JSON bodies are single-key objects, and 89% of their groups are attacks.
Most benign rows that *declare* JSON actually carry a form body.

**Fields** are less impoverished than the earlier quick look suggested:
- passwords with a non-alphanumeric character: 315 benign groups (all CSIC);
- addresses with numbers and words: 751 (all CSIC);
- free-text fields carrying free text: 877 (all synthetic).

What is missing is the *combination*: two-field forms, `'`/`#`/`!` in those values, and English
prose with SQL-homonym words.

### 3.4 Envelope (audit only, D44)

**Envelope features are balanced between classes in TRAIN** (D1's shared envelope works):
- every User-Agent family has a benign share of 0.38–0.44;
- Cookie, Accept, Connection and header count are balanced too;
- `Host: localhost` appears 375 ALLOW vs 380 BLOCK rows;
- ports are only none / 8000 / 8080, balanced.

**Absent from both classes:**
- any other port;
- a loopback **IP** Host (`127.0.0.1`, `[::1]`);
- `Proxy-Connection`;
- `Content-Length` on ordinary bodies — **9 of the 13,686 rows with a body carry it (3 benign,
  6 attack), all in the request-smuggling "framing" shape** (`parse_dataset_v4.py:364-370`).

**The data plane renders headers "exactly as received"** (`data_plane/data_plane.py:113-118`).
So **every real POST/PUT/PATCH reaches V4 with a `Content-Length` header V4 essentially never saw
on a body**, and every non-8000/8080 port is unseen.

**The literal `127.0.0.1` occurs in 58 TRAIN rows, all BLOCK** (27 in the request line, 31 in a
body; **never in a Host header**). Any loopback/internal literal: 0 benign vs 85 attack groups.

## 4. Contrast with development data (#57, #60)

| | #57 (S1 + S2) | #60 (paired) |
|---|---:|---:|
| Unique benign texts | 145 | 142 |
| V4 ALLOW / BLOCK | 102 / 43 | 97 / 45 |
| BLOCK with ≥ 1 uncovered **content** marker | 9 / 43 | **42 / 45** |
| ALLOW with ≥ 1 uncovered content marker | 11 / 102 | 57 / 97 |
| BLOCK with **0** uncovered content markers | **34** (S1 envelope variants, `/`, `/favicon.ico`) | 3 |
| Content-marker profiles with **mixed** V4 decisions | 4 profiles, 110 texts | **7 profiles, 39 texts** |

Selected per-marker counts in #60 (unique benign texts, V4 BLOCK / ALLOW; TRAIN benign groups in
parentheses):

| Marker | V4 BLOCK | V4 ALLOW | TRAIN benign groups |
|---|---:|---:|---:|
| `Content-Length` present | 32 | 17 | 3 |
| form with exactly 2 fields | 22 | 6 | 0 |
| `!` / `%21` | 11 / 10 | 4 / 3 | 19 |
| `'` | 6 | 1 | 19 |
| `#` | 3 | 0 | 0 |
| `&` inside a value | 4 | 0 | 0 |
| encoded path segment | 6 | 1 | 0 |
| JSON URL string | 6 | 1 | 0 |
| JSON with 3 keys and numbers | 10 | 11 | 0 |
| **4 query params** | **0** | **16** | 0 |
| **2 query params** | 2 | 15 | 0 |
| port 9100 (every #60 text) | 45 | 97 | 0 |

Mixed-decision profiles in #60 (same content markers, different V4 decision):

| Profile | V4 decisions |
|---|---|
| `POST` form `username=<x>&password=s3cret%21` | 8 BLOCK (alice, bob, a.khan, fatima, n.garcia, …) / 3 ALLOW (jose.ramirez, lee.wong, mary-jane) |
| `/search?q=<words>` | "return policy details" BLOCK (HPP) vs 6 similar queries ALLOW |
| `/search?q=…select…` | "select your plan comparison" BLOCK vs "how to select a good password" ALLOW |
| `/search?q=…union…` | "credit union savings…" BLOCK vs "labor union history books" ALLOW |
| static path with `%2F` | 6 BLOCK / 1 ALLOW |
| checkout address with `'` | 1 BLOCK / 1 ALLOW |
| URL-valued parameter | external CDN host BLOCK / 6 same-host ALLOW |

## 5. Evidence FOR the benign-coverage explanation (fact → correlation)

1. **Fact:** TRAIN benign lacks whole regions:
   - punctuation such as `#`, `;`, `&`, `'`, `!`;
   - English function and SQL-homonym words;
   - two-field forms;
   - JSON beyond one string key;
   - encoded path segments.
   
   **Fact:** those markers recur in #60's benign texts that V4 blocks.
   **Correlation:** 42 of 45 benign texts V4 blocks in #60 carry at least one uncovered content
   marker, against 57 of 97 that V4 allows.
2. **Fact:** the generator's benign value pools are tiny (5 fixed comment sentences, `_b64ish`
   passwords, single-key JSON; `parse_dataset_v4.py:919-959`). Synthetic benign carries
   **0** `'`/`!`.
3. **Fact:** V4 emits 4 reason strings that do not exist in its 19-reason training vocabulary,
   on 22 benign checkout records in #60 (earlier diagnostic) — compatible with extrapolation
   outside the learned distribution.
4. **Fact:** for in-distribution benign rows V4 is near-perfect internally (2/3,103, a
   non-independent split, D24).

## 6. Evidence AGAINST, or limiting, it (attempted falsification)

1. **Uncovered ≠ blocked.** 57 of 97 benign texts V4 allows in #60 carry uncovered markers. For
   example, 4-query-parameter GETs (absent in both classes) are allowed 16/16, and 3-key JSON
   with numbers is split 10 / 11. Coverage gaps are not sufficient for a false block.
2. **Same profile, different decision.** In 7 content profiles (39 texts) V4 flips while every
   audited content marker is identical. Example: login forms that differ only in a username made
   of covered characters (8 BLOCK / 3 ALLOW). No coverage marker explains that. It points to
   **decision instability near the boundary** — a model-behaviour component.
3. **Envelope-only false blocks exist.** 34 of #57's 43 V4-blocked benign texts have zero
   uncovered content markers. They differ from allowed twins only in envelope values that are
   **absent from both classes** (unseen ports, Proxy-Connection, a loopback-IP Host). TRAIN's
   envelope is balanced, so this is not a learned envelope shortcut. It is behaviour on unseen
   envelope values.
4. **Confounding in #60.** Every #60 text uses an unseen port (9100). Every #60 body request
   carries `Content-Length` (essentially unseen on bodies). Within #60, body requests are
   blocked 32/49 against GETs 13/93. **Body structure, `Content-Length` and form/JSON shape are
   perfectly confounded in #60**, so the content-coverage correlation in §5.1 cannot be separated
   from an envelope train/serve skew with this data.
5. **Not everything is a gap.**
   - Passwords with symbols are SUPPORTED (315 CSIC groups), so "password complexity" alone is
     not the gap — only `!` specifically is scarce.
   - `%20` is SUPPORTED in benign.
   - URL-valued parameters are SUPPORTED (but only `https`).
6. **A token association that crosses positions.** `127.0.0.1` appears only in BLOCK rows and
   never as a Host. V4 blocks loopback-IP Hosts (#57). That is compatible with a learned
   token → attack association applied outside its trained position, not with envelope imbalance.

## 7. What the problems appear to be

| Category | Status | Evidence |
|---|---|---|
| **Dataset coverage (benign content)** | supported correlationally; not causal | §3.1–3.3, §5 |
| **Envelope train/serve skew** (Content-Length on bodies, unseen ports, Proxy-Connection, loopback IP Host) — *not* class imbalance | supported as a fact about TRAIN vs the data plane; effect on V4 **unknown** and confounded in #60 | §3.4, §6.3–6.4 |
| **Token association across positions** (`127.0.0.1`) | compatible, untested | §6.6 |
| **Model behaviour** (boundary instability, out-of-vocabulary reasons) | supported by within-profile flips | §6.2, §5.3 |
| Reverse shortcuts (`the`, `please`, `https`, form-body-under-JSON-type ⇒ benign) | fact about TRAIN; effect unknown | §3.2–3.3 |
| Unknown | the relative weight of each mechanism | needs minimal pairs |

**Conclusion.** Benign coverage is a real, measurable defect and must be fixed in V5. **It is
not a sufficient explanation on its own.** V5 must also fix the envelope train/serve skew, and
the minimal-pair study is needed to separate the confounded mechanisms before the V5 generator
is frozen.

## 8. V5 benign family specification (concepts, not templates)

None of these copies `fwlab.test`, `/login`, `/checkout`, `/api/orders`, `/search`, `/static`,
any #57/#60 value or any External v1 material. Each family states what is missing and what must
be added **symmetrically**.

**Rules for every family:**
- **Both classes, same carriers.** Each new benign structure gets an attack counterpart in the
  same structure, with the payload in one field or leaf. Otherwise V5 learns a new shortcut,
  e.g. "multi-key JSON ⇒ benign".
- **Grouping.** The group key is the benign value-source identity, i.e. the template plus the
  value-pool draw (D16): the canonical value tuple before rendering. Split by group before
  rendering.
- **Validation.** Grouped V5 VALIDATION, the minimal-pair suite (§9, which must be disjoint from
  the generator), #57/#60 as read-only diagnostics, and External v2 for any claim.

| # | Family | Missing coverage (§3) | Benign generator concept | Attack counterpart | Main risks |
|---|---|---|---|---|---|
| F1 | Punctuation-rich human values | `'` `#` `!` `;` `&` `(` `)` `"` in names, addresses, notes, passwords | Real-world name, address and password character distributions (apostrophe surnames, `Apt #`, `&` in company names, symbol passwords) | Same fields with SQLi/XSS/cmdi payloads | **Recall:** quotes and `;` are genuine SQLi/cmdi signals; benign must carry them in human syntax, attacks in executable syntax |
| F2 | Natural-language free text | function words; SQL/shell homonyms (select, union, from, where, table, call, match, include, order, drop, delete, update); prose > 64 chars | Search queries and notes from a real-text corpus (subagent A: Natural Questions, CC BY-SA), not 5 fixed sentences | Payloads embedded in the same prose fields | Reverse shortcut (`the`, `please`) must be broken: attacks must also appear inside prose |
| F3 | Multi-field forms and queries | exactly 2 and 4 params absent; 3 scarce; repeated names absent | Typed forms with 2–8 fields (credentials, profile, contact, filters, pagination), arrays as repeated names | Payload in one of N fields | HPP labelling is ambiguous (repeated names are often benign): needs an explicit label rule |
| F4 | Realistic JSON | ≥ 2 keys, numbers, booleans, null, nesting, arrays, URL strings — absent in **both** classes | Schema-faithful bodies from public OpenAPI specs (subagent A: GitHub/Stripe MIT specs, APIs.guru) with realistic values, **matching** Content-Type | Payload in one leaf at varying depth | Must also fix the form-body-under-JSON-type benign skew (661 groups) so Content-Type/body consistency is not a label signal |
| F5 | URLs, callbacks, webhooks | plain `http://` URLs (7 vs 535); URL strings in JSON; external hosts; query strings inside URLs | Legitimate external URLs, both schemes, with paths and queries | SSRF/open-redirect with internal targets in the **same** parameters | **Highest recall risk:** the benign/attack difference is the target host, so benign must never use internal/metadata targets in URL parameters |
| F6 | Encoded and deep paths | `%2F`/`%20` in paths, depth ≥ 4, literal `%` (`%25`) | Resource paths with encoded segments, spaces, `50%25` | Traversal with encoded `..` at the same depths | Traversal recall: benign encoded paths must never decode to `..` |
| F7 | Envelope realism (**both classes**) | `Content-Length` on every body, ports beyond 8000/8080, loopback-IP Host, `Proxy-Connection`, real client header sets | Apply to the shared envelope generator for both classes alike (D1) | Identical | Must stay class-neutral; check with D1's envelope-shortcut gate (`check_dataset.py`) |

**Out of scope for the generator, as a stated limit.** Header-borne JWT/CSRF and stateful
attacks stay NOT TESTABLE / INSUFFICIENT. The audit gives no basis for widening them.

## 9. Next experiment

[`MINIMAL_PAIR_PROTOCOL_DRAFT.md`](MINIMAL_PAIR_PROTOCOL_DRAFT.md) (design only, not executed):
one-factor-at-a-time minimal pairs on V4. It separates the confounded mechanisms of §6.4 and
includes a covered-dimension control that measures boundary instability (§6.2).

## 10. Reproduce

```bash
python3 scripts/dataset/audit_v5_benign_coverage.py --out reports/v5/benign-coverage-audit-v1/results.json
python3 -m unittest tests.test_v5_benign_coverage_audit -v
```

Only the standard library and `data_plane/request_features.py` are needed. The two dataset
files must be regenerated locally (`docs/data_sources.md`); their SHA-256 are checked and the
run refuses on mismatch. `generated_utc` is the only field that changes between runs.

## 11. Limitations

- Markers are pre-declared heuristics. A missing marker can hide a gap, and the lexicon is a
  chosen list, not exhaustive.
- "Uncovered" is about **benign** support; several gaps are absent in both classes, which is a
  different situation from attack-skewed — both are reported.
- #57/#60 are author-constructed development compositions: counts, not rates. #57's S1 varies
  headers by design.
- The field-name classes match substrings (`user`, `pass`…) and may misclassify.
- CSIC-derived benign rows dominate several "supported" markers (`'`, `!`, non-ASCII, addresses).
  Their realism for modern APIs is limited (Spanish 2010 e-shop).
- No claim about causes: §6.4 is exactly why.
