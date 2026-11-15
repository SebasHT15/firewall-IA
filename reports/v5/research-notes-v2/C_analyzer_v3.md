# C — Hybrid Analyzer v3: design research (2026-10-06)

**RESEARCH NOTE, design only.** Nothing was trained, implemented, run or decided. No dataset was
opened or modified. Not read: `datasets/v4_clean/eval.jsonl`, `reports/external/`, any External
Test v1 case. The External v1 figures quoted below are the **published aggregates** of
`reports/hybrid/analyzer-external-v1-run-001/README.md` (D53), used as context only, never for a
design choice. Every choice proposed here needs an owner decision. Claims that could not be
checked against a primary source in this session are marked **UNVERIFIED**.

Inputs read: `reports/v5/research-notes-v1/README.md` §B, `reports/v5/benign-coverage-audit-v1/`,
`reports/hybrid/phase2b-analyzer-v2-run-002/`, `reports/hybrid/analyzer-external-v1-run-001/`
(aggregate README), `reports/hybrid/v4-analyzer-disagreement-v1/`,
`reports/hybrid/v4-analyzer-paired-dev-v1/`, `DECISIONS.md` D9, D10, D15, D43–D55,
`data_plane/request_features.py`, `scripts/training/hybrid_analyzer.py`.

---

## 0. What failed in Analyzer v2, in one table

| Symptom (source) | Mechanism |
|---|---|
| Top attack features are `percent_encoded_ratio` #1, `percent_count` #2, `symbol_count` #3 (run-002 §7) | **raw-encoding features**: the V4 generator percent-encodes payloads, so "is encoded" ≈ "is attack" |
| Category leans on `path_length` (−0.06 macro-F1 when it is removed); 37% top-1 on External v1 | **endpoint shortcut**: the synthetic endpoint encodes the category |
| External v1 aggregate: api-json FP 29/40, api-query 13/40; ECE 0.126 vs 0.024 internally | request-level counts of **shape**, not intent; benign JSON is absent from TRAIN (audit §3.3: 0 JSON objects with ≥ 2 keys, numbers or booleans) |
| #60: scores 64/68 of V4's false positives ≥ 0.5; paired gap median 0.042 | **same data, labels and objective as V4** (`P(BLOCK | request)` on V4-clean) → same errors, no complementarity |
| #60: 122/153 benign that V4 allows score ≥ 0.5 | no lexical view: `?q=how+to+select+a+good+password` ≈ SQLi in a character-count space |
| All header-borne attacks missed (JWT, CSRF) | D44/D48, by construction (not a model problem) |

**Conclusion carried forward from research-notes-v1 §B:** v2 failed by **representation and
objective**, not capacity. HistGradientBoosting itself was fine (stable, calibrated in
distribution, 0.49 ms attack head). Changing the model family without changing the input view,
unit and label would repeat the failure.

---

## 1. What MUST be deterministic

Rule: anything that defines **what the bytes mean to the backend** is deterministic, versioned
and unit-tested; ML never sees an undecoded value and never decides how to parse.

### 1.1 Parsing (backend-faithful, bounded)

| Component | Output | Parse anomalies (evidence, never silently fixed) |
|---|---|---|
| Request line, path | segments, raw + decoded | encoded `/` (`%2F`), `;` path params, backslash, NUL |
| Query, `application/x-www-form-urlencoded` | ordered `(name, value)` list, repeated names kept | `&` inside value after decode, empty names, `+`-vs-`%20` mixture |
| JSON | leaves as `(json_path, type, value)`; duplicate keys kept (as `request_features._json_body` already does) | invalid JSON under a JSON type, depth > cap, leaves > cap, duplicate keys |
| `multipart/form-data` | parts: name, filename, part content type, value | boundary errors, filename with path, nested types |
| XML (minimal) | text and attribute leaves, `DOCTYPE` / `ENTITY` presence | external entity declarations (deterministic XXE evidence) |
| Declared vs sniffed body type | both | **mismatch is evidence** (WAFFLED, Akhavani et al., ACSAC 2025, arXiv 2503.10846: 1,207 confirmed bypasses of 5 WAFs via parsing discrepancies across JSON / multipart / XML; > 90% of sites studied accepted urlencoded and multipart interchangeably) |
| Cookies, `Authorization`, `Origin` / `Referer`, CL/TE framing | **not parsed** until an owner decision revises D44 (research-notes-v1 §B) | — |

Hard caps (proposed, to be fixed by decision): ≤ 256 leaves per request, ≤ 4 KiB analysed per
value (the rest flagged `truncated`), JSON depth ≤ 32. Exceeding a cap is a parse anomaly and a
DEFER signal, never an ALLOW.

### 1.2 Decoding (bounded, per value, ModSecurity-style)

ModSecurity applies named transformations in the order written in a rule (`t:urlDecodeUni`,
`t:htmlEntityDecode`, `t:jsDecode`, `t:cssDecode`, `t:normalizePath`, `t:cmdLine`,
`t:compressWhitespace`, `t:removeComments`, `t:lowercase`, …), each consuming the previous output
(ModSecurity v3 Reference Manual,
<https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)>, checked 2026-10-06).

Proposed pipeline per value: percent (incl. `%uXXXX`, `+` = space only in layer 1 of
query/form, as the audit does) → HTML entities → JS/Unicode escapes (`\uXXXX`, `\xNN`) → UTF-8
validation (invalid / overlong sequences flagged, not repaired) → loop until fixpoint, **max 3
layers**. Base64 is decoded only as a **side view** when the whole value is valid base64 and
decodes to printable text, never in place.

- **Decode depth, overlong UTF-8, mixed encodings are reported as separate evidence** (to the
  Decision Model / coverage gate) and **never fed to the family models** (research-notes-v1 §B).
  This is the direct fix for v2's #1 shortcut.
- Consequence for D15: `double_url_encode`, `unicode_escape`, `html_entity` and
  `mixed_case_percent` become invariant **by construction**. A metamorphic test on them then
  checks the decoder, not the model. `bash_ifs` and `param_fragmentation` stay genuine held-out
  robustness tests and must stay out of training (D15).

### 1.3 Canonicalisation (per family view, deterministic)

- path: RFC 3986 §5.2.4 dot-segment removal **after** decoding, `\` → `/`, duplicate `/`
  collapsed; report "escapes root" as a boolean;
- URL-valued values: parse scheme / host / port; canonicalise IPs (decimal, octal, hex,
  IPv4-mapped IPv6) with an exact address parser; classify loopback / private / link-local /
  metadata (`169.254.169.254`) / non-HTTP schemes (`file`, `gopher`, `dict`); "external" is
  judged against the **configured deployment origin, never `Host`** (D44);
- SQL view: comment removal / replacement and whitespace compression (`/**/` → space), case fold;
- shell view: `t:cmdLine`-like normalisation (quotes and `^` removed, `${IFS}` → space); exact
  semantics to specify from ModSecurity's implementation (**UNVERIFIED** detail);
- lowercase only inside the family views; the original case pattern is a separate count.

### 1.4 Deterministic family detectors (evidence, not verdicts)

| Family | Detector | Source / note |
|---|---|---|
| SQLi, XSS | **libinjection** (`libinjection_sqli`, `libinjection_xss`) | BSD-3; v4.0.0 per its CHANGELOG; tokenizer + folding + fingerprint DB over the first 5 folded tokens; the project itself says it is one signal, not a verdict, and documents gaps (benign SQL before the payload pushes it out of the window; unquoted `or 1=1` intentionally not flagged) and false positives on SQL-like prose — <https://github.com/libinjection/libinjection> (checked 2026-10-06). ModSecurity's `@detectSQLi` / `@detectXSS` are built on it (Reference Manual) |
| path / file access | normalised path contains `..` above root, or sensitive-path list hit, or `file://` / wrapper scheme (`php://`, `data:`) | deterministic |
| command injection | shell metacharacter (`;`, `|`, `&&`, backtick, `$(`, newline) followed by a command-like token in the shell view | deterministic; recall on novel syntax is the weak point (External v1 cmdi recall 32/40 for v2, aggregate) |
| SSRF / open redirect | §1.3 URL classification of any URL-valued value | deterministic |
| SSTI | delimiter pair (`{{…}}`, `${…}`, `<%=…%>`, `#{…}`) enclosing an expression (operator or call) | deterministic |
| CRLF / header injection | decoded `\r` or `\n` inside a query/form value | deterministic |
| XXE | `DOCTYPE` with `ENTITY … SYSTEM/PUBLIC` | deterministic |
| NoSQL | JSON key starting with `$` (`$ne`, `$where`, `$regex`) or bracket syntax `name[$ne]` | deterministic |

D9 says "do not implement CRS/ModSecurity/Coraza now". libinjection is a library, not CRS, but a
detector set *inspired* by CRS still needs an explicit decision, and **none of these may BLOCK
on its own** (D29/D43); they are inputs to the Decision Model.

---

## 2. What genuinely gains from ML, and on what unit

**Unit: the decoded, canonical value (one query/form value, one JSON string leaf, one multipart
part, one path segment).** Not the field, not the request.

| Unit | Verdict | Why |
|---|---|---|
| **per value** | **yes** | the payload lives in one value; position-independent; cannot see endpoint, path, parameter name or envelope, so the v2 shortcuts are structurally impossible; many more independent training units per payload group |
| per field (name + value) | **no learned name** | parameter names are deployment- and generator-specific (endpoint shortcut). A deterministic *value kind* (numeric, email, URL, identifier, free text — computed from the value itself, or from a configured OpenAPI schema) may condition thresholds later |
| per request | **no ML in the Analyzer** | aggregation is deterministic: per family, `max` over values, count of values with evidence, which value (JSON path) fired. Request-level learning belongs to the Decision Model, which has its own gates (research-notes-v1 §C) |

**Where ML adds what grammars miss** (to be shown, not assumed):
1. syntactic variants a fixed fingerprint or rule does not enumerate (SQLi beyond libinjection's
   5-token window, XSS handler/scheme variants, shell syntax without classic metacharacters);
2. a **graded, calibrated** per-family score instead of a binary hit, so the Decision Model can
   trade coverage for benign cap;
3. down-weighting human-syntax look-alikes (apostrophe surnames, `Apt #4`, prose with "select",
   "union", "from") **only if** the benign values contain them (audit F1/F2; today they do not).

**Objective (the main change).** Multi-label, one binary head per family f:
`P̂(value contains executable syntax of family f | canonical value)`. The positive label comes
from **payload provenance** (the injected value), never from "would V4-clean say BLOCK?". The
negative label comes from benign value sources (audit F1–F7 generator, a real-text corpus such
as Natural Questions — licence CC BY-SA, assessment pending — and real API examples). V4's
request-level labels and V4's dataset rendering are not the training target.

---

## 3. Representation: small, decoded, lexical + structural

Per canonical value, all hashed into one sparse vector of **2^12–2^14** signed buckets (feature
hashing, Weinberger et al., ICML 2009, doi:10.1145/1553374.1553516, arXiv:0902.2206 — tail
bounds and negligible interaction between hashed subspaces):

| Block | Content | Rough active features per value |
|---|---|---|
| **token-class n-grams** (n = 1–3) from one small family-agnostic lexer (~30–40 classes: `WORD`, `NUM`, `QUOTE_S/D`, `PAREN_O/C`, `OP_CMP`, `OP_LOGIC`, `COMMENT`, `SEMI`, `PIPE`, `BACKTICK`, `DOLLAR_PAREN`, `TAG_OPEN`, `EVENT_ATTR`, `SCHEME`, `DOTDOT`, `TPL_DELIM`, `WS`, …) | captures syntax: `QUOTE_S OP_LOGIC NUM OP_CMP NUM` vs `WORD QUOTE_S WORD` | 10–100 |
| **keyword identity** from a closed list (SQL, JS/HTML, shell, template keywords), as unigrams and as `KW` × neighbour-class bigrams | separates "select … from …" in SQL syntax from "select your plan" in prose | 0–20 |
| **char-class n-grams** (n = 2–4; letters → `a`, digits → `9`, each ASCII punctuation kept literal, space → `_`) | robust to identifiers; sees punctuation context | 10–200 |
| **structural counts** (dense, ~20 columns): log-binned length, digit/letter/punct/non-ASCII ratios, quote and paren balance, max nesting, longest punctuation run, number of tokens | cheap shape context **of the value**, not of the request | 20 |
| deterministic detector outputs (libinjection hit + fingerprint class, etc.) | optional; only in an ablation-controlled stack (G7) | 0–8 |

Signed hashing (`alternate_sign`) makes collisions cancel in expectation; power-of-two sizes
map evenly (scikit-learn user guide 1.9.1, Feature hashing,
<https://scikit-learn.org/stable/modules/feature_extraction.html>). Hashing is one-way, so a
training-side **reverse map bucket → n-grams** must be kept for interpretation.

**Why not raw encodings (or raw bytes):**
1. v2 shows the failure directly: encoding statistics were the top signal and they are a
   generator artefact (run-002 §7).
2. Encoding is **attacker-controlled and semantics-free** for the backend: WAF-A-MoLE (Demetrio
   et al., SAC 2020, doi:10.1145/3341105.3373962) evades every ML WAF it tests with
   semantics-preserving mutations (case swap, whitespace substitution, comment injection,
   integer encoding…). Features over decoded, comment-compressed, case-folded views make several
   of those operators no-ops by construction.
3. Encoding also varies by **client** (browsers, `curl`, JSON SDKs), so it carries deployment
   identity — the same class of shortcut D1/D44 removed for `Host` / `User-Agent`.
4. Encoding anomalies that *are* evasion indicators (double encoding, overlong UTF-8) are kept,
   but as deterministic evidence for the Decision Model (§1.2), where their weight is decided
   with benign data that actually contains them.

**Why token classes rather than raw word n-grams or a char-CNN/transformer:** the benign side
has no ordinary English function words (audit §3.2: `and`/`or`/`from` 0–1 benign groups vs
hundreds attack), so any raw-word model learns "SQL word ⇒ attack" and reverse shortcuts
(`the`, `please` ⇒ benign). Token classes collapse usernames and free text into a few classes
(less memorisation of tiny benign pools) while the closed keyword list keeps the identities
that matter. No small transformer: no evidence here justifies it; data, not capacity, is the
binding constraint, and it would break embedded portability (D10).

---

## 4. OOD / coverage — simple, deterministic, used as DEFER gates

Four indicators, all computed from training artefacts, none learned with labels:

| Indicator | Method | Cost |
|---|---|---|
| **n-gram novelty** (Anagram-style) | Bloom filter of the token-class 3-grams and char-class 4-grams **seen in training values** (one filter for benign, one for any class). Score = fraction of a value's n-grams absent. Anagram (Wang, Parekh & Stolfo, RAID 2006, LNCS 4219, pp. 226–248; DOI **UNVERIFIED** this session) models high-order n-grams in Bloom filters for space efficiency; PAYL (Wang & Stolfo, RAID 2004) is the 1-gram predecessor | 2^20 bits = 128 KiB per filter, k ≈ 5 hashes (FP rate computed and reported) |
| **length / charset profile** | per value kind: training percentile of length; set of char classes seen. Kruegel & Vigna (CCS 2003, pp. 251–261; <https://sites.cs.ucsb.edu/~chris/research/doc/ccs03_webanomaly.pdf>; DOI **UNVERIFIED** this session) model attribute length, character distribution, structure and token presence per attribute; their per-deployment profiles need real traffic we do not have, so here the profile is the **training distribution**, i.e. a coverage measure, not a deployment anomaly detector | a few KiB |
| **parse anomalies** | §1.1 / §1.2 flags (type mismatch, caps exceeded, invalid UTF-8, decode depth ≥ 2, duplicate keys) | free |
| **structural support** | request shape bucket (method × body format × param-count bucket × JSON depth bucket × value kinds) looked up in a table of training **group** counts with the D18 rule (ABSENT 0 / SCARCE 1–29 / SUPPORTED ≥ 30), exactly the audit's markers | a few KiB |

Use: hard **DEFER** (to V5) gates in the Decision Model first (research-notes-v1 §C), never an
ALLOW and never a learned feature until the DM gates allow it. Not proposed: Isolation Forest,
autoencoders, density models — more parameters, no labels to validate them, poisoning and drift
risks (Sommer & Paxson, IEEE S&P 2010, on the gap between anomaly detection and operational
use; cited from research-notes-v1, not re-verified this session).

---

## 5. Candidate small models

| Model | Fit to §3 | Notes (verified 2026-10-06 unless marked) |
|---|---|---|
| **L1-logistic, one per family, on the sparse hashed vector** | native: sparse CSR, ~100–300 active features | scikit-learn 1.9.1: L1 via `liblinear` or `saga`; `penalty` is deprecated since 1.8 (removed in 1.10) in favour of `l1_ratio=1`; `fit` accepts CSR ([docs](https://scikit-learn.org/stable/modules/generated/sklearn.linear_model.LogisticRegression.html)). Precedent for sparse linear models over WAF evidence: ModSec-Learn (Scano, Floris, Montaruli et al., DCAI 2024, LNNS 1198, arXiv:2406.13547) learns CRS-rule weights and with sparse regularisation discards > 30% of rules; adversarially hardened follow-up ModSec-AdvLearn (Floris et al., IEEE TIFS 2025, doi:10.1109/TIFS.2025.3583234, cited from research-notes-v1) |
| **HistGradientBoosting per family on a compact dense vector** | needs **dense** input: scikit-learn 1.9.1 `HistGradientBoosting*` validates `X` without `accept_sparse` (read in the installed source, `_hist_gradient_boosting/gradient_boosting.py`), so 2^14 hashed columns is impractical; use structural counts + detector outputs + ≤ 2^8–2^10 hashed buckets | captures interactions (quote × keyword × balance) a linear model needs n-grams for; `max_bins` 255, native NaN, `monotonic_cst` / `interaction_cst` available ([docs](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.HistGradientBoostingClassifier.html)) |
| Random forest, MLP, small transformer | not proposed | RF 93.6 MB / 180 MiB RSS in run-002; MLP excluded by D55; transformer: no supporting evidence |

---

## 6. The three candidates

| | **C1 — deterministic evidence engine** | **C2 — C1 + per-value L1-logistic on hashed lexical n-grams (recommended)** | **C3 — C1 + per-value HGB on compact dense features** |
|---|---|---|---|
| Unit | value → deterministic aggregation | value → `max` per family | value → `max` per family |
| Input | canonical views (§1) | §3 hashed 2^12–2^14 + ~20 counts | ~20 counts + detector outputs + 2^8–2^10 hashed buckets |
| Learned parameters | 0 | ≤ 8 × 2^14 weights, most 0 after L1 | 8 × (≈100 trees × ≤ 31 leaves) |
| Model size (estimate) | detectors + tables, < 1 MiB (libinjection binary size **UNVERIFIED**) | ≤ 512 KiB float32 dense, far less as a sparse table, + 2 Bloom filters (256 KiB) | ~0.5–1 MiB as generated C or JSON trees (estimate from run-002's 100-tree attack head; **to measure**) |
| Latency (hypothesis, to measure) | linear in value length | lexer + hashing + sparse dot product per value: sub-ms per request in C; pure-Python stdlib plausible ~1 ms | same front end + tree walk; sklearn single-row overhead (run-002: 8.4 ms for 300 × 8 trees) disappears with TL2cgen |
| Export / runtime | C library (libinjection) + Python or C glue; stdlib-only possible except libinjection (ctypes or a pure port; **D33 question**) | **coefficient table, no dependency**: runs in the stdlib data plane (D33); m2cgen lists `LogisticRegression`; skl2onnx converts `LogisticRegression` and `FeatureHasher` but **not** `HashingVectorizer` → own hashing code in both train and runtime | Treelite `sklearn.import_model` lists `HistGradientBoostingClassifier`; C codegen moved to **TL2cgen** (Treelite ≥ 3.x) with a `quantize` threshold option; **m2cgen does not list HGB**; skl2onnx converts HGB; ONNX Runtime minimal builds need the ORT model format |
| Interpretability | full | coefficients → n-grams via reverse map | permutation importance / SHAP-like only |
| Main strength | encoding-invariant, auditable, no training data needed, different mechanism from V5 | recall on variants with a graded, calibratable score; sparsity; trivially portable | interactions; v2 showed HGB is stable and calibrated in distribution |
| Main risks | recall on novel syntax; rule FPs on human punctuation; D9 decision needed | re-learning generator artefacts if positives come only from PayloadsAllTheThings rendered like V4; benign value scarcity; hash collisions hide meaning; WAF-A-MoLE-style mutation | the dense compact vector re-approaches v2's "counts of shape" view; less portable to stdlib (needs a tree walker or a compiled `.so`) |

**Recommendation.** Build **C1 first** and freeze it as the baseline. Add the learned layer as
**C2** only if it passes the gates of §7 against C1 on pre-registered criteria. Run **C3 only as
a challenger** under the same gates and a mechanical winner rule (as D54/run-002 did), and adopt
it only if it beats C2 on hard-benign and paired separation, not on aggregate ROC-AUC. C2 is
preferred by default because its representation is the one that fixes v2's failure, its
runtime needs no dependency in the stdlib data plane (D33), and it is the most auditable learned
option.

---

## 7. Not repeating v2: acceptance gates (proposed, to be pre-registered)

All on development data and new value-level sets; **never on External v1** (D53/D45). Any claim
of external performance needs External v2 (D40). Numbers are proposals for the owner.

**G0 — data and labels (before any fitting).**
- Value-level dataset with roles TRAIN / VALIDATION / TEST, grouped by **canonical decoded
  payload** (attacks) and **value-source draw** (benign); 0 overlap under canonical string,
  generator group and template (D16/D54 pattern), asserted in code.
- Positives from ≥ 2 independent sources where licences allow; PayloadsAllTheThings-derived
  values grouped so that one canonical payload never spans roles (licences **UNVERIFIED**).
- Benign families F1–F7 (audit §8) each SUPPORTED (≥ 30 groups) **and** each carrier also has
  attack values (symmetry rule), so "multi-key JSON ⇒ benign" cannot be learned.
- The label is per value and per family; no V4 label, no V4 decision, no V4 reason as a target.

**G1 — encoding and mutation invariance (metamorphic).**
- D15 held-out encodings (`double_url_encode`, `unicode_escape`, `html_entity`,
  `mixed_case_percent`): features **byte-identical** to the plain value on 100% of VALIDATION
  values (tests the decoder).
- Genuine held-out transforms (`bash_ifs`, `param_fragmentation`) and WAF-A-MoLE-style SQL
  mutations: per-family recall at the frozen benign cap drops ≤ 5 pp vs unmutated (proposed).

**G2 — envelope and position invariance (exact).** Changing `Host`, `User-Agent`, port,
`Content-Length`, path, parameter name or JSON path, or moving the payload between query / form
/ JSON leaf, leaves every per-value score **identical** (holds by construction; tested).

**G3 — shortcut audit.**
- No raw-encoding, path, parameter-name or header feature exists (code review + test, like D44's
  test).
- Top-50 coefficients (C2) or permutation importances (C3), reverse-mapped to n-grams, contain
  no generator constant (the 5 fixed benign sentences, `_b64ish` patterns, URL pool hosts).
- Ablation: removing the structural-count block costs ≤ a pre-declared fraction of the learned
  layer's gain; if counts carry most of the signal, the lexical view failed.

**G4 — hard benign.** On a new hard-negative set (apostrophe/`#`/`&`/`!` human values, SQL-homonym
prose, legitimate external URLs, encoded paths; minimal-pair protocol draft of the audit):
learned layer flags **no more** benign groups than C1 at the same attack recall, and the claim
"≤ 1% at the cap" requires ≥ 300 independent benign groups (rule of three; ≥ 3,000 for 0.1%).

**G5 — paired separation (same carrier, payload vs benign twin).** Attack twin scored higher in
≥ 95% of pairs, median gap ≥ 0.5 (v2: 176/201 and 0.042 on #60). Use a **new** paired set; #57 and
#60 are consumed development data and only diagnostics.

**G6 — complementarity with V4/V5.** On development data with V4 (later V5) decisions: double-fault
rate and Yule's Q against V4 reported (Kuncheva & Whitaker, Machine Learning 2003, cited from
research-notes-v1); the learned layer must **not** agree with most of V4's benign false
positives (v2: 64/68). Proposed: flags < 50% of V4's false-positive benign groups on the new
hard-negative set.

**G7 — increment over C1.** Adopt the learned layer only if the paired group-bootstrap 95% CI of
its gain in recall at the frozen benign cap over C1 lies entirely above 0 on VALIDATION, with
G4 not worse. If detector outputs are stacked as features, the same gate must hold **without**
them.

**G8 — calibration (D55).** native → sigmoid → isotonic only on a robust OOF Brier gain without
worse log loss; reliability per family; "uncalibrated" is allowed.

**G9 — runtime parity and budget.** Exported runtime (stdlib table, TL2cgen C) equals the Python
reference on 100% of VALIDATION values (|Δp| ≤ 1e-6, identical hashes); P95 ≤ 1 ms per request
and RSS ≤ 16 MiB on the target-class CPU (proposed; D10 platform still TBD); hard caps of §1.1
enforced.

---

## 8. Embedded viability

- **Memory.** C2: sparse weight table + two 128 KiB Bloom filters + lexer tables ≈ < 1 MiB
  (estimate). Compare run-002: 8.9 MB artifact, +15 MiB RSS for HGB + HGB under scikit-learn.
- **Latency.** Work is linear in total value length and bounded by the caps; no matrix product
  beyond a sparse dot product. The run-002 latency was dominated by scikit-learn's per-call
  overhead on the 300 × 8-tree category head, not by tree evaluation itself (hypothesis to
  measure with TL2cgen).
- **Export options, verified status (2026-10-06):**
  - **Treelite** (<https://treelite.readthedocs.io/en/latest/tutorials/import.html>): imports
    `HistGradientBoostingClassifier/Regressor`, RF, ExtraTrees, GBDT and `IsolationForest`.
    Code generation has moved to **TL2cgen** (<https://tl2cgen.readthedocs.io/>), which compiles
    tree ensembles to C; compiler parameter `quantize` quantises thresholds. That the output is
    strict C99 with no runtime dependency is **UNVERIFIED** (not stated on the pages read).
    Research-notes-v1's "Treelite C99 export for HGB" should now read "Treelite import +
    TL2cgen C export".
  - **m2cgen** (<https://github.com/BayesWitnesses/m2cgen>): README lists `LogisticRegression`
    and RF/ExtraTrees, LightGBM/XGBoost boosters, **not** `HistGradientBoosting*`. Release
    cadence **UNVERIFIED** (PyPI page did not load).
  - **skl2onnx** (<https://onnx.ai/sklearn-onnx/supported.html>, sklearn 1.8 table): converts
    `HistGradientBoostingClassifier`, `LogisticRegression`, `FeatureHasher`; `HashingVectorizer`
    is not listed. **ONNX Runtime** minimal builds require the ORT model format and support
    reduced operator kernels (<https://onnxruntime.ai/docs/build/custom.html>); aarch64 size
    figures **UNVERIFIED**.
- **Simplest path:** C2's linear heads need none of these: a versioned JSON/binary table of
  `(family, bucket) → weight` plus bias, read by stdlib code (D33 intact). Treelite/TL2cgen is
  needed only if C3 wins. libinjection is C; using it from the stdlib data plane needs ctypes or a
  port — a D33/D52 decision.
- **Hashing portability:** the same hash function must run at training and at runtime.
  scikit-learn's `FeatureHasher` uses signed 32-bit MurmurHash3 (user guide), which the Python
  stdlib does not provide; either reimplement it (with byte-exact tests) or train with the
  project's own hasher. Decide before G9.

---

## 9. Contract and decision consequences (for the owner, not taken)

- v3's output is a **per-family evidence vector** (family scores, which value fired, detector
  hits, decode depth, parse anomalies, coverage indicators), not D50's `attack` + category.
  That needs a decision superseding D46/D50 for v3 (v2 stays frozen).
- Drop the category head (research-notes-v1 §B); families are multi-label per value.
- Any header-borne family (JWT, CSRF, smuggling) needs a D44 revision first.
- D9 (rule-based detectors) and D29/D43 (no model-free BLOCK) apply: C1's detectors are evidence.

## Sources (claim supported)

- Akhavani et al., *WAFFLED*, ACSAC 2025, arXiv:2503.10846 — parsing-discrepancy WAF bypasses (1,207 across 5 WAFs).
- libinjection, <https://github.com/libinjection/libinjection> — BSD-3, v4.0.0, 5-token fingerprint design, documented gaps/FPs.
- ModSecurity v3 Reference Manual — ordered transformations; `@detectSQLi`/`@detectXSS` built on libinjection.
- Kruegel & Vigna, *Anomaly Detection of Web-based Attacks*, ACM CCS 2003, pp. 251–261 — per-attribute length/charset/structure models (DOI UNVERIFIED this session).
- Wang, Parekh & Stolfo, *Anagram*, RAID 2006, pp. 226–248 — high-order n-grams in Bloom filters (DOI UNVERIFIED this session).
- Weinberger et al., *Feature Hashing for Large Scale Multitask Learning*, ICML 2009, doi:10.1145/1553374.1553516 — hashing bounds.
- Demetrio et al., *WAF-A-MoLE*, SAC 2020, doi:10.1145/3341105.3373962 — semantics-preserving mutations evade ML WAFs.
- Scano, Floris, Montaruli et al., *ModSec-Learn*, DCAI 2024, LNNS 1198, arXiv:2406.13547 — sparse learned weights over CRS rules.
- Floris et al., *ModSec-AdvLearn*, IEEE TIFS 2025, doi:10.1109/TIFS.2025.3583234 — cited from research-notes-v1, not re-verified.
- Kuncheva & Whitaker 2003; Sommer & Paxson 2010; PAYL (Wang & Stolfo 2004) — cited from research-notes-v1, not re-verified.
- scikit-learn 1.9.1 docs: LogisticRegression, HistGradientBoostingClassifier, feature extraction; installed source for HGB's dense-only input.
- Treelite, TL2cgen, m2cgen, skl2onnx, ONNX Runtime docs as linked in §8.
