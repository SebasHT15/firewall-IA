# C2 — Analyzer v3 PRELIMINARY SPEC (2026-10-06)

**PRELIMINARY SPEC, design only.** Nothing was implemented, trained, run or decided. No dataset,
model, runtime file or frozen report was modified; `datasets/v4_clean/eval.jsonl`, External Test v1
cases and the #57 / #60 case files were not opened. Every numeric threshold below is a
**[PROPOSAL]** for the owner to pre-register; every policy choice is an owner decision not yet
taken.

This spec builds on `C_analyzer_v3.md` (the design note, cited as **note-C**) and does not redo it:
the v2 failure analysis (note-C §0), the "what must be deterministic" split (§1), the per-value
unit (§2), the hashed lexical representation (§3), coverage indicators (§4), model candidates
(§5) and gates G0-G9 (§7) are inherited. This spec turns them into a concrete C1 contract and a
C2 go/no-go procedure, and makes **C1-only the default**.

Tags used: **[FACT]** verified in a primary source or in this repo this session; **[HYP]**
hypothesis to be tested; **[PROPOSAL]** a choice or number for the owner; **[UNVERIFIED]** not
checked against a primary source.

Other inputs read for this spec: `DECISIONS.md` D9, D10, D15, D33, D44, D46-D48, D50, D52;
`reports/v5/minimal-pair-probe-v1/README.md` (V4 probe results); `reports/v5/research-notes-v2/README.md`.

---

## 0. Principles and non-goals

1. **Evidence, not verdicts.** C1 and C2 emit facts and calibrated signals about *values*. Neither
   emits ALLOW/BLOCK, `attack`, a category, or a global confidence. Absence of facts is **not**
   evidence of benignity; the `coverage` block says where the engine is blind (D29/D43: no
   model-free BLOCK; D50: no invented confidence).
2. **Backend-faithful parsing is deterministic** and versioned. ML never sees an undecoded value
   and never decides how to parse (note-C §1).
3. **No envelope, no encoding statistics, no field names as model input.** v2's top shortcuts were
   `percent_encoded_ratio`, `percent_count` and `path_length` (note-C §0). `Host`, `User-Agent`
   stay excluded (D44). Encoding anomalies are reported as C1 evidence to the Decision Model (DM),
   never as C2 features.
4. **Simplicity ladder.** Nothing more complex than the simplest technique that passes its gate:
   deterministic rules, then linear sparse models, then (only on a mechanical, pre-registered win)
   anything else. No embeddings, no neural network, no autoencoder / Isolation Forest / density
   OOD model, no transformer. Justification is required for any step up the ladder (§3.3 selection protocol and gate P9).
5. **Reproducibility.** C1 is a pure function: no clock, no randomness, no network, no locale
   dependence, no `PYTHONHASHSEED` dependence. Same bytes + same `config` + same spec version =
   same report, byte for byte.
6. **Respect consumed data.** V4-clean (TRAIN/VALIDATION/INTERNAL TEST, read twice), External Test
   v1 (D40/D53, aggregate only), #57 and #60 (consumed development data), and the minimal-pair
   probes (`research/v5-minimal-pairs-v*`) are **diagnostic-only**. They are not C2 training,
   validation or threshold-selection data, their request texts are never copied into a generator,
   and their **concepts** (apostrophe, `#`, `http` scheme, human punctuation, SQL-homonym prose)
   may be used to design new hard-negative sets.
7. Not goals: JWT/CSRF/smuggling/header-borne attacks (D44/D48; needs a D44 revision), request-level
   learning (DM's job), replacing V4/V5, choosing the embedded platform (D10), choosing the
   runtime (D52: decided after measurement).

---

# PART C1 — Deterministic evidence engine

## 1. Inputs

`AnalyzerInput` (everything C1 may read; anything else is invisible to it):

| Field | Type | Notes |
|---|---|---|
| `method` | token | used only for parse (is a body expected), emitted as context, never a model feature |
| `target` | bytes | raw request target as received (path + query), **before** any decoding |
| `content_type_declared` | string or null | media type + `charset` + multipart `boundary`; used to choose the parser, never to score |
| `body` | bytes | as handed to the data plane. **[FACT]** (note F in this folder, mitmproxy 12.2.3): mitmproxy de-chunks, so `Transfer-Encoding: chunked` is kept as a header and no `Content-Length` is added; gzip is decoded. C1 therefore sees the decoded body and **must not** read framing headers |
| `deployment_origin` | config, optional | the *configured* origin(s) of the protected app, for URL relation facts; **never** the `Host` header (D44) |
| `config` | versioned, hashed | caps (§2.3), closed lists (§2.5), enabled fact groups |

Not inputs: `Host`, `User-Agent`, `Content-Length`, `Transfer-Encoding`, `Proxy-*`, cookies,
`Authorization`, `Origin`/`Referer`, source IP, timing, any model output. Rationale: D44, the
probe's STRONG V4 sensitivity to `Transfer-Encoding: chunked` (18/33 A→B; probe v1 §2.2, a V4
property, not an Analyzer one), and note-C §1.1 ("not parsed until D44 is revised"). The v3 C1
does not parse them; the data plane may report framing separately.

Bounded request budget **[PROPOSAL]**: ≤ 64 KiB of target+body analysed; the remainder is
flagged `request_truncated` (a DEFER signal in the DM, never an ALLOW).

## 2. Processing pipeline

### 2.1 Parse (backend-faithful, bounded)

Inherited from note-C §1.1. Emit **leaves** `(origin, locator, raw_value)`:

| Origin | Parser | Locator (audit only; **never** a model input) |
|---|---|---|
| `path` | split on `/`, keep raw and one-pass-decoded segments | segment index |
| `query` | ordered `(name, value)` list, repeated names kept | name + occurrence index |
| `form` | `application/x-www-form-urlencoded` body, same rules | name + occurrence index |
| `json` | leaves `(json_path, type, value)`; object **keys** are also leaves (origin `json_key`); duplicate keys kept | json path |
| `multipart` | parts: name, filename, part content type, value | part index |
| `xml` | text/attribute leaves + `DOCTYPE`/`ENTITY` presence (no entity expansion, ever) | xpath-like path |
| `raw` | unrecognised or binary body: not parsed into leaves; flagged `body_unparsed` | — |

Each leaf value is analysed independently. Key point for G2-style invariance: the locator is
carried to the output so the DM / analyst can see *where* a fact fired, but nothing computed from
a locator or from the envelope enters any fact except those in the `p.*` parse-evidence group.

### 2.2 Decoding (bounded, per value, ModSecurity-style)

Ordered pipeline, each stage consuming the previous output (ModSecurity v3 Reference Manual,
named `t:` transformations applied in order **[FACT]**, as cited in note-C §1.2):

1. percent-decode (`%XX`, `%uXXXX`; `+` → space only in layer 1 of query/form);
2. HTML entity decode (named + numeric);
3. JS/Unicode escape decode (`\uXXXX`, `\xNN`);
4. UTF-8 validation: invalid or overlong sequences are **flagged, not repaired** (replacement
   char inserted so views stay deterministic);
5. repeat 1-4 until fixpoint or **`max_layers = 3`** **[PROPOSAL]**; non-fixpoint is flagged.

Side view, not in place: a value that is entirely valid base64 and decodes to printable ASCII
gets only the boolean `g.b64_whole_printable`. **No detector is run on the decoded side view in
v3 [PROPOSAL]** (extra surface for little demonstrated need; revisit only if C1 recall review
shows base64-wrapped payloads in the new TEST set).

Every decode operation is recorded as evidence (`g.decode_layers`, `g.decode_ops`) so that the
DM can weigh obfuscation **with benign data that actually contains legitimate encoding**. This
is the direct fix for v2's #1 shortcut (note-C §0, §1.2). By construction `double_url_encode`,
`unicode_escape`, `html_entity`, `mixed_case_percent` (D15 held-out pool) become invariant for
every view-based fact; a metamorphic test on them checks the decoder, not a model. `bash_ifs` and
`param_fragmentation` remain genuine held-out robustness tests (D15) and must stay out of any
fitting.

### 2.3 Caps and budget **[PROPOSAL]**

≤ 256 leaves per request; ≤ 4 KiB analysed per value (rest flagged `truncated`); JSON depth ≤ 32;
decode layers ≤ 3; total analysed ≤ 64 KiB. Work is O(bytes x layers). Exceeding a cap is a parse
anomaly and appears in `coverage`; it never silently discards a leaf (skipped leaves are counted).

### 2.4 Normalisation / canonical views (deterministic, per family)

All derived from the fixpoint-decoded value `v*`:

| View | Construction | Used by |
|---|---|---|
| `V_ws` | `v*` with whitespace runs compressed to one space; original case kept | generic counts |
| `V_sql` | `V_ws` + SQL comment removal/replacement (`/**/`, `-- …`, `# …` to EOL treated as terminator *evidence* before removal) + case fold | `sqli.*` |
| `V_html` | `v*` + HTML-entity-decoded + case fold; NUL and control chars removed *and counted* | `xss.*` |
| `V_path` | RFC 3986 §5.2.4 dot-segment removal **after** decoding, `\` → `/`, duplicate `/` collapsed; "escapes root" boolean | `path.*` |
| `V_shell` | quotes and `^` removed, `${IFS}` → space, backslash-newline removed (exact semantics to be specified from the ModSecurity `cmdLine` description; detail **[UNVERIFIED]**) | `cmd.*` |
| `V_url` | RFC 3986 parse; IPv4 canonicalised with an exact parser (decimal, octal, hex, IPv4-mapped IPv6) | `url.*` |
| `V_tpl` | `v*` unchanged (delimiters are the evidence) | `ssti.*` |
| `V_fold` | NFKC of `v*` (fullwidth / compatibility folding), used **only** to emit `g.nonascii_fold_changed` and to re-run the `xss.*`/`sqli.*` token facts under namespace `fold.*` **[HYP]** that attackers use fullwidth forms; keep only if a held-out unicode evasion slice shows C1 misses it | evasion evidence |

Lowercasing happens only inside views; the original case pattern is separate (`g.case_mixed_kw`).
Canonicalisation is idempotent and its output length is bounded by the input length x a small
constant (unit-tested properties).

### 2.5 Fact catalogue (what C1 emits)

A **fact** is a deterministic function `f(view) → bool | int | enum | short string`, defined in a
versioned catalogue file (`catalogue_sha256` is emitted in every report). Each fact has: id,
type, definition in terms of tokens of a view, **≥ 5 positive and ≥ 5 negative golden vectors
written from the grammar / primary documentation**, not harvested from V4-clean, External v1,
#57/#60 or the probes. A fact never contains a threshold learned from data.

Shared tokenizer **[PROPOSAL]**: one small family-agnostic lexer (~30-40 token classes: `WORD`,
`NUM`, `STR_S`, `STR_D`, `QUOTE_S`, `QUOTE_D`, `PAREN_O/C`, `OP_CMP`, `OP_LOGIC`, `COMMENT_*`,
`SEMI`, `PIPE`, `AMP`, `BACKTICK`, `DOLLAR_PAREN`, `TAG_OPEN`, `EVENT_ATTR`, `SCHEME`, `DOTDOT`,
`TPL_DELIM`, `WS`, …) feeds the `sqli.*`, `xss.*`, `cmd.*`, `ssti.*` facts **and** C2's features
(§3.2). One lexer = one place to test, and shared lexer bugs are a known coupling between C1 and
C2, accepted for simplicity.

Closed keyword lists live in `config`, versioned, with a documented source per list (SQL
reference grammars, HTML tag/event lists, common shell utilities). Lists are not derived from
the V4 dataset.

**Group `g` (per value, all families).**

| Fact | Meaning |
|---|---|
| `g.decode_layers` (0-3), `g.decode_fixpoint` (bool) | how many decode passes changed the value; whether a fixpoint was reached |
| `g.decode_ops` | ordered set of ops that fired (`pct`, `pct_u`, `html`, `js_u`, `js_x`) |
| `g.encoded_metachar` (int) | count of structurally significant chars (`' " < > ; | & $ ` ( ) { } \ / . \r \n NUL`) that exist only as encoded forms in the raw value |
| `g.invalid_utf8`, `g.overlong_utf8`, `g.nul`, `g.ctrl_chars` | encoding anomalies |
| `g.nonascii_fold_changed` | NFKC changes the value |
| `g.truncated`, `g.b64_whole_printable` | cap / side-view flags |
| `g.kind` (enum) | `empty`, `numeric`, `uuid`, `email_like`, `url_like`, `identifier`, `short_token`, `free_text`, `markup_like`, `other`, from the value only (never the field name) |
| `g.len_bytes`, `g.len_chars` | raw lengths (log-bin in the DM, not here) |

> `g.encoded_metachar`, `g.decode_*` are **evidence for the DM and the coverage gate only**. They
> must not be given to C2 and must not be given to the DM as weighted features until a benign
> set containing legitimate encoding exists (note-C §1.2; probe v1 factor F-ENC showed no V4 effect for `%20` vs `+`).

**Group `p` (per request, parse evidence).** `p.body_type_declared`, `p.body_type_sniffed`,
`p.body_type_mismatch`, `p.json_invalid`, `p.json_dup_keys`, `p.json_depth_exceeded`,
`p.leaves_exceeded`, `p.multipart_malformed`, `p.multipart_filename_path`,
`p.param_repeat_max` (largest repeat count of one name, HPP evidence), `p.empty_param_name`,
`p.path_encoded_slash`, `p.path_backslash`, `p.path_param_semicolon`, `p.path_nul`. Basis:
declared-vs-sniffed parser discrepancies are a documented WAF bypass class (WAFFLED, Akhavani et
al., ACSAC 2025, arXiv:2503.10846, 1,207 bypasses across 5 WAFs **[FACT, cited from note-C]**).

**Per-family detectors.** All booleans unless stated; "within k tokens" k = 6 **[PROPOSAL]**.

| Family (D47 id) | Facts | View |
|---|---|---|
| **SQL injection** `sql_injection` | `sqli.quote_logic_cmp` (quote token, then logic op, then comparison within k); `sqli.tautology` (`NUM=NUM`, `STR=STR`, `x=x`, `1<2` pattern after a quote or logic op); `sqli.union_select` (`UNION [ALL\|DISTINCT] SELECT`); `sqli.stacked_stmt` (`;` followed by DML/DDL/exec keyword); `sqli.comment_terminator` (`--`, `#` or `/*` as the **last** non-space token **and** preceded by a quote/paren/SQL keyword; so `Apt #4` and a trailing `#` after a bare word do not fire); `sqli.inline_comment` (comment between non-whitespace tokens); `sqli.fn_set` (int: count of names from the closed dangerous-function list: `sleep`, `benchmark`, `pg_sleep`, `waitfor`, `load_file`, `extractvalue`, `updatexml`, `information_schema`, `@@version`, …); `sqli.kw_count` (int: distinct closed-list SQL keywords); `sqli.kw_adjacent_pairs` (int: keyword-keyword adjacent bigrams, e.g. `select … from`); `sqli.quote_unbalanced` (odd number of unescaped `'`). **Optional namespace `ext.libinjection`**: `ext.libinjection.sqli` (bool) + fingerprint string, only if D9/D33 approve the dependency (§2.9) |
| **XSS** `xss` | `xss.tag_known` (`<` + name from the closed HTML list); `xss.event_attr` (`on[a-z]+\s*=`); `xss.js_scheme` (`javascript:`, `vbscript:`, `data:text/html` after folding); `xss.script_api` (`alert`, `prompt`, `confirm`, `eval`, `document.cookie`, `document.write`, `fetch(`, …); `xss.attr_break` (`"><`, `'><`, `"\s*on…=`); `xss.css_expr` (`expression(`, `url(javascript:`); `xss.srcdoc_or_svg_use`. Optional `ext.libinjection.xss` |
| **Path / file access** `path_file_access` (D49 merged) | `path.dotdot_count` (int, on `V_path` before dot-removal); `path.escapes_root` (bool, after removal); `path.sensitive_hit` (closed list: `/etc/passwd`, `/etc/shadow`, `win.ini`, `boot.ini`, `.git/`, `.env`, `web.xml`, `id_rsa`, `/proc/self`, …); `path.abs_in_value` (value starts with `/` or drive letter); `path.wrapper_scheme` (`php://`, `file://`, `expect://`, `zip://`, `phar://`, `data:`); `path.nul` |
| **Command injection** `command_injection` | `cmd.meta_then_cmd` (decoded `; \| \|\| && \n` or backtick/`$(`, followed within k tokens by a name from the closed command list: `cat`, `ls`, `id`, `whoami`, `wget`, `curl`, `nc`, `bash`, `sh`, `ping`, `nslookup`, `powershell`, …); `cmd.subst` (`` `…` `` or `$(…)`); `cmd.ifs_or_brace` (`${IFS}`, `{cat,/etc/passwd}`); `cmd.redirect_path` (`>`/`>>`/`<` + path-like token); `cmd.pipe_to_shell` (`\| sh`, `\| bash`, `\| python …`); `cmd.name_count` (int) |
| **SSRF / open redirect** `ssrf`, `open_redirect` | on any value with `g.kind ∈ {url_like}` or a leading `//`: `url.scheme` (enum); `url.scheme_nonhttp` (`file`, `gopher`, `dict`, `ftp`, `ldap`, `jar`, …); `url.http_cleartext` (scheme is `http`); `url.host_class` (enum: `loopback`, `private`, `link_local`, `metadata`, `reserved`, `public_ip`, `dns_name`, `invalid`); `url.host_ip_noncanonical` (decimal/octal/hex/short form); `url.userinfo` (`@` authority trick); `url.scheme_relative` (`//host`); `url.origin_relation` (enum: `same`, `different`, `unknown_no_config`) against `deployment_origin` **only**; `url.port` (int or null). *Facts only:* a public external URL is a fact, not an attack (legitimate external links are benign, probe v1 shows V4 flips on `http` scheme alone 18/30) |
| **SSTI** `ssti` | `ssti.delim` (enum: `{{}}`, `${}`, `<%=%>`, `#{}`, `{%%}`); `ssti.expr_inside` (operator, call or attribute chain inside the delimiter pair); `ssti.dunder` (`__class__`, `__mro__`, `__globals__`, `__import__`, …); `ssti.gadget` (closed list: `getRuntime`, `T(java.lang`, `freemarker.template.utility.Execute`, `request.application`, `config.items`, …) |
| **Other** `other_attack` (residual bucket, D47) | **CRLF:** `crlf.cr_lf_decoded`, `crlf.header_like_after` (`\nName:`), `crlf.encoded_only`. **XXE:** `xml.doctype`, `xml.entity_decl`, `xml.entity_external` (`SYSTEM`/`PUBLIC`), `xml.parameter_entity`, `xml.xinclude`. **NoSQL:** `nosql.dollar_key` (JSON key `$`-operator), `nosql.bracket_op` (`name[$ne]` syntax), `nosql.where_js`, `nosql.regex_op` |

Families deliberately **not** covered in v3, reported statically in `coverage.unsupported`: LDAP,
XPath, GraphQL, insecure deserialisation, JWT (D48), CSRF, request smuggling (D44 / framing out of
scope). C1 emitting nothing for those is a blind spot, not an ALLOW signal.

Design notes: **(a)** facts are structural conjunctions (quote + logic + comparison), never a bare
character (`'`, `#`, `&`, `!`, `;`), because those characters are exactly what human values
contain and exactly where V4 failed in the probe (`'` 30/30, `#` 19/30 flips, `http` 18/30; probe
v1 §2.2 **[FACT]**); **(b)** a bare-character count is still emitted as a plain count
(`g.n_punct_*` not listed here; the DM may request it) so nothing is hidden, but it is not a
"detector"; **(c)** a fact definition may be changed only through a versioned catalogue edit
with a change log entry (see §2.8).

### 2.6 Output: `EvidenceReport` (contract sketch)

```
EvidenceReport {
  spec: "analyzer_v3.c1", spec_version, catalogue_sha256, config_sha256,
  input_sha256,                       # of the analysed bytes, for audit
  request: { p.* facts, n_leaves, n_analysed, request_truncated },
  values: [ {                         # one per leaf; full detail for leaves with >= 1 fact
      vid, origin, locator,           # locator: audit only
      g.* facts,
      facts: { "<family>.<name>": bool | int | enum | str, ... }   # only non-default facts
  } ],
  aggregates: {                       # per family f, deterministic
      f: { n_values_with_fact, fact_ids_union, first_vid, max_int_facts{...} }
  },
  coverage: { ... }                   # §2.7
}
```

- No `score`, `attack`, `category`, `confidence`, `severity`, `risk` field exists. Aggregation is
  `count` / `union` / `max` of facts only. The contract validator rejects any such field (as
  D50's validator rejects unknown signals).
- Output is canonical JSON (sorted keys, no floats except through integers), so two runs hash
  identically; the report carries no timestamp and no timing. Latency is telemetry, outside the
  report.
- This **supersedes D46/D50 for v3 only** (v2 stays frozen): v3's contract is an evidence
  vector, with no `attack` + `category`. Needs a decision (note-C §9).
- Payload-bearing data: `values[].facts` carry short enums/strings only (fingerprints,
  scheme, host class), **not** copies of request values, so reports can be logged without
  re-leaking request content (cf. the logging concern in research-notes-v2/README for
  `classifier_api.py`).

### 2.7 Coverage information (always emitted)

| Field | Content |
|---|---|
| `coverage.parse_complete` | every leaf parsed with no anomaly in {`json_invalid`, `multipart_malformed`, `body_unparsed`} |
| `coverage.caps_hit` | which cap(s) hit: leaves, value bytes, depth, layers, request bytes |
| `coverage.values_total / analysed / skipped / truncated` | counts |
| `coverage.decode_incomplete` | number of values with no fixpoint in `max_layers` |
| `coverage.body_type` | declared / sniffed / mismatch |
| `coverage.kinds` | histogram of `g.kind` over leaves |
| `coverage.fact_groups_enabled` | e.g. `ext.libinjection` on/off, `fold.*` on/off |
| `coverage.unsupported` | static list of families C1 cannot see (above) |
| `coverage.catalogue_support` | **offline artefact**, not run-time learning: for each fact the number of golden vectors; flags facts whose catalogue entry has no benign golden vector (so DM knows "never tested against benign") |

Not in v3 C1 **[PROPOSAL, no-over-engineering]**: Anagram-style Bloom-filter n-gram novelty and a
learned structural-support table (note-C §4). They need a training corpus and only matter if the
DM needs them for a DEFER gate. Defer until the DM's own spec asks for them; if added, they are
built once from the separate C2 corpus and shipped as frozen artefacts. Not proposed at all:
Isolation Forest / autoencoder / density models.

### 2.8 Determinism, versioning, tests (C1 acceptance)

| Check | Requirement |
|---|---|
| Purity | same input + `config` + version → identical canonical JSON (property test on random bytes) |
| Bounded work | fuzz on adversarial inputs (nested `%25…`, huge JSON depth, 10^6 repeated names); wall time and memory bounded by caps (no regex with catastrophic backtracking; linear-time matchers only) |
| Decoder properties | idempotent at fixpoint; never expands beyond declared bound; invalid UTF-8 never raises |
| Golden vectors | each fact has ≥ 5 + / ≥ 5 − golden cases from primary documentation |
| Invariance (G1/G2 inherited) | changing `Host`, `User-Agent`, port, `Content-Length`, path, parameter name, or moving a value between query/form/JSON leaf leaves every `g.*` and family fact **identical**; D15 held-out encodings give byte-identical views |
| Differential (optional libinjection) | the Python/ctypes wrapper equals the upstream CLI on the pinned commit for a golden corpus |
| Contract | rejects `score` / `attack` / `category` / `confidence` fields; rejects non-canonical JSON |
| Change control | a catalogue edit bumps `catalogue_sha256`, appends to a change log with the reason and **which data had been looked at** (consumed dev data seen → label "informed by development data") |

### 2.9 Open decisions specific to C1 (owner)

1. **libinjection**: BSD-3, v4.0.0 per its CHANGELOG, built on a tokenizer + folding +
   fingerprint DB over the first ~5 folded tokens, documented gaps and FP on SQL-like prose
   (note-C §1.4, README of the project **[FACT]**, checked in note-C). Third-party mirrors state it
   has false-positive reports and is largely unmaintained, and the OWASP CRS mailing list has FP
   reports on fingerprint `1c` (search result 2026-10-06; first-party maintenance status
   **[UNVERIFIED]**). Default here: **C1 core uses the own-lexer facts above (stdlib-only,
   reproducible)**; libinjection is an *optional* `ext.libinjection` namespace, enabled only after
   (i) D9 / D33 / D52 approve a C dependency or ctypes wrapper and (ii) it shows incremental
   recall over the own-lexer facts on VALIDATION. Pin an exact commit hash if enabled.
2. D9 (no CRS/ModSecurity/Coraza *now*): the fact set is *inspired by* CRS-style detection but
   emits no score/BLOCK, and none of it may BLOCK alone (D29/D43). Needs an explicit statement.
3. Closed lists (§2.5): who owns and reviews them, and their documented source.
4. Max caps (§2.3) and the 64 KiB budget.

### 2.10 C1 evaluation and its data policy

C1 has **zero learned parameters**, so it needs no TRAIN set; it needs a *measurement* set. Use
the same new value-level corpus defined in §3.5 (roles VALIDATION and TEST only for C1; the
TRAIN role exists for C2 and for the "fitted-C1 baseline" of §3.7).

- Measured, per family and per fact: recall on positive values, fact rate on benign values, hard-benign fact rate (the new hard-negative set), per-fact breakdown. These are the numbers that decide whether C2 has any room (§3.7 gate X0).
- C1 facts have no threshold to tune, but the **choice of facts** can be tuned by looking at failures. Therefore: write definitions before looking; evaluate once on VALIDATION; fix only bugs against golden vectors; freeze `catalogue_sha256` **before** C2 is fitted or the TEST role is read; one single TEST read for the C1 baseline (same D54-style discipline used for Analyzer v2).
- Running C1 on #57/#60/V4-clean/External v1 is allowed **only as a labelled diagnostic**, with no definition changes afterwards on the basis of it (or, if changed, the change log marks C1 as "informed by" that data and it cannot claim independence from it).

---

# PART C2 — Optional small per-value ML

## 3. C2 definition and go/no-go

### 3.1 Role and scope

C2 is a **graded, calibrated, per-value, per-family signal** for the cases where grammars do not
enumerate the variants (note-C §2). It is **optional**: it exists in v3 only if it demonstrably
adds over C1 (§3.7). It emits a signal, never a verdict.

**Scope restriction (no-over-engineering) [PROPOSAL]:** C2 heads are trained only for families
whose syntax is open-ended and where C1's grammar is expected to leak: **SQLi, XSS, command
injection, SSTI**. Path/file access, SSRF/redirect, CRLF, XXE and NoSQL have closed grammars that
C1 parses exactly (dot-segments, IP/URL canonicalisation, `$`-operators, `DOCTYPE`), so an ML head
there would replace an exact test with an approximation. **[HYP]** C1 recall in those families
is already adequate; verify with gate X0 and add a head only if X0 fails for that family.

Unit: **one decoded, canonical value** (query/form value, JSON string leaf, multipart part, path
segment). Not the field, not the request (note-C §2 table). The head sees no origin, locator,
field name, endpoint, or envelope, so the v2 shortcuts are structurally impossible (G2).

### 3.2 Candidate representation (R1; inherited from note-C §3)

Per canonical value (`V_sql`-style folded view `V_c2` = decoded, comment-compressed, case-folded;
the same view for every family so heads share one feature vector), signed-hashed into **2^14**
buckets **[PROPOSAL]**:

| Block | Content |
|---|---|
| token-class n-grams (n = 1-3) from the shared lexer (§2.5) | syntax, e.g. `QUOTE_S OP_LOGIC NUM OP_CMP NUM` vs `WORD QUOTE_S WORD` |
| closed-list keyword identities, and keyword x neighbour-class bigrams | separates `select … from …` as SQL from `select your plan` prose |
| char-class n-grams (n = 2-4; letters → `a`, digits → `9`, ASCII punctuation literal, space → `_`) | identifier-robust punctuation context |
| structural counts (≈ 20 dense columns, **of the value only**): log-binned length, class ratios, quote/paren balance, nesting, longest punct run | cheap shape of the value |

Excluded by construction: raw (pre-decode) bytes, percent/encoding statistics, any C1 `g.*` /
`p.*` fact, the origin, parameter name, JSON path, URL host, any envelope. C1 detector facts are
**not** C2 inputs by default (keeps errors less correlated, which is the point of adding C2);
stacking them is a DM question under the same ablation rule as note-C G7.

**Simplicity ablation (R0)**: the simplest possible variant, raw character n-grams (n = 1-4) of
`V_c2` hashed into 2^14 buckets with no lexer. R1 is retained over R0 **only if** it beats R0 by
the pre-declared margin in gate P9 (§3.7). If R0 matches R1, the lexer is dropped from C2 (it
stays in C1 for facts).

Hash function: the Python stdlib has no MurmurHash3 and scikit-learn's `FeatureHasher` uses
signed 32-bit MurmurHash3 (note-C §8). **[PROPOSAL]** Use an own, trivially portable hash
(FNV-1a 32-bit over the feature string, sign from one bit), computed by the project's code in
training **and** runtime, building the CSR matrix directly (not through `FeatureHasher`), with
byte-exact cross-implementation tests. A training-side reverse map `bucket → n-grams` is kept
for interpretation (note-C §3).

### 3.3 Candidate models (the simple one + at most two alternatives)

| | **M1 (default candidate): L1 logistic regression, one head per scoped family** | **M2: linear SVM on the same sparse vector (L2 or L1 penalty)** | **M3: tiny GBDT on a compact dense vector** |
|---|---|---|---|
| Input | R1 (R0 for the ablation), 2^14 hashed + counts | same | ≈ 20 counts + 2^8-2^10 hashed buckets (HGB needs dense input: HistGradientBoosting validates dense `X`, note-C §5 **[FACT]** installed source) |
| Why it is a reasonable candidate | sparse, native to hashed n-grams; L1 yields a small, auditable weight table; precedent for sparse linear weights over WAF evidence (ModSec-Learn, DCAI 2024, arXiv:2406.13547, discards > 30% of CRS rules by sparse regularisation **[FACT, cited from note-C]**) | maximum-margin linear models with TF-IDF-style features were the most robust to train/test distribution shift in a cross-dataset SQLi study (Pejo & Kapui, arXiv:2304.12115: models trained on one source drop sharply on other sources; "TF-IDF and SVM seem more robust" **[FACT, paper read this session]**; 2023, small datasets, SQLi only, so a hypothesis for our setting **[HYP]**) | captures interactions (quote x keyword x balance) a linear model needs n-grams for; v2 showed HGB is stable and calibrated in distribution |
| Output | `P̂` from logit (calibrate: native → sigmoid → isotonic only on robust OOF gain, D55 convention) | margin, **not a probability**: Platt (sigmoid) calibration on a held-out CAL fold (`CalibratedClassifierCV`; scikit-learn docs show LinearSVC is under-confident, sigmoid/isotonic both fix it **[FACT]**) | native probability, calibrate as in M1 |
| Artefact | `(family, bucket) → weight` + bias; ≤ 4 x 2^14 float32 = **256 KiB dense**, far less as a sparse table after L1 **[HYP]** | same size dense; L1-penalised linear SVM (liblinear, `dual=False`) to get sparsity **[UNVERIFIED]** for the installed scikit-learn version, verify before use | 4 heads x ≈ 100 trees x ≤ 31 leaves ≈ 0.5-1 MiB (note-C estimate, to measure) |
| Runtime | stdlib dict/array lookup, **no dependency** (D33 intact) | same as M1 | tree walker or compiled code (Treelite import + TL2cgen C export per note-C §8); not stdlib-trivial |
| Main risk | re-learning generator artefacts from positives rendered like V4; scarcity of benign values; hash collisions hiding meaning | no native probability; extra calibration step; no sparsity unless L1 | re-approaches v2's "counts of shape" view; heavier runtime |
| Complexity rank | 1 (default) | 1 (same artefact) | 2 (extra runtime) |

**Not evaluated, with reason:** random forest (93.6 MB / 180 MiB RSS in v2's run-002, note-C §5);
MLP (excluded by D55); small transformer, byte/char CNN, embeddings (no evidence here that capacity
is the constraint: data and representation are, note-C §3; they would break embedded
portability D10 and add non-reproducible training); Isolation Forest / autoencoder OOD (note-C
§4). **Pooled "any-family" head** is run as a **simplicity baseline** (one head instead of
four): per-family heads are kept only if they add attributable evidence at the DM-relevant
operating point; otherwise a single head plus C1's family facts is simpler.

Selection protocol **[PROPOSAL]**: each of M1, M2, M3 is fitted **once** with a fixed small
hyperparameter grid declared in advance (regularisation C only; `max_depth`/`n_estimators` for M3;
selected on VALIDATION by a fixed rule, e.g. benign-cap recall); a mechanical winner rule
(D54 style) chooses the **simplest** model that passes all gates; M2/M3 beat M1 only if their gain
over M1 on the hard-benign-adjusted metric has a paired-bootstrap lower bound > 0 *and* their
cost is within budget (§3.6). Holm correction over the three models in gate P2. If M1 fails a gate
because of model class rather than data (e.g. misses only interaction cases), that is the only
case in which M3 is considered more than a challenger.

### 3.4 Training labels

- One binary label per (value, family) in the C2 scope. **Positive:** the value was *produced* as
  the injected payload of family f by a documented source (payload provenance), after decoding
  and canonicalisation (e.g. a SQLi string from an SQLi payload list). **Negative for f:** values
  from benign sources and values whose provenance label set does not contain f. Values with
  unknown or multiple provenance labels are excluded from f's negatives and logged.
- Labels are **never** derived from: V4's BLOCK/ALLOW, V4's reason, a V4 or Analyzer v2 score,
  the V4-clean request-level label, or any C1 fact. (v2's error pattern (64/68 of V4's FPs scored
  ≥ 0.5, paired gap median 0.042) came from using V4's label and objective; note-C §0.)
- **Label-noise audit [PROPOSAL]:** a random sample of ≥ 100 positives per family is checked
  manually (or by a second independent parser) for "is this executable syntax of the family in
  isolation?" Positives that are valid only in a specific host context (e.g. a bare `1;` or
  partial tag) are tagged `context_dependent`. Rate reported; if the label-noise estimate exceeds
  a pre-declared bound (e.g. 10%), the labels are redesigned before fitting.
- **Value ambiguity is inherent [HYP]:** a code-editor or "run this script" field legitimately
  carries shell/SQL/HTML. A per-value model cannot know field intent by design. C2 must not try;
  value-kind / schema conditioning is a later DM concern (note-C §2).

### 3.5 Separate-dataset requirements

C2 uses a **new value-level corpus**. It is not Analyzer v2's data and not V4-clean. Requirements
(G0 of note-C §7, made explicit):

| Requirement | Rule |
|---|---|
| Independence from consumed data | No row of V4-clean (train, eval, INTERNAL TEST), External Test v1, #57, #60, minimal-pair probe v1/v2 cases is a C2 row. No V4 request rendering is used. Their texts are not copied; their concepts may be |
| Payload overlap | Compute canonical decoded strings of the **positive payloads of V4-clean and External v1** (read-only, hashes of canonical strings are enough). Any C2 positive whose canonical string equals one of them is **removed from VALIDATION and TEST** and, **by default, from TRAIN** too (owner may allow TRAIN overlap *if the source is demonstrably independent*; overlap counts reported either way) |
| Positive sources | ≥ 2 independent provenance sources per family where licences allow; one canonical payload never spans roles (group = canonical decoded payload); licences **[UNVERIFIED]**, to be assessed with `B_datasets.md` |
| Benign sources | Per `B_datasets.md` headline: GitHub and Stripe OpenAPI structure (MIT) with a value pool from real corpora; Natural Questions-style prose (licence assessment pending); human names, addresses, passwords-like strings, URLs, free text. **open-appsec Legitimate is EVAL-ONLY**, not training (`B_datasets.md`). Benign groups = value-source draw, not a rendered request |
| Hard benign (new) | Built from the **concepts** in the probe v1 and the benign coverage audit: surnames with `'`; addresses and passwords with `#`, `&`, `!`, `;`, `,`; SQL/shell-homonym prose ("select a plan", "union membership"); legitimate external `http`/`https` URLs; encoded paths; markup-like but benign text. Each concept SUPPORTED (≥ 30 groups, D18) **and** present on the attack side too (symmetry rule), so a carrier cannot be learned as the label |
| Roles | TRAIN / VALIDATION / TEST by grouped split (canonical payload for attacks, value-source draw for benign), 0 overlap under canonical string, source group and template, asserted in code (D16 / D54 pattern). TEST is read **once** per frozen candidate set |
| Source-held-out slice | At least one positive source and one benign source kept out entirely from TRAIN ("leave-one-source-out" evaluation, §3.7 P3) |
| Held-out transforms | `bash_ifs`, `param_fragmentation` (D15) and WAF-A-MoLE-style mutations (case swap, whitespace substitution, comment injection, integer encoding; Demetrio et al., SAC 2020, doi:10.1145/3341105.3373962 **[FACT, cited from note-C]**) generate **nothing** used for fitting |
| Size minimums **[PROPOSAL]** | per scoped family: ≥ 1,000 positive groups TRAIN, ≥ 300 VALIDATION, ≥ 300 TEST; benign ≥ 5,000 TRAIN values from ≥ 5 distinct value-source types, ≥ 1,000 benign VALIDATION/TEST groups, ≥ 300 independent hard-benign TEST groups (rule of three: 0 errors in n=300 gives a 95% upper bound of 1%; ≥ 3,000 for 0.1%). With 300 positives a 95% recall interval has half-width ≈ 5.7 pp at p = 0.5 (normal approximation), which is why the material-gain threshold below is ≥ 5 pp on a paired design |
| Insufficient data | If a minimum cannot be met for a family, C2 for that family is **not tested** and C1-only stands (D18 spirit: no claim without support) |

### 3.6 Embedded feasibility and latency target

- **Memory [HYP, to measure]:** M1/M2 artefact ≤ 256 KiB dense (4 heads x 2^14 float32), typically far smaller after L1; lexer tables + closed lists ≈ tens of KiB; no Bloom filters in v3 (§2.7). Total C1+C2 resident footprint estimate < 1 MiB, against run-002's 8.9 MB artefact and +15 MiB RSS for scikit-learn HGB (note-C §8). Proposed budget: **artefact ≤ 512 KiB, RSS increment ≤ 16 MiB** in the runtime that ships (note-C G9).
- **Runtime:** M1/M2 need only a coefficient table read by stdlib code (D33 intact; no scikit-learn in the data plane). M3 would need a tree walker or compiled code. Where it runs (data plane vs control plane) is decided after measurement (D52).
- **Latency target [PROPOSAL]:** C1 + C2 together ≤ **1 ms P95 per typical request** (≤ 16 values, ≤ 1 KiB analysed) in the runtime that ships; **C2 increment ≤ 0.3 ms P95**; worst case at the caps ≤ 10 ms. Context: the architecture target is P95 ≤ 200 ms for the whole pipeline (D36; 269.58 ms today, dominated by the LLM, not met), so the Analyzer must stay a rounding error. A Python reference implementation need not hit these but must be measured; if pure-Python C1+C2 exceeds 5 ms typical, the compiled path becomes a decision. Platform for the measurement is TBD (D10); the figures are only meaningful on the target-class CPU.
- Work is linear in total value length; no matrix product beyond a sparse dot product **[HYP]** (v2's latency was scikit-learn per-call overhead, not tree arithmetic, note-C §8).

### 3.7 Evaluation GATES: C2 is adopted only if all pass

All gates are pre-registered **before any C2 fit**, evaluated on VALIDATION for model selection
and on TEST **once**; never on External Test v1 (D53/D45); any external claim needs External v2
(D40).

**Baselines (so that "beats C1" is not a straw man).**
- **B0 = C1 raw**: per family, flag = OR of the family's *designated structural facts* (list fixed
  with the catalogue, not tuned).
- **B1 = C1-fitted**: the same simplest learner (L2 logistic on the C1 fact vector, no n-grams)
  fitted on TRAIN. This is the honest competitor: it captures "what a learner can do with C1's
  own evidence".
- **C2 candidate = B1 + C2 score** *and* **C2 alone** (stack and standalone are both reported;
  the gate uses the stack for increment, standalone for independence).
- All compared at the **same operating point**: the frozen benign cap (recall at benign-group FPR
  = 1%, needs ≥ 300 benign groups; higher precision caps need more).

| Gate | Requirement (all proposals) | If it fails |
|---|---|---|
| **X0. Headroom (no-training exit)** | On VALIDATION, per scoped family, C1 (B1) recall at the benign cap is **< 95%** (so the maximum possible gain ≥ 5 pp) **and** ≥ 30 positive groups are missed by C1. Otherwise no C2 head for that family | C1-only for that family, **no fitting performed** |
| **P0. Data prerequisites** | §3.5 minimums met; independence asserted in code; label-noise audit within bound | C2 untestable → C1-only |
| **P1. C1 frozen first** | `catalogue_sha256` frozen and C1 baseline measured before any C2 fit; B1 fitted by the same protocol | invalid experiment |
| **P2. Material increment over C1** | Paired group-bootstrap 95% CI of (C2 stack − B1) recall gain at the benign cap: **lower bound > 0 *and* point gain ≥ 5 pp**, per adopted family, on VALIDATION, confirmed on TEST once; Holm across M1/M2/M3 | C1-only |
| **P3. Source-held-out transfer** | The gain of P2 holds (lower bound > 0 or, with few sources, point estimate > 0 in every held-out source) when a whole positive source and a whole benign source are excluded from TRAIN. Reason: ML SQLi detectors collapse across data sources (Pejo & Kapui, arXiv:2304.12115) | C1-only |
| **P4. Hard benign not worse** | On the hard-benign TEST set, C2 stack flags **no more** benign groups than B1 at the same attack recall; per-concept (apostrophe, `#`, `&`/`!`/`;`, SQL-homonym prose, external `http` URL, encoded path) flag rate not higher than B1, and each concept's upper bound reported (n ≥ 30) | C1-only |
| **P5. Invariance (exact)** | G1/G2 of note-C: D15 held-out encodings give byte-identical features on 100% of VALIDATION values; envelope/field-name/path/position changes leave every C2 score **identical** (by construction, tested); mutation slice: per-family recall at the cap drops ≤ 5 pp vs unmutated | C1-only |
| **P6. Shortcut audit** | (a) top-50 coefficients (M1/M2) or permutation importances (M3), reverse-mapped to n-grams, contain no generator constant or source-specific string; (b) ablation: dropping the structural-count block removes ≤ a pre-declared fraction (e.g. 30%) of C2's gain; (c) **source-identifiability probe:** a tiny LR trained to predict *source id* from C2 features within positives (and within benign) is not much above chance after controlling the label **[HYP]** (informative, not proof); (d) no raw-encoding, path, parameter-name or header feature in code (test, like D44's) | C1-only |
| **P7. Complementarity with V4 (later V5)** | On the new development data, with V4 decisions obtained by inference on rendered new values (new dev run): C2 flags **< 50%** of V4's false-positive benign groups; double-fault rate and Yule's Q vs V4 reported (Kuncheva & Whitaker, Machine Learning 2003, cited from note-C) | C1-only |
| **P8. Calibration and stability** | Native → sigmoid → isotonic only on robust OOF Brier gain without worse log loss (D55); reliability per family; "uncalibrated" allowed. Stability: refit on 5 bootstrap resamples of TRAIN groups with fixed seeds keeps the P2 sign and ≥ 60% overlap of non-zero coefficients (M1) **[PROPOSAL]**; deterministic refit from the same seed gives identical weights | C1-only |
| **P9. Simplicity** | R1 beats R0 (raw char n-grams, no lexer) by ≥ 2 pp of P2 gain, else the lexer is dropped from C2; per-family heads beat the pooled head on family attribution at the cap, else use the pooled head; M3 / M2 replace M1 only per §3.3 | simplify, or C1-only |
| **P10. Runtime parity and budget** | Exported runtime equals the Python reference on 100% of VALIDATION values (|Δp| ≤ 1e-6, identical bucket indices, byte-exact hash tests); budgets of §3.6 met; caps of §2.3 enforced | C1-only (or fix, once) |

**Adoption rule (mechanical):** C2 is adopted for exactly those families that pass X0 and P0-P10,
with the simplest passing model/representation. **Any single failure → C1-only for that family.**
There is no "adopt with a caveat".

### 3.8 The C1-only gate (explicit)

**C1-only is the answer — and nothing is fitted — whenever any one of these holds:**
1. X0: C1 (fitted B1) already catches ≥ 95% of the positive groups at the benign cap in every
   scoped family (headroom < 5 pp);
2. data minimums (§3.5) cannot be met, or independence from consumed data cannot be demonstrated;
3. the paired increment of C2 over B1 at the benign cap has a 95% lower bound ≤ 0, or a point gain
   < 5 pp;
4. the gain disappears under source-held-out evaluation (P3) or the hard-benign set (P4);
5. any of P5-P10 fails.

In every one of these cases the Analyzer v3 deliverable is C1 (+ the DM weighting its facts), and
the C2 code, corpus builder and registered protocol are archived as a documented negative result.
**A negative C2 result is a valid outcome and is not an incentive to change the gates.**

### 3.9 C2 output (if adopted)

Added to each value's record: `c2.<family> ∈ [0, 1]` = `P̂(value has executable syntax of family f | canonical value)` (calibrated per P8), `c2.version`, `c2.applicable` (false for values that are truncated, invalid-UTF-8, or `g.kind` empty/numeric/uuid, where the model is out of its input domain). Aggregates: per family `max` over values and the `vid` that attains it. **No verdict, no category, no global confidence.**

---

## 4. Recommended default and decisions needed

### 4.1 Recommended default: **C1-only for v3, C2 as a gated experiment**

Reasons from current evidence:

1. **[FACT]** Analyzer v2's failure was representation + objective, not capacity (note-C §0;
   64/68 V4 FP agreement; paired gap median 0.042). A deterministic, decoded, per-value evidence
   engine fixes the identified mechanisms **without any data we do not yet have**.
2. **[FACT]** The three STRONG V4 content failure concepts (apostrophe, `#`, `http` scheme) are
   *human-syntax* look-alikes. Whether any ML on a value can separate them depends on benign
   data that does not exist yet in the project (audit: 0 JSON objects with ≥ 2 keys; benign
   values lack ordinary punctuation); C2 without it risks re-learning shortcuts.
3. **[HYP]** C1's structural-conjunction facts already separate most of these cases (`'` alone,
   `#` alone, `http` alone do not fire a structural fact), so the remaining headroom for C2 may
   be < 5 pp (X0). This is testable in one cheap C1 measurement before any C2 data is built.
4. **[FACT]** Cross-source brittleness of ML SQLi detectors is documented (Pejo & Kapui) and was
   directly observed here in External v1 (ECE 0.126 vs 0.024 internally, aggregate only).
5. C1 is stdlib-only, ≈ zero model memory, reproducible, auditable (D10, D33).

So: **build C1 first and freeze it. Decide C2 only after the X0 measurement.** If X0 shows
headroom and the corpus (§3.5) can be built with independence, run the pre-registered C2
experiment once; otherwise C1-only. **No evidence today supports "C1 + C2"**, so the default
recommendation is **C1-only**.

### 4.2 Owner decisions needed (none taken here)

1. Supersede D46/D50 for v3: evidence-vector contract, no `attack`/`category` (note-C §9).
2. D9 clarification: closed-list, CRS-inspired detectors as *evidence only*; libinjection allowed
   as optional dependency or not (D33/D52).
3. Fact catalogue ownership, closed-list sources, caps (§2.3), 64 KiB budget.
4. Authorise building the new value-level corpus and its overlap rule against V4-clean / External
   v1 payloads (default: remove from VAL/TEST/TRAIN, §3.5).
5. Pre-register the gates (§3.7), including the 5 pp materiality and 95% headroom exit.
6. Hashing: own FNV-1a vs MurmurHash3 reimplementation (§3.2); decide before P10.
7. Whether D44 stays (framing/headers outside v3) given the V4 `Transfer-Encoding: chunked`
   sensitivity (probe v1: 18/33 flips): that is a V4/data-plane issue, not solvable by the
   per-value Analyzer.

### 4.3 FACT / HYPOTHESIS ledger

| Statement | Status |
|---|---|
| v2 shortcut features (`percent_encoded_ratio`, `percent_count`, `path_length`), 64/68 V4-FP agreement, paired gap 0.042, External v1 ECE 0.126 | **[FACT]** (note-C, from run-002 and the published aggregates) |
| V4 flips: `'` 30/30, `#` 19/30, `http` 18/30, TE chunked 18/33; ports, IP Host, `Content-Length`: 0-1 | **[FACT]** (probe v1 §2.2, a V4 property) |
| mitmproxy 12.2.3 de-chunks and decodes gzip before `render_request` | **[FACT]** (note F) |
| ML SQLi models degrade across data sources; TF-IDF + SVM more robust | **[FACT]** for the cited study (arXiv 2304.12115); transfer to our setting **[HYP]** |
| sklearn LinearSVC is under-confident; sigmoid/isotonic calibration fixes it | **[FACT]** (scikit-learn calibration docs) |
| libinjection is a signal not a verdict; FP/maintenance concerns | **[FACT]** upstream README (via note-C); maintenance status **[UNVERIFIED]** first-party |
| C1 structural facts leave < 5 pp headroom for C2 | **[HYP]**, test via X0 |
| Per-value C2 adds recall over C1 without re-learning generator artefacts | **[HYP]**, no evidence yet |
| Latency and memory numbers for C1/C2 | **[HYP]**, to be measured on the D10 target-class CPU |
| L1 `LinearSVC(penalty='l1', dual=False)` availability/behaviour in the installed sklearn | **[UNVERIFIED]** |
| Exact ModSecurity `cmdLine` semantics for `V_shell` | **[UNVERIFIED]** |
| Licences of PayloadsAllTheThings-derived and other payload sources | **[UNVERIFIED]** |

## Sources

- note-C: `reports/v5/research-notes-v2/C_analyzer_v3.md` (and its source list; items cited from it are marked "cited from note-C").
- Pejo & Kapui, *SQLi Detection with ML: A Data-Source Perspective*, arXiv:2304.12115 (SCITEPRESS 2023), <https://ar5iv.labs.arxiv.org/html/2304.12115> (read 2026-10-06).
- scikit-learn, *Probability calibration* / `CalibratedClassifierCV` and calibration-curve example, <https://scikit-learn.org/stable/auto_examples/calibration/plot_calibration_curve.html> (search 2026-10-06).
- libinjection, <https://github.com/libinjection/libinjection> (via note-C); third-party mirror/CRS mailing-list FP report (search 2026-10-06, secondary): <https://groups.google.com/a/owasp.org/g/modsecurity-core-rule-set-project/c/wPdKUBZOrkM/m/qcLPgAbQBgAJ>.
- `reports/v5/minimal-pair-probe-v1/README.md` (V4 probe figures); `DECISIONS.md` D9, D10, D15, D16, D18, D29, D33, D36, D40, D43-D55.
- WAFFLED (arXiv:2503.10846), WAF-A-MoLE (doi:10.1145/3341105.3373962), ModSec-Learn (arXiv:2406.13547), Kuncheva & Whitaker 2003: cited from note-C, not re-verified.
