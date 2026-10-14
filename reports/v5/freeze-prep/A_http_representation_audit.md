# A — HTTP architecture and canonical representation audit (issue #64, Workstream A)

> **Dated note (2026-10-12).** Superseded where it differs by **D56/D57** and V5 DRAFT r3 §5. In particular the model text carries **only `Content-Type`**; the 4-header allowlist (A1) in §7 is not adopted. This audit is kept unchanged as historical evidence.


Date: 2026-10-11. Scope: how a request becomes the text V4 scores at serving time and at training
time, what differs, what the backend actually interprets, and a PROPOSED single canonical-input
contract for V5. Read-only audit of the repository plus one characterization test file.
Nothing was trained, no model or gateway was run, no existing file was modified.

Labels used throughout: **FACT** (verified in code, tests or a stored report; cited `file:line`),
**INFERENCE** (follows from facts, not directly verified), **PROPOSAL** (design for the owner; not a
decision). Counts marked *(train.jsonl)* were computed by me over `datasets/v4_clean/train.jsonl`
(25,134 rows, 12,567 ALLOW / 12,567 BLOCK) with a throwaway script outside the repo; they are
aggregates, not cases. External Test v1 data was not opened.

## 0. Top findings

1. **Serving and training use two independent renderers with the same layout but different
   distributions.** Serving: `data_plane.py:102-126`. Training: `parse_dataset_v4.py:770-881`.
   The existing round-trip test checks layout only (`tests/test_data_plane.py:434-454`).
2. **Framing is the largest structural skew.** In training, `Content-Length` appears in 9 of 25,134
   rows (0.07% of 13,686 body rows) and `Transfer-Encoding` in 5 rows, all BLOCK *(train.jsonl)*.
   A real client sends one of the two on essentially every body request (INFERENCE from note F).
   V4 is insensitive to a correct `Content-Length` (1/33 flips) but flips on
   `Transfer-Encoding: chunked` (18/33) (`reports/v5/minimal-pair-probe-v1/README.md:99-100`).
3. **All six smuggling variants V4 trains on cannot reach V4 through the gateway** with mitmproxy's
   default `validate_inbound_headers=true` (each is a TE+CL, duplicate-CL, duplicate-TE or
   space-before-colon form that mitmproxy answers with 400 before the addon; note G rows 1, 2, 8, 16,
   18). The category is learned from text the serving path never produces (the mapping of variants to
   rows is my INFERENCE; the per-category rejections are FACT).
4. **Percent-encoding layers are label-correlated in training.** A second layer (`%25XX`) occurs in
   3,473 BLOCK rows and 0 ALLOW rows; escapes with a lowercase hex digit occur in 137 BLOCK rows and
   0 ALLOW *(train.jsonl)*. Cause: `quote(payload, safe="")` re-encodes payloads that already contain
   `%XX` (`parse_dataset_v4.py:757-763, 873, 875`; sources at `:578-595`).
5. **JSON-typed training bodies are mostly not JSON.** 661 of the 764 ALLOW rows with
   `Content-Type: application/json` carry a `name=value` body (`parse_dataset_v4.py:853-865`: the
   benign branch writes a form-style body whatever content type was drawn); only 103 ALLOW rows hold
   valid JSON, all single-key *(train.jsonl)*. This is a plausible mechanism for the JSON-carrier
   instability in evidence-matrix rows #9/#10 (INFERENCE).
6. **Non-UTF-8 bytes are handled inconsistently at serving.** Body bytes become U+FFFD; bytes in the
   target or a header become lone surrogates, `httpx` then cannot serialize the JSON, and the addon's
   catch-all blocks with 503 without ever asking V4 (pinned by test; live delivery of such bytes by
   mitmproxy not tested).
7. **D1 vs the draft's "resolve framing out of the ML text" is a real but resolvable tension** (§5):
   the clause being superseded is only "preserve Content-Length/Transfer-Encoding in the ML text";
   the safety intent of D1 is better met by the deterministic validator that already exists in
   mitmproxy and that the repo does not pin.
8. **Recommendation:** option C in its minimal form (header allowlist, no framing/hop-by-hop headers,
   body = de-chunked + content-decoded, one shared `canonicalize()` used by generator and gateway),
   with deterministic reject paths instead of silent truncation or replacement (§7).

## 1. Facts: how a request becomes the V4 text at serving time

Path: mitmproxy `request` hook -> `FirewallGateway.enforce` -> `render_request(req)` (once)
-> `POST /classify {"request": text}` -> `build_prompt` -> tokenizer -> generate.

| # | Fact | Evidence |
|---|------|----------|
| S1 | Request line is `{method} {request.path} {request.http_version}`. `path` is mitmproxy's origin-form target including the query, as received. Version string is verbatim (`HTTP/1.0`, `HTTP/2.0` would appear). Method is upper-cased by mitmproxy. | `data_plane.py:117`; pinned by new tests `test_http_version_is_rendered_verbatim`, `test_method_is_uppercased_by_mitmproxy` |
| S2 | Headers: every header, in received order, original name case, repeats kept, one `Name: value` line each, joined by `\n`. No allowlist, no denylist, no normalization. `Host`, `User-Agent`, `Content-Length`, `Transfer-Encoding`, `Connection`, `Proxy-Connection`, `Cookie` are all rendered. | `data_plane.py:118-119`; `tests/test_data_plane.py:426-432`; new test `test_framing_and_hop_by_hop_headers_are_not_filtered` |
| S3 | Headers mitmproxy changes before the hook: `Expect: 100-continue` is removed; value whitespace is stripped by the parser; obs-fold stays inside one value as `CRLF + SP`; a lone CR survives. | `F_mitmproxy_dechunking.md` §2, §5; `G_...` rows 4b, 15b, 15c; new test `test_obs_fold_and_lone_cr_survive_into_one_rendered_header` |
| S4 | Body: `request.get_content(strict=False)` (not `.raw_content`). It undoes `Content-Encoding`, falls back to the raw bytes if decoding fails, and never touches headers. Chunked bodies are already de-chunked by mitmproxy, `Transfer-Encoding: chunked` stays and no `Content-Length` is added. A body with neither framing header is read as empty. | `data_plane.py:120-123`; `F_...` §2; `G_...` row 13; new tests `test_chunked_keeps_its_header_and_adds_no_content_length`, `test_undecodable_or_unknown_content_encoding_leaves_the_body_as_is` |
| S5 | Body text = `body.decode("utf-8", errors="replace")`. Content-Type `charset` is ignored; invalid bytes collapse to U+FFFD (not injective); BOM is kept. A body exists in the text iff it is non-empty after decoding, then separated by exactly one blank line (`\n\n`). A body of `\n` renders as `...\n\n\n`. | `data_plane.py:124-125`; new tests `test_body_bytes_are_decoded_as_utf8_with_replacement`, `test_utf8_bom_and_whitespace_only_bodies_are_kept` |
| S6 | Path, query and header values are not decoded or re-encoded: one visible layer exactly as the client sent it (`%2527` stays `%2527`, `+` stays `+`, hex case kept). | `data_plane.py:117`; new test `test_percent_encoding_is_neither_decoded_nor_normalized` |
| S7 | Form and JSON are not treated differently by the renderer: the body is the decoded bytes verbatim (spacing, escapes, key order). Content-type-specific handling exists only in the shadow extractor, which reads the rendered text. | `data_plane.py:123-125`; `request_features.py:112-132`; new test `test_json_body_is_kept_verbatim_including_escapes_and_spacing` |
| S8 | The text carries no scheme and no port (only the `Host` header as sent). | new test `test_scheme_and_port_are_not_part_of_the_text` |
| S9 | No size limit anywhere on the path: no truncation in the renderer, none in `ClassifyRequest` (only `min_length=1`), none in the tokenizer call (`tok(prompt, return_tensors="pt")`, no `truncation`/`max_length`); the repo sets no `body_size_limit`/`stream_large_bodies`. Tokenizer `model_max_length` is 2048. | `data_plane.py:123-125`; `classifier_api.py:82`; `inference_core.py:186`; `model-output-v4-clean/tokenizer_config.json`; `F_...` §2 last bullet; new test `test_there_is_no_size_limit_in_the_renderer` |
| S10 | Non-UTF-8 in the target or a header: mitmproxy's str view uses surrogateescape, so the text holds lone surrogates; `httpx` JSON encoding raises `UnicodeEncodeError`; that is not an `httpx.HTTPError`, so it reaches `request()`'s catch-all and the request is answered 503 "classifier unavailable" with the classifier never called. (Constructed requests only; whether mitmproxy's wire parser admits such bytes was not tested.) | `data_plane.py:147-151, 235-239`; new tests `test_non_utf8_path_and_header_bytes_become_lone_surrogates`, `test_non_utf8_target_is_blocked_with_503_and_never_classified` |
| S11 | `render_request` is the only serving renderer: the External v1 capture addon imports it (object identity is tested), so every capture and probe used this exact function. | `scripts/external/capture_addon.py:17-22` |
| S12 | Prompt: `<|system|>\n{INSTRUCTION}</s>\n<|user|>\n{text}</s>\n<|assistant|>\n`; text is placed verbatim (`</s>` or `<|assistant|>` inside a body is not escaped). | `inference_core.py:69-78` |
| S13 | Hybrid shadow extractor parses the same text: `partition("\n\n")`, `split("\n")`, first `Content-Type` line only; so the text grammar is load-bearing for Phase 1 features. | `request_features.py:112-118, 186-193` |

## 2. Facts: how the training text is rendered

| # | Fact | Evidence |
|---|------|----------|
| T1 | Envelope: one generator for both classes. Fixed presence-probabilities and a **fixed header order**: Host, User-Agent, Accept, Accept-Language, Accept-Encoding, Connection, X-Requested-With, Cookie, then shape headers (Authorization, Origin, Referer, framing headers), then Content-Type. The docstring says order is randomised; the code randomises presence only (3 of 25,134 rows deviate from the fixed order *(train.jsonl)*). | `parse_dataset_v4.py:216-243` (docstring `:217-220`), `:785-817`; new test `test_envelope_header_order_is_fixed_not_randomised` |
| T2 | Header set is closed: the envelope never emits Content-Length, Transfer-Encoding, Proxy-Connection, Keep-Alive, Expect, Upgrade, TE or Content-Encoding. `Host` is the first header in 100% of rows, drawn from 32 hosts; User-Agent absent in ~14%. | `parse_dataset_v4.py:151-189, 216-243`; new test `test_envelope_never_contains_framing_or_hop_by_hop_extras` |
| T3 | Request line is always `METHOD target HTTP/1.1`; asserted as an invariant on every row. Methods: GET/HEAD/DELETE/POST/PUT/PATCH only. | `parse_dataset_v4.py:877, 1414-1418, 257-258` |
| T4 | `Content-Length` exists only in the `framing_headers` shape (benign counterpart: exact `str(len(payload))` before Content-Type) and in hard-coded smuggling variants (wrong or duplicated by design). `Transfer-Encoding` exists only in smuggling variants. | `parse_dataset_v4.py:812-833, 625-632`; new tests `test_content_length_appears_only_in_the_framing_shape`, `test_transfer_encoding_is_never_rendered_for_benign_requests`, `test_benign_framing_counterpart_has_an_exact_content_length_before_content_type` |
| T5 | Smuggling rows contain literal CR and LF characters in the body (`0\r\n\r\nSMUGGLED`) and odd header bytes (`Transfer-Encoding ` with trailing space, `\tchunked`). Counts *(train.jsonl)*: 5 rows with a TE header line (all BLOCK), 9 with a CL header line (3 ALLOW benign framing, 6 BLOCK), 5 rows containing CR. | `parse_dataset_v4.py:625-632, 648-652`; new tests `test_smuggling_rows_carry_literal_crlf_and_conflicting_framing_in_the_text`, `test_obfuscated_te_variants_render_the_odd_bytes_verbatim` |
| T6 | Query/target encoding: the attack payload is placed with `quote(v, safe="")` (every reserved char incl. `'` `#` `!` becomes `%XX`, space becomes `%20`, uppercase hex). Form bodies use the same `quote`; HPP uses `quote`. Payloads already containing `%XX` get a second layer. | `parse_dataset_v4.py:112, 757-763, 806, 821, 857, 873, 875`; new tests `test_attack_payload_is_percent_encoded_exactly_once_in_the_query`, `test_payload_that_is_already_encoded_gets_a_second_layer`, `test_form_body_is_quote_encoded_with_percent20_never_plus` |
| T7 | JSON: attack bodies use `json.dumps` defaults (`", "`/`": "`, `ensure_ascii=True`, single line); only 6 valid JSON rows have two keys, none has more. Benign bodies in JSON-capable shapes may be `name=value` under `Content-Type: application/json`. | `parse_dataset_v4.py:841-846, 859-860, 870-871`; new tests `test_json_attack_body_uses_python_default_separators`, `test_benign_form_style_body_can_be_labelled_application_json` |
| T8 | CSIC rows are re-rendered under the same envelope with their original query/body strings (`+` and `%XX` as in the source, Content-Type always form). | `parse_dataset_v4.py:1106-1122` |
| T9 | Training sequences: `<|system|>...<|user|>{input}</s>...{output}</s>`, `max_length=512` tokens (TRL truncates). Longest training text is 975 characters, p99 596 *(train.jsonl)*; token length not measured (tokenizer not run). | `scripts/training/finetune.py:128, 203-210, 261` |
| T10 | `canonical_key` is a **grouping** key (D16), not a model input: up to 3 `unquote_plus` passes, `<`/HTML-entity/`/**/`/`${IFS}` removal, whitespace collapse, lower-casing. Its decoding depth (3) is a property of grouping only. | `parse_dataset_v4.py:659-681`; new `TestCanonicalKeyIsAGroupingKeyNotAModelInput` |

## 3. Train-vs-serve differences (each a FACT unless marked)

| ID | Dimension | Training (V4 data) | Serving (gateway) | Consequence |
|----|-----------|--------------------|-------------------|-------------|
| X1 | `Content-Length` | 9/25,134 rows; exact only on the 3 benign framing rows (`:827-833`) | present on nearly every client body request (INFERENCE, note F §5) | skew; empirically no V4 effect when correct (1/33) |
| X2 | `Transfer-Encoding` | 5 rows, all BLOCK, always paired with CL/duplicates (`:625-632`) | `chunked` with de-chunked body and no CL on any valid chunked client (F §5) | V4 flips benign->BLOCK, 18/33 (probe v1); matrix #7 |
| X3 | CL accuracy | value = `len(str)` characters (`:831`), or deliberately wrong | value = mitmproxy-read length; for gzip bodies it counts compressed bytes while the text shows the decoded body (F §4c) | text/header disagree by construction at serving only |
| X4 | Header set / hop-by-hop | closed 8-name envelope + shape headers (T2) | arbitrary: `Proxy-Connection`, `Keep-Alive`, `Upgrade`, `TE`, `Accept-*`, `X-Forwarded-*`, `Sec-*`, `Referer`, ... | unseen headers are in-prompt noise; effect of most is untested (v1: `Proxy-Connection` 0 flips) |
| X5 | Header order | fixed (T1) | client-defined, e.g. curl `Content-Length` before `Content-Type` and `Proxy-Connection` after `Accept` (F §4g) | order is a fixed function of the set in training |
| X6 | Header name case / spacing | canonical case, one `": "` | client case, repeated headers, raw value whitespace | unmodelled variation |
| X7 | `Host` / `User-Agent` | `Host` always first from a 32-host pool; UA absent in ~14% | actual deployment values (loopback/IP/port variants) | D1 kept them with shared distributions; D44 excludes them from features; real-http-fp-v1 showed V4 sensitive to a loopback Host |
| X8 | Percent-encoding layers | `%25XX`: 3,473 BLOCK / 0 ALLOW; lowercase-hex escapes: 137 BLOCK / 0 ALLOW; any `%XX`: 89.8% of BLOCK vs 25.9% of ALLOW *(train.jsonl)* | one layer as sent by the client | the encoding itself is a class signal in training (matrix #6) |
| X9 | `'`, `#`, `!` representation | `%27` in 2,525 BLOCK vs 19 ALLOW rows *(train.jsonl)*; benign values pass through `quote` so they would be encoded too but are rare | clients encode legitimate punctuation routinely | the evidence-matrix over-block |
| X10 | Space encoding | `%20` in synthetic rows; `+` appears only through CSIC source strings (2,615 ALLOW / 2,453 BLOCK rows contain `+`) | form clients use `+`, URL clients `%20` | two conventions mixed, source-coupled |
| X11 | Body typing | 661/764 JSON-typed ALLOW bodies are not JSON (T7) | body matches its Content-Type, typically compact JSON (`{"a":1}`) | JSON carrier effectively unseen: valid benign JSON = 103 rows, 1 key |
| X12 | JSON formatting | `json.dumps` defaults (`": "` spaced), ASCII-escaped | compact or pretty, UTF-8 raw | whitespace/escape style differs (INFERENCE on clients) |
| X13 | Body decoding | strings (no bytes involved); no gzip, no charset variation | `get_content` decode, `utf-8`/`replace` (S4, S5) | `Content-Encoding` present in training: 0 rows (header absent from T2); serving can show `Content-Encoding: gzip` over a decoded body |
| X14 | Non-UTF-8 | cannot occur (control chars rejected at `:503-505`, strings) | U+FFFD in body, surrogates -> 503 in target/headers (S5, S10) | undefined behaviour region |
| X15 | Request line | `HTTP/1.1` only (T3) | verbatim version (S1) | unseen versions possible |
| X16 | Size | max 975 chars, trained at 512 tokens (T9) | unbounded (S9) | long bodies are out of distribution and unbounded latency/context risk |
| X17 | Origin/Referer | 66 rows; CSRF cross-origin pair is the causal case (`:790-799`) | browsers send `Origin`/`Referer` on most state changes | covered by D1; kept in proposal |
| X18 | `Expect: 100-continue` | absent | stripped by mitmproxy before the hook (S3) | no skew (listed for completeness) |
| X19 | Two renderers | `parse_dataset_v4.render_request` | `data_plane.render_request` | no shared function; parity is tested only text -> request -> text over `eval.jsonl` (skipped when the split is absent) |

## 4. Gateway-observed representation vs what the backend interprets

All FACT from notes F and G (mitmproxy 12.2.3, regular proxy mode, defaults); I did not re-run mitmproxy.

1. mitmproxy **terminates and re-serializes** HTTP/1.1: the client side parses into an object, the
   server side rebuilds the upstream request from it (G §0.1). The backend never sees the client's bytes.
2. Chunked: the classifier sees de-chunked content + `Transfer-Encoding: chunked`; the backend receives
   the body re-chunked (F §4 a,d,h). Content is consistent, the header is redundant to the classifier.
3. `Content-Encoding: gzip`: classifier sees decoded text under the compressed `Content-Length`;
   the backend receives the gzip bytes and decodes them itself (F §4c). Content consistent; length not.
4. **`Transfer-Encoding: gzip, chunked`**: mitmproxy decodes `Content-Encoding` only, so the text holds
   still-compressed bytes while a backend that honours TE decompresses (G row 5). Real divergence.
5. Lost before the hook (not visible to any classifier): CL padding, outer TE whitespace, chunk
   extensions, chunk sizes/boundaries, line endings, bytes after the framed body (G rows 4b, 7, 11,
   13, 15a, 17b). A clean text does not prove clean wire framing.
6. Kept and divergent-prone: obs-fold inside a value, lone CR in a value (G rows 15b, 15c). The rendered
   text embeds `CRLF`/`CR` inside one "line" while the upstream re-emits them.
7. Rejected before the hook with mitmproxy's 400/close page, never classified: duplicate or invalid
   CL, TE+CL, multiple TE, TE on HTTP/1.0, non-final `chunked`, whitespace before the colon, malformed
   chunks, trailers, short bodies (G rows 1-4a, 6, 8-10, 12, 16-18). This is the **only framing
   validator in the system**. It is mitmproxy's, gated by the default `validate_inbound_headers=true`;
   the repo neither sets nor tests that option (G §0.3: disabling it lets several of these reach the addon).
8. Encodings of the target are not interpreted by the gateway at all: the classifier and the backend
   each apply their own percent-decoding (one layer, two layers, `+` handling), so "what the backend
   interprets" for query/form values is application-specific (INFERENCE; no experiment here).
9. Residual risk common to every option (H §7): a front-end classifier does not remove desync risk
   unless the forwarded message is the normalized one. Today the forwarded message is mitmproxy's
   re-serialization of the parsed request, with headers as parsed, not the canonical text.

## 5. Evaluation of the draft's options and the D1 tension

**What D1 says** (`DECISIONS.md:24-53`): headers are not stripped; the regenerated dataset must preserve
headers that can carry security meaning, "including cases such as `Origin`/`Referer` and
`Content-Length`/`Transfer-Encoding`"; neutral metadata (Host, UA, cookies) must be drawn from shared
distributions. **Rationale given**: stripping all headers would remove the causal headers for CSRF and
smuggling. **D44** (`DECISIONS.md:1683-1710`) excludes Host/UA from features and explicitly leaves the
V4/V5 `/classify` text under D1.

**What the draft proposes** (`v5-data-spec-draft/README.md` §5): resolve `Transfer-Encoding`, `Content-Length`,
conflicts, duplicate/invalid CL, extensions/trailers, `Expect` and hop-by-hop headers out of the ML text
into a structured audit record; keep application headers "V4 already sees (Host/User-Agent/Accept/Content-Type)".

**Precise tension.**
- Literal conflict: D1's "preserve Content-Length/Transfer-Encoding" vs "remove them from the ML text".
  Only that sentence conflicts. "Origin/Referer" is untouched, and "headers will not be stripped" is
  violated only in the sense of an allowlist.
- D1's justification is that framing headers are *causal* for smuggling. At serving that causality can
  no longer be presented to the model: every conflicting-framing form is rejected by mitmproxy first
  (§4.7, top finding 3), and every framing that survives is valid and carries no attack information
  (valid CL equals the body length; valid chunked is a transport detail). So the preserved header is
  either unreachable (the attack form) or information-free (the valid form), while its presence/absence
  in training is a measured skew (X1-X3). D1's goal (do not blind the model to causal structure) is
  preserved better by the deterministic validator than by the text.
- Second, separate tension inside the draft: it lists Host/UA among the canonical ML headers while
  D44 treats them as identity leakage. D44 does not forbid it for V5 text, but the draft should not
  silently keep the F1 shortcut risk. This is Pending decision 2.
- Evidence that CL in the text is *harmless* to V4 (1/33 flips) argues for "no urgency", not for keeping
  it; evidence that TE is harmful (18/33) argues for removal or coverage.

**Options.**

| Option | ML input | Pros | Cons / what must hold |
|--------|----------|------|----------------------|
| A: framing as text | raw as today | no change | no source supports it (H §7); keeps X1-X3; **rejected** |
| B: validate + remove framing; ML sees what it sees today minus framing | request line + all other headers + body | smallest delta from V4 text; keeps Host/UA/Accept noise; keeps header-set skew X4-X6 | leaves the unbounded header population as ML noise; not idempotent on header set |
| C: validate + ML sees a canonical request | fixed grammar, allowlisted headers, decoded body | removes X1-X6 by construction; one shared function; injective-ish text; supports invariance tests | needs an owner decision on the allowlist; a canonical text is a *view*, not what is forwarded (§4.9) |
| C2: C but emit synthetic `Content-Length: <decoded length>` (RFC 9112 §7.1.3 canonical form) | C + CL | keeps D1's letter; removes the chunked/gzip disagreement | CL is a deterministic function of the body: zero information, more tokens, a new generator-consistency burden |

**Recommendation: C (minimal).** C2 only if the owner wants D1's wording to stay literally true.

## 6. Deterministic validation vs ML

| Concern | Owner | Why |
|---------|-------|-----|
| TE+CL conflict, duplicate/invalid/non-numeric CL, CL != raw body length, multiple TE, TE not exactly `chunked` (or a coding list ending in chunked), TE on 1.0, whitespace before colon, obs-fold, CR/LF/NUL in header values, chunk extensions/trailers, bytes after the framed body | **Deterministic** (today: mitmproxy; to be pinned and extended in the addon for what mitmproxy normalizes or passes) | parser-disagreement problem, not a payload problem (H §5, §7); an ML model is not a parser |
| `Transfer-Encoding: <coding>, chunked` (still-compressed body), `Content-Encoding` undecodable/unknown/too large after decompression | **Deterministic** | the classified content would differ from the executed content (§4.4) |
| Request-line shape: method token, origin-form target, version, target bytes (space, control, DEL, invalid UTF-8), duplicate singleton headers (`Content-Type`, `Origin`, `Referer`, `Authorization`), `Host` presence and syntax | **Deterministic** | undefined behaviour today (S10); cheap and exact |
| Size limits: target, header block, body, total text/token budget | **Deterministic reject**, never silent truncation | S9/X16; truncation hides the tail where payloads sit |
| Unknown or unsupported media types (multipart, octet-stream) | Deterministic *flag* in the audit record; verdict policy for the Decision Model | not in training at all |
| Attack semantics in path, query, form/JSON/XML bodies, Authorization token content, Origin/Referer relation to Host (CSRF) | **ML** | the learned part; D1 causal set |
| Declared-vs-actual body type (`json_invalid`) | Analyzer feature, not a validator | already extracted (`request_features.py:208-223`) |

## 7. PROPOSED canonical-input contract ("canonical-request/v1")

Status: **PROPOSAL**. Nothing is implemented. One pure function used identically by the dataset
generator and the gateway:

```
canonicalize(parts: RequestParts) -> Canonical(text, audit) | Reject(reason, audit)
```

`RequestParts` is produced by two thin adapters: the gateway (from a mitmproxy request: method,
`http_version`, origin-form target bytes, headers as a list of byte pairs in received order,
**application body** = `get_content(strict=True)` bytes, plus raw framing facts for the audit) and the
generator (from a logical sample plus a sampled client profile). The generator no longer builds strings.

### 7.1 ML text grammar

```
{METHOD} {TARGET} HTTP/1.1 LF
{Canonical-Header-Name}: {value} LF     (zero or more, allowlist, fixed order)
LF {BODY}                               (only if BODY is non-empty)
```

Same grammar as today's D1 text (so `request_features.py` and the V4 layout tests keep working); the
last header line is not followed by an extra LF unless a body follows.

| Field | Rule |
|-------|------|
| method | Upper-case token; must be in {GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS} else Reject `method`. (Training has 6; OPTIONS to be added to the data spec or removed here.) |
| version | Constant `HTTP/1.1` in the text. Actual version goes to the audit record. 1.0 allowed (CL-only); anything else Reject `version`. |
| target | Origin-form, starts with `/`. Bytes exactly as received: **no decoding, no re-encoding, no case change, no dot-segment removal, no hex-case normalization.** Must be valid UTF-8 and contain no space, control char or DEL, else Reject `target_bytes`. Length <= `MAX_TARGET` (proposed 2048 bytes). Query stays inside the target. |
| headers | Allowlist A1 in this order: `Content-Type`, `Origin`, `Referer`, `Authorization`. Canonical name spelling. Value = received value, outer OWS stripped, valid UTF-8, no CR/LF/NUL/other controls (HTAB ok), <= 1024 bytes. A duplicate singleton header is Reject `duplicate_header`. Absent header = omitted line (no placeholder). **Everything else** (Host, User-Agent, Accept*, Connection, Proxy-Connection, Keep-Alive, Upgrade, TE, Transfer-Encoding, Content-Length, Content-Encoding, Expect, Cookie, X-*) is excluded from the text and summarized in the audit record. |
| body | Bytes after de-chunking and `Content-Encoding` decoding (strict: failure or unknown coding is Reject `content_encoding`). Decoded as UTF-8 strictly; invalid UTF-8 is rendered with `errors="backslashreplace"` (injective, ASCII-visible) and flagged `body_utf8=false` in the audit. CR, LF, BOM, blank lines kept verbatim. Declared `charset` is not interpreted. Absent or empty body: no blank line, no placeholder. |
| encoding policy | The canonicalizer is **byte-preserving** for target and body: it applies UTF-8 decoding and nothing else. Percent-encoding equivalence is handled in *data* (the generator renders each logical value through several realistic client encoders in both classes), not in the function. Considered and excluded: decoding one layer (ambiguates `%26`, `%3D`, `%2B`; backend decoding policy unknown), upper-casing hex (RFC 3986 normal form, but would erase the reserved `mixed_case_percent` held-out transform at `parse_dataset_v4.py:744-751`; can be added later as a pure, testable step). |
| size limit | `len(text)` <= `MAX_TEXT`, chosen at freeze so that the tokenized V5 prompt is <= the V5 training `max_length` (V4: 512 tokens; the byte value is NOT measured here). Over the limit: Reject `oversize`, never truncate. |
| determinism | No clock, no randomness, no locale; pure function of `RequestParts`. |

### 7.2 Structured audit record (never ML text; no raw path/query/body, per the existing log policy)

`canonicalizer_version`; `http_version`; `method`; `scheme` and `port` (gateway only); `verdict`
(`ok`/`reject`) and `reasons[]`; framing observed (`cl_present`, `cl_valid`, `cl_equals_raw_length`,
`te_class` in {none, chunked, coding+chunked, invalid}, `body_source` in {content-length, chunked,
none}); `raw_body_bytes`, `decoded_body_bytes`, `content_encoding_chain`, `body_utf8`, `target_utf8`;
header inventory (`count`, `bytes`, names of well-known headers present as lowercase tokens, unknown
names counted not listed); `host_present`; flags (`obs_fold`, `lone_cr`, `duplicate_singleton`,
`unsupported_media_type`); `text_bytes`, `text_sha256`. These feed deterministic Decision Model
signals and logs, and make a framing reject explainable without reaching the model.

### 7.3 Consequences for the data spec (not decided here)

- Smuggling variants (`parse_dataset_v4.py:625-632`) become **validator test vectors with expected
  reject reasons**, not ML training rows. D18 already records the category as not evaluable.
- Matrix #7 (chunked) is closed by construction; the "chunked envelope" benign family in the draft
  (§2) is replaced by invariance test I4 below, not by training data.
- Generator rules that follow from the audit: sample a client profile (CL / chunked / gzip, encoder,
  header set) **independently of the label**; encode logical values once; type the body to its
  declared Content-Type; never emit a header outside the allowlist into text.

## 8. Testable invariants

Function-level (unit tests on `canonicalize`):

| ID | Invariant |
|----|-----------|
| I1 | **One function.** Generator and gateway call the same `canonicalize`; a test imports both call sites and asserts identity (as `capture_addon` does for `render_request`). |
| I2 | **Train/serve byte equality.** For any `RequestParts`, the text the generator writes into `train.jsonl` equals the text the gateway sends to `/classify` for the same parts. |
| I3 | **Idempotence.** Parsing a canonical text back into `RequestParts` and canonicalizing it returns the same text. |
| I4 | **Framing independence.** The same logical request sent with CL, chunked (any chunking), `gzip`+CL or `gzip`+chunked yields byte-identical text. |
| I5 | **Metadata invariance.** Changing or removing Host, User-Agent, Accept*, Connection, Proxy-Connection, Keep-Alive, Cookie (if A1), header order or name case, a valid Content-Length value, or the HTTP version in {1.0, 1.1} leaves the text unchanged. (D44-style, for the ML text.) |
| I6 | **Byte preservation.** `%XX` triplets, `+`, hex case, quotes and key order in target and body appear unchanged in the text. |
| I7 | **Totality.** Every `RequestParts` maps to exactly one of Canonical or Reject; no exception escapes; no silent truncation (`len(text)` <= `MAX_TEXT` or Reject). |
| I8 | **Unambiguous grammar.** The request line, allowlisted headers and body are recoverable from the text (`\n\n` only after the header block; header values contain no LF). |
| I9 | **Grouping stays separate.** `canonical_key` is computed on the logical (decoded) value and is identical for all encoder renderings of it; it is never applied to or compared with the canonical text. |
| I10 | **Validator vectors.** Each smuggling/framing vector in §6 yields the expected Reject reason and never reaches text. |

Dataset-level (checks over the generated corpus; would have failed on V4 data):

| ID | Invariant | V4 measured |
|----|-----------|-------------|
| G1 | Per-class frequency of {encoding layers, hex case, space as `%20`/`+`/literal, reserved char encoded vs literal} is independent of the label within tolerance | `%25XX` 3,473 vs 0 |
| G2 | Every row's body parses under its declared Content-Type (form/JSON/XML) | 661 + 50 JSON violations |
| G3 | Header names in text subset of the allowlist; header set and order independent of the label | by construction in C |
| G4 | Valid-JSON benign rows include multi-key, typed, nested bodies (coverage) | 0 multi-key |
| G5 | Token length of every row <= V5 `max_length` | not measured for V4 |

## 9. Pending decisions for the owner (max 3)

**P1. Canonical form for the ML text and the D1 amendment.**
- (a) B: validate + drop framing, keep every other header. Pro: smallest change. Con: keeps X4-X6, header-set noise, no invariance story.
- (b) **C (recommended)**: validate + fixed grammar + allowlist + decoded body. Pro: removes X1-X6 by construction, enables I1-I10. Con: a view that differs from the forwarded message; changes D1 for V5 on framing headers only.
- (c) C2: C plus synthetic canonical `Content-Length`. Pro: D1 wording survives. Con: no information, more tokens.
- Needs: a D1/D44 amendment stating that for V5 the framing-header clause is replaced by deterministic validation, and Origin/Referer is unchanged.

**P2. Header allowlist and Host/User-Agent in the V5 text.**
- (a) Keep the V4 envelope (D1 as is, shared distributions). Pro: no semantic change. Con: Host/UA sensitivity persists (D44 rationale), unbounded header noise.
- (b) **A1 (recommended)**: Content-Type, Origin, Referer, Authorization only. Pro: matches "evidence before inclusion" (draft §1.3), enables I5. Con: header-borne attacks (UA, X-Forwarded-For, Cookie) are invisible to the ML text; they must be covered by the Analyzer or a later decision.
- (c) A1 + Cookie. Pro: classic injection carrier. Con: random cookie tokens cost tokens; no cookie family in the draft data spec.
- Recommend (b), with (c) only if the data spec adds cookie-borne families.

**P3. Reject policy and where validation runs.**
- (a) Reject deterministically in the addon `request` hook before rendering, with the firewall's own response (403 for policy, 400/413 for malformed/oversize), pin `validate_inbound_headers=true` by a config test. Pro: no silent distortion, explainable audit. Con: malformed-but-benign legacy clients are blocked.
- (b) Never reject: escape or truncate and let the ML decide. Pro: fewer hard failures. Con: truncation hides payload tails; breaks I7; recreates S10/S5 ambiguity.
- (c) Mixed: reject framing/encoding anomalies, truncate only bodies of declared binary media types. Pro: pragmatic. Con: two policies to test.
- Recommend (a); revisit (c) when a binary-media corpus exists. Needs the client-visible wording (mitmproxy's own 400 today, G §4).

## 10. Tests written

File: `tests/test_v4_representation_contract.py` (40 tests; 21 need the data plane environment
(20 serving-side plus the generator-to-serving round trip); the other 19, training-side and
`canonical_key`, run in any environment). They pin **current** behaviour, including
behaviour this audit flags as a defect (T7, S10, X8); a deliberate fix must update them. Not re-pinned:
no-body layout, blank-line rule, headers-as-received, eval.jsonl round trip (`test_data_plane.py`),
Host/UA never features (`test_request_features.py`).

Exact commands and results (run 2026-10-11):

```
.venv-dataplane/bin/python -m unittest tests.test_v4_representation_contract -v
  -> Ran 40 tests ... OK   (0 skipped, 0 failures)
.venv-dataplane/bin/python -m unittest discover -s tests -p 'test_v4_representation_contract.py'
  -> Ran 40 tests ... OK
python3 -m unittest tests.test_v4_representation_contract         (3.14, no mitmproxy)
python3.12 -m unittest tests.test_v4_representation_contract
.venv-analyzer/bin/python -m unittest tests.test_v4_representation_contract
  -> Ran 40 tests ... OK (skipped=21)   (serving-side classes need mitmproxy/httpx)
.venv-dataplane/bin/python -m unittest tests.test_data_plane      -> Ran 36 tests, OK (unchanged)
```

Coverage by class: `TestServingFraming` (chunked header kept/no CL added, wrong CL not recomputed,
gzip decoded under compressed CL, undecodable/unknown encoding left raw, no header filtering,
obs-fold/lone CR); `TestServingEncoding` (percent-encoding untouched, form/JSON verbatim, UTF-8
replacement and charset ignored, BOM/whitespace bodies, CRLF in body, lone surrogates);
`TestServingRequestLine` (version verbatim, no scheme/port, method upper-cased, `/?`, no size limit);
`TestServingFailClosedOnUnencodableText` (503 and classifier never called for a non-UTF-8 target;
U+FFFD for a body); `TestTrainingEnvelope`, `TestTrainingRendering` (CL/TE only in framing shapes,
double-encoding, `%20` vs `+`, JSON separators, form body under JSON type, smuggling bytes);
`TestTrainingRenderingMatchesServingRenderer` (file-independent layout round trip over generated
rows including the six smuggling variants); `TestCanonicalKeyIsAGroupingKeyNotAModelInput`.

## 11. Limitations

- Serving behaviours come from constructing mitmproxy request objects (`tutils.treq`), as the existing
  tests do. Whether mitmproxy's wire parser delivers non-UTF-8 targets/headers, and every row of note G,
  rests on notes F/G (loopback, mitmproxy 12.2.3); I did not re-run them. HTTP/2/3, TLS interception,
  reverse mode, `stream_large_bodies` and `validate_inbound_headers=false` remain untested.
- The mapping of the six training smuggling variants to mitmproxy rejections is my reading of note G's
  categories, not a replay of those exact texts.
- Training counts are over `datasets/v4_clean/train.jsonl` (untracked in git; regenerated by
  `parse_dataset_v4.py`) using regexes on the rendered text, e.g. "lowercase-hex escapes" means
  `%[a-f][0-9a-f]|%[0-9][a-f]`. They describe the corpus, not the full generator support.
- Token lengths (X16, G5) and the numeric `MAX_TEXT`/`MAX_TARGET` values were not measured (tokenizer
  not run); they are placeholders for the freeze.
- "Real clients always send CL or chunked", "clients encode legitimate punctuation" and "JSON clients send
  compact JSON" are INFERENCE from F and general practice, not measured on this deployment.
- Whether the canonical form changes V4/V5 FP or recall is untested; this audit proposes a contract,
  it does not show it improves behaviour. The proposed allowlist makes header-borne attacks invisible to
  the ML text by design (P2).
- Multipart, XML namespaces/entities and other media types are outside the training distribution; the
  contract passes them through unchanged and only flags them in the audit record.
- The two other untracked files in the working tree (`scripts/dataset/v5_dataset_checks.py`,
  `tests/test_v5_dataset_checks.py`) belong to other workstreams and were not read or touched.
