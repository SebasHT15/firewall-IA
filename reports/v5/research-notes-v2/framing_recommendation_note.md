# Framing & canonicalization — brief recommendation note (reconstructed)

Date: 2026-10-06. **RECOMMENDATION — NOT A PROJECT DECISION.** This note does not change
`DECISIONS.md`, does not reopen a large framing investigation, and adds no new experiment. It is a
short reconstruction of a previously removed note, drawn **exclusively** from the frozen research
artifacts in this folder:

- `F_mitmproxy_dechunking.md` — does mitmproxy de-chunk request bodies before `render_request()`;
- `G_mitmproxy_framing_anomalies.md` — what mitmproxy does with framing anomalies before the addon;
- `H_framing_rfc_literature.md` — RFC 9110/9112/9113, OWASP, PortSwigger, and academic evidence.

No attack payloads are reproduced. Claims carry the verification level used in the source notes.

## FACTS (from F, G, H)

1. **mitmproxy 12.2.3 terminates and re-serializes HTTP/1.1.** The client-side server parses the
   request into an object; the server-side client rebuilds the upstream request from that object.
   The backend sees mitmproxy's framing, never the client's raw bytes. (G §0, §2; FACT, source+test)
2. **The gateway has only a `request` hook**, reached only after Layer A (`expected_http_body_size`)
   and Layer B (`validate_headers`, gated by `validate_inbound_headers`, default **true**) and a
   complete, well-formed body. Rejections before the hook never reach the classifier — they are
   "blocked" with no model decision and the client gets mitmproxy's own 400/close, not the
   firewall's wording. (G §0.5, §4)
3. **`validate_inbound_headers=true` is load-bearing.** Many smuggling-shaped inputs (empty/padded
   or duplicate Content-Length, TE+CL, multiple TE lines, TE on HTTP/1.0, whitespace before the
   colon, non-final `chunked`) are rejected (400/close) before the addon. With the option disabled,
   several would reach the addon with mitmproxy's own length reading. The repo does not disable it.
   (G §0.3, table rows 1–9,16,18)
4. **What V4 actually sees for a chunked request:** `Transfer-Encoding: chunked` in the headers,
   **no** `Content-Length`, and a **de-chunked** body (no chunk-size lines, no terminator).
   mitmproxy never adds/removes/normalizes CL or TE. (F §2–§5; FACT, source+test)
5. **The rendered classifier text can disagree with the wire by construction:** the `chunked`
   header remains while the body is already de-chunked; a `Content-Encoding: gzip` body is shown
   decoded under a `Content-Length` that counts the *compressed* bytes; `TE: <coding>, chunked`
   leaves the body still compressed in the text; `Expect: 100-continue` is dropped; header folding
   and a lone CR survive into the text. (F §5; G §1 rows 5,15; G §2)
6. **The RFCs separate framing from content.** RFC 9110 §6.4: content is the stream "after it has
   been extracted from the message framing" (excludes chunk lengths, chunked syntax, trailers).
   RFC 9112 §7.1.3 defines the canonical de-chunked form: set `Content-Length := decoded length`
   and remove `chunked` from Transfer-Encoding. RFC 9110 §7.6.1 lists Transfer-Encoding, TE,
   Connection, Proxy-Connection, Keep-Alive, Upgrade as hop-by-hop. (H §1, §2)
7. **Smuggling is a parser-disagreement problem, not a payload problem.** RFC 9112 §6.3 + §11.2,
   T-Reqs (CCS'21), HDiff (DSN'22), Gudifu (RAID'24) and the HTTP Garden all attribute it to
   differences in parsing among recipients; the defensive remedy across sources is strict RFC
   parsing with reject-or-rewrite, not pattern signatures. (H §5)
8. **An ML model is not a parser, and signature defenses are bypassable.** WAFFLED (ACSAC'25) shows
   1,207 WAF bypasses via parsing discrepancies and proposes an "HTTP-Normalizer" gateway that
   rejects non-compliant requests and re-serializes compliant ones so "invalid state is not
   representable"; PortSwigger (2025) warns regex/WAF framing defenses give an "illusion of
   security." No source recommends feeding raw framing to a detector; no peer-reviewed study of an
   ML detector's input representation w.r.t. TE/CL framing was found (UNVERIFIED either way). (H §4b, §5, §7)

## CURRENT RECOMMENDATION (not a decision)

Framing / request-smuggling security should be handled by a **deterministic HTTP parser/validator**,
not delegated to the ML model. The recommended future pipeline is:

```
wire request
  → strict, deterministic HTTP framing validation (reject non-compliant; RFC 9110/9112)
  → canonical application request (de-chunked body; framing/hop-by-hop headers resolved)
  → Fast Path
  → Analyzer
  → Decision Model
  → V5
```

This is consistent with RFC 9112 §6.3/§7.1.3, RFC 9110 §6.4/§7.6.1, OWASP WSTG-INJT-16 remediation,
PortSwigger 2019/2025, WAFFLED §7, and the 2001 traffic-normalizer precedent (H §7, options B/C).
**Binding condition the sources imply (INFERENCE):** the representation the classifier scores must be
the same bytes the backend will actually interpret after validation, or inspection and execution
diverge (the WAFFLED / CVE-2013-5705 failure class). Consequently **training and serving must share
the exact same canonicalization function.**

## UNRESOLVED ITEMS

- **A vs B vs C for the classifier input is not decided.** H gathers evidence toward B (validate +
  remove framing from ML input) and C (validate + ML sees a canonical request) but takes no
  decision; A (framing as text) has no support.
- Exactly **what is stripped** vs retained in the canonical form (TE/CL header lines only, or also
  trailers, extensions, folding, lone CR) is unspecified.
- `validate_inbound_headers=false` behavior was not run (source-only). 600 s `tcp_timeout` default
  not waited out (source-only). HTTP/2/3 front ends, TLS interception, `stream_large_bodies`,
  reverse/upstream modes not tested. (F §2 note; G §4)
- Whether a canonical representation changes V4/Analyzer FP/recall behavior is **untested** (no
  experiment in this session; the v2 probe keeps `Transfer-Encoding: chunked` as the gateway renders
  it, i.e. header present + de-chunked body, so it measures today's behavior, not a canonical form).
- Residual desync risk is not removed by any in-line classifier alone unless the forwarded message
  is the normalized one and the backend hop is consistent (or upstream HTTP/2). (H §7 residual row)

## FUTURE DECISIONS REQUIRED (for the owner; none taken here)

1. Choose option **B or C** for the ML input representation, with the binding condition above.
2. Specify the **canonical application request** precisely (the "Canonical Model Input" draft in the
   V5 Data Spec is the first attempt) and decide whether it **extends or replaces D1** for V5.
3. Decide where strict framing validation lives relative to the Fast Path, and the
   client-visible behavior for framing rejections (today: mitmproxy's 400, not the firewall's).
4. Decide the `validate_inbound_headers` posture and whether to add framing validation the repo does
   not currently perform (non-final chunked value checks, duplicate-CL semantics, etc.).

These are design questions, not findings. Nothing above is implemented or committed in this session.
