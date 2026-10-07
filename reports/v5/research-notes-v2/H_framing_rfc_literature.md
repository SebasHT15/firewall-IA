# H — HTTP message framing: RFC, OWASP and literature evidence

Date: 2026-10-06. Scope: read-only literature gathering for one open question: should message-framing
information (Transfer-Encoding, Content-Length, TE+CL conflicts, duplicate CL, malformed chunking) be
**(A)** given to the ML model as text, **(B)** validated deterministically and removed from the ML input,
or **(C)** validated deterministically while the ML sees a canonicalized request?
**This note does not decide.** It gathers primary evidence. Nothing in the repo was changed.
No attack payloads are reproduced; attack classes are described only as far as defence needs.

## Method and verification levels

- **VERIFIED-TEXT**: I read the primary text myself (RFC `.txt` from rfc-editor.org; CRS rule files from
  `raw.githubusercontent.com/coreruleset/coreruleset` at tag `v4.30.0` and `main`; PortSwigger pages;
  paper PDFs from arXiv / the publisher-linked PDF; DOIs checked against the Crossref API).
- **VERIFIED-ABSTRACT**: only the abstract / metadata was read (paywalled paper).
- **INFERENCE**: my reading of how verified text combines. Marked as such.
- **UNVERIFIED**: could not be confirmed.
- Web-fetch summaries of the RFCs were cross-checked against the RFC text and only the RFC text is used
  below (one summary contained wording that does not match RFC 9110 §7.6; it was discarded).

---

## 1. RFC 9112 — HTTP/1.1 (June 2022, STD 99)

URL: https://www.rfc-editor.org/rfc/rfc9112 (text: https://www.rfc-editor.org/rfc/rfc9112.txt). VERIFIED-TEXT.

| § | What it says (paraphrase unless quoted) |
|---|---|
| §6 Message Body | The body carries the *content*; it equals the content unless a transfer coding was applied. In a request, a body is signalled only by Content-Length or Transfer-Encoding; request framing is independent of method semantics. |
| §6.1 Transfer-Encoding | Lists the codings applied "in order to form the message body". Recipient MUST be able to parse chunked. Sender MUST NOT apply chunked twice. If any non-chunked coding is applied to a **request**, chunked MUST be the final coding. A server that gets a coding it does not understand SHOULD answer 501. TE is "a property of the message, not of the representation": any recipient on the chain MAY decode it or add codings, if it updates the field. TE was added in HTTP/1.1: a client MUST NOT send it unless it knows the server handles 1.1; an HTTP/1.0 message that contains TE MUST be treated as faulty framing and the connection closed after processing. |
| §6.1 (TE+CL paragraphs) | Explains why TE overrides CL instead of the two being mutually exclusive (old implementations sent both). Says forwarding such a message "can lead to vulnerabilities regarding request smuggling" if any downstream recipient parses differently. **A server MAY reject a request containing both CL and TE, or process it by TE alone; either way it MUST close the connection after responding.** |
| §6.2 Content-Length | CL gives the framing when there is no TE. **A sender MUST NOT send CL in any message that contains TE.** |
| §6.3 rule 3 (TE+CL) | TE overrides CL. Such a message "might indicate an attempt to perform request smuggling" and "ought to be handled as an error" (SHOULD-level, not MUST). **An intermediary that chooses to forward it MUST first remove the received CL and process the TE before forwarding.** So the RFC allows reject, or forward-after-removing-CL; it never allows forwarding both unchanged. |
| §6.3 rule 4 | TE present and chunked is final: read and decode chunks until complete. In a **request** where chunked is NOT the final coding, length cannot be determined: the server MUST answer 400 and close. |
| §6.3 rule 5 (invalid CL, no TE) | Framing is invalid and the recipient MUST treat it as an unrecoverable error. **Exception**: a comma-separated list whose values are all valid and all identical is processed with that single value. In a request the server MUST answer 400 and close; a proxy receiving it in a response MUST close, discard and send 502. |
| §6.3 rule 6 / 7 | Valid CL (no TE) defines the length; a short body means "incomplete" and the connection is closed. Request with neither TE nor CL has length zero. |
| §6.3 closing paragraphs | Requests are never close-delimited. A user agent MUST NOT send chunked unless it knows the server speaks 1.1. |
| §7.1 chunked coding | Grammar: `chunk-size [chunk-ext] CRLF data CRLF`, last chunk size zero, optional trailer section, final empty line. Recipients MUST anticipate very large hex sizes and prevent integer overflow / precision loss. "The chunked coding does not define any parameters. Their presence SHOULD be treated as an error." |
| §7.1.1 chunk extensions | Per-chunk metadata. They are specific to a connection and "likely to be removed or recoded by each recipient (including intermediaries)". A recipient MUST ignore unrecognized extensions. A server ought to limit their total length and answer 4xx beyond a limit. |
| §7.1.2 trailers | A recipient that removes the chunked coding MAY keep or discard trailers. It MUST NOT merge a trailer field into the header section unless that field's definition explicitly permits and says how. |
| §7.1.3 decoding | Informative pseudo-code. After decoding, **`Content-Length := length` and `chunked` is removed from Transfer-Encoding**. This is the RFC's own canonical form of a de-chunked message. |
| §2.2 message parsing | Parse as octets in a US-ASCII superset, not as Unicode text: Unicode-string parsing "creates security vulnerabilities". A recipient MAY accept bare LF. A bare CR outside content MUST be rejected or replaced by SP before processing or forwarding. Whitespace between the start-line and the first header MUST be rejected or consumed; this is "necessary to prevent their misinterpretation by downstream recipients" vulnerable to smuggling. Non-grammatical input: SHOULD answer 400 and close. |
| §5.1 | A server MUST answer 400 to whitespace between field name and colon (historic source of routing / handling bugs). |
| §5.2 | Obsolete line folding: a server MUST either answer 400 or replace each fold with SP(s) before interpreting or forwarding. |
| §11.2 Request Smuggling | Smuggling "exploits differences in protocol parsing among various recipients". The spec "introduced new requirements on request parsing, particularly with regard to message framing in Section 6.3, to reduce the effectiveness". (Short section; the real defence text is the MUSTs above.) |
| §11.1 Response Splitting | Exploits line-based framing; stronger mitigation is to stop anything but core protocol libraries from emitting CR or LF in the header section. |
| §11.3 Message Integrity | HTTP has no integrity mechanism of its own; `http` gives no protection against modification. Relevance here: low. |

**INFERENCE (duplicate CL):** RFC 9112 never says "duplicate Content-Length header lines" explicitly. RFC 9110 §5.3 lets a
recipient combine same-name lines into a comma list, and CL is not a list field, so two CL lines
become `a, b`. §6.3 rule 5 then accepts it only when all values are equal and valid; unequal values
are an unrecoverable framing error (400 + close).

## 2. RFC 9110 — HTTP Semantics (June 2022, STD 97)

URL: https://www.rfc-editor.org/rfc/rfc9110 (text: https://www.rfc-editor.org/rfc/rfc9110.txt). VERIFIED-TEXT.

| § | What it says |
|---|---|
| §3.7 | Defines intermediaries: proxy, gateway, tunnel. (Not re-read in detail.) |
| §5.3 Field Order | A recipient MAY combine same-name field lines with commas; a proxy MUST NOT reorder them. A server MUST NOT act on a request before the whole header section arrives, since later lines may carry "deliberately misleading duplicate header fields". |
| §6.1 Framing and completeness | Framing says "how each message begins and ends"; each HTTP major version has its own mechanism. A message is complete when all octets indicated by the framing are available. |
| §6.4 Content | Content is the stream "after it has been extracted from the message framing". The RFC's own example: an HTTP/1.1 body may be chunked, but the *content* excludes "the chunk lengths, chunked framing syntax, nor the trailer fields". **This is the normative separation of framing from content.** |
| §6.5 Trailers | Trailer fields are not content and have their own processing/limits (§6.5.1, §6.5.2). |
| §7.6 Message forwarding | Intermediaries may filter content or enhance/interfere with the stream; senders and recipients "cannot rely on incremental delivery" because implementations may buffer "for the sake of network efficiency, security checks, or content transformations". An intermediary not acting as a tunnel MUST implement Connection and exclude fields meant only for the incoming connection. |
| §7.6.1 Connection | Intermediaries MUST parse Connection, remove every field it names, then remove or replace Connection itself. They SHOULD also remove/replace fields known to be hop-specific even if not listed: **Proxy-Connection, Keep-Alive, TE, Transfer-Encoding, Upgrade**. So TE-the-framing-header is explicitly hop-by-hop. A connection-specific field arriving without a matching Connection option "usually indicates" improper forwarding and "ought to be ignored". |
| §8.6 Content-Length | CL is the data length of the content (used for delimiting framing) or, in other cases, of the selected representation. Value is 1*DIGIT; huge values must not overflow. **A sender MUST NOT forward a message with a CL "known to be incorrect"** and MUST NOT forward a CL that does not match the ABNF. Single exception: `42, 42`-style repeats, which a recipient MAY reject or collapse to one value, because they "likely" come from an upstream duplicate. Reason given: CL can affect how downstream recipients parse even if the current hop is not HTTP/1.1. |
| §10.1.4 TE | Request TE header (what the client accepts), distinct from Transfer-Encoding. |
| §17 | Security considerations (not mined in detail). |

**Distinction the RFCs make (useful for A/B/C):** Transfer-Encoding, TE and Connection are properties of the *hop* (message framing).
Content-Encoding, Content-Type and Content-Language are properties of the *representation*. Content-Length is both: framing in HTTP/1.1,
representation size otherwise (§8.6).

### 2b. RFC 9113 (HTTP/2) — relevant by contrast. VERIFIED-TEXT

https://www.rfc-editor.org/rfc/rfc9113
- §8.2.2: HTTP/2 messages MUST NOT carry connection-specific fields (Connection, Proxy-Connection, Keep-Alive, **Transfer-Encoding**, Upgrade); such a message is malformed. TE may appear only with value `trailers`. An intermediary converting HTTP/1.x to HTTP/2 MUST remove them.
- §8.1.1: a message is malformed if `content-length` differs from the summed DATA payload lengths. Intermediaries MUST NOT forward a malformed message. The text says the strictness is deliberate: "being permissive can expose implementations".
- Implication (INFERENCE): in HTTP/2 and HTTP/3 there is no TE-framing information to give an ML model; framing is binary and unambiguous. HTTP/1.1 text rendering is where the question lives.

---

## 3. OWASP

### 3a. WSTG (testing guide)

- Latest: **WSTG-INJT-16 "HTTP Request Smuggling"**, https://wstg.owasp.org/latest/ (source file `document/4-Web_Application_Security_Testing/07-Injection/16-HTTP_Request_Smuggling.md` in https://github.com/OWASP/wstg). VERIFIED-TEXT.
  - Definition: parsing inconsistencies between front-end and back-end; historically CL/TE; now also HTTP/2 downgrade, H2C, header-normalization mismatches, connection reuse.
  - **Remediation section (5 bullets):** enforce strict RFC-compliant parsing; normalize request handling across all intermediaries; disable H2C where not required; avoid protocol downgrades on untrusted connections; terminate and revalidate backend connections upon parsing errors.
- v4.2: **WSTG-INPV-15 "Testing for HTTP Splitting/Smuggling"**, https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling . VERIFIED-TEXT. Contains an "Application Firewall Bypass" scenario (a firewall and the server disagree about where requests start and end, so the firewall misses content). It has **no remediation section** (I found none). It credits Linhart, Klein, Heled, Orrin (2005) as the original whitepaper.
- Scope caveat: WSTG is a *testing* guide. Its "remediation" is five generic bullets; it does not say "remove framing from detector input".

### 3b. OWASP Cheat Sheet Series

I did not find an OWASP Cheat Sheet dedicated to request smuggling. UNVERIFIED that none exists (not exhaustively searched).

### 3c. OWASP CRS (Core Rule Set) — see §6 for rules.

---

## 4. PortSwigger Web Security Research (James Kettle) — defensive content only

### 4a. "HTTP Desync Attacks: Request Smuggling Reborn" (Black Hat USA 2019; DEF CON 27)
https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn . Page dated 2019-08-07, updated 2025. VERIFIED-TEXT.
Defensive statements:
1. All variants are resolved by configuring the **front-end to speak HTTP/2 exclusively to back-ends**, or by **disabling back-end connection reuse**, or by running **identical webserver software and configuration** on every hop.
2. "Specific instances" can be resolved by **reconfiguring the front-end to normalize ambiguous requests before routing them onward**; "probably the only realistic solution" for CDNs; Cloudflare and Fastly "seem to apply it successfully" (his words, unaudited).
3. **Normalising is "not an option" for back-ends: they must reject ambiguous requests and drop the connection.** Because rejection hits legitimate traffic more than normalisation, he recommends focusing prevention on the front-end.
4. Notes that HTTPS does not help. A real-world mitigation he cites: one large payment site was fixed by getting its CDN to reject requests that used chunked encoding at all.

### 4b. "HTTP/1.1 must die: the desync endgame" (Black Hat USA / DEF CON 33, 2025)
https://portswigger.net/research/http1-must-die . Dated 2025-08-06. VERIFIED-TEXT. Defensive statements:
- Root cause is protocol ambiguity (several ways to specify length); patching individual parser bugs has not kept pace over six years of variants (CL/TE 2019, H2 downgrade 2021, CL.0 2022, TE.0 2024 (exploits de-chunking), chunk-extension TE.TE 2025, 0.CL / Expect 2025).
- Primary fix: **upstream HTTP/2 end to end**. Downgrading client HTTP/2 to upstream HTTP/1.1 gives "minimal security benefit" and adds exposure.
- "How to survive with HTTP/1.1" (if stuck): enable all normalization and validation options on the front-end; enable validation on the back-end; avoid niche webservers; scan regularly; disable upstream connection reuse; reject requests with a body when the method does not need one (GET/HEAD/OPTIONS).
- **WAF caveat (directly relevant):** be wary of vendor claims that WAFs stop desync as well as upstream HTTP/2. He says WAFs now use regexes to block obfuscated Transfer-Encoding or HTTP requests inside bodies, which makes his old probes fail without fixing the underlying bug (the "illusion of security"), and that regex defences are bypassable.
- Rationale he gives for why normalisation is not yet done: fear of breaking legacy clients ("we resort to regex-based defences").

### 4c. 2026 follow-up
PortSwigger lists "CRLF-Powered Desync Attacks: Beheading HTTP Streams" (Aug 2026, https://portswigger.net/research/crlf-powered-desync-attacks) as related research. **I did not read it.** UNVERIFIED defensive content.

---

## 5. Academic literature

DOIs were checked with Crossref (and Semantic Scholar for abstracts).

| Paper | Year / venue | DOI / URL | Defensive claim it supports | Level |
|---|---|---|---|---|
| **T-Reqs: HTTP Request Smuggling with Differential Fuzzing** — Jabiyev, Sprecher, Onarlioglu, Kirda | 2021, ACM CCS (pp. 1805–1820, Nov 2021) | https://doi.org/10.1145/3460120.3485384 | Smuggling arises from *processing discrepancies between two servers in a proxy-origin pair*, not from faults in either server alone; tested 10 server/proxy/CDN products, identified server pairs prone to smuggling and new request manipulations. Supports "framing must be interpreted identically on every hop, or the ambiguous message must be rejected/rewritten". The paper's own mitigation section was not available to me. | VERIFIED-ABSTRACT (paper is closed access) |
| **HDiff: A Semi-automatic Framework for Discovering Semantic Gap Attack in HTTP Implementations** — Shen, Lu, Yang, Chen, Zhang, Duan, Zhang, Zheng | 2022, IEEE/IFIP DSN | https://doi.org/10.1109/DSN53405.2022.00014 | Real paper (confirmed). Extracts rules from the specs with NLP and differential-tests 10 HTTP implementations; 14 vulnerabilities, 29 affected server pairs, 7 new CVEs (Apache, Tomcat, WebLogic, IIS). Supports "implementations deviate from the RFC rules, and those deviations are the attack surface". | VERIFIED-ABSTRACT |
| **Gudifu: Guided Differential Fuzzing for HTTP Request Parsing Discrepancies** — Jabiyev, Gavazzi, Onarlioglu, Kirda | 2024, RAID '24 (Padua) | https://doi.org/10.1145/3678890.3678904 | **§5.3** (request-body discrepancies, Tables 4–5): proxies differ on malformed CL values, CL+chunked, trailers, bad chunk sizes (non-hex bytes), oversize chunk sizes and mismatched chunk lengths. Some answer 400, some forward as-is, some **reconstruct a fresh clean chunked body**. **§8.3**: the "immediately actionable recommendation" for proxy/server developers is to **follow RFC guidance strictly**; many discrepancies come from "liberties" in behaviour the spec already defines; standards bodies should also drop the loose MAY/SHOULD/MUST style. Also states there is "no known solution" to the emergent problem in general. | VERIFIED-TEXT (PDF) |
| **The HTTP Garden: Discovering Parsing Vulnerabilities in HTTP/1.1 Implementations by Differential Fuzzing of Request Streams** — Kallus et al. (author list not verified) | 2024, arXiv:2405.17737 (venue UNVERIFIED) | https://arxiv.org/abs/2405.17737 | Argues the most significant parsing anomalies are inside *origin* servers, and that examining a gateway's output alone misses some vulnerabilities; 100+ parsing bugs found, 68 fixed, 39 judged exploitable. Supports "a front-end that validates cannot assume the back-end parses like it". | VERIFIED-ABSTRACT |
| **WAFFLED: Exploiting Parsing Discrepancies to Bypass Web Application Firewalls** — Akhavani, Jabiyev, Kallus, Topcuoglu, Bratus, Kirda | 2025, ACSAC (IEEE) | https://doi.org/10.1109/ACSAC67867.2025.00062 ; arXiv:2503.10846 (v4, 13 Mar 2026) | **Closest to our question.** 1,207 bypasses confirmed across 5 WAFs (AWS, Azure, Cloud Armor, Cloudflare, ModSecurity). They mutate **non-malicious** parts (headers, body segments) of `application/json`, `multipart/form-data`, `application/xml` requests so the WAF and the framework parse different content. Over 90% of sampled sites accept form-urlencoded and multipart interchangeably. **Defence (§7): "HTTP-Normalizer"** is a gateway in front of the WAF that parses against a strict RFC grammar, **rejects non-compliant requests, and re-serializes compliant ones with optional/deprecated parts stripped**, so "invalid state is not representable". Evaluation: 63 sampled bypass requests; 55 rejected, 8 normalized, and the 8 were blocked by Cloudflare's WAF. **Scope caveats (VERIFIED-TEXT): it concerns Content-Type/body parsing (multipart prototype), not TE/CL framing; HTTP/1.1 only; tool is a proof of concept, not production-grade; the 63-request evaluation is a sample.** | VERIFIED-TEXT (arXiv PDF) |
| **Network Intrusion Detection: Evasion, Traffic Normalization, and End-to-End Protocol Semantics** — Handley, Paxson, Kreibich | 2001, USENIX Security '01 | https://www.usenix.org/legacy/events/sec01/full_papers/handley/handley.pdf | Classic precedent for option C: a **traffic normalizer** sits in line and "patches up" the stream to remove ambiguity *before the monitor sees it*, trading off end-to-end semantics. It is about IP/TCP, not HTTP. Cited as design precedent only. | VERIFIED-TEXT (abstract/first page) |
| WAF-A-MoLE: Evading Web Application Firewalls through Adversarial Machine Learning — Demetrio et al. | 2020, ACM SAC | https://doi.org/10.1145/3341105.3373962 | Metadata confirmed only. Concerns ML-based WAFs evaded by payload mutation (SQLi), not framing. Content not read. | UNVERIFIED (content) |

Not found: a peer-reviewed paper that studies an **ML detector's input representation** with respect to TE/CL framing
(neither a result for nor against giving framing headers to the model). UNVERIFIED that none exists; I did a bounded search only.

Older sources named by OWASP/RFC 9112: Linhart, Klein, Heled, Orrin (2005) "HTTP Request Smuggling" (WatchFire/WASC); not re-read.

---

## 6. Is "the WAF/detector sees the de-chunked content" standard practice?

### 6a. OWASP CRS rules about framing — VERIFIED-TEXT
Rule files at tag **v4.30.0** (latest release on 2026-10-02) and `main` (4.31.0-dev), https://github.com/coreruleset/coreruleset/tree/main/rules .
CRS works by anomaly scoring (default critical = 5, warning = 3, inbound threshold = 5, from `crs-setup.conf.example`; rule 949110 denies when the score reaches the threshold).

| Rule id | File | Phase / PL / severity | What it checks (from the rule text) |
|---|---|---|---|
| **920160** | REQUEST-920 | 1 / PL1 / CRITICAL | Request `Content-Length` header does not match `^\d+$` ("not numeric"). Does not evaluate the CL value against actual body length. By regex, `42, 42` (the RFC-permitted repeat) also fails (INFERENCE). |
| **920170** | REQUEST-920 | 1 / PL1 / CRITICAL | GET or HEAD with a Content-Length that is not empty/0. Comment cites RFC 9110 ("SHOULD NOT generate content in GET/HEAD"). |
| **920171** | REQUEST-920 | 1 / PL1 / CRITICAL | GET or HEAD with a Transfer-Encoding header present. |
| **920180** | REQUEST-920 | 1 / PL1 / WARNING | POST (non-HTTP/2, non-HTTP/3) with neither Content-Length nor Transfer-Encoding. Comment explains HTTP/2 and HTTP/3 have no chunked TE. |
| **920181** | REQUEST-920 | 1 / PL1 / WARNING | Both Transfer-Encoding and Content-Length present. Comment cites "RFC7230 3.3.2" (now RFC 9112 §6.2): sender MUST NOT send CL with TE. Scored 3 < threshold 5, so alone it does not block at defaults (INFERENCE from the defaults above). |
| 920340 | REQUEST-920 | PL1 / CRITICAL | Non-zero Content-Length but missing Content-Type. |
| **921110** | REQUEST-921 | 2 / PL1 / CRITICAL | "HTTP Request Smuggling Attack": looks for an HTTP method + target + `http/N` pattern in ARGS, ARGS_NAMES, **REQUEST_BODY** and XML (i.e. a second request embedded in content). Content signature, not framing validation. |
| 921130 / 921160 | REQUEST-921 | PL1 | Response splitting / header injection payloads in arguments or cookies. |
| 922120 | REQUEST-922 | 2 | `Content-Transfer-Encoding` inside a multipart part (deprecated by RFC 7578). Not HTTP framing. |

Corrections to the briefing's rule list: **920190 is the `Range` header check ("Invalid Last Byte Value"), not a framing rule**; **920181 is the CL+TE rule** (the briefing did not list it); 920171 is the GET/HEAD+TE rule.
**What CRS does *not* do (VERIFIED by grep of all 27 `rules/*.conf` at v4.30.0):** the only rules that mention Transfer-Encoding/chunk are 920171, 920180, 920181 (header *presence*) and 922120 (multipart). **There is no CRS rule that validates the TE value (e.g. non-final chunked, obfuscated TE values), chunk syntax, chunk extensions, or duplicate/unequal Content-Length lines.** CRS delegates body framing to the web server / ModSecurity engine; whether the engine or the server rejects those cases is outside the rule set (UNVERIFIED per product).

### 6b. ModSecurity
- ModSecurity v2 (Apache module): `apache2/modsecurity.c` (v2/master) sets `reqbody_should_exist` and `reqbody_chunked` from the headers: it reads Content-Length first, and only if there is none does it look for "chunked" in Transfer-Encoding. VERIFIED-TEXT. This is a header-based "is there a body" decision; **the file does not itself implement RFC 9112 §6.3 precedence** (TE overrides CL); the actual framing is done by the Apache core (INFERENCE; not traced).
- **CVE-2013-5705** (NVD, published 2014-04-15): ModSecurity before 2.7.6 let remote attackers bypass rules by using chunked coding with a capitalized `Chunked` value in Transfer-Encoding. Fix commit `f8d441c…`, listed in ModSecurity's CHANGES under "Security Issues". VERIFIED (NVD API + CHANGES). Illustrates the exact failure class: the inspector's idea of the framing differed from the server's.
- ModSecurity v2 CHANGES also mentions `{dis|en}able-dechunk-logging` ("dechunking" in the audit log), i.e. the engine has a dechunking step. VERIFIED-TEXT (CHANGES file).
- The ModSecurity v2 Reference Manual pages for Variables and Configuration Directives contain **no** statements about chunked encoding or de-chunking (searched; none found). So "ModSecurity processes the de-chunked body" is true as implementation behaviour but **not documented in the manual**. ModSecurity v3 / connector behaviour: UNVERIFIED.
- Matching the RFC 9110 §6.4 definition: the variable a WAF rule sees as `REQUEST_BODY` is content (after framing is removed), and framing headers stay available as separate `REQUEST_HEADERS` fields. CRS 921110 targets `REQUEST_BODY` in phase 2 (VERIFIED-TEXT).

### 6c. Takeaway on "standard practice" (INFERENCE)
- Standard WAF practice is **hybrid**: the body is inspected de-framed (content), while framing *headers* are checked by small deterministic header rules (CRS 920xxx) and are not part of the body signatures. This most resembles option B/C for the body, with deterministic header checks. It is not practice to feed raw framing bytes to a pattern engine.
- The CRS header checks are **thin** (presence/numeric checks, §6a), and Kettle (§4b) and WAFFLED (§5) report that WAFs bypass via parsing differences. Both treat thin regex/signature checks as insufficient; the literature's remedy is a strict RFC parser/normalizer, not more signatures.

---

## 7. Evidence-to-option map (not a decision)

| Option | Evidence that bears on it |
|---|---|
| **A: framing as text to the ML** | No source recommends it. Everything in §§1–5 treats framing as something to be **parsed deterministically per the RFC, rejected, or rewritten**, because the harm comes from *parser disagreement*, and an ML model is not a parser. RFC 9110 §6.4 separates framing from content. WAFs in practice do not use raw framing bytes in body signatures (§6c). The literature says nothing specific about ML inputs (UNVERIFIED either way). Note from note F: mitmproxy keeps `Transfer-Encoding: chunked` in the headers while the body is already de-chunked and no CL is added, so in the rendered text the framing header and the body disagree by construction. |
| **B: validate deterministically, remove from ML input** | Strongly consistent with: RFC 9112 §6.3 rules 3–5 (reject/400 cases), §6.1 (server MAY reject TE+CL), RFC 9110 §8.6 (never forward a known-wrong CL), Kettle 2019 ("back-end must reject"), OWASP WSTG-INJT-16 remediation (strict RFC parsing; terminate on parse error), Gudifu §8.3, WAFFLED §7 (reject branch). Open point: what exactly is removed (TE/CL header lines only, or trailers/extensions too). |
| **C: validate + canonicalize (ML sees a canonical request)** | Consistent with: RFC 9112 §6.3 rule 3 (an intermediary that forwards MUST drop CL and process TE), §7.1.3 (decode, set CL to decoded length, drop `chunked`), §7.1.1/§7.1.2 (extensions and trailers can be dropped by the recipient), RFC 9110 §7.6.1 (intermediaries remove TE/hop-by-hop fields), Kettle 2019 ("front-end should normalize"), WAFFLED HTTP-Normalizer (reject if non-compliant, else re-serialize into a form where invalid state is not representable), Handley et al. 2001 (normalizer before the monitor). WAFFLED's tool covers multipart only. **Condition that every source implies (INFERENCE): the representation the classifier scores must be the one the backend will actually interpret**, i.e. the same bytes the proxy forwards after validation/normalization; otherwise inspection and execution diverge (the WAFFLED / CVE-2013-5705 failure class). |
| Residual risk common to B and C | Kettle 2025: normalization/validation at the front-end only helps if the **forwarded** message is the normalized one and the back-end hop is consistent (or upstream HTTP/2); a classifier or WAF in front does not remove desync risk by itself. |

---

## 8. UNVERIFIED / not confirmed

1. T-Reqs (CCS 2021) own mitigation text: paper is closed access; only abstract read.
2. HDiff (DSN 2022): abstract only; no defensive section read.
3. HTTP Garden author list and publication venue (arXiv preprint verified; venue not confirmed).
4. PortSwigger "CRLF-Powered Desync Attacks" (Aug 2026): not read.
5. WAF-A-MoLE content (only DOI/metadata confirmed).
6. ModSecurity v3 / nginx-connector de-chunking behaviour; ModSecurity v2 manual does not document it; which layer (Apache core vs engine) de-chunks was not traced.
7. Whether an OWASP Cheat Sheet on request smuggling exists (none found, search not exhaustive).
8. Any peer-reviewed study of ML/learned WAFs with framing headers as input features (none found; search was bounded).
9. Claims that Cloudflare/Fastly "apply normalization successfully" are Kettle's 2019 remark, not independently audited.
10. Duplicate Content-Length line handling is an INFERENCE from RFC 9110 §5.3 + RFC 9112 §6.3 rule 5; no RFC sentence names "duplicate CL lines".
11. Default CRS scores (5/3/threshold 5) come from commented defaults in `crs-setup.conf.example`; a deployment may override.

## 9. Source URLs

- RFC 9112: https://www.rfc-editor.org/rfc/rfc9112 ; RFC 9110: https://www.rfc-editor.org/rfc/rfc9110 ; RFC 9113: https://www.rfc-editor.org/rfc/rfc9113
- OWASP WSTG latest: https://wstg.owasp.org/latest/ (WSTG-INJT-16) ; v4.2: https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling ; repo https://github.com/OWASP/wstg
- OWASP CRS: https://github.com/coreruleset/coreruleset (tag v4.30.0; files `rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf`, `REQUEST-921-PROTOCOL-ATTACK.conf`, `REQUEST-922-MULTIPART-ATTACK.conf`, `crs-setup.conf.example`)
- ModSecurity: https://github.com/owasp-modsecurity/ModSecurity (v2/master `apache2/modsecurity.c`, `CHANGES`); CVE-2013-5705 https://nvd.nist.gov/vuln/detail/CVE-2013-5705
- PortSwigger: https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn ; https://portswigger.net/research/http1-must-die
- Papers: https://doi.org/10.1145/3460120.3485384 ; https://doi.org/10.1109/DSN53405.2022.00014 ; https://doi.org/10.1145/3678890.3678904 ; https://arxiv.org/abs/2405.17737 ; https://doi.org/10.1109/ACSAC67867.2025.00062 / https://arxiv.org/abs/2503.10846 ; https://www.usenix.org/legacy/events/sec01/full_papers/handley/handley.pdf ; https://doi.org/10.1145/3341105.3373962

Related note in this folder: `F_mitmproxy_dechunking.md` (what the gateway actually shows the classifier).
