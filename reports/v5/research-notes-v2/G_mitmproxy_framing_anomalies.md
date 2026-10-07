# G — HTTP/1.1 request-framing anomalies: what mitmproxy does BEFORE the addon

Date: 2026-10-06. Scope: read-only source review plus a loopback test of the gateway stack
(`data_plane/data_plane.py`, `render_request()` called from the `request` hook). Builds on note F.
Installed: mitmproxy 12.2.3, Python 3.12.15, h11 0.16.0 (`.venv-dataplane`). Defaults apply: no repo
override of `validate_inbound_headers` (default True), `stream_large_bodies`, or `tcp_timeout` (default 600 s).
Mode tested: regular proxy (absolute-form targets), HTTP/1.1 plain, the same as production.

Verdict vocabulary: REJECTED (error status or dropped connection; the `request` hook, and so
`render_request`, never runs) / NORMALIZED (reaches the addon, original framing detail no longer
visible) / PASSED-THROUGH (reaches the addon with the anomaly still visible in the headers) / UNVERIFIED.

This note describes categories and outcomes only. The raw test requests are not reproduced; the throwaway
scripts were kept in the session scratchpad and not in the repo.

## 0. Architecture facts that decide everything (FACT, source + test)

1. mitmproxy terminates and re-serializes. `Http1Server` (client side) parses the request into a `Request`
   object; `Http1Client` (server side) builds a new request from that object. The upstream never sees the
   client's bytes, only: request line from `_assemble_request_line`, headers from `bytes(request.headers)`
   (`b"name: value"` joined with CRLF), then the body re-framed from the object (`assemble.py`,
   `_http1.py::Http1Client.send`). The body is re-chunked iff the header text contains "chunked" (any case),
   otherwise sent raw as read. Whatever the proxy did not parse into the object is not forwarded.
2. Header parsing is mitmproxy's own code, not h11: `net/http/http1/read.py::_read_headers` (splits on the
   first `:`, strips the value, joins obs-fold continuations) fed by `h11._receivebuffer.ReceiveBuffer.maybe_extract_lines`
   (accepts bare LF; strips a trailing CR per line). h11 is used only for the body readers
   (`ContentLengthReader`, `ChunkedReader`, `Http10Reader`) via `_http1.py::make_body_reader`.
3. Two layers decide framing, and they can disagree:
   - Layer A, `read.py::expected_http_body_size` (called in `Http1Server.read_headers`): a `ValueError`
     gives an immediate 400 plus close. It uses `headers.get(...)`, which joins repeated header lines with ", ".
   - Layer B, `net/http/validate.py::validate_headers` (called from `layers/http/__init__.py::validate_request`
     / `check_invalid`, gated by `validate_inbound_headers`): a `ValueError` gives 400, `requestheaders` and
     `error` hooks fire, `request` hook does not.
   Several smuggling-shaped inputs pass Layer A with a different body length than a strict parser would
   choose and are stopped only by Layer B (checked by calling both functions directly):
   empty `Content-Length`, whitespace before the colon in `Content-Length`/`Transfer-Encoding` (Layer A reads
   body length 0), `Transfer-Encoding` given as two lines `gzip`+`chunked` (joined to `gzip, chunked`, read as chunked),
   TE together with CL, TE on HTTP/1.0, TE `gzip` alone / `identity` / empty. With `validate_inbound_headers=false`
   these would reach the addon. **`validate_inbound_headers` (default true) is load-bearing; the option text itself
   warns that disabling it makes mitmproxy vulnerable to HTTP smuggling.**
4. `render_request` reads `request.headers.items(multi=True)` and `get_content(strict=False)`; the `request`
   hook is only reached after Layer A, Layer B, and a complete, well-formed body (`state_consume_request_body`).
5. The gateway has only a `request` hook. Rejections before that hook therefore never reach the classifier, so
   they are "blocked" without a model decision, and the client sees mitmproxy's 400 page or a silent close.

## 1. Verdict table

Test column: `t:` = loopback result (benign body `q=hello`), `S:` = source reference. Paths are under
`.venv-dataplane/lib/python3.12/site-packages/`; `mp` = `mitmproxy`.

| # | Category | Verdict | What the addon sees | What is forwarded upstream | Evidence |
|---|----------|---------|---------------------|----------------------------|----------|
| 1 | Duplicate Content-Length, identical values | REJECTED (400, close) | nothing (`request` hook not called; `requestheaders` + `error` hooks fire) | nothing | S: `mp/net/http/http1/read.py::expected_http_body_size` (joined "7, 7" fails `validate.parse_content_length`); also `validate.py::validate_headers` "multiple content-length headers". t: 400 |
| 2 | Duplicate Content-Length, different values | REJECTED (400, close) | nothing | nothing | same as 1. t: 400 |
| 3 | Single Content-Length with comma list of equal values | REJECTED (400, close) | nothing | nothing | S: `validate.py::parse_content_length` regex `^(0|[1-9][0-9]*)$`; `validate_headers` comment "stricter, reject comma-separated lists". t: 400 |
| 4a | Non-numeric / signed (`+`, `-`) / leading-zero / empty Content-Length | REJECTED (400, close) | nothing | nothing | S: `parse_content_length` regex. Empty value: Layer A treats it as length 0 and only Layer B rejects (`validate_headers`). t: 400 for alpha, `+`, `-`, `07`, empty |
| 4b | Whitespace-PADDED Content-Length (spaces around a valid number) | NORMALIZED | `Content-Length: 7` (padding gone), body verbatim | `Content-Length: 7` re-serialized, body verbatim. Mitmproxy's framing and the backend's agree | S: `read.py::_read_headers` does `value.strip()`. t: observed on both sides. LOST: the padding |
| 5 | Transfer-Encoding list ending in chunked: `gzip`/`deflate`/`compress` + `chunked` (any case/spaces around the comma) | PASSED-THROUGH (header), body de-chunked but NOT transfer-decoded | header exactly as sent (e.g. `gzip, chunked`, `GZip ,<tab> Chunked`); body = the still-gzip-compressed bytes, rendered as garbled text. mitmproxy decodes `Content-Encoding`, never `Transfer-Encoding` codings | original TE header kept; body re-chunked around the same (still compressed) bytes. The backend, if it honors TE gzip, decompresses; the classifier text never contained the decompressed payload | S: `validate.py::_HTTP_1_1_TRANSFER_ENCODINGS` allow-list (`compress,chunked`, `deflate,chunked`, `gzip,chunked`); `http.py::get_content` uses only `content-encoding`. t: `gzip, chunked` and `deflate, chunked` accepted; the gzip body was shown as compressed bytes (27-byte compressed form vs 7-byte payload). With `deflate, chunked` and a plain body the plain body was shown. Any other coding in the list (e.g. `br`, `foo`) is REJECTED (400) |
| 6 | chunked NOT last (`chunked, gzip`, `chunked, identity`, `chunked, chunked`); unknown coding only; `gzip` / `identity` alone on a request | REJECTED (400, close) | nothing | nothing | S: `validate.py::parse_transfer_encoding` (anything outside the 8-value allow-list raises); `validate_headers` rejects `gzip`/`deflate`/`compress`/`identity` for requests. t: 400 for all tested forms |
| 7 | Case / whitespace variants of the `chunked` token | Mixed. Case variants and leading/trailing whitespace or tab: PASSED-THROUGH with TE value case kept (`Chunked`, `CHUNKED`) or NORMALIZED (outer whitespace stripped). Interior whitespace (`chun ked`), `chunked;q=1`: REJECTED (400) | for `Chunked`/`CHUNKED` the exact case; for outer whitespace the stripped `chunked`; header NAME case also kept (`tRANSFER-eNCODING`) | TE header forwarded with the same case; body re-chunked | S: `parse_transfer_encoding` lowercases and normalises spaces around commas for the check only; `Http1Client.send` tests `"chunked" in te.lower()`. t: `Chunked`, `CHUNKED`, trailing spaces, leading tab, lower-case name all accepted; 400 for interior space and for `;q=1`. LOST: outer whitespace only |
| 8 | Multiple Transfer-Encoding header lines | REJECTED (400, close) | nothing | nothing | S: `validate.py::validate_headers` "multiple transfer-encoding headers"; Layer A joins them with ", " (so `gzip`+`chunked` is read as chunked there: Layer B is the only guard). t: 400 for chunked+chunked, gzip+chunked, chunked+foo |
| 9 | Transfer-Encoding on an HTTP/1.0 request | REJECTED (400, close) | nothing | nothing | S: `validate_headers` ("unexpected HTTP transfer-encoding ... for HTTP/1.0"); Layer A alone would read it as chunked. t: 400. Control: HTTP/1.0 with Content-Length passes and is forwarded as HTTP/1.0 with CL |
| 10a | Malformed chunk-size line: non-hex, `0x` prefix, bare-LF size line, more than 20 hex digits | REJECTED (silent: connection closed, NO status line) | nothing (`requestheaders` and `error` hooks fire, `request` hook does not) | nothing | S: `h11/_abnf.py` `chunk_size = {HEXDIG}{1,20}`, `_readers.py::ChunkedReader` `validate(chunk_header_re ...)`; caught in `_http1.py::read_body` -> `CloseConnection` + `RequestProtocolError`. t: no response, closed. Valid edge cases accepted: upper/lower-case hex, up to 20 digits with leading zeros |
| 10b | Chunk data length not matching the declared size (short or long) | REJECTED (silent close) | nothing | nothing | S: `ChunkedReader` "malformed chunk footer". t: no response, closed |
| 10c | Huge declared chunk size, fewer bytes sent (stall) | REJECTED eventually (silent close) after the idle timeout; no body-size cap | nothing | nothing | S: no size limit (`stream_large_bodies`/`body_size_limit` unset); `proxy/server.py::TimeoutWatchdog` closes after `tcp_timeout` (default 600 s). t: no hook, no response, still open at 13 s; with `tcp_timeout=5` closed at 5 s. The 600 s default itself was not waited out (UNVERIFIED by test, FACT from source) |
| 11 | Chunk extensions (also on the last chunk) | NORMALIZED | de-chunked body only, no extension text | upstream gets plain chunk lines with no extension | S: `ChunkedReader` regex accepts `;.*` and drops it ("XX FIXME: we discard chunk extensions"). t: accepted; extension absent on both addon and upstream sides. LOST: the extension text |
| 12 | Chunked trailers | REJECTED (silent: per-connection crash, no status; stalls until client closes or the idle timeout) | nothing (`requestheaders` hook only) | nothing | S: `_http1.py::read_body` `raise NotImplementedError("HTTP trailers are not implemented yet.")`. t: log shows "mitmproxy has crashed!" traceback for that one connection; the proxy kept serving later connections; with `tcp_timeout=5` the connection closed at 5 s |
| 13 | Body sent with neither CL nor TE | NORMALIZED (body dropped, not rendered) | request with no body (rendered text has no body part) | request with no body, no framing headers (`POST` with no body) | S: `expected_http_body_size` rule 6 "request with neither -> 0". t: addon saw no body; upstream saw none. The unread bytes stay in the connection buffer and are parsed as the NEXT request on a persistent connection: a complete second request in that spot reached the addon as a separate request and was forwarded separately; a non-request fragment waited for a complete head and was never forwarded (log: "Client closed connection before completing request headers"). With `Connection: close` or a closing upstream reply the leftover is never parsed |
| 14 | Content-Length on GET / HEAD (and TE chunked on GET) | PASSED-THROUGH | `Content-Length: 7` header and the body | forwarded as sent: same method, CL header, body (chunked re-chunked) | S: `expected_http_body_size` does not look at the request method for requests. t: GET, HEAD with CL+body, GET with chunked body all forwarded intact |
| 15a | Bare-LF line endings (whole head, or one header line) | NORMALIZED | headers as parsed, no line endings | CRLF re-serialization | S: `h11/_receivebuffer.py::maybe_extract_lines` (accepts `\n\r?\n`, strips CR per line). t: accepted; upstream received CRLF only. LOST: the original line endings |
| 15b | Obsolete line folding of an ordinary header | PASSED-THROUGH (the fold is kept inside the header VALUE) | one header whose value contains CRLF + one space (`a<CR><LF> b`); `render_request` therefore embeds a CRLF inside one rendered line | the fold is re-emitted: `X-Test: a<CRLF> b` (still folded) | S: `read.py::_read_headers` ("continued header": value + `\r\n ` + stripped continuation). t: observed on both sides. A folded Content-Length value is REJECTED (400); a fold on the first header line (no preceding header) is REJECTED (400); a fold of the TE value is REJECTED (400) |
| 15c | A lone CR inside a header value (not part of CRLF) | PASSED-THROUGH | the CR character inside the value | forwarded unchanged with the CR | t: observed on both sides (neither mitmproxy layer rejects it). Included for completeness: not in the question list, but it is a header-level anomaly that survives |
| 16 | Whitespace between header name and colon (any header, incl. CL and TE) | REJECTED (400, close) | nothing | nothing | S: `validate.py::_valid_header_name` token regex (the name keeps its trailing space/tab because `_read_headers` splits at the first colon); Layer A would read the name as unknown and report body length 0, so Layer B is the only guard. t: 400 for CL, TE, and an ordinary header, with space or tab |
| 17a | Content-Length larger than the bytes sent (incomplete body) | REJECTED (no status; connection closed on peer close or idle timeout) | nothing (`requestheaders` + `error` hooks only) | nothing (the upstream connection is made only after the request hook) | S: `h11 ContentLengthReader.read_eof` -> `RemoteProtocolError`; `_http1.py::read_body`; idle timer in `proxy/server.py`. t: the `request` hook never ran, no response during a 14 s hold; the error fired when the client closed. With `tcp_timeout=5` the proxy closed the connection at 5 s. Default 600 s is from source (UNVERIFIED by test) |
| 17b | Content-Length smaller than the bytes sent (extra bytes) | NORMALIZED (body truncated to CL) | exactly CL bytes of body | exactly CL bytes, `Content-Length` as sent | S: `ContentLengthReader`. t: the extra bytes were treated like case 13 (parsed as the next request on a persistent connection, otherwise never forwarded) |
| 18 | (context, from note F) TE together with CL | REJECTED (400) | nothing | nothing | t again in this run; `validate_headers` |

## 2. Does what mitmproxy forwards upstream ever disagree with its own parse?

No, not in the sense that matters for smuggling, with the default `validate_inbound_headers=true`:

- Upstream is built from the parsed `Request` object, so the backend sees one request per parsed request, with
  mitmproxy's framing (`Content-Length` as parsed and re-printed, or re-chunked). Bytes mitmproxy did not
  consume for a body are not appended to the forwarded request. They are either parsed by mitmproxy as the next
  request (and then also pass through the addon) or discarded when the connection is closed.
- The client's raw framing details are lost for: padding in CL, outer whitespace in the TE value, chunk
  extensions, chunk sizes and boundaries, line endings, and the number of chunks.
- Residual places where the backend can still see something the classifier text does not show:
  1. `Transfer-Encoding: <coding>, chunked` bodies (case 5): the classifier text holds the still-compressed bytes.
  2. Header folding (15b) and a lone CR (15c): the forwarded headers keep the odd bytes; a backend with a
     different folding policy could read them differently. The rendered text also contains the CRLF/CR character
     inside one line.
  3. `Expect: 100-continue` is removed (note F), and `Content-Encoding` bodies are shown decoded while
     `Content-Length` counts the compressed bytes (note F).
- If `validate_inbound_headers` were ever set to false, the Layer-A-only inputs listed in section 0.3 would reach
  the addon and be forwarded with mitmproxy's own (possibly different) reading of the length. Nothing in the
  repo sets it; this was NOT run with it disabled (UNVERIFIED in practice, shown only by calling the two
  functions directly).

## 3. Answers

**Can framing evidence relevant to request smuggling be lost before `render_request`?**
Yes. The anomalous-framing forms that the HTTP spec treats as smuggling vectors are rejected outright
(cases 1 to 4a, 6, 8, 9, 16, 18) and never get a classifier decision. Of the ones that do reach the addon,
what is lost is: CL padding, outer TE whitespace, chunk extensions, chunk boundaries and sizes, line endings,
and, for a body without framing or extra bytes after the framed body, the bytes themselves (dropped or turned
into a separate next request). A clean-looking rendered request therefore does not prove that the wire framing
was clean. What the classifier does see for chunked is `Transfer-Encoding: chunked`, no CL, and the de-chunked body.

**Does mitmproxy terminate and re-serialize HTTP/1.1 framing, so the backend sees mitmproxy's framing?**
Yes (FACT, source + test). The client-side `Http1Server` parses and the server-side `Http1Client` re-emits request
line + headers + body from the parsed object; chunked is re-chunked, Content-Length bodies are re-sent with the
parsed CL. Headers are re-emitted as parsed (name case, order, repeats, a folded value) minus the stripping above.

## 4. Open items / UNVERIFIED

- The default 600 s `tcp_timeout` was shown to work with a 5 s override only (mechanism FACT; 600 s default from source).
- `validate_inbound_headers=false` was not run.
- HTTP/2 and HTTP/3 front ends, TLS interception, `stream_large_bodies`, and upstream/reverse modes were not tested
  (not applicable to the plain-HTTP regular-mode path used here).
- HTTP pipelining of several requests in one TCP segment is handled by mitmproxy one at a time (`Http1Server` waits
  for the response first); only a limited check was done (two requests, and a framed request followed by a second
  request, both reached the addon separately).
- The 400 body text returned to the client names the reason (e.g. the offending header). That is mitmproxy's own
  page, not the firewall's "Request blocked by firewall-IA." wording, so client-visible behavior differs between a
  mitmproxy-level rejection and a model BLOCK.

## 5. Test procedure (reproducible, no repo files touched)

Loopback only: `mitmdump` from `.venv-dataplane` on 127.0.0.1:18775 (scratch `confdir`), a raw-socket upstream on
127.0.0.1:18776 that logs the exact bytes received and replies 200, a probe addon that imports
`render_request` unmodified and logs `requestheaders`/`request`/`error` events (headers, `raw_content`, rendered
text), and a raw-socket client that varied only the framing of benign `q=hello` requests (about 75 cases). A second
run used a keep-alive upstream for the leftover-bytes cases, and a third run used `--set tcp_timeout=5` for the
stall cases. Classifier not started; ports 8000/8080 not used. All processes were stopped and ports 18775/18776
confirmed free afterwards. The only repo change is this file.
