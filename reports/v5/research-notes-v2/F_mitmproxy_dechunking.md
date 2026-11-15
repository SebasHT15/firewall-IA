# F — Does mitmproxy de-chunk request bodies before `render_request()`?

Date: 2026-10-06. Scope: read-only investigation of the gateway (`data_plane/data_plane.py`,
`render_request()`, called from the `request` hook) on the mitmproxy installed in `.venv-dataplane`.
No repo file was modified except this note. The live test ran only on loopback (ports 18765/18766),
with throwaway scripts in the session scratchpad, a scratch `confdir`, and no classifier.

## Verdicts

| # | Question | Verdict |
|---|----------|---------|
| 1 | Installed mitmproxy version | **FACT**: 12.2.3 (Python 3.12.15), h11 0.16.0 |
| 2 | Chunked request body is de-chunked before the `request` hook; `get_content()` returns the de-chunked payload | **FACT** (source + live test) |
| 3 | With chunked, headers still show `Transfer-Encoding: chunked` and no `Content-Length` is added | **FACT** (source + live test) |
| 4 | Content-Length body: header kept as sent, body verbatim | **FACT** (live test) |
| 5 | gzip `Content-Encoding`: body shown decoded, `Content-Encoding: gzip` and the *compressed* `Content-Length` stay | **FACT** (source + live test) |
| 6 | Request with both TE and CL never reaches the addon (400 by mitmproxy) | **FACT** (source + live test, default `validate_inbound_headers=true`) |
| 7 | `Expect: 100-continue` is removed before the addon sees the headers | **FACT** (source + live test). This is an exception to "exactly as received" |

## 1. Version

```
$ .venv-dataplane/bin/mitmdump --version
Mitmproxy: 12.2.3
Python:    3.12.15
$ .venv-dataplane/bin/pip show mitmproxy   -> Version: 12.2.3
$ .venv-dataplane/bin/pip show h11         -> Version: 0.16.0
```

## 2. Source evidence (`.venv-dataplane/lib/python3.12/site-packages/mitmproxy/`)

- `net/http/http1/read.py::expected_http_body_size`: when `Transfer-Encoding` ends in `chunked` it returns
  `None` ("chunked encoding"), otherwise it returns the `Content-Length` value, or 0 for a request with neither.
- `proxy/layers/http/_http1.py`: `Http1Server.read_headers` calls `make_body_reader(expected_body_size)`, which is
  h11's `ChunkedReader` / `ContentLengthReader`. `read_body` emits only `h11.Data.data` as `RequestData`,
  so the chunk-size lines and the terminating `0\r\n\r\n` are stripped there. Trailers raise
  `NotImplementedError("HTTP trailers are not implemented yet.")`.
- `proxy/layers/http/__init__.py::state_consume_request_body`: it concatenates the `RequestData` into
  `request_body_buf`, then on end-of-message does `self.flow.request.data.content = bytes(self.request_body_buf)`
  and only after that `yield HttpRequestHook(self.flow)`. That is the hook where `render_request` runs.
  It writes `data.content` directly, not through `set_content()`, so it does **not** add or rewrite `Content-Length`.
  (`Message.set_content()` would add `content-length` only when no `transfer-encoding` is present, but the
  proxy layer does not call it.)
- Same file, before the hook: `if headers.get("expect").lower() == "100-continue": ... self.flow.request.headers.pop("expect")`.
  In reverse mode without `keep_host_header`, the `Host` header is rewritten to the upstream. In regular mode an
  absolute-form target becomes origin-form.
- On the way upstream, `Http1Client.send` re-chunks the body (`b"%x\r\n%s\r\n"`) when the request headers contain
  `chunked`. The destination therefore gets chunked framing again.
- `http.py::Message.get_content`: if `content-encoding` is set it returns `encoding.decode(raw_content, ce)`, and
  with `strict=False` it returns the raw bytes when decoding fails. It never touches the headers.
- `net/http/validate.py::validate_headers`: it raises `"message with both transfer-encoding and content-length headers"`
  and also rejects multiple TE headers and TE on HTTP/1.0. Called from `__init__.py` when `validate_inbound_headers` is on.
- Repo: no `stream_large_bodies`, `validate_inbound_headers` or `store_streamed_bodies` override in the repo, and no
  `~/.mitmproxy/config.yaml`, so defaults apply. With `stream_large_bodies` set, `raw_content` could be `None`
  and the classifier would see no body. That is not configured today.

## 3. Official docs

- https://docs.mitmproxy.org/stable/api/mitmproxy/http.html: `raw_content` is "The raw (potentially compressed)
  HTTP message body". `content` is the uncompressed body. `get_content(strict=False)` returns the compressed body
  as-is when it cannot decode. `raw_content` may be `None` when streaming.
- https://docs.mitmproxy.org/stable/concepts/options/: `validate_inbound_headers` defaults to True ("Disabling this
  option makes mitmproxy vulnerable to HTTP smuggling attacks"). `stream_large_bodies` defaults to None.
- The docs do not state explicitly that bodies are de-chunked. That claim rests on the source and the test above.

## 4. Live loopback test

Throwaway files in the scratchpad (not in the repo):
- `probe_addon.py`: `sys.path.insert(0, ".../firewall-IA/data_plane"); from data_plane import render_request`.
  In its `request(flow)` hook it appends `render_request(flow.request)`, the hex of `raw_content` and the headers
  to `rendered.jsonl`. `data_plane.py` was imported, not modified.
- `upstream.py 18766`: a raw socket server that logs the exact bytes it receives and replies `200 ok`.
- `client.py 18765 18766`: raw-socket requests in absolute form (regular proxy mode, the same as production).

Commands (both mitmdump and upstream were killed at the end, `ss -ltn` confirmed both ports free, and no processes were left):
```
python upstream.py 18766 &
.venv-dataplane/bin/mitmdump --listen-host 127.0.0.1 -p 18765 -s probe_addon.py --set confdir=<scratch>/confdir &
python client.py 18765 18766
curl -x http://127.0.0.1:18765 --noproxy '' -d 'q=hello' http://127.0.0.1:18766/g_curl_d
curl -x ... -H 'Transfer-Encoding: chunked' -d 'q=hello' http://127.0.0.1:18766/h_curl_chunked
curl -x ... -H 'Expect: 100-continue' --data-binary @big.txt(2000 x 'a') http://127.0.0.1:18766/i_curl_expect
kill <mitmdump> <upstream>
```

Client output:
```
a_chunked -> HTTP/1.1 200 OK
b_content_length -> HTTP/1.1 200 OK
c_gzip_cl -> HTTP/1.1 200 OK
d_gzip_chunked -> HTTP/1.1 200 OK
e_te_and_cl -> HTTP/1.1 400 Bad Request | ... request smuggling attacks. Disable the validate_inbound_headers option to skip this security check.
f_get_nobody -> HTTP/1.1 200 OK
```

What `render_request()` produced (Python `repr`, so `\n` is LF). The body payload is
`username=admin&password=x' OR '1'='1` (36 bytes). It was sent as chunks `a` + `1a` in (a).

```
(a) chunked (2 chunks on the wire)
"POST /a_chunked HTTP/1.1\nHost: 127.0.0.1:18766\nContent-Type: application/x-www-form-urlencoded\nTransfer-Encoding: chunked\nConnection: close\n\nusername=admin&password=x' OR '1'='1"
raw_content = 36 de-chunked bytes (no chunk-size lines, no 0-terminator)

(b) Content-Length
"POST /b_content_length HTTP/1.1\nHost: 127.0.0.1:18766\nContent-Type: application/x-www-form-urlencoded\nContent-Length: 36\nConnection: close\n\nusername=admin&password=x' OR '1'='1"

(c) gzip + Content-Length
"POST /c_gzip_cl HTTP/1.1\nHost: 127.0.0.1:18766\nContent-Type: application/x-www-form-urlencoded\nContent-Encoding: gzip\nContent-Length: 56\nConnection: close\n\nusername=admin&password=x' OR '1'='1"
raw_content = 56 gzip bytes (1f8b08...); rendered body = decoded 36 bytes; Content-Length still 56

(d) gzip + chunked
"POST /d_gzip_chunked HTTP/1.1\nHost: 127.0.0.1:18766\nContent-Type: application/x-www-form-urlencoded\nContent-Encoding: gzip\nTransfer-Encoding: chunked\nConnection: close\n\nusername=admin&password=x' OR '1'='1"

(e) TE + CL  -> never rendered (400 from mitmproxy, addon not called)

(f) GET, no body
'GET /f_get_nobody?q=1 HTTP/1.1\nHost: 127.0.0.1:18766\nConnection: close'      (no trailing blank line)

(g) curl -d
'POST /g_curl_d HTTP/1.1\nHost: 127.0.0.1:18766\nUser-Agent: curl/8.18.0\nAccept: */*\nProxy-Connection: Keep-Alive\nContent-Length: 7\nContent-Type: application/x-www-form-urlencoded\n\nq=hello'

(h) curl chunked
'POST /h_curl_chunked HTTP/1.1\nHost: ...\nProxy-Connection: Keep-Alive\nTransfer-Encoding: chunked\nContent-Type: application/x-www-form-urlencoded\n\nq=hello'

(i) curl with Expect: 100-continue -> rendered headers have Content-Length: 2000 and NO Expect header
```

What the upstream received: (a), (d) and (h) were re-chunked (`24\r\n...\r\n0\r\n\r\n`, `38\r\n<gzip>\r\n0\r\n\r\n`).
(b), (c) and (g) arrived byte-identical with `Content-Length`. (c) and (d) were forwarded still gzip-compressed.
(i) was forwarded without `Expect`.

## 5. Implication for the V4 minimal-pair probe

- The gateway never adds, removes or normalizes `Content-Length` or `Transfer-Encoding`. What V4 sees is what the
  client sent:
  - **Content-Length client** (curl `-d`, HTML form posts, most libraries with a known-size body):
    `Content-Length: N` in the headers and the body verbatim.
  - **Chunked client**: `Transfer-Encoding: chunked`, **no** `Content-Length`, and a clean **de-chunked** body
    (no hex size lines).
  - **Both**: never reaches V4 (400 from mitmproxy).
- So the answer to "does the gateway always pass Content-Length or TE: chunked plus a de-chunked body" is yes for
  every POST body that is framed validly on HTTP/1.1. The only alternatives are a body with no framing headers,
  which mitmproxy reads as length 0, and HTTP/2/3, which do not apply to this plain-HTTP proxy path.
- Because ordinary real clients send `Content-Length`, almost every real body request that V4 sees carries a
  header which in V4 TRAIN appears only on the 9 "request smuggling framing" rows. A faithful minimal pair should
  therefore vary `Content-Length` present/absent, plus `Transfer-Encoding: chunked` with a de-chunked body, on
  otherwise identical benign bodies. The probe body must be the **de-chunked** text, not raw chunk framing.
- gzip caveat: the rendered text shows the decoded body under a `Content-Length` that counts the compressed bytes
  (56 vs 36 here). That length mismatch exists only in the classifier text.
- Other deltas from "as received": `Expect: 100-continue` is dropped. Regular mode turns the absolute-form target
  into origin-form. curl through a proxy adds `Proxy-Connection: Keep-Alive`, which is kept. In reverse mode `Host`
  is rewritten.
