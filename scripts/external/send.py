"""External Test v1 — real-client request sender for the DRAFT capture phase.

Turns a Spec into a request that a REAL client (curl or Python httpx) puts on the wire,
through the CAPTURE proxy. It never sends the classifier representation directly: the whole
point is that the frozen text is what a genuine client produced, headers and framing
included, as the capture proxy renders it (protocol 4.2).

Guarantees required for order-based capture correlation (protocol 11, and label_candidates):
  - exactly ONE request per Spec: redirects are NOT followed and clients do not retry, so a
    302 from /login or /cart yields one captured record, not two;
  - requests are sent synchronously and in list order, so the capture proxy records them in
    that order.

No marker, correlation id or test header is added — every header is model input
(ml_evaluation_methodology.md section 8). Flows are separated by capture-file offset
(run_capture.py), never by a tag inside a request under test.
"""

from __future__ import annotations

import subprocess


def _url(spec) -> str:
    return f"http://{spec.host}:{spec.port}{spec.path}"


def send_via_curl(spec, proxy: str, timeout: float = 30.0) -> int:
    url = _url(spec)
    if spec.method == "HEAD":
        args = ["curl", "-sS", "-I", "--max-time", str(int(timeout)), "-x", proxy]
    else:
        args = ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                "--max-time", str(int(timeout)), "-x", proxy, "-X", spec.method]
    for name, value in spec.headers:
        args += ["-H", f"{name}: {value}"]
    if spec.body is not None:
        # list-form subprocess: no shell, so payloads pass verbatim with no escaping.
        # '--data-binary' sends bytes exactly; leading '@' would mean a file, but no spec
        # body begins with '@'.
        args += ["--data-binary", spec.body]
    args.append(url)
    subprocess.run(args, check=False, capture_output=True, timeout=timeout + 5)
    return 0


def send_via_httpx(spec, proxy: str, timeout: float = 30.0) -> int:
    import httpx
    url = _url(spec)
    content = spec.body.encode("utf-8") if spec.body is not None else None
    # trust_env=False: only the explicit capture proxy is used. follow_redirects=False: one
    # request per spec. A fresh client per call keeps flows isolated; volume is small.
    with httpx.Client(proxy=proxy, trust_env=False, timeout=timeout,
                      follow_redirects=False) as c:
        req = c.build_request(spec.method, url, headers=dict(spec.headers), content=content)
        try:
            c.send(req)
        except httpx.HTTPError:
            # A benign non-2xx (e.g. 405 on a PUT the app does not implement) is expected and
            # is still a real captured request. Transport errors are surfaced by the caller's
            # boundary count, not swallowed silently here.
            pass
    return 0


def send_spec(spec, proxy: str, timeout: float = 30.0) -> int:
    """Dispatch a Spec to the client its provenance declares."""
    if spec.client == "httpx":
        return send_via_httpx(spec, proxy, timeout)
    return send_via_curl(spec, proxy, timeout)   # curl for "curl" and "mixed" curl specs
