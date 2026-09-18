"""
firewall-IA — Data Plane (mitmproxy addon).

Authorized inline interception. Every HTTP request that reaches the proxy is
sent to the Control Plane (`classifier_api.py`, POST /classify), and the answer
is enforced here, before anything is forwarded:

    client -> mitmdump + this addon -> POST /classify -> ALLOW: forwarded to the destination
                                                      -> BLOCK: answered by the proxy, never forwarded

The model is never loaded here. The data plane only speaks HTTP to the control
plane and runs in its own environment (see requirements-data-plane.txt).

FAIL-CLOSED (D4, D25, D28). A request is forwarded ONLY when the classifier
answers HTTP 200 with `status: "ok"` and `decision: "ALLOW"`. Everything else
blocks: timeout, connection error, a non-200 answer (503 model not loaded,
500 inference failure, ...), a body that is not valid JSON, `status: "invalid"`,
a missing or unknown decision, and any unexpected error inside this addon.
A model BLOCK is answered with 403 and a classifier failure with 503, so the
two stay distinguishable. The client is never told the model's reason.

RUN (from the repository root, in the data plane environment):
    .venv-dataplane/bin/mitmdump -s data_plane/data_plane.py --listen-host 127.0.0.1 -p 8080

The classifier URL and timeout are read from config.yaml when the script loads.
"""

import logging
import os
import time
from typing import NamedTuple

import httpx
import yaml
from mitmproxy import ctx, http

log = logging.getLogger("firewall.data_plane")
# httpx logs every classifier call at INFO; the ALLOW/BLOCK line already covers it.
logging.getLogger("httpx").setLevel(logging.WARNING)

# config.yaml stays at the repository root; this file lives in data_plane/.
CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "config.yaml")

BLOCKED_BODY = "Request blocked by firewall-IA.\n"
UNAVAILABLE_BODY = "Request blocked by firewall-IA: classifier unavailable (fail-closed).\n"


# ── Configuration ──────────────────────────────────────────────────────────
def load_config(path: str = CONFIG_PATH) -> tuple[str, float]:
    """Return `(classifier_url, classifier_timeout_seconds)` from config.yaml.

    Raises on a missing file, a missing key or an invalid value. Raised while
    mitmdump loads the script, that makes mitmdump exit before it starts
    listening (verified on mitmproxy 12.2.3): a misconfigured gateway never runs.
    """
    with open(path, encoding="utf-8") as f:
        section = yaml.safe_load(f)["data_plane"]
    url = section["classifier_url"]
    timeout = float(section["classifier_timeout_seconds"])
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        raise ValueError(f"data_plane.classifier_url must be an http(s) URL, got {url!r}")
    if not timeout > 0:
        raise ValueError(f"data_plane.classifier_timeout_seconds must be > 0, got {timeout}")
    return url, timeout


# ── Request representation (D1) ────────────────────────────────────────────
def render_request(request: http.Request) -> str:
    """Render a request as the raw HTTP text that `/classify` expects (D1).

    Same layout as the V4 dataset the model was trained and evaluated on
    (`parse_dataset_v4.render_request`):

        METHOD /path?query HTTP/1.1
        Name: value                   <- one line per header
                                      <- blank line, only when there is a body
        body

    LF line endings and an origin-form target. Headers are rendered exactly as
    received (order, case and repeats kept) and are never filtered or
    normalized toward the training distribution.
    """
    lines = [f"{request.method} {request.path} {request.http_version}"]
    lines += [f"{name}: {value}" for name, value in request.headers.items(multi=True)]
    text = "\n".join(lines)
    # get_content() undoes Content-Encoding (gzip, br, ...), so the model sees
    # the body the destination will process; strict=False keeps the raw bytes
    # if decoding fails.
    body = request.get_content(strict=False)
    if body:
        text += "\n\n" + body.decode("utf-8", errors="replace")
    return text


# ── Classifier call ────────────────────────────────────────────────────────
class Verdict(NamedTuple):
    decision: str               # "ALLOW" or "BLOCK", nothing else
    reason: str | None = None   # the model's reason, when the classifier gave one
    failure: str | None = None  # set only on a fail-closed BLOCK: why no decision was obtained


def fail_closed(failure: str) -> Verdict:
    return Verdict("BLOCK", failure=failure)


async def ask_classifier(client: httpx.AsyncClient, url: str, raw_request: str) -> Verdict:
    """POST one raw request to /classify and interpret the answer.

    Only an explicit, well-formed ALLOW allows. Every other outcome becomes a
    fail-closed BLOCK carrying a short description of what went wrong.
    """
    try:
        response = await client.post(url, json={"request": raw_request})
    except httpx.TimeoutException:
        return fail_closed("classifier timeout")
    except httpx.HTTPError as exc:  # connection refused, reset, protocol error, ...
        return fail_closed(f"classifier unreachable ({type(exc).__name__})")

    if response.status_code != 200:
        # 503: model not loaded (D28). 500: inference failed. 422: input rejected.
        return fail_closed(f"classifier returned HTTP {response.status_code}")
    try:
        body = response.json()
    except ValueError:
        return fail_closed("classifier returned invalid JSON")
    if not isinstance(body, dict):
        return fail_closed("classifier returned unexpected JSON")

    status, decision = body.get("status"), body.get("decision")
    if status != "ok" or decision not in ("ALLOW", "BLOCK"):
        # status "invalid" means the model output did not satisfy the contract (D25).
        return fail_closed(f"no valid decision (status={status!r}, decision={decision!r})")
    reason = body.get("reason")
    return Verdict(decision, reason if isinstance(reason, str) else None)


# ── mitmproxy addon ────────────────────────────────────────────────────────
def blocked_response(verdict: Verdict) -> http.Response:
    """The proxy's own answer. Setting it on a flow in the `request` hook stops
    mitmproxy from contacting the destination."""
    headers = {"Content-Type": "text/plain; charset=utf-8"}
    if verdict.failure:
        return http.Response.make(503, UNAVAILABLE_BODY, headers)
    return http.Response.make(403, BLOCKED_BODY, headers)


class FirewallGateway:
    def __init__(self, classifier_url: str, timeout_seconds: float,
                 transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.classifier_url = classifier_url
        self.timeout_seconds = timeout_seconds
        self.transport = transport  # None in production; tests pass an httpx.MockTransport

    def running(self) -> None:
        log.info("data plane ready: classifier=%s timeout=%.1fs policy=fail-closed",
                 self.classifier_url, self.timeout_seconds)

    async def request(self, flow: http.HTTPFlow) -> None:
        if flow.response is not None:
            # Already answered by mitmproxy itself (e.g. block_list, see done()):
            # nothing will be forwarded, so there is nothing to classify.
            return
        # mitmproxy logs an exception raised by a hook and then FORWARDS the
        # request anyway (verified on 12.2.3), so no exception may escape here.
        try:
            await self.enforce(flow)
        except Exception:
            log.exception("[%s] BLOCK (fail-closed) unexpected data plane error", flow.id[:8])
            flow.response = blocked_response(fail_closed("data plane error"))

    async def enforce(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        tag = flow.id[:8]
        # The query string and the body stay out of the log: they may carry
        # credentials or personal data, and they are attacker-controlled.
        target = f"{req.method} {req.pretty_host}:{req.port}{req.path.split('?', 1)[0]}"
        log.info("[%s] received %s (body %d bytes)", tag, target, len(req.raw_content or b""))

        started = time.perf_counter()
        # trust_env=False ignores HTTP_PROXY & co., so a shell configured to use
        # this proxy cannot route the classifier call back through the proxy.
        async with httpx.AsyncClient(transport=self.transport, timeout=self.timeout_seconds,
                                     trust_env=False) as client:
            verdict = await ask_classifier(client, self.classifier_url, render_request(req))
        elapsed_ms = (time.perf_counter() - started) * 1000

        if verdict.decision == "ALLOW":
            log.info("[%s] ALLOW %s reason=%r (classifier %.0f ms)",
                     tag, target, verdict.reason, elapsed_ms)
            return
        if verdict.failure:
            log.error("[%s] BLOCK (fail-closed) %s cause=%s (after %.0f ms)",
                      tag, target, verdict.failure, elapsed_ms)
        else:
            log.warning("[%s] BLOCK %s reason=%r (classifier %.0f ms)",
                        tag, target, verdict.reason, elapsed_ms)
        flow.response = blocked_response(verdict)

    def done(self) -> None:
        # mitmdump reloads a script whenever its file changes. If the new version
        # fails to load, the proxy keeps running WITHOUT this addon and forwards
        # traffic unclassified (verified on 12.2.3). So if this addon is removed
        # while the proxy is still running, switch on mitmproxy's built-in
        # block_list, which runs before any script, for all traffic until
        # mitmdump is restarted. On a normal shutdown there is nothing to do.
        if ctx.master.should_exit.is_set():
            return
        ctx.options.update(block_list=["/~all/503"])
        log.error("data plane addon unloaded while the proxy is running: "
                  "blocking ALL traffic (503) until mitmdump is restarted")


addons = [FirewallGateway(*load_config())]
