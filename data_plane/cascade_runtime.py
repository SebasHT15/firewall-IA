"""
firewall-IA — cascade runtime wiring: the real stage bindings for `cascade.py`.

Turns a parsed wire request into the single canonical snapshot (canonicalized
exactly once, with the V5 token budget as the size bound) and binds the three
stages to their real implementations:

    Fast Path   fast_path.safe_evaluate (+ make_fast_path_input)
    Model 2     model2_decider.Model2Decider.decide
    V5          the V5 control-plane service over HTTP (urllib), or an in-process
                callable for evaluation without a socket

`build_router` assembles a `cascade.CascadeRouter`. The V5 client maps HTTP
outcomes to `cascade.V5Reply`: a timeout, connection error, non-200 or malformed
answer becomes `status="error"`, which the router treats fail-closed (DENY). The
canonical snapshot's size is bounded with `max_bytes_per_token` (data-plane
reverse bound); the exact V5 budget is re-checked inside the V5 core, which
rejects over-budget content rather than truncating.

Standard library only (urllib for the HTTP client).
"""

import json
import urllib.error
import urllib.request
from typing import Optional

import canonical_request as CR
import fast_path as fp
import cascade as C


def v5_limits(token_budget_B: int, max_bytes_per_token: int = 48) -> CR.Limits:
    """Canonical Limits for the cascade: decoded-body cap >= 48*B (spec §5.5),
    size bounded by the byte reverse bound; exact token count is re-checked at V5."""
    return CR.Limits(max_decoded_body=max_bytes_per_token * token_budget_B,
                     token_budget=token_budget_B,
                     max_bytes_per_token=max_bytes_per_token)


def build_snapshot(parts: CR.RequestParts, framing, limits: CR.Limits, *,
                   correlation_id: Optional[str] = None,
                   raw_request_text: Optional[str] = None) -> C.Snapshot:
    """Canonicalize ONCE and assemble the per-request snapshot shared by all stages."""
    canonical = CR.canonicalize(parts, limits)
    return C.Snapshot(
        method=parts.method, target=parts.target, http_version=parts.http_version,
        headers=parts.headers, body=parts.body, canonical=canonical, framing=framing,
        raw_request_text=raw_request_text, correlation_id=correlation_id)


def make_fast_path_input(snapshot: C.Snapshot) -> fp.FastPathInput:
    return fp.FastPathInput(
        method=snapshot.method, target=snapshot.target, http_version=snapshot.http_version,
        headers=snapshot.headers, body=snapshot.body,
        canonical=snapshot.canonical, framing=snapshot.framing)


class V5HttpClient:
    """Calls the V5 control-plane /classify with the canonical text."""

    def __init__(self, url: str, timeout_s: float = 10.0):
        self.url = url.rstrip("/") + "/classify"
        self.timeout_s = timeout_s

    def __call__(self, canonical_text: str) -> C.V5Reply:
        data = json.dumps({"canonical_request": canonical_text}).encode("utf-8")
        req = urllib.request.Request(self.url, data=data,
                                     headers={"Content-Type": "application/json"},
                                     method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                if resp.status != 200:
                    return C.V5Reply(status="error", detail=f"http_{resp.status}")
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return C.V5Reply(status="error", detail=f"http_{e.code}")
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            return C.V5Reply(status="error", detail=type(e).__name__)
        except ValueError:
            return C.V5Reply(status="error", detail="bad_json")
        return C.V5Reply(
            status=payload.get("status", "error"),
            decision=payload.get("decision"),
            invalid_reason=payload.get("invalid_reason"),
            generate_ms=payload.get("generate_ms"), reason=payload.get("reason"))


class V5InProcessClient:
    """Calls the loaded V5 model directly (evaluation without a socket)."""

    def __init__(self, v5_model, core):
        self.m = v5_model
        self.core = core

    def __call__(self, canonical_text: str) -> C.V5Reply:
        parsed, measure = self.core.classify_canonical(self.m, canonical_text)
        return C.V5Reply(status=parsed.status, decision=parsed.decision,
                         invalid_reason=parsed.invalid_reason,
                         generate_ms=measure.get("generate_ms"), reason=parsed.reason)


class V4HttpClient:
    """Historical-reference V4 service client (raw request text)."""

    def __init__(self, url: str, timeout_s: float = 10.0):
        self.url = url.rstrip("/") + "/classify"
        self.timeout_s = timeout_s

    def __call__(self, raw_request_text: str) -> C.V4Reply:
        data = json.dumps({"request": raw_request_text}).encode("utf-8")
        req = urllib.request.Request(self.url, data=data,
                                     headers={"Content-Type": "application/json"},
                                     method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                if resp.status != 200:
                    return C.V4Reply(status="error", detail=f"http_{resp.status}")
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return C.V4Reply(status="error", detail=f"http_{e.code}")
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            return C.V4Reply(status="error", detail=type(e).__name__)
        except ValueError:
            return C.V4Reply(status="error", detail="bad_json")
        return C.V4Reply(status=payload.get("status", "error"),
                         decision=payload.get("decision"))


def build_router(config: C.CascadeConfig, *, model2_decider=None, v5_client=None,
                 v4_client=None) -> C.CascadeRouter:
    """Assemble a router. `model2_decider` is a `Model2Decider` (its .decide is bound);
    `v5_client`/`v4_client` are callables as above."""
    m2 = (model2_decider.decide if model2_decider is not None
          and config.mode not in (C.V5_ONLY, C.FAST_PATH_V5) else None)
    return C.CascadeRouter(
        config,
        fast_path_evaluate=fp.safe_evaluate,
        model2_decide=m2,
        v5_classify=v5_client,
        v4_classify=v4_client,
        make_fast_path_input=make_fast_path_input)
