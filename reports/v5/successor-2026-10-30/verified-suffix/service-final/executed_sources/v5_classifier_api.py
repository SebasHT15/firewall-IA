"""
firewall-IA — Control Plane V5 classification service (hybrid cascade).

A thin HTTP surface over `v5_inference_core`, the semantic stage of the PDF
cascade. It serves V5 on the CANONICAL REQUEST text (the shared representation
Model 2 scores and the generator trained on), never V4's D1 render and never raw
wire bytes. Like the V4 service it REPORTS; it enforces nothing (D4 fail-closed
lives in the data plane / cascade router).

This is a SEPARATE service from `classifier_api.py` (V4), which stays untouched
for comparison and explicit reversion. Changing V4's `FIREWALL_ADAPTER_DIR` would
NOT make the V4 service serve V5 — the template, tokenizer handling and parser
differ — so V5 has its own service and its own `FIREWALL_V5_ADAPTER_DIR`.

An output that is not exactly one ratified vocabulary string terminated by native
EOS is reported `status: "invalid"` with an `invalid_reason`; it is never coerced
into a decision and never into an ALLOW.

Concurrency: one GPU, one generation at a time (a lock). A bounded number of
requests may wait for the lock; beyond that the service returns 503 (saturation)
rather than growing an unbounded queue. A per-request wall-clock bound on lock
acquisition yields 503 as well, so a stuck generation cannot stall the caller
forever. These make the service's failure modes explicit and testable; they are
fail-closed from the data plane's point of view (503 -> reject).

RUN (from repo root; single worker, model loaded once at startup):
    /usr/bin/python3.12 -m uvicorn --app-dir control_plane v5_classifier_api:app \
        --host 127.0.0.1 --port 8001
"""

import logging
import os
import threading
import time
from contextlib import asynccontextmanager
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

import v5_inference_core as core

log = logging.getLogger("firewall.control_plane.v5")

# One GPU: one generation at a time. `_MAX_INFLIGHT` bounds how many requests may
# be in the service at once (one running + the rest waiting); beyond that is 503.
_MAX_INFLIGHT = int(os.environ.get("FIREWALL_V5_MAX_INFLIGHT", "8"))
# Wall-clock bound (seconds) for acquiring the GPU lock. Exceeding it is 503.
_ACQUIRE_TIMEOUT_S = float(os.environ.get("FIREWALL_V5_ACQUIRE_TIMEOUT_S", "15"))

_GPU_LOCK = threading.Lock()
_SLOTS = threading.BoundedSemaphore(_MAX_INFLIGHT)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    log.info("startup: loading V5 adapter %s", core.DEFAULT_ADAPTER_DIR)
    t0 = time.perf_counter()
    try:
        app.state.v5 = core.load_v5(
            core.DEFAULT_ADAPTER_DIR,
            runtime_profile_path=os.environ.get("FIREWALL_V5_RUNTIME_PROFILE"),
            runtime_profile_sha256=os.environ.get("FIREWALL_V5_RUNTIME_PROFILE_SHA256"),
            allow_experimental_runtime=(os.environ.get("FIREWALL_V5_ALLOW_EXPERIMENTAL_RUNTIME") == "1"))
        app.state.contract = core.contract_summary(app.state.v5.contract)
        app.state.contract["runtime_profile"] = (
            app.state.v5.runtime_profile.summary() if app.state.v5.runtime_profile else None)
        app.state.contract["runtime_settings"] = app.state.v5.runtime_settings
        app.state.load_s = time.perf_counter() - t0
        log.info("startup: V5 ready on %s in %.1f s (fingerprint %s adapter %s)",
                 app.state.v5.device, app.state.load_s,
                 app.state.contract["template_fingerprint"][:12],
                 app.state.v5.adapter_sha256[:12])
    except Exception:
        log.exception("startup: V5 failed to load — /classify will return 503")
        app.state.v5 = None
        app.state.contract = None
        app.state.load_s = None
    yield
    log.info("shutdown")


app = FastAPI(title="firewall-IA V5 control plane", version="1.0.0", lifespan=lifespan)
app.state.v5 = None
app.state.contract = None
app.state.load_s = None


class ClassifyRequest(BaseModel):
    """The CANONICAL REQUEST text (canonical-request/v1 CanonicalResult.text).

    Not raw wire bytes and not V4's D1 render: the data plane canonicalizes once
    and sends that exact text, so serving and the generator share one
    representation."""
    canonical_request: str = Field(..., min_length=1)


class ClassifyResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    status: Literal["ok", "invalid"]
    decision: Optional[Literal["ALLOW", "BLOCK"]] = None
    reason: Optional[str] = None
    invalid_reason: Optional[str] = None
    generate_ms: float
    pipeline_ms: float
    generated_tokens: int
    prompt_tokens: int
    ended_with_eos: bool
    queue_wait_ms: float
    service_ms: float


class HealthResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    status: Literal["ok"]
    model_loaded: bool
    adapter_dir: str
    adapter_sha256: Optional[str] = None
    template_fingerprint: Optional[str] = None
    load_s: Optional[float] = None
    max_inflight: int
    runtime_profile: Optional[dict] = None
    runtime_settings: Optional[dict] = None


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    v5 = app.state.v5
    return HealthResponse(
        status="ok",
        model_loaded=v5 is not None,
        adapter_dir=core.DEFAULT_ADAPTER_DIR,
        adapter_sha256=(v5.adapter_sha256 if v5 else None),
        template_fingerprint=(app.state.contract["template_fingerprint"] if app.state.contract else None),
        load_s=app.state.load_s,
        max_inflight=_MAX_INFLIGHT,
        runtime_profile=(v5.runtime_profile.summary() if v5 and v5.runtime_profile else None),
        runtime_settings=(v5.runtime_settings if v5 else None),
    )


@app.get("/contract")
def contract() -> dict:
    if app.state.contract is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    return app.state.contract


@app.post("/classify", response_model=ClassifyResponse)
def classify(body: ClassifyRequest) -> ClassifyResponse:
    v5 = app.state.v5
    if v5 is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    # Saturation bound: refuse rather than queue without limit.
    if not _SLOTS.acquire(blocking=False):
        log.warning("classify: saturated (>%d in flight), returning 503", _MAX_INFLIGHT)
        raise HTTPException(status_code=503, detail="Saturated")
    t_in = time.perf_counter()
    try:
        got = _GPU_LOCK.acquire(timeout=_ACQUIRE_TIMEOUT_S)
        if not got:
            log.warning("classify: GPU lock wait exceeded %.1fs, returning 503", _ACQUIRE_TIMEOUT_S)
            raise HTTPException(status_code=503, detail="Busy")
        queue_wait_ms = (time.perf_counter() - t_in) * 1000
        try:
            parsed, measure = core.classify_canonical(v5, body.canonical_request)
        finally:
            _GPU_LOCK.release()
    except HTTPException:
        raise
    except Exception:
        log.exception("classify: inference failed")
        raise HTTPException(status_code=500, detail="Inference failed")
    finally:
        _SLOTS.release()

    pipeline_ms = (measure["encode_ms"] + measure["transfer_ms"] + measure["generate_ms"]
                   + measure["decode_ms"] + measure["parse_ms"])
    if parsed.status == "ok":
        log.info("classify: ok decision=%s generate_ms=%.1f", parsed.decision, measure["generate_ms"])
    else:
        log.warning("classify: invalid reason=%s ended_with_eos=%s raw=%r",
                    parsed.invalid_reason, measure["ended_with_eos"],
                    measure.get("raw_text", "")[:120])
    return ClassifyResponse(
        status=parsed.status,
        decision=parsed.decision,
        reason=parsed.reason,
        invalid_reason=parsed.invalid_reason,
        generate_ms=measure["generate_ms"],
        pipeline_ms=pipeline_ms,
        generated_tokens=measure["generated_tokens"],
        prompt_tokens=measure["prompt_tokens"],
        ended_with_eos=measure["ended_with_eos"],
        queue_wait_ms=queue_wait_ms,
        service_ms=(time.perf_counter() - t_in) * 1000,
    )
