"""
firewall-IA — Control Plane (HTTP classification service).

A thin HTTP surface over `inference_core`. It does not build prompts, load
models, generate or parse: every decision comes from the same V4 pipeline the
evaluation harness uses (`test_model.py`), so runtime and evaluation cannot
drift apart.

SCOPE (Issue #15) — classification only. This service REPORTS its result,
including the fact that a model output was unparseable (`status: "invalid"`).
It does NOT enforce anything. The fail-closed policy of D4 belongs to the
future Data Plane (Issues #16/#17), which will decide what to do with an
`invalid` result, a 5xx, or a timeout.

An unparseable model output is NEVER coerced into a decision — not to ALLOW,
not to BLOCK. See `inference_core.parse_prediction`.

RUN (single worker: one GPU, model loaded once at startup):
    python3.12 -m uvicorn classifier_api:app --host 127.0.0.1 --port 8000

Point at a different adapter without editing this file:
    FIREWALL_ADAPTER_DIR=/path/to/adapter python3.12 -m uvicorn classifier_api:app
"""

import logging
import threading
import time
from contextlib import asynccontextmanager
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

import inference_core as core

log = logging.getLogger("firewall.control_plane")

# One GPU, one model: generate() runs one request at a time. The endpoints are
# declared `def` (not `async def`), so FastAPI runs them in its worker
# threadpool and this plain lock is all the serialization needed — no queue,
# no scheduler, no async plumbing.
_GPU_LOCK = threading.Lock()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load the model exactly once, at startup."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    log.info("startup: loading adapter %s", core.DEFAULT_ADAPTER_DIR)
    t0 = time.perf_counter()
    try:
        app.state.tokenizer, app.state.model = core.load_model(core.DEFAULT_ADAPTER_DIR)
        app.state.device = core.resolve_device()
        log.info("startup: model ready on %s in %.1f s",
                 app.state.device, time.perf_counter() - t0)
    except Exception:
        # Stay up so /health can report the failure and the operator (or the
        # future Data Plane) can see an unready control plane rather than a
        # connection refused. /classify returns 503 while in this state.
        log.exception("startup: model failed to load — /classify will return 503")
    yield
    log.info("shutdown")


app = FastAPI(title="firewall-IA control plane", version="1.0.0", lifespan=lifespan)

# Populated by lifespan; declared here so /health works even if loading failed.
app.state.tokenizer = None
app.state.model = None
app.state.device = None


# ── Schemas ────────────────────────────────────────────────────────────────
class ClassifyRequest(BaseModel):
    """Raw HTTP request text, exactly the representation the model was trained
    on (D1). Never structured method/path/header fields — that would be a
    second serialization, different from the one used in evaluation."""

    request: str = Field(..., min_length=1)


class ClassifyResponse(BaseModel):
    # `model_` is a pydantic-protected prefix; the field name is part of the
    # agreed contract, so opt out of the namespace check rather than rename it.
    model_config = ConfigDict(protected_namespaces=())

    status: Literal["ok", "invalid"]
    decision: Optional[Literal["ALLOW", "BLOCK"]] = None
    reason: Optional[str] = None
    model_latency_ms: float


class HealthResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    status: Literal["ok"]
    model_loaded: bool
    adapter_dir: str


# ── Endpoints ──────────────────────────────────────────────────────────────
@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Liveness plus model readiness. Always 200 while the process is up;
    `model_loaded` carries the readiness signal."""
    return HealthResponse(
        status="ok",
        model_loaded=app.state.model is not None,
        adapter_dir=core.DEFAULT_ADAPTER_DIR,
    )


@app.post("/classify", response_model=ClassifyResponse)
def classify(body: ClassifyRequest) -> ClassifyResponse:
    """Classify one raw HTTP request.

    Returns `status: "ok"` with a decision and reason, or `status: "invalid"`
    with both null when the model output does not satisfy the contract. The
    caller decides what to do with an invalid result (D4 fail-closed lives in
    the Data Plane, not here).
    """
    if app.state.model is None:
        log.error("classify: rejected, model not loaded")
        raise HTTPException(status_code=503, detail="Model not loaded")

    # Request bodies are attacker-controlled and are not logged by default.
    log.info("classify: received request (%d bytes)", len(body.request))

    try:
        with _GPU_LOCK:
            raw, model_latency_ms = core.classify_raw(
                app.state.tokenizer, app.state.model, body.request, app.state.device
            )
    except Exception:
        log.exception("classify: inference failed")   # traceback to the log ...
        raise HTTPException(status_code=500, detail="Inference failed")  # ... not to the client

    decision, reason, status = core.parse_prediction(raw)

    if status == "ok":
        log.info("classify: status=ok decision=%s reason=%r model_latency_ms=%.1f",
                 decision, reason, model_latency_ms)
    else:
        # Not coerced. The raw output is logged (it is model output, not the
        # request body) because it is the only way to diagnose the failure.
        log.warning("classify: status=invalid model_latency_ms=%.1f raw=%r",
                    model_latency_ms, raw[:200])

    return ClassifyResponse(
        status=status,
        decision=decision,
        reason=reason,
        model_latency_ms=model_latency_ms,
    )
