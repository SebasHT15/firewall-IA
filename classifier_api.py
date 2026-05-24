"""
firewall-IA — classification engine (control plane).

Wraps the v3 QLoRA-fine-tuned TinyLlama classifier behind an HTTP API.
Inference logic mirrors test_model.py's classify() exactly (prompt format,
generation params, extraction regex) — do not alter, the model's correctness
depends on matching training.

RUN (single worker is MANDATORY — one GPU, model loaded once):
    python3.12 -m uvicorn classifier_api:app --host 0.0.0.0 --port 8000 --workers 1

The ML stack is installed for python3.12 on this machine, NOT the default
python3. Use python3.12 to launch.

Point at a different adapter without editing this file:
    FIREWALL_ADAPTER_DIR=/path/to/adapter python3.12 -m uvicorn classifier_api:app --workers 1

TEST:
    curl localhost:8000/health

    # benign request -> expect ALLOW
    curl -X POST localhost:8000/classify \
        -H 'Content-Type: application/json' \
        -d '{"request":"GET /index.html HTTP/1.1\nHost: example.com"}'

    # attack payload (SQL injection) -> expect BLOCK
    curl -X POST localhost:8000/classify \
        -H 'Content-Type: application/json' \
        -d '{"request":"GET /api/users?id=1'"'"' OR '"'"'1'"'"'='"'"'1 HTTP/1.1\nHost: target.com"}'
"""

import asyncio
import os
import re
import time
from contextlib import asynccontextmanager

import torch
from fastapi import FastAPI
from peft import PeftModel
from pydantic import BaseModel
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
)

# ── Configuration ──────────────────────────────────────────────────
BASE_MODEL = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
ADAPTER_DIR = os.path.expanduser(
    os.environ.get("FIREWALL_ADAPTER_DIR", "~/Desktop/firewall-IA/model-output-v3")
)

INSTRUCTION = (
    "You are a network security firewall classifier. "
    "Analyze the following HTTP request and respond with exactly: "
    "ALLOW or BLOCK | <one sentence reason>. Then output ###END###"
)

EXTRACT_RE = re.compile(r"(ALLOW|BLOCK)\s*\|\s*(.+?)(?:\s*###END###|\.|$)")

# ── Module-level state (populated once at startup) ──────────────────
tokenizer = None
model = None
device = "cuda" if torch.cuda.is_available() else "cpu"
end_token_id = None
MODEL_LOADED = False

# GPU runs one inference at a time; serialize concurrent requests.
gpu_lock = asyncio.Lock()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global tokenizer, model, end_token_id, MODEL_LOADED

    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.float16,
    )

    tokenizer = AutoTokenizer.from_pretrained(ADAPTER_DIR)
    tokenizer.pad_token = tokenizer.eos_token

    base_model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL,
        quantization_config=bnb_config,
        device_map="auto",
    )
    base_model.resize_token_embeddings(len(tokenizer))

    model = PeftModel.from_pretrained(base_model, ADAPTER_DIR)
    model.eval()

    end_token_id = tokenizer.convert_tokens_to_ids("###END###")
    MODEL_LOADED = True
    yield


app = FastAPI(title="firewall-IA classifier", lifespan=lifespan)


class ClassifyRequest(BaseModel):
    request: str


class ClassifyResponse(BaseModel):
    decision: str
    reason: str
    raw_output: str
    latency_ms: float


def _classify_raw(request: str):
    """Replicates test_model.py classify() 1:1, returning structured parts."""
    prompt = (
        f"<|system|>\n{INSTRUCTION}</s>\n"
        f"<|user|>\n{request}</s>\n"
        f"<|assistant|>\n"
    )
    inputs = tokenizer(prompt, return_tensors="pt").to(device)
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=40,
            do_sample=False,
            pad_token_id=tokenizer.eos_token_id,
            eos_token_id=end_token_id,
        )
    input_len = inputs["input_ids"].shape[1]
    new_tokens = outputs[0][input_len:]
    response = tokenizer.decode(new_tokens, skip_special_tokens=True)

    match = EXTRACT_RE.search(response)
    if match:
        decision = match.group(1)
        reason = match.group(2).strip()
    else:
        reason = response.split("\n")[0].strip()
        decision = "BLOCK" if "BLOCK" in response.upper() else "ALLOW"

    return decision, reason, response


@app.post("/classify", response_model=ClassifyResponse)
async def classify(body: ClassifyRequest):
    async with gpu_lock:
        t0 = time.perf_counter()
        decision, reason, raw_output = await asyncio.get_event_loop().run_in_executor(
            None, _classify_raw, body.request
        )
        latency_ms = (time.perf_counter() - t0) * 1000

    return ClassifyResponse(
        decision=decision,
        reason=reason,
        raw_output=raw_output,
        latency_ms=latency_ms,
    )


@app.get("/health")
async def health():
    return {"status": "ok", "model_loaded": MODEL_LOADED}
